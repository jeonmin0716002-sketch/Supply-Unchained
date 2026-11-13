"""의존성 목록 → 판정 보고서. ``fast`` 는 알려진 취약점만, ``full`` 은 패키지별 전체 파이프라인.

원칙: 확인하지 못한 항목은 ``unchecked`` 로 사유와 함께 남긴다. 버전을 모르는(미고정)
의존성, 조회 실패, 어댑터 없음 모두 "깨끗함"으로 세지 않는다.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

import httpx

import ecosystems
from ecosystems.base import Dependency
from inventory.osv_batch import SEVERITY_ORDER, OsvQuery, VulnInfo, query_batch

_VERDICT_RANK = {"safe": 0, "warn": 1, "block": 2}


@dataclass
class Row:
    dep: Dependency
    verdict: str = "safe"          # fast 모드는 취약점 심각도로 warn/block 을 정하지 않는다
    vulns: list[VulnInfo] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    risk_score: int | None = None
    error: str | None = None
    sources: list[str] = field(default_factory=list)

    @property
    def max_severity(self) -> str | None:
        if not self.vulns:
            return None
        return max(self.vulns, key=lambda v: SEVERITY_ORDER[v.severity]).severity.value


@dataclass
class Report:
    mode: str
    rows: list[Row] = field(default_factory=list)
    #: (의존성, 사유) — 확인하지 못한 것
    unchecked: list[tuple[Dependency, str]] = field(default_factory=list)

    def counts(self) -> dict:
        verdicts = Counter(r.verdict for r in self.rows if r.error is None)
        sev = Counter(r.max_severity for r in self.rows if r.vulns)
        return {
            "checked": len(self.rows), "unchecked": len(self.unchecked),
            "errors": sum(1 for r in self.rows if r.error),
            "verdict": dict(verdicts), "severity": {k: v for k, v in sev.items() if k},
        }

    def results_map(self) -> dict:
        """sbom.write_cyclonedx 에 넘기는 형태."""
        return {
            (r.dep.ecosystem, r.dep.name, r.dep.version): {
                "verdict": r.verdict, "findings": r.findings,
                "vulns": [{"id": v.id, "severity": v.severity.value, "summary": v.summary,
                           "fixed": v.fixed} for v in r.vulns]}
            for r in self.rows
        }

    def fails(self, fail_on: str) -> bool:
        """``--fail-on`` 기준에 걸리는가. 조회 오류가 있으면 통과시키지 않는다(실패로 본다)."""
        if any(r.error for r in self.rows):
            return True
        if fail_on == "block":
            return any(r.verdict == "block" for r in self.rows)
        if fail_on == "warn":
            return any(_VERDICT_RANK.get(r.verdict, 0) >= 1 for r in self.rows) or any(
                r.vulns for r in self.rows)
        need = {"vuln-high": 3, "vuln-critical": 4}.get(fail_on)
        if need is None:
            raise ValueError(f"알 수 없는 --fail-on: {fail_on}")
        return any(SEVERITY_ORDER[v.severity] >= need for r in self.rows for v in r.vulns)


ScanFn = Callable[[Dependency], Awaitable[dict]]


async def scan_dependencies(
    deps: list[Dependency], *, mode: str = "fast", client: httpx.AsyncClient,
    sources: dict | None = None, scan_fn: ScanFn | None = None, concurrency: int = 4,
) -> Report:
    if mode not in ("fast", "full"):
        raise ValueError("mode 는 fast | full")
    report = Report(mode=mode)
    table = {e.id: e for e in ecosystems.available()}
    pinned: list[Dependency] = []
    for dep in deps:
        if dep.version is None:
            report.unchecked.append((dep, "not checked — unpinned (정확한 버전 없음)"))
        elif dep.ecosystem not in table:
            report.unchecked.append((dep, f"not checked — {dep.ecosystem} 어댑터 없음"))
        else:
            pinned.append(dep)

    outcomes = await query_batch(
        [OsvQuery(table[d.ecosystem].osv_ecosystem, d.name, d.version) for d in pinned],
        client=client)
    for dep, out in zip(pinned, outcomes, strict=True):
        key = (dep.ecosystem, table[dep.ecosystem].normalize_name(dep.name), dep.version)
        row = Row(dep, vulns=out.vulns, error=out.error, sources=(sources or {}).get(key, []))
        if out.error:
            row.reasons.append(f"OSV 조회 실패: {out.error}")
        report.rows.append(row)

    if mode == "full":
        fn = scan_fn or _default_scan_fn(client)
        sem = asyncio.Semaphore(concurrency)

        async def one(row: Row) -> None:
            async with sem:
                try:
                    res = await fn(row.dep)
                except Exception as exc:  # 한 패키지 실패가 전체를 막지 않게
                    row.error = f"전체 스캔 실패: {exc}"
                    row.reasons.append(row.error)
                    return
            row.verdict = res.get("verdict", "warn")
            row.risk_score = res.get("risk_score")
            row.reasons += res.get("verdict_reasons") or []
            row.findings = [f"{f.get('rule')} {f.get('severity')} {f.get('location')}"
                            for f in res.get("static_findings") or []]
            if res.get("layer_errors"):
                row.reasons += [f"레이어 오류: {e}" for e in res["layer_errors"]]

        await asyncio.gather(*(one(r) for r in report.rows if not r.error))
    return report


def _default_scan_fn(client: httpx.AsyncClient) -> ScanFn:
    """api.routers.scan.run_scan 을 지연 import 해서 부른다 (무거운 import 를 fast 에서 피함)."""
    async def run(dep: Dependency) -> dict:
        from api.routers.scan import run_scan
        from api.schemas import ScanRequest
        from api.storage import ScanStore

        store = ScanStore()
        await store.init()
        req = ScanRequest(ecosystem=dep.ecosystem, name=dep.name, version=dep.version)
        return (await run_scan(req, http=client, store=store)).model_dump(mode="json")

    return run
