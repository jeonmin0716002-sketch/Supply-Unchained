"""감시 한 주기 — 피드 수집 → 처음 보는 릴리스만 스캔 → 의심 건을 검토 큐에.

스캔은 ``api.routers.scan.run_scan`` 을 그대로 쓴다. 즉 감시기도 패키지를 **설치하거나
실행하지 않는다** — 아카이브를 받아 안전 추출 후 정적분석만 한다(common/pypi.py).
신뢰할 수 없는 업로드를 하루 수천 건 다루는 도구라 이 원칙이 가장 중요하다.

큐에 넣는 기준(``is_suspicious``)이 판정(verdict)과 다른 이유가 둘 있다.

* WARN 의 대부분은 "정상 패키지의 구버전에 알려진 CVE 가 있다"인데, 감시기의 목적은
  악성 패키지 헌팅이라 그건 노이즈다.
* 메타데이터 위험도(risk_score)도 쓰지 않는다. 감시 대상이 전부 갓 올라온 패키지라
  "신규 계정"(+25) 신호가 항상 켜져 있고, 배포 버스트(+15)나 설치 스크립트(+20) 하나만
  더해져도 주의 임계 40 에 닿는다. 실측(2026-10-16, PyPI 60건): 위험도만으로 걸린 6건이
  전부 이 조합이었고 typosquat 유사도는 0.38~0.60 — 평범한 새 패키지였다.

그래서 BLOCK 이거나, 새 패키지에서도 변별력이 남는 메타데이터 신호인 typosquat 유사도가
높은(``TYPOSQUAT_MIN_RATIO`` 이상) 것만 올린다.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx

from api.schemas import ScanRequest
from api.storage import ScanStore
from common.pypi import PyPIError, fetch_project
from scoring.features import TYPOSQUAT_MIN_RATIO
from watcher.feed import fetch_feeds

Item = tuple[str, str | None]
FetchFn = Callable[[httpx.AsyncClient], Awaitable[tuple[list[Item], list[str]]]]
ResolveFn = Callable[[str, httpx.AsyncClient], Awaitable[str]]


@dataclass
class CycleReport:
    fetched: int = 0                       # 피드에서 읽은 항목 수 (중복 제거 후)
    scanned: int = 0
    deferred: int = 0                      # max_scans 초과로 다음 주기로 미룬 수
    flagged: list[dict] = field(default_factory=list)       # 큐에 넣은 스캔 결과
    failed: list[tuple[str, str]] = field(default_factory=list)  # (spec, 사유)
    skipped_invalid: list[str] = field(default_factory=list)     # 이름/버전 검증 실패
    feed_errors: list[str] = field(default_factory=list)


def is_suspicious(record: dict) -> bool:
    if record["verdict"] == "block":
        return True
    signals = record.get("risk_signals") or {}
    return (signals.get("typosquat_score") or 0.0) >= TYPOSQUAT_MIN_RATIO


async def resolve_latest(name: str, http: httpx.AsyncClient) -> str:
    project = await fetch_project(name, client=http)
    version = project.info.get("version")
    if not version:
        raise PyPIError(f"{name}: PyPI JSON 에 최신 버전이 없음")
    return version


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


async def run_cycle(
    *,
    http: httpx.AsyncClient,
    store: ScanStore,
    scan: Callable[..., Awaitable],
    fetch: FetchFn = fetch_feeds,
    resolve: ResolveFn = resolve_latest,
    max_scans: int = 50,
    concurrency: int = 3,
) -> CycleReport:
    report = CycleReport()
    items, report.feed_errors = await fetch(http)
    items = list(dict.fromkeys(items))
    report.fetched = len(items)

    # 신규 프로젝트 피드는 버전이 없다. 이미 본 이름이면 최신 버전 조회를 건너뛴다 —
    # 그 뒤의 릴리스는 updates 피드로 들어오므로, 매 주기 40건씩 JSON 을 다시 받을 이유가 없다.
    known = await store.seen_names([n for n, v in items if v is None])
    sem = asyncio.Semaphore(concurrency)

    async def _resolve(name: str) -> tuple[str, str] | None:
        async with sem:
            try:
                return name, await resolve(name, http)
            except (PyPIError, httpx.HTTPError) as exc:
                report.failed.append((name, f"최신 버전 조회 실패: {exc}"))
                return None

    resolved = await asyncio.gather(
        *(_resolve(n) for n, v in items if v is None and n not in known)
    )
    candidates = [(n, v) for n, v in items if v is not None] + [r for r in resolved if r]

    requests: list[ScanRequest] = []
    for name, version in dict.fromkeys(candidates):
        try:
            requests.append(ScanRequest(name=name, version=version))
        except ValueError:
            report.skipped_invalid.append(f"{name}=={version}")

    pending = await store.unseen([(r.name, r.version) for r in requests])
    report.deferred = max(0, len(pending) - max_scans)
    todo = {p for p in pending[:max_scans]}
    requests = [r for r in requests if (r.name, r.version) in todo]

    async def _scan(req: ScanRequest) -> None:
        async with sem:
            try:
                result = await scan(req, http=http, store=store)
            except Exception as exc:  # 한 패키지 실패가 주기 전체를 죽이면 안 됨
                # seen 으로 표시하지 않는다 — 피드에 남아 있는 동안 다음 주기에 재시도된다.
                report.failed.append((f"{req.name}=={req.version}", str(exc)))
                return
        record = result.model_dump(mode="json")
        await store.mark_seen(req.name, req.version, _now())
        report.scanned += 1
        if is_suspicious(record):
            await store.enqueue(record, _now())
            report.flagged.append(record)

    await asyncio.gather(*(_scan(r) for r in requests))
    return report
