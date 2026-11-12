"""정상 패키지 오탐률 — PyPI 다운로드 상위 N 개의 최신 버전을 커스텀 규칙으로 스캔.

목록: hugovk/top-pypi-packages (최근 30일 다운로드 순). 최신 릴리스의 sdist 를 우선
받는다(설치 시점 코드인 setup.py 는 sdist 에만 있다 — common.pypi.select_artifact).
실행하지 않고 정적분석만 한다. eval_malware_dataset.py 와 짝: 그쪽이 탐지율, 이쪽이 오탐률.

**직전 릴리스 비교도 잰다.** 제품 경로와 똑같이 engine.version_diff.escalate_new_behaviors
를 부른다 — 후보(새로 나타나면 승격될 MEDIUM, 또는 HIGH)가 있을 때만 업로드 시각 기준
직전 릴리스를 받아 비교한다. ``diff_blocked`` 가 "정상 릴리스인데 새 행위로 차단"된 수 —
버전 비교의 오탐률이다. ``--diff-all`` 은 후보와 무관하게 모든 패키지의 직전 릴리스를 받아,
MEDIUM 규칙별로 "새로 나타난" 비율을 잰다 (어떤 규칙을 승격 대상에 넣을지 정하는 근거).

사용:
    uv run python tools/eval_benign_top.py --n 300
    uv run python tools/eval_benign_top.py --n 300 --diff-all
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import Counter
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api.schemas import ScanRequest
from common.pypi import PackageContext, PyPIError, fetch_project
from engine import analyze_package
from engine.rules.install_time import RULE_INSTALL_SPAWN
from engine.version_diff import (
    analyze_release,
    behavior_key,
    escalate_new_behaviors,
    has_candidates,
    previous_version,
)

TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"


async def scan_one(name: str, http: httpx.AsyncClient, sem: asyncio.Semaphore,
                   diff_all: bool = False) -> dict:
    async with sem:
        static_errors: list[str] = []
        diff_errors: list[str] = []
        try:
            project = await fetch_project(name, client=http)
            version = project.info.get("version")
            req = ScanRequest(name=name, version=version)
            async with PackageContext(name, version, client=http) as ctx:
                findings = await analyze_package(req, ctx=ctx, errors=static_errors)
                extra = await escalate_new_behaviors(ctx, findings, errors=diff_errors)
                medium_new: dict[str, int] | None = None
                prev = previous_version(project, version)
                if diff_all and prev is not None:
                    try:
                        before = {behavior_key(f) for f in
                                  await analyze_release(project, prev, client=http)}
                        medium_new = dict(Counter(
                            f.rule for f in findings
                            if f.severity.value == "medium" and behavior_key(f) not in before))
                    except (PyPIError, OSError) as exc:
                        diff_errors.append(f"diff-all: {exc}"[:200])
        except (PyPIError, ValueError, httpx.HTTPError) as exc:
            return {"name": name, "status": "error", "error": str(exc)[:200]}
    high = [f for f in findings if f.severity.value in ("high", "critical")]
    escalated = [f for f in extra if f.severity.value in ("high", "critical")]
    return {
        "name": name,
        "version": version,
        "previous": prev,
        "status": "ok",
        "blocked": bool(high),
        "high": [{"rule": f.rule, "location": f.location, "detail": f.detail[:200]} for f in high],
        "spawn_medium": [f"{f.location} {f.detail[:160]}" for f in findings
                         if f.rule == RULE_INSTALL_SPAWN],
        "diff_candidates": has_candidates(findings),
        "diff_blocked": bool(escalated) and not high,
        "diff_new": [{"location": f.location, "detail": f.detail[:240]} for f in extra],
        "diff_errors": diff_errors,
        "static_errors": static_errors,
        **({"medium_new_by_rule": medium_new} if medium_new is not None else {}),
    }


async def run(n: int, concurrency: int, diff_all: bool = False) -> list[dict]:
    async with httpx.AsyncClient(timeout=120, follow_redirects=True) as http:
        top = (await http.get(TOP_URL)).json()["rows"][:n]
        sem = asyncio.Semaphore(concurrency)
        return await asyncio.gather(*(scan_one(r["project"], http, sem, diff_all)
                                      for r in top))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--concurrency", type=int, default=6)
    ap.add_argument("--out", type=Path, default=Path("benign-results.json"))
    ap.add_argument("--diff-all", action="store_true",
                    help="모든 패키지의 직전 릴리스를 받아 MEDIUM 규칙별 '새로 나타남' 비율을 잰다")
    args = ap.parse_args()

    results = asyncio.run(run(args.n, args.concurrency, args.diff_all))
    ok = [r for r in results if r["status"] == "ok"]
    summary = {
        "packages": len(results),
        "analyzed": len(ok),
        "errors": len(results) - len(ok),
        "blocked": sum(r["blocked"] for r in ok),
        "false_positive_rate": round(sum(r["blocked"] for r in ok) / (len(ok) or 1), 3),
        "high_rule_counts": dict(Counter(h["rule"] for r in ok for h in r.get("high", []))),
        "blocked_packages": [r["name"] for r in ok if r["blocked"]],
        "spawn_medium_packages": sum(bool(r["spawn_medium"]) for r in ok),
        "version_diff": {
            "with_previous_release": sum(r["previous"] is not None for r in ok),
            "candidates_downloaded_previous": sum(r["diff_candidates"] for r in ok),
            "diff_blocked": sum(r["diff_blocked"] for r in ok),
            "diff_blocked_packages": [r["name"] for r in ok if r["diff_blocked"]],
            "false_positive_rate_with_diff": round(
                sum(r["blocked"] or r["diff_blocked"] for r in ok) / (len(ok) or 1), 3),
            "diff_errors": sum(bool(r["diff_errors"]) for r in ok),
        },
        "static_errors": [f"{r['name']}: {e}" for r in ok for e in r["static_errors"]],
        **({"medium_new_by_rule": dict(sum(
            (Counter(r["medium_new_by_rule"]) for r in ok if "medium_new_by_rule" in r),
            Counter()))} if args.diff_all else {}),
    }
    args.out.write_text(json.dumps({"summary": summary, "results": results},
                                   ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
