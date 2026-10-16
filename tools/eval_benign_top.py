"""정상 패키지 오탐률 — PyPI 다운로드 상위 N 개의 최신 버전을 커스텀 규칙으로 스캔.

목록: hugovk/top-pypi-packages (최근 30일 다운로드 순). 최신 릴리스의 sdist 를 우선
받는다(설치 시점 코드인 setup.py 는 sdist 에만 있다 — common.pypi.select_artifact).
실행하지 않고 정적분석만 한다. eval_malware_dataset.py 와 짝: 그쪽이 탐지율, 이쪽이 오탐률.

사용:
    uv run python tools/eval_benign_top.py --n 300
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

TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"


async def scan_one(name: str, http: httpx.AsyncClient, sem: asyncio.Semaphore) -> dict:
    async with sem:
        try:
            version = (await fetch_project(name, client=http)).info.get("version")
            req = ScanRequest(name=name, version=version)
            async with PackageContext(name, version, client=http) as ctx:
                findings = await analyze_package(req, ctx=ctx)
        except (PyPIError, ValueError, httpx.HTTPError) as exc:
            return {"name": name, "status": "error", "error": str(exc)[:200]}
    high = [f for f in findings if f.severity.value in ("high", "critical")]
    return {
        "name": name,
        "version": version,
        "status": "ok",
        "blocked": bool(high),
        "high": [{"rule": f.rule, "location": f.location, "detail": f.detail[:200]} for f in high],
    }


async def run(n: int, concurrency: int) -> list[dict]:
    async with httpx.AsyncClient(timeout=120, follow_redirects=True) as http:
        top = (await http.get(TOP_URL)).json()["rows"][:n]
        sem = asyncio.Semaphore(concurrency)
        return await asyncio.gather(*(scan_one(r["project"], http, sem) for r in top))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--concurrency", type=int, default=6)
    ap.add_argument("--out", type=Path, default=Path("benign-results.json"))
    args = ap.parse_args()

    results = asyncio.run(run(args.n, args.concurrency))
    ok = [r for r in results if r["status"] == "ok"]
    summary = {
        "packages": len(results),
        "analyzed": len(ok),
        "errors": len(results) - len(ok),
        "blocked": sum(r["blocked"] for r in ok),
        "false_positive_rate": round(sum(r["blocked"] for r in ok) / (len(ok) or 1), 3),
        "high_rule_counts": dict(Counter(h["rule"] for r in ok for h in r.get("high", []))),
        "blocked_packages": [r["name"] for r in ok if r["blocked"]],
    }
    args.out.write_text(json.dumps({"summary": summary, "results": results},
                                   ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
