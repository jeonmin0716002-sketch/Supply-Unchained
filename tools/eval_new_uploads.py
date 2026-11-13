"""신규 업로드의 운영 오탐률 재측정 — 감시기 DB 를 읽기 전용으로 열어 현재 엔진으로 다시 스캔.

README 의 오탐률 0.7% 는 다운로드 상위 300개(성숙한 패키지)에서 잰 값이라, 갓 올라온
패키지의 실제 block 비율을 대표하지 않는다. 그래서 감시기가 실제로 본 릴리스로 잰다:

(a) 예전에 ``block`` 이던 릴리스 전부를 지금 엔진(커스텀 정적 규칙)으로 다시 스캔한다.
    그 뒤 엔진 수정이 여럿 들어갔으므로 "지금도 막히는가"가 핵심이다. PyPI 에서 이미
    사라진 릴리스는 ``removed`` 로 따로 센다 — 그 자체가 악성 쪽 증거다.
(b) 감시한 전체 릴리스에서 시드 고정 무작위 표본(기본 500)을 다시 스캔해, 평범한 신규
    업로드의 block 비율을 Wilson 신뢰구간과 함께 낸다.

패키지를 설치·실행하지 않는다 — 내려받아 안전 추출한 뒤 읽기만 한다(common.pypi).
DB 는 ``mode=ro`` 로만 연다. 결과는 JSON + 규칙별 요약.

사용:
    uv run python tools/eval_new_uploads.py --db data/supply_unchained.db --out new-uploads.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import random
import sqlite3
import sys
from collections import Counter
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api.schemas import ScanRequest
from common.pypi import PackageContext, PackageNotFound, PyPIError
from engine import analyze_package


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """이항 비율의 Wilson 구간. n=0 이면 (0, 1)."""
    if n == 0:
        return 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (c - h) / d), min(1.0, (c + h) / d)


def open_ro(path: str) -> sqlite3.Connection:
    uri = Path(path).resolve().as_uri() + "?mode=ro"
    return sqlite3.connect(uri, uri=True)


def previously_blocked(db: sqlite3.Connection) -> list[dict]:
    """한 번이라도 block 이던 (name, version) — 큐 상태(오탐 표시 등)를 함께 붙인다."""
    q = {
        (n, v): s for n, v, s in db.execute(
            "SELECT name, version, status FROM watch_queue WHERE verdict = 'block'"
        )
    }
    rows = db.execute(
        "SELECT DISTINCT name, version FROM scans WHERE verdict = 'block' ORDER BY name, version"
    ).fetchall()
    return [{"name": n, "version": v, "queue_status": q.get((n, v))} for n, v in rows]


def sample_releases(db: sqlite3.Connection, n: int, seed: int) -> list[dict]:
    """감시한 모든 릴리스(watch_seen, '(removed)' 표시 제외)에서 시드 고정 표본."""
    rows = db.execute(
        "SELECT name, version FROM watch_seen WHERE version != '(removed)' ORDER BY name, version"
    ).fetchall()
    rng = random.Random(seed)
    pick = rng.sample(rows, min(n, len(rows)))
    return [{"name": a, "version": b} for a, b in pick], len(rows)


async def scan_one(item: dict, http: httpx.AsyncClient, sem: asyncio.Semaphore) -> dict:
    name, version = item["name"], item["version"]
    out = dict(item)
    async with sem:
        try:
            req = ScanRequest(name=name, version=version)
            async with PackageContext(name, version, client=http) as ctx:
                findings = await analyze_package(req, ctx=ctx)
        except PackageNotFound:
            return {**out, "status": "removed"}
        except (PyPIError, ValueError, httpx.HTTPError) as exc:
            return {**out, "status": "error", "error": str(exc)[:200]}
    high = [f for f in findings if f.severity.value in ("high", "critical")]
    return {
        **out,
        "status": "ok",
        "blocked": bool(high),
        "high": [
            {"rule": f.rule, "location": f.location, "detail": f.detail[:300]} for f in high
        ],
    }


async def run(items: list[dict], concurrency: int) -> list[dict]:
    async with httpx.AsyncClient(timeout=120, follow_redirects=True) as http:
        sem = asyncio.Semaphore(concurrency)
        return await asyncio.gather(*(scan_one(i, http, sem) for i in items))


def summarize(results: list[dict]) -> dict:
    ok = [r for r in results if r["status"] == "ok"]
    blocked = [r for r in ok if r["blocked"]]
    lo, hi = wilson(len(blocked), len(ok))
    return {
        "releases": len(results),
        "analyzed": len(ok),
        "removed": sum(r["status"] == "removed" for r in results),
        "errors": sum(r["status"] == "error" for r in results),
        "blocked": len(blocked),
        "block_rate": round(len(blocked) / (len(ok) or 1), 4),
        "wilson95": [round(lo, 4), round(hi, 4)],
        "rule_counts": dict(Counter(h["rule"] for r in blocked for h in r["high"])),
        "blocked_releases": [f"{r['name']}=={r['version']}" for r in blocked],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--db", required=True, help="감시기 SQLite (읽기 전용으로 연다)")
    ap.add_argument("--sample", type=int, default=500)
    ap.add_argument("--seed", type=int, default=20261113)
    ap.add_argument("--concurrency", type=int, default=6)
    ap.add_argument("--out", type=Path, default=Path("new-uploads-results.json"))
    args = ap.parse_args()

    db = open_ro(args.db)
    prev = previously_blocked(db)
    sample, population = sample_releases(db, args.sample, args.seed)
    db.close()

    print(f"이전 block {len(prev)}건 재스캔 …", flush=True)
    prev_res = asyncio.run(run(prev, args.concurrency))
    print(f"무작위 표본 {len(sample)}/{population}건 재스캔 …", flush=True)
    samp_res = asyncio.run(run(sample, args.concurrency))

    summary = {
        "previously_blocked": summarize(prev_res),
        "random_sample": {**summarize(samp_res), "population": population, "seed": args.seed},
    }
    args.out.write_text(
        json.dumps(
            {"summary": summary, "previously_blocked": prev_res, "random_sample": samp_res},
            ensure_ascii=False, indent=1,
        ),
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
