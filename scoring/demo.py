"""Manual test helper for the scoring layer -- score any package by hand.

Usage (from repo root):
    python -m scoring.demo <name> [version]
    python scoring/demo.py requests 2.31.0
    python scoring/demo.py reqeusts            # version optional -> latest

Prints the individual risk signals, how they add up to the 0-100 score, and the
human-readable reasons. This exercises the real scoring layer (live PyPI
metadata); it does not run the CVE / static-analysis layers.
"""

from __future__ import annotations

import asyncio
import sys

import httpx

from scoring.collector import collect
from scoring.scorer import build_signals, compute_score

# Scoring-layer view of the verdict thresholds (final verdict also folds in the
# CVE + static-analysis layers, which this demo does not run).
WARN_AT = 40
BLOCK_AT = 70

BAR = "=" * 56


async def _latest_version(name: str) -> str | None:
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as c:
        try:
            r = await c.get(f"https://pypi.org/pypi/{name}/json")
            if r.status_code == 200:
                return r.json()["info"]["version"]
        except httpx.HTTPError:
            return None
    return None


def _band(score: int) -> str:
    if score >= BLOCK_AT:
        return "BLOCK  (>= 70)"
    if score >= WARN_AT:
        return "WARN   (>= 40)"
    return "safe   (< 40)"


async def run(name: str, version: str | None) -> None:
    if not version:
        version = await _latest_version(name)
        if version is None:
            version = "0"

    meta = await collect(name, version)
    signals = build_signals(name, meta)
    score, reasons = compute_score(signals)

    print(BAR)
    print(f"  {name} == {version}")
    print(f"  found on PyPI: {meta.found}" + (f"  ({meta.note})" if meta.note else ""))
    print(BAR)
    print("  risk signals")
    print(f"    is_new_account     : {signals.is_new_account}")
    print(f"    typosquat_score    : {signals.typosquat_score:.2f}"
          + ("   <- resembles a popular package" if signals.typosquat_score >= 0.80 else ""))
    print(f"    has_install_script : {signals.has_install_script}")
    print(f"    release_burst      : {signals.release_burst}")
    print(f"    dependency_count   : {signals.dependency_count}")
    print(BAR)
    print(f"  RISK SCORE : {score:3d} / 100   ->  {_band(score)}")
    print("  why:")
    for r in reasons:
        print(f"    - {r}")
    print(BAR)


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: python -m scoring.demo <name> [version]")
        raise SystemExit(1)
    name = sys.argv[1]
    version = sys.argv[2] if len(sys.argv) > 2 else None
    asyncio.run(run(name, version))


if __name__ == "__main__":
    main()
