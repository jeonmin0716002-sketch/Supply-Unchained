"""crates.io 신규·갱신 피드 — ``/api/v1/summary`` 의 ``new_crates`` · ``just_updated``.

인증 없이 동작한다(실측). 한 번에 각 10개 안팎이라 짧은 주기로 돌려야 놓치지 않는다 —
그 한계는 호출하는 감시기의 주기 설정 몫이다. 조회 실패는 빈 목록이 아니라 오류로 돌려준다.
"""

from __future__ import annotations

import httpx

from ecosystems.cargo.registry import API, USER_AGENT


async def fetch_feed(client: httpx.AsyncClient) -> tuple[list[tuple[str, str | None]], list[str]]:
    try:
        resp = await client.get(f"{API}/summary", headers={"User-Agent": USER_AGENT})
    except httpx.HTTPError as exc:
        return [], [f"crates.io feed: {exc}"]
    if resp.status_code != 200:
        return [], [f"crates.io feed: HTTP {resp.status_code}"]
    try:
        data = resp.json()
    except ValueError:
        return [], ["crates.io feed: non-JSON body"]
    out: list[tuple[str, str | None]] = []
    seen: set[tuple[str, str | None]] = set()
    for key in ("new_crates", "just_updated"):
        for item in data.get(key) or []:
            name = item.get("name")
            if not isinstance(name, str):
                continue
            version = item.get("newest_version") or item.get("max_version")
            pair = (name, version if isinstance(version, str) else None)
            if pair not in seen:
                seen.add(pair)
                out.append(pair)
    return out, []
