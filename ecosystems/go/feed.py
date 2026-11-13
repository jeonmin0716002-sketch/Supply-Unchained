"""Go 모듈 인덱스(index.golang.org) 피드 — 프록시가 새로 캐시한 (모듈, 버전).

``/index?since=<RFC3339>&limit=2000`` 은 인증 없이 동작하고 줄마다 JSON
``{"Path","Version","Timestamp"}`` 를 돌려준다(실측: 20분에 1,200여 줄). ``since`` 를 최근 시각으로
잡아 그 이후만 가져온다. 이전 호출 이후 간격이 크면 limit 에서 잘려 최신 쪽을 놓칠 수 있으므로,
감시기는 짧은 주기로 돌려야 한다 — 잘렸을 때는 오류로 알린다.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx

INDEX = "https://index.golang.org/index"
LIMIT = 2000
#: ``fetch_feed`` 가 거슬러 올라가는 기본 시간 창
WINDOW = timedelta(minutes=15)


async def fetch_feed(
    client: httpx.AsyncClient, *, since: datetime | None = None
) -> tuple[list[tuple[str, str | None]], list[str]]:
    start = (since or datetime.now(UTC) - WINDOW).astimezone(UTC)
    params = {"since": start.strftime("%Y-%m-%dT%H:%M:%SZ"), "limit": str(LIMIT)}
    try:
        resp = await client.get(INDEX, params=params)
    except httpx.HTTPError as exc:
        return [], [f"go index feed: {exc}"]
    if resp.status_code != 200:
        return [], [f"go index feed: HTTP {resp.status_code}"]
    out: list[tuple[str, str | None]] = []
    errors: list[str] = []
    seen: set[tuple[str, str]] = set()
    lines = [ln for ln in resp.text.splitlines() if ln.strip()]
    for ln in lines:
        try:
            item = json.loads(ln)
            path, version = item["Path"], item["Version"]
        except (ValueError, KeyError, TypeError):
            errors.append("go index feed: 해석할 수 없는 줄")
            continue
        if (path, version) not in seen:
            seen.add((path, version))
            out.append((path, version))
    if len(lines) >= LIMIT:
        errors.append(f"go index feed: {LIMIT}줄 상한에 닿았다 — 이 창의 뒷부분을 놓쳤을 수 있다")
    return out, errors
