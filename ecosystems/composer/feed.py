"""Packagist 신규 업데이트 피드 — 메타데이터 변경 API.

``https://packagist.org/metadata/changes.json?since=<타임스탬프>`` (2026-11 비인증 200 실측).
``since`` 는 유닉스 초 곱하기 10000. 응답 ``actions`` 항목은 type(update·delete·resync)·package
(``vendor/name`` 또는 ``vendor/name~dev``)·time 을 가진다. 버전은 알려주지 않으므로
``(name, None)`` 으로 돌려준다 — 감시기가 최신 버전을 조회한다. ``~dev`` 는 브랜치 갱신이라
같은 이름으로 합친다. ``resync`` (``*``) 는 since 가 너무 오래됐다는 뜻이라 오류로 보고한다.
"""

from __future__ import annotations

import time

import httpx

CHANGES_URL = "https://packagist.org/metadata/changes.json"
#: 감시 주기보다 넉넉하게 — 이전 호출과 겹쳐도 감시기가 같은 (name, version) 을 거른다
WINDOW_SECONDS = 15 * 60


async def fetch_feed(
    client: httpx.AsyncClient, *, now: float | None = None
) -> tuple[list[tuple[str, str | None]], list[str]]:
    since = int(((now if now is not None else time.time()) - WINDOW_SECONDS) * 10000)
    try:
        resp = await client.get(CHANGES_URL, params={"since": since})
        if resp.status_code != 200:
            return [], [f"packagist changes: HTTP {resp.status_code}"]
        data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        return [], [f"packagist changes: {exc}"]
    actions = data.get("actions") if isinstance(data, dict) else None
    if not isinstance(actions, list):
        return [], ["packagist changes: unexpected payload"]
    items: list[tuple[str, str | None]] = []
    errors: list[str] = []
    seen: set[str] = set()
    for act in actions:
        if not isinstance(act, dict):
            continue
        pkg = str(act.get("package") or "")
        if act.get("type") == "resync" or pkg == "*":
            errors.append("packagist changes: resync 요청 — since 가 너무 오래됐다")
            continue
        if act.get("type") != "update" or "/" not in pkg:
            continue
        name = pkg.split("~", 1)[0]
        if name not in seen:
            seen.add(name)
            items.append((name, None))
    return items, errors
