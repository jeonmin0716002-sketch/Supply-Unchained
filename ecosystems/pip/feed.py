"""PyPI 신규 업로드 피드 — watcher.feed 에 위임 (구현과 실측 근거는 그쪽에 있다)."""

from __future__ import annotations

import httpx


async def fetch_feed(client: httpx.AsyncClient) -> tuple[list[tuple[str, str | None]], list[str]]:
    # 지연 import: watcher 는 api.routers.scan 을 끌어오므로 어댑터 import 시점에 부르면
    # ScanRequest 검증 → ecosystems.get → 이 모듈 → scan 의 순환이 생긴다.
    from watcher.feed import fetch_feeds

    return await fetch_feeds(client)
