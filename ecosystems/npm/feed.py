"""npm 신규 업로드 피드 — 레지스트리 복제 changes 피드(``replicate.npmjs.com/_changes``).

2026-11-13 실측: 인증 없이 ``?limit=N&descending=true`` 가 최신 변경부터 돌려준다
(``{"results":[{"seq":..,"id":"<name>","changes":[{"rev":..}]}],"last_seq":..}``). 문서는
포함되지 않아(``include_docs`` 는 2025 년 폐지) **버전은 모른다** — ``(name, None)`` 으로 내고,
감시기가 packument 를 따로 조회해 최신 버전을 정한다.

한계 (docs/eval/npm.md): 변경 피드라 새 버전뿐 아니라 메타데이터 수정·deprecate·unpublish 도
섞여 온다. 한 번에 받는 양은 ``limit`` 으로 정한다 — npm 은 초당 수십 건이 바뀌므로 폴링
간격 동안의 변경을 다 받으려면 ``limit`` 을 크게(기본 500) 잡아야 한다. 놓친 구간은 감시기가
``since=<last_seq>`` 로 이어 받는 쪽이 정확하지만, 계약(fetch_feed(client))에 상태가 없어
여기서는 최신 N 건만 준다.
"""

from __future__ import annotations

import httpx

CHANGES_URL = "https://replicate.npmjs.com/_changes"
FEED_LIMIT = 500


async def fetch_feed(
    client: httpx.AsyncClient, *, limit: int = FEED_LIMIT
) -> tuple[list[tuple[str, str | None]], list[str]]:
    try:
        resp = await client.get(CHANGES_URL, params={"limit": limit, "descending": "true"},
                                headers={"Accept": "application/json"})
        resp.raise_for_status()
        doc = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        return [], [f"npm changes feed: {exc}"[:300]]
    results = doc.get("results") if isinstance(doc, dict) else None
    if not isinstance(results, list):
        return [], ["npm changes feed: unexpected response shape"]
    out: list[tuple[str, str | None]] = []
    seen: set[str] = set()
    for r in results:
        name = r.get("id") if isinstance(r, dict) else None
        # 설계 문서(_design/...) 는 패키지가 아니다; 삭제 표시도 감시 대상이 아니다
        if not isinstance(name, str) or name.startswith("_") or r.get("deleted"):
            continue
        if name not in seen:
            seen.add(name)
            out.append((name, None))
    return out, []


__all__ = ["CHANGES_URL", "fetch_feed"]
