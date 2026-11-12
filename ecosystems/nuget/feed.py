"""NuGet 카탈로그 → 새로 올라온 ``(id, version)``.

카탈로그 루트의 페이지는 오래된 것부터 정렬돼 있고(실측: 마지막이 최신), 페이지 항목도
시간순이다. 최신 몇 페이지만 받는다 — 페이지 수는 상한이 있어 호출 비용이 일정하다.
``nuget:PackageDelete`` 항목은 새 업로드가 아니므로 뺀다.
"""

from __future__ import annotations

import httpx

CATALOG_INDEX = "https://api.nuget.org/v3/catalog0/index.json"
#: 한 번에 읽을 최신 페이지 수 (페이지당 약 500~2000건)
MAX_PAGES = 2
MAX_ITEMS = 1500


async def fetch_feed(client: httpx.AsyncClient) -> tuple[list[tuple[str, str | None]], list[str]]:
    errors: list[str] = []
    try:
        resp = await client.get(CATALOG_INDEX)
        resp.raise_for_status()
        pages = resp.json().get("items") or []
    except (httpx.HTTPError, ValueError) as exc:
        return [], [f"nuget catalog index: {exc}"]
    pages = sorted(
        (p for p in pages if isinstance(p, dict) and p.get("@id")),
        key=lambda p: str(p.get("commitTimeStamp", "")),
    )[-MAX_PAGES:]

    out: list[tuple[str, str | None]] = []
    seen: set[tuple[str, str | None]] = set()
    for page in reversed(pages):  # 최신 페이지부터
        url = str(page["@id"])
        if not url.startswith("https://api.nuget.org/"):
            errors.append(f"nuget catalog page: unexpected url {url!r}")
            continue
        try:
            r = await client.get(url)
            r.raise_for_status()
            items = r.json().get("items") or []
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(f"nuget catalog page {url}: {exc}")
            continue
        for item in reversed(items):
            if not isinstance(item, dict) or "PackageDetails" not in str(item.get("@type")):
                continue
            pkg, ver = item.get("nuget:id"), item.get("nuget:version")
            if isinstance(pkg, str) and isinstance(ver, str) and (pkg, ver) not in seen:
                seen.add((pkg, ver))
                out.append((pkg, ver))
            if len(out) >= MAX_ITEMS:
                return out, errors
    return out, errors
