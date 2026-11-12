"""RubyGems 신규 업로드 피드 — 인증 없이 되는 ``activity/latest``(새 gem)·``just_updated``(새 버전).

2026-11 실측: 둘 다 200, 각 약 50건, 항목에 name·version·version_created_at.
"""

from __future__ import annotations

import httpx

LATEST_URL = "https://rubygems.org/api/v1/activity/latest.json"
JUST_UPDATED_URL = "https://rubygems.org/api/v1/activity/just_updated.json"


async def fetch_feed(
    client: httpx.AsyncClient,
) -> tuple[list[tuple[str, str | None]], list[str]]:
    items: list[tuple[str, str | None]] = []
    errors: list[str] = []
    seen: set[tuple[str, str | None]] = set()
    for label, url in (("latest", LATEST_URL), ("just_updated", JUST_UPDATED_URL)):
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                errors.append(f"rubygems {label}: HTTP {resp.status_code}")
                continue
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(f"rubygems {label}: {exc}")
            continue
        if not isinstance(data, list):
            errors.append(f"rubygems {label}: unexpected payload")
            continue
        for row in data:
            if not isinstance(row, dict) or not row.get("name"):
                continue
            key = (str(row["name"]), str(row["version"]) if row.get("version") else None)
            if key not in seen:
                seen.add(key)
                items.append(key)
    return items, errors
