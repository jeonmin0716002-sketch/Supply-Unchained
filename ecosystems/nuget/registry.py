"""NuGet v3 API → ``Project``.

등록 인덱스(registration5-gz-semver2)는 페이지로 나뉜다. 버전이 많은 패키지는 페이지에
``items`` 가 없고 ``@id`` 로 따로 받아야 한다. 실측(2026-11): 인덱스·페이지 모두 gzip 이고
httpx 가 자동으로 푼다. 없는 패키지는 404.

* ``published`` 가 1900-01-01 이면 목록에서 내려간(unlisted) 버전이다 — 시각을 모르는 것으로
  취급하고(None) ``yanked`` 로 표시해 "직전 버전" 계산에서 빠지게 한다.
* 다운로드 주소는 직접 조립하지 않고 ``packageContent`` 를 쓴다 (버전 정규화 규칙이 있다).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from common.pypi import PackageNotFound, PyPIError
from ecosystems.base import Artifact, Project, Release

REGISTRATION_URL = "https://api.nuget.org/v3/registration5-gz-semver2/{lower}/index.json"
#: 보호: 등록 페이지가 비정상적으로 많아도 이 이상은 따라가지 않는다.
MAX_PAGES = 60
_UNLISTED_YEAR = 1900


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.year <= _UNLISTED_YEAR:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


async def _get_json(client: httpx.AsyncClient, url: str, what: str) -> dict[str, Any] | None:
    try:
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        raise PyPIError(f"NuGet lookup failed for {what}: {exc}") from exc
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise PyPIError(f"NuGet returned {resp.status_code} for {what}")
    try:
        data = resp.json()
    except ValueError as exc:
        raise PyPIError(f"NuGet returned a non-JSON body for {what}") from exc
    if not isinstance(data, dict):
        raise PyPIError(f"NuGet returned an unexpected body for {what}")
    return data


def _release_from_entry(entry: dict[str, Any], leaf_content: str | None) -> Release | None:
    version = entry.get("version")
    if not isinstance(version, str) or not version:
        return None
    content = entry.get("packageContent") or leaf_content
    listed = entry.get("listed", True) is not False
    deps: list[str] = []
    for group in entry.get("dependencyGroups") or []:
        for dep in group.get("dependencies") or []:
            dep_id = dep.get("id")
            if isinstance(dep_id, str) and dep_id not in deps:
                deps.append(dep_id)
    artifacts: list[Artifact] = []
    if isinstance(content, str) and content.startswith("https://"):
        artifacts.append(Artifact(
            filename=content.rsplit("/", 1)[-1], url=content, kind="nupkg",
            archive_format="zip",
        ))
    return Release(
        version=version,
        uploaded_at=_parse_time(entry.get("published")),
        artifacts=artifacts,
        yanked=not listed,
        dependencies=deps,
    )


async def fetch_project(name: str, *, client: httpx.AsyncClient) -> Project:
    index = await _get_json(client, REGISTRATION_URL.format(lower=name.lower()), name)
    if index is None:
        raise PackageNotFound(f"{name} is not on NuGet (never existed, or removed)")

    pages = index.get("items") or []
    if len(pages) > MAX_PAGES:
        raise PyPIError(f"NuGet registration for {name} has too many pages ({len(pages)})")

    releases: dict[str, Release] = {}
    authors: list[str] = []
    repo: str | None = None
    for page in pages:
        leaves = page.get("items")
        if leaves is None:  # 페이지 본문이 인덱스에 안 들어 있는 큰 패키지
            page_url = page.get("@id")
            if not isinstance(page_url, str) or not page_url.startswith("https://api.nuget.org/"):
                raise PyPIError(f"NuGet registration page for {name} has no usable URL")
            body = await _get_json(client, page_url, f"{name} (page)")
            if body is None:
                raise PyPIError(f"NuGet registration page for {name} disappeared")
            leaves = body.get("items") or []
        for leaf in leaves:
            entry = leaf.get("catalogEntry") or {}
            rel = _release_from_entry(entry, leaf.get("packageContent"))
            if rel is None:
                continue
            releases[rel.version] = rel
            if not authors and entry.get("authors"):
                authors = [a.strip() for a in str(entry["authors"]).split(",") if a.strip()]
            if not repo and isinstance(entry.get("projectUrl"), str):
                repo = entry["projectUrl"]

    def _rank(r: Release) -> datetime:
        return r.uploaded_at or datetime.min.replace(tzinfo=UTC)

    stable = [r for r in releases.values() if not r.yanked and "-" not in r.version]
    pool = stable or [r for r in releases.values() if not r.yanked]
    latest = max(pool, key=_rank).version if pool else None
    return Project(
        ecosystem="nuget", name=name, latest=latest, releases=releases,
        repository_url=repo, maintainers=authors,
    )
