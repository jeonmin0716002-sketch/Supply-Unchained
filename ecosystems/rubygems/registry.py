"""rubygems.org 조회 — 버전 목록과 gem 메타데이터를 공통 ``Project`` 로.

``/api/v1/versions/<name>.json`` 은 철회(yank)된 버전을 빼고 모든 버전을 준다. 같은 버전이
플랫폼별로 여러 줄이다 (``ruby`` 순수 gem 과 ``x86_64-linux`` 같은 사전 빌드 gem) — 사용자는
자기 플랫폼 것을 받으므로 릴리스 하나에 아티팩트를 여럿 둔다.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

import httpx

from common.pypi import PackageNotFound, PyPIError
from ecosystems.base import Artifact, Project, Release

BASE = "https://rubygems.org"
VERSIONS_URL = BASE + "/api/v1/versions/{name}.json"
GEM_URL = BASE + "/api/v1/gems/{name}.json"
DOWNLOAD_URL = BASE + "/downloads/{filename}"

_PLATFORM_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,63}$")
_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z]*(?:[._][0-9A-Za-z]+)*$")


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


async def _get_json(client: httpx.AsyncClient, url: str, name: str) -> Any:
    try:
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        raise PyPIError(f"RubyGems lookup failed for {name}: {exc}") from exc
    if resp.status_code == 404:
        raise PackageNotFound(f"{name} is not on RubyGems (never existed, or removed)")
    if resp.status_code != 200:
        raise PyPIError(f"RubyGems returned {resp.status_code} for {name}")
    try:
        return resp.json()
    except ValueError as exc:
        raise PyPIError(f"RubyGems returned a non-JSON body for {name}") from exc


def gem_filename(name: str, number: str, platform: str) -> str:
    return f"{name}-{number}.gem" if platform in ("", "ruby") else f"{name}-{number}-{platform}.gem"


async def fetch_project(name: str, *, client: httpx.AsyncClient) -> Project:
    rows = await _get_json(client, VERSIONS_URL.format(name=name), name)
    if not isinstance(rows, list):
        raise PyPIError(f"RubyGems returned an unexpected versions payload for {name}")

    releases: dict[str, Release] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        number = str(row.get("number") or "")
        platform = str(row.get("platform") or "ruby")
        if not _VERSION_RE.match(number) or not _PLATFORM_RE.match(platform):
            raise PyPIError(f"RubyGems returned an unusable version entry for {name}: {number!r}")
        created = _parse_time(row.get("created_at"))
        rel = releases.setdefault(number, Release(version=number, uploaded_at=created))
        if created and (rel.uploaded_at is None or created < rel.uploaded_at):
            rel.uploaded_at = created
        filename = gem_filename(name, number, platform)
        sha = row.get("sha")
        rel.artifacts.append(Artifact(
            filename=filename, url=DOWNLOAD_URL.format(filename=filename), kind="gem",
            size=int(row.get("size") or 0),
            sha256=sha if isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha) else None,
            archive_format="tar",
        ))
        # 순수 ruby 플랫폼 gem 이 먼저 오게
        rel.artifacts.sort(key=lambda a: (a.filename != gem_filename(name, number, "ruby"),
                                          a.filename))
    if not releases:
        raise PackageNotFound(f"{name} is not on RubyGems (never existed, or removed)")

    stable = [r for r in releases.values()
              if not any(str(x.get("number")) == r.version and x.get("prerelease") for x in rows
                         if isinstance(x, dict))]
    pool = stable or list(releases.values())
    latest = max((r for r in pool if r.uploaded_at), key=lambda r: r.uploaded_at,
                 default=pool[0]).version

    project = Project(ecosystem="rubygems", name=name, latest=latest, releases=releases)
    # 저장소·작성자·런타임 의존성은 보조 정보 — 없어도 스캔은 계속한다
    try:
        meta = await _get_json(client, GEM_URL.format(name=name), name)
    except PyPIError as exc:
        project.extra["gem_meta_error"] = str(exc)
        return project
    if isinstance(meta, dict):
        project.repository_url = meta.get("source_code_uri") or meta.get("homepage_uri") or None
        authors = meta.get("authors")
        if isinstance(authors, str):
            project.maintainers = [a.strip() for a in authors.split(",") if a.strip()]
        deps = (meta.get("dependencies") or {}).get("runtime") or []
        if meta.get("version") in releases:
            releases[meta["version"]].dependencies = [
                d["name"] for d in deps if isinstance(d, dict) and d.get("name")
            ]
        project.extra["info"] = {k: meta.get(k) for k in ("downloads", "licenses", "version")}
    return project
