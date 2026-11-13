"""Packagist p2 메타데이터(minified) → 공통 ``Project``.

``https://repo.packagist.org/p2/<vendor>/<package>.json`` 은 용량을 줄이려고 **첫 버전만 전체**
를 주고, 이후 버전은 앞 버전과 **달라진 키만** 담는다 (``"minified": "composer/2.0"``).
복원 규칙(Composer 문서): 앞 버전의 필드를 이어받아 덮어쓰고, 값이 문자열 ``"__unset"`` 이면
그 키를 지운다.

dist URL 은 메타데이터가 주는 값이라 공격자가 정할 수 있는 입력이다. 그래서 호스트를
허용 목록으로 제한하고(https 만, 사용자 정보 없음) 벗어나면 그 버전의 아티팩트를 만들지
않는다 — 임의 URL 을 가져오지 않는다.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

import httpx

from common.pypi import PackageNotFound, PyPIError
from ecosystems.base import Artifact, Project, Release

P2_URL = "https://repo.packagist.org/p2/{name}.json"

#: Packagist 가 실제로 dist 로 내려주는 호스트 (GitHub zipball API·codeload·archive, GitLab,
#: Bitbucket). 이 밖이면 받지 않는다.
DIST_HOSTS = frozenset({
    "api.github.com", "codeload.github.com", "github.com",
    "gitlab.com", "bitbucket.org", "api.bitbucket.org",
})


def dist_url_allowed(url: str) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return (
        parts.scheme == "https"
        and parts.hostname in DIST_HOSTS
        and not parts.username
        and parts.port in (None, 443)
    )


def expand_minified(versions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """minified 버전 목록을 완전한 딕셔너리 목록으로 복원한다."""
    out: list[dict[str, Any]] = []
    prev: dict[str, Any] = {}
    for entry in versions:
        if not isinstance(entry, dict):
            continue
        cur = dict(prev)
        for k, v in entry.items():
            if v == "__unset":
                cur.pop(k, None)
            else:
                cur[k] = v
        out.append(cur)
        prev = cur
    return out


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _require_names(req: Any) -> list[str]:
    if not isinstance(req, dict):
        return []
    # php·ext-* 는 패키지가 아니라 플랫폼 요구사항
    return [n for n in req if "/" in n]


async def fetch_project(name: str, *, client: httpx.AsyncClient) -> Project:
    try:
        resp = await client.get(P2_URL.format(name=name))
    except httpx.HTTPError as exc:
        raise PyPIError(f"Packagist lookup failed for {name}: {exc}") from exc
    if resp.status_code == 404:
        raise PackageNotFound(f"{name} is not on Packagist (never existed, or removed)")
    if resp.status_code != 200:
        raise PyPIError(f"Packagist returned {resp.status_code} for {name}")
    try:
        data = resp.json()
    except ValueError as exc:
        raise PyPIError(f"Packagist returned a non-JSON body for {name}") from exc

    pkgs = data.get("packages") if isinstance(data, dict) else None
    raw = pkgs.get(name) if isinstance(pkgs, dict) else None
    if not isinstance(raw, list):
        raise PyPIError(f"Packagist returned an unexpected payload for {name}")
    versions = expand_minified(raw) if data.get("minified") else [v for v in raw
                                                                   if isinstance(v, dict)]
    if not versions:
        raise PackageNotFound(f"{name} is not on Packagist (never existed, or removed)")

    releases: dict[str, Release] = {}
    skipped: list[str] = []
    for v in versions:
        number = str(v.get("version") or "")
        if not number or number.startswith("dev-") or number.endswith("-dev"):
            continue  # 브랜치(개발) 버전 — 고정된 릴리스가 아니다
        rel = Release(
            version=number, uploaded_at=_parse_time(v.get("time")),
            dependencies=_require_names(v.get("require")),
        )
        dist = v.get("dist")
        url = dist.get("url") if isinstance(dist, dict) else None
        if isinstance(url, str) and url:
            if dist_url_allowed(url):
                # shasum 은 보통 비어 있고 있어도 sha1 이라 Artifact.sha256 에는 넣지 않는다
                rel.artifacts.append(Artifact(
                    filename=f"{name.replace('/', '-')}-{number}.zip", url=url, kind="zip",
                    archive_format="zip",
                ))
            else:
                skipped.append(f"{number}: {urlsplit(url).hostname}")
        rel.install_script = bool(v.get("type") == "composer-plugin" or v.get("scripts"))
        releases[number] = rel

    stable = [r for r in releases.values()
              if not re.search(r"(?i)(?:alpha|beta|rc|dev|a\d|b\d)", r.version)]
    pool = stable or list(releases.values())
    latest = max((r for r in pool if r.uploaded_at), key=lambda r: r.uploaded_at,
                 default=pool[0]).version if pool else None

    project = Project(ecosystem="composer", name=name, latest=latest, releases=releases)
    newest = versions[0]
    repo = (newest.get("source") or {}).get("url") if isinstance(newest.get("source"), dict) \
        else None
    project.repository_url = repo or newest.get("homepage") or None
    authors = newest.get("authors")
    if isinstance(authors, list):
        project.maintainers = [a["name"] for a in authors if isinstance(a, dict) and a.get("name")]
    project.extra["versions"] = {
        str(v.get("version")): {"type": v.get("type"), "abandoned": v.get("abandoned")}
        for v in versions
    }
    if skipped:
        project.extra["dist_host_rejected"] = skipped
    return project
