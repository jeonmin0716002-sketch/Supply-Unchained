"""Maven Central → ``Project``.

버전 목록은 ``maven-metadata.xml``(권위 있는 원본, 없으면 404), 업로드 시각과 어떤 파일이
있는지(``ec`` 확장자 목록)는 Central 검색 API(``core=gav``)에서 얻는다. 실측(2026-11):
검색 API 는 응답이 오지만 인덱스가 몇 달 뒤처질 수 있고 일시 장애도 있다. 그래서 검색은
**최선 노력**이다 — 실패하면 시각은 None, 파일은 ``.jar`` 로 가정하고, 원인을
``Project.extra["search_error"]`` 에 남긴다 (조용히 숨기지 않는다).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx

from common.pypi import PackageNotFound, PyPIError
from ecosystems.base import Artifact, Project, Release
from ecosystems.maven._xml import parse_xml

REPO_BASE = "https://repo1.maven.org/maven2"
SEARCH_URL = "https://search.maven.org/solrsearch/select"
SEARCH_ROWS = 200
#: 검색 페이지 상한 (200 x 5 = 버전 1000개). 넘는 버전은 시각을 모른다.
SEARCH_MAX_PAGES = 5
MAX_VERSIONS = 5000


def split_name(name: str) -> tuple[str, str]:
    group, _, artifact = name.partition(":")
    return group, artifact


def base_url(name: str, version: str | None = None) -> str:
    group, artifact = split_name(name)
    path = f"{REPO_BASE}/{quote(group, safe='.-_').replace('.', '/')}/{quote(artifact, safe='.-_')}"
    return f"{path}/{quote(version, safe='.-_+')}" if version else path


def _artifact(name: str, version: str, suffix: str, kind: str) -> Artifact:
    _, artifact = split_name(name)
    filename = f"{artifact}-{version}{suffix}"
    return Artifact(
        filename=filename, url=f"{base_url(name, version)}/{filename}", kind=kind,
        archive_format="zip" if suffix.endswith(("jar", "aar")) else None,
    )


def artifacts_for(name: str, version: str, ec: list[str] | None) -> list[Artifact]:
    """``ec`` = 검색 API 가 알려준 확장자 목록. None 이면 모른다 — 소스 jar 는 없을 수 있으니
    빼고 ``.jar`` + ``.pom``."""
    if ec is None:
        # POM 은 모든 아티팩트에 있다 — 검색 정보가 없을 때 jar 가 없는 pom 패키징(부모 POM·BOM)이
        # "다운로드 실패"로 끝나지 않게 같이 둔다.
        return [_artifact(name, version, ".jar", "jar"), _artifact(name, version, ".pom", "pom")]
    out: list[Artifact] = []
    if ".jar" in ec:
        out.append(_artifact(name, version, ".jar", "jar"))
    if ".aar" in ec:
        out.append(_artifact(name, version, ".aar", "aar"))
    if "-sources.jar" in ec:
        out.append(_artifact(name, version, "-sources.jar", "sources-jar"))
    if not out:  # 부모 POM·BOM 같은 pom 패키징 — 빌드에 상속되므로 POM 자체를 본다
        out.append(_artifact(name, version, ".pom", "pom"))
    return out


async def _search(client: httpx.AsyncClient, name: str) -> dict[str, dict[str, Any]]:
    group, artifact = split_name(name)
    docs: dict[str, dict[str, Any]] = {}
    for page in range(SEARCH_MAX_PAGES):
        q = f'g:"{group}" AND a:"{artifact}"'
        resp = await client.get(SEARCH_URL, params={
            "q": q, "core": "gav", "rows": SEARCH_ROWS, "start": page * SEARCH_ROWS, "wt": "json",
        })
        resp.raise_for_status()
        body = resp.json().get("response") or {}
        for d in body.get("docs") or []:
            if isinstance(d, dict) and isinstance(d.get("v"), str):
                docs[d["v"]] = d
        if (page + 1) * SEARCH_ROWS >= int(body.get("numFound") or 0):
            break
    return docs


def _time(ms: Any) -> datetime | None:
    if not isinstance(ms, (int, float)) or ms <= 0:
        return None
    try:
        return datetime.fromtimestamp(ms / 1000, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


async def fetch_project(name: str, *, client: httpx.AsyncClient) -> Project:
    url = f"{base_url(name)}/maven-metadata.xml"
    try:
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        raise PyPIError(f"Maven Central lookup failed for {name}: {exc}") from exc
    if resp.status_code == 404:
        raise PackageNotFound(f"{name} is not on Maven Central (never existed, or removed)")
    if resp.status_code != 200:
        raise PyPIError(f"Maven Central returned {resp.status_code} for {name}")
    try:
        root = parse_xml(resp.text)
    except ValueError as exc:
        raise PyPIError(f"Maven Central returned unusable metadata for {name}: {exc}") from exc

    versions = [v.text.strip() for v in root.iter("version") if v.text and v.text.strip()]
    if len(versions) > MAX_VERSIONS:
        raise PyPIError(f"{name} lists too many versions ({len(versions)})")
    latest = None
    for tag in ("release", "latest"):
        el = root.find(f"versioning/{tag}")
        if el is not None and el.text and el.text.strip() in versions:
            latest = el.text.strip()
            break

    extra: dict[str, Any] = {}
    try:
        docs = await _search(client, name)
    except (httpx.HTTPError, ValueError) as exc:
        docs = {}
        extra["search_error"] = str(exc)

    releases: dict[str, Release] = {}
    for v in versions:
        doc = docs.get(v)
        ec = [e for e in doc.get("ec") or [] if isinstance(e, str)] if doc else None
        releases[v] = Release(
            version=v, uploaded_at=_time(doc.get("timestamp")) if doc else None,
            artifacts=artifacts_for(name, v, ec),
        )
    if latest is None and versions:
        latest = versions[-1]
    # 검색 색인이 못 따라온 최신 버전은 jar 가 있는지 HEAD 로 확인한다 (부모 POM·BOM 은 jar 가 없어
    # 그대로 두면 "다운로드 실패"가 된다). 비용 때문에 최신 버전 하나만.
    if latest and latest not in docs:
        art = _artifact(name, latest, ".jar", "jar")
        try:
            head = await client.head(art.url)
            if head.status_code == 404:
                releases[latest].artifacts = [_artifact(name, latest, ".pom", "pom")]
        except httpx.HTTPError:
            pass
    return Project(ecosystem="maven", name=name, latest=latest, releases=releases, extra=extra)
