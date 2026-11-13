"""npm 레지스트리 조회 — packument(``https://registry.npmjs.org/<name>``) → ``Project``.

전체 packument 를 쓴다. 설치용 축약 메타데이터(``application/vnd.npm.install-v1+json``)는
작지만 버전별 업로드 시각(``time``)·관리자·저장소가 없다 — 스코어링(새 계정·연속 배포)과
"직전 버전" 비교가 그 값을 쓴다.

삭제(unpublish)된 패키지는 404 가 아니라 200 과 ``time.unpublished`` 만 있는 문서로 온다
(실측: 실제 삭제된 악성 패키지 packument). 버전이 하나도 없으면 "없음"으로 본다.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from ecosystems.base import Artifact, PackageNotFound, Project, RegistryError, Release

REGISTRY = "https://registry.npmjs.org"
#: packument 상한. 인기 패키지(@types/node 등)는 수십 MB 다 — 그 이상은 조회를 포기한다.
MAX_PACKUMENT_BYTES = 80 * 1024 * 1024
REGISTRY_LABEL = "npm"


def packument_url(name: str) -> str:
    """스코프 패키지는 ``@scope%2Fname`` 으로 — 레지스트리가 요구하는 형태."""
    return f"{REGISTRY}/{quote(name, safe='@')}"


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _repo_url(repo: Any) -> str | None:
    if isinstance(repo, dict):
        repo = repo.get("url")
    if not isinstance(repo, str) or not repo:
        return None
    url = repo.removeprefix("git+")
    if url.startswith("github:"):
        url = "https://github.com/" + url[len("github:"):]
    elif "://" not in url and url.count("/") == 1 and not url.startswith(("git@", ".")):
        url = "https://github.com/" + url  # "owner/repo" 축약
    return url.removesuffix(".git")


def _people(value: Any) -> list[str]:
    out = []
    for p in value if isinstance(value, list) else []:
        if isinstance(p, dict) and isinstance(p.get("name"), str):
            out.append(p["name"])
        elif isinstance(p, str):
            out.append(p.split("<", 1)[0].strip())
    return out


def tarball_filename(url: str) -> str:
    return urlparse(url).path.rsplit("/", 1)[-1]


def project_from_packument(name: str, doc: dict[str, Any]) -> Project:
    versions = doc.get("versions")
    if not isinstance(versions, dict) or not versions:
        raise PackageNotFound(f"{name} is not on {REGISTRY_LABEL} (never existed, or removed)")
    times = doc.get("time") if isinstance(doc.get("time"), dict) else {}
    releases: dict[str, Release] = {}
    deprecated: dict[str, str] = {}
    for ver, meta in versions.items():
        if not isinstance(meta, dict):
            continue
        dist = meta.get("dist") if isinstance(meta.get("dist"), dict) else {}
        artifacts = []
        url = dist.get("tarball")
        if isinstance(url, str) and url:
            artifacts.append(Artifact(
                filename=tarball_filename(url),
                url=url,
                kind="tarball",
                size=0,  # unpackedSize 는 다운로드 크기가 아니다
                sha256=None,
                archive_format="tar",
            ))
        deps = meta.get("dependencies")
        if isinstance(meta.get("deprecated"), str):
            deprecated[ver] = meta["deprecated"]
        scripts = meta.get("scripts") if isinstance(meta.get("scripts"), dict) else {}
        install = meta.get("hasInstallScript")
        if install is None and scripts:
            install = any(k in scripts for k in ("preinstall", "install", "postinstall"))
        releases[ver] = Release(
            version=ver,
            uploaded_at=_parse_time(times.get(ver)),
            artifacts=artifacts,
            # npm 의 deprecated 는 설치를 막지 않는다 — pip 의 yanked 와 다르다
            yanked=False,
            dependencies=sorted(deps) if isinstance(deps, dict) else [],
            install_script=bool(install) if install is not None else None,
        )
    tags = doc.get("dist-tags") if isinstance(doc.get("dist-tags"), dict) else {}
    latest = tags.get("latest") if isinstance(tags.get("latest"), str) else None
    latest_meta = versions.get(latest, {}) if latest else {}
    repo = _repo_url(latest_meta.get("repository") if isinstance(latest_meta, dict) else None)
    repo = repo or _repo_url(doc.get("repository"))
    return Project(
        ecosystem="npm",
        name=doc.get("name") if isinstance(doc.get("name"), str) else name,
        latest=latest,
        releases=releases,
        repository_url=repo,
        maintainers=_people(doc.get("maintainers")),
        extra={
            "deprecated": deprecated,
            "created": times.get("created"),
            "dist": {
                v: (m.get("dist") or {}) for v, m in versions.items() if isinstance(m, dict)
            },
            "scripts": {
                v: m.get("scripts") for v, m in versions.items()
                if isinstance(m, dict) and isinstance(m.get("scripts"), dict)
            },
        },
    )


async def fetch_project(name: str, *, client: httpx.AsyncClient) -> Project:
    try:
        resp = await client.get(packument_url(name), headers={"Accept": "application/json"},
                                follow_redirects=True)
    except httpx.HTTPError as exc:
        raise RegistryError(f"npm registry request failed for {name}: {exc}") from exc
    if resp.status_code == 404:
        raise PackageNotFound(f"{name} is not on {REGISTRY_LABEL} (never existed, or removed)")
    if resp.status_code >= 400:
        raise RegistryError(f"npm registry returned {resp.status_code} for {name}")
    if len(resp.content) > MAX_PACKUMENT_BYTES:
        raise RegistryError(f"npm packument for {name} too large ({len(resp.content)} bytes)")
    try:
        doc = resp.json()
    except ValueError as exc:
        raise RegistryError(f"npm registry returned invalid JSON for {name}") from exc
    if not isinstance(doc, dict):
        raise RegistryError(f"npm registry returned unexpected document for {name}")
    return project_from_packument(name, doc)
