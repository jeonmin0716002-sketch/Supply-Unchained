"""Go 모듈 프록시(proxy.golang.org) 조회 → 공통 ``Project`` 모델.

프록시 프로토콜(실측): ``/<escaped>/@v/list`` 는 버전 목록(줄바꿈 텍스트), ``/@v/<v>.info`` 는
``{"Version","Time","Origin"}``, ``/@latest`` 는 최신, ``/@v/<v>.zip`` 은 모듈 소스.
없는 모듈은 404(+텍스트 본문), 삭제·차단된 모듈은 410.

모듈 경로의 대문자는 ``!`` + 소문자로 이스케이프한다 (대소문자 구분 없는 파일시스템에서 충돌을 피하려는
프록시 규약). 버전에도 같은 규칙이 적용된다.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime

import httpx

from ecosystems.base import Artifact, PackageNotFound, Project, RegistryError, Release

PROXY = "https://proxy.golang.org"
LABEL = "Go module proxy"
#: ``.info`` 로 시각을 채울 최신 버전 수 — 버전이 수백 개인 모듈이 있어 전부 조회하지 않는다
INFO_LIMIT = 25

_SEMVER = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def escape(s: str) -> str:
    """``github.com/BurntSushi/toml`` → ``github.com/!burnt!sushi/toml``."""
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), s)


def unescape(s: str) -> str:
    return re.sub(r"!([a-z])", lambda m: m.group(1).upper(), s)


def _sort_key(v: str) -> tuple:
    m = _SEMVER.match(v)
    if not m:
        return (-1, 0, 0, 0, "")
    major, minor, patch, pre = int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4)
    # 사전 릴리스(pre)는 같은 숫자의 정식 릴리스보다 낮다
    return (major, minor, patch, 1 if pre is None else 0, pre or "")


def sort_versions(versions: list[str]) -> list[str]:
    return sorted(versions, key=_sort_key)


def zip_url(module: str, version: str) -> str:
    return f"{PROXY}/{escape(module)}/@v/{escape(version)}.zip"


def _ts(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


async def _get(client: httpx.AsyncClient, url: str, name: str) -> httpx.Response:
    try:
        return await client.get(url)
    except httpx.HTTPError as exc:
        raise RegistryError(f"{LABEL} lookup failed for {name}: {exc}") from exc


async def _info(client: httpx.AsyncClient, module: str, version: str) -> dict | None:
    try:
        resp = await client.get(f"{PROXY}/{escape(module)}/@v/{escape(version)}.info")
        return resp.json() if resp.status_code == 200 else None
    except (httpx.HTTPError, ValueError):
        return None  # 시각은 보조 메타데이터다 — 못 받아도 소스 스캔에는 영향이 없다


async def fetch_project(name: str, *, client: httpx.AsyncClient) -> Project:
    listing = await _get(client, f"{PROXY}/{escape(name)}/@v/list", name)
    if listing.status_code in (404, 410):
        raise PackageNotFound(f"{name} is not on {LABEL} (never existed, or removed)")
    if listing.status_code != 200:
        raise RegistryError(f"{LABEL} returned {listing.status_code} for {name}")
    versions = [v.strip() for v in listing.text.splitlines() if v.strip()]

    latest_resp = await _get(client, f"{PROXY}/{escape(name)}/@latest", name)
    latest_info: dict | None = None
    if latest_resp.status_code == 200:
        try:
            latest_info = latest_resp.json()
        except ValueError as exc:
            raise RegistryError(f"{LABEL} returned a non-JSON @latest for {name}") from exc
    elif latest_resp.status_code in (404, 410):
        if not versions:  # 목록도 최신도 비었다 — 존재하지 않는다
            raise PackageNotFound(f"{name} is not on {LABEL} (never existed, or removed)")
    else:
        raise RegistryError(f"{LABEL} returned {latest_resp.status_code} for {name}@latest")

    latest = latest_info.get("Version") if latest_info else None
    if latest and latest not in versions:
        versions.append(latest)  # 유사 버전(pseudo-version)만 있는 모듈은 목록이 비어 있다
    ordered = sort_versions(versions)

    recent = ordered[-INFO_LIMIT:]
    infos = await asyncio.gather(*(_info(client, name, v) for v in recent))
    times = {v: _ts((i or {}).get("Time")) for v, i in zip(recent, infos, strict=True)}
    if latest_info and latest:
        times[latest] = _ts(latest_info.get("Time")) or times.get(latest)

    releases = {
        v: Release(
            version=v,
            uploaded_at=times.get(v),
            artifacts=[Artifact(
                filename=f"{name.rsplit('/', 1)[-1]}@{v}.zip", url=zip_url(name, v),
                kind="zip", archive_format="zip")],
            install_script=False,  # Go 에는 설치 스크립트가 없다
        )
        for v in ordered
    }
    origin = (latest_info or {}).get("Origin") or {}
    return Project(
        ecosystem="go",
        name=name,
        latest=latest or (ordered[-1] if ordered else None),
        releases=releases,
        repository_url=origin.get("URL"),
        maintainers=[],
        extra={"origin": origin, "versions_with_time": len(recent)},
    )

# ruff: noqa: E501
