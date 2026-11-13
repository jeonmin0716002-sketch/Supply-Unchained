"""crates.io 레지스트리 조회 → 공통 ``Project`` 모델.

crates.io API 는 User-Agent 가 없으면 403 을 준다(실측) — 서술적인 이름을 항상 붙인다.
다운로드는 API 의 ``dl_path``(302 리다이렉트) 대신 CDN 주소(static.crates.io)를 직접 쓴다.
크롤러는 그쪽을 쓰라는 crates.io 정책이고, 속도 제한을 API 와 나누지 않는다.
"""

from __future__ import annotations

from datetime import datetime

import httpx

from ecosystems.base import Artifact, PackageNotFound, Project, RegistryError, Release

API = "https://crates.io/api/v1"
CDN = "https://static.crates.io/crates"
USER_AGENT = "supply-unchained-scanner"
LABEL = "crates.io"


def _ts(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def crate_url(name: str, version: str) -> str:
    return f"{CDN}/{name}/{name}-{version}.crate"


async def fetch_project(name: str, *, client: httpx.AsyncClient) -> Project:
    try:
        resp = await client.get(f"{API}/crates/{name}", headers={"User-Agent": USER_AGENT})
    except httpx.HTTPError as exc:
        raise RegistryError(f"{LABEL} lookup failed for {name}: {exc}") from exc
    if resp.status_code == 404:
        raise PackageNotFound(f"{name} is not on {LABEL} (never existed, or removed)")
    if resp.status_code != 200:
        raise RegistryError(f"{LABEL} returned {resp.status_code} for {name}")
    try:
        data = resp.json()
        crate = data["crate"]
        versions = data["versions"]
    except (ValueError, KeyError, TypeError) as exc:
        raise RegistryError(f"{LABEL} returned an unusable body for {name}") from exc

    releases: dict[str, Release] = {}
    maintainers: list[str] = []
    for v in versions:
        num = v.get("num")
        if not isinstance(num, str):
            continue
        releases[num] = Release(
            version=num,
            uploaded_at=_ts(v.get("created_at")),
            yanked=bool(v.get("yanked")),
            artifacts=[Artifact(
                filename=f"{name}-{num}.crate",
                url=crate_url(crate.get("name", name), num),
                kind="crate",
                size=int(v.get("crate_size") or 0),
                sha256=v.get("checksum"),
                archive_format="tar",
            )],
            # build.rs 유무는 메타데이터에 없다 — 아카이브를 보고 has_install_script 가 판단
            install_script=None,
        )
        login = (v.get("published_by") or {}).get("login")
        if login and login not in maintainers:
            maintainers.append(login)
    latest = crate.get("max_stable_version") or crate.get("max_version") or crate.get("newest_version")
    return Project(
        ecosystem="cargo",
        name=crate.get("name", name),
        latest=latest,
        releases=releases,
        repository_url=crate.get("repository"),
        maintainers=maintainers,
        extra={
            "description": crate.get("description"),
            "downloads": crate.get("downloads"),
            "created_at": crate.get("created_at"),
            "updated_at": crate.get("updated_at"),
        },
    )

# ruff: noqa: E501
