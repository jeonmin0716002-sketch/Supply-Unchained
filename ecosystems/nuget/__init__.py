"""NuGet 어댑터 — ``ecosystems.get("nuget")``."""

from __future__ import annotations

import re

import httpx

from api.schemas import StaticFinding
from ecosystems.base import Artifact, Dependency, Ecosystem, Project
from ecosystems.nuget import feed as _feed
from ecosystems.nuget import manifests as _manifests
from ecosystems.nuget import registry as _registry
from ecosystems.nuget import rules as _rules


class NuGetEcosystem(Ecosystem):
    id = "nuget"
    osv_ecosystem = "NuGet"
    purl_type = "nuget"
    registry_label = "NuGet"
    manifest_filenames = ("packages.lock.json", "packages.config", "directory.packages.props")
    has_feed = True
    #: 선택 추출(common.pypi.SCAN_SUFFIXES)에 없는데 규칙이 읽는 파일 — 관리형 .dll 문자열 테이블
    scan_suffixes = (".dll",)

    # NuGet id: 영숫자·'.'·'_'·'-', 최대 100자. 대소문자 구분 없음.
    NAME_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9._-]*[A-Za-z0-9_])?$")
    # SemVer 2 (+ 레거시 4자리) — 프리릴리스·빌드 메타데이터 허용
    VERSION_RE = re.compile(
        r"^\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
    )
    MAX_NAME_LEN = 100

    def web_url(self, name: str, version: str | None = None) -> str:
        base = f"https://www.nuget.org/packages/{name}"
        return f"{base}/{version}" if version else base

    async def fetch_project(self, name: str, *, client: httpx.AsyncClient) -> Project:
        return await _registry.fetch_project(name, client=client)

    def analyze_tree(self, tree, *, artifact: Artifact | None = None) -> list[StaticFinding]:
        return _rules.analyze_tree(tree, artifact=artifact)

    def rule_cwes(self) -> dict[str, frozenset[str]]:
        return _rules.rule_cwes()

    def has_install_script(self, project: Project, version: str, archive_names: list[str]) -> bool:
        return _rules.has_executable_hooks(archive_names)

    def handles_filename(self, filename: str) -> bool:
        """``*.csproj`` 등 이름이 고정이 아닌 프로젝트 파일까지 포함한 판별 (inventory 용)."""
        return _manifests.handles_filename(filename)

    def parse_manifest(self, filename: str, text: str) -> list[Dependency]:
        return _manifests.parse_manifest(filename, text)

    async def fetch_feed(self, client: httpx.AsyncClient):
        return await _feed.fetch_feed(client)


ADAPTER = NuGetEcosystem()
