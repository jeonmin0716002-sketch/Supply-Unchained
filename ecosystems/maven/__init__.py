# ruff: noqa: E501
"""Maven Central 어댑터 — ``ecosystems.get("maven")``.

피드(``has_feed``)는 만들지 않았다: 신규 업로드를 최신순으로 주는 인증 없는 엔드포인트가
없다. Central 검색 API 의 ``timestamp desc`` 정렬은 동작하지만 인덱스가 수개월 뒤처져
(2026-11 실측: 가장 최신 항목이 2026-06) "새로 올라온 것"을 보여주지 못한다.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import quote

import httpx

from api.schemas import StaticFinding
from common.archive import ArchiveError
from ecosystems.base import Artifact, Dependency, Ecosystem, Project
from ecosystems.maven import manifests as _manifests
from ecosystems.maven import registry as _registry
from ecosystems.maven import rules as _rules

MAX_POM_BYTES = 2 * 1024 * 1024


class MavenEcosystem(Ecosystem):
    id = "maven"
    osv_ecosystem = "Maven"
    purl_type = "maven"
    registry_label = "Maven Central"
    manifest_filenames = ("pom.xml", "gradle.lockfile", "build.gradle", "build.gradle.kts")
    has_feed = False
    #: 선택 추출(common.pypi.SCAN_SUFFIXES)에 없는데 규칙이 읽는 파일 — .class 상수 풀, 중첩 jar
    scan_suffixes = (".class", ".jar", ".war")

    # 이름은 ``groupId:artifactId``. 각 부분은 영숫자·'.'·'_'·'-'.
    NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*:[A-Za-z0-9_][A-Za-z0-9._-]*$")
    VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
    MAX_NAME_LEN = 200

    def normalize_name(self, name: str) -> str:
        return name  # Maven 좌표는 대소문자를 구분한다

    def purl(self, name: str, version: str) -> str:
        group, artifact = _registry.split_name(name)
        return f"pkg:maven/{quote(group, safe='.-_')}/{quote(artifact, safe='.-_')}@{quote(version, safe='.-_+')}"

    def web_url(self, name: str, version: str | None = None) -> str:
        group, artifact = _registry.split_name(name)
        base = f"https://central.sonatype.com/artifact/{group}/{artifact}"
        return f"{base}/{version}" if version else base

    async def fetch_project(self, name: str, *, client: httpx.AsyncClient) -> Project:
        return await _registry.fetch_project(name, client=client)

    def extract(self, data: bytes, artifact: Artifact, dest: str | Path) -> Path:
        if artifact.kind == "pom":  # 압축 파일이 아니라 POM 본문 하나
            if len(data) > MAX_POM_BYTES:
                raise ArchiveError(f"{artifact.filename} is too large for a POM")
            root = Path(dest)
            root.mkdir(parents=True, exist_ok=True)
            (root / "pom.xml").write_bytes(data)
            return root
        return super().extract(data, artifact, dest)

    def analyze_tree(self, tree, *, artifact: Artifact | None = None) -> list[StaticFinding]:
        return _rules.analyze_tree(tree, artifact=artifact)

    def rule_cwes(self) -> dict[str, frozenset[str]]:
        return _rules.rule_cwes()

    def has_install_script(self, project: Project, version: str, archive_names: list[str]) -> bool:
        return _rules.has_build_hooks(archive_names)

    def parse_manifest(self, filename: str, text: str) -> list[Dependency]:
        return _manifests.parse_manifest(filename, text)


ADAPTER = MavenEcosystem()
