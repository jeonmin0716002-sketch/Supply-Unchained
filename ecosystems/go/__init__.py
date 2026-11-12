"""Go 모듈 어댑터. 실행 경로: init()·패키지 var 초기화·cgo (ecosystems/go/rules.py)."""

from __future__ import annotations

import re
from typing import ClassVar

import httpx

from api.schemas import StaticFinding
from ecosystems.base import Artifact, Dependency, Ecosystem, Project
from ecosystems.go import feed, manifests, registry, rules
from engine.rules.base import SourceTree

_SEG = r"[A-Za-z0-9_~-](?:[A-Za-z0-9._~-]*[A-Za-z0-9_~-])?"


class GoEcosystem(Ecosystem):
    id: ClassVar[str] = "go"
    osv_ecosystem: ClassVar[str] = "Go"
    purl_type: ClassVar[str] = "golang"
    registry_label: ClassVar[str] = "Go module proxy"
    manifest_filenames: ClassVar[tuple[str, ...]] = ("go.mod", "go.sum")
    has_feed: ClassVar[bool] = True

    # 모듈 경로: 슬래시로 나뉜 요소, 첫 요소에 점(도메인)이 있다. 요소는 점으로 시작·끝나지 않는다.
    NAME_RE: ClassVar[re.Pattern[str]] = re.compile(rf"^{_SEG}(?:/{_SEG})*$")
    MAX_NAME_LEN: ClassVar[int] = 300
    # v1.2.3 · v1.2.3-rc.1 · v0.0.0-20190404164418-38d8ce5564a5 · v2.0.0+incompatible
    VERSION_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
        r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
    )
    MAX_VERSION_LEN: ClassVar[int] = 128

    def validate(self, name: str, version: str) -> None:
        super().validate(name, version)
        if "." not in name.split("/", 1)[0]:
            raise ValueError(f"Go 모듈 경로의 첫 요소는 도메인이어야 합니다: {name!r}")

    def normalize_name(self, name: str) -> str:
        return name  # Go 모듈 경로는 대소문자를 구분한다

    def web_url(self, name: str, version: str | None = None) -> str:
        return f"https://pkg.go.dev/{name}@{version}" if version else f"https://pkg.go.dev/{name}"

    async def fetch_project(self, name: str, *, client: httpx.AsyncClient) -> Project:
        return await registry.fetch_project(name, client=client)

    def select_artifacts(self, project: Project, version: str) -> list[Artifact]:
        """목록에 없는 버전(유사 버전 등)도 프록시가 서빙하므로 직접 만든다."""
        release = project.release(version)
        if release:
            return list(release.artifacts)
        return [Artifact(
            filename=f"{project.name.rsplit('/', 1)[-1]}@{version}.zip",
            url=registry.zip_url(project.name, version), kind="zip", archive_format="zip")]

    def analyze_tree(
        self, tree: SourceTree, *, artifact: Artifact | None = None
    ) -> list[StaticFinding]:
        return rules.analyze(tree)

    def rule_cwes(self) -> dict[str, frozenset[str]]:
        return dict(rules.RULE_CWES)

    def has_install_script(self, project: Project, version: str, archive_names: list[str]) -> bool:
        return False  # 설치 스크립트가 없다 — import 시점 코드는 rules 가 본다

    def parse_manifest(self, filename: str, text: str) -> list[Dependency]:
        name = filename.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if name == "go.mod":
            return manifests.parse_go_mod(text, filename)
        if name == "go.sum":
            return manifests.parse_go_sum(text, filename)
        return []

    async def fetch_feed(self, client):
        return await feed.fetch_feed(client)


ADAPTER = GoEcosystem()
