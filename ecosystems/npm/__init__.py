"""npm 어댑터 — ``ecosystems.get("npm")`` 이 찾는 ``ADAPTER``.

설치 시점 실행 경로: ``package.json`` 의 ``preinstall``·``install``·``postinstall``
(git 의존성은 ``prepare`` 도), 루트 ``binding.gyp`` (install 스크립트가 없으면 npm 이
``node-gyp rebuild`` 를 스스로 돈다), 그리고 ``require`` 시점의 진입점 최상단.
규칙은 ``rules.py``, 렉서는 ``jslex.py`` 에 있다.
"""

from __future__ import annotations

import re
from typing import ClassVar

import httpx

from api.schemas import StaticFinding
from ecosystems.base import Artifact, Dependency, Ecosystem, Project
from engine.rules.base import SourceTree


class NpmEcosystem(Ecosystem):
    id = "npm"
    osv_ecosystem = "npm"
    purl_type = "npm"
    registry_label = "npm"
    manifest_filenames = (
        "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
        "pnpm-lock.yaml",
    )
    has_feed = True

    #: npm 이름 규칙(validate-npm-package-name) 중 URL 안전한 부분: 소문자·숫자·``-._~``,
    #: 선택적 ``@scope/``. 대문자는 옛 패키지(``JSONStream`` 등)에 남아 있어 허용한다.
    #: ``.``·``_`` 로 시작하는 이름, 슬래시 2개 이상, ``..`` 은 거부 — 경로 조립에 쓰인다.
    NAME_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:@[A-Za-z0-9~-][A-Za-z0-9._~-]*/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$"
    )
    #: semver 2.0 (``1.2.3``, ``1.0.0-beta.1``, ``1.0.0+build.5``) — 앞의 ``v``·``=`` 없이.
    VERSION_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
        r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
    )
    MAX_NAME_LEN: ClassVar[int] = 214
    MAX_VERSION_LEN: ClassVar[int] = 256

    def validate(self, name: str, version: str) -> None:
        if "%" in name or "\\" in name:
            raise ValueError(f"npm 패키지명으로 쓸 수 없는 값: {name!r}")
        super().validate(name, version)

    def normalize_name(self, name: str) -> str:
        # npm 은 이름을 대소문자 구분한다 (옛 대문자 이름이 따로 존재) — 소문자로 합치지 않는다
        return name

    def purl(self, name: str, version: str) -> str:
        # purl 규격: 스코프 @ 는 %40 으로
        if name.startswith("@"):
            scope, _, base = name.partition("/")
            return f"pkg:npm/%40{scope[1:]}/{base}@{version}"
        return f"pkg:npm/{name}@{version}"

    def web_url(self, name: str, version: str | None = None) -> str:
        # npmjs.com 의 코드 탭은 내려받지 않고 파일을 본다
        return f"https://www.npmjs.com/package/{name}" + (f"/v/{version}" if version else "")

    async def fetch_project(self, name: str, *, client: httpx.AsyncClient) -> Project:
        from ecosystems.npm.registry import fetch_project

        return await fetch_project(name, client=client)

    def analyze_tree(
        self, tree: SourceTree, *, artifact: Artifact | None = None
    ) -> list[StaticFinding]:
        from ecosystems.npm.rules import analyze_tree

        return analyze_tree(tree)

    def rule_cwes(self) -> dict[str, frozenset[str]]:
        from ecosystems.npm.rules import RULE_CWES

        return dict(RULE_CWES)

    def has_install_script(self, project: Project, version: str, archive_names: list[str]) -> bool:
        if super().has_install_script(project, version, archive_names):
            return True
        # 루트 binding.gyp 는 install 스크립트가 없어도 node-gyp 를 돌게 한다
        return any(n.count("/") <= 1 and n.endswith("binding.gyp") for n in archive_names)

    def typosquat_score(self, name: str) -> float:
        from scoring.features import typosquat_score

        popular = self.popular_names()
        score = typosquat_score(name, popular=popular)
        # @scope/name 은 base 이름으로도 비교한다 — "@evil/lodash" 같은 스코프 사칭
        if name.startswith("@") and "/" in name:
            base = name.split("/", 1)[1]
            if base not in popular:
                score = max(score, typosquat_score(base, popular=popular))
        return score

    def parse_manifest(self, filename: str, text: str) -> list[Dependency]:
        from ecosystems.npm.manifests import parse_manifest

        return parse_manifest(filename, text)

    async def fetch_feed(
        self, client: httpx.AsyncClient
    ) -> tuple[list[tuple[str, str | None]], list[str]]:
        from ecosystems.npm.feed import fetch_feed

        return await fetch_feed(client)


ADAPTER = NpmEcosystem()

__all__ = ["ADAPTER", "NpmEcosystem"]
