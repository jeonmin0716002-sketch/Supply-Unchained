"""pip(PyPI) 어댑터 — 기존 파이썬 엔진·PyPI 코드를 어댑터 계약으로 감싼다.

새 로직을 넣는 곳이 아니라 연결하는 곳이다. 검증 문구·이름 사칭 비교 대상·설치 스크립트
판단은 어댑터 도입 전 동작과 같게 유지한다(tests/test_security.py·test_scoring.py).
"""

from __future__ import annotations

import re
from typing import ClassVar

import httpx

from api.schemas import StaticFinding
from ecosystems.base import Artifact, Dependency, Ecosystem, Project
from ecosystems.pip import registry
from engine.rules.base import SourceTree

# 의존성 파일 파서는 inventory 세션 소유(ecosystems/pip/manifests.py) — 있으면 쓴다.
try:
    from ecosystems.pip import manifests as _manifests
except ImportError:  # 아직 병합 전
    _manifests = None


class PipEcosystem(Ecosystem):
    id = "pip"
    osv_ecosystem = "PyPI"
    purl_type = "pypi"
    registry_label = "PyPI"
    has_feed = True
    manifest_filenames: ClassVar[tuple[str, ...]] = tuple(
        getattr(_manifests, "MANIFEST_FILENAMES", None)
        or getattr(_manifests, "manifest_filenames", None)
        or ()
    )

    NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
    # base 의 기본값과 달리 '~' 를 받지 않는다 — PEP 440 에 없는 문자다.
    VERSION_RE = re.compile(r"^[A-Za-z0-9]+(?:[._+!-][A-Za-z0-9]+)*$")
    MAX_NAME_LEN = 214
    MAX_VERSION_LEN = 64

    def validate(self, name: str, version: str) -> None:
        # 문구는 어댑터 도입 전 api/schemas.py 의 것 그대로 (CLI 가 사용자에게 그대로 보인다)
        if not (0 < len(name) <= self.MAX_NAME_LEN) or not self.NAME_RE.fullmatch(name):
            raise ValueError(
                "패키지명은 영숫자로 시작·끝나고 중간에 . _ - 만 쓸 수 있습니다 "
                "(PEP 503 — Command Injection 방지)"
            )
        if not (0 < len(version) <= self.MAX_VERSION_LEN) or not self.VERSION_RE.fullmatch(version):
            raise ValueError("버전은 영숫자와 . _ + ! - 만 쓸 수 있습니다 (PEP 440 문자셋)")

    def normalize_name(self, name: str) -> str:
        return re.sub(r"[-_.]+", "-", name).lower()

    def web_url(self, name: str, version: str | None = None) -> str:
        return f"https://pypi.org/project/{name}/{version}/" if version else (
            f"https://pypi.org/project/{name}/"
        )

    async def fetch_project(self, name: str, *, client: httpx.AsyncClient) -> Project:
        return await registry.fetch_project(name, client=client)

    def select_artifacts(self, project: Project, version: str) -> list[Artifact]:
        return registry.select_artifacts(project, version)

    def analyze_tree(
        self, tree: SourceTree, *, artifact: Artifact | None = None
    ) -> list[StaticFinding]:
        from engine.static_analyzer import analyze_tree

        # base 는 규칙이 FileContext.path 를 만들 때 쓴다. 읽기 실패는 tree 쪽에서 센다
        # (파이프라인이 추적용 트리로 감싸 넘긴다) — 여기서도 세면 두 번 보고된다.
        return analyze_tree(tree, base=getattr(tree, "root", None))

    def has_install_script(self, project: Project, version: str, archive_names: list[str]) -> bool:
        # 기존 scoring.collector._has_setup_py 와 같은 기준: 아카이브 어디든 setup.py
        return any(n.rsplit("/", 1)[-1] == "setup.py" for n in archive_names)

    def popular_names(self) -> frozenset[str]:
        from scoring.popular_packages import POPULAR_PACKAGES

        # 손으로 고른 기존 목록(검증셋 튜닝 근거가 있는 것)에 수집 목록(data/popular/pip.txt,
        # 있으면)을 더한다. 기존 목록을 빼면 test_scoring 의 튜닝 수치가 깨진다.
        return frozenset(POPULAR_PACKAGES) | super().popular_names()

    def typosquat_score(self, name: str) -> float:
        from scoring.features import typosquat_score

        extra = super().popular_names()
        # 추가 목록이 없으면 기존 함수 그대로(정규화 캐시를 쓰는 기본 경로)
        return typosquat_score(name) if not extra else typosquat_score(
            name, popular=self.popular_names()
        )

    def parse_manifest(self, filename: str, text: str) -> list[Dependency]:
        fn = getattr(_manifests, "parse_manifest", None)
        return list(fn(filename, text)) if fn else []

    async def fetch_feed(
        self, client: httpx.AsyncClient
    ) -> tuple[list[tuple[str, str | None]], list[str]]:
        from ecosystems.pip.feed import fetch_feed

        return await fetch_feed(client)


ADAPTER = PipEcosystem()
