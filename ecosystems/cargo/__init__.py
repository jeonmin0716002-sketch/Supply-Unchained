"""cargo(crates.io) 어댑터. 실행 경로: build.rs · proc-macro (ecosystems/cargo/rules.py)."""

from __future__ import annotations

import re
from typing import ClassVar

import httpx

from api.schemas import StaticFinding
from ecosystems.base import Artifact, Dependency, Ecosystem, Project
from ecosystems.cargo import feed, manifests, registry, rules
from engine.rules.base import SourceTree


class CargoEcosystem(Ecosystem):
    id: ClassVar[str] = "cargo"
    osv_ecosystem: ClassVar[str] = "crates.io"
    purl_type: ClassVar[str] = "cargo"
    registry_label: ClassVar[str] = "crates.io"
    manifest_filenames: ClassVar[tuple[str, ...]] = ("cargo.lock", "cargo.toml")
    has_feed: ClassVar[bool] = True

    # 크레이트 이름: ASCII 영문으로 시작, 영숫자·`-`·`_` (crates.io 규칙, 최대 64자)
    NAME_RE: ClassVar[re.Pattern[str]] = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")
    MAX_NAME_LEN: ClassVar[int] = 64
    # SemVer 2.0: 1.2.3, 1.0.0-rc.1, 1.0.0+build.5
    VERSION_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
        r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
    )

    def normalize_name(self, name: str) -> str:
        # crates.io 는 대소문자와 `-`/`_` 를 구분하지 않는다
        return name.lower().replace("_", "-")

    def web_url(self, name: str, version: str | None = None) -> str:
        # docs.rs 소스 보기 — 내려받지 않고 코드를 볼 수 있다
        if version:
            return f"https://docs.rs/crate/{name}/{version}/source/"
        return f"https://crates.io/crates/{name}"

    async def fetch_project(self, name: str, *, client: httpx.AsyncClient) -> Project:
        return await registry.fetch_project(name, client=client)

    def analyze_tree(
        self, tree: SourceTree, *, artifact: Artifact | None = None
    ) -> list[StaticFinding]:
        return rules.analyze(tree)

    def rule_cwes(self) -> dict[str, frozenset[str]]:
        return dict(rules.RULE_CWES)

    def has_install_script(self, project: Project, version: str, archive_names: list[str]) -> bool:
        """``build.rs`` 가 있으면 빌드 때 코드가 돈다 (대부분 평범하다 — 판정은 rules 가 한다)."""
        # build.rs 가 기본이고, build/main.rs · builder/main.rs 같은 분리형도 흔하다
        return any(
            n.count("/") <= 2 and (
                n.endswith(("build.rs", "/build/main.rs", "/builder/main.rs"))
            )
            for n in archive_names
        )

    def parse_manifest(self, filename: str, text: str) -> list[Dependency]:
        name = filename.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if name == "cargo.lock":
            return manifests.parse_cargo_lock(text, filename)
        if name == "cargo.toml":
            return manifests.parse_cargo_toml(text, filename)
        return []

    async def fetch_feed(self, client):
        return await feed.fetch_feed(client)


ADAPTER = CargoEcosystem()
