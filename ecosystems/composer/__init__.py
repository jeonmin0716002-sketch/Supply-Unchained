"""Composer(Packagist) 어댑터."""

from __future__ import annotations

import re

import httpx

from api.schemas import StaticFinding
from ecosystems.base import Artifact, Dependency, Ecosystem, Project
from ecosystems.composer import feed as _feed
from ecosystems.composer import manifests, registry, rules
from engine.rules.base import SourceTree


class ComposerAdapter(Ecosystem):
    id = "composer"
    osv_ecosystem = "Packagist"
    purl_type = "composer"
    registry_label = "Packagist"
    manifest_filenames = ("composer.lock", "composer.json")
    has_feed = True

    # ``vendor/package`` — 소문자, 구분자는 ``.``·``_``·``-`` (Packagist 이름 규칙).
    # ``\Z`` 로 끝을 못 박는다 (``$`` 는 끝의 개행을 통과시킨다).
    NAME_RE = re.compile(
        r"^[a-z0-9](?:[_.-]?[a-z0-9]+)*/[a-z0-9](?:(?:[_.]|-{1,2})?[a-z0-9]+)*\Z"
    )
    VERSION_RE = re.compile(r"^v?[0-9][0-9A-Za-z]*(?:[._+-][0-9A-Za-z]+)*\Z")
    MAX_NAME_LEN = 200

    def purl(self, name: str, version: str) -> str:
        vendor, _, pkg = name.partition("/")
        return f"pkg:composer/{vendor}/{pkg}@{version}"

    def web_url(self, name: str, version: str | None = None) -> str:
        return f"https://packagist.org/packages/{name}"

    async def fetch_project(self, name: str, *, client: httpx.AsyncClient) -> Project:
        return await registry.fetch_project(name, client=client)

    def analyze_tree(
        self, tree: SourceTree, *, artifact: Artifact | None = None
    ) -> list[StaticFinding]:
        return rules.analyze_tree(tree)

    def rule_cwes(self) -> dict[str, frozenset[str]]:
        return dict(rules.RULE_CWES)

    def has_install_script(self, project: Project, version: str, archive_names: list[str]) -> bool:
        """composer-plugin 은 설치 중 코드가 돈다. 의존성의 ``scripts`` 는 안 돈다."""
        info = (project.extra.get("versions") or {}).get(version) or {}
        return info.get("type") == "composer-plugin"

    def parse_manifest(self, filename: str, text: str) -> list[Dependency]:
        low = filename.lower().rsplit("/", 1)[-1]
        if low == "composer.lock":
            return manifests.parse_composer_lock(text, filename)
        if low == "composer.json":
            return manifests.parse_composer_json(text, filename)
        return []

    async def fetch_feed(
        self, client: httpx.AsyncClient
    ) -> tuple[list[tuple[str, str | None]], list[str]]:
        return await _feed.fetch_feed(client)


ADAPTER = ComposerAdapter()
__all__ = ["ADAPTER", "ComposerAdapter"]
