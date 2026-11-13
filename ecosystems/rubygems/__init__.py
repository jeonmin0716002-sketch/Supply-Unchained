"""RubyGems 어댑터 — ``.gem`` 은 tar 안에 ``data.tar.gz`` 와 ``metadata.gz`` 가 든 중첩 구조다."""

from __future__ import annotations

import re
import tempfile
import zlib
from pathlib import Path

import httpx

from api.schemas import StaticFinding
from common.archive import ArchiveError, ExtractReport, extract_archive
from common.pypi import MAX_UNCOMPRESSED_BYTES
from ecosystems.base import Artifact, Dependency, Ecosystem, Project
from ecosystems.rubygems import feed as _feed
from ecosystems.rubygems import manifests, registry, rules
from engine.rules.base import SourceTree

#: 플랫폼별 사전 빌드 gem 이 수십 개인 경우(nokogiri 등)의 상한. 순수 ruby gem 은 항상 포함한다.
MAX_PLATFORM_ARTIFACTS = 8
_METADATA_CAP = 2 * 1024 * 1024


def _gunzip_capped(data: bytes, cap: int) -> bytes:
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = d.decompress(data, cap + 1)
    except zlib.error as exc:
        raise ArchiveError(f"could not gunzip gem metadata: {exc}") from exc
    if len(out) > cap:
        raise ArchiveError("gem metadata exceeds size limit (possible decompression bomb)")
    return out


class RubyGemsAdapter(Ecosystem):
    id = "rubygems"
    osv_ecosystem = "RubyGems"
    purl_type = "gem"
    registry_label = "RubyGems"
    manifest_filenames = ("gemfile.lock", "gemfile")
    has_feed = True

    # ``$`` 는 끝의 개행 앞에서도 맞아 끝 개행이 통과한다 — ``\Z``
    # 실제 gem 이름: 영숫자·``_``·``-``·``.`` (대소문자 구분)
    NAME_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9._-]*[A-Za-z0-9_])?\Z")
    VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z]*(?:[._][0-9A-Za-z]+)*\Z")
    MAX_NAME_LEN = 100

    def normalize_name(self, name: str) -> str:
        return name.lower()  # 비교용. rubygems 는 대소문자를 구분하지만 이름 사칭 비교는 소문자

    def web_url(self, name: str, version: str | None = None) -> str:
        base = f"https://rubygems.org/gems/{name}"
        return f"{base}/versions/{version}" if version else base

    async def fetch_project(self, name: str, *, client: httpx.AsyncClient) -> Project:
        return await registry.fetch_project(name, client=client)

    def select_artifacts(self, project: Project, version: str) -> list[Artifact]:
        rel = project.release(version)
        if rel is None:
            return []
        ruby = [a for a in rel.artifacts if a.filename == f"{project.name}-{version}.gem"]
        others = [a for a in rel.artifacts if a not in ruby]
        return ruby + others[:MAX_PLATFORM_ARTIFACTS]

    def extract(self, data: bytes, artifact: Artifact, dest: str | Path) -> Path:
        """바깥 tar → ``data.tar.gz`` 를 dest 에, ``metadata.gz`` 를 ``_gem_metadata.yml`` 로.

        바깥 tar 도 안쪽 data.tar.gz 도 common.archive 의 크기·개수·경로 상한을 거친다."""
        dest = Path(dest)
        with tempfile.TemporaryDirectory() as outer_dir:
            # 바깥 tar 의 멤버(data.tar.gz·metadata.gz)는 분석 대상 접미사가 아니라 선택 추출이
            # 건너뛴다 — 통합 시 실측: "has no data.tar.gz". 바깥 추출만 .gz 를 허용하고, 기록은
            # 따로 둬서 archive_names() 에는 안쪽(실제 gem 내용) 이름만 남게 한다.
            outer = extract_archive(
                data, "gem.tar", outer_dir, fmt="tar",
                report=ExtractReport(extra_suffixes=frozenset({".gz"})),
            )
            data_tgz = outer / "data.tar.gz"
            meta_gz = outer / "metadata.gz"
            if not data_tgz.is_file():
                raise ArchiveError(f"{artifact.filename} has no data.tar.gz (not a .gem?)")
            extract_archive(data_tgz.read_bytes(), "data.tar.gz", dest, fmt="tar")
            if meta_gz.is_file():
                cap = min(_METADATA_CAP, MAX_UNCOMPRESSED_BYTES)
                text = _gunzip_capped(meta_gz.read_bytes(), cap)
                (dest / rules.METADATA_FILE).write_bytes(text)
        return dest

    def analyze_tree(
        self, tree: SourceTree, *, artifact: Artifact | None = None
    ) -> list[StaticFinding]:
        hint = None
        if artifact is not None:
            m = re.match(r"^(.+?)-\d[0-9A-Za-z._]*(?:-[A-Za-z0-9_.\-]+)?\.gem$", artifact.filename)
            hint = m.group(1) if m else None
        return rules.analyze_tree(tree, name_hint=hint)

    def rule_cwes(self) -> dict[str, frozenset[str]]:
        return dict(rules.RULE_CWES)

    def has_install_script(self, project: Project, version: str, archive_names: list[str]) -> bool:
        """네이티브 확장 빌드 스크립트(extconf.rb 등)가 있으면 gem install 이 코드를 돌린다."""
        return any(
            n.rsplit("/", 1)[-1].lower() in ("extconf.rb", "mkrf_conf.rb") for n in archive_names
        )

    def parse_manifest(self, filename: str, text: str) -> list[Dependency]:
        low = filename.lower().rsplit("/", 1)[-1]
        if low == "gemfile.lock":
            return manifests.parse_gemfile_lock(text, filename)
        if low == "gemfile":
            return manifests.parse_gemfile(text, filename)
        return []

    async def fetch_feed(
        self, client: httpx.AsyncClient
    ) -> tuple[list[tuple[str, str | None]], list[str]]:
        return await _feed.fetch_feed(client)


ADAPTER = RubyGemsAdapter()
__all__ = ["ADAPTER", "RubyGemsAdapter"]
