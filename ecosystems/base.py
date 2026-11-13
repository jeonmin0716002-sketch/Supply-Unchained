"""생태계 어댑터 계약 — 모든 패키지 생태계가 파이프라인에 꽂히는 단 하나의 인터페이스.

스캔 파이프라인(api/routers/scan.py), 감시기(watcher/), 프로젝트 스캔(inventory/)은
"pip 인지 npm 인지"를 몰라야 한다. 생태계마다 다른 것은 전부 이 파일의 ``Ecosystem``
뒤로 숨긴다:

    레지스트리 조회      fetch_project()      -> Project (공통 모델)
    받을 파일 고르기     select_artifacts()   -> [Artifact]
    압축 풀기            extract()            (기본: common.archive)
    정적분석             analyze_tree()       -> [StaticFinding]  (동기·순수 함수)
    이름 사칭 비교 대상   popular_names()
    의존성 파일 읽기     parse_manifest()     -> [Dependency]
    신규 업로드 피드     fetch_feed()

어댑터는 ``ecosystems/<id>/__init__.py`` 에 ``ADAPTER = <Ecosystem 인스턴스>`` 로 둔다.
레지스트리(``ecosystems.get``)가 이름으로 찾아 쓰므로 다른 파일을 고칠 필요가 없다.

지켜야 할 원칙 (기존 파이썬 엔진에서 실측으로 얻은 것 — docs/design/multi-ecosystem.md):

* **설치·실행하지 않는다.** 받은 아카이브는 안전 추출 후 읽기만 한다.
* **"못 봤다"를 "봤고 깨끗했다"로 보고하지 않는다.** 조회·추출 실패는 예외로 올린다.
* **HIGH 는 공급망 공격에 특유한 조합에만.** 위험 함수가 "있다"가 아니라 "설치·로드 시점에
  실행되고 무엇을 하느냐"로 본다. 그 언어 코드에 흔한 것은 MEDIUM(정황)이다.
* 네트워크 I/O 는 ``fetch_project``·``fetch_feed`` 에만 둔다. 나머지는 오프라인 테스트 가능.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from functools import cache
from pathlib import Path
from typing import Any, ClassVar

import httpx

from api.schemas import StaticFinding
from common.pypi import PackageNotFound, PyPIError
from engine.rules.base import SourceTree

#: 레지스트리 조회·다운로드·추출 실패의 공통 예외. 기존 코드가 전부 ``PyPIError`` 를 잡고
#: 있어서 같은 클래스를 쓴다 (이름만 일반화). ``PackageNotFound`` 메시지는 반드시
#: ``"<name> is not on <registry_label> (never existed, or removed)"`` 형태로 만든다 —
#: 감시기가 layer_errors 의 ``" is not on "`` 로 "삭제됨"을 가린다.
RegistryError = PyPIError

__all__ = [
    "Artifact",
    "Dependency",
    "Ecosystem",
    "PackageNotFound",
    "Project",
    "RegistryError",
    "Release",
    "load_popular",
]

_POPULAR_DIR = Path(__file__).parent / "data" / "popular"


@dataclass(frozen=True)
class Artifact:
    """릴리스의 내려받을 파일 하나."""

    filename: str
    url: str
    #: "sdist" | "wheel" | "tarball"(npm) | "crate" | "gem" | "jar" | "sources-jar" |
    #: "nupkg" | "zip"(go 모듈·composer dist)
    kind: str = ""
    size: int = 0
    sha256: str | None = None
    #: common.archive.extract_archive 의 fmt — "tar" | "zip". None 이면 파일명으로 판단.
    archive_format: str | None = None


@dataclass
class Release:
    version: str
    uploaded_at: datetime | None = None
    artifacts: list[Artifact] = field(default_factory=list)
    yanked: bool = False
    #: 런타임 의존성 **이름** (선택적·개발용 의존성 제외). 모르면 빈 리스트.
    dependencies: list[str] = field(default_factory=list)
    #: 레지스트리 메타데이터가 알려주는 "설치 시 실행 코드 있음" (npm ``hasInstallScript`` 등).
    #: None = 메타데이터로는 알 수 없음 → 아카이브를 보고 ``has_install_script()`` 가 판단.
    install_script: bool | None = None


@dataclass
class Project:
    """레지스트리 한 프로젝트의 공통 모델. 스코어링·감시기·버전 비교가 이것만 본다."""

    ecosystem: str
    name: str
    latest: str | None = None
    releases: dict[str, Release] = field(default_factory=dict)
    repository_url: str | None = None
    maintainers: list[str] = field(default_factory=list)
    #: 어댑터 전용 원본 데이터 (공통 코드는 읽지 않는다)
    extra: dict[str, Any] = field(default_factory=dict)

    def release(self, version: str) -> Release | None:
        return self.releases.get(version)

    def previous_version(self, version: str) -> str | None:
        """``version`` 직전에 올라온(업로드 시각 기준) 철회되지 않은 버전. 없으면 None.

        버전 문자열 정렬이 아니라 업로드 시각을 쓴다 — 생태계마다 버전 규칙이 다르고,
        "계정 탈취 직전의 정상 버전"은 시간상 직전 릴리스다.
        """
        cur = self.releases.get(version)
        if cur is None or cur.uploaded_at is None:
            return None
        older = [
            r for r in self.releases.values()
            if r.version != version and not r.yanked
            and r.uploaded_at is not None and r.uploaded_at < cur.uploaded_at
        ]
        return max(older, key=lambda r: r.uploaded_at).version if older else None


@dataclass(frozen=True)
class Dependency:
    """의존성 파일(lockfile·manifest)에서 읽은 항목 하나."""

    ecosystem: str
    name: str
    #: 정확한 버전. 범위만 있으면 None (그 경우 spec 에 원문).
    version: str | None
    spec: str = ""
    source: str = ""          # 읽은 파일 경로
    direct: bool | None = None  # 직접 의존성인가 (모르면 None)


@cache
def load_popular(ecosystem_id: str) -> frozenset[str]:
    """``ecosystems/data/popular/<id>.txt`` — 한 줄에 이름 하나, ``#`` 주석. 없으면 빈 집합."""
    path = _POPULAR_DIR / f"{ecosystem_id}.txt"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return frozenset()
    return frozenset(s for line in lines if (s := line.split("#", 1)[0].strip()))


class Ecosystem(ABC):
    """생태계 어댑터. 서브클래스는 클래스 속성과 ``fetch_project``·``analyze_tree`` 를 채운다."""

    #: API·CLI 가 쓰는 식별자 (api.schemas.Ecosystem 값과 같다): "pip", "npm", "cargo", ...
    id: ClassVar[str]
    #: OSV.dev 의 ecosystem 이름: "PyPI", "npm", "crates.io", "Go", "Maven", "RubyGems",
    #: "NuGet", "Packagist"
    osv_ecosystem: ClassVar[str]
    #: Package URL type (CycloneDX SBOM): "pypi", "npm", "cargo", "golang", "maven", "gem",
    #: "nuget", "composer"
    purl_type: ClassVar[str]
    #: 사람이 읽는 레지스트리 이름 — 오류 메시지에 쓴다: "PyPI", "npm", "crates.io", ...
    registry_label: ClassVar[str]
    #: ``parse_manifest`` 가 읽을 수 있는 파일 이름 (정확히 일치, 소문자 비교)
    manifest_filenames: ClassVar[tuple[str, ...]] = ()
    #: 신규 업로드 피드를 제공하는가 (``fetch_feed``)
    has_feed: ClassVar[bool] = False
    #: 압축은 선택 추출이다 — ``common.pypi.SCAN_SUFFIXES``·접미사 없는 파일·진입점만 풀린다.
    #: 규칙이 그 밖의 파일을 읽으면 여기에 접미사를 적는다 (예: maven 의 ``.class``).
    scan_suffixes: ClassVar[tuple[str, ...]] = ()

    #: 이름·버전 화이트리스트. 셸 메타문자·공백·경로 탈출(``..``)을 입구에서 막는다
    #: (api/schemas.py 의 Secure Design 주석 참고). 생태계 문법에 맞게 덮어쓴다.
    NAME_RE: ClassVar[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
    VERSION_RE: ClassVar[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9]+(?:[._+!~-][A-Za-z0-9]+)*$")
    MAX_NAME_LEN: ClassVar[int] = 214
    MAX_VERSION_LEN: ClassVar[int] = 64

    # ── 식별 ──────────────────────────────────────────────────────

    def validate(self, name: str, version: str) -> None:
        """잘못된 이름·버전이면 ValueError. URL·파일 경로를 조립하기 전에 반드시 통과시킨다."""
        if not (0 < len(name) <= self.MAX_NAME_LEN) or not self.NAME_RE.match(name):
            raise ValueError(f"{self.registry_label} 패키지명으로 쓸 수 없는 값: {name!r}")
        if ".." in name or ".." in version:
            raise ValueError("이름·버전에 '..' 는 쓸 수 없습니다")
        if not (0 < len(version) <= self.MAX_VERSION_LEN) or not self.VERSION_RE.match(version):
            raise ValueError(f"{self.registry_label} 버전으로 쓸 수 없는 값: {version!r}")

    def normalize_name(self, name: str) -> str:
        """같은 패키지를 가리키는 표기를 하나로. 기본은 소문자."""
        return name.lower()

    def purl(self, name: str, version: str) -> str:
        return f"pkg:{self.purl_type}/{name}@{version}"

    def web_url(self, name: str, version: str | None = None) -> str:
        """사람이 검토할 때 여는 레지스트리 페이지. 코드를 내려받지 않고 보는 링크가 있으면 그것."""
        return ""

    # ── 레지스트리 ────────────────────────────────────────────────

    @abstractmethod
    async def fetch_project(self, name: str, *, client: httpx.AsyncClient) -> Project:
        """프로젝트 메타데이터. 없으면 ``PackageNotFound``, 그 밖의 실패는 ``RegistryError``."""

    def select_artifacts(self, project: Project, version: str) -> list[Artifact]:
        """분석할 파일들. **사용자가 실제로 설치하게 되는 파일이 빠지면 안 된다** — 소스와
        빌드 산출물이 따로 올라가는 생태계(pip 의 sdist·wheel)는 둘 다 돌려준다."""
        release = project.release(version)
        return list(release.artifacts) if release else []

    def extract(self, data: bytes, artifact: Artifact, dest: str | Path) -> Path:
        """아카이브를 dest 에 안전 추출. 중첩 구조(.gem)는 어댑터가 덮어쓴다."""
        from common.archive import extract_archive

        return extract_archive(data, artifact.filename, dest, fmt=artifact.archive_format)

    # ── 분석 ──────────────────────────────────────────────────────

    @abstractmethod
    def analyze_tree(
        self, tree: SourceTree, *, artifact: Artifact | None = None
    ) -> list[StaticFinding]:
        """추출된 파일 트리에 이 생태계의 규칙을 돌린다. 동기·순수 함수 (I/O 는 tree 로만).

        규칙 ID 는 ``<id>-<이름>`` (예: ``npm-lifecycle-script``), 심각도 높은 순으로 정렬해
        돌려준다. 읽지 못한 파일은 조용히 건너뛰지 말고 ``unreadable`` 속성에 남긴다.
        """

    def rule_cwes(self) -> dict[str, frozenset[str]]:
        """규칙 ID → 그 규칙이 낼 수 있는 CWE. 문서·테스트가 한 곳에서 읽는다."""
        return {}

    def has_install_script(self, project: Project, version: str, archive_names: list[str]) -> bool:
        """설치 시 실행되는 코드가 있는가 (스코어링 신호). 기본은 메타데이터 값."""
        release = project.release(version)
        return bool(release and release.install_script)

    # ── 이름 사칭 ─────────────────────────────────────────────────

    def popular_names(self) -> frozenset[str]:
        return load_popular(self.id)

    def typosquat_score(self, name: str) -> float:
        """인기 패키지와의 이름 유사도 0.0~1.0. 스코프·그룹이 있는 생태계는 덮어쓴다."""
        from scoring.features import typosquat_score

        return typosquat_score(name, popular=self.popular_names())

    # ── 의존성 파일 ───────────────────────────────────────────────

    def parse_manifest(self, filename: str, text: str) -> list[Dependency]:
        """``manifest_filenames`` 중 하나의 내용 → 의존성 목록. 깨진 파일은 ValueError."""
        return []

    # ── 감시 ──────────────────────────────────────────────────────

    async def fetch_feed(
        self, client: httpx.AsyncClient
    ) -> tuple[list[tuple[str, str | None]], list[str]]:
        """새로 올라온 ``(name, version | None)`` 목록과 조회 오류. 실패를 빈 목록으로 숨기지
        않는다 — "새 패키지 없음"과 구분이 안 된다."""
        return [], []
