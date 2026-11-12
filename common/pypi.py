"""Shared PyPI access: metadata, artifact download, and safe extraction.

Both detection parts need the same two things from PyPI -- the project's JSON
metadata and the release artifact -- so fetching them lives here instead of
being implemented twice:

    engine.static_analyzer   needs the extracted tree to run rules over
    scoring.collector        needs release dates, deps, and the file listing

``PackageContext`` fetches each of those at most once per scan and hands the
same result to both parts. Before this existed a single ``/scan`` downloaded
the same sdist twice and carried two separate copies of the archive-safety
logic.

Safety notes -- this code downloads and unpacks archives that are, by
assumption, hostile. A scanner that can be attacked by the thing it scans is
worse than no scanner:

* the download is streamed and capped, and Content-Length is rejected up front
  so an oversized artifact is never buffered in memory at all
* the uncompressed total is capped while walking members, which is what stops
  a decompression bomb -- the compressed size alone says nothing
* member paths are rejected if absolute, drive-qualified, or containing '..'
  (zip-slip), and non-regular members (symlinks, devices) are skipped entirely
* tar extraction additionally uses Python 3.12's vetted ``filter="data"``
"""

from __future__ import annotations

import asyncio
import contextvars
import io
import os
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any

import httpx

PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"

DEFAULT_TIMEOUT = httpx.Timeout(15.0)
USER_AGENT = "Supply-Unchained/0.1 (+https://github.com/jeonmin0716002-sketch/Supply-Unchained)"

def _artifact_cap_bytes() -> int:
    try:
        mb = float(os.environ.get("SU_MAX_ARTIFACT_MB", "100"))
    except ValueError:
        mb = 100.0
    return int(max(mb, 1.0) * 1024 * 1024)


#: 내려받을 아티팩트 하나의 상한 (SU_MAX_ARTIFACT_MB, 기본 100 MB).
#:
#: 예전 값 30 MB 는 "메모리에 통째로 버퍼링한다"는 전제의 값이었다. 이제 디스크로 스트리밍
#: 하므로 메모리가 아니라 시간·디스크가 한계이고, 상한을 넘으면 "검사하지 못함"이 되어
#: 판정이 최소 warn·프록시는 차단이다 — 상한이 낮을수록 정상 패키지가 막힌다. 100 MB 는
#: PyPI 의 기본 파일 업로드 상한이라, 별도 증설을 받지 않은 프로젝트(torch·tensorflow 같은
#: 소수의 거대 바이너리 wheel 제외)의 모든 파일이 들어온다.
MAX_ARTIFACT_BYTES = _artifact_cap_bytes()
#: 분석 대상 파일들의 압축 해제 합계 상한 (decompression bomb 방어). 분석하지 않는 파일은
#: 풀지 않으므로 세지 않는다.
MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024
#: 풀어서 분석할 파일 수 상한. 아카이브 전체 멤버 수가 아니다 — 데이터 파일이 많은 정상
#: 패키지를 "멤버 5000개 초과"로 통째로 못 보던 문제(감시기 실측 16k 스캔 중 61건)를 막는다.
MAX_MEMBERS = 5000
#: 목록을 만들 아카이브 멤버 수의 상한. tar 는 끝까지 읽어야 멤버를 알 수 있어서, 헤더만
#: 수백만 개인 조작된 아카이브로 메모리를 채우는 것을 막는다. 넘으면 그 뒤는 못 본 것으로
#: 보고한다.
MAX_LISTED_MEMBERS = 200_000

_DRIVE_PREFIX = re.compile(r"^[a-zA-Z]:")
_TAR_SUFFIXES = (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")
_ZIP_SUFFIXES = (".zip", ".whl", ".egg")


class PyPIError(RuntimeError):
    """PyPI could not be reached, or returned something unusable."""


class PackageNotFound(PyPIError):
    """The project does not exist on PyPI (404)."""


class ArchiveError(PyPIError):
    """The artifact could not be unpacked, or violated a safety limit."""


@dataclass
class Artifact:
    """One downloadable file of a release."""

    filename: str
    packagetype: str  # "sdist" | "bdist_wheel" | ...
    url: str
    size: int = 0

    @property
    def is_sdist(self) -> bool:
        return self.packagetype == "sdist"


@dataclass
class ProjectData:
    """The parts of PyPI's project JSON that either part actually reads."""

    name: str
    info: dict[str, Any] = field(default_factory=dict)
    releases: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    def has_version(self, version: str) -> bool:
        return version in self.releases

    def artifacts(self, version: str) -> list[Artifact]:
        return [
            Artifact(
                filename=f.get("filename", ""),
                packagetype=f.get("packagetype", ""),
                url=f.get("url", ""),
                size=int(f.get("size") or 0),
            )
            for f in self.releases.get(version, [])
            if f.get("url")
        ]


def new_client(timeout: httpx.Timeout | None = None) -> httpx.AsyncClient:
    """A client configured the way every caller here wants it."""
    return httpx.AsyncClient(
        timeout=timeout or DEFAULT_TIMEOUT,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    )


async def fetch_project(name: str, *, client: httpx.AsyncClient) -> ProjectData:
    """Fetch a project's PyPI JSON.

    Raises ``PackageNotFound`` on 404 and ``PyPIError`` on anything else, so
    "does not exist" stays distinguishable from "lookup failed" -- a scanner
    must never report those two as the same thing.
    """
    try:
        resp = await client.get(PYPI_JSON_URL.format(name=name))
    except httpx.HTTPError as exc:
        raise PyPIError(f"PyPI lookup failed for {name}: {exc}") from exc

    if resp.status_code == 404:
        raise PackageNotFound(f"{name} is not on PyPI (never existed, or removed)")
    if resp.status_code != 200:
        raise PyPIError(f"PyPI returned {resp.status_code} for {name}")

    try:
        data = resp.json()
    except ValueError as exc:
        raise PyPIError(f"PyPI returned a non-JSON body for {name}") from exc

    return ProjectData(
        name=name,
        info=data.get("info") or {},
        releases=data.get("releases") or {},
    )


def select_artifact(artifacts: list[Artifact]) -> Artifact | None:
    """Pick the artifact worth analysing.

    sdists win because install-time code (``setup.py``) only ships there. A
    wheel is still worth scanning when that is all a release publishes: wheels
    can carry ``.pth`` files, which execute at interpreter startup.
    """
    for art in artifacts:
        if art.is_sdist:
            return art
    for art in artifacts:
        if art.filename.endswith(".whl"):
            return art
    return artifacts[0] if artifacts else None


async def download(artifact: Artifact, *, client: httpx.AsyncClient) -> bytes:
    """Stream an artifact into memory, refusing anything oversized.

    The cap is enforced *during* the transfer, not after: checking the size of
    an already-buffered body would mean the damage is done.
    """
    if artifact.size and artifact.size > MAX_ARTIFACT_BYTES:
        raise ArchiveError(
            f"{artifact.filename} is {artifact.size} bytes, over the "
            f"{MAX_ARTIFACT_BYTES} byte limit"
        )

    buf = bytearray()
    try:
        async with client.stream("GET", artifact.url) as resp:
            resp.raise_for_status()

            declared = resp.headers.get("content-length")
            if declared and int(declared) > MAX_ARTIFACT_BYTES:
                raise ArchiveError(
                    f"{artifact.filename} declares {declared} bytes, over the limit"
                )

            async for chunk in resp.aiter_bytes():
                buf += chunk
                if len(buf) > MAX_ARTIFACT_BYTES:
                    raise ArchiveError(
                        f"{artifact.filename} exceeded {MAX_ARTIFACT_BYTES} bytes mid-transfer"
                    )
    except httpx.HTTPError as exc:
        raise ArchiveError(f"download failed for {artifact.filename}: {exc}") from exc

    return bytes(buf)


async def download_to_file(
    artifact: Artifact | Any, path: Path, *, client: httpx.AsyncClient
) -> Path:
    """디스크로 스트리밍해 받는다 — 상한까지 받아도 메모리에는 청크 하나만 올라간다.

    상한 검사는 ``download()`` 와 같다: 메타데이터 크기 → Content-Length → 전송 중 누적.
    """
    if artifact.size and artifact.size > MAX_ARTIFACT_BYTES:
        raise ArchiveError(
            f"{artifact.filename} is {artifact.size} bytes, over the "
            f"{MAX_ARTIFACT_BYTES} byte limit (SU_MAX_ARTIFACT_MB)"
        )
    written = 0
    try:
        async with client.stream("GET", artifact.url) as resp:
            resp.raise_for_status()
            declared = resp.headers.get("content-length")
            if declared and int(declared) > MAX_ARTIFACT_BYTES:
                raise ArchiveError(
                    f"{artifact.filename} declares {declared} bytes, over the limit "
                    "(SU_MAX_ARTIFACT_MB)"
                )
            with open(path, "wb") as fh:
                async for chunk in resp.aiter_bytes():
                    written += len(chunk)
                    if written > MAX_ARTIFACT_BYTES:
                        raise ArchiveError(
                            f"{artifact.filename} exceeded {MAX_ARTIFACT_BYTES} bytes "
                            "mid-transfer (SU_MAX_ARTIFACT_MB)"
                        )
                    fh.write(chunk)
    except httpx.HTTPError as exc:
        raise ArchiveError(f"download failed for {artifact.filename}: {exc}") from exc
    return path


def is_safe_member_name(name: str) -> bool:
    """Reject archive paths that would escape the extraction directory."""
    if not name or name.startswith(("/", "\\")):
        return False
    if _DRIVE_PREFIX.match(name):
        return False
    normalized = name.replace("\\", "/")
    return all(part not in ("..", "") for part in PurePosixPath(normalized).parts)


# ──────────────────────────────
# 선택 추출
# ──────────────────────────────

#: 분석기가 읽는 파일 — 생태계 전부의 코드·설정·스크립트. 이것만 풀고, 이것만 상한에 센다.
#: 접미사가 없는 파일(``bin/cli``·``Rakefile``·``META-INF/services/*``·``PKG-INFO``)도 푼다 —
#: 셸 스크립트·서비스 등록 파일은 접미사 없이 실행 경로가 된다.
SCAN_SUFFIXES = frozenset({
    # python (engine.static_analyzer.TEXT_SUFFIXES 포함)
    ".py", ".pyw", ".pth", ".toml", ".cfg", ".txt", ".in", ".ini",
    # 스크립트
    ".sh", ".bash", ".bat", ".cmd", ".ps1", ".psm1", ".psd1",
    # js
    ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx", ".json", ".gyp", ".gypi",
    # rust·go·c (build.rs, cgo, 네이티브 확장)
    ".rs", ".go", ".mod", ".sum", ".c", ".h", ".cc", ".cpp", ".s",
    # jvm
    ".java", ".kt", ".kts", ".groovy", ".gradle", ".scala", ".xml", ".properties", ".mf",
    # ruby·php
    ".rb", ".gemspec", ".rake", ".ru", ".php", ".phtml", ".inc",
    # .net
    ".targets", ".props", ".nuspec", ".cs", ".vb", ".fs", ".csx", ".config",
    # 공통 설정
    ".yml", ".yaml", ".lock",
})

#: 설치·import·로드 시점에 실행되거나 실행을 결정하는 파일 — 상한에 걸려 일부만 풀 때 먼저
#: 푼다 (docs/design/multi-ecosystem.md §2.4 의 생태계별 자동 실행 경로).
ENTRYPOINT_BASENAMES = frozenset({
    "setup.py", "__init__.py", "__main__.py", "pyproject.toml", "setup.cfg", "PKG-INFO",
    "METADATA", "WHEEL", "entry_points.txt", "package.json", "binding.gyp", "build.rs",
    "Cargo.toml", "go.mod", "extconf.rb", "Rakefile", "install.ps1", "init.ps1",
    "composer.json", "pom.xml",
})
_ENTRYPOINT_SUFFIXES = (".pth", ".gemspec", ".targets", ".props", ".nuspec")


@dataclass
class ExtractReport:
    """한 번의 추출(중첩 추출이면 여러 번)에 대한 기록. 파이프라인이 "다 봤는가"를 판단한다."""

    #: 아카이브의 모든 멤버 이름 (풀지 않은 것 포함) — archive_names() 의 원본
    names: list[str] = field(default_factory=list)
    #: 일부만 푼 사유들. 비어 있으면 분석 대상 파일을 전부 풀었다.
    truncated: list[str] = field(default_factory=list)
    #: 어댑터가 더 풀고 싶은 접미사 (``scan_suffixes`` 속성)
    extra_suffixes: frozenset[str] = frozenset()
    extracted: int = 0


#: 어댑터가 ``extract()`` 를 덮어써도(.gem 중첩 등) common.archive 를 거치기만 하면 기록이
#: 남게 하는 통로. PackageContext 가 추출 전에 설정한다 (asyncio.to_thread 는 컨텍스트를
#: 복사하므로 스레드 안에서도 같은 객체가 보인다).
current_report: contextvars.ContextVar[ExtractReport | None] = contextvars.ContextVar(
    "su_extract_report", default=None
)


def is_scan_target(name: str, extra_suffixes: frozenset[str] = frozenset()) -> bool:
    base = name.rsplit("/", 1)[-1]
    if not base:
        return False
    suffix = PurePosixPath(base).suffix.lower()
    return (
        suffix == ""
        or suffix in SCAN_SUFFIXES
        or suffix in extra_suffixes
        or base in ENTRYPOINT_BASENAMES
    )


def _priority(name: str) -> tuple[int, int, str]:
    base = name.rsplit("/", 1)[-1]
    entry = (
        base in ENTRYPOINT_BASENAMES
        or base.endswith(_ENTRYPOINT_SUFFIXES)
        or "META-INF/services/" in name
    )
    return (0 if entry else 1, name.count("/"), name)


def _plan(candidates: list[tuple[str, int]], report: ExtractReport) -> set[str]:
    """분석 대상 (이름, 크기) 중 상한 안에서 풀 것을 고른다.

    상한을 넘으면 진입점 → 얕은 경로 → 이름 순으로 채우고, 못 푼 개수를 보고한다.
    예전처럼 통째로 거부하지 않는 이유: 그러면 setup.py 하나 못 보고 "검사 불가"가 된다.
    부분이라도 보는 것이 낫고, 부분이라는 사실은 숨기지 않는다(판정은 최소 warn).
    """
    total = sum(size for _n, size in candidates)
    if len(candidates) <= MAX_MEMBERS and total <= MAX_UNCOMPRESSED_BYTES:
        return {n for n, _s in candidates}
    chosen: set[str] = set()
    used = 0
    for name, size in sorted(candidates, key=lambda c: _priority(c[0])):
        if len(chosen) >= MAX_MEMBERS:
            break
        if used + size > MAX_UNCOMPRESSED_BYTES:
            continue  # 큰 파일 하나 때문에 작은 진입점을 버리지 않는다
        chosen.add(name)
        used += size
    skipped = len(candidates) - len(chosen)
    reasons = []
    if len(candidates) > MAX_MEMBERS:
        reasons.append(f"분석 대상 파일 {len(candidates)}개 > 상한 {MAX_MEMBERS}개")
    if total > MAX_UNCOMPRESSED_BYTES:
        reasons.append(
            f"압축 해제 합계 {total} bytes > 상한 {MAX_UNCOMPRESSED_BYTES} bytes "
            "(decompression bomb 방어)"
        )
    report.truncated.append(
        f"{' · '.join(reasons)} — 진입점·얕은 경로 우선으로 {len(chosen)}개만 풀고 "
        f"{skipped}개는 검사하지 못함"
    )
    return chosen


def _extract_tar(src: bytes | Path, dest: Path, report: ExtractReport) -> None:
    # "r:*" transparently handles gz/bz2/xz/uncompressed; hard-coding one
    # compression silently skips the others.
    source = {"name": src} if isinstance(src, Path) else {"fileobj": io.BytesIO(src)}
    with tarfile.open(mode="r:*", **source) as tar:
        members: dict[str, tarfile.TarInfo] = {}
        candidates: list[tuple[str, int]] = []
        for index, member in enumerate(tar):
            if index >= MAX_LISTED_MEMBERS:
                report.truncated.append(
                    f"아카이브 멤버가 {MAX_LISTED_MEMBERS}개를 넘어 그 뒤는 목록도 보지 못함"
                )
                break
            # 경로 검사는 풀지 않을 멤버에도 한다 — 경로 탈출을 시도하는 아카이브는 그 자체로
            # 적대적이고, "안 풀었으니 괜찮다"로 넘기면 다른 도구가 풀 때 터진다.
            if not is_safe_member_name(member.name):
                raise ArchiveError(f"unsafe archive path: {member.name!r}")
            # Links and device nodes have no content to analyse and are the
            # classic path-escape trick.
            if not member.isreg():
                continue
            report.names.append(member.name)
            if is_scan_target(member.name, report.extra_suffixes):
                members[member.name] = member
                candidates.append((member.name, member.size))
        chosen = _plan(candidates, report)
        selected = [m for n, m in members.items() if n in chosen]
        tar.extractall(dest, members=selected, filter="data")
        report.extracted += len(selected)


def _extract_zip(src: bytes | Path, dest: Path, report: ExtractReport) -> None:
    with zipfile.ZipFile(src if isinstance(src, Path) else io.BytesIO(src)) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_LISTED_MEMBERS:
            report.truncated.append(
                f"아카이브 멤버가 {len(infos)}개 > {MAX_LISTED_MEMBERS}개라 그 뒤는 보지 못함"
            )
            infos = infos[:MAX_LISTED_MEMBERS]
        by_name: dict[str, zipfile.ZipInfo] = {}
        candidates: list[tuple[str, int]] = []
        for info in infos:
            if not is_safe_member_name(info.filename):
                raise ArchiveError(f"unsafe archive path: {info.filename!r}")
            if info.is_dir():
                continue
            report.names.append(info.filename)
            if is_scan_target(info.filename, report.extra_suffixes):
                by_name[info.filename] = info
                candidates.append((info.filename, info.file_size))
        chosen = _plan(candidates, report)
        selected = [i for n, i in by_name.items() if n in chosen]
        # 억제 근거(B202): bandit 은 extractall 호출만 보고 HIGH 를 매기지만, 위 루프가
        # 모든 멤버 이름을 is_safe_member_name() 으로 이미 검사해 경로 탈출을 걸러냈다.
        # zipfile 은 tarfile 과 달리 심볼릭 링크를 링크로 풀지 않고 일반 파일로 쓰므로
        # tar 쪽의 filter="data" 에 해당하는 추가 방어가 필요 없다. file_size 를 속여도
        # ZipExtFile 이 선언 크기까지만 내놓고 CRC 불일치는 BadZipFile 로 올린다.
        zf.extractall(dest, members=selected)  # nosec B202
        report.extracted += len(selected)


def _archive_kind(filename: str) -> str | None:
    lowered = filename.lower()
    if lowered.endswith(_TAR_SUFFIXES):
        return "tar"
    if lowered.endswith(_ZIP_SUFFIXES):
        return "zip"
    return None


def extract(
    data: bytes | Path, filename: str, dest: str | Path, *, report: ExtractReport | None = None
) -> Path:
    """Unpack an artifact into ``dest``, enforcing the safety limits above.

    ``data`` 는 바이트 또는 디스크에 받아 둔 파일 경로. 분석 대상 파일만 풀고, 상한에 걸려
    일부만 풀었으면 ``report.truncated`` 에 사유를 남긴다(예외가 아니다 — 부분이라도 본다).
    ``report`` 를 안 주면 ``current_report`` 컨텍스트 값을 쓴다.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    if report is None:
        report = current_report.get() or ExtractReport()
    kind = _archive_kind(filename)
    src = Path(data) if isinstance(data, os.PathLike) else data

    try:
        if kind == "tar":
            _extract_tar(src, dest, report)
        elif kind == "zip":
            _extract_zip(src, dest, report)
        else:
            raise ArchiveError(f"unsupported archive format: {filename}")
    except ArchiveError:
        raise
    except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError) as exc:
        raise ArchiveError(f"could not unpack {filename}: {exc}") from exc

    return dest


@dataclass
class ExtractedArtifact:
    """한 아카이브를 푼 결과. 파일마다 따로 푼다 — 규칙이 루트 배치에 의존하기 때문이다
    (wheel 루트의 ``.pth`` 는 인터프리터 시작 시 실행되지만, sdist 안의 같은 파일은 아니다).
    """

    artifact: Any  # ecosystems.base.Artifact
    root: Path | None = None
    #: 아카이브의 **모든** 멤버 이름 (선택 추출로 풀지 않은 파일 포함)
    names: list[str] = field(default_factory=list)
    #: 받거나 풀지 못한 사유. None 이 아니면 이 파일은 검사되지 않은 것이다.
    error: PyPIError | None = None
    #: 상한 때문에 일부만 풀었으면 그 사유 (None = 분석 대상 파일 전부 풀었음)
    truncated: str | None = None

    @property
    def filename(self) -> str:
        return self.artifact.filename


def _as_artifact(art: Any) -> Any:
    """``common.pypi.Artifact``(구형) 도 받는다 — 프록시·도구가 아직 그 모양을 쓴다."""
    from ecosystems.base import Artifact as EcoArtifact

    if isinstance(art, EcoArtifact):
        return art
    kind = getattr(art, "kind", None) or {"bdist_wheel": "wheel"}.get(
        getattr(art, "packagetype", ""), getattr(art, "packagetype", "")
    )
    return EcoArtifact(
        filename=art.filename, url=art.url, kind=kind, size=int(getattr(art, "size", 0) or 0)
    )


class PackageContext:
    """Per-scan registry state, fetched once and shared by every layer.

    Use as an async context manager so the extracted trees are cleaned up::

        async with PackageContext(name, version, ecosystem="npm") as ctx:
            for ex in await ctx.extracted_roots():
                ...

    생태계 무관: 레지스트리 조회·파일 선택·추출은 ``ecosystems.get(ecosystem)`` 어댑터가
    한다. pip 은 기존 공개 API(``project()`` 가 PyPI JSON 의 ``ProjectData`` 를 돌려주는 것,
    ``extracted_path()`` 가 루트 하나를 돌려주는 것)를 그대로 유지한다 — engine/·scoring/·
    tools/ 가 그 모양에 의존한다.

    ``artifacts`` 를 주면 레지스트리가 고르는 대신 **그 파일들만** 스캔한다. 프록시가 "요청된
    바로 그 파일"을 스캔하는 데 쓴다(스캔한 파일 = 설치되는 파일).
    """

    def __init__(
        self,
        name: str,
        version: str,
        *,
        client: httpx.AsyncClient | None = None,
        ecosystem: str = "pip",
        artifacts: list[Any] | None = None,
    ) -> None:
        self.name = name
        self.version = version
        self.ecosystem = getattr(ecosystem, "value", ecosystem)
        self._explicit = [_as_artifact(a) for a in artifacts] if artifacts is not None else None
        self._client = client
        self._owns_client = client is None
        self._project: ProjectData | None = None
        self._project_error: PyPIError | None = None
        self._loaded = False
        self._model: Any = None
        self._model_error: PyPIError | None = None
        self._model_done = False
        self._tmpdir: TemporaryDirectory | None = None
        self._roots: list[ExtractedArtifact] | None = None
        self._roots_error: PyPIError | None = None
        # 락을 나누는 이유: 아티팩트를 고르려면 프로젝트 JSON 이 필요해서, 락 하나로는
        # 자기 자신을 기다리며 멈춘다 (asyncio.Lock 은 재진입이 안 된다).
        self._project_lock = asyncio.Lock()
        self._model_lock = asyncio.Lock()
        self._artifact_lock = asyncio.Lock()

    async def __aenter__(self) -> PackageContext:
        if self._client is None:
            self._client = new_client()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._tmpdir is not None:
            self._tmpdir.cleanup()
            self._tmpdir = None
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = new_client()
        return self._client

    @property
    def eco(self) -> Any:
        """이 스캔의 생태계 어댑터 (``ecosystems.base.Ecosystem``)."""
        import ecosystems  # 지연 import — ecosystems.base 가 이 모듈을 import 한다

        return ecosystems.get(self.ecosystem)

    async def project(self) -> Any:
        """pip: PyPI 프로젝트 JSON(``ProjectData``). 그 밖의 생태계: ``model()`` 과 같다.

        한 번만 조회하고, 실패도 캐시해 같은 예외를 다시 던진다.
        """
        if self.ecosystem != "pip":
            return await self.model()
        async with self._project_lock:
            if not self._loaded:
                self._loaded = True
                try:
                    self._project = await fetch_project(self.name, client=self.client)
                except PyPIError as exc:
                    self._project_error = exc
        if self._project_error is not None:
            raise self._project_error
        assert self._project is not None
        return self._project

    async def model(self) -> Any:
        """공통 ``ecosystems.base.Project`` 모델 (스코어링·버전 비교가 본다)."""
        async with self._model_lock:
            if not self._model_done:
                self._model_done = True
                try:
                    if self.ecosystem == "pip":
                        from ecosystems.pip.registry import to_project

                        self._model = to_project(await self.project())
                    else:
                        self._model = await self.eco.fetch_project(self.name, client=self.client)
                except PyPIError as exc:
                    self._model_error = exc
        if self._model_error is not None:
            raise self._model_error
        return self._model

    async def previous_version(self) -> str | None:
        """업로드 시각 기준 직전 버전 (``Project.previous_version``)."""
        return (await self.model()).previous_version(self.version)

    async def selected_artifacts(self) -> list[Any]:
        """스캔할 파일들. 명시한 ``artifacts`` 가 있으면 그것, 없으면 어댑터가 고른다."""
        if self._explicit is not None:
            return list(self._explicit)
        return self.eco.select_artifacts(await self.model(), self.version)

    async def extracted_roots(self) -> list[ExtractedArtifact]:
        """선택된 파일마다 하나씩 푼 루트. 첫 항목이 주(primary) 아티팩트다.

        파일 하나가 실패해도 나머지는 푼다 — 실패는 그 항목의 ``error`` 에 남는다(호출부가
        "검사하지 못함"으로 보고한다). 아티팩트 목록 자체를 못 얻으면(조회 실패) 예외.
        """
        async with self._artifact_lock:
            if self._roots is None and self._roots_error is None:
                try:
                    self._roots = await self._download_and_extract_all()
                except PyPIError as exc:
                    self._roots_error = exc
        if self._roots_error is not None:
            raise self._roots_error
        assert self._roots is not None
        return self._roots

    async def _download_and_extract_all(self) -> list[ExtractedArtifact]:
        arts = await self.selected_artifacts()
        out: list[ExtractedArtifact] = []
        for index, art in enumerate(arts):
            if self._tmpdir is None:
                self._tmpdir = TemporaryDirectory(prefix="su-scan-")
            dest = Path(self._tmpdir.name) / str(index)
            item = ExtractedArtifact(artifact=art)
            try:
                await self._fetch_one(art, dest, item)
            except PyPIError as exc:
                item.error = exc
                item.root = None
            out.append(item)
        return out

    async def _fetch_one(self, art: Any, dest: Path, item: ExtractedArtifact) -> None:
        from ecosystems.base import Ecosystem

        eco = self.eco
        dest.mkdir(parents=True, exist_ok=True)
        blob = dest.with_name(dest.name + ".download")
        await download_to_file(art, blob, client=self.client)
        report = ExtractReport(
            extra_suffixes=frozenset(s.lower() for s in getattr(eco, "scan_suffixes", ()) or ())
        )

        def _extract() -> Path:
            token = current_report.set(report)
            try:
                if type(eco).extract is Ecosystem.extract:
                    # 기본 추출 — 파일 경로를 그대로 넘겨 메모리에 올리지 않는다.
                    from common.archive import extract_archive

                    return extract_archive(blob, art.filename, dest, fmt=art.archive_format)
                # 어댑터가 덮어쓴 추출(.gem 중첩 등)은 계약상 bytes 를 받는다.
                return eco.extract(blob.read_bytes(), art, dest)
            finally:
                current_report.reset(token)

        try:
            # 추출은 최대 MAX_UNCOMPRESSED_BYTES(200 MB) 를 디스크에 쓰는 동기 작업이라
            # 코루틴에서 그대로 부르면 이벤트 루프가 멈춘다 — /health 와 프록시 스트리밍까지
            # 함께 죽는다. 실측으로 /health 가 3.3초까지 밀렸다.
            root = await asyncio.to_thread(_extract)
        finally:
            blob.unlink(missing_ok=True)
        item.root = Path(root)
        item.names = list(report.names) or [
            p.relative_to(item.root).as_posix() for p in item.root.rglob("*") if p.is_file()
        ]
        item.truncated = "; ".join(report.truncated) or None

    async def extracted_path(self) -> Path | None:
        """주 아티팩트를 푼 경로. 이 릴리스에 파일이 없으면 None.

        한 번만 받고 풀며, 실패도 캐시한다 — 깨진 아카이브를 다음 레이어가 다시 받지 않는다.
        """
        roots = await self.extracted_roots()
        if not roots:
            return None
        if roots[0].error is not None:
            raise roots[0].error
        return roots[0].root

    async def archive_names(self) -> list[str]:
        """주 아티팩트 안의 파일 경로 목록 (없으면 빈 리스트)."""
        roots = await self.extracted_roots()
        if not roots:
            return []
        if roots[0].error is not None:
            raise roots[0].error
        return list(roots[0].names)
