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
import io
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

#: Largest artifact we will pull down. Malicious packages are almost always
#: tiny; this is a guard, not a functional limit.
MAX_ARTIFACT_BYTES = 30 * 1024 * 1024
#: Largest total uncompressed payload we will unpack (decompression bomb guard).
MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024
#: Largest number of archive members we will consider.
MAX_MEMBERS = 5000

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


def is_safe_member_name(name: str) -> bool:
    """Reject archive paths that would escape the extraction directory."""
    if not name or name.startswith(("/", "\\")):
        return False
    if _DRIVE_PREFIX.match(name):
        return False
    normalized = name.replace("\\", "/")
    return all(part not in ("..", "") for part in PurePosixPath(normalized).parts)


def _extract_tar(data: bytes, dest: Path) -> None:
    # "r:*" transparently handles gz/bz2/xz/uncompressed; hard-coding one
    # compression silently skips the others.
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
        members = []
        total = 0
        for index, member in enumerate(tar):
            if index >= MAX_MEMBERS:
                raise ArchiveError(f"archive has more than {MAX_MEMBERS} members")
            # Links and device nodes have no content to analyse and are the
            # classic path-escape trick.
            if not (member.isreg() or member.isdir()):
                continue
            if not is_safe_member_name(member.name):
                raise ArchiveError(f"unsafe archive path: {member.name!r}")
            total += member.size
            if total > MAX_UNCOMPRESSED_BYTES:
                raise ArchiveError(
                    f"uncompressed size exceeds {MAX_UNCOMPRESSED_BYTES} bytes "
                    "(possible decompression bomb)"
                )
            members.append(member)
        tar.extractall(dest, members=members, filter="data")


def _extract_zip(data: bytes, dest: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            raise ArchiveError(f"archive has more than {MAX_MEMBERS} members")

        total = 0
        for info in infos:
            if not is_safe_member_name(info.filename):
                raise ArchiveError(f"unsafe archive path: {info.filename!r}")
            total += info.file_size
            if total > MAX_UNCOMPRESSED_BYTES:
                raise ArchiveError(
                    f"uncompressed size exceeds {MAX_UNCOMPRESSED_BYTES} bytes "
                    "(possible decompression bomb)"
                )
        # 억제 근거(B202): bandit 은 extractall 호출만 보고 HIGH 를 매기지만, 위 루프가
        # 모든 멤버 이름을 is_safe_member_name() 으로 이미 검사해 경로 탈출을 걸러냈다.
        # zipfile 은 tarfile 과 달리 심볼릭 링크를 링크로 풀지 않고 일반 파일로 쓰므로
        # tar 쪽의 filter="data" 에 해당하는 추가 방어가 필요 없다. 억제하지 않으면
        # CI 의 bandit 게이트가 상시 빨간불이 되어 진짜 신규 findings 를 가린다.
        zf.extractall(dest)  # nosec B202


def extract(data: bytes, filename: str, dest: str | Path) -> Path:
    """Unpack an artifact into ``dest``, enforcing the safety limits above."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    lowered = filename.lower()

    try:
        if lowered.endswith(_TAR_SUFFIXES):
            _extract_tar(data, dest)
        elif lowered.endswith(_ZIP_SUFFIXES):
            _extract_zip(data, dest)
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
        data = await download(art, client=self.client)
        # 추출은 최대 MAX_UNCOMPRESSED_BYTES(200 MB) 를 디스크에 쓰는 동기 작업이라 코루틴에서
        # 그대로 부르면 이벤트 루프가 멈춘다 — /health 와 프록시 스트리밍까지 함께 죽는다.
        # 실측으로 /health 가 3.3초까지 밀렸다.
        root = await asyncio.to_thread(self.eco.extract, data, art, dest)
        item.root = Path(root)
        item.names = [
            p.relative_to(item.root).as_posix() for p in item.root.rglob("*") if p.is_file()
        ]

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
