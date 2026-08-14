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
        zf.extractall(dest)


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


class PackageContext:
    """Per-scan PyPI state, fetched once and shared by every layer.

    Use as an async context manager so the extracted tree is cleaned up::

        async with PackageContext(name, version) as ctx:
            findings = await analyze_package(req, ctx=ctx)
            signals, score = await score_package(req, ctx=ctx)
    """

    def __init__(
        self,
        name: str,
        version: str,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.name = name
        self.version = version
        self._client = client
        self._owns_client = client is None
        self._project: ProjectData | None = None
        self._project_error: PyPIError | None = None
        self._loaded = False
        self._tmpdir: TemporaryDirectory | None = None
        self._extracted: Path | None = None
        self._extract_error: PyPIError | None = None
        self._extract_done = False
        # Two locks, not one: fetching the artifact needs the project JSON, so a
        # single lock would deadlock on itself (asyncio.Lock is not reentrant).
        self._project_lock = asyncio.Lock()
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

    async def project(self) -> ProjectData:
        """The project JSON, fetched at most once. Re-raises the same error."""
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

    async def extracted_path(self) -> Path | None:
        """Path to the unpacked artifact, or None if this release has none.

        Downloaded and unpacked at most once. Failures are cached too, so a
        broken artifact is not re-fetched by the next layer that asks.
        """
        async with self._artifact_lock:
            if not self._extract_done:
                self._extract_done = True
                try:
                    self._extracted = await self._download_and_extract()
                except PyPIError as exc:
                    self._extract_error = exc
        if self._extract_error is not None:
            raise self._extract_error
        return self._extracted

    async def _download_and_extract(self) -> Path | None:
        project = await self.project()
        artifact = select_artifact(project.artifacts(self.version))
        if artifact is None:
            return None

        data = await download(artifact, client=self.client)
        self._tmpdir = TemporaryDirectory(prefix="su-scan-")
        return extract(data, artifact.filename, self._tmpdir.name)

    async def archive_names(self) -> list[str]:
        """Flat list of file paths inside the artifact (empty if there is none)."""
        root = await self.extracted_path()
        if root is None:
            return []
        return [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()]
