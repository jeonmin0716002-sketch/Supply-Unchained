"""Download + safe extraction of a package archive for static analysis.

``engine.static_analyzer.analyze_package`` is documented as "still to come"
(archive download/extraction is the missing half; ``analyze_path`` is done).
Integration can't wait on that, so the missing half lives here in the API layer
for now — once the engine part implements its own ``analyze_package``, the
router swaps ``fetched_package_tree`` + ``analyze_path`` for that single call
and this module retires. No engine code is modified in the meantime.

Safety notes (this extracts *untrusted* archives — treat accordingly):
  * tarfile uses the Python 3.12 ``filter="data"`` extraction filter, which
    rejects absolute paths, ``..`` traversal, symlinks/hardlinks out of the
    tree, and device files (PEP 706).
  * zipfile members are validated by hand (absolute paths / drive letters /
    ``..`` components are rejected) because zipfile has no equivalent filter.
  * Compressed size, decompressed size, and member count are all capped to
    guard against zip/tar bombs.
  * Nothing from the archive is ever imported or executed — files are only
    *read* by the AST-based analyzer.
"""

from __future__ import annotations

import tarfile
import tempfile
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path, PurePosixPath

import httpx

PYPI_JSON_URL = "https://pypi.org/pypi/{name}/{version}/json"

MAX_ARCHIVE_BYTES = 30 * 1024 * 1024        # compressed download cap
MAX_EXTRACTED_BYTES = 120 * 1024 * 1024     # decompressed total cap
MAX_MEMBERS = 4000                          # archive-bomb guard
_TIMEOUT = httpx.Timeout(20.0)

#: Preferred archive order — sdists carry setup.py / .pth install hooks, which
#: are exactly what the custom rules target, so they are analysed first choice.
_ARCHIVE_PREFERENCE = ("sdist", "bdist_wheel")


class PackageFetchError(RuntimeError):
    """Package archive could not be fetched/extracted (surfaced as layer_errors)."""


def _pick_archive_url(payload: dict) -> str | None:
    files = payload.get("urls") or []
    for wanted in _ARCHIVE_PREFERENCE:
        for f in files:
            if f.get("packagetype") == wanted and f.get("url"):
                return f["url"]
    return None


def _safe_zip_members(zf: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members: list[zipfile.ZipInfo] = []
    total = 0
    for info in zf.infolist():
        if len(members) >= MAX_MEMBERS:
            raise PackageFetchError("archive has too many members (bomb guard)")
        name = PurePosixPath(info.filename)
        if name.is_absolute() or ".." in name.parts or (name.parts and ":" in name.parts[0]):
            raise PackageFetchError(f"unsafe zip member path: {info.filename}")
        total += info.file_size
        if total > MAX_EXTRACTED_BYTES:
            raise PackageFetchError("archive decompresses too large (bomb guard)")
        members.append(info)
    return members


def _extract(archive: Path, dest: Path) -> None:
    if tarfile.is_tarfile(archive):
        with tarfile.open(archive) as tf:
            members = []
            total = 0
            for m in tf:
                if len(members) >= MAX_MEMBERS:
                    raise PackageFetchError("archive has too many members (bomb guard)")
                total += max(m.size, 0)
                if total > MAX_EXTRACTED_BYTES:
                    raise PackageFetchError("archive decompresses too large (bomb guard)")
                members.append(m)
            # PEP 706 data filter: blocks traversal / abs paths / links / devices.
            tf.extractall(dest, members=members, filter="data")
    elif zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest, members=_safe_zip_members(zf))
    else:
        raise PackageFetchError(f"unsupported archive format: {archive.name}")


async def _download(client: httpx.AsyncClient, url: str, dest: Path) -> None:
    size = 0
    try:
        async with client.stream("GET", url, timeout=_TIMEOUT, follow_redirects=True) as resp:
            resp.raise_for_status()
            with dest.open("wb") as fh:
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                    if size > MAX_ARCHIVE_BYTES:
                        raise PackageFetchError("archive exceeds download size cap")
                    fh.write(chunk)
    except httpx.HTTPError as exc:
        raise PackageFetchError(f"archive download failed: {exc}") from exc


@asynccontextmanager
async def fetched_package_tree(
    name: str,
    version: str,
    *,
    client: httpx.AsyncClient,
):
    """Async context manager yielding a temp directory with the extracted package.

    Usage (router)::

        async with fetched_package_tree(req.name, req.version, client=http) as tree:
            findings = engine.analyze_path(tree)

    The temp directory (archive included) is removed on exit, success or not.
    Raises :class:`PackageFetchError` for anything that prevents analysis; the
    router converts that into a ``layer_errors`` entry rather than failing the
    whole scan.
    """
    try:
        resp = await client.get(
            PYPI_JSON_URL.format(name=name, version=version), timeout=_TIMEOUT
        )
        if resp.status_code == 404:
            raise PackageFetchError(f"{name}=={version} not found on PyPI")
        resp.raise_for_status()
        payload = resp.json()
    except httpx.HTTPError as exc:
        raise PackageFetchError(f"PyPI metadata lookup failed: {exc}") from exc
    except ValueError as exc:
        raise PackageFetchError("PyPI returned a non-JSON body") from exc

    url = _pick_archive_url(payload)
    if not url:
        raise PackageFetchError(f"{name}=={version} publishes no sdist/wheel archive")

    with tempfile.TemporaryDirectory(prefix="su-scan-") as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / "archive"
        await _download(client, url, archive)

        tree = tmp_path / "tree"
        tree.mkdir()
        _extract(archive, tree)
        yield tree
