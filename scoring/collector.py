"""PyPI metadata collector.

This is the I/O layer of the scoring package. Given a package name and version,
it fetches everything we need from public PyPI endpoints and returns a plain
``PackageMetadata`` object. All the *analysis* happens in :mod:`scoring.features`
and :mod:`scoring.scorer`, which operate on that object and never touch the
network -- that split keeps the scoring logic unit-testable offline.

Data sources (both public, no auth):
    * PyPI JSON API  ``https://pypi.org/pypi/{name}/json``
    * The source distribution (sdist) archive, only its file *listing* is read
      to decide whether an install-time ``setup.py`` exists.

Important limitations (be honest about these in the demo):
    * The JSON API does **not** expose the maintainer account's creation date,
      so ``is_new_account`` is approximated by "the package itself is new"
      (see :func:`scoring.features.is_new_package`).
    * The JSON API no longer exposes download counts, so the "new but spiking
      downloads" signal from the design doc is left as a future hook.
"""

from __future__ import annotations

import io
import tarfile
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx

PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"

# Network + safety limits.
_HTTP_TIMEOUT = httpx.Timeout(10.0)
# Skip inspecting an sdist larger than this (compressed). Malicious packages are
# almost always tiny; this just guards against accidentally pulling a huge file.
_MAX_SDIST_BYTES = 20 * 1024 * 1024
# Stop scanning archive members after this many, as a tar-bomb guard.
_MAX_ARCHIVE_MEMBERS = 2000


@dataclass
class PackageMetadata:
    """Normalized, network-free view of a package used by the scorer.

    When ``found`` is ``False`` (package missing / removed / lookup failed) the
    remaining fields carry safe defaults, so downstream code can treat the
    object uniformly without ``None`` checks.
    """

    name: str
    version: str
    found: bool = False
    # Release datetime (earliest file upload) for every version of the package.
    release_dates: list[datetime] = field(default_factory=list)
    # Runtime dependencies declared for the requested version (raw specifiers).
    requires_dist: list[str] = field(default_factory=list)
    # Whether the requested version ships a source distribution containing a
    # setup.py -- i.e. code that can run at install time.
    has_install_script: bool = False
    # Free-form note for diagnostics (e.g. why a lookup failed).
    note: str | None = None


def _parse_release_dates(releases: dict) -> list[datetime]:
    """Earliest upload time per version, across all versions of the package."""
    dates: list[datetime] = []
    for files in releases.values():
        version_times: list[datetime] = []
        for f in files:
            raw = f.get("upload_time_iso_8601") or f.get("upload_time")
            if not raw:
                continue
            try:
                # PyPI uses e.g. "2023-05-22T15:12:44.123456Z".
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                continue
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            version_times.append(dt)
        if version_times:
            dates.append(min(version_times))
    return sorted(dates)


def _find_sdist_url(version_files: list[dict]) -> str | None:
    """URL of the source distribution for a version, if one is published."""
    for f in version_files:
        if f.get("packagetype") == "sdist":
            return f.get("url")
    return None


async def _sdist_has_setup_py(client: httpx.AsyncClient, url: str) -> bool:
    """Return True if the sdist archive contains a ``setup.py`` member.

    Only the archive's file *listing* is read; nothing is extracted or executed,
    so this is safe to run against untrusted packages. Any error is treated as
    "unknown" and returns False rather than failing the whole scan.
    """
    try:
        resp = await client.get(url)
        resp.raise_for_status()
        content = resp.content
        if len(content) > _MAX_SDIST_BYTES:
            return False
        # sdists are gzipped tarballs (.tar.gz). Read members sequentially and
        # stop as soon as we see a setup.py.
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
            for i, member in enumerate(tar):
                if i >= _MAX_ARCHIVE_MEMBERS:
                    break
                if member.name.rsplit("/", 1)[-1] == "setup.py":
                    return True
    except (httpx.HTTPError, tarfile.TarError, OSError, ValueError):
        return False
    return False


async def collect(
    name: str,
    version: str,
    *,
    client: httpx.AsyncClient | None = None,
    inspect_sdist: bool = True,
) -> PackageMetadata:
    """Fetch metadata for ``name==version`` from PyPI.

    Returns a :class:`PackageMetadata`; on a 404 or any network error the object
    has ``found=False`` and safe defaults, so the caller can still score the
    package on name-only signals (typosquatting) without special-casing.
    """
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(
            timeout=_HTTP_TIMEOUT,
            follow_redirects=True,
            headers={"User-Agent": "Supply-Unchained/0.1"},
        )
    try:
        try:
            resp = await client.get(PYPI_JSON_URL.format(name=name))
        except httpx.HTTPError as exc:
            return PackageMetadata(name=name, version=version, note=f"lookup failed: {exc!r}")

        if resp.status_code == 404:
            return PackageMetadata(
                name=name,
                version=version,
                note="package not found on PyPI (removed, private, or typo)",
            )
        if resp.status_code != 200:
            return PackageMetadata(
                name=name, version=version, note=f"unexpected status {resp.status_code}"
            )

        data = resp.json()
        info = data.get("info", {})
        releases = data.get("releases", {}) or {}

        meta = PackageMetadata(
            name=name,
            version=version,
            found=True,
            release_dates=_parse_release_dates(releases),
            requires_dist=list(info.get("requires_dist") or []),
        )

        # has_install_script: only meaningful when we can look at the requested
        # version's sdist. Wheel-only versions cannot run arbitrary install code.
        version_files = releases.get(version, [])
        sdist_url = _find_sdist_url(version_files)
        if inspect_sdist and sdist_url:
            meta.has_install_script = await _sdist_has_setup_py(client, sdist_url)

        return meta
    finally:
        if owns_client:
            await client.aclose()
