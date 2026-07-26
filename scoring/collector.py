"""PyPI metadata collector.

This is the I/O layer of the scoring package. Given a package name and version,
it fetches everything we need from public PyPI endpoints and returns a plain
``PackageMetadata`` object. All the *analysis* happens in :mod:`scoring.features`
and :mod:`scoring.scorer`, which operate on that object and never touch the
network -- that split keeps the scoring logic unit-testable offline.

PyPI access itself lives in :mod:`common.pypi`, which is shared with the engine:
a scan needs the same project JSON and the same artifact for both layers, and
fetching them twice meant two downloads and two copies of the archive-safety
code. This module now only decides what the scorer needs from that data.

Important limitations (be honest about these in the demo):
    * The JSON API does **not** expose the maintainer account's creation date,
      so ``is_new_account`` is approximated by "the package itself is new"
      (see :func:`scoring.features.is_new_package`).
    * The JSON API no longer exposes download counts, so the "new but spiking
      downloads" signal from the design doc is left as a future hook.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx

from common.pypi import PackageContext, PyPIError


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


def _has_setup_py(archive_names: list[str]) -> bool:
    """True if the artifact ships an install-time ``setup.py``."""
    return any(name.rsplit("/", 1)[-1] == "setup.py" for name in archive_names)


async def _collect_with_context(ctx: PackageContext, *, inspect_sdist: bool) -> PackageMetadata:
    try:
        project = await ctx.project()
    except PyPIError as exc:
        return PackageMetadata(name=ctx.name, version=ctx.version, note=str(exc))

    meta = PackageMetadata(
        name=ctx.name,
        version=ctx.version,
        found=True,
        release_dates=_parse_release_dates(project.releases),
        requires_dist=list(project.info.get("requires_dist") or []),
    )

    if not project.has_version(ctx.version):
        # The project exists but this release does not. Metadata-derived signals
        # would describe some other version, so say so rather than implying the
        # requested one was checked.
        meta.note = f"version {ctx.version} is not published for {ctx.name}"
        return meta

    if inspect_sdist:
        try:
            meta.has_install_script = _has_setup_py(await ctx.archive_names())
        except PyPIError as exc:
            # Do not let "we could not look" pass as "there is no install
            # script" -- that silently removes 20 points of risk.
            meta.note = f"artifact not inspected: {exc}"

    return meta


async def collect(
    name: str,
    version: str,
    *,
    client: httpx.AsyncClient | None = None,
    ctx: PackageContext | None = None,
    inspect_sdist: bool = True,
) -> PackageMetadata:
    """Fetch metadata for ``name==version`` from PyPI.

    Pass the router's ``ctx`` so the project JSON and artifact are fetched once
    per scan and shared with the engine; otherwise a private context is used.

    Never raises: on a 404 or any network error the returned
    :class:`PackageMetadata` has ``found=False``, safe defaults, and a ``note``
    saying why, so the caller can still score the package on name-only signals
    (typosquatting) without special-casing. Malicious packages get removed from
    PyPI, so "not found" is a case worth scoring, not an error.
    """
    if ctx is not None:
        return await _collect_with_context(ctx, inspect_sdist=inspect_sdist)

    async with PackageContext(name, version, client=client) as own_ctx:
        return await _collect_with_context(own_ctx, inspect_sdist=inspect_sdist)
