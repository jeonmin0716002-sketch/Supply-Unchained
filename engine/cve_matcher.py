"""Layer (1): known-vulnerability matching against OSV.dev.

OSV is the single upstream source for now (it already aggregates CVE, GHSA and
PyPA advisories for PyPI); NVD is a later reinforcement, hence the ``VulnSource``
enum already carrying both.

Network I/O lives here and nowhere else in the engine, so the parsing logic
below stays unit-testable offline against captured OSV payloads.
"""

from __future__ import annotations

from typing import Any

import httpx

from api.schemas import Ecosystem, ScanRequest, Severity, Vulnerability, VulnSource

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
DEFAULT_TIMEOUT = 10.0

# Our Ecosystem enum uses installer-facing names ("pip"); OSV uses index names.
_OSV_ECOSYSTEM = {Ecosystem.PIP: "PyPI"}

# GHSA/OSV publish a coarse label in database_specific. "MODERATE" is GitHub's
# spelling of what our schema calls "medium".
_LABEL_TO_SEVERITY = {
    "LOW": Severity.LOW,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}

# Range kinds whose "fixed" event is a version a user can actually install.
# GIT ranges are excluded on purpose — those carry commit hashes.
_INSTALLABLE_RANGE_TYPES = {"ECOSYSTEM", "SEMVER"}

# Used when an advisory carries only a CVSS vector string and no coarse label.
# Deriving a real base score from the vector needs a CVSS implementation; until
# then we degrade to "medium" rather than silently under- or over-stating risk.
# TODO(engine): add CVSS v3/v4 vector scoring so this fallback becomes rare.
_UNKNOWN_SEVERITY = Severity.MEDIUM


class CveLookupError(RuntimeError):
    """Upstream OSV lookup failed — the API surfaces this as HTTP 502."""


def _parse_severity(vuln: dict[str, Any]) -> Severity:
    label = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(label, str):
        mapped = _LABEL_TO_SEVERITY.get(label.upper())
        if mapped is not None:
            return mapped
    return _UNKNOWN_SEVERITY


def _parse_fixed_version(vuln: dict[str, Any], package_name: str) -> str | None:
    """First version that fixes the advisory, for the CLI's upgrade hint.

    OSV expresses fixes as range *events*; an advisory may cover several
    packages, so entries are filtered back down to the one we asked about.

    Only ECOSYSTEM/SEMVER ranges are usable: a GIT range's "fixed" event is a
    commit hash, and telling a user to upgrade to
    "74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5" is worse than saying nothing.
    """
    wanted = _normalize_name(package_name)
    for affected in vuln.get("affected") or []:
        name = ((affected.get("package") or {}).get("name")) or ""
        if _normalize_name(name) != wanted:
            continue
        for rng in affected.get("ranges") or []:
            if rng.get("type") not in _INSTALLABLE_RANGE_TYPES:
                continue
            for event in rng.get("events") or []:
                fixed = event.get("fixed")
                if fixed:
                    return str(fixed)
    return None


def _normalize_name(name: str) -> str:
    """PEP 503 normalisation — 'Foo.Bar_baz' and 'foo-bar-baz' are one project."""
    out = []
    prev_dash = False
    for ch in name.lower():
        if ch in "-_.":
            if not prev_dash:
                out.append("-")
            prev_dash = True
        else:
            out.append(ch)
            prev_dash = False
    return "".join(out)


def parse_osv_response(payload: dict[str, Any], package_name: str) -> list[Vulnerability]:
    """Map a raw OSV /v1/query payload onto the shared ``Vulnerability`` contract."""
    results: list[Vulnerability] = []
    for vuln in payload.get("vulns") or []:
        vuln_id = vuln.get("id")
        if not vuln_id:
            continue
        results.append(
            Vulnerability(
                source=VulnSource.OSV,
                id=str(vuln_id),
                severity=_parse_severity(vuln),
                summary=vuln.get("summary") or None,
                fixed_version=_parse_fixed_version(vuln, package_name),
            )
        )
    return results


async def query_osv(
    name: str,
    version: str,
    *,
    ecosystem: Ecosystem = Ecosystem.PIP,
    client: httpx.AsyncClient | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[Vulnerability]:
    """Ask OSV which advisories affect exactly this name+version.

    Passing ``client`` lets the caller reuse a connection pool (the API should,
    once this is wired into the router).
    """
    body = {
        "version": version,
        "package": {
            "name": name,
            "ecosystem": _OSV_ECOSYSTEM.get(ecosystem, "PyPI"),
        },
    }

    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=timeout)
    try:
        response = await client.post(OSV_QUERY_URL, json=body, timeout=timeout)
        response.raise_for_status()
        payload = response.json()
    except httpx.HTTPError as exc:
        raise CveLookupError(f"OSV lookup failed for {name}=={version}: {exc}") from exc
    except ValueError as exc:  # malformed JSON
        raise CveLookupError(f"OSV returned a non-JSON body for {name}=={version}") from exc
    finally:
        if owns_client:
            await client.aclose()

    return parse_osv_response(payload, name)


async def match_package(
    req: ScanRequest,
    *,
    client: httpx.AsyncClient | None = None,
) -> list[Vulnerability]:
    """Engine entry point for layer (1) — replaces the router's ``_mock_cve_layer``."""
    return await query_osv(
        req.name,
        req.version,
        ecosystem=req.ecosystem,
        client=client,
    )
