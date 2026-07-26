"""Engine regression tests — offline except for the opt-in live OSV check."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from api.schemas import Ecosystem, Severity, VulnSource
from engine import cve_matcher
from engine.cve_matcher import CveLookupError, parse_osv_response, query_osv
from engine.rules.code_patterns import RULE_DANGEROUS_CALL, RULE_OBFUSCATED
from engine.rules.install_hooks import RULE_INSTALL_HOOK, RULE_PTH
from engine.static_analyzer import _SEVERITY_ORDER, StaticAnalysisError, analyze_path
from engine.verdict import KNOWN_CWES, RULE_CATALOG

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def rules_in(findings) -> set[str]:
    return {f.rule for f in findings}


# ──────────────────────────────
# Layer 2 — samples/ end-to-end
# ──────────────────────────────


def test_samples_directory_is_scannable():
    findings = analyze_path(SAMPLES)
    assert findings, "the sample fixtures must produce findings"
    # Most severe first, so the router can slice the head for verdict reasons.
    ranks = [_SEVERITY_ORDER[f.severity] for f in findings]
    assert ranks == sorted(ranks)


@pytest.mark.parametrize(
    ("sample", "expected_rule"),
    [
        ("sample1_install_hook", RULE_DANGEROUS_CALL),
        ("sample1_install_hook", RULE_INSTALL_HOOK),
        ("sample2_obfuscated", RULE_OBFUSCATED),
        ("sample2_obfuscated", RULE_DANGEROUS_CALL),
        ("sample3_pth_autoexec", RULE_PTH),
        ("sample4_pickle", RULE_DANGEROUS_CALL),
    ],
)
def test_each_sample_is_detected(sample, expected_rule):
    assert expected_rule in rules_in(analyze_path(SAMPLES / sample))


def test_pth_finding_is_high_and_tagged():
    findings = analyze_path(SAMPLES / "sample3_pth_autoexec")
    pth = [f for f in findings if f.rule == RULE_PTH]
    assert len(pth) == 1
    assert pth[0].severity is Severity.HIGH
    assert pth[0].cwe == "CWE-94"
    assert pth[0].location.endswith(":4")


# ──────────────────────────────
# Layer 2 — false-positive guards
# ──────────────────────────────


def test_pth_path_entries_are_not_flagged(tmp_path):
    """A normal .pth is a list of path entries — those must stay silent."""
    (tmp_path / "normal.pth").write_text(
        "../src\n/opt/company/lib\n# a comment\nimportlib_is_not_a_trigger\n",
        encoding="utf-8",
    )
    assert analyze_path(tmp_path) == []


def test_build_ext_override_is_not_flagged(tmp_path):
    """Compiled packages legitimately override build_ext."""
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\n"
        "setup(name='x', cmdclass={'build_ext': object})\n",
        encoding="utf-8",
    )
    assert RULE_INSTALL_HOOK not in rules_in(analyze_path(tmp_path))


def test_subprocess_without_shell_is_not_flagged(tmp_path):
    (tmp_path / "mod.py").write_text(
        "import subprocess\nsubprocess.run(['ls', '-la'])\n", encoding="utf-8"
    )
    assert analyze_path(tmp_path) == []


def test_decoder_without_exec_sink_is_not_flagged(tmp_path):
    """b64decode on its own is ordinary; only decode-into-exec is the signal."""
    (tmp_path / "mod.py").write_text(
        "import base64\nlogo = base64.b64decode(ICON)\n", encoding="utf-8"
    )
    assert RULE_OBFUSCATED not in rules_in(analyze_path(tmp_path))


# ──────────────────────────────
# Layer 2 — rule detail
# ──────────────────────────────


def test_from_import_form_is_detected(tmp_path):
    """`from os import system` must match the same rule as `os.system`."""
    (tmp_path / "mod.py").write_text(
        "from os import system\nsystem('id')\n", encoding="utf-8"
    )
    findings = analyze_path(tmp_path)
    assert RULE_DANGEROUS_CALL in rules_in(findings)
    assert findings[0].cwe == "CWE-78"


def test_shell_true_is_detected(tmp_path):
    (tmp_path / "mod.py").write_text(
        "import subprocess\nsubprocess.run('curl evil', shell=True)\n", encoding="utf-8"
    )
    assert RULE_DANGEROUS_CALL in rules_in(analyze_path(tmp_path))


def test_nested_decode_chain_is_detected(tmp_path):
    (tmp_path / "mod.py").write_text(
        "import base64, zlib\nexec(zlib.decompress(base64.b64decode(P)))\n",
        encoding="utf-8",
    )
    assert RULE_OBFUSCATED in rules_in(analyze_path(tmp_path))


def test_unparseable_python_is_skipped_not_fatal(tmp_path):
    (tmp_path / "legacy.py").write_text("print 'python 2'\n", encoding="utf-8")
    assert analyze_path(tmp_path) == []


def test_missing_path_raises():
    with pytest.raises(StaticAnalysisError):
        analyze_path(SAMPLES / "does-not-exist")


# ──────────────────────────────
# CWE catalogue consistency
# ──────────────────────────────


def test_every_emitted_cwe_is_declared():
    """Guards against a rule quietly introducing an unreviewed CWE tag."""
    for finding in analyze_path(SAMPLES):
        info = RULE_CATALOG.get(finding.rule)
        assert info is not None, f"{finding.rule} missing from RULE_CATALOG"
        assert finding.cwe in info.cwes
        assert finding.cwe in KNOWN_CWES


# ──────────────────────────────
# Layer 1 — OSV parsing
# ──────────────────────────────

OSV_PAYLOAD = {
    "vulns": [
        {
            "id": "GHSA-9wx4-h78v-vm56",
            "summary": "Requests leaks Proxy-Authorization headers on redirect",
            "database_specific": {"severity": "MODERATE"},
            "affected": [
                {
                    "package": {"name": "Requests", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "2.31.0"}],
                        }
                    ],
                }
            ],
        },
        {
            "id": "PYSEC-0000-1",
            "database_specific": {"severity": "CRITICAL"},
            "affected": [{"package": {"name": "other-pkg", "ecosystem": "PyPI"}}],
        },
        {
            # Only a CVSS vector, no coarse label -> documented medium fallback.
            "id": "CVE-0000-0000",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N"}],
        },
        {
            # PYSEC entries often carry a GIT range whose "fixed" is a commit.
            "id": "PYSEC-0000-2",
            "affected": [
                {
                    "package": {"name": "requests", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "GIT",
                            "events": [{"fixed": "74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5"}],
                        }
                    ],
                }
            ],
        },
    ]
}


def test_parse_osv_maps_contract_fields():
    vulns = parse_osv_response(OSV_PAYLOAD, "requests")
    assert [v.id for v in vulns] == [
        "GHSA-9wx4-h78v-vm56",
        "PYSEC-0000-1",
        "CVE-0000-0000",
        "PYSEC-0000-2",
    ]
    assert all(v.source is VulnSource.OSV for v in vulns)

    ghsa = vulns[0]
    assert ghsa.severity is Severity.MEDIUM  # GitHub's "MODERATE"
    assert ghsa.fixed_version == "2.31.0"  # matched despite "Requests" casing
    assert ghsa.summary


def test_fixed_version_ignores_other_packages():
    """An advisory covering several projects must not leak another's fix."""
    assert parse_osv_response(OSV_PAYLOAD, "requests")[1].fixed_version is None


def test_cvss_only_entry_falls_back_to_medium():
    assert parse_osv_response(OSV_PAYLOAD, "requests")[2].severity is Severity.MEDIUM


def test_git_range_is_not_reported_as_a_fixed_version():
    """A commit hash is not something a user can `pip install`."""
    assert parse_osv_response(OSV_PAYLOAD, "requests")[3].fixed_version is None


def test_empty_response_is_no_vulnerabilities():
    assert parse_osv_response({}, "requests") == []


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [("Foo.Bar_baz", "foo-bar-baz"), ("zope--interface", "zope-interface")],
)
def test_name_normalization(raw, normalized):
    assert cve_matcher._normalize_name(raw) == normalized


# ──────────────────────────────
# Layer 1 — transport behaviour
# ──────────────────────────────


async def test_query_osv_sends_expected_body():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.read()))
        return httpx.Response(200, json=OSV_PAYLOAD)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        vulns = await query_osv("requests", "2.30.0", client=client)

    assert seen["package"] == {"name": "requests", "ecosystem": "PyPI"}
    assert seen["version"] == "2.30.0"
    assert len(vulns) == 4


async def test_upstream_failure_raises_lookup_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(CveLookupError):
            await query_osv("requests", "2.30.0", client=client)


async def test_network_error_raises_lookup_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(CveLookupError):
            await query_osv("requests", "2.30.0", client=client)


@pytest.mark.live
async def test_live_osv_lookup():
    """Opt-in: `uv run pytest -m live`. Hits the real OSV.dev API."""
    vulns = await query_osv("requests", "2.30.0", ecosystem=Ecosystem.PIP)
    assert any(v.id.startswith(("GHSA", "CVE", "PYSEC")) for v in vulns)
