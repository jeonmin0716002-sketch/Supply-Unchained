"""API-part integration tests — offline (layers are monkeypatched or use samples/).

Covers: verdict wiring, partial-failure policy (layer_errors), persistence,
history endpoints, proxy link rewriting, and the download gate blocking flow.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from api import cwe
from api.cwe import UNKNOWN_CWE, cwe_for_bandit
from api.main import app
from api.routers import proxy, scan
from api.schemas import RiskSignals, Severity, StaticFinding, Vulnerability, VulnSource
from common.pypi import PyPIError

SAFE_SIGNALS = RiskSignals(
    is_new_account=False,
    typosquat_score=0.05,
    has_install_script=False,
    dependency_count=4,
)
BAD_SIGNALS = RiskSignals(
    is_new_account=True,
    typosquat_score=0.82,
    has_install_script=True,
    dependency_count=0,
    release_burst=True,
)

PTH_FINDING = StaticFinding(
    rule="custom-pth",
    cwe="CWE-94",
    severity=Severity.HIGH,
    location="install.pth:1",
    detail=".pth autoexec",
)
CVE = Vulnerability(
    source=VulnSource.OSV,
    id="GHSA-test",
    severity=Severity.MEDIUM,
    summary="test advisory",
    fixed_version="9.9.9",
)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SU_DB_PATH", str(tmp_path / "test.db"))

    async def _no_tagging(vulns, http):  # CWE 태깅은 전용 테스트에서만 (오프라인 원칙)
        return None

    monkeypatch.setattr(scan, "tag_vulnerabilities", _no_tagging)
    with TestClient(app) as c:  # lifespan 실행 (http client + store init)
        yield c


def _patch_layers(monkeypatch, *, vulns=(), findings=(), signals=SAFE_SIGNALS, score=5):
    async def fake_cve(req, http, errors):
        return list(vulns)

    async def fake_static(req, ctx, errors):
        return list(findings)

    async def fake_scoring(req, ctx, errors):
        return signals, score

    monkeypatch.setattr(scan, "_layer_cve", fake_cve)
    monkeypatch.setattr(scan, "_layer_static", fake_static)
    monkeypatch.setattr(scan, "_layer_scoring", fake_scoring)


# ──────────────────────────────
# /api/v1/scan — 판정 배선
# ──────────────────────────────

def test_scan_safe(client, monkeypatch):
    _patch_layers(monkeypatch)
    r = client.post("/api/v1/scan", json={"name": "httpx", "version": "0.27.0"})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "safe"
    assert body["scan_id"] >= 1
    assert body["layer_errors"] == []


def test_scan_warn_on_cve(client, monkeypatch):
    _patch_layers(monkeypatch, vulns=[CVE])
    body = client.post("/api/v1/scan", json={"name": "requests", "version": "2.31.0"}).json()
    assert body["verdict"] == "warn"
    assert body["vulnerabilities"][0]["fixed_version"] == "9.9.9"


def test_scan_block_on_static_high(client, monkeypatch):
    _patch_layers(monkeypatch, findings=[PTH_FINDING], signals=BAD_SIGNALS, score=90)
    body = client.post("/api/v1/scan", json={"name": "reqeusts", "version": "1.0.0"}).json()
    assert body["verdict"] == "block"
    assert any("고위험" in x for x in body["verdict_reasons"])


def test_scan_survives_layer_failure(client, monkeypatch):
    """OSV 장애 시 502로 죽지 않고 layer_errors 에 명시 (부분 실패 정책)."""

    async def broken_cve(req, http, errors):
        errors.append("cve: OSV lookup failed (simulated)")
        return []

    _patch_layers(monkeypatch)
    monkeypatch.setattr(scan, "_layer_cve", broken_cve)
    body = client.post("/api/v1/scan", json={"name": "httpx", "version": "0.27.0"}).json()
    assert body["verdict"] == "safe"
    assert body["layer_errors"] and "cve:" in body["layer_errors"][0]


def test_static_layer_converts_fetch_error(client, monkeypatch):
    """아카이브 수집 실패가 스캔 실패가 아니라 layer_errors 로 강등되는지.

    실제 ``_layer_static`` 의 변환을 통과시켜야 의미가 있으므로 ①③만 오프라인으로
    대체하고, 엔진 호출만 PyPIError 를 던지게 만든다.
    """

    async def fake_cve(req, http, errors):
        return []

    async def fake_scoring(req, ctx, errors):
        return SAFE_SIGNALS, 5

    async def boom(req, *, ctx=None):
        raise PyPIError("ghost-pkg is not on PyPI")

    monkeypatch.setattr(scan, "_layer_cve", fake_cve)
    monkeypatch.setattr(scan, "_layer_scoring", fake_scoring)
    monkeypatch.setattr(scan, "analyze_package", boom)

    body = client.post("/api/v1/scan", json={"name": "ghost-pkg", "version": "0.0.1"}).json()
    assert any(e.startswith("static:") for e in body["layer_errors"])
    assert body["verdict"] == "safe"  # 남은 레이어로 판정은 계속된다


def test_layers_share_one_package_context(client, monkeypatch):
    """②③ 가 같은 PackageContext 를 받는지 — PyPI 중복 조회 방지의 핵심 계약."""
    seen = []

    async def fake_cve(req, http, errors):
        return []

    async def fake_static(req, ctx, errors):
        seen.append(ctx)
        return []

    async def fake_scoring(req, ctx, errors):
        seen.append(ctx)
        return SAFE_SIGNALS, 5

    monkeypatch.setattr(scan, "_layer_cve", fake_cve)
    monkeypatch.setattr(scan, "_layer_static", fake_static)
    monkeypatch.setattr(scan, "_layer_scoring", fake_scoring)

    client.post("/api/v1/scan", json={"name": "httpx", "version": "0.27.0"})
    assert len(seen) == 2 and seen[0] is seen[1]


def test_offline_demo_needs_no_network(client, monkeypatch):
    """SU_OFFLINE_DEMO — 회선이 죽어도 block 판정 데모가 되는지 (레이어 미호출)."""
    monkeypatch.setattr(scan, "_OFFLINE_DEMO", True)
    body = client.post("/api/v1/scan", json={"name": "reqeusts", "version": "1.0.0"}).json()
    assert body["verdict"] == "block"
    assert any("오프라인 데모" in r for r in body["verdict_reasons"])
    assert body["scan_id"] >= 1  # 데모 결과도 이력에 남아 대시보드가 동작한다


# ──────────────────────────────
# 이력 / 영속성
# ──────────────────────────────

def test_history_roundtrip(client, monkeypatch):
    _patch_layers(monkeypatch)
    first = client.post("/api/v1/scan", json={"name": "a", "version": "1"}).json()
    client.post("/api/v1/scan", json={"name": "b", "version": "2"})

    rows = client.get("/api/v1/scans", params={"limit": 10}).json()
    assert [r["name"] for r in rows[:2]] == ["b", "a"]  # 최신 우선

    one = client.get(f"/api/v1/scans/{first['scan_id']}")
    assert one.status_code == 200 and one.json()["name"] == "a"
    assert client.get("/api/v1/scans/999999").status_code == 404


# ──────────────────────────────
# pip 프록시
# ──────────────────────────────

def test_index_link_rewrite():
    html = ('<a href="https://files.pythonhosted.org/packages/aa/bb/x-1.0.tar.gz'
            '#sha256=deadbeef">x-1.0.tar.gz</a>')
    out = proxy.rewrite_index_html(html)
    assert 'href="/files?u=https%3A%2F%2Ffiles.pythonhosted.org' in out
    assert out.endswith('#sha256=deadbeef">x-1.0.tar.gz</a>')  # 해시 검증 프래그먼트 보존


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("requests-2.31.0.tar.gz", ("requests", "2.31.0")),
        ("requests-2.31.0-py3-none-any.whl", ("requests", "2.31.0")),
        ("scikit_learn-1.5.0-cp312-cp312-manylinux_2_17_x86_64.whl", ("scikit_learn", "1.5.0")),
        ("weird_name.txt", None),
    ],
)
def test_parse_archive_filename(filename, expected):
    assert proxy.parse_archive_filename(filename) == expected


def test_gate_blocks_malicious(client, monkeypatch):
    _patch_layers(monkeypatch, findings=[PTH_FINDING], signals=BAD_SIGNALS, score=90)
    url = "https%3A%2F%2Ffiles.pythonhosted.org%2Fpackages%2Fx%2Freqeusts-1.0.0.tar.gz"
    r = client.get(f"/files?u={url}")
    assert r.status_code == 403
    assert r.json()["error"] == "blocked_by_supply_unchained"
    assert r.json()["package"] == "reqeusts==1.0.0"


def test_gate_rejects_open_proxy_abuse(client):
    r = client.get("/files", params={"u": "https://evil.example.com/x-1.0.tar.gz"})
    assert r.status_code == 400


# ──────────────────────────────
# CWE 파싱 (재웅 담당분)
# ──────────────────────────────

def test_bandit_blacklist_cwe_comes_from_bandit_itself():
    assert cwe_for_bandit("B301") == "CWE-502"   # pickle
    assert cwe_for_bandit("B102") == "CWE-78"    # exec_used (supplement)
    assert cwe_for_bandit("B999") == UNKNOWN_CWE


def test_cwes_from_osv_parses_ghsa_shape():
    payload = {"database_specific": {"cwe_ids": ["CWE-522", "CWE-200", "not-a-cwe"]}}
    assert cwe.cwes_from_osv(payload) == ["CWE-522", "CWE-200"]
    assert cwe.cwes_from_osv({}) == []                      # PYSEC 계열: CWE 없음이 정상
    assert cwe.cwes_from_osv({"database_specific": {}}) == []


async def test_tag_vulnerabilities_fills_cwe_ids_and_survives_errors():
    """OSV /v1/vulns 재조회 태깅 — 성공/404/비JSON 이 섞여도 스캔을 막지 않는다."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/GHSA-good"):
            return httpx.Response(
                200, json={"database_specific": {"cwe_ids": ["CWE-94"]}}
            )
        if request.url.path.endswith("/GHSA-gone"):
            return httpx.Response(404)
        return httpx.Response(200, text="not json")

    vulns = [
        Vulnerability(source=VulnSource.OSV, id="GHSA-good", severity=Severity.HIGH),
        Vulnerability(source=VulnSource.OSV, id="GHSA-gone", severity=Severity.LOW),
        Vulnerability(source=VulnSource.OSV, id="GHSA-junk", severity=Severity.LOW),
    ]
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as fake:
        await cwe.tag_vulnerabilities(vulns, fake)

    assert vulns[0].cwe_ids == ["CWE-94"]
    assert vulns[1].cwe_ids == [] and vulns[2].cwe_ids == []
