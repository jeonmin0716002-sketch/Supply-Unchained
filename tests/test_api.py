"""API-part integration tests — offline (layers are monkeypatched or use samples/).

Covers: verdict wiring, partial-failure policy (layer_errors), persistence,
history endpoints, proxy link rewriting, and the download gate blocking flow.
"""

from __future__ import annotations

import asyncio
import re
import time
from unittest import mock
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient

from api import cwe
from api.cwe import UNKNOWN_CWE, cwe_for_bandit
from api.main import app
from api.routers import proxy, scan
from api.schemas import (
    RiskSignals,
    ScanRequest,
    Severity,
    StaticFinding,
    Vulnerability,
    VulnSource,
)
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


def _patch_layers(
    monkeypatch, *, vulns=(), findings=(), bandit_findings=(), signals=SAFE_SIGNALS, score=5
):
    async def fake_cve(req, http, errors):
        return list(vulns)

    async def fake_static(req, ctx, errors):
        return list(findings)

    async def fake_bandit(req, ctx, errors):
        return list(bandit_findings)

    async def fake_scoring(req, ctx, errors):
        return signals, score

    monkeypatch.setattr(scan, "_layer_cve", fake_cve)
    monkeypatch.setattr(scan, "_layer_static", fake_static)
    monkeypatch.setattr(scan, "_layer_bandit", fake_bandit)
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

    async def fake_bandit(req, ctx, errors):
        return []

    async def fake_scoring(req, ctx, errors):
        return SAFE_SIGNALS, 5

    async def boom(req, *, ctx=None):
        raise PyPIError("ghost-pkg is not on PyPI")

    monkeypatch.setattr(scan, "_layer_cve", fake_cve)
    monkeypatch.setattr(scan, "_layer_bandit", fake_bandit)
    monkeypatch.setattr(scan, "_layer_scoring", fake_scoring)
    monkeypatch.setattr(scan, "analyze_package", boom)

    body = client.post("/api/v1/scan", json={"name": "ghost-pkg", "version": "0.0.1"}).json()
    assert any(e.startswith("static:") for e in body["layer_errors"])
    assert body["verdict"] == "safe"  # 남은 레이어로 판정은 계속된다


def test_layers_share_one_package_context(client, monkeypatch):
    """②②'③ 가 같은 PackageContext 를 받는지 — PyPI 중복 조회 방지의 핵심 계약."""
    seen = []

    async def fake_cve(req, http, errors):
        return []

    async def fake_static(req, ctx, errors):
        seen.append(ctx)
        return []

    async def fake_bandit(req, ctx, errors):
        seen.append(ctx)
        return []

    async def fake_scoring(req, ctx, errors):
        seen.append(ctx)
        return SAFE_SIGNALS, 5

    monkeypatch.setattr(scan, "_layer_cve", fake_cve)
    monkeypatch.setattr(scan, "_layer_static", fake_static)
    monkeypatch.setattr(scan, "_layer_bandit", fake_bandit)
    monkeypatch.setattr(scan, "_layer_scoring", fake_scoring)

    client.post("/api/v1/scan", json={"name": "httpx", "version": "0.27.0"})
    assert len(seen) == 3 and seen[0] is seen[1] is seen[2]


def test_offline_demo_needs_no_network(client, monkeypatch):
    """SU_OFFLINE_DEMO — 회선이 죽어도 block 판정 데모가 되는지 (레이어 미호출)."""
    monkeypatch.setattr(scan, "OFFLINE_DEMO", True)
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
    assert 'href="/files/x-1.0.tar.gz?u=https%3A%2F%2Ffiles.pythonhosted.org' in out
    assert out.endswith('#sha256=deadbeef">x-1.0.tar.gz</a>')  # 해시 검증 프래그먼트 보존


def test_rewritten_link_keeps_filename_in_path():
    """pip 계약: 재작성된 링크의 *경로*가 아카이브 파일명으로 끝나야 한다.

    원본 URL 을 쿼리에만 담으면 pip 이 경로에서 파일명을 못 뽑아
    ``Skipping link: not a file`` 로 전 링크를 버리고 "from versions: none" 이 된다
    (실제 pip 으로 재현됨). 문자열 모양 대신 이 계약 자체를 검증한다.
    """
    html = ('<a href="https://files.pythonhosted.org/packages/aa/bb/'
            'scikit_learn-1.5.0-cp312-cp312-win_amd64.whl#sha256=beef">x</a>')
    href = re.search(r'href="([^"]+)"', proxy.rewrite_index_html(html)).group(1)
    parsed = urlparse(href)

    filename = parsed.path.rsplit("/", 1)[-1]
    assert filename == "scikit_learn-1.5.0-cp312-cp312-win_amd64.whl"
    # pip 은 이 파일명에서 버전과 wheel 태그를 읽는다 — 우리 파서도 읽을 수 있어야 한다.
    assert proxy.parse_archive_filename(filename) == ("scikit_learn", "1.5.0")
    assert parse_qs(parsed.query)["u"][0].startswith("https://files.pythonhosted.org/")
    assert parsed.fragment == "sha256=beef"  # 해시 검증은 프래그먼트에 남아야 한다


def test_metadata_attribute_is_stripped():
    """PEP 658 광고 속성 제거 — 남기면 pip 이 URL 끝에 '.metadata' 를 붙여 깨진다.

    pip 은 링크 URL '문자열' 뒤에 접미사를 붙이므로, 원본 URL 이 쿼리에 있는 우리
    링크에서는 그 접미사가 쿼리 값 안으로 들어가 게이트가 400 을 낸다(실제 pip 재현).
    """
    html = ('<a href="https://files.pythonhosted.org/packages/aa/bb/x-1.0-py3-none-any.whl"'
            ' data-core-metadata="sha256=abc" data-requires-python="&gt;=3.8">x</a>')
    out = proxy.rewrite_index_html(html)
    assert "data-core-metadata" not in out
    assert "data-requires-python" in out  # 버전 해석에 필요한 속성은 보존


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
    r = client.get(f"/files/reqeusts-1.0.0.tar.gz?u={url}")
    assert r.status_code == 403
    assert r.json()["error"] == "blocked_by_supply_unchained"
    assert r.json()["package"] == "reqeusts==1.0.0"


def test_gate_rejects_open_proxy_abuse(client):
    r = client.get(
        "/files/x-1.0.tar.gz", params={"u": "https://evil.example.com/x-1.0.tar.gz"}
    )
    assert r.status_code == 400


def test_demo_index_is_synthesised_offline(client, monkeypatch):
    """데모 typosquat 이름은 PyPI 에서 삭제돼(404) 업스트림 프록시로는 시연이 안 된다.

    SU_OFFLINE_DEMO 에서 인덱스를 합성해 pip 이 게이트까지 도달하는지 — 그리고 그
    링크가 pip 계약(경로가 파일명으로 끝남)을 지키는지 확인한다.
    """
    monkeypatch.setattr(scan, "OFFLINE_DEMO", True)
    r = client.get("/simple/reqeusts/")
    assert r.status_code == 200

    href = re.search(r'href="([^"]+)"', r.text).group(1)
    parsed = urlparse(href)
    assert parsed.path == "/files/reqeusts-1.0.0.tar.gz"
    assert proxy.parse_archive_filename(parsed.path.rsplit("/", 1)[-1]) == (
        "reqeusts",
        "1.0.0",
    )

    # 합성된 링크를 그대로 따라가면 게이트가 차단해야 한다 (pip 이 하는 동작).
    blocked = client.get(href)
    assert blocked.status_code == 403
    assert blocked.json()["package"] == "reqeusts==1.0.0"


def test_demo_index_not_synthesised_when_demo_off(client, monkeypatch):
    """데모 모드가 아니면 합성하지 않고 업스트림을 재작성한다.

    실서비스에서 가짜 인덱스가 새어나가면 존재하지 않는 패키지를 존재하는 것처럼
    광고하게 되므로, 합성은 SU_OFFLINE_DEMO 로 확실히 격리돼야 한다.
    """
    monkeypatch.setattr(scan, "OFFLINE_DEMO", False)
    monkeypatch.setattr(proxy, "demo_index_html", lambda *a, **k: "SYNTHETIC")

    upstream_html = ('<a href="https://files.pythonhosted.org/packages/aa/bb/'
                     'reqeusts-9.9.9.tar.gz">reqeusts-9.9.9.tar.gz</a>')

    async def fake_get(url, **kwargs):
        return httpx.Response(200, text=upstream_html, request=httpx.Request("GET", url))

    monkeypatch.setattr(client.app.state.http, "get", fake_get)

    r = client.get("/simple/reqeusts/")
    assert r.status_code == 200
    assert "SYNTHETIC" not in r.text
    assert "/files/reqeusts-9.9.9.tar.gz?u=" in r.text  # 업스트림 링크를 재작성한 결과


def test_gate_rejects_filename_mismatch(client, monkeypatch):
    """경로 파일명 ≠ 업스트림 파일명이면 거부.

    허용하면 "안전한 A 를 스캔받고 악성 B 를 내려받는" 게이트 우회가 성립한다 —
    판정 대상을 경로 파일명이 결정하기 때문.
    """
    _patch_layers(monkeypatch)
    url = "https%3A%2F%2Ffiles.pythonhosted.org%2Fpackages%2Fx%2Freqeusts-1.0.0.tar.gz"
    r = client.get(f"/files/six-1.16.0.tar.gz?u={url}")
    assert r.status_code == 400


def test_gate_is_fail_closed_on_unparseable_filename(client, monkeypatch):
    """파일명에서 name==version 을 못 읽으면 스캔이 불가능하므로 통과시키지 않는다.

    통과시키면 인덱스 페이지를 통제하는 쪽 — 정확히 이 프로젝트의 위협 모델 — 이
    파싱 안 되는 이름 하나로 게이트를 통째로 우회할 수 있다.
    """
    scanned: list[str] = []

    async def spy_static(req, ctx, errors):
        scanned.append(req.name)
        return []

    _patch_layers(monkeypatch)
    monkeypatch.setattr(scan, "_layer_static", spy_static)

    # .tar 는 _SDIST_RE 가 다루지 않는 확장자라 파싱에 실패한다.
    url = "https%3A%2F%2Ffiles.pythonhosted.org%2Fpackages%2Fx%2Fmystery.tar"
    r = client.get(f"/files/mystery.tar?u={url}")

    assert r.status_code == 403
    assert not scanned, "스캔도 못 한 아카이브가 통과 경로로 샜다"


# ──────────────────────────────
# Bandit 레이어 (재웅 담당분)
# ──────────────────────────────

def test_run_bandit_caps_high_severity_to_medium(tmp_path):
    """Bandit 은 HIGH 를 매기지만, 오탐률을 실측하기 전까지는 여기서 MEDIUM 으로 눌러야 한다.

    풀어주면 _decide() 가 risk_score 와 무관하게 무조건 block 해버려서, 커스텀 룰이
    requests 의 os.system() 을 일부러 MEDIUM 으로 낮췄던 것과 같은 오차단이 재현된다.
    """
    (tmp_path / "mod.py").write_text("import ftplib\n", encoding="utf-8")
    findings, truncated = scan._run_bandit(tmp_path)

    assert truncated is None
    assert findings, "ftplib import 는 bandit 이 B402 HIGH 로 잡아야 한다"
    finding = next(f for f in findings if f.rule == "B402")
    assert finding.cwe.startswith("CWE-")
    assert finding.severity == Severity.MEDIUM  # HIGH -> 캡 확인
    assert finding.location.startswith("mod.py:")  # 절대경로가 아니라 상대경로


def test_run_bandit_skips_noise_directories(tmp_path):
    """tests/examples/docs 는 배포되더라도 install·import 시점에 실행되지 않는다.

    이 배선이 없으면 flask 한 패키지에서 1006 findings 가 나오고, 대부분이 examples 안의
    B101 이라 진짜 신호가 묻힌다.
    """
    payload = "import ftplib\n"
    (tmp_path / "real.py").write_text(payload, encoding="utf-8")
    for noise in ("tests", "examples", "docs"):
        (tmp_path / noise).mkdir()
        (tmp_path / noise / "mod.py").write_text(payload, encoding="utf-8")
    # 디렉터리 이름 정확 일치여야 한다 — "docs" 로 시작하는 모듈은 진짜 배포 코드다.
    (tmp_path / "docs_helper.py").write_text(payload, encoding="utf-8")

    findings, _ = scan._run_bandit(tmp_path)
    scanned = {f.location.split(":")[0] for f in findings}
    assert scanned == {"real.py", "docs_helper.py"}


def test_run_bandit_exclusion_is_relative_to_package_root(tmp_path):
    """제외 판정은 **패키지 루트 기준 상대경로**로만 해야 한다.

    bandit 의 excluded_paths 는 절대경로 부분문자열로 비교하기 때문에, 추출 임시
    디렉터리 경로에 우연히 'docs' 가 끼면 패키지 전체가 조용히 스킵되고 응답에는
    "findings 없음"만 남는다 — 검사 못 한 것이 깨끗한 것으로 둔갑하는 최악의 실패다.
    """
    root = tmp_path / "docs" / "pkg-1.0"   # 루트 **위쪽** 경로에 제외 이름이 섞인 상황
    root.mkdir(parents=True)
    (root / "setup.py").write_text("import ftplib\n", encoding="utf-8")

    findings, _ = scan._run_bandit(root)
    assert [f.location.split(":")[0] for f in findings] == ["setup.py"]


def test_run_bandit_skips_oversized_files_and_says_so(tmp_path, monkeypatch):
    """크기 상한에 걸린 파일은 건너뛰되, 건너뛴 사실이 반드시 밖으로 나가야 한다."""
    monkeypatch.setattr(scan, "MAX_BANDIT_FILE_BYTES", 200)
    (tmp_path / "small.py").write_text("import ftplib\n", encoding="utf-8")
    (tmp_path / "huge.py").write_text("import ftplib\n" + "# pad\n" * 200, encoding="utf-8")

    findings, truncated = scan._run_bandit(tmp_path)
    assert [f.location.split(":")[0] for f in findings] == ["small.py"]
    assert truncated and "huge.py" in truncated


def test_run_bandit_budget_stops_early_and_says_so(tmp_path):
    """예산을 0 으로 주면 한 파일도 돌기 전에 멈추고, 그 사실이 사유로 남아야 한다.

    조용히 빈 리스트를 돌려주면 "검사했는데 깨끗함"과 구분이 안 된다.
    """
    (tmp_path / "mod.py").write_text("import ftplib\n", encoding="utf-8")

    findings, truncated = scan._run_bandit(tmp_path, budget=0.0)
    assert findings == []
    assert truncated and "예산 초과" in truncated


async def test_layer_bandit_survives_errors():
    """PackageContext.extracted_path 가 예외를 던져도 스캔 전체가 죽지 않고
    layer_errors 로 강등되는지 — 다른 레이어들과 동일한 부분 실패 정책.
    """

    class BoomCtx:
        async def extracted_path(self):
            raise RuntimeError("boom")

    errors: list[str] = []
    result = await scan._layer_bandit(ScanRequest(name="x", version="1"), BoomCtx(), errors)
    assert result == []
    assert errors and errors[0].startswith("bandit:")


async def test_layer_bandit_reports_truncation_as_layer_error(tmp_path):
    """_run_bandit 의 미완료 사유는 layer_errors 로 흘러나가야 한다 —
    _layer_static 이 PyPIError 를 다루는 방식과 같은 정책.
    """

    class Ctx:
        async def extracted_path(self):
            return tmp_path

    (tmp_path / "mod.py").write_text("import ftplib\n", encoding="utf-8")
    errors: list[str] = []
    with mock.patch.object(scan, "BANDIT_BUDGET_SECONDS", 0.0):
        await scan._layer_bandit(ScanRequest(name="x", version="1"), Ctx(), errors)
    assert errors and "예산 초과" in errors[0]


async def test_layer_bandit_does_not_block_the_event_loop(tmp_path):
    """bandit 은 동기 CPU 작업이라 스레드로 내보내야 한다.

    코루틴 안에서 그대로 부르면 gather 로 묶은 나머지 레이어가 전부 그 시간만큼 멈추고,
    같은 프로세스의 /health 와 프록시 스트리밍도 같이 죽는다(rich 실측 15.6초).
    여기서는 bandit 이 도는 동안 이벤트 루프가 다른 태스크를 실제로 돌리는지 본다.
    """
    (tmp_path / "mod.py").write_text("import ftplib\n", encoding="utf-8")

    class Ctx:
        async def extracted_path(self):
            return tmp_path

    ticks = 0

    async def heartbeat():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.001)
            ticks += 1

    beat = asyncio.create_task(heartbeat())
    try:
        # _run_bandit 이 스레드에서 도는 동안만 루프가 살아있을 수 있다.
        with mock.patch.object(scan, "_run_bandit", _slow_bandit):
            await scan._layer_bandit(ScanRequest(name="x", version="1"), Ctx(), [])
    finally:
        beat.cancel()

    assert ticks > 0, "bandit 이 도는 동안 이벤트 루프가 멈춰 있었다"


def _slow_bandit(root, budget=None):
    """스레드로 나갔는지 보기 위한 대역 — 동기로 0.2초를 태운다."""
    time.sleep(0.2)
    return [], None


def test_scan_merges_bandit_findings_with_static(client, monkeypatch):
    bandit_finding = StaticFinding(
        rule="B402", cwe="CWE-829", severity=Severity.MEDIUM,
        location="mod.py:1", detail="A telnetlib import was detected.",
    )
    _patch_layers(monkeypatch, findings=[PTH_FINDING], bandit_findings=[bandit_finding])
    body = client.post("/api/v1/scan", json={"name": "reqeusts", "version": "1.0.0"}).json()
    rules = {f["rule"] for f in body["static_findings"]}
    assert rules == {"custom-pth", "B402"}
    assert body["verdict"] == "block"  # PTH_FINDING(HIGH) 하나로도 여전히 block


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
