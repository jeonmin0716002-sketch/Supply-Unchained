"""보안 하드닝 테스트 (재웅 파트) — 입력값 검증 + 요청 크기 제한.

api/schemas.py 의 화이트리스트 검증과 api/main.py 의 body 크기 제한이
실제 HTTP 경계에서 동작하는지 확인한다. 전부 오프라인.
"""

from __future__ import annotations

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
