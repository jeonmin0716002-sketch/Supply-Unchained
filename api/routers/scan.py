"""
POST /api/v1/scan — 통합 스캔 엔드포인트

세 레이어가 전부 실제 모듈로 연결되어 있습니다:
  ① CVE/OSV 매칭   → engine.cve_matcher.match_package
  ② 정적분석       → engine.static_analyzer.analyze_package
  ③ 위험도 스코어링 → scoring.scorer.score_package

PyPI 조회·아카이브 다운로드는 요청당 한 번만 일어납니다. `PackageContext`를
여기서 만들어 ②③에 넘기기 때문입니다 (레이어마다 따로 받으면 같은 sdist를
두 번 내려받게 됩니다).

`SU_OFFLINE_DEMO=1` 이면 네트워크 없이 mock 데이터로 동작합니다. 발표장 회선이
죽어도 데모가 되게 하려는 용도이며, 응답의 verdict_reasons에 mock임이 명시됩니다.
"""

import os
from datetime import UTC, datetime
from itertools import count

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from api.schemas import (
    ErrorResponse,
    RiskSignals,
    ScanRequest,
    ScanResponse,
    Severity,
    StaticFinding,
    Verdict,
    Vulnerability,
    VulnSource,
)
from common.pypi import PackageContext, PyPIError
from engine.cve_matcher import CveLookupError, match_package
from engine.static_analyzer import analyze_package
from scoring.scorer import score_package

router = APIRouter(prefix="/api/v1", tags=["scan"])

# 심각도 순위 (문자열 비교는 알파벳순이라 critical < medium 이 돼버림)
_SEVERITY_ORDER = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}

_scan_id_seq = count(1)

_OFFLINE_DEMO = os.getenv("SU_OFFLINE_DEMO", "").strip().lower() in {"1", "true", "yes"}

# 오프라인 데모용 시나리오: 패키지 이름에 따라 3가지 판정을 재현
_DEMO_MALICIOUS = {"reqeusts", "colourama", "python-sqlite"}   # typosquat 흉내
_DEMO_VULNERABLE = {"requests"}                                 # 알려진 CVE 보유 흉내


def _mock_cve_layer(req: ScanRequest) -> list[Vulnerability]:
    """오프라인 데모 전용. 실제 경로는 engine.cve_matcher.match_package."""
    if req.name in _DEMO_VULNERABLE:
        return [
            Vulnerability(
                source=VulnSource.OSV,
                id="GHSA-9wx4-h78v-vm56",
                severity=Severity.MEDIUM,
                summary="Proxy-Authorization 헤더가 리다이렉트 시 유출될 수 있음",
                fixed_version="2.31.1",
            )
        ]
    return []


def _mock_static_layer(req: ScanRequest) -> list[StaticFinding]:
    """오프라인 데모 전용. 실제 경로는 engine.static_analyzer.analyze_package."""
    if req.name in _DEMO_MALICIOUS:
        return [
            StaticFinding(
                rule="custom-pth",
                cwe="CWE-94",
                severity=Severity.HIGH,
                location="install.pth:1",
                detail=".pth 파일을 통한 인터프리터 시작 시 자동 실행 코드",
            ),
            StaticFinding(
                rule="custom-obfuscated-payload",
                cwe="CWE-506",
                severity=Severity.HIGH,
                location="setup.py:14",
                detail="base64 디코딩 후 exec() 호출 패턴",
            ),
        ]
    return []


def _mock_risk_layer(req: ScanRequest) -> tuple[RiskSignals, int]:
    """오프라인 데모 전용. 실제 경로는 scoring.scorer.score_package."""
    if req.name in _DEMO_MALICIOUS:
        signals = RiskSignals(
            is_new_account=True,
            typosquat_score=0.82,
            has_install_script=True,
            dependency_count=0,
            release_burst=True,
        )
        # 가중치 합산: 신규계정 25 + typosquat 30 + install script 20 + 배포패턴 15 = 90
        return signals, 90
    signals = RiskSignals(
        is_new_account=False,
        typosquat_score=0.05,
        has_install_script=False,
        dependency_count=4,
        release_burst=False,
    )
    return signals, 5


def _decide(
    vulns: list[Vulnerability],
    findings: list[StaticFinding],
    risk_score: int,
) -> tuple[Verdict, list[str]]:
    """종합 판정 로직 (초안 규칙 — 팀 합의 대상)

    - 정적분석 HIGH 이상 or risk_score >= 70  → block
    - CVE 존재 or risk_score >= 40            → warn
    - 그 외                                    → safe
    """
    reasons: list[str] = []

    has_high_finding = any(
        f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings
    )
    if has_high_finding:
        reasons.append("정적분석에서 고위험 악성 패턴 탐지")
    if risk_score >= 70:
        reasons.append(f"메타데이터 위험도 스코어 {risk_score}점 (임계 70 이상)")
    if has_high_finding or risk_score >= 70:
        return Verdict.BLOCK, reasons

    if vulns:
        worst = max(vulns, key=lambda v: _SEVERITY_ORDER[v.severity]).severity.value
        reasons.append(f"알려진 취약점 {len(vulns)}건 (최고 심각도: {worst})")
    if risk_score >= 40:
        reasons.append(f"메타데이터 위험도 스코어 {risk_score}점 (주의 40 이상)")
    if vulns or risk_score >= 40:
        return Verdict.WARN, reasons

    reasons.append("탐지된 위협 없음")
    return Verdict.SAFE, reasons


def _error(status: int, code: str, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content=ErrorResponse(error=code, detail=detail).model_dump(),
    )


async def _run_offline_demo(req: ScanRequest):
    return (
        _mock_cve_layer(req),
        _mock_static_layer(req),
        _mock_risk_layer(req),
        ["⚠️ 오프라인 데모 모드 (SU_OFFLINE_DEMO) — mock 데이터입니다"],
    )


@router.post(
    "/scan",
    response_model=ScanResponse,
    summary="패키지 통합 스캔",
    responses={502: {"model": ErrorResponse, "description": "외부 API 조회 실패"}},
)
async def scan_package(req: ScanRequest):
    notes: list[str] = []

    if _OFFLINE_DEMO:
        vulns, findings, (signals, risk_score), notes = await _run_offline_demo(req)
    else:
        # 한 요청 = PyPI 조회 1회 + 아카이브 다운로드 1회. ②③가 같은 컨텍스트를 씁니다.
        async with PackageContext(req.name, req.version) as ctx:
            # ① CVE/OSV 매칭
            try:
                vulns = await match_package(req, client=ctx.client)
            except CveLookupError as exc:
                # 조회 자체가 실패했으면 "취약점 없음"이라고 말할 수 없습니다.
                return _error(502, "upstream_unavailable", str(exc))

            # ② 정적분석
            try:
                findings = await analyze_package(req, ctx=ctx)
            except PyPIError as exc:
                # 패키지가 없거나 아카이브를 못 읽은 경우. 스캔 전체를 실패시키지는
                # 않되, "검사하지 못했다"는 사실은 응답에 드러나야 합니다.
                findings = []
                notes.append(f"⚠️ 정적분석 미수행 — {exc}")

            # ③ 위험도 스코어링 (이름 기반 신호는 패키지가 삭제됐어도 동작)
            signals, risk_score = await score_package(req, ctx=ctx)

    verdict, reasons = _decide(vulns, findings, risk_score)
    reasons.extend(notes)

    return ScanResponse(
        scan_id=next(_scan_id_seq),
        ecosystem=req.ecosystem,
        name=req.name,
        version=req.version,
        scanned_at=datetime.now(UTC),
        verdict=verdict,
        risk_score=risk_score,
        verdict_reasons=reasons,
        vulnerabilities=vulns,
        static_findings=findings,
        risk_signals=signals,
    )
