"""
POST /api/v1/scan — 통합 스캔 엔드포인트 (데모)

실제 엔진/스코어러가 아직 없으므로 목(mock) 데이터로 응답 흐름을 시뮬레이션.
각 파트는 아래 _mock_* 함수를 자기 모듈 호출로 교체하면 됨:
  _mock_cve_layer     → engine.cve_matcher
  _mock_static_layer  → engine.static_analyzer
  _mock_risk_layer    → scoring.scorer
"""

from datetime import datetime, timezone
from itertools import count

from fastapi import APIRouter

from api.schemas import (
    RiskSignals,
    ScanRequest,
    ScanResponse,
    Severity,
    StaticFinding,
    Verdict,
    Vulnerability,
    VulnSource,
)

router = APIRouter(prefix="/api/v1", tags=["scan"])

# 심각도 순위 (문자열 비교는 알파벳순이라 critical < medium 이 돼버림)
_SEVERITY_ORDER = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}

_scan_id_seq = count(1)

# 데모용 시나리오: 패키지 이름에 따라 3가지 판정을 재현
_DEMO_MALICIOUS = {"reqeusts", "colourama", "python-sqlite"}   # typosquat 흉내
_DEMO_VULNERABLE = {"requests"}                                 # 알려진 CVE 보유 흉내


def _mock_cve_layer(req: ScanRequest) -> list[Vulnerability]:
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
                rule="B102",
                cwe="CWE-78",
                severity=Severity.HIGH,
                location="setup.py:14",
                detail="base64 디코딩 후 exec() 호출 패턴",
            ),
        ]
    return []


def _mock_risk_layer(req: ScanRequest) -> tuple[RiskSignals, int]:
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


@router.post("/scan", response_model=ScanResponse, summary="패키지 통합 스캔")
async def scan_package(req: ScanRequest) -> ScanResponse:
    # ① CVE/OSV 매칭
    vulns = _mock_cve_layer(req)
    # ② 정적분석
    findings = _mock_static_layer(req)
    # ③ 위험도 스코어링
    signals, risk_score = _mock_risk_layer(req)
    # 종합 판정
    verdict, reasons = _decide(vulns, findings, risk_score)

    return ScanResponse(
        scan_id=next(_scan_id_seq),
        ecosystem=req.ecosystem,
        name=req.name,
        version=req.version,
        scanned_at=datetime.now(timezone.utc),
        verdict=verdict,
        risk_score=risk_score,
        verdict_reasons=reasons,
        vulnerabilities=vulns,
        static_findings=findings,
        risk_signals=signals,
    )
