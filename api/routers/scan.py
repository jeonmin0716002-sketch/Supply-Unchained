"""POST /api/v1/scan — 통합 스캔 엔드포인트 (실 레이어 연동판).

Phase 2 통합: 이전 버전의 _mock_* 3개를 각 파트의 실제 구현으로 교체.

    ① CVE/OSV  -> engine.cve_matcher.match_package      (민규)
    ② 정적분석  -> api.package_fetcher + engine.analyze_path (민규 엔진의 완성 절반 +
                   아카이브 수집은 통합측 임시 담당 — package_fetcher.py 참고)
    ③ 스코어링  -> scoring.scorer.score_package          (승준)

레이어 부분 실패 정책 (팀 리뷰 대상):
    외부 API 장애로 한 레이어가 죽어도 스캔 전체를 502로 죽이지 않고,
    남은 레이어로 판정하되 실패 사실을 ``layer_errors`` 로 응답에 명시한다.
    (보안 도구가 장애를 숨기고 "safe"를 주는 것이 최악의 동작이므로,
    CLI/대시보드는 layer_errors 가 있으면 반드시 경고를 띄운다.)
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, HTTPException, Query, Request

from api.cwe import tag_vulnerabilities
from api.package_fetcher import PackageFetchError, fetched_package_tree
from api.schemas import (
    ErrorResponse,
    RiskSignals,
    ScanRequest,
    ScanResponse,
    Severity,
    StaticFinding,
    Verdict,
    Vulnerability,
)
from api.storage import ScanStore
from engine import CveLookupError, analyze_path, match_package
from scoring.scorer import score_package

router = APIRouter(prefix="/api/v1", tags=["scan"])

# 심각도 순위 (문자열 비교는 알파벳순이라 critical < medium 이 돼버림)
_SEVERITY_ORDER = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}

#: 레이어 실패 시 스코어링 대체값 — "모름"은 0점이 아니라 신호 없음으로 취급하고,
#: 실패 사실 자체는 layer_errors 로 드러낸다.
_NEUTRAL_SIGNALS = RiskSignals(
    is_new_account=False,
    typosquat_score=0.0,
    has_install_script=False,
    dependency_count=0,
    release_burst=False,
)


# ──────────────────────────────
# 레이어 호출 (각각 독립적으로 실패 가능)
# ──────────────────────────────

async def _layer_cve(
    req: ScanRequest, http: httpx.AsyncClient, errors: list[str]
) -> list[Vulnerability]:
    try:
        return await match_package(req, client=http)
    except CveLookupError as exc:
        errors.append(f"cve: {exc}")
        return []


async def _layer_static(
    req: ScanRequest, http: httpx.AsyncClient, errors: list[str]
) -> list[StaticFinding]:
    try:
        async with fetched_package_tree(req.name, req.version, client=http) as tree:
            # analyze_path 는 순수 파일시스템 작업(동기) — 이벤트 루프를 막지 않게 스레드로.
            return await asyncio.to_thread(analyze_path, tree)
    except PackageFetchError as exc:
        errors.append(f"static: {exc}")
        return []


async def _layer_scoring(
    req: ScanRequest, errors: list[str]
) -> tuple[RiskSignals, int]:
    try:
        return await score_package(req)
    except Exception as exc:  # 스코어링 파트 내부 예외 계층이 아직 없어 광범위 캐치
        errors.append(f"scoring: {exc}")
        return _NEUTRAL_SIGNALS, 0


# ──────────────────────────────
# 종합 판정 (week0 회의 기준 규칙 초안 유지)
# ──────────────────────────────

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


# ──────────────────────────────
# 파이프라인 (프록시에서도 재사용하므로 핸들러와 분리)
# ──────────────────────────────

async def run_scan(
    req: ScanRequest, *, http: httpx.AsyncClient, store: ScanStore
) -> ScanResponse:
    layer_errors: list[str] = []

    # 세 레이어는 서로 독립 — 병렬 실행 (①은 OSV, ②는 PyPI 아카이브, ③은 PyPI JSON)
    vulns, findings, (signals, risk_score) = await asyncio.gather(
        _layer_cve(req, http, layer_errors),
        _layer_static(req, http, layer_errors),
        _layer_scoring(req, layer_errors),
    )

    # CWE 태깅 (담당: API 파트) — 취약점별 OSV 재조회로 cwe_ids 를 채운다.
    # 부가 정보라 실패는 조용히 빈 리스트로 남고 판정에는 영향 없음.
    await tag_vulnerabilities(vulns, http)

    verdict, reasons = _decide(vulns, findings, risk_score)

    response = ScanResponse(
        scan_id=0,  # insert 후 확정
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
        layer_errors=layer_errors,
    )

    record = response.model_dump(mode="json")
    scan_id = await store.insert(record)
    response.scan_id = record["scan_id"] = scan_id
    await store.finalize(scan_id, record)
    return response


# ──────────────────────────────
# 엔드포인트
# ──────────────────────────────

@router.post("/scan", response_model=ScanResponse, summary="패키지 통합 스캔")
async def scan_package(req: ScanRequest, request: Request) -> ScanResponse:
    return await run_scan(
        req, http=request.app.state.http, store=request.app.state.store
    )


@router.get("/scans", response_model=list[ScanResponse], summary="최근 스캔 이력")
async def recent_scans(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
) -> list[ScanResponse]:
    """대시보드 이력 화면용. 최신 스캔부터 내림차순."""
    rows = await request.app.state.store.recent(limit)
    return [ScanResponse.model_validate(r) for r in rows]


@router.get(
    "/scans/{scan_id}",
    response_model=ScanResponse,
    responses={404: {"model": ErrorResponse}},
    summary="스캔 결과 단건 조회",
)
async def get_scan(scan_id: int, request: Request) -> ScanResponse:
    row = await request.app.state.store.get(scan_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "scan_not_found", "detail": f"scan {scan_id} 없음"},
        )
    return ScanResponse.model_validate(row)
