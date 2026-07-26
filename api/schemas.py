"""
Supply-Unchained API 스키마 (v1 초안 → 합의용 데모)

README 초안 스키마를 기반으로, 팀 합의가 필요한 지점을 보강한 버전.
- Enum으로 verdict / severity / ecosystem 값을 고정 (문자열 오타 방지 + OpenAPI 문서 자동화)
- scan_id / scanned_at 추가 (DB의 SCAN_RESULT 테이블과 1:1 대응)
- 각 레이어(engine / scoring) 결과를 명확히 분리 → 3파트 병렬 개발 시 계약(contract) 역할
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

# ──────────────────────────────
# 공통 Enum
# ──────────────────────────────

class Ecosystem(str, Enum):
    """확장 대비 필드. 현재는 pip만 지원."""
    PIP = "pip"
    # NPM = "npm"      # Future Work
    # CARGO = "cargo"  # Future Work


class Verdict(str, Enum):
    SAFE = "safe"
    WARN = "warn"
    BLOCK = "block"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnSource(str, Enum):
    OSV = "OSV"
    NVD = "NVD"


# ──────────────────────────────
# Request
# ──────────────────────────────

class ScanRequest(BaseModel):
    ecosystem: Ecosystem = Field(
        default=Ecosystem.PIP,
        description="패키지 에코시스템 (향후 npm 등 확장 대비)",
    )
    name: str = Field(
        min_length=1,
        max_length=214,
        description="패키지 이름",
        examples=["requests"],
    )
    version: str = Field(
        min_length=1,
        description="패키지 버전 (정확한 버전 문자열)",
        examples=["2.31.0"],
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"ecosystem": "pip", "name": "requests", "version": "2.31.0"}
            ]
        }
    }


# ──────────────────────────────
# Response — 레이어별 서브 모델
# ──────────────────────────────

class Vulnerability(BaseModel):
    """① CVE/OSV 매칭 레이어 결과 (탐지 엔진 파트 담당)"""
    source: VulnSource
    id: str = Field(description="CVE / OSV / GHSA ID", examples=["GHSA-9wx4-h78v-vm56"])
    severity: Severity
    summary: str | None = Field(default=None, description="취약점 한 줄 요약")
    fixed_version: str | None = Field(
        default=None, description="패치된 버전 (있으면 사용자에게 업그레이드 안내)"
    )


class StaticFinding(BaseModel):
    """② 정적분석 레이어 결과 (탐지 엔진 파트 담당)"""
    rule: str = Field(description="Bandit 규칙 ID 또는 커스텀 규칙 ID", examples=["custom-pth"])
    cwe: str = Field(description="CWE 태그", examples=["CWE-94"])
    severity: Severity
    location: str = Field(description="파일:라인", examples=["install.pth:1"])
    detail: str | None = Field(default=None, description="탐지된 패턴 설명")


class RiskSignals(BaseModel):
    """③ 위험도 스코어링 레이어의 근거 신호 (데이터·스코어링 파트 담당)"""
    is_new_account: bool = Field(description="배포 직전 생성된 관리자 계정 여부")
    typosquat_score: float = Field(ge=0.0, le=1.0, description="인기 패키지와의 이름 유사도")
    has_install_script: bool = Field(description="setup.py 등 설치 시 실행 코드 포함 여부")
    dependency_count: int = Field(ge=0, description="의존성 개수")
    release_burst: bool = Field(
        default=False, description="짧은 간격 대량 배포 등 비정상 배포 패턴"
    )


# ──────────────────────────────
# Response — 최상위
# ──────────────────────────────

class ScanResponse(BaseModel):
    # 식별 정보 (DB SCAN_RESULT와 대응 — 대시보드에서 재조회 가능)
    scan_id: int = Field(description="스캔 결과 ID")
    ecosystem: Ecosystem
    name: str
    version: str
    scanned_at: datetime

    # 종합 판정
    verdict: Verdict = Field(description="safe | warn | block")
    risk_score: int = Field(ge=0, le=100, description="규칙 기반 가중치 합산 후 0-100 정규화")
    verdict_reasons: list[str] = Field(
        default_factory=list,
        description="판정 근거 요약 — CLI가 사용자에게 그대로 출력할 수 있는 문장 목록",
    )

    # 레이어별 상세
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    static_findings: list[StaticFinding] = Field(default_factory=list)
    risk_signals: RiskSignals


class ErrorResponse(BaseModel):
    """404(패키지 없음) / 502(외부 API 실패) 등 공통 에러 스키마"""
    error: str = Field(examples=["package_not_found"])
    detail: str
