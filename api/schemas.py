"""
Supply-Unchained API 스키마 (v1 초안 → 합의용 데모)

README 초안 스키마를 기반으로, 팀 합의가 필요한 지점을 보강한 버전.
- Enum으로 verdict / severity / ecosystem 값을 고정 (문자열 오타 방지 + OpenAPI 문서 자동화)
- scan_id / scanned_at 추가 (DB의 SCAN_RESULT 테이블과 1:1 대응)
- 각 레이어(engine / scoring) 결과를 명확히 분리 → 3파트 병렬 개발 시 계약(contract) 역할
"""

import re
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, model_validator

# ──────────────────────────────
# 공통 Enum
# ──────────────────────────────

class Ecosystem(str, Enum):
    """패키지 생태계. 값은 ``ecosystems.KNOWN_IDS`` 와 같다 (tests/test_pipeline_multi.py 가 검사).

    enum 에 있다고 스캔할 수 있는 것은 아니다 — 어댑터(``ecosystems/<id>/``)가 병합되지
    않은 생태계는 ScanRequest 검증에서 422 로 거절된다(500 이 아니라).
    """
    PIP = "pip"
    NPM = "npm"
    CARGO = "cargo"
    GO = "go"
    MAVEN = "maven"
    RUBYGEMS = "rubygems"
    NUGET = "nuget"
    COMPOSER = "composer"


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

# --- Secure Design: 입력값 화이트리스트 검증 (Command Injection 원천 차단) ---
#
# 패키지명/버전은 이후 여러 레이어를 타고 흐른다: PyPI URL 조립(common/pypi.py),
# OSV 쿼리, CLI 의 `pip install` subprocess 인자, 프록시 게이트의 파일명 파싱.
# subprocess 는 shell=False 리스트 호출이라 당장 인젝션이 성립하진 않지만,
# 시스템이 확장될수록(셸 스크립트 훅, 로그 파이프라인 등) 어떤 싱크가 생길지
# 모르므로 입구에서 화이트리스트로 잘라내는 게 defense-in-depth 의 기본이다.
#
# 이름·버전 문법은 생태계마다 다르므로 검증은 어댑터(``Ecosystem.validate``)에 맡긴다.
# pip 은 아래 정규식과 오류 문구를 그대로 쓴다(ecosystems/pip — 기존 테스트·CLI 출력 유지):
# 이름: PEP 503 정규화 규칙 그대로 — 영숫자로 시작/끝, 중간에 . _ - 만 허용.
# 버전: PEP 440 이 쓰는 문자만 — 영숫자 토큰을 . _ + ! - 로 연결한 형태.
#       (예: 2.31.0 / 4.0.0rc1 / 1!2.0 / 1.0.0+cpu — 셸 메타문자·공백·따옴표는 전부 거부)
_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9]+(?:[._+!-][A-Za-z0-9]+)*$")

#: Field 단계의 길이 상한은 "어느 생태계든 이보다 길 수 없다"는 바깥 울타리다. 생태계별
#: 상한은 어댑터가 다시 건다. 214(npm 이름 상한)로 두면 Maven ``group:artifact`` 와 Go 모듈
#: 경로(``github.com/org/repo/v2/sub``)가 정상인데도 잘린다.
MAX_NAME_FIELD = 512
MAX_VERSION_FIELD = 128


class ScanRequest(BaseModel):
    ecosystem: Ecosystem = Field(
        default=Ecosystem.PIP,
        description="패키지 에코시스템 (pip·npm·cargo·go·maven·rubygems·nuget·composer)",
    )
    name: str = Field(
        min_length=1,
        max_length=MAX_NAME_FIELD,
        description="패키지 이름 (npm @scope/name, Maven group:artifact, Go 모듈 경로 포함)",
        examples=["requests"],
    )
    version: str = Field(
        min_length=1,
        max_length=MAX_VERSION_FIELD,
        description="패키지 버전 (정확한 버전 문자열)",
        examples=["2.31.0"],
    )

    @model_validator(mode="after")
    def _validate_with_adapter(self) -> "ScanRequest":
        # 지연 import: ecosystems.base 가 이 모듈(StaticFinding)을 import 하므로 위에서
        # 부르면 순환 import 가 된다.
        import ecosystems

        try:
            eco = ecosystems.get(self.ecosystem.value)
        except ecosystems.UnknownEcosystem as exc:
            # 알려진 생태계지만 어댑터가 아직 없다 — 500 이 아니라 422 로 사유를 돌려준다.
            raise ValueError(
                f"{self.ecosystem.value}: 아직 스캔을 지원하지 않습니다 ({exc})"
            ) from exc
        eco.validate(self.name, self.version)
        return self

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
    # CWE 태깅 담당 조정에 따라 추가 (팀 리뷰 대상): 취약점은 CWE가 여러 개일 수
    # 있어 static_findings[].cwe(단수)와 달리 리스트. OSV의 database_specific.cwe_ids
    # 에서 채워지며, 광고문에 CWE가 없으면 빈 리스트 (PYSEC 계열 등).
    cwe_ids: list[str] = Field(
        default_factory=list,
        description="이 취약점에 태깅된 CWE 목록 (예: ['CWE-522'])",
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

    # 통합 시 추가 (팀 리뷰 대상): 외부 API 장애 등으로 일부 레이어가 실패했을 때
    # 어떤 레이어가 빠진 채 판정됐는지 명시. 보안 도구가 조용히 "safe"를 주는 것보다
    # "OSV 조회 실패한 상태의 판정"임을 CLI/대시보드가 표시하는 쪽이 안전함.
    layer_errors: list[str] = Field(
        default_factory=list,
        description="실패한 탐지 레이어와 사유 (비어있으면 전 레이어 정상)",
    )


class ErrorResponse(BaseModel):
    """404(패키지 없음) / 502(외부 API 실패) 등 공통 에러 스키마"""
    error: str = Field(examples=["package_not_found"])
    detail: str
