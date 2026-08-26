"""POST /api/v1/scan — 통합 스캔 엔드포인트 (실 레이어 연동판).

세 레이어가 전부 실제 모듈로 연결되어 있습니다:

    ① CVE/OSV     -> engine.cve_matcher.match_package        (민규)
    ② 정적분석     -> engine.static_analyzer.analyze_package   (민규)
    ②' Bandit    -> _run_bandit (아래, 이 파일)                (재웅)
    ③ 스코어링     -> scoring.scorer.score_package            (승준)

②' 은 CWE 소유권 분리(engine/verdict.py 참고: "CWE for OSV/CVE 및 Bandit B-codes ->
API part")에 따라 engine/ 이 아니라 여기서 돈다 — engine.static_analyzer.analyze_path
와 그 RULE_CATALOG/KNOWN_CWES 를 건드리지 않기 위해서다 (Bandit 의 B-코드는 커스텀
룰 카탈로그에 등록된 적이 없어 거기 섞이면 tests/test_engine.py::
test_every_emitted_cwe_is_declared 가 즉시 깨진다).

PyPI 조회·아카이브 다운로드는 요청당 한 번만 일어납니다. ``common.pypi.PackageContext``
를 여기서 만들어 ②③에 넘기기 때문입니다 (레이어마다 따로 받으면 같은 sdist를 두 번
내려받습니다). 통합 초기에 ②의 아카이브 수집을 임시로 맡았던 ``api.package_fetcher``
는 엔진이 ``analyze_package`` 를 구현하면서 예고대로 은퇴했습니다.

레이어 부분 실패 정책 (팀 리뷰 대상):
    외부 API 장애로 한 레이어가 죽어도 스캔 전체를 502로 죽이지 않고,
    남은 레이어로 판정하되 실패 사실을 ``layer_errors`` 로 응답에 명시한다.
    (보안 도구가 장애를 숨기고 "safe"를 주는 것이 최악의 동작이므로,
    CLI/대시보드는 layer_errors 가 있으면 반드시 경고를 띄운다.)

``SU_OFFLINE_DEMO=1`` 이면 네트워크 없이 mock 데이터로 동작합니다. 발표장 회선이
죽어도 데모가 되게 하려는 용도이며, 응답의 verdict_reasons에 mock임이 명시됩니다.
"""

from __future__ import annotations

import asyncio
import os
import time
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

import httpx
from bandit.core import config as bandit_config
from bandit.core import manager as bandit_manager
from fastapi import APIRouter, HTTPException, Query, Request

from api.cwe import finding_from_bandit_issue, tag_vulnerabilities
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
from api.storage import ScanStore
from common.pypi import PackageContext, PyPIError
from engine import CveLookupError, analyze_package, match_package
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

#: 공개 이름인 이유: pip 프록시(api/routers/proxy.py)도 이 값을 읽어 데모용 인덱스
#: 페이지를 합성한다. 데모 판정 규칙이 두 군데로 흩어지지 않게 여기 한 곳에 둔다.
OFFLINE_DEMO = os.getenv("SU_OFFLINE_DEMO", "").strip().lower() in {"1", "true", "yes"}


# ──────────────────────────────
# 레이어 호출 (각각 독립적으로 실패 가능)
# ──────────────────────────────

async def _layer_cve(
    req: ScanRequest, http: httpx.AsyncClient, errors: list[str]
) -> list[Vulnerability]:
    # ①만 ctx 가 아니라 http 를 직접 받습니다 — OSV 는 PyPI 가 아니라서 공유할 상태가 없음.
    try:
        return await match_package(req, client=http)
    except CveLookupError as exc:
        errors.append(f"cve: {exc}")
        return []


async def _layer_static(
    req: ScanRequest, ctx: PackageContext, errors: list[str]
) -> list[StaticFinding]:
    try:
        return await analyze_package(req, ctx=ctx)
    except PyPIError as exc:
        # 패키지가 없거나 아카이브를 못 읽은 경우. "검사하지 못했다"는 사실이
        # "검사했고 깨끗했다"로 보이면 안 되므로 layer_errors 로 남긴다.
        errors.append(f"static: {exc}")
        return []


#: Bandit 자체 severity 를 그대로 통과시키면 안 되는 이유: B602(subprocess shell=True)
#: 처럼 손으로 짠 애플리케이션 코드 기준으로 튜닝된 규칙이 기본 HIGH 를 매기는데,
#: _decide() 는 HIGH finding 하나만으로 risk_score 와 무관하게 무조건 block 한다.
#: 커스텀 룰이 requests 의 os.system() 을 일부러 MEDIUM 으로 낮춘 것과 같은 이유
#: (engine/rules/code_patterns.py 상단 주석 참고) — 실제 유명 패키지 대상 오탐률을
#: 재보기 전까지는 여기서 상한을 걸어둔다.
_BANDIT_SEVERITY_CAP = Severity.MEDIUM

#: sdist 에는 tests/examples/docs 가 그대로 들어있는 경우가 흔한데, 그 코드는
#: `pip install` 이나 `import` 시점에 실행되지 않는다 — 여기 있는 assert/hardcoded
#: password 는 "이 패키지가 우리 프로세스에서 실행할 코드"가 아니라 노이즈다.
#: flask==3.0.0 실측: 제외 전 1006 findings, 대부분 examples/tests 내부 B101.
#:
#: bandit 의 ``excluded_paths`` 를 쓰지 않고 직접 거르는 이유가 둘 있다.
#:   1) bandit 은 제외 패턴을 **절대경로 부분문자열**로 비교한다(BanditManager 내부
#:      구현 디테일). 추출 임시 디렉터리 경로에 우연히 "docs" 가 들어가면 패키지 전체가
#:      조용히 스킵돼 "검사했고 깨끗했다"로 보인다.
#:   2) 문서화된 계약이 아니라 bandit 업그레이드 한 번에 말없이 깨질 수 있다.
#: 그래서 패키지 루트 기준 상대경로의 **디렉터리 이름 정확 일치**로 판정한다.
_BANDIT_EXCLUDE_DIRS = frozenset({"tests", "test", "examples", "docs", "doc"})

#: Bandit 은 순수 CPU 작업이라 코루틴 안에서 그냥 부르면 이벤트 루프가 그대로 멈춘다
#: (site-packages/rich 실측: 100 파일에 15.6초 — 그동안 /health 도, 프록시의 아카이브
#: 스트리밍도, 다른 스캔도 전부 정지한다). api/storage.py 가 동기 sqlite 를
#: asyncio.to_thread 로 감싸는 것과 같은 이유로 스레드에 넘긴다.
#:
#: 다만 to_thread 로 넘긴 스레드는 취소할 수 없다 — asyncio.wait_for 로 감싸면 요청은
#: 돌아오지만 스레드는 계속 CPU 를 먹는다. 그래서 시간 예산은 **스레드 안에서** 지킨다.
BANDIT_BUDGET_SECONDS = float(os.environ.get("SU_BANDIT_BUDGET", "20"))

#: 한 패키지에서 bandit 에 태울 파일 수 상한. 아카이브는 MAX_MEMBERS(=5000) 까지
#: 통과할 수 있어서 상한이 없으면 조작된 sdist 하나로 스캐너를 몇 분씩 붙잡아둘 수 있다
#: — 공급망 스캐너가 스캔 대상에게 DoS 당하는 모양새라 예산과 별도로 못을 박아둔다.
MAX_BANDIT_FILES = 400

#: 파일 **하나**의 크기 상한. 예산만으로 부족한 이유: bandit 은 run_tests() 안에서 파일
#: 단위로만 끊을 수 있어서, 예산 초과분이 "가장 무거운 파일 하나"만큼은 반드시 생긴다.
#: 그 파일이 얼마나 나쁠 수 있는지가 이 상한의 존재 이유다.
#:
#: 실측(파일 1개씩 bandit 단독 실행):
#:     rich/_emoji_codes.py       137 KB   8.9초    <- 거대한 dict 리터럴
#:     fastapi/routing.py         248 KB   0.6초
#:     fastapi/applications.py    179 KB   0.2초
#:     rich/console.py             99 KB   0.3초
#: 비용은 크기에도 AST 노드 수에도 비례하지 않는다 — _emoji_codes.py 는 routing.py 보다
#: 노드가 3분의 1인데 15배 느리다. 문자열 상수가 수천 개인 파일에서 특정 플러그인이
#: 터지는 형태라, 미리 싸게 예측할 방법이 없다. 그래서 예측 대신 크기로 자른다.
#:
#: 64 KB 는 안전 쪽으로 기운 선택이고, 대가가 있다 — routing.py 처럼 **진짜 로직인 큰
#: 파일도 같이 걷힌다**. 그 대가를 받아들이는 근거는 셋이다. (1) bandit 은 브레드스넷
#: 보조 레이어고, 커스텀 룰(engine/static_analyzer)은 이 상한과 무관하게 전부 훑는다.
#: (2) 건너뛴 파일은 응답의 layer_errors 에 파일명까지 남아 "검사했고 깨끗했다"로
#: 둔갑하지 않는다. (3) 상한을 128 KB 로 풀면 조작된 파일 하나의 최악 비용이 2초대에서
#: 9초대로 뛴다. 팀이 커버리지 쪽을 택하고 싶으면 SU_BANDIT_MAX_FILE_KB 로 올리면 된다.
MAX_BANDIT_FILE_BYTES = int(os.environ.get("SU_BANDIT_MAX_FILE_KB", "64")) * 1024

#: 예산을 확인하는 주기(파일 수). run_tests() 는 통짜 호출이라 중간에 끊을 수 없으므로
#: files_list 를 이 크기로 잘라 넘기고 청크 사이에서 시계를 본다. 1 인 이유는 예산
#: 초과분이 "청크 하나를 도는 시간"만큼 생기기 때문 — rich 로 재보니 8 로 묶으면 3초
#: 예산이 9.6초까지 밀렸다(무거운 파일 하나가 청크에 섞이면 그렇게 된다). 1 로 낮추는
#: 대가는 run_tests() 재호출 오버헤드 약 6% (rich 전체 12.9초 -> 13.8초)로, 예산을
#: 3배 넘기는 것보다 싸다.
_BANDIT_CHUNK = 1


def _relative_to_root(path: str, root: Path) -> str:
    """추출 루트 기준 상대경로. 루트 밖이면 원본을 그대로 돌려준다."""
    try:
        return Path(path).resolve().relative_to(root).as_posix()
    except ValueError:
        return path


def _is_excluded(relpath: str) -> bool:
    """상대경로의 디렉터리 이름 중 하나라도 제외 목록에 있으면 True.

    파일명 자체는 보지 않는다 — ``docs.py`` 같은 모듈은 실제 배포 코드다.
    """
    return any(part in _BANDIT_EXCLUDE_DIRS for part in PurePosixPath(relpath).parts[:-1])


def _too_big(path: str) -> bool:
    """MAX_BANDIT_FILE_BYTES 초과 여부. stat 실패는 "못 읽는 파일"이라 건너뛴다."""
    try:
        return Path(path).stat().st_size > MAX_BANDIT_FILE_BYTES
    except OSError:
        return True


def _run_bandit(
    root: Path, budget: float | None = None
) -> tuple[list[StaticFinding], str | None]:
    """Bandit 브레드스넷 — 추출된 패키지 트리에서 실제 배포되는 코드만 라이브러리로 돈다.

    반환값은 ``(findings, 미완료 사유)``. 예산이나 파일 수 상한에 걸려 일부만 본 경우
    사유 문자열이 채워지며, 호출부가 그걸 layer_errors 로 남긴다 — "검사하지 못했다"가
    "검사했고 깨끗했다"로 보이면 안 된다는 _layer_static 과 같은 정책이다.
    """
    root = root.resolve()
    b_conf = bandit_config.BanditConfig()
    mgr = bandit_manager.BanditManager(b_conf, "file", quiet=True)
    mgr.discover_files([str(root)], recursive=True)

    # 얕은 경로 우선 — 예산이 모자라 잘릴 때 무엇이 남는지를 결정한다. setup.py 나
    # <pkg>/__init__.py 처럼 트리 위쪽에 있는 파일이 `pip install`·`import` 시점에
    # 실제로 실행되는 코드라, 깊은 서브모듈보다 먼저 봐야 잘린 결과도 쓸모가 있다.
    scoped = sorted(
        (
            (rel, fname)
            for fname, rel in ((f, _relative_to_root(f, root)) for f in mgr.files_list)
            if not _is_excluded(rel)
        ),
        key=lambda pair: (pair[0].count("/"), pair[0]),
    )

    # 미완료 사유는 누적한다 — 크기 상한과 예산에 동시에 걸릴 수 있고, 둘 중 하나만
    # 보고하면 응답을 보는 사람이 사각의 크기를 잘못 짐작한다.
    notes: list[str] = []

    oversized = [rel for rel, f in scoped if _too_big(f)]
    if oversized:
        scoped = [pair for pair in scoped if pair[0] not in set(oversized)]
        notes.append(
            f"{MAX_BANDIT_FILE_BYTES // 1024} KB 초과 파일 {len(oversized)}개 건너뜀 "
            f"({', '.join(sorted(oversized)[:3])}{' 외' if len(oversized) > 3 else ''})"
        )

    if len(scoped) > MAX_BANDIT_FILES:
        notes.append(
            f"파이썬 파일 {len(scoped)}개 중 얕은 경로 우선 {MAX_BANDIT_FILES}개만 검사함"
        )
        scoped = scoped[:MAX_BANDIT_FILES]

    # 비교를 >= 로 두는 이유: Windows 의 time.monotonic() 해상도가 ~15ms 라 budget=0 에서
    # now > now 가 False 로 떨어져 "예산이 0인데 파일 하나는 돈다"가 된다. 0 은 0이어야 한다.
    deadline = None if budget is None else time.monotonic() + budget
    scanned = 0
    for start in range(0, len(scoped), _BANDIT_CHUNK):
        if deadline is not None and time.monotonic() >= deadline:
            notes.append(
                f"{budget:g}초 예산 초과 — 파일 {len(scoped)}개 중 {scanned}개까지만 검사함"
            )
            break
        chunk = [fname for _, fname in scoped[start : start + _BANDIT_CHUNK]]
        # run_tests() 는 self.files_list 를 훑고 결과를 self.results 에 누적하므로,
        # 목록을 갈아끼우며 여러 번 부르면 청크 단위 실행이 된다.
        mgr.files_list = chunk
        mgr.run_tests()
        scanned += len(chunk)

    findings: list[StaticFinding] = []
    for issue in mgr.get_issue_list():
        finding = finding_from_bandit_issue(
            issue, root_relpath=_relative_to_root(issue.fname, root)
        )
        if _SEVERITY_ORDER[finding.severity] > _SEVERITY_ORDER[_BANDIT_SEVERITY_CAP]:
            finding = finding.model_copy(update={"severity": _BANDIT_SEVERITY_CAP})
        findings.append(finding)
    return findings, "; ".join(notes) or None


async def _layer_bandit(
    req: ScanRequest, ctx: PackageContext, errors: list[str]
) -> list[StaticFinding]:
    try:
        root = await ctx.extracted_path()
        if not root:
            return []
        # 스레드로 내보내야 나머지 세 레이어의 gather 병렬성이 살아있다 — 여기서 동기로
        # 부르면 bandit 이 끝날 때까지 ①③은 시작조차 못 한다 (BANDIT_BUDGET_SECONDS 주석).
        findings, truncated = await asyncio.to_thread(
            _run_bandit, root, BANDIT_BUDGET_SECONDS
        )
        if truncated:
            errors.append(f"bandit: {truncated}")
        return findings
    except Exception as exc:  # bandit 내부 예외 계층이 알려져 있지 않아 광범위 캐치
        errors.append(f"bandit: {exc}")
        return []


async def _layer_scoring(
    req: ScanRequest, ctx: PackageContext, errors: list[str]
) -> tuple[RiskSignals, int]:
    try:
        return await score_package(req, ctx=ctx)
    except Exception as exc:  # 스코어링 파트 내부 예외 계층이 아직 없어 광범위 캐치
        errors.append(f"scoring: {exc}")
        return _NEUTRAL_SIGNALS, 0


# ──────────────────────────────
# 오프라인 데모 (SU_OFFLINE_DEMO) — 실제 경로는 위 세 레이어
# ──────────────────────────────

# 패키지 이름에 따라 3가지 판정을 재현
DEMO_MALICIOUS = {"reqeusts", "colourama", "python-sqlite"}   # typosquat 흉내
DEMO_VULNERABLE = {"requests"}                                # 알려진 CVE 보유 흉내

_DEMO_NOTE = "⚠️ 오프라인 데모 모드 (SU_OFFLINE_DEMO) — mock 데이터입니다"


def _demo_layers(
    req: ScanRequest,
) -> tuple[list[Vulnerability], list[StaticFinding], tuple[RiskSignals, int]]:
    vulns: list[Vulnerability] = []
    findings: list[StaticFinding] = []

    if req.name in DEMO_VULNERABLE:
        vulns = [
            Vulnerability(
                source=VulnSource.OSV,
                id="GHSA-9wx4-h78v-vm56",
                severity=Severity.MEDIUM,
                summary="Proxy-Authorization 헤더가 리다이렉트 시 유출될 수 있음",
                fixed_version="2.31.1",
            )
        ]

    if req.name in DEMO_MALICIOUS:
        findings = [
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
        signals = RiskSignals(
            is_new_account=True,
            typosquat_score=0.82,
            has_install_script=True,
            dependency_count=0,
            release_burst=True,
        )
        # 가중치 합산: 신규계정 25 + typosquat 30 + install script 20 + 배포패턴 15 = 90
        return vulns, findings, (signals, 90)

    signals = RiskSignals(
        is_new_account=False,
        typosquat_score=0.05,
        has_install_script=False,
        dependency_count=4,
        release_burst=False,
    )
    return vulns, findings, (signals, 5)


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
    notes: list[str] = []

    if OFFLINE_DEMO:
        vulns, findings, (signals, risk_score) = _demo_layers(req)
        notes.append(_DEMO_NOTE)
    else:
        # 한 요청 = PyPI JSON 1회 + 아카이브 1회. ②③가 같은 컨텍스트를 씁니다.
        # 앱의 공유 커넥션 풀을 넘기므로 ctx 는 클라이언트를 닫지 않고 임시 디렉터리만
        # 정리합니다. PackageContext 는 내부에 락이 있어 병렬 접근에 안전합니다.
        async with PackageContext(req.name, req.version, client=http) as ctx:
            # 네 레이어는 서로 독립 — 병렬 실행 (①은 OSV, ②②'③은 공유 ctx)
            vulns, findings, bandit_findings, (signals, risk_score) = await asyncio.gather(
                _layer_cve(req, http, layer_errors),
                _layer_static(req, ctx, layer_errors),
                _layer_bandit(req, ctx, layer_errors),
                _layer_scoring(req, ctx, layer_errors),
            )
            findings = findings + bandit_findings

        # CWE 태깅 (담당: API 파트) — 취약점별 OSV 재조회로 cwe_ids 를 채운다.
        # 부가 정보라 실패는 조용히 빈 리스트로 남고 판정에는 영향 없음.
        await tag_vulnerabilities(vulns, http)

    verdict, reasons = _decide(vulns, findings, risk_score)
    reasons.extend(notes)

    response = ScanResponse(
        scan_id=0,  # insert 후 확정
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
