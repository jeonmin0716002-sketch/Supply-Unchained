"""감시 한 주기 — 피드 수집 → 처음 보는 릴리스만 스캔 → 의심 건을 검토 큐에.

스캔은 ``api.routers.scan.run_scan`` 을 그대로 쓴다. 즉 감시기도 패키지를 **설치하거나
실행하지 않는다** — 아카이브를 받아 안전 추출 후 정적분석만 한다(common/pypi.py).
신뢰할 수 없는 업로드를 하루 수천 건 다루는 도구라 이 원칙이 가장 중요하다.

큐에 넣는 기준(``is_suspicious``)이 판정(verdict)과 다른 이유가 둘 있다.

* WARN 의 대부분은 "정상 패키지의 구버전에 알려진 CVE 가 있다"인데, 감시기의 목적은
  악성 패키지 헌팅이라 그건 노이즈다.
* 메타데이터 위험도(risk_score)도 쓰지 않는다. 감시 대상이 전부 갓 올라온 패키지라
  "신규 계정"(+25) 신호가 항상 켜져 있고, 배포 버스트(+15)나 설치 스크립트(+20) 하나만
  더해져도 주의 임계 40 에 닿는다. 실측(2026-10-16, PyPI 60건): 위험도만으로 걸린 6건이
  전부 이 조합이었고 typosquat 유사도는 0.38~0.60 — 평범한 새 패키지였다.

그래서 BLOCK 이거나, 새 패키지에서도 변별력이 남는 메타데이터 신호인 typosquat 유사도가
높은(``TYPOSQUAT_MIN_RATIO`` 이상) 것만 올린다. 이름 유사도는 다시 **새 프로젝트**
(첫 릴리스가 NEW_PACKAGE_DAYS 이내)일 때만 센다 — 이름 사칭은 갓 만든 이름으로 올라와
며칠 안에 끝난다. 12시간 실측에서 유사도로 걸린 45건 대부분은 수개월~수년 된 정상
프로젝트였다(oauth2-lib 는 2021년부터 55개 릴리스, langchaint 는 "It ain't langchain").

같은 패키지가 같은 이유로 다시 걸리면 큐에 다시 넣지 않는다(``signature``) — dagz 는
nightly 마다 같은 .pth 로 6번 올라왔다. 이유가 바뀌면(예: 정상이던 패키지의 새 버전에
처음으로 난독화가 생김 — 계정 탈취의 전형) 다시 올린다. 오탐으로 기록한 것도 같은 규칙이다.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx

from api.schemas import ScanRequest
from api.storage import ScanStore
from common.pypi import PyPIError, fetch_project
from scoring.features import TYPOSQUAT_MIN_RATIO
from watcher.feed import fetch_feeds

Item = tuple[str, str | None]
FetchFn = Callable[[httpx.AsyncClient], Awaitable[tuple[list[Item], list[str]]]]
ResolveFn = Callable[[str, httpx.AsyncClient], Awaitable[str]]


@dataclass
class CycleReport:
    fetched: int = 0                       # 피드에서 읽은 항목 수 (중복 제거 후)
    scanned: int = 0
    deferred: int = 0                      # max_scans 초과로 다음 주기로 미룬 수
    flagged: list[dict] = field(default_factory=list)       # 큐에 넣은 스캔 결과
    repeat: int = 0                        # 같은 패키지·같은 이유라 큐에 다시 넣지 않은 수
    failed: list[tuple[str, str]] = field(default_factory=list)  # (spec, 사유)
    skipped_invalid: list[str] = field(default_factory=list)     # 이름/버전 검증 실패
    feed_errors: list[str] = field(default_factory=list)


def _lookalike_new_project(record: dict) -> bool:
    signals = record.get("risk_signals") or {}
    return bool(signals.get("is_new_account")) and (
        (signals.get("typosquat_score") or 0.0) >= TYPOSQUAT_MIN_RATIO
    )


def _blocked_by_antivirus(record: dict) -> bool:
    """정적분석이 백신에 막혀 파일을 못 읽었다 — Windows Defender 는 실제 악성 파일의 읽기를
    막는다(OSError 22, 실측: DataDog 악성 샘플). 그 자체가 강한 신호인데, 그 파일을 못 봤으니
    판정은 safe 로 나올 수 있다. 큐에 안 올리면 백신이 잡은 걸 감시기가 놓친다."""
    return any("백신" in e for e in record.get("layer_errors", ()) if e.startswith("static:"))


def is_suspicious(record: dict) -> bool:
    return (
        record["verdict"] == "block"
        or _lookalike_new_project(record)
        or _blocked_by_antivirus(record)
    )


def signature(record: dict) -> tuple:
    """"같은 이유로 걸렸다"의 기준 — 판정, 고위험 규칙 목록, 이름 사칭 여부."""
    findings = record.get("static_findings", ())
    high_rules = sorted({f["rule"] for f in findings if f["severity"] in ("high", "critical")})
    return (
        record["verdict"],
        tuple(high_rules),
        _lookalike_new_project(record),
        _blocked_by_antivirus(record),
    )


async def resolve_latest(name: str, http: httpx.AsyncClient) -> str:
    project = await fetch_project(name, client=http)
    version = project.info.get("version")
    if not version:
        raise PyPIError(f"{name}: PyPI JSON 에 최신 버전이 없음")
    return version


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


async def run_cycle(
    *,
    http: httpx.AsyncClient,
    store: ScanStore,
    scan: Callable[..., Awaitable],
    fetch: FetchFn = fetch_feeds,
    resolve: ResolveFn = resolve_latest,
    max_scans: int = 50,
    concurrency: int = 3,
) -> CycleReport:
    report = CycleReport()
    items, report.feed_errors = await fetch(http)
    items = list(dict.fromkeys(items))
    report.fetched = len(items)

    # 신규 프로젝트 피드는 버전이 없다. 이미 본 이름이면 최신 버전 조회를 건너뛴다 —
    # 그 뒤의 릴리스는 updates 피드로 들어오므로, 매 주기 40건씩 JSON 을 다시 받을 이유가 없다.
    known = await store.seen_names([n for n, v in items if v is None])
    sem = asyncio.Semaphore(concurrency)

    async def _resolve(name: str) -> tuple[str, str] | None:
        async with sem:
            try:
                return name, await resolve(name, http)
            except (PyPIError, httpx.HTTPError) as exc:
                report.failed.append((name, f"최신 버전 조회 실패: {exc}"))
                return None

    resolved = await asyncio.gather(
        *(_resolve(n) for n, v in items if v is None and n not in known)
    )
    # 새 프로젝트를 먼저 — max_scans 에 걸려 미뤄질 때 새 이름이 뒤로 밀리면 안 된다.
    # 악성 업로드는 대부분 새 이름(typosquat·dependency confusion)이고, 피드는 최근 항목만
    # 보여주므로 계속 밀리면 스캔 전에 피드에서 빠져 영영 못 보게 된다.
    candidates = [r for r in resolved if r] + [(n, v) for n, v in items if v is not None]

    requests: list[ScanRequest] = []
    for name, version in dict.fromkeys(candidates):
        try:
            requests.append(ScanRequest(name=name, version=version))
        except ValueError:
            report.skipped_invalid.append(f"{name}=={version}")

    pending = await store.unseen([(r.name, r.version) for r in requests])
    report.deferred = max(0, len(pending) - max_scans)
    todo = {p for p in pending[:max_scans]}
    requests = [r for r in requests if (r.name, r.version) in todo]

    async def _scan(req: ScanRequest) -> None:
        async with sem:
            try:
                result = await scan(req, http=http, store=store)
            except Exception as exc:  # 한 패키지 실패가 주기 전체를 죽이면 안 됨
                # seen 으로 표시하지 않는다 — 피드에 남아 있는 동안 다음 주기에 재시도된다.
                report.failed.append((f"{req.name}=={req.version}", str(exc)))
                return
        record = result.model_dump(mode="json")
        await store.mark_seen(req.name, req.version, _now())
        report.scanned += 1
        if is_suspicious(record):
            seen_before = await store.queued_records(req.name)
            if any(signature(r) == signature(record) for r in seen_before):
                report.repeat += 1
                return
            await store.enqueue(record, _now())
            report.flagged.append(record)

    await asyncio.gather(*(_scan(r) for r in requests))
    return report
