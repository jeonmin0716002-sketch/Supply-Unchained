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
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial

import httpx

import ecosystems as ecos
from api.schemas import ScanRequest
from api.storage import ScanStore
from common.pypi import fetch_project
from ecosystems.base import PackageNotFound
from ecosystems.base import RegistryError as PyPIError
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
    removed: list[str] = field(default_factory=list)    # 스캔 전에 PyPI 에서 사라진 패키지
    missing: int = 0                       # 조회가 안 돼 MISSING_GRACE 뒤 다시 볼 패키지 수
    by_ecosystem: dict[str, dict[str, int]] = field(default_factory=dict)  # 생태계별 집계


#: 감시 큐에 "PyPI 에서 삭제됨" 을 남길 때 쓰는 seen 표시 버전 — 다음 주기에 다시 조회하지 않게
REMOVED_MARK = "(removed)"

#: 조회가 안 된 패키지를 "삭제됨"으로 확정하기까지 기다리는 시간(초). 피드에 막 뜬 새
#: 프로젝트는 PyPI JSON API(CDN)에 아직 없어 404 가 나기도 한다 — 실측(2026-10-18 밤):
#: 업로드 1분 뒤 조회해 "삭제됨"으로 기록한 35건 중 34건이 다음 날 멀쩡히 있었다.
MISSING_GRACE = 30 * 60

#: 조회가 안 된 패키지 → (버전 또는 None, 처음 안 된 시각). 주기를 넘어 유지되도록 호출자가 넘긴다.
Missing = dict[str, tuple[str | None, float]]


def _removed_from_registry(record: dict) -> bool:
    """스캔 시점에 이미 레지스트리에 없던 릴리스. 어댑터 계약(ecosystems/base.py)상 메시지는
    항상 ``"<name> is not on <registry_label> (...)"`` 라 레지스트리 이름과 무관하게 맞는다."""
    return any(
        " is not on " in e for e in record.get("layer_errors", ()) if e.startswith("static:")
    )


_removed_from_pypi = _removed_from_registry  # 하위 호환 이름


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


def _adapter(eco_id: str, adapters: dict | None):
    if adapters and eco_id in adapters:
        return adapters[eco_id]
    return ecos.get(eco_id)


async def run_cycle(
    *,
    http: httpx.AsyncClient,
    store: ScanStore,
    scan: Callable[..., Awaitable],
    fetch: FetchFn | None = None,
    resolve: ResolveFn | None = None,
    max_scans: int = 50,
    concurrency: int = 3,
    missing: Missing | None = None,
    clock: Callable[[], float] = time.time,
    ecosystems: Sequence[str] = ("pip",),
    adapters: dict | None = None,
) -> CycleReport:
    """``ecosystems`` 를 차례로 한 주기씩 돈다. ``max_scans`` 는 **생태계마다** 따로 쓴다 —
    바쁜 레지스트리(npm 은 시간당 수천 건)가 한 주기 예산을 다 먹어 pip·cargo 가 계속 밀리면
    피드에서 빠져 영영 못 보게 된다. ``fetch``·``resolve`` 는 pip 전용 주입점(테스트·기존 호출자),
    다른 생태계는 어댑터의 ``fetch_feed``·``fetch_project`` 를 쓴다. ``adapters`` 는
    테스트용 덮어쓰기."""
    report = CycleReport()
    missing = {} if missing is None else missing
    for eco_id in ecosystems:
        try:
            adapter = _adapter(eco_id, adapters)
        except ecos.UnknownEcosystem as exc:
            if eco_id != "pip":
                report.feed_errors.append(f"{eco_id}: {exc}")
                continue
            adapter = None  # pip 어댑터가 없는 브랜치에서도 기존 경로(feed.py)로 돈다
        if eco_id == "pip" and fetch is not None:
            eco_fetch = fetch
        elif eco_id == "pip":
            eco_fetch = fetch_feeds
        elif adapter is not None and adapter.has_feed:
            eco_fetch = adapter.fetch_feed
        else:
            report.feed_errors.append(f"{eco_id}: 신규 업로드 피드가 없는 생태계")
            continue
        if eco_id == "pip" and resolve is not None:
            eco_resolve = resolve
        elif eco_id == "pip":
            eco_resolve = resolve_latest
        else:
            eco_resolve = partial(_resolve_with_adapter, adapter)
        await _run_ecosystem(
            report, eco_id, adapter, eco_fetch, eco_resolve,
            http=http, store=store, scan=scan, max_scans=max_scans,
            concurrency=concurrency, missing=missing, clock=clock,
        )
    return report


async def _resolve_with_adapter(adapter, name: str, http: httpx.AsyncClient) -> str:
    project = await adapter.fetch_project(name, client=http)
    if not project.latest:
        raise PyPIError(f"{name}: {adapter.registry_label} 에 최신 버전이 없음")
    return project.latest


def _make_request(adapter, eco_id: str, name: str, version: str) -> ScanRequest:
    """이름·버전 검증은 생태계 어댑터가 한다(스코프·그룹 좌표 등 pip 정규식에 안 맞는 문법).
    ScanRequest 가 아직 그 생태계를 모르는 브랜치에서는 어댑터 검증을 통과한 값으로
    ``model_construct`` 한다 — 검증을 건너뛰는 게 아니라 어댑터가 대신하는 것이다."""
    if eco_id == "pip":
        return ScanRequest(name=name, version=version)
    adapter.validate(name, version)
    try:
        return ScanRequest(ecosystem=eco_id, name=name, version=version)
    except ValueError:
        return ScanRequest.model_construct(ecosystem=eco_id, name=name, version=version)


async def _run_ecosystem(
    report: CycleReport, eco_id: str, adapter, fetch, resolve, *,
    http, store, scan, max_scans, concurrency, missing, clock,
) -> None:
    # missing 의 키: pip 는 이름 그대로(기존 호출자·테스트 호환), 나머지는 "생태계:이름"
    def mk(name: str) -> str:
        return name if eco_id == "pip" else f"{eco_id}:{name}"

    scanned0, flagged0 = report.scanned, len(report.flagged)
    now = clock()
    # 유예가 끝난 것은 피드에서 이미 빠졌어도 마지막으로 한 번 더 본다
    prefix = "" if eco_id == "pip" else f"{eco_id}:"
    due = {
        k[len(prefix):] for k, (_, t) in missing.items()
        if now - t >= MISSING_GRACE and (k.startswith(prefix) if prefix else ":" not in k)
    }
    items, errs = await fetch(http)
    report.feed_errors += errs
    due_items = [(n, missing[mk(n)][0]) for n in sorted(due)]
    items = list(dict.fromkeys([*items, *due_items]))
    report.fetched += len(items)

    # 신규 프로젝트 피드는 버전이 없다. 이미 본 이름이면 최신 버전 조회를 건너뛴다 —
    # 그 뒤의 릴리스는 updates 피드로 들어오므로, 매 주기 40건씩 JSON 을 다시 받을 이유가 없다.
    known = await store.seen_names([n for n, v in items if v is None], eco_id)
    sem = asyncio.Semaphore(concurrency)

    async def _removed(name: str, version: str) -> None:
        """피드에 보였는데 스캔 전에 레지스트리가 지운 패키지. 새 업로드가 몇 분 만에 사라지는 건
        거의 레지스트리의 악성 차단이다 — 우리 엔진이 봤든 못 봤든 놓치면 안 되는 사후 정답이다
        (실측: OpenSSF 신고 marocolor 는 감시 중 탐지됐는데 우리 기록에 흔적이 없었다)."""
        missing.pop(mk(name), None)
        if await store.enqueue_removed(name, version, _now(), eco_id):
            report.removed.append(name if eco_id == "pip" else f"{eco_id}:{name}")

    async def _not_found(name: str, version: str | None) -> None:
        """조회가 안 됐다 — 유예가 지났으면 삭제로 확정, 아니면 나중에 다시 본다.
        seen 으로 표시하지 않으므로 피드에 남아 있는 동안은 매 주기 다시 조회된다."""
        if name in due:
            if version is None:
                await store.mark_seen(name, REMOVED_MARK, _now(), eco_id)
            await _removed(name, version or "?")
        else:
            missing.setdefault(mk(name), (version, now))

    async def _resolve(name: str) -> tuple[str, str] | None:
        async with sem:
            try:
                return name, await resolve(name, http)
            except PackageNotFound:
                await _not_found(name, None)
                return None
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
            requests.append(_make_request(adapter, eco_id, name, version))
        except ValueError:
            report.skipped_invalid.append(f"{name}=={version}")

    pending = await store.unseen([(r.name, r.version) for r in requests], eco_id)
    report.deferred += max(0, len(pending) - max_scans)
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
        record.setdefault("ecosystem", eco_id)
        report.scanned += 1
        if _removed_from_registry(record):
            if req.name in due:
                await store.mark_seen(req.name, req.version, _now(), eco_id)
            await _not_found(req.name, req.version)
            return
        await store.mark_seen(req.name, req.version, _now(), eco_id)
        missing.pop(mk(req.name), None)
        if is_suspicious(record):
            seen_before = await store.queued_records(req.name, eco_id)
            if any(signature(r) == signature(record) for r in seen_before):
                report.repeat += 1
                return
            await store.enqueue(record, _now())
            report.flagged.append(record)

    await asyncio.gather(*(_scan(r) for r in requests))
    report.missing = len(missing)
    report.by_ecosystem[eco_id] = {
        "scanned": report.scanned - scanned0, "flagged": len(report.flagged) - flagged0,
    }
