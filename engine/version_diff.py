"""직전 버전 대비 새 행위 — 계정 탈취로 끼워 넣은 코드를 "처음 나타났다"로 잡는다.

정상 라이브러리도 import 시점에 프로세스를 띄운다(GPU 확인, 빌드 도구 조사). 그래서
``custom-install-time-spawn`` 은 홀로는 MEDIUM 이다. 그런데 탈취 사고에서는 그 행위가
**이전 릴리스에는 없다가 이번 릴리스에 처음** 나타난다 — lightning 2.6.2(import 시 스레드에서
번들 스크립트 Popen), memoryos 2.0.34(번들 바이너리 chmod 후 Popen) 모두 직전 정상 버전에는
없던 코드였다(DataDog compromised_lib 실측, docs/eval/py-engine.md). 흔한 행위라도 "기존
패키지의 새 릴리스에 처음 등장"은 계정 탈취의 전형이라 HIGH 로 올린다.

두 부분:

* ``new_behaviors(current, previous)`` — 순수 함수. 두 릴리스의 finding 을 비교해 이번에
  새로 나타난 행위에 대한 **추가** finding(``custom-new-behavior``)만 돌려준다.
  - ``custom-install-time-spawn``(MEDIUM)이 새로 나타나면 → HIGH
  - 이미 HIGH 인 커스텀 규칙 행위가 새로 나타나면 → 같은 위치에 "새로 나타남" 주석(HIGH)
* ``escalate_new_behaviors(ctx, findings, *, errors)`` — 스캔 파이프라인 연결 지점
  (docs/design/multi-ecosystem.md §3.1). 후보 finding 이 있을 때만 직전 릴리스를 받아
  커스텀 규칙으로 분석한다 — 대부분의 스캔은 추가 다운로드가 없다. 비교하지 못하면
  ``errors`` 에 ``static:`` 으로 남긴다 — "못 봤다"는 "새 행위 없음"이 아니다.

행위의 이름은 위치(줄번호)가 아니라 **무엇을 했는가**다 — 규칙 + 호출 이름 + 명령 이름
(``프로세스 실행 subprocess.Popen() — 명령 'python'``). 릴리스마다 줄번호와 sdist 루트
디렉터리 이름(``pkg-1.2.3/``)이 바뀌고, 정상 릴리스도 파일을 옮긴다. 그래서 설치·import
시점 규칙은 파일 위치를 행위 이름에서 뺀다. 대가: 이전 릴리스에 같은 이름의 행위(예: 명령을
정적으로 알 수 없는 ``'?'`` 실행)가 이미 있으면, 다른 파일에 새로 들어온 같은 이름의 행위는
새 것으로 보지 않는다.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory

from api.schemas import Severity, StaticFinding
from common.archive import extract_archive
from common.pypi import PackageContext, ProjectData, PyPIError, download, select_artifact
from engine.rules.install_time import (
    ORIGIN_MARK,
    RULE_INDIRECT_NET,
    RULE_INSTALL_SPAWN,
    RULE_INSTALL_TIME,
)
from engine.static_analyzer import analyze_path

RULE_NEW_BEHAVIOR = "custom-new-behavior"

#: 새로 나타나면 MEDIUM → HIGH 로 올리는 규칙. 정상 상위 패키지의 (최신, 직전) 쌍에서
#: 새로 나타나는 비율을 재고 넣는다 (docs/eval/py-engine.md). ``custom-dangerous-call``
#: (eval·exec·pickle 등)은 정상 릴리스에서도 자주 새로 생겨 여기 넣지 않았다.
ESCALATE_WHEN_NEW: frozenset[str] = frozenset({RULE_INSTALL_SPAWN, RULE_INDIRECT_NET})

#: 행위 이름을 "무엇을 했는가"로 잡는 규칙 (파일 위치는 뺀다)
_BY_WHAT = frozenset({RULE_INSTALL_TIME, RULE_INSTALL_SPAWN, RULE_INDIRECT_NET})
_WHAT = re.compile(r"(?:네트워크 호출|수상한 명령 실행|프로세스 실행) .*")

_HIGH = (Severity.HIGH, Severity.CRITICAL)


def behavior_key(f: StaticFinding) -> tuple[str, str]:
    """릴리스가 바뀌어도 같은 행위면 같은 값."""
    if f.rule in _BY_WHAT:
        m = _WHAT.search(f.detail or "")
        if m:
            return f.rule, m.group(0).split(ORIGIN_MARK)[0].strip()
    # 그 밖의 규칙은 파일 위치로 — 줄번호와 sdist 루트(이름-버전/)를 빼고 끝 두 단계만
    path = PurePosixPath(f.location.rsplit(":", 1)[0])
    return f.rule, "/".join(path.parts[-2:])


def _is_candidate(f: StaticFinding) -> bool:
    if f.rule in ESCALATE_WHEN_NEW:
        return True
    return f.rule.startswith("custom-") and f.rule != RULE_NEW_BEHAVIOR and f.severity in _HIGH


def has_candidates(findings: Iterable[StaticFinding]) -> bool:
    """직전 릴리스를 받아 비교할 가치가 있는가 — 없으면 추가 다운로드를 하지 않는다."""
    return any(_is_candidate(f) for f in findings)


def new_behaviors(
    current: Iterable[StaticFinding], previous: Iterable[StaticFinding]
) -> list[StaticFinding]:
    """이번 릴리스에서 처음 나타난 행위에 대한 **추가** finding (행위마다 하나)."""
    before = {behavior_key(f) for f in previous}
    out: list[StaticFinding] = []
    seen: set[tuple[str, str]] = set()
    for f in current:
        if not _is_candidate(f):
            continue
        key = behavior_key(f)
        if key in before or key in seen:
            continue
        seen.add(key)
        if f.severity in _HIGH:
            detail = f"직전 릴리스에 없던 고위험 행위가 이번 릴리스에 처음 나타남: {f.detail}"
        else:
            detail = ("직전 릴리스에 없던 설치·import 시점 행위가 이번 릴리스에 처음 "
                      f"나타남 — 계정 탈취로 끼워 넣은 코드의 전형: {f.detail}")
        out.append(StaticFinding(rule=RULE_NEW_BEHAVIOR, cwe=f.cwe, severity=Severity.HIGH,
                                 location=f.location, detail=detail))
    return out


# ── 직전 릴리스 ───────────────────────────────────────────────────

def _uploaded(files: list[dict]) -> datetime | None:
    times = []
    for f in files:
        raw = f.get("upload_time_iso_8601") or f.get("upload_time")
        if not raw:
            continue
        try:
            t = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            continue
        times.append(t if t.tzinfo else t.replace(tzinfo=UTC))  # PyPI 는 UTC
    return min(times) if times else None


def previous_version(
    project: ProjectData, version: str, *, before: datetime | None = None
) -> str | None:
    """업로드 시각으로 이 릴리스 **직전** 릴리스. 버전 번호 순서가 아니다 — 백포트(1.x 유지보수
    릴리스)가 2.x 뒤에 올라오는 일이 흔하고, 탈취범은 그 시점의 최신 코드를 고쳐 올린다.

    철회(yanked)된 릴리스는 건너뛴다 — 탈취 사고에서는 앞선 악성 릴리스가 철회되는 경우가
    많아서(ultralytics 8.3.41 → 8.3.42), 그걸 기준으로 삼으면 같은 악성 코드가 "기존 행위"가
    된다. 이 릴리스가 메타데이터에서 이미 지워졌으면 ``before`` (예: 발견일)를 기준으로 쓴다.
    """
    cutoff = _uploaded(project.releases.get(version, [])) or before
    if cutoff is None:
        return None
    best: tuple[datetime, str] | None = None
    for v, files in project.releases.items():
        if v == version or not files or any(f.get("yanked") for f in files):
            continue
        t = _uploaded(files)
        if t is not None and t < cutoff and (best is None or t > best[0]):
            best = (t, v)
    return best[1] if best else None


async def analyze_release(project: ProjectData, version: str, *, client) -> list[StaticFinding]:
    """다른 릴리스 하나를 받아 커스텀 규칙만으로 분석한다 (설치·실행하지 않는다).

    스캔 대상과 같은 방식(``select_artifact`` — sdist 우선)으로 파일을 고른다. 다르게 고르면
    sdist 에만 있는 setup.py 행위가 "새 것"으로 보인다.
    """
    artifact = select_artifact(project.artifacts(version))
    if artifact is None:
        raise PyPIError(f"{project.name} {version} 에 분석할 파일이 없음")
    data = await download(artifact, client=client)

    def _extract_and_analyze() -> list[StaticFinding]:
        with TemporaryDirectory(prefix="su-prev-") as tmp:
            root = extract_archive(data, artifact.filename, Path(tmp))
            return analyze_path(root, unreadable=[])

    return await asyncio.to_thread(_extract_and_analyze)


async def escalate_new_behaviors(
    ctx: PackageContext, findings: list[StaticFinding], *, errors: list[str]
) -> list[StaticFinding]:
    """스캔 파이프라인용: 이번 릴리스에 새로 나타난 행위에 대한 추가 finding 만 돌려준다."""
    if not has_candidates(findings):
        return []
    try:
        project = await ctx.project()
    except PyPIError as exc:
        errors.append(f"static: 직전 릴리스와 비교하지 못함 — {exc}")
        return []
    prev = previous_version(project, ctx.version)
    if prev is None:
        return []  # 새 프로젝트(첫 릴리스) — 비교할 대상이 없다
    try:
        previous = await analyze_release(project, prev, client=ctx.client)
    except (PyPIError, OSError) as exc:
        errors.append(f"static: 직전 릴리스 {prev} 와 비교하지 못함 — {exc}")
        return []
    return new_behaviors(findings, previous)
