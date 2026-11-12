# py-engine → 통합 요청 (다른 세션 소유 파일)

브랜치 `claude/py-engine-8c17eb`. 아래는 py-engine 이 고치지 않은, 통합 때 반영할 것들이다.

## 1. `api/routers/scan.py` (core-pipeline) — 직전 릴리스 비교 연결

설계 문서 §3.1 의 guarded import 그대로 쓰면 된다:

```python
try: from engine.version_diff import escalate_new_behaviors
except ImportError: escalate_new_behaviors = None
...
if escalate_new_behaviors is not None:
    diff_errors: list[str] = []
    findings += await escalate_new_behaviors(ctx, findings, errors=diff_errors)
    layer_errors += diff_errors
```

* 돌려받는 것은 **추가할 finding 만**이다 (`custom-new-behavior`, HIGH). 원래 finding 은 그대로 둔다.
* 후보(`custom-install-time-spawn` 또는 HIGH 커스텀 finding)가 없으면 네트워크 요청을 하지 않는다.
  후보가 있으면 `ctx.project()`(캐시됨) + 직전 릴리스 아티팩트 1개 다운로드.
* 비교 실패는 `errors` 에 `static: 직전 릴리스 ... 와 비교하지 못함 — ...` 으로 온다. core-pipeline
  인계 노트의 결정("diff 실패 ≠ 미검사, 결정 후 덧붙임")과 맞다 — 다만 이 경우 spawn 은 MEDIUM 으로
  남아 차단되지 않으므로, 프록시 정책에서 이 문구를 "미검사"로 볼지 정해야 한다. 엔진 쪽 권고는
  **warn** (spawn 이 있고 비교를 못 했다 = 판단 근거 부족).
* 다중 아티팩트(sdist + wheel)를 스캔하게 되면, 직전 릴리스도 같은 아티팩트 집합으로 분석하는 것이
  맞다. 지금 `analyze_release` 는 `select_artifact`(sdist 우선) 1개다. 설치·import 시점 규칙은
  행위 이름에 파일 위치를 쓰지 않아서 sdist↔wheel 차이에 흔들리지 않지만, `.pth` 같은 위치 기반
  규칙은 wheel 에만 있으면 "새 행위" 주석이 붙을 수 있다(이미 HIGH 라 판정은 같다).

## 2. 스캔 레이어 오류 문구 — `unreadable` 에 크기 상한 초과가 섞인다

`engine.static_analyzer.analyze_tree(..., unreadable=lst)` 는 이제 20MB(`MAX_CODE_BYTES`)를 넘는
코드 파일(.py·.pth)도 `lst` 에 `"<relpath> (크기 상한 초과)"` 로 넣는다 (예전엔 2MB 넘는 비진입점
.py 가 조용히 빠졌다). 어댑터·파이프라인이 `analyze_tree` 를 직접 부른다면 문구는
`engine.static_analyzer.unreadable_errors(lst)` 로 만들면 백신 차단과 크기 초과가 구분된다.
`analyze_package` 는 이미 그렇게 한다.

## 3. 새 규칙 ID (대시보드·문서·CWE 표)

| 규칙 | 심각도 | CWE |
|---|---|---|
| `custom-install-time-spawn` | MEDIUM (홀로는 판정 불변) | CWE-78 |
| `custom-new-behavior` | HIGH (직전 릴리스에 없던 행위) | 원 finding 의 CWE |
| `custom-entrypoint-exec` | HIGH (콘솔 명령이 수상한 명령 실행) | CWE-506 |

`engine.verdict.RULE_CATALOG`·`KNOWN_CWES` 에 등록돼 있다.

## 4. `README.md` "탐지 성능 (실측)" 갱신

수치·명령은 `docs/eval/py-engine.md` 에 있다. 탈취 평가 명령은 그대로이고 직전 릴리스 비교가 기본으로
켜진다(`--no-version-diff` 로 끔). 정상 평가는 `--diff-all` 옵션이 생겼다.
