# 다중 생태계 확장 — 진행 상태 (2026-11-14)

브랜치 `feat/multi-ecosystem`. 설계는 [multi-ecosystem.md](multi-ecosystem.md).
`uv run ruff check .` 통과, `uv run pytest -q` 889 통과 · 1 건너뜀(Windows 심볼릭 링크).
`main` 에는 병합하지 않았다.

## 들어간 것

| 영역 | 내용 | 확인 수준 |
|---|---|---|
| 파이프라인 | 어댑터 기반 `run_scan`, 생태계별 OSV 조회, CLI `check -e <생태계>` | 테스트 + pip·cargo·go·maven·nuget·rubygems·composer 실패키지 1개씩 스캔 |
| 게이트 구멍 1 | 프록시가 요청받은 바로 그 파일을 스캔, 그 밖은 sdist + wheel 1개 | 회귀 테스트 |
| 게이트 구멍 2 | 선택 추출, 스캔 불가는 최소 warn, 프록시는 기본 차단(`SU_UNSCANNED_POLICY`) | 회귀 테스트 |
| 어댑터 | npm · cargo · go · maven · nuget · rubygems · composer (+ pip 래핑) | 오프라인 테스트, 인기 패키지 오탐 확인 |
| npm | 규칙·lockfile·피드·`/npm` 프록시, 실측 [docs/eval/npm.md](../eval/npm.md) — held-out 탐지율 52.0% (156/300), 상위 300개 오탐 0 | 실측. 프록시는 실제 `npm install` 로 돌려보지 않음 |
| 파이썬 엔진 | 설치·import 시점 프로세스 실행 규칙, 직전 릴리스 대비 새 행위(`engine/version_diff.py`), 실행 범위 확장, 2MB 초과 파일 누락 수정 | 테스트. **실측 문서 미완** |
| 프로젝트 스캔 | `su-scan project`, `su-scan sbom`, OSV 일괄 조회, CycloneDX 입출력 | 테스트 + 이 레포 `uv.lock` 실행 |
| 감시기·대시보드 | 저장소·감시 주기·큐 API·대시보드의 생태계 구분 | 테스트. 대시보드 화면 확인은 안 함 |
| CI·문서 | Bandit 범위 확장, `action.yml`, `.pre-commit-hooks.yaml`, `docs/usage/` | 로컬만. GitHub 에서 실행해 보지 않음 |

## 남은 것

1. **파이썬 엔진 실측 — 완료.** [docs/eval/py-engine.md](../eval/py-engine.md): 처음 보는 악성 300개 81.0%,
   탈취 패키지 차단 93.1% (27/29, 이전 62%), 정상 상위 300 오탐 0.7% (2/299), 신규 업로드 표본 오탐 0.20% (1/491).
   신규 업로드 오탐 제안 반영 후 예전 block 74건 중 21건만 남음. README 수치 교체 완료.
2. **신규 업로드 오탐률 재측정 — 완료.** [docs/eval/watch-new-uploads.md](../eval/watch-new-uploads.md):
   감시기가 본 릴리스 무작위 500개 중 block 3건 = 0.62% (95% CI 0.21–1.8%), 셋 다 오탐으로 분류.
   예전에 block 이던 74건 중 50건(27개 패키지)이 지금도 block 이고 악성 가능성은 0건으로 봤다.
   문서 끝의 규칙 수정 제안은 py-engine 이 반영했다(위 1번). 이 문서의 수치는 반영 전 엔진 기준이다.
3. **인기 패키지 목록** — pip · npm · cargo · nuget · composer · rubygems 있음. go · maven 은 순위를 주는
   공개 출처를 찾지 못해 없다 → 두 생태계의 이름 사칭 점수는 0 이다.
4. **연결·확인 완료 (2026-11-14)** — `watch --ecosystems`·`crosscheck --ecosystem` 연결, pip·npm·cargo·rubygems
   실제 한 주기 실행. 실제 `npm install --registry .../npm/` 로 스코프 패키지·전이 의존성 4개가 스캔 후 설치됨.
   대시보드 화면 확인(콘솔 오류 없음). 차단 경로는 실제 악성 npm 패키지로 돌려보지 않았다(테스트만).
5. **인기 패키지 오탐 확인** — rubygems 80 · cargo 60 · nuget 60 · composer 60 개에서 HIGH 0건
   (rubygems 는 감시 첫 주기에서 나온 오탐 3종을 고친 뒤의 값). go · maven 은 인기 목록이 없어 소수만 확인.
   **악성 샘플 탐지율은 npm 외 6종 모두 미측정.** npm `compromised_lib` 도 미측정.
6. **README** — 구조·지원 생태계·판정 원칙·실측 수치 갱신 완료.
   `engine.version_diff` 는 직전 릴리스를 아티팩트 1개(sdist 우선)로만 비교한다.
7. 설계 문서 §5 의 이후 과제(결과 캐시, 패키지 배포, 큐 API 인증, 대형 휠 부분 읽기).

세션별 한계와 통합 요청 원문은 [integration-notes/](integration-notes/) 에 있다.
