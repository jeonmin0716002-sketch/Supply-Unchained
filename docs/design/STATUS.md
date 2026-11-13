# 다중 생태계 확장 — 진행 상태 (2026-11-13 중단 시점)

브랜치 `feat/multi-ecosystem`. 설계는 [multi-ecosystem.md](multi-ecosystem.md).
`uv run ruff check .` 통과, `uv run pytest -q` 837 통과 · 1 건너뜀(Windows 심볼릭 링크).
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

1. **파이썬 엔진 실측 문서** — 세션이 정상 상위 300개 오탐률을 재던 중 중단. `docs/eval/py-engine.md` 없음.
   새 규칙이 탐지율·오탐률을 어떻게 바꿨는지 숫자가 아직 없다. README 의 80.7% · 62% · 0.7% 는 이전 엔진 값이다.
2. **신규 업로드 오탐률 재측정** — `tools/eval_new_uploads.py` 는 있음. 실행 결과와
   `docs/eval/watch-new-uploads.md`(분류표)는 없음.
3. **인기 패키지 목록** — pip · npm · cargo 만 있음. go · maven · rubygems · nuget · composer 는 없어서
   그 생태계의 이름 사칭 점수는 0 이다.
4. **연결 안 된 것** — `cli watch --ecosystems` 옵션(감시기는 준비됨, CLI 미연결),
   `engine.version_diff` 가 sdist + wheel 다중 아티팩트를 직전 릴리스에도 적용하는 것.
5. **측정 안 한 것** — cargo · go · maven · nuget · rubygems · composer 규칙의 악성 샘플 탐지율,
   npm `compromised_lib`.
6. **README** — 수치·구조 설명 갱신 전.
7. 설계 문서 §5 의 이후 과제(결과 캐시, 패키지 배포, 큐 API 인증, 대형 휠 부분 읽기).

세션별 한계와 통합 요청 원문은 [integration-notes/](integration-notes/) 에 있다.
