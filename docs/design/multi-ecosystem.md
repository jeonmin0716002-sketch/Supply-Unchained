# 다중 생태계 확장 설계 — pip 전용 스캐너에서 오픈소스 공급망 탐지 제품으로

작성 2026-11-13. 통합 브랜치 `feat/multi-ecosystem`. 이 문서가 병렬 작업의 기준이다.

## 1. 목표와 범위

지금: PyPI 패키지 하나를 `name==version` 으로 받아 CVE/OSV · 정적분석 · 메타데이터
위험도로 `safe/warn/block` 을 낸다.

목표: **어떤 오픈소스 의존성이든** 같은 판정을 낸다.

| 축 | 지금 | 목표 |
|---|---|---|
| 생태계 | pip | pip · npm · cargo · go · maven · rubygems · nuget · composer |
| 입력 | 패키지 1개, requirements.txt | 프로젝트 디렉터리(모든 lockfile), SBOM(CycloneDX·SPDX) |
| 알려진 취약점 | OSV 단건 조회 | OSV 전 생태계 + 일괄 조회(querybatch) |
| 악성 탐지 | 파이썬 AST 규칙 | 생태계별 설치·로드 시점 실행 경로 규칙 |
| 개입 지점 | pip 래퍼·pip 프록시·CI | + npm 레지스트리 프록시, GitHub Action, pre-commit |
| 감시 | PyPI 피드 | 피드가 있는 모든 레지스트리 |

범위 밖(이번에는 하지 않음): 동적 분석(샌드박스 실행), 컨테이너 이미지·OS 패키지 스캔,
라이선스 검사, 소스코드 SAST. 설치·실행하지 않는다는 원칙은 그대로다.

## 2. 구조

```
api/            FastAPI — 스키마(계약), 통합 스캔, 프록시(pip·npm), 감시 큐
cli/            su-scan — check · install · guard · check-file · watch · project · sbom
common/         pypi.py(PackageContext) · archive.py(안전 추출 공통 진입점)
ecosystems/     ← 신규. 생태계 어댑터
  base.py         계약: Ecosystem · Project · Release · Artifact · Dependency
  __init__.py     레지스트리: get(id) · available()
  data/popular/   <id>.txt — 이름 사칭 비교 대상
  pip/ npm/ cargo/ go/ maven/ rubygems/ nuget/ composer/
      __init__.py   ADAPTER = <Ecosystem>
      registry.py   레지스트리 조회 → Project
      rules.py      정적분석 규칙
      manifests.py  lockfile·manifest 파서
      feed.py       신규 업로드 피드 (있는 생태계만)
engine/         파이썬 정적분석(규칙·버전 비교) · OSV 매처 · CVSS
inventory/      ← 신규. 프로젝트 디렉터리·SBOM → 의존성 목록 → 일괄 판정
scoring/        메타데이터 위험도 (Project 모델만 본다)
watcher/        신규 업로드 감시 (피드는 어댑터가 제공)
```

### 2.1 한 번의 스캔

```
ScanRequest{ecosystem,name,version}
  └ eco = ecosystems.get(ecosystem); eco.validate(name, version)
  └ PackageContext(eco, name, version)
       project   = eco.fetch_project()              # 레지스트리 1회
       artifacts = eco.select_artifacts()           # 실제 설치되는 파일을 빠뜨리지 않는다
       roots     = [eco.extract(download(a)) ...]   # 파일마다 따로 푼 루트
  ├ ① CVE     OSV query (eco.osv_ecosystem)
  ├ ② 정적    eco.analyze_tree(root) for root in roots   (+ pip 는 Bandit)
  │           └ 직전 버전 대비 새 행위 승격 (engine.version_diff, pip 부터)
  └ ③ 스코어  Project 모델 + eco.typosquat_score + eco.has_install_script
  → _decide() → ScanResponse (계약은 그대로, ecosystem 값만 늘어난다)
```

### 2.2 어댑터 계약 요약 (`ecosystems/base.py` 가 원본)

| 메서드 | 역할 | 기본 구현 |
|---|---|---|
| `validate(name, version)` | 화이트리스트 검증 | `NAME_RE`·`VERSION_RE` |
| `fetch_project(name, client)` | 메타데이터 → `Project` | 추상 |
| `select_artifacts(project, version)` | 분석할 파일 | 릴리스의 모든 파일 |
| `extract(data, artifact, dest)` | 안전 추출 | `common.archive.extract_archive` |
| `analyze_tree(tree, artifact)` | 정적분석 → `StaticFinding` | 추상 |
| `has_install_script(...)` | 설치 시 실행 코드 여부 | 메타데이터 값 |
| `popular_names()` / `typosquat_score()` | 이름 사칭 | `data/popular/<id>.txt` |
| `parse_manifest(filename, text)` | lockfile → `Dependency` | `[]` |
| `fetch_feed(client)` | 신규 업로드 | `[]` |

### 2.3 판정 원칙 (전 생태계 공통 — 파이썬 엔진 실측에서 얻은 것)

1. **설치·실행하지 않는다.** 내려받아 안전 추출 후 읽기만 한다.
2. **"못 봤다"는 "깨끗하다"가 아니다.** 정적분석을 못 했으면 `layer_errors` 에 `static:` 로
   남기고 판정은 최소 `warn`. 프록시는 기본으로 차단한다(`SU_UNSCANNED_POLICY`).
3. **스캔한 파일 = 설치되는 파일.** 프록시는 요청받은 바로 그 파일을 스캔한다.
4. **HIGH 는 공급망 공격 특유의 조합에만.** "위험 함수가 있다"는 MEDIUM(정황).
   HIGH = 설치·로드 시점에 자동 실행 + (네트워크 전송 | 수상한 명령 | 디코딩→실행 | 유출 채널).
5. **규칙은 측정과 함께 넣는다.** 탐지율(악성 데이터셋)과 오탐률(인기 상위 패키지)을 같이 잰다.
   튜닝에 쓴 샘플로 잰 수치는 참고용이고, 보지 않은 샘플 수치가 실제 값이다.

### 2.4 생태계별 "설치·로드 시점 실행 경로" (규칙이 봐야 할 곳)

| 생태계 | 자동 실행 경로 | OSV 이름 | 피드 |
|---|---|---|---|
| pip | `setup.py`, `.pth`, import 시 모듈 최상단 | PyPI | RSS |
| npm | `package.json` 의 `preinstall`·`install`·`postinstall`·`prepare`, `binding.gyp`, 진입점(`main`) 최상단 | npm | 레지스트리 changes |
| cargo | `build.rs`, proc-macro 크레이트 | crates.io | crates.io API(최근) |
| go | 설치 스크립트 없음 — `init()`, `//go:generate`(직접 실행 시), cgo 지시문 | Go | index.golang.org |
| maven | 설치 스크립트 없음 — 빌드 플러그인·annotation processor(`META-INF/services`), 정적 초기화 | Maven | 없음(검색 API 최신순) |
| rubygems | `extconf.rb`(네이티브 확장 빌드), gemspec `extensions`, `require` 시 최상단 | RubyGems | API(latest·just_updated) |
| nuget | `tools/install.ps1`·`init.ps1`, `build/*.targets`·`.props`(MSBuild 실행) | NuGet | 카탈로그 |
| composer | `composer.json` `scripts`(루트만 실행됨)·플러그인(`type: composer-plugin`), autoload `files` | Packagist | API(최근 업데이트) |

## 3. 작업 분배 — 세션별 소유 파일

병렬로 돌기 때문에 **두 세션이 같은 파일을 고치지 않는다.** 자기 소유가 아닌 파일의 변경이
필요하면 고치지 말고 `docs/design/integration-notes/<세션>.md` 에 적는다(통합 때 반영).
연결 지점은 "있으면 쓰고 없으면 건너뛰는" 방식(guarded import)이라 순서와 무관하게 병합된다.

| 세션 | 모델 | 소유 | 하는 일 |
|---|---|---|---|
| core-pipeline | Opus | `common/*`, `api/schemas.py`, `api/routers/scan.py`·`proxy.py`, `api/main.py`, `api/cwe.py`, `engine/cve_matcher.py`, `scoring/*`, `ecosystems/pip/__init__.py`·`registry.py`·`feed.py`, `cli/su_scan.py`, `tests/test_api.py`·`test_common_pypi.py`·`test_security.py`·`test_scoring.py`·`test_pipeline_multi.py` | 파이프라인을 어댑터 기반으로 일반화, 실제 설치 파일 스캔(1), 스캔 불가 차단(2) |
| py-engine | Opus | `engine/rules/*`, `engine/static_analyzer.py`, `engine/version_diff.py`, `engine/verdict.py`, `engine/README.md`, `tests/test_engine.py`, `tools/eval_malware_dataset.py`·`eval_benign_top.py`, `samples/` 파이썬 샘플 | 직전 버전 대비 새 행위(4), import 시점 실행 범위 확장(5), 실측 |
| eco-npm | Opus | `ecosystems/npm/*`, `api/routers/npm_proxy.py`, `tests/test_eco_npm.py`, `tools/eval_npm.py`, `samples/npm_*` | npm 어댑터 전체 + 레지스트리 프록시 + 실측 |
| eco-cargo-go | Sonnet | `ecosystems/cargo/*`, `ecosystems/go/*`, `tests/test_eco_cargo.py`·`test_eco_go.py` | 어댑터 2종 |
| eco-ruby-php | Sonnet | `ecosystems/rubygems/*`, `ecosystems/composer/*`, 해당 테스트 | 어댑터 2종 |
| eco-jvm-dotnet | Sonnet | `ecosystems/maven/*`, `ecosystems/nuget/*`, 해당 테스트 | 어댑터 2종 |
| inventory | Sonnet | `inventory/*`, `ecosystems/pip/manifests.py`, `cli/project_cmd.py`, `tests/test_inventory.py` | 프로젝트·SBOM 스캔, OSV 일괄 조회, CycloneDX 출력 |
| watch-dash | Sonnet | `watcher/*`, `api/storage.py`, `api/routers/watch.py`, `dashboard/index.html`, `tests/test_watcher.py`, `tools/eval_new_uploads.py`, `docs/eval/watch-*.md` | 감시기·저장소·대시보드 다중 생태계화, 신규 업로드 오탐률 재측정(3) |
| popular-lists | Haiku | `tools/build_popular_lists.py`, `ecosystems/data/popular/*.txt` | 생태계별 인기 패키지 목록 수집 |
| ci-chores | Haiku | `.github/workflows/ci.yml`, `action.yml`, `.pre-commit-hooks.yaml`, `docs/usage/*`, `.env.example` | CI 범위 확장, GitHub Action·pre-commit 훅, 사용 문서 |

`README.md`, `pyproject.toml`, `uv.lock` 은 아무 세션도 고치지 않는다(통합 때 한 번에).
새 런타임 의존성은 넣지 않는다 — 표준 라이브러리와 이미 있는 httpx·pydantic·typer·rich 로 한다.

### 3.1 guarded 연결 지점 (core-pipeline 이 만든다)

```python
# api/routers/scan.py — 있으면 쓴다
try: from engine.version_diff import escalate_new_behaviors
except ImportError: escalate_new_behaviors = None
# api/main.py
try: from api.routers import npm_proxy; app.include_router(npm_proxy.router)
except ImportError: pass
# cli/su_scan.py
try: from cli.project_cmd import register; register(app)
except ImportError: pass
```

약속된 시그니처:

* `engine.version_diff.escalate_new_behaviors(ctx, findings, *, errors) -> list[StaticFinding]` (async).
  `ctx` 는 `common.pypi.PackageContext`. 추가로 붙일 finding 만 돌려준다.
* `api.routers.npm_proxy.router` — FastAPI `APIRouter`, 경로 접두사 `/npm`.
* `cli.project_cmd.register(app: typer.Typer) -> None` — `project`·`sbom` 명령을 붙인다.
* `layer_errors` 접두사: `cve:` · `static:` · `bandit:` · `scoring:`. 패키지가 레지스트리에 없으면
  `static: <name> is not on <registry_label> (never existed, or removed)`.

## 4. 통합 순서

1. 각 세션이 자기 브랜치(워크트리)에 커밋한다. push 하지 않는다.
2. 통합 브랜치에 core-pipeline → py-engine → 어댑터들 → inventory → watch-dash → 나머지 순으로 병합.
3. `integration-notes/` 의 요청 반영, `uv run ruff check . && uv run pytest -q`.
4. 실측 재실행(파이썬 탐지율·오탐률, npm 탐지율·오탐률), README 수치·설명 갱신.

## 5. 이후 과제 (이번 범위 밖)

* 결과 캐시(파일 sha256 기준), PyPI·npm 패키지로 배포(`pipx install`), 감시 큐 API 인증.
* 대형 휠의 원격 zip 부분 읽기(HTTP Range)로 수백 MB 다운로드 없이 코드 파일만 검사.
* JS·Ruby·PHP 의 실제 파서 기반 분석(지금은 토큰·정규식 수준), 전이 의존성 해석.
