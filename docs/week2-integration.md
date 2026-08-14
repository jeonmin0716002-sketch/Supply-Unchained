# 🔗 Week 2 통합 — API 파트 병합 & 실행 검증

- **작성일:** 2026-07-30
- **대상:** 전민규(PL·엔진) · 문승준(스코어링) · 김재웅(API·클라이언트)
- **배경:** 마지막 남은 파트(API 통합)를 합치고, 각 실행 경로를 **실제로 돌려서** 확인한 결과
- **브랜치:** `feat/wire-detection-layers` (base: `main` = `ffc7e54`)

---

## 0. 한 줄 요약

**세 파트가 전부 합쳐졌고, 합친 뒤 실제로 실행해보니 3개 경로가 깨져 있었습니다. 다 고쳤습니다.**

깨져 있던 것들의 공통점은 **유닛 테스트는 전부 통과하면서 실사용에서는 0% 동작**했다는 점입니다.
특히 pip 프록시는 우리 제품의 핵심 기능인데 실제 pip으로는 단 한 패키지도 설치되지 않았습니다.

| 경로 | 병합 직후 | 현재 |
|---|---|---|
| `POST /api/v1/scan` (3레이어) | ✅ 동작 | ✅ 동작 |
| 이력 API · 대시보드 | ✅ 동작 | ✅ 동작 |
| **pip 프록시 게이트** | ❌ **전 패키지 설치 불가** | ✅ 실제 pip 검증 완료 |
| **CLI (`su_scan`)** | ❌ **한국어 Windows에서 100% 크래시** | ✅ 검증 완료 |
| **Docker 이미지** | ❌ **부팅 즉시 사망** | ⚠️ import 검증만 (아래 5-1 ⑥) |
| 발표용 차단 시연 | ❌ 시연 불가 | ✅ 오프라인 동작 |

테스트 106개 통과 · ruff clean.

---

## 1. 무엇을 합쳤나

| 커밋 | 내용 |
|---|---|
| `4b72143`, `4ed9e60` | 엔진(①②) + 공용 PyPI fetcher — 민규 |
| `9f1e203` | 스코어링(③) — 승준 |
| `c824ad2` | **API 통합(FastAPI · CLI · 프록시 · 대시보드 · Docker) — 재웅** |
| `7fc2e21` | MVP 차단 3건 수정 |
| `64ef94a` | 오프라인 데모 시연 복구 + 스캔 DB 추적 해제 |

재웅 님 브랜치는 `main` 기준으로 갈라져 있어서 `common/`(공용 fetcher)과 오프라인 데모가
**아직 없던 시점의 코드**였습니다. 아래 충돌은 그래서 생긴 것이고, 누가 잘못한 게 아니라
브랜치가 오래 떠 있던 결과입니다.

---

## 2. 충돌 해소 — `api/routers/scan.py`

두 브랜치가 **정적분석 입력 경로를 각자 구현**해서 충돌했습니다.

| | 엔진 브랜치 | API 브랜치 |
|---|---|---|
| 정적분석 입력 | `common.pypi.PackageContext` → `analyze_package(req, ctx=ctx)` | `api.package_fetcher` → `analyze_path` |
| PyPI 호출 | 요청당 1회 (②③ 공유) | 레이어별 각각 |
| 레이어 실패 | CVE 실패 → 502 | 부분 실패 허용 → `layer_errors` |

**결정: 재웅 님 구조를 유지하고, 정적분석·스코어링 입력만 `PackageContext` 공유로 교체.**

`run_scan` 분리 / 부분 실패 정책 / SQLite 영속화 / `/scans` 이력 / CWE 태깅 / 프록시·대시보드·CLI·Docker는
전부 그대로 살렸습니다. 부분 실패 정책은 **"보안 도구가 장애를 숨기고 safe를 주는 게 최악"**이라는
판단이 맞다고 봐서 502 정책을 폐기했습니다.

`api/package_fetcher.py`는 삭제했습니다. 이건 재웅 님이 그 파일 docstring에 이미 예고해둔 것입니다:

> "once the engine part implements its own `analyze_package`, the router swaps
> `fetched_package_tree` + `analyze_path` for that single call and **this module retires**."

엔진의 그 절반이 이 브랜치에 있으므로 예고대로 은퇴시켰습니다. `common/pypi.py`와
아카이브 안전 추출 로직이 이중으로 존재하던 상태도 함께 해소됩니다.

**효과 (실측):** 스캔 1건당 외부 호출

```
GET     pypi.org                 1     ← 이전: 2 (스코어러 + 아카이브 수집이 각각 조회)
STREAM  files.pythonhosted.org   1
GET     api.osv.dev              6     ← CWE 태깅 (취약점당 1회, 아래 5-2 참고)
```

`run_scan(req, *, http, store)` 시그니처를 유지해서 `proxy.py`는 수정 불필요했고,
3레이어 병렬 `gather`도 유지됩니다 (`PackageContext`가 내부 락을 갖고 있어 동시 접근 안전).

---

## 3. 실행해보고 찾은 것 — MVP 차단 3건

### 3-1. pip 프록시가 실제 pip과 전혀 동작하지 않음 🔴

```
$ pip download --index-url http://localhost:8000/simple/ six==1.16.0
ERROR: Could not find a version that satisfies the requirement six==1.16.0
       (from versions: none)
```

pip `-vv` 로그가 원인을 정확히 알려줍니다:

```
Skipping link: not a file: http://localhost:8000/files?u=https%3A%2F%2F...%2Fsix-1.16.0.tar.gz
```

**원인:** pip은 링크의 **URL 경로 마지막 세그먼트**에서 파일명을 뽑아 패키지명·버전·wheel 태그를
판단합니다. 재작성이 원본 URL을 쿼리에만 담아 경로가 `/files`로 끝나서, pip이 **모든 링크를 버렸습니다.**

**수정:** 파일명을 경로에 유지.

```
- href="/files?u=<encoded>#sha256=.."
+ href="/files/six-1.16.0.tar.gz?u=<encoded>#sha256=.."
```

같이 넣은 것 두 가지:

- **파일명 일치 검사** — 경로 파일명 ≠ 업스트림 파일명이면 400. 판정 대상을 경로 파일명이
  결정하므로, 어긋남을 허용하면 *"안전한 A를 스캔받고 악성 B를 내려받는"* 게이트 우회가 성립합니다.
  (원래 코드는 파일명을 업스트림 URL에서만 뽑아 이 문제가 없었고, 경로 파일명을 도입한 이번
  수정이 만든 리스크라 함께 막았습니다.)
- **PEP 658/714 `data-core-metadata` 속성 제거** — 남기면 pip이 링크 URL **문자열 끝에**
  `.metadata`를 붙여 요청해서, 그 접미사가 우리 `u=` 쿼리 값 안으로 들어가 깨집니다(실제 pip에서 400 재현).
  속성을 떼면 pip이 아카이브를 직접 받으므로, 게이트 입장에선 오히려 **모든 다운로드가 예외 없이 스캔을 거칩니다.**
  대안(`.metadata` 요청을 별도 경로로 프록시)은 MVP 범위 밖으로 판단했습니다. **← 리뷰 포인트**

### 3-2. CLI가 한국어 Windows에서 100% 크래시 🔴

```
$ uv run python -m cli.su_scan check requests==2.31.0
UnicodeEncodeError: 'cp949' codec can't encode character '⚠'
```

**원인:** 판정 이모지 `⚠️` `✅` `⛔`를 cp949로 인코딩할 수 없어 rich 출력 시점에 사망.
`check` / `install`이 통째로 사용 불가였습니다. **팀 전원이 한국어 Windows이므로 아무도 CLI를 쓸 수 없었고,
발표 시연에서도 그대로 터졌을 상황입니다.**

**수정:** 진입부에서 stdout/stderr를 UTF-8로 reconfigure. 함께 고친 것:

- `raise_for_status()`가 `try` 블록 밖이라 `HTTPStatusError`(= `HTTPError` 서브클래스)가 친절한
  에러 처리를 우회해 raw traceback이 되던 문제
- `_VERDICT_STYLE` 직접 인덱싱 → 기본값을 두는 `_style()` 헬퍼

### 3-3. Docker 이미지가 부팅 즉시 사망 🔴

```
ModuleNotFoundError: No module named 'common'
```

`COPY` 목록에 `common/`이 없었습니다. **이건 재웅 님 잘못이 아니라 이번 머지가 만든 문제입니다** —
재웅 님 브랜치 시점에는 `common/`이 존재하지 않았습니다. `COPY common/ common/` 한 줄로 해결.

---

## 4. 그 밖의 수정

| 항목 | 내용 |
|---|---|
| `api/storage.py` | `journal_mode=WAL` + busy timeout 15s. 프록시가 살아나면서 pip 병렬 다운로드마다 스캔+쓰기가 겹칩니다 |
| `.gitignore` | `data/*.db` (+ WAL 사이드카 `-wal`/`-shm`) 추가, `data/supply_unchained.db` 추적 해제 |
| 발표 시연 | 아래 4-1 |

### 4-1. 발표용 차단 시연이 불가능했던 문제

데모용 typosquat 이름 3개(`reqeusts` · `colourama` · `python-sqlite`)는 **실제 악성 패키지였기에
PyPI에서 이미 삭제**되어 `/simple/reqeusts/`가 404입니다. 업스트림을 프록시하는 정상 경로에서는
인덱스 단계에서 죽어 **게이트까지 도달조차 못 하므로**, "pip install이 차단되는" 장면을 시연할 수 없었습니다.

`SU_OFFLINE_DEMO`에서만 그 이름들의 PEP 503 인덱스를 합성해 pip을 게이트로 보냅니다.
판정은 기존 데모 mock이 그대로 block을 냅니다.

합성이 실서비스로 새면 **없는 패키지를 있는 것처럼 광고**하게 되므로, 데모 모드 격리를 전용 테스트로
못박았습니다. 데모 판정 규칙이 두 모듈로 흩어지지 않게 `scan.py`의 데모 상수를 공개 이름으로
바꿨고(`OFFLINE_DEMO` / `DEMO_MALICIOUS` / `DEMO_VULNERABLE`), 프록시는 그 한 곳만 읽습니다.

---

## 5. 검증 결과 (전부 실측)

### 5-1. 각 경로 실행 결과

```
① API — 실제 네트워크
   POST /api/v1/scan  requests==2.31.0
   → 200 · warn · risk 20 · 취약점 6건(CWE 태깅됨) · 정적분석 9건 · layer_errors 없음

② pip 프록시 — 실제 pip
   $ pip download --index-url http://localhost:8767/simple/ six==1.16.0
   → Successfully downloaded six
   그 다운로드의 스캔 이력: scan_id=1  six==1.16.0 -> safe   (게이트를 지났다는 증거)

③ 게이트 차단 — 오프라인 데모
   $ pip install --index-url http://localhost:8770/simple/ reqeusts
   → ERROR: Could not install requirement reqeusts ... HTTP error 403
   게이트 응답: blocked_by_supply_unchained | reqeusts==1.0.0 | risk 90
     · 정적분석에서 고위험 악성 패턴 탐지
     · 메타데이터 위험도 스코어 90점 (임계 70 이상)

④ 게이트 우회 시도
   파일명 불일치            → 400
   오픈 프록시 오용         → 400

⑤ CLI — cp949 콘솔
   $ uv run python -m cli.su_scan check six==1.16.0
   → ✅ SAFE 패널 + 정적분석 표 정상 렌더

⑥ Docker — COPY 목록만 재현한 트리
   api.main import OK · /api/v1/scan 200 · /api/v1/scans 200 · 게이트 400 · /health 200
```

> ⚠️ **⑥은 `docker build` 실제 실행이 아닙니다.** Dockerfile의 `COPY` 목록과 동일한 파일만
> 모은 트리에서 import와 라우트를 확인한 것입니다(`common/` 누락이 이 방식으로 발견됐습니다).
> 검증 시점에 Docker 데몬이 꺼져 있어 `docker compose up --build`는 돌려보지 못했습니다 —
> **누군가 한 번 실제로 빌드해 주세요.** `uv sync --frozen --no-dev` 단계와 `/data` 볼륨
> 권한은 아직 아무도 실행한 적이 없습니다.

### 5-2. 확인 결과 문제가 아니었던 것

**패키지명 정규화 (`scikit_learn` vs `scikit-learn`)** — 아카이브 파일명은 `_`를 쓰고 실제
프로젝트명은 `-`를 쓰기 때문에, 게이트가 언더스코어 이름으로 조회해서 취약점을 놓칠 수 있다고
의심했습니다. **실측 결과 OSV와 PyPI 모두 이름을 정규화합니다 — 정규화 코드는 불필요합니다.**

| 조회 이름 | OSV 취약점 수 | | 조회 이름 | OSV 취약점 수 |
|---|---|---|---|---|
| `apache-airflow` 2.0.0 | 147 | | `apache_airflow` 2.0.0 | 147 |
| `django-allauth` 0.50.0 | 6 | | `django_allauth` 0.50.0 | 6 |
| `scikit-learn` 0.20.0 | 5 | | `scikit_learn` 0.20.0 | 5 |

PyPI JSON API도 언더스코어 이름에 200 + 정규화된 `info.name`을 반환합니다.

### 5-3. 테스트 — 무엇을 바꿨나

기존 `test_index_link_rewrite`는 **재작성된 문자열 모양만** 검증해서, 프록시가 완전 고장인 상태로
통과하고 있었습니다. **구현이 아니라 요구사항(pip이 받아들이는가)을 검증**하도록 바꿨습니다.

```python
filename = urlparse(href).path.rsplit("/", 1)[-1]
assert filename == "scikit_learn-1.5.0-cp312-cp312-win_amd64.whl"
assert proxy.parse_archive_filename(filename) == ("scikit_learn", "1.5.0")
```

추가한 테스트: 파일명 불일치 거부 · PEP 658 속성 제거 · 데모 인덱스 합성 · 데모 모드 격리 ·
레이어 간 `PackageContext` 공유 계약 · 오프라인 데모.

**106 passed (1 deselected: 네트워크 필요) · ruff clean**

---

## 6. 지금 실행하는 법

```bash
uv sync

# ① API + 대시보드
uv run uvicorn api.main:app
#   http://localhost:8000/dashboard   스캔 콘솔
#   http://localhost:8000/docs        Swagger

# ② CLI
uv run python -m cli.su_scan check requests==2.31.0
uv run python -m cli.su_scan install requests==2.31.0
uv run python -m cli.su_scan history

# ③ pip 프록시 (설치 시점 게이트)
pip install --index-url http://localhost:8000/simple/ <패키지>

# ④ 오프라인 데모 (회선 없이 차단 시연)
SU_OFFLINE_DEMO=1 uv run uvicorn api.main:app
pip install --index-url http://localhost:8000/simple/ reqeusts   # → 403 차단

# ⑤ Docker
docker compose up --build

# 테스트 / 린트
uv run pytest -q
uv run ruff check .
```

---

## 7. 열려 있는 안건

### 7-1. 게이트가 검사하는 아카이브 ≠ pip이 설치하는 아카이브 🟠 **회의 안건**

`common/pypi.py`의 `select_artifact()`가 **sdist를 우선 선택**해 분석하는데, pip이 실제로 받아가는 건
요청된 **wheel**입니다. 즉 **sdist는 깨끗하고 wheel에 악성 코드가 있으면 게이트를 통과합니다.**
wheel의 `.pth` 자동실행은 엔진이 이미 탐지하는 규칙인데 정작 그 wheel을 안 보고 있습니다.

*"설치되기 전에 끊어낸다"*는 제품 주장이 이 케이스에서 성립하지 않으므로 우선순위가 높습니다.
이번 수정으로 **게이트가 정확한 파일명을 알게 됐으니** 고치기 쉬워졌습니다 — `PackageContext`가
요청된 아카이브를 그대로 받도록 하면 됩니다. 엔진 파트 + 스캔 계약 변경이라 **셋이 같이 정해야 합니다.**

### 7-2. 그 밖

| 항목 | 담당 제안 | 비고 |
|---|---|---|
| CWE 태깅 N+1 (스캔당 OSV 재조회 6회) | 민규 | `engine/cve_matcher.parse_osv_response`가 raw payload를 이미 들고 있어 `cwes_from_osv()` 호출 한 줄이면 네트워크 0회 추가. `api/cwe.tag_vulnerabilities`는 그때 은퇴 |
| `README.md` 갱신 | 재웅 | 프록시·대시보드·CLI·Docker가 아직 문서에 없음 |
| CLI `install`이 전이 의존성 미검사 | 재웅 | 프록시 경로는 모든 파일이 게이트를 지나지만 CLI는 named 패키지만 스캔 |
| 게이트 fail-open 2곳 | 재웅 | 파일명 파싱 실패 시 통과(`.egg`/`.tar.xz` 미포함), `files.pythonhosted.org` 외 호스트 링크는 재작성 안 됨 |
| Docker root 실행 | 민규 | 적대적 아카이브를 풀어내는 프로세스라 `USER` 추가 권장 |
| `storage.py` 죽은 인덱스 | 재웅 | `idx_scans_time`은 `scanned_at DESC`인데 `_recent`는 `id DESC` 정렬 |

---

## 8. 리뷰 요청 (재웅 님)

재웅 님 파트 코드를 수정했으므로 아래를 봐주세요.

1. **`proxy.py` 파일명 경로 유지 + 파일명 일치 검사** — 라우트가 `/files/{filename}`으로 바뀌었습니다
2. **PEP 658 속성 제거 결정** — pip의 메타데이터 최적화를 포기하는 대신 모든 다운로드가 게이트를
   지나게 했습니다. 이 트레이드오프에 동의하는지
3. **`storage.py` WAL** — 블로커가 아니었는데 함께 넣었습니다. 원치 않으면 되돌려도 됩니다
4. **데모 인덱스 합성** — `SU_OFFLINE_DEMO` 격리가 충분한지

### 덧붙여

재웅 님 브랜치는 `engine/` · `scoring/` · `common/` 파일을 **한 개도 건드리지 않았습니다.**
정적분석의 아카이브 수집이 필요했을 때 엔진 코드를 고치는 대신 자기 레이어에 임시 구현을 두고
"엔진이 구현하면 은퇴한다"고 예고해둔 처리가 특히 좋았습니다 — 이번에 예고대로 은퇴시켰습니다.
공유 계약(`api/schemas.py`) 변경도 전부 추가만(`default_factory`)이고 `(팀 리뷰 대상)` 주석이
달려 있었습니다. 병렬 작업에서 남을 막지 않으면서 진도를 뽑는 방식이라 그대로 유지하면 좋겠습니다.
