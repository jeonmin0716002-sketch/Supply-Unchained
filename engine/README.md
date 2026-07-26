# engine — 보안 코어 엔진 (탐지 레이어 ① ②)

패키지의 **정황**이 아니라 **실체**를 보는 모듈. 두 레이어를 담당합니다.

| 레이어 | 무엇을 보나 | 성격 |
|---|---|---|
| ① CVE/OSV 매칭 | 이 버전에 **이미 알려진** 취약점이 있는가 | 확정적 |
| ② 정적분석 | 코드 자체에 **악성 패턴**이 있는가 | 휴리스틱 |

레이어 ③(메타데이터 위험도)은 `scoring/` 담당입니다.

> ①은 "누가 이미 신고한 것"만 잡고, ②는 "아무도 신고 안 했지만 수상한 것"을 잡습니다.
> 신종 악성 패키지는 CVE가 없으므로 ②가 없으면 구조적으로 못 잡습니다.

---

## 파일 구조

| 파일 | 역할 |
|---|---|
| `cve_matcher.py` | OSV.dev 조회 → `Vulnerability[]` (**네트워크 I/O 전담**) |
| `static_analyzer.py` | 패키지 트리 순회 + AST 파싱 → `StaticFinding[]` (**진입점**) |
| `rules/base.py` | 룰 인터페이스 (`FileRule` / `AstRule`) |
| `rules/install_hooks.py` | `.pth` 자동실행 · `setup.py` cmdclass 훅 |
| `rules/code_patterns.py` | 위험 함수 호출 · 난독화 페이로드 |
| `rules/__init__.py` | 룰 레지스트리 (활성 룰 목록) |
| `verdict.py` | 커스텀 룰 CWE 카탈로그 |

**설계 원칙:** 네트워크 I/O는 `cve_matcher.query_osv` 한 곳에만 있습니다.
파싱·판정 로직은 전부 순수 함수라 네트워크 없이 단위 테스트가 됩니다
(실제로 28개 테스트 중 27개가 오프라인).

모든 결과는 `api/schemas.py`의 `Vulnerability` / `StaticFinding`을 **그대로** 반환합니다.
엔진 전용 중간 타입을 두지 않아서 API가 변환할 게 없습니다.

---

## ① CVE/OSV 매칭 — `cve_matcher.py`

### 왜 OSV.dev 하나만?

NVD도 후보였지만 초기엔 OSV만 씁니다.

- OSV가 이미 **CVE · GHSA · PyPA advisory를 통합 제공** — 중복 조회 불필요
- **인증키 불필요**, rate limit 여유 (NVD는 키 없으면 30초당 5회)
- 버전 범위를 **정확한 버전 단위로 질의** 가능 — "2.30.0이 영향받나"를 서버가 판정

`VulnSource` enum에 `NVD`가 이미 있으니, 나중에 보강할 때 스키마 변경 없이 붙습니다.

### 요청

```python
POST https://api.osv.dev/v1/query
{ "version": "2.30.0", "package": { "name": "requests", "ecosystem": "PyPI" } }
```

`Ecosystem.PIP` → `"PyPI"` 로 변환합니다. 우리 enum은 설치도구 이름(`pip`),
OSV는 인덱스 이름(`PyPI`)을 쓰기 때문입니다.

### 응답 매핑에서 신경 쓴 것

**1. severity — GitHub은 `MODERATE`, 우리 스키마는 `medium`**

`database_specific.severity`의 `LOW/MODERATE/HIGH/CRITICAL`을 매핑합니다.
라벨 없이 **CVSS 벡터만** 오는 경우가 있는데, 벡터에서 실제 base score를 계산하려면
CVSS 구현체가 필요합니다. 지금은 `medium`으로 폴백하고 코드에 TODO를 남겼습니다.
(과대·과소평가 중 어느 쪽도 하지 않는 중립값)

**2. `fixed_version` — 커밋 해시를 버전으로 내보내면 안 됨**

OSV는 수정 지점을 range *event*로 표현하는데, range 타입이 `GIT`이면
`fixed` 값이 **커밋 해시**입니다. 실제로 `PYSEC-2023-74`가 이렇게 나옵니다:

```
fixed = 74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5   ← pip install 불가
```

사용자에게 "이 해시로 업그레이드하세요"라고 할 수는 없으므로
`ECOSYSTEM` / `SEMVER` range만 읽고 `GIT`은 버립니다 (`fixed_version=None`).

**3. 이름 정규화 — 한 advisory가 여러 패키지를 덮음**

advisory 하나가 여러 프로젝트를 커버할 수 있어서, `affected[]`를 우리가 물어본
패키지로 다시 필터링합니다. 이때 PEP 503 정규화를 적용합니다
(`Foo.Bar_baz` == `foo-bar-baz`). OSV가 `Requests`처럼 대문자로 돌려주는 경우가 있어
단순 문자열 비교로는 `fixed_version`을 놓칩니다.

### 에러 처리

네트워크 실패·5xx·깨진 JSON은 전부 `CveLookupError`로 통일합니다.
API는 이걸 받아 **502**로 내보내면 됩니다 (README의 에러 스키마와 대응).
빈 결과(취약점 없음)와 조회 실패는 명확히 구분됩니다 — 전자는 `[]`, 후자는 예외.

---

## ② 정적분석 — `static_analyzer.py` + `rules/`

### 진입점

```python
analyze_path(root)   # 압축 해제된 패키지 트리 → StaticFinding[] (심각도 높은 순)
```

- `.py .pth .toml .cfg .txt .sh .bat .ps1`만 읽습니다 (나머지는 바이너리·노이즈)
- 2MB 초과 파일, `__pycache__` / `.git` / `node_modules` 등은 스킵
- Python 파싱 실패는 **무시**합니다 — 오래된 sdist에 Python 2 코드가 남아있는 건 흔하고,
  파싱 안 된다는 사실 자체는 증거가 아닙니다
- 결과는 심각도 내림차순 정렬 → API가 앞에서부터 잘라 `verdict_reasons`로 쓰면 됩니다

### 룰 추가하는 법

룰은 그냥 함수입니다. 두 종류뿐입니다.

```python
FileRule = (ctx)       -> findings   # 모든 파일 (.pth 같은 비-Python 포함)
AstRule  = (ctx, tree) -> findings   # 파싱 성공한 Python 모듈만
```

`rules/`에 함수를 쓰고 `rules/__init__.py`의 `FILE_RULES` / `AST_RULES`에 추가하면 끝입니다.
자동 탐색(auto-discovery)을 일부러 안 넣었습니다 — **지금 켜져 있는 룰이 뭔지 한 파일에서
읽히는 게** 보안 도구에선 더 중요합니다.

### 현재 룰

| 룰 ID | 탐지 대상 | CWE | 심각도 |
|---|---|---|:---:|
| `custom-pth` | `.pth` 파일의 인터프리터 시작 시 자동 실행 | CWE-94 | high |
| `custom-install-hook` | `setup(cmdclass={...})` 설치 명령 오버라이드 | CWE-94 | medium |
| `custom-dangerous-call` | `eval`/`exec`/`os.system`/`shell=True` | CWE-78/95 | high |
| `custom-dangerous-call` | `pickle.loads`/`marshal.loads` | CWE-502 | medium |
| `custom-obfuscated-payload` | 디코딩 결과 → 실행 싱크 | CWE-506 | high |
| `custom-obfuscated-payload` | 200자 이상 인코딩 블롭 리터럴 | CWE-506 | medium |

### `custom-pth` 가 이 프로젝트의 핵심 차별점

`.pth` 파일은 `site.py`가 **`import`로 시작하는 줄을 인터프리터 시작 때마다 실행**합니다.
패키지를 import할 필요조차 없고, 한 번 깔리면 그 머신의 **모든 이후 Python 프로세스**에서
실행됩니다.

그런데:

| 도구 | `.pth` 탐지 |
|---|---|
| pip-audit / safety | ❌ CVE만 봄 |
| **Bandit** | ❌ **Python 소스가 아니라 파서 대상 자체가 아님** |
| Supply-Unchained | ✅ `custom-pth` |

Bandit을 아무리 잘 붙여도 이 경로는 안 잡힙니다. 그래서 커스텀 룰이 필요합니다.

### 오탐을 막으려고 일부러 좁힌 것들

보안 도구는 오탐 몇 번이면 아무도 안 씁니다. 다음은 **의도적으로 안 잡습니다:**

| 안 잡는 것 | 이유 |
|---|---|
| `.pth`의 일반 경로 엔트리 | `site.py`의 실제 트리거는 `import ` / `import\t`로 **시작**하는 줄뿐 |
| `cmdclass={'build_ext': ...}` | 컴파일 확장 있는 정상 패키지가 광범위하게 씀 |
| `subprocess.run([...])` (shell 없음) | 리스트 인자 + shell=False는 셸 인젝션 경로가 아님 |
| 단독 `base64.b64decode(...)` | 아이콘·인증서 디코딩 등 정상 용도가 대부분 |

마지막 항목이 `custom-obfuscated-payload`의 설계 이유입니다.
Bandit은 `exec()` 하나, `b64decode()` 하나를 **서로 무관한 저심각도 2건**으로 봅니다.
하지만 `exec(zlib.decompress(base64.b64decode(P)))` 는 그 자체로 malware 시그니처입니다.
그래서 **디코더 출력이 실행 싱크로 흘러들어갈 때만** high로 올립니다
(중첩 체인도 추적합니다).

---

## CWE 태깅 역할 경계 (week-0 합의)

| 대상 | 담당 |
|---|---|
| OSV/CVE advisory의 CWE, Bandit B코드의 CWE | **API 파트** (파싱) |
| 이 엔진 커스텀 룰의 CWE | **엔진 파트** (여기) |

`verdict.py`는 CWE를 *부여*하지 않습니다. `custom-dangerous-call` 하나만 해도
싱크에 따라 CWE-78/95/502로 갈리기 때문에, 태그는 탐지 시점에 정해집니다.
대신 **각 룰이 낼 수 있는 CWE 목록을 선언**해두고, 테스트가 이를 검증합니다.
룰이 검토 안 된 CWE를 내보내기 시작하면 **발표장이 아니라 테스트에서** 터집니다.

> `verdict.py`라는 이름이지만 **종합 판정(safe/warn/block)은 아직 여기 없습니다.**
> 현재 `api/routers/scan.py::_decide`에 있고, 엔진으로 옮기는 건 README에
> "검토"로만 적혀 있어 팀 합의 전입니다. 그래서 일부러 안 옮겼습니다.

---

## 실행 / 테스트

```bash
uv sync

# 오프라인 테스트 (기본)
uv run pytest

# 실제 OSV.dev를 때리는 통합 테스트 (opt-in)
uv run pytest -m live

uv run ruff check .
```

직접 돌려보기:

```python
import asyncio
from api.schemas import ScanRequest
from engine import match_package, analyze_path

asyncio.run(match_package(ScanRequest(name="requests", version="2.30.0")))
analyze_path("samples")
```

검증용 악성 패턴 샘플은 `samples/` 참고 (전부 무해한 픽스처).

---

## ⚠️ 알려진 한계 · 다음 작업

**아직 안 된 것**

- **`analyze_package()` 미구현** — PyPI에서 sdist/wheel을 받아 압축 해제하는 단계가 없습니다.
  `analyze_path()`(핵심 로직)는 완성됐고, 다운로드만 붙이면 됩니다.
  주의: 아카이브 엔트리에 `..`나 절대경로가 들어올 수 있어 **zip-slip 방어**가 필요합니다.
  (악성 패키지를 다루는 도구가 악성 패키지에 당하면 안 됨)
- **Bandit 미연동** — 의존성은 등록했습니다. `bandit.core.manager.BanditManager`로
  같은 트리를 라이브러리 호출하면 되고, B코드 CWE 매핑은 위 경계상 API 파트 몫입니다.
- **API 라우터 미배선** — `api/routers/scan.py`의 `_mock_cve_layer`/`_mock_static_layer`가
  아직 mock입니다. 같은 파일을 `feat/scoring-rule-based`(승준)가 수정 중이라
  **머지 충돌을 피하려고 일부러 미뤘습니다.** 그 브랜치 머지 후 ①③ 한 번에 배선합니다.

**정확도 한계**

- **CVSS 벡터 미파싱** — 위 ①-1 참고. `cvss` 라이브러리 도입으로 해결 가능.
- **난독화는 정적분석의 근본 한계** — 지연 실행, 문자열 분할 조립,
  `getattr(__builtins__, 'e'+'val')` 같은 우회는 AST로 못 잡습니다.
  이 영역은 동적분석(샌드박스) 담당이고 MVP 스코프 밖입니다.
- **`_matches`의 tail 매칭** — `from os import system` 형태를 잡으려고
  이름 끝부분도 매칭합니다. 부작용으로 무관한 `obj.load(...)`가
  `pickle.load`로 걸릴 수 있습니다. 심각도가 medium이라 단독으로 block이 되진 않지만,
  import 추적 기반으로 정밀화하는 게 다음 개선점입니다.
