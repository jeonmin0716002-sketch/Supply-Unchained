# 신규 업로드 운영 오탐률 재측정 (watch-dash, 2026-11-13)

README 의 오탐률 0.7% 는 다운로드 상위 300개(성숙한 패키지)로 잰 값이다. 감시기가 실제로 본
신규 릴리스로 현재 엔진(브랜치 시점의 커스텀 정적 규칙)을 다시 돌려 확인했다.
원자료: [`watch-new-uploads.json`](watch-new-uploads.json). 재현: `tools/eval_new_uploads.py`.

- 입력: 감시기 DB 사본(2026-10-16~18, 스캔 16,286건, 본 릴리스 16,181개). 원본은 읽기 전용으로만 다뤘다.
- 설치·실행 없음 — 내려받아 안전 추출 후 정적분석만. 표본 시드 20261113.

## 1. 수치

| 집합 | 릴리스 | 분석됨 | 삭제됨 | 오류 | 지금도 block | 비율 (Wilson 95%) |
|---|---|---|---|---|---|---|
| 예전에 block 이던 것 | 74 | 71 | 2 | 1 | 50 (27개 패키지) | 70.4% (59.0–79.8%) |
| 무작위 표본 | 500 | 486 | 8 | 6 | 3 | **0.62% (0.21–1.8%)** |

- 규칙별(예전 block 재스캔): `custom-install-time-exec` 34, `custom-pth` 13, `custom-obfuscated-payload` 7, `custom-install-hook` 1.
- 표본의 block 3건(hpcp 9.76, gammonview-helper 0.9.0, chromedriver-binary 158.0.8108.0.0)은 모두 아래 triage 에서 오탐으로 봤다. **신규 업로드의 오탐률은 약 0.6%로 README 값과 비슷하다.** 문제는 비율이 아니라 큐의 정밀도다 —
  악성 0건 확인 / 오탐 33건 / 미검토 12건이라는 실제 큐는 같은 프로젝트가 버전마다 반복해 올라오는 것이 만든다
  (dagz 7개 릴리스, ultralytics 6개, hpcp 5개 …).
- 엔진 수정 효과: 예전 block 74건 중 21건은 지금은 block 이 아니다(오탐 수정 반영).
- 표본의 `삭제됨` 8건 중 6건이 OpenSSF/OSV 와 맞는지 확인 — 아래 §2.2.
- **못 본 것**: 오류 6건은 크기·멤버 한도(30MB, 5000 멤버) 초과로 정적분석을 못 한 것이다 (표본의 1.2%). 설계 원칙 2에 따라 "깨끗함"이 아니라 "못 봄"이다.
- 한계: 표본은 16일 중 3일치 업로드다. 신뢰구간은 표본 크기만 반영하고 시간 편향은 포함하지 않는다.
  "현재 엔진"은 이 브랜치 시점이라 병렬 진행 중인 py-engine 수정은 들어 있지 않다.

## 2. Triage

판정 근거는 정적분석 finding 의 위치를 메모리·임시 디렉터리에서 읽은 것이다(실행하지 않음).
OSV 는 `querybatch` 로 `MAL-` 여부를 조회했다.

### 2.1 지금도 block 인 27개 패키지 — 악성 가능성 0건

| 패키지 (릴리스 수) | 규칙 | 코드 (파일:줄) | 판정 | 근거 |
|---|---|---|---|---|
| agentwire-dev (1) | install-time-exec | agentwire/mcp_voice.py:32 | 오탐 | 설정된 TTS URL 의 `/capabilities` 조회, try/except fail-soft, 함수 안 |
| ai-edge-litert-sdk-{google-tensor,intel,mediatek,qualcomm,samsung}-nightly (9) | install-time-exec | setup.py:70–302 `urlretrieve` | 오탐 | 벤더 SDK 를 설치 중 내려받는 알려진 방식(Google LiteRT 나이틀리). 받은 파일을 실행하지 않음 |
| chatsorter-local (1) | install-time-exec | api_local.py:221 `requests.post` | 오탐(불명확 약간) | 라이선스 키+버전만 보내는 검증 함수(주석에 명시), 함수 안 |
| chromedriver-binary (3) | install-time-exec | setup.py:47, utils.py:86 `urlopen` | 오탐 | 설치 시 chromedriver 를 내려받는 것이 패키지의 목적(공개 프로젝트) |
| dagz (7) | pth | `zzzz_dagz_bootstrap.pth:3` | 오탐 | 자기 패키지의 `dagz.sensor.bootstrap` 만 import. 인라인 exec·URL·인코딩 없음 |
| doeff-hy (1) / quantark (1) / nvidia-cutlass-dsl (1) / triton-utlx-rocm (1) | pth | 각 `.pth` | 오탐 | 같은 배포물의 자기 모듈을 import 하는 한 줄 |
| gammonview-helper (1) | pth | `_gvhelper_startup.pth:1` | 불명확 | `.pth` 가 `_gvhelper_startup` 을 import — 그 모듈 내용은 이번에 읽지 않았다. 형태는 위 pth 오탐과 같음 |
| fiberbrowser (1) | install-time-exec | natural_language_commands.py:183 | 오탐 | 로컬 LLM 엔드포인트 도달 여부 확인, 함수 안, 예외 처리 |
| haddock3 (1) | install-time-exec + install-hook | setup.py:155, :297 | 오탐 | 재시도하는 데이터 파일 다운로드를 `cmdclass` 로 훅. 과학 소프트웨어 |
| hpcp (5) / statblk (1) / statbtrfs (1) | obfuscated-payload | hpcp.py:187, statblk.py:177 | 오탐(불명확 약간) | 같은 저자의 라이브러리(`multiCMD`)를 lzma+ascii85 한 덩어리로 넣고 모듈 네임스페이스에 exec. 세 패키지의 blob 이 동일. 악성 시그니처와 모양은 같다 |
| meerschaum (2) | install-time-exec | utils/typing.py:34 | 오탐 | 구버전 Python 용 `typing_extensions` 를 GitHub raw 에서 받는 대체 경로 |
| radboy (2) | install-time-exec | radboy/x.py:8 `requests.get` | 오탐 | 패키지에 섞여 들어간 스크래핑 연습 스크립트(Walmart 조회). 부주의일 뿐 |
| rubka (1) | install-time-exec | rubka/__init__.py:68 | 오탐 | PyPI JSON 으로 최신 버전 확인(업데이트 알림) |
| sigmaflow (2) | install-time-exec | sigmaflow/version.py:7 | 오탐 | 자기 PyPI RSS 로 최신 버전 확인 |
| sr-harness (1) | install-time-exec | …/sr_scientist.py:133 `create_connection` | 오탐 | 0.25초 포트 열림 확인(벤더링된 벤치마크 코드) |
| trading-matrix-dashboard (2) | install-time-exec | trading_matrix/main.py:29/52 | 오탐 | 사용자가 넣은 텔레그램 토큰으로 메시지 전송(함수 안). URL 이 `telegram.org{token}` 으로 잘못 조립돼 있어 동작도 안 함 |
| ultralytics / ultralytics-opencv-headless (6) | install-time-exec | ultralytics/utils/__init__.py:880 `getaddrinfo` | 오탐 | 온라인 여부 확인(공식 프로젝트). 해당 줄의 앞뒤 문맥은 이번에 읽지 못했다 |

### 2.2 삭제됨 — 이것이 악성 쪽 증거

| 릴리스 | OSV | 비고 |
|---|---|---|
| leakdeep 2.6.6 | **MAL-2026-17921** | 큐에 `삭제됨`으로 올라와 있던 것 — 감시기가 놓치지 않았다 |
| ukraine69 1.2.0, 1.2.8 | **MAL-2026-17919** | 표본에서 발견 |
| sitecard 0.1.7 | **MAL-2026-18242** | 표본에서 발견 |
| reqeusts 1.0.0 | 없음 | 이름 사칭형. 업로드 직후 삭제(PyPI 차단일 가능성) — 불명확 |
| vishap-analyzer 6.4.0 | 없음 | 불명확 |
| piot-fixture-zzz-python-{maturin,no-rust,no-rust-fp,sdist} | 없음 | 이름상 PyPI 테스트 픽스처 — 오탐 아님·악성 아님 |

감시기가 본 악성(OSV 대조 3개 패키지)은 전부 **분석 전에 PyPI 가 지운 것**이었고, 엔진이 분석해서 block 한 27개에서는 확인된 악성이 없다.
"삭제 감지"(30분 유예)가 사실상 이 감시기의 유일한 확정 탐지 경로다 — 이 기능은 유지해야 한다.

## 3. 오탐 패턴과 엔진 규칙 변경안 (py-engine 인계, 우선순위 순)

### P1. `custom-install-time-exec` — 전체 block 의 68%, 대부분 "버전 확인·벤더 다운로드·헬스체크"

문제: 네트워크 호출이 "있다"만으로 HIGH 가 된다. 위 표의 17개 패키지가 그렇다.
- 함수 안에서 `try/except` 로 감싸 실패를 삼키는 GET 은 패키지가 동작하려는 기능이다
  (agentwire-dev mcp_voice.py:32, fiberbrowser :183, sr-harness :133).
- 목적지가 **레지스트리·소스 호스트**(`pypi.org`, `raw.githubusercontent.com`, `localhost`/인자로 받은 host)이면 정황(MEDIUM)으로 낮춘다
  (rubka __init__.py:68, sigmaflow version.py:7, meerschaum typing.py:34).
- HIGH 는 "요청 결과가 exec/eval/파일 쓰기+실행으로 이어짐" 또는 "환경변수·파일·호스트정보를 POST/전송"일 때만.
  이번 표본에서 이 조합을 가진 것은 0건이었다.
- 상세 문구는 `import 시점에 실행되는` 이라고 하지만 확인한 6건 모두 호출이 함수 안이다.
  규칙이 "모듈 최상단에서 도달 가능한 호출"을 어떻게 판정하는지(호출 그래프 도달성) 점검이 필요하다 — 이번에 코드로 확인하지 못했다.
- setup.py 의 `urlretrieve`(ai-edge-litert 5개 계열 9릴리스, chromedriver-binary, haddock3)는 "내려받은 파일을 같은 setup 안에서 실행하는가"로 가른다. 받기만 하면 MEDIUM.

### P2. `custom-pth` — 13건, 전부 "자기 패키지 모듈 import 한 줄"

문제: `.pth` 의 `import x` 라인은 site.py 가 실행하지만, x 가 **같은 배포물이 설치하는 모듈**이면 의도된 시작 훅이다
(dagz, doeff-hy, quantark, nvidia-cutlass-dsl, triton-utlx-rocm).
- HIGH 유지: 인라인 코드(`;` 뒤에 `exec`/`eval`/`__import__`/`subprocess`/`base64`/URL), 같은 배포물에 없는 모듈을 import, 이름이 정상 패키지와 무관.
- 낮춤(MEDIUM): `import <이 배포물의 최상위 모듈>` 한 줄만 있는 경우. 그 모듈의 내용은 별도 규칙(import 시점 실행)이 이미 본다.
- 이름이 `zzzz_` 로 시작하는 것(dagz)은 로딩 순서를 늦추려는 일반 관행이다 — 그 자체는 신호가 아니다.

### P3. `custom-obfuscated-payload` — 7건, 한 저자의 단일 파일 vendoring

hpcp·statblk·statbtrfs 가 동일한 `exec(lzma.decompress(base64.a85decode(...)), multiCMD.__dict__)` 를 쓴다(같은 blob).
- 디코딩된 소스에 네트워크·subprocess·os.system·ctypes 가 있는지 **디코딩해서 한 번 더 분석**하면 갈린다(실행 없이 `lzma`+`a85` 해독만).
  해독이 안전하게 되고 위험 호출이 없으면 MEDIUM, 있으면 HIGH.
- 네임스페이스가 `모듈.__dict__` 인 exec 는 `globals()` 보다 낮은 위험이다 — 보조 신호.

### P4. `custom-install-hook` — 1건 (haddock3)

`cmdclass` 로 `install`/`develop` 를 재정의하는 것만으로는 HIGH 가 아니다 — 재정의 본문이 네트워크+실행/쓰기인지로 판단(P1 과 같은 기준).

### P5. 규칙이 아니라 감시기 쪽

- 같은 프로젝트의 연속 릴리스(nightly) 중복은 이미 `signature` 로 줄였지만, DB 에는 그 이전 기록이 남아 있다. 검토 UI 에서 같은 패키지는 묶어 한 줄로 보여주는 편이 좋다(대시보드 후속 과제).
- 큰 아카이브(30MB 초과, 멤버 5000 초과)는 현재 오류로 끝난다. 큐 기준에 "못 봄" 항목을 별도로 세는 것이 안전하다(설계 원칙 2).

## 4. 하지 않은 것 / 확인하지 못한 것

- gammonview-helper 의 `_gvhelper_startup` 모듈 내용, ultralytics 줄 880 앞뒤, jdaviz(조회 오류)는 읽지 못했다.
- 정답 라벨은 사람이 단 `false_positive` 33건과 이번 triage 뿐이다. "악성 0건"은 이번 표본 안에서만 참이다.
- 엔진 규칙은 고치지 않았다(py-engine 소유). 위 변경안을 적용한 뒤 `tools/eval_new_uploads.py` 를 같은 시드로 다시 돌려 74건·표본 500건이 어떻게 바뀌는지 보면 된다. 동시에 악성 데이터셋 탐지율(`tools/eval_malware_dataset.py`)이 떨어지지 않는지 함께 재야 한다.
