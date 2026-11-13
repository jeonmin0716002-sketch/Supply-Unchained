# py-engine 실측 — import 시점 범위 확장 · 프로세스 실행 규칙 · 직전 릴리스 비교

측정일 2026-11-13, 브랜치 `claude/py-engine-8c17eb`. 모든 수치는 패키지를 **설치·실행하지 않고**
정적분석만 한 결과다. 신뢰구간은 Wilson 95%.

## 1. 요약 (전 → 후)

| 지표 | 데이터 | 전 (68b19b0) | 후 (ea067a8 + a4f4d1e) |
|---|---|---|---|
| **차단 탐지율 — 최종(처음 보는 세트)** | DataDog `malicious_intent` 300개, seed 99 (앞 두 세트 600개 제외) | 80.7% (242/300, 75.8–84.7) | **81.0%** (243/300, 76.2–85.0) |
| 차단 탐지율 — held-out | seed 7, 300개 (이전 세션이 규칙을 보탠 세트라 참고용) | 86.0% (258/300) | 86.0% (258/300) |
| 차단 탐지율 — 튜닝 | seed 42, 300개 (이번에 놓친 것을 본 세트 — 참고용) | 79.7% (239/300) | 80.3% (241/300) |
| **탈취 패키지 — 끼워 넣은 코드로 잡음** | `compromised_lib` 전체 29개 버전, 직전 정상 릴리스와 비교 가능 28개 | 62% (18/29, 44–77) ※ | **85.7%** (24/28, 68.5–94.3) |
| 탈취 패키지 — 차단(직전 비교 승격 포함) | 같은 29개 | 69% (20/29, 51–83) | **93.1%** (27/29, 78.0–98.1) |
| 직전 정상 릴리스 16개 중 HIGH | 탈취 패키지들의 직전 정상 버전 | 1/16 (ultralytics) ※※ | 1/16 (ultralytics) |
| **정상 상위 300 오탐(차단)** | PyPI 다운로드 상위 300개 최신 버전 | 0.7% (2/291, 0.2–2.5) | **0.7%** (2/291, 0.2–2.5) |
| 정상 상위 300 — 직전 비교로 새로 차단 | (최신, 직전) 쌍 291개 | — | **0** (0/291, 0–1.3) |

※ 기준의 18/29 는 README 의 수동 판정(ultralytics 8.3.41·42 제외)이다. 이번에는 평가 도구가 직전 정상
릴리스를 받아 자동으로 판정한다(`attributable`). 같은 판정을 기준 엔진에 적용해도 18 이다.
※※ ultralytics 8.3.40·8.3.44 는 import 시 인터넷 연결 확인(`socket.create_connection`)으로 원래 걸린다 —
README 에 기록된 기존 오탐이다. 두 버전은 같은 패키지라 1개로 센다.

명령 (README 의 기존 명령 그대로; 탈취 평가는 직전 비교가 기본으로 켜진다):

```bash
uv run python tools/eval_malware_dataset.py --n 300 --seed 42 --out tuned.json
uv run python tools/eval_malware_dataset.py --n 300 --seed 7 --exclude-from tuned.json --out holdout.json
uv run python tools/eval_malware_dataset.py --n 300 --seed 99 --exclude-from tuned.json --exclude-from holdout.json
uv run python tools/eval_malware_dataset.py --kind compromised_lib --all-versions      # 직전 비교 포함
uv run python tools/eval_benign_top.py --n 300 --diff-all                               # 직전 비교 포함
```

**정직한 수치는 최종 세트(seed 99)다.** 규칙 설계에는 탈취 세트 샘플(lightning·memoryos)과 튜닝 세트의
놓친 샘플만 봤고, 최종 세트는 결과만 읽었다.

## 2. 무엇을 바꿨고 각각 무엇을 잡았나

### 2.1 import 시점 범위 확장 (`engine/rules/exec_scope.py`)

같은 패키지 다른 모듈의 함수(상대·절대 import, `__init__` 재수출), 인스턴스화 시 `__init__`/`__new__`/
`__post_init__`, 인스턴스·`self` 메서드, Thread 하위 클래스 `start()`→`run()`, `Thread(target=)`·`Timer`·
`Process`·`atexit.register`·`executor.submit` 에 넘긴 함수, 클래스 본문·데코레이터·기본 인자. setup.py 는
`src/` 배치와 상대 import 도 따라간다.

* 처음에는 확장 범위의 네트워크 호출도 HIGH 로 냈다 → 최종 세트 80.7→82.0%, 튜닝 79.7→81.3%,
  held-out 86.0→86.7%, 탈취 차단 20→22 (litellm 1.82.7, memoryos 2.0.34).
* **그러나 오탐이 났다** (§3). 정상 패키지도 확장 범위에서 import 시 통신한다. 그래서 확장 범위에서만 닿은
  네트워크 호출은 `custom-install-time-network-indirect`(MEDIUM)로 내리고, 직전 릴리스에 없던 것만
  version_diff 가 HIGH 로 올리게 했다. 수상한 명령 실행은 확장 범위에서도 HIGH 그대로다.
* 그 결과 범위 확장 자체로 늘어난 차단은 최종 +1, 튜닝 +2 (mlc-ai-nightly 계열 — 설치 훅이 부르는
  코드의 네트워크 호출), held-out 0. 확장 범위의 가치는 대부분 아래 2.3 의 "새 행위" 승격을 통해 나온다.
* 같은 줄에 여러 시작 파일이 닿으므로 위치당 하나만 남긴다 (memoryos: 수백 모듈이 같은 `get_logger()`).

### 2.2 수상 토큰 없는 설치·import 시점 프로세스 실행 (`custom-install-time-spawn`, MEDIUM)

git·cmake·컴파일러·nvidia-smi·uname 등 빌드·조사 명령은 제외. 홀로는 판정을 바꾸지 않는다.

| 세트 | 이 규칙이 난 샘플 | 그중 다른 규칙으로 차단 안 된 것 |
|---|--:|--:|
| 악성 튜닝 300 | 70 | 17 |
| 악성 held-out 300 | 74 | 13 |
| 악성 최종 300 | 82 | 17 |
| 정상 상위 291 | 20 (6.9%) | — |

정상 상위 패키지 20개(6.9%)에서 나므로 단독 HIGH 는 안 된다 — cffi·psutil·uvloop·pynacl 의 setup.py,
psycopg(pg_config)·onnxruntime(oslevel) 의 import 시 환경 조사 등. 악성 쪽 놓친 샘플 대부분은
`os.system(<변수>)`·`os.startfile()` 이 setup.py 최상단·설치 훅에 있는 형태인데, 정상 쪽도 setup.py 의
명령을 변수로 조립하는 경우(pynacl·grpcio-tools·psycopg2-binary)가 많아 "명령을 정적으로 모름"만으로는
가를 수 없었다 — 남은 과제(§5).

### 2.3 직전 릴리스 대비 새 행위 (`engine/version_diff.py`)

새로 나타난 spawn·확장 범위 네트워크 → HIGH, 이미 HIGH 인 커스텀 행위가 새로 나타나면 주석. 탈취 세트에서
**직전 비교로만 차단된 것 7개**: lightning 2.6.2·2.6.3 (스레드에 넘긴 함수의 `Popen([sys.executable, …])`),
litellm 1.82.7 (`proxy_server.py` 의 `subprocess.run([python …])`), memoryos 2.0.34 (모듈 3개를 건너
번들 바이너리 `Popen`), telnyx 4.87.1, xinference 2.6.0·2.6.2.

끼워 넣은 코드로 잡지 못한 4개: ultralytics 8.3.41·8.3.42 (직전 정상 버전에도 있는 연결 확인 코드로만
걸림 — 실제 페이로드는 이 엔진이 보는 곳 밖), num2words 0.5.15·0.5.16 (아무것도 안 걸림). nhmpy 2.4.7 은
PyPI 에서 프로젝트가 지워져 비교 불가(원래 `.pth` 로 차단).

행위 이름은 줄번호가 아니라 "무엇을 했는가"(규칙 + 호출 이름 + 명령 이름)다. 그래서 sdist 루트 이름
(`pkg-1.2.3/`)과 파일 이동에 흔들리지 않는다 — 탈취 샘플(데이터셋의 임시 경로)과 PyPI 의 직전 sdist 처럼
경로 구조가 전혀 다른 쌍에서도 비교가 됐다.

**어떤 규칙을 승격 대상에 넣을지**는 정상 쌍에서 쟀다(§4): `custom-dangerous-call`(eval·exec·pickle)은
최신 릴리스에서 새로 나타나는 일이 잦아 넣지 않았다.

### 2.4 콘솔 스크립트 진입점 (`custom-entrypoint-exec`) — 결국 MEDIUM

진입점 함수는 사용자가 명령을 직접 실행할 때 돌고, 거기서 네트워크는 정상이다. 수상한 명령(숨김
PowerShell·`| sh`·인코딩 명령 등)만 보고한다. **악성 세 세트 900개와 탈취 29개에서 이 규칙이 새로 잡은
것은 0개**였다 — 악성 패키지는 진입점이 아니라 설치·import 시점을 쓴다. 처음엔 HIGH 였지만 오탐이
났다: ultralytics 의 `yolo` 명령이 내려받기 재시도에 `curl` 을 쓰고(다운로드 도구만 있으면 제외로 처리),
신규 업로드에서는 seleniumbase·trqsh·squidbrake 의 정상 PowerShell 호출, pyft8 의 `CREATE_NO_WINDOW`,
pigeon-home-runner 설치 마법사의 crontab 등록이 걸렸다(§7). 탐지 이득 없이 오탐만 늘려 MEDIUM 으로 내렸다.

### 2.5 2MB 넘는 .py 모듈 사각지대 (`engine/static_analyzer.py`)

코드 파일은 20MB 까지 모두 읽고, 넘으면 `unreadable` 에 "(크기 상한 초과)"로 남겨 `static:` 레이어 오류가
된다. 정상 상위 300개에서 20MB 를 넘는 코드 파일은 0개(static 오류 0건). 2–20MB 의 생성 모듈
(google-genai `types.py` 등)을 새로 파싱하면서 생긴 시간 증가는 중복 읽기·파싱 제거로 상쇄했다:
google-genai 3.3.0 분석 19.2초(전) → 36.8초(첫 구현) → 17.8초(후), botocore 7.0 → 7.6초.

## 3. 찾은 오탐과 처리

| 패키지 | 어디서 | 원인 | 처리 |
|---|---|---|---|
| litellm 1.82.6 (정상 직전 버전) | `__init__` → `get_model_cost_map()` 의 `httpx.get` | import 시 모델 가격표를 GitHub 에서 받음 | 확장 범위 네트워크 → MEDIUM |
| elementary-data 0.23.2 | `cli/cli.py` → `utils/package.py` 의 `requests.get` | CLI 모듈 import 시 PyPI 최신 버전 확인 | 같음 |
| memoryos 2.0.33 | `api/config.py:231` 의 `requests.get` | 설정 로드 시 통신 (같은 파일의 확장 범위로 닿음) | 같음 |
| lxml 6.1.3 (정상 상위 300) | setup.py → setupinfo → buildlibxml 의 `urlretrieve`·`ftplib.FTP` | 정적 빌드 옵션일 때 libxml2 다운로드 (두 모듈 건너) | setup.py 의 로컬 모듈 2단계 이상은 확장 범위 → MEDIUM |
| ultralytics 8.3.40·8.3.44 | `yolo` 진입점 → `downloads.py` 의 `subprocess.run(["curl", …])` | CLI 의 내려받기 재시도 | 진입점에서는 다운로드 도구만 있으면 보고 안 함 |

모든 처리 뒤 탈취 세트의 직전 정상 버전 16개 중 HIGH 는 ultralytics(기존 오탐) 하나로 돌아왔다.

## 4. 정상 상위 300 — 오탐률과 직전 비교

측정: a4f4d1e, `eval_benign_top.py --n 300 --diff-all`. 분석 291개(오류 9개 — numpy·scipy·ruff·grpcio·
jedi 는 멤버 5000개 상한, pillow·matplotlib·rapidfuzz·pymupdf 는 30MB 상한 초과. 기준과 같은 9개).

| 항목 | 값 |
|---|---|
| 차단 | 2/291 = **0.7%** — urllib3(기존), coverage(`.pth` — 기존). 기준과 같은 두 개 |
| 범위 확장 중간 단계의 오탐 | lxml 6.1.3 (§3) — 확장 범위 네트워크를 MEDIUM 으로 내린 뒤 해소 |
| `custom-install-time-spawn`(MEDIUM)이 난 패키지 | 20/291 (6.9%) |
| `custom-entrypoint-exec` | 0 |
| 직전 비교 후보(직전 릴리스를 추가로 받은 패키지) | 22/291 (7.6%) — 나머지 269개는 추가 다운로드 없음 |
| 직전 비교로 **새로 차단** | **0/291** |
| 직전 비교의 "새로 나타남" 주석 | coverage 1건(이미 차단된 `.pth`) |
| 직전 비교 실패(`static:` 오류) | 0 |

**승격 대상 규칙 고르기 (`--diff-all`, 291쌍 전부 직전 릴리스와 비교):** 최신 릴리스에서 MEDIUM 이
새로 나타난 수 — `custom-dangerous-call` 27건, `custom-install-hook` 7건, `custom-install-time-spawn`
0건, `custom-install-time-network-indirect` 0건. 그래서 승격 대상은 spawn·확장 범위 네트워크 두 규칙이고,
dangerous-call·install-hook 을 넣었다면 정상 상위 패키지의 약 9%·2.4% 가 차단됐을 것이다.

## 5. 남은 놓침 (최종 세트 300개 중 57개)

| 유형 | 수 | 설명 |
|---|--:|---|
| 아무 신호 없음 | 26 | 사용자가 함수를 직접 불러야 도는 페이로드, 코드 없는 PoC·메타데이터만 있는 패키지 |
| 수상 토큰 없는 설치·import 시점 프로세스 실행 (spawn MEDIUM) | 17 | `os.system(<변수>)`·`os.startfile()` 등. 새 프로젝트라 직전 비교가 없다 |
| 설치 훅·위험 함수 MEDIUM 만 | 11 | `install` 이 아닌 빌드 명령 훅, 디코딩 없는 `exec` |
| 확장 범위 네트워크 MEDIUM 만 | 3 | 다른 모듈·메서드를 거친 통신. 새 프로젝트라 직전 비교가 없다 |

연도별(최종): 2022 56% · 2023 86% · 2024 93% · 2025 60% · 2026 76%.

다음 후보: spawn MEDIUM 과 다른 약한 신호(새 프로젝트·이름 유사도·설치 훅)를 묶는 조합 규칙 — 단, 위
정상 20개를 같이 보며 재야 한다. 그리고 탈취 sdist 가 아니라 **실제 설치되는 wheel** 과 직전 wheel 을
비교하는 것(core-pipeline 의 다중 아티팩트 스캔 통합 후).

## 6. 알려진 한계

* 직전 비교는 행위 이름에 파일 위치를 쓰지 않는다. 직전 릴리스에 이미 명령을 정적으로 모르는(`'?'`)
  import 시점 실행이 있으면, 다른 파일에 새로 들어온 `'?'` 실행은 새 것으로 보지 않는다.
* 직전 릴리스는 `select_artifact`(sdist 우선) 1개로 분석한다. 스캔이 여러 아티팩트를 보게 되면 같은
  집합으로 맞춰야 한다 (`docs/design/integration-notes/py-engine.md`).
* 첫 릴리스(새 프로젝트)에는 승격이 없다 — 악성 목적 패키지 대부분이 여기에 속해 2.3 은 그쪽 탐지율을
  올리지 않는다.
* 범위 추적은 정의 400개에서 멈춘다(`MAX_FOLLOWED_DEFS`). 실측 악성 경로는 깊이 4 이내였다.
* 측정 환경: Windows, 악성 샘플은 메모리에서만 읽음, 직전 정상 릴리스와 정상 상위 패키지는 디스크에 풀어
  분석. 정상 평가의 오류 9개는 기존과 같은 아카이브 상한(30MB·멤버 5000) 초과다 — "못 봄"이지 "깨끗함"이 아니다.

## 7. 신규 업로드 오탐 제안 반영 (docs/eval/watch-new-uploads.md §3) — 2026-11-13 2차

통합 브랜치(`feat/multi-ecosystem`, bd3c15f)를 병합한 뒤, 감시기가 실제로 본 신규 업로드 재스캔에서 나온
규칙 변경안을 반영했다. 감시기 DB 는 원본을 읽기 전용(`mode=ro`)으로 열어 SQLite 백업 API 로 사본을 만들고
사본만 읽었다. 표본 시드 20261113 (watch-dash 와 같음).

### 7.1 전 → 후

| 지표 | watch-dash 측정 (브랜치 시점 엔진) | 병합 직후 (bd3c15f) | **후 (1e76210)** |
|---|---|---|---|
| 신규 업로드 — 예전 block 74건 재스캔에서 지금도 block | 50/71 | 60/72 (83%) | **21/72** (29%, 19.9–40.5) |
| 신규 업로드 — 무작위 500 표본 block | 3/486 (0.62%) | 5/490 (1.0%, 0.44–2.37) | **1/491 (0.20%, 0.04–1.14)** |
| 악성 최종 (seed 99) | — | 81.0% (243/300) | **81.0%** (243/300) |
| 악성 held-out (seed 7) / 튜닝 (seed 42) | — | 86.0% / 80.3% | 86.0% / 80.3% |
| 탈취 — 끼워 넣은 코드로 잡음 / 직전 비교 포함 차단 | — | 24/28 / 27/29 | 24/28 / 27/29 |
| 정상 상위 300 차단 | — | 2/291 (a4f4d1e) | **2/299 (0.7%)** — urllib3·coverage |
| 정상 상위 300 — 직전 비교로 새로 차단 | — | 0/291 | **0/299** (후보 25개만 직전 릴리스 다운로드) |

병합 직후 값이 watch-dash 측정보다 나쁜 것은 py-engine 1차의 `custom-entrypoint-exec`(HIGH) 때문이다 —
예전 block 재스캔에서 76건 발생, 표본에서 4건. 아래 7.2 의 마지막 항목으로 해소.

정상 상위 300 은 통합된 core-pipeline 의 상한 변경(100MB·선택 추출)으로 이제 거의 전부 분석된다(오류 1 —
mypy 메타데이터 조회 일시 실패). 새로 분석된 matplotlib 3.11.2 가 한때 차단됐다(7.2).

### 7.2 반영한 것 (커밋별, 각 변경 후 악성 4세트 재측정 — 모두 차단 수 변화 0)

| 제안 | 변경 | 해소한 오탐 |
|---|---|---|
| P2 `.pth` 자기 모듈 import | 문장이 자기 모듈 import·경로 추가(`sys.path.insert` 등)·자기 모듈 함수 호출뿐이고, import 하는 모듈과 부르는 함수(재수출까지 풀어 범위 추적)에 HIGH·네트워크·프로세스·실행 싱크·디코더가 없으면 MEDIUM. 그 모듈은 위치와 무관하게 import 시점 검사 대상 | dagz 7·doeff-hy·quantark·triton-utlx-rocm (gammonview-helper 는 표본에서) |
| P1 버전 확인 | 목적지가 상수 `pypi.org`·`localhost`·`127.0.0.1` (변수면 그 이름의 모든 대입이 그래야 함) → MEDIUM | rubka·sigmaflow |
| P1 setup.py 다운로드 | `urlretrieve(url, 파일)` 이고 같은 설치 범위에 파일을 실행할 수 있는 호출(spawn·exec·startfile·chmod·ctypes)이 없고, 주소를 조립하지 않았고, 저장 경로가 실행 파일·시작 프로그램 폴더가 아니면 MEDIUM | ai-edge-litert-sdk-* 9릴리스 |
| P3 자기 라이브러리 blob | `exec(<해독 체인>, <모듈>.__dict__)` 일 때만 실행 없이 해독(base64 계열·zlib·lzma·bz2, 8MB 상한)해 "import 되는 모듈"로 다시 분석, 최상단이 조용하면 MEDIUM | hpcp 5·statblk·statbtrfs |
| P4 설치 훅 | 훅 안 싱크가 `urlretrieve` 뿐이면 `custom-install-hook` MEDIUM | (haddock3 대상이었으나 아래 이유로 남음) |
| (측정에서 나온 것) URL/파일 도우미 | 같은 변수의 `startswith(("http://", …))` 분기 안의 통신 → MEDIUM | matplotlib 3.11.2 (정상 상위 300) |
| (측정에서 나온 것) 진입점 규칙 | `custom-entrypoint-exec` HIGH → MEDIUM (§2.4) | seleniumbase·trqsh·squidbrake·pyft8·pigeon-home-runner 9 |

triage 문서의 서술과 실제 코드가 달랐던 곳이 있어 첫 적용으로는 일부만 풀렸다: `.pth` 는 "import 한 줄"이 아니라
`import X; X.func()`·`sys.path.insert(...)` 였고, 버전 확인 URL 은 지역 변수를 거쳤고, hpcp 의 blob 은
`.decode("utf-8")` 로 끝나며 상수가 블록 안에서 대입됐다. 실제 릴리스를 내려받아(실행 없이) 확인한 뒤 맞췄다.

### 7.3 하지 않은 것 / 남긴 것과 이유

* **"try/except 로 실패를 삼키는 GET 은 MEDIUM" — 하지 않음.** 실측 악성 esq* 계열이 setup.py 의 숨김
  PowerShell 을 바로 `try: ... except: pass` 로 감싼다(`tests/test_engine.py` 고정 픽스처). 비용이 탐지율이다.
* **`raw.githubusercontent.com` 을 정상 목적지로 — 하지 않음.** 악성 2단계 페이로드를 두는 흔한 곳이다.
  그래서 meerschaum 2(typing_extensions 대체 경로)는 block 으로 남는다.
* **`urlopen`·`requests.get` 다운로드를 MEDIUM 으로 — 하지 않음.** 상수 주소에 GET 만 해도 의존성 혼동 PoC 의
  비콘(설치한 곳의 IP 유출)이다. 그래서 chromedriver-binary 3 은 남는다.
* **haddock3 는 남김(의도).** 설치 훅이 실행 파일을 내려받아 `os.chmod(executable, 0o755)` 하고 다른 훅에서
  subprocess 를 돌린다 — "받아서 실행 권한 주기"는 정확히 악성이 쓰는 형태라 HIGH 가 맞다.
* **nvidia-cutlass-dsl 은 남김(의도).** `.pth` 가 import 하는 `nvidia_cutlass_dsl` 이 그 휠에 없다(다른 배포물이
  제공) — 같은 배포물에 없는 모듈을 시작 시 띄우는 것은 제안서의 HIGH 유지 조건이다.
* 함수 안 통신이라 "import 시점"이 아니라는 지적(agentwire-dev·fiberbrowser·sr-harness·chatsorter-local·
  trading-matrix-dashboard·radboy·ultralytics): 이들은 모듈 최상단에서 **같은 파일 함수를 불러** 닿는 예전 범위의
  통신이라 실제로 import 시점에 돈다(범위 추적은 정확했다). 목적지가 정상 서비스라는 것은 정적으로 가를 근거가
  없어 남겼다 — 남은 21릴리스 중 15가 이 유형이다. 신규 업로드 무작위 표본의 유일한 block(hopsworks 4.6.8,
  import 시 사용 통계 전송)도 같다.
