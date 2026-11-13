# npm 규칙 실측

측정일 2026-11-13. 도구 `tools/eval_npm.py`. 패키지를 **설치·실행하지 않고** 타르볼 안의 파일을
메모리에서만 읽어 `ecosystems.npm.rules.analyze_tree` 를 돌렸다. 차단 = HIGH 이상 finding 1개 이상.

## 결과

| 지표 | 데이터 | 결과 |
|---|---|---|
| 탐지율 — **held-out (실제 값)** | DataDog `malicious-software-packages-dataset` `samples/npm/malicious_intent` 중 튜닝 세트 300개 패키지를 **뺀** 무작위 300개 (패키지당 1버전, seed 7) | **52.0%** (156/300, 95% CI 46.4–57.6%) |
| 탐지율 — 튜닝 세트 (참고용) | 같은 데이터셋 무작위 300개 (seed 42). 놓친 샘플을 보고 규칙을 고친 세트 | 52.7% (158/300, CI 47.0–58.2%) — 첫 규칙 45.3% |
| 오탐률 (차단) | npm 다운로드 상위 300개 최신 버전 (`wooorm/npm-high-impact`, popular-lists 세션의 `npm.txt`) | **0/300** (95% CI 0–1.3%) |
| 경고(MEDIUM) | 같은 300개 | 1개 — esbuild `install.js` 의 설치 시점 네트워크 호출 (바이너리 내려받기, 의도된 정황) |

```bash
uv run python tools/eval_npm.py malware --n 300 --seed 42 --out npm-tuned.json
uv run python tools/eval_npm.py malware --n 300 --seed 7 --exclude-from npm-tuned.json --out npm-holdout.json
uv run python tools/eval_npm.py benign --n 300 --out npm-benign.json   # ecosystems/data/popular/npm.txt 필요 (없으면 --list)
```

held-out 이 튜닝 세트와 거의 같다(52.0% vs 52.7%) — 튜닝 세트에 과적합되지 않았다. 발견 연도별
held-out: 2024 37% (35/95) · 2025 69% (87/126) · 2026 43% (34/79).

### 52% 를 어떻게 읽나 — 놓친 샘플의 대부분은 "자동 실행 경로가 없다"

held-out 에서 놓친 144개를 휴리스틱으로 나누면(스크래치 스크립트, 정확한 분류 아님):

| 분류 | 수 | 설명 |
|---|---|---|
| 레지스트리 스팸 (자기 복제 게시) | 54 | `auto.js`·`publishScript.js` 가 `npm publish` 를 반복하는 계열(인도네시아어 이름 조합·`*_z3n`·tea.xyz 보상 사냥). **install 스크립트도 진입점 코드도 없다** — 설치해도 아무것도 돌지 않는다. 스팸이지 실행되는 악성 코드가 아니다 |
| 코드 없음·자리표시 | 20 | `package.json` 만, 또는 `console.log('Hello')` 수준 (보안 연구용 자리표시, 이름 선점) |
| install 스크립트 있음 | 22 | 아래 "알려진 한계" — 바이너리 페이로드, 실행되지 않는 깨진 JS, 위장 빌드 |
| 그 밖 | 48 | 진입점이 아닌 파일의 코드, 함수 안에만 있는 코드(사용자가 불러야 돈다), 깃 의존성 등 |

스팸·자리표시 계열(held-out 74개, 튜닝 세트 81개)을 빼면 held-out 156/226 = **69%**, 튜닝
158/219 = 72% 다. 이 계열은 정적분석 규칙이 아니라 메타데이터(새 계정·연속 배포 — scoring)로
보는 것이 맞고, 설계 §2.3 의 "HIGH 는 자동 실행 + 해로운 행위" 원칙상 HIGH 로 올리지 않았다.

## 규칙 (`ecosystems/npm/rules.py`, ID → CWE 는 `RULE_CWES`)

범위: **설치 시점** = `preinstall`·`install`·`postinstall` 이 실행하는 파일 **전체**(+ 그 파일이
`require('./x')` 하거나 자식 프로세스로 띄우는 패키지 안 JS), `node -e` 인라인 코드, 루트
`binding.gyp`. **로드 시점** = `main`/`exports` 진입점의 실행 범위(최상단 + 거기서 부르는 같은
파일 함수 + IIFE + 실행되는 호출에 바로 넘긴 콜백) + 그 범위가 require 하는 파일의 같은 범위.
`prepare` 는 git 의존성에서만 돌아 레지스트리 타르볼에서는 범위가 아니다.

| 규칙 | 심각도 | 잡는 것 | 튜닝/held-out HIGH 건수 |
|---|---|---|---|
| `npm-install-time-exec` | HIGH | 설치 시점 네트워크 전송 + (호스트 정보 `os.hostname/userInfo/...` · `process.env` 직렬화 · 비밀 파일 읽기 · 대역외 수신 주소 · IP 직접 · 받은 값 `eval` · 셸 spawn), 또는 수상한 명령 실행 | 88 / 78 |
| `npm-load-time-exec` | HIGH | 같은 조합이 `require` 순간 실행 | 21 / 17 |
| `npm-install-shell` | HIGH | lifecycle 명령·셸 스크립트의 `curl\|sh`·`wget`·PowerShell `-enc`·`/dev/tcp`·`nslookup`·`ping -c`·대역외 주소 | 45 / 55 |
| `npm-obfuscated` | 설치 HIGH / 그 외 MEDIUM | javascript-obfuscator(`_0x` 범람·`while(!![])` 문자열 배열 회전), 출력 가능 ASCII 문자 코드 배열, API·모듈 이름을 hex·base64·문자 코드로 숨김 | 13 / 12 |
| `npm-decode-exec` | 실행 범위 HIGH / 그 외 MEDIUM | `eval`·`Function`·`vm.*`·`module._compile` 에 `Buffer.from(…,'base64'/'hex')`·`atob`·`fromCharCode`·긴 인코딩 문자열·그 결과를 받은 변수 | 2 / 0 |
| `npm-exfil-endpoint` | HIGH | 토큰이 박힌 Discord 웹훅·Telegram 봇 주소 (어디에 있든) | 8 / 13 |
| `npm-remote-dependency` | http(s) HIGH / git LOW | `dependencies` 의 레지스트리 밖 타르볼 주소 (PhantomRaven 계열) — 설치 때 검사되지 않은 코드가 돈다 | 5 / 6 |
| `npm-binding-gyp` | 수상 명령 HIGH / actions MEDIUM | `<!(cmd)` 명령 치환·`actions` | 0 / 0 |
| `npm-install-network` | MEDIUM | 설치 시점 네트워크 호출만 (바이너리 내려받기와 구분 불가) | — |
| `npm-secret-read` | MEDIUM | 설치·로드 시점 비밀 파일 읽기 + 호스트 정보 (전송 없음) | — |
| `npm-suspicious-host` | MEDIUM/LOW | 실행 경로 밖의 대역외 주소, 붙여넣기·IP 조회 서비스 | — |
| `npm-install-script` | LOW/MEDIUM | lifecycle 스크립트 분류 (빌드 도구 / 번들 JS / 인라인 / 셸), 분리된 백그라운드 프로세스 | — |
| `npm-minified-entry`, `npm-package-oddity` | LOW/MEDIUM | 한 줄 2만 자 넘는 진입점(dist·min 제외), 포함된 `.npmrc`, 패키지 밖을 가리키는 `bin` | — |
| `npm-unreadable` | MEDIUM | 설치·로드 시점 파일을 읽지 못함 ("못 봤다 ≠ 깨끗하다", 백신 차단 포함) | — |

JS 파서 의존성 없이 `ecosystems/npm/jslex.py` 의 토큰 렉서(주석 제거, 문자열·템플릿·정규식 리터럴,
이스케이프 해제, `require('a'+'b')`·`require(String.fromCharCode(...))` 해석, 구조 분해 별칭)로
본다. 600 KB 소스 렉싱 약 1초, 1.5 MB 이상은 앞부분만.

## 찾아서 고친 오탐

| 패키지 | 무엇이 걸렸나 | 고친 것 |
|---|---|---|
| esbuild (HIGH) | `install.js` 의 `fetch` + `spawnSync(…, {env: process.env})` → "환경변수 전체" | `process.env` 는 `JSON.stringify`·`Object.keys`·`Buffer.from`·`write`·`send` 같은 직렬화 호출 안에 있을 때만 센다 |
| acorn, typescript (MEDIUM) | 유니코드 식별자 표(큰 수 배열) → 문자 코드 배열 난독화 | 9–126(출력 가능 ASCII) 범위 수가 80개 이상 연속일 때만 |
| entities, prettier, jiti, @babel/helper-validator-identifier (MEDIUM) | 이스케이프 수백 개짜리 데이터 문자열 | 긴 이스케이프 문자열만으로는 설치 시점 파일에서만 난독화로 본다 |

규칙 설계 단계에서 피한 것: 설치 시점 네트워크 호출 "만"을 HIGH 로 두지 않았다(esbuild·sharp·
node-pre-gyp 계열이 정상적으로 바이너리를 받는다). `os.platform()`·`os.arch()` 는 호스트 정보로
세지 않는다(바이너리 고를 때 늘 쓴다). install 스크립트 존재 자체는 LOW.

## 알려진 한계

* **바이너리 페이로드** — `postinstall.mjs` 가 패키지에 든 실행 파일을 연결만 하는 계열(anyscale·
  kamatera·moatless·potsdam·tiruppur, `bin/stardrop`)과 Supabase 저장소에서 실행 파일을 받는
  계열(tarax)은 JS 만 봐서는 판단할 수 없다.
* **함수 안에만 있는 코드** — 사용자가 내보낸 함수를 불러야 도는 악성 코드는 로드 시점 범위가
  아니라 잡지 않는다 (파이썬 엔진과 같은 원칙, 오탐을 막는 대가).
* **스팸·자리표시** — 위 표. 메타데이터 스코어링 몫.
* 렉서 수준 분석이라 변수 섀도잉·동적 속성 이름(`obj[a+b]()`)·`eval` 로 만든 함수는 따라가지
  못한다. 계산된 속성 호출은 "os 를 쓰는 파일에 `'hostname'` 문자열이 있다" 같은 근사로만 본다.
* `compromised_lib`(탈취된 정상 패키지, 1448 버전) 는 **측정하지 않았다** — 버전 대부분이 수 MB
  번들이고 시간이 모자랐다. `--kind compromised_lib --n 60` 으로 잴 수 있다.
* 프록시는 run_scan 을 바꿔 끼운 오프라인 테스트로만 검증했다 — 실제 `npm install --registry` 로는
  core-pipeline 병합 전이라 돌려 보지 않았다.
* 피드(`replicate.npmjs.com/_changes?descending=true`)는 2026-11-13 인증 없이 동작했지만 버전을
  주지 않고(문서 미포함), 새 게시 외 변경(deprecate 등)이 섞이며, 상태 없는 계약이라 최신 N(기본
  500)건만 본다. npm 공식 문서상 이 엔드포인트의 속도 제한은 공개되지 않았다.
