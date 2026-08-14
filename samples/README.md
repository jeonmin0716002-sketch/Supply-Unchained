# samples — 정적분석 검증용 악성 패턴 샘플

엔진(레이어 ②)이 실제로 탐지하는지 확인하기 위한 **무해한 테스트 픽스처**입니다.
`tests/test_engine.py`가 이 디렉토리를 그대로 스캔해 회귀 테스트를 돌립니다.

> ⚠️ 실제 악성코드가 아닙니다. 페이로드 자리에는 `echo`만 들어 있고,
> 어떤 샘플도 네트워크 접속·파일 변경·데이터 반출을 하지 않습니다.
> 다만 **실행하지는 마세요** — 탐지 대상 패턴 그 자체이므로 정적으로만 다룹니다.

샘플 하나당 디렉토리 하나 = **압축 해제된 패키지 한 개**입니다.
엔진의 `analyze_path()`가 실제로 받는 입력 형태와 같아야 하기 때문입니다
(`custom-install-hook` 규칙은 파일명이 정확히 `setup.py`일 때만 동작 —
파일명을 느슨하게 매칭하면 규칙 자체가 약해지므로 샘플 쪽을 실제 구조에 맞췄습니다).

| 샘플 | 흉내내는 공격 | 탐지되어야 할 규칙 | 차단? |
|---|---|---|:---:|
| `sample1_install_hook/setup.py` | 설치 시점 셸 명령 실행 | `custom-install-hook` (CWE-94, high) · `custom-dangerous-call` (CWE-78, medium) | ✅ |
| `sample2_obfuscated/loader.py` | base64 페이로드 → `exec` | `custom-obfuscated-payload` (CWE-506, high) | ✅ |
| `sample3_pth_autoexec/install.pth` | `.pth` 시작 시 자동 실행 | `custom-pth` (CWE-94, high) | ✅ |
| `sample4_pickle/cache.py` | 신뢰할 수 없는 데이터 역직렬화 | `custom-dangerous-call` (CWE-502, medium) | ❌ |

`sample4`만 차단되지 않는 게 **의도**입니다. `pickle.loads()`는 정상 코드에도
흔해서 그 자체로는 악의의 증거가 아닙니다. high는 공급망 공격에 특유한 신호
(`.pth`·install 훅·디코딩→실행)에만 씁니다 — 자세한 근거는 `engine/README.md`의
"심각도 모델" 참고.

`sample3_install.pth`가 핵심 차별점입니다 — `pip-audit`·`safety`는 물론 Bandit도
`.pth` 파일은 보지 않습니다. (Python 소스가 아니라서 파서 대상 자체가 아님)
