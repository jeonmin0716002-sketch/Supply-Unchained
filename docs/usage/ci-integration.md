# CI 연동 가이드

requirements 파일을 PR 단계에서 검사하는 세 가지 방법을 설명합니다. 셋 다 같은 판정 엔진을 쓰고,
종료 코드 규약도 같습니다.

- **복합 액션** (`action.yml`) — GitHub Actions 워크플로에서 `uses:` 로 호출
- **pre-commit 훅** (`.pre-commit-hooks.yaml`) — 커밋 시점에 로컬에서 실행
- **CLI 직접 호출** (`check-file`) — GitHub Actions, GitLab CI, 그 밖의 셸 어디서든

> 다생태계 `project` 모드와 `sbom` 명령이 들어오면 이 가이드의 CLI 호출부가 `project` 로 바뀝니다.
> 현재 설치되어 있는 명령은 `check-file` 입니다. 자세한 내용은 [project-scan.md](project-scan.md) 를 참고하세요.

## 원칙

- **미검증 패키지를 설치하지 않습니다.** 게이트는 패키지를 `pip install` 하지 않고, 정적분석 결과만 읽습니다.
  CI 러너에서 미검증 패키지를 설치·실행하는 것 자체가 공급망 공격 경로가 되기 때문입니다.
- **"못 봤다"는 "깨끗하다"가 아닙니다.** 판정을 내리지 못한 경우는 통과로 처리하지 않습니다.
- 종료 코드 1(차단)과 2(환경 오류)를 구분합니다. 둘 다 잡을 실패시키지만, 메시지가 다릅니다.

## 종료 코드

| 코드 | 의미 | 잡 결과 |
|---|---|---|
| `0` | 모든 패키지 통과 (block 판정 없음) | 성공 |
| `1` | block 판정이 하나 이상 있음 | 실패 — 보안 차단 |
| `2` | 환경 오류 (파일 없음, 스캐너 연결·설치 실패 등) | 실패 — 환경 문제를 먼저 확인 |

`2` 를 `1` 로 취급하면 "서버가 안 떠서 생긴 에러"를 "악성 패키지 발견"으로 오인합니다. 그래서 구분합니다.

## 1. 복합 액션

이 레포의 `action.yml` 을 다른 레포의 PR 게이트로 씁니다.

```yaml
name: Supply-chain gate

on:
  pull_request:
    paths:
      - "requirements*.txt"

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262  # v4

      - name: Supply-Unchained gate
        uses: jeonmin0716002-sketch/Supply-Unchained@<커밋 SHA>  # 실제 SHA 로 고정
        with:
          path: requirements.txt
          scanner-ref: <커밋 SHA>
```

입력값:

| 입력 | 기본값 | 설명 |
|---|---|---|
| `path` | `requirements.txt` | 검사할 파일 경로 (호출 레포 워크스페이스 기준) |
| `fail-level` | `block` | 실패로 볼 최저 판정. 현재 `block` 만 지원하며, 다른 값은 즉시 실패합니다 |
| `scanner-ref` | `main` | 스캐너 레포에서 받을 ref. 재현성을 위해 커밋 SHA 를 권장합니다 |

액션은 uv 를 설치하고, 스캐너를 `runner.temp` 아래에 체크아웃한 뒤 `uv sync --frozen --no-dev` 로
의존성을 맞추고, `check-file` 을 실행합니다. 호출 레포의 워크스페이스와 섞이지 않습니다.

액션 자체도 커밋 SHA 로 고정하세요. 태그는 다른 커밋을 가리키도록 바뀔 수 있습니다.

## 2. pre-commit 훅

```yaml
# 호출 레포의 .pre-commit-config.yaml
repos:
  - repo: https://github.com/jeonmin0716002-sketch/Supply-Unchained
    rev: <커밋 SHA>
    hooks:
      - id: su-scan-requirements
```

훅은 `language: system` 으로 정의되어 있습니다. 이유는 다음과 같습니다.

- 이 프로젝트는 uv 로 돌고 설치 가능한 패키지가 아닙니다. `language: python` 은 pre-commit 이 레포를
  `pip install` 하려 하므로 맞지 않습니다.
- `system` 은 스캐너의 `uv.lock` 환경을 그대로 씁니다. 훅 환경에 의존성을 따로 설치하지 않습니다.

대신 아래 조건이 필요합니다.

- 훅을 실행하는 머신에 `uv` 가 있어야 합니다.
- 스캐너 체크아웃 위치를 `SU_SCANNER_DIR` 환경변수로 알려줘야 합니다. 설정하지 않으면 현재 디렉터리에서 찾습니다.

```bash
export SU_SCANNER_DIR=/path/to/Supply-Unchained
pre-commit run su-scan-requirements --all-files
```

훅은 `requirements*.txt` 파일이 커밋에 포함될 때만 실행됩니다. 파일이 여러 개면 하나씩 검사하고,
가장 큰 종료 코드를 돌려줍니다.

## 3. CLI 직접 호출

### GitHub Actions

```yaml
      - name: Install uv
        uses: astral-sh/setup-uv@d4b2f3b6ecc6e67c4457f6d3e41ec42d3d0fcb86  # v5
        with:
          python-version: "3.12"

      - name: Sync scanner
        run: uv sync --frozen --no-dev
        working-directory: path/to/Supply-Unchained

      - name: Gate
        run: uv run python -m cli.su_scan check-file "$GITHUB_WORKSPACE/requirements.txt"
        working-directory: path/to/Supply-Unchained
```

### GitLab CI

```yaml
supply-chain-gate:
  image: python:3.12
  stage: test
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  before_script:
    - pip install uv
    - git clone --depth 1 --branch <커밋 SHA 또는 태그> https://github.com/jeonmin0716002-sketch/Supply-Unchained.git scanner
    - cd scanner && uv sync --frozen --no-dev && cd ..
  script:
    - cd scanner && uv run python -m cli.su_scan check-file "$CI_PROJECT_DIR/requirements.txt"
```

`check-file` 은 경로를 현재 디렉터리 기준으로 읽으므로, 검사할 파일은 절대 경로로 넘기세요.

### 서버 경로 (선택)

기본 CLI 는 서버 없이 로컬에서 직접 스캔합니다. API 서버를 거치려면 `SU_API_URL` 을 지정합니다.
이 경우 서버 연결 실패는 종료 코드 `2` 로 나옵니다.

```bash
SU_API_URL=http://scanner.internal:8000 uv run python -m cli.su_scan check-file requirements.txt
```

## 문제 해결

- **종료 코드 2 가 나옴**: 파일 경로가 맞는지, `uv sync --frozen` 이 성공했는지, 스캐너 네트워크 접근이
  되는지 확인하세요. 판정 결과가 아니므로 차단 사유로 보지 않습니다.
- **`fail-level` 오류**: 지원하지 않는 값을 넣으면 게이트가 느슨해지는 것을 막으려고 즉시 실패합니다.
- **`--frozen` 실패**: 스캐너의 `uv.lock` 과 `pyproject.toml` 이 어긋난 상태입니다. 스캐너 쪽에서 수정해야 합니다.
