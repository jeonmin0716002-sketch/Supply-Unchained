# eco-cargo-go 통합 메모

소유 파일 밖에서 필요한 변경(요청)과 알려진 한계.

## 요청 (core-pipeline / common)
1. **`common.archive` 추출 상한 5000 멤버** — Go 모듈은 저장소 전체가 zip 으로 오기 때문에
   `github.com/aws/aws-sdk-go`, `github.com/hashicorp/consul` 같은 큰 모듈이 `ArchiveError("more than 5000 members")`
   로 `static:` 오류가 된다 (판정 warn). Go·cargo 는 `.go .c .h .s .rs Cargo.toml go.mod build.rs` 만 읽으므로
   `extract_archive` 에 "이 확장자만 추출" 필터(또는 멤버 상한을 읽는 파일 기준으로 계산)를 넣어 달라.
2. Go 아티팩트는 `.zip` 이고 루트가 `<모듈경로>@<버전>/` 이다. `go-module-path-mismatch` 규칙이 이 루트 이름에서
   요청 모듈 경로를 읽으므로, 추출 시 최상위 디렉터리를 벗기지 말 것 (cargo 도 `<name>-<ver>/` 루트를 가정하지만
   벗겨도 동작한다).
3. `Go` 의 `fetch_project` 는 버전 시각을 최신 25개만 `.info` 로 채운다. 직전 버전 비교(`previous_version`)는
   그 범위 안에서만 된다. 목록에 없는 유사 버전(pseudo-version)은 `select_artifacts` 가 URL 을 직접 만든다.
4. 감시기: Go 피드는 `fetch_feed(client, since=...)` 로 시작 시각을 줄 수 있다 (기본: 최근 15분). 2000줄 상한에 닿으면
   오류 문자열로 알린다 — 주기를 짧게 하거나 `since` 를 마지막 처리 시각으로 넘길 것.
   cargo 피드는 `/api/v1/summary`(신규·갱신 각 10개 안팎) 라서 1분 안팎 주기가 필요하다.

## 한계
* cargo `Release.dependencies` 는 비어 있다 (crates.io 의존성은 버전별 별도 요청이 필요). `dependency_count` 신호는 0.
* proc-macro 는 `src/**.rs` 전체를 같은 범위로 본다 — 매크로 확장 때만 도는 함수와 헬퍼를 구분하지 않는다.
* Go: 메서드 본문·`init` 이 부르는 다른 패키지(내부 import)의 함수는 따라가지 않는다. 같은 디렉터리(패키지) 안의
  함수 호출만 따라간다. 리플렉션·함수 값 호출은 보지 못한다.
* Go `build tags` 는 해석하지 않는다 (`//go:build ignore` 만 제외).
* cgo 생성자 탐지는 생성자 선언 뒤 1500자 안의 위험 호출 근접성 휴리스틱이다.
* `ruff: noqa: E501` 을 한국어 문자열이 긴 몇몇 파일 끝에 둠 (pyproject 를 건드리지 않기 위해).
