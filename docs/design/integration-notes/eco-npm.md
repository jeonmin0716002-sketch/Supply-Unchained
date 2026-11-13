# eco-npm — 통합 때 반영할 요청

브랜치 `claude/eco-npm-5c0b7c`. 아래는 내 소유가 아닌 파일이라 고치지 않았다.

1. **`api/schemas.py` (core-pipeline)** — `ScanRequest` 가 npm 을 받아야 프록시가 스캔한다.
   * `Ecosystem` 에 `NPM = "npm"`.
   * 이름 검증을 생태계별로: npm 은 `@scope/name` (슬래시 1개, `@` 시작) 을 허용해야 한다.
     `ecosystems.get(ecosystem).validate(name, version)` 에 위임하는 것을 권한다 (npm 버전은
     semver + prerelease/build, 최대 256자 — `ecosystems/npm/__init__.py` 의 `VERSION_RE`).
   * 그 전까지 `api/routers/npm_proxy.py` 는 `ScanRequest(ecosystem="npm")` 검증 실패를 잡아
     **503 (통과시키지 않음)** 을 낸다.
2. **`api/main.py`** — 설계 §3.1 의 guarded include 그대로: `from api.routers import npm_proxy;
   app.include_router(npm_proxy.router)` (접두사 `/npm` 은 라우터에 이미 있다). pip 프록시의
   `/simple`·`/files` 와 겹치지 않는다.
3. **`api/routers/scan.py`** — 프록시는 `scan_layer.static_incomplete(result)` 가 있으면 그것으로
   "정적분석 미완료"를 판단해 `SU_UNSCANNED_POLICY != allow` 일 때 403 을 낸다 (handover 의 이름).
   이름이 바뀌면 `npm_proxy._unscanned_blocked` 한 곳만 고치면 된다.
4. **선택 추출(common.archive)** — 어댑터에 `scan_suffixes` 를 두었다 (`.js .cjs .mjs .json .gyp
   .sh .ts .npmrc .py .bat .ps1`). 확장자 없는 파일도 필요하다(`bin/` 셸 스크립트).
5. **unreadable** — `ADAPTER.analyze_tree(tree)` 는 계약대로 tree 만 받는다. 읽지 못한 설치·로드
   시점 파일은 `npm-unreadable`(MEDIUM) finding 으로 나오고, `ecosystems.npm.rules.analyze_tree(tree,
   unreadable=list)` 를 직접 부르면 목록도 받는다. 파이프라인이 추적 SourceTree 로 감싸는
   방식(handover)이면 그대로 동작한다.
6. **README** — 실측 수치는 `docs/eval/npm.md`: held-out 탐지율 52.0% (156/300), 상위 300개 오탐
   0/300. 실행 경로가 없는 스팸·자리표시를 빼면 69%.
7. **`ecosystems/data/popular/npm.txt`** — popular-lists 세션 것을 썼다(`--list` 로 경로 지정).
   병합되면 `tools/eval_npm.py benign` 이 기본으로 읽는다.
