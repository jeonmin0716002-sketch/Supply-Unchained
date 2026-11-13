# core-pipeline — 통합 메모

브랜치 `claude/core-pipeline-eed389`. 커밋 A(일반화) → B(설치 파일 스캔) → C(미검사 차단).

## 다른 세션이 알아야 할 계약

* **PackageContext** (`common.pypi`): `PackageContext(name, version, *, client=None, ecosystem="pip", artifacts=None)`.
  `model()` → `ecosystems.base.Project`, `extracted_roots()` → `[ExtractedArtifact(artifact, root, names, error, truncated)]`
  (첫 항목이 주 아티팩트), `previous_version()`, `selected_artifacts()`, `eco`.
  pip 의 `project()`(PyPI JSON `ProjectData`)·`extracted_path()`(주 아티팩트 루트)·`archive_names()`(주 아티팩트의
  **모든** 멤버 이름 — 선택 추출로 풀지 않은 것 포함)는 그대로다.
* **py-engine**: `escalate_new_behaviors(ctx, findings, *, errors)` 의 `errors` 는 별도 리스트로 받아, 판정이 끝난 뒤
  `layer_errors` 에 붙인다. 그래서 `static:` 접두사로 써도 "정적분석 미완료"(warn·프록시 차단)로 치지 않는다.
  pip 일 때만 부른다. `engine.static_analyzer.analyze_package` 는 이제 파이프라인이 부르지 않는다(정적 레이어는
  `eco.analyze_tree` 를 루트마다 부른다) — 도구용으로 남아 있고, 주 아티팩트 하나만 본다.
* **어댑터 세션들**:
  - 정적 레이어는 `eco.analyze_tree(tree, artifact=...)` 에 읽기 실패를 세는 래퍼 트리(`.root`, `.unreadable`)를
    넘긴다. 어댑터가 따로 보고하지 않아도 된다. 트리에 **있는** 파일의 `read()` 가 None 일 때만 센다.
  - 압축은 **선택 추출**이다: `common.pypi.SCAN_SUFFIXES`·접미사 없는 파일·`ENTRYPOINT_BASENAMES` 만 풀린다.
    더 필요하면 어댑터 클래스에 `scan_suffixes = (".foo",)`. (이 속성을 `ecosystems/base.py` 계약에 문서화해 달라 —
    base.py 는 이 세션 소유가 아니다.)
  - `extract()` 를 덮어쓰면 계약대로 `bytes` 를 받는다(파이프라인이 디스크에서 읽어 넘김). `common.archive.extract_archive`
    를 거치면 절단 기록이 자동으로 남는다. 기본 `extract` 는 파일 경로로 바로 푼다(메모리에 안 올림).
  - 없음 메시지는 `PackageNotFound("<name> is not on <registry_label> (never existed, or removed)")` 그대로.
* **inventory**: `ecosystems/pip/__init__.py` 가 `ecosystems.pip.manifests` 를 guarded import 해서
  `parse_manifest(filename, text)` 와 `MANIFEST_FILENAMES`(또는 `manifest_filenames`) 를 찾는다. 이름을 맞춰 달라.
* **watch-dash**:
  - `watcher/runner.py:76` 의 삭제 판정이 `"not on PyPI"` 문자열이다 → 다중 생태계면 `" is not on "` 로 바꿔야 한다.
  - 감시기 `ScanRequest(name=, version=)` 에 `ecosystem=` 을 넘기면 run_scan 이 그 생태계로 돈다. Bandit 은 pip 만.
  - 판정 변경: 정적분석이 못 본 패키지(레지스트리에 없음 포함)는 이제 safe 가 아니라 warn + 사유
    `"정적분석 미완료 — ..."`(`api.routers.scan.UNSCANNED_REASON`). `is_suspicious` 는 block·유사도 기준이라
    큐 동작은 그대로일 것이나, 대시보드에 이 사유를 따로 표시하면 좋다. 오탐률 재측정 시 warn 비율이 오른다.
* **ci-chores / README**: 새 환경변수 `SU_MAX_ARTIFACT_MB`(기본 100), `SU_UNSCANNED_POLICY`(`block` 기본 | `allow`).
  CLI: `check -e npm lodash@4.17.21`, `check npm:lodash@4.17.21`, `check-file -e`, `guard --su-ecosystem`(pip 의 `-e`
  와 겹쳐서 접두사), `install` 은 pip 전용.

## 알려진 한계 (README 반영 대상)

* CLI·API·감시기는 pip 에서 sdist + wheel 1개(순수 `py3-none-any` 우선)만 본다. 플랫폼별 wheel 에만 심은 페이로드는
  못 본다. 프록시는 요청된 파일 자체를 스캔하므로 해당 없음.
* 선택 추출은 접미사 기반이다. 분석기가 읽지 않는 파일(.so·.png·.bin·.pkl 등)은 풀지 않는다 — 그 안의 페이로드는
  원래도 규칙이 못 봤다. 진입점 우선 절단은 "일부만 봤다"를 warn 으로 남긴다.
* 상한 초과(100 MB) 파일은 받지 않으므로 판정 warn, 프록시 기본 차단 — torch 같은 거대 wheel 은
  `SU_MAX_ARTIFACT_MB` 상향이나 `SU_UNSCANNED_POLICY=allow` 가 필요하다. (설계 문서 §5 의 HTTP Range 부분 읽기가 해법)
* pip 의 의존성 개수는 프로젝트 JSON 이 최신 버전 것만 주므로 요청 버전과 무관하게 최신 값이다(기존 동작 유지).
