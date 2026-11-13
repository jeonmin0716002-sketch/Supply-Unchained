# 통합 노트 — eco-jvm-dotnet (maven · nuget)

## 요청 (소유 밖 파일)
- **inventory**: NuGet 프로젝트 파일(`*.csproj`/`*.fsproj`/`*.vbproj`)은 이름이 고정이 아니라
  `manifest_filenames` 정확 일치로 안 잡힌다. `ecosystems.get("nuget").handles_filename(name)` 을
  쓰거나 접미사를 직접 비교할 것. `parse_manifest(filename, text)` 는 접미사로도 동작한다.
- **core-pipeline**: maven 은 `Ecosystem.extract` 를 덮어쓴다(kind=="pom" 이면 압축이 아닌 POM
  본문을 `pom.xml` 로 씀). `select_artifacts` 는 `[jar, sources-jar]` 또는 `[pom]`, 검색 색인에
  정보가 없는 버전은 `[jar, pom]` 을 준다 — 아티팩트 하나의 다운로드 실패(jar 404)가 pom 분석을
  가리지 않게 처리하면 좋다(최신 버전은 HEAD 로 미리 걸러 둠).
- **core-pipeline(scan.py)**: 읽지 못한 파일은 `analyze_tree.unreadable`(함수 속성, 두 어댑터
  모두)에 남는다 — 필요하면 `layer_errors` 로 올릴 것.
- **popular-lists**: maven 인기 목록은 `groupId:artifactId` 형식이어야 `typosquat_score` 가 맞는다.
- **watch-dash**: maven 은 `has_feed=False`. Central 검색 API 의 `timestamp desc` 는 동작하지만
  색인이 수개월 뒤처져(2026-11 실측: 최신 항목 2026-06) 신규 업로드 감시에 쓸 수 없다.

## 한계·결정
- nuget: 사용자가 `1.0` 으로 넣어도 레지스트리 키는 `1.0.0` 이라 `Project.release("1.0")` 은 None.
  버전 정규화는 코어(PackageContext)나 `Ecosystem.normalize_version` 이 필요하다.
- nuget: 관리형 `.dll` 은 디컴파일하지 않고 UTF-16/ASCII 문자열에서 토큰 박힌 웹훅만 찾는다.
- maven: `.class` 는 상수 풀만 본다 (메서드 본문·`<clinit>` 호출 관계는 모름). static 초기화
  판단은 `-sources.jar` 의 `.java` 에만 적용된다. 업로드 시각은 Central 검색 API 의존(실패 시 None,
  `Project.extra["search_error"]`). 부모 POM(packaging=pom)의 build 플러그인만 HIGH 후보.
- 중첩 jar 는 한 단계, 최대 8개·25MB·5000항목. 한도 초과는 `maven-scan-truncated`(LOW)로 남긴다.
- 규칙 임계값은 인기 패키지 오탐으로만 확인했고 악성 데이터셋 탐지율은 재지 않았다.
