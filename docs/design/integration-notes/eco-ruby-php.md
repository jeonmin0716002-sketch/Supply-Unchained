# eco-ruby-php 통합 요청·한계

## 다른 파일에 필요한 변경 (소유자 몫)
1. **`ecosystems/base.py` — NAME_RE·VERSION_RE 의 `$`**: `$` 는 문자열 끝의 개행 앞에서도 맞아
   `"name\n"` 이 통과한다. 두 어댑터는 `\Z` 로 자체 정규식을 쓰지만, 기본값을 쓰는 어댑터
   (npm·cargo·go 등)는 같은 구멍이 있다. 기본 정규식 끝을 `\Z` 로(또는 `validate` 에서 `fullmatch`).
2. **프록시·스캔이 `Artifact.size` 를 모른다**: rubygems `versions.json` 에 크기가 없어 `size=0`.
   `common.pypi.download` 의 30MB 상한은 Content-Length 로 막는다 (libv8-node 의 사전 빌드 gem 48MB 는
   `ArchiveError` — "못 봤다"로 보고되어 안전하게 실패).
3. `ecosystems/data/popular/rubygems.txt`·`composer.txt` 는 popular-lists 세션 몫 (composer 이름은 소문자 `vendor/pkg`).

## 설계 결정·알려진 한계
- rubygems `.gem` 추출 결과: `data.tar.gz` 내용이 루트, gemspec 메타데이터는 `_gem_metadata.yml`.
- rubygems `select_artifacts`: 순수 ruby gem + 플랫폼 gem 최대 8개. 플랫폼 gem 이 더 있으면 나머지는 안 본다.
- Ruby·PHP 스캐너는 어휘 수준이다(주석·문자열·heredoc 처리, def/function 본문 제외, 같은 파일 헬퍼 추적).
  `{ }` 블록 안 def, endless def 변형, 보간 안 중첩 따옴표, 동적 호출(`send`, 변수 함수) 난독화는 못 따라간다.
- rubygems: 네트워크 호출이 extconf 최상단에 있으면 HIGH (라이브러리 소스를 내려받는 정상 gem 도
  걸릴 수 있다 — 인기 gem 22종 실측에선 없었음).
- composer: dist `shasum` 은 대부분 비어 있고 sha1 이라 `Artifact.sha256` 은 None.
- composer 피드는 버전을 주지 않아 `(name, None)` — 감시기가 최신 버전을 조회해야 한다.
