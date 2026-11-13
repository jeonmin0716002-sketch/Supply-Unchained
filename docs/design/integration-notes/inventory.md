# inventory 세션 → 통합 요청

* `engine/cve_matcher.py`: `_parse_severity`, `_parse_fixed_version` 이 private 이라 `inventory/osv_batch.py` 가
  그대로 import 해서 쓴다. 공개 이름(`parse_severity`, `parse_fixed_version`)으로 노출해 주면 좋다.
  `_parse_fixed_version` 의 이름 정규화는 PEP 503 이라 다른 생태계에서 이름이 다르면 fixed 가 비게 된다
  (그때는 fast 모드가 "수정 버전 불명"으로 보고한다 — 오탐 아님).
* 통합 시 `ecosystems/pip/__init__.py` (core-pipeline 소유)가 `from ecosystems.pip.manifests import
  MANIFEST_FILENAMES, parse_manifest` 로 `manifest_filenames`·`parse_manifest` 를 연결해야 한다.
* `cli/su_scan.py` 에 guarded `register(app)` 가 있어야 `su-scan project|sbom` 이 붙는다 (설계 문서 §3.1).
