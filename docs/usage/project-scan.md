# 프로젝트·SBOM 스캔

```bash
su-scan project .                       # 디렉터리의 모든 lockfile/manifest (fast)
su-scan project . --mode full           # + 패키지별 전체 파이프라인(정적분석·메타데이터)
su-scan project . --format cyclonedx --output sbom.cdx.json
su-scan sbom bom.json --fail-on vuln-high
python -m cli.project_cmd project .     # 단독 실행
```

종료 코드: 0 통과 · 1 `--fail-on` 기준 실패(OSV 조회 오류 포함) · 2 입력·환경 오류.
`--fail-on`: `block`(기본) · `warn` · `vuln-high` · `vuln-critical`.
`--format`: `table` · `json` · `cyclonedx`(1.5, purl·vulnerabilities·판정 속성 포함).

## 읽는 파일

- pip: `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `pdm.lock`, `pyproject.toml`
- 그 밖의 생태계(npm·cargo·go·maven·rubygems·nuget·composer)는 각 어댑터의 `manifest_filenames` 를
  따른다 — 어댑터가 있는 생태계만 읽는다.
- SBOM: CycloneDX JSON 1.4~1.6, SPDX JSON 2.3 (purl 기준). 어댑터가 없는 purl 은 보고서에 남는다.
- 같은 디렉터리·생태계에 lockfile 과 manifest 가 둘 다 있으면 lockfile 만 읽는다.
- `.git`·`node_modules`·가상환경·`vendor`·`build`·`dist` 등은 건너뛰고, 깊이 8, 파일 8MB 로 제한하며
  심볼릭 링크는 따라가지 않는다. 프로젝트의 코드는 실행하지 않는다.

## fast 와 full

- **fast**: OSV 일괄 조회(알려진 취약점)만. 악성 코드·타이포스쿼팅·메타데이터는 **보지 않는다**.
  아직 취약점으로 등록되지 않은 신규 악성 패키지는 fast 로는 잡히지 않는다.
- **full**: fast + 정확한 버전이 있는 의존성마다 전체 스캔(레지스트리 다운로드 포함, 느림).
- 정확한 버전이 없는(미고정) 의존성은 `not checked — unpinned` 로 따로 보고한다. 조용히 건너뛰지 않는다.
- OSV·전체 스캔이 실패한 의존성은 "깨끗함"이 아니라 ERROR 이며 게이트를 실패시킨다.
- 직접 의존성만 담긴 `pyproject.toml`/`requirements.txt` 는 전이 의존성을 풀지 않는다 — lockfile 을 쓰자.

## CI 예시

```yaml
- run: uv run python -m cli.su_scan project . --fail-on vuln-high --format json --output scan.json
- uses: actions/upload-artifact@v4
  with: { name: scan, path: scan.json }
```
