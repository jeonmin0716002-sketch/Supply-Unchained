"""pip 인덱스 프록시 — `PIP_INDEX_URL` 을 이쪽으로 돌려 설치 시점에 개입한다.

동작 방식 (PEP 503 Simple API 프록시):

    pip install --index-url http://localhost:8000/simple/ reqeusts

    1. pip 이 /simple/reqeusts/ 요청 → 프록시가 pypi.org/simple 원본을 가져와
       파일 링크(files.pythonhosted.org)를 전부
       /files/<파일명>?u=<원본URL> 로 재작성해 반환.
       (#sha256=... 프래그먼트는 보존 — pip 의 해시 검증은 그대로 동작.
        파일명을 경로에 남기는 이유는 rewrite_index_html docstring 참고)
    2. pip 이 버전을 결정하고 /files/<파일명>?u=... 로 실제 아카이브를 요청.
       이 시점에는 파일명에 정확한 버전이 있으므로, **다운로드를 열어주기 전에**
       해당 name==version 을 통합 스캔에 태운다.
    3. verdict 가 block 이면 403 + 판정 근거 반환 → pip 설치 실패로 이어짐.
       safe/warn 이면 원본 바이트를 그대로 스트리밍. (warn 을 어디까지 허용할지는
       팀 리뷰 대상 — 기본값은 "차단은 block 만, warn 은 통과+로그".)

의도적으로 안 하는 것:
    * 인덱스 페이지 단계(1)에서는 차단하지 않는다 — 그 시점엔 pip 이 어떤 버전을
      고를지 알 수 없어서, 버전 단위 판정이 불가능하기 때문.
    * 캐싱 없음 (MVP). 같은 파일 재설치는 재스캔된다.
"""

from __future__ import annotations

import re
from urllib.parse import quote, unquote, urlparse

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from api.routers import scan as scan_layer
from api.routers.scan import run_scan
from api.schemas import ScanRequest, Verdict

router = APIRouter(tags=["pip-proxy"])

UPSTREAM_SIMPLE = "https://pypi.org/simple"
#: 파일 다운로드를 허용할 원본 호스트 (오픈 프록시로 오용되는 것 방지)
ALLOWED_FILE_HOSTS = {"files.pythonhosted.org"}

_HREF_RE = re.compile(r'href="(?P<url>https://files\.pythonhosted\.org/[^"#]+)(?P<frag>#[^"]*)?"')

#: PEP 658/714 메타데이터 광고 속성. 이게 남아 있으면 pip 은 아카이브를 받지 않고
#: "링크 URL 문자열 끝에 ``.metadata`` 를 붙여" 별도 요청을 보낸다. 우리 링크는 원본 URL 을
#: 쿼리에 담으므로 그 접미사가 쿼리 값 안으로 들어가 깨진다(실제 pip 에서 400 확인).
#: 속성을 떼면 pip 은 아카이브를 직접 받으며, 이는 게이트 입장에선 오히려 바람직하다 —
#: 모든 다운로드가 예외 없이 스캔을 거친다. (해결책이 필요하면 .metadata 요청을
#: 별도 경로로 프록시하는 방식이 있으나 MVP 범위 밖.)
_METADATA_ATTR_RE = re.compile(r'\s+data-(?:core-metadata|dist-info-metadata)="[^"]*"')

# 파일명 → (name, version) 파싱
#   wheel : {name}-{version}(-{build})?-{python}-{abi}-{platform}.whl  (PEP 427)
#   sdist : {name}-{version}.tar.gz | .zip
_WHEEL_RE = re.compile(r"^(?P<name>.+?)-(?P<version>[^-]+)(-\d[^-]*)?-[^-]+-[^-]+-[^-]+\.whl$")
_SDIST_RE = re.compile(r"^(?P<name>.+?)-(?P<version>[^-]+)\.(?:tar\.gz|zip|tar\.bz2)$")


def parse_archive_filename(filename: str) -> tuple[str, str] | None:
    """아카이브 파일명에서 (패키지명, 버전) 추출. 실패 시 None."""
    m = _WHEEL_RE.match(filename) or _SDIST_RE.match(filename)
    if not m:
        return None
    return m.group("name"), m.group("version")


def rewrite_index_html(html: str, base_path: str = "/files") -> str:
    """simple 인덱스 HTML의 파일 링크를 프록시 게이트 경로로 재작성.

    **파일명은 반드시 경로 마지막 세그먼트에 남긴다.** pip 은 링크의 *경로*에서
    파일명을 뽑아 패키지명·버전·wheel 태그를 판단하기 때문이다. 원본 URL 을 쿼리에만
    담아 경로가 ``/files`` 로 끝나면 pip 은 모든 링크를 ``Skipping link: not a file``
    로 버리고 "from versions: none" 을 낸다 (실제 pip 으로 확인).

        https://files.pythonhosted.org/packages/../six-1.16.0.tar.gz#sha256=..
        → /files/six-1.16.0.tar.gz?u=<원본URL 인코딩>#sha256=..
    """

    def _sub(m: re.Match) -> str:
        url = m.group("url")
        filename = url.rsplit("/", 1)[-1]
        frag = m.group("frag") or ""
        # 순서 주의: 경로 → 쿼리 → 프래그먼트. 해시 검증 프래그먼트는 맨 뒤에 와야 한다.
        return f'href="{base_path}/{quote(filename)}?u={quote(url, safe="")}{frag}"'

    return _HREF_RE.sub(_sub, _METADATA_ATTR_RE.sub("", html))


# ──────────────────────────────
# 오프라인 데모용 인덱스 합성
# ──────────────────────────────
#
# 데모용 typosquat 이름들(scan.DEMO_MALICIOUS)은 실제 악성 패키지였기에 PyPI 에서 이미
# 삭제됐다 — /simple/reqeusts/ 는 404 다. 그래서 업스트림을 프록시하는 정상 경로로는
# "pip install 이 차단되는" 장면을 시연할 수 없다(인덱스 단계에서 이미 죽으므로 게이트까지
# 도달조차 못 한다). SU_OFFLINE_DEMO 에서는 그 이름들의 인덱스 페이지를 합성해 pip 을
# 게이트까지 보내고, 판정은 scan 레이어의 데모 mock 이 block 을 낸다.
#
# 합성 링크의 u= 는 실제로 조회되지 않는다: 데모 대상은 전부 block 이라 스트리밍 이전에
# 403 으로 끝난다. 호스트를 files.pythonhosted.org 로 두는 것은 게이트의 호스트 검사를
# 통과시키기 위한 것이다.

DEMO_VERSION = "1.0.0"


def demo_index_html(name: str, base_path: str = "/files") -> str:
    """데모 패키지용 PEP 503 인덱스 페이지 합성 (네트워크 불필요)."""
    filename = f"{name}-{DEMO_VERSION}.tar.gz"
    upstream = f"https://files.pythonhosted.org/packages/su-demo/{filename}"
    return (
        "<!DOCTYPE html>\n<html><body>\n"
        f"<h1>Links for {name}</h1>\n"
        f'<a href="{base_path}/{quote(filename)}?u={quote(upstream, safe="")}">'
        f"{filename}</a><br />\n"
        "</body></html>\n"
    )


@router.get("/simple/", summary="pip simple 인덱스 루트 (프록시)")
@router.get("/simple/{name}/", summary="패키지 인덱스 페이지 (프록시 + 링크 재작성)")
async def simple_index(request: Request, name: str | None = None) -> Response:
    if name and scan_layer.OFFLINE_DEMO and name in scan_layer.DEMO_MALICIOUS:
        return Response(content=demo_index_html(name), media_type="text/html")

    http = request.app.state.http
    upstream = f"{UPSTREAM_SIMPLE}/{name}/" if name else f"{UPSTREAM_SIMPLE}/"
    # PEP 691(JSON) 대신 HTML v1 을 요청 — 재작성 로직을 한 포맷으로 유지
    resp = await http.get(
        upstream,
        headers={"Accept": "text/html"},
        follow_redirects=True,
    )
    if resp.status_code == 404:
        raise HTTPException(status_code=404, detail=f"package index not found: {name}")
    resp.raise_for_status()
    return Response(
        content=rewrite_index_html(resp.text),
        media_type="text/html",
    )


@router.get("/files/{filename}", summary="아카이브 다운로드 게이트 (스캔 후 통과/차단)")
async def gated_file(
    request: Request,
    filename: str,
    u: str = Query(description="원본 파일 URL"),
) -> Response:
    upstream_url = unquote(u)
    parsed = urlparse(upstream_url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_FILE_HOSTS:
        raise HTTPException(status_code=400, detail="disallowed upstream host")

    # 경로의 파일명이 판정 대상을 결정하므로, 업스트림 파일명과 반드시 일치해야 한다.
    # 어긋나면 "안전한 A 를 스캔받고 악성 B 를 내려받는" 게이트 우회가 가능해진다.
    upstream_filename = parsed.path.rsplit("/", 1)[-1]
    if filename != upstream_filename:
        raise HTTPException(
            status_code=400,
            detail=f"filename mismatch: path={filename!r} upstream={upstream_filename!r}",
        )

    parsed_name = parse_archive_filename(filename)

    if parsed_name is not None:
        name, version = parsed_name
        result = await run_scan(
            ScanRequest(name=name, version=version),
            http=request.app.state.http,
            store=request.app.state.store,
        )
        if result.verdict is Verdict.BLOCK:
            # pip 에게는 다운로드 실패로 보이고, 사유는 본문에 남는다.
            return JSONResponse(
                status_code=403,
                content={
                    "error": "blocked_by_supply_unchained",
                    "package": f"{name}=={version}",
                    "risk_score": result.risk_score,
                    "reasons": result.verdict_reasons,
                    "scan_id": result.scan_id,
                },
            )
        # safe/warn → 통과. warn 은 스캔 이력(대시보드)에서 확인 가능.

    # 파일명 파싱 실패 시 정책 (팀 리뷰 대상): 현재는 스캔 없이 통과 + 주의.
    # fail-closed 로 바꾸려면 여기서 403 을 반환하면 된다.

    http = request.app.state.http
    upstream = await http.send(
        http.build_request("GET", upstream_url), stream=True, follow_redirects=True
    )
    if upstream.status_code >= 400:
        await upstream.aclose()
        raise HTTPException(status_code=upstream.status_code, detail="upstream fetch failed")

    async def _stream():
        try:
            async for chunk in upstream.aiter_bytes():
                yield chunk
        finally:
            await upstream.aclose()

    passthrough = {
        k: v
        for k, v in upstream.headers.items()
        if k.lower() in {"content-type", "content-length", "etag", "last-modified"}
    }
    return StreamingResponse(_stream(), headers=passthrough)
