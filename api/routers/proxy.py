"""pip 인덱스 프록시 — `PIP_INDEX_URL` 을 이쪽으로 돌려 설치 시점에 개입한다.

동작 방식 (PEP 503 Simple API 프록시):

    pip install --index-url http://localhost:8000/simple/ reqeusts

    1. pip 이 /simple/reqeusts/ 요청 → 프록시가 pypi.org/simple 원본을 가져와
       파일 링크(files.pythonhosted.org)를 전부 /files?u=<원본URL> 로 재작성해 반환.
       (#sha256=... 프래그먼트는 보존 — pip 의 해시 검증은 그대로 동작)
    2. pip 이 버전을 결정하고 /files?u=... 로 실제 아카이브를 요청.
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

from api.routers.scan import run_scan
from api.schemas import ScanRequest, Verdict

router = APIRouter(tags=["pip-proxy"])

UPSTREAM_SIMPLE = "https://pypi.org/simple"
#: 파일 다운로드를 허용할 원본 호스트 (오픈 프록시로 오용되는 것 방지)
ALLOWED_FILE_HOSTS = {"files.pythonhosted.org"}

_HREF_RE = re.compile(r'href="(?P<url>https://files\.pythonhosted\.org/[^"#]+)(?P<frag>#[^"]*)?"')

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
    """simple 인덱스 HTML의 파일 링크를 프록시 게이트 경로로 재작성."""

    def _sub(m: re.Match) -> str:
        url = quote(m.group("url"), safe="")
        frag = m.group("frag") or ""
        return f'href="{base_path}?u={url}{frag}"'

    return _HREF_RE.sub(_sub, html)


@router.get("/simple/", summary="pip simple 인덱스 루트 (프록시)")
@router.get("/simple/{name}/", summary="패키지 인덱스 페이지 (프록시 + 링크 재작성)")
async def simple_index(request: Request, name: str | None = None) -> Response:
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


@router.get("/files", summary="아카이브 다운로드 게이트 (스캔 후 통과/차단)")
async def gated_file(request: Request, u: str = Query(description="원본 파일 URL")) -> Response:
    upstream_url = unquote(u)
    parsed = urlparse(upstream_url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_FILE_HOSTS:
        raise HTTPException(status_code=400, detail="disallowed upstream host")

    filename = parsed.path.rsplit("/", 1)[-1]
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
