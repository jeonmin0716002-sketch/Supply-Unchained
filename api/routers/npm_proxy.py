"""npm 레지스트리 프록시 — ``npm install --registry http://localhost:8000/npm/`` 를 게이트한다.

동작 (api/routers/proxy.py 의 pip 게이트와 같은 결정):

    1. npm 이 GET /npm/<name> (스코프는 /npm/@scope%2fname) 로 packument 를 요청 →
       registry.npmjs.org 원본을 받아 모든 버전의 ``dist.tarball`` 을
       ``<게이트>/npm/<name>/-/<파일명>`` 으로 바꿔 돌려준다. ``dist.integrity``·``shasum`` 은
       그대로 둔다 — 게이트는 원본 바이트를 그대로 흘려보내므로 npm 의 무결성 검사가 통과한다.
    2. npm 이 버전을 고르고 GET /npm/<name>/-/<파일명> 으로 타르볼을 요청 → 이때 이름과
       버전이 정해진다. **다운로드를 열기 전에** 통합 스캔(run_scan)을 돌린다.
    3. block → 403 + JSON 사유. npm install 은 실패하고 사유가 로그에 남는다.
       safe/warn → 원본을 스트리밍.

보안 결정:

* 원본 주소는 요청에서 받지 않는다. 게이트 경로의 (이름, 파일명)으로 packument 를 다시 읽어
  그 버전의 ``dist.tarball`` 을 쓴다 — 쿼리로 원본 URL 을 받는 pip 게이트보다 좁다. 그래도
  ``dist.tarball`` 의 호스트는 허용 목록(registry.npmjs.org)과 대조하고, 그 파일명이 요청
  파일명과 같아야 한다 ("안전한 A 를 스캔받고 B 를 받는" 우회 방지).
* 이름·버전을 확정하지 못하면 403 (fail-closed) — 파싱 안 되는 경로 하나로 게이트를
  건너뛰게 두지 않는다.
* 통합 파이프라인이 아직 npm 을 받지 못하면(ScanRequest 검증 실패) 스캔 불가 → 503.
  스캔하지 못한 패키지를 통과시키지 않는다 (설계 §2.3-2).
* 스코프 이름은 레지스트리로 보낼 때 ``@scope%2fname`` 으로 인코딩한다.

의도적으로 하지 않는 것: packument 단계 차단(버전을 모름), 캐시, ``npm audit`` 등
``/-/`` 하위 API 중계(404 — npm 은 경고만 내고 설치를 계속한다).
"""

from __future__ import annotations

import json
import os
from urllib.parse import quote, urlparse

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from api.routers import scan as scan_layer
from api.schemas import Verdict
from ecosystems.npm import ADAPTER
from ecosystems.npm.registry import MAX_PACKUMENT_BYTES, packument_url, tarball_filename

router = APIRouter(prefix="/npm", tags=["npm-proxy"])

#: 타르볼을 받아도 되는 원본 호스트 (오픈 프록시로 오용되는 것 방지)
ALLOWED_TARBALL_HOSTS = {"registry.npmjs.org"}


def build_scan_request(name: str, version: str):
    """통합 스캔 요청. 파이프라인이 npm 을 아직 모르면 ValueError (→ 503, 통과시키지 않음)."""
    from pydantic import ValidationError

    from api.schemas import ScanRequest

    try:
        return ScanRequest(ecosystem="npm", name=name, version=version)
    except ValidationError as exc:
        raise ValueError(str(exc)) from exc


def gate_base(request: Request) -> str:
    return str(request.base_url).rstrip("/") + router.prefix


def rewrite_packument(doc: dict, name: str, base: str) -> dict:
    """모든 버전의 dist.tarball 을 게이트 경로로. integrity·shasum 은 손대지 않는다."""
    versions = doc.get("versions")
    if not isinstance(versions, dict):
        return doc
    for meta in versions.values():
        dist = meta.get("dist") if isinstance(meta, dict) else None
        if not isinstance(dist, dict) or not isinstance(dist.get("tarball"), str):
            continue
        filename = tarball_filename(dist["tarball"])
        dist["tarball"] = f"{base}/{name}/-/{quote(filename)}"
    return doc


def parse_tarball_path(path: str) -> tuple[str, str, str] | None:
    """``@s/n/-/n-1.0.0.tgz`` → (이름, 버전, 파일명). 형식이 아니면 None."""
    name, sep, filename = path.rpartition("/-/")
    if not sep or "/" in filename or not filename.endswith(".tgz"):
        return None
    base = name.rsplit("/", 1)[-1]
    stem = filename[: -len(".tgz")]
    if not stem.startswith(base + "-"):
        return None
    version = stem[len(base) + 1:]
    try:
        ADAPTER.validate(name, version)
    except ValueError:
        return None
    return name, version, filename


async def _packument(http: httpx.AsyncClient, name: str) -> dict:
    resp = await http.get(packument_url(name), headers={"Accept": "application/json"},
                          follow_redirects=True)
    if resp.status_code == 404:
        raise HTTPException(status_code=404, detail=f"package not found: {name}")
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"npm registry returned {resp.status_code}")
    if len(resp.content) > MAX_PACKUMENT_BYTES:
        raise HTTPException(status_code=502, detail="packument too large")
    try:
        doc = resp.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="invalid packument") from exc
    if not isinstance(doc, dict):
        raise HTTPException(status_code=502, detail="invalid packument")
    return doc


def _unscanned_blocked(result) -> bool:
    """core-pipeline 이 붙이는 '정적분석 미완료' 판정 도우미가 있으면 따른다 (§2.3-2)."""
    helper = getattr(scan_layer, "static_incomplete", None)
    if helper is None or not helper(result):
        return False
    return os.environ.get("SU_UNSCANNED_POLICY", "block").lower() != "allow"


@router.get("/{path:path}", summary="npm 레지스트리 게이트 (packument 재작성 · 타르볼 스캔)")
async def npm_gate(request: Request, path: str) -> Response:
    path = path.strip("/")
    if not path or path.startswith("-/"):
        raise HTTPException(status_code=404, detail="not proxied")
    http: httpx.AsyncClient = request.app.state.http

    if "/-/" in path:
        return await _gated_tarball(request, http, path)

    # packument. npm 은 @scope%2fname 으로 보낸다 — 프레임워크가 %2f 를 풀어 둘 수도 있다.
    name = path.replace("%2f", "/").replace("%2F", "/")
    if not ADAPTER.NAME_RE.match(name) or ".." in name:
        raise HTTPException(status_code=400, detail=f"invalid npm package name: {name!r}")
    doc = await _packument(http, name)
    body = json.dumps(rewrite_packument(doc, name, gate_base(request)))
    return Response(content=body, media_type="application/json")


async def _gated_tarball(request: Request, http: httpx.AsyncClient, path: str) -> Response:
    parsed = parse_tarball_path(path.replace("%2f", "/").replace("%2F", "/"))
    if parsed is None:
        # fail-closed: 이름·버전을 확정할 수 없는 타르볼은 스캔할 수 없다
        raise HTTPException(status_code=403, detail=(
            f"타르볼 경로에서 name@version 을 읽지 못해 스캔할 수 없습니다: {path!r}. "
            "미검증 타르볼은 통과시키지 않습니다."))
    name, version, filename = parsed

    doc = await _packument(http, name)
    meta = (doc.get("versions") or {}).get(version)
    dist = meta.get("dist") if isinstance(meta, dict) else None
    upstream = dist.get("tarball") if isinstance(dist, dict) else None
    if not isinstance(upstream, str):
        raise HTTPException(status_code=404, detail=f"{name}@{version} not on npm")
    u = urlparse(upstream)
    if u.scheme != "https" or u.hostname not in ALLOWED_TARBALL_HOSTS:
        raise HTTPException(status_code=403, detail=f"disallowed tarball host: {u.hostname}")
    if tarball_filename(upstream) != filename:
        raise HTTPException(status_code=403, detail=(
            f"filename mismatch: path={filename!r} upstream={tarball_filename(upstream)!r}"))

    try:
        req = build_scan_request(name, version)
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=(
            "스캔 파이프라인이 npm 요청을 받지 못해 스캔할 수 없습니다 — 통과시키지 않습니다. "
            f"({str(exc)[:200]})")) from exc
    result = await scan_layer.run_scan(req, http=http, store=request.app.state.store)
    blocked = result.verdict is Verdict.BLOCK or _unscanned_blocked(result)
    if blocked:
        return JSONResponse(status_code=403, content={
            "error": "blocked_by_supply_unchained",
            "package": f"{name}@{version}",
            "verdict": result.verdict.value,
            "risk_score": result.risk_score,
            "reasons": result.verdict_reasons,
            "layer_errors": result.layer_errors,
            "scan_id": result.scan_id,
        })

    up = await http.send(http.build_request("GET", upstream), stream=True, follow_redirects=True)
    if up.status_code >= 400:
        await up.aclose()
        raise HTTPException(status_code=502, detail="upstream fetch failed")

    async def _stream():
        try:
            # 원본 바이트 그대로 (aiter_raw) — 디코딩하면 npm 의 integrity 검사가 깨질 수 있다
            async for chunk in up.aiter_raw():
                yield chunk
        finally:
            await up.aclose()

    headers = {k: v for k, v in up.headers.items()
               if k.lower() in {"content-type", "content-length", "content-encoding", "etag",
                                "last-modified"}}
    return StreamingResponse(_stream(), headers=headers)


__all__ = ["build_scan_request", "parse_tarball_path", "rewrite_packument", "router"]
