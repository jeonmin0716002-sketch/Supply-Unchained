"""Supply-Unchained API 진입점 (Phase 2 통합판).

실행:
    uv run uvicorn api.main:app --reload
문서:
    http://localhost:8000/docs        (Swagger UI)
대시보드:
    http://localhost:8000/dashboard
pip 프록시:
    pip install --index-url http://localhost:8000/simple/ <pkg>
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from api.routers import proxy, scan
from api.storage import ScanStore

_DASHBOARD_HTML = Path(__file__).resolve().parents[1] / "dashboard" / "index.html"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 공유 커넥션 풀: OSV/PyPI 를 레이어마다 새로 연결하지 않도록 앱 수명과 함께 관리
    app.state.http = httpx.AsyncClient(
        timeout=httpx.Timeout(15.0),
        limits=httpx.Limits(max_connections=20),
        headers={"User-Agent": "supply-unchained/0.1 (+https://github.com/su-team)"},
    )
    app.state.store = ScanStore()
    await app.state.store.init()
    try:
        yield
    finally:
        await app.state.http.aclose()


app = FastAPI(
    title="Supply-Unchained API",
    version="0.2.0",
    description="pip 공급망 보안 스캐너 — CVE/OSV + 정적분석 + 위험도 스코어링 통합",
    lifespan=lifespan,
)

# --- Secure Design: 요청 본문 크기 제한 (DoS 방지) ---
# 이 API 의 모든 요청 본문은 name/version 문자열 몇 개뿐이다 (ScanRequest).
# 정상 요청이 이 크기를 넘을 이유가 없으므로, 거대한 body 로 메모리·파서를
# 고갈시키는 시도를 파싱 이전 단계에서 413 으로 잘라낸다.
# (프록시의 대용량 트래픽은 "응답" 스트리밍이라 이 제한과 무관하다.)
MAX_BODY_BYTES = 10 * 1024  # 10 KB


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            size = int(content_length)
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"error": "bad_request", "detail": "Content-Length 형식 오류"},
            )
        if size > MAX_BODY_BYTES:
            return JSONResponse(
                status_code=413,
                content={
                    "error": "payload_too_large",
                    "detail": f"요청 본문이 너무 큽니다 (최대 {MAX_BODY_BYTES} bytes)",
                },
            )
    return await call_next(request)


app.include_router(scan.router)
app.include_router(proxy.router)


@app.get("/health", tags=["meta"])
async def health() -> dict:
    return {"status": "ok"}


@app.get("/dashboard", include_in_schema=False)
async def dashboard() -> FileResponse:
    return FileResponse(_DASHBOARD_HTML, media_type="text/html")


@app.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse("/dashboard")
