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
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

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
MAX_BODY_BYTES = 10 * 1024


class RequestBodyRejected(HTTPException):
    """본문 크기 정책 위반. HTTPException 을 상속하는 게 핵심이다.

    FastAPI 는 ``await request.body()`` 를 감싼 try 에서 ``except Exception`` 으로
    아무 예외나 400 "There was an error parsing the body" 로 바꿔버린다. 그 바로 위에
    ``except HTTPException: raise`` 가 있고 주석까지 "미들웨어가 던진 HTTPException 은
    다시 올려보낸다"라고 달려 있으니, 이 계층을 타야 413 이 그대로 나간다.
    """

    def __init__(self, status_code: int, error: str, detail: str) -> None:
        super().__init__(status_code=status_code, detail=detail)
        self.error = error


def _rejection_response(exc: RequestBodyRejected) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.error, "detail": exc.detail},
    )


class BodySizeLimitMiddleware:
    """본문 크기 제한 — Content-Length 선검사 + **실제 수신 바이트** 누적 검사.

    Content-Length 만 보면 헤더 하나로 우회된다: ``Transfer-Encoding: chunked`` 요청에는
    Content-Length 가 아예 없어서 검사를 그냥 통과하고, 본문 전량이 그대로 메모리에
    올라간다 — 막으려던 DoS 경로가 열려 있는 셈이었다. 그래서 ASGI ``receive`` 를 감싸
    도착한 바이트를 세고, 상한을 넘는 순간 끊는다. 헤더 검사는 큰 요청을 읽기도 전에
    되돌려보내는 빠른 경로로 남겨둔다.

    ``@app.middleware("http")`` (BaseHTTPMiddleware) 가 아니라 순수 ASGI 미들웨어인
    이유는 그쪽에서는 ``receive`` 를 감쌀 수 없기 때문이다.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = Headers(scope=scope).get("content-length")
        if declared is not None:
            try:
                size = int(declared)
            except ValueError:
                size = -1
            if size < 0:
                # 길이를 신뢰할 수 없으면 통과시키지 않는다.
                await _rejection_response(
                    RequestBodyRejected(400, "bad_request", "Content-Length 형식 오류")
                )(scope, receive, send)
                return
            if size > self.max_bytes:
                # 아직 아무것도 안 보냈으므로 앱을 부르지 않고 여기서 끝낸다.
                await _rejection_response(
                    RequestBodyRejected(
                        413,
                        "payload_too_large",
                        f"요청 본문이 너무 큽니다 (최대 {self.max_bytes} bytes)",
                    )
                )(scope, receive, send)
                return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise RequestBodyRejected(
                        413,
                        "payload_too_large",
                        f"요청 본문이 너무 큽니다 (최대 {self.max_bytes} bytes)",
                    )
            return message

        await self.app(scope, limited_receive, send)


app.add_middleware(BodySizeLimitMiddleware, max_bytes=MAX_BODY_BYTES)
# 미들웨어보다 안쪽(ExceptionMiddleware)에서 잡아 413 본문을 만든다.
app.add_exception_handler(
    RequestBodyRejected,
    lambda request, exc: _rejection_response(exc),  # type: ignore[arg-type]
)

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
