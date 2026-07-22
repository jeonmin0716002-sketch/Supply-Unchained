"""Supply-Unchained API 데모 진입점

실행:
    uvicorn api.main:app --reload
문서:
    http://localhost:8000/docs  (Swagger UI — 스키마 합의할 때 이 화면 보면서 하면 편함)
"""

from fastapi import FastAPI

from api.routers import scan

app = FastAPI(
    title="Supply-Unchained API",
    version="0.1.0-demo",
    description="pip 공급망 보안 스캐너 — API 스키마 합의용 데모 (엔진은 mock)",
)

app.include_router(scan.router)


@app.get("/health", tags=["meta"])
async def health() -> dict:
    return {"status": "ok"}
