"""PyPI 감시기 검토 큐 — 대시보드가 의심 패키지를 보고 사람이 판정을 기록하는 곳.

감시 자체(피드 수집·스캔)는 이 서버가 아니라 ``su_scan watch`` 프로세스가 돌린다.
API 서버에 백그라운드 루프를 두지 않은 이유: 감시는 하루 종일 외부 업로드를 받아 푸는
작업이라 pip 프록시·대시보드와 수명을 묶으면 한쪽 장애가 다른 쪽을 끌고 간다.
둘은 같은 SQLite 만 공유한다.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from api.schemas import ErrorResponse

router = APIRouter(prefix="/api/v1/watch", tags=["watch"])

WatchStatus = Literal["new", "malicious", "false_positive", "reported"]


class QueueItem(BaseModel):
    id: int
    scan_id: int
    name: str
    version: str
    verdict: str
    risk_score: int
    status: WatchStatus
    note: str
    created_at: str
    updated_at: str


class QueueUpdate(BaseModel):
    status: WatchStatus
    note: str | None = Field(default=None, max_length=500, description="비우면 기존 메모 유지")


@router.get("/queue", response_model=list[QueueItem], summary="감시기 검토 큐")
async def list_queue(
    request: Request,
    status: Annotated[WatchStatus | None, Query(description="비우면 전체")] = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[QueueItem]:
    rows = await request.app.state.store.queue(status, limit)
    return [QueueItem.model_validate(r) for r in rows]


@router.patch(
    "/queue/{item_id}",
    response_model=QueueItem,
    responses={404: {"model": ErrorResponse}},
    summary="검토 결과 기록 (악성 확인 · 오탐 · 신고 완료)",
)
async def update_queue(item_id: int, body: QueueUpdate, request: Request) -> QueueItem:
    now = datetime.now(UTC).isoformat(timespec="seconds")
    row = await request.app.state.store.update_queue(item_id, body.status, body.note, now)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "queue_item_not_found", "detail": f"item {item_id} 없음"},
        )
    return QueueItem.model_validate(row)
