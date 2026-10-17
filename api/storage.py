"""SQLite persistence for scan results (MVP data layer).

README's data design starts with "경량 관계형 DB(SQLite)로 시작 → 필요 시
PostgreSQL 전환". This module is that start, scoped to what the API/dashboard
actually needs today:

  * ``scan_id`` in the response is now a real ``scans.id`` row (the schema
    already promised "DB SCAN_RESULT와 1:1 대응" — this makes it true).
  * The dashboard's history view reads from here (GET /api/v1/scans).

The full normalized ERD (VULNERABILITY / STATIC_FINDING / RISK_PROFILE tables)
is deferred: the whole response is stored as one JSON column instead, which is
enough for history + re-display and keeps this file trivially replaceable by
SQLAlchemy + PostgreSQL later. Splitting into normalized tables only pays off
once something *queries* across scans (e.g. "all packages with CWE-94"), which
nothing does yet.

stdlib ``sqlite3`` is synchronous; calls are wrapped in ``asyncio.to_thread``
so scan handlers never block the event loop on disk I/O.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from pathlib import Path

DEFAULT_DB_PATH = "data/supply_unchained.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem     TEXT NOT NULL,
    name          TEXT NOT NULL,
    version       TEXT NOT NULL,
    verdict       TEXT NOT NULL,
    risk_score    INTEGER NOT NULL,
    scanned_at    TEXT NOT NULL,
    response_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_pkg ON scans (name, version);
CREATE INDEX IF NOT EXISTS idx_scans_time ON scans (scanned_at DESC);

-- PyPI 감시기(watcher/) — 이미 스캔한 릴리스와, 사람이 확인할 의심 패키지 큐
CREATE TABLE IF NOT EXISTS watch_seen (
    name     TEXT NOT NULL,
    version  TEXT NOT NULL,
    seen_at  TEXT NOT NULL,
    PRIMARY KEY (name, version)
);
CREATE TABLE IF NOT EXISTS watch_queue (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans (id),
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    risk_score  INTEGER NOT NULL,
    status      TEXT NOT NULL DEFAULT 'new',
    note        TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_watch_queue_status ON watch_queue (status, id DESC);
"""
# watch_queue.status 값은 api/routers/watch.py 의 WatchStatus 가 정의한다.
# 오탐(false_positive) 기록은 지우지 않는다 — 임계값 튜닝의 실측 데이터다.


def db_path() -> str:
    return os.environ.get("SU_DB_PATH", DEFAULT_DB_PATH)


class ScanStore:
    """Tiny DAO around the scans table. One instance lives on app.state."""

    def __init__(self, path: str | None = None) -> None:
        self._path = path or db_path()

    # ── sync internals (run in a worker thread) ──────────────────────

    def _connect(self) -> sqlite3.Connection:
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        # pip 프록시 게이트가 살아나면서 병렬 다운로드마다 스캔+쓰기가 동시에 들어온다.
        # 기본 busy timeout 만으로는 "database is locked" 가 바로 나므로 명시적으로 준다.
        conn = sqlite3.connect(self._path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            # WAL 은 DB 파일에 한 번 기록되면 유지되는 설정이라 init 에서만 켜면 된다.
            # 읽기(대시보드 이력)가 쓰기(진행 중 스캔)를 막지 않게 하는 것이 목적.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)

    def _insert(self, record: dict) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO scans (ecosystem, name, version, verdict, risk_score,"
                " scanned_at, response_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    record["ecosystem"],
                    record["name"],
                    record["version"],
                    record["verdict"],
                    record["risk_score"],
                    record["scanned_at"],
                    json.dumps(record, ensure_ascii=False),
                ),
            )
            return int(cur.lastrowid)

    def _finalize(self, scan_id: int, record: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET response_json = ? WHERE id = ?",
                (json.dumps(record, ensure_ascii=False), scan_id),
            )

    def _recent(self, limit: int) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT response_json FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [json.loads(r["response_json"]) for r in rows]

    def _get(self, scan_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT response_json FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
        return json.loads(row["response_json"]) if row else None

    def _unseen(self, items: list[tuple[str, str]]) -> list[tuple[str, str]]:
        with self._connect() as conn:
            return [
                (n, v)
                for n, v in items
                if conn.execute(
                    "SELECT 1 FROM watch_seen WHERE name = ? AND version = ?", (n, v)
                ).fetchone()
                is None
            ]

    def _seen_names(self, names: list[str]) -> set[str]:
        with self._connect() as conn:
            return {
                n
                for n in names
                if conn.execute("SELECT 1 FROM watch_seen WHERE name = ? LIMIT 1", (n,)).fetchone()
            }

    def _mark_seen(self, name: str, version: str, now: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO watch_seen (name, version, seen_at) VALUES (?, ?, ?)",
                (name, version, now),
            )

    def _enqueue(self, record: dict, now: str) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO watch_queue (scan_id, name, version, verdict, risk_score,"
                " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    record["scan_id"],
                    record["name"],
                    record["version"],
                    record["verdict"],
                    record["risk_score"],
                    now,
                    now,
                ),
            )
            return int(cur.lastrowid)

    def _enqueue_removed(self, name: str, version: str, now: str) -> bool:
        with self._connect() as conn:
            if conn.execute(
                "SELECT 1 FROM watch_queue WHERE name = ? AND verdict = 'removed'", (name,)
            ).fetchone():
                return False
            conn.execute(
                "INSERT INTO watch_queue (scan_id, name, version, verdict, risk_score,"
                " created_at, updated_at) VALUES (0, ?, ?, 'removed', 0, ?, ?)",
                (name, version, now, now),
            )
            return True

    def _queue(self, status: str | None, limit: int) -> list[dict]:
        sql = "SELECT * FROM watch_queue"
        args: tuple = ()
        if status:
            sql += " WHERE status = ?"
            args = (status,)
        sql += " ORDER BY id DESC LIMIT ?"
        with self._connect() as conn:
            rows = conn.execute(sql, (*args, limit)).fetchall()
        return [dict(r) for r in rows]

    def _queued_records(self, name: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT s.response_json FROM watch_queue q JOIN scans s ON s.id = q.scan_id"
                " WHERE q.name = ?",
                (name,),
            ).fetchall()
        return [json.loads(r["response_json"]) for r in rows]

    def _update_queue(
        self, item_id: int, status: str, note: str | None, now: str
    ) -> dict | None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE watch_queue SET status = ?, note = COALESCE(?, note), updated_at = ?"
                " WHERE id = ?",
                (status, note, now, item_id),
            )
            row = conn.execute("SELECT * FROM watch_queue WHERE id = ?", (item_id,)).fetchone()
        return dict(row) if row else None

    # ── async facade used by the routers ─────────────────────────────

    async def init(self) -> None:
        await asyncio.to_thread(self._init)

    async def insert(self, record: dict) -> int:
        """Insert a scan and return its DB id (used as the response scan_id)."""
        return await asyncio.to_thread(self._insert, record)

    async def finalize(self, scan_id: int, record: dict) -> None:
        """Re-store the record once scan_id has been stamped into it."""
        await asyncio.to_thread(self._finalize, scan_id, record)

    async def recent(self, limit: int = 50) -> list[dict]:
        return await asyncio.to_thread(self._recent, limit)

    async def get(self, scan_id: int) -> dict | None:
        return await asyncio.to_thread(self._get, scan_id)

    # ── PyPI 감시기 ──────────────────────────────────────────────────

    async def unseen(self, items: list[tuple[str, str]]) -> list[tuple[str, str]]:
        """아직 스캔하지 않은 (name, version) 만 순서를 지켜 돌려준다."""
        return await asyncio.to_thread(self._unseen, items)

    async def seen_names(self, names: list[str]) -> set[str]:
        """이 중 어떤 버전이든 한 번이라도 스캔한 이름."""
        return await asyncio.to_thread(self._seen_names, names)

    async def mark_seen(self, name: str, version: str, now: str) -> None:
        await asyncio.to_thread(self._mark_seen, name, version, now)

    async def enqueue(self, record: dict, now: str) -> int:
        """스캔 결과(run_scan 응답 dict)를 검토 큐에 넣는다."""
        return await asyncio.to_thread(self._enqueue, record, now)

    async def enqueue_removed(self, name: str, version: str, now: str) -> bool:
        """피드에 보였는데 스캔 전에 PyPI 에서 사라진 패키지 — 패키지당 한 번만 넣는다.
        scan_id 는 0 (스캔할 아카이브가 이미 없다). 새로 넣었으면 True."""
        return await asyncio.to_thread(self._enqueue_removed, name, version, now)

    async def queue(self, status: str | None = None, limit: int = 100) -> list[dict]:
        return await asyncio.to_thread(self._queue, status, limit)

    async def queued_records(self, name: str) -> list[dict]:
        """이 패키지가 큐에 오른 적이 있으면 그때의 스캔 결과들 (상태 무관)."""
        return await asyncio.to_thread(self._queued_records, name)

    async def update_queue(
        self, item_id: int, status: str, note: str | None, now: str
    ) -> dict | None:
        """상태를 바꾼다. note 가 None 이면 기존 메모를 유지한다."""
        return await asyncio.to_thread(self._update_queue, item_id, status, note, now)
