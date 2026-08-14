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
"""


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
