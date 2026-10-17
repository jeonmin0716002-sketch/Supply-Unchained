"""OpenSSF 악성 패키지 DB 와 감시 결과 대조 — 운영 환경에서의 실제 탐지율.

데이터셋 평가(tools/eval_malware_dataset.py)는 과거 샘플로 엔진을 잰다. 이건 **감시기가
돌던 동안 실제로 올라온** 악성 패키지를 놓쳤는지 잰다. 보안 업계가 공동으로 운영하는
OpenSSF malicious-packages 가 OSV 에 `MAL-` ID 로 공개되므로, 그 목록에서 감시 기간에
탐지된 PyPI 항목을 골라 우리 DB(스캔·큐·삭제 기록)와 맞춘다.

목록은 OSV 버킷의 ``PyPI/modified_id.csv`` (수정 시각 역순, 토큰 불필요)에서 `MAL-` 만
고르고, 각 ID 의 상세는 api.osv.dev 에서 받는다.

"감시 기간에 올라왔는가"의 판단: 아직 PyPI 에 남아 있으면 해당 버전들의 **실제 업로드
시각**을 쓴다. 이미 지워졌으면 업로드 시각을 알 수 없어서, 신고 출처들이 처음 탐지한
시각(``malicious-packages-origins`` 의 가장 이른 ``modified_time``)을 대신 쓴다 — 탐지는
업로드보다 늦으므로 이 근사는 감시 기간에 넣는 쪽으로 기운다. 실측: pyyi 는 감시 중에
탐지됐지만 업로드는 사흘 전이었다.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime

import httpx

INDEX_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/modified_id.csv"
VULN_URL = "https://api.osv.dev/v1/vulns/{id}"


@dataclass
class Report:
    mal_id: str
    name: str
    detected_at: str            # 업로드 시각, 지워졌으면 최초 탐지 시각 (괄호에 근거)
    status: str                 # caught | removed | missed | unseen
    detail: str = ""


def _parse_ts(value: str) -> datetime:
    # OSV 는 나노초까지 준다 — fromisoformat 이 받는 마이크로초로 자른다
    head, _, frac = value.rstrip("Z").partition(".")
    return datetime.fromisoformat(f"{head}.{(frac or '0')[:6]}+00:00")


async def _recent_mal_ids(http: httpx.AsyncClient, since: datetime) -> list[str]:
    resp = await http.get(INDEX_URL)
    resp.raise_for_status()
    out = []
    for row in csv.reader(io.StringIO(resp.text)):
        if len(row) != 2:
            continue
        modified, vuln_id = row
        if _parse_ts(modified) < since:
            break  # 수정 시각 역순이라 여기서부터는 전부 오래된 것
        if vuln_id.startswith("MAL-"):
            out.append(vuln_id)
    return out


def _detected_at(vuln: dict) -> str:
    origins = (vuln.get("database_specific") or {}).get("malicious-packages-origins") or []
    times = [o["modified_time"] for o in origins if o.get("modified_time")]
    return min(times) if times else vuln.get("published", "")


def _our_status(db: sqlite3.Connection, name: str) -> tuple[str, str]:
    q = db.execute(
        "SELECT verdict, status FROM watch_queue WHERE lower(name) = lower(?)", (name,)
    ).fetchall()
    if any(v == "removed" for v, _ in q):
        return "removed", "스캔 전에 PyPI 에서 삭제된 것을 감지"
    if q:
        return "caught", f"감시 큐 등록 ({', '.join(sorted({s for _, s in q}))})"
    scans = db.execute(
        "SELECT version, verdict, response_json FROM scans WHERE lower(name) = lower(?)",
        (name,),
    ).fetchall()
    if scans:
        rules = set()
        for _, _, raw in scans:
            rules |= {f["rule"] for f in json.loads(raw)["static_findings"]}
        seen = ", ".join(f"{v}={verdict}" for v, verdict, _ in scans[:3])
        return "missed", f"스캔했지만 큐에 안 올림 ({seen}; 규칙 {sorted(rules) or '없음'})"
    return "unseen", "감시기 기록 없음"


async def crosscheck(db_path: str, since: datetime, concurrency: int = 8) -> list[Report]:
    db = sqlite3.connect(db_path)
    async with httpx.AsyncClient(timeout=60, follow_redirects=True) as http:
        ids = await _recent_mal_ids(http, since)
        sem = asyncio.Semaphore(concurrency)

        async def one(vuln_id: str) -> dict | None:
            async with sem:
                resp = await http.get(VULN_URL.format(id=vuln_id))
                return resp.json() if resp.status_code == 200 else None

        vulns = [v for v in await asyncio.gather(*(one(i) for i in ids)) if v]

        async def first_upload(name: str, versions: list[str]) -> str | None:
            async with sem:
                resp = await http.get(f"https://pypi.org/pypi/{name}/json")
            if resp.status_code != 200:
                return None  # 지워졌다 — 업로드 시각을 알 수 없다
            releases = resp.json().get("releases") or {}
            times = [f["upload_time_iso_8601"] for v in (versions or releases)
                     for f in releases.get(v, []) if f.get("upload_time_iso_8601")]
            return min(times) if times else None

        candidates = []
        for v in vulns:
            pypi = [a for a in v.get("affected", []) if a["package"]["ecosystem"] == "PyPI"]
            if pypi:
                candidates.append((v, pypi[0]["package"]["name"], pypi[0].get("versions") or []))
        uploads = await asyncio.gather(*(first_upload(n, vs) for _, n, vs in candidates))

    reports = []
    for (v, name, _), uploaded in zip(candidates, uploads, strict=True):
        when = uploaded or _detected_at(v)
        if not when or _parse_ts(when) < since:
            continue  # 감시 시작 전에 올라왔다 (또는 그 전에 이미 탐지됐다)
        status, detail = _our_status(db, name)
        basis = "업로드" if uploaded else "최초 탐지"
        reports.append(Report(v["id"], name, f"{when[:16]} ({basis})", status, detail))
    return sorted(reports, key=lambda r: r.detected_at)


def watcher_start(db_path: str) -> datetime | None:
    row = sqlite3.connect(db_path).execute("SELECT min(seen_at) FROM watch_seen").fetchone()
    return datetime.fromisoformat(row[0]) if row and row[0] else None
