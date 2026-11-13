"""OSV 일괄 조회 (``/v1/querybatch``) + 상세 보강 (``/v1/vulns/<id>``).

실패는 그 의존성의 오류로 올린다 — "조회 못 함"을 "취약점 없음"으로 돌려주면 안 된다.
심각도·수정 버전 파싱은 engine.cve_matcher 의 것을 그대로 쓴다 (복사하지 않는다).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx

from api.schemas import Severity
from engine.cve_matcher import _parse_fixed_version, _parse_severity

BATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/"
CHUNK = 500          # OSV 가 받는 한 요청당 쿼리 수 상한(1000)보다 넉넉히 작게
MAX_PAGES = 20
RETRIES = 3
SEVERITY_ORDER = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


@dataclass(frozen=True)
class OsvQuery:
    osv_ecosystem: str
    name: str
    version: str


@dataclass
class VulnInfo:
    id: str
    severity: Severity
    summary: str | None = None
    fixed: str | None = None


@dataclass
class OsvOutcome:
    vulns: list[VulnInfo] = field(default_factory=list)
    #: 조회 실패 사유. 있으면 vulns 는 "모름"이지 "없음"이 아니다.
    error: str | None = None


async def _post(client: httpx.AsyncClient, body: dict, sleep) -> dict:
    last: Exception | None = None
    for attempt in range(RETRIES):
        try:
            r = await client.post(BATCH_URL, json=body)
            if r.status_code == 429 or r.status_code >= 500:
                raise httpx.HTTPStatusError(f"HTTP {r.status_code}", request=r.request, response=r)
            r.raise_for_status()
            return r.json()
        except (httpx.HTTPError, ValueError) as exc:
            last = exc
            if attempt < RETRIES - 1:
                await sleep(0.5 * 2**attempt)
    raise RuntimeError(f"OSV querybatch 실패: {last}")


async def _get_vuln(client: httpx.AsyncClient, vid: str, sleep) -> dict:
    last: Exception | None = None
    for attempt in range(RETRIES):
        try:
            r = await client.get(VULN_URL + vid)
            if r.status_code == 429 or r.status_code >= 500:
                raise httpx.HTTPStatusError(f"HTTP {r.status_code}", request=r.request, response=r)
            r.raise_for_status()
            return r.json()
        except (httpx.HTTPError, ValueError) as exc:
            last = exc
            if attempt < RETRIES - 1:
                await sleep(0.5 * 2**attempt)
    raise RuntimeError(f"OSV 상세 조회 실패({vid}): {last}")


async def _ids_for_chunk(client, queries: list[OsvQuery], sleep) -> list[list[str] | str]:
    """청크 하나의 결과: 쿼리마다 id 목록, 실패하면 오류 문자열. 페이지가 남으면 이어서 묻는다."""
    ids: list[list[str] | str] = [[] for _ in queries]
    pending = {i: None for i in range(len(queries))}  # 쿼리 인덱스 → page_token
    for _ in range(MAX_PAGES):
        if not pending:
            break
        order = list(pending)
        body = {"queries": [
            {"package": {"name": queries[i].name, "ecosystem": queries[i].osv_ecosystem},
             "version": queries[i].version,
             **({"page_token": pending[i]} if pending[i] else {})}
            for i in order]}
        try:
            data = await _post(client, body, sleep)
        except RuntimeError as exc:
            for i in order:
                ids[i] = str(exc)
            return ids
        results = data.get("results")
        if not isinstance(results, list) or len(results) != len(order):
            for i in order:
                ids[i] = "OSV 응답 형식 오류 (results 길이 불일치)"
            return ids
        nxt = {}
        for i, res in zip(order, results, strict=True):
            res = res or {}
            ids[i].extend(v["id"] for v in res.get("vulns") or [] if v.get("id"))
            if res.get("next_page_token"):
                nxt[i] = res["next_page_token"]
        pending = nxt
    for i in pending:
        ids[i] = f"OSV 페이지가 {MAX_PAGES}개를 넘어 결과를 다 읽지 못했습니다"
    return ids


async def query_batch(
    queries: list[OsvQuery], *, client: httpx.AsyncClient, concurrency: int = 4,
    cache: dict[str, dict] | None = None, sleep=asyncio.sleep,
) -> list[OsvOutcome]:
    """입력과 같은 순서로 결과를 돌려준다. 중복 쿼리는 한 번만 묻는다."""
    cache = {} if cache is None else cache
    unique = list(dict.fromkeys(queries))
    sem = asyncio.Semaphore(concurrency)
    chunks = [unique[i:i + CHUNK] for i in range(0, len(unique), CHUNK)]

    async def run(chunk):
        async with sem:
            return await _ids_for_chunk(client, chunk, sleep)

    chunk_results = await asyncio.gather(*(run(c) for c in chunks))
    by_query: dict[OsvQuery, list[str] | str] = {}
    for chunk, res in zip(chunks, chunk_results, strict=True):
        by_query.update(zip(chunk, res, strict=True))

    # 상세 보강 — id 는 여러 패키지가 공유하므로 한 번만 가져온다
    need = {v for r in by_query.values() if isinstance(r, list) for v in r if v not in cache}

    async def hydrate(vid):
        async with sem:
            try:
                cache[vid] = await _get_vuln(client, vid, sleep)
            except RuntimeError as exc:
                cache[vid] = {"_error": str(exc)}

    await asyncio.gather(*(hydrate(v) for v in need))

    outcomes: dict[OsvQuery, OsvOutcome] = {}
    for q, res in by_query.items():
        if isinstance(res, str):
            outcomes[q] = OsvOutcome(error=res)
            continue
        out = OsvOutcome()
        for vid in dict.fromkeys(res):
            detail: dict[str, Any] = cache.get(vid) or {}
            if "_error" in detail:
                out.error = detail["_error"]  # 상세를 못 받으면 심각도를 모른다 — 오류로 표시
                out.vulns.append(VulnInfo(vid, Severity.MEDIUM))
                continue
            out.vulns.append(VulnInfo(
                vid, _parse_severity(detail), detail.get("summary") or None,
                _parse_fixed_version(detail, q.name)))
        outcomes[q] = out
    return [outcomes[q] for q in queries]
