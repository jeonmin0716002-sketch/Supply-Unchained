"""CWE parsing for OSV/CVE and Bandit results — API-part responsibility.

Week-0 split of CWE work (see engine/verdict.py for the other half):
  * custom rules (.pth / install-hook ...)  -> engine tags them at detection time
  * OSV/CVE advisories and Bandit B-codes   -> parsed HERE, in the API layer

Two consumers:
  * ``finding_from_bandit_issue`` — when the engine's Bandit breadth-net lands
    (engine/static_analyzer.py docstring, "still to come"), it can hand raw
    ``bandit.core.issue.Issue`` objects to this function and get back the shared
    ``StaticFinding`` contract type, CWE included. Bandit >= 1.7 attaches the
    CWE to each issue itself, so no hand-maintained table can drift out of date.
  * ``cwe_for_bandit`` — for contexts where only the bare B-code string is
    available (e.g. parsing `bandit -f json` CLI output). Built dynamically
    from Bandit's own blacklist registry, with a small static supplement for
    the plugin-based checks we expect to meet in malicious packages.
"""

from __future__ import annotations

import asyncio
from functools import lru_cache
from typing import TYPE_CHECKING, Any

import httpx

from api.schemas import Severity, StaticFinding, Vulnerability

if TYPE_CHECKING:  # bandit is a heavy import; only pull it in when actually used
    from bandit.core.issue import Issue

# Bandit plugin checks (non-blacklist) most relevant to malicious packages.
# Blacklist checks (B3xx/B4xx) are NOT listed here — they are read straight out
# of Bandit's own registry in _bandit_blacklist_cwes(), so they cannot drift.
_PLUGIN_CWE_SUPPLEMENT: dict[str, str] = {
    "B101": "CWE-703",  # assert_used
    "B102": "CWE-78",   # exec_used (Bandit's own mapping)
    "B103": "CWE-732",  # set_bad_file_permissions
    "B104": "CWE-605",  # hardcoded_bind_all_interfaces
    "B105": "CWE-259",  # hardcoded_password_string
    "B106": "CWE-259",  # hardcoded_password_funcarg
    "B107": "CWE-259",  # hardcoded_password_default
    "B108": "CWE-377",  # hardcoded_tmp_directory
    "B110": "CWE-703",  # try_except_pass
    "B112": "CWE-703",  # try_except_continue
    "B324": "CWE-327",  # hashlib insecure hash
    "B501": "CWE-295",  # request_with_no_cert_validation
    "B602": "CWE-78",   # subprocess_popen_with_shell_equals_true
    "B603": "CWE-78",   # subprocess_without_shell_equals_true
    "B604": "CWE-78",   # any_other_function_with_shell_equals_true
    "B605": "CWE-78",   # start_process_with_a_shell
    "B606": "CWE-78",   # start_process_with_no_shell
    "B607": "CWE-78",   # start_process_with_partial_path
    "B608": "CWE-89",   # hardcoded_sql_expressions
}

_SEVERITY_FROM_BANDIT = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
}

#: Emitted when neither Bandit's registry nor the supplement knows the code.
UNKNOWN_CWE = "CWE-UNKNOWN"


@lru_cache(maxsize=1)
def _bandit_blacklist_cwes() -> dict[str, str]:
    """B-code -> CWE for Bandit's blacklist checks, read from Bandit itself."""
    try:
        from bandit.core.extension_loader import MANAGER
    except Exception:  # bandit not installed — degrade to the static supplement
        return {}
    mapping: dict[str, str] = {}
    for items in MANAGER.blacklist.values():
        for item in items:
            code, cwe = item.get("id"), item.get("cwe")
            if code and cwe:
                mapping[str(code)] = f"CWE-{cwe}"
    return mapping


def cwe_for_bandit(b_code: str) -> str:
    """CWE tag for a bare Bandit rule id (``"B301"`` -> ``"CWE-502"``)."""
    code = b_code.strip().upper()
    return _bandit_blacklist_cwes().get(code) or _PLUGIN_CWE_SUPPLEMENT.get(code, UNKNOWN_CWE)


def finding_from_bandit_issue(issue: Issue, *, root_relpath: str | None = None) -> StaticFinding:
    """Map a live ``bandit.core.issue.Issue`` onto the shared contract type.

    Prefers the CWE Bandit attached to the issue itself; falls back to
    :func:`cwe_for_bandit` for old Bandit versions without per-issue CWE.
    """
    cwe_obj: Any = getattr(issue, "cwe", None)
    cwe_id = getattr(cwe_obj, "id", None)
    cwe = f"CWE-{cwe_id}" if cwe_id else cwe_for_bandit(issue.test_id)

    location = f"{root_relpath or issue.fname}:{issue.lineno}"
    return StaticFinding(
        rule=issue.test_id,
        cwe=cwe,
        severity=_SEVERITY_FROM_BANDIT.get(str(issue.severity).upper(), Severity.MEDIUM),
        location=location,
        detail=issue.text,
    )


def cwes_from_osv(vuln_payload: dict[str, Any]) -> list[str]:
    """CWE ids from a raw OSV advisory dict (``database_specific.cwe_ids``).

    GHSA-sourced OSV records carry ``cwe_ids``; PYSEC-sourced ones usually do
    not — an empty result is normal, not an error.
    """
    raw = (vuln_payload.get("database_specific") or {}).get("cwe_ids") or []
    return [str(c) for c in raw if str(c).startswith("CWE-")]


# ──────────────────────────────
# OSV 재조회 기반 태깅 (Vulnerability.cwe_ids 채우기)
# ──────────────────────────────
#
# 정석은 engine/cve_matcher.py 의 parse_osv_response 가 /v1/query 응답에서 바로
# cwes_from_osv() 를 부르는 것 (raw payload 를 이미 들고 있으므로 네트워크 0회
# 추가). 그 파일은 엔진 파트 소유라 여기서는 광고문 ID 로 OSV 를 다시 조회하는
# 우회 구현을 쓴다 — 엔진 쪽에 한 줄이 들어오면 이 함수는 은퇴한다.

OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
_OSV_TIMEOUT = 10.0
#: 취약점이 많은 구버전 패키지에서 재조회가 폭주하지 않게 동시 요청 상한
_MAX_CONCURRENT_LOOKUPS = 8


async def fetch_osv_cwes(vuln_id: str, client: httpx.AsyncClient) -> list[str]:
    """OSV /v1/vulns/{id} 를 조회해 해당 광고문의 CWE 목록을 반환.

    태깅은 부가 정보라 실패해도 스캔을 막지 않는다 — 어떤 오류든 빈 리스트.
    """
    try:
        resp = await client.get(OSV_VULN_URL.format(id=vuln_id), timeout=_OSV_TIMEOUT)
        resp.raise_for_status()
        return cwes_from_osv(resp.json())
    except (httpx.HTTPError, ValueError):
        return []


async def tag_vulnerabilities(
    vulns: list[Vulnerability], client: httpx.AsyncClient
) -> None:
    """Vulnerability 목록의 ``cwe_ids`` 를 제자리에서(in-place) 채운다."""
    if not vulns:
        return
    sem = asyncio.Semaphore(_MAX_CONCURRENT_LOOKUPS)

    async def _one(v: Vulnerability) -> None:
        async with sem:
            v.cwe_ids = await fetch_osv_cwes(v.id, client)

    await asyncio.gather(*(_one(v) for v in vulns))
