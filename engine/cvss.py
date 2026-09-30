"""CVSS v3.x base-score calculation from a vector string.

OSV advisories usually carry a coarse label (``database_specific.severity``),
but some only ship a vector such as
``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``. Rather than guessing, we
compute the base score exactly as the FIRST specification defines it and map
it onto the qualitative rating scale.

Only v3.0/v3.1 are handled. v4.0 scoring is table-driven (macro-vector lookup)
and is left to the caller's fallback — a wrong v4 score would be worse than an
honest "unknown".

Reference: https://www.first.org/cvss/v3.1/specification-document (section 7).
"""

from __future__ import annotations

import math

from api.schemas import Severity

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _roundup(value: float) -> float:
    """Spec's Roundup: smallest one-decimal number >= value, float-error safe (v3.1 App. A)."""
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000
    return (math.floor(int_input / 10_000) + 1) / 10.0


def _parse_vector(vector: str) -> dict[str, str] | None:
    parts = vector.strip().split("/")
    if not parts or parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, val = part.partition(":")
        if not sep:
            return None
        metrics[key] = val
    if any(k not in metrics for k in _REQUIRED):
        return None
    return metrics


def base_score(vector: str) -> float | None:
    """Base score 0.0-10.0, or ``None`` if the vector is not a complete v3.x vector."""
    m = _parse_vector(vector)
    if m is None:
        return None
    changed = m["S"] == "C"
    try:
        av, ac, ui = _AV[m["AV"]], _AC[m["AC"]], _UI[m["UI"]]
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError:
        return None
    if m["S"] not in ("U", "C"):
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def score_to_severity(score: float) -> Severity:
    """Qualitative rating scale. 0.0 ("None") has no schema value; it maps to LOW."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def severity_from_vector(vector: str) -> Severity | None:
    score = base_score(vector)
    return None if score is None else score_to_severity(score)
