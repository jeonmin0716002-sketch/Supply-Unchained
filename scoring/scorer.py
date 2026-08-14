"""Rule-based weighted risk scorer.

This is the public entry point of the scoring layer and the drop-in replacement
for the API's ``_mock_risk_layer``. It:

    1. collects PyPI metadata            (scoring.collector)
    2. derives risk signals from it      (scoring.features)
    3. sums weighted signals into 0-100  (compute_score, below)

The weighting is a transparent rule table -- no training data, no model. That
is deliberate: it needs no labelled dataset, and every point of the score maps
to a human-readable reason, which matters for a tool that has to *explain* why
it blocked an install. (A learned model is a possible future upgrade; see the
project roadmap.)

Weights follow the design doc's draft table and are meant to be tuned against
the validation samples, not learned:

    new maintainer account (proxy: new package)  +25
    typosquat similarity to a popular package    +30  (scaled by similarity)
    install-time script present                  +20
    abnormal release burst                       +15
    new-but-download-spike                       +10  (future hook, needs stats)
"""

from __future__ import annotations

from api.schemas import RiskSignals, ScanRequest
from common.pypi import PackageContext
from scoring import features
from scoring.collector import PackageMetadata, collect

# ── weight table (max reachable today = 90; the +10 download signal is a hook) ──
WEIGHT_NEW_ACCOUNT = 25
WEIGHT_TYPOSQUAT = 30
WEIGHT_INSTALL_SCRIPT = 20
WEIGHT_RELEASE_BURST = 15
WEIGHT_DOWNLOAD_ANOMALY = 10  # reserved; contributes 0 until download stats exist

MAX_SCORE = 100

# A near-certain typosquat is the single most reliable malicious indicator, so
# it should raise risk to at least "warn" on its own -- otherwise a blatant
# lookalike whose other signals happen to be quiet (e.g. already removed from
# PyPI, or wheel-only) slips through as "safe". The additive weight alone maxes
# at ~29 (30 x 0.97), which never reaches the warn threshold, so we floor it.
# Tuning evidence: across the validation set no legitimate package scored above
# 0.73, so this floor has zero measured false-positive cost.
HIGH_TYPOSQUAT = 0.90
# Kept in sync with the verdict's warn threshold in api/routers/scan.py::_decide.
TYPOSQUAT_WARN_FLOOR = 40


def build_signals(name: str, meta: PackageMetadata) -> RiskSignals:
    """Assemble the API ``RiskSignals`` from collected metadata.

    Typosquatting is computed from the name alone, so it still works even when
    the package was not found on PyPI (e.g. a malicious typosquat already taken
    down). Metadata-dependent signals fall back to safe defaults when missing.
    """
    return RiskSignals(
        is_new_account=features.is_new_package(meta.release_dates),
        typosquat_score=features.typosquat_score(name),
        has_install_script=meta.has_install_script,
        dependency_count=features.dependency_count(meta.requires_dist),
        release_burst=features.has_release_burst(meta.release_dates),
    )


def compute_score(signals: RiskSignals) -> tuple[int, list[str]]:
    """Turn risk signals into a 0-100 score plus human-readable reasons.

    Pure function -- no I/O -- so it is fully unit-testable. Returned reasons are
    plain sentences the CLI/dashboard can show directly.
    """
    score = 0
    reasons: list[str] = []

    if signals.is_new_account:
        score += WEIGHT_NEW_ACCOUNT
        reasons.append(
            f"Package was first published very recently "
            f"(+{WEIGHT_NEW_ACCOUNT}, proxy for a throwaway maintainer account)"
        )

    if signals.typosquat_score >= features.TYPOSQUAT_MIN_RATIO:
        # Scale the weight by how close the name is: 0.80 similarity -> partial,
        # 1.0 -> full weight.
        contribution = round(WEIGHT_TYPOSQUAT * signals.typosquat_score)
        score += contribution
        reasons.append(
            f"Name closely resembles a popular package "
            f"(similarity {signals.typosquat_score:.2f}, +{contribution})"
        )

    if signals.has_install_script:
        score += WEIGHT_INSTALL_SCRIPT
        reasons.append(
            f"Ships an install-time script (setup.py) that runs on install "
            f"(+{WEIGHT_INSTALL_SCRIPT})"
        )

    if signals.release_burst:
        score += WEIGHT_RELEASE_BURST
        reasons.append(
            f"Abnormal release burst -- many versions in a short window "
            f"(+{WEIGHT_RELEASE_BURST})"
        )

    score = min(score, MAX_SCORE)

    # A high-confidence typosquat warrants at least a warning by itself.
    if signals.typosquat_score >= HIGH_TYPOSQUAT and score < TYPOSQUAT_WARN_FLOOR:
        score = TYPOSQUAT_WARN_FLOOR
        reasons.append(
            f"Name is a near-certain typosquat of a popular package "
            f"(similarity {signals.typosquat_score:.2f}); risk raised to warn level"
        )

    if not reasons:
        reasons.append("No metadata risk signals detected")
    return score, reasons


async def score_package(
    req: ScanRequest,
    *,
    ctx: PackageContext | None = None,
) -> tuple[RiskSignals, int]:
    """Score a package end to end. Drop-in replacement for ``_mock_risk_layer``.

    Pass the router's ``ctx`` so PyPI is queried once per scan and the result is
    shared with the engine's static analysis.

    Returns ``(RiskSignals, risk_score)`` exactly like the API expects, so the
    router only needs to ``await`` this in place of the mock.

    Note: ``compute_score`` also produces per-signal reason sentences, and they
    are dropped here because the agreed contract has nowhere to put them. That
    is a real loss -- "name resembles a popular package (similarity 0.82, +25)"
    is far better demo material than the generic sentence the router
    synthesises -- and widening the contract is a team decision, not one to
    make here.
    """
    meta = await collect(req.name, req.version, ctx=ctx)
    signals = build_signals(req.name, meta)
    score, _reasons = compute_score(signals)
    return signals, score
