"""Offline regression tests for the scoring layer.

Pure/deterministic: no network, no PyPI access -- metadata is hand-built. Runs
under pytest (`uv run pytest`) or standalone (`python tests/test_scoring.py`).
"""

from datetime import datetime, timedelta, timezone

from api.schemas import RiskSignals
from scoring import features
from scoring.collector import PackageMetadata
from scoring.scorer import (
    HIGH_TYPOSQUAT,
    TYPOSQUAT_WARN_FLOOR,
    build_signals,
    compute_score,
)

NOW = datetime(2026, 7, 24, tzinfo=timezone.utc)


# ── typosquat_score ───────────────────────────────────────────────
def test_typosquat_flags_lookalike():
    assert features.typosquat_score("reqeusts") >= features.TYPOSQUAT_MIN_RATIO
    assert features.typosquat_score("colourama") >= features.TYPOSQUAT_MIN_RATIO


def test_typosquat_exact_popular_is_zero():
    assert features.typosquat_score("requests") == 0.0
    # PEP 503 normalization: case/separator differences still resolve to the real pkg
    assert features.typosquat_score("Requests") == 0.0
    assert features.typosquat_score("scikit_learn") == 0.0


def test_typosquat_legit_variant_stays_below_floor():
    # Real packages that merely resemble popular names must not be flagged.
    for name in ("requests-toolbelt", "types-requests", "google-cloud-bigquery"):
        assert features.typosquat_score(name) < features.TYPOSQUAT_MIN_RATIO


# ── is_new_package (proxy for is_new_account) ─────────────────────
def test_new_package_recent_is_true():
    assert features.is_new_package([NOW - timedelta(days=5)], now=NOW) is True


def test_new_package_old_is_false():
    assert features.is_new_package([NOW - timedelta(days=400)], now=NOW) is False


def test_new_package_empty_is_false():
    assert features.is_new_package([], now=NOW) is False


# ── has_release_burst (fraction-based, no mature-package false positive) ──
def test_burst_true_when_clustered_and_dominant():
    dates = [NOW - timedelta(hours=1), NOW - timedelta(hours=2), NOW - timedelta(hours=3)]
    assert features.has_release_burst(dates) is True


def test_burst_false_for_mature_package():
    # 3 releases in one day, but out of 150 total spread over years -> not a burst.
    old = [NOW - timedelta(days=3000 - i * 20) for i in range(147)]
    busy_day = [NOW - timedelta(days=1, hours=h) for h in range(3)]
    assert features.has_release_burst(old + busy_day) is False


def test_burst_false_below_count():
    dates = [NOW - timedelta(hours=1), NOW - timedelta(hours=2)]
    assert features.has_release_burst(dates) is False


# ── dependency_count ──────────────────────────────────────────────
def test_dependency_count_excludes_extras():
    deps = [
        "urllib3 (>=1.21.1,<3)",
        "certifi (>=2017.4.17)",
        "PySocks (>=1.5.6) ; extra == 'socks'",
    ]
    assert features.dependency_count(deps) == 2


# ── compute_score ─────────────────────────────────────────────────
def test_score_full_malicious_signals_is_high():
    sig = RiskSignals(
        is_new_account=True, typosquat_score=0.90, has_install_script=True,
        dependency_count=0, release_burst=True,
    )
    score, reasons = compute_score(sig)
    assert score >= 70  # block territory
    assert len(reasons) >= 4


def test_score_clean_package_is_zero():
    sig = RiskSignals(
        is_new_account=False, typosquat_score=0.05, has_install_script=False,
        dependency_count=5, release_burst=False,
    )
    score, _ = compute_score(sig)
    assert score == 0


def test_strong_typosquat_alone_reaches_warn_floor():
    sig = RiskSignals(
        is_new_account=False, typosquat_score=0.94, has_install_script=False,
        dependency_count=0, release_burst=False,
    )
    score, _ = compute_score(sig)
    assert score == TYPOSQUAT_WARN_FLOOR


def test_borderline_typosquat_not_floored():
    # Below HIGH_TYPOSQUAT: only the proportional additive weight applies.
    sig = RiskSignals(
        is_new_account=False, typosquat_score=HIGH_TYPOSQUAT - 0.05,
        has_install_script=False, dependency_count=0, release_burst=False,
    )
    score, _ = compute_score(sig)
    assert score < TYPOSQUAT_WARN_FLOOR


# ── build_signals with not-found metadata (name-only path) ────────
def test_removed_typosquat_still_scores_on_name():
    meta = PackageMetadata(name="reqeusts", version="1.0.0", found=False)
    sig = build_signals("reqeusts", meta)
    assert sig.typosquat_score >= features.TYPOSQUAT_MIN_RATIO
    assert sig.is_new_account is False  # no metadata -> proxy can't fire


if __name__ == "__main__":
    # Standalone runner so the suite works before `uv add --dev pytest`.
    import traceback

    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            passed += 1
            print(f"[PASS] {t.__name__}")
        except Exception:
            failed += 1
            print(f"[FAIL] {t.__name__}")
            traceback.print_exc()
    print(f"\n{passed} passed, {failed} failed")
    raise SystemExit(1 if failed else 0)
