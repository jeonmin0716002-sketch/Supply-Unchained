"""Risk-signal feature extraction.

Pure functions that turn a :class:`~scoring.collector.PackageMetadata` (plus the
raw package name) into the individual risk signals defined by the API contract's
``RiskSignals`` model. Everything here is network-free and deterministic, so it
can be unit-tested with hand-built metadata -- no PyPI access required.

The signals:
    * typosquat_score   -- name similarity to a popular package (0.0-1.0)
    * is_new_account    -- proxy: the package itself is brand new
    * has_install_script-- comes straight from the collector (sdist has setup.py)
    * release_burst     -- many versions published in a short window
    * dependency_count  -- number of distinct runtime dependencies
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher

from scoring.popular_packages import POPULAR_PACKAGES

# ── tunables (to be calibrated against the validation samples, not learned) ──
NEW_PACKAGE_DAYS = 30          # a package younger than this counts as "new"
BURST_WINDOW = timedelta(hours=24)
BURST_COUNT = 3                # >= this many releases inside one window = burst
BURST_FRACTION = 0.5           # ...and they must be >= this share of all releases
TYPOSQUAT_MIN_RATIO = 0.80     # below this, name similarity is treated as noise
_MAX_LEN_DELTA = 3             # skip comparisons between very different lengths


def normalize_name(name: str) -> str:
    """PEP 503 name normalization: lowercase, collapse runs of -_. to a dash."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


_POPULAR_NORMALIZED: frozenset[str] = frozenset(normalize_name(p) for p in POPULAR_PACKAGES)


def typosquat_score(name: str) -> float:
    """How closely ``name`` resembles a *different* popular package (0.0-1.0).

    Returns 0.0 when the name is itself a known popular package (it is the real
    thing, not an impersonation) or when it looks nothing like any of them.
    A high score means the name is suspiciously close to a popular package --
    the classic typosquatting setup (e.g. ``reqeusts`` vs ``requests``).
    """
    target = normalize_name(name)
    if not target or target in _POPULAR_NORMALIZED:
        return 0.0

    best = 0.0
    for popular in _POPULAR_NORMALIZED:
        if abs(len(popular) - len(target)) > _MAX_LEN_DELTA:
            continue
        ratio = SequenceMatcher(None, target, popular).ratio()
        if ratio > best:
            best = ratio
            if best == 1.0:  # can't do better (shouldn't happen after the guard)
                break
    return round(best, 2)


def is_new_package(release_dates: list[datetime], *, now: datetime | None = None) -> bool:
    """Proxy for ``is_new_account``: was this package first published recently?

    The PyPI JSON API does not expose the maintainer account's creation date,
    so we approximate the "freshly-created throwaway account" signal with the
    package's own age. Freshly published packages are where most malicious
    uploads live. Documented as a proxy; a stronger version would scrape the
    maintainer's profile page.
    """
    if not release_dates:
        return False
    now = now or datetime.now(timezone.utc)
    first_release = min(release_dates)
    return (now - first_release) <= timedelta(days=NEW_PACKAGE_DAYS)


def has_release_burst(release_dates: list[datetime]) -> bool:
    """True if the package's releases are abnormally clustered in time.

    Rapid-fire releases are a known malicious pattern (an attacker pushing many
    versions to dodge takedowns or brute-force dependency confusion). But a
    *mature* package will also have had the odd busy day over its lifetime, so
    a raw "3 in 24h" test false-positives on popular packages.

    To stay specific to the malicious pattern we require both:
      * a window of BURST_WINDOW holding >= BURST_COUNT releases, and
      * those releases making up >= BURST_FRACTION of *all* releases.
    For requests (3-in-a-day out of 150 total) the fraction is tiny -> no burst;
    for a throwaway package (5 versions all within an hour) it is ~1.0 -> burst.
    """
    total = len(release_dates)
    if total < BURST_COUNT:
        return False
    ordered = sorted(release_dates)
    # Sliding window: busiest count of releases within any BURST_WINDOW.
    busiest = 0
    for i, start in enumerate(ordered):
        count = sum(1 for dt in ordered[i:] if dt - start <= BURST_WINDOW)
        busiest = max(busiest, count)
    if busiest < BURST_COUNT:
        return False
    return (busiest / total) >= BURST_FRACTION


def dependency_count(requires_dist: list[str]) -> int:
    """Number of distinct *runtime* dependencies (excludes optional 'extra' deps).

    ``requires_dist`` entries look like ``"urllib3 (>=1.21.1,<3)"`` or
    ``"PySocks (>=1.5.6) ; extra == 'socks'"``. We drop the extras-gated ones and
    count distinct base names.
    """
    names: set[str] = set()
    for spec in requires_dist:
        # Skip dependencies that only apply to an optional extra.
        if "extra ==" in spec:
            continue
        match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", spec)
        if match:
            names.add(normalize_name(match.group(1)))
    return len(names)
