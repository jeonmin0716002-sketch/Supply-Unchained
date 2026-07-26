"""Detection engine — layers (1) CVE/OSV matching and (2) static analysis.

Public entry points, both returning the shared contract types from
``api.schemas`` so the API router can drop them in place of its mocks:

    cve_matcher.match_package(req)   -> list[Vulnerability]
    static_analyzer.analyze_path(p)  -> list[StaticFinding]

The router wiring is intentionally not done yet: ``api/routers/scan.py`` is
also being modified by the scoring branch, so both layers get wired in one
pass once that lands.
"""

from engine.cve_matcher import CveLookupError, match_package
from engine.static_analyzer import analyze_path

__all__ = ["CveLookupError", "analyze_path", "match_package"]
