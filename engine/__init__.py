"""Detection engine — layers (1) CVE/OSV matching and (2) static analysis.

Public entry points, both returning the shared contract types from
``api.schemas`` so the API router can drop them in place of its mocks:

    cve_matcher.match_package(req)      -> list[Vulnerability]
    static_analyzer.analyze_package(req) -> list[StaticFinding]   (fetches)
    static_analyzer.analyze_path(path)   -> list[StaticFinding]   (offline)

Both are wired into ``api/routers/scan.py``. Pass the router's
``common.pypi.PackageContext`` so PyPI is hit once per scan rather than once
per layer.
"""

from engine.cve_matcher import CveLookupError, match_package
from engine.static_analyzer import analyze_package, analyze_path

__all__ = ["CveLookupError", "analyze_package", "analyze_path", "match_package"]
