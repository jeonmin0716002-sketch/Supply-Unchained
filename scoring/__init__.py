"""Supply-Unchained data / risk-scoring layer.

This package implements detection layer (3): metadata-based risk scoring.
It never inspects package *code* (that is the static-analysis engine's job).
Instead it looks at the *circumstances* around a package -- who published it,
when, how often, and whether its name mimics a popular package -- and turns
those signals into a 0-100 risk score.

Public entry point (drop-in replacement for the API's ``_mock_risk_layer``)::

    from scoring.scorer import score_package
    signals, risk_score = await score_package(request)
"""

from scoring.scorer import compute_score, score_package

__all__ = ["compute_score", "score_package"]
