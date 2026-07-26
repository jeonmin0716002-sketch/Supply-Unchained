"""CWE catalogue for the engine's custom rules.

Week-0 split of CWE work:
  * CWE for OSV/CVE advisories and Bandit B-codes  -> API part (parsed there)
  * CWE for this engine's own custom rules         -> here

A rule's CWE is chosen at the point of detection (``custom-dangerous-call``
alone spans CWE-78/95/502 depending on the sink), so this module does not
assign tags — it declares which tags each rule is allowed to emit. That gives
docs, the presentation and ``tests/test_engine.py`` one place to read, and
makes an unreviewed CWE showing up in output a test failure rather than a
surprise in the demo.

Note: the combined safe/warn/block decision still lives in
``api/routers/scan.py::_decide``. Moving it here is listed as "to review" in the
README and has not been agreed by the team, so it is deliberately not moved.
"""

from __future__ import annotations

from dataclasses import dataclass

from engine.rules.code_patterns import RULE_DANGEROUS_CALL, RULE_OBFUSCATED
from engine.rules.install_hooks import RULE_INSTALL_HOOK, RULE_PTH


@dataclass(frozen=True)
class RuleInfo:
    """What a custom rule detects and which CWEs it may tag findings with."""

    rule_id: str
    summary: str
    cwes: frozenset[str]


RULE_CATALOG: dict[str, RuleInfo] = {
    RULE_PTH: RuleInfo(
        rule_id=RULE_PTH,
        summary="'.pth' file executing code at every interpreter startup",
        cwes=frozenset({"CWE-94"}),
    ),
    RULE_INSTALL_HOOK: RuleInfo(
        rule_id=RULE_INSTALL_HOOK,
        summary="setup() cmdclass override running code during 'pip install'",
        cwes=frozenset({"CWE-94"}),
    ),
    RULE_DANGEROUS_CALL: RuleInfo(
        rule_id=RULE_DANGEROUS_CALL,
        summary="direct call to a command-execution or unsafe-deserialisation sink",
        cwes=frozenset({"CWE-78", "CWE-95", "CWE-502"}),
    ),
    RULE_OBFUSCATED: RuleInfo(
        rule_id=RULE_OBFUSCATED,
        summary="encoded payload decoded into an execution sink, or a large encoded blob",
        cwes=frozenset({"CWE-506"}),
    ),
}

#: Every CWE the engine's custom rules are allowed to produce.
KNOWN_CWES: frozenset[str] = frozenset().union(*(info.cwes for info in RULE_CATALOG.values()))


def describe_rule(rule_id: str) -> RuleInfo | None:
    """Look up a custom rule; returns None for Bandit/OSV-sourced rule ids."""
    return RULE_CATALOG.get(rule_id)
