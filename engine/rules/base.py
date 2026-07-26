"""Shared plumbing for custom static-analysis rules.

Two rule kinds, both plain callables so adding a rule is one function plus one
registry entry:

    FileRule  (ctx)             -> findings   # any file, incl. non-Python (.pth)
    AstRule   (ctx, tree)       -> findings   # parsed Python modules only

Rules emit ``api.schemas.StaticFinding`` directly: the schema is the agreed
cross-part contract, so the engine has no private finding type to translate.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from api.schemas import Severity, StaticFinding

if TYPE_CHECKING:
    import ast


@dataclass(frozen=True)
class FileContext:
    """One candidate file, pre-read so each rule does not re-open it."""

    path: Path
    relpath: str
    text: str

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def suffix(self) -> str:
        return self.path.suffix.lower()


FileRule = Callable[[FileContext], Iterable[StaticFinding]]
AstRule = Callable[[FileContext, "ast.Module"], Iterable[StaticFinding]]


def make_finding(
    *,
    rule: str,
    cwe: str,
    severity: Severity,
    ctx: FileContext,
    line: int,
    detail: str,
) -> StaticFinding:
    """Build a finding with the contract's ``file:line`` location format."""
    return StaticFinding(
        rule=rule,
        cwe=cwe,
        severity=severity,
        location=f"{ctx.relpath}:{line}",
        detail=detail,
    )
