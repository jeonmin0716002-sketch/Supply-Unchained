"""Layer (2): static analysis of package contents.

``analyze_path`` is the real work and is pure filesystem + ``ast``, so the whole
rule set is testable offline against the fixtures in ``samples/``.

Still to come (tracked, not silently missing):
  * ``analyze_package`` — fetch the sdist/wheel from PyPI and extract it into a
    temp dir before calling ``analyze_path``. Must extract defensively: archive
    entries can carry ``..`` paths or absolute paths (zip-slip).
  * Bandit as a breadth net alongside the custom rules. It runs as a library
    (``bandit.core.manager.BanditManager``) over the same extracted tree; its
    B-codes then need CWE tags, which by the week-0 split is the API part's
    parsing job, not this module's.
"""

from __future__ import annotations

import ast
from pathlib import Path

from api.schemas import ScanRequest, Severity, StaticFinding
from engine.rules import AST_RULES, FILE_RULES, FileContext

#: Files larger than this are skipped — packaged data blobs, not source.
MAX_FILE_BYTES = 2 * 1024 * 1024

#: Directory names that never contain package code worth scanning.
SKIP_DIRS = frozenset({".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "node_modules"})

#: Only these extensions are read; everything else is binary/noise for now.
TEXT_SUFFIXES = frozenset({".py", ".pth", ".toml", ".cfg", ".txt", ".sh", ".bat", ".ps1"})

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


class StaticAnalysisError(RuntimeError):
    """Raised when a package could not be analysed at all."""


def _iter_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def _read_context(path: Path, root: Path) -> FileContext | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    relpath = path.relative_to(root).as_posix()
    return FileContext(path=path, relpath=relpath, text=text)


def analyze_path(root: str | Path) -> list[StaticFinding]:
    """Run every custom rule over an extracted package tree.

    Returns findings ordered most-severe first so the router can take the head
    of the list for its verdict reasons.
    """
    root = Path(root)
    if not root.exists():
        raise StaticAnalysisError(f"path does not exist: {root}")
    if root.is_file():
        root, targets = root.parent, [root]
    else:
        targets = list(_iter_files(root))

    findings: list[StaticFinding] = []

    for path in targets:
        ctx = _read_context(path, root)
        if ctx is None:
            continue

        for rule in FILE_RULES:
            findings.extend(rule(ctx))

        if ctx.suffix != ".py":
            continue
        try:
            tree = ast.parse(ctx.text, filename=str(path))
        except SyntaxError:
            # Not necessarily malicious (Python 2 leftovers are common in old
            # sdists), and an unparseable file is not evidence on its own.
            continue

        for ast_rule in AST_RULES:
            findings.extend(ast_rule(ctx, tree))

    findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], f.location, f.rule))
    return findings


async def analyze_package(req: ScanRequest) -> list[StaticFinding]:
    """Engine entry point for layer (2) — replaces the router's ``_mock_static_layer``.

    Not implemented yet: needs the PyPI archive download + safe extraction step
    described in the module docstring. ``analyze_path`` is the finished half and
    is what the tests exercise.
    """
    raise NotImplementedError(
        "archive download/extraction is not implemented yet; "
        "use analyze_path() on an already-extracted package tree"
    )
