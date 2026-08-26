"""Layer (2): static analysis of package contents.

``analyze_path`` is the real work and is pure filesystem + ``ast``, so the whole
rule set is testable offline against the fixtures in ``samples/``.
``analyze_package`` is the thin network-facing wrapper: it asks ``common.pypi``
for the unpacked artifact and runs the rules over it.

Still to come (tracked, not silently missing):
  * Bandit as a breadth net alongside the custom rules. It runs as a library
    (``bandit.core.manager.BanditManager``) over the same extracted tree; its
    B-codes then need CWE tags, which by the week-0 split is the API part's
    parsing job, not this module's.
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path

from api.schemas import ScanRequest, Severity, StaticFinding
from common.pypi import PackageContext
from engine.rules import AST_RULES, FILE_RULES, FileContext

#: Files larger than this are skipped — packaged data blobs, not source.
MAX_FILE_BYTES = 2 * 1024 * 1024

#: Directory names that never contain package code worth scanning.
SKIP_DIRS = frozenset({".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "node_modules"})

#: Directories that ship inside an sdist but are never executed by ``pip install``
#: or by importing the package. Their contents are real code, so the rules do fire
#: on them -- and the findings are noise: a test suite is *supposed* to call
#: ``eval()`` and ``exec()``. Measured on PyYAML 5.3.1: 17 findings before, 10 after,
#: and the 7 that went away were all ``exec()``/``eval()`` inside ``tests/`` while the
#: 6 real ones (``pickle.load()`` in ``lib/yaml/__init__.py``) stayed.
#:
#: This is a deliberate blind spot, so state it plainly: a payload parked in a
#: directory named ``tests/`` is not scanned by these rules. It is still not a free
#: pass -- code there does not run unless something outside reaches into it, and
#: whatever does the reaching (``setup.py``, an install hook, a ``.pth``) lives
#: outside these directories and is scanned.
#:
#: Kept in sync with ``_BANDIT_EXCLUDE_DIRS`` in ``api/routers/scan.py``; the two
#: static layers should not disagree about what counts as package code.
NOT_EXECUTED_DIRS = frozenset({"tests", "test", "examples", "docs", "doc"})

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
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        # Directory names only -- ``docs.py`` is a shipped module, not a docs folder.
        if any(part in NOT_EXECUTED_DIRS for part in rel_parts[:-1]):
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


async def analyze_package(
    req: ScanRequest,
    *,
    ctx: PackageContext | None = None,
) -> list[StaticFinding]:
    """Engine entry point for layer (2) — replaces the router's ``_mock_static_layer``.

    Pass the router's ``ctx`` so the artifact is downloaded once per scan and
    shared with the scoring layer. Without one, a private context is created
    and cleaned up here (handy for scripts and one-off checks).

    Returns ``[]`` when the release publishes no analysable artifact. Download
    and unpack failures propagate as ``common.pypi.PyPIError`` — the caller
    decides what to do, because "we could not look" must never be silently
    reported as "we looked and it was clean".
    """
    # analyze_path() 는 트리 전체를 읽고 AST 를 파싱하는 동기 작업이다. 코루틴에서 그대로
    # 부르면 라우터가 asyncio.gather 로 묶어둔 나머지 레이어가 그 시간만큼 통째로 멈추고,
    # 서버의 다른 요청도 같이 멈춘다 (api/routers/scan.py 의 bandit 레이어와 같은 이유).
    if ctx is not None:
        root = await ctx.extracted_path()
        return await asyncio.to_thread(analyze_path, root) if root else []

    async with PackageContext(req.name, req.version) as own_ctx:
        root = await own_ctx.extracted_path()
        return await asyncio.to_thread(analyze_path, root) if root else []
