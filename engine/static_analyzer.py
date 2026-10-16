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
from collections.abc import Mapping
from pathlib import Path, PurePosixPath

from api.schemas import ScanRequest, Severity, StaticFinding
from common.pypi import PackageContext
from engine.rules import AST_RULES, FILE_RULES, FileContext
from engine.rules.base import DiskTree, MemoryTree, SourceTree

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


def _candidates(tree: SourceTree) -> list[str]:
    out = []
    for rel in tree.files():
        parts = PurePosixPath(rel).parts
        if any(part in SKIP_DIRS for part in parts):
            continue
        # Directory names only -- ``docs.py`` is a shipped module, not a docs folder.
        if any(part in NOT_EXECUTED_DIRS for part in parts[:-1]):
            continue
        if PurePosixPath(rel).suffix.lower() not in TEXT_SUFFIXES:
            continue
        if not 0 <= tree.size(rel) <= MAX_FILE_BYTES:
            continue
        out.append(rel)
    return out


def analyze_tree(
    tree: SourceTree, *, base: Path | None = None, unreadable: list[str] | None = None
) -> list[StaticFinding]:
    """Run every custom rule over a package file tree (disk or memory).

    읽지 못한 파일은 건너뛰되 ``unreadable`` 에 남긴다 — 실제 악성 파일은 백신이 읽기를
    막는 경우가 많아서(Windows Defender: OSError 22), 조용히 건너뛰면 "검사하지 못했다"가
    "검사했고 깨끗했다"로 둔갑한다.

    Returns findings ordered most-severe first so the router can take the head
    of the list for its verdict reasons.
    """
    findings: list[StaticFinding] = []
    root = base or Path(".")

    for rel in _candidates(tree):
        text = tree.read(rel)
        if text is None:
            if unreadable is not None:
                unreadable.append(rel)
            continue
        ctx = FileContext(path=root / rel, relpath=rel, text=text, tree=tree)

        for rule in FILE_RULES:
            findings.extend(rule(ctx))

        if ctx.suffix != ".py":
            continue
        try:
            module = ast.parse(ctx.text, filename=rel)
        except (SyntaxError, ValueError):
            # Not necessarily malicious (Python 2 leftovers are common in old
            # sdists), and an unparseable file is not evidence on its own.
            continue

        for ast_rule in AST_RULES:
            findings.extend(ast_rule(ctx, module))

    findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], f.location, f.rule))
    return findings


def analyze_path(root: str | Path, *, unreadable: list[str] | None = None) -> list[StaticFinding]:
    """Run every custom rule over an extracted package tree on disk."""
    root = Path(root)
    if not root.exists():
        raise StaticAnalysisError(f"path does not exist: {root}")
    if root.is_file():
        single = root
        tree = DiskTree(root.parent)
        tree._files = [single.name]
        return analyze_tree(tree, base=root.parent, unreadable=unreadable)
    return analyze_tree(DiskTree(root), base=root, unreadable=unreadable)


def analyze_files(
    files: Mapping[str, str], *, unreadable: list[str] | None = None
) -> list[StaticFinding]:
    """메모리에 있는 파일들(relpath → 내용)을 분석한다. 디스크에 쓰지 않는다."""
    return analyze_tree(MemoryTree(files), unreadable=unreadable)


async def analyze_package(
    req: ScanRequest,
    *,
    ctx: PackageContext | None = None,
    errors: list[str] | None = None,
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
    async def _run(root: Path | None) -> list[StaticFinding]:
        if not root:
            return []
        unreadable: list[str] = []
        findings = await asyncio.to_thread(analyze_path, root, unreadable=unreadable)
        if unreadable and errors is not None:
            shown = ", ".join(unreadable[:3]) + (" 외" if len(unreadable) > 3 else "")
            errors.append(
                f"static: 파일 {len(unreadable)}개를 읽지 못해 검사하지 못함 — "
                f"백신이 차단했을 수 있음 ({shown})"
            )
        return findings

    if ctx is not None:
        return await _run(await ctx.extracted_path())

    async with PackageContext(req.name, req.version) as own_ctx:
        return await _run(await own_ctx.extracted_path())
