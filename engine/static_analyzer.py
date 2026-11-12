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
from engine.rules import AST_RULES, FILE_RULES, ONE_PER_LOCATION, FileContext
from engine.rules.base import DiskTree, MemoryTree, SourceTree

#: 코드가 아닌 텍스트(.txt·.toml·.cfg ...)는 이보다 크면 건너뛴다 — 묶음 데이터다.
MAX_FILE_BYTES = 2 * 1024 * 1024

#: 코드 파일(.py·.pth)은 크기와 무관하게 읽는다 (메모리 보호용 상한만 둔다). 예전엔 진입점
#: (setup.py·__init__.py)만 예외였고 나머지 .py 는 2MB 에서 **조용히** 빠졌다 — __init__ 이
#: import 하는 모듈에 페이로드를 넣고 주석으로 2MB 를 넘기면 검사 대상에서 사라지는 우회로다
#: (setup.py 쪽은 실측 libida 가 실제로 썼다). 상한을 넘는 코드 파일은 건너뛰되 ``unreadable``
#: 에 남겨, 호출자가 "검사하지 못했다"(static: 레이어 오류)로 보고하게 한다.
MAX_CODE_BYTES = 20 * 1024 * 1024
CODE_SUFFIXES = frozenset({".py", ".pth"})
#: 하위 호환용 이름 — 지금은 모든 코드 파일에 MAX_CODE_BYTES 가 적용된다.
ENTRYPOINT_NAMES = frozenset({"setup.py", "__init__.py"})
MAX_ENTRYPOINT_BYTES = MAX_CODE_BYTES

#: ``unreadable`` 항목 중 크기 상한 때문에 건너뛴 것의 표식 (읽기 실패와 구분해 보고한다)
OVERSIZED_MARK = " (크기 상한 초과)"

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


def unreadable_errors(unreadable: list[str]) -> list[str]:
    """``analyze_tree`` 의 ``unreadable`` → ``static:`` 레이어 오류 문구. 읽기 실패(백신)와
    크기 상한 초과를 따로 적는다 — 둘 다 "검사하지 못했다"이지만 원인이 다르다."""
    out = []
    big = [u.removesuffix(OVERSIZED_MARK) for u in unreadable if u.endswith(OVERSIZED_MARK)]
    failed = [u for u in unreadable if not u.endswith(OVERSIZED_MARK)]

    def shown(xs: list[str]) -> str:
        return ", ".join(xs[:3]) + (" 외" if len(xs) > 3 else "")

    if failed:
        out.append(f"static: 파일 {len(failed)}개를 읽지 못해 검사하지 못함 — "
                   f"백신이 차단했을 수 있음 ({shown(failed)})")
    if big:
        out.append(f"static: 코드 파일 {len(big)}개가 {MAX_CODE_BYTES // (1024 * 1024)}MB "
                   f"상한을 넘어 검사하지 못함 ({shown(big)})")
    return out


def _candidates(tree: SourceTree, oversized: list[str] | None = None) -> list[str]:
    out = []
    for rel in tree.files():
        parts = PurePosixPath(rel).parts
        if any(part in SKIP_DIRS for part in parts):
            continue
        # Directory names only -- ``docs.py`` is a shipped module, not a docs folder.
        if any(part in NOT_EXECUTED_DIRS for part in parts[:-1]):
            continue
        suffix = PurePosixPath(rel).suffix.lower()
        if suffix not in TEXT_SUFFIXES:
            continue
        size = tree.size(rel)
        code = suffix in CODE_SUFFIXES
        if size > (MAX_CODE_BYTES if code else MAX_FILE_BYTES):
            if code and oversized is not None:
                oversized.append(rel + OVERSIZED_MARK)
            continue
        # 크기를 못 읽은 파일(-1)도 후보로 둔다 — 예전엔 조용히 빠졌다. read() 가 실패하면
        # unreadable 로 남는다.
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

    for rel in _candidates(tree, unreadable):
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
    return _one_per_location(findings)


def _one_per_location(findings: list[StaticFinding]) -> list[StaticFinding]:
    """범위를 파일 너머로 따라가는 규칙은 같은 줄에 여러 시작 파일에서 닿는다 — 가장 심각한
    것 하나만 남긴다 (정렬 후라 처음 본 것이 가장 심각하다)."""
    seen: set[tuple[str, str]] = set()
    out = []
    for f in findings:
        if f.rule in ONE_PER_LOCATION:
            key = (f.rule, f.location)
            if key in seen:
                continue
            seen.add(key)
        out.append(f)
    return out


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
        if errors is not None:
            errors.extend(unreadable_errors(unreadable))
        return findings

    if ctx is not None:
        return await _run(await ctx.extracted_path())

    async with PackageContext(req.name, req.version) as own_ctx:
        return await _run(await own_ctx.extracted_path())
