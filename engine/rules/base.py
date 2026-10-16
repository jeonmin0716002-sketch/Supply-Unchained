"""Shared plumbing for custom static-analysis rules.

Two rule kinds, both plain callables so adding a rule is one function plus one
registry entry:

    FileRule  (ctx)             -> findings   # any file, incl. non-Python (.pth)
    AstRule   (ctx, tree)       -> findings   # parsed Python modules only

Rules emit ``api.schemas.StaticFinding`` directly: the schema is the agreed
cross-part contract, so the engine has no private finding type to translate.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from api.schemas import Severity, StaticFinding


class SourceTree(Protocol):
    """분석 대상 패키지의 파일 트리. 규칙이 옆 파일을 볼 때는 디스크가 아니라 이걸 쓴다.

    디스크(DiskTree)와 메모리(MemoryTree) 구현이 있다. 메모리 쪽이 필요한 이유: 실제
    악성 샘플을 디스크에 풀면 백신이 읽기를 막는다(Windows Defender — OSError 22).
    평가는 메모리에서 하고, 제품 경로는 읽지 못한 파일을 숨기지 않고 보고한다.
    """

    def files(self) -> list[str]: ...
    def size(self, relpath: str) -> int: ...
    def read(self, relpath: str) -> str | None: ...


class DiskTree:
    def __init__(self, root: Path) -> None:
        self.root = root
        self._files: list[str] | None = None

    def files(self) -> list[str]:
        if self._files is None:
            self._files = sorted(
                p.relative_to(self.root).as_posix() for p in self.root.rglob("*") if p.is_file()
            )
        return self._files

    def size(self, relpath: str) -> int:
        try:
            return (self.root / relpath).stat().st_size
        except OSError:
            return -1

    def read(self, relpath: str) -> str | None:
        """읽기 실패는 None — 백신 차단(Windows: OSError 22)도 여기로 온다."""
        try:
            return (self.root / relpath).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None


class MemoryTree:
    def __init__(self, files: Mapping[str, str]) -> None:
        self._data = dict(files)

    def files(self) -> list[str]:
        return sorted(self._data)

    def size(self, relpath: str) -> int:
        return len(self._data.get(relpath, "").encode("utf-8"))

    def read(self, relpath: str) -> str | None:
        return self._data.get(relpath)


@dataclass(frozen=True)
class FileContext:
    """One candidate file, pre-read so each rule does not re-open it."""

    path: Path
    relpath: str
    text: str
    tree: SourceTree | None = None

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


# ── 이름 해석 (규칙 공용) ─────────────────────────────────────────

def dotted_name(node: ast.AST) -> str | None:
    """호출 대상을 점 이름으로. ``__import__('base64').b64decode`` → ``base64.b64decode``.

    ``__import__('builtins').exec(__import__('base64').b64decode(...))`` 는 실측 악성
    샘플(aio3·pthttp)이 import 문 없이 이름을 숨기는 방식이다.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "__import__"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ):
        return node.args[0].value
    return None


def import_aliases(tree: ast.Module) -> dict[str, str]:
    """import 별칭 → 실제 이름. ``from os import system as _ssystem``·``import base64 as b``
    처럼 이름을 바꿔 숨기는 게 실측 샘플(fluiddaddy·xolo*)에 있었다. 맨 이름 import 도
    풀린다 (``from subprocess import run`` → ``subprocess.run``)."""
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                top = a.name.split(".")[0]
                out[a.asname or top] = a.name if a.asname else top
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for a in node.names:
                out[a.asname or a.name] = f"{node.module}.{a.name}"
    return out


def resolve_name(node: ast.AST, aliases: dict[str, str]) -> str | None:
    name = dotted_name(node)
    if not name:
        return None
    head, dot, rest = name.partition(".")
    return aliases[head] + dot + rest if head in aliases else name
