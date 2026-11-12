"""설치·import 시점에 **실제로 실행되는** 코드 범위 — 파일 경계를 넘어 따라간다.

예전 범위는 "그 파일의 최상단 + 최상단이 부르는 같은 파일 함수"였다. 탈취된 정상 패키지
29개 중 놓친 것의 구조가 그 경계 바깥이었다 (DataDog compromised_lib, 2026-11 실측):

* memoryos 2.0.34 — 거의 모든 모듈 최상단의 ``logger = get_logger(__name__)`` →
  (다른 모듈) ``log.get_logger`` → ``configure_logging()`` → ``from memos._stage0 import
  trigger; trigger()`` → ``subprocess.Popen([binary, ...])``. 패키지 안 **다른 모듈의 함수**를
  두 번 건너야 닿는다.
* lightning 2.6.2 — ``__init__.py`` 최상단의 ``threading.Thread(target=_run_runtime).start()``.
  호출식이 아니라 **함수를 넘겨받아 대신 실행하는 것**(스레드)이라 "부르는 함수"로 안 보였다.

그래서 범위를 실행 의미대로 넓힌다 — "패키지의 아무 함수"가 아니다:

1. 같은 패키지의 다른 모듈에서 가져온 함수를 부르면 그 본문 (상대·절대 import, 재수출 포함)
2. 클래스를 인스턴스화하면 ``__init__``·``__new__``·``__post_init__`` (패키지 안 부모 포함)
3. 그 인스턴스·``self``·``Cls()`` 에 대해 부르는 메서드, Thread 하위 클래스의 ``start()`` → ``run``
4. 대신 실행해 주는 것에 넘긴 함수 — ``threading.Thread(target=f)``·``Timer``·
   ``multiprocessing.Process``·``atexit.register``·``executor.submit`` 등
5. 정의 시점에 도는 코드 — 최상단 클래스 본문의 문장, 데코레이터, 기본 인자값

함수 안에 정의된 함수(웹 핸들러 등)는 여전히 범위 밖이다 — 그 함수를 부를 때가 아니라
요청이 올 때 돈다 (실측 오탐: fd-open-data-mcp).
"""

from __future__ import annotations

import ast
import contextlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from engine.rules.base import SourceTree, dotted_name, import_aliases, resolve_name

_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)

#: 한 시작점에서 따라가는 정의(함수·메서드) 수 상한. 수천 파일짜리 정상 패키지에서도
#: 범위가 폭주하지 않게 하는 안전장치다 — 실측 악성 경로는 깊이 4 이내였다.
MAX_FOLLOWED_DEFS = 400

#: 인스턴스화할 때 자동으로 도는 메서드
_CTOR_METHODS = ("__new__", "__init__", "__post_init__")

#: 넘겨받은 함수를 대신 실행하는 것 → (키워드 인자 이름, 위치 인자 번호)
_RUNNERS: dict[str, tuple[str | None, int]] = {
    "threading.Thread": ("target", 1),
    "threading.Timer": ("function", 1),
    "multiprocessing.Process": ("target", 1),
    "atexit.register": (None, 0),
    "_thread.start_new_thread": (None, 0),
    "thread.start_new_thread": (None, 0),
}
#: 수신자를 풀 수 없어도 이름만으로 "함수를 실행해 준다"고 볼 수 있는 메서드
_RUNNER_METHODS: dict[str, int] = {"submit": 0, "run_in_executor": 1, "apply_async": 0}
#: ``start()`` 하면 ``run()`` 이 도는 부모 클래스
_THREAD_BASES = {"threading.Thread", "multiprocessing.Process"}


# ── 범위 기본 연산 ────────────────────────────────────────────────

def walk_executed(node: ast.AST) -> Iterator[ast.AST]:
    """ast.walk 와 같되, 호출해야만 도는 함수·클래스·람다 본문으로는 내려가지 않는다."""
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        stack.extend(c for c in ast.iter_child_nodes(cur) if not isinstance(c, _DEFS))


def is_main_guard(stmt: ast.stmt) -> bool:
    """``if __name__ == "__main__":`` — ``and`` 로 조건을 덧붙인 형태도 (실측 오탐: rpi-hwid 의
    ``if __name__ == "__main__" and not globals().get(...)``)."""
    if not isinstance(stmt, ast.If):
        return False
    return any(
        isinstance(n, ast.Compare)
        and any(isinstance(p, ast.Name) and p.id == "__name__" for p in [n.left, *n.comparators])
        for n in ast.walk(stmt.test)
    )


def definition_time(node: ast.AST) -> Iterator[ast.AST]:
    """def·class 문이 **정의되는 순간** 도는 부분 — 데코레이터, 기본 인자값, 부모 클래스 식,
    그리고 클래스 본문의 (메서드가 아닌) 문장. 클래스 본문은 import 할 때 그대로 실행된다."""
    yield node  # 데코레이터 처리용 표식 — 본문은 내려가지 않는다
    if isinstance(node, _FUNCS):
        for d in node.decorator_list:
            yield from walk_executed(d)
        for d in [*node.args.defaults, *(k for k in node.args.kw_defaults if k is not None)]:
            yield from walk_executed(d)
    elif isinstance(node, ast.ClassDef):
        for d in [*node.decorator_list, *node.bases, *(k.value for k in node.keywords)]:
            yield from walk_executed(d)
        for stmt in node.body:
            if isinstance(stmt, (*_FUNCS, ast.ClassDef)):
                yield from definition_time(stmt)
            else:
                yield from walk_executed(stmt)


def module_level(tree: ast.Module, *, include_main: bool) -> Iterator[ast.AST]:
    """import(또는 setup.py 실행) 순간 도는 최상단 코드."""
    for stmt in tree.body:
        if isinstance(stmt, (*_FUNCS, ast.ClassDef)):
            yield from definition_time(stmt)
            continue
        if not include_main and is_main_guard(stmt):
            continue
        yield from walk_executed(stmt)


def body_nodes(fn: ast.AST) -> list[ast.AST]:
    """함수를 부르면 도는 본문. 안에 정의된 함수는 제외 (요청이 올 때 도는 핸들러 등)."""
    if isinstance(fn, ast.Lambda):
        return list(walk_executed(fn.body))
    return [n for stmt in fn.body if not isinstance(stmt, _DEFS) for n in walk_executed(stmt)]


def _top_defs(stmts: Iterable[ast.stmt]) -> Iterator[ast.AST]:
    """최상단의 def·class — ``try:``/``if`` 블록 안에 정의한 것도 (``try: def f ... except``)."""
    for stmt in stmts:
        if isinstance(stmt, (*_FUNCS, ast.ClassDef)):
            yield stmt
        elif isinstance(stmt, (ast.If, ast.Try, ast.With)):
            for block in ("body", "orelse", "finalbody"):
                yield from _top_defs(getattr(stmt, block, []))
            for h in getattr(stmt, "handlers", []):
                yield from _top_defs(h.body)


# ── 모듈 ──────────────────────────────────────────────────────────

@dataclass
class Module:
    relpath: str
    tree: ast.Module
    name: str  # 점 이름 (pkg.sub.mod). __init__.py 면 패키지 이름
    root: PurePosixPath  # 최상위 패키지 디렉터리의 부모 — 절대 import 의 기준
    is_pkg: bool
    aliases: dict[str, str] = field(default_factory=dict)
    defs: dict[str, ast.AST] = field(default_factory=dict)
    _instances: dict[str, tuple[Module, ast.ClassDef]] | None = None
    _owners: dict[int, ast.ClassDef] | None = None


def _owners(mod: Module) -> dict[int, ast.ClassDef]:
    """메서드 노드 id → 소유 클래스 (모듈마다 한 번만 계산)."""
    if mod._owners is None:
        mod._owners = {
            id(stmt): node
            for node in ast.walk(mod.tree) if isinstance(node, ast.ClassDef)
            for stmt in node.body if isinstance(stmt, _FUNCS)
        }
    return mod._owners


class ModuleIndex:
    """트리 하나의 모듈 파싱 결과 캐시. 규칙은 파일마다 불리므로 트리에 붙여 재사용한다."""

    def __init__(self, tree: SourceTree | None) -> None:
        self.tree = tree
        self._files = set(tree.files()) if tree is not None else set()
        self._mods: dict[str, Module | None] = {}

    @classmethod
    def of(cls, tree: SourceTree | None) -> ModuleIndex:
        if tree is None:
            return cls(None)
        idx = getattr(tree, "_su_module_index", None)
        if idx is None:
            idx = cls(tree)
            with contextlib.suppress(AttributeError):  # __slots__ 트리면 캐시 없이 간다
                tree._su_module_index = idx  # type: ignore[attr-defined]
        return idx

    def has(self, relpath: str) -> bool:
        return relpath in self._files

    def _name_root(self, relpath: str) -> tuple[str, PurePosixPath, bool]:
        p = PurePosixPath(relpath)
        is_pkg = p.name == "__init__.py"
        parts = [] if is_pkg else [p.stem]
        d = p.parent
        while self.has((d / "__init__.py").as_posix()) and d != d.parent and d.name:
            parts.insert(0, d.name)
            d = d.parent
        return ".".join(parts), d, is_pkg

    def module(self, relpath: str, parsed: ast.Module | None = None) -> Module | None:
        if relpath in self._mods:
            return self._mods[relpath]
        mod = None
        if parsed is None and self.tree is not None and self.has(relpath):
            text = self.tree.read(relpath)
            if text is not None:
                try:
                    parsed = ast.parse(text)
                except (SyntaxError, ValueError):
                    parsed = None
        if parsed is not None:
            name, root, is_pkg = self._name_root(relpath)
            mod = Module(relpath=relpath, tree=parsed, name=name, root=root, is_pkg=is_pkg)
            mod.aliases = _module_aliases(parsed, name, is_pkg)
            for d in _top_defs(parsed.body):
                mod.defs.setdefault(d.name, d)  # type: ignore[attr-defined]
        self._mods[relpath] = mod
        return mod

    def find(self, dotted: str, near: Module) -> Module | None:
        """점 이름 → 같은 트리의 모듈. 패키지 밖(서드파티·표준 라이브러리)이면 None."""
        rel = PurePosixPath(*dotted.split("."))
        roots = [near.root]
        if "." not in near.name and not near.is_pkg:
            roots.append(near.root / "src")  # setup.py 옆 src/ 배치
        for root in roots:
            for cand in (root / rel.with_suffix(".py"), root / rel / "__init__.py"):
                mod = self.module(cand.as_posix())
                if mod is not None:
                    return mod
        return None


def _module_aliases(tree: ast.Module, modname: str, is_pkg: bool) -> dict[str, str]:
    """import 별칭을 **절대** 점 이름으로 — 상대 import(``from .x import f``)도 푼다."""
    out = import_aliases(tree)
    pkg = modname.split(".") if is_pkg else modname.split(".")[:-1]
    for node in ast.walk(tree):
        if not (isinstance(node, ast.ImportFrom) and node.level):
            continue
        up = node.level - 1
        if up > len(pkg):
            continue
        base = pkg[: len(pkg) - up] + ([node.module] if node.module else [])
        prefix = ".".join(p for p in base if p)
        for a in node.names:
            if a.name != "*":
                out[a.asname or a.name] = f"{prefix}.{a.name}" if prefix else a.name
    return out


# ── 따라가기 ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class Reached:
    """실행 범위 안의 노드 하나와 그 노드가 있는 모듈."""

    module: Module
    node: ast.AST
    via_thread: bool = False


_Target = tuple[Module, ast.AST]  # (정의가 있는 모듈, FunctionDef | ClassDef | Lambda)


class Scope:
    """시작점(seed) 노드들에서 실제로 실행되는 노드를 모은다.

    ``import_toplevel`` — setup.py 처럼 범위 안의 import 가 그 모듈 최상단을 **이번에 처음**
    실행시키는 경우. 패키지 모듈끼리는 각 모듈의 최상단을 그 모듈 차례에 따로 보므로 끈다.
    """

    def __init__(self, index: ModuleIndex, *, import_toplevel: bool = False) -> None:
        self.index = index
        self.import_toplevel = import_toplevel
        self._done: set[tuple[str, int]] = set()
        self._followed = 0
        self.reached: list[Reached] = []

    # 이름 해석 -----------------------------------------------------

    def _lookup_in(self, mod: Module, rest: list[str], depth: int) -> _Target | None:
        if not rest or depth > 4:
            return None
        head = rest[0]
        if head in mod.defs:
            d = mod.defs[head]
            if len(rest) == 1:
                return mod, d
            if len(rest) == 2 and isinstance(d, ast.ClassDef):
                return self._method(mod, d, rest[1], depth + 1)
            return None
        if head in mod.aliases:  # 재수출: __init__.py 의 ``from .core import go``
            return self._lookup_dotted(mod, mod.aliases[head].split(".") + rest[1:], depth + 1)
        sub = self.index.find(f"{mod.name}.{head}", mod) if mod.is_pkg and mod.name else None
        return self._lookup_in(sub, rest[1:], depth + 1) if sub is not None else None

    def _lookup_dotted(self, mod: Module, parts: list[str], depth: int = 0) -> _Target | None:
        if depth > 4 or not parts:
            return None
        if parts[0] in mod.defs:
            return self._lookup_in(mod, parts, depth)
        if parts[0] in mod.aliases:
            parts = mod.aliases[parts[0]].split(".") + parts[1:]
        for i in range(len(parts) - 1, 0, -1):
            target = self.index.find(".".join(parts[:i]), mod)
            if target is not None:
                return self._lookup_in(target, parts[i:], depth + 1)
        return None

    def _method(self, mod: Module, cls: ast.ClassDef, name: str, depth: int = 0) -> _Target | None:
        if depth > 6:
            return None
        for stmt in cls.body:
            if isinstance(stmt, _FUNCS) and stmt.name == name:
                return mod, stmt
        for base in cls.bases:
            found = self._resolve_expr(mod, base, depth=depth + 1)
            if found is not None and isinstance(found[1], ast.ClassDef):
                hit = self._method(found[0], found[1], name, depth + 1)
                if hit is not None:
                    return hit
        return None

    def _is_threadlike(self, mod: Module, cls: ast.ClassDef, depth: int = 0) -> bool:
        if depth > 6:
            return False
        for base in cls.bases:
            if resolve_name(base, mod.aliases) in _THREAD_BASES:
                return True
            found = self._resolve_expr(mod, base, depth=depth + 1)
            if (found is not None and isinstance(found[1], ast.ClassDef)
                    and self._is_threadlike(found[0], found[1], depth + 1)):
                return True
        return False

    def _resolve_expr(self, mod: Module, expr: ast.AST, *, depth: int = 0) -> _Target | None:
        name = dotted_name(expr)
        if not name or depth > 6:
            return None
        return self._lookup_dotted(mod, name.split("."), depth)

    def _instances(self, mod: Module) -> dict[str, tuple[Module, ast.ClassDef]]:
        if mod._instances is None:
            mod._instances = {}
            mod._instances = self._assigned_instances(mod, mod.tree.body)
        return mod._instances

    def _assigned_instances(
        self, mod: Module, nodes: Iterable[ast.AST]
    ) -> dict[str, tuple[Module, ast.ClassDef]]:
        """``x = Cls(...)`` — 이후 ``x.m()`` 가 어느 메서드인지 알기 위해."""
        out: dict[str, tuple[Module, ast.ClassDef]] = {}
        for node in nodes:
            if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)):
                continue
            found = self._resolve_expr(mod, node.value.func)
            if found is None or not isinstance(found[1], ast.ClassDef):
                continue
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = (found[0], found[1])
        return out

    def _receiver_class(
        self, mod: Module, recv: ast.AST, env: dict, cls: _Target | None
    ) -> _Target | None:
        if isinstance(recv, ast.Name):
            if recv.id in ("self", "cls") and cls is not None:
                return cls
            if recv.id in env:
                return env[recv.id]
            inst = self._instances(mod)
            if recv.id in inst:
                return inst[recv.id]
            return None
        if isinstance(recv, ast.Call):  # Cls().m()
            found = self._resolve_expr(mod, recv.func)
            if found is not None and isinstance(found[1], ast.ClassDef):
                return found
        return None

    def _callable_targets(
        self, mod: Module, expr: ast.AST, env: dict, cls: _Target | None
    ) -> list[_Target]:
        """호출식의 대상 또는 넘겨진 함수 참조 → 따라갈 정의들."""
        if isinstance(expr, ast.Lambda):
            return [(mod, expr)]
        if isinstance(expr, ast.Call):  # functools.partial(f, ...)
            if (resolve_name(expr.func, mod.aliases) or "").endswith("partial") and expr.args:
                return self._callable_targets(mod, expr.args[0], env, cls)
            return []
        if isinstance(expr, ast.Attribute):
            owner = self._receiver_class(mod, expr.value, env, cls)
            if owner is not None:
                m = self._method(owner[0], owner[1], expr.attr)  # type: ignore[arg-type]
                if m is not None:
                    return [m]
                if expr.attr == "start" and self._is_threadlike(owner[0], owner[1]):  # type: ignore[arg-type]
                    run = self._method(owner[0], owner[1], "run")  # type: ignore[arg-type]
                    return [run] if run is not None else []
                return []
        found = self._resolve_expr(mod, expr)
        if found is None:
            return []
        if isinstance(found[1], ast.ClassDef):  # 인스턴스화
            return [m for n in _CTOR_METHODS
                    if (m := self._method(found[0], found[1], n)) is not None]
        return [found]

    def _runner_args(self, mod: Module, call: ast.Call) -> list[ast.AST]:
        name = resolve_name(call.func, mod.aliases) or ""
        spec = _RUNNERS.get(name)
        if spec is None and isinstance(call.func, ast.Attribute):
            pos = _RUNNER_METHODS.get(call.func.attr)
            spec = (None, pos) if pos is not None else None
        if spec is None:
            return []
        kw, pos = spec
        out = [k.value for k in call.keywords if kw is not None and k.arg == kw]
        if not out and len(call.args) > pos:
            out.append(call.args[pos])
        return out

    # 범위 확장 -----------------------------------------------------

    def run(self, mod: Module, nodes: Iterable[ast.AST], *,
            cls: _Target | None = None, via_thread: bool = False) -> list[Reached]:
        todo: list[tuple[Module, list[ast.AST], _Target | None, bool]] = [
            (mod, list(nodes), cls, via_thread)
        ]
        while todo:
            m, body, owner, threaded = todo.pop()
            env = self._assigned_instances(m, body)
            for node in body:
                self.reached.append(Reached(m, node, threaded))
                if isinstance(node, ast.Call):
                    for tm, tdef in self._callable_targets(m, node.func, env, owner):
                        self._enqueue(todo, tm, tdef, threaded)
                    for arg in self._runner_args(m, node):
                        for tm, tdef in self._callable_targets(m, arg, env, owner):
                            self._enqueue(todo, tm, tdef, True)
                elif isinstance(node, (*_FUNCS, ast.ClassDef)):
                    # 데코레이터는 정의 순간 그 함수를 인자로 불린다. ``@atexit.register`` 는
                    # 함수를 종료 시 실행되게 등록한다.
                    for d in node.decorator_list:
                        if isinstance(d, ast.Call):
                            continue  # 호출식 데코레이터는 Call 노드로 이미 처리된다
                        if resolve_name(d, m.aliases) == "atexit.register":
                            self._enqueue(todo, m, node, True)
                        for tm, tdef in self._callable_targets(m, d, env, owner):
                            self._enqueue(todo, tm, tdef, threaded)
                elif self.import_toplevel and isinstance(node, (ast.Import, ast.ImportFrom)):
                    for sub in self._imported_modules(m, node):
                        key = (sub.relpath, 0)
                        if key not in self._done:
                            self._done.add(key)
                            todo.append((sub, list(module_level(sub.tree, include_main=False)),
                                         None, threaded))
        return self.reached

    def _enqueue(self, todo: list, mod: Module, fn: ast.AST, threaded: bool) -> None:
        key = (mod.relpath, id(fn))
        if key in self._done or self._followed >= MAX_FOLLOWED_DEFS:
            return
        self._done.add(key)
        self._followed += 1
        owner = None
        if isinstance(fn, _FUNCS):  # 메서드면 self 해석용으로 소유 클래스를 찾는다
            cls = _owners(mod).get(id(fn))
            owner = (mod, cls) if cls is not None else None
        todo.append((mod, body_nodes(fn), owner, threaded))

    def _imported_modules(self, mod: Module, node: ast.Import | ast.ImportFrom) -> list[Module]:
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif node.level == 0 and node.module:
            names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
        else:
            resolved = [mod.aliases.get(a.asname or a.name) for a in node.names]
            for r in resolved:
                if r:
                    names += [r.rpartition(".")[0], r]
        out = []
        for n in names:
            sub = self.index.find(n, mod) if n else None
            if sub is not None and sub is not mod and sub not in out:
                out.append(sub)
        return out
