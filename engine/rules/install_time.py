"""설치·import 시점 코드 안의 네트워크 전송·수상한 명령 실행 — 실제 악성 패키지의 주 경로.

다른 HIGH 규칙(.pth · cmdclass 훅 · 디코딩→exec)만으로는 실제 악성 PyPI 패키지 300개 중
13% 만 차단했다 (DataDog malicious-software-packages-dataset, seed 42 — tools/
eval_malware_dataset.py). 아무것도 못 잡은 139개 중 109개는 **setup.py 최상단**에
네트워크 전송·숨김 PowerShell·웹훅이 그대로 있었다. 훅도 난독화도 없이, setup.py 가
실행되는 순간(= pip install 이 sdist 를 빌드하는 순간) 돈다.

"무엇이 있느냐"가 아니라 "언제 돌고 무엇을 하느냐"로 본다:

* 범위 — 실제로 실행되는 코드만. setup.py 는 최상단 문장과 cmdclass 훅 클래스 전체,
  그리고 그 둘이 import 하는 **패키지 안 로컬 모듈**(``from main import main; main()``)
  전체. 그 밖의 모듈은 import 시점에 도는 최상단 문장만 (``if __name__ == "__main__"``
  블록과 함수·클래스 본문은 제외 — 부르기 전엔 안 돈다).
* 조건 — 그 범위 안의 (1) 네트워크 호출, 또는 (2) 수상한 명령을 담은 프로세스 실행.
  ``subprocess.check_output(["git", "describe"])`` 같은 평범한 빌드 명령은 (2)가 아니다.

별도로, 토큰이 박힌 Discord 웹훅·Telegram 봇 주소는 어디에 있든 HIGH 다. 정상 코드가
남의 채널에 쓰는 비밀 토큰을 패키지에 넣어 배포할 이유가 없다.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable, Iterator
from pathlib import PurePosixPath

from api.schemas import Severity, StaticFinding
from engine.rules.base import FileContext, make_finding

RULE_INSTALL_TIME = "custom-install-time-exec"
RULE_EXFIL = "custom-exfil-endpoint"

#: 실제로 패킷을 내보내는 함수만. 모듈의 아무 함수가 아니다 — httpx.Timeout()·
#: requests.Session()·socket.getprotobyname() 은 통신하지 않는다 (정상 상위 300개 실측
#: 오탐: litellm·dill·dnspython·google-resumable-media).
_NETWORK_FUNCS = {
    "requests": {"get", "post", "put", "patch", "delete", "head", "options", "request"},
    "httpx": {"get", "post", "put", "patch", "delete", "head", "options", "request", "stream"},
    "urllib3": {"request"},
    "aiohttp": {"request"},
    # DNS 질의도 외부로 나간다 — 실측 악성 샘플의 DNS 유출 경로(getaddrinfo)
    "socket": {"create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex",
               "gethostbyaddr"},
    "http.client": {"HTTPConnection", "HTTPSConnection"},
    "ftplib": {"FTP", "FTP_TLS"},
    "smtplib": {"SMTP", "SMTP_SSL"},
    "telnetlib": {"Telnet"},
}
#: 어느 모듈에서 왔든 이 이름이면 다운로드다 (urllib.request.urlopen, py2 urllib2.urlopen).
_NETWORK_NAMES = {"urlopen", "urlretrieve"}

_SPAWN_ROOT_ATTRS = {
    "subprocess": {"Popen", "run", "call", "check_call", "check_output", "getoutput",
                   "getstatusoutput"},
    "os": {"system", "popen", "startfile", "execv", "execve", "execl", "execlp", "execvp",
           "spawnv", "spawnl", "spawnve", "spawnlp"},
}
_SPAWN_BARE = {"Popen", "system", "check_output", "check_call", "getoutput", "startfile"}

#: 설치 시점에 정상 패키지가 돌릴 이유가 없는 명령·옵션. git·cmake·pip 같은 빌드 명령은 없다.
_SUSPICIOUS_CMD = re.compile(
    r"powershell|pwsh|-enc(?:odedcommand)?\b|windowstyle\s+hidden|-w\s+hidden|mshta|certutil"
    r"|bitsadmin|rundll32|regsvr32|invoke-webrequest|\biwr\b|invoke-expression|\biex\b"
    r"|\bcurl\b|\bwget\b|/dev/tcp|\bnc\s+-e|base64\s+-d|\|\s*(?:ba)?sh\b|schtasks|crontab"
    # 창 없는 파이썬 — 임시 파일에 쓴 코드를 몰래 돌릴 때 쓴다 (실측: fluiddaddy)
    r"|pythonw",
    re.IGNORECASE,
)
_HIDDEN_FLAGS = {"CREATE_NO_WINDOW", "DETACHED_PROCESS"}

_EXFIL_PATTERNS = (
    ("Discord 웹훅", re.compile(r"discord(?:app)?\.com/api/webhooks/\d{15,}/[\w-]{20,}")),
    ("Telegram 봇 토큰", re.compile(r"api\.telegram\.org/bot\d{6,}:[\w-]{30,}")),
)


# ── 이름 해석 ─────────────────────────────────────────────────────

def _dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _aliases(tree: ast.Module) -> dict[str, str]:
    """import 별칭 → 실제 이름. ``from os import system as _ssystem`` 처럼 이름을 바꿔 숨기는
    게 실측 샘플(fluiddaddy)에 있었다. 맨 이름 import 도 풀린다 (from subprocess import run)."""
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


def _resolve(func: ast.AST, aliases: dict[str, str]) -> str | None:
    name = _dotted(func)
    if not name:
        return None
    head, dot, rest = name.partition(".")
    return aliases[head] + dot + rest if head in aliases else name


def _is_network_call(call: ast.Call, aliases: dict[str, str]) -> bool:
    name = _resolve(call.func, aliases)
    if not name:
        return False
    module, _, func = name.rpartition(".")
    if func in _NETWORK_NAMES:
        return True
    return func in _NETWORK_FUNCS.get(module, ())


def _is_spawn(call: ast.Call, aliases: dict[str, str]) -> bool:
    name = _resolve(call.func, aliases)
    if not name:
        return False
    if "." not in name:
        return name in _SPAWN_BARE
    root, _, attr = name.rpartition(".")
    return attr in _SPAWN_ROOT_ATTRS.get(root.split(".")[-1], set())


def _suspicious_spawn(call: ast.Call, aliases: dict[str, str]) -> str | None:
    """수상한 명령이면 그 근거 문자열, 아니면 None."""
    if not _is_spawn(call, aliases):
        return None
    for sub in ast.walk(call):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            m = _SUSPICIOUS_CMD.search(sub.value)
            if m:
                return m.group(0)
    for kw in call.keywords:
        names = {n.attr if isinstance(n, ast.Attribute) else getattr(n, "id", None)
                 for n in ast.walk(kw.value)}
        hidden = names & _HIDDEN_FLAGS
        if kw.arg == "creationflags" and hidden:
            return sorted(hidden)[0]
    return None


# ── 실행 범위 ─────────────────────────────────────────────────────

_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def _walk_executed(node: ast.AST) -> Iterator[ast.AST]:
    """ast.walk 와 같되, 호출해야만 도는 함수·클래스·람다 본문으로는 내려가지 않는다."""
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        stack.extend(c for c in ast.iter_child_nodes(cur) if not isinstance(c, _DEFS))


def _is_main_guard(stmt: ast.stmt) -> bool:
    if not isinstance(stmt, ast.If) or not isinstance(stmt.test, ast.Compare):
        return False
    parts = [stmt.test.left, *stmt.test.comparators]
    return any(isinstance(p, ast.Name) and p.id == "__name__" for p in parts)


def _module_level(tree: ast.Module, *, include_main: bool) -> Iterator[ast.AST]:
    for stmt in tree.body:
        if isinstance(stmt, _DEFS):
            continue
        if not include_main and _is_main_guard(stmt):
            continue
        yield from _walk_executed(stmt)


def _follow_local_calls(nodes: list[ast.AST], tree: ast.Module) -> list[ast.AST]:
    """실행 범위에서 부르는 **같은 파일의 함수** 본문을 범위에 더한다 (재귀, 중복 없이).

    실측(dependency-confusion 샘플): 훅은 ``custom_command()`` 한 줄이고, 유출 코드는 그
    함수 안 ``socket.getaddrinfo(...)`` 에 있었다. 함수 본문을 안 따라가면 못 본다.
    """
    funcs = {
        n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    out, todo, done = list(nodes), list(nodes), set()
    while todo:
        node = todo.pop()
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        fn = funcs.get(node.func.id)
        if fn is None or fn.name in done:
            continue
        done.add(fn.name)
        body = [n for stmt in fn.body for n in _walk_executed(stmt)]
        out.extend(body)
        todo.extend(body)
    return out


def _hook_classes(tree: ast.Module) -> list[ast.ClassDef]:
    """setup(cmdclass={...}) 가 가리키는 같은 파일의 클래스들."""
    names = {
        v.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        for kw in node.keywords
        if kw.arg == "cmdclass" and isinstance(kw.value, ast.Dict)
        for v in kw.value.values
        if isinstance(v, ast.Name)
    }
    return [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name in names]


def _local_module_scopes(
    nodes: list[ast.AST], aliases: dict[str, str], ctx: FileContext
) -> list[tuple[str, list[ast.AST], dict[str, str]]]:
    """setup.py 의 실행 범위가 import 해서 **실제로 부르는** 로컬 모듈 코드.

    모듈 파일 전체가 아니라 (1) 그 모듈의 최상단(import 순간 실행)과 (2) setup.py 가 부른
    함수의 본문만이다. 파일 전체로 잡으면 버전 문자열만 가져오는 nodeenv 의 setup.py 가
    nodeenv.py 안 모든 urlopen 때문에 걸렸다. 악성 쪽(``from main import main; main()``)은
    (2)로 그대로 잡힌다.
    """
    if ctx.tree is None:
        return []
    base = PurePosixPath(ctx.relpath).parent
    called = {_resolve(n.func, aliases) for n in nodes if isinstance(n, ast.Call)}
    imported = {
        node.module if isinstance(node, ast.ImportFrom) else a.name
        for node in nodes
        if isinstance(node, (ast.Import, ast.ImportFrom))
        and not getattr(node, "level", 0)
        and (not isinstance(node, ast.ImportFrom) or node.module)
        for a in node.names
    }
    out = []
    for mod in sorted(imported):
        rel = PurePosixPath(*mod.split("."))
        for cand in (base / rel.with_suffix(".py"), base / rel / "__init__.py"):
            text = ctx.tree.read(cand.as_posix())
            if text is None:
                continue
            try:
                sub = ast.parse(text)
            except (SyntaxError, ValueError):
                break
            funcs = {n.name: n for n in sub.body
                     if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
            scope = list(_module_level(sub, include_main=False))
            for name, fn in funcs.items():
                if f"{mod}.{name}" in called:
                    scope.extend(n for stmt in fn.body for n in _walk_executed(stmt))
            out.append((cand.name, _follow_local_calls(scope, sub), _aliases(sub)))
            break
    return out


# ── 규칙 ──────────────────────────────────────────────────────────

def _check(nodes: Iterable[ast.AST], ctx: FileContext, when: str, aliases: dict[str, str],
           origin: str = "") -> Iterator[StaticFinding]:
    seen: set[tuple[int, str]] = set()
    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        if _is_network_call(node, aliases):
            what = f"네트워크 호출 {_resolve(node.func, aliases)}()"
        elif (token := _suspicious_spawn(node, aliases)) is not None:
            what = f"수상한 명령 실행 {_resolve(node.func, aliases)}() — '{token}'"
        else:
            continue
        key = (node.lineno, what)
        if key in seen:
            continue
        seen.add(key)
        yield make_finding(
            rule=RULE_INSTALL_TIME,
            cwe="CWE-506",
            severity=Severity.HIGH,
            ctx=ctx,
            line=node.lineno,
            detail=f"{when} {what}{origin}",
        )


def _is_package_module(ctx: FileContext) -> bool:
    """누군가 import 할 코드인가 — 패키지 디렉터리(__init__.py 있음) 안이거나 sdist 최상위
    단일 모듈. ``scripts/``·``tools/``·``other/`` 의 보조 스크립트는 import 되지 않는다
    (정상 상위 300개 실측 오탐: fastapi·black·pyzmq·defusedxml·pyasn1-modules)."""
    rel = PurePosixPath(ctx.relpath)
    if rel.name == "__init__.py":
        return True
    if ctx.tree is not None and ctx.tree.read((rel.parent / "__init__.py").as_posix()) is not None:
        return True
    # sdist 최상위(이름-버전/모듈.py) 의 단일 모듈 — setup.py 가 옆에 있으면 py_modules 다
    return ctx.tree is not None and ctx.tree.read((rel.parent / "setup.py").as_posix()) is not None


def install_time_exec(ctx: FileContext, tree: ast.Module) -> Iterable[StaticFinding]:
    aliases = _aliases(tree)
    if ctx.name == "setup.py":
        top = _follow_local_calls(list(_module_level(tree, include_main=True)), tree)
        hooks = _follow_local_calls([n for c in _hook_classes(tree) for n in ast.walk(c)], tree)
        yield from _check(top, ctx, "pip install 시 setup.py 가 실행하는", aliases)
        yield from _check(hooks, ctx, "pip install 시 설치 훅이 실행하는", aliases)
        # 훅·최상단이 불러 실행하는 패키지 안 모듈은 파일 전체가 설치 시점 코드다
        for fname, scope, sub_aliases in _local_module_scopes(top + hooks, aliases, ctx):
            when = "pip install 시 setup.py 가 불러 실행하는"
            yield from _check(scope, ctx, when, sub_aliases, origin=f" (in {fname})")
        return
    if not _is_package_module(ctx):
        return
    scope = _follow_local_calls(list(_module_level(tree, include_main=False)), tree)
    yield from _check(scope, ctx, "import 시점에 실행되는", aliases)


def exfil_endpoint(ctx: FileContext, tree: ast.Module) -> Iterable[StaticFinding]:
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        for label, pattern in _EXFIL_PATTERNS:
            if pattern.search(node.value):
                yield make_finding(
                    rule=RULE_EXFIL,
                    cwe="CWE-200",
                    severity=Severity.HIGH,
                    ctx=ctx,
                    line=node.lineno,
                    detail=f"토큰이 포함된 {label} 주소가 코드에 박혀 있음 — 유출 채널의 전형",
                )
                break
