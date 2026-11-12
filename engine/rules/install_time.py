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
import tomllib
from collections.abc import Iterable, Iterator
from pathlib import Path, PurePosixPath

from api.schemas import Severity, StaticFinding
from engine.rules.base import (
    FileContext,
    dotted_name,
    import_aliases,
    make_finding,
    resolve_name,
)
from engine.rules.exec_scope import (
    Module,
    ModuleIndex,
    Reached,
    Scope,
    body_nodes,
    module_level,
)

RULE_INSTALL_TIME = "custom-install-time-exec"
RULE_EXFIL = "custom-exfil-endpoint"
RULE_INSTALL_SPAWN = "custom-install-time-spawn"

#: detail 에서 "무엇을 했는가"와 "어디서 불렸는가"를 가르는 표식 (version_diff 가 쓴다)
ORIGIN_MARK = "←"

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

#: 설치·import 시점에 정상 패키지가 흔히 돌리는 빌드·환경 조사 명령. 이 밖의 프로세스 실행은
#: 수상 토큰이 없어도 MEDIUM 으로 남긴다 — 탈취 패키지 lightning 2.6.2 는
#: ``Popen([sys.executable, 번들 스크립트])``, memoryos 2.0.34 는 ``Popen([번들 바이너리, ...])``
#: 였고 둘 다 명령 문자열이 평범했다. 홀로는 판정을 바꾸지 않고(정상 라이브러리도 import 시
#: GPU 확인 등을 한다), **새 릴리스에서 처음 나타나면** version_diff 가 HIGH 로 올린다.
_ORDINARY_COMMANDS = frozenset({
    "git", "hg", "svn", "cmake", "make", "gmake", "ninja", "meson", "pkg-config", "pkgconf",
    "gcc", "g++", "cc", "c++", "clang", "clang++", "cl", "ld", "ar", "gfortran", "icc", "icpc",
    "icx", "ifort", "nvcc", "hipcc", "mpicc", "mpicxx", "swig", "rustc", "cargo", "go",
    "nvidia-smi", "rocm-smi", "rocminfo", "uname", "ldconfig", "ldd", "otool", "xcrun",
    "xcode-select", "sw_vers", "lsb_release", "lscpu", "lspci", "sysctl", "getconf", "nproc",
    "which", "where", "brew", "ccache", "sccache", "file",
})

_EXFIL_PATTERNS = (
    ("Discord 웹훅", re.compile(r"discord(?:app)?\.com/api/webhooks/\d{15,}/[\w-]{20,}")),
    ("Telegram 봇 토큰", re.compile(r"api\.telegram\.org/bot\d{6,}:[\w-]{30,}")),
)


# ── 이름 해석 ─────────────────────────────────────────────────────

# 규칙 공용 이름 해석 (engine/rules/base.py)
_dotted = dotted_name
_aliases = import_aliases
_resolve = resolve_name


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


def command_head(call: ast.Call, aliases: dict[str, str]) -> str:
    """실행하는 명령의 이름(경로·확장자 뺀 첫 낱말). 정적으로 모르면 ``?``.

    ``[sys.executable, ...]`` 은 ``python`` — 파이썬으로 무엇을 돌리는지는 뒤 인자에 있다.
    """
    arg: ast.AST | None = call.args[0] if call.args else next(
        (k.value for k in call.keywords if k.arg in ("args", "cmd", "command", "path")), None)
    if isinstance(arg, (ast.List, ast.Tuple)) and arg.elts:
        arg = arg.elts[0]
    elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        arg = ast.Constant(arg.value.strip().split(" ")[0] if arg.value.strip() else "")
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value:
        name = PurePosixPath(arg.value.strip("\"'").replace("\\", "/")).name.lower()
        return name.removesuffix(".exe")
    if arg is not None and _resolve(arg, aliases) == "sys.executable":
        return "python"
    return "?"


# ── 실행 범위 ─────────────────────────────────────────────────────
# 범위 계산 자체는 engine/rules/exec_scope.py — 파일 경계를 넘는 추적(다른 모듈 함수,
# 인스턴스화, 스레드에 넘긴 함수)의 실측 근거도 그쪽 docstring 에 있다.


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


def _seed_module(ctx: FileContext, tree: ast.Module) -> tuple[ModuleIndex, Module]:
    index = ModuleIndex.of(ctx.tree)
    mod = index.module(ctx.relpath, tree) if ctx.tree is not None else None
    if mod is None or mod.tree is not tree:  # 트리 없이 파일 하나만 볼 때
        name = PurePosixPath(ctx.relpath).stem
        mod = Module(relpath=ctx.relpath, tree=tree, name=name,
                     root=PurePosixPath(ctx.relpath).parent, is_pkg=False)
        mod.aliases = _aliases(tree)
        mod.defs = {d.name: d for d in tree.body
                    if isinstance(d, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    return index, mod


# ── 규칙 ──────────────────────────────────────────────────────────

def _check(reached: Iterable[Reached], ctx: FileContext, when: str,
           *, seed: Module) -> Iterator[StaticFinding]:
    """범위 안의 호출 중 (1) 네트워크 (2) 수상한 명령 실행을 HIGH 로, (3) 그 밖의 프로세스
    실행(평범한 빌드·조사 명령 제외)을 MEDIUM 으로.

    다른 모듈에 있는 코드는 그 모듈 위치로 보고하고, 어디서 불렸는지를 ``←`` 뒤에 적는다.
    ``←`` 앞부분(무엇을 했는가)은 버전 비교(engine/version_diff.py)가 행위의 이름으로 쓴다.
    """
    seen: set[tuple[str, int, str]] = set()
    for r in reached:
        node = r.node
        if not isinstance(node, ast.Call):
            continue
        aliases = r.module.aliases
        if _is_network_call(node, aliases):
            what = f"네트워크 호출 {_resolve(node.func, aliases)}()"
        elif (token := _suspicious_spawn(node, aliases)) is not None:
            what = f"수상한 명령 실행 {_resolve(node.func, aliases)}() — '{token}'"
        elif _is_spawn(node, aliases):
            head = command_head(node, aliases)
            if head in _ORDINARY_COMMANDS:
                continue
            what = f"프로세스 실행 {_resolve(node.func, aliases)}() — 명령 '{head}'"
        else:
            continue
        key = (r.module.relpath, node.lineno, what)
        if key in seen:
            continue
        seen.add(key)
        plain = what.startswith("프로세스 실행")
        yield make_finding(
            rule=RULE_INSTALL_SPAWN if plain else RULE_INSTALL_TIME,
            cwe="CWE-78" if plain else "CWE-506",
            severity=Severity.MEDIUM if plain else Severity.HIGH,
            ctx=_ctx_for(r.module, ctx),
            line=node.lineno,
            detail=f"{when} {what}{_origin(r, seed)}",
        )


def _ctx_for(mod: Module, ctx: FileContext) -> FileContext:
    """위치는 실제 코드가 있는 모듈로 보고한다 (setup.py 줄번호로 붙이면 엉뚱한 줄)."""
    if mod.relpath == ctx.relpath:
        return ctx
    return FileContext(path=Path(mod.relpath), relpath=mod.relpath, text="", tree=ctx.tree)


def _origin(r: Reached, seed: Module) -> str:
    parts = []
    if r.via_thread:
        parts.append("스레드·종료 훅 등에 넘겨져 실행")
    if r.module.relpath != seed.relpath:
        parts.append(f"{seed.relpath} 에서 불림")
    return f" {ORIGIN_MARK} " + ", ".join(parts) if parts else ""


def _is_install_script(ctx: FileContext) -> bool:
    """sdist 최상위의 진짜 설치 스크립트인가. 패키지 안에 ``setup.py`` 라는 이름의 일반 모듈이
    있을 수 있다 (실측 오탐: pigeon-home-runner 의 ``runner/setup.py`` — 설정 마법사). sdist
    루트에는 PKG-INFO 가 늘 있고, 빌드 설정 파일이 옆에 있다."""
    if ctx.name != "setup.py":
        return False
    if ctx.tree is None:
        return True
    base = PurePosixPath(ctx.relpath).parent
    return any(
        ctx.tree.read((base / marker).as_posix()) is not None
        for marker in ("PKG-INFO", "setup.cfg", "pyproject.toml")
    )


def _is_test_file(rel: PurePosixPath) -> bool:
    """패키지에 딸려 배포된 테스트. 실측 오탐: rapid-mlx 의 ``_integration_tests/test_*.py`` 가
    최상단에서 로컬 서버(localhost)에 모델 목록을 묻는다. 테스트는 pytest 로 돌릴 때만 실행된다."""
    if rel.name == "conftest.py" or rel.name.startswith("test_") or rel.stem.endswith("_test"):
        return True
    return any(part in ("test", "tests") or part.endswith("_tests") for part in rel.parts[:-1])


def _is_package_module(ctx: FileContext) -> bool:
    """누군가 import 할 코드인가 — 패키지 디렉터리(__init__.py 있음) 안이거나 sdist 최상위
    단일 모듈. ``scripts/``·``tools/``·``other/`` 의 보조 스크립트는 import 되지 않는다
    (정상 상위 300개 실측 오탐: fastapi·black·pyzmq·defusedxml·pyasn1-modules)."""
    rel = PurePosixPath(ctx.relpath)
    if rel.name == "__main__.py":
        return False  # python -m 으로 직접 실행할 때만 돈다 (실측 오탐: rutis)
    if _is_test_file(rel):
        return False  # pytest 가 모으는 파일 — 사용자 코드가 import 하지 않는다
    if rel.name == "__init__.py":
        return True
    if ctx.tree is not None and ctx.tree.read((rel.parent / "__init__.py").as_posix()) is not None:
        return True
    # sdist 최상위(이름-버전/모듈.py) 의 단일 모듈 — setup.py 가 옆에 있으면 py_modules 다
    return ctx.tree is not None and ctx.tree.read((rel.parent / "setup.py").as_posix()) is not None


def install_time_exec(ctx: FileContext, tree: ast.Module) -> Iterable[StaticFinding]:
    if _is_install_script(ctx):
        index, seed = _seed_module(ctx, tree)
        # setup.py 범위 안의 import 는 그 로컬 모듈 최상단을 이번에 처음 실행시킨다
        top = Scope(index, import_toplevel=True).run(
            seed, list(module_level(tree, include_main=True)))
        yield from _check(_split(top, seed, True), ctx,
                          "pip install 시 setup.py 가 실행하는", seed=seed)
        yield from _check(_split(top, seed, False), ctx,
                          "pip install 시 setup.py 가 불러 실행하는", seed=seed)
        hooks = Scope(index, import_toplevel=True)
        for cls in _hook_classes(tree):
            hooks.run(seed, list(ast.walk(cls)), cls=(seed, cls))
        yield from _check(_split(hooks.reached, seed, True), ctx,
                          "pip install 시 설치 훅이 실행하는", seed=seed)
        yield from _check(_split(hooks.reached, seed, False), ctx,
                          "pip install 시 setup.py 가 불러 실행하는", seed=seed)
        return
    if not _is_package_module(ctx):
        return
    index, seed = _seed_module(ctx, tree)
    reached = Scope(index).run(seed, list(module_level(tree, include_main=False)))
    yield from _check(reached, ctx, "import 시점에 실행되는", seed=seed)


def _split(reached: list[Reached], seed: Module, local: bool) -> list[Reached]:
    return [r for r in reached if (r.module.relpath == seed.relpath) == local]


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


# ── 콘솔 스크립트 진입점 ──────────────────────────────────────────
# [project.scripts]·setup(entry_points=...)·entry_points.txt 의 함수는 사용자가 명령을
# **직접 실행할 때** 돈다. CLI 가 네트워크를 쓰는 건 정상이라(다운로더·API 클라이언트)
# 네트워크 호출은 보지 않는다. 수상한 명령 실행(숨김 PowerShell, curl|sh 등)만 HIGH 다 —
# import 시점 규칙과 같은 토큰 목록이고, 정상 상위 300개에서 이 조합이 나온 패키지 수는
# docs/eval/py-engine.md 에 있다.

RULE_ENTRYPOINT = "custom-entrypoint-exec"
_ENTRY_FILES = {"pyproject.toml", "setup.cfg", "entry_points.txt", "setup.py"}
_SPEC = re.compile(r"^\s*([\w.\-]+)\s*=\s*([\w.]+)\s*:\s*([\w.]+)")


def _entry_specs(ctx: FileContext) -> list[tuple[str, str]]:
    """(모듈 점 이름, 함수 이름) 목록 — console_scripts·gui_scripts 만."""
    specs: list[str] = []
    if ctx.name == "pyproject.toml":
        try:
            data = tomllib.loads(ctx.text)
        except (tomllib.TOMLDecodeError, ValueError):
            return []
        proj = data.get("project") or {}
        tables = [proj.get("scripts"), proj.get("gui-scripts"),
                  ((data.get("tool") or {}).get("poetry") or {}).get("scripts")]
        specs = [f"x = {v}" for t in tables if isinstance(t, dict)
                 for v in t.values() if isinstance(v, str)]
    elif ctx.name in ("setup.cfg", "entry_points.txt"):
        section = None
        for line in ctx.text.splitlines():
            stripped = line.strip()
            if stripped.startswith("["):
                section = stripped.strip("[]").strip()
            elif section in ("console_scripts", "gui_scripts", "options.entry_points"):
                if stripped.startswith(("console_scripts", "gui_scripts")):
                    stripped = stripped.split("=", 1)[1]
                specs.append(stripped)
    elif ctx.name == "setup.py":
        try:
            tree = ast.parse(ctx.text)
        except (SyntaxError, ValueError):
            return []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "entry_points":
                        specs += [n.value for n in ast.walk(kw.value)
                                  if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    out = []
    for spec in specs:
        m = _SPEC.match(spec) or _SPEC.match(f"x = {spec.strip()}")
        if m:
            out.append((m.group(2), m.group(3)))
    return out


def entrypoint_exec(ctx: FileContext) -> Iterable[StaticFinding]:
    if ctx.name not in _ENTRY_FILES or ctx.tree is None:
        return
    if ctx.name == "setup.py" and not _is_install_script(ctx):
        return
    specs = _entry_specs(ctx)
    if not specs:
        return
    index = ModuleIndex.of(ctx.tree)
    base = PurePosixPath(ctx.relpath).parent
    if base.name.endswith((".egg-info", ".dist-info")):
        base = base.parent
    seen: set[tuple[str, int]] = set()
    for modname, attr in specs:
        rel = PurePosixPath(*modname.split("."))
        mod = None
        for root in (base, base / "src"):
            for cand in (root / rel.with_suffix(".py"), root / rel / "__init__.py"):
                mod = index.module(cand.as_posix())
                if mod is not None:
                    break
            if mod is not None:
                break
        if mod is None:
            continue
        scope = Scope(index)
        target = scope._lookup_in(mod, attr.split("."), 0)
        if target is None or not isinstance(target[1], (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for r in scope.run(target[0], body_nodes(target[1])):
            node = r.node
            if not isinstance(node, ast.Call):
                continue
            token = _suspicious_spawn(node, r.module.aliases)
            if token is None or (r.module.relpath, node.lineno) in seen:
                continue
            seen.add((r.module.relpath, node.lineno))
            what = f"수상한 명령 실행 {_resolve(node.func, r.module.aliases)}() — '{token}'"
            yield make_finding(
                rule=RULE_ENTRYPOINT, cwe="CWE-506", severity=Severity.HIGH,
                ctx=_ctx_for(r.module, ctx), line=node.lineno,
                detail=f"콘솔 명령 {modname}:{attr} 실행 시 {what} {ORIGIN_MARK} {ctx.relpath}",
            )
