"""Install-time execution hooks — the coverage gap this project targets.

``pip-audit``/``safety`` only answer "does this version have a CVE", and Bandit
only looks at Python source it is pointed at. Neither flags the delivery path
most real PyPI supply-chain attacks actually use: code that runs *while you are
installing*, before you ever import the package.

Two hooks are covered here:

* ``.pth`` files — ``site.py`` executes any line starting with ``import`` at
  interpreter startup, for every future Python process. Nothing needs to import
  the package for the payload to run.
* ``setup.py`` command overrides — replacing the ``install``/``develop``
  command class runs attacker code during ``pip install`` of an sdist.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from api.schemas import Severity, StaticFinding
from engine.rules.base import FileContext, make_finding

RULE_PTH = "custom-pth"
RULE_INSTALL_HOOK = "custom-install-hook"

# distutils/setuptools commands an attacker overrides to get execution during
# install. `build_ext` is deliberately absent: compiled packages legitimately
# override it, so flagging it would be mostly false positives.
_HOOKED_COMMANDS = {"install", "develop", "egg_info", "build_py", "sdist", "bdist_wheel"}

# Overriding these runs attacker code on the victim's machine during
# `pip install`, which is the attack this project exists to catch.
# The rest mostly run on the *publisher's* machine or during a build, so they
# are worth reporting but not worth blocking on alone.
_VICTIM_SIDE_COMMANDS = {"install", "develop"}

_SETUP_FILENAMES = {"setup.py"}

# 후킹된 커맨드 클래스 **안에서** 실행/네트워크 싱크를 부르는지가 HIGH 의 조건이다.
# 오버라이드 자체는 신호가 아니다 — setuptools 69.5.1 이 직접 install 을 오버라이드해
# .pth 를 심는다(setup.py:85). 그걸 HIGH 로 잡으면 거의 모든 파이썬 환경에 깔려 있는
# 패키지가 block 되고, 그런 스캐너는 아무도 안 쓴다. code_patterns.py 상단의 판단
# 기준과 같다: 존재가 아니라 조합이 신호다.
_HOOK_EXEC_SINKS = {
    "system", "popen", "exec", "eval", "compile", "__import__",
    "execv", "execve", "execl", "execlp", "execvp", "spawn", "spawnv",
    "run", "call", "check_call", "check_output", "Popen",
    "urlopen", "urlretrieve", "get", "post", "socket", "connect",
}


def _calls_exec_sink(node: ast.AST) -> bool:
    """서브트리 안에서 실행·네트워크 싱크 호출이 보이면 True."""
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        fn = sub.func
        name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
        if name in _HOOK_EXEC_SINKS:
            return True
    return False


def _hook_class_defs(tree: ast.Module, value: ast.expr) -> ast.ClassDef | None:
    """cmdclass 값이 가리키는 클래스 정의를 같은 모듈에서 찾는다.

    다른 모듈에서 import 해 온 경우엔 여기서 볼 수 없어 None 을 돌려준다.
    """
    if not isinstance(value, ast.Name):
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == value.id:
            return node
    return None


def pth_autoexec(ctx: FileContext) -> Iterable[StaticFinding]:
    """Flag ``.pth`` lines that ``site.py`` will execute at every startup."""
    if ctx.suffix != ".pth":
        return

    for lineno, raw in enumerate(ctx.text.splitlines(), start=1):
        line = raw.strip()
        # site.py's exact trigger: the line must *start with* "import " or
        # "import\t". Anything else in a .pth is treated as a path entry.
        if not line.startswith(("import ", "import\t")):
            continue

        yield make_finding(
            rule=RULE_PTH,
            cwe="CWE-94",
            severity=Severity.HIGH,
            ctx=ctx,
            line=lineno,
            detail=(
                "'.pth' file executes code at interpreter startup "
                f"(site.py runs this line in every Python process): {line[:120]}"
            ),
        )


def setup_command_hook(ctx: FileContext, tree: ast.Module) -> Iterable[StaticFinding]:
    """Flag ``setup(cmdclass={...})`` overrides of install-time commands."""
    if ctx.name not in _SETUP_FILENAMES:
        return

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg != "cmdclass" or not isinstance(keyword.value, ast.Dict):
                continue

            hooked = [
                key.value
                for key in keyword.value.keys
                if isinstance(key, ast.Constant)
                and isinstance(key.value, str)
                and key.value in _HOOKED_COMMANDS
            ]
            if not hooked:
                continue

            victim_side = sorted(set(hooked) & _VICTIM_SIDE_COMMANDS)

            # 피해자 쪽 커맨드를 가로챈 것만으로는 HIGH 가 아니다. 그 클래스가 실제로
            # 무언가를 *실행*할 때만 HIGH — 아래 _calls_exec_sink 주석 참고.
            sink_hit = False
            unresolved = False
            for key, value in zip(keyword.value.keys, keyword.value.values, strict=False):
                if not (
                    isinstance(key, ast.Constant)
                    and key.value in (set(hooked) & _VICTIM_SIDE_COMMANDS)
                ):
                    continue
                cls = _hook_class_defs(tree, value)
                if cls is None:
                    unresolved = True
                elif _calls_exec_sink(cls):
                    sink_hit = True

            if victim_side and sink_hit:
                severity = Severity.HIGH
                why = (
                    "this code runs on the installing machine during 'pip install' "
                    "and the overriding class calls an exec/network sink"
                )
            elif victim_side:
                severity = Severity.MEDIUM
                why = (
                    "runs on the installing machine during 'pip install'; the overriding "
                    "class was not seen calling an exec/network sink"
                    + (" (defined outside this file — could not inspect)" if unresolved else "")
                )
            else:
                severity = Severity.MEDIUM
                why = "runs at build/publish time, not on the installing machine"

            yield make_finding(
                rule=RULE_INSTALL_HOOK,
                cwe="CWE-94",
                severity=severity,
                ctx=ctx,
                line=keyword.value.lineno,
                detail=f"setup() overrides the {sorted(hooked)} command(s) via cmdclass — {why}",
            )
