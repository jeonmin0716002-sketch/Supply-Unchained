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
            yield make_finding(
                rule=RULE_INSTALL_HOOK,
                cwe="CWE-94",
                severity=Severity.HIGH if victim_side else Severity.MEDIUM,
                ctx=ctx,
                line=keyword.value.lineno,
                detail=(
                    f"setup() overrides the {sorted(hooked)} command(s) via cmdclass — "
                    + (
                        "this code runs on the installing machine during 'pip install'"
                        if victim_side
                        else "runs at build/publish time, not on the installing machine"
                    )
                ),
            )
