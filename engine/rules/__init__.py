"""Custom rule registry.

Adding a rule = write the callable in a module here, then list it below. The
analyzer discovers nothing implicitly, so the active rule set is always
readable in one place.
"""

from engine.rules.base import AstRule, FileContext, FileRule, make_finding
from engine.rules.code_patterns import dangerous_calls, obfuscated_payload
from engine.rules.install_hooks import pth_autoexec, setup_command_hook

#: Applied to every readable file, Python or not.
FILE_RULES: tuple[FileRule, ...] = (pth_autoexec,)

#: Applied to Python modules that parse successfully.
AST_RULES: tuple[AstRule, ...] = (
    dangerous_calls,
    obfuscated_payload,
    setup_command_hook,
)

__all__ = [
    "AST_RULES",
    "FILE_RULES",
    "AstRule",
    "FileContext",
    "FileRule",
    "make_finding",
]
