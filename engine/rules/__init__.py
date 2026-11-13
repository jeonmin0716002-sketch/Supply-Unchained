"""Custom rule registry.

Adding a rule = write the callable in a module here, then list it below. The
analyzer discovers nothing implicitly, so the active rule set is always
readable in one place.
"""

from engine.rules.base import AstRule, FileContext, FileRule, make_finding
from engine.rules.code_patterns import dangerous_calls, obfuscated_payload
from engine.rules.install_hooks import pth_autoexec, setup_command_hook
from engine.rules.install_time import (
    RULE_BENIGN_NET,
    RULE_ENTRYPOINT,
    RULE_INDIRECT_NET,
    RULE_INSTALL_SPAWN,
    RULE_INSTALL_TIME,
    entrypoint_exec,
    exfil_endpoint,
    install_time_exec,
)

#: Applied to every readable file, Python or not.
FILE_RULES: tuple[FileRule, ...] = (pth_autoexec, entrypoint_exec)

#: Applied to Python modules that parse successfully.
AST_RULES: tuple[AstRule, ...] = (
    dangerous_calls,
    obfuscated_payload,
    setup_command_hook,
    install_time_exec,
    exfil_endpoint,
)

#: 파일 경계를 넘어 범위를 따라가는 규칙 — 여러 시작 파일에서 같은 코드에 닿으므로 위치당
#: 한 번만 남긴다 (실측: memoryos 는 수백 모듈이 같은 get_logger() 를 거쳐 같은 줄에 닿는다).
ONE_PER_LOCATION: frozenset[str] = frozenset(
    {RULE_INSTALL_TIME, RULE_INSTALL_SPAWN, RULE_ENTRYPOINT, RULE_INDIRECT_NET,
     RULE_BENIGN_NET}
)
#: 같은 줄의 같은 행위를 범위에 따라 다른 규칙으로 낸 것 — 가장 심각한 하나만 남긴다
SAME_BEHAVIOR: dict[str, str] = {RULE_INDIRECT_NET: RULE_INSTALL_TIME,
                                  RULE_BENIGN_NET: RULE_INSTALL_TIME}

__all__ = [
    "AST_RULES",
    "FILE_RULES",
    "ONE_PER_LOCATION",
    "SAME_BEHAVIOR",
    "AstRule",
    "FileContext",
    "FileRule",
    "make_finding",
]
