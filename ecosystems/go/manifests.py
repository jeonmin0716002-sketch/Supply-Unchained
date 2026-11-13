"""go.mod · go.sum → ``Dependency``.

* go.mod — ``require`` (한 줄·블록). ``// indirect`` 주석이 있으면 직접 의존성이 아니다.
  ``replace`` 로 다른 모듈·로컬 경로가 되면 원래 버전으로 조회하면 틀리므로, 레지스트리 모듈로
  바뀐 경우만 새 이름·버전을 쓰고 로컬 경로 치환은 건너뛴다.
* go.sum — 해시가 기록된 모든 (모듈, 버전). ``/go.mod`` 해시 줄은 소스가 아니라 go.mod 만 받은
  것이라 중복이므로 버전당 한 번만 낸다.
"""

from __future__ import annotations

import re

from ecosystems.base import Dependency

_REQ = re.compile(r"^\s*(\S+)\s+(v\S+?)\s*(//.*)?$")


def _strip_comment(line: str) -> tuple[str, str]:
    code, sep, comment = line.partition("//")
    return code.strip(), (sep + comment).strip() if sep else ""


def parse_go_mod(text: str, source: str = "go.mod") -> list[Dependency]:
    requires: dict[tuple[str, str], bool] = {}
    replaces: dict[str, tuple[str, str] | None] = {}
    block: str | None = None
    saw_module = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        if block:
            if line == ")":
                block = None
                continue
            code, comment = _strip_comment(line)
            if block == "require":
                parts = code.split()
                if len(parts) == 2 and parts[1].startswith("v"):
                    requires[(parts[0], parts[1])] = "indirect" in comment
            elif block == "replace":
                _record_replace(code, replaces)
            continue
        m = re.match(r"^(module|require|replace|exclude|retract|go|toolchain|godebug|tool|ignore)\b\s*(.*)$", line)
        if not m:
            raise ValueError(f"{source}: 알 수 없는 줄: {line[:60]!r}")
        kw, rest = m.group(1), m.group(2)
        if kw == "module":
            saw_module = True
        if rest.startswith("("):
            if kw in ("require", "replace"):
                block = kw
            elif not rest.rstrip().endswith(")"):
                block = kw  # 다른 블록은 읽지 않고 닫힐 때까지 건너뛴다
            continue
        code, comment = _strip_comment(rest)
        if kw == "require":
            parts = code.split()
            if len(parts) == 2 and parts[1].startswith("v"):
                requires[(parts[0], parts[1])] = "indirect" in comment
        elif kw == "replace":
            _record_replace(code, replaces)
    if not saw_module and not requires:
        raise ValueError(f"{source}: go.mod 로 보이지 않는다 (module·require 줄이 없음)")
    out: list[Dependency] = []
    for (name, version), indirect in requires.items():
        if name in replaces:
            target = replaces[name]
            if target is None:
                continue  # 로컬 경로로 치환 — 레지스트리 조회 대상이 아니다
            out.append(Dependency(ecosystem="go", name=target[0], version=target[1],
                                  spec=f"{name} {version} => {target[0]} {target[1]}",
                                  source=source, direct=not indirect))
            continue
        out.append(Dependency(ecosystem="go", name=name, version=version, spec=version,
                              source=source, direct=not indirect))
    return out


def _record_replace(code: str, replaces: dict[str, tuple[str, str] | None]) -> None:
    left, _, right = code.partition("=>")
    lparts, rparts = left.split(), right.split()
    if not lparts or not rparts:
        return
    if len(rparts) >= 2 and rparts[1].startswith("v") and not rparts[0].startswith((".", "/")):
        replaces[lparts[0]] = (rparts[0], rparts[1])
    else:
        replaces[lparts[0]] = None


def parse_go_sum(text: str, source: str = "go.sum") -> list[Dependency]:
    out: dict[tuple[str, str], Dependency] = {}
    for raw in text.splitlines():
        parts = raw.split()
        if not parts:
            continue
        if len(parts) != 3 or not parts[1].startswith("v") or not parts[2].startswith("h1:"):
            raise ValueError(f"{source}: go.sum 형식이 아니다: {raw[:60]!r}")
        name, version = parts[0], parts[1].removesuffix("/go.mod")
        out.setdefault((name, version), Dependency(
            ecosystem="go", name=name, version=version, spec=version, source=source, direct=None))
    return list(out.values())

# ruff: noqa: E501
