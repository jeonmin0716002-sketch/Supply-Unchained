"""Gemfile.lock · Gemfile 파서.

* ``Gemfile.lock`` — ``GEM`` 구획의 ``specs:`` 들여쓰기 4칸 줄이 확정 버전이다
  (``name (1.2.3)``, 플랫폼 gem 은 ``name (1.2.3-x86_64-linux)`` → 플랫폼을 떼어 낸다).
  ``GIT``·``PATH`` 구획은 rubygems.org 가 출처가 아니라 OSV 대조가 틀리므로 넣지 않는다.
  직접 의존성은 ``DEPENDENCIES`` 구획.
* ``Gemfile`` — 루비 코드라 best effort. ``gem 'x', '1.2.3'`` 만 정확 버전, 범위는 None.
"""

from __future__ import annotations

import re

from ecosystems.base import Dependency

_SPEC_LINE = re.compile(r"^ {4}([A-Za-z0-9_.\-]+) \(([^)]+)\)\s*$")
_DEP_LINE = re.compile(r"^ {2}([A-Za-z0-9_.\-]+)(!?)(?: \(.*\))?\s*$")
_GEM_CALL = re.compile(r"""^\s*gem\s*\(?\s*['"]([A-Za-z0-9_.\-]+)['"]\s*(.*)$""")
_QUOTED = re.compile(r"""['"]([^'"]*)['"]""")
_EXACT = re.compile(r"^=?\s*(\d[0-9A-Za-z]*(?:[._][0-9A-Za-z]+)*)$")


def parse_gemfile_lock(text: str, source: str = "Gemfile.lock") -> list[Dependency]:
    section = ""
    in_specs = False
    specs: list[tuple[str, str]] = []
    direct: set[str] = set()
    have_deps = False
    for raw in text.splitlines():
        line = raw.rstrip()
        if line and not line.startswith(" "):
            section, in_specs = line.strip(), False
            if section == "DEPENDENCIES":
                have_deps = True
            continue
        if section == "GEM":
            if line.strip() == "specs:":
                in_specs = True
                continue
            if in_specs:
                m = _SPEC_LINE.match(line)
                if m:
                    specs.append((m.group(1), m.group(2).split("-", 1)[0]))
        elif section == "DEPENDENCIES":
            m = _DEP_LINE.match(line)
            if m:
                direct.add(m.group(1))
    if not specs and "GEM" not in text and "DEPENDENCIES" not in text:
        raise ValueError("Gemfile.lock 형식이 아닙니다 (GEM/DEPENDENCIES 구획 없음)")
    seen: set[tuple[str, str]] = set()
    out: list[Dependency] = []
    for name, version in specs:
        if (name, version) in seen:  # 플랫폼별로 같은 버전이 반복된다
            continue
        seen.add((name, version))
        out.append(Dependency(
            ecosystem="rubygems", name=name, version=version, spec=version, source=source,
            direct=(name in direct) if have_deps else None))
    return out


def parse_gemfile(text: str, source: str = "Gemfile") -> list[Dependency]:
    # 줄 끝 쉼표로 이어진 gem 호출을 한 줄로
    joined: list[str] = []
    buf = ""
    for raw in text.splitlines():
        quoted_hash = re.search(r"""['"][^'"]*#""", raw)
        line = raw if quoted_hash else raw.split("#", 1)[0]
        if buf:
            buf += " " + line.strip()
        else:
            buf = line
        if buf.rstrip().endswith(","):
            continue
        joined.append(buf)
        buf = ""
    if buf:
        joined.append(buf)
    out: list[Dependency] = []
    for line in joined:
        m = _GEM_CALL.match(line)
        if not m:
            continue
        name, rest = m.group(1), m.group(2)
        if re.search(r"\b(?:git|github|gitlab|bitbucket|path):|:(?:git|github|path)\s*=>", rest):
            continue  # rubygems.org 가 출처가 아니다
        # 옵션 해시(``key: value``) 앞까지가 버전 요구사항
        head = re.split(r"""[,\s]+(?:\w+:|:\w+\s*=>)""", rest, maxsplit=1)[0]
        reqs = [q for q in _QUOTED.findall(head) if q.strip()]
        version = None
        if len(reqs) == 1:
            ex = _EXACT.match(reqs[0].strip())
            version = ex.group(1) if ex else None
        out.append(Dependency(
            ecosystem="rubygems", name=name, version=version, spec=", ".join(reqs),
            source=source, direct=True))
    return out
