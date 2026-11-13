"""Go 소스를 정규식이 아니라 구조로 읽기 위한 작은 스캐너 — 주석·문자열 제거, 최상위 선언 경계.

정규식만으로는 못 하는 것이 둘 있다: (1) ``"http://x"`` 안의 ``//`` 와 주석 안의 ``http.Get`` 을
구분하는 것, (2) ``init()`` 본문이 어디서 끝나는지(중괄호 짝) 아는 것. 그래서 파일을 한 번 훑어
같은 길이의 두 사본을 만든다:

* ``nocomment`` — 주석만 공백으로 (문자열 내용은 남김: 명령·URL 은 문자열 안에 있다)
* ``skeleton``  — 주석과 문자열·룬 내용을 모두 공백으로 (따옴표는 남김). 구조(괄호 짝)는 여기서만 본다.

두 사본은 오프셋이 같아서, skeleton 에서 찾은 위치를 nocomment 에서 그대로 잘라 쓴다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


def lex(src: str) -> tuple[str, str]:
    nc: list[str] = []
    sk: list[str] = []
    i, n = 0, len(src)

    def blank(chunk: str) -> str:
        return "".join("\n" if ch == "\n" else " " for ch in chunk)

    while i < n:
        c = src[i]
        two = src[i:i + 2]
        if two == "//":
            j = src.find("\n", i)
            j = n if j < 0 else j
            nc.append(" " * (j - i))
            sk.append(" " * (j - i))
            i = j
        elif two == "/*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            seg = blank(src[i:j])
            nc.append(seg)
            sk.append(seg)
            i = j
        elif c == "`":
            j = src.find("`", i + 1)
            j = n if j < 0 else j + 1
            nc.append(src[i:j])
            sk.append("`" + blank(src[i + 1:j - 1]) + "`" if j - i >= 2 else blank(src[i:j]))
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            j = min(j + 1, n)
            nc.append(src[i:j])
            sk.append(c + blank(src[i + 1:j - 1]) + c if j - i >= 2 else blank(src[i:j]))
            i = j
        else:
            nc.append(c)
            sk.append(c)
            i += 1
    return "".join(nc), "".join(sk)


def match_close(sk: str, open_pos: int) -> int:
    """``open_pos`` 의 여는 괄호에 짝이 되는 닫는 괄호 위치 (없으면 끝). ``( [ {`` 를 한꺼번에 센다."""
    depth = 0
    for k in range(open_pos, len(sk)):
        ch = sk[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return k
    return len(sk) - 1


def body_brace(sk: str, start: int) -> int:
    """함수 시그니처가 시작되는 ``start`` 이후 첫 본문 ``{`` 위치. 괄호 안의 ``interface{}`` ·
    반환형 ``struct{}`` 의 중괄호는 본문이 아니다. 못 찾으면 -1."""
    k, n = start, len(sk)
    paren = 0
    while k < n:
        ch = sk[k]
        if ch in "([":
            paren += 1
        elif ch in ")]":
            paren -= 1
        elif ch == "{" and paren == 0:
            before = sk[max(0, k - 12):k].rstrip()
            if before.endswith(("interface", "struct")):
                k = match_close(sk, k)
            else:
                return k
        k += 1
    return -1


@dataclass(frozen=True)
class Span:
    start: int
    end: int  # 배타


@dataclass
class FileScan:
    nc: str
    sk: str
    funcs: dict[str, Span]       # 패키지 수준 함수 이름 → 본문 범위 (메서드 제외)
    inits: list[Span]            # func init() 본문
    var_specs: list[Span]        # 패키지 수준 var 문장 (초기화식 실행됨)


_FUNC_DECL = re.compile(r"^func\s+(\w+)\s*(?:\[[^\]\n]*\])?\s*\(", re.MULTILINE)
_VAR_DECL = re.compile(r"^var\b", re.MULTILINE)
_FUNC_LIT = re.compile(r"\bfunc\s*\(")


def scan_file(src: str) -> FileScan:
    nc, sk = lex(src)
    funcs: dict[str, Span] = {}
    inits: list[Span] = []
    for m in _FUNC_DECL.finditer(sk):
        open_brace = body_brace(sk, m.end() - 1)
        if open_brace < 0:
            continue  # 본문 없는 선언 (어셈블리 구현 등)
        span = Span(open_brace + 1, match_close(sk, open_brace))
        if m.group(1) == "init":
            inits.append(span)
        else:
            funcs[m.group(1)] = span
    var_specs: list[Span] = []
    for m in _VAR_DECL.finditer(sk):
        k, depth, n = m.end(), 0, len(sk)
        while k < n:
            ch = sk[k]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif ch == "\n" and depth <= 0:
                break
            k += 1
        var_specs.append(Span(m.end(), k))
    return FileScan(nc=nc, sk=sk, funcs=funcs, inits=inits, var_specs=var_specs)


def mask_uninvoked_literals(nc: str, sk: str, span: Span) -> tuple[str, str]:
    """``span`` 의 nocomment 본문에서 호출되지 않는 함수 리터럴 본문을 공백으로 가린다 (nocomment·skeleton 둘 다).

    ``var h = func() {...}`` 는 변수에 담길 뿐 초기화 때 돌지 않는다. ``var _ = func() {...}()`` 는
    즉시 호출이라 돈다 — 닫는 중괄호 바로 뒤에 ``(`` 가 있는지로 구분한다.
    """
    chars = list(nc[span.start:span.end])
    skc = list(sk[span.start:span.end])
    seg = sk[span.start:span.end]
    for m in _FUNC_LIT.finditer(seg):
        ob = body_brace(seg, m.end() - 1)
        if ob < 0:
            continue
        cb = match_close(seg, ob)
        if seg[cb + 1:cb + 8].lstrip().startswith("("):
            continue
        for k in range(ob + 1, cb):
            if chars[k] != "\n":
                chars[k] = skc[k] = " "
    return "".join(chars), "".join(skc)


def split_args(sk: str, nc: str, open_paren: int) -> list[str]:
    """호출 ``f(`` 의 인자들을 최상위 쉼표로 나눠 nocomment 문자열로 돌려준다."""
    close = match_close(sk, open_paren)
    args, depth, last = [], 0, open_paren + 1
    for k in range(open_paren + 1, close):
        ch = sk[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(nc[last:k].strip())
            last = k + 1
    tail = nc[last:close].strip()
    if tail:
        args.append(tail)
    return args

# ruff: noqa: E501
