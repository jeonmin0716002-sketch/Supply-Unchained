"""JavaScript 토큰 수준 분석 — 파서 의존성 없이 규칙이 쓸 만큼만.

왜 정규식으로 파일 텍스트를 바로 훑지 않나: 주석·문자열 안의 ``eval(``·``require('http')``
가 그대로 걸리고, 반대로 ``require ( "child_" + "process" )`` 같은 공백·연결은 놓친다. 또
"함수 본문 안이냐 최상단이냐"를 구분할 수 없는데, 파이썬 엔진 실측에서 오탐의 대부분이
바로 그 구분(부르기 전엔 안 도는 함수 본문)에서 나왔다 (engine/rules/install_time.py).

여기서 하는 것:

* 렉서 — 주석 제거, 문자열·템플릿·정규식 리터럴 구분(문자열은 이스케이프를 풀어 값으로),
  줄 번호. 정규식/나눗셈 ``/`` 모호성은 직전 토큰으로 판단한다(표준적인 휴리스틱).
* 괄호 짝, 함수 본문 범위(``function``·화살표·메서드), 이름 붙은 함수 표.
* 실행 범위 — 모듈을 ``require`` 하는 순간 실제로 도는 토큰: 최상단 + 그 최상단이 부르는
  같은 파일 함수(재귀) + 즉시 실행 함수(IIFE) + 실행되는 호출에 **직접** 넘긴 콜백.
  마지막 것은 ``https.get(url, res => {...})``·``new Promise(r => {...})`` 처럼 악성
  샘플이 유출 코드를 넣는 자리다 (DataDog npm 샘플 실측).

하지 않는 것: 완전한 문법 검증, ASI 의 모든 경우, 스코프별 변수 섀도잉. 규칙은 "확실히
있는 것"만 보도록 짜고, 렉서가 헷갈리는 파일(깨진 JS)은 토큰이 덜 나올 뿐 예외를 내지 않는다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: 렉싱할 최대 크기. 수 MB 번들(webpack 산출물)을 토큰화하면 순수 파이썬이라 초 단위가
#: 걸린다. 악성 페이로드는 거의 다 수 KB 이고, 이보다 큰 파일은 앞부분만 본다.
MAX_LEX_CHARS = 1_500_000

_KEYWORDS_BEFORE_REGEX = frozenset({
    "return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void",
    "throw", "instanceof", "yield", "await",
})
_BLOCK_KEYWORDS = frozenset({"if", "for", "while", "switch", "catch", "with"})
_RESERVED = frozenset({
    "if", "for", "while", "switch", "catch", "with", "return", "typeof", "new", "delete",
    "void", "throw", "function", "class", "var", "let", "const", "else", "do", "try",
    "finally", "in", "of", "instanceof", "yield", "await", "async", "import", "export",
    "super", "this", "case", "default", "break", "continue",
})

_WS = re.compile(r"[ \t\r\f\v\u00a0\ufeff\u2028\u2029]+")
_IDENT = re.compile(r"[A-Za-z_$\u0080-\uffff][\w$\u0080-\uffff]*")
_NUMBER = re.compile(
    r"0[xX][0-9a-fA-F_]+n?|0[oO][0-7_]+n?|0[bB][01_]+n?|(?:\d[\d_]*\.?[\d_]*|\.\d[\d_]*)(?:[eE][+-]?\d+)?n?"
)
_PUNCT = re.compile(
    r">>>=|\.\.\.|===|!==|\*\*=|<<=|>>=|>>>|\?\?=|&&=|\|\|=|=>|==|!=|<=|>=|&&|\|\||\?\?|\?\."
    r"|\+\+|--|\+=|-=|\*=|/=|%=|&=|\|=|\^=|\*\*|<<|>>|[{}()\[\];,<>+\-*/%&|^!~?:=.@#]"
)
_STR_SQ = re.compile(r"'(?:[^'\\\n]|\\[\s\S])*'?")
_STR_DQ = re.compile(r'"(?:[^"\\\n]|\\[\s\S])*"?')
_ESCAPE = re.compile(
    r"\\(?:x([0-9a-fA-F]{2})|u\{([0-9a-fA-F]{1,6})\}|u([0-9a-fA-F]{4})|([0-7]{1,3})|(\r\n|[\s\S]))"
)
_SIMPLE_ESC = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


@dataclass(slots=True)
class Token:
    kind: str     # id | num | str | tpl | regex | punct
    value: str    # 문자열은 이스케이프를 푼 값, 나머지는 원문
    line: int
    #: 문자열 리터럴 안의 \x·\u·8진 이스케이프 개수 (난독화 신호)
    escapes: int = 0


def _unescape(raw: str) -> tuple[str, int]:
    count = 0

    def sub(m: re.Match[str]) -> str:
        nonlocal count
        hx, ub, u4, octal, other = m.groups()
        if hx or ub or u4:
            count += 1
            try:
                return chr(int(hx or ub or u4, 16))
            except (ValueError, OverflowError):
                return ""
        if octal:
            if octal == "0":
                return "\0"
            count += 1
            return chr(int(octal, 8))
        if other in ("\n", "\r\n", "\r", "\u2028", "\u2029"):
            return ""
        return _SIMPLE_ESC.get(other, other)

    return _ESCAPE.sub(sub, raw), count


def _regex_allowed(prev: Token | None) -> bool:
    if prev is None:
        return True
    if prev.kind in ("num", "str", "tpl", "regex"):
        return False
    if prev.kind == "id":
        return prev.value in _KEYWORDS_BEFORE_REGEX
    return prev.value not in (")", "]", "}")


def tokenize(src: str) -> list[Token]:
    """소스 → 토큰. 깨진 입력에도 예외 없이 가능한 만큼 돌려준다."""
    src = src[:MAX_LEX_CHARS]
    toks: list[Token] = []
    i, n, line = 0, len(src), 1
    if src.startswith("#!"):
        i = src.find("\n")
        i = n if i < 0 else i
    #: 템플릿 리터럴 안 ``${`` 마다 그때의 중괄호 깊이를 쌓는다 — 짝이 되는 ``}`` 에서
    #: 템플릿 본문으로 돌아가야 한다.
    tpl_stack: list[int] = []
    depth = 0
    prev: Token | None = None

    def scan_template(j: int) -> int:
        """백틱 또는 ``}`` 다음 위치 j 부터 템플릿 조각을 읽어 토큰 하나를 낸다."""
        nonlocal line, prev
        start_line = line
        buf_start = j
        while j < n:
            c = src[j]
            if c == "\\":
                j += 2
                continue
            if c == "`":
                cooked, esc = _unescape(src[buf_start:j])
                tok = Token("tpl", cooked, start_line, esc)
                toks.append(tok)
                prev = tok
                line += src.count("\n", buf_start, j)
                return j + 1
            if c == "$" and j + 1 < n and src[j + 1] == "{":
                cooked, esc = _unescape(src[buf_start:j])
                tok = Token("tpl", cooked, start_line, esc)
                toks.append(tok)
                line += src.count("\n", buf_start, j)
                tpl_stack.append(depth)
                # ${ 뒤는 식이 온다 — 정규식 허용 위치
                prev = Token("punct", "${", line)
                return j + 2
            j += 1
        cooked, esc = _unescape(src[buf_start:n])
        toks.append(Token("tpl", cooked, start_line, esc))
        line += src.count("\n", buf_start, n)
        return n

    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        m = _WS.match(src, i)
        if m:
            i = m.end()
            continue
        if c == "/" and i + 1 < n:
            nxt = src[i + 1]
            if nxt == "/":
                j = src.find("\n", i)
                i = n if j < 0 else j
                continue
            if nxt == "*":
                j = src.find("*/", i + 2)
                j = n if j < 0 else j + 2
                line += src.count("\n", i, j)
                i = j
                continue
        if c == "<" and src.startswith("<!--", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if c in "'\"":
            m = (_STR_SQ if c == "'" else _STR_DQ).match(src, i)
            assert m is not None
            raw = m.group(0)
            body = raw[1:-1] if len(raw) > 1 and raw[-1] == c else raw[1:]
            cooked, esc = _unescape(body)
            tok = Token("str", cooked, line, esc)
            line += raw.count("\n")
            toks.append(tok)
            prev = tok
            i = m.end()
            continue
        if c == "`":
            i = scan_template(i + 1)
            continue
        if c == "}" and tpl_stack and tpl_stack[-1] == depth:
            tpl_stack.pop()
            i = scan_template(i + 1)
            continue
        if c == "/" and _regex_allowed(prev):
            j, in_class = i + 1, False
            while j < n and src[j] != "\n":
                ch = src[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == "[":
                    in_class = True
                elif ch == "]":
                    in_class = False
                elif ch == "/" and not in_class:
                    break
                j += 1
            j += 1
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            tok = Token("regex", src[i:j], line)
            toks.append(tok)
            prev = tok
            i = j
            continue
        m = _IDENT.match(src, i)
        if m:
            tok = Token("id", m.group(0), line)
            toks.append(tok)
            prev = tok
            i = m.end()
            continue
        if c.isdigit() or (c == "." and i + 1 < n and src[i + 1].isdigit()):
            m = _NUMBER.match(src, i)
            if m and m.end() > i:
                tok = Token("num", m.group(0), line)
                toks.append(tok)
                prev = tok
                i = m.end()
                continue
        m = _PUNCT.match(src, i)
        if m:
            v = m.group(0)
            if v == "{":
                depth += 1
            elif v == "}":
                depth -= 1
            tok = Token("punct", v, line)
            toks.append(tok)
            prev = tok
            i = m.end()
            continue
        i += 1  # 알 수 없는 문자 — 건너뛴다
    return toks


# ── 구조 ──────────────────────────────────────────────────────────

@dataclass(slots=True)
class Func:
    """함수 하나. 토큰 범위 [start, end] — start 는 머리(function/async/매개변수) 시작."""

    start: int
    body_start: int
    end: int
    name: str | None = None
    parent: int = -1  # 둘러싼 함수의 인덱스 (-1 = 최상단)


@dataclass
class Module:
    tokens: list[Token]
    pairs: dict[int, int] = field(default_factory=dict)
    funcs: list[Func] = field(default_factory=list)
    #: 토큰 인덱스 → 가장 안쪽 함수 인덱스 (-1 = 최상단)
    owner: list[int] = field(default_factory=list)
    executed_funcs: set[int] = field(default_factory=set)
    #: 지역 이름 → 모듈 경로 ("https", "child_process", "./lib/x")
    aliases: dict[str, str] = field(default_factory=dict)

    def is_executed(self, idx: int) -> bool:
        f = self.owner[idx]
        return f < 0 or f in self.executed_funcs

    def executed_indices(self) -> list[int]:
        return [i for i in range(len(self.tokens)) if self.is_executed(i)]


def _match_pairs(toks: list[Token]) -> dict[int, int]:
    pairs: dict[int, int] = {}
    stack: list[int] = []
    openers = {"(": ")", "[": "]", "{": "}"}
    for i, t in enumerate(toks):
        if t.kind != "punct":
            continue
        v = t.value
        if v in openers:
            stack.append(i)
        elif v in (")", "]", "}"):
            # 짝이 안 맞으면 맞는 여는 괄호까지 버린다 (깨진 입력에 견디도록)
            while stack and openers[toks[stack[-1]].value] != v:
                stack.pop()
            if stack:
                j = stack.pop()
                pairs[j] = i
                pairs[i] = j
    return pairs


def _is(t: Token | None, kind: str, value: str | None = None) -> bool:
    return t is not None and t.kind == kind and (value is None or t.value == value)


def _arrow_expr_end(toks: list[Token], pairs: dict[int, int], start: int) -> int:
    """화살표 함수의 식 본문 끝 — 같은 깊이의 , ) ] } ; 직전."""
    i = start
    while i < len(toks):
        t = toks[i]
        if t.kind == "punct":
            if t.value in ("(", "[", "{") and i in pairs:
                i = pairs[i] + 1
                continue
            if t.value in (",", ")", "]", "}", ";"):
                return i - 1
        i += 1
    return len(toks) - 1


def _find_funcs(toks: list[Token], pairs: dict[int, int]) -> list[Func]:
    funcs: list[Func] = []
    n = len(toks)
    for i, t in enumerate(toks):
        if t.kind == "id" and t.value == "function" and not _is(toks[i - 1] if i else None,
                                                                    "punct", "."):
            j = i + 1
            if j < n and _is(toks[j], "punct", "*"):
                j += 1
            name = None
            if j < n and toks[j].kind == "id" and toks[j].value not in _RESERVED:
                name = toks[j].value
                j += 1
            if j < n and _is(toks[j], "punct", "(") and j in pairs:
                k = pairs[j] + 1
                if k < n and _is(toks[k], "punct", "{") and k in pairs:
                    start = i - 1 if i and _is(toks[i - 1], "id", "async") else i
                    if name is None:
                        name = _assigned_name(toks, start)
                    funcs.append(Func(start, k, pairs[k], name))
        elif _is(t, "punct", "=>"):
            # 매개변수 시작
            p = i - 1
            closes_params = p >= 0 and _is(toks[p], "punct", ")") and p in pairs
            start = pairs[p] if closes_params else p
            if start - 1 >= 0 and _is(toks[start - 1], "id", "async"):
                start -= 1
            b = i + 1
            if b < n and _is(toks[b], "punct", "{") and b in pairs:
                funcs.append(Func(start, b, pairs[b], _assigned_name(toks, start)))
            elif b < n:
                funcs.append(Func(start, b, _arrow_expr_end(toks, pairs, b),
                                  _assigned_name(toks, start)))
        elif _is(t, "punct", "{") and i in pairs and i:
            prev = toks[i - 1]
            if _is(prev, "punct", ")") and (i - 1) in pairs:
                o = pairs[i - 1]
                before = toks[o - 1] if o else None
                # 메서드 정의 name(...) { — if/for/while 블록과 function 키워드 경우는 제외
                if (
                    before is not None
                    and before.kind == "id"
                    and before.value not in _BLOCK_KEYWORDS
                    and not (o >= 2 and _is(toks[o - 2], "id", "function"))
                    and before.value != "function"
                    and not (o >= 3 and _is(toks[o - 3], "id", "function"))
                ):
                    funcs.append(Func(o - 1, i, pairs[i], None))
            elif (_is(prev, "id") and prev.value not in _RESERVED and i >= 2 and _is(
                toks[i - 2], "id", "class"
            )) or _is(prev, "id", "class") or (
                i >= 3 and _is(toks[i - 2], "id") and _is(toks[i - 3], "id", "extends")
            ):
                # 클래스 본문 — 메서드는 위에서 따로 잡힌다. 본문 자체는 정의 시점에 돌지 않는다
                # (static 블록·필드 초기화는 드물어 무시)
                funcs.append(Func(i, i, pairs[i], None))
    funcs.sort(key=lambda f: (f.start, -f.end))
    return funcs


def _assigned_name(toks: list[Token], start: int) -> str | None:
    """``const NAME = function`` / ``NAME = () =>`` / ``obj.NAME = ...`` 의 NAME."""
    if start >= 2 and _is(toks[start - 1], "punct", "=") and toks[start - 2].kind == "id":
        return toks[start - 2].value
    if start >= 2 and _is(toks[start - 1], "punct", ":") and toks[start - 2].kind in ("id", "str"):
        return toks[start - 2].value
    return None


def _assign_owners(n: int, funcs: list[Func]) -> list[int]:
    owner = [-1] * n
    stack: list[int] = []
    order = sorted(range(len(funcs)), key=lambda k: (funcs[k].start, -funcs[k].end))
    for k in order:
        f = funcs[k]
        while stack and funcs[stack[-1]].end < f.start:
            stack.pop()
        f.parent = stack[-1] if stack else -1
        stack.append(k)
    # 바깥 함수부터 칠해서 안쪽이 덮어쓰게. 머리(매개변수 기본값)는 정의 시점 코드로 본다.
    for k in sorted(range(len(funcs)), key=lambda k: funcs[k].end - funcs[k].start, reverse=True):
        f = funcs[k]
        for idx in range(f.body_start, min(f.end + 1, n)):
            owner[idx] = k
    return owner


_REQUIRE_PREFIX = "node:"


def _strip_node(mod: str) -> str:
    return mod[len(_REQUIRE_PREFIX):] if mod.startswith(_REQUIRE_PREFIX) else mod


def require_target(toks: list[Token], i: int) -> str | None:
    """i 가 ``require`` / ``import`` 이고 ``( '<lit>' )`` 가 따라오면 그 모듈 이름.

    ``require('child_' + 'process')`` 처럼 문자열 리터럴끼리 더한 것도 합친다 (실측:
    탐지 회피용 분할).
    """
    t = toks[i]
    if not (t.kind == "id" and t.value in ("require", "import")):
        return None
    if i + 1 >= len(toks) or not _is(toks[i + 1], "punct", "("):
        return None
    parts, j = [], i + 2
    while j < len(toks):
        if toks[j].kind in ("str", "tpl"):
            parts.append(toks[j].value)
            j += 1
        elif (decoded := _char_codes(toks, j)) is not None:
            # require(String.fromCharCode(104,116,116,112,115)) — 실측(cms_comp_static):
            # 모듈 이름을 문자 코드로 숨긴다
            parts.append(decoded[0])
            j = decoded[1]
        else:
            break
        if j < len(toks) and _is(toks[j], "punct", "+"):
            j += 1
            continue
        break
    if parts and j < len(toks) and _is(toks[j], "punct", ")"):
        return _strip_node("".join(parts))
    return None


def _char_codes(toks: list[Token], j: int) -> tuple[str, int] | None:
    """``String.fromCharCode(n, n, ...)`` 를 풀어 (문자열, 다음 인덱스)."""
    if not (j + 3 < len(toks) and _is(toks[j], "id", "String") and _is(toks[j + 1], "punct", ".")
            and _is(toks[j + 2], "id", "fromCharCode") and _is(toks[j + 3], "punct", "(")):
        return None
    k, out = j + 4, []
    while k < len(toks) and toks[k].kind == "num":
        try:
            out.append(chr(int(toks[k].value, 0) if toks[k].value[:2].lower() in ("0x", "0o", "0b")
                           else int(toks[k].value)))
        except (ValueError, OverflowError):
            return None
        k += 1
        if k < len(toks) and _is(toks[k], "punct", ","):
            k += 1
    if k < len(toks) and _is(toks[k], "punct", ")") and out:
        return "".join(out), k + 1
    return None


def _collect_aliases(toks: list[Token], pairs: dict[int, int]) -> dict[str, str]:
    """지역 이름 → 모듈(또는 모듈.멤버). require·import 둘 다."""
    out: dict[str, str] = {}
    n = len(toks)
    for i in range(n):
        mod = require_target(toks, i)
        if mod is not None:
            close = i + 1
            close = pairs.get(close, close)
            # require('x').member
            member = None
            if (close + 2 < n and _is(toks[close + 1], "punct", ".")
                    and toks[close + 2].kind == "id"):
                member = toks[close + 2].value
            target = f"{mod}.{member}" if member else mod
            # 바로 앞이 = 이면 대입 대상
            if i >= 2 and _is(toks[i - 1], "punct", "="):
                lhs = toks[i - 2]
                if lhs.kind == "id":
                    out[lhs.value] = target
                elif _is(lhs, "punct", "}") and (i - 2) in pairs:
                    _destructure(toks, pairs[i - 2], i - 2, target, out)
            continue
        t = toks[i]
        # import X from 'm' / import * as X from 'm' / import {a as b} from 'm'
        if _is(t, "id", "import") and not (i + 1 < n and _is(toks[i + 1], "punct", "(")):
            j = i + 1
            names: list[tuple[str, str | None]] = []  # (지역, 멤버 또는 None=모듈 자체)
            while j < n and not _is(toks[j], "id", "from") and not _is(toks[j], "punct", ";"):
                if _is(toks[j], "punct", "{") and j in pairs:
                    k = j + 1
                    while k < pairs[j]:
                        if toks[k].kind == "id":
                            member = toks[k].value
                            if k + 2 < pairs[j] and _is(toks[k + 1], "id", "as"):
                                names.append((toks[k + 2].value, member))
                                k += 3
                                continue
                            names.append((member, member))
                        k += 1
                    j = pairs[j] + 1
                    continue
                if _is(toks[j], "punct", "*") and j + 2 < n and _is(toks[j + 1], "id", "as"):
                    names.append((toks[j + 2].value, None))
                    j += 3
                    continue
                if toks[j].kind == "id" and toks[j].value != "type":
                    names.append((toks[j].value, None))
                j += 1
            if j + 1 < n and _is(toks[j], "id", "from") and toks[j + 1].kind == "str":
                mod = _strip_node(toks[j + 1].value)
                for local, member in names:
                    out[local] = f"{mod}.{member}" if member and member != "default" else mod
    return out


def _destructure(toks: list[Token], open_i: int, close_i: int, mod: str,
                 out: dict[str, str]) -> None:
    """``const { exec, spawn: sp } = require('child_process')``."""
    k = open_i + 1
    while k < close_i:
        t = toks[k]
        if t.kind == "id":
            if k + 2 < close_i and _is(toks[k + 1], "punct", ":") and toks[k + 2].kind == "id":
                out[toks[k + 2].value] = f"{mod}.{t.value}"
                k += 3
                continue
            out[t.value] = f"{mod}.{t.value}"
        k += 1


def _call_head(toks: list[Token], open_paren: int) -> int | None:
    """``a.b.c(`` 의 여는 괄호 위치에서 호출 대상 체인의 시작 인덱스."""
    j = open_paren - 1
    if j < 0:
        return None
    if toks[j].kind == "id":
        while j >= 2 and _is(toks[j - 1], "punct", ".") and toks[j - 2].kind == "id":
            j -= 2
        return j
    return None


def _mark_executed(mod: Module) -> None:
    toks, pairs, funcs = mod.tokens, mod.pairs, mod.funcs
    by_name: dict[str, list[int]] = {}
    for k, f in enumerate(funcs):
        if f.name:
            by_name.setdefault(f.name, []).append(k)
    executed: set[int] = set()
    todo: list[int] = [-1]

    def region(k: int) -> range:
        if k < 0:
            return range(len(toks))
        f = funcs[k]
        return range(f.body_start, f.end + 1)

    func_at_start: dict[int, list[int]] = {}
    for k, f in enumerate(funcs):
        func_at_start.setdefault(f.start, []).append(k)

    def add(k: int) -> None:
        if k not in executed:
            executed.add(k)
            todo.append(k)

    while todo:
        cur = todo.pop()
        for idx in region(cur):
            if mod.owner[idx] != cur:
                continue
            t = toks[idx]
            # 같은 파일 함수 호출 foo(
            if (
                t.kind == "id"
                and idx + 1 < len(toks)
                and _is(toks[idx + 1], "punct", "(")
                and not (idx and _is(toks[idx - 1], "punct", "."))
                and not (idx and _is(toks[idx - 1], "id", "function"))
                and not (idx + 1 in pairs and pairs[idx + 1] + 1 < len(toks)
                         and _is(toks[pairs[idx + 1] + 1], "punct", "{"))
                and t.value in by_name
                and t.value not in _RESERVED
            ):
                for k in by_name[t.value]:
                    if funcs[k].start != idx:  # 정의 자신이 아니면
                        add(k)
            # 실행되는 호출의 인자로 바로 넘긴 함수 / IIFE
            if _is(t, "punct", "(") and idx in pairs:
                close = pairs[idx]
                is_call = idx > 0 and (
                    (toks[idx - 1].kind == "id" and toks[idx - 1].value not in _BLOCK_KEYWORDS
                    and toks[idx - 1].value != "function")
                    or _is(toks[idx - 1], "punct", ")") or _is(toks[idx - 1], "punct", "]")
                )
                if is_call:
                    j = idx + 1
                    while j < close:
                        for k in func_at_start.get(j, ()):
                            if funcs[k].end <= close:
                                add(k)
                        if j in pairs and toks[j].value in "([{":
                            # 객체·배열 리터럴 안 함수는 넘긴 게 아니다 (getter 등)
                            j = pairs[j] + 1
                            # 다음 인자 위치로
                            continue
                        j += 1
                # IIFE: (function(){...})( / (()=>{...})( / (function(){}).call(
                if close + 1 < len(toks) and (
                    _is(toks[close + 1], "punct", "(")
                    or (_is(toks[close + 1], "punct", ".") and close + 2 < len(toks)
                        and toks[close + 2].value in ("call", "apply"))
                ):
                    for k in func_at_start.get(idx + 1, ()):
                        if funcs[k].end < close:
                            add(k)
        # !function(){}() / void function(){}()
        for k, f in enumerate(funcs):
            if k in executed or f.parent != cur:
                continue
            called_now = f.end + 1 < len(toks) and _is(toks[f.end + 1], "punct", "(")
            if called_now and toks[f.start].value in ("function", "async") and f.start and (
                toks[f.start - 1].value in ("!", "void", "+", "-", "~", ",", "=")
            ):
                add(k)
    mod.executed_funcs = executed


def parse(src: str) -> Module:
    toks = tokenize(src)
    pairs = _match_pairs(toks)
    funcs = _find_funcs(toks, pairs)
    mod = Module(toks, pairs, funcs, _assign_owners(len(toks), funcs))
    mod.aliases = _collect_aliases(toks, pairs)
    _mark_executed(mod)
    return mod


# ── 호출 해석 ─────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class Call:
    name: str          # 별칭을 푼 점 이름: "https.get", "child_process.exec", "eval"
    head: int          # 체인 시작 토큰
    open: int          # 여는 괄호
    close: int         # 닫는 괄호
    line: int
    is_new: bool = False


def calls(mod: Module, *, executed_only: bool) -> list[Call]:
    """모든 호출식. ``require('https').get(`` 처럼 require 결과에 바로 붙은 것도 푼다."""
    toks, pairs = mod.tokens, mod.pairs
    out: list[Call] = []
    for i, t in enumerate(toks):
        if not (_is(t, "punct", "(") and i in pairs):
            continue
        if executed_only and not mod.is_executed(i):
            continue
        head = _call_head(toks, i)
        name: str | None = None
        if head is not None:
            parts = [toks[k].value for k in range(head, i, 2)]
            if parts[0] in _RESERVED and parts[0] not in ("import", "super"):
                continue
            first = parts[0]
            if first in mod.aliases:
                parts = [mod.aliases[first], *parts[1:]]
            name = ".".join(parts)
            # require('x').y( 체인 앞이 require(...) 인 경우
            if (head >= 2 and _is(toks[head - 1], "punct", ".")
                    and _is(toks[head - 2], "punct", ")")):
                o = pairs.get(head - 2)
                if o is not None and o >= 1:
                    mod_name = require_target(toks, o - 1)
                    if mod_name:
                        name = f"{mod_name}.{name}"
        elif i >= 1 and _is(toks[i - 1], "punct", "]") and (i - 1) in pairs:
            # obj['exec'](  — 문자열 첨자 호출 (난독화에 흔하다)
            o = pairs[i - 1]
            if o + 2 == i - 1 and toks[o + 1].kind == "str":
                h = _call_head(toks, o)
                base = ".".join(toks[k].value for k in range(h, o, 2)) if h is not None else ""
                if base in mod.aliases:
                    base = mod.aliases[base]
                name = f"{base}.{toks[o + 1].value}" if base else toks[o + 1].value
                head = h if h is not None else o
        if name is None or head is None:
            continue
        is_new = head >= 1 and _is(toks[head - 1], "id", "new")
        out.append(Call(name, head, i, pairs[i], toks[i].line, is_new))
    return out


def arg_tokens(mod: Module, call: Call) -> list[Token]:
    return mod.tokens[call.open + 1:call.close]


def string_values(mod: Module, lo: int, hi: int) -> list[str]:
    """[lo, hi) 범위의 문자열·템플릿 리터럴 값. 인접한 ``'a' + 'b'`` 는 합친다."""
    out: list[str] = []
    toks = mod.tokens
    i = lo
    while i < hi:
        if toks[i].kind in ("str", "tpl"):
            buf = toks[i].value
            j = i + 1
            while j + 1 < hi and _is(toks[j], "punct", "+") and toks[j + 1].kind in ("str", "tpl"):
                buf += toks[j + 1].value
                j += 2
            out.append(buf)
            i = j
            continue
        i += 1
    return out


def local_requires(mod: Module, *, executed_only: bool) -> list[str]:
    """``require('./x')`` 처럼 패키지 안 상대 경로 모듈 (실행 범위에서 부른 것)."""
    out = []
    for i, _t in enumerate(mod.tokens):
        if executed_only and not mod.is_executed(i):
            continue
        target = require_target(mod.tokens, i)
        if target and target.startswith((".", "/")):
            out.append(target)
    return out


__all__ = [
    "MAX_LEX_CHARS",
    "Call",
    "Func",
    "Module",
    "Token",
    "arg_tokens",
    "calls",
    "local_requires",
    "parse",
    "require_target",
    "string_values",
    "tokenize",
]
