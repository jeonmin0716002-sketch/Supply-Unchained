"""PHP 소스의 가벼운 어휘 분석 — 주석·문자열·heredoc·태그 밖 HTML 을 걷어 낸다.

규칙을 파일 전체에 정규식으로 돌리면 ``// system('curl ...')`` 같은 주석이나 문서 문자열,
``?>`` 밖의 HTML 텍스트를 코드로 오인한다. ``lex`` 는 그런 부분을 공백으로 가린 ``masked``
(길이·줄바꿈은 원문과 같다)와 문자열 내용 목록을 돌려준다. ``function_regions`` 는 호출해야
도는 함수·메서드·클로저 본문의 범위 — ``autoload.files`` 가 파일을 불러오는 순간 실제로
실행되는 것은 그 밖의 최상단 코드다.

진짜 파서가 아니다. 알려진 한계: ``"{$a["k"]}"`` 처럼 보간 안에 같은 따옴표가 중첩된 문자열,
``fn`` 화살표 함수 본문(호출 전엔 안 돌지만 실행 범위로 본다)은 정확히 따라가지 못한다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_OPEN_TAG = re.compile(r"<\?(?:php\b|=)?", re.IGNORECASE)
_HEREDOC = re.compile(r"<<<[ \t]*(['\"]?)([A-Za-z_]\w*)\1\r?\n")
_FUNC = re.compile(r"(?<![\w$>:])function\b")


@dataclass
class Lexed:
    masked: str
    nocomment: str
    #: (내용 시작, 내용 끝, 종류) — 종류: sq dq xstr heredoc
    literals: list[tuple[int, int, str]] = field(default_factory=list)


def lex(src: str) -> Lexed:
    n = len(src)
    masked = list(src)
    nocomment = list(src)
    lits: list[tuple[int, int, str]] = []

    def blank(buf: list[str], a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if buf[k] != "\n":
                buf[k] = " "

    i = 0
    in_php = False
    while i < n:
        if not in_php:
            m = _OPEN_TAG.search(src, i)
            end = m.start() if m else n
            blank(masked, i, end)
            blank(nocomment, i, end)
            if not m:
                break
            blank(masked, m.start(), m.end())
            blank(nocomment, m.start(), m.end())
            i, in_php = m.end(), True
            continue
        c = src[i]
        two = src[i: i + 2]
        if two == "?>":
            blank(masked, i, i + 2)
            blank(nocomment, i, i + 2)
            i, in_php = i + 2, False
            continue
        if two == "/*":
            end = src.find("*/", i + 2)
            end = n if end < 0 else end + 2
            blank(masked, i, end)
            blank(nocomment, i, end)
            i = end
            continue
        if two == "//" or (c == "#" and src[i + 1: i + 2] != "["):
            j = i
            while j < n and src[j] != "\n" and src[j: j + 2] != "?>":
                j += 1
            blank(masked, i, j)
            blank(nocomment, i, j)
            i = j
            continue
        if c == "'":
            j = i + 1
            while j < n and src[j] != "'":
                j += 2 if src[j] == "\\" else 1
            lits.append((i + 1, min(j, n), "sq"))
            blank(masked, i + 1, j)
            i = j + 1
            continue
        if c in '"`':
            j, depth = i + 1, 0
            while j < n:
                ch = src[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == "{" and src[j + 1: j + 2] == "$":
                    depth += 1
                elif ch == "}" and depth:
                    depth -= 1
                elif ch == c and not depth:
                    break
                j += 1
            lits.append((i + 1, min(j, n), "dq" if c == '"' else "xstr"))
            blank(masked, i + 1, j)
            i = j + 1
            continue
        if two == "<<" and src[i: i + 3] == "<<<":
            m = _HEREDOC.match(src, i)
            if m:
                ident = m.group(2)
                close = re.compile(rf"^[ \t]*{re.escape(ident)}\b", re.MULTILINE)
                cm = close.search(src, m.end())
                body_end = cm.start() if cm else n
                lits.append((m.end(), body_end, "heredoc"))
                blank(masked, m.end(), cm.end() if cm else n)
                i = cm.end() if cm else n
                continue
        i += 1
    return Lexed("".join(masked), "".join(nocomment), lits)


def _match(masked: str, i: int, open_c: str, close_c: str) -> int:
    """``masked[i]`` 가 여는 괄호일 때 짝이 되는 닫는 괄호의 다음 오프셋 (없으면 끝)."""
    depth, n = 0, len(masked)
    while i < n:
        c = masked[i]
        if c == open_c:
            depth += 1
        elif c == close_c:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def function_regions(masked: str) -> list[tuple[int, int, str]]:
    """(function 키워드 시작, 본문 끝, 이름) — 함수·메서드·클로저. 이름 없는 클로저는 ""."""
    out: list[tuple[int, int, str]] = []
    n = len(masked)
    for m in _FUNC.finditer(masked):
        i = m.end()
        nm = re.match(r"\s*&?\s*([A-Za-z_]\w*)", masked[i:])
        name = ""
        if nm:
            name, i = nm.group(1), i + nm.end()
        j = masked.find("(", i)
        if j < 0:
            continue
        j = _match(masked, j, "(", ")")
        while j < n:  # use (...) 와 반환 타입 건너뛰기 — 본문 ``{`` 나 선언 끝 ``;`` 까지
            if masked[j] in "{;":
                break
            j += 1
        if j < n and masked[j] == "{":
            out.append((m.start(), _match(masked, j, "{", "}"), name))  # 선언부 포함
    return out


def blank_ranges(text: str, ranges: list[tuple[int, int, str]]) -> str:
    if not ranges:
        return text
    buf = list(text)
    for a, b, _ in ranges:
        for k in range(a, min(b, len(buf))):
            if buf[k] != "\n":
                buf[k] = " "
    return "".join(buf)


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def statement_end(masked: str, start: int) -> int:
    """``start`` 에서 시작한 문장이 ``;`` 로 끝나는 오프셋 (괄호 안의 ``;`` 는 건너뜀)."""
    depth, n = 0, len(masked)
    for i in range(start, n):
        c = masked[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth < 0:
                return i
        elif c == ";" and depth <= 0:
            return i
    return n
