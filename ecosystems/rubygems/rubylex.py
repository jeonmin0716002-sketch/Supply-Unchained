"""루비 소스의 가벼운 어휘 분석 — 주석·문자열·heredoc 을 걷어내고 코드 구조(def 범위)를 본다.

규칙을 파일 전체에 정규식으로 돌리면 주석·문서 문자열(``# curl ... | sh`` 설치 안내)과
``def`` 안에서만 도는 코드를 "설치 시 실행"으로 오인한다. 그래서 먼저:

1. ``lex`` — 주석을 지우고 문자열·정규식·heredoc 의 **내용**을 공백으로 가린 ``masked`` 를
   만든다 (오프셋·줄 번호는 원문과 동일). 문자열 내용은 ``literals`` 로 따로 돌려준다.
2. ``def_regions`` — ``def ... end`` 와 ``if __FILE__ == $0`` 블록의 오프셋 범위. 이 범위는
   부르기 전/직접 실행했을 때만 돌므로 ``require`` 시점 실행 범위에서 뺀다.

진짜 파서가 아니다(설계 문서 §5 가 파서 기반 분석을 이후 과제로 둔다). 알려진 한계:
``{ }`` 블록 안의 ``def``, endless def 의 일부 변형, 중첩 보간 안의 중첩 문자열은
정확히 따라가지 못한다 — 그 경우에도 "못 읽음"이 아니라 범위가 넓거나 좁게 잡힐 뿐이다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_HEREDOC = re.compile(r"<<([~-]?)([\"'`]?)([A-Za-z_]\w*)\2")
_PAIRS = {"(": ")", "[": "]", "{": "}", "<": ">"}
_REGEX_PREV_WORDS = {
    "if", "unless", "when", "and", "or", "not", "return", "puts", "split", "scan", "sub",
    "gsub", "match", "while", "until", "elsif", "then", "else", "print", "p",
}


@dataclass
class Lexed:
    #: 주석 제거 + 문자열·정규식·heredoc 내용 공백 처리 (길이·줄바꿈 보존)
    masked: str
    #: 주석만 지운 원문 (문자열 안의 URL 을 볼 때)
    nocomment: str
    #: (내용 시작, 내용 끝, 종류) — 종류: sq dq xstr heredoc percent regex
    literals: list[tuple[int, int, str]] = field(default_factory=list)


def lex(src: str) -> Lexed:
    n = len(src)
    masked = list(src)
    nocomment = list(src)
    lits: list[tuple[int, int, str]] = []
    pending: list[tuple[str, str]] = []  # (heredoc 종료 식별자, ~/- 여부)
    pending_kind: list[str] = []

    def blank(buf: list[str], a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if buf[k] != "\n":
                buf[k] = " "

    i = 0
    prev_sig = ""
    prev_word = ""
    at_line_start = True
    while i < n:
        c = src[i]
        if c == "\n":
            i += 1
            if pending:
                for (ident, mode), kind in zip(pending, pending_kind, strict=True):
                    start = i
                    while i < n:
                        eol = src.find("\n", i)
                        eol = n if eol < 0 else eol
                        line = src[i:eol]
                        if (line.strip() if mode else line.rstrip("\r")) == ident:
                            break
                        i = eol + 1
                    lits.append((start, min(i, n), kind))
                    blank(masked, start, i)
                    eol = src.find("\n", i)
                    i = n if eol < 0 else eol + 1  # 종료 줄은 건너뛴다
                    blank(masked, start, i)
                pending.clear()
                pending_kind.clear()
            at_line_start = True
            prev_sig = ""
            continue
        if at_line_start:
            if src.startswith("=begin", i):
                end = src.find("\n=end", i)
                end = n if end < 0 else src.find("\n", end + 1)
                end = n if end < 0 else end
                blank(masked, i, end)
                blank(nocomment, i, end)
                i = end
                continue
            if src.startswith("__END__", i) and src[i + 7: i + 9].strip() == "":
                blank(masked, i, n)
                blank(nocomment, i, n)
                break
            at_line_start = False
        if c in " \t\r":
            i += 1
            continue
        if c == "#":
            eol = src.find("\n", i)
            eol = n if eol < 0 else eol
            blank(masked, i, eol)
            blank(nocomment, i, eol)
            i = eol
            continue
        if c == "'" and prev_sig != "$":
            j = i + 1
            while j < n and src[j] != "'":
                j += 2 if src[j] == "\\" else 1
            lits.append((i + 1, min(j, n), "sq"))
            blank(masked, i + 1, j)
            i, prev_sig = j + 1, "'"
            continue
        if c in "\"`" and prev_sig != "$":
            j, depth = i + 1, 0
            while j < n:
                ch = src[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == "#" and src[j + 1: j + 2] == "{":
                    depth += 1
                    j += 2
                    continue
                if depth and ch == "}":
                    depth -= 1
                elif not depth and ch == c:
                    break
                j += 1
            lits.append((i + 1, min(j, n), "dq" if c == '"' else "xstr"))
            blank(masked, i + 1, j)
            i, prev_sig = j + 1, c
            continue
        if c == "%" and _percent_literal_start(src, i, prev_sig):
            kind_ch = src[i + 1] if src[i + 1].isalpha() else "Q"
            open_at = i + 2 if src[i + 1].isalpha() else i + 1
            opener = src[open_at]
            closer = _PAIRS.get(opener, opener)
            j, depth = open_at + 1, 1
            while j < n:
                ch = src[j]
                if ch == "\\":
                    j += 2
                    continue
                if closer != opener and ch == opener:
                    depth += 1
                elif ch == closer:
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            lits.append((open_at + 1, min(j, n), "xstr" if kind_ch == "x" else "percent"))
            blank(masked, open_at + 1, j)
            i, prev_sig = j + 1, closer
            continue
        if c == "/" and _regex_start(prev_sig, prev_word):
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
            if j < n and src[j] == "/":
                blank(masked, i + 1, j)
                lits.append((i + 1, j, "regex"))
                i, prev_sig = j + 1, "/"
                continue
        if c == "<" and src.startswith("<<", i):
            m = _HEREDOC.match(src, i)
            if m and _heredoc_ok(m, prev_sig, prev_word):
                pending.append((m.group(3), m.group(1)))
                pending_kind.append("heredoc")
                i = m.end()
                prev_sig = "'"
                continue
        if c.isalnum() or c == "_":
            j = i
            while j < n and (src[j].isalnum() or src[j] in "_?!"):
                j += 1
            prev_word = src[i:j]
            prev_sig = src[j - 1]
            i = j
            continue
        prev_sig = c
        if c not in ".:":
            prev_word = ""
        i += 1
    return Lexed("".join(masked), "".join(nocomment), lits)


def _percent_literal_start(src: str, i: int, prev_sig: str) -> bool:
    nxt = src[i + 1: i + 2]
    if not nxt:
        return False
    if nxt.isalpha():
        if nxt not in "qQwWiIxrs" or not src[i + 2: i + 3] or src[i + 2].isalnum():
            return False
        if src[i + 2].isspace():
            return False
        open_ok = True
    else:
        open_ok = nxt in "([{<|!/"
    if not open_ok:
        return False
    # 빈 문자열은 ``in ")]}"`` 가 참이라 줄 첫머리의 %x(...) 를 놓친다 — 비어 있지 않을 때만
    if prev_sig and (prev_sig in ")]}" or prev_sig.isdigit()):
        return False
    if prev_sig.isalnum() or prev_sig == "_":
        # ``puts %w[a b]`` 은 리터럴, ``a %b`` 는 나머지 연산 — 앞에 공백이 있고 뒤는 붙었을 때만
        return i > 0 and src[i - 1] in " \t" and not nxt.isspace()
    return True


def _regex_start(prev_sig: str, prev_word: str) -> bool:
    if prev_word in _REGEX_PREV_WORDS:
        return True
    return prev_sig == "" or not (prev_sig.isalnum() or prev_sig in "_)]}'\"")


def _heredoc_ok(m: re.Match[str], prev_sig: str, prev_word: str) -> bool:
    if m.group(1) or m.group(2):
        return True
    # ``arr << FOO`` (배열 추가) 와 구분: 대입·인자 자리에서 대문자 식별자일 때만 heredoc
    return m.group(3).isupper() and (prev_sig in "=(,{|:" or prev_sig == "")


# ── 구조: def 범위 ────────────────────────────────────────────────

_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_?!]*|\n|;")
_OPENERS = {"def", "class", "module", "case", "begin", "if", "unless", "while", "until", "for"}
_STMT_PREV_WORDS = {"then", "else", "do", "begin", "and", "or", "not", "elsif", "ensure"}
#: 본문이 나중에 불릴 때 도는 블록을 여는 호출 (줄 안에서 ``do`` 앞에 온다)
_DEFERRED_BLOCK = re.compile(
    r"\b(?:define_method|define_singleton_method|lambda|proc)\b|\bProc\.new\b|->"
)
_ENDLESS_DEF = re.compile(r"\s*[\w.?!]+\s*(?:\([^)]*\))?\s*=(?![=~>])")


def def_regions(masked: str) -> list[tuple[int, int, str]]:
    """(시작, 끝, 이름) — 호출해야 도는 ``def`` 본문과 ``__FILE__ == $0`` 가드 블록의 범위."""
    out: list[tuple[int, int, str]] = []
    stack: list[tuple[str, int, str]] = []  # (종류, 시작, 이름)
    loop_do_pending = False
    prev_tok = ""
    for m in _TOKEN.finditer(masked):
        tok = m.group(0)
        if tok in ("\n", ";"):
            loop_do_pending = False
            prev_tok = ""
            continue
        before = masked[max(0, m.start() - 1): m.start()]
        after = masked[m.end(): m.end() + 1]
        hash_key = after == ":" and masked[m.end(): m.end() + 2] != "::"
        if before in (".", ":", "@", "$") or hash_key:
            prev_tok = tok
            continue  # 메서드 호출·심볼·해시 키 — 예약어가 아니다
        line_start = masked.rfind("\n", 0, m.start()) + 1
        head = masked[line_start: m.start()].rstrip()
        if tok in _OPENERS:
            is_open = True
            if tok in ("if", "unless", "while", "until"):
                last = head[-1:]
                stmt_start = (
                    not head
                    or last in "=(,{|&;:?[+-*"
                    or prev_tok in _STMT_PREV_WORDS
                )
                if stmt_start and not head:
                    # 앞줄이 ``\`` 로 이어지면 줄 맨 앞이어도 수식어다:
                    #     raise ArgumentError, "..." \
                    #       unless method.is_a?(Symbol)
                    # 여는 말로 세면 짝 없는 블록이 쌓여 def 의 end 를 먹고, 그 def 본문이 require
                    # 시점 코드로 남는다 (실측 오탐: stripe 21.0.0 connection_manager.rb).
                    prev_line = masked[:line_start].rstrip(" \t\r\n")
                    if prev_line.endswith("\\"):
                        stmt_start = False
                is_open = stmt_start
            if is_open:
                name = ""
                if tok == "def":
                    rest = masked[m.end(): masked.find("\n", m.end()) % (len(masked) + 1)]
                    if _ENDLESS_DEF.match(rest):
                        prev_tok = tok
                        continue
                    nm = re.match(r"\s*([\w.?!=<>+\-*/\[\]]+)", rest)
                    name = nm.group(1).split(".")[-1] if nm else ""
                if tok == "if":
                    eol = masked.find("\n", m.end())
                    line = masked[m.end(): len(masked) if eol < 0 else eol]
                    if "__FILE__" in line and ("$0" in line or "$PROGRAM_NAME" in line):
                        tok_kind = "guard"
                    else:
                        tok_kind = tok
                else:
                    tok_kind = tok
                stack.append((tok_kind, m.start(), name))
                if tok in ("while", "until", "for"):
                    loop_do_pending = True
        elif tok == "do":
            if loop_do_pending:
                loop_do_pending = False
            elif _DEFERRED_BLOCK.search(head):
                # ``define_method('x') do``·``lambda do``·``proc do`` 의 본문은 그 메서드를 부를 때
                # 돈다 — def 본문과 같다. 일반 블록으로 두면 본문이 require 시점 코드로 남아, 거기서
                # 부르는 메서드의 본문까지 되살아난다. 실측 오탐(감시기 첫 주기, 2026-11-14):
                # crawlora-speedrun·-openligadb·-modrinth — API 클라이언트 메서드 안의
                # ``Net::HTTP.new``. 스캔한 rubygems 4개 중 3개가 이 오탐이었다.
                stack.append(("def", m.start(), ""))
            else:
                stack.append(("do", m.start(), ""))
        elif tok == "end" and stack:
            kind, start, name = stack.pop()
            if kind in ("def", "guard"):
                out.append((start, m.end(), name))
        prev_tok = tok
    return out


def blank_ranges(text: str, ranges: list[tuple[int, int, str]]) -> str:
    """``ranges`` 안을 공백으로 (줄바꿈 유지) — 오프셋은 그대로."""
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
    """``start`` 에서 시작한 호출이 끝나는 오프셋 — 괄호가 닫히고 줄이 끝날 때까지."""
    depth, i, n = 0, start, len(masked)
    while i < n:
        c = masked[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == ";" and depth <= 0:
            return i
        elif c == "\n" and depth <= 0:
            tail = masked[start:i].rstrip()
            nxt = masked[i + 1:].lstrip(" \t")
            if tail.endswith((",", "\\", ".", "+", "&&", "||", "|", "=")) or nxt.startswith("."):
                i += 1
                continue
            return i
        i += 1
    return n
