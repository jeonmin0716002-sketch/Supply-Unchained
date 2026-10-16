"""Dangerous-call and obfuscated-payload AST rules.

These overlap with Bandit by design — Bandit is the breadth net, this is the
part we keep in-house so findings carry our own CWE tags and so the
decode-into-``exec`` chain (which Bandit scores as two unrelated low-severity
hits) is reported as the single high-severity signal it actually is.

Severity model — why nothing here is HIGH
-----------------------------------------
Scanning the real ``requests`` sdist flagged three "high severity" calls and
blocked the most-downloaded package on PyPI:

    setup.py:57  os.system("python setup.py sdist bdist_wheel")
    setup.py:58  os.system("twine upload dist/*")
    setup.py:79  exec(f.read(), about)

The first two sit behind ``if sys.argv[-1] == "publish"`` and never run during
an install; the third is the near-universal idiom for reading ``__version__``.
A scanner that blocks ``requests`` is not a scanner anyone will install.

So a dangerous call on its own is *context*, not a verdict. HIGH is reserved
for the signals that are specific to a supply-chain attack rather than merely
present in Python code:

    custom-pth                  code executing at every interpreter start
    custom-install-hook         install/develop command hijacked
    custom-obfuscated-payload   decoded bytes handed to an execution sink

"Executing code you already have" is routine. "Executing code you just
decoded" is malware — that distinction, not the presence of ``exec``, is what
this layer is for.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable

from api.schemas import Severity, StaticFinding
from engine.rules.base import (
    FileContext,
    dotted_name,
    import_aliases,
    make_finding,
    resolve_name,
)

RULE_DANGEROUS_CALL = "custom-dangerous-call"
RULE_OBFUSCATED = "custom-obfuscated-payload"

# call name -> (cwe, severity, human explanation). See the severity note above:
# these are MEDIUM by design -- reported as context, never blocking on their own.
_DANGEROUS_CALLS: dict[str, tuple[str, Severity, str]] = {
    "eval": ("CWE-95", Severity.MEDIUM, "eval() executes an expression built at runtime"),
    "exec": ("CWE-95", Severity.MEDIUM, "exec() executes code built at runtime"),
    "os.system": ("CWE-78", Severity.MEDIUM, "os.system() runs a shell command"),
    "os.popen": ("CWE-78", Severity.MEDIUM, "os.popen() runs a shell command"),
    "os.execv": ("CWE-78", Severity.MEDIUM, "os.execv() replaces the process image"),
    "pickle.loads": ("CWE-502", Severity.MEDIUM, "pickle.loads() deserialises untrusted data"),
    "pickle.load": ("CWE-502", Severity.MEDIUM, "pickle.load() deserialises untrusted data"),
    "marshal.loads": ("CWE-502", Severity.MEDIUM, "marshal.loads() deserialises untrusted data"),
}

# Decoders that turn an opaque blob back into source/bytes. Harmless alone,
# which is why they are only reported when they feed an execution sink.
_DECODERS = {
    "base64.b64decode",
    "base64.b64encode",
    "base64.b32decode",
    "base64.b16decode",
    "base64.a85decode",
    "base64.urlsafe_b64decode",
    "bytes.fromhex",
    "codecs.decode",
    "zlib.decompress",
    "bz2.decompress",
    "lzma.decompress",
}

_EXEC_SINKS = {"eval", "exec", "compile"}

# A long, unbroken base64-ish literal is the usual shape of a stashed payload.
# The threshold is deliberately high: legitimate embedded assets (certs, icons)
# exist, so this is MEDIUM and meant to add weight, not to block on its own.
_B64_BLOB = re.compile(r"^[A-Za-z0-9+/=_-]{200,}$")


#: 수신자를 이름으로 풀 수 없는 메서드 호출의 접두사 — ``f.read().decode()`` → ``?.decode``.
#: 예전엔 수신자를 버리고 ``decode`` 만 남겨서 ``from codecs import decode`` 의 맨 이름과
#: 구분이 안 됐다 (실측 오탐: seleniumbase setup.py 의 ``exec(f.read().decode("utf-8"))``
#: 가 codecs.decode → exec 난독화로 잡혔다).
_UNRESOLVED = "?"


def _call_name(node: ast.AST) -> str | None:
    """Resolve a call target to a dotted name ('os.system', 'b64decode', ...)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent or _UNRESOLVED}.{node.attr}"
    return None


def _matches(name: str, table: Iterable[str]) -> str | None:
    """Match a resolved name against a table, tolerating `from x import y`.

    ``os.system(...)`` and ``system(...)`` after ``from os import system`` are
    the same risk, so a bare tail also matches a dotted table entry.

    점이 없는 항목(``exec``·``eval``·``compile``)은 맨 이름이나 ``builtins.`` 로만 맞춘다.
    아무 수신자의 메서드까지 맞추면 ``re.compile`` 이 실행 싱크 ``compile`` 이 되고
    (실측 오탐: tocode-cli 의 ``re.compile(re.escape(bytes.fromhex(...)))``),
    ``model.eval()`` 이 ``eval`` 이 된다.
    """
    for candidate in table:
        if "." not in candidate:
            if name in (candidate, f"builtins.{candidate}"):
                return candidate
            continue
        if name == candidate or name.endswith("." + candidate):
            return candidate
        if name == candidate.split(".")[-1]:
            return candidate
    return None


def _shell_true(call: ast.Call) -> bool:
    return any(
        kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
        for kw in call.keywords
    )


def dangerous_calls(ctx: FileContext, tree: ast.Module) -> Iterable[StaticFinding]:
    """Flag direct calls to code-execution and unsafe-deserialisation sinks."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        name = _call_name(node.func)
        if not name:
            continue

        matched = _matches(name, _DANGEROUS_CALLS)
        if matched:
            cwe, severity, explanation = _DANGEROUS_CALLS[matched]
            yield make_finding(
                rule=RULE_DANGEROUS_CALL,
                cwe=cwe,
                severity=severity,
                ctx=ctx,
                line=node.lineno,
                detail=explanation,
            )
            continue

        # subprocess.* is only dangerous here in its shell=True form.
        if "subprocess" in name and _shell_true(node):
            yield make_finding(
                rule=RULE_DANGEROUS_CALL,
                cwe="CWE-78",
                severity=Severity.MEDIUM,
                ctx=ctx,
                line=node.lineno,
                detail=f"{name}(..., shell=True) passes the command through a shell",
            )


def _qualified(node: ast.AST, aliases: dict[str, str]) -> str | None:
    """_call_name 에 import 별칭과 ``__import__('모듈')`` 해석을 더한 것.

    풀 수 없는 수신자(``?.decode``)는 그대로 둔다 — bytes.decode 오탐 수정이 유지된다.
    """
    if isinstance(node, ast.Attribute) and dotted_name(node.value) is not None:
        return resolve_name(node, aliases)
    if isinstance(node, ast.Name):
        return resolve_name(node, aliases)
    return _call_name(node)


def _is_chr_join(call: ast.Call, aliases: dict[str, str]) -> bool:
    """``''.join(chr(c) for c in [...])`` — 문자 코드로 소스를 조립한다 (실측: colors-update 등)."""
    name = _call_name(call.func) or ""
    if not name.endswith(".join"):
        return False
    return any(
        isinstance(n, ast.Call) and _qualified(n.func, aliases) in ("chr", "builtins.chr")
        for n in ast.walk(call)
    )


class _DecoderIndex:
    """한 모듈 안에서 "디코딩된 값"이 어디서 나오는지 — 디코더 호출, chr 조립, 그리고
    본문에서 디코딩하는 **자체 함수**(``__vare__``·``invoke``)와 디코딩 결과를 담은 **변수**.

    실측 악성 샘플 중 디코딩→exec 를 한 표현식에 쓰지 않고 함수·변수로 한 번 감싼 것들이
    기존 규칙을 피해 갔다 (dasdsajdjsadsad·forgepys·invokehttp·aes44).
    """

    def __init__(self, tree: ast.Module) -> None:
        self.aliases = import_aliases(tree)
        self.assigned: dict[str, list[ast.AST]] = {}
        bodies: dict[str, list[ast.AST]] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                bodies[node.name] = node.body
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        if isinstance(node.value, ast.Lambda):
                            bodies[t.id] = [node.value.body]
                        else:
                            self.assigned.setdefault(t.id, []).append(node.value)
        # 자체 디코더 함수: 본문에 디코더가 있는 함수 — 함수가 함수를 부르는 경우까지 수렴
        self.local: set[str] = set()
        changed = True
        while changed:
            changed = False
            for fname, body in bodies.items():
                if fname in self.local:
                    continue
                if any(self._direct(n) for stmt in body for n in ast.walk(stmt)):
                    self.local.add(fname)
                    changed = True

    def _direct(self, node: ast.AST) -> str | None:
        if not isinstance(node, ast.Call):
            return None
        name = _qualified(node.func, self.aliases)
        if name:
            matched = _matches(name, _DECODERS)
            if matched:
                return matched
            if name in self.local:
                return f"{name}() (같은 파일의 자체 디코더)"
        if _is_chr_join(node, self.aliases):
            return "chr() 문자열 조립"
        return None

    def find(self, exprs: list[ast.AST]) -> str | None:
        """exprs 안에서 디코딩된 값의 출처를 찾는다. 변수는 한 단계만 따라간다."""
        for expr in exprs:
            for node in ast.walk(expr):
                hit = self._direct(node)
                if hit:
                    return hit
                if isinstance(node, ast.Name) and node.id in self.assigned:
                    for value in self.assigned[node.id]:
                        for sub in ast.walk(value):
                            hit = self._direct(sub)
                            if hit:
                                return f"{hit} → 변수 {node.id}"
        return None


def obfuscated_payload(ctx: FileContext, tree: ast.Module) -> Iterable[StaticFinding]:
    """Flag decoded/decompressed blobs flowing into an execution sink."""
    index = _DecoderIndex(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        sink = _qualified(node.func, index.aliases)
        if not sink or not _matches(sink, _EXEC_SINKS):
            continue

        # Anything nested in the sink's arguments counts: exec(b64decode(x)),
        # exec(zlib.decompress(b64decode(x))), exec(f(b64decode(x))) ...
        matched = index.find(list(node.args))
        if matched:
            yield make_finding(
                rule=RULE_OBFUSCATED,
                cwe="CWE-506",
                severity=Severity.HIGH,
                ctx=ctx,
                line=node.lineno,
                detail=(
                    f"obfuscated payload: {matched} output is passed "
                    f"to {sink}() — decode-then-execute is a malware signature"
                ),
            )

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and _B64_BLOB.match(node.value)
        ):
            yield make_finding(
                rule=RULE_OBFUSCATED,
                cwe="CWE-506",
                severity=Severity.MEDIUM,
                ctx=ctx,
                line=node.lineno,
                detail=(
                    f"encoded blob literal ({len(node.value)} chars) embedded in source — "
                    "may hide a payload"
                ),
            )
