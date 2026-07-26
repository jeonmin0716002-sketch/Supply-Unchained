"""Dangerous-call and obfuscated-payload AST rules.

These overlap with Bandit by design — Bandit is the breadth net, this is the
part we keep in-house so findings carry our own CWE tags and so the
decode-into-``exec`` chain (which Bandit scores as two unrelated low-severity
hits) is reported as the single high-severity signal it actually is.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable

from api.schemas import Severity, StaticFinding
from engine.rules.base import FileContext, make_finding

RULE_DANGEROUS_CALL = "custom-dangerous-call"
RULE_OBFUSCATED = "custom-obfuscated-payload"

# call name -> (cwe, severity, human explanation)
_DANGEROUS_CALLS: dict[str, tuple[str, Severity, str]] = {
    "eval": ("CWE-95", Severity.HIGH, "eval() executes attacker-controlled expressions"),
    "exec": ("CWE-95", Severity.HIGH, "exec() executes arbitrary code at runtime"),
    "os.system": ("CWE-78", Severity.HIGH, "os.system() runs a shell command"),
    "os.popen": ("CWE-78", Severity.HIGH, "os.popen() runs a shell command"),
    "os.execv": ("CWE-78", Severity.HIGH, "os.execv() replaces the process image"),
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


def _call_name(node: ast.AST) -> str | None:
    """Resolve a call target to a dotted name ('os.system', 'b64decode', ...)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _matches(name: str, table: Iterable[str]) -> str | None:
    """Match a resolved name against a table, tolerating `from x import y`.

    ``os.system(...)`` and ``system(...)`` after ``from os import system`` are
    the same risk, so a bare tail also matches a dotted table entry.
    """
    for candidate in table:
        if name == candidate or name.endswith("." + candidate):
            return candidate
        if "." in candidate and name == candidate.split(".")[-1]:
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
                severity=Severity.HIGH,
                ctx=ctx,
                line=node.lineno,
                detail=f"{name}(..., shell=True) passes the command through a shell",
            )


def obfuscated_payload(ctx: FileContext, tree: ast.Module) -> Iterable[StaticFinding]:
    """Flag decoded/decompressed blobs flowing into an execution sink."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        sink = _call_name(node.func)
        if not sink or not _matches(sink, _EXEC_SINKS):
            continue

        # Anything nested in the sink's arguments counts: exec(b64decode(x)),
        # exec(zlib.decompress(b64decode(x))), exec(f(b64decode(x))) ...
        for inner in ast.walk(ast.Module(body=list(node.args), type_ignores=[])):
            if not isinstance(inner, ast.Call):
                continue
            decoder = _call_name(inner.func)
            if not decoder:
                continue
            matched = _matches(decoder, _DECODERS)
            if matched:
                yield make_finding(
                    rule=RULE_OBFUSCATED,
                    cwe="CWE-506",
                    severity=Severity.HIGH,
                    ctx=ctx,
                    line=node.lineno,
                    detail=(
                        f"obfuscated payload: {matched}() output is passed straight "
                        f"to {sink}() — decode-then-execute is a malware signature"
                    ),
                )
                break

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
