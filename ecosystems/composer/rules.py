"""Composer(Packagist) 정적분석 — 자동 실행되는 PHP 코드만 HIGH 로 본다.

의존성 패키지의 코드가 사용자 쪽에서 도는 경로:

* **composer-plugin** (``type: composer-plugin``) — ``extra.class`` 의 플러그인 클래스가
  ``composer install`` 도중 Composer 프로세스 안에서 로드·실행된다. 클래스 전체가 범위.
* **autoload.files** — Composer 의 오토로더가 매 요청 시작에 ``require`` 한다. 그 파일의
  최상단 코드(함수·메서드 본문 제외)가 범위.
* ``scripts`` — **의존성의 scripts 는 Composer 가 실행하지 않는다** (루트 프로젝트만).
  그래서 HIGH 가 아니라 정황(LOW, 수상한 명령이면 MEDIUM)이다. ``create-project`` 로 이
  패키지를 루트로 받는 경우엔 돈다는 점만 상세에 적는다.

판정 (설계 §2.3): 그 범위 안에서 네트워크 호출, 수상한 명령 실행, 디코딩→eval 류,
자격 증명 접근+외부 호출이면 HIGH. 범위 밖에서는 디코딩→eval·수상한 명령만 MEDIUM.
예외: ``$_GET/$_POST/$_REQUEST/$_COOKIE`` 가 곧바로 eval·system 류에 들어가는 **웹셸 모양**은
정상 라이브러리가 쓸 이유가 없어 위치와 무관하게 HIGH (테스트 디렉터리 제외).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import PurePosixPath
from typing import Any

from api.schemas import Severity, StaticFinding
from ecosystems.composer.phplex import (
    Lexed,
    blank_ranges,
    function_regions,
    lex,
    line_of,
    statement_end,
)
from engine.rules.base import FileContext, SourceTree, make_finding

RULE_PLUGIN_EXEC = "composer-plugin-exec"
RULE_AUTOLOAD_EXEC = "composer-autoload-exec"
RULE_DECODE_EVAL = "composer-decode-eval"
RULE_WEBSHELL = "composer-webshell"
RULE_EXFIL = "composer-exfil-endpoint"
RULE_SUSPICIOUS_CMD = "composer-suspicious-command"
RULE_PLUGIN_CONTEXT = "composer-plugin"
RULE_SCRIPTS = "composer-dependency-scripts"
RULE_UNREADABLE = "composer-unreadable"

RULE_CWES: dict[str, frozenset[str]] = {
    RULE_PLUGIN_EXEC: frozenset({"CWE-506"}),
    RULE_AUTOLOAD_EXEC: frozenset({"CWE-506"}),
    RULE_DECODE_EVAL: frozenset({"CWE-94", "CWE-502"}),
    RULE_WEBSHELL: frozenset({"CWE-78", "CWE-94"}),
    RULE_EXFIL: frozenset({"CWE-200"}),
    RULE_SUSPICIOUS_CMD: frozenset({"CWE-78"}),
    RULE_PLUGIN_CONTEXT: frozenset({"CWE-829"}),
    RULE_SCRIPTS: frozenset({"CWE-829"}),
    RULE_UNREADABLE: frozenset({"CWE-693"}),
}

MAX_FILE_BYTES = 2 * 1024 * 1024

_NETWORK = re.compile(
    r"(?<![\w$>:])(?:curl_exec|curl_multi_exec|fsockopen|pfsockopen|stream_socket_client"
    r"|socket_connect|gethostbyname|gethostbynamel|dns_get_record|checkdnsrr|get_headers)\s*\("
    r"|(?<![\w$>:])(?:file_get_contents|fopen|readfile|copy|file|simplexml_load_file)\s*\(\s*"
    r"[\"']"  # URL 은 masked 에서 가려져 있어 따옴표까지만 맞추고 원문으로 확인한다
    r"|(?<![\w$>:])new\s+(?:\\?SoapClient|\\?SoapServer)\b"
    r"|(?<![\w$>:])(?:include|require)(?:_once)?\s*\(?\s*[\"']"
)
_SPAWN = re.compile(
    r"(?<![\w$>:])(?:system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\("
)
_SUSPICIOUS_CMD = re.compile(
    r"powershell|pwsh|-enc(?:odedcommand)?\b|windowstyle\s+hidden|mshta|certutil|bitsadmin"
    r"|rundll32|regsvr32|invoke-webrequest|\biwr\b|invoke-expression|\biex\b"
    r"|\bcurl\b|\bwget\b|/dev/tcp|\bnc\s+-e|\bncat\b|base64\s+-d|\|\s*(?:ba|z)?sh\b"
    r"|\bbash\s+-i|schtasks|crontab|chmod\s+\+x\s+/(?:tmp|var/tmp|dev/shm)",
    re.IGNORECASE,
)
_EVAL = re.compile(
    r"(?<![\w$>:])(?:eval|assert|create_function)\s*\("
    r"|(?<![\w$>:])unserialize\s*\("
    r"|(?<![\w$>:])preg_replace\s*\("
)
#: preg_replace 의 패턴 문자열은 masked 에서 가려지므로 원문으로 /e 수식어를 확인한다
_PREG_E = re.compile(r"preg_replace\s*\(\s*[\"'][^\"']*/[a-zA-Z]*e[a-zA-Z]*[\"']")
_DECODER = re.compile(
    r"(?<![\w$>:])(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin"
    r"|convert_uudecode|openssl_decrypt|mcrypt_decrypt)\s*\("
    r"|[\"']ev[\"']\s*\.\s*[\"']al[\"']"
)
_ASSIGN = re.compile(r"(\$\w+)\s*=(?![=>])")
_SUPERGLOBAL = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\b")
_WEBSHELL_SINK = re.compile(
    r"(?<![\w$>:])(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open"
    r"|create_function)\s*\("
)
_VARFUNC_SUPERGLOBAL = re.compile(r"(?<![\w>:])\$\w+\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b")
_CREDENTIALS = re.compile(
    r"\.ssh/|\.aws/credentials|\.npmrc|\.netrc|\.git-credentials|/etc/passwd|/etc/shadow"
    r"|\bauth\.json|\.docker/config|\$_ENV\b(?!\s*\[)|(?<![\w$>:])getenv\s*\(\s*\)"
)
_EXFIL_STRONG = (
    ("Discord 웹훅", re.compile(r"discord(?:app)?\.com/api/webhooks/\d{15,}/[\w-]{20,}")),
    ("Telegram 봇 토큰", re.compile(r"api\.telegram\.org/bot\d{6,}:[\w-]{30,}")),
)
_EXFIL_WEAK = (
    ("수집 서비스 주소",
     re.compile(r"(?:webhook\.site|requestbin\.(?:com|net)|\.pipedream\.net|\.oastify\.com"
                r"|\.interact\.sh|burpcollaborator\.net|\.canarytokens\.com)", re.IGNORECASE)),
)
_TEST_PATH = re.compile(
    r"(?:^|/)(?:tests?|testing|fixtures?|examples?|docs?)(?:/|$)", re.IGNORECASE
)
_PHP_SUFFIXES = (".php", ".inc", ".phtml", ".php5", ".php7")


def _cwe(rule: str) -> str:
    return sorted(RULE_CWES[rule])[0]


class _Analysis:
    def __init__(self, relpath: str, text: str) -> None:
        self.relpath = relpath
        self.text = text
        self.lx: Lexed = lex(text)
        self.funcs = function_regions(self.lx.masked)

    def scope(self, *, mode: str) -> str:
        """mode: ``all`` 파일 전체 · ``top`` 함수 본문을 뺀 최상단(+최상단에서 부르는 로컬 함수)."""
        if mode == "all":
            return self.lx.masked
        blanked = list(self.funcs)
        names = {nm: (a, b) for a, b, nm in self.funcs if nm}
        for _ in range(8):
            cur = blank_ranges(self.lx.masked, blanked)
            called = [
                nm for nm, (a, b) in names.items()
                if (a, b, nm) in blanked
                and re.search(rf"(?<![\w$>:]){re.escape(nm)}\s*\(", cur)
            ]
            if not called:
                break
            for nm in called:
                blanked.remove((names[nm][0], names[nm][1], nm))
        return blank_ranges(self.lx.masked, blanked)


def _decoded_vars(a: _Analysis) -> set[str]:
    out: set[str] = set()
    for m in _ASSIGN.finditer(a.lx.masked):
        end = statement_end(a.lx.masked, m.start())
        if _DECODER.search(a.lx.nocomment[m.start():end]):
            out.add(m.group(1))
    return out


def _scan(a: _Analysis, scope: str) -> list[tuple[str, int, str]]:
    """범위 안 위험 행위 → [(종류, 줄, 설명)]. 종류: net spawn decode cred"""
    out: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int]] = set()

    def add(kind: str, off: int, detail: str) -> None:
        ln = line_of(a.text, off)
        if (kind, ln) not in seen:
            seen.add((kind, ln))
            out.append((kind, ln, detail))

    for m in _NETWORK.finditer(scope):
        # 리터럴(URL)은 masked 에서 가려져 있으므로 원문(주석 제외)으로 한 번 더 확인한다
        text = a.lx.nocomment[m.start():statement_end(a.lx.masked, m.start())]
        if re.match(r"(?:file_get_contents|fopen|readfile|copy|file|simplexml_load_file|include|"
                    r"require)", m.group(0)) and not re.search(r"(?:https?|ftps?)://", text):
            continue
        add("net", m.start(), f"네트워크 호출 `{m.group(0).strip()[:40]}`")
    for m in _SPAWN.finditer(scope):
        text = a.lx.nocomment[m.start():statement_end(a.lx.masked, m.start())]
        hit = _SUSPICIOUS_CMD.search(text)
        if hit:
            add("spawn", m.start(), f"수상한 명령 실행 `{hit.group(0)}`")
    for s, e, kind in a.lx.literals:
        if kind != "xstr" or scope[s - 1: s] in ("", " "):
            continue
        hit = _SUSPICIOUS_CMD.search(a.text[s:e])
        if hit:
            add("spawn", s, f"수상한 명령 실행(백틱) `{hit.group(0)}`")
    decoded = _decoded_vars(a)
    for m in _EVAL.finditer(scope):
        text = a.lx.nocomment[m.start():statement_end(a.lx.masked, m.start())]
        is_preg_e = m.group(0).lstrip().startswith("preg_replace")
        if is_preg_e and not _PREG_E.match(text):
            continue
        fed = _DECODER.search(text) or any(
            re.search(rf"{re.escape(v)}\b", text) for v in decoded)
        if fed:
            add("decode", m.start(), f"디코딩 결과를 실행/역직렬화 `{m.group(0).strip()[:30]}`")
        elif is_preg_e:
            add("decode", m.start(), "preg_replace /e (코드 실행 수식어)")
    for m in _CREDENTIALS.finditer(scope + " " + " ".join(
            a.text[s:e] for s, e, k in a.lx.literals if s < len(scope))):
        add("cred", min(m.start(), len(a.text) - 1), f"자격 증명 접근 `{m.group(0)}`")
    return out


def _file_findings(
    ctx: FileContext, a: _Analysis, *, rule: str | None, mode: str, origin: str
) -> list[StaticFinding]:
    """rule 이 있으면 자동 실행 파일(범위 안은 HIGH), 없으면 정황(MEDIUM)만."""
    out: list[StaticFinding] = []
    auto = rule is not None
    hits = _scan(a, a.scope(mode=mode))
    active = any(k in ("net", "spawn", "decode") for k, _, _ in hits)
    for kind, ln, detail in hits:
        if kind == "decode":
            r = RULE_DECODE_EVAL
        elif auto:
            r = rule or RULE_AUTOLOAD_EXEC
        elif kind == "spawn":
            r = RULE_SUSPICIOUS_CMD
        else:
            continue  # 범위 밖의 네트워크·자격 증명 접근은 평범한 라이브러리 코드
        if auto and kind == "cred" and not active:
            sev, detail = Severity.MEDIUM, detail + " (단독 — 외부 전송은 못 봄)"
        else:
            sev = Severity.HIGH if auto else Severity.MEDIUM
        out.append(make_finding(rule=r, cwe=_cwe(r), severity=sev, ctx=ctx, line=ln,
                                detail=f"{origin}: {detail}"))
    return out


def _webshell(ctx: FileContext, a: _Analysis) -> list[StaticFinding]:
    out: list[StaticFinding] = []
    for m in _WEBSHELL_SINK.finditer(a.lx.masked):
        text = a.lx.nocomment[m.start():statement_end(a.lx.masked, m.start())]
        if _SUPERGLOBAL.search(text):
            out.append(make_finding(
                rule=RULE_WEBSHELL, cwe="CWE-78", severity=Severity.HIGH, ctx=ctx,
                line=line_of(a.text, m.start()),
                detail=f"웹셸 모양 — 요청 입력이 `{m.group(0).strip()[:12]}` 에 그대로 들어간다"))
    for m in _VARFUNC_SUPERGLOBAL.finditer(a.lx.masked):
        out.append(make_finding(
            rule=RULE_WEBSHELL, cwe="CWE-94", severity=Severity.MEDIUM, ctx=ctx,
            line=line_of(a.text, m.start()),
            detail="변수 함수에 요청 입력을 직접 넘김 (웹셸 변형 가능성)"))
    return out


def _exfil(ctx: FileContext, a: _Analysis, *, auto: bool) -> list[StaticFinding]:
    out: list[StaticFinding] = []
    for label, pat in _EXFIL_STRONG:
        for m in pat.finditer(a.lx.nocomment):
            out.append(make_finding(
                rule=RULE_EXFIL, cwe="CWE-200", severity=Severity.HIGH, ctx=ctx,
                line=line_of(a.text, m.start()),
                detail=f"{label} — 남의 채널에 쓰는 비밀 토큰이 패키지에 박혀 있다"))
    for label, pat in _EXFIL_WEAK:
        for m in pat.finditer(a.lx.nocomment):
            out.append(make_finding(
                rule=RULE_EXFIL, cwe="CWE-200",
                severity=Severity.HIGH if auto else Severity.MEDIUM, ctx=ctx,
                line=line_of(a.text, m.start()), detail=f"{label}: {m.group(0)}"))
    return out


def _json(text: str | None) -> dict[str, Any]:
    if not text:
        return {}
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def _norm(base: str, rel: str) -> str:
    p = PurePosixPath(base) / rel.lstrip("./") if base else PurePosixPath(rel.lstrip("./"))
    return p.as_posix().replace("//", "/")


def _class_files(
    fqcn: str, autoload: dict[str, Any], base: str, files: set[str], texts: dict[str, str]
) -> list[str]:
    """플러그인 클래스 이름 → 파일 (psr-4 · psr-0 · 클래스 이름 일치 검색 순)."""
    fqcn = fqcn.lstrip("\\")
    found: list[str] = []
    psr4 = autoload.get("psr-4") if isinstance(autoload.get("psr-4"), dict) else {}
    for prefix, paths in psr4.items():
        if not fqcn.startswith(prefix.lstrip("\\")):
            continue
        tail = fqcn[len(prefix.lstrip("\\")):].replace("\\", "/") + ".php"
        found += [_norm(base, f"{p.rstrip('/')}/{tail}") for p in _as_list(paths) or [""]]
    psr0 = autoload.get("psr-0") if isinstance(autoload.get("psr-0"), dict) else {}
    for prefix, paths in psr0.items():
        if fqcn.startswith(prefix.lstrip("\\")):
            tail = fqcn.replace("\\", "/") + ".php"
            found += [_norm(base, f"{p.rstrip('/')}/{tail}") for p in _as_list(paths) or [""]]
    found = [f for f in found if f in files]
    if not found:
        short = fqcn.rsplit("\\", 1)[-1]
        pat = re.compile(rf"\bclass\s+{re.escape(short)}\b")
        found = [f for f in sorted(files) if f.endswith(".php") and f.startswith(base)
                 and short.lower() in f.lower() and pat.search(texts.get(f, ""))][:3]
    return found


def analyze_tree(tree: SourceTree) -> list[StaticFinding]:
    files = set(tree.files())
    # 공급받은 zipball 은 ``vendor-package-<sha>/`` 한 겹에 싸여 있다 — composer.json 위치가 루트
    roots = sorted((f for f in files if PurePosixPath(f).name == "composer.json"),
                   key=lambda f: f.count("/"))
    base = str(PurePosixPath(roots[0]).parent) if roots else ""
    base = "" if base == "." else base
    manifest = _json(tree.read(roots[0])) if roots else {}
    autoload = manifest.get("autoload") if isinstance(manifest.get("autoload"), dict) else {}
    extra = manifest.get("extra") if isinstance(manifest.get("extra"), dict) else {}

    findings: list[StaticFinding] = []
    unreadable: list[str] = []
    cache: dict[str, tuple[FileContext, _Analysis] | None] = {}

    def load(rel: str) -> tuple[FileContext, _Analysis] | None:
        if rel in cache:
            return cache[rel]
        res = None
        if rel in files and rel.lower().endswith(_PHP_SUFFIXES):
            if tree.size(rel) > MAX_FILE_BYTES:
                unreadable.append(f"{rel} (>{MAX_FILE_BYTES} bytes)")
            else:
                text = tree.read(rel)
                if text is None:
                    unreadable.append(rel)
                else:
                    ctx = FileContext(path=PurePosixPath(rel), relpath=rel, text=text, tree=tree)  # type: ignore[arg-type]
                    res = (ctx, _Analysis(rel, text))
        cache[rel] = res
        return res

    manifest_loc = f"{roots[0]}:1" if roots else "composer.json:1"

    # 이름 일치 검색이 파일 내용을 봐야 해서 php 파일을 한 번 읽어 둔다 (크기 상한 안에서)
    texts: dict[str, str] = {}
    for f in files:
        if f.lower().endswith(_PHP_SUFFIXES) and tree.size(f) <= MAX_FILE_BYTES:
            texts[f] = tree.read(f) or ""

    plugin_files: dict[str, str] = {}
    if str(manifest.get("type", "")).lower() == "composer-plugin":
        classes = _as_list(extra.get("class"))
        for cls in classes:
            for f in _class_files(cls, autoload, base, files, texts):
                plugin_files[f] = cls
        findings.append(StaticFinding(
            rule=RULE_PLUGIN_CONTEXT, cwe="CWE-829", severity=Severity.LOW,
            location=manifest_loc,
            detail="composer-plugin — 설치 중 Composer 프로세스 안에서 플러그인 클래스가 실행된다"
                   + (f" ({', '.join(classes[:2])})" if classes else " (extra.class 없음)")))
        if classes and not plugin_files:
            unreadable.append(f"plugin class {classes[0]} (파일을 찾지 못함)")

    autoload_files = {
        _norm(base, p) for p in _as_list(autoload.get("files"))
    } & files

    scripts = manifest.get("scripts") if isinstance(manifest.get("scripts"), dict) else {}
    if scripts:
        cmds = " ".join(c for v in scripts.values() for c in _as_list(v))
        hit = _SUSPICIOUS_CMD.search(cmds)
        findings.append(StaticFinding(
            rule=RULE_SCRIPTS, cwe="CWE-829",
            severity=Severity.MEDIUM if hit else Severity.LOW, location=manifest_loc,
            detail="scripts 는 의존성일 때 Composer 가 실행하지 않는다(루트 프로젝트만; "
                   "create-project 로 루트가 되면 실행됨): " + ", ".join(sorted(scripts)[:6])
                   + (f" — 수상한 명령 `{hit.group(0)}`" if hit else "")))

    for rel in sorted(files):
        got = load(rel)
        if got is None:
            continue
        ctx, a = got
        if rel in plugin_files:
            findings += _file_findings(ctx, a, rule=RULE_PLUGIN_EXEC, mode="all",
                                       origin="Composer 플러그인 클래스(설치 중 실행)")
            auto = True
        elif rel in autoload_files:
            findings += _file_findings(ctx, a, rule=RULE_AUTOLOAD_EXEC, mode="top",
                                       origin="autoload.files — 매 요청 시작에 실행")
            auto = True
        else:
            auto = False
            if not _TEST_PATH.search(rel):
                findings += _file_findings(
                    ctx, a, rule=None, mode="all", origin="자동 실행 범위 밖")
        if not _TEST_PATH.search(rel):
            findings += _webshell(ctx, a)
        findings += _exfil(ctx, a, auto=auto)

    if unreadable:
        findings.append(StaticFinding(
            rule=RULE_UNREADABLE, cwe="CWE-693", severity=Severity.MEDIUM,
            location=f"{unreadable[0].split(' ')[0]}:1",
            detail=f"읽지 못한 파일 {len(unreadable)}개 — 분석에서 빠졌다: "
                   + ", ".join(unreadable[:5])))
    return _sorted(_dedupe(findings))


_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


def _dedupe(items: Iterable[StaticFinding]) -> list[StaticFinding]:
    seen: set[tuple[str, str, str]] = set()
    out = []
    for f in items:
        key = (f.rule, f.location, f.detail or "")
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def _sorted(items: list[StaticFinding]) -> list[StaticFinding]:
    return sorted(items, key=lambda f: (_ORDER[f.severity], f.location))
