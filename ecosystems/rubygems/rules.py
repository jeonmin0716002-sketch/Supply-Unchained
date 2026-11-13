"""RubyGems 정적분석 — 설치·``require`` 시점에 자동 실행되는 코드만 HIGH 로 본다.

gem 이 사용자 머신에서 코드를 돌리는 경로:

* **네이티브 확장** — gemspec 의 ``extensions`` (보통 ``ext/<x>/extconf.rb``). ``gem install`` 이
  빌드하면서 실행한다. ``mkmf`` 의 ``create_makefile``·``have_library``·``pkg_config`` 는
  평범한 사용이라 finding 이 아니다.
* **require 시점** — ``lib/<name>.rb`` 와 그 파일이 ``require_relative`` 하는 파일의 최상단
  (클래스·모듈 본문 포함, ``def`` 본문은 부르기 전엔 안 돈다), 그리고 RubyGems 가 모든 gem
  명령에서 자동으로 읽는 ``rubygems_plugin.rb``.

판정(설계 §2.3): 그 실행 범위 안에서 (1) 네트워크 호출, (2) 수상한 명령을 담은 프로세스
실행, (3) 디코딩 결과를 ``eval`` 류에 넣기, (4) 자격 증명 파일 읽기 + 외부 호출 중 하나면
HIGH. 같은 행위가 실행 범위 밖이거나 ``def`` 안이면 MEDIUM 이거나 아예 보고하지 않는다.
``post_install_message`` 는 문자열일 뿐이라 보지 않는다.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import PurePosixPath

from api.schemas import Severity, StaticFinding
from ecosystems.rubygems.rubylex import (
    Lexed,
    blank_ranges,
    def_regions,
    lex,
    line_of,
    statement_end,
)
from engine.rules.base import FileContext, SourceTree, make_finding

RULE_EXT_EXEC = "rubygems-ext-exec"
RULE_LOAD_EXEC = "rubygems-load-time-exec"
RULE_DECODE_EVAL = "rubygems-decode-eval"
RULE_EXFIL = "rubygems-exfil-endpoint"
RULE_SUSPICIOUS_CMD = "rubygems-suspicious-command"
RULE_NATIVE_EXT = "rubygems-native-extension"
RULE_UNREADABLE = "rubygems-unreadable"

RULE_CWES: dict[str, frozenset[str]] = {
    RULE_EXT_EXEC: frozenset({"CWE-506"}),
    RULE_LOAD_EXEC: frozenset({"CWE-506"}),
    RULE_DECODE_EVAL: frozenset({"CWE-94", "CWE-502"}),
    RULE_EXFIL: frozenset({"CWE-200"}),
    RULE_SUSPICIOUS_CMD: frozenset({"CWE-78"}),
    RULE_NATIVE_EXT: frozenset({"CWE-829"}),
    RULE_UNREADABLE: frozenset({"CWE-693"}),
}

#: gem 안의 메타데이터 파일 (RubyGemsAdapter.extract 가 metadata.gz 를 풀어 둔다)
METADATA_FILE = "_gem_metadata.yml"

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FOLLOWED = 40

_NETWORK = re.compile(
    r"(?<![\w:])(?:Gem::)?Net::(?:HTTP|HTTPS|FTP|SMTP|IMAP|POP3|Telnet)\s*\.\s*"
    r"(?:get|get_response|get_print|post|post_form|start|new|open|put|delete|head)\b"
    r"|(?<![\w])(?:TCPSocket|UDPSocket|TCPServer|SSLSocket|UNIXSocket)\s*\.\s*(?:new|open)\b"
    r"|(?<![\w])Socket\s*\.\s*(?:tcp|udp|getaddrinfo|gethostbyname)\b"
    r"|(?<![\w])Resolv(?:::DNS)?\s*\.\s*(?:getaddress|getaddresses|getname|new|open)\b"
    r"|(?<![\w])(?:HTTParty|Faraday|RestClient|Excon|Typhoeus|Curl::Easy|Patron)\s*\.\s*"
    r"(?:get|post|put|patch|delete|head|new|request|open|http_post|http_get|perform)\b"
    r"|(?<![\w])(?:URI|OpenURI)\s*\.\s*open\b"
    r"|(?<![\w])URI\s*\.\s*(?:parse|join)\s*\([^)\n]*\)\s*\.\s*(?:read|open)\b"
    r"|(?<![\w.:@$])open\s*\(?\s*[\"']https?://"
)

_SPAWN = re.compile(
    r"(?<![\w.:@$])(?:Kernel\s*\.\s*|Process\s*\.\s*|IO\s*\.\s*|Open3\s*\.\s*)?"
    r"(?:system|exec|spawn|popen|popen2|popen2e|popen3|capture2|capture2e|capture3|pipeline\w*)"
    r"\b(?!\s*[:=]\s*[^=:])"
    r"|(?<![\w.:@$])(?:Kernel\s*\.\s*|IO\s*\.\s*)open\s*\(\s*[\"']\|"
)

#: 설치 시점에 정상 gem 이 돌릴 이유가 없는 명령 (git·make·cc·pkg-config 같은 빌드 명령은 없다)
_SUSPICIOUS_CMD = re.compile(
    r"powershell|pwsh|-enc(?:odedcommand)?\b|windowstyle\s+hidden|mshta|certutil|bitsadmin"
    r"|rundll32|regsvr32|invoke-webrequest|\biwr\b|invoke-expression|\biex\b"
    r"|\bcurl\b|\bwget\b|/dev/tcp|\bnc\s+-e|\bncat\b|base64\s+-d|\|\s*(?:ba|z)?sh\b"
    r"|\bbash\s+-i|schtasks|crontab|chmod\s+\+x\s+/(?:tmp|var/tmp|dev/shm)",
    re.IGNORECASE,
)

_EVAL = re.compile(
    r"(?<![\w.:@$])(?<!def )(?:Kernel\s*\.\s*)?"
    r"(?:eval|instance_eval|class_eval|module_eval|instance_exec|load)\b(?!\s*[:=]\s*[^=:])"
    r"|\.\s*(?:instance_eval|class_eval|module_eval|eval)\b"
    r"|(?<![\w])(?:Marshal\s*\.\s*(?:load|restore)|YAML\s*\.\s*unsafe_load)\b"
    r"|\bsend\s*\(\s*:(?:eval|instance_eval)\b"
)
_DECODER = re.compile(
    r"Base64\s*\.\s*(?:strict_|urlsafe_)?decode64|\.unpack1?\(\s*[\"']m0?[\"']\s*\)"
    r"|Zlib(?:::Inflate|\s*\.\s*inflate|::GzipReader)|\.unpack1?\(\s*[\"']H\*[\"']\s*\)"
    r"|\.pack\(\s*[\"']H\*[\"']\s*\)|N-ZA-Mn-za-m|\.hex\b.*\.chr"
)
_DATA_FILE_LOAD = re.compile(r"Marshal|YAML")
_FILE_READ = re.compile(r"GzipReader\s*\.\s*open|File\s*\.\s*(?:bin)?read|IO\s*\.\s*(?:bin)?read")
_EMBEDDED_DECODER = re.compile(r"Base64|unpack1?\(|\.pack\(|N-ZA-Mn-za-m|\.hex\b")


def _reads_bundled_file(text: str) -> bool:
    return bool(_FILE_READ.search(text)) and not _EMBEDDED_DECODER.search(text)


_ASSIGN = re.compile(r"^\s*(@{0,2}\w+)\s*=(?![=~>])", re.MULTILINE)

_CREDENTIALS = re.compile(
    r"\.ssh/|\.aws/credentials|\.npmrc|\.netrc|\.git-credentials|/etc/passwd|/etc/shadow"
    r"|\.gem/credentials|\.docker/config|\bENV\s*\.\s*(?:to_h|to_a|inspect|each)\b|\bENV\.to_s"
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

_RUBY_SUFFIXES = (".rb", ".gemspec", ".rake")
_RUBY_NAMES = {"rakefile", "gemfile"}
_EXT_FILE_NAMES = {"extconf.rb", "mkrf_conf.rb"}
_REQ_RELATIVE = re.compile(r"""require_relative\s*\(?\s*['"]([^'"]+)['"]""")
_REQ_PATH = re.compile(r"""(?<![\w.])require\s*\(?\s*['"]([^'"]+)['"]""")


def _is_ruby(path: str) -> bool:
    low = path.lower()
    return low.endswith(_RUBY_SUFFIXES) or PurePosixPath(low).name in _RUBY_NAMES


def _yaml_list(meta: str, key: str) -> list[str]:
    m = re.search(rf"^{key}:\s*(?:\[\s*\])?\s*\n((?:\s*- .*\n?)+)", meta + "\n", re.MULTILINE)
    if not m:
        return []
    return [ln.strip()[2:].strip().strip("'\"") for ln in m.group(1).splitlines() if ln.strip()]


def _yaml_scalar(meta: str, key: str) -> str | None:
    m = re.search(rf"^{key}:\s*(\S.*)$", meta, re.MULTILINE)
    return m.group(1).strip().strip("'\"") if m else None


class _Analysis:
    """파일 하나의 어휘 분석 결과와 '자동 실행 범위'."""

    def __init__(self, relpath: str, text: str) -> None:
        self.relpath = relpath
        self.text = text
        self.lx: Lexed = lex(text)
        self.defs = def_regions(self.lx.masked)

    def scope(self, *, auto: bool) -> str:
        """감시할 코드 범위. auto 면 부르기 전엔 안 도는 def 본문을 뺀 뒤, 거기서 부르는
        같은 파일 메서드의 본문을 되살린다 (extconf 가 헬퍼 ``download(url)`` 를 최상단에서
        부르는 형태)."""
        if not auto:
            return self.lx.masked
        blanked = list(self.defs)
        names = {name: (a, b) for a, b, name in self.defs if name}
        for _ in range(8):  # 호출 사슬 고정점
            cur = blank_ranges(self.lx.masked, blanked)
            called = {
                nm for nm in names
                if re.search(rf"(?<![\w.:@$]){re.escape(nm)}\b", cur)
                and (names[nm][0], names[nm][1], nm) in blanked
            }
            if not called:
                break
            for nm in called:
                reg = (names[nm][0], names[nm][1], nm)
                blanked.remove(reg)
        return blank_ranges(self.lx.masked, blanked)


def _stmt_text(a: _Analysis, offset: int) -> str:
    end = statement_end(a.lx.masked, offset)
    return a.lx.nocomment[offset:end]


def _literal_texts(a: _Analysis, start: int, end: int) -> str:
    out = [a.text[s:e] for s, e, k in a.lx.literals if start <= s < end and k != "regex"]
    return " ".join(out)


def _scan_exec_scope(a: _Analysis, scope: str) -> list[tuple[str, int, str]]:
    """자동 실행 범위의 위험 행위 → [(종류, 줄, 설명)]. 종류: net spawn decode cred"""
    out: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int]] = set()

    def add(kind: str, off: int, detail: str) -> None:
        ln = line_of(a.text, off)
        if (kind, ln) not in seen:
            seen.add((kind, ln))
            out.append((kind, ln, detail))

    for m in _NETWORK.finditer(scope):
        add("net", m.start(), f"네트워크 호출 `{m.group(0).strip()}`")
    for m in _SPAWN.finditer(scope):
        end = statement_end(a.lx.masked, m.start())
        text = a.lx.nocomment[m.start():end]
        hit = _SUSPICIOUS_CMD.search(text)
        if hit:
            add("spawn", m.start(), f"수상한 명령 실행 `{hit.group(0)}`")
    for s, e, kind in a.lx.literals:
        # 백틱·%x 문자열. 범위 밖(def 본문)이면 구분자 자리가 공백으로 지워져 있다
        if kind != "xstr" or scope[s - 1: s] in ("", " "):
            continue
        hit = _SUSPICIOUS_CMD.search(a.text[s:e])
        if hit:
            add("spawn", s, f"수상한 명령 실행(백틱·%x) `{hit.group(0)}`")
    decoded = _decoded_vars(a)
    for m in _EVAL.finditer(scope):
        end = statement_end(a.lx.masked, m.start())
        text = a.lx.nocomment[m.start():end]
        if _DATA_FILE_LOAD.search(m.group(0)) and _reads_bundled_file(text):
            # 압축된 **자기 데이터 파일**을 풀어 Marshal.load 하는 것은 캐시·표 로딩 관용구다
            # (실측 오탐: unicode-display_width 3.3.0 — 상위 80개 gem 중 유일한 HIGH). 코드에 박은
            # Base64·hex 덩어리를 푸는 것과 다르다. eval 계열은 파일에서 읽었어도 그대로 잡는다.
            continue
        if _DECODER.search(text) or any(re.search(rf"(?<![\w@]){re.escape(v)}\b", text)
                                        for v in decoded):
            add("decode", m.start(), f"디코딩 결과를 실행/역직렬화 `{m.group(0).strip()}`")
    for m in _CREDENTIALS.finditer(scope + " " + _literal_texts(a, 0, len(scope))):
        add("cred", min(m.start(), len(a.text) - 1), f"자격 증명 접근 `{m.group(0)}`")
    return out


def _decoded_vars(a: _Analysis) -> set[str]:
    names: set[str] = set()
    for m in _ASSIGN.finditer(a.lx.masked):
        end = statement_end(a.lx.masked, m.start())
        if _DECODER.search(a.lx.nocomment[m.start():end]):
            names.add(m.group(1))
    return names


def _findings_for_file(
    ctx: FileContext, a: _Analysis, *, rule: str, auto: bool, origin: str
) -> list[StaticFinding]:
    """자동 실행 파일이면 범위 안 행위를 HIGH 로, 아니면 수상한 명령·디코딩→eval 만 MEDIUM 으로.

    실행 범위 밖의 네트워크 호출·자격 증명 접근은 평범한 라이브러리 코드라 보고하지 않는다."""
    out: list[StaticFinding] = []
    hits = _scan_exec_scope(a, a.scope(auto=auto))
    has_active = any(k in ("net", "spawn", "decode") for k, _, _ in hits)
    for kind, ln, detail in hits:
        if kind == "decode":
            r = RULE_DECODE_EVAL
        elif auto:
            r = rule
        elif kind == "spawn":
            r = RULE_SUSPICIOUS_CMD
        else:
            continue
        if auto and kind == "cred" and not has_active:
            sev, detail = Severity.MEDIUM, detail + " (단독 — 외부 전송은 못 봄)"
        else:
            sev = Severity.HIGH if auto else Severity.MEDIUM
        out.append(make_finding(rule=r, cwe=_cwe_for(r), severity=sev, ctx=ctx, line=ln,
                                detail=f"{origin}: {detail}"))
    return out


def _cwe_for(rule: str) -> str:
    return sorted(RULE_CWES[rule])[0]


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


def _require_targets(a: _Analysis, files: set[str], lib_dirs: list[str]) -> list[str]:
    """이 파일이 최상단에서 require 하는 패키지 안 파일들."""
    scope = a.scope(auto=True)
    base = PurePosixPath(a.relpath).parent
    found: list[str] = []
    for m in _REQ_RELATIVE.finditer(a.lx.nocomment):
        if m.start() >= len(scope) or scope[m.start()] == " ":
            continue
        cand = (base / m.group(1)).as_posix()
        found += [c for c in (cand, cand + ".rb") if c in files]
    for m in _REQ_PATH.finditer(a.lx.nocomment):
        if scope[m.start(): m.start() + 1] == " ":
            continue
        for lib in lib_dirs:
            cand = f"{lib}/{m.group(1)}"
            found += [c for c in (cand, cand + ".rb") if c in files]
    return [PurePosixPath(c).as_posix().replace("/./", "/") for c in found]


def analyze_tree(tree: SourceTree, *, name_hint: str | None = None) -> list[StaticFinding]:
    files = set(tree.files())
    meta = tree.read(METADATA_FILE) or ""
    name = _yaml_scalar(meta, "name") or name_hint or ""
    extensions = [e.lstrip("./") for e in _yaml_list(meta, "extensions")]
    lib_dirs = [d.rstrip("/") for d in _yaml_list(meta, "require_paths")] or ["lib"]

    findings: list[StaticFinding] = []
    unreadable: list[str] = []
    cache: dict[str, tuple[FileContext, _Analysis] | None] = {}

    def load(rel: str) -> tuple[FileContext, _Analysis] | None:
        if rel in cache:
            return cache[rel]
        res = None
        if rel in files and _is_ruby(rel):
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

    ext_files = {
        f for f in files
        if _is_ruby(f) and (
            PurePosixPath(f).name.lower() in _EXT_FILE_NAMES or f in extensions
        )
    }
    ext_files |= {e for e in extensions if e in files and _is_ruby(e)}
    if extensions:
        findings.append(StaticFinding(
            rule=RULE_NATIVE_EXT, cwe="CWE-829", severity=Severity.LOW,
            location=f"{METADATA_FILE}:1",
            detail=f"네이티브 확장 빌드(gem install 시 실행): {', '.join(extensions[:5])}"))

    names = {name, name.replace("-", "/"), name.replace("-", "_")} - {""}
    load_roots: set[str] = set()
    for lib in lib_dirs:
        for nm in names:
            load_roots.add(f"{lib}/{nm}.rb")
        load_roots.add(f"{lib}/rubygems_plugin.rb")
    if not name:  # 이름을 모르면 lib 바로 아래 파일을 진입점으로 본다
        load_roots |= {f for f in files if f.endswith(".rb") and f.count("/") == 1
                       and f.split("/")[0] in lib_dirs}
    load_roots &= files

    auto_origin: dict[str, tuple[str, str]] = {}
    for f in sorted(ext_files):
        auto_origin[f] = (RULE_EXT_EXEC, "설치 시 실행되는 확장 빌드 스크립트")
    queue = sorted(load_roots)
    while queue and len(auto_origin) < MAX_FOLLOWED:
        f = queue.pop(0)
        if f in auto_origin:
            continue
        auto_origin[f] = (RULE_LOAD_EXEC, "require 시점에 실행")
        got = load(f)
        if got:
            queue += [t for t in _require_targets(got[1], files, lib_dirs) if t not in auto_origin]

    for rel in sorted(files):
        got = load(rel)
        if got is None:
            continue
        ctx, a = got
        auto = rel in auto_origin
        rule, origin = auto_origin.get(rel, (RULE_SUSPICIOUS_CMD, "자동 실행 범위 밖"))
        if rel.lower().endswith("rakefile") or rel.endswith(".rake"):
            auto = auto and rel in extensions
        findings += _findings_for_file(ctx, a, rule=rule, auto=auto, origin=origin)
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
