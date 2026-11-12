"""Go 정적분석 — 모듈을 import·빌드할 때 자동으로 도는 코드만 본다.

Go 에는 설치 스크립트가 없다. 사용자 머신에서 ``go build``·``go get`` 이후 저절로 실행되는 것:

* ``func init()`` 와 **패키지 수준 ``var`` 초기화식** — 패키지를 import 하는 순간 (main 보다 먼저).
  init 이 같은 패키지의 다른 함수를 부르면 그 함수 본문도 실행 범위다.
* cgo — C 코드의 ``__attribute__((constructor))`` 는 프로그램이 로드될 때 돈다. ``#cgo`` 지시문은 빌드에 쓰인다.
* ``//go:generate`` — ``go generate`` 를 직접 돌릴 때만 실행된다. 그래서 정황(MEDIUM)으로만 센다.

판정 원칙은 전 생태계 공통이다(docs/design/multi-ecosystem.md §2.3): 위험 API 가 "있다"가 아니라
"import 시점에 도는 범위 안에서 무엇을 하느냐". 평범한 Go 코드가 init 에서 하는 일(정규식 컴파일,
플래그 등록, 테이블 구성)은 아무것도 내지 않는다. HIGH 는 크리덴셜+네트워크, 수상한 명령,
디코딩→실행, 지속성, 토큰이 박힌 웹훅, 그리고 C 생성자에서의 프로세스·소켓 호출뿐이다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from api.schemas import Severity, StaticFinding
from ecosystems.go.scanner import (
    FileScan,
    Span,
    mask_uninvoked_literals,
    scan_file,
    split_args,
)
from engine.rules.base import SourceTree

R_EXFIL = "go-init-exfil"
R_ENDPOINT = "go-exfil-endpoint"
R_SUSPICIOUS = "go-init-suspicious-command"
R_PAYLOAD = "go-init-payload-exec"
R_PERSIST = "go-init-persistence"
R_NETWORK = "go-init-network"
R_SPAWN = "go-init-spawn"
R_CGO_CTOR = "go-cgo-constructor"
R_CGO_FLAGS = "go-cgo-flags"
R_GENERATE = "go-generate-command"
R_MODPATH = "go-module-path-mismatch"
R_UNREADABLE = "go-unreadable-file"

RULE_CWES: dict[str, frozenset[str]] = {
    R_EXFIL: frozenset({"CWE-200"}),
    R_ENDPOINT: frozenset({"CWE-200"}),
    R_SUSPICIOUS: frozenset({"CWE-78"}),
    R_PAYLOAD: frozenset({"CWE-94"}),
    R_PERSIST: frozenset({"CWE-506"}),
    R_NETWORK: frozenset({"CWE-494"}),
    R_SPAWN: frozenset({"CWE-78"}),
    R_CGO_CTOR: frozenset({"CWE-94", "CWE-78"}),
    R_CGO_FLAGS: frozenset({"CWE-78", "CWE-427"}),
    R_GENERATE: frozenset({"CWE-78"}),
    R_MODPATH: frozenset({"CWE-829"}),
    R_UNREADABLE: frozenset({"CWE-693"}),
}

_MAX_GO = 8_000_000
_MAX_C = 20_000_000
_SEV_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}

#: 실제로 패킷을 내보내는 (import 경로, 함수·심볼). 타입 이름만 쓰는 것은 통신이 아니다.
_NETWORK = {
    "net/http": {"Get", "Post", "PostForm", "Head", "NewRequest", "NewRequestWithContext",
                 "DefaultClient"},
    "net": {"Dial", "DialTimeout", "DialTCP", "DialUDP", "DialIP", "DialUnix", "LookupHost",
            "LookupIP", "LookupAddr", "LookupCNAME", "LookupMX", "LookupNS", "LookupTXT",
            "LookupSRV", "LookupPort", "ResolveTCPAddr", "ResolveUDPAddr", "ResolveIPAddr"},
    "crypto/tls": {"Dial", "DialWithDialer"},
    "net/smtp": {"SendMail", "Dial"},
    "net/rpc": {"Dial", "DialHTTP", "DialHTTPPath"},
    "net/textproto": {"Dial"},
    "golang.org/x/net/websocket": {"Dial", "DialConfig"},
    "github.com/gorilla/websocket": {"DefaultDialer"},
}
_EXEC = {
    "os/exec": {"Command", "CommandContext"},
    "syscall": {"Exec", "ForkExec", "StartProcess"},
    "os": {"StartProcess"},
}

_ORDINARY = frozenset({"git", "go", "gcc", "cc", "clang", "pkg-config", "uname", "sw_vers",
                       "which", "nproc", "getconf", "hostname", "whoami", "id", "ldconfig"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "cmd", "powershell", "pwsh"})

_SUSPICIOUS_CMD = re.compile(
    r"powershell|pwsh|-enc(?:odedcommand)?\b|windowstyle\s+hidden|-w\s+hidden|mshta|certutil"
    r"|bitsadmin|rundll32|regsvr32|invoke-webrequest|\biwr\b|invoke-expression|\biex\b"
    r"|/dev/tcp|\bnc\s+-e|bash\s+-i|base64\s+-d|\|\s*(?:ba)?sh\b|schtasks|crontab|reg\s+add",
    re.IGNORECASE,
)
_DOWNLOADER = re.compile(r"\b(?:curl|wget)\b", re.IGNORECASE)
_CRED_ENV = re.compile(
    r"TOKEN|SECRET|PASSW(?:OR)?D|API_?KEY|PRIVATE_?KEY|CREDENTIAL|AWS_SECRET|AWS_ACCESS|SSH_AUTH_SOCK",
    re.IGNORECASE,
)
_CRED_FILE = re.compile(
    r"\.ssh/|\.aws/credentials|\.npmrc|\.pypirc|\.git-credentials|\.cargo/credentials|\.netrc"
    r"|\.docker/config\.json|Login Data|wallet\.dat|\.kube/config|\.config/gcloud",
    re.IGNORECASE,
)
_DECODE_CALL = {("encoding/hex", "DecodeString"),
                ("compress/gzip", "NewReader"), ("compress/zlib", "NewReader"),
                ("compress/flate", "NewReader"), ("encoding/ascii85", "NewDecoder")}
_WRITE_CALL = {("os", "WriteFile"), ("io/ioutil", "WriteFile"), ("os", "Create"),
               ("os", "OpenFile"), ("os", "Chmod"), ("io/ioutil", "TempFile"),
               ("os", "CreateTemp")}
_PERSIST = re.compile(
    r"\.bashrc|\.zshrc|\.bash_profile|\.profile\b|authorized_keys|LaunchAgents|LaunchDaemons"
    r"|\\Startup\\|/etc/cron|crontab|systemd/(?:user|system)|/etc/profile|/etc/ld\.so\.preload"
    r"|CurrentVersion\\\\?Run",
    re.IGNORECASE,
)
_WEBHOOK = re.compile(
    r"discord(?:app)?\.com/api/webhooks/\d{15,}/[\w-]{20,}|api\.telegram\.org/bot\d{6,}:[\w-]{30,}"
)
_COLLECTOR = re.compile(
    r"webhook\.site|requestbin|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|interact\.sh"
    r"|oast\.(?:pro|live|site|online|fun|me)|burpcollaborator\.net|canarytokens\.com"
    r"|pastebin\.com/raw|transfer\.sh|file\.io|\.trycloudflare\.com",
    re.IGNORECASE,
)
_RAW_IP_URL = re.compile(r"https?://(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")

_CALL = re.compile(r"(?<![\w.])([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)")
_LOCAL_CALL = re.compile(r"(?<![\w.])([A-Za-z_]\w*)\s*\(")
_STR = re.compile(r'"((?:[^"\\\n]|\\.)*)"|`([^`]*)`')
_IMPORT_SPEC = re.compile(r'(?:(?<!\w)(?!import\b)([A-Za-z_]\w*|\.)\s+)?"([^"\n]+)"')
_FIRST_DECL = re.compile(r"^(?:func|var|type|const)\b", re.MULTILINE)


def _public_ip(m: re.Match[str]) -> bool:
    a, b, *_ = (int(g) for g in m.groups())
    if a in (0, 10, 127) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
        return False
    return not (a == 169 and b == 254)


Hit = tuple[str, int, str]


@dataclass
class Facts:
    network: list[Hit] = field(default_factory=list)
    spawns: list[Hit] = field(default_factory=list)
    suspicious: list[Hit] = field(default_factory=list)
    creds: list[Hit] = field(default_factory=list)
    decode: list[Hit] = field(default_factory=list)
    writes: list[Hit] = field(default_factory=list)
    persist: list[Hit] = field(default_factory=list)
    endpoints: list[Hit] = field(default_factory=list)
    any_exec: bool = False


def import_aliases(nc: str) -> dict[str, str]:
    """파일의 import 별칭 → 경로. ``import h "net/http"`` 처럼 이름을 바꿔 숨기는 것을 푼다."""
    out: dict[str, str] = {}
    first = _FIRST_DECL.search(nc)
    head = nc[:first.start()] if first else nc
    for m in _IMPORT_SPEC.finditer(head):
        alias, path = m.group(1), m.group(2)
        if alias in ("_", "."):
            continue
        if alias is None:
            parts = path.split("/")
            alias = parts[-1]
            if re.fullmatch(r"v\d+", alias) and len(parts) > 1:
                alias = parts[-2]
            alias = alias.split(".")[0] if alias.startswith(("yaml", "gopkg")) else alias
        out[alias] = path
    return out


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _open_paren(text: str, pos: int) -> int:
    m = re.compile(r"\s*\(").match(text, pos)
    return m.end() - 1 if m else -1


def _is_string_literal(arg: str) -> str | None:
    m = re.fullmatch(r'"((?:[^"\\]|\\.)*)"|`([^`]*)`', arg.strip())
    if not m:
        return None
    return m.group(1) if m.group(1) is not None else m.group(2)


def scan_scope(rel: str, fs: FileScan, text: str, sk: str, base: int, facts: Facts,
               aliases: dict[str, str]) -> None:
    """한 실행 범위(``text`` = nocomment 조각, ``sk`` 는 같은 길이 skeleton, ``base`` 는 파일 내
    오프셋)에서 행위를 모은다."""
    def line(pos: int) -> int:
        return _line_of(fs.nc, base + pos)

    for m in _CALL.finditer(sk):
        qual, attr = m.group(1), m.group(2)
        path = aliases.get(qual)
        if path is None:
            continue
        if attr in _NETWORK.get(path, ()):
            facts.network.append((rel, line(m.start()), f"{path}.{attr}"))
        if attr in _EXEC.get(path, ()):
            facts.any_exec = True
            _record_exec(rel, fs, text, sk, base, m, path, attr, facts)
        if (path, attr) in _DECODE_CALL or (
                path == "encoding/base64" and (attr.endswith("Encoding") or attr == "NewDecoder")):
            facts.decode.append((rel, line(m.start()), f"{path}.{attr}"))
        if (path, attr) in _WRITE_CALL:
            facts.writes.append((rel, line(m.start()), f"{path}.{attr}"))
        if path == "os" and attr in ("Getenv", "LookupEnv"):
            paren = _open_paren(text, m.end())
            args = split_args(sk, text, paren) if paren >= 0 else []
            lit = _is_string_literal(args[0]) if args else None
            if lit and _CRED_ENV.search(lit):
                facts.creds.append((rel, line(m.start()), f"env {lit}"))
        if path == "os" and attr == "Environ":
            facts.creds.append((rel, line(m.start()), "os.Environ() 전체 덤프"))

    for lit in _STR.finditer(text):
        s = lit.group(1) if lit.group(1) is not None else lit.group(2)
        ln = line(lit.start())
        if (h := _CRED_FILE.search(s)):
            facts.creds.append((rel, ln, f"파일 {h.group(0)}"))
        if (h := _PERSIST.search(s)):
            facts.persist.append((rel, ln, h.group(0)))
        for pat in (_WEBHOOK, _COLLECTOR):
            if (h := pat.search(s)):
                facts.endpoints.append((rel, ln, h.group(0)))
        ip = _RAW_IP_URL.search(s)
        if ip and _public_ip(ip):
            facts.endpoints.append((rel, ln, ip.group(0)))


def _record_exec(rel: str, fs: FileScan, text: str, sk: str, base: int, m: re.Match[str],
                 path: str, attr: str, facts: Facts) -> None:
    paren = _open_paren(text, m.end())
    ln = _line_of(fs.nc, base + m.start())
    if paren < 0:
        facts.spawns.append((rel, ln, "<computed>"))
        return
    args = split_args(sk, text, paren)
    idx = 1 if attr == "CommandContext" else 0  # 첫 인자가 context
    prog_lit = _is_string_literal(args[idx]) if len(args) > idx else None
    lits = [s for a in args if (s := _is_string_literal(a)) is not None]
    cmdline = " ".join(lits)
    base_name = PurePosixPath((prog_lit or "").replace("\\", "/")).name.lower()
    base_name = base_name[:-4] if base_name.endswith(".exe") else base_name
    if base_name in ("curl", "wget") or (base_name in _SHELLS and _DOWNLOADER.search(cmdline)):
        facts.network.append((rel, ln, f"exec {base_name or 'curl/wget'}"))
    if (h := _SUSPICIOUS_CMD.search(cmdline)):
        facts.suspicious.append((rel, ln, h.group(0)))
    elif prog_lit is None:
        facts.spawns.append((rel, ln, "<computed>"))
    elif base_name and base_name not in _ORDINARY:
        facts.spawns.append((rel, ln, prog_lit))


def _f(rule: str, sev: Severity, where: Hit, detail: str) -> StaticFinding:
    return StaticFinding(rule=rule, cwe=sorted(RULE_CWES[rule])[0], severity=sev,
                         location=f"{where[0]}:{where[1]}", detail=detail)


def judge(facts: Facts, scope: str) -> list[StaticFinding]:
    out: list[StaticFinding] = []
    web = [e for e in facts.endpoints if not _RAW_IP_URL.fullmatch(e[2])]
    if web:
        out.append(_f(R_ENDPOINT, Severity.HIGH, web[0],
                      f"{scope}에 유출 채널 주소가 박혀 있다: {web[0][2]}"))
    ips = [e for e in facts.endpoints if _RAW_IP_URL.fullmatch(e[2])]
    if ips and facts.network:
        out.append(_f(R_ENDPOINT, Severity.HIGH, ips[0],
                      f"{scope}이 공인 IP({ips[0][2]})로 직접 통신한다"))
    if facts.network and facts.creds:
        c = facts.creds[0]
        out.append(_f(R_EXFIL, Severity.HIGH, c,
                      f"{scope}이 크리덴셜({c[2]})을 읽고 네트워크 호출({facts.network[0][2]})도 한다"))
    if facts.suspicious:
        s = facts.suspicious[0]
        out.append(_f(R_SUSPICIOUS, Severity.HIGH, s, f"{scope}이 수상한 명령을 실행한다: {s[2]}"))
    runnable = [s for s in facts.spawns if s[2] == "<computed>" or s[2] not in _ORDINARY]
    if facts.decode and runnable and (facts.writes or facts.any_exec):
        d = facts.decode[0]
        out.append(_f(R_PAYLOAD, Severity.HIGH, d,
                      f"{scope}이 디코딩/압축 해제({d[2]}) 후 외부 프로그램을 실행한다"))
    if facts.persist and facts.writes:
        p = facts.persist[0]
        out.append(_f(R_PERSIST, Severity.HIGH, p,
                      f"{scope}이 지속성 위치({p[2]})를 건드린다 — 셸 시작 파일·cron·자동 실행 등록"))
    if facts.network and not any(o.severity == Severity.HIGH for o in out):
        n = facts.network[0]
        out.append(_f(R_NETWORK, Severity.MEDIUM, n,
                      f"{scope}이 import 시점에 네트워크 접근({n[2]}) — 라이브러리 init 이 외부와 "
                      "통신할 이유가 드물다"))
    named = [s for s in facts.spawns if s[2] != "<computed>"]
    if named:
        s = named[0]
        out.append(_f(R_SPAWN, Severity.MEDIUM, s,
                      f"{scope}이 import 시점에 프로그램({s[2]})을 실행한다"))
    return out


# ── 패키지 단위 실행 범위 ─────────────────────────────────────────

def _skip_path(rel: str) -> bool:
    parts = rel.split("/")
    if rel.endswith("_test.go"):
        return True
    return any(p in ("vendor", "testdata", "example", "examples")
               or p.startswith(("_", ".")) for p in parts[:-1])


def _module_root(files: list[str]) -> tuple[str, str | None]:
    """(zip 루트 디렉터리, 요청된 모듈 경로). 모듈 zip 의 루트는 ``<모듈경로>@<버전>/`` 이다."""
    for f in files:
        top = f.split("/", 1)[0]
        if "@" in top and "/" in f:
            return top, top.rsplit("@", 1)[0]
    # 첫 구성요소가 module/path@v 처럼 여러 단계일 수도 있다
    for f in files:
        m = re.match(r"^(.+?@[^/]+)/", f)
        if m:
            return m.group(1), m.group(1).rsplit("@", 1)[0]
    return "", None


def _ignored_build(nc_head: str) -> bool:
    return bool(re.search(r"^//go:build\s+ignore\b|^// \+build\s+ignore\b", nc_head, re.MULTILINE))


def analyze(tree: SourceTree) -> list[StaticFinding]:
    findings: list[StaticFinding] = []
    files = tree.files()
    root, requested = _module_root(files)
    prefix = root + "/" if root else ""

    # 1) go.mod 의 모듈 경로 == 요청 경로 ?  (go 는 어긋난 모듈을 거부하지만, 프록시·미러·
    #    repo-jacking 맥락에서 어긋남 자체가 단서다)
    gomod = tree.read(prefix + "go.mod") if (prefix + "go.mod") in files else None
    if gomod is not None and requested:
        m = re.search(r'^\s*module\s+"?([^\s"]+)"?', gomod, re.MULTILINE)
        if m and m.group(1) != requested:
            findings.append(StaticFinding(
                rule=R_MODPATH, cwe="CWE-829", severity=Severity.MEDIUM,
                location=f"{prefix}go.mod:1",
                detail=f"go.mod 의 module 이 {m.group(1)!r} 인데 요청한 모듈은 {requested!r} — "
                       "저장소 이전·탈취(repo-jacking)·이름 사칭을 의심해 출처를 확인해야 한다"))

    # 2) Go 파일을 패키지(디렉터리)별로 읽는다
    pkgs: dict[str, dict[str, FileScan]] = {}
    webhook_anywhere: list[Hit] = []
    for rel in files:
        if rel.endswith(".go") and not _skip_path(rel[len(prefix):] if prefix else rel):
            size = tree.size(rel)
            if size > _MAX_GO:
                findings.append(StaticFinding(
                    rule=R_UNREADABLE, cwe="CWE-693", severity=Severity.MEDIUM,
                    location=f"{rel}:1",
                    detail=f"{size} 바이트 — 분석 상한({_MAX_GO})을 넘어 읽지 않았다"))
                continue
            text = tree.read(rel)
            if text is None:
                findings.append(StaticFinding(
                    rule=R_UNREADABLE, cwe="CWE-693", severity=Severity.MEDIUM,
                    location=f"{rel}:1", detail="파일을 읽지 못했다 — 분석하지 못했다"))
                continue
            fs = scan_file(text)
            if _ignored_build(text[:2000]):
                continue
            pkgs.setdefault(str(PurePosixPath(rel).parent), {})[rel] = fs
            for m in _WEBHOOK.finditer(fs.nc):
                webhook_anywhere.append((rel, _line_of(fs.nc, m.start()), m.group(0)))
            findings += _directive_findings(rel, text)

    facts_all = Facts()
    for pkg_files in pkgs.values():
        funcs = {name: (rel, span) for rel, fs in pkg_files.items() for name, span in fs.funcs.items()}
        for rel, fs in pkg_files.items():
            aliases = import_aliases(fs.nc)
            work: list[tuple[str, FileScan, Span, bool]] = [
                (rel, fs, s, False) for s in fs.inits
            ] + [(rel, fs, s, True) for s in fs.var_specs]
            seen: set[tuple[str, int]] = set()
            depth_budget = 200
            while work and depth_budget:
                depth_budget -= 1
                r, f, span, is_var = work.pop()
                key = (r, span.start)
                if key in seen:
                    continue
                seen.add(key)
                if is_var:
                    text, sk = mask_uninvoked_literals(f.nc, f.sk, span)
                else:
                    text, sk = f.nc[span.start:span.end], f.sk[span.start:span.end]
                scan_scope(r, f, text, sk, span.start, facts_all,
                           aliases if r == rel else import_aliases(f.nc))
                for m in _LOCAL_CALL.finditer(sk):
                    target = funcs.get(m.group(1))
                    if target and m.group(1) not in ("init",):
                        work.append((target[0], pkg_files[target[0]], target[1], False))

    if webhook_anywhere and not any(e[2] == webhook_anywhere[0][2] for e in facts_all.endpoints):
        facts_all.endpoints.append(webhook_anywhere[0])
    findings += judge(facts_all, "import 시점 실행 코드(init·패키지 var)")

    # 3) C 코드: 생성자는 로드 시점에 돈다
    for rel in files:
        if rel.endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".m", ".go")) and \
                not _skip_path(rel[len(prefix):] if prefix else rel):
            size = tree.size(rel)
            if size > _MAX_C:
                findings.append(StaticFinding(
                    rule=R_UNREADABLE, cwe="CWE-693", severity=Severity.MEDIUM,
                    location=f"{rel}:1", detail=f"{size} 바이트 — C 분석 상한을 넘어 읽지 않았다"))
                continue
            if rel.endswith(".go") and size > _MAX_GO:
                continue
            findings += _cgo_constructor(rel, tree)

    findings.sort(key=lambda f: _SEV_ORDER[f.severity])
    return findings


_CTOR = re.compile(r"__attribute__\s*\(\(\s*(?:__)?constructor(?:__)?\b|#pragma\s+init\b|\bDllMain\b")
_C_DANGER = re.compile(
    r"\bsystem\s*\(|\bpopen\s*\(|\bexec[lv][pe]?\s*\(|\bgetaddrinfo\s*\(|\bgethostbyname\s*\("
    r"|\bconnect\s*\(|\bcurl_easy_perform\b|\bWinExec\b|\bCreateProcess[AW]?\b|\bShellExecute[AW]?\b"
    r"|\bfork\s*\(|\bsocket\s*\("
)


def _cgo_constructor(rel: str, tree: SourceTree) -> list[StaticFinding]:
    if rel.endswith(".go"):
        head = tree.read(rel)
        if head is None or 'import "C"' not in head:
            return []
        text = head
    else:
        text = tree.read(rel)
        if text is None:
            return [StaticFinding(rule=R_UNREADABLE, cwe="CWE-693", severity=Severity.MEDIUM,
                                  location=f"{rel}:1", detail="C 파일을 읽지 못했다")]
    m = _CTOR.search(text)
    if not m:
        return []
    window = text[m.start():m.start() + 1500]
    danger = _C_DANGER.search(window)
    line = _line_of(text, m.start())
    if danger:
        return [StaticFinding(
            rule=R_CGO_CTOR, cwe="CWE-94", severity=Severity.HIGH, location=f"{rel}:{line}",
            detail=f"C 생성자(프로그램 로드 때 자동 실행) 근처에서 {danger.group(0).strip()} 를 부른다")]
    return [StaticFinding(
        rule=R_CGO_CTOR, cwe="CWE-94", severity=Severity.MEDIUM, location=f"{rel}:{line}",
        detail="C 생성자/DllMain — 프로그램 로드 때 자동 실행된다 (무엇을 하는지 확인 필요)")]


_CGO_DIRECTIVE = re.compile(r"^[ \t]*(?://|/\*|\*)?[ \t]*#cgo\s+([^:\n]*):([^\n]*)", re.MULTILINE)
_GENERATE = re.compile(r"^[ \t]*//go:generate[ \t]+(.+)$", re.MULTILINE)
_FLAG_PLUGIN = re.compile(r"-fplugin|-Xclang|-wrapper|-specs=|-fuse-ld=|-fuse-linker-plugin")


def _directive_findings(rel: str, text: str) -> list[StaticFinding]:
    out: list[StaticFinding] = []
    for m in _CGO_DIRECTIVE.finditer(text):
        flags = m.group(2)
        line = _line_of(text, m.start())
        if _DOWNLOADER.search(flags) or _SUSPICIOUS_CMD.search(flags):
            out.append(StaticFinding(
                rule=R_CGO_FLAGS, cwe="CWE-78", severity=Severity.HIGH, location=f"{rel}:{line}",
                detail=f"#cgo 지시문이 명령을 끌어들인다: {flags.strip()[:80]}"))
        elif _FLAG_PLUGIN.search(flags) or re.search(r"`|\$\(", flags):
            out.append(StaticFinding(
                rule=R_CGO_FLAGS, cwe="CWE-427", severity=Severity.MEDIUM, location=f"{rel}:{line}",
                detail=f"#cgo 지시문에 컴파일러·링커 동작을 바꾸는 옵션: {flags.strip()[:80]}"))
    for m in _GENERATE.finditer(text):
        cmd = m.group(1)
        if _DOWNLOADER.search(cmd) or _SUSPICIOUS_CMD.search(cmd):
            out.append(StaticFinding(
                rule=R_GENERATE, cwe="CWE-78", severity=Severity.MEDIUM,
                location=f"{rel}:{_line_of(text, m.start())}",
                detail=f"//go:generate 가 네트워크·수상한 명령을 실행한다 (go generate 를 직접 돌릴 때만 "
                       f"실행됨): {cmd.strip()[:80]}"))
    return out

# ruff: noqa: E501
