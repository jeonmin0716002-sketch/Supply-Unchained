"""npm 패키지 정적분석 규칙 — "언제 돌고 무엇을 하느냐"로 본다 (파이썬 엔진과 같은 원칙).

자동 실행 경로는 둘이다:

* **설치 시점** — ``package.json`` 의 ``preinstall``·``install``·``postinstall`` 이 부르는
  명령과 그 명령이 실행하는 패키지 안 JS 파일(+ 그 파일이 ``require('./x')`` 하는 파일) 전체.
  루트 ``binding.gyp`` 는 install 스크립트가 없으면 npm 이 ``node-gyp rebuild`` 로 돌린다.
* **로드 시점** — ``main``/``exports`` 진입점을 ``require`` 하는 순간 도는 코드: 최상단과
  거기서 부르는 같은 파일 함수·IIFE·바로 넘긴 콜백 (jslex 의 실행 범위), 그리고 그 범위가
  ``require('./x')`` 하는 파일의 같은 범위.

HIGH 는 그 범위 안의 공급망 공격 특유 조합에만 낸다 (docs/design/multi-ecosystem.md §2.3):

* 네트워크 전송 + (호스트 정보 수집 | 환경변수 통째 | 비밀 파일 읽기 | 수상한 목적지)
* 수상한 명령을 담은 프로세스 실행 (curl|sh, PowerShell, /dev/tcp ...)
* 디코딩한 값을 eval·Function·vm 으로 실행
* 설치 시점 파일의 javascript-obfuscator 형태
* 토큰이 박힌 Discord 웹훅·Telegram 봇 주소 (어디에 있든)

**install 스크립트 자체는 HIGH 가 아니다.** node-gyp 빌드, husky, esbuild·sharp 같은 바이너리
내려받기는 정상이다 — esbuild 의 install.js 는 설치 시점에 https.get 으로 바이너리를 받는다.
그래서 설치 시점 네트워크 호출 "만"은 MEDIUM(정황)이다. 실측 근거는 docs/eval/npm.md.
"""

from __future__ import annotations

import contextlib
import json
import re
import shlex
from collections.abc import Iterable
from pathlib import PurePosixPath

from api.schemas import Severity, StaticFinding
from ecosystems.npm import jslex
from engine.rules.base import SourceTree

# ── 규칙 ID ───────────────────────────────────────────────────────

RULE_INSTALL_SCRIPT = "npm-install-script"
RULE_INSTALL_SHELL = "npm-install-shell"
RULE_INSTALL_EXEC = "npm-install-time-exec"
RULE_LOAD_EXEC = "npm-load-time-exec"
RULE_INSTALL_NETWORK = "npm-install-network"
RULE_DECODE_EXEC = "npm-decode-exec"
RULE_OBFUSCATED = "npm-obfuscated"
RULE_EXFIL = "npm-exfil-endpoint"
RULE_SUSPICIOUS_HOST = "npm-suspicious-host"
RULE_SECRET_READ = "npm-secret-read"
RULE_GYP = "npm-binding-gyp"
RULE_MINIFIED = "npm-minified-entry"
RULE_PACKAGE_ODDITY = "npm-package-oddity"
RULE_UNREADABLE = "npm-unreadable"
RULE_REMOTE_DEP = "npm-remote-dependency"

RULE_CWES: dict[str, frozenset[str]] = {
    RULE_INSTALL_SCRIPT: frozenset({"CWE-829"}),
    RULE_INSTALL_SHELL: frozenset({"CWE-506", "CWE-78"}),
    RULE_INSTALL_EXEC: frozenset({"CWE-506"}),
    RULE_LOAD_EXEC: frozenset({"CWE-506"}),
    RULE_INSTALL_NETWORK: frozenset({"CWE-829"}),
    RULE_DECODE_EXEC: frozenset({"CWE-94"}),
    RULE_OBFUSCATED: frozenset({"CWE-506"}),
    RULE_EXFIL: frozenset({"CWE-200"}),
    RULE_SUSPICIOUS_HOST: frozenset({"CWE-200"}),
    RULE_SECRET_READ: frozenset({"CWE-522"}),
    RULE_GYP: frozenset({"CWE-829", "CWE-78"}),
    RULE_MINIFIED: frozenset({"CWE-506"}),
    RULE_PACKAGE_ODDITY: frozenset({"CWE-829"}),
    RULE_UNREADABLE: frozenset({"CWE-693"}),
    RULE_REMOTE_DEP: frozenset({"CWE-829"}),
}

_JS_SUFFIXES = (".js", ".cjs", ".mjs")
#: 파일 하나에서 분석할 최대 크기 — 렉서 상한과 같다
_MAX_FILE = jslex.MAX_LEX_CHARS
#: require 를 따라갈 최대 파일 수 — 진입점이 수백 파일을 끌어오는 큰 라이브러리 대비
_MAX_FOLLOW = 40

_LIFECYCLE = ("preinstall", "install", "postinstall")

# ── 판정 재료 ─────────────────────────────────────────────────────

#: 실제로 패킷을 내보내는 호출. 모듈의 아무 함수가 아니다 (파이썬 엔진 실측: Timeout()·
#: Session() 같은 생성자는 통신하지 않는다).
_NET_METHODS = {
    "http": {"request", "get"},
    "https": {"request", "get"},
    "http2": {"connect"},
    "net": {"connect", "createConnection", "Socket"},
    "tls": {"connect"},
    "dgram": {"createSocket"},
    "axios": {"get", "post", "put", "patch", "request", "delete", "head", "create"},
    "got": {"get", "post", "put", "patch", "stream"},
    "request": {"get", "post", "put"},
    "needle": {"get", "post", "request"},
    "superagent": {"get", "post", "put"},
    "node-fetch": set(),
    "undici": {"request", "fetch", "stream"},
    "ws": set(),
}
#: 모듈 자체를 호출하면 요청이 나가는 것 (axios(cfg), got(url), require('node-fetch')(url))
_NET_CALLABLE = {"axios", "got", "request", "needle", "superagent", "node-fetch", "fetch",
                 "XMLHttpRequest", "WebSocket", "ws", "undici.fetch"}

_DNS_FUNCS = {"lookup", "resolve", "resolve4", "resolve6", "resolveTxt", "resolveCname",
              "resolveAny", "resolveMx", "resolveNs", "resolveSrv", "reverse"}

#: 호스트 지문 — 의존성 혼동(dependency confusion) 샘플이 보내는 값. os.platform()/arch()
#: 는 없다: 바이너리를 고르는 정상 설치 스크립트(esbuild·sharp)가 늘 쓴다.
_HARVEST = {"os.hostname", "os.userInfo", "os.networkInterfaces", "os.homedir", "os.release",
            "os.cpus", "os.totalmem"}

_FS_READ = {"readFileSync", "readFile", "createReadStream", "readdirSync", "readdir"}

_SPAWN = {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"}
#: 셸 자체를 띄우는 인자 — 소켓과 같이 있으면 리버스 셸 (실측: reve-wix-test 의
#: net.Socket + spawn('/bin/sh') + pipe)
_SHELLS = {"/bin/sh", "/bin/bash", "sh", "bash", "/bin/zsh", "cmd.exe", "cmd",
           "powershell.exe", "powershell", "pwsh"}
#: 문자열로 숨겼을 때 의미가 있는 API·모듈 이름 — 이것을 hex·base64·문자 코드로 감추는 것은
#: 정적 탐지를 피하려는 것 말고 이유가 없다 (실측: @hopper-b2b/utilities 의 metrics.js 는
#: 'os'·'https'·'userInfo'·'hostname' 을 전부 hex 로 감췄다)
_SENSITIVE_NAMES = {"child_process", "exec", "execSync", "spawn", "eval", "http", "https", "net",
                    "dns", "os", "hostname", "userInfo", "homedir", "networkInterfaces",
                    "request", "readFileSync", "require", "Function", "env", "writeFileSync",
                    "fetch", "POST", "username", "platform"}

#: 설치 시점에 정상 패키지가 돌릴 이유가 없는 명령·옵션 (engine/rules/install_time.py 의 목록
#: 에 npm 쪽 실측 형태를 더했다)
_SUSPICIOUS_CMD = re.compile(
    r"powershell|pwsh|-enc(?:odedcommand)?\b|windowstyle\s+hidden|-w\s+hidden|mshta|certutil"
    r"|bitsadmin|rundll32|regsvr32|invoke-webrequest|\biwr\b|invoke-expression|\biex\b"
    r"|\bcurl\b|\bwget\b|/dev/tcp|\bnc\s+-e|\bncat\b|base64\s+(?:-d|--decode)"
    r"|\|\s*(?:ba|z)?sh\b|schtasks|crontab|osascript|chmod\s+\+x\s+/tmp|/tmp/\S+\s*&"
    r"|\bnslookup\b|\bdig\b\s|\bwhoami\b|\bhostname\b|/etc/passwd|\buname\s+-a"
    r"|\bping\s+-[cn]\b",
    re.IGNORECASE,
)

#: 비밀이 있는 경로 — 이것을 읽어 내보내는 것이 자격증명 탈취다
_SECRET_PATH = re.compile(
    r"\.npmrc|\.ssh\b|id_rsa|id_ed25519|\.aws[/\\]credentials|\.git-credentials|\.gitconfig"
    r"|\.docker[/\\]config\.json|\.kube[/\\]config|\.netrc|\.bash_history|\.zsh_history"
    r"|/etc/passwd|/etc/shadow|Local Storage[/\\]leveldb|Login Data|Local State"
    r"|\bCookies\b|discord(?:canary|ptb)?[/\\]|Exodus|Electrum|MetaMask"
    r"|nkbihfbeogaeaoehlefnkodbefgpgknn|\bkeychain\b|wallet\.dat|\.config[/\\]solana"
    r"|\.ethereum[/\\]keystore",
    re.IGNORECASE,
)

_EXFIL_PATTERNS = (
    ("Discord 웹훅", re.compile(r"discord(?:app)?\.com/api/webhooks/\d{15,}/[\w-]{20,}")),
    ("Telegram 봇 토큰", re.compile(r"api\.telegram\.org/bot\d{6,}:[\w-]{30,}")),
)

#: 대역외(OAST) 수신기·요청 수집기 — 침투 테스트·버그바운티와 의존성 혼동 공격이 데이터를
#: 받는 곳. 정상 패키지가 설치·로드 시점에 이곳으로 보낼 이유가 없다.
_OAST_HOST = re.compile(
    r"(?:oastify\.com|burpcollaborator\.net|interact\.sh|interactsh|oast\.(?:fun|pro|live|site|"
    r"online|me)|dnslog\.cn|ceye\.io|canarytokens\.com|pipedream\.net|webhook\.site"
    r"|requestbin|requestcatcher\.com|beeceptor\.com|ngrok(?:-free)?\.(?:io|app)"
    r"|trycloudflare\.com|serveo\.net|\.loca\.lt|bind9-or-callback|eo[0-9a-z]{10,}\.m\.pipedream"
    # AWS Lambda 함수 URL — 실측 샘플(@web-kit-package/grab-login)의 수신처. 설치 시점에 정상
    # 패키지가 남의 Lambda 로 POST 할 이유가 없다
    r"|lambda-url\.[a-z0-9-]+\.on\.aws)",
    re.IGNORECASE,
)
#: 붙여넣기·파일 공유·IP 조회 — 정상 코드에도 가끔 있어 단독으로는 정황(MEDIUM)
_CONTEXT_HOST = re.compile(
    r"pastebin\.com|paste\.ee|hastebin|transfer\.sh|file\.io|anonfiles|api\.ipify\.org"
    r"|ipinfo\.io|ifconfig\.me|icanhazip\.com|checkip\.amazonaws\.com|ip-api\.com",
    re.IGNORECASE,
)
_BARE_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IP_URL = re.compile(r"(?:https?|wss?|tcp)://(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?:/|$)")
_PRIVATE_IP = re.compile(r"^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.)")

_B64_LONG = re.compile(r"^[A-Za-z0-9+/]{200,}={0,2}$")
_HEX_LONG = re.compile(r"^(?:[0-9a-fA-F]{2}){150,}$")
_OBF_ID = re.compile(r"^_0x[0-9a-f]{4,}$")

#: 정상 install 스크립트로 흔한 명령 (상위 패키지 실측) — 출처를 남겨 분류만 한다
_KNOWN_BUILDERS = re.compile(
    r"^(?:node-gyp(?:-build)?|prebuild-install|node-pre-gyp|husky|is-ci|patch-package|"
    r"opencollective(?:-postinstall)?|cmake-js|napi-postinstall|electron-rebuild|tsc|"
    r"ngcc|lerna|npm|yarn|pnpm|npx|echo|exit|true|cd|node-gyp-build-optional-packages)$"
)


# ── 공용 ──────────────────────────────────────────────────────────

def _finding(rule: str, severity: Severity, location: str, detail: str,
             cwe: str | None = None) -> StaticFinding:
    return StaticFinding(rule=rule, cwe=cwe or sorted(RULE_CWES[rule])[0], severity=severity,
                         location=location, detail=detail[:500])


def _package_root(files: list[str]) -> str:
    """가장 얕은 package.json 의 디렉터리 ("" 또는 "package"). 타르볼 최상위는 보통
    ``package/`` 지만 옛 패키지는 다른 이름(``node-uuid/``)을 쓴다."""
    cands = [f for f in files if PurePosixPath(f).name == "package.json"
             and "node_modules" not in f]
    if not cands:
        return ""
    best = min(cands, key=lambda f: (f.count("/"), f))
    parent = PurePosixPath(best).parent.as_posix()
    return "" if parent == "." else parent


def _join(root: str, rel: str) -> str:
    p = PurePosixPath(root) / rel if root else PurePosixPath(rel)
    parts: list[str] = []
    for part in p.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/".join(parts)


def _resolve_module(tree_files: set[str], base_dir: str, spec: str) -> str | None:
    """``require('./lib/x')`` → 실제 파일 (확장자·index.js 보완, Node 해석 순서)."""
    target = _join(base_dir, spec)
    for cand in (target, *(target + s for s in (*_JS_SUFFIXES, ".json")),
                 *(f"{target}/index{s}" for s in _JS_SUFFIXES)):
        if cand in tree_files:
            return cand
    return None


def _is_executed_or_all(mod: jslex.Module, i: int, whole: bool) -> bool:
    return whole or mod.is_executed(i)


# ── 파일 하나 분석 ────────────────────────────────────────────────

class _FileFacts:
    """한 파일의 범위 안에서 모은 사실. 규칙 조합은 _judge 가 한다."""

    def __init__(self) -> None:
        self.network: list[tuple[int, str]] = []
        self.dns_dynamic: list[tuple[int, str]] = []
        self.harvest: list[tuple[int, str]] = []
        self.secret_reads: list[tuple[int, str]] = []
        self.env_dump: list[int] = []
        self.oast: list[tuple[int, str]] = []
        self.ip_dest: list[tuple[int, str]] = []
        self.spawn_bad: list[tuple[int, str]] = []
        self.decode_exec: list[tuple[int, str]] = []
        self.shell_spawn: list[tuple[int, str]] = []
        self.eval_dynamic: list[tuple[int, str]] = []
        self.decoded: list[str] = []
        self.background: list[int] = []
        self.js_refs: list[str] = []


def _net_kind(name: str) -> str | None:
    parts = name.split(".")
    mod = parts[0]
    if name in _NET_CALLABLE or (len(parts) == 1 and mod in _NET_METHODS and mod != "http"):
        return name
    if mod == "dns" and parts[-1] in _DNS_FUNCS:
        return name
    if len(parts) >= 2 and parts[-1] in _NET_METHODS.get(mod, ()):
        return name
    if len(parts) == 2 and mod == "globalThis" and parts[1] == "fetch":
        return name
    return None


def _decoder_in(mod: jslex.Module, lo: int, hi: int, tainted: set[str]) -> str | None:
    toks = mod.tokens
    for k in range(lo, hi):
        t = toks[k]
        if t.kind == "id":
            if t.value == "atob" and k + 1 < hi and toks[k + 1].value == "(":
                return "atob()"
            if t.value == "fromCharCode":
                return "String.fromCharCode()"
            if t.value in tainted:
                return f"디코딩된 값 {t.value}"
            if t.value == "from" and k >= 2 and toks[k - 2].value == "Buffer":
                close = mod.pairs.get(k + 1)
                if close is not None:
                    enc = [toks[j].value for j in range(k + 2, close)
                           if toks[j].kind == "str"]
                    codec = next((e for e in enc if e in ("base64", "hex", "base64url")), None)
                    if codec:
                        return f"Buffer.from(..., '{codec}')"
        elif t.kind in ("str", "tpl"):
            if t.escapes >= 40:
                return f"이스케이프 {t.escapes}개 문자열"
            if _B64_LONG.match(t.value) or _HEX_LONG.match(t.value):
                return f"인코딩된 긴 문자열({len(t.value)}자)"
    return None


def _tainted_names(mod: jslex.Module) -> set[str]:
    """``const x = Buffer.from(s, 'base64').toString()`` 처럼 디코딩 결과를 받은 변수."""
    toks, out = mod.tokens, set()
    for i in range(1, len(toks) - 1):
        if toks[i].value == "=" and toks[i].kind == "punct" and toks[i - 1].kind == "id":
            # 같은 문장 끝(; 또는 다음 선언)까지
            j = i + 1
            while j < len(toks) and toks[j].value not in (";",) and j - i < 200:
                if toks[j].value in ("(", "[", "{") and j in mod.pairs:
                    j = mod.pairs[j] + 1
                    continue
                if toks[j].kind == "id" and toks[j].value in ("const", "let", "var"):
                    break
                j += 1
            if _decoder_in(mod, i + 1, j, out):
                out.add(toks[i - 1].value)
    return out


_EXEC_SINKS = {"eval", "Function", "vm.runInThisContext", "vm.runInNewContext",
               "vm.runInContext", "vm.Script", "vm.compileFunction", "module._compile",
               "window.eval", "global.eval", "globalThis.eval"}


def _collect(mod: jslex.Module, whole: bool) -> _FileFacts:
    facts = _FileFacts()
    toks = mod.tokens
    tainted = _tainted_names(mod)
    has_spawn = False
    for c in jslex.calls(mod, executed_only=False):
        # 디코딩해 쓰는 문자열은 실행 범위와 무관하게 모은다 — 회전 함수·디코더는 보통 함수
        # 본문 안에 있다
        args = jslex.arg_tokens(mod, c)
        if c.name in ("Buffer.from", "atob") and args and args[0].kind == "str":
            enc = [t.value for t in args[1:] if t.kind == "str"]
            raw = args[0].value
            try:
                if c.name == "atob" or enc[:1] in (["base64"], ["base64url"]):
                    import base64
                    facts.decoded.append(base64.b64decode(raw + "=" * (-len(raw) % 4),
                                                          validate=False).decode("utf-8"))
                elif enc[:1] == ["hex"]:
                    facts.decoded.append(bytes.fromhex(raw).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                pass
        elif c.name == "String.fromCharCode" and args and all(
            t.kind == "num" or t.value == "," for t in args
        ):
            with contextlib.suppress(ValueError, OverflowError):
                facts.decoded.append("".join(chr(int(t.value, 0) if t.value[:2].lower() in (
                    "0x", "0o", "0b") else int(t.value)) for t in args if t.kind == "num"))
    for c in jslex.calls(mod, executed_only=not whole):
        name = c.name
        last = name.rsplit(".", 1)[-1]
        strs = jslex.string_values(mod, c.open + 1, c.close)
        if last in ("hostname", "userInfo", "networkInterfaces") and "." in name:
            # 받는 쪽 이름을 몰라도(동적 require) 이 세 메서드를 *호출*하는 것은 os 뿐이다
            facts.harvest.append((c.line, name + "()"))
        net = _net_kind(name)
        if net:
            facts.network.append((c.line, net))
            if name.startswith("dns."):
                # 템플릿·연결로 만든 질의 이름 — DNS 유출의 전형
                args = jslex.arg_tokens(mod, c)
                if any(t.kind == "tpl" or t.value == "+" or t.kind == "id" for t in args[:12]):
                    facts.dns_dynamic.append((c.line, name))
            for s in strs:
                if (m := _IP_URL.search(s)) and not _PRIVATE_IP.match(m.group(1)):
                    facts.ip_dest.append((c.line, m.group(0)))
        if name in _HARVEST or (name.startswith("os.") and last in
                                {n.split(".")[1] for n in _HARVEST}):
            facts.harvest.append((c.line, name + "()"))
        if last in _FS_READ and (name.startswith(("fs.", "fs/promises.")) or name == last):
            for s in strs:
                if _SECRET_PATH.search(s):
                    facts.secret_reads.append((c.line, s[:80]))
        if last in _SPAWN and (name in _SPAWN
                               or name.startswith(("child_process.", "shelljs.", "execa"))):
            has_spawn = True
            shell = next((s for s in strs if s.strip() in _SHELLS), None)
            if shell is not None:
                facts.shell_spawn.append((c.line, f"{name}('{shell}')"))
            for s in strs:
                if s.endswith(_JS_SUFFIXES):
                    facts.js_refs.append(s)
            for s in strs:
                if m := _SUSPICIOUS_CMD.search(s):
                    facts.spawn_bad.append((c.line, f"{name}() — '{m.group(0)}'"))
                    break
        if name in ("shell.exec", "shelljs.exec", "execa", "execa.command", "execaSync"):
            for s in strs:
                if m := _SUSPICIOUS_CMD.search(s):
                    facts.spawn_bad.append((c.line, f"{name}() — '{m.group(0)}'"))
                    break
        if name in _EXEC_SINKS or (name == "setTimeout" and strs and c.open + 1 < c.close
                                   and toks[c.open + 1].kind == "str"):
            dec = _decoder_in(mod, c.open + 1, c.close, tainted)
            if dec:
                facts.decode_exec.append((c.line, f"{name}({dec})"))
            elif any(t.kind == "id" for t in jslex.arg_tokens(mod, c)):
                facts.eval_dynamic.append((c.line, f"{name}()"))
    for i, t in enumerate(toks):
        if not _is_executed_or_all(mod, i, whole):
            continue
        if t.kind == "id" and t.value == "env" and i >= 2 and toks[i - 1].value == "." and \
                toks[i - 2].value == "process":
            nxt = toks[i + 1].value if i + 1 < len(toks) else ""
            if nxt not in (".", "[", "?.", "=", "&&", "||", "??") and _serialized(mod, i):
                facts.env_dump.append(t.line)
        elif t.kind == "id" and t.value == "detached" and i + 2 < len(toks) and \
                toks[i + 1].value == ":" and toks[i + 2].value == "true":
            facts.background.append(t.line)
        elif t.kind in ("str", "tpl"):
            if m := _OAST_HOST.search(t.value):
                facts.oast.append((t.line, m.group(0)))
            v = t.value.strip()
            if _BARE_IP.match(v) and not _PRIVATE_IP.match(v) and all(
                int(x) < 256 for x in v.split(".")
            ):
                facts.ip_dest.append((t.line, v))
            elif (m := _IP_URL.search(v)) and not _PRIVATE_IP.match(m.group(1)):
                facts.ip_dest.append((t.line, m.group(0)))
            if whole and has_spawn and (m := _SUSPICIOUS_CMD.search(t.value)) and not \
                    facts.spawn_bad:
                # 설치 시점 파일 전체: 명령 문자열을 도우미 함수로 넘겨 실행하는 경우
                # (실측: strapi-plugin-blurhash 의 run('curl -sk ...'))
                facts.spawn_bad.append((t.line, f"프로세스 실행 + 명령 문자열 '{m.group(0)}'"))
            if _SECRET_PATH.search(t.value) and t.kind == "str" and len(t.value) < 200:
                # path.join(os.homedir(), '.npmrc') 처럼 읽기 호출 인자 밖에서 경로를 만드는 경우
                facts.secret_reads.append((t.line, t.value[:80])) if _secret_used(mod, i) else None
    # 계산된 속성으로 부르는 경우: os['hostname']() · _0x1[dec('686f...')]() — 이름이 문자열로만
    # 남는다. os 를 쓰는 파일에서 그 이름이 문자열(또는 디코딩된 문자열)로 있으면 수집으로 본다.
    uses_os = "os" in mod.aliases.values() or "os" in facts.decoded or any(
        v.startswith("os.") for v in mod.aliases.values())
    pool = {t.value for t in toks if t.kind == "str"} | set(facts.decoded)
    if uses_os:
        for name in ("hostname", "userInfo", "networkInterfaces"):
            if name in pool:
                facts.harvest.append((1, f"os['{name}']"))
    if facts.decoded and not facts.network:
        net_mods = {"http", "https", "net", "dns", "tls", "dgram"} & set(facts.decoded)
        if net_mods and (uses_os or "request" in facts.decoded or "get" in facts.decoded):
            facts.network.append((1, f"require('{sorted(net_mods)[0]}') (숨긴 이름)"))
    return facts


#: process.env 를 통째로 문자열·바이트로 만드는 호출. ``spawn(cmd, {env: process.env})`` 처럼
#: 자식 프로세스에 넘기는 것은 정상이다 (실측 오탐: esbuild 의 install.js).
_SERIALIZERS = {"stringify", "keys", "entries", "values", "from", "btoa", "write", "send",
                "end", "encode", "post", "put"}


def _serialized(mod: jslex.Module, i: int) -> bool:
    """i 번째 토큰(process.env 의 env)이 직렬화 호출의 인자 안에 있는가 (가장 가까운 호출만)."""
    toks, pairs = mod.tokens, mod.pairs
    depth_limit = 0
    k = i - 3
    while k >= 0 and depth_limit < 400:
        depth_limit += 1
        t = toks[k]
        if t.kind == "punct" and t.value == "(" and k in pairs and pairs[k] > i:
            if k >= 1 and toks[k - 1].kind == "id":
                return toks[k - 1].value in _SERIALIZERS
            return False
        if t.kind == "punct" and t.value in (";", "{") and not (k in pairs and pairs[k] > i):
            return False
        k -= 1
    return False


def _install_js_refs(mod: jslex.Module) -> list[str]:
    """프로세스를 띄우는 파일 안의 ``'*.js'`` 문자열 — 자식 프로세스로 실행될 수 있는 파일."""
    names = {c.name.rsplit(".", 1)[-1] for c in jslex.calls(mod, executed_only=False)}
    if not names & _SPAWN:
        return []
    return [t.value.lstrip("/") for t in mod.tokens
            if t.kind == "str" and t.value.endswith(_JS_SUFFIXES) and "/" not in t.value[:1]
            and len(t.value) < 120 and " " not in t.value]


def _secret_used(mod: jslex.Module, i: int) -> bool:
    """비밀 경로 문자열 근처(같은 줄 ±2)에 파일 읽기 호출이 있는가."""
    line = mod.tokens[i].line
    lo, hi = max(0, i - 40), min(len(mod.tokens), i + 40)
    return any(
        t.kind == "id" and t.value in _FS_READ and abs(t.line - line) <= 2
        for t in mod.tokens[lo:hi]
    )


def _obfuscation(mod: jslex.Module, *, install: bool = False) -> str | None:
    """javascript-obfuscator 형태 — ``_0x`` 식별자 범람, 문자열 배열 회전, 긴 문자 코드 배열."""
    toks = mod.tokens
    ids = [t for t in toks if t.kind == "id"]
    if not ids:
        return None
    obf = sum(1 for t in ids if _OBF_ID.match(t.value))
    if obf >= 30 and obf / len(ids) >= 0.15:
        return f"_0x 식별자 {obf}개 ({obf * 100 // len(ids)}%)"
    # 문자열 배열 회전: while(!![]) { ... push(...shift()) }
    for i in range(len(toks) - 6):
        if (toks[i].value == "while" and toks[i + 1].value == "(" and toks[i + 2].value == "!"
                and toks[i + 3].value == "!" and toks[i + 4].value == "["
                and toks[i + 5].value == "]"):
            window = {t.value for t in toks[i:i + 120]}
            if {"push", "shift"} <= window:
                return "문자열 배열 회전(while(!![]) … push/shift)"
    # 긴 문자 코드 배열: [104,116,116,112,...] 다음에 fromCharCode
    # 출력 가능한 ASCII 범위의 수만 센다 — 유니코드 식별자 표(acorn·typescript 의 큰 수 배열)는
    # 문자 코드 페이로드가 아니다 (실측 오탐)
    run = best = 0
    for t in toks:
        if t.kind == "num":
            try:
                v = int(t.value, 0) if t.value[:2].lower() in ("0x", "0o", "0b") else int(t.value)
            except ValueError:
                v = -1
            if 9 <= v <= 126:
                run += 1
                best = max(best, run)
            else:
                run = 0
        elif t.value != ",":
            run = 0
    if best >= 80 and any(t.value == "fromCharCode" for t in ids):
        return f"문자 코드 배열({best}개) + String.fromCharCode"
    esc = max((t.escapes for t in toks if t.kind in ("str", "tpl")), default=0)
    # 긴 이스케이프 문자열만으로는 설치 시점 파일에서만 본다 — 정상 라이브러리의 데이터 표
    # (entities 의 HTML 엔티티 표, prettier·jiti 번들)가 같은 모양이다 (실측 오탐)
    if esc >= 200 and install:
        return f"이스케이프 {esc}개짜리 문자열"
    return None


def _judge(facts: _FileFacts, rel: str, scope: str, when: str) -> list[StaticFinding]:
    """scope: install | load | other."""
    out: list[StaticFinding] = []
    rule = RULE_INSTALL_EXEC if scope == "install" else RULE_LOAD_EXEC
    auto = scope in ("install", "load")
    if auto and facts.network:
        line, what = facts.network[0]
        why = []
        if facts.harvest:
            why.append("호스트 정보 " + ", ".join(sorted({h for _, h in facts.harvest})[:3]))
        if facts.env_dump:
            why.append("환경변수 전체(process.env)")
        if facts.secret_reads:
            why.append(f"비밀 파일 '{facts.secret_reads[0][1]}'")
        if facts.oast:
            why.append(f"대역외 수신 주소 {facts.oast[0][1]}")
        if facts.ip_dest:
            why.append(f"IP 직접 접속 {facts.ip_dest[0][1]}")
        if facts.dns_dynamic and facts.harvest:
            why.append("DNS 질의 이름에 실어 보냄")
        if facts.eval_dynamic:
            why.append(f"받은 값을 실행 {facts.eval_dynamic[0][1]}")
        if facts.shell_spawn:
            why.append(f"셸 실행 {facts.shell_spawn[0][1]} — 리버스 셸 형태")
        if why:
            out.append(_finding(rule, Severity.HIGH, f"{rel}:{line}",
                                f"{when} 네트워크 전송 {what}() + " + " · ".join(why)))
        elif scope == "install":
            out.append(_finding(RULE_INSTALL_NETWORK, Severity.MEDIUM, f"{rel}:{line}",
                                f"{when} 네트워크 호출 {what}() — 바이너리 내려받기일 수도, "
                                "유출일 수도 있다"))
    if auto and not facts.network and facts.secret_reads and (facts.harvest or facts.env_dump):
        line, path = facts.secret_reads[0]
        out.append(_finding(RULE_SECRET_READ, Severity.MEDIUM, f"{rel}:{line}",
                            f"{when} 비밀 파일 '{path}' 읽기"))
    hidden = sorted(_SENSITIVE_NAMES & set(facts.decoded))
    if len(hidden) >= 2:
        sev = Severity.HIGH if scope == "install" else Severity.MEDIUM
        out.append(_finding(RULE_OBFUSCATED, sev, f"{rel}:1",
                            f"{when} 코드가 API·모듈 이름을 인코딩해 숨김: "
                            + ", ".join(hidden[:6])))
    if scope == "install" and facts.background and facts.js_refs:
        loc = f"{rel}:{facts.background[0]}"
        out.append(_finding(RULE_INSTALL_SCRIPT, Severity.MEDIUM, loc,
                            f"{when} 코드가 {facts.js_refs[0]} 를 분리된 백그라운드 프로세스로 "
                            "띄움 — 설치가 끝난 뒤에도 돈다"))
    if facts.spawn_bad:
        line, what = facts.spawn_bad[0]
        sev = Severity.HIGH if auto else Severity.MEDIUM
        out.append(_finding(rule if auto else RULE_LOAD_EXEC, sev, f"{rel}:{line}",
                            f"{when} 수상한 명령 실행 {what}", cwe="CWE-78"))
    if facts.decode_exec:
        line, what = facts.decode_exec[0]
        sev = Severity.HIGH if auto else Severity.MEDIUM
        out.append(_finding(RULE_DECODE_EXEC, sev, f"{rel}:{line}",
                            f"{when} 디코딩한 코드를 실행: {what}"))
    if not auto and facts.oast:
        line, host = facts.oast[0]
        out.append(_finding(RULE_SUSPICIOUS_HOST, Severity.MEDIUM, f"{rel}:{line}",
                            f"대역외 수신·요청 수집 주소 {host}"))
    return out


def _analyze_js(text: str, rel: str, scope: str, when: str, *, whole: bool,
                entry: bool = False) -> tuple[list[StaticFinding], jslex.Module]:
    mod = jslex.parse(text)
    out = _judge(_collect(mod, whole), rel, scope, when)
    if (obf := _obfuscation(mod, install=scope == "install")) is not None:
        sev = Severity.HIGH if scope == "install" else Severity.MEDIUM
        out.append(_finding(RULE_OBFUSCATED, sev, f"{rel}:1", f"{when} 난독화: {obf}"))
    return out, mod


def _endpoint_findings(text: str, rel: str) -> Iterable[StaticFinding]:
    for label, pattern in _EXFIL_PATTERNS:
        m = pattern.search(text)
        if m:
            line = text.count("\n", 0, m.start()) + 1
            yield _finding(RULE_EXFIL, Severity.HIGH, f"{rel}:{line}",
                           f"토큰이 포함된 {label} 주소가 코드에 박혀 있음 — 유출 채널의 전형")
    m = _CONTEXT_HOST.search(text)
    if m:
        line = text.count("\n", 0, m.start()) + 1
        yield _finding(RULE_SUSPICIOUS_HOST, Severity.LOW, f"{rel}:{line}",
                       f"붙여넣기·IP 조회 서비스 주소 {m.group(0)}")


# ── lifecycle 스크립트 ────────────────────────────────────────────

_SPLIT_OPS = re.compile(r"\s*(?:&&|\|\||;|\|)\s*")


def _split_commands(cmd: str) -> list[str]:
    return [c for c in _SPLIT_OPS.split(cmd) if c.strip()]


#: JS 파일을 실행하는 명령. bun·ts-node 도 실측 샘플(anyscale·js-logger-pack)이 쓴다.
_NODE_RUNNERS = {"node", "node.exe", "nodejs", "bun", "ts-node", "tsx", "deno"}


def _node_target(words: list[str]) -> tuple[str | None, str | None]:
    """``node [opts] file.js`` → (file, None), ``node -e "code"`` → (None, code)."""
    if not words or PurePosixPath(words[0]).name not in _NODE_RUNNERS:
        return None, None
    if words[0] == "deno" and len(words) > 1 and words[1] == "run":
        words = words[1:]
    k = 1
    while k < len(words):
        w = words[k]
        if w in ("-e", "--eval", "-p", "--print") and k + 1 < len(words):
            return None, words[k + 1]
        if w.startswith("-"):
            k += 2 if w in ("-r", "--require", "--import", "--loader") else 1
            continue
        return w, None
    return None, None


def _lifecycle(pkg: dict, root: str, files: set[str], rel_pkg: str
               ) -> tuple[list[StaticFinding], list[tuple[str, str]], list[str]]:
    """(findings, 설치 시점 파일 [(경로, 어느 스크립트)], 인라인 코드)."""
    out: list[StaticFinding] = []
    targets: list[tuple[str, str]] = []
    inline: list[str] = []
    scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
    for key in (*_LIFECYCLE, "prepare"):
        cmd = scripts.get(key)
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        auto = key in _LIFECYCLE
        loc = f"{rel_pkg}:1"
        bad = _SUSPICIOUS_CMD.search(cmd) or _OAST_HOST.search(cmd)
        if bad and auto:
            out.append(_finding(RULE_INSTALL_SHELL, Severity.HIGH, loc,
                                f"npm install 시 실행되는 {key} 스크립트에 수상한 명령 "
                                f"'{bad.group(0)}': {cmd[:200]}"))
        kinds = []
        for part in _split_commands(cmd):
            try:
                words = shlex.split(part)
            except ValueError:
                words = part.split()
            if not words:
                continue
            words = [w for w in words if "=" not in w or w.startswith("-")] or words
            file, code = _node_target(words)
            if code is not None:
                kinds.append("인라인 node -e")
                if auto:
                    inline.append(code)
            elif file is not None:
                resolved = _resolve_module(files, root, file if file.startswith(".")
                                           else "./" + file)
                kinds.append(f"번들 JS {file}" if resolved else f"JS {file}(패키지에 없음)")
                if resolved and auto:
                    targets.append((resolved, key))
            elif PurePosixPath(words[0]).name in ("sh", "bash", "zsh") and len(words) > 1:
                kinds.append(f"셸 스크립트 {words[1]}")
                sh = _join(root, words[1])
                if auto and sh in files:
                    targets.append((sh, key))
            elif _KNOWN_BUILDERS.match(PurePosixPath(words[0]).name):
                kinds.append(f"빌드 도구 {words[0]}")
            else:
                kinds.append(f"명령 {words[0]}")
        if not auto:
            continue  # prepare 는 git 의존성에서만 돈다 — 레지스트리 타르볼은 해당 없음
        sev = Severity.MEDIUM if any(k.startswith(("인라인", "셸")) for k in kinds) \
            else Severity.LOW
        out.append(_finding(RULE_INSTALL_SCRIPT, sev, loc,
                            f"{key} 스크립트 ({', '.join(kinds) or '?'}): {cmd[:200]}"))
    return out, targets, inline


_REGISTRY_HOSTS = ("registry.npmjs.org", "registry.yarnpkg.com", "npm.pkg.github.com")


def _remote_deps(pkg: dict, rel_pkg: str) -> list[StaticFinding]:
    """``dependencies`` 의 http(s) 타르볼 주소 — 레지스트리를 거치지 않는 코드.

    실측: 이번 튜닝 세트에서 놓친 샘플 6개(PhantomRaven 계열 — packages.storeartifact.com
    등)가 패키지 자체는 깨끗하고 악성 코드를 이 주소의 "의존성"으로 받아온다. npm 은 이것을
    설치 때 그대로 내려받아 그 안의 install 스크립트를 돌린다 — 스캐너가 볼 수 없는 코드다.
    git 의존성(github:…)은 정상 패키지에도 가끔 있어 정황으로만 남긴다.
    """
    out = []
    for field in ("dependencies", "optionalDependencies", "peerDependencies"):
        deps = pkg.get(field)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(spec, str):
                continue
            low = spec.strip().lower()
            if low.startswith(("http://", "https://")):
                host = re.sub(r"^https?://", "", low).split("/", 1)[0]
                if host.endswith(_REGISTRY_HOSTS):
                    continue
                out.append(_finding(RULE_REMOTE_DEP, Severity.HIGH, f"{rel_pkg}:1",
                                    f"{field} 의 {name} 를 레지스트리 밖 주소에서 받음: "
                                    f"{spec[:150]} — 설치 때 검사되지 않은 코드가 실행된다"))
            elif low.startswith(("git+", "git:", "github:", "gitlab:", "bitbucket:")) or (
                re.match(r"^[\w.-]+/[\w.-]+(?:#.*)?$", low) and not low.startswith(".")
            ):
                out.append(_finding(RULE_REMOTE_DEP, Severity.LOW, f"{rel_pkg}:1",
                                    f"{field} 의 {name} 가 git 저장소: {spec[:150]}"))
    return out


def _gyp(text: str, rel: str) -> list[StaticFinding]:
    """binding.gyp — ``<!(cmd)`` 명령 치환과 ``actions`` 는 node-gyp 가 빌드 때 실행한다."""
    out = []
    cmds = re.findall(r"<!@?\(([^)]*)\)", text)
    for cmd in cmds:
        if m := _SUSPICIOUS_CMD.search(cmd):
            out.append(_finding(RULE_GYP, Severity.HIGH, f"{rel}:1",
                                f"binding.gyp 명령 치환에 수상한 명령 '{m.group(0)}': {cmd[:200]}",
                                cwe="CWE-78"))
            return out
    if re.search(r"['\"]actions['\"]\s*:", text):
        out.append(_finding(RULE_GYP, Severity.MEDIUM, f"{rel}:1",
                            "binding.gyp 의 actions — node-gyp 빌드 때 임의 명령이 돈다"))
    return out


# ── 진입점 ────────────────────────────────────────────────────────

def _entry_points(pkg: dict, root: str, files: set[str]) -> list[str]:
    specs: list[str] = []
    main = pkg.get("main")
    specs.append(main if isinstance(main, str) and main else "index.js")
    exp = pkg.get("exports")

    def walk(v: object, depth: int = 0) -> None:
        if depth > 4:
            return
        if isinstance(v, str):
            specs.append(v)
        elif isinstance(v, dict):
            for key, sub in v.items():
                # "./package.json"·타입 선언은 실행 코드가 아니다
                if key in ("types", "typings") or key.endswith("package.json"):
                    continue
                if key.startswith(".") and key not in (".", "./"):
                    continue  # 하위 경로 export 는 사용자가 골라 require 할 때만
                walk(sub, depth + 1)
        elif isinstance(v, list):
            for sub in v:
                walk(sub, depth + 1)

    walk(exp)
    out = []
    for s in specs:
        r = _resolve_module(files, root, s if s.startswith(".") else "./" + s)
        if r and r.endswith(_JS_SUFFIXES) and r not in out:
            out.append(r)
    return out


def _is_bundle_path(rel: str) -> bool:
    p = PurePosixPath(rel)
    return p.name.endswith((".min.js", ".bundle.js")) or any(
        part in ("dist", "build", "umd", "bundle", "browser", "lib-cov", "vendor")
        for part in p.parts[:-1]
    )


# ── 진입 ──────────────────────────────────────────────────────────

_SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


def analyze_tree(tree: SourceTree, *, unreadable: list[str] | None = None
                 ) -> list[StaticFinding]:
    all_files = tree.files()
    files = set(all_files)
    root = _package_root(all_files)
    rel_pkg = _join(root, "package.json")
    out: list[StaticFinding] = []
    missing: list[str] = []

    def read(rel: str) -> str | None:
        text = tree.read(rel)
        if text is None:
            missing.append(rel)
        return text

    pkg: dict = {}
    if rel_pkg in files:
        raw = read(rel_pkg)
        try:
            loaded = json.loads(raw) if raw else {}
            pkg = loaded if isinstance(loaded, dict) else {}
        except ValueError:
            out.append(_finding(RULE_PACKAGE_ODDITY, Severity.LOW, f"{rel_pkg}:1",
                                "package.json 을 JSON 으로 읽을 수 없음"))

    # 1) lifecycle, 레지스트리 밖 의존성
    lf, targets, inline = _lifecycle(pkg, root, files, rel_pkg)
    out.extend(lf)
    out.extend(_remote_deps(pkg, rel_pkg))
    for code in inline:
        found, _ = _analyze_js(code, rel_pkg, "install", "npm install 시 node -e 가 실행하는",
                               whole=True)
        out.extend(found)

    analyzed: set[str] = set()
    # 2) 설치 시점 파일 — 파일 전체 + 상대 require 를 따라간다
    queue = list(targets)
    while queue and len(analyzed) < _MAX_FOLLOW:
        rel, key = queue.pop(0)
        if rel in analyzed:
            continue
        analyzed.add(rel)
        text = read(rel)
        if text is None:
            continue
        when = f"npm install 시 {key} 가 실행하는"
        if rel.endswith((".sh", ".bash")):
            if m := _SUSPICIOUS_CMD.search(text):
                line = text.count("\n", 0, m.start()) + 1
                out.append(_finding(RULE_INSTALL_SHELL, Severity.HIGH, f"{rel}:{line}",
                                    f"{when} 셸 스크립트에 수상한 명령 '{m.group(0)}'"))
            continue
        found, mod = _analyze_js(text, rel, "install", when, whole=True)
        out.extend(found)
        base = PurePosixPath(rel).parent.as_posix()
        specs = jslex.local_requires(mod, executed_only=False)
        # 설치 스크립트가 자식 프로세스로 띄우는 패키지 안 JS (실측: espresso-idling-resource
        # 의 postinstall 이 spawn('node', [main.js], {detached: true}))
        specs += [s if s.startswith(".") else "./" + s for s in _install_js_refs(mod)]
        for spec in specs:
            r = _resolve_module(files, "" if base == "." else base, spec) or \
                _resolve_module(files, root, spec)
            if r and r.endswith(_JS_SUFFIXES):
                queue.append((r, key))

    # 3) 로드 시점 — 진입점의 실행 범위 + 그 범위가 require 하는 파일
    queue2 = _entry_points(pkg, root, files)
    entries = set(queue2)
    loaded: set[str] = set()
    while queue2 and len(loaded) < _MAX_FOLLOW:
        rel = queue2.pop(0)
        if rel in loaded or rel in analyzed:
            continue
        loaded.add(rel)
        text = read(rel)
        if text is None:
            continue
        found, mod = _analyze_js(text, rel, "load", "require 시점에 실행되는", whole=False)
        out.extend(found)
        if rel in entries and not _is_bundle_path(rel):
            longest = max((len(x) for x in text.splitlines()), default=0)
            if longest > 20_000:
                out.append(_finding(RULE_MINIFIED, Severity.LOW, f"{rel}:1",
                                    f"진입점이 한 줄 {longest}자 — 압축·난독화된 코드"))
        base = PurePosixPath(rel).parent.as_posix()
        for spec in jslex.local_requires(mod, executed_only=True):
            r = _resolve_module(files, "" if base == "." else base, spec)
            if r and r.endswith(_JS_SUFFIXES):
                queue2.append(r)

    # 4) 나머지 JS — 실행 경로는 모르지만 웹훅 토큰·디코딩 실행·난독화는 정황으로
    for rel in all_files:
        if "node_modules/" in rel:
            continue
        low = rel.lower()
        is_js = low.endswith(_JS_SUFFIXES)
        if not (is_js or low.endswith((".json", ".ts", ".sh", ".py"))):
            continue
        if tree.size(rel) > _MAX_FILE:
            continue
        text = tree.read(rel)
        if text is None:
            if rel in analyzed or rel in loaded or rel in entries:
                missing.append(rel)
            elif is_js and unreadable is not None:
                unreadable.append(rel)
            continue
        out.extend(_endpoint_findings(text, rel))
        if is_js and rel not in analyzed and rel not in loaded:
            found, _ = _analyze_js(text, rel, "other", "패키지 안 코드에서", whole=False)
            out.extend(f for f in found if f.rule in (RULE_DECODE_EXEC, RULE_OBFUSCATED,
                                                      RULE_SUSPICIOUS_HOST))

    # 5) binding.gyp, 포장 이상
    gyp = _join(root, "binding.gyp")
    if gyp in files and (text := read(gyp)) is not None:
        out.extend(_gyp(text, gyp))
    if _join(root, ".npmrc") in files:
        out.append(_finding(RULE_PACKAGE_ODDITY, Severity.LOW, f"{_join(root, '.npmrc')}:1",
                            "패키지에 .npmrc 가 들어 있음 "
                            "(설치에는 영향 없음 — 토큰 유출 흔적일 수 있다)"))
    bins = pkg.get("bin")
    bin_paths = [bins] if isinstance(bins, str) else list(bins.values()) if isinstance(
        bins, dict) else []
    for b in bin_paths:
        if isinstance(b, str) and (b.startswith("/") or ".." in b or "\\" in b):
            out.append(_finding(RULE_PACKAGE_ODDITY, Severity.MEDIUM, f"{rel_pkg}:1",
                                f"bin 이 패키지 밖을 가리킴: {b!r}"))

    for rel in sorted(set(missing)):
        if unreadable is not None:
            unreadable.append(rel)
        out.append(_finding(RULE_UNREADABLE, Severity.MEDIUM, f"{rel}:1",
                            "설치·로드 시점에 실행되는 파일을 읽지 못함 — 못 본 것은 깨끗한 것이 "
                            "아니다 (백신 차단일 수 있음)"))

    # 중복 제거 + 심각도 순
    seen: set[tuple[str, str, str]] = set()
    uniq = []
    for f in out:
        key = (f.rule, f.location, f.detail or "")
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    uniq.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], f.rule, f.location))
    return uniq


__all__ = ["RULE_CWES", "analyze_tree"]
