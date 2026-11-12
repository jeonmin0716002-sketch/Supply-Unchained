"""cargo 정적분석 — 빌드·컴파일 시점에 사용자 머신에서 자동 실행되는 코드만 본다.

crates.io 에는 npm 의 postinstall 같은 설치 훅이 없다. 대신 **의존성을 받는 순간
(``cargo build``) 돌아가는 코드**가 둘 있다:

* ``build.rs`` — 컴파일 전에 빌더 권한으로 실행되는 임의 프로그램.
* proc-macro 크레이트(``[lib] proc-macro = true``) — 컴파일러 프로세스 안에서 매크로 확장 때
  실행된다 (이쪽은 거의 감시되지 않는다).

판정 원칙은 전 생태계 공통(docs/design/multi-ecosystem.md §2.3)이다:

* ``build.rs`` 가 있다, ``cc``·``cmake``·``bindgen``·``pkg-config`` 를 부른다 → **평범**, 아무것도 안 낸다.
  C 라이브러리를 묶는 크레이트의 대부분이 그렇다.
* HIGH 는 공급망 공격 특유의 조합 — 크리덴셜 읽기 + 네트워크, 수상한 명령(PowerShell·
  ``curl | sh``), 디코딩/내장 blob → 파일로 쓰고 실행, 셸 시작 파일·cron 등 지속성, 토큰이 박힌
  웹훅. 네트워크만 쓰는 것은 MEDIUM: 미리 컴파일된 바이너리를 내려받는 정상 크레이트(ort·tch 류)가
  있어서다.

파일을 읽을 때 주석은 지우되 문자열은 남긴다 — 명령 이름·URL 이 문자열 안에 있다.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from api.schemas import Severity, StaticFinding
from engine.rules.base import SourceTree

R_EXFIL = "cargo-build-exfil"
R_ENDPOINT = "cargo-exfil-endpoint"
R_SUSPICIOUS = "cargo-build-suspicious-command"
R_PAYLOAD = "cargo-build-payload-exec"
R_PERSIST = "cargo-build-persistence"
R_NETWORK = "cargo-build-network"
R_SPAWN = "cargo-build-spawn"
R_PROCMACRO = "cargo-proc-macro-sideeffect"
R_BUILD_PATH = "cargo-manifest-build-path"
R_GIT_DEP = "cargo-manifest-git-dependency"
R_UNREADABLE = "cargo-unreadable-file"
R_BAD_MANIFEST = "cargo-manifest-invalid"

RULE_CWES: dict[str, frozenset[str]] = {
    R_EXFIL: frozenset({"CWE-200"}),
    R_ENDPOINT: frozenset({"CWE-200"}),
    R_SUSPICIOUS: frozenset({"CWE-78"}),
    R_PAYLOAD: frozenset({"CWE-94"}),
    R_PERSIST: frozenset({"CWE-506"}),
    R_NETWORK: frozenset({"CWE-494"}),
    R_SPAWN: frozenset({"CWE-78"}),
    R_PROCMACRO: frozenset({"CWE-94"}),
    R_BUILD_PATH: frozenset({"CWE-829"}),
    R_GIT_DEP: frozenset({"CWE-829"}),
    R_UNREADABLE: frozenset({"CWE-693"}),
    R_BAD_MANIFEST: frozenset({"CWE-693"}),
}

_MAX_FILE = 2_000_000  # 이보다 큰 소스는 읽지 않는다 (난독화 덩어리이거나 생성 코드)
_SEV_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


# ── Rust 어휘 처리 ────────────────────────────────────────────────

def strip_comments(src: str) -> str:
    """주석을 공백으로 지운다. 문자열·문자 리터럴은 그대로 둔다 (줄 번호·오프셋 보존).

    정규식으로 ``//`` 를 지우면 ``"https://..."`` 가 잘린다 — 문자열 안인지 알아야 하므로
    한 글자씩 읽는 작은 렉서를 쓴다. 중첩 블록 주석, 원시 문자열(``r#"..."#``),
    수명(``'a``)과 문자 리터럴(``'a'``)의 구분을 처리한다.
    """
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        two = src[i:i + 2]
        if two == "//":
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif two == "/*":
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif src.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            out.append("".join("\n" if ch == "\n" else " " for ch in src[i:j]))
            i = j
        elif c == "r" and re.match(r'r#*"', src[i:i + 40]) and (i == 0 or not _ident(src[i - 1])):
            hashes = len(re.match(r"r(#*)", src[i:]).group(1))
            end = src.find('"' + "#" * hashes, i + 2 + hashes)
            j = n if end < 0 else end + 1 + hashes
            out.append(src[i:j])
            i = j
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1])
            i = j + 1
        elif c == "'":
            m = re.match(r"'(?:\\.[^']*|[^\\'])'", src[i:i + 12])
            if m:  # 문자 리터럴
                out.append(m.group(0))
                i += len(m.group(0))
            else:  # 수명 'a
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _ident(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


# ── 패턴 ──────────────────────────────────────────────────────────

#: 실제로 패킷을 내보내는 것만. 타입만 쓰는 ``http::`` · ``url::`` 는 통신하지 않는다.
_NET = re.compile(
    r"\b(?:reqwest|ureq|attohttpc|minreq|isahc|surf|http_req|awc)\s*::"
    r"|\bcurl\s*::\s*easy\b|\bhyper\s*::\s*client\b|\bhyper_util\s*::\s*client\b"
    r"|\b(?:TcpStream|UdpSocket)\s*::\s*(?:connect|bind)\b|\bto_socket_addrs\b|\blookup_host\b"
)
_COMMAND = re.compile(r"\bCommand\s*::\s*new\s*\(")
_STR = re.compile(r'(?:b?"((?:[^"\\]|\\.)*)")|(?:r(#*)"(.*?)"\2)', re.DOTALL)

#: 정상 빌드가 돌리는 명령. 이것들은 아무 규칙도 켜지 않는다.
_ORDINARY = frozenset(["cc", "gcc", "g++", "c++", "cpp", "clang", "clang++", "clang-cl", "cl", "ld", "lld", "ar", "ranlib", "lib", "link", "nm", "objcopy", "strip", "as", "cmake", "ctest", "make", "gmake", "mingw32-make", "nmake", "ninja", "meson", "pkg-config", "pkgconf", "git", "rustc", "cargo", "rustfmt", "rustup", "python", "python3", "python2", "py", "perl", "ruby", "nasm", "yasm", "sh", "bash", "zsh", "dash", "cmd", "uname", "sw_vers", "xcrun", "xcode-select", "which", "where", "lsb_release", "llvm-config", "tar", "unzip", "gzip", "patch", "cp", "mv", "rm", "mkdir", "sed", "awk", "autoreconf", "autoconf", "automake", "libtoolize", "aclocal", "configure", "nproc", "getconf", "dpkg", "ldconfig", "bindgen", "protoc", "flatc", "node", "npm", "npx", "go", "java", "javac", "swiftc", "dotnet", "sccache", "ccache", "windres", "nvcc", "emcc", "wasm-bindgen", "wasm-pack", "msbuild", "vcpkg", "conan", "bundle", "gem", "echo", "true", "false", "test", "env", "curl-config", "sdl2-config", "freetype-config", "xml2-config", "mysql_config", "pg_config", "krb5-config"])
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "cmd", "powershell", "pwsh"})

#: 정상 빌드가 돌릴 이유가 없는 명령·옵션 (curl·wget 은 네트워크로 따로 센다)
_SUSPICIOUS_CMD = re.compile(
    r"powershell|pwsh|-enc(?:odedcommand)?\b|windowstyle\s+hidden|-w\s+hidden|mshta|certutil"
    r"|bitsadmin|rundll32|regsvr32|invoke-webrequest|\biwr\b|invoke-expression|\biex\b"
    r"|/dev/tcp|\bnc\s+-e|base64\s+-d|\|\s*(?:ba)?sh\b|schtasks|crontab|reg\s+add",
    re.IGNORECASE,
)
_DOWNLOADER = re.compile(r"\b(?:curl|wget)\s", re.IGNORECASE)

_CRED_ENV = re.compile(
    r"TOKEN|SECRET|PASSW(?:OR)?D|API_?KEY|PRIVATE_?KEY|CREDENTIAL|AWS_SECRET|AWS_ACCESS|SSH_AUTH_SOCK",
    re.IGNORECASE,
)
_ENV_READ = re.compile(r"\benv\s*::\s*(?:var|var_os)\s*\(\s*\"([^\"]*)\"")
_ENV_DUMP = re.compile(r"\benv\s*::\s*vars(?:_os)?\s*\(\s*\)")
_CRED_FILE = re.compile(
    r"\.ssh/|\.aws/credentials|\.npmrc|\.pypirc|\.git-credentials|\.cargo/credentials|\.netrc"
    r"|\.docker/config\.json|Login Data|wallet\.dat|\.kube/config|\.config/gcloud",
    re.IGNORECASE,
)
_DECODE = re.compile(
    r"\bbase64\s*::|\bSTANDARD\s*\.\s*decode\b|\bURL_SAFE\w*\s*\.\s*decode\b|\bhex\s*::\s*decode\b"
    r"|\bfrom_hex\b|\bdecode_config\b|\bflate2\s*::|\bxz2\s*::|\bzstd\s*::\s*decode"
)
_INCLUDE_BYTES = re.compile(r"\binclude_bytes\s*!")
_WRITE = re.compile(
    r"\bfs\s*::\s*(?:write|copy|rename)\b|\bFile\s*::\s*create\b|\bOpenOptions\b"
    r"|\bwrite_all\b|\bset_permissions\b|\bPermissionsExt\b"
)
_PERSIST = re.compile(
    r"\.bashrc|\.zshrc|\.bash_profile|\.profile\b|authorized_keys|LaunchAgents|LaunchDaemons"
    r"|\\Startup\\|/etc/cron|crontab|systemd/(?:user|system)|/etc/profile|/etc/ld\.so\.preload"
    r"|CurrentVersion\\\\?Run",
    re.IGNORECASE,
)
#: 토큰이 박힌 웹훅·봇 주소 — 정상 코드가 남의 채널 비밀을 패키지에 넣어 배포할 이유가 없다
_WEBHOOK = re.compile(
    r"discord(?:app)?\.com/api/webhooks/\d{15,}/[\w-]{20,}|api\.telegram\.org/bot\d{6,}:[\w-]{30,}"
)
#: 수신 전용 유출 채널 — 빌드 스크립트가 이 주소를 알 이유가 없다
_COLLECTOR = re.compile(
    r"webhook\.site|requestbin|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|interact\.sh"
    r"|oast\.(?:pro|live|site|online|fun|me)|burpcollaborator\.net|canarytokens\.com"
    r"|pastebin\.com/raw|transfer\.sh|file\.io|\.trycloudflare\.com",
    re.IGNORECASE,
)
_RAW_IP_URL = re.compile(r"https?://(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")


def _public_ip(m: re.Match[str]) -> bool:
    a, b, *_ = (int(g) for g in m.groups())
    if a in (0, 10, 127) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
        return False
    return not (a == 169 and b == 254)


@dataclass
class Facts:
    """한 실행 범위(빌드 스크립트 또는 proc-macro 소스) 안에서 본 행위."""

    network: list[tuple[str, int, str]] = field(default_factory=list)
    spawns: list[tuple[str, int, str]] = field(default_factory=list)     # 평범하지 않은 명령
    suspicious: list[tuple[str, int, str]] = field(default_factory=list)
    creds: list[tuple[str, int, str]] = field(default_factory=list)
    decode: list[tuple[str, int, str]] = field(default_factory=list)
    writes: list[tuple[str, int, str]] = field(default_factory=list)
    persist: list[tuple[str, int, str]] = field(default_factory=list)
    endpoints: list[tuple[str, int, str]] = field(default_factory=list)
    any_spawn: bool = False


def _statement_end(text: str, pos: int) -> int:
    end = text.find(";", pos)
    return len(text) if end < 0 else min(end, pos + 800)


def _literals(chunk: str) -> list[str]:
    return [m.group(1) if m.group(1) is not None else m.group(3) for m in _STR.finditer(chunk)]


def scan_code(rel: str, text: str, facts: Facts) -> None:
    """주석이 지워진 Rust 소스 하나에서 행위를 모은다."""
    for m in _NET.finditer(text):
        facts.network.append((rel, _line_of(text, m.start()), m.group(0).strip()))

    shell_seen = False
    for m in _COMMAND.finditer(text):
        facts.any_spawn = True
        stmt = text[m.end():_statement_end(text, m.end())]
        lits = _literals(stmt)
        first = re.match(r"\s*(?:b?\"((?:[^\"\\]|\\.)*)\")", stmt)
        program = (first.group(1) if first else "").replace("\\\\", "/")
        base = PurePosixPath(program.replace("\\", "/")).name.lower()
        base = base[:-4] if base.endswith(".exe") else base
        line = _line_of(text, m.start())
        cmdline = " ".join(lits)
        if base in _SHELLS:
            shell_seen = True
        if base in ("curl", "wget") or (base in _SHELLS and _DOWNLOADER.search(cmdline + " ")):
            facts.network.append((rel, line, f"Command {base or 'curl/wget'}"))
        hit = _SUSPICIOUS_CMD.search(cmdline)
        if hit:
            facts.suspicious.append((rel, line, hit.group(0)))
        elif first and base and base not in _ORDINARY:
            facts.spawns.append((rel, line, program))
        elif not first:
            # 프로그램 이름이 리터럴이 아님: 정상(CC 환경변수)일 수도, 내려받은 파일일 수도 있다.
            facts.spawns.append((rel, line, "<computed>"))
    if shell_seen:  # 셸에 넘기는 문자열은 문장 밖 ``.arg("-c").arg("...")`` 로 흩어질 수 있다
        for m in _STR.finditer(text):
            s = m.group(1) if m.group(1) is not None else m.group(3)
            hit = _SUSPICIOUS_CMD.search(s)
            if hit:
                facts.suspicious.append((rel, _line_of(text, m.start()), hit.group(0)))

    for m in _ENV_READ.finditer(text):
        if _CRED_ENV.search(m.group(1)):
            facts.creds.append((rel, _line_of(text, m.start()), f"env {m.group(1)}"))
    for m in _ENV_DUMP.finditer(text):
        facts.creds.append((rel, _line_of(text, m.start()), "env::vars() 전체 덤프"))
    for lit_m in _STR.finditer(text):
        s = lit_m.group(1) if lit_m.group(1) is not None else lit_m.group(3)
        pos = lit_m.start()
        if _CRED_FILE.search(s):
            facts.creds.append((rel, _line_of(text, pos), f"파일 {_CRED_FILE.search(s).group(0)}"))
        if _PERSIST.search(s):
            facts.persist.append((rel, _line_of(text, pos), _PERSIST.search(s).group(0)))
        for pat in (_WEBHOOK, _COLLECTOR):
            h = pat.search(s)
            if h:
                facts.endpoints.append((rel, _line_of(text, pos), h.group(0)))
        ip = _RAW_IP_URL.search(s)
        if ip and _public_ip(ip):
            facts.endpoints.append((rel, _line_of(text, pos), ip.group(0)))

    for pat, bucket in ((_DECODE, facts.decode), (_INCLUDE_BYTES, facts.decode),
                        (_WRITE, facts.writes)):
        for m in pat.finditer(text):
            bucket.append((rel, _line_of(text, m.start()), m.group(0).strip()))


def _f(rule: str, sev: Severity, where: tuple[str, int, str] | tuple[str, int], detail: str
       ) -> StaticFinding:
    return StaticFinding(rule=rule, cwe=sorted(RULE_CWES[rule])[0], severity=sev,
                         location=f"{where[0]}:{where[1]}", detail=detail)


def _judge(facts: Facts, *, scope: str, proc_macro: bool) -> list[StaticFinding]:
    """수집한 행위를 판정으로. ``scope`` 는 사람이 읽는 실행 범위 이름."""
    out: list[StaticFinding] = []
    rule = lambda r: R_PROCMACRO if proc_macro else r  # noqa: E731

    # 웹훅은 어디에 있든 HIGH 가 아니라 실행 범위 안에서만 (여기까지 오는 건 이미 실행 범위)
    web = [e for e in facts.endpoints if not _RAW_IP_URL.fullmatch(e[2])]
    if web:
        out.append(_f(rule(R_ENDPOINT), Severity.HIGH, web[0],
                      f"{scope}에 유출 채널 주소가 박혀 있다: {web[0][2]}"))
    ips = [e for e in facts.endpoints if _RAW_IP_URL.fullmatch(e[2])]
    if ips and facts.network:
        out.append(_f(rule(R_ENDPOINT), Severity.HIGH, ips[0],
                      f"{scope}이 공인 IP 주소({ips[0][2]})로 직접 통신한다"))
    if facts.network and facts.creds:
        c = facts.creds[0]
        out.append(_f(rule(R_EXFIL), Severity.HIGH, c,
                      f"{scope}이 크리덴셜({c[2]})을 읽고 네트워크 코드({facts.network[0][2]})도 가진다"))
    if facts.suspicious:
        s = facts.suspicious[0]
        out.append(_f(rule(R_SUSPICIOUS), Severity.HIGH, s,
                      f"{scope}이 수상한 명령을 실행한다: {s[2]}"))
    dropped = [s for s in facts.spawns if s[2] == "<computed>" or s[2] not in _ORDINARY]
    if facts.decode and facts.writes and dropped:
        d = facts.decode[0]
        out.append(_f(rule(R_PAYLOAD), Severity.HIGH, d,
                      f"{scope}이 디코딩/내장 blob({d[2]}) → 파일 쓰기 → 외부 프로그램 실행 순서를 가진다"))
    if facts.persist and facts.writes:
        p = facts.persist[0]
        out.append(_f(rule(R_PERSIST), Severity.HIGH, p,
                      f"{scope}이 지속성 위치({p[2]})를 건드린다 — 셸 시작 파일·cron·자동 실행 등록"))
    if facts.network and not any(o.severity == Severity.HIGH for o in out):
        n = facts.network[0]
        out.append(_f(rule(R_NETWORK), Severity.MEDIUM, n,
                      f"{scope}이 빌드 중 네트워크 접근({n[2]}) — 정상 크레이트도 사전 빌드 바이너리를 "
                      "받지만 무결성 검증 여부를 확인해야 한다"))
    named = [s for s in facts.spawns if s[2] != "<computed>"]
    if named:
        s = named[0]
        out.append(_f(rule(R_SPAWN), Severity.MEDIUM, s,
                      f"{scope}이 일반 빌드 도구가 아닌 프로그램({s[2]})을 실행한다"))
    return out


# ── 크레이트 구조 ─────────────────────────────────────────────────

def _crate_root(files: list[str]) -> str | None:
    """가장 얕은 Cargo.toml 의 디렉터리 (``.crate`` 는 ``<name>-<ver>/`` 로 한 겹 싸여 있다)."""
    roots = sorted((f for f in files if PurePosixPath(f).name == "Cargo.toml"),
                   key=lambda f: f.count("/"))
    if not roots:
        return None
    parent = str(PurePosixPath(roots[0]).parent)
    return "" if parent == "." else parent


def _join(root: str, rel: str) -> str:
    return f"{root}/{rel}" if root else rel


def _module_files(tree: SourceTree, base_dir: str, text: str, files: set[str]) -> list[str]:
    """빌드 스크립트가 ``mod x;`` · ``include!("x.rs")`` 로 끌어오는 파일들."""
    found: list[str] = []
    for m in re.finditer(r"^\s*(?:pub\s+)?mod\s+(\w+)\s*;", text, re.MULTILINE):
        for cand in (f"{m.group(1)}.rs", f"{m.group(1)}/mod.rs"):
            path = _join(base_dir, cand)
            if path in files:
                found.append(path)
    for m in re.finditer(r'\binclude!\s*\(\s*"([^"]+)"', text):
        path = str(PurePosixPath(_join(base_dir, m.group(1))))
        if path in files:
            found.append(path)
    return found


def analyze(tree: SourceTree) -> list[StaticFinding]:
    findings: list[StaticFinding] = []
    files = set(tree.files())
    root = _crate_root(tree.files())
    if root is None:
        return findings  # 크레이트가 아니다 (Cargo.toml 없음). 호출자가 판단한다
    manifest_path = _join(root, "Cargo.toml")
    raw = tree.read(manifest_path)
    manifest: dict = {}
    if raw is None:
        findings.append(StaticFinding(rule=R_UNREADABLE, cwe="CWE-693", severity=Severity.MEDIUM,
                                      location=manifest_path, detail="Cargo.toml 을 읽지 못했다"))
    else:
        try:
            manifest = tomllib.loads(raw)
        except tomllib.TOMLDecodeError as exc:
            findings.append(StaticFinding(
                rule=R_BAD_MANIFEST, cwe="CWE-693", severity=Severity.MEDIUM,
                location=manifest_path,
                detail=f"Cargo.toml 이 TOML 로 해석되지 않는다 ({exc}) — cargo publish 가 정규화한 "
                       "파일이면 이럴 수 없다"))

    findings += _manifest_findings(manifest, manifest_path, root, files)

    pkg = manifest.get("package") or {}
    lib = manifest.get("lib") or {}
    proc_macro = bool(lib.get("proc-macro") or lib.get("proc_macro"))

    # 빌드 스크립트 — build = false 면 없다, 문자열이면 그 경로, 없으면 build.rs 자동 감지
    build = pkg.get("build", None)
    script: str | None = None
    if build is not False:
        script = _join(root, build if isinstance(build, str) else "build.rs")
        if script not in files:
            script = None
    if script:
        facts = Facts()
        queue, seen = [script], set()
        while queue:
            rel = queue.pop()
            if rel in seen:
                continue
            seen.add(rel)
            text = _read_rs(tree, rel, findings)
            if text is None:
                continue
            scan_code(rel, strip_comments(text), facts)
            parent = PurePosixPath(rel).parent.as_posix()
            queue += _module_files(tree, "" if parent == "." else parent, text, files)
        findings += _judge(facts, scope="build.rs", proc_macro=False)

    if proc_macro:
        facts = Facts()
        prefix = _join(root, "src/")
        for rel in sorted(files):
            if rel.startswith(prefix) and rel.endswith(".rs"):
                text = _read_rs(tree, rel, findings)
                if text is not None:
                    scan_code(rel, strip_comments(text), facts)
        findings += _judge(facts, scope="proc-macro 코드", proc_macro=True)

    findings.sort(key=lambda f: _SEV_ORDER[f.severity])
    return findings


def _read_rs(tree: SourceTree, rel: str, findings: list[StaticFinding]) -> str | None:
    size = tree.size(rel)
    if size > _MAX_FILE:
        findings.append(StaticFinding(
            rule=R_UNREADABLE, cwe="CWE-693", severity=Severity.MEDIUM, location=f"{rel}:1",
            detail=f"{size} 바이트 — 분석 상한({_MAX_FILE})을 넘어 읽지 않았다"))
        return None
    text = tree.read(rel)
    if text is None:
        findings.append(StaticFinding(
            rule=R_UNREADABLE, cwe="CWE-693", severity=Severity.MEDIUM, location=f"{rel}:1",
            detail="파일을 읽지 못했다 (백신 차단 또는 I/O 오류) — 분석하지 못했다"))
    return text


def _manifest_findings(manifest: dict, path: str, root: str, files: set[str]
                       ) -> list[StaticFinding]:
    out: list[StaticFinding] = []
    build = (manifest.get("package") or {}).get("build")
    if isinstance(build, str):
        norm = PurePosixPath(build)
        odd = (".." in norm.parts or norm.is_absolute() or norm.suffix != ".rs"
               or _join(root, build) not in files)
        if odd:
            out.append(StaticFinding(
                rule=R_BUILD_PATH, cwe="CWE-829", severity=Severity.MEDIUM, location=path,
                detail=f"build = {build!r} — 빌드 스크립트가 관례(build.rs)와 다른 경로를 가리킨다"))
    tables = [manifest.get(k) or {} for k in ("dependencies", "build-dependencies")]
    for target in (manifest.get("target") or {}).values():
        if isinstance(target, dict):
            tables += [target.get("dependencies") or {}, target.get("build-dependencies") or {}]
    for tbl in tables:
        for dep, spec in tbl.items():
            if isinstance(spec, dict) and spec.get("git"):
                out.append(StaticFinding(
                    rule=R_GIT_DEP, cwe="CWE-829", severity=Severity.MEDIUM, location=path,
                    detail=f"의존성 {dep} 이 git 저장소({spec['git']})를 가리킨다 — crates.io 감시 밖 코드"))
    return out

# ruff: noqa: E501
