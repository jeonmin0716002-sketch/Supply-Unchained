# ruff: noqa: E501
"""Maven 아티팩트(.jar·-sources.jar·.pom) 정적분석 규칙.

Maven 에는 설치 스크립트가 없다. 소비자의 머신에서 **자동으로** 코드가 도는 경로는 좁다:

* annotation processor (``META-INF/services/javax.annotation.processing.Processor``) —
  javac 가 클래스패스에서 찾아 컴파일러 안에서 실행한다 (빌드 시점).
* 부모 POM(packaging=pom)의 ``build/plugins`` — 자식 프로젝트가 상속해 빌드마다 돈다.
  (일반 jar 의 POM 플러그인은 소비자에게 상속되지 않는다 — 그건 정황일 뿐이다.)
* 클래스 로드 시점의 정적 초기화(``static {}``)·서비스 로더 제공자.

원칙(파이썬 엔진 실측): "있다"가 아니라 "자동 경로에서 무엇을 하느냐". annotation processor·
Java 에이전트·플러그인이 *있다*는 것 자체는 흔해서(lombok·dagger·mapstruct·byte-buddy)
MEDIUM/LOW 정황이고, HIGH 는 그런 자동 경로의 클래스가 네트워크+프로세스 실행, 디코딩→클래스
로딩, 수상한 명령, 토큰 박힌 유출 채널 같은 공급망 공격 특유 조합을 보일 때만이다.

``.class`` 는 디컴파일하지 않는다 — 상수 풀(classfile.py)의 클래스·메서드 참조와 문자열만 본다.
"""

from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Protocol

from api.schemas import Severity, StaticFinding
from ecosystems.maven._xml import child_text, parse_xml
from ecosystems.maven.classfile import ClassFileError, Constants, parse_constant_pool
from engine.rules.base import FileContext, SourceTree, make_finding

R_AGENT = "maven-java-agent"
R_PROC = "maven-annotation-processor"
R_SERVICE = "maven-service-loader-exec"
R_STATIC = "maven-static-init-exec"
R_CLASS = "maven-class-strings"
R_EXFIL = "maven-exfil-endpoint"
R_POM_REPO = "maven-foreign-repository"
R_POM_PLUGIN = "maven-pom-exec-plugin"
R_POM_SYSTEM = "maven-system-scope"
R_NESTED = "maven-nested-jar"
R_PLUGIN = "maven-plugin-descriptor"
R_LIMIT = "maven-scan-truncated"

_CWES = {
    R_AGENT: frozenset({"CWE-829", "CWE-506"}),
    R_PROC: frozenset({"CWE-829", "CWE-94"}),
    R_SERVICE: frozenset({"CWE-94"}),
    R_STATIC: frozenset({"CWE-94", "CWE-78"}),
    R_CLASS: frozenset({"CWE-78", "CWE-94"}),
    R_EXFIL: frozenset({"CWE-200"}),
    R_POM_REPO: frozenset({"CWE-829"}),
    R_POM_PLUGIN: frozenset({"CWE-78"}),
    R_POM_SYSTEM: frozenset({"CWE-829"}),
    R_NESTED: frozenset({"CWE-829"}),
    R_PLUGIN: frozenset({"CWE-78"}),
    R_LIMIT: frozenset({"CWE-693"}),
}

MAX_CLASSES = 4000          # 트리당 상수 풀을 파싱할 클래스 수
MAX_NESTED_JARS = 8
MAX_NESTED_BYTES = 25 * 1024 * 1024
MAX_NESTED_ENTRIES = 5000
MAX_NESTED_CLASSES = 1500
MAX_ENTRY_BYTES = 4 * 1024 * 1024
MAX_TEXT_BYTES = 2_000_000

_CENTRAL_HOSTS = ("repo1.maven.org", "repo.maven.apache.org", "central.sonatype.com",
                  "oss.sonatype.org", "s01.oss.sonatype.org", "search.maven.org")

_PROCESSOR_SERVICE = "META-INF/services/javax.annotation.processing.Processor"

_SUSPICIOUS_CMD = re.compile(
    r"powershell|pwsh|-enc(?:odedcommand)?\b|windowstyle\s+hidden|mshta|certutil|bitsadmin|"
    r"rundll32|regsvr32|invoke-webrequest|\biwr\b|invoke-expression|\bcurl\b|\bwget\b|/dev/tcp|"
    r"\bnc\s+-e|base64\s+-d|\|\s*(?:ba)?sh\b|schtasks|\bcrontab\b|chmod\s+\+x\s+/tmp",
    re.IGNORECASE,
)
_EXFIL_PATTERNS = (
    ("Discord 웹훅", re.compile(r"discord(?:app)?\.com/api/webhooks/\d{15,}/[\w-]{20,}")),
    ("Telegram 봇 토큰", re.compile(r"api\.telegram\.org/bot\d{6,}:[\w-]{30,}")),
)
_SUSPECT_HOSTS = re.compile(
    r"https?://(?:[^/\s\"']*\.)?(?:webhook\.site|requestbin\.\w+|pipedream\.net|"
    r"ngrok(?:-free)?\.(?:io|app|dev)|interact\.sh|oast\.(?:pro|live|site|online|fun|me)|"
    r"burpcollaborator\.net|transfer\.sh|serveo\.net|trycloudflare\.com)\b",
    re.IGNORECASE,
)
_IP_URL = re.compile(r"https?://(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::\d+)?(?:/|$)")


def _public_ip_url(s: str) -> bool:
    m = _IP_URL.search(s)
    if not m:
        return False
    a, b, c, d = (int(x) for x in m.groups())
    if max(a, b, c, d) > 255:
        return False
    if a in (0, 10, 127) or (a == 169 and b == 254) or (a == 192 and b == 168):
        return False
    return not (a == 172 and 16 <= b <= 31)


# ── 소스 추상화 (디스크 트리 / 중첩 jar 를 같은 규칙으로) ───────────

class _Source(Protocol):
    def names(self) -> list[str]: ...
    def size(self, name: str) -> int: ...
    def read(self, name: str) -> bytes | None: ...


class _TreeSource:
    def __init__(self, tree: SourceTree) -> None:
        self._tree = tree
        self.unreadable: list[str] = []

    def names(self) -> list[str]:
        return self._tree.files()

    def size(self, name: str) -> int:
        return self._tree.size(name)

    def read(self, name: str) -> bytes | None:
        root = getattr(self._tree, "root", None)
        if root is not None:
            try:
                return (root / name).read_bytes()
            except OSError:
                self.unreadable.append(name)
                return None
        text = self._tree.read(name)
        if text is None:
            self.unreadable.append(name)
            return None
        # MemoryTree(테스트)는 문자열만 담는다. latin-1 이면 클래스 파일 바이트도 그대로 담긴다.
        try:
            return text.encode("latin-1")
        except UnicodeEncodeError:
            return text.encode("utf-8")


class _ZipSource:
    def __init__(self, zf: zipfile.ZipFile) -> None:
        self._zf = zf
        self._infos = {i.filename: i for i in zf.infolist() if not i.is_dir()}

    def names(self) -> list[str]:
        return sorted(self._infos)

    def size(self, name: str) -> int:
        return self._infos[name].file_size

    def read(self, name: str) -> bytes | None:
        info = self._infos.get(name)
        if info is None or info.file_size > MAX_ENTRY_BYTES:
            return None
        try:
            return self._zf.read(info)
        except (zipfile.BadZipFile, RuntimeError, OSError, NotImplementedError):
            return None


def _text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _ctx(rel: str, text: str = "") -> FileContext:
    return FileContext(path=PurePosixPath(rel), relpath=rel, text=text)  # type: ignore[arg-type]


def _find(rel: str, severity: Severity, rule: str, cwe: str, detail: str,
          line: int = 1) -> StaticFinding:
    return make_finding(rule=rule, cwe=cwe, severity=severity, ctx=_ctx(rel), line=line,
                        detail=detail)


# ── 클래스 증거 ────────────────────────────────────────────────

_NET_CLASSES = {"java/net/URL", "java/net/Socket", "java/net/HttpURLConnection",
                "java/net/URLConnection", "java/net/http/HttpClient", "java/net/DatagramSocket"}
_NET_METHODS = {"openConnection", "openStream"}


@dataclass
class _Evidence:
    exec_: bool = False
    net: bool = False
    load: bool = False
    b64: bool = False
    script: bool = False
    susp: str | None = None
    webhook: str | None = None
    hosts: list[str] = field(default_factory=list)

    @property
    def strong(self) -> str | None:
        """공급망 공격 특유의 조합이면 그 설명."""
        if self.webhook:
            return f"{self.webhook} 주소가 박혀 있음"
        if self.exec_ and self.susp:
            return f"프로세스 실행 + 수상한 명령 문자열({self.susp})"
        if self.exec_ and self.net:
            return "프로세스 실행 + 네트워크 I/O"
        if self.net and self.load:
            return "네트워크 I/O + 클래스 동적 로딩"
        if self.b64 and (self.load or self.exec_ or self.script):
            return "Base64 디코딩 + 클래스 로딩/프로세스 실행/스크립트 평가"
        return None


def _class_evidence(c: Constants) -> _Evidence:
    ev = _Evidence()
    ev.exec_ = ("java/lang/Runtime", "exec") in c.methods or "java/lang/ProcessBuilder" in c.classes
    ev.net = bool(c.classes & _NET_CLASSES) and (
        bool(c.classes & {"java/net/Socket", "java/net/http/HttpClient", "java/net/DatagramSocket"})
        or any(m in _NET_METHODS for _, m in c.methods)
    )
    ev.load = (any(m == "defineClass" for _, m in c.methods)
               or "java/net/URLClassLoader" in c.classes)
    ev.b64 = "java/util/Base64" in c.classes or "javax/xml/bind/DatatypeConverter" in c.classes
    ev.script = "javax/script/ScriptEngineManager" in c.classes
    for s in c.strings:
        m = _SUSPICIOUS_CMD.search(s)
        if m and ev.susp is None:
            ev.susp = m.group(0)
        for label, pat in _EXFIL_PATTERNS:
            if pat.search(s):
                ev.webhook = label
        if _SUSPECT_HOSTS.search(s) or _public_ip_url(s):
            ev.hosts.append(s[:80])
    for s in c.utf8:  # 문자열이 아닌 Utf8 에 박힌 웹훅도 잡는다
        for label, pat in _EXFIL_PATTERNS:
            if pat.search(s):
                ev.webhook = label
    return ev


_JAVA_EXEC = re.compile(r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|new\s+ProcessBuilder")
_JAVA_NET = re.compile(
    r"\.openConnection\s*\(|\.openStream\s*\(|new\s+Socket\s*\(|HttpClient\b|HttpURLConnection")
_JAVA_LOAD = re.compile(r"\bdefineClass\s*\(|new\s+URLClassLoader")
_JAVA_B64 = re.compile(r"Base64\s*\.\s*getDecoder|parseBase64Binary|Base64\s*\.\s*decode")
_JAVA_SCRIPT = re.compile(r"ScriptEngineManager|getEngineByName")


def _java_evidence(text: str) -> _Evidence:
    ev = _Evidence()
    ev.exec_ = bool(_JAVA_EXEC.search(text))
    ev.net = bool(_JAVA_NET.search(text))
    ev.load = bool(_JAVA_LOAD.search(text))
    ev.b64 = bool(_JAVA_B64.search(text))
    ev.script = bool(_JAVA_SCRIPT.search(text))
    for m in re.finditer(r'"((?:[^"\\\n]|\\.){4,300})"', text):
        s = m.group(1)
        cm = _SUSPICIOUS_CMD.search(s)
        if cm and ev.susp is None:
            ev.susp = cm.group(0)
    for label, pat in _EXFIL_PATTERNS:
        if pat.search(text):
            ev.webhook = label
    return ev


def _blank_literals(text: str) -> str:
    """문자열·문자 리터럴과 주석의 내용을 공백으로 지운다 (길이·줄바꿈 유지 — 오프셋이 같다).
    ``"static { ... }"`` 같은 문자열 안의 구문을 실제 초기화 블록으로 오인하지 않으려는 것."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'":
            j = i + 1
            while j < n and text[j] != ch and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i)
            j = n if j < 0 else j + 2
            for k in range(i, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


def _static_blocks(text: str) -> list[tuple[int, str]]:
    """``static { ... }`` 블록의 (시작 줄, 원문 본문)."""
    blank = _blank_literals(text)
    out = []
    for m in re.finditer(r"\bstatic\s*\{", blank):
        i, depth, n = m.end(), 1, len(blank)
        while i < n and depth:
            if blank[i] == "{":
                depth += 1
            elif blank[i] == "}":
                depth -= 1
            i += 1
        out.append((text.count("\n", 0, m.start()) + 1, text[m.end(): i]))
    return out

# ── 매니페스트·서비스 ──────────────────────────────────────────

def _manifest_attrs(text: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    last = None
    for line in text.splitlines():
        if line.startswith(" ") and last:
            attrs[last] += line[1:]
        elif ":" in line:
            k, _, v = line.partition(":")
            last = k.strip()
            attrs[last] = v.strip()
        elif not line.strip():
            break  # 첫 섹션(메인 속성)만
    return attrs


def _providers(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line and re.fullmatch(r"[\w.$]+", line):
            out.append(line)
    return out


def _class_evidence_for(src: _Source, names: set[str], cls: str) -> tuple[_Evidence, str] | None:
    """클래스 이름 → 이 소스 안의 .class(상수 풀) 또는 .java 증거와 그 경로."""
    base = cls.replace(".", "/")
    if f"{base}.class" in names:
        data = src.read(f"{base}.class")
        if data is not None:
            try:
                return _class_evidence(parse_constant_pool(data)), f"{base}.class"
            except ClassFileError:
                return None
    for cand in (f"{base}.java", f"src/main/java/{base}.java"):
        if cand in names:
            data = src.read(cand)
            if data is not None:
                return _java_evidence(_text(data)), cand
    return None


# ── POM ────────────────────────────────────────────────────────

_EXEC_PLUGINS = {"exec-maven-plugin", "maven-antrun-plugin", "gmaven-plugin",
                 "groovy-maven-plugin", "gmavenplus-plugin", "maven-scripting-plugin"}


def _scan_pom(rel: str, text: str) -> list[StaticFinding]:
    try:
        root = parse_xml(text)
    except ValueError as exc:
        return [_find(rel, Severity.MEDIUM, R_POM_REPO, "CWE-829",
                      f"POM 을 해석하지 못함 (분석 불가): {exc}")]
    out: list[StaticFinding] = []
    packaging = child_text(root, "packaging") or "jar"
    for repo in root.findall("repositories/repository") + root.findall("pluginRepositories/pluginRepository"):
        url = child_text(repo, "url") or ""
        host = re.sub(r"^\w+://", "", url).split("/", 1)[0].split(":", 1)[0].lower()
        if not host or "${" in host:
            continue
        if host.endswith(_CENTRAL_HOSTS):
            continue
        insecure = url.lower().startswith("http://")
        out.append(_find(
            rel, Severity.MEDIUM, R_POM_REPO, "CWE-829",
            f"이 의존성을 쓰는 빌드가 Central 이 아닌 저장소({host})도 조회함"
            + (" — 평문 http" if insecure else "")))
    for dep in root.findall("dependencies/dependency"):
        if child_text(dep, "scope") == "system":
            out.append(_find(rel, Severity.LOW, R_POM_SYSTEM, "CWE-829",
                             f"system 스코프 의존성 {child_text(dep, 'artifactId')} (로컬 경로 jar)"))
    for plugin in root.findall("build/plugins/plugin"):
        aid = child_text(plugin, "artifactId") or ""
        if aid not in _EXEC_PLUGINS:
            continue
        blob = "".join(plugin.itertext())
        m = _SUSPICIOUS_CMD.search(blob)
        inherited = packaging == "pom"  # 부모 POM 의 플러그인만 소비자 빌드에 상속된다
        if m:
            out.append(_find(
                rel, Severity.HIGH if inherited else Severity.MEDIUM, R_POM_PLUGIN, "CWE-78",
                f"{aid} 가 수상한 명령 실행({m.group(0)})"
                + (" — 부모 POM 이라 자식 빌드마다 실행됨" if inherited else "")))
        elif inherited:
            out.append(_find(rel, Severity.LOW, R_POM_PLUGIN, "CWE-78",
                             f"부모 POM 이 {aid} 를 빌드에 묶음 (자식 빌드에 상속)"))
    return out


# ── 한 소스(jar 한 개 분량) 분석 ────────────────────────────────

def _analyze_source(src: _Source, prefix: str, *, class_budget: int) -> list[StaticFinding]:
    names_list = src.names()
    names = set(names_list)
    out: list[StaticFinding] = []
    auto_classes: dict[str, str] = {}   # 자동 경로 클래스 → 이유

    def loc(rel: str) -> str:
        return f"{prefix}{rel}"

    # MANIFEST — Java 에이전트
    if "META-INF/MANIFEST.MF" in names:
        data = src.read("META-INF/MANIFEST.MF")
        if data is not None:
            attrs = _manifest_attrs(_text(data))
            for key in ("Premain-Class", "Agent-Class", "Launcher-Agent-Class"):
                if attrs.get(key):
                    auto_classes[attrs[key]] = f"{key}"
                    out.append(_find(
                        loc("META-INF/MANIFEST.MF"), Severity.MEDIUM, R_AGENT, "CWE-829",
                        f"{key}: {attrs[key]} — JVM 에이전트로 실행되면 모든 클래스 로딩에 개입 가능"))

    # 서비스 로더
    for n in names_list:
        if not n.startswith("META-INF/services/") or n.count("/") != 2:
            continue
        data = src.read(n)
        if data is None:
            continue
        is_proc = n == _PROCESSOR_SERVICE
        providers = _providers(_text(data))
        if is_proc and providers:
            out.append(_find(
                loc(n), Severity.MEDIUM, R_PROC, "CWE-829",
                f"annotation processor {', '.join(providers[:3])} — 컴파일러 안에서 빌드 시 자동 실행"))
        for cls in providers[:50]:
            auto_classes.setdefault(cls, "annotation processor" if is_proc else f"서비스 제공자({PurePosixPath(n).name})")

    # 자동 경로 클래스의 증거
    for cls, why in auto_classes.items():
        got = _class_evidence_for(src, names, cls)
        if got is None:
            continue
        ev, path = got
        strong = ev.strong
        if strong:
            is_proc = why == "annotation processor"
            out.append(_find(
                loc(path), Severity.HIGH, R_PROC if is_proc else R_SERVICE, "CWE-94",
                f"{why} 클래스가 {strong}"))

    # 소스: 정적 초기화 + 프로세서 상속
    for n in names_list:
        if not n.endswith(".java") or src.size(n) > MAX_TEXT_BYTES:
            continue
        data = src.read(n)
        if data is None:
            continue
        text = _text(data)
        for label, pat in _EXFIL_PATTERNS:
            m = pat.search(text)
            if m:
                out.append(_find(loc(n), Severity.HIGH, R_EXFIL, "CWE-200",
                                 f"{label} 주소가 박혀 있음", text.count("\n", 0, m.start()) + 1))
        for line, body in _static_blocks(text):
            ev = _java_evidence(body)
            strong = ev.strong
            if strong:
                out.append(_find(loc(n), Severity.HIGH, R_STATIC, "CWE-94",
                                 f"클래스 로드 시 실행되는 static 초기화가 {strong}", line))
            elif ev.exec_ or ev.load or ev.script:
                out.append(_find(loc(n), Severity.MEDIUM, R_STATIC, "CWE-94",
                                 "static 초기화에서 프로세스 실행/클래스 동적 로딩/스크립트 평가", line))
        if "AbstractProcessor" in text and (strong := _java_evidence(text).strong):
            out.append(_find(loc(n), Severity.HIGH, R_PROC, "CWE-94",
                             f"annotation processor 소스가 {strong}"))

    # 클래스: 상수 풀 스캔
    parsed = 0
    hosts_reported = 0
    truncated = False
    for n in names_list:
        if not n.endswith(".class") or n.endswith("module-info.class"):
            continue
        if parsed >= class_budget:
            truncated = True
            break
        parsed += 1
        data = src.read(n)
        if data is None:
            continue
        try:
            c = parse_constant_pool(data)
        except ClassFileError:
            continue
        ev = _class_evidence(c)
        if ev.webhook:
            out.append(_find(loc(n), Severity.HIGH, R_EXFIL, "CWE-200",
                             f"{ev.webhook} 주소가 상수 풀에 박혀 있음"))
        if ev.exec_ and ev.susp:
            out.append(_find(loc(n), Severity.MEDIUM, R_CLASS, "CWE-78",
                             f"프로세스 실행 클래스가 수상한 명령 문자열({ev.susp})을 가짐"))
        if ev.hosts and hosts_reported < 5:
            hosts_reported += 1
            out.append(_find(loc(n), Severity.MEDIUM, R_CLASS, "CWE-200",
                             f"상수 풀에 의심 엔드포인트: {ev.hosts[0]}"))
    if truncated:
        out.append(_find(prefix + "(classes)", Severity.LOW, R_LIMIT, "CWE-693",
                         f"클래스가 {class_budget}개를 넘어 일부만 상수 풀 스캔함"))

    # POM
    for n in names_list:
        if (n == "pom.xml" or (n.startswith("META-INF/maven/") and n.endswith("/pom.xml"))
                or n.endswith(".pom")) and src.size(n) <= MAX_TEXT_BYTES:
            data = src.read(n)
            if data is not None:
                out += _scan_pom(loc(n), _text(data))
    if "META-INF/maven/plugin.xml" in names:
        out.append(_find(loc("META-INF/maven/plugin.xml"), Severity.LOW, R_PLUGIN, "CWE-78",
                         "Maven 플러그인 — 빌드에서 이 플러그인을 쓰면 mojo 가 빌드 머신에서 실행됨"))
    return out


_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


def analyze_tree(tree: SourceTree, *, artifact=None) -> list[StaticFinding]:
    src = _TreeSource(tree)
    findings = _analyze_source(src, "", class_budget=MAX_CLASSES)

    # 중첩 jar (fat/shaded jar) — 한 단계만, 한도 안에서
    nested = [n for n in src.names()
              if n.lower().endswith((".jar", ".war")) and n.lower() != "pom.xml"]
    if nested:
        findings.append(_find(
            nested[0], Severity.LOW, R_NESTED, "CWE-829",
            f"중첩 jar {len(nested)}개 포함 (shaded/fat jar) — 최대 {MAX_NESTED_JARS}개까지 한 단계 검사"))
    for n in nested[:MAX_NESTED_JARS]:
        if src.size(n) > MAX_NESTED_BYTES:
            findings.append(_find(n, Severity.LOW, R_LIMIT, "CWE-693", "중첩 jar 가 너무 커서 검사 생략"))
            continue
        data = src.read(n)
        if data is None:
            continue
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                if len(zf.infolist()) > MAX_NESTED_ENTRIES:
                    findings.append(_find(n, Severity.LOW, R_LIMIT, "CWE-693",
                                          "중첩 jar 항목이 너무 많아 검사 생략"))
                    continue
                findings += _analyze_source(_ZipSource(zf), f"{n}!/", class_budget=MAX_NESTED_CLASSES)
        except zipfile.BadZipFile:
            findings.append(_find(n, Severity.MEDIUM, R_NESTED, "CWE-829",
                                  "중첩 jar 가 zip 으로 열리지 않음 (분석 불가)"))
    if len(nested) > MAX_NESTED_JARS:
        findings.append(_find(nested[MAX_NESTED_JARS], Severity.LOW, R_LIMIT, "CWE-693",
                              f"중첩 jar {len(nested) - MAX_NESTED_JARS}개는 검사하지 않음"))
    findings.sort(key=lambda f: _ORDER.get(f.severity, 9))
    analyze_tree.unreadable = src.unreadable  # type: ignore[attr-defined]
    return findings


def rule_cwes() -> dict[str, frozenset[str]]:
    return dict(_CWES)


def has_build_hooks(names: list[str]) -> bool:
    """annotation processor 또는 Maven 플러그인 디스크립터가 있는가 (자동 실행 경로)."""
    return _PROCESSOR_SERVICE in names or "META-INF/maven/plugin.xml" in names
