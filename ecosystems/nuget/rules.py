"""NuGet 패키지(.nupkg = zip) 정적분석 규칙.

자동 실행 경로 (docs/design/multi-ecosystem.md §2.4):

* ``tools/install.ps1``·``uninstall.ps1``·``init.ps1`` — packages.config/Visual Studio 가 실행.
* ``build/``·``buildTransitive/``·``buildMultiTargeting/`` 의 ``*.targets``·``*.props`` —
  패키지를 참조한 프로젝트를 빌드하면 MSBuild 가 **자동으로 import** 한다. ``<Exec>``·인라인
  태스크(``CodeTaskFactory``/``RoslynCodeTaskFactory``)는 빌드 머신에서 임의 코드가 된다.

원칙 (파이썬 엔진 실측): "있다"가 아니라 "자동 실행되고 무엇을 하느냐". 속성만 정하거나
네이티브 라이브러리를 복사하는 .targets 는 정상이라 아무것도 내지 않는다. HIGH 는
다운로드→실행, 인코딩된 명령, 디코딩→어셈블리 로드, 숨김 창 실행, 토큰 박힌 웹훅 같은
공급망 공격 특유의 조합에만 붙인다.

관리형 .dll 은 디컴파일하지 않는다. 문자열 테이블만 보고, 토큰이 박힌 유출 채널(웹훅)만
찾는다 (정상 라이브러리가 남의 채널 비밀 토큰을 넣어 배포할 이유가 없다).
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from api.schemas import Severity, StaticFinding
from ecosystems.nuget._xml import parse_xml
from engine.rules.base import FileContext, SourceTree, make_finding

R_PS = "nuget-powershell-exec"
R_ENC = "nuget-encoded-command"
R_MSBUILD = "nuget-msbuild-exec"
R_INLINE = "nuget-inline-task"
R_EXFIL = "nuget-exfil-endpoint"
R_SCRIPT = "nuget-install-script"
R_TYPE = "nuget-package-type"
R_DLL = "nuget-dll-strings"

_CWES = {
    R_PS: frozenset({"CWE-494", "CWE-78"}),
    R_ENC: frozenset({"CWE-506"}),
    R_MSBUILD: frozenset({"CWE-78"}),
    R_INLINE: frozenset({"CWE-94"}),
    R_EXFIL: frozenset({"CWE-200"}),
    R_SCRIPT: frozenset({"CWE-94"}),
    R_TYPE: frozenset({"CWE-829"}),
    R_DLL: frozenset({"CWE-200"}),
}

_AUTO_PS = {"install.ps1", "uninstall.ps1", "init.ps1"}
_BUILD_DIRS = {"build", "buildtransitive", "buildmultitargeting"}
MAX_TEXT_BYTES = 2_000_000
MAX_DLL_BYTES = 8_000_000
MAX_DLLS = 60

_DOWNLOAD = re.compile(
    r"invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|downloadstring|downloadfile|"
    r"downloaddata|net\.webclient|start-bitstransfer|\bcurl(?:\.exe)?\s|\bwget\s|bitsadmin|certutil",
    re.IGNORECASE,
)
_EXEC = re.compile(
    r"invoke-expression|\biex\b|start-process|\[\s*(?:system\.)?reflection\.assembly\s*\]\s*::\s*load"
    r"|assembly\s*\]\s*::\s*load|\.invoke\(|\bmshta\b|rundll32|regsvr32|cmd(?:\.exe)?\s+/c",
    re.IGNORECASE,
)
_ENCODED = re.compile(r"-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{24,}", re.IGNORECASE)
_B64 = re.compile(r"frombase64string", re.IGNORECASE)
_LOAD = re.compile(r"assembly\s*\]\s*::\s*load|invoke-expression|\biex\b|\.invoke\(", re.IGNORECASE)
_HIDDEN = re.compile(r"-w(?:indowstyle)?\s+hidden|createnowindow|windowstyle\s*=\s*hidden",
                     re.IGNORECASE)
_UPLOAD = re.compile(r"uploadstring|uploadfile|uploaddata|-method\s+post", re.IGNORECASE)
_SENSITIVE = re.compile(
    r"\$env:|computername|\busername\b|\.ssh|\.aws|\.npmrc|credential|get-childitem\s+env:",
    re.IGNORECASE,
)
_EXFIL_PATTERNS = (
    ("Discord 웹훅", re.compile(r"discord(?:app)?\.com/api/webhooks/\d{15,}/[\w-]{20,}")),
    ("Telegram 봇 토큰", re.compile(r"api\.telegram\.org/bot\d{6,}:[\w-]{30,}")),
)
_SUSPICIOUS_CMD = re.compile(
    r"powershell|pwsh|-enc(?:odedcommand)?\b|windowstyle\s+hidden|mshta|certutil|bitsadmin|"
    r"rundll32|regsvr32|invoke-webrequest|\biwr\b|invoke-expression|\biex\b|\bcurl\b|\bwget\b|"
    r"base64\s+-d|\|\s*(?:ba)?sh\b|schtasks|downloadstring",
    re.IGNORECASE,
)
_INLINE_DANGER = re.compile(
    r"Process\.Start|ProcessStartInfo|WebClient|HttpClient|DownloadString|DownloadFile|"
    r"Assembly\.Load|FromBase64String|Invoke-Expression|Socket",
)
_INLINE_NET = re.compile(r"WebClient|HttpClient|DownloadString|DownloadFile|\bSocket\b|WebRequest")
_INLINE_EXEC = re.compile(r"Process\.Start|ProcessStartInfo|Assembly\.Load|\.Invoke\(")


# ── 파일 읽기 ──────────────────────────────────────────────────

def read_bytes(tree: SourceTree, rel: str) -> bytes | None:
    """디스크 트리는 원본 바이트, 메모리 트리(테스트)는 UTF-8 로 되돌린다."""
    root = getattr(tree, "root", None)
    if root is not None:
        try:
            return (root / rel).read_bytes()
        except OSError:
            return None
    text = tree.read(rel)
    return None if text is None else text.encode("utf-8", "surrogateescape")


def _decode(data: bytes) -> str:
    """PowerShell 스크립트는 UTF-16 BOM 인 경우가 흔하다 (VS 가 그렇게 저장한다)."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8-sig", errors="replace")


def _ctx(rel: str, text: str) -> FileContext:
    return FileContext(path=PurePosixPath(rel), relpath=rel, text=text)  # type: ignore[arg-type]


def _line_of(text: str, m: re.Match[str] | None) -> int:
    return text.count("\n", 0, m.start()) + 1 if m else 1


# ── PowerShell ─────────────────────────────────────────────────

def _scan_powershell(rel: str, text: str, auto: bool) -> list[StaticFinding]:
    ctx = _ctx(rel, text)
    out: list[StaticFinding] = []
    high = Severity.HIGH if auto else Severity.MEDIUM  # 자동 실행 경로가 아니면 정황
    where = "자동 실행 스크립트" if auto else "스크립트"

    for label, pat in _EXFIL_PATTERNS:
        m = pat.search(text)
        if m:  # 토큰 박힌 유출 채널은 어디에 있든 HIGH
            out.append(make_finding(rule=R_EXFIL, cwe="CWE-200", severity=Severity.HIGH, ctx=ctx,
                                    line=_line_of(text, m), detail=f"{label} 주소가 박혀 있음"))
    m = _ENCODED.search(text)
    if m:
        out.append(make_finding(rule=R_ENC, cwe="CWE-506", severity=high, ctx=ctx,
                                line=_line_of(text, m),
                                detail=f"{where}: 인코딩된 명령(-EncodedCommand)"))
    b64 = _B64.search(text)
    if b64 and _LOAD.search(text):
        out.append(make_finding(rule=R_ENC, cwe="CWE-506", severity=high, ctx=ctx,
                                line=_line_of(text, b64),
                                detail=f"{where}: Base64 디코딩 후 어셈블리 로드/실행"))
    dl, ex = _DOWNLOAD.search(text), _EXEC.search(text)
    if dl and ex:
        out.append(make_finding(rule=R_PS, cwe="CWE-494", severity=high, ctx=ctx,
                                line=_line_of(text, dl),
                                detail=f"{where}: 다운로드({dl.group(0).strip()}) + "
                                       f"실행({ex.group(0).strip()})"))
    hid = _HIDDEN.search(text)
    if hid and (dl or re.search(r"start-process", text, re.IGNORECASE)):
        out.append(make_finding(rule=R_PS, cwe="CWE-78", severity=high, ctx=ctx,
                                line=_line_of(text, hid),
                                detail=f"{where}: 숨김 창으로 프로세스 실행"))
    up = _UPLOAD.search(text)
    if up and _SENSITIVE.search(text):
        out.append(make_finding(rule=R_EXFIL, cwe="CWE-200", severity=high, ctx=ctx,
                                line=_line_of(text, up),
                                detail=f"{where}: 환경변수·자격증명 성격의 값을 외부로 전송"))
    return out


# ── MSBuild .targets / .props ──────────────────────────────────

def _scan_msbuild(rel: str, text: str) -> list[StaticFinding]:
    ctx = _ctx(rel, text)
    out: list[StaticFinding] = []
    try:
        root = parse_xml(text)
    except ValueError as exc:
        # 못 읽은 파일을 "깨끗함"으로 넘기지 않는다 — DTD·깨진 XML 은 그 자체가 정황.
        return [make_finding(rule=R_MSBUILD, cwe="CWE-78", severity=Severity.MEDIUM, ctx=ctx,
                             line=1, detail=f"MSBuild 파일을 해석하지 못함 (분석 불가): {exc}")]

    has_download = False
    for el in root.iter():
        tag = el.tag if isinstance(el.tag, str) else ""
        if tag == "DownloadFile":
            has_download = True
            out.append(make_finding(
                rule=R_MSBUILD, cwe="CWE-494", severity=Severity.MEDIUM, ctx=ctx, line=1,
                detail="빌드 중 DownloadFile 태스크로 외부 파일을 받음"))
        elif tag == "Exec":
            cmd = el.get("Command") or ""
            m = _SUSPICIOUS_CMD.search(cmd)
            if m:
                out.append(make_finding(
                    rule=R_MSBUILD, cwe="CWE-78", severity=Severity.HIGH, ctx=ctx, line=1,
                    detail=f"빌드 시 자동 실행되는 <Exec> 가 수상한 명령 실행: {m.group(0)}"))
            else:
                out.append(make_finding(
                    rule=R_MSBUILD, cwe="CWE-78", severity=Severity.LOW, ctx=ctx, line=1,
                    detail="빌드 시 <Exec> 로 명령 실행 (정황, 명령 자체는 평범)"))
        elif tag == "UsingTask":
            factory = el.get("TaskFactory") or ""
            if factory.lower() in ("codetaskfactory", "roslyncodetaskfactory"):
                body = "".join(c.text or "" for c in el.iter("Code"))
                net, ex = _INLINE_NET.search(body), _INLINE_EXEC.search(body)
                b64, ld = re.search(r"FromBase64String", body), re.search(r"Assembly\.Load", body)
                if (net and ex) or (b64 and ld):
                    out.append(make_finding(
                        rule=R_INLINE, cwe="CWE-94", severity=Severity.HIGH, ctx=ctx, line=1,
                        detail="인라인 태스크가 네트워크 + 프로세스/어셈블리 실행 또는 "
                               "Base64 디코딩 + 어셈블리 로드를 함"))
                else:
                    danger = _INLINE_DANGER.search(body)
                    out.append(make_finding(
                        rule=R_INLINE, cwe="CWE-94", severity=Severity.MEDIUM, ctx=ctx, line=1,
                        detail="빌드 시 컴파일·실행되는 인라인 태스크(" + factory + ")"
                               + (f", {danger.group(0)} 사용" if danger else "")))
    for label, pat in _EXFIL_PATTERNS:
        m = pat.search(text)
        if m:
            out.append(make_finding(rule=R_EXFIL, cwe="CWE-200", severity=Severity.HIGH, ctx=ctx,
                                    line=_line_of(text, m), detail=f"{label} 주소가 박혀 있음"))
    if has_download and any(el.tag == "Exec" for el in root.iter() if isinstance(el.tag, str)):
        out.append(make_finding(rule=R_MSBUILD, cwe="CWE-494", severity=Severity.MEDIUM, ctx=ctx,
                                line=1, detail="같은 파일에서 DownloadFile 과 Exec 를 함께 씀"))
    return out


# ── .nuspec ────────────────────────────────────────────────────

def _scan_nuspec(rel: str, text: str) -> list[StaticFinding]:
    try:
        root = parse_xml(text)
    except ValueError:
        return []
    ctx = _ctx(rel, text)
    out = []
    for pt in root.iter("packageType"):
        name = (pt.get("name") or "").strip()
        if name.lower() in ("dotnettool", "template"):
            out.append(make_finding(
                rule=R_TYPE, cwe="CWE-829", severity=Severity.LOW, ctx=ctx, line=1,
                detail=f"packageType {name} — 사용자가 도구를 실행/템플릿을 적용할 때 코드가 돈다"))
    return out


# ── .dll 문자열 ────────────────────────────────────────────────

def _scan_dll(rel: str, data: bytes) -> list[StaticFinding]:
    # UTF-16LE 문자열(.NET 문자열 리터럴)은 NUL 을 걷어내면 ASCII 로 읽힌다.
    flat = data.replace(b"\x00", b"").decode("latin-1")
    out = []
    ctx = _ctx(rel, "")
    for label, pat in _EXFIL_PATTERNS:
        if pat.search(flat):
            out.append(make_finding(rule=R_DLL, cwe="CWE-200", severity=Severity.HIGH, ctx=ctx,
                                    line=1, detail=f"어셈블리 문자열에 {label} 주소가 박혀 있음"))
    return out


# ── 진입점 ─────────────────────────────────────────────────────

_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


def analyze_tree(tree, *, artifact=None) -> list[StaticFinding]:
    findings: list[StaticFinding] = []
    unreadable: list[str] = []
    dlls = 0
    for rel in tree.files():
        p = PurePosixPath(rel)
        parts = [s.lower() for s in p.parts[:-1]]
        name = p.name.lower()
        is_auto_ps = name in _AUTO_PS and (parts[:1] == ["tools"] or not parts)
        is_ps = name.endswith((".ps1", ".psm1", ".psd1"))
        is_msbuild = (name.endswith((".targets", ".props"))
                      and bool(parts and parts[0] in _BUILD_DIRS))
        is_nuspec = name.endswith(".nuspec") and not parts
        is_dll = name.endswith(".dll")
        if not (is_ps or is_msbuild or is_nuspec or is_dll):
            continue
        if tree.size(rel) > (MAX_DLL_BYTES if is_dll else MAX_TEXT_BYTES):
            unreadable.append(rel)
            continue
        if is_dll:
            dlls += 1
            if dlls > MAX_DLLS:
                continue
            data = read_bytes(tree, rel)
            if data is None:
                unreadable.append(rel)
            else:
                findings += _scan_dll(rel, data)
            continue
        data = read_bytes(tree, rel)
        if data is None:
            unreadable.append(rel)
            continue
        text = _decode(data)
        if is_ps:
            findings += _scan_powershell(rel, text, auto=is_auto_ps)
            if is_auto_ps:
                findings.append(make_finding(
                    rule=R_SCRIPT, cwe="CWE-94", severity=Severity.LOW, ctx=_ctx(rel, text), line=1,
                    detail=f"{name} — 패키지 설치/로드 시 실행되는 스크립트가 있음"))
        elif is_msbuild:
            findings += _scan_msbuild(rel, text)
        elif is_nuspec:
            findings += _scan_nuspec(rel, text)
    findings.sort(key=lambda f: _ORDER.get(f.severity, 9))
    analyze_tree.unreadable = unreadable  # type: ignore[attr-defined]
    return findings


def rule_cwes() -> dict[str, frozenset[str]]:
    return dict(_CWES)


def has_executable_hooks(names: list[str]) -> bool:
    """tools/install·init.ps1 또는 build 디렉터리의 .targets/.props 가 있는가."""
    for n in names:
        p = PurePosixPath(n.lower())
        parts = p.parts
        if p.name in _AUTO_PS and parts[:1] == ("tools",):
            return True
        if p.name.endswith((".targets", ".props")) and parts and parts[0] in _BUILD_DIRS:
            return True
    return False
