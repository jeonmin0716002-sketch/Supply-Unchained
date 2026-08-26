"""su-scan — Supply-Unchained CLI.

pip 앞단에서 스캔을 태우는 두 가지 진입점 중 "명시 호출" 쪽 구현.
(다른 하나는 pip 프록시 — api/routers/proxy.py 참고.)

기본적으로 **서버 없이** 이 프로세스 안에서 스캔 파이프라인을 직접 돌린다. uvicorn 을
먼저 띄워야만 도는 CLI 는 pip 앞단 도구로 쓰기 어렵기 때문 — CI 잡이나 남의 셸에서
서버를 먼저 올려둘 수는 없다.

사용:
    uv run python -m cli.su_scan check requests==2.31.0
    uv run python -m cli.su_scan check reqeusts            # 버전 생략 → 최신 버전 조회
    uv run python -m cli.su_scan install requests==2.31.0  # 스캔 통과 시에만 pip install
    uv run python -m cli.su_scan history                   # 최근 스캔 이력

환경변수:
    SU_API_URL       설정하면 그 주소의 API 서버를 호출한다 (미설정 시 로컬 실행).
                     프록시·대시보드를 함께 쓸 때 이력을 한곳에 모으려면 지정.
    SU_DB_PATH       스캔 이력 SQLite 경로 (기본 data/supply_unchained.db)
    SU_OFFLINE_DEMO  1 이면 네트워크 없이 mock 판정 (로컬 실행에도 그대로 적용)
"""

from __future__ import annotations

import asyncio
import os
import re
import subprocess
import sys

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Windows 기본 콘솔 코드페이지(한국어 환경은 cp949)는 판정 이모지 ⚠️/✅/⛔ 를 인코딩할
# 수 없어, rich 가 출력하는 순간 UnicodeEncodeError 로 죽는다 — 즉 check/install 이 통째로
# 사용 불가였다. 출력 스트림을 UTF-8 로 올려서 해결한다 (errors="replace" 는 그래도 못 쓰는
# 글리프가 남는 콘솔에서 크래시 대신 대체문자를 쓰게 하는 마지막 안전망).
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure") and (_stream.encoding or "").lower().replace(
        "-", ""
    ) not in ("utf8", "utf8sig"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

app = typer.Typer(help="Supply-Unchained — pip 설치 전 공급망 스캔", no_args_is_help=True)
console = Console()

DEFAULT_API = "http://localhost:8000"
_TIMEOUT = 120.0  # 정적분석은 아카이브 다운로드를 포함하므로 넉넉히

_VERDICT_STYLE = {
    "safe": ("✅ SAFE", "green"),
    "warn": ("⚠️  WARN", "yellow"),
    "block": ("⛔ BLOCK", "red"),
}


def _style(verdict: str) -> tuple[str, str]:
    """판정의 (라벨, 색). 판정값이 늘어나도 KeyError 로 죽지 않게 기본값을 둔다."""
    return _VERDICT_STYLE.get(verdict, (verdict.upper(), "white"))


def _api_url() -> str:
    return os.environ.get("SU_API_URL", DEFAULT_API).rstrip("/")


def _use_server() -> bool:
    """SU_API_URL 이 명시돼 있을 때만 HTTP 로 서버를 부른다.

    기본값이 로컬 실행인 이유: CLI 하나만 치면 스캔이 끝나야 한다. 서버를 먼저 띄워야만
    도는 CLI 는 "pip 앞단에 끼워넣는 도구"로 쓰기 어렵다 — 게이트를 걸고 싶은 CI 잡이나
    남의 셸에서 uvicorn 을 먼저 올릴 수는 없으니까.

    서버를 쓰는 경로도 남겨둔다. pip 프록시·대시보드는 어차피 서버가 떠 있어야 하고,
    그때는 스캔 이력이 한곳에 쌓이는 게 맞다. 그 경우 SU_API_URL 을 주면 된다.
    """
    return "SU_API_URL" in os.environ


def _run_local(coro):
    """로컬 실행 진입점. asyncio 루프를 여기서만 연다."""
    return asyncio.run(coro)


def _scan_local(name: str, version: str) -> dict:
    """API 서버 없이 스캔 파이프라인을 이 프로세스에서 직접 돌린다.

    api.routers.scan.run_scan 은 FastAPI 핸들러가 아니라 순수 함수라 그대로 부를 수 있다
    (프록시도 같은 함수를 재사용한다). 무거운 import(bandit·fastapi)를 지연시키려고
    함수 안에서 import 한다 — `--help` 한 번 치는 데 몇 초씩 걸리면 안 된다.
    """
    from api.routers.scan import run_scan
    from api.schemas import ScanRequest
    from api.storage import ScanStore

    try:
        req = ScanRequest(name=name, version=version)
    except ValueError as exc:
        # 서버 경로의 422 에 대응하는 자리. 화이트리스트 검증(api/schemas.py)은
        # 로컬 실행에서도 똑같이 걸려야 한다.
        console.print(f"[red]잘못된 요청:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    async def _go() -> dict:
        store = ScanStore()
        await store.init()
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(_TIMEOUT),
            limits=httpx.Limits(max_connections=20),
            headers={"User-Agent": "supply-unchained-cli/0.1"},
        ) as http:
            result = await run_scan(req, http=http, store=store)
        return result.model_dump(mode="json")

    return _run_local(_go())


def _scan_remote(name: str, version: str) -> dict:
    try:
        resp = httpx.post(
            f"{_api_url()}/api/v1/scan",
            json={"ecosystem": "pip", "name": name, "version": version},
            timeout=_TIMEOUT,
        )
    except httpx.HTTPError as exc:
        console.print(
            f"[red]API 연결 실패:[/red] {_api_url()} — {exc}\n"
            f"서버 실행: [bold]uv run uvicorn api.main:app[/bold]\n"
            f"또는 SU_API_URL 을 지우면 서버 없이 로컬로 스캔합니다."
        )
        raise typer.Exit(code=2) from exc
    if resp.status_code == 422:
        console.print(f"[red]잘못된 요청:[/red] {resp.json()}")
        raise typer.Exit(code=2)
    # raise_for_status 가 던지는 HTTPStatusError 는 위 except 의 HTTPError 서브클래스지만
    # try 블록 밖이라 그대로 새어나가 raw traceback 이 됐다 — 여기서 받아서 메시지로 바꾼다.
    try:
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        console.print(f"[red]API 오류 {resp.status_code}:[/red] {resp.text[:300]}")
        raise typer.Exit(code=2) from exc
    return resp.json()


def _scan(name: str, version: str) -> dict:
    return _scan_remote(name, version) if _use_server() else _scan_local(name, version)


def _parse_spec(spec: str) -> tuple[str, str | None]:
    """'name==version' 또는 'name' → (name, version|None)."""
    if "==" in spec:
        name, _, version = spec.partition("==")
        return name.strip(), version.strip() or None
    return spec.strip(), None


def _resolve_latest(name: str) -> str:
    """버전 생략 시 PyPI JSON API로 최신 버전 결정."""
    try:
        resp = httpx.get(f"https://pypi.org/pypi/{name}/json", timeout=15.0)
        resp.raise_for_status()
        return resp.json()["info"]["version"]
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        # 오프라인 데모의 typosquat 이름들은 실제 악성 패키지였기에 PyPI 에서 이미 삭제됐다
        # — 여기서 404 로 죽으면 `pip install reqeusts` 시연이 판정까지 가지도 못한다.
        # 데모 모드에서만 프록시가 합성하는 것과 같은 버전으로 대체한다.
        if os.environ.get("SU_OFFLINE_DEMO") == "1":
            from api.routers.proxy import DEMO_VERSION

            console.print(
                f"[dim]{name}: PyPI 조회 불가 — 데모 버전 {DEMO_VERSION} 으로 진행[/dim]"
            )
            return DEMO_VERSION
        console.print(f"[red]최신 버전 조회 실패:[/red] {name} — {exc}")
        raise typer.Exit(code=2) from exc


def _render(result: dict) -> None:
    verdict = result["verdict"]
    label, color = _style(verdict)
    pkg = f"{result['name']}=={result['version']}"

    lines = [f"[bold]{pkg}[/bold]   위험도 [bold]{result['risk_score']}[/bold]/100"]
    lines += [f"  · {r}" for r in result["verdict_reasons"]]
    if result.get("layer_errors"):
        lines.append("")
        lines.append("[yellow]⚠ 일부 탐지 레이어가 실패한 상태의 판정입니다:[/yellow]")
        lines += [f"  · {e}" for e in result["layer_errors"]]
    console.print(Panel("\n".join(lines), title=label, border_style=color))

    if result["vulnerabilities"]:
        t = Table(title="알려진 취약점 (CVE/OSV)", title_justify="left")
        for col in ("ID", "CWE", "심각도", "요약", "패치 버전"):
            t.add_column(col)
        for v in result["vulnerabilities"]:
            t.add_row(
                v["id"],
                ", ".join(v.get("cwe_ids") or []) or "-",
                v["severity"],
                v.get("summary") or "-",
                v.get("fixed_version") or "-",
            )
        console.print(t)

    if result["static_findings"]:
        t = Table(title="정적분석 탐지", title_justify="left")
        for col in ("규칙", "CWE", "심각도", "위치", "내용"):
            t.add_column(col)
        for f in result["static_findings"]:
            t.add_row(f["rule"], f["cwe"], f["severity"], f["location"], f.get("detail") or "-")
        console.print(t)

    footer = f"scan_id={result['scan_id']}"
    if _use_server():
        footer += f" · 대시보드 {_api_url()}/dashboard"
    console.print(f"[dim]{footer}[/dim]")


@app.command()
def check(
    spec: str = typer.Argument(help="패키지 (name 또는 name==version)"),
    as_json: bool = typer.Option(False, "--json", help="원본 JSON 응답 출력"),
) -> None:
    """패키지를 설치하지 않고 스캔만 수행."""
    name, version = _parse_spec(spec)
    version = version or _resolve_latest(name)
    result = _scan(name, version)

    if as_json:
        console.print_json(data=result)
    else:
        _render(result)

    # 종료 코드: safe=0 / warn=0 / block=1 → CI 파이프라인에서 그대로 게이트로 사용 가능
    raise typer.Exit(code=1 if result["verdict"] == "block" else 0)


@app.command()
def install(
    spec: str = typer.Argument(help="패키지 (name 또는 name==version)"),
    yes: bool = typer.Option(False, "--yes", "-y", help="warn 판정도 확인 없이 설치"),
    force: bool = typer.Option(False, "--force", help="block 판정 무시 (권장하지 않음)"),
) -> None:
    """스캔을 통과한 경우에만 실제 pip install 을 실행."""
    name, version = _parse_spec(spec)
    version = version or _resolve_latest(name)
    result = _scan(name, version)
    _render(result)

    verdict = result["verdict"]
    if verdict == "block" and not force:
        console.print("[red]차단됨 — 설치를 진행하지 않습니다.[/red] (--force 로 무시 가능)")
        raise typer.Exit(code=1)
    if verdict == "block" and force:
        console.print("[red bold]경고: 차단 판정을 무시하고 설치합니다.[/red bold]")
    if (
        verdict == "warn"
        and not yes
        and not force
        and not typer.confirm("경고가 있는 패키지입니다. 설치할까요?")
    ):
        raise typer.Exit(code=1)

    cmd = [sys.executable, "-m", "pip", "install", f"{name}=={version}"]
    console.print(f"[dim]$ {' '.join(cmd)}[/dim]")
    raise typer.Exit(code=subprocess.call(cmd))


@app.command("check-file")
def check_file(
    path: str = typer.Argument("requirements.txt", help="requirements 파일 경로"),
) -> None:
    """requirements.txt 전체를 스캔 — block 이 하나라도 있으면 exit 1.

    CI/CD 게이트용 (.github/workflows/supply-chain-scan.yml 에서 호출).
    `name==version` 형태의 줄만 검사하고 주석·빈 줄·기타 지정자는 건너뛴다.
    미검증 패키지를 설치하지 않는다 — 스캔 결과만으로 판단한다.
    """
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        console.print(f"[red]파일을 찾을 수 없습니다:[/red] {path}")
        raise typer.Exit(code=2) from None

    results: list[tuple[str, str, dict]] = []
    skipped: list[str] = []
    for line in lines:
        stripped = line.split("#", 1)[0].strip()
        if not stripped:
            continue
        if "==" not in stripped:
            skipped.append(stripped)
            continue
        name, version = _parse_spec(stripped)
        if not version:
            skipped.append(stripped)
            continue
        results.append((name, version, _scan(name, version)))

    t = Table(title=f"{path} — {len(results)}개 패키지 스캔", title_justify="left")
    for col in ("패키지", "판정", "점수", "사유"):
        t.add_column(col)
    blocked = 0
    for name, version, r in results:
        _label, color = _style(r["verdict"])
        if r["verdict"] == "block":
            blocked += 1
        t.add_row(
            f"{name}=={version}",
            f"[{color}]{r['verdict']}[/{color}]",
            str(r["risk_score"]),
            "; ".join(r.get("verdict_reasons") or []) or "-",
        )
    console.print(t)
    if skipped:
        console.print(f"[dim]건너뜀 (==핀 아님): {', '.join(skipped)}[/dim]")

    if blocked:
        console.print(f"[red]⛔ 차단 판정 {blocked}건 — 게이트를 통과할 수 없습니다.[/red]")
        raise typer.Exit(code=1)
    console.print("[green]✅ 모든 패키지 통과.[/green]")


@app.command()
def history(limit: int = typer.Option(20, help="가져올 개수")) -> None:
    """최근 스캔 이력 (API의 SQLite 저장분)."""
    if _use_server():
        try:
            resp = httpx.get(f"{_api_url()}/api/v1/scans", params={"limit": limit}, timeout=15.0)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            console.print(f"[red]API 연결 실패:[/red] {exc}")
            raise typer.Exit(code=2) from exc
        rows = resp.json()
    else:
        # 서버가 읽는 것과 같은 SQLite 파일(SU_DB_PATH)을 그대로 읽는다.
        from api.storage import ScanStore

        async def _recent() -> list[dict]:
            store = ScanStore()
            await store.init()
            return await store.recent(limit)

        rows = _run_local(_recent())

    t = Table(title=f"최근 스캔 {limit}건", title_justify="left")
    for col in ("id", "패키지", "판정", "점수", "시각"):
        t.add_column(col)
    for r in rows:
        _label, color = _style(r["verdict"])
        t.add_row(
            str(r["scan_id"]),
            f"{r['name']}=={r['version']}",
            f"[{color}]{r['verdict']}[/{color}]",
            str(r["risk_score"]),
            r["scanned_at"][:19].replace("T", " "),
        )
    console.print(t)


# ──────────────────────────────
# pip 래퍼 (guard) — 셸에서 `pip install` 을 가로채 스캔을 끼워넣는다
# ──────────────────────────────
#
# install 명령을 확장하지 않고 별도 명령으로 둔 이유: pip 의 CLI 를 우리가 다시 구현할
# 수는 없다. guard 는 인자를 **해석하지 않고 그대로 pip 에 넘기고**, 그중 우리가 확실히
# 알아볼 수 있는 PyPI 스펙만 골라 스캔한다. 모르는 인자는 건드리지 않으므로 pip 의
# 플래그가 늘어나도 깨지지 않는다.

#: 값을 하나 더 먹는 pip install 플래그. 그 값이 패키지명으로 오인되지 않게 같이 건너뛴다
#: (`pip install -t ./libs requests` 의 ./libs 를 패키지로 보면 안 된다).
_PIP_VALUE_FLAGS = {
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable",
    "-i", "--index-url", "--extra-index-url", "-f", "--find-links",
    "-t", "--target", "--prefix", "--root", "--src", "--upgrade-strategy",
    "--no-binary", "--only-binary", "--python-version", "--platform",
    "--implementation", "--abi", "--report", "--proxy", "--cert",
    "--client-cert", "--cache-dir", "--log", "--config-settings", "--hash",
}

#: PyPI 이름이 아닌 것들. 로컬 경로·URL·VCS·아카이브 직접 지정은 스캔 대상이 아니다.
_NON_PYPI_PREFIXES = ("http://", "https://", "git+", "hg+", "svn+", "bzr+", "file:")
_ARCHIVE_SUFFIXES = (".whl", ".tar.gz", ".zip", ".tar.bz2", ".tar.xz")

#: `name[extra1,extra2] <op> version` 에서 이름과 (있으면) 정확 버전을 뽑는다.
_REQ_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[[^\]]*\])?"
    # 순서 주의: === 를 == 보다 먼저 둬야 한다. 뒤에 두면 == 가 먼저 걸려서
    # requests===2.31.0 의 버전이 "=2.31.0" 으로 잘린다.
    r"(?:\s*(?P<op>===|==|>=|<=|~=|!=|>|<)\s*(?P<version>[^\s,;]+))?"
)


def _looks_like_pypi_spec(token: str) -> bool:
    if token.startswith("-") or token.startswith(_NON_PYPI_PREFIXES):
        return False
    if token in (".", "..") or token.startswith(("./", "../", "/", "~", "\\")):
        return False
    if re.match(r"^[A-Za-z]:[\/]", token):  # C:\path
        return False
    if token.lower().endswith(_ARCHIVE_SUFFIXES):
        return False
    return "/" not in token and "\\" not in token


def _specs_from_requirements(path: str) -> list[str]:
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as exc:
        console.print(f"[yellow]requirements 파일을 읽지 못했습니다:[/yellow] {path} — {exc}")
        return []
    out = []
    for line in lines:
        stripped = line.split("#", 1)[0].strip()
        if stripped and not stripped.startswith("-"):
            out.append(stripped)
    return out


def _extract_specs(argv: list[str]) -> tuple[list[str], list[str]]:
    """pip install 인자에서 스캔 가능한 PyPI 스펙과, 건너뛴 토큰을 분리."""
    specs: list[str] = []
    skipped: list[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in ("-r", "--requirement"):
            if i + 1 < len(argv):
                specs.extend(_specs_from_requirements(argv[i + 1]))
            i += 2
            continue
        if tok in _PIP_VALUE_FLAGS:
            i += 2  # 플래그 + 그 값
            continue
        if tok.startswith("-"):
            i += 1  # --flag=value 포함, 값을 따로 먹지 않는 플래그
            continue
        (specs if _looks_like_pypi_spec(tok) else skipped).append(tok)
        i += 1
    return specs, skipped


def _resolve_spec(spec: str) -> tuple[str, str, bool] | None:
    """'requests>=2.0' → (name, 스캔할 버전, 정확한 버전인가).

    ``==`` 이 아니면 pip 이 어떤 버전을 고를지 우리가 알 수 없다. 최신 버전을 스캔하되
    "정확하지 않음"을 표시해서, 화면에서 그 사실이 감춰지지 않게 한다.
    """
    m = _REQ_RE.match(spec.strip())
    if not m:
        return None
    name = m.group("name")
    if m.group("op") in ("==", "===") and m.group("version"):
        return name, m.group("version"), True
    return name, _resolve_latest(name), False


@app.command(
    "guard",
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
def guard(
    ctx: typer.Context,
    su_yes: bool = typer.Option(False, "--su-yes", help="warn 도 확인 없이 진행"),
    su_force: bool = typer.Option(False, "--su-force", help="block 도 무시하고 설치"),
    su_pip: str = typer.Option(
        "", "--su-pip", help="위임할 pip 실행 파일 (기본: 현재 인터프리터의 -m pip)"
    ),
) -> None:
    """`pip install` 인자를 그대로 받아 스캔한 뒤 진짜 pip 에 위임 (셸 래퍼용).

    옵션에 ``--su-`` 접두사를 붙인 이유는 pip 의 플래그와 이름이 겹치지 않게 하기 위함이다.
    """
    argv = list(ctx.args)
    specs, skipped = _extract_specs(argv)

    results: list[tuple[str, str, bool, dict]] = []
    for spec in specs:
        resolved = _resolve_spec(spec)
        if resolved is None:
            skipped.append(spec)
            continue
        name, version, exact = resolved
        results.append((name, version, exact, _scan(name, version)))

    if results:
        t = Table(title=f"설치 전 스캔 — {len(results)}개", title_justify="left")
        for col in ("패키지", "판정", "점수", "사유"):
            t.add_column(col)
        for name, version, exact, r in results:
            _label, color = _style(r["verdict"])
            label = f"{name}=={version}" + ("" if exact else "  [dim](최신 기준)[/dim]")
            t.add_row(
                label,
                f"[{color}]{r['verdict']}[/{color}]",
                str(r["risk_score"]),
                "; ".join(r.get("verdict_reasons") or []) or "-",
            )
        console.print(t)

    if skipped:
        # 스캔 못 한 것을 조용히 넘기면 "검사했고 깨끗했다"로 오해된다.
        console.print(
            f"[yellow]스캔하지 않음[/yellow] (로컬 경로·URL·VCS 등): {', '.join(skipped)}"
        )

    blocked = [f"{n}=={v}" for n, v, _e, r in results if r["verdict"] == "block"]
    warned = [f"{n}=={v}" for n, v, _e, r in results if r["verdict"] == "warn"]

    if blocked and not su_force:
        console.print(
            f"[red]⛔ 차단 — 설치를 진행하지 않습니다:[/red] {', '.join(blocked)}\n"
            "[dim](--su-force 로 무시할 수 있으나 권장하지 않습니다)[/dim]"
        )
        raise typer.Exit(code=1)
    if blocked:
        console.print(
            "[red bold]경고: 차단 판정을 무시하고 설치합니다 — "
            f"{', '.join(blocked)}[/red bold]"
        )
    if (
        warned
        and not su_yes
        and not su_force
        and not typer.confirm(f"경고가 있는 패키지: {', '.join(warned)} — 설치할까요?")
    ):
        raise typer.Exit(code=1)

    cmd = ([su_pip] if su_pip else [sys.executable, "-m", "pip"]) + ["install", *argv]
    console.print(f"[dim]$ {' '.join(cmd)}[/dim]")
    raise typer.Exit(code=subprocess.call(cmd))


if __name__ == "__main__":
    app()
