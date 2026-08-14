"""su-scan — Supply-Unchained CLI.

pip 앞단에서 스캔을 태우는 두 가지 진입점 중 "명시 호출" 쪽 구현.
(다른 하나는 pip 프록시 — api/routers/proxy.py 참고.)

사용:
    uv run python -m cli.su_scan check requests==2.31.0
    uv run python -m cli.su_scan check reqeusts            # 버전 생략 → 최신 버전 조회
    uv run python -m cli.su_scan install requests==2.31.0  # 스캔 통과 시에만 pip install
    uv run python -m cli.su_scan history                   # 최근 스캔 이력

환경변수:
    SU_API_URL   API 주소 (기본 http://localhost:8000)
"""

from __future__ import annotations

import os
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
        console.print(f"[red]최신 버전 조회 실패:[/red] {name} — {exc}")
        raise typer.Exit(code=2) from exc


def _scan(name: str, version: str) -> dict:
    try:
        resp = httpx.post(
            f"{_api_url()}/api/v1/scan",
            json={"ecosystem": "pip", "name": name, "version": version},
            timeout=_TIMEOUT,
        )
    except httpx.HTTPError as exc:
        console.print(
            f"[red]API 연결 실패:[/red] {_api_url()} — {exc}\n"
            f"서버 실행: [bold]uv run uvicorn api.main:app[/bold]"
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

    console.print(f"[dim]scan_id={result['scan_id']} · 대시보드 {_api_url()}/dashboard[/dim]")


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
    try:
        resp = httpx.get(f"{_api_url()}/api/v1/scans", params={"limit": limit}, timeout=15.0)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        console.print(f"[red]API 연결 실패:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    t = Table(title=f"최근 스캔 {limit}건", title_justify="left")
    for col in ("id", "패키지", "판정", "점수", "시각"):
        t.add_column(col)
    for r in resp.json():
        _label, color = _style(r["verdict"])
        t.add_row(
            str(r["scan_id"]),
            f"{r['name']}=={r['version']}",
            f"[{color}]{r['verdict']}[/{color}]",
            str(r["risk_score"]),
            r["scanned_at"][:19].replace("T", " "),
        )
    console.print(t)


if __name__ == "__main__":
    app()
