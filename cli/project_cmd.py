"""``su-scan project`` · ``su-scan sbom`` — 프로젝트 디렉터리·SBOM 전체 스캔.

종료 코드는 su_scan 과 같다: 0 통과, 1 차단(--fail-on 기준), 2 환경·입력 오류.
``cli.su_scan`` 이 guarded import 로 ``register(app)`` 을 부른다. 단독 실행도 된다:
    uv run python -m cli.project_cmd project .
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure") and (_s.encoding or "").lower().replace("-", "") not in (
            "utf8", "utf8sig"):
        _s.reconfigure(encoding="utf-8", errors="replace")

console = Console()
_COLOR = {"safe": "green", "warn": "yellow", "block": "red"}
_FORMATS = ("table", "json", "cyclonedx")
_FAIL_ON = ("block", "warn", "vuln-high", "vuln-critical")


def _check_opts(mode: str, fmt: str, fail_on: str) -> None:
    for val, allowed, flag in ((mode, ("fast", "full"), "--mode"), (fmt, _FORMATS, "--format"),
                               (fail_on, _FAIL_ON, "--fail-on")):
        if val not in allowed:
            console.print(f"[red]{flag} 는 {' | '.join(allowed)} 중 하나[/red]")
            raise typer.Exit(code=2)


def _report_json(report, deps_note: dict) -> dict:
    return {
        "mode": report.mode, "counts": report.counts(),
        "rows": [{
            "ecosystem": r.dep.ecosystem, "name": r.dep.name, "version": r.dep.version,
            "verdict": r.verdict, "risk_score": r.risk_score, "error": r.error,
            "sources": r.sources, "reasons": r.reasons, "findings": r.findings,
            "vulnerabilities": [{"id": v.id, "severity": v.severity.value, "fixed": v.fixed,
                                 "summary": v.summary} for v in r.vulns]}
            for r in report.rows],
        "unchecked": [{"ecosystem": d.ecosystem, "name": d.name, "spec": d.spec, "reason": why}
                      for d, why in report.unchecked],
        **deps_note,
    }


def _render_table(report, notes: list[str]) -> None:
    t = Table(title=f"의존성 {len(report.rows)}개 스캔 ({report.mode})", title_justify="left")
    for col in ("생태계", "패키지", "판정", "취약점", "사유"):
        t.add_column(col)
    for r in report.rows:
        color = "white" if r.error else _COLOR.get(r.verdict, "white")
        vulns = ", ".join(f"{v.id}({v.severity.value})" for v in r.vulns[:3]) or "-"
        if len(r.vulns) > 3:
            vulns += f" +{len(r.vulns) - 3}"
        label = "ERROR" if r.error else r.verdict
        t.add_row(r.dep.ecosystem, escape(f"{r.dep.name}=={r.dep.version}"),
                  f"[{color}]{label}[/{color}]", escape(vulns),
                  escape("; ".join(r.reasons) or "-"))
    console.print(t)
    if report.unchecked:
        console.print(f"[yellow]확인 못 함 {len(report.unchecked)}건[/yellow]")
        for d, why in report.unchecked[:20]:
            console.print(f"  [dim]{escape(d.ecosystem)}/{escape(d.name)} {escape(d.spec)}"
                          f" — {escape(why)}[/dim]")
    for n in notes:
        console.print(f"[dim]{escape(n)}[/dim]")
    console.print(f"[dim]요약: {report.counts()}[/dim]")


async def _run(deps, sources, mode, fail_on):
    from inventory.scan import scan_dependencies

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(120.0), headers={"User-Agent": "supply-unchained-cli/0.1"},
        limits=httpx.Limits(max_connections=20),
    ) as client:
        return await scan_dependencies(deps, mode=mode, client=client, sources=sources)


def _finish(deps, sources, mode, fmt, output, fail_on, notes, extra):
    try:
        report = asyncio.run(_run(deps, sources, mode, fail_on))
    except (httpx.HTTPError, OSError) as exc:
        console.print(f"[red]스캔 환경 오류:[/red] {escape(str(exc))}")
        raise typer.Exit(code=2) from exc
    if fmt == "table":
        _render_table(report, notes)
        text = None
    elif fmt == "json":
        text = json.dumps(_report_json(report, extra), ensure_ascii=False, indent=2)
    else:
        from inventory.sbom import write_cyclonedx

        text = json.dumps(write_cyclonedx([r.dep for r in report.rows] +
                                          [d for d, _ in report.unchecked],
                                          report.results_map()), ensure_ascii=False, indent=2)
    if text is not None:
        if output:
            Path(output).write_text(text, encoding="utf-8")
            console.print(f"[dim]{escape(str(output))} 에 저장[/dim]")
        else:
            sys.stdout.write(text + "\n")
    elif output:
        Path(output).write_text(
            json.dumps(_report_json(report, extra), ensure_ascii=False, indent=2), encoding="utf-8")
    if report.fails(fail_on):
        Console(stderr=True).print(f"[red]⛔ --fail-on {fail_on} 기준 실패 (조회 오류 포함).[/red]")
        raise typer.Exit(code=1)
    if fmt == "table":
        console.print("[green]✅ 통과.[/green]")


def register(app: typer.Typer) -> None:
    @app.command("project")
    def project(
        path: str = typer.Argument(".", help="프로젝트 디렉터리 (또는 의존성 파일)"),
        mode: str = typer.Option("fast", help="fast: 알려진 취약점만 | full: 패키지별 전체 스캔"),
        fmt: str = typer.Option("table", "--format", help="table | json | cyclonedx"),
        output: str = typer.Option(None, "--output", help="결과를 쓸 파일"),
        fail_on: str = typer.Option("block", "--fail-on",
                                    help="block | warn | vuln-high | vuln-critical"),
    ) -> None:
        """프로젝트의 모든 lockfile·manifest 의존성을 스캔한다 (설치·실행 없음)."""
        _check_opts(mode, fmt, fail_on)
        from inventory.discover import discover

        if not Path(path).exists():
            console.print(f"[red]경로를 찾을 수 없습니다:[/red] {escape(path)}")
            raise typer.Exit(code=2)
        found = discover(path)
        notes = [f"읽은 파일: {', '.join(found.files) or '없음'}"]
        notes += [f"읽기 실패 {p}: {why}" for p, why in found.errors]
        if not found.dependencies:
            console.print("[yellow]의존성을 찾지 못했습니다.[/yellow] " + escape(notes[0]))
            raise typer.Exit(code=2 if found.errors else 0)
        _finish(found.dependencies, found.sources, mode, fmt, output, fail_on, notes,
                {"files": found.files, "read_errors": found.errors})

    @app.command("sbom")
    def sbom(
        file: str = typer.Argument(..., help="CycloneDX/SPDX JSON 파일"),
        mode: str = typer.Option("fast", help="fast | full"),
        fmt: str = typer.Option("table", "--format", help="table | json | cyclonedx"),
        output: str = typer.Option(None, "--output", help="결과를 쓸 파일"),
        fail_on: str = typer.Option("block", "--fail-on",
                                    help="block | warn | vuln-high | vuln-critical"),
    ) -> None:
        """SBOM 의 구성요소를 스캔한다."""
        _check_opts(mode, fmt, fail_on)
        from inventory.sbom import read_sbom

        try:
            read = read_sbom(Path(file).read_text(encoding="utf-8"), source=file)
        except OSError:
            console.print(f"[red]파일을 읽을 수 없습니다:[/red] {escape(file)}")
            raise typer.Exit(code=2) from None
        except ValueError as exc:
            console.print(f"[red]SBOM 형식 오류:[/red] {escape(str(exc))}")
            raise typer.Exit(code=2) from exc
        notes = [f"지원하지 않는 purl {len(read.unsupported)}건: {', '.join(read.unsupported[:5])}"
                 ] if read.unsupported else []
        _finish(read.dependencies, {}, mode, fmt, output, fail_on, notes,
                {"unsupported_purls": read.unsupported})


if __name__ == "__main__":
    _app = typer.Typer(no_args_is_help=True)
    register(_app)
    _app()
