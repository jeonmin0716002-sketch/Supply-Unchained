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
