"""inventory 세션 테스트 — 전부 오프라인."""

from __future__ import annotations

import json

import pytest

from ecosystems.pip.manifests import parse_manifest


def _by(deps):
    return {d.name: d for d in deps}


def test_requirements_pins_hashes_markers_comments():
    text = (
        "# 주석\n"
        "-r base.txt\n"
        "--index-url https://example.org/simple\n"
        "requests==2.31.0 \\\n    --hash=sha256:abc \\\n    --hash=sha256:def\n"
        "Flask_Login>=0.6  # 범위\n"
        "pywin32==306 ; sys_platform == 'win32'\n"
        "uvicorn[standard]==0.30.1\n"
        "unpinned\n"
        "git+https://github.com/x/y.git#egg=y\n"
    )
    d = _by(parse_manifest("requirements.txt", text))
    assert d["requests"].version == "2.31.0"
    assert d["flask-login"].version is None and d["flask-login"].spec == ">=0.6"
    assert d["pywin32"].version == "306"
    assert d["uvicorn"].version == "0.30.1"
    assert d["unpinned"].version is None
    assert "y" not in d and len(d) == 5


def test_toml_lockfiles_skip_virtual_projects():
    uv = (
        'version = 1\n[[package]]\nname = "Foo_Bar"\nversion = "1.2.3"\n'
        '[[package]]\nname = "me"\nversion = "0.1"\nsource = { virtual = "." }\n'
    )
    d = parse_manifest("uv.lock", uv)
    assert [(x.name, x.version) for x in d] == [("foo-bar", "1.2.3")]
    poetry = '[[package]]\nname = "attrs"\nversion = "23.1.0"\n'
    assert parse_manifest("sub/poetry.lock", poetry)[0].version == "23.1.0"
    assert parse_manifest("pdm.lock", poetry)[0].name == "attrs"


def test_pipfile_lock():
    text = json.dumps({"default": {"requests": {"version": "==2.31.0"}},
                       "develop": {"pytest": {"version": "*"}}})
    d = _by(parse_manifest("Pipfile.lock", text))
    assert d["requests"].version == "2.31.0"
    assert d["pytest"].version is None


def test_pyproject_pep621_and_poetry():
    text = (
        '[project]\nname="x"\ndependencies=["httpx>=0.27", "pydantic==2.7.0"]\n'
        '[project.optional-dependencies]\ndev=["pytest>=8"]\n'
        '[tool.poetry.dependencies]\npython="^3.12"\nrich="^13"\n'
    )
    d = _by(parse_manifest("pyproject.toml", text))
    assert d["pydantic"].version == "2.7.0"
    assert d["httpx"].version is None
    assert "pytest" in d and "rich" in d and "python" not in d


def test_broken_file_raises_value_error():
    with pytest.raises(ValueError):
        parse_manifest("uv.lock", "[[package")
    with pytest.raises(ValueError):
        parse_manifest("Pipfile.lock", "{")


# ── discover ──────────────────────────────────────────────────────────

import ecosystems  # noqa: E402
from ecosystems.base import Dependency, Ecosystem  # noqa: E402
from inventory.discover import discover  # noqa: E402


class FakeEco(Ecosystem):
    id = "fake"
    osv_ecosystem = "Fake"
    purl_type = "fake"
    registry_label = "Fake"
    manifest_filenames = ("fake.lock", "fake.json")

    async def fetch_project(self, name, *, client):
        raise NotImplementedError

    def analyze_tree(self, tree, *, artifact=None):
        return []

    def parse_manifest(self, filename, text):
        if text.strip() == "BAD":
            raise ValueError("깨짐")
        return [Dependency("fake", n.strip(), "1.0") for n in text.split(",") if n.strip()]


@pytest.fixture
def fake_eco(monkeypatch):
    monkeypatch.setattr(ecosystems, "available", lambda: [FakeEco()])


def test_discover_prefers_lock_dedupes_and_skips(tmp_path, fake_eco):
    (tmp_path / "fake.lock").write_text("A,b")
    (tmp_path / "fake.json").write_text("zzz")  # lock 이 있으니 읽히면 안 됨
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "fake.json").write_text("A")  # manifest 만 있는 디렉터리
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "fake.lock").write_text("evil")
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "fake.lock").write_text("BAD")
    r = discover(tmp_path)
    assert sorted(d.name for d in r.dependencies) == ["A", "b"]
    key = ("fake", "a", "1.0")
    assert sorted(r.sources[key]) == ["fake.lock", "sub/fake.json"]
    assert [e[0] for e in r.errors] == ["bad/fake.lock"]


def test_discover_does_not_follow_symlink_out_of_root(tmp_path, fake_eco):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "fake.lock").write_text("leak")
    proj = tmp_path / "proj"
    proj.mkdir()
    try:
        (proj / "link").symlink_to(outside, target_is_directory=True)
        (proj / "fake.lock").symlink_to(outside / "fake.lock")
    except (OSError, NotImplementedError):
        pytest.skip("심볼릭 링크를 만들 수 없는 환경")
    r = discover(proj)
    assert r.dependencies == []
    assert r.errors and "루트 밖" in r.errors[0][1]


# ── sbom ──────────────────────────────────────────────────────────────

from inventory.sbom import parse_purl, read_sbom, write_cyclonedx  # noqa: E402


class _Maven(FakeEco):
    id = "maven"
    purl_type = "maven"


class _Npm(FakeEco):
    id = "npm"
    purl_type = "npm"


@pytest.fixture
def sbom_ecos(monkeypatch):
    monkeypatch.setattr(ecosystems, "available", lambda: [FakeEco(), _Maven(), _Npm()])


def test_parse_purl_variants():
    assert parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1") == (
        "maven", "org.apache.logging.log4j:log4j-core", "2.14.1")
    assert parse_purl("pkg:npm/%40babel/core@7.0.0") == ("npm", "@babel/core", "7.0.0")
    assert parse_purl("pkg:golang/github.com/foo/bar@v1.2.3?type=x#sub") == (
        "golang", "github.com/foo/bar", "v1.2.3")
    assert parse_purl("pkg:npm/left-pad") == ("npm", "left-pad", None)
    assert parse_purl("notapurl") is None


def test_sbom_round_trip_and_vulns(sbom_ecos):
    deps = [Dependency("npm", "@babel/core", "7.0.0"),
            Dependency("maven", "org.x:y", "1.0"),
            Dependency("npm", "left-pad", None)]
    results = {("npm", "@babel/core", "7.0.0"): {
        "verdict": "warn", "findings": ["rule-a"],
        "vulns": [{"id": "GHSA-1", "severity": "high", "summary": "s", "fixed": "7.1"}]}}
    bom = write_cyclonedx(deps, results)
    assert bom["specVersion"] == "1.5"
    assert bom["vulnerabilities"][0]["affects"][0]["ref"] == "pkg:npm/%40babel/core@7.0.0"
    back = read_sbom(json.dumps(bom))
    assert [(d.ecosystem, d.name, d.version) for d in back.dependencies] == [
        (d.ecosystem, d.name, d.version) for d in deps]


def test_read_spdx_and_unsupported(sbom_ecos):
    doc = {"spdxVersion": "SPDX-2.3", "packages": [
        {"externalRefs": [{"referenceType": "purl",
                           "referenceLocator": "pkg:npm/left-pad@1.3.0"}]},
        {"externalRefs": [{"referenceType": "purl",
                           "referenceLocator": "pkg:hex/plug@1.0"}]}]}
    r = read_sbom(json.dumps(doc))
    assert [d.name for d in r.dependencies] == ["left-pad"]
    assert r.unsupported == ["pkg:hex/plug@1.0"]
    with pytest.raises(ValueError):
        read_sbom("{}")


# ── osv_batch ─────────────────────────────────────────────────────────

import httpx  # noqa: E402

from inventory import osv_batch  # noqa: E402
from inventory.osv_batch import OsvQuery, query_batch  # noqa: E402


async def _nosleep(_):
    return None


def _osv_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_osv_chunking_pagination_and_hydration(monkeypatch):
    monkeypatch.setattr(osv_batch, "CHUNK", 2)
    posts = []

    def handler(req: httpx.Request):
        if req.method == "POST":
            qs = json.loads(req.content)["queries"]
            posts.append(len(qs))
            res = []
            for q in qs:
                if q["package"]["name"] == "a" and not q.get("page_token"):
                    res.append({"vulns": [{"id": "V1"}], "next_page_token": "t"})
                elif q["package"]["name"] == "a":
                    res.append({"vulns": [{"id": "V2"}]})
                else:
                    res.append({})
            return httpx.Response(200, json={"results": res})
        vid = req.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json={
            "id": vid, "summary": f"sum {vid}", "database_specific": {"severity": "HIGH"},
            "affected": [{"package": {"name": "a"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "2.0"}]}]}]})

    qs = [OsvQuery("PyPI", n, "1") for n in ("a", "b", "c")]
    async with _osv_client(handler) as c:
        out = await query_batch(qs, client=c, sleep=_nosleep)
    assert [v.id for v in out[0].vulns] == ["V1", "V2"]
    assert out[0].vulns[0].fixed == "2.0" and out[0].vulns[0].severity.value == "high"
    assert out[1].vulns == [] and out[1].error is None
    assert sorted(posts) == [1, 1, 2]  # 청크 2개, 그중 a 가 든 청크 한 번 더 (a 만 재질의)


async def test_osv_failure_is_error_not_clean():
    def handler(req):
        return httpx.Response(503)

    async with _osv_client(handler) as c:
        out = await query_batch([OsvQuery("PyPI", "a", "1")], client=c, sleep=_nosleep)
    assert out[0].error and out[0].vulns == []


async def test_osv_detail_failure_marks_error():
    def handler(req):
        if req.method == "POST":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "V9"}]}]})
        return httpx.Response(500)

    async with _osv_client(handler) as c:
        out = await query_batch([OsvQuery("PyPI", "a", "1")], client=c, sleep=_nosleep)
    assert out[0].error and out[0].vulns[0].id == "V9"


# ── scan ──────────────────────────────────────────────────────────────

from inventory.scan import scan_dependencies  # noqa: E402


def _osv_ok(req: httpx.Request):
    if req.method == "POST":
        qs = json.loads(req.content)["queries"]
        return httpx.Response(200, json={"results": [
            {"vulns": [{"id": "V1"}]} if q["package"]["name"] == "vuln" else {} for q in qs]})
    return httpx.Response(200, json={"id": "V1", "database_specific": {"severity": "CRITICAL"}})


DEPS = [Dependency("fake", "vuln", "1.0"), Dependency("fake", "ok", "2.0"),
        Dependency("fake", "loose", None), Dependency("ghost", "x", "1")]


async def test_fast_mode_reports_unchecked_and_severity(fake_eco):
    async with _osv_client(_osv_ok) as c:
        rep = await scan_dependencies(DEPS, mode="fast", client=c)
    assert [r.dep.name for r in rep.rows] == ["vuln", "ok"]
    assert rep.counts()["severity"] == {"critical": 1}
    reasons = {d.name: why for d, why in rep.unchecked}
    assert "unpinned" in reasons["loose"] and "어댑터 없음" in reasons["x"]
    assert rep.fails("vuln-critical") and rep.fails("warn") and not rep.fails("block")


async def test_full_mode_uses_stubbed_scan(fake_eco):
    async def stub(dep):
        if dep.name == "ok":
            raise RuntimeError("boom")
        return {"verdict": "block", "risk_score": 90, "verdict_reasons": ["bad"],
                "static_findings": [{"rule": "r", "severity": "high", "location": "a:1"}]}

    async with _osv_client(_osv_ok) as c:
        rep = await scan_dependencies(DEPS[:2], mode="full", client=c, scan_fn=stub)
    by = {r.dep.name: r for r in rep.rows}
    assert by["vuln"].verdict == "block" and by["vuln"].findings == ["r high a:1"]
    assert by["ok"].error and rep.fails("block")  # 스캔 실패는 통과가 아니다


async def test_osv_error_fails_gate(fake_eco):
    async with _osv_client(lambda r: httpx.Response(500)) as c:
        rep = await scan_dependencies(DEPS[:2], mode="fast", client=c)
    assert all(r.error for r in rep.rows) and rep.fails("block")
