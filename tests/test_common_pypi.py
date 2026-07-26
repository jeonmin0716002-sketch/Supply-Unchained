"""Safety tests for the shared PyPI fetcher.

This module unpacks archives that are hostile by assumption, so the limits are
the point -- a scanner that can be attacked by the package it is scanning is
worse than no scanner. Everything here is offline.
"""

from __future__ import annotations

import io
import tarfile
import zipfile

import httpx
import pytest

from common.pypi import (
    MAX_ARTIFACT_BYTES,
    ArchiveError,
    Artifact,
    PackageContext,
    PackageNotFound,
    PyPIError,
    download,
    extract,
    fetch_project,
    is_safe_member_name,
    select_artifact,
)


def make_tar(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, payload in entries.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def make_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, payload in entries.items():
            zf.writestr(name, payload)
    return buf.getvalue()


# ──────────────────────────────
# path safety
# ──────────────────────────────


@pytest.mark.parametrize(
    "name",
    [
        "../../etc/passwd",
        "pkg/../../escape.py",
        "/absolute/path.py",
        "\\windows\\style.py",
        "C:/Windows/System32/evil.dll",
        "..",
        "",
    ],
)
def test_unsafe_member_names_rejected(name):
    assert is_safe_member_name(name) is False


@pytest.mark.parametrize(
    "name",
    ["pkg/setup.py", "pkg-1.0/src/mod.py", "install.pth", "a/b/c/d.txt"],
)
def test_safe_member_names_accepted(name):
    assert is_safe_member_name(name) is True


def test_tar_zip_slip_is_rejected(tmp_path):
    data = make_tar({"../escaped.py": b"pwned"})
    with pytest.raises(ArchiveError, match="unsafe archive path"):
        extract(data, "evil-1.0.tar.gz", tmp_path)


def test_zip_slip_is_rejected(tmp_path):
    data = make_zip({"../../escaped.py": b"pwned"})
    with pytest.raises(ArchiveError, match="unsafe archive path"):
        extract(data, "evil-1.0.zip", tmp_path)


def test_nothing_is_written_outside_dest(tmp_path):
    dest = tmp_path / "out"
    outside = tmp_path / "escaped.py"
    with pytest.raises(ArchiveError):
        extract(make_tar({"../escaped.py": b"pwned"}), "evil.tar.gz", dest)
    assert not outside.exists()


# ──────────────────────────────
# resource limits
# ──────────────────────────────


def test_tar_decompression_bomb_is_rejected(tmp_path, monkeypatch):
    """Highly compressible payloads must be capped by *uncompressed* size.

    The cap is patched down rather than allocating a real 200 MB bomb; the code
    path under test is identical, and the compressed size of this archive is a
    couple of hundred bytes -- which is exactly why a compressed-size check
    alone is not enough.
    """
    monkeypatch.setattr("common.pypi.MAX_UNCOMPRESSED_BYTES", 1024)
    data = make_tar({"bomb.bin": b"\0" * 65536})
    assert len(data) < 1024  # tiny on the wire, 64 KB once unpacked
    with pytest.raises(ArchiveError, match="decompression bomb"):
        extract(data, "bomb-1.0.tar.gz", tmp_path)


def test_zip_decompression_bomb_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr("common.pypi.MAX_UNCOMPRESSED_BYTES", 1024)
    data = make_zip({"bomb.bin": b"\0" * 65536})
    with pytest.raises(ArchiveError, match="decompression bomb"):
        extract(data, "bomb-1.0.zip", tmp_path)


def test_too_many_members_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr("common.pypi.MAX_MEMBERS", 5)
    data = make_tar({f"pkg/mod{i}.py": b"x = 1\n" for i in range(20)})
    with pytest.raises(ArchiveError, match="more than 5 members"):
        extract(data, "many-1.0.tar.gz", tmp_path)


def test_unsupported_format_is_rejected(tmp_path):
    with pytest.raises(ArchiveError, match="unsupported archive format"):
        extract(b"not an archive", "package-1.0.rar", tmp_path)


def test_corrupt_archive_raises_archive_error(tmp_path):
    with pytest.raises(ArchiveError, match="could not unpack"):
        extract(b"definitely not a tarball", "broken-1.0.tar.gz", tmp_path)


async def test_download_rejects_declared_oversize():
    """Content-Length over the cap is refused before any body is buffered."""
    body_seen = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal body_seen
        body_seen = True
        return httpx.Response(
            200,
            headers={"content-length": str(MAX_ARTIFACT_BYTES + 1)},
            content=b"x",
        )

    art = Artifact(filename="big.tar.gz", packagetype="sdist", url="https://x/big.tar.gz")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ArchiveError, match="over the limit"):
            await download(art, client=client)
    assert body_seen  # the request happened, but the body was not accepted


async def test_download_rejects_oversize_from_release_metadata():
    """PyPI already tells us the size; refuse before opening a connection."""
    art = Artifact(
        filename="big.tar.gz",
        packagetype="sdist",
        url="https://x/big.tar.gz",
        size=MAX_ARTIFACT_BYTES + 1,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not be requested at all")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ArchiveError, match="over the"):
            await download(art, client=client)


# ──────────────────────────────
# extraction happy path
# ──────────────────────────────


def test_tar_extracts_and_is_analysable(tmp_path):
    data = make_tar({"pkg-1.0/setup.py": b"import os\n", "pkg-1.0/install.pth": b"import x\n"})
    root = extract(data, "pkg-1.0.tar.gz", tmp_path)
    assert (root / "pkg-1.0" / "setup.py").read_text() == "import os\n"
    assert (root / "pkg-1.0" / "install.pth").exists()


def test_wheel_is_extracted_as_zip(tmp_path):
    """Wheels matter: they cannot carry setup.py but they can carry .pth."""
    data = make_zip({"pkg/install.pth": b"import evil\n"})
    root = extract(data, "pkg-1.0-py3-none-any.whl", tmp_path)
    assert (root / "pkg" / "install.pth").exists()


@pytest.mark.parametrize("suffix", [".tar.gz", ".tgz", ".tar"])
def test_multiple_tar_compressions_supported(tmp_path, suffix):
    """Hard-coding r:gz silently skipped other formats -- regression guard."""
    data = make_tar({"pkg/mod.py": b"x = 1\n"})
    root = extract(data, f"pkg-1.0{suffix}", tmp_path / suffix.replace(".", "_"))
    assert (root / "pkg" / "mod.py").exists()


# ──────────────────────────────
# artifact selection / project fetch
# ──────────────────────────────


def test_sdist_is_preferred_over_wheel():
    arts = [
        Artifact("p-1.0-py3-none-any.whl", "bdist_wheel", "https://x/w"),
        Artifact("p-1.0.tar.gz", "sdist", "https://x/s"),
    ]
    assert select_artifact(arts).is_sdist


def test_wheel_used_when_no_sdist():
    arts = [Artifact("p-1.0-py3-none-any.whl", "bdist_wheel", "https://x/w")]
    assert select_artifact(arts).filename.endswith(".whl")


def test_no_artifacts_selects_nothing():
    assert select_artifact([]) is None


async def test_missing_project_raises_package_not_found():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(PackageNotFound):
            await fetch_project("no-such-package", client=client)


async def test_upstream_error_is_not_package_not_found():
    """'PyPI is down' and 'the package does not exist' are different facts."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(PyPIError) as caught:
            await fetch_project("requests", client=client)
        assert not isinstance(caught.value, PackageNotFound)


# ──────────────────────────────
# PackageContext — one fetch per scan
# ──────────────────────────────


def _project_and_artifact_transport(counter: dict[str, int]) -> httpx.MockTransport:
    sdist = make_tar({"pkg-1.0/setup.py": b"import os\nos.system('id')\n"})

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/json"):
            counter["json"] = counter.get("json", 0) + 1
            return httpx.Response(
                200,
                json={
                    "info": {"requires_dist": []},
                    "releases": {
                        "1.0": [
                            {
                                "filename": "pkg-1.0.tar.gz",
                                "packagetype": "sdist",
                                "url": "https://files.example/pkg-1.0.tar.gz",
                                "size": len(sdist),
                            }
                        ]
                    },
                },
            )
        counter["artifact"] = counter.get("artifact", 0) + 1
        return httpx.Response(200, content=sdist)

    return httpx.MockTransport(handler)


async def test_context_downloads_and_extracts():
    """Regression: extracted_path() needs the project JSON, and both were once
    guarded by the same non-reentrant lock -- which deadlocked every scan."""
    counter: dict[str, int] = {}
    client = httpx.AsyncClient(transport=_project_and_artifact_transport(counter))
    async with PackageContext("pkg", "1.0", client=client) as ctx:
        root = await ctx.extracted_path()
        assert root is not None
        assert (root / "pkg-1.0" / "setup.py").exists()
    await client.aclose()


async def test_context_fetches_each_thing_once():
    """The whole point of sharing a context: no duplicate downloads per scan."""
    counter: dict[str, int] = {}
    client = httpx.AsyncClient(transport=_project_and_artifact_transport(counter))
    async with PackageContext("pkg", "1.0", client=client) as ctx:
        await ctx.project()
        await ctx.project()
        await ctx.extracted_path()
        await ctx.extracted_path()
        await ctx.archive_names()
    await client.aclose()

    assert counter["json"] == 1
    assert counter["artifact"] == 1


async def test_context_cleans_up_extracted_files():
    counter: dict[str, int] = {}
    client = httpx.AsyncClient(transport=_project_and_artifact_transport(counter))
    async with PackageContext("pkg", "1.0", client=client) as ctx:
        root = await ctx.extracted_path()
    await client.aclose()
    assert root is not None and not root.exists()


async def test_context_reraises_cached_failure():
    """A failed lookup must not be silently retried into a different answer."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(404)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    async with PackageContext("ghost", "1.0", client=client) as ctx:
        for _ in range(3):
            with pytest.raises(PackageNotFound):
                await ctx.project()
    await client.aclose()
    assert calls["n"] == 1


async def test_project_parses_releases():
    payload = {
        "info": {"requires_dist": ["urllib3 (>=1.21)"]},
        "releases": {
            "1.0.0": [
                {
                    "filename": "p-1.0.0.tar.gz",
                    "packagetype": "sdist",
                    "url": "https://x/p.tar.gz",
                    "size": 1234,
                }
            ]
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        project = await fetch_project("p", client=client)

    assert project.has_version("1.0.0")
    assert not project.has_version("9.9.9")
    art = select_artifact(project.artifacts("1.0.0"))
    assert art.is_sdist and art.size == 1234
