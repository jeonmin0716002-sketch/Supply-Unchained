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
