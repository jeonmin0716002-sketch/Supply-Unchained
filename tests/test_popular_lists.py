"""Offline checks for the bundled popular-package lists (ecosystems/data/popular/*.txt)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ecosystems.base import _POPULAR_DIR, load_popular

LIST_FILES = sorted(_POPULAR_DIR.glob("*.txt"))


def _names(path: Path) -> list[str]:
    out: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        name = line.split("#", 1)[0].strip()
        if name:
            out.append(name)
    return out


def test_list_files_exist() -> None:
    assert LIST_FILES, "no popular list files found"


@pytest.mark.parametrize("path", LIST_FILES, ids=lambda p: p.stem)
def test_no_duplicates(path: Path) -> None:
    names = _names(path)
    assert len(names) == len(set(names)), f"duplicate names in {path.name}"


@pytest.mark.parametrize("path", LIST_FILES, ids=lambda p: p.stem)
def test_no_blank_or_whitespace_names(path: Path) -> None:
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.split("#", 1)[0]
        if not stripped.strip():
            continue  # blank line or pure comment
        name = stripped.strip()
        assert not any(ch.isspace() for ch in name), f"whitespace in name {name!r} in {path.name}"


@pytest.mark.parametrize("path", LIST_FILES, ids=lambda p: p.stem)
def test_load_popular_loads_the_file(path: Path) -> None:
    loaded = load_popular(path.stem)
    assert loaded == frozenset(_names(path))
    assert loaded, f"{path.name} loaded as empty"
