"""프로젝트 디렉터리를 걸어 의존성 파일을 모으고 어댑터에 파싱을 맡긴다.

어떤 파일이 어느 생태계 것인지는 어댑터(``manifest_filenames``)만 안다 — 여기서 pip/npm 을
하드코딩하지 않는다. 읽기만 하며 프로젝트의 어떤 코드도 실행하지 않는다.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import ecosystems
from ecosystems.base import Dependency

#: 의존성이 아닌 것(가상환경·vendor·빌드 산출물)이 들어 있는 디렉터리. 거기 있는 lockfile 은
#: 사용자 프로젝트의 것이 아니라 남의 패키지 것이라 결과를 오염시킨다.
SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", ".tox", ".nox",
    "__pycache__", "vendor", "third_party", "dist", "build", "target", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".idea", ".gradle", "site-packages", "bower_components",
})
MAX_DEPTH = 8
MAX_FILE_BYTES = 8 * 1024 * 1024

#: 같은 디렉터리·생태계에 둘 다 있을 때 앞선 것이 이긴다 (잠긴 버전 > 범위 선언).
_LOCK_HINTS = ("lock", "sum", "mod", "resolved", "packages.config")


def _is_lock(filename: str) -> bool:
    return any(h in filename for h in _LOCK_HINTS)


@dataclass
class Discovery:
    dependencies: list[Dependency] = field(default_factory=list)
    #: 읽은 파일 (루트 기준 상대 경로)
    files: list[str] = field(default_factory=list)
    #: (경로, 사유) — 못 읽은 파일. 조용히 버리지 않고 보고서에 싣는다.
    errors: list[tuple[str, str]] = field(default_factory=list)
    #: 같은 키로 합쳐졌을 때 모든 출처 경로
    sources: dict[tuple[str, str, str | None], list[str]] = field(default_factory=dict)


def _safe_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root)
    except ValueError:
        return False
    return True


def discover(root: str | Path) -> Discovery:
    root = Path(root).resolve()
    result = Discovery()
    ecos = ecosystems.available()
    names: dict[str, list[ecosystems.Ecosystem]] = {}
    for eco in ecos:
        for fn in eco.manifest_filenames:
            names.setdefault(fn.lower(), []).append(eco)

    if root.is_file():
        entries = [(root.parent, [root.name])]
        walk = iter(entries)
        root = root.parent
    else:
        walk = ((Path(d), files) for d, files in _walk(root))

    merged: dict[tuple[str, str, str | None], Dependency] = {}
    for directory, files in walk:
        by_eco: dict[str, list[tuple[str, ecosystems.Ecosystem]]] = {}
        for fn in sorted(files):
            for eco in ecos:
                if not (eco in names.get(fn.lower(), ()) or eco.handles_filename(fn)):
                    continue
                by_eco.setdefault(eco.id, []).append((fn, eco))
        for _eco_id, cands in by_eco.items():
            has_lock = any(_is_lock(fn.lower()) for fn, _ in cands)
            for fn, eco in cands:
                if has_lock and not _is_lock(fn.lower()):
                    continue  # lockfile 이 있으면 범위만 적은 manifest 는 읽지 않는다
                path = directory / fn
                rel = path.relative_to(root).as_posix()
                if not _safe_inside(path, root):
                    result.errors.append((rel, "루트 밖을 가리키는 링크 — 건너뜀"))
                    continue
                try:
                    if path.stat().st_size > MAX_FILE_BYTES:
                        result.errors.append((rel, f"{MAX_FILE_BYTES} 바이트 초과 — 건너뜀"))
                        continue
                    text = path.read_text(encoding="utf-8-sig", errors="replace")
                    deps = eco.parse_manifest(fn, text)
                except (OSError, ValueError) as exc:
                    result.errors.append((rel, str(exc)))
                    continue
                result.files.append(rel)
                for dep in deps:
                    key = (dep.ecosystem, eco.normalize_name(dep.name), dep.version)
                    if key not in merged:
                        merged[key] = Dependency(
                            dep.ecosystem, dep.name, dep.version, spec=dep.spec,
                            source=rel, direct=dep.direct)
                    result.sources.setdefault(key, [])
                    if rel not in result.sources[key]:
                        result.sources[key].append(rel)
    result.dependencies = list(merged.values())
    return result


def _walk(root: Path):
    """os.walk 래퍼 — 심볼릭 링크 디렉터리는 따라가지 않고, 깊이·제외 디렉터리를 제한한다."""
    base_depth = len(root.parts)
    for d, dirs, files in os.walk(root, followlinks=False):
        depth = len(Path(d).parts) - base_depth
        dirs[:] = sorted(
            x for x in dirs
            if x not in SKIP_DIRS and not x.endswith(".egg-info")
            and not (Path(d) / x).is_symlink()
        )
        if depth >= MAX_DEPTH:
            dirs[:] = []
        yield d, files
