"""NuGet 의존성 파일 파서.

* ``packages.lock.json`` — 해석된 정확한 버전(전이 포함). ``type == Direct`` 가 직접 의존성.
* ``packages.config`` — 레거시. 정확한 버전.
* ``*.csproj`` / ``*.fsproj`` / ``*.vbproj`` — ``PackageReference``. 버전이 리터럴이면 그대로,
  속성(``$(X)``)·부동(``1.*``)·범위·중앙 관리(Version 없음)면 ``version=None``, ``spec`` 에 원문.
* ``Directory.Packages.props`` — 중앙 버전 관리의 ``PackageVersion``.
"""

from __future__ import annotations

import json
import re

from ecosystems.base import Dependency
from ecosystems.nuget._xml import parse_xml

PROJECT_SUFFIXES = (".csproj", ".fsproj", ".vbproj")
_EXACT = re.compile(r"^\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


def handles_filename(filename: str) -> bool:
    """고정 이름이 아닌 프로젝트 파일(``Foo.csproj``)까지 포함해 읽을 수 있는 파일인가.
    inventory 가 ``manifest_filenames`` 정확 일치 대신 쓸 수 있다."""
    low = filename.lower().rsplit("/", 1)[-1]
    return (
        low in ("packages.lock.json", "packages.config", "directory.packages.props")
        or low.endswith(PROJECT_SUFFIXES)
    )


def _exact_version(raw: str | None) -> str | None:
    if not raw:
        return None
    raw = raw.strip()
    if raw.startswith("[") and raw.endswith("]") and "," not in raw:
        raw = raw[1:-1].strip()  # [1.2.3] = 정확히 그 버전
    return raw if _EXACT.match(raw) else None


def _lockfile(text: str, source: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"packages.lock.json 파싱 실패: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("packages.lock.json 형식이 아닙니다")
    best: dict[str, Dependency] = {}
    for deps in (data.get("dependencies") or {}).values():
        if not isinstance(deps, dict):
            continue
        for name, info in deps.items():
            if not isinstance(info, dict):
                continue
            kind = info.get("type")
            if kind == "Project":
                continue  # 솔루션 내부 프로젝트
            resolved = info.get("resolved")
            dep = Dependency(
                ecosystem="nuget", name=name,
                version=resolved if isinstance(resolved, str) else None,
                spec=str(info.get("requested", "")), source=source,
                direct=True if kind == "Direct" else (False if kind == "Transitive" else None),
            )
            key = f"{name.lower()}@{dep.version}"
            if key not in best or dep.direct:
                best[key] = dep
    return list(best.values())


def _packages_config(text: str, source: str) -> list[Dependency]:
    root = parse_xml(text)
    out = []
    for el in root.iter("package"):
        name = el.get("id")
        if name:
            out.append(Dependency(
                ecosystem="nuget", name=name, version=_exact_version(el.get("version")),
                spec=el.get("version") or "", source=source, direct=True,
            ))
    return out


def _project_file(text: str, source: str, tags: tuple[str, ...]) -> list[Dependency]:
    root = parse_xml(text)
    out = []
    for el in root.iter():
        if el.tag not in tags:
            continue
        name = el.get("Include")
        if not name:
            continue  # Update/Remove 는 새 의존성이 아니다
        raw = el.get("Version")
        if raw is None:
            child = el.find("Version")
            raw = child.text.strip() if child is not None and child.text else None
        out.append(Dependency(
            ecosystem="nuget", name=name, version=_exact_version(raw),
            spec=raw or "", source=source, direct=True,
        ))
    return out


def parse_manifest(filename: str, text: str) -> list[Dependency]:
    low = filename.lower().rsplit("/", 1)[-1]
    if low == "packages.lock.json":
        return _lockfile(text, filename)
    if low == "packages.config":
        return _packages_config(text, filename)
    if low == "directory.packages.props":
        return _project_file(text, filename, ("PackageVersion",))
    if low.endswith(PROJECT_SUFFIXES):
        return _project_file(text, filename, ("PackageReference",))
    return []
