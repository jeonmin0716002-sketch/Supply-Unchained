"""npm 의존성 파일 파서 — package.json · package-lock.json(v1·v2·v3) · npm-shrinkwrap.json ·
yarn.lock(classic·berry) · pnpm-lock.yaml.

YAML 의존성을 넣지 않는다(프로젝트 규칙). yarn.lock 과 pnpm-lock.yaml 은 필요한 키만 줄
단위로 읽는다 — 두 형식 모두 도구가 기계적으로 쓰는 고정된 들여쓰기 구조라 이것으로 충분하다.
깨진 파일은 ValueError (base 계약).
"""

from __future__ import annotations

import json
import re
from pathlib import PurePosixPath

from ecosystems.base import Dependency

_DEP_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def _dep(name: str, version: str | None, spec: str, source: str,
         direct: bool | None) -> Dependency:
    return Dependency(ecosystem="npm", name=name, version=version, spec=spec, source=source,
                      direct=direct)


def _json(text: str, filename: str) -> dict:
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"{filename}: JSON 이 아님 ({exc})") from exc
    if not isinstance(doc, dict):
        raise ValueError(f"{filename}: 최상위가 객체가 아님")
    return doc


_EXACT = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


def parse_package_json(text: str, source: str = "package.json") -> list[Dependency]:
    """직접 의존성. 범위(``^1.2.0``)는 version=None, 원문은 spec 에 둔다."""
    doc = _json(text, source)
    out: list[Dependency] = []
    seen: set[str] = set()
    for field in _DEP_FIELDS:
        deps = doc.get(field)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(spec, str) or name in seen:
                continue
            seen.add(name)
            s = spec.strip()
            exact = s.lstrip("=v") if _EXACT.match(s.lstrip("=v")) else None
            out.append(_dep(name, exact, s, source, True))
    return out


def _lock_name_from_path(path: str) -> str | None:
    """``node_modules/a/node_modules/@s/b`` → ``@s/b``."""
    idx = path.rfind("node_modules/")
    if idx < 0:
        return None
    return path[idx + len("node_modules/"):] or None


def parse_package_lock(text: str, source: str = "package-lock.json") -> list[Dependency]:
    doc = _json(text, source)
    out: list[Dependency] = []
    packages = doc.get("packages")
    if isinstance(packages, dict) and packages:
        # v2·v3: "" 은 루트 프로젝트. 직접 의존성 = 루트가 선언한 이름의 최상위 설치본
        root = packages.get("", {}) if isinstance(packages.get(""), dict) else {}
        direct_names = {n for f in _DEP_FIELDS for n in (root.get(f) or {})}
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict) or meta.get("link"):
                continue
            name = meta.get("name") if isinstance(meta.get("name"), str) else \
                _lock_name_from_path(path)
            version = meta.get("version")
            if not name or not isinstance(version, str):
                continue
            top = path == f"node_modules/{name}"
            out.append(_dep(name, version, meta.get("resolved", "") or "", source,
                            top and name in direct_names))
        return out
    # v1: dependencies 트리 (최상위 키가 직접 의존성인지는 lockfile 만으로 모른다 — requires 와
    # dev 표시로 구분할 수 없어서 최상위 = None, 중첩 = False)
    def walk(deps: object, nested: bool) -> None:
        if not isinstance(deps, dict):
            return
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if isinstance(version, str) and not version.startswith(("file:", "link:")):
                exact = version if _EXACT.match(version) else None
                out.append(_dep(name, exact, version if exact is None else
                                (meta.get("resolved") or ""), source,
                                False if nested else None))
            walk(meta.get("dependencies"), True)

    if "dependencies" not in doc and "packages" not in doc:
        raise ValueError(f"{source}: lockfile 형식이 아님 (packages·dependencies 없음)")
    walk(doc.get("dependencies"), False)
    return out


# ── yarn.lock ────────────────────────────────────────────────────

_YARN_KEY = re.compile(r'^"?((?:@[^@/"\s]+/)?[^@"\s,]+)@')


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


def parse_yarn_lock(text: str, source: str = "yarn.lock") -> list[Dependency]:
    """classic(v1) 은 ``version "1.2.3"``, berry(v2+) 는 ``version: 1.2.3`` 이다. 블록 머리는
    둘 다 들여쓰기 없는 ``"name@range, name@range2":`` 형태. 직접 여부는 yarn.lock 만으로
    모른다(None)."""
    out: list[Dependency] = []
    header: list[str] | None = None
    seen: set[tuple[str, str]] = set()
    if "# yarn lockfile v1" not in text and "__metadata:" not in text and text.strip():
        raise ValueError(f"{source}: yarn.lock 형식이 아님")
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith((" ", "\t")):
            line = raw.rstrip()
            if line.endswith(":") and not line.startswith("__metadata"):
                header = [_unquote(p) for p in line[:-1].split(",")]
            else:
                header = None
            continue
        if header is None:
            continue
        stripped = raw.strip()
        m = re.match(r'^version:?\s+"?([^"\s]+)"?$', stripped)
        if not m:
            continue
        version = m.group(1)
        specs = []
        name = None
        for h in header:
            km = _YARN_KEY.match(h.strip())
            if km:
                name = km.group(1)
                specs.append(h.strip()[len(name) + 1:])
        if name and (name, version) not in seen and not version.startswith("0.0.0-use.local"):
            seen.add((name, version))
            spec = ", ".join(specs)
            # berry: "name@workspace:." 같은 로컬 패키지는 레지스트리 패키지가 아니다
            if not any(s.startswith(("workspace:", "link:", "portal:", "file:")) for s in specs):
                out.append(_dep(name, version, spec, source, None))
        header = None
    return out


# ── pnpm-lock.yaml ───────────────────────────────────────────────

_PNPM_PKG_V5 = re.compile(r"^/((?:@[^/]+/)?[^/@]+)/(\d[^_/()]*)")
_PNPM_PKG_V6 = re.compile(r"^/?((?:@[^/@]+/)?[^/@]+)@(\d[^_()]*)")


def parse_pnpm_lock(text: str, source: str = "pnpm-lock.yaml") -> list[Dependency]:
    """``packages:`` 아래 2칸 들여쓴 키가 설치되는 패키지다:

    * v5   ``  /lodash/4.17.21:``
    * v6   ``  /lodash@4.17.21:`` · ``  /@babel/core@7.0.0(supports-color@8.1.1):``
    * v9   ``  lodash@4.17.21:`` · ``  '@babel/core@7.0.0':``

    직접 의존성은 ``importers:`` 의 루트(``.``)·v5 의 최상위 ``dependencies:`` 에 나열된 이름.
    """
    if "lockfileVersion" not in text:
        raise ValueError(f"{source}: pnpm-lock.yaml 형식이 아님 (lockfileVersion 없음)")
    out: list[Dependency] = []
    section = None
    direct: set[str] = set()
    in_root_importer = False
    dep_block = False
    seen: set[tuple[str, str]] = set()
    pkgs: list[tuple[str, str]] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if indent == 0:
            section = line.rstrip(":").strip()
            in_root_importer = False
            dep_block = section in ("dependencies", "devDependencies", "optionalDependencies")
            continue
        if section == "importers":
            if indent == 2:
                in_root_importer = _unquote(line.rstrip(":")) == "."
                dep_block = False
            elif indent == 4 and in_root_importer:
                dep_block = line.rstrip(":") in ("dependencies", "devDependencies",
                                                 "optionalDependencies")
            elif indent == 6 and in_root_importer and dep_block:
                direct.add(_unquote(line.split(":", 1)[0]))
        elif dep_block and indent == 2 and section in ("dependencies", "devDependencies",
                                                        "optionalDependencies"):
            direct.add(_unquote(line.split(":", 1)[0]))
        elif section in ("packages", "snapshots") and indent == 2 and line.endswith(":"):
            key = _unquote(line[:-1])
            m = _PNPM_PKG_V6.match(key) if "@" in key.lstrip("/@") else None
            m = m or _PNPM_PKG_V5.match(key)
            if m:
                pkgs.append((m.group(1), m.group(2)))
    for name, version in pkgs:
        if (name, version) in seen:
            continue
        seen.add((name, version))
        out.append(_dep(name, version, "", source, name in direct if direct else None))
    return out


def parse_manifest(filename: str, text: str) -> list[Dependency]:
    base = PurePosixPath(filename.replace("\\", "/")).name.lower()
    if base == "package.json":
        return parse_package_json(text, filename)
    if base in ("package-lock.json", "npm-shrinkwrap.json"):
        return parse_package_lock(text, filename)
    if base == "yarn.lock":
        return parse_yarn_lock(text, filename)
    if base == "pnpm-lock.yaml":
        return parse_pnpm_lock(text, filename)
    return []


__all__ = ["parse_manifest"]
