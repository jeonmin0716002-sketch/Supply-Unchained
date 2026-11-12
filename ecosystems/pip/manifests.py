"""pip 의존성 파일 파서 — requirements.txt, poetry/uv/pdm lock, Pipfile.lock, pyproject.toml.

설치·실행 없이 텍스트만 읽는다. lockfile 은 정확한 버전을, 범위만 있는 파일
(requirements 의 미고정 줄, pyproject)은 ``version=None`` 으로 돌려준다 — 못 읽은 버전을
추측으로 채우면 "깨끗하다"는 거짓 보고가 되기 때문이다.
"""

from __future__ import annotations

import json
import re
import tomllib

from ecosystems.base import Dependency

MANIFEST_FILENAMES: tuple[str, ...] = (
    "requirements.txt", "poetry.lock", "uv.lock", "pipfile.lock", "pdm.lock", "pyproject.toml",
)

_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
_REQ_RE = re.compile(rf"^(?P<name>{_NAME})\s*(?:\[[^\]]*\])?\s*(?P<spec>[^;#]*)")
_PIN_RE = re.compile(r"^(?:===?)\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)$")


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _from_requirement(req: str, source: str, direct: bool | None) -> Dependency | None:
    """PEP 508 문자열 하나 → Dependency. 환경 마커(``; ...``)는 버리고 이름·지정자만 본다."""
    m = _REQ_RE.match(req.strip())
    if not m:
        return None
    spec = m.group("spec").strip().rstrip(",").strip()
    pin = _PIN_RE.match(spec)
    return Dependency("pip", _norm(m.group("name")), pin.group(1) if pin else None,
                      spec=spec, source=source, direct=direct)


def _parse_requirements(text: str, source: str) -> list[Dependency]:
    out: list[Dependency] = []
    joined = text.replace("\\\r\n", " ").replace("\\\n", " ")  # 해시 줄 이어붙임
    for raw in joined.splitlines():
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        line = re.sub(r"\s--hash=\S+", "", line)
        # -r/-c 포함·옵션 줄은 따라가지 않는다 (호출자가 파일 단위로 다룸)
        if not line or line.startswith("-") or "://" in line.split(";")[0]:
            continue
        dep = _from_requirement(line, source, True)
        if dep:
            out.append(dep)
    return out


def _parse_toml_packages(text: str, source: str) -> list[Dependency]:
    """poetry.lock · uv.lock · pdm.lock 은 모두 ``[[package]]`` 배열에 name/version 이 있다."""
    data = tomllib.loads(text)
    out = []
    for pkg in data.get("package", []):
        name, version = pkg.get("name"), pkg.get("version")
        if not name:
            continue
        src = pkg.get("source")
        if isinstance(src, dict) and ("virtual" in src or "editable" in src):
            continue  # 프로젝트 자기 자신·로컬 편집 설치는 레지스트리 패키지가 아니다
        out.append(Dependency("pip", _norm(name), str(version) if version else None,
                              spec=f"=={version}" if version else "", source=source))
    return out


def _parse_pipfile_lock(text: str, source: str) -> list[Dependency]:
    data = json.loads(text)
    out = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            ver = info.get("version", "") if isinstance(info, dict) else ""
            pin = _PIN_RE.match(ver.strip())
            out.append(Dependency("pip", _norm(name), pin.group(1) if pin else None,
                                  spec=ver, source=source))
    return out


def _parse_pyproject(text: str, source: str) -> list[Dependency]:
    data = tomllib.loads(text)
    out: list[Dependency] = []
    proj = data.get("project") or {}
    reqs = list(proj.get("dependencies") or [])
    for group in (proj.get("optional-dependencies") or {}).values():
        reqs.extend(group)
    for group in (data.get("dependency-groups") or {}).values():
        reqs.extend(r for r in group if isinstance(r, str))
    for r in reqs:
        dep = _from_requirement(r, source, True)
        if dep:
            out.append(dep)
    poetry = (data.get("tool") or {}).get("poetry") or {}
    tables = [poetry.get("dependencies") or {}, poetry.get("dev-dependencies") or {}]
    for grp in (poetry.get("group") or {}).values():
        tables.append((grp or {}).get("dependencies") or {})
    for table in tables:
        for name, val in table.items():
            if name.lower() == "python":
                continue
            if isinstance(val, dict):
                val = val.get("version", "")
            spec = val if isinstance(val, str) else ""
            pin = re.fullmatch(r"=?=?\s*(\d[\w.+!-]*)", spec.strip())
            out.append(Dependency("pip", _norm(name), pin.group(1) if pin else None,
                                  spec=spec, source=source, direct=True))
    return out


def parse_manifest(filename: str, text: str) -> list[Dependency]:
    """파일 이름(경로 가능)으로 형식을 골라 파싱. 깨진 파일은 ValueError."""
    base = filename.replace("\\", "/").rsplit("/", 1)[-1].lower()
    try:
        if base == "requirements.txt":
            return _parse_requirements(text, filename)
        if base in ("poetry.lock", "uv.lock", "pdm.lock"):
            return _parse_toml_packages(text, filename)
        if base == "pipfile.lock":
            return _parse_pipfile_lock(text, filename)
        if base == "pyproject.toml":
            return _parse_pyproject(text, filename)
    except (tomllib.TOMLDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{filename}: 형식 오류 — {exc}") from exc
    return []
