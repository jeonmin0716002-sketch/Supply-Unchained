"""Cargo.lock · Cargo.toml → ``Dependency``.

* Cargo.lock — 정확한 버전. ``source`` 가 crates.io 레지스트리인 항목만 스캔 대상이다
  (git·path 는 레지스트리에 없어서 OSV·다운로드 조회가 불가능). ``source`` 가 없는 패키지는
  워크스페이스 자신이라 그것이 직접 의존하는 것을 direct 로 표시한다.
* Cargo.toml — 직접 의존성. Cargo 의 ``"1.2"`` 는 호환 범위(캐럿)이므로 ``=1.2.3`` 만 정확한 버전이다.
"""

from __future__ import annotations

import re
import tomllib

from ecosystems.base import Dependency

_REGISTRY_SOURCES = ("registry+https://github.com/rust-lang/crates.io-index",
                     "sparse+https://index.crates.io/")
_EXACT = re.compile(r"^=\s*(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$")
_DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


def _load(text: str, filename: str) -> dict:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"{filename} 이 TOML 로 해석되지 않는다: {exc}") from exc


def parse_cargo_lock(text: str, source: str = "Cargo.lock") -> list[Dependency]:
    data = _load(text, source)
    packages = data.get("package") or []
    roots = [p for p in packages if not p.get("source")]
    direct_names = {
        str(d).split(" ", 1)[0] for r in roots for d in (r.get("dependencies") or [])
    }
    out: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    for p in packages:
        name, version = p.get("name"), p.get("version")
        if not name or not version or p.get("source") not in _REGISTRY_SOURCES:
            continue
        if (name, version) in seen:
            continue
        seen.add((name, version))
        out.append(Dependency(ecosystem="cargo", name=name, version=version,
                              spec=f"={version}", source=source,
                              direct=(name in direct_names) if roots else None))
    return out


def _iter_tables(data: dict):
    for key in _DEP_TABLES:
        if isinstance(data.get(key), dict):
            yield data[key]
    for target in (data.get("target") or {}).values():
        if isinstance(target, dict):
            for key in _DEP_TABLES:
                if isinstance(target.get(key), dict):
                    yield target[key]
    ws = data.get("workspace")
    if isinstance(ws, dict) and isinstance(ws.get("dependencies"), dict):
        yield ws["dependencies"]


def parse_cargo_toml(text: str, source: str = "Cargo.toml") -> list[Dependency]:
    data = _load(text, source)
    out: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    for table in _iter_tables(data):
        for key, spec in table.items():
            name, req = key, ""
            if isinstance(spec, str):
                req = spec
            elif isinstance(spec, dict):
                if spec.get("git") or spec.get("path") or spec.get("workspace"):
                    continue  # 레지스트리 밖이거나 워크스페이스 참조 — 조회 대상이 아니다
                name = spec.get("package", key)  # 이름을 바꿔 가져온 경우 실제 크레이트 이름
                req = spec.get("version", "")
            else:
                continue
            m = _EXACT.match(req.strip())
            version = m.group(1) if m else None
            if (name, req) in seen:
                continue
            seen.add((name, req))
            out.append(Dependency(ecosystem="cargo", name=name, version=version, spec=req,
                                  source=source, direct=True))
    return out

# ruff: noqa: E501
