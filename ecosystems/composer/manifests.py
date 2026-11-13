"""composer.lock · composer.json 파서.

* ``composer.lock`` — ``packages``(런타임)와 ``packages-dev`` 의 ``name``·``version`` 이 확정
  버전이다. 직접 의존성 여부는 lock 만으로는 알 수 없다 (``direct=None``).
  ``version`` 의 ``v`` 접두사는 떼지 않는다 — OSV(Packagist)가 태그 그대로를 쓴다.
* ``composer.json`` — ``require``·``require-dev``. ``php``·``ext-*``·``lib-*`` 같은 플랫폼
  요구사항은 패키지가 아니라 건너뛴다. 범위는 ``version=None`` (정확한 버전만 값으로).
"""

from __future__ import annotations

import json
import re

from ecosystems.base import Dependency

_EXACT = re.compile(r"^=?\s*v?(\d[0-9A-Za-z]*(?:[._-][0-9A-Za-z]+)*)$")


def _load(text: str, what: str) -> dict:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"{what} 이 올바른 JSON 이 아닙니다: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{what} 최상위가 객체가 아닙니다")
    return data


def parse_composer_lock(text: str, source: str = "composer.lock") -> list[Dependency]:
    data = _load(text, "composer.lock")
    if "packages" not in data and "packages-dev" not in data:
        raise ValueError("composer.lock 형식이 아닙니다 (packages 없음)")
    out: list[Dependency] = []
    for key in ("packages", "packages-dev"):
        for pkg in data.get(key) or []:
            if not isinstance(pkg, dict) or not pkg.get("name"):
                continue
            version = pkg.get("version")
            out.append(Dependency(
                ecosystem="composer", name=str(pkg["name"]).lower(),
                version=version if isinstance(version, str) and version else None,
                spec=str(version or ""), source=source, direct=None))
    return out


def parse_composer_json(text: str, source: str = "composer.json") -> list[Dependency]:
    data = _load(text, "composer.json")
    out: list[Dependency] = []
    for key in ("require", "require-dev"):
        req = data.get(key)
        if not isinstance(req, dict):
            continue
        for name, spec in req.items():
            if "/" not in name:
                continue  # php, ext-json, lib-curl ...
            spec = str(spec)
            m = _EXACT.match(spec.strip())
            out.append(Dependency(
                ecosystem="composer", name=name.lower(), version=m.group(1) if m else None,
                spec=spec, source=source, direct=True))
    return out
