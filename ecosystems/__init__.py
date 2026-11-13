"""생태계 레지스트리 — 식별자로 어댑터를 찾는다.

어댑터는 ``ecosystems/<id>/__init__.py`` 의 ``ADAPTER`` 다. 여기에 등록 목록을 손으로
적지 않는 이유: 생태계마다 따로 개발·병합되므로, 디렉터리를 추가하는 것만으로 붙어야
파일 충돌이 없다. 대신 ``KNOWN_IDS`` 가 "지원하기로 한 식별자"의 화이트리스트라, 임의의
문자열이 import 경로로 흘러가지 않는다.
"""

from __future__ import annotations

import importlib
from functools import cache

from ecosystems.base import Ecosystem

#: 지원 대상 식별자. api.schemas.Ecosystem 의 값과 같아야 한다.
KNOWN_IDS: tuple[str, ...] = (
    "pip", "npm", "cargo", "go", "maven", "rubygems", "nuget", "composer",
)


class UnknownEcosystem(LookupError):
    """식별자가 화이트리스트에 없거나, 어댑터가 아직 구현되지 않았다."""


@cache
def get(ecosystem_id: str) -> Ecosystem:
    if ecosystem_id not in KNOWN_IDS:
        raise UnknownEcosystem(f"지원하지 않는 생태계: {ecosystem_id!r}")
    try:
        module = importlib.import_module(f"ecosystems.{ecosystem_id}")
    except ModuleNotFoundError as exc:
        if exc.name != f"ecosystems.{ecosystem_id}":
            raise  # 어댑터는 있는데 그 안의 import 가 깨졌다 — 숨기지 않는다
        raise UnknownEcosystem(f"{ecosystem_id} 어댑터가 아직 없습니다") from exc
    adapter = getattr(module, "ADAPTER", None)
    if not isinstance(adapter, Ecosystem):
        raise UnknownEcosystem(f"ecosystems.{ecosystem_id} 에 ADAPTER 가 없습니다")
    return adapter


def available() -> list[Ecosystem]:
    """구현된 어댑터 전부 (KNOWN_IDS 순서)."""
    out = []
    for eco_id in KNOWN_IDS:
        try:
            out.append(get(eco_id))
        except UnknownEcosystem:
            continue
    return out


__all__ = ["KNOWN_IDS", "Ecosystem", "UnknownEcosystem", "available", "get"]
