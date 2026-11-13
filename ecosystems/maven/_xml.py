"""신뢰할 수 없는 XML 을 안전하게 읽는 최소 도구 (pom.xml·plugin.xml·maven-metadata.xml).

표준 라이브러리 파서는 엔티티 확장(billion laughs)에 약하다. 스캔 대상은 적대적이라고
가정하므로 DTD(``<!DOCTYPE``·``<!ENTITY``)가 있는 문서는 파싱하지 않고 거부한다. 정상
POM·메타데이터에는 DTD 가 필요 없다.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

_DTD = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)", re.IGNORECASE)
MAX_XML_CHARS = 2_000_000


def parse_xml(text: str) -> ET.Element:
    """DTD 없는 문서만 파싱하고 네임스페이스를 벗긴 루트를 돌려준다. 실패는 ValueError."""
    if len(text) > MAX_XML_CHARS:
        raise ValueError("XML 이 너무 큽니다")
    if _DTD.search(text):
        raise ValueError("DOCTYPE/ENTITY 가 있는 XML 은 읽지 않습니다")
    try:
        root = ET.fromstring(text.lstrip("﻿"))
    except ET.ParseError as exc:
        raise ValueError(f"XML 파싱 실패: {exc}") from exc
    for el in root.iter():
        if isinstance(el.tag, str) and el.tag.startswith("{"):
            el.tag = el.tag.split("}", 1)[1]
    return root


def child_text(el: ET.Element, tag: str) -> str | None:
    child = el.find(tag)
    if child is None or child.text is None:
        return None
    return child.text.strip() or None
