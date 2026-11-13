"""신뢰할 수 없는 XML 을 안전하게 읽는 최소 도구.

표준 라이브러리 파서는 엔티티 확장(billion laughs)에 약하다. 스캔 대상 패키지의 .nuspec·
.targets·packages.config 는 적대적이라고 가정하므로, DTD 가 있는 문서는 파싱하지 않고 거부한다
(정상 NuGet·MSBuild 파일에는 DOCTYPE 이 필요 없다).
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

_DTD = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)", re.IGNORECASE)
MAX_XML_CHARS = 2_000_000


def parse_xml(text: str) -> ET.Element:
    """DTD 가 없는 문서만 파싱하고 네임스페이스를 벗긴 루트를 돌려준다. 실패는 ValueError."""
    if len(text) > MAX_XML_CHARS:
        raise ValueError("XML 이 너무 큽니다")
    if _DTD.search(text):
        raise ValueError("DOCTYPE/ENTITY 가 있는 XML 은 읽지 않습니다")
    try:
        # 억제 근거(B314): bandit 은 fromstring 호출만 보고 XML 공격을 경고한다. 엔티티 확장·외부
        # 엔티티는 DTD 로만 정의할 수 있는데, 바로 위에서 DOCTYPE·ENTITY 가 있는 문서를 파싱 전에
        # 거부하고 크기도 MAX_XML_CHARS 로 묶었다. defusedxml 을 들이지 않는 이유는
        # watcher/feed.py 와 같다 — 의존성 하나보다 입구에서 잘라내는 쪽이 작다.
        root = ET.fromstring(text.lstrip("﻿"))  # nosec B314
    except ET.ParseError as exc:
        raise ValueError(f"XML 파싱 실패: {exc}") from exc
    for el in root.iter():
        if isinstance(el.tag, str) and el.tag.startswith("{"):
            el.tag = el.tag.split("}", 1)[1]
    return root
