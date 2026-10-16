"""PyPI RSS 피드 — 새로 올라온 패키지·릴리스 목록.

두 피드를 쓴다:

* ``packages.xml`` — 새로 **등록된 프로젝트** (최근 40개). 악성 패키지 대부분이
  여기로 들어온다: typosquat·dependency confusion 은 새 이름이 필요하기 때문.
  링크에 버전이 없어서 호출부가 최신 버전을 따로 조회한다.
* ``updates.xml`` — 새 **릴리스** (최근 100개). 탈취된 기존 계정이 악성 버전을
  올리는 경로를 본다. 링크가 ``/project/<name>/<version>/`` 형태다.

XML 파서를 쓰지 않고 ``<link>`` 만 정규식으로 뽑는다. 필요한 정보가 링크 하나뿐이고,
외부에서 받은 XML 을 stdlib ``xml.etree`` 로 파싱하면 엔티티 확장 공격면이 생긴다
(bandit B314) — 그걸 막으려 defusedxml 의존성을 들이는 것보다 링크 패턴 하나를
화이트리스트로 읽는 쪽이 작고 안전하다. 이름·버전은 이후 ScanRequest 검증을 한 번 더 탄다.
"""

from __future__ import annotations

import re

import httpx

NEW_PACKAGES_URL = "https://pypi.org/rss/packages.xml"
UPDATES_URL = "https://pypi.org/rss/updates.xml"

# 채널 자체의 <link>https://pypi.org/</link> 는 /project/ 가 없어서 걸리지 않는다.
_LINK_RE = re.compile(
    r"<link>https://pypi\.org/project/([A-Za-z0-9._-]+)/(?:([A-Za-z0-9._+!-]+)/)?</link>"
)


def parse_feed(xml: str) -> list[tuple[str, str | None]]:
    """피드 본문 → ``[(name, version | None), ...]`` (피드 순서 유지, 중복 제거)."""
    out: list[tuple[str, str | None]] = []
    seen: set[tuple[str, str | None]] = set()
    for name, version in _LINK_RE.findall(xml):
        item = (name, version or None)
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


async def fetch_feeds(
    http: httpx.AsyncClient,
) -> tuple[list[tuple[str, str | None]], list[str]]:
    """두 피드를 합쳐 ``(items, errors)`` 로 돌려준다. 하나가 실패해도 나머지는 쓴다.

    실패를 삼키지 않고 errors 로 넘기는 이유: 둘 다 실패했을 때 빈 items 만 돌려주면
    "새 패키지 없음"과 구분이 안 된다 — 스캔 레이어의 layer_errors 와 같은 원칙.
    """
    items: list[tuple[str, str | None]] = []
    errors: list[str] = []
    for url in (NEW_PACKAGES_URL, UPDATES_URL):
        try:
            resp = await http.get(url)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            errors.append(f"{url}: {exc}")
            continue
        items.extend(parse_feed(resp.text))
    return items, errors
