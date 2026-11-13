# ruff: noqa: E501
"""Maven·Gradle 의존성 파일 파서.

* ``pom.xml`` — ``project/dependencies/dependency`` 만 (직접 의존성). 버전이 리터럴이면 그대로,
  ``${속성}``·범위·미지정(dependencyManagement 가 정함)이면 ``version=None``, ``spec`` 에 원문.
  속성은 풀지 않는다 — 부모 POM·프로필 속성까지 맞게 풀려면 Maven 해석기가 필요해서,
  틀린 버전을 확정하느니 모른다고 한다.
* ``gradle.lockfile`` — ``group:artifact:version=configs`` 줄. 해석된 정확한 버전(전이 포함).
* ``build.gradle`` / ``build.gradle.kts`` — 문자열 좌표 ``"g:a:v"`` 와 ``group:/name:/version:``
  맵 표기를 정규식으로 (best effort — 변수·버전 카탈로그는 version=None).
"""

from __future__ import annotations

import re

from ecosystems.base import Dependency
from ecosystems.maven._xml import child_text, parse_xml

_LITERAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
_STRING_COORD = re.compile(
    r"""['"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)(?::([^'":@\s]+))?(?:@[A-Za-z]+)?['"]"""
)
_MAP_COORD = re.compile(
    r"group\s*[:=]\s*['\"]([\w.-]+)['\"]\s*,\s*name\s*[:=]\s*['\"]([\w.-]+)['\"]"
    r"(?:\s*,\s*version\s*[:=]\s*['\"]([^'\"]+)['\"])?"
)
_GRADLE_CONFIG = re.compile(
    r"(?:^|[\s{;])(?:api|implementation|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|"
    r"testCompileOnly|annotationProcessor|kapt|ksp|classpath|compile|runtime|testCompile)\b",
)


def _literal_version(raw: str | None) -> str | None:
    if not raw:
        return None
    raw = raw.strip()
    if raw.startswith("[") and raw.endswith("]") and "," not in raw:
        raw = raw[1:-1].strip()  # [1.2.3] = 정확히 그 버전
    return raw if _LITERAL.match(raw) and "${" not in raw else None


def _pom(text: str, source: str) -> list[Dependency]:
    root = parse_xml(text)
    out = []
    for dep in root.findall("dependencies/dependency"):
        g, a = child_text(dep, "groupId"), child_text(dep, "artifactId")
        if not g or not a or "${" in g or "${" in a:
            continue
        raw = child_text(dep, "version")
        out.append(Dependency(
            ecosystem="maven", name=f"{g}:{a}", version=_literal_version(raw),
            spec=raw or "", source=source, direct=True,
        ))
    return out


def _lockfile(text: str, source: str) -> list[Dependency]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "empty=")):
            continue
        coord = line.split("=", 1)[0]
        parts = coord.split(":")
        if len(parts) != 3 or not all(parts):
            raise ValueError(f"gradle.lockfile 줄을 읽을 수 없습니다: {line!r}")
        out.append(Dependency(
            ecosystem="maven", name=f"{parts[0]}:{parts[1]}", version=_literal_version(parts[2]),
            spec=parts[2], source=source, direct=None,
        ))
    return out


def _gradle(text: str, source: str) -> list[Dependency]:
    out: list[Dependency] = []
    seen: set[tuple[str, str | None]] = set()

    def add(g: str, a: str, v: str | None) -> None:
        raw = v or ""
        key = (f"{g}:{a}", raw)
        if key in seen:
            return
        seen.add(key)
        out.append(Dependency(
            ecosystem="maven", name=f"{g}:{a}", version=_literal_version(raw) if "$" not in raw else None,
            spec=raw, source=source, direct=True,
        ))

    for line in text.splitlines():
        if line.lstrip().startswith(("//", "*", "/*")):
            continue
        # 의존성 선언 줄이거나 plugins 블록의 coordinate 가 아닌 것만 — 설정 이름으로 시작하는 줄
        if _GRADLE_CONFIG.search(line):
            for m in _STRING_COORD.finditer(line):
                add(m.group(1), m.group(2), m.group(3))
            for m in _MAP_COORD.finditer(line):
                add(m.group(1), m.group(2), m.group(3))
    return out


def parse_manifest(filename: str, text: str) -> list[Dependency]:
    low = filename.lower().rsplit("/", 1)[-1]
    if low == "pom.xml":
        return _pom(text, filename)
    if low == "gradle.lockfile":
        return _lockfile(text, filename)
    if low in ("build.gradle", "build.gradle.kts"):
        return _gradle(text, filename)
    return []
