"""PyPI 레지스트리 → 공통 ``Project`` 모델.

조회 자체는 ``common.pypi.fetch_project`` 가 한다(오류 메시지 형식 — ``... is not on PyPI
(never existed, or removed)`` — 을 감시기가 읽으므로 한 곳에 둔다). 여기서는 그 JSON 을
스코어링·버전 비교가 보는 모델로 옮기고, 분석할 파일을 고른다.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import httpx

from common.pypi import ProjectData
from common.pypi import fetch_project as fetch_project_json
from ecosystems.base import Artifact, Project, Release

_KIND = {"sdist": "sdist", "bdist_wheel": "wheel", "bdist_egg": "egg"}
_REQ_NAME_RE = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _parse_time(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        # PyPI 는 "2023-05-22T15:12:44.123456Z" 형식
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def runtime_dependency_names(requires_dist: list[str]) -> list[str]:
    """``requires_dist`` → 런타임 의존성 이름 (extra 전용 제외, 중복 제거, 소문자 정규화).

    scoring.features.dependency_count 와 같은 규칙이다 — 둘이 다르면 Project 모델로 옮긴
    뒤 의존성 개수 신호가 말없이 바뀐다.
    """
    names: list[str] = []
    for spec in requires_dist:
        if "extra ==" in spec:
            continue
        m = _REQ_NAME_RE.match(spec)
        if m:
            norm = re.sub(r"[-_.]+", "-", m.group(1)).lower()
            if norm not in names:
                names.append(norm)
    return names


def _artifact(f: dict[str, Any]) -> Artifact:
    digests = f.get("digests") or {}
    return Artifact(
        filename=f.get("filename", ""),
        url=f.get("url", ""),
        kind=_KIND.get(f.get("packagetype", ""), f.get("packagetype", "")),
        size=int(f.get("size") or 0),
        sha256=digests.get("sha256"),
    )


def to_project(data: ProjectData) -> Project:
    """PyPI JSON → Project.

    의존성 주의: 프로젝트 JSON 의 ``info.requires_dist`` 는 **최신 버전**의 것이다. 그래서
    최신 릴리스에만 채우고, 다른 릴리스는 비워 둔다(모르는 값을 지어내지 않는다). 기존
    스코어링은 요청 버전과 무관하게 이 값을 썼으므로, 같은 동작을 위해
    ``extra["latest_dependencies"]`` 에도 남긴다(scoring.collector 가 대체값으로 읽는다).
    """
    info = data.info or {}
    latest = info.get("version") or None
    deps = runtime_dependency_names(list(info.get("requires_dist") or []))
    releases: dict[str, Release] = {}
    for version, files in (data.releases or {}).items():
        files = files or []
        times = [t for f in files if (t := _parse_time(f.get("upload_time_iso_8601")
                                                         or f.get("upload_time")))]
        releases[version] = Release(
            version=version,
            uploaded_at=min(times) if times else None,
            artifacts=[_artifact(f) for f in files if f.get("url")],
            # 파일 단위 철회 — 전부 철회됐을 때만 릴리스가 철회된 것이다
            yanked=bool(files) and all(f.get("yanked") for f in files),
            dependencies=list(deps) if version == latest else [],
        )
    urls = info.get("project_urls") or {}
    repo = next(
        (u for k, u in urls.items()
         if k.lower() in {"source", "repository", "code", "source code"}),
        None,
    ) or info.get("home_page") or None
    maintainers = [m for m in (info.get("maintainer"), info.get("author")) if m]
    return Project(
        ecosystem="pip",
        name=data.name,
        latest=latest,
        releases=releases,
        repository_url=repo,
        maintainers=maintainers,
        extra={"info": info, "latest_dependencies": deps},
    )


async def fetch_project(name: str, *, client: httpx.AsyncClient) -> Project:
    return to_project(await fetch_project_json(name, client=client))


def _is_pure_wheel(filename: str) -> bool:
    # py3-none-any 와 py2.py3-none-any 둘 다 "아무 환경에서나 설치되는" 순수 wheel 이다
    return filename.endswith("-none-any.whl") and "py3" in filename.rsplit("-", 3)[-3]


def select_artifacts(project: Project, version: str) -> list[Artifact]:
    """sdist 1개 + wheel 1개.

    sdist 만 보던 시절의 우회: 깨끗한 sdist 와 악성 wheel 을 함께 올리면 스캔은 sdist 를
    보고 safe 를 주는데 pip 은 wheel 을 설치한다. 그래서 둘 다 본다. wheel 은 순수
    ``py3-none-any`` 를 우선하고(대부분의 사용자가 받는 파일), 없으면 첫 wheel.

    알려진 한계: 플랫폼별 wheel 이 여러 개면 하나만 본다 — 특정 플랫폼 wheel 에만 심은
    페이로드는 이 경로(CLI·API·감시기)로는 못 본다. 프록시는 요청된 파일 자체를 스캔하므로
    이 한계가 없다.
    """
    release = project.release(version)
    if release is None:
        return []
    arts = release.artifacts
    out: list[Artifact] = []
    sdist = next((a for a in arts if a.kind == "sdist"), None)
    if sdist:
        out.append(sdist)
    wheels = [a for a in arts if a.filename.endswith(".whl")]
    wheel = next((a for a in wheels if _is_pure_wheel(a.filename)), None) or (
        wheels[0] if wheels else None
    )
    if wheel:
        out.append(wheel)
    if not out and arts:
        out.append(arts[0])
    return out
