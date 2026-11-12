"""아카이브 안전 추출 — 생태계와 무관한 공통 진입점.

모든 어댑터는 압축을 직접 풀지 않고 여기를 거친다. 스캔 대상은 적대적이라고 가정하므로
크기·개수 상한, 경로 탈출(zip-slip) 거부, 링크·장치 파일 건너뛰기를 한 곳에서 지킨다
(근거는 common/pypi.py 상단 Safety notes).

지금은 common.pypi 의 구현에 위임한다. 구현을 이쪽으로 옮기거나 선택 추출을 넣더라도
``extract_archive`` 의 시그니처는 유지한다 — 어댑터들이 이 함수에만 의존한다.
"""

from __future__ import annotations

from pathlib import Path

from common.pypi import ArchiveError, extract, is_safe_member_name

#: fmt → common.pypi.extract 가 형식을 판단하는 데 쓰는 접미사
_FMT_SUFFIX = {"tar": ".tar", "zip": ".zip"}

#: 파일명만으로 형식을 알 수 있는 확장자 (생태계별 포장 형식 포함)
_TAR_LIKE = (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar", ".crate")
_ZIP_LIKE = (".zip", ".whl", ".egg", ".jar", ".aar", ".war", ".nupkg")

__all__ = ["ArchiveError", "extract_archive", "is_safe_member_name"]


def extract_archive(
    data: bytes, filename: str, dest: str | Path, *, fmt: str | None = None
) -> Path:
    """``data`` 를 ``dest`` 에 안전 추출하고 dest 를 돌려준다.

    ``fmt`` 는 "tar"(gz·bz2·xz 자동 판별) 또는 "zip". None 이면 파일명으로 판단한다.
    상한 위반·경로 탈출·알 수 없는 형식은 ``ArchiveError``.
    """
    if fmt is None:
        lowered = filename.lower()
        if lowered.endswith(_TAR_LIKE):
            fmt = "tar"
        elif lowered.endswith(_ZIP_LIKE):
            fmt = "zip"
    if fmt not in _FMT_SUFFIX:
        raise ArchiveError(f"unsupported archive format: {filename}")
    return extract(data, "archive" + _FMT_SUFFIX[fmt], dest)
