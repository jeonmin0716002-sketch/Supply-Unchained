"""아카이브 안전 추출 — 생태계와 무관한 공통 진입점.

모든 어댑터는 압축을 직접 풀지 않고 여기를 거친다. 스캔 대상은 적대적이라고 가정하므로
크기·개수 상한, 경로 탈출(zip-slip) 거부, 링크·장치 파일 건너뛰기를 한 곳에서 지킨다
(근거는 common/pypi.py 상단 Safety notes).

지금은 common.pypi 의 구현에 위임한다. ``extract_archive`` 의 시그니처는 유지한다 —
어댑터들이 이 함수에만 의존한다 (``data`` 로 디스크 경로도 받게 넓혔을 뿐이다).

선택 추출: 분석기가 읽는 파일(``SCAN_SUFFIXES``·접미사 없는 파일·진입점)만 풀고 그것만
상한에 센다. 상한을 넘으면 진입점·얕은 경로부터 풀고 사유를 ``ExtractReport.truncated`` 에
남긴다 — 예외가 아니다. 어댑터가 더 풀어야 할 접미사가 있으면 어댑터 클래스에
``scan_suffixes = (".foo",)`` 를 두면 된다(PackageContext 가 읽는다).
"""

from __future__ import annotations

from pathlib import Path

from common.pypi import (
    SCAN_SUFFIXES,
    ArchiveError,
    ExtractReport,
    current_report,
    extract,
    is_safe_member_name,
    is_scan_target,
)

#: fmt → common.pypi.extract 가 형식을 판단하는 데 쓰는 접미사
_FMT_SUFFIX = {"tar": ".tar", "zip": ".zip"}

#: 파일명만으로 형식을 알 수 있는 확장자 (생태계별 포장 형식 포함)
_TAR_LIKE = (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar", ".crate")
_ZIP_LIKE = (".zip", ".whl", ".egg", ".jar", ".aar", ".war", ".nupkg")

__all__ = [
    "SCAN_SUFFIXES",
    "ArchiveError",
    "ExtractReport",
    "current_report",
    "extract_archive",
    "is_safe_member_name",
    "is_scan_target",
]


def extract_archive(
    data: bytes | Path,
    filename: str,
    dest: str | Path,
    *,
    fmt: str | None = None,
    report: ExtractReport | None = None,
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
    return extract(data, "archive" + _FMT_SUFFIX[fmt], dest, report=report)
