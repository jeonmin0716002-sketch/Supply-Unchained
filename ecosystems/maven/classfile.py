"""Java ``.class`` 파일의 상수 풀(constant pool) 파서 — 디컴파일 없이 문자열·참조만 읽는다.

클래스 파일 형식(JVMS §4.1·§4.4)을 따라 정확히 파싱한다. 원시 바이트에 정규식을 돌리지
않는 이유: 상수 풀 밖(바이트코드·속성)의 우연한 바이트열을 문자열로 오인하지 않기 위해서다.

돌려주는 것: Utf8 문자열 전체, 클래스 참조 이름, String 리터럴, (클래스, 메서드) 참조.
바이트코드(Code 속성)는 읽지 않는다 — 어느 메서드가 무엇을 호출하는지까지는 모른다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

MAGIC = 0xCAFEBABE
#: 비정상적으로 큰 상수 풀은 거부 (정상 상한은 65535 이지만 악의적 입력 방어는 파싱 비용으로)
MAX_CLASS_BYTES = 4 * 1024 * 1024


class ClassFileError(ValueError):
    pass


@dataclass
class Constants:
    utf8: list[str] = field(default_factory=list)
    classes: set[str] = field(default_factory=set)         # "java/lang/Runtime"
    strings: list[str] = field(default_factory=list)       # String 리터럴 (코드가 쓰는 문자열)
    methods: set[tuple[str, str]] = field(default_factory=set)  # (클래스, 메서드명)
    this_class: str = ""


def _mutf8(raw: bytes) -> str:
    # modified UTF-8 은 NUL 과 보충 문자 표현만 표준 UTF-8 과 다르다. 분석용이라 대체 문자로 충분.
    return raw.decode("utf-8", errors="replace")


def parse_constant_pool(data: bytes) -> Constants:
    if len(data) > MAX_CLASS_BYTES:
        raise ClassFileError("class file too large")
    if len(data) < 10 or struct.unpack_from(">I", data, 0)[0] != MAGIC:
        raise ClassFileError("not a class file")
    count = struct.unpack_from(">H", data, 8)[0]
    off = 10
    utf8: dict[int, str] = {}
    class_idx: dict[int, int] = {}
    string_idx: list[int] = []
    method_refs: list[tuple[int, int]] = []      # (class index, name_and_type index)
    nat: dict[int, int] = {}                     # NameAndType index → name utf8 index
    i = 1
    try:
        while i < count:
            tag = data[off]
            off += 1
            if tag == 1:
                (ln,) = struct.unpack_from(">H", data, off)
                utf8[i] = _mutf8(data[off + 2: off + 2 + ln])
                if off + 2 + ln > len(data):
                    raise ClassFileError("truncated utf8 entry")
                off += 2 + ln
            elif tag in (3, 4):
                off += 4
            elif tag in (5, 6):
                off += 8
                i += 1  # Long·Double 은 슬롯 두 개
            elif tag == 7:
                class_idx[i] = struct.unpack_from(">H", data, off)[0]
                off += 2
            elif tag == 8:
                string_idx.append(struct.unpack_from(">H", data, off)[0])
                off += 2
            elif tag in (9, 10, 11):
                cls, nt = struct.unpack_from(">HH", data, off)
                if tag != 9:
                    method_refs.append((cls, nt))
                off += 4
            elif tag == 12:
                nat[i] = struct.unpack_from(">HH", data, off)[0]
                off += 4
            elif tag == 15:
                off += 3
            elif tag in (16, 19, 20):
                off += 2
            elif tag in (17, 18):
                off += 4
            else:
                raise ClassFileError(f"unknown constant pool tag {tag}")
            i += 1
        if off > len(data):
            raise ClassFileError("truncated constant pool")
        # 상수 풀 직후: access_flags(2) this_class(2)
        this_idx = struct.unpack_from(">H", data, off + 2)[0]
    except (struct.error, IndexError) as exc:
        raise ClassFileError("truncated class file") from exc

    out = Constants(utf8=list(utf8.values()))
    out.classes = {utf8[u] for u in class_idx.values() if u in utf8}
    out.strings = [utf8[u] for u in string_idx if u in utf8]
    for cls, nt in method_refs:
        cname = utf8.get(class_idx.get(cls, -1))
        mname = utf8.get(nat.get(nt, -1))
        if cname and mname:
            out.methods.add((cname, mname))
    out.this_class = utf8.get(class_idx.get(this_idx, -1), "")
    return out
