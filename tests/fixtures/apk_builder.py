"""合成样本 APK 生成器（测试用，程序化构造最小 APK）。

构造内容：
  - 最小二进制 AndroidManifest.xml（AXML 格式，包含 package/uses-permission）
  - 最小 classes.dex（包含类与字符串池，供代码层分析）

仅用于单元/集成测试；不包含任何真实恶意代码。
"""
from __future__ import annotations

import hashlib
import io
import struct
import zipfile
import zlib

# ---------------------------------------------------------------------------
# AXML (Android Binary XML) 构造
# ---------------------------------------------------------------------------

_RES_XML_TYPE = 0x0003
_RES_STRING_POOL_TYPE = 0x0001
_RES_XML_START_NAMESPACE = 0x0100
_RES_XML_END_NAMESPACE = 0x0101
_RES_XML_START_ELEMENT = 0x0102
_RES_XML_END_ELEMENT = 0x0103
_RES_XML_RESOURCE_MAP = 0x0180

_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10

# android 命名空间与常用属性名（string pool 索引顺序即添加顺序）
_ATTR_NAMESPACE = "http://schemas.android.com/apk/res/android"
_ANDROID_ATTRS = (
    "name",
    "package",
    "versionCode",
    "versionName",
    "minSdkVersion",
    "targetSdkVersion",
    "label",
)


class _StringPool:
    """AXML string pool 构造器（UTF-16LE，8 字节对齐）"""

    def __init__(self) -> None:
        self._strings: list[str] = []

    def add(self, s: str) -> int:
        if s not in self._strings:
            self._strings.append(s)
        return self._strings.index(s)

    def index(self, s: str) -> int:
        return self._strings.index(s)

    def build(self) -> bytes:
        # 计算偏移
        header_size = 28
        offset_data = header_size + 4 * len(self._strings)
        offsets: list[int] = []
        data = bytearray()
        pos = offset_data
        for s in self._strings:
            # offsets 为相对字符串数据区起点(stringsStart)的偏移（Android 规范）
            offsets.append(pos - offset_data)
            encoded = s.encode("utf-16-le")
            # uint16 字符数 + 数据（8 字节对齐）
            data += struct.pack("<H", len(s)) + encoded + b"\x00\x00"
            # 对齐到 8 字节
            while (pos + len(encoded) + 4) % 8 != 0:
                data += b"\x00"
                pos += 1
            pos += len(encoded) + 4

        size = offset_data + len(data)
        buf = io.BytesIO()
        # chunk header: type(2) headerSize(2)=28 size(4) stringCount(4) styleCount(4)
        #              flags(4) stringsStart(4) stylesStart(4)
        buf.write(struct.pack("<HHIIIIII", _RES_STRING_POOL_TYPE, 28, size,
                              len(self._strings), 0, 0, offset_data, 0))
        for off in offsets:
            buf.write(struct.pack("<I", off))
        buf.write(data)
        return buf.getvalue()


def build_axml(
    package: str,
    permissions: list[str],
    version_name: str = "1.0",
    version_code: str = "1",
) -> bytes:
    """构造最小 AndroidManifest.xml（AXML 二进制格式）"""
    pool = _StringPool()
    # 预留常见字符串
    for attr in _ANDROID_ATTRS:
        pool.add(attr)
    pool.add(_ATTR_NAMESPACE)
    pool.add("android")  # namespace prefix
    pool.add("manifest")
    pool.add("uses-permission")
    pool.add("application")
    for p in permissions:
        pool.add(p)
    pool.add(package)
    pool.add(version_name)
    pool.add(version_code)

    chunks = bytearray()
    chunks += pool.build()
    # resource map chunk（空）：type(2) headerSize(2)=8 size(4)=8
    chunks += struct.pack("<HHI", _RES_XML_RESOURCE_MAP, 0x08, 0x08)

    # start namespace: node header(16) + prefix(4) + uri(4) = 24
    ns_start = struct.pack(
        "<HHIIIII", _RES_XML_START_NAMESPACE, 0x10, 24,
        1,  # line
        0xFFFFFFFF,  # comment
        pool.index("android"),  # prefix
        pool.index(_ATTR_NAMESPACE),  # uri
    )
    chunks += ns_start

    def start_element(name: str, attrs: list[tuple[str, int, int]], ns: int = 0xFFFFFFFF) -> bytes:
        # attrs: (attr_name, string_index, raw_value_index or -1)
        # start element chunk: node header(16) + attrExt(20) + attrs(20*n)
        node_header = 16
        attr_ext = 20
        attr_size = 20  # 安卓规范 ResXMLTree_attribute = ns(4)+name(4)+rawValue(4)+typedValue(8)
        size = node_header + attr_ext + attr_size * len(attrs)
        buf = io.BytesIO()
        # node header: type(H) headerSize(H) size(I) line(I) comment(I)
        # attrExt: ns(I) name(I) attributeStart(H) attributeSize(H) attributeCount(H)
        #          idIndex(H) classIndex(H) styleIndex(H)
        buf.write(struct.pack(
            "<HHIIIIIHHHHHH",
            _RES_XML_START_ELEMENT, node_header, size,
            1, 0xFFFFFFFF,  # line, comment
            ns, pool.index(name),  # ns, name
            attr_ext, attr_size, len(attrs),  # attributeStart, attributeSize, attributeCount
            0xFFFF, 0xFFFF, 0xFFFF,  # id/class/style index
        ))
        for attr_name, str_idx, raw_idx in attrs:
            ns_idx = pool.index(_ATTR_NAMESPACE)
            name_idx = pool.index(attr_name)
            buf.write(struct.pack("<II", ns_idx, name_idx))
            # rawValue: string pool index（字符串类型属性）
            raw_value = raw_idx if raw_idx >= 0 else str_idx
            buf.write(struct.pack("<I", raw_value))
            # typed value: size=8, type=STRING, data=string index
            buf.write(struct.pack("<HBBI", 8, 0, _TYPE_STRING, str_idx))
        return buf.getvalue()

    def end_element(name: str) -> bytes:
        # end element: 仅 node header(16)，无 name 字段
        return struct.pack(
            "<HHIII", _RES_XML_END_ELEMENT, 0x10, 16,
            1, 0xFFFFFFFF,  # line, comment
        )

    chunks += start_element(
        "manifest",
        [
            ("package", pool.index(package), pool.index(package)),
            ("versionCode", pool.index(version_code), pool.index(version_code)),
            ("versionName", pool.index(version_name), pool.index(version_name)),
        ],
    )
    for perm in permissions:
        chunks += start_element(
            "uses-permission",
            [("name", pool.index(perm), pool.index(perm))],
        )
        chunks += end_element("uses-permission")
    chunks += start_element("application", [])
    chunks += end_element("application")
    chunks += end_element("manifest")

    # end namespace: node header(16) + prefix(4) + uri(4) = 24
    chunks += struct.pack(
        "<HHIIIII", _RES_XML_END_NAMESPACE, 0x10, 24,
        1, 0xFFFFFFFF,
        pool.index("android"), pool.index(_ATTR_NAMESPACE),
    )

    # 组装文件头（8 字节：type/headerSize/size）
    total_size = 8 + len(chunks)
    header = struct.pack("<HHI", _RES_XML_TYPE, 0x08, total_size)
    return header + bytes(chunks)


# ---------------------------------------------------------------------------
# 最小 DEX 构造
# ---------------------------------------------------------------------------

def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def build_minimal_dex(class_name: str, payload_strings: list[str]) -> bytes:
    """构造最小 DEX：一个类 + 字符串池（含 payload 字符串）。

    布局：header(0x70) + string_ids + type_ids + string_data + map_list
    """
    strings = [class_name, *payload_strings]
    string_ids: list[int] = []
    string_data = bytearray()

    def add_string(s: str) -> None:
        nonlocal string_data
        # string_data_item 连续排列（androguard 顺序解析，不允许 padding 间隔）
        data_offset = 0x70 + 4 * len(strings) + 4 + len(string_data)
        encoded = s.encode("utf-8")
        string_data += _uleb128(len(encoded)) + encoded + b"\x00"
        string_ids.append(data_offset)

    for s in strings:
        add_string(s)

    # ---- 各 section 偏移 ----
    string_ids_off = 0x70
    type_ids_off = string_ids_off + 4 * len(strings)
    string_data_off = type_ids_off + 4  # 1 个 type_id
    map_off = string_data_off + len(string_data)

    # ---- map_list ----
    map_items = [
        (0x0000, 1, 0),  # HEADER_ITEM
        (0x0001, len(strings), string_ids_off),  # STRING_ID_ITEM
        (0x0002, 1, type_ids_off),  # TYPE_ID_ITEM
        (0x1000, 1, map_off),  # MAP_LIST
        (0x2002, len(strings), string_data_off),  # STRING_DATA_ITEM
    ]
    map_buf = bytearray()
    map_buf += struct.pack("<I", len(map_items))
    for mtype, msize, moff in map_items:
        map_buf += struct.pack("<HHII", mtype, 0, msize, moff)

    # ---- header ----
    header = bytearray(0x70)

    def put_u32(offset: int, value: int) -> None:
        struct.pack_into("<I", header, offset, value)

    header[0:8] = b"dex\n035\0"
    put_u32(0x20, map_off + len(map_buf))  # file_size
    put_u32(0x24, 0x70)  # header_size
    put_u32(0x28, 0x12345678)  # endian_tag
    put_u32(0x34, map_off)  # map_off
    put_u32(0x38, len(strings))  # string_ids_size
    put_u32(0x3C, string_ids_off)
    put_u32(0x40, 1)  # type_ids_size
    put_u32(0x44, type_ids_off)
    put_u32(0x68, len(string_data))  # data_size
    put_u32(0x6C, string_data_off)

    # ---- 组装 ----
    type_ids = struct.pack("<I", 0)  # 指向 class 名字符串
    string_ids_bytes = b"".join(struct.pack("<I", off) for off in string_ids)

    dex_bytes = bytearray()
    dex_bytes += header + string_ids_bytes + type_ids + string_data + map_buf
    # SHA-1 signature（0x0c 到 0x20，覆盖从 offset 32 到文件末尾）
    dex_bytes[0x0c:0x20] = hashlib.sha1(bytes(dex_bytes[0x20:])).digest()
    # Adler32 checksum（offset 0x08，覆盖从 offset 12 到文件末尾）
    struct.pack_into(
        "<I", dex_bytes, 0x08,
        zlib.adler32(bytes(dex_bytes[0x0c:])) & 0xFFFFFFFF,
    )
    return bytes(dex_bytes)


def build_apk(
    package: str,
    permissions: list[str],
    payload_strings: list[str],
    class_name: str = "Lcom/test/MainActivity;",
) -> bytes:
    """构造最小 APK（zip 容器）"""
    manifest = build_axml(package, permissions)
    dex = build_minimal_dex(class_name, payload_strings)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex)
        # 最小 resources.arsc 占位
        zf.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"\x00" * 8)
    return buf.getvalue()
