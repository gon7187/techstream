"""Native ConverterTSE_DT saved AD3/DC6 conversion without OEM execution.

Source: ConverterTSE_DT 3.0.10.0, SHA256
77c477bc6ab72f58e599147e306ac297e3836600b49ab726c59b8dfa4662765e.
Wire fields without a recovered domain meaning retain neutral names and bytes.
"""

from __future__ import annotations

import heapq
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Protocol

MAX_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 100_000


class TSEConversionError(ValueError):
    """Malformed, cancelled, or unsafe native legacy conversion input."""


@dataclass(frozen=True)
class LegacyGroup:
    header_raw: int
    records: tuple[tuple[int, bytes, bytes], ...]


@dataclass(frozen=True)
class LegacyMultiGroup:
    header_raw: int
    records: tuple[tuple[bytes, tuple[tuple[int, bytes], ...]], ...]


@dataclass(frozen=True)
class LegacySource:
    source: bytes
    inner: bytes
    extension: str
    record_type: int
    metadata_raw: bytes
    time_raw: bytes
    blobs: tuple[bytes, ...]
    groups: tuple[LegacyGroup, ...]
    multi_group: LegacyMultiGroup | None
    trailing: bytes
    compression_raw: int
    compressed_size_raw: int
    outer_prefix: bytes
    outer_trailing: bytes


class _Reader:
    def __init__(self, data: bytes, cancelled: Callable[[], bool] | None):
        self.data = data
        self.pos = 0
        self.cancelled = cancelled
        self.records = 0

    def check(self) -> None:
        if self.cancelled is not None and self.cancelled():
            raise TSEConversionError("legacy conversion cancelled")

    def count(self, value: int) -> None:
        self.check()
        if value > MAX_RECORDS - self.records:
            raise TSEConversionError("legacy record count exceeds host budget")
        self.records += value

    def take(self, size: int) -> bytes:
        self.check()
        if size < 0 or size > len(self.data) - self.pos:
            raise TSEConversionError("truncated native legacy field")
        start = self.pos
        self.pos += size
        return self.data[start : self.pos]

    def integer(self, size: int = 4) -> int:
        return int.from_bytes(self.take(size), "little")

    def blob(self, size_width: int = 4) -> bytes:
        return self.take(self.integer(size_width))


@dataclass(frozen=True)
class LegacyDisplayInfo:
    header_raw: tuple[int, int]
    effective_version: int
    value_raw: int
    text_raw: bytes | None
    bounds_raw: tuple[int, int]
    flag_raw: int
    source: bytes


@dataclass(frozen=True)
class LegacyConversionTable:
    header_raw: tuple[int, int]
    coefficients_raw: tuple[int, int, int]
    list_header_raw: tuple[int, int]
    displays: tuple[LegacyDisplayInfo, ...]
    fields_30_3c_raw: tuple[int, int, int, int]
    field_14_raw: int
    field_16_raw: int
    field_18_raw: int
    source: bytes


def _core(reader: _Reader, supported: int) -> tuple[tuple[int, int], int]:
    # Legacy RVA 52c20: a newer wire version becomes zero, not the supported max.
    version, revision = reader.integer(2), reader.integer(2)
    return (version, revision), version if version <= supported else 0


def _string(reader: _Reader) -> bytes | None:
    # Legacy RVA 52f50 allocates exactly this length. Zero leaves a NULL pointer.
    _core(reader, 1)
    value = reader.blob(2)
    return value if value else None


def _conversion_table(reader: _Reader) -> LegacyConversionTable:
    # Legacy RVA 73d30 and DispInfo Read739d0; AddTail08b80 constructs version 2.
    start = reader.pos
    header, _ = _core(reader, 1)
    coefficients = (reader.integer(), reader.integer(), reader.integer())
    list_header, _ = _core(reader, 1)
    count = reader.integer()
    reader.count(count)
    displays = []
    for _ in range(count):
        item_start = reader.pos
        item_header, effective = _core(reader, 2)
        value = reader.integer()
        text = _string(reader)
        bounds = (reader.integer(), reader.integer())
        # Constructor73910→RemoveAll73ab0 initializes this byte with version 2.
        flag = reader.integer(1) if effective >= 2 else 0
        displays.append(
            LegacyDisplayInfo(
                item_header,
                effective,
                value,
                text,
                bounds,
                flag,
                reader.data[item_start : reader.pos],
            )
        )
    fields = (reader.integer(), reader.integer(), reader.integer(), reader.integer())
    field_14, field_16, field_18 = (
        reader.integer(2),
        reader.integer(1),
        reader.integer(2),
    )
    return LegacyConversionTable(
        header,
        coefficients,
        list_header,
        tuple(displays),
        fields,
        field_14,
        field_16,
        field_18,
        reader.data[start : reader.pos],
    )


@dataclass(frozen=True)
class LegacyMultiData:
    header_raw: tuple[int, int]
    value_raw: int
    flag_raw: int
    source: bytes


@dataclass(frozen=True)
class LegacyFreezeSignal:
    header_raw: tuple[int, int]
    identifier_raw: int
    string_fields_raw: tuple[bytes | None, bytes | None, bytes | None]
    selector_raw: int
    field_3d_raw: int
    conversion: LegacyConversionTable
    multi_header_raw: tuple[int, int]
    multi_data: tuple[LegacyMultiData, ...]
    source: bytes


def _freeze_signal(reader: _Reader) -> LegacyFreezeSignal:
    # Legacy Read776d0, ctor77540, MultiData Read779f0 / ctor77990.
    start = reader.pos
    header, _ = _core(reader, 1)
    identifier = reader.integer(2)
    strings = (_string(reader), _string(reader), _string(reader))
    selector, field_3d = reader.integer(1), reader.integer(1)
    conversion = _conversion_table(reader)
    multi_header, _ = _core(reader, 1)
    count = reader.integer()
    reader.count(count)
    multi = []
    for _ in range(count):
        item_start = reader.pos
        item_header, _ = _core(reader, 1)
        value, flag = reader.integer(), reader.integer(1)
        multi.append(
            LegacyMultiData(
                item_header, value, flag, reader.data[item_start : reader.pos]
            )
        )
    return LegacyFreezeSignal(
        header,
        identifier,
        strings,
        selector,
        field_3d,
        conversion,
        multi_header,
        tuple(multi),
        reader.data[start : reader.pos],
    )


@dataclass(frozen=True)
class LegacyReply:
    kind: str
    header_raw: tuple[int, int, int, int, int]
    prefix_fields_raw: tuple[int, ...]
    list_data: LegacyList | None
    source: bytes


def _reply(reader: _Reader, kind: str) -> LegacyReply:
    # Legacy base528b0 is five DWORDs; it has no CCmdCore HH prefix.
    generic = (
        "CGetDiagCodeRcv",
        "CGetDiagDetailIdListRcv",
        "CGetDiagDetailRcv",
        "CGetEcuFuncListRcv",
        "CGetPendingCodeRcv",
    )
    if kind not in (
        *generic,
        "CGetFrzFrmDatRcv",
        "CGetFrzFrmDatSnd",
        "CGetMultiFrzFrmDatRcv",
    ):
        raise TSEConversionError("unknown native legacy reply class")
    start = reader.pos
    header = tuple(reader.integer() for _ in range(5))
    if kind == "CGetFrzFrmDatSnd":
        prefix = (reader.integer(1), reader.integer(2))  # RVA4ddb0; no alignment byte.
        list_data = None
    else:
        if kind == "CGetFrzFrmDatRcv":  # RVA34710
            prefix = (reader.integer(),)
        elif kind == "CGetMultiFrzFrmDatRcv":  # RVA497d0
            prefix = (reader.integer(1), reader.integer(1))
        else:  # Shared Read50cd0 for all five generic receive classes.
            prefix = ()
        # Shared Read aliases do not imply a buffer. The constructor's nested
        # vtable binds this member to the appropriate CCmdList specialization.
        item_kind = {
            "CGetDiagCodeRcv": "DTC",
            "CGetPendingCodeRcv": "DTC",
            "CGetDiagDetailIdListRcv": "Detail",
            "CGetDiagDetailRcv": "Freeze",
            "CGetEcuFuncListRcv": "Func",
            "CGetFrzFrmDatRcv": "Freeze",
            "CGetMultiFrzFrmDatRcv": "Freeze",
        }[kind]
        list_data = _native_list(reader, item_kind)
    return LegacyReply(
        kind,
        (header[0], header[1], header[2], header[3], header[4]),
        prefix,
        list_data,
        reader.data[start : reader.pos],
    )


@dataclass(frozen=True)
class LegacyFunctionDetail:
    header_raw: tuple[int, int]
    identifier_raw: int
    value_raw: int
    source: bytes


@dataclass(frozen=True)
class LegacyFunction:
    header_raw: tuple[int, int]
    identifier_raw: int
    field_1c_raw: int
    text_raw: bytes | None
    details_header_raw: tuple[int, int]
    details: tuple[LegacyFunctionDetail, ...]
    source: bytes


@dataclass(frozen=True)
class LegacyFunctionInfo:
    header_raw: tuple[int, int]
    base_fields_raw: tuple[int, int, int, int, int]
    list_header_raw: tuple[int, int]
    functions: tuple[LegacyFunction, ...]
    source: bytes


@dataclass(frozen=True)
class LegacyList:
    header_raw: tuple[int, int]
    records: tuple[LegacyNode, ...]


@dataclass(frozen=True)
class LegacyNode:
    """A native object; keys are original in-memory member offsets, not wire offsets."""

    kind: str
    header_raw: tuple[int, int]
    effective_version: int
    fields: tuple[tuple[int, _NodeValue], ...]
    source: bytes

    def member(self, offset: int) -> _NodeValue:
        for key, value in self.fields:
            if key == offset:
                return value
        raise TSEConversionError(f"native {self.kind} member {offset:#x} was not read")


_NodeValue = int | bytes | None | LegacyList | LegacyNode | LegacyConversionTable


def _native_list(reader: _Reader, kind: str) -> LegacyList:
    header, _ = _core(reader, 1)
    count = reader.integer()
    reader.count(count)
    return LegacyList(header, tuple(_native_node(reader, kind) for _ in range(count)))


def _native_node(reader: _Reader, kind: str) -> LegacyNode:
    """Legacy Read methods, including their original field order and versions."""
    start = reader.pos
    supported = {"ECU": 2, "DTC": 4, "Function": 4}.get(kind, 1)
    header, version = _core(reader, supported)
    fields: list[tuple[int, _NodeValue]] = []

    def number(offset: int, width: int = 4) -> None:
        fields.append((offset, reader.integer(width)))

    def string(offset: int) -> None:
        fields.append((offset, _string(reader)))

    def items(offset: int, item_kind: str) -> None:
        fields.append((offset, _native_list(reader, item_kind)))

    def base() -> None:
        # CCmdBaseInfo Read35370: five DWORDs after CCmdCore.
        for offset in (8, 0x10, 0x14, 0x18, 0x1C):
            number(offset)

    if kind in ("Count", "Highlight"):
        number(8, 2)
        number(10, 1)
    elif kind == "Detail":
        for offset in (8, 0xC, 0x10):
            number(offset)
    elif kind == "FuncDetail":
        number(8, 2)
        number(0xC)
    elif kind == "Func":
        # Read78290 / ctor78160.
        number(8, 2)
        number(0x1C, 2)
        string(0xC)
        items(0x20, "FuncDetail")
    elif kind == "DTC":
        # Read36290. This order deliberately differs from memory member order.
        string(0xC)
        string(0x20)
        number(0x30)
        number(0x34, 1)
        string(0x38)
        number(8, 2)
        if version >= 2:
            number(0x48)
            number(0x4C)
            signal = _freeze_signal(reader)
            fields.append((0x50, _freeze_node(signal)))
            number(0xE4)
            number(0xE8)
            fields.append((0xEC, _freeze_node(_freeze_signal(reader))))
        if version >= 3:
            number(0x180)
        if version >= 4:
            fields.append((0x184, _freeze_node(_freeze_signal(reader))))
    elif kind == "DTCInfo":
        # Read36660.
        string(8)
        number(0x18, 2)
        string(0x1C)
        for offset, width in ((0x2C, 1), (0x30, 4), (0x34, 1), (0x36, 2), (0x38, 2)):
            number(offset, width)
        items(0x3C, "Highlight")
    elif kind == "DTCList":
        base()
        number(0x20)
        items(0x24, "DTC")
        number(0x38)
    elif kind in ("DetailIDList", "DetailFreezeList"):
        base()
        number(0x20, 1)
        items(0x24, "Detail" if kind == "DetailIDList" else "Freeze")
    elif kind == "DetailList":
        base()
        number(0x20)
        items(0x24, "Freeze")
    elif kind == "FreezeList":
        # Read386a0: unaligned BYTE/WORD/DWORD fields.
        base()
        number(0x20, 1)
        number(0x22, 2)
        number(0x24)
        items(0x28, "Freeze")
    elif kind == "MultiFreezeList":
        # Original Read391c0 (three consecutive BYTEs), list ctor390a0.
        base()
        for offset in (0x20, 0x21, 0x22):
            number(offset, 1)
        items(0x24, "Freeze")
    elif kind == "FreezeNo":
        number(0x1C, 1)
        number(8, 2)
        string(0xC)
    elif kind == "Function":
        # Read17760, not the separate Func Read78290.
        string(8)
        for offset, width in ((0x18, 2), (0x1A, 2), (0x1C, 2), (0x20, 4), (0x24, 2)):
            number(offset, width)
        if version >= 2:
            number(0x26, 2)
        if version >= 3:
            number(0x28)
            number(0x2C)
        if version >= 4:
            for offset in (0x30, 0x34, 0x38, 0x3C):
                number(offset)
    elif kind == "ECU":
        # Read37fc0. The version-one form has no nested diagnostic families.
        number(8)
        string(0x10)
        number(0x20, 1)
        items(0x24, "Count")
        number(0x38)
        number(0x3C, 2)
        number(0x3E, 2)
        number(0x40, 1)
        if version >= 2:
            fields.append((0x44, _function_node(_function_info(reader))))
            for offset, item_kind in (
                (0x78, "DTCList"),
                (0x8C, "FreezeList"),
                (0xA0, "DetailIDList"),
                (0xB4, "DetailList"),
                (0xC8, "MultiFreezeList"),
                (0xDC, "DetailFreezeList"),
            ):
                items(offset, item_kind)
    elif kind == "Connection":
        base()
        items(0x20, "ECU")
        number(0x34)
        number(0x38)
        number(0x3C, 2)
    elif kind == "Freeze":
        # Reuse the exact typed decoder; it consumes its own CCmdCore header.
        reader.pos = start
        return _freeze_node(_freeze_signal(reader))
    else:
        raise TSEConversionError(f"native legacy object reader not recovered: {kind}")
    return LegacyNode(
        kind, header, version, tuple(fields), reader.data[start : reader.pos]
    )


def _freeze_node(signal: LegacyFreezeSignal) -> LegacyNode:
    # Signals have a dedicated DTO so scalar providers never depend on a tree schema.
    return LegacyNode(
        "Freeze",
        signal.header_raw,
        signal.header_raw[0] if signal.header_raw[0] <= 1 else 0,
        (
            (8, signal.identifier_raw),
            *zip((0xC, 0x1C, 0x2C), signal.string_fields_raw),
            (0x3C, signal.selector_raw),
            (0x3D, signal.field_3d_raw),
            (0x40, signal.conversion),
            (
                0x80,
                LegacyList(
                    signal.multi_header_raw,
                    tuple(
                        LegacyNode(
                            "MultiData",
                            item.header_raw,
                            item.header_raw[0] if item.header_raw[0] <= 1 else 0,
                            ((8, item.value_raw), (0xC, item.flag_raw)),
                            item.source,
                        )
                        for item in signal.multi_data
                    ),
                ),
            ),
        ),
        signal.source,
    )


def _function_node(info: LegacyFunctionInfo) -> LegacyNode:
    return LegacyNode(
        "FunctionInfo",
        info.header_raw,
        info.header_raw[0] if info.header_raw[0] <= 1 else 0,
        (
            *zip((8, 0x10, 0x14, 0x18, 0x1C), info.base_fields_raw),
            (
                0x20,
                LegacyList(
                    info.list_header_raw,
                    tuple(
                        LegacyNode(
                            "Func",
                            item.header_raw,
                            item.header_raw[0] if item.header_raw[0] <= 1 else 0,
                            (
                                (8, item.identifier_raw),
                                (0x1C, item.field_1c_raw),
                                (0xC, item.text_raw),
                                (
                                    0x20,
                                    LegacyList(
                                        item.details_header_raw,
                                        tuple(
                                            LegacyNode(
                                                "FuncDetail",
                                                detail.header_raw,
                                                detail.header_raw[0]
                                                if detail.header_raw[0] <= 1
                                                else 0,
                                                (
                                                    (8, detail.identifier_raw),
                                                    (0xC, detail.value_raw),
                                                ),
                                                detail.source,
                                            )
                                            for detail in item.details
                                        ),
                                    ),
                                ),
                            ),
                            item.source,
                        )
                        for item in info.functions
                    ),
                ),
            ),
        ),
        info.source,
    )


def decode_legacy_object(
    data: bytes, kind: str, *, cancelled: Callable[[], bool] | None = None
) -> LegacyNode:
    """Decode one original Legacy command object with an exact extent."""
    if type(data) is not bytes or len(data) > MAX_BYTES:
        raise TSEConversionError("legacy object exceeds host byte budget")
    if cancelled is not None and not callable(cancelled):
        raise TSEConversionError("cancellation predicate must be callable")
    reader = _Reader(data, cancelled)
    result = _native_node(reader, kind)
    if reader.pos != len(data):
        raise TSEConversionError("trailing native legacy object bytes")
    return result


class LegacyScalarProvider(Protocol):
    def __call__(
        self,
        selector: int,
        raw_value: int,
        table: LegacyConversionTable,
        field_3d: int,
        field_16: int,
        /,
        *,
        codepage: str,
        decimal_point: bytes = b".",
    ) -> bytes | None: ...


def _wide_prefix(raw: bytes) -> bytes:
    end = next(
        (i for i in range(0, len(raw) - 1, 2) if raw[i : i + 2] == b"\0\0"), None
    )
    if end is None:
        raise TSEConversionError("native wide CString reads beyond its stored extent")
    return raw[:end]


def _ansi(raw: bytes | None, codepage: str) -> bytes:
    """d940 / 16ae0: explicit thread ACP, UTF-16LE NUL-terminated source."""
    if raw is None:
        return b""
    try:
        return _wide_prefix(raw).decode("utf-16-le").encode(codepage)
    except (UnicodeError, LookupError) as exc:
        # Python has no Windows best-fit table. Never silently invent its output.
        raise TSEConversionError(
            "wide CString cannot be represented exactly in source ACP"
        ) from exc


def _packed_string(value: bytes) -> bytes:
    value = value.split(b"\0", 1)[0]
    if len(value) > 0xFFFF:
        raise TSEConversionError("native converted CString exceeds uint16 extent")
    return len(value).to_bytes(2, "little") + value


def convert_legacy_signal(
    data: bytes,
    *,
    codepage: str,
    scalar: LegacyScalarProvider,
    decimal_point: bytes = b".",
    cancelled: Callable[[], bool] | None = None,
) -> bytes:
    """Convert a real CCmdFrzFrmDat into the converter's saved signal wire.

    Shared by AD10790/11060/11ad0 and DC14880/15250/15c60. Native output
    omits the second legacy string and does not copy the display-choice list;
    that list is normalized for scalar evaluation only. No DLL is executed.
    """
    if type(data) is not bytes or len(data) > MAX_BYTES:
        raise TSEConversionError("legacy signal exceeds host byte budget")
    if cancelled is not None and not callable(cancelled):
        raise TSEConversionError("cancellation predicate must be callable")
    if not callable(scalar):
        raise TSEConversionError("explicit compatible legacy scalar provider required")
    # Validate even when every native string is NULL.
    try:
        "".encode(codepage)
    except (LookupError, TypeError) as exc:
        raise TSEConversionError("explicit source ACP codec required") from exc
    reader = _Reader(data, cancelled)
    signal = _freeze_signal(reader)
    if reader.pos != len(data):
        raise TSEConversionError("trailing native legacy signal bytes")
    table = signal.conversion
    normalized = replace(
        table,
        displays=tuple(
            replace(
                item,
                text_raw=None
                if item.text_raw is None
                else _ansi(item.text_raw, codepage) + b"\0",
            )
            for item in table.displays
        ),
    )
    chunks = [signal.identifier_raw.to_bytes(2, "little")]
    chunks += [
        _packed_string(_ansi(signal.string_fields_raw[0], codepage)),
        b"\0\0",
        _packed_string(_ansi(signal.string_fields_raw[2], codepage)),
        bytes((signal.selector_raw, signal.field_3d_raw)),
    ]
    chunks.extend(value.to_bytes(4, "little") for value in table.coefficients_raw)
    chunks.extend(
        (
            table.field_14_raw.to_bytes(2, "little"),
            bytes((table.field_16_raw,)),
            table.field_18_raw.to_bytes(2, "little"),
            b"\0\0",
        )
    )
    chunks.extend(value.to_bytes(4, "little") for value in table.fields_30_3c_raw)
    if len(signal.multi_data) > 0xFFFF:
        raise TSEConversionError("native converted signal value count exceeds uint16")
    chunks.append(len(signal.multi_data).to_bytes(2, "little"))
    output_size = sum(map(len, chunks))
    for item in signal.multi_data:
        reader.check()
        display = scalar(
            signal.selector_raw,
            item.value_raw,
            normalized,
            signal.field_3d_raw,
            table.field_16_raw,
            codepage=codepage,
            decimal_point=decimal_point,
        )
        if display is not None and type(display) is not bytes:
            raise TSEConversionError("legacy scalar returned a non-byte CString")
        text = _packed_string(display or b"")
        output_size += 5 + len(text)
        if output_size > MAX_BYTES:
            raise TSEConversionError("converted signal exceeds host byte budget")
        chunks.extend(
            (item.value_raw.to_bytes(4, "little"), text, bytes((item.flag_raw,)))
        )
    output = b"".join(chunks)
    if len(output) > MAX_BYTES:
        raise TSEConversionError("converted signal exceeds host byte budget")
    return output


@dataclass(frozen=True)
class LegacyFreezeFamilies:
    standard: bytes
    multi: bytes
    details: bytes = b"\0\0"
    detailed: bytes = b"\0\0"


def _node_number(node: LegacyNode, offset: int) -> int:
    value = node.member(offset)
    if type(value) is not int:
        raise TSEConversionError("native object member is not an integer")
    return value


def _node_list(node: LegacyNode, offset: int) -> LegacyList:
    value = node.member(offset)
    if not isinstance(value, LegacyList):
        raise TSEConversionError("native object member is not a list")
    return value


def _packed_records(records: tuple[bytes, ...]) -> bytes:
    if len(records) > 0xFFFF:
        raise TSEConversionError("native converted collection exceeds uint16 count")
    if sum(map(len, records)) > MAX_BYTES - 2:
        raise TSEConversionError("native converted collection exceeds host byte budget")
    return len(records).to_bytes(2, "little") + b"".join(records)


def convert_legacy_ecu_freezes(
    data: bytes,
    *,
    codepage: str,
    scalar: LegacyScalarProvider,
    decimal_point: bytes = b".",
    cancelled: Callable[[], bool] | None = None,
) -> LegacyFreezeFamilies:
    """AD roots10790/11060/11ad0: ordinary, multi and detailed saved families.

    Input is a complete original CCmdEcuInfo, not a synthesized current DTO.
    Outputs are the four native WORD-counted arrays inside DTCMon version1007.
    """
    ecu = decode_legacy_object(data, "ECU", cancelled=cancelled)
    if ecu.effective_version < 2:
        return LegacyFreezeFamilies(bytes(2), bytes(2))
    control = _Reader(b"", cancelled)

    def signals(frame: LegacyNode, offset: int) -> bytes:
        records = []
        total = 2
        for signal in _node_list(frame, offset).records:
            control.check()
            records.append(
                convert_legacy_signal(
                    signal.source,
                    codepage=codepage,
                    scalar=scalar,
                    decimal_point=decimal_point,
                    cancelled=cancelled,
                )
            )
            total += len(records[-1])
            if total > MAX_BYTES:
                raise TSEConversionError("converted frame exceeds host byte budget")
        return _packed_records(tuple(records))

    standard = []
    total = 4
    for frame in _node_list(ecu, 0x8C).records:
        control.check()
        standard.append(
            _node_number(frame, 0x22).to_bytes(2, "little")
            + bytes((_node_number(frame, 0x20),))
            + _node_number(frame, 0x24).to_bytes(4, "little")
            + signals(frame, 0x28)
        )
        total += len(standard[-1])
        if total > MAX_BYTES:
            raise TSEConversionError("converted ECU exceeds host byte budget")
    multi = []
    for frame in _node_list(ecu, 0xC8).records:
        control.check()
        multi.append(
            bytes((_node_number(frame, 0x20),))
            + signals(frame, 0x24)
            + bytes((_node_number(frame, 0x21), _node_number(frame, 0x22)))
        )
        total += len(multi[-1])
        if total > MAX_BYTES:
            raise TSEConversionError("converted ECU exceeds host byte budget")
    details = []
    detailed = []
    # Root11ad0 matches only the first DetailList with the selected detail ID.
    for group in _node_list(ecu, 0xA0).records:
        control.check()
        kind = _node_number(group, 0x20)
        selected = []
        last_frame_id = 0
        for detail in _node_list(group, 0x24).records:
            control.check()
            if _node_number(detail, 0x10) != 1:
                continue
            identifier = _node_number(detail, 8)
            selected.append(
                identifier.to_bytes(4, "little")
                + _node_number(detail, 0xC).to_bytes(4, "little")
                + (1).to_bytes(4, "little")
                + b"\0\0\x01\0!"
            )
            body = bytes(2)
            for frame in _node_list(ecu, 0xB4).records:
                control.check()
                if _node_number(frame, 0x20) == identifier:
                    last_frame_id = identifier
                    body = signals(frame, 0x24)
                    break
            # Native local214 is initialized once per group; a missing later
            # match retains the previous ID, but the signal list is cleared.
            detailed.append(
                bytes((kind,)) + last_frame_id.to_bytes(4, "little") + bytes(4) + body
            )
            total += len(selected[-1]) + len(detailed[-1])
            if total > MAX_BYTES:
                raise TSEConversionError("converted ECU exceeds host byte budget")
        details.append(bytes((kind,)) + _packed_records(tuple(selected)))
    return LegacyFreezeFamilies(
        _packed_records(tuple(standard)),
        _packed_records(tuple(multi)),
        _packed_records(tuple(details)),
        _packed_records(tuple(detailed)),
    )


def _exact_reply(
    data: bytes, kind: str, cancelled: Callable[[], bool] | None
) -> LegacyReply:
    reader = _Reader(data, cancelled)
    result = _reply(reader, kind)
    if reader.pos != len(data):
        raise TSEConversionError("trailing native legacy reply bytes")
    return result


def convert_legacy_dc_freezes(
    source: LegacySource,
    *,
    codepage: str,
    scalar: LegacyScalarProvider,
    decimal_point: bytes = b".",
    cancelled: Callable[[], bool] | None = None,
) -> LegacyFreezeFamilies:
    """DC roots14880/15250/15c60 over the actual saved send/receive records."""
    if source.extension != ".DC" or source.record_type != 6 or len(source.groups) != 3:
        raise TSEConversionError("native DC6 source required")
    control = _Reader(b"", cancelled)
    total = 8

    def signals(reply: LegacyReply) -> bytes:
        nonlocal total
        assert reply.list_data is not None
        records = []
        for signal in reply.list_data.records:
            control.check()
            value = convert_legacy_signal(
                signal.source,
                codepage=codepage,
                scalar=scalar,
                decimal_point=decimal_point,
                cancelled=cancelled,
            )
            total += len(value)
            if total > MAX_BYTES:
                raise TSEConversionError("converted DC exceeds host byte budget")
            records.append(value)
        return _packed_records(tuple(records))

    standard = []
    multi = []
    details = []
    detailed = []
    for _, send_data, receive_data in source.groups[0].records:
        control.check()
        if not send_data or not receive_data:
            continue
        send = _exact_reply(send_data, "CGetFrzFrmDatSnd", cancelled)
        receive = _exact_reply(receive_data, "CGetFrzFrmDatRcv", cancelled)
        standard.append(
            send.prefix_fields_raw[1].to_bytes(2, "little")
            + bytes((send.prefix_fields_raw[0],))
            + receive.prefix_fields_raw[0].to_bytes(4, "little")
            + signals(receive)
        )
    for identifier, _, receive_data in source.groups[1].records:
        control.check()
        if not receive_data:
            continue
        receive = _exact_reply(receive_data, "CGetMultiFrzFrmDatRcv", cancelled)
        multi.append(
            bytes((identifier & 0xFF,))
            + signals(receive)
            + bytes(receive.prefix_fields_raw)
        )
    if source.multi_group is not None:
        # The native loop is bounded by both the send and detail-group counts.
        for (_, send_data, _), (detail_data, slots) in zip(
            source.groups[0].records, source.multi_group.records
        ):
            control.check()
            if not send_data:
                continue
            send = _exact_reply(send_data, "CGetFrzFrmDatSnd", cancelled)
            kind = send.prefix_fields_raw[0]
            if not detail_data:
                continue
            reply = _exact_reply(detail_data, "CGetDiagDetailIdListRcv", cancelled)
            assert reply.list_data is not None
            if len(reply.list_data.records) > 20:
                raise TSEConversionError(
                    "native detail selection would overwrite twenty-byte flag storage"
                )
            selected = []
            for detail in reply.list_data.records:
                if _node_number(detail, 0x10) == 1:
                    selected.append(
                        _node_number(detail, 8).to_bytes(4, "little")
                        + _node_number(detail, 0xC).to_bytes(4, "little")
                        + (1).to_bytes(4, "little")
                        + b"\0\0\x01\0!"
                    )
            details.append(bytes((kind,)) + _packed_records(tuple(selected)))
            for index, detail in enumerate(reply.list_data.records[:5]):
                control.check()
                if _node_number(detail, 0x10) & 0xFF != 1 or not slots[index][1]:
                    continue
                receive = _exact_reply(slots[index][1], "CGetDiagDetailRcv", cancelled)
                detailed.append(
                    bytes((kind,))
                    + (index + 1).to_bytes(4, "little")
                    + bytes(4)
                    + signals(receive)
                )
    output_size = 8 + sum(
        len(record)
        for records in (standard, multi, details, detailed)
        for record in records
    )
    if output_size > MAX_BYTES:
        raise TSEConversionError("converted DC exceeds host byte budget")
    return LegacyFreezeFamilies(
        *(
            _packed_records(tuple(records))
            for records in (standard, multi, details, detailed)
        )
    )


@dataclass(frozen=True)
class _ConvertedDTC:
    identifier: int
    code: bytes
    name: bytes
    value: int
    flag: int
    details: tuple[tuple[int, int, int], ...]
    states: tuple[int, int, int, int]
    marker: bytes
    marker_state: int

    def wire(self) -> bytes:
        detail_records = tuple(
            kind.to_bytes(4, "little")
            + value.to_bytes(4, "little")
            + bytes((flag,))
            + bytes(5)
            for kind, value, flag in self.details
        )
        chunks = [
            self.identifier.to_bytes(2, "little"),
            _packed_string(self.code),
            bytes(2),
            _packed_string(self.name),
            self.value.to_bytes(4, "little"),
            bytes((self.flag,)),
            bytes(2),
            _packed_records(detail_records),
        ]
        chunks.extend(_packed_string(b"X" if state else b"") for state in self.states)
        chunks.extend(state.to_bytes(4, "little") for state in self.states)
        chunks.extend((_packed_string(self.marker), bytes((self.marker_state,))))
        return b"".join(chunks)


def _node_text(node: LegacyNode, offset: int, codepage: str) -> bytes:
    value = node.member(offset)
    if value is not None and not isinstance(value, bytes):
        raise TSEConversionError("native object member is not a CString")
    return _ansi(value, codepage)


def _dtc_row(
    node: LegacyNode, kind: int, marker: tuple[bytes, int], codepage: str
) -> _ConvertedDTC:
    value, flag = _node_number(node, 0x30), _node_number(node, 0x34)
    if kind not in (1, 2, 4):
        raise TSEConversionError("unrecovered native DTC list selector")
    pending = False
    if kind == 4:
        raw = node.member(0x38)
        if not isinstance(raw, bytes):
            raise TSEConversionError(
                "native pending DTC comparison reads a NULL wide string"
            )
        pending = _wide_prefix(raw) != "DTC-NONE".encode("utf-16-le")
    return _ConvertedDTC(
        _node_number(node, 8),
        _node_text(node, 0xC, codepage),
        _node_text(node, 0x20, codepage),
        value,
        flag,
        (((999 if kind == 4 else kind), value, flag),) if value == 1 else (),
        (int(kind == 1), int(kind == 2), int(pending), 0),
        *marker,
    )


def _merge_dtc_rows(rows: list[_ConvertedDTC], control: _Reader) -> bytes:
    # Match native selection-sort swaps (including equal-ID reordering), using
    # a position heap so a 100,000-record saved input does not take O(n²).
    heap = [(row.identifier, index, index, row) for index, row in enumerate(rows)]
    heapq.heapify(heap)
    ticket = len(rows)
    for index in range(len(rows)):
        control.check()
        while True:
            _, position, _, row = heapq.heappop(heap)
            if position >= index and rows[position] is row:
                break
        if position != index:
            displaced = rows[index]
            rows[index], rows[position] = row, displaced
            heapq.heappush(heap, (displaced.identifier, position, ticket, displaced))
            ticket += 1
    merged: list[_ConvertedDTC] = []
    detail_lists: list[list[tuple[int, int, int]]] = []
    for row in rows:
        control.check()
        if not merged or row.identifier != merged[-1].identifier:
            merged.append(row)
            detail_lists.append(list(row.details))
            continue
        previous = merged[-1]
        use_other = row.value == 1 and (previous.value == 0 or previous.flag < row.flag)
        merged[-1] = replace(
            previous,
            value=previous.value | row.value,
            flag=row.flag if use_other else previous.flag,
            states=tuple(
                a | b for a, b in zip(previous.states, row.states, strict=True)
            ),
            marker=row.marker if use_other else previous.marker,
            marker_state=row.marker_state if use_other else previous.marker_state,
        )
        detail_lists[-1].extend(row.details)
    return _packed_records(
        tuple(
            replace(row, details=tuple(details)).wire()
            for row, details in zip(merged, detail_lists, strict=True)
        )
    )


def convert_legacy_ecu_dtcs(
    data: bytes, *, codepage: str, cancelled: Callable[[], bool] | None = None
) -> bytes:
    """AD rootf930 and native4190..439a: map, sort and merge saved DTC rows."""
    ecu = decode_legacy_object(data, "ECU", cancelled=cancelled)
    if ecu.effective_version < 2:
        return bytes(2)
    control = _Reader(b"", cancelled)
    rows = []
    for group in _node_list(ecu, 0x78).records:
        kind = _node_number(group, 0x20)
        for dtc in _node_list(group, 0x24).records:
            control.check()
            marker = (b"", 1)
            if _node_number(dtc, 0x30) == 1:
                marker = (b"!!", 3)
                for frame in _node_list(ecu, 0x8C).records:
                    control.check()
                    if (
                        _node_number(frame, 0x20) == _node_number(dtc, 0x34)
                        and _node_number(frame, 0x24) == 1
                    ):
                        marker = (b"!!!", 4)
                        break
            rows.append(_dtc_row(dtc, kind, marker, codepage))
    return _merge_dtc_rows(rows, control)


def convert_legacy_dc_dtcs(
    source: LegacySource, *, codepage: str, cancelled: Callable[[], bool] | None = None
) -> bytes:
    """DC root13210 + marker14540: map three real saved DTC list streams."""
    if source.extension != ".DC" or source.record_type != 6 or len(source.groups) != 3:
        raise TSEConversionError("native DC6 source required")
    control = _Reader(b"", cancelled)
    rows = []
    for kind, data in zip((1, 2, 4), source.blobs[1:4], strict=True):
        if not data:
            continue
        group = decode_legacy_object(data, "DTCList", cancelled=cancelled)
        for dtc in _node_list(group, 0x24).records:
            control.check()
            marker = (b"", 1)
            if _node_number(dtc, 0x30) == 1 and source.groups[0].records:
                marker = (b"!!", 3)
                for _, send_data, receive_data in source.groups[0].records:
                    control.check()
                    if not send_data or not receive_data:
                        continue
                    send = _exact_reply(send_data, "CGetFrzFrmDatSnd", cancelled)
                    receive = _exact_reply(receive_data, "CGetFrzFrmDatRcv", cancelled)
                    if (
                        send.prefix_fields_raw[0] == _node_number(dtc, 0x34)
                        and receive.prefix_fields_raw[0] == 1
                    ):
                        marker = (b"!!!", 4)
                        break
            rows.append(_dtc_row(dtc, kind, marker, codepage))
    return _merge_dtc_rows(rows, control)


def _converted_function(function: LegacyNode) -> bytes:
    details = tuple(
        _node_number(item, 8).to_bytes(2, "little") + bytes(4)
        for item in _node_list(function, 0x20).records
    )
    return (
        _node_number(function, 8).to_bytes(2, "little")
        + bytes(4)
        + _packed_records(details)
    )


def _selected_function(info: LegacyNode) -> LegacyNode | None:
    return next(
        (
            item
            for item in _node_list(info, 0x20).records
            if _node_number(item, 8) in (1, 0x10)
        ),
        None,
    )


def _metadata_ecu_name(data: bytes, codepage: str) -> bytes:
    reader = _Reader(data, None)
    reader.take(6)
    reader.blob(2)
    reader.blob(2)
    reader.take(28)
    for _ in range(3):
        reader.blob(2)
    reader.take(8)
    reader.blob(2)
    raw = reader.blob(2)
    return _ansi(raw if raw else None, codepage)


def convert_legacy(
    data: bytes,
    *,
    extension: str,
    codepage: str,
    caller_time: bytes,
    decimal_point: bytes = b".",
    cancelled: Callable[[], bool] | None = None,
) -> bytes:
    """Convert native AD3/DC6 saved records into a complete native TSE file.

    The original caller supplies FOUR DWORDs by value as the common date; this
    API requires those exact16 bytes. It never substitutes the saved input date.
    The host assembler computes offsets from actual emitted fragment sizes.
    """
    from scripts import snapshot, tse_reports
    from scripts.legacy_scalar import convert_legacy_scalar

    if type(caller_time) is not bytes or len(caller_time) != 16:
        raise TSEConversionError("explicit sixteen-byte native caller time required")
    if type(decimal_point) is not bytes or len(decimal_point) != 1:
        raise TSEConversionError("explicit one-byte native decimal point required")
    try:
        "".encode(codepage)
    except (LookupError, TypeError) as exc:
        raise TSEConversionError("explicit source ACP codec required") from exc
    source = decode_legacy(data, extension=extension, cancelled=cancelled)
    control = _Reader(b"", cancelled)
    # Each pair is the native EcuData prefix and its separately indexed DTCMon.
    groups: list[tuple[bytes, bytes]] = []
    group_bytes = 0

    def append_group(
        identifier: int,
        name: bytes,
        function: LegacyNode,
        number: int,
        dtcs: bytes,
        freezes: LegacyFreezeFamilies,
    ) -> None:
        nonlocal group_bytes
        control.check()
        if len(groups) >= 4096:
            raise TSEConversionError(
                "converted ECU count exceeds native index host budget"
            )
        metadata = (
            bytes.fromhex("00100000")
            + bytes(2)
            + identifier.to_bytes(4, "little")
            + bytes(2)
            + _packed_string(name)
            + _packed_records((_converted_function(function),))
            + bytes(80)
        )
        common = bytes.fromhex("0010") + _packed_string(
            f"Data {number}".encode("ascii")
        )
        common += (16).to_bytes(2, "little") + caller_time + bytes(2)
        report = bytes.fromhex("ffffffff06ffffff07100100") + common + dtcs
        report += (
            freezes.standard
            + freezes.multi
            + freezes.details
            + freezes.detailed
            + bytes(14 + 80)
        )
        group_bytes += len(metadata) + len(report)
        if group_bytes > MAX_BYTES:
            raise TSEConversionError("converted groups exceed host byte budget")
        groups.append((metadata, report))

    if source.extension == ".AD" and source.blobs[1]:
        connection = decode_legacy_object(
            source.blobs[1], "Connection", cancelled=cancelled
        )
        for index, ecu in enumerate(_node_list(connection, 0x20).records):
            control.check()
            if ecu.effective_version < 2:
                continue
            info = ecu.member(0x44)
            assert isinstance(info, LegacyNode)
            function = _selected_function(info)
            if function is None:
                continue
            freezes = convert_legacy_ecu_freezes(
                ecu.source,
                codepage=codepage,
                scalar=convert_legacy_scalar,
                decimal_point=decimal_point,
                cancelled=cancelled,
            )
            append_group(
                _node_number(ecu, 8),
                _node_text(ecu, 0x10, codepage),
                function,
                (index & 0xFFFF) + 1,
                convert_legacy_ecu_dtcs(
                    ecu.source, codepage=codepage, cancelled=cancelled
                ),
                freezes,
            )
    elif source.extension == ".DC" and source.blobs[5]:
        reader = _Reader(source.blobs[5], cancelled)
        info = _function_node(_function_info(reader))
        if reader.pos != len(reader.data):
            raise TSEConversionError("trailing native function-info bytes")
        function = _selected_function(info)
        if function is not None:
            append_group(
                _node_number(info, 8),
                _metadata_ecu_name(source.metadata_raw, codepage),
                function,
                1,
                convert_legacy_dc_dtcs(source, codepage=codepage, cancelled=cancelled),
                convert_legacy_dc_freezes(
                    source,
                    codepage=codepage,
                    scalar=convert_legacy_scalar,
                    decimal_point=decimal_point,
                    cancelled=cancelled,
                ),
            )
    control.check()
    ini = tse_reports.encode_section(
        tse_reports.ReportSection(
            "IniCarInfo",
            0xFFFFFFFF,
            0xFFFFFF01,
            0x1000,
            (b"", (), (), (), 0, 0, bytes(80)),
        )
    )
    conf_fields = (b"",) * 9 + (0, b"", 0, 0, caller_time) + (b"",) * 6
    conf_fields += (source.record_type.to_bytes(2, "little") + bytes(78),)
    conf = tse_reports.encode_section(
        tse_reports.ReportSection(
            "ConfCarInfo", 0xFFFFFFFF, 0xFFFFFF02, 0x100F, conf_fields
        )
    )
    template = snapshot.create_tse_header(
        snapshot.TSEHeader(
            "TSE",
            8,
            0x1013,
            0,
            0x25,
            0,
            3,
            b"",
            b"",
            tuple(range(len(groups))),
            (0x2711, 0x2713, 0x2716),
            bytes(80),
        )
    )
    fragments = []
    ecu_index = -1
    for entry in template.metadata["index_entries"]:
        control.check()
        tag = entry["tag"]
        if tag == "IniCarInfo":
            fragment = ini
        elif tag == "ConfCarInfo":
            fragment = conf
        elif tag == "ECUInfo":
            fragment = (
                (
                    bytes.fromhex("ffffffff04ffffff0310")
                    + len(groups).to_bytes(2, "little")
                )
                if groups
                else b""
            )
        elif tag == "EcuData":
            ecu_index += 1
            fragment = groups[ecu_index][0]
        elif tag == "DTCMon":
            fragment = groups[ecu_index][1]
        else:
            fragment = b""
        fragments.append(fragment)
    try:
        return snapshot.assemble_tse(template, tuple(fragments)).source
    except snapshot.SnapshotError as exc:
        raise TSEConversionError(
            f"native converted index assembly failed: {exc}"
        ) from exc


def _function_info(reader: _Reader) -> LegacyFunctionInfo:
    # Legacy Read37980→BaseInfo35370; Func78290 and FuncDetail780e0.
    start = reader.pos
    header, _ = _core(reader, 1)
    base = tuple(reader.integer() for _ in range(5))
    list_header, _ = _core(reader, 1)
    count = reader.integer()
    reader.count(count)
    functions = []
    for _ in range(count):
        item_start = reader.pos
        item_header, _ = _core(reader, 1)
        identifier, field_1c = reader.integer(2), reader.integer(2)
        text = _string(reader)
        details_header, _ = _core(reader, 1)
        detail_count = reader.integer()
        reader.count(detail_count)
        details = []
        for _ in range(detail_count):
            detail_start = reader.pos
            detail_header, _ = _core(reader, 1)
            detail_id, value = reader.integer(2), reader.integer()
            details.append(
                LegacyFunctionDetail(
                    detail_header,
                    detail_id,
                    value,
                    reader.data[detail_start : reader.pos],
                )
            )
        functions.append(
            LegacyFunction(
                item_header,
                identifier,
                field_1c,
                text,
                details_header,
                tuple(details),
                reader.data[item_start : reader.pos],
            )
        )
    return LegacyFunctionInfo(
        header,
        (base[0], base[1], base[2], base[3], base[4]),
        list_header,
        tuple(functions),
        reader.data[start : reader.pos],
    )


def _decode_block(data: bytes, capacity: int, reader: _Reader) -> bytes:
    """DataDecode@12, including input-exhaustion termination (RVA 1bd0).

    The native wrapper checks only the declared output prefix. Native writes
    beyond its allocation or reads from its uninitialized dictionary fail here.
    """
    if len(data) < 5:
        raise TSEConversionError("truncated native compression header")
    expected = int.from_bytes(data[:4], "little")
    if expected > capacity:
        raise TSEConversionError("native compression would exceed its allocation")
    ring = bytearray(4096)
    initialized = bytearray(4096)
    output = bytearray()
    pos, write, flags, next_check = 5, 0xFEE, 0, 0
    while True:
        if len(output) >= next_check:
            reader.check()
            next_check = len(output) + 4096
        flags >>= 1
        if not flags & 0x100:
            if pos == len(data):
                break
            flags = data[pos] | 0xFF00
            pos += 1
        if pos == len(data):
            break
        low = data[pos]
        pos += 1
        if flags & 1:
            offset, length = 0, 1
        else:
            if pos == len(data):
                break
            high = data[pos]
            pos += 1
            offset, length = low | ((high & 0xF0) << 4), (high & 15) + 3
        if length > capacity - len(output):
            raise TSEConversionError(
                "native compression would overwrite its allocation"
            )
        for index in range(length):
            source = (offset + index) & 0xFFF
            if not flags & 1 and not initialized[source]:
                raise TSEConversionError(
                    "native compression reads uninitialized dictionary"
                )
            value = low if flags & 1 else ring[source]
            output.append(value)
            ring[write] = value
            initialized[write] = 1
            write = (write + 1) & 0xFFF
    if len(output) < expected:
        raise TSEConversionError("native checksum would read uninitialized output")
    checksum = 0
    for index, value in enumerate(output[:expected]):
        if not index % 4096:
            reader.check()
        checksum |= value
    if checksum != data[4]:
        raise TSEConversionError("native compression OR checksum mismatch")
    return bytes(output[:expected])


def _metadata(reader: _Reader) -> bytes:
    # Converter RVA 1a190: I,H,H-blob,H-blob,8,16,4,three H-blobs,8,two H-blobs.
    start = reader.pos
    reader.take(6)
    reader.blob(2)
    reader.blob(2)
    reader.take(28)
    for _ in range(3):
        reader.blob(2)
    reader.take(8)
    reader.blob(2)
    reader.blob(2)
    return reader.data[start : reader.pos]


def _group(reader: _Reader) -> LegacyGroup:
    # Converter RVA 184e0/185b0; type 6 includes the first detail blob.
    header, count = reader.integer(), reader.integer()
    reader.count(count)
    records = []
    for _ in range(count):
        records.append((reader.integer(), reader.blob(), reader.blob()))
    return LegacyGroup(header, tuple(records))


def _multi_group(reader: _Reader) -> LegacyMultiGroup:
    # Converter RVA 18610: each record has a blob and exactly five I/I/blob items.
    header, count = reader.integer(), reader.integer()
    reader.count(count * 6)
    records = []
    for _ in range(count):
        first = reader.blob()
        items = tuple((reader.integer(), reader.blob()) for _ in range(5))
        records.append((first, items))
    return LegacyMultiGroup(header, tuple(records))


def decode_legacy(
    data: bytes,
    *,
    extension: str,
    cancelled: Callable[[], bool] | None = None,
) -> LegacySource:
    """Read actual AD3/DC6 outer and inner native streams, preserving opaque bytes.

    This is the converter's input reader; it does not perform business conversion
    or infer text encoding. The host budgets are 32 MiB and 100,000 records.
    """
    if type(data) is not bytes or len(data) > MAX_BYTES:
        raise TSEConversionError("legacy source exceeds host byte budget")
    if extension not in (".AD", ".ad", ".Ad", ".aD", ".DC", ".dc", ".Dc", ".dC"):
        raise TSEConversionError("expected native .AD or .DC input extension")
    if cancelled is not None and not callable(cancelled):
        raise TSEConversionError("cancellation predicate must be callable")
    extension = extension.upper()
    outer = _Reader(data, cancelled)
    outer.check()
    if len(data) < 10:
        raise TSEConversionError("truncated native legacy container")
    outer_type = int.from_bytes(data[4:6], "little")
    if extension == ".DC" and outer_type < 4:
        raise TSEConversionError("native DC conversion requires inner type 6")
    metadata_size = int.from_bytes(data[6:10], "little")
    prefix_size = metadata_size + 26
    outer.take(prefix_size)
    first_size = outer.integer()
    outer.take(first_size)
    prefix_size = outer.pos
    compression, compressed_size = outer.integer(), outer.integer()
    if compression:
        allocation = (int.from_bytes(data[:4], "little") + 4) & 0xFFFFFFFF
        if allocation > MAX_BYTES:
            raise TSEConversionError("legacy allocation exceeds host byte budget")
        inner = _decode_block(outer.take(compressed_size), allocation, outer)
        outer_trailing = data[outer.pos :]
    else:
        # RVA 198f0 ignores the stored size in the uncompressed branch.
        inner = data[outer.pos :]
        outer_trailing = b""
    reader = _Reader(inner, cancelled)
    reader.take(4)  # Size is consumed, not validated by native Read17970/17ea0.
    record_type = reader.integer(2)
    if record_type != (3 if extension == ".AD" else 6):
        raise TSEConversionError("unexpected native legacy record type")
    metadata = _metadata(reader)
    time_raw = reader.take(16)
    blobs = [reader.blob()]
    groups: tuple[LegacyGroup, ...] = ()
    multi = None
    if extension == ".AD":
        blobs.extend((reader.blob(), reader.blob()))
    else:
        blobs.extend(reader.blob() for _ in range(3))
        first, second = _group(reader), _group(reader)
        multi = _multi_group(reader)
        groups = (first, second, _group(reader))
        blobs.extend((reader.blob(), reader.blob()))
    return LegacySource(
        data,
        inner,
        extension,
        record_type,
        metadata,
        time_raw,
        tuple(blobs),
        groups,
        multi,
        inner[reader.pos :],
        compression,
        compressed_size,
        data[:prefix_size],
        outer_trailing,
    )
