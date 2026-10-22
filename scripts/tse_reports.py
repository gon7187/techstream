"""Strict native TSE report-section bodies recovered from GTSFileController.

Native text, reserved fields and numeric selectors retain their original bytes.
No proprietary module is loaded and no vehicle communication occurs.
"""

from __future__ import annotations

import codecs
import datetime
import io
import lzma
import re
import struct
import xml.etree.ElementTree as ET
import zipfile
import zlib
from dataclasses import dataclass, fields, is_dataclass, replace
from typing import Any, NoReturn
from xml.parsers import expat

from scripts import snapshot
from scripts.local_files import read_regular
from scripts.signal_display import render_signal

MAX_BYTES = snapshot.MAX_BYTES
MAX_NODES = 100_000
ReportError = snapshot.SnapshotError
_SEQUENCE_CHECK_BYTES = 384


def _charge_sequence_check(budget: list[int]) -> None:
    if budget[0] + 1 > MAX_NODES or budget[1] + _SEQUENCE_CHECK_BYTES > MAX_BYTES:
        raise ReportError("DDR sequence admission metadata exceeds aggregate budget")
    budget[0] += 1
    budget[1] += _SEQUENCE_CHECK_BYTES


@dataclass(frozen=True)
class _Named:
    kind: str
    layout: Any
    full: bool = False
    extended: bool = False
    version: int = 0
    flavor: int = 0


@dataclass(frozen=True)
class _Dynamic:
    resolve: Any


@dataclass(frozen=True)
class _Monitor:
    version: int


@dataclass(frozen=True)
class _Array:
    item: Any
    width: int = 2


@dataclass(frozen=True)
class _Raw:
    size: int


@dataclass(frozen=True)
class _Blob:
    width: int = 2
    limit: int = MAX_BYTES


_BLOB = _Blob()


class _Codec:
    def __init__(self, data: bytes | None = None):
        if data is not None and (not isinstance(data, bytes) or len(data) > MAX_BYTES):
            raise ReportError("native report input exceeds byte budget or is not bytes")
        self.cursor = snapshot.Cursor(data) if data is not None else None
        self.output = bytearray()
        self.nodes = 0
        self.active: set[int] = set()

    def integer(self, width: int, value: int | None = None) -> int:
        if self.cursor is not None:
            return int.from_bytes(self.cursor.take(width), "little")
        if type(value) is not int or not 0 <= value < 1 << (width * 8):
            raise ReportError(f"native report integer must fit uint{width * 8}")
        self.put(value.to_bytes(width, "little"))
        return value

    def put(self, data: bytes) -> None:
        if len(data) > MAX_BYTES - len(self.output):
            raise ReportError("native report exceeds byte budget")
        self.output.extend(data)

    def node(
        self, layout: Any, value: Any = None, depth: int = 0, scope: tuple = ()
    ) -> Any:
        self.nodes += 1
        if self.nodes > MAX_NODES or depth > 64:
            raise ReportError("native report exceeds structural budget")
        if isinstance(layout, _Named):
            result = self.node(layout.layout, value, depth + 1, scope)
            if layout.kind == "image" and result[2] > len(result[1]):
                raise ReportError("native image stored-size span exceeds buffer")
            return result
        if isinstance(layout, _Dynamic):
            return self.node(layout.resolve(scope), value, depth + 1)
        if type(layout) is int:
            return self.integer(layout, value)
        if isinstance(layout, _Monitor):
            if self.cursor is not None:
                value = snapshot._read_tse_datalist(self.cursor, layout.version)
                # Shared reader includes the caller-owned 80-byte reserved area.
                # Report families may insert fields before that area.
                self.cursor.position -= 80
                return replace(value, reserved=b"")
            if not isinstance(value, snapshot.TSEDataList) or value.reserved:
                raise ReportError("expected native monitor body without reserved tail")
            section = snapshot.TSEDataListSection(
                0xFFFFFFFF,
                0xFFFFFF05,
                layout.version,
                (replace(value, reserved=bytes(80)),),
            )
            self.put(snapshot.encode_tse_datalist_section(section)[12:-80])
            return value

        if isinstance(layout, (_Raw, _Blob)):
            if self.cursor is not None:
                size = (
                    layout.size
                    if isinstance(layout, _Raw)
                    else self.integer(layout.width)
                )
                if isinstance(layout, _Blob) and size > layout.limit:
                    raise ReportError("native report buffer exceeds field limit")
                return self.cursor.take(size)
            if not isinstance(value, bytes):
                raise ReportError("native report buffer must be bytes")
            if isinstance(layout, _Raw):
                if len(value) != layout.size:
                    raise ReportError("native fixed buffer has wrong size")
            else:
                if len(value) > layout.limit:
                    raise ReportError("native report buffer exceeds field limit")
                self.integer(layout.width, len(value))
            self.put(value)
            return value
        if self.cursor is not None:
            if isinstance(layout, _Array):
                count = self.integer(layout.width)
                if count > MAX_NODES - self.nodes:
                    raise ReportError("native report count exceeds node budget")
                return tuple(
                    self.node(layout.item, depth=depth + 1) for _ in range(count)
                )
            children: list = []
            for item in layout:
                children.append(self.node(item, depth=depth + 1, scope=tuple(children)))
            return tuple(children)
        if not isinstance(value, tuple):
            raise ReportError("native report aggregate must be a tuple")
        identity = id(value)
        if identity in self.active:
            raise ReportError("recursive native report input")
        self.active.add(identity)
        try:
            if isinstance(layout, _Array):
                if len(value) > MAX_NODES - self.nodes:
                    raise ReportError("native report count exceeds node budget")
                self.integer(layout.width, len(value))
                for item in value:
                    self.node(layout.item, item, depth + 1)
            else:
                if len(value) != len(layout):
                    raise ReportError("native report field count mismatch")
                for index, (item, child) in enumerate(zip(layout, value, strict=True)):
                    self.node(item, child, depth + 1, scope=value[:index])
        finally:
            self.active.remove(identity)
        return value


@dataclass(frozen=True)
class ReportSection:
    family: str
    identifier: int
    type_raw: int
    version: int
    records: tuple
    context_mode: int = 0

    def to_dict(self) -> dict:
        return _report_dict(self, [0, 0])


def _report_dict(section: ReportSection, budget: list[int]) -> dict:
    # Validate authored replacements too, before recursive presentation.
    encode_section(section)

    def convert(value: Any) -> Any:
        budget[0] += 1
        budget[1] += 64
        if budget[0] > MAX_NODES or budget[1] > MAX_BYTES:
            raise ReportError("report presentation exceeds aggregate budget")
        if isinstance(value, bytes):
            budget[1] += 2 * len(value)
            if budget[1] > MAX_BYTES:
                raise ReportError("report presentation exceeds byte budget")
            return {"bytes_hex": value.hex()}
        if is_dataclass(value) and not isinstance(value, type):
            return {
                field.name: convert(getattr(value, field.name))
                for field in fields(value)
            }
        if isinstance(value, tuple):
            return [convert(item) for item in value]
        return value

    return {
        "family": section.family,
        "identifier": section.identifier,
        "type_raw": section.type_raw,
        "version": section.version,
        "context_mode": section.context_mode,
        "records": convert(section.records),
        "provenance": "GTSFileController-native-static-layout",
    }


def decode_section(family: str, data: bytes, *, context_mode: int = 0) -> ReportSection:
    codec = _Codec(data)
    identifier, type_raw, version = (codec.integer(size) for size in (4, 4, 2))
    layout = _section_layout(family, type_raw, version, context_mode)
    records = codec.node(layout)
    assert codec.cursor is not None
    codec.cursor.end()
    return ReportSection(family, identifier, type_raw, version, records, context_mode)


def encode_section(section: ReportSection) -> bytes:
    layout = _section_layout(
        section.family, section.type_raw, section.version, section.context_mode
    )
    codec = _Codec()
    for width, value in (
        (4, section.identifier),
        (4, section.type_raw),
        (2, section.version),
    ):
        codec.integer(width, value)
    codec.node(layout, section.records)
    return bytes(codec.output)


def _section_layout(
    family: str, type_raw: int, version: int, context_mode: int = 0
) -> Any:
    if type(version) is not int or not 0x1000 <= version <= (
        0x2009 if family in ("ErrRep", "TMRRep") else 0x1027
    ):
        raise ReportError("unsupported native report version")
    if family in ("SysChk", "FuelCon") and version > 0x1021:
        raise ReportError("unsupported native monitor-backed report version")
    if type(context_mode) is not int or context_mode not in (0, 1):
        raise ReportError("native report context mode must be 0 or 1")

    def call(function: str, flavor: int = 1, full: bool = True) -> Any:
        return _layout(function, version, flavor, full)

    if family == "IniCarInfo":
        return (
            _BLOB,
            _Array((4, 4, _BLOB)),
            _Array((2, _BLOB)),
            _Array((2, _BLOB)),
            2,
            2,
            _Raw(80),
        )
    if family == "ConfCarInfo":
        values = (_BLOB,) * 9 + (4, _BLOB, 4)
        if version >= 0x100A:
            values += (4,)
        if version > 0x100A:
            values += (_Blob(limit=16),)
        if version > 0x100B:
            values += (_BLOB,)
        if version > 0x100C:
            values += (_BLOB, _BLOB)
        if version > 0x100D:
            values += (_BLOB, _BLOB)
        if version > 0x100E:
            values += (_BLOB,)
        if version > 0x100F:
            values += (_BLOB,)
        if version >= 0x1011:
            values += (4,)
        return values + (_Raw(80),)
    if family in ("ErrRep", "TMRRep"):
        item = (4,)
        if version > 0x2007:
            item += (_Raw(12), 4)
        if version > 0x2008:
            item += (_Raw(12), 4)
        item += (_BLOB, _BLOB)
        if version > 0x100B:
            item += (_Raw(16),)
        if version > 0x1009:
            item += (4,)
        item += (_BLOB,) * 4
        if version >= 0x2003:
            item += (2,)
        if version > 0x2005:
            item += (4,)
        item += (call("98930"),)
        if version >= 0x2000:
            item += (
                (2, 2) + (_BLOB,) * 7,
                (2,) * (11 if version > 0x2004 else 10) + (_BLOB,) * 12,
                (_BLOB,) * (7 if version > 0x2003 else 3),
            )
            if version > 0x2000:
                item += ((4, 2),)
        if version >= 0x2002:
            item += (_Raw(32),)
        if version > 0x2008:
            item += ((2, _Raw(4), _Raw(80)),)
        item += (_Raw(116),)
        if version < 0x2009:
            item += (_Raw(102),)
        return _Array(item)
    if family == "OpeInope":
        # a6470: assembly a6824..a6d10; the stack probe confuses decompilation.
        signal = _signal(version, 13, False)
        inner = (
            _BLOB,
            4,
            1,
            1,
            1,
            4,
            4,
            signal,
            4,
            4,
            4,
            signal,
            4,
            signal,
            _Array(_signal(version, 13, True)),
        )
        if version >= 0x1001:
            inner += (4, call("85800", 13))
        item = (
            _common(version),
            _Array(_Named("event", inner)),
            call("804f0", 13),
            call("805d0", 13),
        )
        if version >= 0x1001:
            item += (4, call("85800", 13))
        if version >= 0x1002:
            item += (4,)
        return _Array(item)
    if family == "DDRData":
        item = (_common(version),)
        if version > 0x1004:
            item += (1, 1)
        if version >= 0x1009:
            item += (4, 4, _BLOB, _BLOB)
        item += (
            _Array(_Named("ddr-mask", (call("b1340"), call("b1760")), version=version)),
        )
        if version > 0x1000:
            item += (_Array(call("b1db0")),)
        item += (_Named("ddr-recording-count", 4), call("804f0", 7), call("805d0", 7))
        if version > 0x1002:
            item += (_Named("ddr-specification", 4),)
        if version > 0x1003:
            item += (_Named("ddr-attributes", (4,) * 26),)
        if version > 0x1004:
            item += (_Array(1),)
        if version >= 0x1007:
            item += (1, 1)
        if version > 0x1007:
            item += (4, _Array(1), 1)
        if version > 0x1008:
            item += (
                _Array(
                    _Named(
                        "ddr-mask",
                        (call("b2190"), call("b2560")),
                        version=version,
                        flavor=1,
                    )
                ),
                4,
                _Array(call("b1db0")),
                _Array(1),
                1,
            )
        if version > 0x100A:
            item += (_Array(1), 1)
        return _Array(item)
    if family == "CanBus":
        item = (_common(version),) + ((2,) if version > 0x1001 else ())
        item += (call("89f50"),)
        if version > 0x1001:
            item += (call("8a5b0"),)
        if version > 0x1002:
            item += (call("8b190"),)
        item += (call("8b4b0"),)
        if version > 0x1001:
            item += (call("804f0", 11),)
            if version > 0x1004:
                item += (_Array((4, call("804f0", 11))),)
            item += (_Array(_BLOB), 4, 4)
        return _Array(item)
    if family in ("OpeFFD", "ImgFFD"):
        return _Array((4, _Named("image", (_BLOB, _Blob(width=4), 4))))
    if family == "TimeStamp":
        return _Array(
            (
                _common(version, version >= 0x1001),
                (call("804f0", 3), call("805d0", 3), call("aebe0")),
                _Raw(80),
            )
        )
    if family == "MultiPID":
        return call("7fa20", 9, False)
    if family == "FuncName":
        return _Array((4, 4, _BLOB))
    if family == "MILMessage":
        return (_Array((_BLOB, _BLOB, _BLOB, _Blob(limit=16), _Blob(limit=16))),) * 2
    if family in ("MktMonRam", "MktMonRamSSR"):
        item = ((4,) if version > 0x1000 else ()) + (_Blob(width=4),)
        return _Array((_BLOB, _Array(item)))
    if family == "HealthCheck":
        return _Array(
            (_common(version, version >= 0x1012), _health(version))
            + ((_Raw(28),) if version > 0x101F else ())
            + (_Raw(80),)
        )
    if family == "SysChk":
        return _Array((_Monitor(version), _Raw(80)))
    if family == "FuelCon":
        return _Array((_Monitor(version), call("9b650"), _Raw(80)))
    if family in ("Oscillo", "AFO2Sn"):
        tail = (4, 4, 4, 4) if family == "Oscillo" else (2,)
        return _Array(
            (
                _common(version),
                4,
                call("a2f50"),
                call("a3230", 0),
                call("a35d0"),
                call("a37d0"),
            )
            + tail
        )
    if family == "PreFFD":
        return _Array(
            (
                _common(version),
                4,
                1,
                2,
                call("815d0"),
                call("84420", 10),
                (2, 2),
                call("a3230", 10),
                call("a35d0"),
            )
        )
    if family in ("ABSHis", "PSDHis"):
        flavor = 8 if family == "ABSHis" else 12
        extra = (
            (call("87340"),)
            if family == "ABSHis" and version > 0x1000
            else (call("a9d20"),)
            if family == "PSDHis"
            else ()
        )
        item = (_BLOB, 1, 1, 2, 1, 4, call("7fa20", flavor, False)) + extra
        return _Array((_common(version), _Array(_Named("event", item)), 4))
    if family == "ICSHis":
        value = _signal(version, 6, False)
        item = (_BLOB, 1, 1, 4, 4, 4, value, 4, 4, 4, value, 4, value, call("7fa20", 6))
        return _Array(
            (
                _common(version),
                1,
                _Array(_Named("event", item)),
                call("804f0", 6),
                call("805d0", 6),
            )
        )
    if family == "ROB":
        fields = (_common(version, False), 4)
        fields += (2,) if version > 0x1003 else ()
        fields += (2, 2) if version > 0x1001 else ()
        fields += (2,) if version > 0x1005 else ()
        fields += (call("ab5d0"), call("804f0", 5), call("805d0", 5))
        if version > 0x1005:
            fields += (call("ac0a0"),)
        return _Array(fields + (_Raw(80),))
    if family == "ROBCommon":
        return (
            _Array(
                (
                    _common(version, False),
                    4,
                    _Array((4, 2)),
                    call("804f0", 5),
                    call("805d0", 5),
                )
            ),
            _Raw(80),
        )
    if family == "OpeHis":
        return _Array(
            (
                _common(version, False),
                call("a4c10"),
                call("a4f60"),
                call("a55f0"),
                call("7f910", 4),
                call("805d0", 4),
                _Raw(80),
            )
        )
    if family == "DTCMon":
        return _Array(_dtc_record(version, context_mode))
    if family == "DTCP5":
        fields = (_common(version), 2) + ((4,) if version > 0x1002 else ())
        fields += (
            call("815d0"),
            2,
            call("83010", 10),
            call("94e00"),
            call("83010", 10),
            call("94e00"),
            call("82680", 10),
        )
        if version > 0x1001:
            fields += (
                call("7d680", 10),
                call("95310", 10),
                call("95590", 10),
                call("912f0"),
                call("957e0", 10),
                call("84990"),
                call("84420", 10),
                call("95a60"),
            )
        if version > 0x101C:
            fields += (call("84990"),)
        if version > 0x1002:
            fields += (call("84420", 10), (2, 2), call("a3230", 10), call("a35d0"))
        return _Array(fields)
    raise ReportError(
        f"native report layout is not recovered: {family}/{type_raw:#x}/{version:#x}"
    )


def _dtc_record(version: int, context_mode: int) -> tuple:
    def call(function: str, full: bool = True) -> Any:
        return _layout(function, version, 1, full)

    dtcs = tuple(call(name) for name in ("7d680", "90d20", "90f60", "912f0", "918d0"))
    extra = (call("92e20"), call("93470")) if version > 0x1006 else ()
    if version > 0x1007:
        extra += (call("93810"),)
    fields = (_common(version, version >= 0x1006),) + dtcs + extra + (2,)
    full = version >= 0x1004
    ffd = (
        (call("92530", full), call("92950", full))
        if context_mode
        else (call("7d1f0", full), call("91cc0", full))
    )
    if version < 0x100B:
        if version == 0x100A:
            fields += (2, 4) + dtcs + (call("93470"), call("92e20"), call("93810"))
        if context_mode and version == 0x1001:
            ffd = (call("7d1f0", False), call("92950", full))
        fields += ffd
        if not context_mode and version > 0x1004:
            fields += ffd
    else:
        fields += ffd
        if not context_mode:
            fields += ffd
        fields += (2, 4) + dtcs
        fields += (
            (call("93470"), call("92e20"))
            if version < 0x100C
            else (call("92e20"), call("93470"))
        ) + (call("93810"),)
    return fields + (_Raw(80),)


def _wide(version: int, flavor: int, thresholds: dict[int, int]) -> int:
    return 4 if flavor in thresholds and version >= thresholds[flavor] else 2


def _common(version: int, full: bool = True) -> _Named:
    # 80480 -> 7cfb0 / 7d170: native label/date/description, optional u16 ID.
    return _Named(
        "common",
        ((2,) if full else ()) + (_BLOB, _Blob(limit=16), _BLOB),
        full=full,
        version=version,
    )


def _descriptor() -> tuple:
    # 7fe90 mode2 and 80220 preserve all choices, limits and mode bytes.
    return (4, 4, 4, 2, 1, 2, _Array((4, _BLOB, 4, 4, 1)), 4, 4, 4, 4)


def _signal(
    version: int, flavor: int = 1, full: bool = True, extended: bool = False
) -> _Named:
    width = _wide(
        version,
        flavor,
        {
            1: 0x1009,
            2: 0x1016 if extended else 0xFFFF,
            3: 0x1002,
            4: 0x1003,
            5: 0x1001,
            6: 0x1001,
            7: 0x1002,
            8: 0x1002,
            9: 0x1001,
            10: 0x1000,
            11: 0x1002,
            13: 0x1000,
        },
    )
    layout = (
        (2,)
        + ((width,) if full else ())
        + (
            _BLOB,
            _BLOB,
            _BLOB,
            1,
            1,
            _descriptor(),
            _Array((4, 1) if extended else (4, _BLOB, 1)),
        )
    )

    return _Named("signal", layout, full, extended, version, flavor)


def _dtc(version: int, flavor: int = 1, full: bool = True) -> _Named:
    fields: tuple = (2, _BLOB)
    if flavor in (3, 10) or version > 0x1003:
        fields += (
            _wide(version, flavor, {1: 0x1009, 2: 0x1015, 3: 0x1002, 10: 0x1000}),
        )
    fields += (_BLOB, 4, 1, _BLOB)
    if full and (
        (flavor == 1 and version > 0x1005)
        or (flavor == 2 and version > 0x1011)
        or flavor == 10
    ):
        fields += (_Array((4, 4, 1, _BLOB, _BLOB, 1)),)
    fields += (_BLOB, _BLOB, _BLOB)
    if flavor in (2, 3, 10) or (flavor == 1 and version > 0x1002):
        fields += (_BLOB,)
    fields += (4, 4, 4)
    if flavor in (2, 3, 10) or (flavor == 1 and version > 0x1002):
        fields += (4,)
    return _Named("dtc", fields + (_BLOB, 1), full=full, version=version, flavor=flavor)


def _byte_signal(version: int, flavor: int = 1, full: bool = True) -> tuple:
    fields: tuple = (_Array(1),)
    if full:
        fields += (_wide(version, flavor, {1: 0x1009, 2: 0x1015, 10: 0x1000}),)
    return fields + (_BLOB, 4, 2, 2, 2, 4)


def _pair_strings() -> _Array:
    return _Array((_BLOB, _BLOB))


def _history_values(version: int) -> _Array:
    width = 4 if version > 0x1008 else 2
    item = (_BLOB, width, _BLOB, 1, 4, 1, 2, width, _Array((2, 1)))
    return _Array((_BLOB, _Array(item)))


def _history_parameters(version: int, flavor: int = 1) -> _Array:
    width = (
        2
        if (flavor == 1 and version < 0x1009) or (flavor == 10 and version < 0x1001)
        else 4
    )
    return _Array((_BLOB, _BLOB, 2, 2, 1, 2, width, 2))


def _layout(function: str, version: int, flavor: int = 1, full: bool = True) -> Any:
    """Authored schemas; labels are native reader RVAs, not inferred semantics."""
    signal = _signal(version, flavor, full)
    if function in ("7fd30", "80e50"):
        return _signal(version, flavor, full, function == "80e50")
    if function == "98930":
        image = _Named("image", (_BLOB, _Blob(width=4), 4))
        return (
            (_Array(image),)
            + (image,) * 4
            + ((_Array(image),) if version > 0x2002 else ())
        )
    if function in ("81180", "81250", "81320", "81400"):
        return _Array({"81180": 1, "81250": 4, "81320": 2, "81400": _BLOB}[function])
    if function == "85d30":
        return _Named(
            "signal",
            (2, _BLOB, _BLOB, _BLOB, 1, 1, _descriptor(), _Array((8, _BLOB, 1))),
            full=False,
            version=version,
            flavor=7,
        )
    if function == "b1db0":
        return (
            2,
            _BLOB,
            _BLOB,
            _BLOB,
            2 if version < 0x1002 else 4,
            4,
            1,
            4,
            4,
            4,
            2,
            4,
            4,
            4,
            4,
        )
    if function in ("b1340", "b2190"):
        byte_list = _Array(1)
        string_list = _Array(_BLOB)
        item = (
            byte_list,
            byte_list,
            _Array(2 if version < 0x1002 else 4),
            string_list,
            string_list,
            _descriptor(),
        )
        item += (1, 1, 4, 4, 4, 4) if function == "b1340" else (4, 4, 4)
        signal = _signal(version, 7, False)
        item += (signal, 4, signal, signal, 4, signal)
        item += (1, 1, 1) if function == "b1340" else (1,)
        item += (byte_list,) * 3
        if function == "b1340":
            item += (signal, _Array(signal), _Array(signal))
        else:
            if version < 0x100A:
                item += (signal,)
            item += (_Array(_layout("85d30", version)),) * 2
        if version > 0x1002:
            item += (_Array(4), string_list)
        if function == "b1340":
            item += (1,) * 7 if version >= 0x1007 else ()
        else:
            item += (1,) * 6 + (_layout("85d30", version),) * 3
        return item
    if function in ("b1760", "b2560"):
        byte_list = _Array(1)
        item = (byte_list,) * 4
        if function == "b1760":
            item += (1,) * 14 + (byte_list,) * 4
        else:
            item += (1,) * 4 + ((1,) if version < 0x100A else (byte_list,))
            item += (1,) * 4 + (byte_list,) * (4 if version < 0x100A else 3)
        item += (_Array(byte_list),) * 2
        if version > 0x1002:
            item += (byte_list, byte_list)
        item += (1,) * (9 if function == "b2560" else 7 if version >= 0x1007 else 0)
        return item
    if function == "89f50":
        return _Array((4, _BLOB, _Array((4, _BLOB, 4, 1, 2))))
    if function == "8a5b0":
        item = (4, 4, _BLOB, 1)
        if version > 0x1003:
            item += (4, 4, _BLOB)
        return _Array(item + (_layout("8aa50", version),))
    if function == "8aa50":
        return _Array(
            (
                4,
                4,
                _BLOB,
                4,
                4,
                4,
                _BLOB,
                4,
                1,
                4,
                1,
                4,
                2,
                4,
                _signal(version, 11, False),
                2,
            )
        )
    if function == "8b190":
        return _Array((4, 4, _BLOB, 4, 2))
    if function == "8b4b0":
        item = (_BLOB, _BLOB) + ((4, _BLOB) if version > 0x1000 else ())
        return _Array((4, _BLOB, _Array(item)))
    if function == "85800":
        return tuple(_signal(version, flavor, False) for _ in range(12))
    if function == "aebe0":
        item = (2, _BLOB, 4, 2 if version < 0x1002 else 4, _BLOB, 4)
        if version > 0x1002:
            item += (1, 2)
        if version >= 0x1027:
            item += (4,)
        item += (_Array(_layout("7ea50", version)),)
        if version > 0x1002:
            item += (_layout("815d0", version),)
        if version > 0x101E:
            item += (_layout("804f0", version, 3),)
        if version > 0x1021:
            item += (4,)
        return _Array(item)
    if function == "7ea50":
        item = ((4, _BLOB) if version >= 0x1001 else ()) + (
            _layout("7f910", version, 3),
        )
        if version > 0x1021:
            item += (4, _layout("85800", version, 3))
        return (_dtc(version, 3, True), _Array(item) if version >= 0x1001 else item)
    if function == "7fa20":
        return _Array(signal)
    if function == "7d680":
        return _Array(_dtc(version, flavor, full))
    if function in ("7d1f0", "83010"):
        return _Array(_byte_signal(version, flavor, full))
    if function == "90d20":
        return _Array((2, 1, 4, _Array(_signal(version, full=False))))
    if function == "90f60":
        return _Array((1, _Array(_signal(version, full=False)), 1, 1))
    if function == "912f0":
        return _Array((1, _Array((4, 4, 4, _BLOB, _BLOB))))
    if function == "918d0":
        return _Array((1, 4, 4, _Array(_signal(version, full=False))))
    if function in ("92e20", "84990"):
        return _history_values(version)
    if function in ("93470", "84420"):
        return _history_parameters(version, flavor)
    if function == "93810":
        return _Array(_Array((2, 2) if version > 0x1009 else 2))
    if function == "91c90":
        return 2
    if function == "91cc0":
        return _Array(
            (
                _Array(1),
                _Array((_signal(version, full=full, extended=True), 4, 2, 4, 2, 4)),
            )
        )
    if function == "92530":
        return _Array(
            (
                _signal(version, full=full, extended=True),
                2 if version < 0x1009 else 4,
                2,
            )
        )
    if function == "92950":
        return _Array(
            (
                _signal(version, full=full, extended=True),
                2,
                2,
                2,
                4,
                2,
                4,
                2,
                4 if version >= 0x1009 else 2,
            )
        )
    if function == "804f0":
        return (
            4,
            4,
            4,
            _signal(version, flavor, False),
            4,
            4,
            4,
            _signal(version, flavor, False),
        )
    if function == "805d0":
        return _Array(tuple(_signal(version, flavor, False) for _ in range(12)))
    if function == "7f910":
        return (
            4,
            4,
            4,
            _signal(version, flavor, False),
            4,
            4,
            4,
            _signal(version, flavor, False),
            4,
            _signal(version, flavor, False),
        )
    if function == "a2f50":
        return _Array((4, _BLOB))
    if function == "a3480":
        return (4, 4, 4, 4, 8, 4, 8, 8, 4, 4, 2) + (
            (2,) if version > 0x1003 or flavor == 10 else ()
        )
    if function == "a3230":
        return _Array((4, 4, 4, _layout("a3480", version, flavor), 8, 8, 4))
    if function == "a35d0":
        return (
            (_Array((4, 4, 4, 4) + ((4,) if version > 0x1001 else ())), 4, 4)
            + ((4,) if version > 0x1001 else ())
            + (4, 4)
        )
    if function == "a37d0":
        item = (
            (4, _BLOB, _BLOB)
            + ((2,) if version > 0x1002 else ())
            + (
                _Array(4 if version < 0x1001 else 2),
                _Blob(4),
                _Blob(4),
                _Blob(4),
                _Array(2),
                _Array((2, 4 if version >= 0x1005 else 2)),
            )
        )
        return _Array(_Named("oscillo-monitor", item, version=version))
    if function == "82360":
        return (2, 4, _BLOB, 4, _BLOB, 1, 1, 1, _descriptor(), _Array((4, _BLOB, 1, 4)))
    if function == "815d0":
        item = _layout("82360", version)
        fields: tuple = (4, 4, 4, _BLOB, 4, _BLOB, 4, _BLOB, 4, 1)
        if version > 0x1017:
            fields += (_Array(1), _Array(1), 4)
        fields += (_Array(item), 4, item, item, item, 4, item, 1, 2, 1)
        if version > 0x1021:
            fields += (4, (item,) * 6)
        return _Array(fields)
    if function == "82680":
        return _Array(
            (
                2,
                _BLOB,
                4,
                _BLOB,
                4,
                1,
                _BLOB,
                4,
                4,
                _signal(version, flavor),
                4,
                4,
                _signal(version, flavor),
                4,
                _signal(version, flavor),
            )
        )
    if function == "95cf0":
        return (2, 2)
    if function == "95c60":
        return _Array((2, 2))
    if function == "a9d20":
        return _Array((2, 4, 4))
    if function == "9b870":
        return (2, _BLOB, _BLOB, _BLOB, 2, _Array(8), _Array(8))
    if function == "9ba70":
        return (2, _BLOB, _BLOB, _BLOB, 2, 4, 4, 4, 4, 4)
    if function == "9bb60":
        return _Array((2, 4))
    if function == "9b650":
        return (
            (4, _layout("9b870", version), _layout("9ba70", version))
            if version >= 0x1001
            else ()
        ) + (_layout("9bb60", version), _Array(2), 8)
    if function == "aca20":
        return (_BLOB, 4, _BLOB, 2)
    if function in ("95310", "95590", "957e0"):
        prefix = {"95310": (2, 1, 4), "95590": (1,), "957e0": (1, 4, 4)}[function]
        return _Array(
            prefix
            + (_Array(_signal(version, flavor, False)),)
            + ((1, 1) if function == "95590" else ())
        )
    if function == "94e00":
        return _Array(
            (_Array(1), _Array((_signal(version, 10, True, True), 4, 2, 4, 2, 4)))
        )
    if function == "95a60":
        return _Array(_Array((2, 2)))
    if function == "87340":
        return _Array((2, 2, 2) if version < 0x1002 else (2, 4, 4))
    if function == "a4cd0":
        item = (_BLOB, 4, _BLOB, 2)
        return _Array(item) if version >= 0x1004 else (item,) * 3
    if function == "a4c10":
        return (2, 2, 2, 2, 2, 2, 1, _layout("a4cd0", version))
    if function == "a4f60":
        item = ((4, 4) if version > 0x1001 else ()) + (
            1,
            _BLOB,
            _layout("a5210", version),
        )
        return _Array(_Named("event", item, flavor=3 if version > 0x1001 else 1))
    if function == "a55f0":
        return _Array(
            _Named("event", (4, 4, 1, _BLOB, _layout("a58a0", version)), flavor=3)
        )
    if function == "a5210":
        return _Array(_Named("history-content", (4, 1, _BLOB, _BLOB, 4, _BLOB, 2)))
    if function == "a58a0":
        return _Array((4, 1, _BLOB, _BLOB, _BLOB, _layout("7f910", version, 4)))
    if function == "ab5d0":
        item = (2, _BLOB, 2 if version < 0x1001 else 4, _BLOB)
        item += ((1,) if version > 0x1002 else ()) + (
            4,
            4,
            4,
            4,
            _layout("7f910", version, 5),
        )
        if version > 0x1004:
            item += (4,) + tuple(_signal(version, 5, False) for _ in range(6))
        return _Array(_Named("event", item + (_layout("abce0", version),), flavor=1))
    if function == "abce0":
        return _Array(
            (2, _signal(version, 5, False))
            + ((4, _layout("aca90", version)) if version > 0x1006 else ())
        )
    if function == "aca90":
        return _Array((1, _BLOB))
    if function == "ac0a0":
        text_value = _layout("aca20", version)
        inner = (2, _BLOB, text_value, text_value, text_value, text_value, _BLOB, 2)
        return (
            _Array((4, 2, _BLOB, _Array(inner))),
            text_value,
            text_value,
            text_value,
            2,
            2,
            2,
            2,
            2,
            2,
        )
    raise ReportError(f"native report nested layout is not recovered: {function}")


def _health(version: int) -> tuple:
    # 9cdd0: the serialized selector controls the optional measurement block.
    prefix: tuple = (4, _Blob(limit=16))
    if version >= 0x1011:
        prefix += (4,)
    if version > 0x1016:
        prefix += (1,)
    if version > 0x1017:
        prefix += (4,)
    return prefix + (
        _Dynamic(
            lambda scope: _health_detail(version, scope[2] if version >= 0x1011 else 0)
        ),
    )


def _health_detail(version: int, mode: int) -> tuple:
    detail: tuple = ()
    if mode == 1:
        detail += (4, 4, 8, 8, _Array((1, 1, _BLOB, 1, (4, 4, 4, 2, 1, 2), 4, _BLOB)))
        if version > 0x1012:
            detail += (_Array((1, 1, _BLOB, 1, (4, 4, 4, 2, 1, 2), 4, _BLOB)),)
    detail += (_BLOB, _BLOB)
    if version > 0x1013:
        detail += (_BLOB,)
    if version > 0x101A:
        detail += ((4, _BLOB),)
    if version > 0x101B:
        detail += (_Array((_BLOB, _BLOB)),)
    if version > 0x101D:
        detail += (_Array((_BLOB, _BLOB, _BLOB, _BLOB)),)
    detail += (_health_ecus(version, mode),)
    if version >= 0x1020:
        detail += (2,)
    if version >= 0x1026:
        detail += (4,)
    return detail


def _health_ecus(version: int, mode: int) -> _Array:
    fields: tuple = (4, 4, _BLOB, 4)
    if version > 0x100F:
        fields += (2 if version < 0x1015 else 4,)
    fields += (_BLOB, 1) + ((2,) if version > 0x100C else ())
    if mode == 0:
        fields += ((4, 4),) * (4 if version > 0x100D else 3)
    else:
        fields += (4, 4, 4, 4, _layout("7d680", version, 2))
        if version > 0x1015:
            extra: tuple = (_layout("815d0", version), _layout("82680", version, 2))
            if version > 0x101C:
                extra += (_history_values(version),)
            if version > 0x1018:
                extra += (_history_parameters(version, 2),)
            fields += (extra,)
            if version > 0x1016:
                fields += (
                    (4, 4, 4, 2, 4, 4, 4, 4, _layout("7d680", version, 2)),
                    _Array(2),
                )
        fields += (_Array(2),)
    fields += (_Array(_byte_signal(version, 2, version >= 0x1010)),)
    if version >= 0x101B:
        fields += (2,)
    fields += (_pair_strings(),)
    if version > 0x100E:
        fields += (_pair_strings(),)
    fields += (_pair_strings(),)
    if version > 0x101A:
        fields += ((_BLOB, _BLOB),)
    if version > 0x101E:
        fields += ((2, _Blob(limit=16)) + ((2,) if version > 0x1022 else ()),)
    if version > 0x1023:
        fields += ((2, 2, 2),)
    if version > 0x1024:
        fields += ((2, 2),)
    return _Array(_Named("health-system", fields, version=version, flavor=mode))


# Native dispatcher feature gates. Offset aliases alone do not imply presence.
GLOBAL_FEATURES = {
    "IniCarInfo": (0x2711,),
    "ConfCarInfo": (0x2711,),
    "MultiPID": (0x2724,),
    "FuncName": (0x2725,),
    "HealthCheck": (0x2712,),
    "TimeStamp": (0x271F,),
    "ROBCommon": (0x2721,),
    "MILMessage": (0x271B,),
    "CanBus": (0x2723,),
    "DDRData": (0x272A,),
    "OpeFFD": (0x272F,),
    "ImgFFD": (0x272E,),
    "ErrRep": (0x2718,),
    "MktMonRam": (0x2731,),
    "MktMonRamSSR": (0x2735,),
    "TMRRep": (0x2734,),
}
ECU_FEATURES = {
    "DTCMon": (0x2716,),
    "DTCP5": (0x272D,),
    "SysChk": (0x2719,),
    "FuelCon": (0x271E,),
    "OpeHis": (0x2720,),
    "ROB": (0x2721, 0x2722),
    "Oscillo": (0x2727,),
    "ABSHis": (0x2729,),
    "ICSHis": (0x272B,),
    "AFO2Sn": (0x272C,),
    "PSDHis": (0x2730,),
    "PreFFD": (0x2732,),
    "OpeInope": (0x2733,),
}


def _selected(file: snapshot.TSEFile, family: str, ecu_index: int | None) -> int:
    if not isinstance(file, snapshot.TSEFile):
        raise ReportError("expected native TSE/TMM/TMR file")
    features = GLOBAL_FEATURES if ecu_index is None else ECU_FEATURES
    if not isinstance(family, str) or family not in features:
        raise ReportError("report family is not valid for this index scope")
    if not set(features[family]).intersection(file.metadata["supported_feature_ids"]):
        raise ReportError("native report feature is absent")
    if ecu_index is None:
        index = file.metadata["global_index"]
    else:
        ecus = file.metadata["ecu_index"]
        if type(ecu_index) is not int or not 0 <= ecu_index < len(ecus):
            raise ReportError("native report ECU index is absent")
        index = ecus[ecu_index]
    offset = index.get(family)
    if type(offset) is not int or not file.body_offset <= offset < len(file.source):
        raise ReportError("native report section offset is absent")
    return offset


def select_report_section(
    file: snapshot.TSEFile, family: str, ecu_index: int | None = None
) -> tuple[int, ReportSection]:
    """Select one present report with native feature/scope/context enforcement."""
    offset = _selected(file, family, ecu_index)
    return offset, decode_section(
        family,
        snapshot.tse_section(file, offset),
        context_mode=int(file.file_type == 4),
    )


def reports(file: snapshot.TSEFile) -> list[dict]:
    """Decode every present recovered report; reject malformed active families."""
    if not isinstance(file, snapshot.TSEFile):
        raise ReportError("expected native TSE/TMM/TMR file")
    supported = set(file.metadata["supported_feature_ids"])
    budget = [0, 0]
    result = []
    cache: dict[tuple[str, int], ReportSection] = {}
    for ecu_index, families in [(None, GLOBAL_FEATURES)] + [
        (index, ECU_FEATURES) for index in range(len(file.metadata["ecu_index"]))
    ]:
        for family, features in families.items():
            if not supported.intersection(features):
                continue
            offset = _selected(file, family, ecu_index)
            key = (family, offset)
            if key not in cache:
                cache[key] = decode_section(
                    family,
                    snapshot.tse_section(file, offset),
                    context_mode=int(file.file_type == 4),
                )
            section = cache[key]
            result.append(
                {
                    "ecu_index": ecu_index,
                    "offset": offset,
                    **_report_dict(section, budget),
                }
            )
    return result


def replace_section(
    file: snapshot.TSEFile, section: ReportSection, ecu_index: int | None = None
) -> snapshot.TSEFile:
    """Replace an indexed existing body and relocate all later native offsets."""
    start = _selected(file, section.family, ecu_index)
    original = snapshot.tse_section(file, start)
    previous = decode_section(
        section.family, original, context_mode=int(file.file_type == 4)
    )
    if (
        section.context_mode != previous.context_mode
        or section.type_raw != previous.type_raw
    ):
        raise ReportError("replacement report context or type differs from original")
    replacement = encode_section(section)
    end = start + len(original)
    delta = len(replacement) - len(original)
    if len(file.source) + delta > MAX_BYTES:
        raise ReportError("edited native TSE exceeds byte budget")
    data = bytearray(file.source[:start] + replacement + file.source[end:])
    for entry in file.metadata["index_entries"]:
        if entry["offset"] >= end:
            struct.pack_into("<I", data, entry["position"], entry["offset"] + delta)
    return snapshot.parse_tse(bytes(data))


@dataclass(frozen=True)
class Attachment:
    """98cc0 name, allocated stored bytes, and trailing stored-size field."""

    name_raw: bytes
    stored_bytes: bytes
    stored_size: int


def attachments(section: ReportSection) -> tuple[Attachment, ...]:
    """Enumerate native embedded images without creating paths or files."""
    encode_section(section)
    images = []
    if section.family in ("ImgFFD", "OpeFFD"):
        images = [item[1] for item in section.records]
    elif section.family in ("ErrRep", "TMRRep"):
        version = section.version
        index = 1 + (2 if version > 0x2007 else 0) + (2 if version > 0x2008 else 0)
        index += 2 + (1 if version > 0x100B else 0) + (1 if version > 0x1009 else 0)
        index += 4 + (1 if version >= 0x2003 else 0) + (1 if version > 0x2005 else 0)
        for item in section.records:
            group = item[index]
            images.extend(group[0])
            images.extend(group[1:5])
            if version > 0x2002:
                images.extend(group[5])
    return tuple(Attachment(*image) for image in images)


def unpack_attachment(attachment: Attachment) -> tuple[dict, ...]:
    """Native99230 ZIP expansion, bounded in memory; no filesystem extraction."""
    if (
        not isinstance(attachment, Attachment)
        or not isinstance(attachment.name_raw, bytes)
        or not isinstance(attachment.stored_bytes, bytes)
        or type(attachment.stored_size) is not int
        or not 0 <= attachment.stored_size <= len(attachment.stored_bytes)
        or len(attachment.stored_bytes) > MAX_BYTES
    ):
        raise ReportError("invalid native attachment stored-size span")
    payload = attachment.stored_bytes[: attachment.stored_size]
    # Bound the actual central directory before ZipFile creates its ZipInfo list.
    end = payload.rfind(b"PK\x05\x06", max(0, len(payload) - 65557))
    if end < 0 or len(payload) - end < 22:
        raise ReportError("native attachment ZIP directory is absent")
    _, disk, directory_disk, disk_count, count, size, offset, comment = (
        struct.unpack_from("<4s4H2IH", payload, end)
    )
    if (
        disk
        or directory_disk
        or disk_count != count
        or count == 0xFFFF
        or size == 0xFFFFFFFF
        or offset == 0xFFFFFFFF
        or end + 22 + comment != len(payload)
    ):
        raise ReportError("unsupported or malformed native attachment ZIP directory")
    position = end - size
    if position < 0:
        raise ReportError("native attachment ZIP directory exceeds input")
    actual_count = 0
    while position < end:
        if end - position < 46 or payload[position : position + 4] != b"PK\x01\x02":
            raise ReportError("malformed native attachment ZIP directory entry")
        name_size, extra_size, comment_size = struct.unpack_from(
            "<3H", payload, position + 28
        )
        position += 46 + name_size + extra_size + comment_size
        actual_count += 1
        if actual_count > MAX_NODES:
            raise ReportError("native attachment archive exceeds entry budget")
    if position != end or actual_count != count:
        raise ReportError("native attachment ZIP directory count/size mismatch")
    try:
        with zipfile.ZipFile(
            io.BytesIO(attachment.stored_bytes[: attachment.stored_size])
        ) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_NODES:
                raise ReportError("native attachment archive exceeds entry budget")
            size = 0
            for info in entries:
                size += (
                    info.file_size
                    + len(info.filename.encode("utf-8"))
                    + len(info.extra)
                    + len(info.comment)
                )
                if size > MAX_BYTES or info.flag_bits & 1:
                    raise ReportError(
                        "native attachment archive exceeds budget or is encrypted"
                    )
                if info.compress_type == zipfile.ZIP_LZMA:
                    # ZIP's raw LZMA dictionary is independent of file_size.
                    # Bound its properties before ZipExtFile constructs liblzma.
                    offset = info.header_offset
                    if (
                        not 0 <= offset <= len(payload) - 30
                        or payload[offset : offset + 4] != b"PK\x03\x04"
                    ):
                        raise ReportError("malformed LZMA attachment local header")
                    name_size, extra_size = struct.unpack_from(
                        "<2H", payload, offset + 26
                    )
                    start = offset + 30 + name_size + extra_size
                    if info.compress_size < 9 or start + info.compress_size > len(
                        payload
                    ):
                        raise ReportError("truncated LZMA attachment properties")
                    property_size = struct.unpack_from("<H", payload, start + 2)[0]
                    dictionary = struct.unpack_from("<I", payload, start + 5)[0]
                    if property_size != 5 or dictionary > MAX_BYTES:
                        raise ReportError(
                            "LZMA attachment dictionary exceeds budget or is malformed"
                        )
            result = []
            for info in entries:
                with archive.open(info) as source:
                    data = source.read(info.file_size + 1)
                    if len(data) != info.file_size:
                        raise ReportError(
                            "native attachment member size differs from archive"
                        )
                result.append(
                    {
                        "name": info.filename,
                        "data": data,
                        "compression": info.compress_type,
                        "crc32": info.CRC,
                        "date_time_raw": info.date_time,
                        "flags_raw": info.flag_bits,
                        "external_attributes_raw": info.external_attr,
                        "extra_raw": info.extra,
                        "comment_raw": info.comment,
                    }
                )
            return tuple(result)
    except (
        OSError,
        ValueError,
        RuntimeError,
        NotImplementedError,
        zipfile.BadZipFile,
        zlib.error,
        lzma.LZMAError,
    ) as exc:
        raise ReportError(f"native attachment ZIP expansion failed: {exc}") from exc


def view_section(
    section: ReportSection, *, encoding: str, _budget: list[int] | None = None
) -> dict:
    """Named stored report rows with explicit native text decoding context."""
    encode_section(section)
    try:
        codecs.lookup(encoding)
        if "\0".encode(encoding) != b"\0":
            raise ReportError("native report text requires a byte-string encoding")
    except (LookupError, TypeError) as exc:
        raise ReportError("explicit report text encoding is invalid") from exc
    budget = [0, 0] if _budget is None else _budget
    result: dict = {
        "family": section.family,
        "captures": [],
        "dtcs": [],
        "parameters": [],
        "systems": [],
        "images": [],
        "events": [],
        "monitors": [],
        "vehicle": [],
        "functions": [],
        "error_reports": [],
        "memory_captures": [],
        "messages": [],
        "ddr_attributes": [],
        "ddr_headers": [],
        "history_contents": [],
        "history_headers": [],
        "history_time_information": [],
    }

    signal_masks: dict[tuple, tuple[tuple, tuple, bool | None]] = {}
    sequence_masks: dict[tuple, tuple[tuple, tuple]] = {}

    def text(raw: bytes) -> str:
        try:
            value = raw.split(b"\0", 1)[0].decode(encoding, errors="strict")
        except UnicodeError as exc:
            raise ReportError(
                "stored report text does not match supplied encoding"
            ) from exc
        budget[1] += 12 * len(value)
        if budget[1] > MAX_BYTES:
            raise ReportError("named report text exceeds aggregate budget")
        return value

    def emit(kind: str, item: dict, path: tuple) -> None:
        budget[0] += 1
        budget[1] += 512
        if budget[0] > MAX_NODES or budget[1] > MAX_BYTES:
            raise ReportError("named report rows exceed aggregate budget")
        result[kind].append({"source_path": list(path), **item})

    def monitor_view(record: snapshot.MonitorBuffer, path: tuple) -> None:
        signals = [
            snapshot.decode_signal_item(bytes.fromhex(raw))
            for raw in snapshot.decode_signal_table(record.signal_table)["items_hex"]
        ]
        packets = snapshot.monitor_packets(record)
        work = len(packets) * sum(1 + len(signal.patterns) for signal in signals)
        size = len(packets) * sum(
            1024
            + 12
            * (
                len(text(signal.name))
                + len(text(signal.unit))
                + max((len(text(pattern[1])) for pattern in signal.patterns), default=0)
            )
            for signal in signals
        )
        if work > MAX_NODES - budget[0] or size > MAX_BYTES - budget[1]:
            raise ReportError("report monitor playback exceeds aggregate budget")
        budget[0] += work
        budget[1] += size
        emit(
            "monitors",
            {
                "name": text(record.name),
                "description": text(record.description),
                "signals": [
                    {
                        "pid": signal.pid,
                        "name": text(signal.name),
                        "unit": text(signal.unit),
                    }
                    for signal in signals
                ],
                "samples": snapshot.monitor_samples(record, encoding=encoding),
                "timestamp_units": "native-raw-unknown",
                "interpolation": "none",
            },
            path,
        )

    def calendar(raw_time: bytes) -> dict:
        words = struct.unpack("<8H", raw_time.ljust(16, b"\0"))
        year, month, _weekday, day, hour, minute, second, millisecond = words
        timestamp = None
        if raw_time:
            try:
                # Serialized SYSTEMTIME is local wall time, with no zone field.
                timestamp = datetime.datetime(  # noqa: DTZ001
                    year, month, day, hour, minute, second, millisecond * 1000
                ).isoformat(timespec="milliseconds")
            except ValueError:
                pass  # Raw SYSTEMTIME words remain available without inventing a date.
        return {"timestamp": timestamp, "system_time_raw": words}

    def named(layout: _Named, value: tuple, path: tuple) -> None:
        if layout.kind == "ddr-mask":
            info, masks = value
            ads = layout.flavor == 1
            value_slot, signal_slot, invalidity_slot = (
                (8, 9, 7) if ads else (11, 12, 10)
            )
            raw = info[value_slot]
            precision = info[signal_slot][5]
            invalidity = masks[invalidity_slot]
            if invalidity or raw >= 0x80000000:
                display = "-"
            elif precision > 8:
                display = None
            elif precision:
                scale = 10**precision
                display = f" {raw // scale}.{raw % scale:0{precision}d}".zfill(5)
            else:
                display = str(raw).zfill(5)
            emit(
                "ddr_headers",
                {
                    "key_cycle_raw": raw,
                    "key_cycle_precision_raw": precision,
                    "key_cycle_invalidity_raw": invalidity,
                    "key_cycle_display": display,
                    **(
                        {"key_cycle_display_status": "source-semantics-open"}
                        if precision > 8 and display is None
                        else {}
                    ),
                    "key_cycle_value_source_path": list(path + (0, value_slot)),
                    "key_cycle_precision_source_path": list(path + (0, signal_slot, 5)),
                    "key_cycle_invalidity_source_path": list(
                        path + (1, invalidity_slot)
                    ),
                },
                path,
            )
            if not ads:
                sequence_masks[path + (0, 24)] = (masks, path)
            side = (20 if layout.version < 0x100A else 19) if ads else 25
            mask_slot = (17 if layout.version < 0x100A else 16) if ads else 22
            for mode in (0, 1):
                for channel in range(len(info[side + mode])):
                    # Native5eecd0 suppresses a channel iff neither side has a zero.
                    suppressed = not any(
                        0 in group[channel]
                        for group in masks[mask_slot : mask_slot + 2]
                        if channel < len(group)
                    )
                    group = masks[mask_slot + mode]
                    signal_masks[path + (0, side + mode, channel)] = (
                        group[channel] if channel < len(group) else (),
                        path + (1, mask_slot + mode, channel),
                        suppressed,
                    )
        elif layout.kind == "common":
            start = int(layout.full)
            raw_time = value[start + 1]
            emit(
                "captures",
                {
                    "name": text(value[start]),
                    "description": text(value[start + 2]),
                    **calendar(raw_time),
                    "identifier_raw": value[0] if layout.full else None,
                },
                path,
            )
        elif layout.kind == "signal":
            start = 2 if layout.full else 1
            name, short_name, unit = (text(value[start + i]) for i in range(3))
            selector, flags, descriptor, samples = value[start + 3 :]
            values = []
            patterns = ()
            if layout.extended:
                work = len(samples) * max(1, len(descriptor[6]))
                if work > MAX_NODES - budget[0]:
                    raise ReportError("native report conversion exceeds work budget")
                budget[0] += work
                patterns = tuple(
                    (choice[2], text(choice[1]), choice[2], choice[3])
                    for choice in descriptor[6]
                )
            for sample in samples:
                budget[1] += 256
                if budget[1] > MAX_BYTES:
                    raise ReportError("named report values exceed byte budget")
                budget[0] += 1
                if budget[0] > MAX_NODES:
                    raise ReportError("named report values exceed aggregate budget")
                if not layout.extended:
                    values.append(
                        {
                            "raw": sample[0],
                            "display": text(sample[1]),
                            "flags_raw": sample[2],
                            "display_source": "stored-native-text",
                        }
                    )
                else:
                    try:
                        rendered = render_signal(
                            sample[0],
                            selector=selector,
                            sign_mode=descriptor[4],
                            bits=descriptor[5],
                            multiplier=descriptor[0],
                            divisor=descriptor[1],
                            offset=descriptor[2],
                            precision=descriptor[3],
                            patterns=patterns,
                            minimum_raw=descriptor[7],
                            maximum_raw=descriptor[9],
                        )
                    except (ValueError, ZeroDivisionError, OverflowError) as exc:
                        raise ReportError(
                            f"native report value conversion failed: {exc}"
                        ) from exc
                    if rendered["kind"] == "unresolved":
                        raise ReportError(
                            "native extended report display mapping is unsupported"
                        )
                    values.append(
                        {
                            **rendered,
                            "flags_raw": sample[1],
                            "display_source": "native-conversion-metadata",
                        }
                    )
            mask = signal_masks.get(path)
            if mask is not None:
                raw_masks, mask_path, suppressed = mask
                for index, sample in enumerate(values):
                    budget[1] += 256
                    if budget[1] > MAX_BYTES:
                        raise ReportError(
                            "named invalidity metadata exceeds byte budget"
                        )
                    raw_mask = raw_masks[index] if index < len(raw_masks) else None
                    invalid = raw_mask is None or raw_mask != 0
                    sample.update(
                        invalidity_raw=raw_mask,
                        invalidity_check=invalid,
                        invalidity_source_path=list(mask_path + (index,))
                        if raw_mask is not None
                        else None,
                        stored_display=sample["display"],
                    )
                    if invalid:
                        sample.update(
                            display=None,
                            display_source="native-invalid-resource",
                            invalid_display_resource="DISPLAY_VALUE_INVALID",
                        )
            sequence = sequence_masks.get(path)
            if sequence is not None:
                raw_masks, pair_path = sequence
                for index, sample in enumerate(values):
                    _charge_sequence_check(budget)
                    checks = []
                    for order, slot in enumerate((21, 0, 1)):
                        if order and (index == 0 or not checks[-1]["passes"]):
                            break
                        if order:
                            _charge_sequence_check(budget)
                        mask_values = raw_masks[slot]
                        byte_raw = (
                            mask_values[index] if index < len(mask_values) else None
                        )
                        passes = byte_raw == 0
                        checks.append(
                            {
                                "mask_slot": slot,
                                "byte_raw": byte_raw,
                                "source_path": list(pair_path + (1, slot, index))
                                if byte_raw is not None
                                else None,
                                "passes": passes,
                            }
                        )
                        if not passes:
                            break
                    sample.update(
                        sequence_format_admitted=all(item["passes"] for item in checks),
                        sequence_format_checks=checks,
                    )
            emit(
                "parameters",
                {
                    **(
                        {"native_channel_suppressed": mask[2]}
                        if mask is not None and mask[2] is not None
                        else {}
                    ),
                    "identifier_raw": value[0],
                    "definition_id_raw": value[1] if layout.full else None,
                    "name": name,
                    "short_name": short_name,
                    "unit": unit,
                    "selector_raw": selector,
                    "flags_raw": flags,
                    "values": values,
                },
                path,
            )
        elif layout.kind == "dtc":
            index = 2 + int(layout.flavor in (3, 10) or layout.version > 0x1003)
            marker_index = index + 4
            if isinstance(layout.layout[marker_index], _Array):
                marker_index += 1
            permanent = layout.flavor in (2, 3, 10) or layout.version > 0x1002
            emit(
                "dtcs",
                {
                    "identifier_raw": value[0],
                    "code": text(value[1]),
                    "description": text(value[index]),
                    "freeze_frame_state_raw": value[index + 1],
                    "freeze_frame_marker": text(value[-2]),
                    "freeze_frame_data_check": value[index + 1] == 1,
                    "freeze_frame_number_raw": value[index + 2],
                    "metadata_flags_raw": value[-1],
                    "comment": text(value[index + 3]),
                    "status_flags_raw": {
                        "current": value[marker_index + 3 + int(permanent)],
                        "history": value[marker_index + 4 + int(permanent)],
                        "pending": value[marker_index + 5 + int(permanent)],
                        "permanent": value[marker_index + 7] if permanent else None,
                    },
                    "status_markers": {
                        "current": text(value[marker_index]),
                        "pending": text(value[marker_index + 2]),
                        "history": text(value[marker_index + 1]),
                        "permanent": text(value[marker_index + 3])
                        if permanent
                        else None,
                    },
                },
                path,
            )
        elif layout.kind == "history-content":
            # CommandAPI2373a..23761 logs Contents/TimeInfo/DispType;
            # GUI47f2e0 expands the same Rcv child for GFCa5210.
            emit(
                "history_contents",
                {
                    "identifier_raw": value[0],
                    "metadata_byte_raw": value[1],
                    "contents": text(value[2]),
                    "strings": [text(value[2]), text(value[3]), text(value[5])],
                    "time_info_raw": value[4],
                    "display_type_raw": value[6],
                },
                path,
            )
        elif layout.kind == "ddr-recording-count":
            # CmdRcv+3c -> ApiRcv+18 (514af); labeled550a2..550b5;
            # GUI+a0 -> GFC+90 (4a16ea..4a16f6).
            emit("ddr_headers", {"maximum_recording_count": value}, path)
        elif layout.kind == "ddr-specification":
            # CmdRcv+48 -> ApiRcv+30 (514b2); named5509f..550b5;
            # GUI+b8 -> GFC+94 (4a16fc..4a1713).
            emit("ddr_headers", {"specification_number_raw": value}, path)
        elif layout.kind == "ddr-attributes":
            # GetDDRInfo_DT b680 normal logical159..171 slot names;
            # P5 may fill final171 slot from177, so no observed-ID claim.
            # CommandAPI52d30 flattens CmdRcv+60 toApiRcv+34;
            # GUI4a16f0/49f5e0 preserves these26DWORD atGFC+98.
            for index in range(13):
                emit(
                    "ddr_attributes",
                    {
                        "normal_logical_id": 159 + index,
                        "present_raw": value[2 * index],
                        "value_raw": value[2 * index + 1],
                    },
                    path + (2 * index,),
                )
        elif layout.kind == "event":
            emit(
                "events",
                {
                    "name": text(value[layout.flavor]),
                    "labels": [
                        text(child) for child in value if isinstance(child, bytes)
                    ],
                },
                path,
            )
        elif layout.kind == "oscillo-monitor":
            # GUI478fc2..478fed copies GFCa37d0 +40/+48/+50; GUI4793b7,
            # 4793e7 and47941b pass them to Frame/Signal/Ring::Read.
            start = 3 + int(layout.version > 0x1002)
            monitor_view(
                snapshot.MonitorBuffer(
                    value[1],
                    b"",
                    value[2],
                    value[start + 1],
                    value[start + 2],
                    value[start + 3],
                    0,
                    (),
                    value[start],
                    b"",
                    value[start + 4],
                ),
                path,
            )
            result["monitors"][-1]["capture_identifier_raw"] = value[0]
        elif layout.kind == "image":
            emit(
                "images",
                {
                    "name": text(value[0]),
                    "stored_size": value[2],
                    "storage_bytes": len(value[1]),
                },
                path,
            )
        elif layout.kind == "health-system":
            # GUI4bcb10/4bcb37 names6000b0 GetEcuGroupType;
            # Health9d44b1 passes this second header field, lowWORD only.
            group_id = value[1] & 0xFFFF
            group_type = group_id % 3 or (3 if group_id else 0)
            emit(
                "systems",
                {
                    "name": text(value[5 if layout.version > 0x100F else 4]),
                    "short_name": text(value[2]),
                    "group_name": text(value[2]),
                    "ecu_identifier_raw": value[3],
                    "header_values_raw": value[:2],
                    "ecu_group_type": group_type,
                },
                path,
            )

    def walk(
        layout: Any, value: Any, path: tuple = (), scope: tuple = (), depth: int = 0
    ) -> None:
        budget[0] += 1
        if budget[0] > MAX_NODES or depth > 64:
            raise ReportError("named report exceeds structural budget")
        if isinstance(layout, _Named):
            named(layout, value, path)
            walk(layout.layout, value, path, scope, depth + 1)
        elif isinstance(layout, _Dynamic):
            walk(layout.resolve(scope), value, path, scope, depth + 1)
        elif isinstance(layout, _Array):
            for index, child in enumerate(value):
                walk(layout.item, child, path + (index,), (), depth + 1)
        elif isinstance(layout, tuple):
            for index, child in enumerate(layout):
                walk(child, value[index], path + (index,), value[:index], depth + 1)
        elif isinstance(layout, _Monitor):
            monitor_view(value.monitor, path)
            emit(
                "captures",
                {
                    "name": text(value.monitor.name),
                    "description": text(value.monitor.description),
                    "monitor": True,
                },
                path,
            )

    if section.family == "OpeHis":
        # CommandAPI23434..234c3 names Rcv+2c six current-time WORDs;
        # GUI47d4b0..47d609 ->47db90 copies them to GFC record+3c.
        for index, row in enumerate(section.records):
            stored = row[1]
            emit(
                "history_headers",
                {
                    "current_time": dict(
                        zip(
                            ("year", "month", "day", "hour", "minute", "second"),
                            stored[:6],
                        )
                    ),
                    "metadata_byte_raw": stored[6],
                    "normal_coefficient_low_byte_raw": stored[6],
                },
                (index, 1),
            )
            # Rcv+18 entries: CommandAPI2354a..23581 logs TimeInfo/DisplayType;
            # GUI47d576..47d5e1 and47e070 preserve the two strings and scalars.
            for item_index, item in enumerate(stored[7]):
                summary = {}
                if item_index < 3:
                    # Native C967CE..C96BA2 ordinary current summary, not history.
                    resource = (
                        "STRING_QUESTION"
                        if any(entry[3] == 0x8000 for entry in stored[7][:3])
                        else None
                    )
                    display = None
                    if resource is None:
                        if item[3] & 0x4000:
                            display = "-"
                        elif item_index in (0, 2) and item[3] == 0:
                            display = str(
                                item[1] - (1 << 32) if item[1] & 0x80000000 else item[1]
                            )
                        elif item_index == 1 and item[3] == 4:
                            days, remainder = divmod(item[1], 86400)
                            hours, remainder = divmod(remainder, 3600)
                            display = f"{hours:02d}h {remainder // 60:02d}m"
                            if days:
                                display = f"{days}d " + display
                    summary = {
                        "current_summary_display": display,
                        "current_summary_resource": resource,
                        "current_summary_display_source": "native-current-summary-resource"
                        if resource
                        else "native-current-summary-format"
                        if display is not None
                        else "native-current-summary-unresolved",
                    }
                emit(
                    "history_time_information",
                    {
                        "strings": [text(item[0]), text(item[2])],
                        "time_info_raw": item[1],
                        "display_type_raw": item[3],
                        **summary,
                    },
                    (index, 1, 7, item_index),
                )

    if section.family == "MILMessage":
        # GUI476000 maps wire order; be4ec0..be4fde composes prefix/body/suffix.
        # a34c7d classifies the last buffer; a36101 selects TEXT presentation.
        for group, screen in enumerate(("message", "confirmation")):
            for index, row in enumerate(section.records[group]):
                emit(
                    "messages",
                    {
                        "screen": screen,
                        "text": text(row[0]),
                        "prefix": text(row[1]),
                        "suffix": text(row[2]),
                        "format": text(row[3]),
                        "category": text(row[4]),
                    },
                    (group, index),
                )
    if section.family in ("ErrRep", "TMRRep"):
        first = 1 + 2 * (section.version > 0x2007) + 2 * (section.version > 0x2008)
        strings = first + 2 + (section.version > 0x100B) + (section.version > 0x1009)
        for index, row in enumerate(section.records):
            # ErrorReportLib1136a cache+168/+268 -> GFC+70/+84;
            # ER_GetLogCapAndNote(dc19) returns the identical native fields.
            item: dict = {
                "caption": text(row[strings + 2]),
                "note": text(row[strings + 3]),
                "log_identifier": text(row[strings]),
                "event_cause": text(row[strings + 1]),
                "date_text": text(row[first]),
                "time_text": text(row[first + 1]),
                "tick_count_ms": row[first + 2 + (section.version > 0x100B)]
                if section.version > 0x1009
                else None,
            }
            if section.version > 0x100B:
                item.update(calendar(row[first + 2]))
            if section.version >= 0x2000:
                images = (
                    strings
                    + 4
                    + (section.version >= 0x2003)
                    + (section.version > 0x2005)
                )
                contact = row[images + 1]
                item["contact"] = {
                    "dealer_type_raw": contact[0],
                    "default_brand_id_raw": contact[1],
                    **dict(
                        zip(
                            (
                                "user_name",
                                "shop_name",
                                "dealer_code",
                                "dealer_phone",
                                "shop_address",
                                "shop_email",
                                "shop_url",
                            ),
                            (text(raw) for raw in contact[2:]),
                            strict=True,
                        )
                    ),
                }
                preferences = row[images + 2]
                start = 11 if section.version > 0x2004 else 10
                item["settings"] = {
                    "vehicle_brand_id_raw": preferences[0],
                    "font_size": preferences[1],
                    "language_id_raw": preferences[2],
                    "unit_selectors_raw": dict(
                        zip(
                            (
                                "vehicle_speed",
                                "temperature",
                                "weight",
                                "air_flow",
                                "air_pressure",
                                "vapor_pressure",
                                "fuel_pressure",
                            ),
                            preferences[3:10],
                            strict=True,
                        )
                    ),
                    "additional_selector_raw": preferences[10] if start == 11 else None,
                }
                item["hotkeys"] = dict(
                    zip(
                        tuple(f"menu_{n}" for n in range(1, 10))
                        + ("record", "snapshot"),
                        (text(raw) for raw in preferences[start : start + 11]),
                        strict=True,
                    )
                )
                item["saved_file_directory"] = text(preferences[start + 11])
                item["application_product_version"] = text(row[images + 3][0])
                item["communication_tool_version"] = text(row[images + 3][1])
                item["denso_os_build"] = text(row[images + 3][2])
                if section.version > 0x2003:
                    item["device"] = dict(
                        zip(
                            ("name", "firmware_version", "dll_version", "api_version"),
                            (text(raw) for raw in row[images + 3][3:7]),
                            strict=True,
                        )
                    )
            emit("error_reports", item, (index,))
    if section.family == "FuncName":
        for index, row in enumerate(section.records):
            emit(
                "functions",
                {"identifiers_raw": row[:2], "name": text(row[2])},
                (index,),
            )
    if section.family in ("MktMonRam", "MktMonRamSSR"):
        for index, row in enumerate(section.records):
            blocks = row[1]
            work, size = len(blocks), 256 * len(blocks)
            if work > MAX_NODES - budget[0] or size > MAX_BYTES - budget[1]:
                raise ReportError("named memory-capture blocks exceed aggregate budget")
            budget[0] += work
            budget[1] += size
            emit(
                "memory_captures",
                {
                    "name": text(row[0]),
                    "block_count": len(blocks),
                    "total_bytes": sum(len(block[-1]) for block in blocks),
                    "blocks": [
                        {
                            "identifier_raw": block[0]
                            if section.version > 0x1000
                            else None,
                            "size": len(block[-1]),
                        }
                        for block in blocks
                    ],
                },
                (index,),
            )
    if section.family == "IniCarInfo":
        # GUI45bc30 restores the CommandAPI SelectCarTypeVin10 response.
        # CommandAPI b9f65/ba021/ba0fe logs the same lists with named IDs.
        emit(
            "vehicle",
            {
                "name": "selection_identity",
                "field": "vin_code",
                "value": text(section.records[0]),
            },
            (0,),
        )
        for group in range(1, 4):
            for index, row in enumerate(section.records[group]):
                emit(
                    "vehicle",
                    {
                        "name": "selection_choice",
                        "field": ("selection_name", "car_information", "option_name")[
                            group - 1
                        ],
                        **(
                            {"category_id_raw": row[0], "selection_id_raw": row[1]}
                            if group == 1
                            else {"information_id_raw": row[0]}
                            if group == 2
                            else {"selection_id_raw": row[0]}
                        ),
                        "value": text(row[-1]),
                        "group": group,
                        "identifiers_raw": row[:-1],
                    },
                    (group, index, len(row) - 1),
                )
    if section.family == "ConfCarInfo":
        # GFCa1a70 -> Techstream475ad0 -> NTTk consumers560cac..560d93.
        # The caller's region chooses the old/new model-year field; retain both.
        fields = (("vehicle_type", 10), ("model_year", 2))
        if section.version > 0x100C:
            fields += (("engine", 15), ("alternate_model_year", 16))
        for label, index in fields:
            emit(
                "vehicle",
                {"name": label, "value": text(section.records[index])},
                (index,),
            )

    walk(
        _section_layout(
            section.family, section.type_raw, section.version, section.context_mode
        ),
        section.records,
    )
    return result


def report_views(file: snapshot.TSEFile, *, encoding: str) -> list[dict]:
    """Named report views for all present native sections, sharing output budgets."""
    if not isinstance(file, snapshot.TSEFile):
        raise ReportError("expected native TSE/TMM/TMR file")
    supported = set(file.metadata["supported_feature_ids"])
    budget = [0, 0]
    result = []
    cache = {}
    for ecu_index, families in [(None, GLOBAL_FEATURES)] + [
        (index, ECU_FEATURES) for index in range(len(file.metadata["ecu_index"]))
    ]:
        for family, features in families.items():
            if not supported.intersection(features):
                continue
            offset = _selected(file, family, ecu_index)
            key = (family, offset)
            if key not in cache:
                cache[key] = decode_section(
                    family,
                    snapshot.tse_section(file, offset),
                    context_mode=int(file.file_type == 4),
                )
            result.append(
                {
                    "ecu_index": ecu_index,
                    "offset": offset,
                    **view_section(cache[key], encoding=encoding, _budget=budget),
                }
            )
    return result


# Native parameter schema: AllDTCReadModule RVA a050, 118 entries.
ALL_DTC_PARAMETERS: tuple[tuple[str, int], ...] = (
    ("Version", 7),
    ("DST-iVersion", 7),
    ("ManufactureInfo", 7),
    ("Index", 6),
    ("Comment", 7),
    ("VehicleInfo/VehicleId", 6),
    ("VehicleInfo/VehicleNameId", 6),
    ("VehicleInfo/VehicleName", 7),
    ("VehicleInfo/VehicleTypeNameId", 6),
    ("VehicleInfo/VehicleTypeName", 7),
    ("VehicleInfo/EngineNameId", 6),
    ("VehicleInfo/EngineName", 7),
    ("VehicleInfo/ModelYear", 7),
    ("VehicleInfo/array-Option/Option/OptionNameId", 6),
    ("VehicleInfo/array-Option/Option/OptionName", 7),
    ("BrandInfo/ManufacturerId", 6),
    ("BrandInfo/BrandId", 6),
    ("BrandInfo/BrandName", 7),
    ("BrandInfo/MarketId", 6),
    ("AllDiag/array-ECUInfo/ECUInfo/ECUId", 6),
    ("AllDiag/array-ECUInfo/ECUInfo/ECUNameId", 6),
    ("AllDiag/array-ECUInfo/ECUInfo/ECUName", 7),
    ("AllDiag/array-ECUInfo/ECUInfo/ECUShortNameId", 6),
    ("AllDiag/array-ECUInfo/ECUInfo/ECUShortName", 7),
    ("AllDiag/array-ECUInfo/ECUInfo/ECUGroupId", 6),
    ("AllDiag/array-ECUInfo/ECUInfo/ECUGroupNameId", 6),
    ("AllDiag/array-ECUInfo/ECUInfo/ECUGroupName", 7),
    ("AllDiag/array-ECUInfo/ECUInfo/ConnectionStatus", 6),
    ("AllDiag/array-ECUInfo/ECUInfo/CIDInfo", 7),
    ("AllDiag/array-ECUInfo/ECUInfo/ProtocolInfo/PhaseType", 6),
    ("AllDiag/array-ECUInfo/ECUInfo/ProtocolInfo/BusType", 6),
    ("AllDiag/array-ECUInfo/ECUInfo/array-FunctionInfo/FunctionInfo/FunctionId", 6),
    ("AllDiag/array-ECUInfo/ECUInfo/array-FunctionInfo/FunctionInfo/ErrorInfo", 10),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-FunctionInfo/FunctionInfo/array-DetailFuctionInfo/DetailFuctionInfo/DetailFuctionInfoId",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-FunctionInfo/FunctionInfo/array-DetailFuctionInfo/DetailFuctionInfo/IsDiagError",
        10,
    ),
    ("AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/DTCTypeNameId", 6),
    ("AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/DTCTypeName", 7),
    ("AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/DTCTypeId", 6),
    ("AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/DTCUndecordedValue", 5),
    ("AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/DTCDispValue", 7),
    ("AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/DTCNameId", 6),
    ("AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/DTCName", 7),
    ("AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/DiagnosisType", 7),
    ("AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/DiagnosisTypeGridNameId", 7),
    ("AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/DiagnosisTypeGridName", 7),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/DiagnosisTypeTooltipNameId",
        7,
    ),
    ("AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/DiagnosisTypeTooltipName", 7),
    ("AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/StatusInfo", 7),
    ("AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/StatusGridNameId", 7),
    ("AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/StatusGridName", 7),
    ("AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/StatusTooltipNameId", 7),
    ("AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/StatusTooltipName", 7),
    ("AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/DTCGroupId", 6),
    ("AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/PredictionInfo", 7),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/FrameNo",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/FFDType",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/PIDId",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/ParameterNameId",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/ParameterName",
        7,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/ParameterShortNameId",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/ParameterShortName",
        7,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/ParameterUnitNameId",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/ParameterUnitName",
        7,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/ParameterDataType",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/ParameterDecimalCount",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/ParameterGraphMax",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/ParameterGraphMin",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/ConversionInfo/ConversionMul",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/ConversionInfo/ConversionDiv",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/ConversionInfo/ConversionOffset",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/ConversionInfo/ConversionTypeId",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/ConversionInfo/ConversionSignType",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/ConversionInfo/ParameterBitLength",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/array-Pattern/ParameterPatternInfo/ParameterPatternDecordedId",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/array-Pattern/ParameterPatternInfo/ParameterPatternDecorded",
        7,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/array-Pattern/ParameterPatternInfo/ParameterPatternUndecoredValue",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/array-Parameter/ParameterValue/ParameterTimeIndex",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/array-FFDSignalInfo/FFDSignalInfo/array-Parameter/ParameterValue/PrameterRawValueBitShifted",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/FFDMulti/FFDMultiStart",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/FFDMulti/FFDMultiEnd",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDInfo/FFDInfo/FFDMulti/FFDMultiTimeInterval",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDDetailInfoId",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDDetailInfoValue",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDDetailInfoAvailableFlag",
        10,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/PIDId",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/ParameterNameId",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/ParameterName",
        7,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/ParameterShortNameId",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/ParameterShortName",
        7,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/ParameterUnitNameId",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/ParameterUnitName",
        7,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/ParameterDataType",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/ParameterDecimalCount",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/ParameterGraphMax",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/ParameterGraphMin",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/ConversionInfo/ConversionMul",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/ConversionInfo/ConversionDiv",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/ConversionInfo/ConversionOffset",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/ConversionInfo/ConversionTypeId",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/ConversionInfo/ConversionSignType",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/ConversionInfo/ParameterBitLength",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/array-Pattern/ParameterPatternInfo/ParameterPatternDecordedId",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/array-Pattern/ParameterPatternInfo/ParameterPatternDecorded",
        7,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/array-Pattern/ParameterPatternInfo/ParameterPatternUndecoredValue",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/array-Parameter/ParameterValue/ParameterTimeIndex",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/array-FFDDetailInfo/FFDDetailInfo/FFDSignalInfo/array-Parameter/ParameterValue/PrameterRawValueBitShifted",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/TimeStampInfo/TripTimeFailFlag",
        10,
    ),
    ("AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/TimeStampInfo/TripTime", 6),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/TimeStampInfo/IGOnElapsedTimeErrorFlag",
        10,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/TimeStampInfo/IgOnElapsedTime",
        7,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/TimeStampInfo/OriginalCountInfo",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/TimeStampInfo/ClockTypeInfo",
        7,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/StatusByteInfo/StatusByteRawValue",
        6,
    ),
    (
        "AllDiag/array-ECUInfo/ECUInfo/array-DTCInfo/DTCInfo/StatusByteInfo/StatusByteDecorededValue",
        7,
    ),
    ("AllDiag/array-ECUInfo/ECUInfo/CurrentTimeInfo/TripTimeFailFlag", 10),
    ("AllDiag/array-ECUInfo/ECUInfo/CurrentTimeInfo/TripTime", 6),
    ("AllDiag/array-ECUInfo/ECUInfo/CurrentTimeInfo/IGOnElapsedTimeErrorFlag", 10),
    ("AllDiag/array-ECUInfo/ECUInfo/CurrentTimeInfo/IgOnElapsedTime", 7),
)


@dataclass
class _XMLText:
    chunks: list[str]
    cdata: bool = False


class AllDTCXML:
    """Bounded host adapter for the nine AllDTCReadModule reader exports.

    Errors remain sticky as in the native object. Python methods return values
    rather than writing through pointers; failed queries raise ReportError.
    """

    def __init__(self) -> None:
        self._root: ET.Element | None = None
        self._content: dict[ET.Element, list[Any]] = {}
        self._preserve: dict[ET.Element, bool] = {}
        self.source = b""
        self._error = 0

    def _fail(self, error: int, message: str) -> NoReturn:
        self._error = error
        raise ReportError(message)

    def open_bytes(self, data: bytes, *, native_file: bool = False) -> None:
        if self._root is not None:
            raise ReportError("AllDTC reader is already open")
        if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
            raise ReportError("AllDTC XML byte budget or type is invalid")
        if native_file:
            if not data.startswith(b"\xfe\xff") or len(data) % 2:
                raise ReportError("native AllDTC file requires UTF-16BE BOM")
            try:
                text = data[2:].decode("utf-16be")
                text = text.removesuffix("\0")
                if "\0" in text:
                    raise ReportError("embedded NUL in native AllDTC XML")
            except UnicodeError as exc:
                raise ReportError("invalid native AllDTC UTF-16BE") from exc
            # The native loader passes wide XML directly to MSXML.
            parsed: bytes | str = text
        else:
            parsed = data
        # Expat exposes CDATA boundaries that ElementTree normally discards.
        # Retain native text-node segments once, never copy text into ancestors.
        parser = expat.ParserCreate(namespace_separator="}")
        stack: list[ET.Element] = []
        root: ET.Element | None = None
        content: dict[ET.Element, list[Any]] = {}
        preserve: dict[ET.Element, bool] = {}
        objects = retained = 0
        cdata = False

        def reserve(size: int = 0) -> None:
            nonlocal objects, retained
            if objects >= MAX_NODES or size > MAX_BYTES - retained:
                raise ReportError("AllDTC XML node/text budget exceeded")
            objects += 1
            retained += size

        def start(name: str, attributes: dict[str, str]) -> None:
            nonlocal root
            if len(stack) >= 64:
                raise ReportError("AllDTC XML depth budget exceeded")
            if "}" in name or ":" in name:
                raise ReportError("AllDTC XML namespaces are unsupported")
            reserve(len(name.encode("utf-8")))
            attrs = {}
            for key, value in attributes.items():
                reserve(len(key.encode("utf-8")) + len(value.encode("utf-8")))
                attrs["{" + key if "}" in key else key] = value
            node = ET.Element(name, attrs)
            content[node] = []
            inherited = preserve[stack[-1]] if stack else False
            local = attrs.get("{http://www.w3.org/XML/1998/namespace}space")
            preserve[node] = inherited if local is None else local == "preserve"
            if stack:
                stack[-1].append(node)
                content[stack[-1]].append(node)
            else:
                root = node
            stack.append(node)

        def end(_name: str) -> None:
            stack.pop()

        def characters(text: str) -> None:
            if not stack or not text:
                return
            reserve(len(text.encode("utf-8")))
            entries = content[stack[-1]]
            if (
                entries
                and isinstance(entries[-1], _XMLText)
                and entries[-1].cdata == cdata
            ):
                entries[-1].chunks.append(text)
            else:
                entries.append(_XMLText([text], cdata))

        def barrier(*_args: Any) -> None:
            if stack:
                reserve()
                content[stack[-1]].append(None)

        def begin_cdata() -> None:
            nonlocal cdata
            cdata = True
            barrier()
            if stack:
                reserve()
                content[stack[-1]].append(_XMLText([], True))

        def end_cdata() -> None:
            nonlocal cdata
            cdata = False
            barrier()

        def forbidden(*_args: Any) -> Any:
            raise ReportError("AllDTC XML declarations are forbidden")

        parser.StartElementHandler = start
        parser.EndElementHandler = end
        parser.CharacterDataHandler = characters
        parser.StartCdataSectionHandler = begin_cdata
        parser.EndCdataSectionHandler = end_cdata
        parser.CommentHandler = barrier
        parser.ProcessingInstructionHandler = barrier
        parser.StartDoctypeDeclHandler = forbidden
        parser.EntityDeclHandler = forbidden
        parser.ExternalEntityRefHandler = forbidden
        try:
            for offset in range(0, len(parsed), 4096):
                parser.Parse(parsed[offset : offset + 4096], False)
            parser.Parse(b"" if isinstance(parsed, bytes) else "", True)
        except (expat.ExpatError, UnicodeError, LookupError, ValueError) as exc:
            raise ReportError("invalid AllDTC XML") from exc
        if root is None:
            raise ReportError("empty AllDTC XML")
        self._content = content
        self._preserve = preserve
        self._root = root
        self.source = data

    def open_xml_w(self, path: str, *, native_file: bool = True) -> None:
        self.open_bytes(read_regular(path, limit=MAX_BYTES), native_file=native_file)

    def open_xml_a(self, path: bytes, *, native_file: bool = True) -> None:
        if not isinstance(path, bytes):
            raise ReportError("AllDTC A path must be CP932 bytes")
        try:
            name = path.decode("cp932")
        except UnicodeError as exc:
            raise ReportError("invalid AllDTC CP932 path") from exc
        self.open_xml_w(name, native_file=native_file)

    def close_xml(self) -> None:
        self._root = None
        self._content = {}
        self._preserve = {}
        self.source = b""

    def get_api_last_error(self) -> int:
        return self._error

    def _select(
        self, parameter: int, indexes: tuple[int, ...]
    ) -> tuple[ET.Element, int]:
        if self._root is None:
            self._fail(5, "AllDTC reader is closed")
        if type(parameter) is not int or not 0 <= parameter < len(ALL_DTC_PARAMETERS):
            self._fail(4, "unknown AllDTC parameter")
        if (
            not isinstance(indexes, tuple)
            or len(indexes) > 20
            or any(
                type(index) is not int or not 0 <= index <= 0x7FFFFFFF
                for index in indexes
            )
        ):
            raise ReportError("invalid AllDTC index vector")
        path, kind = ALL_DTC_PARAMETERS[parameter]
        parts = path.split("/")
        vector = tuple(
            indexes[level] if level < len(indexes) else 0 for level in range(len(parts))
        )
        found = self._query(path, vector, first_only=True)
        if not found:
            self._fail(3, "AllDTC parameter node is absent")
        return found[0], kind

    def _query(
        self, path: str, indexes: tuple[int | None, ...], *, first_only: bool = False
    ) -> list[ET.Element]:
        # Microsoft MSXML3 DOMNode::getElementsByTagName prepends raw './/'
        # and invokes its XSLPattern parser. Implement only the fixed native
        # schema subset: names, child steps, per-parent zero-based positions.
        root = self._root
        if root is None:
            self._fail(5, "AllDTC reader is closed")
        parts = path.split("/")
        work = 0

        def tick() -> None:
            nonlocal work
            work += 1
            if work > MAX_NODES * 20:
                raise ReportError("AllDTC query work budget exceeded")

        chain: list[tuple[ET.Element, int]] = []
        result: list[ET.Element] = []

        def visit(node: ET.Element, position: int) -> bool:
            tick()
            chain.append((node, position))
            if node.tag == parts[-1] and len(chain) >= len(parts):
                matched = True
                for level, (ancestor, ordinal) in enumerate(chain[-len(parts) :]):
                    tick()
                    if ancestor.tag != parts[level] or indexes[level] not in (
                        None,
                        ordinal,
                    ):
                        matched = False
                        break
                if matched:
                    if len(result) >= MAX_NODES:
                        raise ReportError("AllDTC query result budget exceeded")
                    result.append(node)
                    if first_only:
                        return True
            positions: dict[str, int] = {}
            for child in node:
                ordinal = positions.get(child.tag, 0)
                positions[child.tag] = ordinal + 1
                if visit(child, ordinal):
                    return True
            chain.pop()
            return False

        visit(root, 0)
        return result

    def _text(self, node: ET.Element, *, ignore_xml_space: bool = False) -> str:
        output: list[str] = []
        pending = False
        length = 0

        def append(text: str) -> None:
            nonlocal length
            if len(text) > MAX_BYTES // 2 - length:
                raise ReportError("AllDTC parameter text budget exceeded")
            length += len(text)
            output.append(text)

        def visit(current: ET.Element) -> None:
            nonlocal pending
            for entry in self._content[current]:
                if isinstance(entry, ET.Element):
                    visit(entry)
                elif isinstance(entry, _XMLText):
                    raw = "".join(entry.chunks)
                    keep = entry.cdata or (
                        not ignore_xml_space and self._preserve[current]
                    )
                    if keep:
                        if pending and length:
                            append(" ")
                        append(raw)
                        pending = False
                    else:
                        trimmed = raw.strip(" \t\r\n")
                        if trimmed:
                            if (pending or raw[0] in " \t\r\n") and length:
                                append(" ")
                            append(trimmed)
                            pending = raw[-1] in " \t\r\n"
                        elif raw:
                            pending = True

        visit(node)
        return "".join(output).replace("\r\n", "\n").replace("\r", "\n")

    def get_parameter(
        self, parameter: int, indexes: tuple[int, ...] = ()
    ) -> str | int | bool:
        node, kind = self._select(parameter, indexes)
        text = self._text(node)
        if len(text) * 2 > MAX_BYTES:
            raise ReportError("AllDTC parameter text budget exceeded")
        if kind == 7:
            if parameter == 2 and text:
                try:
                    if len(text) % 4 or re.fullmatch(r"[0-9a-fA-F]+", text) is None:
                        raise ValueError("invalid outer hexadecimal string")
                    first = bytes.fromhex(text)
                    # Native 16a0 decodes hexadecimal twice, then transforms
                    # only the payload bytes; the allocated final byte is NUL.
                    second = bytes.fromhex(first.decode("ascii"))
                    text = (
                        bytes((251 - value) & 255 for value in second)
                        .split(b"\0", 1)[0]
                        .decode("cp932")
                    )
                except (ValueError, UnicodeError) as exc:
                    raise ReportError(
                        "invalid AllDTC ManufactureInfo encoding"
                    ) from exc
            return text
        if kind == 10:
            if text not in ("true", "1", "false", "0"):
                raise ReportError("invalid AllDTC boolean")
            return text in ("true", "1")
        if kind not in (5, 6):
            raise ReportError("unsupported AllDTC parameter type")
        # MSVCR100 wcstol/wcstoul: leading whitespace/sign permitted, all
        # remaining characters must be consumed, overflow saturates at 32 bits.
        if text == "":
            return 0
        if len(text) > 128 or re.fullmatch(r"\s*[+-]?[0-9]+", text) is None:
            raise ReportError("invalid AllDTC decimal")
        number = int(text)
        if kind == 6:
            return min(0x7FFFFFFF, max(-0x80000000, number))
        return 0xFFFFFFFF if abs(number) > 0xFFFFFFFF else number & 0xFFFFFFFF

    def _parameter_bytes(
        self, parameter: int, indexes: tuple[int, ...], ansi: bool
    ) -> bytes:
        value = self.get_parameter(parameter, indexes)
        kind = ALL_DTC_PARAMETERS[parameter][1]
        if kind == 7:
            assert isinstance(value, str)
            try:
                return value.encode("cp932" if ansi else "utf-16le") + (
                    b"\0" if ansi else b"\0\0"
                )
            except UnicodeError as exc:
                raise ReportError("AllDTC string is not representable") from exc
        assert isinstance(value, int)
        return bytes((value,)) if kind == 10 else struct.pack("<I", value & 0xFFFFFFFF)

    def get_parameter_w(
        self, parameter: int, capacity: int, indexes: tuple[int, ...] = ()
    ) -> bytes:
        return self._get_buffer(parameter, capacity, indexes, False)

    def get_parameter_a(
        self, parameter: int, capacity: int, indexes: tuple[int, ...] = ()
    ) -> bytes:
        return self._get_buffer(parameter, capacity, indexes, True)

    def _get_buffer(
        self, parameter: int, capacity: int, indexes: tuple[int, ...], ansi: bool
    ) -> bytes:
        if type(capacity) is not int or not 0 < capacity <= MAX_BYTES:
            raise ReportError("invalid AllDTC output capacity")
        data = self._parameter_bytes(parameter, indexes, ansi)
        required = (
            self.get_parameter_length_w(parameter, indexes)
            if parameter == 2 and not ansi
            else len(data)
        )
        if required > capacity:
            self._fail(1, "AllDTC output buffer is too small")
        return data

    def _get_length(self, parameter: int, indexes: tuple[int, ...], ansi: bool) -> int:
        if self._root is None:
            self._fail(5, "AllDTC reader is closed")
        if type(parameter) is not int or not 0 <= parameter < len(ALL_DTC_PARAMETERS):
            self._fail(4, "unknown AllDTC parameter")
        if ALL_DTC_PARAMETERS[parameter][1] != 7:
            self._fail(2, "AllDTC length requires a string parameter")
        if parameter == 2 and not ansi:
            node, _ = self._select(parameter, indexes)
            raw = self._text(node)
            return ((len(raw.encode("utf-16le")) + 2) >> 2) + 2 if raw else 2
        value = self.get_parameter(parameter, indexes)
        if value == "":
            return 1 if parameter == 2 and ansi else 0
        return len(self._parameter_bytes(parameter, indexes, ansi))

    def get_parameter_length_w(
        self, parameter: int, indexes: tuple[int, ...] = ()
    ) -> int:
        return self._get_length(parameter, indexes, False)

    def get_parameter_length_a(
        self, parameter: int, indexes: tuple[int, ...] = ()
    ) -> int:
        return self._get_length(parameter, indexes, True)

    def get_dtc_number(
        self, type_id: int, *, capacity: int = MAX_NODES
    ) -> tuple[tuple[int, int], ...]:
        if self._root is None:
            self._fail(5, "AllDTC reader is closed")
        if type(type_id) is not int or not -0x80000000 <= type_id <= 0x7FFFFFFF:
            raise ReportError("invalid AllDTC diagnostic type")
        if type(capacity) is not int or not 0 < capacity <= MAX_NODES:
            raise ReportError("invalid AllDTC ECU capacity")
        arrays = self._query("AllDiag/array-ECUInfo", (None, None))
        groups = [list(array.iterfind("ECUInfo")) for array in arrays]
        total = sum(map(len, groups))
        if total > capacity:
            raise ReportError("AllDTC ECU output buffer is too small")
        # The original counts all ECU nodes but its subsequent per-parent
        # positional queries exhaust the index space when several nonempty
        # array-ECUInfo parents exist. Preserve this failure, not invented rows.
        if total > max(map(len, groups), default=0):
            self._fail(3, "native AllDTC ECU index space is exhausted")
        ecus = next((group for group in groups if group), [])
        rows = []
        for ecu in ecus:
            identifier_node = ecu.find("ECUId")
            if identifier_node is None:
                self._fail(3, "AllDTC ECU identifier is absent")
            identifier_text = self._text(identifier_node)
            if identifier_text == "":
                identifier_text = "0"
            if (
                len(identifier_text) > 128
                or re.fullmatch(r"\s*[+-]?[0-9]+", identifier_text) is None
            ):
                raise ReportError("invalid AllDTC ECU identifier")
            identifier_value = int(identifier_text)
            identifier = (
                0xFFFFFFFF
                if abs(identifier_value) > 0xFFFFFFFF
                else identifier_value & 0xFFFFFFFF
            )
            count = 0
            for dtc in ecu.iterfind("array-DTCInfo/DTCInfo"):
                type_node = dtc.find("DTCTypeId")
                if type_node is not None and self._text(
                    type_node, ignore_xml_space=True
                ) == str(type_id):
                    count += 1
            rows.append((identifier & 0xFFFFFFFF, count))
        return tuple(rows)


def parse_all_dtc_xml(data: bytes, *, native_file: bool = False) -> AllDTCXML:
    reader = AllDTCXML()
    reader.open_bytes(data, native_file=native_file)
    return reader


def load_all_dtc_xml(path: str, *, native_file: bool = True) -> AllDTCXML:
    reader = AllDTCXML()
    reader.open_xml_w(path, native_file=native_file)
    return reader


def view_all_dtc_xml(reader: AllDTCXML) -> dict[str, Any]:
    """Expose saved vehicle, ECU, DTC and freeze-frame labels without enum guesses."""
    if not isinstance(reader, AllDTCXML) or reader._root is None:
        raise ReportError("an open AllDTC XML reader is required")
    root = reader._root
    nodes = retained = 0

    def reserve(text: str = "") -> None:
        nonlocal nodes, retained
        size = len(text.encode("utf-8"))
        if nodes >= MAX_NODES or size > MAX_BYTES - retained:
            raise ReportError("AllDTC view aggregate budget exceeded")
        nodes += 1
        retained += size

    def leaves(node: ET.Element) -> dict[str, Any]:
        reserve()
        result: dict[str, Any] = {}
        for child in node:
            reserve(child.tag)
            if len(child):
                value: Any = leaves(child)
            else:
                value = reader._text(child)
                reserve(value)
            if child.tag in result:
                previous = result[child.tag]
                if not isinstance(previous, list):
                    previous = [previous]
                    result[child.tag] = previous
                previous.append(value)
            else:
                result[child.tag] = value
        return result

    ecus = []
    for ecu in reader._query("AllDiag/array-ECUInfo/ECUInfo", (None, None, None)):
        reserve()
        row: dict[str, Any] = {}
        for child in ecu:
            if not len(child):
                reserve(child.tag)
                reserve(reader._text(child))
                row[child.tag] = reader._text(child)
        row["dtcs"] = [leaves(dtc) for dtc in ecu.iterfind("array-DTCInfo/DTCInfo")]
        ecus.append(row)
    vehicles = reader._query("VehicleInfo", (None,), first_only=True)
    vehicle = vehicles[0] if vehicles else None
    return {
        "vehicle": leaves(vehicle) if vehicle is not None else {},
        "ecus": ecus,
        "stored_fields": leaves(root),
    }
