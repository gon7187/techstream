"""Source-bound retained MS2 diagnostic operations over native communication primitives.

Only independently recovered operations are advertised. OEM modules are never loaded.
"""

from __future__ import annotations

import math
import struct
import sys
from dataclasses import dataclass
from fractions import Fraction
from typing import Protocol, cast

from scripts import utility_ex_security as security
from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import (
    SHA_18_TY,
    SHA_PLUS_TY,
    TYComm,
    TYContext,
    TYSourceError,
)


class MS2Comm(TYComm, Protocol):
    def select_diagnostic_mode(self, kind: int) -> int: ...

    def keepalive(self, enabled: bool, wait: bool = False) -> int | None: ...

    def configure_keepalive(
        self, interval_ms: int, request: bytes, response_size: int, flags: int
    ) -> None: ...


@dataclass(frozen=True)
class MS2RAB02Message:
    """Native RAB buffer plus the selected metadata record's DWORD at offset8."""

    data: bytearray
    record_identifier: int
    module_sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.data, bytearray)
            or type(self.record_identifier) is not int
            or not 0 <= self.record_identifier <= 0xFFFFFFFF
        ):
            raise ValueError(
                "MS2RAB requires mutable native data and a uint32 metadata DID"
            )
        if self.module_sha256 not in (SHA_18_TY, SHA_PLUS_TY):
            raise TYSourceError("MS2RAB metadata source is unreviewed")


@dataclass(frozen=True)
class MS2IG01Message:
    """Native IG message plus the selected record's DWORD at native offset4."""

    data: bytearray
    record_identifier: int
    module_sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.data, bytearray)
            or type(self.record_identifier) is not int
            or not 0 <= self.record_identifier <= 0xFFFFFFFF
        ):
            raise ValueError(
                "MS2IG requires mutable data and uint32 selected metadata DID"
            )
        if self.module_sha256 not in (SHA_18_TY, SHA_PLUS_TY):
            raise TYSourceError("MS2IG selected record belongs to an unreviewed source")


_EXPORTS = (
    "Ex2MS2ABS_01_CheckPressureSensorValue",
    "Ex2MS2ABS_01_SendMessage",
    "Ex2MS2ABS_02_SendMessage",
    "Ex2MS2ABS_03_SendMessage",
    "Ex2MS2ABS_04_SendMessage",
    "Ex2MS2ABS_05_SendMessage",
    "Ex2MS2AT_01_SendMessage",
    "Ex2MS2AT_02_SendMessage",
    "Ex2MS2BDY_01_SendMessage",
    "Ex2MS2DCM_01_SendMessage",
    "Ex2MS2DCM_02_SendMessage",
    "Ex2MS2EFI_01_SendMessage",
    "Ex2MS2EFI_02_SendMessage",
    "Ex2MS2EFI_03_SendMessage",
    "Ex2MS2EFI_04_SendMessage",
    "Ex2MS2EFI_05_SendMessage",
    "Ex2MS2EFI_06_SendMessage",
    "Ex2MS2EMPS_01_SendMessage",
    "Ex2MS2EMPS_02_SendMessage",
    "Ex2MS2GWY_01_SendMessage",
    "Ex2MS2IG_01_SendMessage",
    "Ex2MS2MET_01_SendMessage",
    "Ex2MS2MET_02_SendMessage",
    "Ex2MS2PWD_01_SendMessage",
    "Ex2MS2PWD_02_SendMessage",
    "Ex2MS2RAB_01_SendMessage",
    "Ex2MS2RAB_02_SendMessage",
    "Ex2MS2SAS_01_SendMessage",
    "Ex2MS2SAS_02_SendMessage",
    "Ex2MS2SAS_03_SendMessage",
    "Ex2MS2TPW_01_SendMessage",
)


def supported_exports(source_sha256: str) -> tuple[str, ...]:
    if source_sha256 not in (SHA_18_TY, SHA_PLUS_TY):
        return ()
    from scripts import utility_ex_ms2_eyes

    return _EXPORTS + utility_ex_ms2_eyes.supported_exports(source_sha256)


def _finalize(*communications: TYComm) -> None:
    """Attempt every owned cleanup and preserve the original typed host failure."""
    active, first = sys.exception(), None
    for communication in communications:
        try:
            communication.finalize()
        except BaseException as error:  # noqa: BLE001 - finish every manager, then preserve failure
            if active is not None:
                active.add_note("MS2 finalization raised " + type(error).__name__)
            elif first is None:
                first = error
    if active is None and first is not None:
        raise first


def _check(context: TYContext) -> None:
    if context.is_cancelled():
        raise Cancelled("MS2 operation cancelled")


def _u32(data: bytearray, offset: int = 0) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _put(data: bytearray, offset: int, value: int) -> None:
    data[offset : offset + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")


def _manager(context: TYContext) -> TYComm:
    return context.comm(
        "native:1011d4f0" if context.module_sha256 == SHA_18_TY else "native:101392d0"
    )


def _initialize(comm: TYComm, context: TYContext, retries: int = 0) -> int:
    _check(context)
    status = comm.initialize()
    if not status:
        comm.configure("native_1080", 0)
        comm.configure("native_1084", 180000)
        comm.configure("native_1064", retries)
    return status


def _exchange(
    comm: TYComm,
    context: TYContext,
    request: bytes,
    minimum: int,
    echo: int,
    retry_helper: bool = False,
    publish_nrc: bool = True,
) -> tuple[int, bytes]:
    _check(context)
    status, reply = comm.exchange(request)
    if retry_helper and status in (2, 7):
        context.native_sleep(0)
    if status == 7 and publish_nrc:
        key = "native_global:" + (
            "1012ae38" if context.module_sha256 == SHA_18_TY else "10153554"
        )
        context.state[key] = reply[2] if len(reply) > 2 else 0
    if not status and (
        len(reply) < minimum or reply[1 : echo + 1] != request[1 : echo + 1]
    ):
        status = 3
    return status, reply


def _read(
    comm: TYComm,
    context: TYContext,
    identifier: int,
    minimum: int,
    retry_helper: bool = False,
) -> tuple[int, bytes]:
    return _exchange(
        comm, context, b"\x22" + identifier.to_bytes(2, "big"), minimum, 2, retry_helper
    )


def _routine(
    comm: TYComm,
    context: TYContext,
    identifier: int,
    subfunction: int,
    minimum: int = 4,
    payload: bytes = b"",
) -> tuple[int, bytes]:
    status, reply = _exchange(
        comm,
        context,
        b"\x31" + bytes([subfunction]) + identifier.to_bytes(2, "big") + payload,
        minimum,
        3,
        True,
    )
    return status, reply


def _restore(comm: TYComm, context: TYContext) -> int:
    _check(context)
    return comm.session(1, 1, stop_on_error=True)


def _support_bitmap(
    comm: TYComm,
    context: TYContext,
    identifier: int,
    bitmap: bytearray,
    group: int | None = None,
) -> int:
    if group is not None:
        cursor = group
    elif 0x100 < identifier <= 0x200:
        cursor = 0x100
    elif 0x200 < identifier <= 0x300:
        cursor = 0x200
    elif 0x300 < identifier <= 0x1000:
        cursor = 0x300
    elif 0x1000 < identifier <= 0x2000:
        cursor = 0x1000
    elif 0x2000 < identifier <= 0x3000:
        cursor = 0x2000
    else:
        raise TYSourceError(
            "MS2 support group requires an explicit reviewed source group"
        )
    stop = (identifier - ((identifier - 1) & 31) - 1) & 0xFFFF
    while True:
        status, reply = _read(comm, context, cursor, 7, True)
        if status:
            return status
        offset = (cursor >> 3) & 0x1FF
        if offset + 4 > len(bitmap):
            raise TYSourceError("MS2 support bitmap exceeded recovered native span")
        bitmap[offset : offset + 4] = reply[3:7]
        if cursor >= stop or not reply[6] & 1:
            return 0
        cursor += 0x20


def _supported(bitmap: bytearray, identifier: int) -> bool:
    offset = ((identifier & 0xFFF) - 1) >> 3
    return bool(bitmap[offset] & (0x80 >> ((identifier - 1) & 7)))


def _support(
    comm: TYComm,
    context: TYContext,
    identifier: int,
    required: tuple[int, ...],
    missing: int = 3,
) -> int:
    bitmap = bytearray(0x200)
    status = _support_bitmap(comm, context, identifier, bitmap)
    return status or (
        0 if all(_supported(bitmap, pid) for pid in required) else missing
    )


def _start_abs(
    comm: TYComm, context: TYContext, routine: int, denied: int = 2000
) -> int:
    _restore(comm, context)
    status = comm.session(3, 1)
    if status == 7 and comm.read_field("native_10b0") == 0x69:
        return denied
    if status:
        return status
    status, _ = _routine(comm, context, routine, 1)
    if status:
        _restore(comm, context)
        return denied + 1
    return 0


def _finish_abs(
    comm: TYComm, context: TYContext, routine: int, failure: int, delay: int = 0
) -> int:
    while True:
        status, reply = _routine(comm, context, routine, 3, 6)
        if status or int.from_bytes(reply[4:6], "big") != 1:
            break
    if not status and int.from_bytes(reply[4:6], "big") == 2:
        status = _restore(comm, context)
        if not status and delay:
            context.native_sleep(delay)
        return status
    _restore(comm, context)
    return failure


def _pressure(data: bytearray, comm: TYComm, context: TYContext) -> int:
    status, reply = _read(comm, context, 0x102B, 5)
    if not status:
        _put(data, 8, int.from_bytes(reply[3:5], "big", signed=True) * 0x51A)
    return status


def _abs(export: str, data: bytearray, comm: TYComm, context: TYContext) -> int:
    action = _u32(data)
    group = export.split("_")[1]
    globals18 = {"01": "1012ae20", "02": "1012ae24", "03": "1012ae28"}
    globals_plus = {"01": "1015353c", "02": "10153540", "03": "10153544"}
    address = (globals18 if context.module_sha256 == SHA_18_TY else globals_plus).get(
        group
    )
    key = "native_global:" + address if address else ""
    status = 0
    retain = False
    try:
        if not key or not context.state.get(key, 0):
            status = _initialize(comm, context)
            if status:
                return status
            if key:
                context.state[key] = 1
        if group == "01":
            if action == 0:
                status = _support(comm, context, 0x102B, (0x102B,))
            elif action == 1:
                status = _pressure(data, comm, context)
            elif action == 2:
                while True:
                    for _ in range(20):
                        _check(context)
                        if _u32(data, 4):
                            break
                        context.native_sleep(10)
                    if _u32(data, 4):
                        status = 2003 if _u32(data, 4) == 1 else 0
                        break
                    status = _pressure(data, comm, context)
                    if status:
                        break
            elif action == 3:
                status = _start_abs(comm, context, 0x203)
            elif action == 4:
                context.native_sleep(4200)
            elif action == 5:
                status = _finish_abs(comm, context, 0x203, 2002, 5000)
            retain = 0 < action < 5 and status == 0
        elif group == "02":
            if action == 0:
                status = _start_abs(comm, context, 0x204)
            elif action == 1:
                context.native_sleep(4200)
            elif action == 2:
                context.native_sleep(3200)
                status = _finish_abs(comm, context, 0x204, 2002)
            retain = 0 <= action < 2 and status == 0
        elif group == "03":
            if action == 0:
                status = _support(comm, context, 0x102D, (0x1029, 0x102C, 0x102D))
            elif action == 1:
                status, reply = _read(comm, context, 0x1029, 5)
                if (
                    not status
                    and not -12 <= int.from_bytes(reply[3:5], "big", signed=True) <= 12
                ):
                    status = 2000
                for identifier, error in ((0x102D, 2001), (0x102C, 2002)):
                    if status:
                        break
                    status, reply = _read(comm, context, identifier, 4)
                    if (
                        not status
                        and not -17
                        <= int.from_bytes(reply[3:4], "big", signed=True)
                        <= 17
                    ):
                        status = error
            elif action == 2:
                status = _start_abs(comm, context, 0x202, 2003)
                if not status:
                    context.native_sleep(10)
                    status = _finish_abs(comm, context, 0x202, 2005)
            retain = action == 1 and status == 0
        else:
            _restore(comm, context)
            status = comm.session(3, 1)
            if status == 7:
                return 2000 if comm.read_field("native_10b0") == 0x69 else 2002
            if status:
                return 2002
            status, _ = _routine(comm, context, 0x207, 1)
            if status:
                _restore(comm, context)
                return 2001
            status = _finish_abs(comm, context, 0x207, 2002)
        return status
    finally:
        if not retain:
            _finalize(comm)
            if key:
                context.state[key] = 0


def _efi01(data: bytearray, comm: TYComm, context: TYContext) -> int:
    try:
        status = _initialize(comm, context)
        if status:
            return status
        action = _u32(data, 0x4090)
        if action == 0:
            bitmap = bytearray(16)
            status = _support_bitmap(comm, context, 0x1064, bitmap)
            data[:16] = bitmap
            if not status and (
                not _supported(bitmap, 0x1022)
                or not any(_supported(bitmap, pid) for pid in range(0x1061, 0x1065))
            ):
                status = 22
            return status
        if action != 1:
            return 0
        status, reply = _read(comm, context, 0x1022, 4)
        if status:
            return status
        if reply[3] == 0:
            return 1000
        if reply[3] != 0xFF:
            return 3
        for index, identifier in enumerate(range(0x1061, 0x1065)):
            offset = 16 + index * 0x1020
            data[offset : offset + 0x1020] = bytes(0x1020)
            if _supported(data, identifier):
                status, reply = _read(comm, context, identifier, 8)
                if status:
                    return status
                if len(reply) > 0x1020:
                    raise TYSourceError(
                        "MS2EFI01 response exceeds native output capacity"
                    )
                data[offset : offset + len(reply)] = reply
        return 0
    finally:
        _finalize(comm)


# Nonsecret diagnostic identifiers and reply lengths:18dbc60/Pluse0910.
_EFI04_ROWS = (
    (0x13D2, 5),
    (0x13D3, 5),
    (0x13D4, 5),
    (0x13D5, 5),
    (0x13D6, 5),
    (0x13D7, 5),
    (0x13D9, 4),
    (0x13DD, 4),
    (0x13E3, 5),
    (0x13E4, 6),
    (0x13E5, 6),
)


def _efi04(data: bytearray, comm: TYComm, context: TYContext) -> int:
    try:
        status = _initialize(comm, context)
        if status:
            return status
        if _u32(data, 0xE0) == 0:
            bitmap = bytearray(0x80)
            status = _support_bitmap(comm, context, 0x13E5, bitmap)
            data[:0x80] = bitmap
            return status or (
                0 if any(_supported(bitmap, pid) for pid, _ in _EFI04_ROWS) else 1000
            )
        data[0x80:0xE0] = bytes(0x60)
        output = 0x80
        for identifier, minimum in _EFI04_ROWS:
            if not _supported(data, identifier):
                continue
            status, reply = _read(comm, context, identifier, minimum)
            if status:
                return status
            _put(data, output, identifier)
            _put(data, output + 4, int.from_bytes(reply[3:minimum], "big"))
            output += 8
        return 0
    finally:
        _finalize(comm)


# Nonsecret DID selection table:18dbb70/Pluse0810, independently checked.
_BDY_IDS = (
    0x10A2,
    0x10AE,
    0x10B2,
    0x10B8,
    0x10B9,
    0x10BA,
    0x10BD,
    0x10D3,
    0x10DB,
    0x1124,
    0x1126,
    0x1129,
    0x112C,
    0x112D,
    0x112E,
    0x1131,
    0x1132,
    0x1134,
    0x1136,
    0x113D,
    0x1145,
    0x1146,
    0x114C,
    0x114D,
    0x1163,
    0x1164,
    0x1165,
    0x1166,
    0x1168,
    0x1173,
    0x2001,
    0x2002,
    0x2003,
    0x2004,
    0x2005,
    0x2006,
    0x2007,
    0x2008,
    0x2009,
    0x2010,
    0x2011,
    0x2012,
    0x2014,
    0x2015,
    0x2016,
    0x2017,
    0x2018,
)


def _bdy(data: bytearray, comm: TYComm, context: TYContext) -> int:
    try:
        status = _initialize(comm, context)
        if status:
            return status
        action = _u32(data)
        if action == 0:
            bitmap = bytearray(64)
            if _support_bitmap(comm, context, 0x114D, bitmap):
                return 2000
            if not _supported(bitmap, 0x114D):
                return 22
            status, reply = _read(comm, context, 0x114D, 4)
            if status:
                return status
            if reply[3] == 0xFF:
                return 2001
            bitmap = bytearray(64)
            status = _support_bitmap(comm, context, 0x1173, bitmap)
            if status:
                return status
            second = bytearray(4)
            status = _support_bitmap(comm, context, 0x2018, second)
            if status:
                return status
            data[4:51] = bytes(
                int(_supported(bitmap if pid < 0x2000 else second, pid))
                for pid in _BDY_IDS
            )
            if not any(data[4:51]):
                return 22
        elif action == 1:
            identifier = _BDY_IDS[data[98]]
            status, _ = _exchange(
                comm,
                context,
                b"\x2e" + identifier.to_bytes(2, "big") + data[99:100],
                3,
                2,
                True,
            )
            if status:
                return status
        data[51:98] = bytes(47)
        for index, identifier in enumerate(_BDY_IDS):
            if data[index + 4] != 1:
                continue
            status, reply = _read(comm, context, identifier, 4)
            data[index + 51] = 0x55 if status else reply[3]
        return 0
    finally:
        _finalize(comm)


def _rab01(data: bytearray, comm: TYComm, context: TYContext) -> int:
    try:
        status = _initialize(comm, context)
        if status:
            return status
        if _u32(data, 32) == 0:
            bitmap = bytearray(24)
            status = _support_bitmap(comm, context, 0x10A6, bitmap)
            required = (0x10A1, 0x10A2, 0x10A3, 0x10A4, 0x10A5, 0x10A6, 0x101E)
            return status or (
                0 if all(_supported(bitmap, pid) for pid in required) else 22
            )
        data[:32] = bytes(32)
        for index, identifier in enumerate((0x10A1, 0x10A3, 0x10A5)):
            status, reply = _read(comm, context, identifier, 4)
            if status:
                return status
            _put(data, index * 8, reply[3])
            if reply[3]:
                status, reply = _read(comm, context, identifier + 1, 5)
                if status:
                    return status
                _put(data, index * 8 + 4, int.from_bytes(reply[3:5], "big"))
        if not any(_u32(data, index * 8) for index in range(3)):
            return 1004
        status, reply = _read(comm, context, 0x101E, 5)
        if not status:
            _put(data, 28, int.from_bytes(reply[3:5], "big"))
        return status
    finally:
        _finalize(comm)


def _sas02(data: bytearray, comm: TYComm, context: TYContext) -> int:
    try:
        status = _initialize(comm, context)
        if status:
            return status
        action = _u32(data)
        if action == 0:
            return _support(comm, context, 0x105E, (0x105E,), 22)
        if action != 1:
            return 0
        status, reply = _read(comm, context, 0xF190, 20)
        if status:
            return status
        if len(reply) != 20:
            return 3
        data[4:21] = reply[3:20]
        status, reply = _read(comm, context, 0x105E, 4)
        if not status:
            if reply[3] not in (0, 0xFF):
                return 3
            data[22] = reply[3]
        return status
    finally:
        _finalize(comm)


_MET01_IDS = (
    0xA002,
    0xA003,
    0xA004,
    0xA005,
    0xA006,
    0xA009,
    0xA00C,
    0xA00F,
    0xA010,
    0xA011,
    0xA014,
    0xA016,
    0xA021,
    0xA022,
    0xA023,
    0xA024,
    0xA025,
    0xA026,
    0xA027,
    0xA028,
)


def _met01(data: bytearray, comm: TYComm, context: TYContext) -> int:
    try:
        status = _initialize(comm, context)
        if status:
            return status
        if _u32(data, 0x188) != 0:
            return 0
        bitmap = bytearray(8)
        if _support_bitmap(comm, context, 0xA028, bitmap, 0xA000):
            return 1000
        found = False
        for identifier in _MET01_IDS:
            if _supported(bitmap, identifier):
                count = _u32(data, 0x180)
                if count >= 32:
                    raise ValueError(
                        "MS2MET selected records exceed native output capacity"
                    )
                _put(data, count * 12, identifier)
                _put(data, 0x180, count + 1)
                _put(data, 0x184, 1)
                found = True
        if not found:
            return 3
        for index in range(_u32(data, 0x180)):
            offset = index * 12
            status, reply = _read(comm, context, _u32(data, offset), 4)
            if status:
                return status
            _put(data, offset + 8, 1)
            data[offset + 4] = reply[3]
        return 0
    finally:
        _finalize(comm)


def _sas01(data: bytearray, comm: TYComm, context: TYContext) -> int:
    old = context.module_sha256 == SHA_18_TY
    other = context.comm("native:1011c400" if old else "native:10135c58")
    vin_comm = context.comm("native:1011b310" if old else "native:10136e10")

    def cleanup_session() -> None:
        if _u32(data, 0x44) == 1:
            _restore(comm, context)

    def authenticate() -> int:
        status = comm.session(3, 1, normal_first=True)
        if status:
            return status
        _put(data, 0x44, 1)
        key = security.source_key(context, 0xDBD90 if old else 0xE0A40, 16)
        return security.security_access(
            context,
            cast(MS2Comm, comm),
            level=3,
            key=key,
            preliminary_comm=cast(MS2Comm, other),
            expected_capability=2,
            mode=1,
            direction=2,
        )

    def write(identifier: int, value: bytes) -> int:
        return _exchange(
            comm, context, b"\x2e" + identifier.to_bytes(2, "big") + value, 3, 2, True
        )[0]

    try:
        status = comm.initialize()
        if status:
            return status
        other.configure_target(0x763)
        status = _initialize(other, context)
        if status:
            return status
        status = cast(MS2Comm, vin_comm).select_diagnostic_mode(3)
        if status:
            return status
        vin_comm.configure_target(0x7A2, 0, 0x7DF, 0, 0x7E0)
        status = vin_comm.initialize()
        if status:
            return status
        for manager in (comm, vin_comm):
            manager.configure("native_1080", 0)
            manager.configure("native_1084", 180000)
            manager.configure("native_1064", 0)
        periodic = cast(MS2Comm, comm)
        periodic.configure_keepalive(1000, b"\x3e\x00", 1, 0xF0)
        action = _u32(data)
        if action == 0:
            bitmap = bytearray(512)
            if _support_bitmap(other, context, 0x251, bitmap):
                return 1003
            if not all(_supported(bitmap, identifier) for identifier in (0x250, 0x251)):
                return 1001
            bitmap = bytearray(512)
            if _support_bitmap(comm, context, 0x105E, bitmap):
                return 1003
            return 0 if _supported(bitmap, 0x105E) else 1001
        if action == 2:
            _put(data, 0x40, 1)
            if not authenticate() and not write(0x105E, b"\xff"):
                status = _restore(comm, context)
                _put(data, 0x44, 0)
                cleanup_session()
                return 1003 if status else 0
            cleanup_session()
            return 1003
        if action != 1:
            _put(data, 0x40, 1)
            _restore(comm, context)
            return 0
        status, reply = _read(comm, context, 0x105E, 4)
        if status:
            cleanup_session()
            return 1003
        if reply[3]:
            cleanup_session()
            return 1002 if reply[3] == 0xFF else 1003
        status, reply = _exchange(vin_comm, context, b"\x09\x02", 20, 1, True)
        if status:
            cleanup_session()
            return 1003
        data[4:22] = reply[3:20] + b"\0"
        _finalize(vin_comm)
        status = cast(MS2Comm, vin_comm).select_diagnostic_mode(2)
        if status:
            cleanup_session()
            return status
        vin_comm.configure_target(0x7A2, 0, 0x7DF, 0, 0x7E0)
        status = _initialize(vin_comm, context)
        if status:
            cleanup_session()
            return status
        status, reply = _exchange(vin_comm, context, b"\x09\x0a", 4, 1, True)
        if status or len(reply) > 23:
            cleanup_session()
            return 1005
        data[0x28:0x3D] = bytes(21)
        data[0x28 : 0x28 + len(reply) - 3] = reply[3:]
        # Native trims trailing zeros and changes only interior zeros into spaces.
        last = 19
        while last >= 0 and not data[0x28 + last]:
            last -= 1
        for index in range(last + 1):
            if not data[0x28 + index]:
                data[0x28 + index] = 0x20
        vin = bytes(data[4:21])
        if vin == bytes(17) or vin == b"\xff" * 17:
            cleanup_session()
            return 1004
        if data[12] not in b"0123456789X":
            cleanup_session()
            return 1005
        if authenticate() or write(0xF190, vin):
            cleanup_session()
            return 1003
        status = _restore(comm, context)
        _put(data, 0x44, 0)
        if status:
            cleanup_session()
            return 1003
        for attempt in range(4):
            status, reply = _read(comm, context, 0xF190, 20)
            if status or len(reply) != 20:
                cleanup_session()
                return 1003
            data[22:40] = reply[3:20] + b"\0"
            if bytes(data[22:39]) == vin:
                _put(data, 0x40, 0)
                return 0
            if attempt == 3:
                cleanup_session()
                return 1006
        raise AssertionError("native SAS verification loop lost terminal status")
    finally:
        _finalize(comm, other, vin_comm)


def _met02(data: bytearray, comm: TYComm, context: TYContext) -> int:
    other = context.comm(
        "native:1011a220" if context.module_sha256 == SHA_18_TY else "native:1013d6a8"
    )
    host_fault = False
    try:
        if _u32(data, 0x210) == 1:
            status = comm.initialize()
            if status:
                return status
            other.configure_target(0x763)
            status = other.initialize()
            if status:
                return status
            for manager in (comm, other):
                manager.configure("native_1080", 0)
                manager.configure("native_1084", 180000)
                manager.configure("native_1098", 4)
                manager.configure("native_1064", 4)
        action = _u32(data, 0x218)
        if action == 0:
            bitmap = bytearray(28)
            status = _support_bitmap(comm, context, 0x10C2, bitmap)
            if status:
                return 1000
            if not _supported(bitmap, 0x10C2):
                return 3
            status, reply = _read(comm, context, 0x10C2, 4)
            if status:
                return 3
            data[0x20C] = reply[3]
            return 0
        if action == 3:
            _put(data, 0x210, 1)
            _restore(comm, context)
            return 0
        if action == 1:
            key = security.source_key(
                context, 0xDBD70 if context.module_sha256 == SHA_18_TY else 0xE0A20, 32
            )
            status = security.security_access(
                context,
                cast(MS2Comm, comm),
                level=3,
                key=key,
                preliminary_comm=cast(MS2Comm, other),
                expected_capability=0,
                mode=2,
                direction=2,
            )
            if not status:
                status = cast(MS2Comm, comm).keepalive(True)
                if type(status) is not int:
                    raise TYSourceError(
                        "MS2MET worker start did not return native status"
                    )
                if not status:
                    status, _ = _exchange(
                        comm, context, b"\x2e\x10\xc2\xff", 3, 2, True
                    )
            if not status:
                _put(data, 0x210, 0)
                host_fault = False
                return 0
            _restore(comm, context)
            _put(data, 0x210, 1)
            return 3
        _put(data, 0x210, 1)
        selected = _u32(data, 0x204)
        if selected:
            bitmap = bytearray(512)
            last = _u32(data, 0x208)
            group = (last - 1) & 0xF000 if last > 0x3000 else None
            status = _support_bitmap(comm, context, last, bitmap, group)
            ids = tuple(_u32(data, 0x184 + i * 4) for i in range(selected))

            def base(identifier: int) -> int:
                if not 0x100 < identifier <= 0xF000:
                    return -1
                return (
                    0x100
                    if identifier <= 0x200
                    else 0x200
                    if identifier <= 0x300
                    else 0x300
                    if identifier <= 0x1000
                    else (identifier - 1) & 0xF000
                )

            if (
                not status
                and base(ids[0]) != -1
                and all(base(i) == base(ids[0]) for i in ids)
                and all((i & 31) and _supported(bitmap, i) for i in ids)
            ):
                count = _u32(data, 0x180)
                if count & 0x80000000:
                    count = 0
                for index in range(count):
                    offset = index * 12
                    width = _u32(data, offset + 8)
                    status, _ = _exchange(
                        comm,
                        context,
                        b"\x2e"
                        + (_u32(data, offset) & 0xFFFF).to_bytes(2, "big")
                        + data[offset + 4 : offset + 4 + width],
                        3,
                        2,
                        True,
                    )
                    if status:
                        _restore(comm, context)
                        return 3
                status, _ = _exchange(comm, context, b"\x2e\x10\xc2\x00", 3, 2, True)
                _restore(comm, context)
                return 3 if status == 5 else 1001 if status else 0
        _restore(comm, context)
        return 3
    except BaseException:
        host_fault = True
        raise
    finally:
        if host_fault or _u32(data, 0x210) == 1:
            _finalize(comm, other)


def _tpw(data: bytearray, context: TYContext) -> int:
    comm = context.comm("selected")
    try:
        _check(context)
        status = comm.initialize()
        if status:
            return status
        setter = (
            "native_rva:12180"
            if context.module_sha256 == SHA_18_TY
            else "native_rva:142f0"
        )
        comm.configure(setter, 150)
        action = _u32(data)
        if action == 0:
            status, reply = _exchange(
                comm, context, b"\x21\x06", 4, 1, publish_nrc=False
            )
            if not status:
                data[4:6] = reply[2:4]
            return status
        if action != 1:
            return 0
        payload = bytearray(32)
        payload[0] = 0 if _u32(data, 12) == 1 else 0x80
        payload[1] = 5 if _u32(data, 8) == 5 else 4
        for index, offset in enumerate((4, 10, 16, 22, 28)):
            payload[offset : offset + 4] = data[16 + index * 4 : 20 + index * 4]
        status, _ = _exchange(
            comm, context, b"\x3b\x0e" + payload, 2, 1, publish_nrc=False
        )
        return status
    finally:
        _finalize(comm)


_EMPS_VARIANTS = tuple(
    bytes.fromhex(value)
    for value in (
        "5a2c95000100",
        "5a2c95100100",
        "5a2c95000101",
        "5a2c95100101",
    )
)


def _emps(export: str, data: bytearray, context: TYContext) -> int:
    comm = context.comm("selected")
    action = _u32(data)
    first = "MS2EMPS_01" in export
    retain = False

    def exchange(request: bytes) -> tuple[int, bytes]:
        return _exchange(comm, context, request, 0, 0, publish_nrc=False)

    def restore() -> int:
        return exchange(b"\x10\x01")[0]

    def dtcs() -> tuple[int, tuple[int, ...]]:
        _check(context)
        status, reply = comm.read_dtcs(0x81, 0x1000)
        # The source helper owns framing; callers read from its zeroed native buffer.
        count = reply[1] if len(reply) > 1 else 0
        padded = reply.ljust(0x1020, b"\0")
        return status, tuple(
            int.from_bytes(padded[2 + i * 2 : 4 + i * 2], "big") for i in range(count)
        )

    def supported(reply: bytes) -> bool:
        if reply[:6] in _EMPS_VARIANTS:
            return True
        if context.module_sha256 == SHA_PLUS_TY:
            return reply[:5] in tuple(
                bytes.fromhex(v)
                for v in ("5a5c950001", "5a5c951001", "5ac6202700", "5ac6202710")
            )
        return False

    def check_final_dtcs() -> int:
        status, records = dtcs()
        result = 0
        if status:
            result = 1011
        elif any(
            identifier not in (0x5515, 0x5516, 0x5525, 0x5581) for identifier in records
        ):
            result = 1010
        elif any(identifier in (0x5515, 0x5516) for identifier in records):
            result = 1009
        restored = restore()
        return result or restored

    def read_result() -> int:
        status, reply = exchange(b"\xa9\x03")
        if status:
            return 1011 if status == 5 else status
        if len(reply) < 3:
            return 1000
        data[4] = reply[2]
        return 1005

    try:
        if not first or action in (0, 1, 2):
            status = comm.initialize()
            if status:
                return status
            comm.configure(
                "native_rva:12180"
                if context.module_sha256 == SHA_18_TY
                else "native_rva:142f0",
                150,
            )
        if not first:
            if action == 0:
                status, reply = exchange(b"\x3b\x00")
                if status:
                    return 1011 if status == 5 else status
                padded = reply.ljust(4, b"\0")
                if (
                    len(reply) < 3
                    or (int.from_bytes(padded[:3], "big") & 0xFFFF40) != 0x7B0040
                ):
                    return 1000
                status, reply = exchange(b"\x1a\x81")
                if status:
                    return 1011 if status == 5 else status
                if len(reply) < 6:
                    return 1000
                return 0 if supported(reply) else 1013
            if action == 1:
                status, records = dtcs()
                if status:
                    return 1011 if status == 5 else status
                if any(
                    identifier in (0x5534, 0x5581, 0x5582, 0x5583)
                    for identifier in records
                ):
                    return (
                        1003
                        if any(identifier in (0x5534, 0x5581) for identifier in records)
                        else 1004
                    )
                return read_result()
            if action == 2:
                return read_result()
            status, reply = exchange(b"\x3b\x02")
            if not status:
                return 1000 if len(reply) < 2 else 0
            if status == 5:
                return 1011
            # Source compares the zero-initialized third receive byte even for a short error reply.
            error = reply[2] if len(reply) > 2 else 0
            return 1010 if error == 0x10 else 1009 if error == 0x22 else status
        if action == 0:
            status, reply = exchange(b"\x1a\x81")
            if status:
                return status
            if len(reply) < 6:
                return 1000
            if not supported(reply):
                return 1011
            status, records = dtcs()
            if not status and any(
                identifier not in (0x5515, 0x5525, 0x5581) for identifier in records
            ):
                return 1012
            return status
        if action == 1:
            status, _ = exchange(b"\xa6\x01")
            return status if status else exchange(b"\x14")[0]
        if action == 2:
            status, _ = exchange(b"\x10\x40")
            retain = status == 0
            return status
        if action == 3:
            status, _ = exchange(b"\x10\x61")
            retain = _u32(data, 4) == 0
            if _u32(data, 4) == 1:
                if status in (0, 5):
                    return check_final_dtcs()
                restore()
            return status
        if action == 4:
            return check_final_dtcs()
        restore()
        return 1011
    except BaseException:
        retain = False
        raise
    finally:
        if not retain:
            _finalize(comm)


def _at02(data: bytearray, comm: TYComm, context: TYContext) -> int:
    action, retain = _u32(data), False

    def read(
        identifier: int, width: int = 1, manager: TYComm = comm
    ) -> tuple[int, bytes]:
        status, reply = _exchange(
            manager,
            context,
            b"\x22" + identifier.to_bytes(2, "big"),
            3 + width,
            2,
            publish_nrc=False,
        )
        return status, reply[3 : 3 + width]

    def control(payload: bytes) -> int:
        return _exchange(
            comm, context, b"\x2f\x16\x21" + payload, 4, 3, publish_nrc=False
        )[0]

    def status_read() -> int:
        status, value = read(0x11FA)
        if not status:
            if not value[0]:
                return 2002
            if value[0] == 0xFF:
                return 0
            status = 2003
        if status != 2002:
            _restore(comm, context)
        return status

    def pressure_control() -> int:
        status = control(b"\x03\xff")
        if status:
            result = (
                2004 if status == 7 and comm.read_field("native_10b0") == 0x69 else 2005
            )
            if result == 2004:
                control(b"\x00")
            if _u32(data, 0x34) == 1 or result:
                _restore(comm, context)
            return result
        status = control(b"\x02")
        if not status:
            started = context.ticks()
            _put(data, 0x3C, 1)
            while _u32(data, 0x34) != 1:
                _check(context)
                if (context.ticks() - started) & 0xFFFFFFFF >= 400:
                    status = control(b"\x02")
                    if status:
                        break
                    started = context.ticks()
                if _u32(data, 0x38) == 1:
                    status, value = read(0x10D2)
                    if status:
                        result = 2009
                        control(b"\x00")
                        _restore(comm, context)
                        return result
                    data[4] = value[0]
                    if data[6] < value[0]:
                        control(b"\x00")
                        _restore(comm, context)
                        return 2008
                    data[9] = 1 if value[0] < data[7] else 2
            if not status:
                result = control(b"\x00")
                if _u32(data, 0x34) == 1 or result:
                    _restore(comm, context)
                return result
        result = (
            2004 if status == 7 and comm.read_field("native_10b0") == 0x69 else 2005
        )
        control(b"\x00")
        _restore(comm, context)
        return result

    try:
        if action in (0, 1):
            status = _initialize(comm, context)
            if status:
                retain = True
                return status
        if action == 0:
            data[12:52] = bytes(40)
            bitmap = bytearray(512)
            status = _support_bitmap(comm, context, 0x1624, bitmap)
            if status:
                return status
            identifiers = (
                0x10D2,
                0x11F6,
                0x11FA,
                0x1204,
                0x1205,
                0x1219,
                0x121E,
                0x1622,
                0x1623,
                0x1624,
            )
            flags = tuple(
                int(_supported(bitmap, identifier)) for identifier in identifiers
            )
            for index, flag in enumerate(flags):
                _put(data, 12 + index * 4, flag)
            return 0 if all(flags) else 3
        if action == 1:
            status = comm.session(3, 1, normal_first=True)
            if status:
                retain = status == 2000
                return status
            values = []
            for identifier in (0x10D2, 0x1622, 0x1623, 0x1624):
                status, value = read(identifier)
                if status:
                    if status == 2000:
                        retain = True
                        return status
                    _restore(comm, context)
                    return status
                values.append(value[0])
                if len(values) == 1:
                    data[4] = value[0]
            if values[1] != 0xFF:
                retain = True
                return 2000
            data[5:8] = bytes(values[1:])
            if values[0] < values[3]:
                retain = True
                return 0
            _restore(comm, context)
            return 2001
        if action == 2:
            other = context.comm(
                "native:1011c400"
                if context.module_sha256 == SHA_18_TY
                else "native:10135c58"
            )
            other.configure_target(0x7A2)
            status = other.initialize()
            if not status:
                try:
                    for field, value in (
                        ("native_1080", 0),
                        ("native_1084", 180000),
                        ("native_1064", 0),
                    ):
                        other.configure(field, value)
                    started: int | None = None
                    while True:
                        status, value = read(0xF40C, 2, other)
                        if status:
                            break
                        if int.from_bytes(value, "big") < 0x899:
                            started = None
                        elif started is None:
                            started = context.ticks()
                        elif (context.ticks() - started) & 0xFFFFFFFF >= 1000:
                            break
                finally:
                    _finalize(other)
            if status:
                _restore(comm, context)
                return status
            status = status_read()
            retain = status in (0, 2002)
            return status
        if action == 3:
            status = status_read()
            retain = status in (0, 2002)
            return status
        if action in (5, 6):
            _restore(comm, context)
            return 2011 if action == 5 else 2010
        if action != 4:
            retain = True
            return 0
        index = data[8]
        identifiers = (0x1205, 0x121E, 0x1204, 0x11F6, 0x1204, 0x121E, 0x1205, 0x1219)
        if index >= len(identifiers):
            raw_identifier = context.state.get("native_stack:MS2AT02:selector_did")
            if type(raw_identifier) is not int or not 0 <= raw_identifier <= 0xFFFF:
                raise TYSourceError(
                    "MS2AT out-of-range selector requires native stack uint16 DID"
                )
            identifier = raw_identifier
        else:
            identifier = identifiers[index]
        started = None
        while True:
            status, value = read(identifier)
            if status:
                _restore(comm, context)
                return status
            if value[0] != 0xFF:
                started = None
            elif started is None:
                started = context.ticks()
            elif (context.ticks() - started) & 0xFFFFFFFF >= 1000:
                break
        if index < 7:
            retain = True
            return 0
        status, value = read(0x10D2)
        if status:
            _restore(comm, context)
            return status
        data[4] = value[0]
        if value[0] >= data[7]:
            _restore(comm, context)
            return 2001
        status = pressure_control()
        retain = status == 0
        return status
    except BaseException:
        retain = False
        raise
    finally:
        if not retain:
            _finalize(comm)


def _dcm01(data: bytearray, comm: TYComm, context: TYContext) -> int:
    action = _u32(data, 16)
    retain = False

    def mapped(status: int, replacement: int) -> int:
        return (
            replacement
            if status == 7 and comm.read_field("native_10b0") == 0x69
            else status
        )

    try:
        if action in (0, 1):
            status = _initialize(comm, context)
            if status:
                retain = True
                return status
        if action == 0:
            data[0:2] = bytes(2)
            bitmap = bytearray(12)
            status = _support_bitmap(comm, context, 0x104C, bitmap)
            if status:
                return status
            flags = sum(0x8000 >> i for i in range(8) if _supported(bitmap, 0x1045 + i))
            data[0:2] = flags.to_bytes(2, "little")
            return 0 if flags & 0xE000 and flags & 0x1F00 else 22
        if action == 1:
            _restore(comm, context)
            status = mapped(comm.session(3, 1), 2000)
            retain = status == 0
            return status
        if action in (2, 3, 4):
            retain = True
            return mapped(
                _io_control(comm, context, 0x1043 + action, 3, bytes([data[11]])), 2000
            )
        if action == 7:
            retain = True
            if int.from_bytes(data[:2], "little") & 0x2000:
                _io_control(comm, context, 0x1047, 0)
            return 0
        if action == 6:
            retain = True
            mask = int.from_bytes(data[:2], "little")
            data[8:11] = b"\xff" * 3
            data[4:8] = bytes.fromhex("ff0fff0f")
            data[2:4] = bytes(2)
            while not data[12]:
                _check(context)
                for _ in range(5):
                    context.native_sleep(100)
                    _check(context)
                    if data[12]:
                        break
                if data[12]:
                    data[2:4] = bytes(2)
                    break
                flags = 0
                for bit, identifier, minimum, offset, width, outputflag in (
                    (0x1000, 0x1048, 4, 8, 1, 0x8000),
                    (0x800, 0x1049, 5, 4, 2, 0x4000),
                    (0x400, 0x104A, 5, 6, 2, 0x2000),
                    (0x200, 0x104B, 4, 9, 1, 0x1000),
                    (0x100, 0x104C, 4, 10, 1, 0x800),
                ):
                    if mask & bit:
                        status, reply = _read(comm, context, identifier, minimum)
                        if not status:
                            flags |= outputflag
                            value = int.from_bytes(reply[3 : 3 + width], "big")
                            data[offset : offset + width] = value.to_bytes(
                                width, "little"
                            )
                data[2:4] = flags.to_bytes(2, "little")
                if not flags:
                    return 3
                data[2:4] = bytes(2)
            return 2002 if data[12] & 0x80 else 2004
        mask = int.from_bytes(data[:2], "little")
        for index in range(3):
            if mask & (0x8000 >> index):
                _io_control(comm, context, 0x1045 + index, 0)
        while True:
            _check(context)
            values = []
            for index in range(3):
                if not mask & (0x8000 >> index):
                    values.append(0)
                    continue
                status, reply = _read(comm, context, 0x1045 + index, 4)
                if status:
                    status = mapped(status, 2001)
                    _restore(comm, context)
                    return status
                values.append(reply[3])
            if not any(values):
                return mapped(_restore(comm, context), 2001)
    except BaseException:
        retain = False
        raise
    finally:
        if not retain:
            _finalize(comm)


def _dcm02(data: bytearray, comm: TYComm, context: TYContext) -> int:
    try:
        status = _initialize(comm, context)
        if status:
            return status
        action = _u32(data)
        if action == 0:
            return _support(comm, context, 0x10E5, (0x1032, 0x10E5), 22)
        if action == 1:
            status, reply = _read(comm, context, 0x1032, 4)
            if not status:
                data[5] = reply[3]
            return status
        if action != 2:
            return 0
        _restore(comm, context)
        status = comm.session(3, 1)
        if status:
            return status
        status, _ = _exchange(comm, context, b"\x2e\x10\xe5" + data[4:5], 3, 2, True)
        if status:
            status = 2000
        else:
            status, reply = _read(comm, context, 0x1032, 4)
            if status:
                status = 2001
            else:
                data[5] = reply[3]
        _restore(comm, context)
        return status
    finally:
        _finalize(comm)


def _secondary(context: TYContext) -> TYComm:
    return context.comm(
        "native:1011a220" if context.module_sha256 == SHA_18_TY else "native:1013d6a8"
    )


_ABS04_KEYS = {
    SHA_18_TY: tuple((rva, 1) for rva in range(0xA60CD, 0xA6119, 5)),
    SHA_PLUS_TY: ((0xAADCA, 4), (0xAADD4, 4), (0xAADDB, 4), (0xAADE2, 4)),
}


def _abs04(data: bytearray, comm: TYComm, context: TYContext) -> int:
    other = _secondary(context)
    status, retain = 0, False
    try:
        action = _u32(data)
        if action == 4:
            _restore(comm, context)
            return 0
        status = _initialize(comm, context)
        if status:
            return status
        other.configure_target(0x763)
        status = _initialize(other, context)
        if status:
            return status
        if action == 0:
            status = _support(comm, context, 0x250, (0x250,), 22)
            # Both native support calls execute before either support-bit check.
            if status not in (0, 22):
                return status
            second = _support(comm, context, 0x1086, (0x1086,), 22)
            return second or status
        if action == 1:
            status, reply = _read(comm, context, 0x1086, 4)
            if not status:
                result = reply[3]
                status = 0 if result == 0 else 2000 if 1 <= result <= 10 else 99
            return status
        if action == 2:
            status = comm.session(3, 1, normal_first=True)
            if status:
                return status
            status, _ = _read(comm, context, 0x250, 4)
            if not status:
                key = security.source_immediate_key(
                    context, _ABS04_KEYS[context.module_sha256]
                )
                status = security.security_access(
                    context,
                    cast(security.SecurityComm, comm),
                    level=1,
                    key=key,
                    preliminary_comm=cast(security.SecurityComm, other),
                    expected_capability=2,
                )
                if status:
                    retain = True
                    return 2002
            status = comm.session(0x40, 1)
            if status:
                retain = True
                return 2001
            return 0
        if action == 3:
            return _restore(comm, context)
        return 0
    finally:
        if not retain:
            _finalize(comm, other)


_AT01_KEYS = {
    SHA_18_TY: tuple((rva, 1) for rva in range(0xA63EE, 0xA643A, 5)),
    SHA_PLUS_TY: ((0xAB4EA, 4), (0xAB4F1, 4), (0xAB4F8, 4), (0xAB4FF, 4)),
}


def _at01(data: bytearray, comm: TYComm, context: TYContext) -> int:
    other = _secondary(context)
    retain = False
    try:
        action = _u32(data)
        if action == 0:
            if _initialize(comm, context):
                return 2000
            other.configure_target(0x763)
            if _initialize(other, context):
                return 2000
            if comm.session(3, 1, normal_first=True):
                return 2000
            key = security.source_immediate_key(
                context, _AT01_KEYS[context.module_sha256]
            )
            status = security.security_access(
                context,
                cast(security.SecurityComm, comm),
                level=3,
                key=key,
                preliminary_comm=cast(security.SecurityComm, other),
                expected_capability=0xC2,
            )
            if status:
                retain = True
                return 2001
        if action not in (0, 1):
            if action == 2:
                _restore(comm, context)
            else:
                retain = True
            return 0
        status, _ = _exchange(
            comm, context, bytes.fromhex("3101ff000001"), 4, 3, publish_nrc=False
        )
        if status:
            retain = True
            return 2002
        while True:
            status, reply = _exchange(
                comm, context, bytes.fromhex("3103ff00"), 6, 3, publish_nrc=False
            )
            if status or reply[4] != 0:
                retain = True
                return 2002
            if reply[5] == 1:
                continue
            if reply[5] != 2:
                retain = True
                return 2002
            status = _restore(comm, context)
            retain = status != 0
            return 2000 if status else 0
    finally:
        if not retain:
            _finalize(comm, other)


def _rab02(
    data: bytearray, identifier: int | None, comm: TYComm, context: TYContext
) -> int:
    try:
        status = _initialize(comm, context)
        if status:
            return status
        control = 0x7F4 if context.module_sha256 == SHA_18_TY else 0x9FC
        action = _u32(data, control)
        if action == 0:
            return _support(comm, context, 0x10B0, (0x101E, *range(0x10A7, 0x10B1)), 22)
        if action == 1:
            status, reply = _read(comm, context, 0x101E, 5)
            if status:
                return status
            _put(data, 4, int.from_bytes(reply[3:5], "big"))
            request = bytes.fromhex("2210a710a810a910aa10ab")
            status, reply = _exchange(comm, context, request, 21, 0, publish_nrc=False)
            if status:
                return status
            if any(
                reply[1 + i * 4 : 3 + i * 4] != request[1 + i * 2 : 3 + i * 2]
                for i in range(5)
            ):
                return 3
            for index in range(5):
                _put(
                    data,
                    8 + index * 4,
                    int.from_bytes(reply[3 + index * 4 : 5 + index * 4], "big"),
                )
            return 0 if any(_u32(data, 8 + i * 4) for i in range(5)) else 1004
        if identifier is None:
            raise ValueError(
                "MS2RAB block read requires the selected native metadata record"
            )
        status, reply = _read(comm, context, identifier & 0xFFFF, 0x5CE)
        if not status:
            # Native copies1486bytes from zeroed receive buffer offset3, not length-3.
            data[28 : 28 + 0x5CE] = reply[3 : 3 + 0x5CE].ljust(0x5CE, b"\0")
        return status
    finally:
        _finalize(comm)


def _efi03_result(comm: TYComm, context: TYContext, result: int) -> int:
    mapped = {0x10: 1011, 0x3010: 1010, 0x3011: 1012}
    if result in mapped:
        return mapped[result]
    if result == 2:
        status, _ = _routine(comm, context, 0x8011, 2)
        if not status:
            return 9905 if _restore(comm, context) else 0
    _restore(comm, context)
    return 3


def _efi03(data: bytearray, comm: TYComm, context: TYContext) -> int:
    action, retain = _u32(data, 4), False
    try:
        if action in (0, 1, 2):
            status = _initialize(comm, context)
            if status:
                return status
        if action == 0:
            return _support(comm, context, 0x13D8, (0x13D8,))
        if action == 1:
            status, reply = _read(comm, context, 0x13D8, 4)
            if status:
                return status
            value = reply[3]
            return (
                1001
                if value == 0
                else 0
                if value in (1, 2, 3, 4)
                else 1004
                if value == 5
                else 3
            )
        if action == 2:
            if comm.session(3, 1, normal_first=True):
                return 1014
            status, _ = _routine(comm, context, 0x8011, 1)
            if status:
                _restore(comm, context)
                return 1014
            status, reply = _routine(comm, context, 0x8011, 3, 6)
            if status:
                _restore(comm, context)
                return 3
            result = int.from_bytes(reply[4:6], "big")
            if result in (0, 1):
                retain = True
                return 1007
            status = _efi03_result(comm, context, result)
            retain = status in (1010, 1011, 1012)
            return status
        if action == 3:
            while True:
                context.native_sleep(1)
                status, reply = _routine(comm, context, 0x8011, 3, 6)
                if status:
                    _restore(comm, context)
                    return 3
                result = int.from_bytes(reply[4:6], "big")
                if result not in (0, 1) or _u32(data) != 0:
                    break
            if _u32(data) == 1:
                retain = True
                return 1005
            status = _efi03_result(comm, context, result)
            retain = status in (1010, 1011, 1012)
            return status
        if action == 4:
            status, _ = _routine(comm, context, 0x8011, 2)
            restore = _restore(comm, context)
            return 3 if status else 9905 if restore else 1005
        if action == 5:
            _routine(comm, context, 0x8011, 2)
            _restore(comm, context)
            return 1005
        return 0
    finally:
        if not retain:
            _finalize(comm)


_EFI05_KEYS = {
    SHA_18_TY: tuple(
        (rva, 1)
        for rva in (
            0xA8D05,
            0xA8D37,
            0xA8D3C,
            0xA8D05,
            0xA8D41,
            0xA8D46,
            0xA8D16,
            0xA8D16,
            0xA8D4B,
            0xA8D50,
            0xA8D55,
            0xA8D5A,
            0xA8D5F,
            0xA8D64,
            0xA8D69,
            0xA8D6E,
        )
    ),
    SHA_PLUS_TY: ((0xADFBE, 4), (0xADFC8, 4), (0xADFCF, 4), (0xADFD6, 4)),
}


def _efi_records(data: bytearray) -> tuple[int, ...]:
    result = []
    offset = 0x84
    while offset + 4 <= len(data):
        if _u32(data, offset) == 0:
            return tuple(result)
        if offset + 12 > len(data):
            break
        result.append(offset)
        offset += 12
    raise ValueError("MS2EFI native record list lacks its terminating zero DID")


def _efi05(
    data: bytearray, records: tuple[int, ...], comm: TYComm, context: TYContext
) -> int:
    other, retain = _secondary(context), False
    action = _u32(data)
    try:
        if action in (0, 1):
            _check(context)
            status = comm.initialize()
            if status:
                return status
            other.configure_target(0x763)
            status = other.initialize()
            if status:
                return status
            for connection in (comm, other):
                connection.configure("native_1080", 0)
                connection.configure("native_1084", 180000)
                connection.configure("native_1064", 0)
        if action == 0:
            bitmap = bytearray(data[4:132])
            status = _support_bitmap(comm, context, 0x13E5, bitmap)
            data[4:132] = bitmap
            if status:
                return status
            identifiers = tuple(pid for pid, _ in _EFI04_ROWS)
            if not any(_supported(bitmap, pid) for pid in identifiers):
                return 3
            selected = {_u32(data, offset) for offset in records}
            return (
                0
                if all(
                    (pid in selected) == _supported(bitmap, pid) for pid in identifiers
                )
                else 3000
            )
        if action == 1:
            if comm.session(3, 1, normal_first=True):
                return 3
            key = security.source_immediate_key(
                context, _EFI05_KEYS[context.module_sha256]
            )
            status = security.security_access(
                context,
                cast(security.SecurityComm, comm),
                level=3,
                key=key,
                preliminary_comm=cast(security.SecurityComm, other),
                expected_capability=2,
            )
            if status:
                _restore(comm, context)
            else:
                retain = True
            return status
        if action == 2:
            for offset in records:
                identifier, width, value = (
                    _u32(data, offset),
                    data[offset + 4],
                    _u32(data, offset + 8),
                )
                if width not in (1, 2, 3):
                    retain = True
                    return 4000
                payload = value.to_bytes(4, "big")[-width:]
                request = b"\x2e" + (identifier & 0xFFFF).to_bytes(2, "big") + payload
                status, _ = _exchange(comm, context, request, 3, 2, publish_nrc=False)
                if status:
                    retain = True
                    return 4000
            retain = True
            return 0
        _restore(comm, context)
        return 1000 if action == 3 else 5000 if action == 4 else 0
    finally:
        if not retain:
            _finalize(comm, other)


_EFI06_KEYS = {
    SHA_18_TY: tuple(
        (rva, 1)
        for rva in (
            0xA9263,
            0xA9294,
            0xA9299,
            0xA9263,
            0xA929E,
            0xA92A3,
            0xA9274,
            0xA9274,
            0xA92A8,
            0xA92AD,
            0xA92B2,
            0xA92B7,
            0xA92BC,
            0xA92C1,
            0xA92C6,
            0xA92CB,
        )
    ),
    SHA_PLUS_TY: ((0xAE81E, 4), (0xAE828, 4), (0xAE82F, 4), (0xAE836, 4)),
}


def _efi06(data: bytearray, comm: TYComm, context: TYContext) -> int:
    other, retain = _secondary(context), False
    action = _u32(data)
    try:
        status = cast(MS2Comm, comm).select_diagnostic_mode(1)
        if status:
            return status
        if action == 4:
            _wire_session(comm, context, 1)
            return 1001
        if action == 1 or action > 4:
            status = cast(MS2Comm, comm).select_diagnostic_mode(3)
            if status:
                return status
            target = 0x7DF
        elif action in (2, 3):
            target = 0x7A2
        else:
            global_key = "native_global:" + (
                "1011f700" if context.module_sha256 == SHA_18_TY else "1013fa38"
            )
            target = context.state.get(global_key)
            if type(target) is not int or not 0 <= target <= 0xFFFFFFFF:
                raise TYSourceError(
                    "MS2EFI06 requires the exact source-selected target global"
                )
        comm.configure_target(cast(int, target))
        status = comm.initialize()
        if status:
            return status
        other.configure_target(0x763)
        status = other.initialize()
        if status:
            return status
        for connection in (comm, other):
            connection.configure("native_1080", 0)
            connection.configure("native_1084", 180000)
            connection.configure("native_1064", 0)
        if action == 0:
            return _support(comm, context, 0x228, (0x228,))
        if action == 2:
            status, reply = _read(comm, context, 0x228, 4, True)
            if not status:
                data[4] = reply[3] & 0x60
            return status
        if action == 3:
            timeout_field = (
                "native_rva:1a890"
                if context.module_sha256 == SHA_18_TY
                else "native_rva:1e280"
            )
            _wire_session(comm, context, 1)
            comm.configure(timeout_field, 2500)
            status, _ = _wire_session(comm, context, 3)
            comm.configure(timeout_field, 1020)
            if status:
                return 1009
            key = security.source_immediate_key(
                context, _EFI06_KEYS[context.module_sha256]
            )
            status = security.security_access(
                context,
                cast(security.SecurityComm, comm),
                level=3,
                key=key,
                preliminary_comm=cast(security.SecurityComm, other),
                expected_capability=2,
            )
            if status:
                retain = True
                return 1013
            comm.configure(timeout_field, 100)
            status, _ = _exchange(
                comm, context, b"\x2e\xf1\x90" + data[6:23], 3, 2, True
            )
            comm.configure(timeout_field, 1020)
            _wire_session(comm, context, 1)
            return 9909 if status else 0
        status, _ = _exchange(comm, context, b"\x01\x00", 2, 1, True)
        if status:
            return status
        if action == 1:
            status, reply = _exchange(comm, context, b"\x09\x00", 6, 1, True)
            if status:
                return status
            if not reply[2] & 0x40:
                return 3
        status, reply = _exchange(comm, context, b"\x09\x02", 20, 1, True)
        if status:
            return status
        previous = bytes(data[6:23])
        data[6:24] = reply[3:20] + b"\0"
        if action == 1:
            return 0
        if previous == data[6:23]:
            return 1011
        data[5] = (data[5] + 1) & 0xFF
        return 1003 if data[5] < 3 else 1010
    finally:
        if not retain:
            _finalize(comm, other)


_SAS03_KEYS = {
    SHA_18_TY: ((0xAD3D6, 1),) + tuple((rva, 1) for rva in range(0xAD3DD, 0xAD424, 5)),
    SHA_PLUS_TY: ((0xB2E83, 4), (0xB2E8A, 4), (0xB2E91, 4), (0xB2E98, 4)),
}


def _sas03_dtcs(data: bytearray, comm: TYComm, context: TYContext) -> tuple[int, bytes]:
    _wire_session(comm, context, 1)
    status, _ = _wire_session(comm, context, 3)
    reply = b""
    if not status:
        status, reply = _exchange(
            comm, context, bytes.fromhex("190202"), 3, 0, publish_nrc=False
        )
        if not status:
            if len(reply) > 0x1020:
                raise TYSourceError("MS2SAS DTC reply exceeds native receive span")
            data[: len(reply)] = reply
    _wire_session(comm, context, 1)
    return status, reply


def _sas03_routine(data: bytearray, comm: TYComm, context: TYContext) -> int:
    result, repeats = 0, 0
    while True:
        status, _ = _routine(comm, context, 0x3300, 1)
        if status:
            _wire_session(comm, context, 1)
            _put(data, 0x1020, result)
            return 1022
        while True:
            status, reply = _routine(comm, context, 0x3300, 3)
            if status:
                _wire_session(comm, context, 1)
                _put(data, 0x1020, result)
                return 1022
            result = int.from_bytes(reply[4:6].ljust(2, b"\0"), "big")
            if result != 1:
                break
        if result == 0x20:
            repeats += 1
            if repeats <= 3:
                continue
        status, _ = _wire_session(comm, context, 1)
        _put(data, 0x1020, result)
        return status if result == 2 else 1023


def _sas03_measure(data: bytearray, raw: int, context: TYContext) -> int:
    from scripts.utility_ex_ty_retained_07 import _binary

    plus = context.module_sha256 == SHA_PLUS_TY
    word = context.state.get("host:mxcsr" if plus else "host:x87_control_word")
    if type(word) is not int or not 0 <= word <= 0xFFFF:
        raise TYSourceError(
            "MS2SAS measurement requires explicit native floating-point control state"
        )
    rounding = (word >> (13 if plus else 10)) & 3
    precision = 53 if plus else {0: 24, 2: 53, 3: 64}.get((word >> 8) & 3)
    if precision is None or not word & (0x1000 if plus else 0x20):
        raise TYSourceError(
            "MS2SAS floating-point precision/inexact exception mode is unsupported"
        )

    def rounded(value: Fraction | float) -> Fraction:
        return _binary(Fraction(value), precision, rounding)

    observed = rounded(Fraction(raw) * Fraction.from_float(0.001))
    stored = _binary(observed, 53, rounding)
    struct.pack_into("<d", data, 0x1028, float(stored))
    expected = struct.unpack_from("<d", data, 0x1030)[0]
    if not math.isfinite(expected):
        if not word & (0x80 if plus else 1):
            raise TYSourceError("MS2SAS unmasked invalid floating-point exception")
        return 1014 if plus else 0
    converted = Fraction.from_float(expected)
    if _u32(data, 0x1024) == 2:
        converted = (
            rounded(converted / Fraction.from_float(2.205))
            if plus
            else rounded(converted * Fraction.from_float(0.4535147392290249))
        )
        comparison = rounded(converted + Fraction.from_float(2.220446049250313e-16))
        converted = rounded(
            converted + (1 if comparison >= 0 else -1) * Fraction.from_float(0.0005)
        )
    difference = rounded(rounded(observed - converted) * 1000)
    integer = int(difference)
    if plus:
        integer = integer if -(1 << 31) <= integer < (1 << 31) else -(1 << 31)
    else:
        # Native imported _ftol returnsEDX:EAX; only the lowDWORD is compared.
        integer = integer if -(1 << 63) <= integer < (1 << 63) else -(1 << 63)
        integer = ((integer + (1 << 31)) & 0xFFFFFFFF) - (1 << 31)
    return 0 if -2500 <= integer <= 2500 else 1014


def _sas03(data: bytearray, comm: TYComm, context: TYContext) -> int:
    other = _secondary(context)
    try:
        status = _initialize(comm, context)
        if status:
            return status
        other.configure_target(0x763)
        status = _initialize(other, context)
        if status:
            return status
        action = _u32(data, 0x1038)
        if action not in (1, 2, 3):
            return _support(comm, context, 0x1054, (0x1054,), 22)
        if action == 3:
            status, reply = _read(comm, context, 0x1054, 7, True)
            return (
                1021
                if status
                else _sas03_measure(
                    data, int.from_bytes(reply[3:7], "big", signed=True), context
                )
            )
        data[:0x101D] = bytes(0x101D)
        status, reply = _sas03_dtcs(data, comm, context)
        if status:
            return status
        prefixes = tuple(
            int.from_bytes(reply[i : i + 2], "big") for i in range(3, len(reply) - 3, 4)
        )
        if action == 1:
            return 1018 if any(prefix in (0x978C, 0x9796) for prefix in prefixes) else 0
        if any(
            prefix not in (0x978C, 0x9796, 0x9783, 0x9784, 0x9785, 0x9786)
            for prefix in prefixes
        ):
            return 1019
        status = comm.session(3, 1, normal_first=True)
        if status:
            return status
        key = security.source_immediate_key(context, _SAS03_KEYS[context.module_sha256])
        status = security.security_access(
            context,
            cast(security.SecurityComm, comm),
            level=3,
            key=key,
            preliminary_comm=cast(security.SecurityComm, other),
            expected_capability=2,
            direction=2,
        )
        if status:
            _wire_session(comm, context, 1)
            return status
        return _sas03_routine(data, comm, context)
    finally:
        _finalize(comm, other)


_IG01_KEYS = {
    SHA_18_TY: (
        tuple((rva, 1) for rva in range(0xAB5D6, 0xAB626, 5)),
        tuple((rva, 1) for rva in range(0xAB716, 0xAB766, 5)),
    ),
    SHA_PLUS_TY: (
        ((0xB1002, 4), (0xB100C, 4), (0xB1013, 4), (0xB101A, 4)),
        ((0xB0DD2, 4), (0xB0DDC, 4), (0xB0DE3, 4), (0xB0DEA, 4)),
    ),
}


def _io_control(
    comm: TYComm,
    context: TYContext,
    identifier: int,
    control: int,
    payload: bytes = b"",
) -> int:
    request = (
        b"\x2f" + (identifier & 0xFFFF).to_bytes(2, "big") + bytes([control]) + payload
    )
    status, reply = _exchange(comm, context, request, 3, 0)
    if not status and reply.ljust(4, b"\0")[1:4] != request[1:4]:
        return 3
    return status


def _ig01(
    data: bytearray, identifier: int | None, comm: TYComm, context: TYContext
) -> int:
    other, retain = _secondary(context), False
    action = _u32(data, 40)
    try:
        if action in (0, 1):
            status = comm.initialize()
            if status:
                return status
            other.configure_target(0x763)
            status = other.initialize()
            if status:
                return status
            for connection in (comm, other):
                connection.configure("native_1080", 0)
                connection.configure("native_1084", 180000)
                connection.configure("native_1064", 0)
        if action in (0, 1):
            status = comm.session(3, 1, normal_first=True)
            if status:
                return status if action == 0 else 1002
            key = security.source_immediate_key(
                context, _IG01_KEYS[context.module_sha256][action]
            )
            status = security.security_access(
                context,
                cast(security.SecurityComm, comm),
                level=3,
                key=key,
                preliminary_comm=cast(security.SecurityComm, other),
                expected_capability=2,
            )
            if action == 0:
                if not status:
                    bitmap = bytearray(12)
                    status = _support_bitmap(comm, context, 0x3042, bitmap, 0x3000)
                    if not status:
                        if any(
                            _supported(bitmap, pid)
                            for pid in (0x3022, 0x302B, 0x302E, 0x3030, 0x3042)
                        ):
                            if context.module_sha256 == SHA_18_TY:
                                data[:32] = (
                                    bitmap + key + (0x3022).to_bytes(4, "little")
                                )
                            else:
                                residual = context.state.get(
                                    "native_stack:100b0fc0:uninitialized_1c"
                                )
                                if type(residual) is not bytes or len(residual) != 4:
                                    raise TYSourceError(
                                        "Plus MS2IG native stack DWORD requires an explicit residual-byte observation"
                                    )
                                data[:32] = bitmap + residual + key
                        else:
                            status = 22
                restored = _restore(comm, context)
                return status or restored
            if status:
                _restore(comm, context)
                return 1001
            assert identifier is not None
            status = _io_control(comm, context, identifier, 3, b"\0\x01")
            if not status:
                retain = True
                return 0
            _restore(comm, context)
            return status
        if action == 2:
            assert identifier is not None
            started = context.ticks()
            while True:
                context.native_sleep(200)
                _check(context)
                now = context.ticks()
                if ((started + 3000) & 0xFFFFFFFF) < now:
                    status = _io_control(comm, context, identifier, 2)
                    if status:
                        _restore(comm, context)
                        return status
                    started = context.ticks()
                if _u32(data, 36) != 0:
                    retain = True
                    return 0
        if action == 3:
            assert identifier is not None
            status = _io_control(comm, context, identifier, 0)
            _restore(comm, context)
            return status
        return 0
    finally:
        if not retain:
            _finalize(comm, other)


def _efi02(comm: TYComm, context: TYContext) -> int:
    try:
        status = _initialize(comm, context)
        if status:
            return status
        status = comm.session(3, 1, normal_first=True)
        if status:
            return status
        status, _ = _exchange(
            comm, context, bytes.fromhex("31018010"), 4, 3, publish_nrc=False
        )
        if not status:
            while True:
                status, reply = _exchange(
                    comm, context, bytes.fromhex("31038010"), 6, 3
                )
                if status:
                    break
                result = int.from_bytes(reply[4:6], "big")
                if result in (0, 1):
                    continue
                status = 0 if result == 2 else 1000 if result == 16 else 3
                break
        restore = _restore(comm, context)
        return restore or status
    finally:
        _finalize(comm)


def _pwd(export: str, data: bytearray, comm: TYComm, context: TYContext) -> int:
    action = _u32(data)
    retain = False
    try:
        if action == 0:
            status = _initialize(comm, context)
            if status:
                return status
            if comm.session(3, 1, normal_first=True):
                return 1001
        if action not in (0, 1):
            _restore(comm, context)
            return 1003
        payload = b"\0\0" if "_01_" in export else b"\0\x02"
        status, _ = _routine(comm, context, 0xFF00, 1, payload=payload)
        if status:
            retain = True
            return 1002
        while True:
            status, reply = _routine(comm, context, 0xFF00, 3, 6)
            if status:
                if status in (5, 7):
                    retain = True
                    return 1002
                _restore(comm, context)
                return 1001
            result = int.from_bytes(reply[4:6], "big")
            if result == 1:
                continue
            restore = _restore(comm, context)
            return 1001 if result != 2 or restore else 0
    finally:
        if not retain:
            _finalize(comm)


def _wire_session(comm: TYComm, context: TYContext, mode: int) -> tuple[int, bytes]:
    _check(context)
    request = bytes((0x10, mode))
    status, reply = comm.exchange(request)
    if status in (2, 7):
        context.native_sleep(0)
        if status == 7:
            key = "native_global:" + (
                "1012ae38" if context.module_sha256 == SHA_18_TY else "10153554"
            )
            context.state[key] = reply[2] if len(reply) > 2 else 0
    if not status:
        if mode == 3:
            started = cast(MS2Comm, comm).keepalive(True, wait=True)
            if type(started) is not int:
                raise TYSourceError(
                    "MS2 session worker did not publish a native status"
                )
            status = started
            if status:
                return status, reply
        if len(reply) < 6 or reply[1] != mode:
            status = 3
    return status, reply


def _gwy(data: bytearray, comm: TYComm, context: TYContext) -> int:
    action = _u32(data)
    retain = False
    try:
        if action != 3:
            status = _initialize(comm, context, 4)
            if status:
                return status
        if action == 0:
            return _support(comm, context, 0x103B, (0x103B,), 22)
        if action == 1:
            status, reply = _read(comm, context, 0x103B, 4)
            if not status:
                _put(data, 4, reply[3])
                return 1000
        elif action == 2:
            status, reply = _wire_session(comm, context, 1)
            if not status:
                status, reply = _wire_session(comm, context, 3)
                if not status:
                    status, reply = _routine(comm, context, 0x20C, 1)
                    if not status:
                        retain = True
                        return 2000
                    _wire_session(comm, context, 1)
        else:
            context.native_sleep(5000)
            _wire_session(comm, context, 1)
            return 3000
        if status == 7:
            # The source getter reads the shared helper global after recovery.
            key = "native_global:" + (
                "1012ae38" if context.module_sha256 == SHA_18_TY else "10153554"
            )
            _put(data, 8, cast(int, context.state.get(key, 0)))
        elif status == 5:
            _put(data, 8, 0x78)
        return status
    finally:
        if not retain:
            _finalize(comm)


def run_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    if export not in supported_exports(context.module_sha256):
        raise TYSourceError("MS2 export has no reviewed body for selected source")
    if "MS2EYES_" in export:
        from scripts import utility_ex_ms2_eyes

        return utility_ex_ms2_eyes.invoke_export(export, context, *args)
    if export in ("Ex2MS2ABS_05_SendMessage", "Ex2MS2EFI_02_SendMessage"):
        if args:
            raise ValueError("MS2 operation takes no native arguments")
        _check(context)
        if export == "Ex2MS2EFI_02_SendMessage":
            return _efi02(_manager(context), context)
        return _abs(export, bytearray(4), _manager(context), context)
    if len(args) != 1:
        raise ValueError("MS2 export requires one native argument")
    if export.endswith("CheckPressureSensorValue"):
        value = args[0]
        if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
            raise ValueError("MS2 pressure sensor value must be int32")
        return int(0x7F8A < value < 0x11EF68)
    if "MS2EMPS" in export:
        data = args[0]
        if not isinstance(data, bytearray) or len(data) < 8:
            raise ValueError("MS2EMPS requires an eight-byte mutable native message")
        _check(context)
        return _emps(export, data, context)
    if export == "Ex2MS2TPW_01_SendMessage":
        data = args[0]
        if not isinstance(data, bytearray) or len(data) < 4:
            raise ValueError("MS2TPW requires a mutable native action buffer")
        action = _u32(data)
        minimum = 6 if action == 0 else 36 if action == 1 else 4
        if len(data) < minimum:
            raise ValueError(f"MS2TPW native action requires at least {minimum} bytes")
        _check(context)
        return _tpw(data, context)
    if export == "Ex2MS2RAB_02_SendMessage":
        argument = args[0]
        if isinstance(argument, MS2RAB02Message):
            if argument.module_sha256 != context.module_sha256:
                raise TYSourceError(
                    "MS2RAB selected metadata belongs to another source"
                )
            data, identifier = argument.data, argument.record_identifier
        else:
            data, identifier = argument, None
        minimum = 0x7F8 if context.module_sha256 == SHA_18_TY else 0xA00
        if not isinstance(data, bytearray) or len(data) < minimum:
            raise ValueError(f"MS2RAB native buffer requires at least {minimum} bytes")
        control = minimum - 4
        if _u32(data, control) > 1 and identifier is None:
            raise ValueError("MS2RAB block read requires selected native metadata")
        _check(context)
        return _rab02(data, identifier, _manager(context), context)
    if export == "Ex2MS2EFI_05_SendMessage":
        data = args[0]
        if not isinstance(data, bytearray) or len(data) < 4:
            raise ValueError("MS2EFI05 requires a mutable native buffer")
        records = _efi_records(data) if _u32(data) in (0, 2) else ()
        _check(context)
        return _efi05(data, records, _manager(context), context)
    if export == "Ex2MS2IG_01_SendMessage":
        argument = args[0]
        if isinstance(argument, MS2IG01Message):
            if argument.module_sha256 != context.module_sha256:
                raise TYSourceError("MS2IG selected record differs from module source")
            data, identifier = argument.data, argument.record_identifier
        else:
            data, identifier = argument, None
        if not isinstance(data, bytearray) or len(data) < 44:
            raise ValueError("MS2IG requires44native message bytes")
        if _u32(data, 40) in (1, 2, 3) and identifier is None:
            raise ValueError("MS2IG requires the selected native metadata record")
        _check(context)
        return _ig01(data, identifier, _manager(context), context)
    minimum = (
        0x103C
        if "MS2SAS_03" in export
        else (
            4
            if isinstance(args[0], bytearray)
            and len(args[0]) >= 4
            and _u32(args[0]) in (0, 4)
            else 24
        )
        if "MS2EFI_06" in export
        else 8
        if "MS2EFI_03" in export
        else 6
        if "MS2DCM_02" in export
        else 64
        if "MS2AT_02" in export
        else 20
        if "MS2DCM_01" in export
        else 0x21C
        if "MS2MET_02" in export
        else 0x18C
        if "MS2MET_01" in export
        else 72
        if "MS2SAS_01" in export
        else 23
        if "MS2SAS_02" in export
        else 100
        if "MS2BDY_01" in export
        else 36
        if "MS2RAB_01" in export
        else 0xE4
        if "MS2EFI_04" in export
        else 0x4094
        if "MS2EFI_01" in export
        else 12
        if "MS2ABS_01" in export or "MS2GWY" in export
        else 4
    )
    data = args[0]
    if not isinstance(data, bytearray) or len(data) < minimum:
        raise ValueError(
            f"MS2 operation requires a mutable native buffer of at least {minimum} bytes"
        )
    if "MS2BDY_01" in export and _u32(data) == 1 and data[98] >= len(_BDY_IDS):
        raise ValueError("MS2BDY selected DID index exceeds native table")
    if "MS2MET_01" in export and _u32(data, 0x188) == 0:
        count = _u32(data, 0x180)
        if count > 32 or any(
            _u32(data, i * 12) not in _MET01_IDS for i in range(min(count, 32))
        ):
            raise ValueError("MS2MET existing records do not match native table")
    _check(context)
    comm = _manager(context)
    if "MS2SAS_01" in export:
        return _sas01(data, comm, context)
    if "MS2MET_02" in export:
        selected, count = _u32(data, 0x204), _u32(data, 0x180)
        if (
            selected > 32
            or (count > 32 and not count & 0x80000000)
            or any(
                _u32(data, i * 12 + 8) > min(4125, len(data) - (i * 12 + 4))
                for i in range(0 if count & 0x80000000 else count)
            )
        ):
            raise ValueError("MS2MET selected records exceed native message spans")
        return _met02(data, comm, context)
    if "MS2SAS_03" in export:
        return _sas03(data, comm, context)
    if "MS2EFI_06" in export:
        return _efi06(data, comm, context)
    if "MS2EFI_03" in export:
        return _efi03(data, comm, context)
    if "MS2AT_02" in export:
        return _at02(data, comm, context)
    if "MS2AT_01" in export:
        return _at01(data, comm, context)
    if "MS2ABS_04" in export:
        return _abs04(data, comm, context)
    if "MS2DCM_01" in export:
        return _dcm01(data, comm, context)
    if "MS2DCM_02" in export:
        return _dcm02(data, comm, context)
    if "MS2MET_01" in export:
        return _met01(data, comm, context)
    if "MS2SAS_02" in export:
        return _sas02(data, comm, context)
    if "MS2BDY_01" in export:
        return _bdy(data, comm, context)
    if "MS2RAB_01" in export:
        return _rab01(data, comm, context)
    if "MS2EFI_04" in export:
        return _efi04(data, comm, context)
    if "MS2EFI_01" in export:
        return _efi01(data, comm, context)
    if "MS2PWD" in export:
        return _pwd(export, data, comm, context)
    if "MS2GWY" in export:
        return _gwy(data, comm, context)
    return _abs(export, data, comm, context)
