"""Exact-source RES, GS, LDR and PCM business bodies, without loading vendor code.

The common UtilityEx layer owns the exported wrapper, worker and timeout lifecycle.
"""

from __future__ import annotations

import hashlib
import struct
from fractions import Fraction

from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import (
    SHA_12_TY,
    SHA_18_TY,
    SHA_PLUS_TY,
    TYComm,
    TYContext,
    TYSourceError,
)

_SOURCES: tuple[str, ...] = (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY)
_PENDING: dict[str, str] = dict(
    zip(_SOURCES, ("native_rva:b940", "native_rva:12180", "native_rva:142f0"))
)
_SELECTED = (
    "Ex2RES_03_InitialRegistrationRequest",
    "Ex2RES_03_SupportCheck",
    "Ex2RES_04_RemoteStartRegistration",
    "Ex2RES_04_SupportCheck",
    "Ex2GS_01_CheckShutterStatus",
    "Ex2GS_01_ShiftMode",
    "Ex2GS_01_SupportCheck",
    "Ex2GS_02_SendMessage",
)


def supported_exports(module_sha256: str) -> tuple[str, ...]:
    """Only exact reviewed pairs; other retained families remain unavailable."""
    if module_sha256 not in _SOURCES:
        return ()
    return (
        *_SELECTED,
        "Ex2PCM_04_SendMessage",
        *((_SIL + _LDR) if module_sha256 != _SOURCES[0] else ()),
    )


def _u32(data: bytearray, offset: int = 0) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _put(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value)


def _check(context: TYContext) -> None:
    if context.is_cancelled():
        raise Cancelled("TY retained operation cancelled")


def _sleep(context: TYContext, ms: int) -> None:
    _check(context)
    context.native_sleep(ms)
    _check(context)


def _exchange(context: TYContext, comm: TYComm, request: bytes) -> tuple[int, bytes]:
    _check(context)
    return comm.exchange(request)


def _snapshot(
    context: TYContext, comm: TYComm, kind: int
) -> tuple[int, bytes, tuple[int, ...]]:
    _check(context)
    status, data, offsets = comm.support_snapshot(kind)
    if not status and (len(data) > 0x1020 or len(offsets) != 256):
        raise ValueError("Native support snapshot exceeds the 0x1020/256 buffers")
    return status, data, offsets


def _record(
    data: bytes, offsets: tuple[int, ...], identifier: int
) -> tuple[int, bytes]:
    offset = offsets[identifier]
    if offset == 0x1020:
        return 22, b""
    if offset < 0 or offset + 1 >= len(data):
        return 99, b""
    length = data[offset + 1]
    if offset + 1 + length > 0x1020 or offset + 2 + length > len(data):
        return 99, b""
    return 0, data[offset + 2 : offset + 2 + length]


def _mask(
    data: bytes, offsets: tuple[int, ...], identifier: int, position: int, mask: int
) -> int:
    status, record = _record(data, offsets, identifier)
    if status:
        return status
    index = position - 3
    if index < 0 or index >= len(record):
        return 22
    return 0 if record[index] and record[index] & mask == mask else 22


def _count(data: bytes, offsets: tuple[int, ...], identifier: int) -> tuple[int, int]:
    status, record = _record(data, offsets, identifier)
    if status:
        return status, 0
    count = sum(value != 0 for value in record)
    return (0 if count else 22), count


def _read(
    context: TYContext, comm: TYComm, identifier: int, count: int
) -> tuple[int, bytes]:
    if count > 0x101E:
        raise ValueError("Native local identifier data exceeds receive buffer")
    status, reply = _exchange(context, comm, bytes((0x21, identifier)))
    if not status and (len(reply) != count + 2 or reply[1] != identifier):
        status = 3
    return status, reply[2:] if not status else b""


def _gs_support(context: TYContext, comm: TYComm, data: bytearray) -> int:
    status, snapshot, offsets = _snapshot(context, comm, 1)
    if status:
        return status
    status = _mask(snapshot, offsets, 0x27, 3, 1)
    if status:
        return status
    counted, count = _count(snapshot, offsets, 0x27)
    # The original ignores the count-helper failure after the support mask passes.
    if not counted:
        _put(data, 0, count + 2)
    status, snapshot, offsets = _snapshot(context, comm, 3)
    if status:
        return status
    status = _mask(snapshot, offsets, 0x27, 3, 1)
    if not status:
        _put(data, 4, snapshot[offsets[0x27] + 1] + 2)
    return status


def _gs_status(context: TYContext, comm: TYComm, data: bytearray) -> int:
    status, reply = _exchange(context, comm, b"\x21\x27")
    if not status and (len(reply) != _u32(data) or len(reply) < 2 or reply[1] != 0x27):
        status = 3
    # The native zeroed receive buffer is copied even when the exchange failed.
    data[8] = (reply[2] if len(reply) > 2 else 0) & 1
    return status


def _gs_shift(context: TYContext, comm: TYComm, data: bytearray) -> int:
    count = _u32(data, 4)
    if count > 0x1020:
        raise ValueError("Native GS request length exceeds transmit buffer")
    frame = bytearray(max(3, count))
    frame[:3] = bytes((0x3B, 0x27, int(data[8] == 0)))
    status, reply = _exchange(context, comm, bytes(frame[:count]))
    if not status and (len(reply) != 2 or reply[1] != 0x27):
        status = 3
    return 10000 if status else _gs_status(context, comm, data)


def _res_support(context: TYContext, comm: TYComm, data: bytearray) -> int:
    status, snapshot, offsets = _snapshot(context, comm, 3)
    if status:
        return status
    status = _mask(snapshot, offsets, 0x62, 3, 0x40)
    if not status:
        status, count = _count(snapshot, offsets, 0x62)
        _put(data, 0, count)
    return status


def _res_register(
    context: TYContext, comm: TYComm, data: bytearray, remote: bool
) -> int:
    count = _u32(data) + 2
    if count > 0x1020:
        raise ValueError("Native RES request length exceeds transmit buffer")
    frame = bytearray(max(3, count))
    frame[:3] = bytes((0x3B, 0x62, 8 if remote else 0x40))
    status, reply = _exchange(context, comm, bytes(frame[:count]))
    if not status and reply != b"\x7b\x62":
        status = 3
    return status


def _res04_support(context: TYContext, comm: TYComm, data: bytearray) -> int:
    if _u32(data, 0x50):
        status, reply = _read(context, comm, 0x21, _u32(data, 4))
        if (
            not status
            and len(reply) >= 2
            and reply[0] & 0xF0 == 0xC0
            and reply[1] & 15 == 12
        ):
            return 9008
        return status
    status, snapshot, offsets = _snapshot(context, comm, 1)
    if status:
        return status
    status = _mask(snapshot, offsets, 0x21, 3, 0xF0)
    if not status:
        status = _mask(snapshot, offsets, 0x21, 4, 15)
    _put(data, 8, int(status == 0))
    if not status:
        _, count = _count(snapshot, offsets, 0x21)
        _put(data, 4, count)
    status, snapshot, offsets = _snapshot(context, comm, 3)
    if status:
        return status
    status = _mask(snapshot, offsets, 0x62, 3, 8)
    if not status:
        _put(data, 0, snapshot[offsets[0x62] + 1])
    return status


def _gs02(context: TYContext, comm: TYComm, data: bytearray) -> int:
    action = _u32(data, 12)
    if action == 0:
        status, snapshot, offsets = _snapshot(context, comm, 1)
        for identifier, mask, offset in ((0x21, 0xFF, 0), (0x26, 0x40, 4)):
            if status:
                return status
            status = _mask(snapshot, offsets, identifier, 3, mask)
            if not status:
                _, count = _count(snapshot, offsets, identifier)
                _put(data, offset, count)
        if status:
            return status
        status, snapshot, offsets = _snapshot(context, comm, 2)
        if not status:
            status = _mask(snapshot, offsets, 1, 3, 0x40)
            if not status:
                _, count = _count(snapshot, offsets, 1)
                _put(data, 8, count)
        return status
    if action != 1:
        return 0
    status, reply = _read(context, comm, 0x21, _u32(data))
    if status:
        return status
    if reply and reply[0]:
        return 9005
    count = _u32(data, 8) + 3
    if count > 0x1020:
        raise ValueError("Native GS actuator request exceeds transmit buffer")
    frame = bytearray(max(4, count))
    frame[:4] = b"\x30\x01\x00\x40"
    status, reply = _exchange(context, comm, bytes(frame[:count]))
    if not status:
        if len(reply) not in (2, 3) or reply[1] != 1:
            status = 3
        elif len(reply) == 3:
            status = 9005 if reply[2] == 0 else 3
    if status:
        return status
    started = context.ticks()
    try:
        while True:
            _sleep(context, 1000)
            status, reply = _read(context, comm, 0x26, _u32(data, 4))
            if status:
                return status
            if reply and reply[0] & 0x40:
                return 9005
            if (context.ticks() - started) & 0xFFFFFFFF > 25000:
                return 0
    finally:
        # Native actuator release is unconditional after polling begins.
        comm.exchange(b"\x30")


def run_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    """Execute a body after the source-bound wrapper selects its native worker."""
    if export not in supported_exports(context.module_sha256):
        raise TYSourceError(
            "No reviewed retained07 body for the exact source/export pair"
        )
    if hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256:
        raise TYSourceError("TY module bytes do not match the selected source identity")
    minimum = {
        "Ex2RES_04_SupportCheck": 0x54,
        "Ex2PCM_04_SendMessage": 56,
        "Ex2GS_02_SendMessage": 16,
        "Ex2GS_01_CheckShutterStatus": 9,
        "Ex2GS_01_ShiftMode": 9,
        "Ex2GS_01_SupportCheck": 8,
    }.get(
        export,
        0x60 if export in _SIL else (12 if export == _LDR[0] else 4),
    )
    if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < minimum:
        raise ValueError(
            f"{export} requires a mutable native buffer of at least {minimum} bytes"
        )
    data = args[0]
    if export in _LDR[1:3] and _u32(data) == 1:
        minimum = 0x3070 if export == _LDR[1] else 0x204D
        if len(data) < minimum:
            raise ValueError(f"{export} action1 requires {minimum} mutable bytes")
    if export in _LDR:
        return _ldr(context, export, data)
    if export in _SIL:
        return _sil(context, export, data)
    if export == "Ex2PCM_04_SendMessage":
        return _pcm(context, data)
    _check(context)
    comm = context.comm("selected")
    early_pending = export in ("Ex2GS_01_CheckShutterStatus", "Ex2GS_01_ShiftMode")
    try:
        if early_pending:
            comm.configure(_PENDING[context.module_sha256], 150)
        status = comm.initialize()
        if status:
            return status
        if not early_pending:
            comm.configure(_PENDING[context.module_sha256], 150)
        if export == "Ex2GS_01_SupportCheck":
            return _gs_support(context, comm, data)
        if export == "Ex2GS_01_CheckShutterStatus":
            return _gs_status(context, comm, data)
        if export == "Ex2GS_01_ShiftMode":
            return _gs_shift(context, comm, data)
        if export == "Ex2GS_02_SendMessage":
            return _gs02(context, comm, data)
        if export == "Ex2RES_03_SupportCheck":
            return _res_support(context, comm, data)
        if export == "Ex2RES_04_SupportCheck":
            return _res04_support(context, comm, data)
        return _res_register(
            context, comm, data, export == "Ex2RES_04_RemoteStartRegistration"
        )
    finally:
        comm.finalize()


def _pcm(context: TYContext, data: bytearray) -> int:
    _check(context)
    manager: dict[str, str] = dict(
        zip(_SOURCES, ("native:100aed50", "native:1011d4f0", "native:101392d0"))
    )
    comm = context.comm(manager[context.module_sha256])
    try:
        status = comm.initialize()
        if status:
            return status
        comm.configure("native_1080", 0)
        comm.configure("native_1084", 180000)
        status = comm.session(1)
        if status:
            return status
        status, reply = _exchange(context, comm, b"\x22\xda\xb4")
        if not status and (len(reply) < 4 or reply[1:3] != b"\xda\xb4"):
            status = 3
        if status:
            return status
        _put(data, 0, int(reply[3] != 0))
        status, reply = _exchange(context, comm, b"\x22\xda\xd8")
        if not status and (len(reply) < 35 or reply[1:3] != b"\xda\xd8"):
            status = 3
        if status:
            return status
        for offset, index in zip((40, 36, 32, 28, 24, 44, 48, 52), range(3, 35, 4)):
            data[offset : offset + 4] = reply[index : index + 4]
        if not _u32(data):
            return 0
        values = {
            offset: int.from_bytes(data[offset : offset + 4], "big")
            for offset in range(24, 56, 4)
        }
        if any(values[offset] == 0 for offset in (28, 24, 32, 36)):
            return 1001
        percent, remaining = _pcm_calculate(context, values)
        struct.pack_into("<d", data, 8, percent)
        struct.pack_into("<d", data, 16, remaining)
        return 0
    finally:
        comm.finalize()


_SIL = tuple(
    "Ex2RES_04_" + name + "_SIL"
    for name in (
        "GetEcuInfo",
        "GetSupportFunction",
        "KeepAlive",
        "SendKey",
        "SupportCheck",
    )
)


def _sil_body(context: TYContext, comm: TYComm, export: str, data: bytearray) -> int:
    if export == "Ex2RES_04_SupportCheck_SIL":
        status, snapshot, offsets = _snapshot(context, comm, 1)
        if status:
            _put(data, 0x14, 0)
            return 0 if status == 9012 else status
        status = _mask(snapshot, offsets, 0x12, 4, 2)
        if not status:
            _, record = _record(snapshot, offsets, 0x12)
            _put(data, 0x10, 2 + int(record[0] != 0))
            _, count = _count(snapshot, offsets, 0x12)
            _put(data, 0xC, count)
        _put(data, 0x14, int(status == 0))
        # 9012 means unsupported, and is consumed into the output flag.
        return 0
    if export == "Ex2RES_04_GetSupportFunction_SIL":
        status, reply = _read(context, comm, 0x12, _u32(data, 12))
        if not status:
            offset = _u32(data, 16) - 2
            if not 0 <= offset < 0x1020:
                raise ValueError("Native RES support index exceeds receive buffer")
            _put(data, 24, int(offset < len(reply) and bool(reply[offset] & 2)))
        return status
    if export == "Ex2RES_04_KeepAlive_SIL":
        while True:
            status, _ = _read(context, comm, 0, 4)
            if status or _u32(data, 0x4C):
                return status
            _sleep(context, 3000)
    if export == "Ex2RES_04_GetEcuInfo_SIL":
        status, reply = _exchange(context, comm, b"\x1a\x84")
        if not status and len(reply) != 10:
            status = 3
        if status:
            return status
        data[0x2D:0x35] = reply[2:10]
        status, reply = _exchange(context, comm, b"\x27\x07")
        if not status and (len(reply) != 8 or reply[1] != 7):
            status = 3
        if not status:
            data[0x35:0x3B] = reply[2:8]
        return status
    count = _u32(data, 0x48)
    if count > 10 or 0x3B + count > len(data):
        raise ValueError("Native RES key exceeds its ten-byte transmit buffer")
    status, reply = _exchange(context, comm, b"\x27\x08" + data[0x3B : 0x3B + count])
    if not status:
        if len(reply) != 3 or reply[1] != 8:
            status = 3
        elif reply[2] != 0x34:
            status = 9528
    return status


def _sil(context: TYContext, export: str, data: bytearray) -> int:
    # Native override and restore deliberately retain the saved values in the UI buffer.
    base, pointer, protocol, manager = (
        (0x1011F700, 0x1011F764, 0x1011F78C, 0x1011E5E0)
        if context.module_sha256 == SHA_18_TY
        else (0x1013FA38, 0x1013FAB0, 0x1013FAB4, 0x10139210)
    )
    keys = tuple(
        f"native_global:{address:x}" for address in (base + 16, base, base + 4)
    )
    values = tuple(context.state.get(key) for key in keys)
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in values):
        raise TYSourceError(
            "RES SIL requires initialized native protocol and target globals"
        )
    for offset, value in zip((0x54, 0x58, 0x5C), values):
        assert isinstance(value, int)
        _put(data, offset, value)
    context.state[f"native_global:{pointer:x}"] = manager
    context.state[f"native_global:{protocol:x}"] = 0x104
    context.state[keys[1]] = 0xC1
    context.state[keys[2]] = 0
    comm: TYComm | None = None
    try:
        comm = context.comm("selected")
        _check(context)
        status = comm.initialize()
        if status:
            return status
        comm.configure(_PENDING[context.module_sha256], 150)
        return _sil_body(context, comm, export, data)
    finally:
        try:
            if comm is not None:
                comm.finalize()
        finally:
            context.state[f"native_global:{pointer:x}"] = 0
            context.state[f"native_global:{protocol:x}"] = _u32(data, 0x54)
            context.state[keys[1]] = _u32(data, 0x58)
            context.state[keys[2]] = _u32(data, 0x5C)


_LDR = tuple(f"Ex2LDR_{number:02}_SendMessage" for number in range(9, 13))


def _did(
    context: TYContext, comm: TYComm, identifier: int, minimum: int
) -> tuple[int, bytes]:
    request = b"\x22" + identifier.to_bytes(2, "big")
    status, reply = _exchange(context, comm, request)
    if not status and (len(reply) < minimum + 3 or reply[1:3] != request[1:3]):
        status = 3
    return status, reply[3:] if not status else b""


def _routine(
    context: TYContext,
    comm: TYComm,
    action: int,
    identifier: int,
    payload: bytes = b"",
    count: int = 0,
) -> tuple[int, bytes]:
    request = bytes((0x31, action)) + identifier.to_bytes(2, "big") + payload
    status, reply = _exchange(context, comm, request)
    if not status and (len(reply) < count + 4 or reply[1:4] != request[1:4]):
        status = 3
    return status, reply[4:] if not status else b""


def _ldr09_error(context: TYContext, comm: TYComm, data: bytearray) -> int:
    _sleep(context, 100)
    status, reply = _did(context, comm, 0x1005, 1)
    if status or not reply[0] & 0xF8:
        return 2001
    data[4] = reply[0]
    return 2002


def _ldr09(context: TYContext, comm: TYComm, data: bytearray) -> int:
    action = _u32(data)
    if action not in (0, 1):
        return 0
    cleanup = action == 1
    normal = action == 1
    try:
        if action == 0:
            status = comm.initialize()
            if status:
                cleanup = True
                return 2000
            for field, value in (
                ("native_1080", 0),
                ("native_1084", 180000),
                ("native_1064", 0),
            ):
                comm.configure(field, value)
            if comm.session(3, normal_first=True):
                cleanup = True
                return 2000
            status, _ = _routine(context, comm, 1, 0x1101, b"\x09")
            if status:
                cleanup = normal = True
                return _ldr09_error(context, comm, data)
            context.state["retained07:ldr09:active"] = True
            return 0
        _sleep(context, 200)
        if _u32(data, 8) == 1:
            return 2003
        while True:
            status, reply = _routine(context, comm, 3, 0x1101, count=1)
            if status or reply[0] not in (1, 2):
                result = _ldr09_error(context, comm, data)
                return 2003 if _u32(data, 8) == 1 else result
            if reply[0] == 2:
                return 2003 if _u32(data, 8) == 1 else 0
            _sleep(context, 200)
            if _u32(data, 8) == 1:
                return 2003
    except BaseException:
        cleanup = normal = True
        raise
    finally:
        if cleanup:
            try:
                if normal:
                    comm.session(1, stop_on_error=True)
            finally:
                comm.finalize()
                context.state["retained07:ldr09:active"] = False


def _ldr_support(context: TYContext, comm: TYComm, number: int) -> int:
    for target in (263, 264, 265):
        comm.configure("native_lower_38", target)
        status = comm.session(3, normal_first=True)
        if status:
            return status
        status, reply = _did(context, comm, 0x0101, 32)
        if not status and not reply[2] & 0x80:
            status = 22
        if not status:
            status, reply = _did(context, comm, 0x1000, 32)
            masks = (
                ((0, 0x40), (1, 0x40), (1, 0x20))
                if number == 10
                else ((0, 0x20), (1, 0x20))
            )
            if not status and any(
                reply[offset] & mask != mask for offset, mask in masks
            ):
                status = 22
        if not status:
            status, reply = _did(context, comm, 0x1002 if number == 10 else 0x1003, 1)
            if not status and not reply[0] & 0x80:
                status = 22
        if status:
            comm.session(1, stop_on_error=True)
            return status
        status = comm.session(1, stop_on_error=True)
        if status:
            return status
    return 0


def _ldr10_read(context: TYContext, comm: TYComm, data: bytearray) -> int:
    for index, target in enumerate((263, 264, 265)):
        comm.configure("native_lower_38", target)
        status = comm.session(3, normal_first=True)
        if status:
            return status
        status, reply = _did(context, comm, 0x1002, 2)
        if not status:
            identifier, count = (0x100B, 6) if reply[1] & 0x80 else (0x100A, 5)
            struct.pack_into("<H", data, 0x306A + index * 2, identifier)
            struct.pack_into("<H", data, 0x3064 + index * 2, count)
            start = 4 + index * 0x1020
            data[start : start + 0x1020] = bytes(0x1020)
            status, reply = _did(context, comm, identifier, count)
            if not status:
                if len(reply) > 0x1020:
                    raise ValueError("Native LDR read exceeds output slot")
                data[start : start + len(reply)] = reply
        if status:
            comm.session(1, stop_on_error=True)
            return status
        comm.session(1, stop_on_error=True)
    return 0


def _ldr11_write(context: TYContext, comm: TYComm, data: bytearray) -> int:
    for index, target in enumerate((263, 264, 265)):
        comm.configure("native_lower_38", target)
        status = comm.session(3, normal_first=True)
        if status:
            return status
        _sleep(context, 600)
        if _u32(data, 4):
            comm.session(1, stop_on_error=True)
            return 0
        expected = bytes(data[8 + index * 0x1020 : 13 + index * 0x1020])
        status, _ = _routine(context, comm, 1, 0x1104, b"\x01" + expected)
        if status:
            comm.session(1, stop_on_error=True)
            return 2000
        _sleep(context, 600)
        while True:
            if _u32(data, 4):
                comm.session(1, stop_on_error=True)
                return 0
            status, reply = _routine(context, comm, 3, 0x1104, count=1)
            if status or reply[0] not in (0, 1):
                break
            _sleep(context, 600)
        if status or reply[0] != 2:
            comm.session(1, stop_on_error=True)
            return 2000
        status, actual = _did(context, comm, 0x100B, 6)
        if not status:
            status, flags = _did(context, comm, 0x1003, 2)
        else:
            flags = b""
        if status:
            comm.session(1, stop_on_error=True)
            return 2000
        status = comm.session(1, stop_on_error=True)
        if status or actual[:5] != expected or flags[1] & 0x80:
            return 2000
    return 0


def _ldr12(context: TYContext, comm: TYComm, data: bytearray) -> int:
    for target in (262, 263, 264, 265):
        comm.configure("native_lower_38", target)
        status = comm.session(3, normal_first=True)
        if status:
            return status
        status, reply = _did(context, comm, 0x0204, 1)
        if not status and len(reply) < 2:
            status = 2000
        if not status:
            payload = bytearray(reply)
            payload[1] = (payload[1] | 0x40) if _u32(data) else (payload[1] & 0xBF)
            status, ack = _exchange(context, comm, b"\x2e\x02\x04" + payload)
            if not status and (len(ack) < 3 or ack[1:3] != b"\x02\x04"):
                status = 3
            if not status:
                _sleep(context, 500)
                status, reply = _did(context, comm, 0x0204, 1)
                if not status and len(reply) < 2:
                    status = 2000
                if not status:
                    comm.session(1, stop_on_error=True)
                    if (payload[1] ^ reply[1]) & 0x40:
                        return 2000
                    continue
        comm.session(1, stop_on_error=True)
        return status
    return 0


def _ldr(context: TYContext, export: str, data: bytearray) -> int:
    comm = context.comm(
        "native:1011e618" if context.module_sha256 == SHA_18_TY else "native:10134b78"
    )
    number = int(export[7:9])
    if number == 9:
        return _ldr09(context, comm, data)
    try:
        status = comm.initialize()
        if status:
            return status
        for field, value in (
            ("native_1080", 0),
            ("native_1084", 180000),
            ("native_1064", 0),
        ):
            comm.configure(field, value)
        if number == 12:
            return _ldr12(context, comm, data)
        action = _u32(data)
        if action == 0:
            return _ldr_support(context, comm, number)
        if action != 1:
            return 0
        if number == 10:
            return _ldr10_read(context, comm, data)
        return _ldr11_write(context, comm, data)
    finally:
        comm.finalize()


def _binary(value: Fraction, precision: int, rounding: int) -> Fraction:
    """One finite x87/SSE arithmetic instruction, including its control-word rounding."""
    if not value:
        return value
    numerator, denominator = abs(value.numerator), value.denominator
    exponent = numerator.bit_length() - denominator.bit_length()
    if exponent >= 0:
        if numerator < denominator << exponent:
            exponent -= 1
    elif numerator << -exponent < denominator:
        exponent -= 1
    shift = precision - 1 - exponent
    if shift >= 0:
        quotient, remainder = divmod(numerator << shift, denominator)
        divisor = denominator
    else:
        divisor = denominator << -shift
        quotient, remainder = divmod(numerator, divisor)
    if rounding == 0:
        increment = 2 * remainder > divisor or (
            2 * remainder == divisor and quotient & 1
        )
    else:
        increment = bool(remainder) and (
            (rounding == 1 and value < 0) or (rounding == 2 and value > 0)
        )
    quotient += int(increment)
    result = (
        Fraction(quotient, 1 << shift) if shift >= 0 else Fraction(quotient << -shift)
    )
    return -result if value < 0 else result


def _pcm_calculate(context: TYContext, values: dict[int, int]) -> tuple[float, float]:
    import math

    word = context.state.get("host:x87_control_word")
    if type(word) is not int or not 0 <= word <= 0xFFFF:
        raise TYSourceError(
            "PCM arithmetic requires the explicit host x87 control word"
        )
    precision = {0: 24, 2: 53, 3: 64}.get((word >> 8) & 3)
    if precision is None:
        raise TYSourceError("Reserved x87 precision-control encoding")
    if not word & 0x20:
        raise TYSourceError("PCM requires masked x87 inexact exceptions")
    rounding = (word >> 10) & 3
    plus = context.module_sha256 == SHA_PLUS_TY
    sse_rounding = 0
    if plus:
        mxcsr = context.state.get("host:mxcsr")
        if type(mxcsr) is not int or not 0 <= mxcsr <= 0xFFFF:
            raise TYSourceError("Plus PCM arithmetic requires the explicit host MXCSR")
        if not mxcsr & 0x1000:
            raise TYSourceError("PCM requires masked SSE inexact exceptions")
        sse_rounding = (mxcsr >> 13) & 3

    def x87(value: Fraction | float) -> Fraction:
        return _binary(Fraction(value), precision, rounding)

    def stored(value: Fraction | float) -> Fraction:
        return _binary(Fraction(value), 53, rounding)

    def sse(value: Fraction | float) -> Fraction:
        return _binary(Fraction(value), 53, sse_rounding)

    coefficients = [
        sse(Fraction(-19, 2 * values[offset]))
        if plus
        else stored(x87(Fraction(-19, 2 * values[offset])))
        for offset in (28, 24, 32, 36)
    ]

    def clipped(offset: int, coefficient: Fraction, sse_path: bool) -> int:
        if plus and sse_path:
            raw = sse(sse(values[offset] * coefficient) + 11)
        else:
            raw = x87(x87(values[offset] * coefficient) + 11)
            if plus:
                raw = stored(raw)
        if raw <= 1:
            return 1
        raw = stored(raw)
        rounded = (
            sse(raw + Fraction(1, 2)) if plus else stored(x87(raw + Fraction(1, 2)))
        )
        return math.floor(rounded)

    first = clipped(48, coefficients[0], False)
    second = clipped(52, coefficients[1], True)
    third = clipped(44, coefficients[2], False)
    fourth = clipped(52, coefficients[3], True)
    weight = Fraction(values[40])
    opposite = sse(1 - weight) if plus else stored(x87(1 - weight))
    if plus:
        mixed = sse(sse(fourth * opposite) + sse(third * weight))
    else:
        mixed = stored(x87(x87(fourth * opposite) + stored(x87(third * weight))))
    result = min(first, second, math.floor(mixed))
    percent = sse(sse(result - 1) * 10) if plus else stored(x87(x87(result - 1) * 10))
    if result == 11:
        return float(percent), 0.0
    if plus:
        fraction = _binary(sse(percent / 100), 24, sse_rounding)
        denominator = sse(1 - fraction)
        remaining = sse(sse(Fraction(values[52]) / denominator) - values[52])
    else:
        denominator = x87(1 - x87(percent * Fraction(0.01)))
        remaining = stored(x87(x87(Fraction(values[52]) / denominator) - values[52]))
    return float(percent), float(math.floor(remaining))
