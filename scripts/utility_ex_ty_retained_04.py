"""Exact-source retained TY AHS, power-seat and image-view-monitor bodies.

Only primitive communication is injected. Native caller buffers remain mutable and
owned by the caller across retained UDS sessions.
"""

from __future__ import annotations

import hashlib

from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import (
    SHA_12_TY,
    SHA_18_TY,
    SHA_PLUS_TY,
    TYComm,
    TYContext,
    TYSourceError,
)

_AHS = (
    "Ex2AHS_01_CameraOpticAxisAdjustmentRequest",
    "Ex2AHS_01_CameraOpticAxisConfirmation",
    "Ex2AHS_01_SupportCheck",
    "Ex2AHS_02_CalibSwivelMarginAngle",
    "Ex2AHS_02_SupportCheck",
    "Ex2AHS_03_HeightSensorInitializationAndDTCCheck",
    "Ex2AHS_03_SupportCheckAndDTCCheck",
    "Ex2AHS_04_SupportCheckAndDTCCheck",
    "Ex2AHS_04_SynchronizeInformationAndDTCCheck",
)
_PSEAT = (
    "Ex2PSEAT_01_SendMessage",
    "Ex2PSEAT_03_SendMessage",
    "Ex2PSEAT_04_SendMessage",
)
_IVM = "Ex2IVM_01_SendMessage"
_EXPORTS = {
    SHA_12_TY: _AHS,
    SHA_18_TY: _AHS + _PSEAT + (_IVM,),
    SHA_PLUS_TY: _AHS + _PSEAT + (_IVM,),
}
_CLASSIC = {
    SHA_12_TY: (0xB940, 0xB960, 0xB980),
    SHA_18_TY: (0x12180, 0x121D0, 0x121F0),
    SHA_PLUS_TY: (0x142F0, 0x14320, 0x140C0),
}
_RESULT = {SHA_12_TY: 0x100AB770, SHA_18_TY: 0x10118E38, SHA_PLUS_TY: 0x10134AB8}
_DTC03 = (
    0xA415,
    0xA416,
    0xA41A,
    0xA420,
    0xA451,
    0xA453,
    0xA456,
    0xA42C,
    0xA42D,
    0xC129,
    0xC142,
    0xC242,
)
_DTC04 = (
    0xA420,
    0xA451,
    0xA453,
    0xA456,
    0xA42C,
    0xA42D,
    0xC100,
    0xC142,
    0xC242,
    0xC293,
)
_DTCSYNC = (0xA420, 0xA451, 0xA453, 0xA42C, 0xA42D, 0xA456)


def supported_exports(module_sha256: str) -> tuple[str, ...]:
    """Return only the 35 assigned exact-source pairs."""
    return _EXPORTS.get(module_sha256, ())


def _check(context: TYContext) -> None:
    if context.is_cancelled():
        raise Cancelled("TY retained operation cancelled")


def _sleep(context: TYContext, duration: int) -> None:
    _check(context)
    context.native_sleep(duration)
    _check(context)


def _exchange(comm: TYComm, context: TYContext, request: bytes) -> tuple[int, bytes]:
    _check(context)
    status, reply = comm.exchange(request)
    if type(status) is not int or type(reply) is not bytes or len(reply) > 0x1020:
        raise ValueError("Native exchange status/response is malformed")
    return status, reply


def _u32(data: bytearray, offset: int = 0) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _put(data: bytearray, offset: int, value: int) -> None:
    data[offset : offset + 4] = value.to_bytes(4, "little")


def _frame(prefix: bytes, length: int) -> bytes:
    if not 0 <= length <= 0x1020:
        raise ValueError("Native request length exceeds the 0x1020-byte buffer")
    return (prefix + bytes(0x1020 - len(prefix)))[:length]


def _classic_reply(status: int, reply: bytes, service: int) -> int:
    if status and len(reply) == 3 and reply[:2] == bytes((0x7F, service)):
        return {0x21: 27, 0x22: 26, 0x24: 1001}.get(reply[2], status)
    return status


def _snapshot(
    comm: TYComm, context: TYContext, kind: int
) -> tuple[int, bytes, tuple[int, ...]]:
    _check(context)
    status, data, offsets = comm.support_snapshot(kind)
    if type(data) is not bytes or len(data) > 0x1020 or len(offsets) != 256:
        raise ValueError("Native support buffer and 256 offsets required")
    if any(type(x) is not int or not 0 <= x <= 0x1020 for x in offsets):
        raise ValueError("Native support offset exceeds the source buffer")
    return status, data + bytes(0x1020 - len(data)), offsets


def _support(
    data: bytes,
    offsets: tuple[int, ...],
    pid: int,
    column: int | None = None,
    mask: int = 0,
) -> tuple[int, int]:
    """12340/123f0: count nonzero entries, preserving sparse-column indexing."""
    base = offsets[pid]
    if base == 0x1020:
        return 22, -1
    if base + 1 >= 0x1020 or base + 1 + data[base + 1] > 0x1020:
        return 99, -1
    count = data[base + 1]
    if column is None:
        result = sum(value != 0 for value in data[base + 2 : base + 2 + count])
        return (0 if result else 22), result
    if count < column - 2:
        return 22, -1
    index = column - 1
    if base + index >= 0x1020:
        return 99, -1
    output = 2 + sum(value != 0 for value in data[base + 2 : base + index])
    value = data[base + index]
    return (0 if value and value & mask == mask else 22), output


def _dtcs(
    comm: TYComm, context: TYContext, wanted: tuple[int, ...]
) -> tuple[int, tuple[bool, ...]]:
    _check(context)
    status, reply = comm.read_dtcs(0x81, 0x1000)
    if type(reply) is not bytes or len(reply) > 0x1020:
        raise ValueError("Native DTC buffer is malformed")
    padded = reply + bytes(0x1020 - len(reply))
    codes = {
        int.from_bytes(padded[i : i + 2], "big") for i in range(2, 2 + padded[1] * 2, 2)
    }
    return status, tuple(code in codes for code in wanted)


def _ahs_support01(comm: TYComm, context: TYContext, data: bytearray) -> int:
    status, raw, offsets = _snapshot(comm, context, 1)
    if status:
        return status
    for column in (3, 4):
        status, _ = _support(raw, offsets, 8, column, 0xFF)
        if status:
            return status
    status, count = _support(raw, offsets, 8)
    if status:
        return status
    _put(data, 0, count)
    status, index = _support(raw, offsets, 9, 5, 0x80)
    if index >= 0:
        _put(data, 12, index)
    if status:
        return status
    status, count = _support(raw, offsets, 9)
    if status:
        return status
    _put(data, 4, count)
    status, raw, offsets = _snapshot(comm, context, 2)
    if not status:
        status, _ = _support(raw, offsets, 4, 3, 0x80)
        if not status:
            status, count = _support(raw, offsets, 4)
            if not status:
                _put(data, 8, count)
    return status


def _ahs(comm: TYComm, context: TYContext, export: str, data: bytearray) -> int:
    pending, busy, getter = _CLASSIC[context.module_sha256]
    # AHS01 changes module target globals; the other families use selected target.
    if export in _AHS[:3]:
        comm.select_target(0x750, 0x7C)
    saved: int | None = None
    try:
        _check(context)
        status = comm.initialize(0)
        if status:
            return status
        if export in _AHS[:2]:
            saved = comm.read_field(f"native_rva:{getter:x}")
            comm.configure(f"native_rva:{busy:x}", 0)
        comm.configure(f"native_rva:{pending:x}", 150)
        if export == _AHS[2]:
            return _ahs_support01(comm, context, data)
        if export == _AHS[1]:
            status, reply = _exchange(comm, context, b"\x21\x08")
            if not status:
                if len(reply) != _u32(data) + 2 or reply[:2] != b"\x61\x08":
                    return 3
                padded = reply + bytes(2)
                data[16:18] = padded[2:4]
            return _classic_reply(status, reply, 0x21)
        if export == _AHS[0]:
            status, reply = _exchange(
                comm, context, _frame(b"\x30\x04\x00\x80", _u32(data, 8) + 3)
            )
            status = _classic_reply(status, reply, 0x30)
            if not status and reply != b"\x70\x04":
                status = 3
            if status:
                return status
            _sleep(context, 1000)
            start = context.ticks()
            while (context.ticks() - start) & 0xFFFFFFFF < 5000:
                status, reply = _exchange(comm, context, b"\x21\x09")
                status = _classic_reply(status, reply, 0x21)
                if not status:
                    if len(reply) != _u32(data, 4) + 2 or reply[:2] != b"\x61\x09":
                        return 3
                    index = _u32(data, 12)
                    if index >= 0x1020:
                        raise ValueError(
                            "AHS completion index exceeds native response buffer"
                        )
                    status = (
                        0
                        if (reply + bytes(0x1020 - len(reply)))[index] & 0x80
                        else 1002
                    )
                if status != 1002:
                    return status
                _sleep(context, 1000)
            return 1000
        if export == _AHS[4]:
            status, raw, offsets = _snapshot(comm, context, 2)
            if not status:
                for column, mask in ((3, 0xF0), (4, 0x80)):
                    status, _ = _support(raw, offsets, 12, column, mask)
                    if status:
                        return status
                _, count = _support(raw, offsets, 12)
                _put(data, 0, count + 3)
            return status
        if export == _AHS[3]:
            status, reply = _exchange(
                comm, context, _frame(b"\x30\x0c\x00" + bytes(data[4:6]), _u32(data))
            )
            if not status and (len(reply) != 2 or reply[1] != 12):
                status = 3
            if status:
                return status
            if data[4] == 0:
                _sleep(context, 1000)
            elif data[4] in (0x10, 0x20, 0x40, 0x80):
                _sleep(context, 7000)
            status, matches = _dtcs(comm, context, (0xA420,))
            return status or (9999 if any(matches) else 0)
        if export == _AHS[6]:
            _put(data, 0, 0)
            status, reply = _exchange(comm, context, b"\xa8\x12\x04")
            if status:
                return status
            padded = reply + bytes(0x1020 - len(reply))
            if padded[:3] != b"\xe8\x12\x04" or padded[3] < 2:
                return 3
            if not padded[4] & 0x80 or padded[5] != 0xFF:
                return 22
            _put(data, 0, sum(value != 0 for value in padded[4 : 4 + padded[3]]))
            status, matches = _dtcs(comm, context, _DTC03)
            return status or (1000 if any(matches) else 0)
        if export == _AHS[5]:
            angle = {1: 8, 2: 6, 3: 4, 4: 2, 5: 1}.get(_u32(data, 4), 0)
            status, reply = _exchange(
                comm,
                context,
                _frame(b"\x30\x04\x00\x80" + bytes((angle,)), _u32(data) + 3),
            )
            if not status and reply == b"\x70\x04":
                return 0
            _sleep(context, 1500)
            status, matches = _dtcs(comm, context, (0xA420, 0xA42C, 0xA42D))
            return status or (1000 if any(matches) else 1001)
        if export == _AHS[7]:
            status, raw, offsets = _snapshot(comm, context, 3)
            if status:
                return status
            status, _ = _support(raw, offsets, 1, 3, 0x40)
            if status:
                return status
            _put(data, 0, raw[offsets[1] + 1])
            status, raw, offsets = _snapshot(comm, context, 1)
            if status:
                return status
            present = True
            for column in (11, 12):
                status, _ = _support(raw, offsets, 3, column, 0xFF)
                if status:
                    present = False
                    break
            _put(data, 4, int(present))
            status, matches = _dtcs(comm, context, _DTC04)
            if status:
                return status
            if any(matches[6:]):
                return 1004
            if any(matches[i] for i in (0, 4, 5)):
                return 1000
            return 0 if any(matches[1:4]) else 1003
        status, reply = _exchange(
            comm, context, _frame(b"\x3b\x01\x40", _u32(data) + 2)
        )
        if not status and reply != b"\x7b\x01":
            status = 3
        if status:
            return status
        _sleep(context, 12000 if _u32(data, 4) == 1 else 100)
        status, matches = _dtcs(comm, context, _DTCSYNC)
        if status:
            return status
        if any(matches[i] for i in (0, 3, 4)):
            return 1000
        if matches[1]:
            return 1001
        return 1002 if matches[2] or matches[5] else 0
    finally:
        try:
            if saved is not None:
                comm.configure(f"native_rva:{busy:x}", saved)
        finally:
            comm.finalize()


def _configure(comm: TYComm) -> None:
    for field, value in (
        ("native_1080", 0),
        ("native_1084", 180000),
        ("native_1064", 0),
    ):
        comm.configure(field, value)


def _routine(
    comm: TYComm,
    context: TYContext,
    action: int,
    rid: int,
    payload: bytes = b"",
    minimum: int = 0,
) -> tuple[int, bytes]:
    request = bytes((0x31, action, 0x11, rid)) + payload
    status, reply = _exchange(comm, context, request)
    if not status and (len(reply) < 4 + minimum or reply[1:4] != request[1:4]):
        return 3, reply
    return status, reply[4:]


def _pseat(comm: TYComm, context: TYContext, export: str, data: bytearray) -> int:
    action = _u32(data)
    rid = (1, 5, 6)[_PSEAT.index(export)]
    retained = False
    try:
        if action == 0:
            _check(context)
            status = comm.initialize(0)
            if status:
                return status
            _configure(comm)
            status = comm.session(3, normal_first=True)
            if status:
                return status
            status, _ = _routine(comm, context, 1, rid)
            if status:
                comm.session(1)
            else:
                retained = True
            return status
        status = 0
        if action == 1:
            try:
                while _u32(data, 4) == 0:
                    status, reply = _routine(comm, context, 3, rid, minimum=1)
                    if status:
                        break
                    if reply[0] != 1:
                        status = 0 if reply[0] == 2 else 2000
                        break
            finally:
                comm.session(1)
        return status
    finally:
        if not retained:
            comm.finalize()


def _read_did(
    comm: TYComm,
    context: TYContext,
    data: bytearray,
    did: bytes,
    offset: int,
    length_offset: int | None,
    minimum: int,
) -> int:
    status, reply = _exchange(comm, context, b"\x22" + did)
    if status:
        return status
    if len(reply) < minimum + 3 or reply[1:3] != did:
        return 3
    payload = reply[3:]
    if len(payload) > 0x1020 or offset + len(payload) > len(data):
        raise ValueError("Native DID payload exceeds caller allocation")
    if length_offset is not None:
        _put(data, length_offset, len(payload))
    data[offset : offset + len(payload)] = payload
    return 0


def _ivm_write(comm: TYComm, context: TYContext, data: bytearray) -> int:
    count = _u32(data, 0x2040)
    if count > 0x101D:
        raise ValueError("IVM retained data exceeds native request buffer")
    status, reply = _exchange(
        comm, context, b"\x2e\x02\x04" + bytes(data[0x1020 : 0x1020 + count])
    )
    if not status and (len(reply) < 3 or reply[1:3] != b"\x02\x04"):
        return 3
    return status


def _ivm_restore(comm: TYComm, context: TYContext, data: bytearray) -> int:
    status = _ivm_write(comm, context, data)
    if status:
        return 1007
    comm.session(1)
    return 0


def _ivm_poll(
    comm: TYComm, context: TYContext, rid: int, duration: int
) -> tuple[int, int]:
    start = context.ticks()
    _sleep(context, 200)
    while True:
        status, reply = _routine(comm, context, 3, rid, minimum=1)
        value = reply[0] if not status else 0
        if (
            status
            or value not in (0, 1)
            or (context.ticks() - start) & 0xFFFFFFFF >= duration
        ):
            return status, value
        _sleep(context, 200)


def _ivm(comm: TYComm, context: TYContext, data: bytearray) -> int:
    action = _u32(data, 0x2044)
    retained = False
    try:
        if action not in (0, 1, 2):
            comm.session(1)
            return 2000
        if action == 2:
            status = _ivm_restore(comm, context, data)
            retained = status == 1007
            return status
        if action == 0:
            _check(context)
            status = comm.initialize(0)
            if status:
                retained = status in (1005, 1007)
                return status
            _configure(comm)
            status = comm.session(3, normal_first=True)
            if status:
                retained = status in (1005, 1007)
                return status
            status = _read_did(comm, context, data, b"\x02\x04", 0x1020, 0x2040, 2)
            if status:
                comm.session(1)
                retained = status in (1005, 1007)
                return status
            if not data[0x1021] & 0x80:
                data[0x1021] |= 0x80
                status = _ivm_write(comm, context, data)
                if status:
                    comm.session(1)
                    retained = status in (1005, 1007)
                    return status
            data[0x1021] &= 0x7F
            rid = 1
            status, _ = _routine(comm, context, 1, rid, b"\x00")
            if not status:
                start = context.ticks()
                _sleep(context, 200)
                while True:
                    status, reply = _routine(comm, context, 3, rid, minimum=1)
                    if status or reply[0] not in (0, 1):
                        break
                    if (context.ticks() - start) & 0xFFFFFFFF >= 20000:
                        status = 3
                        break
                    _sleep(context, 200)
                if not status and reply[0] == 3:
                    status = _read_did(comm, context, data, b"\x10\x11", 0, None, 4)
                    if not status:
                        retained = True
                        return 1005
                    status = _ivm_restore(comm, context, data)
                    retained = status == 1007
                    return status or 3
                if not status and reply[0] == 2:
                    rid = 2
                    status, _ = _routine(comm, context, 1, rid, b"\x00")
                    if not status:
                        status, value = _ivm_poll(comm, context, rid, 15000)
                        if not status and value == 2:
                            _put(data, 0x2048, 1)
                            status = _ivm_restore(comm, context, data)
                            retained = status == 1007
                            return status
        else:
            rid = 2
            status, _ = _routine(comm, context, 1, rid, b"\x01")
            if not status:
                status, value = _ivm_poll(comm, context, rid, 15000)
                if not status and value == 2:
                    _put(data, 0x2048, 2)
                    status = _ivm_restore(comm, context, data)
                    retained = status == 1007
                    return status
        _routine(comm, context, 2, rid)
        status = _ivm_restore(comm, context, data)
        retained = status == 1007
        return status or 3
    except BaseException:
        # Host cancellation/fault cannot strand an offline retained native manager.
        comm.finalize()
        retained = True
        raise
    finally:
        if not retained:
            comm.finalize()


def run_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    """Run one exact selected body; wrapper scheduling is owned by UtilityExEngine."""
    if hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256:
        raise TYSourceError("TY module bytes do not match the selected source identity")
    if export not in supported_exports(context.module_sha256):
        raise TYSourceError("No exact retained TY source/export pair")
    if context.mode not in ((4,) if export in _AHS else (20, 21)):
        return 99
    minimum = (
        (16, 18, 16, 6, 4, 8, 4, 8, 8)[_AHS.index(export)] if export in _AHS else 8
    )
    if export == _IVM:
        minimum = 0x204C
    if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < minimum:
        raise ValueError(
            f"{export} requires a mutable native buffer of at least {minimum} bytes"
        )
    _check(context)
    selector = (
        "selected"
        if export in _AHS
        else (
            "native:1011d4f0"
            if context.module_sha256 == SHA_18_TY
            else "native:101392d0"
        )
    )
    comm = context.comm(selector)
    if export in _AHS:
        result = _ahs(comm, context, export, args[0])
    elif export in _PSEAT:
        result = _pseat(comm, context, export, args[0])
    else:
        result = _ivm(comm, context, args[0])
    context.state[f"native_global:{_RESULT[context.module_sha256]:x}"] = result
    return result
