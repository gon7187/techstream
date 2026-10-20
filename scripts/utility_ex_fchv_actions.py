"""Literal FCHV03/04/11/12/17 workers for the two reviewed TY sources."""

from __future__ import annotations

import hashlib
import sys
from contextvars import ContextVar
from types import TracebackType
from typing import cast

from scripts.utility_ex_fchv import (
    _check,
    _extended,
    _initialize,
    _put,
    _status,
    _u32,
)
from scripts.utility_ex_fchv import (
    _exchange as _native_exchange,
)
from scripts.utility_ex_ty import (
    SHA_18_TY,
    SHA_PLUS_TY,
    TYComm,
    TYContext,
    TYSourceError,
    elapsed_ticks,
)

_EXPORTS = tuple(
    f"Ex2FCHV_{group}_SendMessage" for group in ("03", "04", "11", "12", "17")
)
_MANAGERS = {SHA_18_TY: "native:1011d4f0", SHA_PLUS_TY: "native:101392d0"}
# Independently recovered five 16-byte records at 18:f8740 and Plus:f41d8.
_TABLES = {
    SHA_18_TY: (
        (0x97, 0x800, 6, 2),
        (0x98, 0x400, 6, 2),
        (0x99, 0x200, 6, 2),
        (0x9A, 0x80, 2, 0),
        (0x9B, 0x40, 2, 0),
    ),
    SHA_PLUS_TY: (
        (0x97, 0x800, 6, 2),
        (0x98, 0x400, 6, 2),
        (0x99, 0x200, 6, 2),
        (0x9A, 0x80, 2, 0),
        (0x9B, 0x40, 2, 0),
    ),
}


_OPERATION: ContextVar[tuple[BaseException | None, TracebackType | None] | None] = (
    ContextVar("fchv-action-operation", default=None)
)


def _primary() -> BaseException | None:
    baseline = _OPERATION.get()
    current = sys.exception()
    if baseline is None or current is None:
        return None
    if current is baseline[0] and current.__traceback__ is baseline[1]:
        return None
    return current


def supported_exports(module_sha256: str) -> tuple[str, ...]:
    return _EXPORTS if module_sha256 in _MANAGERS else ()


def _sleep(context: TYContext, ms: int) -> None:
    _check(context)
    context.native_sleep(ms)
    _check(context)


def _outputs(context: TYContext) -> dict[int, tuple[TYComm, dict[bytes, None]]]:
    key = "fchv-actions:active-outputs"
    if key not in context.state:
        context.state[key] = {}
    return cast(dict[int, tuple[TYComm, dict[bytes, None]]], context.state[key])


def _release_request(request: bytes) -> bytes | None:
    if request[:1] == b"\x30" and len(request) > 1:
        return b"\x30"
    if (
        len(request) >= 4
        and request[0] == 0x31
        and request[1] == 1
        and request[3] in (0x16, 0x19)
    ):
        return b"\x31\x02" + request[2:4]
    if len(request) >= 5 and request[0] == 0x2F and request[3] == 3:
        payload = bytes((0, request[-1])) if request[2] == 0x0C else request[-1:]
        return request[:3] + b"\x00" + payload
    return None


def _exchange(comm: TYComm, context: TYContext, request: bytes) -> tuple[int, bytes]:
    release = _release_request(request)
    if release is not None:
        # Authored HOST safety: retain uncertain activation until a confirmed release.
        _, pending = _outputs(context).setdefault(id(comm), (comm, {}))
        pending[release] = None
    result = _native_exchange(comm, context, request)
    if request == b"\x30" and not result[0]:
        entry = _outputs(context).get(id(comm))
        if entry is not None:
            entry[1].pop(request, None)
    return result


def _abort(comm: TYComm, context: TYContext) -> None:
    entry = _outputs(context).get(id(comm))
    if entry is None:
        return
    primary = _primary()
    for request in tuple(entry[1]):
        try:
            status, reply = comm.cleanup_exchange(request)
            echo = request[1:4]
            if not status and (
                request == b"\x30" or len(reply) >= 4 and reply[1:4] == echo
            ):
                del entry[1][request]
            elif primary is not None:
                primary.add_note(
                    f"FCHV safety release {request.hex()} returned {status}"
                )
        except BaseException as error:
            if primary is None:
                raise
            if primary is not None:
                primary.add_note(
                    f"FCHV safety release {request.hex()} failed: {error!r}"
                )


def _echo(comm: TYComm, context: TYContext, request: bytes) -> int:
    status, reply = _exchange(comm, context, request)
    status = (
        3 if not status and (len(reply) < 4 or reply[1:4] != request[1:4]) else status
    )
    if not status:
        entry = _outputs(context).get(id(comm))
        if entry is not None:
            entry[1].pop(request, None)
    return status


def _read(
    comm: TYComm, context: TYContext, did: bytes, offset: int, size: int
) -> tuple[int, bytes]:
    if len(did) != 2 or not 0 <= offset <= 4125 or not 0 <= size <= 4125 - offset:
        raise ValueError("FCHV DID descriptor exceeds native reply capacity")
    status, reply = _exchange(comm, context, b"\x22" + did)
    if not status and (len(reply) < 3 + offset + size or reply[1:3] != did):
        return 3, b""
    return status, reply[3 + offset : 3 + offset + size]


def _io(
    comm: TYComm, context: TYContext, second: int, control: int, payload: bytes
) -> int:
    return _echo(comm, context, bytes((0x2F, 0x28, second, control)) + payload)


def _routine(
    comm: TYComm, context: TYContext, sub: int, second: int, payload: bytes = b""
) -> int:
    return _echo(comm, context, bytes((0x31, sub, 0x11, second)) + payload)


def _normal(comm: TYComm) -> int:
    active = _primary()
    try:
        return _status(
            (comm.cleanup_session if active is not None else comm.session)(
                1, 1, stop_on_error=True
            )
        )
    except BaseException as error:
        if active is None:
            raise
        active.add_note(f"FCHV normal-session cleanup failed: {error!r}")
        return 0


def _finalize(comm: TYComm) -> None:
    active = _primary()
    try:
        comm.finalize()
    except BaseException as error:
        if active is None:
            raise
        active.add_note(f"FCHV finalization failed: {error!r}")


def _finish(comm: TYComm) -> None:
    try:
        _normal(comm)
    finally:
        _finalize(comm)


def _valves(
    comm: TYComm,
    context: TYContext,
    data: bytearray,
    enabled: bool,
    *,
    wait: bool = True,
    normal: bool = True,
) -> int:
    mask = data[0x2C] & 7
    status = _io(comm, context, 0x0C, 3, bytes((0, mask if enabled else 0, 0, mask)))
    if not wait:
        return 0
    if status == 7:
        status = 2001 if _status(comm.read_field("native_10b0")) == 105 else 2000
    elif status:
        status = 2000
    else:
        started = None
        while True:
            _sleep(context, 200)
            status, reply = _read(comm, context, b"\x1b\x94", 0, 2)
            if status:
                status = 2000
                break
            if started is None:
                started = context.ticks()
            selected, actual = reply
            actual = actual if enabled else ~actual
            if actual & selected & 7 == selected & 7:
                return 0
            if elapsed_ticks(context.ticks(), started) >= 5000:
                status = 2001
                break
    _io(comm, context, 0x0C, 0, bytes((0, data[0x2C] & 7)))
    if normal:
        _normal(comm)
    return status


def _support11(comm: TYComm, context: TYContext, data: bytearray) -> int:
    normalized = False
    data[12:14] = bytes(2)
    data[0x2C] = 0
    status = _extended(comm)
    if status:
        return status
    try:
        status, flags = _read(comm, context, b"\x01\x01", 0, 32)
        if status:
            return status
        if not flags[3] & 0x10:
            return 3
        status, mask = _read(comm, context, b"\x28\x0c", 0, 1)
        if status:
            return status
        data[0x2C] = mask[0]
        status, flags = _read(comm, context, b"\x1b\x00", 0, 32)
        if status:
            return status
        if (
            flags[18] & 0x12 != 0x12
            or flags[19] & 0x60 != 0x60
            or not mask[0] & 1
            or (mask[0] & 2 and not flags[18] & 1)
            or (mask[0] & 4 and not flags[19] & 0x80)
        ):
            return 3
        bits = sum(
            value
            for byte, bit, value in (
                (18, 0x10, 0x8000),
                (18, 2, 0x800),
                (18, 1, 0x400),
                (19, 0x80, 0x200),
                (19, 0x40, 0x80),
                (19, 0x20, 0x40),
            )
            if flags[byte] & bit
        )
        data[12:14] = bits.to_bytes(2, "little")
        normalized = True
        return _normal(comm)
    finally:
        if not normalized:
            _normal(comm)


def _table_read(comm: TYComm, context: TYContext, data: bytearray, row: int) -> int:
    second, flag, size, _ = _TABLES[context.module_sha256][row]
    selected = int.from_bytes(data[12:14], "little")
    if selected & flag != flag:
        return 0
    status, payload = _read(comm, context, bytes((0x1B, second)), 0, size)
    if not status:
        data[14 + row * 6 : 14 + row * 6 + size] = payload
    return status


def _fchv11(data: bytearray, context: TYContext, comm: TYComm) -> int:
    action = _u32(data, 0)
    retain = False
    try:
        if action in (0, 1):
            status = _initialize(comm, context)
            if status:
                return status
        action = _u32(data, 0)
        if action == 0:
            return _support11(comm, context, data)
        if action == 1:
            status = _extended(comm)
            if status:
                return status
            status = _routine(comm, context, 1, 0x1A, b"\x01")
            if status:
                _normal(comm)
                return 2000
            status = _valves(comm, context, data, True, normal=False)
            if status:
                _normal(comm)
            retain = not status
            return status
        if action == 2:
            for row in range(3):
                status = _table_read(comm, context, data, row)
                if status:
                    _normal(comm)
                    return 2000
                _, flag, _, offset = _TABLES[context.module_sha256][row]
                if (
                    int.from_bytes(data[12:14], "little") & flag == flag
                    and data[14 + row * 6 + offset : 16 + row * 6 + offset]
                    < b"\x70\x61"
                ):
                    _normal(comm)
                    return 2002
            status = _valves(comm, context, data, True, normal=False)
            if status:
                _normal(comm)
            retain = not status
            return status
        if action in (3, 4, 5):
            status = _valves(comm, context, data, action == 3, wait=action != 5)
            retain = action == 5 or not status
            return status
        if action == 6:
            _io(comm, context, 0x0C, 0, bytes((0, data[0x2C] & 7)))
            _normal(comm)
            return 0
        if action in (7, 8):
            retain = True
            while True:
                _check(context)
                if _u32(data, 4):
                    return 2050
                started = context.ticks()
                for row in range(0 if action == 8 else 3, 5):
                    status = _table_read(comm, context, data, row)
                    if status:
                        if action == 7:
                            _io(comm, context, 0x0C, 0, bytes((0, data[0x2C] & 7)))
                            _normal(comm)
                        return 2000 if action == 7 else 2003
                _put(data, 8, 1)
                elapsed = elapsed_ticks(context.ticks(), started)
                if elapsed <= 200:
                    _sleep(context, 200 - elapsed)
        if action == 9:
            _normal(comm)
        return 0
    except BaseException:
        _abort(comm, context)
        retain = False
        if action != 0:
            _normal(comm)
        raise
    finally:
        if not retain:
            _finalize(comm)


def _rows12(
    comm: TYComm,
    context: TYContext,
    data: bytearray,
    count: int,
    *,
    paced: bool = False,
) -> int:
    for row in range(count):
        _check(context)
        base = row * 0x38
        if _u32(data, base + 12) == 1:
            if paced:
                _sleep(context, 200)
            status, payload = _read(
                comm,
                context,
                bytes(data[base + 8 : base + 10]),
                _u32(data, base + 24),
                2,
            )
            if status:
                return status
            data[base + 28 : base + 30] = payload
    return 0


def _support12(comm: TYComm, context: TYContext, data: bytearray) -> int:
    normalized = False
    data[0x120] = 0
    status = _initialize(comm, context)
    if status:
        return status
    status = _extended(comm)
    if status:
        return status
    try:
        status, flags = _read(comm, context, b"\x01\x01", 0, 32)
        if status:
            return status
        if not flags[3] & 0x10:
            return 3
        status, mask = _read(comm, context, b"\x28\x0c", 0, 1)
        if status:
            return status
        data[0x120] = mask[0] & 7
        status, flags = _read(comm, context, b"\x1b\x00", 0, 32)
        if status:
            return status
        for row in range(5):
            base = row * 0x38
            index = _u32(data, base + 16)
            if index >= 32:
                raise ValueError("FCHV support index exceeds source 32-byte snapshot")
            mask_byte = data[base + 20]
            if flags[index] & mask_byte == mask_byte:
                _put(data, base + 12, 1)
        mask_byte = data[0x120]
        if (
            flags[18] & 0x12 != 0x12
            or flags[19] & 0x60 != 0x60
            or (mask_byte & 2 and not flags[18] & 1)
            or (mask_byte & 4 and not flags[19] & 0x80)
        ):
            return 3
        normalized = True
        return _normal(comm)
    finally:
        if not normalized:
            _normal(comm)


def _poll12(comm: TYComm, context: TYContext, mask: int) -> int:
    status = _io(comm, context, 0x0C, 3, bytes((0, mask, 0, mask)))
    if status == 7:
        status = _status(comm.read_field("native_10b0"))
    if status:
        return 1009 if status == 105 else 1008
    started = None
    while True:
        _sleep(context, 200)
        status, payload = _read(comm, context, b"\x1b\x94", 0, 2)
        if status:
            return 1008
        if started is None:
            started = context.ticks()
        if (payload[0] ^ payload[1]) & 7 == 0:
            return 0
        if elapsed_ticks(context.ticks(), started) >= 5000:
            return 1009


def _fchv12(data: bytearray, context: TYContext, comm: TYComm) -> int:
    action = _u32(data, 0)
    mask = data[0x120]
    retain = False
    normal = False
    try:
        if action == 0:
            return _support12(comm, context, data)
        if action == 2:
            retain = True
            while True:
                status = _rows12(comm, context, data, 5, paced=True)
                if status:
                    return 1023
                if _u32(data, 0x124):
                    return 0
        if action == 3:
            normal = True
            _io(comm, context, 0x0C, 0, bytes((0, mask)))
            return 1016
        if action == 4:
            _io(comm, context, 0x0C, 3, bytes((0, 0, 0, mask)))
            retain = True
            return 1020
        normal = True
        if action == 1:
            normal = False
            status = _initialize(comm, context)
            if status:
                return status
            status = _extended(comm)
            if status:
                return status
            normal = True
            status = _routine(comm, context, 1, 0x1A, b"\x01")
            if status:
                return 1008
            status = _rows12(comm, context, data, 3)
            if status:
                return 1008
            for row in range(3):
                base = row * 0x38
                second = data[base + 9]
                if (
                    second in (0x97, 0x98, 0x99)
                    and data[0x120] & (1 << (second - 0x97))
                    and data[base + 28 : base + 30] <= b"\x70\x60"
                ):
                    return 1012
        status = _poll12(comm, context, mask)
        if status:
            _io(comm, context, 0x0C, 0, bytes((0, mask)))
            return status
        if action == 1:
            status = _rows12(comm, context, data, 5, paced=True)
            retain = True
            return 1023 if status else 0
        retain = True
        return 1026
    except BaseException:
        _abort(comm, context)
        retain = False
        normal = action != 0
        raise
    finally:
        if not retain:
            try:
                if normal:
                    _normal(comm)
            finally:
                _finalize(comm)


def _fchv04(data: bytearray, context: TYContext, comm: TYComm) -> int:
    action, dual = _u32(data, 8), _u32(data, 12) == 1
    plus = context.module_sha256 == SHA_PLUS_TY
    second = (
        context.comm("native:10135c58")
        if plus and (16 <= action <= 21 or action == 15 and dual)
        else None
    )

    def other() -> TYComm:
        nonlocal second
        if second is None:
            second = context.comm("native:10135c58")
        return second

    selected = second if 16 <= action <= 21 and second is not None else comm
    try:
        comm_to_init = (
            (comm, second)
            if action == 15 and dual and second is not None
            else (selected,)
        )
        status = 0
        for controller in comm_to_init:
            controller.configure_target(
                0x7C4 if controller is second else 0x7D2, 0, 0, 0, 0
            )
            _check(context)
            status = _status(controller.initialize(0))
            if not status:
                setters = (
                    ("native_rva:1a8c0", "native_rva:1a860", "native_rva:1a880")
                    if not plus
                    else ("native_rva:1e2d0", "native_rva:1e290", "native_rva:1e2b0")
                )
                for setter, value in zip(setters, (0, 0, 180000), strict=True):
                    controller.configure(setter, value)
            if status:
                current = _u32(data, 8)
                return (
                    0
                    if current in ((20, 21) if controller is second else (8, 9, 14, 15))
                    or action == 15
                    and dual
                    else status
                )
        action = _u32(data, 8)
        selected = other() if plus and 16 <= action <= 21 else comm
        if action == 15:
            if plus and _u32(data, 12) == 1:
                second = other()
                _sleep(context, 125)
                _exchange(comm, context, b"\x3e\x00")
                _sleep(context, 125)
                _exchange(second, context, b"\x3e\x00")
            else:
                _exchange(comm, context, b"\x3e\x00")
                _sleep(context, 500)
                _exchange(comm, context, b"\x3e\x00")
            return 0
        if action == 16 and plus:
            status, _ = _exchange(selected, context, b"\x3e\x00")
            if not status:
                _put(data, 12, 1)
            return 0
        if action in (13, 17):
            if action == 17 and not plus:
                return 0
            status = _extended(selected)
            return (
                2005
                if status and plus and action == 13 and _u32(data, 12) == 1
                else status
            )
        if action in (14, 21):
            if action == 14 or plus:
                _normal(selected)
            return 0
        if plus and action in (18, 19):
            if action != 19 and _io(selected, context, 3, 3, b"\x01\x80"):
                return 2005
            return (
                2005
                if _io(
                    selected,
                    context,
                    0x10,
                    3,
                    bytes((1 if _u32(data, 8) == 19 else 2, 0x80)),
                )
                else 0
            )
        if plus and action == 20:
            _io(selected, context, 0x10, 0, b"\x80")
            _io(selected, context, 3, 0, b"\x80")
            return 0
        if action in (8, 9):
            if action == 9:
                _io(comm, context, 9, 0, b"\x80")
            _io(comm, context, 0x0E, 0, b"\x80")
            return 0
        if action not in (3, 4, 5, 6, 7, 10, 11, 12):
            return 0
        if action in (7, 10, 11, 12):
            _io(comm, context, 0x0E, 0, b"\x80")
        speed_action = _u32(data, 8) if action in (10, 11, 12) else action
        speed = {
            3: b"\x07\xd0",
            4: b"\x09\xc4",
            5: b"\x0a\xf0",
            6: b"\x0a\xf0",
            7: b"\x09\xc4",
            10: b"\x09\xc4",
            11: b"\x0a\xf0",
            12: b"\x0a\xf0",
        }.get(speed_action)
        payload = b"\x03" + speed + b"\x80" if speed is not None else bytes(4)
        status = _echo(comm, context, b"\x2f\x28\x0e" + payload)
        if not status and action != 7:
            if action in (10, 11, 12):
                current = _u32(data, 8)
                payload = (
                    bytes((3, 1 if current in (10, 11) else 100, 0x80))
                    if current in (10, 11, 12)
                    else bytes(3)
                )
                status = _echo(comm, context, b"\x2f\x28\x09" + payload)
            else:
                status = _io(
                    comm, context, 9, 3, bytes((50 if action == 6 else 100, 0x80))
                )
        if status:
            _io(comm, context, 9, 0, b"\x80")
            _io(comm, context, 0x0E, 0, b"\x80")
            return 2002 if action in (3, 4, 5) else 2004 if action == 6 else status
        return 0
    except BaseException:
        _abort(comm, context)
        if second is not None:
            _abort(second, context)
        _normal(selected)
        raise
    finally:
        primary = _primary()
        try:
            current = _u32(data, 8)
            if plus and current == 15 and _u32(data, 12) == 1:
                try:
                    _finalize(comm)
                finally:
                    _finalize(other())
            else:
                _finalize(other() if plus and 16 <= current <= 21 else comm)
        except BaseException as error:
            if primary is None:
                raise
            primary.add_note(f"FCHV manager finalization failed: {error!r}")


def _stop03(comm: TYComm, context: TYContext, data: bytearray) -> int:
    return _io(comm, context, 0x0C, 0, bytes((0, data[0x300] & 7)))


def _poll03(
    comm: TYComm, context: TYContext, *, active: bool = True, ready: bool = False
) -> int:
    started = None
    while True:
        _sleep(context, 200)
        status, payload = _read(
            comm,
            context,
            b"\x1b\x06" if ready else b"\x1b\x94",
            1 if ready else 0,
            1 if ready else 2,
        )
        if status:
            return 2210
        if started is None:
            started = context.ticks()
        if (
            ready
            and payload[0] & 0x40
            or not ready
            and (
                (payload[0] ^ payload[1]) & 7 == 0
                if active
                else payload[0] & payload[1] & 7 == 0
            )
        ):
            return 0
        if elapsed_ticks(context.ticks(), started) >= (5001 if ready else 5000):
            return 2226


def _stream03(comm: TYComm, context: TYContext, data: bytearray, action: int) -> int:
    orders = [
        _u32(data, 4 + row * 44 + (24 if action == 6 else 28 if action == 7 else 32))
        for row in range(17)
    ]
    started = None
    status = 0
    while True:
        _check(context)
        for priority in range(1, 15 if action == 6 else 13 if action == 7 else 10):
            for row in range(17):
                base = 4 + row * 44
                order = _u32(data, base + 32) if action == 8 else orders[row]
                if order != priority or not _u32(data, base + 12):
                    continue
                status, payload = _read(
                    comm,
                    context,
                    bytes(data[base : base + 2]),
                    _u32(data, base + 16),
                    2,
                )
                if status:
                    if action != 8:
                        return status
                    continue
                did = bytes(data[base : base + 2])
                if did == b"\x1b\x94":
                    if row + 6 > 17:
                        raise ValueError(
                            "FCHV grouped valve rows exceed native 17-row array"
                        )
                    for sub in range(6):
                        output = base + sub * 44
                        data[output + 36] = 0
                        data[output + 37] = int(
                            bool(payload[sub // 3] & data[output + 21])
                        )
                        _put(data, output + 40, 1)
                else:
                    data[base + 36] = (
                        0 if did == b"\x1b\x06" else payload[0] & data[base + 20]
                    )
                    data[base + 37] = (
                        int(bool(payload[1] & data[base + 21]))
                        if did == b"\x1b\x06"
                        else payload[1] & data[base + 21]
                    )
                    _put(data, base + 40, 1)
            if (
                action == 8
                and started is not None
                and elapsed_ticks(context.ticks(), started) >= 5000
            ):
                return status
            if action != 8 and _u32(data, 0x2FC):
                return status
        if action == 8:
            if started is None:
                started = context.ticks()
            if elapsed_ticks(context.ticks(), started) >= 5000:
                return status


def _fchv03(data: bytearray, context: TYContext, comm: TYComm) -> int:
    action = _u32(data, 0)
    finalized = False
    try:
        if action in (0, 14):
            status = _initialize(comm, context)
            if status:
                _finalize(comm)
                return status
            status = _extended(comm)
            if status:
                _finalize(comm)
                return status
            if action == 14:
                status = _routine(comm, context, 1, 0x1A, b"\x01")
                if not status:
                    return 0
                _finish(comm)
                return 2207
            normalized = False
            try:
                status, flags = _read(comm, context, b"\x01\x01", 3, 1)
                if status:
                    return status
                if flags[0] & 0x10:
                    status, flags = _read(comm, context, b"\x1b\x00", 0, 20)
                    if status:
                        return status
                    for row in range(17):
                        base = 4 + row * 44
                        index = _u32(data, base + 4)
                        if index >= 20:
                            raise ValueError(
                                "FCHV support row exceeds native 20-byte snapshot"
                            )
                        if flags[index] & data[base + 8]:
                            _put(data, base + 12, 1)
                status, mask = _read(comm, context, b"\x28\x0c", 0, 1)
                if not status:
                    data[0x300] = mask[0] & 7
                    normalized = True
                    return _normal(comm)
                return status
            finally:
                finalized = True
                try:
                    if not normalized:
                        _normal(comm)
                finally:
                    _finalize(comm)
        if action in (2, 3):
            mask = data[0x300]
            status = _io(comm, context, 0x0C, 3, bytes((0, mask, 0, mask)))
            if status:
                _stop03(comm, context, data)
                _finish(comm)
                return 2205
            status = _poll03(comm, context)
            if not status:
                _sleep(context, 3000 if action == 2 else 2000)
                _put(data, 0x304, 1 if action == 2 else 4)
                status = _routine(comm, context, 1, 0x19, b"\xc8")
                if not status:
                    _sleep(context, 3000)
                    return 2224
                status = 2226
                _routine(comm, context, 2, 0x19)
            _stop03(comm, context, data)
            return status
        if action == 4:
            status = _routine(comm, context, 1, 0x16)
            if not status:
                status = _poll03(comm, context, ready=True)
                if not status:
                    return 2227 if _u32(data, 0x304) in (1, 2, 4) else 2219
            _routine(comm, context, 2, 0x16)
            if _u32(data, 0x304) not in (1, 2, 4):
                _finish(comm)
                return 2225
            _stop03(comm, context, data)
            return status
        if action == 5:
            _routine(comm, context, 2, 0x16)
            phase = _u32(data, 0x304)
            if phase in (1, 4):
                if phase == 1:
                    _put(data, 0x304, 2)
                status = _routine(comm, context, 1, 0x19, b"\xc8")
                if not status:
                    _sleep(context, 3000)
                    return 2224 if phase == 1 else 2215
                _routine(comm, context, 2, 0x19)
                _stop03(comm, context, data)
                return 2226
            if phase == 2:
                status = _io(comm, context, 0x0C, 3, bytes((0, 0, 0, data[0x300])))
                if not status:
                    status = _poll03(comm, context, active=False)
                    if not status:
                        return 2213
                _stop03(comm, context, data)
                return status if status == 2210 else 2226
            if phase == 3:
                return 2214
            _finish(comm)
            return 2220 if phase == 5 else 99
        if action in (6, 7, 8):
            return _stream03(comm, context, data, action)
        if action in (15, 16):
            if action == 16:
                _routine(comm, context, 2, 0x19)
            _stop03(comm, context, data)
            return 2210
        if action == 17:
            _routine(comm, context, 2, 0x19)
            return 2218 if _u32(data, 0x304) in (1, 2, 4) else 2223
        _finish(comm)
        return 0
    except BaseException:
        _abort(comm, context)
        if not finalized:
            _finish(comm)
        raise


def _stop17(comm: TYComm, context: TYContext, data: bytearray) -> int:
    status = _u32(data, 12)
    try:
        for second in (11, 10, 20):
            _io(comm, context, second, 0, b"\x80")
        _routine(comm, context, 2, 0x16)
    finally:
        _finish(comm)
    return status


def _ready17(comm: TYComm, context: TYContext) -> int:
    started = None
    while True:
        _sleep(context, 200)
        status, payload = _read(comm, context, b"\x1b\xbf", 1, 1)
        if status:
            return status
        if started is None:
            started = context.ticks()
        if payload[0] & 0x40:
            return 0
        if elapsed_ticks(context.ticks(), started) >= 5000:
            return 1007


def _fchv17(data: bytearray, context: TYContext, comm: TYComm) -> int:
    action = _u32(data, 0)
    try:
        if action == 0:
            status = _initialize(comm, context)
            if not status:
                status = _extended(comm)
                if not status:
                    # Literal ASM stores 1 in the stack byte omitted by the C decompiler.
                    status = _routine(comm, context, 1, 0x1A, b"\x01")
                    if not status:
                        return 0
                    _normal(comm)
                    status = 1006
            _finalize(comm)
            return status
        if action != 1:
            return _stop17(comm, context, data)
        _put(data, 12, 1007)
        started = context.ticks()
        for index, second in enumerate((11, 10, 20)):
            status = _io(comm, context, second, 3, b"\x64\x80")
            if status:
                for cleanup in (11, 10, 20)[: index + 1]:
                    _io(comm, context, cleanup, 0, b"\x80")
                _finish(comm)
                return 1007
            if index == 0:
                started = context.ticks()
        status = _routine(comm, context, 1, 0x16)
        if status:
            return _stop17(comm, context, data)
        status = _ready17(comm, context)
        if status:
            return _stop17(comm, context, data)
        _put(data, 4, 1)
        enabled_since = context.ticks()
        stopped_since = None
        while True:
            _check(context)
            if _u32(data, 8) == 1:
                _put(data, 12, 1010)
                return 0
            status, payload = _read(comm, context, b"\x1b\xbf", 1, 1)
            if status:
                return 1006
            if elapsed_ticks(context.ticks(), started) >= 480000:
                return 1005
            if (
                enabled_since is not None
                and elapsed_ticks(context.ticks(), enabled_since) < 230000
            ):
                stop = not payload[0] & 0x40
            else:
                stop = stopped_since is None
            if stop:
                enabled_since = None
                if _routine(comm, context, 2, 0x16):
                    return 1007
                stopped_since = context.ticks()
            elif (
                stopped_since is not None
                and elapsed_ticks(context.ticks(), stopped_since) >= 5000
            ):
                _sleep(context, 500)
                if _routine(comm, context, 1, 0x16):
                    return 1007
                if _ready17(comm, context):
                    return 1007
                stopped_since = None
                enabled_since = context.ticks()
    except BaseException:
        _abort(comm, context)
        _finish(comm)
        raise


def run_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    if (
        export not in supported_exports(context.module_sha256)
        or hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256
    ):
        raise TYSourceError(
            "Exact reviewed FCHV actions source/export identity required"
        )
    return _run(export, args, context)


def _classic04(data: bytearray, context: TYContext) -> int:
    comm = context.comm("selected")
    try:
        comm.select_target(0x7C4, 0)
        status = _status(comm.initialize(0))
        if status:
            return 0 if _u32(data, 8) == 2 else status
        comm.configure(
            "native_rva:12180"
            if context.module_sha256 == SHA_18_TY
            else "native_rva:142f0",
            150,
        )
        action = _u32(data, 8)
        if action == 2:
            _exchange(comm, context, b"\x30")
        elif action in (0, 1):
            request = b"\x30\x19\x00\x02\x02"
            status, reply = _exchange(comm, context, request)
            if status or len(reply) < 2 or reply[1] != request[1]:
                return 2003
            _put(data, 4, context.ticks())
            request = bytes((0x30, 0x18, 0, int(_u32(data, 8) != 0) + 1))
            status, reply = _exchange(comm, context, request)
            if status or len(reply) < 2 or reply[1] != request[1]:
                return 2003
        return 0
    finally:
        if _primary() is not None:
            _abort(comm, context)
        _finalize(comm)


def _dispatch(export: str, args: tuple[object, ...], context: TYContext) -> int:
    group = export.split("_")[1]
    minimum = {"03": 0x308, "04": 16, "11": 48, "12": 0x128, "17": 16}[group]
    if (
        type(args) is not tuple
        or len(args) != 1
        or type(args[0]) is not bytearray
        or not minimum <= len(args[0]) <= 65536
    ):
        raise ValueError(
            "FCHV action requires one bounded mutable native argument block"
        )
    data = args[0]
    try:
        _check(context)
    except BaseException:
        for controller, pending in tuple(_outputs(context).values()):
            if pending:
                _abort(controller, context)
                _normal(controller)
                _finalize(controller)
        raise
    if group == "04" and context.mode == 4:
        return _classic04(data, context)
    comm = context.comm(_MANAGERS[context.module_sha256])
    return {"03": _fchv03, "04": _fchv04, "11": _fchv11, "12": _fchv12, "17": _fchv17}[
        group
    ](data, context, comm)


def _run(export: str, args: tuple[object, ...], context: TYContext) -> int:
    ambient = sys.exception()
    token = _OPERATION.set(
        (ambient, ambient.__traceback__ if ambient is not None else None)
    )
    try:
        return _dispatch(export, args, context)
    finally:
        _OPERATION.reset(token)
