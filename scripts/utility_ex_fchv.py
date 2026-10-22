"""Source-bound FCHV tank-valve and value-buffer workers.

Native argument blocks remain mutable byte arrays; dynamic pointers use an owned
FCHVValues buffer. Scheduling and wrapper mode predicates belong to utility_ex.
"""

from __future__ import annotations

import hashlib
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from types import TracebackType

from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import (
    SHA_18_TY,
    SHA_PLUS_TY,
    TYComm,
    TYContext,
    TYSourceError,
    elapsed_ticks,
)

_TANK_SUFFIXES = (
    "AutoPowerOFFCancel",
    "SupportCheck",
    "ReadTankShutValveStart",
    "ReadTankShutValveOpen",
    "ReadTankShutValveClose",
    "ReadTemperature",
    "TankShutValveDrive",
    "ReadTankShutValveRetrun",
    "ReadPressure",
    "TankShutValveStop",
)
_VALUES = ("Ex2FCHV_07_ReadValues", "Ex2FCHV_08_ReadValues", "Ex2FCHV_08_WriteValues")
_EXPORTS = {
    SHA_18_TY: tuple(f"Ex2FCHV_02_{suffix}" for suffix in _TANK_SUFFIXES) + _VALUES,
    SHA_PLUS_TY: tuple(f"Ex2FCHV_02_{suffix}" for suffix in _TANK_SUFFIXES)
    + tuple(
        f"Ex2FCHV_26_{suffix}"
        for suffix in _TANK_SUFFIXES
        if suffix != "AutoPowerOFFCancel"
    )
    + ("Ex2FCHV_26_ReadData",)
    + _VALUES,
}
_MANAGERS = {SHA_18_TY: "native:1011d4f0", SHA_PLUS_TY: "native:101392d0"}
_SETTERS = {
    SHA_18_TY: ("native_rva:1a860", "native_rva:1a880", "native_rva:1a8c0"),
    SHA_PLUS_TY: ("native_rva:1e290", "native_rva:1e2b0", "native_rva:1e2d0"),
}


@dataclass
class FCHVValues:
    """Owned native pointer/length pair followed by the three selection DWORDs."""

    data: bytearray = field(default_factory=bytearray)
    selected: tuple[int, int, int] = (0, 0, 0)


def supported_exports(module_sha256: str) -> tuple[str, ...]:
    return _EXPORTS.get(module_sha256, ())


def _check(context: TYContext) -> None:
    if context.is_cancelled():
        raise Cancelled("FCHV operation cancelled")


def _status(value: int) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise TypeError("FCHV communication status must be uint32")
    return value


def _exchange(
    comm: TYComm, context: TYContext, request: bytes, *, check_cancel: bool = True
) -> tuple[int, bytes]:
    if check_cancel:
        _check(context)
    status, reply = (
        comm.exchange(request) if check_cancel else comm.cleanup_exchange(request)
    )
    _status(status)
    if type(reply) is not bytes or len(reply) > 4128:
        raise ValueError("FCHV reply exceeds the native immutable buffer")
    return status, reply


_OPERATION: ContextVar[tuple[BaseException | None, TracebackType | None] | None] = (
    ContextVar("fchv-tank-values-operation", default=None)
)


@contextmanager
def _operation() -> Iterator[None]:
    ambient = sys.exception()
    token = _OPERATION.set(
        (ambient, ambient.__traceback__ if ambient is not None else None)
    )
    try:
        yield
    finally:
        _OPERATION.reset(token)


def _primary() -> BaseException | None:
    baseline = _OPERATION.get()
    current = sys.exception()
    if baseline is None or current is None:
        return None
    if current is baseline[0] and current.__traceback__ is baseline[1]:
        return None
    return current


def _cleanup(*actions: Callable[[], object]) -> None:
    """Attempt every release while preserving an in-flight host exception."""
    primary = _primary()
    failure: BaseException | None = None
    for action in actions:
        try:
            action()
        except BaseException as error:  # noqa: BLE001 - retain primary while all releases run
            if primary is not None:
                primary.add_note(f"FCHV cleanup failed: {error!r}")
            elif failure is None:
                failure = error
            else:
                failure.add_note(f"FCHV cleanup failed: {error!r}")
    if primary is None and failure is not None:
        raise failure


def _initialize(comm: TYComm, context: TYContext) -> int:
    _check(context)
    status = _status(comm.initialize(0))
    if not status:
        for setter, value in zip(
            _SETTERS[context.module_sha256], (0, 180000, 0), strict=True
        ):
            comm.configure(setter, value)
    return status


def _normal(comm: TYComm) -> int:
    return _status(comm.session(1, 1))


def _normal_on_exit(comm: TYComm) -> int:
    if _primary() is not None:
        return _status(comm.cleanup_session(1, 1, stop_on_error=True))
    return _normal(comm)


def _extended(comm: TYComm) -> int:
    return _status(comm.session(3, 1, normal_first=True))


def _mapped_nrc(comm: TYComm) -> int:
    return _status(comm.read_field("native_10b0"))


def _u32(data: bytearray, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _put(data: bytearray, offset: int, value: int) -> None:
    data[offset : offset + 4] = value.to_bytes(4, "little")


def _tank_buffer(args: tuple[object, ...], newer: bool) -> bytearray:
    if (
        type(args) is not tuple
        or len(args) != 1
        or type(args[0]) is not bytearray
        or not (0xC4 if newer else 0x13C) <= len(args[0]) <= 65536
    ):
        raise ValueError("FCHV requires one bounded mutable native tank block")
    return args[0]


def _validate_read_rows(
    data: bytearray, rows: range, *, unconditional: bool = False
) -> None:
    for row in rows:
        base = row * 0x38
        if not unconditional and not _u32(data, base + 0x2C):
            continue
        offset, size = _u32(data, base + 4), _u32(data, base + 12)
        # The native DID helper produces 2 or 4 bytes; reject reads of its stack tail.
        capacity = 2 if data[base + 1] in (0x9A, 0x9B) else 4
        if size > 8 or offset + size > capacity:
            raise ValueError("FCHV tank descriptor exceeds the recovered DID payload")


def _read_did(
    comm: TYComm, context: TYContext, first: int, second: int
) -> tuple[int, bytes]:
    status, reply = _exchange(comm, context, bytes((0x22, first, second)))
    size = 2 if second in (0x9A, 0x9B) else 4
    if not status and (len(reply) < size + 3 or reply[1:3] != bytes((first, second))):
        return 3, b""
    return status, reply[3 : 3 + size]


def _write_row(data: bytearray, base: int, payload: bytes) -> None:
    offset, size = _u32(data, base + 4), _u32(data, base + 12)
    if size > 8 or offset + size > len(payload):
        raise ValueError("FCHV live descriptor exceeds the actual returned DID payload")
    data[base + 0x30 : base + 0x30 + size] = payload[offset : offset + size]


def _read_rows(comm: TYComm, context: TYContext, data: bytearray, rows: range) -> int:
    for row in rows:
        _check(context)
        base = row * 0x38
        if _u32(data, base + 0x2C):
            status, payload = _read_did(comm, context, data[base], data[base + 1])
            if status:
                return status
            _write_row(data, base, payload)
    return 0


def _stream(
    comm: TYComm, context: TYContext, data: bytearray, newer: bool, count: int
) -> int:
    row = 2 if count == (3 if newer else 5) else 0
    stop = 0xAC if newer else 0x11C
    pressure_ready, all_ready = (0xB4, 0xB8) if newer else (0x124, 0x128)
    started = context.ticks()
    while True:
        status = _read_rows(comm, context, data, range(row, row + 1))
        if status:
            return status
        if row == 1:
            elapsed = elapsed_ticks(context.ticks(), started)
            if elapsed < 200:
                _check(context)
                context.native_sleep(200 - elapsed)
                _check(context)
            started = context.ticks()
        if row == count - 1:
            row = 0
            ready = all_ready if count == (3 if newer else 5) else pressure_ready
            if not _u32(data, ready):
                _put(data, ready, 1)
        else:
            row += 1
        if _u32(data, stop):
            return 0


def _mask(data: bytearray) -> int:
    return sum((1 << index) for index in range(3) if _u32(data, 0x12C + 4 * index))


def _drive(
    comm: TYComm, context: TYContext, data: bytearray, newer: bool, enabled: bool
) -> int:
    if newer:
        mask = bytes((0, data[0xBC], 0, data[0xBD], 0, data[0xBE], 0, data[0xBF]))
        request = b"\x2f\x28\x1f\x03" + (mask if enabled else bytes(8)) + mask
        echo = b"\x28\x1f\x03"
    else:
        mask_byte = _mask(data)
        request = b"\x2f\x28\x0c\x03\0" + bytes(
            (mask_byte if enabled else 0, 0, mask_byte)
        )
        echo = b"\x28\x0c\x03"
    status, reply = _exchange(comm, context, request)
    if status == 7:
        return _mapped_nrc(comm)
    if not status and (len(reply) < 6 or reply[1:4] != echo):
        return 3
    return status


def _stop(
    comm: TYComm,
    context: TYContext,
    data: bytearray,
    newer: bool,
    *,
    check_cancel: bool = True,
) -> int:
    if newer:
        request = b"\x2f\x28\x1f\0\0" + bytes(
            (data[0xBC], 0, data[0xBD], 0, data[0xBE], 0, data[0xBF])
        )
        echo = b"\x28\x1f\0\0" + bytes((data[0xBC],))
    else:
        request = b"\x2f\x28\x0c\0\0" + bytes((_mask(data),))
        echo = request[1:]
    status, reply = _exchange(comm, context, request, check_cancel=check_cancel)
    if not status and (len(reply) < 6 or reply[1:6] != echo):
        return 3
    return status


def _poll(
    comm: TYComm, context: TYContext, data: bytearray, newer: bool, enabled: bool
) -> int:
    status = _drive(comm, context, data, newer, enabled)
    if status:
        return status
    started: int | None = None
    while True:
        _check(context)
        context.native_sleep(200)
        did = b"\x1b\xbe" if newer else b"\x1b\x94"
        status, reply = _exchange(comm, context, b"\x22" + did)
        if status:
            return status
        if len(reply) < (11 if newer else 5) or reply[1:3] != did:
            return 3
        if started is None:
            started = context.ticks()
        if newer:
            actual = reply[3:11]
            bits = (actual[1], actual[3], actual[5], actual[7])
            expected = (data[0xBC], data[0xBD], data[0xBE], data[0xBF] & 7)
            settled = all(
                (got & wanted) == wanted if enabled else (got & wanted) == 0
                for got, wanted in zip(bits, expected, strict=True)
            )
        else:
            selected, actual = reply[3], reply[4]
            settled = all(
                not selected & bit or bool(actual & bit) == enabled for bit in (1, 2, 4)
            )
        if settled:
            return 0
        if elapsed_ticks(context.ticks(), started) >= 5000:
            return 1005


def _support(comm: TYComm, context: TYContext, data: bytearray, newer: bool) -> int:
    status, reply = _exchange(comm, context, b"\x22\x01\x01")
    if status:
        return status
    if len(reply) != 35 or reply[1:3] != b"\x01\x01":
        return 3
    if not reply[6] & 0x10:
        return 1001
    if newer:
        data[0xBC:0xC0] = bytes(4)
        status, reply = _exchange(comm, context, b"\x22\x28\x1f")
        if status:
            return status
        if len(reply) < 11 or reply[1:3] != b"\x28\x1f":
            return 3
        data[0xBC:0xC0] = bytes((reply[3], reply[5], reply[7], reply[9] & 7))
        for offset in (0x2C, 0x64, 0x9C, 0xC0):
            _put(data, offset, 0)
    else:
        for offset in (0x12C, 0x130, 0x134):
            _put(data, offset, 0)
        status, reply = _exchange(comm, context, b"\x22\x28\x0c")
        if status:
            return status
        if len(reply) < 4 or reply[1:3] != b"\x28\x0c":
            return 3
        for index in range(3):
            if reply[3] & (1 << index):
                _put(data, 0x12C + 4 * index, 1)
        _put(data, 0x138, 0)
    status, reply = _exchange(comm, context, b"\x22\x1b\0")
    if status:
        return status
    if len(reply) != 35 or reply[1:3] != b"\x1b\0":
        return 3
    if newer:
        if reply[26] & 4:
            _put(data, 0xC0, 1)
        for row in range(3):
            if data[row * 0x38 + 1] == 0x9B and reply[22] & 0x20:
                _put(data, row * 0x38 + 0x2C, 1)
        status, reply = _exchange(comm, context, b"\x22\x1b\xcf")
        if status:
            return status
        if len(reply) < 8 or reply[1:3] != b"\x1b\xcf":
            return 3
        for row in range(3):
            second = data[row * 0x38 + 1]
            if (second == 0xAE and reply[3] & 0x80) or (
                second == 0x9A and reply[7] & 4
            ):
                _put(data, row * 0x38 + 0x2C, 1)
        if not _u32(data, 0xC0) or any(
            not _u32(data, row * 0x38 + 0x2C) for row in range(3)
        ):
            return 1001
    else:
        if reply[21] & 0x10:
            _put(data, 0x138, 1)
        for row in range(5):
            base = row * 0x38
            second = data[base + 1]
            if (
                (second == 0x97 and reply[21] & 2)
                or (second == 0x9A and reply[22] & 0x40)
                or (second == 0x9B and reply[22] & 0x20)
                or (second == 0x98 and reply[21] & 1)
                or (second == 0x99 and reply[22] & 0x80)
            ):
                _put(data, base + 0x2C, 1)
        for row in range(5):
            base = row * 0x38
            second = data[base + 1]
            available = _u32(data, base + 0x2C)
            chosen = _u32(data, 0x130) if second == 0x98 else _u32(data, 0x134)
            if not available:
                if second not in (0x98, 0x99) or chosen:
                    return 1001
            elif second in (0x98, 0x99) and not chosen:
                _put(data, base + 0x2C, 0)
        if not _u32(data, 0x138):
            return 1001
    return 0


def _temperature(
    comm: TYComm, context: TYContext, data: bytearray, newer: bool
) -> tuple[int, bool]:
    if newer:
        # ce4e0 reads the third row unconditionally, unlike the old selected loop.
        base = 0x70
        status, payload = _read_did(comm, context, data[base], data[base + 1])
        if not status:
            _write_row(data, base, payload)
    else:
        status = _read_rows(comm, context, data, range(2, 5))
    if status:
        return status, False
    acceptable = True
    for row in range(3 if newer else 5):
        base = row * 0x38
        if newer:
            if (
                data[base + 1] == 0xAE
                and int.from_bytes(data[base + 0x30 : base + 0x32], "big", signed=True)
                <= -3277
            ):
                acceptable = False
        elif data[base + 1] in (0x97, 0x98, 0x99):
            chosen = _u32(data, 0x12C + 4 * (data[base + 1] - 0x97))
            if chosen:
                size = _u32(data, base + 12)
                if size > 2:
                    raise ValueError(
                        "FCHV temperature comparison exceeds native two-byte threshold"
                    )
                if data[base + 0x30 : base + 0x30 + size] <= b"\x70\x60"[:size]:
                    acceptable = False
    if not acceptable:
        return 1002, False
    return _poll(comm, context, data, newer, True), True


def _auto_power(args: tuple[object, ...], context: TYContext) -> int:
    with _operation():
        return _auto_power_body(args, context)


def _auto_power_body(args: tuple[object, ...], context: TYContext) -> int:
    if (
        type(args) is not tuple
        or len(args) != 1
        or type(args[0]) is not bytearray
        or not 0x11C <= len(args[0]) <= 65536
    ):
        raise ValueError("FCHV AutoPower requires a bounded mutable status block")
    data = args[0]
    comm = context.comm(_MANAGERS[context.module_sha256])
    target = comm.read_target()
    if (
        type(target) is not tuple
        or len(target) != 2
        or any(
            type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in target
        )
    ):
        raise TYSourceError("FCHV target snapshot requires two source broker DWORDs")
    try:
        comm.configure_target(0x750, 0xE9, 0, 0, 0)
        comm.select_protocol(0x11)
        status = _initialize(comm, context)
        if not status:
            if _u32(data, 0x118) == 1007:
                status, _ = _exchange(comm, context, b"\x3e\0")
                _put(data, 0x118, status)
            if not _u32(data, 0x118):
                status = _normal(comm)
                if not status:
                    status = _status(comm.session(3, 1))
                    if not status:
                        try:
                            status, reply = _exchange(comm, context, b"\x22\x20\x01")
                            if not status:
                                if len(reply) < 5:
                                    raise ValueError(
                                        "FCHV AutoPower successful reply lacks native flag byte"
                                    )
                                if not reply[4] & 0x40:
                                    payload = bytearray(reply[3:])
                                    payload[1] |= 0x40
                                    _exchange(comm, context, b"\x2e\x20\x01" + payload)
                        finally:
                            _cleanup(lambda: _normal_on_exit(comm))
        return 1009
    finally:
        _cleanup(
            comm.finalize,
            lambda: comm.select_protocol(0),
            lambda: comm.configure_target(target[0], target[1], 0, 0, 0),
        )


def _tank(export: str, args: tuple[object, ...], context: TYContext) -> int:
    with _operation():
        return _tank_body(export, args, context)


def _tank_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    newer = export.startswith("Ex2FCHV_26_")
    suffix = export.split("_", 2)[2]
    data = _tank_buffer(args, newer)
    if suffix in ("ReadData", "ReadPressure"):
        _validate_read_rows(
            data, range(2 if suffix == "ReadPressure" else (3 if newer else 5))
        )
    elif suffix == "ReadTemperature":
        _validate_read_rows(data, range(2, 3 if newer else 5), unconditional=newer)
    comm = context.comm(_MANAGERS[context.module_sha256])
    # Native successful start/poll/read workers retain the initialized controller.
    retain = False
    release_on_fault = suffix not in (
        "SupportCheck",
        "ReadTankShutValveStart",
        "TankShutValveStop",
    )
    normal_needed = suffix not in ("SupportCheck", "ReadTankShutValveStart")
    try:
        if suffix == "SupportCheck":
            status = _initialize(comm, context)
            if status:
                return status
            status = _extended(comm)
            if status:
                return 1000
            normal_needed = True
            status = _support(comm, context, data, newer)
            if not status:
                normal_needed = False
                return 1000 if _normal(comm) else 0
            return status
        if suffix == "ReadTankShutValveStart":
            status = _initialize(comm, context)
            if status:
                return 1000
            status = _extended(comm)
            if status:
                return 1000
            normal_needed = True
            status, reply = _exchange(comm, context, b"\x31\x01\x11\x1a\x01")
            if not status and (len(reply) < 4 or reply[1:4] != b"\x01\x11\x1a"):
                status = 3
            if status:
                return status
            release_on_fault = True
            status = _poll(comm, context, data, newer, True)
            if status:
                _stop(comm, context, data, newer)
                return status
            retain = True
            return 0
        if suffix == "TankShutValveStop":
            _stop(comm, context, data, newer)
            return 1004
        if suffix == "TankShutValveDrive":
            _drive(comm, context, data, newer, False)
            retain = True
            return 1010
        if suffix in ("ReadData", "ReadPressure"):
            status = _stream(
                comm,
                context,
                data,
                newer,
                (3 if newer else 5) if suffix == "ReadData" else 2,
            )
            if suffix == "ReadData":
                retain = True
                return status
        elif suffix == "ReadTemperature":
            status, stop_on_error = _temperature(comm, context, data, newer)
            if status:
                if stop_on_error:
                    _stop(comm, context, data, newer)
                return status
        else:
            status = _poll(
                comm, context, data, newer, suffix != "ReadTankShutValveClose"
            )
            if not status:
                retain = True
                return {
                    "ReadTankShutValveClose": 1012,
                    "ReadTankShutValveRetrun": 1011,
                }.get(suffix, 0)
        if status:
            _stop(comm, context, data, newer)
        else:
            retain = True
        return status
    except BaseException:
        if release_on_fault:
            # HOST release uses the bounded lower cleanup scope; global cancel stays set.
            _cleanup(lambda: _stop(comm, context, data, newer, check_cancel=False))
        raise
    finally:
        if not retain:
            if normal_needed:
                _cleanup(lambda: _normal_on_exit(comm), comm.finalize)
            else:
                _cleanup(comm.finalize)


def _values_argument(args: tuple[object, ...]) -> FCHVValues:
    if type(args) is not tuple or len(args) != 1 or type(args[0]) is not FCHVValues:
        raise ValueError("FCHV values require one owned pointer/length descriptor")
    value = args[0]
    if (
        type(value.data) is not bytearray
        or len(value.data) > 12387
        or type(value.selected) is not tuple
        or len(value.selected) != 3
        or any(
            type(flag) is not int or not 0 <= flag <= 0xFFFFFFFF
            for flag in value.selected
        )
    ):
        raise ValueError("Invalid bounded FCHV value buffer or selection DWORDs")
    return value


def _read_value(
    comm: TYComm, context: TYContext, did: bytes, minimum: int
) -> tuple[int, bytes]:
    status, reply = _exchange(comm, context, b"\x22" + did)
    if status:
        return status, b""
    if len(reply) < minimum or reply[1:3] != did:
        return 3, b""
    return 0, did + (len(reply) - 3).to_bytes(2, "big") + reply[3:]


def _records(data: bytearray) -> dict[bytes, bytes]:
    result: dict[bytes, bytes] = {}
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise ValueError("Truncated FCHV value record header")
        length = int.from_bytes(data[offset + 2 : offset + 4], "big")
        end = offset + 4 + length
        if length > 4125 or end > len(data):
            raise ValueError("FCHV value record exceeds owned buffer")
        # Native scan picks the first record with this DID.
        result.setdefault(
            bytes(data[offset : offset + 2]), bytes(data[offset + 4 : end])
        )
        offset = end
    return result


def _values(export: str, args: tuple[object, ...], context: TYContext) -> int:
    with _operation():
        return _values_body(export, args, context)


def _values_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    value = _values_argument(args)
    writing = export == "Ex2FCHV_08_WriteValues"
    if export == "Ex2FCHV_08_ReadValues" and len(value.data) < 7:
        raise ValueError("FCHV comparison requires two bytes at native offset5")
    comm = context.comm(_MANAGERS[context.module_sha256])
    session = False
    try:
        status = _initialize(comm, context)
        if status:
            return status
        status = _extended(comm)
        if status:
            return status
        session = True
        _values_argument(args)
        if export == "Ex2FCHV_07_ReadValues":
            value.data.clear()
            parts = [b"", b"", b""]
            for index, (did, minimum) in enumerate(
                zip(
                    (b"\x20\x05", b"\x20\x10", b"\x20\x11"),
                    (6, 213, 75),
                    strict=True,
                )
            ):
                _values_argument(args)
                if value.selected[index]:
                    status, parts[index] = _read_value(comm, context, did, minimum)
                    if status:
                        return status
            output = bytearray()
            for index, part in enumerate(parts):
                _values_argument(args)
                if value.selected[index]:
                    output.extend(part)
            value.data[:] = output
            return 0
        if not writing:
            status, actual = _read_value(comm, context, b"\x20\x05", 6)
            if not status:
                _values_argument(args)
                if len(value.data) < 7:
                    raise ValueError(
                        "FCHV comparison requires two bytes at native offset5"
                    )
                if value.data[5:7] != actual[5:7]:
                    return 99
            return status
        records = _records(value.data)
        selected_payloads = [
            (did, records.get(did, b""))
            for index, did in enumerate((b"\x20\x05", b"\x20\x10", b"\x20\x11"))
            if value.selected[index]
        ]
        for did, payload in selected_payloads:
            if payload:
                if did == b"\x20\x05":
                    payload = b"\x01" + payload[1:]
                status, reply = _exchange(comm, context, b"\x2e" + did + payload)
                if status or len(reply) < 3 or reply[1:3] != did:
                    return 1000
        return 0
    finally:
        if session:
            _cleanup(lambda: _normal_on_exit(comm), comm.finalize)
        else:
            _cleanup(comm.finalize)


def run_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    """Dispatch only complete workers from the exact source identity."""
    if (
        export not in supported_exports(context.module_sha256)
        or hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256
    ):
        raise TYSourceError("Exact reviewed FCHV source/export identity required")
    if export in _VALUES:
        return _values(export, args, context)
    if export == "Ex2FCHV_02_AutoPowerOFFCancel":
        return _auto_power(args, context)
    return _tank(export, args, context)
