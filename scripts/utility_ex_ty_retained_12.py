"""Exact retained TY GWY/STRACT/LAMP/ABG/EOM native business operations.

Mutable native structures are bytearrays, DWORDs are little endian. No OEM code
is loaded. The selected communication controller owns transport and keepalive.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import (
    SHA_12_TY,
    SHA_18_TY,
    SHA_PLUS_TY,
    TYComm,
    TYContext,
    TYSourceError,
)

_RETAINED = (
    "Ex2GWY_02_CheckTheDtc",
    "Ex2GWY_02_EndInit",
    "Ex2GWY_02_ErrorInit",
    "Ex2GWY_02_StartInit",
    "Ex2GWY_02_StartSession",
    "Ex2GWY_03_EndInit",
    "Ex2GWY_03_StartInit",
    "Ex2GWY_03_StartInitResult",
    "Ex2STRACT_01_ModeTransition",
    "Ex2STRACT_01_SupportCheck",
    "Ex2STRACT_03_ClearZeroPointAdjustment",
    "Ex2STRACT_03_EndExtendedSessionFinal",
    "Ex2STRACT_03_StartExtendedSession",
    "Ex2STRACT_03_StartTestMode",
    "Ex2STRACT_03_StartZeroPointAdjustment",
    "Ex2STRACT_04_SendMessage",
    "Ex2LAMP_04_SendMessage",
    "Ex2ABG_02_CheckLoadSpecInfo",
    "Ex2ABG_02_StartLoadSpecInfo",
    "Ex2EOM_01_ModeTransition",
)
_LAMP = (
    "Ex2LAMP_01_HeightSensorInitializationRequest",
    "Ex2LAMP_01_SupportCheck",
)


def supported_exports(source_sha256: str) -> tuple[str, ...]:
    if source_sha256 in (SHA_18_TY, SHA_PLUS_TY):
        return _RETAINED + _LAMP
    return _LAMP if source_sha256 == SHA_12_TY else ()


def _u32(data: bytearray, offset: int = 0) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _put(data: bytearray, offset: int, value: int) -> None:
    data[offset : offset + 4] = value.to_bytes(4, "little")


def _check(context: TYContext) -> None:
    if context.is_cancelled():
        raise Cancelled("Retained TY operation cancelled")


def _sleep(context: TYContext, milliseconds: int) -> None:
    _check(context)
    context.native_sleep(milliseconds)
    _check(context)


@contextmanager
def _after(action: Callable[[], object]) -> Iterator[None]:
    try:
        yield
    except BaseException as primary:
        try:
            action()
        except BaseException as cleanup_error:  # noqa: BLE001 - retain the primary even for cancellation
            primary.add_note(f"Cleanup also failed: {cleanup_error!r}")
        raise
    else:
        action()


def _initialize(comm: TYComm, context: TYContext) -> int:
    _check(context)
    status = comm.initialize()
    if not status:
        for field, value in (
            ("native_1080", 0),
            ("native_1084", 180000),
            ("native_1064", 0),
        ):
            comm.configure(field, value)
    return status


def _exchange(
    comm: TYComm, context: TYContext, request: bytes, minimum: int, echo: int = 3
) -> tuple[int, bytes]:
    _check(context)
    status, reply = comm.exchange(request)
    if not status and (
        len(reply) < minimum or reply[1 : echo + 1] != request[1 : echo + 1]
    ):
        status = 3
    return status, reply


def _routine(
    comm: TYComm,
    context: TYContext,
    identifier: int,
    subfunction: int = 1,
    minimum: int = 4,
) -> tuple[int, bytes]:
    return _exchange(
        comm,
        context,
        b"\x31" + bytes((subfunction,)) + identifier.to_bytes(2, "big"),
        minimum,
    )


def _restore(comm: TYComm, *, stop_on_error: bool = False) -> int:
    return comm.session(1, 1, stop_on_error=stop_on_error)


def _normal(comm: TYComm) -> int:
    return _restore(comm)


def _extended(comm: TYComm) -> int:
    return comm.session(3, 1, normal_first=True)


def _cleanup(
    comm: TYComm, finish: Callable[[], None], *, stop_on_error: bool = False
) -> None:
    with _after(finish):
        _restore(comm, stop_on_error=stop_on_error)


def _abg_cleanup(comm: TYComm, context: TYContext, finish: Callable[[], None]) -> None:
    with _after(lambda: _cleanup(comm, finish)):
        _sleep(context, 50)


def _buffer(args: tuple[object, ...], minimum: int) -> bytearray:
    if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < minimum:
        raise ValueError(f"Native TY structure requires a mutable {minimum}-byte span")
    return args[0]


def _gateway(
    export: str,
    data: bytearray,
    comm: TYComm,
    context: TYContext,
    finish: Callable[[], None],
) -> int:
    if export == "Ex2GWY_02_StartInit":
        start = context.ticks()
        count = 1 if context.mode == 22 else data[4]
        for index in range(count):
            identifier = int.from_bytes(data[6 + index * 2 : 8 + index * 2], "little")
            status, _ = _routine(
                comm, context, identifier, minimum=5 if context.mode == 22 else 4
            )
            if status:
                return status
            if context.mode == 22 or not _u32(data, 16):
                break
            while True:
                _sleep(context, 200)
                status, reply = _routine(comm, context, identifier, 3, 5)
                if status:
                    return status
                if reply[4] != 1:
                    break
                if (context.ticks() - start) & 0xFFFFFFFF >= 180000:
                    return 5
            if reply[4] != 2:
                return 99
        if _u32(data, 12):
            _sleep(context, _u32(data, 12))
        return 1002
    if export == "Ex2GWY_03_StartInitResult":
        while True:
            _sleep(context, 200)
            status, reply = _routine(comm, context, 0x1114, 3, 5)
            if status or reply[4] not in (1, 2):
                return 1002
            if reply[4] == 2:
                return 1001
            if _u32(data) == 1002:
                return 5
    if export == "Ex2GWY_02_EndInit":
        with _after(finish):
            status, _ = _exchange(comm, context, b"\x14\xff\xff\xff", 0, 0)
            normal = _normal(comm)
            return status if context.mode == 22 or status else normal
    if export in ("Ex2GWY_02_ErrorInit", "Ex2GWY_03_EndInit"):
        _cleanup(comm, finish)
        return 1004 if export == "Ex2GWY_02_ErrorInit" else 0
    status = _initialize(comm, context)
    retained = False
    with _after(lambda: None if retained else finish()):
        if status:
            return status
        status = _extended(comm)
        if status:
            return status
        if export in ("Ex2GWY_02_StartSession", "Ex2STRACT_03_StartExtendedSession"):
            retained = True
            return 0
        if export == "Ex2GWY_03_StartInit":
            status, _ = _routine(comm, context, 0x1114)
            if status:
                _normal(comm)
                return 1000
            retained = True
            return 0
        status, reply = _exchange(comm, context, b"\x19\x02\x01", 3, 1)
        normal = _normal(comm)
        if status:
            return status
        if normal and context.mode != 22:
            return normal
        found = bool(
            reply[2] & 1
            and any(
                reply[i] & 0xC0 == 0xC0 and reply[i + 3] & 1
                for i in range(3, len(reply) - 3, 4)
            )
        )
        return 1000 + found


def _stract(
    export: str,
    data: bytearray,
    comm: TYComm,
    context: TYContext,
    finish: Callable[[], None],
) -> int:
    if export == "Ex2STRACT_03_EndExtendedSessionFinal":
        _cleanup(comm, finish)
        return 1005
    if export in (
        "Ex2STRACT_03_ClearZeroPointAdjustment",
        "Ex2STRACT_03_StartZeroPointAdjustment",
        "Ex2STRACT_03_StartTestMode",
    ):
        identifier = {
            "Ex2STRACT_03_ClearZeroPointAdjustment": 0x110F,
            "Ex2STRACT_03_StartZeroPointAdjustment": 0x110E,
            "Ex2STRACT_03_StartTestMode": 0x1002,
        }[export]
        status, _ = _routine(comm, context, identifier)
        if export == "Ex2STRACT_03_StartZeroPointAdjustment" and not status:
            return 1004
        if export == "Ex2STRACT_03_StartTestMode" and not status:
            while True:
                _check(context)
                if _u32(data):
                    return 1001
                status, reply = _routine(comm, context, 0x1002, 3, 5)
                if status or reply[4] not in (1, 2):
                    status = 1000
                    break
                if reply[4] == 2:
                    return 1002
        if status and (
            export != "Ex2STRACT_03_StartTestMode" or status not in (1001, 1002)
        ):
            _cleanup(comm, finish)
        return status
    if export == "Ex2STRACT_04_SendMessage":
        action = _u32(data)
        if action == 0:
            status = _initialize(comm, context)
            if not status:
                status = _extended(comm)
            if status:
                finish()
            return status
        if action == 1:
            status, _ = _routine(comm, context, 0x1002)
            if not status:
                if _u32(data, 4) == 1:
                    return 0
                while True:
                    status, reply = _routine(comm, context, 0x1002, 3, 5)
                    if status or reply[4] not in (1, 2):
                        status = 1008
                        break
                    if reply[4] == 2 or _u32(data, 4) == 1:
                        return 0
            _cleanup(comm, finish)
            return status
        if action == 2:
            status, _ = _routine(comm, context, 0x110F)
            _cleanup(comm, finish)
            return 1008 if status else 0
        _cleanup(comm, finish)
        return 99
    if export == "Ex2STRACT_01_SupportCheck":
        data[:8] = bytes(8)
    status = _initialize(comm, context)
    with _after(finish):
        if status:
            return status
        status = _extended(comm)
        if status:
            return status
        with _after(
            lambda: (
                _restore(comm, stop_on_error=True)
                if export == "Ex2STRACT_01_ModeTransition"
                else None
            )
        ):
            if export == "Ex2STRACT_01_SupportCheck":
                status, reply = _routine(comm, context, 0x1001, minimum=7)
                bits = bytes(2)
                if not status and reply[6] & 0x40:
                    status, reply = _routine(comm, context, 0x1100, minimum=5)
                    if not status:
                        # Native copy may include a zero-initialized byte beyond the reply.
                        bits = (reply[4:6] + bytes(2))[:2]
                normal = _restore(comm, stop_on_error=True)
                if not status and not normal:
                    _put(data, 0, int(bool(bits[0] & 0x20)))
                    _put(data, 4, int(bool(bits[1] & 0x80)))
                return status or normal
            status = 0
            for identifier in (
                ((0x1109,) if _u32(data, 4) else ())
                + (0x1002,)
                + ((0x1103,) if _u32(data) else ())
            ):
                status, _ = _routine(comm, context, identifier)
                if status:
                    return 1007
            while _u32(data, 8) != 1:
                _sleep(context, 200)
            return 0


def _lamp4(
    data: bytearray, comm: TYComm, context: TYContext, finish: Callable[[], None]
) -> int:
    if _u32(data, 4) == 0:
        status = _initialize(comm, context)
        if not status:
            status = _extended(comm)
            if not status:
                status, _ = _routine(comm, context, 0x1104)
                if status:
                    _restore(comm, stop_on_error=True)
            if not status:
                return 1004
        finish()
        return status
    with _after(lambda: _cleanup(comm, finish, stop_on_error=True)):
        if data[0] == 1:
            return 0
        while True:
            _sleep(context, 200)
            status, reply = _routine(comm, context, 0x1104, 3, 5)
            if status:
                return status
            if context.module_sha256 == SHA_PLUS_TY and reply[4] not in (0, 1):
                return 0 if reply[4] == 2 else 3
            if data[0] == 1:
                return 0


def _abg(
    export: str,
    data: bytearray,
    comm: TYComm,
    context: TYContext,
    finish: Callable[[], None],
) -> int:
    if export == "Ex2ABG_02_StartLoadSpecInfo":
        status = _initialize(comm, context)
        retained = False
        with _after(lambda: None if retained else finish()):
            if status:
                return status
            _sleep(context, 5000)
            status = _normal(comm)
            if not status:
                _sleep(context, 50)
                status = comm.session(3, 1)
            if status:
                return status
            _sleep(context, 50)
            status, _ = _routine(comm, context, 0x1007)
            if not status:
                retained = True
                return 0
            _sleep(context, 50)
            _normal(comm)
            return status
    with _after(lambda: _abg_cleanup(comm, context, finish)):
        while True:
            _check(context)
            if _u32(data):
                return 1001
            _sleep(context, 500)
            status, reply = _routine(comm, context, 0x1007, 3, 5)
            if status:
                return status
            if reply[4] != 1:
                return 1000 if reply[4] == 2 else 1002


def _lamp1(
    export: str,
    data: bytearray,
    comm: TYComm,
    context: TYContext,
    finish: Callable[[], None],
) -> int:
    status = comm.initialize()
    with _after(finish):
        if status:
            return status
        comm.configure(
            "native_global:100f8194"
            if context.module_sha256 == SHA_18_TY
            else "native_rva:142f0"
            if context.module_sha256 == SHA_PLUS_TY
            else "native_rva:b940",
            150,
        )
        if export == "Ex2LAMP_01_SupportCheck":
            status, snapshot, offsets = comm.support_snapshot(2)
            if status:
                return status
            if len(offsets) <= 4:
                raise TYSourceError("LAMP support provider omitted native offset table")
            offset = offsets[4]
            if offset == 0x1020:
                return 22
            if offset < 0 or offset + 1 >= 0x1020 or offset + 1 >= len(snapshot):
                return 99
            length = snapshot[offset + 1]
            if offset + 1 + length > 0x1020 or offset + 2 + length > len(snapshot):
                return 99
            block = snapshot[offset + 2 : offset + 2 + length]
            for index in (0, 2):
                if len(block) <= index or not block[index] & 0x80:
                    return 22
            _put(data, 4, 2 + sum(value != 0 for value in block[:2]))
            count = sum(value != 0 for value in block)
            _put(data, 0, count + 3)
            return 0
        if context.module_sha256 != SHA_12_TY:
            _sleep(context, 2000)
        size, index = _u32(data), _u32(data, 4)
        request = bytearray(0x1020)
        request[:4] = b"\x30\x04\x00\x80"
        request[index + 1] = 0x80
        status, reply = comm.exchange(bytes(request[:size]))
        if not status and (len(reply) != 2 or reply[1] != 4):
            status = 3
        if status:
            comm.exchange(b"\x30")
        return status


def run_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    """Execute one reviewed source/export pair through selected native primitives."""
    if export not in supported_exports(context.module_sha256):
        raise TYSourceError("Retained TY source/export pair is outside leaf131")
    if hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256:
        raise TYSourceError("Retained TY image bytes do not match selected source")
    _check(context)
    modes = (4,) if export in _LAMP else (20, 21)
    if context.module_sha256 == SHA_PLUS_TY and export.startswith("Ex2GWY_02_"):
        modes += (22,)
    if context.mode not in modes:
        return 99
    data = bytearray()
    if export in _LAMP:
        data = _buffer(args, 8)
        if export == _LAMP[0] and not (
            4 <= _u32(data) <= 0x1020 - 3 and 0 <= _u32(data, 4) + 1 < 0x1020
        ):
            raise ValueError("LAMP initialization span exceeds native stack buffer")
    elif export == "Ex2GWY_02_StartInit":
        data = _buffer(args, 20)
        if len(data) < 6 + data[4] * 2:
            raise ValueError("GWY initialization identifier array is truncated")
    elif export in ("Ex2STRACT_01_ModeTransition",):
        data = _buffer(args, 12)
    elif export in (
        "Ex2STRACT_01_SupportCheck",
        "Ex2STRACT_04_SendMessage",
        "Ex2LAMP_04_SendMessage",
    ):
        data = _buffer(args, 8)
    elif export in (
        "Ex2GWY_03_StartInitResult",
        "Ex2STRACT_03_StartTestMode",
        "Ex2ABG_02_CheckLoadSpecInfo",
    ):
        data = _buffer(args, 4)
    elif len(args) > 1 or (export == "Ex2EOM_01_ModeTransition" and args):
        raise ValueError("Native TY wrapper argument count differs")
    selector = (
        "selected"
        if export in _LAMP
        else "native:1013e7d0"
        if context.mode == 22
        else "native:1011d4f0"
        if context.module_sha256 == SHA_18_TY
        else "native:101392d0"
    )
    comm = context.comm(selector)
    finalized = False

    def finish() -> None:
        nonlocal finalized
        if not finalized:
            finalized = True
            comm.finalize()

    try:
        if export in _LAMP:
            result = _lamp1(export, data, comm, context, finish)
        elif (
            export.startswith("Ex2GWY_")
            or export == "Ex2STRACT_03_StartExtendedSession"
        ):
            result = _gateway(export, data, comm, context, finish)
        elif export.startswith("Ex2STRACT_"):
            result = _stract(export, data, comm, context, finish)
        elif export == "Ex2LAMP_04_SendMessage":
            result = _lamp4(data, comm, context, finish)
        elif export.startswith("Ex2ABG_"):
            result = _abg(export, data, comm, context, finish)
        else:
            with _after(finish):
                result = _initialize(comm, context)
                if not result:
                    result, _ = _routine(comm, context, 0x1180)
    except BaseException as primary:
        # Host cancellation replaces unsafe native TerminateThread; release ownership.
        try:
            finish()
        except BaseException as cleanup_error:  # noqa: BLE001 - retain the primary even for cancellation
            primary.add_note(f"Manager cleanup also failed: {cleanup_error!r}")
        raise
    context.state[
        "native_global:"
        + (
            "100ab770"
            if context.module_sha256 == SHA_12_TY
            else "10118e38"
            if context.module_sha256 == SHA_18_TY
            else "10134ab8"
        )
    ] = result
    return result
