"""Exact retained TY worker business bodies through primitive communication only.

D15 remains unadvertised until its distinct selected P5 interface is admitted.
"""

from __future__ import annotations

import hashlib
from typing import Protocol, cast

from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import (
    SHA_12_TY,
    SHA_18_TY,
    SHA_PLUS_TY,
    TYComm,
    TYContext,
    TYSourceError,
)

_MANAGERS = {
    SHA_12_TY: ("native:100aed50", "native_global:100ab770"),
    SHA_18_TY: ("native:1011d4f0", "native_global:10118e38"),
    SHA_PLUS_TY: ("native:101392d0", "native_global:10134ab8"),
}
_PI_ABSOLUTE = "Ex2PI_01_GetAbsoTime"
_PI_RESET = "Ex2PI_02_SendMessage"
_PI_SUPPORT = "Ex2PI_01_SupportCheck"
_PI = ("Ex2PI_01_GetCurrentTimeStamp", "Ex2PI_01_GetFuseHistory")
_SZEIU = "Ex2SZEIU_01_SendMessage"
_VIF1 = "Ex2VIF_01_SendMessage"
_VIF2 = "Ex2VIF_02_SendMessage"
_VC5 = "Ex2VC_05_SendMessage"
_VC34 = ("Ex2VC_03_SendMessage", "Ex2VC_04_SendMessage")
_VC_SUPPORT = ("Ex2VC_01_SupportCheck", "Ex2VC_02_SupportCheck")
_VC_LEARN = "Ex2VC_02_Learn0Point"
_HVB = ("Ex2HVB_10_SendMessage", "Ex2HVB_11_SendMessage")
_VC = ("Ex2VC_01_GetActuationCnt", "Ex2VC_01_WriteActuationCnt")
_DSC = ("Ex2DSC_01_SendMessage", "Ex2DSC_02_SendMessage")


def supported_exports(module_sha256: str) -> tuple[str, ...]:
    """Only fully ported exact source/export pairs are dispatchable."""
    return (
        (
            _DSC
            + _VC
            + _VC_SUPPORT
            + (_VC_LEARN,)
            + _PI
            + ((_SZEIU,) if module_sha256 == SHA_PLUS_TY else ())
            + (
                _PI_SUPPORT,
                _PI_ABSOLUTE,
            )
            + (
                _HVB
                + _VC34
                + (
                    _PI_RESET,
                    _VIF2,
                    _VIF1,
                    _VC5,
                )
                if module_sha256 in (SHA_18_TY, SHA_PLUS_TY)
                else ()
            )
        )
        if module_sha256 in _MANAGERS
        else ()
    )


def _cleanup(
    context: TYContext,
    comm: TYComm,
    restore: tuple[str, int, int] | None = None,
    *,
    primary: BaseException | None = None,
) -> None:
    failure: BaseException | None = None
    try:
        comm.finalize()
    except BaseException as error:  # noqa: BLE001 - preserve primary HOST/cancel identity
        failure = error
    if restore is not None:
        field, first, second = restore
        context.state[field] = 0
        try:
            comm.select_target(first, second)
        except BaseException as error:  # noqa: BLE001 - preserve primary HOST/cancel identity
            if failure is None:
                failure = error
    if primary is None and failure is not None:
        raise failure


def _pending(context: TYContext, comm: TYComm) -> None:
    comm.configure(
        {
            SHA_12_TY: "native_rva:b940",
            SHA_18_TY: "native_rva:12180",
            SHA_PLUS_TY: "native_rva:142f0",
        }[context.module_sha256],
        150,
    )


def _cancel(context: TYContext) -> None:
    if context.is_cancelled():
        raise Cancelled("Retained TY worker cancelled")


def _exchange(context: TYContext, comm: TYComm, request: bytes) -> tuple[int, bytes]:
    _cancel(context)
    status, response = comm.exchange(request)
    if (
        type(status) is not int
        or not 0 <= status <= 0xFFFFFFFF
        or type(response) is not bytes
        or len(response) > 0x1020
    ):
        raise ValueError("Primitive exchange returned malformed native status/buffer")
    _cancel(context)
    return status, response


def _session(context: TYContext, comm: TYComm, mode: int) -> int:
    _cancel(context)
    return comm.session(mode, 1)


def _dsc_read(context: TYContext, comm: TYComm, buffer: bytearray) -> int:
    result = _session(context, comm, 1)
    if result:
        return result
    for offset, identifier, size in (
        (0, 0x55, 6),
        (6, 0x56, 6),
        (12, 0x57, 6),
        (18, 0x58, 6),
        (24, 0x3F, 9),
        (33, 0x40, 9),
    ):
        request = bytes((0x22, 0x28, identifier))
        result, response = _exchange(context, comm, request)
        if result:
            return result
        # Native compares the DID, not the service byte, then copies N bytes.
        if len(response) < size + 3 or response[1:3] != request[1:3]:
            return 3
        buffer[offset : offset + size] = response[3 : size + 3]
    return 0


def _dsc_clear(context: TYContext, comm: TYComm, buffer: bytearray) -> int:
    context.sleep(3000)
    result = _session(context, comm, 1)
    if result:
        return result
    result = _session(context, comm, 3)
    if result:
        return result
    for _ in range(4):
        _cancel(context)
        context.sleep(100)
        request = bytes((0x31, 1, 0x30, buffer[0]))
        result, response = _exchange(context, comm, request)
        if not result:
            if len(response) != 5 or response[1:4] != request[1:4]:
                result = 3
            else:
                result = 1001 if response[4] == 0x10 else 1002
        if result != 1002:
            if result == 1001:
                result, response = _exchange(context, comm, b"\x14\xff\xff\xff")
                if not result and len(response) != 1:
                    result = 3
            break
    # The normal-session result is deliberately discarded by the native body.
    _session(context, comm, 1)
    return result


def _vc_count(context: TYContext, comm: TYComm, buffer: bytearray, write: bool) -> int:
    if write:
        size = int.from_bytes(buffer[:4], "little")
        if size > 0x1020:
            raise ValueError("VC write length exceeds native request allocation")
        packet = bytearray(0x1020)
        packet[:3] = b"\x3b\x78\x20"
        packet[11:15] = buffer[8:12]
        result, response = _exchange(context, comm, bytes(packet[:size]))
        if result:
            return result
        # ASM restores the successful branch incorrectly removed by 12/18 C output.
        return 0 if len(response) == 2 and response[1] == 0x78 else 3
    result, response = _exchange(context, comm, b"\xa9\x78")
    if result:
        return result
    native = response[:0x1020].ljust(0x1020, b"\0")
    if native[1] != 0x78:
        return 3
    buffer[4:8] = native[11:15]
    return 0


def _hvb_routine(
    context: TYContext, comm: TYComm, routine: int, action: int
) -> tuple[int, int]:
    request = bytes((0x31, action, 0x11, routine))
    uds = context.module_sha256 == SHA_PLUS_TY and context.mode == 22
    saved = comm.read_field("native_10a4") if uds and action == 3 else None
    if saved is not None:
        comm.configure("native_10a4", 0)
    operation_error: BaseException | None = None
    try:
        result, response = _exchange(context, comm, request)
        if result:
            if uds and action == 3 and response in (b"\x7f\x31\x21", b"\x7f\x31\x24"):
                return 1031, 0
            return result, 0
        minimum = (6 if action == 3 else 5) if uds else (5 if action == 3 else 4)
        if len(response) < minimum or response[1:4] != request[1:4]:
            return 3, 0
        return 0, response[5 if uds else 4] if action == 3 else 0
    except BaseException as error:
        operation_error = error
        raise
    finally:
        if saved is not None:
            primary = operation_error
            try:
                comm.configure("native_10a4", saved)
            except BaseException:
                if primary is None:
                    raise


def _hvb(
    context: TYContext, comm: TYComm, buffer: bytearray, second: bool
) -> tuple[int, bool]:
    action = int.from_bytes(buffer[:4], "little")
    routine = 0x26 if second else 0x25
    if action == 0:
        result = comm.initialize(0)
        if result:
            return result, False
        comm.configure("native_1080", 0)
        comm.configure("native_1084", 180000)
        comm.configure("native_1064", 0)
        result = comm.session(3, 1, normal_first=True)
        if result:
            return result, False
        result, _ = _hvb_routine(context, comm, routine, 1)
        if result == 0:
            return 1005, True
        _session(context, comm, 1)
        return 1004, False
    if action == 1:
        while int.from_bytes(buffer[4:8], "little") == 0:
            _cancel(context)
            result, status = _hvb_routine(context, comm, routine, 3)
            if context.module_sha256 == SHA_PLUS_TY and context.mode == 22:
                if result == 1031:
                    continue
                if result == 0 and status == 2:
                    return 1022, True
                _session(context, comm, 1)
                return 1004, False
            if result or status not in (0, 1):
                if result == 0 and status == 2:
                    return 1022, True
                _session(context, comm, 1)
                return 1004, False
        _session(context, comm, 1)
        return 0, False
    identifier = 0x51 if second else 0x50
    request = bytes((0x22, 0x18, identifier))
    result, response = _exchange(context, comm, request)
    if result == 0 and (
        len(response) < (6 if second else 4) or response[1:3] != request[1:3]
    ):
        result = 3
    if result == 0 and second:
        buffer[9:11] = response[4:6]
    _session(context, comm, 1)
    if result:
        return 1004, False
    status = response[3]
    if status > 3:
        return 3, False
    buffer[8] = status
    return (1007 if second and status == 0 else 1006), False


def _snapshot(
    context: TYContext, comm: TYComm, kind: int
) -> tuple[int, bytes, tuple[int, ...]]:
    _cancel(context)
    result, raw, offsets = comm.support_snapshot(kind)
    if (
        type(raw) is not bytes
        or len(raw) > 0x1020
        or len(offsets) != 256
        or any(type(value) is not int or not 0 <= value <= 0x1020 for value in offsets)
    ):
        raise ValueError("Malformed native support snapshot")
    return result, raw.ljust(0x1020, b"\0"), offsets


def _support(
    raw: bytes, offsets: tuple[int, ...], identifier: int, position: int, mask: int
) -> tuple[int, int]:
    base = offsets[identifier]
    if base == 0x1020:
        return 22, 0
    if base + 1 >= 0x1020 or base + 1 + raw[base + 1] > 0x1020:
        return 99, 0
    if raw[base + 1] < position - 2:
        return 22, 0
    index = base + max(2, position - 1)
    if index >= 0x1020:
        raise ValueError("Native support read crosses allocated buffer")
    count = 2 + sum(value != 0 for value in raw[base + 2 : index])
    return (0 if raw[index] and raw[index] & mask == mask else 22), count


def _vc_support(
    context: TYContext, comm: TYComm, buffer: bytearray, second: bool
) -> int:
    if second:
        result, raw, offsets = _snapshot(context, comm, 1)
        if result:
            return result
        result, count = _support(raw, offsets, 0xCC, 6, 0xFF)
        if result:
            return result
        buffer[4:8] = count.to_bytes(4, "little")
        base = offsets[0xCC]
        nonzero = sum(value != 0 for value in raw[base + 2 : base + 2 + raw[base + 1]])
        buffer[:4] = (nonzero + 2).to_bytes(4, "little")
    result, raw, offsets = _snapshot(context, comm, 3)
    if result:
        return result
    identifier = 0x41 if second else 0x78
    checks = (
        ((3, 2), (4, 2))
        if second
        else ((3, 0x20), (12, 0xFF), (13, 0xFF), (14, 0xFF), (15, 0xFF))
    )
    for position, mask in checks:
        result, _ = _support(raw, offsets, identifier, position, mask)
        if result:
            return result
    output = 8 if second else 0
    buffer[output : output + 4] = (raw[offsets[identifier] + 1] + 2).to_bytes(
        4, "little"
    )
    return 0


def _vc_learn(context: TYContext, comm: TYComm, buffer: bytearray) -> int:
    length = int.from_bytes(buffer[:4], "little")
    offset = int.from_bytes(buffer[4:8], "little")
    request_size = int.from_bytes(buffer[8:12], "little")
    if offset >= 0x1020 or request_size > 0x1020:
        raise ValueError("VC learning buffer offset/length exceeds native allocation")

    def set_mode(mode: int) -> int:
        packet = bytes((0x3B, 0x41, 2, mode)).ljust(request_size, b"\0")[:request_size]
        result, response = _exchange(context, comm, packet)
        return (
            result if result else 0 if len(response) == 2 and response[1] == 0x41 else 3
        )

    result = set_mode(2)
    if result:
        return result
    start = context.ticks()
    consecutive = 0
    elapsed = 0
    succeeded = False
    operation_error: BaseException | None = None
    try:
        while True:
            result, response = _exchange(context, comm, b"\x21\xcc")
            elapsed = (context.ticks() - start) & 0xFFFFFFFF
            if not result and (
                len(response) != length or response.ljust(2, b"\0")[1] != 0xCC
            ):
                result = 3
            if result:
                break
            sample = response[:0x1020].ljust(0x1020, b"\0")[offset]
            consecutive = consecutive + 1 if 99 <= sample <= 101 else 0
            if consecutive >= 3:
                succeeded = True
                break
            context.sleep(500)
            if elapsed >= 3000:
                break
    except BaseException as error:
        operation_error = error
        raise
    finally:
        primary = operation_error
        stop_result = 0
        try:
            if not context.is_cancelled():
                stop_result = set_mode(0)
        except BaseException:
            if primary is None:
                raise
    return stop_result if succeeded else 9999 if elapsed > 3000 else result


def _timestamp(
    context: TYContext,
    comm: TYComm,
    buffer: bytearray,
    row: int,
    descriptor: int | None = None,
) -> int:
    source = row if descriptor is None else descriptor
    identifier = buffer[source + 1]
    length = int.from_bytes(buffer[source + 0x1C : source + 0x20], "little")
    position = int.from_bytes(buffer[source + 0x20 : source + 0x24], "little")
    if position + (13 if identifier == 0x41 else 6) > 0x1020:
        raise ValueError("PI timestamp offset crosses native receive allocation")
    output = row + 0x24
    result, response = _exchange(context, comm, bytes((0x21, identifier)))
    if result:
        if identifier not in (0x41, 0xE1) and response == b"\x7f\x21\x22":
            buffer[output + 20] = 1
            return 0
        return result
    native = response[:0x1020].ljust(0x1020, b"\0")
    if len(response) != length + 2 or native[1] != identifier:
        return 3
    if identifier == 0x41:
        buffer[output + 22] = 1
        buffer[output + 7 : output + 20] = native[position : position + 13]
        return 0
    if native[position : position + 2] == b"\xff\xff":
        return 3
    extension = bool(buffer[output + 21])
    if native[position + 3 : position + 6] == b"\xff" * 3 and (
        not extension or native[position + 2] & 0x1F == 0x1F
    ):
        return 3
    flags = native[position + 2]
    if flags & 0x80:
        return 3
    buffer[output : output + 2] = native[position : position + 2]
    buffer[output + 2] = flags & 0xE0
    if extension:
        buffer[output + 3] = flags & 0x1F
    buffer[output + 4 : output + 7] = native[position + 3 : position + 6]
    return 10000 if flags & 0xE0 in (0, 0x20) else 0


def _pi(
    context: TYContext, comm: TYComm, buffer: bytearray, current: bool, initial: int
) -> int:
    if current:
        if initial:
            return initial
        result = _timestamp(context, comm, buffer, 0x4BC)
        return 0 if result == 10000 else result
    count = int.from_bytes(buffer[0x4B8:0x4BC], "little", signed=True)
    if count > 20:
        raise ValueError("PI row count exceeds native descriptor area")
    if initial:
        for index in range(max(0, count)):
            buffer[8 + 60 * index] = 0
        return 0
    pending = False
    result = 0
    for index in range(max(0, count)):
        row = 8 + 60 * index
        if buffer[row]:
            result = _timestamp(context, comm, buffer, row)
            if result == 10000:
                pending = True
            elif result:
                buffer[row] = 0
                result = 0
    return 10000 if pending and result in (0, 10000) else result


def _pi_support(context: TYContext, comm: TYComm, buffer: bytearray) -> int:
    result, raw, offsets = _snapshot(context, comm, 1)
    if result:
        return result
    count = int.from_bytes(buffer[0x4B8:0x4BC], "little", signed=True)
    if count > 20:
        raise ValueError("PI support row count exceeds native descriptor area")
    any_supported = False
    for row in (0x4BC, *(8 + index * 60 for index in range(max(0, count)))):
        identifier = buffer[row + 1]
        start = int.from_bytes(buffer[row + 4 : row + 8], "little", signed=True)
        masks = int.from_bytes(buffer[row + 8 : row + 12], "little", signed=True)
        if masks > 16 or start < 0:
            raise ValueError("PI support masks exceed native descriptor allocation")
        columns = 0
        for index in range(max(0, masks)):
            result, columns = _support(
                raw, offsets, identifier, start + 3 + index, buffer[row + 12 + index]
            )
            if result:
                break
        if result:
            if row == 0x4BC:
                return result
            continue
        buffer[row] = 1
        buffer[row + 0x20 : row + 0x24] = ((columns - masks + 1) & 0xFFFFFFFF).to_bytes(
            4, "little"
        )
        base = offsets[identifier]
        if base != 0x1020 and base + 1 < 0x1020 and base + 1 + raw[base + 1] <= 0x1020:
            total = sum(
                value != 0 for value in raw[base + 2 : base + 2 + raw[base + 1]]
            )
            if total:
                buffer[row + 0x1C : row + 0x20] = total.to_bytes(4, "little")
        result, _ = _support(raw, offsets, identifier, start + 5, 0x1F)
        if result == 0:
            buffer[row + 0x39] = 1
        if row != 0x4BC:
            any_supported = True
    return 0 if any_supported else 3


def _pi_reset(context: TYContext, comm: TYComm) -> int:
    result = comm.initialize(0)
    if result:
        return result
    comm.configure("native_1080", 0)
    comm.configure("native_1084", 180000)
    comm.configure("native_1064", 0)
    result = comm.session(3, 1, normal_first=True)
    if result:
        return result
    operation_error: BaseException | None = None
    try:
        result, response = _exchange(context, comm, b"\x31\x01\x11\x01")
        if result == 7 and comm.read_field("native_10b0") == 0x69:
            return 0x69
        if result:
            return result
        return 0 if len(response) >= 4 and response[1:4] == b"\x01\x11\x01" else 3
    except BaseException as error:
        operation_error = error
        raise
    finally:
        primary = operation_error
        try:
            if not context.is_cancelled():
                _session(context, comm, 1)
        except BaseException:
            if primary is None:
                raise


def _pi_absolute_support(
    context: TYContext, comm: TYComm, buffer: bytearray, kind: int, row: int
) -> int:
    result, raw, offsets = _snapshot(context, comm, kind)
    if result:
        return result
    identifier = buffer[row + 1]
    start = int.from_bytes(buffer[row + 4 : row + 8], "little", signed=True)
    masks = int.from_bytes(buffer[row + 8 : row + 12], "little", signed=True)
    if masks > 16 or start < 0:
        raise ValueError("PI absolute support descriptor exceeds native allocation")
    columns = 0
    for index in range(max(0, masks)):
        result, columns = _support(
            raw, offsets, identifier, start + 3 + index, buffer[row + 12 + index]
        )
        if result:
            return result
    buffer[row + 0x20 : row + 0x24] = ((columns - masks + 1) & 0xFFFFFFFF).to_bytes(
        4, "little"
    )
    base = offsets[identifier]
    if base == 0x1020:
        return 22
    if base + 1 >= 0x1020 or base + 1 + raw[base + 1] > 0x1020:
        return 99
    total = sum(value != 0 for value in raw[base + 2 : base + 2 + raw[base + 1]])
    buffer[row + 0x1C : row + 0x20] = total.to_bytes(4, "little")
    return 0 if total else 22


def _pi_absolute(context: TYContext, comm: TYComm, buffer: bytearray) -> int:
    callback_global, callback_address = {
        SHA_12_TY: ("native_global:100afea4", 0x100AB6C0),
        SHA_18_TY: ("native_global:1011f764", 0x10118D70),
        SHA_PLUS_TY: ("native_global:1013fab0", 0x10139248),
    }[context.module_sha256]
    count = int.from_bytes(buffer[0x4B8:0x4BC], "little", signed=True)
    if count > 20:
        raise ValueError("PI absolute row count exceeds native descriptor area")
    context.state[callback_global] = callback_address
    operation_error: BaseException | None = None
    try:
        comm.select_target(2000, 0)
        result = comm.initialize(0)
        if result:
            return 0
        _pending(context, comm)
        for kind, descriptor in ((1, 0x4F8), (2, 0x534)):
            result = _pi_absolute_support(context, comm, buffer, kind, descriptor)
            if result:
                return 0
        for index in range(max(0, count)):
            row = 8 + 60 * index
            output = row + 0x24
            if (
                not buffer[row]
                or buffer[output + 20]
                or buffer[output + 2] not in (0, 0x20)
            ):
                continue
            result, response = _exchange(
                context, comm, b"\x30\x41\0" + bytes(buffer[output : output + 2])
            )
            if not result and len(response) == 2 and response[1] == 0x41:
                _timestamp(context, comm, buffer, row, 0x4F8)
        return 0
    except BaseException as error:
        operation_error = error
        raise
    finally:
        _cleanup(
            context,
            comm,
            (
                callback_global,
                int.from_bytes(buffer[:4], "little"),
                int.from_bytes(buffer[4:8], "little"),
            ),
            primary=operation_error,
        )


def _vc_security(context: TYContext, comm: TYComm, strict: bool) -> int:
    result, response = _exchange(context, comm, b"\x27\x01")
    # 712c0 checks shape before the exchange status;70bc0 checks status first.
    if strict and (len(response) < 3 or response[1] != 1):
        return 3
    if result:
        return result
    if len(response) < 3 or response[1] != 1 or len(response) > 0x1020:
        return 3
    result, response = _exchange(
        context, comm, b"\x27\x02" + bytes(value ^ 0xFF for value in response[2:])
    )
    return result if result else 0 if len(response) == 2 and response[1] == 2 else 3


def _vc34(context: TYContext, comm: TYComm, buffer: bytearray, fourth: bool) -> int:
    action = int.from_bytes(buffer[12:16], "little")
    if action == 0:
        if fourth:
            return _vc_support(context, comm, buffer, False)
        result, raw, offsets = _snapshot(context, comm, 1)
        if result:
            return result
        result, _ = _support(raw, offsets, 0xCC, 3, 0x80)
        if result:
            return result
        base = offsets[0xCC]
        total = sum(value != 0 for value in raw[base + 2 : base + 2 + raw[base + 1]])
        if total:
            buffer[:4] = total.to_bytes(4, "little")
        result, raw, offsets = _snapshot(context, comm, 3)
        if result:
            return result
        for position in (3, 4):
            result, _ = _support(raw, offsets, 0x41, position, 2)
            if result:
                return result
        buffer[4:8] = raw[offsets[0x41] + 1].to_bytes(4, "little")
        return 0
    if action == 1 and fourth:
        result, response = _exchange(context, comm, b"\xa9\x78")
        if result:
            return result
        if len(response) < 15 or response[1] != 0x78:
            return 3
        buffer[4:8] = response[11:15]
        return 0
    size = 0 if fourth else int.from_bytes(buffer[4:8], "little")
    if size + 2 > 0x1020:
        raise ValueError("VC operation length exceeds native request allocation")
    if action == 1:
        minimum = int.from_bytes(buffer[:4], "little") + 2
        result = 0
        operation_error: BaseException | None = None
        try:
            while not buffer[8]:
                context.sleep(200)
                result, response = _exchange(context, comm, b"\x21\xcc")
                if result:
                    break
                if len(response) < minimum or response.ljust(2, b"\0")[1] != 0xCC:
                    result = 3
                    break
                if response[:3].ljust(3, b"\0")[2] & 0x80:
                    result = 1001
                    break
        except BaseException as error:
            operation_error = error
            raise
        finally:
            primary = operation_error
            try:
                if not context.is_cancelled():
                    _exchange(
                        context,
                        comm,
                        b"\x3b\x41\x02\0".ljust(size + 2, b"\0")[: size + 2],
                    )
            except BaseException:
                if primary is None:
                    raise
        return result
    if action != 2:
        return 0
    if fourth:
        buffer[8:12] = (1).to_bytes(4, "little")
    result = _vc_security(context, comm, fourth)
    if fourth and result:
        buffer[8:12] = bytes(4)
    if result:
        return result
    if fourth:
        request_size = int.from_bytes(buffer[:4], "little")
        if request_size > 0x1020:
            raise ValueError("VC write length exceeds native allocation")
        packet = bytearray(0x1020)
        packet[:3] = b"\x3b\x78\x20"
        packet[11:15] = buffer[4:8]
        result, response = _exchange(context, comm, bytes(packet[:request_size]))
        return (
            result if result else 0 if len(response) == 2 and response[1] == 0x78 else 3
        )
    result, response = _exchange(
        context, comm, b"\x3b\x41\x02\x02".ljust(size + 2, b"\0")[: size + 2]
    )
    return result if result else 0 if len(response) >= 2 and response[1] == 0x41 else 3


def _vif2(context: TYContext, comm: TYComm, buffer: bytearray) -> int:
    action = int.from_bytes(buffer[:4], "little")
    if action:
        first = (buffer[24] if any(buffer[16:20]) else 0) | (
            buffer[40] if any(buffer[32:36]) else 0
        )
        second = (buffer[56] if any(buffer[48:52]) else 0) | (
            buffer[72] if any(buffer[64:68]) else 0
        )
        for identifier, mask, size in (
            (0x7B, first, int.from_bytes(buffer[4:8], "little")),
            (0x7C, second, int.from_bytes(buffer[8:12], "little")),
        ):
            if not mask:
                continue
            if size + 2 > 0x1020:
                raise ValueError("VIF write data exceeds native request allocation")
            data = bytes((mask,)).ljust(size, b"\0")[:size]
            result, response = _exchange(
                context, comm, bytes((0x3B, identifier)) + data
            )
            if result:
                return result
            if len(response) < 2 or response[1] != identifier:
                return 3
        return 0
    result, raw, offsets = _snapshot(context, comm, 3)
    if result:
        return result
    for identifier, output in ((0x7B, 4), (0x7C, 8)):
        offset = offsets[identifier]
        if offset + 1 >= 0x1020:
            raise ValueError("Native VIF support length reads beyond allocation")
        buffer[output : output + 4] = raw[offset + 1].to_bytes(4, "little")
    any_supported = False
    for row in range(0x4C, 0x28C, 48):
        identifier = buffer[row]
        start = int.from_bytes(buffer[row + 8 : row + 12], "little", signed=True)
        count = int.from_bytes(buffer[row + 44 : row + 48], "little", signed=True)
        if start < 0 or count > 32:
            raise ValueError("VIF support masks exceed native row allocation")
        result = 0
        for index in range(max(0, count), 0, -1):
            result, _ = _support(
                raw, offsets, identifier, start + 2 + index, buffer[row + 11 + index]
            )
            if result:
                break
        if not result:
            buffer[row + 4 : row + 8] = (1).to_bytes(4, "little")
            any_supported = True
    if not any_supported:
        return 3
    for flags, target in (
        ((0x50, 0x110), 0xC),
        ((0xB0,), 0x1C),
        ((0x170, 0x230), 0x2C),
        ((0x1D0,), 0x3C),
    ):
        if all(
            int.from_bytes(buffer[offset : offset + 4], "little") == 1
            for offset in flags
        ):
            buffer[target : target + 4] = (1).to_bytes(4, "little")
    return 0


class _SZComm(TYComm, Protocol):
    def configure_keepalive(
        self, interval_ms: int, request: bytes, response_size: int, flags: int
    ) -> None: ...
    def keepalive(self, enabled: bool, wait: bool = False) -> int: ...


def _sz_routine(
    context: TYContext, comm: TYComm, number: int, value: int | None = None
) -> int:
    request = bytes((0x31, 1, 0xC0, number)) + (
        b"" if value is None else bytes((value,))
    )
    result, response = _exchange(context, comm, request)
    return (
        result
        if result
        else 0
        if len(response) >= 4 and response[1:4] == request[1:4]
        else 3
    )


def _sz_read(context: TYContext, comm: TYComm) -> tuple[int, int]:
    result, response = _exchange(context, comm, b"\x22\x12\x01")
    if not result and (len(response) < 18 or response[1:3] != b"\x12\x01"):
        result = 3
    return result, response[17] if not result else 0


def _sz_phase(context: TYContext, comm: TYComm, wanted: int) -> int:
    start = context.ticks()
    context.sleep(200)
    while (context.ticks() - start) & 0xFFFFFFFF < 3000:
        result, status = _sz_read(context, comm)
        if result:
            return result
        if status == wanted:
            return 0
        context.sleep(200)
    return 2000


def _szeiu(context: TYContext, buffer: bytearray) -> int:
    # This is the same concrete100d1cc0 helper used by the other SZ business body.
    from scripts.utility_ex_ty_retained_03 import _sz_security

    first = cast(_SZComm, context.comm("native:101392d0"))
    second = context.comm("native:10135c58")
    entered = False
    result = 0
    operation_error: BaseException | None = None
    try:
        for comm, target in ((first, 0x790), (second, 0x751)):
            comm.configure_target(target, 0, 0, 0, 0)
            result = comm.initialize(0)
            if result:
                return result
            comm.configure("native_1080", 0)
            comm.configure("native_1084", 255000)
            comm.configure("native_1064", 0)
        action = int.from_bytes(buffer[:4], "little")
        if action not in (0, 1):
            result, status = _sz_read(context, second)
            if result or status != 0xAA:
                return result
        entered = True
        result = first.session(3, keepalive=0)
        if result:
            return result
        first.configure_keepalive(2000, b"\x3e\0", 2, 0)
        result = first.keepalive(True)
        if result == 0:
            result = _sz_security(context, first, 0x790)
        if result:
            return result
        result = (
            _sz_routine(context, first, 0xC)
            if action == 1
            else _sz_routine(context, first, 0xD, 0)
        )
        if result == 0:
            result = _sz_phase(context, second, 0)
        if result == 0:
            result = (
                _sz_routine(context, first, 0xD, 1)
                if action == 1
                else _sz_routine(context, first, 0xB)
            )
        if result == 0:
            result = _sz_phase(context, second, 0xAA if action == 1 else 0x55)
        if result:
            _sz_routine(context, first, 0xB)
        return result
    except BaseException as error:
        operation_error = error
        raise
    finally:
        primary = operation_error
        failure: BaseException | None = None
        actions = (
            [
                lambda: first.keepalive(False, False),
                lambda: first.session(1, keepalive=0),
            ]
            if entered
            else []
        ) + [first.finalize, second.finalize]
        for cleanup in actions:
            try:
                cleanup()
            except BaseException as error:  # noqa: BLE001 - run all cleanup without replacing primary HOST/cancel
                if failure is None:
                    failure = error
        if primary is None and failure is not None:
            raise failure


def _word(buffer: bytearray, offset: int) -> int:
    return int.from_bytes(buffer[offset : offset + 4], "little")


def _vif1(context: TYContext, comm: TYComm, buffer: bytearray) -> int:
    action = _word(buffer, 0x1090)
    targets = (0x3F0, 0x800)
    support_rows = range(0xC10, 0x1090, 48)
    if action == 0:
        for row in support_rows:
            buffer[row + 4 : row + 8] = bytes(4)
        for target in targets:
            buffer[target + 4 : target + 8] = bytes(4)
        previous_kind = 0xFF
        raw = bytes(0x1020)
        offsets = (0,) * 256
        read_supported = write_supported = False
        target_index = 0
        for row in support_rows:
            identifier, kind = buffer[row], buffer[row + 1]
            if kind != previous_kind:
                result, raw, offsets = _snapshot(context, comm, kind)
                if result:
                    return result
                previous_kind = kind
                if kind == 3:
                    for target in targets:
                        base = offsets[buffer[target]]
                        size = (
                            raw[base + 1] if base != 0x1020 and base + 1 < 0x1020 else 0
                        )
                        buffer[target + 0x408 : target + 0x40C] = size.to_bytes(
                            4, "little"
                        )
            start, count = _word(buffer, row + 8), _word(buffer, row + 44)
            if count > 32 or start > 0x101F:
                raise ValueError("VIF native support descriptor exceeds its allocation")
            result = 0
            for index in range(count, 0, -1):
                result, _ = _support(
                    raw,
                    offsets,
                    identifier,
                    start + 2 + index,
                    buffer[row + 11 + index],
                )
                if result:
                    break
            if result == 0:
                buffer[row + 4 : row + 8] = (1).to_bytes(4, "little")
                if kind == 4:
                    write_supported = True
                    if target_index >= 2 or row < 0xE50:
                        raise ValueError(
                            "VIF write support has no native paired read descriptor"
                        )
                    target = targets[target_index]
                    if buffer[target] == identifier and _word(buffer, row - 572) == 1:
                        buffer[target + 4 : target + 8] = (1).to_bytes(4, "little")
                else:
                    read_supported = True
            if kind == 4 and buffer[row] != buffer[row + 48]:
                target_index += 1
        return 0 if read_supported and write_supported else 3
    if action == 1:
        for target in targets:
            if _word(buffer, target + 4) != 1:
                continue
            result, response = _exchange(context, comm, bytes((0xA9, buffer[target])))
            if result:
                return result
            if len(response) < 3 or response[1] != buffer[target]:
                return 3
            if len(response) - 2 > 1024:
                raise ValueError("VIF native target response crosses caller allocation")
            buffer[target + 8 : target + 6 + len(response)] = response[2:]
            buffer[target + 0x408 : target + 0x40C] = (len(response) - 2).to_bytes(
                4, "little"
            )
        return 0
    return _vif1_write(context, comm, buffer)


def _vif1_write(context: TYContext, comm: TYComm, buffer: bytearray) -> int:
    descriptors = list(range(0, 0x3F0, 84))
    support_rows = list(range(0xC10, 0x1090, 48))
    descriptor_index = support_index = second_descriptor_index = 0
    any_written = False
    for target in (0x3F0, 0x800):
        if (
            descriptor_index >= len(descriptors)
            or buffer[descriptors[descriptor_index]] != buffer[target]
        ):
            raise ValueError(
                "VIF native descriptor groups do not match target ordering"
            )
        group = []
        while (
            descriptor_index < len(descriptors)
            and buffer[descriptors[descriptor_index]] == buffer[target]
        ):
            group.append(descriptors[descriptor_index])
            descriptor_index += 1
        packet = bytearray(0x1020)
        for row in group:
            offset, count, mode = (
                _word(buffer, row + 8),
                _word(buffer, row + 76),
                _word(buffer, row + 80),
            )
            if count > 32 or offset + max(1, count) > 0x1020:
                raise ValueError("VIF native mask write crosses its allocation")
            if mode == 0:
                packet[offset] |= buffer[row + 44]
            else:
                if not count or offset + count > 1024:
                    raise ValueError(
                        "VIF current-value descriptor crosses target allocation"
                    )
                for index in range(count):
                    mask = buffer[row + 12 + index]
                    value = buffer[target + 8 + offset + index] & mask
                    if value != mask and mask != 0xFF:
                        break
                    packet[offset + index] |= value
        changed = False
        while True:
            if second_descriptor_index >= len(descriptors):
                raise ValueError("VIF native rewrite descriptor crosses allocation")
            row = descriptors[second_descriptor_index]
            offset, count, mode = (
                _word(buffer, row + 8),
                _word(buffer, row + 76),
                _word(buffer, row + 80),
            )
            while support_index < len(support_rows):
                support = support_rows[support_index]
                if (
                    buffer[support] == buffer[row]
                    and _word(buffer, support + 8) == offset
                    and buffer[support + 12] == buffer[row + 12]
                ):
                    break
                support_index += 1
            else:
                raise ValueError("VIF native support match is missing")
            support = support_rows[support_index]
            if _word(buffer, support + 4) == 0:
                for index in range(count):
                    packet[offset + index] &= buffer[row + 12 + index] ^ 0xFF
                if mode == 0:
                    next_support = support + 48
                    if next_support + 8 > len(buffer):
                        raise ValueError(
                            "VIF native paired support row crosses allocation"
                        )
                    changed |= _word(buffer, next_support + 4) == 1
                    buffer[next_support + 4 : next_support + 8] = bytes(4)
                else:
                    if second_descriptor_index == 0:
                        raise ValueError("VIF native previous descriptor is missing")
                    row = descriptors[second_descriptor_index - 1]
                    previous_offset = _word(buffer, row + 8)
                    if previous_offset >= len(packet):
                        raise ValueError(
                            "VIF native previous descriptor crosses allocation"
                        )
                    packet[previous_offset] &= buffer[row + 12] ^ 0xFF
            else:
                changed = True
            next_index = second_descriptor_index + 1
            next_row = (
                descriptors[next_index] if next_index < len(descriptors) else 0x3F0
            )
            second_descriptor_index = next_index
            support_index += 1
            if buffer[row] != buffer[next_row]:
                break
        size = _word(buffer, target + 0x408)
        if size > 1024:
            raise ValueError("VIF native target write crosses caller allocation")
        if _word(buffer, target + 0x40C) and size and changed:
            request = bytes((0x3B, buffer[target])) + bytes(packet[:size])
            result, response = _exchange(context, comm, request)
            if not result and len(response) >= 2 and response[1] == buffer[target]:
                any_written = True
    return 0 if any_written else 3


def _vc5_support(context: TYContext, comm: TYComm, buffer: bytearray) -> int:
    targets = list(range(0x8560, 0xE2D0, 0x410))
    rows = range(0xE2D0, 0x17450, 48)
    for row in rows:
        buffer[row + 4 : row + 8] = bytes(4)
    for target in targets:
        buffer[target + 4 : target + 8] = bytes(4)
    previous_kind = 255
    raw = bytes(0x1020)
    offsets = (0,) * 256
    read_supported = write_supported = False
    target_index = 0
    for row in rows:
        identifier, kind = buffer[row], buffer[row + 1]
        if kind != previous_kind:
            result, raw, offsets = _snapshot(context, comm, kind)
            if result:
                return result
            previous_kind = kind
            if kind == 3:
                for target in targets:
                    base = offsets[buffer[target]]
                    size = raw[base + 1] if base != 0x1020 and base + 1 < 0x1020 else 0
                    buffer[target + 0x408 : target + 0x40C] = size.to_bytes(4, "little")
        start, count = _word(buffer, row + 8), _word(buffer, row + 44)
        if count > 32 or start > 0x101F:
            raise ValueError("VC05 support masks exceed native descriptor allocation")
        result = 0
        for index in range(count, 0, -1):
            result, _ = _support(
                raw, offsets, identifier, start + 2 + index, buffer[row + 11 + index]
            )
            if result:
                break
        if not result:
            buffer[row + 4 : row + 8] = (1).to_bytes(4, "little")
            if kind == 4:
                write_supported = True
                if target_index >= len(targets):
                    raise ValueError(
                        "VC05 support target groups exceed native allocation"
                    )
                target = targets[target_index]
                if buffer[target] == identifier:
                    buffer[target + 4 : target + 8] = (1).to_bytes(4, "little")
            else:
                read_supported = True
        if kind == 4 and buffer[row] != buffer[row + 48]:
            target_index += 1
    return 0 if read_supported and write_supported else 3


def _vc5_reset(context: TYContext, comm: TYComm) -> int:
    result, response = _exchange(context, comm, b"\x31\x04")
    if result == 7 and response[:3].ljust(3, b"\0")[2] == 0x11:
        result = 2011
    if not result and (len(response) < 2 or response[1] != 4):
        result = 3
    if result not in (0, 2011):
        return result
    for _ in range(3):
        result, response = _exchange(context, comm, b"\x11\x01")
        if result == 0 and len(response) != 1:
            result = 3
        if result not in (2, 7):
            break
    return result


def _vc5_rewrite(context: TYContext, comm: TYComm, buffer: bytearray) -> int:
    alternate = _word(buffer, 0x17458) == 1
    base = 0xF20 if alternate else 0
    first_index = second_index = support_index = 0
    result = 0
    for target in list(range(0x8560, 0xE2D0, 0x410))[: 20 if alternate else 7]:
        packet = bytearray(0x1020)
        row = base + first_index * 88
        if row + 176 > 0x8560 or buffer[row] != buffer[target]:
            raise ValueError("VC05 native descriptor ordering does not match target")
        while True:
            row = base + first_index * 88
            offset, count, mode = (
                _word(buffer, row + 8),
                _word(buffer, row + 76),
                _word(buffer, row + 80),
            )
            if not 1 <= count <= 32 or offset + count > 1024:
                raise ValueError("VC05 mask rewrite crosses native target allocation")
            for index in range(count):
                mask = buffer[row + 12 + index]
                value = buffer[target + 8 + offset + index] & mask
                if value != mask and mask != 255:
                    if mode == 0:
                        first_index += 1
                        row = base + first_index * 88
                    break
                packet[offset + index] |= (
                    value if mode == 1 else buffer[row + 44 + index]
                )
            next_row = base + (first_index + 1) * 88
            if next_row + 88 > 0x8560:
                raise ValueError("VC05 next descriptor crosses native allocation")
            if buffer[row] != buffer[next_row]:
                break
            first_index += 1
        first_index += 1
        changed = False
        while True:
            row = base + second_index * 88
            if row + 88 > 0x8560:
                raise ValueError("VC05 rewrite descriptor crosses allocation")
            offset, count, mode = (
                _word(buffer, row + 8),
                _word(buffer, row + 76),
                _word(buffer, row + 80),
            )
            if count > 32 or offset + count > len(packet):
                raise ValueError("VC05 rewrite mask crosses native request allocation")
            while support_index < 776:
                support = 0xE2D0 + support_index * 48
                if (
                    buffer[support] == buffer[row]
                    and _word(buffer, support + 8) == offset
                    and buffer[support + 12] == buffer[row + 12]
                ):
                    break
                support_index += 1
            else:
                raise ValueError("VC05 native support match is missing")
            if not _word(buffer, support + 4):
                for index in range(count):
                    packet[offset + index] &= buffer[row + 12 + index] ^ 255
                if mode == 0:
                    changed |= _word(buffer, support + 52) == 1
                    buffer[support + 52 : support + 56] = bytes(4)
                elif mode == 1 and count < 5:
                    if second_index == 0:
                        raise ValueError("VC05 native previous descriptor is missing")
                    row = base + (second_index - 1) * 88
                    previous_offset = _word(buffer, row + 8)
                    if previous_offset >= len(packet):
                        raise ValueError(
                            "VC05 previous descriptor offset crosses allocation"
                        )
                    packet[previous_offset] &= buffer[row + 12] ^ 255
            else:
                changed = True
            next_row = base + (second_index + 1) * 88
            second_index += 1
            support_index += 1
            if next_row + 88 > 0x8560:
                raise ValueError("VC05 next rewrite descriptor crosses allocation")
            if buffer[row] != buffer[next_row]:
                break
        size = _word(buffer, target + 0x408)
        if size > 1024:
            raise ValueError("VC05 native target size exceeds caller backing")
        if _word(buffer, target + 0x40C) and (size or changed):
            for _ in range(3):
                context.sleep(1000)
                result, response = _exchange(
                    context, comm, bytes((0x3B, buffer[target])) + bytes(packet[:size])
                )
                if not result and (len(response) < 2 or response[1] != buffer[target]):
                    result = 3
                if not result:
                    break
    return result


def _vc5(context: TYContext, comm: TYComm, buffer: bytearray) -> int:
    action = _word(buffer, 0x17450)
    if action == 0:
        return _vc5_support(context, comm, buffer)
    if action == 1:
        for target in range(0x8560, 0xE2D0, 0x410):
            if _word(buffer, target + 4) != 1:
                continue
            result, response = _exchange(context, comm, bytes((0xA9, buffer[target])))
            if result:
                return result
            if len(response) < 3 or response[1] != buffer[target]:
                return 3
            if len(response) - 2 > 1024:
                raise ValueError("VC05 response crosses caller target allocation")
            buffer[target + 8 : target + 6 + len(response)] = response[2:]
            buffer[target + 0x408 : target + 0x40C] = (len(response) - 2).to_bytes(
                4, "little"
            )
        return 0
    if _word(buffer, 0x17454) == 0:
        result = _vc_security(context, comm, False)
        if result:
            return result
        _vc5_rewrite(context, comm, buffer)
        result = _vc5_reset(context, comm)
        if result:
            return 1011
    context.sleep(1000)
    buffer[0x17454:0x17458] = (1).to_bytes(4, "little")
    result = _vc5_support(context, comm, buffer)
    if result:
        return result
    result = _vc_security(context, comm, False)
    if result:
        return result
    buffer[0x17458:0x1745C] = (1).to_bytes(4, "little")
    _vc5_rewrite(context, comm, buffer)
    return 1010


def _d15_settings(comm: TYComm) -> None:
    comm.configure("native_rva:142f0", 0)
    comm.configure("native_rva:14300", 180000)


def _d15(context: TYContext, comm: TYComm, buffer: bytearray) -> int:
    """Native P5 business only; admission awaits a distinct12820 P5 facade."""
    if len(buffer) < 5:
        raise ValueError("D15 native action/cancel buffer requires five bytes")
    operation_error: BaseException | None = None
    try:
        result = comm.initialize(0)
        if result:
            return result
        _d15_settings(comm)
        if _word(buffer, 0) != 0:
            result, response = _exchange(context, comm, b"\x10\x03")
            if not result and (len(response) != 6 or response[1] != 3):
                result = 3
            poll_error: BaseException | None = None
            try:
                if result:
                    return result
                while True:
                    context.sleep(200)
                    result, response = _exchange(context, comm, b"\x31\x03\x11\x83")
                    if buffer[4] == 1 or result:
                        return result
                    if len(response) != 5 or response[1:4] != b"\x03\x11\x83":
                        return 3
                    if response[4] == 2:
                        return 0
                    if response[4] != 1:
                        return 3
            except BaseException as error:
                poll_error = error
                raise
            finally:
                try:
                    comm.session(1, 1)
                except BaseException:
                    if poll_error is None:
                        raise
        result = comm.session(1, 1)
        if result:
            return result
        result = comm.session(3, 1)
        if result:
            return result
        result, response = _exchange(context, comm, b"\x31\x01\x11\x83\x5a")
        if not result and (len(response) != 4 or response[1:4] != b"\x01\x11\x83"):
            result = 3
        if result == 0:
            comm.finalize()
            result = comm.select_protocol(3)
            if result == 0:
                result = comm.initialize(0)
                if result == 0:
                    _d15_settings(comm)
                    context.sleep(1000)
                    result, response = _exchange(context, comm, b"\x04")
                    if not result and len(response) != 1:
                        result = 3
                    if result == 0:
                        context.sleep(2000)
                comm.finalize()
                comm.select_protocol(1)
                restored = comm.initialize(0)
                if restored == 0:
                    _d15_settings(comm)
                if result == 0:
                    return 0xA92
        comm.session(1, 1)
        return result
    except BaseException as error:
        operation_error = error
        raise
    finally:
        _cleanup(context, comm, primary=operation_error)


def run_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    """Run a body; wrapper admission and scheduler remain in UtilityExEngine."""
    if hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256:
        raise TYSourceError("Retained TY source bytes differ from selected identity")
    if export not in supported_exports(context.module_sha256):
        raise TYSourceError("Retained TY source/export pair is not implemented")
    if export == _SZEIU:
        if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < 4:
            raise ValueError("SZEIU requires native mutable action DWORD")
        _cancel(context)
        result = _szeiu(context, args[0])
        context.state[_MANAGERS[context.module_sha256][1]] = result
        return result
    if export == _PI_ABSOLUTE:
        if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < 0x570:
            raise ValueError(
                "PI absolute requires native mutable descriptor buffer of0x570 bytes"
            )
        _cancel(context)
        result = _pi_absolute(context, context.comm("selected"), args[0])
        context.state[_MANAGERS[context.module_sha256][1]] = result
        return result
    if export == _PI_RESET:
        if args:
            raise TypeError("PI reset wrapper takes no native arguments")
        _cancel(context)
        manager, result_global = _MANAGERS[context.module_sha256]
        comm = context.comm(manager)
        operation_error: BaseException | None = None
        try:
            result = _pi_reset(context, comm)
            context.state[result_global] = result
            return result
        except BaseException as error:
            operation_error = error
            raise
        finally:
            _cleanup(context, comm, primary=operation_error)
    if len(args) != 1 or not isinstance(args[0], bytearray):
        raise TypeError(
            "Retained TY requires one caller-owned mutable native byte buffer"
        )
    buffer = args[0]
    required = (
        0x1745C
        if export == _VC5
        else 0x1094
        if export == _VIF1
        else 0x28C
        if export == _VIF2
        else 16
        if export in _VC34
        else 0x4F8
        if export in (_PI[0], _PI_SUPPORT)
        else 0x4BC
        if export == _PI[1]
        else 12
        if export in _VC + _VC_SUPPORT + _PI + _VC34
        or export in (_VIF1, _VIF2, _VC5)
        or export in (_VC_LEARN, _PI_SUPPORT)
        else 11
        if export in _HVB
        else 42
        if export == _DSC[0]
        else 1
    )
    if len(buffer) < required:
        raise ValueError(
            f"Retained TY native buffer requires at least {required} bytes"
        )
    _cancel(context)
    manager, result_global = _MANAGERS[context.module_sha256]
    if (
        export in _VC + _VC_SUPPORT + _PI + _VC34
        or export in (_VIF1, _VIF2, _VC5)
        or export in (_VC_LEARN, _PI_SUPPORT)
    ):
        manager = "selected"
    if export in _HVB and context.module_sha256 == SHA_PLUS_TY and context.mode == 22:
        manager = "native:1013e7d0"
    comm = context.comm(manager)
    retained = False
    operation_error: BaseException | None = None
    try:
        if export in _HVB:
            result, retained = _hvb(context, comm, buffer, export == _HVB[1])
            context.state[result_global] = result
            return result
        if export == _VC_LEARN:
            _pending(context, comm)
        result = comm.initialize(0)
        if export == _PI_SUPPORT:
            if result == 0:
                _pending(context, comm)
                result = _pi_support(context, comm, buffer)
            context.state[result_global] = result
            return result
        if export in _PI:
            if result == 0:
                _pending(context, comm)
            result = _pi(context, comm, buffer, export == _PI[0], result)
            context.state[result_global] = result
            return result
        if result == 0:
            if export != _VC_LEARN:
                if export in _VC + _VC_SUPPORT + _VC34 or export in (
                    _VIF1,
                    _VIF2,
                    _VC5,
                ):
                    _pending(context, comm)
                else:
                    comm.configure("native_1080", 0)
            if export not in _VC + _VC_SUPPORT + _VC34 and export not in (
                _VC_LEARN,
                _VIF2,
                _VIF1,
                _VC5,
            ):
                comm.configure("native_1084", 180000)
            result = (
                _vc5(context, comm, buffer)
                if export == _VC5
                else _vif1(context, comm, buffer)
                if export == _VIF1
                else _vif2(context, comm, buffer)
                if export == _VIF2
                else _vc34(context, comm, buffer, export == _VC34[1])
                if export in _VC34
                else _vc_support(context, comm, buffer, export == _VC_SUPPORT[1])
                if export in _VC_SUPPORT
                else _vc_learn(context, comm, buffer)
                if export == _VC_LEARN
                else _vc_count(context, comm, buffer, export == _VC[1])
                if export in _VC
                else _dsc_read(context, comm, buffer)
                if export == _DSC[0]
                else _dsc_clear(context, comm, buffer)
            )
        context.state[result_global] = result
        return result
    except BaseException as error:
        operation_error = error
        raise
    finally:
        if not retained:
            _cleanup(context, comm, primary=operation_error)
