"""Exact retained TY HNPCS, DMC, HNAHB, SIS and PSAALM business bodies.

The common UtilityEx dispatcher owns the native scheduler and wrapper mode gate.
Only communication primitives cross the context boundary; no business callbacks.
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

HNPCS = (
    "Ex2HNPCS_02_SendMessage",
    "Ex2HNPCS_02_SupportCheck",
    "Ex2HNPCS_03_InitializeTheLearningValue",
    "Ex2HNPCS_03_SupportCheck",
    "Ex2HNPCS_04_ClearPCSOperationCount",
    "Ex2HNPCS_04_ReadPCSOperationCount",
    "Ex2HNPCS_04_SupportCheck",
)
DMC = (
    "Ex2DMC_01_SendMessage",
    "Ex2DMC_02_ReadImageInformationOperation",
    "Ex2DMC_02_WriteImageInformationOperation",
)
HNAHB = ("Ex2HNAHB_01_GetSupport", "Ex2HNAHB_01_HistoryClear")
SIS = ("Ex2SIS_01_SendMessage", "Ex2SIS_02_SendMessage")
PSAALM = "Ex2PSAALM_01_SendMessage"


def supported_exports(sha: str) -> tuple[str, ...]:
    if sha == SHA_12_TY:
        return (*HNPCS, PSAALM)
    if sha == SHA_18_TY:
        return (*HNPCS, *DMC, *HNAHB, *SIS, PSAALM)
    if sha == SHA_PLUS_TY:
        return (*HNPCS, *DMC, *HNAHB, *SIS)
    return ()


def _check(ctx: TYContext) -> None:
    if ctx.is_cancelled():
        raise Cancelled("retained TY operation cancelled")


def _exchange(ctx: TYContext, comm: TYComm, request: bytes) -> tuple[int, bytes]:
    _check(ctx)
    status, reply = comm.exchange(request)
    if len(reply) > 0x1020:
        raise ValueError("native TY response exceeds 0x1020-byte buffer")
    return status, reply


def _init(ctx: TYContext, comm: TYComm, *, selected: bool = False) -> int:
    _check(ctx)
    status = comm.initialize()
    if not status:
        if selected:
            comm.configure(
                {
                    SHA_12_TY: "native_rva:b940",
                    SHA_18_TY: "native_rva:12180",
                    SHA_PLUS_TY: "native_rva:142f0",
                }[ctx.module_sha256],
                150,
            )
        else:
            for field, value in (
                ("native_1080", 0),
                ("native_1084", 180000),
                ("native_1064", 0),
            ):
                comm.configure(field, value)
    return status


def _close(
    comm: TYComm, *, restore: bool = False, primary: BaseException | None = None
) -> None:
    """Attempt all cleanup, preserving the original HOST/cancel exception object."""
    failure: BaseException | None = None
    try:
        if restore:
            comm.session(1, 1)
    except BaseException as error:  # noqa: BLE001 - preserve HOST/cancel identity
        failure = error
    try:
        comm.finalize()
    except BaseException as error:  # noqa: BLE001 - attempt cleanup after any fault
        if failure is None:
            failure = error
    if primary is None and failure is not None:
        raise failure


def _buffer(args: tuple[object, ...], size: int) -> bytearray:
    if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < size:
        raise ValueError(
            f"native TY operation requires bytearray of at least {size} bytes"
        )
    return args[0]


def _dword(data: bytearray, offset: int = 0) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _put(data: bytearray, offset: int, value: int) -> None:
    data[offset : offset + 4] = value.to_bytes(4, "little")


def _support_record(
    raw: bytes, offsets: tuple[int, ...], identifier: int
) -> tuple[int, bytes]:
    if len(offsets) != 256:
        raise ValueError("support table must contain 256 native offsets")
    offset = offsets[identifier]
    if offset == 0x1020:
        return 22, b""
    if offset < 0 or offset + 1 >= 0x1020:
        return 99, b""
    padded = raw + bytes(0x1020 - len(raw))
    length = padded[offset + 1]
    if offset + 1 + length > 0x1020:
        return 99, b""
    # The original permits offset+1+length==0x1020 then reads one byte past
    # the array. Reject that native fault instead of manufacturing a byte.
    if offset + 2 + length > 0x1020:
        raise ValueError("native support record crosses its allocated buffer")
    return 0, padded[offset + 2 : offset + 2 + length]


def _support(ctx: TYContext, comm: TYComm, data: bytearray, export: str) -> int:
    if export == HNPCS[1]:
        checks = ((2, 0xA7, ((3, 0x80),), 0, 3),)
    elif export == HNPCS[3]:
        checks = ((3, 0x43, ((3, 0xFC), (4, 0xF0), (5, 0xFF), (6, 0xFF)), 0, 2),)
    elif export == HNPCS[6]:
        checks = (
            (3, 0x42, ((3, 0xFF), (5, 0xFF)), 4, 2),
            (4, 0x42, ((3, 0xFF), (5, 0xFF)), 8, 2),
        )
    else:
        checks = ((3, 1, ((3, 0x20),), 0, 0),)
    for kind, identifier, masks, output, extra in checks:
        _check(ctx)
        status, raw, offsets = comm.support_snapshot(kind)
        if status:
            return status
        if len(raw) > 0x1020:
            raise ValueError("native support snapshot exceeds capacity")
        status, record = _support_record(raw, offsets, identifier)
        if status:
            return 3 if export == HNAHB[0] else status
        for position, mask in masks:
            index = position - 3
            if (
                len(record) < position - 2
                or not record[index]
                or record[index] & mask != mask
            ):
                return 3 if export == HNAHB[0] else 22
        if export == HNAHB[0]:
            offset = offsets[1] + 1
            _put(data, 0, (raw + bytes(0x1020 - len(raw)))[offset])
        else:
            count = sum(value != 0 for value in record)
            if count or export == HNPCS[6]:
                _put(data, output, count + extra)
    return 0


def _selected(ctx: TYContext, export: str, args: tuple[object, ...]) -> int:
    if export == PSAALM:
        if args:
            raise ValueError("PSAALM takes no arguments")
        data = bytearray()
    else:
        data = _buffer(
            args,
            12
            if export == HNPCS[6]
            else (8 if export == HNPCS[4] and ctx.module_sha256 == SHA_PLUS_TY else 4),
        )
    comm = ctx.comm("selected")
    primary: BaseException | None = None
    try:
        status = _init(ctx, comm, selected=True)
        if status:
            return status
        if export in (HNPCS[1], HNPCS[3], HNPCS[6], HNAHB[0]):
            return _support(ctx, comm, data, export)
        if export == PSAALM:
            ctx.native_sleep(100)
            request = b"\x3b\x85"
            status, reply = _exchange(ctx, comm, request)
            return status or (0 if len(reply) == 2 and reply[1] == 0x85 else 3)
        if export == HNPCS[5]:
            status, reply = _exchange(ctx, comm, b"\xa9\x42")
            if not status:
                if len(reply) < 5 or reply[1] != 0x42:
                    return 3
                data[0], data[1] = reply[2], reply[4]
            return status
        if export == HNAHB[1]:
            length = _dword(data) + 2
            if not 3 <= length <= 0x1020:
                raise ValueError("HNAHB clear length exceeds native request capacity")
            status, reply = _exchange(ctx, comm, b"\x3b\x01\x20" + bytes(length - 3))
            return status or (0 if reply else 3)
        request = {
            HNPCS[0]: b"\x30\xa7\x00\x80\x00",
            HNPCS[2]: b"\x3b\x43\x00\x00\xff\x00",
            HNPCS[4]: b"\x3b\x42",
        }[export]
        length = (
            _dword(data, 4)
            if export == HNPCS[4] and ctx.module_sha256 == SHA_PLUS_TY
            else _dword(data)
        )
        if length > 0x1020:
            raise ValueError("HNPCS send length exceeds native request capacity")
        request = (request + bytes(max(0, length - len(request))))[:length]
        status, reply = _exchange(ctx, comm, request)
        echo = {HNPCS[0]: 0xA7, HNPCS[2]: 0x43, HNPCS[4]: 0x42}[export]
        if not status and (len(reply) != 2 or reply[1] != echo):
            status = 3
        if export == HNPCS[0] and status:
            _exchange(ctx, comm, b"\x30")
        return 1001 if export == HNPCS[4] and not status else status
    except BaseException as error:
        primary = error
        raise
    finally:
        _close(comm, primary=primary)


def _routine(
    ctx: TYContext, comm: TYComm, request: bytes, minimum: int = 0
) -> tuple[int, bytes]:
    status, reply = _exchange(ctx, comm, request)
    # Native compares the echo in its zero-filled receive array even when the
    # reported length is short; retain that comparison separately from minimum.
    padded = reply + bytes(max(0, len(request[:4]) - len(reply)))
    if not status and (len(reply) < minimum or padded[1:4] != request[1:4]):
        status = 3
    return status, reply


def _security(ctx: TYContext, comm: TYComm) -> int:
    status, reply = _exchange(ctx, comm, b"\x27\x03")
    if status:
        return status
    if len(reply) < 18 or reply[1] != 3:
        return 3
    seed = reply[2:18]
    if not any(seed):
        return 0
    key = bytearray(seed)
    shifts = (1, 2, 3, 3, 2, 1, 1, 2, 3, 3, 2, 1, 1, 2, 3, 3)
    for index, value in enumerate(seed):
        shift = ((value >> shifts[index]) & 3) + 1
        key[index] = (
            ((value >> (8 - shift)) | (value << shift)) + key[value & 15]
        ) & 255
    status, reply = _exchange(ctx, comm, b"\x27\x04" + key)
    return status or (0 if len(reply) >= 2 and reply[1] == 4 else 3)


def _dmc(ctx: TYContext, export: str, data: bytearray) -> int:
    plus = ctx.module_sha256 == SHA_PLUS_TY
    comm = ctx.comm("native:101392d0" if plus else "native:1011d4f0")
    retain = False
    primary: BaseException | None = None
    try:
        if export == DMC[0] and _dword(data):
            while not data[4]:
                ctx.native_sleep(200)
                status, reply = _routine(ctx, comm, b"\x31\x03\x10\x15", 5)
                if status:
                    return 1008
                if reply[4] not in (0, 1):
                    return 0 if reply[4] == 2 else 1008
            return 0
        status = _init(ctx, comm)
        if status:
            return status
        if export == DMC[0]:
            status = comm.session(3, 1, normal_first=True, stop_on_error=False)
            if not status:
                status, _ = _routine(ctx, comm, b"\x31\x01\x10\x15")
                retain = not status
                if status:
                    comm.session(1, 1)
            return status
        status = comm.session(1, 1)
        if not status:
            status = comm.session(3, 1)
        if status:
            return status
        if export == DMC[1]:
            status, reply = _exchange(ctx, comm, b"\x22\x20\x03")
            if not status:
                if len(reply) < 5 or reply[1:3] != b"\x20\x03":
                    status = 3
                else:
                    data[: len(reply)] = reply
                    _put(data, 0x1020, len(reply))
            comm.session(1, 1)
            return status
        status = _security(ctx, comm)
        if status:
            comm.session(1, 1)
            return status
        length = _dword(data, 0x1020)
        if length > 0x1020:
            raise ValueError("DMC image length exceeds native buffer capacity")
        request = bytearray(0x1020)
        request[:length] = data[:length]
        request[0:3] = b"\x2e\x20\x03"
        request[4] ^= 0x80
        status, reply = _exchange(ctx, comm, bytes(request[:length]))
        if not status and (len(reply) < 3 or reply[1:3] != b"\x20\x03"):
            status = 3
        comm.session(1, 1)
        return 1001 if status else 1000
    except BaseException as error:
        primary = error
        raise
    finally:
        if not retain:
            _close(
                comm, restore=export == DMC[0] and bool(_dword(data)), primary=primary
            )


def _sis_read(
    ctx: TYContext, comm: TYComm, first: int, second: int, minimum: int
) -> tuple[int, bytes]:
    request = bytes((0x22, first, second))
    status, reply = _exchange(ctx, comm, request)
    if not status and (len(reply) < minimum + 3 or reply[1:3] != request[1:3]):
        status = 3
    return status, reply[3:]


def _sis_routine(
    ctx: TYContext,
    comm: TYComm,
    action: int,
    identifier: int,
    mode: int,
    payload: bytes = b"",
    minimum: int = 0,
) -> tuple[int, bytes]:
    request = bytes((0x31, action, identifier, mode)) + payload
    status, reply = _routine(ctx, comm, request, minimum + 4)
    return status, reply[4:]


def _sis_ready(ctx: TYContext, comm: TYComm, data: bytearray) -> int:
    if data[0x28] != 1:
        ctx.native_sleep(200)
        status, reply = _sis_read(ctx, comm, 1, 1, 32)
        if status:
            return status
        data[0x28] = 1
        if not reply[2] & 128:
            data[0x29] = 2
    if data[0x29] == 2:
        return 3
    if data[0x29] != 1:
        ctx.native_sleep(200)
        status, reply = _sis_read(ctx, comm, 0x10, 0, 32)
        if status:
            return status
        data[0x29] = 1
        for offset, bit in ((0x2A, 6), (0x2B, 5), (0x2C, 4)):
            data[offset] = 2 + ((reply[1] >> bit) & 1)
    return 0


def _sis02(ctx: TYContext, comm: TYComm, data: bytearray) -> int:
    action = _dword(data)
    if action in (0, 1, 3):
        status = _sis_ready(ctx, comm, data)
        if status:
            return status
    if action == 0:
        if data[0x2A:0x2C] != b"\x03\x03":
            return 3
        for identifier, minimum, offset in ((10, 6, 4), (11, 16, 10)):
            ctx.native_sleep(200)
            status, reply = _sis_read(ctx, comm, 0x10, identifier, minimum)
            if status:
                return status
            data[offset : offset + minimum] = reply[:minimum]
        return 0
    if action == 1:
        if data[0x2C] != 3:
            return 3
        ctx.native_sleep(200)
        status, reply = _sis_read(ctx, comm, 0x10, 12, 3)
        if status:
            return status
        if reply[0] & 0xF0:
            return 2001
        if data[0x2D] != 1:
            ctx.native_sleep(200)
            status, reply = _sis_routine(ctx, comm, 1, 0x10, 1, minimum=32)
            if status:
                return status
            data[0x2D] = 1
            if not reply[2] & 64:
                data[0x2E] = 2
        if data[0x2E] == 2:
            return 3
        if data[0x2E] != 1:
            ctx.native_sleep(200)
            status, reply = _sis_routine(ctx, comm, 1, 0x11, 0, minimum=32)
            if status:
                return status
            data[0x2E] = 1
            data[0x2F], data[0x30] = (
                2 + ((reply[0] >> 6) & 1),
                2 + ((reply[0] >> 5) & 1),
            )
        if data[0x2F:0x31] != b"\x03\x03":
            return 3
        ctx.native_sleep(200)
        return _sis_routine(ctx, comm, 1, 0x11, 2, b"\x01")[0]
    if action == 5:
        payload = b"".join(bytes((0, value)) for value in data[0x1A:0x22])
        ctx.native_sleep(200)
        return 2004 if _sis_routine(ctx, comm, 1, 0x11, 3, payload)[0] else 0
    if action in (2, 6):
        ctx.native_sleep(200)
        while _dword(data, 0x24) != 1:
            status, reply = _sis_routine(
                ctx, comm, 3, 0x11, 2 if action == 2 else 3, minimum=1
            )
            if status:
                return 2002 if action == 2 else 2003
            if reply[0] == 1:
                ctx.native_sleep(200)
                continue
            if reply[0] == 2:
                return 0
            if reply[0] != 3:
                return 2002 if action == 2 else 2003
            ctx.native_sleep(200)
            if _dword(data, 0x24) == 1:
                break
            status, reply = _sis_read(ctx, comm, 0x10, 12, 3)
            if status:
                return 2002 if action == 2 else 2003
            if reply[0] & 0xF0 == (0x20 if action == 2 else 0x50):
                return 2005 if action == 2 else 2007
            if reply[0] & 0xF0 == 0x80:
                data[0x23] = reply[2]
                return 2006 if action == 2 else 2008
            return 2002 if action == 2 else 2003
        return 2013
    if action in (3, 4, 8):
        if action == 3 and data[0x2C] != 3:
            return 3
        if action == 8:
            ctx.native_sleep(200)
        while action == 3 or _dword(data, 0x24) != 1:
            status, reply = _sis_read(ctx, comm, 0x10, 12, 3)
            if status:
                return 2012 if action == 8 else 2002
            high = reply[0] & 0xF0
            if action == 8:
                if high == 0x40:
                    ctx.native_sleep(200)
                    continue
                if high == 0x90:
                    data[0x22] = reply[1]
                    return 0
                if high in (0x60, 0x70, 0x80):
                    if high == 0x80:
                        data[0x23] = reply[2]
                    return {0x60: 2009, 0x70: 2010, 0x80: 2011}[high]
                return 2012
            if high == 0x90:
                data[0x22] = reply[1]
                if action == 3 or reply[1] > 99:
                    return 0
                continue
            if high in (0x80, 0xA0):
                data[0x23] = reply[2]
                return 2000
            if high == 0:
                data[0x22] = reply[1]
                return 2001
            return 2002
        return 2013
    return 0


def _sis(ctx: TYContext, export: str, data: bytearray) -> int:
    plus = ctx.module_sha256 == SHA_PLUS_TY
    comm = ctx.comm("native:10134b78" if plus else "native:1011e618")
    action = _dword(data)
    retain = False
    restore = False
    primary: BaseException | None = None
    try:
        if export == SIS[0]:
            if action == 0:
                status = _init(ctx, comm)
                if not status:
                    status = comm.session(3, 1, normal_first=True)
                    if not status:
                        restore = True
                        ctx.native_sleep(200)
                        status, _ = _sis_routine(ctx, comm, 1, 0x11, 1)
                        retain = not status
                return status
            status = 0
            restore = True
            while not data[5]:
                ctx.native_sleep(200)
                status, reply = _sis_routine(ctx, comm, 3, 0x11, 1, minimum=1)
                if status or reply[0] == 2:
                    break
                if reply[0] == 1:
                    continue
                status, reply = _sis_read(ctx, comm, 0x10, 5, 1)
                if not status:
                    status = 3 if not reply[0] & 0xF0 else 2205
                    if status == 2205:
                        data[4] = reply[0]
                break
            return status
        if action in (0, 1, 3, 5, 7):
            status = _init(ctx, comm)
            if status:
                retain = True  # Native bypasses finalize on initialization error.
                return status
            status = comm.session(3, 1, normal_first=True)
            if status:
                return status
        restore = True
        status = _sis02(ctx, comm, data)
        if action in (2, 4, 6, 8) and _dword(data, 0x24) == 1:
            status = 2013
        retain = action not in (0, 2, 4, 6) and not status
        return status
    except BaseException as error:
        primary = error
        raise
    finally:
        if not retain:
            _close(comm, restore=restore, primary=primary)


def run_body(export: str, args: tuple[object, ...], ctx: TYContext) -> int:
    if hashlib.sha256(ctx.module_bytes).hexdigest() != ctx.module_sha256:
        raise TYSourceError("TY module bytes do not match selected source identity")
    if export not in supported_exports(ctx.module_sha256):
        raise TYSourceError("retained TY source/export pair is not supported")
    _check(ctx)
    if export in (*HNPCS, *HNAHB, PSAALM):
        return _selected(ctx, export, args)
    data = _buffer(
        args,
        (8 if export == DMC[0] else 0x1024)
        if export in DMC
        else (6 if export == SIS[0] else 0x31),
    )
    return _dmc(ctx, export, data) if export in DMC else _sis(ctx, export, data)
