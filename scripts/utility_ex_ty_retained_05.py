"""Exact retained TY STB, RCAM and PSA SRS bodies over the selected native controller.

Mutable arguments are borrowed bytearrays containing native little-endian DWORDs.
The common UtilityEx engine supplies wrapper/thread scheduling and source identity.
"""

from __future__ import annotations

import hashlib
import struct

from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import (
    SHA_12_TY,
    SHA_18_TY,
    SHA_PLUS_TY,
    TYComm,
    TYContext,
    TYSourceError,
)

STB03 = tuple(
    "Ex2STB_03_" + x
    for x in (
        "SupportCheck",
        "PreSensorCalibration",
        "StartSensorCalibration",
        "ExecutingSensorCalibration",
    )
)
STB04 = tuple(
    "Ex2STB_04_" + x
    for x in (
        "SupportCheck",
        "PreparateActiveStabi",
        "DriveActiveStabi",
        "RestartActiveStabi",
        "ExitActiveStabi",
    )
)
PSA = ("Ex2PSASRS_01_GetStatus", "Ex2PSASRS_01_SetStatus")
RCAM = tuple(f"Ex2RCAM_0{i}_SendMessage" for i in (1, 2, 3))
SOURCES = (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY)
# Pending-limit setters are global procedures, not fields of a stack manager.
PENDING = {
    SHA_12_TY: "native_rva:b940",
    SHA_18_TY: "native_rva:12180",
    SHA_PLUS_TY: "native_rva:142f0",
}
POINTER = {
    SHA_12_TY: ("100afea4", "100ab6c0"),
    SHA_18_TY: ("1011f764", "10118d70"),
    SHA_PLUS_TY: ("1013fab0", "10139248"),
}
RESULT = {SHA_12_TY: "100ab770", SHA_18_TY: "10118e38", SHA_PLUS_TY: "10134ab8"}
DRIVE = bytes.fromhex("30020001a00a636301")


def supported_exports(sha: str) -> tuple[str, ...]:
    if sha not in SOURCES:
        return ()
    return (
        STB03
        + STB04
        + (PSA if sha != SHA_PLUS_TY else ())
        + (RCAM if sha != SHA_12_TY else ())
    )


def _cancel(c: TYContext) -> None:
    if c.is_cancelled():
        raise Cancelled("TY retained operation cancelled")


def _u32(buf: bytearray, offset: int) -> int:
    return struct.unpack_from("<I", buf, offset)[0]


def _write(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", buf, offset, value)


def _target(buf: bytearray, offset: int) -> tuple[int, int]:
    return _u32(buf, offset), _u32(buf, offset + 4)


def _exchange(
    c: TYContext,
    target: tuple[int, int] | None,
    request: bytes,
    *,
    cleanup: bool = False,
) -> tuple[int, bytes]:
    if not cleanup:
        _cancel(c)
    comm = c.comm("selected")
    if target is not None:
        # Native setup writes the module-global parameter pointer before connecting.
        pointer, data = POINTER[c.module_sha256]
        c.state["native_global:" + pointer] = int(data, 16) if target[1] == 0 else 0
        comm.select_target(*target)
    try:
        status = comm.initialize(0)
        if status:
            return status, b""
        comm.configure(PENDING[c.module_sha256], 150)
        return comm.exchange(request)
    finally:
        comm.finalize()


def _command(
    c: TYContext,
    target: tuple[int, int],
    request: bytes,
    check: str = "echo",
    *,
    cleanup: bool = False,
) -> int:
    status, reply = _exchange(c, target, request, cleanup=cleanup)
    if status:
        return status
    if check == "ignore":
        return 0
    if check == "one":
        return 0 if len(reply) == 1 else 3
    if len(reply) < 2:
        return 3
    if check == "stop":
        return 0 if len(reply) == 2 and reply[1] == 2 else 6
    if reply[1] != request[1]:
        return 3
    return 6 if check == "two" and len(reply) != 2 else 0


def _dtc(c: TYContext, target: tuple[int, int], policy: str) -> tuple[int, bytes]:
    status, reply = _exchange(c, target, b"\x13\x81")
    if status:
        return status, reply
    if len(reply) < 2:
        return 3, reply
    if policy == "empty":
        return (0 if reply == bytes((reply[0], 0)) else 6), reply
    if len(reply) != reply[1] * 2 + 2:
        return (3 if policy == "find" else 6), reply
    if policy == "allowed" and any(
        reply[i : i + 2] not in (b"\x59\xa7", b"\x59\xa9")
        for i in range(2, len(reply), 2)
    ):
        return 6, reply
    return 0, reply


def _snapshot(
    c: TYContext, target: tuple[int, int], kind: int
) -> tuple[int, bytes, tuple[int, ...]]:
    _cancel(c)
    comm = c.comm("selected")
    pointer, data = POINTER[c.module_sha256]
    c.state["native_global:" + pointer] = int(data, 16) if target[1] == 0 else 0
    comm.select_target(*target)
    try:
        status = comm.initialize(0)
        if status:
            return status, b"", ()
        comm.configure(PENDING[c.module_sha256], 150)
        return comm.support_snapshot(kind)
    finally:
        comm.finalize()


def _record(data: bytes, offsets: tuple[int, ...], kind: int) -> tuple[int, bytes]:
    if len(offsets) != 256 or len(data) > 0x1020:
        raise ValueError(
            "Native support snapshot requires 256 offsets and bounded bytes"
        )
    offset = offsets[kind]
    if offset == 0x1020:
        return 22, b""
    if type(offset) is not int or offset < 0 or offset + 1 >= len(data):
        return 99, b""
    size = data[offset + 1]
    if offset + 1 + size > 0x1020 or offset + 2 + size > len(data):
        return 99, b""
    return 0, data[offset : offset + 2 + size]


def _required(record: bytes, position: int) -> int:
    if record[1] < position - 2 or position - 1 >= len(record):
        return 22
    return 0 if record[position - 1] == 255 else 22


def _support(c: TYContext, buf: bytearray, active: bool) -> int:
    status, data, offsets = _snapshot(c, (0x7A3, 0), 3)
    if status:
        return status
    status, record = _record(data, offsets, 1)
    if status:
        return status
    for position in (3, 4):
        status = _required(record, position)
        if status:
            return status
    # Native reads byte offset+1 of record ID 1, i.e. its length, not its flags.
    _write(buf, 0, record[1])
    if not active:
        status, data, offsets = _snapshot(c, _target(buf, 12), 1)
        if status:
            return status
        status, record = _record(data, offsets, 0x83)
        if status:
            return status
        status = _required(record, 5)
        if status:
            return status
        _write(buf, 8, sum(x != 0 for x in record[2:]) + 2)
    status, data, offsets = _snapshot(c, _target(buf, 8 if active else 12), 2)
    if status:
        return status
    status, record = _record(data, offsets, 2)
    if status:
        return status
    for position in range(3, 9):
        status = _required(record, position)
        if status:
            return status
    count = sum(x != 0 for x in record[2:])
    if not count:
        return 22
    _write(buf, 4, count + 3)
    return 0


def _pre(c: TYContext, buf: bytearray) -> int:
    target = _target(buf, 12)
    status, _ = _dtc(c, (0x7A3, 0), "empty")
    if status:
        return status
    status, _ = _dtc(c, target, "allowed")
    if status:
        return status
    status, reply = _exchange(c, target, b"\x21\x83")
    if status:
        return status
    if len(reply) < 5 or reply[1] != 0x83:
        return 3
    if reply[4] == 1:
        return 0
    if reply[4] != 0:
        return 3
    status = _command(c, target, b"\x10\x40", "one")
    if status:
        return status
    status = _command(c, target, b"\xa6\x01", "one")
    result = _command(c, target, b"\x10\x01", "one", cleanup=True)
    return status or result


def _start(c: TYContext, buf: bytearray) -> int:
    target = _target(buf, 12)
    status = _command(c, (0x7A3, 0), b"\x10\x40", "one")
    if status:
        return status
    status = _command(c, (0x7A3, 0), b"\x3b\x01\x01\x00")
    if not status:
        status = _command(c, target, b"\x10\x40", "one")
        if not status:
            status = _command(c, target, b"\x10\x62", "one")
            if not status:
                status = _command(c, target, DRIVE)
            if not status:
                return 0
            _command(c, target, b"\x10\x01", "ignore", cleanup=True)
    _command(c, (0x7A3, 0), b"\x10\x01", "ignore", cleanup=True)
    return status


def _executing(c: TYContext, buf: bytearray) -> int:
    target = _target(buf, 12)
    status, reply = _dtc(c, target, "find")
    if not status and any(
        reply[i : i + 2] in (b"\x59\xa7", b"\x59\xa9") for i in range(2, len(reply) - 1)
    ):
        status = 6
    # Both native cleanup calls run even after a nonzero diagnostic result.
    _command(c, target, b"\x10\x01", "ignore", cleanup=True)
    _command(c, (0x7A3, 0), b"\x10\x01", "ignore", cleanup=True)
    return status


def _active(c: TYContext, buf: bytearray, export: str) -> int:
    if export == STB04[4]:
        _command(c, (0x7A3, 0), b"\x3b\x01\x00\x00", "stop", cleanup=True)
        _command(c, (0x7A3, 0), b"\x10\x01", cleanup=True)
        return 0
    target = _target(buf, 8)
    if export == STB04[1]:
        status, _ = _dtc(c, (0x7A3, 0), "empty")
        return status or _dtc(c, target, "empty")[0]
    if export == STB04[2]:
        status = _command(c, (0x7A3, 0), b"\x10\x40", "ignore")
        if status:
            return status
        status = _command(c, (0x7A3, 0), b"\x3b\x01\x01\x00", "two")
        if status:
            _command(c, (0x7A3, 0), b"\x10\x01", cleanup=True)
            return status
    status = _command(c, target, DRIVE)
    if status:
        _command(c, (0x7A3, 0), b"\x3b\x01\x00\x00", "stop", cleanup=True)
        _command(c, (0x7A3, 0), b"\x10\x01", cleanup=True)
    return status


def _psa(c: TYContext, buf: bytearray, write: bool) -> int:
    _cancel(c)
    comm = c.comm("selected")
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(PENDING[c.module_sha256], 150)
        c.native_sleep(100)
        _cancel(c)
        if write:
            identifier = 0xDF if _u32(buf, 0) == 1 else 0xE0
            status, reply = comm.exchange(bytes((0x3B, identifier, 0)))
            return status or (0 if len(reply) == 2 and reply[1] == identifier else 3)
        status, reply = comm.exchange(b"\x21\x80")
        if status:
            return status
        if len(reply) != 24 or reply[1] != 0x80:
            return 3
        # Native checks response positions 20..22 before choosing the second ID.
        identifier, length, index = (
            (0xD0, 8, 7) if reply[20:23] == b"FYS" else (0xCA, 1, 0)
        )
        c.native_sleep(100)
        _cancel(c)
        status, reply = comm.exchange(bytes((0x21, identifier)))
        if status:
            return status
        if len(reply) != length + 2 or reply[1] != identifier:
            return 3
        buf[4] = reply[2 + index] & 15
        return 0
    finally:
        comm.finalize()


def _rcam_frame(
    comm: TYComm, request: bytes, minimum: int, echo: int
) -> tuple[int, bytes]:
    if len(request) > 0x1020:
        raise ValueError("RCAM request exceeds native 0x1020 allocation")
    status, reply = comm.exchange(request)
    if len(reply) > 0x1020:
        raise ValueError("RCAM reply exceeds native 0x1020 allocation")
    if status:
        return status, reply
    if len(reply) < minimum or reply[1 : 1 + echo] != request[1 : 1 + echo]:
        return 3, reply
    return 0, reply


def _rcam_key(comm: TYComm) -> int:
    status, reply = _rcam_frame(comm, b"\x27\x03", 8, 1)
    if status:
        return status
    seed = reply[2:8]
    if seed == bytes(6):
        return 0
    key = bytearray(seed)
    for i, shift in enumerate((1, 2, 3, 3, 2, 1)):
        value = seed[i]
        index = value & 7
        if index > 5:
            index -= 6
        rotate = ((value >> shift) & 3) + 1
        key[i] = (((value >> (8 - rotate)) | (value << rotate)) + key[index]) & 255
    return _rcam_frame(comm, b"\x27\x04" + key, 2, 1)[0]


def _rcam(c: TYContext, buf: bytearray, export: str) -> int:
    comm = c.comm(
        "native:1011d4f0" if c.module_sha256 == SHA_18_TY else "native:101392d0"
    )
    action = _u32(buf, 0)
    retain = False
    close_session = False
    try:
        if export == RCAM[1] or action in (0, 1):
            status = comm.initialize(0)
            if status:
                return status
            if export == RCAM[2] and action == 0:
                return 1000
            comm.configure("native_1080", 0)
            comm.configure("native_1084", 180000)
            comm.configure("native_1064", 0)
        if export == RCAM[1]:
            status = comm.session(3, 1, normal_first=True)
            if status:
                return status
            close_session = True
            if _u32(buf, 0x1028) == 0:
                status, reply = _rcam_frame(comm, b"\x22\x20\x30", 5, 2)
                if not status:
                    payload = reply[3:]
                    buf[4 : 4 + len(payload)] = payload
                    _write(buf, 0, len(payload))
                return status
            size = _u32(buf, 0)
            if not 2 <= size <= 0x101D:
                raise ValueError("RCAM native payload requires 2..4125 bytes")
            status = _rcam_key(comm)
            if status:
                return status
            c.native_sleep(100)
            _cancel(c)
            payload = bytearray(buf[4 : 4 + size])
            if buf[0x1024] == 1:
                payload[1] &= 0x7F
            else:
                payload[1] |= 0x80
            status, _ = _rcam_frame(comm, b"\x2e\x20\x30" + payload, 3, 2)
            return 2000 if status else 0
        if export == RCAM[2]:
            if action == 1:
                status = comm.session(3, 1, normal_first=True)
                if status:
                    return status
                close_session = True
                status, _ = _rcam_frame(
                    comm, bytes((0x31, 1, 0x11, 0x31, buf[8], buf[11], buf[12])), 4, 3
                )
                retain = status == 0
                return status
            close_session = True
            while buf[4] == 0:
                _cancel(c)
                c.native_sleep(200)
                _cancel(c)
                status, reply = _rcam_frame(comm, b"\x31\x03\x11\x31", 5, 3)
                if status:
                    return status
                if reply[4] == 2:
                    return 0
                if reply[4] == 3:
                    return 1008
                if reply[4] not in (0, 1):
                    return 3
            return 0
        if action == 0:
            _write(buf, 4, 0)
            status = comm.session(3, 1, normal_first=True)
            if status:
                return status
            close_session = True
            status, reply = _rcam_frame(comm, b"\x31\x01\x10\x01", 36, 3)
            if status:
                return status
            if not reply[6] & 0x80:
                return 22
            status, reply = _rcam_frame(comm, b"\x31\x01\x10\x00", 36, 3)
            if status:
                return status
            flags = reply[6]
            if not flags & 0x18:
                return 22
            _write(
                buf,
                4,
                (0x80000000 if flags & 0x10 else 0) | (0x40000000 if flags & 8 else 0),
            )
            return 0
        if action in (1, 3):
            if action == 1:
                status = comm.session(3, 1, normal_first=True)
                if status:
                    return status
            mask = 0x80000000 if action == 1 else 0x40000000
            flags = _u32(buf, 4)
            if not flags & mask:
                close_session = action == 3
                status = 22
            elif action == 1 and flags & 0x40000000:
                status = 22
            else:
                identifier = 0x14 if action == 1 else 0x15
                payload = b"\xff\xff" if action == 1 else b""
                status, _ = _rcam_frame(
                    comm, bytes((0x31, 1, 0x10, identifier)) + payload, 4, 3
                )
                close_session = status != 0
            retain = status in (0, 22) if action == 1 else status == 0
            return status
        if action == 5:
            close_session = True
            return 0
        close_session = True
        while _u32(buf, 8) == 0:
            _cancel(c)
            c.native_sleep(200)
            _cancel(c)
            status, reply = _rcam_frame(comm, b"\x22\x11\x27", 8, 2)
            if status:
                return status
            if reply[7] == 1:
                if action == 2:
                    retain = True
                    close_session = False
                return 0
        retain = action == 2
        return 0
    finally:
        try:
            if close_session and not (retain and action in (1, 3)):
                comm.session(1, 1)
        finally:
            if not retain:
                comm.finalize()
        c.state["ty_retained05:rcam_connected"] = retain


def run_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    if export not in supported_exports(context.module_sha256):
        raise TYSourceError("Retained TY export/source pair has no reviewed body")
    if hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256:
        raise TYSourceError("TY retained HOST module identity mismatch")
    if len(args) != 1 or not isinstance(args[0], bytearray):
        raise TypeError("One borrowed native mutable bytearray is required")
    buf = args[0]
    required = (
        0
        if export == STB04[4]
        else 5
        if export == PSA[0]
        else 4
        if export in PSA or export in RCAM
        else 20
        if export in STB03
        else 16
    )
    if len(buf) < required:
        raise ValueError("Native argument buffer is truncated")
    if export == RCAM[1]:
        required = 0x102C
    elif export == RCAM[0]:
        action = _u32(buf, 0)
        required = 8 if action in (0, 1, 3) else 12 if action not in (5,) else 4
    elif export == RCAM[2]:
        action = _u32(buf, 0)
        required = 4 if action == 0 else 13 if action == 1 else 5
    if len(buf) < required:
        raise ValueError("Native action argument buffer is truncated")
    _cancel(context)
    if export in RCAM:
        result = _rcam(context, buf, export)
    elif export in PSA:
        result = _psa(context, buf, export == PSA[1])
    elif export == STB03[0] or export == STB04[0]:
        result = _support(context, buf, export == STB04[0])
    elif export == STB03[1]:
        result = _pre(context, buf)
    elif export == STB03[2]:
        result = _start(context, buf)
    elif export == STB03[3]:
        result = _executing(context, buf)
    else:
        result = _active(context, buf, export)
    context.state["native_global:" + RESULT[context.module_sha256]] = result
    return result
