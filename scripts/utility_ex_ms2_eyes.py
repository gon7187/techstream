"""Exact TY18/Plus MS2 EYES controllers; caller-owned PE data is never executed."""

from __future__ import annotations

import hashlib
import os
import shutil
import struct
from datetime import datetime
from pathlib import Path
from typing import Protocol, cast

from scripts import utility_ex_ms2 as common
from scripts import utility_ex_security as security
from scripts.utility_ex_ty import (
    SHA_18_TY,
    SHA_PLUS_TY,
    TYComm,
    TYContext,
    TYSourceError,
)
from scripts.utility_ex_ty_retained_03 import _module_data


class EYESComm(TYComm, Protocol):
    def select_diagnostic_mode(self, mode: int) -> int: ...


_EXPORTS = tuple(f"Ex2MS2EYES_{i:02}_SendMessage" for i in range(1, 8))
# Source addresses only: no source key or captured vehicle bytes are shipped.
_LAYOUT = {
    SHA_18_TY: (
        "native:1011a220",
        "native:1011c400",
        0xF8598,
        0xF85CC,
        0xDBCC0,
        0xDBE28,
        0xDBE38,
        0xDBE3C,
        0xDBE40,
        0x1012AE2C,
    ),
    SHA_PLUS_TY: (
        "native:1013d6a8",
        "native:10135c58",
        0xF4090,
        0xF40C4,
        0xE0970,
        0xE0B20,
        0xE0B30,
        0xE0BC4,
        0xE0B38,
        0x10153548,
    ),
}
_IMMEDIATE = {
    SHA_18_TY: tuple(
        (rva, 1)
        for rva in (
            0xA9970,
            0xA9975,
            0xA997A,
            0xA997F,
            0xA9984,
            0xA9989,
            0xA998E,
            0xA9993,
            0xA9998,
            0xA9950,
            0xA999D,
            0xA99A2,
            0xA99A7,
            0xA9950,
            0xA99AC,
            0xA99B1,
        )
    ),
    SHA_PLUS_TY: tuple((rva, 4) for rva in (0xAED78, 0xAED82, 0xAED89, 0xAED90)),
}


def supported_exports(source_sha256: str) -> tuple[str, ...]:
    return _EXPORTS if source_sha256 in _LAYOUT else ()


def _data(context: TYContext, rva: int, size: int) -> bytes:
    return _module_data(context.module_bytes, rva, size)


def _ids(context: TYContext, index: int) -> tuple[int, ...]:
    return struct.unpack(
        "<13I", _data(context, cast(int, _LAYOUT[context.module_sha256][index]), 52)
    )


def _wire(
    context: TYContext, comm: TYComm, attempts: int = 1, delay: int = 0
) -> security._Wire:
    return security._Wire(
        context, cast(security.SecurityComm, comm), attempts, delay, 180000
    )


def _exchange(
    context: TYContext,
    comm: TYComm,
    request: bytes,
    minimum: int,
    echo: int,
    attempts: int = 1,
) -> tuple[int, bytes]:
    status, reply = _wire(context, comm, attempts).exchange(request)
    if not status and (
        len(reply) < minimum or reply[1 : echo + 1] != request[1 : echo + 1]
    ):
        status = 3
    return status, reply


def _read(
    context: TYContext,
    comm: TYComm,
    identifier: int,
    minimum: int = 4,
    attempts: int = 1,
) -> tuple[int, bytes]:
    request = b"\x22" + identifier.to_bytes(2, "big")
    if attempts != 1:
        return _exchange(context, comm, request, minimum, 2, attempts)
    # c5630/d0ae0 calls the manager directly; no retry-helper Sleep(0).
    status, reply = common._exchange(comm, context, request, minimum, 2)
    if len(reply) > 0x1020:
        raise TYSourceError("EYES response exceeded the native receive span")
    return status, reply


def _routine(
    context: TYContext,
    comm: TYComm,
    identifier: int,
    sub: int,
    minimum: int = 4,
    attempts: int = 30,
) -> tuple[int, bytes]:
    return _exchange(
        context,
        comm,
        b"\x31" + bytes([sub]) + identifier.to_bytes(2, "big"),
        minimum,
        3,
        attempts,
    )


def _normal(context: TYContext, comm: TYComm) -> int:
    common._check(context)
    return comm.session(1, 1, stop_on_error=True)


def _auth(
    context: TYContext,
    primary: TYComm,
    secondary: TYComm,
    key_index: int = 0,
    attempts: int = 1,
) -> int:
    key = (
        security.source_immediate_key(context, _IMMEDIATE[context.module_sha256])
        if not key_index
        else security.source_key(
            context, cast(int, _LAYOUT[context.module_sha256][key_index]), 16
        )
    )
    return security.security_access(
        context,
        cast(security.SecurityComm, primary),
        level=5 if key_index == 5 else 3,
        key=key,
        preliminary_comm=cast(security.SecurityComm, secondary),
        expected_capability=16,
        attempts=attempts,
    )


def _support(
    context: TYContext, comm: TYComm, identifier: int
) -> tuple[int, bytearray]:
    bitmap = bytearray(512)
    status = common._support_bitmap(
        comm, context, identifier, bitmap, 0x3000 if identifier >= 0x3000 else None
    )
    return status, bitmap


def _bit(bitmap: bytearray, identifier: int) -> bool:
    return bool(
        bitmap[((identifier & 0xFFF) - 1) >> 3] & (0x80 >> ((identifier - 1) & 7))
    )


def _eyes01(context: TYContext, comm: TYComm, data: bytearray) -> int:
    if common._u32(data, 12) == 0:
        status, bitmap = _support(context, comm, 0x224)
        if not status:
            first, second = _bit(bitmap, 0x223), _bit(bitmap, 0x224)
            for enabled, identifier, required, output in (
                (first, 0x3040, 0x3001, 0),
                (second, 0x3060, 0x3041, 4),
            ):
                if enabled:
                    status, selected = _support(context, comm, identifier)
                    if not status and _bit(selected, required):
                        common._put(data, output, 1)
        return status if common._u32(data) or common._u32(data, 4) else 3
    if common._u32(data, 12) != 1:
        return 0
    selection = common._u32(data, 8)
    first, last = (0x3001, 0x3028) if selection == 1 else (0x3041, 0x304F)
    count, status = 0, 0
    identifier = first
    while identifier <= last:
        status, reply = _read(context, comm, identifier)
        if status:
            break
        common._put(data, 16 + count * 4, reply[-1])
        paired = identifier + 1 if identifier != 0x301F else 0x3021
        if common._u32(data, 16 + count * 4):
            status, reply = _read(context, comm, paired, 5)
            if status:
                break
            data[0xB0 + count * 2 : 0xB2 + count * 2] = reply[-2:]
        count += 1
        identifier = paired + 1
    common._put(data, 0x100, count)
    return status


def _eyes02(
    context: TYContext, primary: TYComm, secondary: TYComm, data: bytearray
) -> int:
    if common._u32(data):
        _normal(context, primary)
        return 1004
    if primary.session(3, 1, normal_first=True):
        return 1003
    if _auth(context, primary, secondary):
        return 1001
    status, _ = _routine(context, primary, 0x2003, 1, attempts=1)
    if not status:
        status, reply = _routine(context, primary, 0x2003, 3, 5, 1)
        started = context.ticks()
        while not status:
            if reply[4] == 2:
                status, _ = _routine(context, primary, 0x2003, 2, attempts=1)
                break
            if reply[4] != 1:
                status = 3
                break
            if ((started + 30000) & 0xFFFFFFFF) <= context.ticks():
                status = 1002
                break
            context.native_sleep(100)
            status, reply = _routine(context, primary, 0x2003, 3, 5, 1)
    restore = _normal(context, primary)
    return status if status or not restore else 1003


def _poll(
    context: TYContext,
    primary: TYComm,
    identifier: int,
    timeout: str,
    data: bytearray | None = None,
) -> tuple[int, int]:
    started = context.ticks()
    while True:
        status, reply = _routine(context, primary, identifier, 3)
        if status:
            return status, 0
        value = int.from_bytes(reply[4:6].ljust(2, b"\0"), "big")
        if value != 0x1001:
            return 0, value
        now = context.ticks()
        expired = (
            ((now - started) & 0xFFFFFFFF) >= 60000
            if timeout == "elapsed"
            else ((started + 60000) & 0xFFFFFFFF) < now
        )
        if expired:
            if data is not None:
                common._put(data, 12, 1)
            return 3 if timeout == "elapsed" else 1001, 0
        context.native_sleep(100)


def _eyes03(
    context: TYContext, primary: TYComm, secondary: TYComm, data: bytearray
) -> int:
    if common._u32(data) == 0:
        _wire(context, primary, 3, 1000).session(1)
        status = _wire(context, primary, 3, 1000).session(3)
        if status:
            return status
        if _auth(context, primary, secondary, attempts=30):
            status = 1002
        else:
            _read(context, primary, 0x221, attempts=30)
            _read(context, primary, 0x231, attempts=30)
            status, _ = _routine(context, primary, 0x1001, 1)
            if not status:
                status, value = _poll(context, primary, 0x1001, "absolute")
                if not status:
                    if value == 0x1002:
                        status, _ = _routine(context, primary, 0x100F, 1)
                        if not status:
                            return 0
                    else:
                        status = 1003
                _routine(context, primary, 0x1001, 2)
        _wire(context, primary, 3, 1000).session(1)
        return status
    status, value = _poll(context, primary, 0x100F, "absolute")
    if not status:
        common._put(data, 4, value)
    stopped, _ = _routine(context, primary, 0x1001, 2)
    if not status:
        status = stopped
    normal = _wire(context, primary, 3, 1000).session(1)
    return status or normal


def _eyes04_cleanup(
    context: TYContext, primary: TYComm, data: bytearray, successful: bool = False
) -> int:
    if successful or common._u32(data, 8) == 1:
        status, _ = _routine(context, primary, 0x1001, 2)
        common._put(data, 8, 0)
        if successful and status:
            return _eyes04_cleanup(context, primary, data)
    if successful or common._u32(data, 4) == 1:
        status = _wire(context, primary, 3, 1000).session(1)
        common._put(data, 4, 0)
        if successful and status:
            return _eyes04_cleanup(context, primary, data)
    return 9999 if successful else 8000 if common._u32(data, 12) else 7000


def _eyes04_run(
    context: TYContext, primary: TYComm, data: bytearray, identifier: int
) -> int:
    status, _ = _routine(context, primary, identifier, 1)
    if status:
        return status
    if identifier == 0x1001:
        common._put(data, 8, 1)
    status, value = _poll(context, primary, identifier, "elapsed", data)
    if not status:
        common._put(data, 16, value)
    return status


def _eyes04(
    context: TYContext, primary: TYComm, secondary: TYComm, data: bytearray
) -> int:
    action = common._u32(data)
    if action not in (1, 2, 3, 4):
        return _eyes04_cleanup(context, primary, data, True)
    if action == 1:
        status = _wire(context, primary, 3, 1000).session(1)
        if not status:
            status = _wire(context, primary, 3, 1000).session(3)
        if not status:
            common._put(data, 4, 1)
            if _auth(context, primary, secondary, attempts=30):
                _wire(context, primary, 3, 1000).session(1)
                common._put(data, 4, 0)
                return 2000
            _read(context, primary, 0x221, attempts=30)
            _read(context, primary, 0x231, attempts=30)
            status = _eyes04_run(context, primary, data, 0x1001)
            if not status:
                status = 0 if common._u32(data, 16) == 0x1002 else 3
            if not status:
                return 1000
        return _eyes04_cleanup(context, primary, data)
    identifier = {2: 0x1002, 3: 0x100E, 4: 0x1008}[action]
    status = _eyes04_run(context, primary, data, identifier)
    if not status:
        value = common._u32(data, 16)
        if action == 2:
            status = 0 if value == 0x1400 else 5000 if value == 0x140F else 10000
        elif action == 3:
            status = 0 if value == 0x1500 else 10000 if value == 0x1501 else 2000
        else:
            status = 0 if value == 0x1300 else 10000
    finish = status in ((10000, 2000) if action == 3 else (0, 10000))
    if finish:
        normal = _eyes04_cleanup(context, primary, data, True)
        if normal != 9999:
            status = normal
    allowed = (
        (0, 7000, 10000, 5000)
        if action == 2
        else (0, 7000, 10000, 2000)
        if action == 3
        else (0, 7000, 10000)
    )
    return status if status in allowed else _eyes04_cleanup(context, primary, data)


def _vin(context: TYContext, auxiliary: TYComm) -> tuple[int, bytes]:
    # c6d40/d06f0 is OBD09 information02; byte2 is the message count.
    status, reply = _exchange(context, auxiliary, b"\x09\x02", 20, 1)
    vin = reply[3:20]
    if not status and (vin == bytes(17) or vin == b"\xff" * 17):
        status = 3
    return status, vin


def _records(
    context: TYContext,
    primary: TYComm,
    data: bytearray,
    identifiers: tuple[int, ...],
    action: int,
) -> int:
    if action == 1:
        common._put(data, 0x198, 0)
        common._put(data, 0x4A0, 0)
    elif action == 2:
        common._put(data, 0x31C, 0)
    empty = 0
    for index, identifier in enumerate(identifiers):
        status, reply = _read(context, primary, identifier)
        if status:
            return 1006
        payload = reply[3:]
        if len(payload) > 4:
            raise TYSourceError("EYES record exceeded recovered inline DWORD capacity")
        empty += not any(payload)
        starts = (0x18, 0x320) if action == 1 else (0x19C,) if action == 2 else ()
        for start in starts:
            offset = start + index * 12
            data[offset : offset + 12] = bytes(12)
            common._put(data, offset, identifier)
            data[offset + 4 : offset + 4 + len(payload)] = payload
            common._put(data, offset + 8, len(payload))
        for count in (0x198, 0x4A0) if action == 1 else (0x31C,) if action == 2 else ():
            common._put(data, count, common._u32(data, count) + 1)
    return 9800 if empty == 13 else 0


def _compare(
    context: TYContext, primary: TYComm, data: bytearray, identifiers: tuple[int, ...]
) -> int:
    for _ in range(11):
        failed = False
        for index, identifier in enumerate(identifiers):
            offset = 0x320 + index * 12
            length = common._u32(data, offset + 8)
            payload = bytes(data[offset + 4 : offset + 4 + length])
            status, _ = _exchange(
                context,
                primary,
                b"\x2e" + identifier.to_bytes(2, "big") + payload,
                3,
                2,
            )
            failed |= bool(status)
        actual: list[bytes] = []
        for identifier in identifiers:
            status, reply = _read(context, primary, identifier)
            failed |= bool(status)
            actual.append(reply[3:] if not status else b"")
        if not failed:
            for index, payload in enumerate(actual):
                offset = 0x320 + index * 12
                length = common._u32(data, offset + 8)
                expected = bytes(data[offset + 4 : offset + 4 + length])
                if payload[:length].ljust(length, b"\0") != expected:
                    failed = True
                    break
        if not failed:
            _normal(context, primary)
            return 1004
    _normal(context, primary)
    return 1001


def _eyes05(
    context: TYContext,
    primary: TYComm,
    secondary: TYComm,
    auxiliary: TYComm,
    data: bytearray,
) -> int:
    action, identifiers = common._u32(data), _ids(context, 2)
    if action == 0:
        status, bitmap = _support(context, primary, 0x309D)
        return (
            status
            if status
            else 0
            if all(_bit(bitmap, identifier) for identifier in identifiers)
            else 3
        )
    if action == 3:
        status, vin = _vin(context, auxiliary)
        if status or vin != bytes(data[4:21]):
            return 1018
        return _compare(context, primary, data, identifiers)
    if action == 4:
        return _compare(context, primary, data, identifiers)
    if action not in (1, 2, 5):
        _normal(context, primary)
        return 9900
    if action == 1:
        status, vin = _vin(context, auxiliary)
        if status:
            return 1006
        data[4:22] = vin + b"\0"
    status = primary.session(3, 1, normal_first=True)
    if status:
        return 1001
    if _auth(context, primary, secondary):
        if action == 5:
            _normal(context, primary)
        return 9700
    if action == 5:
        return 0
    status = _records(context, primary, data, identifiers, action)
    if action == 1:
        _normal(context, primary)
    return status


def _eyes06(
    context: TYContext, primary: TYComm, secondary: TYComm, data: bytearray
) -> int:
    identifiers = _ids(context, 3)
    if common._u32(data, 0x184) == 0:
        status, bitmap = _support(context, primary, 0x309D)
        return 0 if not status and all(_bit(bitmap, i) for i in identifiers) else 3
    status = primary.session(3, 1, normal_first=True)
    if status:
        return status
    status = _auth(context, primary, secondary, 4)
    if not status:
        common._put(data, 0x180, 0)
        for index, identifier in enumerate(identifiers):
            status, reply = _read(context, primary, identifier)
            if status:
                break
            payload = reply[3:]
            if len(payload) > 4:
                raise TYSourceError(
                    "EYES06 record exceeds native inline DWORD capacity"
                )
            offset = index * 12
            data[offset : offset + 12] = bytes(12)
            common._put(data, offset, identifier)
            common._put(data, offset + 8, len(payload))
            data[offset + 4 : offset + 4 + len(payload)] = payload
            common._put(data, 0x180, index + 1)
    _normal(context, primary)
    return status


def _rc4(data: bytearray, key: bytes) -> None:
    if not key:
        raise ValueError("RC4 key must be nonempty")
    state, j = list(range(256)), 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 255
        state[i], state[j] = state[j], state[i]
    i = j = 0
    for offset, value in enumerate(data):
        i = (i + 1) & 255
        j = (j + state[i]) & 255
        state[i], state[j] = state[j], state[i]
        data[offset] = value ^ state[(state[i] + state[j]) & 255]


def _save_capture(context: TYContext, data: bytearray, capture: bytes) -> int:
    wide = context.module_sha256 == SHA_PLUS_TY
    raw = bytes(data[0x38 : 0x240 if wide else 0x13C])
    if wide:
        end = next(
            (i for i in range(0, len(raw), 2) if raw[i : i + 2] == b"\0\0"), len(raw)
        )
        folder_name = raw[:end].decode("utf-16-le")
        if not folder_name or end == len(raw):
            return 2004
        folder = Path(folder_name)
    else:
        folder_name = os.fsdecode(raw.split(b"\0", 1)[0])
        if not folder_name or b"\0" not in raw:
            return 2004
        folder = Path(folder_name)
    try:
        if shutil.disk_usage(folder).free < len(capture):
            return 2003
        stamp = datetime.now().astimezone().strftime("%Y%m%d%H%M%S")
        # The filesystem is native: colliding existing captures are preserved.
        suffix_rva = 0xF8714 if not wide else 0xE0C5C
        suffix_data = _data(context, suffix_rva, 16)
        if wide:
            end = next(
                (
                    i
                    for i in range(0, len(suffix_data), 2)
                    if suffix_data[i : i + 2] == b"\0\0"
                ),
                len(suffix_data),
            )
            suffix = suffix_data[:end].decode("utf-16-le")
        else:
            suffix = os.fsdecode(suffix_data.split(b"\0", 1)[0])
        if "/" in suffix or "\\" in suffix:
            raise TYSourceError("Source capture suffix is not a filename extension")
        encoded = (stamp + "\0").encode("utf-16-le" if wide else "ascii")
        offset = 0x240 if wide else 0x13C
        data[offset : offset + len(encoded)] = encoded
        with (folder / (stamp + suffix)).open("xb") as output:
            if output.write(capture) != len(capture):
                return 2004
        return 0
    except OSError:
        return 2004


def _eyes07_summary(
    context: TYContext, primary: TYComm, secondary: TYComm, data: bytearray
) -> int:
    data[8:36] = bytes(28)
    status = primary.session(3, 1, normal_first=True)
    if status:
        return status
    if _auth(context, primary, secondary, 5):
        return 2000
    identifiers = struct.unpack(
        "<2H", _data(context, cast(int, _LAYOUT[context.module_sha256][7]), 4)
    )
    for group, identifier in enumerate(identifiers):
        for index in range(4):
            status, reply = _read(context, primary, identifier + index, 5)
            if status:
                break
            offset = 8 + group * 8 + index * 2
            data[offset : offset + 2] = reply[3:5]
        if status:
            break
    if not status:
        flags = tuple(
            int(
                any(
                    int.from_bytes(
                        data[8 + group * 8 + i * 2 : 10 + group * 8 + i * 2], "little"
                    )
                    not in (0, 65535)
                    for i in range(4)
                )
            )
            for group in range(2)
        )
        common._put(data, 24, flags[0])
        common._put(data, 28, flags[1])
        if not any(flags):
            status = 2001
        else:
            base = cast(int, _LAYOUT[context.module_sha256][9])
            old = context.state.get(f"native_global:{base:08x}", 0)
            if old and flags != tuple(
                context.state.get(f"native_global:{base + 4 + i * 4:08x}", 0)
                for i in range(2)
            ):
                common._put(data, 32, 1)
            for i, value in enumerate(flags):
                context.state[f"native_global:{base + 4 + i * 4:08x}"] = value
    _normal(context, primary)
    if not status:
        context.state[
            f"native_global:{cast(int, _LAYOUT[context.module_sha256][9]):08x}"
        ] = 1
    return status


def _eyes07_capture(
    context: TYContext, primary: TYComm, secondary: TYComm, data: bytearray
) -> int:
    selected = sum(bool(common._u32(data, 40 + i * 4)) for i in range(4))
    try:
        capture = bytearray(0x100 + selected * 0x1BF9E)
    except MemoryError:
        return 2002
    capture[:3] = b"PRE"
    capture[6] = 1
    capture[12:16] = (len(capture) - 256).to_bytes(4, "big")
    status = primary.session(3, 1, normal_first=True)
    if status:
        return status
    if _auth(context, primary, secondary, 5):
        return 2000
    status = 0
    if not common._u32(data, 4):
        status, reply = _read(context, primary, 0xF100, 6)
        if status:
            return 2002
        capture[16:19] = reply[3:6]
        table = _data(context, cast(int, _LAYOUT[context.module_sha256][8]), 5 * 28)
        block = 0
        for selection in range(4):
            if status or common._u32(data, 4):
                break
            if not common._u32(data, 40 + selection * 4):
                continue
            for row in range(5):
                if status or common._u32(data, 4):
                    break
                size, count, offset = struct.unpack_from("<3I", table, row * 28)
                identifier = struct.unpack_from(
                    "<H",
                    table,
                    row * 28 + 12 + (selection + common._u32(data, 36) * 4) * 2,
                )[0]
                if size > 0x101D or offset + size * count > 0x1BF9E:
                    raise TYSourceError(
                        "Source capture row exceeds recovered native bounds"
                    )
                for index in range(count):
                    if common._u32(data, 4):
                        break
                    context.native_sleep(100)
                    status, reply = _read(
                        context, primary, (identifier + index) & 65535, size + 3
                    )
                    if status:
                        status = 2002
                        break
                    destination = 256 + block * 0x1BF9E + offset + size * index
                    capture[destination : destination + size] = reply[3 : 3 + size]
            block += 1
        if not status:
            _normal(context, primary)
    else:
        _normal(context, primary)
    if not status and not common._u32(data, 4):
        body = capture[256:]
        seed = _data(context, cast(int, _LAYOUT[context.module_sha256][6]), 4)
        # Base CSP flags0: 40 effective key bits plus its default88 zero salt bits.
        _rc4(body, hashlib.md5(seed).digest()[:5] + bytes(11))
        capture[256:] = body
        for _ in range(3):
            status = _save_capture(context, data, bytes(capture))
            if status != 2004:
                break
    # Keep the source fault path: failed block reads do not restore the session.
    return status


def invoke_export(export: str, context: TYContext, *args: object) -> int:
    if export not in supported_exports(context.module_sha256):
        raise TYSourceError("EYES body has no reviewed exact source")
    if len(args) != 1 or not isinstance(args[0], bytearray):
        raise ValueError("EYES requires one mutable native message")
    data = args[0]
    number = _EXPORTS.index(export) + 1
    minimum = {
        1: 0x104,
        2: 4,
        3: 8,
        4: 20,
        5: 0x4A4,
        6: 0x188,
        7: 0x27C if context.module_sha256 == SHA_PLUS_TY else 0x15C,
    }[number]
    if len(data) < minimum:
        raise ValueError(f"EYES{number:02} requires {minimum} native bytes")
    if (
        number == 1
        and common._u32(data, 12) == 1
        and common._u32(data, 8) not in (1, 2)
    ):
        raise ValueError(
            "EYES01 selection must be one of the recovered native DID banks"
        )
    if (
        number == 5
        and common._u32(data) in (3, 4)
        and any(common._u32(data, 0x328 + i * 12) > 4 for i in range(13))
    ):
        raise ValueError("EYES05 inline record length exceeds native DWORD capacity")
    if number == 7 and common._u32(data) == 1 and common._u32(data, 36) not in (0, 1):
        raise ValueError("EYES07 capture bank exceeds native source table")
    security._authenticate(context)
    common._check(context)
    primary = common._manager(context)
    layout = _LAYOUT[context.module_sha256]
    secondary = context.comm(cast(str, layout[0])) if number != 1 else None
    auxiliary = context.comm(cast(str, layout[1])) if number == 5 else None
    action = common._u32(data)
    retained, failed = False, False
    status = 0
    try:
        initialize = not (
            number == 3
            and action != 0
            or number == 4
            and action != 1
            or number == 7
            and action == 2
            or number == 5
            and action in (3, 4, 6)
        )
        if initialize:
            common._check(context)
            status = primary.initialize()
            if not status and number in (1, 5):
                primary.configure("native_1080", 0)
                primary.configure("native_1084", 180000)
                primary.configure("native_1064", 0)
            if not status and secondary is not None:
                secondary.configure_target(0x763)
                common._check(context)
                status = secondary.initialize()
            if status:
                return status
            configured = (
                (secondary,)
                if number == 5
                else (primary, secondary)
                if number != 1
                else ()
            )
            for selected in configured:
                if selected is None:
                    continue
                fields = (
                    (("native_1084", 180000), ("native_1080", 0))
                    if number == 2
                    else (("native_1080", 0), ("native_1084", 180000))
                )
                for field, value in fields:
                    selected.configure(field, value)
                if number == 4:
                    cast(security.SecurityComm, selected).keepalive(False)
                selected.configure("native_1064", 0)
                if number == 3:
                    cast(security.SecurityComm, selected).keepalive(False)
        if auxiliary is not None:
            status = cast(EYESComm, auxiliary).select_diagnostic_mode(3)
            if not status:
                auxiliary.configure_target(0x7A2, 0, 0x7DF, 0, 0x7E0)
                status = common._initialize(auxiliary, context)
            if status:
                return status
        if number == 1:
            status = _eyes01(context, primary, data)
        elif number == 2:
            status = _eyes02(context, primary, cast(TYComm, secondary), data)
        elif number == 3:
            status = _eyes03(context, primary, cast(TYComm, secondary), data)
            retained = action == 0 and status == 0
        elif number == 4:
            status = _eyes04(context, primary, cast(TYComm, secondary), data)
            retained = (action, status) in ((1, 1000), (2, 5000), (3, 0))
        elif number == 5:
            status = _eyes05(
                context, primary, cast(TYComm, secondary), cast(TYComm, auxiliary), data
            )
            retained = (
                action == 2
                or action == 1
                and status == 9700
                or action == 3
                and status == 1018
                or action == 5
                and status == 0
            )
        elif number == 6:
            status = _eyes06(context, primary, cast(TYComm, secondary), data)
        elif action == 0:
            status = _eyes07_summary(context, primary, cast(TYComm, secondary), data)
            retained = status == 2000
        elif action == 1:
            status = _eyes07_capture(context, primary, cast(TYComm, secondary), data)
            retained = status in (2000, 2002)
        elif action == 2:
            _normal(context, primary)
        return status
    except BaseException:
        failed = True
        raise
    finally:
        first: BaseException | None = None
        for comm in (() if retained else (primary, secondary)) + (
            (auxiliary,) if auxiliary is not None else ()
        ):
            if comm is None:
                continue
            try:
                comm.finalize()
            except BaseException as error:  # noqa: BLE001 - preserve the operation exception
                if first is None:
                    first = error
        if first is not None and not failed:
            raise first
