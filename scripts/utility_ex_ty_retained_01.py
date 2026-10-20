"""Exact-source PSABSI, RWG and EVP business algorithms.

Mutable arguments are native byte buffers. Communication stays in the selected
UtilityEx manager; no OEM code, transport replay, or whole-body callback runs.
"""

from __future__ import annotations

import hashlib
from typing import Protocol

from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import (
    SHA_12_TY,
    SHA_18_TY,
    SHA_PLUS_TY,
    TYComm,
    TYSourceError,
)


class Context(Protocol):
    module_sha256: str
    module_bytes: bytes
    state: dict[str, object]

    @property
    def mode(self) -> int: ...

    def comm(self, kind: str, /) -> TYComm: ...
    def is_cancelled(self) -> bool: ...
    def native_sleep(self, milliseconds: int, /) -> None: ...
    def ticks(self) -> int: ...


_PSA = tuple(
    "Ex2PSABSI_" + name
    for name in (
        "01_SendMessage",
        "02_ExitEconomyMode",
        "03_GetMode",
        "03_SetMode",
        "04_ForcingOfGaugingRequest",
        "05_BSIStatusCheck",
        "05_ExitCommunication",
        "05_KeyRegister",
        "05_UnlockRequest",
        "06_BSIStatusCheck",
        "06_ProgramADCCode",
        "07_BSIStatusCheck",
        "07_UnlockRequest",
        "08_GetVIN",
        "08_WriteVIN",
    )
)
_RWG = tuple(
    "Ex2RWG_01_" + name for name in ("DTCRead", "LearnZeroPos", "SupportCheck")
)
_EVP = ("Ex2EVP_01_InitializeAllMemory",)
_EXPORTS = {
    SHA_12_TY: _PSA + _RWG,
    SHA_18_TY: _PSA + _RWG + _EVP,
    SHA_PLUS_TY: _RWG + _EVP,
}
# Direct setters recovered separately for each module, not filename aliases.
_PENDING_SETTERS = {
    SHA_18_TY: "native_rva:12180",
    SHA_12_TY: "native_rva:b940",
    SHA_PLUS_TY: "native_rva:142f0",
}
_FORCING_SETTERS = {
    SHA_18_TY: ("native_rva:121d0", "native_rva:12200"),
    SHA_12_TY: ("native_rva:b960", "native_rva:b990"),
}
_RESULT_GLOBALS = {
    SHA_12_TY: "native_global:100ab770",
    SHA_18_TY: "native_global:10118e38",
    SHA_PLUS_TY: "native_global:10134ab8",
}

_STATUS_FIELDS: dict[int, int] = dict(
    zip(
        (
            4,
            6,
            8,
            10,
            12,
            13,
            14,
            15,
            16,
            20,
            22,
            28,
            30,
            45,
            32,
            35,
            41,
            42,
            40,
            0,
            26,
            43,
            46,
            47,
            44,
        ),
        (1, 1, 1, 1, 1, 1, 1, 8, 8, 1, 1, 1, 1, 1, 1, 1, 8, 8, 1, 1, 1, 1, 1, 8, 1),
        strict=True,
    )
)
_MODE_FIELDS: dict[int, int] = dict(
    zip(
        (
            0x15,
            0x45,
            0x46,
            0x48,
            0x16,
            0x3B,
            0x43,
            0x3C,
            0x0F,
            0x37,
            0x34,
            0x36,
            5,
            0x29,
            0x2A,
            0x4A,
            0x3E,
            0x28,
            12,
            13,
            0x38,
            0,
            0x32,
            1,
            0x30,
            3,
            0x21,
            0x23,
            0x3A,
            0x5F,
            0x2E,
            0x31,
            0x33,
            0x35,
            0x3F,
            0x40,
            0x49,
            0x41,
            0x42,
            0x44,
            0x5E,
            0x61,
            0x2F,
            0x5C,
            0x5D,
            0x2C,
            0x2D,
            0x47,
            0x25,
        ),
        (
            8,
            8,
            1,
            1,
            8,
            1,
            8,
            1,
            1,
            8,
            1,
            8,
            1,
            8,
            8,
            8,
            1,
            8,
            1,
            1,
            8,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            8,
            8,
            16,
            16,
            8,
            1,
            8,
            1,
            8,
            1,
            1,
            1,
            1,
            32,
            16,
            32,
            8,
        ),
        strict=True,
    )
)


def supported_exports(source_sha256: str) -> tuple[str, ...]:
    return _EXPORTS.get(source_sha256, ())


def _check(context: Context) -> None:
    if context.is_cancelled():
        raise Cancelled("UtilityEx retained TY operation cancelled")


def _sleep(context: Context, milliseconds: int) -> None:
    _check(context)
    context.native_sleep(milliseconds)
    _check(context)


def _u32(data: bytearray, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _put(data: bytearray, offset: int, value: int) -> None:
    data[offset : offset + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")


def _exchange(comm: TYComm, context: Context, request: bytes) -> tuple[int, bytes]:
    _check(context)
    status, reply = comm.exchange(request)
    _check(context)
    if not isinstance(reply, bytes) or len(reply) > 0x1020:
        raise ValueError("Native reply exceeds the 0x1020-byte buffer")
    return status, reply


def _routine(
    comm: TYComm,
    context: Context,
    request: bytes,
    accepted: tuple[int, ...],
    error: int = 3,
) -> int:
    status, reply = _exchange(comm, context, request)
    if status:
        return status
    if len(reply) != 3 or reply[1] != request[1]:
        return 3
    return 0 if reply[2] in accepted else error


def _poll(
    comm: TYComm,
    context: Context,
    identifier: int,
    mapping: dict[int, int],
    default: int,
    limit: int,
    timeout: int,
    delay: int = 500,
    *,
    before: bool = True,
) -> int:
    start = context.ticks()
    while True:
        _check(context)
        if before and ((context.ticks() - start) & 0xFFFFFFFF) > limit:
            return timeout
        _sleep(context, delay)
        status, reply = _exchange(comm, context, bytes((0x31, identifier, 1)))
        if not status:
            if len(reply) != 3 or reply[1] != identifier:
                return 3
            status = 0 if reply[2] == 2 else mapping.get(reply[2], default)
        if status != 0x238C:
            return status
        if not before and ((context.ticks() - start) & 0xFFFFFFFF) >= limit + 1:
            return timeout


def _read(
    comm: TYComm, context: Context, identifier: int, length: int, index: int
) -> tuple[int, int]:
    status, reply = _exchange(comm, context, bytes((0x21, identifier)))
    if status:
        return status, 0
    padded = reply.ljust(0x1020, b"\0")
    if (length and len(reply) != length + 2) or padded[1] != identifier:
        return 3, 0
    if index >= 0x101E:
        raise ValueError("Native data index outside response allocation")
    return 0, padded[index + 2]


def _download(comm: TYComm, context: Context) -> tuple[int, bytes]:
    """e100/e140/e2c0: segmented35 descriptor stream and terminator index."""
    content = bytearray()
    for sequence in range(1, 0x1000000):
        count_bytes = sequence.to_bytes(3, "big")
        status, reply = _exchange(comm, context, b"\x35\xc0" + count_bytes + b"\x11")
        if status:
            return status, bytes(content)
        padded = reply.ljust(9, b"\0")
        if padded[1] != 0xC0 or padded[2] not in (0x80, 0xFF):
            return 3, bytes(content)
        count = padded[6]
        if (
            (padded[2] == 0x80 and count != 0x11)
            or len(reply) != count + 9
            or padded[3:6] != count_bytes
        ):
            return 3, bytes(content)
        # Native allocation has1012 descriptor bytes; reject its overflow.
        if len(content) + count > 0x1012:
            raise ValueError("Native descriptor allocation overflow")
        content.extend(reply[7 : 7 + count])
        if padded[2] == 0xFF:
            return 0, bytes(content)
    return 0x238C, bytes(content)


def _field(
    content: bytes, identifier: int, target: int, widths: dict[int, int]
) -> tuple[int, int, int, int | None]:
    """e300: low-nibble stream selector, bit packing, partial native outputs."""
    marker = identifier & 15
    start = 0 if content[:1] == bytes((marker,)) else -1
    for index in range(1, min(len(content), 0x1012)):
        if content[index - 1] == 0xFF:
            if content[index] == 0xFF:
                break
            if content[index] == marker:
                start = index
    if start < 0:
        return 3, 0, 255, None
    offset, bits, status, selected, mask = 0, 0, 3, 0, 255
    for value in (content + b"\xff")[start + 1 : 0x1012]:
        if value == 255:
            return status, selected, mask, offset + int(bits != 0)
        width = widths.get(value, 0)
        if width == 0:
            return status, selected, mask, 0
        if width == 1:
            if value == target:
                selected, status, mask = offset, 0, (1 << bits) & 255
            bits += 1
            if bits == 8:
                bits, offset = 0, offset + 1
        else:
            if bits:
                offset, bits = offset + 1, 0
            if value == target:
                selected, status = offset, 0
            offset += width >> 3
    return status, selected, mask, None


def _status(comm: TYComm, context: Context, data: bytearray, group: int) -> int:
    _sleep(context, 100)
    status, content = _download(comm, context)
    if status:
        return status
    targets = (0x1E,) if group == 6 else (0x1A, 0x1E)
    for position, target in enumerate(targets):
        status, offset, mask, length = _field(content, 0xC7, target, _STATUS_FIELDS)
        data[8 if group == 6 else 12 + position] = mask
        if length is not None:
            _put(data, 0, length)
        if not status:
            _put(data, 4 + position * 4, offset)
        if status:
            return status
    _sleep(context, 100)
    status, value = _read(
        comm, context, 0xC7, _u32(data, 0), _u32(data, 4 if group == 6 else 8)
    )
    if status:
        return status
    hit = value & data[8 if group == 6 else 13]
    if group == 7:
        return 0x232B - int(bool(hit))
    if bool(hit) == (group == 5):
        return 0x2331
    data[16 if group == 6 else 20 : 24 if group == 6 else 28] = bytes(8)
    return 0


def _security(comm: TYComm, context: Context, data: bytearray, offset: int) -> int:
    _put(data, offset, 1)
    _sleep(context, 100)
    status, reply = _exchange(comm, context, b"\x27\x83")
    if status or len(reply) != 6 or reply[1] != 0x83:
        _put(data, offset + 8, 0x1773)
        return status or 3
    data[offset + 16 : offset + 20] = reply[2:6]
    if reply[5] == 0:
        _put(data, offset + 8, 0x1773)
        return 0
    _put(data, offset + 8, 0x1771)
    while True:
        _sleep(context, 2000)
        action = _u32(data, offset + 4)
        if action != 5000:
            break
        _exchange(comm, context, b"\x3e")
    _put(data, offset + 8, 0x1772)
    _put(data, offset + 4, 5000)
    if action != 0x138A:
        return action
    _sleep(context, 100)
    status, reply = _exchange(
        comm, context, b"\x27\x84" + bytes(data[offset + 20 : offset + 24])
    )
    return status or (0 if len(reply) == 2 and reply[1] == 0x84 else 3)


def _psa(
    export: str, data: bytearray, comm: TYComm, context: Context
) -> tuple[int, bool]:
    """Return status and whether the native body releases selected communication."""
    name = export.removeprefix("Ex2PSABSI_")
    if name == "05_ExitCommunication":
        return 0, True
    if name == "05_KeyRegister":
        _sleep(context, 100)
        status = _routine(
            comm, context, b"\x31\xa2\x00" + bytes((data[40],)), (1, 128), 0x2340
        )
        if not status:
            status = _poll(
                comm,
                context,
                0xA2,
                {
                    1: 0x238C,
                    128: 0x238C,
                    8: 0x2340,
                    16: 0x2341,
                    17: 0x2342,
                    18: 0x2343,
                    19: 0x2344,
                    4: 0x2345,
                    255: 0x2346,
                    254: 0x2347,
                    32: 0x2348,
                    240: 0x2349,
                },
                0x234A,
                0x4074,
                0x2340,
            )
        return status, False
    if name.endswith("BSIStatusCheck"):
        return _status(comm, context, data, int(name[:2])), True
    if name in ("05_UnlockRequest", "07_UnlockRequest"):
        group = int(name[:2])
        _sleep(context, 100)
        status, value = _read(comm, context, 0xC7, _u32(data, 0), _u32(data, 4))
        if status:
            return status, group == 7 or status != 0
        if value & data[12]:
            if group == 5:
                return 0x2330, False
            status = _sessions(comm, context)
            if status:
                return status, True
        _sleep(context, 100)
        status = _routine(
            comm,
            context,
            b"\x31\xa0\x00" + bytes(data[14:18]),
            (1,),
            0x2337 if group == 5 else 3,
        )
        if not status:
            mapping = (
                {1: 0x238C, 0: 0x2336, 254: 0x2336, 16: 0x2339, 4: 0x233A, 32: 0x233A}
                if group == 5
                else {1: 0x238C, 4: 0x232E, 16: 0x232F}
            )
            status = _poll(
                comm,
                context,
                0xA0,
                mapping,
                0x2338 if group == 5 else 0x2330,
                6000,
                0x2337 if group == 5 else 3,
            )
            if group == 5 and status == 0x233A:
                count = (_u32(data, 20) + 1) & 0xFFFFFFFF
                _put(data, 20, count)
                if count > 2:
                    status = 0x233B
            if group == 7 and not status:
                _sessions(comm, context)
        return status, group == 7 or bool(status)
    if name == "06_ProgramADCCode":
        _sleep(context, 100)
        status = _routine(
            comm, context, b"\x31\xa1\x00" + bytes(data[9:13]), (1,), 0x233A
        )
        if not status:
            status = _poll(
                comm,
                context,
                0xA1,
                {1: 0x238C, 0: 0x2337, 254: 0x2337, 16: 0x2338},
                0x2339,
                6000,
                0x233A,
            )
        return status, True
    if name == "08_GetVIN":
        data[:18] = bytes(18)
        status, reply = _exchange(comm, context, b"\x21\xb0")
        if not status:
            if len(reply) < 19 or reply[1] != 0xB0:
                return 3, True
            data[:17] = reply[2:19]
        return status, True
    if name == "08_WriteVIN":
        for identifier, source_offset, count, destination, backing, length in (
            (0x80, 0, 5, 0x12, 0x1A, 0x205C),
            (0xFE, 21, 3, 0x17, 0x103A, 0x2060),
        ):
            status, reply = _exchange(comm, context, bytes((0x21, identifier)))
            if status:
                return status, True
            if reply.ljust(2, b"\0")[1] != identifier:
                return 3, True
            _put(data, length, len(reply))
            data[backing : backing + len(reply)] = reply
            if source_offset + 2 + count > len(reply):
                return 3, True
            data[destination : destination + count] = reply[
                source_offset + 2 : source_offset + 2 + count
            ]
        status = _security(comm, context, data, 0x2064)
        if status:
            return status, True
        status, reply = _exchange(comm, context, b"\x3b\xb0\xff" + bytes(data[:17]))
        # ASM5c499 retains the success branch lost by the decompiler.
        return status or (0 if len(reply) == 2 and reply[1] == 0xB0 else 3), True
    if name == "03_GetMode":
        _sleep(context, 100)
        status, content = _download(comm, context)
        if status:
            return status, True
        status, offset, _mask, length = _field(content, 0xC0, 0x28, _MODE_FIELDS)
        if length is not None:
            _put(data, 12, length)
        if not status:
            _put(data, 8, offset)
            _sleep(context, 500)
            status, value = _read(comm, context, 0xC0, _u32(data, 12), offset)
            if not status:
                data[0] = value
        return status, True
    if name in (
        "01_SendMessage",
        "02_ExitEconomyMode",
        "03_SetMode",
        "04_ForcingOfGaugingRequest",
    ):
        forcing = name.startswith("04")
        _sleep(context, 1000 if forcing else 500)
        if name.startswith("01"):
            status = _routine(comm, context, b"\x31\xaa\x00\x01", (1,), 0x238D)
            identifier, limit, timeout = 0xAA, 10000, 0x238D
            mapping, default = {}, 0x238C
        else:
            payload = (
                b"\x00\x00\xc7\x01"
                if forcing
                else (
                    b"\x00\x00\xca\x3c"
                    if name.startswith("02")
                    else bytes((0, 0, 0xA2 if _u32(data, 4) == 1 else 0xA1, 1))
                )
            )
            request = b"\x31\xad" + payload
            if name.startswith("02") or forcing:
                status, reply = _exchange(comm, context, request)
                if not status:
                    status = (
                        3
                        if len(reply) != 3 or reply[1] != 0xAD
                        else (0 if reply[2] == 1 else (0x2332 if forcing else 0x2392))
                    )
                elif len(reply) == 3 and reply[:2] == b"\x7f\x31":
                    status = (
                        {0x22: 0x2331, 0x12: 0x2330}
                        if forcing
                        else {0x22: 0x2392, 0x12: 0x23FC}
                    ).get(reply[2], status)
                if not forcing and status == 0x23FC:
                    _sleep(context, 500)
                    status, reply = _exchange(
                        comm, context, b"\x31\xad\x00\x00\xc8\x01"
                    )
                    if not status:
                        status = (
                            3
                            if len(reply) != 3 or reply[1] != 0xAD
                            else (0 if reply[2] == 1 else 0x2392)
                        )
                    elif len(reply) == 3 and reply[:2] == b"\x7f\x31":
                        status = {0x22: 0x2392, 0x12: 0x23FC}.get(reply[2], status)
            else:
                status = _routine(comm, context, request, (1,), 0x232F)
            identifier, limit, timeout = (
                0xAD,
                6000 if forcing or name.startswith("02") else 10000,
                0x2392 if name.startswith("02") else 0x232F,
            )
            mapping, default = (
                ({1: 0x238C, 8: 0x2333}, 0x2332)
                if forcing
                else ({0: 0x2392, 4: 0x2392}, 0x238C)
                if name.startswith("02")
                else ({}, 0x238C)
            )
        if not status:
            status = _poll(
                comm,
                context,
                identifier,
                mapping,
                default,
                limit,
                timeout,
                100 if forcing else 500,
                before=False,
            )
        return status, True
    raise TYSourceError("No retained PSABSI business body")


def _sessions(comm: TYComm, context: Context) -> int:
    for identifier in (0x81, 0xC0):
        _sleep(context, 100)
        status, reply = _exchange(comm, context, bytes((0x10, identifier)))
        if status or len(reply) != 2 or reply[1] != identifier:
            return status or 3
    return 0


def _support_field(
    payload: bytes, offsets: tuple[int, ...], identifier: int, position: int, mask: int
) -> tuple[int, int]:
    index = offsets[identifier] if identifier < len(offsets) else 0x1020
    if index == 0x1020:
        return 0x16, 0
    padded = payload.ljust(0x1020, b"\0")
    if index < 0 or index + 1 >= 0x1020 or index + 1 + padded[index + 1] > 0x1020:
        return 99, 0
    if padded[index + 1] < ((position - 2) & 0xFFFFFFFF):
        return 0x16, 0
    selected = 2 + sum(value != 0 for value in padded[index + 2 : index + position - 1])
    value = padded[index + position - 1]
    return (0 if value and value & mask == mask else 0x16), selected


def _support_count(
    payload: bytes, offsets: tuple[int, ...], identifier: int, previous: int
) -> int:
    index = offsets[identifier] if identifier < len(offsets) else 0x1020
    padded = payload.ljust(0x1020, b"\0")
    if index < 0 or index + 1 >= 0x1020 or index + 1 + padded[index + 1] > 0x1020:
        return previous
    return sum(
        value != 0 for value in padded[index + 2 : index + 2 + padded[index + 1]]
    )


def _rwg(export: str, data: bytearray, comm: TYComm, context: Context) -> int:
    if export.endswith(("DTCRead", "SupportCheck")):
        status, reply = _exchange(comm, context, b"\x13")
        if not status:
            native = reply.ljust(0x1020, b"\0")
            if any(
                native[index : index + 2] == b"\xc1\x29"
                for index in range(0, native[1] * 2, 2)
            ):
                status = 1001
        if status or export.endswith("DTCRead"):
            return status
        _check(context)
        status, payload, offsets = comm.support_snapshot(1)
        if status:
            return status
        count = 0
        for identifier, destination in ((0x26, 8), (0x27, 12)):
            for position in (3, 4):
                status, _selected = _support_field(
                    payload, offsets, identifier, position, 255
                )
                if status:
                    return status
            count = _support_count(payload, offsets, identifier, count)
            _put(data, destination, count + 2)
        status, selected = _support_field(payload, offsets, 0x23, 5, 255)
        if status:
            return status
        _put(data, 0, selected)
        count = _support_count(payload, offsets, 0x23, count)
        _put(data, 4, count + 2)
        _check(context)
        status, payload, offsets = comm.support_snapshot(2)
        if status:
            return status
        status, _selected = _support_field(payload, offsets, 1, 3, 128)
        _put(data, 16, _support_count(payload, offsets, 1, 0) + 3)
        return status
    count = _u32(data, 16)
    if count > 0x1020:
        raise ValueError("RWG native request length exceeds allocation")
    request = b"\x30\x01\x00\x80".ljust(0x1020, b"\0")[:count]
    status, reply = _exchange(comm, context, request)
    if not status:
        status = 0 if len(reply) == 2 else 3
    if not status:
        start = context.ticks()
        if ((context.ticks() - start) & 0xFFFFFFFF) >= 10000:
            return status
        while True:
            status, reply = _exchange(comm, context, b"\x21\x23")
            if not status and len(reply) != _u32(data, 4):
                status = 3
            if status:
                break
            index = _u32(data, 0)
            if index >= 0x1020:
                raise ValueError("RWG native response index outside allocation")
            value = reply.ljust(0x1020, b"\0")[index]
            angles = []
            for identifier, length_offset in ((0x26, 8), (0x27, 12)):
                status, reply = _exchange(comm, context, bytes((0x21, identifier)))
                if not status and len(reply) != _u32(data, length_offset):
                    status = 3
                angles.append(
                    int.from_bytes(reply.ljust(4, b"\0")[2:4], "big", signed=True)
                )
                if status:
                    break
            if status:
                break
            if value != 255 or -9999 in angles:
                return 0
            _sleep(context, 500)
            status = 1000
            if ((context.ticks() - start) & 0xFFFFFFFF) >= 10000:
                break
    # Both sources call stop on failure, preserve the first business status.
    _exchange(comm, context, b"\x30")
    return status


def _run_body(export: str, args: tuple[object, ...], context: Context) -> int:
    """Execute a scheduled body for its exact source; wrappers own scheduling."""
    source = context.module_sha256
    if hashlib.sha256(context.module_bytes).hexdigest() != source:
        raise TYSourceError("TY module bytes do not match the selected source identity")
    if export not in supported_exports(source):
        raise TYSourceError("Unassigned TY retained source/export pair")
    expected_mode = 19 if export in _PSA else 4
    if context.mode != expected_mode:
        return 99
    minimum = {
        "Ex2PSABSI_05_KeyRegister": 44,
        "Ex2PSABSI_03_GetMode": 16,
        "Ex2PSABSI_03_SetMode": 8,
        "Ex2PSABSI_05_BSIStatusCheck": 28,
        "Ex2PSABSI_05_UnlockRequest": 24,
        "Ex2PSABSI_06_BSIStatusCheck": 24,
        "Ex2PSABSI_06_ProgramADCCode": 13,
        "Ex2PSABSI_07_BSIStatusCheck": 28,
        "Ex2PSABSI_07_UnlockRequest": 18,
        "Ex2PSABSI_08_GetVIN": 18,
        "Ex2PSABSI_08_WriteVIN": 0x207C,
        "Ex2RWG_01_SupportCheck": 20,
        "Ex2RWG_01_LearnZeroPos": 20,
    }.get(export, 0)
    if minimum:
        if (
            len(args) != 1
            or not isinstance(args[0], bytearray)
            or len(args[0]) < minimum
        ):
            raise ValueError(
                f"{export} requires a mutable native buffer of at least {minimum} bytes"
            )
        data = args[0]
    else:
        if len(args) > (1 if export.endswith(("DTCRead", "KeyRegister")) else 0):
            raise ValueError(f"{export} has no used native input")
        data = bytearray()
    _check(context)
    comm = context.comm("selected")
    release = True
    primary = _PENDING_SETTERS[source]
    try:
        if export == "Ex2PSABSI_05_ExitCommunication":
            return 0
        if export == "Ex2PSABSI_05_KeyRegister":
            release = False
            comm.configure(primary, 150)
            status, release = _psa(export, data, comm, context)
            return status
        if export.startswith("Ex2EVP_"):
            comm.select_target(0x750, 0x29)
        if export == "Ex2PSABSI_01_SendMessage":
            comm.configure(primary, 150)
        status = comm.initialize(0)
        if status:
            if export == "Ex2RWG_01_LearnZeroPos":
                _exchange(comm, context, b"\x30")
            if export == "Ex2PSABSI_06_ProgramADCCode":
                context.state[_RESULT_GLOBALS[source]] = status
            if export == "Ex2PSABSI_05_UnlockRequest":
                release = False
            return status
        if export != "Ex2PSABSI_01_SendMessage":
            comm.configure(primary, 150)
        if export == "Ex2PSABSI_04_ForcingOfGaugingRequest":
            secondary, timeout = _FORCING_SETTERS[source]
            comm.configure(secondary, 150)
            comm.configure(timeout, 1000)
        if export.startswith("Ex2EVP_"):
            status, reply = _exchange(comm, context, b"\xa6\x00")
            return status or (0 if len(reply) == 1 else 3)
        if export in _RWG:
            return _rwg(export, data, comm, context)
        status, release = _psa(export, data, comm, context)
        if export == "Ex2PSABSI_06_ProgramADCCode":
            context.state[_RESULT_GLOBALS[source]] = status
        return status
    finally:
        if release:
            comm.finalize()


def run_body(export: str, args: tuple[object, ...], context: Context) -> int:
    """Publish the exact native result global at the callback return boundary."""
    expected_mode = 19 if export in _PSA else 4
    entered = context.mode == expected_mode
    status = _run_body(export, args, context)
    # A wrapper-mode refusal never enters the callback or changes its result.
    if entered and export != "Ex2PSABSI_06_ProgramADCCode":
        context.state[_RESULT_GLOBALS[context.module_sha256]] = status
    return status
