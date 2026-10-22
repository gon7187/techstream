"""Native retained OCC/ACC/MG/ADX/SZABS bodies for exact supplied TY sources.

The selected engine owns worker scheduling. Buffers are caller-owned native ABI
images, with little-endian DWORD fields and byte-exact diagnostic responses.
"""

from __future__ import annotations

import hashlib
import struct
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

OCC05 = tuple(
    "Ex2OCC_05_" + suffix
    for suffix in (
        "ExitCommunication",
        "Get30KgLoadRange",
        "GetNoLoadRange",
        "GetReclineLoadRange",
        "GetSensorInfo",
        "GetTotalWeightInfo",
        "ZeroPointCalibration",
    )
)
OCC06 = ("Ex2OCC_06_SupportCheck", "Ex2OCC_06_ZeroPointCalibration")
ACC = tuple(
    "Ex2ACC_01_" + suffix
    for suffix in (
        "LostCommunicationHistoryClear",
        "LostCommunicationHistoryRead",
        "SupportCheck",
    )
)
MODERN = (
    "Ex2OCC_07_SendMessage",
    "Ex2MG_02_SendMessage",
    "Ex2MG_03_SendMessage",
    "Ex2MG_04_SendMessage",
    "Ex2ADX_01_SendMessage",
)
SZABS = "Ex2SZABS_52_SendMessage"


class SZComm(TYComm, Protocol):
    def configure_keepalive(
        self, interval_ms: int, request: bytes, response_size: int, flags: int
    ) -> None: ...
    def keepalive(self, enabled: bool, wait: bool = False) -> int | None: ...


def supported_exports(module_sha256: str) -> tuple[str, ...]:
    if module_sha256 == SHA_12_TY:
        return OCC05 + OCC06 + ACC
    if module_sha256 == SHA_18_TY:
        return OCC05 + OCC06 + ACC + MODERN
    if module_sha256 == SHA_PLUS_TY:
        return OCC05 + OCC06 + ACC + MODERN + (SZABS,)
    return ()


def _check(ctx: TYContext) -> None:
    if ctx.is_cancelled():
        raise Cancelled("TY retained operation cancelled")


def _exchange(
    ctx: TYContext,
    comm: TYComm,
    request: bytes,
    minimum: int = 0,
    echo: bytes = b"",
    exact: int | None = None,
) -> tuple[int, bytes]:
    _check(ctx)
    status, reply = comm.exchange(request)
    if status:
        return status, reply
    if (
        len(reply) < minimum
        or len(reply) > 0x1020
        or (exact is not None and len(reply) != exact)
        or (echo and reply[1 : 1 + len(echo)] != echo)
    ):
        return 3, reply
    return 0, reply


def _sleep(ctx: TYContext, ms: int) -> None:
    _check(ctx)
    ctx.native_sleep(ms)
    _check(ctx)


def _get(data: bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _put(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value & 0xFFFFFFFF)


def _cleanup(ctx: TYContext, comm: TYComm, *, exit_request: bool = False) -> None:
    # Native cleanup ignores its diagnostic result, preserving the body status.
    try:
        if exit_request:
            comm.exchange(b"\x82")
    finally:
        comm.finalize()


def _security(ctx: TYContext, comm: TYComm, extended: bool) -> int:
    sub = 3 if extended else 1
    status, reply = _exchange(
        ctx, comm, bytes((0x27, sub, 0x5D, 0xC2)), exact=5 if extended else 4
    )
    if status:
        return status
    seed = reply[2:4]
    if extended and seed == b"\0\0":
        return 0
    lo = ((~seed[1] & 255) + 0xA4) & 255
    hi = ((~seed[0] & 255) + 0x61 + (lo < (~seed[1] & 255))) & 255
    status, reply = _exchange(ctx, comm, bytes((0x27, sub + 1, hi, lo)), exact=3)
    if status:
        return status
    if extended:
        return 0 if reply[1] == 4 else 3
    return 0 if reply[2] == 0xAA else 9000


def _occ_range(ctx: TYContext, comm: TYComm, data: bytearray, kind: int) -> int:
    first, second = (
        (0xC1, 0xC2),
        (0xCF, 0xD0),
        (0xD1, 0xD2),
        (0xC4, 0xC5),
        (0xC7, 0xC8),
    )[kind]
    for identifier, offset in ((first, kind * 8 + 4), (second, kind * 8)):
        status, reply = _exchange(
            ctx, comm, bytes((0x21, identifier)), minimum=6, echo=bytes((identifier,))
        )
        if status:
            return status
        data[offset : offset + 4] = reply[2:6]
    return 0


def _occ_weight(ctx: TYContext, comm: TYComm, data: bytearray) -> int:
    _put(data, 0x2C, 1)
    status, reply = _exchange(ctx, comm, b"\x21\x18", minimum=6)
    if not status:
        data[0x28:0x2C] = reply[2:6]
    return status


def _occ05(export: str, data: bytearray, ctx: TYContext) -> int:
    comm = ctx.comm("selected")
    close = False
    try:
        if export == OCC05[0]:
            close = True
            return 0
        if export == OCC05[4]:
            close = True
            status = comm.initialize()
            if status:
                return status
            status, reply = _exchange(ctx, comm, b"\x21\0", minimum=5)
            if not status and reply[3] & 1 and reply[4] & 0xE0 == 0x40:
                _put(data, 0x34, 1)
            return status
        if export == OCC05[6]:
            if _get(data, 0x34):
                status = comm.initialize()
                if status:
                    _put(data, 0x2C, 6)
                    close = True
                    return status
            _put(data, 0x2C, 4)
            status = _security(ctx, comm, False)
            if not status:
                _put(data, 0x2C, 5)
                status, reply = _exchange(ctx, comm, b"\xa5\1\xaa", minimum=5)
                if not status:
                    data[0x30:0x33] = reply[2:5]
            close = bool(status)
            return status
        if export == OCC05[3]:
            status = comm.initialize()
            if status:
                close = True
                return status
            _put(data, 0x2C, 0)
            status = _occ_range(ctx, comm, data, 0)
            if not status:
                data[0x33] = 0
                for identifier, mask in ((0xC3, 1), (0xC6, 0x10)):
                    status, reply = _exchange(
                        ctx,
                        comm,
                        bytes((0x21, identifier)),
                        minimum=3,
                        echo=bytes((identifier,)),
                    )
                    if status:
                        break
                    if reply[2] == 0x55:
                        data[0x33] |= mask
                if not status:
                    for kind, mask in ((3, 1), (4, 0x10)):
                        if data[0x33] & mask:
                            status = _occ_range(ctx, comm, data, kind)
                            if status:
                                break
        elif export in (OCC05[1], OCC05[2]):
            kind = 2 if export == OCC05[1] else 1
            _put(data, 0x2C, kind + 1)
            status = _occ_range(ctx, comm, data, kind)
        else:
            status = 0
        if not status:
            status = _occ_weight(ctx, comm, data)
        close = bool(status)
        return status
    except BaseException:
        close = True
        raise
    finally:
        if close:
            _cleanup(ctx, comm, exit_request=True)


def _support_record(
    raw: bytes, offsets: tuple[int, ...], identifier: int, last_index: int, mask: int
) -> tuple[int, int]:
    if len(offsets) != 256:
        return 99, 0
    offset = offsets[identifier]
    if offset == 0x1020:
        return 22, 0
    if offset < 0 or offset + 1 >= min(len(raw), 0x1021):
        return 99, 0
    length = raw[offset + 1]
    if offset + 1 + length > min(len(raw), 0x1020):
        return 99, 0
    if length < last_index - 2:
        return 22, 0
    index = last_index - 1
    if offset + index >= len(raw):
        return 99, 0
    if not raw[offset + index] or raw[offset + index] & mask != mask:
        return 22, 0
    count = sum(bool(value) for value in raw[offset + 2 : offset + 2 + length])
    return (0, count) if count else (22, 0)


def _support(
    ctx: TYContext,
    comm: TYComm,
    data: bytearray,
    kind: int,
    identifier: int,
    last_index: int,
    mask: int,
    output: int = 0,
) -> int:
    _check(ctx)
    status, raw, offsets = comm.support_snapshot(kind)
    if status:
        return status
    for index in range(3, last_index + 1):
        status, count = _support_record(raw, offsets, identifier, index, mask)
        if status:
            return status
    _put(data, output, count)
    return 0


def _legacy(export: str, data: bytearray, ctx: TYContext) -> int:
    comm = ctx.comm("selected")
    try:
        status = comm.initialize()
        if status:
            return status
        comm.configure(
            "native_rva:142f0"
            if ctx.module_sha256 == SHA_PLUS_TY
            else (
                "native_rva:b940"
                if ctx.module_sha256 == SHA_12_TY
                else "native_rva:12180"
            ),
            150,
        )
        if export == OCC06[0]:
            return _support(ctx, comm, data, 3, 0x11, 3, 0xFF)
        if export == OCC06[1]:
            status = _security(ctx, comm, True)
            if status:
                return status
            _sleep(ctx, 100)
            length = _get(data, 0)
            if length > 0x101E:
                raise ValueError("OCC06 native request length exceeds buffer")
            request = (b"\x3b\x11\xaa" + bytes(0x101D))[: length + 2]
            status, reply = _exchange(ctx, comm, request, exact=2, echo=b"\x11")
            return 1000 if status == 7 and reply == b"\x7f\x3b\x81" else status
        if export == ACC[2]:
            status = _support(ctx, comm, data, 1, 0xFB, 0x3A, 0xFF, 0x38)
            if status:
                return status
            status, raw, offsets = comm.support_snapshot(3)
            if status:
                return status
            status, _ = _support_record(raw, offsets, 0xFA, 3, 0x80)
            if status:
                return status
            _put(data, 0x3C, raw[offsets[0xFA] + 1])
            return 0
        if export == ACC[1]:
            status, reply = _exchange(
                ctx, comm, b"\x21\xfb", exact=_get(data, 0x38) + 2, echo=b"\xfb"
            )
            if not status:
                # Native fixed 14 DWORD copy; short frames retain zeroed stack tail.
                data[:56] = (reply[2:] + bytes(56))[:56]
            return status
        length = _get(data, 0x3C)
        if length > 0x101E:
            raise ValueError("ACC native request length exceeds buffer")
        request = (b"\x3b\xfa\x80" + bytes(0x101D))[: length + 2]
        status, reply = _exchange(ctx, comm, request, exact=2, echo=b"\xfa")
        return status if status or reply[:1] == b"\x7b" else 3
    finally:
        comm.finalize()


def _manager(ctx: TYContext, adx: bool = False) -> TYComm:
    address = (
        ("10134b78" if adx else "101392d0")
        if ctx.module_sha256 == SHA_PLUS_TY
        else ("1011e618" if adx else "1011d4f0")
    )
    return ctx.comm("native:" + address)


def _configure(comm: TYComm, adx: bool = False) -> None:
    comm.configure("native_1074" if adx else "native_1080", 0)
    comm.configure("native_1078" if adx else "native_1084", 180000)
    comm.configure("native_1060" if adx else "native_1064", 0)


def _normal(comm: TYComm, stop_on_error: bool = True) -> int:
    return comm.session(1, stop_on_error=stop_on_error)


def _mg(export: str, data: bytearray, ctx: TYContext) -> int:
    comm = _manager(ctx)
    try:
        status = comm.initialize()
        if status:
            return status
        _configure(comm)
        if export == MODERN[1]:
            status = _normal(comm, False)
            if not status:
                status = _normal(comm, False)
            if status:
                return status
            status, _ = _exchange(
                ctx, comm, b"\x31\1\x11\x14", minimum=4, echo=b"\1\x11\x14"
            )
            cleanup = _normal(comm, False)
            return cleanup or status
        action = _get(data, 0)
        if export == MODERN[2] and action:
            status, reply = _exchange(
                ctx, comm, b"\x22\x20\6", minimum=7, echo=b"\x20\6"
            )
            if not status:
                status = 0 if len(reply) == 7 and reply[3:7] == data[4:8] else 2000
            return status
        if export == MODERN[3] and action not in (0, 1):
            data[4:0x1024] = bytes(0x1020)
            _put(data, 0x1024, 0)
        status = comm.session(3, normal_first=True)
        if status:
            return status
        try:
            if action == 0:
                if export == MODERN[3]:
                    length = _get(data, 0x2048)
                    if length > 0x101D:
                        raise ValueError(
                            "MG native write payload exceeds frame capacity"
                        )
                    payload = data[0x1028 : 0x1028 + length]
                else:
                    payload = data[4:8]
                status, _ = _exchange(
                    ctx, comm, b"\x2e\x20\6" + payload, minimum=3, echo=b"\x20\6"
                )
                if status:
                    return (
                        2001
                        if (
                            export == MODERN[2]
                            and status == 7
                            and comm.read_field("native_10b0") == 0x6B
                        )
                        else 2000
                    )
                return 0
            status, reply = _exchange(
                ctx, comm, b"\x22\x20\6", minimum=7, echo=b"\x20\6"
            )
            if status:
                return 2000
            payload = reply[3:]
            if action == 1:
                expected = _get(data, 0x2048)
                return (
                    0
                    if expected == len(payload)
                    and data[0x1028 : 0x1028 + expected] == payload
                    else 2000
                )
            data[4:0x1024] = bytes(0x1020)
            _put(data, 0x1024, len(payload))
            data[4 : 4 + len(payload)] = payload
            return 0
        finally:
            _normal(comm)
    finally:
        comm.finalize()


def _routine(
    ctx: TYContext, comm: TYComm, sub: int, high: int, low: int, minimum: int = 0
) -> tuple[int, bytes]:
    return _exchange(
        ctx,
        comm,
        bytes((0x31, sub, high, low)),
        minimum=4 + minimum,
        echo=bytes((sub, high, low)),
    )


def _adx(data: bytearray, ctx: TYContext) -> int:
    action = _get(data, 0)
    comm = _manager(ctx, True)
    close = False
    try:
        if action == 0:
            close = True
            status = comm.initialize()
            if not status:
                _configure(comm, True)
                status = comm.session(3, normal_first=True)
            if not status:
                status, _ = _routine(ctx, comm, 1, 0x10, 7)
                if not status:
                    close = False
                    return 0
                _normal(comm)
            return 2000
        if action != 1:
            return 0
        close = True
        _sleep(ctx, 200)
        status = 0
        while _get(data, 4) != 1:
            status, reply = _routine(ctx, comm, 3, 0x10, 7, 1)
            if status or reply[4] not in (0, 1, 2):
                status = 2000
                break
            if reply[4] == 2:
                break
            _sleep(ctx, 200)
        _normal(comm)
        return 2001 if _get(data, 4) == 1 else status
    except BaseException:
        close = True
        raise
    finally:
        if close:
            comm.finalize()


def _occ07(data: bytearray, ctx: TYContext) -> int:
    comm = _manager(ctx)
    action = _get(data, 0)
    close = False
    try:
        if action == 0:
            close = True
            status = comm.initialize()
            if status:
                return status
            _configure(comm)
            status = comm.session(3, normal_first=True)
            if status:
                return status
            status, seed = _exchange(
                ctx, comm, b"\x27\7\x5d\xc2", minimum=4, echo=b"\7"
            )
            if not status and any(seed[2:4]):
                # Native same two-byte carry transform as OCC05 seed/key.
                low = ((~seed[3] & 255) + 0xA4) & 255
                high = ((~seed[2] & 255) + 0x61 + (low < (~seed[3] & 255))) & 255
                status, _ = _exchange(
                    ctx, comm, bytes((0x27, 8, high, low)), echo=b"\10", minimum=2
                )
            if not status:
                status, _ = _routine(ctx, comm, 1, 0x11, 3)
            if not status:
                close = False
                return 2204
            _normal(comm)
            return status
        if action != 1:
            return 0
        close = True
        status = _occ07_poll(data, ctx, comm)
        cleanup = _normal(comm)
        return (cleanup or 2207) if status == 2207 else status
    except BaseException:
        close = True
        raise
    finally:
        if close:
            comm.finalize()


def _occ07_poll(data: bytearray, ctx: TYContext, comm: TYComm) -> int:
    status = 0
    while not data[4]:
        _sleep(ctx, 200)
        status, reply = _exchange(
            ctx, comm, b"\x31\3\x11\3", exact=15, echo=b"\3\x11\3"
        )
        if status:
            return status
        value = reply[4]
        if value == 2:
            return 2206
        if value == 3:
            failed = False
            for i in range(40):
                enabled = i < 23 and i not in (8, 11)
                bit = (reply[5 + i // 4] >> ((i % 4) * 2)) & 3
                data[5 + i] = int(enabled and bit == 2)
                failed |= bool(data[5 + i])
            return 2207 if failed else 3
        if value != 1:
            return 0
    return status


def run_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    if export not in supported_exports(context.module_sha256):
        raise TYSourceError("Unreviewed retained TY source/export pair")
    if hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256:
        raise TYSourceError("TY retained module identity mismatch")
    if export == OCC05[0]:
        if args:
            raise ValueError("OCC05 exit takes no arguments")
        data = bytearray()
    else:
        if len(args) != 1 or type(args[0]) is not bytearray:
            raise ValueError("TY retained body requires one mutable native ABI buffer")
        data = args[0]
        minimum = (
            0x204C
            if export == MODERN[3]
            else 64
            if export in ACC
            else 0x38
            if export in OCC05
            else 0x2D
            if export == MODERN[0]
            else 0x1C
            if export == SZABS
            else 0
            if export == MODERN[1]
            else 4
            if export in OCC06
            else 8
        )
        if len(data) < minimum:
            raise ValueError(f"TY retained native ABI buffer needs {minimum} bytes")
    _check(context)
    if export in OCC05:
        status = _occ05(export, data, context)
    elif export in OCC06 + ACC:
        status = _legacy(export, data, context)
    elif export in MODERN[1:4]:
        status = _mg(export, data, context)
    elif export == MODERN[4]:
        status = _adx(data, context)
    elif export == MODERN[0]:
        status = _occ07(data, context)
    else:
        status = _szabs(data, context)
    # Every assigned callback publishes after its native cleanup calls.
    result_global = {
        SHA_12_TY: "100ab770",
        SHA_18_TY: "10118e38",
        SHA_PLUS_TY: "10134ab8",
    }[context.module_sha256]
    context.state["native_global:" + result_global] = status
    return status


def _module_data(module: bytes, rva: int, size: int) -> bytes:
    """Read source-bound immutable PE constants without executing OEM code."""
    pe = struct.unpack_from("<I", module, 0x3C)[0]
    sections = struct.unpack_from("<H", module, pe + 6)[0]
    start = pe + 24 + struct.unpack_from("<H", module, pe + 20)[0]
    for index in range(sections):
        entry = start + index * 40
        virtual_size, virtual, raw_size, raw = struct.unpack_from(
            "<IIII", module, entry + 8
        )
        if virtual <= rva and rva + size <= virtual + min(virtual_size, raw_size):
            data = module[raw + rva - virtual : raw + rva - virtual + size]
            if len(data) == size:
                return data
    raise TYSourceError("TY immutable source constant outside mapped PE data")


def _sz_read(
    ctx: TYContext, comm: TYComm, first: int, second: int, offset: int, count: int = 1
) -> tuple[int, bytes]:
    status, reply = _exchange(
        ctx,
        comm,
        bytes((0x22, first, second)),
        minimum=3 + offset + count,
        echo=bytes((first, second)),
    )
    return status, reply[3 + offset : 3 + offset + count]


def _sz_write(ctx: TYContext, comm: TYComm, second: int, value: int) -> int:
    status, _ = _exchange(
        ctx,
        comm,
        bytes((0x2E, 0x70, second, value)),
        minimum=3,
        echo=bytes((0x70, second)),
    )
    return status


def _aes128_block(key: bytes, block: bytes) -> bytes | None:
    """CryptoAPI AES-128 ECB without padding; key stays inside this process."""
    import ctypes
    import ctypes.util

    if len(key) != 16 or len(block) != 16:
        raise ValueError("AES-128 native security requires one 16-byte block/key")
    path = ctypes.util.find_library("crypto")
    if path is None:
        return None
    try:
        crypto = ctypes.CDLL(path)
        pointer, integer = ctypes.c_void_p, ctypes.c_int
        crypto.EVP_CIPHER_CTX_new.restype = pointer
        crypto.EVP_CIPHER_CTX_new.argtypes = []
        crypto.EVP_CIPHER_CTX_free.argtypes = [pointer]
        crypto.EVP_CIPHER_CTX_free.restype = None
        crypto.EVP_aes_128_ecb.restype = pointer
        crypto.EVP_aes_128_ecb.argtypes = []
        crypto.EVP_EncryptInit_ex.argtypes = [
            pointer,
            pointer,
            pointer,
            pointer,
            pointer,
        ]
        crypto.EVP_EncryptInit_ex.restype = integer
        crypto.EVP_CIPHER_CTX_set_padding.argtypes = [pointer, integer]
        crypto.EVP_CIPHER_CTX_set_padding.restype = integer
        crypto.EVP_EncryptUpdate.argtypes = [
            pointer,
            pointer,
            pointer,
            pointer,
            integer,
        ]
        crypto.EVP_EncryptUpdate.restype = integer
        crypto.EVP_EncryptFinal_ex.argtypes = [pointer, pointer, pointer]
        crypto.EVP_EncryptFinal_ex.restype = integer
        context = crypto.EVP_CIPHER_CTX_new()
        if not context:
            return None
        try:
            key_buffer = ctypes.create_string_buffer(key, 16)
            input_buffer = ctypes.create_string_buffer(block, 16)
            output = ctypes.create_string_buffer(32)
            used, tail = integer(), integer()
            if (
                crypto.EVP_EncryptInit_ex(
                    context, crypto.EVP_aes_128_ecb(), None, key_buffer, None
                )
                != 1
                or crypto.EVP_CIPHER_CTX_set_padding(context, 0) != 1
                or crypto.EVP_EncryptUpdate(
                    context, output, ctypes.byref(used), input_buffer, 16
                )
                != 1
                or crypto.EVP_EncryptFinal_ex(
                    context, ctypes.byref(output, used.value), ctypes.byref(tail)
                )
                != 1
            ):
                return None
            return output.raw[:16] if used.value + tail.value == 16 else None
        finally:
            crypto.EVP_CIPHER_CTX_free(context)
    except (OSError, AttributeError):
        return None


def _sz_security(ctx: TYContext, comm: TYComm, identifier: int) -> int:
    status, identity = _sz_read(ctx, comm, 0x10, 0x10, 0, 9)
    if status:
        return status
    table = _module_data(ctx.module_bytes, 0xE0CB0, 27)
    lengths = struct.unpack("<III", _module_data(ctx.module_bytes, 0xE0CCC, 12))
    identity = identity.split(b"\0", 1)[0]
    if not any(
        len(identity) == length and identity == table[index * 9 : index * 9 + length]
        for index, length in enumerate(lengths)
    ):
        return 3
    status, reply = _exchange(ctx, comm, b"\x27\x11", minimum=18, echo=b"\x11")
    if status:
        return status
    seed = reply[2:18]
    if not any(seed):
        return 0
    key_index = (0x770, 0x773, 0x790).index(identifier)
    key = b"".join(
        _module_data(ctx.module_bytes, 0xD1CEE + key_index * 40 + part * 10, 4)
        for part in range(4)
    )
    encrypted = _aes128_block(key, seed)
    if encrypted is None:
        return 3
    status, _ = _exchange(ctx, comm, b"\x27\x12" + encrypted, minimum=2, echo=b"\x12")
    return status


def _sz_begin(ctx: TYContext, comm: SZComm, second: SZComm, count: int) -> int:
    for target, identifier in ((comm, 0x770), (second, 0x773))[:count]:
        status = target.session(3, keepalive=0)
        if status:
            return status
        target.configure_keepalive(2000, b"\x3e\0", 2, 0)
        status = target.keepalive(True)
        if status:
            return status
        status = _sz_security(ctx, target, identifier)
        if status:
            return status
    return 0


def _sz_end(comm: SZComm, second: SZComm, count: int) -> None:
    for target in (comm, second)[:count]:
        target.keepalive(False, False)
        target.session(1, keepalive=0)


def _szabs(data: bytearray, ctx: TYContext) -> int:
    comm = cast(SZComm, ctx.comm("native:101392d0"))
    second = cast(SZComm, ctx.comm("native:10135c58"))
    action, status = _get(data, 0), 0
    finalize_primary = action in (2, 3, 7, 12, 13, 17, 18, 21)
    finalize_secondary = action == 17

    def routine(
        sub: int, high: int, low: int, value: int | None = None, target: TYComm = comm
    ) -> int:
        request = bytes((0x31, sub, high, low))
        if value is not None:
            request += bytes((value,))
        return _exchange(ctx, target, request, minimum=4, echo=bytes((sub, high, low)))[
            0
        ]

    def end(count: int = 1) -> None:
        _sz_end(comm, second, count)

    def start(count: int = 1) -> int:
        return _sz_begin(ctx, comm, second, count)

    def clear() -> int:
        return _exchange(ctx, comm, b"\x14\xff\xff\xff")[0]

    def cycles(high_value: bool) -> int:
        offset = 0x10 if high_value else 8
        if high_value:
            _put(data, offset, 0)
        progress = 0
        while True:
            if not high_value:
                _put(data, offset, progress + 1)
            for value, delay in (
                (0x50 if high_value else 5, 1000),
                (0xF0 if high_value else 15, 3000),
                (0x50 if high_value else 5, 1000),
                (0, 0),
            ):
                result = routine(1, 0xC2, 0, value)
                if result:
                    return result
                if delay:
                    _sleep(ctx, delay)
            if high_value:
                _put(data, offset, _get(data, offset) + 1)
            progress = _get(data, offset)
            if progress >= 2:
                break
        result = routine(1, 0xC2, 1, 4)
        if not result:
            _sleep(ctx, 5000)
            result = routine(1, 0xC2, 1, 0)
        return result

    try:
        if action in (0, 1, 2, 3, 4, 8):
            comm.configure_target(0x770)
            status = comm.initialize()
            if status:
                return status
            for name, value in (
                ("native_1080", 0),
                ("native_1084", 255000),
                ("native_1064", 0),
            ):
                comm.configure(name, value)
        if action == 1:
            second.configure_target(0x773)
            status = second.initialize()
            if status:
                return status
            for name, value in (
                ("native_1080", 0),
                ("native_1084", 255000),
                ("native_1064", 0),
            ):
                second.configure(name, value)
        if action in (0, 1):
            status = start(action + 1)
            if status:
                end(action + 1)
        elif action in (2, 3):
            status = start()
            if not status:
                status = _sz_write(ctx, comm, 0, 0)
            if not status:
                status, value = _sz_read(ctx, comm, 0x10, 0, 0x28)
                if action == 2:
                    status = 2003 if status or value[0] & 8 else 0
                elif not status and value[0] & 8:
                    status = 3
            if not status and action == 3:
                status = routine(1, 0xC0, 0x16)
                if not status:
                    status, value = _sz_read(ctx, comm, 0x10, 0, 0xA7)
                    if not status and value[0] & 4:
                        status = 3
                if not status:
                    status = clear()
                if not status:
                    status = routine(1, 0xC4, 3)
            end()
        elif action in (4, 5, 8, 9):
            if action in (4, 8):
                status = start()
            if not status:
                status = routine(1, 0xC1, 2 if action in (8, 9) else 1)
            if status:
                end()
        elif action in (6, 16):
            _sleep(ctx, 60000)
            status = routine(2, 0xC1, 1)
            if status:
                end(2 if action == 16 else 1)
        elif action in (7, 12, 17):
            if action != 12 or _get(data, 0x14) == 0:
                status = _sz_write(ctx, comm, 0x10, {7: 1, 12: 3, 17: 15}[action])
            if action == 17:
                if not status and _get(data, 0xC) != 2:
                    status = 2001
                if status != 2001:
                    end(2)
            else:
                end()
                if (
                    action == 12
                    and not status
                    and _get(data, 0x14) == 2
                    and _get(data, 4) != 2
                ):
                    status = 2000
        elif action == 10:
            status = routine(2, 0xC1, 2)
            if status:
                end()
        elif action == 11:
            while _get(data, 0x18) != 1:
                status, value = _sz_read(ctx, comm, 0x10, 0, 0x5F)
                if status:
                    break
                if not value[0] & 0x10:
                    _sleep(ctx, 15)
                    status = routine(1, 0xC1, 2)
                    if status:
                        break
            if status:
                end()
        elif action == 13:
            status = cycles(False)
            end()
        elif action == 14:
            _put(data, 0xC, _get(data, 0xC) + 1)
            status = routine(1, 0xC0, 0x51, target=second)
            if not status:
                status = cycles(True)
            if not status:
                status = routine(2, 0xC0, 0x51, target=second)
            if status:
                end(2)
        elif action == 15:
            status = routine(1, 0xC1, 1)
            if status:
                end(2)
        elif action == 18:
            _put(data, 0x10, 0)
            status = routine(1, 0xC1, 4)
            while not status:
                while True:
                    status, value = _sz_read(ctx, comm, 0x10, 0, 0x28)
                    if status or value[0] & 1:
                        break
                if status:
                    break
                while True:
                    status, value = _sz_read(ctx, comm, 0x10, 0, 0x5F)
                    if status or not value[0] & 0x10:
                        break
                if status:
                    break
                _put(data, 0x10, _get(data, 0x10) + 1)
                if _get(data, 0x10) > 5:
                    status = _sz_write(ctx, comm, 0x10, 0x1F)
                    if not status:
                        status = _sz_write(ctx, comm, 0, 0x13)
                    break
                status = routine(1, 0xC1, 4)
            end()
        elif action == 19:
            status = routine(1, 0xC1, 0, 2)
            if not status:
                _sleep(ctx, 20000)
            else:
                end()
        elif action == 20:
            status, reply = _exchange(ctx, comm, b"\x19\2\x09", minimum=3)
            if not status:
                payload = reply[3:]
                allowed = {
                    0x538754,
                    0x539254,
                    0x538154,
                    0x532054,
                    0x539654,
                    0x531154,
                    0x53BA55,
                    0x53BA56,
                }
                # Native zeroed scratch buffer supplies the partial record tail.
                records = payload + bytes((-len(payload)) % 4)
                if any(
                    records[i + 3] & 1
                    and int.from_bytes(records[i : i + 3], "big") not in allowed
                    for i in range(0, len(records), 4)
                ):
                    status = 2004
                if not status:
                    status = routine(1, 0xC0, 0x21, 1)
                if not status:
                    status = routine(1, 0xC0, 0x10)
            if status:
                end()
        elif action == 21:
            _sleep(ctx, 120000)
            status, value = _sz_read(ctx, comm, 0x10, 0, 0xA7)
            if not status and value[0] & 15 != 15:
                status = 3
            if not status:
                status = routine(1, 0xC0, 0x21, 0)
            if not status:
                status = routine(1, 0xC0, 0x15)
            if not status:
                status = clear()
            end()
        return status
    except BaseException:
        finalize_primary = finalize_secondary = True
        raise
    finally:
        if status and action in (0, 1, 4, 5, 6, 8, 9, 10, 11, 14, 15, 16, 19, 20):
            finalize_primary = True
        if action == 17 and status == 2001:
            finalize_primary = finalize_secondary = False
        if status and action in (1, 14, 15, 16):
            finalize_secondary = True
        if finalize_primary:
            comm.finalize()
        if finalize_secondary:
            second.finalize()
