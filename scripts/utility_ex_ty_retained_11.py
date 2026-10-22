"""Exact-source retained TY bodies, implemented over the native communication core."""

from __future__ import annotations

import ctypes
import ctypes.util
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
from scripts.utility_ex_ty_chassis import _support_record, _support_required
from scripts.utility_ex_ty_retained_03 import _module_data

# Admission grows only when the complete callback has an executable native port.
_HNFCM = tuple(
    "Ex2HNFCM_02_" + name
    for name in (
        "SupportCheck",
        "ReadCameraData",
        "LearnTarget1",
        "LearnTarget2",
        "LearnTarget3",
        "LearnTargetAll",
    )
)
_COMMON = ("Ex2ITS_01_SendMessage", "Ex2DR_01_GetDataList")
_UDS = tuple(f"Ex2DSEAT_{n:02}_SendMessage" for n in range(1, 5)) + (
    "Ex2ITS_02_SendMessage",
    "Ex2ASECT_01_SendMessage",
)


def supported_exports(source_sha256: str) -> tuple[str, ...]:
    if source_sha256 == SHA_12_TY:
        return _COMMON + _HNFCM
    if source_sha256 in (SHA_18_TY, SHA_PLUS_TY):
        return (
            _COMMON
            + _UDS
            + _HNFCM
            + tuple(f"Ex2ADS_{n:02}_SendMessage" for n in range(4, 11))
        )
    return ()


def _check(context: TYContext) -> None:
    if context.is_cancelled():
        raise Cancelled("Native retained TY worker cancelled")


def _exchange(context: TYContext, comm: TYComm, request: bytes) -> tuple[int, bytes]:
    _check(context)
    return comm.exchange(request)


def _buffer(args: tuple[object, ...], size: int) -> bytearray:
    if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < size:
        raise ValueError(f"Native retained TY needs a mutable {size}-byte buffer")
    return args[0]


def _manager(context: TYContext) -> TYComm:
    return context.comm(
        "native:101392d0" if context.module_sha256 == SHA_PLUS_TY else "native:1011d4f0"
    )


def _initialize(context: TYContext, comm: TYComm) -> int:
    _check(context)
    status = comm.initialize()
    if status == 0:
        setters = (
            ("1e290", "1e2b0", "1e2d0")
            if context.module_sha256 == SHA_PLUS_TY
            else ("1a860", "1a880", "1a8c0")
        )
        for name, value in zip(setters, (0, 180000, 0), strict=True):
            comm.configure("native_rva:" + name, value)
    return status


def _normal(comm: TYComm) -> None:
    comm.session(1, 1, stop_on_error=True)


def _close(
    comm: TYComm,
    session: bool = False,
    *,
    direct: bool = False,
    primary: BaseException | None = None,
) -> None:
    failure = primary
    try:
        if session:
            if direct:
                comm.session(1, 1)
            else:
                _normal(comm)
    except BaseException as error:  # noqa: BLE001 - preserve first cleanup failure
        if failure is None:
            failure = error
    try:
        comm.finalize()
    except BaseException as error:  # noqa: BLE001 - preserve first cleanup failure
        if failure is None:
            failure = error
    if primary is None and failure is not None:
        raise failure


def _routine(
    context: TYContext,
    comm: TYComm,
    sub: int,
    identifier: int,
    count: int = 0,
    high: int = 0x11,
) -> tuple[int, bytes]:
    request = bytes((0x31, sub, high, identifier))
    status, reply = _exchange(context, comm, request)
    if status:
        return status, b""
    # Native compares only the three echoed bytes, not the positive SID.
    if len(reply) < 4 + count or reply[1:4] != request[1:]:
        return 3, b""
    return 0, reply[4 : 4 + count]


def _dseat(export: str, args: tuple[object, ...], context: TYContext) -> int:
    data = _buffer(args, 5)
    index = int(export[9:11]) - 1
    identifier = (1, 3, 5, 6)[index]
    poll_identifier = (
        (3, 5, 6, 6)[index] if context.module_sha256 == SHA_PLUS_TY else identifier
    )
    comm = _manager(context)
    retained = False
    session = False
    primary: BaseException | None = None
    try:
        if int.from_bytes(data[:4], "little") == 0:
            status = _initialize(context, comm)
            if status:
                return status
            status = comm.session(3, 1, normal_first=True)
            if status:
                return status
            session = True
            status, _ = _routine(context, comm, 1, identifier)
            retained = status == 0
            return status
        # The second call consumes the first call's retained manager/session.
        session = True
        while data[4] == 0:
            status, reply = _routine(context, comm, 3, poll_identifier, 1)
            if status:
                return status
            if reply[0] == 2:
                return 0
            if reply[0] != 1:
                return 1000
        return 0
    except BaseException as error:
        primary = error
        raise
    finally:
        if not retained:
            _close(comm, session, primary=primary)


def _selected(export: str, args: tuple[object, ...], context: TYContext) -> int:
    if export == "Ex2ITS_01_SendMessage":
        if args:
            raise ValueError("Native ITS01 takes no arguments")
        data = None
    else:
        data = _buffer(args, 10)
    comm = context.comm("selected")
    primary: BaseException | None = None
    try:
        _check(context)
        status = comm.initialize()
        if status:
            return status
        setter = {
            SHA_12_TY: "b940",
            SHA_18_TY: "12180",
            SHA_PLUS_TY: "142f0",
        }[context.module_sha256]
        comm.configure("native_rva:" + setter, 150)
        if data is None:
            status, reply = _exchange(context, comm, b"\x3b\xf1\x01")
            return status or (0 if len(reply) == 2 and reply[1] == 0xF1 else 3)
        status, reply = _exchange(context, comm, b"\x21\x01")
        if status:
            return status
        if len(reply) != 5:
            return 3
        data[9] = reply[2]
        status, reply = _exchange(context, comm, b"\x21\x03")
        if status:
            return status
        if len(reply) != 11:
            return 3
        data[4:9] = reply[2:7]
        data[:4] = reply[7:11]
        return 0
    except BaseException as error:
        primary = error
        raise
    finally:
        _close(comm, primary=primary)


def _its02(args: tuple[object, ...], context: TYContext) -> int:
    if args:
        raise ValueError("Native ITS02 takes no arguments")
    comm = _manager(context)
    session = False
    primary: BaseException | None = None
    try:
        status = _initialize(context, comm)
        if status:
            return status
        status = comm.session(3, 1, normal_first=True)
        if status:
            return status
        session = True
        status, _ = _routine(context, comm, 1, 7, high=0x10)
        return 1000 if status else 0
    except BaseException as error:
        primary = error
        raise
    finally:
        _close(comm, session, primary=primary)


def _word(data: bytearray, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _put(data: bytearray, offset: int, value: int) -> None:
    data[offset : offset + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")


def _hn_support(context: TYContext, comm: TYComm, data: bytearray) -> int:
    for kind, count, base, stride in ((1, 4, 0, 24), (2, 2, 96, 24), (4, 13, 144, 56)):
        _check(context)
        status, raw, offsets = comm.support_snapshot(kind)
        if status:
            return status
        for index in range(count):
            at = base + index * stride
            required = _word(data, at + 12)
            if required > 10:
                raise ValueError("HNFCM support masks overlap native descriptor fields")
            for shift in reversed(range(required)):
                status, selected = _support_required(
                    raw,
                    offsets,
                    data[at],
                    data[at + 1] + 3 + shift,
                    data[at + 2 + shift],
                )
                if status:
                    _put(data, at + 16, -1)
                    return status
                _put(data, at + 16, selected)
            # Native deliberately discards the count helper's status.
            status, payload = _support_record(raw, offsets, data[at])
            if not status:
                _put(data, at + 20, sum(bool(value) for value in payload))
    return 0


def _hn_read(
    context: TYContext, comm: TYComm, data: bytearray, at: int, service: int
) -> tuple[int, bytes]:
    expected = _word(data, at + 20) + 2
    if expected > 0x1020:
        raise ValueError("HNFCM descriptor reply size exceeds native buffer")
    status, reply = _exchange(context, comm, bytes((service, data[at])))
    if not status and (
        len(reply) != expected or len(reply) < 2 or reply[1] != data[at]
    ):
        status = 3
    return status, reply.ljust(0x1020, b"\0")


def _hn_stop(context: TYContext, comm: TYComm) -> None:
    _exchange(context, comm, b"\x30")  # Native discards cleanup result.


def _hn_result(context: TYContext, comm: TYComm, data: bytearray, check: bool) -> int:
    status, reply = _hn_read(context, comm, data, 48, 0x21)
    if status:
        return status
    bit_at, output_at = _word(data, 64), _word(data, 88)
    if max(bit_at, output_at) >= 0x1020:
        raise ValueError("HNFCM result offset exceeds native reply backing")
    data[899] = reply[output_at]
    return 9999 if check and reply[bit_at] & 2 else 0


def _hnfcm(export: str, args: tuple[object, ...], context: TYContext) -> int:
    camera = export.endswith("ReadCameraData")
    data = _buffer(
        args, 899 if camera else 872 if export.endswith("SupportCheck") else 900
    )
    comm = context.comm("selected")
    primary: BaseException | None = None
    try:
        _check(context)
        status = comm.initialize()
        if status:
            return status
        setter = {SHA_12_TY: "b940", SHA_18_TY: "12180", SHA_PLUS_TY: "142f0"}[
            context.module_sha256
        ]
        comm.configure("native_rva:" + setter, 150)
        if export.endswith("SupportCheck"):
            return _hn_support(context, comm, data)
        if camera:
            status, reply = _hn_read(context, comm, data, 144, 0xA9)
            if not status:
                data[0x368:0x383] = reply[:27]
            return status
        all_targets = export.endswith("All")
        mask = 1 if all_targets else {"1": 32, "2": 64, "3": 128}[export[-1]]
        at = 96 if all_targets else 120
        length, position = _word(data, at + 20), _word(data, at + 16)
        if length > 0x101D or position >= length + 2:
            raise ValueError("HNFCM write descriptor exceeds native backing")
        request = bytearray(length + 3)
        request[0:2] = bytes((0x30, data[at]))
        request[position + 1] = mask
        status, reply = _exchange(context, comm, bytes(request))
        if not status and (len(reply) != 2 or reply[1] != data[at]):
            status = 3
        if status:
            _hn_stop(context, comm)
            return status
        context.sleep(10000)
        at = 0 if all_targets else 24
        status, reply = _hn_read(context, comm, data, at, 0x21)
        if not status:
            position = _word(data, at + 16)
            if position >= 0x1020:
                raise ValueError("HNFCM mask offset exceeds native backing")
            mask = 8 if all_targets else mask
            status = 0 if reply[position] & mask == mask else 9999
        if all_targets:
            if status in (0, 9999):
                result = _hn_result(context, comm, data, True)
                if result or status == 9999:
                    _hn_stop(context, comm)
                return result or status
            _hn_stop(context, comm)
        elif status == 9999:
            _hn_stop(context, comm)
            return _hn_result(context, comm, data, False) or status
        elif status:
            _hn_stop(context, comm)
        elif export.endswith("3"):
            status = _hn_result(context, comm, data, True)
            if status:
                _hn_stop(context, comm)
        return status
    except BaseException as error:
        primary = error
        raise
    finally:
        _close(comm, primary=primary)


def _asect(args: tuple[object, ...], context: TYContext) -> int:
    data = _buffer(args, 7)
    comm = _manager(context)
    retained = False
    session = False
    primary: BaseException | None = None
    try:
        action = _word(data, 0)
        if action == 10:
            session = True
            return 1016
        if action == 0:
            status = _initialize(context, comm)
            if status:
                return status
            status, reply = _exchange(context, comm, b"\x14\xff\xff\xff")
            if status or len(reply) != 1:
                return status or 3
        if action not in (9, 11):
            if action == 0:
                status = comm.session(3, 1, normal_first=True)
                if status:
                    return status
            session = True
            status, _ = _routine(context, comm, 1, 0x9A)
            if status:
                if (
                    action == 0
                    and status == 7
                    and comm.read_field("native_10b0") == 0x69
                ):
                    status = 1005
                return status
            if action in (6, 7):
                retained = True
                return 1009 if action == 6 else 1011
            if action > 11:
                retained = True
                return 0
        session = True
        first = True
        while True:
            if action == 11 and _word(data, 0) == 9:
                retained = True
                return 0
            _check(context)
            context.sleep(200)
            status, reply = _routine(context, comm, 3, 0x9A, 3)
            if status:
                return status
            if action == 11:
                continue
            state, phase, error = reply
            if phase != 0x11:
                data[6] = error
            action = 0 if action == 8 else 3 if action == 9 else action
            terminal = {
                0: (1, 1009),
                1: (3, 1010),
                2: (5, 1003),
                3: (6, 1011),
                4: (8, 1012),
            }
            if (
                action in terminal
                and state == 1
                and phase == terminal[action][0]
                and error == 0
            ):
                retained = True
                return terminal[action][1]
            if action == 5 and (state, phase, error) == (2, 16, 0):
                return 1015
            valid = False
            recoverable = False
            if action == 0:
                valid = state in (0, 1) and phase == 0 and error == 0
                recoverable = state in (0, 1) and phase == 0 and error == 1
            elif state == 1 and action in (1, 2, 3, 4, 5):
                phases = {1: (1, 2), 2: (3, 4), 3: (5,), 4: (6, 7), 5: (8, 9)}[action]
                if phase in phases:
                    allowed_errors = (3, 8) if phase in (3, 5, 8) else (3, 7, 8)
                    recoverable = error in allowed_errors and first
                    valid = error == 0 and (first or action not in (2, 5))
                    if action in (2, 5) and error == 2:
                        valid = True
                        if first:
                            first = False
                            status, _ = _routine(context, comm, 1, 0x9A)
                            if status:
                                return status
            if recoverable:
                retained = True
                return 1013
            if not valid:
                _routine(context, comm, 1, 0x9A)
                return 1006
    except BaseException as error:
        primary = error
        raise
    finally:
        if not retained:
            _close(comm, session, primary=primary)


def _ads_comm(context: TYContext) -> TYComm:
    return context.comm(
        "native:10134b78" if context.module_sha256 == SHA_PLUS_TY else "native:1011e618"
    )


def _ads_init(context: TYContext, comm: TYComm) -> int:
    _check(context)
    status = comm.initialize()
    if not status:
        fields = (
            ("1fbb0", "1fbc0", "1fbd0")
            if context.module_sha256 == SHA_PLUS_TY
            else ("1b730", "1b750", "1b7a0")
        )
        for field, value in zip(fields, (0, 180000, 0), strict=True):
            comm.configure("native_rva:" + field, value)
    return status


def _ads_read(
    context: TYContext, comm: TYComm, high: int, low: int, minimum: int = 1
) -> tuple[int, bytes]:
    request = bytes((0x22, high, low))
    status, reply = _exchange(context, comm, request)
    if not status and (len(reply) < minimum + 3 or reply[1:3] != request[1:]):
        status = 3
    return status, reply[3:]


def _ads_write(
    context: TYContext, comm: TYComm, high: int, low: int, payload: bytes
) -> int:
    if len(payload) > 0x101D:
        raise ValueError("ADS payload exceeds native backing")
    status, reply = _exchange(context, comm, bytes((0x2E, high, low)) + payload)
    return status or (0 if len(reply) == 3 and reply[1:] == bytes((high, low)) else 3)


def _ads_routine(
    context: TYContext, comm: TYComm, sub: int, high: int, low: int, count: int = 0
) -> tuple[int, bytes]:
    request = bytes((0x31, sub, high, low))
    if sub == 1 and low == 0x14:
        request += b"\xff\xff"
    status, reply = _exchange(context, comm, request)
    if not status and (len(reply) < 4 + count or reply[1:4] != request[1:4]):
        status = 3
    return status, reply[4:]


def _aes_block(key: bytes, seed: bytes) -> bytes:
    """CryptoAPI CALG_AES_128 + CRYPT_MODE_ECB, exactly one unpadded block."""
    if len(key) != 16 or len(seed) != 16:
        raise ValueError("Native AES requires one 16-byte key and block")
    library = ctypes.util.find_library("crypto")
    if library is None:
        raise TYSourceError("Native AES provider unavailable")
    crypto = ctypes.CDLL(library)
    crypto.AES_set_encrypt_key.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
    )
    crypto.AES_set_encrypt_key.restype = ctypes.c_int
    crypto.AES_encrypt.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
    crypto.AES_encrypt.restype = None
    schedule = ctypes.create_string_buffer(244)
    output = ctypes.create_string_buffer(16)
    if crypto.AES_set_encrypt_key(key, 128, schedule) != 0:
        raise TYSourceError("Native AES key initialization failed")
    crypto.AES_encrypt(seed, output, schedule)
    return output.raw


def _ads_security(context: TYContext, comm: TYComm, second: bool) -> int:
    status, reply = _exchange(context, comm, b"\x27\x03")
    if status:
        return status
    if len(reply) < 18 or reply[1] != 3:
        return 3
    if not any(reply[2:18]):
        return 0
    rva = 0xF4278 if context.module_sha256 == SHA_PLUS_TY else 0xF87C8
    key = _module_data(context.module_bytes, rva + (16 if second else 0), 16)
    answer = _aes_block(key, reply[2:18])
    status, reply = _exchange(context, comm, b"\x27\x04" + answer)
    return status or (0 if len(reply) >= 2 and reply[1] == 4 else 3)


def _ads_gate(context: TYContext, comm: TYComm) -> tuple[int, bytes]:
    status, payload = _ads_read(context, comm, 1, 1, 32)
    if status:
        return status, b""
    if payload[4] & 128 == 0:
        return 22, b""
    status, payload = _ads_read(context, comm, 0x20, 0, 32)
    if status:
        return status, b""
    if payload[0] & 4 == 0:
        return 22, b""
    status, payload = _ads_read(context, comm, 0x20, 6, 2)
    return status or (0 if payload and payload[0] else 22), payload


def _ads_bits(data: bytearray, payload: bytes) -> None:
    if len(payload) > 0x1020:
        raise ValueError("ADS read exceeds caller backing")
    data[16:0x1030] = payload.ljust(0x1020, b"\0")
    _put(data, 0x1034, len(payload))
    for bit in range(16):
        data[bit] = (payload[bit // 8] >> (bit % 8)) & 1


def _ads(export: str, args: tuple[object, ...], context: TYContext) -> int:
    number = int(export[7:9])
    size = {4: 12, 5: 5, 6: 0x1028, 7: 8, 8: 0x103C, 9: 0x1028, 10: 0x1028}[number]
    data = _buffer(args, size)
    comm = _ads_comm(context)
    retained = False
    session = False
    primary: BaseException | None = None
    try:
        action = _word(data, 8 if number == 4 else 0x1038 if number == 8 else 0)
        if number == 4 and action not in (0, 1):
            retained = True
            return 0
        if number not in (4, 5, 7) or action == 0:
            status = _ads_init(context, comm)
            if status:
                return status
        if number == 4 and action == 1:
            session = True
            while _word(data, 0) != 1:
                context.sleep(200)
                status, payload = _ads_routine(context, comm, 3, 0x10, 7, 1)
                if status:
                    return status
                if payload[0] not in (0, 1):
                    return 0 if payload[0] == 2 else 2000 if payload[0] == 3 else 2001
            return 0
        if number in (5, 7) and action != 0:
            session = True
            while (_word(data, 4) if number == 7 else data[4]) == 0:
                context.sleep(200)
                status, payload = _ads_routine(
                    context,
                    comm,
                    3,
                    0x11 if number == 7 else 0x10,
                    0x0F if number == 7 else 0x14,
                    1,
                )
                if status:
                    return status
                value = payload[0]
                if number == 5:
                    if value != 1:
                        return 0 if value == 2 else 3
                elif value > 1:
                    return 1006 if value == 2 else 3
            return 0
        if number in (8, 9) and action not in (0, 1):
            return 0
        status = comm.session(3, 1, normal_first=True)
        if status:
            return 2000 if number == 10 and action else status
        session = True
        if number == 4:
            status, first = _ads_read(context, comm, 0x20, 3)
            if status:
                return status
            status, second = _ads_read(context, comm, 0x20, 4)
            if status:
                return status
            status = _ads_write(context, comm, 0x20, 3, bytes((data[4],)) + first[1:])
            if status:
                return status
            status = _ads_write(context, comm, 0x20, 4, bytes((data[5],)) + second[1:])
            if status:
                return status
            status, _ = _ads_routine(context, comm, 1, 0x10, 7)
            retained = status == 0
            return status
        if number in (5, 7):
            if number == 5:
                context.sleep(20)
            status, _ = _ads_routine(
                context,
                comm,
                1,
                0x11 if number == 7 else 0x10,
                0x0F if number == 7 else 0x14,
            )
            retained = status == 0
            return 1004 if retained and number == 7 else status
        if number == 6:
            if action == 0:
                status, payload = _ads_read(context, comm, 0x23, 0x0C)
                if not status and payload[0] not in (0, 1):
                    status = 3
                if not status:
                    if len(payload) > 0x1020:
                        raise ValueError("ADS06 read exceeds caller backing")
                    data[4 : 4 + len(payload)] = payload
                    _put(data, 0x1024, len(payload))
                return status
            length = _word(data, 0x1024)
            if length > 0x1020:
                raise ValueError("ADS06 write exceeds caller backing")
            return _ads_write(context, comm, 0x23, 0x0C, bytes(data[4 : 4 + length]))
        if number in (8, 10) and action == 1 or number == 10 and action != 0:
            status = _ads_security(context, comm, number == 10)
            if status:
                return status
            if number == 8:
                length = _word(data, 0x1034)
                if not 2 <= length <= 0x1020:
                    raise ValueError("ADS08 retained payload length invalid")
                wanted = bytearray(data[16 : 16 + length])
                bit = data[0x1030] & 31
                mask = (1 << bit) & 255
                wanted[1] = wanted[1] | mask if data[0x1031] else wanted[1] & ~mask
                high, low = 0x20, 6
            else:
                length = int.from_bytes(data[6:8], "big")
                if length > 0x1020 or 8 + length > len(data):
                    raise ValueError("ADS10 input payload length invalid")
                wanted = data[8 : 8 + length]
                high, low = data[4], data[5]
            status = _ads_write(context, comm, high, low, bytes(wanted))
            if status:
                return status
            context.sleep(200)
            status, payload = _ads_read(context, comm, high, low, 2)
            if status:
                return status
            if number == 8:
                _ads_bits(data, payload)
            return 0 if bytes(wanted) == payload else 99
        if number in (8, 9, 10) and action == 0:
            status, payload = _ads_gate(context, comm)
            if not status and number == 8:
                _ads_bits(data, payload)
            return status
        if number == 9:
            status, payload = _ads_read(context, comm, 0x20, 6, 2)
            if not status:
                if len(payload) > len(data) - 6:
                    raise ValueError("ADS09 output exceeds caller backing")
                data[4:6] = len(payload).to_bytes(2, "little")
                data[6 : 6 + len(payload)] = payload
            return status
        raise AssertionError("Unreachable native ADS branch")
    except BaseException as error:
        primary = error
        raise
    finally:
        if not retained:
            _close(comm, session, direct=number == 4, primary=primary)


def _run(export: str, args: tuple[object, ...], context: TYContext) -> int:
    if export not in supported_exports(context.module_sha256):
        raise TYSourceError(
            "Retained TY source/export pair has no complete native body"
        )
    if export.startswith("Ex2ADS_"):
        return _ads(export, args, context)
    if export == "Ex2ASECT_01_SendMessage":
        return _asect(args, context)
    if export in _HNFCM:
        return _hnfcm(export, args, context)
    if export in _COMMON:
        return _selected(export, args, context)
    if export == "Ex2ITS_02_SendMessage":
        return _its02(args, context)
    return _dseat(export, args, context)


def run_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    if hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256:
        raise TYSourceError("TY module bytes do not match selected source identity")
    return _run(export, args, context)
