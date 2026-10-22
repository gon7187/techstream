"""Exact-source FC, HAL, MGR and IC native bodies; wrapper scheduling is owned by UtilityEx.

Immutable FC05 tables are read from the identity-checked caller supplied PE.
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
    elapsed_ticks,
)

FC04 = tuple(
    "Ex2FC_04_" + name
    for name in (
        "SupportCheck",
        "StartKeepAlive",
        "StartAirBleed",
        "ConfirmAirBleed",
        "CheckCanAirBleed",
        "ExecuteAirBleedHeater",
    )
)
FC05 = ("Ex2FC_05_SupportCheck", "Ex2FC_05_MonitorAndActivateValve")
IC = "Ex2IC_01_SendMessage"
HAL = (
    "Ex2HAL_02_SupportCheckAndDTCCheck",
    "Ex2HAL_02_HeightSensorInitializationAndDTCCheck",
    "Ex2HAL_03_SupportCheckAndDTCCheck",
    "Ex2HAL_03_SynchronizeInformationAndDTCCheck",
)
MGR = tuple(f"Ex2MGR_0{i}_SendMessage" for i in (1, 2, 3))
MANAGERS = {
    SHA_12_TY: "native:100aed50",
    SHA_18_TY: "native:1011d4f0",
    SHA_PLUS_TY: "native:101392d0",
}


def supported_exports(module_sha256: str) -> tuple[str, ...]:
    """Only complete bodies, selected by the original module content identity."""
    return (
        (*FC04, *FC05, *HAL, IC, *(MGR if module_sha256 != SHA_12_TY else ()))
        if module_sha256 in MANAGERS
        else ()
    )


def _u32(data: bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _set32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value)


def _check(context: TYContext) -> None:
    if context.is_cancelled():
        raise Cancelled("TY retained operation cancelled")


def _sleep(context: TYContext, ms: int) -> None:
    _check(context)
    context.native_sleep(ms)
    _check(context)


def _fc_transaction(
    comm: TYComm, target: int, request: bytes, pending: str
) -> tuple[int, bytes]:
    # 18 52a30/52de0; Plus 4e2e0/4df10: every transaction owns its channel.
    try:
        comm.select_target(target, 0)
        status = comm.initialize(0)
        comm.configure(pending, 150)
        return (status, b"") if status else comm.exchange(request)
    finally:
        comm.finalize()


def _fc_send(
    comm: TYComm,
    data: bytearray,
    offset: int,
    target: int,
    control: int,
    payload: bytes,
    pending: str,
) -> int:
    echo, count, index, length = struct.unpack_from("<IIII", data, offset)
    if count > len(payload) or index + count + 1 > 0x1020 or length + 3 > 0x1020:
        raise ValueError("FC descriptor exceeds native 0x1020-byte frame or payload")
    frame = bytearray(0x1020)
    frame[:3] = bytes((0x30, echo & 0xFF, control))
    frame[index + 1 : index + 1 + count] = payload[:count]
    status, reply = _fc_transaction(comm, target, bytes(frame[: length + 3]), pending)
    if not status and (len(reply) != 2 or reply[1] != (echo & 0xFF)):
        return 3
    return status


def _fc_cleanup(comm: TYComm, targets: tuple[int, ...]) -> None:
    # 18 52c00 ignores initialize status and does not set the pending global.
    for target in targets:
        try:
            comm.select_target(target, 0)
            comm.initialize(0)
            comm.exchange(b"\x30")
        finally:
            comm.finalize()


def _fc_start(comm: TYComm, data: bytearray, pending: str) -> int:
    for offset, target, payload in (
        (0x40, 0x7C4, b"\x01"),
        (0x50, 0x7C4, b"\x02\x02"),
        (0x20, 0x7D1, b"\x32"),
        (0x30, 0x7D1, b"\x07\xd0"),
    ):
        status = _fc_send(comm, data, offset, target, 255, payload, pending)
        if status:
            return status
    return 0


def _fc_support(comm: TYComm, data: bytearray, pending: str) -> int:
    # Literal descriptors are in/out: +8 physical position, +12 nonzero count.
    for offset, target, kind, count in (
        (0, 0x7D1, 1, 1),
        (0x20, 0x7D1, 2, 2),
        (0x40, 0x7C4, 2, 2),
    ):
        try:
            comm.select_target(target, 0)
            status = comm.initialize(0)
            comm.configure(pending, 150)
            if status:
                return status
            status, snapshot, offsets = comm.support_snapshot(kind)
            if status:
                return status
            for item in range(count):
                base = offset + item * 16
                identifier, displacement = data[base : base + 2]
                masks = _u32(data, base + 4)
                if masks > 2:
                    raise ValueError(
                        "FC support descriptor masks exceed inline storage"
                    )
                if identifier >= len(offsets):
                    return 99
                start = offsets[identifier]
                if start == 0x1020:
                    return 22
                if start < 0 or start + 1 >= 0x1020 or start + 1 >= len(snapshot):
                    return 99
                size = snapshot[start + 1]
                if start + 1 + size > 0x1020 or start + 2 + size > len(snapshot):
                    return 99
                for bit in reversed(range(masks)):
                    position = displacement + 3 + bit
                    if size < position - 2:
                        return 22
                    physical = 2 + sum(
                        value != 0
                        for value in snapshot[start + 2 : start + position - 1]
                    )
                    _set32(data, base + 8, physical)
                    value = snapshot[start + position - 1]
                    if (
                        not value
                        or value & data[base + 2 + bit] != data[base + 2 + bit]
                    ):
                        return 22
                nonzero = sum(
                    value != 0 for value in snapshot[start + 2 : start + 2 + size]
                )
                _set32(data, base + 12, nonzero)
                if not nonzero:
                    return 22
        finally:
            comm.finalize()
    return 0


def _fc04(export: str, data: bytearray, context: TYContext) -> int:
    comm = context.comm("selected")
    pending = {
        SHA_12_TY: "native_rva:b940",
        SHA_18_TY: "native_rva:12180",
        SHA_PLUS_TY: "native_rva:142f0",
    }[context.module_sha256]
    if export == FC04[0]:
        return _fc_support(comm, data, pending)
    if export == FC04[4]:
        start = context.ticks()
        status = 0
        echo, _, index, length = struct.unpack_from("<IIII", data)
        if index + 1 >= 0x1020 or length + 2 > 0x1020:
            raise ValueError("FC status descriptor exceeds native buffer")
        while elapsed_ticks(context.ticks(), start) < 120000:
            _sleep(context, 1000)
            status, reply = _fc_transaction(comm, 0x7D1, b"\x21\x50", pending)
            if status:
                break
            if len(reply) != length + 2 or reply[1] != (echo & 255):
                status = 3
            elif index + 1 >= len(reply):
                status = 99
            elif reply[index : index + 2] != b"\x00\x03":
                status = 9999
            if status != 9999:
                break
        return status
    targets = (0x7C4,) if export == FC04[5] else (0x7D1, 0x7C4)
    try:
        if export == FC04[1]:
            while _u32(data, 0x60):
                _check(context)
                for offset, target, payload in (
                    (0x20, 0x7D1, b"\x32"),
                    (0x40, 0x7C4, b"\x01"),
                ):
                    status = _fc_send(comm, data, offset, target, 0, payload, pending)
                    if status:
                        return status
                _sleep(context, 3000)
            return 0
        if export == FC04[5]:
            start = context.ticks()
            while elapsed_ticks(context.ticks(), start) < 300000:
                _check(context)
                for offset, payload in ((0x40, b"\x01"), (0x50, b"\x02\x02")):
                    status = _fc_send(comm, data, offset, 0x7C4, 0, payload, pending)
                    if status:
                        return status
                _sleep(context, 3000)
            return 0
        status = _fc_start(comm, data, pending)
        if status:
            return status
        if export == FC04[2]:
            _sleep(context, 30000)
            return 0
        for _ in range(5):
            for payload in (b"\x00", b"\x32"):
                _sleep(context, 4000)
                status = _fc_send(comm, data, 0x20, 0x7D1, 3, payload, pending)
                if status:
                    return status
        return 0
    finally:
        _fc_cleanup(comm, targets)


def _ic(comm: TYComm, data: bytearray, context: TYContext) -> int:
    # Plus 84920; recovered exact18 81c80 and12 66fc0 have identical branches.
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure("native_1080", 0)
        comm.configure("native_1084", 180000)
        status = comm.session(1, 1)
        if status:
            return status
        for index in range(10):
            _check(context)
            request = bytes((0x22, 0xDB, 0x70 + index))
            status, reply = comm.exchange(request)
            if status:
                return status
            if len(reply) != 13 or reply[1:3] != request[1:3]:
                return 3
            data[index * 10 : index * 10 + 10] = reply[3:13]
        status, reply = comm.exchange(b"\x22\xdd\x00")
        if status:
            return status
        if len(reply) != 7 or reply[1:3] != b"\xdd\x00":
            return 3
        data[100:104] = reply[3:7]
        for index in range(10):
            record = data[index * 10 : index * 10 + 10]
            a, b, c, d, e = record[5:10]
            if (
                a
                or b & 0xCE
                or b & 0x30 == 0x20
                or c & 0xE0 in (0x60, 0x80)
                or c & 0x1C == 0x10
                or c & 3
                or d & 0xE0 == 0x80
                or d & 0x1C == 4
                or e
            ):
                return 0
        return 1001
    finally:
        comm.finalize()


_PENDING = {
    SHA_12_TY: "native_rva:b940",
    SHA_18_TY: "native_rva:12180",
    SHA_PLUS_TY: "native_rva:142f0",
}


def _dtcs(comm: TYComm) -> tuple[int, set[int]]:
    status, reply = comm.read_dtcs(0x81, 0x1000)
    if status:
        return status, set()
    # 18 ffa0 compares pairs in wire byte order, count is native header byte1.
    if len(reply) < 2 or len(reply) < 2 + reply[1] * 2:
        return 3, set()
    return 0, {
        int.from_bytes(reply[i : i + 2], "big") for i in range(2, 2 + reply[1] * 2, 2)
    }


def _hal_support(comm: TYComm, data: bytearray, kind: int) -> int:
    if kind == 2:
        _set32(data, 0, 0)
        status, reply = comm.exchange(b"\xa8\x12\x04")
        if status:
            return status
        if len(reply) < 6 or reply[:3] != b"\xe8\x12\x04" or reply[3] < 2:
            return 3
        if reply[4] & 0x80 == 0 or reply[5] != 255:
            return 22
        if len(reply) < 4 + reply[3]:
            return 99
        _set32(data, 0, sum(value != 0 for value in reply[4 : 4 + reply[3]]))
        return 0
    status, reply, offsets = comm.support_snapshot(3)
    if status:
        return status
    if len(offsets) < 2 or offsets[1] == 0x1020:
        return 22
    offset = offsets[1]
    if (
        offset < 0
        or offset + 2 >= len(reply)
        or offset + 1 + reply[offset + 1] > 0x1020
    ):
        return 99
    if not reply[offset + 1] or reply[offset + 2] & 0x40 != 0x40:
        return 22
    _set32(data, 0, reply[offset + 1])
    return 0


def _hal(export: str, data: bytearray, context: TYContext) -> int:
    comm = context.comm("selected")
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(_PENDING[context.module_sha256], 150)
        if export in (HAL[0], HAL[2]):
            status = _hal_support(comm, data, 2 if export == HAL[0] else 3)
            if status:
                return status
        else:
            length = _u32(data, 0)
            maximum = 0x1020 - (3 if export == HAL[1] else 2)
            if length > maximum:
                raise ValueError("HAL request exceeds native 0x1020-byte buffer")
            if export == HAL[1]:
                value = {1: 8, 2: 6, 3: 4, 4: 2, 5: 1}.get(_u32(data, 4), 0)
                frame = (b"\x30\x04\x00\x80" + bytes((value,))).ljust(0x1020, b"\0")
                status, reply = comm.exchange(frame[: length + 3])
                if not status and reply != b"\x70\x04":
                    status = 3
                if not status:
                    return 0
                _sleep(context, 1500)
                status, codes = _dtcs(comm)
                if status:
                    return status
                if 0xA420 in codes:
                    return 9001
                if codes & {0xA42D, 0xA42C}:
                    return 9002
                return 1001
            frame = b"\x3b\x01\x40" + bytes(0x1020 - 3)
            status, reply = comm.exchange(frame[: length + 2])
            if status:
                return status
            if reply != b"\x7b\x01":
                return 3
            _sleep(context, 12000)
        status, codes = _dtcs(comm)
        if status:
            return status
        if export == HAL[0]:
            checked = {
                0xA415,
                0xA416,
                0xA41A,
                0xA420,
                0xA451,
                0xA453,
                0xC129,
                0xC132,
                0xC142,
                0xA42C,
                0xA42D,
                0xA443,
                0xA455,
                0xA456,
                0xC242,
            }
            return 1000 if codes & checked else 0
        if export == HAL[2]:
            # 18 3bcf0/Plus40540: priority is literal nested branch order.
            for code, result in (
                (0xA443, 9104),
                (0xC100, 9109),
                (0xC142, 9110),
                (0xC293, 9111),
                (0xC242, 9112),
                (0xA420, 1000),
                (0xA455, 9105),
                (0xA42C, 9107),
                (0xA42D, 9108),
            ):
                if code in codes:
                    return result
            checked = {
                0xA420,
                0xA451,
                0xA453,
                0xA443,
                0xA455,
                0xA456,
                0xA42C,
                0xA42D,
                0xC100,
                0xC142,
                0xC293,
                0xC242,
            }
            return 0 if codes & checked else 1003
        for code, result in (
            (0xA420, 1000),
            (0xA455, 9105),
            (0xA42C, 9107),
            (0xA42D, 9108),
            (0xA451, 1001),
            (0xA453, 1002),
            (0xA456, 9106),
        ):
            if code in codes:
                return result
        return 0
    finally:
        comm.finalize()


def _mgr_read(comm: TYComm, minimum: int) -> tuple[int, bytes]:
    status, reply = comm.exchange(b"\x22\x20\x07")
    if not status and (len(reply) < minimum + 3 or reply[1:3] != b"\x20\x07"):
        return 3, b""
    return status, reply[3:]


def _mgr_write(comm: TYComm, payload: bytes) -> int:
    status, reply = comm.exchange(b"\x2e\x20\x07" + payload)
    return 3 if not status and (len(reply) < 3 or reply[1:3] != b"\x20\x07") else status


def _mgr(export: str, data: bytearray, context: TYContext) -> int:
    comm = context.comm(MANAGERS[context.module_sha256])
    try:
        status = comm.initialize(0)
        if status:
            return status
        for field, value in (
            ("native_1080", 0),
            ("native_1084", 180000),
            ("native_1064", 0),
        ):
            comm.configure(field, value)
        if export == MGR[0]:
            status = comm.session(1, 1)
            if not status:
                status = comm.session(3, 1)
            if status:
                return status
            status, reply = comm.exchange(b"\x31\x01\x11\x12")
            if not status and (len(reply) < 4 or reply[1:4] != b"\x01\x11\x12"):
                status = 3
            restore = comm.session(1, 1)
            return restore or status
        action = _u32(data, 0)
        if export == MGR[1] and action:
            status, payload = _mgr_read(comm, 4)
            if not status and (len(payload) != 4 or payload != data[4:8]):
                return 2000
            return status
        if export == MGR[2] and action not in (0, 1):
            _set32(data, 0x1024, 0)
            data[4:0x1024] = bytes(0x1020)
        status = comm.session(3, 1)
        if status:
            return status
        if export == MGR[1]:
            status = _mgr_write(comm, bytes(data[4:8]))
            if status:
                status = (
                    2001
                    if status == 7 and comm.read_field("native_10b0") == 0x6B
                    else 2000
                )
            comm.session(1, 1)
            return status
        if action == 0:
            count = _u32(data, 0x2048)
            if count > 0x101D:
                raise ValueError("MGR write exceeds native 0x1020-byte frame")
            status = _mgr_write(comm, bytes(data[0x1028 : 0x1028 + count]))
            comm.session(1, 1)
            return 2000 if status else 0
        status, payload = _mgr_read(comm, 4)
        comm.session(1, 1)
        if status:
            return 2000
        if len(payload) > 0x1020:
            return 2000
        if action == 1:
            count = _u32(data, 0x2048)
            return (
                0
                if len(payload) == count and payload == data[0x1028 : 0x1028 + count]
                else 2000
            )
        data[4 : 4 + len(payload)] = payload
        _set32(data, 0x1024, len(payload))
        return 0
    finally:
        comm.finalize()


_FC05_TABLES = {
    SHA_12_TY: (0x76D38, 26, 0x76ED8, 0x1A0),
    SHA_18_TY: (0xDB740, 44, 0xDBA00, 0x2C0),
    SHA_PLUS_TY: (0xE02F0, 44, 0xE05B0, 0x2C0),
}


def _module_data(module: bytes, rva: int, size: int) -> bytes:
    """Static immutable tables from the already identity-checked original image."""
    try:
        pe = struct.unpack_from("<I", module, 60)[0]
        if module[:2] != b"MZ" or module[pe : pe + 4] != b"PE\0\0":
            raise ValueError("invalid PE header")
        sections = struct.unpack_from("<H", module, pe + 6)[0]
        start = pe + 24 + struct.unpack_from("<H", module, pe + 20)[0]
        for index in range(sections):
            virtual_size, virtual, raw_size, raw = struct.unpack_from(
                "<IIII", module, start + index * 40 + 8
            )
            if virtual <= rva and rva + size <= virtual + min(virtual_size, raw_size):
                data = module[raw + rva - virtual : raw + rva - virtual + size]
                if len(data) == size:
                    return data
    except (struct.error, ValueError) as exc:
        raise TYSourceError("TY immutable PE table is malformed") from exc
    raise TYSourceError("TY immutable table outside mapped source data")


def _support_value(
    snapshot: bytes, offsets: tuple[int, ...], identifier: int, position: int, mask: int
) -> tuple[int, int | None]:
    if identifier >= len(offsets) or offsets[identifier] == 0x1020:
        return 22, None
    start = offsets[identifier]
    if start < 0 or start + 1 >= len(snapshot) or start + 1 >= 0x1020:
        return 99, None
    size = snapshot[start + 1]
    if start + 1 + size > 0x1020 or start + position - 1 >= len(snapshot):
        return 99, None
    if size < position - 2:
        return 22, None
    physical = 2 + sum(
        value != 0 for value in snapshot[start + 2 : start + position - 1]
    )
    value = snapshot[start + position - 1]
    return (0 if value and value & mask == mask else 22), physical


def _support_count(
    snapshot: bytes, offsets: tuple[int, ...], identifier: int
) -> tuple[int, int | None]:
    if identifier >= len(offsets) or offsets[identifier] == 0x1020:
        return 22, None
    start = offsets[identifier]
    if start < 0 or start + 1 >= len(snapshot) or start + 1 >= 0x1020:
        return 99, None
    size = snapshot[start + 1]
    if start + 1 + size > 0x1020 or start + 2 + size > len(snapshot):
        return 99, None
    count = sum(value != 0 for value in snapshot[start + 2 : start + 2 + size])
    return (0 if count else 22), count


def _fc05_support(
    comm: TYComm,
    data: bytearray,
    context: TYContext,
    table: bytes,
    count: int,
    base: int,
    limits: bytes,
) -> int:
    modern = context.module_sha256 != SHA_12_TY
    if modern:
        data[base + 0x48] = 10
    status, snapshot, offsets = comm.support_snapshot(1)
    highest = -1
    if not status:
        previous = -1
        last_status = 0
        for index in range(count):
            at = index * 16
            identifier, displacement, masks, _ = struct.unpack_from("<IIII", table, at)
            data[at] = identifier & 255
            data[at + 12 : at + 15] = bytes((masks & 255, 0, 0))
            for bit in reversed(range(masks)):
                last_status, physical = _support_value(
                    snapshot,
                    offsets,
                    identifier,
                    displacement + 3 + bit,
                    table[at + 12 + bit],
                )
                if physical is not None:
                    _set32(data, at + 8, physical)
                if last_status:
                    break
            _set32(data, at + 4, int(last_status == 0))
            if not last_status:
                if previous != identifier:
                    highest += 1
                    data[base + highest * 8] = identifier & 255
                    previous = identifier
                _, size = _support_count(snapshot, offsets, identifier)
                if size is not None:
                    _set32(data, base + highest * 8 + 4, size)
    _set32(data, base + 0x38, highest & 0xFFFFFFFF)
    if (
        modern
        and highest >= 0
        and any(_u32(data, at) for at in (0x34, 0x44, 0x54, 0x64, 0x74))
        and data[base + highest * 8] != 0x63
        and _u32(data, 0x2B4)
    ):
        highest -= 1
        _set32(data, base + 0x38, highest & 0xFFFFFFFF)
    for offset in range(0, 64, 16):
        index = struct.unpack_from("<I", limits, offset + 4)[0]
        if not _u32(data, index * 16 + 4):
            return 3
    status, snapshot, offsets = comm.support_snapshot(2)
    if status:
        return status
    mask = 15 if modern else 3
    for position in (3, 4):
        status, _ = _support_value(snapshot, offsets, 0xC6, position, mask)
        if status:
            if not modern:
                return status
            mask = 3
            for fallback in (3, 4):
                status, _ = _support_value(snapshot, offsets, 0xC6, fallback, 3)
                if status:
                    return status
            break
    if modern:
        data[base + 0x48] = 11 if mask == 15 else 10
    _, size = _support_count(snapshot, offsets, 0xC6)
    _set32(data, base + 0x3C, (size or 0) + 3)
    if modern and data[base + 0x48] == 11:
        for offset in range(64, 160, 16):
            index = struct.unpack_from("<I", limits, offset + 4)[0]
            if not _u32(data, index * 16 + 4):
                return 3
    return 0


def _fc05_poll(
    comm: TYComm,
    data: bytearray,
    table: bytes,
    count: int,
    base: int,
    index: int,
    modern: bool,
) -> int:
    row = base + index * 8
    identifier, length = struct.unpack_from("<II", data, row)
    status, reply = comm.exchange(bytes((0x21, identifier & 255)))
    if status:
        return status
    if len(reply) != length + 2 or reply[:2] != bytes((0x61, identifier & 255)):
        return 3
    for item in range(count):
        at = item * 16
        if data[at] != identifier or not _u32(data, at + 4):
            continue
        physical = _u32(data, at + 8)
        size = data[at + 12]
        if physical + size > len(reply) or size > 3:
            return 99
        if size == 1:
            mask = table[at + (12 if modern else 13)]
            data[at + 13] = 0
            data[at + 14] = (
                int(reply[physical] & mask == mask)
                if mask in (1, 2, 4, 8, 16, 32, 64, 128)
                else reply[physical]
            )
        else:
            data[at + 13 : at + 13 + size] = reply[physical : physical + size]
    return 0


def _fc05_threshold(data: bytearray, limits: bytes, identifier: int, wide: bool) -> int:
    selected = limits[64:160] if wide else limits[:64]
    for target, index, threshold, direction in struct.iter_unpack("<IIII", selected):
        if target != identifier:
            continue
        value = int.from_bytes(data[index * 16 + 13 : index * 16 + 15], "big")
        if (
            (value <= (threshold & 65535))
            if direction
            else ((threshold & 65535) <= value)
        ):
            return 98
    return 0


def _fc05(export: str, data: bytearray, context: TYContext) -> int:
    rva, count, limit_rva, base = _FC05_TABLES[context.module_sha256]
    modern = context.module_sha256 != SHA_12_TY
    table = _module_data(context.module_bytes, rva, count * 16)
    limits = _module_data(context.module_bytes, limit_rva, 160 if modern else 64)
    comm = context.comm("selected")
    initialized = False
    if modern and export == FC05[0]:
        data[base + 0x48] = 10
    try:
        status = comm.initialize(0)
        if status:
            return status
        initialized = True
        comm.configure(_PENDING[context.module_sha256], 150)
        if export == FC05[0]:
            return _fc05_support(comm, data, context, table, count, base, limits)
        previous = _u32(data, base + 0x44)
        last = 0
        started = context.ticks()
        activated = False
        index = 0
        while _u32(data, base + 0x44):
            _check(context)
            highest = struct.unpack_from("<i", data, base + 0x38)[0]
            if not 0 <= highest < 7:
                return 99
            status = _fc05_poll(comm, data, table, count, base, index, modern)
            if status:
                return status
            identifier = data[base + index * 8]
            wide = modern and data[base + 0x48] == 11
            if activated:
                status = _fc05_threshold(data, limits, identifier, wide)
                if status:
                    return status
            action = _u32(data, base + 0x44)
            now = elapsed_ticks(context.ticks(), started)
            if action in (2, 3) and (
                ((now - last) & 0xFFFFFFFF) >= 3000 or action != previous
            ):
                length = _u32(data, base + 0x3C)
                if length > 0x1020:
                    return 99
                multiplicity = _u32(data, base + 0x40)
                value = {1: 1, 2: 2, 3: 15 if wide else 3}.get(action, 0)
                frame = bytearray(0x1020)
                frame[:4] = bytes((0x30, 0xC6, 0, value))
                if multiplicity == 2:
                    frame[4] = value
                status, reply = comm.exchange(bytes(frame[:length]))
                if status or reply[:2] != b"\x70\xc6":
                    return 99
                previous = _u32(data, base + 0x44)
                activated = True
                last = elapsed_ticks(context.ticks(), started)
            index = index + 1 if index < highest else 0
        return 0
    finally:
        try:
            if initialized and export == FC05[1]:
                comm.exchange(b"\x30")
        finally:
            comm.finalize()


def run_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    if hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256:
        raise TYSourceError("TY module bytes do not match the selected source identity")
    if export not in supported_exports(context.module_sha256):
        raise TYSourceError("retained06 exact source body is not implemented")
    minimum = (
        0x204C
        if export == MGR[2]
        else 8
        if export == MGR[1]
        else 0
        if export == MGR[0]
        else 104
        if export == IC
        else (8 if export == HAL[1] else 4)
        if export in HAL
        else 100
    )
    if export in FC05:
        minimum = 0x1E8 if context.module_sha256 == SHA_12_TY else 0x309
    if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < minimum:
        raise ValueError(
            f"{export} requires a mutable native buffer of {minimum} bytes"
        )
    _check(context)
    if export in FC05:
        return _fc05(export, args[0], context)
    if export in MGR:
        return _mgr(export, args[0], context)
    if export in HAL:
        return _hal(export, args[0], context)
    if export == IC:
        return _ic(context.comm(MANAGERS[context.module_sha256]), args[0], context)
    return _fc04(export, args[0], context)
