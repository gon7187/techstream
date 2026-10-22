"""Source-identified retained TY radar, EVB and VCIB native business bodies.

Mutable native argument buffers preserve UI writes across scheduler sleeps. The
shared engine owns the exported wrapper and thread protocol; no OEM code runs.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import (
    SHA_12_TY,
    SHA_18_TY,
    SHA_PLUS_TY,
    TYComm,
    TYContext,
    TYSourceError,
)

EVB = "Ex2EVB_02_READYONProhibitionCancel"
FRD1 = "Ex2FRD_01_LearnTarget"
FRD2 = "Ex2FRD_02_SendMessage"
FRD3 = "Ex2FRD_03_SendMessage"
FRD4 = "Ex2FRD_04_SendMessage"
FRD5 = "Ex2FRD_05_SendMessage"
VCIB2 = "Ex2VCIB_02_SendMessage"
VCIB3 = "Ex2VCIB_03_SendMessage"
VCIB5 = "Ex2VCIB_05_SendMessage"
FAS = "Ex2FAS_01_SendMessage"
DP2_13_SUPPORT = "Ex2DP2_13_GetSupportBitInformation"
DP2_13_ACTIVE = "Ex2DP2_13_ActiveTest"
DP2_14 = "Ex2DP2_14_SendMessage"
DP2_FRONT = "Ex2DP2_11_FrontBeamAxisAdjustment"
DP2_ACTIVE12 = "Ex2DP2_12_ActiveTest"
DP2_BSM = "Ex2DP2_11_BSMFSRRadarFrontBeamAxisAdjustment"
DP2_OFFSET = "Ex2DP2_12_BSMFSRRadarDealershipAxisOffsetAngleOut"
DP2_11_SUPPORT = "Ex2DP2_11_SupportCheck"
DP2_12_SUPPORT = "Ex2DP2_12_GetSupportBitInformation"
DP2_11_DID = "Ex2DP2_11_SupportCheck_DID"
DP2_12_DID = "Ex2DP2_12_SupportCheck_DID"
CLASSIC_DP2 = (DP2_13_SUPPORT, DP2_13_ACTIVE, DP2_14)
_EXPORTS = {
    SHA_12_TY: (
        EVB,
        FRD1,
        DP2_FRONT,
        DP2_ACTIVE12,
        DP2_11_SUPPORT,
        DP2_12_SUPPORT,
        *CLASSIC_DP2,
    ),
    SHA_18_TY: (
        EVB,
        FRD1,
        FRD2,
        FRD3,
        FRD4,
        FRD5,
        VCIB2,
        VCIB3,
        VCIB5,
        FAS,
        DP2_FRONT,
        DP2_ACTIVE12,
        DP2_BSM,
        DP2_OFFSET,
        DP2_11_SUPPORT,
        DP2_12_SUPPORT,
        DP2_11_DID,
        DP2_12_DID,
        *CLASSIC_DP2,
    ),
    SHA_PLUS_TY: (
        EVB,
        FRD1,
        FRD2,
        FRD3,
        FRD4,
        FRD5,
        VCIB2,
        VCIB3,
        VCIB5,
        FAS,
        DP2_FRONT,
        DP2_ACTIVE12,
        DP2_BSM,
        DP2_OFFSET,
        DP2_11_SUPPORT,
        DP2_12_SUPPORT,
        DP2_11_DID,
        DP2_12_DID,
        *CLASSIC_DP2,
    ),
}


@dataclass
class TYRetainedBlock:
    """Owned native argument memory; callers retain and may update this object."""

    data: bytearray

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytearray):
            raise TypeError("Native argument memory must be mutable bytearray")

    def require(self, size: int) -> None:
        if len(self.data) < size:
            raise ValueError(f"Native argument requires at least {size} bytes")

    def u32(self, offset: int) -> int:
        self.require(offset + 4)
        return int.from_bytes(self.data[offset : offset + 4], "little")

    def put32(self, offset: int, value: int) -> None:
        self.require(offset + 4)
        self.data[offset : offset + 4] = value.to_bytes(4, "little")


def supported_exports(module_sha256: str) -> tuple[str, ...]:
    """Only exact implemented source/export pairs are advertised."""
    return _EXPORTS.get(module_sha256, ())


def _check(context: TYContext) -> None:
    if context.is_cancelled():
        raise Cancelled("Retained TY utility cancelled")


def _sleep(context: TYContext, ms: int) -> None:
    context.native_sleep(ms)


def _open(comm: TYComm) -> int:
    status = comm.initialize(0)
    if status == 0:
        for field, value in (
            ("native_1080", 0),
            ("native_1084", 180000),
            ("native_1064", 0),
        ):
            comm.configure(field, value)
    return status


def _extended(comm: TYComm) -> int:
    return comm.session(3, 1, normal_first=True)


def _normal(comm: TYComm) -> None:
    comm.session(1, 1, stop_on_error=True)


def _read(comm: TYComm, did: bytes, count: int, offset: int = 0) -> tuple[int, bytes]:
    status, reply = comm.exchange(b"\x22" + did)
    if status:
        return status, b""
    if len(reply) < 3 + offset + count or reply[1:3] != did:
        return 3, b""
    return 0, reply[3 + offset : 3 + offset + count]


def _routine(
    comm: TYComm, action: int, rid: bytes, data: bytes = b"", count: int = 0
) -> tuple[int, bytes]:
    request = bytes((0x31, action)) + rid + data
    status, reply = comm.exchange(request)
    if status:
        return status, b""
    if len(reply) < 4 + count or reply[1:4] != request[1:4]:
        return 3, b""
    return 0, reply[4:]


def _evb(context: TYContext) -> int:
    # 12 337a0/33880;18 3f4c0/3f5a0;plus 3ace0/3ac10.
    comm = context.comm("selected")
    try:
        status = comm.initialize(0)
        if status == 0:
            setter = {
                SHA_12_TY: "native_rva:b940",
                SHA_18_TY: "native_rva:12180",
                SHA_PLUS_TY: "native_rva:142f0",
            }[context.module_sha256]
            comm.configure(setter, 150)
            _sleep(context, 10000)
            status, reply = comm.exchange(bytes.fromhex("3b2301"))
            if status == 0 and len(reply) != 2:
                return 3
        return status
    finally:
        comm.finalize()


def _frd3(comm: TYComm, block: TYRetainedBlock) -> int:
    # 18 bcc00/bcc50/bcd20 and plus c3530/c3380/c3580; ASM restores echo-success.
    status = _extended(comm)
    if status:
        return status
    try:
        status, reply = comm.exchange(bytes.fromhex("2220f0"))
        if status:
            return status
        if len(reply) < 7 or reply[1:3] != bytes.fromhex("20f0"):
            return 3
        if len(reply) > 0x1020:
            raise ValueError("Native response exceeds 0x1020 byte buffer")
        block.data[: len(reply)] = reply
        block.put32(0x1020, len(reply))
        request = bytearray(reply)
        request[:3] = bytes.fromhex("2e20f0")
        request[6] = block.data[0x1024]
        status, response = comm.exchange(bytes(request))
        if status == 0 and (len(response) < 3 or response[1:3] != request[1:3]):
            return 3
        return status
    finally:
        _normal(comm)


def _frd4(comm: TYComm) -> int:
    # 18 c0ce0..c0f56 and plus c78e0..c7bc0.
    status = _extended(comm)
    if status:
        return status
    try:
        status, reply = comm.exchange(bytes.fromhex("220204"))
        if status:
            return status
        if len(reply) < 5 or reply[1:3] != bytes.fromhex("0204"):
            return 3
        data = bytearray(reply[3:])
        if not data[1] & 0x20:
            return 1005
        data[1] &= 0xDF
        status, reply = comm.exchange(bytes.fromhex("2e0204") + data)
        if status:
            return status
        if len(reply) < 3 or reply[1:3] != bytes.fromhex("0204"):
            return 3
        status, reply = comm.exchange(bytes.fromhex("220204"))
        if status:
            return status
        if len(reply) < 3 + len(data) or reply[1:3] != bytes.fromhex("0204"):
            return 3
        return 3 if reply[4] & 0x20 else 0
    finally:
        _normal(comm)


def _frd5(comm: TYComm, block: TYRetainedBlock, context: TYContext) -> int:
    # 18 c0f60/c0fa0/c1020 ASM; plus c7ce0/c7d10/c7c20 C+ASM.
    if block.u32(0) == 0:
        retained = False
        try:
            status = _open(comm)
            if status:
                return status
            status = _extended(comm)
            if status == 0:
                status, _ = _routine(comm, 1, b"\x11\x06", b"\x02")
                if status == 0:
                    retained = True
                    return 0  # Native successful start intentionally retains resources.
                status = 1006
                _normal(comm)
            return status
        finally:
            if not retained:
                comm.finalize()
    try:
        while block.data[4] != 1:
            _sleep(context, 200)
            status, data = _routine(comm, 3, b"\x11\x06", count=1)
            if status == 0 and data[0] == 1:
                _check(
                    context
                )  # Host forced-termination boundary for retained polling.
                continue
            if status == 0 and data[0] in (2, 3):
                return 0 if data[0] == 2 else 1006
            status, _ = _routine(comm, 1, b"\x11\x06", b"\x00")
            if status:
                return 1008
            _sleep(context, 200)
            return 1006
        status, _ = _routine(comm, 1, b"\x11\x06", b"\x00")
        if status:
            return 1007
        _sleep(context, 200)
        return 0
    finally:
        _normal(comm)
        comm.finalize()


def _vcib5(comm: TYComm, block: TYRetainedBlock) -> int:
    # 18 cc4a0..cc630; plus d7340..d74f0. Received DWORDs are real outputs.
    try:
        status = _open(comm)
        if status:
            return status
        status = _extended(comm)
        if status:
            return status
        try:
            if block.u32(0):
                status, data = _read(comm, b"\x10\x1d", 16)
                if status == 0:
                    block.data[4:20] = data
                return status
            status, data = _read(comm, b"\x01\x01", 32)
            if status:
                return status
            if not data[2] & 0x80:
                return 3
            status, data = _read(comm, b"\x10\x00", 32)
            return status if status else (0 if data[3] & 8 else 3)
        finally:
            _normal(comm)
    finally:
        comm.finalize()


def _fas(comm: TYComm, block: TYRetainedBlock, context: TYContext) -> int:
    # 18 a4e10..a5135, plus a9b40..a9dd0. Successful action1 retains resources.
    action = block.u32(0)
    status = 0
    retained = False
    try:
        if action != 2:
            status = _open(comm)
            if status:
                return status
            if action == 0:
                status = _extended(comm)
                if status:
                    return status
                try:
                    status, data = _read(comm, b"\x01\x01", 32)
                    if status or not data[2] & 0x80:
                        return status if status else 22
                    status, data = _read(comm, b"\x10\x00", 32)
                    return status if status else (0 if data[0] & 0x60 == 0x60 else 22)
                finally:
                    _normal(comm)
            if action == 1:
                status = _extended(comm)
                if status:
                    return status
                status, _ = _routine(comm, 1, b"\x11\x02")
                if status:
                    _normal(comm)
                else:
                    retained = True
                return status
            return status
        try:
            return _fas_poll(comm, block, context)
        finally:
            _normal(comm)
    finally:
        if not retained:
            comm.finalize()


def _fas_poll(comm: TYComm, block: TYRetainedBlock, context: TYContext) -> int:
    # Keep the original ESI result: secondary DID faults do not overwrite it.
    status = 0
    stop = False
    _sleep(context, 200)
    if block.u32(8):
        _routine(comm, 2, b"\x11\x02")
        return status
    while True:
        status, data = _routine(comm, 3, b"\x11\x02", count=1)
        if status:
            stop = True
            break
        if data[0] == 1:
            _sleep(context, 200)
            if block.u32(8):
                stop = True
                break
            _check(context)
            continue
        if data[0] == 2:
            break
        status = 99
        if data[0] != 3:
            stop = True
            break
        _sleep(context, 200)
        while True:
            if block.u32(8):
                stop = True
                break
            read_status, stage = _read(comm, b"\x10\x02", 1)
            if read_status:
                return status
            if stage[0] not in (1, 2, 3, 4, 5):
                break
            _check(context)
            _sleep(context, 200)
        if not stop and stage[0] in (0, 6):
            read_status, flags = _read(comm, b"\x10\x03", 2)
            if read_status == 0:
                block.data[4] = flags[0] & 0xFC
                if block.data[4]:
                    block.data[4] &= flags[1]
                    if block.data[4]:
                        status = 2000
        break
    if stop:
        _routine(comm, 2, b"\x11\x02")
    return status


def _run_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    """Execute a reviewed native body through typed primitive communication."""
    if hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256:
        raise TYSourceError("Retained TY source identity mismatch")
    if export not in supported_exports(context.module_sha256):
        raise TYSourceError("Retained TY source/export pair is not implemented")
    if export == VCIB2:
        if context.mode != 20:
            return 99
        if len(args) != 1 or not isinstance(args[0], VCIBBlock):
            raise ValueError(
                "VCIB history requires one VCIBBlock with primitive host operations"
            )
        comm = context.comm(
            "native:1011e618"
            if context.module_sha256 == SHA_18_TY
            else "native:10134b78"
        )
        return _VCIB(args[0], context, comm).run()
    if export in (DP2_BSM, DP2_OFFSET):
        if context.mode not in (20, 21):
            return 99
        if len(args) != 1 or not isinstance(args[0], TYRetainedBlock):
            raise ValueError("Native export requires one TYRetainedBlock")
        block = args[0]
        block.require(84)
        comm = context.comm(
            "native:1011d4f0"
            if context.module_sha256 == SHA_18_TY
            else "native:101392d0"
        )
        return (
            _dp2_bsm(comm, block, context)
            if export == DP2_BSM
            else _dp2_offset(comm, block, context)
        )
    if export in (DP2_FRONT, DP2_ACTIVE12):
        if context.mode not in (4, 20, 21):
            return 99
        if len(args) != 1 or not isinstance(args[0], TYRetainedBlock):
            raise ValueError("Native export requires one TYRetainedBlock")
        block = args[0]
        block.require(20 if context.mode == 4 else 44 if export == DP2_ACTIVE12 else 32)
        comm = context.comm(
            "selected"
            if context.mode == 4
            else "native:"
            + {SHA_12_TY: "100aed50", SHA_18_TY: "1011d4f0", SHA_PLUS_TY: "101392d0"}[
                context.module_sha256
            ]
        )
        if context.mode in (20, 21):
            return (
                _dp2_front_uds(comm, block, context)
                if export == DP2_FRONT
                else _dp2_active_uds(comm, block, context)
            )
        try:
            status = _classic_open(comm, context.module_sha256)
            if status:
                return status
            return (
                _dp2_front_classic(comm, block, context)
                if export == DP2_FRONT
                else _dp2_active(comm, block, context, 11)
            )
        finally:
            comm.finalize()
    if export in (DP2_11_SUPPORT, DP2_12_SUPPORT, DP2_11_DID, DP2_12_DID):
        modes = (20, 21) if export.endswith("_DID") else (4, 20, 21)
        if context.mode not in modes:
            return 99
        if context.module_sha256 == SHA_12_TY and context.mode in (20, 21):
            return 0  # Exact12 wrappers return inline without invoking or reading a pointer.
        if len(args) != 1 or not isinstance(args[0], TYRetainedBlock):
            raise ValueError("Native export requires one TYRetainedBlock")
        block = args[0]
        block.require(16 if context.mode == 4 else 64)
        twelve = export in (DP2_12_SUPPORT, DP2_12_DID)
        comm = context.comm(
            "selected"
            if context.mode == 4
            else "native:"
            + {SHA_18_TY: "1011d4f0", SHA_PLUS_TY: "101392d0"}[context.module_sha256]
        )
        if export.endswith("_DID"):
            return _dp2_did(comm, block, twelve)
        if context.mode in (20, 21):
            return _dp2_probe(comm, block, twelve)
        try:
            status = _classic_open(comm, context.module_sha256)
            if status:
                return status
            return (
                _dp2_support(comm, block)
                if twelve
                else _dp2_classic11_support(comm, block)
            )
        finally:
            comm.finalize()
    modes = (
        (4,)
        if export == EVB or export in CLASSIC_DP2
        else ((20,) if export in (VCIB3, VCIB5) else (20, 21))
    )
    if context.mode not in modes:
        return 99
    _check(context)
    if export in (EVB, FRD4):
        if args:
            raise ValueError("Native export takes no arguments")
        if export == EVB:
            return _evb(context)
        comm = context.comm(
            "native:1011d4f0"
            if context.module_sha256 == SHA_18_TY
            else "native:101392d0"
        )
        try:
            status = _open(comm)
            return _frd4(comm) if status == 0 else status
        finally:
            comm.finalize()
    if export in CLASSIC_DP2:
        if len(args) != 1 or not isinstance(args[0], TYRetainedBlock):
            raise ValueError("Native export requires one TYRetainedBlock")
        block = args[0]
        block.require(
            0x10F0 if export == DP2_14 else 20 if export == DP2_13_ACTIVE else 16
        )
        comm = context.comm("selected")
        try:
            status = _classic_open(comm, context.module_sha256)
            if status:
                return status
            if export == DP2_13_SUPPORT:
                return _dp2_support(comm, block)
            if export == DP2_13_ACTIVE:
                return _dp2_active(comm, block, context, 0x11)
            return _dp2_14(comm, block)
        finally:
            comm.finalize()
    if len(args) != 1 or not isinstance(args[0], TYRetainedBlock):
        raise ValueError("Native export requires one TYRetainedBlock")
    block = args[0]
    block.require(
        0x1030
        if export == FRD2
        else 0x1028
        if export == FRD3
        else 8
        if export == VCIB3
        else 20
        if export == VCIB5
        else 12
        if export in (FAS, FRD1)
        else 5
    )
    manager = (
        ("1011e618" if context.module_sha256 == SHA_18_TY else "10134b78")
        if export in (VCIB3, VCIB5)
        else (
            {SHA_12_TY: "100aed50", SHA_18_TY: "1011d4f0", SHA_PLUS_TY: "101392d0"}[
                context.module_sha256
            ]
        )
    )
    if export == FRD2:
        return _frd2(block, context)
    comm = context.comm("native:" + manager)
    if export == VCIB3:
        return _vcib3(comm, block, context)
    if export == FRD1:
        return _frd1(comm, block, context)
    if export == FRD5:
        return _frd5(comm, block, context)
    if export == VCIB5:
        return _vcib5(comm, block)
    if export == FAS:
        return _fas(comm, block, context)
    try:
        status = _open(comm)
        return _frd3(comm, block) if status == 0 else status
    finally:
        comm.finalize()


def _classic_open(comm: TYComm, sha: str) -> int:
    status = comm.initialize(0)
    if status == 0:
        setter = {
            SHA_12_TY: "native_rva:b940",
            SHA_18_TY: "native_rva:12180",
            SHA_PLUS_TY: "native_rva:142f0",
        }[sha]
        comm.configure(setter, 150)
    return status


def _support_record(
    raw: bytes, offsets: tuple[int, ...], identifier: int
) -> tuple[int, bytes]:
    if len(raw) != 0x1020 or len(offsets) != 256:
        raise ValueError(
            "Native support snapshot requires 0x1020 bytes and 256 offsets"
        )
    offset = offsets[identifier]
    if type(offset) is not int or not 0 <= offset <= 0x1020:
        raise ValueError("Native support offset outside buffer")
    if offset == 0x1020:
        return 22, b""
    if offset + 2 > len(raw) or offset + 2 + raw[offset + 1] > len(raw):
        return 99, b""
    return 0, raw[offset + 2 : offset + 2 + raw[offset + 1]]


def _required(payload: bytes, index: int, mask: int) -> tuple[int, int]:
    position = index - 3
    if (
        position < 0
        or position >= len(payload)
        or not payload[position]
        or payload[position] & mask != mask
    ):
        return 22, 0
    return 0, 2 + sum(bool(value) for value in payload[:position])


def _dp2_support(comm: TYComm, block: TYRetainedBlock) -> int:
    # 12 484c0/48640;18 542c0/54440;plus 4f8d0/4f5b0.
    status, raw, offsets = comm.support_snapshot(1)
    if status:
        return status
    status, payload = _support_record(raw, offsets, 0x28)
    if status:
        return status
    for index, mask, output in (
        (4, 0xFF, 8),
        (9, 0x7F, 12),
        (10, 0x7F, None),
        (11, 0xF8, None),
    ):
        status, value = _required(payload, index, mask)
        if status:
            return status
        if output is not None:
            block.put32(output, value)
    block.put32(0, sum(bool(value) for value in payload) + 2)
    status, raw, offsets = comm.support_snapshot(2)
    if status:
        return status
    status, payload = _support_record(raw, offsets, 0x28)
    if status:
        return status
    status, _ = _required(payload, 3, 0xFF)
    if status:
        return status
    block.put32(4, sum(bool(value) for value in payload) + 3)
    return 0


def _dp2_active(
    comm: TYComm, block: TYRetainedBlock, context: TYContext, mask: int
) -> int:
    # 12 48750,18 54550,plus 4fb70: exact 35s strict-'>' timer and masks.
    length = block.u32(4)
    if not 0 <= length <= 0x1020:
        raise ValueError("Native active request length exceeds buffer")
    request = bytearray(0x1020)
    request[:4] = bytes((0x30, 0x28, 0xFF, mask))
    status, reply = comm.exchange(bytes(request[:length]))
    if status:
        return status
    if len(reply) != 2 or reply[1] != 0x28:
        return 3
    start = context.ticks()
    delay = 1000
    try:
        while True:
            _sleep(context, delay)
            status, reply = comm.exchange(bytes.fromhex("2128"))
            if status:
                return status
            if len(reply) != block.u32(0) or len(reply) < 2 or reply[1] != 0x28:
                return 3
            first, second = block.u32(8), block.u32(12)
            if first >= 0x1020 or second + 2 >= 0x1020:
                raise ValueError("Native active response offset exceeds buffer")
            padded = reply.ljust(0x1020, b"\0")
            block.data[16:20] = bytes(
                (padded[first], padded[second], padded[second + 1], padded[second + 2])
            )
            values = block.data[16:20]
            if (
                values[0] & mask == mask
                and values[1] & 0x3F != 0x3F
                and values[2] & 0x3F != 0x3F
            ):
                return 0
            if values[3] & 0xF8:
                return 9002
            if (context.ticks() - start) & 0xFFFFFFFF > 35000:
                return 9001
            delay = 100
    finally:
        comm.exchange(b"\x30")  # Native stop status is discarded.


def _dp2_14(comm: TYComm, block: TYRetainedBlock) -> int:
    # 12 49df0..4a320;18 55c20..56150;plus 51030..51570.
    action = block.u32(0x102C)
    rows = tuple(0x1030 + 28 * index for index in range(7))
    if action == 0:
        status, raw, offsets = comm.support_snapshot(1)
        if status:
            return status
        status, payload = _support_record(raw, offsets, 3)
        if status:
            payload = b""
        for row in rows:
            result, value = _required(payload, block.u32(row) + 3, block.data[row + 4])
            block.put32(row + 8, int(result == 0))
            if result == 0:
                block.put32(row, value - 2)
        if status:
            return status
        count = sum(bool(value) for value in payload)
        block.put32(0, count)
        if not count:
            return 22
        status, raw, offsets = comm.support_snapshot(3)
        if status:
            return status
        status, command_payload = _support_record(raw, offsets, 2)
        if status:
            command_payload = b""
        for row in rows:
            result, _ = _required(
                command_payload, block.u32(row + 12) + 3, block.data[row + 16]
            )
            block.put32(row + 20, int(result == 0))
        # Native source reads the support-record length even when individual masks fail.
        offset = offsets[2]
        if not 0 <= offset < 0x101F:
            raise ValueError("Native command support record has no length byte")
        block.put32(0x1024, raw[offset + 1])
        count = sum(
            block.u32(row + 8) == 1 and block.u32(row + 20) == 1 for row in rows
        )
        block.put32(0x1028, count)
        return 0 if count else 22
    if action == 1:
        block.data[4:0x1022] = bytes(0x101E)
        count = block.u32(0)
        if count > 0x101E:
            raise ValueError("Native DP2 data length exceeds buffer")
        status, reply = comm.exchange(bytes.fromhex("2103"))
        if status == 0:
            if len(reply) != count + 2 or reply[1:2] != b"\x03":
                return 3
            block.data[4 : 4 + count] = reply[2:]
        return status
    if action == 2:
        payload = bytearray(0x1020)
        for row in rows:
            if block.u32(row + 8) != 1 or block.u32(row + 20) != 1:
                continue
            index, mask = block.u32(row), block.data[row + 4]
            if index >= 0x101E:
                raise ValueError("Native DP2 data index exceeds buffer")
            if block.data[index + 4] & mask == mask:
                target = block.u32(row + 12)
                if target >= len(payload):
                    raise ValueError("Native DP2 command index exceeds buffer")
                payload[target] = (payload[target] + block.data[row + 16]) & 255
        length = block.u32(0x1024)
        if length > 0x101E:
            raise ValueError("Native DP2 command length exceeds buffer")
        status, reply = comm.exchange(bytes.fromhex("3b02") + payload[:length])
        if status == 0 and (len(reply) != 2 or reply[1:2] != b"\x02"):
            return 3
        return status
    return 0


def _frd1(comm: TYComm, block: TYRetainedBlock, context: TYContext) -> int:
    # 12 68310..685b0;18 831c0..83480;plus 85ce0..85f50.
    # Normal restore has native precedence over the body result.
    try:
        if block.u32(4) == 0:
            status = _open(comm)
            if status:
                return status
            status = _extended(comm)
            if status:
                return status
            _sleep(context, 200)
            status, reply = comm.exchange(bytes.fromhex("3101110105"))
            if status:
                if reply == bytes.fromhex("7f3122"):
                    status = 1005
            elif len(reply) < 4 or reply[1:4] != bytes.fromhex("011101"):
                status = 1004
            else:
                return 1007  # Native start-success signals UI and retains the open manager.
        else:
            result = 0
            status = 0
            while not block.u32(8):
                _sleep(context, 200)
                status, reply = comm.exchange(bytes.fromhex("31031101"))
                if status:
                    break
                if len(reply) < 5 or reply[1:4] != bytes.fromhex("031101"):
                    status = 1004
                    break
                if reply[4] == 1:
                    _check(context)
                    continue
                if reply[4] == 2:
                    _sleep(context, 500)
                    break
                if reply[4] == 3:
                    _sleep(context, 500)
                    status, reply = comm.exchange(bytes.fromhex("221005"))
                    if status == 0:
                        if len(reply) < 4 or reply[1:3] != bytes.fromhex("1005"):
                            status = 1004
                        else:
                            result = reply[3] >> 3
                            status = 1006
                    break
                status = 1004
                break
            block.data[0] = result
        restore = comm.session(1, 1)
        comm.finalize()
        return restore if restore else status
    except BaseException:
        # Host cancellation/exceptions cannot strand a retained native manager.
        try:
            _normal(comm)
        finally:
            comm.finalize()
        raise


def _frd2_prepare(context: TYContext, comm: TYComm, alternate: bool) -> int:
    # 18 b75c0/b7650 and plus bd600/bd0c0: broker writes are observable inputs.
    if (
        context.set_parameter(0xAB, 0 if alternate else 15) != 1
        or context.write_parameters() != 1
    ):
        return 3
    context.refresh_parameters()
    status = comm.select_protocol(16 if alternate else 17)
    if status:
        return status
    comm.configure_target(
        0x700 if alternate else 0x750, 0 if alternate else 15, 0, 0, 0
    )
    return _open(comm)


def _frd2_read(comm: TYComm) -> tuple[int, bytes]:
    status, reply = comm.exchange(bytes.fromhex("222093"))
    if status:
        return status, b""
    if len(reply) < 5 or reply[1:3] != bytes.fromhex("2093"):
        return 3, b""
    if len(reply) > 0x1020:
        raise ValueError("Native FRD reply exceeds capacity")
    return 0, reply[3:]


def _frd2_restart(context: TYContext, comm: TYComm) -> int:
    try:
        status = _frd2_prepare(context, comm, True)
        if status:
            return status
        status = _extended(comm)
        if status:
            return status
        try:
            status, _ = _routine(comm, 1, b"\x11\xff")
            if status:
                return status
            start = context.ticks()
            while True:
                _sleep(context, 200)
                status, data = _routine(comm, 3, b"\x11\xff", count=1)
                if status:
                    return status
                if data[0] not in (0, 1):
                    return 0 if data[0] == 2 else 3
                if (context.ticks() - start) & 0xFFFFFFFF >= 5000:
                    return 3
        finally:
            _normal(comm)
    finally:
        comm.finalize()


def _frd2(block: TYRetainedBlock, context: TYContext) -> int:
    # Native body 18 b7300..b7650;plus bd0c0..bd8f0.
    action = block.u32(0)
    if action not in (0, 1, 2):
        return 0
    alternate = action == 0
    source = context.module_sha256
    address = (
        {SHA_18_TY: "1011c400", SHA_PLUS_TY: "10135c58"}
        if alternate
        else {SHA_18_TY: "1011d4f0", SHA_PLUS_TY: "101392d0"}
    )[source]
    comm = context.comm("native:" + address)
    if action == 0:
        block.put32(8, 0)
    elif action == 1:
        block.put32(12, 0)
        block.data[16:0x1030] = bytes(0x1020)
    try:
        status = _frd2_prepare(context, comm, alternate)
        if status:
            return status
        status = _extended(comm)
        if status:
            return status
        try:
            if action == 0:
                status, data = _routine(comm, 1, b"\x10\x01", count=32)
                if status == 0 and data[2] & 0x40:
                    status, data = _routine(comm, 1, b"\x11\x00", count=32)
                    if status == 0 and data[31] & 2:
                        block.put32(8, 0x80000000)
                restore = comm.session(1, 1, stop_on_error=True)
                return status if status else restore
            if action == 1:
                status, data = _frd2_read(comm)
                if status == 0:
                    block.put32(12, len(data))
                    block.data[16 : 16 + len(data)] = data
                return status
            length = block.u32(12)
            if not 2 <= length <= 0x101D:
                raise ValueError("Native FRD setting length exceeds capacity")
            block.data[17] = (
                block.data[17] | 0x80 if block.u32(4) == 1 else block.data[17] & 0x7F
            )
            expected = bytes(block.data[16 : 16 + length])
            status, reply = comm.exchange(bytes.fromhex("2e2093") + expected)
            if status == 0 and (len(reply) < 3 or reply[1:3] != bytes.fromhex("2093")):
                status = 3
            if status:
                return status
            _sleep(context, 200)
            status, data = _frd2_read(comm)
            if status:
                return status
            if data != expected:
                return 3
            block.put32(12, len(data))
            block.data[16 : 16 + len(data)] = data
        finally:
            if action != 0:
                _normal(comm)
    finally:
        comm.finalize()
    if block.u32(8) & 0x80000000:
        alternate_comm = context.comm(
            "native:" + {SHA_18_TY: "1011c400", SHA_PLUS_TY: "10135c58"}[source]
        )
        return _frd2_restart(context, alternate_comm)
    return 0


def _vcib3(comm: TYComm, block: TYRetainedBlock, context: TYContext) -> int:
    # 18 ca0a0..ca4db ASM and plus d5920..d5d50: action2 uses retained session.
    action = block.u32(0)
    retained = False
    try:
        if action in (0, 1, 3):
            status = _open(comm)
            if status:
                return status
        if action == 3:
            status = _extended(comm)
            retained = status == 0
            return status
        if action == 0:
            status = _extended(comm)
            if status:
                return status
            try:
                status, data = _routine(comm, 1, b"\x10\x01", count=32)
                if status:
                    return status
                if not data[2] & 0x40:
                    return 22
                status, data = _routine(comm, 1, b"\x11\x00", count=32)
                return status if status else (0 if data[0] & 3 == 3 else 22)
            finally:
                _normal(comm)
        if action not in (1, 2):
            return 0
        rid = bytes((0x11, 7 if action == 1 else 8))
        if action == 1:
            status = _extended(comm)
            if status:
                return status
        try:
            status, _ = _routine(comm, 1, rid, b"\x00\x00" if action == 2 else b"")
            if status:
                return 2001
            while not block.u32(4):
                _sleep(context, 100)
                status, data = _routine(comm, 3, rid, count=1)
                if status:
                    return 2001
                if data[0] == 2:
                    _check(context)
                    continue
                return 0 if data[0] == 1 else 2001
            return 0
        finally:
            _normal(comm)
    finally:
        if not retained:
            comm.finalize()


def _dp2_probe(comm: TYComm, block: TYRetainedBlock, twelve: bool) -> int:
    # 18 7e700/7f9e0;plus 81500/82b70: four independent target observations.
    offset = 0x2C if twelve else 0x20
    block.require(offset + 20)
    block.data[offset : offset + 20] = bytes(20)
    target, second = comm.read_target()
    try:
        for index, address in enumerate((0x41, 0x42, 0x81, 0x82)):
            comm.configure_target(0x750, address, 0, 0, 0)
            if second == 0:
                comm.select_protocol(17)
            try:
                status = _open(comm)
                if status:
                    return 10000
                status, reply = comm.exchange(bytes.fromhex("3e00"))
                if status or len(reply) < 2 or reply[1] != 0:
                    continue  # Probe failure is native absence, not a positive observation.
                if _extended(comm):
                    return 10000
                status, data = _dp2_bitmap(comm, b"\x01\x01")
                if status == 0 and data[4] & 0x80:
                    status, data = _dp2_bitmap(comm, b"\x20\x00")
                    if status == 0 and data[10] & 8:
                        status, data = _read(comm, b"\x20\x55", 1)
                        if status == 0:
                            block.put32(offset, 1)
                            block.put32(offset + 4 + index * 4, int(bool(data[0] & 1)))
                comm.session(1, 1)
                if status:
                    return status
            finally:
                comm.finalize()
        return 0
    finally:
        comm.configure_target(target, second, 0, 0, 0)
        if second == 0:
            comm.select_protocol(16)


def _dp2_classic11_support(comm: TYComm, block: TYRetainedBlock) -> int:
    # 12 47550/476a0;18 53350/534a0;plus 4f100/4ecb0.
    status, raw, offsets = comm.support_snapshot(1)
    if status:
        return status
    status, payload = _support_record(raw, offsets, 0x28)
    if status:
        return status
    for index, mask, output in ((4, 255, 0), (11, 248, 4)):
        status, value = _required(payload, index, mask)
        if status:
            return status
        block.put32(output, value)
    block.put32(8, sum(bool(value) for value in payload))
    status, raw, offsets = comm.support_snapshot(2)
    if status:
        return status
    status, payload = _support_record(raw, offsets, 0x28)
    if status:
        return status
    status, _ = _required(payload, 3, 255)
    if status:
        return status
    block.put32(12, sum(bool(value) for value in payload))
    return 0


def _dp2_did(comm: TYComm, block: TYRetainedBlock, twelve: bool) -> int:
    # 18 7eae0/7fc70;plus 82310/831e0. Native state10011 means execute once.
    result_offset = 0x24 if twelve else 0x18
    flag_offset = 0x20 if twelve else 0x13
    block.require(result_offset + 4)
    result = block.u32(result_offset)
    if result != 10011:
        return result
    try:
        status = _open(comm)
        if status:
            result = 10000
            return result
        if _extended(comm):
            result = 10000
            return result
        status, data = _dp2_bitmap(comm, b"\x01\x01")
        enabled = status == 0 and bool(data[2] & 0x80)
        if status == 0 and enabled:
            status, data = _dp2_bitmap(comm, b"\x10\x00")
            if status == 0:
                enabled = bool(data[0] & 0x40)
                block.data[flag_offset] = int(bool(data[0] & 0x20))
            if status == 0 and enabled:
                status, data = _read(comm, b"\x10\x02", 1)
                if status == 0:
                    enabled = bool(data[0] & 0x20)
                if status == 0 and block.data[flag_offset]:
                    block.data[flag_offset + 1] = 0
                    status, data = _read(comm, b"\x10\x03", 2)
                    if status == 0:
                        block.data[flag_offset + 1] = int(bool(data[1] & 0x40))
        if status:
            if status not in (10012, 10000):
                comm.session(1, 1)
            result = status
        else:
            result = 10000 if comm.session(1, 1) else (10012 if enabled else 0)
        return result
    finally:
        comm.finalize()
        block.put32(result_offset, result)


def _dp2_bitmap(comm: TYComm, did: bytes) -> tuple[int, bytes]:
    status, reply = comm.exchange(b"\x22" + did)
    if status:
        return status, b""
    if len(reply) != 35 or reply[1:3] != did:
        return 3, b""
    return 0, reply[3:]


def _dp2_begin(
    comm: TYComm, context: TYContext, option: int, *, wait: bool = True
) -> int:
    if wait:
        _sleep(context, 200)
    request = bytes((0x31, 1, 0x11, 1, option))
    status, reply = comm.exchange(request)
    if status:
        return 10006 if reply == bytes.fromhex("7f3122") else status
    return 0 if len(reply) >= 4 and reply[1:4] == request[1:4] else 3


def _dp2_poll(
    comm: TYComm, context: TYContext, block: TYRetainedBlock, *, active: bool
) -> int:
    # 18 7f1d0/80120;plus 82180/83050;12 65940/65ce0.
    last = context.ticks()
    while True:
        elapsed = (context.ticks() - last) & 0xFFFFFFFF
        delay = 200 - ((context.ticks() - last) & 0xFFFFFFFF) if elapsed < 200 else 0
        _sleep(context, delay)
        last = context.ticks()
        status, reply = comm.exchange(bytes.fromhex("31031101"))
        if status:
            return status
        if len(reply) < 5 or reply[1:4] != bytes.fromhex("031101"):
            return 3
        if block.u32(0x1C) if active else block.data[0x12]:
            return 10009 if active else 10007
        if reply[4] == 1:
            _check(context)  # Host termination; native UI status remains separate.
            continue
        if reply[4] == 2:
            return 0
        return (9002 if active else 9000) if reply[4] == 3 else 3


def _dp2_option(block: TYRetainedBlock, active: bool) -> int:
    status_offset, selection_offset, flags = (
        (0x24, 0x28, 0x20) if active else (0x18, 0x1C, 0x13)
    )
    if block.u32(status_offset) == 10012:
        if block.u32(selection_offset) == 2:
            return 10 if active else 9
        if (
            block.u32(selection_offset) == 1
            and block.data[flags]
            and block.data[flags + 1]
        ):
            return 12 if active else 11
    return 4 if active else 3


def _dp2_front_uds(comm: TYComm, block: TYRetainedBlock, context: TYContext) -> int:
    # 12 65720;18 7ef50;plus 819f0; ASM restores the real received angle.
    try:
        status = _open(comm)
        if status:
            return status
        if _extended(comm):
            return 10000
        option = 3 if context.module_sha256 == SHA_12_TY else _dp2_option(block, False)
        status = _dp2_begin(
            comm, context, option, wait=context.module_sha256 != SHA_12_TY
        )
        if status == 0:
            block.data[0x11] = 0xF1
            while True:
                _sleep(context, 200)
                if block.data[0x11] == 0xF2:
                    break
                _check(context)  # Host replacement for Win32 forced worker termination.
            status = _dp2_poll(comm, context, block, active=False)
            if status in (0, 9000):
                if context.module_sha256 != SHA_12_TY:
                    _sleep(context, 500)
                if status == 9000:
                    status, data = _read(comm, b"\x10\x05", 1)
                    if status == 0:
                        block.data[0x10] = data[0] >> 3
                        status = 9000
        comm.session(1, 1)
        return status
    except Cancelled:
        _normal(comm)
        raise
    finally:
        comm.finalize()


def _dp2_active_uds(comm: TYComm, block: TYRetainedBlock, context: TYContext) -> int:
    # 12 65a80;18 7ff80;plus 82e00: start status10008 retains manager until result.
    action = block.u32(0x18)
    retained = False
    try:
        status = 0
        if action == 0:
            status = _open(comm)
            if status:
                # The native early initialize return does not acquire a retained session.
                retained = True
                return status
            if _extended(comm):
                status = 10000
            else:
                option = (
                    4
                    if context.module_sha256 == SHA_12_TY
                    else _dp2_option(block, True)
                )
                status = _dp2_begin(comm, context, option)
                if status in (0, 10008):
                    retained = True
                    return 10008
        if action == 1:
            status = _dp2_poll(comm, context, block, active=True)
            if status == 0:
                status, data = _read(comm, b"\x10\x0d", 2)
                # Native12/18 local is zero initialized even if its read fails.
                block.data[0x15:0x17] = data if status == 0 else bytes(2)
            elif status == 9002:
                status, data = _read(comm, b"\x10\x05", 1)
                if status == 0:
                    block.data[0x14] = data[0]
                    status = 9002
        comm.session(1, 1)
        return status
    except Cancelled:
        _normal(comm)
        raise
    finally:
        if not retained:
            comm.finalize()


def _dp2_front_classic(comm: TYComm, block: TYRetainedBlock, context: TYContext) -> int:
    # 12 477b0/47a00;18 535b0/53910;plus 4eed0/4ec40.
    length = block.u32(12)
    if length > 0x101D:
        raise ValueError("Native classic front request length exceeds capacity")
    request = bytearray(0x1020)
    request[:4] = bytes.fromhex("3028ff08")
    status, reply = comm.exchange(bytes(request[: length + 3]))
    if status:
        return status
    if len(reply) != 2 or reply[1] != 0x28:
        return 3
    start = context.ticks()
    phase = 8
    try:
        _sleep(context, 1000)
        while True:
            status, reply = comm.exchange(bytes.fromhex("2128"))
            if status:
                return status
            if len(reply) != block.u32(8) + 2 or len(reply) < 2 or reply[1] != 0x28:
                return 3
            first, second = block.u32(0), block.u32(4)
            if first >= 0x1020 or second >= 0x1020:
                raise ValueError("Native classic front response index exceeds buffer")
            padded = reply.ljust(0x1020, b"\0")
            fault, value = padded[first], padded[second] >> 3
            complete = value == 8 if phase == 8 else value == 0 and fault == 0
            if complete:
                if phase == 0:
                    return 0
                phase = 0
            elif fault:
                block.data[16] = fault
                return 9000
            elif (context.ticks() - start) & 0xFFFFFFFF >= 35000:
                return 9001
            _sleep(context, 100)
    finally:
        comm.exchange(b"\x30")


def run_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    """Publish the native worker result after its body and cleanup have completed."""
    status = _run_body(export, args, context)
    modes = (
        (4,)
        if export == EVB or export in CLASSIC_DP2
        else (20,)
        if export.startswith("Ex2VCIB_")
        else (20, 21)
        if export in (DP2_BSM, DP2_OFFSET) or export.endswith("_DID")
        else (4, 20, 21)
        if export.startswith("Ex2DP2_")
        else (20, 21)
    )
    inline = (
        context.module_sha256 == SHA_12_TY
        and export in (DP2_11_SUPPORT, DP2_12_SUPPORT)
        and context.mode in (20, 21)
    )
    if context.mode in modes and not inline:
        address = {
            SHA_12_TY: "100ab770",
            SHA_18_TY: "10118e38",
            SHA_PLUS_TY: "10134ab8",
        }[context.module_sha256]
        context.state["native_global:" + address] = status
    return status


def _dp2_target_value(comm: TYComm) -> tuple[int, bytes]:
    status, reply = comm.exchange(bytes.fromhex("222055"))
    if status:
        return status, b""
    if len(reply) < 3 or reply[1:3] != bytes.fromhex("2055"):
        return 3, b""
    return 0, reply[3:]


def _dp2_targets(
    comm: TYComm, block: TYRetainedBlock, *, active: bool, enable: bool
) -> int:
    # 18 7f4f0/7f6e0/80470/80660;plus 812b0/81000/82920/82670.
    # The original do/while reads uninitialized data for an empty selection: reject at host boundary.
    offset = 0x30 if active else 0x24
    targets = [
        address
        for index, address in enumerate((0x41, 0x42, 0x81, 0x82))
        if block.u32(offset + index * 4)
    ]
    if not targets:
        raise ValueError("Native radar target selection is empty")
    original, second = comm.read_target()
    failed = False
    status = 0
    try:
        for address in targets:
            comm.configure_target(0x750, address, 0, 0, 0)
            if second == 0:
                comm.select_protocol(17)
            try:
                status = _open(comm)
                if status == 0:
                    if _extended(comm):
                        status = 10000
                    else:
                        status, data = _dp2_target_value(comm)
                        # Native buffers are zero initialized; missing second data byte is zero.
                        value = data[1] if len(data) > 1 else 0
                        if status == 0 and bool(value) != enable:
                            payload = bytearray(data.ljust(2, b"\0"))
                            payload[1] = (payload[1] & 0xFE) + int(enable)
                            # Preserve native sent length, even for a zero-length DID payload.
                            status, reply = comm.exchange(
                                bytes.fromhex("2e2055") + payload[: len(data)]
                            )
                            if status == 0 and (
                                len(reply) < 3 or reply[1:3] != bytes.fromhex("2055")
                            ):
                                status = 3
                            if status == 0:
                                status, data = _dp2_target_value(comm)
                                value = data[1] if len(data) > 1 else 0
                                if status == 0 and bool(value) != enable:
                                    status = 3
                        comm.session(1, 1)
            finally:
                comm.finalize()
            if status:
                failed = True
                if enable:
                    _dp2_targets(comm, block, active=active, enable=False)
                    return 10006
        if not enable and failed:
            seen, result, read_seen, read_result, special = (
                (0x40, 0x4C, 0x44, 0x50, 9002)
                if active
                else (0x34, 0x3C, 0x38, 0x40, 9000)
            )
            if not (
                block.u32(seen)
                and block.u32(result) == special
                and block.u32(read_seen)
                and block.u32(read_result) == 0
            ):
                return 10016
        return status
    finally:
        comm.configure_target(original, second, 0, 0, 0)
        if second == 0:
            comm.select_protocol(16)


def _dp2_bsm(comm: TYComm, block: TYRetainedBlock, context: TYContext) -> int:
    # 18 7f310 and plus80e00 record both poll and detail results before cleanup.
    for offset in (0x34, 0x38, 0x3C, 0x40):
        block.put32(offset, 0)
    prepared = False
    interrupted = False
    status = 0
    try:
        status = _dp2_targets(comm, block, active=False, enable=True)
        if status == 0:
            prepared = True
            status = _open(comm)
            if status == 0:
                if _extended(comm):
                    status = 10000
                else:
                    status = _dp2_begin(comm, context, _dp2_option(block, False))
                    if status == 0:
                        block.data[0x11] = 0xF1
                        while True:
                            _sleep(context, 200)
                            if block.data[0x11] == 0xF2:
                                break
                            _check(
                                context
                            )  # Host forced-termination boundary; keep Sleep intact.
                        status = _dp2_poll(comm, context, block, active=False)
                        block.put32(0x34, 1)
                        block.put32(0x3C, status)
                        if status in (0, 9000):
                            _sleep(context, 500)
                            if status == 9000:
                                detail, data = _read(comm, b"\x10\x05", 1)
                                block.put32(0x38, 1)
                                block.put32(0x40, detail)
                                if detail:
                                    status = 10006
                                else:
                                    block.data[16] = data[0] >> 3
                        elif status != 10007:
                            status = 10006
                    else:
                        status = 10006
                    comm.session(1, 1)
    except Cancelled:
        interrupted = True
        _normal(comm)
        raise
    finally:
        comm.finalize()
        if interrupted and prepared:
            _dp2_targets(comm, block, active=False, enable=False)
    if prepared and _dp2_targets(comm, block, active=False, enable=False) == 10016:
        status = 10016
    return status


def _dp2_offset(comm: TYComm, block: TYRetainedBlock, context: TYContext) -> int:
    # 18 80260 and plus82470: exactly one retained start; outcome counters reset per call.
    for offset in (0x40, 0x44, 0x4C, 0x50):
        block.put32(offset, 0)
    action = block.u32(0x18)
    prepared = action == 1
    retained = False
    interrupted = False
    restore_session = action != 0
    status = 0
    try:
        if action == 0:
            status = _dp2_targets(comm, block, active=True, enable=True)
            if status:
                return status
            prepared = True
            status = _open(comm)
            if status == 0:
                if _extended(comm):
                    status = 10000
                else:
                    restore_session = True
                    status = _dp2_begin(comm, context, _dp2_option(block, True))
                    if status == 0:
                        retained = True
                        return 10008
                    status = 10006
        if action == 1:
            status = _dp2_poll(comm, context, block, active=True)
            block.put32(0x40, 1)
            block.put32(0x4C, status)
            if status in (0, 9002):
                detail, data = _read(
                    comm,
                    b"\x10\x0d" if status == 0 else b"\x10\x05",
                    2 if status == 0 else 1,
                )
                block.put32(0x44, 1)
                block.put32(0x50, detail)
                if detail:
                    status = 10006
                elif status == 0:
                    block.data[21:23] = data
                else:
                    block.data[20] = data[0]
            elif status != 10009:
                status = 10006
        if restore_session:
            comm.session(1, 1)
    except Cancelled:
        interrupted = True
        _normal(comm)
        raise
    finally:
        if not retained:
            comm.finalize()
            if interrupted and prepared:
                _dp2_targets(comm, block, active=True, enable=False)
    if prepared and _dp2_targets(comm, block, active=True, enable=False) == 10016:
        status = 10016
    return status


NativeDate = tuple[int, int, int, int, int, int]


@runtime_checkable
class VCIBHost(Protocol):
    """Individual native host operations; procedure control remains in this module."""

    def local_time(self) -> NativeDate: ...
    def mktime(self, value: NativeDate) -> int: ...
    def gmtime(self, seconds: int) -> NativeDate: ...
    def localtime(self, seconds: int) -> NativeDate: ...
    def decode_ansi(self, value: bytes) -> str: ...
    def common_application_data(self) -> str: ...
    def allocate(self, size: int) -> object | None: ...
    def release(self, allocation: object) -> None: ...
    def mkdir(self, path: str) -> None: ...
    def write(self, path: str, value: bytes) -> int: ...
    def read(self, path: str) -> bytes: ...
    def exists(self, path: str) -> bool: ...
    def delete(self, path: str) -> None: ...
    def files(self, directory: str, suffix: str) -> tuple[str, ...]: ...
    def free_space(self, directory: str) -> int: ...
    def zip_open(self, path: str, *, update: bool) -> object: ...
    def zip_add(
        self, handle: object, path: str, name: str, *, shell_flags: int = 0
    ) -> None: ...
    def zip_count(self, handle: object) -> int: ...
    def zip_close(self, handle: object) -> None: ...


@dataclass
class VCIBBlock(TYRetainedBlock):
    """Native memory plus explicit primitive clock, allocation and file provider."""

    host: VCIBHost

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.host, VCIBHost):
            raise TypeError("VCIB requires a complete primitive host provider")


@dataclass(frozen=True)
class _VCIBLayout:
    directory: int
    path_size: int
    zip_name: int
    flags: int
    dates: int
    count: int
    selected: int
    start: int
    primary: int
    progress: int
    total: int
    log_kind: int
    globals: tuple[int, ...]


_VCIB_LAYOUTS = {
    SHA_18_TY: _VCIBLayout(
        0x108,
        260,
        0x20C,
        0x22A,
        0x612,
        0x1D84,
        0x1D88,
        0x2170,
        0x2176,
        0x2178,
        0x217A,
        0x217C,
        (
            0x1012AE3C,
            0x1012AE40,
            0x1012AE5C,
            0x1012AE6C,
            0x1012AE74,
            0x1012AE58,
            0x1012AE50,
            0x1012AE78,
            0x1012AE54,
            0x1012AE70,
        ),
    ),
    SHA_PLUS_TY: _VCIBLayout(
        0x20C,
        520,
        0x414,
        0x450,
        0x838,
        0x1FA8,
        0x1FAC,
        0x2394,
        0x239A,
        0x239C,
        0x239E,
        0x23A0,
        (
            0x101535A0,
            0x101535A4,
            0x10153598,
            0x1015359C,
            0x10153558,
            0x1015355C,
            0x1015356C,
            0x10153560,
            0x10153564,
            0x10153568,
        ),
    ),
}


class _VCIB:
    def __init__(self, block: VCIBBlock, context: TYContext, comm: TYComm):
        self.block, self.context, self.comm = block, context, comm
        self.host = block.host
        self.layout = _VCIB_LAYOUTS[context.module_sha256]
        self.plus = context.module_sha256 == SHA_PLUS_TY
        block.require(self.layout.log_kind + 4)

    def get(self, field: int) -> int:
        value = self.context.state.get(
            f"native_global:{self.layout.globals[field]:x}", 0
        )
        if type(value) is not int:
            raise ValueError("Native VCIB global is not an integer")
        return value

    def put(self, field: int, value: int) -> None:
        self.context.state[f"native_global:{self.layout.globals[field]:x}"] = (
            value & 0xFFFFFFFF
        )

    def word(self, offset: int, value: int) -> None:
        self.block.data[offset : offset + 2] = (value & 0xFFFF).to_bytes(2, "little")

    def increment(self) -> None:
        offset = self.layout.progress
        self.word(
            offset, int.from_bytes(self.block.data[offset : offset + 2], "little") + 1
        )

    def path(self, offset: int) -> str:
        data = bytes(self.block.data[offset : offset + self.layout.path_size])
        if self.plus:
            end = next(
                (
                    index
                    for index in range(0, len(data), 2)
                    if data[index : index + 2] == b"\0\0"
                ),
                None,
            )
            if end is None:
                raise ValueError("Native wide path is not NUL terminated")
            return data[:end].decode("utf-16-le")
        end = data.find(b"\0")
        if end < 0:
            raise ValueError("Native ANSI path is not NUL terminated")
        return self.host.decode_ansi(data[:end])

    def stamp(self) -> tuple[str, str]:
        year, month, day, hour, minute, second = self.host.local_time()
        date, clock = f"{year:04}{month:02}{day:02}", f"{hour:02}{minute:02}{second:02}"
        self.context.state[f"vcib:{self.context.module_sha256}:date"] = date
        self.context.state[f"vcib:{self.context.module_sha256}:time"] = clock
        date_address, time_address = (
            (0x10153570, 0x10153584) if self.plus else (0x1012AE60, 0x1012AE44)
        )
        encoding, capacity = ("utf-16-le", 32) if self.plus else ("ascii", 12)
        self.context.state[f"native_global:{date_address:x}"] = date.encode(
            encoding
        ).ljust(capacity, b"\0")
        self.context.state[f"native_global:{time_address:x}"] = clock.encode(
            encoding
        ).ljust(capacity, b"\0")
        return date, clock

    def fetch(self, identifier: int, minimum: int, capacity: int) -> tuple[int, bytes]:
        # 18 cb0a0 ASM and plus d6e60: actual bounded payload length, not the decompiler's -3.
        _check(
            self.context
        )  # Host forced-termination boundary before another native packet.
        allocation = self.host.allocate(0x8000003)
        if allocation is None:
            return 3, b""
        try:
            did = identifier.to_bytes(2, "big")
            status, reply = self.comm.exchange(b"\x22" + did)
            if status:
                return status, b""
            if len(reply) < minimum + 3 or reply[1:3] != did:
                return 3, b""
            return 0, reply[3 : 3 + capacity]
        finally:
            self.host.release(allocation)

    def write_file(self, identifier: int, payload: bytes) -> bool:
        date = self.context.state.get(f"vcib:{self.context.module_sha256}:date")
        clock = self.context.state.get(f"vcib:{self.context.module_sha256}:time")
        if not isinstance(date, str) or not isinstance(clock, str):
            raise TypeError("VCIB export start timestamp is missing")
        directory = self.path(self.layout.directory)
        extension = ".dat" if self.block.u32(0) == 2 else ".tgz"
        name = directory + date + clock + f"_{identifier & 0xFFFF:04X}" + extension
        try:
            self.host.mkdir(self.path(4))
            self.host.mkdir(directory)
            return self.host.write(name, payload) == len(payload)
        except OSError:
            return False

    def store(self, identifier: int, payload: bytes, field: int) -> int:
        for _ in range(3):
            if self.write_file(identifier, payload):
                self.put(0, self.get(0) + len(payload))
                self.put(field, 1)
                return 0
            if self.host.free_space(self.path(self.layout.directory)) <= len(payload):
                self.put(3, 1)
                return 2004
        # Native exhausts three unsuccessful writes with enough free space and proceeds.
        return 0

    def start(self) -> int:
        for field in (0, 1, 2, 3):
            self.put(field, 0)
        status = _extended(self.comm)
        if status:
            return status
        for field in (4, 5, 6, 7, 8):
            self.put(field, 0)
        self.word(self.layout.progress, 0)
        self.word(self.layout.total, 0)
        self.stamp()
        second_status, second = self.fetch(0x1B01, 1, 1)
        first_status, first = self.fetch(0x1A01, 1, 1)
        a = min(first[0], 60) if first else 0
        b = min(second[0], 60) if second else 0
        self.block.data[self.layout.primary : self.layout.primary + 2] = bytes((a, b))
        self.word(self.layout.total, a + b)
        if second_status and (first_status or a == 0):
            _normal(self.comm)
            return 2001
        if not b:
            if first_status or not a:
                _normal(self.comm)
                return 2002
        elif first_status or not a:
            self.put(1, 2100)
            return 0
        if second_status:
            self.put(1, 2101)
        return 0

    def primary(self) -> int:
        allocation = self.host.allocate(0x400000)
        if allocation is None:
            return 3
        status = 0
        index = 2
        end = self.block.data[self.layout.primary] + 2
        try:
            while index < end:
                status, data = self.fetch(0x1A00 + index, 1, 0x400000)
                if status:
                    self.word(
                        self.layout.progress, self.block.data[self.layout.primary]
                    )
                    return (
                        0  # Native partial primary collection does not fail the export.
                    )
                self.increment()
                status = self.store(0x1A00 + index, data, 4)
                if status:
                    _normal(self.comm)
                    return status
                index += 1
            if index == end:
                self.put(7, 1)
            return 0
        finally:
            self.host.release(allocation)

    def secondary(self) -> int:
        allocation = self.host.allocate(0x400000)
        if allocation is None:
            status = 2001 if not (self.get(4) or self.get(5)) else 2000
            if status == 2000:
                self.put(2, 1)
            _normal(self.comm)
            return status
        try:
            if self.get(1) != 2101 and self.block.data[self.layout.primary + 1]:
                for index in range(2, self.block.data[self.layout.primary + 1] + 2):
                    status, data = self.fetch(0x1B00 + index, 1, 0x400000)
                    if status:
                        break
                    self.increment()
                    status = self.store(0x1B00 + index, data, 5)
                    if status:
                        _normal(self.comm)
                        return status
                else:
                    self.put(2, 1)
                    return 0
                status = 2000 if self.get(4) or self.get(5) else 2001
            elif self.get(1) == 2101:
                status = 2000 if self.get(4) or self.get(5) else 2001
            else:
                status = 2000 if self.get(4) or self.get(5) else 2002
            if status == 2000:
                self.put(2, 1)
            _normal(self.comm)
            return status
        finally:
            self.host.release(allocation)

    def dates(self, payload: bytes) -> None:
        # 18 cb2c0 (32-bit CRT time);plus d5e00 (64-bit CRT time), full1000 records.
        from calendar import monthrange

        layout, data = self.layout, self.block.data
        if len(payload) < 6000:
            raise ValueError("Native VCIB timestamp table requires6000 bytes")
        data[layout.flags : layout.flags + 1000] = bytes(1000)
        data[layout.dates : layout.dates + 6000] = bytes(6000)
        self.block.put32(layout.count, 0)
        start = (
            (data[layout.start] + 2000) * 10000
            + data[layout.start + 1] * 100
            + data[layout.start + 2]
        )
        end = (
            (data[layout.start + 3] + 2000) * 10000
            + data[layout.start + 4] * 100
            + data[layout.start + 5]
        )
        for index in range(1000):
            record = payload[index * 6 : index * 6 + 6]
            if not any(record):
                continue
            parts = tuple((value >> 4) * 10 + (value & 15) for value in record)
            year, month, day, hour, minute, second = (2000 + parts[0], *parts[1:])
            if not (
                2000 <= year < 2100
                and 1 <= month <= 12
                and 1 <= day <= 31
                and hour < 24
                and minute < 60
                and second < 60
            ):
                continue
            if day > monthrange(year, month)[1]:
                continue
            local = self.host.mktime((year, month, day, hour, minute, second))
            if not self.plus:
                local = ((local + 0x80000000) & 0xFFFFFFFF) - 0x80000000
            utc_as_local = self.host.mktime(self.host.gmtime(local))
            if not self.plus:
                utc_as_local = ((utc_as_local + 0x80000000) & 0xFFFFFFFF) - 0x80000000
            adjusted = 2 * local - utc_as_local
            if not self.plus:
                adjusted = ((adjusted + 0x80000000) & 0xFFFFFFFF) - 0x80000000
            converted = self.host.localtime(adjusted)
            year, month, day, hour, minute, second = converted
            date = year * 10000 + month * 100 + day
            if start <= date <= end:
                data[layout.flags + index] = 1
                offset = layout.dates + index * 6
                data[offset : offset + 6] = bytes(
                    ((year - 2000) & 255, month, day, hour, minute, second)
                )
                self.block.put32(layout.count, self.block.u32(layout.count) + 1)
                self.put(9, 1)

    def date_table(self) -> int:
        layout = self.layout
        self.block.data[layout.flags : layout.flags + 1000] = bytes(1000)
        allocation = self.host.allocate(6000)
        if allocation is None:
            return 3
        self.put(9, 0)
        self.put(6, 0)
        self.word(layout.progress, 0)
        self.word(layout.total, 0)
        entered = False
        try:
            status = _extended(self.comm)
            if status:
                return status
            entered = True
            status, data = self.fetch(0x1C01, 6000, 6000)
            if status:
                return 2001
            self.dates(data)
            return 0 if self.get(9) else 2003
        finally:
            self.host.release(allocation)
            if entered:
                _normal(self.comm)

    def trace(self) -> int:
        allocation = self.host.allocate(0x8000000)
        if allocation is None:
            return 3
        for field in (0, 2, 3):
            self.put(field, 0)
        self.stamp()
        complete = False
        try:
            for index in range(1000):
                value = 0x1C04 + index
                if self.block.data[self.layout.selected + index] == 0:
                    continue
                identifier = (
                    value - 2
                    if value - 2 <= 0x1CFF
                    else value - 1
                    if value - 1 <= 0x1DFF
                    else value
                    if value <= 0x1EFF
                    else value + 1
                )
                status, data = self.fetch(identifier, 1, 0x8000000)
                if status:
                    if self.get(6):
                        self.put(2, 1)
                        return 2000
                    return 2001
                self.increment()
                status = self.store(identifier, data, 6)
                if status:
                    return status
            complete = True
            self.put(2, 1)
            return 0
        finally:
            self.host.release(allocation)
            if not complete:
                _normal(self.comm)

    def _zip_name(self) -> str:
        year, month, day, hour, minute, _ = self.host.local_time()
        kind = "eventlog" if self.block.u32(self.layout.log_kind) == 1 else "tracelog"
        name = f"{year:04}{month:02}{day:02}{hour:02}{minute:02}_{kind}.zip"
        encoded = name.encode("utf-16-le" if self.plus else "ascii")
        capacity = 60 if self.plus else 30
        if len(encoded) >= capacity:
            raise ValueError("Native VCIB ZIP name exceeds capacity")
        offset = self.layout.zip_name
        self.block.data[offset : offset + capacity] = encoded.ljust(capacity, b"\0")
        return name

    def archive_plus(self) -> int:
        # ReplaceFromLegasy.dll8969d835 Alt_VCIB_02_CreateZip/Compress IL, not a COM callback.
        directory = (
            self.host.common_application_data() + "\\GTSPlus\\InterfaceBoxLogFile"
        )
        path = directory + "\\" + self._zip_name()
        suffix = ".DAT" if self.block.u32(self.layout.log_kind) == 1 else ".TGZ"
        files = self.host.files(directory, suffix)
        if not files:
            return 2001
        free = self.host.free_space(directory)
        if sum(len(self.host.read(name)) for name in files) > free:
            return 2004
        status = 0
        for _ in range(3):
            handle = None
            try:
                handle = self.host.zip_open(path, update=True)
                for name in files:
                    self.host.zip_add(
                        handle, name, name.replace("\\", "/").rsplit("/", 1)[-1]
                    )
                status = 0
            except OSError:
                status = 2001
            finally:
                if handle is not None:
                    try:
                        self.host.zip_close(handle)
                    except OSError:
                        status = 2001
            if status == 0:
                break
            try:
                self.host.delete(path)
            except OSError:
                status = 2001
        return status

    def archive18(self) -> int:
        # cb700 actual shell ZIP count polling: at most6 waits400ms for each entry,3 outer attempts.
        directory = self.path(self.layout.directory)
        path = directory + self._zip_name()
        try:
            if self.host.write(path, b"PK\x05\x06" + bytes(18)) != 22:
                raise OSError("Native empty ZIP write failed")
            handle = self.host.zip_open(path, update=False)
        except OSError:
            try:
                self.host.delete(path)
            except OSError:
                pass
            return 2001
        any_file = False
        failed = False
        status = 0
        date = self.context.state.get(f"vcib:{self.context.module_sha256}:date")
        clock = self.context.state.get(f"vcib:{self.context.module_sha256}:time")
        if not isinstance(date, str) or not isinstance(clock, str):
            self.host.zip_close(handle)
            raise TypeError("Native archive collection timestamp is absent")
        identifiers = (
            tuple(0x1A00 + index for index in range(2, 62))
            + tuple(0x1B00 + index for index in range(2, 62))
            if self.block.u32(self.layout.log_kind) == 1
            else tuple(range(0x1C02, 0x1FED))
        )
        suffix = ".dat" if self.block.u32(self.layout.log_kind) == 1 else ".tgz"
        try:
            for _ in range(3):
                for identifier in identifiers:
                    name = f"{date}{clock}_{identifier:04X}{suffix}"
                    source = directory + name
                    if not self.host.exists(source):
                        continue
                    old_count = self.host.zip_count(handle)
                    self.host.zip_add(handle, source, name, shell_flags=0x414)
                    for _ in range(6):
                        _sleep(self.context, 400)
                        if self.host.zip_count(handle) > old_count:
                            any_file = True
                            break
                        _check(
                            self.context
                        )  # Host termination replaces native forced worker exit.
                    else:
                        failed = True
                        break
                if any_file or failed:
                    break
                if self.host.free_space(directory) <= self.get(0):
                    status = 2004
                    self.put(3, 1)
                    break
        finally:
            self.host.zip_close(handle)
        if not any_file or failed:
            try:
                self.host.delete(path)
            except OSError:
                pass
            return status if status else 2001
        return status

    def cleanup(self) -> None:
        directory = self.path(self.layout.directory)
        for suffix in (".dat", ".tgz"):
            for name in self.host.files(directory, suffix):
                try:
                    self.host.delete(name)
                except OSError:
                    pass  # Native DeleteFile failures are ignored.

    def run(self) -> int:
        action = self.block.u32(0)
        status = 0
        keep = False
        try:
            if action not in (2, 4, 6):
                status = _open(self.comm)
            if status == 0:
                if action == 0:
                    status = _extended(self.comm)
                    if status == 0:
                        try:
                            for identifier, offset, mask in (
                                (0x0101, 3, 0x38),
                                (0x1A00, 0, 0x80),
                                (0x1B00, 0, 0x80),
                                (0x1C00, 0, 0x80),
                            ):
                                status, payload = self.fetch(identifier, 32, 32)
                                if status:
                                    break
                                if payload[offset] & mask != mask:
                                    status = 3
                                    break
                        finally:
                            _normal(self.comm)
                elif action == 1:
                    status = self.start()
                    keep = status == 0
                elif action == 2:
                    if self.get(1) in (0, 2101):
                        status = self.primary()
                    if status == 0:
                        status = self.secondary()
                    keep = status == 0
                elif action == 3:
                    status = self.date_table()
                elif action == 4:
                    status = self.trace()
                    keep = status == 0
                elif action == 5:
                    status = _extended(self.comm)
                    if status == 0:
                        selected = self.block.data[
                            self.layout.selected : self.layout.selected + 1001
                        ]
                        self.word(
                            self.layout.total, sum(value == 1 for value in selected)
                        )
                        keep = True
                elif action == 6:
                    self.put(8, 1)
                    _normal(self.comm)
                    if self.block.u32(self.layout.log_kind) == 1 and not self.get(7):
                        status = 2000
        finally:
            if not keep:
                self.comm.finalize()
        if not keep:
            if self.get(2):
                zipped = self.archive_plus() if self.plus else self.archive18()
                if zipped:
                    status = zipped
                self.put(2, 0)
                self.put(3, 1)
            if self.get(3):
                self.cleanup()
                self.put(3, 0)
        return status
