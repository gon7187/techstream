"""Exact-source retained TY FSR/HNCSN/BCM/AVS/SBW business bodies.

Source branch review and concrete lower composition remain separately gated.
"""

from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass
from fractions import Fraction

from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import (
    SHA_12_TY,
    SHA_18_TY,
    SHA_PLUS_TY,
    TYComm,
    TYContext,
    TYSourceError,
)


class TYUndefinedNativeState(TYSourceError):
    """A source stack-local value needs an explicit observation, never a guessed zero."""


class NativeTYArithmeticFault(ArithmeticError):
    """An unmasked native floating-point invalid operation."""


class NativeTYMemoryFault(ValueError):
    """A native UI/stack access escapes its supplied allocation."""


HNCSN_EXPORTS = (
    "Ex2HNCSN_01_TransitionToNormalMode",
    "Ex2HNCSN_01_WriteNeutralPosition",
    "Ex2HNCSN_01_EcuCal",
    "Ex2HNCSN_01_InitStatusOfSensor",
    "Ex2HNCSN_01_WriteAngleOfSensor",
    "Ex2HNCSN_01_SupportCheck",
    "Ex2HNCSN_01_WriteAngleOfRrSensor",
    "Ex2HNCSN_01_WriteBumperType",
)

BCM_EXPORTS = ("Ex2BCM_01_SendMessage", "Ex2BCM_02_SendMessage")
BCM_DIDS = (
    bytes(range(0x90, 0xBA)) + bytes(range(0xD1, 0xE0)) + bytes(range(0xE1, 0xE4))
)

FSR_EXPORTS = (
    "Ex2FSR_01_02_SupportCheck",
    "Ex2FSR_03_04_SupportCheck",
    "Ex2FSR_05_06_SupportCheck",
    "Ex2FSR_05_06_GetAbnormalHistory",
    "Ex2FSR_05_06_ClearAbnormalHistory",
    "Ex2FSR_01_02_ActiveTest",
    "Ex2FSR_03_04_ActiveTest",
)

EXPORTS = (
    "Ex2AVS_01_SendMessage",
    "Ex2AVS_02_SendMessage",
    "Ex2SBW_01_ActPositionLearningResult",
    "Ex2SBW_01_StartActPositionLearning",
)


@dataclass(frozen=True)
class Contract:
    source_sha256: str
    manager: str
    setters: tuple[str, str, str]
    timed_fsr: bool = False


CONTRACTS = {
    SHA_12_TY: Contract(
        SHA_12_TY,
        "native:100aed50",
        ("native_rva:12960", "native_rva:12980", "native_rva:129d0"),
        True,
    ),
    SHA_18_TY: Contract(
        SHA_18_TY,
        "native:1011d4f0",
        ("native_rva:1a860", "native_rva:1a880", "native_rva:1a8c0"),
    ),
    SHA_PLUS_TY: Contract(
        SHA_PLUS_TY,
        "native:101392d0",
        ("native_rva:1e290", "native_rva:1e2b0", "native_rva:1e2d0"),
    ),
}


def supported_exports(module_sha256: str) -> tuple[str, ...]:
    if module_sha256 not in CONTRACTS:
        return ()
    if module_sha256 == SHA_12_TY:
        return FSR_EXPORTS + BCM_EXPORTS
    return (
        FSR_EXPORTS
        + BCM_EXPORTS
        + EXPORTS
        + (HNCSN_EXPORTS if module_sha256 == SHA_PLUS_TY else HNCSN_EXPORTS[:6])
    )


def _word(data: bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


class Engine:
    def __init__(self, contract: Contract):
        self.contract = contract

    @staticmethod
    def _check(context: TYContext) -> None:
        if context.is_cancelled():
            raise Cancelled("retained TY worker cancelled")

    def _exchange(
        self,
        context: TYContext,
        comm: TYComm,
        request: bytes,
        minimum: int = 0,
        echo: int | None = None,
    ) -> tuple[int, bytes]:
        self._check(context)
        status, reply = comm.exchange(request)
        if type(status) is not int or not isinstance(reply, bytes):
            raise TypeError("native exchange requires (int, bytes)")
        if status:
            return status, reply
        if len(reply) > 0x1020:
            raise NativeTYMemoryFault("native response exceeds 0x1020-byte allocation")
        # Native helpers compare echoed arguments, not the response SID.
        memory = reply.ljust(0x1020, b"\0")
        if (
            len(reply) < minimum
            or memory[1 : 1 + (len(request) - 1 if echo is None else echo)]
            != request[1 : 1 + (len(request) - 1 if echo is None else echo)]
        ):
            return 3, memory
        return 0, memory

    def _open(self, comm: TYComm) -> int:
        status = comm.initialize(0)
        if not status:
            for field, value in zip(self.contract.setters, (0, 180000, 0), strict=True):
                comm.configure(field, value)
        return status

    def _hncsn_normal(
        self, context: TYContext, selected: TYComm, force: bool = True
    ) -> int:
        manager = context.comm(self.contract.manager)
        setters = (
            ("1a860", "1a880", "1b7e0", "1a8d0", "1b7b0", "1a8c0", "1a8e0")
            if self.contract.source_sha256 != SHA_PLUS_TY
            else ("1e290", "1e2b0", "1e300", "1e2e0", "1e330", "1e2d0", "1e320")
        )
        if force:
            for name, value in zip(setters, (1, 0, 1, 0, 1, 1, 1), strict=True):
                manager.configure("native_rva:" + name, value)
        try:
            self._check(context)
            status, reply = selected.exchange(b"\x10\1")
            if len(reply) > 0x1020:
                raise NativeTYMemoryFault("HNCSN normal response escapes native stack")
            return 3 if not status and len(reply) != 1 else status
        finally:
            if force:
                for name, value in zip(
                    setters, (150, 180000, 255, 0, 3, 3, 0), strict=True
                ):
                    manager.configure("native_rva:" + name, value)

    def _hncsn_support_fields(
        self, data: bytearray, context: TYContext, comm: TYComm
    ) -> int:
        from scripts.utility_ex_ty_chassis import _support_record, _support_required

        plus = self.contract.source_sha256 == SHA_PLUS_TY
        status, raw, offsets = comm.support_snapshot(1)
        if status:
            if not plus:
                struct.pack_into("<II", data, 0, 0x100DA9BC, 0x100DA9BC)
                return status
            raise TYUndefinedNativeState(
                "Plus HNCSN support publishes undefined stack locals on snapshot error"
            )
        for identifier, mask in ((0x41, 0xC0), (0x3F, 0x7F)):
            status, _ = _support_required(raw, offsets, identifier, 3, mask)
            if status:
                if not plus:
                    struct.pack_into("<II", data, 0, 0x100DA9BC, 0x100DA9BC)
                    return status
                raise TYUndefinedNativeState(
                    "Plus HNCSN support publishes undefined stack locals on predicate failure"
                )
        _, payload = _support_record(raw, offsets, 0x3A)
        selected = 0xFFFFFFFF
        # The ignored predicate still writes a position before its mask check.
        if len(payload) >= 4:
            selected = 2 + sum(bool(value) for value in payload[:3])
        struct.pack_into("<I", data, 8 if plus else 4, selected)
        struct.pack_into("<I", data, 0, sum(bool(value) for value in payload) + 2)
        if plus:
            status, selected = _support_required(raw, offsets, 0x28, 7, 15)
            struct.pack_into("<I", data, 12, 0xFFFFFFFF if status else selected)
            _, payload = _support_record(raw, offsets, 0x28)
            struct.pack_into("<I", data, 4, sum(bool(value) for value in payload) + 2)
        status, raw, offsets = comm.support_snapshot(3)
        if status:
            raise TYUndefinedNativeState(
                "HNCSN command support publishes undefined native locals on snapshot error"
            )
        for identifier, mask in ((1, 64), (0x41, 192)):
            status, _ = _support_required(raw, offsets, identifier, 3, mask)
            if status:
                raise TYUndefinedNativeState(
                    "HNCSN command support publishes undefined native locals on predicate failure"
                )
        base = 16 if plus else 8
        for index, identifier in enumerate(
            (1, 0x41, 0x34, 0x3E) + ((0x43,) if plus else ())
        ):
            offset = offsets[identifier]
            if offset + 1 >= 0x1020:
                raise NativeTYMemoryFault(
                    "HNCSN support length accesses absent native record"
                )
            struct.pack_into("<I", data, base + 4 * index, raw[offset + 1] + 2)
        for offset, identifier, index, mask in (
            (36 if plus else 24, 0x3E, 5, 192),
            (40 if plus else 28, 1, 3, 128),
        ):
            status, _ = _support_required(raw, offsets, identifier, index, mask)
            struct.pack_into("<I", data, offset, int(status == 0))
        if plus and _word(data, 12) != 0xFFFFFFFF:
            status, reply = self._exchange(context, comm, b"\x21\x28", _word(data, 4))
            if status:
                return status
            index = _word(data, 12)
            if index >= 0x1020:
                raise NativeTYMemoryFault("HNCSN bumper type read escapes native stack")
            value = reply[index] & 15
            if value not in (0, 2):
                return 99
            struct.pack_into("<I", data, 116, 4 if value == 0 else 8)
        return 0

    def _hncsn_support(self, data: bytearray, context: TYContext, comm: TYComm) -> int:
        try:
            status = comm.initialize(0)
            if status:
                return status
            comm.configure(
                "native_rva:142f0"
                if self.contract.source_sha256 == SHA_PLUS_TY
                else "native_rva:12180",
                150,
            )
            return self._hncsn_support_fields(data, context, comm)
        finally:
            comm.finalize()

    @staticmethod
    def _angle_byte(value: float, context: TYContext, plus: bool) -> int:
        from scripts.utility_ex_ty_retained_07 import _binary

        if plus:
            control = context.state.get("host:mxcsr")
            if type(control) is not int or not 0 <= control <= 0xFFFF:
                raise TYSourceError(
                    "HNCSN SSE angle conversion requires explicit host MXCSR"
                )
            precision, rounding, maximum = 53, (control >> 13) & 3, 2147483648
            invalid_masked = bool(control & 128)
            if (
                math.isfinite(value)
                and value
                and abs(value) < 2.0**-1022
                and control & 64
            ):
                value = 0.0
        else:
            control = context.state.get("host:x87_control_word")
            if type(control) is not int or not 0 <= control <= 0xFFFF:
                raise TYSourceError(
                    "HNCSN angle conversion requires explicit host x87 control word"
                )
            precision = {0: 24, 2: 53, 3: 64}.get((control >> 8) & 3)
            if precision is None:
                raise TYSourceError("Reserved x87 precision control")
            rounding, maximum = (control >> 10) & 3, 9223372036854775808
            invalid_masked = bool(control & 1)
        scaled = (
            _binary(Fraction.from_float(value) * 10, precision, rounding)
            if math.isfinite(value)
            else value
        )
        if (
            plus
            and control & 32768
            and scaled
            and abs(scaled) < Fraction.from_float(2.0**-1022)
        ):
            scaled = Fraction(0)
        invalid = not math.isfinite(value) or abs(scaled) >= maximum
        if invalid and not invalid_masked:
            raise NativeTYArithmeticFault("Unmasked HNCSN native integer conversion")
        truncated = -maximum if invalid else int(abs(scaled))
        negative = (math.isnan(value) and not plus) or scaled <= 0
        return (truncated + (128 if negative else 0)) & 255

    def _hncsn_stage(
        self, data: bytearray, stage: int, context: TYContext, comm: TYComm
    ) -> int:
        if self.contract.source_sha256 == SHA_PLUS_TY:
            flags = data[44]
            if stage < 2 and flags & 13:
                return 1000
            if stage < 3 and _word(data, 36) and flags & 5:
                return 1001
            if (
                stage < 4
                and _word(data, 12) != 0xFFFFFFFF
                and _word(data, 116) == 8
                and flags & 9
            ):
                return 1006
            if stage <= 4 and _word(data, 40) and flags & 3:
                return 1002
            self._hncsn_normal(context, comm, force=False)
            return 0
        flags = data[32]
        if stage == 0 and flags & 5:
            return 1000
        if stage < 2 and _word(data, 24) and flags & 5:
            return 1001
        if stage < 3 and _word(data, 28) and flags & 3:
            return 1002
        self._hncsn_normal(context, comm, force=False)
        return 0

    def _hncsn_write(
        self,
        prefix: bytes,
        length: int,
        context: TYContext,
        comm: TYComm,
        *,
        angle: bool = False,
    ) -> int:
        if length > 0x1020:
            raise NativeTYMemoryFault("HNCSN padded request escapes native stack")
        if angle and length > 256:
            return 22
        request = prefix.ljust(0x1020, b"\0")[:length]
        # Only the identifier, not the complete write payload, is echoed.
        self._check(context)
        status, reply = comm.exchange(request)
        if len(reply) > 0x1020:
            raise NativeTYMemoryFault("HNCSN write response escapes native stack")
        return 3 if not status and (len(reply) < 2 or reply[1] != prefix[1]) else status

    def _hncsn_sensor(self, context: TYContext, comm: TYComm) -> tuple[int, int]:
        status, reply = self._exchange(context, comm, b"\x21\x41", 3)
        return status, (0, 1, 16, 17)[reply[2] >> 6] if not status else 0

    def _hncsn_read_bumper(
        self, data: bytearray, context: TYContext, comm: TYComm
    ) -> tuple[int, bool]:
        self._check(context)
        status, reply = comm.exchange(b"\x21\x3f")
        if status:
            return status, False
        length = len(reply)
        if length > 0x1020:
            raise NativeTYMemoryFault("HNCSN response escapes native allocation")
        if length < 3 or reply[1] != 0x3F:
            return 3, False
        if 120 + length > len(data):
            raise NativeTYMemoryFault(
                "HNCSN readback memcpy escapes caller UI allocation"
            )
        data[120 : 120 + length] = reply[:length]
        return 0, not (reply[2] & 127)

    def _hncsn_calibration_plus(
        self, export: str, data: bytearray, context: TYContext, comm: TYComm
    ) -> int:
        def forced() -> None:
            self._hncsn_normal(context, comm)

        def sensors() -> tuple[int, int, int]:
            status, reply = self._exchange(context, comm, b"\x21\x41", 3)
            if status:
                return status, 0, 0
            states = (0, 1, 16, 17)
            return 0, states[reply[2] >> 6], states[(reply[2] >> 4) & 3]

        if export == HNCSN_EXPORTS[7]:
            choice = _word(data, 112)
            desired = (choice if choice in (1, 2, 3) else 4) | (data[122] & 128)
            data[122] = desired
        try:
            status = comm.initialize(0)
            if status:
                return status
            comm.configure("native_rva:142f0", 150)
            if export == HNCSN_EXPORTS[7]:
                status, _ = self._exchange(
                    context, comm, bytes((0x3B, 0x3F, desired)), 2, 1
                )
                if not status:
                    status, _ = self._hncsn_read_bumper(data, context, comm)
                if status:
                    forced()
                    return status
                if (data[122] ^ desired) & 127:
                    forced()
                    return 99
                return self._hncsn_stage(data, 1, context, comm)
            if export == HNCSN_EXPORTS[2]:
                self._check(context)
                status, reply = comm.exchange(b"\x10\x74\1")
                if len(reply) > 0x1020:
                    raise NativeTYMemoryFault(
                        "HNCSN session response escapes native stack"
                    )
                if not status and len(reply) != 1:
                    status = 3
                if status:
                    forced()
                    return status
                start = context.ticks()
                status, done = self._hncsn_read_bumper(data, context, comm)
                if status:
                    forced()
                    return status
                while not done:
                    context.native_sleep(500)
                    status, front, rear = sensors()
                    if status:
                        forced()
                        return status
                    if front and (
                        _word(data, 12) == 0xFFFFFFFF or _word(data, 116) != 8 or rear
                    ):
                        break
                    if (context.ticks() - start) & 0xFFFFFFFF >= 10000:
                        forced()
                        return 99
                if data[44] & 1:
                    status = self._hncsn_write(
                        b"\x3b\1\x40", _word(data, 16), context, comm
                    )
                    if not status:
                        status = self._hncsn_support_fields(data, context, comm)
                    if status:
                        forced()
                        return status
                    if _word(data, 12) != 0xFFFFFFFF and _word(data, 116) == 8:
                        return 1005
                return self._hncsn_stage(data, 0, context, comm)
            if export == HNCSN_EXPORTS[3]:
                status, front, rear = sensors()
                if status:
                    forced()
                    return status
                rear_enabled = _word(data, 12) != 0xFFFFFFFF and _word(data, 116) == 8
                if front or (rear_enabled and rear):
                    flags = data[44] & 13
                    choice = (
                        21
                        if _word(data, 12) == 0xFFFFFFFF
                        or _word(data, 116) == 4
                        or flags == 4
                        else 69
                        if flags == 8
                        else 5
                    )
                    status, _ = self._exchange(
                        context, comm, bytes((0x3B, 0x41, choice)), 2, 1
                    )
                    if status:
                        forced()
                        return status
                start = context.ticks()
                while True:
                    context.native_sleep(500)
                    status, front, rear = sensors()
                    if status:
                        forced()
                        return status
                    if front == 1 and (not rear_enabled or rear == 1):
                        return self._hncsn_stage(data, 2, context, comm)
                    active = rear if front == 1 and rear_enabled else front
                    if active or (context.ticks() - start) & 0xFFFFFFFF >= 10000:
                        forced()
                        return 99
            rear = export == HNCSN_EXPORTS[6]
            encoded = bytearray()
            for offset in range(80 if rear else 48, 112 if rear else 80, 8):
                value = struct.unpack_from("<d", data, offset)[0]
                encoded.append(self._angle_byte(value, context, True))
            status = self._hncsn_write(
                bytes((0x3B, 0x43 if rear else 0x34)) + encoded,
                _word(data, 32 if rear else 24),
                context,
                comm,
                angle=True,
            )
            if not status:
                status = self._hncsn_write(
                    bytes((0x3B, 0x3E, 0, 32, 48 if rear else 192)),
                    _word(data, 28),
                    context,
                    comm,
                )
            if status:
                forced()
                return status
            start = context.ticks()
            while True:
                context.native_sleep(500)
                index = _word(data, 8)
                if index == 0xFFFFFFFF:
                    status, decoded = 22, 0
                else:
                    status, reply = self._exchange(
                        context, comm, b"\x21\x3a", _word(data, 0)
                    )
                    if index + 1 >= 0x1020:
                        raise NativeTYMemoryFault(
                            "HNCSN angle index escapes native stack"
                        )
                    shifts = (2, 0) if rear else (6, 4)
                    values = (
                        [
                            (reply[index + i] >> shift) & 3
                            for i in (0, 1)
                            for shift in shifts
                        ]
                        if not status
                        else []
                    )
                    decoded = (
                        1
                        if values == [1] * 4
                        else 17
                        if 3 in values
                        else 16
                        if 2 in values
                        else 0
                    )
                if status:
                    forced()
                    if status != 1004:
                        forced()
                    return status
                if decoded == 1:
                    return self._hncsn_stage(data, 4 if rear else 3, context, comm)
                if decoded == 16:
                    return 1004
                if decoded == 17 or (context.ticks() - start) & 0xFFFFFFFF >= 12000:
                    forced()
                    return 99
        finally:
            comm.finalize()

    def _hncsn_calibration18(
        self, export: str, data: bytearray, context: TYContext, comm: TYComm
    ) -> int:
        def forced() -> None:
            self._hncsn_normal(context, comm)

        try:
            status = comm.initialize(0)
            if status:
                return status
            comm.configure("native_rva:12180", 150)
            if export == HNCSN_EXPORTS[2]:
                self._check(context)
                status, reply = comm.exchange(b"\x10\x74\1")
                if len(reply) > 0x1020:
                    raise NativeTYMemoryFault(
                        "HNCSN session response escapes native stack"
                    )
                if not status and len(reply) != 1:
                    status = 3
                if status:
                    forced()
                    return status
                start = context.ticks()
                status, reply = self._exchange(context, comm, b"\x21\x3f", 3)
                if status:
                    forced()
                    return status
                done = not (reply[2] & 127)
                while not done:
                    context.native_sleep(500)
                    status, sensor = self._hncsn_sensor(context, comm)
                    if status:
                        forced()
                        return status
                    if sensor:
                        break
                    if (context.ticks() - start) & 0xFFFFFFFF >= 10000:
                        forced()
                        return 99
                if data[32] & 1:
                    status = self._hncsn_write(
                        b"\x3b\1\x40", _word(data, 8), context, comm
                    )
                    if status:
                        forced()
                        return status
                return self._hncsn_stage(data, 0, context, comm)
            if export == HNCSN_EXPORTS[3]:
                status, sensor = self._hncsn_sensor(context, comm)
                if status:
                    forced()
                    return status
                if sensor:
                    status, _ = self._exchange(context, comm, b"\x3b\x41\x15", 2, 1)
                    if status:
                        forced()
                        return status
                start = context.ticks()
                while True:
                    context.native_sleep(500)
                    status, sensor = self._hncsn_sensor(context, comm)
                    if status:
                        forced()
                        return status
                    if sensor == 1:
                        return self._hncsn_stage(data, 1, context, comm)
                    if sensor or (context.ticks() - start) & 0xFFFFFFFF >= 10000:
                        forced()
                        return 99
            encoded = bytearray()
            for offset in range(40, 72, 8):
                value = struct.unpack_from("<d", data, offset)[0]
                encoded.append(self._angle_byte(value, context, False))
            status = self._hncsn_write(
                b"\x3b\x34" + encoded, _word(data, 16), context, comm, angle=True
            )
            if not status:
                status = self._hncsn_write(
                    b"\x3b\x3e\0\x20\xc0", _word(data, 20), context, comm
                )
            if status:
                forced()
                return status
            start = context.ticks()
            while True:
                context.native_sleep(500)
                index = _word(data, 4)
                if index == 0xFFFFFFFF:
                    status, decoded = 22, 0
                else:
                    status, reply = self._exchange(
                        context, comm, b"\x21\x3a", _word(data, 0)
                    )
                    if index + 1 >= 0x1020:
                        raise NativeTYMemoryFault(
                            "HNCSN angle status index escapes native stack"
                        )
                    values = (
                        [
                            (reply[index + i] >> shift) & 3
                            for i in (0, 1)
                            for shift in (6, 4)
                        ]
                        if not status
                        else []
                    )
                    decoded = (
                        1
                        if values == [1] * 4
                        else 17
                        if 3 in values
                        else 16
                        if 2 in values
                        else 0
                    )
                if status:
                    forced()
                    if status != 1004:
                        forced()
                    return status
                if decoded == 1:
                    return self._hncsn_stage(data, 2, context, comm)
                if decoded == 16:
                    return 1004
                if decoded == 17 or (context.ticks() - start) & 0xFFFFFFFF >= 12000:
                    forced()
                    return 99
        finally:
            comm.finalize()

    def _hncsn_neutral(self, data: bytearray, context: TYContext, comm: TYComm) -> int:
        try:
            status = comm.initialize(0)
            if status:
                return status
            plus = self.contract.source_sha256 == SHA_PLUS_TY
            comm.configure("native_rva:142f0" if plus else "native_rva:12180", 150)
            length = _word(data, 16 if plus else 8)
            if length > 0x1020:
                raise NativeTYMemoryFault("HNCSN neutral request exceeds native stack")
            self._check(context)
            status, reply = comm.exchange(b"\x3b\1\x80".ljust(0x1020, b"\0")[:length])
            if len(reply) > 0x1020:
                raise NativeTYMemoryFault("HNCSN neutral response escapes native stack")
            if not status and (len(reply) < 2 or reply[1] != 1):
                status = 3
            self._hncsn_normal(context, comm, force=bool(status))
            return status
        finally:
            comm.finalize()

    def _hncsn_transition(self, context: TYContext, comm: TYComm) -> int:
        try:
            status = comm.initialize(0)
            if not status:
                comm.configure(
                    "native_rva:142f0"
                    if self.contract.source_sha256 == SHA_PLUS_TY
                    else "native_rva:12180",
                    150,
                )
                self._hncsn_normal(context, comm)
            return 1003
        finally:
            comm.finalize()

    def _bcm(
        self, export: str, data: bytearray, context: TYContext, comm: TYComm
    ) -> int:
        first = export == BCM_EXPORTS[0]
        width, count = (7, 60) if first else (6, 20)
        try:
            comm.configure_target(0x726, 0, 0, 0, 0)
            status = comm.initialize(0)
            if status:
                return status
            for field, value in zip(
                self.contract.setters[:2], (0, 180000), strict=True
            ):
                comm.configure(field, value)
            status = comm.session(1, 1)
            if status:
                return status
            for index, identifier in enumerate(
                BCM_DIDS if first else range(0xBA, 0xCE)
            ):
                status, reply = self._exchange(
                    context, comm, bytes((0x22, 0xDA, identifier)), width + 3
                )
                if status:
                    return status
                data[index * width : (index + 1) * width] = reply[3 : 3 + width]
            comm.finalize()
            comm.configure_target(0x720, 0, 0, 0, 0)
            status = comm.initialize(0)
            if status:
                return status
            status, reply = self._exchange(context, comm, b"\x22\xdd\0", 7)
            if status:
                return status
            data[count * width : count * width + 4] = reply[3:7]
            for index in range(count):
                base = index * width
                if first:
                    actionable = (
                        data[base + 4 : base + 6] != b"\0\0" and data[base + 6] & 0xFE
                    )
                else:
                    actionable = data[base + 4] & 0xFE and data[base + 5] != 0
                if actionable:
                    return 0
            return 1001
        finally:
            comm.finalize()

    def _fsr_active(
        self, export: str, data: bytearray, context: TYContext, comm: TYComm
    ) -> int:
        second = export == FSR_EXPORTS[6]
        action = 20 if second else 16
        retained = not self.contract.timed_fsr
        selected = 2 if second else 3
        finalize = True

        def raw(request: bytes) -> tuple[int, bytes, int]:
            self._check(context)
            status, reply = comm.exchange(request)
            if len(reply) > 0x1020:
                raise NativeTYMemoryFault("FSR response exceeds native allocation")
            return status, reply.ljust(0x1020, b"\0"), len(reply)

        def poll() -> int:
            status, reply, length = raw(b"\x21\x68")
            if not status:
                expected = _word(data, 4 if second else 0)
                if length != expected or reply[1] != 0x68:
                    return 3
                return 9000 if reply[2] & 128 else 9001
            return status

        def result() -> int:
            status, reply, length = raw(b"\x21\x7b" if second else b"\x21\x6b")
            if status:
                return status
            if length != _word(data, 0 if second else 4) or reply[1] != (
                0x7B if second else 0x6B
            ):
                return 3
            if second:
                offset = _word(data, 12)
                if offset + 1 >= 0x1020:
                    raise NativeTYMemoryFault(
                        "FSR result index escapes native response allocation"
                    )
                data[16:18] = bytes((reply[offset + 1], reply[offset]))
                return 0
            return 0 if reply[2] & 128 else 9001

        try:
            if not retained or _word(data, action) == 0:
                status = comm.initialize(0)
                if status:
                    return status
                setter = {
                    SHA_12_TY: "native_rva:b940",
                    SHA_PLUS_TY: "native_rva:142f0",
                }.get(self.contract.source_sha256, "native_rva:12180")
                comm.configure(setter, 150)
                length = _word(data, 8)
                if length > 0x1020:
                    raise NativeTYMemoryFault(
                        "FSR request length escapes native allocation"
                    )
                request = bytes((0x30, selected, 0, 128)).ljust(0x1020, b"\0")[:length]
                status, reply, received = raw(request)
                if not status and (received != 2 or reply[1] != selected):
                    status = 3
                if retained:
                    if not status:
                        finalize = False
                        return 3406 if second else 1206
                    return 9001
                if status:
                    return 9001
                start = context.ticks()
            while True:
                status = poll()
                if retained and data[action + 4] == 1:
                    break
                if status == 9000:
                    status = result()
                    break
                if status != 9001:
                    break
                if not retained:
                    if (context.ticks() - start) & 0xFFFFFFFF > 5000:
                        break
                    context.native_sleep(500)
            raw(b"\x30")
            return status
        finally:
            if finalize:
                comm.finalize()

    def _fsr(
        self, export: str, data: bytearray, context: TYContext, comm: TYComm
    ) -> int:
        from scripts.utility_ex_ty_chassis import _support_record, _support_required

        try:
            status = comm.initialize(0)
            if status:
                return status
            setter = {
                SHA_12_TY: "native_rva:b940",
                SHA_PLUS_TY: "native_rva:142f0",
            }.get(self.contract.source_sha256, "native_rva:12180")
            comm.configure(setter, 150)
            if export.endswith("SupportCheck"):
                if export == FSR_EXPORTS[2]:
                    groups = (
                        (1, ((0x6C, 3, 0xF8),), ((0x6C, 0, 2),)),
                        (3, ((0x6C, 3, 0xF8),), ((0x6C, 4, 2),)),
                    )
                elif export == FSR_EXPORTS[0]:
                    groups = (
                        (
                            1,
                            ((0x68, 3, 128), (0x6B, 3, 128)),
                            ((0x68, 0, 2), (0x6B, 4, 2)),
                        ),
                        (2, ((3, 3, 128),), ((3, 8, 3),)),
                    )
                else:
                    groups = (
                        (
                            1,
                            ((0x68, 3, 128), (0x7B, 6, 255), (0x7B, 7, 255)),
                            ((0x68, 4, 2), (0x7B, 0, 2)),
                        ),
                        (2, ((2, 3, 128),), ((2, 8, 3),)),
                    )
                for kind, predicates, outputs in groups:
                    self._check(context)
                    status, raw, offsets = comm.support_snapshot(kind)
                    if status:
                        return status
                    for identifier, index, mask in predicates:
                        status, selected = _support_required(
                            raw, offsets, identifier, index, mask
                        )
                        if status:
                            return status
                        if (
                            export == FSR_EXPORTS[1]
                            and identifier == 0x7B
                            and index == 6
                        ):
                            struct.pack_into("<I", data, 12, selected)
                    count = 0
                    for identifier, offset, extra in outputs:
                        result, payload = _support_record(raw, offsets, identifier)
                        # The count helper's return is ignored; the local retains its last count.
                        if not result:
                            count = sum(bool(value) for value in payload)
                        struct.pack_into("<I", data, offset, count + extra)
                return 0
            self._check(context)
            clearing = export.endswith("ClearAbnormalHistory")
            status, reply = comm.exchange(b"\x3b\x6c\0" if clearing else b"\x21\x6c")
            if status:
                return status
            if len(reply) > 0x1020:
                raise NativeTYMemoryFault("FSR response exceeds native allocation")
            memory = reply.ljust(0x1020, b"\0")
            if len(reply) != (2 if clearing else _word(data, 0)) or memory[1] != 0x6C:
                return 3
            if clearing:
                return 9000
            struct.pack_into("<I", data, 8, memory[2])
            return 0
        finally:
            comm.finalize()

    def _sbw(
        self, export: str, data: bytearray, context: TYContext, comm: TYComm
    ) -> int:
        if export.endswith("ActPositionLearningResult"):
            while True:
                self._check(context)
                if _word(data, 4):
                    return 1002
                status, reply = self._exchange(context, comm, b"\x22\x14\x58", 4)
                if status or reply[3] not in (0, 1):
                    if not status and reply[3] != 3:
                        status = 3
                    if status != 1002:
                        comm.session(1, 1)
                        comm.finalize()
                    return status
        status = 0
        if _word(data, 0) == 0:
            status = self._open(comm)
            if not status:
                status = comm.session(1, 1)
                if not status:
                    status = comm.session(3, 1)
                if not status:
                    struct.pack_into("<I", data, 8, 1)
                    context.native_sleep(700)
                    status, _ = self._exchange(context, comm, b"\x31\x01\x11\xf9", 4)
        else:
            while True:
                self._check(context)
                if _word(data, 4) == 1:
                    return 1002
                context.native_sleep(200)
                status, reply = self._exchange(context, comm, b"\x31\x03\x11\xf9", 5)
                if status:
                    break
                if reply[4] == 1:
                    break
                if reply[4] != 0:
                    status = 3
                    break
        if status == 1002:
            return status
        if not status:
            return 1004 if _word(data, 0) == 0 else 1001
        if _word(data, 8) == 1:
            comm.session(1, 1)
            struct.pack_into("<I", data, 8, 0)
        comm.finalize()
        return status

    def _avs(
        self, export: str, data: bytearray, context: TYContext, comm: TYComm
    ) -> int:
        classic = (
            export == EXPORTS[1]
            and self.contract.source_sha256 == SHA_PLUS_TY
            and context.mode == 22
        )
        if export == EXPORTS[0] and _word(data, 0):
            status = 0
            while not data[4]:
                context.native_sleep(500)
                status, reply = self._exchange(context, comm, b"\x31\x03\x10\x07", 5)
                if status or reply[4] != 1:
                    if not status and reply[4] != 2:
                        status = 3
                    break
            context.native_sleep(50)
            comm.session(1, 1)
            comm.finalize()
            return status
        status = self._open(comm)
        if not status:
            status = comm.session(3, 1)
            if not status:
                if export == EXPORTS[0]:
                    context.native_sleep(50)
                    status, _ = self._exchange(context, comm, b"\x31\x01\x10\x07")
                    if not status:
                        return 0
                    context.native_sleep(50)
                else:
                    for selection in (2, 1) if classic else (3, 4):
                        request = bytes((0x31, 1, 3 if classic else 0x11, selection, 7))
                        status, _ = self._exchange(
                            context, comm, request, 5 if classic else 4, 3
                        )
                        # Byte 4 is a request-only mask; the helper compares 3 bytes.
                        if status:
                            break
                    if not status:
                        context.native_sleep(5000)
                        status, reply = self._exchange(
                            context,
                            comm,
                            b"\x22\x12\x0b" if classic else b"\x22\x13\x01",
                            5,
                        )
                        comm.session(1, 1)
                        if not status:
                            data[0] = reply[4]
                            status = 1002 if data[0] & 7 == 7 else 1003
                            if classic and status == 1003:
                                value = data[0]
                                data[0] = (
                                    ((value >> 2) & 1)
                                    | (value & 2)
                                    | ((value & 1) << 2)
                                )
                        comm.finalize()
                        return status
                comm.session(1, 1)
        comm.finalize()
        return status

    def run_body(
        self, export: str, args: tuple[object, ...], context: TYContext
    ) -> int:
        if (
            context.module_sha256 != self.contract.source_sha256
            or hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256
        ):
            raise TYSourceError("TY retained source identity mismatch")
        hncsn = (
            HNCSN_EXPORTS
            if self.contract.source_sha256 == SHA_PLUS_TY
            else HNCSN_EXPORTS[:6]
        )
        if export not in FSR_EXPORTS + BCM_EXPORTS + hncsn + EXPORTS:
            raise TYSourceError("TY retained export has no implemented body")
        minimum = (
            124
            if export in HNCSN_EXPORTS[2:]
            and self.contract.source_sha256 == SHA_PLUS_TY
            else 124
            if export == HNCSN_EXPORTS[5] and self.contract.source_sha256 == SHA_PLUS_TY
            else 32
            if export == HNCSN_EXPORTS[5]
            else 72
            if export == HNCSN_EXPORTS[4]
            else 33
            if export in HNCSN_EXPORTS[2:4]
            else 20
            if export == HNCSN_EXPORTS[1]
            else 424
            if export == BCM_EXPORTS[0]
            else 124
            if export == BCM_EXPORTS[1]
            else 25
            if export == FSR_EXPORTS[6]
            else 21
            if export == FSR_EXPORTS[5]
            else 16
            if export == FSR_EXPORTS[1]
            else 12
            if export in FSR_EXPORTS[:4] or export.startswith("Ex2SBW")
            else 5
            if export == EXPORTS[0]
            else 1
        )
        if (
            len(args) != 1
            or not isinstance(args[0], bytearray)
            or len(args[0]) < minimum
        ):
            raise NativeTYMemoryFault(
                f"retained TY requires one mutable {minimum}-byte buffer"
            )
        self._check(context)
        kind = (
            "selected"
            if export in FSR_EXPORTS + HNCSN_EXPORTS
            else self.contract.manager
        )
        if (
            export == EXPORTS[1]
            and self.contract.source_sha256 == SHA_PLUS_TY
            and context.mode == 22
        ):
            kind = "native:1013e7d0"
        comm = context.comm(kind)
        if export == HNCSN_EXPORTS[5]:
            return self._hncsn_support(args[0], context, comm)
        if export in HNCSN_EXPORTS[2:] and self.contract.source_sha256 == SHA_PLUS_TY:
            return self._hncsn_calibration_plus(export, args[0], context, comm)
        if export in HNCSN_EXPORTS[2:5]:
            return self._hncsn_calibration18(export, args[0], context, comm)
        if export == HNCSN_EXPORTS[1]:
            return self._hncsn_neutral(args[0], context, comm)
        if export == HNCSN_EXPORTS[0]:
            return self._hncsn_transition(context, comm)
        if export in BCM_EXPORTS:
            return self._bcm(export, args[0], context, comm)
        if export in FSR_EXPORTS[5:]:
            return self._fsr_active(export, args[0], context, comm)
        if export in FSR_EXPORTS:
            return self._fsr(export, args[0], context, comm)
        # Host cancellation/driver exceptions remain exceptions, never native status.
        if export.startswith("Ex2SBW"):
            return self._sbw(export, args[0], context, comm)
        return self._avs(export, args[0], context, comm)


def run_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    if context.module_sha256 not in CONTRACTS:
        raise TYSourceError("TY retained source is unreviewed")
    if export not in supported_exports(context.module_sha256):
        raise TYSourceError("TY retained export has no implemented exact-source body")
    return Engine(CONTRACTS[context.module_sha256]).run_body(export, args, context)
