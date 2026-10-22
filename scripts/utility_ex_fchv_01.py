"""Literal FCHV01 action workers for the reviewed 18 and Plus TY images."""

from __future__ import annotations

import hashlib
from typing import cast

from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import (
    SHA_18_TY,
    SHA_PLUS_TY,
    TYComm,
    TYContext,
    TYSourceError,
)
from scripts.utility_ex_ty import (
    elapsed_ticks as _elapsed,
)

_EXPORT = "Ex2FCHV_01_SendMessage"
_MANAGERS = {SHA_18_TY: "native:1011d4f0", SHA_PLUS_TY: "native:101392d0"}
_SETTERS = {
    SHA_18_TY: ("native_rva:1a860", "native_rva:1a880", "native_rva:1a8c0"),
    SHA_PLUS_TY: ("native_rva:1e290", "native_rva:1e2b0", "native_rva:1e2d0"),
}


def supported_exports(module_sha256: str) -> tuple[str, ...]:
    return (_EXPORT,) if module_sha256 in _MANAGERS else ()


def _u32(data: bytearray, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _put(data: bytearray, offset: int, value: int) -> None:
    data[offset : offset + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")


class _Worker:
    def __init__(self, data: bytearray, context: TYContext, comm: TYComm):
        self.data = data
        self.context = context
        self.comm = comm
        self.plus = context.module_sha256 == SHA_PLUS_TY
        self.timer: int | None = None
        # Authored host-fault safety persists across successful retained messages.
        self.pending = cast(
            set[tuple[int, int]],
            context.state.setdefault(f"fchv01:{context.module_sha256}:outputs", set()),
        )

    @property
    def special(self) -> bool:
        return _u32(self.data, 0x18) == 0x18D

    @property
    def stopped(self) -> bool:
        self.check()
        return _u32(self.data, 4) == 1

    @property
    def sensor_did(self) -> int:
        return 5 if self.special else 0xC1

    @property
    def flag_did(self) -> int:
        return 6 if self.plus or self.special else 0xBF

    def check(self) -> None:
        if self.context.is_cancelled():
            raise Cancelled("FCHV01 cancelled")

    def sleep(self, ms: int) -> None:
        self.check()
        self.context.native_sleep(ms)
        self.check()

    def start(self) -> None:
        if self.timer is None:
            self.timer = self.context.ticks()

    def reset(self) -> None:
        self.timer = None

    def elapsed(self) -> int:
        now = self.context.ticks()
        return 0 if self.timer is None else _elapsed(now, self.timer)

    def exchange(self, request: bytes) -> tuple[int, bytes]:
        self.check()
        status, reply = self.comm.exchange(request)
        if type(status) is not int or not 0 <= status <= 0xFFFFFFFF:
            raise TypeError("FCHV01 communication status must be uint32")
        if type(reply) is not bytes or len(reply) > 4128:
            raise ValueError("FCHV01 reply exceeds native buffer")
        return status, reply

    def read(
        self, did: int, offset: int = 0, size: int = 2, first: int = 0x1B
    ) -> tuple[int, bytes]:
        status, reply = self.exchange(bytes((0x22, first, did)))
        if not status:
            if len(reply) < offset + size + 3 or reply[1:3] != bytes((first, did)):
                return 3, bytes(size)
            return 0, reply[offset + 3 : offset + size + 3]
        return status, bytes(size)

    def number(self, did: int, offset: int = 0, size: int = 2) -> tuple[int, int]:
        status, data = self.read(did, offset, size)
        return status, int.from_bytes(data, "big")

    def control(self, did: int, payload: bytes = b"\0\x80") -> int:
        if payload[0]:
            self.pending.add((0x2F, did))
        status, reply = self.exchange(bytes((0x2F, 0x28, did)) + payload)
        if not status and (
            len(reply) < 4 or reply[1:4] != bytes((0x28, did, payload[0]))
        ):
            return 3
        if not status and not payload[0]:
            self.pending.discard((0x2F, did))
        return status

    def routine(self, mode: int, number: int, value: int | None = None) -> int:
        if mode == 1:
            self.pending.add((0x31, number))
        request = bytes((0x31, mode, 0x11, number))
        if value is not None:
            request += bytes((value,))
        status, reply = self.exchange(request)
        if not status and (len(reply) < 4 or reply[1:4] != request[1:4]):
            return 3
        if not status and mode == 2:
            self.pending.discard((0x31, number))
        return status

    def release_host(self, primary: BaseException) -> None:
        # Stop routines before controls; do not veto safety cleanup on host cancel.
        for kind, number in sorted(
            self.pending, key=lambda item: (item[0] != 0x31, item[1])
        ):
            request = (
                bytes((0x31, 2, 0x11, number))
                if kind == 0x31
                else bytes((0x2F, 0x28, number, 0, 0x80))
            )
            try:
                status, reply = self.comm.cleanup_exchange(request)
                if (
                    type(status) is not int
                    or status != 0
                    or type(reply) is not bytes
                    or len(reply) < 4
                    or reply[1:4] != request[1:4]
                ):
                    primary.add_note(
                        f"FCHV01 host release {request.hex()} unconfirmed: {status!r}"
                    )
                else:
                    self.pending.discard((kind, number))
            except BaseException as cleanup:  # noqa: BLE001 - preserve host fault/cancel
                primary.add_note(
                    f"FCHV01 host release {request.hex()} failed: {cleanup!r}"
                )

    def controls(self, *dids: int) -> None:
        for did in dids:
            self.control(did)

    def cleanup(self, *before: int) -> None:
        self.controls(*before)
        self.sleep(3000)
        self.controls(0x14, 0x0A)

    def support(self) -> int:
        status, data = self.read(1, 0, 32, 1)
        if status:
            return status
        if not data[3] & 0x10:
            return 22
        status, data = self.read(0, 0, 32)
        if status:
            return status
        masks = ((2, 0x43), (3, 0x80), (7, 0x80), (13, 0x80), (19, 0x38))
        masks += ((0, 0x0C), (12, 1)) if self.special else ((23, 3), (24, 0x80))
        return 0 if all(data[index] & mask == mask for index, mask in masks) else 22

    def prepare(self) -> int:
        if self.routine(1, 0x1A, 3):
            return 2025
        while True:
            self.sleep(500)
            if self.special:
                status, value = self.number(0x68, size=1)
                if status:
                    return 2025
                self.start()
                if value == 3:
                    status, value = self.number(0x69, size=1)
                    if status:
                        return 2025
                    if value == 10:
                        return 0
            else:
                status, value = self.number(0x69, size=1)
                if status:
                    return 2025
                self.start()
                if value == 10:
                    return 0
            if self.elapsed() >= 30000:
                return 2025

    def raise_pressure(self, action: int) -> int:
        did, offset = {3: (0x0B, 10), 5: (0x0A, 6), 6: (0x14, 14)}[action]
        result = {3: 2026, 5: 2028, 6: 2029}[action]
        if not self.control(did, b"\x03\x64\x80"):
            while True:
                self.sleep(200)
                status, value = self.number(self.sensor_did, offset)
                if status:
                    break
                self.start()
                if value > 0xB0A3:
                    if action != 6:
                        return 0
                    if not self.control(0x0B):
                        return 0
                    result = 2026
                    break
                if self.elapsed() >= 5000:
                    break
        if action == 3:
            self.control(0x0B)
        elif action == 5:
            self.control(0x11)
            self.sleep(3000)
            self.controls(0x0A, 0x0B)
        else:
            self.cleanup(0x11)
            if result != 2026:
                self.control(0x0B)
        return result

    def drive(self, action: int) -> int:
        payload = b"\x03\x09\xc4\x80" if action == 4 else b"\x03\x03\xe8\x80"
        low, high, minimum = (
            (0x88C9, 0x8ABF, 32) if action == 4 else (0x8383, 0x844D, 7)
        )
        if not self.control(0x11, payload):
            if action == 4:
                _put(self.data, 12, self.context.ticks())
            self.sleep(200)
            while True:
                status, value = self.number(0x18)
                if status:
                    break
                self.start()
                if low < value < high:
                    status, other = self.number(0x19)
                    if status:
                        break
                    if (
                        (value - 0x8000) * 9 // 10
                        <= other
                        <= (value - 0x8000) * 11 // 10
                    ):
                        status, current = self.number(0x17, 3)
                        if status:
                            break
                        if current > minimum:
                            return 0
                if self.elapsed() >= 10000:
                    break
                self.sleep(200)
        if action == 4:
            self.control(0x11)
            self.sleep(3000)
            self.control(0x0B)
        else:
            self.cleanup(0x11)
        return 2027

    def decay(self) -> int:
        first_limit = 9000 if self.plus and not self.special else 5000
        self.sleep(200)
        result = 2026
        while not self.stopped:
            status, value = self.number(self.sensor_did, 10)
            if status:
                break
            self.start()
            if value < 0x8290:
                self.timer = self.context.ticks()
                while not self.stopped and self.elapsed() < 60000:
                    self.check()
                if self.stopped:
                    break
                total_limit = 300000 if self.special else 600000
                self.sleep(1000)
                while not self.stopped:
                    status, value = self.number(0x39)
                    if status:
                        break
                    if value < 250:
                        return 0
                    if (
                        _elapsed(self.context.ticks(), _u32(self.data, 12))
                        >= total_limit
                    ):
                        result = 2032
                        break
                    self.sleep(1000)
                break
            if self.elapsed() >= first_limit:
                break
            self.sleep(200)
        if self.stopped:
            result = 2100
        self.cleanup(0x11)
        return result

    def warm(self) -> int:
        self.sleep(200)
        while True:
            status, value = self.number(0x9B)
            if status:
                break
            self.start()
            if value > 199:
                return 0
            if self.elapsed() >= 10000:
                break
            self.sleep(200)
        self.cleanup(0x11)
        return 2033

    def fill(self) -> int:
        if not self.routine(1, 0x19, 0x82):
            _put(self.data, 20, self.context.ticks())
            self.sleep(200)
            while True:
                status, pressure = self.number(0x9C)
                if status:
                    break
                self.start()
                status, target = self.number(0x9D)
                if status:
                    break
                if target <= pressure:
                    return 0
                if self.elapsed() >= 10000:
                    break
                self.sleep(200)
        self.routine(2, 0x19)
        self.cleanup(0x11)
        return 2034

    def balance(self) -> int:
        result = 2035
        if not self.control(0x0D, b"\x03\x0c\x80\x80"):
            while True:
                self.sleep(200)
                status, data = self.read(self.sensor_did, 0, 4)
                if status:
                    break
                self.start()
                first = int.from_bytes(data[:2], "big")
                left, right = (
                    first // 4 - 0x2000,
                    int.from_bytes(data[2:], "big") // 4 - 0x2000,
                )
                if first > 0x9F3F and int(left * 9 / 10) <= right <= int(
                    left * 11 / 10
                ):
                    if not self.plus or self.special:
                        if self.routine(1, 0x16):
                            result = 2036
                            self.routine(2, 0x16)
                            break
                    else:
                        _put(self.data, 8, 1)
                    return 0
                if self.elapsed() >= 5000:
                    break
        self.control(0x0D)
        if not self.plus or self.special:
            self.routine(2, 0x19)
        self.cleanup(0x11)
        return result

    def cool(self) -> int:
        result = 2034
        self.sleep(1000)
        while not self.stopped:
            status, value = self.number(0x39)
            if status:
                result = 2038 if self.plus and not self.special else 2034
                break
            self.start()
            if value < 420:
                return 0
            if self.elapsed() >= 180000:
                result = 2038
                break
            self.sleep(1000)
        if self.stopped:
            result = 2100
        self.cleanup(0x0D, 0x11)
        return result

    def release(self) -> int:
        result, pending = 2035, True
        if not self.control(0x0D):
            while True:
                self.sleep(200)
                status, value = self.number(self.sensor_did, 2)
                if status:
                    break
                self.start()
                if value < 0x8321:
                    if self.plus and not self.special:
                        return 0
                    pending = False
                    result = 2037 if self.control(0x11) else 0
                    _put(self.data, 16, self.context.ticks())
                    if not result:
                        return 0
                    break
                if self.elapsed() >= 10000:
                    break
        if pending:
            self.control(0x11)
        self.cleanup()
        return result

    def idle(self) -> int:
        if not self.routine(1, 0x16):
            return 0
        self.routine(2, 0x16)
        self.controls(0x14, 0x0A)
        return 2036

    def abort(self, action: int) -> int:
        if action == 20:
            self.control(0x11)
        elif action in (21, 22):
            self.controls(0x0D, 0x11)
        if action < 24:
            self.sleep(3000)
        self.controls(0x14, 0x0A)
        return 2100

    def hold(self) -> int:
        pending16, pending19 = True, True
        result = 2036
        self.sleep(200)
        while not self.stopped:
            status, value = self.number(self.flag_did, 1, 1)
            if status:
                break
            self.start()
            if value & 0x40:
                while (
                    not self.stopped
                    and _elapsed(self.context.ticks(), _u32(self.data, 20)) < 120000
                ):
                    self.check()
                if self.stopped:
                    break
                pending16 = False
                if self.routine(2, 0x16):
                    break
                self.reset()
                self.sleep(200)
                while not self.stopped:
                    status, value = self.number(self.flag_did, 1, 1)
                    if status:
                        break
                    self.start()
                    if not value & 0x40:
                        pending19 = False
                        result = 2034 if self.routine(2, 0x19) else 0
                        break
                    if self.elapsed() >= 5000:
                        break
                    self.sleep(200)
                break
            if self.elapsed() >= 5000:
                break
            self.sleep(200)
        if self.stopped:
            result = 2100
        elif not result:
            return 0
        if pending16:
            self.routine(2, 0x16)
        self.control(0x0D)
        if pending19:
            self.routine(2, 0x19)
        self.cleanup(0x11)
        return result

    def drain(self) -> int:
        started16, settle = False, True
        result = 2037
        self.sleep(200)
        while not self.stopped:
            status, value = self.number(0x17, 3)
            if status:
                break
            self.start()
            if value < 10:
                status, value = self.number(0x19)
                if status:
                    break
                if value < 101:
                    self.sleep(1000)
                    while not self.stopped:
                        status, value = self.number(0x39)
                        if status:
                            break
                        if value < 240:
                            settle = False
                            _put(self.data, 8, 1)
                            started16 = True
                            result = 2036 if self.routine(1, 0x16) else 0
                            break
                        if (
                            _elapsed(self.context.ticks(), _u32(self.data, 16))
                            >= 1200000
                        ):
                            settle, result = False, 2038
                            break
                        self.sleep(1000)
                    break
            if self.elapsed() >= 10000:
                break
            self.sleep(200)
        if self.stopped:
            result = 2100
        elif not result:
            return 0
        if started16:
            self.routine(2, 0x16)
        if settle:
            self.sleep(3000)
        self.controls(0x14, 0x0A)
        return result

    def transition(self) -> int:
        pending16, started19 = True, False
        result = 2036
        self.sleep(200)
        while not self.stopped:
            status, value = self.number(self.flag_did, 1, 1)
            if status:
                break
            self.start()
            if value & 0x40:
                self.reset()
                self.sleep(200)
                while not self.stopped:
                    status, pressure = self.number(0x9C)
                    if status:
                        break
                    self.start()
                    status, temperature = self.number(0x12, 4)
                    if status:
                        break
                    if int((pressure - 0x8000) * 22 / 1000) < temperature // 100 + 10:
                        pending16 = False
                        if self.routine(2, 0x16):
                            break
                        self.reset()
                        self.sleep(200)
                        while not self.stopped:
                            status, value = self.number(self.flag_did, 1, 1)
                            if status:
                                break
                            self.start()
                            if not value & 0x40:
                                self.timer = self.context.ticks()
                                while not self.stopped and self.elapsed() < 30000:
                                    self.check()
                                if self.stopped:
                                    break
                                started19 = True
                                result = 2034 if self.routine(1, 0x19, 0x82) else 0
                                break
                            if self.elapsed() >= 5000:
                                break
                            self.sleep(200)
                        break
                    if self.elapsed() >= 5000:
                        break
                    self.sleep(200)
                break
            if self.elapsed() >= 5000:
                break
            self.sleep(200)
        if self.stopped:
            result = 2100
        elif not result:
            return 0
        if pending16:
            self.routine(2, 0x16)
        if started19:
            self.routine(2, 0x19)
        self.controls(0x14, 0x0A)
        return result

    def retry(self) -> int:
        pending19 = True
        result = 2034
        self.sleep(200)
        while not self.stopped:
            status, pressure = self.number(0x9C)
            if status:
                break
            self.start()
            status, target = self.number(0x9D)
            if status:
                break
            if target <= pressure:
                pending19 = False
                if self.routine(2, 0x19):
                    break
                self.reset()
                self.sleep(500)
                while not self.stopped:
                    status, value = self.number(0x39)
                    if status:
                        break
                    self.start()
                    if value > 239:
                        count = _u32(self.data, 8)
                        if count < 5:
                            _put(self.data, 8, count + 1)
                            return 2101
                        result = 2038
                        break
                    if self.elapsed() >= 30000:
                        return 0
                    self.sleep(500)
                break
            if self.elapsed() >= 10000:
                break
            self.sleep(200)
        if self.stopped:
            result = 2100
        if pending19:
            self.routine(2, 0x19)
        self.controls(0x14, 0x0A)
        return result

    def cycle(self) -> int:
        result = 2036
        if not self.routine(1, 0x16):
            while True:
                self.sleep(200)
                status, value = self.number(self.flag_did, 1, 1)
                if status:
                    break
                self.start()
                if value & 0x40:
                    self.sleep(5000)
                    if self.routine(2, 0x16):
                        # Unlike initial activation/poll failure, do not retry this stop.
                        self.controls(0x14, 0x0A)
                        return 2036
                    self.reset()
                    while True:
                        self.sleep(200)
                        status, value = self.number(self.flag_did, 1, 1)
                        if status:
                            break
                        self.start()
                        if not value & 0x40:
                            result = 0
                            break
                        if self.elapsed() >= 5000:
                            break
                    self.controls(0x14, 0x0A)
                    if not result:
                        self.routine(2, 0x1A)
                    return result
                if self.elapsed() >= 10000:
                    break
        self.routine(2, 0x16)
        self.controls(0x14, 0x0A)
        return result

    def plus_finish(self) -> int:
        result = 2037
        if not self.control(0x11):
            self.sleep(200)
            while not self.stopped:
                status, value = self.number(0x17, 3)
                if status:
                    break
                self.start()
                if value < 10:
                    status, value = self.number(0x19)
                    if status:
                        break
                    if value <= 100:
                        self.reset()
                        while True:
                            for _ in range(4):
                                if self.stopped:
                                    break
                                self.sleep(250)
                            if self.stopped:
                                break
                            status, value = self.number(0x39)
                            if status:
                                result = 2038
                                break
                            self.start()
                            if value < 240:
                                result = 0
                                break
                            if self.elapsed() >= 1200000:
                                result = 2038
                                break
                        if _u32(self.data, 4) != 0:
                            self.sleep(3000)
                        self.controls(0x14, 0x0A)
                        if self.stopped:
                            return 2100
                        if not result:
                            self.routine(2, 0x1A)
                        return result
                if self.elapsed() >= 10000:
                    break
                self.sleep(200)
        self.reset()
        self.sleep(3000)
        self.controls(0x14, 0x0A)
        return 2100 if self.stopped else result

    def plus_repeat(self) -> int:
        pending19, pending16 = True, False
        result = 2034
        while True:
            if self.routine(1, 0x19, 200):
                pending19, pending16 = True, False
                break
            self.sleep(200)
            while not self.stopped:
                status, pressure = self.number(0x9C)
                if status:
                    break
                self.start()
                status, target = self.number(0x9D)
                if status:
                    break
                if target <= pressure:
                    break
                if self.elapsed() >= 5000:
                    status = 1
                    break
                self.sleep(200)
            else:
                status = 1
            if status or self.stopped:
                self.reset()
                pending19, pending16 = True, False
                break
            self.reset()
            for _ in range(50):
                self.sleep(200)
                if self.stopped:
                    break
            if self.stopped:
                pending19, pending16 = True, False
                break
            pending19 = False
            if self.routine(2, 0x19):
                break
            for _ in range(2):
                self.sleep(250)
                if self.stopped:
                    break
            if self.stopped:
                break
            pending16 = True
            result = 2036
            if self.routine(1, 0x16):
                break
            self.sleep(200)
            while not self.stopped:
                status, data = self.read(0xBF)
                if status:
                    break
                self.start()
                if data[1] & 0x40:
                    break
                if self.elapsed() >= 5000:
                    status = 1
                    break
                self.sleep(200)
            else:
                status = 1
            if status or self.stopped:
                self.reset()
                break
            self.reset()
            self.sleep(200)
            while not self.stopped:
                status, pressure = self.number(0x9C)
                if status:
                    break
                self.start()
                if pressure < 0x9632:
                    break
                if self.elapsed() >= 60000:
                    status = 1
                    break
                self.sleep(200)
            else:
                status = 1
            if status or self.stopped:
                self.reset()
                break
            self.reset()
            pending16 = False
            if self.routine(2, 0x16):
                break
            self.sleep(200)
            while not self.stopped:
                status, data = self.read(0xBF)
                if status:
                    break
                if not data[1] & 0x40:
                    break
                self.start()
                if self.elapsed() >= 5000:
                    status = 1
                    break
                self.sleep(200)
            else:
                status = 1
            if status or self.stopped:
                self.reset()
                break
            self.reset()
            count = _u32(self.data, 8)
            if count >= 6:
                return 0
            _put(self.data, 8, count + 1)
            result = 2034
        if self.stopped:
            result = 2100
        if pending19 or result == 2100:
            self.routine(2, 0x19)
        if pending16 or result == 2100:
            self.routine(2, 0x16)
        self.cleanup(0x0D, 0x11)
        return result

    def action(self, action: int) -> int:
        if action == 0:
            return self.support()
        if action == 2:
            return self.prepare()
        if action in (3, 5, 6):
            return self.raise_pressure(action)
        if action in (4, 8):
            return self.drive(action)
        if action == 7:
            return self.decay()
        if action == 9:
            return self.warm()
        if action == 10:
            return self.fill()
        if action == 11:
            return self.balance()
        if action == 12:
            return self.plus_repeat() if self.plus and not self.special else self.hold()
        if action == 13:
            return self.cool()
        if action == 14:
            return self.release()
        if action == 15:
            return self.drain()
        if action == 16:
            return self.transition()
        if action == 17:
            return self.retry()
        if action == 18:
            return (
                self.plus_finish() if self.plus and not self.special else self.cycle()
            )
        if action == 19:
            return self.idle()
        if 20 <= action <= 25:
            return self.abort(action)
        return 0


def _run(args: tuple[object, ...], context: TYContext) -> int:
    if (
        type(args) is not tuple
        or len(args) != 1
        or type(args[0]) is not bytearray
        or not 28 <= len(args[0]) <= 65536
    ):
        raise ValueError(
            "FCHV01 requires one mutable bounded native 0x1c-byte argument block"
        )
    data = args[0]
    action = _u32(data, 0)
    comm = context.comm(_MANAGERS[context.module_sha256])
    worker = _Worker(data, context, comm)
    try:
        worker.check()
        if action in (0, 2):
            status = comm.initialize(0)
            if status:
                return status
            for setter, value in zip(
                _SETTERS[context.module_sha256], (0, 180000, 0), strict=True
            ):
                comm.configure(setter, value)
            if comm.session(3, 1, normal_first=True):
                comm.finalize()
                return 2000
        result = worker.action(_u32(data, 0))
        # Native worker reloads action after the mutable UI block returns.
        completion_action = _u32(data, 0)
        if completion_action == 0:
            status = comm.session(1, 1, stop_on_error=True)
            result = status or result
        elif completion_action == 18 or result not in (0, 2101):
            comm.session(1, 1)
        else:
            return result
        comm.finalize()
        return result
    except BaseException as primary:
        worker.release_host(primary)
        try:
            comm.cleanup_session(1, 1, stop_on_error=True)
        except BaseException as cleanup:  # noqa: BLE001 - preserve host fault/cancel
            primary.add_note(f"FCHV01 host normal-session cleanup failed: {cleanup!r}")
        try:
            comm.finalize()
        except BaseException as cleanup:  # noqa: BLE001 - preserve host fault/cancel
            primary.add_note(f"FCHV01 host finalization failed: {cleanup!r}")
        raise


def run_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    if (
        export not in supported_exports(context.module_sha256)
        or hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256
    ):
        raise TYSourceError("Exact reviewed FCHV01 source/export identity required")
    return _run(args, context)
