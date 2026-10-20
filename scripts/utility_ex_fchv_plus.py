"""Source-bound Plus FCHV24/25/27/28 native action workers."""

from __future__ import annotations

import hashlib
from typing import cast

from scripts.utility_ex_fchv import (
    _check,
    _exchange,
    _extended,
    _initialize,
    _put,
    _status,
    _u32,
)
from scripts.utility_ex_ty import (
    SHA_PLUS_TY,
    TYComm,
    TYContext,
    TYSourceError,
    elapsed_ticks,
)

_EXPORTS = tuple(f"Ex2FCHV_{n}_SendMessage" for n in (24, 25, 27, 28))
# Plus f4228: three independent 16-byte diagnostic descriptors (not resources).
_PRESSURES = ((0x1B, 0xAE, 4, 2), (0x1B, 0x9A, 2, 0), (0x1B, 0x9B, 2, 0))


def supported_exports(module_sha256: str) -> tuple[str, ...]:
    return _EXPORTS if module_sha256 == SHA_PLUS_TY else ()


def _normal(comm: TYComm) -> int:
    # Plus 130f0 stops the keepalive worker even when session restoration fails.
    return _status(comm.session(1, 1, stop_on_error=True))


class _Worker:
    def __init__(self, data: bytearray, context: TYContext, comm: TYComm):
        self.data, self.context, self.comm = data, context, comm
        self.timer: int | None = None
        self.closed = False
        self.state_key = f"fchv-plus:{context.module_sha256}"
        # Host safety state survives the native worker's retained-message lifecycle.
        self.pending = cast(
            dict[tuple[int, int], bytes],
            context.state.setdefault(self.state_key + ":outputs", {}),
        )
        context.state[self.state_key + ":retained"] = True

    def sleep(self, ms: int) -> None:
        _check(self.context)
        self.context.native_sleep(ms)
        _check(self.context)

    def start_timer(self) -> None:
        if self.timer is None:
            self.timer = self.context.ticks()

    def elapsed(self) -> int:
        now = self.context.ticks()
        return 0 if self.timer is None else elapsed_ticks(now, self.timer)

    def read(
        self, first: int, second: int, offset: int, size: int
    ) -> tuple[int, bytes]:
        if not 0 <= offset <= 4125 or not 0 <= size <= 4125 - offset:
            raise ValueError("FCHV diagnostic slice exceeds native reply")
        did = bytes((first, second))
        status, reply = _exchange(self.comm, self.context, b"\x22" + did)
        if not status and (len(reply) < offset + size + 3 or reply[1:3] != did):
            return 3, bytes(size)
        return status, reply[3 + offset : 3 + offset + size] if not status else bytes(
            size
        )

    def echo(self, packet: bytes) -> int:
        status, reply = _exchange(self.comm, self.context, packet)
        return (
            3
            if not status and (len(reply) < 4 or reply[1:4] != packet[1:4])
            else status
        )

    def io(self, mode: int, payload: bytes) -> int:
        key = (0x2F, 0x1F)
        if mode == 3:
            self.pending[key] = b"\x2f\x28\x1f\0" + payload[-8:]
        result = self.echo(bytes((0x2F, 0x28, 0x1F, mode)) + payload)
        if mode == 0 and not result:
            self.pending.pop(key, None)
        return result

    def routine(self, mode: int, number: int, payload: bytes = b"") -> int:
        key = (0x31, number)
        if mode == 1:
            self.pending[key] = bytes((0x31, 2, 0x11, number))
        result = self.echo(bytes((0x31, mode, 0x11, number)) + payload)
        if mode == 2 and not result:
            self.pending.pop(key, None)
        return result

    def finish(self, normal: bool = True) -> int:
        result = _normal(self.comm) if normal else 0
        self.comm.finalize()
        self.closed = True
        self.context.state[self.state_key + ":retained"] = False
        return result

    def masks(self, offset: int) -> bytes:
        return b"".join(bytes((0, value)) for value in self.data[offset : offset + 4])

    def fault_cleanup(self, offset: int, primary: BaseException) -> None:
        # Bounded cleanup primitives bypass cancellation without clearing its flag.
        releases = dict(self.pending)
        releases.setdefault((0x2F, 0x1F), b"\x2f\x28\x1f\0" + self.masks(offset))
        for key in sorted(releases, key=lambda item: (item[0] != 0x31, item[1])):
            request = releases[key]
            try:
                status, reply = self.comm.cleanup_exchange(request)
                if (
                    type(status) is int
                    and status == 0
                    and type(reply) is bytes
                    and 4 <= len(reply) <= 4128
                    and reply[1:4] == request[1:4]
                ):
                    self.pending.pop(key, None)
                else:
                    primary.add_note(
                        f"FCHV release {request.hex()} unconfirmed: {status!r}"
                    )
            except BaseException as cleanup:  # noqa: BLE001 - preserve primary and attempt all releases
                primary.add_note(f"FCHV release {request.hex()} failed: {cleanup!r}")
        try:
            status = _status(self.comm.cleanup_session(1, 1, stop_on_error=True))
            if status:
                primary.add_note(f"FCHV normal cleanup unconfirmed: {status}")
        except BaseException as cleanup:  # noqa: BLE001 - finalize despite session cleanup failure
            primary.add_note(f"FCHV normal cleanup failed: {cleanup!r}")
        self.closed = True
        self.context.state[self.state_key + ":retained"] = False
        try:
            self.comm.finalize()
        except BaseException as cleanup:  # noqa: BLE001 - preserve primary host fault/cancel
            primary.add_note(f"FCHV finalize failed: {cleanup!r}")


class _Valves(_Worker):
    @property
    def state(self) -> int:
        return _u32(self.data, 0x388)

    def release(self) -> None:
        self.io(0, self.masks(0x384))

    def support(self, plus25: bool) -> int:
        status = _initialize(self.comm, self.context)
        if status:
            self.finish(False)
            return status
        status = _extended(self.comm)
        if status:
            self.finish(False)
            return status
        status, support = self.read(1, 1, 3, 1)
        if not status and support[0] & 0x10:
            status, support = self.read(0x1B, 0, 0, 0x18 if plus25 else 0x1A)
            if not status:
                for row in range(20):
                    base = 4 + row * 44
                    index = _u32(self.data, base + 4)
                    if index >= len(support):
                        raise ValueError("FCHV support index exceeds source bitmap")
                    if support[index] & self.data[base + 8]:
                        _put(self.data, base + 12, 1)
                if not plus25:
                    _put(self.data, 0x220, 0)
                    if support[25] & 2:
                        status, secondary = self.read(0x1B, 0xCF, 0, 5)
                        if not status and secondary[4] & 4:
                            _put(self.data, 0x220, 1)
        if not status:
            status, masks = self.read(0x28, 0x1F, 0, 7)
            if not status:
                self.data[0x384:0x388] = bytes(
                    (masks[0], masks[2], masks[4], masks[6] & 7)
                )
        normal = self.finish()
        return status or normal

    def start(self, action: int, plus25: bool) -> int:
        state = 1 if action == 2 else 4
        status = 0
        result: int | None = None
        if not (plus25 and action == 3):
            masks = self.masks(0x384)
            status = self.io(3, masks + masks)
            if status:
                result = 0x89D
            else:
                self.sleep(200)
                while True:
                    status, reply = self.read(0x1B, 0xBE, 0, 2)
                    if status:
                        result = 0x8A2
                        break
                    self.start_timer()
                    if (reply[0] ^ reply[1]) & 0x3F == 0:
                        self.sleep(3000 if action == 2 else 2000)
                        break
                    if self.elapsed() >= 5000:
                        result = 0x8B2
                        break
                    self.sleep(200)
            # A source activation failure restores masks; read/timeout does too.
            if result is not None:
                self.release()
                if status and result == 0x89D:
                    self.finish()
                return result
        _put(self.data, 0x388, state)
        if not self.routine(1, 0x19, b"\xc8"):
            self.sleep(3000)
            return 0x8B0
        self.routine(2, 0x19)
        self.release()
        return 0x8B2

    def activate(self) -> int:
        result = 0x8B2
        status = self.routine(1, 0x16)
        if not status:
            self.sleep(200)
            while True:
                status, reply = self.read(0x1B, 0xBF, 1, 1)
                if status:
                    result = 0x8A2
                    break
                self.start_timer()
                if reply[0] & 0x40:
                    return 0x8B3 if self.state in (1, 2, 4) else 0x8AB
                if self.elapsed() > 5000:
                    break
                self.sleep(200)
        self.routine(2, 0x16)
        if self.state not in (1, 2, 4):
            self.finish()
            return 0x8B1
        self.release()
        return result

    def advance(self) -> int:
        self.routine(2, 0x16)
        state = self.state
        if state in (1, 4):
            if state == 1:
                _put(self.data, 0x388, 2)
            if not self.routine(1, 0x19, b"\xc8"):
                self.sleep(3000)
                return 0x8B0 if state == 1 else 0x8A7
            self.routine(2, 0x19)
        elif state == 2:
            status = self.io(3, bytes(8) + self.masks(0x384))
            if not status:
                self.sleep(200)
                while True:
                    status, reply = self.read(0x1B, 0xBE, 0, 2)
                    if status:
                        self.release()
                        return 0x8A2
                    self.start_timer()
                    if reply[0] & reply[1] & 0x3F == 0:
                        return 0x8A5
                    if self.elapsed() >= 5000:
                        break
                    self.sleep(200)
        elif state == 3:
            return 0x8A6
        elif state == 5:
            self.finish()
            return 0x8AC
        else:
            self.finish()
            return 99
        self.release()
        return 0x8B2

    def monitor(self, action: int) -> int:
        orders = [
            _u32(self.data, 4 + i * 44 + (24 if action == 6 else 28)) for i in range(20)
        ]
        result = 0
        while True:
            for priority in range(1, 16 if action == 8 else 18 if action == 6 else 19):
                _check(self.context)
                for row in range(20):
                    base = 4 + row * 44
                    order = _u32(self.data, base + 32) if action == 8 else orders[row]
                    if order != priority or not _u32(self.data, base + 12):
                        continue
                    result, reply = self.read(
                        self.data[base],
                        self.data[base + 1],
                        _u32(self.data, base + 16),
                        2,
                    )
                    if result:
                        if action != 8:
                            break
                        continue
                    did = self.data[base : base + 2]
                    if did == b"\x1b\xbe":
                        if row > 8:
                            raise ValueError(
                                "FCHV twelve-row bitmap exceeds native row table"
                            )
                        for offset in range(12):
                            target = base + offset * 44
                            self.data[target + 36] = 0
                            self.data[target + 37] = int(
                                bool(reply[offset // 6] & self.data[target + 21])
                            )
                            _put(self.data, target + 40, 1)
                    else:
                        first, second = (
                            reply[0] & self.data[base + 20],
                            reply[1] & self.data[base + 21],
                        )
                        if did == b"\x1b\xbf":
                            first, second = 0, int(bool(second))
                        self.data[base + 36 : base + 38] = bytes((first, second))
                        _put(self.data, base + 40, 1)
                if action != 8 and (_u32(self.data, 0x380) or result):
                    return result
                if action == 8 and self.elapsed() >= 5000:
                    return result
            if action == 8:
                self.start_timer()
                if self.elapsed() >= 5000:
                    return result

    def action(self, action: int, plus25: bool) -> int:
        if action == 0:
            return self.support(plus25)
        if action in (2, 3):
            return self.start(action, plus25)
        if action == 4:
            return self.activate()
        if action == 5:
            return self.advance()
        if action in (6, 7, 8):
            return self.monitor(action)
        if action == 14:
            result = _initialize(self.comm, self.context)
            if not result:
                result = _extended(self.comm)
                if not result:
                    if not self.routine(1, 0x1A, b"\x01"):
                        return 0
                    _normal(self.comm)
                    result = 0x89F
            self.finish(False)
            return result
        if action in (16, 17):
            self.routine(2, 0x19)
        if action in (15, 16):
            self.release()
            return 0x8A2
        if action == 17:
            return 0x8AA if self.state in (1, 2, 4) else 0x8AF
        self.finish()
        return 0


class _Pressure(_Worker):
    def release(self, normal: bool) -> None:
        self.io(0, self.masks(0x20))
        if normal:
            _normal(self.comm)

    def control(self, enable: bool, wait: bool, keep: bool) -> int:
        masks = self.masks(0x20)
        result = self.io(3, (masks if enable else bytes(8)) + masks)
        if not wait:
            return 0
        if result:
            result = (
                (2001 if _status(self.comm.read_field("native_10b0")) == 105 else 2000)
                if result == 7
                else 2000
            )
        else:
            self.sleep(200)
            while True:
                status, reply = self.read(0x1B, 0xBE, 0, 8)
                if status:
                    result = 2000
                    break
                self.start_timer()
                if all(
                    (
                        (reply[1 + i * 2] if enable else ~reply[1 + i * 2])
                        & masks[1 + i * 2]
                        & (7 if i == 3 else 255)
                    )
                    == (masks[1 + i * 2] & (7 if i == 3 else 255))
                    for i in range(4)
                ):
                    return 0
                if self.elapsed() >= 5000:
                    result = 2001
                    break
                self.sleep(200)
        self.release(not keep)
        return result

    def sample(self, index: int) -> int:
        first, second, size, _ = _PRESSURES[index]
        result, reply = self.read(first, second, 0, size)
        if not result:
            self.data[14 + index * 6 : 14 + index * 6 + size] = reply
        return result

    def support(self) -> int:
        self.data[12:14], self.data[32:36] = bytes(2), bytes(4)
        result = _extended(self.comm)
        if result:
            return result
        result, reply = self.read(1, 1, 0, 32)
        if not result and not reply[3] & 0x10:
            _normal(self.comm)
            return 3
        if not result:
            result, masks = self.read(0x28, 0x1F, 0, 8)
            if not result:
                self.data[32:36] = bytes((masks[0], masks[2], masks[4], masks[6] & 7))
                result, reply = self.read(0x1B, 0, 0, 32)
                if not result and (not reply[19] & 0x20 or not reply[23] & 4):
                    _normal(self.comm)
                    return 3
                if not result:
                    result, reply = self.read(0x1B, 0xCF, 0, 5)
                    if not result and (not reply[0] & 0x80 or not reply[4] & 4):
                        _normal(self.comm)
                        return 3
        normal = _normal(self.comm)
        return result or normal

    def monitor(self, alternate: bool) -> int:
        first = 0 if alternate else 1
        while True:
            _check(self.context)
            if _u32(self.data, 4):
                return 0x802
            start = self.context.ticks()
            for index in range(first, 3):
                if self.sample(index):
                    if not alternate:
                        self.release(True)
                    return 2003 if alternate else 2000
            _put(self.data, 8, 1)
            wait = (200 - elapsed_ticks(self.context.ticks(), start)) & 0xFFFFFFFF
            if wait <= 200:
                self.sleep(wait)

    def action(self, action: int) -> int:
        release = True
        if action in (0, 1):
            result = _initialize(self.comm, self.context)
            if result:
                self.finish(False)
                return result
        action = _u32(self.data, 0)
        if action == 0:
            result = self.support()
        elif action == 1:
            result = _extended(self.comm)
            if not result:
                if self.routine(1, 0x1A, b"\x01"):
                    _normal(self.comm)
                    result = 2000
                else:
                    result = self.control(True, True, True)
                    if result:
                        _normal(self.comm)
            release = bool(result)
        elif action == 2:
            result = 0
            for index, (_, _, size, offset) in enumerate(_PRESSURES[:2]):
                if self.sample(index):
                    result = 2000
                    break
                value = int.from_bytes(
                    self.data[14 + index * 6 + offset : 14 + index * 6 + offset + 2],
                    "big",
                    signed=True,
                )
                if value < -0xCCC:
                    result = 2002
                    break
            if not result:
                result = self.control(True, True, True)
            if result:
                _normal(self.comm)
            release = bool(result)
        elif action in (3, 4, 5):
            result = self.control(action == 3, action != 5, action == 5)
            release = bool(result) if action != 5 else False
        elif action == 6:
            self.release(True)
            result = 0
        elif action in (7, 8):
            result, release = self.monitor(action == 8), False
        elif action == 9:
            _normal(self.comm)
            result = 0
        else:
            result = 0
        if release:
            self.finish(False)
        return result


class _Monitor(_Worker):
    def release(self) -> None:
        self.io(0, self.masks(0xB0))

    def sample(self) -> int:
        for row in range(3):
            base = 8 + row * 56
            result, reply = self.read(
                self.data[base], self.data[base + 1], _u32(self.data, base + 12), 2
            )
            if result:
                return 0x3FF
            self.data[base + 16 : base + 18] = reply
        return 0

    def support(self) -> int:
        _put(self.data, 0xB0, 0)
        result = _initialize(self.comm, self.context)
        if result:
            self.finish(False)
            return result
        result = _extended(self.comm)
        if result:
            self.finish(False)
            return result
        result, support = self.read(1, 1, 0, 32)
        if not result and not support[3] & 0x10:
            result = 3
        if not result:
            result, masks = self.read(0x28, 0x1F, 0, 8)
            if not result:
                self.data[0xB0:0xB4] = bytes(
                    (masks[0], masks[2], masks[4], masks[6] & 7)
                )
                result, support = self.read(0x1B, 0, 0, 32)
                if not result:
                    for row in range(3):
                        base = 8 + row * 56
                        if self.data[base + 1] != 0x9B:
                            continue
                        index = _u32(self.data, base + 4)
                        if index >= 32:
                            raise ValueError("FCHV28 support index exceeds bitmap")
                        if (
                            self.data[base + 1] == 0x9B
                            and support[index] & self.data[base + 8]
                            != self.data[base + 8]
                        ):
                            result = 3
                            break
                    if not result:
                        if support[23] & 4:
                            result, support = self.read(0x1B, 0xCF, 0, 5)
                            if not result and (
                                not support[0] & 0x80 or not support[4] & 4
                            ):
                                result = 3
                        else:
                            result = 3
        normal = self.finish()
        return result or normal

    def control(self, initialize: bool) -> int:
        masks = self.masks(0xB0)
        if initialize:
            result = _initialize(self.comm, self.context)
            if result:
                self.finish(False)
                return result
            result = _extended(self.comm)
            if result:
                self.finish(False)
                return result
            if self.routine(1, 0x1A, b"\x01"):
                self.finish()
                return 0x3F0
            base = 8
            result, reply = self.read(
                self.data[base], self.data[base + 1], _u32(self.data, base + 12), 2
            )
            if result:
                self.finish()
                return 0x3F0
            self.data[24:26] = reply
            if int.from_bytes(reply, "big", signed=True) < -0xCCC:
                self.finish()
                return 0x3F4
        result = self.io(3, masks + masks)
        if result == 7:
            result = _status(self.comm.read_field("native_10b0"))
        if result:
            result = 0x3F1 if result == 105 else 0x3F0
        else:
            self.sleep(200)
            while True:
                status, reply = self.read(0x1B, 0xBE, 0, 8)
                if status:
                    result = 0x3F0
                    break
                self.start_timer()
                if all(
                    reply[1 + i * 2] & masks[1 + i * 2] & (7 if i == 3 else 255)
                    == masks[1 + i * 2] & (7 if i == 3 else 255)
                    for i in range(4)
                ):
                    return self.sample() if initialize else 0x402
                if self.elapsed() >= 5000:
                    result = 0x3F1
                    break
                self.sleep(200)
        self.io(0, masks)
        self.finish()
        return result

    def action(self, action: int) -> int:
        if action == 0:
            return self.support()
        if action == 1:
            return self.control(True)
        if action == 2:
            while True:
                result = self.sample()
                if result:
                    return result
                self.sleep(200)
                if _u32(self.data, 0xB4):
                    return 0
        if action == 3:
            self.release()
            self.finish()
            return 0x3F8
        if action == 4:
            self.io(3, bytes(8) + self.masks(0xB0))
            return 0x3FC
        return self.control(False)


def _run(export: str, args: tuple[object, ...], context: TYContext) -> int:
    kind = _EXPORTS.index(export)
    minimum = (0x38C, 0x38C, 0x24, 0xB8)[kind]
    if (
        type(args) is not tuple
        or len(args) != 1
        or type(args[0]) is not bytearray
        or not minimum <= len(args[0]) <= 65536
    ):
        raise ValueError(
            f"FCHV action requires one bounded mutable {minimum:#x}-byte native block"
        )
    state_key = f"fchv-plus:{context.module_sha256}"
    if not context.state.get(state_key + ":outputs") and not context.state.get(
        state_key + ":retained"
    ):
        _check(context)
    worker_type = _Valves if kind < 2 else _Pressure if kind == 2 else _Monitor
    worker = worker_type(args[0], context, context.comm("native:101392d0"))
    try:
        _check(context)
        action = _u32(args[0], 0)
        return (
            worker.action(action, kind == 1)
            if isinstance(worker, _Valves)
            else worker.action(action)
        )
    except BaseException as error:
        if not worker.closed:
            worker.fault_cleanup(
                0x384 if kind < 2 else 0x20 if kind == 2 else 0xB0, error
            )
        raise


def run_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    if (
        export not in supported_exports(context.module_sha256)
        or hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256
    ):
        raise TYSourceError("Exact reviewed Plus FCHV source/export identity required")
    return _run(export, args, context)
