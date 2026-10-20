"""Exact supplied TY MS2 security helpers over primitive diagnostic exchanges.

Secrets are projected from authenticated caller-owned PE bytes, never bundled here.
"""

from __future__ import annotations

import hashlib
from contextlib import suppress
from typing import Protocol

from scripts.programming_2026_common import native_aes128_ecb_block
from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import (
    SHA_18_TY,
    SHA_PLUS_TY,
    TYComm,
    TYContext,
    TYSourceError,
)
from scripts.utility_ex_ty_retained_03 import _module_data


class SecurityComm(TYComm, Protocol):
    def keepalive(self, enabled: bool, wait: bool = False) -> int | None: ...


# Addresses of immediate operands, not their source-owned contents.
_PRELIMINARY = {
    SHA_18_TY: ((0xC6369, 1),) + tuple((rva, 1) for rva in range(0xC6371, 0xC63B8, 5)),
    SHA_PLUS_TY: tuple((rva, 4) for rva in range(0xD0CD6, 0xD0CF5, 10)),
}
_TABLES = {SHA_18_TY: 0xF8790, SHA_PLUS_TY: 0xF4258}


def _authenticate(context: TYContext) -> None:
    if context.module_sha256 not in _PRELIMINARY or (
        hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256
    ):
        raise TYSourceError("MS2 security requires the exact supplied TY source image")


def source_key(context: TYContext, rva: int, size: int) -> bytes:
    """Project a caller's native data key only after exact source authentication."""
    _authenticate(context)
    if type(rva) is not int or rva < 0 or size not in (16, 32):
        raise ValueError("Native source key requires a nonnegative RVA and 16/32 bytes")
    return _module_data(context.module_bytes, rva, size)


def source_immediate_key(
    context: TYContext, operands: tuple[tuple[int, int], ...]
) -> bytes:
    """Project code-immediate operands in native destination order, without execution."""
    _authenticate(context)
    if (
        not operands
        or any(
            type(rva) is not int or rva < 0 or width not in (1, 2, 4)
            for rva, width in operands
        )
        or sum(width for _, width in operands) not in (16, 32)
    ):
        raise ValueError("Native key operands must describe exactly 16/32 bytes")
    return b"".join(
        _module_data(context.module_bytes, rva, width) for rva, width in operands
    )


def legacy_key(
    seed: bytes, key: bytes, table: bytes, *, reverse: bool = False
) -> bytes:
    """c6a60/c6ac0 and d0060/d0030: sixteen source-key Feistel rounds."""
    if len(seed) != 4 or len(key) != 32 or len(table) != 32:
        raise ValueError("Native legacy security requires 4/32/32-byte inputs")
    state = int.from_bytes(seed, "big")
    words = [int.from_bytes(key[i : i + 2], "big") for i in range(0, 32, 2)]
    for word in reversed(words) if reverse else words:
        repeated = ((state & 0xFFFF) ^ word) * 0x10001
        substituted = 0
        for _ in range(4):
            substituted = ((substituted >> 4) | (table[repeated & 31] << 12)) & 0xFFFF
            repeated >>= 4
        mixed = (substituted * 0x10001) >> 3
        state = (
            ((state << 16) & 0xFFFFFFFF) + ((mixed & 0xFFFF) ^ (state >> 16))
        ) & 0xFFFFFFFF
    result = state.to_bytes(4, "big")
    return result[2:] + result[:2]


class _Wire:
    def __init__(
        self,
        context: TYContext,
        comm: SecurityComm,
        attempts: int,
        delay_ms: int,
        timeout_ms: int,
    ) -> None:
        self.context, self.comm = context, comm
        self.attempts, self.delay_ms = attempts, delay_ms
        self.started, self.timeout_ms = context.ticks(), timeout_ms

    def check(self) -> None:
        if self.context.is_cancelled():
            raise Cancelled("MS2 security cancelled")
        if (self.context.ticks() - self.started) & 0xFFFFFFFF >= self.timeout_ms:
            raise TimeoutError("MS2 security deadline expired")

    def exchange(self, request: bytes, *, cleanup: bool = False) -> tuple[int, bytes]:
        status, reply = 0, b""
        for _ in range(self.attempts):
            if not cleanup:
                self.check()
            status, reply = self.comm.exchange(request)
            if len(reply) > 0x1020:
                raise TYSourceError("MS2 response exceeded native receive buffer")
            if status not in (2, 7):
                return status, reply
            self.context.native_sleep(self.delay_ms)
        if status == 7:
            key = "native_global:" + (
                "1012ae38" if self.context.module_sha256 == SHA_18_TY else "10153554"
            )
            self.context.state[key] = reply[2] if len(reply) > 2 else 0
        return status, reply

    def session(self, mode: int, *, cleanup: bool = False) -> int:
        status, reply = self.exchange(bytes((0x10, mode)), cleanup=cleanup)
        if status:
            return status
        if mode == 3:
            status = self.comm.keepalive(True) or 0
            if status:
                return status
        return 0 if len(reply) >= 6 and reply[1] == mode else 3

    def capability(self, mode: int) -> tuple[int, int]:
        def read(identifier: int, minimum: int) -> tuple[int, bytes]:
            request = b"\x22" + identifier.to_bytes(2, "big")
            status, reply = self.exchange(request)
            if not status and (len(reply) < minimum or reply[1:3] != request[1:]):
                status = 3
            return status, reply

        status, reply = read(0x240, 7)
        if status:
            reply = bytes(7)
        if reply[4] & 1:
            available = reply[5] & 0x80
            status, reply = read(0x250, 4)
            if status:
                return status, 0
            if reply[3] & 0x80:
                if not available:
                    return 0x16, 0
                status, reply = read(0x251, 4)
                return status, reply[3] if not status else 0
        return (0 if mode == 2 else 0x16), 0

    def authenticate(
        self,
        level: int,
        key: bytes,
        expected: int,
        mode: int,
        capability: int,
        direction: int,
    ) -> int:
        count = 16 if mode == 1 else 4
        answer_level = {1: 2, 3: 4, 5: 6, 7: 8}.get(level, 10)
        for _ in range(3):
            status, reply = self.exchange(bytes((0x27, level)))
            if status:
                return status
            if len(reply) < count + 2 or reply[1] != level:
                return 3
            seed = reply[2 : count + 2]
            if not any(seed):
                return 0
            if mode == 1:
                if expected != capability:
                    return 3
                try:
                    answer = native_aes128_ecb_block(key, seed, encrypt=direction == 1)
                except ValueError:
                    return 3
            else:
                seed = bytes(
                    seed[i]
                    for i in {3: (2, 0, 1, 3), 5: (2, 1, 3, 0)}.get(level, (0, 1, 2, 3))
                )
                table = _module_data(
                    self.context.module_bytes, _TABLES[self.context.module_sha256], 32
                )
                answer = legacy_key(seed, key, table, reverse=direction == 2)
                answer = bytes(
                    answer[i]
                    for i in {4: (3, 1, 2, 0), 6: (2, 0, 3, 1)}.get(
                        answer_level, (0, 1, 2, 3)
                    )
                )
            status, reply = self.exchange(bytes((0x27, answer_level)) + answer)
            if not status:
                return 0 if len(reply) >= 2 and reply[1] == answer_level else 3
        return status


def security_access(
    context: TYContext,
    comm: SecurityComm,
    *,
    level: int,
    key: bytes,
    preliminary_comm: SecurityComm,
    expected_capability: int,
    mode: int = 1,
    attempts: int = 1,
    delay_ms: int = 0,
    direction: int = 1,
    timeout_ms: int = 180000,
) -> int:
    """c5e80/d0e40: preliminary level7/routine0200, then selected second auth.

    ``key`` must be projected from this exact source by its owning native caller.
    ``preliminary_comm`` is native argument8, ``comm`` is argument7.
    Session errors in the two initial session calls are deliberately discarded.
    The caller retains connection/finalization ownership.
    """
    _authenticate(context)
    for value in (level, expected_capability):
        if type(value) is not int or not 0 <= value <= 255:
            raise ValueError("Native security level/capability must be bytes")
    if (
        type(mode) is not int
        or not 1 <= mode <= 0xFFFFFFFF
        or type(key) is not bytes
        or len(key) != (16 if mode == 1 else 32)
    ):
        raise ValueError("Native security mode/key extent differs")
    if (
        any(
            type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (attempts, delay_ms, timeout_ms, direction)
        )
        or timeout_ms == 0
    ):
        raise ValueError("Native security timing and direction must be uint32")
    wire = _Wire(context, comm, attempts, delay_ms, timeout_ms)
    preliminary_wire = _Wire(context, preliminary_comm, attempts, delay_ms, timeout_ms)
    try:
        for preliminary in (True, False):
            selected_wire = preliminary_wire if preliminary else wire
            selected_wire.session(1)
            selected_wire.session(3)
            status, capability = selected_wire.capability(1 if preliminary else mode)
            if not status:
                material = (
                    source_immediate_key(context, _PRELIMINARY[context.module_sha256])
                    if preliminary
                    else key
                )
                status = selected_wire.authenticate(
                    7 if preliminary else level,
                    material,
                    4 if preliminary else expected_capability,
                    1 if preliminary else mode,
                    capability,
                    1 if preliminary else direction,
                )
            if not status and preliminary:
                status, reply = preliminary_wire.exchange(b"\x31\x01\x02\x00")
                if not status and (len(reply) < 4 or reply[1:4] != b"\x01\x02\x00"):
                    status = 3
            if status:
                with suppress(Exception):
                    preliminary_wire.session(1, cleanup=True)
                return status
        return 0
    except BaseException:
        # Host cancellation/fault cleanup keeps the primary exception visible.
        with suppress(Exception):
            preliminary_wire.session(1, cleanup=True)
        raise
