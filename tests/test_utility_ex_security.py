"""Authored vectors for source-bound MS2 security; no OEM payloads or keys."""

from __future__ import annotations

import struct
import unittest
from collections import deque
from typing import cast
from unittest.mock import patch

from scripts import utility_ex_security as security
from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import SHA_18_TY, SHA_PLUS_TY, TYContext, TYSourceError

KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
SEED = bytes.fromhex("00112233445566778899aabbccddeeff")
CIPHER = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")


class Context:
    def __init__(self, source: str = SHA_18_TY) -> None:
        self.module_sha256, self.module_bytes = source, b"authored"
        self.state: dict[str, object] = {}
        self.cancelled = False
        self.now = 0
        self.tick_step = 0
        self.sleeps: list[int] = []

    def ticks(self) -> int:
        now = self.now
        self.now += self.tick_step
        return now

    def is_cancelled(self) -> bool:
        return self.cancelled

    def native_sleep(self, ms: int) -> None:
        self.sleeps.append(ms)
        self.now += ms


class Comm:
    def __init__(self, replies: list[tuple[int, bytes]]) -> None:
        self.replies = deque(replies)
        self.calls: list[bytes | bool] = []
        self.keepalive_status = 0
        self.fault: Exception | None = None

    def exchange(self, request: bytes) -> tuple[int, bytes]:
        self.calls.append(request)
        if self.fault:
            error, self.fault = self.fault, None
            raise error
        return self.replies.popleft()

    def keepalive(self, enabled: bool, wait: bool = False) -> int:
        self.calls.append(enabled)
        return self.keepalive_status


def wire(ctx: Context, comm: Comm, attempts: int = 1, delay: int = 0) -> security._Wire:
    return security._Wire(
        cast(TYContext, ctx), cast(security.SecurityComm, comm), attempts, delay, 100
    )


def setup(capability: int) -> list[tuple[int, bytes]]:
    return [
        (0, b"\x50\x01\0\0\0\0"),
        (0, b"\x50\x03\0\0\0\0"),
        (0, b"\x62\x02\x40\0\x01\x80\0"),
        (0, b"\x62\x02\x50\x80"),
        (0, bytes((0x62, 2, 0x51, capability))),
    ]


class SecurityTests(unittest.TestCase):
    def test_nist_encrypt_decrypt_and_input_extent(self) -> None:
        aes = security.native_aes128_ecb_block
        self.assertEqual(aes(KEY, SEED), CIPHER)
        self.assertEqual(aes(KEY, CIPHER, encrypt=False), SEED)
        with self.assertRaises(ValueError):
            aes(KEY, SEED[:-1])

    def test_source_mismatch_rejected_before_wire_or_secret_read(self) -> None:
        ctx, comm = Context(), Comm([])
        with self.assertRaises(TYSourceError):
            security.security_access(
                cast(TYContext, ctx),
                cast(security.SecurityComm, comm),
                level=3,
                key=KEY,
                preliminary_comm=cast(security.SecurityComm, comm),
                expected_capability=4,
            )
        with self.assertRaises(TYSourceError):
            security.source_key(cast(TYContext, ctx), 0x100, 16)
        self.assertEqual(comm.calls, [])

    def test_authored_pe_projection_operand_order_and_bounds(self) -> None:
        image = bytearray(0x300)
        struct.pack_into("<I", image, 0x3C, 0x80)
        struct.pack_into("<H", image, 0x86, 1)
        struct.pack_into("<IIII", image, 0xA0, 0x100, 0x1000, 0x100, 0x200)
        image[0x200:] = bytes(range(256))
        ctx = Context()
        ctx.module_bytes = bytes(image)
        context = cast(TYContext, ctx)
        with patch.object(security, "_authenticate"):
            self.assertEqual(security.source_key(context, 0x1000, 16), bytes(range(16)))
            self.assertEqual(
                security.source_immediate_key(
                    context, ((0x1030, 4), (0x1020, 4), (0x1010, 4), (0x1000, 4))
                ),
                b'0123 !"#' + bytes(range(16, 20)) + bytes(range(4)),
            )
            for operands in ((), ((0x1000, 3),), ((0x1000, 4),)):
                with self.assertRaises(ValueError):
                    security.source_immediate_key(context, operands)
            with self.assertRaises(TYSourceError):
                security.source_key(context, 0x10F8, 16)

    def test_complete_two_authentication_wire_with_real_aes(self) -> None:
        for source in (SHA_18_TY, SHA_PLUS_TY):
            with self.subTest(source=source):
                ctx = Context(source)
                comm = Comm(
                    setup(4)
                    + [
                        (0, b"\x67\x07" + SEED),
                        (0, b"\x67\x08"),
                        (0, b"\x71\x01\x02\x00"),
                    ]
                    + setup(0x10)
                    + [(0, b"\x67\x03" + CIPHER), (0, b"\x67\x04")]
                )
                with (
                    patch.object(security, "_authenticate"),
                    patch.object(security, "source_immediate_key", return_value=KEY),
                ):
                    status = security.security_access(
                        cast(TYContext, ctx),
                        cast(security.SecurityComm, comm),
                        level=3,
                        key=KEY,
                        preliminary_comm=cast(security.SecurityComm, comm),
                        expected_capability=0x10,
                        direction=2,
                    )
                self.assertEqual(status, 0)
                self.assertIn(b"\x27\x08" + CIPHER, comm.calls)
                self.assertIn(b"\x27\x04" + SEED, comm.calls)
                self.assertEqual(comm.calls.count(True), 2)
                self.assertFalse(comm.replies)

    def test_distinct_preliminary_and_selected_communication_and_cleanup(self) -> None:
        ctx = Context()
        preliminary = Comm(
            setup(4)
            + [
                (0, b"\x67\x07" + bytes(16)),
                (0, b"\x71\x01\x02\x00"),
                (0, b"\x50\x01\0\0\0\0"),
            ]
        )
        selected = Comm(setup(0x10) + [(2, b"")])
        with (
            patch.object(security, "_authenticate"),
            patch.object(security, "source_immediate_key", return_value=KEY),
        ):
            result = security.security_access(
                cast(TYContext, ctx),
                cast(security.SecurityComm, selected),
                preliminary_comm=cast(security.SecurityComm, preliminary),
                level=3,
                key=KEY,
                expected_capability=0x10,
            )
        self.assertEqual(result, 2)
        self.assertEqual(preliminary.calls[-1], b"\x10\x01")
        self.assertEqual(selected.calls[-1], b"\x27\x03")
        self.assertIn(b"\x31\x01\x02\x00", preliminary.calls)
        self.assertNotIn(b"\x31\x01\x02\x00", selected.calls)

    def test_native_failures_restore_arg8_without_overwriting_status(self) -> None:
        vectors = [
            (setup(4)[:2] + [(0, b"\x62\x02\x40\0\0\0\0")], 22),
            (setup(4) + [(2, b"")], 2),
            (setup(4) + [(0, b"\x67\x07" + SEED), (0, b"\x67\x09")], 3),
            (setup(4) + [(0, b"\x67\x07" + bytes(16)), (0, b"\x71\x01\x02")], 3),
        ]
        for replies, expected in vectors:
            ctx, comm = Context(), Comm(replies + [(7, b"\x7f\x10\x22")])
            with (
                patch.object(security, "_authenticate"),
                patch.object(security, "source_immediate_key", return_value=KEY),
            ):
                status = security.security_access(
                    cast(TYContext, ctx),
                    cast(security.SecurityComm, comm),
                    preliminary_comm=cast(security.SecurityComm, comm),
                    level=3,
                    key=KEY,
                    expected_capability=0x10,
                )
            self.assertEqual(status, expected)
            self.assertEqual(comm.calls[-1], b"\x10\x01")

    def test_cleanup_host_fault_preserves_native_failure(self) -> None:
        ctx, comm = Context(), Comm([])
        with (
            patch.object(security, "_authenticate"),
            patch.object(
                comm,
                "exchange",
                side_effect=setup(4)[:2]
                + [(2, b""), OSError("authored cleanup fault")],
            ),
        ):
            self.assertEqual(
                security.security_access(
                    cast(TYContext, ctx),
                    cast(security.SecurityComm, comm),
                    preliminary_comm=cast(security.SecurityComm, comm),
                    level=3,
                    key=KEY,
                    expected_capability=0x10,
                ),
                22,
            )

    def test_ignored_initial_session_status_and_zero_seed_capability_bypass(
        self,
    ) -> None:
        ctx = Context()
        replies = (
            [(2, b""), (7, b"\x7f\x10\x22")]
            + setup(4)[2:]
            + [(0, b"\x67\x07" + bytes(16)), (0, b"\x71\x01\x02\x00")]
            + setup(0x82)
            + [(0, b"\x67\x03" + bytes(16))]
        )
        comm = Comm(replies)
        with (
            patch.object(security, "_authenticate"),
            patch.object(security, "source_immediate_key", return_value=KEY),
        ):
            self.assertEqual(
                security.security_access(
                    cast(TYContext, ctx),
                    cast(security.SecurityComm, comm),
                    preliminary_comm=cast(security.SecurityComm, comm),
                    level=3,
                    key=KEY,
                    expected_capability=0x10,
                ),
                0,
            )
        self.assertFalse(
            any(
                isinstance(call, bytes) and call[:2] in (b"\x27\x04", b"\x27\x08")
                for call in comm.calls
            )
        )

    def test_capability_each_branch(self) -> None:
        vectors = [
            ([(2, b"")], 1, (22, 0)),
            ([(7, b"\x7f\x22\x31")], 2, (0, 0)),
            ([(0, b"\x62\x02\x40\0\0\0\0")], 1, (22, 0)),
            ([(0, b"\x62\x02\x40\0\x01\0\0"), (0, b"\x62\x02\x50\x80")], 2, (22, 0)),
            ([(0, b"\x62\x02\x40\0\x01\x80\0"), (2, b"")], 1, (2, 0)),
            ([(0, b"\x62\x02\x40\0\x01\x80\0"), (0, b"\x62\x02\x50\0")], 2, (0, 0)),
            (
                [
                    (0, b"\x62\x02\x40\0\x01\x80\0"),
                    (0, b"\x62\x02\x50\x80"),
                    (0, b"\x62\x02\x51\x82"),
                ],
                1,
                (0, 0x82),
            ),
        ]
        for replies, mode, result in vectors:
            self.assertEqual(wire(Context(), Comm(replies)).capability(mode), result)

    def test_seed_zero_echo_short_and_capability(self) -> None:
        for reply, expected, status in [
            (b"\x67\x03" + bytes(16), 4, 0),
            (b"\x67\x02" + SEED, 4, 3),
            (b"\x67\x03" + SEED[:-1], 4, 3),
            (b"\x67\x03" + SEED, 5, 3),
        ]:
            comm = Comm([(0, reply)])
            self.assertEqual(
                wire(Context(), comm).authenticate(3, KEY, expected, 1, 4, 1), status
            )
            self.assertEqual(len(comm.calls), 1)

    def test_three_key_failures_reread_seed_but_seed_failure_does_not(self) -> None:
        comm = Comm([(0, b"\x67\x03" + SEED), (7, b"\x7f\x27\x35")] * 3)
        ctx = Context()
        self.assertEqual(wire(ctx, comm).authenticate(3, KEY, 4, 1, 4, 1), 7)
        self.assertEqual(len(comm.calls), 6)
        self.assertEqual(ctx.state["native_global:1012ae38"], 0x35)
        comm = Comm([(2, b"")])
        self.assertEqual(wire(Context(), comm).authenticate(3, KEY, 4, 1, 4, 1), 2)
        self.assertEqual(len(comm.calls), 1)

    def test_exchange_retry_status_nrc_and_native_zero_attempts(self) -> None:
        ctx, comm = Context(), Comm([(2, b""), (7, b"\x7f\x27\x78"), (0, b"ok")])
        self.assertEqual(wire(ctx, comm, 3, 4).exchange(b"x"), (0, b"ok"))
        self.assertEqual(ctx.sleeps, [4, 4])
        self.assertEqual(wire(ctx, comm, 0).exchange(b"never"), (0, b""))
        self.assertNotIn(b"never", comm.calls)
        plus = Context(SHA_PLUS_TY)
        self.assertEqual(
            wire(plus, Comm([(7, b"\x7f\x27\x35")])).exchange(b"x"),
            (7, b"\x7f\x27\x35"),
        )
        self.assertEqual(plus.state["native_global:10153554"], 0x35)

    def test_crypto_fault_maps_native_error_and_does_not_send_key(self) -> None:
        comm = Comm([(0, b"\x67\x03" + SEED)])
        with patch.object(
            security,
            "native_aes128_ecb_block",
            side_effect=ValueError("authored provider fault"),
        ):
            self.assertEqual(wire(Context(), comm).authenticate(3, KEY, 4, 1, 4, 1), 3)
        self.assertEqual(len(comm.calls), 1)

    def test_reply_validation_and_postsession_order(self) -> None:
        comm = Comm([(0, b"\x50\x03")])
        self.assertEqual(wire(Context(), comm).session(3), 3)
        self.assertEqual(comm.calls, [b"\x10\x03", True])
        comm = Comm([(0, b"\x67\x03" + SEED), (0, b"\x67\x05")])
        self.assertEqual(wire(Context(), comm).authenticate(3, KEY, 4, 1, 4, 1), 3)
        with self.assertRaises(TYSourceError):
            wire(Context(), Comm([(0, bytes(0x1021))])).exchange(b"x")

    def test_cancel_timeout_and_native_fault_restore_session(self) -> None:
        for error in (Cancelled, TimeoutError, OSError):
            ctx, comm = Context(), Comm([(0, b"\x50\x01\0\0\0\0")])
            if error is Cancelled:
                ctx.cancelled = True
            elif error is OSError:
                comm.fault = OSError("authored transport fault")
            else:
                ctx.tick_step = 100
            with patch.object(security, "_authenticate"), self.assertRaises(error):
                security.security_access(
                    cast(TYContext, ctx),
                    cast(security.SecurityComm, comm),
                    level=3,
                    key=KEY,
                    preliminary_comm=cast(security.SecurityComm, comm),
                    expected_capability=4,
                    timeout_ms=50,
                )
            self.assertEqual(comm.calls[-1], b"\x10\x01")

    def test_legacy_round_directions_and_permutations(self) -> None:
        for reverse, expected in ((False, "ab856fac"), (True, "3d13e724")):
            self.assertEqual(
                security.legacy_key(
                    bytes.fromhex("12345678"),
                    bytes(range(32)),
                    bytes(range(32)),
                    reverse=reverse,
                ),
                bytes.fromhex(expected),
            )
        # Authored zero substitution makes every round a plain half-word swap.
        for reverse in (False, True):
            self.assertEqual(
                security.legacy_key(
                    bytes.fromhex("12345678"),
                    bytes(range(32)),
                    bytes(32),
                    reverse=reverse,
                ),
                bytes.fromhex("56781234"),
            )
        for level, outgoing in (
            (1, (0, 1, 2, 3)),
            (3, (3, 1, 2, 0)),
            (5, (2, 0, 3, 1)),
            (9, (0, 1, 2, 3)),
        ):
            comm = Comm(
                [
                    (0, bytes((0x67, level)) + b"abcd"),
                    (0, bytes((0x67, {1: 2, 3: 4, 5: 6, 9: 10}[level]))),
                ]
            )
            with (
                patch.object(security, "_module_data", return_value=bytes(32)),
                patch.object(security, "legacy_key", return_value=b"1234") as primitive,
            ):
                self.assertEqual(
                    wire(Context(), comm).authenticate(level, bytes(32), 0, 2, 0, 2), 0
                )
                assert isinstance(comm.calls[-1], bytes)
                self.assertEqual(
                    comm.calls[-1][2:], bytes(b"1234"[i] for i in outgoing)
                )  # type: ignore[index]
                self.assertTrue(primitive.call_args.kwargs["reverse"])


if __name__ == "__main__":
    unittest.main()
