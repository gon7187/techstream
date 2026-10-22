"""Authored literal native DSC frames and buffer mutations; no OEM fixtures."""

from __future__ import annotations

import struct
import unittest
from typing import cast
from unittest.mock import patch

from scripts.toyota_session import Cancelled
from scripts.utility_ex_comm import UtilityExComm
from scripts.utility_ex_ty import SHA_12_TY, SHA_18_TY, SHA_PLUS_TY, TYSourceError
from scripts.utility_ex_ty_retained_10 import (
    _d15,
    _pi,
    _pi_absolute,
    _pi_support,
    _szeiu,
    _vc5,
    _vc5_reset,
    _vc5_rewrite,
    _vc34,
    _vc_learn,
    _vc_support,
    _vif2,
    _word,
    run_body,
    supported_exports,
)
from tests.test_utility_ex_ty import Comm, Context


class SessionComm(Comm):
    def select_protocol(self, kind):
        self.events.append(("protocol", kind))
        return 0

    def configure_target(self, first, second=0, third=0, fourth=0, fifth=0):
        self.events.append(("configure_target", first, second, third, fourth, fifth))

    def configure_keepalive(self, interval_ms, request, response_size, flags):
        self.events.append(
            ("keepalive_config", interval_ms, request, response_size, flags)
        )

    def keepalive(self, enabled, wait=False):
        self.events.append(("keepalive", enabled, wait))
        return 0

    def read_field(self, field):
        if field == "native_10a4":
            self.events.append(("read_field", field))
            return 255
        return super().read_field(field)

    def select_target(self, identifier, second=0):
        self.events.append(("target", identifier, second))

    def session(self, mode, keepalive=1, **kwargs):
        self.events.append(("session", mode, keepalive))
        return 0


class RetainedDSCTests(unittest.TestCase):
    def context(self, replies=(), sha=SHA_18_TY):
        context = Context()
        context.controller = SessionComm(list(replies))
        context.module_sha256 = sha
        return context

    def run_native(self, name, buffer, context):
        with patch("scripts.utility_ex_ty_retained_10.hashlib.sha256") as digest:
            digest.return_value.hexdigest.return_value = context.module_sha256
            return run_body(name, (buffer,), context)

    def test_literal_read_all_sources_same_buffer(self):
        for sha in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY):
            with self.subTest(sha=sha):
                replies = []
                for identifier, count in (
                    (0x55, 6),
                    (0x56, 6),
                    (0x57, 6),
                    (0x58, 6),
                    (0x3F, 9),
                    (0x40, 9),
                ):
                    replies.append(
                        (
                            0,
                            bytes((0x62, 0x28, identifier))
                            + bytes((identifier,)) * count,
                        )
                    )
                context = self.context(replies, sha)
                buffer = bytearray(42)
                self.assertEqual(
                    self.run_native("Ex2DSC_01_SendMessage", buffer, context), 0
                )
                self.assertEqual(
                    buffer,
                    b"U" * 6 + b"V" * 6 + b"W" * 6 + b"X" * 6 + b"?" * 9 + b"@" * 9,
                )
                self.assertEqual(
                    [e for e in context.controller.events if isinstance(e, bytes)],
                    [
                        b"\x22\x28\x55",
                        b"\x22\x28\x56",
                        b"\x22\x28\x57",
                        b"\x22\x28\x58",
                        b"\x22\x28\x3f",
                        b"\x22\x28\x40",
                    ],
                )
                self.assertEqual(context.controller.events[-1], "finalize")

    def test_malformed_short_or_wrong_did_preserves_buffer(self):
        for reply in (b"\x62\x28\x55", b"\x62\x28\x56abcdef"):
            context = self.context([(0, reply)])
            buffer = bytearray(b"x" * 42)
            self.assertEqual(
                self.run_native("Ex2DSC_01_SendMessage", buffer, context), 3
            )
            self.assertEqual(buffer, b"x" * 42)
            self.assertEqual(context.state["native_global:10118e38"], 3)

    def test_fault_preserves_completed_record(self):
        context = self.context([(0, b"\x62\x28\x55abcdef"), (7, b"")])
        buffer = bytearray(b"x" * 42)
        self.assertEqual(self.run_native("Ex2DSC_01_SendMessage", buffer, context), 7)
        self.assertEqual(buffer, b"abcdef" + b"x" * 36)
        self.assertEqual(context.controller.events[-1], "finalize")

    def test_clear_pending_then_complete(self):
        context = self.context(
            [(0, b"\x71\x01\x30\x02\x00"), (0, b"\x71\x01\x30\x02\x10"), (0, b"\x54")]
        )
        self.assertEqual(
            self.run_native("Ex2DSC_02_SendMessage", bytearray([2]), context), 0
        )
        self.assertEqual(
            [e for e in context.controller.events if isinstance(e, bytes)],
            [b"\x31\x01\x30\x02", b"\x31\x01\x30\x02", b"\x14\xff\xff\xff"],
        )

    def test_clear_retry_exactly_four(self):
        context = self.context([(0, b"\x71\x01\x30\x02\x00")] * 4)
        self.assertEqual(
            self.run_native("Ex2DSC_02_SendMessage", bytearray([2]), context), 1002
        )
        self.assertEqual(
            len([e for e in context.controller.events if isinstance(e, bytes)]), 4
        )

    def test_vc_count_get_exact_offset_and_native_zero_fill(self):
        for sha in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY):
            context = self.context(
                [(0, b"\xe9\x78" + b"x" * 9 + b"\x12\x34\x56\x78")], sha
            )
            buffer = bytearray(12)
            self.assertEqual(
                self.run_native("Ex2VC_01_GetActuationCnt", buffer, context), 0
            )
            self.assertEqual(buffer[4:8], b"\x12\x34\x56\x78")
        context = self.context([(0, b"\xe9\x78")])
        buffer = bytearray(b"x" * 12)
        self.assertEqual(
            self.run_native("Ex2VC_01_GetActuationCnt", buffer, context), 0
        )
        self.assertEqual(buffer[4:8], b"\0" * 4)

    def test_vc_count_write_build_delta_and_literal_packet(self):
        for sha, status in ((SHA_12_TY, 0), (SHA_18_TY, 0), (SHA_PLUS_TY, 0)):
            context = self.context([(0, b"\x7b\x78")], sha)
            buffer = bytearray((15).to_bytes(4, "little") + b"xxxx" + b"ABCD")
            self.assertEqual(
                self.run_native("Ex2VC_01_WriteActuationCnt", buffer, context), status
            )
            self.assertIn(
                b"\x3b\x78\x20" + b"\0" * 8 + b"ABCD", context.controller.events
            )
        context = self.context([(7, b"")])
        self.assertEqual(
            self.run_native("Ex2VC_01_WriteActuationCnt", bytearray(12), context), 7
        )

    def test_hvb_retains_then_polls_same_native_manager(self):
        for sha in (SHA_18_TY, SHA_PLUS_TY):
            context = self.context(
                [
                    (0, b"\x71\x01\x11\x25"),
                    (0, b"\x71\x03\x11\x25\x00"),
                    (0, b"\x71\x03\x11\x25\x02"),
                ],
                sha,
            )
            buffer = bytearray(11)
            self.assertEqual(
                self.run_native("Ex2HVB_10_SendMessage", buffer, context), 1005
            )
            self.assertNotIn("finalize", context.controller.events)
            buffer[:4] = (1).to_bytes(4, "little")
            self.assertEqual(
                self.run_native("Ex2HVB_10_SendMessage", buffer, context), 1022
            )
            self.assertNotIn("finalize", context.controller.events)
            self.assertEqual(
                sum(e == ("init", 0) for e in context.controller.events), 1
            )
            buffer[4] = 1
            self.assertEqual(
                self.run_native("Ex2HVB_10_SendMessage", buffer, context), 0
            )
            self.assertEqual(context.controller.events[-1], "finalize")

    def test_hvb_final_status_and_second_payload(self):
        for sha in (SHA_18_TY, SHA_PLUS_TY):
            for status, expected in (
                (0, 1007),
                (1, 1006),
                (2, 1006),
                (3, 1006),
                (4, 3),
            ):
                context = self.context(
                    [(0, bytes((0x62, 0x18, 0x51, status, 0x81, 0x82)))], sha
                )
                buffer = bytearray((2).to_bytes(4, "little") + b"\0" * 7)
                self.assertEqual(
                    self.run_native("Ex2HVB_11_SendMessage", buffer, context), expected
                )
                self.assertEqual(buffer[9:11], b"\x81\x82")
                self.assertEqual(context.controller.events[-1], "finalize")
                self.assertNotIn(("init", 0), context.controller.events)

    def test_hvb_fault_and_cancel_close_retained_manager(self):
        context = self.context([(7, b"")])
        buffer = bytearray((1).to_bytes(4, "little") + b"\0" * 7)
        self.assertEqual(
            self.run_native("Ex2HVB_10_SendMessage", buffer, context), 1004
        )
        self.assertEqual(context.controller.events[-1], "finalize")
        context = self.context([(0, b"\x71\x03\x11\x25\x00")])
        original_exchange = context.controller.exchange

        def cancel_after_exchange(request):
            result = original_exchange(request)
            context.cancelled = True
            return result

        context.controller.exchange = cancel_after_exchange
        with self.assertRaises(Cancelled):
            self.run_native("Ex2HVB_10_SendMessage", buffer, context)
        self.assertEqual(context.controller.events[-1], "finalize")

    def test_vc_support_literal_sparse_offsets(self):
        context = self.context()
        raw = bytearray(40)
        raw[1] = 13
        raw[2:15] = b"\x20" + b"\xff" * 12
        offsets = tuple(0 if i == 0x78 else 0x1020 for i in range(256))
        context.controller.support_snapshot = lambda kind: (0, bytes(raw), offsets)
        buffer = bytearray(12)
        self.assertEqual(_vc_support(context, context.controller, buffer, False), 0)
        self.assertEqual(buffer[:4], b"\x0f\0\0\0")
        raw[13] = 0
        self.assertEqual(_vc_support(context, context.controller, buffer, False), 22)

    def test_vc_zero_point_three_consecutive_then_stop(self):
        context = self.context(
            [
                (0, b"\x7b\x41"),
                (0, b"\x61\xcc\x63"),
                (0, b"\x61\xcc\x64"),
                (0, b"\x61\xcc\x65"),
                (0, b"\x7b\x41"),
            ]
        )
        buffer = bytearray(
            (3).to_bytes(4, "little")
            + (2).to_bytes(4, "little")
            + (4).to_bytes(4, "little")
        )
        self.assertEqual(_vc_learn(context, context.controller, buffer), 0)
        self.assertEqual(
            context.controller.events,
            [
                b"\x3b\x41\x02\x02",
                b"\x21\xcc",
                b"\x21\xcc",
                b"\x21\xcc",
                b"\x3b\x41\x02\0",
            ],
        )
        self.assertEqual(context.clock, 1000)

    def test_vc_zero_point_bad_poll_still_stops(self):
        context = self.context([(0, b"\x7b\x41"), (7, b""), (0, b"\x7b\x41")])
        buffer = bytearray(
            (3).to_bytes(4, "little")
            + (2).to_bytes(4, "little")
            + (4).to_bytes(4, "little")
        )
        self.assertEqual(_vc_learn(context, context.controller, buffer), 7)
        self.assertEqual(context.controller.events[-1], b"\x3b\x41\x02\0")

    def test_actual97_aggregator_preserves_mutable_native_buffer(self):
        from scripts.utility_ex_ty import run_body as selected_body

        context = self.context([(0, b"\xe9\x78" + b"\0" * 9 + b"ABCD")])
        buffer = bytearray(12)
        with patch("scripts.utility_ex_ty_retained_10.hashlib.sha256") as digest:
            digest.return_value.hexdigest.return_value = context.module_sha256
            self.assertEqual(
                selected_body("Ex2VC_01_GetActuationCnt", (buffer,), context), 0
            )
        self.assertEqual(buffer[4:8], b"ABCD")
        self.assertEqual(context.events[0], ("comm", "selected"))

    def test_pi_timestamp_literal_struct_and_status(self):
        for sha in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY):
            context = self.context([(0, b"\x61\x42\x34\x12\x40\x78\x56\x9a")], sha)
            buffer = bytearray(0x4F8)
            row = 0x4BC
            buffer[row + 1] = 0x42
            buffer[row + 0x1C : row + 0x20] = (6).to_bytes(4, "little")
            buffer[row + 0x20 : row + 0x24] = (2).to_bytes(4, "little")
            self.assertEqual(
                self.run_native("Ex2PI_01_GetCurrentTimeStamp", buffer, context), 0
            )
            self.assertEqual(
                buffer[row + 0x24 : row + 0x2B], b"\x34\x12\x40\0\x78\x56\x9a"
            )

    def test_pi_fuse_history_pending_negative_and_fault_flags(self):
        context = self.context(
            [(0, b"\x61\x42\x34\x12\0\x78\x56\x9a"), (7, b"\x7f\x21\x22"), (3, b"")]
        )
        buffer = bytearray(0x4BC)
        buffer[0x4B8:0x4BC] = (3).to_bytes(4, "little")
        for index in range(3):
            row = 8 + 60 * index
            buffer[row : row + 2] = b"\x01\x42"
            buffer[row + 0x1C : row + 0x20] = (6).to_bytes(4, "little")
            buffer[row + 0x20 : row + 0x24] = (2).to_bytes(4, "little")
        self.assertEqual(_pi(context, context.controller, buffer, False, 0), 10000)
        self.assertEqual(buffer[8], 1)
        self.assertEqual(buffer[68 + 0x24 + 20], 1)
        self.assertEqual(buffer[128], 0)
        self.assertEqual(_pi(context, context.controller, buffer, False, 7), 0)
        self.assertEqual([buffer[8], buffer[68], buffer[128]], [0, 0, 0])

    def test_pi_support_master_and_one_literal_row(self):
        context = self.context()
        raw = b"\x42\x04\xff\xff\xff\xff"
        offsets = tuple(0 if index == 0x42 else 0x1020 for index in range(256))
        context.controller.support_snapshot = lambda kind: (0, raw, offsets)
        buffer = bytearray(0x4F8)
        buffer[0x4B8:0x4BC] = (1).to_bytes(4, "little")
        for row in (8, 0x4BC):
            buffer[row + 1] = 0x42
            buffer[row + 8 : row + 12] = (1).to_bytes(4, "little")
            buffer[row + 12] = 0xFF
        self.assertEqual(_pi_support(context, context.controller, buffer), 0)
        for row in (8, 0x4BC):
            self.assertEqual(buffer[row], 1)
            self.assertEqual(buffer[row + 0x1C : row + 0x20], b"\x04\0\0\0")
            self.assertEqual(buffer[row + 0x20 : row + 0x24], b"\x02\0\0\0")
            self.assertEqual(buffer[row + 0x39], 1)

    def test_pi_reset_no_argument_and_native_error_translation(self):
        for reply, native_error, expected in (
            ((0, b"\x71\x01\x11\x01"), 0, 0),
            ((7, b""), 0x69, 0x69),
            ((7, b""), 0x33, 7),
            ((0, b"\x71\x01"), 0, 3),
        ):
            context = self.context([reply])
            context.controller.native_error = native_error
            with patch("scripts.utility_ex_ty_retained_10.hashlib.sha256") as digest:
                digest.return_value.hexdigest.return_value = context.module_sha256
                self.assertEqual(
                    run_body("Ex2PI_02_SendMessage", (), context), expected
                )
            self.assertIn(b"\x31\x01\x11\x01", context.controller.events)
            self.assertEqual(context.controller.events[-1], "finalize")

    def test_pi_absolute_target_restore_and_literal_timestamp(self):
        context = self.context(
            [(0, b"\x70\x41"), (0, b"\x61\x42\x34\x12\x40\x78\x56\x9a")]
        )
        buffer = bytearray(0x570)
        buffer[:8] = (700).to_bytes(4, "little") + (701).to_bytes(4, "little")
        buffer[8] = 1
        buffer[0x4B8:0x4BC] = (1).to_bytes(4, "little")
        for row, identifier in ((0x4F8, 0x42), (0x534, 0x43)):
            buffer[row + 1] = identifier
            buffer[row + 8 : row + 12] = (1).to_bytes(4, "little")
            buffer[row + 12] = 0xFF
        context.controller.support_snapshot = lambda kind: (
            0,
            b"\0\x06" + b"\xff" * 6,
            tuple(
                0 if i == (0x42 if kind == 1 else 0x43) else 0x1020 for i in range(256)
            ),
        )
        self.assertEqual(_pi_absolute(context, context.controller, buffer), 0)
        self.assertEqual(buffer[44:51], b"\x34\x12\x40\0\x78\x56\x9a")
        self.assertEqual(context.controller.events[0], ("target", 2000, 0))
        self.assertEqual(
            context.controller.events[-2:], ["finalize", ("target", 700, 701)]
        )
        self.assertEqual(context.state["native_global:1011f764"], 0)

    def test_plus_hvb_mode22_distinct_callback_pending_and_retention(self):
        context = self.context(
            [
                (7, b"\x7f\x31\x21"),
                (7, b"\x7f\x31\x24"),
                (0, b"\x71\x03\x11\x25\0\x02"),
            ],
            SHA_PLUS_TY,
        )
        context.mode = 22
        buffer = bytearray((1).to_bytes(4, "little") + b"\0" * 7)
        self.assertEqual(
            self.run_native("Ex2HVB_10_SendMessage", buffer, context), 1022
        )
        self.assertEqual(context.events[0], ("comm", "native:1013e7d0"))
        self.assertNotIn("finalize", context.controller.events)
        self.assertEqual(
            sum(event == ("native_10a4", 0) for event in context.controller.events), 3
        )
        self.assertEqual(
            sum(event == ("native_10a4", 255) for event in context.controller.events), 3
        )

    def test_cleanup_host_fault_preserves_primary_exception_identity(self):
        primary = RuntimeError("authored HOST exchange failed")
        cleanup = RuntimeError("authored finalizer failed")
        context = self.context()

        def fail_exchange(request):
            raise primary

        def fail_cleanup():
            raise cleanup

        context.controller.exchange = fail_exchange
        context.controller.finalize = fail_cleanup
        with self.assertRaises(RuntimeError) as raised:
            self.run_native("Ex2VC_01_GetActuationCnt", bytearray(12), context)
        self.assertIs(raised.exception, primary)

    def test_absolute_cleanup_restores_globals_and_target_after_finalizer_fault(self):
        context = self.context()
        context.controller.initial_status = 7
        cleanup = RuntimeError("authored finalizer failed")

        def fail_cleanup():
            raise cleanup

        context.controller.finalize = fail_cleanup
        buffer = bytearray(0x570)
        buffer[:4] = (700).to_bytes(4, "little")
        with self.assertRaises(RuntimeError) as raised:
            _pi_absolute(context, context.controller, buffer)
        self.assertIs(raised.exception, cleanup)
        self.assertEqual(context.state["native_global:1011f764"], 0)
        self.assertEqual(context.controller.events[-1], ("target", 700, 0))

    def test_vc03_security_inversion_and_begin_literal(self):
        context = self.context(
            [(0, b"\x67\x01\x01\xfe"), (0, b"\x67\x02"), (0, b"\x7b\x41")]
        )
        buffer = bytearray(16)
        buffer[4:8] = (2).to_bytes(4, "little")
        buffer[12:16] = (2).to_bytes(4, "little")
        self.assertEqual(_vc34(context, context.controller, buffer, False), 0)
        self.assertEqual(
            context.controller.events,
            [b"\x27\x01", b"\x27\x02\xfe\x01", b"\x3b\x41\x02\x02"],
        )

    def test_vc04_security_and_count_write_marker(self):
        context = self.context(
            [(0, b"\x67\x01\x00\xff"), (0, b"\x67\x02"), (0, b"\x7b\x78")]
        )
        buffer = bytearray(
            (15).to_bytes(4, "little") + b"ABCD" + bytes(4) + (2).to_bytes(4, "little")
        )
        self.assertEqual(_vc34(context, context.controller, buffer, True), 0)
        self.assertEqual(buffer[8:12], b"\x01\0\0\0")
        self.assertEqual(
            context.controller.events[-1], b"\x3b\x78\x20" + bytes(8) + b"ABCD"
        )
        context = self.context([(7, b"")])
        self.assertEqual(_vc34(context, context.controller, buffer, True), 3)
        self.assertEqual(buffer[8:12], bytes(4))

    def test_vc03_poll_ready_and_always_stop(self):
        context = self.context([(0, b"\x61\xcc\x80"), (7, b"")])
        buffer = bytearray(
            (1).to_bytes(4, "little")
            + (2).to_bytes(4, "little")
            + bytes(4)
            + (1).to_bytes(4, "little")
        )
        self.assertEqual(_vc34(context, context.controller, buffer, False), 1001)
        self.assertEqual(context.controller.events[-1], b"\x3b\x41\x02\0")

    def test_vif2_support_composes_native_group_flags(self):
        context = self.context()
        context.controller.support_snapshot = lambda kind: (
            0,
            b"\0\x04\xff\xff\xff\xff",
            tuple(0 for _ in range(256)),
        )
        buffer = bytearray(0x28C)
        self.assertEqual(_vif2(context, context.controller, buffer), 0)
        self.assertEqual(buffer[4:12], b"\x04\0\0\0" * 2)
        for offset in (0xC, 0x1C, 0x2C, 0x3C):
            self.assertEqual(buffer[offset : offset + 4], b"\x01\0\0\0")

    def test_vif2_selected_mask_bytes_and_two_literal_writes(self):
        context = self.context([(0, b"\x7b\x7b"), (0, b"\x7b\x7c")])
        buffer = bytearray(0x28C)
        buffer[:4] = (1).to_bytes(4, "little")
        buffer[4:8] = (2).to_bytes(4, "little")
        buffer[8:12] = (1).to_bytes(4, "little")
        for offset in (0x10, 0x20, 0x30, 0x40):
            buffer[offset] = 1
        buffer[0x18] = 1
        buffer[0x28] = 2
        buffer[0x38] = 4
        buffer[0x48] = 8
        self.assertEqual(_vif2(context, context.controller, buffer), 0)
        self.assertEqual(
            context.controller.events, [b"\x3b\x7b\x03\0", b"\x3b\x7c\x0c"]
        )

    def test_actual83_wrapper_scheduler_and_same_buffer(self):
        from scripts.utility_ex import UtilityExContext, UtilityExEngine
        from tests.test_utility_ex import Host

        with patch("scripts.utility_ex_ty_retained_10.hashlib.sha256") as digest:
            digest.return_value.hexdigest.return_value = SHA_18_TY
            context = UtilityExContext(
                b"authored source substitution", Host(), None, None
            )
            comm = SessionComm([(0, b"\xe9\x78" + bytes(9) + b"ABCD")])
            context._communication["selected"] = cast(UtilityExComm, comm)
            engine = UtilityExEngine(context)
            buffer = bytearray(12)
            self.assertEqual(engine.invoke("Ex2VC_01_GetActuationCnt", (buffer,)), 15)
            self.assertEqual(engine.worker.get_status(), 0)
            self.assertEqual(buffer[4:8], b"ABCD")
        self.assertEqual(comm.events[-1], "finalize")

    def test_szeiu_two_target_routines_and_keepalive_cleanup(self):
        context = self.context(sha=SHA_PLUS_TY)
        first = SessionComm(
            [
                (0, b"\x62\x10\x10" + b"A" * 9),
                (0, b"\x67\x11" + bytes(16)),
                (0, b"\x71\x01\xc0\x0d"),
                (0, b"\x71\x01\xc0\x0b"),
            ]
        )
        second = SessionComm(
            [
                (0, b"\x62\x12\x01" + bytes(15)),
                (0, b"\x62\x12\x01" + bytes(14) + b"\x55"),
            ]
        )
        context.comm = lambda kind: first if kind == "native:101392d0" else second

        def authored_data(module, rva, count):
            if rva == 0xE0CB0:
                return b"A" * 9 + bytes(18)
            if rva == 0xE0CCC:
                return struct.pack("<III", 9, 0, 0)
            raise AssertionError("zero seed must not read a native key")

        with patch("scripts.utility_ex_ty_retained_03._module_data", authored_data):
            self.assertEqual(_szeiu(context, bytearray(4)), 0)
        self.assertIn(("keepalive_config", 2000, b"\x3e\0", 2, 0), first.events)
        self.assertEqual(
            first.events[-3:],
            [("keepalive", False, False), ("session", 1, 0), "finalize"],
        )
        self.assertEqual(second.events[-1], "finalize")

    def test_szeiu_existing_state_short_circuit_and_timer_bound(self):
        context = self.context(sha=SHA_PLUS_TY)
        first = SessionComm([])
        second = SessionComm([(0, b"\x62\x12\x01" + bytes(15))])
        context.comm = lambda kind: first if kind == "native:101392d0" else second
        self.assertEqual(_szeiu(context, bytearray((2).to_bytes(4, "little"))), 0)
        self.assertNotIn(("keepalive", True, False), first.events)
        self.assertEqual(first.events[-1], "finalize")
        from scripts.utility_ex_ty_retained_10 import _sz_phase

        context = self.context([(0, b"\x62\x12\x01" + bytes(14) + b"\x01")] * 14)
        self.assertEqual(_sz_phase(context, context.controller, 0), 2000)
        self.assertEqual(context.clock, 3000)
        self.assertEqual(len(context.controller.replies), 0)

    def vif1_buffer(self):
        buffer = bytearray(0x1094)
        for index in range(12):
            row = index * 84
            identifier = 0x7B if index < 6 else 0x7C
            buffer[row] = identifier
            buffer[row + 12] = 0xFF
            buffer[row + 44] = 1 if index < 6 else 2
            buffer[row + 76 : row + 80] = (1).to_bytes(4, "little")
        for index in range(24):
            row = 0xC10 + index * 48
            buffer[row] = 0x7B if index % 12 < 6 else 0x7C
            buffer[row + 1] = 3 if index < 12 else 4
            buffer[row + 4 : row + 8] = (1).to_bytes(4, "little")
            buffer[row + 12] = 0xFF
        for row, identifier in ((0x3F0, 0x7B), (0x800, 0x7C)):
            buffer[row] = identifier
            buffer[row + 4 : row + 8] = (1).to_bytes(4, "little")
            buffer[row + 0x408 : row + 0x40C] = (1).to_bytes(4, "little")
            buffer[row + 0x40C : row + 0x410] = (1).to_bytes(4, "little")
        return buffer

    def test_vif1_support_pairing_read_buffers_and_mask_writes(self):
        context = self.context()
        buffer = self.vif1_buffer()
        context.controller.support_snapshot = lambda kind: (
            0,
            b"\0\x01\xff",
            tuple(0 for _ in range(256)),
        )
        self.assertEqual(self.run_native("Ex2VIF_01_SendMessage", buffer, context), 0)
        self.assertEqual(buffer[0x3F4:0x3F8], b"\x01\0\0\0")
        self.assertEqual(buffer[0x804:0x808], b"\x01\0\0\0")
        buffer[0x1090:0x1094] = (1).to_bytes(4, "little")
        context.controller.replies = [(0, b"\xe9\x7b\x81"), (0, b"\xe9\x7c\x82")]
        self.assertEqual(self.run_native("Ex2VIF_01_SendMessage", buffer, context), 0)
        self.assertEqual(buffer[0x3F8], 0x81)
        self.assertEqual(buffer[0x808], 0x82)
        buffer[0x1090:0x1094] = (2).to_bytes(4, "little")
        context.controller.replies = [(0, b"\x7b\x7b"), (0, b"\x7b\x7c")]
        self.assertEqual(self.run_native("Ex2VIF_01_SendMessage", buffer, context), 0)
        self.assertEqual(
            [event for event in context.controller.events if isinstance(event, bytes)][
                -2:
            ],
            [b"\x3b\x7b\x01", b"\x3b\x7c\x02"],
        )

    def test_ambient_caller_exception_does_not_hide_sole_cleanup_fault(self):
        context = self.context(
            [
                (0, b"\x62\x28" + bytes((identifier,)) + bytes(size))
                for identifier, size in (
                    (0x55, 6),
                    (0x56, 6),
                    (0x57, 6),
                    (0x58, 6),
                    (0x3F, 9),
                    (0x40, 9),
                )
            ]
        )
        cleanup = RuntimeError("sole cleanup failure")

        def fail_cleanup():
            raise cleanup

        context.controller.finalize = fail_cleanup
        try:
            raise ValueError("unrelated ambient caller error")
        except ValueError:
            with self.assertRaises(RuntimeError) as raised:
                self.run_native("Ex2DSC_01_SendMessage", bytearray(42), context)
        self.assertIs(raised.exception, cleanup)

    def test_vif1_second_target_unsupported_first_uses_global_previous(self):
        context = self.context([(0, b"\x7b\x7b")])
        buffer = self.vif1_buffer()
        buffer[0x1090:0x1094] = (2).to_bytes(4, "little")
        row = 6 * 84
        buffer[row + 80 : row + 84] = (1).to_bytes(4, "little")
        buffer[0x808] = 0x82
        support = 0xC10 + 6 * 48
        buffer[support + 4 : support + 8] = bytes(4)
        self.assertEqual(self.run_native("Ex2VIF_01_SendMessage", buffer, context), 0)
        self.assertEqual(
            [event for event in context.controller.events if isinstance(event, bytes)],
            [b"\x3b\x7b\x01"],
        )

    def test_vc5_all776_support_records_and_partial_read(self):
        context = self.context()
        buffer = bytearray(0x1745C)
        for index in range(776):
            buffer[0xE2D0 + index * 48 + 1] = 3 if index < 388 else 4
        context.controller.support_snapshot = lambda kind: (
            0,
            b"\0\x01\xff",
            tuple(0 for _ in range(256)),
        )
        self.assertEqual(_vc5(context, context.controller, buffer), 0)
        self.assertEqual(
            sum(_word(buffer, 0xE2D4 + index * 48) == 1 for index in range(776)), 776
        )
        buffer[0x17450:0x17454] = (1).to_bytes(4, "little")
        context.controller.replies = [(0, b"\xe9\0\x81")]
        self.assertEqual(_vc5(context, context.controller, buffer), 0)
        self.assertEqual(buffer[0x8568], 0x81)

    def test_vc5_seven_mask_groups_three_retry_limit(self):
        context = self.context(
            [(7, b""), (7, b"")]
            + [(0, bytes((0x7B, identifier))) for identifier in range(1, 8)]
        )
        buffer = bytearray(0x1745C)
        for index in range(8):
            descriptor = index * 88
            buffer[descriptor] = index + 1
            buffer[descriptor + 12] = 1
            buffer[descriptor + 44] = 2
            buffer[descriptor + 76 : descriptor + 80] = (1).to_bytes(4, "little")
            support = 0xE2D0 + index * 48
            buffer[support] = index + 1
            buffer[support + 4] = 1
            buffer[support + 12] = 1
            if index < 7:
                target = 0x8560 + index * 0x410
                buffer[target] = index + 1
                buffer[target + 8] = 1
                buffer[target + 0x408] = 1
                buffer[target + 0x40C] = 1
        self.assertEqual(_vc5_rewrite(context, context.controller, buffer), 0)
        self.assertEqual(context.clock, 9000)
        self.assertEqual(context.controller.events[:3], [b"\x3b\x01\x02"] * 3)
        self.assertEqual(context.controller.events[-1], b"\x3b\x07\x02")

    def test_vc5_reset_native_2011_and_three_retry(self):
        context = self.context([(7, b"\x7f\x31\x11"), (2, b""), (7, b""), (0, b"\x51")])
        self.assertEqual(_vc5_reset(context, context.controller), 0)
        self.assertEqual(
            context.controller.events,
            [b"\x31\x04", b"\x11\x01", b"\x11\x01", b"\x11\x01"],
        )

    def test_d15_unadmitted_business_protocol_restore_and_2706(self):
        context = self.context([(0, b"\x71\x01\x11\x83"), (0, b"\x44")], SHA_PLUS_TY)
        self.assertEqual(_d15(context, context.controller, bytearray(5)), 2706)
        self.assertIn(("protocol", 3), context.controller.events)
        self.assertIn(("protocol", 1), context.controller.events)
        self.assertEqual(context.clock, 3000)
        self.assertEqual(context.controller.events.count("finalize"), 3)
        self.assertNotIn("Ex2D_EFI_15_SendMessage", supported_exports(SHA_PLUS_TY))

    def test_d15_unadmitted_poll_literal_and_cancel_byte(self):
        context = self.context(
            [
                (0, b"\x50\x03" + bytes(4)),
                (0, b"\x71\x03\x11\x83\x01"),
                (0, b"\x71\x03\x11\x83\x02"),
            ],
            SHA_PLUS_TY,
        )
        self.assertEqual(
            _d15(
                context,
                context.controller,
                bytearray((1).to_bytes(4, "little") + b"\0"),
            ),
            0,
        )
        self.assertEqual(
            [event for event in context.controller.events if isinstance(event, bytes)],
            [b"\x10\x03", b"\x31\x03\x11\x83", b"\x31\x03\x11\x83"],
        )
        self.assertEqual(context.clock, 400)

    def test_source_identity_and_unimplemented_fail_closed(self):
        context = self.context()
        with self.assertRaises(TYSourceError):
            run_body("Ex2DSC_01_SendMessage", (bytearray(42),), context)
        self.assertEqual(supported_exports("unknown"), ())
        with self.assertRaises(TYSourceError):
            self.run_native("Ex2D_EFI_15_SendMessage", bytearray(42), context)
        self.assertEqual(context.controller.events, [])

    def test_invalid_buffers_and_cancel(self):
        for buffer in (b"0" * 42, bytearray(41)):
            with self.assertRaises((TypeError, ValueError)):
                self.run_native("Ex2DSC_01_SendMessage", buffer, self.context())
        context = self.context()
        context.cancelled = True
        with self.assertRaises(Cancelled):
            self.run_native("Ex2DSC_01_SendMessage", bytearray(42), context)
        self.assertEqual(context.controller.events, [])


if __name__ == "__main__":
    unittest.main()
