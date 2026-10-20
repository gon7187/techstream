"""Authored literal retained TY branch and memory vectors."""

import hashlib
import json
import struct
import unittest
from dataclasses import replace
from pathlib import Path
from typing import cast
from unittest.mock import patch

from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import (
    SHA_12_TY,
    SHA_18_TY,
    SHA_PLUS_TY,
    TYContext,
    TYSourceError,
)
from scripts.utility_ex_ty_retained_08 import (
    BCM_EXPORTS,
    EXPORTS,
    FSR_EXPORTS,
    HNCSN_EXPORTS,
    Contract,
    Engine,
    NativeTYArithmeticFault,
    NativeTYMemoryFault,
    run_body,
    supported_exports,
)


class Comm:
    def __init__(self, replies=(), sessions=(), initial=0):
        self.snapshots = []
        self.replies = list(replies)
        self.sessions = list(sessions)
        self.initial = initial
        self.events = []

    def configure_target(self, *values):
        self.events.append(("configure_target", *values))

    def initialize(self, mode=0):
        self.events.append(("initialize", mode))
        return self.initial

    def configure(self, name, value):
        self.events.append(("configure", name, value))

    def session(self, mode, keepalive=1):
        self.events.append(("session", mode, keepalive))
        return self.sessions.pop(0) if self.sessions else 0

    def exchange(self, request):
        self.events.append(("exchange", request))
        return self.replies.pop(0)

    def support_snapshot(self, kind):
        self.events.append(("support_snapshot", kind))
        return self.snapshots.pop(0)

    def finalize(self):
        self.events.append(("finalize",))


class Context:
    mode = 20
    module_bytes = b"authored-retained08-vector"
    module_sha256 = hashlib.sha256(module_bytes).hexdigest()

    def __init__(self, comm):
        self.controller = comm
        self.state = {"host:x87_control_word": 0x027F}
        self.cancelled = False
        self.sleeps = []
        self.tick = 0
        self.on_sleep = lambda _: None

    def comm(self, name):
        assert name in ("authored-manager", "selected")
        return self.controller

    def native_sleep(self, ms):
        self.sleep(ms)

    def sleep(self, ms):
        self.sleeps.append(ms)
        self.tick = (self.tick + ms) & 0xFFFFFFFF
        self.on_sleep(ms)

    def ticks(self):
        return self.tick

    def is_cancelled(self):
        return self.cancelled


def engine():
    return Engine(
        Contract(
            Context.module_sha256, "authored-manager", ("retry", "pending", "count")
        )
    )


def call(index, data, replies=(), sessions=(), initial=0):
    comm = Comm(replies, sessions, initial)
    context = Context(comm)
    result = engine().run_body(EXPORTS[index], (data,), cast(TYContext, context))
    return result, context, comm


def snapshot(records):
    raw = bytearray(0x1020)
    offsets = [0x1020] * 256
    offset = 0
    for identifier, payload in records:
        offsets[identifier] = offset
        raw[offset : offset + len(payload) + 2] = (
            bytes((identifier, len(payload))) + payload
        )
        offset += len(payload) + 2
    return 0, bytes(raw), tuple(offsets)


def plus_context(comm):
    from scripts.utility_ex import UtilityExContext, UtilityHost

    path = Path(
        "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll"
    )

    class Host:
        elapsed = 0

        def get_parameter(self, key):
            return 4 if key == 0x6F else 0

        def sleep(self, milliseconds):
            self.elapsed = (self.elapsed + milliseconds) & 0xFFFFFFFF

        def ticks(self):
            return self.elapsed

    context = UtilityExContext(path.read_bytes(), cast(UtilityHost, Host()), None, None)
    context.state["host:mxcsr"] = 0x1F80
    return context


class RetainedTests(unittest.TestCase):
    def test_angle_arithmetic_requires_explicit_host_control_state(self):
        context = Context(Comm())
        context.state.clear()
        with self.assertRaises(TYSourceError):
            Engine._angle_byte(0.3, cast(TYContext, context), False)
        with self.assertRaises(TYSourceError):
            Engine._angle_byte(0.3, cast(TYContext, context), True)

    def test_x87_precision_and_rounding_affect_native_angle_bytes(self):
        context = Context(Comm())
        for control, expected in (
            (0x007F, 3),
            (0x027F, 3),
            (0x037F, 2),
            (0x067F, 2),
            (0x0A7F, 3),
            (0x0E7F, 2),
        ):
            context.state["host:x87_control_word"] = control
            self.assertEqual(
                Engine._angle_byte(0.3, cast(TYContext, context), False), expected
            )

    def test_masked_indefinite_and_unmasked_native_arithmetic_fault(self):
        context = Context(Comm())
        context.state["host:mxcsr"] = 0x1F80
        self.assertEqual(
            Engine._angle_byte(float("nan"), cast(TYContext, context), False), 128
        )
        self.assertEqual(
            Engine._angle_byte(float("nan"), cast(TYContext, context), True), 0
        )
        context.state["host:x87_control_word"] = 0x027E
        with self.assertRaises(NativeTYArithmeticFault):
            Engine._angle_byte(float("nan"), cast(TYContext, context), False)
        context.state["host:mxcsr"] = 0x1F00
        with self.assertRaises(NativeTYArithmeticFault):
            Engine._angle_byte(1e100, cast(TYContext, context), True)

    def test_plus_hncsn_calibration_init_and_bumper_readback(self):
        from scripts.utility_ex import UtilityExContext

        vectors = (
            (HNCSN_EXPORTS[2], [(0, b"\x50"), (0, b"\x61\x3f\0"), (0, b"\x50")]),
            (
                HNCSN_EXPORTS[3],
                [(0, b"\x61\x41\0"), (0, b"\x61\x41\x40"), (0, b"\x50")],
            ),
            (HNCSN_EXPORTS[7], [(0, b"\x7b\x3f"), (0, b"\x61\x3f\x82"), (0, b"\x50")]),
        )
        for export, replies in vectors:
            comm = Comm(replies)
            data = bytearray(124)
            struct.pack_into("<I", data, 112, 2)
            data[122] = 128
            context = plus_context(comm)
            with patch.object(UtilityExContext, "comm", return_value=comm):
                self.assertEqual(run_body(export, (data,), context), 0)
            self.assertEqual(comm.events[-2:], [("exchange", b"\x10\1"), ("finalize",)])
            if export == HNCSN_EXPORTS[7]:
                self.assertEqual(data[120:123], b"\x61\x3f\x82")
                self.assertIn(("exchange", b"\x3b\x3f\x82"), comm.events)

    def test_plus_front_and_rear_angles_use_distinct_status_nibbles_and_sse(self):
        from scripts.utility_ex import UtilityExContext

        for rear in (False, True):
            data = bytearray(124)
            struct.pack_into("<I", data, 0, 4)
            struct.pack_into("<I", data, 8, 2)
            struct.pack_into("<I", data, 32 if rear else 24, 6)
            struct.pack_into("<I", data, 28, 5)
            struct.pack_into("<dddd", data, 80 if rear else 48, 0.3, -0.3, 0.0, 1.2)
            comm = Comm(
                [
                    (0, bytes((0x7B, 0x43 if rear else 0x34))),
                    (0, b"\x7b\x3e"),
                    (0, b"\x61\x3a\5\5" if rear else b"\x61\x3a\x55\x55"),
                    (0, b"\x50"),
                ]
            )
            context = plus_context(comm)
            with patch.object(UtilityExContext, "comm", return_value=comm):
                self.assertEqual(
                    run_body(HNCSN_EXPORTS[6 if rear else 4], (data,), context), 0
                )
            wire = [x[1] for x in comm.events if x[0] == "exchange"]
            self.assertEqual(
                wire[0], bytes((0x3B, 0x43 if rear else 0x34, 3, 131, 128, 12))
            )
            self.assertEqual(
                wire[1], b"\x3b\x3e\0\x20\x30" if rear else b"\x3b\x3e\0\x20\xc0"
            )

    def test_plus_support_includes_optional_bumper_type_and_rear_length(self):
        from scripts.utility_ex import UtilityExContext

        comm = Comm([(0, b"\x61\x28\0\0\0\0\2")])
        comm.snapshots = [
            snapshot(
                [
                    (0x41, b"\xc0"),
                    (0x3F, b"\x7f"),
                    (0x3A, b"\1\0\1\xc0"),
                    (0x28, b"\1\1\1\1\x0f"),
                ]
            ),
            snapshot(
                [
                    (1, b"\xc0"),
                    (0x41, b"\xc0"),
                    (0x34, b"1234"),
                    (0x3E, b"\1\2\xc0"),
                    (0x43, b"1234"),
                ]
            ),
        ]
        context = plus_context(comm)
        data = bytearray(124)
        with patch.object(UtilityExContext, "comm", return_value=comm):
            self.assertEqual(run_body(HNCSN_EXPORTS[5], (data,), context), 0)
        self.assertEqual(struct.unpack_from("<IIII", data), (5, 7, 4, 6))
        self.assertEqual(
            struct.unpack_from("<IIIIIII", data, 16), (3, 3, 6, 5, 6, 1, 1)
        )
        self.assertEqual(struct.unpack_from("<I", data, 116)[0], 8)

    def test_hncsn18_support_payload_counts_and_command_lengths_differ(self):
        comm = Comm()
        comm.snapshots = [
            snapshot([(0x41, b"\xc0"), (0x3F, b"\x7f"), (0x3A, b"\1\0\1\xc0")]),
            snapshot(
                [(1, b"\xc0"), (0x41, b"\xc0"), (0x34, b"1234"), (0x3E, b"\1\2\xc0")]
            ),
        ]
        data = bytearray(32)
        self.assertEqual(
            engine().run_body(
                HNCSN_EXPORTS[5], (data,), cast(TYContext, Context(comm))
            ),
            0,
        )
        self.assertEqual(struct.unpack("<IIIIIIII", data), (5, 4, 3, 3, 6, 5, 1, 1))

    def test_hncsn_support_undefined_native_local_is_not_fabricated_status(self):
        comm = Comm()
        comm.snapshots = [snapshot([])]
        data = bytearray(32)
        self.assertEqual(
            engine().run_body(
                HNCSN_EXPORTS[5], (data,), cast(TYContext, Context(comm))
            ),
            22,
        )
        self.assertEqual(struct.unpack_from("<II", data), (0x100DA9BC, 0x100DA9BC))
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_hncsn18_calibrated_positive_and_sensor_init(self):
        for export, replies in (
            (HNCSN_EXPORTS[2], [(0, b"\x50"), (0, b"\x61\x3f\0"), (0, b"\x50")]),
            (
                HNCSN_EXPORTS[3],
                [(0, b"\x61\x41\0"), (0, b"\x61\x41\x40"), (0, b"\x50")],
            ),
        ):
            comm = Comm(replies)
            context = Context(comm)
            status = engine().run_body(
                export, (bytearray(33),), cast(TYContext, context)
            )
            self.assertEqual(status, 0)
            self.assertEqual(comm.events[-2:], [("exchange", b"\x10\1"), ("finalize",)])
            self.assertEqual(
                context.sleeps, [] if export == HNCSN_EXPORTS[2] else [500]
            )

    def test_hncsn18_angles_preserve_x87_extended_multiply_and_decode(self):
        data = bytearray(72)
        for offset, value in ((0, 4), (4, 2), (16, 6), (20, 5)):
            struct.pack_into("<I", data, offset, value)
        struct.pack_into("<dddd", data, 40, 0.3, -0.3, 0.0, 1.2)
        comm = Comm(
            [(0, b"\x7b\x34"), (0, b"\x7b\x3e"), (0, b"\x61\x3a\x55\x55"), (0, b"\x50")]
        )
        context = Context(comm)
        context.state["host:x87_control_word"] = 0x037F
        self.assertEqual(
            engine().run_body(HNCSN_EXPORTS[4], (data,), cast(TYContext, context)), 0
        )
        self.assertEqual(
            [x[1] for x in comm.events if x[0] == "exchange"],
            [b"\x3b\x34\2\x82\x80\x0b", b"\x3b\x3e\0\x20\xc0", b"\x21\x3a", b"\x10\1"],
        )
        self.assertEqual(context.sleeps, [500])

    def test_hncsn_neutral_variable_wire_length_and_nonforced_normal(self):
        data = bytearray(20)
        struct.pack_into("<I", data, 8, 6)
        comm = Comm([(0, b"\x7b\1"), (99, b"")])
        status = engine().run_body(
            HNCSN_EXPORTS[1], (data,), cast(TYContext, Context(comm))
        )
        self.assertEqual(status, 0)
        self.assertEqual(
            [x[1] for x in comm.events if x[0] == "exchange"],
            [b"\x3b\1\x80\0\0\0", b"\x10\1"],
        )
        self.assertFalse(
            any(x[:2] == ("configure", "native_rva:1a860") for x in comm.events)
        )
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_hncsn_neutral_error_forces_normal_then_restores_setters(self):
        data = bytearray(20)
        struct.pack_into("<I", data, 8, 3)
        comm = Comm([(31, b""), (0, b"\x50")])
        status = engine().run_body(
            HNCSN_EXPORTS[1], (data,), cast(TYContext, Context(comm))
        )
        self.assertEqual(status, 31)
        self.assertEqual(
            [x for x in comm.events if x[:2] == ("configure", "native_rva:1a860")],
            [
                ("configure", "native_rva:1a860", 1),
                ("configure", "native_rva:1a860", 150),
            ],
        )

    def test_actual83_all49_public_wrappers_schedule_actual97_bodies(self):
        from scripts.utility_ex import UtilityEx2TY, UtilityExContext, UtilityHost

        paths = {
            SHA_18_TY: Path(
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll"
            ),
            SHA_12_TY: Path(
                "artifacts/extracted/techstream-12-application/Techstream_Bin/UtilityEx2TY.dll"
            ),
            SHA_PLUS_TY: Path(
                "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll"
            ),
        }

        class Host:
            def get_parameter(self, key):
                return 0

        rows = json.loads(
            Path("analysis/evidence/no-car-127/wrapper-import-packet.json").read_text()
        )["rows"]
        self.assertEqual(len(rows), 49)
        for row in rows:
            with self.subTest(source=row["source_sha256"], export=row["export"]):
                path = paths[row["source_sha256"]]
                if not path.exists():
                    self.skipTest("private original source absent")
                context = UtilityExContext(
                    path.read_bytes(), cast(UtilityHost, Host()), None, None
                )
                consumer = UtilityEx2TY(context)
                data = bytearray(424)
                comm = Comm([(42, b"")], initial=42)
                with patch.object(UtilityExContext, "comm", return_value=comm):
                    self.assertEqual(consumer.invoke(row["export"], (data,)), 99)
                    self.assertFalse(comm.events)
                    context._parameters[0x6F] = row["modes"][0]
                    self.assertEqual(consumer.invoke(row["export"], (data,)), 15)
                    self.assertEqual(
                        consumer.worker.get_status(),
                        1003 if row["export"] == HNCSN_EXPORTS[0] else 42,
                    )
                    self.assertEqual(consumer.worker.timeout_ms, 10000)

    def test_native_ui_fault_is_distinct_from_host_identity_fault(self):
        context = Context(Comm())
        with self.assertRaises(NativeTYMemoryFault):
            engine().run_body(EXPORTS[3], (bytearray(11),), cast(TYContext, context))
        self.assertFalse(context.controller.events)

    def test_host_driver_exception_is_preserved_by_identity(self):
        class Broken(Comm):
            def exchange(self, request):
                raise failure

        failure = RuntimeError("authored host driver fault")
        context = Context(Broken())
        with self.assertRaises(RuntimeError) as caught:
            engine().run_body(EXPORTS[2], (bytearray(12),), cast(TYContext, context))
        self.assertIs(caught.exception, failure)

    def test_actual97_selected_aggregator_plus_mode22_alternate_callback(self):
        from scripts.utility_ex import UtilityExContext, UtilityExEngine, UtilityHost

        path = Path(
            "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll"
        )
        if not path.exists():
            self.skipTest("private original source absent")

        class Host:
            def get_parameter(self, key):
                return 22 if key == 0x6F else 0

            def sleep(self, milliseconds):
                pass

        context = UtilityExContext(
            path.read_bytes(), cast(UtilityHost, Host()), None, None
        )
        comm = Comm(
            [(0, b"\x71\1\3\2\0"), (0, b"\x71\1\3\1\0"), (0, b"\x62\x12\x0b\0\1")]
        )
        data = bytearray(1)
        with patch.object(UtilityExContext, "comm", return_value=comm) as selected:
            status = UtilityExEngine(context).run_body(EXPORTS[1], (data,))
        self.assertEqual((status, data[0]), (1003, 4))
        selected.assert_called_once_with("native:1013e7d0")
        self.assertEqual(
            [x[1] for x in comm.events if x[0] == "exchange"],
            [b"\x31\1\3\2\7", b"\x31\1\3\1\7", b"\x22\x12\x0b"],
        )

    def test_actual97_selected_aggregator_fsr_retains_actual_mutable_buffer(self):
        from scripts.utility_ex import UtilityExContext, UtilityExEngine, UtilityHost

        path = Path(
            "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll"
        )
        if not path.exists():
            self.skipTest("private original source absent")

        class Host:
            def get_parameter(self, key):
                return 4 if key == 0x6F else 0

        context = UtilityExContext(
            path.read_bytes(), cast(UtilityHost, Host()), None, None
        )
        comm = Comm([(0, b"\x61\x6c\xa5")])
        data = bytearray(struct.pack("<III", 3, 0, 0))
        with patch.object(UtilityExContext, "comm", return_value=comm) as selected:
            status = UtilityExEngine(context).run_body(FSR_EXPORTS[3], (data,))
        self.assertEqual(status, 0)
        self.assertEqual(struct.unpack_from("<I", data, 8)[0], 0xA5)
        selected.assert_called_once_with("selected")

    def test_hncsn_transition_restores_configuration_and_ignores_wire_status(self):
        comm = Comm([(83, b"")])
        status = engine().run_body(
            HNCSN_EXPORTS[0], (bytearray(1),), cast(TYContext, Context(comm))
        )
        self.assertEqual(status, 1003)
        self.assertIn(("exchange", b"\x10\1"), comm.events)
        self.assertEqual(comm.events[-1], ("finalize",))
        self.assertEqual(
            [x for x in comm.events if x[:2] == ("configure", "native_rva:1a860")],
            [
                ("configure", "native_rva:1a860", 1),
                ("configure", "native_rva:1a860", 150),
            ],
        )

    def test_hncsn_transition_failed_initialization_still_returns_1003(self):
        comm = Comm(initial=42)
        status = engine().run_body(
            HNCSN_EXPORTS[0], (bytearray(1),), cast(TYContext, Context(comm))
        )
        self.assertEqual(status, 1003)
        self.assertEqual(comm.events, [("initialize", 0), ("finalize",)])

    def test_bcm02_literal_20_dids_target_switch_and_tail_copy(self):
        replies = [
            (0, bytes((0x62, 0xDA, identifier)) + b"\1\2\3\4\0\0")
            for identifier in range(0xBA, 0xCE)
        ]
        replies.append((0, b"\x62\xdd\0\x11\x22\x33\x44"))
        comm = Comm(replies)
        data = bytearray(124)
        status = engine().run_body(
            BCM_EXPORTS[1], (data,), cast(TYContext, Context(comm))
        )
        self.assertEqual(status, 1001)
        self.assertEqual(data[:6], b"\1\2\3\4\0\0")
        self.assertEqual(data[120:124], b"\x11\x22\x33\x44")
        wire = [x[1] for x in comm.events if x[0] == "exchange"]
        self.assertEqual(
            wire, [bytes((0x22, 0xDA, i)) for i in range(0xBA, 0xCE)] + [b"\x22\xdd\0"]
        )
        self.assertEqual(
            [x for x in comm.events if x[0] == "configure_target"],
            [
                ("configure_target", 0x726, 0, 0, 0, 0),
                ("configure_target", 0x720, 0, 0, 0, 0),
            ],
        )
        self.assertEqual(comm.events.count(("finalize",)), 2)

    def test_bcm01_nonzero_word_and_status_marks_actionable(self):
        identifiers = bytes.fromhex(
            "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9d1d2d3d4d5d6d7d8d9dadbdcdddedfe1e2e3"
        )
        replies = [
            (0, bytes((0x62, 0xDA, identifier)) + b"\0\0\0\0\1\0\2")
            for identifier in identifiers
        ]
        replies.append((0, b"\x62\xdd\0abcd"))
        comm = Comm(replies)
        data = bytearray(424)
        self.assertEqual(
            engine().run_body(BCM_EXPORTS[0], (data,), cast(TYContext, Context(comm))),
            0,
        )
        self.assertEqual(data[420:424], b"abcd")
        self.assertEqual(
            [x[1] for x in comm.events if x[0] == "exchange"][:-1],
            [bytes((0x22, 0xDA, i)) for i in identifiers],
        )

    def test_bcm_malformed_read_preserves_uncopied_rows_and_closes(self):
        comm = Comm([(0, b"\x62\xda\xba12345")])
        data = bytearray([0x55] * 124)
        self.assertEqual(
            engine().run_body(BCM_EXPORTS[1], (data,), cast(TYContext, Context(comm))),
            3,
        )
        self.assertEqual(data, bytearray([0x55] * 124))
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_fsr_retained_start_exact_special_status_keeps_manager(self):
        for export, selector, expected in (
            (FSR_EXPORTS[5], 3, 1206),
            (FSR_EXPORTS[6], 2, 3406),
        ):
            comm = Comm([(0, bytes((0x70, selector)))])
            data = bytearray(28)
            struct.pack_into("<I", data, 8, 5)
            status = engine().run_body(export, (data,), cast(TYContext, Context(comm)))
            self.assertEqual(status, expected)
            self.assertEqual(
                comm.events[-1], ("exchange", bytes((0x30, selector, 0, 128, 0)))
            )
            self.assertNotIn(("finalize",), comm.events)

    def test_fsr_retained_start_masks_native_error_to_pending_and_closes(self):
        comm = Comm([(43, b"")])
        data = bytearray(24)
        struct.pack_into("<I", data, 8, 4)
        self.assertEqual(
            engine().run_body(FSR_EXPORTS[5], (data,), cast(TYContext, Context(comm))),
            9001,
        )
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_fsr_continuation_reverses_two_result_bytes_then_stop(self):
        data = bytearray(struct.pack("<IIIIIII", 5, 3, 4, 3, 0, 1, 0))
        comm = Comm([(0, b"\x61\x68\x80"), (0, b"\x61\x7b\0\x12\x34"), (55, b"")])
        status = engine().run_body(
            FSR_EXPORTS[6], (data,), cast(TYContext, Context(comm))
        )
        self.assertEqual(status, 0)
        self.assertEqual(data[16:18], b"\x34\x12")
        self.assertEqual(comm.events[-2:], [("exchange", b"\x30"), ("finalize",)])
        self.assertNotIn(("initialize", 0), comm.events)

    def test_fsr_twelve_elapsed_boundary_and_unsigned_wrap(self):
        data = bytearray(24)
        struct.pack_into("<III", data, 0, 3, 3, 4)
        comm = Comm([(0, b"\x70\3")] + [(0, b"\x61\x68\0")] * 12 + [(0, b"\x70")])
        context = Context(comm)
        context.tick = 0xFFFFFFF0
        timed = Engine(replace(engine().contract, timed_fsr=True))
        status = timed.run_body(FSR_EXPORTS[5], (data,), cast(TYContext, context))
        self.assertEqual(status, 9001)
        self.assertEqual(context.sleeps, [500] * 11)
        self.assertEqual(comm.events[-2:], [("exchange", b"\x30"), ("finalize",)])

    def test_fsr_support_mutates_counts_and_partial_selected_position(self):
        comm = Comm()
        comm.snapshots = [
            snapshot([(0x68, b"\x80"), (0x7B, b"\1\0\1\xff\xff")]),
            snapshot([(2, b"\x80\1")]),
        ]
        data = bytearray(16)
        status = engine().run_body(
            FSR_EXPORTS[1], (data,), cast(TYContext, Context(comm))
        )
        self.assertEqual(status, 0)
        self.assertEqual(struct.unpack("<IIII", data), (6, 3, 5, 4))
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_fsr_missing_support_is_native22_not_host_fault(self):
        comm = Comm()
        comm.snapshots = [snapshot([])]
        status = engine().run_body(
            FSR_EXPORTS[0], (bytearray(12),), cast(TYContext, Context(comm))
        )
        self.assertEqual(status, 22)
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_fsr_history_and_clear_have_distinct_wire_and_return(self):
        for export, reply, expected in (
            (FSR_EXPORTS[3], b"\x61\x6c\x9a", 0),
            (FSR_EXPORTS[4], b"\x7b\x6c", 9000),
        ):
            comm = Comm([(0, reply)])
            data = bytearray(struct.pack("<III", 3, 0, 0))
            status = engine().run_body(export, (data,), cast(TYContext, Context(comm)))
            self.assertEqual(status, expected)
            self.assertEqual(
                comm.events[-2],
                ("exchange", b"\x3b\x6c\0" if expected else b"\x21\x6c"),
            )
            self.assertEqual(comm.events[-1], ("finalize",))
            if not expected:
                self.assertEqual(struct.unpack_from("<I", data, 8)[0], 0x9A)

    def test_fsr_bad_echo_preserves_output_and_finalizes(self):
        comm = Comm([(0, b"\x61\x6d\x9a")])
        data = bytearray(struct.pack("<III", 3, 0, 42))
        status = engine().run_body(
            FSR_EXPORTS[3], (data,), cast(TYContext, Context(comm))
        )
        self.assertEqual(status, 3)
        self.assertEqual(struct.unpack_from("<I", data, 8)[0], 42)
        self.assertEqual(comm.events[-1], ("finalize",))

    def test_exact_source_exports(self):
        self.assertEqual(
            supported_exports(SHA_18_TY),
            FSR_EXPORTS + BCM_EXPORTS + EXPORTS + HNCSN_EXPORTS[:6],
        )
        self.assertEqual(
            supported_exports(SHA_PLUS_TY),
            FSR_EXPORTS + BCM_EXPORTS + EXPORTS + HNCSN_EXPORTS,
        )
        self.assertEqual(supported_exports(SHA_12_TY), FSR_EXPORTS + BCM_EXPORTS)
        self.assertEqual(supported_exports("unknown"), ())

    def test_host_identity_is_exception_before_native_io(self):
        context = Context(Comm())
        with self.assertRaises(TYSourceError):
            run_body(EXPORTS[0], (bytearray(5),), cast(TYContext, context))
        self.assertFalse(context.controller.events)
        context.module_bytes += b"mutated"
        with self.assertRaises(TYSourceError):
            engine().run_body(EXPORTS[0], (bytearray(5),), cast(TYContext, context))
        self.assertFalse(context.controller.events)

    def test_short_buffer_and_unsupported_fail_without_wire(self):
        context = Context(Comm())
        with self.assertRaises(ValueError):
            engine().run_body(EXPORTS[3], (bytearray(11),), cast(TYContext, context))
        with self.assertRaises(TYSourceError):
            engine().run_body(
                "Ex2HNCSN_01_WriteBumperType",
                (bytearray(1024),),
                cast(TYContext, context),
            )
        self.assertFalse(context.controller.events)

    def test_sbw_start_keeps_manager_and_marks_ui(self):
        data = bytearray(12)
        status, context, comm = call(3, data, [(0, b"\x00\x01\x11\xf9")])
        self.assertEqual(status, 1004)
        self.assertEqual(struct.unpack_from("<I", data, 8)[0], 1)
        self.assertEqual(context.sleeps, [700])
        self.assertEqual(
            comm.events[-3:],
            [("session", 1, 1), ("session", 3, 1), ("exchange", b"\x31\x01\x11\xf9")],
        )
        self.assertNotIn(("finalize",), comm.events)

    def test_sbw_init_failure_finalizes_without_normal_session(self):
        status, _, comm = call(3, bytearray(12), initial=42)
        self.assertEqual(status, 42)
        self.assertEqual(comm.events, [("initialize", 0), ("finalize",)])

    def test_sbw_session_failure_resets_existing_ui_flag(self):
        data = bytearray(struct.pack("<III", 0, 0, 1))
        status, _, comm = call(3, data, sessions=[51])
        self.assertEqual(status, 51)
        self.assertEqual(data[8:12], b"\0" * 4)
        self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])

    def test_sbw_continuation_polls_status_not_decompiler_dead_loop(self):
        data = bytearray(struct.pack("<III", 1, 0, 1))
        status, context, comm = call(
            3, data, [(0, b"\x71\x03\x11\xf9\0"), (0, b"\x71\x03\x11\xf9\1")]
        )
        self.assertEqual(status, 1001)
        self.assertEqual(context.sleeps, [200, 200])
        self.assertNotIn(("finalize",), comm.events)
        self.assertEqual(data[8], 1)

    def test_sbw_stop_flag_returns_native_cancel_retaining_manager(self):
        status, _, comm = call(3, bytearray(struct.pack("<III", 1, 1, 1)))
        self.assertEqual(status, 1002)
        self.assertFalse(comm.events)

    def test_sbw_malformed_and_unknown_status_cleanup(self):
        for response in (
            b"\x71\x03\x11\xf9",
            b"\x71\x03\x11\xf9\2",
            b"\x71\x03\x12\xf9\1",
        ):
            data = bytearray(struct.pack("<III", 1, 0, 1))
            status, _, comm = call(3, data, [(0, response)])
            self.assertEqual(status, 3)
            self.assertEqual(data[8], 0)
            self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])

    def test_sbw_result_pending_then_completed_cleanup(self):
        status, _, comm = call(
            2,
            bytearray(12),
            [(0, b"\x62\x14\x58\0"), (0, b"\x62\x14\x58\1"), (0, b"\x62\x14\x58\3")],
        )
        self.assertEqual(status, 0)
        self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])

    def test_sbw_result_native_cancel_keeps_manager(self):
        status, _, comm = call(2, bytearray(12), [(1002, b"")])
        self.assertEqual(status, 1002)
        self.assertEqual(len(comm.events), 1)

    def test_avs_start_retains_manager(self):
        status, context, comm = call(0, bytearray(5), [(0, b"\0\1\x10\7")])
        self.assertEqual(status, 0)
        self.assertEqual(context.sleeps, [50])
        self.assertNotIn(("finalize",), comm.events)

    def test_avs_poll_one_pending_two_finished(self):
        status, context, comm = call(
            0,
            bytearray(b"\1\0\0\0\0"),
            [(0, b"\x71\3\x10\7\1"), (0, b"\x71\3\x10\7\2")],
        )
        self.assertEqual(status, 0)
        self.assertEqual(context.sleeps, [500, 500, 50])
        self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])

    def test_avs_native_ui_cancel_flag_still_cleans(self):
        status, context, comm = call(0, bytearray(b"\1\0\0\0\1"))
        self.assertEqual(status, 0)
        self.assertEqual(context.sleeps, [50])
        self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])

    def test_avs02_mask_is_not_echoed_and_output_is_mutated(self):
        for output, expected in ((7, 1002), (6, 1003)):
            data = bytearray(1)
            replies = [
                (0, b"\x71\1\x11\3"),
                (0, b"\x71\1\x11\4"),
                (0, bytes((0x62, 0x13, 1, 0, output))),
            ]
            status, context, comm = call(1, data, replies)
            self.assertEqual((status, data[0]), (expected, output))
            self.assertEqual(context.sleeps, [5000])
            self.assertEqual(
                [x[1] for x in comm.events if x[0] == "exchange"],
                [b"\x31\1\x11\3\7", b"\x31\1\x11\4\7", b"\x22\x13\1"],
            )
            self.assertEqual(comm.events[-2:], [("session", 1, 1), ("finalize",)])

    def test_host_cancellation_is_not_native_1002(self):
        context = Context(Comm())
        context.cancelled = True
        with self.assertRaises(Cancelled):
            engine().run_body(EXPORTS[3], (bytearray(12),), cast(TYContext, context))
        self.assertFalse(context.controller.events)


if __name__ == "__main__":
    unittest.main()
