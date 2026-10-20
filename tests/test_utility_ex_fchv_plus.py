"""Literal native Plus packet traces and mutable action/lifecycle checks."""

from __future__ import annotations

import hashlib
import unittest
from collections.abc import Callable
from pathlib import Path

from scripts.toyota_session import Cancelled
from scripts.utility_ex_fchv_plus import (
    _EXPORTS,
    SHA_PLUS_TY,
    _Monitor,
    _Pressure,
    _put,
    _run,
    _u32,
    _Valves,
    run_body,
    supported_exports,
)
from scripts.utility_ex_ty import SHA_18_TY, TYSourceError
from tests.test_utility_ex_fchv import Context

Step = tuple[bytes, int, bytes]
MASK = b"\0\x01\0\x02\0\x04\0\x07"


def io(mode=0, payload=MASK, status=0) -> Step:
    packet = bytes((0x2F, 0x28, 0x1F, mode)) + payload
    return packet, status, b"\x6f" + packet[1:4]


def routine(mode, number, payload=b"", status=0) -> Step:
    packet = bytes((0x31, mode, 0x11, number)) + payload
    return packet, status, b"\x71" + packet[1:4]


def read(first, second, payload, status=0) -> Step:
    did = bytes((first, second))
    return b"\x22" + did, status, b"\x62" + did + payload


def block(kind, action, state=1):
    data = bytearray(0x38C if kind in (24, 25) else 0x24 if kind == 27 else 0xB8)
    _put(data, 0, action)
    offset = 0x384 if kind in (24, 25) else 0x20 if kind == 27 else 0xB0
    data[offset : offset + 4] = b"\x01\x02\x04\x07"
    if kind in (24, 25):
        _put(data, 0x388, state)
    return data


class Trace(Context):
    def __init__(self, steps=()):
        super().__init__(SHA_PLUS_TY)
        self.steps = list(steps)
        self.on_exchange: Callable[[bytes], None] | None = None
        self.tick_step = 0

    def exchange(self, request):
        self.events.append(("exchange", request))
        if self.on_exchange:
            self.on_exchange(request)
        if self.fault:
            raise self.fault
        if not self.steps:
            raise AssertionError(f"Unexpected frame {request.hex()}")
        expected, status, reply = self.steps.pop(0)
        if expected != request:
            raise AssertionError(f"Frame {request.hex()}, expected {expected.hex()}")
        return status, reply

    def native_sleep(self, milliseconds: int) -> None:
        self.sleep(milliseconds)

    def read_dtcs(self, mode: int = 0x80, capacity: int = 0x1000) -> tuple[int, bytes]:
        raise AssertionError("Unexpected DTC read")

    def ticks(self):
        value = self.clock
        self.clock = (self.clock + self.tick_step) & 0xFFFFFFFF
        return value


class PlusTests(unittest.TestCase):
    def invoke(self, kind, action, steps=(), state=1, setup=None):
        data, context = block(kind, action, state), Trace(steps)
        if setup:
            setup(data, context)
        result = _run(f"Ex2FCHV_{kind}_SendMessage", (data,), context)
        self.assertEqual(context.steps, [])
        return result, data, context

    def assert_closed(self, context, expected=True):
        self.assertEqual(("finalize",) in context.events, expected)

    def test_exact_exports_and_source_controls(self):
        self.assertEqual(supported_exports(SHA_PLUS_TY), _EXPORTS)
        self.assertEqual(supported_exports(SHA_18_TY), ())
        context = Trace()
        for name in (*_EXPORTS, "Ex2FCHV_26_SendMessage"):
            with self.subTest(name=name), self.assertRaises(TYSourceError):
                run_body(name, (block(24, 1),), context)
        context.module_sha256 = hashlib.sha256(context.module_bytes).hexdigest()
        with self.assertRaises(TYSourceError):
            run_body(_EXPORTS[0], (block(24, 1),), context)
        self.assertEqual(context.events, [])

    def test_native_input_contract(self):
        for kind, minimum in ((24, 0x38C), (25, 0x38C), (27, 0x24), (28, 0xB8)):
            for args in (
                (),
                (bytes(minimum),),
                (bytearray(minimum - 1),),
                (bytearray(65537),),
                (block(kind, 0), 0),
            ):
                with (
                    self.subTest(kind=kind, args_type=type(args)),
                    self.assertRaises(ValueError),
                ):
                    _run(f"Ex2FCHV_{kind}_SendMessage", args, Trace())

    def test_valve_straight_native_actions(self):
        for kind in (24, 25):
            for action, state, steps, expected in (
                (1, 1, [], 0),
                (14, 1, [routine(1, 0x1A, b"\x01")], 0),
                (15, 1, [io()], 0x8A2),
                (16, 1, [routine(2, 0x19), io()], 0x8A2),
                (17, 1, [routine(2, 0x19)], 0x8AA),
                (17, 3, [routine(2, 0x19)], 0x8AF),
                (5, 3, [routine(2, 0x16)], 0x8A6),
                (5, 5, [routine(2, 0x16)], 0x8AC),
                (5, 8, [routine(2, 0x16)], 99),
            ):
                with self.subTest(kind=kind, action=action, state=state):
                    result, _, context = self.invoke(kind, action, steps, state)
                    self.assertEqual(result, expected)
                    self.assert_closed(
                        context, action == 1 or action == 5 and state in (5, 8)
                    )

    def test_valve_start_independent_25_branch_and_mutable_state(self):
        for kind, action, state in ((24, 2, 1), (24, 3, 4), (25, 2, 1), (25, 3, 4)):
            steps = (
                []
                if kind == 25 and action == 3
                else [io(3, MASK + MASK), read(0x1B, 0xBE, b"\x03\x43")]
            )
            steps += [routine(1, 0x19, b"\xc8")]
            result, data, context = self.invoke(kind, action, steps)
            self.assertEqual((result, _u32(data, 0x388)), (0x8B0, state))
            self.assert_closed(context, False)
            sleeps = [row[1] for row in context.events if row[0] == "sleep"]
            self.assertEqual(
                sleeps,
                [3000]
                if kind == 25 and action == 3
                else [200, 3000 if action == 2 else 2000, 3000],
            )

    def test_valve_start_fault_mapping_and_release(self):
        for kind in (24, 25):
            for steps, expected, closed in (
                ([io(3, MASK + MASK, 7), io()], 0x89D, True),
                ([io(3, MASK + MASK), read(0x1B, 0xBE, b"", 8), io()], 0x8A2, False),
                (
                    [
                        io(3, MASK + MASK),
                        read(0x1B, 0xBE, b"\0\0"),
                        routine(1, 0x19, b"\xc8", 8),
                        routine(2, 0x19),
                        io(),
                    ],
                    0x8B2,
                    False,
                ),
            ):
                result, _, context = self.invoke(kind, 2, steps)
                self.assertEqual(result, expected)
                self.assert_closed(context, closed)

    def test_valve_activation_and_state_sensitive_cleanup(self):
        for state in (1, 2, 3, 4):
            result, _, context = self.invoke(
                24, 4, [routine(1, 0x16), read(0x1B, 0xBF, b"\0\x40")], state
            )
            self.assertEqual(result, 0x8B3 if state in (1, 2, 4) else 0x8AB)
            self.assert_closed(context, False)
        for state in (1, 3):
            steps = [routine(1, 0x16, status=8), routine(2, 0x16)] + (
                [io()] if state == 1 else []
            )
            result, _, context = self.invoke(24, 4, steps, state)
            self.assertEqual(result, 0x8B2 if state == 1 else 0x8B1)
            self.assert_closed(context, state == 3)
        self.assertEqual(
            self.invoke(
                24,
                4,
                [routine(1, 0x16), read(0x1B, 0xBF, b"", 9), routine(2, 0x16), io()],
            )[0],
            0x8A2,
        )

    def test_valve_advance_branches(self):
        for state in (1, 4):
            result, data, _ = self.invoke(
                24, 5, [routine(2, 0x16), routine(1, 0x19, b"\xc8")], state
            )
            self.assertEqual(result, 0x8B0 if state == 1 else 0x8A7)
            self.assertEqual(_u32(data, 0x388), 2 if state == 1 else 4)
        self.assertEqual(
            self.invoke(
                24,
                5,
                [
                    routine(2, 0x16),
                    io(3, bytes(8) + MASK),
                    read(0x1B, 0xBE, b"\x01\x02"),
                ],
                2,
            )[0],
            0x8A5,
        )
        self.assertEqual(
            self.invoke(
                24,
                5,
                [
                    routine(2, 0x16),
                    io(3, bytes(8) + MASK),
                    read(0x1B, 0xBE, b"", 8),
                    io(),
                ],
                2,
            )[0],
            0x8A2,
        )
        self.assertEqual(
            self.invoke(24, 5, [routine(2, 0x16), io(3, bytes(8) + MASK, 8), io()], 2)[
                0
            ],
            0x8B2,
        )

    def test_valve_support_bitmaps_and_masks(self):
        for kind in (24, 25):
            support = bytearray(26 if kind == 24 else 24)
            support[0] = 4
            support[-1] = 2 if kind == 24 else 0
            steps = [read(1, 1, b"\0\0\0\x10"), read(0x1B, 0, bytes(support))]
            if kind == 24:
                steps += [read(0x1B, 0xCF, b"\0\0\0\0\x04")]
            steps += [read(0x28, 0x1F, b"\x11\0\x22\0\x44\0\xff")]

            def setup(data, context):
                data[12] = 4

            result, data, context = self.invoke(kind, 0, steps, setup=setup)
            self.assertEqual(
                (result, _u32(data, 16), data[0x384:0x388]), (0, 1, b"\x11\x22\x44\x07")
            )
            self.assert_closed(context)
        result, _, context = self.invoke(
            24, 0, [read(1, 1, b"\0\0\0\0"), read(0x28, 0x1F, bytes(7))]
        )
        self.assertEqual(result, 0)
        self.assert_closed(context)

    def test_valve_monitor_exact_row_offsets_and_boolean_masks(self):
        for action in (6, 7, 8):

            def setup(data, context, action=action):
                data[4:6] = b"\x1b\xbf"
                _put(data, 16, 1)
                _put(data, 20, 0)
                data[25] = 0x40
                _put(data, 28 if action == 6 else 32 if action == 7 else 36, 1)
                _put(data, 0x380, 1)
                if action == 8:
                    context.tick_step = 6000

            steps = [read(0x1B, 0xBF, b"\0\x40")]
            result, data, _ = self.invoke(24, action, steps, setup=setup)
            self.assertEqual((result, data[40:42], _u32(data, 44)), (0, b"\0\x01", 1))

    def test_valve_twelve_bit_expansion(self):
        def setup(data, context):
            data[4:6] = b"\x1b\xbe"
            _put(data, 16, 1)
            _put(data, 28, 1)
            _put(data, 0x380, 1)
            for row in range(12):
                data[25 + row * 44] = 1 << (row % 6)

        result, data, _ = self.invoke(
            24, 6, [read(0x1B, 0xBE, b"\x15\x2a")], setup=setup
        )
        self.assertEqual(result, 0)
        self.assertEqual(
            [data[41 + row * 44] for row in range(12)],
            [1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1],
        )

    def test_pressure_straight_actions_and_retention(self):
        for action, steps, expected, closed in (
            (3, [io(3, MASK + MASK), read(0x1B, 0xBE, MASK)], 0, False),
            (4, [io(3, bytes(8) + MASK), read(0x1B, 0xBE, bytes(8))], 0, False),
            (5, [io(3, bytes(8) + MASK, 8)], 0, False),
            (6, [io()], 0, True),
            (9, [], 0, True),
            (99, [], 0, True),
        ):
            result, _, context = self.invoke(27, action, steps)
            self.assertEqual(result, expected)
            self.assert_closed(context, closed)
        result, _, context = self.invoke(
            27,
            1,
            [routine(1, 0x1A, b"\x01"), io(3, MASK + MASK), read(0x1B, 0xBE, MASK)],
        )
        self.assertEqual(result, 0)
        self.assert_closed(context, False)

    def test_pressure_threshold_checks_use_two_signed_descriptors(self):
        steps = [
            read(0x1B, 0xAE, b"\0\0\xf3\x34"),
            read(0x1B, 0x9A, b"\x7f\xff"),
            io(3, MASK + MASK),
            read(0x1B, 0xBE, MASK),
        ]
        result, data, context = self.invoke(27, 2, steps)
        self.assertEqual(
            (result, data[14:18], data[20:22]), (0, b"\0\0\xf3\x34", b"\x7f\xff")
        )
        self.assert_closed(context, False)
        result, _, context = self.invoke(27, 2, [read(0x1B, 0xAE, b"\0\0\xf3\x33")])
        self.assertEqual(result, 2002)
        self.assert_closed(context)

    def test_pressure_failure_and_nrc_mapping(self):
        for status, nrc, expected in ((7, 105, 2001), (7, 104, 2000), (8, 105, 2000)):

            def setup(data, context, nrc=nrc):
                context.nrc = nrc

            result, _, context = self.invoke(
                27, 3, [io(3, MASK + MASK, status), io()], setup=setup
            )
            self.assertEqual(result, expected)
            self.assert_closed(context)
        self.assertEqual(self.invoke(27, 1, [routine(1, 0x1A, b"\x01", 8)])[0], 2000)

    def test_pressure_monitor_stop_flags_outputs_and_errors(self):
        for action in (7, 8):

            def setup(data, context):
                context.on_sleep = lambda: _put(data, 4, 1)

            steps = [read(0x1B, 0xAE, bytes(4))] if action == 8 else []
            steps += [read(0x1B, 0x9A, b"\x12\x34"), read(0x1B, 0x9B, b"\x56\x78")]
            result, data, context = self.invoke(27, action, steps, setup=setup)
            self.assertEqual(
                (result, _u32(data, 8), data[20:22], data[26:28]),
                (0x802, 1, b"\x12\x34", b"\x56\x78"),
            )
            self.assert_closed(context, False)
        self.assertEqual(self.invoke(27, 7, [read(0x1B, 0x9A, b"", 7), io()])[0], 2000)
        self.assertEqual(self.invoke(27, 8, [read(0x1B, 0xAE, b"", 7)])[0], 2003)

    def test_pressure_support_native_checks(self):
        support = bytearray(32)
        support[19], support[23] = 0x20, 4
        steps = [
            read(1, 1, b"\0\0\0\x10" + bytes(28)),
            read(0x28, 0x1F, MASK),
            read(0x1B, 0, bytes(support)),
            read(0x1B, 0xCF, b"\x80\0\0\0\x04"),
        ]
        result, data, context = self.invoke(27, 0, steps)
        self.assertEqual((result, data[32:36]), (0, bytes(4)))
        self.assert_closed(context)
        self.assertEqual(self.invoke(27, 0, [read(1, 1, bytes(32))])[0], 3)

    def test_monitor_native_straight_actions(self):
        for action, steps, expected in (
            (3, [io()], 0x3F8),
            (4, [io(3, bytes(8) + MASK, 7)], 0x3FC),
            (5, [io(3, MASK + MASK), read(0x1B, 0xBE, MASK)], 0x402),
        ):
            result, _, context = self.invoke(28, action, steps)
            self.assertEqual(result, expected)
            self.assert_closed(context, action == 3)

    def test_monitor_three_literal_rows_and_stop_after_sample(self):
        def setup(data, context):
            for row, did in enumerate((0x9A, 0x9B, 0xAE)):
                base = 8 + row * 56
                data[base : base + 2] = bytes((0x1B, did))
            context.on_sleep = lambda: _put(data, 0xB4, 1)

        steps = [
            read(0x1B, did, value.to_bytes(2, "big"))
            for did, value in ((0x9A, 12), (0x9B, 34), (0xAE, 56))
        ]
        result, data, context = self.invoke(28, 2, steps, setup=setup)
        self.assertEqual(
            (result, data[24:26], data[80:82], data[136:138]),
            (0, b"\0\x0c", b"\0\x22", b"\0\x38"),
        )
        self.assert_closed(context, False)
        self.assertEqual(self.invoke(28, 2, [read(0, 0, b"", 8)])[0], 0x3FF)

    def test_monitor_start_signed_limit_and_retained_sample_fault(self):
        steps = [
            routine(1, 0x1A, b"\x01"),
            read(0, 0, b"\xf3\x34"),
            io(3, MASK + MASK),
            read(0x1B, 0xBE, MASK),
            read(0, 0, b"", 7),
        ]
        result, _, context = self.invoke(28, 1, steps)
        self.assertEqual(result, 0x3FF)
        self.assert_closed(context, False)
        result, _, context = self.invoke(
            28, 1, [routine(1, 0x1A, b"\x01"), read(0, 0, b"\xf3\x33")]
        )
        self.assertEqual(result, 0x3F4)
        self.assert_closed(context)

    def test_monitor_native_error_map(self):
        for status, nrc, expected in (
            (7, 105, 0x3F1),
            (7, 104, 0x3F0),
            (8, 105, 0x3F0),
        ):

            def setup(data, context, nrc=nrc):
                context.nrc = nrc

            result, _, context = self.invoke(
                28, 5, [io(3, MASK + MASK, status), io()], setup=setup
            )
            self.assertEqual(result, expected)
            self.assert_closed(context)
        self.assertEqual(
            self.invoke(28, 5, [io(3, MASK + MASK), read(0x1B, 0xBE, b"", 8), io()])[0],
            0x3F0,
        )

    def test_monitor_support_exact_descriptor_checks(self):
        support = bytearray(32)
        support[1], support[23] = 4, 4

        def setup(data, context):
            data[9] = 0x9B
            _put(data, 12, 1)
            data[16] = 4

        steps = [
            read(1, 1, b"\0\0\0\x10" + bytes(28)),
            read(0x28, 0x1F, MASK),
            read(0x1B, 0, bytes(support)),
            read(0x1B, 0xCF, b"\x80\0\0\0\x04"),
        ]
        result, data, context = self.invoke(28, 0, steps, setup=setup)
        self.assertEqual((result, data[0xB0:0xB4]), (0, bytes(4)))
        self.assert_closed(context)
        self.assertEqual(self.invoke(28, 0, [read(1, 1, bytes(32))])[0], 3)

    def test_native_initialize_and_session_failures_finalize(self):
        for kind, action in (
            (24, 0),
            (25, 0),
            (24, 14),
            (27, 0),
            (27, 1),
            (28, 0),
            (28, 1),
        ):
            for initialize in (True, False):

                def setup(data, context, initialize=initialize):
                    context.init_status = 61 if initialize else 0
                    context.session_status = 62

                result, _, context = self.invoke(kind, action, setup=setup)
                self.assertEqual(result, 61 if initialize else 62)
                self.assert_closed(context)

    def test_malformed_replies_and_host_fault_cleanup(self):
        for cls, kind in ((_Valves, 24), (_Pressure, 27), (_Monitor, 28)):
            for reply in (b"", b"\x62\x1b\xff\0\0"):
                context = Trace([(b"\x22\x1b\xbe", 0, reply)])
                worker = cls(block(kind, 0), context, context)
                self.assertEqual(worker.read(0x1B, 0xBE, 0, 2)[0], 3)
            for status in (-1, True, 1 << 32):
                context = Trace([(b"\x22\x1b\xbe", status, b"")])
                with self.assertRaises(TypeError):
                    cls(block(kind, 0), context, context).read(0x1B, 0xBE, 0, 2)
        for kind, action in ((24, 2), (25, 2), (27, 3), (28, 5)):
            context = Trace()
            context.fault = OSError("driver fault")
            with self.assertRaisesRegex(OSError, "driver fault"):
                _run(f"Ex2FCHV_{kind}_SendMessage", (block(kind, action),), context)
            self.assert_closed(context)

    def test_cancel_before_io_and_during_wait_releases(self):
        for kind in (24, 25, 27, 28):
            context = Trace()
            context.cancelled = True
            with self.assertRaises(Cancelled):
                _run(f"Ex2FCHV_{kind}_SendMessage", (block(kind, 0),), context)
            self.assertEqual(context.events, [])
        for kind, action, start in (
            (24, 2, [io(3, MASK + MASK)]),
            (27, 3, [io(3, MASK + MASK)]),
            (28, 5, [io(3, MASK + MASK)]),
        ):
            context, data = Trace(start + [io()]), block(kind, action)
            context.on_sleep = lambda context=context: setattr(
                context, "cancelled", True
            )
            with self.assertRaises(Cancelled):
                _run(f"Ex2FCHV_{kind}_SendMessage", (data,), context)
            self.assert_closed(context)
            self.assertEqual(context.steps, [])

    def test_wrapping_native_timeout_not_iteration_limit(self):
        context = Trace(
            [
                io(3, MASK + MASK),
                read(0x1B, 0xBE, bytes(8)),
                read(0x1B, 0xBE, bytes(8)),
                io(),
            ]
        )
        context.clock, context.tick_step = 0xFFFFFF00, 5000
        result = _run(_EXPORTS[2], (block(27, 3),), context)
        self.assertEqual(result, 2001)
        self.assert_closed(context)
        self.assertEqual(context.steps, [])

    def test_timeout_helpers_use_exact_native_boundaries(self):
        for cls, kind, action, steps, expected in (
            (
                _Valves,
                24,
                2,
                [io(3, MASK + MASK), read(0x1B, 0xBE, b"\x01\x02"), io()],
                0x8B2,
            ),
            (
                _Valves,
                24,
                4,
                [routine(1, 0x16), read(0x1B, 0xBF, bytes(2)), routine(2, 0x16), io()],
                0x8B2,
            ),
            (
                _Valves,
                24,
                5,
                [
                    routine(2, 0x16),
                    io(3, bytes(8) + MASK),
                    read(0x1B, 0xBE, b"\x01\x01"),
                    io(),
                ],
                0x8B2,
            ),
            (
                _Monitor,
                28,
                5,
                [io(3, MASK + MASK), read(0x1B, 0xBE, bytes(8)), io()],
                0x3F1,
            ),
        ):
            context, data = Trace(steps), block(kind, action, 2)
            worker = cls(data, context, context)
            worker.timer = 0
            context.clock = 5001
            result = (
                worker.action(action, False)
                if isinstance(worker, _Valves)
                else worker.action(action)
            )
            self.assertEqual(result, expected)
            self.assertEqual(context.steps, [])

    def test_malformed_echoes_and_bounded_driver_reply(self):
        for packet in (io(3, MASK + MASK)[0], routine(1, 0x16)[0]):
            for reply in (b"", b"\x71\x00\x11\x16", b"\x6f\x28\x1f"):
                context = Trace([(packet, 0, reply)])
                worker = _Valves(block(24, 0), context, context)
                self.assertEqual(worker.echo(packet), 3)
        for reply in (bytearray(), bytes(4129)):
            context = Trace([(b"\x22\x1b\xbe", 0, reply)])
            with self.assertRaises(ValueError):
                _Valves(block(24, 0), context, context).read(0x1B, 0xBE, 0, 2)
        context = Trace()
        worker = _Valves(block(24, 0), context, context)
        for offset, size in ((-1, 2), (4125, 2)):
            with self.assertRaises(ValueError):
                worker.read(0x1B, 0xBE, offset, size)
        self.assertEqual(context.events, [])

    def test_cancel_active_routine_stops_before_mask_release(self):
        context = Trace([routine(1, 0x16), routine(2, 0x16), io()])
        context.on_sleep = lambda: setattr(context, "cancelled", True)
        with self.assertRaises(Cancelled):
            _run(_EXPORTS[0], (block(24, 4),), context)
        self.assert_closed(context)
        self.assertEqual(context.steps, [])

    def test_normal_restore_error_precedence_and_support_error_cleanup(self):
        for kind, action, steps in (
            (24, 0, [read(1, 1, bytes(4)), read(0x28, 0x1F, bytes(7))]),
            (27, 0, [read(1, 1, bytes(32))]),
        ):
            context, data = Trace(steps), block(kind, action)

            # Extended succeeds while normal restore fails.
            def session(
                mode,
                keepalive=1,
                *,
                normal_first=False,
                stop_on_error=False,
                context=context,
            ):
                context.events.append(("session", mode))
                return 61 if mode == 1 else 0

            context.session = session
            result = _run(f"Ex2FCHV_{kind}_SendMessage", (data,), context)
            self.assertEqual(result, 61 if kind == 24 else 3)
            self.assert_closed(context)
            self.assertEqual(context.steps, [])

    def test_untrusted_descriptor_indices_and_slices_fail_closed(self):
        context, data = (
            Trace([read(1, 1, b"\0\0\0\x10"), read(0x1B, 0, bytes(26)), io()]),
            block(24, 0),
        )
        _put(data, 8, 26)
        with self.assertRaisesRegex(ValueError, "support index"):
            _run(_EXPORTS[0], (data,), context)
        self.assert_closed(context)
        self.assertEqual(context.steps, [])
        context, data = Trace([io()]), block(28, 2)
        _put(data, 20, 4125)
        with self.assertRaisesRegex(ValueError, "diagnostic slice"):
            _run(_EXPORTS[3], (data,), context)
        self.assert_closed(context)
        self.assertEqual(context.steps, [])
        context, data = Trace([read(0x1B, 0xBE, bytes(2)), io()]), block(24, 6)
        base = 4 + 9 * 44
        data[base : base + 2] = b"\x1b\xbe"
        _put(data, base + 12, 1)
        _put(data, base + 24, 1)
        with self.assertRaisesRegex(ValueError, "twelve-row bitmap"):
            _run(_EXPORTS[0], (data,), context)
        self.assert_closed(context)
        self.assertEqual(context.steps, [])

    def test_pressure_dispatch_reloads_mutable_action_after_initialization(self):
        data, context = block(27, 0), Trace()

        def initialize(mode=0):
            context.events.append(("initialize", mode))
            _put(data, 0, 9)
            return 0

        context.initialize = initialize
        self.assertEqual(_run(_EXPORTS[2], (data,), context), 0)
        self.assertFalse(any(event[0] == "exchange" for event in context.events))
        self.assertIn(("session", 1, 1, False, True), context.events)
        self.assert_closed(context)

    def test_pressure_poll_snapshot_and_live_release_have_distinct_boundaries(self):
        data = block(27, 3)
        context = Trace(
            [io(3, MASK + MASK), read(0x1B, 0xBE, bytes(8)), io(0, bytes(8))]
        )
        context.on_exchange = lambda request: data.__setitem__(
            slice(0x20, 0x24), bytes(4)
        )
        context.clock = 5001
        worker = _Pressure(data, context, context)
        worker.timer = 0
        self.assertEqual(worker.control(True, True, False), 2001)
        self.assertEqual(context.steps, [])
        self.assertIn(("session", 1, 1, False, True), context.events)

    def test_monitor_poll_and_release_both_keep_entry_snapshot(self):
        data = block(28, 5)
        context = Trace([io(3, MASK + MASK), read(0x1B, 0xBE, bytes(8)), io()])
        context.on_exchange = lambda request: data.__setitem__(
            slice(0xB0, 0xB4), bytes(4)
        )
        context.clock = 5001
        worker = _Monitor(data, context, context)
        worker.timer = 0
        self.assertEqual(worker.control(False), 0x3F1)
        self.assertEqual(context.steps, [])
        self.assert_closed(context)

    def test_monitor_captures_masks_before_initialize_callback(self):
        data = block(28, 1)
        context = Trace(
            [
                routine(1, 0x1A, b"\x01"),
                read(0, 0, bytes(2)),
                io(3, MASK + MASK),
                read(0x1B, 0xBE, MASK),
            ]
            + [read(0, 0, bytes(2))] * 3
        )

        def initialize(mode=0):
            data[0xB0:0xB4] = bytes(4)
            return 0

        context.initialize = initialize
        self.assertEqual(_run(_EXPORTS[3], (data,), context), 0)
        self.assertEqual(context.steps, [])
        self.assert_closed(context, False)

    def test_native_normal_failure_unconditionally_stops_keepalive(self):
        class SessionFailure(Trace):
            def __init__(self, steps):
                super().__init__(steps)
                self.keepalive = True

            def session(
                self, mode, keepalive=1, *, normal_first=False, stop_on_error=False
            ):
                self.events.append(
                    ("session", mode, keepalive, normal_first, stop_on_error)
                )
                if mode == 1 and stop_on_error:
                    self.keepalive = False
                return 7

        for kind, action, steps in (
            (24, 1, []),
            (25, 1, []),
            (27, 9, []),
            (28, 3, [io()]),
        ):
            context = SessionFailure(steps)
            _run(f"Ex2FCHV_{kind}_SendMessage", (block(kind, action),), context)
            self.assertFalse(context.keepalive)
            self.assert_closed(context)

    def test_non9b_unused_bitmap_index_preserves_native_support_success(self):
        data = block(28, 0)
        data[8:10] = b"\x1b\x9a"
        _put(data, 12, 0xFFFFFFFF)
        support = bytearray(32)
        support[23] = 4
        context = Trace(
            [
                read(1, 1, b"\0\0\0\x10" + bytes(28)),
                read(0x28, 0x1F, MASK),
                read(0x1B, 0, bytes(support)),
                read(0x1B, 0xCF, b"\x80\0\0\0\x04"),
            ]
        )
        self.assertEqual(_run(_EXPORTS[3], (data,), context), 0)
        self.assertEqual(context.steps, [])
        self.assert_closed(context)

    def test_retained_routine_released_on_later_fault_and_canceled_entry(self):
        for cancelled in (False, True):
            data = block(24, 4)
            context = Trace([routine(1, 0x16), read(0x1B, 0xBF, b"\0\x40")])
            self.assertEqual(_run(_EXPORTS[0], (data,), context), 0x8B3)
            context.steps.extend([routine(2, 0x16), io()])
            primary = LookupError("later retained monitor fault")
            _put(data, 0, 6)
            data[4:6] = b"\x1b\0"
            _put(data, 16, 1)
            _put(data, 28, 1)

            def fault(request, primary=primary):
                if request == b"\x22\x1b\0":
                    raise primary

            context.on_exchange = fault
            context.cancelled = cancelled
            if cancelled:
                with self.assertRaises(Cancelled):
                    _run(_EXPORTS[0], (data,), context)
            else:
                with self.assertRaises(LookupError) as caught:
                    _run(_EXPORTS[0], (data,), context)
                self.assertIs(caught.exception, primary)
            self.assertEqual(context.cancelled, cancelled)
            self.assertEqual(context.steps, [])
            self.assert_closed(context)
            self.assertEqual(context.state[f"fchv-plus:{SHA_PLUS_TY}:outputs"], {})

    def test_retained_valve_release_uses_saved_mask_after_caller_mutation(self):
        data = block(27, 5)
        context = Trace([io(3, bytes(8) + MASK), io()])
        self.assertEqual(_run(_EXPORTS[2], (data,), context), 0)
        data[0x20:0x24] = bytes(4)
        context.cancelled = True
        with self.assertRaises(Cancelled):
            _run(_EXPORTS[2], (data,), context)
        self.assertEqual(context.steps, [])
        self.assertTrue(context.cancelled)
        self.assert_closed(context)

    def test_cleanup_secondary_baseexceptions_preserve_primary_and_all_releases(self):
        class FaultCleanup(Trace):
            def cleanup_exchange(self, request):
                self.events.append(("cleanup_exchange", request))
                raise KeyboardInterrupt("secondary release fault")

            def cleanup_session(
                self, mode, keepalive=1, *, normal_first=False, stop_on_error=False
            ):
                self.events.append(("cleanup_session", mode, stop_on_error))
                raise SystemExit("secondary session fault")

            def finalize(self):
                self.events.append(("finalize",))
                raise KeyboardInterrupt("secondary finalize fault")

        data = block(24, 4)
        context = FaultCleanup([routine(1, 0x16), read(0x1B, 0xBF, b"\0\x40")])
        self.assertEqual(_run(_EXPORTS[0], (data,), context), 0x8B3)
        primary = LookupError("retained primary")
        _put(data, 0, 6)
        data[4:6] = b"\x1b\0"
        _put(data, 16, 1)
        _put(data, 28, 1)

        def fault(request):
            raise primary

        context.on_exchange = fault
        with self.assertRaises(LookupError) as caught:
            _run(_EXPORTS[0], (data,), context)
        self.assertIs(caught.exception, primary)
        self.assertEqual(
            [e[1] for e in context.events if e[0] == "cleanup_exchange"],
            [routine(2, 0x16)[0], io()[0]],
        )
        self.assertIn(("cleanup_session", 1, True), context.events)
        self.assert_closed(context)
        self.assertEqual(len(primary.__notes__), 4)

    def test_retained_outputs_release_before_finalize_when_normal_helper_raises(self):
        data = block(24, 4)
        context = Trace(
            [routine(1, 0x16), read(0x1B, 0xBF, b"\0\x40"), routine(2, 0x16), io()]
        )
        self.assertEqual(_run(_EXPORTS[0], (data,), context), 0x8B3)
        _put(data, 0, 1)
        primary = LookupError("normal helper host fault")

        def session(mode, keepalive=1, *, normal_first=False, stop_on_error=False):
            raise primary

        context.session = session
        with self.assertRaises(LookupError) as caught:
            _run(_EXPORTS[0], (data,), context)
        self.assertIs(caught.exception, primary)
        self.assertEqual(context.steps, [])
        self.assertLess(
            context.events.index(("exchange", routine(2, 0x16)[0])),
            context.events.index(("finalize",)),
        )

    def test_retained_outputs_release_after_native_finalize_host_fault(self):
        data = block(24, 4)
        context = Trace(
            [routine(1, 0x16), read(0x1B, 0xBF, b"\0\x40"), routine(2, 0x16), io()]
        )
        self.assertEqual(_run(_EXPORTS[0], (data,), context), 0x8B3)
        _put(data, 0, 1)
        primary = SystemExit("native finalizer host fault")
        calls = 0

        def finalize():
            nonlocal calls
            calls += 1
            context.events.append(("finalize",))
            if calls == 1:
                raise primary

        context.finalize = finalize
        with self.assertRaises(SystemExit) as caught:
            _run(_EXPORTS[0], (data,), context)
        self.assertIs(caught.exception, primary)
        self.assertEqual(context.steps, [])
        self.assertEqual(calls, 2)

    def test_retained_manager_sequence_uses_same_mutable_block(self):
        data = block(24, 2, 3)
        context = Trace(
            [
                io(3, MASK + MASK),
                read(0x1B, 0xBE, bytes(2)),
                routine(1, 0x19, b"\xc8"),
                routine(1, 0x16),
                read(0x1B, 0xBF, b"\0\x40"),
                routine(2, 0x16),
                routine(1, 0x19, b"\xc8"),
                routine(2, 0x19),
                io(),
            ]
        )
        results = []
        for action in (2, 4, 5, 16, 1):
            _put(data, 0, action)
            results.append(_run(_EXPORTS[0], (data,), context))
        self.assertEqual(results, [0x8B0, 0x8B3, 0x8B0, 0x8A2, 0])
        self.assertEqual(_u32(data, 0x388), 2)
        self.assertEqual(context.events.count(("finalize",)), 1)
        self.assertEqual(context.steps, [])

    def test_real_current_ty_aggregator_source_join(self):
        from scripts.utility_ex_ty import run_body as ty_run_body
        from scripts.utility_ex_ty import supported_exports as ty_supported_exports

        path = Path(
            "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll"
        )
        if not path.exists():
            self.skipTest("Private supplied source unavailable")
        image = path.read_bytes()
        for kind in (24, 25, 27, 28):
            export = f"Ex2FCHV_{kind}_SendMessage"
            self.assertIn(export, ty_supported_exports(SHA_PLUS_TY))
            self.assertNotIn(export, ty_supported_exports(SHA_18_TY))
            action = 1 if kind == 28 else 2
            data = block(kind, action, 3)
            if kind in (24, 25):
                steps = [
                    io(3, MASK + MASK),
                    read(0x1B, 0xBE, bytes(2)),
                    routine(1, 0x19, b"\xc8"),
                ]
                expected = 0x8B0
            elif kind == 27:
                steps = [
                    read(0x1B, 0xAE, b"\0\0\0\x11"),
                    read(0x1B, 0x9A, b"\0\x22"),
                    io(3, MASK + MASK),
                    read(0x1B, 0xBE, MASK),
                ]
                expected = 0
            else:
                steps = [
                    routine(1, 0x1A, b"\x01"),
                    read(0, 0, b"\0\x11"),
                    io(3, MASK + MASK),
                    read(0x1B, 0xBE, MASK),
                ]
                steps += [
                    read(0, 0, b"\0\x22"),
                    read(0, 0, b"\0\x33"),
                    read(0, 0, b"\0\x44"),
                ]
                expected = 0
            context = Trace(steps)
            context.module_bytes = image
            self.assertEqual(ty_run_body(export, (data,), context), expected)
            self.assertEqual(context.steps, [])
            self.assert_closed(context, False)
            if kind in (24, 25):
                self.assertEqual(_u32(data, 0x388), 1)
            elif kind == 27:
                self.assertEqual(data[14:18], b"\0\0\0\x11")
            else:
                self.assertEqual(
                    (data[24:26], data[80:82], data[136:138]),
                    (b"\0\x22", b"\0\x33", b"\0\x44"),
                )

    def test_real_original_hash_admission(self):
        path = Path(
            "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll"
        )
        if not path.exists():
            self.skipTest("Private supplied source unavailable")
        context = Trace()
        context.module_bytes = path.read_bytes()
        self.assertEqual(hashlib.sha256(context.module_bytes).hexdigest(), SHA_PLUS_TY)
        self.assertEqual(run_body(_EXPORTS[0], (block(24, 1),), context), 0)
        self.assert_closed(context)
        context.module_bytes += b"changed"
        with self.assertRaises(TYSourceError):
            run_body(_EXPORTS[0], (block(24, 1),), context)


if __name__ == "__main__":
    unittest.main()
