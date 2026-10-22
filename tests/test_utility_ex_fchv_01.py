"""Authored literal wire traces; tests never execute an OEM instruction."""

from __future__ import annotations

import hashlib
import unittest
from collections.abc import Callable
from typing import cast
from unittest.mock import patch

from scripts.toyota_session import Cancelled
from scripts.utility_ex_fchv_01 import (
    SHA_18_TY,
    SHA_PLUS_TY,
    _put,
    _run,
    _u32,
    _Worker,
    run_body,
    supported_exports,
)
from scripts.utility_ex_ty import TYSourceError, elapsed_ticks
from tests.test_utility_ex_fchv import Context

EXPORT = "Ex2FCHV_01_SendMessage"
SOURCES = (SHA_18_TY, SHA_PLUS_TY)
Step = tuple[bytes, int, bytes]


def ctl(did: int, payload: bytes = b"\0\x80", status: int = 0) -> Step:
    return (
        b"\x2f\x28" + bytes((did,)) + payload,
        status,
        b"\x6f\x28" + bytes((did, payload[0])),
    )


def routine(mode: int, number: int, value: int | None = None, status: int = 0) -> Step:
    packet = bytes((0x31, mode, 0x11, number))
    if value is not None:
        packet += bytes((value,))
    return packet, status, b"\x71" + packet[1:4]


def read(
    did: int,
    number: int,
    offset: int = 0,
    size: int = 2,
    *,
    first: int = 0x1B,
    status: int = 0,
) -> Step:
    return (
        bytes((0x22, first, did)),
        status,
        bytes((0x62, first, did)) + bytes(offset) + number.to_bytes(size, "big"),
    )


def block(
    action: int, *, special: bool = True, stop: int = 0, count: int = 0
) -> bytearray:
    data = bytearray(28)
    for offset, value in (
        (0, action),
        (4, stop),
        (8, count),
        (24, 0x18D if special else 0),
    ):
        _put(data, offset, value)
    return data


class Trace(Context):
    def __init__(self, steps: list[Step], source: str = SHA_18_TY):
        super().__init__(source)
        self.steps = steps[:]
        self.tick_step = 0
        self.on_exchange: Callable[[bytes], None] | None = None

    def exchange(self, request):
        self.events.append(("exchange", request))
        if self.fault:
            raise self.fault
        if self.on_exchange:
            self.on_exchange(request)
        if not self.steps:
            raise AssertionError(f"Unexpected packet: {request.hex()}")
        expected, status, reply = self.steps.pop(0)
        if request != expected:
            raise AssertionError(f"Packet {request.hex()}, expected {expected.hex()}")
        return status, reply

    def cleanup_exchange(self, request: bytes) -> tuple[int, bytes]:
        return self.exchange(request)

    def cleanup_session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int:
        return self.session(
            mode, keepalive, normal_first=normal_first, stop_on_error=stop_on_error
        )

    def native_sleep(self, milliseconds: int) -> None:
        self.sleep(milliseconds)

    def read_dtcs(self, mode: int = 0x80, capacity: int = 0x1000) -> tuple[int, bytes]:
        raise AssertionError("Unexpected native DTC read")

    def ticks(self):
        value = self.clock
        self.clock = (self.clock + self.tick_step) & 0xFFFFFFFF
        return value

    def assert_consumed(self, case: unittest.TestCase):
        case.assertEqual(self.steps, [])


def wires(context: Trace) -> list[bytes]:
    return [row[1] for row in context.events if row[0] == "exchange"]


class ActionTests(unittest.TestCase):
    def invoke(
        self,
        action,
        steps,
        *,
        source=SHA_18_TY,
        special=True,
        count=0,
        stop=0,
        tick_step=0,
    ):
        data = block(action, special=special, count=count, stop=stop)
        context = Trace(steps, source)
        context.tick_step = tick_step
        result = _run((data,), context)
        context.assert_consumed(self)
        return result, data, context

    def test_all_straight_success_actions_each_source(self):
        for source in SOURCES:
            for special in (True, False):
                sensor = 5 if special else 0xC1
                support = bytearray(b"\xff" * 32)
                cases: dict[int, list[Step]] = {
                    0: [
                        read(1, int.from_bytes(support, "big"), size=32, first=1),
                        read(0, int.from_bytes(support, "big"), size=32),
                    ],
                    2: [routine(1, 0x1A, 3)]
                    + ([read(0x68, 3, size=1)] if special else [])
                    + [read(0x69, 10, size=1)],
                    3: [ctl(0x0B, b"\x03\x64\x80"), read(sensor, 0xB0A4, 10)],
                    4: [
                        ctl(0x11, b"\x03\x09\xc4\x80"),
                        read(0x18, 0x88CA),
                        read(0x19, 2250),
                        read(0x17, 33, 3),
                    ],
                    5: [ctl(0x0A, b"\x03\x64\x80"), read(sensor, 0xB0A4, 6)],
                    6: [
                        ctl(0x14, b"\x03\x64\x80"),
                        read(sensor, 0xB0A4, 14),
                        ctl(0x0B),
                    ],
                    8: [
                        ctl(0x11, b"\x03\x03\xe8\x80"),
                        read(0x18, 0x8384),
                        read(0x19, 900),
                        read(0x17, 8, 3),
                    ],
                    9: [read(0x9B, 200)],
                    10: [routine(1, 0x19, 0x82), read(0x9C, 1234), read(0x9D, 1234)],
                    11: [
                        ctl(0x0D, b"\x03\x0c\x80\x80"),
                        read(sensor, 0xA000A000, size=4),
                    ]
                    + (
                        []
                        if source == SHA_PLUS_TY and not special
                        else [routine(1, 0x16)]
                    ),
                    13: [read(0x39, 419)],
                    14: [ctl(0x0D), read(sensor, 0x8320, 2)]
                    + ([] if source == SHA_PLUS_TY and not special else [ctl(0x11)]),
                    15: [
                        read(0x17, 9, 3),
                        read(0x19, 100),
                        read(0x39, 239),
                        routine(1, 0x16),
                    ],
                    17: [
                        read(0x9C, 10),
                        read(0x9D, 10),
                        routine(2, 0x19),
                        read(0x39, 240),
                    ],
                    19: [routine(1, 0x16)],
                }
                for action, steps in cases.items():
                    with self.subTest(
                        source=source[:12], special=special, action=action
                    ):
                        result, data, context = self.invoke(
                            action, steps, source=source, special=special
                        )
                        self.assertEqual(result, 2101 if action == 17 else 0)
                        final = [row for row in context.events if row[0] == "finalize"]
                        self.assertEqual(len(final), int(action == 0))
                        if action in (11, 15) and (
                            action == 15 or source == SHA_PLUS_TY and not special
                        ):
                            self.assertEqual(_u32(data, 8), 1)
                        if action in (4, 10):
                            self.assertEqual(_u32(data, 12 if action == 4 else 20), 0)

    def test_hold_and_transition_did_offsets_and_timer_resets(self):
        for source in SOURCES:
            for special in (True, False):
                flag = 6 if source == SHA_PLUS_TY or special else 0xBF
                steps = [
                    read(flag, 0x40, 1, 1),
                    routine(2, 0x16),
                    read(flag, 0, 1, 1),
                    routine(2, 0x19),
                ]
                if source != SHA_PLUS_TY or special:
                    result, _, context = self.invoke(
                        12, steps, source=source, special=special, tick_step=120001
                    )
                    self.assertEqual(result, 0)
                    self.assertNotIn(("finalize",), context.events)
                steps = [
                    read(flag, 0x40, 1, 1),
                    read(0x9C, 0x8000),
                    read(0x12, 1000, 4),
                    routine(2, 0x16),
                    read(flag, 0, 1, 1),
                    routine(1, 0x19, 0x82),
                ]
                result, _, context = self.invoke(
                    16, steps, source=source, special=special, tick_step=30001
                )
                self.assertEqual(result, 0)
                self.assertNotIn(("finalize",), context.events)

    def test_decay_busy_wait_then_temperature_reads(self):
        for source in SOURCES:
            result, _, context = self.invoke(
                7,
                [read(5, 0x828F, 10), read(0x39, 249)],
                source=source,
                tick_step=60001,
            )
            self.assertEqual(result, 0)
            self.assertEqual(
                [row for row in context.events if row[0] == "sleep"],
                [("sleep", 200), ("sleep", 1000)],
            )

    def test_cycle_special_cleanup_even_success(self):
        for source in SOURCES:
            steps = [
                routine(1, 0x16),
                read(6, 0x40, 1, 1),
                routine(2, 0x16),
                read(6, 0, 1, 1),
                ctl(0x14),
                ctl(0x0A),
                routine(2, 0x1A),
            ]
            result, _, context = self.invoke(18, steps, source=source)
            self.assertEqual(result, 0)
            self.assertIn(("sleep", 5000), context.events)
            self.assertEqual(
                context.events[-2:], [("session", 1, 1, False, False), ("finalize",)]
            )

    def test_plus_finish_nonspecial_has_four_interruptible_quarter_second_waits(self):
        steps = [
            ctl(0x11),
            read(0x17, 9, 3),
            read(0x19, 100),
            read(0x39, 239),
            ctl(0x14),
            ctl(0x0A),
            routine(2, 0x1A),
        ]
        result, _, context = self.invoke(18, steps, source=SHA_PLUS_TY, special=False)
        self.assertEqual(result, 0)
        self.assertEqual(
            [row[1] for row in context.events if row[0] == "sleep"],
            [200, 250, 250, 250, 250],
        )

    def test_plus_repeat_nonspecial_repeats_exactly_seven_cycles(self):
        cycle = [
            routine(1, 0x19, 200),
            read(0x9C, 10),
            read(0x9D, 10),
            routine(2, 0x19),
            routine(1, 0x16),
            read(0xBF, 0x0040),
            read(0x9C, 0x9631),
            routine(2, 0x16),
            read(0xBF, 0),
        ]
        result, data, context = self.invoke(
            12, cycle * 7, source=SHA_PLUS_TY, special=False
        )
        self.assertEqual(result, 0)
        self.assertEqual(_u32(data, 8), 6)
        self.assertEqual(
            sum(1 for row in context.events if row == ("sleep", 200)), 7 * 54
        )
        self.assertNotIn(("finalize",), context.events)

    def test_aborts_and_noop_all_native_switch_values(self):
        for source in SOURCES:
            for action in range(20, 26):
                dids = (
                    [0x11]
                    if action == 20
                    else [0x0D, 0x11]
                    if action in (21, 22)
                    else []
                ) + [0x14, 0x0A]
                result, _, context = self.invoke(
                    action, [ctl(did) for did in dids], source=source
                )
                self.assertEqual(result, 2100)
                self.assertEqual(("sleep", 3000) in context.events, action < 24)
                self.assertEqual(context.events[-1], ("finalize",))
            for action in (1, 26, 0xFFFFFFFF):
                result, _, context = self.invoke(action, [], source=source)
                self.assertEqual(result, 0)
                self.assertEqual(len(context.events), 1)

    def test_native_mutations_preserve_other_argument_bytes(self):
        for action, steps, offset in (
            (
                4,
                [
                    ctl(0x11, b"\x03\x09\xc4\x80"),
                    read(0x18, 0x88CA),
                    read(0x19, 2250),
                    read(0x17, 33, 3),
                ],
                12,
            ),
            (10, [routine(1, 0x19, 0x82), read(0x9C, 1), read(0x9D, 1)], 20),
            (14, [ctl(0x0D), read(5, 0x8320, 2), ctl(0x11)], 16),
        ):
            data = block(action)
            context = Trace(steps)
            context.clock = 123456
            before = bytes(data)
            self.assertEqual(_run((data,), context), 0)
            self.assertEqual(_u32(data, offset), 123456 + (200 if action == 14 else 0))
            self.assertEqual(
                data[:offset] + data[offset + 4 :],
                before[:offset] + before[offset + 4 :],
            )


class FailureTests(unittest.TestCase):
    invoke = ActionTests.invoke

    def test_support_mask_every_bit_and_first_gate(self):
        for special in (True, False):
            masks = [(2, 0x43), (3, 0x80), (7, 0x80), (13, 0x80), (19, 0x38)] + (
                [(0, 0x0C), (12, 1)] if special else [(23, 3), (24, 0x80)]
            )
            for index, mask in masks:
                for bit in range(8):
                    if not mask & 1 << bit:
                        continue
                    payload = bytearray(b"\xff" * 32)
                    payload[index] &= ~(1 << bit)
                    steps = [
                        read(1, (1 << 256) - 1, size=32, first=1),
                        read(0, int.from_bytes(payload, "big"), size=32),
                    ]
                    result, _, _ = self.invoke(0, steps, special=special)
                    self.assertEqual(result, 22)
        result, _, _ = self.invoke(0, [read(1, 0, size=32, first=1)])
        self.assertEqual(result, 22)

    def test_cleanup_on_initial_failed_controls_and_routines(self):
        cases = {
            2: ([routine(1, 0x1A, 3, 17)], 2025),
            3: ([ctl(0x0B, b"\x03\x64\x80", 17), ctl(0x0B)], 2026),
            4: ([ctl(0x11, b"\x03\x09\xc4\x80", 17), ctl(0x11), ctl(0x0B)], 2027),
            5: (
                [
                    ctl(0x0A, b"\x03\x64\x80", 17),
                    ctl(0x11),
                    ctl(0x0A),
                    ctl(0x0B),
                ],
                2028,
            ),
            6: (
                [
                    ctl(0x14, b"\x03\x64\x80", 17),
                    ctl(0x11),
                    ctl(0x14),
                    ctl(0x0A),
                    ctl(0x0B),
                ],
                2029,
            ),
            8: (
                [ctl(0x11, b"\x03\x03\xe8\x80", 17), ctl(0x11), ctl(0x14), ctl(0x0A)],
                2027,
            ),
            10: (
                [
                    routine(1, 0x19, 0x82, 17),
                    routine(2, 0x19),
                    ctl(0x11),
                    ctl(0x14),
                    ctl(0x0A),
                ],
                2034,
            ),
            11: (
                [
                    ctl(0x0D, b"\x03\x0c\x80\x80", 17),
                    ctl(0x0D),
                    routine(2, 0x19),
                    ctl(0x11),
                    ctl(0x14),
                    ctl(0x0A),
                ],
                2035,
            ),
            14: ([ctl(0x0D, status=17), ctl(0x11), ctl(0x14), ctl(0x0A)], 2035),
            18: (
                [routine(1, 0x16, status=17), routine(2, 0x16), ctl(0x14), ctl(0x0A)],
                2036,
            ),
            19: (
                [routine(1, 0x16, status=17), routine(2, 0x16), ctl(0x14), ctl(0x0A)],
                2036,
            ),
        }
        for source in SOURCES:
            for action, (steps, expected) in cases.items():
                with self.subTest(source=source[:12], action=action):
                    result, _, context = self.invoke(action, steps, source=source)
                    self.assertEqual(result, expected)
                    self.assertEqual(context.events[-1], ("finalize",))

    def test_native_ui_stop_still_runs_each_action_cleanup(self):
        for source in SOURCES:
            for special in (True, False):
                for action in (7, 12, 13, 15, 16, 17, 18):
                    if action == 18 and (source != SHA_PLUS_TY or special):
                        continue  # Native cycle deliberately ignores UI stop.
                    if action == 7:
                        steps = [ctl(0x11), ctl(0x14), ctl(0x0A)]
                    elif action == 12:
                        steps = (
                            [routine(1, 0x19, 200), routine(2, 0x19), routine(2, 0x16)]
                            if source == SHA_PLUS_TY and not special
                            else [routine(2, 0x16), ctl(0x0D), routine(2, 0x19)]
                        )
                        if source == SHA_PLUS_TY and not special:
                            steps.append(ctl(0x0D))
                        steps += [ctl(0x11), ctl(0x14), ctl(0x0A)]
                    elif action == 13:
                        steps = [ctl(0x0D), ctl(0x11), ctl(0x14), ctl(0x0A)]
                    elif action == 15:
                        steps = [ctl(0x14), ctl(0x0A)]
                    elif action == 16:
                        steps = [routine(2, 0x16), ctl(0x14), ctl(0x0A)]
                    elif action == 17:
                        steps = [routine(2, 0x19), ctl(0x14), ctl(0x0A)]
                    else:
                        steps = [ctl(0x11), ctl(0x14), ctl(0x0A)]
                    with self.subTest(
                        source=source[:12], special=special, action=action
                    ):
                        result, _, context = self.invoke(
                            action, steps, source=source, special=special, stop=1
                        )
                        self.assertEqual(result, 2100)
                        self.assertEqual(context.events[-1], ("finalize",))

    def test_retry_counter_limit_and_retention(self):
        for count, expected in ((0, 2101), (4, 2101), (5, 2038)):
            steps = [read(0x9C, 10), read(0x9D, 10), routine(2, 0x19), read(0x39, 240)]
            if count == 5:
                steps += [ctl(0x14), ctl(0x0A)]
            result, data, context = self.invoke(17, steps, count=count)
            self.assertEqual(result, expected)
            self.assertEqual(_u32(data, 8), count + int(count < 5))
            self.assertEqual(("finalize",) in context.events, count == 5)

    def test_timeout_edges_preserve_source_error_and_cleanup(self):
        tail = [ctl(0x14), ctl(0x0A)]
        cases = {
            2: ([routine(1, 0x1A, 3), read(0x68, 0, size=1)], 2025),
            3: ([ctl(0x0B, b"\x03\x64\x80"), read(5, 0xB0A3, 10), ctl(0x0B)], 2026),
            4: (
                [
                    ctl(0x11, b"\x03\x09\xc4\x80"),
                    read(0x18, 0x88C9),
                    ctl(0x11),
                    ctl(0x0B),
                ],
                2027,
            ),
            5: (
                [
                    ctl(0x0A, b"\x03\x64\x80"),
                    read(5, 0xB0A3, 6),
                    ctl(0x11),
                    ctl(0x0A),
                    ctl(0x0B),
                ],
                2028,
            ),
            6: (
                [ctl(0x14, b"\x03\x64\x80"), read(5, 0xB0A3, 14), ctl(0x11)]
                + tail
                + [ctl(0x0B)],
                2029,
            ),
            7: ([read(5, 0x8290, 10), ctl(0x11)] + tail, 2026),
            8: (
                [ctl(0x11, b"\x03\x03\xe8\x80"), read(0x18, 0x8383), ctl(0x11)] + tail,
                2027,
            ),
            9: ([read(0x9B, 199), ctl(0x11)] + tail, 2033),
            10: (
                [
                    routine(1, 0x19, 0x82),
                    read(0x9C, 9),
                    read(0x9D, 10),
                    routine(2, 0x19),
                    ctl(0x11),
                ]
                + tail,
                2034,
            ),
            11: (
                [
                    ctl(0x0D, b"\x03\x0c\x80\x80"),
                    read(5, 0x9F3F9F3F, size=4),
                    ctl(0x0D),
                    routine(2, 0x19),
                    ctl(0x11),
                ]
                + tail,
                2035,
            ),
            12: (
                [
                    read(6, 0, 1, 1),
                    routine(2, 0x16),
                    ctl(0x0D),
                    routine(2, 0x19),
                    ctl(0x11),
                ]
                + tail,
                2036,
            ),
            13: ([read(0x39, 420), ctl(0x0D), ctl(0x11)] + tail, 2038),
            14: ([ctl(0x0D), read(5, 0x8321, 2), ctl(0x11)] + tail, 2035),
            15: ([read(0x17, 10, 3)] + tail, 2037),
            16: ([read(6, 0, 1, 1), routine(2, 0x16)] + tail, 2036),
            17: ([read(0x9C, 9), read(0x9D, 10), routine(2, 0x19)] + tail, 2034),
            18: ([routine(1, 0x16), read(6, 0, 1, 1), routine(2, 0x16)] + tail, 2036),
        }
        for source in SOURCES:
            for action, (steps, expected) in cases.items():
                with self.subTest(source=source[:12], action=action):
                    result, _, _ = self.invoke(
                        action, steps, source=source, tick_step=2000000
                    )
                    self.assertEqual(result, expected)
        for action, steps, expected in (
            (
                12,
                [
                    routine(1, 0x19, 200),
                    read(0x9C, 9),
                    read(0x9D, 10),
                    routine(2, 0x19),
                    ctl(0x0D),
                    ctl(0x11),
                ]
                + tail,
                2034,
            ),
            (18, [ctl(0x11), read(0x17, 10, 3)] + tail, 2037),
        ):
            result, _, _ = self.invoke(
                action, steps, source=SHA_PLUS_TY, special=False, tick_step=2000000
            )
            self.assertEqual(result, expected)

    def test_each_straight_sensor_failure_maps_to_native_cleanup(self):
        tail = [ctl(0x14), ctl(0x0A)]
        cases = {
            2: ([routine(1, 0x1A, 3), read(0x68, 0, size=1, status=17)], 2025),
            3: (
                [ctl(0x0B, b"\x03\x64\x80"), read(5, 0, 10, status=17), ctl(0x0B)],
                2026,
            ),
            4: (
                [
                    ctl(0x11, b"\x03\x09\xc4\x80"),
                    read(0x18, 0, status=17),
                    ctl(0x11),
                    ctl(0x0B),
                ],
                2027,
            ),
            7: ([read(5, 0, 10, status=17), ctl(0x11)] + tail, 2026),
            9: ([read(0x9B, 0, status=17), ctl(0x11)] + tail, 2033),
            10: (
                [
                    routine(1, 0x19, 0x82),
                    read(0x9C, 0, status=17),
                    routine(2, 0x19),
                    ctl(0x11),
                ]
                + tail,
                2034,
            ),
            11: (
                [
                    ctl(0x0D, b"\x03\x0c\x80\x80"),
                    read(5, 0, size=4, status=17),
                    ctl(0x0D),
                    routine(2, 0x19),
                    ctl(0x11),
                ]
                + tail,
                2035,
            ),
            12: (
                [
                    read(6, 0, 1, 1, status=17),
                    routine(2, 0x16),
                    ctl(0x0D),
                    routine(2, 0x19),
                    ctl(0x11),
                ]
                + tail,
                2036,
            ),
            13: ([read(0x39, 0, status=17), ctl(0x0D), ctl(0x11)] + tail, 2034),
            14: ([ctl(0x0D), read(5, 0, 2, status=17), ctl(0x11)] + tail, 2035),
            15: ([read(0x17, 0, 3, status=17)] + tail, 2037),
            16: ([read(6, 0, 1, 1, status=17), routine(2, 0x16)] + tail, 2036),
            17: ([read(0x9C, 0, status=17), routine(2, 0x19)] + tail, 2034),
            18: (
                [routine(1, 0x16), read(6, 0, 1, 1, status=17), routine(2, 0x16)]
                + tail,
                2036,
            ),
        }
        for source in SOURCES:
            for action, (steps, expected) in cases.items():
                with self.subTest(source=source[:12], action=action):
                    result, _, _ = self.invoke(action, steps, source=source)
                    self.assertEqual(result, expected)

    def test_action6_stop_fault_uses_distinct_error_and_no_duplicate_0b(self):
        steps = [
            ctl(0x14, b"\x03\x64\x80"),
            read(5, 0xB0A4, 14),
            ctl(0x0B, status=17),
            ctl(0x11),
            ctl(0x14),
            ctl(0x0A),
        ]
        result, _, context = self.invoke(6, steps)
        self.assertEqual(result, 2026)
        self.assertEqual(wires(context).count(b"\x2f\x28\x0b\0\x80"), 1)

    def test_action14_failed_stop_retains_tick_and_omits_duplicate_stop(self):
        steps = [
            ctl(0x0D),
            read(5, 0x8320, 2),
            ctl(0x11, status=17),
            ctl(0x14),
            ctl(0x0A),
        ]
        result, data, _ = self.invoke(14, steps)
        self.assertEqual(result, 2037)
        self.assertEqual(_u32(data, 16), 200)

    def test_live_ui_stop_after_routine_success_overrides_zero(self):
        data = block(15)
        steps = [
            read(0x17, 9, 3),
            read(0x19, 100),
            read(0x39, 239),
            routine(1, 0x16),
            routine(2, 0x16),
            ctl(0x14),
            ctl(0x0A),
        ]
        context = Trace(steps)

        def stop_after_activation(packet):
            if packet == b"\x31\x01\x11\x16":
                _put(data, 4, 1)

        context.on_exchange = stop_after_activation
        self.assertEqual(_run((data,), context), 2100)
        self.assertEqual(_u32(data, 8), 1)
        context.assert_consumed(self)

    def test_worker_reloads_mutable_action_before_post_session(self):
        data = block(19)
        context = Trace([routine(1, 0x16)])
        context.on_exchange = lambda packet: _put(data, 0, 18)
        self.assertEqual(_run((data,), context), 0)
        self.assertEqual(
            context.events[-2:], [("session", 1, 1, False, False), ("finalize",)]
        )

    def test_dispatch_reloads_action_after_initialization_and_session(self):
        for source in SOURCES:
            for callback in ("initialize", "session"):
                data = block(0)
                context = Trace([], source)
                original = getattr(context, callback)

                def mutate(*args, original=original, data=data, **kwargs):
                    result = original(*args, **kwargs)
                    _put(data, 0, 1)
                    return result

                setattr(context, callback, mutate)
                self.assertEqual(_run((data,), context), 0)
                self.assertFalse(wires(context))
                self.assertNotIn(("finalize",), context.events)

    def test_host_fault_releases_retained_outputs_and_preserves_primary(self):
        for source in SOURCES:
            data = block(3)
            context = Trace([ctl(0x0B, b"\x03\x64\x80"), read(5, 0xB0A4, 10)], source)
            self.assertEqual(_run((data,), context), 0)
            self.assertNotIn(("finalize",), context.events)
            _put(data, 0, 19)
            primary = LookupError("authored activation host fault")
            original = context.exchange

            def fail_once(request, original=original, primary=primary):
                if request == b"\x31\x01\x11\x16":
                    raise primary
                return original(request)

            context.exchange = fail_once
            context.steps = [routine(2, 0x16), ctl(0x0B)]
            with self.assertRaises(LookupError) as caught:
                _run((data,), context)
            self.assertIs(caught.exception, primary)
            self.assertEqual(context.steps, [])
            self.assertEqual(
                context.events[-2:], [("session", 1, 1, False, True), ("finalize",)]
            )

    def test_primary_identity_survives_every_cleanup_fault(self):
        data = block(19)
        context = Trace([])
        primary = LookupError("authored primary")

        def fail_exchange(request):
            if request[1] == 1:
                raise primary
            raise RuntimeError("authored release fault")

        def fail_session(*args, **kwargs):
            context.events.append(("normal attempted",))
            raise RuntimeError("authored normal fault")

        def fail_finalize():
            context.events.append(("finalize attempted",))
            raise RuntimeError("authored finalize fault")

        context.exchange = fail_exchange
        context.session = fail_session
        context.finalize = fail_finalize
        with self.assertRaises(LookupError) as caught:
            _run((data,), context)
        self.assertIs(caught.exception, primary)
        self.assertIn(("normal attempted",), context.events)
        self.assertEqual(context.events[-1], ("finalize attempted",))
        self.assertEqual(len(primary.__notes__), 3)

    def test_host_cancel_releases_attempted_activation_without_check_veto(self):
        data = block(3)
        context = Trace([ctl(0x0B, b"\x03\x64\x80"), ctl(0x0B)])
        context.on_sleep = lambda: setattr(context, "cancelled", True)
        with self.assertRaises(Cancelled):
            _run((data,), context)
        self.assertEqual(context.steps, [])
        self.assertEqual(
            context.events[-2:], [("session", 1, 1, False, True), ("finalize",)]
        )

    def test_direct_native_sleep_preserves_one_unsliced_source_duration(self):
        class NativeSleepTrace(Trace):
            def sleep(self, milliseconds):
                raise AssertionError("FCHV direct Sleep must not use sliced helper")

            def native_sleep(self, milliseconds):
                self.events.append(("native_sleep", milliseconds))
                self.clock += milliseconds

        for source in SOURCES:
            context = NativeSleepTrace([ctl(0x14), ctl(0x0A)], source)
            self.assertEqual(_run((block(23),), context), 2100)
            self.assertEqual(
                [event for event in context.events if event[0] == "native_sleep"],
                [("native_sleep", 3000)],
            )

    def test_failed_host_release_keeps_output_for_next_cleanup_attempt(self):
        context = Trace([ctl(0x0B, b"\x03\x64\x80"), ctl(0x0B, status=17)])
        context.on_sleep = lambda: setattr(context, "cancelled", True)
        with self.assertRaises(Cancelled) as first:
            _run((block(3),), context)
        self.assertEqual(len(first.exception.__notes__), 1)
        context.steps = [ctl(0x0B)]
        with self.assertRaises(Cancelled):
            _run((block(1),), context)
        self.assertEqual(context.steps, [])
        self.assertEqual(
            context.state[f"fchv01:{context.module_sha256}:outputs"], set()
        )

    def test_decay_deadlines_snapshot_at_distinct_source_stages(self):
        for source in SOURCES:
            data = block(7)
            context = Trace(
                [read(0xC1, 0x8290, 10), ctl(0x11), ctl(0x14), ctl(0x0A)], source
            )
            context.tick_step = 6000
            context.on_sleep = lambda data=data: _put(data, 24, 0)
            self.assertEqual(_run((data,), context), 2026)
            self.assertEqual(context.steps, [])

            data = block(7)
            context = Trace(
                [read(5, 0x828F, 10), read(0x39, 250), ctl(0x11), ctl(0x14), ctl(0x0A)],
                source,
            )
            context.tick_step = 60001

            def change_total_bound(data=data, context=context):
                if context.events[-1] == ("sleep", 1000):
                    _put(data, 24, 0)
                    context.clock = 350000

            context.on_sleep = change_total_bound
            self.assertEqual(_run((data,), context), 2032)
            self.assertEqual(context.steps, [])

    def test_cool_read_fault_rereads_plus_variant_after_exchange(self):
        for source in SOURCES:
            data = block(13)
            context = Trace(
                [read(0x39, 0, status=17), ctl(0x0D), ctl(0x11), ctl(0x14), ctl(0x0A)],
                source,
            )
            context.on_exchange = lambda request, data=data: _put(data, 24, 0)
            self.assertEqual(
                _run((data,), context), 2038 if source == SHA_PLUS_TY else 2034
            )
            self.assertEqual(context.steps, [])

    def test_scoped_host_cleanup_preserves_global_cancel(self):
        class CanceledTrace(Trace):
            def exchange(self, request):
                if self.cancelled:
                    raise Cancelled("ordinary exchange is canceled")
                return super().exchange(request)

            def cleanup_exchange(self, request):
                return Trace.exchange(self, request)

            def session(
                self, mode, keepalive=1, *, normal_first=False, stop_on_error=False
            ):
                if self.cancelled:
                    raise Cancelled("ordinary session is canceled")
                return super().session(
                    mode,
                    keepalive,
                    normal_first=normal_first,
                    stop_on_error=stop_on_error,
                )

            def cleanup_session(
                self, mode, keepalive=1, *, normal_first=False, stop_on_error=False
            ):
                return Context.session(
                    self,
                    mode,
                    keepalive,
                    normal_first=normal_first,
                    stop_on_error=stop_on_error,
                )

        context = CanceledTrace([ctl(0x0B, b"\x03\x64\x80"), ctl(0x0B)])
        context.on_sleep = lambda: setattr(context, "cancelled", True)
        with self.assertRaises(Cancelled) as caught:
            _run((block(3),), context)
        self.assertEqual(context.steps, [])
        self.assertTrue(context.cancelled)
        self.assertFalse(getattr(caught.exception, "__notes__", []))
        self.assertEqual(
            context.events[-2:], [("session", 1, 1, False, True), ("finalize",)]
        )

    def test_action5_error_cleanup_omits_unrequested_2814(self):
        for source in SOURCES:
            for special in (True, False):
                for failure in ("activation", "sensor"):
                    steps = [
                        ctl(0x0A, b"\x03\x64\x80", 17 if failure == "activation" else 0)
                    ]
                    if failure == "sensor":
                        steps.append(read(5 if special else 0xC1, 0, 6, status=17))
                    steps += [ctl(0x11), ctl(0x0A), ctl(0x0B)]
                    result, _, context = self.invoke(
                        5, steps, source=source, special=special
                    )
                    self.assertEqual(result, 2028)
                    self.assertNotIn(b"\x2f\x28\x14\0\x80", wires(context))
                    release = [
                        event
                        for event in context.events
                        if event[0] in ("exchange", "sleep")
                    ][-4:]
                    self.assertEqual(
                        release,
                        [
                            ("exchange", b"\x2f\x28\x11\0\x80"),
                            ("sleep", 3000),
                            ("exchange", b"\x2f\x28\x0a\0\x80"),
                            ("exchange", b"\x2f\x28\x0b\0\x80"),
                        ],
                    )

    def test_initialization_and_session_error_lifetimes(self):
        for action in (0, 2):
            context = Trace([])
            context.init_status = 41
            self.assertEqual(_run((block(action),), context), 41)
            self.assertNotIn(("finalize",), context.events)
            context = Trace([])
            context.session_status = 17
            self.assertEqual(_run((block(action),), context), 2000)
            self.assertEqual(context.events[-1], ("finalize",))
            self.assertEqual(sum(row[0] == "configure" for row in context.events), 3)

    def test_support_normal_session_overrides_body_status(self):
        context = Trace([read(1, 0, size=32, first=1)])
        original = context.session

        def session(mode, *args, **kwargs):
            value = original(mode, *args, **kwargs)
            return 55 if mode == 1 else value

        context.session = session
        self.assertEqual(_run((block(0),), context), 55)
        self.assertEqual(context.events[-1], ("finalize",))

    def test_protocol_helpers_reject_each_echo_short_reply_and_bad_bound(self):
        for request, reply, call in (
            (b"\x22\x1b\x39", b"\x62\x1b\x39\0", lambda worker: worker.number(0x39)[0]),
            (
                b"\x22\x1b\x39",
                b"\x62\x1b\x38\0\0",
                lambda worker: worker.number(0x39)[0],
            ),
            (
                b"\x2f\x28\x11\0\x80",
                b"\x6f\x28\x11",
                lambda worker: worker.control(0x11),
            ),
            (
                b"\x2f\x28\x11\0\x80",
                b"\x6f\x28\x11\x03",
                lambda worker: worker.control(0x11),
            ),
            (
                b"\x31\x01\x11\x16",
                b"\x71\x01\x11",
                lambda worker: worker.routine(1, 0x16),
            ),
            (
                b"\x31\x01\x11\x16",
                b"\x71\x02\x11\x16",
                lambda worker: worker.routine(1, 0x16),
            ),
        ):
            context = Trace([(request, 0, reply)])
            self.assertEqual(call(_Worker(block(19), context, context)), 3)
        for status, reply, error in (
            (-1, b"", TypeError),
            (False, b"", TypeError),
            (0, bytearray(), ValueError),
            (0, bytes(4129), ValueError),
        ):
            context = Trace([cast(Step, (b"\x31\x01\x11\x16", status, reply))])
            with self.assertRaises(error):
                _run((block(19),), context)
            self.assertEqual(context.events[-1], ("finalize",))

    def test_host_fault_and_cancellation_close_retained_controller(self):
        for action in (2, 3, 12, 19):
            context = Trace([])
            context.fault = RuntimeError("authored link fault")
            with self.assertRaisesRegex(RuntimeError, "authored link fault"):
                _run((block(action),), context)
            self.assertEqual(context.events[-1], ("finalize",))
        context = Trace([])
        context.on_sleep = lambda: setattr(context, "cancelled", True)
        with self.assertRaises(Cancelled):
            _run((block(7),), context)
        self.assertEqual(context.events[-1], ("finalize",))

    def test_bad_buffer_and_source_identity_never_touch_controller(self):
        for args in (
            (),
            (bytes(28),),
            (bytearray(27),),
            (bytearray(65537),),
            (bytearray(28), 1),
        ):
            context = Trace([])
            with self.assertRaises(ValueError):
                _run(args, context)
            self.assertEqual(context.events, [])
        context = Trace([])
        with self.assertRaises(TYSourceError):
            run_body(EXPORT, (block(1),), context)
        self.assertEqual(context.events, [])
        self.assertEqual(supported_exports(""), ())
        for source in SOURCES:
            self.assertEqual(supported_exports(source), (EXPORT,))

    def test_timer_wrap_matches_shared_native_helper(self):
        for now, then, expected in ((4, 0xFFFFFFFE, 5), (100, 5, 95)):
            self.assertEqual(elapsed_ticks(now, then), expected)

    def test_aggregator_preserves_native_argument_and_retained_exports(self):
        from scripts import utility_ex_ty

        context = Trace([])
        context.module_sha256 = hashlib.sha256(context.module_bytes).hexdigest()
        data = block(1)

        def body(export, args, selected):
            self.assertIs(args[0], data)
            self.assertIs(selected, context)
            _put(data, 8, 7)
            return 29

        with (
            patch(
                "scripts.utility_ex_fchv_01.supported_exports", return_value=(EXPORT,)
            ),
            patch("scripts.utility_ex_fchv_01.run_body", side_effect=body) as provider,
        ):
            self.assertIn(
                EXPORT, utility_ex_ty.supported_exports(context.module_sha256)
            )
            self.assertEqual(utility_ex_ty.run_body(EXPORT, (data,), context), 29)
            self.assertEqual(_u32(data, 8), 7)
            provider.assert_called_once()
            context.module_bytes += b"changed"
            with self.assertRaises(TYSourceError):
                utility_ex_ty.run_body(EXPORT, (data,), context)
            provider.assert_called_once()
        for source in SOURCES:
            retained = set(utility_ex_ty.load_contract(source).exports)
            self.assertTrue(retained <= set(utility_ex_ty.supported_exports(source)))


if __name__ == "__main__":
    unittest.main()
