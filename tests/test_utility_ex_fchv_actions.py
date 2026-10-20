"""Authored native branch vectors; no OEM code or device execution."""

import hashlib
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

from scripts.toyota_session import Cancelled
from scripts.utility_ex_fchv_actions import (
    SHA_18_TY,
    SHA_PLUS_TY,
    _put,
    _run,
    run_body,
    supported_exports,
)
from scripts.utility_ex_ty import TYComm, TYSourceError


class Context:
    def __init__(self, source=SHA_18_TY):
        self.module_sha256 = source
        self.module_bytes = b"authored"
        self.mode = 20
        self.state: dict[str, object] = {}
        self.events: list[tuple] = []
        self.clock = 0
        self.cancelled = False
        self.init = 0
        self.on_init: Callable[[], None] | None = None
        self.session_status = 0
        self.nrc = 105
        self.payloads: dict[bytes, bytes] = {}
        self.statuses: dict[bytes, int] = {}
        self.bad_echo = False
        self.fault: BaseException | None = None
        self.on_exchange: Callable[[bytes], None] | None = None
        self.on_sleep: Callable[[], None] | None = None
        self.step = 0

    def comm(self, kind: str) -> TYComm:
        self.events.append(("comm", kind))
        return self

    def initialize(self, mode=0):
        self.events.append(("initialize", mode))
        if self.on_init:
            self.on_init()
        return self.init

    def configure(self, field, value):
        self.events.append(("configure", field, value))

    def configure_target(self, first, second=0, third=0, fourth=0, fifth=0):
        self.events.append(("target", first, second, third, fourth, fifth))

    def select_target(self, identifier, second=0):
        self.events.append(("select_target", identifier, second))

    def session(self, mode, keepalive=1, *, normal_first=False, stop_on_error=False):
        self.events.append(("session", mode))
        return self.session_status

    def exchange(self, request):
        self.events.append(("exchange", request))
        self.clock = (self.clock + self.step) & 0xFFFFFFFF
        if self.fault:
            raise self.fault
        if self.on_exchange:
            self.on_exchange(request)
        status = self.statuses.get(request, 0)
        if request[0] == 0x22:
            payload = self.payloads.get(request[1:], bytes(32))
            reply = b"\x62" + request[1:] + payload
        else:
            reply = bytes((request[0] + 0x40,)) + request[1:]
        return status, b"bad" if self.bad_echo else reply

    def cleanup_exchange(self, request):
        self.events.append(("cleanup_exchange", request))
        return self.exchange(request)

    def cleanup_session(
        self, mode, keepalive=1, *, normal_first=False, stop_on_error=False
    ):
        self.events.append(("cleanup_session", mode))
        return self.session(
            mode, keepalive, normal_first=normal_first, stop_on_error=stop_on_error
        )

    def read_field(self, field):
        self.events.append(("read_field", field))
        return self.nrc

    def finalize(self):
        self.events.append(("finalize",))

    def sleep(self, ms):
        self.events.append(("sleep", ms))
        self.clock = (self.clock + ms) & 0xFFFFFFFF
        if self.on_sleep:
            self.on_sleep()

    def native_sleep(self, ms, /):
        self.sleep(ms)

    def ticks(self):
        return self.clock

    def is_cancelled(self):
        return self.cancelled

    def read_dtcs(self, mode=0x80, capacity=0x1000):
        raise AssertionError("Unexpected DTC read")

    def support_snapshot(self, kind):
        raise AssertionError("Unexpected support snapshot")

    def select_protocol(self, kind):
        raise AssertionError("Unexpected protocol change")

    def read_target(self):
        return (0x7E0, 0x7E8)

    def set_parameter(self, key, value):
        raise AssertionError("Unexpected broker mutation")

    def write_parameters(self):
        raise AssertionError("Unexpected broker mutation")

    def refresh_parameters(self):
        raise AssertionError("Unexpected broker refresh")


def block(group, action):
    data = bytearray({"03": 0x308, "04": 16, "11": 48, "12": 0x128, "17": 16}[group])
    _put(data, 8 if group == "04" else 0, action)
    return data


def execute(group, data, ctx):
    return _run(f"Ex2FCHV_{group}_SendMessage", (data,), ctx)


class ActionsTests(unittest.TestCase):
    def test_exact_sources_and_identity_before_io(self):
        for source in (SHA_18_TY, SHA_PLUS_TY):
            self.assertEqual(len(supported_exports(source)), 5)
            ctx = Context(source)
            with self.assertRaises(TYSourceError):
                run_body("Ex2FCHV_04_SendMessage", (block("04", 8),), ctx)
            self.assertEqual(ctx.events, [])
        self.assertEqual(supported_exports("other"), ())

    def test_argument_bounds_before_io(self):
        for group in ("03", "04", "11", "12", "17"):
            for args in ((), (b"wrong",), (bytearray(3),), (bytearray(65537),)):
                ctx = Context()
                with self.assertRaises(ValueError):
                    _run(f"Ex2FCHV_{group}_SendMessage", args, ctx)
                self.assertEqual(ctx.events, [])

    def test_04_all_can_actions_and_cleanup(self):
        for source in (SHA_18_TY, SHA_PLUS_TY):
            for action in range(3, 22 if source == SHA_PLUS_TY else 16):
                ctx = Context(source)
                data = block("04", action)
                self.assertEqual(execute("04", data, ctx), 0, (source, action))
                self.assertEqual(ctx.events[-1], ("finalize",))
                requests = [e[1] for e in ctx.events if e[0] == "exchange"]
                if action == 3:
                    self.assertEqual(
                        requests,
                        [b"\x2f\x28\x0e\x03\x07\xd0\x80", b"\x2f\x28\x09\x03\x64\x80"],
                    )
                if action in (18, 19):
                    self.assertIn(("comm", "native:10135c58"), ctx.events)

    def test_plus04_second_controller_is_independent(self):
        first = Context(SHA_PLUS_TY)
        second = Context(SHA_PLUS_TY)

        def select(kind):
            return second if kind == "native:10135c58" else first

        first.comm = select
        data = block("04", 18)
        self.assertEqual(execute("04", data, first), 0)
        self.assertFalse(any(event[0] == "exchange" for event in first.events))
        self.assertIn(("target", 0x7C4, 0, 0, 0, 0), second.events)
        self.assertEqual(second.events[-1], ("finalize",))

    def test_04_failure_mapping_and_stop_sequence(self):
        for action, expected in ((3, 2002), (6, 2004), (7, 3), (10, 3)):
            ctx = Context()
            ctx.bad_echo = True
            self.assertEqual(execute("04", block("04", action), ctx), expected)
            requests = [e[1] for e in ctx.events if e[0] == "exchange"]
            self.assertEqual(
                requests[-2:], [b"\x2f\x28\x09\x00\x80", b"\x2f\x28\x0e\x00\x80"]
            )
        ctx = Context(SHA_PLUS_TY)
        ctx.session_status = 7
        data = block("04", 13)
        _put(data, 12, 1)
        self.assertEqual(execute("04", data, ctx), 2005)

    def test_04_dual_keepalive_and_classic_mode4(self):
        ctx = Context(SHA_PLUS_TY)
        data = block("04", 15)
        _put(data, 12, 1)
        self.assertEqual(execute("04", data, ctx), 0)
        self.assertEqual(
            [e for e in ctx.events if e[0] == "sleep"], [("sleep", 125), ("sleep", 125)]
        )
        for source in (SHA_18_TY, SHA_PLUS_TY):
            for action in (0, 1, 2, 99):
                ctx = Context(source)
                ctx.mode = 4
                ctx.clock = 0xFFFFFFF0
                data = block("04", action)
                self.assertEqual(execute("04", data, ctx), 0)
                self.assertEqual(ctx.events[0], ("comm", "selected"))
                if action in (0, 1):
                    self.assertEqual(int.from_bytes(data[4:8], "little"), 0xFFFFFFF0)
                    self.assertIn(
                        ("exchange", bytes((0x30, 0x18, 0, action + 1))), ctx.events
                    )

    def test_support11_literal_stack_flags_and_state(self):
        for source in (SHA_18_TY, SHA_PLUS_TY):
            ctx = Context(source)
            ctx.payloads[b"\x01\x01"] = b"\0\0\0\x10" + bytes(28)
            ctx.payloads[b"\x28\x0c"] = b"\x07"
            flags = bytearray(32)
            flags[18:20] = b"\x13\xe0"
            ctx.payloads[b"\x1b\x00"] = bytes(flags)
            data = block("11", 0)
            self.assertEqual(execute("11", data, ctx), 0)
            self.assertEqual(data[12:14], b"\xc0\x8e")
            self.assertEqual(data[44], 7)
            self.assertEqual(ctx.events.count(("session", 1)), 1)
            self.assertEqual(ctx.events[-1], ("finalize",))

    def test_11_all_action_retention_and_table_threshold(self):
        for source in (SHA_18_TY, SHA_PLUS_TY):
            for action in range(1, 10):
                ctx = Context(source)
                data = block("11", action)
                data[44] = 7
                ctx.payloads[b"\x1b\x94"] = (
                    b"\x07\x07" if action in (1, 2, 3) else b"\x07\x00"
                )
                if action in (7, 8):
                    _put(data, 4, 1)
                expected = 2050 if action in (7, 8) else 0
                self.assertEqual(execute("11", data, ctx), expected, (source, action))
                self.assertEqual(("finalize",) in ctx.events, action in (6, 9))
            ctx = Context(source)
            data = block("11", 2)
            data[12:14] = b"\x00\x08"
            ctx.payloads[b"\x1b\x97"] = b"AA\x70\x60BB"
            self.assertEqual(execute("11", data, ctx), 2002)
            self.assertEqual(data[14:20], b"AA\x70\x60BB")

    def test_11_nrc_timeout_malformed_and_stream_output(self):
        ctx = Context()
        ctx.statuses[b"\x2f\x28\x0c\x03\x00\x00\x00\x00"] = 7
        self.assertEqual(execute("11", block("11", 3), ctx), 2001)
        ctx = Context()
        ctx.payloads[b"\x1b\x94"] = b"\x01\x00"
        self.assertEqual(execute("11", block("11", 3), ctx), 2001)
        self.assertGreaterEqual(ctx.clock, 5000)
        ctx = Context()
        ctx.bad_echo = True
        self.assertEqual(execute("11", block("11", 3), ctx), 2000)
        ctx = Context()
        data = block("11", 8)
        data[12:14] = b"\x80\x00"
        ctx.payloads[b"\x1b\x9a"] = b"xy"
        ctx.on_sleep = lambda: _put(data, 4, 1)
        self.assertEqual(execute("11", data, ctx), 2050)
        self.assertEqual(data[32:34], b"xy")
        self.assertEqual(data[8:12], b"\x01\0\0\0")

    def test_12_all_actions_support_and_retained_rows(self):
        for source in (SHA_18_TY, SHA_PLUS_TY):
            ctx = Context(source)
            ctx.payloads[b"\x01\x01"] = b"\0\0\0\x10" + bytes(28)
            ctx.payloads[b"\x28\x0c"] = b"\x07"
            flags = bytearray(32)
            flags[18:20] = b"\x13\xe0"
            ctx.payloads[b"\x1b\x00"] = bytes(flags)
            self.assertEqual(execute("12", block("12", 0), ctx), 0)
            for action, expected in ((1, 0), (2, 0), (3, 1016), (4, 1020), (5, 1026)):
                ctx = Context(source)
                data = block("12", action)
                _put(data, 0x124, 1)
                self.assertEqual(execute("12", data, ctx), expected)
                self.assertEqual(("finalize",) in ctx.events, action == 3)
            ctx = Context(source)
            data = block("12", 1)
            data[0x120] = 1
            data[8:10] = b"\x1b\x97"
            _put(data, 12, 1)
            ctx.payloads[b"\x1b\x97"] = b"\x70\x60"
            self.assertEqual(execute("12", data, ctx), 1012)

    def test_12_bad_support_nrc_read_and_timeout(self):
        self.assertEqual(execute("12", block("12", 0), Context()), 3)
        ctx = Context()
        ctx.payloads[b"\x1b\x94"] = b"\x01\x00"
        self.assertEqual(execute("12", block("12", 5), ctx), 1009)
        ctx = Context()
        ctx.statuses[b"\x2f\x28\x0c\x03\0\0\0\0"] = 7
        self.assertEqual(execute("12", block("12", 5), ctx), 1009)
        ctx = Context()
        data = block("12", 2)
        _put(data, 12, 1)
        ctx.bad_echo = True
        self.assertEqual(execute("12", data, ctx), 1023)

    def test_03_support_rows_and_every_action(self):
        for source in (SHA_18_TY, SHA_PLUS_TY):
            ctx = Context(source)
            data = block("03", 0)
            _put(data, 8, 2)
            data[12] = 4
            ctx.payloads[b"\x01\x01"] = b"\0\0\0\x10"
            ctx.payloads[b"\x1b\x00"] = b"\0\0\x04" + bytes(17)
            ctx.payloads[b"\x28\x0c"] = b"\x07"
            self.assertEqual(execute("03", data, ctx), 0)
            self.assertEqual(data[16:20], b"\x01\0\0\0")
            self.assertEqual(data[0x300], 7)
            for action, expected in (
                (1, 0),
                (2, 2224),
                (3, 2224),
                (4, 2219),
                (5, 99),
                (6, 0),
                (7, 0),
                (8, 0),
                (14, 0),
                (15, 2210),
                (16, 2210),
                (17, 2223),
            ):
                ctx = Context(source)
                data = block("03", action)
                _put(data, 0x2FC, 1)
                ctx.payloads[b"\x1b\x06"] = b"\0\x40"
                if action == 8:
                    ctx.step = 1000
                    _put(data, 4 + 32, 1)
                    _put(data, 4 + 12, 1)
                self.assertEqual(execute("03", data, ctx), expected, (source, action))

    def test_03_native_phase_transitions(self):
        for phase, expected in (
            (1, 2224),
            (2, 2213),
            (3, 2214),
            (4, 2215),
            (5, 2220),
            (99, 99),
        ):
            data = block("03", 5)
            _put(data, 0x304, phase)
            self.assertEqual(execute("03", data, Context()), expected)
            if phase == 1:
                self.assertEqual(int.from_bytes(data[0x304:0x308], "little"), 2)
        ctx = Context()
        ctx.bad_echo = True
        self.assertEqual(execute("03", block("03", 2), ctx), 2205)
        ctx = Context()
        ctx.payloads[b"\x1b\x94"] = b"\x01\0"
        self.assertEqual(execute("03", block("03", 2), ctx), 2226)

    def test_03_stream_data_uses_actual_payload_not_decompiler_zeros(self):
        for source in (SHA_18_TY, SHA_PLUS_TY):
            ctx = Context(source)
            data = block("03", 6)
            data[4:6] = b"\x12\x34"
            _put(data, 16, 1)
            _put(data, 28, 1)
            data[24:26] = b"\x0f\xf0"
            _put(data, 0x2FC, 1)
            ctx.payloads[b"\x12\x34"] = b"\xab\xcd"
            self.assertEqual(execute("03", data, ctx), 0)
            self.assertEqual(data[40:42], b"\x0b\xc0")
            self.assertEqual(data[44:48], b"\x01\0\0\0")

    def test_17_retained_start_drive_and_explicit_stop(self):
        for source in (SHA_18_TY, SHA_PLUS_TY):
            ctx = Context(source)
            self.assertEqual(execute("17", block("17", 0), ctx), 0)
            self.assertIn(("exchange", b"\x31\x01\x11\x1a\x01"), ctx.events)
            self.assertNotIn(("finalize",), ctx.events)
            ctx = Context(source)
            ctx.payloads[b"\x1b\xbf"] = b"\0\x40"
            data = block("17", 1)
            _put(data, 8, 1)
            self.assertEqual(execute("17", data, ctx), 0)
            self.assertEqual(data[4:8], b"\x01\0\0\0")
            self.assertEqual(int.from_bytes(data[12:16], "little"), 1010)
            self.assertNotIn(("finalize",), ctx.events)
            _put(data, 0, 2)
            self.assertEqual(execute("17", data, ctx), 1010)
            self.assertEqual(ctx.events[-1], ("finalize",))

    def test_17_partial_start_failure_timeout_and_cyclic_stop(self):
        ctx = Context()
        ctx.statuses[b"\x2f\x28\x0a\x03\x64\x80"] = 7
        self.assertEqual(execute("17", block("17", 1), ctx), 1007)
        requests = [e[1] for e in ctx.events if e[0] == "exchange"]
        self.assertEqual(
            requests[-2:], [b"\x2f\x28\x0b\x00\x80", b"\x2f\x28\x0a\x00\x80"]
        )
        ctx = Context()
        self.assertEqual(execute("17", block("17", 1), ctx), 1007)
        self.assertEqual(ctx.events[-1], ("finalize",))
        ctx = Context()
        ctx.payloads[b"\x1b\xbf"] = b"\0\x40"
        ctx.step = 10000
        self.assertEqual(execute("17", block("17", 1), ctx), 1005)
        self.assertIn(("exchange", b"\x31\x02\x11\x16"), ctx.events)

    def test_cancel_and_host_fault_release_every_group(self):
        for group, action in (("03", 2), ("04", 3), ("11", 3), ("12", 5), ("17", 1)):
            for fault in (
                OSError("authored transport fault"),
                Cancelled("authored cancellation"),
            ):
                ctx = Context()
                ctx.fault = fault
                with self.assertRaises(type(fault)):
                    execute(group, block(group, action), ctx)
                self.assertIn(("finalize",), ctx.events)
            ctx = Context()
            ctx.cancelled = True
            with self.assertRaises(Cancelled):
                execute(group, block(group, action), ctx)
            self.assertEqual(ctx.events, [])

    def test_selected_native_status_and_inflight_cancel(self):
        for group, action in (("03", 0), ("04", 3), ("11", 0), ("12", 0), ("17", 0)):
            ctx = Context()
            ctx.init = 77
            self.assertEqual(execute(group, block(group, action), ctx), 77)
            self.assertEqual(ctx.events[-1], ("finalize",))
        for group, action in (("03", 2), ("11", 3), ("12", 5), ("17", 1)):
            ctx = Context()
            ctx.on_sleep = lambda ctx=ctx: setattr(ctx, "cancelled", True)
            with self.assertRaises(Cancelled):
                execute(group, block(group, action), ctx)
            self.assertEqual(ctx.events[-1], ("finalize",))

    def test_live_dispatch_and_classic_second_frame(self):
        for source in (SHA_18_TY, SHA_PLUS_TY):
            ctx = Context(source)
            data = block("11", 0)
            ctx.on_init = lambda data=data: _put(data, 0, 9)
            self.assertEqual(execute("11", data, ctx), 0)
            self.assertFalse(any(e[0] == "exchange" for e in ctx.events))
            ctx = Context(source)
            ctx.mode = 4
            data = block("04", 0)
            ctx.on_init = lambda data=data: _put(data, 8, 2)
            self.assertEqual(execute("04", data, ctx), 0)
            self.assertIn(("exchange", b"\x30"), ctx.events)
            ctx = Context(source)
            ctx.mode = 4
            data = block("04", 0)
            ctx.on_exchange = lambda request, data=data: (
                _put(data, 8, 25) if request == b"\x30\x19\0\2\2" else None
            )
            self.assertEqual(execute("04", data, ctx), 0)
            self.assertIn(("exchange", b"\x30\x18\0\2"), ctx.events)

    def test_plus04_dispatch_and_finalize_reload_manager(self):
        first, second = Context(SHA_PLUS_TY), Context(SHA_PLUS_TY)
        first.comm = lambda kind: second if kind == "native:10135c58" else first
        data = block("04", 3)
        first.on_init = lambda: _put(data, 8, 18)
        self.assertEqual(execute("04", data, first), 0)
        self.assertFalse(any(e[0] == "exchange" for e in first.events))
        self.assertTrue(any(e[0] == "exchange" for e in second.events))
        self.assertNotIn(("finalize",), first.events)
        self.assertIn(("finalize",), second.events)
        first, second = Context(SHA_PLUS_TY), Context(SHA_PLUS_TY)
        first.comm = lambda kind: second if kind == "native:10135c58" else first
        data = block("04", 3)
        first.on_exchange = lambda request: _put(data, 8, 18)
        self.assertEqual(execute("04", data, first), 0)
        self.assertNotIn(("finalize",), first.events)
        self.assertIn(("finalize",), second.events)

    def test_12_wire_snapshot_and_live_temperature_mask(self):
        data = block("12", 1)
        data[0x120] = 1
        ctx = Context()
        ctx.on_init = lambda: data.__setitem__(0x120, 0)
        self.assertEqual(execute("12", data, ctx), 0)
        self.assertIn(("exchange", b"\x2f\x28\x0c\3\0\1\0\1"), ctx.events)
        data = block("12", 1)
        data[8:10] = b"\x1b\x97"
        _put(data, 12, 1)
        ctx = Context()
        ctx.on_exchange = lambda request: (
            data.__setitem__(0x120, 1) if request == b"\x22\x1b\x97" else None
        )
        self.assertEqual(execute("12", data, ctx), 1012)

    def test_retained_output_abort_preserves_primary_fault(self):
        ctx = Context()
        data = block("17", 1)
        _put(data, 8, 1)
        ctx.payloads[b"\x1b\xbf"] = b"\0\x40"
        self.assertEqual(execute("17", data, ctx), 0)
        data[0:4] = (1).to_bytes(4, "little")
        primary = LookupError("primary host failure")
        fired = False

        def fail_once(request):
            nonlocal fired
            if not fired:
                fired = True
                raise primary

        ctx.on_exchange = fail_once

        def bad_finalize():
            raise RuntimeError("secondary finalization fault")

        ctx.finalize = bad_finalize
        with self.assertRaises(LookupError) as raised:
            execute("17", data, ctx)
        self.assertIs(raised.exception, primary)
        for request in (
            b"\x2f\x28\x0b\0\x80",
            b"\x2f\x28\x0a\0\x80",
            b"\x2f\x28\x14\0\x80",
            b"\x31\2\x11\x16",
        ):
            self.assertIn(("exchange", request), ctx.events)
        self.assertTrue(any("finalization" in note for note in primary.__notes__))

    def test_direct_native_sleep_is_one_host_wait(self):
        from scripts.utility_ex import UtilityExContext
        from scripts.utility_ex_fchv_actions import _sleep
        from tests.test_utility_ex import Host

        host = Host()
        source = Path(
            "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll"
        ).read_bytes()
        context = UtilityExContext(source, host, None, None)
        _sleep(context, 3000)
        self.assertEqual(host.waits, [3000])

    def test_cancelled_next_message_releases_retained_outputs(self):
        ctx = Context()
        data = block("17", 1)
        _put(data, 8, 1)
        ctx.payloads[b"\x1b\xbf"] = b"\0\x40"
        self.assertEqual(execute("17", data, ctx), 0)
        ctx.cancelled = True
        with self.assertRaises(Cancelled):
            execute("17", data, ctx)
        self.assertIn(("exchange", b"\x31\2\x11\x16"), ctx.events)
        self.assertEqual(ctx.events[-1], ("finalize",))

    def test_snapshot_priority_updates_and_deadline_are_per_priority(self):
        for source in (SHA_18_TY, SHA_PLUS_TY):
            ctx = Context(source)
            data = block("03", 8)
            for row in range(2):
                base = 4 + row * 44
                data[base : base + 2] = bytes((0x12, row))
                _put(data, base + 12, 1)
            _put(data, 36, 1)
            reads = [0, 0]

            def advance(request, reads=reads, data=data, ctx=ctx):
                if request[:2] != b"\x22\x12":
                    return
                row = request[2]
                reads[row] += 1
                if row == 0:
                    _put(data, 80, 2)
                    if reads[0] == 2:
                        ctx.clock = 6000

            ctx.on_exchange = advance
            self.assertEqual(execute("03", data, ctx), 0)
            self.assertEqual(reads, [2, 1])

    def test_04_helper_reload_after_reset_and_activation(self):
        ctx = Context()
        data = block("04", 10)

        def mutate(request):
            if request == b"\x2f\x28\x0e\0\x80":
                _put(data, 8, 11)
            elif request == b"\x2f\x28\x0e\3\x0a\xf0\x80":
                _put(data, 8, 12)

        ctx.on_exchange = mutate
        self.assertEqual(execute("04", data, ctx), 0)
        self.assertIn(("exchange", b"\x2f\x28\x0e\3\x0a\xf0\x80"), ctx.events)
        self.assertIn(("exchange", b"\x2f\x28\x09\3\x64\x80"), ctx.events)

    def test_sole_finalization_fault_inside_unrelated_except_propagates(self):
        ctx = Context()
        cleanup = RuntimeError("sole finalization failure")

        def fail_finalize():
            raise cleanup

        ctx.finalize = fail_finalize
        try:
            raise LookupError("unrelated caller exception")
        except LookupError:
            with self.assertRaises(RuntimeError) as raised:
                execute("04", block("04", 8), ctx)
        self.assertIs(raised.exception, cleanup)

    def test_actual_ty18_sdk_business_lifecycle_and_cancelled_release(self):
        from scripts.j2534_2026 import NativeMessage, PrimitiveResult
        from scripts.utility_ex import UtilityEx2TY, UtilityExContext

        requests = []
        filters = iter((51, 52))

        def connect(protocol, flags, output):
            output[:] = (42).to_bytes(4, "little")
            return PrimitiveResult()

        def start_filter(channel, kind, mask, pattern, flow, output):
            output[:] = next(filters).to_bytes(4, "little")
            return PrimitiveResult()

        def write(channel, messages, count, timeout):
            requests.append(messages[0].data[4:])
            return PrimitiveResult()

        def read(channel, messages, count, timeout):
            request = requests[-1]
            payload = (
                b"\x62\x1b\xbf\0\x40"
                if request == b"\x22\x1b\xbf"
                else bytes((request[0] + 0x40,)) + request[1:]
            )
            messages[0] = NativeMessage(6, b"\0\0\x07\xe8" + payload)
            return PrimitiveResult()

        names = (
            "PassThruConnect",
            "PassThruOemConnect",
            "PassThruDisconnect",
            "PassThruIoctl",
            "PassThruGetLastError",
            "PassThruWriteMsgs",
            "PassThruReadMsgs",
            "PassThruStartPeriodicMsg",
            "PassThruStopPeriodicMsg",
            "PassThruStartMsgFilter",
            "PassThruStopMsgFilter",
            "PassThruSetProgrammingVoltage",
            "PassThruReadVersion",
            "J2534CtrlInitialize",
            "J2534CtrlFinalize",
        )
        exports: dict[str, Callable[..., object]] = dict.fromkeys(
            names, lambda *args: PrimitiveResult()
        )
        exports.update(
            PassThruConnect=connect,
            PassThruStartMsgFilter=start_filter,
            PassThruWriteMsgs=write,
            PassThruReadMsgs=read,
        )

        class Host:
            def __init__(self):
                self.tick = 0

            def get_parameter(self, key):
                return {
                    0x6F: 20,
                    0x70: 0x12,
                    0x74: 0x7E0,
                    0xD3: 0xFFFFFFFF,
                    0xDD: 0xFFFFFFFF,
                }.get(key, 0)

            def get_data_size(self, key):
                return 8 if key == 500 else 0

            def get_data(self, key):
                return (
                    (1).to_bytes(4, "little") + (500000).to_bytes(4, "little")
                    if key == 500
                    else b""
                )

            def set_parameter(self, key, value):
                return 0

            def write_parameters(self):
                return 0

            def refresh_parameters(self):
                pass

            def ticks(self):
                self.tick += 1
                return self.tick

            def sleep(self, milliseconds):
                self.tick += milliseconds

        source = Path(
            "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll"
        ).read_bytes()
        context = UtilityExContext(source, Host(), None, None, driver_exports=exports)
        engine = UtilityEx2TY(context)
        self.assertEqual(engine.invoke("Ex2FCHV_17_SendMessage", (block("17", 0),)), 15)
        worker = engine.worker._thread
        assert worker is not None
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(engine.worker.get_status(), 0)
        comm = context.comm("native:1011d4f0")
        self.assertTrue(comm._fixed_lifecycle().worker_active)
        self.assertEqual(requests, [b"\x10\1", b"\x10\3", b"\x31\1\x11\x1a\1"])
        active = block("17", 1)
        _put(active, 8, 1)
        self.assertEqual(engine.run_body("Ex2FCHV_17_SendMessage", (active,)), 0)
        context._cancel.set()
        with self.assertRaises(Cancelled):
            engine.run_body("Ex2FCHV_17_SendMessage", (block("17", 2),))
        self.assertTrue(context.is_cancelled())
        self.assertEqual(
            requests[-5:],
            [
                b"\x2f\x28\x0b\0\x80",
                b"\x2f\x28\x0a\0\x80",
                b"\x2f\x28\x14\0\x80",
                b"\x31\2\x11\x16",
                b"\x10\1",
            ],
        )
        self.assertEqual(comm._fixed_lifecycle().fields.current_session, 0)
        self.assertFalse(comm._fixed_lifecycle().worker_active)

    def test_actual_ty_engine_join_preserves_native_argument(self):
        from scripts.utility_ex_ty import run_body as ty_run_body
        from scripts.utility_ex_ty import supported_exports as ty_supported_exports

        paths = {
            SHA_18_TY: "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll",
            SHA_PLUS_TY: "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll",
        }
        for source, path in paths.items():
            ctx = Context(source)
            ctx.module_bytes = Path(path).read_bytes()
            self.assertEqual(hashlib.sha256(ctx.module_bytes).hexdigest(), source)
            export = "Ex2FCHV_04_SendMessage"
            self.assertIn(export, ty_supported_exports(source))
            self.assertEqual(ty_run_body(export, (block("04", 3),), ctx), 0)

    def test_actual_public_wrappers_run_native_callbacks(self):
        from scripts.utility_ex import UtilityEx2TY, UtilityExContext
        from tests.test_utility_ex import Host

        paths = {
            SHA_18_TY: "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll",
            SHA_PLUS_TY: "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll",
        }
        for source, path in paths.items():
            for mode in (20, 21):
                for group, action, expected in (
                    ("03", 15, 2210),
                    ("04", 3, 0),
                    ("11", 5, 0),
                    ("12", 4, 1020),
                    ("17", 2, 1234),
                ):
                    with self.subTest(source=source, mode=mode, group=group):
                        host = Host()
                        host.values[0x6F] = mode
                        context = UtilityExContext(
                            Path(path).read_bytes(), host, None, None
                        )
                        engine = UtilityEx2TY(context)
                        communication = Context(source)
                        data = block(group, action)
                        if group == "17":
                            _put(data, 12, 1234)
                        with patch.object(context, "comm", return_value=communication):
                            self.assertEqual(
                                engine.invoke(f"Ex2FCHV_{group}_SendMessage", (data,)),
                                15,
                            )
                            worker = engine.worker._thread
                            assert worker is not None
                            worker.join(2)
                            self.assertFalse(worker.is_alive())
                            self.assertEqual(engine.worker.get_status(), expected)
            host = Host()
            context = UtilityExContext(Path(path).read_bytes(), host, None, None)
            engine = UtilityEx2TY(context)
            with patch.object(context, "comm", return_value=Context(source)):
                self.assertEqual(
                    engine.invoke("Ex2FCHV_04_SendMessage", (block("04", 0),)), 15
                )
                worker = engine.worker._thread
                assert worker is not None
                worker.join(2)
                self.assertFalse(worker.is_alive())
                self.assertEqual(engine.worker.get_status(), 0)


if __name__ == "__main__":
    unittest.main()
