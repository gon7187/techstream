"""Authored packet, native buffer, retention and error controls for FCHV bodies."""

import unittest
from collections.abc import Callable
from pathlib import Path

from scripts.toyota_session import Cancelled
from scripts.utility_ex_fchv import (
    SHA_18_TY,
    SHA_PLUS_TY,
    FCHVValues,
    _auto_power,
    _put,
    _tank,
    _values,
    run_body,
    supported_exports,
)
from scripts.utility_ex_ty import TYSourceError
from scripts.utility_ex_ty import run_body as ty_run_body
from scripts.utility_ex_ty import supported_exports as ty_supported_exports
from tests.private_evidence import require_private


class Context:
    def __init__(self, source=SHA_18_TY, replies=()):
        self.module_sha256 = source
        self.module_bytes = b"authored"
        self.mode = 20
        self.state: dict[str, object] = {}
        self.replies = iter(replies)
        self.events = []
        self.clock = 0
        self.cancelled = False
        self.init_status = 0
        self.session_status = 0
        self.fault: BaseException | None = None
        self.on_sleep: Callable[[], None] | None = None
        self.nrc = 105

    def comm(self, kind):
        self.events.append(("comm", kind))
        return self

    def initialize(self, mode=0):
        self.events.append(("initialize", mode))
        return self.init_status

    def configure(self, field, value):
        self.events.append(("configure", field, value))

    def session(self, mode, keepalive=1, *, normal_first=False, stop_on_error=False):
        self.events.append(("session", mode, keepalive, normal_first, stop_on_error))
        return self.session_status

    def exchange(self, request):
        self.events.append(("exchange", request))
        if self.fault:
            raise self.fault
        return next(self.replies)

    def cleanup_session(
        self, mode, keepalive=1, *, normal_first=False, stop_on_error=False
    ):
        self.events.append(
            ("cleanup_session", mode, keepalive, normal_first, stop_on_error)
        )
        return self.session(
            mode, keepalive, normal_first=normal_first, stop_on_error=stop_on_error
        )

    def cleanup_exchange(self, request):
        self.events.append(("cleanup_exchange", request))
        return self.exchange(request)

    def finalize(self):
        self.events.append(("finalize",))

    def is_cancelled(self):
        return self.cancelled

    def native_sleep(self, milliseconds):
        self.sleep(milliseconds)

    def ticks(self):
        return self.clock

    def sleep(self, ms):
        self.clock = (self.clock + ms) & 0xFFFFFFFF
        self.events.append(("sleep", ms))
        if self.on_sleep:
            self.on_sleep()

    def read_field(self, field):
        self.events.append(("read_field", field))
        return self.nrc

    def read_dtcs(self, mode=0x80, capacity=0x1000):
        raise AssertionError("Unexpected diagnostic read")

    def support_snapshot(self, kind):
        raise AssertionError("Unexpected support snapshot")

    def select_target(self, identifier, second=0):
        raise AssertionError("Unexpected selected target change")

    def configure_target(self, first, second=0, third=0, fourth=0, fifth=0):
        self.events.append(("target", first, second, third, fourth, fifth))

    def select_protocol(self, kind):
        self.events.append(("protocol", kind))
        return 0

    def read_target(self):
        return (0x7E0, 0x7E8)

    def set_parameter(self, key, value):
        raise AssertionError("Unexpected parameter write")

    def write_parameters(self):
        raise AssertionError("Unexpected parameter write")

    def refresh_parameters(self):
        raise AssertionError("Unexpected parameter refresh")


def tank(newer=False):
    data = bytearray(0xC4 if newer else 0x13C)
    for row in range(3 if newer else 5):
        data[row * 0x38 : row * 0x38 + 2] = b"\x1b\x9b"
        _put(data, row * 0x38 + 12, 2)
    return data


def wire(context):
    return [event[1] for event in context.events if event[0] == "exchange"]


def record(did, payload):
    return did + len(payload).to_bytes(2, "big") + payload


class TankTests(unittest.TestCase):
    def test_auto_power_target_protocol_and_payload_restore(self):
        data = bytearray(0x11C)
        _put(data, 0x118, 1007)
        ctx = Context(replies=[(0, b""), (0, b"\x62\x20\x01\xaa\x01\xbb"), (17, b"")])
        self.assertEqual(_auto_power((data,), ctx), 1009)
        self.assertEqual(
            wire(ctx), [b"\x3e\0", b"\x22\x20\x01", b"\x2e\x20\x01\xaa\x41\xbb"]
        )
        self.assertEqual(int.from_bytes(data[0x118:0x11C], "little"), 0)
        self.assertEqual(
            ctx.events[-3:],
            [("finalize",), ("protocol", 0), ("target", 0x7E0, 0x7E8, 0, 0, 0)],
        )

    def test_auto_power_primary_survives_inner_normal_and_outer_finalize_faults(self):
        primary = LookupError("AutoPower read failed")

        class Faults(Context):
            def exchange(self, request):
                self.events.append(("exchange", request))
                raise primary

            def session(
                self, mode, keepalive=1, *, normal_first=False, stop_on_error=False
            ):
                if mode == 1 and ("exchange", b"\x22\x20\x01") in self.events:
                    raise RuntimeError("normal cleanup failed")
                return 0

            def finalize(self):
                self.events.append(("finalize",))
                raise RuntimeError("finalize failed")

        ctx = Faults()
        with self.assertRaises(LookupError) as caught:
            _auto_power((bytearray(284),), ctx)
        self.assertIs(caught.exception, primary)
        self.assertEqual(
            ctx.events[-2:], [("protocol", 0), ("target", 0x7E0, 0x7E8, 0, 0, 0)]
        )

    def test_auto_power_failed_tester_present_retains_status(self):
        data = tank()
        _put(data, 0x118, 1007)
        ctx = Context(replies=[(23, b"")])
        self.assertEqual(_auto_power((data,), ctx), 1009)
        self.assertEqual(int.from_bytes(data[0x118:0x11C], "little"), 23)
        self.assertEqual(wire(ctx), [b"\x3e\0"])

    def test_start_retains_controller_and_packet(self):
        for sha in (SHA_18_TY, SHA_PLUS_TY):
            data = tank()
            _put(data, 0x12C, 1)
            ctx = Context(
                sha,
                [
                    (0, b"\x71\x01\x11\x1a"),
                    (0, b"\x6f\x28\x0c\x03\0\x01"),
                    (0, b"\x62\x1b\x94\x01\x01"),
                ],
            )
            self.assertEqual(
                _tank("Ex2FCHV_02_ReadTankShutValveStart", (data,), ctx), 0
            )
            self.assertEqual(
                wire(ctx),
                [
                    b"\x31\x01\x11\x1a\x01",
                    b"\x2f\x28\x0c\x03\0\x01\0\x01",
                    b"\x22\x1b\x94",
                ],
            )
            self.assertNotIn(("finalize",), ctx.events)

    def test_newer_masks_all_four_banks(self):
        data = tank(True)
        data[0xBC:0xC0] = b"\x01\x02\x04\x07"
        ctx = Context(
            SHA_PLUS_TY,
            [
                (0, b"\x6f\x28\x1f\x03\0\0"),
                (0, b"\x62\x1b\xbe\0\x01\0\x02\0\x04\0\x07"),
            ],
        )
        self.assertEqual(_tank("Ex2FCHV_26_ReadTankShutValveOpen", (data,), ctx), 0)
        self.assertEqual(
            wire(ctx)[0], bytes.fromhex("2f281f0300010002000400070001000200040007")
        )
        self.assertNotIn(("finalize",), ctx.events)

    def test_close_success_status_and_retention(self):
        ctx = Context(
            replies=[(0, b"\x6f\x28\x0c\x03\0\0"), (0, b"\x62\x1b\x94\x07\0")]
        )
        self.assertEqual(
            _tank("Ex2FCHV_02_ReadTankShutValveClose", (tank(),), ctx), 1012
        )
        self.assertNotIn(("finalize",), ctx.events)

    def test_return_success_normalization(self):
        ctx = Context(
            replies=[(0, b"\x6f\x28\x0c\x03\0\0"), (0, b"\x62\x1b\x94\x07\x07")]
        )
        self.assertEqual(
            _tank("Ex2FCHV_02_ReadTankShutValveRetrun", (tank(),), ctx), 1011
        )

    def test_poll_fault_stops_restores_and_finalizes(self):
        data = tank()
        ctx = Context(replies=[(0, b"bad"), (0, b"\x6f\x28\x0c\0\0\0")])
        self.assertEqual(_tank("Ex2FCHV_02_ReadTankShutValveOpen", (data,), ctx), 3)
        self.assertEqual(wire(ctx)[-1], b"\x2f\x28\x0c\0\0\0")
        self.assertEqual(
            ctx.events[-2:], [("session", 1, 1, False, False), ("finalize",)]
        )

    def test_native_nrc_getter(self):
        ctx = Context(replies=[(7, b""), (0, b"\x6f\x28\x0c\0\0\0")])
        self.assertEqual(_tank("Ex2FCHV_02_ReadTankShutValveOpen", (tank(),), ctx), 105)
        self.assertIn(("read_field", "native_10b0"), ctx.events)

    def test_poll_timeout_wraparound(self):
        ctx = Context(
            replies=[(0, b"\x6f\x28\x0c\x03\0\0")]
            + [(0, b"\x62\x1b\x94\x01\0")] * 27
            + [(0, b"\x6f\x28\x0c\0\0\0")]
        )
        ctx.clock = 0xFFFFFF00
        self.assertEqual(
            _tank("Ex2FCHV_02_ReadTankShutValveOpen", (tank(),), ctx), 1005
        )
        self.assertEqual(wire(ctx).count(b"\x22\x1b\x94"), 27)

    def test_drive_ignores_wire_status_and_retains(self):
        ctx = Context(replies=[(42, b"")])
        self.assertEqual(_tank("Ex2FCHV_02_TankShutValveDrive", (tank(),), ctx), 1010)
        self.assertNotIn(("finalize",), ctx.events)

    def test_stop_ignores_wire_status_but_cleans(self):
        ctx = Context(replies=[(42, b"")])
        self.assertEqual(_tank("Ex2FCHV_02_TankShutValveStop", (tank(),), ctx), 1004)
        self.assertEqual(ctx.events[-1], ("finalize",))

    def test_stream_updates_exact_bytes_ready_flags_and_retains(self):
        data = tank(True)
        _put(data, 0x9C, 1)
        _put(data, 0xAC, 1)
        ctx = Context(SHA_PLUS_TY, [(0, b"\x62\x1b\x9b\x12\x34")])
        self.assertEqual(_tank("Ex2FCHV_26_ReadData", (data,), ctx), 0)
        self.assertEqual(data[0xA0:0xA2], b"\x12\x34")
        self.assertEqual(int.from_bytes(data[0xB8:0xBC], "little"), 1)
        self.assertNotIn(("finalize",), ctx.events)

    def test_temperature_signed_boundary(self):
        data = tank(True)
        data[0x71] = 0xAE
        ctx = Context(SHA_PLUS_TY, [(0, b"\x62\x1b\xae\xf3\x33\0\0")])
        self.assertEqual(_tank("Ex2FCHV_26_ReadTemperature", (data,), ctx), 1002)
        self.assertEqual(wire(ctx), [b"\x22\x1b\xae"])
        self.assertEqual(ctx.events[-1], ("finalize",))

    def test_support_newer_mutates_capabilities(self):
        data = tank(True)
        for row, second in enumerate((0x9B, 0x9A, 0xAE)):
            data[row * 0x38 + 1] = second
        support = bytearray(b"\x62\x01\x01" + bytes(32))
        support[6] = 0x10
        live = bytearray(b"\x62\x1b\0" + bytes(32))
        live[26] = 4
        live[22] = 0x20
        ctx = Context(
            SHA_PLUS_TY,
            [
                (0, bytes(support)),
                (0, b"\x62\x28\x1f\x01\0\x02\0\x04\0\xff\0"),
                (0, bytes(live)),
                (0, b"\x62\x1b\xcf\x80\0\0\0\x04"),
            ],
        )
        self.assertEqual(_tank("Ex2FCHV_26_SupportCheck", (data,), ctx), 0)
        self.assertEqual(data[0xBC:0xC0], b"\x01\x02\x04\x07")
        for offset in (0x2C, 0x64, 0x9C, 0xC0):
            self.assertEqual(int.from_bytes(data[offset : offset + 4], "little"), 1)
        self.assertEqual(ctx.events[-1], ("finalize",))

    def test_support_missing_capability_is1001(self):
        ctx = Context(replies=[(0, b"\x62\x01\x01" + bytes(32))])
        self.assertEqual(_tank("Ex2FCHV_02_SupportCheck", (tank(),), ctx), 1001)
        self.assertEqual(ctx.events[-1], ("finalize",))

    def test_cancellation_and_host_exception_cleanup(self):
        for error in (Cancelled("cancel"), RuntimeError("host")):
            ctx = Context()
            ctx.fault = error
            with self.assertRaises(type(error)):
                _tank("Ex2FCHV_02_ReadTankShutValveOpen", (tank(),), ctx)
            self.assertEqual(ctx.events[-1], ("finalize",))
        ctx = Context()
        ctx.cancelled = True
        with self.assertRaises(Cancelled):
            _tank("Ex2FCHV_02_ReadTankShutValveStart", (tank(),), ctx)
        self.assertEqual(wire(ctx), [])

    def test_live_did_change_cannot_resize_native_argument_block(self):
        for newer in (False, True):
            data = tank(newer)
            base = 0x70 if newer else 0
            _put(data, base + 0x2C, 1)

            class Mutating(Context):
                block = data
                row = base
                next_did = 0xAE if newer else 0x97

                def exchange(self, request):
                    result = super().exchange(request)
                    self.block[self.row + 1] = self.next_did
                    _put(self.block, self.row + 12, 4)
                    return result

            ctx = Mutating(
                SHA_PLUS_TY if newer else SHA_18_TY, [(0, b"\x62\x1b\x9b\x12\x34")]
            )
            original_length = len(data)
            export = (
                "Ex2FCHV_26_ReadTemperature" if newer else "Ex2FCHV_02_ReadPressure"
            )
            with self.assertRaisesRegex(ValueError, "actual returned DID payload"):
                _tank(export, (data,), ctx)
            self.assertEqual(len(data), original_length)
            self.assertEqual(data[base + 0x30 : base + 0x32], bytes(2))

    def test_unused_descriptor_is_not_read_or_validated(self):
        data = tank()
        _put(data, 4, 100)
        ctx = Context(replies=[(42, b"")])
        self.assertEqual(_tank("Ex2FCHV_02_TankShutValveDrive", (data,), ctx), 1010)
        self.assertEqual(len(wire(ctx)), 1)

    def test_support_failure_publishes_all_five_availability_flags(self):
        for source in (SHA_18_TY, SHA_PLUS_TY):
            data = tank()
            data[1], data[57] = 0x97, 0x9A
            gate = bytearray(b"\x62\x01\x01" + bytes(32))
            gate[6] = 0x10
            live = bytearray(b"\x62\x1b\0" + bytes(32))
            live[21] = 0x10
            live[22] = 0x40
            ctx = Context(
                source, [(0, bytes(gate)), (0, b"\x62\x28\x0c\x07"), (0, bytes(live))]
            )
            self.assertEqual(_tank("Ex2FCHV_02_SupportCheck", (data,), ctx), 1001)
            self.assertEqual(int.from_bytes(data[100:104], "little"), 1)

    def test_host_primary_survives_stop_normal_and_finalize_faults(self):
        primary = LookupError("host exchange failed")

        class Faults(Context):
            def session(
                self, mode, keepalive=1, *, normal_first=False, stop_on_error=False
            ):
                self.events.append(("normal_fault",))
                raise RuntimeError("normal failed")

            def finalize(self):
                self.events.append(("finalize_fault",))
                raise RuntimeError("finalize failed")

        ctx = Faults()
        ctx.fault = primary
        with self.assertRaises(LookupError) as caught:
            _tank("Ex2FCHV_02_ReadTankShutValveOpen", (tank(),), ctx)
        self.assertIs(caught.exception, primary)
        self.assertEqual(wire(ctx)[-1], b"\x2f\x28\x0c\0\0\0")
        self.assertIn(("normal_fault",), ctx.events)
        self.assertIn(("finalize_fault",), ctx.events)
        self.assertEqual(len(primary.__notes__), 3)

    def test_cancel_after_activation_attempts_raw_stop_then_restore(self):
        class Cancelling(Context):
            def exchange(self, request):
                result = super().exchange(request)
                if request[0:4] == b"\x2f\x28\x0c\x03":
                    self.cancelled = True
                return result

        ctx = Cancelling(
            replies=[(0, b"\x6f\x28\x0c\x03\0\0"), (0, b"\x6f\x28\x0c\0\0\0")]
        )
        with self.assertRaises(Cancelled):
            _tank("Ex2FCHV_02_ReadTankShutValveOpen", (tank(),), ctx)
        self.assertEqual(
            wire(ctx), [b"\x2f\x28\x0c\x03\0\0\0\0", b"\x2f\x28\x0c\0\0\0"]
        )
        self.assertIn(("cleanup_exchange", b"\x2f\x28\x0c\0\0\0"), ctx.events)
        self.assertTrue(ctx.cancelled)
        self.assertEqual(ctx.events[-1], ("finalize",))

    def test_invalid_descriptor_before_io(self):
        data = tank()
        _put(data, 4, 100)
        _put(data, 0x2C, 1)
        ctx = Context()
        with self.assertRaises(ValueError):
            _tank("Ex2FCHV_02_ReadPressure", (data,), ctx)
        self.assertEqual(ctx.events, [])


class ValuesTests(unittest.TestCase):
    def test_write_extracts_records_only_after_initialize_and_session(self):
        for mutate_in in ("initialize", "session"):
            value = FCHVValues(bytearray(record(b"\x20\x05", b"abc")), (1, 0, 0))

            class Mutating(Context):
                target = value
                when = mutate_in

                def initialize(self, mode=0):
                    if self.when == "initialize":
                        self.target.data[4:7] = b"xyz"
                    return super().initialize(mode)

                def session(
                    self, mode, keepalive=1, *, normal_first=False, stop_on_error=False
                ):
                    if self.when == "session" and mode == 3:
                        self.target.data[4:7] = b"xyz"
                    return super().session(
                        mode,
                        keepalive,
                        normal_first=normal_first,
                        stop_on_error=stop_on_error,
                    )

            ctx = Mutating(replies=[(0, b"\x6e\x20\x05")])
            self.assertEqual(_values("Ex2FCHV_08_WriteValues", (value,), ctx), 0)
            self.assertEqual(wire(ctx), [b"\x2e\x20\x05\x01yz"])

    def test_read_reloads_selection_before_each_read_and_final_copy(self):
        value = FCHVValues(bytearray(), (1, 1, 0))

        class Deselecting(Context):
            def exchange(self, request):
                value.selected = (0, 0, 1)
                return super().exchange(request)

        ctx = Deselecting(
            replies=[(0, b"\x62\x20\x05abc"), (0, b"\x62\x20\x11" + bytes(72))]
        )
        self.assertEqual(_values("Ex2FCHV_07_ReadValues", (value,), ctx), 0)
        self.assertEqual(wire(ctx), [b"\x22\x20\x05", b"\x22\x20\x11"])
        self.assertEqual(value.data, record(b"\x20\x11", bytes(72)))

    def test_newly_selected_past_slot_has_zero_length_without_invented_read(self):
        value = FCHVValues(bytearray(), (0, 1, 0))

        class Reselecting(Context):
            def exchange(self, request):
                value.selected = (1, 0, 0)
                return super().exchange(request)

        ctx = Reselecting(replies=[(0, b"\x62\x20\x10" + bytes(210))])
        self.assertEqual(_values("Ex2FCHV_07_ReadValues", (value,), ctx), 0)
        self.assertEqual(wire(ctx), [b"\x22\x20\x10"])
        self.assertEqual(value.data, b"")

    def test_read_selected_records_preserves_order(self):
        value = FCHVValues(bytearray(b"old"), (1, 0, 1))
        first, third = b"abc", bytes(range(72))
        ctx = Context(
            replies=[(0, b"\x62\x20\x05" + first), (0, b"\x62\x20\x11" + third)]
        )
        self.assertEqual(_values("Ex2FCHV_07_ReadValues", (value,), ctx), 0)
        self.assertEqual(
            value.data, record(b"\x20\x05", first) + record(b"\x20\x11", third)
        )
        self.assertEqual(wire(ctx), [b"\x22\x20\x05", b"\x22\x20\x11"])
        self.assertEqual(ctx.events[-1], ("finalize",))

    def test_failed_read_clears_old_output_without_partial_publish(self):
        value = FCHVValues(bytearray(b"old"), (1, 1, 0))
        ctx = Context(replies=[(0, b"\x62\x20\x05abc"), (0, b"short")])
        self.assertEqual(_values("Ex2FCHV_07_ReadValues", (value,), ctx), 3)
        self.assertEqual(value.data, b"")

    def test_initialize_failure_preserves_output(self):
        value = FCHVValues(bytearray(b"old"), (1, 0, 0))
        ctx = Context()
        ctx.init_status = 13
        self.assertEqual(_values("Ex2FCHV_07_ReadValues", (value,), ctx), 13)
        self.assertEqual(value.data, b"old")
        self.assertEqual(wire(ctx), [])

    def test_compare_only_native_offset5_two_bytes(self):
        for actual, expected in ((b"Zbc", 0), (b"Zbx", 99)):
            value = FCHVValues(bytearray(record(b"\x20\x05", b"abc")))
            ctx = Context(replies=[(0, b"\x62\x20\x05" + actual)])
            self.assertEqual(_values("Ex2FCHV_08_ReadValues", (value,), ctx), expected)
            self.assertEqual(value.data, record(b"\x20\x05", b"abc"))

    def test_write_first_matching_record_and_force_first_byte(self):
        data = (
            record(b"\x20\x05", b"abc")
            + record(b"\x20\x05", b"xyz")
            + record(b"\x20\x10", b"pq")
        )
        value = FCHVValues(bytearray(data), (1, 1, 1))
        ctx = Context(SHA_PLUS_TY, [(0, b"\x6e\x20\x05"), (0, b"\x6e\x20\x10")])
        self.assertEqual(_values("Ex2FCHV_08_WriteValues", (value,), ctx), 0)
        self.assertEqual(wire(ctx), [b"\x2e\x20\x05\x01bc", b"\x2e\x20\x10pq"])
        self.assertEqual(value.data, data)

    def test_write_fault_normalized1000(self):
        value = FCHVValues(bytearray(record(b"\x20\x05", b"abc")), (1, 0, 0))
        ctx = Context(replies=[(17, b"")])
        self.assertEqual(_values("Ex2FCHV_08_WriteValues", (value,), ctx), 1000)
        self.assertEqual(ctx.events[-1], ("finalize",))

    def test_caller_except_does_not_hide_new_cleanup_fault_or_select_host_cleanup(self):
        for operation in ("values", "tank", "auto"):
            failure = RuntimeError("sole finalize fault")

            class FinalizeFault(Context):
                error = failure

                def finalize(self):
                    raise self.error

            ctx = FinalizeFault(replies=[(42, b"")])
            caller = ValueError("unrelated caller exception")
            try:
                raise caller
            except ValueError:
                with self.assertRaises(RuntimeError) as caught:
                    if operation == "values":
                        _values("Ex2FCHV_07_ReadValues", (FCHVValues(),), ctx)
                    elif operation == "tank":
                        _tank("Ex2FCHV_02_TankShutValveStop", (tank(),), ctx)
                    else:
                        data = bytearray(284)
                        _put(data, 280, 1)
                        _auto_power((data,), ctx)
                self.assertIs(caught.exception, failure)
            self.assertFalse(hasattr(caller, "__notes__"))
            self.assertFalse(any(event[0] == "cleanup_session" for event in ctx.events))
            if operation != "auto":
                self.assertIn(("session", 1, 1, False, False), ctx.events)

    def test_values_primary_survives_normal_and_finalize_faults(self):
        primary = LookupError("value read failed")

        class Faults(Context):
            def exchange(self, request):
                raise primary

            def session(
                self, mode, keepalive=1, *, normal_first=False, stop_on_error=False
            ):
                if mode == 1:
                    self.events.append(("normal_fault",))
                    raise RuntimeError("normal failed")
                return 0

            def finalize(self):
                self.events.append(("finalize_fault",))
                raise RuntimeError("finalize failed")

        ctx = Faults()
        with self.assertRaises(LookupError) as caught:
            _values("Ex2FCHV_07_ReadValues", (FCHVValues(selected=(1, 0, 0)),), ctx)
        self.assertIs(caught.exception, primary)
        self.assertEqual(ctx.events[-2:], [("normal_fault",), ("finalize_fault",)])

    def test_malformed_values_rejected_before_write(self):
        ctx = Context()
        for data in (b"a", b"\x20\x05\xff\xff"):
            with self.assertRaises(ValueError):
                _values("Ex2FCHV_08_WriteValues", (FCHVValues(bytearray(data)),), ctx)
        self.assertEqual(wire(ctx), [])

    def test_source_mismatch_and_unknown_export_rejected(self):
        ctx = Context()
        with self.assertRaises(TYSourceError):
            run_body("Ex2FCHV_02_ReadPressure", (tank(),), ctx)
        self.assertEqual(supported_exports("unrecognized"), ())
        self.assertEqual(ctx.events, [])

    def test_typed_values_reach_the_actual_ty_dispatcher(self):
        require_private(
            "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll"
        )
        path = Path(
            "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll"
        )
        ctx = Context(replies=[(0, b"\x62\x20\x05abc")])
        ctx.module_bytes = path.read_bytes()
        value = FCHVValues(bytearray(), (1, 0, 0))
        self.assertIn("Ex2FCHV_07_ReadValues", ty_supported_exports(SHA_18_TY))
        self.assertEqual(ty_run_body("Ex2FCHV_07_ReadValues", (value,), ctx), 0)
        self.assertEqual(value.data, record(b"\x20\x05", b"abc"))

    def test_exact_module_identity_offline(self):
        sources = {
            SHA_18_TY: "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll",
            SHA_PLUS_TY: "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll",
        }
        require_private(*sources.values())
        for sha, path in sources.items():
            ctx = Context(
                sha, [(0, b"\x6f\x28\x0c\x03\0\0"), (0, b"\x62\x1b\x94\x01\x01")]
            )
            ctx.module_bytes = Path(path).read_bytes()
            self.assertEqual(
                run_body("Ex2FCHV_02_ReadTankShutValveOpen", (tank(),), ctx), 0
            )
            ctx.module_bytes += b"changed"
            with self.assertRaises(TYSourceError):
                run_body("Ex2FCHV_02_ReadTankShutValveOpen", (tank(),), ctx)


if __name__ == "__main__":
    unittest.main()
