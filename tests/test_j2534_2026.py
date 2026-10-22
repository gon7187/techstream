"""Authored no-car controls for source-audited CUW2026 J2534 algorithms."""

import unittest
from typing import Any

from scripts.j2534_2026 import (
    J2534Device2026,
    NativeMessage,
    NativePassThruError2026,
    PrimitiveResult,
    j2534_indication,
)
from scripts.programming import NativeTransportError
from scripts.programming_2026_common import CanDiag2026, NativeRuntime2026


class Provider:
    def __init__(self):
        self.calls = []
        self.reads = []
        self.responses = {}

    def __call__(self, operation, remaining):
        self.calls.append((operation, remaining))
        name = operation["operation"]
        if name in self.responses:
            return self.responses[name]
        if name == "passthru_read":
            return PrimitiveResult(value=self.reads.pop(0) if self.reads else ())
        if name == "passthru_write":
            return PrimitiveResult(value=operation["count"])
        if name in (
            "passthru_open",
            "passthru_connect",
            "passthru_start_filter",
            "passthru_start_periodic",
        ):
            return PrimitiveResult(value=0)
        return PrimitiveResult()

    @property
    def operations(self):
        return [item[0]["operation"] for item in self.calls]


class J2534Tests(unittest.TestCase):
    def setUp(self):
        self.provider = Provider()
        self.device = J2534Device2026(
            self.provider, clock=lambda: 0, background_workers=False
        )
        from scripts.j2534_2026 import MessageHistory2026

        self.device.set_history_sink(MessageHistory2026())
        self.device.open()
        self.device.connect(6)
        self.provider.calls.clear()

    def test_defaults_flags_can_fd_and_zero_handles(self):
        self.assertEqual(self.device.device_id, 0)
        self.assertEqual(self.device.channel_id, 0)
        self.assertEqual((self.device.timeout, self.device.send_timeout), (0, 1000))
        self.assertTrue(self.device.padding)
        self.device.configure_can_fd(True)
        self.assertEqual(
            self.provider.calls[-1][0]["parameters"],
            (
                (0x805C, 2000000),
                (0x8001, 0x60E),
                (0x805D, 0x20),
                (0x805E, 3),
                (0x805F, 1000),
                (0x8060, 0xCC),
            ),
        )

    def test_direct_wrapped_write_has_no_history_or_indication_and_preserves_zero_input_count(
        self,
    ):
        self.device.last_message = (4, b"preceding")
        self.provider.reads = [(NativeMessage(6, b"aaaa", rx_status=9),)]
        self.assertEqual(self.device.wrap_write_messages((NativeMessage(3, b"x"),)), 1)
        self.assertEqual(self.provider.operations, ["passthru_ioctl", "passthru_write"])
        self.assertEqual(self.device.last_message, (4, b"preceding"))
        written = self.provider.calls[-1][0]["messages"][0]
        self.assertEqual(
            (written.protocol_id, written.tx_flags, written.data), (6, 0x40, b"x")
        )
        self.assertEqual(len(self.provider.reads), 1)
        self.assertEqual(self.device.wrap_write_messages(()), 0)
        self.assertEqual(self.provider.calls[-1][0]["count"], 0)

    def test_full_write_zero_requested_count_retains_first_backing_message_for_history_and_indication(
        self,
    ):
        first = NativeMessage(3, b"aaaa\x10", tx_flags=0x80)
        self.provider.reads = [(NativeMessage(6, b"aaaa", rx_status=9),)]
        self.assertEqual(self.device.write_messages((first,), count=0), 0)
        self.assertEqual(self.device.last_message, (5, first.data))
        write = self.provider.calls[1][0]
        self.assertEqual(write["count"], 0)
        self.assertEqual(write["messages"], (first,))
        self.assertEqual(
            self.provider.operations,
            ["passthru_ioctl", "passthru_write", "passthru_read"],
        )
        with self.assertRaises(ValueError):
            self.device.wrap_write_messages((first,), 2)

    def test_zero_requested_read_reaches_native_api_and_full_read_keeps_first_indication(
        self,
    ):
        self.assertEqual(self.device.read_messages(0), ())
        self.assertEqual(self.provider.calls[-1][0]["count"], 0)
        self.provider.reads = [(NativeMessage(6, b"discarded", rx_status=9),), ()]
        self.assertEqual(self.device.read_after_indication(0), ())
        self.assertEqual([op["count"] for op, _ in self.provider.calls], [0, 1, 0])
        self.provider.responses["passthru_read"] = PrimitiveResult(status=7)
        with self.assertRaises(NativeTransportError) as caught:
            self.device.read_messages(0)
        self.assertEqual(caught.exception.code, 7)

    def test_explicit_native_unknown_indication_faults_follow_native_catch_all_but_host_errors_do_not(
        self,
    ):
        from scripts.programming_2026_common import NativeException2026

        original = self.provider
        read_calls = [0]

        def action(operation, remaining):
            if operation["operation"] == "passthru_read":
                read_calls[0] += 1
                if read_calls[0] == 1:
                    raise NativeException2026("authored typed native failure")
            return original(operation, remaining)

        self.device.provider = action
        self.provider.reads = [(NativeMessage(6, b"payload"),)]
        self.assertEqual(self.device.read_after_indication()[0].data, b"payload")
        read_calls[0] = 0
        self.assertEqual(self.device.write_messages((NativeMessage(6, b"aaaa1"),)), 1)
        host = OSError("authored host failure")

        def host_action(operation, remaining):
            if operation["operation"] == "passthru_read":
                raise host
            return original(operation, remaining)

        self.device.provider = host_action
        with self.assertRaises(OSError) as caught:
            self.device.read_after_indication()
        self.assertIs(caught.exception, host)

    def test_zero_address_specified_read_matches_initialized_backing_without_fabricating_count(
        self,
    ):
        for requested, protocol in ((1, 6), (0, 0)):
            with self.subTest(requested=requested):
                result = self.device.read_specified_result(bytes(4), count=requested)
                self.assertEqual(
                    (result.count, result.message.protocol_id, result.message.data),
                    (0, protocol, b""),
                )
                self.assertEqual(self.device.last_message, (4, b""))
                self.assertEqual(self.provider.calls[-1][0]["count"], requested)
        self.assertEqual(self.device.read_specified(bytes(5)).data, b"")
        self.provider.reads = [(NativeMessage(6, b"abc"),)]
        result = self.device.read_specified_result(b"abc\0")
        self.assertEqual((result.count, result.message.data), (1, b"abc"))
        # Addressed indication requires DataSize >= address length; empty backing
        # must be skipped even for an all-zero address.
        self.provider.reads = [(), (NativeMessage(6, bytes(4), rx_status=2),), ()]
        result = self.device.read_specified_result(bytes(4), frame=1)
        self.assertEqual(result.count, 0)
        self.assertEqual([op["count"] for op, _ in self.provider.calls[-3:]], [1, 1, 1])

    def test_reported_zero_count_preserves_explicit_backing_for_native_header_and_indication_checks(
        self,
    ):
        from scripts.j2534_2026 import NativeReadBatch2026

        message = NativeMessage(6, b"aaaa\x50", rx_status=0)
        self.provider.reads = [NativeReadBatch2026((message,), 0)]
        result = self.device.read_specified_result(b"aaaa")
        self.assertEqual((result.count, result.message), (0, message))
        self.provider.reads = [
            NativeReadBatch2026((NativeMessage(6, b"aaaa", rx_status=2),), 0)
        ]
        self.assertEqual(self.device.read_indication(b"aaaa"), 1)
        self.provider.reads = [
            NativeReadBatch2026((NativeMessage(6, b"", rx_status=9),), 0)
        ]
        self.assertEqual(self.device.read_indication(), 0)
        self.provider.reads = [NativeReadBatch2026((message,), 0)]
        self.assertEqual(self.device.read_messages(), ())
        self.provider.reads = [NativeReadBatch2026((message,), 0)]
        self.assertEqual(self.device.read_messages_result().messages, (message,))

    def test_byte_bridge_observes_first_backing_data_without_replacing_reported_count(
        self,
    ):
        from scripts.j2534_2026 import NativeReadBatch2026

        payload = NativeReadBatch2026((NativeMessage(6, b"backing"),), 0)
        self.provider.reads = [payload]
        runtime = NativeRuntime2026(self.device.primitive)
        self.assertEqual(runtime.call("read_messages", count=1), b"backing")
        self.provider.reads = [payload]
        self.assertEqual(runtime.call("read_messages_result", count=1), payload)
        self.provider.reads = [(), payload]
        self.assertEqual(runtime.call("read_after_indication", count=1), b"backing")
        self.provider.reads = [(), payload]
        self.assertEqual(runtime.call("read_after_indication_result", count=1), payload)

    def test_indication_literal_status_and_padding(self):
        for status, expected in ((0, 3), (2, 1), (9, 0), (16, 2), (1, 4), (0x82, 1)):
            self.assertEqual(j2534_indication(status, True), expected)
        self.assertEqual(j2534_indication(16, False), 3)

    def test_write_clears_rx_before_write_consumes_indication_history_before_mutation(
        self,
    ):
        address = bytes.fromhex("000007e0")
        self.provider.reads = [
            (),
            (NativeMessage(6, b"xxxx", rx_status=9),),
            (NativeMessage(6, address, rx_status=9),),
        ]
        message = NativeMessage(3, address + b"\x10\x02", tx_flags=0x80)
        self.assertEqual(self.device.write_messages((message,)), 1)
        self.assertEqual(
            self.provider.operations[:2], ["passthru_ioctl", "passthru_write"]
        )
        written = self.provider.calls[1][0]["messages"][0]
        self.assertEqual((written.protocol_id, written.tx_flags), (6, 0xC0))
        self.assertEqual(message.protocol_id, 3)
        self.assertEqual(self.device.last_message, (5, message.data))
        self.assertEqual(self.provider.calls[1][0]["timeout"], 1000)

    def test_matching_read_rejects_wrong_header_indications_and_truncated_data(self):
        address = b"\x00\x00\x07\xe8"
        self.provider.reads = [
            (NativeMessage(6, address[:3]),),
            (NativeMessage(6, b"xxxx\x50"),),
            (NativeMessage(6, address, rx_status=2),),
            (NativeMessage(6, address, rx_status=16),),
            (NativeMessage(6, address + b"\x50"),),
        ]
        self.assertEqual(self.device.read_specified(address).data, address + b"\x50")
        self.assertEqual(self.device.last_message, (4, address + b"\x50"))
        self.assertEqual(len(self.provider.calls), 5)

    def test_many_consumes_one_requested_header_per_message_in_arrival_order(self):
        a, b = b"aaaa", b"bbbbb"
        self.provider.reads = [(NativeMessage(6, b + b"2"), NativeMessage(6, a + b"1"))]
        result = self.device.read_specified_many((a, b))
        self.assertEqual(tuple(item.data for item in result), (b + b"2", a + b"1"))

    def test_flow_filter_literal_flags_extended_and_width(self):
        request, response = bytes.fromhex("18daf1e001"), bytes.fromhex("18dae0f101")
        self.device.start_flow_control_filter(request, response)
        operation = self.provider.calls[-1][0]
        self.assertEqual(operation["filter_type"], 3)
        self.assertEqual(operation["mask"].data, b"\xff" * 5)
        self.assertEqual(operation["pattern"].data, response)
        self.assertEqual(operation["flow_control"].data, request)
        self.assertEqual(operation["mask"].tx_flags, 0x1C0)
        self.device.stop_filter(0)
        self.assertEqual(self.device.filters, [])
        before = len(self.provider.calls)
        with self.assertRaises(ValueError):
            self.device.start_flow_control_filter(request[:4], response)
        self.assertEqual(len(self.provider.calls), before)

    def test_can_filter_and_periodic_different_padding_contract(self):
        self.device.padding = False
        self.device.start_can_filter(1, b"\xff" * 5, b"abcdx")
        operation = self.provider.calls[-1][0]
        self.assertEqual(
            (
                operation["filter_type"],
                operation["mask"].data,
                operation["pattern"].data,
            ),
            (2, b"\xff" * 4, b"abcd"),
        )
        self.device.start_periodic(NativeMessage(0, b"abcd", tx_flags=0x100), 500)
        self.assertEqual(self.provider.calls[-1][0]["message"].tx_flags, 0x140)
        self.device.stop_periodic(0)
        self.assertEqual(self.device.periodics, [])

    def test_voltage_only_native_enable_disable_transitions(self):
        for voltage in (12345, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFF):
            self.device.set_programming_voltage(12, voltage)
        self.assertEqual(
            self.provider.operations, ["passthru_voltage", "passthru_voltage"]
        )
        self.assertFalse(self.device.voltage_enabled)

    def test_native_disconnect_and_close_ignore_return_status(self):
        self.provider.responses["passthru_disconnect"] = PrimitiveResult(9)
        self.provider.responses["passthru_close"] = PrimitiveResult(16)
        self.device.disconnect()
        self.assertIsNone(self.device.channel_id)
        self.assertIsNone(self.device.device_id)
        self.assertEqual(
            self.provider.operations[-2:], ["passthru_disconnect", "passthru_close"]
        )

    def test_cancel_after_acquisition_retains_handle_and_cleanup_bypasses_cancel(self):
        cancelled = [False]

        def action(operation, _remaining):
            cancelled[0] = True
            return PrimitiveResult(
                value=7 if operation["operation"] == "passthru_open" else None
            )

        device = J2534Device2026(
            action,
            clock=lambda: 0,
            background_workers=False,
            cancelled=lambda: cancelled[0],
        )
        with self.assertRaises(InterruptedError):
            device.open()
        self.assertEqual(device.device_id, 7)
        device.disconnect()
        self.assertIsNone(device.device_id)

    def test_zero_reads_timeout_and_malformed_provider(self):
        now = [0]

        def action(_operation, _remaining):
            now[0] += 1
            return PrimitiveResult(value=())

        self.device.provider = action
        self.device.clock = lambda: now[0]
        self.device.deadline = 2
        with self.assertRaises(TimeoutError):
            self.device.read_specified(b"abcd")
        self.device.clock = lambda: 0
        self.device.deadline = 30
        self.device.provider = lambda *_: PrimitiveResult(value=(b"bad",))
        with self.assertRaises(ValueError):
            self.device.read_messages()
        malformed: Any = lambda *_: 0
        self.device.provider = malformed
        with self.assertRaises(TypeError):
            self.device.control_io(8)

    def test_bridge_padding_observes_actual_instance_state(self):
        other = J2534Device2026(self.provider, clock=lambda: 0)
        self.assertIs(
            self.device.primitive({"operation": "get_can_frame_padding"}, 1), True
        )
        self.device.padding = False
        self.assertIs(
            self.device.primitive({"operation": "get_can_frame_padding"}, 1), False
        )
        self.assertIs(other.primitive({"operation": "get_can_frame_padding"}, 1), True)
        self.assertEqual(self.provider.calls, [])

    def test_runtime_periodic_bridge_acquires_and_releases_typed_message(self):
        runtime = NativeRuntime2026(self.device.primitive, clock=lambda: 0)
        identifier = runtime.acquire(
            "start_periodic",
            "stop_periodic",
            message=NativeMessage(0, b"abcd", tx_flags=0x100),
            interval=500,
        )
        self.assertEqual(identifier, 0)
        self.assertEqual(self.device.periodics, [0])
        runtime.close()
        self.assertEqual(self.device.periodics, [])
        self.assertEqual(
            self.provider.operations,
            ["passthru_start_periodic", "passthru_stop_periodic"],
        )
        started = self.provider.calls[0][0]
        self.assertEqual(started["interval"], 500)
        self.assertEqual(started["message"], NativeMessage(6, b"abcd", tx_flags=0x140))
        self.provider.calls.clear()
        with self.assertRaises(TypeError):
            self.device.primitive(
                {"operation": "start_periodic", "message": b"abcd", "interval": 500}, 1
            )
        self.assertEqual(self.provider.calls, [])

    def test_periodic_bridge_late_acquisition_rolls_back_only_fresh_id(self):
        for late in ("cancel", "deadline", "failed-stop"):
            with self.subTest(late=late):
                self._check_periodic_rollback(late)

    def _check_periodic_rollback(self, late):
        cancelled, now = [False], [0.0]
        base = Provider()

        def provider(operation, remaining):
            if operation["operation"] == "passthru_start_periodic":
                base.calls.append((operation, remaining))
                if late == "deadline":
                    now[0] = 31
                else:
                    cancelled[0] = True
                return PrimitiveResult(value=32)
            if (
                late == "failed-stop"
                and operation["operation"] == "passthru_stop_periodic"
            ):
                base.calls.append((operation, remaining))
                return PrimitiveResult(status=9)
            return base(operation, remaining)

        device = J2534Device2026(
            provider,
            clock=lambda: now[0],
            cancelled=lambda: cancelled[0],
            background_workers=False,
        )
        device.open()
        device.connect(6)
        device.periodics[:] = [30, 31]
        runtime = NativeRuntime2026(
            device.primitive,
            clock=lambda: now[0],
            cancelled=lambda: cancelled[0],
        )
        expected = TimeoutError if late == "deadline" else InterruptedError
        with self.assertRaises(expected) as caught:
            runtime.acquire(
                "start_periodic",
                "stop_periodic",
                message=NativeMessage(6, b"abcd"),
                interval=500,
            )
        runtime.close()
        self.assertEqual(
            device.periodics,
            [30, 31, 32] if late == "failed-stop" else [30, 31],
        )
        self.assertEqual(
            [
                op["identifier"]
                for op, _ in base.calls
                if op["operation"] == "passthru_stop_periodic"
            ],
            [32],
        )
        self.assertTrue(device.connecting)
        if late == "failed-stop":
            self.assertIn(
                "device-owned", str(getattr(caught.exception, "__notes__", []))
            )

    def test_disconnect_preserves_first_host_fault_and_attempts_all_cleanup(self):
        from unittest.mock import patch

        primary = OSError("worker primary")
        failures = {
            name: OSError(name)
            for name in (
                "passthru_disconnect",
                "passthru_close",
                "passthru_unload_library",
            )
        }
        original = self.provider

        def provider(operation, remaining):
            name = operation["operation"]
            if name in failures:
                original.calls.append((operation, remaining))
                raise failures[name]
            return original(operation, remaining)

        self.device.provider = provider
        self.device.shim_handle = 9
        self.device.driver_loaded = True
        with (
            patch.object(self.device, "stop_sync_periodic", side_effect=primary),
            patch.object(self.device, "release_ownership") as release,
        ):
            with self.assertRaises(OSError) as caught:
                self.device.disconnect()
            release.assert_called_once_with()
        self.assertIs(caught.exception, primary)
        self.assertEqual(self.provider.operations, list(failures))
        self.assertEqual(len(getattr(primary, "__notes__", [])), 3)
        self.assertTrue(self.device.connecting)
        self.assertTrue(self.device.opened)
        self.assertTrue(self.device.driver_loaded)
        self.provider.calls.clear()
        with self.assertRaises(OSError) as lone:
            self.device.disconnect()
        self.assertIs(lone.exception, failures["passthru_disconnect"])
        self.assertEqual(self.provider.operations, list(failures))

    def test_equivalent_active_import_preserves_unexported_resources_and_pointer_identity(
        self,
    ):
        from dataclasses import replace

        from scripts.j2534_2026 import DriverMetadata2026, MessageHistory2026

        self.device.set_driver(DriverMetadata2026("authored", "fixture.dll"))
        self.device.start_periodic(NativeMessage(6, b"abcd"), 500)
        self.device.filters[:] = [31]
        self.device.logical[0x8203] = 32
        snapshot = self.device.export_data()
        self.device.import_data(snapshot)
        self.assertEqual(self.device.periodics, [0])
        self.assertEqual(self.device.filters, [31])
        self.assertEqual(self.device.logical, {0x8203: 32})
        self.assertIs(self.device.history_sink, snapshot.history_sink)
        before = len(self.provider.calls)
        for changed in (
            replace(snapshot, device_id=1),
            replace(snapshot, provider=Provider()),
            replace(snapshot, history_sink=MessageHistory2026()),
        ):
            with self.assertRaises(ValueError):
                self.device.import_data(changed)
        self.assertEqual(len(self.provider.calls), before)
        self.assertEqual(self.device.periodics, [0])
        self.assertEqual(self.device.filters, [31])

    def test_actual_battery_probe_preserves_raw_version_config_and_dword(self):
        # CUW33e50/33f80: consumers perform the unsigned DWORD conversion.
        for version in (0, 1):
            with self.subTest(version=version):
                self.device.version = version
                self.provider.calls.clear()
                self.provider.responses["passthru_read_version"] = PrimitiveResult(
                    value=("firmware", "dll", "api")
                )
                self.provider.responses["passthru_ioctl"] = PrimitiveResult(
                    value=0xFFFFFFFF
                )
                self.assertEqual(
                    self.device.read_device_version(), ("firmware", "dll", "api")
                )
                self.device.control_io(1, ((1, 0),))
                self.assertEqual(self.device.control_io(3), 0xFFFFFFFF)
                calls = [entry[0] for entry in self.provider.calls]
                self.assertEqual(
                    [call["operation"] for call in calls],
                    ["passthru_read_version", "passthru_ioctl", "passthru_ioctl"],
                )
                self.assertEqual(calls[0]["device"], 0)
                self.assertEqual(calls[1]["ioctl"], 1)
                self.assertEqual(calls[1]["parameters"], ((1, 0),))
                self.assertEqual(calls[1]["channel"], 0)
                self.assertEqual(calls[2]["ioctl"], 3)
                self.assertEqual(calls[2]["channel"], 0)
                if version == 1:
                    self.assertEqual(calls[2]["resource"], (1, 1, (16,)))
                else:
                    self.assertEqual(calls[2]["parameters"], ())
                self.provider.responses["passthru_ioctl"] = PrimitiveResult(status=7)
                with self.assertRaises(NativePassThruError2026) as caught:
                    self.device.control_io(3)
                self.assertEqual(caught.exception.passthru_status, 7)

    def test_native_runtime_candiag_integration(self):
        request, response = bytes.fromhex("000007e0"), bytes.fromhex("000007e8")
        self.provider.reads = [
            (NativeMessage(6, request, rx_status=9),),
            (NativeMessage(6, response + b"\x7f\x22\x78"),),
            (NativeMessage(6, response + b"\x62\xf1\x90OK"),),
        ]
        runtime = NativeRuntime2026(self.device.primitive, clock=lambda: 0)
        result = CanDiag2026(runtime).call(
            request, response, b"\x22\xf1\x90", b"\x62", send_tester_present=False
        )
        self.assertEqual(result, b"\x62\xf1\x90OK")
        self.assertEqual(self.device.timeout, 0)

    def test_input_rejected_before_transport(self):
        invalid: Any
        for invalid in (True, -1, 2**32, "6"):
            with self.assertRaises(ValueError):
                self.device.control_io(invalid)
        for invalid in (b"a" * 4129, bytearray(b"aaaa")):
            with self.assertRaises(ValueError):
                NativeMessage(6, invalid)
        with self.assertRaises(ValueError):
            self.device.write_messages((NativeMessage(6, b"ab"),))
        self.assertEqual(self.provider.calls, [])


class PairedInterfaceTests(unittest.TestCase):
    def _pair(
        self,
        provider=None,
        cancelled=None,
        *,
        max_calls=65536,
        max_cleanup_calls=1024,
        background_workers=False,
    ):
        from scripts.j2534_2026 import DriverMetadata2026, J2534InterfacePair2026

        provider = provider if provider is not None else Provider()
        clock = lambda: 0
        cancelled = cancelled if cancelled is not None else lambda: False
        engine = J2534Device2026(
            provider,
            clock=clock,
            cancelled=cancelled,
            background_workers=background_workers,
            max_calls=max_calls,
            max_cleanup_calls=max_cleanup_calls,
        )
        control = J2534Device2026(
            provider,
            clock=clock,
            cancelled=cancelled,
            background_workers=background_workers,
            max_calls=max_calls,
            max_cleanup_calls=max_cleanup_calls,
        )
        for view in (engine, control):
            view.set_driver(DriverMetadata2026("authored", "fixture.dll"))
        pair = J2534InterfacePair2026(engine, control)
        return pair, provider

    def test_issued_channel_lease_tracks_physical_release_without_peer_flag_changes(
        self,
    ):
        from unittest.mock import patch

        pair, provider = self._pair()
        engine, control = pair.engine, pair.control
        engine.open()
        engine.connect(6)
        pair.import_into(control, pair.export_from(engine))
        self.assertIs(control.interface_pair, pair)
        lease = pair.channel_lease(control)
        self.assertIs(pair.channel_lease(engine), lease)
        before = (len(provider.calls), engine.calls, control.calls)
        self.assertFalse(pair.channel_lease_retired(lease))
        pair.validate_channel_lease(control, lease)
        self.assertEqual((len(provider.calls), engine.calls, control.calls), before)
        primary = NativePassThruError2026(7)
        with (
            patch.object(engine, "stop_sync_periodic", side_effect=primary),
            self.assertRaises(NativePassThruError2026) as caught,
        ):
            engine.disconnect()
        self.assertIs(caught.exception, primary)
        self.assertTrue(control.connecting)
        self.assertTrue(pair.channel_lease_retired(lease))
        with self.assertRaises(ValueError):
            pair.validate_channel_lease(control, lease)
        with self.assertRaises(ValueError):
            pair.channel_lease(control)

    def test_successful_exact_parent_close_retires_channel_after_failed_disconnect(
        self,
    ):
        pair, provider = self._pair()
        engine, control = pair.engine, pair.control
        engine.open()
        engine.connect(6)
        pair.import_into(control, pair.export_from(engine))
        lease = pair.channel_lease(control)
        provider.responses["passthru_disconnect"] = PrimitiveResult(status=7)
        engine.disconnect()
        self.assertTrue(control.connecting)
        self.assertTrue(pair.channel_lease_retired(lease))
        control.disconnect()
        self.assertEqual(provider.operations.count("passthru_disconnect"), 1)
        self.assertEqual(provider.operations.count("passthru_close"), 1)
        provider.responses.clear()
        control.open()
        control.connect(6)
        fresh = pair.channel_lease(control)
        self.assertFalse(pair.channel_lease_retired(fresh))
        self.assertTrue(pair.channel_lease_retired(lease))
        pair.validate_channel_lease(control, fresh)

    def test_actual_runtime_stops_peer_host_worker_after_physical_parent_release(self):
        provider = LiveOSProvider()
        pair, _ = self._pair(provider, background_workers=True)
        engine, control = pair.engine, pair.control
        engine.open()
        engine.connect(6)
        pair.import_into(control, pair.export_from(engine))
        runtime = NativeRuntime2026(control.primitive)
        try:
            control.start_sync_periodic((NativeMessage(6, b"0000payload"),), 100, 10)
            self.assertTrue(provider.transmitted.wait(1))
            worker = control.sync_worker
            assert worker is not None
            runtime.own("stop_sync_periodic")
            engine.disconnect()
            self.assertEqual(runtime.close(), [])
            self.assertFalse(runtime.owns_resource("stop_sync_periodic"))
            self.assertFalse(worker.is_alive())
            self.assertIsNone(control.sync)
            self.assertEqual(provider.handles, {})
            self.assertTrue(control.connecting)
        finally:
            control.clear()
            engine.clear()
        self.assertEqual(provider.operations.count("passthru_disconnect"), 1)
        self.assertEqual(provider.operations.count("passthru_close"), 1)

    def test_channel_lease_failed_release_and_numeric_zero_reuse_do_not_authorize_old_cleanup(
        self,
    ):
        pair, provider = self._pair()
        engine, control = pair.engine, pair.control
        engine.open()
        engine.connect(6)
        pair.import_into(control, pair.export_from(engine))
        old = pair.channel_lease(control)
        provider.responses["passthru_disconnect"] = PrimitiveResult(status=7)
        provider.responses["passthru_close"] = PrimitiveResult(status=8)
        control.disconnect()
        self.assertFalse(pair.channel_lease_retired(old))
        provider.responses.clear()
        control.open()
        control.connect(6)
        current = pair.channel_lease(control)
        self.assertEqual(current.channel_id, 0)
        self.assertIsNot(current, old)
        before = len(provider.calls)
        with self.assertRaises(ValueError):
            pair.validate_channel_lease(control, old)
        self.assertEqual(len(provider.calls), before)
        pair.validate_channel_lease(control, current)
        control.disconnect()
        self.assertTrue(pair.channel_lease_retired(current))
        self.assertFalse(pair.channel_lease_retired(old))
        control.open()
        control.connect(6)
        fresh = pair.channel_lease(control)
        self.assertIsNot(fresh, current)
        self.assertFalse(pair.channel_lease_retired(fresh))
        pair.validate_channel_lease(control, fresh)
        with self.assertRaises(ValueError):
            pair.validate_channel_lease(control, current)

    def test_channel_lease_rejects_forged_and_foreign_authority_and_unknown_parent(
        self,
    ):
        from dataclasses import replace

        pair, _ = self._pair()
        other, _ = self._pair()
        self.assertIsNone(J2534Device2026(Provider()).interface_pair)
        with self.assertRaises(AttributeError):
            pair.engine.interface_pair = other  # type: ignore[misc]
        with self.assertRaises(ValueError):
            pair.channel_lease(pair.control)
        pair.engine.open()
        pair.engine.connect(6)
        lease = pair.channel_lease(pair.engine)
        for forged in (replace(lease), True, (lease.channel_id, lease.generation)):
            with self.assertRaises(ValueError):
                pair.channel_lease_retired(forged)
        with self.assertRaises(ValueError):
            other.channel_lease_retired(lease)
        with self.assertRaises(ValueError):
            pair.channel_lease(other.engine)

    def test_channel_lease_survives_cancel_after_successful_channel_acquisition(self):
        cancelled = [False]
        provider = Provider()

        def action(operation, remaining):
            result = provider(operation, remaining)
            if operation["operation"] == "passthru_connect":
                cancelled[0] = True
            return result

        pair, _ = self._pair(action, lambda: cancelled[0])
        pair.engine.open()
        with self.assertRaises(InterruptedError):
            pair.engine.connect(6)
        lease = pair.channel_lease(pair.engine)
        pair.import_into(pair.control, pair.export_from(pair.engine))
        self.assertIs(pair.channel_lease(pair.control), lease)
        pair.engine.disconnect()
        self.assertTrue(pair.channel_lease_retired(lease))
        self.assertTrue(pair.control.connecting)

    def test_closed_peer_return_is_literal_and_does_not_repeat_native_releases(self):
        pair, provider = self._pair()
        engine, control = pair.engine, pair.control
        engine.open()
        engine.connect(6)
        pair.import_into(control, pair.export_from(engine))
        engine.filters[:] = [91]
        engine.periodics[:] = [92]
        engine.logical[0x8203] = 93
        control.disconnect()
        self.assertTrue(engine.opened)
        self.assertTrue(engine.connecting)
        self.assertFalse(control.opened)
        pair.import_into(engine, pair.export_from(control))
        self.assertFalse(engine.opened)
        self.assertFalse(engine.connecting)
        self.assertEqual(engine.filters, [91])
        self.assertEqual(engine.periodics, [92])
        self.assertEqual(engine.logical, {0x8203: 93})
        engine.disconnect()
        self.assertEqual(provider.operations.count("passthru_disconnect"), 1)
        self.assertEqual(provider.operations.count("passthru_close"), 1)

    def test_stale_peer_cleanup_and_reused_zero_ids_have_distinct_generations(self):
        pair, provider = self._pair()
        engine, control = pair.engine, pair.control
        engine.open()
        engine.connect(6)
        pair.import_into(control, pair.export_from(engine))
        control.disconnect()
        control.open()
        control.connect(6)
        # Engine still sees generation one at zero, control now owns generation two.
        engine.disconnect()
        self.assertEqual(provider.operations.count("passthru_disconnect"), 1)
        self.assertEqual(provider.operations.count("passthru_close"), 1)
        self.assertTrue(control.connecting)
        pair.import_into(engine, pair.export_from(control))
        engine.disconnect()
        self.assertEqual(provider.operations.count("passthru_disconnect"), 2)
        self.assertEqual(provider.operations.count("passthru_close"), 2)
        control.disconnect()
        self.assertEqual(provider.operations.count("passthru_disconnect"), 2)
        self.assertEqual(provider.operations.count("passthru_close"), 2)

    def test_failed_native_release_is_not_retired_and_host_failure_is_preserved(self):
        pair, provider = self._pair()
        engine, control = pair.engine, pair.control
        engine.open()
        engine.connect(6)
        pair.import_into(control, pair.export_from(engine))
        provider.responses["passthru_disconnect"] = PrimitiveResult(status=7)
        provider.responses["passthru_close"] = PrimitiveResult(status=8)
        control.disconnect()
        provider.responses.clear()
        engine.disconnect()
        self.assertEqual(provider.operations.count("passthru_disconnect"), 2)
        self.assertEqual(provider.operations.count("passthru_close"), 2)
        self.assertFalse(engine.connecting)

    def test_acquired_handle_is_registered_before_late_cancel_for_peer_cleanup(self):
        cancelled = [False]
        provider = Provider()

        def action(operation, remaining):
            if operation["operation"] == "passthru_open":
                provider.calls.append((operation, remaining))
                cancelled[0] = True
                return PrimitiveResult(value=0)
            return provider(operation, remaining)

        pair, _ = self._pair(action, lambda: cancelled[0])
        with self.assertRaises(InterruptedError):
            pair.engine.open()
        self.assertTrue(pair.engine.opened)
        pair.import_into(pair.control, pair.export_from(pair.engine))
        pair.control.disconnect()
        pair.engine.disconnect()
        self.assertEqual(provider.operations.count("passthru_close"), 1)

    def test_only_latest_exact_peer_snapshot_and_unchanged_capability_are_accepted(
        self,
    ):
        from dataclasses import replace

        pair, _ = self._pair()
        engine, control = pair.engine, pair.control
        engine.open()
        engine.connect(6)
        old = pair.export_from(engine)
        latest = pair.export_from(engine)
        for foreign in (old, replace(latest, opened=False), engine.export_data()):
            with self.assertRaises(ValueError):
                pair.import_into(control, foreign)
        with self.assertRaises(ValueError):
            engine._import_data(latest, _issuer=pair)
        pair.import_into(control, latest)
        self.assertTrue(control.opened)
        # Nested descriptor strings are mutable despite the frozen outer record.
        assert latest.driver is not None
        latest.driver.dll_name = "changed.dll"
        with self.assertRaises(ValueError):
            pair.import_into(control, latest)
        engine.provider = Provider()
        with self.assertRaises(ValueError):
            pair.validate_views()

    def test_peer_import_replaces_active_sil_prefix_but_preserves_non_sil_zero_id(self):
        pair, _ = self._pair()
        engine, control = pair.engine, pair.control
        engine.open()
        engine.connect(6)
        engine.filters[:] = [0]
        pair.import_into(control, pair.export_from(engine))
        pair.import_into(engine, pair.export_from(control))
        self.assertEqual(engine.filters, [0])
        engine.sil_filter_count = 1
        engine.sil_filter_ids[0] = 11
        engine.sil_filter_active[0] = True
        engine.filters.append(11)
        pair.import_into(control, pair.export_from(engine))
        control.sil_filter_ids[0] = 12
        pair.import_into(engine, pair.export_from(control))
        self.assertEqual(engine.filters, [0, 12])

    def test_source_operations_and_direct_state_changes_invalidate_issued_snapshot(
        self,
    ):
        pair, _ = self._pair()
        engine, control = pair.engine, pair.control
        engine.open()
        engine.connect(6)
        snapshot = pair.export_from(engine)
        engine.close()
        with self.assertRaises(ValueError):
            pair.import_into(control, snapshot)
        snapshot = pair.export_from(engine)
        engine.set_opened(True)
        with self.assertRaises(ValueError):
            pair.import_into(control, snapshot)

    def test_native_views_share_normal_cleanup_call_budgets_and_deadline(self):
        pair, provider = self._pair(max_calls=3, max_cleanup_calls=1)
        engine, control = pair.engine, pair.control
        engine.open()
        engine.connect(6)
        pair.import_into(control, pair.export_from(engine))
        control.control_io(8)
        with self.assertRaisesRegex(ValueError, "call budget"):
            engine.control_io(8)
        self.assertEqual(provider.operations.count("passthru_ioctl"), 1)
        control.close()
        with self.assertRaisesRegex(ValueError, "cleanup call budget"):
            engine.close()
        self.assertEqual(provider.operations.count("passthru_close"), 1)
        second, second_provider = self._pair()
        second.engine.deadline = -1
        with self.assertRaises(TimeoutError):
            second.control.open()
        self.assertEqual(second_provider.calls, [])

    def test_shared_driver_and_module_release_tokens_survive_native_unexported_loaded_flag(
        self,
    ):
        provider = Provider()

        def action(operation, remaining):
            if operation["operation"] == "load_library":
                provider.calls.append((operation, remaining))
                return PrimitiveResult(
                    value=9 if operation["name"] == "MsgDatCommWrapper.dll" else 8
                )
            if operation["operation"] == "get_symbol":
                provider.calls.append((operation, remaining))
                return PrimitiveResult(value=1)
            return provider(operation, remaining)

        pair, _ = self._pair(action)
        pair.engine.load_driver()
        pair.import_into(pair.control, pair.export_from(pair.engine))
        self.assertFalse(pair.control.driver_loaded)
        pair.control.clear()
        self.assertTrue(pair.engine.driver_loaded)
        pair.engine.clear()
        self.assertEqual(provider.operations.count("passthru_unload_library"), 1)
        freed = [
            operation["handle"]
            for operation, _ in provider.calls
            if operation["operation"] == "free_library"
        ]
        self.assertEqual(freed, [8, 9])

    def test_real_shared_ownership_worker_release_and_peer_clear_do_not_reuse_closed_event(
        self,
    ):
        provider = LiveOSProvider()
        pair, _ = self._pair(provider, background_workers=True)
        engine, control = pair.engine, pair.control
        engine.have_ownership()
        engine.open()
        engine.connect(6)
        pair.import_into(control, pair.export_from(engine))
        worker = engine.ownership_thread
        assert worker is not None
        control.clear()
        self.assertFalse(worker.is_alive())
        self.assertIsNotNone(engine.ownership_release)
        assert engine.ownership_release is not None
        self.assertTrue(engine.ownership_release.closed)
        engine.clear()
        self.assertEqual(provider.handles, {})
        self.assertEqual(provider.operations.count("release_mutex"), 1)
        self.assertEqual(provider.operations.count("passthru_disconnect"), 1)
        self.assertEqual(provider.operations.count("passthru_close"), 1)

    def test_host_release_failure_does_not_retire_generation(self):
        provider = Provider()
        failure = OSError("actual host release fault")
        fail = [True]

        def action(operation, remaining):
            if operation["operation"] == "passthru_disconnect" and fail[0]:
                provider.calls.append((operation, remaining))
                fail[0] = False
                raise failure
            return provider(operation, remaining)

        pair, _ = self._pair(action)
        pair.engine.open()
        pair.engine.connect(6)
        pair.import_into(pair.control, pair.export_from(pair.engine))
        lease = pair.channel_lease(pair.control)
        provider.responses["passthru_close"] = PrimitiveResult(status=8)
        with self.assertRaises(OSError) as caught:
            pair.control.disconnect()
        self.assertIs(caught.exception, failure)
        self.assertTrue(pair.control.connecting)
        self.assertFalse(pair.channel_lease_retired(lease))
        provider.responses.clear()
        pair.engine.disconnect()
        pair.control.disconnect()
        self.assertEqual(provider.operations.count("passthru_disconnect"), 2)
        self.assertEqual(provider.operations.count("passthru_close"), 2)

    def test_pair_rejects_foreign_execution_policy_and_simultaneous_unlinked_owners(
        self,
    ):
        from scripts.j2534_2026 import J2534InterfacePair2026

        provider = Provider()
        clock = lambda: 0
        first = J2534Device2026(provider, clock=clock, background_workers=False)
        second = J2534Device2026(provider, clock=lambda: 0, background_workers=False)
        with self.assertRaises(ValueError):
            J2534InterfacePair2026(first, second)
        second.clock = clock
        first.open()
        second.open()
        with self.assertRaises(ValueError):
            J2534InterfacePair2026(first, second)


class AddressTests(unittest.TestCase):
    def test_native_record_header_and_malformed_metadata(self):
        from scripts.j2534_2026 import separate_can_id

        standard = separate_can_id("07e0/07E8")
        self.assertEqual(standard.record(), bytes.fromhex("07e00007e80000"))
        self.assertEqual(
            standard.headers(), (bytes.fromhex("000007e0"), bytes.fromhex("000007e8"))
        )
        extended = separate_can_id("0740FE/0748FE")
        self.assertEqual(extended.headers()[0], bytes.fromhex("00000740fe"))
        for text in (
            "07e0",
            "07e0/",
            "/07e8",
            "07xz/07e8",
            "07e0/07e8/0000",
        ):
            with self.assertRaises(ValueError):
                separate_can_id(text)

    def test_strategy_order_clear_unknown_and_false_stop_preserves_partial(self):
        from scripts.j2534_2026 import CommunicationAddress2026

        resolver = CommunicationAddress2026({"CanIDForGetCID": ("07e0/07e8",)})
        ok, values = resolver.resolve(("GetCanIDsFromParamForGetCID", "unknown"))
        self.assertTrue(ok)
        self.assertEqual(len(values), 1)
        ok, values = resolver.resolve(("unknown", "GetCanIDsFromParamForGetCID"))
        self.assertEqual((ok, values), (False, ()))
        ok, values = resolver.resolve(
            ("GetCanIDsFromParamForGetCID", "GetCanIDsFromParamForPrepareWrite")
        )
        self.assertFalse(ok)
        self.assertEqual(len(values), 1)
        self.assertEqual(resolver.resolve(()), (False, ()))

    def test_matched_prefix_star_and_respond_cid_repeats_accumulated_vector(self):
        from scripts.j2534_2026 import CommunicationAddress2026

        resolver = CommunicationAddress2026(
            {
                "CIDForCalcCpuNum": ("AB",),
                "CanIDMatchedPartOfCID": ("0700/0708",),
                "CanIDForPrepareWrite": ("07e0/07e8",),
            }
        )
        ok, addresses = resolver.resolve(
            ("GetCanIDsFromParamMatchedPartOfCIDForPrepareWrite",),
            cids=("AB1", "XXAB2"),
        )
        self.assertTrue(ok)
        self.assertEqual(addresses, ())
        ok, addresses = resolver.resolve(
            (
                "GetCanIDsFromParamMatchedPartOfCIDForPrepareWrite",
                "GetCanIDsFromParamRespondCID",
            ),
            cids=("AB1", "AB2"),
        )
        self.assertTrue(ok)
        self.assertEqual(
            [v.request.hex() for v in addresses], ["0700", "07e0", "0700", "07e0"]
        )
        wildcard = CommunicationAddress2026(
            {"CIDForCalcCpuNum": ("*",), "CanIDMatchedPartOfCID": ("0700/0708",)}
        )
        self.assertEqual(
            len(
                wildcard.resolve(
                    ("GetCanIDsFromParamMatchedPartOfCIDForPrepareWrite",),
                    cids=("x", "y"),
                )[1]
            ),
            1,
        )

    def test_history_duplicates_request_only_and_width_match(self):
        from scripts.j2534_2026 import CommunicationAddress2026, separate_can_id

        history = []
        resolver = CommunicationAddress2026(
            {"CanIDForGetCID": ("07e0/07e8", "07e1/07e9", "07e0aa/07e8aa")},
            history=history,
        )
        resolver.remember(separate_can_id("07e0/0000"))
        resolver.remember(separate_can_id("07e0/0000"))
        self.assertEqual(resolver.history_request_ids(), ("07E0", "07E0"))
        ok, addresses = resolver.resolve(("GetCanIDsFromResultOfGetCID",))
        self.assertTrue(ok)
        self.assertEqual(len(addresses), 1)
        self.assertEqual(addresses[0].response.hex(), "07e8")

    def test_table_incomplete_preserves_partial_and_suzuki_forces_two_bytes(self):
        from scripts.j2534_2026 import CommunicationAddress2026

        resolver = CommunicationAddress2026(
            {},
            node_diag_ids=("07e0", "07e1"),
            response_canids={"07e0": "07e8"},
            suzuki_ids=("0700aa", "0708aa"),
        )
        ok, addresses = resolver.resolve(("GetCanIDsFromCANIDTable",))
        self.assertFalse(ok)
        self.assertEqual(len(addresses), 1)
        ok, addresses = resolver.resolve(("GetCanIDsFromCalibrationFileForSUZUKI",))
        self.assertTrue(ok)
        self.assertEqual(
            (addresses[0].request, addresses[0].extended), (b"\x07\0", False)
        )

    def test_location_native_offsets_and_gateway_branch(self):
        from scripts.j2534_2026 import CommunicationAddress2026

        resolver = CommunicationAddress2026({})
        ok, addresses = resolver.resolve(
            ("GetCanIDsFromLocationIDForWrite",), location_id="07e807e000000720"
        )
        self.assertTrue(ok)
        self.assertEqual(
            addresses[0].headers(),
            (bytes.fromhex("000007e0"), bytes.fromhex("000007e8")),
        )
        self.assertEqual(addresses[1].request, bytes.fromhex("0720"))
        _, addresses = resolver.resolve(
            ("GetCanIDsFromLocationIDForWrite",), location_id="07e807e000000000"
        )
        self.assertEqual(
            (addresses[1].request.hex(), addresses[1].extended), ("0740fe", True)
        )
        with self.assertRaises(ValueError):
            resolver.resolve(
                ("GetCanIDsFromLocationIDForWrite",), location_id="07e807e0"
            )


class SourceAndLifecycleTests(unittest.TestCase):
    def test_exact_native_identity_rejects_legacy_and_name_digest_swap(self):
        from scripts.j2534_2026 import (
            ADDRESS_SHA256,
            J2534_SHA256,
            NativeModuleIdentity2026,
        )

        NativeModuleIdentity2026("TCUWJ2534DeviceIF.dll", J2534_SHA256)
        NativeModuleIdentity2026("TCUWCommunicationAddress.dll", ADDRESS_SHA256)
        for name, digest in (
            ("TCUWCommunicationAddress.dll", J2534_SHA256),
            ("TCUWJ2534DeviceIF.dll", "0" * 64),
            ("legacy.dll", ADDRESS_SHA256),
        ):
            with self.assertRaises(ValueError):
                NativeModuleIdentity2026(name, digest)

    def test_sil_filters_and_can_fd_virtual_slot_argument(self):
        provider = Provider()
        device = J2534Device2026(provider, clock=lambda: 0, background_workers=False)
        device.open()
        device.connect(3)
        filters = [
            op for op, _ in provider.calls if op["operation"] == "passthru_start_filter"
        ]
        self.assertEqual([op["pattern"].data for op in filters], [b"\0", b"\x80"])
        self.assertTrue(all(op["mask"].data == b"\x80" for op in filters))
        device.disconnect()
        self.assertEqual(
            provider.operations[-4:],
            [
                "passthru_stop_filter",
                "passthru_stop_filter",
                "passthru_disconnect",
                "passthru_close",
            ],
        )
        device.open(2)
        device.connect(0x8012)
        self.assertIn((0x805E, 3), provider.calls[-1][0]["parameters"])
        self.assertEqual(provider.calls[-2][0]["flags"], 0x900)

    def test_outer_deadline_and_exhausted_normal_budget_do_not_block_cleanup(self):
        provider = Provider()
        device = J2534Device2026(provider, clock=lambda: 0, background_workers=False)
        device.open()
        device.connect(6)
        device.primitive({"operation": "control_io", "ioctl": 8}, 0.5)
        self.assertEqual(provider.calls[-1][1], 0.5)
        device.calls = 65536
        with self.assertRaises(ValueError):
            device.control_io(8)
        device.disconnect()
        self.assertIsNone(device.device_id)
        self.assertEqual(provider.calls[-1][1], 5)


class J25340500Tests(unittest.TestCase):
    def setUp(self):
        self.provider = Provider()
        self.provider.responses.update(
            {
                "passthru_scan_devices": PrimitiveResult(value=1),
                "passthru_next_device": PrimitiveResult(value="offline-fixture"),
                "passthru_connect_0500": PrimitiveResult(value=5),
                "passthru_logical_connect": PrimitiveResult(value=7),
            }
        )
        self.device = J2534Device2026(
            self.provider, clock=lambda: 0, background_workers=False
        )
        self.device.version = 1
        self.device.open()
        self.device.connect(0x800F)

    def test_discovery_open_and_connect_resource_order(self):
        self.assertEqual(
            self.provider.operations[:6],
            [
                "passthru_scan_devices",
                "passthru_next_device",
                "passthru_open",
                "passthru_ioctl",
                "passthru_ioctl",
                "passthru_connect_0500",
            ],
        )
        self.assertEqual(self.provider.calls[2][0]["name"], "J2534-2:offline-fixture")
        self.assertEqual(self.provider.calls[3][0]["resource"], (1, 1, (8,)))
        self.assertEqual(self.provider.calls[4][0]["resource"], 0x1FE)
        self.assertEqual(
            self.provider.calls[5][0]["resources"], (1, 4, (3, 11, 12, 13))
        )
        self.assertEqual(self.provider.calls[5][0]["baud"], 100000000)

    def test_logical_descriptor_routing_discovery_and_disconnect(self):
        self.device.logical_connect(0x8203)
        self.device.logical_connect(0x8205, discovery=True)
        self.assertEqual(self.provider.calls[-2][0]["descriptor"], (0x3458,))
        self.assertEqual(self.provider.calls[-1][0]["ioctl"], 8)
        self.device.logical_connect(0x8206, b"0000address")
        self.assertEqual(self.provider.calls[-1][0]["descriptor"], b"\x01\xc0X4address")
        self.assertEqual(self.device.logical[0x8208], 7)
        self.device.control_io(8)
        self.assertEqual(self.provider.calls[-1][0]["channel"], 7)
        self.device.logical_disconnect(0x8206)
        self.assertNotIn(0x8208, self.device.logical)
        self.device.logical_disconnect(0x8205, discovery=True)
        self.assertNotIn(0x8207, self.device.logical)

    def test_tcp_two_stage_read_and_address_match(self):
        from scripts.j2534_2026 import BufferRead2026

        self.device.logical[0x8208] = 9
        self.device.logical[0x8206] = 9
        self.provider.responses["passthru_queue"] = PrimitiveResult(value=1)
        replies = [
            BufferRead2026(NativeMessage(0, b"\0" * 8), 0),
            BufferRead2026(NativeMessage(0, b""), 0),
            BufferRead2026(NativeMessage(0, b"\0" * 4 + b"\0\0\0\x04"), 8),
            BufferRead2026(NativeMessage(0, b"xxxx"), 4),
            BufferRead2026(NativeMessage(0, b"\0" * 4 + b"\0\0\0\x04"), 8),
            BufferRead2026(NativeMessage(0, b"cdab"), 4),
        ]
        original = self.provider

        def provider(operation, remaining):
            if operation["operation"] == "passthru_read_buffer":
                original.calls.append((operation, remaining))
                return PrimitiveResult(value=replies.pop(0))
            return original(operation, remaining)

        self.device.provider = provider
        self.assertEqual(
            self.device.write_tcp(NativeMessage(0x8208, b"0" * 8 + b"abcd")), 1
        )
        reads = [
            op for op, _ in original.calls if op["operation"] == "passthru_read_buffer"
        ]
        self.assertEqual([op["count"] for op in reads], [8, 0, 8, 4, 8, 4])
        self.assertTrue(all(op["channel"] == 9 for op in reads))

    def test_scan_zero_and_tcp_truncated_header_are_not_success(self):
        from scripts.j2534_2026 import BufferRead2026

        self.device.disconnect()
        self.provider.responses["passthru_scan_devices"] = PrimitiveResult(value=0)
        with self.assertRaises(NativeTransportError):
            self.device.open()
        self.assertIsNone(self.device.device_id)
        self.provider.responses["passthru_scan_devices"] = PrimitiveResult(value=1)
        self.device.open()
        self.device.connect(0x800F)
        self.provider.responses["passthru_read_buffer"] = PrimitiveResult(
            value=BufferRead2026(NativeMessage(0, b"bad"), 3)
        )
        with self.assertRaises(ValueError):
            self.device.read_tcp()


class SyncPeriodicTests(unittest.TestCase):
    def test_native_raw_writes_ignore_status_and_preserve_timestamp_order(self):
        provider = Provider()
        provider.responses["create_mutex"] = PrimitiveResult(value=7)
        provider.responses["local_time_ms"] = PrimitiveResult(value=1500)
        device = J2534Device2026(provider, clock=lambda: 0, background_workers=False)
        device.open()
        device.connect(6)
        message = NativeMessage(3, b"abcd", tx_flags=0x100)
        device.start_sync_periodic((message,), 1000, 20, post_delay=50)
        provider.calls.clear()
        provider.responses["passthru_write"] = PrimitiveResult(9, 0)
        self.assertTrue(device.sync_step())
        self.assertEqual(
            provider.operations,
            [
                "local_time_ms",
                "lock",
                "passthru_write",
                "local_time_ms",
                "wait",
                "unlock",
            ],
        )
        written = provider.calls[2][0]["messages"][0]
        self.assertEqual((written.protocol_id, written.tx_flags), (6, 0x140))
        self.assertEqual(message.protocol_id, 3)
        self.assertNotIn("passthru_ioctl", provider.operations)
        device.stop_sync_periodic()
        self.assertEqual(
            provider.calls[-1][0], {"operation": "close_handle", "handle": 7}
        )
        self.assertIsNone(device.sync)

    def test_wait_and_midnight_wrap_and_no_post_delay_updates_after_unlock(self):
        provider = Provider()
        provider.responses["create_mutex"] = PrimitiveResult(value=7)
        provider.responses["local_time_ms"] = PrimitiveResult(value=200)
        device = J2534Device2026(provider, clock=lambda: 0, background_workers=False)
        device.open()
        device.connect(6)
        device.start_sync_periodic((NativeMessage(6, b"abcd"),), 1000, 20)
        self.assertFalse(device.sync_step())
        self.assertEqual(
            provider.calls[-1][0], {"operation": "wait", "milliseconds": 20}
        )
        assert device.sync is not None
        device.sync.previous = 86399000
        provider.calls.clear()
        self.assertTrue(device.sync_step())
        self.assertEqual(provider.operations[-2:], ["unlock", "local_time_ms"])
        self.assertEqual(device.sync.previous, 200)

    def test_cancel_after_mutex_acquisition_retains_cleanup(self):
        provider = Provider()
        cancelled = [False]

        def action(operation, remaining):
            if operation["operation"] == "create_mutex":
                cancelled[0] = True
                return PrimitiveResult(value=8)
            return provider(operation, remaining)

        device = J2534Device2026(
            action,
            clock=lambda: 0,
            background_workers=False,
            cancelled=lambda: cancelled[0],
        )
        device.open()
        device.connect(6)
        with self.assertRaises(InterruptedError):
            device.start_sync_periodic((NativeMessage(6, b"abcd"),), 1000, 20)
        device.disconnect()
        self.assertIn("close_handle", provider.operations)
        self.assertIsNone(device.sync)


class DriverLoaderTests(unittest.TestCase):
    def setUp(self):
        from scripts.j2534_2026 import DriverMetadata2026

        self.provider = Provider()
        self.provider.responses["load_library"] = PrimitiveResult(value=7)
        self.provider.responses["get_symbol"] = PrimitiveResult(value=9)
        self.provider.responses["passthru_read_version"] = PrimitiveResult(
            value=("firmware", "driver", "04.04")
        )
        self.device = J2534Device2026(
            self.provider, clock=lambda: 0, background_workers=False
        )
        self.device.set_driver(
            DriverMetadata2026("Offline authored driver", "fixture.dll")
        )

    def test_native_device_info_swallows_native_fault_but_preserves_copied_version_outputs(
        self,
    ):
        self.provider.responses["passthru_read_version"] = PrimitiveResult(
            9, ("partial-fw", "partial-driver", "partial-api")
        )
        previous = ("old-name", "old-fw", "old-driver", "old-api")
        self.assertEqual(
            self.device.get_device_info(previous),
            ("Offline authored driver", "partial-fw", "partial-driver", "partial-api"),
        )
        self.assertFalse(self.device.opened)
        self.assertFalse(self.device.driver_loaded)
        self.assertEqual(self.provider.operations.count("passthru_close"), 1)
        self.assertEqual(self.provider.operations.count("passthru_unload_library"), 1)
        self.device.open()
        with self.assertRaises(NativePassThruError2026) as caught:
            self.device.read_device_version()
        self.assertEqual(caught.exception.passthru_status, 9)
        self.assertEqual(
            caught.exception.versions, ("partial-fw", "partial-driver", "partial-api")
        )
        self.device.close()

    def test_native_device_info_loader_and_open_faults_retain_preceding_outputs(self):
        previous = ("old-name", "old-fw", "old-driver", "old-api")
        expected = ("Offline authored driver", "old-fw", "old-driver", "old-api")
        self.provider.responses["get_symbol"] = PrimitiveResult(value=0)
        self.assertEqual(self.device.get_device_info(previous), expected)
        self.assertNotIn("passthru_unload_library", self.provider.operations)
        self.assertNotIn("passthru_close", self.provider.operations)
        self.assertEqual(self.device.shim_handle, 7)
        self.provider.responses["get_symbol"] = PrimitiveResult(value=9)
        self.provider.responses["passthru_open"] = PrimitiveResult(status=9)
        self.provider.calls.clear()
        self.assertEqual(self.device.get_device_info(previous), expected)
        self.assertIn("passthru_unload_library", self.provider.operations)
        self.assertNotIn("passthru_close", self.provider.operations)

    def test_loader_exact_symbol_order_and_device_info_temporary_cleanup(self):
        self.assertEqual(
            self.device.get_device_info(),
            ("Offline authored driver", "firmware", "driver", "04.04"),
        )
        symbols = [
            op["name"]
            for op, _ in self.provider.calls
            if op["operation"] == "get_symbol"
        ]
        self.assertEqual(
            symbols[:6],
            [
                "PassThruOpen",
                "PassThruClose",
                "PassThruConnect",
                "PassThruDisconnect",
                "PassThruReadMsgs",
                "PassThruWriteMsgs",
            ],
        )
        self.assertEqual(symbols[-1], "ER_SetCommunicationLogModeCS")
        self.assertEqual(
            self.provider.operations[-2:], ["passthru_close", "passthru_unload_library"]
        )
        self.assertFalse(self.device.driver_loaded)
        self.assertEqual(self.device.shim_handle, 7)
        self.assertIsNone(self.device.device_id)

    def test_missing_symbol_and_load_error_preserve_resources_for_cleanup(self):
        self.provider.responses["get_symbol"] = PrimitiveResult(value=0)
        with self.assertRaises(NativeTransportError) as error:
            self.device.load_driver()
        self.assertEqual(error.exception.code, 2)
        self.assertFalse(self.device.driver_loaded)
        self.assertEqual(self.device.shim_handle, 7)
        self.assertNotIn("passthru_load_library", self.provider.operations)
        self.device.unload_shim()
        self.assertIsNone(self.device.shim_handle)

    def test_loader_0500_has_queue_and_logical_symbols_and_driver_selection(self):
        from scripts.j2534_2026 import DriverMetadata2026

        self.device.switch_version()
        self.device.set_driver(DriverMetadata2026("0500 fixture", "fixture0500.dll"))
        self.device.load_driver()
        symbols = [
            op["name"]
            for op, _ in self.provider.calls
            if op["operation"] == "get_symbol"
        ]
        self.assertEqual(
            symbols[:2], ["PassThruGetNextDevice", "PassThruScanForDevices"]
        )
        self.assertIn("PassThruQueueMsgs", symbols)
        self.assertIn("PassThruLogicalDisconnect", symbols)
        self.assertNotIn("PassThruWriteMsgs", symbols)
        self.device.switch_version()
        self.assertEqual(
            self.device.driver.dll_name if self.device.driver else None, "fixture.dll"
        )


class WirelessMetadataTests(unittest.TestCase):
    def device(self):
        from scripts.j2534_2026 import DriverMetadata2026

        provider = Provider()
        provider.responses["load_library"] = PrimitiveResult(value=7)
        provider.responses["get_symbol"] = PrimitiveResult(value=9)
        device = J2534Device2026(provider, clock=lambda: 0, background_workers=False)
        device.set_driver(DriverMetadata2026("Authored fixture", "fixture.dll"))
        return device, provider

    def test_probe_cleanup_keeps_primary_host_error_and_attempts_remaining_release(
        self,
    ):
        for method, failed_operation in (
            ("supports_can_fd", "passthru_ioctl"),
            ("get_device_info", "passthru_read_version"),
            ("is_wireless_connecting", "passthru_ioctl"),
        ):
            with self.subTest(method=method):
                device, provider = self.device()
                primary = OSError("authored primary query failure")

                def action(
                    operation,
                    remaining,
                    failed_operation=failed_operation,
                    primary=primary,
                    provider=provider,
                ):
                    name = operation["operation"]
                    if name == failed_operation:
                        raise primary
                    if name == "passthru_close":
                        raise OSError("authored close cleanup failure")
                    return provider(operation, remaining)

                device.provider = action
                with self.assertRaises(OSError) as caught:
                    if method == "is_wireless_connecting":
                        device.is_wireless_connecting(2)
                    else:
                        getattr(device, method)()
                self.assertIs(caught.exception, primary)
                self.assertTrue(
                    any("close cleanup failure" in note for note in primary.__notes__)
                )
                self.assertTrue(device.opened)
                self.assertFalse(device.driver_loaded)
                self.assertIn("passthru_unload_library", provider.operations)
                device.provider = provider
                device.clear()

    def test_dsti_symbol_host_error_survives_failed_library_cleanup_with_retained_handle(
        self,
    ):
        device, provider = self.device()
        primary = OSError("authored primary symbol failure")

        def action(operation, remaining):
            if operation["operation"] == "call_symbol":
                raise primary
            if operation["operation"] == "free_library":
                raise OSError("authored free cleanup failure")
            return provider(operation, remaining)

        device.provider = action
        with self.assertRaises(OSError) as caught:
            device.dsti_fix_interface(4)
        self.assertIs(caught.exception, primary)
        self.assertTrue(
            any("free cleanup failure" in note for note in primary.__notes__)
        )
        self.assertEqual(device.temporary_libraries, [7])
        device.provider = provider
        device.clear()
        self.assertEqual(device.temporary_libraries, [])

    def test_native_wireless_kind_opens_before_info_and_retries_through_catch(self):
        device, provider = self.device()
        device.driver_loaded = True
        provider.responses["get_symbol"] = PrimitiveResult(value=0)
        provider.responses["passthru_read_version"] = PrimitiveResult(
            value=("MongoosePro authored", "driver", "api")
        )
        self.assertEqual(device.wireless_device_kind(), 2)
        self.assertFalse(device.opened)
        self.assertNotIn("passthru_load_library", provider.operations)
        self.assertEqual(
            provider.operations[-3:],
            ["passthru_open", "passthru_read_version", "passthru_close"],
        )
        provider.calls.clear()
        attempts = [0]

        def action(operation, remaining):
            if operation["operation"] == "passthru_open":
                attempts[0] += 1
                provider.calls.append((operation, remaining))
                return (
                    PrimitiveResult(status=9)
                    if attempts[0] == 1
                    else PrimitiveResult(value=0)
                )
            return provider(operation, remaining)

        device.provider = action
        self.assertEqual(device.wireless_device_kind(), 2)
        self.assertEqual(attempts[0], 2)
        self.assertEqual(provider.operations.count("passthru_close"), 1)
        self.assertFalse(device.opened)

    def test_native_unknown_mongoose_query_fault_returns_false_with_cleanup(self):
        from scripts.programming_2026_common import NativeException2026

        device, provider = self.device()
        device.driver_loaded = True

        def action(operation, remaining):
            if operation["operation"] == "passthru_ioctl":
                raise NativeException2026("authored native query failure")
            return provider(operation, remaining)

        device.provider = action
        self.assertFalse(device.is_wireless_connecting(2))
        self.assertFalse(device.opened)
        self.assertIn("passthru_close", provider.operations)

    def test_native_wireless_probe_faults_use_catch_outputs_and_cleanup(self):
        from scripts.j2534_2026 import DeviceInfo2026

        device, provider = self.device()
        device.driver_loaded = True
        provider.responses["passthru_ioctl"] = PrimitiveResult(
            9, DeviceInfo2026(0x100, 3, 1)
        )
        self.assertTrue(device.is_wireless_connecting(2))
        self.assertFalse(device.opened)
        provider.responses["passthru_ioctl"] = PrimitiveResult(9)
        self.assertFalse(device.is_wireless_connecting(2))
        provider.responses["passthru_open"] = PrimitiveResult(9)
        self.assertFalse(device.is_wireless_connecting(1))
        self.assertEqual(device.temporary_libraries, [])
        calls = [
            op["arguments"]
            for op, _ in provider.calls
            if op["operation"] == "call_symbol"
        ]
        self.assertEqual(calls, [(0, 0), (4, 0), (0, 0)])
        device, provider = self.device()
        provider.responses["get_symbol"] = PrimitiveResult(value=0)
        self.assertFalse(device.is_wireless_connecting(1))
        self.assertNotIn("passthru_unload_library", provider.operations)
        self.assertFalse(device.driver_loaded)

    def test_native_canfd_query_fault_returns_false_but_failed_loader_propagates(self):
        from scripts.j2534_2026 import DeviceInfo2026

        device, provider = self.device()
        device.driver_loaded = True
        provider.responses["passthru_ioctl"] = PrimitiveResult(
            9, DeviceInfo2026(0x4D, 0, 1)
        )
        self.assertFalse(device.supports_can_fd())
        self.assertFalse(device.opened)
        self.assertIn("passthru_close", provider.operations)
        device, provider = self.device()
        provider.responses["get_symbol"] = PrimitiveResult(value=0)
        with self.assertRaises(NativePassThruError2026) as caught:
            device.supports_can_fd()
        self.assertEqual(caught.exception.native_error_code, 2)
        self.assertNotIn("passthru_unload_library", provider.operations)

    def test_native_canfd_open_fallback_returns_false_without_query_and_rethrows_second_fault(
        self,
    ):
        self._check_canfd_fallback(False)
        self._check_canfd_fallback(True)

    def _check_canfd_fallback(self, fail_second):
        device, provider = self.device()
        device.driver_loaded = True
        names = []

        def action(operation, remaining):
            if operation["operation"] == "passthru_open":
                names.append(operation["name"])
                provider.calls.append((operation, remaining))
                if len(names) == 1:
                    return PrimitiveResult(status=7)
                return (
                    PrimitiveResult(status=9)
                    if fail_second
                    else PrimitiveResult(value=0)
                )
            return provider(operation, remaining)

        device.provider = action
        if fail_second:
            with self.assertRaises(NativePassThruError2026) as caught:
                device.supports_can_fd()
            self.assertEqual(caught.exception.passthru_status, 9)
        else:
            self.assertFalse(device.supports_can_fd())
            self.assertIn("passthru_close", provider.operations)
        self.assertEqual(names, ["J2534-2:", None])
        self.assertNotIn("passthru_ioctl", provider.operations)
        self.assertFalse(device.opened)

    def test_dsti_symbol_detect_and_fix_sequence_and_resource_cleanup(self):
        device, provider = self.device()
        self.assertEqual(device.wireless_device_kind(), 1)
        self.assertEqual(device.temporary_libraries, [])
        device.dsti_fix_interface(4)
        calls = [
            op["arguments"]
            for op, _ in provider.calls
            if op["operation"] == "call_symbol"
        ]
        self.assertEqual(calls, [(0, 0), (4, 0)])
        self.assertEqual(provider.calls[-1][0]["operation"], "free_library")

    def test_mongoose_raw_info_supported_and_value_decide_wireless(self):
        from scripts.j2534_2026 import DeviceInfo2026

        device, provider = self.device()
        device.driver_loaded = True
        provider.responses["passthru_ioctl"] = PrimitiveResult(
            value=DeviceInfo2026(0x100, 3, 1)
        )
        self.assertTrue(device.is_wireless_connecting(2))
        self.assertIsNone(device.device_id)
        provider.responses["passthru_ioctl"] = PrimitiveResult(
            value=DeviceInfo2026(0x100, 3, 0)
        )
        self.assertFalse(device.is_wireless_connecting(2))
        provider.responses["passthru_ioctl"] = PrimitiveResult(
            value=DeviceInfo2026(0x100, 2, 1)
        )
        self.assertFalse(device.is_wireless_connecting(2))

    def test_can_fd_probe_only_closed_and_exact_supported_field(self):
        from scripts.j2534_2026 import DeviceInfo2026

        device, provider = self.device()
        device.driver_loaded = True
        provider.responses["passthru_ioctl"] = PrimitiveResult(
            value=DeviceInfo2026(0x4D, 0, 1)
        )
        self.assertTrue(device.supports_can_fd())
        self.assertIsNone(device.device_id)
        opens = [op for op, _ in provider.calls if op["operation"] == "passthru_open"]
        self.assertEqual(opens[-1]["name"], "J2534-2:")
        device.open()
        before = len(provider.calls)
        self.assertFalse(device.supports_can_fd())
        self.assertEqual(len(provider.calls), before)


class OwnershipAndSerialTests(unittest.TestCase):
    def test_ownership_zero_then_500ms_wait_and_release_order(self):
        provider = Provider()
        provider.responses["create_mutex"] = PrimitiveResult(value=7)
        waits = [258, 0]

        def action(operation, remaining):
            if operation["operation"] == "wait_handle":
                provider.calls.append((operation, remaining))
                return PrimitiveResult(value=waits.pop(0))
            return provider(operation, remaining)

        device = J2534Device2026(action, clock=lambda: 0, background_workers=False)
        device.have_ownership()
        self.assertTrue(device.ownership_acquired)
        self.assertEqual(
            [
                op["milliseconds"]
                for op, _ in provider.calls
                if op["operation"] == "wait_handle"
            ],
            [0, 500],
        )
        before = len(provider.calls)
        device.have_ownership()
        self.assertEqual(len(provider.calls), before)
        device.release_ownership()
        self.assertEqual(provider.operations[-2:], ["release_mutex", "close_handle"])
        self.assertIsNone(device.ownership_mutex)

    def test_cancel_after_wait_acquisition_still_releases_held_mutex(self):
        provider = Provider()
        provider.responses["create_mutex"] = PrimitiveResult(value=7)
        cancelled = [False]

        def action(operation, remaining):
            if operation["operation"] == "wait_handle":
                cancelled[0] = True
                return PrimitiveResult(value=0)
            return provider(operation, remaining)

        device = J2534Device2026(
            action,
            clock=lambda: 0,
            background_workers=False,
            cancelled=lambda: cancelled[0],
        )
        with self.assertRaises(InterruptedError):
            device.have_ownership()
        self.assertTrue(device.ownership_acquired)
        device.release_ownership()
        self.assertEqual(provider.operations[-2:], ["release_mutex", "close_handle"])

    def test_five_baud_and_fast_init_raw_result_contracts(self):
        provider = Provider()
        device = J2534Device2026(provider, clock=lambda: 0, background_workers=False)
        device.open()
        device.connect(3)
        provider.responses["passthru_ioctl"] = PrimitiveResult(value=b"")
        self.assertEqual(
            device.primitive({"operation": "five_baud_init", "data": b"\x33"}, 1), b""
        )
        self.assertEqual(provider.calls[-1][0]["capacity"], 256)
        returned = NativeMessage(3, b"raw", rx_status=9)
        provider.responses["passthru_ioctl"] = PrimitiveResult(value=returned)
        self.assertIs(
            device.primitive(
                {
                    "operation": "fast_init",
                    "data": b"\x81\x10\xf1\x81\x03",
                    "tx_flags": 0,
                },
                1,
            ),
            returned,
        )
        self.assertEqual(provider.calls[-1][0]["message"].protocol_id, 3)

    def test_successful_close_recorded_before_cleanup_timeout_no_double_close(self):
        provider = Provider()
        now = [0]

        def action(operation, remaining):
            if operation["operation"] == "passthru_close":
                now[0] += 6
            return provider(operation, remaining)

        device = J2534Device2026(action, clock=lambda: now[0], background_workers=False)
        device.open()
        with self.assertRaises(TimeoutError):
            device.close()
        self.assertIsNone(device.device_id)
        device.close()
        self.assertEqual(provider.operations.count("passthru_close"), 1)


class CalibrationAddressIntegrationTests(unittest.TestCase):
    @staticmethod
    def container(text):
        import struct
        import zlib

        from scripts.calibration_2026 import parse_cuw_2026

        def record(name, data):
            return (
                struct.pack(">H", len(name))
                + name
                + struct.pack(">II", len(data), zlib.crc32(data))
                + data
            )

        body = (
            record(b"attach.att", text.encode("ascii"))
            + b"\x01"
            + record(b"authored", b"data")
        )
        raw = (
            b"\0CALIBRATION\0"
            + b"\x68"
            + bytes(4)
            + struct.pack(">I", 22 + len(body))
            + body
        )
        raw = raw[:14] + struct.pack(">I", zlib.crc32(raw[18:])) + raw[18:]
        return parse_cuw_2026(raw)

    def test_real_container_metadata_address_headers_to_native_filter(self):
        from scripts.j2534_2026 import communication_addresses_from_calibration

        text = (
            "[Format]\nVersion=10\n[Vehicle]\nNumberOfCalibration=1\nByteNumberOfTransmitting=FFF\n"
            "CANIDTx_Phys_USDT=0700\nCANIDRx_Phys_USDT=0708\n"
            "CANIDTx_Func_USDT=07DF\n[CPU01]\nCPUImageName=authored\n"
        )
        resolver = communication_addresses_from_calibration(self.container(text), {})
        ok, addresses = resolver.resolve(("GetCanIDsFromCalibrationFileForSUZUKI",))
        self.assertTrue(ok)
        request, response = addresses[0].headers()
        provider = Provider()
        device = J2534Device2026(provider, clock=lambda: 0, background_workers=False)
        device.open()
        device.connect(6)
        device.start_flow_control_filter(request, response)
        operation = provider.calls[-1][0]
        self.assertEqual(operation["flow_control"].data, bytes.fromhex("00000700"))
        self.assertEqual(operation["pattern"].data, bytes.fromhex("00000708"))
        self.assertEqual(resolver.node_diag_ids, ())

    def test_cbytes_setnum_right_alignment_and_raw_table_left_alignment(self):
        from scripts.j2534_2026 import CommunicationAddress2026, separate_can_id

        self.assertEqual(separate_can_id("000007e0/000007e8").request.hex(), "07e0")
        self.assertEqual(separate_can_id("07/08").request.hex(), "0007")
        self.assertEqual(separate_can_id("07e0/0748fe").response.hex(), "48fe")
        resolver = CommunicationAddress2026(
            {}, node_diag_ids=("000007e0",), response_canids={"000007e0": "000007e8"}
        )
        _, addresses = resolver.resolve(("GetCanIDsFromCANIDTable",))
        self.assertEqual(addresses[0].request.hex(), "0000")


class AdditionalBoundaryTests(unittest.TestCase):
    def test_multiread_fault_retains_partial_count_and_unknown_fault_translation(self):
        from scripts.j2534_2026 import NativeReadError2026

        provider = Provider()
        provider.reads = [(NativeMessage(6, b"aaaa1", extra_data_index=4),)]
        calls = [0]

        def action(operation, remaining):
            if operation["operation"] == "passthru_read":
                calls[0] += 1
                if calls[0] > 1:
                    return PrimitiveResult(9)
            return provider(operation, remaining)

        device = J2534Device2026(action, clock=lambda: 0, background_workers=False)
        device.open()
        device.connect(6)
        with self.assertRaises(NativeReadError2026) as error:
            device.read_specified_many((b"aaaa", b"bbbb"))
        self.assertEqual(error.exception.code, 9)
        self.assertEqual(error.exception.returned_count, 0)
        self.assertEqual(error.exception.first_data_size, 0)
        self.assertEqual(error.exception.messages[0].extra_data_index, 4)
        self.assertEqual(
            tuple(item.data for item in error.exception.messages), (b"aaaa1",)
        )

        host_error = OSError("authored primitive failure")

        def faulty(_operation, _remaining):
            raise host_error

        device.provider = faulty
        with self.assertRaises(OSError) as host:
            device.read_specified_many((b"aaaa",))
        self.assertIs(host.exception, host_error)
        from scripts.programming_2026_common import NativeException2026

        def native_faulty(_operation, _remaining):
            raise NativeException2026("authored native unknown exception")

        device.provider = native_faulty
        with self.assertRaises(NativeReadError2026) as error:
            device.read_specified_many((b"aaaa",))
        self.assertEqual(error.exception.native_error_code, 9999)
        self.assertIsNone(error.exception.passthru_status)

    def test_address_copy_move_preserve_context_and_independent_result_vectors(self):
        import copy

        from scripts.j2534_2026 import CommunicationAddress2026, separate_can_id

        resolver = CommunicationAddress2026({"CanIDForGetCID": ("07e0/07e8",)})
        resolver.resolve(("GetCanIDsFromParamForGetCID",))
        clone = copy.copy(resolver)
        resolver.resolve(())
        self.assertEqual(len(clone.addresses), 1)
        moved = clone.move()
        self.assertEqual(clone.addresses, ())
        moved.remember(separate_can_id("07e0/07e8"))
        self.assertEqual(resolver.history_request_ids(), ("07E0",))

    def test_default_null_history_sink_and_disable_recording(self):
        from scripts.j2534_2026 import MessageHistory2026

        provider = Provider()
        device = J2534Device2026(provider, clock=lambda: 0, background_workers=False)
        device.open()
        device.connect(6)
        provider.reads = [(NativeMessage(6, b"aaaa", rx_status=9),)]
        device.write_messages((NativeMessage(6, b"aaaa1"),))
        self.assertIsNone(device.last_message)
        sink = MessageHistory2026()
        device.set_history_sink(sink)
        provider.reads = [(NativeMessage(6, b"aaaa", rx_status=9),)]
        device.write_messages((NativeMessage(6, b"aaaa2"),))
        self.assertEqual(sink.value, (4, b"aaaa2"))
        device.last_enabled = False
        provider.reads = [(NativeMessage(6, b"aaaa", rx_status=9),)]
        device.write_messages((NativeMessage(6, b"aaaa3"),))
        self.assertEqual(sink.value, (4, b"aaaa2"))

    def test_connected_protocol_query_and_send_timeout_boundary(self):
        device = J2534Device2026(Provider(), clock=lambda: 0, background_workers=False)
        with self.assertRaises(ValueError):
            device.primitive({"operation": "get_protocol_id"}, 1)
        device.primitive({"operation": "connect", "protocol": 6}, 1)
        self.assertEqual(device.primitive({"operation": "get_protocol_id"}, 1), 6)
        device.primitive({"operation": "set_send_timeout", "milliseconds": 500}, 1)
        self.assertEqual(device.primitive({"operation": "get_send_timeout"}, 1), 500)
        with self.assertRaises(ValueError):
            device.primitive({"operation": "set_send_timeout", "milliseconds": -1}, 1)


class PeriodicConsumerIntegrationTests(unittest.TestCase):
    def test_dh_actual_phase5_consumer_start_pump_and_runtime_cleanup(self):
        from scripts.programming_2026_dh import start_sync_periodic_phase5

        provider = Provider()
        provider.responses["create_mutex"] = PrimitiveResult(value=7)
        provider.responses["local_time_ms"] = PrimitiveResult(value=1000)
        device = J2534Device2026(provider, clock=lambda: 0, background_workers=False)
        device.open()
        device.connect(6)
        runtime = NativeRuntime2026(device.primitive, clock=lambda: 0)
        runtime.call("set_local_time_to_previous_send_time")
        start_sync_periodic_phase5(runtime, 2)
        self.assertTrue(runtime.call("is_sending_sync_periodic"))
        assert device.sync is not None
        self.assertEqual(device.sync.previous, 1000)
        self.assertEqual(len(device.sync.messages), 4)
        provider.responses["local_time_ms"] = PrimitiveResult(value=2999)
        self.assertFalse(device.sync_step())
        provider.responses["local_time_ms"] = PrimitiveResult(value=3000)
        self.assertTrue(device.sync_step())
        writes = [
            operation
            for operation, _ in provider.calls
            if operation["operation"] == "passthru_write"
        ]
        self.assertEqual(len(writes), 4)
        self.assertEqual(writes[-1]["messages"][0].data, bytes.fromhex("000007863e01"))
        self.assertEqual(runtime.close(), [])
        self.assertFalse(runtime.call("is_sending_sync_periodic"))
        start_sync_periodic_phase5(runtime, 0)
        assert device.sync is not None
        self.assertEqual(device.sync.previous, 3000)
        runtime.close()

    def test_sync_filter_lock_released_if_cancelled_after_lock_acquired(self):
        provider = Provider()
        provider.responses["create_mutex"] = PrimitiveResult(value=7)
        cancelled = [False]

        def action(operation, remaining):
            if operation["operation"] == "lock":
                cancelled[0] = True
            return provider(operation, remaining)

        device = J2534Device2026(
            action,
            clock=lambda: 0,
            background_workers=False,
            cancelled=lambda: cancelled[0],
        )
        device.open()
        device.connect(6)
        device.start_sync_periodic((NativeMessage(6, b"aaaa"),), 1000, 20)
        with self.assertRaises(InterruptedError):
            device.start_flow_control_filter(b"aaaa", b"bbbb")
        self.assertEqual(provider.operations[-2:], ["lock", "unlock"])
        device.disconnect()


class NativeMetadataUtilityTests(unittest.TestCase):
    def test_0500_initializer_retains_or_replaces_buffer_and_clears_all_seven_fields(
        self,
    ):
        from scripts.j2534_2026 import MessageBuffer0500, init_passthru_message_0500

        previous = MessageBuffer0500(tuple(range(7)), b"nonzero")
        result = init_passthru_message_0500(previous)
        self.assertEqual(result.header, (0,) * 7)
        self.assertEqual(result.data, bytes(7))
        self.assertEqual(previous.data, b"nonzero")
        self.assertEqual(
            init_passthru_message_0500(previous, b"123456789", 4).data, bytes(4)
        )
        with self.assertRaises(ValueError):
            init_passthru_message_0500(previous, b"short")

    def test_readmsgs_native_discards_one_indication_before_wrapped_read(self):
        provider = Provider()
        device = J2534Device2026(provider, clock=lambda: 0, background_workers=False)
        device.open()
        device.connect(6)
        provider.reads = [
            (NativeMessage(6, b"indication", rx_status=9),),
            (NativeMessage(6, b"payload"),),
        ]
        self.assertEqual(device.read_after_indication()[0].data, b"payload")

    def test_log_mode_signed_raw_result_and_log_error_code(self):
        provider = Provider()
        provider.responses["set_communication_log_mode"] = PrimitiveResult(value=-1)
        device = J2534Device2026(provider, clock=lambda: 0, background_workers=False)
        self.assertEqual(device.set_communication_log_mode(-1), -1)
        provider.responses["passthru_save_log"] = PrimitiveResult(9)
        with self.assertRaises(NativeTransportError) as error:
            device.output_shim_log("authored.log")
        self.assertEqual(error.exception.code, 9)


class LiveOSProvider(Provider):
    """Real thread-owned mutexes/Sleep; all transport remains authored in-memory."""

    def __init__(self):
        import threading

        super().__init__()
        self.mutexes = {}
        self.handles = {}
        self.next_handle = 10
        self.guard = threading.Lock()
        self.transmitted = threading.Event()
        self.completed_batch = threading.Event()
        self.ownership_threads = []
        self.write_count = 0
        self.fail_write = False

    def __call__(self, operation, remaining):
        import threading
        import time

        name = operation["operation"]
        with self.guard:
            self.calls.append((dict(operation), remaining))
        if name in self.responses:
            return self.responses[name]
        if name == "create_mutex":
            with self.guard:
                mutex = self.mutexes.setdefault(operation["name"], threading.RLock())
                handle = self.next_handle
                self.next_handle += 1
                self.handles[handle] = mutex
            return PrimitiveResult(value=handle)
        if name == "wait_handle":
            acquired = self.handles[operation["handle"]].acquire(
                timeout=operation["milliseconds"] / 1000
            )
            if acquired:
                self.ownership_threads.append(("acquire", threading.get_ident()))
            return PrimitiveResult(value=0 if acquired else 258)
        if name == "release_mutex":
            self.ownership_threads.append(("release", threading.get_ident()))
            self.handles[operation["handle"]].release()
            return PrimitiveResult()
        if name == "lock":
            if not self.handles[operation["mutex"]].acquire(timeout=remaining):
                raise TimeoutError("Authored OS mutex timeout")
            return PrimitiveResult()
        if name == "unlock":
            self.handles[operation["mutex"]].release()
            return PrimitiveResult()
        if name == "close_handle":
            del self.handles[operation["handle"]]
            return PrimitiveResult()
        if name == "wait":
            time.sleep(min(operation["milliseconds"] / 1000, remaining))
            return PrimitiveResult()
        if name == "local_time_ms":
            current = time.localtime()
            return PrimitiveResult(
                value=((current.tm_hour * 60 + current.tm_min) * 60 + current.tm_sec)
                * 1000
                + int(time.time() * 1000) % 1000
            )
        if name == "passthru_write":
            with self.guard:
                self.write_count += 1
                if self.write_count >= 4:
                    self.completed_batch.set()
            self.transmitted.set()
            if self.fail_write:
                raise OSError("Authored low-level write failure")
            return PrimitiveResult(value=operation["count"])
        if name in ("load_library", "get_symbol"):
            return PrimitiveResult(value=7)
        if name in ("passthru_open", "passthru_connect", "passthru_start_filter"):
            return PrimitiveResult(value=1)
        return PrimitiveResult()


class ActualThreadAndTransferTests(unittest.TestCase):
    def test_udp_discovery_wrapper_uses_zero_timeout_and_queue_result_is_bounded(self):
        from scripts.j2534_2026 import BufferRead2026

        provider = Provider()
        device = J2534Device2026(provider, background_workers=False)
        device.open()
        device.connect(6)
        device.set_version(1)
        device.timeout = 987
        device.logical[0x8207] = 23
        provider.responses["passthru_read_buffer"] = PrimitiveResult(
            value=BufferRead2026(NativeMessage(0x8207, b"abcd"), 4)
        )
        self.assertEqual(device.read_buffer(0x8207, 8).count, 4)
        self.assertEqual(
            (provider.calls[-1][0]["channel"], provider.calls[-1][0]["timeout"]),
            (23, 0),
        )
        provider.responses["passthru_queue"] = PrimitiveResult(value=0)
        self.assertEqual(device.queue_message(NativeMessage(0x8205, b"abcd")), 0)
        provider.responses["passthru_queue"] = PrimitiveResult(value=2)
        with self.assertRaises(ValueError):
            device.queue_message(NativeMessage(0x8205, b"abcd"))
        with self.assertRaises(ValueError):
            device.queue_message(NativeMessage(0x8205, b"abcd"), 2)
        device.disconnect()

    def test_sync_guard_retains_primary_filter_fault_when_unlock_also_fails(self):
        provider = LiveOSProvider()
        device = J2534Device2026(provider, background_workers=False)
        device.open()
        device.connect(6)
        device.start_sync_periodic((NativeMessage(6, b"aaaa"),), 1000, 20)
        provider.responses["passthru_start_filter"] = PrimitiveResult(status=8)
        provider.responses["unlock"] = PrimitiveResult(status=9)
        with self.assertRaises(NativeTransportError) as caught:
            device.start_flow_control_filter(b"aaaa", b"bbbb")
        self.assertEqual(caught.exception.code, 8)
        self.assertTrue(
            any("mutex release failed" in note for note in caught.exception.__notes__)
        )
        self.assertEqual(device.filters, [])
        self.assertIsNotNone(device.sync)
        del provider.responses["unlock"]
        device.cleanup_primitive({"operation": "unlock"}, 5)
        device.disconnect()
        self.assertEqual(provider.handles, {})

    def test_routine_paired_unlocks_preserve_shutdown_budget_and_failed_retry_is_bounded(
        self,
    ):
        provider = LiveOSProvider()
        device = J2534Device2026(
            provider, background_workers=False, max_calls=4096, max_cleanup_calls=8
        )
        device.open()
        device.connect(6)
        device.start_sync_periodic((NativeMessage(6, b"aaaa"),), 1000, 20)
        runtime = NativeRuntime2026(device.primitive, max_calls=4096)
        for _ in range(1050):
            runtime.call("lock")
            runtime.call("unlock", cleanup=True)
        self.assertEqual(device.routine_release_calls, 1050)
        self.assertEqual(device.cleanup_calls, 0)
        runtime.call("lock")
        provider.responses["unlock"] = PrimitiveResult(status=9)
        with self.assertRaises(NativeTransportError):
            runtime.call("unlock", cleanup=True)
        self.assertEqual(device.routine_release_calls, 1051)
        self.assertEqual(device.cleanup_calls, 0)
        del provider.responses["unlock"]
        runtime.call("unlock", cleanup=True)
        self.assertEqual(device.cleanup_calls, 1)
        device.disconnect()
        self.assertIsNone(device.sync)
        self.assertEqual(provider.handles, {})
        self.assertLessEqual(device.cleanup_calls, 8)

    def test_call_budgets_require_positive_uint32_values(self):
        for value in (0, -1, True, 0x100000000):
            for key in ("max_calls", "max_cleanup_calls"):
                with (
                    self.subTest(key=key, value=value),
                    self.assertRaises((TypeError, ValueError)),
                ):
                    J2534Device2026(Provider(), **{key: value})  # pyright: ignore[reportArgumentType]

    def test_cleanup_switch_restores_ethernet_after_cancel_using_classic_native_slot(
        self,
    ):
        provider = Provider()
        cancelled = [False]
        device = J2534Device2026(
            provider, cancelled=lambda: cancelled[0], background_workers=False
        )
        device.set_version(1)
        provider.responses["passthru_scan_devices"] = PrimitiveResult(value=1)
        provider.responses["passthru_next_device"] = PrimitiveResult(value="authored")
        provider.responses["passthru_connect_0500"] = PrimitiveResult(value=0)
        device.open()
        device.connect(0x800F)
        device.switch_connection(6)
        cancelled[0] = True
        device.cleanup_primitive(
            {"operation": "switch_connection", "protocol": 0x800F}, 5
        )
        self.assertTrue(device.connecting)
        self.assertEqual(device.protocol_id, 0x800F)
        call = [
            op for op, _ in provider.calls if op["operation"] == "passthru_connect"
        ][-1]
        self.assertEqual(
            (call["protocol"], call["flags"], call["baud"]), (0x800F, 0, 0)
        )
        device.cleanup_primitive({"operation": "disconnect"}, 5)

    def test_native_direct0500_resource_and_unacquired_logical_disconnect_use_raw_zero(
        self,
    ):
        provider = Provider()
        device = J2534Device2026(provider, background_workers=False)
        device.set_version(1)
        device.control_io_0500(3, resource=8)
        self.assertEqual(provider.calls[-1][0]["resource"], (1, 1, (8,)))
        self.assertEqual(provider.calls[-1][0]["channel"], 0)
        device.logical_disconnect(0x8206)
        self.assertEqual(
            provider.calls[-1][0],
            {"operation": "passthru_logical_disconnect", "channel": 0},
        )
        provider.responses["passthru_logical_disconnect"] = PrimitiveResult(status=8)
        with self.assertRaises(NativePassThruError2026) as caught:
            device.logical_disconnect(0x8203)
        self.assertEqual(caught.exception.passthru_status, 8)
        self.assertEqual(device.logical, {})
        with self.assertRaises(ValueError):
            device.logical_disconnect(0x8208)

    def test_native_switch_preserves_history_and_current_driver_setter_does_not_mutate_versions(
        self,
    ):
        from scripts.j2534_2026 import DriverMetadata2026, MessageHistory2026

        provider = Provider()
        device = J2534Device2026(provider, background_workers=False)
        sink = MessageHistory2026()
        device.set_history_sink(sink)
        device.open()
        device.connect(6)
        device.last_enabled, sink.value = False, (4, b"preceding")
        device.switch_connection(5)
        self.assertFalse(device.last_enabled)
        self.assertEqual(sink.value, (4, b"preceding"))
        device.disconnect()
        current = DriverMetadata2026("current", "current.dll")
        device.set_current_driver(current)
        current.clear()
        self.assertEqual(device.get_dll_name(), "current.dll")
        self.assertEqual(
            tuple(record.dll_name for record in device.export_data().drivers), ("", "")
        )
        device.driver_versions[1].set_dll_name("selected.dll")
        device.switch_version()
        device.driver_versions[1].clear()
        self.assertEqual(device.get_dll_name(), "selected.dll")
        device.clear()
        self.assertEqual(
            tuple(record.dll_name for record in device.export_data().drivers), ("", "")
        )

    def test_native_direct_connect0500_does_not_acquire_ownership_or_reset_history(
        self,
    ):
        from scripts.j2534_2026 import DriverMetadata2026, MessageHistory2026

        provider = LiveOSProvider()
        provider.responses["passthru_scan_devices"] = PrimitiveResult(value=1)
        provider.responses["passthru_next_device"] = PrimitiveResult(value="authored")
        provider.responses["passthru_connect_0500"] = PrimitiveResult(value=2)
        device = J2534Device2026(provider)
        device.set_version(1)
        device.set_current_driver(DriverMetadata2026("authored", "offline.dll"))
        sink = MessageHistory2026((4, b"preceding"))
        device.set_history_sink(sink)
        device.last_enabled = False
        try:
            device.connect_0500(0x800F)
            self.assertTrue(device.connecting)
            self.assertIsNone(device.ownership_thread)
            self.assertFalse(device.last_enabled)
            self.assertEqual(sink.value, (4, b"preceding"))
            self.assertFalse(
                any(op["operation"] == "create_mutex" for op, _ in provider.calls)
            )
        finally:
            device.clear()
        self.assertEqual(provider.handles, {})

    def test_native_tx_indication_fault_does_not_undo_successful_write(self):
        provider = Provider()
        device = J2534Device2026(provider, background_workers=False)
        device.open()
        device.connect(6)
        provider.responses["passthru_read"] = PrimitiveResult(status=9)
        self.assertEqual(device.write_messages((NativeMessage(6, b"aaaa1"),)), 1)
        provider.responses["passthru_write"] = PrimitiveResult(status=7)
        with self.assertRaises(NativePassThruError2026) as caught:
            device.write_messages((NativeMessage(6, b"aaaa1"),))
        self.assertEqual(caught.exception.passthru_status, 7)

    def test_native_0500_periodic_frame_fault_is_skipped_without_skipping_next_frame(
        self,
    ):
        provider = Provider()
        provider.responses["local_time_ms"] = PrimitiveResult(value=1000)
        provider.responses["create_mutex"] = PrimitiveResult(value=7)
        queues = []

        def action(operation, remaining):
            if operation["operation"] == "passthru_queue":
                queues.append(operation["message"].data)
                if len(queues) == 1:
                    return PrimitiveResult(status=9)
                return PrimitiveResult(value=1)
            return provider(operation, remaining)

        device = J2534Device2026(action, background_workers=False)
        device.set_version(1)
        device.opened, device.connecting = True, True
        device.device_id, device.channel_id, device.protocol_id = 1, 2, 0x800F
        device.start_sync_periodic(
            (NativeMessage(0x800F, b"first"), NativeMessage(0x800F, b"second")), 0, 10
        )
        self.assertTrue(device.sync_step())
        self.assertEqual(queues, [b"first", b"second"])
        self.assertIsNone(device.sync_error)
        self.assertEqual(device.previous_send_time, 1000)
        device.stop_sync_periodic()
        self.assertIsNone(device.sync)

    def test_native_canfd_configuration_fallback_fully_reconnects_once(self):
        self._check_canfd_configuration_fallback(False, False)
        self._check_canfd_configuration_fallback(True, False)
        self._check_canfd_configuration_fallback(False, True)
        self._check_canfd_configuration_fallback(False, False, version=1)

    def _check_canfd_configuration_fallback(self, fail_fallback, switching, version=0):
        from scripts.j2534_2026 import DriverMetadata2026

        provider = LiveOSProvider()
        provider.responses["passthru_scan_devices"] = PrimitiveResult(value=1)
        provider.responses["passthru_next_device"] = PrimitiveResult(value="authored")
        provider.responses["passthru_connect_0500"] = PrimitiveResult(value=2)
        configurations = []

        def action(operation, remaining):
            result = provider(operation, remaining)
            if (
                operation["operation"] == "passthru_ioctl"
                and operation.get("ioctl") == 2
            ):
                parameters = operation.get("parameters", ())
                if parameters and parameters[0][0] == 0x805C:
                    configurations.append(parameters)
                    if len(configurations) == 1:
                        return PrimitiveResult(status=7)
                    if fail_fallback:
                        return PrimitiveResult(status=9)
            return result

        device = J2534Device2026(action)
        device.set_version(version)
        device.set_driver(DriverMetadata2026("authored", "offline.dll"))
        try:
            if switching:
                device.connect_native(6)
                provider.calls.clear()
                device.switch_connection(0x8012)
            elif fail_fallback:
                with self.assertRaises(NativePassThruError2026) as caught:
                    device.connect_native(0x8012)
                self.assertEqual(caught.exception.passthru_status, 9)
            else:
                device.connect_native(0x8012)
            self.assertEqual(len(configurations), 2)
            self.assertIn((0x805E, 3), configurations[0])
            self.assertNotIn((0x805E, 3), configurations[1])
            self.assertTrue(device.connecting)
            self.assertEqual(device.protocol_id, 0x8012)
            names = [op["operation"] for op, _ in provider.calls]
            self.assertEqual(
                names.count("passthru_connect_0500" if version else "passthru_connect"),
                2,
            )
            self.assertEqual(names.count("passthru_disconnect"), 2 if switching else 1)
            self.assertEqual(names.count("passthru_close"), 1)
            self.assertEqual(names.count("passthru_unload_library"), 1)
            self.assertEqual(names.count("release_mutex"), 1)
        finally:
            device.clear()
        self.assertEqual(provider.handles, {})

    def test_native_sil_indication_single_shot_zero_count_and_two_read_eh(self):
        provider = Provider()
        device = J2534Device2026(provider, background_workers=False)
        device.open()
        device.connect(3)
        provider.calls.clear()
        self.assertEqual(device.read_indication(), 3)
        self.assertEqual(provider.operations, ["passthru_read"])
        provider.calls.clear()
        runtime = NativeRuntime2026(device.primitive)
        self.assertEqual(runtime.call("read_messages", count=1), b"")
        self.assertEqual(provider.operations, ["passthru_read"])
        provider.calls.clear()
        provider.reads = [(), (NativeMessage(3, b"second"),)]
        self.assertEqual(runtime.call("read_after_indication", count=1), b"second")
        self.assertEqual(provider.operations, ["passthru_read", "passthru_read"])
        provider.calls.clear()
        reads = [0]

        def first_error(operation, remaining):
            if operation["operation"] == "passthru_read":
                reads[0] += 1
                if reads[0] == 1:
                    return PrimitiveResult(status=7)
                return PrimitiveResult(value=(NativeMessage(3, b"native-second"),))
            return provider(operation, remaining)

        device.provider = first_error
        self.assertEqual(
            runtime.call("read_after_indication", count=1), b"native-second"
        )
        self.assertEqual(reads[0], 2)

        def host_failure(operation, remaining):
            if operation["operation"] == "passthru_read":
                reads[0] += 1
                raise OSError("Authored provider failure")
            return provider(operation, remaining)

        device.provider = host_failure
        reads[0] = 0
        with self.assertRaises(OSError):
            runtime.call("read_after_indication", count=1)
        self.assertEqual(reads[0], 1)
        cancelled = [False]

        def cancel_after_first(operation, remaining):
            if operation["operation"] == "passthru_read":
                reads[0] += 1
                cancelled[0] = True
                return PrimitiveResult(value=())
            return provider(operation, remaining)

        device.cancelled = lambda: cancelled[0]
        device.provider = cancel_after_first
        reads[0] = 0
        with self.assertRaises(InterruptedError):
            runtime.call("read_after_indication", count=1)
        self.assertEqual(reads[0], 1)

    def test_native_explicit_open_flag_retains_literal_zero_device_id(self):
        provider = Provider()
        device = J2534Device2026(provider, background_workers=False)
        device.set_version(1)
        device.set_padding(False)
        device.set_opened(True)
        self.assertEqual(device.export_data().device_id, 0)
        device.close()
        self.assertEqual(
            provider.calls[-1][0], {"operation": "passthru_close", "device": 0}
        )
        self.assertFalse(device.opened)
        with self.assertRaises(TypeError):
            device.set_opened(1)  # type: ignore[arg-type]

    def test_terminated_ownership_slot_survives_release_and_clear_like_native_export(
        self,
    ):
        provider = LiveOSProvider()
        provider.responses["wait_handle"] = PrimitiveResult(value=258)
        device = J2534Device2026(provider)
        with self.assertRaises(NativeTransportError):
            device.have_ownership()
        stale = device.ownership_thread
        self.assertIsNotNone(stale)
        self.assertFalse(stale.is_alive() if stale is not None else True)
        device.release_ownership()
        self.assertIsNone(device.ownership_thread)
        self.assertIs(device.export_data().ownership_thread, stale)
        device.clear()
        self.assertIs(device.export_data().ownership_thread, stale)
        self.assertIsNone(device.export_data().ownership_release)
        provider.responses.pop("wait_handle")
        device.have_ownership()
        replacement = device.ownership_thread
        self.assertIsNot(replacement, stale)
        device.release_ownership()
        self.assertIsNone(device.export_data().ownership_thread)
        self.assertEqual(provider.handles, {})
        device.clear()

    def test_consumer_local_time_and_history_restoration_primitives(self):
        from scripts.j2534_2026 import MessageHistory2026

        cancelled = [False]
        provider = Provider()
        provider.responses["local_time_ms"] = PrimitiveResult(value=86399999)
        device = J2534Device2026(
            provider, cancelled=lambda: cancelled[0], background_workers=False
        )
        sink = MessageHistory2026((4, b"preceding"))
        device.set_history_sink(sink)
        runtime = NativeRuntime2026(device.primitive)
        self.assertEqual(runtime.call("local_time_ms"), 86399999)
        system_time = (2026, 10, 2, 20, 18, 42, 1, 999)
        provider.responses["get_system_time"] = PrimitiveResult(value=system_time)
        self.assertEqual(runtime.call("get_system_time"), system_time)
        provider.responses["get_system_time"] = PrimitiveResult(value=system_time[:-1])
        with self.assertRaises(ValueError):
            runtime.call("get_system_time")
        provider.responses["local_time_ms"] = PrimitiveResult(value=86400000)
        with self.assertRaises(ValueError):
            runtime.call("local_time_ms")
        cancelled[0] = True
        before = len(provider.calls)
        runtime.call("set_history_enabled", enabled=False, cleanup=True)
        self.assertFalse(device.last_enabled)
        runtime.call("set_history_enabled", enabled=True, cleanup=True)
        self.assertTrue(device.last_enabled)
        self.assertEqual(sink.value, (4, b"preceding"))
        self.assertEqual(len(provider.calls), before)
        with self.assertRaises(TypeError):
            runtime.call("set_history_enabled", enabled=1, cleanup=True)

    def test_switch_disconnect_late_success_forgets_ownership_but_exports_native_id(
        self,
    ):
        now = [0.0]
        base = Provider()
        base.responses["passthru_connect"] = PrimitiveResult(value=77)

        def provider(operation, remaining):
            result = base(operation, remaining)
            if operation["operation"] == "passthru_disconnect":
                now[0] = 31
            return result

        device = J2534Device2026(
            provider, clock=lambda: now[0], background_workers=False
        )
        device.open()
        device.connect(6)
        with self.assertRaises(TimeoutError):
            device.switch_connection(5)
        self.assertFalse(device.connecting)
        self.assertIsNone(device.channel_id)
        self.assertEqual(device.protocol_id, 0)
        snapshot = device.export_data()
        self.assertEqual(snapshot.channel_id, 77)
        device.disconnect()
        self.assertEqual(base.operations.count("passthru_disconnect"), 1)
        device.clear()
        self.assertEqual(device.export_data().channel_id, 0)

    def test_actual_candiag_filter_postcancel_and_deadline_roll_back_only_fresh_id(
        self,
    ):
        for late in ("cancel", "deadline", "failed-stop"):
            with self.subTest(late=late):
                self._check_filter_rollback(late)

    def _check_filter_rollback(self, late):
        cancelled, now = [False], [0.0]
        base = Provider()

        def provider(operation, remaining):
            if operation["operation"] == "passthru_start_filter":
                base.calls.append((operation, remaining))
                if late == "deadline":
                    now[0] = 31
                else:
                    cancelled[0] = True
                return PrimitiveResult(value=32)
            if (
                late == "failed-stop"
                and operation["operation"] == "passthru_stop_filter"
            ):
                base.calls.append((operation, remaining))
                return PrimitiveResult(status=9)
            return base(operation, remaining)

        device = J2534Device2026(
            provider,
            clock=lambda: now[0],
            cancelled=lambda: cancelled[0],
            background_workers=False,
        )
        device.open()
        device.connect(6)
        device.filters[:] = [30, 31]
        runtime = NativeRuntime2026(
            device.primitive,
            clock=lambda: now[0],
            cancelled=lambda: cancelled[0],
        )
        expected = TimeoutError if late == "deadline" else InterruptedError
        with self.assertRaises(expected) as caught:
            CanDiag2026(runtime).start_filter(b"abcd", b"efgh")
        runtime.close()
        self.assertEqual(
            device.filters, [30, 31, 32] if late == "failed-stop" else [30, 31]
        )
        stops = [
            op["identifier"]
            for op, _ in base.calls
            if op["operation"] == "passthru_stop_filter"
        ]
        self.assertEqual(stops, [32])
        self.assertTrue(device.connecting)
        if late == "failed-stop":
            self.assertIn(
                "device-owned", str(getattr(caught.exception, "__notes__", []))
            )

    def test_native_exception_primary_enum_remains_separate_from_j2534_status(self):
        provider = Provider()
        device = J2534Device2026(provider, background_workers=False)
        device.open()
        device.connect(6)
        provider.responses["passthru_ioctl"] = PrimitiveResult(status=16)
        with self.assertRaises(NativeTransportError) as caught:
            device.control_io(8)
        self.assertEqual(caught.exception.code, 16)
        assert isinstance(caught.exception, NativePassThruError2026)
        self.assertEqual(caught.exception.native_error_code, 1)
        self.assertEqual(caught.exception.passthru_status, 16)
        provider.responses.pop("passthru_ioctl")
        provider.responses["passthru_read"] = PrimitiveResult(status=9)
        with self.assertRaises(NativeTransportError) as caught:
            device.read_specified_many((b"abcd",))
        assert isinstance(caught.exception, NativePassThruError2026)
        self.assertEqual(caught.exception.native_error_code, 1)
        self.assertEqual(caught.exception.passthru_status, 9)
        self.assertEqual(getattr(caught.exception, "returned_count", -1), 0)
        self.assertEqual(getattr(caught.exception, "first_data_size", -1), 0)
        with self.assertRaises(NativePassThruError2026) as single:
            device.read_specified(b"abcd")
        self.assertEqual(getattr(single.exception, "returned_count", -1), 0)
        self.assertEqual(getattr(single.exception, "first_data_size", -1), 0)
        self.assertEqual(single.exception.passthru_status, 9)
        provider.responses["create_mutex"] = PrimitiveResult(value=0)
        with self.assertRaises(NativeTransportError) as caught:
            device.have_ownership()
        assert isinstance(caught.exception, NativePassThruError2026)
        self.assertEqual(caught.exception.native_error_code, 2)
        self.assertIsNone(caught.exception.passthru_status)

    def test_switch_version_reconnect_uses_native_full_load_and_ownership_path(self):
        from scripts.j2534_2026 import DriverMetadata2026

        provider = LiveOSProvider()
        provider.responses["passthru_scan_devices"] = PrimitiveResult(value=1)
        provider.responses["passthru_next_device"] = PrimitiveResult(value="authored")
        provider.responses["passthru_connect_0500"] = PrimitiveResult(value=2)
        device = J2534Device2026(provider)
        device.set_driver(DriverMetadata2026("0404", "offline0404.dll"))
        device.driver_versions[1] = DriverMetadata2026("0500", "offline0500.dll")
        device.open()
        device.connect(6)
        try:
            device.primitive(
                {"operation": "switch_connection_with_version", "protocol": 0x800F}, 30
            )
            self.assertEqual((device.protocol_id, device.version), (0x800F, 1))
            self.assertTrue(device.driver_loaded)
            self.assertIsNotNone(device.ownership_thread)
            names = [entry[0]["operation"] for entry in provider.calls]
            self.assertLess(
                names.index("create_mutex"), names.index("passthru_load_library")
            )
            loaded = [
                op["name"]
                for op, _ in provider.calls
                if op["operation"] == "passthru_load_library"
            ]
            self.assertEqual(loaded, ["offline0500.dll"])
        finally:
            device.clear()
        self.assertEqual(provider.handles, {})

    def test_native_driver_descriptor_assignment_empty_clear_and_selection_copy(self):
        import copy

        from scripts.j2534_2026 import DriverMetadata2026

        descriptor = DriverMetadata2026()
        self.assertEqual((descriptor.device_name, descriptor.dll_name), ("", ""))
        descriptor.set_device_name("authored")
        descriptor.set_dll_name("offline.dll")
        destination = DriverMetadata2026().assign(descriptor)
        device = J2534Device2026(Provider(), background_workers=False)
        device.set_driver(descriptor)
        descriptor.clear()
        self.assertEqual(destination.dll_name, "offline.dll")
        self.assertEqual(device.get_dll_name(), "offline.dll")
        with self.assertRaises(TypeError):
            copy.copy(destination)
        with self.assertRaises(ValueError):
            destination.set_dll_name("invalid\0.dll")
        self.assertEqual(destination.dll_name, "offline.dll")

    def test_actual_ownership_contention_and_manual_reset_events(self):
        from scripts.j2534_2026 import ManualResetEvent2026

        provider = LiveOSProvider()
        first, second = J2534Device2026(provider), J2534Device2026(provider)
        first.have_ownership()
        try:
            with self.assertRaises(NativeTransportError) as caught:
                second.have_ownership()
            self.assertEqual(caught.exception.code, 2)
            self.assertTrue(first.ownership_acquired)
            self.assertEqual(len(provider.handles), 1)
        finally:
            second.release_ownership()
            first.release_ownership()
        self.assertEqual(provider.handles, {})
        event = ManualResetEvent2026()
        self.assertFalse(event.wait(0))
        event.set()
        self.assertTrue(event.wait(0))
        self.assertTrue(event.wait(0))
        event.clear()
        self.assertFalse(event.wait(0))
        event.close()
        with self.assertRaises(ValueError):
            event.set()

    def test_sil_transfer_copies_only_native_count_and_preserves_out_slots(self):
        from scripts.j2534_2026 import DriverMetadata2026

        device = J2534Device2026(Provider(), background_workers=False)
        device.set_driver(DriverMetadata2026("device", "driver"))
        device.sil_filter_ids = [11, 12]
        device.sil_filter_active = [True, True]
        preceding = device.export_data()
        device.sil_filter_count = 1
        device.sil_filter_ids[0] = 13
        snapshot = device.export_data(preceding)
        self.assertEqual(snapshot.sil_ids, (13, 12))
        receiver = J2534Device2026(Provider(), background_workers=False)
        receiver.import_data(snapshot)
        self.assertEqual(receiver.sil_filter_ids, [13, 0])
        self.assertEqual(receiver.filters, [13])
        device.sil_filter_count = 0
        device.driver = None
        empty = device.export_data(snapshot)
        self.assertEqual(empty.driver, snapshot.driver)
        self.assertEqual(empty.sil_ids, snapshot.sil_ids)
        receiver = J2534Device2026(Provider(), background_workers=False)
        receiver.import_data(empty)
        self.assertEqual(receiver.filters, [])

    def test_actual_runtime_cleanup_ignores_cancel_with_exact_native_dictionary(self):
        cancelled = [False]
        provider = Provider()
        device = J2534Device2026(
            provider, cancelled=lambda: cancelled[0], background_workers=False
        )
        device.open()
        device.connect(6)
        runtime = NativeRuntime2026(device.primitive, cancelled=lambda: cancelled[0])
        cancelled[0] = True
        with self.assertRaises(InterruptedError):
            runtime.call("control_io", ioctl=2, parameters=((1, 500000),))
        runtime.call("control_io", cleanup=True, ioctl=2, parameters=((1, 10400),))
        self.assertEqual(
            provider.calls[-1][0],
            {
                "operation": "passthru_ioctl",
                "channel": device.channel_id,
                "ioctl": 2,
                "parameters": ((1, 10400),),
                "protocol": None,
            },
        )
        with self.assertRaises(ValueError):
            device.cleanup_primitive(
                {"operation": "write_messages", "data": b"abcd"}, 1
            )
        with self.assertRaises(InterruptedError):
            device.primitive({"operation": "control_io", "ioctl": 2}, 1)
        runtime.call("disconnect", cleanup=True)
        self.assertFalse(device.opened)

    def test_actual_dh_background_worker_mutex_exclusion_stop_and_join(self):
        import time

        from scripts.programming_2026_dh import start_sync_periodic_phase5

        provider = LiveOSProvider()
        device = J2534Device2026(provider)
        device.open()
        device.connect(6)
        runtime = NativeRuntime2026(device.primitive)
        try:
            start_sync_periodic_phase5(runtime, 2)
            self.assertTrue(provider.completed_batch.wait(1))
            worker = device.sync_worker
            self.assertIsNotNone(worker)
            runtime.call("lock")
            try:
                before = provider.write_count
                time.sleep(0.03)
                self.assertEqual(provider.write_count, before)
            finally:
                runtime.call("unlock", cleanup=True)
            self.assertEqual(runtime.close(), [])
            self.assertFalse(worker.is_alive() if worker is not None else True)
            self.assertIsNone(device.sync)
            self.assertEqual(provider.handles, {})
        finally:
            device.disconnect()

    def test_real_ownership_worker_events_are_shared_by_exact_native_transfer(self):
        import threading

        from scripts.j2534_2026 import DriverMetadata2026, MessageHistory2026

        provider = LiveOSProvider()
        owner = J2534Device2026(provider)
        owner.set_driver(DriverMetadata2026("authored", "fixture.dll"))
        owner.set_history_sink(MessageHistory2026())
        imported = J2534Device2026(provider)
        try:
            owner.have_ownership()
            thread = owner.ownership_thread
            self.assertIsNotNone(thread)
            state = owner.export_data()
            imported.import_data(state)
            self.assertIs(imported.ownership_thread, thread)
            self.assertIs(imported.ownership_release, owner.ownership_release)
            self.assertIs(imported.history_sink, owner.history_sink)
            self.assertFalse(
                owner.ownership_ready.is_set()
                if owner.ownership_ready is not None
                else True
            )
            imported.release_ownership()
            self.assertFalse(thread.is_alive() if thread is not None else True)
            self.assertIsNone(owner.ownership_mutex)
            self.assertEqual(provider.ownership_threads[0][0], "acquire")
            self.assertEqual(provider.ownership_threads[-1][0], "release")
            self.assertEqual(
                provider.ownership_threads[0][1], provider.ownership_threads[-1][1]
            )
            self.assertNotEqual(provider.ownership_threads[0][1], threading.get_ident())
        finally:
            owner.release_ownership()

    def test_native_transfer_excludes_logical_periodic_loaded_and_history_enable(self):
        import dataclasses

        from scripts.j2534_2026 import DriverMetadata2026

        provider = Provider()
        owner = J2534Device2026(provider, background_workers=False)
        owner.set_driver(DriverMetadata2026("authored", "fixture.dll"))
        owner.device_id, owner.opened, owner.channel_id, owner.connecting = (
            7,
            True,
            8,
            True,
        )
        owner.protocol_id = 6
        owner.logical[0x8203] = 99
        owner.driver_loaded = True
        owner.last_enabled = False
        owner.timeout, owner.send_timeout = 42, 43
        owner.function_slots = {offset: offset for offset in range(0x60, 0xC4, 4)}
        receiver = J2534Device2026(provider, background_workers=False)
        receiver.last_enabled = True
        receiver.previous_send_time = 123
        receiver.import_data(owner.export_data())
        self.assertEqual(
            (
                receiver.device_id,
                receiver.opened,
                receiver.channel_id,
                receiver.connecting,
            ),
            (7, True, 8, True),
        )
        self.assertEqual((receiver.timeout, receiver.send_timeout), (42, 43))
        self.assertEqual(receiver.function_slots, owner.function_slots)
        self.assertEqual(receiver.logical, {})
        self.assertIsNone(receiver.sync)
        self.assertFalse(receiver.driver_loaded)
        self.assertTrue(receiver.last_enabled)
        self.assertEqual(receiver.previous_send_time, 123)
        with self.assertRaises(ValueError):
            dataclasses.replace(owner.export_data(), function_slots=(0,))
        receiver.import_data(owner.export_data())
        with self.assertRaises(ValueError):
            receiver.import_data(dataclasses.replace(owner.export_data(), channel_id=9))

    def test_actual_background_transport_fault_is_reported_and_all_resources_close(
        self,
    ):
        provider = LiveOSProvider()
        provider.fail_write = True
        device = J2534Device2026(provider)
        device.open()
        device.connect(6)
        device.start_sync_periodic((NativeMessage(6, b"aaaa1"),), 0, 5)
        self.assertTrue(provider.transmitted.wait(1))
        worker = device.sync_worker
        if worker is not None:
            worker.join(1)
        with self.assertRaises(OSError):
            device.disconnect()
        self.assertIsNone(device.sync)
        self.assertIsNone(device.device_id)
        self.assertFalse(device.opened)
        self.assertEqual(provider.handles, {})


if __name__ == "__main__":
    unittest.main()
