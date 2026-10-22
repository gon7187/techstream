"""Authored raw SDK chronology; original artifacts are read statically only."""

import hashlib
import json
import struct
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

from scripts.cuw_2026 import CUWEngine2026
from scripts.cuw_gateway_startup import GatewayStartup2026
from scripts.demo_calibration import table
from scripts.j2534_2026 import (
    DriverMetadata2026,
    J2534Device2026,
    J2534InterfacePair2026,
    NativeMessage,
    PrimitiveResult,
)
from scripts.programming_2026_common import (
    NativeCentralGatewayKey2026,
    NativeException2026,
    NativeGeneralParameters2026,
    NativePassThruException2026,
    NativeRuntime2026,
)
from tests import test_cuw_engine_worker as fixtures
from tests import test_cuw_online as online_fixtures
from tests import test_programming_2026_body as body_fixtures
from tests.test_calibration_2026 import cuw
from tests.test_j2534_2026 import LiveOSProvider

REQUEST = bytes.fromhex("000007505f")
RESPONSE = bytes.fromhex("000007585f")
SOURCE = Path("runtime/no-car-21/recovered/CUW.dll")


class HostTimeoutFault(OSError):
    passthru_status = 9


class RawSDK:
    def __init__(self, replies):
        self.replies = list(replies)
        self.reads = []
        self.calls = []
        self.writes = []
        self.cancelled = False
        self.fail: Callable[[dict], object] | None = None
        self.writer_replies: list[bytes] | None = None
        self.writer_response = b""
        self.writer_read_count = 0
        self.writer_indications: set[int] = set()
        self.periodic_identifier = 16
        self.filter_identifier = 10
        self.full_wire = False
        self.os = LiveOSProvider()

    def __call__(self, operation, remaining):
        self.calls.append(operation)
        name = operation["operation"]
        if self.fail is not None and self.fail(operation):
            return PrimitiveResult(status=7)
        if name in ("passthru_open", "passthru_connect"):
            return PrimitiveResult(value=1)
        if name in ("passthru_scan_devices", "passthru_connect_0500"):
            return PrimitiveResult(value=1)
        if name == "passthru_next_device":
            return PrimitiveResult(value="authored")
        if name in (
            "create_mutex",
            "wait_handle",
            "release_mutex",
            "close_handle",
            "load_library",
            "get_symbol",
            "lock",
            "unlock",
        ):
            return self.os(operation, remaining)
        if name == "passthru_start_filter":
            self.filter_identifier += 1
            return PrimitiveResult(value=self.filter_identifier)
        if name == "passthru_start_periodic":
            self.periodic_identifier += 1
            return PrimitiveResult(value=self.periodic_identifier)
        if name == "passthru_write":
            message = operation["messages"][0]
            self.writes.append(message.data)
            if self.replies:
                expected, reply = self.replies.pop(0)
                wire = expected if self.full_wire else REQUEST + expected
                if message.data != wire:
                    raise AssertionError((message.data, wire))
                response = b"" if self.full_wire else RESPONSE
            else:
                assert self.writer_replies is not None
                reply = b""
                response = (int.from_bytes(message.data[:4], "big") + 8).to_bytes(
                    4, "big"
                )
                if message.tx_flags & 0x80:
                    response += message.data[4:5]
                if not self.writer_response:
                    self.writer_response = response
            self.reads.append(
                PrimitiveResult(
                    value=(NativeMessage(6, message.data[:4], rx_status=9),)
                )
            )
            if self.writer_replies is None:
                self.reads.append(
                    PrimitiveResult(status=reply)
                    if type(reply) is int
                    else PrimitiveResult(value=(NativeMessage(6, response + reply),))
                )
            return PrimitiveResult(value=1)
        if name == "passthru_read":
            if not self.reads and self.writer_replies is not None:
                if (
                    self.writer_read_count in (1, 3)
                    and self.writer_read_count not in self.writer_indications
                ):
                    self.writer_indications.add(self.writer_read_count)
                    return PrimitiveResult(
                        value=(NativeMessage(6, self.writer_response, rx_status=2),)
                    )
                self.writer_read_count += 1
                return PrimitiveResult(
                    value=(
                        NativeMessage(
                            6, self.writer_response + self.writer_replies.pop(0)
                        ),
                    )
                )
            return self.reads.pop(0)
        return PrimitiveResult()


class GatewayStartupTests(unittest.TestCase):
    def setUp(self):
        if not SOURCE.is_file():
            self.skipTest("Private static CUW2026 source unavailable")

    def context(self, replies, *, general=None, source=None, cpu_index=0):
        sdk = RawSDK(replies)
        device = J2534Device2026(
            sdk,
            clock=lambda: 0,
            cancelled=lambda: sdk.cancelled,
            background_workers=False,
        )
        device.set_driver(DriverMetadata2026("authored", "fixture.dll"))
        control_device = J2534Device2026(
            sdk,
            clock=device.clock,
            cancelled=device.cancelled,
            background_workers=False,
        )
        assert device.driver is not None
        control_device.set_driver(device.driver)
        pair = J2534InterfacePair2026(device, control_device)
        device.open()
        device.connect(6)
        runtime = NativeRuntime2026(
            control_device.primitive, clock=device.clock, cancelled=device.cancelled
        )
        runtime.bind_central_gateway_key(
            NativeCentralGatewayKey2026.from_native_module(SOURCE.read_bytes())
        )
        engine = CUWEngine2026(SOURCE.read_bytes(), general_parameters=general)
        engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
        if source is None and general is not None:
            source = cuw(
                "[Format]\nVersion=7\n[Vehicle]\nKindOfECU=149\nContactType=P5-Unified\n"
                "NumberOfCalibration=1\n[CPU01]\nCPUType=311\nCPUImageName=authored.vbf\n"
                "NumberOfTargets=1\n01_TargetCalibration=OLD\n01_TargetData=12345678\n",
                (bytes(1024),),
            )
        engine.load_cuw(
            fixtures.calibration() if source is None else source, cpu_index=cpu_index
        )
        self.addCleanup(engine.close)
        self.addCleanup(runtime.close)
        controller = fixtures.make_controller(runtime)
        worker = engine.bind_worker(controller)
        engine.bind_interface_pair(pair)
        # The engine owns the issued producer: the ED0C publication guard
        # rejects a producer obtained through the private issuer path.
        producer = engine.bind_gateway_startup()
        return sdk, device, engine, controller, worker, producer

    def p4_replies(self, *, classify=b"\x7e"):
        seed = bytes(range(16))
        binding = NativeCentralGatewayKey2026.from_native_module(SOURCE.read_bytes())
        return [
            (b"\x3e", classify),
            (b"\x27\x51", b"\x67\x51" + seed),
            (b"\x27\x52" + binding.calculate(seed), b"\x67\x52\x34"),
            (b"\x10\x60", b"\x50"),
        ]

    def writer_inputs(self, module="TCUWP4CanBodyFlashWriter.dll"):
        return body_fixtures.writer_selection(
            module,
            initialize_prepare=True,
            encoded=True,
            gateway_startup=True,
        )

    def cancel_context(self, replies, *, contact="P4"):
        source = cuw(
            "[Format]\nVersion=105\n[Vehicle]\nNumberOfNode=1\n"
            f"ContactType={contact}\nKindOfECU=149\n[Node01]\nNumberOfCalibration=1\n"
            "[CPU11]\nCPUImageName=authored.vbf\nCPUType=311\n",
            (bytes(1024),),
        )
        context = self.context(replies, source=source)
        context[0].full_wire = True
        if contact == "Ethernet":
            pair = context[2].interface_pair
            assert pair is not None
            for view in (pair.engine, pair.control):
                view.driver_versions[1] = DriverMetadata2026(
                    "authored0500", "fixture0500.dll"
                )
        return context

    @staticmethod
    def cancel_p6_replies(*, enabled=True):
        request, response = bytes.fromhex("18da72e0"), bytes.fromhex("18dae072")
        replies = [
            (request + b"\x10\x03", response + b"\x50\x03" + bytes(4)),
            (
                request + b"\x22\x21\x03",
                response + b"\x62\x21\x03" + bytes((1 if enabled else 0, 0xA0)),
            ),
        ]
        if enabled:
            replies.append(
                (request + b"\x2e\x21\x03\x01\xa1", response + b"\x6e\x21\x03")
            )
        return replies

    def test_callback29_literal_p6_session_did_and_conditional_write(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                sdk, device, engine, controller, worker, producer = self.cancel_context(
                    self.cancel_p6_replies(enabled=enabled)
                )
                with engine.controller_execution(controller, 0):
                    self.assertIs(producer.callback29(), True)
                self.assertTrue(producer.cancel_state.returned)
                self.assertFalse(worker.native_initial_command_retry)
                self.assertEqual(device.filters, [])
                self.assertEqual(sdk.replies, [])
                flags = [
                    e["messages"][0].tx_flags
                    for e in sdk.calls
                    if e["operation"] == "passthru_write"
                ]
                self.assertTrue(all(value == 0x140 for value in flags))

    def test_callback29_p6_initial_timeout9_16_enters_actual_p5_session(self):
        request, response = bytes.fromhex("00000750e9"), bytes.fromhex("00000758e9")
        for status in (9, 16):
            with self.subTest(status=status):
                replies = [
                    (bytes.fromhex("18da72e01003"), status),
                    (request + b"\x10\x03", response + b"\x50\x03" + bytes(4)),
                    (request + b"\x22\x20\x01", response + b"\x62\x20\x01\x40\x80"),
                    (request + b"\x2e\x20\x01\x40\xc0", response + b"\x6e\x20\x01"),
                ]
                sdk, device, engine, controller, _, producer = self.cancel_context(
                    replies
                )
                with engine.controller_execution(controller, 0):
                    self.assertIs(producer.callback29(), True)
                self.assertEqual(sdk.replies, [])
                self.assertEqual(device.filters, [])

    def test_callback29_p5_session7f1012_has_exact_p4_fallback(self):
        request, response = bytes.fromhex("00000750e9"), bytes.fromhex("00000758e9")
        for fallback in (b"\x50", b"\x7f\x10\x11", b"\x7f\x10\x12", b"\x7f\x10\x13"):
            with self.subTest(fallback=fallback):
                replies = [
                    (bytes.fromhex("18da72e01003"), 16),
                    (request + b"\x10\x03", response + b"\x7f\x10\x12"),
                    (request + b"\x10\x70", response + fallback),
                ]
                sdk, device, engine, controller, _, producer = self.cancel_context(
                    replies
                )
                with engine.controller_execution(controller, 0):
                    self.assertIs(producer.callback29(), True)
                self.assertEqual(sdk.replies, [])
                self.assertEqual(device.filters, [])

    def test_callback29_sil_switches6_then3_only_after_normal_cancel(self):
        sdk, device, engine, controller, _, producer = self.cancel_context(
            self.cancel_p6_replies(), contact="SIL"
        )
        with engine.controller_execution(controller, 0):
            self.assertIs(producer.callback29(), True)
        self.assertEqual(device.protocol_id, 3)
        connects = [
            e["protocol"] for e in sdk.calls if e["operation"] == "passthru_connect"
        ]
        self.assertEqual(connects, [6, 6, 3])
        self.assertEqual(sdk.replies, [])

    def test_callback29_sil_host_fault_does_not_restore_connection_or_hide_cause(self):
        sdk, device, engine, controller, _, producer = self.cancel_context(
            self.cancel_p6_replies(), contact="SIL"
        )
        original = OSError("Authored cancel IG-off host fault")

        def fail(event):
            if event["operation"] == "passthru_write":
                raise original

        sdk.fail = fail
        with (
            self.assertRaises(OSError) as caught,
            engine.controller_execution(controller, 0),
        ):
            producer.callback29()
        self.assertIs(caught.exception, original)
        self.assertIsNone(producer.cancel_state.returned)
        self.assertEqual(device.protocol_id, 6)
        connects = [
            e["protocol"] for e in sdk.calls if e["operation"] == "passthru_connect"
        ]
        self.assertEqual(connects, [6, 6])

    def test_callback29_ethernet_switches_version_only_after_actual_cancel(self):
        sdk, device, engine, controller, _, producer = self.cancel_context(
            self.cancel_p6_replies(), contact="Ethernet"
        )
        try:
            with engine.controller_execution(controller, 0):
                self.assertIs(producer.callback29(), True)
            self.assertEqual((device.protocol_id, device.version), (0x800F, 1))
            self.assertTrue(device.driver_loaded)
            loaded = [
                e["name"]
                for e in sdk.calls
                if e["operation"] == "passthru_load_library"
            ]
            self.assertEqual(loaded, ["fixture0500.dll"])
            self.assertEqual(sdk.replies, [])
        finally:
            device.clear()
        self.assertEqual(sdk.os.handles, {})

    def test_callback29_native_session_negative_and_late_p6_timeout_do_not_fallback(
        self,
    ):
        for replies, primary, status in (
            (
                [(bytes.fromhex("18da72e01003"), bytes.fromhex("18dae0727f1012"))],
                0x58,
                None,
            ),
            (
                self.cancel_p6_replies()[:1] + [(bytes.fromhex("18da72e0222103"), 9)],
                1,
                9,
            ),
        ):
            with self.subTest(primary=primary, status=status):
                sdk, device, engine, controller, worker, producer = self.cancel_context(
                    replies
                )
                with engine.controller_execution(controller, 0):
                    engine.dh_state.record_native_error(3, 111, 77)
                    self.assertIs(producer.callback29(), False)
                    self.assertEqual(worker.control_state.primary_error, primary)
                    self.assertEqual(
                        worker.control_state.passthru_error,
                        77 if status is None else status,
                    )
                    self.assertEqual(engine.native_error_output, (0, 0))
                self.assertEqual(producer.cancel_state.primary_error, primary)
                self.assertEqual(producer.cancel_state.passthru_status, status)
                self.assertEqual(device.filters, [])
                self.assertTrue(
                    all(
                        data.startswith(bytes.fromhex("18da72e0"))
                        for data in sdk.writes
                    )
                )

    def test_callback29_p5_initial_timeout_is_suppressed_and_other_nrc_reaches_local_error(
        self,
    ):
        request, response = bytes.fromhex("00000750e9"), bytes.fromhex("00000758e9")
        for payload, fallback, result, primary in (
            (16, None, True, None),
            (response + b"\x7f\x10\x13", None, False, 0x58),
            (response + b"\x7f\x10\x12", response + b"\x7f\x10\x22", False, 0x4E),
        ):
            with self.subTest(payload=payload, fallback=fallback):
                replies = [
                    (bytes.fromhex("18da72e01003"), 9),
                    (request + b"\x10\x03", payload),
                ]
                if fallback is not None:
                    replies.append((request + b"\x10\x70", fallback))
                sdk, device, engine, controller, _, producer = self.cancel_context(
                    replies
                )
                with engine.controller_execution(controller, 0):
                    self.assertIs(producer.callback29(), result)
                self.assertEqual(producer.cancel_state.primary_error, primary)
                self.assertEqual(device.filters, [])
                self.assertEqual(sdk.replies, [])

    def test_callback29_unknown_native_business_maps9999_to_local_catch(self):
        sdk, _, engine, controller, worker, producer = self.cancel_context([])

        def fail(event):
            if event["operation"] == "passthru_start_filter":
                raise NativeException2026("Authored cancel native unknown")

        sdk.fail = fail
        with engine.controller_execution(controller, 0):
            self.assertIs(producer.callback29(), False)
            self.assertEqual(worker.control_state.primary_error, 9999)
            self.assertEqual(engine.native_error_output, (0, 0))
        self.assertEqual(producer.cancel_state.primary_error, 9999)

    def test_callback29_native_filter_stop_failure_does_not_change_normal_al(self):
        sdk, device, engine, controller, _, producer = self.cancel_context(
            self.cancel_p6_replies()
        )
        fired = False

        def fail(event):
            nonlocal fired
            if event["operation"] == "passthru_stop_filter" and not fired:
                fired = True
                return True
            return False

        sdk.fail = fail
        with engine.controller_execution(controller, 0):
            self.assertIs(producer.callback29(), True)
        self.assertTrue(fired)
        self.assertEqual(device.filters, [11])
        self.assertEqual(controller.runtime.close(), [])
        self.assertEqual(device.filters, [])

    def test_callback29_each_p6_and_p5_wire_boundary_preserves_host_fault(self):
        request, response = bytes.fromhex("00000750e9"), bytes.fromhex("00000758e9")
        chains = (
            self.cancel_p6_replies(),
            [
                (bytes.fromhex("18da72e01003"), 16),
                (request + b"\x10\x03", response + b"\x50\x03" + bytes(4)),
                (request + b"\x22\x20\x01", response + b"\x62\x20\x01\x40\x80"),
                (request + b"\x2e\x20\x01\x40\xc0", response + b"\x6e\x20\x01"),
            ],
        )
        operations = {"passthru_start_filter", "passthru_write", "passthru_read"}
        for chain in chains:
            sdk, _, engine, controller, _, producer = self.cancel_context(chain)
            start = len(sdk.calls)
            with engine.controller_execution(controller, 0):
                self.assertTrue(producer.callback29())
            count = sum(e["operation"] in operations for e in sdk.calls[start:])
            for index in range(count):
                with self.subTest(chain=len(chain), index=index):
                    sdk, device, engine, controller, _, producer = self.cancel_context(
                        chain
                    )
                    failure = HostTimeoutFault("Authored callback29 wire fault")
                    visited = 0

                    def fail(event, *, index=index, failure=failure):
                        nonlocal visited
                        if event["operation"] in operations:
                            current, visited = visited, visited + 1
                            if current == index:
                                raise failure
                        return False

                    sdk.fail = fail
                    with (
                        engine.controller_execution(controller, 0),
                        self.assertRaises(OSError) as caught,
                    ):
                        producer.callback29()
                    self.assertIs(caught.exception, failure)
                    self.assertEqual(device.filters, [])
                    self.assertIsNone(producer.cancel_state.returned)

    def test_callback29_cancellation_after_each_acquired_wire_resource(self):
        request, response = bytes.fromhex("00000750e9"), bytes.fromhex("00000758e9")
        chains = (
            self.cancel_p6_replies(),
            [
                (bytes.fromhex("18da72e01003"), 16),
                (request + b"\x10\x03", response + b"\x50\x03" + bytes(4)),
                (request + b"\x22\x20\x01", response + b"\x62\x20\x01\x00\x80"),
            ],
        )
        for chain in chains:
            for name in ("passthru_start_filter", "passthru_write", "passthru_read"):
                with self.subTest(chain=len(chain), operation=name):
                    sdk, device, engine, controller, _, producer = self.cancel_context(
                        chain
                    )

                    def fail(event, *, name=name, sdk=sdk):
                        if event["operation"] == name:
                            sdk.cancelled = True
                        return False

                    sdk.fail = fail
                    with (
                        self.assertRaises(InterruptedError),
                        engine.controller_execution(controller, 0),
                    ):
                        producer.callback29()
                    self.assertEqual(device.filters, [])
                    self.assertIsNone(producer.cancel_state.returned)

    def test_callback29_p5_clear_bit_and_did_write_native_failures(self):
        request, response = bytes.fromhex("00000750e9"), bytes.fromhex("00000758e9")
        for enabled, fault_index in ((False, None), (True, 2), (True, 3)):
            with self.subTest(enabled=enabled, fault=fault_index):
                replies = [
                    (bytes.fromhex("18da72e01003"), 16),
                    (request + b"\x10\x03", response + b"\x50\x03" + bytes(4)),
                    (
                        request + b"\x22\x20\x01",
                        response
                        + b"\x62\x20\x01"
                        + bytes((0x40 if enabled else 0, 0x80)),
                    ),
                ]
                if enabled:
                    replies.append(
                        (request + b"\x2e\x20\x01\x40\xc0", response + b"\x6e\x20\x01")
                    )
                if fault_index is not None:
                    replies[fault_index] = (
                        replies[fault_index][0],
                        response + b"\x7f\x22\x31",
                    )
                    replies = replies[: fault_index + 1]
                sdk, device, engine, controller, worker, producer = self.cancel_context(
                    replies
                )
                with engine.controller_execution(controller, 0):
                    self.assertIs(producer.callback29(), fault_index is None)
                    if fault_index is not None:
                        self.assertEqual(
                            worker.control_state.primary_error,
                            0x57 if fault_index == 2 else 0x4E,
                        )
                        self.assertEqual(engine.native_error_output, (0, 0))
                self.assertEqual(device.filters, [])
                self.assertEqual(sdk.replies, [])

    def run_owned(self, engine, controller, producer):
        # Phase0 avoids the worker's independently tested automatic phase1 gate.
        with engine.controller_execution(controller, 0):
            return producer.run_classifier()

    def test_literal_class2_actual_device_aes_mode_and_cleanup(self):
        sdk, device, engine, controller, worker, producer = self.context(
            self.p4_replies()
        )
        state = self.run_owned(engine, controller, producer)
        self.assertEqual((state.classification, state.returned), (2, True))
        self.assertFalse(state.output_flag)
        self.assertEqual(engine.repro_gateway_node, 0)
        self.assertIsNone(state.periodic_identifier)
        self.assertFalse(worker.native_initial_command_retry)
        self.assertEqual(device.filters, [])
        self.assertEqual(sdk.replies, [])
        self.assertEqual(sdk.reads, [])
        io = [
            v["parameters"]
            for v in sdk.calls
            if v["operation"] == "passthru_ioctl" and v["ioctl"] == 2
        ]
        self.assertEqual(io, [((0x1E, 1),), ((0x1E, 0),)])
        self.assertEqual(sdk.calls[-1]["operation"], "passthru_stop_filter")

    def test_pair_startup_uses_engine_view_before_actual_import_into_control(self):
        _, device, engine, controller, _, producer = self.context(self.p4_replies())
        pair = engine.interface_pair
        assert pair is not None
        device.timeout, pair.control.timeout = 73, 19
        original_action = controller.runtime.action
        self.assertFalse(pair.control.connecting)
        self.assertTrue(device.connecting)
        self.assertTrue(self.run_owned(engine, controller, producer).returned)
        self.assertIs(controller.runtime.action, original_action)
        self.assertIs(getattr(original_action, "__self__", None), pair.control)
        self.assertEqual((device.timeout, pair.control.timeout), (73, 19))
        self.assertFalse(pair.control.connecting)
        self.assertEqual(pair.control.calls, 0)
        pair.import_into(pair.control, pair.export_from(pair.engine))
        self.assertTrue(pair.control.connecting)
        self.assertEqual(pair.control.timeout, 73)
        self.assertIsNot(pair.control, pair.engine)

    def test_classification_cache_skips_probe_but_does_not_skip_authentication(self):
        replies = self.p4_replies()
        sdk, _, engine, controller, _, producer = self.context(replies + replies[1:])
        self.run_owned(engine, controller, producer)
        self.run_owned(engine, controller, producer)
        self.assertEqual(sdk.writes.count(REQUEST + b"\x3e"), 1)
        self.assertEqual(sdk.writes.count(REQUEST + b"\x10\x60"), 2)
        self.assertIs(engine.bind_gateway_startup(), producer)

    def test_callback14_runs_actual5b1e0_without_inventing5a835_be0(self):
        sdk, _, engine, controller, worker, producer = self.context(self.p4_replies())
        with engine.controller_execution(controller, 0):
            self.assertIs(producer.callback14(), True)
            self.assertEqual(engine.repro_gateway_node, 2)
            self.assertFalse(worker.native_initial_command_retry)
        self.assertEqual(sdk.replies, [])

    def test_5b1e0_non_timeout_j2534_error_sets_output_and_controller_fields(self):
        sdk, device, engine, controller, worker, producer = self.context([])
        sdk.fail = lambda event: event["operation"] == "passthru_ioctl"
        with engine.controller_execution(controller, 0):
            self.assertIs(producer.callback14(), False)
            state = producer.source_state
            self.assertTrue(state.output_flag)
            self.assertFalse(state.classification_returned)
            self.assertEqual((state.primary_error, state.passthru_status), (1, 7))
            self.assertEqual(worker.control_state.primary_error, 1)
            self.assertEqual(worker.control_state.passthru_error, 7)
            self.assertEqual(worker.control_state.error_kind, 0)
            self.assertFalse(worker.control_state.failed)
            self.assertEqual(engine.native_error_output, (0, 0))
        self.assertEqual(device.filters, [])

    def test_5b1e0_online_false1010_sets_output_and_preserves_driver_error(self):
        _, device, engine, controller, worker, producer, _ = self.p5_context(
            approved=False
        )
        with engine.controller_execution(controller, 0):
            self.assertIs(producer.callback14(), False)
            state = producer.source_state
            self.assertTrue(state.output_flag)
            self.assertEqual(state.primary_error, 1010)
            self.assertIsNone(state.passthru_status)
            self.assertEqual(worker.control_state.primary_error, 1010)
            self.assertEqual(worker.control_state.error_kind, 0)
            self.assertFalse(worker.control_state.failed)
            self.assertEqual(engine.native_error_output, (0, 0))
        self.assertEqual(device.periodics, [])

    def test_5a835_consumes_false_al_true_output_as_failed_without_980(self):
        sdk, _, engine, controller, worker, _ = self.context(
            [], general=self.general(True)
        )
        sdk.fail = lambda event: event["operation"] == "passthru_ioctl"
        with engine.controller_execution(controller, 1):
            state = worker.run_gateway_startup()
            assert state is not None
            self.assertFalse(state.returned)
            self.assertTrue(state.output_flag)
            self.assertFalse(worker.native_initial_command_retry980)
            self.assertTrue(worker.control_state.failed)
            self.assertEqual(worker.control_state.error_kind, 1)
            self.assertEqual(worker.control_state.primary_error, 1)
            self.assertEqual(worker.control_state.passthru_error, 7)

    def test_5b1e0_host_failure_keeps_identity_and_does_not_become_native_al(self):
        sdk, _, engine, controller, worker, producer = self.context([])
        failure = OSError("Authored full wrapper host failure")
        fired = False

        def fail(event):
            nonlocal fired
            if event["operation"] == "passthru_ioctl" and not fired:
                fired = True
                raise failure
            return False

        sdk.fail = fail
        with engine.controller_execution(controller, 0):
            with self.assertRaises(OSError) as caught:
                producer.callback14()
            self.assertIs(caught.exception, failure)
            self.assertFalse(producer.source_state.returned)
            self.assertFalse(producer.source_state.output_flag)
            self.assertFalse(worker.native_initial_command_retry980)

    def test_host_status_attribute_does_not_select_native_classifier_fallback(self):
        sdk, device, engine, controller, _, producer = self.context(self.p4_replies())
        failure = HostTimeoutFault("Authored host exception with driver-like field")

        def fail(event):
            if event["operation"] == "passthru_read":
                raise failure
            return False

        sdk.fail = fail
        with engine.controller_execution(controller, 0):
            with self.assertRaises(HostTimeoutFault) as caught:
                producer.callback14()
            self.assertIs(caught.exception, failure)
            self.assertEqual(producer.source_state.classification, 0)
        self.assertEqual(sdk.writes, [REQUEST + b"\x3e"])
        self.assertEqual(device.filters, [])

    def test_close_reload_revokes_old_source_producer_lease(self):
        _, _, engine, controller, worker, producer = self.context([])
        pair = engine.interface_pair
        engine.close()
        with self.assertRaises(ValueError):
            producer.validate_owner(engine, worker)
        engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
        engine.load_cuw(fixtures.calibration())
        next_worker = engine.bind_worker(controller)
        engine.bind_interface_pair(pair)
        fresh = engine.bind_gateway_startup()
        self.assertIsNot(fresh, producer)
        self.assertIs(fresh.worker, next_worker)

    def test_worker_rebind_rejects_unissued_or_active_owners_without_io(self):
        sdk, _, engine, controller, worker, producer = self.context([])
        state, calls = producer.source_state, len(sdk.calls)
        with self.assertRaises(TypeError):
            producer.rebind_worker(worker, object())
        with self.assertRaises(ValueError):
            producer.rebind_worker(worker, worker)
        with engine.controller_execution(controller, 0), self.assertRaises(ValueError):
            producer.rebind_worker(worker, worker)
        self.assertIs(producer.worker, worker)
        self.assertEqual(producer.source_state, state)
        self.assertEqual(len(sdk.calls), calls)

    def test_stopped_worker_rebind_preserves_actual_p5_periodic_cache_and_aes(self):
        from scripts.cuw_engine_worker import (
            _finalize_engine_worker_replacement,
            _replace_engine_worker,
            _rollback_engine_worker_replacement,
        )

        sdk, device, engine, controller, previous, producer, _ = self.p5_context()
        with engine.controller_execution(controller, 1):
            previous.run_gateway_startup()
        retry = engine.bind_retry_controller()
        state, runtime = producer.source_state, previous.runtime
        aes, calls = runtime._central_gateway_key, len(sdk.calls)
        replacement = _replace_engine_worker(engine, controller, previous)
        retry.rebind_worker(previous, replacement)
        with (
            engine.controller_execution(controller, 0),
            self.assertRaisesRegex(ValueError, "stopped-worker gateway"),
        ):
            producer.rebind_worker(previous, replacement)
        producer.rebind_worker(previous, replacement)
        self.assertIs(replacement._gateway_startup, producer)
        self.assertIs(producer.worker, replacement)
        self.assertIs(engine.bind_gateway_startup(), producer)
        self.assertIs(replacement.runtime, runtime)
        self.assertIs(runtime._central_gateway_key, aes)
        self.assertEqual(producer.source_state, state)
        self.assertEqual((engine.repro_gateway_node, device.periodics), (1, [18]))
        self.assertEqual(len(sdk.calls), calls)
        with self.assertRaises(ValueError):
            producer.validate_owner(engine, previous)
        producer.validate_owner(engine, replacement)
        # The engine rolls back its worker first, then reverses dependent leases.
        _rollback_engine_worker_replacement(engine, previous, replacement)
        producer.rebind_worker(replacement, previous)
        retry.rebind_worker(replacement, previous)
        self.assertIs(engine.bind_gateway_startup(), producer)
        self.assertIs(producer.worker, previous)
        self.assertEqual(producer.source_state, state)
        replacement = _replace_engine_worker(engine, controller, previous)
        retry.rebind_worker(previous, replacement)
        producer.rebind_worker(previous, replacement)
        _finalize_engine_worker_replacement(engine, previous, replacement)
        self.assertIs(engine.bind_gateway_startup(), producer)
        self.assertEqual((producer.source_state, device.periodics), (state, [18]))
        self.assertEqual(len(sdk.calls), calls)

    def test_timeout_probe_falls_back_to_p5_but_online_binding_is_required(self):
        seed = bytes(range(16))
        replies = [
            (b"\x3e", 16),
            (b"\x3e\x00", b"\x7e\x00"),
            (b"\x10\x03", b"\x50\x03" + bytes(4)),
            (b"\x27\x21", b"\x67\x21" + seed),
        ]
        sdk, device, engine, controller, _, producer = self.context(replies)
        with self.assertRaisesRegex(ValueError, "online controller binding required"):
            self.run_owned(engine, controller, producer)
        self.assertEqual(producer.source_state.classification, 1)
        self.assertFalse(producer.source_state.returned)
        self.assertEqual(device.filters, [])
        self.assertEqual(device.periodics, [])
        self.assertEqual(
            [x["operation"] for x in sdk.calls].count("passthru_stop_periodic"), 1
        )

    def p5_context(self, *, approved=True):
        from scripts.cuw_online import OnlineKeyController2026

        seed, key = bytes(range(16)), b"\xab" * 256
        replies = [
            (b"\x3e", 9),
            (b"\x3e\x00", b"\x7e\x00"),
            (b"\x10\x03", b"\x50\x03" + bytes(4)),
            (b"\x27\x21", b"\x67\x21" + seed),
            (b"\x27\x22" + key, b"\x67\x22"),
            (b"\x31\x01\x10\x11", b"\x71\x01\x10\x11"),
            (b"\x31\x03\x10\x11", b"\x71\x03\x10\x11\x01"),
            (b"\x31\x01\x10\x12", b"\x71\x01\x10\x12"),
            (b"\x31\x03\x10\x12", b"\x71\x03\x10\x12\x01"),
        ]
        sdk, device, engine, controller, worker, producer = self.context(
            replies, general=self.general(True)
        )
        engine.set_vin(b"JT123456789012345")
        online = OnlineKeyController2026(worker, online_fixtures.configuration())
        capture = online_fixtures.capture(
            online,
            seed,
            [
                online_fixtures.step("online.SetReprogrammingKey", (b"aB" * 256).hex())
                if approved
                else online_fixtures.step("online.finish")
            ],
        )
        controller.runtime.bind_p5_online(online, capture, advance_clock=lambda _: None)
        return sdk, device, engine, controller, worker, producer, capture

    def test_literal_class1_full_online_callback_and_routine_sequence(self):
        sdk, device, engine, controller, _, producer, capture = self.p5_context()
        state = self.run_owned(engine, controller, producer)
        self.assertEqual((state.classification, state.returned), (1, True))
        self.assertEqual(device.periodics, [18])
        self.assertEqual(device.filters, [])
        self.assertEqual(sdk.replies, [])
        periodic = [v for v in sdk.calls if v["operation"] == "passthru_start_periodic"]
        self.assertEqual(len(periodic), 2)
        for event in periodic:
            self.assertEqual(event["message"].data, REQUEST + b"\x3e\x80")
            self.assertEqual(event["interval"], 2000)
        self.assertTrue(capture.used)

    def test_actual_phase1_class1_publishes_980_and_equality1_new_password(self):
        sdk, device, engine, controller, worker, _, capture = self.p5_context()
        with engine.controller_execution(controller, 1):
            state = worker.run_gateway_startup()
            assert state is not None
            self.assertEqual(state.classification, 1)
            self.assertTrue(worker.native_initial_command_retry)
            self.assertEqual(engine.repro_gateway_node, 1)
            self.assertTrue(worker.control_state.use_new_password)
        self.assertTrue(capture.used)
        self.assertEqual(sdk.replies, [])
        self.assertEqual(device.periodics, [18])

    def test_actual_p5_startup_periodic_is_consumed_by_retry_before_query_wait(self):
        sdk, device, engine, controller, worker, _, _ = self.p5_context()
        with engine.controller_execution(controller, 1):
            worker.run_gateway_startup()
        retry = engine.bind_retry_controller()

        def cancel_after_stop(event):
            if event["operation"] == "passthru_stop_periodic":
                sdk.cancelled = True

        sdk.fail = cancel_after_stop
        with (
            self.assertRaises(InterruptedError),
            engine.controller_execution(controller, 0),
        ):
            engine.dh_state.record_native_error(3, 1008, 17)
            engine.notify_native_error_kind()
            engine.notify_native_errors()
            retry.callback3()
        self.assertEqual(device.periodics, [])
        self.assertEqual(
            sum(e["operation"] == "passthru_stop_periodic" for e in sdk.calls), 2
        )
        self.assertFalse(
            controller.runtime.owns_resource("stop_periodic", identifier=18)
        )

    def test_p5_online_decline_has_literal1010_error_and_releases_periodic(self):
        _, device, engine, controller, _, producer, capture = self.p5_context(
            approved=False
        )
        with self.assertRaises(NativePassThruException2026) as caught:
            self.run_owned(engine, controller, producer)
        self.assertEqual(getattr(caught.exception, "native_error_code", None), 0x3F2)
        self.assertTrue(capture.used)
        self.assertEqual(device.periodics, [])
        self.assertEqual(device.filters, [])
        self.assertFalse(producer.source_state.returned)

    def general(self, enabled):
        return NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": table(
                    (
                        "ParamFileKeySystemProtocolMicon",
                        "FlagToChangeToReprogGWModeForCentralGW",
                        "M16CTypeFlag",
                        "FORESTTypeFlag",
                    ),
                    (("149P5-Unified311", "1" if enabled else "0", "0", "0"),),
                )
            },
            encoded=False,
        )

    def test_actual_phase1_5a835_publishes_980_and_retains_raw_classifier2(self):
        sdk, _, engine, controller, worker, producer = self.context(
            self.p4_replies(), general=self.general(True)
        )
        controller.runtime._central_gateway_key = None
        with engine.controller_execution(controller, 1):
            self.assertFalse(worker.native_initial_command_retry)
            state = worker.run_gateway_startup()
            assert state is not None
            self.assertEqual(state.classification, 2)
            self.assertTrue(worker.native_initial_command_retry)
            self.assertEqual(engine.repro_gateway_node, 2)
            self.assertFalse(worker.control_state.use_new_password)
            self.assertIs(worker._gateway_startup, producer)
            self.assertIs(
                controller.runtime._central_gateway_key, engine._central_gateway_key
            )
        self.assertEqual(sdk.replies, [])

    def test_imported_recovery_cids_do_not_fabricate_writer_target(self):
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
            RequestedAddress,
            encode_recovery_info,
            parse_recovery_info,
        )

        module = "TCUWP4CanBodyFlashWriter.dll"
        raw, _, _, general = body_fixtures.writer_selection(
            module, initialize_prepare=True, encoded=True, gateway_startup=True
        )
        _, _, engine, _, worker, _ = self.context(
            self.p4_replies(), general=general, source=raw, cpu_index=1
        )
        with tempfile.TemporaryDirectory() as directory:
            saved_path = r"C:\authored\Save\fixture.cuw"
            recovered = ReproInfoState(
                (
                    RecoveryCalibration(
                        "authored.cuw",
                        raw,
                        saved_path=saved_path,
                        cids=("OLD_A", "OLD_B"),
                        requested_addresses=(
                            RequestedAddress("0100"),
                            RequestedAddress("0100"),
                        ),
                    ),
                ),
                write_cpu_index=1,
            )
            persistence = CUWPersistence.import_recovery(
                Path(directory),
                parse_recovery_info(encode_recovery_info(recovered)),
                {saved_path: raw},
                cpu_capacity=4,
            )
            engine.bind_persistence(persistence)
            with self.assertRaisesRegex(ValueError, "owned native CID completion"):
                worker.refresh_target_selection()
            with self.assertRaisesRegex(
                ValueError, "no completed native CID selection"
            ):
                _ = engine.native_writer_target_index
            self.assertFalse(engine.native_initial_command_retry980)

    def test_actual_getter_startup_980_reaches_public_body_writer(self):
        self.run_canonical_startup_writer(
            "TCUWP4CanBodyFlashWriter.dll", "authored-getter-startup-writer.json"
        )

    def test_actual_getter_startup_980_is_consumed_by_sonar_initial_timeout(self):
        self.run_canonical_startup_writer(
            body_fixtures.SONAR_WRITE, "authored-getter-startup-sonar.json"
        )

    @staticmethod
    def recorded_messages(row) -> tuple[NativeMessage, ...]:
        from scripts.programming_replay import _driver_value2026, _typed_value

        decoded = _driver_value2026(_typed_value(row["result"]))
        assert isinstance(decoded, dict)
        messages = decoded["value"]
        assert isinstance(messages, tuple)
        assert all(type(message) is NativeMessage for message in messages)
        return messages

    def test_actual_constructor_empty_dh_fallback_al_and_output_flag(self):
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )
        from scripts.programming_2026_common import NativeSecurityComposer2026
        from scripts.programming_replay import load_programming_replay

        raw, _, selection, general = self.writer_inputs()
        root = Path("runtime/no-car-21/recovered")
        modules = {
            name: (root / name).read_bytes()
            for name in (
                "CUW.dll",
                "TCUWControlCommPhase.dll",
                "TCUWJ2534DeviceIF.dll",
                "TCUWCanCIDGetter.dll",
                "TCUWDHUtils.dll",
                "SecretInfo.dll",
                "TCUWP4CanBodyFlashWriter.dll",
                body_fixtures.BODY,
            )
        }
        for connected, fault in (
            (False, None),
            (True, None),
            (True, "cpass"),
            (True, "j2534"),
        ):
            with (
                self.subTest(connected=connected, fault=fault),
                tempfile.TemporaryDirectory() as directory,
            ):
                rows = json.loads(
                    Path(
                        "analysis/evidence/no-car-134",
                        f"authored-empty-dh-{int(connected)}.json",
                    ).read_bytes()
                )
                if fault:
                    key_reply = next(
                        row
                        for row in rows
                        if row["request"]["operation"] == "passthru_read"
                        and any(
                            message.data == bytes.fromhex("0000078e670234")
                            for message in self.recorded_messages(row)
                        )
                    )
                    if fault == "cpass":
                        key_reply["result"]["value"]["value"]["value"][0]["value"][
                            "data"
                        ]["value"] = "0000078e7f2735"
                    else:
                        key_reply["result"] = {
                            "type": "mapping",
                            "value": {
                                "status": {"type": "int", "value": 7},
                                "value": {"type": "tuple", "value": []},
                            },
                        }
                returned = connected and fault is None
                hard_error = fault == "j2534"
                document = {
                    "schema": "techstream-programming-replay-v1",
                    "source": "recorded_unverified",
                    "calibration_sha256": hashlib.sha256(raw).hexdigest(),
                    "operation": "get_cid",
                    "node": 1,
                    "observations": {
                        "current_cids": [],
                        "tester_info_hex": bytes(32).hex(),
                        "system_time": [2026, 10, 2, 20, 1, 2, 3, 4],
                        "timeout_seconds": 300,
                        "cid_mode": 2,
                        "host": {"cpu_index": 0, "driver_recording": "j2534_2026"},
                    },
                    "events": rows,
                }
                session = load_programming_replay(
                    raw,
                    json.dumps(document).encode(),
                    dict(selection.catalog_sources),
                    modules,
                )
                trace = session.trace
                runtime = NativeRuntime2026(
                    trace.action,
                    cleanup_action=trace.cleanup_primitive,
                    clock=trace.clock,
                    cancelled=trace.cancelled,
                    local_seconds_of_day=trace.native_local_seconds_of_day,
                    local_milliseconds_of_day=trace.native_local_milliseconds_of_day,
                )
                runtime.bind_security_composer(
                    NativeSecurityComposer2026.from_native_modules(
                        modules["SecretInfo.dll"], modules["CUW.dll"]
                    )
                )
                engine = CUWEngine2026(modules["CUW.dll"], general_parameters=general)
                engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
                engine.load_cuw(raw)
                self.addCleanup(engine.close)
                self.addCleanup(runtime.close)
                controller = fixtures.make_controller(runtime)
                session.bind_controller2026(controller)
                session.bind_engine2026(engine)
                worker = engine.bind_worker(controller)
                pair = engine.interface_pair
                assert pair is not None
                for view in (pair.engine, pair.control):
                    view.set_driver(DriverMetadata2026("authored", "fixture.dll"))
                pair.engine.open()
                pair.engine.connect(6)
                persistence = CUWPersistence(
                    Path(directory),
                    ReproInfoState((RecoveryCalibration("authored.cuw", raw),)),
                )
                engine.bind_persistence(persistence)
                with engine.controller_execution(controller, 1):
                    controller.bind_startup_session(engine, session)
                    empty = controller.empty_control_parameter(engine)
                    self.assertEqual(empty.parameter.headers, ())
                    state = worker.run_gateway_startup()
                    assert state is not None
                    self.assertIs(state.returned, returned)
                    self.assertIs(state.output_flag, returned or hard_error)
                    self.assertFalse(state.classification_returned)
                    self.assertEqual(state.classification, 0)
                    self.assertEqual(engine.repro_gateway_node, 0)
                    self.assertIs(worker.native_initial_command_retry980, returned)
                    self.assertIs(persistence.state.is_central_gw_exist, returned)
                    self.assertIs(controller.dh_mode_could_be_changed, returned)
                    self.assertIs(worker.control_state.failed, hard_error)
                    self.assertEqual(
                        (
                            worker.control_state.error_kind,
                            worker.control_state.primary_error,
                        ),
                        (1, 1) if hard_error else (0, 0),
                    )
                    self.assertEqual(state.primary_error, 1 if hard_error else None)
                    self.assertEqual(state.passthru_status, 7 if hard_error else None)
                    self.assertFalse(session.used)
                    self.assertIsNone(pair.control.channel_id)
                self.assertEqual(runtime.close(), [])
                engine.close()
                self.assertEqual(trace.position, len(rows))

    def run_canonical_startup_writer(self, module, recording):
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )
        from scripts.programming_2026_body import (
            bind_native_context,
            run_native_context,
        )
        from scripts.programming_2026_common import bind_native_parameter2026
        from scripts.programming_replay import load_programming_replay

        raw, _, original_selection, general = self.writer_inputs(module)
        rows = json.loads(
            Path(
                "analysis/evidence/no-car-134",
                recording.replace(".json", "-caller-order.json"),
            ).read_bytes()
        )
        document = {
            "schema": "techstream-programming-replay-v1",
            "source": "recorded_unverified",
            "calibration_sha256": hashlib.sha256(raw).hexdigest(),
            "operation": "get_cid",
            "node": 1,
            "observations": {
                "current_cids": [],
                "tester_info_hex": bytes(32).hex(),
                "system_time": [2026, 10, 2, 20, 1, 2, 3, 4],
                "timeout_seconds": 300,
                "cid_mode": 2,
                "host": {"cpu_index": 0, "driver_recording": "j2534_2026"},
            },
            "events": rows,
        }
        modules = {
            name: Path("runtime/no-car-21/recovered", name).read_bytes()
            for name in (
                "CUW.dll",
                "TCUWControlCommPhase.dll",
                "TCUWJ2534DeviceIF.dll",
                "TCUWCanCIDGetter.dll",
                body_fixtures.BODY,
                module,
            )
        }
        session = load_programming_replay(
            raw,
            json.dumps(document).encode(),
            dict(original_selection.catalog_sources),
            modules,
        )
        trace = session.trace
        runtime = NativeRuntime2026(
            trace.action,
            cleanup_action=trace.cleanup_primitive,
            clock=trace.clock,
            cancelled=trace.cancelled,
            local_seconds_of_day=trace.native_local_seconds_of_day,
            local_milliseconds_of_day=trace.native_local_milliseconds_of_day,
        )
        engine = CUWEngine2026(SOURCE.read_bytes(), general_parameters=general)
        engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
        engine.load_cuw(raw)
        self.addCleanup(engine.close)
        self.addCleanup(runtime.close)
        session.bind_runtime2026(runtime)
        controller = fixtures.make_controller(runtime)
        session.bind_controller2026(controller)
        session.bind_engine2026(engine)
        worker = engine.bind_worker(controller)
        pair = engine.interface_pair
        assert pair is not None
        for view in (pair.engine, pair.control):
            view.set_driver(DriverMetadata2026("authored", "fixture.dll"))
        with engine.controller_execution(controller, 0):
            from scripts.programming_2026_common import (
                _control_has_ordinary_getter_return2026,
            )

            held = controller.native_control_context2026(engine)
            received = controller.execute(engine, session)
            self.assertTrue(_control_has_ordinary_getter_return2026(held))
            worker.import_control_getter_return2026(held)
            self.assertEqual(received["identifiers"], (b"OLD_A", b"OLD_B"))
            self.assertEqual(engine.received_identifiers, (b"OLD_A", b"OLD_B"))
            self.assertTrue(worker.mark_cid_reception_complete())
        self.assertFalse(pair.engine.opened)
        self.assertFalse(pair.engine.connecting)
        pair.engine.open()
        pair.engine.connect(6)
        engine.select_target(1, 1, controller=controller)
        with tempfile.TemporaryDirectory() as directory:
            persistence = CUWPersistence(
                Path(directory),
                ReproInfoState(
                    (RecoveryCalibration("authored.cuw", raw),), write_cpu_index=1
                ),
            )
            engine.bind_persistence(persistence)
            prepare_document = dict(document)
            prepare_document["operation"] = "prepare"
            prepare_document["observations"] = dict(document["observations"])
            prepare_document["observations"]["host"] = {"cpu_index": 1}
            prepare_root = load_programming_replay(
                raw,
                json.dumps(prepare_document).encode(),
                dict(original_selection.catalog_sources),
                modules,
            )
            prepare_root.trace = trace
            prepare_root.bind_runtime2026(runtime)
            with engine.controller_execution(controller, 1):
                controller.bind_startup_session(engine, prepare_root)
                startup = worker.run_gateway_startup()
                assert startup is not None
                self.assertTrue(startup.returned)
                self.assertTrue(startup.classification_returned)
                self.assertEqual(startup.classification, 2)
            self.assertTrue(engine.native_initial_command_retry980)
            selection = bind_native_parameter2026(
                engine.native_metadata.source_container,
                dict(original_selection.catalog_sources),
                "write",
                cpu_index=1,
                metadata_state=engine.native_metadata,
            )
            context = bind_native_context(
                engine.native_metadata.source_container,
                1,
                (),
                selection,
                body_fixtures.identity(module),
                {},
                {
                    "target_index": engine.native_writer_target_index,
                    "retry_password": engine.dh_state.use_new_password,
                    "native_initial_command_retry_980": engine.native_initial_command_retry980,
                },
            )
            with engine.controller_execution(controller, 2):
                pair.import_into(pair.control, pair.export_from(pair.engine))
                result = run_native_context(context, runtime, engine=engine)
            self.assertTrue(result["native_return"], repr(result))
            self.assertEqual(result["counts"], (0, 2048, 0, 0))
            self.assertEqual(runtime.close(), [])
            engine.close()
        self.assertEqual(trace.position, len(rows))
        self.assertIsNot(pair.engine, pair.control)
        id_read = next(
            row
            for row in rows
            if row["request"]["operation"] == "passthru_read"
            and any(
                message.data == bytes.fromhex("00000208") + b"ID"
                for message in self.recorded_messages(row)
            )
        )
        if module == body_fixtures.SONAR_WRITE:
            self.assertEqual(id_read["request"]["timeout"], 10000)

    def test_imported_recovery_classifier3_and255_skip_probe_preserve_raw_bf9(self):
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
            encode_recovery_info,
            parse_recovery_info,
        )

        raw, _, _, general = body_fixtures.writer_selection(
            "TCUWP4CanBodyFlashWriter.dll",
            initialize_prepare=True,
            encoded=True,
            gateway_startup=True,
        )
        for cached in (3, 255):
            with (
                self.subTest(cached=cached),
                tempfile.TemporaryDirectory() as directory,
            ):
                sdk, _, engine, controller, worker, _ = self.context(
                    self.p4_replies()[1:], general=general, source=raw, cpu_index=1
                )
                saved_path = r"C:\authored\Save\fixture.cuw"
                state = ReproInfoState(
                    (RecoveryCalibration("fixture.cuw", raw, saved_path=saved_path),),
                    write_cpu_index=1,
                    repro_gw_node=cached,
                )
                document = parse_recovery_info(encode_recovery_info(state))
                persistence = CUWPersistence.import_recovery(
                    Path(directory), document, {saved_path: raw}, cpu_capacity=4
                )
                engine.bind_persistence(persistence)
                with engine.controller_execution(controller, 1):
                    observed = worker.run_gateway_startup()
                    assert observed is not None
                    self.assertEqual(observed.classification, cached)
                    self.assertEqual(engine.repro_gateway_node, cached)
                    self.assertTrue(worker.native_initial_command_retry)
                    self.assertFalse(worker.control_state.use_new_password)
                    self.assertTrue(persistence.state.is_central_gw_exist)
                self.assertEqual(sdk.replies, [])
                self.assertNotIn(REQUEST + b"\x3e", sdk.writes)
                self.assertEqual(persistence.state.repro_gw_node, cached)

    def test_5a835_ec90_changes_at_actual_gate_and_al_without_immediate_save(self):
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )

        for enabled, failure in ((False, False), (True, True), (True, False)):
            with (
                self.subTest(enabled=enabled, failure=failure),
                tempfile.TemporaryDirectory() as directory,
            ):
                raw, _, _, general = body_fixtures.writer_selection(
                    "TCUWP4CanBodyFlashWriter.dll",
                    initialize_prepare=True,
                    encoded=True,
                    gateway_startup=enabled,
                )
                sdk, _, engine, controller, worker, _ = self.context(
                    self.p4_replies(), general=general, source=raw, cpu_index=1
                )
                persistence = CUWPersistence(
                    Path(directory),
                    ReproInfoState(
                        (RecoveryCalibration("authored.cuw", raw),),
                        write_cpu_index=1,
                        is_central_gw_exist=True,
                    ),
                )
                engine.bind_persistence(persistence)
                observed = []

                def fail(
                    event,
                    *,
                    persistence=persistence,
                    failure=failure,
                    observed=observed,
                ):
                    if event["operation"] == "passthru_ioctl":
                        observed.append(persistence.state.is_central_gw_exist)
                        return failure
                    return False

                sdk.fail = fail
                before = len(persistence.events)
                with engine.controller_execution(controller, 1):
                    state = worker.run_gateway_startup()
                    if enabled:
                        assert state is not None
                        self.assertIs(state.returned, not failure)
                    else:
                        self.assertIsNone(state)
                self.assertIs(
                    persistence.state.is_central_gw_exist, not enabled or not failure
                )
                self.assertEqual(observed, [False] * len(observed))
                self.assertIs(bool(observed), enabled)
                self.assertEqual(len(persistence.events), before)

    def test_new_classification_updates_logged_recovery_before_authentication(self):
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
            parse_recovery_info,
        )

        raw, _, _, general = body_fixtures.writer_selection(
            "TCUWP4CanBodyFlashWriter.dll",
            initialize_prepare=True,
            encoded=True,
            gateway_startup=True,
        )
        replies = self.p4_replies()[:2]
        replies[-1] = replies[-1][0], b"\x7f\x27\x35"
        sdk, _, engine, controller, worker, producer = self.context(
            replies, general=general, source=raw, cpu_index=1
        )
        with tempfile.TemporaryDirectory() as directory:
            persistence = CUWPersistence(
                Path(directory),
                ReproInfoState(
                    (RecoveryCalibration("fixture.cuw", raw),), write_cpu_index=1
                ),
            )
            engine.bind_persistence(persistence)
            persistence.notification.assign(True)
            self.assertTrue(persistence.state.logged)
            before = sum(
                e["operation"] == "encode_recovery" for e in persistence.events
            )
            with (
                self.assertRaises(ValueError),
                engine.controller_execution(controller, 1),
            ):
                worker.run_gateway_startup()
            self.assertFalse(worker.native_initial_command_retry)
            self.assertFalse(producer.source_state.returned)
            self.assertEqual(persistence.state.repro_gw_node, 2)
            self.assertEqual(
                sum(e["operation"] == "encode_recovery" for e in persistence.events),
                before + 1,
            )
            document = parse_recovery_info(
                (Path(directory) / "Save/RecoveryInfo.ini").read_bytes()
            )
            self.assertEqual(document.sections["RecoveryInfo"]["ReproGWNode"], "2")
            self.assertEqual(sdk.replies, [])

    def test_phase_parameter_and_alternate_cid_gates_do_not_invent_980(self):
        for enabled, alternate in ((False, False), (True, True)):
            with self.subTest(enabled=enabled, alternate=alternate):
                sdk, _, engine, controller, worker, _ = self.context(
                    [], general=self.general(enabled)
                )
                controller.alternate_cid_used = alternate
                before = len(sdk.calls)
                with engine.controller_execution(controller, 1):
                    self.assertIsNone(worker.run_gateway_startup())
                    self.assertFalse(worker.native_initial_command_retry)
                self.assertEqual(len(sdk.calls), before)
        _, _, engine, controller, worker, _ = self.context(
            [], general=self.general(True)
        )
        with (
            engine.controller_execution(controller, 0),
            self.assertRaisesRegex(ValueError, "phase1"),
        ):
            worker.run_gateway_startup()
        self.assertFalse(worker.native_initial_command_retry)

    def test_failed_real_startup_cannot_publish_phase1_980(self):
        replies = self.p4_replies()[:2]
        replies[-1] = replies[-1][0], b"\x7f\x27\x35"
        _, _, engine, controller, worker, producer = self.context(
            replies, general=self.general(True)
        )
        with self.assertRaises(ValueError), engine.controller_execution(controller, 1):
            worker.run_gateway_startup()
        self.assertFalse(worker.native_initial_command_retry)
        self.assertFalse(producer.source_state.returned)

    def test_p5_fallback_and_each_business_reply_are_validated(self):
        for index in range(1, 9):
            with self.subTest(index=index):
                sdk, device, engine, controller, _, producer, _ = self.p5_context()
                expected, _ = sdk.replies[index]
                sdk.replies[index] = expected, b"\x7f\x31\x22"
                with self.assertRaises(ValueError):
                    self.run_owned(engine, controller, producer)
                self.assertEqual(device.filters, [])
                self.assertEqual(device.periodics, [])
                self.assertFalse(producer.source_state.returned)

    def test_every_p5_typed_cancellation_cleans_up_before_reporting(self):
        baseline, _, engine, controller, _, producer, _ = self.p5_context()
        self.run_owned(engine, controller, producer)
        start = next(
            index
            for index, event in enumerate(baseline.calls)
            if event["operation"] == "passthru_ioctl"
            and event.get("parameters") == ((0x1E, 1),)
        )
        stop = next(
            index
            for index, event in enumerate(baseline.calls[start:])
            if event["operation"] == "passthru_ioctl"
            and event.get("parameters") == ((0x1E, 0),)
        )
        for position in range(stop):
            with self.subTest(position=position):
                sdk, device, engine, controller, _, producer, _ = self.p5_context()
                seen = 0

                def cancel(_event, position=position, sdk=sdk):
                    nonlocal seen
                    current, seen = seen, seen + 1
                    if current == position:
                        sdk.cancelled = True

                sdk.fail = cancel
                with self.assertRaises(InterruptedError):
                    self.run_owned(engine, controller, producer)
                self.assertEqual(device.filters, [])
                self.assertFalse(producer.source_state.returned)

    def test_every_p5_typed_host_fault_preserves_identity_and_never_returns(self):
        baseline, _, engine, controller, _, producer, _ = self.p5_context()
        self.run_owned(engine, controller, producer)
        start = next(
            index
            for index, event in enumerate(baseline.calls)
            if event["operation"] == "passthru_ioctl"
            and event.get("parameters") == ((0x1E, 1),)
        )
        count = len(baseline.calls) - start
        for position in range(count):
            with self.subTest(position=position):
                sdk, _, engine, controller, _, producer, _ = self.p5_context()
                seen, fired = 0, False
                original = OSError("Authored P5 startup primitive failure")

                def fail(_event, position=position, original=original):
                    nonlocal seen, fired
                    current, seen = seen, seen + 1
                    if current == position and not fired:
                        fired = True
                        raise original

                sdk.fail = fail
                with self.assertRaises(OSError) as caught:
                    self.run_owned(engine, controller, producer)
                self.assertIs(caught.exception, original)
                self.assertTrue(fired)
                self.assertFalse(producer.source_state.returned)

    def test_p5_periodic_cleanup_fault_does_not_replace_online_primary(self):
        seed = bytes(range(16))
        replies = [
            (b"\x3e", 9),
            (b"\x3e\x00", b"\x7e\x00"),
            (b"\x10\x03", b"\x50\x03" + bytes(4)),
            (b"\x27\x21", b"\x67\x21" + seed),
        ]
        sdk, device, engine, controller, _, producer = self.context(replies)

        def fail(event):
            if event["operation"] == "passthru_stop_periodic":
                raise OSError("Authored periodic cleanup failure")

        sdk.fail = fail
        with self.assertRaisesRegex(
            ValueError, "online controller binding required"
        ) as caught:
            self.run_owned(engine, controller, producer)
        self.assertTrue(
            any("periodic cleanup" in note for note in caught.exception.__notes__)
        )
        self.assertEqual(device.filters, [])
        self.assertEqual(device.periodics, [17])

    def test_native_temporary_periodic_stop_fault_resumes_computed_key_send(self):
        sdk, device, engine, controller, _, producer, capture = self.p5_context()
        fired = False

        def fail(event):
            nonlocal fired
            if event["operation"] == "passthru_stop_periodic" and not fired:
                fired = True
                return True
            return False

        sdk.fail = fail
        state = self.run_owned(engine, controller, producer)
        self.assertTrue(state.returned)
        self.assertEqual(state.periodic_identifier, 18)
        self.assertEqual(device.periodics, [17, 18])
        with (
            engine.controller_execution(controller, 0),
            controller.runtime.engine_device_calls(engine),
        ):
            self.assertTrue(
                controller.runtime.owns_resource("stop_periodic", identifier=17)
            )
        self.assertTrue(capture.used)
        self.assertEqual(sdk.replies, [])

    def test_non_timeout_j2534_fault_does_not_reclassify(self):
        sdk, device, engine, controller, _, producer = self.context([(b"\x3e", 7)])
        with self.assertRaises(Exception) as caught:
            self.run_owned(engine, controller, producer)
        self.assertEqual(getattr(caught.exception, "passthru_status", None), 7)
        self.assertEqual(producer.source_state.classification, 0)
        self.assertFalse(producer.source_state.returned)
        self.assertEqual(len(sdk.writes), 1)
        self.assertEqual(device.filters, [])

    def test_native_initial_config_fault_has_no_business_restore(self):
        sdk, _, engine, controller, _, producer = self.context([])
        sdk.fail = lambda event: (
            event["operation"] == "passthru_ioctl" and event["ioctl"] == 2
        )
        with self.assertRaises(Exception) as caught:
            self.run_owned(engine, controller, producer)
        self.assertEqual(getattr(caught.exception, "passthru_status", None), 7)
        configs = [
            e["parameters"]
            for e in sdk.calls
            if e["operation"] == "passthru_ioctl" and e["ioctl"] == 2
        ]
        self.assertEqual(configs, [((0x1E, 1),)])

    def test_native_restore_fault_skips_stop_filter_and_keeps_owner(self):
        sdk, device, engine, controller, _, producer = self.context(self.p4_replies())
        sdk.fail = lambda event: (
            event["operation"] == "passthru_ioctl"
            and event.get("parameters") == ((0x1E, 0),)
        )
        with self.assertRaises(Exception) as caught:
            self.run_owned(engine, controller, producer)
        self.assertEqual(getattr(caught.exception, "passthru_status", None), 7)
        self.assertEqual(device.filters, [11])
        self.assertFalse(
            any(e["operation"] == "passthru_stop_filter" for e in sdk.calls)
        )
        self.assertFalse(producer.source_state.returned)

    def test_native_stop_filter_fault_is_swallowed_but_resource_stays_owned(self):
        sdk, device, engine, controller, _, producer = self.context(self.p4_replies())
        fired = False

        def fail(event):
            nonlocal fired
            if event["operation"] == "passthru_stop_filter" and not fired:
                fired = True
                return True
            return False

        sdk.fail = fail
        self.assertTrue(self.run_owned(engine, controller, producer).returned)
        self.assertTrue(fired)
        self.assertEqual(device.filters, [11])
        self.assertEqual(controller.runtime.close(), [])
        self.assertEqual(device.filters, [])

    def test_native_unknown_business_fault_is_mapped9999_after_cleanup(self):
        sdk, device, engine, controller, _, producer = self.context([])
        original = NativeException2026("Authored unknown native fault")

        def fail(event):
            if event["operation"] == "passthru_start_filter":
                raise original

        sdk.fail = fail
        with self.assertRaises(NativePassThruException2026) as caught:
            self.run_owned(engine, controller, producer)
        self.assertEqual(caught.exception.native_error_code, 9999)
        self.assertIs(caught.exception.__cause__, original)
        self.assertEqual(device.filters, [])
        configs = [
            e["parameters"]
            for e in sdk.calls
            if e["operation"] == "passthru_ioctl" and e["ioctl"] == 2
        ]
        self.assertEqual(configs, [((0x1E, 1),), ((0x1E, 0),)])

    def test_wrong_positive_authentication_and_mode_never_return_success(self):
        for index in (1, 2, 3):
            with self.subTest(index=index):
                replies = self.p4_replies()[: index + 1]
                replies[-1] = (replies[-1][0], b"\x7f\x27\x35")
                _, device, engine, controller, _, producer = self.context(replies)
                with self.assertRaises(ValueError):
                    self.run_owned(engine, controller, producer)
                self.assertFalse(producer.source_state.returned)
                self.assertEqual(device.filters, [])

    def test_issuer_owner_phase_and_crypto_binding_are_enforced(self):
        _, device, engine, controller, worker, producer = self.context(
            self.p4_replies()
        )
        with self.assertRaises(TypeError):
            GatewayStartup2026(engine, worker)
        with self.assertRaises(ValueError):
            producer.run()
        with self.assertRaises(ValueError):
            producer.validate_owner(object(), worker)
        controller.runtime._central_gateway_key = None
        with self.assertRaisesRegex(ValueError, "Same-engine"):
            self.run_owned(engine, controller, producer)
        self.assertEqual(device.filters, [])
        self.assertFalse(producer.source_state.returned)

    def test_cancellation_after_filter_acquisition_rolls_back_every_resource(self):
        sdk, device, engine, controller, _, producer = self.context([])
        sdk.fail = lambda op: (
            setattr(sdk, "cancelled", True)
            if op["operation"] == "passthru_start_filter"
            else False
        )
        with self.assertRaises(InterruptedError):
            self.run_owned(engine, controller, producer)
        self.assertEqual(device.filters, [])
        self.assertFalse(producer.source_state.returned)

    def test_every_p4_typed_host_fault_preserves_identity_and_never_returns(self):
        baseline, _, engine, controller, _, producer = self.context(self.p4_replies())
        self.run_owned(engine, controller, producer)
        start = next(
            index
            for index, event in enumerate(baseline.calls)
            if event["operation"] == "passthru_ioctl"
            and event.get("parameters") == ((0x1E, 1),)
        )
        count = len(baseline.calls) - start
        for position in range(count):
            with self.subTest(position=position):
                sdk, _, engine, controller, _, producer = self.context(
                    self.p4_replies()
                )
                seen, fired = 0, False
                original = OSError("Authored startup primitive failure")

                def fail(_event, position=position, original=original):
                    nonlocal seen, fired
                    current, seen = seen, seen + 1
                    if current == position and not fired:
                        fired = True
                        raise original

                sdk.fail = fail
                with self.assertRaises(OSError) as caught:
                    self.run_owned(engine, controller, producer)
                self.assertIs(caught.exception, original)
                self.assertTrue(fired)
                self.assertFalse(producer.source_state.returned)

    def test_every_p4_typed_cancellation_cleans_up_before_reporting(self):
        baseline, _, engine, controller, _, producer = self.context(self.p4_replies())
        self.run_owned(engine, controller, producer)
        start = next(
            index
            for index, event in enumerate(baseline.calls)
            if event["operation"] == "passthru_ioctl"
            and event.get("parameters") == ((0x1E, 1),)
        )
        # Native cleanup runs uncancelled; cancellation during cleanup itself
        # cannot retroactively invalidate a successful wire operation.
        stop = next(
            index
            for index, event in enumerate(baseline.calls[start:])
            if event["operation"] == "passthru_ioctl"
            and event.get("parameters") == ((0x1E, 0),)
        )
        for position in range(stop):
            with self.subTest(position=position):
                sdk, device, engine, controller, _, producer = self.context(
                    self.p4_replies()
                )
                seen = 0

                def cancel(_event, position=position, sdk=sdk):
                    nonlocal seen
                    current, seen = seen, seen + 1
                    if current == position:
                        sdk.cancelled = True

                sdk.fail = cancel
                with self.assertRaises(InterruptedError):
                    self.run_owned(engine, controller, producer)
                self.assertEqual(device.filters, [])
                self.assertFalse(producer.source_state.returned)


if __name__ == "__main__":
    unittest.main()
