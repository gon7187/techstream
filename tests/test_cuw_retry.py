"""Authored native retry input and real engine controller contract checks."""

import importlib.util
import io
import json
import struct
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path

from scripts.calibration_2026 import native2026_logical_cpu_flash_size, parse_cuw_2026
from scripts.cuw_2026 import CUWEngine2026
from scripts.cuw_file_services import admit_file_sources_2026
from scripts.cuw_persistence import (
    CUWPersistence,
    RecoveryCalibration,
    ReproInfoState,
    encode_nibble_text,
    encode_recovery_info,
    parse_recovery_info,
)
from scripts.cuw_retry import (
    RetryController2026,
    RetryInput2026,
    _issue_retry_controller,
    _notification_configuration,
)
from scripts.j2534_2026 import (
    DriverMetadata2026,
    J2534Device2026,
    J2534InterfacePair2026,
    NativeJ2534Error2026,
    PrimitiveResult,
)
from scripts.programming_2026_common import NativeRuntime2026
from tests.private_evidence import require_private
from tests.test_calibration_2026 import cuw, logical_text
from tests.test_cuw_engine_worker import calibration, make_controller
from tests.test_j2534_2026 import LiveOSProvider


def bind_pair(engine, runtime, device):
    """Bind actual separate CONTROL and CUW views with one authored provider."""
    control_device = J2534Device2026(
        device.provider,
        clock=device.clock,
        cancelled=device.cancelled,
        background_workers=device.background_workers,
        max_calls=device.max_calls,
        max_cleanup_calls=device.max_cleanup_calls,
    )
    control_device.set_version(device.version)
    if device.driver is not None:
        control_device.set_driver(device.driver)
    control_device.driver_versions = list(device.driver_versions)
    pair = J2534InterfacePair2026(device, control_device)
    runtime.action = control_device.primitive
    engine.bind_interface_pair(pair)
    return pair


class RetryInputTests(unittest.TestCase):
    def test_literal_native_input_values_are_preserved(self):
        for result in (-2147483648, -1, 0, 1, 2, 2147483647):
            for option in (0, 1, 255):
                event = RetryInput2026(7, result, option)
                self.assertEqual(
                    (event.sequence, event.native_result, event.native_option),
                    (7, result, option),
                )

    def test_malformed_values_are_not_coerced(self):
        for values in (
            (0, 1, 0),
            (True, 1, 0),
            (1, True, 0),
            (1, 2**31, 0),
            (1, -(2**31) - 1, 0),
            (1, 1, -1),
            (1, 1, 256),
            (1, 1, True),
        ):
            with self.subTest(values=values), self.assertRaises(ValueError):
                RetryInput2026(*values)

    def test_native_rcn_colors_signed_stol_and_message_bytes(self):
        source = b"".join(
            b"[" + section + b"]\r\nRed1=-1\r\nGreen1=257\r\nBlue1=258\r\n"
            b"Red2=3\r\nGreen2=4\r\nBlue2=5\r\nBlinkCycle=-1tail\r\n"
            b"Message1=\xa0\r\nMessage2=authored error\r\n"
            for section in (b"Success", b"Error")
        )
        records = _notification_configuration(
            encode_nibble_text(source, noise=lambda: 0)
        )
        self.assertEqual(records[1].kind, 1)
        self.assertEqual(
            (records[1].color1, records[1].color2, records[1].blink_cycle),
            (0x0201FF, 0x050403, 0xFFFFFFFF),
        )
        self.assertEqual(
            (records[1].message1, records[1].message2), (b"\xa0", b"authored error")
        )

    def test_direct_controller_construction_is_rejected(self):
        with self.assertRaises(TypeError):
            RetryController2026(None, None)  # pyright: ignore[reportArgumentType] - malformed constructor boundary


class RetryControllerTests(unittest.TestCase):
    def setUp(self):
        path = Path("runtime/no-car-21/recovered/CUW.dll")
        if not path.is_file():
            self.skipTest("Private authenticated static CUW2026 source unavailable")
        self.engine = CUWEngine2026(path.read_bytes())
        self.engine.configure(struct.pack("<IIddII", 4, 0, 5.0, 13.0, 0, 0))
        self.engine.load_cuw(calibration())
        self.runtime = NativeRuntime2026(lambda *_args, **_kw: None)
        self.control = make_controller(self.runtime)
        self.worker = self.engine.bind_worker(self.control)
        self.retry = self.engine.bind_retry_controller()
        self.addCleanup(self.engine.close)

    def test_prepare_prefix_retains_real_modal_result_and_clears_checkpoint(self):
        from scripts.cuw_online import OnlineKeyController2026
        from tests.test_cuw_online import configuration

        online = OnlineKeyController2026(self.worker, configuration())
        online.start(bytes(16))
        with self.engine.controller_execution(self.control, 0):
            self.retry.callback3()
            self.retry.record_callback30(7)
        self.assertEqual(self.retry.result, 1)
        self.runtime.local_milliseconds_of_day = lambda: 54321
        with self.engine.controller_execution(self.control, 1):
            self.assertEqual(self.retry.result, 1)
            self.assertEqual(self.retry._checkpoint_byte, 0)
            self.assertEqual(self.retry.source_state.resume_milliseconds_d314, 54321)
            self.assertEqual(self.engine._native_prepare_d314_2026, 54321)

    def test_lazy_retry_constructor_preserves_actual_prepare_clock(self):
        engine = CUWEngine2026(Path("runtime/no-car-21/recovered/CUW.dll").read_bytes())
        self.addCleanup(engine.close)
        engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
        engine.load_cuw(calibration())
        runtime = NativeRuntime2026(
            lambda *_args, **_kw: None, local_milliseconds_of_day=lambda: 23456
        )
        control = make_controller(runtime)
        engine.bind_worker(control)
        self.assertIsNone(engine._retry_controller)
        self.assertEqual(engine._native_prepare_d314_2026, 0)
        with engine.controller_execution(control, 1):
            pass
        retry = engine.bind_retry_controller()
        self.assertEqual(retry.source_state.resume_milliseconds_d314, 23456)
        self.assertEqual(engine._native_prepare_d314_2026, 23456)

    def test_actual_failed_dh_export_consumes_input_and_retained_prepare_retry(self):
        require_private(
            "runtime/no-car-119/verify_failed_dh_retry.py",
            "runtime/no-car-119/dh_retry_fixture.py",
            "runtime/no-car-119/verify_failed_sonar_retry.py",
            "runtime/no-car-119/sonar_retry_fixture.py",
        )
        spec = importlib.util.spec_from_file_location(
            "private119_failed_dh", "runtime/no-car-119/verify_failed_dh_retry.py"
        )
        assert spec is not None and spec.loader is not None
        proof = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(proof)
        for decision in (0, 1):
            with self.subTest(native_result=decision):
                path = Path(f"runtime/no-car-119/failed-dh-query-{decision}.json")
                if not path.is_file():
                    self.skipTest("Private authored native SDK capture unavailable")
                _, receipt = proof.exercise(
                    decision, events=json.loads(path.read_bytes())
                )
                self.assertEqual(receipt["failed_native_code"], 1)
                self.assertTrue(receipt["source_prepare_retry_flag"])
                self.assertEqual(receipt["source_retry_decision"], decision == 1)
                self.assertEqual(receipt["native_prepare_retry_exports"], decision)
                self.assertTrue(receipt["exact_final_trace"])

    def test_actual_failed_sonar_export_consumes_captured_query_input(self):
        require_private(
            "runtime/no-car-119/verify_failed_sonar_retry.py",
            "runtime/no-car-119/sonar_retry_fixture.py",
        )
        spec = importlib.util.spec_from_file_location(
            "private119_failed_sonar", "runtime/no-car-119/verify_failed_sonar_retry.py"
        )
        assert spec is not None and spec.loader is not None
        proof = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(proof)
        for decision in (0, 1):
            with self.subTest(native_result=decision):
                path = Path(f"runtime/no-car-119/failed-sonar-query-{decision}.json")
                if not path.is_file():
                    self.skipTest("Private authored native SDK capture unavailable")
                _, receipt = proof.exercise(
                    decision, events=json.loads(path.read_bytes())
                )
                self.assertEqual(receipt["failed_native_code"], 7)
                self.assertFalse(receipt["source_prepare_retry_flag"])
                self.assertEqual(receipt["source_retry_decision"], decision == 1)
                self.assertTrue(receipt["exact_final_trace"])

    def test_external_native_version_fault_acknowledges_actual_parked_child(self):
        require_private(
            "runtime/no-car-next-20261022/retry-regressions/prepare_ack.py",
        )
        spec = importlib.util.spec_from_file_location(
            "retry_regression_prepare_ack",
            "runtime/no-car-next-20261022/retry-regressions/prepare_ack.py",
        )
        assert spec is not None and spec.loader is not None
        proof = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(proof)
        for delayed in (False, True):
            with self.subTest(delayed=delayed):
                suffix = "delayed" if delayed else "parked"
                path = Path(
                    f"runtime/no-car-next-20261022/retry-regressions/prepare-ack-{suffix}-sdk.json"
                )
                if not path.is_file():
                    self.skipTest("Private authored native SDK capture unavailable")
                _, receipt = proof.exercise(
                    json.loads(path.read_bytes()), delayed=delayed
                )
                self.assertEqual(receipt["handshake"], [1, 2])
                self.assertTrue(receipt["ordinary_prepare_receipt_consumed"])
                self.assertEqual(receipt["canonical_prepare_clock"], 1000)
                self.assertTrue(receipt["actual_child_still_alive"])
                self.assertTrue(receipt["actual_child_waiting_for_resume"])
                self.assertEqual(receipt["captured_retry_inputs"], 0)
                self.assertEqual(
                    receipt["external_wait_observed_before_actual_park"], delayed
                )
                self.assertTrue(receipt["exact_final_trace"])

    def test_callback30_byte_survives_scope_entry_until_source_consumer(self):
        self.control.runtime.local_milliseconds_of_day = lambda: 123
        with self.engine.controller_execution(self.control, 0):
            self.retry.record_callback30(1)
        with self.engine.controller_execution(self.control, 0):
            self.retry._wait_worker_resume()
        self.assertEqual(self.retry.source_state.resume_milliseconds_d314, 123)
        self.assertEqual(self.engine._native_prepare_d314_2026, 123)
        self.assertEqual(self.retry._checkpoint_byte, 0)
        self.assertEqual(self.retry.inputs, ())

    def test_actual_worker_exit_ends_query_observer_without_native_decision(self):
        with self.engine.controller_execution(self.control, 0):
            pass
        with self.assertRaisesRegex(RuntimeError, "worker stopped"):
            self.retry.wait_for_query()
        self.assertEqual(self.retry.queries, ())
        self.assertEqual(self.retry.inputs, ())

    def test_actual_online_modal_producer_bypasses_native_query(self):
        from scripts.cuw_online import OnlineKeyController2026
        from tests.test_cuw_online import configuration

        online = OnlineKeyController2026(self.worker, configuration())
        online.start(bytes(16))
        self.assertEqual(self.engine.online_modal_state, 6)
        with self.engine.controller_execution(self.control, 0):
            self.retry.callback3()
        self.assertEqual(self.retry.source_state.result14, 1)
        self.assertFalse(self.engine.write_complete_output)
        self.assertEqual(self.retry.queries, ())
        self.assertEqual(self.retry.inputs, ())

    def test_issue_reuses_exact_engine_worker(self):
        self.assertIs(_issue_retry_controller(self.engine, self.worker), self.retry)
        self.assertIs(self.retry.engine, self.engine)
        self.assertIs(self.retry.worker, self.worker)
        with self.assertRaises(TypeError):
            _issue_retry_controller(self.engine, object())

    def test_native_cid_stop_reissue_preserves_captured_retry_globals(self):
        from tests.test_cuw_engine_threads import ThreadOwnershipTests

        fixture = ThreadOwnershipTests()
        self.addCleanup(fixture.doCleanups)
        engine, control, job, session = fixture.imported_prepare(operation="get_cid")
        retry = engine.bind_retry_controller()
        old = engine.worker
        control.runtime.local_milliseconds_of_day = lambda: 0
        failures = []

        def query():
            try:
                with engine.controller_execution(control, 0):
                    engine.dh_state.record_native_error(7, 8, 0)
                    engine.notify_native_error_kind()
                    engine.notify_native_errors()
                    retry.callback3()
            except Exception as error:  # noqa: BLE001 - actual scoped source consumer
                failures.append(error)

        thread = threading.Thread(target=query)
        thread.start()
        try:
            retry.wait_for_query()
            self.assertEqual(engine.inform_result_of_query_retry(1, 231), 0)
        finally:
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        shared = engine.bind_cleanup_controller().state
        history, counters = shared.history, shared.vectors[0xD33C]
        resume, changed, stopped = retry._resume, retry._changed, retry._stopped
        source = retry.source_state
        configuration = engine.configuration
        assert configuration is not None
        self.assertEqual(
            source.error_counts38c, (1,) + (0,) * (configuration.cpu_maximum - 1)
        )
        self.assertEqual(retry.native_option, 231)
        with self.assertRaises(TypeError):
            retry.rebind_worker(object(), object())
        with self.assertRaises(ValueError):
            retry.rebind_worker(old, old)
        fault = ValueError("authored native CID clock capture fault")

        def clock_fault():
            raise fault

        session.trace.native_local_milliseconds_of_day = clock_fault
        control.runtime.local_milliseconds_of_day = clock_fault
        session.bind_runtime2026(control.runtime)
        session.bind_engine2026(engine)
        session.bind_controller2026(control)
        job.start(session)
        self.assertTrue(engine.native_receiving_cfe2_2026)
        with self.assertRaises(ValueError) as caught:
            job.result(2)
        self.assertIs(caught.exception, fault)
        source = retry.source_state
        self.assertEqual(engine.stop_receiving_cid(timeout=2), 0)
        control.runtime.local_milliseconds_of_day = lambda: 0
        replacement = engine.bind_thread_job(control)
        self.assertIsNot(replacement, job)
        self.assertIsNot(engine.worker, old)
        self.assertIs(engine.bind_retry_controller(), retry)
        self.assertIs(retry.worker, engine.worker)
        self.assertIs(engine.bind_cleanup_controller().state.history, history)
        self.assertIs(engine.bind_cleanup_controller().state.vectors[0xD33C], counters)
        self.assertIs(retry._resume, resume)
        self.assertIs(retry._changed, changed)
        self.assertIs(retry._stopped, stopped)
        self.assertEqual(retry.source_state, source)
        self.assertEqual(retry.inputs, (RetryInput2026(1, 1, 231),))
        self.assertEqual(engine.inform_result_of_query_retry(1, 0), 3005)

    def test_query_observer_waits_actual_reserved_job_before_child_adoption(self):
        from tests.test_cuw_engine_threads import ThreadOwnershipTests

        fixture = ThreadOwnershipTests()
        self.addCleanup(fixture.doCleanups)
        engine, control, job, session = fixture.imported_prepare(operation="get_cid")
        retry = engine.bind_retry_controller()
        control.runtime.local_milliseconds_of_day = lambda: 0
        with engine.controller_execution(control, 0):
            pass
        child_entered, release_child, observer_done = (
            threading.Event(),
            threading.Event(),
            threading.Event(),
        )
        fault = ValueError("authored CID clock boundary fault")

        def cancelled():
            if threading.current_thread().name == "CUW2026-5ccd0":
                child_entered.set()
                if not release_child.wait(2):
                    raise TimeoutError("Authored child host boundary was not released")
            return False

        def clock_fault():
            raise fault

        session.trace.cancelled = control.runtime.cancelled = cancelled
        session.trace.native_local_milliseconds_of_day = clock_fault
        control.runtime.local_milliseconds_of_day = clock_fault
        failures = []

        def observe():
            try:
                retry.wait_for_query()
            except Exception as error:  # noqa: BLE001 - actual host observer outcome
                failures.append(error)
            finally:
                observer_done.set()

        job.start(session)
        observer = threading.Thread(target=observe, daemon=True)
        try:
            self.assertTrue(child_entered.wait(1))
            self.assertTrue(job.native_work_pending)
            self.assertTrue(retry._stopped.is_set())
            observer.start()
            self.assertFalse(observer_done.wait(0.03))
        finally:
            release_child.set()
        with self.assertRaises(ValueError) as caught:
            job.result(2)
        self.assertIs(caught.exception, fault)
        observer.join(2)
        self.assertFalse(observer.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], RuntimeError)
        self.assertEqual(retry.queries, ())
        self.assertEqual(retry.inputs, ())

    def test_no_query_returns_literal_3005_and_retains_globals(self):
        self.engine.dh_state.record_native_error(3, 1008, 7)
        self.engine.notify_native_error_kind()
        self.assertEqual(self.retry.inform_result(1, 255), 3005)
        self.assertEqual(self.engine.native_error_kind_output, 3)
        self.assertEqual(self.retry.inputs, ())
        self.assertFalse(self.retry.query_pending)

    def concrete_device(self, *, millivolts=12345, fault=None):
        calls = []

        def provider(operation, _remaining):
            calls.append(operation)
            if fault is not None:
                raise fault
            if operation["operation"] == "passthru_read_version":
                return PrimitiveResult(value=("fw", "dll", "api"))
            if operation["operation"] == "passthru_ioctl":
                return PrimitiveResult(
                    value=millivolts if operation["ioctl"] == 3 else None
                )
            self.fail(f"Unexpected native primitive {operation}")

        self._captured_provider = provider
        if self.engine.interface_pair is None:
            device = J2534Device2026(
                lambda operation, remaining: self._captured_provider(
                    operation, remaining
                ),
                background_workers=False,
            )
            device.set_driver(DriverMetadata2026("authored", "authored.dll"))
            device.opened, device.device_id = True, 7
            device.connecting, device.channel_id = True, 8
            bind_pair(self.engine, self.runtime, device)
        return self.engine.engine_runtime_device(), calls

    def test_connection_check_requires_engine_pair_before_using_control_view(self):
        calls = []
        device = J2534Device2026(
            lambda operation, _remaining: calls.append(operation) or PrimitiveResult(),
            background_workers=False,
        )
        device.set_driver(DriverMetadata2026("authored", "authored.dll"))
        self.runtime.action = device.primitive
        self.assertEqual(self.retry.check_j2534_connection(), 4003)
        self.assertEqual(calls, [])
        self.assertIs(self.control.runtime_device(), device)

    def test_public_connection_check_before_worker_uses_real_device_primitives(self):
        capture = {"millivolts": 1001, "fault": None}
        calls = []

        def provider(operation, _remaining):
            calls.append(operation)
            name = operation["operation"]
            if name == "passthru_open":
                return PrimitiveResult(value=7)
            if name == "passthru_connect":
                return PrimitiveResult(value=8)
            if name == "passthru_read_version":
                if capture["fault"] is not None:
                    raise capture["fault"]
                return PrimitiveResult(value=("authored", "1", "1"))
            if name == "passthru_ioctl":
                return PrimitiveResult(
                    value=capture["millivolts"] if operation["ioctl"] == 3 else None
                )
            return PrimitiveResult()

        engine_device = J2534Device2026(provider, background_workers=False)
        control_device = J2534Device2026(provider, background_workers=False)
        descriptor = DriverMetadata2026("authored", "authored.dll")
        engine_device.set_driver(descriptor)
        control_device.set_driver(descriptor)
        pair = J2534InterfacePair2026(engine_device, control_device)
        with CUWEngine2026(
            Path("runtime/no-car-21/recovered/CUW.dll").read_bytes()
        ) as engine:
            engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
            engine.bind_interface_pair(pair)
            self.assertEqual(engine.check_j2534_connection(), 4003)
            self.assertEqual(calls, [])
            engine.load_cuw(calibration())
            engine_device.open()
            engine_device.connect(6)
            try:
                self.assertEqual(engine.check_j2534_connection(), 0)
                capture["millivolts"] = 1000
                self.assertEqual(engine.check_j2534_connection(), 4012)
                fault = OSError("authored standalone version capture fault")
                capture["fault"] = fault
                with self.assertRaises(OSError) as caught:
                    engine.check_j2534_connection()
                self.assertIs(caught.exception, fault)
                self.assertIsNone(engine._worker)
                self.assertFalse(control_device.opened)
                self.assertFalse(control_device.connecting)
            finally:
                capture["fault"] = None
                engine_device.clear()

    def test_actual_device_connection_check_low_battery_literal_boundary(self):
        self.concrete_device(millivolts=1000)
        self.assertEqual(self.retry.check_j2534_connection(), 4012)
        self.concrete_device(millivolts=1001)
        self.assertEqual(self.retry.check_j2534_connection(), 0)

    def test_actual_device_connection_probe_order_and_status3(self):
        _device, calls = self.concrete_device()
        self.engine.dh_state.record_native_error(3, 7, 0)
        self.engine.notify_native_error_kind()
        self.assertEqual(self.retry.check_j2534_connection(), 4005)
        self.assertEqual(
            [(item["operation"], item.get("ioctl")) for item in calls],
            [
                ("passthru_read_version", None),
                ("passthru_ioctl", 1),
                ("passthru_ioctl", 3),
                ("passthru_read_version", None),
                ("passthru_ioctl", 1),
            ],
        )

    def test_actual_native_reconnect_selects_j2534_version_and_disconnects(self):
        original = parse_cuw_2026(calibration()).attached.data.decode("ascii")
        for contact, initial, wanted, protocol in (
            ("P5-Unified", 1, 0, 6),
            ("Ethernet", 0, 1, 0x800F),
        ):
            with self.subTest(contact=contact):
                provider = LiveOSProvider()
                provider.responses["passthru_scan_devices"] = PrimitiveResult(value=1)
                provider.responses["passthru_next_device"] = PrimitiveResult(
                    value="authored"
                )
                provider.responses["passthru_connect_0500"] = PrimitiveResult(value=2)
                device = J2534Device2026(provider, background_workers=False)
                device.set_version(initial)
                device.set_driver(
                    DriverMetadata2026("authored", f"initial{initial}.dll")
                )
                device.driver_versions[wanted] = DriverMetadata2026(
                    "authored", f"wanted{wanted}.dll"
                )
                source = cuw(original.replace("P5-Unified", contact))
                try:
                    with CUWEngine2026(
                        Path("runtime/no-car-21/recovered/CUW.dll").read_bytes()
                    ) as engine:
                        engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
                        engine.load_cuw(source)
                        controller = make_controller(
                            NativeRuntime2026(device.primitive)
                        )
                        engine.bind_worker(controller)
                        bind_pair(engine, controller.runtime, device)
                        retry = engine.bind_retry_controller()
                        self.assertEqual(retry.check_j2534_connection(), 0)
                        self.assertEqual(device.version, wanted)
                        self.assertFalse(device.connecting)
                        loads = [
                            item["name"]
                            for item, _ in provider.calls
                            if item["operation"] == "passthru_load_library"
                        ]
                        self.assertEqual(loads, [f"wanted{wanted}.dll"])
                        connections = [
                            item
                            for item, _ in provider.calls
                            if item["operation"]
                            in ("passthru_connect", "passthru_connect_0500")
                        ]
                        self.assertEqual(connections[0]["protocol"], protocol)
                finally:
                    device.clear()
                self.assertEqual(provider.handles, {})

    def test_native_connection_errors_keep_primary_enum_distinct_from_sdk_status(self):
        for operation, result, expected in (
            ("load_library", PrimitiveResult(value=0), 4004),
            ("passthru_open", PrimitiveResult(status=1008), 4005),
        ):
            with self.subTest(operation=operation):
                provider = LiveOSProvider()
                provider.responses[operation] = result
                device = J2534Device2026(provider, background_workers=False)
                device.set_driver(DriverMetadata2026("authored", "authored.dll"))
                try:
                    with CUWEngine2026(
                        Path("runtime/no-car-21/recovered/CUW.dll").read_bytes()
                    ) as engine:
                        engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
                        engine.load_cuw(calibration())
                        runtime = NativeRuntime2026(device.primitive)
                        engine.bind_worker(make_controller(runtime))
                        bind_pair(engine, runtime, device)
                        retry = engine.bind_retry_controller()
                        self.assertEqual(retry.check_j2534_connection(), expected)
                        self.assertEqual(retry.inputs, ())
                finally:
                    device.clear()
                self.assertEqual(provider.handles, {})

    def test_phase6_canfd_detection_uses_native_node_protocol_field(self):
        original = parse_cuw_2026(calibration()).attached.data.decode("ascii")
        source = cuw(
            original.replace("P5-Unified", "Phase6").replace(
                "[Node01]", "[Node01]\nProtocol=02"
            )
        )
        provider = LiveOSProvider()
        provider.responses["passthru_ioctl"] = PrimitiveResult(status=7)
        device = J2534Device2026(provider, background_workers=False)
        device.set_driver(DriverMetadata2026("authored", "authored.dll"))
        try:
            with CUWEngine2026(
                Path("runtime/no-car-21/recovered/CUW.dll").read_bytes()
            ) as engine:
                engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
                engine.load_cuw(source)
                controller = make_controller(NativeRuntime2026(device.primitive))
                engine.bind_worker(controller)
                bind_pair(engine, controller.runtime, device)
                retry = engine.bind_retry_controller()
                self.assertEqual(retry.check_j2534_connection(), 4013)
                self.assertTrue(
                    any(
                        item["operation"] == "passthru_ioctl"
                        for item, _ in provider.calls
                    )
                )
        finally:
            device.clear()
        self.assertEqual(provider.handles, {})

    def test_connection_probe_host_fault_retains_identity(self):
        fault = OSError("authored primitive capture fault")
        self.concrete_device(fault=fault)
        with self.assertRaises(OSError) as caught:
            self.retry.check_j2534_connection()
        self.assertIs(caught.exception, fault)
        self.assertEqual(self.retry.inputs, ())

    def test_missing_actual_device_selection_returns4003_without_io(self):
        device, calls = self.concrete_device()
        device.driver = None
        self.assertEqual(self.retry.check_j2534_connection(), 4003)
        self.assertEqual(calls, [])

    def test_real_error_query_wait_preserves_host_fault_and_retained_kind(self):
        backing = self.engine.native_metadata.source_container
        original_digest = self.engine.source_sha256
        cancel = threading.Event()
        fault = OSError("authored input capture failed while query waits")
        failures = []

        def cancelled():
            if cancel.is_set():
                raise fault
            return False

        self.runtime.cancelled = cancelled

        def worker():
            try:
                with self.engine.controller_execution(self.control, 0):
                    self.engine.dh_state.record_native_error(3, 1008, 17)
                    self.engine.notify_native_error_kind()
                    self.engine.notify_native_errors()
                    self.retry.callback3()
            except OSError as error:
                failures.append(error)

        thread = threading.Thread(target=worker)
        thread.start()
        try:
            query = self.retry.wait_for_query()
            self.assertEqual(
                (
                    query.sequence,
                    query.error_kind,
                    query.primary_error,
                    query.passthru_error,
                    query.recovery_status,
                ),
                (1, 3, 1008, 17, 3),
            )
            self.assertTrue(self.retry.query_pending)
            self.assertEqual(self.engine.native_previous_error_kind_output, 3)
            self.assertEqual(self.retry.inputs, ())
        finally:
            cancel.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertIs(failures[0], fault)
        self.assertFalse(self.retry.query_pending)
        self.assertEqual(self.engine.native_error_output, (1008, 17))
        self.assertEqual(self.retry.source_state.error_counts38c, (0, 0, 0, 0))
        self.assertIs(self.engine.native_metadata.source_container, backing)
        self.assertEqual(self.engine.source_sha256, original_digest)

    def test_actual_engine_captured_5e950_input_resumes_query_consumer(self):
        shared = self.engine.bind_cleanup_controller().state
        shared.history[0] = 0xA5
        shared.history[-1] = 0x5A
        observations = []
        failures = []

        def worker():
            try:
                with self.engine.controller_execution(self.control, 0):
                    self.engine.dh_state.record_native_error(3, 1008, 17)
                    self.engine.notify_native_error_kind()
                    self.engine.notify_native_errors()
                    self.retry.callback3()
                    observations.append(
                        (
                            self.engine.write_complete_output,
                            self.engine.native_error_kind_output,
                            self.engine.native_previous_error_kind_output,
                            self.engine.native_error_output,
                            self.retry.query_pending,
                        )
                    )
            except Exception as error:  # noqa: BLE001 - capture cross-thread identity for this test
                failures.append(error)

        thread = threading.Thread(target=worker)
        thread.start()
        try:
            query = self.retry.wait_for_query()
            self.assertEqual(query.error_kind, 3)
            for result, option in ((True, 0), (1, True), (2**31, 0), (1, 256)):
                with self.assertRaises(ValueError):
                    self.engine.inform_result_of_query_retry(result, option)
                self.assertTrue(self.retry.query_pending)
                self.assertEqual(self.engine.native_error_output, (1008, 17))
            with self.assertRaises(ValueError):
                self.retry.close()
            self.assertEqual(self.retry.inputs, ())
            self.assertEqual(self.engine.inform_result_of_query_retry(1, 231), 0)
        finally:
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(observations, [(True, 0, 0, (0, 0), False)])
        self.assertEqual(self.retry.inputs, (RetryInput2026(1, 1, 231),))
        self.assertEqual(self.retry.native_option, 231)
        self.assertEqual(shared.history, bytes(0x1028))
        self.assertEqual(self.engine.inform_result_of_query_retry(1, 0), 3005)

    def test_captured_option_resets_actual_delta_group_without_clearing_error_counter(
        self,
    ):
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr(
                "Setting.ini",
                "[DeltaReproCalFile]\nFileNum=2\nFileName1=first.cuw\n"
                "FileName2=second.cuw\n[WholeReproCalFile]\nFileName=whole.cuw\n",
            )
            for name in ("first", "second", "whole"):
                archive.writestr(f"{name}.cuw", calibration(first_target=name.upper()))
        # Reissue the worker against the actual parsed FILE source set.
        self.engine.close()
        self.engine = CUWEngine2026(
            Path("runtime/no-car-21/recovered/CUW.dll").read_bytes()
        )
        self.engine.configure(struct.pack("<IIddII", 4, 0, 5.0, 13.0, 0, 0))
        from tests.test_cuw_file_services import PublicFileTests

        self.engine.bind_frontend_parameters(
            PublicFileTests.frontend_parameters(include_empty_can_id=True)
        )
        issued = admit_file_sources_2026(
            self.engine,
            "input.json",
            b'["plain.cuw","group.scuw"]',
            region=0,
            source_files={
                "plain.cuw": calibration(first_target="PLAIN"),
                "group.scuw": b"[Vehicle]\nContactType=P5-Unified\n[DataCompression]\n"
                + payload.getvalue(),
            },
        )
        self.engine.bind_file_sources(issued)
        self.assertTrue(issued.delta_archive)
        self.assertFalse(issued.current_is_retained_clone)
        self.worker = self.engine.bind_worker(self.control)
        self.retry = self.engine.bind_retry_controller()
        self.addCleanup(self.engine.close)
        with self.engine.controller_execution(self.control, 0):
            self.engine._select_worker_metadata(
                issued.files[1], controller=self.control, worker=self.worker
            )
        self.assertEqual(self.worker.source_state.current_file_index, 1)
        failures = []

        def worker():
            try:
                with self.engine.controller_execution(self.control, 0):
                    self.engine.dh_state.record_native_error(7, 8, 0)
                    self.engine.notify_native_error_kind()
                    self.engine.notify_native_errors()
                    self.retry.callback3()
            except Exception as error:  # noqa: BLE001 - capture actual source consumer
                failures.append(error)

        thread = threading.Thread(target=worker)
        thread.start()
        try:
            self.retry.wait_for_query()
            self.assertEqual(self.retry.source_state.error_counts38c, (1, 0, 0, 0))
            self.assertEqual(self.engine.inform_result_of_query_retry(1, 1), 0)
        finally:
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(self.worker.loaded_metadata), 2)
        self.assertEqual(
            self.engine.native_metadata.cpu.values["01_targetcalibration"], "WHOLE"
        )
        self.assertEqual(self.retry.source_state.error_counts38c, (1, 0, 0, 0))
        self.assertTrue(self.engine.native_cycle_output)

    def test_direct_scuw_zero_map_captured_255_resets_actual_delta_file(self):
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr(
                "Setting.ini",
                "[DeltaReproCalFile]\nFileNum=1\nFileName1=part.cuw\n"
                "[WholeReproCalFile]\nFileName=whole.cuw\n",
            )
            archive.writestr("part.cuw", calibration(first_target="PART"))
            archive.writestr("whole.cuw", calibration(first_target="WHOLE"))
        self.engine.close()
        self.engine = CUWEngine2026(
            Path("runtime/no-car-21/recovered/CUW.dll").read_bytes()
        )
        self.engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
        from tests.test_cuw_file_services import PublicFileTests

        self.engine.bind_frontend_parameters(
            PublicFileTests.frontend_parameters(include_empty_can_id=True)
        )
        issued = admit_file_sources_2026(
            self.engine,
            "direct.scuw",
            b"[Vehicle]\nContactType=P5-Unified\n[DataCompression]\n"
            + payload.getvalue(),
            region=0,
        )
        self.engine.bind_file_sources(issued)
        self.worker = self.engine.bind_worker(self.control)
        self.retry = self.engine.bind_retry_controller()
        self.addCleanup(self.engine.close)
        self.assertEqual(issued.delta_map_size, 0)
        with self.engine.controller_execution(self.control, 0):
            self.engine._select_worker_metadata(
                issued.files[0], controller=self.control, worker=self.worker
            )
        failures = []

        def run():
            try:
                with self.engine.controller_execution(self.control, 0):
                    self.engine.dh_state.record_native_error(7, 8, 0)
                    self.engine.notify_native_error_kind()
                    self.engine.notify_native_errors()
                    self.retry.callback3()
            except Exception as error:  # noqa: BLE001 - actual source consumer
                failures.append(error)

        thread = threading.Thread(target=run)
        thread.start()
        try:
            self.retry.wait_for_query()
            self.assertEqual(self.engine.inform_result_of_query_retry(1, 255), 0)
        finally:
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        assert self.engine.file_sources is not None
        self.assertEqual(self.engine.file_sources.files, ())
        self.assertEqual(
            self.engine.native_metadata.cpu.values["01_targetcalibration"], "WHOLE"
        )
        self.assertEqual(self.retry.source_state.error_counts38c, (1, 0, 0, 0))
        self.assertTrue(self.engine.native_cycle_output)

    def test_actual_logical_postwait_option_zero_and_literal_255_methods(self):
        for option, routine, repro_zero, routine_zero, retain_old, expected in (
            (0, False, False, False, False, "02"),
            (255, False, False, False, False, "05"),
            (255, True, False, False, False, "01"),
            (255, False, True, False, False, "05"),
            (255, True, False, True, False, "01"),
            (255, True, True, True, True, "01"),
        ):
            with self.subTest(
                option=option,
                routine=routine,
                repro_zero=repro_zero,
                routine_zero=routine_zero,
            ):
                first = logical_text(209, method="02", slot=1, routine=routine).replace(
                    "NumberOfLogicalBlock=1", "NumberOfLogicalBlock=2"
                )
                second = (
                    logical_text(209, method="02", slot=2, routine=routine)
                    .split("[LogicalBlock102]", 1)[1]
                    .replace("NewCID=authored-new", "NewCID=second-new")
                    .replace(
                        "01_TargetCalibration=authored-old",
                        "01_TargetCalibration=second-old",
                    )
                )
                if repro_zero:
                    second = second.replace("Length=00000004", "Length=00", 1)
                if routine_zero:
                    head, tail = second.split("[EraseAndReproRoutine102]", 1)
                    second = (
                        head
                        + "[EraseAndReproRoutine102]"
                        + tail.replace("Length=00000004", "Length=00", 1)
                    )
                payloads = [b"data"] + ([b"code"] if routine else [])
                if not repro_zero:
                    payloads.append(b"data")
                if routine and not routine_zero:
                    payloads.append(b"code")
                if retain_old:
                    second += "[DeltaOrCompressionReproData102]\nStartAddress=00003000\nLength=00000006\n"
                    payloads.append(b"delta!")
                source = cuw(first + "[LogicalBlock102]" + second, tuple(payloads))
                with CUWEngine2026(
                    Path("runtime/no-car-21/recovered/CUW.dll").read_bytes()
                ) as engine:
                    engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
                    engine.load_cuw(source, cpu_index=1)
                    backing = engine.native_metadata.source_container
                    source_digest = engine.source_sha256
                    original_attached = parse_cuw_2026(source).attached.data
                    runtime = NativeRuntime2026(lambda *_args: None)
                    control = make_controller(runtime)
                    worker = engine.bind_worker(control)
                    retry = engine.bind_retry_controller()
                    failures = []

                    def run(
                        engine=engine, control=control, retry=retry, failures=failures
                    ):
                        try:
                            with engine.controller_execution(control, 0):
                                engine.dh_state.record_native_error(3, 7, 0)
                                engine.notify_native_error_kind()
                                engine.notify_native_errors()
                                retry.callback3()
                        except Exception as error:  # noqa: BLE001 - actual source consumer
                            failures.append(error)

                    thread = threading.Thread(target=run)
                    thread.start()
                    try:
                        self.assertEqual(retry.wait_for_query().cpu_index, 1)
                        self.assertEqual(
                            engine.inform_result_of_query_retry(1, option), 0
                        )
                    finally:
                        thread.join(2)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(failures, [])
                    self.assertEqual(worker.source_state.current_global_cpu_index, 0)
                    self.assertEqual(
                        {
                            block.slot: block.repro_method
                            for block in engine.native_metadata.logical_blocks
                        },
                        {1: "02", 2: expected},
                    )
                    self.assertFalse(engine.native_cycle_output)
                    self.assertEqual(retry.native_option, option)
                    self.assertIs(engine.native_metadata.source_container, backing)
                    self.assertEqual(engine.source_sha256, source_digest)
                    self.assertEqual(backing.attached.data, original_attached)
                    total = (0 if repro_zero else 4) + (
                        4 if routine and not routine_zero else 0
                    )
                    if option and total:
                        self.assertEqual(
                            engine.native_metadata.cpu_flash_size_overrides[1],
                            total,
                        )
                    else:
                        self.assertEqual(
                            dict(engine.native_metadata.cpu_flash_size_overrides), {}
                        )
                    if retain_old:
                        self.assertEqual(
                            native2026_logical_cpu_flash_size(
                                engine.native_metadata, 1
                            ),
                            6,
                        )

    def test_scoped_control_query_captured_input_reconnect_and_fault_boundaries(self):
        for scenario in ("retry", "nonretry", "native_reconnect", "host_reconnect"):
            with self.subTest(scenario=scenario):
                os_provider = LiveOSProvider()
                os_provider.responses["passthru_ioctl"] = PrimitiveResult(value=12000)
                fault = OSError("authored reconnect capture fault")
                capture = {"fail_connect": False}

                def provider(
                    operation,
                    remaining,
                    capture=capture,
                    scenario=scenario,
                    fault=fault,
                    os_provider=os_provider,
                ):
                    if (
                        capture["fail_connect"]
                        and operation["operation"] == "passthru_connect"
                    ):
                        if scenario == "host_reconnect":
                            raise fault
                        return PrimitiveResult(status=7)
                    return os_provider(operation, remaining)

                engine_device = J2534Device2026(provider, background_workers=False)
                engine_device.set_version(0)
                engine_device.set_driver(DriverMetadata2026("authored", "authored.dll"))
                with CUWEngine2026(
                    Path("runtime/no-car-21/recovered/CUW.dll").read_bytes()
                ) as engine:
                    engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
                    engine.load_cuw(calibration())
                    cancel = threading.Event()
                    runtime = NativeRuntime2026(
                        engine_device.primitive, cancelled=cancel.is_set
                    )
                    control = make_controller(runtime)
                    engine.bind_worker(control)
                    pair = bind_pair(engine, runtime, engine_device)
                    retry = engine.bind_retry_controller()
                    failures, outcomes = [], []

                    def worker(
                        engine=engine,
                        control=control,
                        pair=pair,
                        capture=capture,
                        scenario=scenario,
                        failures=failures,
                        outcomes=outcomes,
                    ):
                        try:
                            with engine.controller_execution(control, 0):
                                if scenario != "nonretry":
                                    pair.control.connect_native(6)
                                    pair.import_into(
                                        pair.engine, pair.export_from(pair.control)
                                    )
                                capture["fail_connect"] = scenario in (
                                    "native_reconnect",
                                    "host_reconnect",
                                )
                                engine.dh_state.record_native_error(3, 7, 0)
                                control.query_control_error(engine)
                                outcomes.append(engine.worker.control_state.failed)
                        except Exception as error:  # noqa: BLE001 - source worker result
                            failures.append(error)
                        finally:
                            capture["fail_connect"] = False
                            pair.control.clear()
                            pair.engine.clear()

                    thread = threading.Thread(target=worker)
                    thread.start()
                    try:
                        query = retry.wait_for_query()
                        self.assertEqual(
                            (query.error_kind, query.primary_error), (3, 7)
                        )
                        result = engine.inform_result_of_query_retry(
                            0 if scenario == "nonretry" else 1, 0
                        )
                        if scenario == "native_reconnect":
                            self.assertEqual(result, 4004)
                            second = retry.wait_for_query(query.sequence)
                            self.assertEqual(
                                (
                                    second.error_kind,
                                    second.primary_error,
                                    second.passthru_error,
                                ),
                                (3, 1, 7),
                            )
                            capture["fail_connect"] = False
                            self.assertEqual(
                                engine.inform_result_of_query_retry(1, 0), 0
                            )
                        else:
                            self.assertEqual(result, 0)
                    finally:
                        cancel.set()
                        thread.join(2)
                    self.assertFalse(thread.is_alive())
                    if scenario == "host_reconnect":
                        self.assertEqual(failures, [fault])
                        self.assertEqual(outcomes, [])
                    else:
                        self.assertEqual(failures, [])
                        self.assertEqual(outcomes, [scenario != "nonretry"])
                    self.assertEqual(
                        len(retry.inputs), 2 if scenario == "native_reconnect" else 1
                    )
                self.assertEqual(os_provider.handles, {})

    def test_captured_input_returns_source_status_of_next_real_query(self):
        for kind, primary, expected in (
            (3, 1008, 4012),
            (3, 7, 4005),
            (4, 8, 0),
            (1, 7, 9999),
        ):
            with self.subTest(kind=kind, primary=primary):
                self.concrete_device()
                cancel = threading.Event()
                self.runtime.cancelled = cancel.is_set
                failures = []
                observed = len(self.retry.queries)

                def worker(kind=kind, primary=primary, failures=failures):
                    try:
                        with self.engine.controller_execution(self.control, 0):
                            for error_kind, error in ((3, 7), (kind, primary)):
                                self.engine.dh_state.record_native_error(
                                    error_kind, error, 0
                                )
                                self.engine.notify_native_error_kind()
                                self.engine.notify_native_errors()
                                self.retry.callback3()
                    except Exception as error:  # noqa: BLE001 - capture the concrete worker result
                        failures.append(error)

                thread = threading.Thread(target=worker)
                thread.start()
                try:
                    self.retry.wait_for_query(observed)
                    self.assertEqual(
                        self.engine.inform_result_of_query_retry(1, 13), expected
                    )
                    self.assertTrue(self.engine.active)
                    self.assertTrue(self.retry.query_pending)
                    self.assertEqual(self.retry.queries[-1].error_kind, kind)
                    self.assertEqual(self.engine.inform_result_of_query_retry(1, 17), 0)
                finally:
                    cancel.set()
                    thread.join(2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(failures, [])

    def _assert_nonretry_input_cleanup(self, native_result):
        def no_io(operation, _remaining):
            self.fail(f"Empty typed device must not perform I/O: {operation}")

        device = J2534Device2026(no_io, background_workers=False)
        bind_pair(self.engine, self.runtime, device)
        failures = []
        decisions = []

        def worker():
            try:
                with self.engine.controller_execution(self.control, 0):
                    self.engine.dh_state.record_native_error(3, 7, 0)
                    self.engine.notify_native_error_kind()
                    self.engine.notify_native_errors()
                    self.retry.callback3()
                    decisions.append(self.engine.write_complete_output)
            except Exception as error:  # noqa: BLE001 - capture the actual worker outcome
                failures.append(error)

        thread = threading.Thread(target=worker)
        thread.start()
        try:
            self.retry.wait_for_query()
            self.assertEqual(
                self.engine.inform_result_of_query_retry(native_result, 200), 0
            )
        finally:
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(decisions, [False])
        self.assertIsNone(self.engine.source_sha256)
        self.assertEqual(self.retry.inputs, (RetryInput2026(1, native_result, 200),))
        self.assertEqual(self.retry.native_option, 200)
        self.assertFalse(self.retry.query_pending)
        self.assertEqual(self.retry.result, 0)

    def test_captured_nonretry_input_runs_actual_whole_engine_cleanup(self):
        self._assert_nonretry_input_cleanup(2)

    def test_captured_zero_input_is_nonretry_and_runs_cleanup(self):
        self._assert_nonretry_input_cleanup(0)

    def test_captured_negative_input_is_nonretry_and_runs_cleanup(self):
        self._assert_nonretry_input_cleanup(-1)

    def test_native_battery_failure_still_publishes_real_query(self):
        self.concrete_device(fault=NativeJ2534Error2026(9))
        cancel = threading.Event()
        self.runtime.cancelled = cancel.is_set
        failures = []

        def worker():
            try:
                with self.engine.controller_execution(self.control, 0):
                    self.engine.dh_state.record_native_error(4, 8, 0)
                    self.engine.notify_native_error_kind()
                    self.engine.notify_native_errors()
                    self.retry.callback3()
            except InterruptedError as error:
                failures.append(error)

        thread = threading.Thread(target=worker)
        thread.start()
        try:
            query = self.retry.wait_for_query()
            self.assertEqual(
                (query.error_kind, query.primary_error, query.recovery_status),
                (4, 8, 2),
            )
            state = self.retry.source_state
            self.assertTrue(state.battery_query5a8)
            self.assertEqual(state.battery_voltage5a0, 0.0)
            self.assertFalse(state.battery_above_threshold598)
            self.assertEqual(state.error_counts38c, (1, 0, 0, 0))
            self.assertEqual(len(self.retry.notifications), 1)
            self.assertFalse(state.log_flag398)
        finally:
            cancel.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertEqual(self.retry.inputs, ())
        self.runtime.cancelled = lambda: False
        self.runtime.local_milliseconds_of_day = lambda: 65432
        with self.engine.controller_execution(self.control, 1):
            state = self.retry.source_state
            self.assertFalse(state.battery_above_threshold598)
            self.assertEqual(state.battery_voltage5a0, 0.0)
            self.assertFalse(state.battery_query5a8)
            self.assertEqual(state.resume_milliseconds_d314, 65432)

    def test_owned_recovery_bypass_has_no_query_or_user_input(self):
        source = calibration()
        saved = r"C:\old\Save\authored.cuw"
        original = ReproInfoState(
            (RecoveryCalibration("authored.cuw", source, saved_path=saved),)
        )
        document = parse_recovery_info(encode_recovery_info(original))
        with tempfile.TemporaryDirectory() as directory:
            persistence = CUWPersistence.import_recovery(
                Path(directory), document, {saved: source}, cpu_capacity=4
            )
            with CUWEngine2026(
                Path("runtime/no-car-21/recovered/CUW.dll").read_bytes(),
                persistence=persistence,
            ) as engine:
                engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
                engine.load_cuw(source)
                control = make_controller(NativeRuntime2026(lambda *_args: None))
                worker = engine.bind_worker(control)
                retry = engine.bind_retry_controller()
                with engine.controller_execution(control, 0):
                    self.assertTrue(worker.control_state.recovery_mode)
                    engine.dh_state.record_native_error(1, 7, 0)
                    engine.notify_native_error_kind()
                    retry.callback3()
                    self.assertTrue(retry.decision)
                    self.assertTrue(engine.write_complete_output)
                    self.assertFalse(worker.control_state.recovery_mode)
                self.assertEqual(retry.queries, ())
                self.assertEqual(retry.inputs, ())

    def test_callback30_keeps_raw_byte_and_requires_actual_phase(self):
        with self.assertRaises(ValueError):
            self.retry.record_callback30(1)
        with self.engine.controller_execution(self.control, 0):
            for malformed in (True, -1, 256):
                with self.assertRaises(ValueError):
                    self.retry.record_callback30(malformed)
            self.retry.record_callback30(255)
            self.retry._wait_worker_resume()
            self.assertGreaterEqual(self.retry.source_state.resume_milliseconds_d314, 0)
        self.assertEqual(self.retry.inputs, ())

    def test_unowned_callback_is_rejected_before_query_publication(self):
        with self.assertRaises(ValueError):
            self.retry.callback3()
        self.assertEqual(self.retry.queries, ())

    def test_host_check_exception_keeps_identity_and_no_native_query(self):
        fault = OSError("authored capture failure")

        def fail():
            raise fault

        self.runtime.cancelled = fail
        with self.assertRaises(OSError) as caught:
            self.retry._check()
        self.assertIs(caught.exception, fault)
        self.assertEqual(self.retry.inputs, ())

    def test_host_cancel_and_deadline_are_not_retry_input(self):
        self.runtime.cancelled = lambda: True
        with self.assertRaises(InterruptedError):
            self.retry._check()
        self.runtime.cancelled = lambda: False
        self.runtime.deadline = self.runtime.clock() - 1
        with self.assertRaises(TimeoutError):
            self.retry._check()
        self.assertEqual(self.retry.inputs, ())

    def test_input_pump_host_fault_cannot_publish_native_retry_decision(self):
        input_thread = threading.get_ident()
        fault = OSError("authored input pump cancellation fault")
        cancel = threading.Event()
        failures = []

        def cancelled():
            if threading.get_ident() == input_thread:
                raise fault
            return cancel.is_set()

        def worker():
            try:
                with self.engine.controller_execution(self.control, 0):
                    self.engine.dh_state.record_native_error(3, 7, 0)
                    self.engine.notify_native_error_kind()
                    self.engine.notify_native_errors()
                    self.retry.callback3()
            except Exception as error:  # noqa: BLE001 - capture actual worker result
                failures.append(error)

        thread = threading.Thread(target=worker)
        thread.start()
        try:
            self.retry.wait_for_query()
            self.runtime.cancelled = cancelled
            with self.assertRaises(OSError) as caught:
                self.engine.inform_result_of_query_retry(1, 0)
            self.assertIs(caught.exception, fault)
            self.assertFalse(self.engine.write_complete_output)
            self.assertEqual(self.engine.native_error_output, (7, 0))
            self.assertEqual(self.retry.inputs, ())
            self.assertTrue(self.retry.query_pending)
        finally:
            cancel.set()
            thread.join(2)
            self.runtime.cancelled = lambda: False
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], InterruptedError)

    def test_frozen_capture_clock_cannot_make_host_query_wait_infinite(self):
        self.runtime.clock = lambda: 0.0
        self.runtime.deadline = 0.02
        self.retry.worker_started()
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            self.retry.wait_for_query()
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertFalse(self.retry.query_pending)
        self.assertEqual(self.retry.inputs, ())

    def test_observer_and_periodic_validation(self):
        for value in (-1, True, 1.0):
            with self.assertRaises(ValueError):
                self.retry.wait_for_query(value)  # pyright: ignore[reportArgumentType] - malformed input boundary
        with self.assertRaises(TypeError):
            self.retry.accept_gateway_startup(object())

    def test_closed_controller_wakes_and_rejects_host_wait(self):
        self.retry.close()
        with self.assertRaises(ValueError):
            self.retry._check()
        with self.assertRaisesRegex(ValueError, "closed"):
            self.retry.wait_for_query()


if __name__ == "__main__":
    unittest.main()
