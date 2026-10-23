"""Actual engine reservation and native thread lifetime checks."""

import copy
import hashlib
import json
import struct
import threading
import time
import unittest
from contextlib import nullcontext
from dataclasses import replace
from itertools import cycle
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from scripts.cuw_2026 import CUWEngine2026
from scripts.cuw_engine_threads import (
    EngineThreadJob2026,
    ThreadPhaseLease2026,
    validate_thread_phase_lease,
)
from scripts.cuw_file_services import admit_file_sources_2026
from scripts.j2534_2026 import (
    J2534Device2026,
    J2534InterfacePair2026,
    NativeMessage,
    PrimitiveResult,
)
from scripts.programming_2026_common import (
    NativeException2026,
    NativeGeneralParameters2026,
    NativeRuntime2026,
)
from scripts.programming_replay import ProgrammingReplay, load_programming_replay
from tests import test_cuw_gateway_startup as gateway_fixtures
from tests.private_evidence import read_private_bytes, require_private
from tests.test_calibration_2026 import cuw
from tests.test_cuw_engine_worker import calibration, encoded_table, make_controller


class ThreadOwnershipTests(unittest.TestCase):
    _sequence_generations = 1

    def setUp(self):
        path = Path("runtime/no-car-21/recovered/CUW.dll")
        if not path.is_file():
            self.skipTest("Private authenticated static source unavailable")
        self.engine = CUWEngine2026(path.read_bytes())
        self.engine.configure(struct.pack("<IIddII", 4, 0, 5.0, 13.0, 0, 0))
        self.engine.load_cuw(calibration())
        self.runtime = NativeRuntime2026(lambda *_args, **_kw: None)
        self.controller = make_controller(self.runtime)
        self.worker = self.engine.bind_worker(self.controller)
        self.addCleanup(self.engine.close)

    def imported_prepare(
        self,
        *,
        paired=False,
        operation="prepare",
        source=None,
        source_files=None,
        include_control=True,
        include_profile=True,
        legacy_flag=None,
        recorded_driver=False,
        events=(),
        frontend_parameters=None,
        catalog_sources=None,
        cpu_maximum=None,
        module_name=None,
        persistence=None,
        cpu_index=0,
        bind_owners=False,
    ):
        source = source or cuw(
            "[Format]\nVersion=6\n[Vehicle]\nKindOfECU=1\nContactType=SIL\n"
            "NumberOfCalibration=1\n[CPU01]\nCPUType=1\nCPUImageName=one.vbf\n"
        )
        name = (
            "TCUWSilPrepareWriter.dll"
            if operation == "prepare"
            else "TCUWSilCIDGetter.dll"
        )
        key = "1SIL1"
        if module_name is not None:
            if (
                type(module_name) is not str
                or not module_name.endswith(".dll")
                or Path(module_name).name != module_name
            ):
                raise ValueError("A source module basename is required")
            name = module_name
        column = (
            "DLLFileNameForPrepareWrite"
            if operation == "prepare"
            else "DLLFileNameForGetCID"
        )
        catalog = {
            key + ".ini": encoded_table(
                ("ParamFileKeySystemProtocolMicon", column),
                ((key, name),),
            ),
            "Parameter.ini": encoded_table(
                (
                    "ParamFileKeySystemProtocolMicon",
                    "M16CTypeFlag",
                    "FlagToChangeToReprogGWModeForCentralGW",
                    "FORESTTypeFlag",
                    "PasswordAddress",
                    "ByteOrder",
                    "FlagToDoIGOFFONAtCPUTypeChange",
                    *(
                        ("FlagToUseCIDGetterAndFlashWriterDLL",)
                        if legacy_flag is not None
                        else ()
                    ),
                ),
                tuple(
                    (item, "0", "0", "0", "00", "1", "0")
                    + (
                        ("1" if legacy_flag else "0",)
                        if legacy_flag is not None
                        else ()
                    )
                    for item in (key,)
                ),
            ),
        }
        if catalog_sources is not None:
            catalog = dict(catalog_sources)
        if not include_profile:
            catalog.pop(key + ".ini", None)
        context = {
            "schema": "techstream-programming-replay-v1",
            "source": "recorded_unverified",
            "calibration_sha256": hashlib.sha256(source).hexdigest(),
            "operation": operation,
            "node": 1,
            "observations": {
                "current_cids": [],
                "tester_info_hex": bytes(32).hex(),
                "system_time": [2026, 10, 20, 20, 1, 2, 3, 4],
                "timeout_seconds": 30,
                "cid_mode": 2,
                "host": {
                    **(
                        {"driver_recording": "j2534_2026"}
                        if recorded_driver or paired
                        else {}
                    ),
                    "cpu_index": cpu_index,
                },
            },
            "events": events,
        }
        images = Path("runtime/no-car-21/recovered")
        require_private(images)
        session = load_programming_replay(
            source,
            json.dumps(context).encode(),
            catalog,
            {
                name: read_private_bytes(images / name),
                **(
                    {
                        "TCUWControlCommPhase.dll": read_private_bytes(
                            images / "TCUWControlCommPhase.dll"
                        )
                    }
                    if include_control
                    else {}
                ),
                **(
                    {
                        "TCUWJ2534DeviceIF.dll": read_private_bytes(
                            images / "TCUWJ2534DeviceIF.dll"
                        )
                    }
                    if recorded_driver or paired
                    else {}
                ),
            },
        )
        runtime = NativeRuntime2026(
            session.trace.action,
            clock=session.trace.clock,
            cancelled=session.trace.cancelled,
            local_seconds_of_day=session.trace.native_local_seconds_of_day,
            local_milliseconds_of_day=session.trace.native_local_milliseconds_of_day,
        )
        if not any(
            row.get("request", {}).get("operation") == "get_local_milliseconds_of_day"
            for row in events
        ):
            # 36800 samples host-local time before it schedules the child.
            # Supply a deterministic host clock without fabricating a trace row.
            local_clock = lambda: 1000
            session.trace.native_local_milliseconds_of_day = local_clock
            runtime.local_milliseconds_of_day = local_clock
        general_parameters = (
            frontend_parameters.general
            if frontend_parameters is not None
            else NativeGeneralParameters2026.from_sources(catalog)
        )
        engine = CUWEngine2026(
            read_private_bytes(images / "CUW.dll"),
            general_parameters=general_parameters,
            persistence=persistence,
        )
        if frontend_parameters is not None:
            engine.bind_frontend_parameters(frontend_parameters)
        configured_maximum = (
            (4 if source_files is not None else 1)
            if cpu_maximum is None
            else cpu_maximum
        )
        if type(configured_maximum) is not int or not 1 <= configured_maximum <= 4096:
            raise ValueError("A bounded native CPU maximum is required")
        engine.configure(struct.pack("<IIddII", configured_maximum, 0, 1, 2, 0, 0))
        engine.load_cuw(source, cpu_index=cpu_index)
        if source_files is not None:
            engine.bind_file_sources(
                admit_file_sources_2026(
                    engine,
                    "input.json",
                    json.dumps(list(source_files), separators=(",", ":")).encode(),
                    region=0,
                    source_files=source_files,
                )
            )
        if paired:
            session.bind_engine2026(engine)
            session.bind_runtime2026(runtime)
            pair = session.trace.interface_pair
            if pair is None:
                raise AssertionError("Paired source replay did not bind its device")
            engine.bind_interface_pair(pair)
        controller = make_controller(runtime)
        if recorded_driver:
            session.bind_controller2026(controller)
            engine.bind_interface_pair(session.trace.interface_pair)
        if paired:
            session.bind_controller2026(controller)
        elif bind_owners:
            # Bind the exact already-created replay/controller/engine tuple so
            # raw CONTROL source paths enter their guarded pre-child prefix.
            session.bind_engine2026(engine)
            session.bind_runtime2026(runtime)
            session.bind_controller2026(controller)
        job = engine.bind_thread_job(controller)
        self.addCleanup(engine.close)
        self.addCleanup(job.stop)
        return engine, controller, job, session

    def authored_two_file_getter_job(self):
        """Build the source-authored two-FILE CONTROL getter fixture."""
        import tempfile

        from scripts.cuw_2026 import CUWEngine2026, identity_2026
        from scripts.cuw_file_services import admit_file_sources_2026
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )
        from scripts.j2534_2026 import DriverMetadata2026, PrimitiveResult
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeFrontendParameters2026,
        )
        from tests.test_calibration_2026 import srecord
        from tests.test_programming_replay import (
            authored_classic_can40_inputs,
            make_authored_control_recorder,
        )

        def source(first_target: str) -> bytes:
            sections = [
                "[Format]",
                "Version=40",
                "[Vehicle]",
                "ContactType=CAN",
                "KindOfECU=149",
                "NumberOfCalibration=2",
            ]
            for index, (cpu_type, targets) in enumerate(
                (
                    (311, (first_target, "LATEST")),
                    (312, ("SECOND-OLD", "SECOND-LATEST")),
                ),
                1,
            ):
                sections.extend(
                    (
                        f"[CPU{index:02}]",
                        f"CPUImageName=authored{index}.bin",
                        f"CPUType={cpu_type}",
                        f"NewCID=NEW{index}",
                        "NumberOfTargetHardwares=1",
                        "01_TargetHardware=",
                        "NumberOfTargets=2",
                        f"01_TargetCalibration={targets[0]}",
                        f"02_TargetCalibration={targets[1]}",
                    )
                )
            image = b"\n".join((srecord(1, 0, b"data"), srecord(7, 0)))
            return cuw("\n".join(sections) + "\n", (image, image))

        first_source = source("OLD")
        second_source = source("OTHER")
        catalog_sources = authored_classic_can40_inputs()[1]
        payloads = tuple(
            (
                b"\x49\x00\x10\x00\x00\x00",
                b"\x49\x04\x02"
                + b"".join(
                    (value + b"\0").ljust(16, b" ")
                    for value in (first, b"SECOND-LATEST")
                ),
            )
            for first in (b"OLD", b"OTHER")
        )

        class GetterSDK:
            def __init__(self):
                self.payloads = iter(payload for root in payloads for payload in root)
                self.pending = []
                self.clock_ms = 1000

            def __call__(self, request, remaining):
                operation = request["operation"]
                if operation == "get_local_milliseconds_of_day":
                    value = self.clock_ms
                    self.clock_ms += 1000
                    return value
                if operation == "get_local_seconds_of_day":
                    return self.clock_ms // 1000
                if operation.startswith("notify_"):
                    return None
                if operation == "wait":
                    return PrimitiveResult()
                if operation == "set_communication_log_mode":
                    return 0
                if operation in ("get_timeout", "get_send_timeout"):
                    return 1000
                if operation == "passthru_write":
                    messages = request["messages"]
                    if request["count"] != 1 or len(messages) != 1:
                        raise AssertionError("One actual source message required")
                    message = messages[0]
                    if message.protocol_id != 6:
                        raise AssertionError(
                            ("Unexpected source protocol", message.protocol_id)
                        )
                    address, pdu = message.data[:4], message.data[4:]
                    self.pending.append(
                        PrimitiveResult(value=(NativeMessage(6, address, rx_status=9),))
                    )
                    response_address = (int.from_bytes(address, "big") + 8).to_bytes(
                        4, "big"
                    )
                    if pdu in (b"\x09\x00", b"\x09\x04"):
                        self.pending.append(
                            PrimitiveResult(
                                value=(
                                    NativeMessage(
                                        6, response_address + next(self.payloads)
                                    ),
                                )
                            )
                        )
                    else:
                        raise AssertionError(
                            ("Unexpected actual getter PDU", pdu.hex())
                        )
                    return PrimitiveResult(value=1)
                if operation == "passthru_read":
                    if not self.pending:
                        raise AssertionError("Read without a source-authored response")
                    return self.pending.pop(0)
                if operation in (
                    "passthru_open",
                    "passthru_connect",
                    "passthru_start_filter",
                ):
                    return PrimitiveResult(
                        value={
                            "passthru_open": 17,
                            "passthru_connect": 19,
                            "passthru_start_filter": 23,
                        }[operation]
                    )
                if operation == "passthru_ioctl":
                    return PrimitiveResult(
                        value=13000 if request.get("ioctl") == 3 else None
                    )
                if operation == "passthru_read_version":
                    return PrimitiveResult(value=("Authored offline SDK", "1", "1"))
                if operation == "create_mutex":
                    return PrimitiveResult(value=51)
                if operation == "wait_handle":
                    return PrimitiveResult(value=0)
                if operation == "load_library":
                    return PrimitiveResult(
                        value=31
                        if (request.get("name") or "").startswith("ptshim")
                        else 32
                    )
                if operation == "get_symbol":
                    return PrimitiveResult(
                        value=0
                        if request.get("name") == "_GtsNewVimFixInterface@8"
                        else 201
                    )
                if operation in {
                    "passthru_load_library",
                    "passthru_unload_library",
                    "passthru_stop_filter",
                    "passthru_disconnect",
                    "passthru_close",
                    "free_library",
                    "release_mutex",
                    "close_handle",
                    "call_symbol",
                }:
                    return PrimitiveResult()
                raise AssertionError(("Unauthored SDK/host operation", operation))

        module_names = (
            "CUW.dll",
            "TCUWControlCommPhase.dll",
            "TCUWCanCIDGetter.dll",
            "TCUWJ2534DeviceIF.dll",
        )
        image_root = Path("runtime/no-car-21/recovered")
        modules = {name: read_private_bytes(image_root / name) for name in module_names}
        sdk = GetterSDK()
        root, runtime, pair, rows = make_authored_control_recorder(
            self,
            source=first_source,
            catalog_sources=catalog_sources,
            module_files=modules,
            primitive_reply=sdk,
        )
        frontend = NativeFrontendParameters2026.from_sources(
            catalog_sources, encoded=True
        )
        engine = CUWEngine2026(modules["CUW.dll"], general_parameters=frontend.general)
        self.addCleanup(engine.close)
        engine.configure(struct.pack("<IIddII", 4, 0, 1, 2, 0, 0))
        engine.bind_frontend_parameters(frontend)
        source_files = {"first.cuw": first_source, "second.cuw": second_source}
        sources = admit_file_sources_2026(
            engine,
            "input.json",
            b'["first.cuw","second.cuw"]',
            region=0,
            source_files=source_files,
        )
        engine.bind_file_sources(sources)
        names, originals, count = sources.recovery_sources()
        persistence_root = tempfile.TemporaryDirectory()
        self.addCleanup(persistence_root.cleanup)
        engine.bind_persistence(
            CUWPersistence(
                Path(persistence_root.name),
                ReproInfoState(
                    tuple(
                        RecoveryCalibration(name, data, blank_ecu_flags=(False,) * 4)
                        for name, data in zip(names, originals, strict=True)
                    ),
                    multi_calibration_file_num=count,
                    loaded=False,
                ),
            )
        )
        controller = ControlCommPhase2026(
            identity_2026(
                modules["TCUWControlCommPhase.dll"],
                "TCUWControlCommPhase.dll",
            ),
            runtime,
        )
        root.bind_engine2026(engine)
        root.bind_controller2026(controller)
        for view in (pair.engine, pair.control):
            view.set_current_driver(DriverMetadata2026("Authored", "authored.dll"))
        engine.bind_interface_pair(pair)
        job = engine.bind_thread_job(controller)
        self.addCleanup(job.stop)
        return engine, controller, job, root, pair, rows, sdk, sources

    def complete_two_file_getter_roots(self, engine, controller, job, root):
        self.assertEqual(job.start(root), 1)
        first_report = job.result(5, sequence=1)
        deadline = time.monotonic() + 5
        while job.state.sequence < 2 and time.monotonic() < deadline:
            time.sleep(0.001)
        second_report = job.result(5, sequence=2)
        self.assertIs(first_report["native_return"], True)
        self.assertIs(second_report["native_return"], True)
        worker = job.worker
        self.assertEqual(
            worker._getter_flow_received_cids2026[:2],
            ((b"OLD", b"SECOND-LATEST"), (b"OTHER", b"SECOND-LATEST")),
        )
        self.assertEqual(worker.source_state.current_file_index, 0)
        with engine.controller_execution(controller, 0):
            self.assertTrue(worker.mark_cid_reception_complete())
        self.assertEqual(worker.source_state.target_indices, (0, 1))
        self.assertEqual(worker.source_state.authored_target_indices, (0, 1))
        return first_report, second_report

    def test_actual_missing_control_loader_publishes_fatal_without_raw_export(self):
        engine, controller, job, session = self.imported_prepare(
            operation="get_cid", include_control=False
        )
        clock = lambda: 1000
        session.trace.native_local_milliseconds_of_day = clock
        controller.runtime.local_milliseconds_of_day = clock
        with engine.controller_execution(controller, 0):
            engine.dh_state.record_native_error(3, 8, 9)
        job.start(session)
        report = job.result(2)
        self.assertIsNone(report["native_return"])
        self.assertEqual(report["exports"], ())
        self.assertFalse(report["programming_completed"])
        self.assertTrue(job.worker.native_fatal_input80)
        self.assertEqual(job.worker.control_state.error_kind, 9999)
        self.assertEqual(job.worker.control_state.primary_error, 0)
        self.assertEqual(job.worker.control_state.passthru_error, 0)
        self.assertTrue(engine.native_fatal_output)
        self.assertFalse(engine.native_control_fatal_output)
        self.assertFalse(session.used)
        self.assertEqual(session.trace.position, 0)
        self.assertTrue(job.state.waiting_for_resume)
        self.assertTrue(job.state.child_alive)
        self.assertFalse(job.native_work_pending)

    def test_ordinary36800_abort_preserves_clock_error_after_configuration_drift(self):
        engine, controller, job, session = self.imported_prepare()
        session.bind_runtime2026(controller.runtime)
        session.bind_engine2026(engine)
        session.bind_controller2026(controller)
        previous_configuration = engine.configuration
        sentinel = OSError("clock provider failed after configuration changed")
        original_flags = (
            engine._native_outer_cfe0_2026,
            engine._native_be54_pending2026,
            engine._native_receiving_cfe2_2026,
        )

        def fail_clock():
            engine.__dict__["configuration"] = object()
            raise sentinel

        controller.runtime.local_milliseconds_of_day = fail_clock
        with self.assertRaises(OSError) as caught:
            job.start(session)

        self.assertIs(caught.exception, sentinel)
        self.assertEqual(job.state.sequence, 0)
        self.assertIsNone(job._lease)
        self.assertIsNone(job._ordinary_prepare_binding2026)
        self.assertIsNone(job._ordinary_prepare_origin2026)
        self.assertFalse(job._ordinary_prepare_starting2026)
        self.assertIsNone(job._prepared_ordinary_entry2026)
        self.assertIsNone(engine._ordinary_prepare_scope2026)
        self.assertIsNone(engine._prepare_prefix_owner)
        self.assertFalse(engine._active)
        self.assertTrue(engine._phase_finished.is_set())
        self.assertEqual(
            (
                engine._native_outer_cfe0_2026,
                engine._native_be54_pending2026,
                engine._native_receiving_cfe2_2026,
            ),
            original_flags,
        )
        self.assertEqual(job.worker._retained_cpu_type, "1")
        self.assertTrue(engine._lock.acquire(blocking=False))
        engine._lock.release()
        engine.configuration = previous_configuration

    def test_control_handoffs_require_the_actual_child_thread(self):
        engine, _controller, job, _session = self.imported_prepare(operation="get_cid")
        with self.assertRaisesRegex(ValueError, "actual child"):
            job.dispatch_control_progress(object(), "count")
        with self.assertRaisesRegex(ValueError, "actual child"):
            job.dispatch_control_getter_return()
        self.assertEqual(engine.dh_state.transferred_bytes, (0,))

    def test_ordinary_false_getter_imports_pair_on_outer_thread(self):
        from tests.test_programming_2026_common import RawControlStageMachineTests

        fixture = RawControlStageMachineTests()
        self.addCleanup(fixture.doCleanups)
        engine, controller, session = fixture.fixture(
            operation="get_cid",
            paired=True,
            dependencies=("TCUWControlCommPhase.dll",),
        )
        session.bind_engine2026(engine)
        session.bind_runtime2026(controller.runtime)
        session.bind_controller2026(controller)
        job = engine.bind_thread_job(controller)
        self.addCleanup(job.stop)
        pair = engine.interface_pair
        assert pair is not None
        runner_calls = []

        def ordinary_false_getter(*_args):
            runner_calls.append(True)
            return lambda: {"native_success": False, "identifiers": (b"CID",)}

        with (
            patch.object(ProgrammingReplay, "_runner", ordinary_false_getter),
            patch.object(pair, "import_into", wraps=pair.import_into) as imports,
        ):
            job.start(session)
            report = job.result(5)

        self.assertIs(report["native_return"], False, report)
        self.assertEqual(report["identifiers"], (b"CID",))
        self.assertEqual(runner_calls, [True])
        self.assertEqual(
            [call.args[0] for call in imports.call_args_list],
            [pair.control, pair.engine],
        )
        self.assertEqual(engine.received_identifiers, (b"CID",))

    def test_actual_p5_false_getter_imports_pair_through_thread_job(self):
        self._run_actual_p5_getter_thread(fail_status=True)

    def test_actual_p5_true_getter_imports_pair_through_thread_job(self):
        self._run_actual_p5_getter_thread(
            fail_status=False, expect_unsupported_success=True
        )

    def test_actual_getter_stop_after_3cb90_probe_returns_no_event_without_receipt(
        self,
    ):
        self._run_actual_p5_getter_thread(fail_status=True, stop_after_completion=True)

    def test_actual_late_be8_two_suppresses_after_candidate_and_both_acks(self):
        from pathlib import Path

        from scripts.cuw_2026 import identity_2026
        from scripts.j2534_2026 import (
            DriverMetadata2026,
            J2534Device2026,
            NativeMessage,
            NativePassThruError2026,
            NativeReadBatch2026,
            PrimitiveResult,
        )
        from scripts.programming_2026_common import ControlCommPhase2026
        from scripts.programming_2026_p5_getters import run_native_context
        from scripts.programming_replay import _native_request
        from tests.private_evidence import read_private_bytes
        from tests.test_calibration_2026 import cuw
        from tests.test_cuw_engine_worker import encoded_table
        from tests.test_programming_2026_common import make_raw_control_fixture2026
        from tests.test_programming_2026_p5_getters import (
            P5,
            fixture,
            p5,
            typed_runtime,
        )

        native, container, binding = fixture(P5, "0100/0108\n0200/0208")
        provider_runtime, device, _provider_events = typed_runtime(
            cycle((b"\0" + p5(b"FIRST"),))
        )
        provider_events = []
        captured_timeline = []
        late_fault_enabled = False

        def captured_clock():
            captured_timeline.append(("clock", 1000))
            return 1000

        provider_runtime.local_milliseconds_of_day = captured_clock

        def typed_value(value):
            if value is None:
                return {"type": "none", "value": None}
            if type(value) is bool:
                return {"type": "bool", "value": value}
            if type(value) is int:
                return {"type": "int", "value": value}
            if isinstance(value, bytes):
                return {"type": "bytes", "value": value.hex()}
            if type(value) is NativeMessage:
                return {
                    "type": "mapping",
                    "value": {
                        "_native_type": {
                            "type": "text",
                            "value": "PASSTHRU_MSG_2026",
                        },
                        **{key: typed_value(item) for key, item in vars(value).items()},
                    },
                }
            if type(value) is NativeReadBatch2026:
                return {
                    "type": "mapping",
                    "value": {
                        "_native_type": {
                            "type": "text",
                            "value": "READ_BATCH_2026",
                        },
                        "messages": typed_value(value.messages),
                        "count": typed_value(value.count),
                    },
                }
            if isinstance(value, tuple):
                return {"type": "tuple", "value": [typed_value(item) for item in value]}
            if isinstance(value, list):
                return {
                    "type": "sequence",
                    "value": [typed_value(item) for item in value],
                }
            if isinstance(value, dict):
                return {
                    "type": "mapping",
                    "value": {key: typed_value(item) for key, item in value.items()},
                }
            raise TypeError(f"Unsupported typed driver value: {type(value)!r}")

        original_provider = device.provider

        def capture_driver(event, remaining):
            nonlocal late_fault_enabled
            result = original_provider(event, remaining)
            if event["operation"] == "create_mutex":
                result = PrimitiveResult(value=1)
            elif event["operation"] == "wait_handle":
                result = PrimitiveResult(value=0)
            elif event["operation"] == "load_library":
                result = PrimitiveResult(value=2)
            elif event["operation"] == "get_symbol":
                result = PrimitiveResult(value=3)
            elif event["operation"] == "passthru_read_version":
                result = (
                    PrimitiveResult(status=16)
                    if late_fault_enabled
                    else PrimitiveResult(value=("firmware", "driver", "api"))
                )
            provider_events.append((event, result))
            captured_timeline.append(("driver", event, result))
            return result

        device.provider = capture_driver
        peer = J2534Device2026(
            device.provider,
            clock=device.clock,
            cancelled=device.cancelled,
            background_workers=False,
        )
        direct_pair = J2534InterfacePair2026(peer, device)
        for view in (direct_pair.engine, direct_pair.control):
            view.set_current_driver(DriverMetadata2026("Authored", "authored.dll"))

        values = {
            key: "\n".join(value)
            for key, value in binding.values.items()
            if key != "ParamFileKeySystemProtocolMicon"
        }
        values["EnableDLLVersionInformation"] = "0\n0\n0\n0"
        profile_fields = ("ParamFileKeySystemProtocolMicon", *values)
        catalog = {
            "8P5" + cpu + ".ini": encoded_table(
                profile_fields, (("8P5" + cpu, *values.values()),)
            )
            for cpu in ("A", "B")
        }
        catalog["Parameter.ini"] = encoded_table(
            (
                "ParamFileKeySystemProtocolMicon",
                "M16CTypeFlag",
                "FlagToChangeToReprogGWModeForCentralGW",
                "FORESTTypeFlag",
                "PasswordAddress",
                "ByteOrder",
            ),
            tuple(("8P5" + cpu, "0", "0", "0", "00", "1") for cpu in ("A", "B")),
        )
        source = cuw(
            container.attached.data.decode("ascii"),
            tuple(record.data for record in container.records),
        )
        from scripts.cuw_2026 import CUWEngine2026

        direct_engine = CUWEngine2026(
            read_private_bytes(Path("runtime/no-car-21/recovered/CUW.dll")),
            general_parameters=NativeGeneralParameters2026.from_sources(catalog),
        )
        direct_engine.configure(struct.pack("<IIddII", 16, 0, 1, 2, 0, 0))
        direct_engine.load_cuw(source)
        direct_engine.bind_interface_pair(direct_pair)
        direct_controller = ControlCommPhase2026(
            identity_2026(
                read_private_bytes(
                    Path("runtime/no-car-21/recovered/TCUWControlCommPhase.dll")
                ),
                "TCUWControlCommPhase.dll",
            ),
            provider_runtime,
        )
        self.addCleanup(direct_engine.close)
        direct_job = direct_engine.bind_thread_job(direct_controller)
        self.addCleanup(direct_job.stop)
        with direct_engine.controller_execution(direct_controller, 1):
            pass
        with direct_engine.controller_execution(direct_controller, 0):
            pass
        phase_zero_end_index = len(captured_timeline)
        getter_start_index = len(captured_timeline)
        direct = run_native_context(native, provider_runtime)
        self.assertIs(direct["bool_out"], True, (direct, provider_events))
        self.assertEqual(direct["cids"], (b"FIRST", b"FIRST"))
        getter_end_index = len(captured_timeline)
        direct_pair.engine.have_ownership()
        direct_pair.engine.open()
        late_fault_enabled = True
        with self.assertRaises(NativePassThruError2026):
            direct_pair.engine.read_device_version()
        version_start_index = getter_end_index
        phase_zero_finish = captured_timeline[phase_zero_end_index - 1]
        self.assertEqual(phase_zero_finish[0], "clock")
        ordered_timeline = [
            *captured_timeline[: phase_zero_end_index - 1],
            *captured_timeline[getter_start_index:getter_end_index],
            *captured_timeline[version_start_index:],
            phase_zero_finish,
        ]
        recorded_rows = []
        for item in ordered_timeline:
            if item[0] == "clock":
                recorded_rows.append(
                    {
                        "kind": "action",
                        "request": {"operation": "get_local_milliseconds_of_day"},
                        "result": {"type": "int", "value": item[1]},
                        "elapsed_ms": 1,
                    }
                )
            else:
                _, event, result = item
                recorded_rows.append(
                    {
                        "kind": "action",
                        "request": _native_request(event),
                        "result": typed_value(
                            {"status": result.status, "value": result.value}
                        ),
                        "elapsed_ms": 1,
                    }
                )
        engine, controller, session = make_raw_control_fixture2026(
            self,
            source=source,
            catalog=catalog,
            module_files={
                P5: read_private_bytes(Path("runtime/no-car-21/recovered") / P5),
                "TCUWControlCommPhase.dll": read_private_bytes(
                    Path("runtime/no-car-21/recovered/TCUWControlCommPhase.dll")
                ),
            },
            operation="get_cid",
            events=recorded_rows,
            paired=True,
        )
        session.bind_engine2026(engine)
        session.bind_controller2026(controller)
        pair = engine.interface_pair
        assert pair is not None
        session.bind_controller2026(controller)
        session.bind_engine2026(engine)
        job = engine.bind_thread_job(controller)
        self.addCleanup(job.stop)
        with engine.controller_execution(controller, 1):
            pass
        candidates = []
        decisions = []
        ack_stages = []
        original_capture = job._capture_getter_candidate_2026
        original_native_fatal = engine.publish_native_fatal
        original_control_fatal = engine.publish_control_fatal

        def capture_candidate(context):
            candidate = original_capture(context)
            candidates.append((candidate, job.worker.native_prepare_handshake))
            return candidate

        def publish_native_fatal(*args, **kwargs):
            nonlocal late_fault_enabled
            ack_stages.append("native-fatal")
            result = original_native_fatal(*args, **kwargs)
            late_fault_enabled = True
            pair.engine.have_ownership()
            pair.engine.open()
            self.assertFalse(job.worker.check_device_version())
            ack_stages.append("version-fault")
            return result

        def publish_control_fatal(*args, **kwargs):
            ack_stages.append("control-fatal")
            return original_control_fatal(*args, **kwargs)

        original_finish = job._finish_getter_decision_2026

        def finish_decision(candidate):
            decision = original_finish(candidate)
            decisions.append(decision)
            return decision

        with (
            patch.object(job, "_capture_getter_candidate_2026", capture_candidate),
            patch.object(job, "_finish_getter_decision_2026", finish_decision),
            patch.object(engine, "publish_native_fatal", publish_native_fatal),
            patch.object(engine, "publish_control_fatal", publish_control_fatal),
        ):
            job.start(session)
            try:
                report = job.result(5, sequence=1)
            except BaseException as error:
                raise AssertionError(
                    (
                        error,
                        [
                            (index, row["request"].get("operation"))
                            for index, row in enumerate(session.trace.rows)
                        ],
                    )
                ) from error

        self.assertIs(report["native_return"], True)
        self.assertEqual(report["identifiers"], (b"FIRST", b"FIRST"))
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0][1], 1)
        self.assertEqual(ack_stages, ["native-fatal", "version-fault", "control-fatal"])
        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0].prepare_handshake_be8, 2)
        self.assertEqual(decisions[0].route, "suppressed")
        self.assertTrue(
            any(
                event["operation"] == "passthru_read_version" and result.status == 16
                for event, result in provider_events
            )
        )
        self.assertTrue(pair.engine.opened)
        self.assertEqual(session.trace.position, len(session.trace.rows))

    def test_p5_true_typed_none_is_rejected_before_g_mutation(self):
        self._run_actual_p5_getter_thread(
            fail_status=False, expect_unsupported_success=True
        )

    def _run_actual_p5_getter_thread(
        self,
        *,
        fail_status: bool,
        stop_after_execute: bool = False,
        stop_after_completion: bool = False,
        gate_retire_window: bool = False,
        expect_unsupported_success: bool = False,
        source_busy_stop_probe: bool = False,
        observe_busy_lock_order: bool = False,
    ):
        from pathlib import Path

        from scripts.j2534_2026 import (
            DriverMetadata2026,
            J2534Device2026,
            NativeMessage,
            NativeReadBatch2026,
            PrimitiveResult,
        )
        from scripts.programming_2026_p5_getters import run_native_context
        from scripts.programming_replay import _native_request
        from tests.private_evidence import read_private_bytes
        from tests.test_calibration_2026 import cuw
        from tests.test_cuw_engine_worker import encoded_table
        from tests.test_programming_2026_common import make_raw_control_fixture2026
        from tests.test_programming_2026_p5_getters import (
            P5,
            fixture,
            p5,
            typed_runtime,
        )

        generations = getattr(self, "_sequence_generations", 1)
        native, container, binding = fixture(P5, "0100/0108\n0200/0208", allow="")
        getter_replies = (b"\0" + p5(b"FIRST"),)
        provider_runtime, device, _provider_events = typed_runtime(
            cycle(getter_replies)
        )
        rows = []
        reads = 0

        def typed_value(value):
            if value is None:
                return {"type": "none", "value": None}
            if type(value) is bool:
                return {"type": "bool", "value": value}
            if type(value) is int:
                return {"type": "int", "value": value}
            if isinstance(value, bytes):
                return {"type": "bytes", "value": value.hex()}
            if type(value) is NativeMessage:
                return {
                    "type": "mapping",
                    "value": {
                        "_native_type": {"type": "text", "value": "PASSTHRU_MSG_2026"},
                        **{key: typed_value(item) for key, item in vars(value).items()},
                    },
                }
            if type(value) is NativeReadBatch2026:
                return {
                    "type": "mapping",
                    "value": {
                        "_native_type": {"type": "text", "value": "READ_BATCH_2026"},
                        "messages": typed_value(value.messages),
                        "count": typed_value(value.count),
                    },
                }
            if isinstance(value, tuple):
                return {"type": "tuple", "value": [typed_value(item) for item in value]}
            if isinstance(value, list):
                return {
                    "type": "sequence",
                    "value": [typed_value(item) for item in value],
                }
            if isinstance(value, dict):
                return {
                    "type": "mapping",
                    "value": {key: typed_value(item) for key, item in value.items()},
                }
            raise TypeError(f"Unsupported typed driver value: {type(value)!r}")

        original_provider = device.provider

        def capture_driver(event, remaining):
            nonlocal reads
            result = original_provider(event, remaining)
            if event["operation"] == "create_mutex":
                result = PrimitiveResult(value=1)
            elif event["operation"] == "wait_handle":
                result = PrimitiveResult(value=0)
            elif event["operation"] == "load_library":
                result = PrimitiveResult(value=2)
            elif event["operation"] == "get_symbol":
                result = PrimitiveResult(value=3)
            if event["operation"] == "passthru_read":
                reads += 1
                if reads % 4 == 0 and fail_status:
                    result = PrimitiveResult(status=16)
            rows.append(
                {
                    "kind": "action",
                    "request": _native_request(event),
                    "result": typed_value(
                        {"status": result.status, "value": result.value}
                    ),
                    "elapsed_ms": 1,
                }
            )
            return result

        device.provider = capture_driver
        peer = J2534Device2026(
            device.provider,
            clock=device.clock,
            cancelled=device.cancelled,
            background_workers=False,
        )
        direct_pair = J2534InterfacePair2026(peer, device)
        for view in (direct_pair.engine, direct_pair.control):
            view.set_current_driver(DriverMetadata2026("Authored", "authored.dll"))
        device.have_ownership()
        direct = run_native_context(native, provider_runtime)
        expected_cids = (b"FIRST",) if fail_status else (b"FIRST", b"FIRST")
        self.assertIs(direct["bool_out"], not fail_status)
        self.assertEqual(direct["cids"], expected_cids)
        for _ in range(1, generations):
            repeated = run_native_context(native, provider_runtime)
            self.assertIs(repeated["bool_out"], not fail_status)
            self.assertEqual(repeated["cids"], expected_cids)
        values = {
            key: "\n".join(value)
            for key, value in binding.values.items()
            if key != "ParamFileKeySystemProtocolMicon"
        }
        values["EnableDLLVersionInformation"] = "0\n0\n0\n0"
        catalog = {
            "8P5" + cpu + ".ini": encoded_table(
                ("ParamFileKeySystemProtocolMicon", *values),
                (("8P5" + cpu, *values.values()),),
            )
            for cpu in ("A", "B")
        }
        catalog["Parameter.ini"] = encoded_table(
            (
                "ParamFileKeySystemProtocolMicon",
                "M16CTypeFlag",
                "FlagToChangeToReprogGWModeForCentralGW",
                "FORESTTypeFlag",
                "PasswordAddress",
                "ByteOrder",
            ),
            tuple(("8P5" + cpu, "0", "0", "0", "00", "1") for cpu in ("A", "B")),
        )
        source = cuw(
            container.attached.data.decode("ascii"),
            tuple(record.data for record in container.records),
        )
        engine, controller, session = make_raw_control_fixture2026(
            self,
            source=source,
            catalog=catalog,
            module_files={
                P5: read_private_bytes(Path("runtime/no-car-21/recovered") / P5),
                "TCUWControlCommPhase.dll": read_private_bytes(
                    Path("runtime/no-car-21/recovered/TCUWControlCommPhase.dll")
                ),
            },
            operation="get_cid",
            events=rows,
            paired=True,
        )
        session.bind_engine2026(engine)
        session.bind_controller2026(controller)
        import copy

        persistence = cast(Any, engine._persistence)
        persistence_state = None if persistence is None else persistence.state
        persistence_before = copy.deepcopy(persistence_state)
        fixed_clock = lambda: 1000
        session.trace.native_local_milliseconds_of_day = fixed_clock
        controller.runtime.local_milliseconds_of_day = fixed_clock
        job = engine.bind_thread_job(controller)
        if source_busy_stop_probe:
            self.assertTrue(job._is_raw_control_getter_root2026(session))
        flow_before = job.worker._flow_file_index2026
        reset_epoch_before = job.worker._getter_reset_epoch2026
        observation_before = job.worker._getter_last_observation2026
        histories_before = job.worker._getter_histories_a34_2026
        flow_cids_before = job.worker._getter_flow_received_cids2026
        flow_queries_before = job.worker._getter_flow_query_records2026
        self.addCleanup(job.stop)
        busy_stop_results = []
        busy_stop_errors = []
        busy_source_state = []
        busy_publisher_calls = []
        child_adoption_entered = threading.Event()
        release_child_adoption = threading.Event()
        stop_job_attempted = threading.Event()
        stop_phase_acquired = threading.Event()
        stop_thread_id: list[int | None] = [None]
        original_adopt = ThreadPhaseLease2026._adopt
        original_job_lock = job._lock
        original_phase_lock = engine._phase_state_lock
        busy_stopper_holder: list[threading.Thread | None] = [None]

        def restore_busy_probe():
            release_child_adoption.set()
            ThreadPhaseLease2026._adopt = cast(Any, original_adopt)
            job._lock = original_job_lock
            engine._phase_state_lock = original_phase_lock

        if source_busy_stop_probe:
            self.addCleanup(restore_busy_probe)

        if source_busy_stop_probe:

            def gated_adopt(lease):
                if lease.engine.thread_job is job and job._sequence == 1:
                    child_adoption_entered.set()
                    if not release_child_adoption.wait(3):
                        raise TimeoutError("Actual child-adoption gate expired")
                return original_adopt(lease)

            class ObservedJobLock:
                def __init__(self, inner):
                    self.inner = inner

                def acquire(self, *args, **kwargs):
                    if threading.get_ident() == stop_thread_id[0]:
                        stop_job_attempted.set()
                        kwargs.setdefault("timeout", 2)
                    acquired = self.inner.acquire(*args, **kwargs)
                    if acquired is False:
                        raise TimeoutError("Native stop job-lock wait expired")
                    return acquired

                def release(self):
                    self.inner.release()

                def __enter__(self):
                    self.acquire()
                    return self

                def __exit__(self, *_args):
                    self.release()

            class ObservedPhaseLock:
                def __init__(self, inner):
                    self.inner = inner

                def acquire(self, *args, **kwargs):
                    acquired = self.inner.acquire(*args, **kwargs)
                    if (
                        acquired
                        and threading.get_ident() == stop_thread_id[0]
                        and stop_job_attempted.is_set()
                    ):
                        stop_phase_acquired.set()
                    return acquired

                def release(self):
                    self.inner.release()

                def __enter__(self):
                    self.acquire()
                    return self

                def __exit__(self, *_args):
                    self.release()

            ThreadPhaseLease2026._adopt = cast(Any, gated_adopt)
            if observe_busy_lock_order:
                job._lock = cast(Any, ObservedJobLock(original_job_lock))
                engine._phase_state_lock = cast(
                    Any, ObservedPhaseLock(original_phase_lock)
                )

            def stop_at_real_busy_store():
                stop_thread_id[0] = threading.get_ident()
                try:
                    busy_stop_results.append(engine.stop_receiving_cid(timeout=3))
                except BaseException as error:  # noqa: BLE001 - exact native stop failure
                    busy_stop_errors.append(error)

            def busy_store(_origin):
                if busy_stopper_holder[0] is not None:
                    raise AssertionError("Actual busy publisher ran more than once")
                busy_source_state.append(
                    (
                        engine._native_outer_cfe0_2026,
                        engine._native_be54_pending2026,
                        engine._native_receiving_cfe2_2026,
                        job._sequence,
                        None if job._lease is None else job._lease.state,
                    )
                )
                busy_stopper_holder[0] = threading.Thread(
                    target=stop_at_real_busy_store, daemon=True
                )
                busy_stopper_holder[0].start()
                if observe_busy_lock_order:
                    if not stop_job_attempted.wait(2):
                        raise TimeoutError("Native stop did not request the job lock")
                    if stop_phase_acquired.is_set():
                        raise AssertionError(
                            "Native stop acquired the phase lock before the job lock"
                        )

        else:
            busy_store = cast(Any, None)

        original_busy_publisher = engine._publish_getter_entry_busy_34cb0_2026

        def observed_busy_publisher(origin):
            busy_publisher_calls.append(origin)
            result = original_busy_publisher(origin)
            if busy_store is not None:
                busy_store(origin)
            return result

        pair = engine.interface_pair
        assert pair is not None
        runner_calls = []
        stages = []
        candidates = []
        decisions = []
        execute_record_at_import = []
        execute_record_checks = []
        combined_tail_calls = []
        import_entered = threading.Event()
        release_import = threading.Event()
        retire_entered = threading.Event()
        release_retire = threading.Event()
        self.addCleanup(release_retire.set)
        stop_errors = []
        stop_results = []
        import_state = []
        original_native_fatal = engine.publish_native_fatal
        original_control_fatal = engine.publish_control_fatal
        original_capture = job._capture_getter_candidate_2026
        original_finish = job._finish_getter_decision_2026
        original_execute_record = job._record_getter_execute_return_2026
        original_import = job.worker.import_control_getter_return2026
        original_combined_tail = job.worker._publish_outer_control_tail
        original_retire = job._retire_getter_receipts_2026

        def publish_native_fatal(*args, **kwargs):
            stages.append(("native", threading.current_thread()))
            return original_native_fatal(*args, **kwargs)

        def publish_control_fatal(*args, **kwargs):
            stages.append(("control", threading.current_thread()))
            return original_control_fatal(*args, **kwargs)

        def finish_decision(candidate):
            decision = original_finish(candidate)
            job._validate_getter_decision_2026(decision, route=decision.route)
            with self.assertRaises(ValueError):
                original_finish(candidate)
            with self.assertRaises(ValueError):
                job._validate_getter_decision_2026(
                    replace(decision), route=decision.route
                )
            with self.assertRaises(ValueError):
                job._validate_getter_decision_2026(decision, route="suppressed")
            decisions.append(decision)
            return decision

        def capture_candidate(context):
            candidate = original_capture(context)
            output = job.worker._imported_getter_output2026(context)
            self.assertIs(job._getter_execute_return2026, candidate.execute_record)
            self.assertEqual(candidate.sequence, job._sequence)
            self.assertIs(candidate.output, output)
            with self.assertRaises(ValueError):
                original_capture(context)
            with self.assertRaises(ValueError):
                job.dispatch_getter_callback_stage2026(
                    replace(candidate), "getter_native_fatal_5b1b0"
                )
            with self.assertRaises(ValueError):
                original_finish(candidate)
            candidates.append(candidate)
            return candidate

        def import_getter(context):
            execute_record_at_import.append(job._getter_execute_return2026)
            if stop_after_execute:
                import_state.append(
                    (
                        engine._native_outer_cfe0_2026,
                        engine._native_be54_pending2026,
                        engine._native_receiving_cfe2_2026,
                        engine.native_phase,
                        engine.worker_phase,
                        None if job._lease is None else job._lease.state,
                        job._activity.is_set(),
                        job._sequence,
                    )
                )
                import_entered.set()
                if not release_import.wait(3):
                    raise TimeoutError("Actual getter import gate expired")
            return original_import(context)

        def record_execute_return(context, result):
            pending = job._getter_execute_pending2026
            assert pending is not None
            self.assertIs(pending[0], context)
            self.assertIs(pending[1], result)
            self.assertEqual(pending[3], job._sequence)
            with self.assertRaises(ValueError):
                original_execute_record(context, dict(result))
            execute_record_checks.append(result)
            return original_execute_record(context, result)

        def combined_tail():
            combined_tail_calls.append(threading.current_thread())
            return original_combined_tail()

        def retire_getter_receipts(sequence):
            if gate_retire_window:
                self.assertTrue(decisions[0].candidate.execute_record.context._expired)
                retire_entered.set()
                if not release_retire.wait(3):
                    raise TimeoutError("Getter receipt retirement gate expired")
            return original_retire(sequence)

        original_runner = ProgrammingReplay._runner

        def runner(*args):
            runner_calls.append(True)
            return original_runner(*args)

        stopper = None
        if stop_after_execute:

            def stop_native_getter():
                try:
                    if not import_entered.wait(3):
                        raise TimeoutError("Actual getter did not reach import")
                    stop_results.append(engine.stop_receiving_cid(timeout=3))
                except BaseException as error:  # noqa: BLE001 - preserve source stop failure
                    stop_errors.append(error)

            stopper = threading.Thread(target=stop_native_getter)
            stopper.start()

        with (
            patch.object(ProgrammingReplay, "_runner", runner),
            patch.object(pair, "import_into", wraps=pair.import_into) as imports,
            patch.object(engine, "publish_native_fatal", publish_native_fatal),
            patch.object(engine, "publish_control_fatal", publish_control_fatal),
            patch.object(job, "_capture_getter_candidate_2026", capture_candidate),
            patch.object(job, "_finish_getter_decision_2026", finish_decision),
            patch.object(
                job,
                "_record_getter_execute_return_2026",
                record_execute_return,
            ),
            patch.object(job.worker, "import_control_getter_return2026", import_getter),
            patch.object(job.worker, "_publish_outer_control_tail", combined_tail),
            patch.object(job, "_retire_getter_receipts_2026", retire_getter_receipts),
            patch.object(
                engine,
                "_publish_getter_entry_busy_34cb0_2026",
                observed_busy_publisher,
            )
            if source_busy_stop_probe
            else nullcontext(),
        ):
            job.start(session)
            try:
                if source_busy_stop_probe:
                    self.assertTrue(child_adoption_entered.wait(3))
                    deadline = time.monotonic() + 3
                    while (
                        job._getter_stop_receipt2026 is None
                        and not busy_stop_errors
                        and time.monotonic() < deadline
                    ):
                        time.sleep(0.001)
                    receipt = cast(Any, job._getter_stop_receipt2026)
                    self.assertIsNotNone(
                        receipt,
                        f"stop_errors={busy_stop_errors!r}; results={busy_stop_results!r}; "
                        f"source={busy_source_state!r}; "
                        f"publisher_calls={len(busy_publisher_calls)!r}; "
                        f"child_gate={child_adoption_entered.is_set()!r}; "
                        f"flags={(engine._native_outer_cfe0_2026, engine._native_be54_pending2026, engine._native_receiving_cfe2_2026)!r}",
                    )
                    self.assertEqual(receipt.producer, "5f030")
                    self.assertEqual(receipt.sequence, 1)
                    self.assertEqual(receipt.lease.state, "reserved")
                    if observe_busy_lock_order:
                        self.assertTrue(stop_job_attempted.is_set())
                        self.assertFalse(stop_phase_acquired.is_set())
                    release_child_adoption.set()
                    stop_thread = cast(Any, busy_stopper_holder[0])
                    self.assertIsNotNone(stop_thread)
                    stop_thread.join(3)
                    self.assertFalse(stop_thread.is_alive())
                    self.assertEqual(busy_stop_errors, [])
                    self.assertEqual(busy_stop_results, [0])
                if gate_retire_window:
                    self.assertTrue(retire_entered.wait(3))
                    self.assertEqual(len(decisions), 1)
                    expired_decision = decisions[0]
                    with self.assertRaises(ValueError):
                        job._validate_getter_decision_2026(
                            expired_decision, route=expired_decision.route
                        )
                    release_retire.set()
                if stop_after_execute:
                    self.assertTrue(import_entered.wait(3))
                    deadline = time.monotonic() + 3
                    while (
                        not stop_results
                        and not stop_errors
                        and time.monotonic() < deadline
                    ):
                        time.sleep(0.001)
                    self.assertEqual(stop_errors, [])
                    self.assertEqual(stop_results, [1])
                    self.assertIsNone(job._getter_stop_receipt2026)
                    release_import.set()
                try:
                    report = job.result(5)
                except ValueError as error:
                    if not expect_unsupported_success or fail_status:
                        raise
                    self.assertIn("complete imported CanCID output", str(error))
                    self.assertEqual(len(decisions), 1)
                    candidate = decisions[0].candidate
                    execute_record = candidate.execute_record
                    self.assertIsNone(candidate.output)
                    self.assertTrue(candidate.execute_return)
                    self.assertIsNone(job._getter_execute_return2026)
                    self.assertIs(execute_record.result["native_return"], True)
                    self.assertIs(type(execute_record.result["native_phase"]), int)
                    self.assertEqual(
                        execute_record.result["identifiers"], expected_cids
                    )
                    self.assertEqual(
                        [call.args[0] for call in imports.call_args_list],
                        [pair.control, pair.engine],
                    )
                    self.assertIsNone(job._pending_getter_next_entry_3d120_2026)
                    self.assertIs(
                        job.worker._getter_last_observation2026, observation_before
                    )
                    self.assertEqual(job.worker._flow_file_index2026, flow_before)
                    self.assertEqual(
                        job.worker._getter_reset_epoch2026, reset_epoch_before + 1
                    )
                    self.assertIs(
                        job.worker._getter_histories_a34_2026, histories_before
                    )
                    self.assertIs(
                        job.worker._getter_flow_received_cids2026, flow_cids_before
                    )
                    self.assertIs(
                        job.worker._getter_flow_query_records2026,
                        flow_queries_before,
                    )
                    self.assertIs(
                        None if persistence is None else persistence.state,
                        persistence_state,
                    )
                    self.assertEqual(persistence_state, persistence_before)
                    self.assertEqual(session.trace.position, len(session.trace.rows))
                    if stop_after_execute and stopper is not None:
                        stopper.join(3)
                        self.assertFalse(stopper.is_alive())
                        self.assertEqual(stop_results, [1])
                    if source_busy_stop_probe:
                        restore_busy_probe()
                    return
            except ValueError as error:
                raise AssertionError(
                    f"raw P5 child stopped at event {session.trace.position}; "
                    f"runner calls={runner_calls}; captured={[row['request'].get('operation') for row in rows]}; "
                    f"next={session.trace.rows[session.trace.position : session.trace.position + 1]}"
                ) from error
            reports = [report]
            if stop_after_completion:
                self.assertEqual(engine.stop_receiving_cid(timeout=3), 1)
                self.assertIsNone(job._getter_stop_receipt2026)
            for sequence in range(2, generations + 1):
                session = session.next_session2026(
                    "get_cid", node=session.node, cpu_index=0
                )
                try:
                    started_sequence = job.start(session)
                except BaseException as error:
                    raise AssertionError(
                        "Later raw P5 source start failed: "
                        f"flags={(engine._native_outer_cfe0_2026, engine._native_be54_pending2026, engine._native_receiving_cfe2_2026)!r}; "
                        f"native_phase={engine.native_phase!r}; worker_phase={engine.worker_phase!r}; "
                        f"sequence={job._sequence!r}; prior_record={job._active_record!r}; "
                        f"lease={None if job._lease is None else (job._lease.state, job._lease.phase)!r}"
                    ) from error
                self.assertEqual(started_sequence, sequence)
                reports.append(job.result(5, sequence=sequence))

        if source_busy_stop_probe:
            restore_busy_probe()
        if stopper is not None:
            release_import.set()
            stopper.join(3)
            self.assertFalse(stopper.is_alive())
            self.assertEqual(stop_errors, [])

        self.assertIs(report["native_return"], not fail_status, report)
        self.assertEqual(report["identifiers"], expected_cids)
        self.assertEqual(runner_calls, [True] * generations)
        self.assertEqual(
            [call.args[0] for call in imports.call_args_list],
            [pair.control, pair.engine] * generations,
        )
        self.assertEqual(engine.received_identifiers, expected_cids)
        self.assertEqual(session.trace.position, len(session.trace.rows))
        self.assertEqual(len(decisions), generations)
        self.assertEqual(len(candidates), generations)
        for index, decision in enumerate(decisions):
            execute_record = decision.candidate.execute_record
            self.assertIs(execute_record.result, reports[index])
            self.assertIs(type(execute_record.result["native_return"]), bool)
            self.assertIs(type(execute_record.result["native_phase"]), int)
            self.assertTrue(execute_record.context._expired)
        expected_stage_names = [
            item for _ in range(generations) for item in ("native", "control")
        ]
        self.assertEqual([name for name, _thread in stages], expected_stage_names)
        self.assertEqual(combined_tail_calls, [])
        actual_outer = stages[0][1]
        self.assertIsNotNone(actual_outer)
        self.assertTrue(all(thread is actual_outer for _name, thread in stages))
        self.assertEqual(len(execute_record_at_import), generations)
        self.assertTrue(all(item is not None for item in execute_record_at_import))
        self.assertEqual(len(execute_record_checks), generations)
        self.assertIsNone(job._getter_execute_pending2026)
        expected_route = "success_3d120" if not fail_status else "failure_30340"
        self.assertEqual(
            [item.route for item in decisions], [expected_route] * generations
        )
        self.assertIsNone(job._getter_execute_return2026)
        self.assertIsNone(job._getter_callback_candidate2026)
        self.assertIsNone(job._getter_callback_decision2026)
        with self.assertRaises(ValueError):
            job._validate_getter_decision_2026(decisions[-1], route=decisions[-1].route)
        if generations > 1:
            self.assertIs(job.result(5, sequence=1), report)
            self.assertEqual(
                [item["identifiers"] for item in reports],
                [expected_cids] * generations,
            )
            self.assertEqual(job.state.sequence, generations)

    def test_prepare_return_does_not_import_getter_snapshot(self):
        from tests.test_programming_2026_common import RawControlStageMachineTests

        fixture = RawControlStageMachineTests()
        self.addCleanup(fixture.doCleanups)
        engine, controller, session = fixture.fixture(
            operation="prepare",
            paired=True,
            dependencies=("TCUWControlCommPhase.dll",),
            events=(
                fixture.event("set_communication_log_mode", mode=2),
                fixture.event("set_communication_log_mode", mode=0),
            ),
        )
        session.bind_engine2026(engine)
        session.bind_runtime2026(controller.runtime)
        session.bind_controller2026(controller)
        job = engine.bind_thread_job(controller)
        self.addCleanup(job.stop)
        pair = engine.interface_pair
        assert pair is not None

        with (
            patch.object(
                ProgrammingReplay,
                "_runner",
                return_value=lambda: {"native_return": True},
            ),
            patch.object(pair, "import_into", wraps=pair.import_into) as imports,
        ):
            job.start(session)
            report = job.result(5)

        self.assertIs(report["native_return"], True)
        self.assertEqual(
            [call.args[0] for call in imports.call_args_list], [pair.control]
        )

    def test_raw_getter_throw_does_not_import_return_snapshot(self):
        from tests.test_programming_2026_common import RawControlStageMachineTests

        fixture = RawControlStageMachineTests()
        self.addCleanup(fixture.doCleanups)
        engine, controller, session = fixture.fixture(
            operation="get_cid",
            paired=True,
            dependencies=("TCUWControlCommPhase.dll",),
        )
        job = engine.bind_thread_job(controller)
        self.addCleanup(job.stop)
        pair = engine.interface_pair
        assert pair is not None
        fault = RuntimeError("authored raw getter fault")

        def throwing_getter(*_args):
            raise fault

        with (
            patch.object(ProgrammingReplay, "_runner", throwing_getter),
            patch.object(pair, "import_into", wraps=pair.import_into) as imports,
        ):
            job.start(session)
            with self.assertRaises(RuntimeError) as caught:
                job.result(5)

        self.assertIs(caught.exception, fault)
        self.assertEqual(
            [call.args[0] for call in imports.call_args_list], [pair.control]
        )

    def test_actual_dh_progress_publishes_before_percent_observer_fault(self):
        import tempfile
        from pathlib import Path

        from scripts.calibration import CalibrationContainer
        from scripts.calibration_2026 import parse_cuw_2026
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )
        from scripts.native_modules import identify_native_module
        from scripts.programming_2026_common import NativeRuntime2026
        from scripts.programming_2026_dh import (
            bind_native_context,
            execute_context,
        )
        from scripts.programming_replay import _native_request
        from tests.test_cuw_engine_worker import encoded_table
        from tests.test_programming_2026_common import make_raw_control_fixture2026
        from tests.test_programming_2026_dh import (
            DHUDSGetterLifecycle,
            bind_dh_parameter_fixture,
            table,
        )

        source_case = DHUDSGetterLifecycle(
            "test_loaded_control_base_binds_gateway_without_reselecting_row"
        )
        self.addCleanup(source_case.doCleanups)
        source_engine = source_case.engine_fixture(
            cpu_count=1, image_data=b"S1071000646174614E\nS9031000EC\n"
        )
        source = source_engine._source
        assert source is not None
        container = parse_cuw_2026(source)
        assert isinstance(container, CalibrationContainer)
        module_name = "TCUWCanDHGatewayFlashWriter.dll"
        profile_values = {
            "CanIDForPrepareWrite": "0700/0708",
            "StartAddress": "00001000",
        }
        profile_fields = (
            "ParamFileKeySystemProtocolMicon",
            "DLLFileNameForPrepareWrite",
            "DLLFileNameForFlashWrite",
            "DLLFileNameForGetCID",
            "DLLFileNameForChangeToReprogGatewayMode",
            "EnableDLLVersionInformation",
            "GetCANIDFunctionNameForFlashWrite",
            "AlternateDLLFileNamesForGetCID",
            "EnableAlternateDLLVersionsInformationForGetCID",
            *profile_values,
        )
        profile_row = (
            "108CAN383",
            "TCUWSilPrepareWriter.dll",
            module_name,
            "TCUWSilCIDGetter.dll",
            "",
            "0\n0\n0\n0",
            "GetCanIDsFromParamForPrepareWrite",
            "",
            "0",
            *profile_values.values(),
        )
        catalog = {
            "108CAN383.ini": encoded_table(profile_fields, (profile_row,)),
            "Parameter.ini": encoded_table(
                (
                    "ParamFileKeySystemProtocolMicon",
                    "M16CTypeFlag",
                    "FORESTTypeFlag",
                    "PasswordAddress",
                    "ByteOrder",
                    "FlagToNonChangeReprogGWModeProcess",
                ),
                (("108CAN383", "0", "0", "00", "1", "1"),),
            ),
        }
        image_root = Path("runtime/no-car-21/recovered")
        module_files = {
            name: read_private_bytes(image_root / name)
            for name in (
                module_name,
                "TCUWControlCommPhase.dll",
                "TCUWSilPrepareWriter.dll",
                "TCUWSilCIDGetter.dll",
                "TCUWDHUtils.dll",
                "SecretInfo.dll",
                "CUW.dll",
            )
        }
        identity = identify_native_module(
            hashlib.sha256(module_files[module_name]).hexdigest(), module_name
        )
        family_selection = bind_dh_parameter_fixture(
            container,
            {
                "108CAN383.ini": table(
                    [
                        "ParamFileKeySystemProtocolMicon",
                        "DLLFileNameForFlashWrite",
                        "GetCANIDFunctionNameForFlashWrite",
                        "CanIDForPrepareWrite",
                        "StartAddress",
                    ],
                    [
                        [
                            "108CAN383",
                            module_name,
                            "GetCanIDsFromParamForPrepareWrite",
                            profile_values["CanIDForPrepareWrite"],
                            profile_values["StartAddress"],
                        ]
                    ],
                )
            },
            "write",
            encoded=False,
        )
        family_context = bind_native_context(
            container,
            1,
            (),
            family_selection,
            identity,
            {
                "selected_module": module_files[module_name],
                "dh_utils_module": module_files["TCUWDHUtils.dll"],
                "secret_info_module": module_files["SecretInfo.dll"],
                "cuw_module": module_files["CUW.dll"],
            },
            {"cpu_index": 0, "dh_state": source_engine.dh_state},
        )
        pending, rows = [], []

        def capture(event, remaining):
            operation = event["operation"]
            if operation == "get_timeout":
                result = 101
            elif operation == "get_send_timeout":
                result = 102
            elif operation == "start_flow_control_filter":
                result = 17
            elif operation == "is_sending_sync_periodic":
                result = False
            elif operation == "write_messages":
                pdu = event["data"][4:]
                if pdu == bytes.fromhex("22fd10"):
                    answer = bytes.fromhex("62fd10")
                elif pdu == bytes.fromhex("3101f010"):
                    answer = bytes.fromhex("7101f0109a")
                elif pdu.startswith(b"\x34"):
                    answer = bytes.fromhex("74200003")
                elif pdu.startswith(b"\x36"):
                    answer = b"\x76"
                elif pdu == b"\x37":
                    answer = b"\x77"
                elif pdu.startswith(bytes.fromhex("3101f011000144")):
                    answer = bytes.fromhex("7101f011200003")
                elif pdu == bytes.fromhex("3101f01101"):
                    answer = bytes.fromhex("7101f01100")
                elif pdu == bytes.fromhex("1101"):
                    answer = b"\x51"
                else:
                    raise AssertionError(f"Unexpected native writer PDU: {pdu.hex()}")
                pending.append(answer)
                result = 1
            elif operation == "read_specified_can_message":
                result = bytes.fromhex("00000708") + pending.pop(0)
            else:
                result = None
            rows.append(
                {
                    "kind": "action",
                    "request": _native_request(event),
                    "result": {
                        "type": (
                            "none"
                            if result is None
                            else "bool"
                            if type(result) is bool
                            else "int"
                            if type(result) is int
                            else "bytes"
                        ),
                        "value": result.hex() if type(result) is bytes else result,
                    },
                    "elapsed_ms": 1,
                }
            )
            return result

        direct_runtime = NativeRuntime2026(capture)
        direct_result = execute_context(family_context, direct_runtime)
        self.assertIs(direct_result["native_return"], True)
        self.assertTrue(
            any(
                row["request"]["operation"] == "notify_progress_percent" for row in rows
            )
        )
        clock_start = {
            "kind": "action",
            "request": {"operation": "get_local_milliseconds_of_day"},
            "result": {"type": "int", "value": 1000},
            "elapsed_ms": 1,
        }
        clock_end = {**clock_start, "result": {"type": "int", "value": 2000}}
        mode_start = {
            "kind": "action",
            "request": {"operation": "set_communication_log_mode", "mode": 2},
            "result": {"type": "int", "value": 0},
            "elapsed_ms": 1,
        }
        mode_end = {
            **mode_start,
            "request": {"operation": "set_communication_log_mode", "mode": 0},
        }
        engine, controller, session = make_raw_control_fixture2026(
            self,
            source=source,
            catalog=catalog,
            module_files=module_files,
            operation="write",
            events=(clock_start, mode_start, *rows, mode_end, clock_end),
        )
        self.addCleanup(engine.close)
        self.addCleanup(session.trace.close)
        output = tempfile.TemporaryDirectory(dir="runtime/no-car-33")
        self.addCleanup(output.cleanup)
        assert engine._source is not None
        engine.bind_persistence(
            CUWPersistence(
                Path(output.name),
                ReproInfoState((RecoveryCalibration("authored.cuw", engine._source),)),
            )
        )
        initial_counts = tuple(range(101, 117))
        initial_percentages = tuple(range(11, 27))
        engine.dh_state._transferred_bytes = initial_counts
        engine.dh_state._progress = initial_percentages
        job = engine.bind_thread_job(controller)
        self.addCleanup(job.stop)
        self.assertEqual(job.worker._control_count_scratch2026, [0] * 16)
        self.assertEqual(
            job.worker._control_percent_scratch2026, list(initial_percentages)
        )
        observed = []
        original_action = session.trace.action

        def faulting_observer(event, remaining):
            if event["operation"] in (
                "notify_progress_count",
                "notify_progress_percent",
            ):
                observed.append(
                    (
                        event["operation"],
                        engine.dh_state._transferred_bytes,
                        engine.dh_state._progress,
                        job.worker._previous_percentages2026,
                    )
                )
                if event["operation"] == "notify_progress_percent":
                    raise RuntimeError("authored progress observer fault")
            return original_action(event, remaining)

        session.trace.action = faulting_observer
        controller.runtime.action = faulting_observer
        job.start(session)
        with self.assertRaisesRegex(RuntimeError, "authored progress observer fault"):
            job.result(5)
        self.assertEqual(
            observed,
            [
                (
                    "notify_progress_count",
                    (2, *([0] * 15)),
                    initial_percentages,
                    (),
                ),
                (
                    "notify_progress_percent",
                    (2, *([0] * 15)),
                    (50, *initial_percentages[1:]),
                    initial_percentages,
                ),
            ],
        )
        self.assertEqual(engine.dh_state._transferred_bytes, (2, *([0] * 15)))
        self.assertEqual(engine.dh_state._progress, (50, *initial_percentages[1:]))
        self.assertEqual(job.worker._previous_percentages2026, initial_percentages)
        self.assertEqual(
            job.worker._control_percent_scratch2026,
            [50, *initial_percentages[1:]],
        )

    def test_missing_profile_loader_uses_actual_general_fallback(self):
        for legacy_flag in (True, False):
            with self.subTest(legacy_flag=legacy_flag):
                engine, controller, job, session = self.imported_prepare(
                    operation="get_cid", include_profile=False, legacy_flag=legacy_flag
                )
                clock = lambda: 1000
                session.trace.native_local_milliseconds_of_day = clock
                controller.runtime.local_milliseconds_of_day = clock
                job.start(session)
                report = job.result(2)
                self.assertIsNone(report["native_return"])
                self.assertEqual(report["exports"], ())
                self.assertTrue(job.worker.native_fatal_input80)
                self.assertEqual(job.worker.control_state.error_kind, 9999)
                self.assertTrue(engine.native_fatal_output)
                self.assertFalse(session.used)
                self.assertEqual(session.trace.position, 0)

    def test_late_native_cleanup_retains_exclusive_phase_admission(self):
        engine, controller, job, session = self.imported_prepare(
            operation="get_cid", include_control=False
        )
        cleanup = engine.bind_cleanup_controller()
        original = cleanup.release_retired_selected
        reached, release = threading.Event(), threading.Event()
        clock = lambda: 1000
        session.trace.native_local_milliseconds_of_day = clock
        controller.runtime.local_milliseconds_of_day = clock

        def gated_cleanup(worker):
            reached.set()
            if not release.wait(2):
                raise TimeoutError("Authored late-cleanup gate timed out")
            original(worker)

        with patch.object(
            cleanup, "release_retired_selected", side_effect=gated_cleanup
        ):
            job.start(session)
            try:
                self.assertTrue(reached.wait(2))
                self.assertFalse(engine.active)
                self.assertTrue(job.native_work_pending)
                with (
                    self.assertRaises(ValueError),
                    engine.controller_execution(controller, 0),
                ):
                    self.fail("New phase entered before late native cleanup")
                reservation = None
                try:
                    with self.assertRaises(ValueError):
                        reservation = engine.reserve_phase(controller, 0)
                finally:
                    if reservation is not None:
                        engine.release_reserved_phase(reservation)
                self.assertFalse(engine.active)
                self.assertTrue(job.native_work_pending)
            finally:
                release.set()
            job.result(2)
        self.assertFalse(job.native_work_pending)
        with engine.controller_execution(controller, 0):
            pass

    def test_missing_profile_lookup_integer_fault_does_not_mark_native_fatal(self):
        from scripts.programming_2026_common import NativeCallbackLookupError

        engine, controller, job, session = self.imported_prepare(
            operation="get_cid", include_profile=False
        )
        clock = lambda: 1000
        session.trace.native_local_milliseconds_of_day = clock
        controller.runtime.local_milliseconds_of_day = clock
        job.start(session)
        with self.assertRaises(NativeCallbackLookupError):
            job.result(2)
        self.assertFalse(job.worker.native_fatal_input80)
        self.assertFalse(engine.native_fatal_output)
        self.assertFalse(session.used)

    def test_host_boundary_fault_unwinds_actual_child_preserving_identity(self):
        engine, controller, job, session = self.imported_prepare()
        fault = ValueError("authored host cancellation probe fault")

        def cancelled():
            if threading.current_thread() is job._child:
                raise fault
            return False

        controller.runtime.cancelled = cancelled
        job.start(session)
        with self.assertRaises(ValueError) as caught:
            job.result(2)
        self.assertIs(caught.exception, fault)
        self.assertIs(controller.runtime.cancelled, cancelled)
        self.assertFalse(engine.active)
        self.assertFalse(engine.native_fatal_output)
        self.assertTrue(job.state.child_alive)
        self.assertTrue(job.state.waiting_for_resume)
        self.assertEqual(job.state.child_exit_code, 0x103)
        self.assertFalse(session.used)
        job.stop(2)
        self.assertFalse(job.state.child_alive)
        self.assertEqual(job.state.child_exit_code, 0)
        self.assertEqual(job.state.outer_exit_code, 0)

    def test_real_gateway_failure_queries_and_reconnects_actual_engine_view(self):
        fixture = gateway_fixtures.GatewayStartupTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        sdk, engine_device, engine, controller, worker, _producer = fixture.context(
            [], general=fixture.general(True)
        )
        job = engine.bind_thread_job(controller)
        retry = engine.bind_retry_controller()
        errors = []

        def phase():
            try:
                with engine.controller_execution(controller, 1):
                    sdk.fail = lambda event: event["operation"] == "passthru_ioctl"
                    startup = worker.run_gateway_startup()
                    self.assertIsNotNone(startup)
                    assert startup is not None
                    self.assertFalse(startup.returned)
                    self.assertTrue(startup.output_flag)
                    sdk.fail = None
                    job._query_native_worker_error()
            except BaseException as error:  # noqa: BLE001 - retain actual phase failure for its owner
                errors.append(error)

        thread = threading.Thread(target=phase, daemon=True)
        thread.start()
        try:
            query = retry.wait_for_query()
            result = engine.inform_result_of_query_retry(1, 0)
            thread.join(2)
        finally:
            sdk.cancelled = True
            thread.join(2)
            sdk.cancelled = False
        self.assertEqual(query.error_kind, 1)
        self.assertEqual(result, 0)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(engine_device.connecting)
        self.assertFalse(controller.runtime_device().connecting)
        self.assertEqual(controller.runtime_device().calls, 0)
        self.assertTrue(worker.control_state.failed)
        self.assertEqual(
            (worker.control_state.primary_error, worker.control_state.passthru_error),
            (0, 0),
        )
        operations = [item["operation"] for item in sdk.calls]
        self.assertIn("passthru_disconnect", operations)
        self.assertGreaterEqual(operations.count("passthru_connect"), 2)

    def test_prepare_reentry_runs_prefix_without_new_dispatch_or_result(self):
        engine, controller, job, session = self.imported_prepare(include_control=False)
        retry = engine.bind_retry_controller()
        clock_calls = []
        now = [1000]

        def clock():
            clock_calls.append(now[0])
            return now[0]

        session.trace.native_local_milliseconds_of_day = clock
        controller.runtime.local_milliseconds_of_day = clock
        self.assertEqual(job.start(session), 1)
        report = job.result(2)
        self.assertEqual(job.worker.native_prepare_handshake, 1)
        previous_calls = len(clock_calls)
        cancelled = controller.runtime.cancelled
        fault = ValueError("Authored external prepare-prefix boundary fault")

        def cancelled_fault():
            raise fault

        controller.runtime.cancelled = cancelled_fault
        try:
            with self.assertRaises(ValueError) as caught:
                job.start(session)
            self.assertIs(caught.exception, fault)
        finally:
            controller.runtime.cancelled = cancelled
        self.assertEqual(job.worker.native_prepare_handshake, 1)
        self.assertEqual(len(clock_calls), previous_calls)
        now[0] = 2000
        with (
            patch.object(
                threading.Thread,
                "start",
                side_effect=AssertionError("Prepare reentry must not start a thread"),
            ),
            patch.object(
                job.worker,
                "_reapply_retained_selection_3e710",
                side_effect=AssertionError("Prepare reentry must not enter36800 body"),
            ),
        ):
            self.assertIsNone(job.start(session))
        self.assertEqual(len(clock_calls), previous_calls + 1)
        self.assertEqual(retry.source_state.resume_milliseconds_d314, 2000)
        self.assertEqual(job.worker.native_prepare_handshake, 3)
        self.assertEqual(job.state.sequence, 1)
        self.assertTrue(job.native_worker_exists)
        self.assertFalse(job.native_work_pending)
        self.assertFalse(engine.active)
        self.assertFalse(session.used)
        self.assertIs(job.result(2), report)

    def test_native_cid_stop_without_native_event_returns_without_host_interruption(
        self,
    ):
        engine, controller, job, session = self.imported_prepare(operation="get_cid")
        fault = ValueError("authored native local-clock host fault")

        def clock_fault():
            raise fault

        session.trace.native_local_milliseconds_of_day = clock_fault
        controller.runtime.local_milliseconds_of_day = clock_fault
        cancelled = controller.runtime.cancelled
        job.start(session)
        with self.assertRaises(ValueError) as caught:
            job.result(2)
        self.assertIs(caught.exception, fault)
        self.assertEqual(engine.native_phase, 0)
        self.assertFalse(engine.active)
        self.assertTrue(job.native_worker_exists)
        self.assertTrue(job.state.child_alive)
        self.assertFalse(job.host_stop_requested)
        self.assertEqual(engine.stop_receiving_cid(timeout=2), 1)
        self.assertFalse(engine.native_cancelled())
        self.assertFalse(job.host_stop_requested)
        self.assertTrue(job.native_worker_exists)
        self.assertTrue(job.state.child_alive)
        self.assertIs(controller.runtime.cancelled, cancelled)
        job.stop(2)
        self.assertTrue(job.host_stop_requested)
        self.assertFalse(job.state.child_alive)

    def test_outer_late_cleanup_rejects_both_native_self_joins_before_receipt(self):
        engine, _controller, job, root, _pair, _rows, _sdk, _sources = (
            self.authored_two_file_getter_job()
        )
        cleanup = engine.bind_cleanup_controller()
        original_release = cleanup.release_retired_selected
        observations = []
        checked = False

        def outer_late_cleanup(worker):
            nonlocal checked
            self.assertIs(threading.current_thread(), job._outer)
            if not checked:
                checked = True
                self.assertTrue(engine._native_receiving_cfe2_2026)
                for producer, invoke in (
                    ("5f030", lambda: engine.stop_receiving_cid(timeout=1)),
                    ("40580", lambda: engine._cleanup_wait_for_worker(cleanup)),
                ):
                    cancelled_before = engine.native_cancelled()
                    with self.assertRaises(ValueError):
                        invoke()
                    self.assertIsNone(job._getter_stop_receipt2026)
                    self.assertIsNone(engine._pending_getter_stop_origin2026)
                    self.assertEqual(engine.native_cancelled(), cancelled_before)
                    observations.append(producer)
            original_release(worker)

        with patch.object(
            cleanup, "release_retired_selected", side_effect=outer_late_cleanup
        ):
            self.assertEqual(job.start(root), 1)
            job.result(5, sequence=1)

        self.assertEqual(observations, ["5f030", "40580"])
        self.assertIsNone(job._getter_stop_receipt2026)
        self.assertIsNone(engine._pending_getter_stop_origin2026)
        self.assertFalse(engine.native_cancelled())
        deadline = time.monotonic() + 5
        while job.state.sequence < 2 and time.monotonic() < deadline:
            time.sleep(0.001)
        second_report = job.result(5, sequence=2)
        self.assertIs(second_report["native_return"], True)
        self.assertFalse(engine.active)
        self.assertTrue(job.native_worker_exists)

    def test_host_stopped_child_rejects_partial_cleanup_then_finishes_cleanup(self):
        engine, controller, job, session = self.imported_prepare(
            paired=True, operation="get_cid"
        )
        cleanup = engine.bind_cleanup_controller()
        entered, release = threading.Event(), threading.Event()
        original_check = controller.runtime.check

        def blocked_child_check():
            if threading.current_thread() is job._child:
                entered.set()
                if not release.wait(2):
                    raise TimeoutError("Authored host-cleanup child gate expired")
            return original_check()

        controller.runtime.check = blocked_child_check
        job.start(session)
        try:
            self.assertTrue(entered.wait(2))
            with self.assertRaises(TimeoutError):
                job.stop(0.01)
            self.assertTrue(job.host_stop_requested)
            self.assertTrue(job.state.child_alive)
            with self.assertRaises((ValueError, InterruptedError)):
                cleanup.run()
            self.assertIsNone(job._getter_stop_receipt2026)
            self.assertFalse(engine.native_cancelled())
        finally:
            release.set()

        job.stop(2)
        self.assertTrue(job.host_stop_requested)
        self.assertIsNone(job._getter_stop_receipt2026)
        cleanup.run()
        self.assertTrue(cleanup.state.completed)
        self.assertEqual(engine.native_phase, 4)
        self.assertTrue(job.host_stop_requested)
        self.assertIsNone(job._getter_stop_receipt2026)

    def test_actual_5f030_stop_receipt_survives_native_timeout_and_lease_retirement(
        self,
    ):
        engine, _controller, job, root, _pair, _rows, _sdk, _sources = (
            self.authored_two_file_getter_job()
        )
        entered, release = threading.Event(), threading.Event()
        original_adopt = ThreadPhaseLease2026._adopt

        def gate_reserved_second_child(lease):
            if lease.engine is engine and job.state.sequence == 2:
                entered.set()
                if not release.wait(3):
                    raise TimeoutError("Actual second-root adoption gate expired")
            return original_adopt(lease)

        try:
            with patch.object(
                ThreadPhaseLease2026, "_adopt", gate_reserved_second_child
            ):
                self.assertEqual(job.start(root), 1)
                self.assertIs(job.result(5, sequence=1)["native_return"], True)
                self.assertTrue(entered.wait(3))
                with self.assertRaises(TimeoutError):
                    engine.stop_receiving_cid(timeout=0.05)
                receipt = cast(Any, job._getter_stop_receipt2026)
                self.assertIsNotNone(receipt)
                self.assertEqual(receipt.producer, "5f030")
                self.assertEqual(receipt.sequence, 2)
                self.assertEqual(
                    cast(Any, job._getter_stop_stage2026).stage, "child_requested"
                )
                release.set()
                self.assertEqual(engine.stop_receiving_cid(timeout=3), 0)
                self.assertIs(job._getter_stop_receipt2026, receipt)
                self.assertIsNone(job._lease)
        finally:
            release.set()
            job.stop(3)

    def test_actual_5f030_completed_idle_returns_without_native_event(self):
        engine, controller, job, root, _pair, _rows, _sdk, _sources = (
            self.authored_two_file_getter_job()
        )
        self.complete_two_file_getter_roots(engine, controller, job, root)
        self.assertTrue(job.native_worker_exists)
        self.assertIsNone(job._lease)
        self.assertIsNone(job._getter_stop_receipt2026)

        self.assertFalse(engine._native_receiving_cfe2_2026)
        self.assertEqual(engine.stop_receiving_cid(timeout=2), 1)
        self.assertIsNone(job._getter_stop_receipt2026)
        self.assertFalse(job.host_stop_requested)

    def test_actual_40580_idle_cleanup_issues_receipt(self):
        engine, controller, job, session = self.imported_prepare(operation="get_cid")
        cleanup = engine.bind_cleanup_controller()
        clock = lambda: 1000
        session.trace.native_local_milliseconds_of_day = clock
        controller.runtime.local_milliseconds_of_day = clock
        job.start(session)
        job.result(2)
        self.assertTrue(job.native_worker_exists)
        self.assertIsNone(job._lease)

        engine._cleanup_wait_for_worker(cleanup)

        receipt = cast(Any, job._getter_stop_receipt2026)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt.producer, "40580")
        self.assertIs(receipt.origin.cleanup, cleanup)
        self.assertIsNone(receipt.lease)
        self.assertIs(receipt.origin.generation, job._native_start_generation2026)
        self.assertFalse(job.host_stop_requested)

    def test_actual_40580_active_cleanup_issues_receipt_before_join(self):
        engine, controller, job, session = self.imported_prepare(operation="get_cid")
        cleanup = engine.bind_cleanup_controller()
        entered, release = threading.Event(), threading.Event()

        def blocked_clock():
            entered.set()
            if not release.wait(2):
                raise TimeoutError("Authored cleanup clock gate expired")
            return 1000

        session.trace.native_local_milliseconds_of_day = blocked_clock
        controller.runtime.local_milliseconds_of_day = blocked_clock
        job.start(session)
        self.assertTrue(entered.wait(2))
        child = cast(Any, job._child)
        self.assertIsNotNone(child)
        self.assertTrue(child.is_alive())
        errors = []

        def native_cleanup_wait():
            try:
                engine._cleanup_wait_for_worker(cleanup)
            except BaseException as error:  # noqa: BLE001 - exact cleanup evidence
                errors.append(error)

        cleanup_waiter = threading.Thread(target=native_cleanup_wait)
        cleanup_waiter.start()
        try:
            deadline = time.monotonic() + 2
            while job._getter_stop_receipt2026 is None and time.monotonic() < deadline:
                time.sleep(0.001)
            receipt = cast(Any, job._getter_stop_receipt2026)
            self.assertIsNotNone(receipt)
            self.assertEqual(receipt.producer, "40580")
            self.assertIs(receipt.lease, job._lease)
            self.assertIs(receipt.origin.cleanup, cleanup)
        finally:
            release.set()
            cleanup_waiter.join(2)
            self.assertFalse(cleanup_waiter.is_alive())
        self.assertEqual(errors, [])

    def test_actual_5f030_accepts_current_released_lease_before_outer_retirement(self):
        engine, controller, job, root, _pair, _rows, _sdk, _sources = (
            self.authored_two_file_getter_job()
        )
        cleanup = engine.bind_cleanup_controller()
        reached, release = threading.Event(), threading.Event()
        clock = lambda: 1000
        root.trace.native_local_milliseconds_of_day = clock
        controller.runtime.local_milliseconds_of_day = clock
        errors = []
        original_release = cleanup.release_retired_selected

        def release_gate(worker):
            reached.set()
            if not release.wait(2):
                raise TimeoutError("Authored released-lease gate expired")
            original_release(worker)

        with patch.object(
            cleanup, "release_retired_selected", side_effect=release_gate
        ):
            job.start(root)
            try:
                self.assertTrue(reached.wait(2))
                lease = cast(Any, job._lease)
                self.assertIsNotNone(lease)
                self.assertEqual(lease.state, "released")
                self.assertFalse(cast(Any, job._active_record).completed.is_set())
                self.assertTrue(engine._phase_finished.is_set())

                def native_stop():
                    try:
                        engine.stop_receiving_cid(timeout=2)
                    except BaseException as error:  # noqa: BLE001 - source result
                        errors.append(error)

                stopper = threading.Thread(target=native_stop)
                stopper.start()
                deadline = time.monotonic() + 2
                while (
                    job._getter_stop_receipt2026 is None and time.monotonic() < deadline
                ):
                    time.sleep(0.001)
                receipt = cast(Any, job._getter_stop_receipt2026)
                self.assertIsNotNone(receipt)
                self.assertIs(receipt.lease, lease)
                self.assertEqual(receipt.producer, "5f030")
            finally:
                release.set()
            stopper.join(2)
            self.assertFalse(stopper.is_alive())
            job.result(5, sequence=1)
        self.assertEqual(errors, [])

    def test_getter_stop_receipt_rejects_forged_origin_and_host_stop(self):
        engine, controller, job, session = self.imported_prepare(operation="get_cid")
        with self.assertRaises((TypeError, ValueError)):
            job._record_getter_stop_14_2026(producer="5f030", origin=object())
        with self.assertRaises(ValueError):
            job._record_getter_stop_14_2026(producer="31780", origin=object())
        self.assertIsNone(job._getter_stop_receipt2026)

        entered, release = threading.Event(), threading.Event()

        def blocked_clock():
            entered.set()
            if not release.wait(2):
                raise TimeoutError("Authored host clock gate expired")
            return 1000

        session.trace.native_local_milliseconds_of_day = blocked_clock
        controller.runtime.local_milliseconds_of_day = blocked_clock
        job.start(session)
        self.assertTrue(entered.wait(2))
        host_errors = []

        def host_stop():
            try:
                job.stop(2)
            except BaseException as error:  # noqa: BLE001 - exact host stop evidence
                host_errors.append(error)

        host_stopper = threading.Thread(target=host_stop)
        host_stopper.start()
        try:
            deadline = time.monotonic() + 2
            while not job.host_stop_requested and time.monotonic() < deadline:
                time.sleep(0.001)
            self.assertTrue(job.host_stop_requested)
            self.assertEqual(engine.stop_receiving_cid(timeout=0.05), 1)
            self.assertIsNone(job._getter_stop_receipt2026)
        finally:
            release.set()
            host_stopper.join(2)
            self.assertFalse(host_stopper.is_alive())
        self.assertEqual(host_errors, [])

    def test_actual_start_and_native_stop_use_deadlock_free_lock_order(self):
        engine, _controller, job, root, _pair, _rows, _sdk, _sources = (
            self.authored_two_file_getter_job()
        )
        entered, release = threading.Event(), threading.Event()
        stop_thread_id: list[int | None] = [None]
        stop_job_attempted, stop_job_acquired = threading.Event(), threading.Event()
        stop_phase_acquired = threading.Event()
        original_job_lock = job._lock
        original_phase_lock = engine._phase_state_lock
        original_adopt = ThreadPhaseLease2026._adopt
        stop_results, stop_errors = [], []

        class ObservedJobLock:
            def __init__(self, inner):
                self.inner = inner

            def acquire(self, *args, **kwargs):
                is_stopper = threading.get_ident() == stop_thread_id[0]
                if is_stopper:
                    stop_job_attempted.set()
                    kwargs.setdefault("timeout", 2)
                acquired = self.inner.acquire(*args, **kwargs)
                if acquired is False:
                    raise TimeoutError("Native stop job-lock wait expired")
                if is_stopper:
                    stop_job_acquired.set()
                return acquired

            def release(self):
                self.inner.release()

            def __enter__(self):
                self.acquire()
                return self

            def __exit__(self, *_args):
                self.release()

        class ObservedPhaseLock:
            def __init__(self, inner):
                self.inner = inner

            def acquire(self, *args, **kwargs):
                if (
                    threading.get_ident() == stop_thread_id[0]
                    and stop_job_attempted.is_set()
                    and not stop_job_acquired.is_set()
                ):
                    raise AssertionError("Native stop acquired phase before job lock")
                acquired = self.inner.acquire(*args, **kwargs)
                if acquired and threading.get_ident() == stop_thread_id[0]:
                    stop_phase_acquired.set()
                return acquired

            def release(self):
                self.inner.release()

            def __enter__(self):
                self.acquire()
                return self

            def __exit__(self, *_args):
                self.release()

        def gate_reserved_second_child(lease):
            if lease.engine is engine and job.state.sequence == 2:
                entered.set()
                if not release.wait(3):
                    raise TimeoutError("Actual second-root adoption gate expired")
            return original_adopt(lease)

        job._lock = cast(Any, ObservedJobLock(original_job_lock))
        engine._phase_state_lock = cast(Any, ObservedPhaseLock(original_phase_lock))

        def stop():
            stop_thread_id[0] = threading.get_ident()
            try:
                stop_results.append(engine.stop_receiving_cid(timeout=3))
            except BaseException as error:  # noqa: BLE001 - actual stop path
                stop_errors.append(error)

        stopper = None
        try:
            with patch.object(
                ThreadPhaseLease2026, "_adopt", gate_reserved_second_child
            ):
                self.assertEqual(job.start(root), 1)
                self.assertIs(job.result(5, sequence=1)["native_return"], True)
                self.assertTrue(entered.wait(3))
                stopper = threading.Thread(target=stop)
                stopper.start()
                deadline = time.monotonic() + 2
                while (
                    job._getter_stop_receipt2026 is None and time.monotonic() < deadline
                ):
                    time.sleep(0.001)
                self.assertIsNotNone(
                    job._getter_stop_receipt2026,
                    (
                        stop_errors,
                        job._getter_stop_stage2026,
                        engine.native_receiving_status2026(),
                    ),
                )
                self.assertTrue(stop_job_attempted.is_set())
                self.assertTrue(stop_job_acquired.is_set())
                self.assertTrue(stop_phase_acquired.is_set())
                release.set()
                stopper.join(3)
                self.assertFalse(stopper.is_alive())
                self.assertEqual(stop_errors, [])
                self.assertEqual(stop_results, [0])
        finally:
            release.set()
            job._lock = original_job_lock
            engine._phase_state_lock = original_phase_lock
            if stopper is not None:
                stopper.join(3)

    def test_actual_5f030_accepts_new_reserved_lease_before_child_adoption(self):
        engine, _controller, job, root, _pair, _rows, _sdk, _sources = (
            self.authored_two_file_getter_job()
        )
        entered, release = threading.Event(), threading.Event()
        stop_results = []
        stop_errors = []
        original_adopt = ThreadPhaseLease2026._adopt

        def gate_reserved_second_child(lease):
            if lease.engine is engine and job.state.sequence == 2:
                self.assertEqual(lease.state, "reserved")
                entered.set()
                if not release.wait(3):
                    raise TimeoutError("Actual second-root adoption gate expired")
            return original_adopt(lease)

        def stop():
            try:
                stop_results.append(engine.stop_receiving_cid(timeout=3))
            except BaseException as error:  # noqa: BLE001 - forward source error
                stop_errors.append(error)

        stopper = None
        try:
            with patch.object(
                ThreadPhaseLease2026, "_adopt", gate_reserved_second_child
            ):
                self.assertEqual(job.start(root), 1)
                self.assertIs(job.result(5, sequence=1)["native_return"], True)
                self.assertTrue(entered.wait(3))
                stopper = threading.Thread(target=stop)
                stopper.start()
                deadline = time.monotonic() + 2
                while (
                    job._getter_stop_receipt2026 is None and time.monotonic() < deadline
                ):
                    time.sleep(0.001)
                receipt = cast(Any, job._getter_stop_receipt2026)
                self.assertIsNotNone(receipt)
                self.assertEqual(receipt.producer, "5f030")
                self.assertEqual(receipt.sequence, 2)
                self.assertIsNotNone(receipt.lease)
                self.assertEqual(receipt.lease.state, "reserved")
                self.assertTrue(engine._native_outer_cfe0_2026)
                self.assertTrue(engine._native_receiving_cfe2_2026)
                self.assertIs(type(engine._native_be54_pending2026), bool)
                release.set()
                stopper.join(3)
                self.assertFalse(stopper.is_alive())
                self.assertEqual(stop_errors, [])
                self.assertEqual(stop_results, [0])
        finally:
            release.set()
            if stopper is not None:
                stopper.join(3)

    def test_native_cid_stop_reissues_fresh_worker_preserving_global_resources(self):
        engine, controller, old_job, root, _pair, _rows, _sdk, _sources = (
            self.authored_two_file_getter_job()
        )
        cleanup = engine.bind_cleanup_controller()
        retry = engine.bind_retry_controller()
        state = cleanup.state
        history, selected = state.history, state.selected
        history[:] = b"x" * 0x1028
        state.buffers[:] = [bytearray(b"authored retained buffer"), None]
        buffer = state.buffers[0]
        engine.set_vin(b"JTDBE32KX10000001")
        clock = lambda: 1000
        root.trace.native_local_milliseconds_of_day = clock
        controller.runtime.local_milliseconds_of_day = clock
        with engine.controller_execution(controller, 2):
            engine.dh_state.set_native_count(0, 37)
            engine.dh_state.set_native_percentage(0, 53)
        with engine.controller_execution(controller, 1):
            pass
        old_worker = engine.worker
        self.complete_two_file_getter_roots(engine, controller, old_job, root)
        timing = old_worker.source_state.phase_elapsed_ms
        metadata, configuration = engine.native_metadata, engine.configuration
        fault = ValueError("authored stopped-CID clock fault")

        def clock_fault():
            raise fault

        controller.runtime.local_milliseconds_of_day = clock_fault
        root.trace.native_local_milliseconds_of_day = clock_fault
        fresh = root.next_session2026("get_cid", node=1, cpu_index=0)
        fresh.bind_runtime2026(controller.runtime)
        fresh.bind_engine2026(engine)
        fresh.bind_controller2026(controller)
        fresh.trace.native_local_milliseconds_of_day = clock_fault
        old_job.start(fresh)
        with self.assertRaises(ValueError) as caught:
            old_job.result(5)
        self.assertIs(caught.exception, fault)
        self.assertEqual(engine.stop_receiving_cid(timeout=2), 0)
        old_receipt = cast(Any, old_job._getter_stop_receipt2026)
        self.assertIsNotNone(old_receipt)
        new_job = engine.bind_thread_job(controller)
        self.addCleanup(new_job.stop)
        new_worker = engine.worker
        self.assertIsNot(new_job, old_job)
        self.assertIsNot(
            new_job._native_start_generation2026,
            old_job._native_start_generation2026,
        )
        self.assertIsNone(new_job._getter_stop_receipt2026)
        with self.assertRaises(ValueError):
            new_job._record_getter_stop_14_2026(
                producer="5f030", origin=old_receipt.origin
            )
        self.assertIsNone(new_job._getter_stop_receipt2026)
        self.assertIsNot(new_worker, old_worker)
        self.assertIs(new_job.worker, new_worker)
        self.assertIs(vars(controller)["worker"], new_worker)
        self.assertIs(cleanup.worker, new_worker)
        self.assertIs(retry.worker, new_worker)
        self.assertIs(cleanup.state, state)
        self.assertIs(state.history, history)
        self.assertEqual(state.history, b"x" * 0x1028)
        self.assertIs(state.selected, selected)
        self.assertIs(state.buffers[0], buffer)
        self.assertIs(engine.native_metadata, metadata)
        self.assertIs(engine.configuration, configuration)
        self.assertEqual(engine.vin, b"JTDBE32KX10000001")
        self.assertEqual(engine.dh_state.transferred_bytes, (37, 0, 0, 0))
        self.assertEqual(engine.dh_state.progress, (53, 0, 0, 0))
        self.assertEqual(new_worker.source_state.phase_elapsed_ms, timing)
        self.assertEqual(new_worker.native_prepare_handshake, 0)
        self.assertFalse(new_worker.control_state.fatal)
        self.assertFalse(new_worker.control_state.failed)
        with self.assertRaises(ValueError):
            old_worker.validate_source()
        with self.assertRaises(ValueError):
            old_job.validate_owner(engine)

    def test_native_cid_reissue_preserves_two_file_received_projection(self):
        engine, controller, job, root, _pair, rows, sdk, _sources = (
            self.authored_two_file_getter_job()
        )
        self.assertEqual(job.start(root), 1)
        first_report = job.result(5, sequence=1)
        deadline = time.monotonic() + 5
        while job.state.sequence < 2 and time.monotonic() < deadline:
            time.sleep(0.001)
        second_report = job.result(5, sequence=2)
        self.assertIs(first_report["native_return"], True)
        self.assertIs(second_report["native_return"], True)
        worker = job.worker
        self.assertEqual(
            worker._getter_flow_received_cids2026[:2],
            ((b"OLD", b"SECOND-LATEST"), (b"OTHER", b"SECOND-LATEST")),
        )
        self.assertEqual(worker.source_state.current_file_index, 0)
        with engine.controller_execution(controller, 0):
            self.assertTrue(worker.mark_cid_reception_complete())
        self.assertEqual(worker.source_state.target_indices, (0, 1))
        self.assertEqual(worker.source_state.authored_target_indices, (0, 1))

        old_worker = worker
        loaded = worker.loaded_metadata
        sources, metadata = engine.file_sources, engine.native_metadata
        cleanup = engine.bind_cleanup_controller()
        selected = cleanup.state.selected
        fault = ValueError("authored projection-preserving CID clock fault")

        def clock_fault():
            raise fault

        root.trace.native_local_milliseconds_of_day = clock_fault
        controller.runtime.local_milliseconds_of_day = clock_fault
        fresh = root.next_session2026("get_cid", node=1, cpu_index=0)
        fresh.bind_runtime2026(controller.runtime)
        fresh.bind_engine2026(engine)
        fresh.bind_controller2026(controller)
        fresh.trace.native_local_milliseconds_of_day = clock_fault
        job.start(fresh)
        with self.assertRaises(ValueError) as caught:
            job.result(5)
        self.assertIs(caught.exception, fault)
        self.assertEqual(engine.stop_receiving_cid(timeout=2), 0)
        replacement = engine.bind_thread_job(controller)
        self.addCleanup(replacement.stop)
        self.assertIsNot(replacement, job)
        self.assertIsNot(replacement.worker, old_worker)
        self.assertIs(engine.file_sources, sources)
        self.assertIs(engine.native_metadata, metadata)
        self.assertIs(cleanup.state.selected, selected)
        self.assertEqual(replacement.worker.loaded_metadata, loaded)
        self.assertEqual(replacement.worker.source_state.target_indices, (0, 1))
        self.assertEqual(
            replacement.worker.source_state.authored_target_indices,
            (0, 1),
        )
        self.assertEqual(replacement.worker.native_writer_target_index, 0)
        self.assertTrue(rows)
        self.assertTrue(sdk.pending == [])

    def test_native_worker_reissue_rolls_back_dependent_owner_failure(self):
        engine, controller, old_job, root, _pair, _rows, _sdk, _sources = (
            self.authored_two_file_getter_job()
        )
        cleanup = engine.bind_cleanup_controller()
        retry = engine.bind_retry_controller()
        old_worker = engine.worker
        state = cleanup.state
        self.complete_two_file_getter_roots(engine, controller, old_job, root)
        clock_fault = ValueError("authored stopped-CID clock fault")

        def clock():
            raise clock_fault

        root.trace.native_local_milliseconds_of_day = clock
        controller.runtime.local_milliseconds_of_day = clock
        fresh = root.next_session2026("get_cid", node=1, cpu_index=0)
        fresh.bind_runtime2026(controller.runtime)
        fresh.bind_engine2026(engine)
        fresh.bind_controller2026(controller)
        fresh.trace.native_local_milliseconds_of_day = clock
        old_job.start(fresh)
        with self.assertRaises(ValueError) as caught:
            old_job.result(5)
        self.assertIs(caught.exception, clock_fault)
        self.assertFalse(old_job.native_work_pending)
        self.assertEqual(engine.stop_receiving_cid(timeout=2), 0)
        failure = RuntimeError("authored dependent-owner rebind fault")
        with (
            patch.object(retry, "rebind_worker", side_effect=failure),
            self.assertRaises(RuntimeError) as caught,
        ):
            engine.bind_thread_job(controller)
        self.assertIs(caught.exception, failure)
        self.assertIs(engine.thread_job, old_job)
        self.assertIs(engine.worker, old_worker)
        self.assertIs(vars(controller)["worker"], old_worker)
        self.assertIs(cleanup.worker, old_worker)
        self.assertIs(retry.worker, old_worker)
        self.assertIs(cleanup.state, state)
        old_worker.validate_source()
        old_job.validate_owner(engine)
        replacement = engine.bind_thread_job(controller)
        self.addCleanup(replacement.stop)
        self.assertIsNot(replacement, old_job)
        self.assertIs(cleanup.worker, replacement.worker)
        self.assertIs(retry.worker, replacement.worker)

    def test_actual_thread_unwind_composes_nonempty_whole_engine_cleanup(self):
        engine, controller, job, session = self.imported_prepare(paired=True)
        cleanup = engine.bind_cleanup_controller()
        selected = cleanup.state.selected
        cleanup.state.buffers[:] = [
            bytearray(b"authored one"),
            bytearray(b"authored two"),
        ]
        cleanup.state.history[:] = b"x" * 0x1028
        fault = ValueError("authored host deadline source fault")

        def cancelled():
            if threading.current_thread() is job._child:
                raise fault
            return False

        controller.runtime.cancelled = cancelled
        job.start(session)
        with self.assertRaises(ValueError) as caught:
            job.result(2)
        self.assertIs(caught.exception, fault)
        self.assertIs(cleanup.state.selected, selected)
        self.assertTrue(job.state.child_alive)
        controller.runtime.cancelled = lambda: False
        cleanup.run()
        self.assertTrue(cleanup.state.completed)
        self.assertIsNone(cleanup.state.selected)
        assert selected is not None
        self.assertTrue(selected.deleted)
        self.assertEqual(cleanup.state.targets, [None] * 16)
        self.assertEqual(cleanup.state.buffers, [None, None])
        self.assertEqual(cleanup.state.history, bytes(0x1028))
        self.assertFalse(job.state.child_alive)
        self.assertEqual(job.state.outer_exit_code, 0)
        self.assertEqual(engine.native_phase, 4)

    def test_external_stop_is_bounded_and_prestart_cancel_is_not_lost(self):
        engine, _controller, job, session = self.imported_prepare()
        ready, release = threading.Event(), threading.Event()
        original = threading.Thread.start

        def start(thread):
            if thread.name == "CUW2026-5ccd0":
                ready.set()
                if not release.wait(2):
                    raise TimeoutError("authored thread-start gate timed out")
            original(thread)

        with patch.object(threading.Thread, "start", start):
            job.start(session)
            self.assertTrue(ready.wait(2))
            self.assertTrue(engine.active)
            try:
                with self.assertRaises(TimeoutError):
                    job.stop(0.01)
                self.assertFalse(engine.native_cancelled())
                self.assertTrue(engine.active)
            finally:
                release.set()
            job.stop(2)
        with self.assertRaises(InterruptedError):
            job.result(2)
        self.assertFalse(engine.active)
        self.assertTrue(engine._phase_finished.is_set())
        self.assertFalse(session.used)
        self.assertFalse(job.state.child_alive)

    def test_external_stop_deadline_includes_stalled_outer_start_lock(self):
        engine, controller, job, session = self.imported_prepare()
        ready, release = threading.Event(), threading.Event()
        original = threading.Thread.start
        errors = []
        controller.runtime.cancelled = lambda: True

        def start(thread):
            if thread.name == "CUW2026-3cb90":
                ready.set()
                if not release.wait(2):
                    raise TimeoutError("authored outer-start gate timed out")
            original(thread)

        def schedule():
            try:
                job.start(session)
            except BaseException as error:  # noqa: BLE001 - propagate scheduler thread assertion
                errors.append(error)

        with patch.object(threading.Thread, "start", start):
            scheduler = threading.Thread(target=schedule)
            scheduler.start()
            self.assertTrue(ready.wait(2))
            try:
                with self.assertRaisesRegex(TimeoutError, "ownership wait"):
                    job.stop(0.01)
                self.assertTrue(engine.active)
            finally:
                release.set()
            scheduler.join(2)
            self.assertFalse(scheduler.is_alive())
            job.stop(2)
        self.assertEqual(errors, [])
        self.assertFalse(engine.active)
        with self.assertRaises(InterruptedError):
            job.result(2)

    def test_native_outer_cannot_join_itself(self):
        engine, controller, job, session = self.imported_prepare()
        original = threading.Thread.start
        observed = []

        def start(thread):
            if thread.name == "CUW2026-5ccd0":
                try:
                    job.stop(0.1)
                except ValueError as error:
                    observed.append(error)
                controller.runtime.cancelled = lambda: True
            original(thread)

        with patch.object(threading.Thread, "start", start):
            job.start(session)
            with self.assertRaises(InterruptedError):
                job.result(2)
        self.assertEqual(len(observed), 1)
        self.assertIn("join itself", str(observed[0]))
        self.assertFalse(engine.active)

    def test_outer_start_failure_releases_real_reservation(self):
        engine, _controller, job, session = self.imported_prepare()
        fault = RuntimeError("authored Thread.start failure")
        with (
            patch.object(threading.Thread, "start", side_effect=fault),
            self.assertRaises(RuntimeError) as caught,
        ):
            job.start(session)
        self.assertIs(caught.exception, fault)
        self.assertFalse(engine.active)
        self.assertFalse(job.state.outer_started)
        self.assertEqual(job.state.sequence, 0)
        self.assertFalse(session.used)
        self.assertTrue(engine._phase_finished.is_set())

    def test_inner_start_failure_releases_reservation_and_preserves_identity(self):
        engine, _controller, job, session = self.imported_prepare()
        fault = RuntimeError("authored inner Thread.start failure")
        original = threading.Thread.start

        def start(thread):
            if thread.name == "CUW2026-5ccd0":
                raise fault
            original(thread)

        with patch.object(threading.Thread, "start", start):
            job.start(session)
            with self.assertRaises(RuntimeError) as caught:
                job.result(2)
            job.stop(2)
        self.assertIs(caught.exception, fault)
        self.assertFalse(engine.active)
        self.assertEqual(job.state.outer_exit_code, 1)
        self.assertFalse(session.used)

    def test_inner_start_failure_terminal_job_completes_real_cleanup(self):
        engine, _controller, job, session = self.imported_prepare(
            paired=True, operation="get_cid"
        )
        cleanup = engine.bind_cleanup_controller()
        fault = RuntimeError("authored terminal child Thread.start failure")
        original = threading.Thread.start

        def start(thread):
            if thread.name == "CUW2026-5ccd0":
                raise fault
            original(thread)

        with patch.object(threading.Thread, "start", start):
            job.start(session)
            with self.assertRaises(RuntimeError) as caught:
                job.result(2)

        self.assertIs(caught.exception, fault)
        self.assertIsNone(job._child)
        self.assertIsNone(job._child_exit)
        self.assertFalse(engine.active)
        self.assertTrue(engine._phase_finished.is_set())
        self.assertFalse(job.host_stop_requested)
        self.assertTrue(job._stop)
        self.assertFalse(cast(Any, job._outer).is_alive())
        self.assertIsNone(job._getter_stop_receipt2026)
        self.assertIsNone(engine._pending_getter_stop_origin2026)

        record = job._completion_records[job._sequence]
        actual_record_sequence = record.sequence
        record.sequence = actual_record_sequence + 1
        try:
            with self.assertRaises(ValueError):
                cleanup.run()
            self.assertIsNone(job._getter_stop_receipt2026)
            self.assertIsNone(engine._pending_getter_stop_origin2026)
            self.assertFalse(engine.native_cancelled())
        finally:
            record.sequence = actual_record_sequence

        cleanup.run()

        self.assertTrue(cleanup.state.completed)
        self.assertEqual(engine.native_phase, 4)
        self.assertIsNone(job._getter_stop_receipt2026)
        self.assertIsNone(engine._pending_getter_stop_origin2026)
        with self.assertRaises(RuntimeError) as after_cleanup:
            job.result(2)
        self.assertIs(after_cleanup.exception, fault)

    def test_direct_construction_rejected(self):
        with self.assertRaises(TypeError):
            ThreadPhaseLease2026(None, None, 0)
        with self.assertRaises(TypeError):
            EngineThreadJob2026(None, None)

    def test_phase_reserves_real_engine_before_child_start(self):
        lease = self.engine.reserve_phase(self.controller, 0)
        self.assertTrue(self.engine.active)
        self.assertIsNone(self.engine._phase_thread)
        self.assertEqual(lease.state, "reserved")
        with self.assertRaisesRegex(ValueError, "active"):
            self.engine.reserve_phase(self.controller, 1)
        with self.assertRaisesRegex(ValueError, "active"):
            self.engine.load_cuw(calibration())
        self.engine.release_reserved_phase(lease)
        self.assertFalse(self.engine.active)
        self.assertEqual(lease.state, "released")
        with self.assertRaises(ValueError):
            validate_thread_phase_lease(lease, self.engine)

    def test_exact_identity_and_phase_lease_copy_are_rejected(self):
        lease = self.engine.reserve_phase(self.controller, 0)
        try:
            for candidate, owner, phase in (
                (copy.copy(lease), self.engine, 0),
                (lease, object(), 0),
                (lease, self.engine, 1),
            ):
                with self.subTest(phase=phase), self.assertRaises(ValueError):
                    validate_thread_phase_lease(candidate, owner, phase=phase)
            with self.assertRaises(ValueError):
                validate_thread_phase_lease(lease, self.engine, controller=object())
        finally:
            self.engine.release_reserved_phase(lease)

    def test_actual_child_adopts_phase_and_releases_original_event(self):
        lease = self.engine.reserve_phase(self.controller, 0)
        completed = self.engine._phase_finished
        observed = []
        errors = []

        def child():
            try:
                with self.engine.controller_execution(self.controller, 0, lease=lease):
                    self.engine._require_owned_phase()
                    observed.append((lease.state, self.engine._phase_thread))
                    self.assertIs(self.engine.worker, self.worker)
            except BaseException as error:  # noqa: BLE001 - propagate actual child assertions
                errors.append(error)

        thread = threading.Thread(target=child)
        thread.start()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(observed, [("adopted", thread.ident)])
        self.assertIs(self.engine._phase_finished, completed)
        self.assertTrue(completed.is_set())
        self.assertEqual(lease.state, "released")
        self.assertFalse(self.engine.active)

    def test_prestart_cancellation_survives_child_adoption_and_fault(self):
        lease = self.engine.reserve_phase(self.controller, 0)
        self.engine._cancelled.set()
        errors = []

        def child():
            try:
                with self.engine.controller_execution(self.controller, 0, lease=lease):
                    self.assertTrue(self.runtime.native_cancellation_requested())
                    self.runtime.check_native_cancelled()
            except BaseException as error:  # noqa: BLE001 - transport actual fault to test owner
                errors.append(error)

        thread = threading.Thread(target=child)
        thread.start()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], NativeException2026)
        self.assertEqual(lease.state, "released")
        self.assertFalse(self.engine.active)
        self.assertTrue(self.engine._phase_finished.is_set())

    def test_thread_job_identity_and_stop_without_start(self):
        job = self.engine.bind_thread_job(self.controller)
        self.assertIs(job, self.engine.bind_thread_job(self.controller))
        self.assertIs(job.worker, self.worker)
        self.assertIs(self.engine.thread_job, job)
        with self.assertRaises(ValueError):
            job.validate_owner(object())
        with self.assertRaises(TypeError):
            job.start(object())  # pyright: ignore[reportArgumentType] - malformed boundary
        with self.assertRaises(ValueError):
            job.result()
        with self.assertRaisesRegex(ValueError, "native cancellation"):
            job.stop_native()
        with self.assertRaises(ValueError):
            job.wait_prepare_acknowledgement()
        with self.assertRaises(ValueError):
            job.request_prepare_acknowledgement()
        with self.assertRaises(ValueError):
            job.dispatch_retry_callback()
        with self.assertRaises(ValueError):
            job.dispatch_worker_tail()
        with self.assertRaises(ValueError):
            job.validate_callback_handoff()
        with self.assertRaises(ValueError):
            copy.copy(job).validate_owner(self.engine)
        for timeout in (0, -1, float("inf"), float("nan")):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                job.stop(timeout)
        job.stop()
        self.assertTrue(job.state.stop_requested)
        self.assertFalse(job.state.outer_started)


class EngineThreadRetryBridgeTests(unittest.TestCase):
    """Public thread-job dispatch of leaf 51's retry callback."""

    class Lease:
        state = "reserved"

    class Retry:
        def __init__(self, error=None):
            self.calls = []
            self.error = error

        def callback3(self):
            self.calls.append(threading.current_thread())
            if self.error is not None:
                raise self.error

    class Cleanup:
        def __init__(self):
            self.released = []

        def release_retired_selected(self, worker):
            self.released.append(worker)

    class Engine:
        def __init__(self, error=None):
            self._retry_controller = None
            self.retry = EngineThreadRetryBridgeTests.Retry(error)
            self.cleanup = EngineThreadRetryBridgeTests.Cleanup()
            self.callback_threads = []
            self.released_leases = []

        def thread_callback_execution(self, job):
            engine = self

            class Execution:
                def __enter__(self):
                    engine.callback_threads.append(threading.current_thread())

                def __exit__(self, *error):
                    return False

            return Execution()

        def bind_retry_controller(self):
            return self.retry

        def bind_cleanup_controller(self):
            return self.cleanup

        def release_reserved_phase(self, lease):
            self.released_leases.append(lease)

        def _require_owned_phase(self):
            pass

    class Runtime:
        def __init__(self):
            self.checks = 0

        def check(self):
            self.checks += 1

    class Controller:
        def __init__(self):
            self.runtime = EngineThreadRetryBridgeTests.Runtime()

    class Worker:
        def __init__(self, controller):
            self.controller = controller
            self.tail = 0
            self.next = 0
            self.logical = []
            self.continuation = None

        def _publish_outer_control_tail(self):
            self.tail += 1

        def notify_next_cpu(self):
            self.next += 1

        def notify_logical_cpu_boundary(self, index):
            self.logical.append(index)

        def take_continuation(self):
            return self.continuation

    def _job(self, *, error=None):
        job: Any = object.__new__(EngineThreadJob2026)
        job._lock = threading.RLock()
        job._resume = threading.Event()
        job._completed = threading.Event()
        job._child_resume = threading.Event()
        job._child_done = threading.Event()
        job._child_parked = threading.Event()
        job._prepare_pending = threading.Event()
        job._activity = threading.Event()
        job._callback_requested = threading.Event()
        job._callback_returned = threading.Event()
        job._callback_error = None
        job._callback_kind = None
        job._callback_argument = None
        job._outer = None
        job._child = None
        job._lease = self.Lease()
        job._session = None
        job._stop = False
        job._host_stop = False
        job._waiting = False
        job._sequence = 1
        from scripts.cuw_engine_threads import _CompletionRecord2026

        job._active_record = _CompletionRecord2026(1)
        job._completion_records = {1: job._active_record}
        job._result = None
        job._error = None
        job._continuation = None
        job._child_exit = None
        job._outer_exit = None
        job._controller_entry = None
        job._getter_continuation2026 = None
        job._getter_continuation_stage2026 = None
        job._getter_stop_receipt2026 = None
        job._getter_stop_stage2026 = None
        job.controller = self.Controller()
        job.worker = self.Worker(job.controller)
        job.engine = self.Engine(error)
        return job

    def _run(self, job):
        errors = []

        def child():
            try:
                job.dispatch_retry_callback()
            except BaseException as error:  # noqa: BLE001 - preserve child failure
                errors.append(error)
            finally:
                job._child_exit = 0
                job._child_done.set()
                job._activity.set()

        job._run_child = child
        outer = threading.Thread(target=job._run_outer, daemon=True)
        job._outer = outer
        outer.start()
        job._resume.set()
        try:
            self.assertTrue(job._completed.wait(2))
        finally:
            job._stop = True
            job._resume.set()
            outer.join(2)
        self.assertFalse(outer.is_alive())
        return errors

    def test_child_retry_callback_runs_on_the_outer_thread(self):
        job = self._job()
        errors = self._run(job)
        self.assertEqual(errors, [])
        self.assertEqual(len(job.engine.retry.calls), 1)
        self.assertIs(job.engine.retry.calls[0], job._outer)
        self.assertEqual(len(job.engine.callback_threads), 1)
        self.assertIs(job.engine.callback_threads[0], job._outer)
        self.assertEqual(job.controller.runtime.checks, 1)
        self.assertEqual(job.engine.cleanup.released, [job.worker])
        self.assertIsNone(job._error)
        self.assertFalse(job._callback_requested.is_set())

    def test_retry_callback_failure_returns_to_the_child(self):
        failure = OSError("authored retry callback failure")
        job = self._job(error=failure)
        errors = self._run(job)
        self.assertEqual(errors, [failure])
        self.assertEqual(len(job.engine.retry.calls), 1)
        self.assertIs(job._callback_error, failure)
        self.assertIsNone(job._error)

    def test_outer_failure_acks_pending_callback_before_join(self):
        failure = OSError("authored outer failure")
        job = self._job()

        class FailingActivity:
            def wait(self):
                raise failure

            def set(self):
                pass

        job._activity = FailingActivity()
        job._resume.set()
        child_errors = []

        def child():
            try:
                job.dispatch_retry_callback()
            except BaseException as error:  # noqa: BLE001 - retain callback failure
                child_errors.append(error)
            finally:
                job._child_exit = 0
                job._child_done.set()

        child_thread = threading.Thread(target=child, daemon=True)
        job._child = child_thread
        child_thread.start()
        self.assertTrue(job._callback_requested.wait(2))
        outer = threading.Thread(target=job._run_outer, daemon=True)
        job._outer = outer
        outer.start()
        outer.join(2)

        self.assertFalse(outer.is_alive(), "outer failure must release callback join")
        self.assertEqual(child_errors, [failure])
        self.assertIs(job._error, failure)
        self.assertEqual(job._outer_exit, 1)

    def test_retry_callback_rejects_a_non_child_publisher(self):
        job = self._job()
        with self.assertRaises(ValueError):
            job.dispatch_retry_callback()
        self.assertFalse(job._callback_requested.is_set())


class ThreadSequenceCompletionTests(unittest.TestCase):
    def _job_fixture(self, **kwargs):
        fixture = ThreadOwnershipTests()
        fixture.setUp()
        engine, controller, job, session = fixture.imported_prepare(**kwargs)
        return fixture, engine, controller, job, session

    def test_00_old_waiter_keeps_the_sequence_selected_at_call_entry(self):
        from scripts.cuw_engine_threads import _CompletionRecord2026

        class WaitGate(threading.Event):
            def wait(self, timeout=None):
                self.entered.set()
                return self.release.wait(timeout)

            def __init__(self):
                super().__init__()
                self.entered = threading.Event()
                self.release = threading.Event()

        old_result = {"generation": 1}
        new_result = {"generation": 2}
        gate = WaitGate()
        old = _CompletionRecord2026(1, completed=gate, result=old_result)
        job = object.__new__(EngineThreadJob2026)
        job._lock = threading.RLock()
        job._outer = job._child = None
        job._sequence = 1
        job._completion_records = {1: old}
        job._completed = gate
        job._result = old_result
        job._error = None
        returned = []
        waiter = threading.Thread(target=lambda: returned.append(job.result(2)))
        waiter.start()
        self.assertTrue(gate.entered.wait(2))

        new = _CompletionRecord2026(2)
        new.completed.set()
        new.result = new_result
        with job._lock:
            job._completion_records[2] = new
            job._sequence = 2
            job._completed = new.completed
            job._result = new_result
        gate.release.set()
        waiter.join(2)

        self.assertFalse(waiter.is_alive())
        self.assertEqual(len(returned), 1)
        self.assertIs(returned[0], old_result)

    def test_three_actual_source_bound_generations_share_the_persistent_job(self):
        fixture = ThreadOwnershipTests()
        fixture.setUp()
        fixture._sequence_generations = 3
        try:
            fixture.test_actual_p5_false_getter_imports_pair_through_thread_job()
        finally:
            fixture.doCleanups()

    def test_old_result_and_error_objects_survive_later_publication(self):
        from scripts.cuw_engine_threads import _CompletionRecord2026

        def record(result=None, error=None, continuation=None):
            item = _CompletionRecord2026(1)
            item.completed.set()
            item.result, item.error, item.continuation = result, error, continuation
            return item

        job = object.__new__(EngineThreadJob2026)
        job._lock = threading.RLock()
        job._outer = job._child = None
        old_result = {"generation": 1}
        later_error = OSError("generation 2")
        latest_continuation = object()
        job._sequence = 3
        job._completion_records = {
            1: record(result=old_result),
            2: record(error=later_error),
            3: record(result={"generation": 3}, continuation=latest_continuation),
        }

        self.assertIs(job.result(2, sequence=1), old_result)
        with self.assertRaises(OSError) as caught:
            job.result(2, sequence=2)
        self.assertIs(caught.exception, later_error)
        self.assertIs(job.continuation, latest_continuation)

        earlier_error = RuntimeError("generation 1")
        latest_result = {"generation": 3}
        job._completion_records[1] = record(error=earlier_error)
        job._completion_records[3] = record(
            result=latest_result, continuation=latest_continuation
        )
        with self.assertRaises(RuntimeError) as caught:
            job.result(2, sequence=1)
        self.assertIs(caught.exception, earlier_error)
        self.assertIs(job.result(2), latest_result)

    def test_result_rejects_unissued_invalid_sequences(self):
        job = object.__new__(EngineThreadJob2026)
        job._lock = threading.RLock()
        job._outer = job._child = None
        job._sequence = 1
        from scripts.cuw_engine_threads import _CompletionRecord2026

        record = _CompletionRecord2026(1)
        record.completed.set()
        record.result = {}
        job._completion_records = {1: record}
        for sequence in (True, 0, -1, 2):
            with self.subTest(sequence=sequence), self.assertRaises(ValueError):
                job.result(2, sequence=sequence)

    def test_child_prelude_fault_is_published_to_its_sequence(self):
        fixture, _engine, _controller, job, session = self._job_fixture(
            operation="get_cid", include_control=False
        )
        fault = RuntimeError("controlled child prelude fault")
        original_clear = job._child_parked.clear
        clear_calls = 0

        def fail_child_clear():
            nonlocal clear_calls
            clear_calls += 1
            if clear_calls == 2:
                raise fault
            return original_clear()

        try:
            with patch.object(job._child_parked, "clear", side_effect=fail_child_clear):
                job.start(session)
                with self.assertRaises(RuntimeError) as caught:
                    job.result(2, sequence=1)
            self.assertIs(caught.exception, fault)
        finally:
            fixture.doCleanups()

    def test_reserved_release_failure_keeps_the_legacy_winning_error(self):
        fixture, engine, controller, job, session = self._job_fixture(
            operation="get_cid", include_control=False
        )
        primary = ValueError("controlled runtime check failure")
        cleanup = OSError("controlled reserved release failure")
        original_release = engine.release_reserved_phase
        release_calls = 0

        def fail_first_release(lease):
            nonlocal release_calls
            release_calls += 1
            if release_calls == 1:
                raise cleanup
            return original_release(lease)

        try:
            with (
                patch.object(controller.runtime, "check", side_effect=primary),
                patch.object(
                    engine, "release_reserved_phase", side_effect=fail_first_release
                ),
            ):
                job.start(session)
                caught = []
                try:
                    job.result(2, sequence=1)
                except (
                    ValueError,
                    OSError,
                ) as error:  # preserve exact worker error identity
                    caught.append(error)
            self.assertEqual(release_calls, 1)
            self.assertEqual(len(caught), 1)
            self.assertIs(caught[0], cleanup)
            self.assertIs(job._completion_records[1].error, cleanup)
        finally:
            fixture.doCleanups()

    def test_late_outer_wait_fault_cannot_mutate_published_record(self):
        fixture, _engine, _controller, job, session = self._job_fixture(
            operation="get_cid", include_control=False
        )
        clock = lambda: 1000
        session.trace.native_local_milliseconds_of_day = clock
        _controller.runtime.local_milliseconds_of_day = clock
        original_wait = job._resume.wait
        waits = 0
        fault = RuntimeError("controlled late outer wait fault")

        def fail_second_wait(timeout=None):
            nonlocal waits
            waits += 1
            if waits == 2:
                raise fault
            return original_wait(timeout)

        try:
            with patch.object(job._resume, "wait", side_effect=fail_second_wait):
                sequence = job.start(session)
                self.assertEqual(sequence, 1)
                outer = job._outer
                self.assertIsNotNone(outer)
                assert outer is not None
                outer.join(2)
            record = job._completion_records[1]
            self.assertTrue(record.completed.is_set())
            self.assertIsNone(record.error)
            self.assertIs(job.result(2, sequence=1), record.result)
        finally:
            fixture.doCleanups()

    def test_outer_cleanup_preserves_child_winner_and_appends_note(self):
        case = EngineThreadRetryBridgeTests()
        job = case._job()
        record = job._active_record
        primary = OSError("controlled child winner")
        existing_note = "pre-existing cleanup note"
        outer_cleanup = ValueError("controlled outer cleanup fault")
        job._error = record.error = primary
        primary.add_note(existing_note)
        job._child_done.set()
        child = threading.Thread(target=lambda: None)
        child.start()
        child.join()
        job._child = child
        job.engine.cleanup.release_retired_selected = lambda worker: (
            _ for _ in ()
        ).throw(outer_cleanup)
        job._resume.set()

        job._run_outer()

        self.assertEqual(
            primary.__notes__,
            [
                existing_note,
                "Native outer cleanup failure: ValueError",
            ],
        )
        self.assertIs(job._error, primary)
        self.assertIs(record.error, primary)
        self.assertTrue(record.completed.is_set())
        with self.assertRaises(OSError) as caught:
            job.result(1, sequence=1)
        self.assertIs(caught.exception, primary)

    def test_unstarted_no_argument_result_keeps_legacy_message(self):
        fixture, _engine, _controller, job, _session = self._job_fixture()
        try:
            with self.assertRaisesRegex(
                ValueError, "^Native thread job has not been started$"
            ):
                job.result()
        finally:
            fixture.doCleanups()


class VbfProcessBeforeRequestTests(unittest.TestCase):
    def test_request_is_opaque_and_unassociated_lease_reports_none(self):
        from scripts.cuw_engine_threads import (
            VbfProcessBeforeRequest2026,
            _issue_thread_phase_lease,
            validate_vbf_process_before2026,
        )

        with self.assertRaises(TypeError):
            VbfProcessBeforeRequest2026()
        with self.assertRaises(TypeError):
            validate_vbf_process_before2026(object(), object(), states=("issued",))

        fixture = ThreadOwnershipTests()
        fixture.setUp()
        try:
            lease = _issue_thread_phase_lease(fixture.engine, fixture.controller, 0)
            self.assertIsNone(lease.vbf_request)
            lease._release()
        finally:
            fixture.doCleanups()


class VbfProcessBeforeResumeTests(unittest.TestCase):
    def test_vbf_source_validator_does_not_issue_freeze_authority(self):
        from typing import Any, cast

        from scripts.cuw_engine_threads import _validate_vbf_source

        with self.assertRaises(TypeError):
            cast(Any, _validate_vbf_source)(None, None, freeze=True)

    def test_source_driven_getter_judge_mapped141_external_vbf(self):
        self._run_source_driven_getter_judge_mapped141_external_vbf()

    def test_source_driven_getter_judge_vbf_store_fault_preserves_partial_state(self):
        self._run_source_driven_getter_judge_mapped141_external_vbf(
            fault_at="engine_store"
        )

    def test_source_driven_getter_judge_vbf_mirror_fault_preserves_partial_state(self):
        self._run_source_driven_getter_judge_mapped141_external_vbf(
            fault_at="worker_complete"
        )

    def _run_source_driven_getter_judge_mapped141_external_vbf(self, *, fault_at=None):
        import io
        import tempfile
        import zipfile

        from scripts.calibration_2026 import parse_cuw_2026
        from scripts.cuw_2026 import CUWEngine2026, identity_2026
        from scripts.cuw_file_services import admit_file_sources_2026
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )
        from scripts.j2534_2026 import (
            DriverMetadata2026,
            NativeMessage,
            PrimitiveResult,
        )
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeFrontendParameters2026,
            _control_getter_output2026,
        )
        from tests.private_evidence import read_private_bytes
        from tests.test_calibration_2026 import cuw, srecord
        from tests.test_programming_replay import (
            authored_classic_can40_inputs,
            make_authored_control_recorder,
        )

        plain_source, catalog_sources, raw_payloads_by_root = (
            authored_classic_can40_inputs()
        )
        source = plain_source
        maximum = 2
        external_fault = {}
        captured_vbf_origins = []
        vbf_parked_snapshots = []
        catalog_sources = dict(catalog_sources)
        general = NativeGeneralParameters2026.from_sources(catalog_sources)
        catalog_sources["Parameter.ini"] = encoded_table(
            (*general.headers, "FlagToChangeWFSE"),
            tuple(
                (*tuple("\n".join(cell) for cell in row), "0") for row in general.rows
            ),
        )

        def target_file(
            name: str,
            rows: tuple[tuple[int, str, str], ...],
            *,
            extension: str,
        ) -> bytes:
            sections = [
                "[Format]",
                "Version=40",
                "[Vehicle]",
                "ContactType=CAN",
                "KindOfECU=149",
                f"NumberOfCalibration={len(rows)}",
            ]
            records = []
            for index, (cpu_type, new_cid, target) in enumerate(rows, start=1):
                sections.extend(
                    (
                        f"[CPU{index:02}]",
                        f"CPUImageName={name}{index}.{extension}",
                        f"CPUType={cpu_type}",
                        f"NewCID={new_cid}",
                        "NumberOfTargetHardwares=1",
                        "01_TargetHardware=",
                        "NumberOfTargets=1",
                        f"01_TargetCalibration={target}",
                    )
                )
                records.append(
                    b"\n".join(
                        (
                            srecord(1, 0, target.encode()[:4].ljust(4, b"x")),
                            srecord(7, 0),
                        )
                    )
                )
            return cuw(
                "\n".join(sections) + "\n",
                tuple(records),
            )

        group = io.BytesIO()
        with zipfile.ZipFile(group, "w") as archive:
            archive.writestr(
                "Setting.ini",
                "[DeltaReproCalFile]\nFileNum=2\nFileName1=part1.cuw\n"
                "FileName2=part2.cuw\n[WholeReproCalFile]\nFileName=whole.cuw\n",
            )
            archive.writestr(
                "part1.cuw",
                target_file(
                    "part1",
                    (
                        (311, "NEW_PART1_M16C", "OLD_GROUP"),
                        (312, "FOREST_NEW", "NOT_RECEIVED"),
                    ),
                    extension="bin",
                ),
            )
            archive.writestr(
                "part2.cuw",
                target_file(
                    "part2",
                    (
                        (311, "NEW_PART2_M16C", "PART2_UNRELATED"),
                        (312, "NEW_PART2_FOREST", "PART2_UNRELATED"),
                    ),
                    extension="bin",
                ),
            )
            archive.writestr(
                "whole.cuw",
                target_file(
                    "whole",
                    (
                        (311, "WHOLE_M16C_NEW", "OLD_GROUP"),
                        (312, "WHOLE_FOREST_NEW", "FOREST_NEW"),
                    ),
                    extension="vbf",
                ),
            )
        group_source = (
            b"[Vehicle]\nContactType=CAN\nKindOfECU=149\n"
            b"[DataCompression]\n" + group.getvalue()
        )
        source_files = {"plain.cuw": source, "group.scuw": group_source}

        images = Path("runtime/no-car-21/recovered")
        modules = {
            name: read_private_bytes(images / name)
            for name in (
                "TCUWCanCIDGetter.dll",
                "TCUWCanDHPrepareWriter.dll",
                "TCUWCanDHFlashWriter.dll",
                "TCUWDHUtils.dll",
                "SecretInfo.dll",
                "CUW.dll",
            )
        }
        modules.update(
            {
                "TCUWControlCommPhase.dll": read_private_bytes(
                    images / "TCUWControlCommPhase.dll"
                ),
                "TCUWJ2534DeviceIF.dll": read_private_bytes(
                    images / "TCUWJ2534DeviceIF.dll"
                ),
            }
        )

        class AuthoredSDK:
            def __init__(self):
                self.cid_payloads = iter(
                    payload
                    for root_rows in raw_payloads_by_root
                    for payload in root_rows
                )
                self.pending = []
                self.clock_ms = 1000

            def __call__(self, event, remaining):

                operation = event["operation"]
                if external_fault and operation == "passthru_read":
                    roots.append(job._session)
                    raise sentinel
                if operation == "get_local_milliseconds_of_day":
                    value = self.clock_ms
                    self.clock_ms += 1000
                    return value
                if operation == "get_local_seconds_of_day":
                    return self.clock_ms // 1000
                if operation.startswith("notify_"):
                    return None
                if operation == "wait":
                    return PrimitiveResult()
                if operation == "set_communication_log_mode":
                    return 0
                if operation in ("get_timeout", "get_send_timeout"):
                    return 1000
                if operation == "passthru_write":
                    if event["count"] != 1 or len(event["messages"]) != 1:
                        raise AssertionError("One actual source message required")
                    message = event["messages"][0]
                    address, pdu = message.data[:4], message.data[4:]
                    if pdu.startswith(b"\x34"):
                        return PrimitiveResult(status=24)
                    if message.protocol_id == 5:
                        if message.data != bytes.fromhex("0000072002a027e916000000"):
                            raise AssertionError(
                                ("Unauthored protocol5 mask", message.data.hex())
                            )
                        return PrimitiveResult(value=1)
                    self.pending.append(
                        PrimitiveResult(value=(NativeMessage(6, address, rx_status=9),))
                    )
                    response_address = (int.from_bytes(address, "big") + 8).to_bytes(
                        4, "big"
                    )
                    if pdu in (b"\x09\x00", b"\x09\x04"):
                        payload = next(self.cid_payloads)
                        self.pending.append(
                            PrimitiveResult(
                                value=(NativeMessage(6, response_address + payload),)
                            )
                        )
                    elif pdu == b"\x21\x05":
                        self.pending.append(PrimitiveResult(status=9))
                    elif pdu == b"\x10\x85":
                        self.pending.append(
                            PrimitiveResult(
                                value=(
                                    NativeMessage(6, response_address + b"\x50\x85"),
                                )
                            )
                        )
                    elif pdu == b"\x27\x01":
                        self.pending.append(
                            PrimitiveResult(
                                value=(
                                    NativeMessage(
                                        6,
                                        response_address
                                        + bytes.fromhex("67010102030400"),
                                    ),
                                )
                            )
                        )
                    elif pdu == bytes.fromhex("270201020304"):
                        self.pending.append(
                            PrimitiveResult(
                                value=(
                                    NativeMessage(
                                        6, response_address + bytes.fromhex("670234")
                                    ),
                                )
                            )
                        )
                    elif pdu not in (bytes.fromhex("a027"), bytes.fromhex("fea027")):
                        raise AssertionError(
                            ("Unauthored actual DH PDU", address.hex(), pdu.hex())
                        )
                    return PrimitiveResult(value=1)
                if operation == "passthru_read":
                    if not self.pending:
                        raise AssertionError(
                            "Actual read has no authored pending observation"
                        )
                    return self.pending.pop(0)
                if operation in (
                    "passthru_open",
                    "passthru_connect",
                    "passthru_start_filter",
                ):
                    return PrimitiveResult(
                        value={
                            "passthru_open": 17,
                            "passthru_connect": 19,
                            "passthru_start_filter": 23,
                        }[operation]
                    )
                if operation == "passthru_ioctl":
                    return PrimitiveResult(
                        value=13000 if event.get("ioctl") == 3 else None
                    )
                if operation == "passthru_read_version":
                    return PrimitiveResult(value=("Authored offline SDK", "1", "1"))
                if operation == "create_mutex":
                    return PrimitiveResult(value=51)
                if operation == "wait_handle":
                    return PrimitiveResult(value=0)
                if operation == "load_library":
                    return PrimitiveResult(
                        value=31
                        if (event.get("name") or "").startswith("ptshim")
                        else 32
                    )
                if operation == "get_symbol":
                    return PrimitiveResult(
                        value=0
                        if event.get("name") == "_GtsNewVimFixInterface@8"
                        else 201
                    )
                if operation in {
                    "passthru_load_library",
                    "passthru_unload_library",
                    "passthru_stop_filter",
                    "passthru_disconnect",
                    "passthru_close",
                    "free_library",
                    "release_mutex",
                    "close_handle",
                    "call_symbol",
                }:
                    return PrimitiveResult()
                raise AssertionError(("Unauthored SDK/host operation", operation))

        session, runtime, pair, recorder_rows = make_authored_control_recorder(
            self,
            source=source,
            catalog_sources=catalog_sources,
            module_files=modules,
            primitive_reply=AuthoredSDK(),
        )
        frontend = NativeFrontendParameters2026.from_sources(
            catalog_sources, encoded=True
        )
        engine = CUWEngine2026(
            read_private_bytes(images / "CUW.dll"),
            general_parameters=frontend.general,
        )
        self.addCleanup(engine.close)
        engine.configure(struct.pack("<IIddII", maximum, 0, 1, 2, 0, 0))
        engine.bind_frontend_parameters(frontend)
        sources = admit_file_sources_2026(
            engine,
            "input.json",
            b'["plain.cuw","group.scuw"]',
            region=0,
            source_files=source_files,
        )
        engine.bind_file_sources(sources)
        names, originals, count = sources.recovery_sources()
        persistence_state = ReproInfoState(
            tuple(
                RecoveryCalibration(
                    name,
                    original,
                    blank_ecu_flags=(False,) * maximum,
                )
                for name, original in zip(names, originals, strict=True)
            ),
            multi_calibration_file_num=count,
            loaded=False,
        )
        output_dir = tempfile.TemporaryDirectory()
        self.addCleanup(output_dir.cleanup)
        engine.bind_persistence(
            CUWPersistence(Path(output_dir.name), persistence_state)
        )
        controller = ControlCommPhase2026(
            identity_2026(
                modules["TCUWControlCommPhase.dll"], "TCUWControlCommPhase.dll"
            ),
            runtime,
        )
        session.bind_runtime2026(runtime)
        session.bind_engine2026(engine)
        session.bind_controller2026(controller)
        pair = session.trace.interface_pair
        self.assertIsNotNone(pair)
        assert pair is not None
        for view in (pair.engine, pair.control):
            view.set_current_driver(DriverMetadata2026("Authored", "authored.dll"))
        engine.bind_interface_pair(pair)
        job = engine.bind_thread_job(controller)
        self.addCleanup(job.stop)
        outputs = []
        original_execute = controller.execute
        busy_observations = []
        parameter_observations = []
        general_parameters = engine._general_parameters
        assert general_parameters is not None
        original_busy = engine._publish_getter_entry_busy_34cb0_2026
        original_boolean = engine.general_parameter_boolean

        def observe_busy(origin):
            busy_observations.append(
                (
                    engine._native_outer_cfe0_2026,
                    engine._native_be54_pending2026,
                    engine._worker_phase,
                    engine.native_phase,
                    engine._native_receiving_cfe2_2026,
                    origin.cfe0_at_issue,
                    getattr(origin, "be54_at_issue", None),
                )
            )
            return original_busy(origin)

        def observe_general_boolean(*args, **kwargs):
            parameter_observations.append((args, kwargs))
            return original_boolean(*args, **kwargs)

        def observe_execute(execution_engine, execution_session):
            result = original_execute(execution_engine, execution_session)
            context = controller.native_control_context2026(execution_engine)
            output = _control_getter_output2026(context)
            if output is not None:
                outputs.append((result, output))
            return result

        outer = child = None
        root_route = job._is_raw_control_getter_root2026(session)
        if not root_route:
            module = session.modules.get("TCUWControlCommPhase.dll")
            identity = None if module is None else module.native_identity
            self.fail(
                "Raw getter root predicate inputs: "
                f"op={session.operation!r}, used={session.used!r}, "
                f"owners={(session._engine2026 is engine, session._controller2026 is controller, session._runtime2026 is runtime)!r}, "
                f"source={(session.container.digest == engine.source_sha256, session.node, engine.native_metadata.node)!r}, "
                f"cpu={(session.context['observations']['host'].get('cpu_index', 0), engine.dh_state.selection_cpu_index)!r}, "
                f"module={(module is not None, identity is controller.identity, identity == controller.identity, identity is None)!r}, "
                f"loaded_identity={identity!r}; controller_identity={controller.identity!r}; "
                f"exports={(None if identity is None else sorted(identity.callable_exports))!r}"
            )
        with (
            patch.object(controller, "execute", new=observe_execute),
            patch.object(
                engine, "_publish_getter_entry_busy_34cb0_2026", new=observe_busy
            ),
            patch.object(
                engine, "general_parameter_boolean", new=observe_general_boolean
            ),
        ):
            self.assertEqual(job.start(session), 1)
            try:
                first_report = job.result(5, sequence=1)
            except BaseException as error:
                raise AssertionError(
                    f"G busy precondition observations: {busy_observations!r}; "
                    f"general lookup={parameter_observations!r}; "
                    f"general headers={general_parameters.headers!r}; "
                    f"general rows={general_parameters.rows!r}"
                ) from error
            self.assertIs(first_report["native_return"], True)
            outer, child = job._outer, job._child
            self.assertIsNotNone(child)
            assert child is not None

            deadline = time.monotonic() + 5
            while job.state.sequence < 2 and time.monotonic() < deadline:
                time.sleep(0.001)
            self.assertEqual(job.state.sequence, 2)
            try:
                second_report = job.result(5, sequence=2)
            except BaseException as error:
                position = session.trace.position
                following = (
                    session.trace.rows[position]
                    if position < len(session.trace.rows)
                    else None
                )
                worker_index = job.worker._current_file_index
                worker_metadata = job.worker._all_loaded_metadata[worker_index]
                engine_metadata = engine.native_metadata
                raise AssertionError(
                    f"second-root chronology position={position}, "
                    f"next={following!r}, root lengths="
                    f"recorded rows={len(recorder_rows)}, "
                    "worker/engine source="
                    f"{(worker_index, worker_metadata.source_container.digest, worker_metadata.source_sha256, engine_metadata.source_container.digest, engine_metadata.source_sha256, worker_metadata.source_container is engine_metadata.source_container)!r}"
                ) from error
            self.assertIs(second_report["native_return"], True)

            self.assertEqual(len(outputs), 2)
            self.assertIn(b"PLAIN_OLD", outputs[0][1].identifiers)
            self.assertIn(b"OLD_GROUP", outputs[1][1].identifiers)
            self.assertIs(engine.thread_job, job)
            self.assertTrue(job.native_worker_exists)
            self.assertIs(job._outer, outer)
            self.assertIs(job._child, child)
            source_state = job.worker.source_state
            self.assertEqual(source_state.current_file_index, 0)
            self.assertEqual(sources.delta_map_size, 2)

            judged = engine.judge_flashable(region=1)
            self.assertEqual(judged.status, 0)
            self.assertGreater(judged.row_count, 0)
            self.assertEqual(
                (judged.live_file_kind, judged.live_file_index), ("part", 1)
            )
            self.assertEqual(
                (judged.flow_file_index, judged.recovery_file_index), (1, 1)
            )
            self.assertEqual(persistence_state.calibration_file_index, 1)
            self.assertEqual(job.worker.source_state.current_file_index, 1)
            old_retirement = job._getter_retirement2026
            self.assertIsNotNone(old_retirement)

            # Construct a fresh ordinary root from the exact PART1 selected by H.
            # It shares this trace, pair, module/catalog bytes and live owners.
            selected_group = sources.group_for_file(
                job.worker.source_state.current_file_index
            )
            self.assertIsNotNone(selected_group)
            assert selected_group is not None
            self.assertEqual(
                sources.file_names[
                    job.worker.source_state.current_file_index
                ].casefold(),
                "part1.cuw",
            )
            prepare_source = sources.file_sources[
                job.worker.source_state.current_file_index
            ]
            self.assertIs(type(prepare_source), bytes)
            prepare_digest = hashlib.sha256(prepare_source).hexdigest()
            self.assertEqual(engine.source_sha256, prepare_digest)
            prepare_container = parse_cuw_2026(prepare_source)
            prepare_context = dict(session.context)
            prepare_observations = dict(prepare_context["observations"])
            prepare_host = dict(prepare_observations["host"])
            prepare_host["cpu_index"] = engine.dh_state.selection_cpu_index
            if "native2026" in prepare_host:
                prepare_native = dict(prepare_host["native2026"])
                prepare_native.pop("stage", None)
                prepare_native.pop("export", None)
                prepare_native["cpu_index"] = prepare_host["cpu_index"]
                prepare_host["native2026"] = prepare_native
            prepare_observations["host"] = prepare_host
            prepare_context.update(
                operation="prepare",
                node=engine.native_metadata.node,
                calibration_sha256=prepare_digest,
                observations=prepare_observations,
            )
            prepare_hashes = dict(session.input_hashes)
            prepare_hashes["calibration"] = prepare_digest
            prepare_session = ProgrammingReplay(
                prepare_container,
                prepare_context,
                session.catalog,
                session.modules,
                session.attachments,
                session.trace,
                prepare_hashes,
                _catalog_sources=session._catalog_sources,
                _module_files=session._module_files,
            )
            prepare_session.bind_runtime2026(runtime)
            prepare_session.bind_engine2026(engine)
            prepare_session.bind_controller2026(controller)
            if not pair.engine.opened:
                pair.engine.have_ownership()
                pair.engine.open()
            if not pair.engine.connecting:
                pair.engine.connect(6)
            retry = engine.bind_retry_controller()
            self.assertIsNot(prepare_session.container, session.container)
            self.assertIs(prepare_session.trace, session.trace)
            self.assertIs(prepare_session.catalog, session.catalog)
            self.assertIs(prepare_session.modules, session.modules)
            prepare_sequence = job.state.sequence + 1
            self.assertEqual(job.start(prepare_session), prepare_sequence)
            prepare_record = job._active_record
            assert prepare_record is not None
            deadline = time.monotonic() + 5
            while (
                not retry.query_pending
                and not prepare_record.completed.is_set()
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            self.assertIs(job._getter_retirement2026, old_retirement)
            self.assertEqual(job._getter_retirement_stage2026, "retired")
            if not retry.query_pending:
                if prepare_record.completed.is_set():
                    job.result(0, sequence=prepare_sequence)
                self.fail(
                    "Actual retry query was not published: "
                    f"sequence={prepare_sequence}, "
                    f"completed={prepare_record.completed.is_set()}, "
                    f"error={prepare_record.error!r}, "
                    f"native_phase={engine.native_phase}, "
                    f"worker_cpu={job.worker._current_cpu_index}"
                )
            retry_query = retry.wait_for_query()
            self.assertEqual(
                (
                    retry_query.error_kind,
                    retry_query.primary_error,
                    retry_query.passthru_error,
                    retry_query.cpu_index,
                ),
                (2, 1, 24, 1),
            )
            self.assertEqual(job.worker.source_state.cpu_offset, 1)
            self.assertEqual(persistence_state.write_cpu_index, 0)
            from dataclasses import fields

            from scripts import programming_2026_dh as dh2026

            dh_binding_diagnostics = []
            dh_capture_provenance = []
            original_dh_bind = dh2026.bind_native_context

            def metadata_summary(metadata):
                if metadata is None:
                    return None
                container = metadata.source_container
                return (
                    metadata.source_sha256,
                    getattr(container, "digest", None),
                    metadata.node,
                    metadata.cpu_index,
                    tuple((cpu.section, cpu.node, cpu.index) for cpu in metadata.cpus),
                    metadata.runtime_selected_cpu,
                    metadata.runtime_projection,
                )

            def observe_dh_bind(
                container, node, cids, selection, identity, files, observations
            ):
                state = observations.get("dh_state")
                state_metadata = getattr(state, "metadata", None)
                selected_metadata = selection.metadata
                target = engine._controller_export_target2026
                target_binding = None if target is None else target.binding
                target_context = None if target is None else target._context
                target_capture = (
                    None
                    if target_context is None
                    else getattr(target_context, "_capture", None)
                )
                module_binding = None if target is None else target.module_binding
                dh_binding_diagnostics.append(
                    (
                        type(state).__module__,
                        type(state).__qualname__,
                        isinstance(state, dh2026.DHControllerState2026),
                        state_metadata is selected_metadata,
                        state_metadata == selected_metadata,
                        ("engine", metadata_summary(engine.native_metadata)),
                        (
                            "worker",
                            metadata_summary(
                                job.worker._all_loaded_metadata[
                                    job.worker._current_file_index
                                ]
                            ),
                        ),
                        (
                            "target",
                            None
                            if target_binding is None
                            else metadata_summary(target_binding.metadata),
                        ),
                        (
                            "target_context_capture",
                            None
                            if target_capture is None
                            else metadata_summary(
                                getattr(target_capture, "metadata", None)
                            ),
                        ),
                        (
                            "module_binding",
                            None
                            if module_binding is None
                            else metadata_summary(
                                getattr(module_binding, "metadata", None)
                            ),
                        ),
                        (
                            "target_context_capture_phase",
                            None
                            if target_capture is None
                            else getattr(target_capture, "_phase", None),
                        ),
                        ("state", metadata_summary(state_metadata)),
                        ("selection", metadata_summary(selected_metadata)),
                        tuple(
                            (
                                item.name,
                                repr(getattr(state_metadata, item.name, None))[:240],
                                repr(getattr(selected_metadata, item.name, None))[:240],
                            )
                            for item in fields(type(selected_metadata))
                            if getattr(state_metadata, item.name, None)
                            != getattr(selected_metadata, item.name, None)
                        ),
                        ("state_is_engine", state is engine.dh_state),
                    )
                )
                dh_capture_provenance.append(
                    (
                        target_capture,
                        None
                        if target_capture is None
                        else getattr(target_capture, "_import_epoch", None),
                        None
                        if target_capture is None
                        else getattr(target_capture, "_thread_job", None),
                        None
                        if target_capture is None
                        else getattr(target_capture, "_thread_id", None),
                    )
                )
                return original_dh_bind(
                    container, node, cids, selection, identity, files, observations
                )

            from scripts.cuw_engine_worker import EngineWorker2026
            from scripts.programming_replay import ProgrammingTrace

            cleanup = engine.bind_cleanup_controller()
            original_cleanup = cleanup.release_retired_selected
            cleanup_entered = threading.Event()
            release_cleanup = threading.Event()
            sentinel = OSError("g7-external-vbf-host-sentinel")
            phases, calls, external_result, external_error, roots = [], [], [], [], []
            original_prepare, original_retry = (
                dh2026.prepare_dh,
                dh2026.prepare_retry_dh,
            )
            original_provider = ProgrammingTrace.driver_primitive
            original_phase_started = EngineWorker2026._phase_started
            old_capture = job.worker._control_file_capture
            old_lease = job._lease
            self.assertIsNotNone(old_lease)
            assert old_lease is not None

            def observe_retry(context, *args):
                from scripts.programming_2026_common import (
                    _NATIVE_CONTROL_HELPER_LEASES_2026,
                )

                lease = controller._native_control_export_lease2026
                record = _NATIVE_CONTROL_HELPER_LEASES_2026.get(id(lease))
                self.assertIsNotNone(record)
                if record is None:
                    raise AssertionError(
                        "Authenticated PrepareRetry helper lease required"
                    )
                self.assertIs(record[0], lease)
                info = record[1]
                self.assertEqual(info["export"], "PrepareRetry")
                self.assertIs(info["engine"], engine)
                self.assertIs(info["controller"], controller)
                self.assertIs(info["target"], engine._controller_export_target2026)
                self.assertIs(context.state, engine.dh_state)
                self.assertIs(
                    context.selection.metadata, info["target"].binding.metadata
                )
                self.assertIsNot(context.state.metadata, context.selection.metadata)
                calls.append(
                    (
                        "authenticated_outer_lease",
                        id(lease),
                        id(info["context"]),
                        id(context.state),
                        id(context.selection),
                        info["helper"],
                        info["stage"],
                    )
                )
                calls.append(
                    (
                        "retry_enter",
                        id(context),
                        id(context.state),
                        id(context.selection),
                        engine._controller_export_target2026,
                    )
                )
                result = original_retry(context, *args)
                calls.append(("retry_return", result))
                return result

            def observe_prepare(context, *args):
                target = engine._controller_export_target2026
                self.assertIsNotNone(target)
                if target is None:
                    raise AssertionError("Source-issued DH target required")
                self.assertIs(context.state, engine.dh_state)
                self.assertIs(
                    context.selection.metadata,
                    target.binding.metadata,
                )
                self.assertIsNotNone(controller._native_control_export_lease2026)
                calls.append(
                    (
                        "prepare_enter",
                        id(context),
                        id(context.state),
                        id(context.selection),
                        context.state.metadata.source_sha256,
                        context.selection.metadata.source_sha256,
                    )
                )
                result = original_prepare(context, *args)
                calls.append(("prepare_return", result))
                return result

            def held_cleanup(worker):
                original_cleanup(worker)
                if job._active_record is prepare_record:
                    cleanup_entered.set()
                    if not release_cleanup.wait(10):
                        raise TimeoutError("G7 retired cleanup barrier")

            def observe_provider(trace, event, remaining):
                if (
                    job.state.sequence > prepare_sequence
                    and event["operation"] == "passthru_read"
                ):
                    roots.append(job._session)
                    raise sentinel
                return original_provider(trace, event, remaining)

            def observe_phase(worker, phase, *, _vbf_request=None):
                result = original_phase_started(
                    worker, phase, _vbf_request=_vbf_request
                )
                if _vbf_request is not None:
                    phases.append(
                        (
                            _vbf_request.started_ms,
                            worker._phase_started_ms,
                            worker._control_file_capture,
                            threading.current_thread(),
                        )
                    )
                return result

            def external():
                try:
                    external_result.append(
                        engine.process_before_reprogramming(
                            engine._general_parameters, engine.engine_runtime_device()
                        )
                    )
                except BaseException as error:  # noqa: BLE001 - preserve exact host failure
                    external_error.append(error)

            try:
                with (
                    patch.object(dh2026, "bind_native_context", observe_dh_bind),
                    patch.object(dh2026, "prepare_retry_dh", observe_retry),
                    patch.object(dh2026, "prepare_dh", observe_prepare),
                    patch.object(cleanup, "release_retired_selected", held_cleanup),
                    patch.object(EngineWorker2026, "_phase_started", observe_phase),
                ):
                    inform_results, inform_errors = [], []

                    def inform():
                        try:
                            inform_results.append(
                                engine.inform_result_of_query_retry(1, 1)
                            )
                        except BaseException as error:  # noqa: BLE001 - preserve exact host failure
                            inform_errors.append(error)

                    informer = threading.Thread(target=inform)
                    informer.start()
                    self.assertTrue(
                        cleanup_entered.wait(5), (prepare_record.error, calls)
                    )
                    self.assertTrue(
                        any(row[0] == "retry_enter" for row in calls), calls
                    )
                    self.assertTrue(
                        any(row[0] == "prepare_enter" for row in calls), calls
                    )
                    self.assertTrue(job._child_parked.is_set())
                    self.assertFalse(prepare_record.completed.is_set())
                    self.assertEqual(old_lease.state, "released")
                    caller = threading.Thread(target=external)
                    original_issue_successor = job._issue_vbf_cpu_successor_36800_2026
                    original_record_cpu_store = job._record_vbf_cpu_store_36800_2026

                    def observe_issue_successor(request, *, worker):
                        origin = original_issue_successor(request, worker=worker)
                        captured_vbf_origins.append((request, origin))
                        return origin

                    def fail_before_cpu_store(origin, *, worker):
                        captured_vbf_origins.append((None, origin))
                        vbf_parked_snapshots.append(
                            (
                                origin.record.fields["cpu_index"],
                                origin.record.parked_global_cpu_index,
                                origin.record.fields["metadata"],
                            )
                        )
                        raise sentinel

                    def fail_before_worker_complete(origin, *, worker):
                        vbf_parked_snapshots.append(
                            (
                                origin.record.fields["cpu_index"],
                                origin.record.parked_global_cpu_index,
                                origin.record.fields["metadata"],
                            )
                        )
                        raise sentinel

                    if fault_at == "engine_store":
                        with (
                            patch.object(
                                job,
                                "_issue_vbf_cpu_successor_36800_2026",
                                observe_issue_successor,
                            ),
                            patch.object(
                                job,
                                "_record_vbf_cpu_store_36800_2026",
                                fail_before_cpu_store,
                            ),
                        ):
                            caller.start()
                            caller.join(5)
                    elif fault_at == "worker_complete":
                        with (
                            patch.object(
                                job,
                                "_issue_vbf_cpu_successor_36800_2026",
                                observe_issue_successor,
                            ),
                            patch.object(
                                job,
                                "_complete_vbf_cpu_successor_36800_2026",
                                fail_before_worker_complete,
                            ),
                        ):
                            caller.start()
                            caller.join(5)
                    else:
                        caller.start()
                        caller.join(5)
                    self.assertFalse(caller.is_alive(), external_error)
                    if fault_at in ("engine_store", "worker_complete"):
                        self.assertEqual(external_result, [])
                        self.assertEqual(external_error, [sentinel])
                        self.assertEqual(job.state.sequence, prepare_sequence)
                        self.assertIs(job._session, prepare_session)
                        self.assertIs(job._active_record, prepare_record)
                        self.assertFalse(prepare_record.completed.is_set())
                        self.assertEqual(engine.native_metadata.cpu_index, 1)
                        self.assertEqual(engine.dh_state.global_cpu_index, 1)
                        self.assertEqual(engine.dh_state.cpu_index, 1)
                        self.assertEqual(persistence_state.write_cpu_index, 0)
                        self.assertEqual(
                            job.worker._current_global_cpu_index,
                            0 if fault_at == "engine_store" else 1,
                        )
                        self.assertEqual(
                            job.worker._current_cpu_index,
                            0 if fault_at == "engine_store" else 1,
                        )
                        self.assertEqual(job.worker.source_state.cpu_offset, 1)
                        self.assertEqual(
                            len(captured_vbf_origins),
                            2 if fault_at == "engine_store" else 1,
                        )
                        actual_request, actual_origin = captured_vbf_origins[0]
                        self.assertIsNotNone(actual_request)
                        self.assertIsNotNone(actual_origin)
                        self.assertEqual(len(vbf_parked_snapshots), 1)
                        parked_cpu, parked_global_cpu, parked_metadata = (
                            vbf_parked_snapshots[0]
                        )
                        self.assertEqual(parked_cpu, 0)
                        self.assertEqual(parked_global_cpu, 0)
                        self.assertEqual(parked_metadata.cpu_index, 0)
                        self.assertEqual(actual_origin.record.fields["cpu_index"], 0)
                        self.assertEqual(
                            actual_origin.record.parked_global_cpu_index, 0
                        )
                        self.assertIs(
                            actual_origin.record.fields["metadata"], parked_metadata
                        )
                        release_cleanup.set()
                        prepare_report = job.result(5, sequence=prepare_sequence)
                        informer.join(5)
                        self.assertFalse(informer.is_alive())
                        self.assertEqual(inform_errors, [])
                        self.assertEqual(inform_results, [0])
                        self.assertIs(
                            job.result(1, sequence=prepare_sequence), prepare_report
                        )
                        self.assertEqual(job.state.sequence, prepare_sequence)
                        self.assertIsNotNone(engine._persistence_cpu_transition2026)
                        self.assertEqual(actual_origin.record.fields["cpu_index"], 0)
                        self.assertEqual(
                            actual_origin.record.parked_global_cpu_index, 0
                        )
                        self.assertIs(
                            actual_origin.record.fields["metadata"], parked_metadata
                        )
                        from scripts.cuw_engine_threads import (
                            _queued_vbf_request,
                            validate_vbf_process_before2026,
                        )

                        self.assertIsNone(_queued_vbf_request(job))
                        with self.assertRaises(ValueError):
                            validate_vbf_process_before2026(
                                actual_request, job, states=("parked",)
                            )
                        with self.assertRaises(ValueError):
                            original_record_cpu_store(actual_origin, worker=job.worker)
                        return
                    self.assertEqual(external_error, [])
                    self.assertEqual(external_result, [0])
                    self.assertEqual(job.state.sequence, prepare_sequence)
                    pair.engine.disconnect()
                    if not pair.engine.opened:
                        pair.engine.have_ownership()
                        pair.engine.open()
                    pair.engine.connect(6)
                    pair.validate_channel_lease(
                        pair.engine, pair.channel_lease(pair.engine)
                    )
                    external_fault["enabled"] = True
                    release_cleanup.set()
                    prepare_report = job.result(5, sequence=prepare_sequence)
                    informer.join(5)
                    self.assertFalse(informer.is_alive())
                    self.assertEqual(inform_errors, [])
                    self.assertEqual(inform_results, [0])
                    deadline = time.monotonic() + 5
                    while (
                        job.state.sequence == prepare_sequence
                        and time.monotonic() < deadline
                    ):
                        time.sleep(0.001)
                    self.assertEqual(job.state.sequence, prepare_sequence + 1)
                    with self.assertRaises(OSError) as caught:
                        job.result(5, sequence=prepare_sequence + 1)
                    self.assertIs(caught.exception, sentinel)
                    self.assertIs(job._outer, outer)
                    self.assertIs(job._child, child)
                    self.assertIs(
                        job.result(1, sequence=prepare_sequence), prepare_report
                    )
                    self.assertEqual(len(roots), 1)
                    self.assertIsNot(roots[0], prepare_session)
                    self.assertIs(roots[0].trace, session.trace)
                    self.assertEqual(len(phases), 1)
                    request_timestamp, timestamp, capture, phase_thread = phases[0]
                    self.assertEqual(timestamp, request_timestamp)
                    self.assertIs(phase_thread, child)
                    self.assertIsNot(capture, old_capture)
                    self.assertEqual(job.worker.source_state.cpu_offset, 1)
                    self.assertEqual(persistence_state.write_cpu_index, 0)
            except BaseException:
                release_cleanup.set()
                raise
            finally:
                release_cleanup.set()
            self.assertIs(
                type(prepare_report.get("native_return")), bool, prepare_report
            )
            self.assertIsNone(job._prepared_ordinary_entry2026)
            self.assertEqual(job.worker.source_state.cpu_offset, 1)
            self.assertEqual(persistence_state.write_cpu_index, 0)
            self.assertEqual(
                len(dh_binding_diagnostics),
                2,
                tuple(
                    tuple(binding[index] for index in (5, 6, 7, 8, 9, 11, 12, 13))
                    for binding in dh_binding_diagnostics
                ),
            )
            binding = dh_binding_diagnostics[0]
            resumed_binding = dh_binding_diagnostics[1]
            self.assertTrue(binding[2])
            # Source 3b90 deliberately combines retained CONTROL metadata with
            # the live WHOLE DH state; those metadata objects must stay distinct.
            self.assertFalse(binding[3], repr(binding))
            self.assertFalse(binding[4], repr(binding))
            # The live engine stays on the source44 WHOLE pointer while the
            # retained CONTROL export and its captured CPU remain PART1.
            self.assertEqual(binding[5][1][0], binding[6][1][0])
            self.assertEqual(binding[5][1][3], 0)
            self.assertEqual(binding[6][1][0], binding[11][1][0])
            self.assertEqual(binding[6][1][3], 0)
            self.assertTrue(binding[13][1])
            self.assertEqual(binding[11][1][0], binding[5][1][0])
            self.assertEqual(binding[11][1][3], 0)
            self.assertEqual(binding[7][1][0], prepare_digest)
            self.assertEqual(binding[7][1][3], 1)
            self.assertEqual(binding[8][1][0], prepare_digest)
            self.assertEqual(binding[8][1][3], 1)
            self.assertEqual(binding[9][1][0], prepare_digest)
            self.assertEqual(binding[9][1][3], 1)
            self.assertEqual(binding[12][1][0], prepare_digest)
            self.assertEqual(binding[12][1][3], 1)
            # The second bind belongs to the fresh raw root consumed by the
            # same persistent child after the external VBF prefix. Its live
            # engine and target now use the fresh WHOLE/CPU1 capture; the
            # worker's loaded FILE mirror still records CPU0.
            self.assertTrue(resumed_binding[2], repr(resumed_binding))
            self.assertFalse(resumed_binding[3], repr(resumed_binding))
            self.assertTrue(resumed_binding[4], repr(resumed_binding))
            self.assertEqual(
                resumed_binding[5][1][0], engine.native_metadata.source_sha256
            )
            self.assertEqual(resumed_binding[5][1][3], 1)
            self.assertEqual(
                resumed_binding[6][1][0], engine.native_metadata.source_sha256
            )
            self.assertEqual(resumed_binding[6][1][3], 0)
            self.assertEqual(
                resumed_binding[11][1][0], engine.native_metadata.source_sha256
            )
            self.assertEqual(resumed_binding[11][1][3], 1)
            self.assertTrue(resumed_binding[14][1])
            self.assertEqual(
                resumed_binding[7][1][0], engine.native_metadata.source_sha256
            )
            self.assertEqual(resumed_binding[7][1][3], 1)
            self.assertEqual(
                resumed_binding[8][1][0], engine.native_metadata.source_sha256
            )
            self.assertEqual(resumed_binding[8][1][3], 1)
            self.assertEqual(
                resumed_binding[9][1][0], engine.native_metadata.source_sha256
            )
            self.assertEqual(resumed_binding[9][1][3], 1)
            self.assertEqual(
                resumed_binding[12][1][0], engine.native_metadata.source_sha256
            )
            self.assertEqual(resumed_binding[12][1][3], 1)
            self.assertIsNot(dh_capture_provenance[0][0], dh_capture_provenance[1][0])
            self.assertGreater(dh_capture_provenance[1][1], dh_capture_provenance[0][1])
            self.assertIs(dh_capture_provenance[1][2], job)
            self.assertEqual(dh_capture_provenance[1][3], child.ident)
        self.assertEqual(session.trace.position, len(recorder_rows))

    def test_power_p4_status49_then_persistent_vbf_host_fault(self):
        import tempfile

        from scripts.cuw_engine_worker import EngineWorker2026
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )
        from scripts.j2534_2026 import NativeReadBatch2026
        from scripts.programming_replay import ProgrammingTrace, _native_request
        from tests.test_cuw_engine_worker import encoded_table
        from tests.test_programming_2026_common import make_raw_control_fixture2026
        from tests.test_programming_2026_p5_prepare import (
            POWER,
            run_native_context,
        )
        from tests.test_programming_2026_p5_prepare import (
            fixture as power_fixture,
        )

        _native, container, binding = power_fixture(  # type: ignore[misc]
            POWER, return_inputs=True, ig_off_retriable=False
        )
        rows = []
        echo = []
        reads_after_probe = 0

        def typed_value(value):
            if value is None:
                return {"type": "none", "value": None}
            if type(value) is bool:
                return {"type": "bool", "value": value}
            if type(value) is int:
                return {"type": "int", "value": value}
            if isinstance(value, bytes):
                return {"type": "bytes", "value": value.hex()}
            if isinstance(value, NativeMessage):
                return {
                    "type": "mapping",
                    "value": {
                        "_native_type": {
                            "type": "text",
                            "value": "PASSTHRU_MSG_2026",
                        },
                        **{key: typed_value(item) for key, item in vars(value).items()},
                    },
                }
            if isinstance(value, NativeReadBatch2026):
                return {
                    "type": "mapping",
                    "value": {
                        "_native_type": {"type": "text", "value": "READ_BATCH_2026"},
                        "messages": typed_value(value.messages),
                        "count": typed_value(value.count),
                    },
                }
            if isinstance(value, tuple):
                return {"type": "tuple", "value": [typed_value(item) for item in value]}
            if isinstance(value, list):
                return {
                    "type": "sequence",
                    "value": [typed_value(item) for item in value],
                }
            if isinstance(value, dict):
                return {
                    "type": "mapping",
                    "value": {key: typed_value(item) for key, item in value.items()},
                }
            raise TypeError(f"Unsupported typed driver value: {type(value)!r}")

        def capture_provider(event, _remaining):
            nonlocal reads_after_probe
            operation = event["operation"]
            if operation in (
                "passthru_open",
                "passthru_connect",
                "passthru_start_filter",
            ):
                result = PrimitiveResult(
                    value=101 if operation == "passthru_start_filter" else 17
                )
            elif operation == "passthru_write":
                message = event["messages"][0]
                echo.append(NativeMessage(6, message.data[:4], rx_status=9))
                result = PrimitiveResult(value=event["count"])
            elif operation == "passthru_read":
                if echo:
                    result = PrimitiveResult(value=(echo.pop(0),))
                else:
                    reads_after_probe += 1
                    result = PrimitiveResult(status=49)
            else:
                result = PrimitiveResult()
            rows.append(
                {
                    "kind": "action",
                    "request": _native_request(event),
                    "result": typed_value(
                        {"status": result.status, "value": result.value}
                    ),
                    "elapsed_ms": 1,
                }
            )
            return result

        direct_device = J2534Device2026(
            capture_provider, clock=lambda: 0, background_workers=False
        )
        direct_device.open()
        direct_device.connect(6)
        direct = run_native_context(
            _native,
            NativeRuntime2026(
                direct_device.primitive,
                clock=lambda: 0,
                cleanup_action=direct_device.cleanup_primitive,
            ),
        )
        self.assertFalse(direct["native_return"])
        self.assertEqual(
            (direct["native_error_code"], direct["driver_error_code"]), (1, 49)
        )
        self.assertFalse(direct["programming_completed"])
        self.assertEqual(reads_after_probe, 1)
        direct_device.disconnect()
        direct_device.close()

        operations = [row["request"].get("operation") for row in rows]
        probe_write = next(
            index
            for index, row in enumerate(rows)
            if row["request"].get("operation") == "passthru_write"
            and row["request"]["messages"][0]["data"]["value"].endswith("1002")
        )
        probe_reads = [
            index
            for index in range(probe_write + 1, len(rows))
            if operations[index] == "passthru_read"
        ]
        self.assertEqual(len(probe_reads), 2)
        stop_filter = next(
            index
            for index in range(probe_reads[-1] + 1, len(rows))
            if operations[index] == "passthru_stop_filter"
        )
        start_filter = operations.index("passthru_start_filter")
        second_generation_driver_rows = [
            *rows[start_filter : probe_reads[-1]],
            rows[stop_filter],
        ]
        clock_rows = [
            {
                "kind": "action",
                "request": {"operation": "get_local_milliseconds_of_day"},
                "result": {"type": "int", "value": timestamp},
                "elapsed_ms": 1,
            }
            for timestamp in (1000, 1100, 1200, 1300)
        ]
        trace_events = [
            *rows[:start_filter],
            clock_rows[0],
            *rows[start_filter : stop_filter + 1],
            clock_rows[1],
            clock_rows[2],
            *second_generation_driver_rows,
        ]

        values = {
            key: "\n".join(value)
            for key, value in binding.values.items()
            if key != "ParamFileKeySystemProtocolMicon"
        }
        values["EnableDLLVersionInformation"] = "0\n0\n0\n0"
        profile_fields = ("ParamFileKeySystemProtocolMicon", *values)
        profile = encoded_table(profile_fields, (("8P4A", *values.values()),))
        catalog = {
            "8P4A.ini": profile,
            "8P4B.ini": encoded_table(profile_fields, (("8P4B", *values.values()),)),
            "Parameter.ini": encoded_table(
                (
                    "ParamFileKeySystemProtocolMicon",
                    "M16CTypeFlag",
                    "FORESTTypeFlag",
                    "PasswordAddress",
                    "ByteOrder",
                    "FlagToChangeWFSE",
                    "FlagToUseCIDGetterAndFlashWriterDLL",
                    "FlagToChangeToReprogGWModeForCentralGW",
                ),
                (
                    ("8P4A", "0", "0", "00", "1", "0", "0", "0"),
                    ("8P4B", "0", "0", "00", "1", "0", "0", "0"),
                ),
            ),
        }
        source = cuw(
            container.attached.data.decode("ascii"),
            tuple(record.data for record in container.records),
        )
        images = Path("runtime/no-car-21/recovered")
        first_probe = threading.Event()
        allow_first_probe = threading.Event()
        cleanup_entered = threading.Event()
        allow_cleanup = threading.Event()
        sentinel = OSError("vbf-second-probe-host-sentinel")
        saw_probe_reads = 0
        last_request = None
        new_roots = []
        original_provider = ProgrammingTrace.driver_primitive

        def gated_provider(trace, event, remaining):
            nonlocal saw_probe_reads, last_request
            operation = event["operation"]
            if operation == "passthru_write":
                last_request = event["messages"][0].data[4:]
            if operation == "passthru_read" and last_request == b"\x10\x02":
                saw_probe_reads += 1
                if saw_probe_reads == 2:
                    if not first_probe.is_set():
                        first_probe.set()
                        if not allow_first_probe.wait(3):
                            raise TimeoutError("first probe barrier expired")
                elif saw_probe_reads == 4:
                    new_roots.append(job._session)
                    raise sentinel
            return original_provider(trace, event, remaining)

        provider_patch = patch.object(
            ProgrammingTrace, "driver_primitive", new=gated_provider
        )
        provider_patch.start()
        self.addCleanup(provider_patch.stop)
        engine, controller, session = make_raw_control_fixture2026(
            self,
            source=source,
            catalog=catalog,
            module_files={
                POWER: read_private_bytes(images / POWER),
                "TCUWControlCommPhase.dll": read_private_bytes(
                    images / "TCUWControlCommPhase.dll"
                ),
            },
            operation="prepare",
            events=trace_events,
            paired=True,
        )
        self.addCleanup(engine.close)
        output = tempfile.TemporaryDirectory(dir="runtime/no-car-33")
        self.addCleanup(output.cleanup)
        assert engine._source is not None
        engine.bind_persistence(
            CUWPersistence(
                Path(output.name),
                ReproInfoState(
                    (RecoveryCalibration("authored.vbf", engine._source),),
                ),
            )
        )
        job = engine.bind_thread_job(controller)
        self.addCleanup(job.stop)
        trace = session.trace
        pair = trace.interface_pair
        assert pair is not None
        cleanup_owner = engine.bind_cleanup_controller()
        original_cleanup = cleanup_owner.release_retired_selected

        def held_cleanup(worker):
            original_cleanup(worker)
            cleanup_entered.set()
            if not allow_cleanup.wait(3):
                raise TimeoutError("retired cleanup barrier expired")

        call_result = []
        call_error = []
        phase_imports = []
        issued_requests = []
        original_phase_started = EngineWorker2026._phase_started

        def observe_phase_started(worker, phase, *, _vbf_request=None):
            result = original_phase_started(worker, phase, _vbf_request=_vbf_request)
            if _vbf_request is not None:
                phase_imports.append(
                    (
                        _vbf_request.started_ms,
                        worker._phase_started_ms,
                        threading.current_thread() is job._child,
                        worker._control_file_capture,
                    )
                )
            return result

        def process_before():
            try:
                call_result.append(
                    engine.process_before_reprogramming(
                        engine._general_parameters, engine.engine_runtime_device()
                    )
                )
            except BaseException as error:  # noqa: BLE001 - preserve exact provider failure identity
                call_error.append(error)

        with (
            patch.object(
                cleanup_owner, "release_retired_selected", side_effect=held_cleanup
            ),
            patch.object(EngineWorker2026, "_phase_started", new=observe_phase_started),
        ):
            session.bind_engine2026(engine)
            session.bind_controller2026(controller)
            pair.engine.open()
            pair.engine.connect(6)
            job.start(session)
            self.assertTrue(
                first_probe.wait(3),
                f"child error={job._error!r}, trace={trace.position}/{len(trace.rows)}, "
                f"ops={[row['request'].get('operation') for row in rows]!r}, "
                f"next={trace.rows[trace.position : trace.position + 1]!r}, "
                f"tb={__import__('traceback').format_exception(job._error) if job._error else None}",
            )
            external = threading.Thread(target=process_before)
            outer_identity = job._outer
            child_identity = job._child
            old_capture = job.worker._control_file_capture
            external.start()
            deadline = time.monotonic() + 3
            while (
                job.worker.native_prepare_handshake != 2 and time.monotonic() < deadline
            ):
                time.sleep(0.001)
            self.assertEqual(
                (job.worker.native_prepare_handshake, call_error, call_result),
                (2, [], []),
            )
            from scripts.cuw_engine_threads import _VBF_REQUESTS

            issued_requests.extend(
                request
                for request, record in _VBF_REQUESTS.values()
                if record.fields["job"] is job
            )
            self.assertEqual(len(issued_requests), 1)
            foreign_errors = []

            def foreign_issuer():
                try:
                    job._validate_vbf_issuer2026(issued_requests[0])
                except BaseException as error:  # noqa: BLE001 - retain exact guard outcome
                    foreign_errors.append(error)

            foreign = threading.Thread(target=foreign_issuer)
            foreign.start()
            foreign.join(3)
            self.assertFalse(foreign.is_alive())
            self.assertEqual(len(foreign_errors), 1)
            self.assertIsInstance(foreign_errors[0], ValueError)
            allow_first_probe.set()
            self.assertTrue(cleanup_entered.wait(3))
            external.join(3)
            self.assertFalse(external.is_alive())
            self.assertEqual(call_error, [])
            self.assertEqual(call_result, [0])
            self.assertEqual(job.worker.native_prepare_handshake, 1)
            self.assertEqual(len(phase_imports), 0)
            self.assertTrue(job._child_parked.is_set())
            self.assertEqual(job.state.sequence, 1)
            with self.assertRaises(ValueError):
                engine.reserve_phase(controller, 1)
            allow_cleanup.set()
            deadline = time.monotonic() + 3
            while job.state.sequence < 2 and time.monotonic() < deadline:
                time.sleep(0.001)
            self.assertEqual(job.state.sequence, 2)
            old_result = job.result(5, sequence=1)
            with self.assertRaises(OSError) as caught:
                job.result(5, sequence=2)
            self.assertIs(caught.exception, sentinel)
            from scripts.cuw_engine_threads import validate_vbf_process_before2026

            with self.assertRaises(ValueError):
                validate_vbf_process_before2026(
                    issued_requests[0], job, states=("adopted",)
                )
            self.assertEqual(len(phase_imports), 1)
            self.assertEqual(phase_imports[0][:3], (1200, 1200, True))
            new_capture = phase_imports[0][3]
            self.assertIsNot(new_capture, old_capture)
            self.assertIs(new_capture, job.worker._control_file_capture)
            self.assertIs(job._outer, outer_identity)
            self.assertIs(job._child, child_identity)
            self.assertEqual(len(new_roots), 1)
            self.assertIsNot(new_roots[0], session)
            self.assertIs(new_roots[0].trace, trace)
            self.assertIs(job.result(5, sequence=1), old_result)
            old_record = job._completion_records[1]
            self.assertTrue(old_record.completed.is_set())
            assert old_record.result is not None
            self.assertIs(old_record.result["native_return"], False)
        self.assertEqual(session.trace.position, len(session.trace.rows))
        self.assertEqual(
            [
                event["result"]["value"]
                for event in trace_events
                if event["request"].get("operation") == "get_local_milliseconds_of_day"
            ],
            [1000, 1100, 1200],
        )


if __name__ == "__main__":
    unittest.main()
