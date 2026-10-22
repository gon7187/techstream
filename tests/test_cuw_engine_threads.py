"""Actual engine reservation and native thread lifetime checks."""

import copy
import hashlib
import json
import struct
import threading
import time
import unittest
from itertools import cycle
from pathlib import Path
from typing import Any
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
        if source_files is not None:
            key = "149P5-Unified311"
            name = "TCUWCanUnifiedCIDGetter.dll"
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
                    for item in (
                        (key, "149P5-Unified") if source_files is not None else (key,)
                    )
                ),
            ),
        }
        if not include_profile:
            del catalog[key + ".ini"]
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
                "host": {"driver_recording": "j2534_2026"} if recorded_driver else {},
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
                    if recorded_driver
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
        engine = CUWEngine2026(
            read_private_bytes(images / "CUW.dll"),
            general_parameters=NativeGeneralParameters2026.from_sources(catalog),
        )
        engine.configure(
            struct.pack("<IIddII", 4 if source_files is not None else 1, 0, 1, 2, 0, 0)
        )
        engine.load_cuw(source)
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

            def provider(_operation, _remaining):
                return PrimitiveResult()

            engine_device = J2534Device2026(provider, background_workers=False)
            control_device = J2534Device2026(provider, background_workers=False)
            engine.bind_interface_pair(
                J2534InterfacePair2026(engine_device, control_device)
            )
            runtime = NativeRuntime2026(control_device.primitive)
        controller = make_controller(runtime)
        if recorded_driver:
            session.bind_controller2026(controller)
            engine.bind_interface_pair(session.trace.interface_pair)
        job = engine.bind_thread_job(controller)
        self.addCleanup(engine.close)
        self.addCleanup(job.stop)
        return engine, controller, job, session

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
        from pathlib import Path

        from scripts.j2534_2026 import (
            DriverMetadata2026,
            J2534Device2026,
            J2534InterfacePair2026,
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
        provider_runtime, device, _provider_events = typed_runtime(
            cycle((p5(b"ONE"), b"SECOND"))
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
                if reads == 4:
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
        self.assertIs(direct["bool_out"], False)
        self.assertEqual(direct["cids"], (b"ONE",))
        for _ in range(1, generations):
            repeated = run_native_context(native, provider_runtime)
            self.assertIs(repeated["bool_out"], False)
            self.assertEqual(repeated["cids"], (b"ONE",))
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
        fixed_clock = lambda: 1000
        session.trace.native_local_milliseconds_of_day = fixed_clock
        controller.runtime.local_milliseconds_of_day = fixed_clock
        job = engine.bind_thread_job(controller)
        self.addCleanup(job.stop)
        pair = engine.interface_pair
        assert pair is not None
        runner_calls = []

        original_runner = ProgrammingReplay._runner

        def runner(*args):
            runner_calls.append(True)
            return original_runner(*args)

        with (
            patch.object(ProgrammingReplay, "_runner", runner),
            patch.object(pair, "import_into", wraps=pair.import_into) as imports,
        ):
            job.start(session)
            try:
                report = job.result(5)
            except ValueError as error:
                raise AssertionError(
                    f"raw P5 child stopped at event {session.trace.position}; "
                    f"runner calls={runner_calls}; captured={[row['request'].get('operation') for row in rows]}; "
                    f"next={session.trace.rows[session.trace.position : session.trace.position + 1]}"
                ) from error
            reports = [report]
            for sequence in range(2, generations + 1):
                session = session.next_session2026(
                    "get_cid", node=session.node, cpu_index=0
                )
                self.assertEqual(job.start(session), sequence)
                reports.append(job.result(5, sequence=sequence))

        self.assertIs(report["native_return"], False, report)
        self.assertEqual(report["identifiers"], (b"ONE",))
        self.assertEqual(runner_calls, [True] * generations)
        self.assertEqual(
            [call.args[0] for call in imports.call_args_list],
            [pair.control, pair.engine] * generations,
        )
        self.assertEqual(engine.received_identifiers, (b"ONE",))
        self.assertEqual(session.trace.position, len(session.trace.rows))
        if generations > 1:
            self.assertIs(job.result(5, sequence=1), report)
            self.assertEqual(
                [item["identifiers"] for item in reports],
                [(b"ONE",)] * generations,
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
            raise fault

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

    def test_native_cid_stop_joins_actual_idle_threads_without_host_interruption(self):
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
        self.assertEqual(engine.stop_receiving_cid(timeout=2), 0)
        self.assertTrue(engine.native_cancelled())
        self.assertFalse(job.host_stop_requested)
        self.assertFalse(job.native_worker_exists)
        self.assertFalse(job.state.child_alive)
        self.assertIs(controller.runtime.cancelled, cancelled)

    def test_native_cid_stop_reissues_fresh_worker_preserving_global_resources(self):
        engine, controller, old_job, session = self.imported_prepare(
            operation="get_cid"
        )
        cleanup = engine.bind_cleanup_controller()
        retry = engine.bind_retry_controller()
        state = cleanup.state
        history, selected = state.history, state.selected
        history[:] = b"x" * 0x1028
        state.buffers[:] = [bytearray(b"authored retained buffer"), None]
        buffer = state.buffers[0]
        engine.set_vin(b"JTDBE32KX10000001")
        clock_values = iter((1000, 1017, 2000, 2000))
        clock = lambda: next(clock_values)
        session.trace.native_local_milliseconds_of_day = clock
        controller.runtime.local_milliseconds_of_day = clock
        with engine.controller_execution(controller, 2):
            engine.dh_state.set_native_count(0, 37)
            engine.dh_state.set_native_percentage(0, 53)
        with engine.controller_execution(controller, 1):
            pass
        old_worker = engine.worker
        self.assertEqual(old_worker.native_prepare_handshake, 1)
        timing = old_worker.source_state.phase_elapsed_ms
        metadata, configuration = engine.native_metadata, engine.configuration
        fault = ValueError("authored stopped-CID clock fault")

        def clock_fault():
            raise fault

        session.trace.native_local_milliseconds_of_day = clock_fault
        controller.runtime.local_milliseconds_of_day = clock_fault
        old_job.start(session)
        with self.assertRaises(ValueError) as caught:
            old_job.result(2)
        self.assertIs(caught.exception, fault)
        self.assertEqual(engine.stop_receiving_cid(timeout=2), 0)
        new_job = engine.bind_thread_job(controller)
        self.addCleanup(new_job.stop)
        new_worker = engine.worker
        self.assertIsNot(new_job, old_job)
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
        self.assertEqual(engine.dh_state.transferred_bytes, (37,))
        self.assertEqual(engine.dh_state.progress, (53,))
        self.assertEqual(new_worker.source_state.phase_elapsed_ms, timing)
        self.assertEqual(new_worker.native_prepare_handshake, 0)
        self.assertFalse(new_worker.control_state.fatal)
        self.assertFalse(new_worker.control_state.failed)
        with self.assertRaises(ValueError):
            old_worker.validate_source()
        with self.assertRaises(ValueError):
            old_job.validate_owner(engine)

    def test_native_cid_reissue_preserves_two_file_received_projection(self):
        first = calibration(cpus=2)
        second = calibration(cpus=2, first_target="OTHER")
        engine, controller, old_job, session = self.imported_prepare(
            operation="get_cid",
            source=first,
            source_files={"first.cuw": first, "second.cuw": second},
        )
        engine._import_identifier_context()
        engine.commit_received_identifiers(
            (b"OLD", b"SECOND-LATEST"), controller=controller
        )
        controller.runtime.local_milliseconds_of_day = lambda: 1000
        with engine.controller_execution(controller, 0):
            self.assertTrue(old_job.worker.mark_cid_reception_complete())
        old_worker = old_job.worker
        source_state = old_worker.source_state
        self.assertEqual(source_state.target_indices, (0, 1))
        loaded = old_worker.loaded_metadata
        self.assertEqual(len(loaded), 2)
        sources, metadata = engine.file_sources, engine.native_metadata
        cleanup = engine.bind_cleanup_controller()
        selected = cleanup.state.selected
        fault = ValueError("authored projection-preserving CID clock fault")

        def clock():
            raise fault

        session.trace.native_local_milliseconds_of_day = clock
        controller.runtime.local_milliseconds_of_day = clock
        old_job.start(session)
        with self.assertRaises(ValueError) as caught:
            old_job.result(2)
        self.assertIs(caught.exception, fault)
        self.assertEqual(engine.stop_receiving_cid(timeout=2), 0)
        replacement = engine.bind_thread_job(controller)
        self.addCleanup(replacement.stop)
        self.assertIs(engine.file_sources, sources)
        self.assertIs(engine.native_metadata, metadata)
        self.assertIs(cleanup.state.selected, selected)
        self.assertEqual(replacement.worker.loaded_metadata, loaded)
        self.assertEqual(replacement.worker.source_state.target_indices, (0, 1))
        self.assertEqual(
            replacement.worker.source_state.authored_target_indices,
            source_state.authored_target_indices,
        )
        self.assertEqual(replacement.worker.native_writer_target_index, 0)

    def test_native_worker_reissue_rolls_back_dependent_owner_failure(self):
        engine, controller, old_job, session = self.imported_prepare(
            operation="get_cid"
        )
        cleanup = engine.bind_cleanup_controller()
        retry = engine.bind_retry_controller()
        old_worker = engine.worker
        state = cleanup.state
        clock_fault = ValueError("authored stopped-CID clock fault")

        def clock():
            raise clock_fault

        session.trace.native_local_milliseconds_of_day = clock
        controller.runtime.local_milliseconds_of_day = clock
        old_job.start(session)
        with self.assertRaises(ValueError) as caught:
            old_job.result(2)
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
            raise fault

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
        state = "adopted"

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
