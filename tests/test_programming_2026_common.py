"""Authored controls for shared2026 primitives; no original secret material."""

import threading
import unittest
from typing import Any

from scripts.programming_2026_common import NativeRuntime2026, NotificationBool


class SuzukiWaitRuntimeBoundaryTests(unittest.TestCase):
    def test_standalone_wait_notification_remains_provider_only(self):
        events = []
        runtime = NativeRuntime2026(
            lambda event, _remaining: events.append(event), clock=lambda: 0
        )
        runtime.call("notify_igoffon_wait", value=0xFFFFFFFF)
        runtime.call("notify_igoffon_wait", cleanup=True, value=0)
        self.assertEqual(
            events,
            [
                {"operation": "notify_igoffon_wait", "value": 0xFFFFFFFF},
                {"operation": "notify_igoffon_wait", "value": 0},
            ],
        )
        self.assertIsNone(getattr(runtime._device_calls, "suzuki_wait_origin", None))

    def test_arbitrary_scope_entry_and_unissued_origins_cannot_publish(self):
        runtime = NativeRuntime2026(
            lambda *_: self.fail("No provider call"), clock=lambda: 0
        )
        with (
            self.assertRaisesRegex(ValueError, "selected Suzuki runner"),
            runtime._suzuki_igoffon_wait_scope_2026(
                object(), engine=object(), controller=object()
            ),
        ):
            self.fail("Arbitrary caller entered selected scope")
        for origin in (None, object(), 123, (object(), 1)):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                runtime._consume_suzuki_igoffon_wait_origin_58e20_2026(
                    origin, engine=object()
                )


class NotificationTests(unittest.TestCase):
    def test_assign_notifies_without_change_and_disable_enable(self):
        events = []
        value = NotificationBool()
        value.set_event_handler(events, lambda _context, flag: events.append(flag))
        value.assign(False).assign(True)
        value.disable_event_handler()
        value.disable_event_handler()
        value.assign(False)
        value.enable_event_handler()
        value.assign(False)
        self.assertEqual(events, [False, True, False])
        self.assertFalse(value)

    def test_copy_and_reset_do_not_notify(self):
        events = []
        original = NotificationBool(True)
        original.set_event_handler(events, lambda _context, flag: events.append(flag))
        value = NotificationBool().assign(original)
        self.assertTrue(value)
        self.assertIs(value.handler, original.handler)
        self.assertEqual(events, [])
        value.reset()
        value.assign(True)
        self.assertEqual(events, [])

    def test_set_handler_preserves_disabled_backup(self):
        events = []
        value = NotificationBool()
        value.set_event_handler(events, lambda _context, flag: events.append((1, flag)))
        value.disable_event_handler()
        value.set_event_handler(events, lambda _context, flag: events.append((2, flag)))
        value.enable_event_handler()
        value.assign(True)
        self.assertEqual(events, [(1, True)])

    def test_null_context_and_invalid(self):
        value = NotificationBool()
        value.set_event_handler(None, lambda *_: self.fail("Null native context"))
        value.assign(True)
        invalid: Any
        for invalid in (0, 1, None, "true"):
            with self.assertRaises(ValueError):
                value.assign(invalid)
            with self.assertRaises(ValueError):
                NotificationBool(invalid)


class BytesConstructorTests(unittest.TestCase):
    def test_constructor_strtol_pairs_differ_from_strict_setter(self):
        from scripts.programming_2026_common import NativeBytes2026

        self.assertEqual(
            NativeBytes2026.from_hex("+1-1 2\t3").data, bytes.fromhex("01ff0203")
        )
        value = NativeBytes2026(b"previous")
        for malformed in ("+1", "-1", " 2", "\t3"):
            with self.assertRaises(ValueError):
                value.set_bytes_from_hex(malformed)
            self.assertEqual(value.data, b"previous")
        value.set_bytes_from_hex("aB01")
        self.assertEqual(value.data, bytes.fromhex("ab01"))


class MetadataRuntimeStateBindingTests(unittest.TestCase):
    def test_region_and_parser_profile_validation_remain_source_bound(self):
        from dataclasses import replace

        from scripts.calibration_2026 import (
            native2026_metadata,
            native2026_with_parser_parameters,
            parse_cuw_2026,
        )
        from scripts.programming_2026_common import (
            NativeGeneralParameters2026,
            bind_parameter2026,
        )
        from tests.test_calibration_2026 import cuw

        text = "[Format]\nVersion=6\n[Vehicle]\nKindOfECU=1\nContactType=SIL\nNumberOfCalibration=1\n[CPU01]\nCPUType=1\nCPUImageName=one.vbf\n"
        container = parse_cuw_2026(cuw(text))
        general_data = b"ParamFileKeySystemProtocolMicon,M16CTypeFlag\r\n1SIL1,0\r\n"
        sources = {
            "Parameter.ini": general_data,
            "1SIL1.ini": b"ParamFileKeySystemProtocolMicon,DLLFileNameForFlashWrite\r\n1SIL1,Authored.dll\r\n",
        }
        general = NativeGeneralParameters2026.from_sources(sources, encoded=False)
        state = native2026_with_parser_parameters(
            native2026_metadata(container, region=2), general
        )
        bound = bind_parameter2026(
            container, sources, "write", encoded=False, metadata_state=state
        )
        self.assertEqual(bound.metadata.region, 2)
        self.assertTrue(bound.metadata.parser_parameters_validated)
        self.assertEqual(bound.validate_against(container, operation="write"), bound)
        wrong_sources = {**sources, "Parameter.ini": general_data.replace(b",0", b",1")}
        with self.assertRaises(ValueError):
            bind_parameter2026(
                container, wrong_sources, "write", encoded=False, metadata_state=state
            )
        other_container = parse_cuw_2026(cuw(text.replace("one.vbf", "other.vbf")))
        with self.assertRaises(ValueError):
            bind_parameter2026(
                container,
                sources,
                "write",
                encoded=False,
                metadata_state=replace(state, source_container=other_container),
            )

    def test_issued_received_cid_projection_binds_and_retains_loaded_row(self):
        import struct
        from dataclasses import replace

        from scripts.calibration_2026 import (
            native2026_archive,
            native2026_metadata,
            native2026_select_received_cids,
            parse_cuw_2026,
        )
        from scripts.cuw_2026 import configure_2026
        from scripts.programming_2026_common import (
            NativeGeneralParameters2026,
            bind_parameter2026,
        )
        from tests.test_calibration_2026 import cpu_text, cuw, srecord

        text = (
            cpu_text(8)
            .replace(".vbf", ".hex")
            .replace("NumberOfCalibration=1", "NumberOfCalibration=2")
        )
        text += (
            "NewCID=NEW1\nNumberOfTargets=1\n01_TargetCalibration=OLD1\n"
            "[CPU02]\nCPUImageName=two.hex\nCPUType=311\nNewCID=NEW2\n"
            "NumberOfTargets=1\n01_TargetCalibration=OLD2\n"
        )
        images = tuple(
            srecord(3, 0x1000, payload) + b"\n" + srecord(7, 0x1000) + b"\n"
            for payload in (b"FIRST", b"SECOND")
        )
        container = parse_cuw_2026(cuw(text, images))
        sources = {
            "Parameter.ini": b"ParamFileKeySystemProtocolMicon,M16CTypeFlag\r\n149P5-Unified311,0\r\n",
            "149P5-Unified311.ini": b"ParamFileKeySystemProtocolMicon,DLLFileNameForFlashWrite\r\n149P5-Unified311,Authored.dll\r\n",
        }
        general = NativeGeneralParameters2026.from_sources(sources, encoded=False)
        original = native2026_metadata(container)
        loaded = bind_parameter2026(container, sources, "write", encoded=False)
        projected = native2026_select_received_cids(
            original,
            (b"MISSING", b"OLD2"),
            (bytes(12), bytes(12)),
            general,
            configuration=configure_2026(struct.pack("<IIddII", 4, 0, 0.0, 0.0, 0, 0)),
            shrink_flag=False,
        ).rebuilt_metadata
        bound = bind_parameter2026(
            container, sources, "write", encoded=False, metadata_state=projected
        )
        self.assertIs(bound.metadata, projected)
        self.assertEqual(native2026_archive(bound.metadata).data, b"SECOND")
        self.assertEqual(bound.validate_against(container, operation="write"), bound)
        retained = loaded.rebind_writer_metadata(projected)
        self.assertEqual(retained.loaded_parameter_metadata, loaded.metadata)
        self.assertEqual(
            retained.validate_against(container, operation="write"), retained
        )
        for forged in (
            replace(projected),
            replace(projected, vehicle=original.vehicle),
        ):
            with self.assertRaisesRegex(ValueError, "Issued"):
                bind_parameter2026(
                    container, sources, "write", encoded=False, metadata_state=forged
                )
            with self.assertRaisesRegex(ValueError, "Issued"):
                loaded.rebind_writer_metadata(forged)


class NativeControlContextTests(unittest.TestCase):
    @staticmethod
    def engine_and_controller():
        import struct
        from pathlib import Path

        from scripts.cuw_2026 import CUWEngine2026, identity_2026
        from scripts.programming_2026_common import ControlCommPhase2026
        from tests.test_calibration_2026 import cpu_text, cuw

        folder = Path("runtime/no-car-21/recovered")
        if not (folder / "CUW.dll").is_file():
            raise unittest.SkipTest("Authenticated static CUW2026 image is absent")
        identity = identity_2026(
            (folder / "TCUWControlCommPhase.dll").read_bytes(),
            "TCUWControlCommPhase.dll",
        )
        controller = ControlCommPhase2026(
            identity, NativeRuntime2026(lambda _event, _remaining: None)
        )
        engine = CUWEngine2026((folder / "CUW.dll").read_bytes())
        engine.configure(struct.pack("<IIddII", 2, 0, 0, 0, 0, 0))
        engine.load_cuw(cuw(cpu_text()))
        return engine, controller

    def test_real_import_issues_held_context_and_phase_expiry_revokes_it(self):
        from scripts.programming_2026_common import NativeControlContext2026

        engine, controller = self.engine_and_controller()
        self.addCleanup(engine.close)
        with engine.controller_execution(controller, 0) as worker:
            context = controller.native_control_context2026(engine)
            capture = worker._control_file_capture
            if capture is None:
                self.fail("The actual 59ab0 import did not issue a FILE capture")
            self.assertIs(type(context), NativeControlContext2026)
            self.assertEqual(
                context.metadata, context.metadata_for_cpu(context.cpu_index)
            )
            self.assertEqual(context.target_indices, capture.target_indices)
            self.assertEqual(context.cpu_index, capture.control_cpu_start)
            self.assertEqual(
                context.native_index_for_source_cpu(0),
                capture.native_order.index(0),
            )
            with self.assertRaises(AttributeError):
                context._cpu_index = 1
        with self.assertRaises(ValueError):
            context.validate(engine, controller)
        with self.assertRaises(ValueError):
            controller.native_control_context2026(engine)

    def test_context_is_unforgeable_foreign_and_thread_bound(self):
        import copy

        from scripts.programming_2026_common import NativeControlContext2026

        engine, controller = self.engine_and_controller()
        self.addCleanup(engine.close)
        foreign = type(controller)(
            controller.identity, NativeRuntime2026(lambda *_: None)
        )
        with engine.controller_execution(controller, 0):
            context = controller.native_control_context2026(engine)
            with self.assertRaises(TypeError):
                NativeControlContext2026()
            with self.assertRaises(TypeError):
                copy.copy(context)
            with self.assertRaises(ValueError):
                context.validate(engine, foreign)
            with self.assertRaises(ValueError):
                foreign.native_control_context2026(engine)
            errors = []

            def validate_from_foreign_thread():
                try:
                    context.validate(engine, controller)
                except ValueError as error:
                    errors.append(error)

            thread = threading.Thread(target=validate_from_foreign_thread)
            thread.start()
            thread.join()
            self.assertEqual(len(errors), 1)
            self.assertIs(type(errors[0]), ValueError)

    def test_pooled_binding_uses_loaded_row_and_export_target_rejects_slot_reload(self):
        from dataclasses import replace

        from scripts.cuw_parameter_pool import ControlParameterPool2026
        from scripts.programming_2026_common import NativeControlExportTarget2026

        engine, controller = self.engine_and_controller()
        self.addCleanup(engine.close)
        pool = None
        with engine.controller_execution(controller, 0):
            pool = ControlParameterPool2026.issue(
                engine,
                controller,
                {
                    "149P5-Unified.ini": (
                        b"ParamFileKeySystemProtocolMicon,DLLFileNameForGetCID\r\n"
                        b"149P5-Unified,Authored.dll\r\n"
                    )
                },
                encoded=False,
            )
            self.addCleanup(pool.close)
            self.assertEqual(pool.load_for(engine, controller, "get_cid"), (0,))
            binding = pool.selected_binding(engine, controller, 0, "get_cid")
            self.assertEqual(binding.key, "149P5-Unified")
            self.assertEqual(binding.value("DLLFileNameForGetCID"), "Authored.dll")
            self.assertEqual(binding.parameter.row_index, 1)
            self.assertIs(
                binding.validate_against(
                    binding.metadata.source_container, operation="get_cid"
                ),
                binding,
            )
            with self.assertRaises(ValueError):
                replace(binding).validate_against(
                    binding.metadata.source_container, operation="get_cid"
                )
            target = NativeControlExportTarget2026.issue(
                engine, controller, pool, 0, "get_cid"
            )
            self.assertIs(target.binding.source_name, binding.source_name)
            self.assertEqual(
                target.target_index,
                controller.native_control_context2026(engine).target_index,
            )
            pool.load_for(engine, controller, "get_cid")
            with self.assertRaises(ValueError):
                target.validate(engine, controller)


def make_raw_control_fixture2026(
    case,
    *,
    source,
    catalog,
    module_files,
    operation="prepare",
    events=(),
    paired=False,
    bind_frontend=False,
    bind_persistence=False,
    bind_file_sources=False,
):
    """Authored FILE/recorded primitives with authenticated original module bytes."""
    import hashlib
    import json
    import struct
    from pathlib import Path

    from scripts.cuw_2026 import CUWEngine2026, identity_2026
    from scripts.programming_2026_common import ControlCommPhase2026
    from scripts.programming_replay import load_programming_replay
    from tests.private_evidence import read_private_bytes, require_private

    images = Path("runtime/no-car-21/recovered")
    require_private(images)
    context = {
        "schema": "techstream-programming-replay-v1",
        "source": "recorded_unverified",
        "calibration_sha256": hashlib.sha256(source).hexdigest(),
        "operation": operation,
        "node": 1,
        "observations": {
            "current_cids": [],
            "tester_info_hex": bytes(32).hex(),
            "system_time": [2026, 10, 22, 22, 1, 2, 3, 4],
            "timeout_seconds": 30,
            "cid_mode": 2,
            "host": {},
        },
        "events": list(events),
    }
    if paired:
        context["observations"]["host"]["driver_recording"] = "j2534_2026"
        module_files = {
            **module_files,
            "TCUWJ2534DeviceIF.dll": read_private_bytes(
                images / "TCUWJ2534DeviceIF.dll"
            ),
        }
    session = load_programming_replay(
        source, json.dumps(context).encode(), catalog, module_files
    )
    case.addCleanup(session.trace.close)
    runtime = NativeRuntime2026(
        session.trace.action,
        clock=session.trace.clock,
        cancelled=session.trace.cancelled,
        local_seconds_of_day=session.trace.native_local_seconds_of_day,
        local_milliseconds_of_day=session.trace.native_local_milliseconds_of_day,
    )
    from scripts.programming_2026_common import (
        NativeFrontendParameters2026,
        NativeGeneralParameters2026,
    )

    frontend = (
        NativeFrontendParameters2026.from_sources(catalog, encoded=True)
        if bind_frontend
        else None
    )
    general = (
        frontend.general
        if frontend is not None
        else NativeGeneralParameters2026.from_sources(catalog)
        if "Parameter.ini" in catalog
        else None
    )
    engine = CUWEngine2026(
        read_private_bytes(images / "CUW.dll"), general_parameters=general
    )
    engine.configure(struct.pack("<IIddII", 16, 0, 1, 2, 0, 0))
    if frontend is not None:
        engine.bind_frontend_parameters(frontend)
    sources = None
    if bind_file_sources:
        from scripts.cuw_file_services import admit_file_sources_2026

        sources = admit_file_sources_2026(
            engine,
            "input.json",
            b'["fixture.cuw"]',
            region=0,
            source_files={"fixture.cuw": source},
        )
        engine.bind_file_sources(sources)
    else:
        engine.load_cuw(source)
    if bind_persistence:
        import tempfile

        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )

        persistence_root = tempfile.TemporaryDirectory()
        case.addCleanup(persistence_root.cleanup)
        if sources is None:
            names, originals, count = ("fixture.cuw",), (source,), 0
        else:
            names, originals, count = sources.recovery_sources()
        engine.bind_persistence(
            CUWPersistence(
                Path(persistence_root.name),
                ReproInfoState(
                    tuple(
                        RecoveryCalibration(
                            name, original, blank_ecu_flags=(False,) * 4
                        )
                        for name, original in zip(names, originals, strict=True)
                    ),
                    multi_calibration_file_num=count,
                    loaded=False,
                ),
            )
        )
    controller = ControlCommPhase2026(
        identity_2026(
            read_private_bytes(images / "TCUWControlCommPhase.dll"),
            "TCUWControlCommPhase.dll",
        ),
        runtime,
    )
    if paired:
        session.bind_runtime2026(runtime)
        from scripts.j2534_2026 import DriverMetadata2026

        pair = session.trace.interface_pair
        assert pair is not None
        for view in (pair.engine, pair.control):
            view.set_current_driver(DriverMetadata2026("Authored", "authored.dll"))
        engine.bind_interface_pair(pair)
    case.addCleanup(engine.close)
    case.addCleanup(lambda: controller._close_control_pool2026(engine))
    return engine, controller, session


class RawControlStageMachineTests(unittest.TestCase):
    """Actual held pool/lease/replay joins; family algorithms have separate oracles."""

    @staticmethod
    def event(operation, value=0, **values):
        return {
            "kind": "action",
            "request": {"operation": operation, **values},
            "result": {"type": "int", "value": value},
            "elapsed_ms": max(1, values.get("milliseconds", 1)),
        }

    def fixture(
        self,
        *,
        operation="prepare",
        contact="SIL",
        kind="1",
        selector="",
        versions="0\n0\n0\n0",
        events=(),
        gateway="",
        alternate="",
        getter="TCUWSilCIDGetter.dll",
        cpus=1,
        paired=False,
        dependencies=(),
        diag_id=None,
        bind_frontend=False,
        bind_persistence=False,
        bind_file_sources=False,
        writer="TCUWSilFlashWriter.dll",
        preparer="TCUWSilPrepareWriter.dll",
        parameter_values=None,
    ):
        from pathlib import Path

        from tests.private_evidence import read_private_bytes
        from tests.test_calibration_2026 import cuw
        from tests.test_cuw_engine_worker import encoded_table

        modern = contact in ("P5-Unified", "Phase6", "Ethernet")
        keys = (
            (
                kind
                + contact
                + ("02" if contact == "Phase6" and diag_id is not None else ""),
                *(
                    (kind + contact,)
                    if contact == "Phase6" and diag_id is not None
                    else ()
                ),
            )
            if modern
            else tuple(kind + contact + str(i + 1) for i in range(cpus))
        )
        names = (preparer, writer, getter)
        parameter_values = parameter_values or {}
        headers = (
            "ParamFileKeySystemProtocolMicon",
            "DLLFileNameForPrepareWrite",
            "DLLFileNameForFlashWrite",
            "DLLFileNameForGetCID",
            "DLLFileNameForChangeToReprogGatewayMode",
            "EnableDLLVersionInformation",
            "GetCANIDFunctionNameForFlashWrite",
            "AlternateDLLFileNamesForGetCID",
            "EnableAlternateDLLVersionsInformationForGetCID",
            *parameter_values,
        )
        catalog = {
            key + ".ini": encoded_table(
                headers,
                (
                    (
                        key,
                        *names,
                        gateway,
                        versions,
                        selector,
                        alternate,
                        "0",
                        *parameter_values.values(),
                    ),
                ),
            )
            for key in keys
        }
        catalog["Parameter.ini"] = encoded_table(
            (
                "ParamFileKeySystemProtocolMicon",
                "M16CTypeFlag",
                "FlagToChangeToReprogGWModeForCentralGW",
                "FORESTTypeFlag",
                "PasswordAddress",
                "ByteOrder",
                "FlagToDoIGOFFONAtCPUTypeChange",
                "WaitTimeForIGOFFON",
                "WaitTimeAfterBatteryDisconnected",
                "WaitTimeAfterBatteryConnected",
                "BatteryVoltageUpperThreshold",
                "FlagToChangeProtocolAtSuccessGetCID",
            ),
            tuple(
                (
                    key,
                    "0",
                    "0",
                    "0",
                    "00",
                    "1",
                    "0",
                    "0",
                    "0",
                    "0",
                    "0",
                    "0",
                )
                for key in keys
            ),
        )
        if modern:
            node_fields = (
                f"DiagID={diag_id}\nProtocol=02\nWakeUpTimeAfterReset=0\n"
                if contact == "Phase6" and diag_id is not None
                else ""
            )
            text = (
                f"[Format]\nVersion=105\n[Vehicle]\nKindOfECU={kind}\nContactType="
                + contact
                + f"\nNumberOfNode=1\n[Node01]\nRequiredSpecReproVer=02\n{node_fields}NumberOfCalibration={cpus}\n"
            )
        else:
            text = (
                f"[Format]\nVersion={8 if cpus > 1 else 6}\n[Vehicle]\nKindOfECU=1\nContactType="
                + contact
                + f"\nNumberOfCalibration={cpus}\n"
            )
        for i in range(cpus):
            text += f"[CPU{(11 if modern else 1) + i:02}]\nCPUType={i + 1}\nCPUImageName=image{i}.vbf\n"
        source = cuw(text, tuple(f"DATA{i}".encode() for i in range(cpus)))
        if bind_frontend:
            from tests.test_programming_replay import authored_classic_can40_inputs

            _source, frontend_sources, _payloads = authored_classic_can40_inputs()
            for name in ("CanIDTable.ini", "LogicalAddressTable.ini"):
                catalog[name] = frontend_sources[name]
            if contact == "Phase6" and diag_id is not None:
                catalog["CanIDTable.ini"] = encoded_table(
                    ("RequestCANID", "CalibrationType"), ((diag_id, "17"),)
                )
        images = Path("runtime/no-car-21/recovered")
        return make_raw_control_fixture2026(
            self,
            source=source,
            catalog=catalog,
            module_files={
                name: read_private_bytes(images / name)
                for name in {*names, gateway, alternate, *dependencies}
                if name
            },
            operation=operation,
            paired=paired,
            bind_frontend=bind_frontend,
            bind_persistence=bind_persistence,
            bind_file_sources=bind_file_sources,
            events=(
                self.event("get_local_milliseconds_of_day", 1000),
                *events,
                self.event("get_local_milliseconds_of_day", 2000),
            ),
        )

    def test_classic_prepare_gateway_empty_write_share_one_execute_and_cursor(self):
        from unittest.mock import patch

        from scripts.programming_replay import ProgrammingReplay

        events = (
            self.event("wait", milliseconds=11),
            self.event("set_communication_log_mode", mode=2),
            self.event("wait", milliseconds=22),
            self.event("set_communication_log_mode", mode=0),
        )
        engine, control, session = self.fixture(events=events)
        exports, runtimes, positions = ([], [], [])

        def runner(stage, *_args):

            def run():
                target = stage._control_target2026
                target.validate(engine, control)
                exports.append(stage._control_export2026)
                runtimes.append(stage._runtime2026)
                positions.append(stage.trace.position)
                stage._runtime2026.call(
                    "wait", milliseconds=11 if stage.operation == "prepare" else 22
                )
                return {"native_return": True}

            return run

        with (
            patch.object(ProgrammingReplay, "_runner", runner),
            engine.controller_execution(control, 1),
        ):
            context = control.native_control_context2026(engine)
            result = control.execute(engine, session)
            self.assertTrue(result["native_return"])
            self.assertEqual(context.cpu_index, 1)
            self.assertEqual(engine.comm_phase, 2)
            self.assertEqual(len(result["exports"]), 2)
            self.assertIsNone(control._native_control_helper_entry2026)
        self.assertEqual(exports, ["StartPrepareWrite", "StartFlashWrite"])
        self.assertEqual(runtimes, [control.runtime, control.runtime])
        self.assertEqual(positions, [1, 3])
        self.assertEqual(session.trace.position, len(session.trace.rows))
        self.assertTrue(session.used)

    def test_primary_getter_vector_does_not_determine_raw_out_byte(self):
        from unittest.mock import patch

        from scripts.programming_2026_common import (
            _control_getter_return_al2026,
            _control_getter_return_values2026,
        )
        from scripts.programming_replay import ProgrammingReplay

        for out in (False, True):
            with self.subTest(out=out):
                engine, control, session = self.fixture(operation="get_cid")
                from scripts.programming_2026_common import (
                    _control_getter_output2026,
                )

                with (
                    patch.object(
                        ProgrammingReplay,
                        "_runner",
                        return_value=lambda out=out: {
                            "native_success": out,
                            "native_return": None,
                            "identifiers": (b"CID",),
                        },
                    ),
                    engine.controller_execution(control, 0),
                ):
                    result = control.execute(engine, session)
                    context = control.native_control_context2026(engine)
                    self.assertIs(result["native_return"], out)
                    self.assertIs(_control_getter_return_al2026(context), out)
                    self.assertEqual(
                        _control_getter_return_values2026(context), (b"CID",)
                    )
                    self.assertIsNone(_control_getter_output2026(context))
                    self.assertEqual(engine.received_identifiers, ())

    def test_getter_attempt_and_return_hooks_preserve_actual_order(self):
        from unittest.mock import patch

        from scripts.programming_2026_common import (
            _record_control_getter_family_attempt2026,
            _record_control_getter_family_return2026,
        )
        from scripts.programming_replay import ProgrammingReplay

        engine, control, session = self.fixture(
            operation="get_cid", alternate="TCUWP5CanCIDGetter.dll"
        )

        def runner(stage, *_args):
            alternate = stage._control_target2026.binding.alternate_cid
            return lambda: {
                "native_return": None,
                "bool_out": bool(alternate),
                "native_success": not bool(alternate),
                "cids": (b"ALT",) if alternate else (),
            }

        with (
            patch.object(ProgrammingReplay, "_runner", runner),
            patch(
                "scripts.programming_2026_common._record_control_getter_family_attempt2026",
                wraps=_record_control_getter_family_attempt2026,
            ) as attempts,
            patch(
                "scripts.programming_2026_common._record_control_getter_family_return2026",
                wraps=_record_control_getter_family_return2026,
            ) as returns,
            engine.controller_execution(control, 0),
        ):
            control.execute(engine, session)

        attempted_targets = tuple(call.args[0] for call in attempts.call_args_list)
        returned_targets = tuple(call.args[0] for call in returns.call_args_list)
        self.assertEqual(len(attempted_targets), 2)
        self.assertEqual(len(returned_targets), 2)
        self.assertTrue(
            all(
                started is returned
                for started, returned in zip(attempted_targets, returned_targets)
            )
        )

    def test_caught_alternate_cpass_keeps_raw_getter_but_withholds_typed_output(self):
        from unittest.mock import patch

        from scripts.programming_2026_common import (
            NativePassThruException2026,
            _control_getter_output2026,
        )
        from scripts.programming_replay import ProgrammingReplay

        engine, control, session = self.fixture(
            operation="get_cid", alternate="TCUWP5CanCIDGetter.dll"
        )

        def runner(stage, *_args):
            if stage._control_target2026.binding.alternate_cid:
                return lambda: (_ for _ in ()).throw(
                    NativePassThruException2026(77, "authored-alternate", 1)
                )
            return lambda: {
                "native_return": None,
                "native_success": False,
                "cids": (),
            }

        with (
            patch.object(ProgrammingReplay, "_runner", runner),
            engine.controller_execution(control, 0),
        ):
            result = control.execute(engine, session)
            context = control.native_control_context2026(engine)
            self.assertFalse(result["native_return"])
            self.assertEqual(result["identifiers"], ())
            self.assertIsNone(_control_getter_output2026(context))

    def test_authenticated_cancid_module_issues_complete_typed_snapshot(self):
        from scripts.programming_2026_common import _control_getter_output2026

        payloads = (
            b"\x49\0\x10\0\0\0",
            b"\x49\x04\x01" + b"DEMO\0".ljust(16, b" "),
        )
        operations = (
            ("connect", None, {"protocol": 6}),
            ("set_timeout", None, {"milliseconds": 123}),
            (
                "start_flow_control_filter",
                7,
                {
                    "request_address": b"\0\0\x01\0",
                    "response_address": b"\0\0\x01\x08",
                },
            ),
            ("get_timeout", 123, {}),
            (
                "write_messages",
                1,
                {"protocol": 6, "tx_flags": 0, "data": b"\0\0\x01\0\x09\0", "count": 1},
            ),
            ("wait", None, {"milliseconds": 0}),
            (
                "read_specified_can_message",
                b"\0\0\x01\x08" + payloads[0],
                {"address": b"\0\0\x01\x08", "count": 1, "frame": 2},
            ),
            ("set_timeout", None, {"milliseconds": 123}),
            ("set_timeout", None, {"milliseconds": 123}),
            ("stop_filter", None, {"identifier": 7}),
            (
                "start_flow_control_filter",
                7,
                {
                    "request_address": b"\0\0\x01\0",
                    "response_address": b"\0\0\x01\x08",
                },
            ),
            ("get_timeout", 123, {}),
            (
                "write_messages",
                1,
                {
                    "protocol": 6,
                    "tx_flags": 0,
                    "data": b"\0\0\x01\0\x09\x04",
                    "count": 1,
                },
            ),
            ("wait", None, {"milliseconds": 0}),
            (
                "read_specified_can_message",
                b"\0\0\x01\x08" + payloads[1],
                {"address": b"\0\0\x01\x08", "count": 1, "frame": 2},
            ),
            ("set_timeout", None, {"milliseconds": 123}),
            ("set_timeout", None, {"milliseconds": 123}),
            ("stop_filter", None, {"identifier": 7}),
            ("disconnect", None, {}),
        )

        def trace_event(operation, value, values):
            def encode(item):
                if type(item) is bytes:
                    return {"type": "bytes", "value": item.hex()}
                if type(item) is dict:
                    return {key: encode(nested) for key, nested in item.items()}
                if type(item) in (tuple, list):
                    return [encode(nested) for nested in item]
                return item

            if type(value) is bytes:
                result = {"type": "bytes", "value": value.hex()}
            elif value is None:
                result = {"type": "none", "value": None}
            else:
                result = {"type": "int", "value": value}
            return {
                "kind": "action",
                "request": encode({"operation": operation, **values}),
                "result": result,
                "elapsed_ms": 1,
            }

        events = tuple(trace_event(*item) for item in operations)
        engine, control, session = self.fixture(
            operation="get_cid",
            getter="TCUWCanCIDGetter.dll",
            selector="GetCanIDsFromParamForGetCID",
            parameter_values={
                "GetCANIDFunctionNameForGetCID": "GetCanIDsFromParamForGetCID",
                "CanIDForGetCID": "0100/0108",
                "ReceiveTimeoutBeforeGetCID": "123",
            },
            events=events,
        )
        with engine.controller_execution(control, 0):
            result = control.execute(engine, session)
            context = control.native_control_context2026(engine)
            output = _control_getter_output2026(context)
            self.assertIsNotNone(output)
            assert output is not None
            self.assertEqual(result["identifiers"], (b"DEMO",))
            self.assertEqual(output.identifiers, (b"DEMO",))
            self.assertIs(output.context, context)
            self.assertIs(output.capture, context._capture)
            self.assertIs(output.configuration, context._capture.configuration)
            self.assertEqual(output.getter_mode, 0)
            self.assertTrue(output.raw_al)
            self.assertEqual(len(output.getter_targets), 1)
            self.assertEqual(
                output.getter_targets[0].module_binding.module_name,
                "TCUWCanCIDGetter.dll",
            )
            self.assertEqual(
                output.query_records34, tuple(engine._working_identifier_records)
            )
            self.assertEqual(len(output.query_records34), 34)
            self.assertTrue(all(len(record) == 12 for record in output.query_records34))
            self.assertEqual(len(output.communication_addresses), 1)
            self.assertEqual(
                output.communication_addresses, tuple(control.address_history)
            )
            self.assertEqual(output.hardware, b"")
            self.assertEqual(
                output.retained_bytes_9dc, b"\0" * output.configuration.cpu_maximum
            )
            self.assertEqual(
                tuple(map(len, output.node_strings_9c8)),
                (13,) * output.configuration.cpu_maximum,
            )
            self.assertEqual(
                tuple(map(len, output.node_strings_9cc)),
                (257,) * output.configuration.cpu_maximum,
            )
            self.assertEqual(
                len(output.node_cells_9e0), output.configuration.cpu_maximum
            )
            self.assertTrue(
                all(cells == (b"\0" * 14,) * 32 for cells in output.node_cells_9e0)
            )
            self.assertEqual(
                output.node_dwords_a10, (0,) * output.configuration.cpu_maximum
            )
            self.assertEqual(output.tail_a14, b"\0" * 21)
            self.assertEqual(
                output.configured_bytes_9d8,
                bytes(context._capture.configured_bits),
            )
        with self.assertRaises(ValueError):
            _control_getter_output2026(context)

    def test_post_prepare_cpass_retains_saved_true_and_native_outputs(self):
        from unittest.mock import patch

        from scripts.programming_2026_common import NativePassThruException2026
        from scripts.programming_replay import ProgrammingReplay

        engine, control, session = self.fixture()
        error = NativePassThruException2026(77, "source-test", 1)
        with (
            patch.object(
                ProgrammingReplay,
                "_runner",
                return_value=lambda: {"native_return": True},
            ),
            engine.controller_execution(control, 1),
        ):
            engine.dh_state.record_native_error(6, 12, 34)
            with patch.object(
                engine.worker, "finish_classic_prepare", side_effect=error
            ):
                result = control.execute(engine, session)
            self.assertTrue(result["native_return"])
            self.assertTrue(engine.worker.control_state.fatal)
            self.assertTrue(engine.worker.control_state.native_fatal_input)
            self.assertEqual(engine.dh_state.primary_error, 77)
            self.assertEqual(engine.dh_state.error_kind, 6)
            self.assertEqual(engine.dh_state.passthru_error, 34)
            self.assertFalse(engine.worker.control_state.failed)
            self.assertEqual(len(result["exports"]), 1)

    def test_host_fault_propagates_without_ordinary_return_or_second_stage(self):
        from unittest.mock import patch

        from scripts.programming_replay import ProgrammingReplay

        engine, control, session = self.fixture()
        error = RuntimeError("host primitive fault")
        with (
            patch.object(
                ProgrammingReplay,
                "_runner",
                return_value=lambda: (_ for _ in ()).throw(error),
            ),
            self.assertRaises(RuntimeError) as caught,
            engine.controller_execution(control, 1),
            patch(
                "scripts.programming_2026_common._record_control_return2026"
            ) as ordinary,
        ):
            try:
                control.execute(engine, session)
            finally:
                ordinary.assert_not_called()
                self.assertIsNone(control._native_control_raw_execution2026)
                self.assertIsNone(control._native_control_helper_entry2026)
        self.assertIs(caught.exception, error)
        self.assertFalse(session.used)

    def test_modern_address_false_is_b9c_and_does_not_call_family(self):
        from unittest.mock import patch

        from scripts.programming_replay import ProgrammingReplay

        engine, control, session = self.fixture(
            operation="write",
            contact="P5-Unified",
            selector="GetCanIDsFromParamForGetCID",
        )
        with (
            patch.object(ProgrammingReplay, "_runner") as runner,
            engine.controller_execution(control, 2),
        ):
            result = control.execute(engine, session)
            self.assertFalse(result["native_return"])
            self.assertEqual(engine.dh_state.primary_error, 9999)
            self.assertTrue(engine.worker.control_state.fatal)
            runner.assert_not_called()

    def test_classic_null_callback_does_not_gain_frontend_table_authority(self):
        from unittest.mock import patch

        from scripts.programming_replay import ProgrammingReplay

        engine, control, session = self.fixture(
            operation="write", selector="GetCanIDsFromCANIDTable"
        )
        with (
            patch.object(ProgrammingReplay, "_runner") as runner,
            engine.controller_execution(control, 2),
        ):
            result = control.execute(engine, session)
            self.assertFalse(result["native_return"])
            self.assertEqual(engine.dh_state.primary_error, 9999)
            runner.assert_not_called()

    def test_modern_two_cpu_rows_consume_distinct_archives_and_one_entry_module(self):
        from unittest.mock import patch

        from scripts.calibration_2026 import (
            native2026_archive,
            native2026_global_cpu_index,
        )
        from scripts.programming_replay import ProgrammingReplay

        engine, control, session = self.fixture(
            operation="write", contact="P5-Unified", cpus=2
        )
        consumed, modules = [], []

        def runner(stage, selection, *_args):
            def run():
                consumed.append(
                    (
                        native2026_global_cpu_index(selection.metadata),
                        native2026_archive(selection.metadata).data,
                    )
                )
                modules.append(stage._control_target2026.module_binding)
                return {"native_return": True}

            return run

        with (
            patch.object(ProgrammingReplay, "_runner", runner),
            engine.controller_execution(control, 2),
        ):
            context = control.native_control_context2026(engine)
            result = control.execute(engine, session)
            self.assertTrue(result["native_return"])
            self.assertEqual(context.cpu_index, 2)
            self.assertEqual(consumed, [(0, b"DATA0"), (1, b"DATA1")])
            self.assertIs(modules[0], modules[1])

    def test_nonempty_gateway_out_flag_controls_same_execute_transition(self):
        from unittest.mock import patch

        from scripts.programming_replay import ProgrammingReplay

        for flag, result_byte in ((False, False), (True, True)):
            with self.subTest(flag=flag):
                events = (
                    self.event("set_communication_log_mode", mode=2),
                    self.event("set_communication_log_mode", mode=0),
                )
                engine, control, session = self.fixture(
                    gateway="TCUWP4CanBodyPrepareWriter.dll", events=events
                )
                exports = []

                def runner(
                    stage, *_args, flag=flag, result_byte=result_byte, exports=exports
                ):
                    def run():
                        exports.append(stage._control_export2026)
                        if stage.operation == "change_gateway":
                            return {
                                "native_return": result_byte,
                                "gateway_mode_changed": flag,
                            }
                        return {"native_return": True}

                    return run

                with (
                    patch.object(ProgrammingReplay, "_runner", runner),
                    engine.controller_execution(control, 1),
                ):
                    result = control.execute(engine, session)
                    self.assertTrue(result["native_return"])
                    self.assertEqual(engine.comm_phase, 2)
                    self.assertEqual(
                        exports,
                        [
                            "StartPrepareWrite",
                            "ChangeToReprogGatewayMode",
                            "StartFlashWrite",
                        ],
                    )

    def test_alternate_getter_reuses_loaded_slot_and_overwrites_actual_out_byte(self):
        from unittest.mock import patch

        from scripts.programming_replay import ProgrammingReplay

        engine, control, session = self.fixture(
            operation="get_cid", alternate="TCUWP5CanCIDGetter.dll"
        )
        slots = []

        def runner(stage, *_args):
            slots.append(stage._control_target2026.entry_slot)
            if stage._control_target2026.binding.alternate_cid:
                self.assertIsNone(session._phase6_getter_import2026)
                return lambda: {
                    "native_return": None,
                    "bool_out": False,
                    "cids": (b"ALT",),
                }

            def primary():
                # Model a valid empty P6 receipt before the native alternate
                # attempt; the next issued getter stage must discard it.
                session._phase6_getter_import2026 = type(
                    "EmptyP6Receipt", (), {"identifiers": ()}
                )()
                return {
                    "native_return": None,
                    "native_success": True,
                    "cids": (),
                }

            return primary

        with (
            patch.object(ProgrammingReplay, "_runner", runner),
            engine.controller_execution(control, 0),
        ):
            result = control.execute(engine, session)
            self.assertFalse(result["native_return"])
            self.assertEqual(result["identifiers"], (b"ALT",))
            self.assertIsNone(session._phase6_getter_import2026)
            self.assertTrue(control.alternate_cid_used)
            self.assertIs(slots[0], slots[1])
            self.assertTrue(engine.native_control_alternate_cache2026)

    def test_issued_phase6_getter_imports_counted_records_before_selection(self):
        from unittest.mock import patch

        from scripts import programming_2026_p6

        engine, control, session = self.fixture(
            operation="get_cid",
            contact="Phase6",
            kind="149",
            getter="TCUWP6CanCIDGetter.dll",
            paired=True,
            dependencies=("TCUWControlCommPhase.dll",),
            diag_id="12",
            bind_frontend=True,
            bind_persistence=True,
            bind_file_sources=True,
        )
        session.context["observations"]["host"]["native2026"] = {
            "programming_started_at": 0.0,
            "initial_delay_seconds": 0,
            "unresolved_retry_seconds": 0,
            "check_dtcs": False,
        }
        session.bind_engine2026(engine)
        session.bind_controller2026(control)
        session.bind_runtime2026(control.runtime)
        job = engine.bind_thread_job(control)
        worker = job.worker
        pair = engine.interface_pair
        assert pair is not None
        expected_records = (
            b"\0" * 4 + b"12" + b"\0" * 6,
            b"\0" * 4 + b"12" + b"\0" * 6,
        )
        original_import = worker.import_control_getter_return2026

        def checked_outer_import(context):
            receipt = worker._control_return_receipt2026[4]
            initial_ids = engine.received_identifiers
            initial_records = engine.identifier_records
            initial_pair_issued = dict(pair._issued)
            self.assertIsNone(pair._importing)
            with patch.object(pair, "import_into", wraps=pair.import_into) as imports:
                sequence = receipt.sequence
                receipt.sequence = sequence + 1
                try:
                    with self.assertRaises(ValueError):
                        original_import(context)
                finally:
                    receipt.sequence = sequence

                owner = receipt.job
                receipt.job = object()
                try:
                    with self.assertRaises(ValueError):
                        original_import(context)
                finally:
                    receipt.job = owner

                records = receipt.records
                receipt.records = (b"invalid",) * len(receipt.identifiers)
                try:
                    with self.assertRaises(ValueError):
                        original_import(context)
                finally:
                    receipt.records = records

                self.assertEqual(imports.call_count, 0)
                self.assertEqual(engine.received_identifiers, initial_ids)
                self.assertEqual(engine.identifier_records, initial_records)
                self.assertEqual(dict(pair._issued), initial_pair_issued)
                self.assertIsNone(pair._importing)
                original_import(context)
                self.assertEqual(imports.call_count, 1)

        with (
            patch.object(
                programming_2026_p6,
                "get_phase6_cids",
                return_value=({"cids": ("CID-A", "CID-B")},),
            ),
            patch.object(
                worker,
                "import_control_getter_return2026",
                side_effect=checked_outer_import,
            ),
        ):
            sequence = job.start(session)
            report = job.result(15, sequence=sequence)

        self.assertTrue(engine._wait_active_admission2026)
        self.assertEqual(engine.received_identifiers, (b"CID-A", b"CID-B"))
        self.assertEqual(engine.identifier_records, expected_records)
        self.assertEqual(report["identifiers"], (b"CID-A", b"CID-B"))
        self.assertTrue(report["native_return"])
        self.assertIsNone(session._phase6_getter_import2026)

    def test_ordinary_getter_exports_snapshot_and_only_outer_getter_imports(self):
        from unittest.mock import patch

        from scripts.programming_2026_common import (
            _control_has_ordinary_getter_return2026,
        )
        from scripts.programming_replay import ProgrammingReplay

        engine, control, session = self.fixture(operation="get_cid", paired=True)
        with (
            patch.object(
                ProgrammingReplay,
                "_runner",
                return_value=lambda: {
                    "native_success": True,
                    "identifiers": (b"second", b"first", b"second"),
                },
            ),
            engine.controller_execution(control, 0),
        ):
            context = control.native_control_context2026(engine)
            self.assertFalse(_control_has_ordinary_getter_return2026(context))
            pair = engine.interface_pair
            assert pair is not None
            with patch.object(pair, "import_into", wraps=pair.import_into) as imports:
                result = control.execute(engine, session)
                self.assertTrue(_control_has_ordinary_getter_return2026(context))
                self.assertIsNotNone(result["control_snapshot"])
                self.assertEqual(
                    [call.args[0] for call in imports.call_args_list], [pair.control]
                )
                self.assertEqual(engine.received_identifiers, ())
                engine.worker.import_control_getter_return2026(context)
                self.assertEqual(
                    [call.args[0] for call in imports.call_args_list],
                    [pair.control, pair.engine],
                )
                self.assertEqual(
                    engine.received_identifiers, (b"second", b"first", b"second")
                )
                with self.assertRaises(ValueError):
                    engine.worker.import_control_getter_return2026(context)

    def test_actual_p5_getter_partial_vector_and_param7_share_raw_execute(self):
        from pathlib import Path

        from scripts.programming import NativeTransportError
        from scripts.programming_2026_p5_getters import run_native_context
        from scripts.programming_replay import _native_request
        from tests.private_evidence import read_private_bytes
        from tests.test_calibration_2026 import cuw
        from tests.test_cuw_engine_worker import encoded_table
        from tests.test_programming_2026_p5_getters import (
            P5,
            fixture,
            p5,
            primitive_runtime,
        )

        for code, expected in ((9, True), (16, False)):
            with self.subTest(code=code):
                native, container, binding = fixture(
                    P5, "0100/0108\n0200/0208", allow="0200" if expected else ""
                )
                provider, _events = primitive_runtime(
                    (p5(b"ONE"), NativeTransportError(code))
                )
                rows = []

                def capture(event, remaining, provider=provider, rows=rows):
                    try:
                        value = provider.action(event, remaining)
                    except NativeTransportError as error:
                        result = {
                            "type": "error",
                            "value": {"domain": "native", "code": error.code},
                        }
                        rows.append(
                            {
                                "kind": "action",
                                "request": _native_request(event),
                                "result": result,
                                "elapsed_ms": 1,
                            }
                        )
                        raise
                    kind = (
                        "none"
                        if value is None
                        else "bytes"
                        if type(value) is bytes
                        else "bool"
                        if type(value) is bool
                        else "int"
                    )
                    result = {
                        "type": kind,
                        "value": value.hex() if type(value) is bytes else value,
                    }
                    rows.append(
                        {
                            "kind": "action",
                            "request": _native_request(event),
                            "result": result,
                            "elapsed_ms": max(1, event.get("milliseconds", 1)),
                        }
                    )
                    return value

                direct = run_native_context(
                    native, NativeRuntime2026(capture, native_cancelled=lambda: False)
                )
                self.assertIs(direct["bool_out"], expected)
                self.assertEqual(direct["cids"], (b"ONE",))
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
                    tuple(
                        ("8P5" + cpu, "0", "0", "0", "00", "1") for cpu in ("A", "B")
                    ),
                )
                source = cuw(
                    container.attached.data.decode("ascii"),
                    tuple(record.data for record in container.records),
                )
                engine, control, session = make_raw_control_fixture2026(
                    self,
                    source=source,
                    catalog=catalog,
                    module_files={
                        P5: read_private_bytes(Path("runtime/no-car-21/recovered") / P5)
                    },
                    operation="get_cid",
                    events=(
                        self.event("get_local_milliseconds_of_day", 1000),
                        *rows,
                        self.event("get_local_milliseconds_of_day", 2000),
                    ),
                )
                with engine.controller_execution(control, 0):
                    result = control.execute(engine, session)
                    self.assertIs(result["native_return"], expected)
                    self.assertEqual(result["identifiers"], (b"ONE",))
                    self.assertEqual(result["exports"][0]["query_ids"], (b"\x01\0",))
                self.assertEqual(session.trace.position, len(session.trace.rows))

    def test_accepted_prepare_retry_clears_only_primary_status_and_preserves_failed(
        self,
    ):
        from unittest.mock import patch

        from scripts.programming_replay import ProgrammingReplay

        engine, control, session = self.fixture(
            operation="write",
            writer="TCUWCanSBRFlashWriter.dll",
            parameter_values={"IGOffRetriableFlag": "1", "PrepareRetryFlag": "1"},
            events=(
                self.event("set_communication_log_mode", mode=2),
                self.event("set_communication_log_mode", mode=1),
            ),
        )
        observed = []

        def runner(stage, *_args):
            def run():
                if stage.operation == "write":
                    engine.dh_state.record_native_error(6, 77, 88)
                    engine.worker._failed = True
                    engine._write_complete_output = True
                    return {"native_return": False}
                observed.append(
                    (stage._control_export2026, engine.worker.control_state.failed)
                )
                return {"native_return": True}

            return run

        with (
            patch.object(ProgrammingReplay, "_runner", runner),
            engine.controller_execution(control, 2),
            patch.object(control, "query_control_error"),
        ):
            result = control.execute(engine, session)
            state = engine.worker.control_state
            self.assertFalse(result["native_return"])
            self.assertEqual(observed, [("PrepareRetry", True)])
            self.assertEqual(
                (state.error_kind, state.primary_error, state.passthru_error), (6, 0, 0)
            )
            self.assertTrue(state.failed)
            self.assertTrue(state.native_context_964)
            self.assertFalse(state.fatal)

    def test_confirmation_tail_clears_failed_but_preserves_original_export_bool(self):
        from unittest.mock import patch

        from scripts.programming_replay import ProgrammingReplay

        events = (
            self.event("set_communication_log_mode", mode=2),
            self.event("set_communication_log_mode", mode=1),
            self.event("wait", milliseconds=5000),
        )
        engine, control, session = self.fixture(
            operation="write",
            writer="TCUWP4CanAirbagFlashWriter.dll",
            parameter_values={
                "IGOffRetriableFlag": "1",
                "ConfirmAfterEndOfFlashingFlag": "1",
            },
            events=events,
        )

        def runner(stage, *_args):
            def run():
                if stage.operation == "write":
                    engine.dh_state.record_native_error(6, 77, 88)
                    engine.dh_state.set_flashing_ended(True)
                    engine.worker._failed = True
                    engine._write_complete_output = True
                    return {"native_return": False}
                return {"native_return": True}

            return run

        with (
            patch.object(ProgrammingReplay, "_runner", runner),
            engine.controller_execution(control, 2),
            patch.object(control, "query_control_error"),
        ):
            result = control.execute(engine, session)
            self.assertTrue(result["native_return"])
            self.assertEqual(
                [row["native_return"] for row in result["exports"]], [False, True]
            )
            self.assertFalse(engine.worker.control_state.failed)
            self.assertEqual(
                (engine.dh_state.primary_error, engine.dh_state.passthru_error),
                (77, 88),
            )
            self.assertEqual(control.native_control_context2026(engine).cpu_index, 0)

    def test_phase6_void_retry_keeps_exact_loaded_module_and_primary_bool(self):
        from unittest.mock import patch

        from scripts.programming_replay import ProgrammingReplay

        for operation in ("prepare", "write"):
            with self.subTest(operation=operation):
                engine, control, session = self.fixture(
                    operation=operation,
                    contact="Phase6",
                    writer="TCUWP6CanReprostdFlashWriter.dll",
                    preparer="TCUWP6CanReprostdPrepareWriter.dll",
                    parameter_values={"IGOffRetriableFlag": "1"},
                )
                observed = []

                def runner(stage, selection, *_args, observed=observed, engine=engine):
                    def run():
                        observed.append(
                            (
                                stage._control_export2026,
                                stage._control_target2026.module_binding,
                                selection,
                            )
                        )
                        engine.worker._failed = True
                        engine._write_complete_output = True
                        return {
                            "native_return": None
                            if stage._control_export2026
                            == "ProcessBeforeIGOffOnAtRetry"
                            else False
                        }

                    return run

                with (
                    patch.object(ProgrammingReplay, "_runner", runner),
                    engine.controller_execution(
                        control, 1 if operation == "prepare" else 2
                    ),
                    patch.object(control, "query_control_error"),
                ):
                    result = control.execute(engine, session)
                    self.assertFalse(result["native_return"])
                    self.assertEqual(observed[-1][0], "ProcessBeforeIGOffOnAtRetry")
                    self.assertIs(observed[0][1], observed[1][1])
                    self.assertIs(observed[0][2], observed[1][2])
                    self.assertEqual(
                        control.native_control_context2026(engine).cpu_index, 0
                    )

    def test_final_dh_catch_is_limited_to_actual_virtual_call_native_fault(self):
        from pathlib import Path
        from unittest.mock import patch

        from scripts.programming_2026_common import (
            NativeException2026,
            NativeSecurityComposer2026,
        )
        from scripts.programming_2026_dh import DHGateway2026
        from scripts.programming_replay import ProgrammingReplay
        from tests.private_evidence import read_private_bytes

        for error in (NativeException2026("native"), RuntimeError("host")):
            with self.subTest(error=type(error).__name__):
                events = (
                    self.event("set_communication_log_mode", mode=2),
                    self.event("set_communication_log_mode", mode=0),
                )
                engine, control, session = self.fixture(
                    events=events, dependencies=("TCUWDHUtils.dll",)
                )
                images = Path("runtime/no-car-21/recovered")
                control.runtime.bind_security_composer(
                    NativeSecurityComposer2026.from_native_modules(
                        read_private_bytes(images / "SecretInfo.dll"),
                        read_private_bytes(images / "CUW.dll"),
                    )
                )
                control.dh_mode_could_be_changed = True
                with (
                    patch.object(
                        ProgrammingReplay,
                        "_runner",
                        return_value=lambda: {"native_return": True},
                    ),
                    patch.object(
                        DHGateway2026, "end_reprogramming_mode", side_effect=error
                    ) as tail,
                ):
                    if isinstance(error, RuntimeError):
                        with (
                            self.assertRaises(RuntimeError) as caught,
                            engine.controller_execution(control, 1),
                            patch(
                                "scripts.programming_2026_common._record_control_return2026"
                            ) as ordinary,
                        ):
                            try:
                                control.execute(engine, session)
                            finally:
                                ordinary.assert_not_called()
                        self.assertIs(caught.exception, error)
                        self.assertTrue(control.dh_mode_could_be_changed)
                    else:
                        with engine.controller_execution(control, 1):
                            result = control.execute(engine, session)
                            self.assertTrue(result["native_return"])
                            self.assertFalse(control.dh_mode_could_be_changed)
                    tail.assert_called_once_with(0x3FC)

    def test_getter_typed_postreturn_fault_preserves_out_byte_before_vector_copy(self):
        from unittest.mock import patch

        from scripts.programming_2026_common import NativePassThruException2026
        from scripts.programming_replay import ProgrammingReplay

        engine, control, session = self.fixture(operation="get_cid")
        error = NativePassThruException2026(55, "post-return", 1)

        def runner(_stage, *_args):
            def run():
                original = control.runtime.check
                raised = False

                def check():
                    nonlocal raised
                    if not raised:
                        raised = True
                        raise error
                    return original()

                control.runtime.check = check
                return {"native_success": True, "identifiers": (b"NOT-COPIED",)}

            return run

        with (
            patch.object(ProgrammingReplay, "_runner", runner),
            engine.controller_execution(control, 0),
        ):
            result = control.execute(engine, session)
            self.assertTrue(result["native_return"])
            self.assertEqual(result["identifiers"], ())
            self.assertTrue(engine.worker.control_state.fatal)
            self.assertEqual(engine.dh_state.primary_error, 55)

    def test_classic_incremental_preflight_fault_leaves_next_slot_constructor_empty(
        self,
    ):
        from unittest.mock import patch

        from scripts.programming_replay import ProgrammingReplay

        engine, control, session = self.fixture(operation="write", cpus=2, versions="0")
        with (
            patch.object(ProgrammingReplay, "_runner") as runner,
            engine.controller_execution(control, 2),
        ):
            result = control.execute(engine, session)
            self.assertFalse(result["native_return"])
            pool = control._control_parameter_pool2026
            assert pool is not None
            self.assertTrue(pool.slot(0).loaded)
            self.assertFalse(pool.slot(1).loaded)
            self.assertEqual(pool.slot(1).parameter.row_index, 0)
            self.assertTrue(engine.worker.control_state.fatal)
            runner.assert_not_called()

    def test_startup_prelude_retains_real_constructor_array_without_family_dispatch(
        self,
    ):
        from unittest.mock import patch

        engine, control, session = self.fixture(
            parameter_values={"IGOffRetriableFlag": "1"},
            dependencies=(
                "TCUWControlCommPhase.dll",
                "CUW.dll",
                "SecretInfo.dll",
                "TCUWDHUtils.dll",
            ),
        )
        with (
            engine.controller_execution(control, 1),
            patch.object(
                session,
                "selected_identity",
                side_effect=AssertionError("eager family dispatch"),
            ),
        ):
            control.bind_startup_session(engine, session)
            pool = control._control_parameter_pool2026
            assert pool is not None
            self.assertFalse(pool.slot(0).loaded)
            self.assertIsNotNone(control.runtime._security_composer)
            empty = control.empty_control_parameter(engine)
            base = control._control_base_parameter2026(engine)
            self.assertIsNone(base.parameter.boolean("IGOffRetriableFlag"))
            pool.load_for(engine, control, "prepare")
            revision = pool.slot(0).revision
            self.assertTrue(base.parameter.boolean("IGOffRetriableFlag"))
            with self.assertRaises(ValueError):
                empty.validate(engine)
            with self.assertRaises(ValueError):
                control.empty_control_parameter(engine)
            control.bind_startup_session(engine, session)
            self.assertIs(control._control_parameter_pool2026, pool)
            self.assertEqual(pool.slot(0).revision, revision)
            self.assertTrue(base.parameter.boolean("IGOffRetriableFlag"))
        with self.assertRaises(ValueError):
            base.validate(engine)

    def test_combined_3b90_accepted_retry_reaches_confirmation_with_failed_still_true(
        self,
    ):
        """Generic3b90 flow only: known2026 writers have no combined export pair."""
        from unittest.mock import patch

        from scripts.cuw_parameter_pool import ControlParameterPool2026

        engine, control, session = self.fixture(
            operation="write",
            writer="TCUWCanSBRFlashWriter.dll",
            parameter_values={
                "IGOffRetriableFlag": "1",
                "PrepareRetryFlag": "1",
                "ConfirmAfterEndOfFlashingFlag": "1",
            },
            events=(self.event("wait", milliseconds=5000),),
        )
        calls = []

        def auxiliary(_engine, _session, _target, export, _helper, reports):
            calls.append(export)
            if export == "IsFinishReprogramming":
                state = engine.worker.control_state
                self.assertTrue(state.failed)
                self.assertEqual((state.primary_error, state.passthru_error), (0, 0))
                self.assertEqual(state.error_kind, 6)
                self.assertTrue(state.native_context_964)
            report = {"native_return": True}
            reports.append(report)
            return report

        with (
            engine.controller_execution(control, 2),
            patch.object(control, "query_control_error"),
            patch.object(control, "_control_call2026", side_effect=auxiliary),
        ):
            token = control._begin_native_control_raw_execution2026(engine)
            entry = control._begin_native_control_helper_entry2026(
                engine, helper="4c10"
            )
            try:
                session._bind_control_root2026(engine, control, control.runtime)
                pool = ControlParameterPool2026.issue(
                    engine, control, session._catalog_sources
                )
                control._control_parameter_pool2026 = pool
                pool.load_for(engine, control, "write")
                target = control._control_target2026(engine, 0, "write")
                engine.dh_state.record_native_error(6, 77, 88)
                engine.dh_state.set_flashing_ended(True)
                engine.worker._failed = True
                engine._write_complete_output = True
                reports = []
                control._retry_control2026(engine, session, target, "4c10", reports)
                self.assertEqual(calls, ["PrepareRetry", "IsFinishReprogramming"])
                self.assertEqual(len(reports), 2)
                self.assertFalse(engine.worker.control_state.failed)
                self.assertEqual(
                    (engine.dh_state.primary_error, engine.dh_state.passthru_error),
                    (0, 0),
                )
            finally:
                control._end_native_control_helper_entry2026(engine, lease=entry)
                control._end_native_control_raw_execution2026(engine, token)

    def test_actual_raw_combined_flags_reject_missing_finish_export_before_writing(
        self,
    ):
        from unittest.mock import patch

        from scripts.programming_replay import ProgrammingReplay

        engine, control, session = self.fixture(
            operation="write",
            writer="TCUWCanSBRFlashWriter.dll",
            parameter_values={
                "IGOffRetriableFlag": "1",
                "PrepareRetryFlag": "1",
                "ConfirmAfterEndOfFlashingFlag": "1",
            },
        )
        with (
            patch.object(ProgrammingReplay, "_runner") as runner,
            engine.controller_execution(control, 2),
        ):
            faults = []
            publish = engine.worker._record_control_helper_cpass2026

            def record(context, error, lease):
                faults.append(error)
                return publish(context, error, lease)

            with patch.object(
                engine.worker, "_record_control_helper_cpass2026", side_effect=record
            ):
                result = control.execute(engine, session)
            runner.assert_not_called()
            self.assertFalse(result["native_return"])
            self.assertEqual(len(faults), 1)
            self.assertEqual(faults[0].line, 0x2D0)
            self.assertTrue(engine.worker.control_state.fatal)


class RawControlExecuteTests(unittest.TestCase):
    def test_worker_entry_lookup_rejects_context_without_actual_helper_entry(self):
        from scripts.programming_2026_common import _control_helper_entry2026

        engine, controller = NativeControlContextTests.engine_and_controller()
        self.addCleanup(engine.close)
        with engine.controller_execution(controller, 0):
            context = controller.native_control_context2026(engine)
            with self.assertRaisesRegex(ValueError, "No active source-issued"):
                _control_helper_entry2026(context)

    def test_getter_outer_values_require_an_actual_raw_helper_result(self):
        from scripts.programming_2026_common import (
            _control_getter_return_al2026,
            _control_getter_return_values2026,
        )

        engine, controller = NativeControlContextTests.engine_and_controller()
        self.addCleanup(engine.close)
        with engine.controller_execution(controller, 0):
            context = controller.native_control_context2026(engine)
            with self.assertRaisesRegex(
                ValueError, "Actual ordinary CONTROL getter result"
            ):
                _control_getter_return_values2026(context)
            with self.assertRaisesRegex(
                ValueError, "Actual ordinary CONTROL getter return byte"
            ):
                _control_getter_return_al2026(context)

    def test_saved_native_helper_result_requires_its_live_entry_lease(self):
        from scripts.programming_2026_common import (
            _control_saved_family_return2026,
        )

        engine, controller = NativeControlContextTests.engine_and_controller()
        self.addCleanup(engine.close)
        with engine.controller_execution(controller, 0):
            context = controller.native_control_context2026(engine)
            with self.assertRaisesRegex(ValueError, "Active source-issued saved"):
                _control_saved_family_return2026(context, object())


class NativeParameterRowTests(unittest.TestCase):
    def test_multi_value_key_lookup_keeps_selected_row_and_reports_total(self):
        from scripts.programming_2026_common import NativeParameter2026

        parameter = NativeParameter2026.from_csv(
            b'ParamFileKeySystemProtocolMicon,V\r\n1CAN2,"first\nsecond"\r\n'
            b"1CAN3,third\r\n"
        )
        self.assertTrue(parameter.set_keys("1", "3", "CAN"))
        self.assertEqual(
            parameter.parameters_with_keys("V", "1", "2", "CAN", 1),
            (("first",), 2),
        )
        self.assertEqual(
            parameter.parameters_with_keys("V", "1", "2", "CAN", 0), ((), 2)
        )
        self.assertIsNone(parameter.parameters_with_keys("V", "missing", "2", "CAN", 1))
        with self.assertRaises(ValueError):
            parameter.parameters_with_keys("V", "1", "2", "CAN", -1)
        self.assertEqual(parameter.string("V"), "third")

    def test_default_constructor_and_base_delete_preserve_derived_indices(self):
        from scripts.programming_2026_common import NativeParameter2026

        empty = NativeParameter2026()
        self.assertEqual(
            (empty.headers, empty.rows, empty.row_index, empty.key_column),
            ((), (), 0, 0),
        )
        self.assertIsNone(empty.string("Missing"))
        parameter = NativeParameter2026.from_csv(
            b"V,K\r\nvalue,A01B\r\n\xff", key_column="K"
        )
        self.assertTrue(parameter.set_keys("A", "B", "01"))
        self.assertEqual((parameter.row_index, parameter.key_column), (1, 1))
        parameter.delete()
        parameter.delete()
        self.assertEqual((parameter.headers, parameter.rows), ((), ()))
        self.assertEqual((parameter.row_index, parameter.key_column), (1, 1))
        self.assertIsNone(parameter.string("V"))

    def test_native_header_zero_and_search_rows_start_at_one(self):
        from scripts.programming_2026_common import NativeParameter2026

        parameter = NativeParameter2026.from_csv(
            b"K,V\r\nABC,1\r\nAXC,2\r\n", key_column="K"
        )
        self.assertEqual(parameter.row_index, 0)
        self.assertEqual(parameter.string("V"), "V")
        self.assertEqual(parameter.search_row(0, "ABC"), 1)
        self.assertTrue(parameter.set_keys("A", "C", "B"))
        self.assertEqual(parameter.row_index, 1)
        self.assertEqual(parameter.string_with_keys("V", "A", "C", "X"), "2")
        self.assertEqual(parameter.row_index, 1)
        self.assertFalse(parameter.set_keys("missing", "", ""))
        self.assertIsNone(parameter.string("V"))


class NativeCSVScannerTests(unittest.TestCase):
    def test_leading_blank_header_lines_and_eof_ignore_trailing_bytes(self):
        from scripts.programming_2026_common import NativeParameter2026

        parameter = NativeParameter2026.from_csv(
            b"\r\n\r\nK,V\r\nkey,value\r\n\xffignored,after,eof", key_column="K"
        )
        self.assertEqual(parameter.headers, ("K", "V"))
        self.assertEqual(parameter.rows, ((("key",), ("value",)),))

    def test_unquoted_and_quoted_quote_pairs_collapse_once(self):
        from scripts.programming_2026_common import NativeParameter2026

        for field in (b'a""b', b'"a""b"'):
            parameter = NativeParameter2026.from_csv(
                b"K,V\r\nkey," + field + b"\r\n\xff", key_column="K"
            )
            self.assertEqual(parameter.rows[0][1], ('a"b',))
        parameter = NativeParameter2026.from_csv(
            b'K,V\r\nkey,a"b\r\n\xff', key_column="K"
        )
        self.assertEqual(parameter.rows[0][1], ('a"b',))


class DuplicateColumnBindingTests(unittest.TestCase):
    def test_binding_and_alternate_selection_retain_first_duplicate_column(self):
        from scripts.calibration_2026 import parse_cuw_2026
        from scripts.programming_2026_common import bind_parameter2026
        from tests.test_calibration_2026 import cuw

        source = cuw(
            "[Format]\nVersion=6\n[Vehicle]\nKindOfECU=1\nContactType=SIL\nNumberOfCalibration=1\n[CPU01]\nCPUType=1\nCPUImageName=one.vbf\n"
        )
        headers = "ParamFileKeySystemProtocolMicon,DLLFileNameForFlashWrite,DLLFileNameForFlashWrite,AlternateCPUType,AlternateCPUType\r\n"
        sources = {
            "1SIL1.ini": (headers + "1SIL1,First.dll,Last.dll,2,9\r\n").encode(),
            "1SIL2.ini": (
                headers + "1SIL2,FirstAlternate.dll,LastAlternate.dll,,\r\n"
            ).encode(),
        }
        binding = bind_parameter2026(
            parse_cuw_2026(source), sources, "write", encoded=False
        )
        self.assertEqual(binding.module_name, "First.dll")
        self.assertEqual(
            binding.parameter.string("DLLFileNameForFlashWrite"), "First.dll"
        )
        alternate = binding.reselect_alternate_cpu()
        self.assertEqual(alternate.cpu_type, "2")
        self.assertEqual(alternate.module_name, "FirstAlternate.dll")


class NativeErrorDWORDTests(unittest.TestCase):
    def test_signed_native_members_preserve_dword_bits_without_unbounded_wrap(self):
        from scripts.programming_2026_common import (
            NativeJ2534Exception2026,
            NativePassThruException2026,
            native_error_fields2026,
        )

        self.assertEqual(
            native_error_fields2026(NativePassThruException2026(-1, "authored", 1)),
            (0xFFFFFFFF, None),
        )
        self.assertEqual(
            native_error_fields2026(
                NativeJ2534Exception2026(-0x80000000, "authored", 1)
            ),
            (1, 0x80000000),
        )
        error = NativeJ2534Exception2026(9, "authored", 1)
        error.j2534_error = 1 << 40
        with self.assertRaises(TypeError):
            native_error_fields2026(error)


class NativeFaultBoundaryTests(unittest.TestCase):
    def test_host_faults_are_not_native_catch_all_inputs(self):
        from scripts.programming_2026_common import (
            CommonResponseError,
            NativeException2026,
            is_native_exception2026,
        )

        self.assertTrue(
            is_native_exception2026(NativeException2026("authored native fault"))
        )
        self.assertTrue(is_native_exception2026(CommonResponseError(16)))
        for error in (
            OSError("host"),
            ValueError("host"),
            TypeError("host"),
            InterruptedError("host"),
            TimeoutError("host"),
        ):
            self.assertFalse(is_native_exception2026(error))

    def test_native_block_triples_use_strtol_prefix_default(self):
        from scripts.programming_2026_common import NativeBlockInfo, native_block_info

        self.assertEqual(
            native_block_info({"BlockSizeInfo": "+0:1KiB:2"}),
            (NativeBlockInfo(0, 1, 2),),
        )
        self.assertEqual(
            native_block_info({"BlockSizeInfo": "0:abc:2"}), (NativeBlockInfo(0, 0, 2),)
        )
        with self.assertRaises(ValueError):
            native_block_info({"BlockSizeInfo": "0:1"})


class NativeOTAClockAndOwnershipTests(unittest.TestCase):
    def test_ota_uses_native_local_milliseconds_backward_day_wrap(self):
        from scripts.programming_2026_common import Unified2026

        start = bytes.fromhex("18dae01c7101db05")
        busy = bytes.fromhex("18dae01c7103db050003")
        p = PrimitiveReplay((start, busy, start, busy))
        native_times = iter((200000, 200000, 190000))
        runtime = NativeRuntime2026(
            p, clock=lambda: 0, local_milliseconds_of_day=lambda: next(native_times)
        )
        Unified2026(runtime).stop_ota_reprogramming()
        self.assertEqual(
            sum(event["operation"] == "write_messages" for event in p.events), 4
        )
        self.assertEqual(p.events[-1], {"operation": "stop_filter", "identifier": 17})

    def test_ota_protocol_switch_is_owned_before_host_postcheck(self):
        from scripts.programming_2026_common import Unified2026

        cancelled = False
        events = []

        def provider(action, remaining):
            nonlocal cancelled
            events.append(action)
            if action["operation"] == "get_protocol_id":
                return 0x800F
            if action.get("protocol") == 6:
                cancelled = True

        runtime = NativeRuntime2026(provider, cancelled=lambda: cancelled)
        with self.assertRaises(InterruptedError):
            Unified2026(runtime).stop_ota_reprogramming()
        self.assertEqual(
            events,
            [
                {"operation": "get_protocol_id"},
                {"operation": "switch_connection", "protocol": 6},
                {"operation": "switch_connection", "protocol": 0x800F},
            ],
        )
        self.assertFalse(runtime._resources)


class NativePendingClockTests(unittest.TestCase):
    def test_phase5_uses_native_whole_local_seconds_and_hour_rollover(self):
        from scripts.programming_2026_common import CanDiag2026, CommonResponseError

        request, response = bytes.fromhex("00000750"), bytes.fromhex("00000758")
        for values in ((0, 1), (86399, 0), (100, 99)):
            p = PrimitiveReplay((response + bytes.fromhex("7f2278"),))
            native_times = iter(values)
            runtime = NativeRuntime2026(
                p,
                clock=lambda: 0.9,
                local_seconds_of_day=lambda native_times=native_times: next(
                    native_times
                ),
            )
            with self.assertRaises(CommonResponseError):
                CanDiag2026(runtime).call(
                    request, response, b"\x22", b"\x62", phase5=True, pending_limit=1
                )
            self.assertEqual(
                [
                    event["data"]
                    for event in p.events
                    if event["operation"] == "write_messages"
                ],
                [request + b"\x22", request + b"\x3e\x00"],
            )
            self.assertEqual(
                p.events[-1], {"operation": "set_timeout", "milliseconds": 100}
            )


class NativeAESTests(unittest.TestCase):
    def test_nist_one_block_encrypt_decrypt_and_strict_dimensions(self):
        from scripts.programming_2026_common import native_aes128_ecb_block

        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plain = bytes.fromhex("00112233445566778899aabbccddeeff")
        encrypted = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(native_aes128_ecb_block(key, plain), encrypted)
        self.assertEqual(native_aes128_ecb_block(key, encrypted, encrypt=False), plain)
        for invalid in (b"", bytes(15), bytes(17)):
            with self.assertRaises(ValueError):
                native_aes128_ecb_block(invalid, plain)
            with self.assertRaises(ValueError):
                native_aes128_ecb_block(key, invalid)


class NativeCancellationBoundaryTests(unittest.TestCase):
    def test_observer_cannot_mask_host_cancel_or_deadline(self):
        for expired in (False, True):
            now = [0]
            host_cancel = [False]

            def native_cancel(expired=expired, now=now, host_cancel=host_cancel):
                if expired:
                    now[0] = 31
                else:
                    host_cancel[0] = True
                return True

            runtime = NativeRuntime2026(
                lambda *_: None,
                clock=lambda now=now: now[0],
                cancelled=lambda host_cancel=host_cancel: host_cancel[0],
                native_cancelled=native_cancel,
            )
            with self.assertRaises(TimeoutError if expired else InterruptedError):
                runtime.check_native_cancelled()


class ControllerBoundaryTests(unittest.TestCase):
    def test_control_battery_uses_only_control_read_vbatt_unsigned_dword(self):
        from scripts.j2534_2026 import J2534Device2026, PrimitiveResult
        from scripts.programming_2026_common import ControlCommPhase2026

        calls = []
        result: Any = PrimitiveResult(value=0xFFFFFFFF)

        def provider(request, remaining):
            calls.append(request)
            if isinstance(result, BaseException):
                raise result
            return result

        device = J2534Device2026(provider)
        controller = object.__new__(ControlCommPhase2026)
        controller.runtime = NativeRuntime2026(device.primitive)
        self.assertEqual(controller.read_control_battery_voltage(), 4294967.295)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["operation"], "passthru_ioctl")
        self.assertEqual(calls[0]["ioctl"], 3)
        for invalid in (True, -1, 0x100000000, None):
            result = PrimitiveResult(value=invalid)
            with self.assertRaises(ValueError):
                controller.read_control_battery_voltage()
        result = OSError("authored host driver failure")
        with self.assertRaises(OSError) as caught:
            controller.read_control_battery_voltage()
        self.assertIs(caught.exception, result)

    def test_native_cid_history_preserves_order_duplicates_and_prior_assignments(self):
        from scripts.j2534_2026 import NativeCommunicationAddress
        from scripts.programming_2026_common import ControlCommPhase2026

        controller = object.__new__(ControlCommPhase2026)
        controller.address_history = []
        first = NativeCommunicationAddress(b"\x07\xe0", b"\x07\xe8")
        extended = NativeCommunicationAddress(b"\x07\xe0\x12", b"\x07\xe8\x13", True)
        controller.remember_cid_address(first)
        controller.remember_cid_address(extended)
        controller.remember_cid_address(first)
        self.assertEqual(controller.address_history, [first, extended, first])
        with self.assertRaises(TypeError):
            controller.remember_cid_address(first.record())
        self.assertEqual(controller.address_history, [first, extended, first])
        controller.address_history = [first] * 4096
        with self.assertRaises(ValueError):
            controller.remember_cid_address(extended)
        self.assertEqual(len(controller.address_history), 4096)

    def test_bound_export_rejects_opaque_business_callbacks_before_io(self):
        from scripts.programming_2026_common import ControlCommPhase2026

        # Type validation precedes all state/provider use, including on a forged shell.
        controller = object.__new__(ControlCommPhase2026)
        with self.assertRaises(TypeError):
            controller.execute(lambda: True, lambda: {"native_return": True})


class BlockIndexTests(unittest.TestCase):
    def test_source_inclusive_indices_append_and_native_wrap_rejection(self):
        from scripts.programming_2026_common import set_block_ranges

        self.assertEqual(
            set_block_ranges(2, 4, ((8, 10),)), ((8, 10), (3, 3), (4, 4), (5, 5))
        )
        self.assertEqual(set_block_ranges(5, 2, ((8, 10),)), ((8, 10),))
        for first, last in ((0, 65535), (65535, 65535), (-1, 3), (True, 2)):
            with self.assertRaises(ValueError):
                set_block_ranges(first, last)


class RuntimeTests(unittest.TestCase):
    def test_actual_disconnect_retires_child_ownership_without_driver_retry(self):
        from scripts.j2534_2026 import (
            J2534Device2026,
            J2534InterfacePair2026,
            NativeMessage,
        )
        from tests.test_j2534_2026 import Provider

        provider = Provider()
        device = J2534Device2026(provider, background_workers=False)
        peer = J2534Device2026(provider, background_workers=False)
        J2534InterfacePair2026(peer, device)
        device.open()
        device.connect(6)
        runtime = NativeRuntime2026(device.primitive)
        runtime.acquire(
            "start_periodic",
            "stop_periodic",
            message=NativeMessage(6, bytes.fromhex("000007e03e00")),
            interval=100,
        )
        runtime.own("stop_sync_periodic")
        runtime.own("stop_sync_periodic_message")
        runtime.own("logical_disconnect", protocol=0x8203)
        runtime.own("logical_disconnect_udp_discovery")
        runtime.own("disconnect")
        device.disconnect()
        before = len(provider.calls)
        runtime._forget_disconnected_children()
        self.assertEqual(runtime.owned_identifiers("stop_periodic"), ())
        for operation in ("stop_sync_periodic", "stop_sync_periodic_message"):
            self.assertTrue(runtime.owns_resource(operation))
        self.assertFalse(runtime.owns_resource("logical_disconnect_udp_discovery"))
        self.assertFalse(runtime.owns_resource("logical_disconnect", protocol=0x8203))
        self.assertTrue(runtime.owns_resource("disconnect"))
        self.assertEqual(runtime.close(), [])
        self.assertEqual(len(provider.calls), before)

    def test_paired_child_retirement_uses_exact_physical_generation(self):
        from scripts.j2534_2026 import (
            DriverMetadata2026,
            J2534Device2026,
            J2534InterfacePair2026,
            NativeJ2534Error2026,
            PrimitiveResult,
        )
        from tests.test_j2534_2026 import Provider

        for close_status in (0, 7):
            with self.subTest(close_status=close_status):
                provider = Provider()
                clock = lambda: 0.0
                engine = J2534Device2026(
                    provider, clock=clock, background_workers=False
                )
                control = J2534Device2026(
                    provider, clock=clock, background_workers=False
                )
                pair = J2534InterfacePair2026(engine, control)
                for view in (engine, control):
                    view.set_driver(DriverMetadata2026("authored", "fixture.dll"))
                engine.open()
                engine.connect(6)
                pair.import_into(control, pair.export_from(engine))
                runtime = NativeRuntime2026(control.primitive, clock=clock)
                runtime.acquire(
                    "start_flow_control_filter",
                    "stop_filter",
                    request_address=bytes.fromhex("000007e0"),
                    response_address=bytes.fromhex("000007e8"),
                )
                # A failed Disconnect alone proves no retirement. A successful
                # Close still invalidates children of that exact device generation.
                provider.responses["passthru_disconnect"] = PrimitiveResult(status=7)
                provider.responses["passthru_close"] = PrimitiveResult(
                    status=close_status
                )
                try:
                    engine.disconnect()
                except NativeJ2534Error2026:
                    if close_status == 0:
                        raise
                before = len(provider.calls)
                runtime._forget_disconnected_children()
                self.assertEqual(
                    runtime.owned_identifiers("stop_filter"),
                    () if close_status == 0 else (0,),
                )
                self.assertEqual(len(provider.calls), before)
                if close_status == 0:
                    self.assertEqual(runtime.close(), [])
                    self.assertEqual(len(provider.calls), before)
                else:
                    # Reusing raw device/channel/filter ID zero does not retire
                    # the earlier, unproven generation.
                    provider.responses.clear()
                    engine.open()
                    engine.connect(6)
                    pair.import_into(control, pair.export_from(engine))
                    runtime.acquire(
                        "start_flow_control_filter",
                        "stop_filter",
                        request_address=bytes.fromhex("000007e0"),
                        response_address=bytes.fromhex("000007e8"),
                    )
                    engine.disconnect()
                    runtime._forget_disconnected_children()
                    self.assertEqual(runtime.owned_identifiers("stop_filter"), (0,))
                    before = len(provider.calls)
                    self.assertEqual(runtime.close(), ["ValueError"])
                    self.assertEqual(len(provider.calls), before)

    def test_disconnected_child_sweep_keeps_unanchored_ownership(self):
        runtime = NativeRuntime2026(lambda request, remaining: None)
        runtime.own("stop_filter", identifier=0)
        runtime._forget_disconnected_children()
        self.assertEqual(runtime.owned_identifiers("stop_filter"), (0,))

    def test_conditional_native_result_owns_only_exact_integer_success(self):
        release = {
            "export": "DirectoryFree",
            "module": 7,
            "function": 6,
            "arguments": (),
        }
        for returned in (0, 2, -1, 0xFFFFFFFF, True, None):
            with self.subTest(returned=returned):
                calls = []

                def provider(event, remaining, calls=calls, returned=returned):
                    calls.append(event)
                    return returned

                runtime = NativeRuntime2026(provider)
                self.assertIs(
                    runtime.call_result_owned(
                        "techvim_sdk_call",
                        "techvim_sdk_call",
                        release_values=release,
                        export="Directory",
                        module=7,
                        function=5,
                        arguments=(),
                    ),
                    returned,
                )
                self.assertFalse(runtime.owns_resource("techvim_sdk_call", **release))
                self.assertEqual(runtime.close(), [])
                self.assertEqual(len(calls), 1)

    def test_conditional_success_is_owned_before_post_provider_cancel_or_timeout(self):
        release = {
            "export": "DirectoryFree",
            "module": 7,
            "function": 6,
            "arguments": (),
        }
        for boundary in ("cancel", "timeout", "host_error"):
            with self.subTest(boundary=boundary):
                calls = []
                now = [0.0]
                acquired = [False]
                host_error = OSError("authored cancellation observation failure")

                def cancelled(
                    acquired=acquired, boundary=boundary, host_error=host_error
                ):
                    if acquired[0] and boundary == "host_error":
                        raise host_error
                    return acquired[0] and boundary == "cancel"

                def provider(
                    event,
                    remaining,
                    calls=calls,
                    acquired=acquired,
                    boundary=boundary,
                    now=now,
                ):
                    calls.append(event)
                    if event["function"] == 5:
                        acquired[0] = True
                        if boundary == "timeout":
                            now[0] = 2.0
                    return 1

                runtime = NativeRuntime2026(
                    provider,
                    timeout=1,
                    clock=lambda now=now: now[0],
                    cancelled=cancelled,
                )
                expected = {
                    "cancel": InterruptedError,
                    "timeout": TimeoutError,
                    "host_error": OSError,
                }[boundary]
                with self.assertRaises(expected) as caught:
                    runtime.call_result_owned(
                        "techvim_sdk_call",
                        "techvim_sdk_call",
                        release_values=release,
                        export="Directory",
                        module=7,
                        function=5,
                        arguments=(),
                    )
                if boundary == "host_error":
                    self.assertIs(caught.exception, host_error)
                self.assertEqual(
                    calls[-1], {"operation": "techvim_sdk_call", **release}
                )
                self.assertEqual([event["function"] for event in calls], [5, 6])
                self.assertEqual(runtime.close(), [])

    def test_release_result_consumes_completed_native_false_but_retains_host_fault(
        self,
    ):
        release = {
            "export": "DirectoryFree",
            "module": 7,
            "function": 6,
            "arguments": (),
        }
        fault = OSError("authored directory free failure")
        failed = [True]
        calls = []

        def provider(event, remaining):
            calls.append(event)
            if event["function"] == 5:
                return 1
            if failed[0]:
                raise fault
            return 0

        runtime = NativeRuntime2026(provider)
        runtime.call_result_owned(
            "techvim_sdk_call",
            "techvim_sdk_call",
            release_values=release,
            export="Directory",
            module=7,
            function=5,
            arguments=(),
        )
        with self.assertRaises(OSError) as caught:
            runtime.release_with_result("techvim_sdk_call", **release)
        self.assertIs(caught.exception, fault)
        self.assertTrue(runtime.owns_resource("techvim_sdk_call", **release))
        failed[0] = False
        self.assertEqual(runtime.release_with_result("techvim_sdk_call", **release), 0)
        self.assertFalse(runtime.owns_resource("techvim_sdk_call", **release))
        self.assertEqual(runtime.close(), [])
        self.assertEqual([event["function"] for event in calls], [5, 6, 6])

    def test_native_abandonment_is_not_a_provider_release(self):
        calls = []
        runtime = NativeRuntime2026(lambda event, remaining: calls.append(event))
        runtime.own("techvim_sdk_call", export="DirectoryFree", function=6)
        runtime.abandon_resource("techvim_sdk_call", export="DirectoryFree", function=6)
        self.assertEqual(runtime.close(), [])
        self.assertEqual((calls, runtime.cleanup_calls), ([], 0))
        with self.assertRaises(ValueError):
            runtime.abandon_resource(
                "techvim_sdk_call", export="DirectoryFree", function=6
            )

    def test_native_channel_observation_authenticates_imported_generation(self):
        from scripts.j2534_2026 import (
            DriverMetadata2026,
            J2534Device2026,
            J2534InterfacePair2026,
        )
        from tests.test_j2534_2026 import Provider

        self.assertIsNone(
            NativeRuntime2026(lambda *_: None).native_channel_connected2026()
        )
        provider = Provider()
        engine = J2534Device2026(provider, background_workers=False)
        control = J2534Device2026(provider, background_workers=False)
        pair = J2534InterfacePair2026(engine, control)
        for view in (engine, control):
            view.set_driver(DriverMetadata2026("authored", "fixture.dll"))
        runtime = NativeRuntime2026(control.primitive)
        self.assertIs(runtime.native_channel_connected2026(), False)
        engine.open()
        engine.connect(6)
        pair.import_into(control, pair.export_from(engine))
        before = len(provider.calls)
        self.assertIs(runtime.native_channel_connected2026(), True)
        self.assertEqual((runtime.calls, len(provider.calls)), (0, before))
        engine.disconnect()
        before = len(provider.calls)
        self.assertTrue(control.connecting)
        with self.assertRaises(ValueError):
            runtime.native_channel_connected2026()
        self.assertEqual((runtime.calls, len(provider.calls)), (0, before))
        control.disconnect()
        self.assertIs(runtime.native_channel_connected2026(), False)

    def test_owned_identifier_snapshot_includes_unreturned_rollback_failure_handle(
        self,
    ):
        cancelled = [False]

        def provider(request, remaining):
            if request["operation"] == "start_flow_control_filter":
                cancelled[0] = True
                return 7
            raise OSError("authored filter rollback failure")

        runtime = NativeRuntime2026(provider, cancelled=lambda: cancelled[0])
        with self.assertRaises(InterruptedError):
            runtime.acquire("start_flow_control_filter", "stop_filter")
        self.assertEqual(runtime.owned_identifiers("stop_filter"), (7,))
        runtime.own("stop_filter", identifier=7)
        self.assertEqual(runtime.owned_identifiers("stop_filter"), (7, 7))
        runtime.forget_invalidated_resource("stop_filter", identifier=7)
        runtime.forget_invalidated_resource("stop_filter", identifier=7)
        self.assertEqual(runtime.owned_identifiers("stop_filter"), ())
        runtime.own("unrelated_release", channel=3)
        self.assertEqual(runtime.owned_identifiers("stop_filter"), ())
        runtime.own("stop_filter", identifier=8, channel=3)
        with self.assertRaises(ValueError):
            runtime.owned_identifiers("stop_filter")

    def test_primitive_budget_and_reverse_cleanup(self):
        calls = []
        runtime = NativeRuntime2026(
            lambda item, seconds: calls.append((item, seconds)), clock=lambda: 0
        )
        runtime.call("connect", protocol=6)
        runtime.own("disconnect", channel=1)
        runtime.own("stop_filter", identifier=2)
        self.assertEqual(runtime.close(), [])
        self.assertEqual(
            [item[0]["operation"] for item in calls],
            ["connect", "stop_filter", "disconnect"],
        )
        self.assertEqual(calls[0][1], 30)
        self.assertEqual(calls[1][1], 5)
        self.assertEqual(runtime.close(), [])

    def test_cancel_before_and_after_primitive(self):
        flag = [True]
        calls = []
        runtime = NativeRuntime2026(
            lambda *args: calls.append(args), cancelled=lambda: flag[0]
        )
        with self.assertRaises(InterruptedError):
            runtime.call("write_messages")
        self.assertEqual(calls, [])
        flag[0] = False
        runtime.action = lambda *_: flag.__setitem__(0, True)
        with self.assertRaises(InterruptedError):
            runtime.call("read_messages")

    def test_fault_cleanup_attempts_every_release_after_cancel(self):
        calls = []

        def action(item, _seconds):
            calls.append(item["operation"])
            if item["operation"] == "stop_filter":
                raise OSError("synthetic failure")

        runtime = NativeRuntime2026(action, cancelled=lambda: True)
        runtime.own("disconnect")
        runtime.own("stop_filter")
        self.assertEqual(runtime.close(), ["OSError"])
        self.assertEqual(calls, ["stop_filter", "disconnect"])
        self.assertTrue(runtime.owns_resource("stop_filter"))
        self.assertFalse(runtime.owns_resource("disconnect"))
        runtime.cleanup_action = lambda item, seconds: None
        self.assertEqual(runtime.close(), [])
        self.assertFalse(runtime.owns_resource("stop_filter"))

    def test_expired_provider_and_malformed_deadlines(self):
        now = [0]

        def action(*_):
            now[0] = 31

        runtime = NativeRuntime2026(action, clock=lambda: now[0])
        with self.assertRaises(TimeoutError):
            runtime.call("read_messages")
        invalid: Any
        for invalid in (0, -1, True, float("nan"), float("inf"), "1"):
            with self.assertRaises(ValueError):
                NativeRuntime2026(lambda *_: None, timeout=invalid)
        with self.assertRaises(ValueError):
            runtime.call("")


class CommonAlgorithmTests(unittest.TestCase):
    def test_authored_vectors(self):
        from scripts.programming_2026_common import (
            basic_conversion,
            cpu_bus_type,
            seed_key_four_round,
            seed_key_six_byte,
            seed_key_two_byte,
        )

        self.assertEqual(
            basic_conversion(bytes.fromhex("12345678"), bytes.fromhex("abcd")),
            bytes.fromhex("5678b9f9"),
        )
        self.assertEqual(seed_key_two_byte(b"\xff\xff", b"\x00\x00"), b"\x00\x00")
        self.assertEqual(seed_key_two_byte(b"\x00\x00", b"\x00\x00"), b"\xff\xff")
        self.assertEqual(
            seed_key_six_byte(bytes.fromhex("010203040506")),
            bytes.fromhex("04070a0d1a64"),
        )
        self.assertEqual(seed_key_four_round(bytes(4), (bytes(2),) * 4), bytes(4))
        self.assertEqual([cpu_bus_type(bytes((v,)), "0") for v in range(3)], [0, 1, 2])
        self.assertEqual(cpu_bus_type(b"\x01\x00", "1 trailing"), 0)
        self.assertEqual(cpu_bus_type(b"\x01\x00", "invalid"), 1)
        with self.assertRaises(ValueError):
            cpu_bus_type(bytes(1), "01")


class PrimitiveReplay:
    def __init__(self, responses=()):
        self.responses = iter(responses)
        self.events = []
        self.now = 0

    def __call__(self, item, seconds):
        self.events.append(dict(item))
        op = item["operation"]
        if op == "get_timeout":
            return 100
        if op == "get_protocol_id":
            return 6
        if op == "start_flow_control_filter":
            return 17
        if op == "write_messages":
            return 1
        if op == "read_specified_can_message":
            return next(self.responses)
        if op == "wait":
            self.now += item["milliseconds"] / 1000
        return None


class CommunicationTests(unittest.TestCase):
    def make(self, responses, timeout=30):
        from scripts.programming_2026_common import CanDiag2026

        provider = PrimitiveReplay(responses)
        runtime = NativeRuntime2026(
            provider,
            clock=lambda: provider.now,
            timeout=timeout,
            native_cancelled=lambda: False,
        )
        return provider, runtime, CanDiag2026(runtime)

    def test_phase6_literal_wire_and_filter_cleanup(self):
        from scripts.programming_2026_common import Unified2026

        provider, runtime, _ = self.make([bytes.fromhex("18dae072500300000000")])
        self.assertEqual(
            Unified2026(runtime).extended_session_phase6(b"\x72"),
            bytes.fromhex("500300000000"),
        )
        writes = [e for e in provider.events if e["operation"] == "write_messages"]
        self.assertEqual(
            writes,
            [
                {
                    "operation": "write_messages",
                    "protocol": 6,
                    "tx_flags": 0x100,
                    "data": bytes.fromhex("18da72e01003"),
                    "count": 1,
                }
            ],
        )
        self.assertEqual(
            provider.events[-1], {"operation": "stop_filter", "identifier": 17}
        )
        self.assertEqual(runtime.close(), [])

    def test_receive_pending_never_retransmits_and_restores_timeout(self):
        provider, _, diag = self.make(
            [bytes.fromhex("000007e87f2278"), bytes.fromhex("000007e8621234")]
        )
        self.assertEqual(
            diag.call(
                bytes.fromhex("000007e0"),
                bytes.fromhex("000007e8"),
                bytes.fromhex("221234"),
                b"\x62",
                minimum=3,
            ),
            bytes.fromhex("621234"),
        )
        self.assertEqual(
            len([e for e in provider.events if e["operation"] == "write_messages"]), 1
        )
        self.assertIn(
            {"operation": "set_timeout", "milliseconds": 5000}, provider.events
        )
        self.assertEqual(
            provider.events[-1], {"operation": "set_timeout", "milliseconds": 100}
        )

    def test_busy_resends_but_phase5_does_not(self):
        from scripts.programming_2026_common import CommonResponseError

        request, response = bytes.fromhex("000007e0"), bytes.fromhex("000007e8")
        provider, _, diag = self.make(
            [response + bytes.fromhex("7f1021"), response + bytes.fromhex("5002")]
        )
        self.assertEqual(
            diag.call(request, response, b"\x10\x02", b"\x50"), b"\x50\x02"
        )
        self.assertEqual(
            len([e for e in provider.events if e["operation"] == "write_messages"]), 2
        )
        provider, _, diag = self.make([response + bytes.fromhex("7f1021")])
        with self.assertRaises(CommonResponseError):
            diag.call(request, response, b"\x10\x02", b"\x50", phase5=True)
        self.assertEqual(
            len([e for e in provider.events if e["operation"] == "write_messages"]), 1
        )

    def test_pending_limit_tester_present_wire_and_malformed(self):
        from scripts.programming_2026_common import CommonResponseError

        request, response = bytes.fromhex("000007505f"), bytes.fromhex("000007585f")
        provider, _, diag = self.make([response + bytes.fromhex("7f2278")])
        with self.assertRaises(CommonResponseError):
            diag.call(request, response, b"\x22\x20\x01", b"\x62", pending_limit=0)
        self.assertEqual(
            [e["data"] for e in provider.events if e["operation"] == "write_messages"],
            [request + bytes.fromhex("222001"), request + b"\x3e"],
        )
        for invalid in (b"", b"\x00" * 5000, "response", bytes.fromhex("000007e962")):
            provider, _, diag = self.make([invalid])
            with self.assertRaises(ValueError):
                diag.call(
                    bytes.fromhex("000007e0"),
                    bytes.fromhex("000007e8"),
                    b"\x22",
                    b"\x62",
                )
            self.assertEqual(
                provider.events[-1], {"operation": "set_timeout", "milliseconds": 100}
            )

    def test_acquisition_cancel_and_late_return_release_handle(self):
        for expired in (False, True):
            flag = [False]
            now = [0]
            events = []

            def provider(
                item, _seconds, events=events, flag=flag, now=now, expired=expired
            ):
                events.append(item)
                if item["operation"] == "start_flow_control_filter":
                    flag[0] = not expired
                    now[0] = 31 if expired else 0
                    return 19

            runtime = NativeRuntime2026(
                provider,
                cancelled=lambda flag=flag: flag[0],
                clock=lambda now=now: now[0],
            )
            with self.assertRaises(TimeoutError if expired else InterruptedError):
                runtime.acquire("start_flow_control_filter", "stop_filter")
            self.assertEqual(events[-1], {"operation": "stop_filter", "identifier": 19})
            self.assertEqual(runtime.close(), [])

    def test_user_dtc_and_ota_wire(self):
        from scripts.programming_2026_common import Unified2026

        p, r, _ = self.make([bytes.fromhex("18dae001591712ff12345678")])
        self.assertEqual(
            Unified2026(r).get_user_defined_dtcs(b"\x01"), (bytes.fromhex("12345678"),)
        )
        p, r, _ = self.make(
            [bytes.fromhex("18dae01c7101db05"), bytes.fromhex("18dae01c7103db050000")]
        )
        Unified2026(r).stop_ota_reprogramming()
        self.assertEqual(
            [e["data"] for e in p.events if e["operation"] == "write_messages"],
            [bytes.fromhex("18da1ce03101db05"), bytes.fromhex("18da1ce03103db05")],
        )
        self.assertEqual(p.now, 10)


class SharedValueTests(unittest.TestCase):
    def test_bytes_native_resize_endian_and_fold(self):
        from scripts.programming_2026_common import NativeBytes2026

        value = NativeBytes2026.from_hex("123456")
        value.set_num(4)
        self.assertEqual(value.data, bytes.fromhex("00123456"))
        value.convert_endian(2)
        self.assertEqual(value.data, bytes.fromhex("12005634"))
        value.set_num(2)
        self.assertEqual(value.hex_string(5), "5634")
        self.assertEqual(value.unsigned(2), 0x5634)
        self.assertEqual(
            NativeBytes2026.from_unsigned(0x1234, 2).data, bytes.fromhex("1234")
        )
        self.assertEqual(NativeBytes2026(bytes.fromhex("0100000002")).unsigned(), 3)
        for size in (-1, 513):
            with self.assertRaises(ValueError):
                value.set_num(size)
        with self.assertRaises(ValueError):
            NativeBytes2026.from_hex("ABC")
        with self.assertRaises(ValueError):
            value.hex_string(4)

    def test_indication_every_mask_and_upper_bits(self):
        from scripts.programming_2026_common import j2534_indication

        for mask in range(32):
            for padding in (False, True):
                expected = {0: 3, 2: 1, 9: 0, 16: 2 if padding else 3}.get(mask, 4)
                self.assertEqual(j2534_indication(mask, padding), expected)
                self.assertEqual(j2534_indication(mask | 0xFFFFFFE0, padding), expected)

    def test_secret_binding_no_bypass_and_secret_safe_repr(self):
        from scripts.programming_2026_common import SecretInfoClient, security_up_key

        class ForgedClient:
            def get(self, _identifier):
                return b"invented secret"

        forged: Any = ForgedClient()
        with self.assertRaises(TypeError):
            security_up_key(
                NativeRuntime2026(lambda *_: self.fail("Unexpected I/O")),
                forged,
                bytes(16),
                bytes(16),
            )

        secret = b"synthetic-private-value"
        client = SecretInfoClient(
            b"authored-client",
            ((0, secret),) + tuple((i, b"") for i in range(1, 64)),
            "0" * 64,
        )
        from dataclasses import FrozenInstanceError
        from unittest.mock import patch

        from scripts.programming_2026_common import _SECRET_INFO_CLIENTS

        with self.assertRaises(PermissionError):
            client.authorize(b"authored-client")
        with self.assertRaises(PermissionError):
            client.get(0)
        with self.assertRaises(FrozenInstanceError):
            mutable_client: Any = client
            mutable_client._authorized = True
        # Explicit test-only issuance of authored records exercises pure authorization.
        issued = patch.dict(_SECRET_INFO_CLIENTS, {id(client): client})
        issued.start()
        self.addCleanup(issued.stop)
        self.assertEqual(client.get(0), b"")
        client.authorize(b"wrong")
        self.assertEqual(client.get(0), b"")
        client.authorize(b"authored-client")
        self.assertEqual(client.get(0), secret)
        events = []

        def action(item, _remaining):
            events.append(item)
            return (
                bytes.fromhex("abcd" * 8)
                if item["operation"] == "decrypt_secret_info"
                else bytes(range(16))
            )

        runtime = NativeRuntime2026(action)
        self.assertEqual(
            security_up_key(runtime, client, bytes(16), b"\x01" * 16), bytes(range(16))
        )
        self.assertEqual(events[1]["key_hex"], b"ABCD" * 8)
        self.assertEqual(events[1]["seed"], bytes(16))
        self.assertNotIn("synthetic", repr(client))
        client.authorize(b"wrong")
        with self.assertRaises(PermissionError):
            security_up_key(runtime, client, bytes(16), bytes(16))
        with self.assertRaises(ValueError):
            SecretInfoClient.from_native_module(b"MZ")

    def test_cleanup_survives_normal_budget_and_void_acquire_cancel(self):
        events = []
        runtime = NativeRuntime2026(lambda item, _seconds: events.append(item))
        runtime.calls = 65536
        runtime.own("disconnect")
        self.assertEqual(runtime.close(), [])
        self.assertEqual(events, [{"operation": "disconnect"}])
        flag = [False]

        def action(item, _seconds):
            events.append(item)
            if item["operation"] == "connect":
                flag[0] = True

        runtime = NativeRuntime2026(action, cancelled=lambda: flag[0])
        with self.assertRaises(InterruptedError):
            runtime.call_owned("connect", "disconnect", protocol=6)
        self.assertEqual(events[-1], {"operation": "disconnect"})
        self.assertEqual(runtime.close(), [])

    def test_gateway_sequence_and_block_size_cleanup(self):
        from scripts.programming_2026_common import Unified2026

        p = PrimitiveReplay([bytes.fromhex("000007585f7e00")])
        rt = NativeRuntime2026(p, clock=lambda: p.now)
        self.assertEqual(Unified2026(rt).judge_repro_gateway_node(1), 1)
        self.assertEqual(
            [e["data"] for e in p.events if e["operation"] == "write_messages"],
            [bytes.fromhex("000007505f3e00")],
        )

        p = PrimitiveReplay([bytes.fromhex("000007585f6721") + bytes(16)])
        rt = NativeRuntime2026(p, clock=lambda: p.now)
        with self.assertRaisesRegex(ValueError, "online controller"):
            Unified2026(rt).collate_seed_key_phase5_gateway()
        self.assertEqual(
            [e["data"] for e in p.events if e["operation"] == "write_messages"],
            [bytes.fromhex("000007505f2721")],
        )
        self.assertEqual(
            p.events[-2:],
            [
                {"operation": "control_io", "ioctl": 2, "parameters": ((0x1E, 0),)},
                {"operation": "stop_filter", "identifier": 17},
            ],
        )


class SharedMetadataHelperTests(unittest.TestCase):
    def test_flash_geometry_uses_observed_memory_and_native_gap_size(self):
        from scripts.programming_2026_common import (
            NativeBlockInfo,
            block_ranges_from_info,
            calc_block_sizes,
            complete_block_info,
            extract_memory_info,
            native_block_info,
        )

        memory = extract_memory_info(bytes.fromhex("001000002fff0452"))
        self.assertEqual((memory.start_address, memory.end_address), (4096, 12287))
        completed = complete_block_info(
            native_block_info({"BlockSizeInfo": "0:0x0"}), memory
        )
        self.assertEqual(completed, (NativeBlockInfo(0, 4, 2),))
        self.assertEqual(block_ranges_from_info(completed), ((1, 2),))
        self.assertEqual(calc_block_sizes(completed), (4096, 4096))
        self.assertEqual(
            calc_block_sizes((NativeBlockInfo(0, 1, 1), NativeBlockInfo(3, 2, 1))),
            (1024, 2048, 2048, 2048),
        )
        with self.assertRaises(ValueError):
            calc_block_sizes((NativeBlockInfo(0, 1, 2), NativeBlockInfo(1, 2, 1)))

    def test_range_table_and_first_index_native_validation(self):
        from scripts.programming_2026_common import (
            CommonResponseError,
            block_ranges_from_image,
            check_block_ranges,
        )

        data = bytes.fromhex("00aa55aa550000000100010002")
        self.assertEqual(block_ranges_from_image(data), ((2, 2), (3, 3)))
        check_block_ranges(30, (10, 20), ((1, 999), (2, 999)))
        with self.assertRaises(CommonResponseError):
            check_block_ranges(30, (10, 20), ((2, 2), (1, 1)))
        for broken in (
            bytes.fromhex("aa55aa55"),
            data[:-1],
            bytes.fromhex("aa55aa55000000010000ffff"),
        ):
            with self.assertRaises(ValueError):
                block_ranges_from_image(broken)

    def test_parameter_keys_native_prefix_integer_and_saved_selection(self):
        from scripts.programming_2026_common import NativeParameter2026

        parameter = NativeParameter2026.from_csv(
            b'ParamFileKeySystemProtocolMicon,Number,Many\r\nA0102, -12tail,"one\r\ntwo"\r\nB0304,999999999999999,three\r\n\xff'
        )
        self.assertTrue(parameter.set_keys("A", "02", "01"))
        self.assertEqual(parameter.long("Number"), -12)
        self.assertEqual(parameter.values("Many"), ("one\r", "two"))
        self.assertEqual(
            parameter.long_with_keys("Number", "B", "04", "03"), 0x7FFFFFFF
        )
        self.assertEqual(parameter.long("Number"), -12)
        self.assertIsNone(parameter.string_with_keys("Many", "a", "02", "01"))
        self.assertEqual(parameter.values("Many"), ("one\r", "two"))
        parameter.delete()
        self.assertIsNone(parameter.string("Number"))
        for bad in (b"a,b\n1", b'a,b\n1,"unterminated', b"a\n\xffx", b"a\x00"):
            with self.assertRaises(ValueError):
                NativeParameter2026.from_csv(bad)
        with self.assertRaises(ValueError):
            NativeParameter2026.from_csv(b"a\n" + b"x\n" * 4097)

    def test_make_send_data_preserves_whole_records_and_skips_first_s1(self):
        from scripts.programming_2026_common import make_send_data_records

        records = ((1, 0x100, b"skip"), (2, 0x200, b"ab"), (1, 0x900, b"cd"))
        self.assertEqual(make_send_data_records(records, 0x200, 4), b"abcd")
        for size in (1, 3, 5):
            with self.assertRaises(ValueError):
                make_send_data_records(records, 0x200, size)

    def test_acquire_cancel_preserves_original_when_rollback_fails(self):
        cancelled = False
        events = []

        def provider(item, remaining):
            nonlocal cancelled
            events.append(item)
            if item["operation"] == "acquire":
                cancelled = True
                return 7
            raise OSError("release failed")

        runtime = NativeRuntime2026(provider, cancelled=lambda: cancelled)
        with self.assertRaises(InterruptedError) as caught:
            runtime.acquire("acquire", "release")
        self.assertIn("OSError", caught.exception.__notes__[0])
        self.assertTrue(runtime.owns_resource("release", identifier=7))
        self.assertEqual(runtime.close(), ["OSError"])
        self.assertEqual(len(events), 3)

    def test_forget_source_invalidated_child_retires_only_exact_owned_entry(self):
        events = []
        runtime = NativeRuntime2026(lambda action, remaining: events.append(action))
        runtime.own("stop_filter", identifier=17)
        runtime.own("stop_filter", identifier=18)
        runtime.own("disconnect")
        runtime.forget_invalidated_resource("stop_filter", identifier=17)
        self.assertFalse(runtime.owns_resource("stop_filter", identifier=17))
        self.assertTrue(runtime.owns_resource("stop_filter", identifier=18))
        self.assertTrue(runtime.owns_resource("disconnect"))
        self.assertEqual(events, [])
        with self.assertRaises(ValueError):
            runtime.forget_invalidated_resource("stop_filter", identifier=17)
        self.assertEqual(runtime.close(), [])
        self.assertEqual(
            events,
            [
                {"operation": "disconnect"},
                {"operation": "stop_filter", "identifier": 18},
            ],
        )

    def test_cleanup_survives_normal_call_budget_exhaustion(self):
        events = []
        runtime = NativeRuntime2026(lambda item, seconds: events.append(item))
        runtime.own("release", identifier=9)
        runtime.calls = 65536
        with self.assertRaises(ValueError):
            runtime.call("read")
        self.assertEqual(runtime.close(), [])
        self.assertEqual(events, [{"operation": "release", "identifier": 9}])


class UnifiedWireTests(unittest.TestCase):
    def test_software_id_and_read_rob_literal_payloads(self):
        from scripts.programming_2026_common import Unified2026

        request, response = bytes.fromhex("00000750"), bytes.fromhex("00000758")
        p = PrimitiveReplay(
            (response + bytes.fromhex("62f18141"), response + bytes.fromhex("eb0742"))
        )
        runtime = NativeRuntime2026(
            p, clock=lambda: p.now, native_cancelled=lambda: False
        )
        helper = Unified2026(runtime)
        self.assertEqual(
            helper.read_software_id(request, response), bytes.fromhex("62f18141")
        )
        self.assertEqual(helper.read_rob(request, response, 7), bytes.fromhex("eb0742"))
        self.assertEqual(
            [
                event["data"]
                for event in p.events
                if event["operation"] == "write_messages"
            ],
            [request + bytes.fromhex("22f181"), request + bytes.fromhex("ab07")],
        )
        self.assertEqual(sum(event["operation"] == "lock" for event in p.events), 2)
        self.assertEqual(sum(event["operation"] == "unlock" for event in p.events), 2)

    def test_programming_mode_status_and_filter_release_on_mismatch(self):
        from scripts.programming_2026_common import CommonResponseError, Unified2026

        for payload, expected in (("62100503", 1), ("62100502", 0), ("62100603", None)):
            p = PrimitiveReplay((bytes.fromhex("00000761" + payload),))
            helper = Unified2026(
                NativeRuntime2026(p, clock=lambda replay=p: replay.now)
            )
            if expected is None:
                with self.assertRaises(CommonResponseError) as caught:
                    helper.read_programming_mode_control_state()
                self.assertEqual(caught.exception.code, 0x3FA)
            else:
                self.assertEqual(helper.read_programming_mode_control_state(), expected)
            self.assertEqual(
                p.events[-1], {"operation": "stop_filter", "identifier": 17}
            )
            self.assertEqual(
                [e["data"] for e in p.events if e["operation"] == "write_messages"],
                [bytes.fromhex("00000751221005")],
            )

    def test_receive_only_pending_has_no_initial_request(self):
        from scripts.programming_2026_common import CanDiag2026

        request, response = bytes.fromhex("00000750"), bytes.fromhex("00000758")
        p = PrimitiveReplay(
            (response + bytes.fromhex("7f2278"), response + bytes.fromhex("62f181"))
        )
        helper = CanDiag2026(
            NativeRuntime2026(p, clock=lambda: p.now, native_cancelled=lambda: False)
        )
        self.assertEqual(
            helper.receive(
                request,
                response,
                bytes.fromhex("22f181"),
                bytes.fromhex("62f181"),
                pending_limit=1,
            ),
            bytes.fromhex("62f181"),
        )
        self.assertFalse(any(e["operation"] == "write_messages" for e in p.events))


class NativeValueContractTests(unittest.TestCase):
    def test_bytes_index_copy_and_mutation_bounds(self):
        from scripts.programming_2026_common import NativeBytes2026

        source = NativeBytes2026(bytes.fromhex("1234"))
        copied = NativeBytes2026()
        copied.assign(source)
        copied[0] = 0xAB
        self.assertEqual(copied.data, bytes.fromhex("ab34"))
        self.assertEqual(source.data, bytes.fromhex("1234"))
        self.assertEqual(len(copied), 2)
        for index in (-1, 2):
            with self.assertRaises(IndexError):
                _ = copied[index]
        with self.assertRaises(ValueError):
            copied[0] = 256

    def test_native_exception_history_error_and_move_fields(self):
        from scripts.programming_2026_common import NativeJ2534Exception2026

        first = NativeJ2534Exception2026(16, "first.cpp", 7)
        first.set_error_info("second.cpp", 9)
        self.assertEqual(first.messages(), ("first.cpp(7)", "second.cpp(9)"))
        self.assertEqual(
            (first.error, first.j2534_error, first.source, first.line),
            (1, 16, "first.cpp", 7),
        )
        other = NativeJ2534Exception2026(0, "empty.cpp", 0)
        other.assign(first, move=True)
        self.assertEqual(other.messages(), first.messages())
        self.assertEqual(
            (other.error, other.j2534_error, other.source, other.line),
            (1, 16, "first.cpp", 7),
        )
        self.assertEqual(first.source, "")
        self.assertNotIn("first.cpp", str(other))
        with self.assertRaises(ValueError):
            other.set_error_info("x" * 260, 1)

    def test_native_exception_source_is_ansi_bytes_with_260_byte_bound(self):
        from scripts.programming_2026_common import NativePassThruException2026

        source = "\x83" * 256
        error = NativePassThruException2026(7, source, 0)
        self.assertEqual(error.messages(), (source + "(0)",))
        self.assertEqual(len(error.messages()[0].encode("latin1")), 259)
        for invalid in (source + "x", "\u20ac", "embedded\0suffix"):
            with self.assertRaises(ValueError):
                error.set_error_info(invalid, 0)
        self.assertEqual(error.messages(), (source + "(0)",))

    def test_exception_copy_constructor_and_assignment_return_independent_owner(self):
        from scripts.programming_2026_common import (
            NativeException2026,
            NativeJ2534Exception2026,
            NativePassThruException2026,
        )

        for original in (
            NativeException2026("authored"),
            NativePassThruException2026(7, "authored.cpp", 11),
            NativeJ2534Exception2026(23, "authored.cpp", 11),
        ):
            with self.subTest(kind=type(original).__name__):
                copied = type(original).copy_of(original)
                self.assertIsNot(copied, original)
                self.assertEqual(copied.messages(), original.messages())
                copied.add_message("additional")
                self.assertNotEqual(copied.messages(), original.messages())
                self.assertIs(copied.assign(original), copied)
                self.assertIs(copied.assign(copied, move=True), copied)
        original = NativeJ2534Exception2026(23, "authored.cpp", 11)
        moved = NativeJ2534Exception2026.copy_of(original, move=True)
        self.assertEqual(
            (moved.source, moved.line, moved.j2534_error), ("authored.cpp", 11, 23)
        )
        self.assertEqual(original.source, "")
        self.assertEqual(original.messages(), moved.messages())

    def test_multi_parameter_capacity_reports_original_count(self):
        from scripts.programming_2026_common import NativeParameter2026

        parameter = NativeParameter2026(
            ("key", "many"), ((("ABC",), ("one", "two", "three")),), "key"
        )
        parameter.set_keys("A", "C", "B")
        self.assertEqual(parameter.parameters("many", 2), (("one", "two"), 3))
        self.assertEqual(parameter.parameters("many", 0), ((), 3))
        self.assertEqual(parameter.get_data(0, 0), ("key",))
        self.assertEqual(parameter.get_data(1, 1), ("one", "two", "three"))
        self.assertEqual(parameter.get_data(-1, 0), ())


class GatewayAndClockTests(unittest.TestCase):
    def test_central_gateway_literal_security_and_cleanup_order(self):
        from scripts.programming_2026_common import Unified2026

        class Central(PrimitiveReplay):
            def __call__(self, item, seconds):
                if item["operation"] == "calculate_central_gateway_key":
                    self.events.append(dict(item))
                    return bytes(range(16))
                return super().__call__(item, seconds)

        p = Central(
            (
                bytes.fromhex("000007585f6751") + bytes(16),
                bytes.fromhex("000007585f675234"),
            )
        )
        Unified2026(
            NativeRuntime2026(p, clock=lambda: p.now)
        ).collate_seed_key_central_gateway()
        self.assertEqual(
            [e["data"] for e in p.events if e["operation"] == "write_messages"],
            [
                bytes.fromhex("000007505f2751"),
                bytes.fromhex("000007505f2752") + bytes(range(16)),
            ],
        )
        self.assertIn({"operation": "wait", "milliseconds": 100}, p.events)
        self.assertEqual(
            p.events[-2:],
            [
                {"operation": "control_io", "ioctl": 2, "parameters": ((0x1E, 0),)},
                {"operation": "stop_filter", "identifier": 17},
            ],
        )

    def test_block_size_cleanup_attempts_both_and_preserves_original_fault(self):
        from scripts.programming_2026_common import Unified2026

        class FailedRestore(PrimitiveReplay):
            def __call__(self, item, seconds):
                if item["operation"] == "control_io" and item["parameters"] == (
                    (0x1E, 0),
                ):
                    self.events.append(item)
                    raise OSError("restore")
                return super().__call__(item, seconds)

        p = FailedRestore()
        runtime = NativeRuntime2026(p, clock=lambda: p.now)
        runtime.own("disconnect")
        with (
            self.assertRaises(InterruptedError) as caught,
            Unified2026(runtime).block_size_filtered(
                bytes.fromhex("00000750"), bytes.fromhex("00000758")
            ),
        ):
            raise InterruptedError("original")
        self.assertEqual(str(caught.exception), "original")
        self.assertIn("OSError", caught.exception.__notes__[0])
        self.assertEqual(p.events[-1], {"operation": "stop_filter", "identifier": 17})
        self.assertTrue(
            runtime.owns_resource("control_io", ioctl=2, parameters=((0x1E, 0),))
        )
        self.assertTrue(runtime.owns_resource("disconnect"))

    def test_smc_requires_source_binding_before_legacy_crypto_callback(self):
        from scripts.programming_2026_common import Unified2026

        events = []
        with self.assertRaisesRegex(ValueError, "Source-issued"):
            Unified2026(
                NativeRuntime2026(lambda item, remaining: events.append(item))
            ).smc_gateway_key(bytes(32))
        self.assertEqual(events, [])

    def test_native_clock_floor_and_midnight(self):
        from datetime import datetime

        from scripts.programming_2026_common import Unified2026

        self.assertEqual(Unified2026.calc_millisecond(23, 59, 59, 999), 86399999)
        self.assertEqual(Unified2026.get_passed_time(86399990, 10), 20)
        self.assertEqual(
            Unified2026.calc_elapsed_time(
                datetime.fromisoformat("2026-01-01T00:00:00"),
                datetime.fromisoformat("2026-01-01T00:00:01.999"),
            ),
            1,
        )
        self.assertEqual(
            Unified2026.calc_elapsed_time(
                datetime.fromisoformat("2026-01-02T00:00:00"),
                datetime.fromisoformat("2026-01-01T00:00:00"),
            ),
            0,
        )
        with self.assertRaises(ValueError):
            Unified2026.calc_millisecond(24, 0, 0, 0)


class RemainingNativeBoundaryTests(unittest.TestCase):
    def test_unified_pending_always_writes_native_tester_present(self):
        from scripts.programming_2026_common import CanDiag2026, CommonResponseError

        request, response = bytes.fromhex("000007505f"), bytes.fromhex("000007585f")
        p = PrimitiveReplay((response + bytes.fromhex("7f1078"),))
        runtime = NativeRuntime2026(p, clock=lambda: p.now)
        with self.assertRaises(CommonResponseError):
            CanDiag2026(runtime).call(
                request,
                response,
                bytes.fromhex("1001"),
                b"\x50",
                unified_utils=True,
                pending_limit=0,
                send_tester_present=False,
            )
        self.assertEqual(
            [e["data"] for e in p.events if e["operation"] == "write_messages"],
            [request + bytes.fromhex("1001"), request + bytes.fromhex("3e")],
        )
        self.assertEqual(
            sum(e["operation"] == "lock" for e in p.events),
            sum(e["operation"] == "unlock" for e in p.events),
        )

    def test_firmware_prefix_conversion_and_cpu_parameter_finish_flag(self):
        from scripts.programming_2026_common import (
            NativeParameter2026,
            check_cpu_type_from_firmware,
            receive_response_for_finish,
        )

        self.assertTrue(
            check_cpu_type_from_firmware(
                0x52, {"CPUIDNo": "5trailing", "ShrinkFlag": "0ignored"}, False
            )
        )
        self.assertTrue(check_cpu_type_from_firmware(0, {}, False))
        self.assertTrue(
            check_cpu_type_from_firmware(
                0, {"CPUIDNo": "invalid", "ShrinkFlag": "invalid"}, False
            )
        )
        parameter = NativeParameter2026(
            ("key", "FlagToReceiveRespForFinish"),
            ((("A0102",), ("0",)), (("A0103",), ("2",))),
            "key",
        )
        self.assertTrue(receive_response_for_finish(parameter, "A", ("02", "03"), "01"))
        self.assertFalse(receive_response_for_finish(parameter, "A", (), "01"))

    def test_bare_lf_native_multivalue_and_quoted_cr_retention(self):
        from scripts.programming_2026_common import NativeParameter2026

        parameter = NativeParameter2026.from_csv(
            b"key,value\r\nABC,one\ntwo\r\n", "key"
        )
        parameter.set_keys("A", "C", "B")
        self.assertEqual(parameter.values("value"), ("one", "two"))
        parameter = NativeParameter2026.from_csv(
            b'key,value\r\nABC,"one\r\ntwo"\r\n', "key"
        )
        parameter.set_keys("A", "C", "B")
        self.assertEqual(parameter.values("value"), ("one\r", "two"))

    def test_static_native_byte_hex_conversion_keeps_short_destination_unchanged(self):
        from scripts.programming_2026_common import NativeBytes2026

        output = bytearray(b"authored stale buffer")
        NativeBytes2026.convert_bytes_to_string(b"\xaf\x01\xff", 2, output, 4)
        self.assertEqual(output, bytearray(b"authored stale buffer"))
        NativeBytes2026.convert_bytes_to_string(b"\xaf\x01\xff", 2, output, 5)
        self.assertEqual(output, bytearray(b"AF01\0red stale buffer"))
        NativeBytes2026.convert_bytes_to_string(b"", 0, output, 1)
        self.assertEqual(output[0], 0)
        before = output[:]
        NativeBytes2026.convert_bytes_to_string(b"", 0, output, 0)
        self.assertEqual(output, before)
        for count, capacity in ((-1, 5), (4, 9), (2, len(output) + 1)):
            with self.assertRaises(ValueError):
                NativeBytes2026.convert_bytes_to_string(b"abc", count, output, capacity)
        self.assertEqual(output, before)

    def test_bounded_bytes_deterministic_malformed_and_roundtrip_corpus(self):
        import random

        from scripts.programming_2026_common import NativeBytes2026

        randomizer = random.Random(2026)
        for _ in range(64):
            value = randomizer.randbytes(randomizer.randrange(513))
            native = NativeBytes2026.from_hex(value.hex())
            self.assertEqual(native.data, value)
            self.assertEqual(native.checksum(), sum(value) & 255)
            self.assertEqual(native.hex_string(len(value) * 2 + 1), value.hex().upper())
            with self.assertRaises(ValueError):
                native.hex_string(len(value) * 2)
        for malformed in ("0", "gg", "1 ", "00" * 513):
            with self.assertRaises(ValueError):
                NativeBytes2026.from_hex(malformed)


class ChargeBusTests(unittest.TestCase):
    def test_ordinary_and_phase6_literal_wire(self):
        from scripts.programming_2026_common import Unified2026

        p = PrimitiveReplay(
            (bytes.fromhex("000007587101117e"), bytes.fromhex("18dae0497102117e"))
        )
        runtime = NativeRuntime2026(
            p, clock=lambda: p.now, native_cancelled=lambda: False
        )
        helper = Unified2026(runtime)
        helper.routine_charge_local_bus(
            bytes.fromhex("00000750"), bytes.fromhex("00000758"), 0
        )
        helper.routine_charge_local_bus_phase6(1)
        writes = [e for e in p.events if e["operation"] == "write_messages"]
        self.assertEqual(
            [e["data"] for e in writes],
            [bytes.fromhex("000007503101117e"), bytes.fromhex("18da49e03102117e")],
        )
        self.assertEqual([e["tx_flags"] for e in writes], [0, 0x100])
        self.assertEqual(sum(e["operation"] == "stop_filter" for e in p.events), 2)
        self.assertFalse(runtime._resources)

    def test_cancellation_prevents_charge_bus_activity(self):
        from scripts.programming_2026_common import Unified2026

        p = PrimitiveReplay()
        helper = Unified2026(NativeRuntime2026(p, cancelled=lambda: True))
        with self.assertRaises(InterruptedError):
            helper.routine_charge_local_bus_phase6(0)
        self.assertEqual(p.events, [])


class ParameterBindingAndAcceptedCleanupTests(unittest.TestCase):
    def test_exact_stage_protocol_keys_and_no_filename_fallback(self):
        from scripts.calibration_2026 import parse_cuw_2026
        from scripts.programming_2026_common import bind_parameter2026
        from tests.test_calibration_2026 import cuw, logical_text

        text = (
            logical_text()
            .replace("ContactType=P5-Unified", "KindOfECU=7\nContactType=Phase6")
            .replace("Protocol=02", "Protocol=09")
        )
        container = parse_cuw_2026(cuw(text))
        for operation, expected in (
            ("get_cid", "7Phase609"),
            ("prepare", "7Phase609"),
            ("write", "7Phase609"),
        ):
            table = f"ParamFileKeySystemProtocolMicon,DLLFileNameForGetCID,DLLFileNameForPrepareWrite,DLLFileNameForFlashWrite,GetCANIDFunctionNameForGetCID\r\n{expected},Authored.dll,Authored.dll,Authored.dll,ResolveAuthoredAddress\r\n".encode()
            bound = bind_parameter2026(
                container,
                {expected + ".ini": table},
                operation=operation,
                encoded=False,
            )
            self.assertEqual(
                (bound.source_file, bound.key, bound.module_name),
                (expected + ".ini", expected, "Authored.dll"),
            )
            self.assertEqual(
                bound.parameter.string("DLLFileNameForGetCID"), "Authored.dll"
            )
            self.assertEqual(
                bound.selector_functions,
                ("ResolveAuthoredAddress",) if operation == "get_cid" else (),
            )
            with self.assertRaises(TypeError):
                readonly_values: Any = bound.values
                readonly_values["extra"] = ("not mutable",)
            with self.assertRaises(LookupError):
                bind_parameter2026(
                    container,
                    {"similar.ini": table},
                    operation=operation,
                    encoded=False,
                )
            with self.assertRaises(ValueError):
                bound.dispatch(
                    {"Authored.dll": b"authored bytes, not an exact native identity"}
                )

    def test_phase6_prepare_uses_current_node_protocol_with_global_cpu_zero(self):
        from scripts.calibration_2026 import (
            native2026_metadata,
            native2026_with_cpu_type,
            parse_cuw_2026,
        )
        from scripts.programming_2026_common import bind_parameter2026
        from tests.test_calibration_2026 import cuw, logical_text

        first = (
            logical_text()
            .replace("NumberOfNode=1", "NumberOfNode=2")
            .replace("ContactType=P5-Unified", "KindOfECU=7\nContactType=Phase6")
            .replace("Protocol=02", "Protocol=01")
        )
        second = (
            logical_text()
            .split("[Node01]", 1)[1]
            .replace("Protocol=02", "Protocol=09")
            .replace("[LogicalBlock101]", "[LogicalBlock201]")
            .replace("[ReproData101]", "[ReproData201]")
            .replace("authored-new", "other-new")
        )
        container = parse_cuw_2026(
            cuw(first + "\n[Node02]" + second, (b"data", b"data"))
        )
        state = native2026_metadata(container, node=2)
        state = native2026_with_cpu_type(state, 0, "A")
        state = native2026_with_cpu_type(state, 1, "B")
        sources = {
            key
            + ".ini": f"ParamFileKeySystemProtocolMicon,DLLFileNameForPrepareWrite\r\n{key},{module}\r\n".encode()
            for key, module in (
                ("7Phase609A", "CurrentNode.dll"),
                ("7Phase602A", "WrongFixedProtocol.dll"),
                ("7Phase601A", "WrongFirstNode.dll"),
            )
        }
        selected = bind_parameter2026(
            container, sources, "prepare", node=2, encoded=False, metadata_state=state
        )
        self.assertEqual(selected.key, "7Phase609A")
        self.assertEqual(selected.module_name, "CurrentNode.dll")
        sources.pop("7Phase609A.ini")
        with self.assertRaises(LookupError):
            bind_parameter2026(
                container,
                sources,
                "prepare",
                node=2,
                encoded=False,
                metadata_state=state,
            )

    def test_native_controller_requires_four_phase_versions_even_when_absent(self):
        from scripts.calibration_2026 import parse_cuw_2026
        from scripts.programming_2026_common import bind_parameter2026
        from tests.test_calibration_2026 import cuw, logical_text

        container = parse_cuw_2026(
            cuw(
                logical_text().replace(
                    "ContactType=P5-Unified", "KindOfECU=7\nContactType=P4Can"
                )
            )
        )
        header = "ParamFileKeySystemProtocolMicon,DLLFileNameForGetCID,EnableDLLVersionInformation\r\n"
        for versions, accepted in (
            ("", False),
            ("0", False),
            ("0\n0\n0\n0", True),
            ("0\n0\n0\n0\n0", False),
        ):
            table = (header + f'7P4Can02,Getter.dll,"{versions}"\r\n').encode()
            selected = bind_parameter2026(
                container, {"7P4Can02.ini": table}, operation="get_cid", encoded=False
            )
            if accepted:
                selected.require_control_versions()
            else:
                with self.assertRaises(ValueError):
                    selected.require_control_versions()

    def test_native_phase3_gateway_selects_cpu0_classic_source_fields(self):
        from scripts.calibration_2026 import parse_cuw_2026
        from scripts.programming_2026_common import bind_parameter2026
        from tests.test_calibration_2026 import cuw, logical_text

        text = logical_text().replace(
            "ContactType=P5-Unified", "KindOfECU=7\nContactType=P4Can"
        )
        container = parse_cuw_2026(cuw(text))
        table = b"ParamFileKeySystemProtocolMicon,DLLFileNameForChangeToReprogGatewayMode,GetCANIDFunctionNameForChangeToReprogGatewayMode\r\n7P4Can,Gateway.dll,ResolveGateway\r\n"
        selected = bind_parameter2026(
            container, {"7P4Can.ini": table}, operation="change_gateway", encoded=False
        )
        self.assertEqual(selected.module_name, "Gateway.dll")
        self.assertEqual(selected.selector_functions, ("ResolveGateway",))
        self.assertEqual(
            selected.validate_against(container, operation="change_gateway"), selected
        )
        modern = parse_cuw_2026(cuw(logical_text()))
        with self.assertRaises(ValueError):
            bind_parameter2026(modern, {}, operation="change_gateway", encoded=False)

    def test_source_selected_alternate_cid_binding_and_native_one_slot_bound(self):
        from dataclasses import replace

        from scripts.calibration_2026 import parse_cuw_2026
        from scripts.programming_2026_common import bind_parameter2026
        from tests.test_calibration_2026 import cuw, logical_text

        container = parse_cuw_2026(
            cuw(
                logical_text()
                .replace("ContactType=P5-Unified", "KindOfECU=7\nContactType=Phase6")
                .replace("Protocol=02", "Protocol=09")
            )
        )
        header = "ParamFileKeySystemProtocolMicon,DLLFileNameForGetCID,AlternateDLLFileNamesForGetCID,EnableAlternateDLLVersionsInformationForGetCID\r\n"

        def bind(names, versions):
            table = (
                header + f'7Phase609,Primary.dll,"{names}","{versions}"\r\n'
            ).encode()
            return bind_parameter2026(
                container, {"7Phase609.ini": table}, operation="get_cid", encoded=False
            )

        primary = bind("Alternate.dll", "1.2")
        alternate = primary.alternate_cid_binding()
        self.assertIsNotNone(alternate)
        assert alternate is not None
        self.assertEqual(alternate.module_name, "Alternate.dll")
        self.assertTrue(alternate.alternate_cid)
        self.assertIs(alternate.catalog_sources, primary.catalog_sources)
        self.assertEqual(
            alternate.validate_against(container, operation="get_cid"), alternate
        )
        from scripts.calibration_2026 import native2026_with_cpu_type

        live = native2026_with_cpu_type(primary.metadata, 0, "C")
        projected = alternate.rebind_getter_metadata(live)
        self.assertEqual(projected.module_name, "Alternate.dll")
        self.assertEqual(
            projected.validate_against(container, operation="get_cid"), projected
        )
        with self.assertRaises(ValueError):
            replace(
                alternate,
                values={
                    **alternate.values,
                    "AlternateDLLFileNamesForGetCID": ("Forged.dll",),
                },
            ).validate_against(container, operation="get_cid")
        self.assertIsNone(bind("", "1.2").alternate_cid_binding())
        self.assertIsNone(bind("Alternate.dll", "").alternate_cid_binding())
        with self.assertRaises(ValueError):
            bind("Alternate.dll", "1.2\n1.3").alternate_cid_binding()
        first_only = bind("Alternate.dll\nIgnored.dll", "1.2").alternate_cid_binding()
        assert first_only is not None
        self.assertEqual(first_only.module_name, "Alternate.dll")

    def test_native_get_cid_uses_global_cpu_zero_and_first_node_protocol(self):
        from scripts.calibration_2026 import (
            native2026_metadata,
            native2026_with_cpu_type,
            parse_cuw_2026,
        )
        from scripts.programming_2026_common import bind_parameter2026
        from tests.test_calibration_2026 import cuw

        text = "[Format]\nVersion=105\n[Vehicle]\nNumberOfNode=2\nContactType=P5-Unified\nKindOfECU=7\n[Node01]\nRequiredSpecReproVer=02\nProtocol=01\nNumberOfCalibration=1\n[CPU11]\nCPUType=A\nCPUImageName=one.vbf\n[Node02]\nRequiredSpecReproVer=02\nProtocol=09\nNumberOfCalibration=1\n[CPU21]\nCPUType=B\nCPUImageName=two.vbf\n"
        container = parse_cuw_2026(cuw(text, (b"one", b"two")))
        expected = "7P5-Unified01A"
        table = f"ParamFileKeySystemProtocolMicon,DLLFileNameForGetCID\r\n{expected},Authored.dll\r\n".encode()
        state = native2026_metadata(container, node=2)
        state = native2026_with_cpu_type(state, 0, "A")
        state = native2026_with_cpu_type(state, 1, "B")
        bound = bind_parameter2026(
            container,
            {expected + ".ini": table},
            operation="get_cid",
            node=2,
            encoded=False,
            metadata_state=state,
        )
        self.assertEqual(bound.key, expected)
        self.assertEqual(bound.metadata.cpu.values["cputype"], "B")
        # 7c20 uses the already loaded row even if primary CID changed CPUType.
        live = native2026_with_cpu_type(bound.metadata, 0, "C")
        retained = bound.rebind_getter_metadata(live)
        self.assertEqual(retained.key, expected)
        self.assertEqual(retained.metadata.cpu_type_overrides[0], "C")
        self.assertEqual(retained.getter_parameter_metadata, bound.metadata)
        self.assertEqual(
            retained.validate_against(container, operation="get_cid", node=2),
            retained,
        )
        with self.assertRaises(ValueError):
            retained.validate_against(container, operation="prepare", node=2)
        with self.assertRaises(ValueError):
            bound.rebind_getter_metadata(native2026_metadata(container, node=1))

    def test_classic_prepare_cpu_row_uses_global_zero_dll_and_runtime_type(self):
        from scripts.calibration_2026 import (
            native2026_metadata,
            native2026_with_cpu_type,
            parse_cuw_2026,
        )
        from scripts.programming_2026_common import bind_parameter2026
        from tests.test_calibration_2026 import cuw

        text = "[Format]\nVersion=105\n[Vehicle]\nNumberOfNode=2\nContactType=CAN\nKindOfECU=7\n[Node01]\nProtocol=01\nNumberOfCalibration=1\n[CPU11]\nCPUType=A\nCPUImageName=one.vbf\n[Node02]\nProtocol=09\nNumberOfCalibration=1\n[CPU21]\nCPUType=B\nCPUImageName=two.vbf\n"
        container = parse_cuw_2026(cuw(text, (b"one", b"two")))

        def table(key, dll, versions=""):
            return f'ParamFileKeySystemProtocolMicon,DLLFileNameForPrepareWrite,Marker,EnableDLLVersionInformation\r\n{key},{dll},row-{key},"{versions}"\r\n'.encode()

        sources = {
            "7CANA.ini": table("7CANA", "First.dll", "0\n0\n0\n0"),
            "7CANB.ini": table("7CANB", "Second.dll"),
            "7CANC.ini": table("7CANC", "Changed.dll"),
        }
        state = native2026_metadata(container, node=2)
        state = native2026_with_cpu_type(state, 0, "A")
        state = native2026_with_cpu_type(state, 1, "B")
        bound = bind_parameter2026(
            container, sources, "prepare", node=2, encoded=False, metadata_state=state
        )
        self.assertEqual(bound.key, "7CANB")
        self.assertEqual(bound.module_name, "First.dll")
        self.assertEqual(bound.value("Marker"), "row-7CANB")
        bound.require_control_versions()
        state = native2026_with_cpu_type(bound.metadata, 0, "C")
        changed = bind_parameter2026(
            container, sources, "prepare", node=2, encoded=False, metadata_state=state
        )
        self.assertEqual(changed.key, "7CANB")
        self.assertEqual(changed.module_name, "Changed.dll")
        with self.assertRaisesRegex(ValueError, "phase version count"):
            changed.require_control_versions()

    def test_diagnostic_and_filter_cleanup_preserve_native_cancel(self):
        from scripts.programming_2026_common import NativeException2026, Unified2026

        p = PrimitiveReplay()

        def provider(item, remaining):
            if item["operation"] in ("set_timeout", "stop_filter"):
                p.events.append(item)
                raise OSError("authored restoration failure")
            return p(item, remaining)

        native_values = iter((False, True))
        runtime = NativeRuntime2026(
            provider, clock=lambda: p.now, native_cancelled=lambda: next(native_values)
        )
        with self.assertRaises(NativeException2026) as caught:
            Unified2026(runtime).ordinary_session(
                bytes.fromhex("00000750"), bytes.fromhex("00000758")
            )
        self.assertEqual(len(caught.exception.__notes__), 2)
        self.assertTrue(all("OSError" in note for note in caught.exception.__notes__))
        self.assertTrue(runtime.owns_resource("stop_filter", identifier=17))
        self.assertEqual(p.events[-1]["operation"], "stop_filter")

    def test_unified_native_entry_skip_and_post_read_dtc_observation(self):
        from scripts.programming_2026_common import Unified2026

        p = PrimitiveReplay()
        helper = Unified2026(NativeRuntime2026(p, native_cancelled=lambda: True))
        self.assertEqual(
            helper.ordinary_session(
                bytes.fromhex("00000750"), bytes.fromhex("00000758")
            ),
            b"",
        )
        self.assertEqual(helper.default_session_phase6(b"\x01"), b"")
        self.assertIsNone(helper.routine_charge_local_bus_phase6(0))
        self.assertEqual(helper.get_user_defined_dtcs(b"\x01"), ())
        self.assertEqual(p.events, [])
        p = PrimitiveReplay((bytes.fromhex("18dae001591712ff12345678"),))
        observations = iter((False, False, True))
        helper = Unified2026(
            NativeRuntime2026(
                p, clock=lambda: p.now, native_cancelled=lambda: next(observations)
            )
        )
        self.assertEqual(helper.get_user_defined_dtcs(b"\x01"), ())
        self.assertEqual(
            sum(e["operation"] == "read_specified_can_message" for e in p.events), 1
        )
        self.assertEqual(p.events[-1]["operation"], "stop_filter")

    def test_unified_native_cancel_preflight_and_exact_loop_query(self):
        from scripts.programming_2026_common import NativeException2026, Unified2026

        request, response = bytes.fromhex("00000750"), bytes.fromhex("00000758")
        p = PrimitiveReplay((response + bytes.fromhex("500100000000"),))
        with self.assertRaises(ValueError):
            Unified2026(NativeRuntime2026(p)).ordinary_session(request, response)
        self.assertEqual(p.events, [])
        queries = []

        def native_cancel():
            queries.append(tuple(e["operation"] for e in p.events))
            return len(queries) > 1

        runtime = NativeRuntime2026(
            p, clock=lambda: p.now, native_cancelled=native_cancel
        )
        with self.assertRaises(NativeException2026):
            Unified2026(runtime).ordinary_session(request, response)
        self.assertEqual(len(queries), 2)
        self.assertEqual(queries[0], ())
        self.assertIn("write_messages", queries[1])
        self.assertNotIn("read_specified", queries[1])
        self.assertFalse(runtime._resources)

    def test_late_successful_release_is_never_repeated(self):
        now = 0
        events = []

        def provider(item, remaining):
            nonlocal now
            events.append(item)
            now += 6

        runtime = NativeRuntime2026(provider, clock=lambda: now)
        runtime.own("stop_filter", identifier=8)
        with self.assertRaises(TimeoutError):
            runtime.release("stop_filter", identifier=8)
        self.assertFalse(runtime.owns_resource("stop_filter", identifier=8))
        self.assertEqual(runtime.close(), [])
        self.assertEqual(len(events), 1)

    def test_cancel_at_lock_boundary_rolls_back_successful_lock(self):
        from scripts.programming_2026_common import CanDiag2026

        cancelled = False

        class CancelLock(PrimitiveReplay):
            def __call__(self, item, remaining):
                nonlocal cancelled
                if item["operation"] == "lock":
                    cancelled = True
                return super().__call__(item, remaining)

        p = CancelLock()
        runtime = NativeRuntime2026(p, cancelled=lambda: cancelled)
        with self.assertRaises(InterruptedError):
            CanDiag2026(runtime).call(
                bytes.fromhex("00000750"),
                bytes.fromhex("00000758"),
                b"\x22",
                b"\x62",
                phase5=True,
            )
        self.assertEqual(
            [e["operation"] for e in p.events],
            ["get_timeout", "lock", "unlock", "set_timeout"],
        )
        self.assertFalse(runtime.owns_resource("unlock"))


class AlternateParameterBindingTests(unittest.TestCase):
    def test_derived_alternate_cpu_and_source_validation(self):
        from dataclasses import replace

        from scripts.calibration_2026 import native2026_with_cpu_type, parse_cuw_2026
        from scripts.programming_2026_common import bind_parameter2026
        from tests.test_calibration_2026 import cpu_text, cuw

        container = parse_cuw_2026(
            cuw(cpu_text(8).replace("ContactType=P5-Unified", "ContactType=SIL"))
        )
        original = b"ParamFileKeySystemProtocolMicon,DLLFileNameForFlashWrite,AlternateCPUType\r\n149SIL311,Authored.dll,999\r\n"
        alternate = b"ParamFileKeySystemProtocolMicon,DLLFileNameForFlashWrite,AlternateCPUType\r\n149SIL999,Authored.dll,311\r\n"
        sources = {"149SIL311.ini": original, "149SIL999.ini": alternate}
        bound = bind_parameter2026(container, sources, "write", encoded=False)
        self.assertEqual(bound.validate_against(container, operation="write"), bound)
        reselected = bound.reselect_alternate_cpu()
        self.assertEqual((reselected.key, reselected.cpu_type), ("149SIL999", "999"))
        self.assertEqual(
            reselected.validate_against(
                container, operation="write", alternate_cpu=True
            ),
            reselected,
        )
        self.assertEqual(reselected.metadata.cpu.values["cputype"], "999")
        self.assertEqual(reselected.metadata.sections["cpu01"]["cputype"], "311")
        self.assertEqual(reselected.parameter.string("AlternateCPUType"), "311")
        for loaded in (bound, reselected):
            live = native2026_with_cpu_type(loaded.metadata, 0, "CHANGED")
            retained = loaded.rebind_writer_metadata(live)
            self.assertEqual(retained.key, loaded.key)
            self.assertEqual(retained.module_name, "Authored.dll")
            self.assertEqual(retained.loaded_parameter_metadata, loaded.metadata)
            self.assertEqual(
                retained.validate_against(container, operation="write"), retained
            )
            with self.assertRaises(ValueError):
                retained.validate_against(container, operation="prepare")
        sources["149SIL311.ini"] = b"replaced after immutable snapshot"
        self.assertEqual(bound.validate_against(container, operation="write"), bound)
        with self.assertRaises(ValueError):
            replace(bound, key="unrelated").validate_against(
                container, operation="write"
            )
        with self.assertRaises(ValueError):
            reselected.validate_against(container, operation="write")
        with self.assertRaises(LookupError):
            bind_parameter2026(
                container, {"149SIL311.ini": original}, "write", encoded=False
            ).reselect_alternate_cpu()


class RecordedDeviceBindingTests(unittest.TestCase):
    def test_only_actual_trace_driver_device_is_retained_and_revalidated(self):
        from scripts.j2534_2026 import J2534Device2026
        from scripts.programming_2026_common import ControlCommPhase2026
        from scripts.programming_replay import ProgrammingTrace

        trace = ProgrammingTrace.validate([])
        device = trace.bind_recorded_device2026(timeout=30, max_calls=128)
        runtime = NativeRuntime2026(trace.action, clock=trace.clock)
        runtime.bind_recorded_device2026(trace, device)
        runtime.bind_recorded_device2026(trace, device)
        self.assertIs(runtime.recorded_device2026(), device)
        self.assertEqual(runtime.cleanup_action, trace.cleanup_primitive)
        controller = object.__new__(ControlCommPhase2026)
        controller.runtime = runtime
        self.assertIs(controller.runtime_device(), device)
        unrelated = J2534Device2026(trace.driver_primitive)
        with self.assertRaises(ValueError):
            runtime.bind_recorded_device2026(trace, unrelated)
        wrong_runtime = NativeRuntime2026(lambda *_: None)
        with self.assertRaises(ValueError):
            wrong_runtime.bind_recorded_device2026(trace, device)
        late_runtime = NativeRuntime2026(trace.action, clock=trace.clock)
        late_runtime.own("close_device")
        with self.assertRaises(ValueError):
            late_runtime.bind_recorded_device2026(trace, device)
        runtime.action = lambda *_: None
        with self.assertRaises(ValueError):
            controller.runtime_device()
        self.assertEqual(trace.position, 0)


class FrontendParameterSourceTests(unittest.TestCase):
    @staticmethod
    def sources():
        return {
            "Parameter.ini": b"ParamFileKeySystemProtocolMicon,CalibrationType\r\n7CAN1,11\r\n",
            "CanIDTable.ini": b"RequestCANID,CalibrationType\r\n0720,2\r\n",
            "LogicalAddressTable.ini": b"LogicalAddress,CalibrationType\r\n1000,3\r\n",
        }

    def test_literal_tables_keep_independent_keys_and_immutable_source(self):
        from scripts.programming_2026_common import NativeFrontendParameters2026

        sources = self.sources()
        bound = NativeFrontendParameters2026.from_sources(sources, encoded=False)
        self.assertEqual(
            bound.general.long_with_keys("7", "1", "CAN", "CalibrationType"), 11
        )
        for name, key, expected in (
            ("CanIDTable.ini", "0720", 2),
            ("LogicalAddressTable.ini", "1000", 3),
        ):
            table = bound.parameter(name)
            self.assertEqual(
                table.long_with_keys("CalibrationType", key, "", ""), expected
            )
            self.assertIsNone(
                table.long_with_keys("CalibrationType", "missing", "", "")
            )
            table.delete()
            self.assertEqual(
                bound.parameter(name).long_with_keys("CalibrationType", key, "", ""),
                expected,
            )
        sources["CanIDTable.ini"] = b"changed after binding"
        bound.validate_source()
        with self.assertRaises(LookupError):
            bound.parameter("CanIDTableForMazda.ini")

    def test_frontend_retains_empty_extra_resources_and_all_source_hashes(self):
        import hashlib
        from dataclasses import replace

        from scripts.programming_2026_common import NativeFrontendParameters2026

        sources = self.sources()
        sources["P5-Unified03.ini"] = b""
        sources["Another.ini"] = b"retained resource"
        bound = NativeFrontendParameters2026.from_sources(sources, encoded=False)
        self.assertEqual(dict(bound.sources), sources)
        self.assertEqual(
            dict(bound.source_sha256),
            {name: hashlib.sha256(data).hexdigest() for name, data in sources.items()},
        )
        sources["Another.ini"] = b"changed caller resource"
        bound.validate_source()
        self.assertEqual(bound.sources["Another.ini"], b"retained resource")
        with self.assertRaises(ValueError):
            replace(bound, source_sha256={}).validate_source()
        with self.assertRaises(ValueError):
            replace(
                bound, sources={**bound.sources, "Another.ini": b"forged"}
            ).validate_source()

    def test_frontend_rejects_ambiguous_or_non_win32_resource_basenames(self):
        from scripts.programming_2026_common import NativeFrontendParameters2026

        for name in (
            "parameter.INI",
            "",
            ".",
            "..",
            "Ini\\P5-Unified.ini",
            "Ini/P5-Unified.ini",
            "extra.ini.",
            "extra.ini ",
            "C:extra.ini",
            "extra?.ini",
            "nonascii-é.ini",
            "CON.ini",
            "nul",
            "COM1.ini",
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                NativeFrontendParameters2026.from_sources(
                    {**self.sources(), name: b""}, encoded=False
                )

    def test_encoded_tables_and_forged_decoded_state(self):
        from dataclasses import replace

        from scripts.cuw_persistence import encode_nibble_text
        from scripts.programming_2026_common import NativeFrontendParameters2026

        bound = NativeFrontendParameters2026.from_sources(
            {name: encode_nibble_text(data) for name, data in self.sources().items()}
        )
        bound.validate_source()
        self.assertEqual(
            bound.parameter("CanIDTable.ini").long_with_keys(
                "CalibrationType", "0720", "", ""
            ),
            2,
        )
        with self.assertRaises(ValueError):
            replace(bound, source_sha256={}).validate_source()
        with self.assertRaises(ValueError):
            replace(bound, tables={}).validate_source()

    def test_missing_literal_source_and_wrong_key_column_are_rejected(self):
        from scripts.programming_2026_common import NativeFrontendParameters2026

        sources = self.sources()
        sources["SimilarCanIDTable.ini"] = sources.pop("CanIDTable.ini")
        with self.assertRaises(LookupError):
            NativeFrontendParameters2026.from_sources(sources, encoded=False)
        sources = self.sources()
        sources["CanIDTable.ini"] = b"WrongKey,CalibrationType\r\n0720,2\r\n"
        with self.assertRaises(ValueError):
            NativeFrontendParameters2026.from_sources(sources, encoded=False)


class CommonDefinitionAndBudgetTests(unittest.TestCase):
    def test_mutable_native_cpu_capacity_and_fixed_protocol_strings(self):
        from scripts.programming_2026_common import CommonDefinitions2026

        values = CommonDefinitions2026()
        self.assertEqual(values.num_cpu_maxnum, 0)
        self.assertEqual(
            (values.diag_comm_protocol_canfd, values.diag_comm_protocol_ethernet),
            ("02", "03"),
        )
        values.num_cpu_maxnum = 3
        self.assertEqual(values.num_cpu_maxnum, 3)
        for invalid in (-1, 65536, True):
            with self.assertRaises(ValueError):
                values.num_cpu_maxnum = invalid
        self.assertEqual(values.num_cpu_maxnum, 3)

    def test_aliased_parameter_graph_has_aggregate_work_bound(self):
        from scripts.programming_2026_common import NativeParameter2026

        cell = ("x",) * 4096
        row = (cell,) * 256
        with self.assertRaises(ValueError):
            NativeParameter2026(tuple(f"c{i}" for i in range(256)), (row,) * 4096, "c0")

    def test_factory_rejects_unrecognized_native_caller(self):
        from scripts.programming_2026_common import SecretInfoClient

        with self.assertRaises(ValueError):
            SecretInfoClient.from_native_modules(
                b"authored SecretInfo", b"authored CUW"
            )


class OnlineSourceBindingTests(unittest.TestCase):
    def test_online_business_key_fallback_is_rejected_without_concrete_producer(self):
        events = []
        runtime = NativeRuntime2026(
            lambda action, remaining: events.append(action) or bytes(256)
        )
        for operation, seed in (
            ("calculate_p5_gateway_key", bytes(16)),
            ("calculate_dh_gateway_online_key", bytes(8)),
            ("calculate_esw1_key", bytes(16)),
        ):
            with self.assertRaisesRegex(ValueError, "online controller"):
                runtime.call(operation, seed=seed)
        self.assertEqual(events, [])

    def test_suzuki_gateway_requires_callback26_but_other_slots_remain_distinct(self):
        events = []
        runtime = NativeRuntime2026(lambda action, _: events.append(action) or b"other")
        with self.assertRaisesRegex(ValueError, "online controller"):
            runtime.call(
                "observe_authorization_key",
                family="suzuki_uds",
                stage="gateway",
                seed=bytes(16),
                key_length=256,
            )
        self.assertEqual(events, [])
        self.assertEqual(
            runtime.call(
                "observe_authorization_key",
                family="other",
                stage="gateway",
                seed=bytes(16),
                key_length=256,
            ),
            b"other",
        )
        self.assertEqual(len(events), 1)


class CentralGatewaySourceTests(unittest.TestCase):
    def test_concrete_central_key_rejects_unrecognized_source_and_untyped_binding(self):
        from scripts.programming_2026_common import NativeCentralGatewayKey2026

        with self.assertRaises(ValueError):
            NativeCentralGatewayKey2026.from_native_module(b"authored invalid CUW")
        with self.assertRaises(TypeError):
            invalid_binding: Any = object()
            NativeRuntime2026(lambda *_: None).bind_central_gateway_key(invalid_binding)


class SMCHmacTests(unittest.TestCase):
    def test_exact_fixed_key_hmac_algorithm_with_authored_material(self):
        import hmac

        from scripts.programming_2026_common import native_smc_hmac_sha256

        key = bytes(range(32))
        message = b"\x11" + bytes(range(32))
        self.assertEqual(
            native_smc_hmac_sha256(key, message),
            bytes.fromhex(
                "72da3a4f983e285bffd5f6783f7538f2795278b995b2d88e0addc4d7d664b0e3"
            ),
        )
        self.assertEqual(
            native_smc_hmac_sha256(key, b"\x10" + bytes(32)),
            hmac.digest(key, b"\x10" + bytes(32), "sha256"),
        )
        for invalid in (b"", bytes(32), bytes(34)):
            with self.assertRaises(ValueError):
                native_smc_hmac_sha256(key, invalid)
        with self.assertRaises(ValueError):
            native_smc_hmac_sha256(bytes(31), message)

    def test_loaded_native_export_chronology_and_faults(self):
        from scripts.programming_2026_common import (
            CommonResponseError,
            NativePassThruException2026,
            Unified2026,
        )

        for load, symbol, result, expected in (
            (0, 2, bytes(32), NativePassThruException2026),
            (1, 0, bytes(32), NativePassThruException2026),
            (1, 2, False, CommonResponseError),
            (1, 2, bytes(31), ValueError),
            (1, 2, bytes(range(32)), None),
        ):
            events = []

            def provider(
                action,
                remaining,
                events=events,
                load=load,
                symbol=symbol,
                result=result,
            ):
                events.append(action)
                return {
                    "load_smc_hmac_library": load,
                    "resolve_smc_hmac_export": symbol,
                    "invoke_smc_hmac_export": result,
                    "free_smc_hmac_library": None,
                }[action["operation"]]

            runtime = NativeRuntime2026(provider)
            unified = Unified2026(runtime)
            if expected is None:
                self.assertEqual(unified.smc_gateway_key_loaded(bytes(32)), result)
            else:
                with self.assertRaises(expected) as caught:
                    unified.smc_gateway_key_loaded(bytes(32))
                if isinstance(caught.exception, NativePassThruException2026):
                    self.assertEqual(caught.exception.native_error_code, 0x11)
                    self.assertEqual(
                        caught.exception.line, 0xB87 if not load else 0xB96
                    )
            names = [action["operation"] for action in events]
            self.assertEqual(
                names,
                ["load_smc_hmac_library"]
                if not load
                else ["load_smc_hmac_library", "resolve_smc_hmac_export"]
                + (["invoke_smc_hmac_export"] if symbol else [])
                + ["free_smc_hmac_library"],
            )
            self.assertEqual(runtime.close(), [])
            if load and symbol:
                self.assertEqual(events[2]["data"], b"\x11" + bytes(32))

    def test_loaded_native_export_preserves_host_fault_and_frees(self):
        from scripts.programming_2026_common import Unified2026

        fault = OSError("authored host fault")
        events = []

        def provider(action, remaining):
            events.append(action["operation"])
            if action["operation"] == "invoke_smc_hmac_export":
                raise fault
            return 1

        runtime = NativeRuntime2026(provider)
        with self.assertRaises(OSError) as caught:
            Unified2026(runtime).smc_gateway_key_loaded(bytes(32))
        self.assertIs(caught.exception, fault)
        self.assertEqual(events[-1], "free_smc_hmac_library")
        self.assertEqual(runtime.close(), [])

    def test_native_module_factory_rejects_other_bytes_without_io(self):
        from scripts.programming_2026_common import NativeSMCHmac2026

        with self.assertRaises(ValueError):
            NativeSMCHmac2026.from_native_module(b"authored invalid image")


if __name__ == "__main__":
    unittest.main()
