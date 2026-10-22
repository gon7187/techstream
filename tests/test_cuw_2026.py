import hashlib
import io
import json
import struct
import tempfile
import unittest
import zipfile
import zlib
from dataclasses import replace
from pathlib import Path
from threading import Thread
from unittest.mock import MagicMock, patch

from scripts.cuw_2026 import (
    CommunicationLogNativeFault,
    CompletionNotice2026,
    CUWEngine2026,
    CUWEngineError,
    DHControllerState2026,
    EngineStatus2026,
    NoticeConfig,
    NoticeEvent,
    RKSAccess2026,
    RKSSoftwareIdentity2026,
    ServiceError,
    SuzukiControllerState2026,
    ZIPMember,
    configure_2026,
    connect_j2534,
    disconnect_j2534,
    export_vehicle_info,
    extract_zip,
    gateway_authentication2026,
    gateway_wire2026,
    id_conversion_rows,
    identity_2026,
    import_repro_key_2026,
    native_protocol,
    native_vin,
    notification_font_heights,
    process_after_reprogramming,
    read_file_header,
    read_header_buffer,
    rks_data_from_native,
    rks_software_identity2026,
    serialize_object,
    set_communication_log_mode,
    usb_copy_status,
    usb_payload_bytes,
    vehicle_info_from_memory,
    write_new_file,
    write_new_tree,
)
from scripts.j2534_2026 import DriverMetadata2026, J2534Device2026, PrimitiveResult


def archive(rows):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as stream:
        for name, data in rows:
            stream.writestr(name, data)
    return output.getvalue()


class ManagedServicesTests(unittest.TestCase):
    def test_actual141_transition_keeps_recovery_position_while_cpu_resets(self):
        from scripts.calibration_2026 import native2026_metadata_for_cpu
        from scripts.cuw_file_services import admit_file_sources_2026
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )
        from scripts.programming_2026_common import NativeRuntime2026
        from tests.test_cuw_engine_worker import calibration, make_controller

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        part = calibration(cpus=2, first_target="PART")
        whole = calibration(cpus=2, first_target="WHOLE")
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as stream:
            stream.writestr(
                "Setting.ini",
                "[DeltaReproCalFile]\nFileNum=1\nFileName1=part.cuw\n"
                "[WholeReproCalFile]\nFileName=whole.cuw\n",
            )
            stream.writestr("part.cuw", part)
            stream.writestr("whole.cuw", whole)
        bundle = (
            b"[Vehicle]\nContactType=P5-Unified\n[DataCompression]\n"
            + payload.getvalue()
        )
        with tempfile.TemporaryDirectory() as directory:
            persistence = CUWPersistence(
                Path(directory),
                ReproInfoState(
                    (RecoveryCalibration("source.cuw", calibration(cpus=2)),),
                    loaded=True,
                    offset_of_write_cpu_multi_cal_index=1,
                ),
            )
            engine = CUWEngine2026(image.read_bytes())
            engine.configure(struct.pack("<IIddII", 2, 0, 0, 0, 0, 0))
            engine.load_cuw(calibration(cpus=2))
            engine.bind_persistence(persistence)
            issued = admit_file_sources_2026(engine, "direct.scuw", bundle, region=0)
            engine.bind_file_sources(issued)
            self.addCleanup(engine.close)
            controller = make_controller(NativeRuntime2026(lambda *_args: None))
            worker = engine.bind_worker(controller)

            with engine.controller_execution(controller, 2):
                selected = native2026_metadata_for_cpu(engine.native_metadata, 1)
                engine._select_worker_metadata(
                    selected, controller=controller, worker=worker
                )
                worker._persist_position()
                self.assertEqual(persistence.state.write_cpu_index, 1)
                replacement = issued.after_group_reset(0, worker=worker)
                engine._accept_worker_file_reset(issued, replacement, worker=worker)

            self.assertEqual(worker.source_state.cpu_offset, 1)
            self.assertEqual(worker.source_state.current_global_cpu_index, 0)
            self.assertEqual(persistence.state.write_cpu_index, 1)
            engine._validate_persistence_source(engine.native_metadata)
            with engine.controller_execution(controller, 2):
                chained = replacement.after_group_reset(0, worker=worker)
                engine._accept_worker_file_reset(replacement, chained, worker=worker)
            transition = engine._persistence_cpu_transition2026
            assert transition is not None
            self.assertEqual((transition.before_cpu, transition.after_cpu), (0, 0))
            engine._validate_persistence_source(engine.native_metadata)
            snapshot = persistence._snapshot()
            engine._validate_persistence_source(
                engine.native_metadata, state_snapshot=snapshot
            )
            self.assertIs(engine._persistence_cpu_transition2026, transition)
            engine._persistence_cpu_transition2026 = None
            with self.assertRaisesRegex(ValueError, "actual engine target"):
                engine._validate_persistence_source(engine.native_metadata)
            engine._persistence_cpu_transition2026 = transition
            with self.assertRaisesRegex(ValueError, "Finish and release"):
                engine.bind_file_sources(issued)
            self.assertIs(engine._persistence_cpu_transition2026, transition)
            engine._validate_persistence_source(engine.native_metadata)
            stale_fields = {
                "origin": object(),
                "worker": object(),
                "persistence": object(),
                "state": object(),
                "metadata": replace(engine.native_metadata),
                "file_sources": object(),
                "container": object(),
                "digest": "0" * 64,
                "node": transition.node + 1,
                "persisted_cpu": 2,
                "after_cpu": transition.after_cpu + 1,
            }
            for field, value in stale_fields.items():
                with self.subTest(stale_field=field):
                    engine._persistence_cpu_transition2026 = replace(
                        transition, **{field: value}
                    )
                    with self.assertRaisesRegex(ValueError, "actual engine target"):
                        engine._validate_persistence_source(engine.native_metadata)
            engine._persistence_cpu_transition2026 = transition
            persistence.update_cpu(1)
            engine._validate_persistence_source(engine.native_metadata)
            with engine.controller_execution(controller, 2):
                persistence.update_cpu(2)
                self.assertIsNone(engine._persistence_cpu_transition2026)
                with self.assertRaisesRegex(ValueError, "actual engine target"):
                    engine._validate_persistence_source(engine.native_metadata)
                worker._persist_position()
            self.assertEqual(persistence.state.write_cpu_index, 0)
            engine._validate_persistence_source(engine.native_metadata)
            with engine.controller_execution(controller, 2):
                selected = native2026_metadata_for_cpu(engine.native_metadata, 1)
                engine._select_worker_metadata(
                    selected, controller=controller, worker=worker
                )
                worker._persist_position()
            self.assertEqual(persistence.state.write_cpu_index, 1)
            engine._validate_persistence_source(engine.native_metadata)
            current_sources = engine.file_sources
            assert current_sources is not None
            with engine.controller_execution(controller, 2):
                replacement = current_sources.after_group_reset(0, worker=worker)
                engine._accept_worker_file_reset(
                    current_sources, replacement, worker=worker
                )
            self.assertIsNotNone(engine._persistence_cpu_transition2026)
            engine._validate_persistence_source(engine.native_metadata)
            with engine.controller_execution(controller, 2):
                selected = native2026_metadata_for_cpu(engine.native_metadata, 1)
                engine._select_worker_metadata(
                    selected, controller=controller, worker=worker
                )
                worker._persist_position()
            self.assertIsNone(engine._persistence_cpu_transition2026)
            engine._validate_persistence_source(engine.native_metadata)
            current_sources = engine.file_sources
            assert current_sources is not None
            with engine.controller_execution(controller, 2):
                replacement = current_sources.after_group_reset(0, worker=worker)
                engine._accept_worker_file_reset(
                    current_sources, replacement, worker=worker
                )
            self.assertIsNotNone(engine._persistence_cpu_transition2026)
            engine._validate_persistence_source(engine.native_metadata)
            cleanup = engine.bind_cleanup_controller()
            failing_replacement = replacement.after_group_reset(0, worker=worker)
            with (
                engine.controller_execution(controller, 2),
                patch.object(
                    cleanup,
                    "accept_file_reset",
                    side_effect=RuntimeError("cleanup acceptance fault"),
                ),
                self.assertRaisesRegex(RuntimeError, "cleanup acceptance"),
            ):
                engine._accept_worker_file_reset(
                    replacement, failing_replacement, worker=worker
                )
            self.assertIsNone(engine._persistence_cpu_transition2026)
            with self.assertRaisesRegex(ValueError, "actual engine target"):
                engine._validate_persistence_source(engine.native_metadata)

    def test_divided_image_resume_preserves_percentage(self):
        from scripts.demo_calibration import table
        from scripts.programming_2026_common import NativeGeneralParameters2026
        from tests.test_calibration_2026 import cpu_text, cuw, srecord

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        parameters = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": table(
                    (
                        "ParamFileKeySystemProtocolMicon",
                        "M16CTypeFlag",
                        "FORESTTypeFlag",
                    ),
                    (("149P5-Unified311", "0", "0"),),
                )
            },
            encoded=False,
        )
        engine = CUWEngine2026(image.read_bytes(), general_parameters=parameters)
        engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))

        def payload(address, data):
            return b"\r\n".join((srecord(3, address, data), srecord(7, 0))) + b"\r\n"

        engine.load_cuw(
            cuw(
                cpu_text(4) + "01_CPUImageName=ONE\n03_CPUImageName=THREE\n",
                (payload(0x1000, b"ab"), payload(0x2000, b"xyz"), b"flash"),
                count=2,
            )
        )
        state = engine.dh_state
        state.set_native_count(0, 7)
        state.set_native_percentage(0, 31)
        state.resume_divided_image_count()
        self.assertEqual((state.transferred_bytes, state.progress), ((7,), (31,)))
        state.advance_divided_image(0)
        state.resume_divided_image_count()
        self.assertEqual((state.transferred_bytes, state.progress), ((9,), (31,)))

    def test_frontend_calibration_type_uses_actual_global_tables(self):
        from scripts.demo_calibration import table
        from scripts.programming_2026_common import NativeFrontendParameters2026
        from tests.test_calibration_2026 import cpu_text, cuw, logical_text

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        sources = {
            "Parameter.ini": table(
                ("ParamFileKeySystemProtocolMicon", "CalibrationType", "M16CTypeFlag"),
                (("149SIL311", "29suffix", "0"),),
            ),
            "CanIDTable.ini": table(
                ("RequestCANID", "CalibrationType"), (("7E0", "17suffix"),)
            ),
            "LogicalAddressTable.ini": table(
                ("LogicalAddress", "CalibrationType"), (("0103", "18"),)
            ),
        }
        frontend = NativeFrontendParameters2026.from_sources(sources, encoded=False)
        with CUWEngine2026(image.read_bytes()) as engine:
            engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
            engine.bind_frontend_parameters(frontend)
            text = logical_text().replace(
                "[Node01]", "[Node01]\nDiagID=7E0\nLogicalAddress=0103"
            )
            engine.load_cuw(cuw(text))
            self.assertEqual(engine.calibration_type(0), 17)
            engine.load_cuw(
                cuw(text.replace("ContactType=P5-Unified", "ContactType=Ethernet"))
            )
            self.assertEqual(engine.calibration_type(0), 18)
            engine.load_cuw(
                cuw(cpu_text(8).replace("ContactType=P5-Unified", "ContactType=SIL"))
            )
            self.assertEqual(engine.calibration_type(0), 29)
            with self.assertRaises(ValueError):
                engine.calibration_type(1)
            changed = dict(
                sources,
                **{
                    "Parameter.ini": table(
                        ("ParamFileKeySystemProtocolMicon", "CalibrationType"),
                        (("149SIL311", "30"),),
                    )
                },
            )
            with self.assertRaisesRegex(ValueError, "General differs"):
                engine.bind_frontend_parameters(
                    NativeFrontendParameters2026.from_sources(changed, encoded=False)
                )
            self.assertEqual(engine.calibration_type(0), 29)

    def test_engine_set_vin_preserves_native_bytes_and_recovery_state(self):
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )
        from tests.test_calibration_2026 import cpu_text, cuw

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        source = cuw(cpu_text())
        state = ReproInfoState((RecoveryCalibration("authored.cuw", source),))
        with tempfile.TemporaryDirectory() as directory:
            persistence = CUWPersistence(Path(directory), state)
            with CUWEngine2026(image.read_bytes(), persistence=persistence) as engine:
                engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
                engine.load_cuw(source)
                self.assertEqual(engine.set_vin(b"AUTHORED?ignored"), b"AUTHORED")
                self.assertEqual((engine.vin, state.vin), (b"AUTHORED", "AUTHORED"))
                with self.assertRaises(CUWEngineError):
                    engine.set_vin(b"A" * 18)
                self.assertEqual((engine.vin, state.vin), (b"AUTHORED", "AUTHORED"))
                self.assertEqual(engine.set_vin(b"\xffunused"), b"")
                self.assertEqual(state.vin, "")
                self.assertFalse(list(Path(directory).iterdir()))

    def test_actual_mmc_hardware_import_publication_and_phase_guards(self):
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeRuntime2026,
        )
        from tests.test_calibration_2026 import cpu_text, cuw

        folder = Path("runtime/no-car-21/recovered")
        if not (folder / "CUW.dll").is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        control_identity = identity_2026(
            (folder / "TCUWControlCommPhase.dll").read_bytes(),
            "TCUWControlCommPhase.dll",
        )
        mmc_identity = identity_2026(
            (folder / "TCUWCanMMCCIDGetter.dll").read_bytes(),
            "TCUWCanMMCCIDGetter.dll",
        )
        controller = ControlCommPhase2026(
            control_identity,
            NativeRuntime2026(
                lambda event, remaining: None,
                local_milliseconds_of_day=lambda: 1000,
            ),
        )
        foreign = ControlCommPhase2026(
            control_identity, NativeRuntime2026(lambda event, remaining: None)
        )
        with CUWEngine2026((folder / "CUW.dll").read_bytes()) as engine:
            engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
            engine.load_cuw(cuw(cpu_text()))
            self.assertEqual(engine.received_hardware, b"")
            with self.assertRaises(ValueError):
                engine.apply_mmc_getter_hardware(mmc_identity, b"HW123")
            with engine.controller_execution(controller, 0):
                engine._import_identifier_context()
                engine.apply_mmc_getter_hardware(mmc_identity, b"HW123")
                self.assertEqual(engine.received_hardware, b"")
                for invalid in (b"x" * 25, b"HW\0tail"):
                    with self.assertRaises(ValueError):
                        engine.apply_mmc_getter_hardware(mmc_identity, invalid)
                with self.assertRaises(ValueError):
                    engine.apply_mmc_getter_hardware(control_identity, b"wrong")
                with self.assertRaises(ValueError):
                    engine.commit_received_identifiers((), controller=foreign)
                engine.commit_received_identifiers((), controller=controller)
                self.assertEqual(engine.received_hardware, b"HW123")
                engine._import_identifier_context()
                engine.apply_mmc_getter_hardware(mmc_identity, b"")
                engine.commit_received_identifiers((), controller=controller)
                self.assertEqual(engine.received_hardware, b"")

    def test_actual_worker_lease_and_cross_file_source_guards(self):
        from scripts.calibration_2026 import native2026_metadata, parse_cuw_2026
        from scripts.demo_calibration import table
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeGeneralParameters2026,
            NativeRuntime2026,
        )
        from tests.test_calibration_2026 import cpu_text, cuw

        folder = Path("runtime/no-car-21/recovered")
        if not (folder / "CUW.dll").is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        identity = identity_2026(
            (folder / "TCUWControlCommPhase.dll").read_bytes(),
            "TCUWControlCommPhase.dll",
        )
        first = ControlCommPhase2026(
            identity, NativeRuntime2026(lambda event, remaining: None)
        )
        second = ControlCommPhase2026(
            identity, NativeRuntime2026(lambda event, remaining: None)
        )
        parameters = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": table(
                    (
                        "ParamFileKeySystemProtocolMicon",
                        "M16CTypeFlag",
                        "FORESTTypeFlag",
                    ),
                    (("149P5-Unified311", "0", "0"),),
                )
            },
            encoded=False,
        )
        engine = CUWEngine2026(
            (folder / "CUW.dll").read_bytes(), general_parameters=parameters
        )
        source = cuw(cpu_text())
        self.assertEqual(engine.native_phase, 4)
        self.assertEqual(engine.check_j2534_connection(), 4003)
        self.assertEqual(engine.stop_receiving_cid(), 5002)
        previous = bytes(index % 251 for index in range(0x2160))
        self.assertEqual(engine.get_info_for_repro_log(previous), (10001, previous))
        engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
        metadata = engine.load_cuw(source)
        self.assertEqual(engine.get_info_for_repro_log(previous), (10001, previous))
        with self.assertRaises(ValueError):
            engine.get_info_for_repro_log(previous[:-1])
        worker = engine.bind_worker(first)
        self.assertEqual(engine.get_info_for_repro_log(previous), (10001, previous))
        self.assertIs(engine.bind_worker(first), worker)
        self.assertIs(engine.worker, worker)
        self.assertEqual(engine.inform_result_of_query_retry(1, 0), 3005)
        retry = engine.bind_retry_controller()
        self.assertIs(engine.bind_retry_controller(), retry)
        self.assertIs(retry.engine, engine)
        self.assertIs(retry.worker, worker)
        self.assertEqual(engine.inform_result_of_query_retry(1, 0), 3005)
        with self.assertRaises(ValueError):
            engine._publish_retry_decision(retry, True)
        first.runtime.local_milliseconds_of_day = lambda: 1000
        original_native = first.runtime.native_cancelled
        failure = OSError("authored outer controller fault")
        with (
            self.assertRaises(OSError) as raised,
            engine.controller_execution(first, 0) as owned_worker,
        ):
            self.assertIs(owned_worker, worker)
            self.assertTrue(engine.active)
            self.assertTrue(engine.cancel())
            self.assertTrue(engine.native_cancelled())
            raise failure
        self.assertIs(raised.exception, failure)
        self.assertFalse(engine.active)
        self.assertIs(first.runtime.native_cancelled, original_native)
        self.assertIs(engine.source_container, metadata.source_container)
        with self.assertRaises(ValueError):
            engine.bind_worker(second)
        with self.assertRaisesRegex(ValueError, "replacing"):
            engine.load_cuw(source)
        substitute = native2026_metadata(parse_cuw_2026(source))
        with self.assertRaisesRegex(ValueError, "FILE vector"):
            engine._select_worker_metadata(substitute, controller=first, worker=worker)
        self.assertIs(engine.native_metadata, metadata)
        engine.close()
        with self.assertRaises(ValueError):
            worker.validate_source()
        engine.load_cuw(source)
        self.assertIsNot(engine.bind_worker(second), worker)
        self.assertIsNot(engine.bind_retry_controller(), retry)
        self.assertEqual(engine.inform_result_of_query_retry(2, 1), 3005)
        engine.close()

    def test_global_boolean_callback_accepts_only_the_concrete_controller(self):
        from scripts.demo_calibration import table
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeCallbackLookupError,
            NativeGeneralParameters2026,
            NativeRuntime2026,
        )
        from tests.test_calibration_2026 import cpu_text, cuw

        folder = Path("runtime/no-car-21/recovered")
        if not (folder / "CUW.dll").is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        parameters = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": table(
                    (
                        "ParamFileKeySystemProtocolMicon",
                        "FlagToDoIGOFFONAtCPUTypeChange",
                    ),
                    (("149P5-Unified311", "1"),),
                )
            },
            encoded=False,
        )
        with CUWEngine2026(
            (folder / "CUW.dll").read_bytes(), general_parameters=parameters
        ) as engine:
            engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
            engine.load_cuw(cuw(cpu_text()))
            controller = ControlCommPhase2026(
                identity_2026(
                    (folder / "TCUWControlCommPhase.dll").read_bytes(),
                    "TCUWControlCommPhase.dll",
                ),
                NativeRuntime2026(lambda event, remaining: None),
            )
            arguments = ("149", "311", "P5-Unified", "FlagToDoIGOFFONAtCPUTypeChange")
            self.assertTrue(
                engine.general_parameter_boolean(*arguments, controller=controller)
            )
            with self.assertRaises(NativeCallbackLookupError):
                engine.general_parameter_boolean(
                    "149", "311", "P5-Unified", "Missing", controller=controller
                )
            with self.assertRaises(TypeError):
                engine.general_parameter_boolean(*arguments, controller=object())
            with self.assertRaisesRegex(ValueError, "active concrete phase"):
                engine.general_parameter_boolean(*arguments)

    def test_writer_address_groups_reject_source_and_address_substitution(self):
        from scripts.demo_calibration import table
        from scripts.programming_2026_common import bind_parameter2026
        from scripts.programming_2026_vendor import native2026_write_address_groups
        from tests.test_calibration_2026 import cpu_text, cuw

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        with CUWEngine2026(image.read_bytes()) as engine:
            engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
            metadata = engine.load_cuw(cuw(cpu_text()))
            catalog = {
                "149P5-Unified.ini": table(
                    (
                        "ParamFileKeySystemProtocolMicon",
                        "DLLFileNameForFlashWrite",
                        "GetCANIDFunctionNameForFlashWrite",
                        "CanIDForGetCID",
                    ),
                    (
                        (
                            "149P5-Unified",
                            "TCUWCanFlashWriter.dll",
                            "GetCanIDsFromParamForGetCID",
                            "07E0/07E8",
                        ),
                    ),
                )
            }
            selection = bind_parameter2026(
                metadata.source_container,
                catalog,
                "write",
                encoded=False,
                metadata_state=metadata,
            )
            groups = native2026_write_address_groups(
                metadata.source_container, selection
            )
            engine.validate_address_groups(selection, groups)
            with self.assertRaisesRegex(ValueError, "field748"):
                engine.validate_address_groups(selection, ())
            with self.assertRaisesRegex(ValueError, "field748"):
                engine.validate_address_groups(selection, list(groups))
            engine.apply_cpu_type(0, "312")
            with self.assertRaisesRegex(ValueError, "actual engine target"):
                engine.validate_address_groups(selection, groups)

    def test_large_persistence_requires_the_actual_owned_source(self):
        from scripts.cuw_large import LargeSource2026, native_large_cuw_2026
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )
        from tests.test_cuw_large import fixture

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.cuw"
            fixture(
                path,
                version=209,
                text=b"DATA",
                metadata_override=(
                    b"[Format]\nVersion=209\n[Vehicle]\nNumberOfNode=1\n"
                    b"[Node01]\nRequiredSpecReproVer=03\nNumberOfLogicalBlock=1\n"
                    b"[LogicalBlock101]\nNewCID=authored\nReproMethod=02\n"
                    b"NumberOfTargets=0\n[ReproData101]\n"
                    b"StartAddress=00001000\nLength=00000004\n"
                    b"[EraseAndReproRoutine101]\nStartAddress=00002000\n"
                    b"Length=00000004\n"
                ),
            )
            with CUWEngine2026(image.read_bytes()) as engine:
                engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
                metadata = engine.load_large_cuw(path)
                source = LargeSource2026(metadata.source_container)
                state = ReproInfoState((RecoveryCalibration(str(path), source),))
                persistence = CUWPersistence(Path(directory) / "output", state)
                engine.bind_persistence(persistence)
                self.assertIs(engine.notification, persistence.notification)
                engine.validate_persistence_binding(persistence)
                with native_large_cuw_2026(path) as independent:
                    # Identical bytes/digest cannot substitute another source lease.
                    state.calibrations[0].source_bytes = LargeSource2026(independent)
                    with self.assertRaisesRegex(ValueError, "engine-owned container"):
                        engine.validate_persistence_binding(persistence)
                state.calibrations[0].source_bytes = source
                engine.validate_persistence_binding(persistence)
                self.assertFalse((Path(directory) / "output").exists())
                engine.notification.assign(True)
                saved = Path(directory) / "output" / "Save" / path.name
                self.assertEqual(saved.stat().st_size, len(source))
                with saved.open("rb") as copied:
                    self.assertEqual(
                        hashlib.file_digest(copied, "sha256").hexdigest(),
                        engine.source_sha256,
                    )
                self.assertTrue(persistence.state.logged)
                self.assertTrue((saved.parent / "RecoveryInfo.ini").is_file())
            with self.assertRaises(ValueError):
                len(source)

    def test_multirom_progress_uses_source_partition_lengths(self):
        from scripts.demo_calibration import table
        from scripts.programming_2026_common import bind_native_parameter2026
        from tests.test_calibration_2026 import cpu_text, cuw

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        engine = CUWEngine2026(image.read_bytes())
        engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
        metadata = engine.load_cuw(cuw(cpu_text()))
        parameters = table(
            (
                "ParamFileKeySystemProtocolMicon",
                "DLLFileNameForFlashWrite",
                "EachWriteDataSize",
            ),
            (("149P5-Unified", "TCUWCanDHMultiROMFlashWriter.dll", "2\n3"),),
        )
        binding = bind_native_parameter2026(
            metadata.source_container,
            {"149P5-Unified.ini": parameters},
            "write",
            encoded=False,
        )
        state = engine.dh_state
        state.record_multirom_transfer(2, binding)
        self.assertEqual((state.transferred_bytes, state.progress), ((2,), (40,)))
        state.record_multirom_transfer(3, binding)
        self.assertEqual((state.transferred_bytes, state.progress), ((5,), (100,)))
        with self.assertRaises(ValueError):
            state.record_multirom_transfer(1, binding)
        self.assertEqual((state.transferred_bytes, state.progress), ((5,), (100,)))

    def test_shared_source_bound_notification_persists_actual_calibration(self):
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )
        from tests.test_calibration_2026 import cpu_text, cuw

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        source = cuw(cpu_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "recovery"
            persistence = CUWPersistence(
                root, ReproInfoState((RecoveryCalibration("authored.cuw", source),))
            )
            engine = CUWEngine2026(image.read_bytes())
            engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
            engine.load_cuw(source)
            with self.assertRaises(ValueError):
                _ = engine.dh_state.notification
            engine.bind_persistence(persistence)
            self.assertIs(engine.dh_state.notification, persistence.notification)
            self.assertIs(engine.suzuki_state.notification, persistence.notification)
            self.assertFalse(engine.dh_state.programming_active)
            engine.suzuki_state.notification.assign(True)
            self.assertTrue(engine.dh_state.programming_active)
            self.assertTrue(persistence.state.logged)
            self.assertEqual((root / "Save/authored.cuw").read_bytes(), source)
            self.assertTrue((root / "Save/RecoveryInfo.ini").is_file())
            engine.load_cuw(source)
            self.assertIs(engine.dh_state.notification, persistence.notification)
            self.assertTrue(engine.dh_state.programming_active)
            engine.dh_state.notification.assign(False)
            self.assertFalse(engine.suzuki_state.notification.value)
            old_state = engine.dh_state
            with self.assertRaises(ValueError):
                engine.load_cuw(cuw(cpu_text(), payloads=(b"different",)))
            self.assertIs(engine.dh_state, old_state)
            wrong = CUWPersistence(
                Path(directory) / "other",
                ReproInfoState((RecoveryCalibration("other.cuw", b"other"),)),
            )
            with self.assertRaises(ValueError):
                engine.bind_persistence(wrong)
            self.assertIs(engine.dh_state.notification, persistence.notification)
            with self.assertRaises(ValueError):
                engine.set_repro_gateway_node(1)
            self.assertEqual(engine.repro_gateway_node, 0)
            retained = engine.dh_state.notification
            persistence.state.calibrations[0].source_bytes = b"substituted"
            before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
            for operation in (
                lambda: retained.assign(True),
                lambda: persistence.last_block_notification.assign(True),
                persistence.persist,
            ):
                with self.assertRaises(ValueError):
                    operation()
                self.assertEqual(
                    {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}, before
                )

    def test_gateway_aes128_standard_vector_and_private_authentication(self):
        from scripts.cuw_2026 import GatewayAuthentication2026, _aes128_ecb_block

        self.assertEqual(
            _aes128_ecb_block(
                bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
                bytes.fromhex("00112233445566778899aabbccddeeff"),
            ),
            bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"),
        )
        for key, block in ((b"x", bytes(16)), (bytes(16), b"x")):
            with self.assertRaises(ValueError):
                _aes128_ecb_block(key, block)
        with self.assertRaises(TypeError):
            GatewayAuthentication2026("fake", bytes(16), None)
        with self.assertRaises(ValueError):
            gateway_authentication2026(b"authored not native")
        crypto = MagicMock()
        crypto.EVP_CIPHER_CTX_new.return_value = 101
        crypto.EVP_aes_128_ecb.return_value = 102
        crypto.EVP_CipherInit_ex.return_value = 0
        with (
            patch(
                "scripts.programming_2026_common.ctypes.util.find_library",
                return_value="authored",
            ),
            patch("scripts.programming_2026_common.ctypes.CDLL", return_value=crypto),
            self.assertRaises(ValueError),
        ):
            _aes128_ecb_block(bytes(16), bytes(16))
        crypto.EVP_CIPHER_CTX_free.assert_called_once_with(101)

    def test_gateway_wire_native_bytes_fault_cancellation_and_cleanup(self):
        from scripts.j2534_2026 import NativeJ2534Error2026
        from scripts.programming_2026_common import NativeRuntime2026

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        auth = gateway_authentication2026(image.read_bytes())
        self.assertNotIn("_key=", repr(auth))
        for mode in ("success", "fault", "cancel", "config_cancel", "filter_cancel"):
            calls, replies = (
                [],
                [b"\x67\x4f" + bytes(range(16)), b"\x67\x50\x34", b"\x50"],
            )
            cancellation = [False]

            def primitive(
                request,
                remaining,
                calls=calls,
                mode=mode,
                replies=replies,
                cancellation=cancellation,
            ):
                self.assertGreater(remaining, 0)
                calls.append(request)
                operation = request["operation"]
                if (operation == "control_io" and mode == "config_cancel") or (
                    operation == "start_flow_control_filter" and mode == "filter_cancel"
                ):
                    cancellation[0] = True
                if operation == "get_timeout":
                    return 1000
                if operation == "start_flow_control_filter":
                    return 7
                if operation == "write_messages":
                    if mode == "cancel":
                        cancellation[0] = True
                    return 1
                if operation == "read_specified_can_message":
                    if mode == "fault":
                        raise NativeJ2534Error2026(9)
                    return bytes.fromhex("000007585f") + replies.pop(0)
                return None

            runtime = NativeRuntime2026(
                primitive, cancelled=lambda cancellation=cancellation: cancellation[0]
            )
            if mode == "success":
                gateway_wire2026(auth, runtime)
                writes = [
                    call["data"]
                    for call in calls
                    if call["operation"] == "write_messages"
                ]
                self.assertEqual(writes[0], bytes.fromhex("000007505f274f"))
                self.assertTrue(
                    writes[1]
                    == bytes.fromhex("000007505f2750")
                    + auth.calculate(bytes(range(16))),
                    "Gateway key frame differs from the authenticated AES calculation",
                )
                self.assertEqual(writes[2:5], [bytes.fromhex("00000720a027")] * 3)
                self.assertEqual(writes[5], bytes.fromhex("000007505f1002"))
                self.assertFalse(replies)
            else:
                with self.assertRaises(
                    NativeJ2534Error2026 if mode == "fault" else InterruptedError
                ):
                    gateway_wire2026(auth, runtime)
            if mode == "config_cancel":
                self.assertEqual(
                    [call["operation"] for call in calls], ["control_io", "control_io"]
                )
            elif mode == "filter_cancel":
                self.assertEqual(
                    [call["operation"] for call in calls],
                    [
                        "control_io",
                        "start_flow_control_filter",
                        "stop_filter",
                        "control_io",
                    ],
                )
            else:
                self.assertEqual(
                    calls[-2:],
                    [
                        {
                            "operation": "control_io",
                            "ioctl": 2,
                            "parameters": ((0x1E, 1),),
                        },
                        {"operation": "stop_filter", "identifier": 7},
                    ],
                )
            self.assertEqual(runtime.close(), [])

    def test_rks_software_identity_requires_actual_encoded_configuration(self):
        fields = (
            "IFVersion",
            "SoftwareID",
            "SoftwareVersion",
            "LicenseKey",
            "SUBARU_LicenseKey",
            "SUZUKI_LicenseKey",
            "DAIHATSU_LicenseKey",
            "VehicleIdentificationNumber",
            "RequesterKind",
            "KeypairID",
            "DAIHATSU_KeypairID",
        )

        def encoded(software, missing=None):
            text = "[ReproKeyRequest]\n" + "\n".join(
                f"{name}={software if name == 'SoftwareID' else 'authored'}"
                for name in fields
                if name != missing
            )
            result = bytearray()
            for value in text.encode("latin1"):
                value = (value - 0x78) & 255
                result.extend(((value >> 4) << 2, (value & 15) << 2))
            return bytes(result)

        source = encoded("A" * 64)
        identity = rks_software_identity2026(source)
        self.assertEqual(identity.software_id64, b"A" * 64)
        self.assertEqual(identity.source_sha256, hashlib.sha256(source).hexdigest())
        self.assertNotIn("A" * 64, repr(identity))
        short = rks_software_identity2026(encoded("RKS"))
        self.assertEqual(
            short.software_id64,
            b"RKS".ljust(16, b"\0")
            + struct.pack("<II", 3, 15)
            + b"authored"
            + bytes(32),
        )
        self.assertEqual(
            rks_software_identity2026(encoded("A" * 31)).software_id64,
            (b"A" * 31).ljust(64, b"\0"),
        )
        unrecovered = rks_software_identity2026(encoded("A" * 16))
        with self.assertRaises(NotImplementedError):
            _ = unrecovered.software_id64
        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if image.is_file():
            engine = CUWEngine2026(image.read_bytes())
            first = engine.load_rks_configuration(source)
            self.assertIs(engine.load_rks_configuration(encoded("B" * 64)), first)
            self.assertEqual(engine.rks_software_identity.software_id64, b"A" * 64)
            self.assertIs(
                engine.load_rks_configuration(encoded("B" * 64, "LicenseKey")), first
            )
            self.assertFalse(engine.rks_configuration.load(b""))
            self.assertEqual(
                engine.rks_configuration.fields_snapshot()["SoftwareID"], "A" * 64
            )
            self.assertIs(engine.rks_software_identity, first)
        with self.assertRaises(TypeError):
            RKSSoftwareIdentity2026("fake", b"A" * 64, None)
        with self.assertRaises(NotImplementedError):
            rks_software_identity2026(source[:-1])
        self.assertEqual(
            rks_software_identity2026(source + b"\x20\x20" + b"trailing").software_id64,
            identity.software_id64,
        )
        for invalid in (encoded("A" * 64, "LicenseKey"),):
            with self.assertRaises(ValueError):
                rks_software_identity2026(invalid)

    def test_gateway_callback_retains_native_error_fields(self):
        from scripts.j2534_2026 import NativeJ2534Error2026
        from scripts.programming_2026_common import NativeRuntime2026
        from tests.test_calibration_2026 import cpu_text, cuw

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        engine = CUWEngine2026(image.read_bytes())
        engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
        engine.load_cuw(cuw(cpu_text()))
        engine.dh_state.record_native_error(2, 3, 7)
        for domain in ("j2534", "response"):
            calls = []

            def primitive(request, remaining, domain=domain, calls=calls):
                calls.append(request["operation"])
                if request["operation"] == "get_timeout":
                    return 1000
                if request["operation"] == "start_flow_control_filter":
                    return 9
                if request["operation"] == "write_messages":
                    return 1
                if request["operation"] == "read_specified_can_message":
                    if domain == "j2534":
                        raise NativeJ2534Error2026(9)
                    return bytes.fromhex("000007585f00")
                return None

            runtime = NativeRuntime2026(primitive)
            self.assertFalse(engine.gateway_callback(runtime))
            self.assertEqual(engine.dh_state.error_kind, 2)
            self.assertEqual(
                engine.dh_state.primary_error, 1 if domain == "j2534" else 0x10
            )
            self.assertEqual(engine.dh_state.passthru_error, 9)
            self.assertEqual(
                engine.suzuki_state.primary_error, engine.dh_state.primary_error
            )
            self.assertEqual(calls[-1], "stop_filter")
            self.assertEqual(runtime.close(), [])

    def test_before_hook_uses_global_parameters_and_actual_voltage(self):
        from scripts.demo_calibration import table
        from scripts.j2534_2026 import J2534InterfacePair2026
        from scripts.programming_2026_common import (
            NativeCallbackLookupError,
            NativeGeneralParameters2026,
        )
        from tests.test_calibration_2026 import cpu_text, cuw

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        calls = []

        def primitive(request, remaining):
            self.assertGreater(remaining, 0)
            calls.append(request)
            return PrimitiveResult(
                value=11 if request["operation"] == "passthru_open" else None
            )

        device = J2534Device2026(primitive)
        engine_device = J2534Device2026(primitive)
        pair = J2534InterfacePair2026(engine_device, device)
        with CUWEngine2026(image.read_bytes()) as engine:
            self.assertEqual(engine.process_before_reprogramming(None, None), 3008)
            engine.bind_interface_pair(pair)
            engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
            engine.load_cuw(cuw(cpu_text().replace(".vbf", ".bin")))
            for enabled in ("0", "1"):
                parameters = NativeGeneralParameters2026.from_sources(
                    {
                        "Parameter.ini": table(
                            ("ParamFileKeySystemProtocolMicon", "FlagToChangeWFSE"),
                            (("149P5-Unified", enabled),),
                        )
                    },
                    encoded=False,
                )
                if enabled == "1":
                    device.open()
                    engine_device.opened, engine_device.device_id = (
                        device.opened,
                        device.device_id,
                    )
                self.assertEqual(
                    engine.process_before_reprogramming(parameters, engine_device), 0
                )
            self.assertEqual(
                calls[-1],
                {
                    "operation": "passthru_voltage",
                    "device": 11,
                    "pin": 15,
                    "voltage": 0xFFFFFFFE,
                },
            )
            engine.load_cuw(cuw(cpu_text()))
            engine_device.set_programming_voltage(15, 0xFFFFFFFF)
            count = len(calls)
            with self.assertRaises(NotImplementedError):
                engine.process_before_reprogramming(parameters, engine_device)
            self.assertEqual(len(calls), count + 1)
            self.assertEqual(calls[-1]["operation"], "passthru_voltage")
            self.assertEqual(calls[-1]["voltage"], 0xFFFFFFFE)
            missing = NativeGeneralParameters2026.from_sources(
                {
                    "Parameter.ini": table(
                        ("ParamFileKeySystemProtocolMicon",), (("other",),)
                    )
                },
                encoded=False,
            )
            with (
                patch.object(engine, "check_j2534_connection") as check,
                self.assertRaises(NativeCallbackLookupError) as caught,
            ):
                engine.process_before_reprogramming(missing, engine_device)
            check.assert_not_called()
            self.assertEqual(caught.exception.code, 2)
            self.assertFalse(engine.native_cancelled())
        engine_device.close()
        device.close()

    def test_before_hook_normal_native_voltage_errors_use_canonical_catch(self):
        from scripts.demo_calibration import table
        from scripts.j2534_2026 import J2534InterfacePair2026, NativeJ2534Error2026
        from scripts.programming_2026_common import NativeGeneralParameters2026
        from tests.test_calibration_2026 import cpu_text, cuw

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        parameters = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": table(
                    ("ParamFileKeySystemProtocolMicon", "FlagToChangeWFSE"),
                    (("149P5-Unified", "1"),),
                )
            },
            encoded=False,
        )

        for status, expected in ((0, 3008), (0xFA3, 0xFA3)):
            with (
                self.subTest(status=status),
                CUWEngine2026(image.read_bytes()) as engine,
            ):
                engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
                engine.load_cuw(cuw(cpu_text().replace(".vbf", ".bin")))

                def native_provider(request, _remaining):
                    if request["operation"] == "passthru_open":
                        return PrimitiveResult(value=11)
                    if request["operation"] == "passthru_voltage":
                        raise NativeJ2534Error2026(9)
                    return PrimitiveResult()

                control = J2534Device2026(native_provider)
                engine_device = J2534Device2026(native_provider)
                engine.bind_interface_pair(
                    J2534InterfacePair2026(engine_device, control)
                )
                control.open()
                engine_device.opened, engine_device.device_id = (
                    control.opened,
                    control.device_id,
                )
                with patch.object(
                    engine, "check_j2534_connection", return_value=status
                ) as check:
                    self.assertEqual(
                        engine.process_before_reprogramming(parameters, engine_device),
                        expected,
                    )
                check.assert_called_once_with()
                control.close()
                engine_device.close()

        with CUWEngine2026(image.read_bytes()) as engine:
            engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
            engine.load_cuw(cuw(cpu_text().replace(".vbf", ".bin")))
            fault = OSError("host voltage fault")

            def host_provider(request, _remaining):
                if request["operation"] == "passthru_open":
                    return PrimitiveResult(value=11)
                if request["operation"] == "passthru_voltage":
                    raise fault
                return PrimitiveResult()

            control = J2534Device2026(host_provider)
            engine_device = J2534Device2026(host_provider)
            engine.bind_interface_pair(J2534InterfacePair2026(engine_device, control))
            control.open()
            engine_device.opened, engine_device.device_id = (
                control.opened,
                control.device_id,
            )
            with (
                patch.object(engine, "check_j2534_connection") as check,
                self.assertRaises(OSError) as caught,
            ):
                engine.process_before_reprogramming(parameters, engine_device)
            self.assertIs(caught.exception, fault)
            check.assert_not_called()
            control.close()
            engine_device.close()

    def test_vbf_prepare_prefix_rejects_a_forged_receipt(self):
        from scripts.programming_2026_common import NativeRuntime2026
        from tests.test_calibration_2026 import cpu_text, cuw
        from tests.test_cuw_engine_worker import make_controller

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        with CUWEngine2026(image.read_bytes()) as engine:
            engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
            engine.load_cuw(cuw(cpu_text()))
            controller = make_controller(NativeRuntime2026(lambda *_args: None))
            job = engine.bind_thread_job(controller)
            self.addCleanup(job.stop)
            with (
                self.assertRaises(TypeError),
                engine.prepare_vbf_resume_execution(job, object()),
            ):
                self.fail("A caller-created receipt must never own36800")

    def test_outstanding_vbf_receipt_blocks_ordinary_engine_admission(self):
        from scripts.programming_2026_common import NativeRuntime2026
        from tests.test_calibration_2026 import cpu_text, cuw
        from tests.test_cuw_engine_worker import make_controller

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        with CUWEngine2026(image.read_bytes()) as engine:
            engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
            engine.load_cuw(cuw(cpu_text()))
            controller = make_controller(NativeRuntime2026(lambda *_args: None))
            job = engine.bind_thread_job(controller)
            self.addCleanup(job.stop)
            with patch(
                "scripts.cuw_engine_threads._has_vbf_request2026", return_value=True
            ):
                with self.assertRaisesRegex(ValueError, "VBF resume"):
                    engine.reserve_phase(controller, 0)
                with (
                    self.assertRaisesRegex(ValueError, "VBF resume"),
                    engine.controller_execution(controller, 0),
                ):
                    self.fail("Ordinary phase must not bypass a VBF receipt")

            lease = engine.reserve_phase(controller, 0)
            with (
                patch(
                    "scripts.cuw_engine_threads._has_vbf_request2026",
                    return_value=True,
                ),
                self.assertRaisesRegex(ValueError, "VBF resume"),
                engine.controller_execution(controller, 0, lease=lease),
            ):
                self.fail("An old ordinary lease must not bypass a VBF receipt")
            engine.release_reserved_phase(lease)

    def test_before_hook_vbf_literal_and_native_catch_boundary(self):
        from scripts.demo_calibration import table
        from scripts.j2534_2026 import J2534InterfacePair2026, NativeJ2534Error2026
        from scripts.programming_2026_common import NativeGeneralParameters2026
        from tests.test_calibration_2026 import cpu_text, cuw

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        parameters = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": table(
                    ("ParamFileKeySystemProtocolMicon", "FlagToChangeWFSE"),
                    (("149P5-Unified", "1"),),
                )
            },
            encoded=False,
        )

        with CUWEngine2026(image.read_bytes()) as engine:
            engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
            engine.load_cuw(cuw(cpu_text().replace(".vbf", ".VBF")))
            calls = []

            def provider(request, _remaining):
                calls.append(request["operation"])
                return PrimitiveResult(
                    value=11 if request["operation"] == "passthru_open" else None
                )

            control = J2534Device2026(provider)
            engine_device = J2534Device2026(provider)
            engine.bind_interface_pair(J2534InterfacePair2026(engine_device, control))
            control.open()
            engine_device.opened, engine_device.device_id = (
                control.opened,
                control.device_id,
            )
            self.assertEqual(
                engine.process_before_reprogramming(parameters, engine_device), 0
            )
            self.assertEqual(calls.count("passthru_voltage"), 1)
            control.close()
            engine_device.close()

        for status, expected in ((0, 3008), (0xFA3, 0xFA3)):
            with (
                self.subTest(status=status),
                CUWEngine2026(image.read_bytes()) as engine,
            ):
                engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
                engine.load_cuw(cuw(cpu_text()))

                def native_provider(request, _remaining):
                    if request["operation"] == "passthru_open":
                        return PrimitiveResult(value=11)
                    if request["operation"] == "passthru_voltage":
                        raise NativeJ2534Error2026(9)
                    return PrimitiveResult()

                control = J2534Device2026(native_provider)
                engine_device = J2534Device2026(native_provider)
                engine.bind_interface_pair(
                    J2534InterfacePair2026(engine_device, control)
                )
                control.open()
                engine_device.opened, engine_device.device_id = (
                    control.opened,
                    control.device_id,
                )
                with patch.object(
                    engine, "check_j2534_connection", return_value=status
                ) as check:
                    self.assertEqual(
                        engine.process_before_reprogramming(parameters, engine_device),
                        expected,
                    )
                check.assert_called_once_with()
                control.close()
                engine_device.close()

        with CUWEngine2026(image.read_bytes()) as engine:
            engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
            engine.load_cuw(cuw(cpu_text()))
            sentinel = OSError("native-looking provider failure is still host-owned")

            def host_provider(request, _remaining):
                if request["operation"] == "passthru_open":
                    return PrimitiveResult(value=11)
                if request["operation"] == "passthru_voltage":
                    raise sentinel
                return PrimitiveResult()

            control = J2534Device2026(host_provider)
            engine_device = J2534Device2026(host_provider)
            engine.bind_interface_pair(J2534InterfacePair2026(engine_device, control))
            control.open()
            engine_device.opened, engine_device.device_id = (
                control.opened,
                control.device_id,
            )
            with (
                patch.object(engine, "check_j2534_connection") as check,
                self.assertRaises(OSError) as caught,
            ):
                engine.process_before_reprogramming(parameters, engine_device)
            self.assertIs(caught.exception, sentinel)
            check.assert_not_called()
            control.close()
            engine_device.close()

    def test_engine_capacity_and_progress_use_all_native_nodes(self):
        from tests.test_calibration_2026 import cuw

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        source = cuw(
            "[Format]\nVersion=101\n[Vehicle]\nNumberOfNode=2\n"
            "ContactType=Phase6\nKindOfECU=149\n"
            "[Node01]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\n"
            "[Node02]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\n"
            "[CPU11]\nCPUType=311\nCPUImageName=first.vbf\n"
            "[CPU21]\nCPUType=312\nCPUImageName=second.vbf\n",
            payloads=(b"one", b"two"),
        )
        for maximum in (1, 2):
            with CUWEngine2026(image.read_bytes()) as engine:
                engine.configure(struct.pack("<IIddII", maximum, 0, 0, 0, 0, 0))
                if maximum == 1:
                    with self.assertRaises(ValueError):
                        engine.load_cuw(source, node=2)
                    self.assertIsNone(engine.source_sha256)
                    continue
                engine.load_cuw(source, node=2)
                state = engine.dh_state
                self.assertEqual(
                    (
                        state.selection_cpu_index,
                        state.cpu_index,
                        state.global_cpu_index,
                    ),
                    (0, 1, 1),
                )
                state.record_dh_transfer(3, 3, 3, verification=False, checksum=True)
                self.assertEqual(state.transferred_bytes, (0, 3))
                self.assertEqual(state.progress, (0, 100))
                from scripts.calibration_2026 import native2026_cpu_type

                engine.apply_cpu_type(0, "first-alternate")
                engine.apply_cpu_type(1, "second-alternate")
                other = engine.metadata_for(1, 0)
                self.assertEqual(native2026_cpu_type(other, 0), "first-alternate")
                self.assertEqual(native2026_cpu_type(other, 1), "second-alternate")
                self.assertEqual((state.node, state.global_cpu_index), (2, 1))
                state.record_gateway_count(1, 3)
                self.assertEqual(state.transferred_bytes, (1, 3))
                from scripts.demo_calibration import table
                from scripts.programming_2026_common import bind_native_parameter2026

                binding = bind_native_parameter2026(
                    state.metadata.source_container,
                    {
                        f"149Phase6{cpu_type}.ini": table(
                            (
                                "ParamFileKeySystemProtocolMicon",
                                "DLLFileNameForFlashWrite",
                                "EachWriteDataSize",
                            ),
                            (
                                (
                                    f"149Phase6{cpu_type}",
                                    "TCUWCanDHMultiROMFlashWriter.dll",
                                    "2\n3",
                                ),
                            ),
                        )
                        for cpu_type in ("first-alternate", "second-alternate")
                    },
                    "write",
                    node=2,
                    encoded=False,
                    metadata_state=state.metadata,
                )
                state.record_multirom_transfer(1, binding)
                self.assertEqual(state.transferred_bytes, (2, 3))
                self.assertEqual(state.progress, (40, 100))
                from scripts.programming_2026_common import (
                    ControlCommPhase2026,
                    NativeRuntime2026,
                )

                controller = ControlCommPhase2026(
                    identity_2026(
                        Path(
                            "runtime/no-car-21/recovered/TCUWControlCommPhase.dll"
                        ).read_bytes(),
                        "TCUWControlCommPhase.dll",
                    ),
                    NativeRuntime2026(lambda request, remaining: None),
                )
                engine.select_target(1, 0, controller=controller)
                self.assertIs(engine.dh_state, state)
                self.assertEqual((state.node, state.global_cpu_index), (1, 0))
                self.assertEqual(state.transferred_bytes, (2, 3))
                self.assertEqual(engine.suzuki_state.global_cpu_index, 0)
                self.assertEqual(
                    engine.calibration_export().cpu_types,
                    ("first-alternate", "second-alternate"),
                )
                with self.assertRaises(ValueError):
                    engine.select_target(1, 9, controller=controller)
                self.assertEqual((state.node, state.global_cpu_index), (1, 0))

    def test_after_hook_concrete_control_comm_query_disconnect_and_fault(self):
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeRuntime2026,
        )

        image = Path("runtime/no-car-21/recovered/TCUWControlCommPhase.dll")
        if not image.is_file():
            self.skipTest("Authenticated static ControlCommPhase image is absent")
        identity = identity_2026(image.read_bytes(), "TCUWControlCommPhase.dll")
        for sending in (False, True):
            calls = []

            def primitive(request, remaining, calls=calls, sending=sending):
                self.assertGreater(remaining, 0)
                calls.append(request["operation"])
                if request["operation"] == "is_sending_sync_periodic":
                    return sending
                return None

            controller = ControlCommPhase2026(identity, NativeRuntime2026(primitive))
            self.assertEqual(process_after_reprogramming(controller), 0)
            self.assertEqual(
                calls,
                ["is_sending_sync_periodic"] + (["disconnect"] if sending else []),
            )
        controller = ControlCommPhase2026(
            identity, NativeRuntime2026(lambda request, remaining: 1)
        )
        with self.assertRaises(ValueError):
            process_after_reprogramming(controller)
        with self.assertRaises(TypeError):
            process_after_reprogramming(object())

    def test_source_bound_engine_load_transaction_and_phase_guards(self):
        with self.assertRaises(ValueError):
            CUWEngine2026(b"authored bytes are not a native engine")
        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated static CUW2026 image is not present")
        engine = CUWEngine2026(image.read_bytes())
        self.assertEqual(engine.common_definitions.num_cpu_maxnum, 0)
        self.assertEqual(engine.judge_usb_repro_suzuki(), (9101, False))
        with self.assertRaises(ValueError):
            _ = engine.dh_state
        with self.assertRaises(TypeError):
            DHControllerState2026(None, None, None, 0)
        with self.assertRaises(TypeError):
            SuzukiControllerState2026(None, None, None)
        configuration = struct.pack("<IIddII", 1, 0, 1, 2, 0, 0)
        text = (
            b"[Format]\nVersion=10\n[Vehicle]\nNumberOfCalibration=1\n"
            b"ContactType=P5-Unified\nKindOfECU=149\n"
            b"ByteNumberOfTransmitting=FFF\n"
            b"[CPU01]\nCPUType=311\nCPUImageName=authored.vbf\n"
        )

        def record(header, data):
            return (
                struct.pack(">H", len(header))
                + header
                + struct.pack(">II", len(data), zlib.crc32(data))
                + data
            )

        body = record(b"attach.att", text) + b"\x01" + record(b"authored", b"data")
        suffix = struct.pack(">I", 22 + len(body)) + body
        source = b"\0CALIBRATION\0\x68" + struct.pack(">I", zlib.crc32(suffix)) + suffix
        with self.assertRaises(ValueError):
            engine.load_cuw(source)
        engine.configure(configuration)
        self.assertEqual(engine.common_definitions.num_cpu_maxnum, 1)
        metadata = engine.load_cuw(source)
        self.assertEqual(engine.judge_usb_repro_suzuki(), (0, False))
        state = engine.dh_state
        self.assertIs(state.metadata, metadata)
        self.assertEqual(
            (state.progress, state.getter_stage, state.writable_cid), ((0,), 0, False)
        )
        with self.assertRaises(ValueError):
            state.advance_getter_stage(0, 2)
        for stage in range(4):
            state.advance_getter_stage(stage, stage + 1)
        self.assertEqual(state.getter_stage, 4)
        with self.assertRaises(ValueError):
            state.advance_getter_stage(4, 5)
        state.mark_writable_cid()
        self.assertTrue(state.writable_cid)
        state.record_dh_transfer(4, 4, 4, verification=False, checksum=False)
        self.assertEqual((state.transferred_bytes, state.progress), ((4,), (50,)))
        state.record_dh_transfer(2, 2, 4, verification=True, checksum=False)
        self.assertEqual((state.transferred_bytes, state.progress), ((6,), (75,)))
        state.record_dh_transfer(2, 4, 4, verification=True, checksum=False)
        self.assertEqual((state.transferred_bytes, state.progress), ((8,), (100,)))
        with self.assertRaises(ValueError):
            state.record_dh_transfer(1, 1, 5, verification=False, checksum=True)
        self.assertEqual((state.transferred_bytes, state.progress), ((8,), (100,)))
        state.reset_dh_count()
        self.assertEqual((state.transferred_bytes, state.progress), ((0,), (100,)))
        state.reset_dh_progress()
        self.assertEqual((state.transferred_bytes, state.progress), ((0,), (0,)))
        state.record_gateway_count(3, 4)
        self.assertEqual((state.transferred_bytes, state.progress), ((3,), (0,)))
        state.record_gateway_progress(3, 4)
        self.assertEqual((state.transferred_bytes, state.progress), ((3,), (75,)))
        state.record_gateway_count(1, 4)
        self.assertEqual(state.transferred_bytes, (1,))
        with self.assertRaises(ValueError):
            state.record_gateway_progress(3, 5)
        self.assertEqual(state.progress, (75,))
        state.reset_dh_count()
        state.record_uds_transfer(2)
        self.assertEqual((state.transferred_bytes, state.progress), ((2,), (50,)))
        state.record_uds_transfer(4)
        self.assertEqual((state.transferred_bytes, state.progress), ((6,), (150,)))
        state.set_native_count(0, 3)
        state.set_native_percentage(0, 7)
        self.assertEqual((state.transferred_bytes, state.progress), ((3,), (7,)))
        with self.assertRaises(ValueError):
            state.set_native_percentage(1, 100)
        state.reset_usb_progress()
        with self.assertRaises(ValueError):
            state.complete_usb_progress(b"\x5a\xb1\x01")
        self.assertEqual(state.progress, (0,))
        state.complete_usb_progress(b"\x5a\xb1\x00")
        self.assertEqual(state.progress, (100,))
        self.assertFalse(state.native_context_964)
        state.mark_native_retry()
        self.assertTrue(engine.suzuki_state.native_context_964)
        self.assertEqual(state.comm_phase, 0)
        state.mark_flash_code_failed()
        self.assertEqual(state.comm_phase, 1)
        self.assertIsNone(engine.worker_phase)
        with self.assertRaises(ValueError):
            state.advance_divided_image(0)
        self.assertEqual(state.divided_image_index, 0)
        self.assertFalse(engine.write_complete_output)
        state.set_write_complete(True)
        self.assertFalse(engine.write_complete_output)
        engine.notify_write_complete()
        self.assertTrue(engine.write_complete_output)
        state.set_write_complete(False)
        self.assertTrue(engine.write_complete_output)
        engine.notify_write_complete()
        self.assertFalse(engine.write_complete_output)
        state.set_flashing_ended(True)
        state.set_use_new_password(True)
        self.assertTrue(state.flashing_ended)
        self.assertTrue(state.use_new_password)
        with self.assertRaises(TypeError):
            state.set_write_complete(1)  # pyright: ignore[reportArgumentType]
        state.record_native_error(2, 1, 9)
        self.assertEqual(
            (state.error_kind, state.primary_error, state.passthru_error), (2, 1, 9)
        )
        state.record_native_error(None, 0x23)
        self.assertEqual(
            (state.error_kind, state.primary_error, state.passthru_error), (2, 0x23, 9)
        )
        self.assertEqual(engine.suzuki_state.primary_error, 0x23)
        engine.suzuki_state.record_native_error(None, 0x24)
        self.assertEqual(
            (state.error_kind, state.primary_error, state.passthru_error), (2, 0x24, 9)
        )
        self.assertEqual(engine.native_error_kind_output, 0)
        self.assertEqual(engine.native_previous_error_kind_output, 0)
        engine.notify_native_error_kind()
        self.assertEqual(engine.native_error_kind_output, 2)
        self.assertEqual(engine.native_recovery_status(), 2)
        self.assertEqual(engine.native_recovery_status(previous=True), 0)
        copied_kind = 2
        for kind, expected in ((4, 2), (5, 2), (0xFFFFFFFF, -1), (3, 3)):
            state.record_native_error(kind, 0x24, 9)
            self.assertEqual(engine.native_error_kind_output, copied_kind)
            engine.notify_native_error_kind()
            copied_kind = kind
            self.assertEqual(engine.native_recovery_status(), expected)
        state.record_native_error(2, 0x24, 9)
        engine.notify_native_error_kind()
        self.assertEqual(engine.native_error_output, (0, 0))
        engine.notify_native_errors(13)
        self.assertEqual(engine.native_error_output, (0x24, 9))
        engine.suzuki_state.record_native_error(None, 0x25)
        self.assertEqual(engine.native_error_output, (0x24, 9))
        engine.notify_native_errors(9999)
        self.assertEqual(engine.native_error_output, (0x25, 9))
        with self.assertRaises(ValueError):
            state.record_native_error(1, -1, 0)
        self.assertEqual(state.error_kind, 2)
        self.assertFalse(state.alternate_can_address)
        self.assertEqual(state.central_gateway_type, 0)
        for value in (1, 2):
            state.set_central_gateway_type(value)
            self.assertEqual(state.central_gateway_type, value)
        for value in (0, 3, True):
            with self.assertRaises(ValueError):
                state.set_central_gateway_type(value)
        suzuki = engine.suzuki_state
        self.assertEqual(suzuki.value, 0)
        suzuki.compare_prepare_cid(b"hw_sw_ver", b"hw_sw_ver")
        self.assertEqual(suzuki.value, 0)
        suzuki.compare_prepare_cid(b"hw_sw_ver", b"hw_sw_new")
        self.assertEqual(suzuki.value, 1)
        with self.assertRaises(ValueError):
            suzuki.compare_prepare_cid(b"hw\0", b"hw")
        self.assertEqual(suzuki.value, 1)
        suzuki.clear_after_prepare_fault()
        self.assertEqual(suzuki.value, 0)
        suzuki.mark_usb_retry_fault()
        self.assertEqual(suzuki.value, 2)
        self.assertEqual(metadata.source_sha256, hashlib.sha256(source).hexdigest())
        self.assertEqual(engine.source_sha256, metadata.source_sha256)
        original_sections = metadata.sections
        engine.apply_cpu_type(0, "alternate")
        engine.apply_shrink_flag(True)
        selected = engine.metadata_for(1, 0)
        from scripts.calibration_2026 import native2026_cpu_type

        self.assertEqual(native2026_cpu_type(selected, 0), "alternate")
        self.assertEqual(selected.sections, original_sections)
        self.assertIs(engine.dh_state.metadata, engine.native_metadata)
        self.assertIs(engine.suzuki_state.metadata, engine.native_metadata)
        self.assertEqual(engine.calibration_export().cpu_types, ("alternate",))
        self.assertTrue(engine.calibration_export().shrink_flag)
        self.assertEqual(selected.source_sha256, metadata.source_sha256)
        with self.assertRaises(ValueError):
            engine.metadata_for(1, 1)
        self.assertEqual(engine.calibration_export().cpu_types, ("alternate",))
        with self.assertRaises(TypeError):
            engine.apply_shrink_flag(1)  # pyright: ignore[reportArgumentType]
        with self.assertRaises(ValueError):
            engine.load_cuw(source[:-1])
        self.assertIs(engine.dh_state, state)
        self.assertEqual(engine.source_sha256, metadata.source_sha256)
        with self.assertRaises(CUWEngineError) as caught:
            engine.configure(configuration)
        self.assertEqual(caught.exception.code, 7)
        self.assertEqual(engine.common_definitions.num_cpu_maxnum, 1)
        with self.assertRaises(TypeError):
            engine.run_phase(0, object())
        self.assertFalse(engine.cancel())
        self.assertFalse(engine.active)
        text = text.replace(b"Version=10", b"Version=12").replace(
            b"KindOfECU=149", b"KindOfECU=0795"
        )
        body = record(b"attach.att", text) + b"\x01" + record(b"authored", b"data")
        suffix = struct.pack(">I", 22 + len(body)) + body
        source = b"\0CALIBRATION\0\x68" + struct.pack(">I", zlib.crc32(suffix)) + suffix
        engine.load_cuw(source)
        self.assertEqual(engine.judge_usb_repro_suzuki(), (0, True))
        self.assertIsNot(engine.dh_state, state)
        self.assertEqual(engine.dh_state.getter_stage, 0)
        self.assertFalse(engine.dh_state.writable_cid)
        self.assertEqual(engine.suzuki_state.value, 0)

    def test_public_device_protocol_and_concrete_passthru_binding(self):
        self.assertEqual(
            [
                native_protocol(value, "02")
                for value in ("SIL", "Ethernet", "P5-Unified", "Phase6", "CAN")
            ],
            [3, 0x800F, 0x8012, 0x8012, 6],
        )
        self.assertEqual(native_protocol("Phase6", "CANFD"), 6)
        calls = []

        def provider(request, remaining):
            self.assertGreater(remaining, 0)
            calls.append(request)
            if request["operation"] == "get_symbol":
                return PrimitiveResult(
                    value=0 if request["name"] == "_GtsNewVimFixInterface@8" else 9
                )
            return PrimitiveResult(
                value={
                    "passthru_open": 11,
                    "passthru_connect": 22,
                    "passthru_scan_devices": 1,
                    "passthru_next_device": "fake0500",
                    "passthru_connect_0500": 33,
                    "create_mutex": 5,
                    "wait_handle": 0,
                    "load_library": 7,
                    "passthru_read_version": ("authored firmware", "driver", "04.04"),
                }.get(request["operation"])
            )

        device = J2534Device2026(provider)
        self.assertEqual(connect_j2534(None, "CAN"), 4007)
        self.assertEqual(connect_j2534(device, None), 4007)
        self.assertFalse(calls)
        device.open()
        self.assertEqual(connect_j2534(device, "CAN"), 0)
        self.assertEqual(
            calls[-1],
            {
                "operation": "passthru_connect",
                "device": 11,
                "protocol": 6,
                "flags": 0x900,
                "baud": 500000,
            },
        )
        self.assertEqual(device.timeout, 1000)
        self.assertEqual(disconnect_j2534(device), 0)
        self.assertEqual(disconnect_j2534(device), 4008)
        self.assertEqual(
            [row["operation"] for row in calls[-2:]],
            ["passthru_disconnect", "passthru_close"],
        )
        device = J2534Device2026(provider)
        device.open()
        before = len(calls)
        with self.assertRaises(ValueError):
            connect_j2534(device, "Ethernet")
        self.assertEqual(len(calls), before)
        device.disconnect()
        device = J2534Device2026(provider)
        device.version = 1
        device.open()
        self.assertEqual(connect_j2534(device, "Ethernet"), 0)
        self.assertEqual(device.channel_id, 33)
        self.assertEqual(calls[-1]["operation"], "passthru_connect_0500")
        self.assertEqual(calls[-1]["resources"], (1, 4, (3, 11, 12, 13)))
        disconnect_j2534(device)
        calls.clear()
        device = J2534Device2026(provider)
        device.set_driver(DriverMetadata2026("Authored offline driver", "fixture.dll"))
        self.assertEqual(connect_j2534(device, "CAN"), 0)
        operations = [request["operation"] for request in calls]
        self.assertEqual(operations[:2], ["create_mutex", "wait_handle"])
        self.assertLess(
            operations.index("load_library"), operations.index("passthru_open")
        )
        self.assertEqual(operations[-1], "passthru_connect")
        self.assertEqual(device.channel_id, 22)
        self.assertTrue(device.driver_loaded)
        disconnect_j2534(device)

    def test_native_vin_and_conversion_row_mutations(self):
        self.assertEqual(native_vin(b"ABC?TAIL"), b"ABC")
        self.assertEqual(native_vin(b"ABC\xffTAIL"), b"ABC")
        self.assertEqual(native_vin(b"ABC\0TAIL"), b"ABC")
        with self.assertRaises(CUWEngineError):
            native_vin(b"?" + b"A" * 17)
        row = b"12af" + b"-----" + b"CALIBRATION\0"
        self.assertEqual(len(row), 21)
        self.assertEqual(id_conversion_rows(row, 1), ((0x12AF, b"CALIBRATION"),))
        self.assertEqual(
            id_conversion_rows(b"xyz!" + row[4:], 1), ((0, b"CALIBRATION"),)
        )
        self.assertEqual(
            id_conversion_rows(b" -1 " + row[4:], 1), ((65535, b"CALIBRATION"),)
        )
        self.assertIsNone(id_conversion_rows(b"", 0))
        with self.assertRaises(ValueError):
            id_conversion_rows(row[:-1] + b"x", 1)

    def test_native_configuration_stack_layout_and_loaded_guard(self):
        raw = struct.pack("<IIddII", 3, 0xDEADBEEF, 12.5, -1.25, 0x00030201, 0xAABBCCDD)
        value = configure_2026(raw)
        self.assertEqual(
            (value.cpu_maximum, value.scalar_a, value.scalar_b, value.flags),
            (3, 12.5, -1.25, (1, 2, 3)),
        )
        self.assertEqual(value.arguments, raw)
        self.assertEqual(value.zero_counters, ((0, 0, 0),) * 4)
        self.assertEqual(value.unresolved_source_indices, ((-1, -1, -1),) * 16)
        self.assertEqual(value.cpu_flags, (False, False, False))
        self.assertEqual(value.source_cpu_flags, ((False, False, False),) * 16)
        with self.assertRaises(CUWEngineError) as caught:
            configure_2026(raw, calibration_loaded=True)
        self.assertEqual(caught.exception.code, 7)
        for bad in (b"short", struct.pack("<IIddII", 0xFFFFFFFF, 0, 0, 0, 0, 0)):
            with self.assertRaises(ValueError):
                configure_2026(bad)

    def test_native_usb_copy_region_crc_and_status(self):
        source = b"prefix" + b"\x12\x34\x56\x78" + b"payload\0" + b"tail"
        result = usb_payload_bytes(
            source, offset=10, length=8, crc_offset=6, expected_crc=0x12345678
        )
        self.assertEqual(result, b"payload\0")
        self.assertEqual(source, b"prefix\x12\x34\x56\x78payload\0tail")
        for fields in (
            {"offset": 999},
            {"length": 0},
            {"crc_offset": 999},
            {"expected_crc": 0x87654321},
        ):
            inputs = {
                "offset": 10,
                "length": 8,
                "crc_offset": 6,
                "expected_crc": 0x12345678,
            }
            inputs.update(fields)
            with self.assertRaises(ValueError):
                usb_payload_bytes(
                    source,
                    offset=inputs["offset"],
                    length=inputs["length"],
                    crc_offset=inputs["crc_offset"],
                    expected_crc=inputs["expected_crc"],
                )
        with self.assertRaises(InterruptedError):
            usb_payload_bytes(
                source,
                offset=10,
                length=8,
                crc_offset=6,
                expected_crc=0x12345678,
                cancelled=lambda: True,
            )
        self.assertEqual([usb_copy_status(i) for i in range(5)], [9106, 1, 9105, 0, 0])

    def test_literal_public_engine_status_priorities(self):
        base = EngineStatus2026()
        self.assertEqual(base.receiving_status(), (0, False))
        for fields, expected in (
            ({"error": 2, "fatal": True, "phase": 1}, (4004, False)),
            ({"fatal": True}, (2002, True)),
            ({"phase": 1, "receiving": True}, (5003, False)),
            ({"receiving": True, "receiving_prompt": True}, (1, False)),
            ({"receiving_prompt": True, "error": 3}, (2, False)),
            ({"error": 3}, (5004, True)),
        ):
            self.assertEqual(replace(base, **fields).receiving_status(), expected)
        self.assertEqual(replace(base, receiving=True).receiving_result_status(), 5005)
        self.assertEqual(
            replace(base, receiving=True, phase=1).receiving_result_status(), 0
        )
        for fields, expected in (
            ({}, (3002, False)),
            ({"fatal": True}, (2002, True)),
            ({"phase": 1, "key_handle": True, "key_state": 2, "error": 96}, (3, False)),
            ({"phase": 1, "error": 96}, (7012, False)),
            ({"phase": 1, "recovery_status": 2}, (3004, True)),
            ({"phase": 1, "recovery_status": 1}, (3003, True)),
            ({"phase": 1, "recovery_status": 1, "error": 1032}, (9100, False)),
            ({"phase": 1, "recovery_status": 3}, (3002, False)),
            ({"phase": 1, "battery_cycle": True, "complete": True}, (2, False)),
            ({"complete": True}, (0, False)),
            (
                {
                    "phase": 1,
                    "configured_authorization": True,
                    "contact_type": "Phase6",
                },
                (4, False),
            ),
            (
                {
                    "phase": 1,
                    "configured_authorization": True,
                    "contact_type": "Phase6",
                    "receiving": True,
                },
                (1, False),
            ),
            (
                {"phase": 1, "configured_authorization": True, "contact_type": "CAN"},
                (1, False),
            ),
        ):
            self.assertEqual(replace(base, **fields).reprogramming_status(), expected)
        expected = (7002, 2, 1, 1, 3, 4, 7011, 7004, 7010, 7005, 7003, 7002)
        self.assertEqual(
            tuple(
                replace(base, key_handle=True, key_state=state).key_request_status()
                for state in range(12)
            ),
            expected,
        )
        self.assertFalse(
            replace(base, receiving=True).clear_status_allowed(True, controller_mode=0)
        )
        self.assertTrue(
            replace(base, receiving=True).clear_status_allowed(False, controller_mode=1)
        )
        self.assertFalse(
            replace(base, phase=2).clear_status_allowed(False, controller_mode=0)
        )
        self.assertTrue(
            replace(base, phase=2).clear_status_allowed(True, controller_mode=0)
        )
        with self.assertRaises(ValueError):
            EngineStatus2026(phase=True)

    def test_native_vehicle_memory_both_formats_and_output(self):
        base = 0x10000000
        memory = bytearray(2048)
        cursor = 256

        def string(offset, value):
            nonlocal cursor
            data = value.encode("shift_jis") + b"\0"
            memory[cursor : cursor + len(data)] = data
            struct.pack_into("<I", memory, offset, base + cursor)
            cursor += len(data)

        for offset, value in (
            (0, "SW"),
            (4, "ID"),
            (8, "VIN"),
            (20, "DCM"),
            (24, "LOCAL"),
            (28, "HASH"),
        ):
            string(offset, value)
        struct.pack_into("<II", memory, 12, 1, base + 64)
        for offset, value in zip(
            range(64, 84, 4), ("ASSY", "HW", "CAN", "7E0", "日本語"), strict=True
        ):
            string(offset, value)
        for offset, pointer in ((84, 112), (92, 120), (100, 128)):
            struct.pack_into("<II", memory, offset, 1, base + pointer)
        string(112, "SWIN")
        string(120, "CALIB")
        string(124, "1")
        string(128, "BEST")
        source = bytes(memory)
        value = vehicle_info_from_memory(
            source, base, 1, encoding="shift_jis", base=base
        )
        self.assertEqual(set(value["reqData"]), {"vinNo", "ecuInfo", "ifHash"})
        ecu = value["reqData"]["ecuInfo"][0]
        self.assertEqual(ecu["serialNo"], "日本語")
        self.assertEqual(ecu["swinList"], [{"swin": "SWIN"}])
        self.assertEqual(ecu["swNoList"], [{"swNo": "CALIB", "writeFlg": "1"}])
        self.assertEqual(ecu["cBest"], [{"cBestData": "BEST"}])
        newer = vehicle_info_from_memory(
            source, base, 0, encoding="shift_jis", base=base
        )
        self.assertEqual(newer["reqData"]["dcmLocalWriteTime"], "DCM")
        self.assertEqual(newer["reqData"]["localWriteTime"], "LOCAL")
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "vehicle.json"
            self.assertTrue(
                export_vehicle_info(
                    target, source, base, 1, encoding="shift_jis", base=base
                )
            )
            before = target.read_bytes()
            self.assertEqual(json.loads(before), value)
            self.assertFalse(before.startswith(b"\xef\xbb\xbf"))
            self.assertFalse(
                export_vehicle_info(
                    target, source, base, 0, encoding="shift_jis", base=base
                )
            )
            self.assertEqual(target.read_bytes(), before)
        self.assertEqual(bytes(memory), source)
        for offset, bad in ((12, 4097), (16, base + len(memory) + 1), (84, 4097)):
            mutated = bytearray(source)
            struct.pack_into("<I", mutated, offset, bad)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                vehicle_info_from_memory(
                    bytes(mutated), base, 1, encoding="shift_jis", base=base
                )

    def test_header_and_exact_native_strip(self):
        body = archive([("folder/a.bin", bytes(range(256)))])
        header = "日本語\r\n".encode("shift_jis")
        source = header + b"[DaTaCoMpReSsIoN]\n" + body
        result = read_file_header(source)
        self.assertEqual((result.status, result.text), (0, "日本語\r\n"))
        self.assertEqual(result.source_sha256, hashlib.sha256(source).hexdigest())
        files = extract_zip(source, "payload.CUWC")
        self.assertEqual(
            [(m.name, m.data) for m in files], [("folder/a.bin", bytes(range(256)))]
        )
        self.assertEqual(read_file_header(b"[DataCompression]\n").status, 2)
        self.assertEqual(read_file_header(b"no marker").status, 2)
        self.assertEqual(
            read_file_header("①[DataCompression]\n".encode("cp932")).text, "①"
        )
        self.assertEqual(source, header + b"[DaTaCoMpReSsIoN]\n" + body)
        output = bytearray(b"????")
        self.assertEqual(
            read_header_buffer(b"abcdef[DataCompression]\n", output, encoding="ascii"),
            0,
        )
        self.assertEqual(output, b"abc\0")
        self.assertEqual(read_header_buffer(b"absent", output, encoding="ascii"), 2)
        self.assertEqual(output, b"abc\0")

    def test_zip_malformed_and_path_boundaries(self):
        for name in (
            "../escape",
            "/escape",
            "a/../../escape",
            "C:/escape",
            "a\\b",
            "a/./b",
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                extract_zip(archive([(name, b"x")]), "a.zip")
        with self.assertRaises(ValueError):
            extract_zip(archive([("A", b"x"), ("a", b"y")]), "a.zip")
        with self.assertRaises(zipfile.BadZipFile):
            extract_zip(b"not a zip", "a.zip")
        with self.assertRaises(InterruptedError):
            extract_zip(archive([("a", b"x")]), "a.zip", cancelled=lambda: True)
        info = zipfile.ZipInfo("link")
        info.external_attr = 0o120777 << 16
        with self.assertRaises(ValueError):
            extract_zip(archive([(info, b"target")]), "a.zip")

    def test_new_file_preservation_symlink_and_permissions(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "output"
            write_new_file(target, b"exact\0bytes")
            self.assertEqual(target.read_bytes(), b"exact\0bytes")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_new_file(target, b"replacement")
            (root / "link").symlink_to(root, target_is_directory=True)
            with self.assertRaises(OSError):
                write_new_file(root / "link" / "escape", b"x")
            self.assertFalse((root / "escape").exists())

    def test_rks_2026_signature_descendant_value_and_errors(self):
        raw = b"<Signature><x>" + b"A" * 256 + b"</x>" + b"z" * 256 + b"</Signature>"
        key = import_repro_key_2026(raw, source="captured.xml")
        self.assertEqual(key.value, "A" * 256 + "z" * 256)
        self.assertEqual(key.source_sha256, hashlib.sha256(raw).hexdigest())
        self.assertNotIn(key.value, repr(key))
        for data, status in (
            (b"<x/>", 8),
            (b"<Signature>x</Signature>", 9),
            (b"<Signature>" + b"!" * 512 + b"</Signature>", 10),
        ):
            with self.assertRaises(ServiceError) as caught:
                import_repro_key_2026(data, source="test")
            self.assertEqual(caught.exception.status, status)
        with self.assertRaises(ServiceError) as caught:
            RKSAccess2026().import_key("/nonexistent-cuw2026-test")
        self.assertEqual(caught.exception.status, 7)

    def test_json_format_and_strict_input(self):
        shared = [0]
        for _ in range(30):
            shared = [shared, shared]
        with patch("scripts.cuw_2026.json.dumps") as encoder:
            with self.assertRaises(ValueError):
                serialize_object(shared)
            encoder.assert_not_called()
        with patch("scripts.cuw_2026.MAX_BYTES", 64), self.assertRaises(ValueError):
            serialize_object({"value": "\x01" * 16})
        self.assertEqual(
            serialize_object({"a": [1, True, None]}), '{"a":[1,true,null]}'
        )
        self.assertIn("\r\n", serialize_object({"a": 1}, indented=True))
        self.assertEqual(json.loads(serialize_object({"日本語": "x"})), {"日本語": "x"})
        for value in (float("nan"), {1: "bad"}, object()):
            with self.assertRaises((ValueError, TypeError)):
                serialize_object(value)
        with self.assertRaises(ValueError):
            identity_2026(b"not a module", "CUW.dll")

    def test_copy_tree_exact_bytes_cancel_cleanup_and_collision(self):
        members = (ZIPMember("nested/a.bin", b"A" * 140000), ZIPMember("b.bin", b"\0B"))
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "copy"
            manifest = write_new_tree(members, target)
            self.assertEqual((target / "nested/a.bin").read_bytes(), members[0].data)
            self.assertEqual(manifest[1]["sha256"], hashlib.sha256(b"\0B").hexdigest())
            with self.assertRaises(FileExistsError):
                write_new_tree(members, target)
            polls = 0

            def cancel():
                nonlocal polls
                polls += 1
                return polls == 4

            interrupted = Path(folder) / "cancel"
            with self.assertRaises(InterruptedError):
                write_new_tree(members, interrupted, cancelled=cancel)
            self.assertFalse(interrupted.exists())
            self.assertEqual((target / "b.bin").read_bytes(), b"\0B")
            with self.assertRaises(ValueError):
                write_new_tree((ZIPMember("../escape", b"x"),), Path(folder) / "unsafe")

    def test_output_fault_rolls_back_owned_files(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "file"
            with patch("scripts.cuw_2026.os.fsync", side_effect=OSError("injected")):
                with self.assertRaises(OSError):
                    write_new_file(target, b"x")
                with self.assertRaises(OSError):
                    write_new_tree((ZIPMember("a/b", b"x"),), Path(folder) / "tree")
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_rks_inline_wrapper_and_log_primitive(self):
        raw = bytearray(192)
        offsets = (0, 3, 38, 53, 100, 118, 120, 127)
        values = ("2", "SW", "VER", "LIC", "VIN", "1", "PAIR", "SEED")
        for offset, value in zip(offsets, values, strict=True):
            raw[offset : offset + len(value)] = value.encode("ascii")
        value = rks_data_from_native(bytes(raw), encoding="ascii")
        self.assertEqual(value.x_version, "2")
        self.assertEqual(value.seed, "SEED")
        raw[0:3] = b"123"
        with self.assertRaises(ValueError):
            rks_data_from_native(bytes(raw), encoding="ascii")

        class Runtime:
            def call(self, operation, **kwargs):
                self.request = operation, kwargs
                if kwargs["mode"] == -1:
                    raise CommunicationLogNativeFault()
                return 7

        runtime = Runtime()
        self.assertEqual(set_communication_log_mode(runtime, 3), 7)
        self.assertEqual(runtime.request, ("set_communication_log_mode", {"mode": 3}))
        self.assertEqual(set_communication_log_mode(runtime, -1), 0)
        with self.assertRaises(ValueError):
            set_communication_log_mode(runtime, True)

    def test_notification_native_cadence_cursor_and_cleanup(self):
        class Host:
            now = 0.0

            def __init__(self):
                self.colors, self.sounds, self.closed = [], [], []
                self.polls = 0

            def cursor(self, **kwargs):
                return (100, 200)

            def create_window(self, *args, **kwargs):
                return "notice"

            def render(self, window, color, *args, **kwargs):
                self.colors.append((self.now, color))

            def beep(self, mode, frequency, duration_ms, **kwargs):
                self.sounds.append((mode, frequency, duration_ms))
                if mode == 1:
                    self.now += duration_ms / 1000

            def poll_event(self, window, *, timeout, **kwargs):
                self.now += timeout
                self.polls += 1
                return NoticeEvent(window, "move", 151 if self.polls == 5 else 150, 200)

            def close(self, window, **kwargs):
                self.closed.append(window)

        for mode in (0, 1, 2):
            host = Host()
            notice = CompletionNotice2026(host, clock=lambda host=host: host.now)
            self.assertEqual(
                notice.run(NoticeConfig("title", "body", 1, 2, 100, mode)), "move"
            )
            self.assertEqual(host.colors[0], (0, 2))
            self.assertEqual(host.closed, ["notice"])
            if mode == 2:
                self.assertEqual(host.colors[1], (0, 1))
                self.assertFalse(host.sounds)
            else:
                self.assertEqual(host.sounds[0], (mode, 1728, 100))
            with self.assertRaises(RuntimeError):
                notice.run(NoticeConfig("title", "body", 1, 2, 100, mode))
        host = Host()
        with self.assertRaises(InterruptedError):
            CompletionNotice2026(
                host, clock=lambda: host.now, cancelled=lambda: len(host.colors) > 0
            ).run(NoticeConfig("a", "b", 1, 2, 100, 2))
        self.assertEqual(host.closed, ["notice"])
        self.assertEqual(
            notification_font_heights(
                b"longer", b"x", 1000, 1000, lambda text: (len(text) * 10, 10)
            ),
            (150, 195),
        )
        self.assertEqual(
            notification_font_heights(
                b"x", b"longer", 1000, 1000, lambda text: (len(text) * 10, 10)
            ),
            (195, 150),
        )


class ControlContextScopeTests(unittest.TestCase):
    def engine_and_controller(self, cpu_count=1):
        from scripts.demo_calibration import table
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeGeneralParameters2026,
            NativeRuntime2026,
        )
        from tests.test_calibration_2026 import cpu_text, cuw

        folder = Path("runtime/no-car-21/recovered")
        if not (folder / "CUW.dll").is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        identity = identity_2026(
            (folder / "TCUWControlCommPhase.dll").read_bytes(),
            "TCUWControlCommPhase.dll",
        )
        controller = ControlCommPhase2026(
            identity,
            NativeRuntime2026(
                lambda event, remaining: None,
                local_milliseconds_of_day=lambda: 1000,
            ),
        )
        parameters = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": table(
                    (
                        "ParamFileKeySystemProtocolMicon",
                        "M16CTypeFlag",
                        "FORESTTypeFlag",
                    ),
                    (("149P5-Unified311", "0", "0"),),
                )
            },
            encoded=False,
        )
        engine = CUWEngine2026(
            (folder / "CUW.dll").read_bytes(), general_parameters=parameters
        )
        text = cpu_text(8).replace(
            "NumberOfCalibration=1", f"NumberOfCalibration={cpu_count}"
        )
        for index in range(2, cpu_count + 1):
            text += (
                f"[CPU{index:02d}]\nCPUImageName=cpu{index}.vbf\n"
                "CPUType=311\nStartAddress=0100002000\n"
                f"SizeOfUncompressedDownloadData={0x20 * index:08X}\n"
                "SizeOfDownloadData=00000004\n"
            )
        engine.configure(struct.pack("<IIddII", cpu_count, 0, 0, 0, 0, 0))
        engine.load_cuw(cuw(text, (b"image", b"image-longer")[:cpu_count]))
        return engine, controller

    def test_actual_import_issues_and_expires_control_context(self):
        engine, controller = self.engine_and_controller()
        with engine:
            with engine.controller_execution(controller, 0) as worker:
                context = controller.native_control_context2026(engine)
                capture = context._capture
                self.assertIs(worker._control_file_capture, capture)
                self.assertEqual(capture.control_cpu_start, worker.control_cpu_start)
                self.assertEqual(context.metadata, capture.metadata_for_cpu(0))
                self.assertFalse(engine._identifier_context_importing)
                self.assertEqual(
                    engine._identifier_context_epoch, capture._import_epoch
                )
                with (
                    self.assertRaises(ValueError),
                    engine.controller_execution(controller, 0),
                ):
                    pass
            self.assertIsNone(worker._control_file_capture)
            self.assertIsNone(engine._native_control_context2026)
            with self.assertRaises(ValueError):
                controller.native_control_context2026(engine)
            with self.assertRaises(ValueError):
                context.validate(engine, controller)

    def test_control_capture_rejects_foreign_thread_and_fake_import(self):
        engine, controller = self.engine_and_controller()
        with engine, engine.controller_execution(controller, 0):
            context = controller.native_control_context2026(engine)
            failures = []

            def validate_from_foreign_thread():
                try:
                    context.validate(engine, controller)
                except ValueError as error:
                    failures.append(error)

            thread = Thread(target=validate_from_foreign_thread)
            thread.start()
            thread.join()
            self.assertEqual(len(failures), 1)
            with self.assertRaises(ValueError):
                engine.worker.capture_control_file2026(controller)
            self.assertIs(controller.native_control_context2026(engine), context)

    def test_held_control_metadata_survives_outer_cpu_change(self):
        engine, controller = self.engine_and_controller(cpu_count=2)
        with engine:
            with engine.controller_execution(controller, 0):
                context = controller.native_control_context2026(engine)
                held = context.metadata
                engine.select_target(1, 1, controller=controller)
                self.assertEqual(engine.native_metadata.cpu_index, 1)
                self.assertEqual(context.metadata, held)
                self.assertEqual(context.cpu_index, 0)
            self.assertEqual(engine.native_metadata.cpu_index, 1)

    def test_export_scope_rejects_unissued_target_without_projecting_metadata(self):
        engine, controller = self.engine_and_controller()
        with engine:
            outer = engine.native_metadata
            with engine.controller_execution(controller, 0):
                with (
                    self.assertRaises(ValueError),
                    engine.controller_export_target(controller, object()),
                ):
                    pass
                self.assertIs(engine.family_metadata, outer)
                self.assertIsNone(engine._controller_export_target2026)

    def test_unscoped_gateway_transfer_keeps_cpu_zero_flash_size(self):
        from scripts.calibration_2026 import native2026_archive

        engine, controller = self.engine_and_controller(cpu_count=2)
        with engine:
            engine.bind_worker(controller)
            cpu_zero = native2026_archive(engine.worker.metadata_for_native_cpu(0))
            cpu_one = native2026_archive(engine.worker.metadata_for_native_cpu(1))
            self.assertNotEqual(cpu_zero.flash_size, cpu_one.flash_size)
            engine.select_target(1, 1, controller=controller)
            self.assertEqual(engine.native_metadata.cpu_index, 1)
            engine.dh_state._gateway_transfer(0, cpu_zero.flash_size)

    def test_control_callback_caches_keep_distinct_canonical_values(self):
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )

        engine, _controller = self.engine_and_controller()
        self.assertFalse(engine.native_control_retry_cache2026)
        self.assertEqual(engine.native_control_phase_cache2026, 2)
        self.assertFalse(engine.native_control_alternate_cache2026)
        self.assertEqual(engine.native_control_divided_index2026, 0)
        with engine:
            source = engine._source
            assert source is not None
            state = ReproInfoState((RecoveryCalibration("authored.cuw", source),))
            with tempfile.TemporaryDirectory() as directory:
                engine.bind_persistence(CUWPersistence(Path(directory), state))
            state.use_new_software_password = True
            state.comm_phase = 3
            state.sequence_changed_for_get_cid = True
            state.write_target_divided_cpu_image_index = 7
            engine.dh_state._native_comm_phase = 1
            self.assertTrue(engine.native_control_retry_cache2026)
            self.assertEqual(engine.native_control_phase_cache2026, 3)
            self.assertTrue(engine.native_control_alternate_cache2026)
            self.assertEqual(engine.native_control_divided_index2026, 7)
            self.assertEqual(engine.dh_state.comm_phase, 1)

    def test_control_callback_publishers_require_their_source_helper(self):
        engine, controller = self.engine_and_controller()
        with engine:
            engine.bind_worker(controller)
            with engine.controller_execution(controller, 0) as worker:
                with self.assertRaises(ValueError):
                    engine._publish_control_retry_cache2026(worker=worker)
                with self.assertRaises(ValueError):
                    engine._publish_control_phase_cache2026(worker=worker)
                with self.assertRaises(ValueError):
                    engine._publish_control_alternate_cache2026(worker=worker)

    def test_controller_entry_imports_outer_phase_then_keeps_live_mutations(self):
        engine, controller = self.engine_and_controller()
        with engine:
            with engine.controller_execution(controller, 1):
                self.assertEqual(engine.dh_state.comm_phase, 1)
                engine.set_comm_phase(3, controller=controller)
                self.assertEqual(engine.dh_state.comm_phase, 3)
            with engine.controller_execution(controller, 2):
                self.assertEqual(engine.dh_state.comm_phase, 2)

    def test_engine_close_revokes_only_its_owned_control_pool_idempotently(self):
        from scripts.cuw_parameter_pool import ControlParameterPool2026

        engine, controller = self.engine_and_controller()
        other, other_controller = self.engine_and_controller()
        with engine.controller_execution(controller, 0):
            pool = ControlParameterPool2026.issue(
                engine,
                controller,
                {
                    "149P5-Unified311.ini": (
                        b"ParamFileKeySystemProtocolMicon,DLLFileNameForGetCID\r\n"
                        b"149P5-Unified311,Authored.dll\r\n"
                    )
                },
                encoded=False,
            )
            pool.load_for(engine, controller, "get_cid")
            controller._control_parameter_pool2026 = pool
        with other.controller_execution(other_controller, 0):
            other_pool = ControlParameterPool2026.issue(
                other,
                other_controller,
                {
                    "149P5-Unified311.ini": (
                        b"ParamFileKeySystemProtocolMicon,DLLFileNameForGetCID\r\n"
                        b"149P5-Unified311,Other.dll\r\n"
                    )
                },
                encoded=False,
            )
            other_pool.load_for(other, other_controller, "get_cid")
            other_controller._control_parameter_pool2026 = other_pool
        engine.close()
        with self.assertRaises(ValueError):
            pool.slot(0)
        self.assertEqual(pool._state.slots[0].parameter.headers, ())
        with other.controller_execution(other_controller, 0):
            self.assertEqual(other_pool.slot(0).index, 0)
        other.close()
        with self.assertRaises(ValueError):
            other_pool.slot(0)
        engine.close()

    def test_control_pool_survives_repeated_owned_phase_execution(self):
        from scripts.cuw_parameter_pool import ControlParameterPool2026

        engine, controller = self.engine_and_controller()
        with engine:
            pool = None
            for phase in (0, 1):
                with engine.controller_execution(controller, phase):
                    if pool is None:
                        pool = ControlParameterPool2026.issue(
                            engine,
                            controller,
                            {
                                "149P5-Unified311.ini": (
                                    b"ParamFileKeySystemProtocolMicon,DLLFileNameForGetCID\r\n"
                                    b"149P5-Unified311,Authored.dll\r\n"
                                )
                            },
                            encoded=False,
                        )
                        pool.load_for(engine, controller, "get_cid")
                        controller._control_parameter_pool2026 = pool
                    self.assertIs(controller._control_parameter_pool2026, pool)
                    self.assertTrue(pool.slot(0).loaded)
                self.assertIs(controller._control_parameter_pool2026, pool)

    def test_control_progress_uses_worker_scratch_until_whole_vector_publish(self):
        from scripts.cuw_parameter_pool import ControlParameterPool2026
        from scripts.programming_2026_common import NativeControlExportTarget2026

        engine, controller = self.engine_and_controller()
        with engine:
            engine.dh_state._transferred_bytes = (9,)
            engine.dh_state._progress = (31,)
            engine.bind_worker(controller)
            with engine.controller_execution(controller, 0) as worker:
                pool = ControlParameterPool2026.issue(
                    engine,
                    controller,
                    {
                        "149P5-Unified311.ini": (
                            b"ParamFileKeySystemProtocolMicon,DLLFileNameForGetCID\r\n"
                            b"149P5-Unified311,Authored.dll\r\n"
                        )
                    },
                    encoded=False,
                )
                pool.load_for(engine, controller, "get_cid")
                target = NativeControlExportTarget2026.issue(
                    engine, controller, pool, 0, "get_cid"
                )
                context = controller.native_control_context2026(engine)
                state = engine.dh_state
                old_counts, old_percentages = state.transferred_bytes, state.progress
                with engine.controller_export_target(controller, target):
                    self.assertEqual(context.count_scratch, (0,))
                    self.assertEqual(context.percentage_scratch, (31,))
                    state.set_native_count(0, 42)
                    state.set_native_percentage(0, 73)
                    self.assertEqual(state.transferred_bytes, (42,))
                    self.assertEqual(state.progress, (73,))
                    self.assertEqual(state._transferred_bytes, old_counts)
                    self.assertEqual(state._progress, old_percentages)
                    worker.publish_control_count2026(context)
                    self.assertEqual(state._transferred_bytes, (42,))
                    self.assertEqual(state._progress, old_percentages)
                    worker.publish_control_percent2026(context)
                    self.assertEqual(state._progress, (73,))
                    self.assertEqual(worker._previous_percentages2026, old_percentages)
                    with self.assertRaises(ValueError):
                        engine._publish_control_ssmid_cache2026(worker=worker)
                    self.assertEqual(engine.native_ssmid_cache2026, 0)
                    self.assertEqual(worker.read_control_callback_29_2026(context), 0)
            self.assertEqual((state.transferred_bytes, state.progress), ((42,), (73,)))

    def test_writer_address_groups_follow_held_control_target(self):
        from scripts.cuw_parameter_pool import ControlParameterPool2026
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeControlExportTarget2026,
            NativeRuntime2026,
        )
        from scripts.programming_2026_vendor import native2026_write_address_groups
        from tests.test_programming_2026_body import SONAR_WRITE, writer_selection

        folder = Path("runtime/no-car-21/recovered")
        if not (folder / "CUW.dll").is_file():
            self.skipTest("Authenticated static CUW2026 image is absent")
        identity = identity_2026(
            (folder / "TCUWControlCommPhase.dll").read_bytes(),
            "TCUWControlCommPhase.dll",
        )
        controller = ControlCommPhase2026(
            identity,
            NativeRuntime2026(
                lambda event, remaining: None,
                local_milliseconds_of_day=lambda: 1000,
            ),
        )
        raw, _, selection, general = writer_selection(
            SONAR_WRITE,
            cpu_index=0,
            initialize_prepare=True,
            encoded=False,
        )
        engine = CUWEngine2026(
            (folder / "CUW.dll").read_bytes(), general_parameters=general
        )
        engine.configure(struct.pack("<IIddII", 2, 0, 0, 0, 0, 0))
        engine.load_cuw(raw)
        with engine:
            engine.bind_worker(controller)
            with engine.controller_execution(controller, 0):
                pool = ControlParameterPool2026.issue(
                    engine,
                    controller,
                    selection.catalog_sources,
                    encoded=False,
                )
                pool.load_for(engine, controller, "write")
                target = NativeControlExportTarget2026.issue(
                    engine, controller, pool, 0, "write"
                )
                selection = target.binding
                groups = native2026_write_address_groups(
                    target.metadata.source_container, selection
                )
                engine.select_target(1, 1, controller=controller)
                self.assertNotEqual(target.metadata, engine.native_metadata)
                with engine.controller_export_target(controller, target):
                    engine.validate_address_groups(selection, groups)
                    from dataclasses import replace

                    foreign_selection = replace(
                        selection, metadata=engine.native_metadata
                    )
                    with self.assertRaisesRegex(ValueError, "actual engine target"):
                        engine.validate_address_groups(foreign_selection, groups)
                with self.assertRaisesRegex(ValueError, "actual engine target"):
                    engine.validate_address_groups(selection, groups)

    def test_control_dh_mode_and_persistent_byte_cache_share_native_field(self):
        from scripts.cuw_parameter_pool import ControlParameterPool2026
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )
        from scripts.programming_2026_common import NativeControlExportTarget2026

        engine, controller = self.engine_and_controller()
        with engine:
            source = engine._source
            assert source is not None
            repro_state = ReproInfoState((RecoveryCalibration("authored.cuw", source),))
            with tempfile.TemporaryDirectory() as directory:
                engine.bind_persistence(CUWPersistence(Path(directory), repro_state))
            engine.bind_worker(controller)
            with engine.controller_execution(controller, 0) as worker:
                pool = ControlParameterPool2026.issue(
                    engine,
                    controller,
                    {
                        "149P5-Unified311.ini": (
                            b"ParamFileKeySystemProtocolMicon,DLLFileNameForPrepareWrite\r\n"
                            b"149P5-Unified311,Authored.dll\r\n"
                        )
                    },
                    encoded=False,
                )
                pool.load_for(engine, controller, "prepare")
                target = NativeControlExportTarget2026.issue(
                    engine, controller, pool, 0, "prepare"
                )
                state = engine.dh_state
                with engine.controller_export_target(controller, target):
                    state.set_central_gateway_type(2)
                    self.assertEqual(state.central_gateway_type, 2)
                    self.assertEqual(worker._source_mode, 2)
                with self.assertRaises(ValueError):
                    engine._publish_control_ssmid_cache2026(worker=worker)
                with self.assertRaises(ValueError):
                    engine._publish_control_dh_type_cache2026(worker=worker)
                self.assertEqual(engine.native_ssmid_cache2026, 0)
                self.assertEqual(engine.native_dh_type_cache2026, 0)
                self.assertEqual(repro_state.ssmid, 0)
                self.assertEqual(repro_state.dh_central_gw_type, 0)


if __name__ == "__main__":
    unittest.main()
