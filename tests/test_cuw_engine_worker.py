import hashlib
import io
import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.cuw_2026 import CUWEngine2026, identity_2026
from scripts.cuw_engine_worker import NativeWorkerIntegerError2026
from scripts.cuw_file_services import admit_file_sources_2026
from scripts.cuw_persistence import CUWPersistence, RecoveryCalibration, ReproInfoState
from scripts.demo_calibration import table
from scripts.j2534_2026 import (
    J2534Device2026,
    J2534InterfacePair2026,
    NativeJ2534Error2026,
    PrimitiveResult,
)
from scripts.programming_2026_common import (
    ControlCommPhase2026,
    NativeGeneralParameters2026,
    NativeRuntime2026,
)
from scripts.programming_replay import load_programming_replay
from tests.private_evidence import read_private_bytes
from tests.test_calibration_2026 import cuw, srecord

RUNTIME = Path("runtime/no-car-21/recovered")


def calibration(
    *,
    cpus: int = 1,
    daihatsu: bool = False,
    first_target: str = "OLD",
    second_cpu_type: str = "311",
    first_image: str = "authored.bin",
) -> bytes:
    gateway = "NumberOfGateway=1\n01_GatewayDiagID=0751\n" if daihatsu else ""
    text = (
        "[Format]\nVersion=105\n[Vehicle]\nNumberOfNode=1\n"
        "ContactType=P5-Unified\nKindOfECU=149\n"
        f"[Node01]\nRequiredSpecReproVer=02\nNumberOfCalibration={cpus}\n{gateway}"
        f"[CPU11]\nCPUImageName={first_image}\nCPUType=311\nNewCID=NEW1\n"
        "StartAddress=0100001000\nSizeOfUncompressedDownloadData=00000020\n"
        "SizeOfDownloadData=00000004\nNumberOfTargets=2\n"
        f"01_TargetCalibration={'0751' if daihatsu else first_target}\n"
        "02_TargetCalibration=LATEST\n"
    )
    if cpus == 2:
        text += (
            f"[CPU12]\nCPUImageName=authored2.vbf\nCPUType={second_cpu_type}\nNewCID=NEW2\n"
            "StartAddress=0100002000\nSizeOfUncompressedDownloadData=00000020\n"
            "SizeOfDownloadData=00000004\nNumberOfTargets=2\n"
            "01_TargetCalibration=SECOND-OLD\n"
            "02_TargetCalibration=SECOND-LATEST\n"
        )
    return cuw(text, (b"data",) * cpus)


def make_controller(runtime: NativeRuntime2026) -> ControlCommPhase2026:
    return ControlCommPhase2026(
        identity_2026(
            (RUNTIME / "TCUWControlCommPhase.dll").read_bytes(),
            "TCUWControlCommPhase.dll",
        ),
        runtime,
    )


def bind_engine_device(
    engine: CUWEngine2026, control: J2534Device2026
) -> J2534Device2026:
    device = J2534Device2026(
        control.provider,
        clock=control.clock,
        cancelled=control.cancelled,
        background_workers=control.background_workers,
        max_calls=control.max_calls,
        max_cleanup_calls=control.max_cleanup_calls,
    )
    engine.bind_interface_pair(J2534InterfacePair2026(device, control))
    device.opened, device.device_id = control.opened, control.device_id
    device.connecting, device.channel_id = control.connecting, control.channel_id
    return device


def encoded_table(headers: tuple[str, ...], rows: tuple[tuple[str, ...], ...]) -> bytes:
    return bytes(
        (part + 8) << 2
        for byte in table(headers, rows)
        for part in (byte >> 4, byte & 15)
    )


class EngineWorker2026Tests(unittest.TestCase):
    def setUp(self):
        required = (RUNTIME / "CUW.dll", RUNTIME / "TCUWControlCommPhase.dll")
        if any(not path.is_file() for path in required):
            self.skipTest("Authenticated static CUW2026 pipeline is absent")

    def engine(
        self, source: bytes, *, persistence=None, cpu_index: int = 0
    ) -> CUWEngine2026:
        general = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": table(
                    (
                        "ParamFileKeySystemProtocolMicon",
                        "M16CTypeFlag",
                        "FORESTTypeFlag",
                        "PasswordAddress",
                        "ByteOrder",
                        "FlagToDoIGOFFONAtCPUTypeChange",
                        "FlagToChangeToReprogGWModeForCentralGW",
                    ),
                    tuple(
                        (key, "0", "0", "00", "1", "0", "0")
                        for key in (
                            "149P5-Unified",
                            "149P5-Unified311",
                            "149P5-Unified312",
                        )
                    ),
                )
            },
            encoded=False,
        )
        engine = CUWEngine2026(
            read_private_bytes(RUNTIME / "CUW.dll"),
            persistence=persistence,
            general_parameters=general,
        )
        engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
        engine.load_cuw(source, cpu_index=cpu_index)
        return engine

    @staticmethod
    def receive(engine, controller, values: tuple[bytes, ...]) -> None:
        engine._import_identifier_context()
        engine.commit_received_identifiers(values, controller=controller)

    def test_only_engine_issuer_constructs_and_reuses_worker(self):
        from scripts.cuw_engine_worker import EngineWorker2026

        engine = self.engine(calibration())
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        self.addCleanup(engine.close)
        with self.assertRaisesRegex(TypeError, "issued by CUWEngine2026"):
            EngineWorker2026(engine, controller)
        worker = engine.bind_worker(controller)
        self.assertIs(engine.bind_worker(controller), worker)
        self.assertIs(worker.engine, engine)
        self.assertIs(worker.controller, controller)
        self.assertIs(worker.runtime, controller.runtime)

    def test_close_invalidates_controller_lease_and_allows_fresh_issue(self):
        engine = self.engine(calibration())
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        self.addCleanup(engine.close)
        first = engine.bind_worker(controller)
        first.close()
        with self.assertRaisesRegex(ValueError, "closed"):
            first.validate_source()
        second = engine.bind_worker(controller)
        self.assertIsNot(first, second)
        self.assertIs(controller.worker, second)  # pyright: ignore[reportAttributeAccessIssue]

    def test_worker_replacement_preserves_engine_state_and_rolls_back_atomically(self):
        from scripts.cuw_engine_worker import (
            _finalize_engine_worker_replacement,
            _replace_engine_worker,
            _rollback_engine_worker_replacement,
        )

        engine = self.engine(calibration())
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        self.addCleanup(engine.close)
        self.receive(engine, controller, (b"OLD",))
        first = engine.bind_worker(controller)
        with engine.controller_execution(controller, 0):
            self.assertTrue(first.mark_cid_reception_complete())
        with engine.controller_execution(controller, 1):
            first.record_callback_24(2)
        before = first.source_state

        second = _replace_engine_worker(engine, controller, first)
        self.assertIs(engine.worker, second)
        self.assertEqual(second.source_state.target_indices, before.target_indices)
        self.assertEqual(
            second.source_state.retained_cpu_type, before.retained_cpu_type
        )
        self.assertEqual(second.source_state.callback_24_state, 2)
        self.assertEqual(second.native_prepare_handshake, 0)
        self.assertEqual(second.control_state.lifecycle, "issued")
        with self.assertRaisesRegex(ValueError, "closed"):
            first.validate_source()
        for getter in (
            lambda: first.source_state,
            lambda: first.control_state,
            lambda: first.native_prepare_handshake,
        ):
            with self.assertRaisesRegex(ValueError, "closed"):
                getter()

        _rollback_engine_worker_replacement(engine, first, second)
        self.assertIs(engine.worker, first)
        first.validate_source()
        self.assertEqual(first.native_prepare_handshake, 0)
        self.assertEqual(first.control_state.lifecycle, "ready")

        second = _replace_engine_worker(engine, controller, first)
        _finalize_engine_worker_replacement(engine, first, second)
        self.assertIs(engine.worker, second)
        with self.assertRaisesRegex(ValueError, "closed"):
            first.validate_source()

    def test_target_selection_retained_cpu_and_online_context_are_source_issued(self):

        source = calibration(cpus=2, daihatsu=True)
        engine = self.engine(source)
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        self.addCleanup(engine.close)
        self.receive(engine, controller, (b"0751", b"SECOND-LATEST"))
        worker = engine.bind_worker(controller)
        with engine.controller_execution(controller, 0):
            worker.mark_cid_reception_complete()
        worker.set_vin(b"JT12345678901234?")
        with self.assertRaisesRegex(ValueError, "CPU type is empty"):
            _ = worker.native_getter_cpu_type
        engine.apply_cpu_type(0, "311")
        with engine.controller_execution(controller, 1):
            pass
        self.assertEqual(worker.native_writer_target_index, 0)
        self.assertEqual(worker.native_getter_cpu_type, "311")
        self.assertFalse(worker.native_initial_command_retry)
        context = worker.online_context()
        self.assertEqual(context.vin, b"JT12345678901234")
        self.assertEqual(context.region, 0)
        self.assertEqual(context.kind_of_ecu, "149")
        self.assertTrue(context.is_daihatsu)
        self.assertEqual(context.source_sha256, engine.source_sha256)
        self.assertEqual(context.all_loaded_metadata, (engine.native_metadata,))
        self.assertEqual(worker.usb_recovery_context().target_calibration, b"0751")
        self.assertEqual(worker.usb_recovery_context().prior_software_count, 2)

    def test_notify_next_cpu_updates_source_state_without_recursive_phase_entry(self):

        engine = self.engine(calibration(cpus=2))
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        self.addCleanup(engine.close)
        self.receive(engine, controller, (b"OLD", b"SECOND-LATEST"))
        worker = engine.bind_worker(controller)
        with engine.controller_execution(controller, 0):
            worker.mark_cid_reception_complete()
        with engine.controller_execution(controller, 1):
            pass
        with engine.controller_execution(controller, 2):
            worker.notify_next_cpu()
        continuation = worker.take_continuation()
        self.assertIsNotNone(continuation)
        assert continuation is not None
        self.assertEqual(
            (continuation.kind, continuation.cpu_index, continuation.target_index),
            ("cpu", 1, 1),
        )
        self.assertEqual(engine.native_metadata.cpu_index, 1)
        self.assertEqual(worker.native_writer_target_index, 1)
        self.assertEqual(worker.source_state.target_indices, (0, 1))
        self.assertIsNone(engine.continuation_backup)
        self.assertIsNone(worker.take_continuation())

    def test_unmatched_target_fails_closed_until_native_append_runs(self):
        engine = self.engine(calibration())
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        self.addCleanup(engine.close)
        self.receive(engine, controller, (b"UNMATCHED",))
        worker = engine.bind_worker(controller)
        original = engine.native_metadata
        with engine.controller_execution(controller, 0):
            self.assertFalse(worker.mark_cid_reception_complete())

        self.assertIs(engine.native_metadata, original)
        with self.assertRaisesRegex(ValueError, "no completed native CID selection"):
            _ = worker.native_writer_target_index

    def test_owned_cid_completion_rebuilds_order_targets_and_image_password(self):
        from scripts.calibration_2026 import (
            native2026_cpu_targets,
            native2026_cpu_type,
        )

        source = cuw(
            "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=2\n"
            "ContactType=P5-Unified\nKindOfECU=149\n"
            "[CPU01]\nCPUImageName=one.hex\nCPUType=311\nNewCID=M16C\n"
            "NumberOfTargetHardwares=1\n01_TargetHardware=\n"
            "NumberOfTargets=1\n01_TargetCalibration=OLD1\n"
            "[CPU02]\nCPUImageName=two.hex\nCPUType=312\nNewCID=FOREST\n"
            "NumberOfTargetHardwares=1\n01_TargetHardware=\n"
            "NumberOfTargets=1\n01_TargetCalibration=OLD2\n",
            (
                b"\n".join((srecord(1, 0, b"xFIRST"), srecord(7, 0))),
                b"\n".join((srecord(1, 0, b"x\x01\x02\x03\x04z"), srecord(7, 0))),
            ),
        )
        parameters = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": table(
                    (
                        "ParamFileKeySystemProtocolMicon",
                        "M16CTypeFlag",
                        "FORESTTypeFlag",
                        "PasswordAddress",
                        "ByteOrder",
                        "FlagToHoldSFormatRecords",
                        "FlagToDoIGOFFONAtCPUTypeChange",
                    ),
                    (
                        ("149P5-Unified311", "1", "0", "00", "1", "0", "0"),
                        ("149P5-Unified312", "0", "1", "01", "1", "0", "0"),
                    ),
                )
            },
            encoded=False,
        )
        engine = CUWEngine2026(
            (RUNTIME / "CUW.dll").read_bytes(), general_parameters=parameters
        )
        engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
        engine.load_cuw(source)
        self.addCleanup(engine.close)
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        self.receive(engine, controller, (b"OLD1", b"UNKNOWN"))
        worker = engine.bind_worker(controller)

        with engine.controller_execution(controller, 0):
            self.assertTrue(worker.mark_cid_reception_complete())

        self.assertEqual(worker.source_state.target_indices, (0, -1))
        self.assertEqual(worker.source_state.cpu_offset, 0)
        self.assertEqual(native2026_cpu_type(engine.native_metadata, 0), "311")
        with engine.controller_execution(controller, 1):
            pass
        state = worker.source_state
        self.assertEqual((state.cpu_offset, state.target_indices), (1, (1, 0)))
        self.assertEqual(state.unmatched_identifiers, (b"FOREST",))
        self.assertEqual(state.unmatched_companions, (b"",))
        self.assertEqual(state.authored_cpu_count, 2)
        self.assertEqual(state.authored_target_indices, (0, -1))
        self.assertEqual(native2026_cpu_type(engine.native_metadata, 0), "312")
        appended = native2026_cpu_targets(engine.native_metadata, 0)[1]
        self.assertEqual(
            (appended.calibration, appended.password), ("FOREST", 0x01020304)
        )
        self.assertEqual(state.current_global_cpu_index, 1)
        self.assertEqual(worker.native_writer_target_index, 0)
        self.assertEqual(worker.native_index_for_source_cpu(1), 0)
        self.assertEqual(worker.native_index_for_source_cpu(0), 1)
        self.assertEqual(native2026_cpu_type(engine.native_metadata, 1), "311")
        self.assertEqual(worker.native_writer_target_index, 0)

    def test_vbf_prepare_skips_rebuild_and_general_password_lookups(self):
        from scripts.calibration_2026 import native2026_cpu_targets, native2026_cpu_type

        source = cuw(
            "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=2\n"
            "ContactType=P5-Unified\nKindOfECU=149\n"
            "[CPU01]\nCPUImageName=one.vbf\nCPUType=311\nNewCID=M16C\n"
            "NumberOfTargetHardwares=1\n01_TargetHardware=\n"
            "NumberOfTargets=1\n01_TargetCalibration=OLD1\n"
            "[CPU02]\nCPUImageName=two.vbf\nCPUType=312\nNewCID=FOREST\n"
            "NumberOfTargets=1\n01_TargetCalibration=OLD2\n",
            (b"FIRST", b"SECOND"),
        )
        parameters = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": table(
                    (
                        "ParamFileKeySystemProtocolMicon",
                        "M16CTypeFlag",
                        "FORESTTypeFlag",
                    ),
                    (
                        ("149P5-Unified311", "1", "0"),
                        ("149P5-Unified312", "0", "1"),
                    ),
                )
            },
            encoded=False,
        )
        engine = CUWEngine2026(
            (RUNTIME / "CUW.dll").read_bytes(), general_parameters=parameters
        )
        engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
        engine.load_cuw(source)
        self.addCleanup(engine.close)
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        self.receive(engine, controller, (b"OLD1", b"UNKNOWN"))
        worker = engine.bind_worker(controller)

        with engine.controller_execution(controller, 0):
            self.assertTrue(worker.mark_cid_reception_complete())
        with engine.controller_execution(controller, 1):
            pass

        self.assertEqual(worker.source_state.target_indices, (0, -1))
        self.assertEqual(worker.source_state.cpu_offset, 0)
        self.assertEqual(native2026_cpu_type(engine.native_metadata, 0), "311")
        self.assertEqual(len(native2026_cpu_targets(engine.native_metadata, 1)), 1)

    def test_vbf_prepare_preserves_existing_d30c_for_zero_current_cpu(self):
        source = cuw(
            "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=2\n"
            "ContactType=P5-Unified\nKindOfECU=149\n"
            "[CPU01]\nCPUImageName=x.vbf.extra\nCPUType=311\nNewCID=OLD1\n"
            "NumberOfTargetHardwares=1\n01_TargetHardware=\n"
            "NumberOfTargets=1\n01_TargetCalibration=OLD1\n"
            "[CPU02]\nCPUImageName=two.vbf\nCPUType=312\nNewCID=OLD2\n"
            "NumberOfTargetHardwares=1\n01_TargetHardware=\n"
            "NumberOfTargets=1\n01_TargetCalibration=OLD2\n",
            (b"FIRST", b"SECOND"),
        )
        state = ReproInfoState(
            (RecoveryCalibration("source.cuw", source),),
            loaded=True,
            offset_of_write_cpu_multi_cal_index=1,
        )
        with tempfile.TemporaryDirectory() as directory:
            persistence = CUWPersistence(Path(directory), state)
            engine = self.engine(source, persistence=persistence)
            self.addCleanup(engine.close)
            controller = make_controller(NativeRuntime2026(lambda *_: None))
            self.receive(engine, controller, (b"OLD1", b"OLD2"))
            worker = engine.bind_worker(controller)

            with engine.controller_execution(controller, 0):
                self.assertTrue(worker.mark_cid_reception_complete())
            self.assertEqual(worker.source_state.cpu_offset, 1)
            self.assertEqual(worker.source_state.current_global_cpu_index, 0)

            with engine.controller_execution(controller, 1):
                pass

            self.assertEqual(worker.source_state.cpu_offset, 1)
            self.assertEqual(worker.source_state.current_global_cpu_index, 1)
            self.assertEqual(engine.native_metadata.cpu_index, 1)
            self.assertEqual(worker.native_writer_target_index, 0)

    def test_36800_retains_effective_cpu_zero_without_changing_selected_cpu(self):
        source = calibration(cpus=2, second_cpu_type="312")
        engine = self.engine(source, cpu_index=1)
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        self.addCleanup(engine.close)
        worker = engine.bind_worker(controller)
        engine.apply_cpu_type(0, "311")

        with engine.controller_execution(controller, 1):
            pass

        self.assertEqual(engine.native_metadata.cpu_index, 1)
        self.assertEqual(worker.source_state.current_global_cpu_index, 1)
        self.assertEqual(worker.native_getter_cpu_type, "311")
        self.assertEqual(worker.metadata_for_native_cpu(1).cpu_index, 1)
        self.assertEqual(worker.native_index_for_source_cpu(1), 1)
        self.assertTrue(worker.persist_current_cpu)

    def test_36800_vbf_marker_is_case_sensitive_substring(self):
        for image, expected in (("x.vbf.extra", 1), ("x.VBF.extra", 0)):
            with self.subTest(image=image):
                engine = self.engine(calibration(first_image=image))
                self.addCleanup(engine.close)
                controller = make_controller(NativeRuntime2026(lambda *_: None))
                worker = engine.bind_worker(controller)
                with engine.controller_execution(controller, 1):
                    pass
                self.assertEqual(worker.native_prepare_handshake, expected)

    def test_36800_vbf_handshake_reads_effective_cpu_zero_not_selected_cpu(self):
        for first_image, second_image, expected in (
            ("first.bin", "second.vbf", 0),
            ("first.vbf", "second.bin", 1),
        ):
            with self.subTest(first_image=first_image, second_image=second_image):
                source = cuw(
                    "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=2\n"
                    "ContactType=P5-Unified\nKindOfECU=149\n"
                    f"[CPU01]\nCPUImageName={first_image}\nCPUType=311\n"
                    "NewCID=OLD1\nNumberOfTargets=1\n"
                    "01_TargetCalibration=OLD1\n"
                    f"[CPU02]\nCPUImageName={second_image}\nCPUType=312\n"
                    "NewCID=OLD2\nNumberOfTargets=1\n"
                    "01_TargetCalibration=OLD2\n",
                    (b"FIRST", b"SECOND"),
                )
                engine = self.engine(source, cpu_index=1)
                self.addCleanup(engine.close)
                controller = make_controller(NativeRuntime2026(lambda *_: None))
                worker = engine.bind_worker(controller)

                with engine.controller_execution(controller, 1):
                    pass

                self.assertEqual(engine.native_metadata.cpu_index, 1)
                self.assertEqual(worker.native_prepare_handshake, expected)

    def test_prepare_reentry_requires_the_actual_external_prefix_owner(self):
        engine = self.engine(calibration(first_image="authored.vbf.extra"))
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        self.addCleanup(engine.close)
        worker = engine.bind_worker(controller)
        with engine.controller_execution(controller, 1):
            pass
        self.assertEqual(worker.native_prepare_handshake, 1)

        with (
            self.assertRaisesRegex(ValueError, "prepare reentry"),
            engine.controller_execution(controller, 1),
        ):
            self.fail("reentry must return before dispatch")
        self.assertEqual(worker.native_prepare_handshake, 1)
        with self.assertRaisesRegex(ValueError, "owned36800 prepare prefix"):
            worker.prepare_reentry_handshake()
        self.assertEqual(worker.native_prepare_handshake, 1)

    def test_next_cpu_publishes_source_ig_cycle_to_engine_status(self):
        parameters = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": table(
                    (
                        "ParamFileKeySystemProtocolMicon",
                        "M16CTypeFlag",
                        "FORESTTypeFlag",
                        "PasswordAddress",
                        "ByteOrder",
                        "FlagToDoIGOFFONAtCPUTypeChange",
                    ),
                    (
                        ("149P5-Unified311", "0", "0", "00", "1", "0"),
                        ("149P5-Unified312", "0", "0", "00", "1", "1"),
                    ),
                )
            },
            encoded=False,
        )
        engine = CUWEngine2026(
            (RUNTIME / "CUW.dll").read_bytes(), general_parameters=parameters
        )
        engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
        engine.load_cuw(calibration(cpus=2))
        self.addCleanup(engine.close)
        engine.apply_cpu_type(0, "311")
        engine.apply_cpu_type(1, "312")
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        self.receive(engine, controller, (b"OLD", b"SECOND-OLD"))
        worker = engine.bind_worker(controller)
        with engine.controller_execution(controller, 0):
            worker.mark_cid_reception_complete()

        with engine.controller_execution(controller, 2):
            worker.notify_next_cpu()

        self.assertTrue(worker.control_state.ig_off_pending)
        self.assertTrue(engine.native_cycle_output)

    def test_p6_logical_cpu_boundary_updates_selection_without_outer_yield(self):
        engine = self.engine(calibration(cpus=2))
        milliseconds = iter((900, 900, 1000, 1020, 1050))
        controller = make_controller(
            NativeRuntime2026(
                lambda *_: None, local_milliseconds_of_day=lambda: next(milliseconds)
            )
        )
        self.addCleanup(engine.close)
        self.receive(engine, controller, (b"OLD", b"SECOND-LATEST"))
        worker = engine.bind_worker(controller)
        with engine.controller_execution(controller, 0):
            worker.mark_cid_reception_complete()
        with engine.controller_execution(controller, 2):
            worker.notify_logical_cpu_boundary(1)
        self.assertEqual(engine.native_metadata.cpu_index, 1)
        self.assertEqual(worker.source_state.current_global_cpu_index, 1)
        self.assertEqual(worker.native_writer_target_index, 1)
        self.assertEqual(worker.source_state.phase_elapsed_ms[:2], (20, 30))
        self.assertIsNone(engine.continuation_backup)
        self.assertIsNone(worker.take_continuation())

    def test_multifile_continuation_swaps_profile_and_persists_exact_position(self):
        first_source = calibration(first_target="FIRST")
        second_source = calibration(first_target="SECOND")
        state = ReproInfoState(
            (
                RecoveryCalibration("first.cuw", first_source),
                RecoveryCalibration("second.cuw", second_source),
            ),
            multi_calibration_file_num=2,
        )
        with tempfile.TemporaryDirectory() as directory:
            persistence = CUWPersistence(Path(directory), state)
            engine = self.engine(first_source, persistence=persistence)
            self.addCleanup(engine.close)
            controller = make_controller(NativeRuntime2026(lambda *_: None))
            self.receive(engine, controller, (b"FIRST",))
            worker = engine.bind_worker(controller)
            with engine.controller_execution(controller, 0):
                worker.mark_cid_reception_complete()
                first = engine.native_metadata
                second = worker.loaded_metadata[1]
                engine._select_worker_metadata(
                    second, controller=controller, worker=worker
                )
                self.receive(engine, controller, (b"SECOND",))
                worker.mark_cid_reception_complete()
                engine._select_worker_metadata(
                    first, controller=controller, worker=worker
                )
            with engine.controller_execution(controller, 2):
                worker.notify_next_cpu()
            continuation = worker.take_continuation()
            self.assertIsNotNone(continuation)
            assert continuation is not None
            self.assertEqual(continuation.kind, "file")
            self.assertEqual(
                engine.source_sha256, worker.loaded_metadata[1].source_sha256
            )
            self.assertEqual(
                (
                    persistence.state.calibration_file_index,
                    persistence.state.write_cpu_index,
                    persistence.state.offset_of_write_cpu_multi_cal_index,
                ),
                (1, 0, 0),
            )

    def test_direct_delta_worker_separates_execution_clone_from_file_table(self):
        part = calibration(first_target="PART")
        whole = calibration(first_target="WHOLE")
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr(
                "Setting.ini",
                "[DeltaReproCalFile]\nFileNum=1\nFileName1=part.cuw\n"
                "[WholeReproCalFile]\nFileName=whole.cuw\n",
            )
            archive.writestr("part.cuw", part)
            archive.writestr("whole.cuw", whole)
        source = (
            b"[Vehicle]\nContactType=P5-Unified\n[DataCompression]\n"
            + payload.getvalue()
        )
        engine = self.engine(calibration())
        issued = admit_file_sources_2026(engine, "direct.scuw", source, region=0)
        engine.bind_file_sources(issued)
        self.addCleanup(engine.close)
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        worker = engine.bind_worker(controller)

        self.assertEqual(worker.loaded_metadata, (engine.native_metadata,))
        self.assertEqual(worker.online_context().all_loaded_metadata, issued.files)
        self.assertTrue(worker.persist_current_cpu)

    def test_json_delta_group_reset_atomically_replaces_worker_file_views(self):
        first = calibration(first_target="FIRST")
        second = calibration(first_target="SECOND")
        whole = calibration(first_target="WHOLE")
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr(
                "Setting.ini",
                "[DeltaReproCalFile]\nFileNum=2\nFileName1=first.cuw\n"
                "FileName2=second.cuw\n"
                "[WholeReproCalFile]\nFileName=whole.cuw\n",
            )
            archive.writestr("first.cuw", first)
            archive.writestr("second.cuw", second)
            archive.writestr("whole.cuw", whole)
        archive_source = (
            b"[Vehicle]\nContactType=P5-Unified\n[DataCompression]\n"
            + payload.getvalue()
        )
        engine = self.engine(calibration())
        issued = admit_file_sources_2026(
            engine,
            "input.json",
            b'["group.scuw"]',
            region=0,
            source_files={"group.scuw": archive_source},
        )
        engine.bind_file_sources(issued)
        self.addCleanup(engine.close)
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        worker = engine.bind_worker(controller)

        with engine.controller_execution(controller, 2):
            engine._select_worker_metadata(
                issued.files[1], controller=controller, worker=worker
            )
            replacement = issued.after_group_reset(1, worker=worker)
            engine._accept_worker_file_reset(issued, replacement, worker=worker)

        self.assertIs(engine.file_sources, replacement)
        self.assertIs(engine.native_metadata, replacement.selected_metadata)
        self.assertEqual(worker.loaded_metadata, (engine.native_metadata,))
        self.assertEqual(worker.online_context().all_loaded_metadata, replacement.files)
        self.assertTrue(worker.persist_current_cpu)

    def test_47e60_restores_typed_a48_selection_and_36800_reapplies_it(self):
        from scripts.calibration_2026 import native2026_cpu_targets, native2026_cpu_type

        first = calibration(first_target="FIRST")
        second = calibration(first_target="SECOND")
        whole = cuw(
            "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=2\n"
            "ContactType=P5-Unified\nKindOfECU=149\n"
            "[CPU01]\nCPUImageName=one.hex\nCPUType=311\nNewCID=M16C\n"
            "NumberOfTargetHardwares=1\n01_TargetHardware=\n"
            "NumberOfTargets=1\n01_TargetCalibration=OLD1\n"
            "[CPU02]\nCPUImageName=two.hex\nCPUType=312\nNewCID=FOREST\n"
            "NumberOfTargetHardwares=1\n01_TargetHardware=\n"
            "NumberOfTargets=1\n01_TargetCalibration=OLD2\n",
            (
                b"\n".join((srecord(1, 0, b"xFIRST"), srecord(7, 0))),
                b"\n".join((srecord(1, 0, b"x\x01\x02\x03\x04z"), srecord(7, 0))),
            ),
        )
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr(
                "Setting.ini",
                "[DeltaReproCalFile]\nFileNum=2\nFileName1=first.cuw\n"
                "FileName2=second.cuw\n"
                "[WholeReproCalFile]\nFileName=whole.cuw\n",
            )
            archive.writestr("first.cuw", first)
            archive.writestr("second.cuw", second)
            archive.writestr("whole.cuw", whole)
        archive_source = (
            b"[Vehicle]\nContactType=P5-Unified\n[DataCompression]\n"
            + payload.getvalue()
        )
        parameters = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": table(
                    (
                        "ParamFileKeySystemProtocolMicon",
                        "M16CTypeFlag",
                        "FORESTTypeFlag",
                        "PasswordAddress",
                        "ByteOrder",
                        "FlagToHoldSFormatRecords",
                        "FlagToDoIGOFFONAtCPUTypeChange",
                    ),
                    (
                        ("149P5-Unified311", "1", "0", "00", "1", "0", "0"),
                        ("149P5-Unified312", "0", "1", "01", "1", "0", "0"),
                    ),
                )
            },
            encoded=False,
        )
        engine = CUWEngine2026(
            (RUNTIME / "CUW.dll").read_bytes(), general_parameters=parameters
        )
        engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
        engine.load_cuw(calibration())
        issued = admit_file_sources_2026(
            engine,
            "input.json",
            b'["group.scuw"]',
            region=0,
            source_files={"group.scuw": archive_source},
        )
        engine.bind_file_sources(issued)
        self.addCleanup(engine.close)
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        self.receive(engine, controller, (b"OLD1", b"UNKNOWN"))
        worker = engine.bind_worker(controller)

        with engine.controller_execution(controller, 0):
            self.assertTrue(worker.mark_cid_reception_complete())
        self.assertEqual(worker.source_state.target_indices, (0, -1))
        with engine.controller_execution(controller, 1):
            pass
        retained = engine.native_metadata
        self.assertEqual(worker.source_state.target_indices, (1, 0))
        self.assertEqual(worker.source_state.cpu_offset, 1)
        self.assertEqual(native2026_cpu_type(retained, 0), "312")
        self.assertEqual(native2026_cpu_targets(retained, 0)[1].calibration, "FOREST")
        with engine.controller_execution(controller, 2):
            engine._select_worker_metadata(
                issued.files[1], controller=controller, worker=worker
            )
            replacement = issued.after_group_reset(1, worker=worker)
            self.assertIs(replacement.selected_metadata, retained)
            engine._accept_worker_file_reset(issued, replacement, worker=worker)
            worker._restore_file_selection_47e60()
            with self.assertRaisesRegex(ValueError, "no completed native CID"):
                _ = worker.native_writer_target_index

        with engine.controller_execution(controller, 1):
            pass
        self.assertIs(engine.native_metadata, retained)
        self.assertEqual(worker.source_state.target_indices, (1, 0))
        self.assertEqual(worker.source_state.current_global_cpu_index, 1)
        self.assertEqual(worker.native_writer_target_index, 0)
        self.assertEqual(worker.source_state.authored_target_indices, (0, -1))
        self.assertEqual(worker.source_state.authored_cpu_count, 2)
        self.assertEqual(worker.source_state.unmatched_identifiers, (b"FOREST",))
        self.assertEqual(native2026_cpu_type(engine.native_metadata, 0), "312")

    def test_control_state_keeps_fatal_failed_and_callback_fields_independent(self):

        engine = self.engine(calibration())
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        self.addCleanup(engine.close)
        worker = engine.bind_worker(controller)
        with engine.controller_execution(controller, 1):
            worker.set_control_error_kind(7)
            with self.assertRaises(ValueError):
                worker.record_callback_24(True)
            worker.record_callback_24(2)
            worker.record_callback_28(2)
            worker.record_callback_47(3)
        state = worker.control_state
        self.assertEqual(state.error_kind, 7)
        self.assertFalse(state.initial_command_retry)
        self.assertFalse(state.native_context_964)
        self.assertFalse(state.fatal)
        self.assertFalse(state.failed)
        self.assertEqual(state.source_mode, 0)
        self.assertEqual(
            (
                worker.source_state.callback_24_state,
                worker.source_state.callback_28_state,
                worker.source_state.callback_47_state,
            ),
            (2, 2, 3),
        )
        with engine.controller_execution(controller, 2):
            worker.publish_callback_25_gateway_node()
            worker.publish_callback_48_source_mode()
        self.assertEqual(engine.repro_gateway_node, 2)
        self.assertFalse(worker.control_state.use_new_password)
        self.assertEqual(worker.control_state.source_mode, 3)
        self.assertEqual(state.lifecycle, "ready")

    def test_outer_native_fatal_input_publishes_cfd0_without_local_fatal(self):
        from scripts.programming_2026_common import NativePassThruException2026

        engine = self.engine(calibration())
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        self.addCleanup(engine.close)
        worker = engine.bind_worker(controller)
        engine.dh_state.record_native_error(3, 8, 9)
        with engine.controller_execution(controller, 1):
            worker._begin_outer_control_loader()
            worker._record_outer_control_loader_failure(
                NativePassThruException2026(-7, "loader", 0x5A813)
            )
            worker._publish_outer_control_tail()

        self.assertTrue(worker.control_state.native_fatal_input)
        self.assertEqual(worker.control_state.error_kind, 0xFFFFFFF9)
        self.assertEqual(worker.control_state.primary_error, 0)
        self.assertEqual(worker.control_state.passthru_error, 0)
        self.assertTrue(engine.native_fatal_output)
        self.assertFalse(worker.control_state.fatal)
        self.assertFalse(engine.native_control_fatal_output)

    def test_finish_recovery_probe_publishes_cleared_failed_before_notifications(self):
        source = calibration()
        state = ReproInfoState((RecoveryCalibration("source.cuw", source),))
        with tempfile.TemporaryDirectory() as directory:
            persistence = CUWPersistence(Path(directory), state)
            engine = self.engine(source, persistence=persistence)
            self.addCleanup(engine.close)
            controller = make_controller(NativeRuntime2026(lambda *_: None))
            worker = engine.bind_worker(controller)
            retry = engine.bind_retry_controller()
            persistence.notification.assign(True)
            persistence.last_block_notification.assign(True)
            engine.dh_state.record_native_error(7, 8, 9)
            engine.dh_state.set_write_complete(True)
            engine.notify_write_complete()

            with engine.controller_execution(controller, 2):
                worker.copy_control_retry_decision(retry)
                self.assertTrue(worker.control_state.failed)
                worker.finish_recovery_probe(controller)

            self.assertFalse(engine.write_complete_output)
            self.assertFalse(worker.control_state.failed)
            self.assertFalse(worker.control_state.notification)
            self.assertFalse(worker.control_state.last_block_notification)
            self.assertEqual(
                (
                    engine.dh_state.error_kind,
                    engine.dh_state.primary_error,
                    engine.dh_state.passthru_error,
                ),
                (7, 8, 9),
            )

    def test_battery_path_calls_version_get_config_and_read_vbatt(self):

        calls = []

        def provider(operation, _remaining):
            calls.append(operation)
            if operation["operation"] == "passthru_read_version":
                return PrimitiveResult(value=("fw", "dll", "api"))
            if operation["operation"] == "passthru_ioctl":
                return PrimitiveResult(value=12345 if operation["ioctl"] == 3 else None)
            self.fail(f"unexpected primitive {operation}")

        device = J2534Device2026(provider, background_workers=False)
        device.opened, device.device_id = True, 7
        device.connecting, device.channel_id = True, 8
        controller = make_controller(NativeRuntime2026(device.primitive))
        engine = self.engine(calibration())
        self.addCleanup(engine.close)
        bind_engine_device(engine, device)
        worker = engine.bind_worker(controller)
        self.assertEqual(worker.read_battery_voltage(), 12.345)
        self.assertEqual(
            [(item["operation"], item.get("ioctl")) for item in calls],
            [
                ("passthru_read_version", None),
                ("passthru_ioctl", 1),
                ("passthru_ioctl", 3),
            ],
        )
        self.assertEqual(calls[1]["parameters"], ((1, 0),))

    def test_program_log_reads_actual_persistence_device_and_worker_state(self):

        source = calibration()
        state = ReproInfoState((RecoveryCalibration("source.cuw", source),))
        with tempfile.TemporaryDirectory() as directory:
            persistence = CUWPersistence(Path(directory), state)
            engine = self.engine(source, persistence=persistence)
            self.addCleanup(engine.close)
            calls = []

            def provider(operation, _remaining):
                calls.append(operation)
                if operation["operation"] == "passthru_read_version":
                    return PrimitiveResult(value=("fw", "dll", "api"))
                if operation["operation"] == "passthru_ioctl":
                    return PrimitiveResult(
                        value=12600 if operation["ioctl"] == 3 else None
                    )
                self.fail(f"unexpected primitive {operation}")

            device = J2534Device2026(provider, background_workers=False)
            device.opened, device.device_id = True, 7
            device.connecting, device.channel_id = True, 8
            controller = make_controller(NativeRuntime2026(device.primitive))
            bind_engine_device(engine, device)
            self.receive(engine, controller, (b"OLD",))
            worker = engine.bind_worker(controller)
            engine._worker_phase = 0
            self.assertIsNone(worker.programming_log_info())
            self.assertEqual(calls, [])
            engine.dh_state.record_native_error(0, 1, 9)
            engine.notify_native_errors()
            info = worker.programming_log_info()
            self.assertIsNotNone(info)
            assert info is not None
            self.assertEqual((info.filename, info.error_flag), ("source.cuw", 2))
            encoded = worker.write_programming_log(bytes([0xA5]) * 0x2160)
            self.assertIsNotNone(encoded)
            assert encoded is not None
            self.assertEqual(len(encoded), 0x2160)
            self.assertEqual(encoded[-1], 0xA5)

    def test_active_source_online_request_precedes_recovery_log_status(self):
        from scripts.cuw_online import OnlineKeyController2026
        from scripts.cuw_persistence import encode_nibble_text

        source = calibration()
        state = ReproInfoState((RecoveryCalibration("source.cuw", source),))
        with tempfile.TemporaryDirectory() as directory:
            persistence = CUWPersistence(Path(directory), state)
            engine = self.engine(source, persistence=persistence)
            self.addCleanup(engine.close)
            controller = make_controller(NativeRuntime2026(lambda *_: None))
            worker = engine.bind_worker(controller)
            engine.set_vin(b"JT123456789012345")
            encoded = encode_nibble_text(
                b"[ReproKeyRequest]\n"
                b"IFVersion=1\nSoftwareID=test\nSoftwareVersion=1\n"
                b"LicenseKey=a\nSUBARU_LicenseKey=b\nSUZUKI_LicenseKey=c\n"
                b"DAIHATSU_LicenseKey=d\nVehicleIdentificationNumber=unused\n"
                b"RequesterKind=1\nKeypairID=1\nDAIHATSU_KeypairID=2\n"
            )
            online = OnlineKeyController2026(worker, encoded)
            online.start(bytes(16))
            with engine.controller_execution(controller, 2):
                self.assertIsNone(worker.programming_log_info())
            self.assertEqual(engine.online_modal_state, 1)

    def test_program_log_uses_3c410_alternate_progress_during_continuation(self):
        source = calibration(cpus=2)
        state = ReproInfoState((RecoveryCalibration("source.cuw", source),))
        with tempfile.TemporaryDirectory() as directory:
            persistence = CUWPersistence(Path(directory), state)
            engine = self.engine(source, persistence=persistence)
            self.addCleanup(engine.close)
            control = J2534Device2026(
                lambda *_: self.fail("unexpected transport access"),
                background_workers=False,
            )
            controller = make_controller(NativeRuntime2026(control.primitive))
            bind_engine_device(engine, control)
            self.receive(engine, controller, (b"OLD", b"SECOND-OLD"))
            worker = engine.bind_worker(controller)
            with engine.controller_execution(controller, 0):
                self.assertTrue(worker.mark_cid_reception_complete())
            engine.dh_state.record_native_error(0, 1, 9)
            engine.notify_native_errors()

            with engine.controller_execution(controller, 2):
                worker.set_control_error_kind(1)
                engine.notify_native_error_kind()
                engine._retain_native_error_kind(worker=worker)
                engine._begin_continuation_backup(worker=worker)
                try:
                    engine.select_target(1, 1, controller=controller)
                    info = worker.programming_log_info()
                finally:
                    engine._end_continuation_backup(worker=worker)

            self.assertIsNotNone(info)
            assert info is not None
            self.assertEqual(info.cpu_progress_index, 0)
            self.assertIsNone(engine.continuation_backup)

    def test_cancelled_runtime_fails_before_any_device_primitive(self):

        calls = []

        def provider(operation, _remaining):
            calls.append(operation)
            return PrimitiveResult()

        device = J2534Device2026(provider, background_workers=False)
        device.opened, device.device_id = True, 7
        controller = make_controller(
            NativeRuntime2026(device.primitive, cancelled=lambda: True)
        )
        engine = self.engine(calibration())
        self.addCleanup(engine.close)
        bind_engine_device(engine, device)
        worker = engine.bind_worker(controller)
        with self.assertRaises(InterruptedError):
            worker.read_battery_voltage()
        self.assertEqual(calls, [])
        self.assertEqual(worker.control_state.lifecycle, "issued")

    def test_native_version_fault_returns_false_and_acks_only_native_handshake(self):
        def provider(operation, _remaining):
            if operation["operation"] == "passthru_read_version":
                return PrimitiveResult(status=9)
            self.fail(f"unexpected primitive {operation}")

        device = J2534Device2026(provider, background_workers=False)
        device.opened, device.device_id = True, 7
        controller = make_controller(NativeRuntime2026(device.primitive))
        engine = self.engine(calibration(first_image="authored.vbf"))
        self.addCleanup(engine.close)
        bind_engine_device(engine, device)
        worker = engine.bind_worker(controller)
        with engine.controller_execution(controller, 1):
            self.assertFalse(worker.check_device_version())
            self.assertEqual(worker.native_prepare_handshake, 2)
        self.assertEqual(worker.control_state.lifecycle, "ready")

    def test_native_vbatt_fault_raises_literal_integer_one(self):
        def provider(operation, _remaining):
            if operation["operation"] == "passthru_read_version":
                return PrimitiveResult(value=("fw", "dll", "api"))
            if operation["operation"] == "passthru_ioctl":
                return PrimitiveResult(status=9 if operation["ioctl"] == 3 else 0)
            self.fail(f"unexpected primitive {operation}")

        device = J2534Device2026(provider, background_workers=False)
        device.opened, device.device_id = True, 7
        device.connecting, device.channel_id = True, 8
        controller = make_controller(NativeRuntime2026(device.primitive))
        engine = self.engine(calibration(first_image="authored.vbf"))
        self.addCleanup(engine.close)
        bind_engine_device(engine, device)
        worker = engine.bind_worker(controller)
        with (
            self.assertRaises(NativeWorkerIntegerError2026) as caught,
            engine.controller_execution(controller, 1),
        ):
            worker.read_battery_voltage()
        self.assertEqual(caught.exception.code, 1)
        self.assertIsInstance(caught.exception.__cause__, NativeJ2534Error2026)
        self.assertEqual(worker.native_prepare_handshake, 2)
        self.assertEqual(worker.control_state.lifecycle, "faulted")

    def test_failed_version_probe_raises_literal_integer_zero(self):
        def provider(operation, _remaining):
            if operation["operation"] == "passthru_read_version":
                return PrimitiveResult(status=9)
            self.fail(f"unexpected primitive {operation}")

        device = J2534Device2026(provider, background_workers=False)
        device.opened, device.device_id = True, 7
        controller = make_controller(NativeRuntime2026(device.primitive))
        engine = self.engine(calibration())
        self.addCleanup(engine.close)
        bind_engine_device(engine, device)
        worker = engine.bind_worker(controller)
        with self.assertRaises(NativeWorkerIntegerError2026) as caught:
            worker.read_battery_voltage()
        self.assertEqual(caught.exception.code, 0)
        self.assertIsNone(caught.exception.__cause__)
        self.assertEqual(worker.control_state.lifecycle, "issued")

    def test_host_battery_fault_keeps_identity_and_does_not_ack_handshake(self):
        fault = OSError("authored host capture fault")

        def provider(operation, _remaining):
            if operation["operation"] == "passthru_read_version":
                raise fault
            self.fail(f"unexpected primitive {operation}")

        device = J2534Device2026(provider, background_workers=False)
        device.opened, device.device_id = True, 7
        controller = make_controller(NativeRuntime2026(device.primitive))
        engine = self.engine(calibration(first_image="authored.vbf"))
        self.addCleanup(engine.close)
        bind_engine_device(engine, device)
        worker = engine.bind_worker(controller)
        with (
            self.assertRaises(OSError) as caught,
            engine.controller_execution(controller, 1),
        ):
            worker.read_battery_voltage()
        self.assertIs(caught.exception, fault)
        self.assertEqual(worker.native_prepare_handshake, 1)
        self.assertEqual(worker.control_state.lifecycle, "faulted")

    def test_actual_imported_prepare_pipeline_drives_worker_lifecycle(self):
        source = cuw(
            "[Format]\nVersion=6\n[Vehicle]\nKindOfECU=1\nContactType=SIL\n"
            "NumberOfCalibration=1\n[CPU01]\nCPUType=1\nCPUImageName=one.vbf\n"
        )
        module_name = "TCUWSilPrepareWriter.dll"
        catalog = {
            "1SIL1.ini": encoded_table(
                ("ParamFileKeySystemProtocolMicon", "DLLFileNameForPrepareWrite"),
                (("1SIL1", module_name),),
            ),
            "Parameter.ini": encoded_table(
                ("ParamFileKeySystemProtocolMicon", "M16CTypeFlag"),
                (("1SIL1", "0"),),
            ),
        }
        context = {
            "schema": "techstream-programming-replay-v1",
            "source": "recorded_unverified",
            "calibration_sha256": hashlib.sha256(source).hexdigest(),
            "operation": "prepare",
            "node": 1,
            "observations": {
                "current_cids": [],
                "tester_info_hex": bytes(32).hex(),
                "system_time": [2026, 10, 20, 20, 1, 2, 3, 4],
                "timeout_seconds": 30,
                "cid_mode": 2,
                "host": {},
            },
            "events": [
                {
                    "kind": "action",
                    "request": {"operation": "get_local_milliseconds_of_day"},
                    "result": {"type": "int", "value": 1000},
                    "elapsed_ms": 0,
                },
                {
                    "kind": "action",
                    "request": {"operation": "get_local_milliseconds_of_day"},
                    "result": {"type": "int", "value": 1017},
                    "elapsed_ms": 0,
                },
            ],
        }
        module = (RUNTIME / module_name).read_bytes()
        session = load_programming_replay(
            source,
            json.dumps(context).encode(),
            catalog,
            {module_name: module},
        )
        runtime = NativeRuntime2026(
            session.trace.action,
            clock=session.trace.clock,
            cancelled=session.trace.cancelled,
            local_seconds_of_day=session.trace.native_local_seconds_of_day,
            local_milliseconds_of_day=session.trace.native_local_milliseconds_of_day,
        )
        general = NativeGeneralParameters2026.from_sources(catalog, encoded=True)
        engine = CUWEngine2026(
            (RUNTIME / "CUW.dll").read_bytes(), general_parameters=general
        )
        engine.configure(struct.pack("<IIddII", 1, 0, 1, 2, 0, 0))
        engine.load_cuw(source)
        self.addCleanup(engine.close)
        controller = make_controller(runtime)
        worker = engine.bind_worker(controller)
        report = controller.run_bound_export(engine, session)
        self.assertTrue(report["native_return"])
        self.assertTrue(session.used)
        self.assertEqual(worker.native_getter_cpu_type, "1")
        self.assertEqual(worker.control_state.lifecycle, "ready")
        self.assertFalse(worker.source_state.complete)
        session.trace.assert_complete()


if __name__ == "__main__":
    unittest.main()
