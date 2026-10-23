import hashlib
import io
import json
import struct
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace

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
    contact_type: str = "P5-Unified",
) -> bytes:
    gateway = "NumberOfGateway=1\n01_GatewayDiagID=0751\n" if daihatsu else ""
    text = (
        "[Format]\nVersion=105\n[Vehicle]\nNumberOfNode=1\n"
        f"ContactType={contact_type}\nKindOfECU=149\n"
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
    def test_actual_ordinary_early_one_to_three_has_no_scheduling_tail(self):
        from tests.test_cuw_engine_threads import ThreadOwnershipTests

        fixture = ThreadOwnershipTests("runTest")
        engine, controller, job, session = fixture.imported_prepare(paired=True)
        self.addCleanup(fixture.doCleanups)
        controller.runtime.local_milliseconds_of_day = lambda: 1000
        session.trace.native_local_milliseconds_of_day = (
            controller.runtime.local_milliseconds_of_day
        )
        # This real standalone source prefix produces BE8=1 on the same CStart.
        # It is not a completed phase1 child or active-child reentry proof.
        with engine.controller_execution(controller, 1):
            pass
        self.assertEqual(job.worker.native_prepare_handshake, 1)
        flags = (
            engine._native_outer_cfe0_2026,
            engine._native_be54_pending2026,
            engine._native_receiving_cfe2_2026,
        )
        reads = []
        controller.runtime.local_milliseconds_of_day = lambda: reads.append(1) or 23456
        job.start(session)
        self.assertEqual(job.worker.native_prepare_handshake, 3)
        self.assertEqual(reads, [1])
        self.assertEqual(engine.native_phase, 1)
        self.assertEqual(engine._native_prepare_d314_2026, 23456)
        self.assertEqual(
            (
                engine._native_outer_cfe0_2026,
                engine._native_be54_pending2026,
                engine._native_receiving_cfe2_2026,
            ),
            flags,
        )
        self.assertEqual(job.state.sequence, 0)
        self.assertIsNone(job._active_record)
        self.assertIsNone(job._lease)
        self.assertIsNone(job._prepared_ordinary_entry2026)
        self.assertIsNone(job._ordinary_prepare_origin2026)
        self.assertFalse(session.used)
        self.assertEqual(session.trace.position, 0)

    def _ordinary_rebuild_fixture(self, source, *, persistence=None, cpu_index=0):
        from tests.test_cuw_engine_threads import ThreadOwnershipTests

        fixture = ThreadOwnershipTests("runTest")
        catalog = {
            name + ".ini": encoded_table(
                ("ParamFileKeySystemProtocolMicon", "DLLFileNameForPrepareWrite"),
                ((name, "TCUWCanReproStdPrepareWriter.dll"),),
            )
            for name in (
                "149P5-Unified",
                "149P5-Unified03",
                "149P5-Unified311",
                "149P5-Unified312",
            )
        }
        catalog["Parameter.ini"] = encoded_table(
            (
                "ParamFileKeySystemProtocolMicon",
                "M16CTypeFlag",
                "FORESTTypeFlag",
                "PasswordAddress",
                "ByteOrder",
                "FlagToHoldSFormatRecords",
            ),
            (
                ("149P5-Unified", "0", "0", "00", "1", "0"),
                ("149P5-Unified311", "1", "0", "00", "1", "0"),
                ("149P5-Unified312", "0", "1", "01", "1", "0"),
            ),
        )
        result = fixture.imported_prepare(
            paired=True,
            source=source,
            cpu_maximum=2,
            cpu_index=cpu_index,
            persistence=persistence,
            module_name="TCUWCanReproStdPrepareWriter.dll",
            catalog_sources=catalog,
        )
        self.addCleanup(fixture.doCleanups)
        return result

    def test_actual_ordinary_prefix_publishes_zero_file_before_late_cpu_fault(self):
        from scripts.calibration_2026 import native2026_cpu_count

        engine, controller, job, session = self._ordinary_rebuild_fixture(
            calibration(cpus=2, first_image="authored.hex")
        )
        controller.runtime.local_milliseconds_of_day = lambda: 1000
        session.trace.native_local_milliseconds_of_day = (
            controller.runtime.local_milliseconds_of_day
        )
        self.receive(engine, controller, (b"UNKNOWN", b"OTHER"))
        worker = job.worker
        with engine.controller_execution(controller, 0):
            self.assertFalse(worker.mark_cid_reception_complete())
        self.assertEqual(
            worker._judge_live_selection2026.unmatched_ids, (b"NEW1", b"NEW2")
        )
        before = worker.source_state
        clock_reads = []
        controller.runtime.local_milliseconds_of_day = lambda: (
            clock_reads.append(1) or 12345
        )
        native_flags = (
            engine._native_outer_cfe0_2026,
            engine._native_be54_pending2026,
            engine._native_receiving_cfe2_2026,
        )
        source = engine.native_metadata.source_container
        self.assertEqual(before.cpu_offset, 0)
        session.trace.native_local_milliseconds_of_day = (
            controller.runtime.local_milliseconds_of_day
        )
        with self.assertRaisesRegex(ValueError, "Native CPU getter index absent"):
            job.start(session)
        self.assertEqual(clock_reads, [1])
        self.assertEqual(engine._native_prepare_d314_2026, 12345)
        self.assertEqual(engine.native_phase, 1)
        self.assertEqual(
            (
                engine._native_outer_cfe0_2026,
                engine._native_be54_pending2026,
                engine._native_receiving_cfe2_2026,
            ),
            native_flags,
        )
        self.assertFalse(session.used)
        self.assertEqual(session.trace.position, 0)
        self.assertEqual(native2026_cpu_count(engine.native_metadata), 0)
        self.assertIs(engine.native_metadata.source_container, source)
        self.assertIs(worker._all_loaded_metadata[0], engine.native_metadata)
        self.assertEqual(
            worker._current_global_cpu_index, before.current_global_cpu_index
        )
        self.assertEqual(
            (worker._current_node, worker._current_cpu_index),
            (before.current_node, before.current_cpu_index),
        )
        self.assertTrue(worker._cid_rebuild_done_3542026)
        self.assertEqual(job.state.sequence, 0)
        self.assertIsNone(job._lease)
        self.assertIsNone(job._ordinary_prepare_origin2026)

    def test_actual_recovery_prefix_keeps_short_file_and_supersedes_cpu_proof(self):
        from scripts.calibration_2026 import native2026_cpu_count
        from scripts.cuw_persistence import encode_recovery_info, parse_recovery_info
        from tests.test_calibration_2026 import logical_text

        logical = (
            logical_text()
            .replace("[Vehicle]", "[Vehicle]\nKindOfECU=149")
            .replace("NumberOfLogicalBlock=1", "NumberOfLogicalBlock=2")
        )
        logical += (
            "[LogicalBlock102]\nNewCID=SECOND\nNumberOfTargets=1\n"
            "01_TargetCalibration=SECOND-OLD\nReproMethod=02\n"
            "[ReproData102]\nStartAddress=00001004\nLength=00000004\n"
        )
        for source, received, expected_count, expected_cpu in (
            (calibration(cpus=2, first_image="authored.hex"), (b"OLD", b"OTHER"), 1, 1),
            (cuw(logical, (b"data", b"more")), (b"UNKNOWN", b"OTHER"), 0, 0),
        ):
            with (
                self.subTest(expected_count=expected_count),
                tempfile.TemporaryDirectory() as directory,
            ):
                saved = RecoveryCalibration(
                    "authored.cuw", source, saved_path=r"C:\saved\authored.cuw"
                )
                document = parse_recovery_info(
                    encode_recovery_info(
                        ReproInfoState(
                            (saved,),
                            multi_calibration_file_num=1,
                            write_cpu_index=1,
                            use_new_software_password=True,
                            offset_of_write_cpu_multi_cal_index=4,
                        )
                    )
                )
                persistence = CUWPersistence.import_recovery(
                    Path(directory),
                    document,
                    {saved.saved_path: source},
                    cpu_capacity=2,
                )
                engine, controller, job, session = self._ordinary_rebuild_fixture(
                    source, persistence=persistence, cpu_index=1
                )
                controller.runtime.local_milliseconds_of_day = lambda: 1000
                session.trace.native_local_milliseconds_of_day = (
                    controller.runtime.local_milliseconds_of_day
                )
                worker = job.worker
                self.assertTrue(worker.control_state.recovery_mode)
                self.assertEqual(worker.source_state.current_global_cpu_index, 1)
                self.assertEqual(worker.source_state.cpu_offset, 0)
                self.receive(engine, controller, received)
                with engine.controller_execution(controller, 0):
                    self.assertEqual(
                        worker.mark_cid_reception_complete(), expected_count == 1
                    )
                original_metadata = engine.native_metadata
                reads = []
                controller.runtime.local_milliseconds_of_day = lambda reads=reads: (
                    reads.append(1) or 34567
                )
                session.trace.native_local_milliseconds_of_day = (
                    controller.runtime.local_milliseconds_of_day
                )
                with self.assertRaisesRegex(
                    ValueError, "Native CPU getter index absent"
                ):
                    job.start(session)
                self.assertEqual(reads, [1])
                self.assertEqual(engine.native_phase, 2)
                self.assertEqual(engine._native_prepare_d314_2026, 34567)
                self.assertTrue(persistence.notification)
                self.assertTrue(worker.control_state.use_new_password)
                self.assertEqual(worker.source_state.progress_base, 4)
                self.assertEqual(worker.source_state.cpu_offset, 0)
                self.assertEqual(
                    native2026_cpu_count(engine.native_metadata), expected_count
                )
                self.assertIs(worker._all_loaded_metadata[0], engine.native_metadata)
                self.assertIs(
                    engine.native_metadata.source_container,
                    original_metadata.source_container,
                )
                self.assertEqual(worker._current_global_cpu_index, expected_cpu)
                self.assertEqual(worker._current_cpu_index, expected_cpu)
                self.assertTrue(worker._cid_rebuild_done_3542026)
                self.assertEqual(persistence.state.write_cpu_index, 1)
                proof = engine._persistence_cpu_transition2026
                if expected_cpu == 1:
                    self.assertIsNone(proof)
                    self.assertEqual(engine.dh_state._progress[0], 100)
                else:
                    self.assertIsNotNone(proof)
                    assert proof is not None
                    self.assertEqual(
                        (
                            proof.producer,
                            proof.persisted_cpu,
                            proof.before_cpu,
                            proof.after_cpu,
                        ),
                        ("ordinary-36800", 1, 0, 0),
                    )
                    self.assertIs(proof.metadata, engine.native_metadata)
                    self.assertFalse(
                        engine._persistence_cpu_transition_valid2026(
                            original_metadata, persistence.state, None, 0
                        )
                    )
                engine._validate_persistence_source(engine.native_metadata)
                self.assertEqual(job.state.sequence, 0)
                self.assertIsNone(job._lease)
                self.assertIsNone(job._ordinary_prepare_origin2026)
                self.assertFalse(session.used)
                self.assertEqual(session.trace.position, 0)

    def test_actual_ordinary_forest_cpu_store_rebinds_its_selection_cache(self):
        from unittest.mock import patch

        source = cuw(
            "[Format]\nVersion=8\n[Vehicle]\nNumberOfCalibration=2\n"
            "ContactType=P5-Unified\nKindOfECU=149\n"
            "[CPU01]\nCPUImageName=one.hex\nCPUType=311\nNewCID=M16C\n"
            "NumberOfTargets=1\n01_TargetCalibration=OLD1\n"
            "[CPU02]\nCPUImageName=two.hex\nCPUType=312\nNewCID=FOREST\n"
            "NumberOfTargets=1\n01_TargetCalibration=OLD2\n",
            (
                srecord(1, 0, b"xFIRST") + b"\n" + srecord(7, 0),
                srecord(1, 0, b"x\x01\x02\x03\x04z") + b"\n" + srecord(7, 0),
            ),
        )
        engine, controller, job, session = self._ordinary_rebuild_fixture(source)
        worker = job.worker
        controller.runtime.local_milliseconds_of_day = lambda: 1000
        session.trace.native_local_milliseconds_of_day = (
            controller.runtime.local_milliseconds_of_day
        )
        self.receive(engine, controller, (b"OLD1", b"UNKNOWN"))
        with engine.controller_execution(controller, 0):
            self.assertTrue(worker.mark_cid_reception_complete())
        sentinel = OSError("authored child-entry fault after actual ordinary prefix")
        original = worker._phase_started
        observed = []

        def observe_initializer(phase, **kwargs):
            # The input root held CPU0; the real FOREST tail selected CPU1.
            self.assertFalse(job._is_raw_control_ordinary_root2026(session))
            receipt = job._prepared_ordinary_entry2026
            self.assertIsNotNone(receipt)
            job._prepared_ordinary_entry2026 = None
            try:
                with self.assertRaisesRegex(ValueError, "no unconsumed36800 receipt"):
                    original(phase, **kwargs)
                self.assertIsNone(worker._phase_started_ms)
            finally:
                job._prepared_ordinary_entry2026 = receipt
            original(phase, **kwargs)
            selection = worker._selections_by_file[0]
            assert selection is not None
            self.assertIs(selection.rebuilt_metadata, engine.native_metadata)
            self.assertEqual(worker.source_state.cpu_offset, 1)
            self.assertEqual(worker.source_state.current_global_cpu_index, 1)
            self.assertEqual(selection.target_indices, (1, 0))
            observed.append(selection)
            raise sentinel

        with patch.object(worker, "_phase_started", observe_initializer):
            job.start(session)
            with self.assertRaises(OSError) as caught:
                job.result(2)
        self.assertIs(caught.exception, sentinel)
        self.assertEqual(len(observed), 1)
        self.assertTrue(worker._cid_rebuild_done_3542026)
        self.assertFalse(session.used)
        self.assertEqual(session.trace.position, 0)

    def test_actual_child_consumes_ordinary_receipt_before_once_initializer(self):
        from unittest.mock import patch

        from scripts.j2534_2026 import DriverMetadata2026
        from tests.test_cuw_engine_threads import ThreadOwnershipTests

        events_path = Path(
            "runtime/no-car-next-20261022/retry-regressions/prepare-ack-parked-sdk.json"
        )
        events = json.loads(read_private_bytes(events_path))
        fixture = ThreadOwnershipTests("runTest")
        engine, controller, job, session = fixture.imported_prepare(
            recorded_driver=True, events=events
        )
        self.addCleanup(fixture.doCleanups)
        pair = engine.interface_pair
        assert pair is not None
        descriptor = DriverMetadata2026("Authored offline SDK", "offline.dll")
        pair.engine.set_driver(descriptor)
        pair.control.set_driver(descriptor)
        reads = []
        clock = lambda: reads.append(1) or 1000
        session.trace.native_local_milliseconds_of_day = clock
        controller.runtime.local_milliseconds_of_day = clock
        session.bind_runtime2026(controller.runtime)
        session.bind_engine2026(engine)
        session.bind_controller2026(controller)
        engine.bind_retry_controller()
        worker = job.worker
        original = worker._phase_started
        consumed = []

        def observe_initializer(phase, **kwargs):
            receipt = job._prepared_ordinary_entry2026
            original(phase, **kwargs)
            self.assertTrue(job.is_child_thread)
            self.assertIsNotNone(receipt)
            self.assertIsNone(job._prepared_ordinary_entry2026)
            self.assertEqual(reads, [1])
            self.assertEqual(worker._phase_started_ms, 1000)
            with self.assertRaisesRegex(ValueError, "already initialized"):
                original(phase)
            self.assertEqual(reads, [1])
            self.assertIsNone(job._prepared_ordinary_entry2026)
            consumed.append(receipt)

        with patch.object(worker, "_phase_started", observe_initializer):
            job.start(session)
            report = job.result(2)
        self.assertEqual(len(consumed), 1)
        self.assertIs(report["native_return"], False)
        self.assertTrue(job.state.waiting_for_resume)
        self.assertIsNone(job._ordinary_prepare_origin2026)
        self.assertIsNone(job._prepared_ordinary_entry2026)
        # Consume the rest of this real captured native-fault/cleanup trajectory.
        pair.engine.open()
        self.assertFalse(worker.check_device_version())
        self.assertTrue(fixture.doCleanups())
        session.trace.assert_complete()

    def test_reached_rebuild_file_keeps_an_unresolved_numeric_cursor(self):
        from scripts.calibration_2026 import (
            NativeCIDRebuildMetadata2026,
            native2026_cpu_count,
            native2026_rebuild_current_cids_steps,
        )
        from scripts.cuw_engine_worker import EngineWorker2026
        from tests.test_calibration_2026 import Calibration2026Tests

        fixture = Calibration2026Tests("runTest")
        metadata, general, configuration = fixture._current_rebuild_input()
        for unmatched, expected_count in (
            ((b"M16C", b"FOREST"), 0),
            ((b"FOREST",), 1),
        ):
            with self.subTest(unmatched=unmatched):
                iterator = native2026_rebuild_current_cids_steps(
                    metadata,
                    (-1,) * 4,
                    unmatched,
                    (),
                    general,
                    configuration=configuration,
                )
                step = next(
                    value
                    for value in iterator
                    if isinstance(value, NativeCIDRebuildMetadata2026)
                )
                self.assertEqual(step.operation, "16ae0")
                self.assertEqual(native2026_cpu_count(step.metadata), expected_count)
                # Native FILE publication precedes any later CPU-dependent work.
                self.assertIs(
                    EngineWorker2026._ordinary_file_metadata_for_cursor_3e710_2026(
                        step.metadata, 1
                    ),
                    step.metadata,
                )
                self.assertFalse(
                    EngineWorker2026._ordinary_is_logical_cpu_19710_2026(
                        step.metadata, 1
                    )
                )

    def test_control_password_projection_reads_actual_dh_password_field(self):
        engine = self.engine(calibration())
        self.addCleanup(engine.close)
        worker = engine.bind_worker(make_controller(NativeRuntime2026(lambda *_: None)))
        self.assertFalse(worker.control_state.use_new_password)
        engine.dh_state.set_use_new_password(True)
        self.assertTrue(worker.control_state.use_new_password)
        self.assertEqual(engine.repro_gateway_node, 0)

    def test_ordinary_prepare_requires_actual_start_origin_before_source_writes(self):
        engine = self.engine(calibration())
        self.addCleanup(engine.close)
        worker = engine.bind_worker(make_controller(NativeRuntime2026(lambda *_: None)))
        before = worker.source_state
        with self.assertRaises(ValueError):
            worker._apply_ordinary_prepare_36800_2026(origin=object())
        self.assertEqual(worker.source_state, before)

    def test_late_wait_restore_rejects_naked_origin_without_changing_engine_epoch(self):
        engine = self.engine(calibration())
        self.addCleanup(engine.close)
        worker = engine.bind_worker(make_controller(NativeRuntime2026(lambda *_: None)))
        epoch = engine._wait_timing_epoch2026
        with self.assertRaises(ValueError):
            worker._consume_file_wait_restore_origin_32ff0_2026(object(), engine=engine)
        with self.assertRaises(ValueError):
            worker._restore_judge_file_waits_32ff0_2026(object(), 0)
        with self.assertRaises(ValueError):
            worker._validate_frontend_selection_41940_2026(
                engine.native_metadata, engine=engine
            )
        self.assertEqual(engine._wait_timing_epoch2026, epoch)
        self.assertIsNone(worker._file_wait_restore_origin2026)

    def test_a48_pointer_cache_keeps_original_keys_after_real_mode2_compaction(self):
        from scripts.cuw_engine_worker import _native_a48_cache_slot2026

        def archive_source(target):
            payload = io.BytesIO()
            with zipfile.ZipFile(payload, "w") as archive:
                archive.writestr(
                    "Setting.ini",
                    "[DeltaReproCalFile]\nFileNum=2\nFileName1=one.cuw\n"
                    "FileName2=two.cuw\n[WholeReproCalFile]\nFileName=whole.cuw\n",
                )
                archive.writestr("one.cuw", calibration(first_target=target))
                archive.writestr("two.cuw", calibration(first_target=target + "2"))
                archive.writestr("whole.cuw", calibration(first_target=target + "W"))
            return (
                b"[Vehicle]\nContactType=P5-Unified\n[DataCompression]\n"
                + payload.getvalue()
            )

        engine = self.engine(calibration())
        self.addCleanup(engine.close)
        sources = admit_file_sources_2026(
            engine,
            "input.json",
            b'["first.scuw","plain.cuw","second.scuw"]',
            region=0,
            source_files={
                "first.scuw": archive_source("FIRST"),
                "plain.cuw": calibration(),
                "second.scuw": archive_source("SECOND"),
            },
        )
        engine.bind_file_sources(sources)
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        worker = engine.bind_worker(controller)
        second_container = sources.files[3].source_container
        self.assertEqual(_native_a48_cache_slot2026(sources, 0), 0)
        self.assertEqual(_native_a48_cache_slot2026(sources, 1), 0)
        self.assertEqual(_native_a48_cache_slot2026(sources, 3), 1)
        self.assertEqual(_native_a48_cache_slot2026(sources, 4), 1)
        with engine.controller_execution(controller, 2):
            replacement = sources.after_group_reset(0, worker=worker)
            engine._accept_worker_file_reset(sources, replacement, worker=worker)
        self.assertIs(replacement.files[2].source_container, second_container)
        self.assertEqual(_native_a48_cache_slot2026(replacement, 2), 1)
        self.assertEqual(_native_a48_cache_slot2026(replacement, 3), 1)
        self.assertIsNone(_native_a48_cache_slot2026(replacement, 0))

    def test_cold_41940_retains_failed_general_key_before_judge_rows(self):
        from scripts.programming_2026_common import (
            NativeFrontendParameters2026,
            NativePassThruException2026,
        )

        frontend = NativeFrontendParameters2026.from_sources(
            {
                "Parameter.ini": table(
                    (
                        "ParamFileKeySystemProtocolMicon",
                        "M16CTypeFlag",
                        "FORESTTypeFlag",
                    ),
                    (("149P5-Unified311", "0", "0"),),
                ),
                "CanIDTable.ini": table(("RequestCANID", "CalibrationType"), ()),
                "LogicalAddressTable.ini": table(
                    ("LogicalAddress", "CalibrationType"), ()
                ),
            },
            encoded=False,
        )
        engine = CUWEngine2026(
            read_private_bytes(RUNTIME / "CUW.dll"), general_parameters=frontend.general
        )
        self.addCleanup(engine.close)
        engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
        engine.bind_frontend_parameters(frontend)
        source = calibration(contact_type="Classic")
        sources = admit_file_sources_2026(
            engine,
            "input.json",
            b'["plain.cuw"]',
            region=0,
            source_files={"plain.cuw": source},
        )
        with self.assertRaises(NativePassThruException2026) as caught:
            engine.bind_file_sources(sources)
        self.assertEqual(caught.exception.line, 0x2B72)
        self.assertEqual(engine._wait_general_keys2026, ("149", "", "Classic"))
        self.assertIsNone(engine._worker)
        self.assertIsNone(engine._judge_flashable_invocation2026)

    def test_5ffc0_early_3006_preserves_reused_caller_outputs(self):
        from scripts.cuw_2026 import NativeFlashabilityRow2026
        from scripts.cuw_engine_worker import _NativeJudgeRows2026

        engine = self.engine(calibration(contact_type="Classic"))
        self.addCleanup(engine.close)
        worker = engine.bind_worker(make_controller(NativeRuntime2026(lambda *_: None)))
        row = NativeFlashabilityRow2026(bytes(333))
        buffers = _NativeJudgeRows2026(True, (row,), 1)
        self.assertEqual(
            worker._judge_flashable_file_5ffc0_2026(1, None, buffers=buffers),
            (3006, True, (row,)),
        )
        self.assertTrue(buffers.check_target)
        self.assertEqual(buffers.rows, (row,))
        self.assertEqual(buffers.count, 1)

    def test_native_35c60_classic_label_uses_first_cpu_general_key(self):
        from scripts.cuw_engine_worker import (
            EngineWorker2026,
            _native_flashability_row2026,
        )

        source = calibration(contact_type="Classic")
        general = NativeGeneralParameters2026.from_sources(
            {
                "Parameter.ini": table(
                    ("ParamFileKeySystemProtocolMicon", "KindOfECUNames"),
                    (("149Classic", "Front\nRear\nSpare\nExtra"),),
                )
            },
            encoded=False,
        )
        engine = CUWEngine2026(
            read_private_bytes(RUNTIME / "CUW.dll"), general_parameters=general
        )
        self.addCleanup(engine.close)
        engine.configure(struct.pack("<IIddII", 4, 0, 0, 0, 0, 0))
        engine.load_cuw(source)
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        worker = engine.bind_worker(controller)
        self.assertIsInstance(worker, EngineWorker2026)
        row = _native_flashability_row2026(
            old_cid=b"OLD",
            new_cid=b"NEW",
            companion=b"",
            eligible=False,
            description=b"",
            terminal=False,
        )
        self.assertEqual(
            worker._native_flashability_description_35c60_2026(
                engine.native_metadata, None, row, 2
            ),
            b"Rear",
        )

    def test_native_flashability_row_packs_bounded_source_fields(self) -> None:
        from scripts.cuw_engine_worker import _native_flashability_row2026

        raw = _native_flashability_row2026(
            old_cid=b"OLD",
            new_cid=b"NEW",
            companion=b"NODE",
            eligible=True,
            description=b"label",
            terminal=False,
        )
        self.assertEqual(len(raw), 333)
        self.assertEqual(raw[:4], b"OLD\0")
        self.assertEqual(raw[0x22:0x26], b"NEW\0")
        self.assertEqual(raw[0x44:0x49], b"NODE\0")
        self.assertEqual(raw[0x4B], 1)
        self.assertEqual(raw[0x4C:0x52], b"label\0")
        self.assertEqual(raw[0x14C], 0)
        with self.assertRaises(ValueError):
            _native_flashability_row2026(
                old_cid=b"x" * 34,
                new_cid=b"",
                companion=b"",
                eligible=False,
                description=b"",
                terminal=False,
            )

    def test_native_flashability_stable_rows_preserve_four_source_passes(self) -> None:
        from scripts.cuw_engine_worker import (
            _native_flashability_row2026,
            _native_flashability_stable_rows62330_2026,
        )

        rows = (
            _native_flashability_row2026(
                old_cid=b"A",
                new_cid=b"B",
                companion=b"N",
                eligible=False,
                description=b"",
                terminal=False,
            ),
            _native_flashability_row2026(
                old_cid=b"",
                new_cid=b"C",
                companion=b"N",
                eligible=False,
                description=b"",
                terminal=False,
            ),
            _native_flashability_row2026(
                old_cid=b"X",
                new_cid=b"Y",
                companion=b"N",
                eligible=True,
                description=b"",
                terminal=False,
            ),
            _native_flashability_row2026(
                old_cid=b"A",
                new_cid=b"D",
                companion=b"N",
                eligible=False,
                description=b"",
                terminal=False,
            ),
            _native_flashability_row2026(
                old_cid=b"Q",
                new_cid=b"",
                companion=b"N",
                eligible=False,
                description=b"",
                terminal=False,
            ),
        )
        result = _native_flashability_stable_rows62330_2026(rows)
        self.assertEqual(
            [row[0x4B] for row in result],
            [1, 0, 0, 0],
        )
        self.assertEqual(
            [row[:0x22].split(b"\0", 1)[0] for row in result],
            [b"X", b"A", b"Q", b""],
        )

    def test_native_stable_rows_dedupe_against_all_earlier_passes(self):
        from scripts.cuw_engine_worker import (
            _native_flashability_row2026,
            _native_flashability_stable_rows62330_2026,
        )

        def row(old, new, eligible=False):
            return _native_flashability_row2026(
                old_cid=old,
                new_cid=new,
                companion=b"K",
                eligible=eligible,
                description=b"",
                terminal=False,
            )

        eligible = row(b"A", b"B", True)
        distinct = row(b"C", b"D")
        self.assertEqual(
            _native_flashability_stable_rows62330_2026(
                (
                    row(b"", b"D"),
                    row(b"A", b"X"),
                    eligible,
                    row(b"A", b""),
                    distinct,
                    row(b"", b"B"),
                )
            ),
            (eligible, distinct),
        )

    def test_native_getter_query_record_maps_to_recovery_address(self):
        from scripts.cuw_engine_worker import _native_getter_requested_address2026
        from scripts.cuw_persistence import RequestedAddress

        record = (1).to_bytes(4, "little") + b"01A0\0\0\0\0"
        self.assertEqual(
            _native_getter_requested_address2026(record),
            RequestedAddress("01A0", logical=True),
        )
        with self.assertRaises(UnicodeDecodeError):
            _native_getter_requested_address2026(
                (1).to_bytes(4, "little") + b"\xff\0\0\0\0\0\0\0"
            )

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

    def cold_initial_reset_worker(
        self, *, initial_maximum: int, configured_maximum: int
    ):
        from scripts.programming_2026_common import NativeFrontendParameters2026

        general_sources = {
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
            ),
            "CanIDTable.ini": table(
                ("RequestCANID", "CalibrationType"), (("7E0", "17"),)
            ),
            "LogicalAddressTable.ini": table(
                ("LogicalAddress", "CalibrationType"), (("0103", "18"),)
            ),
        }
        frontend = NativeFrontendParameters2026.from_sources(
            general_sources, encoded=False
        )
        image = Path("runtime/no-car-21/recovered/CUW.dll")
        engine = CUWEngine2026(image.read_bytes(), general_parameters=frontend.general)
        if initial_maximum:
            engine.configure(struct.pack("<IIddII", initial_maximum, 0, 0, 0, 0, 0))
        engine.bind_frontend_parameters(frontend)
        if configured_maximum != initial_maximum:
            engine.configure(struct.pack("<IIddII", configured_maximum, 0, 0, 0, 0, 0))
        engine.load_cuw(calibration())
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        return engine, controller

    def cold_worker_for_recording(self, source_engine, source_session):
        from scripts.programming_2026_common import NativeFrontendParameters2026
        from scripts.programming_replay import load_programming_replay

        source = source_engine._source
        assert isinstance(source, bytes)
        catalog = dict(source_session._catalog_sources)
        catalog.setdefault(
            "CanIDTable.ini",
            encoded_table(("RequestCANID", "CalibrationType"), (("0200", "0"),)),
        )
        catalog.setdefault(
            "LogicalAddressTable.ini",
            encoded_table(("LogicalAddress", "CalibrationType"), (("0103", "0"),)),
        )
        session = load_programming_replay(
            source,
            json.dumps(source_session.context).encode(),
            catalog,
            source_session._module_files,
        )
        self.addCleanup(session.trace.close)
        runtime = NativeRuntime2026(
            session.trace.action,
            clock=session.trace.clock,
            cancelled=session.trace.cancelled,
            local_seconds_of_day=session.trace.native_local_seconds_of_day,
            local_milliseconds_of_day=session.trace.native_local_milliseconds_of_day,
        )
        session.bind_runtime2026(runtime)
        frontend = NativeFrontendParameters2026.from_sources(catalog, encoded=True)
        engine = CUWEngine2026(
            (RUNTIME / "CUW.dll").read_bytes(),
            general_parameters=frontend.general,
        )
        self.addCleanup(engine.close)
        engine.bind_frontend_parameters(frontend)
        engine.configure(struct.pack("<IIddII", 4, 0, 1, 2, 0, 0))
        engine.load_cuw(source)
        controller = make_controller(runtime)
        pair = session.trace.interface_pair
        assert pair is not None
        from scripts.j2534_2026 import DriverMetadata2026

        for view in (pair.engine, pair.control):
            view.set_current_driver(DriverMetadata2026("Authored", "authored.dll"))
        engine.bind_interface_pair(pair)
        worker = engine.bind_worker(controller)
        return engine, controller, session, worker

    def test_cold_40580_projection_uses_historical_capacity_without_resetting_4e0(self):
        from unittest.mock import patch

        from scripts.cuw_engine_worker import EngineWorker2026

        for initial_maximum, configured_maximum in ((4, 4), (0, 4), (4, 8)):
            with self.subTest(
                initial_maximum=initial_maximum,
                configured_maximum=configured_maximum,
            ):
                engine, controller = self.cold_initial_reset_worker(
                    initial_maximum=initial_maximum,
                    configured_maximum=configured_maximum,
                )
                self.addCleanup(engine.close)
                origins = []
                apply_initial_reset = (
                    EngineWorker2026._apply_initial_getter_reset_40580_2026
                )

                def observe_initial_reset(
                    worker,
                    origin,
                    _origins=origins,
                    _apply=apply_initial_reset,
                ):
                    _origins.append(origin)
                    _apply(worker, origin)

                with patch.object(
                    EngineWorker2026,
                    "_apply_initial_getter_reset_40580_2026",
                    observe_initial_reset,
                ):
                    worker = engine.bind_worker(controller)
                self.assertEqual(len(origins), 1)
                self.assertIs(engine.native_metadata, worker.loaded_metadata[0])
                self.assertEqual(engine.received_identifiers, ())
                self.assertEqual(worker._getter_reset_epoch2026, 1)
                self.assertEqual(len(worker._getter_histories_a34_2026), 16)
                self.assertEqual(worker._getter_flow_received_cids2026, ((),) * 16)
                self.assertEqual(worker._getter_flow_query_records2026, ((),) * 16)
                self.assertEqual(
                    worker._getter_file_a48_received_cids2026, (None,) * 16
                )
                configuration = engine.configuration
                if configuration is None:
                    self.fail("cold fixture lost its CPU configuration")
                self.assertEqual(
                    worker._getter_configured_masks_4f0_2026,
                    configuration.source_cpu_flags,
                )
                self.assertEqual(
                    tuple(map(len, worker._getter_configured_masks_4f0_2026)),
                    (configured_maximum,) * 16,
                )
                for history in worker._getter_histories_a34_2026:
                    self.assertEqual(history.received_cids, ())
                    self.assertEqual(history.query_records, ())
                    self.assertEqual(len(history.node_strings_28), initial_maximum)
                    self.assertEqual(len(history.node_strings_50), initial_maximum)
                    self.assertEqual(len(history.node_strings_78), initial_maximum)
                    self.assertEqual(len(history.node_strings_a0), initial_maximum)
                    self.assertEqual(
                        len(history.cell_dword_bits_c8), 32 * initial_maximum
                    )
                    self.assertEqual(len(history.cell_strings_d4), 32 * initial_maximum)
                    self.assertEqual(len(history.retained_bits_fc), initial_maximum)
                    self.assertEqual(len(history.node_dword_bits_10c), initial_maximum)
                self.assertEqual(len(worker._node_strings_4402026), initial_maximum)
                self.assertEqual(
                    len(worker._cell_dword_bits_5542026), 32 * initial_maximum
                )
                self.assertEqual(
                    len(worker._cell_strings_5602026), 32 * initial_maximum
                )
                self.assertEqual(len(worker._retained_bits_5882026), initial_maximum)
                self.assertEqual(len(worker._node_dword_bits_1b9c2026), initial_maximum)
                self.assertEqual(
                    len(worker._configured_bits_4e0_2026),
                    configured_maximum,
                )
                history = worker._getter_histories_a34_2026
                with self.assertRaisesRegex(ValueError, "Fresh unpublished worker"):
                    worker._apply_initial_getter_reset_40580_2026(origins[0])
                self.assertEqual(worker._getter_reset_epoch2026, 1)
                self.assertIs(worker._getter_histories_a34_2026, history)
                with self.assertRaisesRegex(TypeError, "source-issued initial"):
                    worker._apply_initial_getter_reset_40580_2026(object())
                with self.assertRaisesRegex(TypeError, "origin required"):
                    worker._reset_getter_history_and_aux_40580_2026(object())
                self.assertEqual(worker._getter_reset_epoch2026, 1)
                self.assertIs(worker._getter_histories_a34_2026, history)
                from scripts.cuw_engine_worker import (
                    _replace_engine_worker,
                    _rollback_engine_worker_replacement,
                )

                replacement = _replace_engine_worker(engine, controller, worker)
                self.assertIs(replacement._getter_histories_a34_2026, history)
                self.assertEqual(
                    replacement._getter_flow_received_cids2026,
                    worker._getter_flow_received_cids2026,
                )
                self.assertEqual(replacement._getter_reset_epoch2026, 1)
                self.assertEqual(
                    replacement._node_strings_4402026,
                    worker._node_strings_4402026,
                )
                self.assertIsNot(
                    replacement._node_strings_4402026,
                    worker._node_strings_4402026,
                )
                _rollback_engine_worker_replacement(engine, worker, replacement)
                self.assertIs(engine.worker, worker)
                self.assertIs(worker._getter_histories_a34_2026, history)
                self.assertEqual(worker._getter_reset_epoch2026, 1)

    def test_authenticated_cleanup_reuses_only_the_literal_getter_reset_subset(self):
        from scripts.j2534_2026 import J2534InterfacePair2026

        engine = self.engine(calibration())
        self.addCleanup(engine.close)

        def provider(*_args):
            return PrimitiveResult()

        engine_device = J2534Device2026(provider, background_workers=False)
        control_device = J2534Device2026(provider, background_workers=False)
        engine.bind_interface_pair(
            J2534InterfacePair2026(engine_device, control_device)
        )
        controller = make_controller(NativeRuntime2026(control_device.primitive))
        worker = engine.bind_worker(controller)
        cleanup = engine.bind_cleanup_controller()

        cleanup.run()

        self.assertEqual(len(worker._getter_histories_a34_2026), 16)
        for history in worker._getter_histories_a34_2026:
            self.assertEqual(len(history.node_strings_28), 4)
            self.assertEqual(len(history.cell_dword_bits_c8), 128)
            self.assertEqual(len(history.retained_bits_fc), 4)
        self.assertEqual(len(worker._node_strings_4402026), 4)
        self.assertEqual(len(worker._cell_dword_bits_5542026), 128)
        self.assertEqual(len(worker._cell_strings_5602026), 128)
        self.assertEqual(len(worker._retained_bits_5882026), 4)
        self.assertEqual(len(worker._configured_bits_4e0_2026), 4)
        self.assertEqual(worker._getter_reset_epoch2026, 1)

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

    def test_manual_close_cannot_bypass_native_worker_reissue(self):
        engine = self.engine(calibration())
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        self.addCleanup(engine.close)
        first = engine.bind_worker(controller)
        configuration = engine.configuration
        assert configuration is not None
        first.close()
        with self.assertRaisesRegex(ValueError, "closed"):
            first.validate_source()
        with self.assertRaisesRegex(ValueError, "Engine worker is closed"):
            engine.bind_worker(controller)
        self.assertIs(engine._worker, first)
        self.assertIsNone(getattr(controller, "worker", None))

    def test_completed_thread_job_is_not_attached_to_standalone_capture(self):
        from tests.test_cuw_engine_threads import ThreadOwnershipTests

        if not (RUNTIME / "CUW.dll").is_file():
            self.skipTest("Authenticated static thread replay fixture is unavailable")
        fixture = ThreadOwnershipTests("runTest")
        engine, controller, job, session = fixture.imported_prepare(
            operation="get_cid", include_control=False
        )
        self.addCleanup(fixture.doCleanups)
        self.addCleanup(engine.close)
        self.addCleanup(job.stop)
        clock = lambda: 1000
        session.trace.native_local_milliseconds_of_day = clock
        controller.runtime.local_milliseconds_of_day = clock
        worker = job.worker

        job.start(session)
        job.result(3)
        self.assertIsNone(job._lease)
        self.assertIsNone(job._session)
        assert job._active_record is not None
        self.assertTrue(job._active_record.completed.is_set())

        with engine.controller_execution(controller, 0):
            capture = worker._control_file_capture
            self.assertIsNotNone(capture)
            assert capture is not None
            self.assertIsNone(capture._thread_job)
            self.assertIsNone(capture.job_sequence)
            self.assertIsNone(capture.phase_lease)
            self.assertIsNone(capture.raw_session)
            self.assertIsNone(capture.completion_record)
            capture.metadata_for_cpu(0)

    def test_actual_unsupported_raw_getter_keeps_legacy_import_untyped(self):
        from unittest.mock import patch

        from scripts.cuw_engine_worker import EngineWorker2026
        from tests.test_cuw_engine_threads import ThreadOwnershipTests

        fixture = ThreadOwnershipTests("runTest")
        self.addCleanup(fixture.doCleanups)
        original_import = EngineWorker2026.import_control_getter_return2026
        outputs = []
        sequences = []
        contexts = []
        workers = []

        def observe_import(worker, context):
            original_import(worker, context)
            outputs.append(worker._imported_getter_output2026(context))
            sequences.append(worker._getter_ordinary_return_sequence2026)
            contexts.append(context)
            workers.append(worker)
            with self.assertRaises(ValueError):
                original_import(worker, context)
            with self.assertRaises(TypeError):
                worker._imported_getter_output2026(object())

        with patch.object(
            EngineWorker2026,
            "import_control_getter_return2026",
            observe_import,
        ):
            fixture.test_actual_p5_false_getter_imports_pair_through_thread_job()
        self.assertEqual(outputs, [None])
        self.assertEqual(sequences, [1])
        self.assertIsNone(workers[0]._imported_getter_output_ref2026)
        with self.assertRaises(ValueError):
            workers[0]._imported_getter_output2026(contexts[0])

    def test_native_getter_raw_cell_conversion_sign_extends_type_byte(self):
        from scripts.cuw_engine_worker import (
            _native_getter_c_string2026,
            _native_getter_cell2026,
        )

        self.assertEqual(
            _native_getter_cell2026(b"\x80TEXT\0" + bytes(8)),
            (0xFFFFFF80, b"TEXT"),
        )
        with self.assertRaises(ValueError):
            _native_getter_cell2026(b"\x80short")
        self.assertEqual(_native_getter_c_string2026(b"A\0\0", 3), b"A")
        with self.assertRaises(ValueError):
            _native_getter_c_string2026(b"AB", 3)

    def test_authenticated_cancid_output_imports_typed_buffers_once(self):
        from scripts.j2534_2026 import (
            DriverMetadata2026,
            J2534Device2026,
            J2534InterfacePair2026,
            NativeMessage,
            PrimitiveResult,
        )
        from scripts.programming_2026_common import (
            NativeRuntime2026,
            _control_getter_output2026,
        )
        from scripts.programming_2026_legacy import bind_can_cid_context, run_can_cid
        from scripts.programming_replay import _native_request
        from tests.test_programming_2026_common import RawControlStageMachineTests

        fixture = RawControlStageMachineTests()
        self.addCleanup(fixture.doCleanups)
        payloads = (b"\x49\0\x10\0\0\0", b"\x49\x04\x01" + b"DEMO\0".ljust(16, b" "))
        recorder_fixture = RawControlStageMachineTests()
        self.addCleanup(recorder_fixture.doCleanups)
        _, _, recorder_session = recorder_fixture.fixture(
            operation="get_cid",
            getter="TCUWCanCIDGetter.dll",
            selector="GetCanIDsFromParamForGetCID",
            parameter_values={
                "GetCANIDFunctionNameForGetCID": "GetCanIDsFromParamForGetCID",
                "CanIDForGetCID": "0200/0208",
                "ReceiveTimeoutBeforeGetCID": "123",
            },
        )
        binding, module, *_ = recorder_session._dispatch()
        cid_context = bind_can_cid_context(
            recorder_session.container,
            recorder_session.node,
            (),
            binding,
            module.native_identity,
            {},
            {},
        )
        reads = []
        rows = []
        fail_start_filter = False

        def encode(value):
            if value is None:
                return {"type": "none", "value": None}
            if type(value) is bool:
                return {"type": "bool", "value": value}
            if type(value) is int:
                return {"type": "int", "value": value}
            if type(value) is bytes:
                return {"type": "bytes", "value": value.hex()}
            if isinstance(value, NativeMessage):
                return {
                    "type": "mapping",
                    "value": {
                        "_native_type": {"type": "text", "value": "PASSTHRU_MSG_2026"},
                        **{key: encode(item) for key, item in vars(value).items()},
                    },
                }
            if type(value) is tuple:
                return {"type": "tuple", "value": [encode(item) for item in value]}
            if type(value) is dict:
                return {
                    "type": "mapping",
                    "value": {key: encode(item) for key, item in value.items()},
                }
            raise TypeError(f"Unsupported captured J2534 result: {type(value)!r}")

        payload_iter = iter(payloads)

        def capture_driver(event, _remaining):
            nonlocal fail_start_filter
            operation = event["operation"]
            if operation == "passthru_write":
                message = event["messages"][0]
                reads.extend(
                    (
                        NativeMessage(6, message.data[:4], rx_status=9),
                        NativeMessage(
                            6, bytes.fromhex("00000208") + next(payload_iter)
                        ),
                    )
                )
                result = PrimitiveResult(value=1)
            elif operation == "passthru_read":
                result = PrimitiveResult(value=(reads.pop(0),))
            elif operation in ("passthru_open", "passthru_connect"):
                result = PrimitiveResult(value=17)
            elif operation == "passthru_start_filter":
                if fail_start_filter:
                    fail_start_filter = False
                    result = PrimitiveResult(status=16)
                else:
                    result = PrimitiveResult(value=101)
            elif operation == "create_mutex":
                result = PrimitiveResult(value=1)
            elif operation == "wait_handle":
                result = PrimitiveResult(value=0)
            elif operation == "load_library":
                result = PrimitiveResult(value=2)
            elif operation == "get_symbol":
                result = PrimitiveResult(value=3)
            else:
                result = PrimitiveResult()
            rows.append(
                {
                    "kind": "action",
                    "request": _native_request(event),
                    "result": encode({"status": result.status, "value": result.value}),
                    "elapsed_ms": 1,
                }
            )
            return result

        clock = lambda: 0
        device = J2534Device2026(capture_driver, clock=clock, background_workers=False)
        peer = J2534Device2026(capture_driver, clock=clock, background_workers=False)
        direct_pair = J2534InterfacePair2026(peer, device)
        for view in (direct_pair.engine, direct_pair.control):
            view.set_current_driver(DriverMetadata2026("Authored", "authored.dll"))
        device.have_ownership()
        direct_result = run_can_cid(
            cid_context,
            NativeRuntime2026(
                device.primitive, clock=lambda: 0, native_cancelled=lambda: False
            ),
        )
        self.assertTrue(direct_result["native_success"])
        self.assertEqual(direct_result["cids"], (b"DEMO",))
        successful_driver_events = tuple(rows)
        rows.clear()
        reads.clear()
        payload_iter = iter(payloads)
        fail_start_filter = True
        failed_device = J2534Device2026(
            capture_driver, clock=clock, background_workers=False
        )
        failed_peer = J2534Device2026(
            capture_driver, clock=clock, background_workers=False
        )
        failed_pair = J2534InterfacePair2026(failed_peer, failed_device)
        for view in (failed_pair.engine, failed_pair.control):
            view.set_current_driver(DriverMetadata2026("Authored", "authored.dll"))
        failed_device.have_ownership()
        failed_direct_result = run_can_cid(
            cid_context,
            NativeRuntime2026(
                failed_device.primitive,
                clock=clock,
                native_cancelled=lambda: False,
            ),
        )
        self.assertFalse(
            failed_direct_result["native_success"],
            f"timeout={cid_context.timeout_allowing_id} addresses={cid_context.addresses!r} "
            f"ops={[row['request']['operation'] for row in rows]}",
        )
        failed_driver_events = tuple(rows)
        engine, controller, session = fixture.fixture(
            operation="get_cid",
            getter="TCUWCanCIDGetter.dll",
            selector="GetCanIDsFromParamForGetCID",
            parameter_values={
                "GetCANIDFunctionNameForGetCID": "GetCanIDsFromParamForGetCID",
                "CanIDForGetCID": "0200/0208",
                "ReceiveTimeoutBeforeGetCID": "123",
            },
            events=successful_driver_events,
            paired=True,
        )
        worker = engine.bind_worker(controller)
        with engine.controller_execution(controller, 0):
            result = controller.execute(engine, session)
            context = controller.native_control_context2026(engine)
            output = _control_getter_output2026(context)
            self.assertIsNotNone(output)
            assert output is not None
            self.assertIs(result["native_return"], True)
            self.assertEqual(output.identifiers, (b"DEMO",))
            self.assertIs(output.raw_al, True)
            self.assertEqual(worker._getter_ordinary_return_sequence2026, 1)
            worker.import_control_getter_return2026(context)
            self.assertIs(worker._imported_getter_output2026(context), output)
            with self.assertRaises(ValueError):
                worker.import_control_getter_return2026(context)
            staged = worker._prepare_getter_import2026(
                context, output, output.identifiers
            )
            self.assertIsNotNone(staged)
            assert staged is not None
            (
                strings,
                cell_bits,
                cell_strings,
                configured,
                retained,
                node_dwords,
                tail1,
                tail2,
                records,
                hardware,
            ) = staged
            maximum = output.configuration.cpu_maximum
            self.assertEqual(strings, ((b"",) * maximum,) * 4)
            self.assertEqual(cell_bits, [0] * (32 * output.configuration.cpu_maximum))
            self.assertEqual(
                cell_strings, [b""] * (32 * output.configuration.cpu_maximum)
            )
            self.assertEqual(configured, [False] * output.configuration.cpu_maximum)
            self.assertEqual(retained, [False] * output.configuration.cpu_maximum)
            self.assertEqual(node_dwords, [0] * output.configuration.cpu_maximum)
            self.assertEqual((tail1, tail2, hardware), (b"", b"", b""))
            self.assertEqual(records, output.query_records34)
            self.assertEqual(engine.received_identifiers, (b"DEMO",))
            self.assertEqual(engine._working_identifier_records, records)
            self.assertEqual(worker._cell_dword_bits_5542026, cell_bits)
            self.assertEqual(worker._cell_strings_5602026, cell_strings)
        with self.assertRaises(ValueError):
            worker._imported_getter_output2026(context)

        failed_fixture = RawControlStageMachineTests()
        self.addCleanup(failed_fixture.doCleanups)
        failed_engine, failed_controller, failed_session = failed_fixture.fixture(
            operation="get_cid",
            getter="TCUWCanCIDGetter.dll",
            selector="GetCanIDsFromParamForGetCID",
            parameter_values={
                "GetCANIDFunctionNameForGetCID": "GetCanIDsFromParamForGetCID",
                "CanIDForGetCID": "0200/0208",
                "ReceiveTimeoutBeforeGetCID": "123",
            },
            events=failed_driver_events,
            paired=True,
        )
        failed_worker = failed_engine.bind_worker(failed_controller)
        with failed_engine.controller_execution(failed_controller, 0):
            failed_result = failed_controller.execute(failed_engine, failed_session)
            failed_context = failed_controller.native_control_context2026(failed_engine)
            failed_output = _control_getter_output2026(failed_context)
            self.assertIsNotNone(failed_output)
            assert failed_output is not None
            self.assertIs(failed_result["native_return"], False)
            self.assertIs(failed_output.raw_al, False)
            self.assertEqual(failed_output.identifiers, ())
            self.assertEqual(failed_worker._getter_ordinary_return_sequence2026, 1)
            histories_before = failed_worker._getter_histories_a34_2026
            flow_before = failed_worker._flow_file_index2026
            reset_epoch_before = failed_worker._getter_reset_epoch2026
            failed_worker.import_control_getter_return2026(failed_context)
            self.assertIs(
                failed_worker._imported_getter_output2026(failed_context), failed_output
            )
            with self.assertRaises(ValueError):
                failed_worker.import_control_getter_return2026(failed_context)
            self.assertEqual(failed_engine.received_identifiers, ())
            self.assertEqual(
                failed_engine._working_identifier_records,
                failed_output.query_records34,
            )
            self.assertIs(failed_worker._getter_histories_a34_2026, histories_before)
            self.assertEqual(failed_worker._flow_file_index2026, flow_before)
            self.assertEqual(failed_worker._getter_reset_epoch2026, reset_epoch_before)
            self.assertTrue(
                all(
                    history.node_strings_28 == ()
                    for history in failed_worker._getter_histories_a34_2026
                )
            )
        with self.assertRaises(ValueError):
            failed_worker._imported_getter_output2026(failed_context)

        mismatch_engine, mismatch_controller, mismatch_session, mismatch_worker = (
            self.cold_worker_for_recording(engine, session)
        )
        self.assertEqual(mismatch_worker._getter_reset_epoch2026, 1)
        self.assertEqual(
            mismatch_worker._getter_histories_a34_2026[0].node_strings_28, ()
        )
        self.assertEqual(len(mismatch_worker._configured_bits_4e0_2026), 4)
        with mismatch_engine.controller_execution(mismatch_controller, 0):
            mismatch_result = mismatch_controller.execute(
                mismatch_engine, mismatch_session
            )
            mismatch_context = mismatch_controller.native_control_context2026(
                mismatch_engine
            )
            mismatch_output = _control_getter_output2026(mismatch_context)
            self.assertIs(mismatch_result["native_return"], True)
            self.assertIsNotNone(mismatch_output)
            histories_before = mismatch_worker._getter_histories_a34_2026
            strings_before = tuple(mismatch_worker._node_strings_4402026)
            cells_before = tuple(mismatch_worker._cell_dword_bits_5542026)
            identifiers_before = mismatch_engine.received_identifiers
            with self.assertRaisesRegex(
                ValueError, "scratch differs from configuration"
            ):
                mismatch_worker.import_control_getter_return2026(mismatch_context)
            self.assertIs(mismatch_worker._getter_histories_a34_2026, histories_before)
            self.assertEqual(
                tuple(mismatch_worker._node_strings_4402026), strings_before
            )
            self.assertEqual(
                tuple(mismatch_worker._cell_dword_bits_5542026), cells_before
            )
            self.assertEqual(mismatch_engine.received_identifiers, identifiers_before)
            self.assertIsNone(mismatch_worker._imported_getter_output_ref2026)

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
        configuration = engine.configuration
        assert configuration is not None
        self.assertEqual(first._flow_file_index2026, 0)
        self.assertFalse(first._getter_sequence_changed_39c2026)
        self.assertEqual(len(first._getter_histories_a34_2026), 16)
        self.assertTrue(
            all(
                history.node_strings_28 == ()
                for history in first._getter_histories_a34_2026
            )
        )
        self.assertEqual(
            len(first._cell_dword_bits_5542026),
            32 * configuration.cpu_maximum,
        )
        self.assertEqual(
            tuple(first._configured_bits_4e0_2026), configuration.cpu_flags
        )
        with engine.controller_execution(controller, 0):
            self.assertTrue(first.mark_cid_reception_complete())
        with engine.controller_execution(controller, 1):
            first.record_callback_24(2)
        before = first.source_state

        second = _replace_engine_worker(engine, controller, first)
        self.assertIs(engine.worker, second)
        self.assertEqual(second._flow_file_index2026, 0)
        self.assertIs(
            second._getter_histories_a34_2026,
            first._getter_histories_a34_2026,
        )
        self.assertEqual(
            second._cell_dword_bits_5542026, first._cell_dword_bits_5542026
        )
        self.assertIsNot(
            second._cell_dword_bits_5542026, first._cell_dword_bits_5542026
        )
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
        configuration = engine.configuration
        assert configuration is not None
        self.assertEqual(
            worker._judge_live_selection2026.targets,
            (-1,) * configuration.cpu_maximum,
        )
        self.assertEqual(worker._judge_live_selection2026.unmatched_ids, (b"NEW1",))
        self.assertEqual(worker._judge_live_selection2026.authored_count, 1)
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

    def test_vbf_prepare_does_not_import_persisted_progress_as_d30c(self):
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
            self.assertEqual(worker.source_state.progress_base, 0)
            self.assertEqual(state.offset_of_write_cpu_multi_cal_index, 1)

            with engine.controller_execution(controller, 0):
                self.assertTrue(worker.mark_cid_reception_complete())
            self.assertEqual(worker.source_state.cpu_offset, 0)
            self.assertEqual(worker.source_state.current_global_cpu_index, 0)

            with engine.controller_execution(controller, 1):
                pass

            self.assertEqual(worker.source_state.cpu_offset, 0)
            self.assertEqual(worker.source_state.current_global_cpu_index, 0)
            self.assertEqual(engine.native_metadata.cpu_index, 0)
            self.assertEqual(worker.native_writer_target_index, 0)

    def test_36800_vbf_keeps_constructor_d30c_without_a_producer(self):
        source = calibration(cpus=2, first_image="first.vbf")
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
            self.assertEqual(worker.source_state.progress_base, 0)
            self.assertEqual(state.offset_of_write_cpu_multi_cal_index, 1)
            self.assertEqual(worker.source_state.current_global_cpu_index, 0)
            self.assertEqual(worker.source_state.cpu_offset, 0)
            self.assertEqual(worker._flow_file_index2026, 0)
            self.assertEqual(engine.native_metadata.cpu_index, 0)

            with engine.controller_execution(controller, 1):
                pass

            self.assertEqual(engine.native_metadata.cpu_index, 0)
            self.assertEqual(worker.source_state.current_global_cpu_index, 0)
            self.assertEqual(worker.source_state.cpu_offset, 0)

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

    def test_vbf_resume_phase_start_rejects_unadopted_request_without_36800(self):
        reads = []
        runtime = NativeRuntime2026(
            lambda *_: None,
            local_milliseconds_of_day=lambda: reads.append(1) or 9876,
        )
        engine = self.engine(calibration(first_image="authored.vbf"))
        controller = make_controller(runtime)
        self.addCleanup(engine.close)
        worker = engine.bind_worker(controller)
        request = SimpleNamespace(started_ms=1234)
        with self.assertRaisesRegex(ValueError, "actual child phase1"):
            worker._phase_started(1, _vbf_request=request)

        self.assertIsNone(worker._phase_started_ms)
        self.assertEqual(worker.native_prepare_handshake, 0)
        self.assertEqual(reads, [])

    def test_vbf_prepare_rejects_unissued_receipt_before_prefix(self):
        reads = []
        runtime = NativeRuntime2026(
            lambda *_: None,
            local_milliseconds_of_day=lambda: reads.append(1) or 9876,
        )
        engine = self.engine(calibration(first_image="authored.vbf"))
        controller = make_controller(runtime)
        self.addCleanup(engine.close)
        worker = engine.bind_worker(controller)
        job = engine.bind_thread_job(controller)

        with self.assertRaisesRegex(TypeError, "Concrete VBF ProcessBefore"):
            worker._prepare_vbf_resume2026(job, object())

        self.assertIsNone(worker._phase_started_ms)
        self.assertEqual(worker.native_prepare_handshake, 0)
        self.assertEqual(reads, [])

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

    def test_actual141_reset_keeps_d30c_zero_without_a_producer(self):
        from scripts.calibration_2026 import native2026_metadata_for_cpu

        part = calibration(cpus=2, first_target="PART")
        whole = calibration(cpus=2, first_target="WHOLE")
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
        state = ReproInfoState(
            (RecoveryCalibration("source.cuw", calibration(cpus=2)),),
            loaded=True,
            offset_of_write_cpu_multi_cal_index=1,
        )
        with tempfile.TemporaryDirectory() as directory:
            persistence = CUWPersistence(Path(directory), state)
            engine = self.engine(calibration(cpus=2), persistence=persistence)
            issued = admit_file_sources_2026(engine, "direct.scuw", source, region=0)
            engine.bind_file_sources(issued)
            self.addCleanup(engine.close)
            controller = make_controller(NativeRuntime2026(lambda *_: None))
            worker = engine.bind_worker(controller)
            self.assertEqual(worker.source_state.cpu_offset, 0)

            with engine.controller_execution(controller, 2):
                selected_cpu = native2026_metadata_for_cpu(engine.native_metadata, 1)
                engine._select_worker_metadata(
                    selected_cpu, controller=controller, worker=worker
                )
                self.assertEqual(engine.native_metadata.cpu_index, 1)
                self.assertEqual(worker.source_state.cpu_offset, 0)
                worker._persist_position()
                self.assertEqual(persistence.state.write_cpu_index, 1)
                self.assertEqual(
                    persistence.state.offset_of_write_cpu_multi_cal_index, 0
                )
                replacement = issued.after_group_reset(0, worker=worker)
                engine._accept_worker_file_reset(issued, replacement, worker=worker)

            self.assertIs(engine.native_metadata, replacement.selected_metadata)
            self.assertEqual(engine.native_metadata.cpu_index, 0)
            self.assertEqual(worker.source_state.current_global_cpu_index, 0)
            self.assertEqual(worker.source_state.cpu_offset, 0)

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
            b'["prefix.cuw","group.scuw"]',
            region=0,
            source_files={
                "prefix.cuw": calibration(first_target="PREFIX"),
                "group.scuw": archive_source,
            },
        )
        engine.bind_file_sources(issued)
        self.addCleanup(engine.close)
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        worker = engine.bind_worker(controller)

        with engine.controller_execution(controller, 2):
            engine._select_worker_metadata(
                issued.files[1], controller=controller, worker=worker
            )
            old_group = issued.group_for_file(worker.source_state.current_file_index)
            self.assertIsNotNone(old_group)
            assert old_group is not None
            self.assertGreater(old_group[0], 0)
            replacement = issued.after_group_reset(1, worker=worker)
            engine._accept_worker_file_reset(issued, replacement, worker=worker)

        self.assertIs(engine.file_sources, replacement)
        assert old_group is not None
        self.assertEqual(worker._flow_file_index2026, old_group[0])
        self.assertIs(engine.native_metadata, replacement.selected_metadata)
        self.assertEqual(worker.loaded_metadata, replacement.files)
        self.assertEqual(worker.online_context().all_loaded_metadata, replacement.files)
        self.assertTrue(worker.persist_current_cpu)

    def test_named_whole_completion_rejects_without_indexed_a48_producer(self):
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

        original_metadata = engine.native_metadata
        original_state = worker.source_state
        self.assertEqual(worker._getter_a48_received_cids2026, ())
        self.assertIsNone(worker._judge_a48_match2026)
        with engine.controller_execution(controller, 0):
            self.assertFalse(worker.mark_cid_reception_complete())
        # A reached false34e10 still publishes its actual native footprints;
        # it does not admit an execution selection from the unrelated global CID.
        self.assertEqual(worker._judge_live_selection2026.targets, (-1,) * 4)
        self.assertEqual(
            worker._judge_live_selection2026.unmatched_ids, (b"M16C", b"FOREST")
        )
        self.assertEqual(worker._judge_live_selection2026.authored_count, 2)
        self.assertIs(engine.native_metadata, original_metadata)
        self.assertEqual(
            worker.source_state.target_indices, original_state.target_indices
        )
        self.assertEqual(
            worker.source_state.current_global_cpu_index,
            original_state.current_global_cpu_index,
        )
        self.assertIsNone(worker._selections_by_file[worker._current_file_index])
        self.assertIsNone(worker._judge_a48_match2026)
        self.assertIsNone(worker._retained_clone_selection)
        with self.assertRaisesRegex(ValueError, "no completed native CID selection"):
            _ = worker.native_writer_target_index

    def test_control_state_keeps_fatal_failed_and_callback_fields_independent(self):

        source = calibration()
        state = ReproInfoState(
            (RecoveryCalibration("control.cuw", source),),
            ssmid=2,
            dh_central_gw_type=3,
        )
        with tempfile.TemporaryDirectory() as directory:
            persistence = CUWPersistence(Path(directory), state)
            engine = self.engine(source, persistence=persistence)
        controller = make_controller(NativeRuntime2026(lambda *_: None))
        self.addCleanup(engine.close)
        worker = engine.bind_worker(controller)
        with engine.controller_execution(controller, 1):
            worker.set_control_error_kind(7)
            with self.assertRaises(ValueError):
                worker.record_callback_24(True)
            worker.record_callback_24(2)
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
            context = controller.native_control_context2026(engine)
            worker.publish_control_callback_30_2026(context)
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
        self.assertEqual(worker.control_state.primary_error, 8)
        self.assertEqual(worker.control_state.passthru_error, 9)
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
        from unittest.mock import patch

        from scripts.programming_replay import ProgrammingReplay
        from tests.test_programming_2026_common import RawControlStageMachineTests

        engine, controller, session = RawControlStageMachineTests().fixture(
            operation="prepare",
            contact="SIL",
            events=(
                RawControlStageMachineTests.event("set_communication_log_mode", mode=2),
                RawControlStageMachineTests.event("set_communication_log_mode", mode=0),
            ),
        )
        worker = engine.bind_worker(controller)
        original_runner = ProgrammingReplay._runner
        runner_calls = []

        def runner(replay, *args):
            module = args[1]
            runner_calls.append((replay.operation, module.name))
            if replay.operation == "write":
                return lambda: {"native_return": True}
            return original_runner(replay, *args)

        with (
            engine.controller_execution(controller, 1),
            patch.object(ProgrammingReplay, "_runner", runner),
        ):
            report = controller.execute(engine, session)
        self.assertTrue(report["native_return"], repr(report))
        self.assertEqual(
            runner_calls,
            [
                ("prepare", "TCUWSilPrepareWriter.dll"),
                ("write", "TCUWSilFlashWriter.dll"),
            ],
        )
        self.assertEqual(len(report["exports"]), 2)
        self.assertTrue(session.used)
        self.assertEqual(worker.native_getter_cpu_type, "1")
        self.assertEqual(worker.control_state.lifecycle, "ready")
        self.assertFalse(worker.source_state.complete)
        self.assertEqual(session.trace.position, len(session.trace.rows))


class GatewayCacheCallbackTests(unittest.TestCase):
    def test_callback24_publishes_engine_cache_for_callback25_after_worker_change(self):
        from scripts.cuw_engine_worker import EngineWorker2026

        engine = object.__new__(CUWEngine2026)
        engine._active = True
        engine._phase_thread = threading.get_ident()
        engine._gateway_classifier_cache = 0
        engine._persistence = None
        engine._repro_gateway_node = 0

        def worker():
            result = object.__new__(EngineWorker2026)
            result._engine = engine
            result._lock = threading.RLock()
            result._closed = False
            result.validate_source = lambda engine=None: None
            return result

        first = worker()
        engine._worker = first
        for value in (1, 2, 255):
            with self.subTest(value=value):
                first.record_callback_24(value)
                self.assertEqual(engine.native_gateway_cache, value)

                replacement = worker()
                engine._worker = replacement
                replacement.publish_callback_25_gateway_node()
                self.assertEqual(engine.repro_gateway_node, value)
                self.assertEqual(engine.native_gateway_cache, value)
                first = replacement

    def test_callback24_rejects_invalid_value_before_cache_mutation(self):
        from scripts.cuw_engine_worker import EngineWorker2026

        engine = object.__new__(CUWEngine2026)
        engine._active = True
        engine._phase_thread = threading.get_ident()
        engine._gateway_classifier_cache = 7
        engine._persistence = None
        worker = object.__new__(EngineWorker2026)
        worker._engine = engine
        worker._lock = threading.RLock()
        worker._closed = False
        worker.validate_source = lambda engine=None: None
        engine._worker = worker

        with self.assertRaises(ValueError):
            worker.record_callback_24(True)
        self.assertEqual(engine.native_gateway_cache, 7)

    def test_callback24_rejects_noncurrent_worker_before_cache_mutation(self):
        from scripts.cuw_engine_worker import EngineWorker2026

        engine = object.__new__(CUWEngine2026)
        engine._active = True
        engine._phase_thread = threading.get_ident()
        engine._gateway_classifier_cache = 7
        engine._persistence = None

        def worker():
            result = object.__new__(EngineWorker2026)
            result._engine = engine
            result._lock = threading.RLock()
            result._closed = False
            result.validate_source = lambda engine=None: None
            return result

        engine._worker = worker()
        with self.assertRaisesRegex(ValueError, "source-issued worker"):
            worker().record_callback_24(2)
        self.assertEqual(engine.native_gateway_cache, 7)


class ControlFileCapture2026Tests(unittest.TestCase):
    def setUp(self):
        required = (RUNTIME / "CUW.dll", RUNTIME / "TCUWControlCommPhase.dll")
        if any(not path.is_file() for path in required):
            self.skipTest("Authenticated static CUW2026 pipeline is absent")
        self.engine = EngineWorker2026Tests().engine(calibration(cpus=2))
        self.addCleanup(self.engine.close)
        self.controller = make_controller(NativeRuntime2026(lambda *_: None))
        self.worker = self.engine.bind_worker(self.controller)
        EngineWorker2026Tests.receive(
            self.engine, self.controller, (b"OLD", b"SECOND-OLD")
        )

    def capture(self):
        capture = self.worker._control_file_capture
        self.assertIsNotNone(capture)
        assert capture is not None
        return capture

    def test_capture_maps_held_nonidentity_order_and_targets(self):
        # Exercise nonidentity execution order over authentic authored FILE rows.
        self.worker._cpu_orders_by_file = ((1, 0),)
        self.worker._targets_by_file = ((1, 0),)
        self.worker._current_global_cpu_index = 1
        with self.engine.controller_execution(self.controller, 2):
            capture = self.capture()
            self.assertEqual(capture.native_order, (1, 0))
            self.assertEqual(capture.target_indices, (1, 0))
            self.assertEqual(capture.control_cpu_start, 1)
            self.assertIsNone(capture.file_sources)
            self.assertIsNone(capture.pointer_view)
            self.assertIsNone(capture.flow_view)
            self.assertEqual(capture.flow_file_index, 0)
            self.assertIs(capture.configuration, self.engine.configuration)
            self.assertEqual(len(capture.query_seed34), 34)
            self.assertTrue(all(len(record) == 12 for record in capture.query_seed34))
            self.assertEqual(
                capture.configured_bits, tuple(self.worker._configured_bits_4e0_2026)
            )
            self.assertFalse(capture.sequence_changed_39c)
            self.assertIsNone(capture.job_sequence)
            self.assertIsNone(capture.phase_lease)
            self.assertIsNone(capture.raw_session)
            self.assertIsNone(capture.completion_record)
            first = capture.metadata_for_cpu(0)
            second = capture.metadata_for_cpu(1)
            self.assertEqual((first.cpu_index, second.cpu_index), (1, 0))
            self.assertIs(first.source_container, capture.metadata.source_container)
            self.assertEqual(capture.metadata, capture.metadata_for_cpu(1))
            self.engine.select_target(1, 1, controller=self.controller)
            capture.validate(self.engine, self.controller)
            self.assertIsNot(capture.metadata, self.engine.native_metadata)

    def test_pointer_admission_fallback_rejects_other_metadata(self):
        engine = EngineWorker2026Tests().engine(calibration())
        other_engine = EngineWorker2026Tests().engine(calibration(first_target="OTHER"))
        self.addCleanup(engine.close)
        self.addCleanup(other_engine.close)
        issued = admit_file_sources_2026(
            engine,
            "input.json",
            b'["file.cuw"]',
            region=0,
            source_files={"file.cuw": calibration(first_target="ISSUED")},
        )
        engine.bind_file_sources(issued)
        worker = engine.bind_worker(make_controller(NativeRuntime2026(lambda *_: None)))
        with self.assertRaisesRegex(ValueError, "differs from its issued view"):
            worker._capture_pointer_view2026(other_engine.native_metadata)

    def test_capture_is_once_only_and_rejects_forged_copied_and_bad_indices(self):
        import copy
        from dataclasses import replace

        with self.engine.controller_execution(self.controller, 2):
            with self.assertRaisesRegex(ValueError, "59ab0"):
                self.worker.capture_control_file2026(self.controller)
            with (
                self.assertRaisesRegex(ValueError, "active"),
                self.engine.controller_execution(self.controller, 2),
            ):
                pass
            capture = self.capture()
            with self.assertRaisesRegex(ValueError, "59ab0"):
                self.worker.capture_control_file2026(self.controller)
            for index in (-1, True, 2, 1.0, "0"):
                with (
                    self.subTest(index=index),
                    self.assertRaises((TypeError, ValueError)),
                ):
                    capture.metadata_for_cpu(index)  # pyright: ignore[reportArgumentType]
            for impostor in (copy.copy(capture), replace(capture)):
                with self.assertRaisesRegex(ValueError, "capture"):
                    impostor.validate(self.engine, self.controller)
            with self.assertRaisesRegex(ValueError, "capture"):
                capture.validate(self.engine, make_controller(self.controller.runtime))
            original_runtime = self.controller.runtime
            self.controller.runtime = NativeRuntime2026(lambda *_: None)
            try:
                with self.assertRaisesRegex(ValueError, "capture"):
                    capture.validate(self.engine, self.controller)
            finally:
                self.controller.runtime = original_runtime

    def test_capture_rejects_foreign_thread_and_expires_at_unwind(self):
        with self.engine.controller_execution(self.controller, 2):
            capture = self.capture()
            errors = []

            def validate_foreign_thread():
                try:
                    capture.validate(self.engine, self.controller)
                except ValueError as error:
                    errors.append(error)

            thread = threading.Thread(target=validate_foreign_thread)
            thread.start()
            thread.join()
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], ValueError)
            capture.validate(self.engine, self.controller)
        with self.assertRaisesRegex(ValueError, "capture"):
            capture.validate(self.engine, self.controller)


class ControlOutput2026Tests(unittest.TestCase):
    def setUp(self):
        required = (RUNTIME / "CUW.dll", RUNTIME / "TCUWControlCommPhase.dll")
        if any(not path.is_file() for path in required):
            self.skipTest("Authenticated static CUW2026 pipeline is absent")
        self.engine = EngineWorker2026Tests().engine(calibration(cpus=2))
        self.addCleanup(self.engine.close)
        self.controller = make_controller(NativeRuntime2026(lambda *_: None))
        state = self.engine.dh_state
        state._transferred_bytes = (19, 23)
        state._progress = (41, 47)
        self.worker = self.engine.bind_worker(self.controller)

    def test_constructor_owns_zero_count_and_copies_global_percent_without_publishing(
        self,
    ):
        self.assertEqual(self.worker._control_count_scratch2026, [0, 0])
        self.assertEqual(self.worker._control_percent_scratch2026, [41, 47])
        self.assertEqual(self.engine.dh_state.transferred_bytes, (19, 23))
        self.assertEqual(self.engine.dh_state.progress, (41, 47))

    def test_repeated_import_retains_scratch_and_new_worker_uses_current_global_percent(
        self,
    ):
        first = self.worker._control_count_scratch2026
        first[:] = [5, 7]
        with self.engine.controller_execution(self.controller, 0):
            pass
        with self.engine.controller_execution(self.controller, 0):
            pass
        self.assertIs(self.worker._control_count_scratch2026, first)
        self.assertEqual(first, [5, 7])
        self.engine.dh_state._progress = (61, 67)
        from scripts.cuw_engine_worker import (
            _finalize_engine_worker_replacement,
            _replace_engine_worker,
        )

        previous = self.worker
        self.worker = _replace_engine_worker(self.engine, self.controller, previous)
        _finalize_engine_worker_replacement(self.engine, previous, self.worker)
        self.assertEqual(self.worker._control_count_scratch2026, [0, 0])
        self.assertEqual(self.worker._control_percent_scratch2026, [61, 67])

    def test_source_reset_pending_clears_only_private_scratch_after_non_be8_two_phase(
        self,
    ):
        self.worker._control_count_scratch2026[:] = [3, 5]
        self.worker._control_percent_scratch2026[:] = [7, 11]
        self.worker._control_scratch_reset_pending2026 = True
        with self.engine.controller_execution(self.controller, 0):
            pass
        self.assertEqual(self.worker._control_count_scratch2026, [0, 0])
        self.assertEqual(self.worker._control_percent_scratch2026, [0, 0])
        self.assertFalse(self.worker._control_scratch_reset_pending2026)
        self.assertEqual(self.engine.dh_state.transferred_bytes, (19, 23))
        self.assertEqual(self.engine.dh_state.progress, (41, 47))

    def test_source_reset_pending_is_preserved_for_be8_two_and_on_phase_failure(self):
        self.worker._control_count_scratch2026[:] = [13, 17]
        self.worker._control_percent_scratch2026[:] = [19, 23]
        self.worker._control_scratch_reset_pending2026 = True
        self.worker._prepare_handshake = 2
        with self.engine.controller_execution(self.controller, 0):
            pass
        self.assertEqual(self.worker._control_count_scratch2026, [13, 17])
        self.assertTrue(self.worker._control_scratch_reset_pending2026)
        self.worker._prepare_handshake = 1
        with (
            self.assertRaisesRegex(RuntimeError, "source fault"),
            self.engine.controller_execution(self.controller, 0),
        ):
            raise RuntimeError("source fault")
        self.assertEqual(self.worker._control_count_scratch2026, [13, 17])
        self.assertTrue(self.worker._control_scratch_reset_pending2026)

    def test_publication_copies_whole_vectors_and_percent_snapshot_precedes_write(self):
        counts = [101, 103]
        percentages = [109, 113]
        self.worker._control_count_scratch2026[:] = counts
        self.worker._control_percent_scratch2026[:] = percentages
        with self.engine.controller_execution(self.controller, 0):
            context = self.controller.native_control_context2026(self.engine)
            self.worker.publish_control_count2026(context)
            self.assertEqual(self.engine.dh_state.transferred_bytes, tuple(counts))
            self.worker.publish_control_percent2026(context)
            self.assertEqual(self.worker._previous_percentages2026, (41, 47))
            self.assertEqual(self.engine.dh_state.progress, tuple(percentages))

    def test_foreign_context_and_bad_dword_are_rejected_without_global_mutation(self):
        with self.engine.controller_execution(self.controller, 0):
            context = self.controller.native_control_context2026(self.engine)
            with self.assertRaises((TypeError, ValueError)):
                self.worker._control_progress_scratch2026(object())
            with self.assertRaises((TypeError, ValueError)):
                self.worker._store_control_count2026(
                    context, object(), 0, 0x1_0000_0000
                )
        self.assertEqual(self.engine.dh_state.transferred_bytes, (19, 23))

    def test_c25_and_c08_hooks_read_source_owned_bytes(self):
        with self.engine.controller_execution(self.controller, 0):
            context = self.controller.native_control_context2026(self.engine)
            with self.assertRaises((TypeError, ValueError)):
                self.worker.publish_sbr_ssm2026(object())
            self.engine.dh_state._central_gateway_type = 0x102
            self.worker._source_mode = 0x205
            with self.assertRaisesRegex((TypeError, ValueError), "helper entry"):
                self.worker.publish_control_callback_2f2026(context)
            self.engine._ssmid_cache2026 = 0xA5
            self.assertEqual(self.worker.store_control_ssm_retry2026(context), 0xA5)
        self.assertEqual(self.worker._control_ssm_byte2026, 0xA5)
        self.assertEqual(self.worker._source_mode, 0x205)
        self.assertEqual(self.engine.dh_state._central_gateway_type, 0x102)

    def test_helper_cpass_rejects_missing_source_entry_without_mutating_native_state(
        self,
    ):
        from scripts.programming_2026_common import NativePassThruException2026

        state = self.engine.dh_state
        state.record_native_error(0x12, 0x34, 0x56)
        self.worker._failed = True
        with self.engine.controller_execution(self.controller, 0):
            context = self.controller.native_control_context2026(self.engine)
            with self.assertRaisesRegex(ValueError, "helper entry"):
                self.worker._record_control_helper_cpass2026(
                    context,
                    NativePassThruException2026(0x78, "test", 1),
                    object(),
                )
        self.assertEqual(
            (state.error_kind, state.primary_error, state.passthru_error),
            (0x12, 0x34, 0x56),
        )
        self.assertTrue(self.worker.control_state.failed)
        self.assertFalse(self.worker.native_fatal_input80)
        self.assertFalse(self.worker.control_state.fatal)

    def test_helper_cpass_copies_only_primary_and_sets_both_native_fatal_fields(self):
        from scripts.programming_2026_common import NativePassThruException2026

        state = self.engine.dh_state
        state.record_native_error(0x12, 0x34, 0x56)
        with self.engine.controller_execution(self.controller, 0):
            context = self.controller.native_control_context2026(self.engine)
            raw_lease = self.controller._begin_native_control_raw_execution2026(
                self.engine
            )
            helper_lease = self.controller._begin_native_control_helper_entry2026(
                self.engine, helper="6f20"
            )
            try:
                self.worker._record_control_helper_cpass2026(
                    context,
                    NativePassThruException2026(-2, "source", 0x123),
                    helper_lease,
                )
            finally:
                self.controller._end_native_control_helper_entry2026(
                    self.engine, lease=helper_lease
                )
                self.controller._end_native_control_raw_execution2026(
                    self.engine, raw_lease
                )
        self.assertEqual(
            (state.error_kind, state.primary_error, state.passthru_error),
            (0x12, 0xFFFFFFFE, 0x56),
        )
        self.assertFalse(self.worker.control_state.failed)
        self.assertTrue(self.worker.native_fatal_input80)
        self.assertTrue(self.worker.control_state.fatal)


class HeldControlFileCapture2026Tests(unittest.TestCase):
    def setUp(self):
        required = (RUNTIME / "CUW.dll", RUNTIME / "TCUWControlCommPhase.dll")
        if any(not path.is_file() for path in required):
            self.skipTest("Authenticated static CUW2026 pipeline is absent")

    def test_held_capture_survives_outer_file_change_without_deleting_source(self):
        first_source = calibration(first_target="FILE-A")
        second_source = calibration(first_target="FILE-B")
        state = ReproInfoState(
            (
                RecoveryCalibration("first.cuw", first_source),
                RecoveryCalibration("second.cuw", second_source),
            ),
            multi_calibration_file_num=2,
        )
        with tempfile.TemporaryDirectory() as directory:
            persistence = CUWPersistence(Path(directory), state)
            engine = EngineWorker2026Tests().engine(
                first_source, persistence=persistence
            )
            self.addCleanup(engine.close)
            controller = make_controller(NativeRuntime2026(lambda *_: None))
            worker = engine.bind_worker(controller)
            original = engine.native_metadata
            with engine.controller_execution(controller, 2):
                capture = worker._control_file_capture
                self.assertIsNotNone(capture)
                assert capture is not None
                second = worker.loaded_metadata[1]
                engine._select_worker_metadata(
                    second, controller=controller, worker=worker
                )
                capture.validate(engine, controller)
                self.assertIs(engine.native_metadata, second)
                self.assertIs(capture.metadata, original)
                self.assertIs(
                    capture.metadata_for_cpu(0).source_container,
                    original.source_container,
                )
                self.assertIsNot(
                    capture.metadata.source_container,
                    engine.native_metadata.source_container,
                )


class ControlDHRetryPublisherTests(unittest.TestCase):
    def test_actual_prepare_retry_writer_lease_publishes_c08(self):
        import importlib.util
        from unittest.mock import patch

        from scripts import programming_2026_common
        from scripts.cuw_engine_worker import EngineWorker2026
        from tests.private_evidence import require_private

        fixture_relative = Path("runtime/no-car-119/dh_retry_fixture.py")
        require_private(fixture_relative)
        fixture_path = Path(__file__).resolve().parents[1] / fixture_relative
        spec = importlib.util.spec_from_file_location("dh_retry_fixture", fixture_path)
        self.assertIsNotNone(spec)
        assert spec is not None and spec.loader is not None
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)

        with fixture.canonical(authoring=True) as (
            engine,
            controller,
            root,
            host_cancel,
        ):
            retry = engine.bind_retry_controller()
            worker = engine.worker
            self.assertIsInstance(worker, EngineWorker2026)
            accepted = []
            rejected_wrong_scope = []
            original_publish = worker._publish_control_gateway_type2026

            def publish(state):
                target = engine._controller_export_target2026
                self.assertIsNotNone(target)
                if target is not None and target.binding.operation == "write":
                    self.assertIn(
                        programming_2026_common._control_export_dispatch2026(
                            target, "PrepareRetry"
                        )["module"],
                        {
                            "TCUWCanDHFlashWriter.dll",
                            "TCUWCanDHUDSFlashWriter.dll",
                            "TCUWP5CanDHUDSFlashWriter.dll",
                        },
                    )
                    accepted.append(target)
                    prior_mode = worker._source_mode
                    helper_lease = controller._native_control_export_lease2026
                    lease_record = (
                        programming_2026_common._NATIVE_CONTROL_HELPER_LEASES_2026[
                            id(helper_lease)
                        ]
                    )
                    prior_export = lease_record[1]["export"]
                    try:
                        lease_record[1]["export"] = "StartFlashWrite"
                        with self.assertRaises((TypeError, ValueError)):
                            original_publish(state)
                        self.assertEqual(worker._source_mode, prior_mode)
                    finally:
                        lease_record[1]["export"] = prior_export
                    rejected_wrong_scope.append(target)
                    return original_publish(state)

            raw_reports, failures = [], []

            def execute():
                try:
                    with engine.controller_execution(controller, 2):
                        raw_reports.append(controller.execute(engine, root))
                except BaseException as error:  # noqa: BLE001 - preserve native fault
                    failures.append(error)

            thread = threading.Thread(target=execute, daemon=True)
            with (
                patch.object(worker, "_publish_control_gateway_type2026", publish),
            ):
                thread.start()
                try:
                    query = retry.wait_for_query()
                    self.assertEqual(query.primary_error, 1)
                    self.assertEqual(query.passthru_error, 24)
                    self.assertEqual(engine.inform_result_of_query_retry(1, 0), 0)
                    thread.join(3)
                    self.assertFalse(thread.is_alive())
                except BaseException:
                    engine.cancel()
                    host_cancel.set()
                    thread.join(3)
                    raise

            if failures:
                raise failures[0]
            self.assertEqual(len(raw_reports), 1)
            self.assertFalse(raw_reports[0]["native_return"])
            self.assertTrue(accepted)
            self.assertTrue(rejected_wrong_scope)
            self.assertEqual(engine.dh_state._central_gateway_type, 1)

            with self.assertRaises((TypeError, ValueError)):
                original_publish(object())
            with self.assertRaises((TypeError, ValueError)):
                original_publish(engine.dh_state)


class ControlSBRActualWorker2026Tests(unittest.TestCase):
    def test_real_prepare_sbr_read_publishes_through_registered_worker(self):
        from dataclasses import replace
        from unittest.mock import patch

        from scripts.cuw_parameter_pool import ControlParameterPool2026
        from scripts.native_modules import identify_native_module
        from scripts.programming_2026_common import NativeControlExportTarget2026
        from scripts.programming_2026_vendor import (
            SBRUtils2026,
            bind_native_context,
            prepare_sbr,
        )

        source = cuw(
            "[Format]\nVersion=9\n[Vehicle]\nNumberOfCalibration=1\n"
            "ContactType=P5-CAN\nKindOfECU=106\n[CPU01]\nCPUType=282\n"
            "NumberOfFiles=1\n[File1001]\nALFID=44\nEraseBlock=1\n"
            "DownloadAddress=00001000\nDownloadMemsize=00000004\n",
            (b"DATA",),
        )
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
                    (("106P5-CAN282", "0", "0", "00", "1", "0", "0"),),
                )
            },
            encoded=False,
        )
        engine = CUWEngine2026(
            read_private_bytes(RUNTIME / "CUW.dll"), general_parameters=general
        )
        engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
        engine.load_cuw(source)
        self.addCleanup(engine.close)

        challenge_fault = OSError("authored SBR challenge read fault")
        read_count = 0

        def provider(operation, _remaining):
            nonlocal read_count
            name = operation["operation"]
            if name == "start_flow_control_filter":
                return 1
            if name == "write_messages":
                return 1
            if name == "read_specified_can_message":
                read_count += 1
                if read_count == 2:
                    raise challenge_fault
                return operation["address"] + b"\x62\xf1\x00\xe0\x00\x00"
            if name == "get_protocol_id":
                return 6
            if name == "get_timeout":
                return 1000
            if name == "lock":
                return 1
            return None

        runtime = NativeRuntime2026(provider)
        controller = make_controller(runtime)
        worker = engine.bind_worker(controller)
        module_name = "TCUWCanSBRPrepareWriter.dll"
        module_data = read_private_bytes(RUNTIME / module_name)
        module_identity = identify_native_module(
            hashlib.sha256(module_data).hexdigest(), module_name
        )
        catalog = {
            "106P5-CAN282.ini": table(
                (
                    "ParamFileKeySystemProtocolMicon",
                    "DLLFileNameForPrepareWrite",
                    "GetCANIDFunctionNameForPrepareWrite",
                    "CanIDForPrepareWrite",
                    "ReceiveTimeoutBeforeGetCID",
                    "SBLStartAddressSize",
                    "DATAStartAddressSize",
                ),
                (
                    (
                        "106P5-CAN282",
                        module_name,
                        "GetCanIDsFromParamForPrepareWrite",
                        "07E0/07E8",
                        "100",
                        "00001000\n00000004",
                        "00001000\n00000004",
                    ),
                ),
            )
        }

        with engine.controller_execution(controller, 0):
            pool = ControlParameterPool2026.issue(
                engine, controller, catalog, encoded=False
            )
            self.addCleanup(pool.close)
            self.assertEqual(pool.load_for(engine, controller, "prepare"), (0,))
            target = NativeControlExportTarget2026.issue(
                engine, controller, pool, 0, "prepare"
            )
            parent_context = bind_native_context(
                target.binding.metadata.source_container,
                target.binding.metadata.node,
                (),
                target.binding,
                module_identity,
                {},
                {"cpu_index": 0},
            )
            with (
                engine.controller_export_target(controller, target),
                patch.object(
                    runtime._device_calls,
                    "control_export",
                    (engine, controller, target),
                    create=True,
                ),
            ):
                with (
                    patch.object(SBRUtils2026, "extended_session"),
                    patch.object(SBRUtils2026, "collate_gateway"),
                    patch.object(SBRUtils2026, "central_gateway_routine"),
                    patch.object(SBRUtils2026, "diagnostic_mask"),
                    patch.object(SBRUtils2026, "stop_communication"),
                    patch.object(SBRUtils2026, "programming_session"),
                    self.assertRaises(OSError) as caught,
                ):
                    prepare_sbr(
                        parent_context,
                        runtime,
                        key_provider=lambda *_: bytes(4),
                        gateway_key_provider=lambda _: bytes(256),
                    )
                self.assertIs(caught.exception, challenge_fault)
                self.assertEqual(worker._control_ssm_byte2026, 0xE0)
                producer = worker._sbr_ssm_producer2026
                self.assertIsNotNone(producer)
                assert producer is not None
                utility = producer[0]
                clone = SBRUtils2026(utility.channel)
                saved_context = utility.context
                self.assertIsNotNone(saved_context)
                assert saved_context is not None
                clone.context = saved_context
                clone.ssm = utility.ssm
                with self.assertRaisesRegex(ValueError, "producer"):
                    worker.publish_sbr_ssm2026(clone)

                utility.context = replace(saved_context)
                try:
                    with self.assertRaisesRegex(ValueError, "producer"):
                        worker.publish_sbr_ssm2026(utility)
                finally:
                    utility.context = saved_context

                saved_runtime = utility.runtime
                utility.runtime = NativeRuntime2026(lambda *_: None)
                try:
                    with self.assertRaisesRegex(ValueError, "producer"):
                        worker.publish_sbr_ssm2026(utility)
                finally:
                    utility.runtime = saved_runtime

                saved_scope = runtime._device_calls.control_export
                runtime._device_calls.control_export = (engine, controller, object())
                try:
                    with self.assertRaisesRegex(ValueError, "producer"):
                        worker.publish_sbr_ssm2026(utility)
                finally:
                    runtime._device_calls.control_export = saved_scope

                errors = []

                def publish_from_foreign_thread():
                    try:
                        worker.publish_sbr_ssm2026(utility)
                    except ValueError as error:
                        errors.append(error)

                foreign = threading.Thread(target=publish_from_foreign_thread)
                foreign.start()
                foreign.join()
                self.assertEqual(len(errors), 1)
            self.assertEqual(worker._control_ssm_byte2026, 0xE0)


if __name__ == "__main__":
    unittest.main()
