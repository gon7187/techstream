"""Authored whole-engine cleanup cases; no native executable is loaded."""

import struct
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.cuw_2026 import CUWEngine2026
from scripts.cuw_engine_cleanup import (
    CleanupCollectionRecord2026,
    CleanupResource2026,
    CleanupStatistics2026,
    EngineCleanup2026,
    _issue_engine_cleanup,
)
from scripts.cuw_persistence import (
    CUWPersistence,
    RecoveryCalibration,
    ReproInfoState,
    parse_recovery_info,
)
from scripts.j2534_2026 import (
    DriverMetadata2026,
    J2534Device2026,
    NativeJ2534Error2026,
    PrimitiveResult,
)
from scripts.programming_2026_common import (
    NativeRuntime2026,
)
from tests.test_cuw_engine_worker import calibration, make_controller


class CleanupValueTests(unittest.TestCase):
    def test_direct_engine_cleanup_construction_is_rejected(self):
        with self.assertRaises(TypeError):
            EngineCleanup2026(None, None)  # pyright: ignore[reportArgumentType]

    def test_record_clear_retains_record_and_container_identity(self):
        record = CleanupCollectionRecord2026(
            CleanupResource2026(None),
            [b"one"],
            [7],
            [b"two"],
            [b"three"],
            8,
            b"four",
            9,
            10,
        )
        strings, words = record.strings80, record.words04
        record.clear()
        self.assertIs(record.strings80, strings)
        self.assertIs(record.words04, words)
        self.assertEqual(record, CleanupCollectionRecord2026())

    def test_native_pointer_duplicate_is_detected_instead_of_silently_deduplicated(
        self,
    ):
        resource = CleanupResource2026(None)
        resource.delete()
        with self.assertRaisesRegex(ValueError, "more than once"):
            resource.delete()

    def test_statistics_cpu_and_32cpu_vectors(self):
        statistics = CleanupStatistics2026()
        statistics.reset(3)
        self.assertEqual(
            [len(values) for values in statistics.strings], [3, 3, 3, 3, 96]
        )
        self.assertEqual(statistics.flagsfc, [False] * 3)
        self.assertEqual(statistics.wordsc8, [0] * 96)
        self.assertEqual(statistics.words10c, [0] * 3)


class EngineCleanupTests(unittest.TestCase):
    def setUp(self):
        path = Path("runtime/no-car-21/recovered/CUW.dll")
        if not path.is_file():
            self.skipTest("Private authenticated static source is unavailable")
        self.engine = CUWEngine2026(path.read_bytes())
        self.engine.configure(struct.pack("<IIddII", 4, 0, 5.0, 13.0, 0, 0))
        self.engine.load_cuw(calibration())
        self.calls = []
        self.provider_fault: BaseException | None = None

        def provider(operation, _remaining):
            self.calls.append(operation)
            if self.provider_fault is not None:
                raise self.provider_fault
            if operation["operation"] == "passthru_read_version":
                return PrimitiveResult(
                    value=("authored-fw", "authored-dll", "authored-api")
                )
            if operation["operation"] == "passthru_ioctl":
                return PrimitiveResult(value=12000 if operation["ioctl"] == 3 else None)
            if operation["operation"] == "passthru_open":
                return PrimitiveResult(value=101)
            if operation["operation"] == "passthru_connect":
                return PrimitiveResult(value=202)
            return PrimitiveResult()

        self.provider = provider
        self.device = J2534Device2026(provider, background_workers=False)
        self.worker = self.bind_views(self.engine, device=self.device)
        self.controller = self.worker.controller
        self.runtime = self.worker.runtime
        self.pair = self.engine.interface_pair
        self.cleanup = _issue_engine_cleanup(self.engine, self.worker)
        self.addCleanup(self.engine.close)

    def bind_views(self, engine, *, device=None):
        from scripts.j2534_2026 import J2534InterfacePair2026

        device = device or J2534Device2026(self.provider, background_workers=False)
        control_device = J2534Device2026(device.provider, background_workers=False)
        engine.bind_interface_pair(J2534InterfacePair2026(device, control_device))
        runtime = NativeRuntime2026(control_device.primitive)
        return engine.bind_worker(make_controller(runtime))

    def test_issuer_reuses_actual_engine_owner(self):
        self.assertIs(_issue_engine_cleanup(self.engine, self.worker), self.cleanup)
        self.cleanup.validate_owner(self.engine, self.worker)
        with self.assertRaises(ValueError):
            self.cleanup.validate_owner(object(), self.worker)
        with self.assertRaises(TypeError):
            _issue_engine_cleanup(self.engine, object())

    def test_worker_rebind_rejects_unissued_replacement_without_mutating_globals(self):
        state = self.cleanup.state
        resources = tuple(state.targets)
        with self.assertRaises(TypeError):
            self.cleanup.rebind_worker(self.worker, object())
        with self.assertRaises(ValueError):
            self.cleanup.rebind_worker(self.worker, self.worker)
        self.assertIs(self.cleanup.worker, self.worker)
        self.assertIs(self.cleanup.state, state)
        self.assertEqual(tuple(state.targets), resources)

    def stopped_two_file_job(self):
        from tests.test_cuw_engine_threads import ThreadOwnershipTests

        fixture = ThreadOwnershipTests()
        self.addCleanup(fixture.doCleanups)
        engine, controller, job, root, _pair, _rows, _sdk, _sources = (
            fixture.authored_two_file_getter_job()
        )
        fixture.complete_two_file_getter_roots(engine, controller, job, root)
        session = root.next_session2026("get_cid", node=1, cpu_index=0)
        session.bind_runtime2026(controller.runtime)
        session.bind_engine2026(engine)
        session.bind_controller2026(controller)
        fault = OSError("authored CID clock boundary")

        def clock_fault():
            raise fault

        session.trace.native_local_milliseconds_of_day = clock_fault
        controller.runtime.local_milliseconds_of_day = clock_fault
        job.start(session)
        with self.assertRaises(OSError) as caught:
            job.result(2)
        self.assertIs(caught.exception, fault)
        self.assertEqual(engine.stop_receiving_cid(timeout=2), 0)
        self.assertFalse(job.native_worker_exists)
        return engine, controller, job

    def test_native_cid_stop_reissues_worker_preserving_actual_two_file_globals(self):
        engine, controller, old_job = self.stopped_two_file_job()
        cleanup = engine.bind_cleanup_controller()
        retry = engine.bind_retry_controller()
        state = cleanup.state
        targets = tuple(state.targets)
        history, vectors = state.history, state.vectors
        persistence = engine.persistence
        assert persistence is not None
        notifications = (persistence.notification, persistence.last_block_notification)
        history[0] = 91
        old = old_job.worker
        containers = tuple(item.source_container for item in old.loaded_metadata)
        job = engine.bind_thread_job(controller)
        self.assertIsNot(job, old_job)
        self.assertIsNot(job.worker, old)
        self.assertTrue(old._closed)
        self.assertIs(cleanup, engine.bind_cleanup_controller())
        self.assertIs(cleanup.worker, job.worker)
        self.assertIs(retry.worker, job.worker)
        self.assertIs(cleanup.state, state)
        self.assertIs(state.history, history)
        self.assertIs(state.vectors, vectors)
        self.assertEqual(history[0], 91)
        self.assertIs(persistence.notification, notifications[0])
        self.assertIs(persistence.last_block_notification, notifications[1])
        self.assertEqual(tuple(state.targets), targets)
        self.assertEqual(len(containers), 2)
        for previous, current in zip(
            containers, job.worker.loaded_metadata, strict=True
        ):
            self.assertIs(previous, current.source_container)
        cleanup.run()
        self.assertTrue(state.completed)
        self.assertTrue(all(item.deleted for item in targets if item is not None))

    def test_native_cid_reissue_failure_restores_cleanup_worker_and_exact_error(self):
        engine, controller, old_job = self.stopped_two_file_job()
        cleanup = engine.bind_cleanup_controller()
        retry = engine.bind_retry_controller()
        state = cleanup.state
        targets = tuple(state.targets)
        old = old_job.worker
        fault = OSError("authored dependent rebind fault")
        with (
            patch.object(type(retry), "rebind_worker", side_effect=fault),
            self.assertRaises(OSError) as caught,
        ):
            engine.bind_thread_job(controller)
        self.assertIs(caught.exception, fault)
        self.assertIs(engine.worker, old)
        self.assertIs(cleanup.worker, old)
        self.assertIs(retry.worker, old)
        self.assertIs(vars(controller)["worker"], old)
        self.assertIs(engine.thread_job, old_job)
        self.assertFalse(old._closed)
        self.assertIs(cleanup.state, state)
        self.assertEqual(tuple(state.targets), targets)
        cleanup.run()
        self.assertTrue(state.completed)

    def test_exact_sixteen_targets_and_selected_pointer_alias(self):
        state = self.cleanup.state
        self.assertEqual(len(state.targets), 16)
        self.assertEqual(len(state.names), 16)
        self.assertIs(state.targets[0], state.selected)
        assert state.selected is not None and state.selected.metadata is not None
        self.assertIs(
            state.selected.metadata.source_container,
            self.engine.native_metadata.source_container,
        )

    def test_collection_exclusions_auxiliary_and_conditional_delete(self):
        state = self.cleanup.state
        selected = state.selected
        auxiliary, independent = CleanupResource2026(None), CleanupResource2026(None)
        state.auxiliary.resource = auxiliary
        records = [
            CleanupCollectionRecord2026(item)
            for item in (selected, auxiliary, independent, None)
        ]
        state.collection[:] = records
        self.cleanup._targets()
        self.assertTrue(independent.deleted)
        self.assertTrue(auxiliary.deleted)
        assert selected is not None
        self.assertTrue(selected.deleted)
        self.assertIsNone(state.selected)
        self.assertEqual(state.targets, [None] * 16)
        self.assertTrue(all(record.resource is None for record in records))

    def test_sparse_name_count_compares_prefix_not_all_named_slots(self):
        state = self.cleanup.state
        resource = CleanupResource2026(None)
        state.targets[15] = resource
        state.names[15] = b"authored sparse target"
        record = CleanupCollectionRecord2026(resource)
        state.collection.append(record)
        # count=2: pointer at15 is not excluded by67a00; native later deletes it again.
        with self.assertRaisesRegex(ValueError, "more than once"):
            self.cleanup._targets()
        self.assertTrue(resource.deleted)
        self.assertIsNone(record.resource)
        self.assertIs(state.targets[15], resource)
        self.assertIsNotNone(state.selected)

    def test_actual_idle_cleanup_releases_engine_and_device_and_retains_config(self):
        configuration = self.engine.configuration
        state = self.cleanup.state
        state.history[:] = b"x" * 0x1028
        state.buffers[:] = [bytearray(b"one"), bytearray(b"two")]
        self.device.connecting, self.device.channel_id = True, 7
        self.device.opened, self.device.device_id = True, 8
        self.cleanup.run()
        self.assertTrue(state.completed)
        self.assertIsNone(state.selected)
        self.assertEqual(state.targets, [None] * 16)
        self.assertEqual(state.buffers, [None, None])
        self.assertEqual(state.history, bytes(0x1028))
        self.assertEqual(state.vectors[0xD2A4], [-1] * 4)
        self.assertEqual(state.vectors[0xD3B0], [0] * 16)
        self.assertEqual(len(state.statistics), 16)
        self.assertEqual(state.statistics[15].wordsc8, [0] * 128)
        self.assertIs(self.engine.configuration, configuration)
        self.assertEqual(self.engine.native_phase, 4)
        self.assertFalse(self.device.connecting)
        self.assertFalse(self.device.opened)
        self.assertEqual(
            [item["operation"] for item in self.calls],
            ["passthru_disconnect", "passthru_close"],
        )

    def test_actual_paired_engine_cleanup_preserves_control_view_and_closes_once(self):
        pair = self.engine.interface_pair
        assert pair is not None
        control = self.controller.runtime_device()
        self.assertIsNot(control, self.device)
        self.assertIs(self.engine.engine_runtime_device(), self.device)
        self.device.set_driver(DriverMetadata2026("authored", "authored.dll"))
        self.device.open()
        self.device.connect(6)
        pair.import_into(control, pair.export_from(self.device))
        self.cleanup.run()
        self.assertFalse(self.device.opened)
        self.assertFalse(self.device.connecting)
        self.assertTrue(control.opened)
        self.assertTrue(control.connecting)
        control.clear()
        operations = [item["operation"] for item in self.calls]
        self.assertEqual(operations.count("passthru_disconnect"), 1)
        self.assertEqual(operations.count("passthru_close"), 1)
        self.assertFalse(control.opened)
        self.assertFalse(control.connecting)

    def test_actual_family_progress_owner_resets_after_device_clear(self):
        state = self.engine.dh_state
        with self.engine.controller_execution(self.controller, 2):
            state.set_native_count(0, 37)
            state.set_native_percentage(0, 105)
        self.assertEqual(state.transferred_bytes, (37, 0, 0, 0))
        self.assertEqual(state.progress, (105, 0, 0, 0))
        self.cleanup.run()
        self.assertEqual(state.transferred_bytes, (0, 0, 0, 0))
        self.assertEqual(state.progress, (0, 0, 0, 0))

    def test_actual_family_progress_survives_clear_fault_until_successful_retry(self):
        state = self.engine.dh_state
        with self.engine.controller_execution(self.controller, 2):
            state.set_native_count(0, 37)
            state.set_native_percentage(0, 105)
        error = OSError("authored clear fault before live vector reset")
        with (
            patch.object(self.device, "clear", side_effect=error),
            self.assertRaises(OSError) as caught,
        ):
            self.cleanup.run()
        self.assertIs(caught.exception, error)
        self.assertEqual(state.transferred_bytes, (37, 0, 0, 0))
        self.assertEqual(state.progress, (105, 0, 0, 0))
        self.cleanup.run()
        self.assertEqual(state.transferred_bytes, (0, 0, 0, 0))
        self.assertEqual(state.progress, (0, 0, 0, 0))

    def test_disconnect_host_fault_retains_identity_and_all_target_owners(self):
        error = OSError("authored host primitive failure")
        original = tuple(self.cleanup.state.targets)
        self.device.connecting, self.device.channel_id = True, 7
        self.provider_fault = error
        with self.assertRaises(OSError) as caught:
            self.cleanup.run()
        self.assertIs(caught.exception, error)
        self.assertEqual(tuple(self.cleanup.state.targets), original)
        self.assertFalse(self.cleanup.state.completed)
        self.assertEqual(self.cleanup.state.trace, ["disconnect"])

    def test_device_clear_fault_keeps_prior_target_release_and_global_reset(self):
        error = InterruptedError("authored host cancellation during device clear")
        with (
            patch.object(self.device, "clear", side_effect=error),
            self.assertRaises(InterruptedError) as caught,
        ):
            self.cleanup.run()
        self.assertIs(caught.exception, error)
        state = self.cleanup.state
        self.assertEqual(state.targets, [None] * 16)
        self.assertIsNone(state.selected)
        self.assertIn("global-prefix-reset", state.trace)
        self.assertNotIn("vectors-reset", state.trace)
        self.assertFalse(state.completed)

    def test_completed_cleanup_does_not_delete_twice(self):
        self.cleanup.run()
        trace = tuple(self.cleanup.state.trace)
        self.cleanup.run()
        self.assertEqual(tuple(self.cleanup.state.trace), trace)

    def test_native_fault_identity_and_partial_global_chronology(self):
        error = NativeJ2534Error2026(19)
        with (
            patch.object(self.device, "clear", side_effect=error),
            self.assertRaises(NativeJ2534Error2026) as caught,
        ):
            self.cleanup.run()
        self.assertIs(caught.exception, error)
        self.assertIsNone(self.cleanup.state.selected)
        self.assertFalse(self.cleanup.state.completed)

    def test_host_cancel_and_deadline_at_worker_wait_leave_resources_owned(self):
        targets = tuple(self.cleanup.state.targets)
        self.runtime.cancelled = lambda: True
        with self.assertRaises(InterruptedError):
            self.cleanup.run()
        self.assertEqual(tuple(self.cleanup.state.targets), targets)
        self.assertFalse(self.cleanup.state.completed)
        self.runtime.cancelled = lambda: False
        self.runtime.deadline = self.runtime.clock() - 1
        with self.assertRaises(TimeoutError):
            self.cleanup.run()
        self.assertEqual(tuple(self.cleanup.state.targets), targets)
        self.assertFalse(self.cleanup.state.completed)

    def test_host_cancellation_observer_exception_keeps_identity(self):
        fault = OSError("authored cancellation observation failed")

        def cancel():
            raise fault

        self.runtime.cancelled = cancel
        with self.assertRaises(OSError) as caught:
            self.cleanup.run()
        self.assertIs(caught.exception, fault)
        self.assertIsNotNone(self.cleanup.state.selected)
        self.assertNotIn("worker-stopped", self.cleanup.state.trace)

    def test_real_retry_input_unwinds_actual_worker_then_cleans_engine(self):
        self.device.set_driver(DriverMetadata2026("authored", "authored.dll"))
        self.device.connecting, self.device.channel_id = True, 7
        self.device.opened, self.device.device_id = True, 8
        retry = self.engine.bind_retry_controller()
        failures = []
        cancelled = threading.Event()
        self.runtime.cancelled = cancelled.is_set

        def worker():
            try:
                with self.engine.controller_execution(self.controller, 0):
                    self.engine.dh_state.record_native_error(3, 1008, 17)
                    self.engine.notify_native_error_kind()
                    self.engine.notify_native_errors()
                    retry.callback3()
            except BaseException as error:  # noqa: BLE001 - ferry thread failures to the assertion
                failures.append(error)

        thread = threading.Thread(target=worker)
        thread.start()
        try:
            query = retry.wait_for_query()
            self.assertEqual(query.primary_error, 1008)
            self.assertEqual(retry.inform_result(0, 0), 0)
        finally:
            cancelled.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertTrue(self.cleanup.state.completed)
        self.assertEqual(retry.inputs[0].native_result, 0)
        self.assertFalse(retry.query_pending)

    def test_cleanup_wakes_actual_pending_query_without_forged_retry_input(self):
        retry = self.engine.bind_retry_controller()
        failures = []
        cancelled = threading.Event()
        self.runtime.cancelled = cancelled.is_set

        def worker():
            try:
                with self.engine.controller_execution(self.controller, 0):
                    self.engine.dh_state.record_native_error(3, 1008, 17)
                    self.engine.notify_native_error_kind()
                    self.engine.notify_native_errors()
                    retry.callback3()
            except BaseException as error:  # noqa: BLE001 - ferry thread failures to the assertion
                failures.append(error)

        thread = threading.Thread(target=worker)
        thread.start()
        try:
            retry.wait_for_query()
            self.cleanup.run()
        finally:
            cancelled.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertTrue(self.cleanup.state.completed)
        self.assertEqual(retry.inputs, ())
        self.assertFalse(retry.query_pending)

    def persistence_engine(self, directory, *, count=1, logged=False):
        sources = tuple(
            calibration(first_target=f"AUTHORED-{index}") for index in range(count)
        )
        state = ReproInfoState(
            tuple(
                RecoveryCalibration(f"file{index}.cuw", source)
                for index, source in enumerate(sources)
            ),
            multi_calibration_file_num=count if count > 1 else 0,
        )
        persistence = CUWPersistence(Path(directory), state)
        engine = CUWEngine2026(
            Path("runtime/no-car-21/recovered/CUW.dll").read_bytes(),
            persistence=persistence,
        )
        self.addCleanup(engine.close)
        engine.configure(struct.pack("<IIddII", 4, 0, 5.0, 13.0, 0, 0))
        engine.load_cuw(sources[0])
        worker = self.bind_views(engine)
        if logged:
            persistence.notification.assign(True)
            persistence.last_block_notification.assign(True)
        return engine, worker, persistence

    def test_actual_sixteen_file_producer_cleanup_and_inplace_recovery_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, worker, persistence = self.persistence_engine(directory, count=16)
            cleanup = engine.bind_cleanup_controller()
            resources = tuple(cleanup.state.targets)
            state = persistence.state
            primary, secondary = (
                persistence.notification,
                persistence.last_block_notification,
            )
            self.assertEqual(len(worker.loaded_metadata), 16)
            self.assertTrue(all(resource is not None for resource in resources))
            cleanup.run()
            self.assertTrue(
                all(resource is not None and resource.deleted for resource in resources)
            )
            self.assertIs(persistence.state, state)
            self.assertEqual(state, ReproInfoState(()))
            self.assertIs(persistence.notification, primary)
            self.assertIs(persistence.last_block_notification, secondary)
            self.assertFalse(primary)
            self.assertFalse(secondary)
            self.assertEqual(worker._all_loaded_metadata, ())
            with self.assertRaisesRegex(ValueError, "closed"):
                _ = worker.loaded_metadata
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_actual_cross_file_selection_changes_selected_owner_without_new_resource(
        self,
    ):
        engine, worker, _sources = self.delta_engine(listed=True)
        cleanup = engine.bind_cleanup_controller()
        second = cleanup.state.targets[1]
        with engine.controller_execution(worker.controller, 0):
            engine._select_worker_metadata(
                worker.loaded_metadata[1], controller=worker.controller, worker=worker
            )
        self.assertIs(cleanup.state.selected, second)
        cleanup.run()
        assert second is not None
        self.assertTrue(second.deleted)
        self.assertTrue(cleanup.state.completed)

    def test_ordinary_close_revokes_retained_cleanup_before_new_source_binding(self):
        previous = self.cleanup
        self.engine.close()
        with self.assertRaises(ValueError):
            previous.validate_owner(self.engine, self.worker)
        self.engine.load_cuw(calibration(first_target="FRESH-AUTHORED"))
        self.engine.bind_interface_pair(self.pair)
        worker = self.engine.bind_worker(self.controller)
        current = self.engine.bind_cleanup_controller()
        self.assertIsNot(current, previous)
        self.assertIsNot(worker, self.worker)
        current.run()
        self.assertTrue(current.state.completed)

    def delta_engine(self, *, listed=False):
        from scripts.cuw_file_services import admit_file_sources_2026
        from tests.test_calibration_2026 import cuw
        from tests.test_cuw_file_services import PublicFileTests

        def source(target):
            return cuw(
                "[Format]\nVersion=105\n[Vehicle]\nNumberOfNode=1\n"
                "ContactType=P5-Unified\nKindOfECU=149\n"
                "[Node01]\nDiagID=0700\nRequiredSpecReproVer=02\n"
                "NumberOfCalibration=1\n[CPU11]\nCPUImageName=authored.bin\n"
                "CPUType=311\nNewCID=NEW1\nNumberOfTargets=2\n"
                f"01_TargetCalibration={target}\n02_TargetCalibration=LATEST\n",
                (b"data",),
            )

        archive = PublicFileTests.archive(
            b"[Vehicle]\nContactType=P5-Unified\n",
            (
                (
                    "Setting.ini",
                    b"[DeltaReproCalFile]\nFileNum=2\nFileName1=part1.cuw\nFileName2=part2.cuw\n[WholeReproCalFile]\nFileName=whole.cuw\n",
                ),
                ("part1.cuw", source("PART-1")),
                ("part2.cuw", source("PART-2")),
                ("whole.cuw", source("WHOLE")),
            ),
        )
        engine = CUWEngine2026(
            Path("runtime/no-car-21/recovered/CUW.dll").read_bytes(),
        )
        self.addCleanup(engine.close)
        engine.bind_frontend_parameters(PublicFileTests.frontend_parameters())
        engine.configure(struct.pack("<IIddII", 4, 0, 5.0, 13.0, 0, 0))
        if listed:
            sources = admit_file_sources_2026(
                engine,
                "files.json",
                b'["plain.cuw","parts.scuw"]',
                region=0,
                source_files={
                    "plain.cuw": source("PLAIN"),
                    "parts.scuw": archive,
                },
            )
        else:
            sources = admit_file_sources_2026(engine, "parts.scuw", archive, region=0)
        engine.bind_file_sources(sources)
        worker = self.bind_views(engine)
        return engine, worker, sources

    def test_actual_direct_delta_table_collection_auxiliary_selected_aliases(self):
        engine, _worker, _sources = self.delta_engine()
        cleanup = engine.bind_cleanup_controller()
        state = cleanup.state
        whole = state.collection[0].resource
        self.assertIs(state.selected, whole)
        self.assertIs(state.auxiliary.resource, whole)
        self.assertTrue(all(resource is not whole for resource in state.targets))
        resources = tuple(
            resource for resource in state.targets if resource is not None
        )
        cleanup.run()
        assert whole is not None
        self.assertTrue(whole.deleted)
        self.assertTrue(all(resource.deleted for resource in resources))
        self.assertTrue(state.completed)

    def test_logged_delta_recovery_keeps_original_archive_identity_during_cleanup(self):
        engine, _worker, sources = self.delta_engine()
        names, originals, count = sources.recovery_sources()
        with tempfile.TemporaryDirectory() as directory:
            persistence = CUWPersistence(
                Path(directory),
                ReproInfoState(
                    tuple(
                        RecoveryCalibration(name, source)
                        for name, source in zip(names, originals, strict=True)
                    ),
                    multi_calibration_file_num=count,
                ),
            )
            engine.bind_persistence(persistence)
            persistence.notification.assign(True)
            persistence.last_block_notification.assign(True)
            cleanup = engine.bind_cleanup_controller()
            cleanup.run()
            self.assertTrue(cleanup.state.completed)
            self.assertEqual(persistence.state, ReproInfoState(()))
            self.assertIsNone(persistence._cleanup_lease)
            self.assertEqual(
                (Path(directory) / "Save" / "parts.scuw").read_bytes(),
                sources.admission_source,
            )

    def test_actual_group_reset_retains_selected_delta_until_worker_wait(self):
        engine, worker, sources = self.delta_engine(listed=True)
        cleanup = engine.bind_cleanup_controller()
        with engine.controller_execution(worker.controller, 0):
            engine._select_worker_metadata(
                worker.loaded_metadata[1], controller=worker.controller, worker=worker
            )
        previous = cleanup.state.selected
        self.assertIs(previous, cleanup.state.targets[1])
        with engine.controller_execution(worker.controller, 0):
            replacement = sources.after_group_reset(1, worker=worker)
            engine._accept_worker_file_reset(sources, replacement, worker=worker)
            self.assertIs(cleanup.state.retired_selected, previous)
            self.assertIs(cleanup.state.selected, cleanup.state.collection[0].resource)
            self.assertIs(cleanup.state.auxiliary.resource, cleanup.state.selected)
            assert previous is not None
            self.assertFalse(previous.deleted)
        cleanup.run()
        self.assertTrue(previous.deleted)
        self.assertIsNone(cleanup.state.retired_selected)
        self.assertTrue(cleanup.state.completed)

    def test_logged_false_callback_updates_ini_preserves_cache_then_resets(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, _worker, persistence = self.persistence_engine(
                directory, logged=True
            )
            source = Path(directory) / "Save" / "file0.cuw"
            original = source.read_bytes()
            engine.bind_cleanup_controller().run()
            document = parse_recovery_info(
                (source.parent / "RecoveryInfo.ini").read_bytes()
            )
            self.assertEqual(document.sections["RecoveryInfo"]["WritingEndBlock"], "0")
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(persistence.state, ReproInfoState(()))
            self.assertIsNone(persistence._cleanup_lease)

    def test_false_notification_io_fault_preserves_later_native_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, _worker, persistence = self.persistence_engine(
                directory, logged=True
            )
            engine._vin = b"AUTHORED-VIN"
            engine._online_modal_state = 19
            fault = OSError("authored cleanup INI write failure")

            def fail(operation, _index):
                if operation == "atomic_replace":
                    raise fault

            persistence.fault_hook = fail
            cleanup = engine.bind_cleanup_controller()
            with self.assertRaises(OSError) as caught:
                cleanup.run()
            self.assertIs(caught.exception, fault)
            self.assertIsNone(cleanup.state.selected)
            self.assertEqual(engine._vin, b"AUTHORED-VIN")
            self.assertEqual(engine._online_modal_state, 19)
            self.assertFalse(persistence.notification)
            self.assertFalse(persistence.last_block_notification)
            self.assertTrue(persistence.state.logged)
            self.assertFalse(persistence.state.writing_end_block)
            self.assertIsNone(persistence._cleanup_lease)
            self.assertNotIn("device-clear", cleanup.state.trace)
            self.assertFalse(cleanup.state.completed)

    def test_primary_false_callback_fault_does_not_clear_secondary_value(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, _worker, persistence = self.persistence_engine(
                directory, logged=True
            )
            cleanup = engine.bind_cleanup_controller()
            error = OSError("authored first false callback failed")
            with (
                patch.object(persistence, "_notification", side_effect=error),
                self.assertRaises(OSError) as caught,
            ):
                cleanup.run()
            self.assertIs(caught.exception, error)
            self.assertFalse(persistence.notification)
            self.assertTrue(persistence.last_block_notification)
            self.assertTrue(persistence.state.writing_end_block)
            self.assertTrue(persistence.state.logged)
            self.assertNotIn("device-clear", cleanup.state.trace)
            self.assertIsNone(persistence._cleanup_lease)

    def test_logged_large_source_closes_before_same_false_callbacks(self):
        from scripts.cuw_large import LargeSource2026
        from tests.test_cuw_large import fixture

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.cuw"
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
            engine = CUWEngine2026(
                Path("runtime/no-car-21/recovered/CUW.dll").read_bytes()
            )
            self.addCleanup(engine.close)
            engine.configure(struct.pack("<IIddII", 4, 0, 5.0, 13.0, 0, 0))
            metadata = engine.load_large_cuw(path)
            source = LargeSource2026(metadata.source_container)
            persistence = CUWPersistence(
                Path(directory) / "cache",
                ReproInfoState((RecoveryCalibration(str(path), source),)),
            )
            engine.bind_persistence(persistence)
            self.bind_views(engine)
            persistence.notification.assign(True)
            persistence.last_block_notification.assign(True)
            primary, secondary = (
                persistence.notification,
                persistence.last_block_notification,
            )
            observations = []

            def observe(operation, _index):
                if operation == "last_block_notification":
                    with self.assertRaisesRegex(ValueError, "closed"):
                        len(source)
                    observations.append("source-closed-before-secondary")

            persistence.fault_hook = observe
            engine.bind_cleanup_controller().run()
            self.assertEqual(observations, ["source-closed-before-secondary"])
            self.assertIs(persistence.notification, primary)
            self.assertIs(persistence.last_block_notification, secondary)
            self.assertFalse(primary)
            self.assertFalse(secondary)
            self.assertEqual(persistence.state, ReproInfoState(()))
            self.assertIsNone(persistence._cleanup_lease)
            saved = Path(directory) / "cache" / "Save" / "large.cuw"
            self.assertEqual(saved.stat().st_size, path.stat().st_size)


if __name__ == "__main__":
    unittest.main()
