"""Actual engine reservation and native thread lifetime checks."""

import copy
import hashlib
import json
import struct
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.cuw_2026 import CUWEngine2026
from scripts.cuw_engine_threads import (
    EngineThreadJob2026,
    ThreadPhaseLease2026,
    validate_thread_phase_lease,
)
from scripts.cuw_file_services import admit_file_sources_2026
from scripts.j2534_2026 import J2534Device2026, J2534InterfacePair2026, PrimitiveResult
from scripts.programming_2026_common import (
    NativeException2026,
    NativeGeneralParameters2026,
    NativeRuntime2026,
)
from scripts.programming_replay import load_programming_replay
from tests import test_cuw_gateway_startup as gateway_fixtures
from tests.private_evidence import read_private_bytes, require_private
from tests.test_calibration_2026 import cuw
from tests.test_cuw_engine_worker import calibration, encoded_table, make_controller


class ThreadOwnershipTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
