"""Authored primitive observations for normal source12/18 polling."""

import copy
import struct
import unittest
from dataclasses import replace
from typing import Literal
from unittest.mock import patch

import test_monitor_instruments as instrument_fixtures
from test_monitor_j2534 import authored_iso_profile, authored_operations

from scripts.data_monitor import (
    MonitorDefinitions,
    MonitorError,
    P4Packing,
    P5Definitions,
    P5DynamicSelection,
    P5PollingPacking,
    RoutineMonitor,
    SelectedP4Monitor,
    SelectedP5CanConnection,
    SelectedP5PollingMonitor,
    p4_setup_commands,
    p5_setup_commands,
    selected_p4_connection,
)
from scripts.diagnostic_db import Section
from scripts.drive_recorder import RecorderCancelled, native_monitor_buffer
from scripts.frame_transport import (
    J2534Result,
    NativeConfig,
    NativeFrameOperations,
    NativeFrameReceive,
    NativeMessage,
    NativeMultiMonOperations,
    get_comm_frame,
)
from scripts.monitor_dual import DualTarget
from scripts.monitor_instruments import OscRead
from scripts.monitor_j2534 import (
    ActiveMonitorEvent,
    DirectJ2534Worker,
    MonitorSystemEvent,
)
from scripts.monitor_p5 import P5MixedPacking, SelectedP5Monitor
from scripts.monitor_poll import (
    OK,
    MultiMonitorPollingWorker,
    NormalOscilloscopeSelection,
    NormalPollingWorker,
    Phase4PacketEvent,
    Phase5ActiveEvent,
    Phase5SystemEvent,
    selected_normal_poll_worker,
    selected_poll_event,
    selected_variable_single_worker,
)
from scripts.monitor_support import MonitorSupportCache, monitor_source_identity
from scripts.monitor_variable import SelectedVariableMonitor, VariableRuntimeTarget
from scripts.native_communication import NativeCommunication, NativeFrameController


def authored_worker(*, build: Literal[12, 18] = 18, p5=False, **kwargs):
    operations, backend = authored_operations(build=build)
    connection = selected_p4_connection(
        operations.profile,
        bus_id=0x12,
        diagnostic_mode=bytes(16),
        controller_category_flags=4,
    )
    identity = monitor_source_identity(operations.profile, "")
    if p5:
        definitions = P5Definitions((1,), (), (), "authored", identity)
        packing = P5PollingPacking(((0x1234, 2),), ((0, 2),), (), ())
        commands = p5_setup_commands(
            interface_id=0x7E0,
            buffer_468=42,
            total_length=2,
            standard_values=(),
            data_ids=packing.data_ids,
            dtc_requests=(),
            routines=(),
            parameter_6=3,
        )
        plan = SelectedP5PollingMonitor(
            definitions, packing, (), ((0, 2),), commands, (), build
        )
    else:
        definitions = MonitorDefinitions((1,), (), (), "authored", identity)
        packing = P4Packing(0x10, 4, (), (b"\x01\x0c", b"\x01\x02"), ((0, 2),), ())
        commands = p4_setup_commands(
            packing,
            interface_id=0x7E0,
            buffer_468=42,
            total_length=2,
            standard_values=(),
            attribute_2_23=False,
        )
        plan = SelectedP4Monitor(
            definitions, packing, (), ((0, 2),), commands, (), build
        )
    worker = NormalPollingWorker(
        operations, plan, connection, clock=lambda: 0, ticks=lambda: 1234, **kwargs
    )
    return worker, backend


def authored_multi(*, build: Literal[12, 18] = 18):
    base, backend = authored_worker(build=build)
    assert isinstance(base.plan, SelectedP4Monitor)
    targets = []
    lower = []
    profiles = {}
    for category in (42, 43):
        profile = copy.copy(base.operations.profile)
        cat = bytearray(profile.category_record)
        struct.pack_into("<H", cat, 68, category)
        catalog = copy.copy(profile.catalog)
        management = catalog.management
        sections = dict(management.sections)
        for slot, width in ((13, 24 if build == 12 else 28), (18, 16), (16, 76)):
            data = bytearray(sections[slot].payload)
            for n in range(sections[slot].count):
                struct.pack_into("<H", data, n * width, category)
            if slot == 16:
                struct.pack_into("<H", data, 68, category)
            sections[slot] = replace(sections[slot], payload=bytes(data))
        sections[29] = Section(
            29, 0, 1, False, struct.pack("<II", 1000, 200) + bytes(8)
        )
        catalog.management = replace(management, sections=sections)
        profile = replace(profile, category_record=bytes(cat), catalog=catalog)
        ecu = f"ecu{category}"
        profiles[ecu] = profile
        cache = MonitorSupportCache(
            profile,
            lambda q: b"",
            ecu,
            source_build=build,
            bus_id=0x12,
            clock=lambda: 0,
        )
        conn = selected_p4_connection(
            profile, bus_id=0x12, diagnostic_mode=bytes(16), controller_category_flags=4
        )
        plan = SelectedVariableMonitor(
            replace(
                base.plan.definitions,
                source_identity=monitor_source_identity(profile, ""),
            ),
            base.plan.packing,
            (),
            base.plan.frame_sizes,
            p4_setup_commands(
                base.plan.packing,
                interface_id=conn.address.request_id,
                buffer_468=category,
                total_length=2,
                standard_values=(),
                attribute_2_23=False,
            ),
            base.plan.pickup_spans,
            build,
            cache.identity,
        )
        target = VariableRuntimeTarget(
            plan,
            cache,
            conn,
            0x7E0,
            native_monitor_buffer(
                category,
                (),
                plan.frame_sizes,
                (),
                phase=0,
                allocation_size=128,
                name=b"test\0",
                text_encoding="utf-8",
            ),
        )
        targets.append(target)
        lower.append(
            DualTarget(
                ecu,
                conn.address.request_id,
                conn.address.response_id,
                0x12,
                profile.category_record[72],
                category,
                3,
                1000,
                200,
                (conn.can_parameter, conn.can_byte_0, conn.can_byte_1),
                0x7E0,
            )
        )
    ops = NativeMultiMonOperations(
        lower,
        profiles,
        backend,
        driver=base.operations.driver,
        native_build=build,
        source_identity="synthetic MultiMon native source observations",
        device_kind=8,
        clock=lambda: 0,
        wait=lambda _: None,
    )
    return ops, tuple(targets), backend


class NormalPollTests(unittest.TestCase):
    def test_normal_factory_registers_selected_category999_before_start(self):
        for build in (12, 18):
            base, backend = authored_worker(build=build)
            fixture = instrument_fixtures.InstrumentTests()
            self.addCleanup(fixture.doCleanups)
            profile = fixture.profile()
            base.operations.profile.catalog.language = profile.catalog.language
            profile = replace(profile, catalog=base.operations.profile.catalog)
            observed = instrument_fixtures.Observations(
                (
                    OscRead(0, b"ABCD", 1000),
                    OscRead(0, b"EFGH", 2000),
                )
            )
            worker = selected_normal_poll_worker(
                base.operations,
                base.plan,
                base.connection,
                oscilloscope=NormalOscilloscopeSelection(
                    profile, (1, 2, 3, 4), observed
                ),
                clock=lambda: 0,
            )
            assert isinstance(worker, DirectJ2534Worker)
            self.assertIsNotNone(worker.oscilloscope)
            self.assertEqual(backend.calls, [])
            self.assertEqual(worker.run(1).packets[0].payload, b"\xaa\xbb")
            assert worker.oscilloscope is not None
            self.assertEqual(worker.oscilloscope.state, "stopped")
            self.assertEqual(worker.oscilloscope.packets[0].payload, b"EFGH")
            self.assertEqual(
                [call[1] for call in observed.calls if call[0] == "read_buffer"],
                [0x1068] * 2,
            )
            self.assertEqual(observed.calls[-1], ("command", 1, None))

    def test_direct_normal_factory_rejects_dmci_device_before_io(self):
        for p5 in (False, True):
            base, backend = authored_worker(p5=p5)
            base.operations.device_kind = 4
            with self.assertRaises(MonitorError):
                selected_normal_poll_worker(
                    base.operations, base.plan, base.connection, clock=lambda: 0
                )
            self.assertEqual(backend.calls, [])

    def test_direct_multimon_rejects_dmci_device_before_io(self):
        operations, targets, backend = authored_multi()
        operations.control.connected_device = 4
        with self.assertRaisesRegex(MonitorError, "device8"):
            MultiMonitorPollingWorker(operations, targets, clock=lambda: 0)
        self.assertEqual(backend.calls, [])

    def test_multimon_two_selected_entries_share_channel_and_round_robin(self):
        for build in (12, 18):
            operations, targets, backend = authored_multi(build=build)
            worker = MultiMonitorPollingWorker(
                operations, targets, clock=lambda: 0, ticks=lambda: 1234
            )
            captures = worker.run((2, 2))
            self.assertEqual(
                [
                    [packet.payload for packet in capture.packets]
                    for capture in captures
                ],
                [[b"\xaa\xbb"] * 2] * 2,
            )
            self.assertEqual(
                [
                    [packet.timestamp_ms for packet in capture.packets]
                    for capture in captures
                ],
                [[1234] * 2] * 2,
            )
            self.assertEqual([name for name, _ in backend.calls].count("connect"), 1)
            self.assertEqual([name for name, _ in backend.calls].count("disconnect"), 1)
            self.assertIsNone(operations.control.channel)
            self.assertEqual(worker.state, "closed")

    def test_multimon_active_temporarily_uses_first_entry_then_restores_second(self):
        operations, targets, backend = authored_multi()
        original = backend.invoke

        def invoke(operation, fields, *, deadline, cancelled):
            result = original(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "read_messages" and backend.request[:1] == b"\x30":
                return J2534Result(
                    count=1,
                    messages=(
                        NativeMessage(6, 0, 0, 0, 0, b"\x00\x00\x07\xe8\x70\x01"),
                    ),
                )
            return result

        backend.invoke = invoke
        worker = MultiMonitorPollingWorker(
            operations, targets, clock=lambda: 0, ticks=lambda: 10
        )
        worker.start()
        for _ in range(3):
            worker.step()
        self.assertEqual(worker.index, 1)
        worker.active = ActiveMonitorEvent(b"\x01")
        worker.step()
        self.assertEqual((worker.slot, worker.index, worker.restore_index), (0, 0, 1))
        worker.step()
        worker.step()
        self.assertEqual((worker.index, worker.restore_index), (1, 0))
        worker.step()
        self.assertEqual((worker.slot, worker.index), (2, 1))
        worker.stop()
        worker.close()
        self.assertIsNone(operations.control.channel)

    def test_multimon_native_worker_does_not_filter_received_source(self):
        operations, targets, backend = authored_multi()
        original = backend.invoke

        def invoke(operation, fields, *, deadline, cancelled):
            result = original(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "read_messages" and backend.request[:1] == b"\x01":
                return J2534Result(
                    count=1,
                    messages=(
                        NativeMessage(
                            6, 0, 0, 0, 0, b"\x00\x00\x01\x23\x41\x0c\xaa\xbb"
                        ),
                    ),
                )
            return result

        backend.invoke = invoke
        worker = MultiMonitorPollingWorker(operations, targets, clock=lambda: 0)
        self.assertEqual(
            [capture.packets[0].payload for capture in worker.run((1, 1))],
            [b"\xaa\xbb"] * 2,
        )

    def test_multimon_mid_receive_cancel_sends_active_end_then_closes(self):
        operations, targets, backend = authored_multi()
        original = backend.invoke
        requests = []

        def invoke(operation, fields, *, deadline, cancelled):
            nonlocal stopped
            result = original(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "write_messages":
                requests.append(backend.request)
            if operation == "read_messages":
                stopped = True
            return result

        stopped = False
        backend.invoke = invoke
        active = ActiveMonitorEvent(b"\x01")
        worker = MultiMonitorPollingWorker(
            operations,
            targets,
            active=active,
            clock=lambda: 0,
            ticks=lambda: 0,
            cancelled=lambda: stopped,
        )
        guard = operations.cancelled
        with self.assertRaises(InterruptedError):
            worker.run((1, 1))
        self.assertEqual(requests[-1], b"\x30")
        self.assertEqual(len(worker.end_results), 1)
        self.assertIsNone(operations.control.channel)
        self.assertIs(operations.cancelled, guard)
        self.assertFalse(operations.defer_cancel_cleanup)

    def test_multimon_foreign_channel_between_construction_and_start_is_preserved(self):
        operations, targets, backend = authored_multi()
        worker = MultiMonitorPollingWorker(operations, targets, clock=lambda: 0)
        self.assertEqual(operations.connect_multi_mon(deadline=30), 0)
        before = list(backend.calls)
        with self.assertRaisesRegex(MonitorError, "fresh owned"):
            worker.run((1, 1))
        self.assertEqual(backend.calls, before)
        self.assertIsNotNone(operations.control.channel)
        operations.close(deadline=30)

    def test_multimon_native_caller_retains_and_ignores_scalar_setup_failure(self):
        operations, targets, backend = authored_multi()
        original = backend.invoke

        def invoke(operation, fields, *, deadline, cancelled):
            result = original(operation, fields, deadline=deadline, cancelled=cancelled)
            return J2534Result(code=9) if operation == "connect" else result

        backend.invoke = invoke
        worker = MultiMonitorPollingWorker(operations, targets, clock=lambda: 0)
        self.assertEqual(worker.start(), OK)
        self.assertEqual(worker.setup_results, [0x91010009, 0x90020701, 0x90020701])
        self.assertEqual(worker.state, "select")
        for _ in range(3):
            self.assertEqual(worker.step(), OK)
        self.assertEqual(worker.step(), 0xE0000102)
        self.assertEqual(worker.notifications[0].code, 0xE0000102)
        worker.stop()
        worker.close()
        self.assertIsNone(operations.control.channel)

    def test_multimon_uncertain_write_poison_releases_without_end_wire(self):
        operations, targets, backend = authored_multi()
        original = backend.invoke

        def invoke(operation, fields, *, deadline, cancelled):
            if operation == "write_messages":
                raise OSError("uncertain driver write")
            return original(operation, fields, deadline=deadline, cancelled=cancelled)

        backend.invoke = invoke
        worker = MultiMonitorPollingWorker(
            operations, targets, active=ActiveMonitorEvent(b"\x01"), clock=lambda: 0
        )
        with self.assertRaisesRegex(OSError, "uncertain"):
            worker.run((1, 1))
        self.assertTrue(operations.control.poisoned)
        self.assertTrue(operations.operations.poisoned)
        self.assertIsNone(operations.control.channel)
        self.assertEqual([name for name, _ in backend.calls].count("disconnect"), 1)

    def test_multimon_packet_entry_fails_before_native_null_event_dereference(self):
        operations, targets, backend = authored_multi()
        first = targets[0]
        plan = first.plan
        assert isinstance(plan, SelectedVariableMonitor)
        packet = replace(
            first, plan=replace(plan, packing=replace(plan.packing, mode_mask=1))
        )
        with self.assertRaisesRegex(MonitorError, "pair setup"):
            MultiMonitorPollingWorker(operations, (packet, targets[1]), clock=lambda: 0)
        self.assertEqual(backend.calls, [])

    def test_multimon_broken_host_clock_still_releases_resources(self):
        operations, targets, _ = authored_multi()
        worker = MultiMonitorPollingWorker(operations, targets, clock=lambda: 0)
        self.assertEqual(worker.start(), OK)
        worker.clock = lambda: float("nan")
        with self.assertRaisesRegex(MonitorError, "clock"):
            worker.close()
        self.assertIsNone(operations.control.channel)

    def test_multimon_rejects_changed_idmap_before_connect(self):
        operations, targets, backend = authored_multi()
        first = targets[0]
        assert first.connection is not None
        changed = replace(first, connection=replace(first.connection, can_parameter=1))
        with self.assertRaisesRegex(MonitorError, "IDMap"):
            MultiMonitorPollingWorker(
                operations, (changed, targets[1]), clock=lambda: 0
            )
        self.assertEqual(backend.calls, [])

    def test_variable_selected_a1_uses_base_wire_and_host_tick_both_builds(self):
        for build in (12, 18):
            _multi, targets, backend = authored_multi(build=build)
            target = targets[0]
            plan = target.plan
            assert isinstance(plan, SelectedVariableMonitor)
            assert target.connection is not None
            packing = P4Packing(1, 4, (), (b"\xa1\x01\x0c",), ((1, 2),), ())
            plan = replace(
                plan,
                packing=packing,
                commands=p4_setup_commands(
                    packing,
                    interface_id=target.connection.address.request_id,
                    buffer_468=target.cache.profile.category,
                    total_length=2,
                    standard_values=(),
                    attribute_2_23=False,
                ),
            )
            target = replace(target, plan=plan)
            base, _ = authored_worker(build=build)
            operations = NativeFrameOperations(
                target.cache.profile,
                get_comm_frame(
                    target.cache.profile,
                    b"\xa1\x01\x0c",
                    bus_id=0x12,
                    driver=base.operations.driver,
                ),
                backend,
                native_build=build,
                bus_id=0x12,
                driver=base.operations.driver,
                device_kind=8,
                clock=lambda: 0,
            )
            original = backend.invoke
            requests = []

            def invoke(
                operation,
                fields,
                *,
                deadline,
                cancelled,
                original=original,
                backend=backend,
                requests=requests,
            ):
                result = original(
                    operation, fields, deadline=deadline, cancelled=cancelled
                )
                if operation == "write_messages":
                    requests.append(backend.request)
                if operation == "read_messages" and backend.request[:1] in (
                    b"\xa1",
                    b"\xa2",
                ):
                    payload = (
                        b"\xe1\x01\x0c"
                        if backend.request[0] == 0xA1
                        else b"\xe2\x01\xaa\xbb"
                    )
                    return J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(6, 0, 0, 1, 0, b"\x00\x00\x07\xe8" + payload),
                        ),
                    )
                return result

            backend.invoke = invoke
            worker = selected_variable_single_worker(
                operations, target, clock=lambda: 0, ticks=lambda: 9000
            )
            packet = worker.run(1).packets[0]
            self.assertEqual((packet.timestamp_ms, packet.payload), (9000, b"\xaa\xbb"))
            self.assertEqual(worker.native_worker_class, "base")
            self.assertEqual(
                [body for body in requests if body[:1] in (b"\xa1", b"\xa2", b"\xa3")],
                [b"\xa1\x01\x0c", b"\xa2\x01"],
            )
            self.assertFalse(worker.burst)
            self.assertFalse(worker.interrupt)

    def test_variable_single_factory_selects_base_without_packet_driver_path(self):
        _operations, targets, backend = authored_multi()
        target = targets[0]
        base, _ = authored_worker()
        # Keep the selected target's actual source and lower setup together.
        selected = NativeFrameOperations(
            target.cache.profile,
            get_comm_frame(
                target.cache.profile,
                b"\x01\x0c",
                bus_id=0x12,
                driver=base.operations.driver,
            ),
            backend,
            native_build=18,
            bus_id=0x12,
            driver=base.operations.driver,
            device_kind=8,
            clock=lambda: 0,
        )
        worker = selected_variable_single_worker(
            selected, target, clock=lambda: 0, ticks=lambda: 4321
        )
        self.assertEqual(worker.native_worker_class, "base")
        self.assertEqual(worker.run(1).packets[0].timestamp_ms, 4321)
        self.assertEqual([name for name, _ in backend.calls].count("connect"), 1)

    def test_p4_both_builds_actual_primitives_and_packet(self):
        for build in (12, 18):
            with self.subTest(build=build):
                worker, backend = authored_worker(build=build)
                capture = worker.run(2)
                self.assertEqual(
                    [p.payload for p in capture.packets], [b"\xaa\xbb"] * 2
                )
                self.assertEqual(
                    [p.timestamp_ms for p in capture.packets], [1234, 1234]
                )
                calls = [name for name, _ in backend.calls]
                self.assertEqual(calls.count("connect"), 1)
                self.assertEqual(calls.count("disconnect"), 1)
                self.assertEqual(worker.state, "closed")

    def test_p5_request_wire_and_zeroed_short_cycle(self):
        worker, backend = authored_worker(p5=True)
        original = backend.invoke
        seen = 0

        def invoke(operation, fields, *, deadline, cancelled):
            nonlocal seen
            result = original(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "read_messages" and backend.request == b"\x22\x12\x34":
                seen += 1
                payload = b"\x62\x12\x34" + (b"\xaa\xbb" if seen == 1 else b"\xcc")
                return J2534Result(
                    count=1,
                    messages=(
                        NativeMessage(6, 0, 0, 9000, 0, b"\x00\x00\x07\xe8" + payload),
                    ),
                )
            return result

        backend.invoke = invoke
        capture = worker.run(2)
        self.assertEqual([p.payload for p in capture.packets], [b"\xaa\xbb", b"\xcc\0"])
        self.assertEqual(capture.packets[0].timestamp_ms, 1234)

    def test_retry_and_negative_mapping(self):
        for p5, expected in ((False, 0xE0000107), (True, 0xE0000301)):
            worker, backend = authored_worker(p5=p5)
            original = backend.invoke

            def invoke(
                operation,
                fields,
                *,
                deadline,
                cancelled,
                backend=backend,
                original=original,
            ):
                if operation == "read_messages" and backend.request != b"\x10\x01":
                    return J2534Result(code=7)
                return original(
                    operation, fields, deadline=deadline, cancelled=cancelled
                )

            backend.invoke = invoke
            with self.assertRaises(MonitorError) as raised:
                worker.run(1)
            self.assertEqual(raised.exception.code, expected)
            self.assertEqual(worker.failures, 3)
            self.assertIsNone(worker.operations.channel)
            self.assertEqual(worker.notifications[-1].code, expected)

    def test_cancel_releases_owned_channel(self):
        worker, _ = authored_worker()
        worker.start()
        worker.cancelled = lambda: True
        with self.assertRaises(RecorderCancelled):
            worker.step()
        worker.close()
        self.assertIsNone(worker.operations.channel)

    def test_resource_cap_and_source_mismatch(self):
        worker, _ = authored_worker(max_bytes=5)
        with self.assertRaisesRegex(MonitorError, "packet budget"):
            worker.run(1)
        self.assertIsNone(worker.operations.channel)
        worker, _ = authored_worker()
        bad = replace(worker.plan, source_build=12)
        with self.assertRaisesRegex(MonitorError, "source build"):
            selected_poll_event(worker.operations, bad, routine_info=False)
        bad = replace(
            worker.plan,
            definitions=replace(worker.plan.definitions, source_identity=("wrong",)),
        )
        with self.assertRaisesRegex(MonitorError, "another selected source"):
            selected_poll_event(worker.operations, bad, routine_info=False)

    def test_call_budget_prevents_wrong_source_infinite_loop(self):
        worker, backend = authored_worker(max_steps=10)
        original = backend.invoke

        def invoke(operation, fields, *, deadline, cancelled):
            result = original(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "read_messages" and backend.request != b"\x10\x01":
                return J2534Result(
                    count=1,
                    messages=(
                        NativeMessage(
                            6, 0, 0, 0, 0, b"\x00\x00\x07\xe9\x41\x0c\xaa\xbb"
                        ),
                    ),
                )
            return result

        backend.invoke = invoke
        with self.assertRaisesRegex(MonitorError, "call budget"):
            worker.run(1)
        self.assertEqual(worker.packet_count, 0)
        self.assertIsNone(worker.operations.channel)

    def test_mixed_p5_selected_plan_reaches_actual_packet_consumer(self):
        base, backend = authored_worker(p5=True)
        assert isinstance(base.plan, SelectedP5PollingMonitor)
        routine = RoutineMonitor(b"\x31\x03\x01\x02", 1, (), (), ())
        commands = p5_setup_commands(
            interface_id=0x7E0,
            buffer_468=42,
            total_length=5,
            standard_values=(),
            data_ids=((0x1234, 2),),
            dtc_requests=(b"\x19\x02\xff",),
            routines=(routine,),
            parameter_6=3,
        )
        plan = SelectedP5Monitor(
            base.plan.definitions,
            P5MixedPacking(
                ((0x1234, 2),), (), ((0, 2),), P5DynamicSelection((), (), (), ()), None
            ),
            (),
            ((0, 2), (1, 2), (2, 1)),
            commands,
            (),
            18,
            0x20,
            (b"\x19\x02\xff",),
            (0,),
            (routine,),
            (),
        )
        original = backend.invoke

        def invoke(operation, fields, *, deadline, cancelled):
            result = original(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "read_messages" and backend.request != b"\x10\x01":
                payload = {
                    0x22: b"\x62\x12\x34\xaa\xbb",
                    0x19: b"\x59\x02\xff\x01\x02\x03\x04",
                    0x31: b"\x71\x03\x01\x02\xcc",
                }[backend.request[0]]
                return J2534Result(
                    count=1,
                    messages=(
                        NativeMessage(6, 0, 0, 9000, 0, b"\x00\x00\x07\xe8" + payload),
                    ),
                )
            return result

        backend.invoke = invoke
        worker = NormalPollingWorker(
            base.operations, plan, base.connection, clock=lambda: 0, ticks=lambda: 1234
        )
        capture = worker.run(1)
        self.assertEqual(capture.packet_bytes(), b"\xd2\x04\0\0\xaa\xbb\0\x01\xcc")

    def test_stop_clear_uses_registered_list_and_real_common_primitives(self):
        base, backend = authored_worker(p5=True)
        assert isinstance(base.plan, SelectedP5PollingMonitor)
        profile = base.operations.profile
        management = profile.catalog.management
        directory = (
            struct.pack("<IH", 0, 2)
            + struct.pack("<IH", 2, 1)
            + struct.pack("<IH", 3, 4)
        )
        variables = directory + b"\x10\x01\x3e\x2c\x03\0\0"
        settings = bytearray(16)
        struct.pack_into("<II", settings, 0, 1000, 200)
        struct.pack_into("<H", settings, 10, 1)
        profile.catalog.management = replace(
            management,
            sections={
                **management.sections,
                0: Section(0, 0, 3, False, variables),
                17: replace(
                    management.sections[17],
                    count=3,
                    payload=management.sections[17].payload
                    + struct.pack("<4H", 3, 3, 0, 0),
                ),
                18: replace(
                    management.sections[18],
                    count=3,
                    payload=management.sections[18].payload
                    + struct.pack("<8H", 42, 0xD4, 1, 3, 0, 0, 0, 0),
                ),
                29: Section(29, 0, 1, False, bytes(settings)),
            },
        )
        commands = p5_setup_commands(
            interface_id=0x7E0,
            buffer_468=42,
            total_length=2,
            standard_values=(),
            data_ids=((0x1234, 2),),
            dtc_requests=(),
            routines=(),
            parameter_6=3,
            clear_ids=(0xF200, 0xF201),
        )
        plan = replace(base.plan, commands=commands)
        original = backend.invoke
        requests = []

        def invoke(operation, fields, *, deadline, cancelled):
            result = original(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "write_messages":
                requests.append(backend.request)
            if operation == "read_messages" and backend.request[:1] == b"\x2c":
                return J2534Result(
                    count=1,
                    messages=(
                        NativeMessage(6, 0, 0, 0, 0, b"\x00\x00\x07\xe8\x6c\x03"),
                    ),
                )
            return result

        backend.invoke = invoke
        worker = NormalPollingWorker(
            base.operations, plan, base.connection, clock=lambda: 0
        )
        worker.start()
        worker.stop()
        worker.close()
        self.assertEqual(
            [request for request in requests if request[:1] == b"\x2c"],
            [b"\x2c\x03\xf2\x00", b"\x2c\x03\xf2\x01"],
        )
        self.assertEqual([result.status for result in worker.clear_results], [0, 0])

    def test_terminal_reply_after_host_deadline_cannot_report_success(self):
        worker, backend = authored_worker()
        now = 0
        worker.clock = lambda: now
        original = backend.invoke

        def invoke(operation, fields, *, deadline, cancelled):
            nonlocal now
            result = original(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "read_messages" and backend.request != b"\x10\x01":
                now = 31
            return result

        backend.invoke = invoke
        with self.assertRaisesRegex(MonitorError, "deadline"):
            worker.run(1)
        self.assertEqual(worker.packet_count, 0)
        self.assertIsNone(worker.operations.channel)

    def test_native_negative_reply_mapping(self):
        for p5, expected in ((False, 0xE000010D), (True, 0xE0000302)):
            worker, backend = authored_worker(p5=p5)
            original = backend.invoke

            def invoke(
                operation,
                fields,
                *,
                deadline,
                cancelled,
                backend=backend,
                original=original,
            ):
                result = original(
                    operation, fields, deadline=deadline, cancelled=cancelled
                )
                if operation == "read_messages" and backend.request != b"\x10\x01":
                    return J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(
                                6,
                                0,
                                0,
                                0,
                                0,
                                b"\x00\x00\x07\xe8\x7f" + backend.request[:1] + b"\x31",
                            ),
                        ),
                    )
                return result

            backend.invoke = invoke
            with self.assertRaises(MonitorError) as raised:
                worker.run(1)
            self.assertEqual(raised.exception.code, expected)
            self.assertEqual(worker.notifications[-1].parameter, 0x31)
            self.assertEqual(worker.failures, 0)

    def test_phase4_packet_actual_two_mode_grammar(self):
        event = Phase4PacketEvent(
            ((6, b"\x21\x02\x01\x02"), (1, b"\x0c")), ((6, 2), (1, 1)), timeout=3000
        )
        self.assertEqual(event.get_snd_frame(1), b"\xa1\x06\x21\x02\x01\x02")
        self.assertEqual(event.check_rcv_frame(b"\xe1\x06\x21\x02\x01\x02", 1), OK)
        self.assertEqual(event.get_snd_frame(2), b"\xa1\x01\x0c")
        self.assertEqual(event.check_rcv_frame(b"\xe1\x01\x0c", 2), OK)
        self.assertEqual(event.get_snd_frame(3), b"\xa2\x06\x01")
        self.assertEqual(event.check_rcv_frame(b"\xe2\x06\xaa\xbb\xee", 4), OK)
        self.assertEqual(event.packets, [])
        self.assertEqual(event.check_rcv_frame(b"\xe2\x01\xcc", 5), OK)
        self.assertEqual(event.packets[0].payload, b"\xaa\xbb\xcc")
        self.assertEqual(event.packets[0].timestamp_ms, 5)
        self.assertEqual(event.check_rcv_frame(b"\xe2\x01\xcc\xdd", 6), 0xE0000104)
        self.assertEqual(event.check_rcv_frame(b"\xe2\x06\xaa", 6), 0xE0000104)

    def test_normal_phase4_packet_factory_actual_wire_stop_and_drain(self):
        base, backend = authored_worker()
        assert isinstance(base.plan, SelectedP4Monitor)
        packing = P4Packing(
            5,
            4,
            (),
            (b"\xa1\x06\x21\x02\x01\x02", b"\xa1\x01\x0c"),
            ((0x0606, 2), (0x0101, 1)),
            (),
        )
        plan = replace(
            base.plan,
            packing=packing,
            frame_sizes=((6, 2), (1, 1)),
            commands=p4_setup_commands(
                packing,
                interface_id=0x7E0,
                buffer_468=42,
                total_length=3,
                standard_values=(),
                attribute_2_23=False,
            ),
        )
        original = backend.invoke
        reads = {}
        writes = []

        def invoke(operation, fields, *, deadline, cancelled):
            result = original(operation, fields, deadline=deadline, cancelled=cancelled)
            request = backend.request
            if operation == "write_messages":
                writes.append(request)
                reads[request] = 0
            if operation == "read_messages" and request[:1] in (
                b"\xa1",
                b"\xa2",
                b"\xa3",
            ):
                reads[request] += 1
                if request[0] == 0xA1:
                    payload = b"\xe1" + request[1:]
                elif request[0] == 0xA2:
                    payload = (
                        b"\xe2\x06\xaa\xbb" if reads[request] == 1 else b"\xe2\x01\xcc"
                    )
                elif reads[request] == 1:
                    payload = b"\xe3"
                else:
                    return J2534Result(code=0x10)
                return J2534Result(
                    count=1,
                    messages=(
                        NativeMessage(
                            6, 0, 0, 1234000, 0, b"\x00\x00\x07\xe8" + payload
                        ),
                    ),
                )
            return result

        backend.invoke = invoke
        worker = selected_normal_poll_worker(
            base.operations, plan, base.connection, clock=lambda: 0, ticks=lambda: 0
        )
        self.assertIsInstance(worker, DirectJ2534Worker)
        capture = worker.run(1)
        self.assertEqual(capture.packets[0].payload, b"\xaa\xbb\xcc")
        self.assertEqual(capture.packets[0].timestamp_ms, 1234)
        self.assertEqual(
            [
                request
                for request in writes
                if request[:1] in (b"\xa1", b"\xa2", b"\xa3")
            ],
            [b"\xa1\x06\x21\x02\x01\x02", b"\xa1\x01\x0c", b"\xa2\x06\x01", b"\xa3"],
        )
        self.assertIsNone(worker.operations.channel)

    def test_phase5_active_queue_timers_end_dedup_and_partial_failure(self):
        active = Phase5ActiveEvent(
            b"\x12\x34\x03", b"\x12\x34\0", active_type=0, delay=10
        )
        self.assertEqual(active.get_snd_frame(1), b"\x2f\x12\x34\x03")
        self.assertEqual(active.info, 2)
        self.assertEqual(active.check_rcv_frame(b"\x6f\x12\x34", 100), OK)
        self.assertEqual((active.item.status, active.item.next_send), (3, 110))
        active.append(b"\x12\x34\x03", b"\x12\x34\0", active_type=0)
        self.assertEqual(len(active.end_items), 1)
        with self.assertRaises(MonitorError):
            active.append(b"\x12\x35\x03", b"\x12\x35\0", active_type=0)
        self.assertEqual(len(active.items), 3)
        active.stop()
        self.assertEqual(active.get_snd_frame(2), b"\x2f\x12\x34\0")
        self.assertEqual(active.info, 3)
        self.assertEqual(active.check_rcv_frame(b"\x6f\x12\x34", 200), OK)
        self.assertEqual(active.item.status, 5)

    def test_factory_phase4_pair_uses_shared_three_slot_runtime(self):
        base, backend = authored_worker()
        assert isinstance(base.plan, SelectedP4Monitor)
        original = backend.invoke
        requests = []

        def invoke(operation, fields, *, deadline, cancelled):
            result = original(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "write_messages":
                requests.append(backend.request)
            if operation == "read_messages" and backend.request[:1] in (
                b"\x30",
                b"\x08",
            ):
                payload = b"\x70\x01" if backend.request[:1] == b"\x30" else b"\x48"
                return J2534Result(
                    count=1,
                    messages=(
                        NativeMessage(6, 0, 0, 0, 0, b"\x00\x00\x07\xe8" + payload),
                    ),
                )
            return result

        backend.invoke = invoke
        worker = selected_normal_poll_worker(
            base.operations,
            base.plan,
            base.connection,
            active=ActiveMonitorEvent(b"\x01"),
            system=MonitorSystemEvent(b"\x02"),
            clock=lambda: 0,
            ticks=lambda: 1234,
        )
        self.assertIsInstance(worker, DirectJ2534Worker)
        self.assertEqual(worker.run(1).packets[0].payload, b"\xaa\xbb")
        self.assertEqual(
            [r for r in requests if r != b"\x10\x01"],
            [b"\x30\x01", b"\x08\x02", b"\x01\x0c", b"\x30"],
        )

    def test_phase5_three_slot_order_and_actual_end_request(self):
        for build in (12, 18):
            base, backend = authored_worker(p5=True, build=build)
            active = Phase5ActiveEvent(b"\x12\x34\x03", b"\x12\x34\0", active_type=0)
            system = Phase5SystemEvent(b"\x02")
            selected = SelectedP5CanConnection(base.connection, 0x7DF, 0x7E8, 0, build)
            original = backend.invoke
            requests = []

            def invoke(
                operation,
                fields,
                *,
                deadline,
                cancelled,
                original=original,
                backend=backend,
                requests=requests,
            ):
                result = original(
                    operation, fields, deadline=deadline, cancelled=cancelled
                )
                if operation == "write_messages":
                    requests.append(backend.request)
                if operation == "read_messages" and backend.request != b"\x10\x01":
                    payload = {
                        0x2F: b"\x6f\x12\x34",
                        8: b"\x48",
                        0x22: b"\x62\x12\x34\xaa\xbb",
                    }[backend.request[0]]
                    return J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(6, 0, 0, 0, 0, b"\x00\x00\x07\xe8" + payload),
                        ),
                    )
                return result

            backend.invoke = invoke
            worker = selected_normal_poll_worker(
                base.operations,
                base.plan,
                base.connection,
                active=active,
                system=system,
                system_connection=selected,
                clock=lambda: 0,
                ticks=lambda: 1234,
            )
            self.assertIsInstance(worker, NormalPollingWorker)
            assert isinstance(worker, NormalPollingWorker)
            self.assertEqual(worker.run(1).packets[0].payload, b"\xaa\xbb")
            self.assertEqual(
                [r for r in requests if r != b"\x10\x01"],
                [b"\x2f\x12\x34\x03", b"\x08\x02", b"\x22\x12\x34", b"\x2f\x12\x34\0"],
            )
            self.assertEqual(worker.notifications[0].code, 7)
            self.assertEqual(worker.end_results, [(0, OK)])

    def test_phase5_end_queue_attempts_every_distinct_stop_after_negative(self):
        for build in (12, 18):
            base, backend = authored_worker(p5=True, build=build)
            active = Phase5ActiveEvent(b"\x12\x34\x03", b"\x12\x34\0", active_type=0)
            active.append(b"\x12\x35\x03", b"\x12\x35\0", active_type=0)
            original = backend.invoke
            requests = []

            def invoke(
                operation,
                fields,
                *,
                deadline,
                cancelled,
                original=original,
                backend=backend,
                requests=requests,
            ):
                result = original(
                    operation, fields, deadline=deadline, cancelled=cancelled
                )
                if operation == "write_messages":
                    requests.append(backend.request)
                if operation == "read_messages" and backend.request[:1] == b"\x2f":
                    # Native shutdown consumes one reply per retained end command,
                    # then advances even after this first negative response.
                    payload = (
                        b"\x7f\x2f\x31"
                        if backend.request[1:3] == b"\x12\x34"
                        else b"\x6f\x12\x35"
                    )
                    return J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(6, 0, 0, 0, 0, b"\x00\x00\x07\xe8" + payload),
                        ),
                    )
                return result

            backend.invoke = invoke
            worker = NormalPollingWorker(
                base.operations,
                base.plan,
                base.connection,
                active=active,
                clock=lambda: 0,
            )
            self.assertEqual(worker.start(), OK)
            self.assertEqual(worker.stop(), OK)
            self.assertEqual(worker.end_results, [(0, 0x90020321), (0, OK)])
            self.assertEqual(
                [request for request in requests if request[:1] == b"\x2f"],
                [b"\x2f\x12\x34\0", b"\x2f\x12\x35\0"],
            )
            self.assertEqual(active.item.status, 5)
            self.assertEqual(worker.close(), 0)
            self.assertIsNone(worker.operations.channel)

    def test_phase5_active_delay_yields_data_until_due(self):
        base, _ = authored_worker(p5=True)
        active = Phase5ActiveEvent(
            b"\x12\x34\x03", b"\x12\x34\0", active_type=0, delay=10
        )
        worker = NormalPollingWorker(
            base.operations,
            base.plan,
            base.connection,
            active=active,
            clock=lambda: 0,
            ticks=lambda: 100,
        )
        self.assertEqual(worker.start(), OK)
        active.get_snd_frame(100)
        self.assertEqual(active.check_rcv_frame(b"\x6f\x12\x34", 100), OK)
        self.assertEqual(worker.step(), OK)
        self.assertEqual((worker.slot, worker.request), (2, b"\x22\x12\x34"))
        worker.state = "select"
        worker.ticks = lambda: 110
        self.assertEqual(worker.step(), OK)
        self.assertEqual(active.item.status, 0)
        self.assertEqual(worker.step(), OK)
        self.assertEqual((worker.slot, worker.request), (0, b"\x2f\x12\x34\x03"))
        worker.close()

    def test_phase5_uses_metadata_selected_psa_lower_without_tester(self):
        for build in (12, 18):
            base, backend = authored_worker(p5=True, build=build)
            category = bytearray(base.operations.profile.category_record)
            category[72] = 0x34
            profile = replace(base.operations.profile, category_record=bytes(category))
            operations = NativeFrameOperations(
                profile,
                get_comm_frame(
                    profile, b"\x22\x12\x34", bus_id=0x12, driver=base.operations.driver
                ),
                backend,
                native_build=build,
                bus_id=0x12,
                driver=base.operations.driver,
                device_kind=8,
                clock=lambda: 0,
            )
            self.assertEqual(operations.native_variant, "psa")
            self.assertEqual(operations.plan.tester_request, b"")
            identity = monitor_source_identity(profile, "")
            plan = replace(
                base.plan,
                definitions=replace(base.plan.definitions, source_identity=identity),
            )
            connection = selected_p4_connection(
                profile,
                bus_id=0x12,
                diagnostic_mode=bytes(16),
                controller_category_flags=4,
            )
            worker = NormalPollingWorker(operations, plan, connection, clock=lambda: 0)
            self.assertEqual(worker.start(), OK)
            self.assertTrue(operations._configured)
            worker.close()
            operations.native_variant = "dual"
            with self.assertRaisesRegex(MonitorError, "normal frame operations"):
                selected_poll_event(operations, plan, routine_info=False)

    def test_phase5_source12_filters_bus4_where_source18_accepts_it(self):
        for build in (12, 18):
            worker, _ = authored_worker(p5=True, build=build)
            self.assertEqual(worker.start(), OK)
            # Isolate ThreadMain's versioned source check from lower bus decoding.
            worker.operations.bus_id = 0x14
            worker.request = b"\x22\x12\x34"
            worker.state = "receive"
            reply = NativeFrameReceive(b"\x62\x12\x34\xaa\xbb", source_id=0x99)
            with patch.object(worker.controller, "receive", return_value=reply):
                self.assertEqual(worker.step(), OK)
            self.assertEqual(worker.packet_count, int(build == 18))
            self.assertEqual(worker.state, "select" if build == 18 else "receive")
            worker.close()

    def test_phase5_active_rid_normal_and_abnormal_status_paths(self):
        cases: tuple[tuple[Literal[12, 18], int, int], ...] = (
            (18, 0x11, 0x0102),
            (18, 0x22, 0x0102),
            (12, 0x11, 0x9901),
            (12, 0x22, 0x9901),
        )
        for build, status, active_rid in cases:
            base, backend = authored_worker(p5=True, build=build)
            assert isinstance(base.plan, SelectedP5PollingMonitor)
            routine = RoutineMonitor(b"\x31\x03\x01\x02", 1, (0x11,), (0x22,), (0x33,))
            commands = p5_setup_commands(
                interface_id=0x7E0,
                buffer_468=42,
                total_length=1,
                standard_values=(),
                data_ids=(),
                dtc_requests=(),
                routines=(routine,),
                parameter_6=3,
            )
            plan = SelectedP5Monitor(
                base.plan.definitions,
                P5MixedPacking(
                    (), (), ((0, 1),), P5DynamicSelection((), (), (), ()), None
                ),
                (),
                ((0, 1),),
                commands,
                (),
                build,
                0x20,
                (),
                (),
                (routine,),
                (),
            )
            active = Phase5ActiveEvent(
                b"\x01" + active_rid.to_bytes(2, "big"),
                b"\x02" + active_rid.to_bytes(2, "big"),
                active_type=1,
            )
            original = backend.invoke

            def invoke(
                operation,
                fields,
                *,
                deadline,
                cancelled,
                backend=backend,
                original=original,
                status=status,
            ):
                result = original(
                    operation, fields, deadline=deadline, cancelled=cancelled
                )
                if operation == "read_messages" and backend.request[:1] == b"\x31":
                    payload = (
                        b"\x71"
                        + backend.request[1:4]
                        + (bytes((status,)) if backend.request[1] == 3 else b"")
                    )
                    return J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(6, 0, 0, 0, 0, b"\x00\x00\x07\xe8" + payload),
                        ),
                    )
                return result

            backend.invoke = invoke
            worker = NormalPollingWorker(
                base.operations,
                plan,
                base.connection,
                active=active,
                max_steps=20,
                clock=lambda: 0,
                ticks=lambda: 10,
            )
            if status == 0x11:
                self.assertEqual(worker.run(1).packets[0].payload, b"\x11")
            else:
                with self.assertRaisesRegex(MonitorError, "call budget"):
                    worker.run(1)
                self.assertEqual(worker.packet_count, 0)
            self.assertEqual(worker.notifications[0].code, 4)
            self.assertEqual(len(worker.routine_notices), 1)
            self.assertEqual(worker.end_results, [(0, OK)])
            self.assertIsNone(worker.operations.channel)

    def test_phase5_mid_write_cancel_delivers_native_end_before_disconnect(self):
        stopped = False
        base, backend = authored_worker(p5=True)
        active = Phase5ActiveEvent(b"\x12\x34\x03", b"\x12\x34\0", active_type=0)
        original = backend.invoke
        guard = base.operations.cancelled
        requests = []

        def invoke(operation, fields, *, deadline, cancelled):
            nonlocal stopped
            result = original(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "write_messages":
                requests.append(backend.request)
                if backend.request[:1] == b"\x22":
                    stopped = True
            if operation == "read_messages" and backend.request[:1] == b"\x2f":
                return J2534Result(
                    count=1,
                    messages=(
                        NativeMessage(6, 0, 0, 0, 0, b"\x00\x00\x07\xe8\x6f\x12\x34"),
                    ),
                )
            return result

        backend.invoke = invoke
        worker = NormalPollingWorker(
            base.operations,
            base.plan,
            base.connection,
            active=active,
            clock=lambda: 0,
            cancelled=lambda: stopped,
        )
        with self.assertRaises(InterruptedError):
            worker.run(1)
        self.assertEqual(requests[-1], b"\x2f\x12\x34\0")
        self.assertEqual(worker.end_results, [(0, OK)])
        self.assertIsNone(worker.operations.channel)
        self.assertIs(worker.operations.cancelled, guard)

    def test_phase5_before_drive_uses_stop_list_and_tags_notice(self):
        base, backend = authored_worker(p5=True)
        assert isinstance(base.plan, SelectedP5PollingMonitor)
        routine = RoutineMonitor(b"\x31\x03\x01\x02", 1, (0x22,), (), (0x11,))
        commands = p5_setup_commands(
            interface_id=0x7E0,
            buffer_468=42,
            total_length=1,
            standard_values=(),
            data_ids=(),
            dtc_requests=(),
            routines=(routine,),
            parameter_6=3,
        )
        plan = SelectedP5Monitor(
            base.plan.definitions,
            P5MixedPacking((), (), ((0, 1),), P5DynamicSelection((), (), (), ()), None),
            (),
            ((0, 1),),
            commands,
            (),
            18,
            0x20,
            (),
            (),
            (routine,),
            (),
        )
        original = backend.invoke

        def invoke(operation, fields, *, deadline, cancelled):
            result = original(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "read_messages" and backend.request[:1] == b"\x31":
                return J2534Result(
                    count=1,
                    messages=(
                        NativeMessage(
                            6, 0, 0, 0, 0, b"\x00\x00\x07\xe8\x71\x03\x01\x02\x11"
                        ),
                    ),
                )
            return result

        backend.invoke = invoke
        worker = NormalPollingWorker(
            base.operations, plan, base.connection, clock=lambda: 0, max_steps=10
        )
        with self.assertRaisesRegex(MonitorError, "call budget"):
            worker.run(1)
        self.assertEqual(worker.routine_notices[0].kind, "before_drive")
        self.assertEqual(worker.packet_count, 0)
        self.assertIsNone(worker.operations.channel)

    def test_phase5_active_stop_fault_notifies_then_continues_and_disconnects_flag1(
        self,
    ):
        base, backend = authored_worker(p5=True)
        active = Phase5ActiveEvent(b"\x02\x01\x02", b"\x02\x01\x02", active_type=1)
        original = backend.invoke

        def invoke(operation, fields, *, deadline, cancelled):
            result = original(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "read_messages" and backend.request != b"\x10\x01":
                payload = (
                    b"\x7f\x31\x31"
                    if backend.request[0] == 0x31
                    else b"\x62\x12\x34\xaa\xbb"
                )
                return J2534Result(
                    count=1,
                    messages=(
                        NativeMessage(6, 0, 0, 0, 0, b"\x00\x00\x07\xe8" + payload),
                    ),
                )
            return result

        backend.invoke = invoke
        worker = NormalPollingWorker(
            base.operations, base.plan, base.connection, active=active, clock=lambda: 0
        )
        with patch.object(
            worker.controller, "disconnect", wraps=worker.controller.disconnect
        ) as disconnected:
            self.assertEqual(worker.run(1).packets[0].payload, b"\xaa\xbb")
        self.assertEqual(worker.notifications[0].code, 0xE0000506)
        self.assertEqual(worker.notifications[0].parameter, 0x31)
        self.assertTrue(worker.stop_fault)
        self.assertEqual(disconnected.call_args.args[0], 1)
        self.assertEqual(worker.end_results, [(0, 0x90020321)])

    def test_mid_open_cancellation_restores_exact_lower_guards(self):
        stop = False
        worker, backend = authored_worker(cancelled=lambda: stop)
        original = backend.invoke
        guard = worker.operations.cancelled
        worker.operations.defer_cancel_cleanup = True

        def invoke(operation, fields, *, deadline, cancelled):
            nonlocal stop
            result = original(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "connect":
                stop = True
            return result

        backend.invoke = invoke
        with self.assertRaises(InterruptedError):
            worker.run(1)
        self.assertEqual([name for name, _ in backend.calls], ["connect", "disconnect"])
        self.assertIs(worker.operations.cancelled, guard)
        self.assertTrue(worker.operations.defer_cancel_cleanup)

    def test_foreign_channel_between_construction_and_run_is_preserved(self):
        worker, backend = authored_worker()
        worker.operations.channel = 999
        with self.assertRaisesRegex(MonitorError, "fresh owned"):
            worker.run(1)
        self.assertEqual(worker.operations.channel, 999)
        self.assertEqual(backend.calls, [])

    def test_broken_host_clock_still_releases_own_channel(self):
        worker, _ = authored_worker()
        worker.start()
        worker.clock = lambda: float("nan")
        with self.assertRaisesRegex(MonitorError, "clock"):
            worker.close()
        self.assertIsNone(worker.operations.channel)

    def test_encoded_iso_and_can22_ids_are_not_physical_target(self):
        for bus in (0x11, 0x22):
            with self.subTest(bus=bus):
                worker, backend = authored_worker()
                operations = worker.operations
                profile = operations.profile
                if bus == 0x11:
                    profile, driver = authored_iso_profile()
                else:
                    driver = operations.driver
                management = profile.catalog.management
                protocol = bytearray(management.sections[13].payload)
                protocol[24] = bus
                profile.catalog.management = replace(
                    management,
                    sections={
                        **management.sections,
                        13: replace(management.sections[13], payload=bytes(protocol)),
                    },
                )
                transport = get_comm_frame(
                    profile, b"\x01\x0c", bus_id=bus, driver=driver
                )
                selected = NativeFrameOperations(
                    profile,
                    transport,
                    backend,
                    native_build=18,
                    bus_id=bus,
                    driver=driver,
                    device_kind=8,
                    clock=lambda: 0,
                )
                connection = selected_p4_connection(
                    profile,
                    bus_id=bus,
                    diagnostic_mode=bytes(16),
                    controller_category_flags=4,
                )
                assert isinstance(worker.plan, SelectedP4Monitor)
                commands = p4_setup_commands(
                    worker.plan.packing,
                    interface_id=connection.address.request_id,
                    buffer_468=profile.category,
                    total_length=2,
                    standard_values=(),
                    attribute_2_23=False,
                )
                plan = replace(
                    worker.plan,
                    definitions=replace(
                        worker.plan.definitions,
                        source_identity=monitor_source_identity(profile, ""),
                    ),
                    commands=commands,
                )
                bound = NormalPollingWorker(selected, plan, connection, clock=lambda: 0)
                self.assertIs(bound.operations, selected)
                self.assertNotEqual(connection.address.request_id, transport.address)
                bad = replace(
                    connection, address=replace(connection.address, request_id=123)
                )
                with self.assertRaisesRegex(MonitorError, "connection differs"):
                    NormalPollingWorker(selected, plan, bad)

    def test_step_states_and_no_stop_pdu(self):
        worker, backend = authored_worker()
        self.assertEqual(worker.start(), OK)
        for state in ("send", "receive", "select"):
            self.assertEqual(worker.step(), OK)
            self.assertEqual(worker.state, state)
        writes = len(backend.calls)
        self.assertEqual(worker.stop(), OK)
        self.assertEqual(len(backend.calls), writes)
        worker.close()
        worker.close()


class RetainedNormalWorkerTests(unittest.TestCase):
    def communication(self, worker):
        controller = NativeFrameController(worker.operations)
        communication = NativeCommunication(
            worker.operations.profile,
            controller,
            "selected-ecu",
            bus_id=worker.operations.bus_id,
            source_build=worker.operations.native_build,
            clock=lambda: 0,
        )
        communication._context_first_request = b"\x10\x01"
        communication._shared_controller = True
        return communication

    def retained_worker(self, base, communication, **kwargs):
        return selected_normal_poll_worker(
            base.operations,
            base.plan,
            base.connection,
            communication=communication,
            clock=lambda: 0,
            ticks=lambda: 1234,
            **kwargs,
        )

    def test_fresh_worker_keeps_enabled_stmin_setup_side_effect_free(self):
        base, backend = authored_worker(p5=True)
        management = base.operations.profile.catalog.management
        section = management.sections[14]
        row = bytearray(section.payload)
        row[26] = 1
        struct.pack_into("<H", row, 20, 0x55)
        management.sections[14] = replace(section, payload=bytes(row))

        worker = selected_normal_poll_worker(
            base.operations,
            base.plan,
            base.connection,
            clock=lambda: 0,
            ticks=lambda: 1234,
        )
        assert isinstance(worker, NormalPollingWorker)
        self.assertEqual(worker.start(), OK)
        self.assertFalse(
            any(
                name == "ioctl"
                and fields.get("ioctl_id") == 2
                and fields.get("input")
                and fields["input"][0].parameter == 0x23
                for name, fields in backend.calls
            )
        )
        self.assertEqual(worker.stop(), OK)
        self.assertEqual(worker.close(), 0)
        self.assertFalse(
            any(
                name == "ioctl"
                and fields.get("ioctl_id") == 2
                and fields.get("input")
                and fields["input"][0].parameter == 0x23
                for name, fields in backend.calls
            )
        )

    def test_retained_cold_start_opens_on_first_actual_send(self):
        base, backend = authored_worker(p5=True)
        communication = self.communication(base)
        worker = self.retained_worker(base, communication)
        assert isinstance(worker, NormalPollingWorker)
        disconnect_flags = []
        controller = communication.operations
        assert isinstance(controller, NativeFrameController)
        original_disconnect = controller.disconnect

        def disconnect(flag=0, *, deadline=None):
            disconnect_flags.append(flag)
            return original_disconnect(flag, deadline=deadline)

        controller.disconnect = disconnect
        self.assertIs(worker.communication, communication)
        self.assertIs(worker.controller, communication.operations)
        self.assertEqual(worker.start(), OK)
        self.assertEqual(backend.calls, [])
        self.assertEqual(worker.step(), OK)  # Select the native event request.
        self.assertEqual(backend.calls, [])
        self.assertEqual(worker.step(), OK)  # First real SendProc performs lazy open.
        self.assertIn("connect", [name for name, _ in backend.calls])
        self.assertIn("write_messages", [name for name, _ in backend.calls])
        self.assertFalse(
            any(
                name == "ioctl"
                and fields.get("ioctl_id") == 1
                and fields.get("channel_id") is None
                for name, fields in backend.calls
            )
        )
        self.assertEqual(worker.stop(), OK)
        worker.stop_fault = True
        self.assertEqual(worker.close(), 0)
        self.assertEqual(disconnect_flags, [1])

    def test_retained_open_channel_applies_and_restores_native_temp_config(self):
        base, backend = authored_worker(p5=True)
        management = base.operations.profile.catalog.management
        section = management.sections[14]
        row = bytearray(section.payload)
        row[26] = 1
        struct.pack_into("<H", row, 20, 0x55)
        management.sections[14] = replace(section, payload=bytes(row))
        original = backend.invoke

        def invoke(operation, fields, *, deadline, cancelled):
            result = original(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "ioctl" and fields.get("ioctl_id") == 1:
                return replace(result, configs=(NativeConfig(0x23, 0x1234),))
            return result

        backend.invoke = invoke
        self.assertEqual(base.operations.open(deadline=100), 0)
        communication = self.communication(base)
        worker = self.retained_worker(base, communication)
        assert isinstance(worker, NormalPollingWorker)
        self.assertEqual(worker.start(), OK)
        self.assertEqual(worker.stop(), OK)
        self.assertEqual(worker.close(), 0)
        calls = backend.calls
        configs = [
            fields["input"][0]
            for name, fields in calls
            if name == "ioctl"
            and fields.get("ioctl_id") == 2
            and fields["input"][0].parameter == 0x23
        ]
        self.assertEqual(
            [(item.parameter, item.value) for item in configs],
            [(0x23, 0x55), (0x23, 0x1234)],
        )
        self.assertEqual(
            sum(
                name == "ioctl" and fields.get("ioctl_id") == 1
                for name, fields in calls
            ),
            1,
        )
        assert isinstance(communication.operations, NativeFrameController)
        self.assertIsNone(communication.operations.operations.channel)

    def test_retained_closed_initialized_stmin_uses_native_handle_zero(self):
        base, backend = authored_worker(p5=True)
        management = base.operations.profile.catalog.management
        section = management.sections[14]
        row = bytearray(section.payload)
        row[26] = 1
        struct.pack_into("<H", row, 20, 0x55)
        management.sections[14] = replace(section, payload=bytes(row))
        original = backend.invoke

        def invoke(operation, fields, *, deadline, cancelled):
            result = original(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "ioctl" and fields.get("ioctl_id") == 1:
                return replace(result, configs=(NativeConfig(0x23, 0x1234),))
            return result

        backend.invoke = invoke
        self.assertEqual(base.operations.open(deadline=100), 0)
        self.assertEqual(base.operations.close(deadline=100), 0)
        self.assertIsNone(base.operations.channel)
        backend.calls.clear()

        communication = self.communication(base)
        worker = self.retained_worker(base, communication)
        assert isinstance(worker, NormalPollingWorker)
        self.assertEqual(worker.start(), OK)
        self.assertEqual(worker.stop(), OK)
        self.assertEqual(worker.close(), 0)
        stmin = [
            (fields["channel_id"], fields["ioctl_id"], fields["input"][0].value)
            for name, fields in backend.calls
            if name == "ioctl" and fields.get("ioctl_id") in (1, 2) and fields["input"]
        ]
        self.assertEqual(stmin, [(0, 1, 0), (0, 2, 0x55), (0, 2, 0x1234)])

    def test_retained_channel_change_and_failed_context_reject_before_io(self):
        base, backend = authored_worker(p5=True)
        communication = self.communication(base)
        worker = self.retained_worker(base, communication)
        base.operations.adopt_channel(99, owned=False)
        with self.assertRaisesRegex(MonitorError, "changed"):
            worker.start()
        self.assertEqual(backend.calls, [])

        fresh, second_backend = authored_worker(p5=True)
        failed = self.communication(fresh)
        assert isinstance(failed.operations, NativeFrameController)
        failed.operations._context_failed = True
        with self.assertRaisesRegex(MonitorError, "context differs"):
            self.retained_worker(fresh, failed)
        self.assertEqual(second_backend.calls, [])

        poisoned, poisoned_backend = authored_worker(p5=True)
        poisoned_communication = self.communication(poisoned)
        poisoned.operations.poisoned = True
        with self.assertRaisesRegex(MonitorError, "context differs"):
            self.retained_worker(poisoned, poisoned_communication)
        self.assertEqual(poisoned_backend.calls, [])

        p4, p4_backend = authored_worker()
        variable_operations, targets, _ = authored_multi()
        self.assertIsInstance(variable_operations, NativeMultiMonOperations)
        with self.assertRaisesRegex(MonitorError, "only selected P4/P5"):
            selected_normal_poll_worker(
                p4.operations,
                targets[0].plan,
                p4.connection,
                communication=self.communication(p4),
            )
        self.assertEqual(p4_backend.calls, [])

    def test_retained_cancellation_and_poison_use_resource_cleanup_only(self):
        base, backend = authored_worker(p5=True)
        self.assertEqual(base.operations.open(deadline=100), 0)
        backend.calls.clear()
        communication = self.communication(base)
        cancelled = [False]
        worker = self.retained_worker(
            base, communication, cancelled=lambda: cancelled[0]
        )
        assert isinstance(worker, NormalPollingWorker)
        self.assertEqual(worker.start(), OK)
        cancelled[0] = True
        with self.assertRaises(RecorderCancelled):
            worker.step()
        self.assertEqual(worker.stop(), OK)
        self.assertEqual(worker.close(), 0)
        self.assertIn("disconnect", [name for name, _ in backend.calls])

        poisoned, poisoned_backend = authored_worker(p5=True)
        poisoned_communication = self.communication(poisoned)
        self.assertEqual(poisoned.operations.open(deadline=100), 0)
        poisoned_worker = self.retained_worker(poisoned, poisoned_communication)
        assert isinstance(poisoned_worker, NormalPollingWorker)
        self.assertEqual(poisoned_worker.start(), OK)
        poisoned.operations.poisoned = True
        self.assertEqual(poisoned_worker.stop(), OK)
        before_close = len(poisoned_backend.calls)
        self.assertEqual(poisoned_worker.close(), 0)
        cleanup = poisoned_backend.calls[before_close:]
        self.assertFalse(
            any(
                name == "ioctl" and fields.get("ioctl_id") in (1, 2)
                for name, fields in cleanup
            )
        )
        self.assertIn("disconnect", [name for name, _ in cleanup])


if __name__ == "__main__":
    unittest.main()
