"""Literal original DataListIF direct-worker communication event vectors."""

import struct
import unittest
from collections.abc import Mapping
from dataclasses import replace
from typing import Any, Literal, cast

from scripts.data_monitor import MonitorError, SelectedMonitorSession
from scripts.diagnostic_db import Database, Section
from scripts.drive_recorder import RecorderCancelled
from scripts.frame_transport import (
    DriverProperties,
    J2534Result,
    NativeConfig,
    NativeFrameOperations,
    NativeMessage,
    get_comm_frame,
)
from scripts.monitor_instruments import (
    DstiOscDriver,
    OscConfiguration,
    OscilloscopeRuntime,
    OscRead,
)
from scripts.monitor_j2534 import (
    INVALID,
    OK,
    ActiveMonitorEvent,
    CenturyJ2534Worker,
    CenturyMonitorEvent,
    CenturyNativeFrameOperations,
    CenturySystem,
    DataMonitorEvent,
    DirectJ2534Worker,
    DkKwpJ2534Worker,
    MonitorSystemEvent,
    NativeMonitorSourceFault,
    NativePacketPrimitives,
    PacketMonitorEvent,
    century_frame_plan,
    selected_packet_frame_cache,
)
from scripts.monitor_support import PacketReceive
from scripts.native_communication import NativeCommunication, NativeFrameController
from scripts.profiles import ProtocolProfile, VehicleCatalog, VehicleProfile
from scripts.toyota_session import Limits


def authored_operations(*, build: Literal[12, 18] = 18, failure=0, cancellation=None):
    category = bytearray(76)
    struct.pack_into("<H", category, 68, 42)
    category[72] = 1
    prot = bytearray(24 if build == 12 else 28)
    struct.pack_into("<6H", prot, 0, 42, 1, 0x33, 0x7DF, 0x7E0, 0xAB)
    prot[22 if build == 12 else 24] = 0x12
    can = bytearray(28)
    struct.pack_into("<IIHHH", can, 0, 0x1234, 500000, 1, 0, 20)
    struct.pack_into("<H", can, 16 if build == 12 else 18, 1)
    directory = struct.pack("<IH", 0, 2) + struct.pack("<IH", 2, 1)
    functions = struct.pack("<8H", 42, 0x67, 0, 1, 0, 0, 0, 0) + struct.pack(
        "<8H", 42, 0x7F, 0, 2, 0, 0, 0, 0
    )
    frames = struct.pack("<8H", 1, 1, 0, 0, 2, 2, 0, 0)
    sections = {
        slot: Section(slot, 0, count, False, payload)
        for slot, count, payload in (
            (0, 2, directory + b"\x10\x01\x3e"),
            (13, 1, bytes(prot)),
            (14, 1, bytes(can)),
            (16, 1, bytes(category)),
            (17, 2, frames),
            (18, 2, functions),
        )
    }
    management = Database(
        1, 0x0100030C if build == 12 else 0x0100032F, "authored-management", sections
    )
    catalog = object.__new__(VehicleCatalog)
    catalog.management = management
    profile = VehicleProfile(
        catalog, bytes(category), Database(2, management.version, "authored-ecu", {})
    )
    driver = DriverProperties(0, b"04.04", "authored-driver-observation")
    plan = get_comm_frame(profile, b"\x01\x0c", bus_id=0x12, driver=driver)

    class PrimitiveObservations:
        def __init__(self):
            self.calls = []
            self.request = b""

        def invoke(
            self, operation: str, fields: Mapping[str, object], *, deadline, cancelled
        ):
            self.calls.append((operation, fields))
            if operation == "connect":
                return J2534Result(handle=7)
            if operation == "start_message_filter":
                return J2534Result(handle=100 + len(self.calls))
            if operation == "write_messages":
                message = cast(tuple[NativeMessage, ...], fields["messages"])[0]
                self.request = message.data[4:]
                return J2534Result(count=1)
            if operation == "read_messages":
                if failure and self.request != b"\x10\x01":
                    return J2534Result(code=failure)
                payload = (
                    b"\x50\x01" if self.request == b"\x10\x01" else b"\x41\x0c\xaa\xbb"
                )
                return J2534Result(
                    count=1,
                    messages=(
                        NativeMessage(6, 0, 0, 1234, 0, b"\x00\x00\x07\xe8" + payload),
                    ),
                )
            return J2534Result()

    observations = PrimitiveObservations()
    operations = NativeFrameOperations(
        profile,
        plan,
        observations,
        native_build=build,
        bus_id=0x12,
        driver=driver,
        device_kind=8,
        clock=lambda: 10,
        cancelled=cancellation,
    )
    return operations, observations


def authored_iso_profile(*, build: Literal[12, 18] = 18):
    operations, _ = authored_operations(build=build)
    profile = operations.profile
    management = profile.catalog.management
    protocol = bytearray(management.sections[13].payload)
    protocol[22 if build == 12 else 24] = 0x31
    iso = bytearray(56)
    struct.pack_into("<IHH", iso, 0, 10400, 1, 1)
    functions = management.sections[18].payload.replace(b"\x67\x00", b"\x68\x00")
    profile.catalog.management = replace(
        management,
        sections={
            **management.sections,
            13: replace(management.sections[13], payload=bytes(protocol)),
            15: Section(15, 0, 1, False, bytes(iso)),
            18: replace(management.sections[18], payload=functions),
        },
    )
    return profile, operations.driver


def authored_century_profiles():
    first, driver = authored_iso_profile()
    database = first.catalog.management
    protocol0 = bytearray(database.sections[13].payload)
    protocol0[24] = 0x11
    struct.pack_into("<H", protocol0, 8, 0x10)
    protocol1 = bytearray(protocol0)
    struct.pack_into("<H", protocol1, 0, 43)
    struct.pack_into("<H", protocol1, 8, 0x18)
    category = bytearray(first.category_record)
    struct.pack_into("<H", category, 68, 43)
    functions = bytearray(database.sections[18].payload)
    for offset in range(0, len(functions), 16):
        struct.pack_into("<H", functions, offset, 43)
    first.catalog.management = replace(
        database,
        sections={
            **database.sections,
            13: replace(
                database.sections[13], count=2, payload=bytes(protocol0 + protocol1)
            ),
            16: replace(
                database.sections[16],
                count=2,
                payload=first.category_record + bytes(category),
            ),
            18: replace(
                database.sections[18],
                count=4,
                payload=database.sections[18].payload + bytes(functions),
            ),
        },
    )
    second = VehicleProfile(
        first.catalog,
        bytes(category),
        Database(2, database.version, "authored-ecu43", {}),
    )
    return (first, second), driver


class NativeEventTests(unittest.TestCase):
    def test_century_frame_plan_needs_only_selected_management_context(self):
        for build in (12, 18):
            with self.subTest(build=build):
                profile, driver = authored_iso_profile(
                    build=cast(Literal[12, 18], build)
                )
                protocol = ProtocolProfile(
                    profile.catalog,
                    profile.category_record,
                    profile.exception_ids,
                    profile.vehicle_name_key,
                )
                self.assertFalse(hasattr(protocol, "database"))
                self.assertEqual(
                    century_frame_plan(protocol, bus_id=0x31, driver=driver),
                    century_frame_plan(profile, bus_id=0x31, driver=driver),
                )

    def test_base_active_only_constructor_waits_for_registration_before_io(self):
        operations, observed = authored_operations()
        worker = DirectJ2534Worker(
            operations,
            None,
            request_id=1,
            response_id=0,
            default_source=0x7E8,
            clock=lambda: 10,
        )
        self.assertEqual(worker.events, (None, None, None))
        self.assertEqual(worker.state, "configured")
        self.assertEqual(observed.calls, [])
        invoke = observed.invoke

        def exchange(operation, fields, *, deadline, cancelled):
            result = invoke(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "read_messages" and observed.request[:1] == b"\x30":
                payload = b"\x70" if observed.request == b"\x30" else b"\x70\x01"
                return J2534Result(
                    count=1,
                    messages=(
                        NativeMessage(6, 0, 0, 1234, 0, b"\x00\x00\x07\xe8" + payload),
                    ),
                )
            return result

        observed.invoke = exchange
        active = ActiveMonitorEvent(b"\x0c\x01")
        worker.events = (active, None, None)
        worker.start()
        worker.step()
        worker.step()
        worker.step()
        self.assertEqual(active.item.status, 4)
        worker.stop()
        worker.close()
        writes = [
            fields["messages"][0].data[4:]
            for op, fields in observed.calls
            if op == "write_messages"
        ]
        self.assertEqual(writes, [b"\x10\x01", b"\x30\x0c\x01", b"\x30"])

    def test_packet_errors_use_reply_nrc_or_selected_slot_context(self):
        from scripts.monitor_poll import Phase4PacketEvent

        cases = (
            (0, b"\xe2\x01\xaa", "reply", 0xE0000104),
            (2, b"\x70\x01\x02", "reply", 0xE00001CC),
            (0, b"\x7f\xa2\x22", "reply", 0xE000010A),
            (2, b"\x7f\x30\x22", "reply", 0xE000010C),
            (0, b"", "receive_error", 0xE0000106),
            (0, b"", "send_error", 0xE0000106),
        )
        for build in (12, 18):
            for slot, payload, fault, expected in cases:
                with self.subTest(build=build, slot=slot, fault=fault, payload=payload):
                    operations, observed = authored_operations(
                        build=cast(Literal[12, 18], build)
                    )
                    invoke = observed.invoke

                    def exchange(
                        operation,
                        fields,
                        *,
                        deadline,
                        cancelled,
                        invoke=invoke,
                        observed=observed,
                        fault=fault,
                        payload=payload,
                    ):
                        if (
                            operation == "write_messages"
                            and fault == "send_error"
                            and not fields["messages"][0].data.endswith(b"\x10\x01")
                        ):
                            return J2534Result(code=7)
                        result = invoke(
                            operation, fields, deadline=deadline, cancelled=cancelled
                        )
                        if (
                            operation != "read_messages"
                            or observed.request == b"\x10\x01"
                        ):
                            return result
                        if fault == "receive_error":
                            return J2534Result(code=7)
                        return J2534Result(
                            count=1,
                            messages=(
                                NativeMessage(
                                    6, 0, 0, 1234, 0, b"\x00\x00\x07\xe8" + payload
                                ),
                            ),
                        )

                    observed.invoke = exchange
                    active = ActiveMonitorEvent(b"\x0c\x01")
                    disabled = []
                    if slot == 2:
                        active.set_status(4)
                    worker = DirectJ2534Worker(
                        operations,
                        Phase4PacketEvent(((1, b"\x0c"),), ((0, 2),), timeout=3000),
                        request_id=1,
                        response_id=0,
                        default_source=0x7E8,
                        active=active,
                        attempts=1,
                        clock=lambda: 10,
                        disable_packet_ecu=disabled.append,
                    )
                    worker.start()
                    worker.step()
                    sent = worker.step()
                    result = sent if fault == "send_error" else worker.step()
                    self.assertEqual(result, expected)
                    self.assertEqual(worker.notifications[-1].code, expected)
                    self.assertEqual(worker.slot, slot)
                    self.assertEqual(disabled, [] if expected == 0xE00001CC else [42])
                    worker.close()

    def test_successful_foreign_source_resets_retry_count_before_filter(self):
        for build in (12, 18):
            for packet in (False, True):
                with self.subTest(build=build, packet=packet):
                    operations, observed = authored_operations(
                        build=cast(Literal[12, 18], build)
                    )
                    invoke = observed.invoke
                    outcomes = iter((9, 9, 0x7E9, 9, 0x7E8))

                    def exchange(
                        operation,
                        fields,
                        *,
                        deadline,
                        cancelled,
                        invoke=invoke,
                        observed=observed,
                        outcomes=outcomes,
                    ):
                        result = invoke(
                            operation, fields, deadline=deadline, cancelled=cancelled
                        )
                        if (
                            operation != "read_messages"
                            or observed.request == b"\x10\x01"
                        ):
                            return result
                        if observed.request == b"\xa3":
                            return J2534Result(code=9)
                        source = (
                            0x7E8 if observed.request[:1] == b"\xa2" else next(outcomes)
                        )
                        if source == 9:
                            return J2534Result(code=9)
                        payload = (
                            b"\xe1" + observed.request[1:]
                            if observed.request[:1] == b"\xa1"
                            else b"\xe2\x01\xaa\xbb"
                            if observed.request[:1] == b"\xa2"
                            else b"\x41\x0c\xaa\xbb"
                        )
                        return J2534Result(
                            count=1,
                            messages=(
                                NativeMessage(
                                    6,
                                    0,
                                    0,
                                    1234,
                                    0,
                                    source.to_bytes(4, "big") + payload,
                                ),
                            ),
                        )

                    observed.invoke = exchange
                    event = (
                        PacketMonitorEvent(1, b"\x0c", ((0, 2),), timeout=3000)
                        if packet
                        else DataMonitorEvent(0, b"\x0c", b"\x02", 2)
                    )
                    worker = DirectJ2534Worker(
                        operations,
                        event,
                        request_id=1,
                        response_id=0,
                        default_source=0x7E8,
                        attempts=3,
                        clock=lambda: 10,
                    )
                    capture = worker.run(1)
                    self.assertEqual(capture.packets[0].payload, b"\xaa\xbb")
                    self.assertEqual(worker.notifications, [])

    def test_native_base_class_with_packet_event_keeps_base_wire_and_stop(self):
        for build in (12, 18):
            with self.subTest(build=build):
                operations, observed = authored_operations(
                    build=cast(Literal[12, 18], build)
                )
                invoke = observed.invoke

                def exchange(
                    operation,
                    fields,
                    *,
                    deadline,
                    cancelled,
                    invoke=invoke,
                    observed=observed,
                ):
                    result = invoke(
                        operation, fields, deadline=deadline, cancelled=cancelled
                    )
                    if operation != "read_messages" or observed.request == b"\x10\x01":
                        return result
                    payload = (
                        b"\xe1" + observed.request[1:]
                        if observed.request[:1] == b"\xa1"
                        else b"\xe2\x01\xaa\xbb"
                    )
                    return J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(
                                6, 0, 0, 1234, 0, b"\x00\x00\x07\xe8" + payload
                            ),
                        ),
                    )

                observed.invoke = exchange
                event = PacketMonitorEvent(1, b"\x0c", ((0, 2),), timeout=3000)
                worker = DirectJ2534Worker(
                    operations,
                    event,
                    request_id=1,
                    response_id=0,
                    default_source=0x7E8,
                    native_worker_class="base",
                    clock=lambda: 10,
                    ticks=lambda: 9000,
                )
                capture = worker.run(1)
                self.assertEqual(capture.packets[0].payload, b"\xaa\xbb")
                self.assertEqual(capture.packets[0].timestamp_ms, 9000)
                writes = [
                    fields["messages"][0].data[4:]
                    for op, fields in observed.calls
                    if op == "write_messages"
                ]
                self.assertEqual(writes, [b"\x10\x01", b"\xa1\x01\x0c", b"\xa2\x01"])
                configs = [
                    config
                    for op, fields in observed.calls
                    if op == "ioctl" and fields["ioctl_id"] == 2
                    for config in fields["input"]
                ]
                self.assertFalse(
                    any(
                        config.parameter in (0x10400, 0x10500, 0x10501)
                        for config in configs
                    )
                )
                self.assertEqual(observed.calls[-1][0], "disconnect")

    def test_combined_packet_reads_once_before_source_filter_and_reports_osc_status(
        self,
    ):
        for osc_status in (0, 0x90020102):
            with self.subTest(osc_status=osc_status):
                operations, observed = authored_operations()
                calls = []

                def exchange(call, deadline, calls=calls, osc_status=osc_status):
                    calls.append(call)
                    if call.export == "DstiOscReadBuffer":
                        return OscRead(osc_status, b"\xaa\xbb\xcc\xdd", 1234)
                    return 0

                instrument = OscilloscopeRuntime(
                    DstiOscDriver(
                        exchange, module_loaded=True, exports=DstiOscDriver.EXPORTS
                    ),
                    OscConfiguration(),
                    clock=lambda: 10,
                )
                event = PacketMonitorEvent(1, b"\x0c", ((0, 2),), timeout=3000)
                worker = DirectJ2534Worker(
                    operations,
                    event,
                    request_id=1,
                    response_id=0,
                    default_source=0x7E9,
                    oscilloscope=instrument,
                    clock=lambda: 10,
                )
                worker.start()
                worker.step()
                worker.step()
                self.assertEqual(worker.step(), osc_status or OK)
                self.assertEqual(
                    [
                        call.maximum
                        for call in calls
                        if call.export == "DstiOscReadBuffer"
                    ],
                    [0],
                )
                self.assertEqual(instrument.read_count, 1)
                self.assertEqual(event.item.status, 8)
                self.assertEqual(instrument.packets, [])
                if osc_status:
                    self.assertEqual(worker.notifications[-1].code, 0xE2001003)
                invoke = observed.invoke
                observed.invoke = (
                    lambda operation, fields, *, deadline, cancelled, invoke=invoke: (
                        J2534Result(code=9)
                        if operation == "read_messages"
                        else invoke(
                            operation, fields, deadline=deadline, cancelled=cancelled
                        )
                    )
                )
                worker.stop()

    def test_packet_cache_uses_concrete_selected_channel_both_builds(self):
        for build in (12, 18):
            with self.subTest(build=build):
                operations, observed = authored_operations(
                    build=cast(Literal[12, 18], build)
                )
                invoke = observed.invoke
                replies = iter((b"\xe2\x11\xaa", b"\xe2\x11\xbb"))

                def exchange(
                    operation,
                    fields,
                    *,
                    deadline,
                    cancelled,
                    invoke=invoke,
                    observed=observed,
                    replies=replies,
                ):
                    result = invoke(
                        operation, fields, deadline=deadline, cancelled=cancelled
                    )
                    if operation == "write_messages" and observed.request == b"\xa3":
                        return J2534Result(code=7)
                    if operation != "read_messages" or observed.request == b"\x10\x01":
                        return result
                    if observed.request == b"\xa3":
                        return J2534Result(code=9)
                    return J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(
                                6, 0, 0, 1234, 0, b"\x00\x00\x07\xe8" + next(replies)
                            ),
                        ),
                    )

                observed.invoke = exchange
                communication = NativeCommunication(
                    operations.profile,
                    NativeFrameController(operations),
                    "engine",
                    bus_id=operations.bus_id,
                    source_build=build,
                    clock=lambda: 10,
                )
                session = SelectedMonitorSession(operations.profile, source_build=build)
                foreign = SelectedMonitorSession(
                    operations.profile, source_build=12 if build == 18 else 18
                )
                with self.assertRaisesRegex(
                    MonitorError, "selected application/vehicle"
                ):
                    selected_packet_frame_cache(communication, monitor_session=foreign)
                self.assertEqual(observed.calls, [])
                cache = selected_packet_frame_cache(
                    communication, monitor_session=session
                )
                self.assertEqual(
                    (cache.send_timer, cache.receive_timer, cache.retries),
                    (1000, 200, 2),
                )
                original_cancelled = operations.cancelled
                frames = cache.get_packet_frame(
                    42, operations.bus_id, source_identity=cache.identity
                )
                self.assertEqual(
                    [(frame.sequence, frame.payload) for frame in frames],
                    [(0x11, b"\xaa")],
                )
                self.assertIs(operations.cancelled, original_cancelled)
                self.assertEqual(cache.disabled, [42])
                self.assertEqual(session.disabled_packet_ecus, (42,))
                writes = [
                    fields["messages"][0].data[4:]
                    for op, fields in observed.calls
                    if op == "write_messages"
                ]
                self.assertEqual(writes, [b"\x10\x01", b"\xa2\x04", b"\xa3"])
                self.assertEqual(communication.calls, 7)
                prior_calls = len(observed.calls)
                self.assertIs(
                    cache.get_packet_frame(
                        42, operations.bus_id, source_identity=cache.identity
                    ),
                    frames,
                )
                self.assertEqual(len(observed.calls), prior_calls)
                self.assertIsNotNone(operations.channel)
                communication.close()
                self.assertIsNone(operations.channel)

    def test_packet_adapter_rejects_foreign_context_and_bounds_before_io(self):
        operations, observed = authored_operations()
        communication = NativeCommunication(
            operations.profile,
            NativeFrameController(operations),
            "engine",
            bus_id=operations.bus_id,
            clock=lambda: 10,
        )
        primitive = NativePacketPrimitives(communication)
        for receive in (
            PacketReceive(43, 8, 200),
            PacketReceive(42, 256, 200),
            PacketReceive(42, 8, -1),
            PacketReceive(42, 8, 200, parameter5=256),
        ):
            with self.assertRaises(ValueError):
                primitive.receive(receive)
        with self.assertRaises(ValueError):
            primitive.send(43, b"\xa2\x04", 1000, 0x12, 0, 0)
        with self.assertRaises(ValueError):
            primitive.send(42, b"\xa2\x04", 1000, 0x13, 0, 0)
        self.assertEqual(observed.calls, [])

    def test_packet_adapter_restores_guard_after_backend_fault(self):
        operations, observed = authored_operations()
        invoke = observed.invoke

        def exchange(operation, fields, *, deadline, cancelled):
            if operation == "write_messages" and fields["messages"][0].data.endswith(
                b"\xa2\x04"
            ):
                raise RuntimeError("unconfirmed packet write")
            return invoke(operation, fields, deadline=deadline, cancelled=cancelled)

        observed.invoke = exchange
        communication = NativeCommunication(
            operations.profile,
            NativeFrameController(operations),
            "engine",
            bus_id=operations.bus_id,
            clock=lambda: 10,
        )
        original_cancelled = operations.cancelled
        with self.assertRaisesRegex(RuntimeError, "unconfirmed packet write"):
            selected_packet_frame_cache(communication).get_packet_frame(
                42,
                operations.bus_id,
                source_identity=communication.cache.identity,
            )
        self.assertIs(operations.cancelled, original_cancelled)
        self.assertTrue(operations.poisoned)
        self.assertFalse(
            any(
                op == "write_messages" and fields["messages"][0].data.endswith(b"\xa3")
                for op, fields in observed.calls
            )
        )

    def test_packet_adapter_composes_cancel_and_enforces_shared_budget(self):
        operations, observed = authored_operations()
        stopped = [False]
        communication = NativeCommunication(
            operations.profile,
            NativeFrameController(operations),
            "engine",
            bus_id=operations.bus_id,
            clock=lambda: 10,
            cancelled=lambda: stopped[0],
            limits=Limits(exchanges=1),
        )
        primitive = NativePacketPrimitives(communication)
        original_cancelled = operations.cancelled
        stopped[0] = True
        with self.assertRaisesRegex(Exception, "cancelled"):
            primitive.send(42, b"\xa3", 1000, 0x12, 0, 0)
        self.assertIs(operations.cancelled, original_cancelled)
        self.assertEqual(observed.calls, [])
        stopped[0] = False
        primitive.interrupt(True)
        with self.assertRaisesRegex(Exception, "budget"):
            primitive.receive(PacketReceive(42, 8, 200))
        self.assertEqual(observed.calls, [])

    def test_combined_start_fault_and_cancel_release_instrument_and_transport(self):
        for cancel in (False, True):
            with self.subTest(cancel=cancel):
                operations, observed = authored_operations()
                calls, stop = [], [False]

                def exchange(call, deadline, cancel=cancel, calls=calls, stop=stop):
                    calls.append(call)
                    if call.export == "DstiOscReadBuffer":
                        return OscRead(0, b"")
                    if call.export == "DstiOscCommand" and call.selector == 2:
                        if cancel:
                            stop[0] = True
                        else:
                            return 0x90020102
                    return 0

                runtime = OscilloscopeRuntime(
                    DstiOscDriver(
                        exchange, module_loaded=True, exports=DstiOscDriver.EXPORTS
                    ),
                    OscConfiguration(),
                    clock=lambda: 10,
                )
                original_cancelled = runtime.cancelled
                worker = DirectJ2534Worker(
                    operations,
                    DataMonitorEvent(0, b"\x0c", b"\x02", 2),
                    request_id=1,
                    response_id=0,
                    default_source=0x7E8,
                    oscilloscope=runtime,
                    clock=lambda: 10,
                    cancelled=lambda stop=stop: stop[0],
                )
                with self.assertRaises(RecorderCancelled if cancel else MonitorError):
                    worker.run(1)
                self.assertEqual(calls[-1].selector, 1)
                self.assertEqual(observed.calls[-1][0], "disconnect")
                self.assertIs(runtime.cancelled, original_cancelled)
                self.assertIsNone(operations.channel)
                if not cancel:
                    self.assertEqual(worker.notifications[0].code, 0xE2001000)
                    self.assertEqual(worker.notifications[0].parameter, 2)

    def test_base_combined_instrument_uses_normal_then_named_drain_and_reverse_capture(
        self,
    ):
        operations, observed = authored_operations()
        calls = []

        def exchange(call, deadline):
            calls.append(call)
            if call.export == "DstiOscReadBuffer":
                return OscRead(0, b"\xaa\xbb\xcc\xdd", 2000)
            return 0

        runtime = OscilloscopeRuntime(
            DstiOscDriver(exchange, module_loaded=True, exports=DstiOscDriver.EXPORTS),
            OscConfiguration(),
            clock=lambda: 10,
        )
        original_clock, original_cancelled = runtime.clock, runtime.cancelled
        worker = DirectJ2534Worker(
            operations,
            DataMonitorEvent(0, b"\x0c", b"\x02", 2),
            request_id=1,
            response_id=0,
            default_source=0x7E8,
            oscilloscope=runtime,
            clock=lambda: 10,
        )
        self.assertEqual(worker.run(1).packets[0].payload, b"\xaa\xbb")
        self.assertEqual(
            runtime.capture().packet_bytes(), b"\x02\x00\x00\x00\xaa\xbb\xcc\xdd"
        )
        self.assertEqual(
            [call.maximum for call in calls if call.export == "DstiOscReadBuffer"],
            [0x1068, 0x1068],
        )
        self.assertEqual(
            [call.selector for call in calls if call.export == "DstiOscCommand"],
            [0, 2, 3, 11, 1],
        )
        self.assertIs(runtime.clock, original_clock)
        self.assertIs(runtime.cancelled, original_cancelled)
        self.assertEqual(observed.calls[-1][0], "disconnect")

    def test_cancel_inside_iso_retry_wait_prevents_second_initialization(self):
        profile, driver = authored_iso_profile()
        database = profile.catalog.management
        iso = bytearray(database.sections[15].payload)
        struct.pack_into("<H", iso, 6, 2)
        profile.catalog.management = replace(
            database,
            sections={
                **database.sections,
                15: replace(database.sections[15], payload=bytes(iso)),
            },
        )
        _, observed = authored_operations()
        parent = observed.invoke
        stop, now, waits = [False], [10.0], []

        def exchange(operation, fields, *, deadline, cancelled):
            result = parent(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "ioctl" and fields["ioctl_id"] == 4:
                return J2534Result(code=7)
            return result

        def wait(seconds):
            waits.append(seconds)
            now[0] += seconds
            stop[0] = True

        observed.invoke = exchange
        operations = NativeFrameOperations(
            profile,
            get_comm_frame(profile, b"\x01\x0c", bus_id=0x31, driver=driver),
            observed,
            native_build=18,
            bus_id=0x31,
            driver=driver,
            device_kind=8,
            clock=lambda: now[0],
            wait=wait,
        )
        original_cancelled = operations.cancelled
        worker = DirectJ2534Worker(
            operations,
            DataMonitorEvent(0, b"\x0c", b"\x02", 2),
            request_id=1,
            response_id=0,
            default_source=0x7E8,
            clock=lambda: now[0],
            cancelled=lambda: stop[0],
        )
        with self.assertRaises(InterruptedError):
            worker.run(1)
        self.assertEqual(len(waits), 1)
        self.assertEqual(
            sum(
                op == "ioctl" and fields["ioctl_id"] == 4
                for op, fields in observed.calls
            ),
            1,
        )
        self.assertEqual(observed.calls[-1][0], "disconnect")
        self.assertIs(operations.cancelled, original_cancelled)
        self.assertFalse(operations.defer_cancel_cleanup)
        self.assertIsNone(operations.channel)

    def test_confirmed_write_deadline_preserves_error_and_sends_active_stop(self):
        operations, observed = authored_operations()
        parent, now = observed.invoke, [10.0]
        operations.clock = lambda: now[0]

        def exchange(operation, fields, *, deadline, cancelled):
            result = parent(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "write_messages" and observed.request == b"\x30\x01":
                now[0] = 41.0
            if operation == "read_messages" and observed.request[:1] == b"\x30":
                return J2534Result(
                    count=1,
                    messages=(NativeMessage(6, 0, 0, 0, 0, b"\x00\x00\x07\xe8\x70"),),
                )
            return result

        observed.invoke = exchange
        worker = DirectJ2534Worker(
            operations,
            DataMonitorEvent(0, b"\x0c", b"\x01", 1),
            request_id=1,
            response_id=0,
            default_source=0x7E8,
            active=ActiveMonitorEvent(b"\x01"),
            clock=lambda: now[0],
        )
        with self.assertRaises(TimeoutError):
            worker.run(1)
        writes = [
            fields["messages"][0].data[4:]
            for op, fields in observed.calls
            if op == "write_messages"
        ]
        self.assertEqual(writes, [b"\x10\x01", b"\x30\x01", b"\x10\x01", b"\x30"])
        self.assertIsNone(worker.cleanup_error)
        self.assertIsNone(operations.channel)
        self.assertFalse(operations.defer_cancel_cleanup)

    def test_cancel_inside_connect_stops_setup_and_restores_both_guards(self):
        operations, observed = authored_operations()
        original_cancelled = operations.cancelled
        parent = observed.invoke
        stop = [False]

        def exchange(operation, fields, *, deadline, cancelled):
            result = parent(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "connect":
                stop[0] = True
            return result

        observed.invoke = exchange
        worker = DirectJ2534Worker(
            operations,
            DataMonitorEvent(0, b"\x0c", b"\x02", 2),
            request_id=1,
            response_id=2,
            default_source=3,
            clock=lambda: 0,
            cancelled=lambda: stop[0],
        )
        with self.assertRaises(InterruptedError):
            worker.run(1)
        self.assertEqual([op for op, _ in observed.calls], ["connect", "disconnect"])
        self.assertIs(operations.cancelled, original_cancelled)
        self.assertFalse(operations.defer_cancel_cleanup)
        self.assertIsNone(operations.channel)

    def test_invalid_acquisition_clock_still_releases_owned_channel(self):
        operations, observed = authored_operations()
        parent = observed.invoke
        now = [0.0]

        def exchange(operation, fields, *, deadline, cancelled):
            result = parent(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "write_messages" and observed.request == b"\x01\x0c":
                now[0] = float("nan")
            return result

        observed.invoke = exchange
        worker = DirectJ2534Worker(
            operations,
            DataMonitorEvent(0, b"\x0c", b"\x02", 2),
            request_id=1,
            response_id=0,
            default_source=0x7E8,
            clock=lambda: now[0],
        )
        with self.assertRaisesRegex(MonitorError, "finite"):
            worker.run(1)
        self.assertEqual(observed.calls[-1][0], "disconnect")
        self.assertIsNone(operations.channel)

    def test_packet_sink_failure_preserves_primary_and_releases(self):
        operations, observed = authored_operations()

        def sink(packet):
            raise OSError("authored sink fault")

        worker = DirectJ2534Worker(
            operations,
            DataMonitorEvent(0, b"\x0c", b"\x02", 2),
            request_id=1,
            response_id=0,
            default_source=0x7E8,
            clock=lambda: 0,
            packet_sink=sink,
        )
        with self.assertRaisesRegex(OSError, "sink fault"):
            worker.run(1)
        self.assertEqual(observed.calls[-1][0], "disconnect")

    def test_native_null_stop_initialization_and_dk_disconnect_difference(self):
        operations, observed = authored_operations()
        parent = observed.invoke

        def reply(operation, fields, *, deadline, cancelled):
            result = parent(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "read_messages" and observed.request == b"\x30":
                return J2534Result(
                    count=1,
                    messages=(NativeMessage(6, 0, 0, 0, 0, b"\x00\x00\x07\xe8\x70"),),
                )
            return result

        observed.invoke = reply
        active = ActiveMonitorEvent(b"\x01")
        active.stop(initialize=True)
        active.skip_end()
        worker = DirectJ2534Worker(
            operations,
            None,
            request_id=1,
            response_id=0,
            default_source=0x7E8,
            active=active,
            clock=lambda: 0,
        )
        worker.start()
        for _ in range(3):
            self.assertEqual(worker.step(), OK)
        self.assertEqual(worker.state, "idle")
        writes = [
            fields["messages"][0].data[4:]
            for op, fields in observed.calls
            if op == "write_messages"
        ]
        self.assertEqual(writes, [b"\x10\x01", b"\x30", b"\x10\x01"])
        worker.close()
        operations, observed = authored_operations()
        worker = DkKwpJ2534Worker(
            operations,
            DataMonitorEvent(0, b"\x0c", b"\x01", 1),
            request_id=1,
            response_id=0,
            default_source=0x7E8,
            active=ActiveMonitorEvent(b"\x01", dk_kwp=True),
            clock=lambda: 0,
        )
        worker.start()
        worker.stop()
        self.assertFalse(any(op == "write_messages" for op, _ in observed.calls))
        self.assertEqual(observed.calls[-1][0], "disconnect")

    def test_cancelled_active_worker_sends_stop_marker_before_disconnect(self):
        operations, observed = authored_operations()
        parent = observed.invoke
        stop = [False]

        def exchange(operation, fields, *, deadline, cancelled):
            result = parent(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "write_messages" and observed.request == b"\x30\x01":
                stop[0] = True
            if operation == "read_messages" and observed.request[:1] == b"\x30":
                return J2534Result(
                    count=1,
                    messages=(NativeMessage(6, 0, 0, 0, 0, b"\x00\x00\x07\xe8\x70"),),
                )
            return result

        observed.invoke = exchange
        worker = DirectJ2534Worker(
            operations,
            DataMonitorEvent(0, b"\x0c", b"\x01", 1),
            request_id=1,
            response_id=0,
            default_source=0x7E8,
            active=ActiveMonitorEvent(b"\x01"),
            clock=lambda: 0,
            cancelled=lambda: stop[0],
        )
        with self.assertRaisesRegex(Exception, "cancelled"):
            worker.run(1)
        writes = [
            fields["messages"][0].data[4:]
            for op, fields in observed.calls
            if op == "write_messages"
        ]
        self.assertEqual(writes, [b"\x10\x01", b"\x30\x01", b"\x30"])
        self.assertIsNone(worker.cleanup_error)
        self.assertEqual(observed.calls[-1][0], "disconnect")

    def test_century_mixed_and_physical_modes_keep_one_physical_channel(self):
        for mixed in (True, False):
            with self.subTest(mixed=mixed):
                profiles, driver = authored_century_profiles()

                class Observed:
                    def __init__(self):
                        self.calls = []
                        self.replies = []

                    def invoke(self, operation, fields, *, deadline, cancelled):
                        self.calls.append((operation, fields))
                        if operation == "connect":
                            return J2534Result(handle=7)
                        if operation == "ioctl" and fields["ioctl_id"] == 5:
                            target = fields["input"].data[1]
                            return J2534Result(
                                messages=(
                                    NativeMessage(
                                        4,
                                        0,
                                        0,
                                        0,
                                        0,
                                        bytes((0x83, 0xF0, target, 0xC1, 8, 8)),
                                    ),
                                )
                            )
                        if operation == "write_messages":
                            data = fields["messages"][0].data
                            pid = data[-1]
                            functional = data[0] & 0xC0 == 0xC0
                            sources = (0x10, 0x18) if functional else (data[1],)
                            self.replies.extend(
                                bytes(
                                    (
                                        0x83,
                                        0xB5 if functional else 0xF0,
                                        source,
                                        0x41,
                                        pid,
                                        source ^ pid,
                                    )
                                )
                                for source in sources
                            )
                            return J2534Result(count=1)
                        if operation == "read_messages":
                            if not self.replies:
                                return J2534Result(code=9)
                            return J2534Result(
                                count=1,
                                messages=(
                                    NativeMessage(4, 0, 0, 1, 0, self.replies.pop(0)),
                                ),
                            )
                        return J2534Result()

                backend = Observed()
                functional = CenturyNativeFrameOperations(
                    profiles[0],
                    century_frame_plan(profiles[0], bus_id=0x11, driver=driver),
                    backend,
                    registered_response_ids=(0x10, 0x18),
                    native_build=18,
                    bus_id=0x11,
                    driver=driver,
                    device_kind=8,
                    clock=lambda: 0,
                )
                systems = []
                for index, (profile, pid) in enumerate(
                    zip(profiles, (13, 14), strict=True)
                ):
                    ids = bytes((12, pid)) if mixed else bytes((pid,))
                    plan = get_comm_frame(
                        profile, bytes((1, pid)), bus_id=0x11, driver=driver
                    )
                    operations = NativeFrameOperations(
                        profile,
                        plan,
                        backend,
                        native_build=18,
                        bus_id=0x11,
                        driver=driver,
                        device_kind=8,
                        clock=lambda: 0,
                    )
                    systems.append(
                        CenturySystem(
                            operations,
                            CenturyMonitorEvent(
                                0, ids, bytes([1]) * len(ids), len(ids)
                            ),
                            index + 1,
                            0xFFFFFFFF,
                            0xFFFFFFFF,
                            1000,
                            200,
                            (0x10, 0x18)[index],
                        )
                    )
                worker = CenturyJ2534Worker(
                    cast(tuple[CenturySystem, CenturySystem], tuple(systems)),
                    functional,
                    default_source=0x10,
                    clock=lambda: 0,
                )
                first, second = worker.run_systems(1)
                self.assertEqual(worker.century_mode, 3 if mixed else 2)
                self.assertEqual(
                    first.packets[0].payload, b"\x1c\x1d" if mixed else b"\x1d"
                )
                self.assertEqual(
                    second.packets[0].payload, b"\x14\x16" if mixed else b"\x16"
                )
                connects = [fields for op, fields in backend.calls if op == "connect"]
                self.assertEqual(len(connects), 3 if mixed else 1)
                self.assertTrue(
                    all(system.operations.channel is None for system in systems)
                )
                self.assertIsNone(functional.channel)

    def test_packet_actual_driver_operations_and_a3_cleanup_order(self):
        for build, cancel_after_a2 in ((12, False), (18, False), (18, True)):
            with self.subTest(build=build, cancelled=cancel_after_a2):
                operations, observed = authored_operations(
                    build=cast(Literal[12, 18], build)
                )
                parent = observed.invoke
                stopped_reads = [0]
                stop = [False]

                def exchange(
                    operation,
                    fields,
                    *,
                    deadline,
                    cancelled,
                    cancel_enabled=cancel_after_a2,
                    parent=parent,
                    observed=observed,
                    stop=stop,
                    stopped_reads=stopped_reads,
                ):
                    result = parent(
                        operation, fields, deadline=deadline, cancelled=cancelled
                    )
                    if (
                        cancel_enabled
                        and operation == "write_messages"
                        and observed.request[:1] == b"\xa2"
                    ):
                        stop[0] = True
                    if operation != "read_messages" or observed.request == b"\x10\x01":
                        return result
                    if observed.request[0] == 0xA1:
                        payload = b"\xe1" + observed.request[1:]
                    elif observed.request[0] == 0xA2:
                        payload = b"\xe2\x01\xaa\xbb"
                    else:
                        stopped_reads[0] += 1
                        if stopped_reads[0] > 1:
                            return J2534Result(code=9)
                        payload = b"\xe3"
                    return J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(
                                6, 0, 0, 1234, 0, b"\x00\x00\x07\xe8" + payload
                            ),
                        ),
                    )

                observed.invoke = exchange
                osc_calls = []

                def osc_exchange(call, deadline, calls=osc_calls):
                    calls.append(call)
                    if call.export == "DstiOscReadBuffer":
                        return OscRead(0, b"\xaa\xbb\xcc\xdd", 2000)
                    return 0

                instrument = OscilloscopeRuntime(
                    DstiOscDriver(
                        osc_exchange, module_loaded=True, exports=DstiOscDriver.EXPORTS
                    ),
                    OscConfiguration(),
                    clock=lambda: 0,
                )
                event = PacketMonitorEvent(1, b"\x0c", ((0, 2),), timeout=3000)
                worker = DirectJ2534Worker(
                    operations,
                    event,
                    request_id=1,
                    response_id=0,
                    default_source=0x7E8,
                    attempts=0,
                    clock=lambda: 0,
                    cancelled=lambda stop=stop: stop[0],
                    oscilloscope=instrument,
                )
                if cancel_after_a2:
                    with self.assertRaisesRegex(Exception, "cancelled"):
                        worker.run(1)
                    self.assertIsNone(worker.cleanup_error)
                else:
                    capture = worker.run(1)
                    self.assertEqual(capture.packets[0].payload, b"\xaa\xbb")
                    self.assertEqual(capture.packets[0].timestamp_ms, 1)
                writes = [
                    fields["messages"][0].data[4:]
                    for op, fields in observed.calls
                    if op == "write_messages"
                ]
                self.assertEqual(
                    writes, [b"\x10\x01", b"\xa1\x01\x0c", b"\xa2\x01", b"\xa3"]
                )
                modes = [
                    fields["input"]
                    for op, fields in observed.calls
                    if op == "ioctl" and fields["ioctl_id"] == 2
                ]
                self.assertIn((NativeConfig(0x10400, 1),), modes)
                self.assertIn((NativeConfig(0x10400, 0),), modes)
                self.assertFalse(
                    any(
                        any(config.parameter == 0x10500 for config in pairs)
                        for pairs in modes
                    )
                )
                self.assertEqual(observed.calls[-1][0], "disconnect")
                self.assertEqual(instrument.state, "stopped")
                self.assertEqual(
                    [
                        call.maximum
                        for call in osc_calls
                        if call.export == "DstiOscReadBuffer"
                    ],
                    [0, 0x1068] if cancel_after_a2 else [0, 0, 0x1068],
                )
                self.assertEqual(
                    instrument.capture().packets[0].payload, b"\xaa\xbb\xcc\xdd"
                )

    def test_century_actual_fixed_iso_framing_two_source_cycle(self):
        for build in (12, 18):
            with self.subTest(build=build):
                self._check_century_fixed_cycle(cast(Literal[12, 18], build))

    def test_century_absent_registered_dm_preserves_idle_and_native_fault_boundary(
        self,
    ):
        for build in (12, 18):
            for missing in ((0,), (1,), (0, 1)):
                with self.subTest(build=build, missing=missing):
                    self._check_century_fixed_cycle(
                        cast(Literal[12, 18], build), missing=missing
                    )

    def _check_century_fixed_cycle(
        self, build: Literal[12, 18], *, missing: tuple[int, ...] = ()
    ):
        profile, driver = authored_iso_profile(build=build)

        class CenturyObservations:
            def __init__(self):
                self.calls = []
                self.requested = False
                self.responses = iter(
                    (b"\x84\xb5\x10\x41\x0c\xaa\xbb", b"\x84\xb5\x18\x41\x0c\xcc\xdd")
                )

            def invoke(self, operation, fields, *, deadline, cancelled):
                self.calls.append((operation, fields))
                if operation == "connect":
                    return J2534Result(handle=7)
                if operation == "ioctl" and fields["ioctl_id"] == 5:
                    return J2534Result(
                        messages=(
                            NativeMessage(4, 0, 0, 0, 0, b"\x83\xb5\x10\xc1\x08\x08"),
                        )
                    )
                if operation == "write_messages":
                    self.requested = True
                    return J2534Result(count=1)
                if operation == "read_messages":
                    if not self.requested:
                        return J2534Result(code=9)
                    return J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(4, 0, 0, 1234, 0, next(self.responses)),
                        ),
                    )
                return J2534Result()

        backend = CenturyObservations()
        plan = century_frame_plan(profile, bus_id=0x31, driver=driver)
        functional = CenturyNativeFrameOperations(
            profile,
            plan,
            backend,
            registered_response_ids=(0x10, 0x18),
            native_build=build,
            bus_id=0x31,
            driver=driver,
            device_kind=8,
            clock=lambda: 0,
        )
        functional.force_initialization = True
        systems = tuple(
            CenturySystem(
                NativeFrameOperations(
                    profile,
                    plan,
                    backend,
                    native_build=build,
                    bus_id=0x31,
                    driver=driver,
                    device_kind=8,
                    clock=lambda: 0,
                ),
                None
                if index in missing
                else CenturyMonitorEvent(0, b"\x0c", b"\x02", 2),
                index + 1,
                0xFFFFFFFF,
                0xFFFFFFFF,
                1000,
                200,
                source,
            )
            for index, source in enumerate((0x10, 0x18))
        )
        retained_active = ActiveMonitorEvent(b"\x01")
        retained_system = MonitorSystemEvent(b"\x02")
        worker = CenturyJ2534Worker(
            cast(tuple[CenturySystem, CenturySystem], systems),
            functional,
            default_source=0x10,
            active=retained_active,
            system=retained_system,
            clock=lambda: 0,
            ticks=lambda: 1234,
        )
        if missing:
            self.assertEqual(worker.state, "configured")
            self.assertEqual(worker.century_mode, 0)
            self.assertEqual(backend.calls, [])
            self.assertEqual(
                tuple(
                    i for i, system in enumerate(worker.systems) if system.event is None
                ),
                missing,
            )
            with self.assertRaisesRegex(
                NativeMonitorSourceFault, "absent registered DM event"
            ):
                worker.start()
            self.assertEqual(backend.calls, [])
            self.assertFalse(worker.owned)
            self.assertIs(worker.events[0], retained_active)
            self.assertIs(worker.events[1], retained_system)
            return
        captures = worker.run_systems(1)
        self.assertIs(worker.events[0], retained_active)
        self.assertIs(worker.events[1], retained_system)
        self.assertEqual(
            tuple(capture.packets[0].payload for capture in captures),
            (b"\xaa\xbb", b"\xcc\xdd"),
        )
        writes = [
            fields["messages"][0].data
            for op, fields in backend.calls
            if op == "write_messages"
        ]
        self.assertEqual(writes, [b"\xc2\xdf\xf0\x01\x0c"])
        self.assertEqual(
            backend.calls[0][1], {"protocol_id": 4, "flags": 0, "baud_rate": 0}
        )
        self.assertEqual(backend.calls[-1][0], "disconnect")
        initialized = [
            fields["input"]
            for op, fields in backend.calls
            if op == "ioctl" and fields["ioctl_id"] == 5
        ]
        self.assertEqual(initialized[0].data, b"\xc2\xdf\xf0\x10\x01")
        self.assertEqual(initialized[0].extra_data_index, 5)
        self.assertEqual(
            functional._validate_message(
                NativeMessage(4, 0, 0, 0, 0, b"\x84\xb5\x99\x41\x0c\xaa\xbb")
            ),
            0x91020325,
        )
        self.assertEqual(
            functional._validate_message(
                NativeMessage(4, 0, 0, 0, 0, b"\x83\xb5\x10\x7f\x01\x22")
            ),
            0x90020321,
        )

    def test_preowned_channel_and_invalid_slots_never_disconnect_caller(self):
        operations, observations = authored_operations()
        operations.adopt_channel(9, owned=True)
        with self.assertRaisesRegex(MonitorError, "fresh"):
            DirectJ2534Worker(
                operations,
                DataMonitorEvent(0, b"\x0c", b"\x02", 2),
                request_id=1,
                response_id=2,
                default_source=3,
            )
        self.assertEqual(operations.channel, 9)
        self.assertFalse(observations.calls)
        operations, observations = authored_operations()
        worker = DirectJ2534Worker(
            operations,
            DataMonitorEvent(0, b"\x0c", b"\x02", 2),
            request_id=1,
            response_id=2,
            default_source=3,
        )
        operations.adopt_channel(9, owned=True)
        with self.assertRaisesRegex(MonitorError, "fresh"):
            worker.run(1)
        self.assertEqual(operations.channel, 9)
        self.assertFalse(observations.calls)
        operations, observations = authored_operations()
        with self.assertRaisesRegex(MonitorError, "typed"):
            DirectJ2534Worker(
                operations,
                cast(Any, object()),
                request_id=1,
                response_id=2,
                default_source=3,
            )
        self.assertFalse(observations.calls)

    def test_capture_budget_charges_timestamp_bytes(self):
        operations, _ = authored_operations()
        event = DataMonitorEvent(0, b"\x0c", b"\x05", 5)
        worker = DirectJ2534Worker(
            operations,
            event,
            request_id=1,
            response_id=2,
            default_source=3,
            max_bytes=8,
        )
        event.check_rcv_frame(b"\x41\x0c\x01\x02\x03\x04\x05", 0)
        with self.assertRaisesRegex(MonitorError, "budget"):
            worker._harvest(event)
        self.assertEqual(worker.byte_count, 0)

    def test_receive_fault_notification_and_cancel_release(self):
        operations, observations = authored_operations(failure=9)
        worker = DirectJ2534Worker(
            operations,
            DataMonitorEvent(0, b"\x0c", b"\x02", 2),
            request_id=0x7E0,
            response_id=0,
            default_source=0x7E8,
            attempts=1,
            clock=lambda: 0,
        )
        with self.assertRaises(MonitorError) as raised:
            worker.run(1)
        self.assertEqual(raised.exception.code, 0xE0000107)
        self.assertEqual(worker.notifications[-1].code, 0xE0000107)
        self.assertEqual(observations.calls[-1][0], "disconnect")
        cancelled = [False]
        operations, observations = authored_operations(
            cancellation=lambda: cancelled[0]
        )
        worker = DirectJ2534Worker(
            operations,
            DataMonitorEvent(0, b"\x0c", b"\x02", 2),
            request_id=1,
            response_id=2,
            default_source=3,
            clock=lambda: 0,
            cancelled=lambda: cancelled[0],
        )
        self.assertEqual(worker.start(), OK)
        cancelled[0] = True
        before = len(observations.calls)
        with self.assertRaisesRegex(Exception, "cancelled"):
            worker.step()
        self.assertEqual(len(observations.calls), before)
        self.assertEqual(worker.close(), 0)
        self.assertEqual(observations.calls[-1][0], "disconnect")

    def test_event_queue_budgets_and_repeated_native_active_stop(self):
        event = DataMonitorEvent(0, b"\x0c", b"\x01", 1)
        event.pending_packet_bytes = 64 * 1024 * 1024
        with self.assertRaisesRegex(MonitorError, "budget"):
            event.check_rcv_frame(b"\x41\x0c\xaa", 1)
        active = ActiveMonitorEvent(b"\x01")
        active.stop()
        self.assertEqual(active.stop(initialize=True), OK)
        self.assertEqual(
            [item.request for item in active.items], [b"\x30\x01", b"\x30", b"\x30"]
        )
        self.assertTrue(active.initialize_after_stop)
        with self.assertRaisesRegex(MonitorError, "boolean"):
            ActiveMonitorEvent(b"\x01", dk_kwp=cast(Any, 1))

    def test_actual_lower_primitives_to_capture_and_owned_cleanup(self):
        for build in (12, 18):
            with self.subTest(build=build):
                operations, observations = authored_operations(build=build)
                event = DataMonitorEvent(0, b"\x0c", b"\x02", 2)
                worker = DirectJ2534Worker(
                    operations,
                    event,
                    request_id=0x7E0,
                    response_id=0,
                    default_source=0x7E8,
                    clock=lambda: 0,
                    ticks=lambda: 1234,
                )
                capture = worker.run(1)
                self.assertEqual(capture.packets[0].payload, b"\xaa\xbb")
                self.assertEqual(capture.packets[0].timestamp_ms, 1234)
                self.assertEqual(observations.calls[0][0], "connect")
                self.assertEqual(observations.calls[-1][0], "disconnect")
                writes = [
                    fields["messages"][0].data
                    for operation, fields in observations.calls
                    if operation == "write_messages"
                ]
                self.assertEqual(
                    writes, [b"\x00\x00\x07\xe0\x10\x01", b"\x00\x00\x07\xe0\x01\x0c"]
                )
                self.assertFalse(event.packets)
                self.assertIsNone(operations.channel)

    def test_worker_bounds_cancel_and_nonfinite_clock_preflight(self):
        for clock in (
            lambda: float("nan"),
            lambda: float("inf"),
            lambda: -float("inf"),
        ):
            operations, observations = authored_operations()
            worker = DirectJ2534Worker(
                operations,
                DataMonitorEvent(0, b"\x0c", b"\x02", 2),
                request_id=1,
                response_id=2,
                default_source=3,
                clock=clock,
            )
            with self.assertRaisesRegex(MonitorError, "finite"):
                worker.start()
            self.assertFalse(observations.calls)
        operations, observations = authored_operations()
        worker = DirectJ2534Worker(
            operations,
            DataMonitorEvent(0, b"\x0c", b"\x02", 2),
            request_id=1,
            response_id=2,
            default_source=3,
            max_steps=1,
            clock=lambda: 0,
        )
        with self.assertRaisesRegex(MonitorError, "budget"):
            worker.run(1)
        self.assertEqual(observations.calls[-1][0], "disconnect")

    def test_service_grammar_and_retained_short_reply(self):
        for data_type, expected in (
            (0, b"\x01\x0c"),
            (1, b"\x21\x0c"),
            (2, b"\x01\x0c\x01"),
            (3, b"\x21\x0c\x01"),
            (6, b"\x21\x0c"),
        ):
            with self.subTest(data_type=data_type):
                event = DataMonitorEvent(data_type, b"\x0c", b"\x02", 2)
                self.assertEqual(event.get_snd_frame(1), expected)
                reply = 0x41 if data_type in (0, 2) else 0x61
                self.assertEqual(
                    event.check_rcv_frame(bytes((reply, 12, 10, 11)), 2), OK
                )
                self.assertEqual(event.check_rcv_frame(bytes((reply, 12, 12)), 3), OK)
                self.assertEqual(event.packets[-1].payload, b"\x0c\x0b")

    def test_dtc_is_last_and_type6_pid1_has_one_byte_header(self):
        event = DataMonitorEvent(6, b"\x01", b"\x02", 3, dtc_request=b"\x80")
        self.assertEqual(event.check_rcv_frame(b"\x53\x01", 0), INVALID)
        self.assertEqual(event.get_snd_frame(0), b"\x21\x01")
        self.assertEqual(event.check_rcv_frame(b"\x61\xaa\xbb", 1), OK)
        self.assertEqual(event.get_snd_frame(1), b"\x13\x80")
        self.assertEqual(event.check_rcv_frame(b"\x53\xcc", 2), OK)
        self.assertEqual(event.packets[-1].payload, b"\xaa\xbb\xcc")

    def test_century_unordered_cycle_and_unknown_pid(self):
        event = CenturyMonitorEvent(0, b"\x0c\x0d", b"\x02\x01", 3)
        self.assertEqual(event.check_rcv_frame(b"\x41\x7f\x99", 1), OK)
        self.assertFalse(event.packets)
        event.check_rcv_frame(b"\x41\x0d\xcc", 2)
        event.check_rcv_frame(b"\x41\x0c\xaa\xbb", 3)
        self.assertEqual(event.packets[-1].payload, b"\xaa\xbb\xcc")
        self.assertEqual(event.receive_flag, 1)
        self.assertEqual(event.received, [False, False])

    def test_packet_setup_echo_and_stop_grammar(self):
        event = PacketMonitorEvent(1, b"\x0c\x0d", ((0, 3),), timeout=3000)
        self.assertEqual(event.get_snd_frame(0), b"\xa1\x01\x0c\x0d")
        self.assertEqual(event.item.status, 8)
        self.assertEqual(event.check_rcv_frame(b"\xe1\x01\x0c\x0e", 1), 0xE0000103)
        self.assertEqual(event.check_rcv_frame(b"\xe1\x01\x0c\x0d", 1), OK)
        self.assertEqual(event.get_snd_frame(10), b"\xa2\x01")
        self.assertEqual(event.item.next_send, 3010)
        event.check_rcv_frame(b"\xe2\x01\xaa\xbb\xcc", 11)
        self.assertEqual(event.packets[-1].payload, b"\xaa\xbb\xcc")
        event.stop()
        self.assertEqual(event.get_snd_frame(12), b"\xa3")
        self.assertEqual(event.item.status, 14)
        self.assertEqual(event.check_rcv_frame(b"\xe3", 13), OK)
        self.assertEqual(event.item.status, 6)

    def test_packet_cache_emits_previous_cycle_before_wrapping_copy(self):
        event = PacketMonitorEvent(4, b"\x02\x01", ((0, 3),), timeout=100)
        self.assertEqual(event.get_snd_frame(0), b"\xa2\x04")
        event.check_rcv_frame(b"\xe2\x11\xaa\xbb", 1)
        event.check_rcv_frame(b"\xe2\x12\xcc", 2)
        self.assertFalse(event.packets)
        event.check_rcv_frame(b"\xe2\x11\xdd\xee", 3)
        self.assertEqual(event.packets[-1].payload, b"\xaa\xbb\xcc")
        self.assertEqual(event.data, b"\xdd\xee\xcc")

    def test_active_timer_reply_width_and_dk_difference(self):
        event = ActiveMonitorEvent(b"\x01\x02", 20)
        self.assertEqual(event.get_snd_frame(0), b"\x30\x01\x02")
        self.assertEqual(event.check_rcv_frame(b"\x70\x00", 0xFFFFFFF8), OK)
        self.assertEqual(event.item.next_send, 12)
        self.assertEqual(event.item.status, 3)
        self.assertEqual(event.check_rcv_frame(b"\x70\x00\x01", 1), 0xE00001CC)
        dk = ActiveMonitorEvent(b"\x01", dk_kwp=True)
        self.assertEqual(dk.check_rcv_frame(b"\x70\x00\x01", 1), OK)
        self.assertEqual(dk.item.status, 4)
        event.stop(initialize=True)
        event.skip_end()
        self.assertEqual(event.get_snd_frame(2), b"\x30")

    def test_system_ack_and_storage_validation(self):
        event = MonitorSystemEvent(b"\x01")
        self.assertEqual(event.get_snd_frame(0), b"\x08\x01")
        self.assertEqual(event.check_rcv_frame(b"\x48", 1), OK)
        self.assertEqual(event.item.status, 4)
        for spans in (((0, -8),), ((True, 8),), ((0, 7),), ((0,),)):
            with self.subTest(spans=spans), self.assertRaises(MonitorError):
                DataMonitorEvent(0, b"\x01", b"\x01", 2, pickup_spans=cast(Any, spans))


if __name__ == "__main__":
    unittest.main()
