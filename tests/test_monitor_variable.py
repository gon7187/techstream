"""Authored variable-drive bytecode regression and source-identity controls."""

import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from scripts.data_monitor import (
    MonitorCommand,
    MonitorDefinitions,
    MonitorError,
    MonitorRange,
    pack_p4,
    select_provider,
    selected_p4_connection,
)
from scripts.demo import _ddb, create_demo
from scripts.diagnostic_db import parse_database
from scripts.monitor_support import MonitorSupportCache
from scripts.monitor_variable import (
    VariableActiveRuntime,
    VariableMeasurement,
    VariableMonitorRuntime,
    VariableMonitorSource,
    VariableNotification,
    VariableRuntimeTarget,
    allocate_variable_measurements,
    check_variable_monitor,
    check_variable_target_from_cache,
    pack_variable,
    run_variable_dmci,
    selected_variable_active_operation,
    selected_variable_monitor_from_cache,
    selected_variable_packet_monitor,
    selected_variable_recording,
    selected_variable_runtime_target,
    selected_variable_system_operation,
    selected_variable_voltage_monitor,
    variable_active_request,
    variable_definitions,
    variable_dmci_lifecycle,
    variable_error_notification,
    variable_excluded_mask,
    variable_measurement,
    variable_target_mask,
    variable_voltage_interface,
)
from scripts.profiles import VehicleCatalog


def records():
    record, pattern = bytearray(92), bytearray(24)
    record[68], record[80], record[86], record[88] = 5, 0x39, 10, 7
    struct.pack_into("<H", pattern, 2, 250)
    struct.pack_into("<H", pattern, 8, 0x103)
    pattern[20] = 1
    return bytes(record), bytes(pattern)


def authored_profile(root: Path, *, freeze_flags: int = 1):
    create_demo(root)
    directory = root / "Techstream_DB_NA"
    management_path = directory / "Toyota.ddb"
    management = parse_database(management_path.read_bytes())
    sections = {
        slot: (item.count, item.payload) for slot, item in management.sections.items()
    }
    category = bytearray(sections[16][1])
    category[72] = 4
    sections[16] = (1, bytes(category))
    protocol = bytearray(28)
    struct.pack_into("<HH", protocol, 0, 1, 7)
    struct.pack_into("<H", protocol, 8, 0x7E0)
    struct.pack_into("<HH", protocol, 14, 12, 12)
    protocol[24] = 0x12
    sections[13] = (1, bytes(protocol))
    can = bytearray(28)
    struct.pack_into("<I", can, 4, 500000)
    struct.pack_into("<H", can, 8, 7)
    sections[14] = (1, bytes(can))
    instructions = b"\2\12\0"
    sections[0] = (
        2,
        struct.pack("<IHIH", 0, len(instructions), len(instructions), 1)
        + instructions
        + b"\x13",
    )
    sections[17] = (2, struct.pack("<8H", 9, 1, 0, 0, 10, 2, 0, 0))
    sections[18] = (1, struct.pack("<8H", 1, 0x13, 1, 10, 0, 1, 0, 0))
    management_path.write_bytes(_ddb(1, sections))
    ecu_path = directory / "DemoEngine.ddb"
    database = parse_database(ecu_path.read_bytes())
    sections = {
        slot: (item.count, item.payload) for slot, item in database.sections.items()
    }
    record, pattern = map(bytearray, records())
    struct.pack_into("<H", record, 56, 4)
    struct.pack_into("<H", record, 64, 3)
    struct.pack_into("<H", record, 74, 9)
    struct.pack_into("<H", pattern, 0, 3)
    sections[41], sections[12] = (1, bytes(record)), (1, bytes(pattern))
    freeze = bytearray(sections[10][1][:84])
    struct.pack_into("<H", freeze, 56, 4)
    struct.pack_into("<HH", freeze, 62, 0, 15)
    freeze[77], freeze[78], freeze[79] = 1, freeze_flags, 9
    sections[10] = (1, bytes(freeze))
    ecu_path.write_bytes(_ddb(2, sections))
    return VehicleCatalog(directory).build_profile(1)


class VariableMonitorTests(unittest.TestCase):
    def test_normal_joined_factory_actual_support_then_fresh_lower(self):
        from test_monitor_j2534 import authored_operations

        from scripts.data_monitor import (
            selected_legacy_check_target,
            selected_variable_monitor_runtime,
        )
        from scripts.diagnostic_db import Section
        from scripts.frame_transport import (
            J2534Result,
            NativeFrameOperations,
            NativeMessage,
            get_comm_frame,
        )
        from scripts.monitor_variable import SelectedVariableMonitor
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )
        from scripts.toyota_session import Limits

        with tempfile.TemporaryDirectory() as directory:
            profile = authored_profile(Path(directory) / "fixture")
            sections = dict(profile.catalog.management.sections)
            requests = (b"\2\12\0", b"\x13", b"\x10\x01", b"\x3e")
            offset, entries = 0, []
            for request in requests:
                entries.append(struct.pack("<IH", offset, len(request)))
                offset += len(request)
            sections[0] = Section(0, 0, 4, False, b"".join(entries + list(requests)))
            sections[17] = Section(
                17,
                0,
                4,
                False,
                struct.pack("<16H", 9, 1, 0, 0, 10, 2, 0, 0, 11, 3, 0, 0, 12, 4, 0, 0),
            )
            sections[18] = Section(
                18,
                0,
                3,
                False,
                struct.pack("<8H", 1, 0x13, 1, 10, 0, 1, 0, 0)
                + struct.pack("<8H", 1, 0x67, 1, 11, 0, 0, 0, 0)
                + struct.pack("<8H", 1, 0x7F, 1, 12, 0, 0, 0, 0),
            )
            profile.catalog.management = replace(
                profile.catalog.management, sections=sections
            )
            prototype, backend = authored_operations()
            invoke = backend.invoke
            support_reads = [0]

            def native_backend(operation, fields, *, deadline, cancelled):
                result = invoke(
                    operation, fields, deadline=deadline, cancelled=cancelled
                )
                if operation == "write_messages" and backend.request == b"\x13":
                    support_reads[0] = 0
                if operation == "read_messages" and backend.request == b"\x13":
                    support_reads[0] += 1
                    if support_reads[0] > 1:
                        return J2534Result(code=9)
                    payload = b"\x53\0\x09\x02\x80\0"
                elif operation == "read_messages" and backend.request[:1] == b"\x01":
                    payload = b"\x41" + backend.request[1:2] + b"AB"
                elif operation == "read_messages" and backend.request[:1] == b"\x30":
                    payload = b"\x70" if len(backend.request) == 1 else b"\x70\x01"
                elif operation == "read_messages" and backend.request[:1] == b"\x08":
                    payload = b"\x48"
                else:
                    return result
                return J2534Result(
                    count=1,
                    messages=(
                        NativeMessage(6, 0, 0, 1234, 0, b"\0\0\x07\xe8" + payload),
                    ),
                )

            backend.invoke = native_backend

            def operations():
                return NativeFrameOperations(
                    profile,
                    get_comm_frame(
                        profile, b"\x13", bus_id=0x12, driver=prototype.driver
                    ),
                    backend,
                    native_build=18,
                    bus_id=0x12,
                    driver=prototype.driver,
                    device_kind=8,
                    clock=lambda: 10,
                    wait=lambda _: None,
                )

            support_ops, live_ops = operations(), operations()
            communication = NativeCommunication(
                profile,
                NativeFrameController(support_ops),
                "engine",
                bus_id=0x12,
                source_build=18,
                clock=lambda: 10,
            )
            observed = {
                key: key == 11 for key in (22, 10, 8, 9, 12, 25, 11, 26, 29, 27, 28, 35)
            }
            target = selected_legacy_check_target(communication, (4,), observed)
            runtime = selected_variable_monitor_runtime(
                (target,),
                live_ops,
                command_kind=7,
                command_ecu=1,
                allocation=128,
                standard_values=((),),
                names=(b"engine\0",),
                text_encoding="utf-8",
                phase=0,
                limits=Limits(10, 256),
                clock=lambda: 10,
                ticks=lambda: 1234,
            )
            self.assertTrue(communication.closed)
            self.assertIsNone(support_ops.channel)
            self.assertEqual(runtime.targets[0].buffer.allocation_size, 128)
            from scripts.monitor_j2534 import DirectJ2534Worker

            runtime.start()
            assert isinstance(runtime.worker, DirectJ2534Worker)
            for _ in range(16):
                if runtime.worker.packet_count:
                    break
                runtime.step()
            self.assertEqual(runtime.worker.packet_count, 1)
            system_operation = selected_variable_system_operation(
                profile,
                0x1234,
                source=VariableMonitorSource.for_build(18),
                observed_bus_id=0x12,
                controller_category_flags=4,
            )
            command96 = runtime.enqueue(96, system_operation)
            for _ in range(3):
                runtime.step()
            self.assertEqual(command96.status, 0)
            self.assertEqual(backend.request, b"\x08\x34")
            active_operation = selected_variable_active_operation(
                profile,
                4,
                0x1234,
                source=VariableMonitorSource.for_build(18),
                observed_bus_id=0x12,
                controller_category_flags=4,
            )
            command11 = runtime.enqueue(11, active_operation)
            for _ in range(3):
                runtime.step()
            self.assertEqual(command11.status, 0)
            self.assertEqual(backend.request, active_operation.request)
            command12 = runtime.enqueue(12)
            runtime.step()
            self.assertEqual(command12.status, 0)
            captures = runtime.stop()
            self.assertEqual(backend.request, b"\x30")
            self.assertEqual(captures[0].packets[0].payload, b"A")
            plan = runtime.targets[0].plan
            assert isinstance(plan, SelectedVariableMonitor)
            self.assertEqual(plan.frame_sizes, ((0, 1),))
            from scripts.snapshot import (
                MonitorBuffer,
                SnapshotError,
                TableFile,
                decode_monitor_buffer,
                monitor_samples,
                parse,
            )

            metadata = MonitorBuffer(
                b"engine", bytes(16), b"", b"", b"", b"", 0, (), (4,), b"", ()
            )
            system = {
                "identifier": 0,
                "strings": [{"core": [1, 0], "data_hex": "00"}] * 2,
                "value_raw": 0,
            }
            exported = parse(runtime.dm_bytes(0, metadata, system))
            assert isinstance(exported, TableFile)
            monitor = decode_monitor_buffer(
                next(table.payload for table in exported.tables if table.id == 0x8101)
            )
            with self.assertRaisesRegex(SnapshotError, "signal bit range"):
                monitor_samples(monitor)
            self.assertIsNone(live_ops.channel)
            self.assertEqual(sum(name == "connect" for name, _ in backend.calls), 2)
            requests_sent = [
                fields["messages"][0].data[4:]
                for name, fields in backend.calls
                if name == "write_messages"
            ]
            self.assertEqual(requests_sent.count(b"\x13"), 2)

    def test_selected_system08_producer_actual113_and_native_host_distinction(self):
        from scripts.drive_recorder import (
            DMCI_WIRE_COMMANDS,
            NativeDmciError,
            NativeVimClient,
            NativeVimReply,
            decode_vim_command,
        )

        with tempfile.TemporaryDirectory() as directory:
            profile = authored_profile(Path(directory) / "fixture")
            for bus in (0x11, 0x12, 0x16, 0x17, 0x18, 0x19):
                protocol = bytearray(profile.catalog.management.sections[13].payload)
                protocol[24] = bus
                profile.catalog.management.sections[13] = replace(
                    profile.catalog.management.sections[13], payload=bytes(protocol)
                )
                operation = selected_variable_system_operation(
                    profile,
                    0x1234,
                    source=VariableMonitorSource.for_build(18),
                    observed_bus_id=bus,
                    controller_category_flags=4,
                )
                body = b"\x34" + (bytes(5) if bus & 15 in (1, 6, 7, 9) else b"")
                self.assertEqual(operation.request, b"\x08" + body)
                self.assertEqual(operation.event().items[0].request, operation.request)
                calls = []

                def exchange(request, *, deadline, cancelled, calls=calls):
                    wire, payload = decode_vim_command(request)
                    calls.append((wire, payload))
                    return NativeVimReply(wire | 0x80, 6, bytes(4)).encode()

                operation.send(
                    NativeVimClient(
                        exchange,
                        capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                    )
                )
                self.assertEqual(calls[0][0], DMCI_WIRE_COMMANDS[0x113])
                self.assertIn(body, calls[0][1])
                if bus == 0x11:
                    self.assertEqual(
                        operation.request_identity, (0x7E0 | 0x8000) << 8 | 0xF0
                    )
                    active = selected_variable_active_operation(
                        profile,
                        4,
                        1,
                        source=VariableMonitorSource.for_build(18),
                        observed_bus_id=bus,
                        controller_category_flags=4,
                    )
                    self.assertEqual(
                        active.request_identity, operation.request_identity
                    )

            def failure(request, *, deadline, cancelled):
                wire, _ = decode_vim_command(request)
                return NativeVimReply(wire | 0x80, 6, struct.pack("<I", 9)).encode()

            with self.assertRaises(MonitorError) as raised:
                operation.send(
                    NativeVimClient(
                        failure,
                        capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                    )
                )
            self.assertEqual(raised.exception.code, 0xA0051401)
            assert isinstance(raised.exception.__cause__, NativeDmciError)
            self.assertEqual(raised.exception.__cause__.status, 9)

            def host_failure(request, *, deadline, cancelled):
                raise TimeoutError("Host timeout")

            with self.assertRaises(TimeoutError):
                operation.send(
                    NativeVimClient(
                        host_failure,
                        capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                    )
                )

    def test_null_controller_uses_management_only_slot_and_real_buffer(self):
        from test_monitor_poll import authored_multi

        from scripts.drive_recorder import (
            DMCI_WIRE_COMMANDS,
            NativeCoreBuffer,
            NativeDmciCommand,
            NativeDmciList,
            NativeMonitorReply,
            NativeVimClient,
            NativeVimReply,
            decode_vim_command,
        )
        from scripts.monitor_support import monitor_source_identity
        from scripts.monitor_variable import VariableNullController
        from scripts.profiles import ProtocolProfile

        for build in (12, 18):
            for fault in (None, "idmap", "setup", "host"):
                with self.subTest(build=build, fault=fault):
                    _, targets, _ = authored_multi(build=build)
                    profile = targets[0].cache.profile
                    controller_profile = ProtocolProfile(
                        profile.catalog,
                        profile.category_record,
                        profile.exception_ids,
                        profile.vehicle_name_key,
                    )
                    connection = targets[0].connection
                    assert connection is not None
                    connection = replace(
                        connection,
                        source_identity=monitor_source_identity(controller_profile, ""),
                    )
                    null = VariableNullController(controller_profile, connection, build)
                    self.assertIsNone(controller_profile.ecu_database_sha256)
                    self.assertFalse(hasattr(controller_profile, "database"))
                    self.assertEqual(null.mode, 0x80)
                    key = targets[1].cache.profile.category
                    calls = []
                    host_error = TimeoutError("NULL controller receive uncertainty")

                    def exchange(
                        request,
                        *,
                        deadline,
                        cancelled,
                        calls=calls,
                        key=key,
                        fault=fault,
                        host_error=host_error,
                    ):
                        wire, payload = decode_vim_command(request)
                        calls.append((wire, payload))
                        if wire == DMCI_WIRE_COMMANDS[0x10D]:
                            self.assertEqual(
                                payload,
                                NativeDmciCommand(
                                    0x10D, (NativeDmciList((1, 0), ((key,),)),)
                                ).encode(),
                            )
                            if fault == "host":
                                raise host_error
                            empty = NativeCoreBuffer((1, 0), b"")
                            body = NativeMonitorReply(
                                0,
                                NativeDmciList(
                                    (1, 0),
                                    (
                                        (
                                            key,
                                            NativeCoreBuffer(
                                                (1, 0), struct.pack("<I", 7) + b"AB"
                                            ),
                                        ),
                                    ),
                                ),
                                (empty, empty, empty, empty, empty),
                                0,
                            ).encode()
                        else:
                            failed = (
                                fault == "idmap"
                                and wire == DMCI_WIRE_COMMANDS[0x111]
                                or fault == "setup"
                                and wire == DMCI_WIRE_COMMANDS[0x10A]
                            )
                            body = struct.pack("<I", 9 if failed else 0)
                        return NativeVimReply(wire | 0x80, 6, body).encode()

                    client = NativeVimClient(
                        exchange,
                        capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                        clock=lambda: 0,
                    )
                    runtime = VariableMonitorRuntime(
                        (targets[1],),
                        client,
                        connected_device=4,
                        controller_connection=connection,
                        null_controller=null,
                        clock=lambda: 0,
                    )
                    self.assertEqual(runtime.native_slot_categories, (42, 43))
                    if fault in ("setup", "host"):
                        with self.assertRaises(Exception) as raised:
                            runtime.run((1,))
                        if fault == "host":
                            self.assertIs(raised.exception, host_error)
                        else:
                            self.assertIsInstance(raised.exception, MonitorError)
                            assert isinstance(raised.exception, MonitorError)
                            self.assertEqual(raised.exception.code, 0xA0050425)
                    else:
                        captures = runtime.run((1,))
                        self.assertEqual(len(captures), 1)
                        self.assertEqual(captures[0].packets[0].payload, b"AB")
                    wires = [wire for wire, _ in calls]
                    self.assertEqual(
                        wires[:5],
                        [
                            DMCI_WIRE_COMMANDS[item]
                            for item in (
                                0x101,
                                0x107,
                                0x111,
                                0x111,
                                0x10A,
                            )
                        ],
                    )
                    self.assertEqual(
                        wires[-3:],
                        [
                            DMCI_WIRE_COMMANDS[item]
                            for item in (
                                0x10E,
                                0x108,
                                0x104,
                            )
                        ],
                    )
                    runtime.mark_fault(0xA0050425)
                    self.assertEqual(runtime.get_fault(0), 0)
                    self.assertEqual(runtime.get_fault(1), 0xA0050425)
                    with self.assertRaises(MonitorError):
                        VariableMonitorRuntime(
                            (targets[1],),
                            client,
                            connected_device=4,
                            controller_connection=connection,
                            null_controller=replace(
                                null, source_build=18 if build == 12 else 12
                            ),
                        )

    def test_null_controller_native_multimon_entry_capacity(self):
        from test_monitor_poll import authored_multi

        from scripts.monitor_support import monitor_source_identity
        from scripts.monitor_variable import VariableNullController
        from scripts.profiles import ProtocolProfile

        for build in (12, 18):
            operations, targets, backend = authored_multi(build=build)
            profile = targets[0].cache.profile
            row = bytearray(profile.category_record)
            struct.pack_into("<H", row, 68, 44)
            controller_profile = ProtocolProfile(
                profile.catalog,
                bytes(row),
                profile.exception_ids,
                profile.vehicle_name_key,
            )
            connection = targets[0].connection
            assert connection is not None
            connection = replace(
                connection,
                ecu_id=44,
                source_identity=monitor_source_identity(controller_profile, ""),
            )
            null = VariableNullController(controller_profile, connection, build)
            for selected, expected in (
                (targets[:1], 0xE0000102),
                (targets, 0xA0050425),
            ):
                with self.subTest(build=build, count=len(selected)):
                    with self.assertRaises(MonitorError) as raised:
                        VariableMonitorRuntime(
                            selected,
                            operations,
                            connected_device=8,
                            controller_connection=connection,
                            null_controller=null,
                        )
                    self.assertEqual(raised.exception.code, expected)
                    self.assertEqual(backend.calls, [])
            with self.assertRaises(MonitorError):
                VariableMonitorRuntime(
                    targets[:1],
                    operations,
                    controller_connection=replace(connection, source_identity=()),
                    null_controller=replace(
                        null, connection=replace(connection, source_identity=())
                    ),
                )

    def test_device4_aggregate_category_keys_and_independent_disposal(self):
        from test_monitor_poll import authored_multi

        from scripts.drive_recorder import (
            DMCI_WIRE_COMMANDS,
            NativeCoreBuffer,
            NativeDmciCommand,
            NativeDmciList,
            NativeMonitorReply,
            NativeVimClient,
            NativeVimReply,
            RecorderCancelled,
            decode_vim_command,
        )
        from scripts.monitor_variable import run_variable_multi_dmci
        from scripts.toyota_session import Limits

        for build in (12, 18):
            for fault in (
                False,
                "wrong-key",
                "idmap",
                "setup",
                "start",
                "native",
                "host",
                "cancel",
                "context",
                "stop",
                "read-status",
            ):
                with self.subTest(build=build, fault=fault):
                    _, targets, _ = authored_multi(build=build)
                    controller = targets[0].connection
                    assert controller is not None
                    self.assertEqual(
                        controller.address.request_id,
                        targets[1].connection.address.request_id,
                    )
                    calls = []
                    uncertainty = TimeoutError("aggregate host receive uncertainty")
                    empty = NativeCoreBuffer((1, 0), b"")
                    keys = tuple(target.cache.profile.category for target in targets)

                    def exchange(
                        request,
                        *,
                        deadline,
                        cancelled,
                        calls=calls,
                        keys=keys,
                        fault=fault,
                        uncertainty=uncertainty,
                        controller=controller,
                        empty=empty,
                        targets=targets,
                        build=build,
                    ):
                        wire, payload = decode_vim_command(request)
                        calls.append(wire)
                        if wire == DMCI_WIRE_COMMANDS[0x10D]:
                            self.assertEqual(
                                payload,
                                NativeDmciCommand(
                                    0x10D,
                                    (
                                        NativeDmciList(
                                            (1, 0), tuple((key,) for key in keys)
                                        ),
                                    ),
                                ).encode(),
                            )
                            if fault == "host":
                                raise uncertainty
                            body = NativeMonitorReply(
                                9 if fault == "read-status" else 0,
                                NativeDmciList(
                                    (1, 0),
                                    tuple(
                                        (
                                            controller.address.request_id
                                            if fault == "wrong-key"
                                            else key,
                                            NativeCoreBuffer(
                                                (1, 0),
                                                struct.pack("<I", 7)
                                                + bytes((key, key)),
                                            ),
                                        )
                                        for key in keys
                                    ),
                                ),
                                (
                                    empty,
                                    NativeCoreBuffer(
                                        (1, 0),
                                        struct.pack("<IIIB", 0x7E0, 0, 0xE0000103, 0),
                                    )
                                    if fault == "native"
                                    else empty,
                                    empty,
                                    empty,
                                    empty,
                                ),
                                0,
                            ).encode()
                        else:
                            if fault == "context" and wire == DMCI_WIRE_COMMANDS[0x101]:
                                targets[0].cache.source_build = (
                                    18 if build == 12 else 12
                                )
                            failed = (
                                (fault == "idmap" and wire == DMCI_WIRE_COMMANDS[0x111])
                                or (
                                    fault == "setup"
                                    and wire == DMCI_WIRE_COMMANDS[0x10A]
                                )
                                or (
                                    fault == "start"
                                    and wire == DMCI_WIRE_COMMANDS[0x10C]
                                )
                                or (
                                    fault == "stop"
                                    and wire == DMCI_WIRE_COMMANDS[0x10E]
                                )
                            )
                            body = struct.pack("<I", 9 if failed else 0)
                        return NativeVimReply(wire | 0x80, 6, body).encode()

                    client = NativeVimClient(
                        exchange,
                        capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                        clock=lambda: 0,
                    )

                    def cancellation(fault=fault, calls=calls):
                        return fault == "cancel" and DMCI_WIRE_COMMANDS[0x10C] in calls

                    if fault and fault != "idmap":
                        expected = TimeoutError if fault == "host" else Exception
                        with self.assertRaises(expected) as raised:
                            run_variable_multi_dmci(
                                targets,
                                controller,
                                client,
                                packet_limits=(1, 1),
                                limits=Limits(10, 64),
                                cancelled=cancellation,
                            )
                        if fault == "host":
                            self.assertIs(raised.exception, uncertainty)
                        if fault == "cancel":
                            self.assertIsInstance(raised.exception, RecorderCancelled)
                        if fault == "setup":
                            assert isinstance(raised.exception, MonitorError)
                            self.assertEqual(raised.exception.code, 0xA0050425)
                        if fault == "native":
                            assert isinstance(raised.exception, MonitorError)
                            self.assertEqual(raised.exception.code, 0xA1050301)
                        if fault == "start":
                            assert isinstance(raised.exception, MonitorError)
                            self.assertEqual(raised.exception.code, 0xA0050421)
                        if fault == "stop":
                            assert isinstance(raised.exception, MonitorError)
                            self.assertEqual(raised.exception.code, 0xA0050431)
                        if fault == "read-status":
                            assert isinstance(raised.exception, MonitorError)
                            self.assertEqual(raised.exception.code, 0xA1050307)
                    else:
                        captures = run_variable_multi_dmci(
                            targets,
                            controller,
                            client,
                            packet_limits=(1, 1),
                            limits=Limits(10, 64),
                        )
                        self.assertEqual(
                            tuple(items[0].payload for items in captures),
                            tuple(bytes((key, key)) for key in keys),
                        )
                        self.assertEqual(calls.count(DMCI_WIRE_COMMANDS[0x101]), 1)
                        self.assertEqual(calls.count(DMCI_WIRE_COMMANDS[0x107]), 1)
                        self.assertEqual(calls.count(DMCI_WIRE_COMMANDS[0x111]), 2)
                        self.assertEqual(calls.count(DMCI_WIRE_COMMANDS[0x10A]), 2)
                        self.assertEqual(calls.count(DMCI_WIRE_COMMANDS[0x10C]), 1)
                    self.assertEqual(
                        calls[-3:],
                        [DMCI_WIRE_COMMANDS[key] for key in (0x10E, 0x108, 0x104)],
                    )
                    self.assertNotIn(DMCI_WIRE_COMMANDS[0x114], calls)
                    self.assertNotIn(DMCI_WIRE_COMMANDS[0x116], calls)

            _, targets, _ = authored_multi(build=build)
            controller = targets[0].connection
            assert controller is not None
            calls = []

            def unexpected(request, *, deadline, cancelled, calls=calls):
                calls.append(request)
                raise AssertionError("Invalid controller order reached native I/O")

            client = NativeVimClient(
                unexpected,
                capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
            )
            with self.assertRaises(MonitorError) as rejected:
                run_variable_multi_dmci(
                    tuple(reversed(targets)), controller, client, packet_limits=(1, 1)
                )
            self.assertIsNone(rejected.exception.code)
            self.assertEqual(calls, [])

    def test_cooperative_device4_runtime_actual_slots_and_native_host_commands(self):
        from test_monitor_poll import authored_multi

        from scripts.drive_recorder import (
            DMCI_WIRE_COMMANDS,
            NativeCoreBuffer,
            NativeDmciList,
            NativeMonitorReply,
            NativeVimClient,
            NativeVimReply,
            decode_vim_command,
        )
        from scripts.monitor_support import monitor_source_identity
        from scripts.monitor_variable import VariableActiveOperation
        from scripts.toyota_session import Cancelled, Limits

        for fault in (
            "native-data",
            "cancel-after-data",
            False,
            "native-active",
            "native-system",
            "host-active",
        ):
            with self.subTest(fault=fault):
                _, targets, _ = authored_multi()
                controller = targets[0].connection
                assert controller is not None
                calls = []
                empty = NativeCoreBuffer((1, 0), b"")
                uncertainty = TimeoutError("authored active host uncertainty")
                cancelled_now = [False]

                def exchange(
                    request,
                    *,
                    deadline,
                    cancelled,
                    calls=calls,
                    targets=targets,
                    fault=fault,
                    empty=empty,
                    uncertainty=uncertainty,
                ):
                    wire, _ = decode_vim_command(request)
                    calls.append(wire)
                    if wire == DMCI_WIRE_COMMANDS[0x10F] and fault == "host-active":
                        raise uncertainty
                    if wire == DMCI_WIRE_COMMANDS[0x10D]:
                        body = NativeMonitorReply(
                            0,
                            NativeDmciList(
                                (1, 0),
                                tuple(
                                    (
                                        target.cache.profile.category,
                                        NativeCoreBuffer(
                                            (1, 0), struct.pack("<I", 7) + b"AB"
                                        ),
                                    )
                                    for target in targets
                                ),
                            ),
                            (
                                empty,
                                NativeCoreBuffer(
                                    (1, 0),
                                    struct.pack("<IIIB", 0x7E0, 0, 0xE0000103, 0),
                                )
                                if fault == "native-data"
                                else empty,
                                empty,
                                empty,
                                empty,
                            ),
                            2 if fault == "native-data" else 0,
                        ).encode()
                    else:
                        failed = (
                            fault == "native-active"
                            and wire == DMCI_WIRE_COMMANDS[0x10F]
                        ) or (
                            fault == "native-system"
                            and wire == DMCI_WIRE_COMMANDS[0x113]
                        )
                        body = struct.pack("<I", 9 if failed else 0)
                    return NativeVimReply(wire | 0x80, 6, body).encode()

                client = NativeVimClient(
                    exchange,
                    capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                    clock=lambda: 0,
                )
                runtime = VariableMonitorRuntime(
                    targets,
                    client,
                    connected_device=4,
                    controller_connection=controller,
                    limits=Limits(10, 128),
                    clock=lambda: 0,
                    cancelled=lambda cancelled_now=cancelled_now: cancelled_now[0],
                )
                runtime.start()
                if fault == "native-data":
                    with self.assertRaises(MonitorError) as native_data:
                        runtime.step()
                    self.assertEqual(native_data.exception.code, 0xA1050301)
                    self.assertEqual(runtime.get_fault(), 0xA1050301)
                    self.assertEqual(
                        tuple(len(capture.packets) for capture in runtime.captures),
                        (1, 1),
                    )
                    from scripts.monitor_variable import VariableDmciWorker

                    assert isinstance(runtime.worker, VariableDmciWorker)
                    self.assertEqual(runtime.worker.completion_count, 2)
                    self.assertEqual(runtime.state, "fault")
                else:
                    runtime.step()
                if fault == "cancel-after-data":
                    cancelled_now[0] = True
                    with self.assertRaises(Cancelled):
                        runtime.step()
                    self.assertEqual(runtime.get_fault(), 0)
                    self.assertEqual(
                        tuple(len(capture.packets) for capture in runtime.captures),
                        (1, 1),
                    )
                    self.assertEqual(runtime.state, "fault")
                if fault in ("native-data", "cancel-after-data"):
                    from scripts.snapshot import MonitorBuffer, TableFile, parse

                    metadata = MonitorBuffer(
                        b"engine", bytes(16), b"", b"", b"", b"", 0, (), (), b"", ()
                    )
                    info = {
                        "identifier": 0,
                        "strings": [{"core": [1, 0], "data_hex": "00"}] * 2,
                        "value_raw": 0,
                    }
                    exported = parse(runtime.dm_bytes(0, metadata, info))
                    assert isinstance(exported, TableFile)
                    self.assertEqual(
                        [table.id for table in exported.tables], [0x8100, 0x8101]
                    )
                    self.assertEqual(
                        calls[-3:],
                        [DMCI_WIRE_COMMANDS[key] for key in (0x10E, 0x108, 0x104)],
                    )
                    continue
                profile = targets[0].cache.profile
                system = selected_variable_system_operation(
                    profile,
                    0x1234,
                    source=VariableMonitorSource.for_build(18),
                    observed_bus_id=0x12,
                    controller_category_flags=4,
                )
                command96 = runtime.enqueue(96, system)
                runtime.step()
                active = VariableActiveOperation(
                    VariableMonitorSource.for_build(18),
                    profile,
                    monitor_source_identity(profile, "")[1:],
                    7,
                    b"\x30\x12",
                    0,
                    controller.address.request_id,
                )
                command11 = runtime.enqueue(11, active)
                runtime.step()
                command12 = runtime.enqueue(12)
                runtime.step()
                self.assertTrue(
                    all(
                        result.completed for result in (command96, command11, command12)
                    )
                )
                self.assertEqual(
                    command96.status, 0xA0051401 if fault == "native-system" else 0
                )
                if fault == "native-active":
                    self.assertEqual(command11.status, 0xA0050441)
                elif fault == "host-active":
                    self.assertIs(command11.error, uncertainty)
                    self.assertIsNone(command11.status)
                else:
                    self.assertEqual(command11.status, 0)
                self.assertEqual(command12.status, 0)
                captures = runtime.stop()
                self.assertEqual(
                    tuple(len(capture.packets) for capture in captures), (4, 4)
                )
                self.assertEqual(
                    tuple(capture.packets[0].payload for capture in captures),
                    (b"AB", b"AB"),
                )
                self.assertEqual(
                    calls[-3:],
                    [DMCI_WIRE_COMMANDS[key] for key in (0x10E, 0x108, 0x104)],
                )
                self.assertEqual(runtime.get_fault(), 0)
                self.assertEqual(runtime.state, "stopped")

        runtime = VariableMonitorRuntime(
            targets,
            client,
            connected_device=4,
            controller_connection=controller,
            limits=Limits(10, 128),
            clock=lambda: 0,
        )
        captures = runtime.run((1, 1))
        self.assertEqual(tuple(len(capture.packets) for capture in captures), (1, 1))
        self.assertEqual(runtime.state, "stopped")

        from scripts.snapshot import MonitorBuffer, TableFile, parse

        metadata = MonitorBuffer(
            b"engine", bytes(16), b"", b"", b"", b"", 0, (), (), b"", ()
        )
        info = {
            "identifier": 0,
            "strings": [{"core": [1, 0], "data_hex": "00"}] * 2,
            "value_raw": 0,
        }
        exported = parse(runtime.dm_bytes(0, metadata, info))
        assert isinstance(exported, TableFile)
        self.assertEqual([table.id for table in exported.tables], [0x8100, 0x8101])
        self.assertEqual(runtime.captures[0].packets[0].timestamp_ms, 7)

    def test_concrete_outer_runtime_capture_export_fault_and_host_cleanup(self):
        from test_monitor_j2534 import authored_operations

        from scripts.data_monitor import P4Packing, p4_setup_commands
        from scripts.drive_recorder import RecorderCancelled, native_monitor_buffer
        from scripts.monitor_j2534 import DirectJ2534Worker
        from scripts.monitor_support import monitor_source_identity
        from scripts.monitor_variable import SelectedVariableMonitor
        from scripts.snapshot import MonitorBuffer, TableFile, parse
        from scripts.toyota_session import Limits

        def selected(
            *, failure=0, cancelled=lambda: False, system=False, allocation=128
        ):
            operations, backend = authored_operations(failure=failure)
            profile = operations.profile
            from scripts.profiles import VehicleProfile

            assert isinstance(profile, VehicleProfile)
            connection = selected_p4_connection(
                profile,
                bus_id=0x12,
                diagnostic_mode=bytes(16),
                controller_category_flags=4,
            )
            cache = MonitorSupportCache(
                profile, lambda query: b"", "engine", bus_id=0x12, clock=lambda: 10
            )
            definitions = MonitorDefinitions(
                (1,), (), (), "authored", monitor_source_identity(profile, "")
            )
            packing = P4Packing(0x10, 4, (), (b"\x01\x0c", b"\x01\x02"), ((0, 2),), ())
            commands = p4_setup_commands(
                packing,
                interface_id=0x7E0,
                buffer_468=profile.category,
                total_length=2,
                standard_values=(),
                attribute_2_23=False,
            )
            plan = SelectedVariableMonitor(
                definitions, packing, (), ((0, 2),), commands, (), 18, cache.identity
            )
            buffer = native_monitor_buffer(
                profile.category,
                (),
                ((0, 2),),
                (1,),
                phase=0,
                allocation_size=allocation,
                name=b"engine\0",
                text_encoding="utf-8",
            )
            target = VariableRuntimeTarget(plan, cache, connection, 0x7E0, buffer)
            if system:
                system_operation = selected_variable_system_operation(
                    profile,
                    0x1234,
                    source=VariableMonitorSource.for_build(18),
                    observed_bus_id=0x12,
                    controller_category_flags=4,
                )
                invoke = backend.invoke

                def with_system(operation, fields, *, deadline, cancelled):
                    result = invoke(
                        operation, fields, deadline=deadline, cancelled=cancelled
                    )
                    if operation == "read_messages" and backend.request[:1] == b"\x08":
                        return replace(
                            result,
                            messages=tuple(
                                replace(message, data=message.data[:4] + b"\x48")
                                for message in result.messages
                            ),
                        )
                    return result

                backend.invoke = with_system
            else:
                system_operation = None
            runtime = VariableMonitorRuntime(
                (target,),
                operations,
                clock=lambda: 10,
                ticks=lambda: 1234,
                limits=Limits(10, 256),
                cancelled=cancelled,
                system=system_operation,
            )
            return runtime, operations, backend, cache

        # Actual running worker: command11 enters30, command12 queues30 end,
        # then outer Stop must tolerate that pending end before its reply.
        from scripts.monitor_variable import VariableActiveOperation

        live, live_ops, live_backend, _ = selected()
        rejected = live.enqueue(11)
        self.assertEqual(rejected.status, 0x90050405)
        self.assertEqual(live_backend.calls, [])
        live.start()
        profile = live.targets[0].cache.profile
        from scripts.profiles import VehicleProfile

        assert isinstance(profile, VehicleProfile)
        active = VariableActiveOperation(
            VariableMonitorSource.for_build(18),
            profile,
            monitor_source_identity(profile, "")[1:],
            7,
            b"\x30\x12",
            0,
            0x7E0,
        )
        invoke = live_backend.invoke

        def active_replies(operation, fields, *, deadline, cancelled):
            result = invoke(operation, fields, deadline=deadline, cancelled=cancelled)
            if operation == "read_messages" and live_backend.request[:1] == b"\x30":
                payload = b"\x70" if live_backend.request == b"\x30" else b"\x70\x12"
                return replace(
                    result,
                    messages=tuple(
                        replace(message, data=message.data[:4] + payload)
                        for message in result.messages
                    ),
                )
            return result

        live_backend.invoke = active_replies
        command11 = live.enqueue(11, active)
        for _ in range(3):
            live.step()
        self.assertTrue(command11.completed)
        self.assertEqual(command11.status, 0)
        self.assertIsNone(command11.error)
        self.assertEqual(live_backend.request, b"\x30\x12")
        assert isinstance(live.worker, DirectJ2534Worker)
        while live.worker.state != "select":
            live.step()
        command12 = live.enqueue(12)
        live.step()
        self.assertTrue(command12.completed)
        self.assertEqual(command12.status, 0)
        live.stop()
        self.assertIsNone(live_ops.channel)
        self.assertEqual(live.state, "stopped")
        self.assertEqual(live_backend.request, b"\x30")
        calls_after_stop = len(live_backend.calls)
        self.assertEqual(live.enqueue(96).status, 0x90050405)
        self.assertEqual(len(live_backend.calls), calls_after_stop)

        live, live_ops, live_backend, _ = selected(system=True)
        system_operation = live.system
        assert system_operation is not None
        # Inject96 after acquisition has started, rather than an initial slot.
        live.system = None
        assert isinstance(live.worker, DirectJ2534Worker)
        live.worker.events = (None, None, live.worker.events[2])
        live.start()
        invalid = live.enqueue(11)
        live.step()
        self.assertEqual(invalid.status, 0xC0050001)
        self.assertIs(invalid.error, live.command_results[-1].error)
        while live.worker.state != "select":
            live.step()
        command96 = live.enqueue(96, system_operation)
        for _ in range(3):
            live.step()
        self.assertEqual(command96.status, 0)
        self.assertEqual(live_backend.request, b"\x08\x34")
        live.stop()
        self.assertIsNone(live_ops.channel)
        self.assertTrue(live.captures[0].packets)

        cancelled_now = [False]
        live, live_ops, _, _ = selected(cancelled=lambda: cancelled_now[0])
        live.start()
        pending = live.enqueue(96, system_operation)
        cancelled_now[0] = True
        with self.assertRaises(RecorderCancelled):
            live.step()
        self.assertEqual(live.state, "fault")
        self.assertIsNone(live_ops.channel)
        self.assertEqual(live.get_fault(), 0)
        self.assertTrue(pending.completed)

        live, live_ops, live_backend, _ = selected()
        live.start()
        live.step()
        live.step()
        timeout = TimeoutError("authored receive uncertainty")
        invoke = live_backend.invoke

        def host_timeout(operation, fields, *, deadline, cancelled):
            if operation == "read_messages":
                raise timeout
            return invoke(operation, fields, deadline=deadline, cancelled=cancelled)

        live_backend.invoke = host_timeout
        with self.assertRaises(TimeoutError) as raised:
            live.step()
        self.assertIs(raised.exception, timeout)
        self.assertEqual(live.get_fault(), 0)
        self.assertIsNone(live_ops.channel)

        runtime, operations, backend, cache = selected()
        with self.assertRaises(MonitorError) as allocation_error:
            selected(allocation=5)
        self.assertEqual(allocation_error.exception.code, 0xA005060E)
        captures = runtime.run((1,))
        self.assertEqual(len(captures[0].packets), 1)
        self.assertEqual(captures[0].packets[0].payload, b"\xaa\xbb")
        self.assertEqual(runtime.state, "stopped")
        assert isinstance(runtime.worker, DirectJ2534Worker)
        self.assertEqual(runtime.worker.native_worker_class, "base")
        self.assertIsNone(operations.channel)
        metadata = MonitorBuffer(
            b"engine", bytes(16), b"", b"", b"", b"", 0, (), (1,), b"", ()
        )
        system = {
            "identifier": 0,
            "strings": [{"core": [1, 0], "data_hex": "00"}] * 2,
            "value_raw": 0,
        }
        exported = parse(runtime.dm_bytes(0, metadata, system))
        assert isinstance(exported, TableFile)
        self.assertEqual([table.id for table in exported.tables], [0x8100, 0x8101])
        from scripts.drive_recorder import (
            DrsFile,
            DrsTable,
            NativeCoreString,
            NativeDmciCommand,
            NativeTriggerInfo,
            NativeTriggerParameters,
            NativeVehicleSelection,
            decode_command,
        )

        selection = NativeVehicleSelection(
            (1, 0),
            NativeCoreString((1, 0), b"\0"),
            ((1, 0), (1, 0), (1, 0)),
            (),
            (),
            (),
            (0, 0),
        )
        trigger = NativeTriggerInfo((1, 0), 1, 1, 0)
        parameters = NativeTriggerParameters((1, 0), 1, 0, (1, 0), (), (1, 0), ())
        recording = selected_variable_recording(
            runtime.targets[0],
            selection,
            system,
            trigger,
            parameters,
            connected_device=8,
            enable_mode=0x10,
        )
        self.assertEqual(DrsFile.parse(recording.encode()), recording)
        groups = {}
        for table in recording.tables:
            if table.table_id not in (0x11, 0x12):
                continue
            children = decode_command(table)["children"]
            assert isinstance(children, tuple)
            commands = []
            for child in children:
                assert isinstance(child, DrsTable)
                command = decode_command(child)["dmci"]
                assert isinstance(command, NativeDmciCommand)
                commands.append(command.command_id)
            groups[table.table_id] = tuple(commands)
        self.assertEqual(groups[0x11], (0x101, 0x107, 0x111, 0x10A, 0x10C))
        self.assertEqual(groups[0x12], (0x10E, 0x108, 0x104))
        with self.assertRaises(MonitorError) as disabled:
            selected_variable_recording(
                runtime.targets[0],
                selection,
                system,
                trigger,
                parameters,
                connected_device=8,
                enable_mode=1,
            )
        self.assertEqual(disabled.exception.code, 0xC005100D)
        with self.assertRaises(MonitorError) as raised:
            runtime.run((1,))
        self.assertEqual(raised.exception.code, 0x90050405)
        cache.source_build = 12
        with self.assertRaises(MonitorError):
            runtime.dm_bytes(0, metadata, system)
        runtime.close()
        self.assertEqual(runtime.state, "closed")

        runtime, operations, backend, _ = selected(system=True)
        self.assertEqual(len(runtime.run((1,))[0].packets), 1)
        assert isinstance(runtime.worker, DirectJ2534Worker)
        system_event = runtime.worker.events[1]
        assert system_event is not None
        self.assertEqual(system_event.items[0].request, b"\x08\x34")
        self.assertEqual(system_event.item.status, 4)
        self.assertIsNone(operations.channel)

        runtime, operations, backend, _ = selected(failure=7)
        with self.assertRaises(MonitorError):
            runtime.run((1,))
        self.assertNotEqual(runtime.get_fault(), 0)
        self.assertEqual(runtime.get_fault(0), runtime.get_fault())
        self.assertEqual(runtime.get_fault(2), 0)
        self.assertIsNone(operations.channel)
        self.assertTrue(any(name == "disconnect" for name, _ in backend.calls))
        runtime, operations, _, _ = selected(allocation=12)
        captures = runtime.run((3,))
        self.assertEqual(len(captures[0].packets), 1)
        self.assertEqual(runtime.rings[0].capacity, 12)
        self.assertEqual(runtime.rings[0].active_size, 6)
        self.assertIsNotNone(captures[0].ring_images)
        self.assertIsNone(operations.channel)
        runtime, operations, _, _ = selected(cancelled=lambda: True)
        with self.assertRaises(RecorderCancelled):
            runtime.run((1,))
        self.assertEqual(runtime.get_fault(), 0)
        self.assertIsNone(operations.channel)
        runtime, operations, _, _ = selected()
        assert isinstance(runtime.worker, DirectJ2534Worker)
        runtime.worker.max_steps = 1
        with self.assertRaises(MonitorError):
            runtime.run((1,))
        self.assertEqual(runtime.get_fault(), 0)
        self.assertIsNone(operations.channel)

    def test_outer_multimon_selected_slots_both_source_builds(self):
        from test_monitor_poll import authored_multi

        from scripts.toyota_session import Limits

        for build in (12, 18):
            operations, targets, backend = authored_multi(build=build)
            runtime = VariableMonitorRuntime(
                targets,
                operations,
                clock=lambda: 0,
                ticks=lambda: 1234,
                limits=Limits(10, 256),
            )
            captures = runtime.run((2, 2))
            self.assertEqual(
                tuple(len(capture.packets) for capture in captures), (2, 2)
            )
            self.assertTrue(all(runtime.get_fault(index) == 0 for index in range(3)))
            self.assertEqual(runtime.state, "stopped")
            self.assertIsNone(operations.control.channel)
            self.assertEqual(sum(name == "connect" for name, _ in backend.calls), 1)
            self.assertTrue(any(name == "disconnect" for name, _ in backend.calls))
            runtime.close()

    def test_selected_single_multi_check_and_host_bounds(self):
        from scripts.monitor_legacy import LegacyCheckTarget
        from scripts.toyota_session import Cancelled, Limits, SessionError

        with tempfile.TemporaryDirectory() as directory:
            profile = authored_profile(Path(directory) / "fixture")
            calls = []

            class Stream:
                def send(self, query):
                    self.reads = 0
                    calls.append(query)
                    return 0

                def receive(self, query):
                    calls.append(query)
                    self.reads += 1
                    return (
                        (0, b"\x53\0\11\2\x80\0")
                        if self.reads == 1
                        else (0x91010009, b"")
                    )

            def transaction(query):
                raise AssertionError("Actual native support must use stream")

            observed = {key: key == 22 for key in (22, 12, 25, 11, 26, 29, 27, 28, 35)}
            target = LegacyCheckTarget(
                profile,
                (4,),
                "engine",
                0x12,
                observed,
                transaction,
                source_build=18,
                support_stream=Stream(),
            )
            single = check_variable_monitor(
                (target,),
                command_kind=7,
                allocation=11,
                connected_device=4,
                command_ecu=1,
            )
            self.assertTrue(single.available)
            self.assertEqual(
                single.measurements[0].measurement, VariableMeasurement(4, 6, 11)
            )
            category = bytearray(profile.category_record)
            struct.pack_into("<H", category, 68, 0x68)
            voltage = replace(
                target,
                profile=replace(profile, category_record=bytes(category)),
                ecu="voltage",
                bus_id=0,
                support_stream=None,
            )
            multi = check_variable_monitor(
                (target, voltage),
                command_kind=0x42,
                allocation=10,
                connected_device=4,
                command_ecu=1,
            )
            self.assertEqual(multi.excluded, 0)
            self.assertEqual(tuple(item.mode for item in multi.measurements), (4, 64))
            self.assertEqual(
                tuple(item.measurement.allocation for item in multi.measurements),
                (5, 5),
            )
            before = len(calls)
            with self.assertRaises(MonitorError) as absent:
                check_variable_monitor(
                    None,
                    command_kind=7,
                    allocation=1,
                    connected_device=4,
                    command_ecu=1,
                )
            self.assertEqual(absent.exception.code, 0xC0050401)
            with self.assertRaises(MonitorError) as result:
                check_variable_monitor(
                    (target, voltage),
                    command_kind=7,
                    allocation=1,
                    connected_device=4,
                    command_ecu=1,
                )
            self.assertEqual(result.exception.code, 0xC0050404)
            self.assertEqual(len(calls), before)
            with self.assertRaises(Cancelled):
                check_variable_monitor(
                    (target,),
                    command_kind=7,
                    allocation=1,
                    connected_device=4,
                    command_ecu=1,
                    cancelled=lambda: True,
                )
            self.assertEqual(len(calls), before)
            with self.assertRaises(SessionError):
                check_variable_monitor(
                    (target,),
                    command_kind=7,
                    allocation=1,
                    connected_device=4,
                    command_ecu=1,
                    limits=Limits(exchanges=1),
                )
            self.assertEqual(len(calls), before + 1)

    def test_distinct_flag9_child_selected_cache_and_actual109(self):
        from scripts.diagnostic_db import Section
        from scripts.drive_recorder import NativeDmciCommand

        with tempfile.TemporaryDirectory() as directory:
            profile = authored_profile(Path(directory) / "fixture")
            category = bytearray(profile.category_record)
            category[72] = 9
            sections = dict(profile.database.sections)
            sections.pop(3, None)
            sections[6] = Section(6, 0, 1, False, bytes((0, 0, 9, 0, 1, 2, 0, 0)))
            profile = replace(
                profile,
                category_record=bytes(category),
                database=replace(profile.database, sections=sections),
            )
            sections = dict(profile.catalog.management.sections)
            sections[16] = Section(16, 0, 1, False, bytes(category))
            sections[18] = Section(
                18, 0, 1, False, struct.pack("<8H", 1, 15, 1, 9, 0, 1, 0, 0)
            )
            profile.catalog.management = replace(
                profile.catalog.management, sections=sections
            )
            queries = []

            def exchange(query):
                queries.append(query.request)
                return bytes((query.request[0] + 0x40,)) + query.request[1:] + b"AB"

            cache = MonitorSupportCache(
                profile, exchange, "engine", bus_id=0x12, source_build=18
            )
            observed = {
                key: key == 8 for key in (22, 10, 8, 9, 12, 25, 11, 26, 29, 27, 28, 35)
            }
            plan = selected_variable_packet_monitor(
                cache,
                (4,),
                observed,
                communication_protocol=0x12,
                interface_id=0x7E0,
                excluded=0,
                max_request=12,
                max_reply=12,
            )
            self.assertEqual(len(queries), 1)
            self.assertEqual(plan.packing.setup_requests, (b"\xa1\x01\x09\xff",))
            self.assertEqual(plan.commands.setup[0].command_id, 0x109)
            self.assertEqual(
                NativeDmciCommand.from_neutral(
                    0x109, plan.commands.setup[0].values
                ).command_id,
                0x109,
            )
            self.assertEqual(plan.source_identity, cache.identity)
            self.assertEqual(plan.source_build, 18)
            target_category = bytearray(profile.category_record)
            target_category[72] = 4
            target_profile = replace(profile, category_record=bytes(target_category))
            target_cache = MonitorSupportCache(
                target_profile, exchange, "other-target", bus_id=0x12, source_build=18
            )
            with self.assertRaises(MonitorError):
                selected_variable_packet_monitor(
                    target_cache,
                    (4,),
                    observed,
                    communication_protocol=0x12,
                    interface_id=0x7E0,
                    excluded=0,
                    max_request=12,
                    max_reply=12,
                )
            controller_selected = selected_variable_packet_monitor(
                target_cache,
                (4,),
                observed,
                communication_protocol=0x12,
                interface_id=0x7E0,
                excluded=0,
                max_request=12,
                max_reply=12,
                controller_category_flags=9,
            )
            self.assertEqual(controller_selected.packing, plan.packing)
            self.assertEqual(target_profile.category_record[72], 4)
            measured = check_variable_target_from_cache(
                cache, (4,), observed, excluded=0
            )
            self.assertEqual(measured.measurement, VariableMeasurement(4, 6))
            protocol = bytearray(profile.catalog.management.sections[13].payload)
            protocol[24] = 0x11
            profile.catalog.management.sections[13] = replace(
                profile.catalog.management.sections[13], payload=bytes(protocol)
            )
            iso_cache = MonitorSupportCache(
                profile, exchange, "engine", bus_id=0x11, source_build=18
            )
            connection = selected_p4_connection(
                profile,
                bus_id=0x11,
                diagnostic_mode=bytes(16),
                controller_category_flags=9,
            )
            iso_plan = selected_variable_packet_monitor(
                iso_cache,
                (4,),
                observed,
                communication_protocol=0x11,
                interface_id=connection.address.request_id,
                excluded=0,
                max_request=12,
                max_reply=12,
            )
            self.assertEqual(iso_plan.packing, plan.packing)
            self.assertEqual(
                check_variable_target_from_cache(
                    iso_cache, (4,), observed, excluded=0
                ).measurement,
                VariableMeasurement(65, 6),
            )
            iso_record = bytearray(56)
            struct.pack_into("<H", iso_record, 4, 7)
            lifecycle = variable_dmci_lifecycle(
                iso_plan,
                connection,
                connected_device=4,
                iso_record=bytes(iso_record),
                init_mode=2,
                parameter_c0=123,
            )
            self.assertEqual(lifecycle.setup[0].command_id, 0x100)
            self.assertEqual(lifecycle.setup[0].values[2:5], (1, 0xC6, 123))
            self.assertNotIn(0x114, [item.command_id for item in lifecycle.setup])
            self.assertNotIn(0x116, [item.command_id for item in lifecycle.setup])

    def test_actual_voltage_selection_and_native_retry_host_boundaries(self):
        from scripts.monitor_dlc12 import DLC12VoltageState
        from scripts.toyota_session import Cancelled, Limits

        with tempfile.TemporaryDirectory() as directory:
            profile = authored_profile(Path(directory) / "fixture")
            category = bytearray(profile.category_record)
            struct.pack_into("<H", category, 68, 0x68)
            profile = replace(profile, category_record=bytes(category))
            cache = MonitorSupportCache(
                profile,
                lambda query: (_ for _ in ()).throw(
                    AssertionError("No voltage exchange")
                ),
                "voltage",
                bus_id=0,
                source_build=18,
            )
            selected = selected_variable_voltage_monitor(
                cache, (4,), voltage_state=DLC12VoltageState(0)
            )
            measured = check_variable_target_from_cache(cache, (4,), {}, excluded=0)
            target = selected_variable_runtime_target(
                selected,
                cache,
                None,
                measurement=replace(
                    measured, measurement=replace(measured.measurement, allocation=128)
                ),
                diagnostic_mode=None,
                phase=0,
                name=b"voltage\0",
                text_encoding="utf-8",
            )
            from test_monitor_j2534 import authored_operations

            operations, backend = authored_operations()
            runtime = VariableMonitorRuntime(
                (target,), operations, limits=Limits(exchanges=2)
            )
            with (
                patch(
                    "scripts.monitor_variable.VoltageMonitorInterface.get_error",
                    return_value=0,
                ),
                self.assertRaises(MonitorError) as voltage_failure,
            ):
                runtime.run((1,))
            self.assertEqual(voltage_failure.exception.code, 0x90051205)
            self.assertEqual(backend.calls, [])
            runtime.close()
            from test_monitor_poll import authored_multi

            from scripts.frame_transport import NativeMultiMonOperations
            from scripts.monitor_poll import MultiMonitorPollingWorker

            prototype, communication_targets, multi_backend = authored_multi()
            communication = communication_targets[0]
            record = bytearray(communication.cache.profile.category_record)
            struct.pack_into("<H", record, 68, 0x68)
            from copy import copy

            voltage_catalog = copy(communication.cache.profile.catalog)
            voltage_catalog.language = profile.catalog.language
            voltage_profile = replace(
                communication.cache.profile,
                category_record=bytes(record),
                database=profile.database,
                catalog=voltage_catalog,
            )
            voltage_cache = MonitorSupportCache(
                voltage_profile,
                lambda q: b"",
                "voltage",
                bus_id=0,
                source_build=18,
                clock=lambda: 0,
            )
            voltage_plan = selected_variable_voltage_monitor(
                voltage_cache, (4,), voltage_state=DLC12VoltageState(0)
            )
            voltage_measurement = check_variable_target_from_cache(
                voltage_cache, (4,), {}, excluded=0
            )
            voltage_target = selected_variable_runtime_target(
                voltage_plan,
                voltage_cache,
                None,
                measurement=replace(
                    voltage_measurement,
                    measurement=replace(
                        voltage_measurement.measurement, allocation=128
                    ),
                ),
                diagnostic_mode=None,
                phase=0,
                name=b"voltage\0",
                text_encoding="utf-8",
            )
            multi_operations = NativeMultiMonOperations(
                prototype.targets[:1],
                prototype.profiles,
                multi_backend,
                driver=prototype.operations.driver,
                native_build=18,
                source_identity=prototype.control.source_identity,
                device_kind=8,
                clock=lambda: 0,
                wait=lambda _: None,
            )
            mixed = VariableMonitorRuntime(
                (communication, voltage_target),
                multi_operations,
                clock=lambda: 0,
                limits=Limits(exchanges=2),
            )
            self.assertIsInstance(mixed.worker, MultiMonitorPollingWorker)
            with self.assertRaises(MonitorError) as unavailable:
                mixed.run((1, 1))
            self.assertIsNone(unavailable.exception.code)
            self.assertEqual(multi_backend.calls, [])
            mixed.close()

            self.assertEqual(selected.instrument.descriptors, (b"\4\0\0\0\1",))
            self.assertEqual(selected.measurement, VariableMeasurement(5, 6))
            self.assertEqual(
                check_variable_target_from_cache(
                    cache, (4,), {}, excluded=0
                ).measurement,
                selected.measurement,
            )
            with self.assertRaises(MonitorError) as result:
                variable_voltage_interface(
                    VariableMonitorSource.for_build(18), limits=Limits(exchanges=2)
                )
            self.assertIsNone(result.exception.code)
            self.assertIn("GetError=0xffffffff", str(result.exception))
            with self.assertRaises(Cancelled):
                variable_voltage_interface(
                    VariableMonitorSource.for_build(18), cancelled=lambda: True
                )
            ticks = iter((0, 2))
            with self.assertRaises(TimeoutError):
                variable_voltage_interface(
                    VariableMonitorSource.for_build(18),
                    limits=Limits(seconds=1),
                    clock=lambda: next(ticks),
                )
            with patch(
                "scripts.monitor_variable.VoltageMonitorInterface.get_error",
                side_effect=(0xFFFFFFFF, 0),
            ) as get_error:
                interface = variable_voltage_interface(
                    VariableMonitorSource.for_build(18), limits=Limits(exchanges=2)
                )
                self.assertEqual(get_error.call_count, 2)
                self.assertFalse(interface.setup(4, 1, object()))

    def test_selected_active_actual_dmci_fault_cancel_and_context_cleanup(self):
        from scripts.drive_recorder import (
            DMCI_WIRE_COMMANDS,
            NativeDmciCommand,
            NativeDmciError,
            NativeVimClient,
            NativeVimReply,
            RecorderCancelled,
            decode_vim_command,
        )

        for mode in ("success", "native", "cancel", "context", "cleanup", "host"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                profile = authored_profile(Path(directory) / "fixture")
                operation = selected_variable_active_operation(
                    profile,
                    4,
                    0x1234,
                    source=VariableMonitorSource.for_build(18),
                    observed_bus_id=0x12,
                )
                calls = []
                cancellation = [False]

                def exchange(
                    request,
                    *,
                    deadline,
                    cancelled,
                    calls=calls,
                    mode=mode,
                    profile=profile,
                    cancellation=cancellation,
                ):
                    wire, body = decode_vim_command(request)
                    calls.append((wire, body))
                    if len(calls) == 1:
                        if mode == "cancel":
                            cancellation[0] = True
                        if mode == "host":
                            raise TimeoutError("Host transport timeout")
                        if mode == "context":
                            profile.catalog.management = replace(
                                profile.catalog.management, sha256="changed"
                            )
                    status = int(
                        mode == "cleanup" or mode == "native" and len(calls) == 1
                    )
                    return NativeVimReply(
                        wire | 0x80, 6, struct.pack("<I", status)
                    ).encode()

                client = NativeVimClient(
                    exchange,
                    capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                )
                runtime = VariableActiveRuntime(operation, client)
                if mode == "success":
                    runtime.start()
                    self.assertEqual(runtime.state, "running")
                    runtime.stop(initialize=True)
                    self.assertEqual(runtime.state, "stopped")
                    runtime.stop()
                    with self.assertRaises(MonitorError):
                        runtime.start()
                else:
                    expected = (
                        RecorderCancelled
                        if mode == "cancel"
                        else TimeoutError
                        if mode == "host"
                        else MonitorError
                    )
                    with self.assertRaises(expected) as result:
                        runtime.start(
                            cancelled=lambda cancellation=cancellation: cancellation[0]
                        )
                    self.assertEqual(runtime.state, "fault")
                    if mode in ("native", "cleanup"):
                        assert isinstance(result.exception, MonitorError)
                        assert isinstance(result.exception.__cause__, NativeDmciError)
                        self.assertEqual(result.exception.code, 0xA0050441)
                        self.assertEqual(result.exception.__cause__.status, 1)
                    if mode == "context":
                        assert isinstance(result.exception, MonitorError)
                        self.assertIsNone(result.exception.code)
                    if mode == "cleanup":
                        self.assertIn(
                            "cleanup also failed", result.exception.__notes__[0]
                        )
                self.assertEqual(len(calls), 2)
                self.assertEqual(
                    calls[0],
                    (
                        DMCI_WIRE_COMMANDS[0x10F],
                        NativeDmciCommand.from_neutral(
                            0x10F, (0x7E0, b"\x39\x34\x12", 250)
                        ).encode(),
                    ),
                )
                self.assertEqual(
                    calls[1],
                    (
                        DMCI_WIRE_COMMANDS[0x110],
                        NativeDmciCommand.from_neutral(
                            0x110, (0x7E0, int(mode == "success"))
                        ).encode(),
                    ),
                )

    def test_actual_multitarget_bus_and_mask_branches(self):
        self.assertEqual(
            variable_target_mask(((1, 0x12), (2, 0x22)), connected_device=4), 5
        )
        self.assertEqual(
            variable_target_mask(
                ((0x68, 0), (2, 0x21)), connected_device=4, excluded=0x10002
            ),
            2,
        )
        self.assertEqual(
            variable_target_mask(((1, 0x11), (2, 0x11)), connected_device=8), 5
        )
        for targets in ((), ((1, 0x11), (2, 0x21)), ((1, 0x12), (2, 0x18))):
            with (
                self.subTest(targets=targets),
                self.assertRaises(MonitorError) as result,
            ):
                variable_target_mask(targets, connected_device=4)
            self.assertEqual(result.exception.code, 0xC0050001)

    def test_variable_native_callback_branches(self):
        for status in (0xE0000100, 0xE0000189, 0xE000018F, 0xE0000190):
            self.assertIsNone(variable_error_notification(1, status, 0, signal_id=9))
        for status in (0xE00001CC, 0xE00001CD):
            self.assertEqual(
                variable_error_notification(1, status, 0, signal_id=9),
                VariableNotification(0x602, 0, 9),
            )
        self.assertEqual(
            variable_error_notification(1, 0xE0000110, 0x122, signal_id=9),
            VariableNotification(0x602, 0, 9),
        )
        self.assertEqual(
            variable_error_notification(1, 0xE0000110, 0x21, signal_id=9),
            VariableNotification(0x603, 0xA1050312),
        )
        self.assertEqual(
            variable_error_notification(5, 0xE000FFFF, 0, signal_id=9),
            VariableNotification(0x608, 5),
        )
        self.assertEqual(
            variable_error_notification(1, 0xE0001000, 0, signal_id=9),
            VariableNotification(0x603, 0xA1050307),
        )

    def test_actual_connected_device_exclusions(self):
        self.assertEqual(variable_excluded_mask(4), 0)
        self.assertEqual(variable_excluded_mask(8), 5)
        self.assertEqual(variable_excluded_mask(4, target_count=2), 5)
        self.assertEqual(
            variable_excluded_mask(4, target_count=2, voltage_targets=1), 0
        )
        for device, status in ((1, 0xC0051301), (2, 0xC0051301), (3, 0xC0051302)):
            with self.assertRaises(MonitorError) as error:
                variable_excluded_mask(device)
            self.assertEqual(error.exception.code, status)

    def test_concrete_support_stream_to_distinct_plan_and_consumer(self):
        from scripts.drive_recorder import (
            DMCI_WIRE_COMMANDS,
            NativeCoreBuffer,
            NativeDmciCommand,
            NativeDmciList,
            NativeMonitorReply,
            NativeVimClient,
            NativeVimReply,
            decode_vim_command,
        )

        with tempfile.TemporaryDirectory() as directory:
            profile = authored_profile(Path(directory) / "fixture")
            calls = []

            class Stream:
                def send(self, query):
                    calls.append(query)
                    return 0

                def receive(self, query):
                    calls.append(query)
                    return (
                        (0, b"\x53\0\11\2\x80\0")
                        if len(calls) == 2
                        else (0x91010009, b"")
                    )

            def transaction(query):
                raise AssertionError("Unexpected non-stream transaction")

            cache = MonitorSupportCache(
                profile,
                transaction,
                "engine",
                bus_id=0x12,
                stream=Stream(),
                source_build=18,
            )
            observed = {key: False for key in (22, 12, 25, 11, 26, 29, 27, 28, 35)}
            observed[22] = True
            plan = selected_variable_monitor_from_cache(
                cache,
                (4,),
                observed,
                communication_protocol=0x12,
                attribute_3_31=True,
                interface_id=0x7E0,
                excluded=0,
                standard_values=(),
                max_request=12,
                max_reply=12,
            )
            self.assertEqual(len(calls), 3)
            self.assertEqual(plan.source_build, 18)
            self.assertEqual(plan.commands.setup[0].command_id, 0x109)
            measured = check_variable_target_from_cache(
                cache, (4,), observed, excluded=0
            )
            self.assertEqual(measured.measurement, VariableMeasurement(4, 6))
            command = plan.commands.setup[0]
            self.assertEqual(
                NativeDmciCommand.from_neutral(
                    command.command_id, command.values
                ).command_id,
                0x109,
            )
            before = len(calls)
            with self.assertRaises(MonitorError):
                selected_variable_monitor_from_cache(
                    cache,
                    (4,),
                    observed,
                    communication_protocol=0x12,
                    attribute_3_31=False,
                    interface_id=0x7E0,
                    excluded=0,
                    standard_values=(),
                    max_request=12,
                    max_reply=12,
                )
            self.assertEqual(len(calls), before)
            with self.assertRaises(MonitorError) as rejected:
                selected_variable_monitor_from_cache(
                    cache,
                    (4,),
                    observed,
                    communication_protocol=0x28,
                    attribute_3_31=True,
                    interface_id=0x7E0,
                    excluded=0,
                    standard_values=(),
                    max_request=12,
                    max_reply=12,
                )
            self.assertEqual(rejected.exception.code, 0xC0050001)
            self.assertEqual(len(calls), before)
            connection = selected_p4_connection(
                profile,
                bus_id=0x12,
                diagnostic_mode=bytes(16),
                controller_category_flags=4,
            )
            allocated = replace(
                measured, measurement=replace(measured.measurement, allocation=128)
            )
            runtime_target = selected_variable_runtime_target(
                plan,
                cache,
                connection,
                measurement=allocated,
                diagnostic_mode=bytes(16),
                phase=0,
                name=b"engine\0",
                text_encoding="utf-8",
            )
            from scripts.drive_recorder import NativeMonitorBuffer

            self.assertEqual(runtime_target.entry_parameter, 0x7E0)
            self.assertEqual(runtime_target.buffer.allocation_size, 128)
            different_check_mode = selected_variable_runtime_target(
                plan,
                cache,
                connection,
                measurement=replace(allocated, mode=0x10),
                diagnostic_mode=bytes(16),
                phase=0,
                name=b"engine\0",
                text_encoding="utf-8",
            )
            self.assertEqual(different_check_mode.buffer, runtime_target.buffer)
            self.assertEqual(
                runtime_target.buffer.value_before_buffer, profile.category
            )
            self.assertEqual(
                NativeMonitorBuffer.parse(runtime_target.buffer.encode()),
                runtime_target.buffer,
            )
            with self.assertRaises(MonitorError):
                selected_variable_runtime_target(
                    plan,
                    cache,
                    connection,
                    measurement=replace(allocated, category=2),
                    diagnostic_mode=bytes(16),
                    phase=0,
                    name=b"engine\0",
                    text_encoding="utf-8",
                )
            cache.source_build = 12
            with self.assertRaises(MonitorError):
                runtime_target.check()
            cache.source_build = 18
            for fault in (
                False,
                True,
                "native",
                "setup",
                "start",
                "stop",
                "idmap",
                "timeout",
                "wrong-key",
            ):
                wire_calls = []
                empty = NativeCoreBuffer((1, 0), b"")

                def exchange(
                    request,
                    *,
                    deadline,
                    cancelled,
                    wire_calls=wire_calls,
                    fault=fault,
                    empty=empty,
                ):
                    wire, request_payload = decode_vim_command(request)
                    wire_calls.append(wire)
                    if fault == "timeout" and wire == DMCI_WIRE_COMMANDS[0x109]:
                        raise TimeoutError("Host setup timeout")
                    if fault is True and len(wire_calls) == 1:
                        cache.source_build = 12
                    if wire == DMCI_WIRE_COMMANDS[0x10D]:
                        self.assertEqual(
                            request_payload,
                            NativeDmciCommand(
                                0x10D, (NativeDmciList((1, 0), ((profile.category,),)),)
                            ).encode(),
                        )
                        payload = NativeMonitorReply(
                            0,
                            NativeDmciList(
                                (1, 0),
                                (
                                    (
                                        connection.address.request_id
                                        if fault == "wrong-key"
                                        else profile.category,
                                        NativeCoreBuffer(
                                            (1, 0), struct.pack("<I", 9) + b"AB"
                                        ),
                                    ),
                                ),
                            ),
                            (
                                empty,
                                NativeCoreBuffer(
                                    (1, 0),
                                    struct.pack("<IIIB", 0x7E0, 0x123, 0xE0000103, 0),
                                )
                                if fault == "native"
                                else empty,
                                empty,
                                empty,
                                empty,
                            ),
                            0,
                        ).encode()
                    else:
                        failed = (
                            {
                                "setup": 0x109,
                                "start": 0x10C,
                                "stop": 0x10E,
                                "idmap": 0x111,
                            }.get(fault)
                            if isinstance(fault, str)
                            else None
                        )
                        payload = struct.pack(
                            "<I",
                            9
                            if failed is not None and wire == DMCI_WIRE_COMMANDS[failed]
                            else 0,
                        ) + (
                            struct.pack("<I", 1)
                            if wire == DMCI_WIRE_COMMANDS[0x114]
                            else b""
                        )
                    return NativeVimReply(wire | 0x80, 6, payload).encode()

                client = NativeVimClient(
                    exchange,
                    capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                )
                if fault == "timeout":
                    with self.assertRaises(TimeoutError):
                        run_variable_dmci(
                            plan,
                            cache,
                            connection,
                            client,
                            connected_device=4,
                            interrupt_send_timing=False,
                            packet_limit=1,
                        )
                elif fault and fault != "idmap":
                    with self.assertRaises(MonitorError) as result:
                        run_variable_dmci(
                            plan,
                            cache,
                            connection,
                            client,
                            connected_device=4,
                            interrupt_send_timing=False,
                            packet_limit=1,
                        )
                    if fault == "native":
                        self.assertEqual(result.exception.code, 0xA1050301)
                    elif fault in ("setup", "start", "stop"):
                        self.assertEqual(
                            result.exception.code,
                            {
                                "setup": 0xA0050425,
                                "start": 0xA0050421,
                                "stop": 0xA0050431,
                            }[fault],
                        )
                else:
                    packets = run_variable_dmci(
                        plan,
                        cache,
                        connection,
                        client,
                        connected_device=4,
                        interrupt_send_timing=False,
                        packet_limit=1,
                    )
                    self.assertEqual(
                        [(item.timestamp_raw, item.payload) for item in packets],
                        [(9, b"AB")],
                    )
                self.assertEqual(
                    wire_calls[-3:],
                    [DMCI_WIRE_COMMANDS[item] for item in (0x10E, 0x108, 0x104)],
                )
                self.assertNotIn(DMCI_WIRE_COMMANDS[0x114], wire_calls)
                self.assertNotIn(DMCI_WIRE_COMMANDS[0x116], wire_calls)
                cache.source_build = 18

    def test_selected_freeze_validity_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = authored_profile(Path(directory) / "valid")
            definitions = variable_definitions(profile, (4,))
            self.assertEqual(definitions.ranges[0].frame_id, 9)
            profile = authored_profile(Path(directory) / "invalid", freeze_flags=0)
            with self.assertRaises(MonitorError) as result:
                variable_definitions(profile, (4,))
            self.assertEqual(result.exception.code, 0xC0050102)

    def test_variable_support_ignores_normal_p4_byte77_switch(self):
        definitions = MonitorDefinitions(
            (4,), (MonitorRange(0, 15, 4, 9, 1, 1, 0),), (), "authored"
        )
        arguments = {
            "category_flags": 4,
            "capabilities": 4,
            "excluded": 0,
            "max_request": 12,
            "max_reply": 12,
        }
        packing = pack_variable(definitions, {9: b"\x80\0"}, **arguments)
        self.assertEqual(packing.setup_requests, (b"\xa1\6\11\2\1\2",))
        self.assertEqual(packing.ranges[0].byte_4d, 1)
        with self.assertRaises(MonitorError):
            pack_p4(definitions, {9: b"\x80\0"}, **arguments)

    def test_measurement_dispatch_and_remainder(self):
        self.assertEqual(
            variable_measurement(1, 0x11, (7, 8)), VariableMeasurement(207, 19)
        )
        self.assertEqual(
            variable_measurement(16, 0x11, (7, 8)), VariableMeasurement(320, 19)
        )
        self.assertEqual(
            variable_measurement(32, 0x12, (6, 7, 14)), VariableMeasurement(24, 31)
        )
        self.assertEqual(
            variable_measurement(64, 0, (2,), request_length=4),
            VariableMeasurement(4, 6),
        )
        values = allocate_variable_measurements(
            10, (VariableMeasurement(10, 3), VariableMeasurement(10, 6))
        )
        self.assertEqual(tuple(item.allocation for item in values), (3, 7))
        self.assertEqual(
            tuple(
                item.allocation
                for item in allocate_variable_measurements(
                    0xFFFFFFFF, (VariableMeasurement(10, 3), VariableMeasurement(10, 6))
                )
            ),
            (0, 1),
        )
        self.assertEqual(
            tuple(
                item.allocation
                for item in allocate_variable_measurements(
                    0x80000000, (VariableMeasurement(10, 3), VariableMeasurement(10, 3))
                )
            ),
            (0xC0000000, 0xC0000000),
        )
        self.assertEqual(
            allocate_variable_measurements(10, (VariableMeasurement(10, 3),))[
                0
            ].allocation,
            10,
        )
        for mode, bus, sizes in ((2, 0x11, (7,)), (1, 0x1A, (7,)), (1, 0x11, ())):
            with self.assertRaises(MonitorError):
                variable_measurement(mode, bus, sizes)
        with self.assertRaises(MonitorError):
            allocate_variable_measurements(1, (VariableMeasurement(0, 1),))

    def test_distinct_selected_provider(self):
        self.assertEqual(select_provider(4, 2, True), "DM_ActVariable_DT.dll")
        self.assertEqual(select_provider(4, 2, False), "DataMonitorPhase4.dll")

    def test_every_recovered_opcode(self):
        request, repeat = variable_active_request(
            *records(),
            bytes((1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 14, 15, 16, 17, 18, 255, 0, 13)),
            4,
            0x1234,
            auxiliary=9,
        )
        self.assertEqual(
            request,
            bytes(
                (
                    0x30,
                    0x39,
                    0,
                    0x34,
                    0xD0,
                    10,
                    10,
                    0x3E,
                    3,
                    9,
                    0,
                    0x12,
                    0,
                    0,
                    7,
                    3,
                    0,
                    0,
                )
            ),
        )
        self.assertEqual(repeat, 250)

    def test_native_rejected_opcodes(self):
        for opcode in (11, 12, 13):
            with self.subTest(opcode=opcode), self.assertRaises(MonitorError) as result:
                variable_active_request(*records(), bytes((opcode,)), 4, 1)
            self.assertEqual(result.exception.code, 0xC0050102)

    def test_phase_service_and_phase7_early_exit(self):
        for phase, sid in ((1, 0x6D), (2, 0x6D), (4, 0x30), (7, 0x3D), (0x27, 0x3D)):
            with self.subTest(phase=phase):
                request, repeat = variable_active_request(*records(), b"\2", phase, 8)
                self.assertEqual(
                    request, bytes((sid, 0x39)) + (b"" if phase & 31 == 7 else b"\10")
                )
                self.assertEqual(repeat, None if phase & 31 == 7 else 250)

    def test_bounds(self):
        self.assertEqual(
            variable_active_request(*records(), b"\10", 4, 0, auxiliary=0xFFFFFFFF)[0],
            b"\x30\x39\xff",
        )
        for instructions in (bytes(62), "bad"):
            with self.assertRaises(MonitorError):
                variable_active_request(*records(), instructions, 4, 1)  # type: ignore[arg-type]
        with self.assertRaises(MonitorError):
            variable_active_request(*records(), b"\2", 4, True)

    def test_explicit_source_build_and_forgery(self):
        for build in (12, 18):
            VariableMonitorSource.for_build(build).check()
        for build in (True, 0, 2026):
            with self.assertRaises(MonitorError):
                VariableMonitorSource.for_build(build)
        with self.assertRaises(MonitorError):
            VariableMonitorSource(None, 18, "0" * 64).check()

    def test_actual_selected_metadata_to_dmci_command(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = authored_profile(Path(directory) / "fixture")
            operation = selected_variable_active_operation(
                profile,
                4,
                0x1234,
                source=VariableMonitorSource.for_build(18),
                observed_bus_id=0x12,
            )
            self.assertEqual(
                operation.command,
                MonitorCommand(0x10F, (0x7E0, b"\x39\x34\x12", 250)),
            )
            self.assertEqual(operation.request, b"\x30\x39\x34\x12")
            event = operation.event()
            self.assertEqual(event.get_snd_frame(0), operation.request)
            self.assertEqual(event.check_rcv_frame(b"\x70\x39", 10), 0xE0000100)
            self.assertEqual(event.item.next_send, 260)
            self.assertEqual(
                operation.stop_command(initialize=True),
                MonitorCommand(0x110, (0x7E0, 1)),
            )
            for request in (b"", b"\x30", bytes(64)):
                with self.assertRaises(MonitorError) as result:
                    _ = replace(operation, request=request).command
                self.assertEqual(result.exception.code, 0xA0050441)
            forged = replace(operation, source_identity=())
            with self.assertRaises(MonitorError):
                _ = forged.command
            for bus, status in ((None, 0xC0040601), (0, 0xC0040602)):
                with self.assertRaises(MonitorError) as result:
                    selected_variable_active_operation(
                        profile,
                        4,
                        1,
                        source=VariableMonitorSource.for_build(18),
                        observed_bus_id=bus,
                    )
                self.assertEqual(result.exception.code, status)
            with self.assertRaises(MonitorError):
                selected_variable_active_operation(
                    profile,
                    999,
                    1,
                    source=VariableMonitorSource.for_build(18),
                    observed_bus_id=0x12,
                )


if __name__ == "__main__":
    unittest.main()
