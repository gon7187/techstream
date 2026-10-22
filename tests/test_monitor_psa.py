"""Authored PSA DDB, exact setup bytes and primitive polling regressions."""

import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any

from scripts.data_monitor import (
    MonitorDefinitions,
    MonitorError,
    MonitorRange,
    MonitorReceive,
)
from scripts.demo import _ddb, create_demo
from scripts.diagnostic_db import parse_database
from scripts.drive_recorder import (
    DrsFile,
    NativeCoreBuffer,
    NativeDmciCommand,
    NativeDmciList,
    NativeMonitorBuffer,
    NativeMonitorPacket,
    NativeMonitorRecorder,
    NativeMonitorReply,
    NativeMonitorSignal,
    NativeTriggerCondition,
    NativeTriggerInfo,
    NativeTriggerParameters,
    NativeVimClient,
    NativeVimReply,
    decode_command,
    decode_vim_command,
    encode_command,
    encode_native_mode21,
    native_monitor_buffer,
)
from scripts.frame_transport import (
    DriverProperties,
    FrameTransportError,
    J2534Result,
    NativeConfig,
    NativeMessage,
    get_comm_frame,
)
from scripts.monitor_legacy import LegacyMonitorEvent
from scripts.monitor_psa import (
    PSACheckTarget,
    PSAController,
    PSAControlMessage,
    PSAJ2534Monitor,
    PSAJ2534Provider,
    PSAMeasurement,
    PSAMonitorStopped,
    PSARunTarget,
    PSAVoltageObservation,
    check_psa_measurement,
    check_psa_multi,
    create_psa_frame_map,
    decode_psa_j2534_message,
    pack_psa,
    psa_allocate_measurements,
    psa_capabilities,
    psa_comtol_commands,
    psa_comtol_identity,
    psa_j2534_frame_plan,
    psa_measurement,
    psa_monitor_cycle,
    psa_notifications,
    psa_voltage_controller,
    psa_voltage_offset,
    psa_voltage_packing,
    selected_psa_active_operation,
    selected_psa_from_exchange,
    selected_psa_from_transaction,
    selected_psa_monitor,
)
from scripts.profiles import VehicleCatalog
from scripts.toyota import ToyotaCodecError
from scripts.toyota_session import Cancelled, Limits


def observed(**changes):
    values = {key: False for key in (22, 10, 8, 9, 12, 25, 11, 26)}
    values[12] = True
    values.update({int(key): value for key, value in changes.items()})
    return values


def authored_profile(root, *, addition=False, version=18):
    assert version in (12, 18)
    create_demo(root)
    directory = root / "Techstream_DB_NA"
    path = directory / "Toyota.ddb"
    management = parse_database(path.read_bytes())
    sections = {
        slot: (value.count, value.payload)
        for slot, value in management.sections.items()
    }
    category = bytearray(sections[16][1])
    category[72] = 10
    sections[16] = (1, bytes(category))
    protocol = bytearray(28)
    struct.pack_into("<H", protocol, 0, 1)
    protocol[24] = 0x12
    struct.pack_into("<H", protocol, 2, 7)
    struct.pack_into("<H", protocol, 8, 0x7E0)
    can_protocol = bytearray(protocol)
    can_protocol[24] = 0x1A
    struct.pack_into("<HH", can_protocol, 2, 7, 0)
    struct.pack_into("<H", can_protocol, 8, 0x7E0)
    protocol_rows = [bytes(protocol)]
    for bus in (0x1A, 0x2A, 0x3A, 0x4A, 0x5A):
        row = bytearray(can_protocol)
        row[24] = bus
        protocol_rows.append(bytes(row))
    sections[13] = (len(protocol_rows), b"".join(protocol_rows))
    can_info = bytearray(28)
    struct.pack_into("<I", can_info, 4, 500000)
    struct.pack_into("<H", can_info, 8, 7)
    struct.pack_into("<H", can_info, 12, 250)
    sections[14] = (1, bytes(can_info))
    variables = (b"\x21\0", b"\x35\0\0\0\1", b"\xaa\xbb")
    entries, pool = bytearray(), bytearray()
    for value in variables:
        entries.extend(struct.pack("<IH", len(pool), len(value)))
        pool.extend(value)
    sections[0] = (3, bytes(entries + pool))
    sections[17] = (
        3,
        b"".join(struct.pack("<4H", key, key, 0, 0) for key in (1, 2, 3)),
    )
    sections[18] = (
        4,
        b"".join(
            struct.pack("<8H", 1, function, 1, key, 0, 1, 0, 0)
            for key, function in ((1, 15), (3, 0x67), (3, 0x7F), (2, 0xCB))
        ),
    )
    if version == 12:
        sections[13] = (
            len(protocol_rows),
            b"".join(row[:22] + row[24:26] for row in protocol_rows),
        )
    data = bytearray(_ddb(1, sections))
    struct.pack_into("<I", data, 28, 0x0100030C if version == 12 else 0x0100032F)
    path.write_bytes(data)
    path = directory / "DemoEngine.ddb"
    database = parse_database(path.read_bytes())
    sections = {
        slot: (value.count, value.payload) for slot, value in database.sections.items()
    }
    sections[6] = (1, bytes((0, 0, 12, 2, 0, 0, 0, 0)))
    if addition:
        sections[55] = (1, struct.pack("<HHBBBB", 3, 0, 12, 0, 0, 0))
    if version == 12:
        sections[14] = (1, sections[14][1][:20])
    data = bytearray(_ddb(2, sections))
    struct.pack_into("<I", data, 28, 0x0100030C if version == 12 else 0x0100032F)
    path.write_bytes(data)
    return VehicleCatalog(directory).build_profile(1)


class Driver:
    def __init__(self, sends, receives):
        self.sends = list(sends)
        self.receives = list(receives)
        self.calls = []

    def send(self, ecu, request, **kwargs):
        self.calls.append(("send", ecu, request, kwargs))
        return self.sends.pop(0)

    def receive(self, ecu, **kwargs):
        self.calls.append(("receive", ecu, kwargs))
        return self.receives.pop(0)


def authored_active_profile(
    root, *, version=18, comm_mode=True, variable_instructions=None, repeat_ms=0x1234
):
    root = root / "active"
    profile = authored_profile(root, version=version)
    path = root / "Techstream_DB_NA" / "DemoEngine.ddb"
    sections = {
        slot: (s.count, s.payload) for slot, s in profile.database.sections.items()
    }
    record = bytearray(92)
    struct.pack_into("<H", record, 56, 42)
    struct.pack_into("<H", record, 64, 7)
    struct.pack_into("<H", record, 74, 0xA82)
    record[82] = 12
    pattern = bytearray(24)
    struct.pack_into("<HH", pattern, 0, 7, repeat_ms)
    pattern[20] = 1
    sections[11] = (1, bytes(record))
    if variable_instructions is not None:
        struct.pack_into("<H", record, 74, 3)
        record[80], record[86], record[88] = 12, 2, 0x77
        sections[41] = (1, bytes(record))
        freeze = bytearray(sections[10][1])
        freeze[83] = 2
        sections[10] = (sections[10][0], bytes(freeze))
    sections[12] = (1, bytes(pattern))
    if comm_mode:
        sections[60] = (1, struct.pack("<HBBBBBB", 42, 0x31, 0, 0, 0, 0, 0))
    data = bytearray(_ddb(2, sections))
    struct.pack_into("<I", data, 28, profile.database.version)
    path.write_bytes(data)
    if variable_instructions is not None:
        path = root / "Techstream_DB_NA" / "Toyota.ddb"
        database = parse_database(path.read_bytes())
        sections = {key: (s.count, s.payload) for key, s in database.sections.items()}
        entries, pool = bytearray(), bytearray()
        for item in (
            bytes.fromhex("2100"),
            bytes.fromhex("3500000001"),
            variable_instructions,
        ):
            entries.extend(struct.pack("<IH", len(pool), len(item)))
            pool.extend(item)
        sections[0] = (3, bytes(entries + pool))
        data = bytearray(_ddb(1, sections))
        struct.pack_into("<I", data, 28, database.version)
        path.write_bytes(data)
    return VehicleCatalog(root / "Techstream_DB_NA").build_profile(1)


def cycle(event, driver, **kwargs):
    values: dict[str, Any] = {
        "expected_source_id": 7,
        "protocol": 0x12,
        "send_timeout": 1000,
        "receive_timeout": 200,
        "retry_limit": 3,
        "tick_ms": lambda: 99,
    }
    values.update(kwargs)
    return psa_monitor_cycle(event, driver, "authored-ecu", **values)


def authored_multi_profiles(root, *, last_identity=None):
    profile = authored_profile(root)
    path = profile.catalog.root / "Toyota.ddb"
    database = parse_database(path.read_bytes())
    sections = {key: (s.count, s.payload) for key, s in database.sections.items()}
    for key, width, offset in ((16, 76, 68), (13, 28, 0), (18, 16, 0)):
        rows = []
        for category in (1, 2, 3):
            for original in database.sections[key].rows(width):
                row = bytearray(original)
                struct.pack_into("<H", row, offset, category)
                if key == 13 and category == 3 and last_identity is not None:
                    struct.pack_into("<H", row, 8, last_identity)
                rows.append(bytes(row))
        sections[key] = (len(rows), b"".join(rows))
    path.write_bytes(_ddb(1, sections))
    catalog = VehicleCatalog(profile.catalog.root)
    return tuple(catalog.build_profile(category) for category in (1, 2, 3))


def authored_psa_primitives():
    def message(data):
        raw = bytes.fromhex(data)
        return NativeMessage(6, 0, 0, 0, len(raw), raw)

    empty = NativeMessage(0, 0, 0, 0, 0, b"")

    def ioctl(number, value):
        return (
            "ioctl",
            {
                "channel_id": 7,
                "ioctl_id": number,
                "input": value,
                "output_capacity": 0,
            },
            J2534Result(),
        )

    return [
        (
            "connect",
            {"protocol_id": 0x1000C, "flags": 0, "baud_rate": 0},
            J2534Result(handle=7),
        ),
        ioctl(
            2,
            tuple(
                NativeConfig(p, v)
                for p, v in (
                    (1, 500000),
                    (0x10103, 0),
                    (0x10106, 250),
                    (0x2A, 0),
                )
            ),
        ),
        ioctl(10, None),
        (
            "start_message_filter",
            {
                "channel_id": 7,
                "filter_type": 1,
                "mask": message("000007ff"),
                "pattern": message("000007c0"),
                "flow_control": empty,
            },
            J2534Result(handle=31),
        ),
        (
            "start_message_filter",
            {
                "channel_id": 7,
                "filter_type": 3,
                "mask": message("ffffffff"),
                "pattern": message("000007c0"),
                "flow_control": message("000007e0"),
            },
            J2534Result(handle=32),
        ),
        ioctl(8, None),
        (
            "write_messages",
            {
                "channel_id": 7,
                "messages": (message("000007e0aabb"),),
                "count": 1,
                "timeout": 1000,
            },
            J2534Result(count=1),
        ),
        (
            "read_messages",
            {"channel_id": 7, "count": 1, "timeout": 1000},
            J2534Result(count=1, messages=(message("000007c0eabb"),)),
        ),
        ioctl(8, None),
        (
            "write_messages",
            {
                "channel_id": 7,
                "messages": (message("000007e0210c"),),
                "count": 1,
                "timeout": 1000,
            },
            J2534Result(count=1),
        ),
        (
            "read_messages",
            {"channel_id": 7, "count": 1, "timeout": 200},
            J2534Result(count=1, messages=(message("000007c0610c1234"),)),
        ),
        (
            "stop_message_filter",
            {"channel_id": 7, "filter_id": 32},
            J2534Result(),
        ),
        (
            "stop_message_filter",
            {"channel_id": 7, "filter_id": 31},
            J2534Result(),
        ),
        ("disconnect", {"channel_id": 7}, J2534Result()),
    ]


class PSAMonitorTests(unittest.TestCase):
    def test_shared_voltage_stubs_and_psa_calibration_native_arithmetic(self):
        self.assertEqual(
            psa_voltage_controller("start", mode_mask=0, interface_present=False), 0
        )
        self.assertEqual(
            psa_voltage_controller("start", mode_mask=0x40, interface_present=False),
            0xC0050001,
        )
        self.assertEqual(
            psa_voltage_controller("start", mode_mask=0x40, interface_present=True),
            0x90051201,
        )
        self.assertEqual(
            psa_voltage_controller("stop", mode_mask=0x40, interface_present=True),
            0x90051202,
        )
        measured = PSAVoltageObservation(
            1,
            True,
            tuple((True, struct.pack("<H", value)) for value in (100, 200, 300, 400)),
        )
        self.assertEqual(measured.setup_ioctl, 0xFFFEFF90)
        self.assertEqual(psa_voltage_offset(1000, 4, 2, measured), (500, None))
        failed = PSAVoltageObservation(0, False, ())
        self.assertEqual(psa_voltage_offset(1000, 4, 0, failed), (1000, 0x90051203))

    def test_native_multi_zero_systems_retains_active_only_primary(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored")
            wire = []

            def exchange(request, *, deadline, cancelled):
                command, _ = decode_vim_command(request)
                wire.append(command)
                return NativeVimReply(command | 0x80, 6, bytes(4)).encode()

            controller = PSAController(
                NativeVimClient(
                    exchange,
                    capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                )
            )
            target = PSARunTarget(profile, (), lambda q: b"", "authored", 0x1A, {}, 0)
            controller.enqueue(PSAControlMessage(0x38, primary=target))
            result = controller.run_one()
            assert result is not None
            self.assertEqual(
                (result.status, result.flags20, result.flags24), (0, 0x80, 1)
            )
            self.assertEqual(wire, [0x257F, 0x137F, 0x1D7F])
            controller.run_one(wait_status=1)
            self.assertEqual(wire[-3:], [0x147F, 0x127F, 2])
            self.assertEqual(controller.slots, [None, None, None])

    def test_run_aggregate_budget_covers_setup_and_polling_with_fresh_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored")
            for budget in (2, 5):
                with self.subTest(budget=budget):
                    wire = []

                    def exchange(request, *, deadline, cancelled, wire=wire):
                        command, _ = decode_vim_command(request)
                        wire.append(command)
                        if command == 0x197F:
                            raise AssertionError(
                                "exhausted budget must fail before monitor read"
                            )
                        return NativeVimReply(command | 0x80, 6, bytes(4)).encode()

                    controller = PSAController(
                        NativeVimClient(
                            exchange,
                            capabilities=frozenset(
                                {"denso-vim-control", "denso-vim-dmci"}
                            ),
                        ),
                        maximum_primitives=budget,
                    )
                    target = PSARunTarget(
                        profile, (1,), lambda q: b"", "authored", 0x1A, observed(), 0
                    )
                    controller.enqueue(PSAControlMessage(9, (target,)))
                    result = controller.run_one()
                    assert result is not None
                    if budget == 2:
                        self.assertNotEqual(result.status, 0)
                        self.assertEqual(wire[:2], [0x257F, 0x137F])
                    else:
                        self.assertEqual(result.status, 0)
                        with self.assertRaises(MonitorError):
                            controller.poll_registered()
                    self.assertEqual(wire[-4:], [0x1A7F, 0x147F, 0x127F, 2])
                    self.assertFalse(controller.created)

    def test_selected_low_a_runtime_reaches_strict_j2534_primitive_chronology(self):
        for version, fault in ((v, f) for v in (12, 18) for f in (0, 1, 2, 4, 7, 11)):
            with (
                self.subTest(version=version, fault=fault),
                tempfile.TemporaryDirectory() as temporary,
            ):
                profile = authored_profile(
                    Path(temporary) / "authored", version=version
                )
                selected = selected_psa_monitor(
                    profile,
                    (1,),
                    {12: 2},
                    observed(),
                    detail_mode35=0,
                    interface_id=0x7E0,
                    excluded=0,
                    standard_values=(),
                )
                monitor = PSAJ2534Monitor(profile, selected, 0x1A, "authored")

                expected = authored_psa_primitives()
                test = self

                class PrimitiveReplay:
                    def __init__(self):
                        self.count = 0
                        self.connected = False
                        self.filters = []

                    def invoke(
                        self,
                        operation,
                        fields,
                        *,
                        deadline,
                        cancelled,
                        test=test,
                        expected=expected,
                        fault=fault,
                    ):
                        test.assertTrue(
                            expected, "unexpected primitive after capture end"
                        )
                        op, wanted, result = expected.pop(0)
                        test.assertEqual((operation, dict(fields)), (op, wanted))
                        test.assertEqual(
                            deadline,
                            15
                            if operation in ("stop_message_filter", "disconnect")
                            else 40,
                        )
                        test.assertFalse(cancelled())
                        self.count += 1
                        if self.count == fault:
                            expected[:] = [
                                entry
                                for entry in expected
                                if (
                                    entry[0] == "stop_message_filter"
                                    and entry[1]["filter_id"] in self.filters
                                )
                                or (entry[0] == "disconnect" and self.connected)
                            ]
                            raise OSError("authored lowA primitive fault")
                        if operation == "connect":
                            self.connected = True
                        elif operation == "start_message_filter":
                            self.filters.append(result.handle)
                        return result

                provider = PSAJ2534Provider(
                    profile,
                    PrimitiveReplay(),
                    "authored",
                    bus_id=0x1A,
                    request=bytes.fromhex("210c"),
                    native_build=12 if version == 12 else 18,
                    driver=DriverProperties(0, b"03.04", "authored primitive"),
                    clock=lambda: 10.0,
                    limits=Limits(seconds=30),
                )
                try:
                    if fault:
                        with self.assertRaises(OSError):
                            provider.open()
                            monitor.start()
                            monitor.poll(
                                provider, tick_ms=lambda: 17, clock=lambda: 10.0
                            )
                        self.assertIsNone(provider.operations.channel)
                    else:
                        provider.open()
                        monitor.start()
                        self.assertEqual(
                            monitor.poll(
                                provider, tick_ms=lambda: 17, clock=lambda: 10.0
                            ),
                            (17, bytes.fromhex("1234")),
                        )
                        # Outer13e70 consumes lower6c idle and clears it via68(0).
                        # The retained outer controller therefore exposes False.
                        self.assertFalse(provider.operations.idle)
                finally:
                    monitor.stop()
                    provider.close()
                self.assertEqual(expected, [])

    def test_driver8_run_uses_fixed_primary_and_last_selected_event_without_dmci(self):
        for version in (12, 18):
            with (
                self.subTest(version=version),
                tempfile.TemporaryDirectory() as temporary,
            ):
                # All selected sources share the actual management source.
                profiles = authored_multi_profiles(Path(temporary) / "authored")
                expected = authored_psa_primitives()
                seen = []
                test = self

                class Backend:
                    def invoke(
                        self,
                        operation,
                        fields,
                        *,
                        deadline,
                        cancelled,
                        test=test,
                        expected=expected,
                        seen=seen,
                    ):
                        test.assertTrue(expected)
                        op, wanted, result = expected.pop(0)
                        test.assertEqual((operation, dict(fields)), (op, wanted))
                        seen.append(operation)
                        return result

                controller = PSAController(
                    backend=Backend(),
                    driver=DriverProperties(0, b"03.04", "authored primitive"),
                    native_build=version,
                    clock=lambda: 10.0,
                )
                targets = tuple(
                    PSARunTarget(
                        profile,
                        ids,
                        lambda q: b"",
                        str(profile.category),
                        0x1A,
                        observed(),
                        0,
                    )
                    for profile, ids in zip(profiles, ((1,), (1,), ()), strict=True)
                )
                controller.enqueue(PSAControlMessage(0x38, targets))
                result = controller.run_one(timeout=30)
                assert result is not None
                self.assertEqual(result.status, 0)
                self.assertEqual(result.flags20, 0xA0)
                self.assertEqual(seen, [])  # native allocation/setup is local
                self.assertEqual(controller._monitor_category, 2)
                assert controller._provider is not None
                self.assertEqual(controller._provider.profile.category, 1)
                packets = controller.poll_registered(timeout=30)
                self.assertEqual(
                    packets, ((2, NativeMonitorPacket(10000, bytes.fromhex("1234"))),)
                )
                controller.enqueue(PSAControlMessage(0xA))
                stopped = controller.run_one()
                assert stopped is not None
                self.assertEqual(stopped.status, 0)
                self.assertEqual(expected, [])

    def test_driver8_last_empty_slot_changes_peer_without_changing_primary_transport(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            profiles = authored_multi_profiles(
                Path(temporary) / "authored", last_identity=0x7E1
            )
            expected = authored_psa_primitives()
            # First result belongs to the original primary peer and must be ignored.
            data = bytes.fromhex("000007c1610c5678")
            expected.insert(
                11,
                (
                    "read_messages",
                    {"channel_id": 7, "count": 1, "timeout": 200},
                    J2534Result(
                        count=1, messages=(NativeMessage(6, 0, 0, 0, len(data), data),)
                    ),
                ),
            )
            test = self

            class Backend:
                def invoke(self, operation, fields, *, deadline, cancelled):
                    test.assertTrue(expected)
                    op, wanted, result = expected.pop(0)
                    test.assertEqual((operation, dict(fields)), (op, wanted))
                    return result

            controller = PSAController(
                backend=Backend(),
                driver=DriverProperties(0, b"03.04", "authored primitive"),
                clock=lambda: 10.0,
            )
            targets = tuple(
                PSARunTarget(
                    profile,
                    ids,
                    lambda q: b"",
                    str(profile.category),
                    0x1A,
                    observed(),
                    0,
                )
                for profile, ids in zip(profiles, ((1,), (1,), ()), strict=True)
            )
            controller.enqueue(PSAControlMessage(0x38, targets))
            result = controller.run_one(timeout=30)
            assert result is not None
            self.assertEqual(result.status, 0)
            self.assertEqual(
                (controller._last_identity, controller._last_peer), (0x7E1, 0x7C1)
            )
            self.assertEqual(
                controller.poll_registered(timeout=30),
                ((2, NativeMonitorPacket(10000, bytes.fromhex("5678"))),),
            )
            controller.run_one(wait_status=1)
            self.assertEqual(expected, [])

    def test_driver8_active_repeat_stop_uses_actual_queue_and_retained_channel(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_active_profile(
                Path(temporary), comm_mode=False, repeat_ms=50
            )
            active = selected_psa_active_operation(
                profile, 42, 0, observed_bus_id=0x1A, variable_drive=False
            )
            self.assertEqual(active.request, bytes.fromhex("300c000000"))
            expected = authored_psa_primitives()
            # Keep actual connect/config/filter/startup and exact cleanup. Replace
            # only the authored monitor exchange with three explicit AT exchanges.
            prefix, suffix = expected[:8], expected[11:]
            clear, write, read = expected[8:11]

            def transfer(request, reply):
                write_fields = dict(write[1])
                data = bytes.fromhex("000007e0" + request)
                write_fields["messages"] = (NativeMessage(6, 0, 0, 0, len(data), data),)
                data = bytes.fromhex("000007c0" + reply)
                result = J2534Result(
                    count=1, messages=(NativeMessage(6, 0, 0, 0, len(data), data),)
                )
                return [
                    clear,
                    (write[0], write_fields, write[2]),
                    (read[0], read[1], result),
                ]

            expected = (
                prefix
                + transfer("300c000000", "700c01")
                + transfer("300c01", "700c01")
                + transfer("300c11", "700c11")
                + suffix
            )
            test = self
            now = [10.0]

            class Backend:
                def invoke(self, operation, fields, *, deadline, cancelled):
                    test.assertTrue(expected, "primitive after capture end")
                    op, wanted, result = expected.pop(0)
                    test.assertEqual((operation, dict(fields)), (op, wanted))
                    return result

            controller = PSAController(
                backend=Backend(),
                driver=DriverProperties(0, b"03.04", "authored primitive"),
                clock=lambda: now[0],
                wait=lambda seconds: now.__setitem__(0, now[0] + seconds),
            )
            target = PSARunTarget(profile, (), lambda q: b"", "authored", 0x1A, {}, 0)
            for message in (
                PSAControlMessage(9, (target,)),
                PSAControlMessage(0xB, active=active),
            ):
                controller.enqueue(message)
                result = controller.run_one(timeout=30)
                assert result is not None
                self.assertEqual(result.status, 0)
            self.assertEqual(len(expected), 20)
            self.assertEqual(controller.poll_registered(timeout=30), ())
            self.assertEqual(controller._active_queue.items[-1].state, 1)
            controller.poll_registered(timeout=30)  # native wait/re-arm turn
            controller.poll_registered(timeout=30)  # repeated request
            controller.enqueue(PSAControlMessage(0xC))
            stopped = controller.run_one()
            assert stopped is not None
            self.assertEqual(stopped.status, 0)
            controller.poll_registered(timeout=30)  # native stop50ms guard
            controller.poll_registered(timeout=30)
            self.assertEqual(controller._active_queue.items[-1].state, 2)
            self.assertEqual(
                [n.message_id for n in controller.notifications],
                [0x60C, 0x60C, 0x60C, 0x515],
            )
            controller.run_one(wait_status=1)
            self.assertEqual(expected, [])

    def test_driver8_run_primitive_faults_preserve_primary_and_dispose(self):
        for fault in (1, 2, 4, 7, 11):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                profile = authored_profile(Path(temporary) / "authored")
                expected = authored_psa_primitives()
                test = self

                class Backend:
                    def __init__(self):
                        self.count = 0
                        self.connected = False
                        self.filters = []

                    def invoke(
                        self,
                        operation,
                        fields,
                        *,
                        deadline,
                        cancelled,
                        test=test,
                        expected=expected,
                        fault=fault,
                    ):
                        test.assertTrue(expected)
                        op, wanted, result = expected.pop(0)
                        test.assertEqual((operation, dict(fields)), (op, wanted))
                        self.count += 1
                        if self.count == fault:
                            expected[:] = [
                                entry
                                for entry in expected
                                if (
                                    entry[0] == "stop_message_filter"
                                    and entry[1]["filter_id"] in self.filters
                                )
                                or (entry[0] == "disconnect" and self.connected)
                            ]
                            raise OSError("authored Run primitive failure")
                        if operation == "connect":
                            self.connected = True
                        elif operation == "start_message_filter":
                            self.filters.append(result.handle)
                        return result

                controller = PSAController(
                    backend=Backend(),
                    driver=DriverProperties(0, b"03.04", "authored primitive"),
                    clock=lambda: 10.0,
                )
                target = PSARunTarget(
                    profile, (1,), lambda q: b"", "authored", 0x1A, observed(), 0
                )
                controller.enqueue(PSAControlMessage(9, (target,)))
                result = controller.run_one(timeout=30)
                assert result is not None
                self.assertEqual(result.status, 0)
                with self.assertRaisesRegex(OSError, "authored Run primitive failure"):
                    controller.poll_registered(timeout=30)
                self.assertEqual(expected, [])
                self.assertFalse(controller.created)
                self.assertIsNone(controller._provider)
                self.assertEqual(controller.slots, [None, None, None])

    def test_driver8_run_empty_start_cancel_and_unsupported_mode_do_no_driver_io(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored")

            class NoBackend:
                def invoke(self, operation, fields, *, deadline, cancelled):
                    raise AssertionError("unreachable driver primitive")

            controller = PSAController(
                backend=NoBackend(),
                driver=DriverProperties(0, b"03.04", "authored primitive"),
            )
            target = PSARunTarget(profile, (), lambda q: b"", "authored", 0x1A, {}, 0)
            message = PSAControlMessage(9, (target,))
            controller.enqueue(message)
            result = controller.run_one(cancelled=lambda: True)
            assert result is not None
            self.assertNotEqual(result.status, 0)
            self.assertTrue(message.completed.is_set())
            self.assertIsInstance(message.exception, Cancelled)
            controller.enqueue(PSAControlMessage(9, (target,)))
            result = controller.run_one()
            assert result is not None
            self.assertEqual(result.flags20, 0x80)
            self.assertEqual(controller.poll_registered(), ())
            controller.run_one(wait_status=1)
            self.assertFalse(controller.created)

    def test_driver8_parent_deadline_rejects_late_reply_and_callback_time(self):
        for active_only in (False, True):
            for stage in ("late_reply", "callback"):
                with (
                    self.subTest(active=active_only, stage=stage),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    profile = authored_active_profile(
                        Path(temporary), comm_mode=False, repeat_ms=0
                    )
                    expected = authored_psa_primitives()
                    if active_only:
                        fields = dict(expected[9][1])
                        data = bytes.fromhex("000007e0300c000000")
                        fields["messages"] = (
                            NativeMessage(6, 0, 0, 0, len(data), data),
                        )
                        expected[9] = (expected[9][0], fields, expected[9][2])
                        data = bytes.fromhex("000007c0700c01")
                        expected[10] = (
                            expected[10][0],
                            expected[10][1],
                            J2534Result(
                                count=1,
                                messages=(NativeMessage(6, 0, 0, 0, len(data), data),),
                            ),
                        )
                    now = [10.0]
                    armed = [False]
                    test = self

                    class Backend:
                        def invoke(
                            self,
                            operation,
                            fields,
                            *,
                            deadline,
                            cancelled,
                            test=test,
                            expected=expected,
                            now=now,
                            armed=armed,
                            stage=stage,
                        ):
                            test.assertTrue(expected)
                            op, wanted, result = expected.pop(0)
                            test.assertEqual((operation, dict(fields)), (op, wanted))
                            if operation not in ("stop_message_filter", "disconnect"):
                                test.assertLessEqual(deadline, 40.0)
                            if operation == "read_messages" and len(expected) == 6:
                                armed[0] = True  # startup reply consumed
                            if (
                                stage == "late_reply"
                                and operation == "read_messages"
                                and len(expected) == 3
                            ):
                                now[0] = 41.0
                            return result

                    def cancel(now=now, armed=armed, stage=stage, expected=expected):
                        if stage == "callback" and armed[0]:
                            now[0] = 41.0
                            expected[:] = [
                                item
                                for item in expected
                                if item[0] in ("stop_message_filter", "disconnect")
                            ]
                        return False

                    controller = PSAController(
                        backend=Backend(),
                        driver=DriverProperties(0, b"03.04", "authored primitive"),
                        clock=lambda now=now: now[0],
                    )
                    target = PSARunTarget(
                        profile,
                        () if active_only else (1,),
                        lambda q: b"",
                        "authored",
                        0x1A,
                        observed(),
                        0,
                    )
                    controller.enqueue(PSAControlMessage(9, (target,)))
                    result = controller.run_one(timeout=30)
                    assert result is not None
                    self.assertEqual(result.status, 0)
                    if active_only:
                        active = selected_psa_active_operation(
                            profile, 42, 0, observed_bus_id=0x1A, variable_drive=False
                        )
                        controller.enqueue(PSAControlMessage(0xB, active=active))
                        result = controller.run_one(timeout=30)
                        assert result is not None
                        self.assertEqual(result.status, 0)
                    with self.assertRaises(TimeoutError):
                        controller.poll_registered(timeout=30, cancelled=cancel)
                    self.assertEqual(expected, [])
                    self.assertFalse(controller.created)
                    self.assertFalse(
                        any(
                            note.message_id == 0x60C
                            for note in controller.notifications
                        )
                    )

    def test_driver8_inflight_repeat_host_fault_sends_stop_before_disconnect(self):
        def exercise(scenario):
            with (
                self.subTest(scenario=scenario),
                tempfile.TemporaryDirectory() as temporary,
            ):
                profile = authored_active_profile(
                    Path(temporary), comm_mode=False, repeat_ms=50
                )
                expected = authored_psa_primitives()
                clear, write, read = expected[8:11]

                def transfer(request, reply):
                    fields = dict(write[1])
                    data = bytes.fromhex("000007e0" + request)
                    fields["messages"] = (NativeMessage(6, 0, 0, 0, len(data), data),)
                    data = bytes.fromhex("000007c0" + reply)
                    return [
                        clear,
                        (write[0], fields, write[2]),
                        (
                            read[0],
                            read[1],
                            J2534Result(
                                count=1,
                                messages=(NativeMessage(6, 0, 0, 0, len(data), data),),
                            ),
                        ),
                    ]

                expected = (
                    expected[:8]
                    + transfer("300c000000", "700c01")
                    + (
                        []
                        if scenario == "cancel_wait"
                        else transfer("300c01", "700c01")[:2]
                    )
                    + transfer("300c11", "700c11")
                    + expected[11:]
                )
                now, stopped, broken = [10.0], [False], [False]
                clock_error = RuntimeError("authored clock failure")
                test = self

                def clock():
                    if broken[0]:
                        raise clock_error
                    return now[0]

                class Backend:
                    def invoke(self, operation, fields, *, deadline, cancelled):
                        test.assertTrue(expected, "primitive after capture end")
                        op, wanted, result = expected.pop(0)
                        test.assertEqual((operation, dict(fields)), (op, wanted))
                        if operation == "write_messages" and fields["messages"][
                            0
                        ].data == bytes.fromhex("000007e0300c01"):
                            if scenario in (
                                "cancel",
                                "cancel_exhausted",
                                "cancel_stop_fault",
                            ):
                                stopped[0] = True
                                if scenario == "cancel_exhausted":
                                    controller._remaining = 0
                            elif scenario == "deadline":
                                now[0] = 41.0
                            elif scenario == "nan":
                                now[0] = float("nan")
                            else:
                                broken[0] = True
                        if (
                            scenario == "cancel_stop_fault"
                            and operation == "write_messages"
                            and fields["messages"][0].data
                            == bytes.fromhex("000007e0300c11")
                        ):
                            expected[:] = [
                                item
                                for item in expected
                                if item[0] in ("stop_message_filter", "disconnect")
                            ]
                            raise OSError("authored pending stop write failure")
                        return result

                controller = PSAController(
                    backend=Backend(),
                    driver=DriverProperties(0, b"03.04", "authored primitive"),
                    clock=clock,
                    wait=lambda seconds: now.__setitem__(0, now[0] + seconds),
                )
                target = PSARunTarget(
                    profile, (), lambda q: b"", "authored", 0x1A, {}, 0
                )
                active = selected_psa_active_operation(
                    profile, 42, 0, observed_bus_id=0x1A, variable_drive=False
                )
                for message in (
                    PSAControlMessage(9, (target,)),
                    PSAControlMessage(0xB, active=active),
                ):
                    controller.enqueue(message)
                    result = controller.run_one(timeout=30)
                    assert result is not None
                    self.assertEqual(result.status, 0)
                controller.poll_registered(timeout=30)
                if scenario == "cancel_wait":
                    stopped[0] = True
                else:
                    controller.poll_registered(timeout=30)  # native repeat re-arm
                error_type = (
                    Cancelled
                    if scenario.startswith("cancel")
                    else RuntimeError
                    if scenario == "raising"
                    else TimeoutError
                )
                with self.assertRaises(error_type) as caught:
                    controller.poll_registered(timeout=30, cancelled=lambda: stopped[0])
                if scenario == "raising":
                    self.assertIs(caught.exception, clock_error)
                self.assertEqual(expected, [])
                self.assertFalse(controller.created)
                self.assertIsNone(controller._provider)
                self.assertEqual(
                    [
                        note.wparam
                        for note in controller.notifications
                        if note.message_id == 0x60C
                    ],
                    [1] if scenario == "cancel_stop_fault" else [1, 0x11],
                )
                if scenario == "cancel_stop_fault":
                    self.assertTrue(
                        any(
                            "pending stop write failure" in note
                            for note in caught.exception.__notes__
                        )
                    )
                else:
                    self.assertEqual(
                        [note.message_id for note in controller.notifications][-1],
                        0x515,
                    )

        for scenario in (
            "cancel",
            "cancel_wait",
            "cancel_exhausted",
            "cancel_stop_fault",
            "deadline",
            "nan",
            "raising",
        ):
            exercise(scenario)

    def test_native_notification_arrays_map_callbacks_in_literal_order(self):
        empty = NativeCoreBuffer((1, 0), b"")
        first = struct.pack("<II", 0x1234, 0) + b"xx"
        detailed = (
            b"".join(
                struct.pack("<III", 99, error, status) + b"\xab"
                for error, status in ((7, 0xE00001CC), (8, 0xE000010E), (9, 0xE0000189))
            )
            + b"tail"
        )
        active = struct.pack("<III", 1, 2, 3) + bytes.fromhex("300c55") + bytes(60)
        reply = NativeMonitorReply(
            0,
            NativeDmciList((1, 0), ()),
            (
                NativeCoreBuffer((1, 0), first),
                NativeCoreBuffer((1, 0), detailed),
                NativeCoreBuffer((1, 0), active),
                empty,
                empty,
            ),
            1,
        )
        self.assertEqual(
            [
                (n.message_id, n.wparam, n.lparam)
                for n in psa_notifications(reply, signal_id=42)
            ],
            [
                (0x608, 0x1234, 0),
                (0x608, 0, 0),
                (0x602, 0, 42),
                (0x603, 0xA1050304, 0),
                (0x515, 0, 0),
                (0x60C, 0x55, 0),
            ],
        )
        excessive = replace(reply, trailing_value=100000)
        with self.assertRaises(MonitorError):
            psa_notifications(excessive)
        malformed = replace(
            reply,
            buffers=(
                empty,
                empty,
                NativeCoreBuffer((1, 0), struct.pack("<III", 1, 2, 64) + bytes(63)),
                empty,
                empty,
            ),
        )
        with self.assertRaises(MonitorError):
            psa_notifications(malformed)

    def test_vim_internal_clock_source_change_is_guarded_before_actual_exchange(self):
        with tempfile.TemporaryDirectory() as temporary:
            first_clock = []
            for attempt in (0, 1):
                profile = authored_profile(Path(temporary) / str(attempt))
                management = profile.catalog.management
                sections = {
                    key: (s.count, s.payload) for key, s in management.sections.items()
                }
                row = bytearray(sections[16][1])
                row[72] = 19
                sections[16] = (1, bytes(row))
                changed = parse_database(_ddb(1, sections))
                ticks = [0]
                wire = []

                def clock(
                    profile=profile, ticks=ticks, changed=changed, attempt=attempt
                ):
                    ticks[0] += 1
                    if attempt and ticks[0] == first_clock[0]:
                        profile.catalog.management = changed
                    return 0.0

                def exchange(
                    request,
                    *,
                    deadline,
                    cancelled,
                    wire=wire,
                    ticks=ticks,
                    attempt=attempt,
                ):
                    command, _ = decode_vim_command(request)
                    if not attempt and not first_clock:
                        first_clock.append(ticks[0])
                    wire.append(command)
                    return NativeVimReply(command | 0x80, 6, bytes(4)).encode()

                controller = PSAController(
                    NativeVimClient(
                        exchange,
                        capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                        clock=clock,
                    )
                )
                target = PSARunTarget(
                    profile, (1,), lambda q: b"", "authored", 0x1A, observed(), 0
                )
                message = PSAControlMessage(9, (target,))
                controller.enqueue(message)
                result = controller.run_one()
                assert result is not None
                if attempt:
                    self.assertNotEqual(result.status, 0)
                    self.assertEqual(wire, [0x1A7F, 0x147F, 0x127F, 2])
                    self.assertTrue(message.completed.is_set())
                else:
                    self.assertEqual(result.status, 0)
                    controller.run_one(wait_status=1)

    def test_run_rejects_foreign_management_before_support_or_wire(self):
        with tempfile.TemporaryDirectory() as temporary:
            first = authored_profile(Path(temporary) / "one")
            other = authored_active_profile(Path(temporary) / "two")
            # Only the ECU database differs here; mutate an actual management
            # category field too, then parse to obtain a genuine new identity.
            path = other.catalog.root / "Toyota.ddb"
            db = parse_database(path.read_bytes())
            sections = {key: (s.count, s.payload) for key, s in db.sections.items()}
            row = bytearray(sections[16][1])
            row[72] = 19
            sections[16] = (1, bytes(row))
            path.write_bytes(_ddb(1, sections))
            other = VehicleCatalog(other.catalog.root).build_profile(1)
            calls = []

            def transaction(query):
                calls.append(query)
                raise AssertionError("foreign context must fail before support")

            def exchange(request, *, deadline, cancelled):
                calls.append(request)
                raise AssertionError("foreign context must fail before wire")

            controller = PSAController(
                NativeVimClient(exchange, capabilities=frozenset())
            )
            targets = tuple(
                PSARunTarget(p, (1,), transaction, "authored", 0x1A, observed(), 0)
                for p in (first, other)
            )
            controller.enqueue(PSAControlMessage(0x38, targets))
            result = controller.run_one()
            assert result is not None
            self.assertEqual(result.status, 0xC0050001)
            self.assertEqual(calls, [])

    def test_run_clock_reentry_and_nonfinite_fault_complete_without_deadlock(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored")
            calls = []
            holder = []

            def clock():
                with self.assertRaises(MonitorError):
                    holder[0].run_one(wait_status=0x102)
                return 0.0

            def exchange(request, *, deadline, cancelled):
                command, _ = decode_vim_command(request)
                calls.append(command)
                return NativeVimReply(command | 0x80, 6, bytes(4)).encode()

            for chosen in (clock, lambda: float("nan")):
                client = NativeVimClient(
                    exchange,
                    capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                    clock=chosen,
                )
                controller = PSAController(client)
                holder[:] = [controller]
                target = PSARunTarget(
                    profile, (1,), lambda q: b"", "authored", 0x1A, observed(), 0
                )
                message = PSAControlMessage(9, (target,))
                controller.enqueue(message)
                result = controller.run_one()
                assert result is not None
                self.assertTrue(message.completed.is_set())
                if chosen is clock:
                    self.assertEqual(result.status, 0)
                    controller.run_one(wait_status=1)
                else:
                    self.assertNotEqual(result.status, 0)
                    self.assertFalse(controller.created)

    def test_multi_registration_replaces_signals_before_support_production(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored")
            queries = []
            wire = []

            def exchange(request, *, deadline, cancelled):
                command, _ = decode_vim_command(request)
                wire.append(command)
                return NativeVimReply(command | 0x80, 6, bytes(4)).encode()

            def support(query):
                queries.append(query)
                return bytes.fromhex("610c1234")

            controller = PSAController(
                NativeVimClient(
                    exchange,
                    capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                )
            )
            # The overwritten invalid signal must never reach the producer.
            first = PSARunTarget(
                profile, (65535,), support, "authored", 0x1A, observed(), 0
            )
            last = PSARunTarget(profile, (1,), support, "authored", 0x1A, observed(), 0)
            controller.enqueue(PSAControlMessage(0x38, (first, last)))
            result = controller.run_one()
            assert result is not None
            self.assertEqual(result.status, 0)
            self.assertEqual(len(queries), 0)
            self.assertEqual(len([slot for slot in controller.slots if slot]), 1)
            self.assertEqual(wire.count(0x1D7F), 1)
            controller.run_one(wait_status=1)

    def test_multi_run_three_selected_categories_route_actual_native_packets(self):
        with tempfile.TemporaryDirectory() as temporary:
            profiles = authored_multi_profiles(Path(temporary) / "authored")
            wire = []
            empty = NativeCoreBuffer((1, 0), b"")
            reply = NativeMonitorReply(
                0,
                NativeDmciList(
                    (1, 0),
                    tuple(
                        (
                            category,
                            NativeCoreBuffer(
                                (1, 0),
                                struct.pack("<I", category)
                                + bytes((category, category)),
                            ),
                        )
                        for category in (3, 1, 2)
                    ),
                ),
                (empty, empty, empty, empty, empty),
                0,
            )

            def exchange(request, *, deadline, cancelled):
                command, payload = decode_vim_command(request)
                wire.append((command, payload))
                return NativeVimReply(
                    command | 0x80, 6, reply.encode() if command == 0x197F else bytes(4)
                ).encode()

            controller = PSAController(
                NativeVimClient(
                    exchange,
                    capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                )
            )
            targets = tuple(
                PSARunTarget(
                    profile,
                    (1,),
                    lambda query: bytes.fromhex("610c1234"),
                    str(profile.category),
                    0x1A,
                    observed(),
                    0,
                )
                for profile in profiles
            )
            controller.enqueue(PSAControlMessage(0x38, targets, phase=1))
            result = controller.run_one()
            assert result is not None
            self.assertEqual(
                (result.status, result.flags20, result.flags24), (0, 0x20, 1)
            )
            self.assertEqual(
                [
                    None if slot is None else slot[0].profile.category
                    for slot in controller.slots
                ],
                [1, 2, 3],
            )
            self.assertEqual(
                [command for command, _ in wire],
                [
                    0x257F,
                    0x137F,
                    0x1D7F,
                    0x167F,
                    0x1D7F,
                    0x167F,
                    0x1D7F,
                    0x167F,
                    0x187F,
                ],
            )
            packets = controller.poll_registered()
            self.assertEqual([category for category, _ in packets], [3, 1, 2])
            self.assertEqual([packet.timestamp_ms for _, packet in packets], [3, 1, 2])
            self.assertEqual(
                [packet.payload for _, packet in packets],
                [bytes((category, category)) for category in (3, 1, 2)],
            )
            controller.post_error(0x1234)
            self.assertEqual(
                [controller.buffer_error(i) for i in range(4)], [0x1234] * 4
            )
            controller.run_one(wait_status=0x102)
            self.assertEqual(controller.active_mask, 0)

    def test_variable_drive_selected_table_and_literal_opcode_request(self):
        for version in (12, 18):
            with (
                self.subTest(version=version),
                tempfile.TemporaryDirectory() as temporary,
            ):
                profile = authored_active_profile(
                    Path(temporary),
                    version=version,
                    variable_instructions=bytes(
                        (2, 3, 4, 5, 6, 7, 8, 10, 16, 17, 18, 20, 21, 0)
                    ),
                )
                active = selected_psa_active_operation(
                    profile,
                    42,
                    0x1234,
                    observed_bus_id=0x1A,
                    variable_drive=True,
                    auxiliary=0xAB,
                )
                self.assertEqual(
                    active.request, bytes.fromhex("310c340002023606ab127700120110")
                )
                self.assertEqual(active.repeat, 0x1234)

    def test_variable_drive_discovers_mode35_and_rejects_invalid_opcodes(self):
        from scripts.monitor_support import MonitorSupportCache

        for opcode in (11, 12, 13, 19):
            with (
                self.subTest(opcode=opcode),
                tempfile.TemporaryDirectory() as temporary,
            ):
                profile = authored_active_profile(
                    Path(temporary), variable_instructions=bytes((opcode,))
                )
                calls = []

                def transaction(query, calls=calls):
                    calls.append(query)
                    self.assertEqual(query.request, bytes.fromhex("3500000001"))
                    return bytes.fromhex("7500ff000000020c02")

                cache = MonitorSupportCache(
                    profile, transaction, "authored", bus_id=0x1A
                )
                if opcode == 19:
                    active = selected_psa_active_operation(
                        profile,
                        42,
                        1,
                        observed_bus_id=0x1A,
                        variable_drive=True,
                        support_cache=cache,
                    )
                    self.assertEqual(active.request, bytes.fromhex("310c00"))
                    self.assertEqual(len(calls), 1)
                else:
                    with self.assertRaises(MonitorError) as caught:
                        selected_psa_active_operation(
                            profile,
                            42,
                            1,
                            observed_bus_id=0x1A,
                            variable_drive=True,
                            support_cache=cache,
                        )
                    self.assertEqual(caught.exception.code, 0xC0050102)
                    self.assertEqual(calls, [])

    def test_active_only_run_skips_support_metadata_setup_and_monitor_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_active_profile(Path(temporary))
            wire = []

            def transaction(query):
                raise AssertionError("native mode80 does not query support")

            def exchange(request, *, deadline, cancelled):
                command, _ = decode_vim_command(request)
                wire.append(command)
                return NativeVimReply(command | 0x80, 6, bytes(4)).encode()

            controller = PSAController(
                NativeVimClient(
                    exchange,
                    capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                )
            )
            target = PSARunTarget(profile, (), transaction, "authored", 0x1A, {}, 0)
            controller.enqueue(PSAControlMessage(9, (target,)))
            result = controller.run_one()
            assert result is not None
            self.assertEqual((result.status, result.flags20), (0, 0x80))
            self.assertEqual(wire, [0x257F, 0x137F, 0x1D7F])
            slot = controller.slots[0]
            assert slot is not None
            self.assertIsNone(slot[2])
            active = selected_psa_active_operation(
                profile, 42, 7, observed_bus_id=0x1A, variable_drive=False
            )
            controller.enqueue(PSAControlMessage(0xB, active=active))
            controller.run_one()
            controller.enqueue(PSAControlMessage(0xA))
            controller.run_one()
            self.assertEqual(
                wire, [0x257F, 0x137F, 0x1D7F, 0x1B7F, 0x1C7F, 0x147F, 0x127F, 2]
            )

    def test_run_queue_selected_support_native_lifecycle_and_active_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_active_profile(Path(temporary))
            path = profile.catalog.root / "DemoEngine.ddb"
            sections = {
                key: (s.count, s.payload)
                for key, s in profile.database.sections.items()
            }
            sections[6] = (1, bytes((0, 0, 12, 0, 0, 0, 0, 0)))
            path.write_bytes(_ddb(2, sections))
            profile = VehicleCatalog(profile.catalog.root).build_profile(1)
            support, wire = [], []

            def transaction(query):
                support.append(query)
                self.assertEqual(query.request, bytes.fromhex("210c"))
                return bytes.fromhex("610c1234")

            def exchange(request, *, deadline, cancelled):
                command, payload = decode_vim_command(request)
                wire.append((command, payload))
                return NativeVimReply(command | 0x80, 6, bytes(4)).encode()

            controller = PSAController(
                NativeVimClient(
                    exchange,
                    capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                )
            )
            target = PSARunTarget(
                profile, (1,), transaction, "authored", 0x1A, observed(), 0
            )
            start = PSAControlMessage(9, (target,))
            controller.enqueue(start)
            result = controller.run_one()
            assert result is not None
            self.assertEqual(
                (result.status, result.flags20, result.flags28), (0, 0x20, 1)
            )
            self.assertTrue(start.completed.is_set())
            self.assertEqual(len(support), 1)
            self.assertEqual(
                [command for command, _ in wire],
                [0x257F, 0x137F, 0x1D7F, 0x167F, 0x187F],
            )
            slot = controller.slots[0]
            assert slot is not None and slot[2] is not None
            self.assertEqual(slot[2].value_before_buffer, 1)
            active = selected_psa_active_operation(
                profile,
                42,
                0x1234,
                observed_bus_id=0x1A,
                variable_drive=False,
                auxiliary=0xAB,
            )
            for command, message in (
                (0x1B7F, PSAControlMessage(0xB, active=active)),
                (0x1C7F, PSAControlMessage(0xC, stop_active=True)),
            ):
                controller.enqueue(message)
                result = controller.run_one()
                assert result is not None
                self.assertEqual(result.status, 0)
                self.assertEqual(wire[-1][0], command)
            controller.enqueue(PSAControlMessage(0xA))
            controller.run_one()
            self.assertEqual(
                [command for command, _ in wire[-4:]], [0x1A7F, 0x147F, 0x127F, 2]
            )
            self.assertEqual(controller.active_mask, 0)

    def test_run_queue_failure_completion_precedes_error_and_all_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored")
            for failed in (0x257F, 0x137F, 0x1D7F, 0x167F, 0x187F):
                with self.subTest(failed=failed):
                    wire = []

                    def exchange(
                        request, *, deadline, cancelled, wire=wire, failed=failed
                    ):
                        command, _ = decode_vim_command(request)
                        wire.append(command)
                        if command == failed:
                            raise OSError("authored primitive fault")
                        return NativeVimReply(command | 0x80, 6, bytes(4)).encode()

                    controller = PSAController(
                        NativeVimClient(
                            exchange,
                            capabilities=frozenset(
                                {"denso-vim-control", "denso-vim-dmci"}
                            ),
                        )
                    )
                    target = PSARunTarget(
                        profile,
                        (1,),
                        lambda query: bytes.fromhex("610c1234"),
                        "authored",
                        0x1A,
                        observed(),
                        0,
                    )
                    message = PSAControlMessage(9, (target,))
                    controller.enqueue(message)
                    result = controller.run_one()
                    assert result is not None
                    self.assertNotEqual(result.status, 0)
                    self.assertTrue(message.completed.is_set())
                    self.assertIsInstance(message.exception, OSError)
                    self.assertEqual(wire[-4:], [0x1A7F, 0x147F, 0x127F, 2])
                    self.assertEqual(list(controller.trace)[1][0], "finish")
                    self.assertEqual(list(controller.trace)[2][0], "error")

    def test_run_native_dispatch_wait_results_and_queue_bounds(self):
        wire = []

        def exchange(request, *, deadline, cancelled):
            wire.append(request)
            raise AssertionError("unsupported queue command must not exchange")

        controller = PSAController(
            NativeVimClient(exchange, capabilities=frozenset()), maximum_queued=1
        )
        for command in (0x57, 0x60, 0x89, 0xB, 0xC):
            message = PSAControlMessage(command)
            controller.enqueue(message)
            with self.assertRaises(MonitorError):
                controller.enqueue(PSAControlMessage(9))
            result = controller.run_one()
            assert result is not None
            self.assertEqual(result.status, 0x90050405)
            with self.assertRaises(MonitorError):
                controller.enqueue(message)
        self.assertIsNone(controller.run_one(wait_status=0x102))
        self.assertIsNone(controller.run_one(wait_status=0xFFFFFFFF))
        message = PSAControlMessage(9)
        controller.enqueue(message)
        controller.run_one(wait_status=1)
        self.assertTrue(message.completed.is_set())
        assert message.result is not None
        self.assertEqual(message.result.status, 0xC0050503)
        self.assertEqual(wire, [])

    def test_selected_active_tables_reach_literal_native_10f_bytes(self):
        for version in (12, 18):
            for override in (False, True):
                with (
                    self.subTest(version=version, override=override),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    profile = authored_active_profile(
                        Path(temporary), version=version, comm_mode=override
                    )
                    active = selected_psa_active_operation(
                        profile,
                        42,
                        0x1234,
                        observed_bus_id=0x1A,
                        variable_drive=False,
                        auxiliary=0xAB,
                    )
                    request = bytes((0x31 if override else 0x30, 12, 0x34, 0xAB, 0x12))
                    self.assertEqual(active.request, request)
                    self.assertEqual(active.repeat, 0x1234)
                    self.assertEqual(active.request_identity, 0x7E0)
                    encoded = NativeDmciCommand.from_neutral(
                        active.command.command_id, active.command.values
                    ).encode()
                    # Request DWORD, buffer core/length, full SID+data, repeat WORD.
                    self.assertEqual(
                        encoded,
                        bytes.fromhex("e00700000100000005000000")
                        + request
                        + bytes.fromhex("3412"),
                    )

    def test_active_requires_observed_bus_function_and_selected_signal(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_active_profile(Path(temporary))
            for bus, signal, expected in (
                (None, 42, 0xC0040601),
                (0, 42, 0xC0040602),
                (0x99, 42, 0xC0050101),
                (0x1A, 43, 0xC0050101),
            ):
                with (
                    self.subTest(bus=bus, signal=signal),
                    self.assertRaises(MonitorError) as caught,
                ):
                    selected_psa_active_operation(
                        profile, signal, 1, observed_bus_id=bus, variable_drive=False
                    )
                self.assertEqual(caught.exception.code, expected)

    def test_capability_query_order_is_psa_specific(self):
        mask, queried = psa_capabilities(observed())
        self.assertEqual(mask, 0x20)
        self.assertEqual(queried, (22, 10, 8, 9, 12, 25, 11, 26))
        values = observed()
        values[22] = True
        self.assertEqual(psa_capabilities(values)[1], (22, 12, 25, 11, 26))
        del values[25]
        with self.assertRaises(MonitorError):
            psa_capabilities(values)

    def test_selected_real_authored_ddb_to_setup_signal_and_packet(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored")
            selected = selected_psa_monitor(
                profile,
                (1,),
                {12: 2},
                observed(),
                detail_mode35=0,
                interface_id=0x123,
                excluded=0,
                standard_values=(),
            )
            self.assertEqual(
                selected.packing.setup_requests, (b"\x21\x0c", b"\x61\x02")
            )
            self.assertEqual(selected.frame_sizes, ((0, 2),))
            self.assertEqual(
                (
                    selected.signals[0].name,
                    selected.signals[0].unit,
                    selected.signals[0].multiplier,
                    selected.signals[0].divisor,
                ),
                ("Engine speed", "rpm", 1, 4),
            )
            command = selected.commands.setup[0]
            self.assertEqual(command.command_id, 0x10A)
            self.assertEqual(
                command.values, (1, 0x123, 1, ((12, 2),), 2, (), 3, 0xFFFFFFFF)
            )
            event = selected.event()
            self.assertEqual(event.request, b"\x21\x0c")
            self.assertEqual(event.accept(b"\x61\x0c\x12\x34", 7), (7, b"\x12\x34"))
            self.assertEqual(event.accept(b"\x61\x0c\x56", 8), (8, b"\x56\0"))

    def test_additional_frame_selected_first_match_and_native117_wire(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored", addition=True)
            selected = selected_psa_monitor(
                profile,
                (1,),
                {12: 2},
                observed(),
                detail_mode35=0,
                interface_id=7,
                excluded=0,
                standard_values=(),
            )
            self.assertEqual(selected.addition_frames, ((12, b"\xaa\xbb"),))
            command = selected.commands.setup[-1]
            self.assertEqual(command.command_id, 0x117)
            self.assertEqual(
                command.values,
                (7, bytes.fromhex("01000000010000000c0100000002000000aabb")),
            )
            self.assertEqual(
                encode_native_mode21(((12, b"\xaa\xbb"),)), command.values[1]
            )
            wire = NativeDmciCommand.from_neutral(
                command.command_id, command.values
            ).encode()
            self.assertIn(b"\xaa\xbb", wire)
            self.assertEqual(selected.event().request, b"\x21\x0c\xaa\xbb")

    def test_pack_source_order_missing_zero_and_native_mode_stubs(self):
        definitions = MonitorDefinitions(
            (1, 2),
            (MonitorRange(0, 7, 1, 5, 0, 0, 0), MonitorRange(0, 7, 2, 6, 0, 0, 0)),
            (),
            "authored",
        )
        packed = pack_psa(
            definitions, {6: 3, 5: 2}, observed(), excluded=0, detail_mode35=0
        )
        self.assertEqual(packed.setup_requests, (b"\x21\x05\x06", b"\x61\x02\x03"))
        with self.assertRaises(MonitorError) as caught:
            pack_psa(definitions, {5: 2}, observed(), excluded=0, detail_mode35=0)
        self.assertEqual(caught.exception.code, 0xC0050414)
        values = observed()
        values[12] = False
        values[22] = True
        with self.assertRaises(MonitorError) as caught:
            pack_psa(definitions, {5: 2, 6: 3}, values, excluded=0, detail_mode35=0)
        self.assertEqual(caught.exception.code, 0xC0050004)

    def test_dynamic_identifier_positions_and_absence(self):
        rows = []
        for signal, identifier, start, end in ((1, 2, 16, 16), (2, 3, 24, 31)):
            row = bytearray(84)
            struct.pack_into("<H", row, 56, signal)
            struct.pack_into("<HH", row, 62, start, end)
            row[79], row[83] = 12, identifier
            rows.append(bytes(row))
        result = create_psa_frame_map(12, b"\x02\x03", rows)
        self.assertEqual(
            (result.positions, result.widths, result.total_bits), ((7, 8), (1, 8), 16)
        )
        self.assertEqual(result.position(rows[0]), (7, 7))
        self.assertEqual(result.position(rows[1]), (8, 15))
        with self.assertRaises(ToyotaCodecError):
            create_psa_frame_map(12, b"\x04", rows)

    def test_mode35_layout_override_flags_and_modes_follow_native26e0(self):
        row = bytearray(84)
        struct.pack_into("<H", row, 56, 1)
        struct.pack_into("<HH", row, 62, 16, 23)
        row[79], row[83] = 12, 2
        definitions = MonitorDefinitions(
            (1,), (MonitorRange(16, 23, 1, 12, 0, 0, 0),), (), "authored"
        )
        for flag, mode, expected in (
            (0, 0, (16, 23)),
            (1, 0, (0, 7)),
            (1, 1, (0, 7)),
            (1, 2, (16, 23)),
        ):
            row[78], row[77] = flag, mode
            result = pack_psa(
                definitions,
                {12: 3},
                observed(),
                excluded=0,
                detail_mode35=1,
                mode35_data={12: b"\x02"},
                freeze_rows=(bytes(row),),
            )
            self.assertEqual(result.layouts[0][2:], expected)
        row[77] = 3
        with self.assertRaises(MonitorError) as caught:
            pack_psa(
                definitions,
                {12: 3},
                observed(),
                excluded=0,
                detail_mode35=1,
                mode35_data={12: b"\x02"},
                freeze_rows=(bytes(row),),
            )
        self.assertEqual(caught.exception.code, 0xA0040004)

    def test_polling_foreign_address_receive_only_and_literal_arguments(self):
        event = LegacyMonitorEvent.psa((12,), (2,))
        driver = Driver(
            [0],
            [
                MonitorReceive(b"\x61\x0c\x00\x00", 8, 0),
                MonitorReceive(b"\x61\x0c\x12\x34", 7, 0),
            ],
        )
        self.assertEqual(cycle(event, driver), (99, b"\x12\x34"))
        self.assertEqual(
            [row[0] for row in driver.calls], ["send", "receive", "receive"]
        )
        self.assertEqual(
            driver.calls[0][3], {"timeout": 1000, "protocol": 0x12, "initialize": True}
        )
        self.assertEqual(
            driver.calls[1][2],
            {
                "buffer": True,
                "maximum": 4096,
                "timeout": 200,
                "argument_5": 0,
                "flags": 100,
            },
        )

    def test_native_tick_observation_precedes_foreign_address_filter(self):
        driver = Driver(
            [0],
            [
                MonitorReceive(b"\x61\x0c\xaa", 8, 0),
                MonitorReceive(b"\x61\x0c\xbb", 7, 0),
            ],
        )
        ticks = []

        def tick():
            ticks.append(len(ticks) + 7)
            return ticks[-1]

        self.assertEqual(
            cycle(LegacyMonitorEvent.psa((12,), (1,)), driver, tick_ms=tick),
            (8, b"\xbb"),
        )
        self.assertEqual(ticks, [7, 8])

    def test_retry_and_negative_response_mapping(self):
        for code, expected in (
            (0x90020321, 0xE000010E),
            (0x90020323, 0xE000010E),
            (1, 0xE0000108),
        ):
            driver = Driver([0, 0, 0], [MonitorReceive(b"\x7f\x21\x22", 7, code)] * 3)
            with self.assertRaises(MonitorError) as caught:
                cycle(LegacyMonitorEvent.psa((12,), (2,)), driver)
            self.assertEqual(caught.exception.code, expected)
        driver = Driver([3, 0], [MonitorReceive(b"\x61\x0c\x12\x34", 7, 0)])
        self.assertEqual(
            cycle(LegacyMonitorEvent.psa((12,), (2,)), driver), (99, b"\x12\x34")
        )

    def test_concrete_raw_support_cache_to_selected_setup(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored")
            # DB206 provides native fixedlength2, so nativeValidIdExt does not query.
            requests = []

            def exchange(ecu, request):
                requests.append((ecu, request))
                raise AssertionError("Native fixed length must not send a query")

            result = selected_psa_from_exchange(
                profile,
                (1,),
                exchange,
                "authored",
                observed(),
                detail_mode35=0,
                interface_id=7,
                excluded=0,
                standard_values=(),
            )
            self.assertEqual(result.frame_sizes, ((0, 2),))
            self.assertEqual(requests, [])
            # Zero DB206 length forces actual template21+PID request and reply2header.
            directory = profile.catalog.root
            path = directory / "DemoEngine.ddb"
            database = parse_database(path.read_bytes())
            sections = {
                slot: (value.count, value.payload)
                for slot, value in database.sections.items()
            }
            sections[6] = (1, bytes((0, 0, 12, 0, 0, 0, 0, 0)))
            path.write_bytes(_ddb(2, sections))
            profile = VehicleCatalog(directory).build_profile(1)

            def captured(ecu, request):
                requests.append((ecu, request))
                self.assertEqual(request, bytes.fromhex("210c"))
                return bytes.fromhex("610c1234")

            result = selected_psa_from_exchange(
                profile,
                (1,),
                captured,
                "authored",
                observed(),
                detail_mode35=0,
                interface_id=7,
                excluded=0,
                standard_values=(),
            )
            self.assertEqual(requests, [("authored", bytes.fromhex("210c"))])
            self.assertEqual(result.frame_sizes, ((0, 2),))

    def test_selected_sld_uses_actual_trigger_frame_and_native_descriptor_dispatch(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored")
            path = profile.catalog.root / "DemoEngine.ddb"
            database = parse_database(path.read_bytes())
            sections = {
                slot: (value.count, value.payload)
                for slot, value in database.sections.items()
            }
            freeze = bytearray(sections[10][1])
            freeze[78] |= 8
            sections[10] = (1, bytes(freeze))
            sections[19] = (1, struct.pack("<HHHBB", 1, 15, 0, 9, 0))
            path.write_bytes(_ddb(2, sections))
            profile = VehicleCatalog(profile.catalog.root).build_profile(1)
            # The actual authoredtrigger21/00 suppliesonlyrequestdescriptor: native
            # zero-filled missinglength has no safecomplete pair, reject beforeI/O.
            with self.assertRaises(MonitorError) as caught:
                selected_psa_monitor(
                    profile,
                    (1,),
                    {},
                    observed(),
                    detail_mode35=0,
                    interface_id=7,
                    excluded=0,
                    standard_values=(),
                )
            self.assertEqual(caught.exception.code, 0xC005100E)

    def test_selected_psa_metadata_and_commands_reach_native_consumers(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored", addition=True)
            selected = selected_psa_monitor(
                profile,
                (1,),
                {12: 2},
                observed(),
                detail_mode35=0,
                interface_id=7,
                excluded=0,
                standard_values=(),
            )
            metadata = native_monitor_buffer(
                profile.category,
                selected.signals,
                selected.frame_sizes,
                selected.definitions.selected_ids,
                phase=0,
                allocation_size=4096,
                name=b"PSA\0",
                text_encoding="ascii",
            )
            decoded = NativeMonitorBuffer.parse(metadata.encode())
            self.assertEqual(decoded.encode(), metadata.encode())
            self.assertEqual(decode_command(decoded.frame_table)["frames"], ((0, 2),))
            signals = decode_command(decoded.signal_table)["signals"]
            assert isinstance(signals, tuple)
            assert isinstance(signals[0], NativeMonitorSignal)
            self.assertEqual(signals[0].scaling_words, (4, 1, 0))
            self.assertEqual(signals[0].strings[0].data, b"Engine speed\0")
            requests = []

            def exchange(request, *, deadline, cancelled):
                self.assertGreater(deadline, 0)
                self.assertFalse(cancelled())
                command, payload = decode_vim_command(request)
                requests.append((command, payload))
                return NativeVimReply(command | 0x80, 6, bytes(4)).encode()

            client = NativeVimClient(
                exchange,
                capabilities=frozenset(
                    {
                        "denso-vim-control",
                        "denso-vim-dmci",
                    }
                ),
            )
            for item in (
                *selected.commands.setup,
                *selected.commands.start,
                *selected.commands.stop,
            ):
                command = NativeDmciCommand.from_neutral(item.command_id, item.values)
                self.assertEqual(client.dmci(command), b"")
            self.assertEqual(
                [item[0] for item in requests], [0x167F, 0x277F, 0x187F, 0x1A7F]
            )
            self.assertEqual(
                requests[1][1],
                NativeDmciCommand.from_neutral(
                    0x117,
                    selected.commands.setup[1].values,
                ).encode(),
            )

    def test_special_layout_uses_native_first_matching_frame_descriptor(self):
        definitions = MonitorDefinitions(
            (1, 2),
            (MonitorRange(0, 15, 1, 12, 0, 0, 0), MonitorRange(0, 7, 2, 12, 0, 8, 0)),
            (),
            "authored",
        )
        packing = pack_psa(
            definitions,
            {12: 2},
            observed(),
            excluded=0,
            detail_mode35=0,
            special_request=b"\x61\x02",
        )
        self.assertEqual(packing.frame_sizes, ((0, 2), (1, 1)))
        self.assertEqual(packing.layouts, ((1, 0, 0, 15), (2, 0, 0, 7)))

    def test_check_measurement_uses_selected_protocol_and_concrete_support(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored")

            def no_exchange(ecu, request):
                self.fail("Fixed selected DB206 length must not contact provider")

            measurement = check_psa_measurement(
                profile,
                (1,),
                no_exchange,
                "authored",
                observed(),
                bus_id=0x12,
                detail_mode35=0,
            )
            self.assertEqual(measurement, PSAMeasurement(4, 6, 0, 0x20))
            with self.assertRaises(MonitorError) as caught:
                check_psa_measurement(
                    profile,
                    (1,),
                    no_exchange,
                    "authored",
                    observed(),
                    bus_id=0x11,
                    detail_mode35=0,
                )
            self.assertEqual(caught.exception.code, 0xC0050101)

    def test_actual_multi_check_joins_and_aggregate_exchange_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored")
            targets = tuple(
                PSACheckTarget(profile, (1,), name, 0x12, observed(), 0)
                for name in ("authored-a", "authored-b")
            )

            def no_exchange(ecu, request):
                self.fail("Fixed selected DB206 lengths require no exchange")

            values = check_psa_multi(targets, 11, no_exchange)
            self.assertEqual(tuple(item.allocation for item in values), (5, 6))
            self.assertEqual(tuple(item.packet_size for item in values), (6, 6))
            with self.assertRaises(MonitorError) as caught:
                check_psa_multi((), 10, no_exchange)
            self.assertEqual(caught.exception.code, 0xC0050404)
            with self.assertRaises(Cancelled):
                check_psa_multi(targets, 11, no_exchange, cancelled=lambda: True)
            path = profile.catalog.root / "DemoEngine.ddb"
            database = parse_database(path.read_bytes())
            sections = {
                slot: (value.count, value.payload)
                for slot, value in database.sections.items()
            }
            sections[6] = (1, bytes((0, 0, 12, 0, 0, 0, 0, 0)))
            path.write_bytes(_ddb(2, sections))
            profile = VehicleCatalog(profile.catalog.root).build_profile(1)
            targets = tuple(
                PSACheckTarget(profile, (1,), name, 0x12, observed(), 0)
                for name in ("authored-a", "authored-b")
            )
            calls = []

            def exchange(ecu, request):
                calls.append((ecu, request))
                return bytes.fromhex("610c1234")

            with self.assertRaises(MonitorError):
                check_psa_multi(targets, 11, exchange, limits=Limits(exchanges=1))
            self.assertEqual(calls, [("authored-a", bytes.fromhex("210c"))])

    def test_support_timeout_performs_native_null_init_before_next_page(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored")
            path = profile.catalog.root / "DemoEngine.ddb"
            database = parse_database(path.read_bytes())
            sections = {
                slot: (value.count, value.payload)
                for slot, value in database.sections.items()
            }
            sections[3] = (
                2,
                bytes((0, 0, 0, 0, 0, 1, 0, 0)) + bytes((0, 0, 0, 0, 8, 1, 0, 0)),
            )
            path.write_bytes(_ddb(2, sections))
            profile = VehicleCatalog(profile.catalog.root).build_profile(1)
            events = []

            class Stream:
                def send(self, send):
                    events.append(
                        (
                            "init",
                            send.request,
                            send.parameter4,
                            send.parameter5,
                            send.parameter6,
                            send.parameter7,
                        )
                    )
                    return 0

                def receive(self, receive):
                    raise AssertionError("InitEcu has no receive")

            def exchange(ecu, request):
                events.append(("query", ecu, request))
                if request == bytes.fromhex("2100"):
                    raise ToyotaCodecError("Authored timeout", 0x91010009)
                self.assertEqual(request, bytes.fromhex("2108"))
                return bytes.fromhex("610810")

            selected = selected_psa_from_exchange(
                profile,
                (1,),
                exchange,
                "authored",
                observed(),
                detail_mode35=0,
                interface_id=7,
                excluded=0,
                standard_values=(),
                support_stream=Stream(),
                bus_id=0x12,
            )
            self.assertEqual(selected.packing.enabled_pairs, ((12, 2),))
            self.assertEqual(
                events,
                [
                    ("query", "authored", bytes.fromhex("2100")),
                    ("init", None, 1000, 0x12, 1, 1),
                    ("query", "authored", bytes.fromhex("2108")),
                ],
            )

    def test_source_selected_comtol_interface_lifecycle_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored")
            self.assertEqual(psa_comtol_identity(profile, 0x1A), (0x7E0, 0x7C0, 50))
            selected = selected_psa_monitor(
                profile,
                (1,),
                {12: 2},
                observed(),
                detail_mode35=0,
                interface_id=0x7E0,
                excluded=0,
                standard_values=(),
            )
            commands = psa_comtol_commands(profile, selected, 0x1A)
            with self.assertRaises(MonitorError):
                psa_comtol_commands(
                    replace(profile, exception_ids=(7,)), selected, 0x1A
                )
            category = bytearray(profile.category_record)
            category[73] ^= 1
            with self.assertRaises(MonitorError):
                psa_comtol_commands(
                    replace(profile, category_record=bytes(category)), selected, 0x1A
                )

            management_path = profile.catalog.root / "Toyota.ddb"
            management = parse_database(management_path.read_bytes())
            sections = {
                slot: (value.count, value.payload)
                for slot, value in management.sections.items()
            }
            altered = bytearray(sections[16][1])
            altered[72] = 19
            sections[16] = (1, bytes(altered))
            management_path.write_bytes(_ddb(1, sections))
            other_profile = VehicleCatalog(profile.catalog.root).build_profile(1)
            self.assertEqual(other_profile.database.sha256, profile.database.sha256)
            self.assertNotEqual(
                other_profile.catalog.management.sha256,
                profile.catalog.management.sha256,
            )
            with self.assertRaises(MonitorError):
                psa_comtol_commands(other_profile, selected, 0x1A)
            self.assertEqual(
                tuple(item.command_id for item in commands.setup),
                (0x115, 0x107, 0x111, 0x10A),
            )
            self.assertEqual(
                commands.setup[0].values, (1, 0x36, 0xC0, 0x1F, 0xC6, 0x40030, 1, 2, 10)
            )
            self.assertEqual(
                commands.setup[2].values, (0x7E0, 0x7C0, 50, 0xFFFFFFFF, 0xFFFFFFFF)
            )
            self.assertEqual(
                tuple(item.command_id for item in commands.stop), (0x10E, 0x108, 0x104)
            )
            calls = []

            def exchange(request, *, deadline, cancelled):
                command, payload = decode_vim_command(request)
                calls.append((command, payload))
                return NativeVimReply(command | 0x80, 6, bytes(4)).encode()

            client = NativeVimClient(
                exchange,
                capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
            )
            for item in (*commands.setup, *commands.start, *commands.stop):
                client.dmci(
                    NativeDmciCommand.from_neutral(item.command_id, item.values)
                )
            self.assertEqual(
                [item[0] for item in calls],
                [0x257F, 0x137F, 0x1D7F, 0x167F, 0x187F, 0x1A7F, 0x147F, 0x127F],
            )
            self.assertTrue(
                calls[0][1].endswith(
                    bytes.fromhex("0136c01fc60000003000040001000000020000000a000000")
                )
            )
            with self.assertRaises(MonitorError):
                psa_comtol_commands(profile, selected, 0x12)

    def test_typed_support_query_reaches_selected_native_frame_builder(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored")
            path = profile.catalog.root / "DemoEngine.ddb"
            database = parse_database(path.read_bytes())
            sections = {
                slot: (value.count, value.payload)
                for slot, value in database.sections.items()
            }
            sections[6] = (1, bytes((0, 0, 12, 0, 0, 0, 0, 0)))
            path.write_bytes(_ddb(2, sections))
            profile = VehicleCatalog(profile.catalog.root).build_profile(1)
            sent = []

            def transaction(query):
                self.assertEqual(query.ecu, "authored")
                self.assertEqual(query.native_parameter, 0)
                self.assertEqual(
                    query.selected.function_record[2:4], bytes.fromhex("0f00")
                )
                self.assertEqual(
                    query.selected.settings_record[:8], struct.pack("<II", 1000, 1000)
                )
                self.assertEqual(
                    query.source_identity[1:3],
                    (profile.database.sha256, profile.catalog.management.sha256),
                )
                plan = get_comm_frame(
                    profile,
                    query.request,
                    bus_id=0x12,
                    driver=DriverProperties(0, b"03.04", "authored observation"),
                )
                sent.append(plan.send.encode())
                self.assertEqual(plan.send.data, bytes.fromhex("000007e0210c"))
                self.assertEqual(plan.startup_request, bytes.fromhex("aabb"))
                return bytes.fromhex("610c1234")

            selected = selected_psa_from_transaction(
                profile,
                (1,),
                transaction,
                "authored",
                observed(),
                detail_mode35=0,
                interface_id=0x7E0,
                excluded=0,
                standard_values=(),
            )
            self.assertEqual(selected.packing.enabled_pairs, ((12, 2),))
            self.assertEqual(len(sent), 1)
            self.assertTrue(sent[0].endswith(bytes.fromhex("000007e0210c")))

    def test_full_selected_psa_drs_capture_and_cleanup_at_each_native_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored")
            selected = selected_psa_monitor(
                profile,
                (1,),
                {12: 2},
                observed(),
                detail_mode35=0,
                interface_id=0x7E0,
                excluded=0,
                standard_values=(),
            )
            lifecycle = psa_comtol_commands(profile, selected, 0x1A)
            metadata = native_monitor_buffer(
                profile.category,
                selected.signals,
                selected.frame_sizes,
                selected.definitions.selected_ids,
                phase=0,
                allocation_size=4096,
                name=b"PSA\0",
                text_encoding="ascii",
            )
            parameters = NativeTriggerParameters(
                (1, 0),
                1,
                2,
                (1, 0),
                (NativeTriggerCondition((1, 0), 1, 6, 12, 1, 1),),
                (1, 0),
                (),
            )
            settings = DrsFile.parse(
                DrsFile(
                    2,
                    0,
                    (
                        encode_command(2, {"monitor": metadata}),
                        encode_command(
                            5, {"trigger": NativeTriggerInfo((1, 0), 2, 2, 50)}
                        ),
                        encode_command(6, {"trigger": parameters}),
                        encode_command(
                            0x11,
                            {
                                "children": tuple(
                                    NativeDmciCommand.from_neutral(
                                        item.command_id, item.values
                                    ).table()
                                    for item in (*lifecycle.setup, *lifecycle.start)
                                )
                            },
                        ),
                        encode_command(
                            0x12,
                            {
                                "children": tuple(
                                    NativeDmciCommand.from_neutral(
                                        item.command_id, item.values
                                    ).table()
                                    for item in lifecycle.stop
                                )
                            },
                        ),
                    ),
                ).encode()
            )
            for failure in (
                None,
                0x257F,
                0x137F,
                0x1D7F,
                0x167F,
                0x187F,
                0x197F,
                0x1A7F,
            ):
                with self.subTest(failure=failure):
                    calls = []
                    values = iter(((1000, 1), (2000, 4), (3000, 5)))
                    primary = OSError("Authored native-stage failure")

                    def exchange(
                        request,
                        *,
                        deadline,
                        cancelled,
                        calls=calls,
                        failure=failure,
                        primary=primary,
                        values=values,
                    ):
                        command, _payload = decode_vim_command(request)
                        calls.append(command)
                        if command == failure:
                            raise primary
                        if command == 0x197F:
                            stamp, value = next(values)
                            empty = NativeCoreBuffer((1, 0), b"")
                            reply = NativeMonitorReply(
                                0,
                                NativeDmciList(
                                    (1, 0),
                                    (
                                        (
                                            0x7E0,
                                            NativeCoreBuffer(
                                                (1, 0),
                                                struct.pack("<I", stamp)
                                                + struct.pack(">H", value * 4),
                                            ),
                                        ),
                                    ),
                                ),
                                (empty, empty, empty, empty, empty),
                                0,
                            ).encode()
                        else:
                            reply = bytes(4)
                        return NativeVimReply(command | 0x80, 6, reply).encode()

                    client = NativeVimClient(
                        exchange,
                        capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                        clock=lambda: 0.0,
                    )
                    recorder = NativeMonitorRecorder(
                        settings, client, interface_id=0x7E0, phase=0
                    )
                    if failure is None:
                        captured = recorder.capture()
                        self.assertEqual(captured.trigger_timestamp_ms, 2000)
                        self.assertEqual(len(captured.packets), 3)
                    else:
                        with self.assertRaises(OSError) as caught:
                            recorder.capture()
                        self.assertIs(caught.exception, primary)
                    self.assertEqual(calls[-3:], [0x1A7F, 0x147F, 0x127F])

    def test_pack_rejects_invalid_native_scalar_widths_and_preserves_output(self):
        for values in (
            (-1, 7, 1, 12, 0, 0, 0),
            (8, 7, 1, 12, 0, 0, 0),
            (0, 7, 1, 256, 0, 0, 0),
            (0, 7, 1, 12, 0, 256, 0),
        ):
            with self.assertRaises(MonitorError):
                MonitorRange(*values)
        missing = MonitorDefinitions(
            (1,), (MonitorRange(0, 7, 1, 12, 0, 0, 0),), (), "authored"
        )
        with self.assertRaises(MonitorError) as caught:
            pack_psa(missing, {}, {}, excluded=0, detail_mode35=0)
        self.assertEqual(caught.exception.code, 0xC0050414)
        source = {12: 2}
        definitions = MonitorDefinitions(
            (1,), (MonitorRange(0, 7, 1, 12, 0, 0, 0),), (), "authored"
        )
        packing = pack_psa(definitions, source, observed(), excluded=0, detail_mode35=0)
        source[12] = 255
        self.assertEqual(
            packing.setup_requests, (bytes.fromhex("210c"), bytes.fromhex("6102"))
        )
        self.assertEqual(packing.frame_sizes, ((0, 2),))

    def test_direct_j2534_source_timers_start_poll_stop_and_reentry(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored")
            selected = selected_psa_monitor(
                profile,
                (1,),
                {12: 2},
                observed(),
                detail_mode35=0,
                interface_id=0x7E0,
                excluded=0,
                standard_values=(),
            )
            monitor = PSAJ2534Monitor(profile, selected, 0x1A, "authored")
            self.assertEqual(
                (monitor.send_timeout, monitor.receive_timeout), (1000, 200)
            )
            with self.assertRaises(MonitorError):
                monitor.poll(Driver([], []), tick_ms=lambda: 1)
            monitor.start()
            self.assertFalse(dict(monitor.signals)[0x30])
            self.assertTrue(dict(monitor.signals)[0x2C])
            driver = Driver([0], [MonitorReceive(bytes.fromhex("610c1234"), 0x7C0, 0)])

            def tick():
                with self.assertRaises(MonitorError):
                    monitor.poll(driver, tick_ms=lambda: 0)
                monitor.stop()
                return 77

            self.assertEqual(
                monitor.poll(driver, tick_ms=tick), (77, bytes.fromhex("1234"))
            )
            self.assertEqual(monitor.state, "stopped")
            self.assertTrue(dict(monitor.signals)[0x38])
            self.assertEqual(driver.calls[0][3]["protocol"], 0x1A)
            self.assertEqual(driver.calls[1][2]["timeout"], 200)
            with self.assertRaises(MonitorError):
                monitor.poll(driver, tick_ms=lambda: 1)
            path = profile.catalog.root / "Toyota.ddb"
            management = parse_database(path.read_bytes())
            sections = {
                slot: (value.count, value.payload)
                for slot, value in management.sections.items()
            }
            rows = [
                sections[18][1][offset : offset + 16]
                for offset in range(0, len(sections[18][1]), 16)
            ]
            rows.append(struct.pack("<8H", 1, 0xA7, 1, 1, 0, 1, 0, 0))
            rows.sort(key=lambda row: struct.unpack_from("<H", row, 2)[0])
            sections[18] = (len(rows), b"".join(rows))
            path.write_bytes(_ddb(1, sections))
            other = VehicleCatalog(profile.catalog.root).build_profile(1)
            with self.assertRaises(MonitorError):
                PSAJ2534Monitor(other, selected, 0x1A, "authored")
            selected = selected_psa_monitor(
                other,
                (1,),
                {12: 2},
                observed(),
                detail_mode35=0,
                interface_id=0x7E0,
                excluded=0,
                standard_values=(),
            )
            monitor = PSAJ2534Monitor(other, selected, 0x1A, "authored")
            self.assertEqual(
                (monitor.send_timeout, monitor.receive_timeout), (1000, 1000)
            )
            monitor.start()
            with self.assertRaises(Cancelled):
                monitor.poll(Driver([], []), tick_ms=lambda: 0, cancelled=lambda: True)
            self.assertEqual(monitor.state, "failed")
            monitor.stop()
            with self.assertRaises(MonitorError):
                monitor.start()
            monitor.setup()
            monitor.start()
            self.assertEqual(monitor.state, "running")

    def test_both_source_versions_use_actual_authored_profile_layouts(self):
        with tempfile.TemporaryDirectory() as temporary:
            for version in (12, 18):
                with self.subTest(version=version):
                    profile = authored_profile(
                        Path(temporary) / str(version), addition=True, version=version
                    )
                    self.assertEqual(
                        profile.database.version,
                        0x0100030C if version == 12 else 0x0100032F,
                    )
                    selected = selected_psa_monitor(
                        profile,
                        (1,),
                        {12: 2},
                        observed(),
                        detail_mode35=0,
                        interface_id=0x7E0,
                        excluded=0,
                        standard_values=(),
                    )
                    self.assertEqual(selected.signals[0].name, "Engine speed")
                    self.assertEqual(selected.frame_sizes, ((0, 2),))
                    self.assertEqual(
                        selected.addition_frames, ((12, bytes.fromhex("aabb")),)
                    )
                    commands = psa_comtol_commands(profile, selected, 0x1A)
                    self.assertEqual(
                        commands.setup[2].values,
                        (0x7E0, 0x7C0, 50, 0xFFFFFFFF, 0xFFFFFFFF),
                    )
                    monitor = PSAJ2534Monitor(profile, selected, 0x1A, "authored")
                    monitor.start()
                    driver = Driver(
                        [0], [MonitorReceive(bytes.fromhex("610c1234"), 0x7C0, 0)]
                    )
                    self.assertEqual(
                        monitor.poll(driver, tick_ms=lambda: 17),
                        (17, bytes.fromhex("1234")),
                    )
                    monitor.stop()

    def test_actual_psa_low_a_frame_plan_and_native_receive_reach_polling(self):
        with tempfile.TemporaryDirectory() as temporary:
            for version in (12, 18):
                with self.subTest(version=version):
                    profile = authored_profile(
                        Path(temporary) / str(version), version=version
                    )
                    observed_driver = DriverProperties(
                        0, b"03.04", "authored driver reply"
                    )
                    plan = psa_j2534_frame_plan(
                        profile,
                        bytes.fromhex("210c"),
                        bus_id=0x1A,
                        driver=observed_driver,
                    )
                    self.assertEqual(
                        plan.frame.connect.encode(), bytes.fromhex("0c00010000000000")
                    )
                    self.assertEqual(plan.open_baud, 0)
                    for bus, prefix, pattern in (
                        (0x2A, "000007e000", "000007e8"),
                        (0x3A, "00000000", None),
                        (0x4A, "000007e0", "000006e0"),
                        (0x5A, "000007e0", "00000720"),
                    ):
                        other = psa_j2534_frame_plan(
                            profile,
                            bytes.fromhex("210c"),
                            bus_id=bus,
                            driver=observed_driver,
                        )
                        self.assertEqual(
                            other.frame.send.data, bytes.fromhex(prefix + "210c")
                        )
                        if pattern is None:
                            self.assertEqual(other.frame.filters, ())
                        else:
                            self.assertEqual(
                                other.frame.filters[0].pattern.data,
                                bytes.fromhex(pattern),
                            )

                    self.assertEqual(
                        plan.frame.send.encode(),
                        bytes.fromhex(
                            "06000000 00000000 00000000 00000000 06000000 06000000 000007e0210c"
                        ),
                    )
                    self.assertEqual(
                        tuple(item.pattern.data for item in plan.frame.filters),
                        (bytes.fromhex("000007c0"), bytes.fromhex("000007c0")),
                    )
                    self.assertEqual(
                        plan.frame.filters[1].flow_control.data,
                        bytes.fromhex("000007e0"),
                    )
                    with self.assertRaises(FrameTransportError):
                        get_comm_frame(
                            profile,
                            bytes.fromhex("210c"),
                            bus_id=0x1A,
                            driver=observed_driver,
                        )
                    selected = selected_psa_monitor(
                        profile,
                        (1,),
                        {12: 2},
                        observed(),
                        detail_mode35=0,
                        interface_id=0x7E0,
                        excluded=0,
                        standard_values=(),
                    )
                    monitor = PSAJ2534Monitor(profile, selected, 0x1A, "authored")
                    writes = []

                    class PrimitiveDriver:
                        def __init__(self, profile, observed_driver, writes):
                            self.profile, self.driver, self.writes = (
                                profile,
                                observed_driver,
                                writes,
                            )

                        def send(self, ecu, request, **options):
                            self_plan = psa_j2534_frame_plan(
                                self.profile,
                                request,
                                bus_id=options["protocol"],
                                driver=self.driver,
                            )
                            self.writes.append(self_plan.frame.send.encode())
                            return 0

                        def receive(self, ecu, **options):
                            raw = NativeMessage(
                                6, 0, 0, 0, 8, bytes.fromhex("000007c0610c1234")
                            )
                            return decode_psa_j2534_message(
                                raw, bus_id=0x1A, maximum=options["maximum"]
                            )

                    monitor.start()
                    self.assertEqual(
                        monitor.poll(
                            PrimitiveDriver(profile, observed_driver, writes),
                            tick_ms=lambda: 9,
                        ),
                        (9, bytes.fromhex("1234")),
                    )
                    monitor.stop()
                    self.assertEqual(writes, [plan.frame.send.encode()])
        for raw in (b"", bytes.fromhex("000007")):
            with self.assertRaises(MonitorError):
                decode_psa_j2534_message(
                    NativeMessage(6, 0, 0, 0, len(raw), raw), bus_id=0x1A
                )
        extended = NativeMessage(6, 0, 0, 0, 7, bytes.fromhex("000007c0aa61bb"))
        self.assertEqual(
            decode_psa_j2534_message(extended, bus_id=0x2A).data, bytes.fromhex("61bb")
        )

    def test_native_stop_at_request_boundary_preserves_partial_packet(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored")
            path = profile.catalog.root / "DemoEngine.ddb"
            database = parse_database(path.read_bytes())
            sections = {
                slot: (value.count, value.payload)
                for slot, value in database.sections.items()
            }
            second = bytearray(sections[10][1])
            struct.pack_into("<H", second, 56, 2)
            second[79] = 13
            sections[10] = (2, sections[10][1] + second)
            sections[6] = (2, bytes((0, 0, 12, 2, 0, 0, 0, 0, 0, 0, 13, 2, 0, 0, 0, 0)))
            path.write_bytes(_ddb(2, sections))
            profile = VehicleCatalog(profile.catalog.root).build_profile(1)
            selected = selected_psa_monitor(
                profile,
                (1, 2),
                {12: 2, 13: 2},
                observed(),
                detail_mode35=0,
                interface_id=0x7E0,
                excluded=0,
                standard_values=(),
            )
            monitor = PSAJ2534Monitor(profile, selected, 0x1A, "authored")
            driver = Driver([0], [MonitorReceive(bytes.fromhex("610c1234"), 0x7C0, 0)])

            def tick():
                monitor.stop()
                return 1

            monitor.start()
            with self.assertRaises(PSAMonitorStopped):
                monitor.poll(driver, tick_ms=tick)
            self.assertEqual(len(driver.calls), 2)
            self.assertEqual(monitor.event.index, 1)
            self.assertEqual(monitor.state, "stopped")
            monitor.setup()
            self.assertEqual(monitor.event.index, 0)
            monitor.start()
            empty = Driver([], [])

            def clock():
                monitor.stop()
                return 0.0

            with self.assertRaises(PSAMonitorStopped):
                monitor.poll(empty, tick_ms=lambda: 0, clock=clock)
            self.assertEqual(empty.calls, [])
            monitor.setup()
            monitor.start()

            class StopDuringRetry(Driver):
                def send(self, ecu, request, **options):
                    status = super().send(ecu, request, **options)
                    if status:
                        monitor.stop()
                    return status

            retry = StopDuringRetry(
                [1, 0], [MonitorReceive(bytes.fromhex("610c1234"), 0x7C0, 0)]
            )
            with self.assertRaises(PSAMonitorStopped):
                monitor.poll(retry, tick_ms=lambda: 0)
            self.assertEqual(
                [item[0] for item in retry.calls], ["send", "send", "receive"]
            )

    def test_direct_worker_rejects_management_reload_after_primitive(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored")
            selected = selected_psa_monitor(
                profile,
                (1,),
                {12: 2},
                observed(),
                detail_mode35=0,
                interface_id=0x7E0,
                excluded=0,
                standard_values=(),
            )
            monitor = PSAJ2534Monitor(profile, selected, 0x1A, "authored")
            path = profile.catalog.root / "Toyota.ddb"
            management = parse_database(path.read_bytes())
            sections = {
                slot: (value.count, value.payload)
                for slot, value in management.sections.items()
            }
            category = bytearray(sections[16][1])
            category[72] = 19
            sections[16] = (1, bytes(category))
            path.write_bytes(_ddb(1, sections))
            other = VehicleCatalog(profile.catalog.root).build_profile(1)

            class ReloadDuringSend(Driver):
                def send(self, ecu, request, **options):
                    result = super().send(ecu, request, **options)
                    profile.catalog.management = other.catalog.management
                    return result

            driver = ReloadDuringSend([0], [])
            monitor.start()
            with self.assertRaisesRegex(MonitorError, "source context changed"):
                monitor.poll(driver, tick_ms=lambda: 0)
            self.assertEqual([item[0] for item in driver.calls], ["send"])
            self.assertEqual(monitor.event.index, 0)
            self.assertEqual(monitor.state, "failed")
            monitor.stop()

    def test_voltage_check_geometry_from_actual_selected_freeze(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = authored_profile(Path(temporary) / "authored")
            path = profile.catalog.root / "Toyota.ddb"
            database = parse_database(path.read_bytes())
            sections = {
                slot: (value.count, value.payload)
                for slot, value in database.sections.items()
            }
            category = bytearray(sections[16][1])
            struct.pack_into("<H", category, 68, 0x68)
            sections[16] = (1, bytes(category))
            path.write_bytes(_ddb(1, sections))
            profile = VehicleCatalog(profile.catalog.root).build_profile(0x68)
            packing = psa_voltage_packing(profile, (1,))
            self.assertEqual(packing.setup_requests, (bytes.fromhex("0400000001"),))
            self.assertEqual(packing.frame_sizes, ((0, 2),))
            self.assertEqual(psa_measurement(packing, 0), PSAMeasurement(4, 6, 0, 0x40))
            with self.assertRaises(MonitorError) as caught:
                psa_voltage_packing(profile, (1, 1))
            self.assertEqual(caught.exception.code, 0x90051003)
            with self.assertRaises(MonitorError) as caught:
                selected_psa_monitor(
                    profile,
                    (1,),
                    {},
                    observed(),
                    detail_mode35=0,
                    interface_id=7,
                    excluded=0,
                    standard_values=(),
                )
            self.assertEqual(caught.exception.code, 0xC0050004)

    def test_native_measurement_bus_cost_and_proportional_remainder(self):
        definitions = MonitorDefinitions(
            (1, 2),
            (MonitorRange(0, 7, 1, 12, 0, 0, 0), MonitorRange(0, 7, 2, 13, 0, 0, 0)),
            (),
            "authored",
        )
        packing = pack_psa(
            definitions, {12: 6, 13: 7}, observed(), excluded=0, detail_mode35=0
        )
        self.assertEqual(
            psa_measurement(packing, 0x11), PSAMeasurement(320, 17, 0, 0x20)
        )
        for bus in (0x12, 0x22, 0x1A, 0x2A):
            self.assertEqual(
                psa_measurement(packing, bus), PSAMeasurement(12, 17, 0, 0x20)
            )
        with self.assertRaises(MonitorError) as caught:
            psa_measurement(packing, 1)
        self.assertEqual(caught.exception.code, 0xC0040602)
        values = (PSAMeasurement(100, 10, 0, 0x20), PSAMeasurement(100, 20, 0, 0x20))
        allocated = psa_allocate_measurements(10, values)
        self.assertEqual(tuple(item.allocation for item in allocated), (3, 7))
        self.assertEqual(tuple(item.allocation for item in values), (0, 0))
        self.assertEqual(psa_allocate_measurements(7, values[:1])[0].allocation, 7)
        for total, items in (
            (0, values),
            (1, ()),
            (1, (PSAMeasurement(0, 1, 0, 0x20),)),
        ):
            with self.assertRaises(MonitorError):
                psa_allocate_measurements(total, items)

    def test_cancellation_deadline_and_driver_call_budget(self):
        for options, exception in (
            ({"cancelled": lambda: True}, Cancelled),
            ({"limits": Limits(exchanges=1)}, MonitorError),
        ):
            driver = Driver([0], [MonitorReceive(b"\x61\x0c\x12\x34", 7, 0)])
            with self.assertRaises(exception):
                cycle(LegacyMonitorEvent.psa((12,), (2,)), driver, **options)
        ticks = iter((0.0, 999.0))
        with self.assertRaises(MonitorError):
            cycle(
                LegacyMonitorEvent.psa((12,), (2,)),
                Driver([], []),
                clock=lambda: next(ticks),
            )


if __name__ == "__main__":
    unittest.main()
