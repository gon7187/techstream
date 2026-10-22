"""Authored native monitor routing and exchange vectors."""

import struct
import unittest
from types import SimpleNamespace
from typing import Literal, cast
from unittest.mock import Mock

from scripts.data_monitor import (
    DynamicSlot,
    DynamicSource,
    MonitorAddress,
    MonitorCommand,
    MonitorDefinitions,
    MonitorError,
    MonitorEvent,
    MonitorGroup,
    MonitorRange,
    MonitorReceive,
    MonitorSetup,
    P5Definitions,
    P5MonitorEvent,
    P5Range,
    RoutineMonitor,
    SelectedMonitorConnection,
    SelectedMonitorSession,
    clear_dynamic_requests,
    dmci_id_map_fields,
    exchange_cycle,
    legacy_initialize,
    monitor_capabilities,
    monitor_mode,
    p4_can_lifecycle,
    p4_composite_layouts,
    p4_iso_configs,
    p4_iso_lifecycle,
    p4_monitor_address,
    p4_monitor_requests,
    p4_setup_commands,
    p4_signal_layouts,
    p5_can_lifecycle,
    p5_dynamic_layouts,
    p5_dynamic_sources,
    p5_monitor_requests,
    p5_setup_commands,
    pack_dynamic_dids,
    pack_p4,
    pack_p5_polling,
    pickup_packet,
    register_dynamic_dids,
    run_monitor_commands,
    select_provider,
    selected_definitions,
    selected_dynamic_slots,
    selected_legacy_check_target,
    selected_monitor_buffer,
    selected_normal_monitor_from_cache,
    selected_normal_monitor_worker,
    selected_p4_connection,
    selected_p4_monitor,
    selected_p5_can_connection,
    selected_p5_definitions,
    selected_p5_dynamic_from_cache,
    selected_p5_polling_monitor,
    selected_p5_signal_metadata,
    selected_signal_metadata,
    selected_variable_monitor_runtime,
)
from scripts.profiles import VehicleProfile


class DataMonitorTests(unittest.TestCase):
    def test_native_dynamic_interchange_sort_reorders_equal_keys(self):
        from unittest.mock import patch

        a = DynamicSource(0x100, ((1, 1), (3, 1)))
        b = DynamicSource(0x101, ((1, 1), (3, 1)))
        c = DynamicSource(0x102, ((1, 1),))
        plan = pack_dynamic_dids(
            b"\x2c\x01\0\0",
            (a, b, c),
            (DynamicSlot(0xF300, 3),),
            max_request=16,
            max_reply=6,
        )
        self.assertEqual(plan.sources, ((c, b),))
        self.assertEqual(plan.remaining, (a,))
        self.assertEqual(
            plan.requests, (bytes.fromhex("2c01f300010201010101010101010301"),)
        )
        with (
            patch("scripts.data_monitor.MAX_DYNAMIC_COMPARISONS", 2),
            self.assertRaisesRegex(MonitorError, "comparison budget"),
        ):
            pack_dynamic_dids(
                b"\x2c\x01\0\0",
                (a, b, c),
                (DynamicSlot(0xF300, 3),),
                max_request=16,
                max_reply=6,
            )

    def test_selected_ddb_dynamic_to_constructor_wire_and_capture(self):
        import tempfile
        from pathlib import Path

        from scripts.demo import _ddb, create_demo
        from scripts.diagnostic_db import parse_database
        from scripts.drive_recorder import (
            NativeCoreBuffer,
            NativeDmciList,
            NativeMonitorReply,
            NativeVimClient,
            NativeVimReply,
            decode_vim_command,
        )
        from scripts.monitor_support import MonitorSupportCache
        from scripts.profiles import VehicleCatalog

        with tempfile.TemporaryDirectory() as temporary:
            root = create_demo(Path(temporary) / "authored") / "Techstream_DB_NA"
            path = root / "Toyota.ddb"
            db = parse_database(path.read_bytes())
            sections = {i: (s.count, s.payload) for i, s in db.sections.items()}
            category = bytearray(sections[16][1])
            category[72] = 20
            sections[16] = (1, bytes(category))
            variables = (
                b"\x21\0",
                b"\x30\0",
                b"\x22\0\0\0",
                b"\x0c",
                b"\x01\0",
                b"\x2c\x03\0\0",
                b"\x2c\x01\0\0",
                b"\x22\0\0",
            )
            pool = bytearray()
            directory = bytearray()
            for variable in variables:
                directory += struct.pack("<IH", len(pool), len(variable))
                pool += variable
            sections[0] = (len(variables), bytes(directory + pool))
            count, rows = sections[17]
            sections[17] = (
                count + 3,
                rows
                + b"".join(
                    struct.pack("<4H", frame, reference, 0, 0)
                    for frame, reference in ((5, 6), (6, 7), (7, 8))
                ),
            )
            count, rows = sections[18]
            sections[18] = (
                count + 4,
                rows
                + b"".join(
                    struct.pack("<8H", 1, function, 1, frame, 0, 1, 0, 0)
                    for function, frame in ((0xC8, 3), (0xCA, 7), (0xD3, 6), (0xD4, 5))
                ),
            )
            protocol = bytearray(28)
            struct.pack_into("<HH", protocol, 0, 1, 99)
            protocol[24] = 0x12
            struct.pack_into("<HH", protocol, 6, 8, 7)
            struct.pack_into("<HH", protocol, 14, 16, 16)
            can = bytearray(28)
            struct.pack_into("<I", can, 4, 500000)
            struct.pack_into("<H", can, 8, 99)
            sections[13] = (1, bytes(protocol))
            sections[14] = (1, bytes(can))
            path.write_bytes(_ddb(1, sections))
            path = root / "DemoEngine.ddb"
            db = parse_database(path.read_bytes())
            sections = {i: (s.count, s.payload) for i, s in db.sections.items()}
            row = bytearray(64)
            struct.pack_into("<I", row, 24, 4)
            struct.pack_into("<HHHH", row, 36, 1, 0, 0, 1)
            struct.pack_into("<HH", row, 44, 3, 10)
            struct.pack_into("<H", row, 54, 0x101)
            sections[62] = (1, bytes(row))
            sections[81] = (1, struct.pack("<HHHBB", 0xF300, 1, 0, 0, 0))
            path.write_bytes(_ddb(2, sections))
            profile = VehicleCatalog(root).build_profile(1)
            queries = []

            def support(query):
                queries.append(query.request)
                return {
                    b"\x22\0\0\0": b"\x62\0\0\x40",
                    b"\x22\x01\0\0": b"\x62\x01\0\x80",
                    b"\x2c\x03\xf3\0": b"\x6c\x03",
                    b"\x2c\x01\xf3\0\x01\x01\x01\x02": b"\x6c\x01",
                    b"\x22\xf3\0": b"\x62\xf3\0AB",
                }[query.request]

            cache = MonitorSupportCache(
                profile, support, "native-selected", source_build=18
            )
            plan = selected_p5_dynamic_from_cache(
                cache,
                (1,),
                {26: True},
                interface_id=7,
                excluded=0,
                standard_values=(),
                parameter_6=2000,
                active_alias_pid=0,
                max_request=16,
                max_reply=16,
            )
            self.assertEqual(len(queries), 5)
            self.assertEqual(
                (
                    plan.signals[0].name,
                    plan.signals[0].start_bit,
                    plan.signals[0].end_bit,
                ),
                ("Engine speed", 3, 10),
            )
            self.assertEqual(
                plan.commands.setup[0].values, (1, 7, ((0xF300, 2),), 2, (), 2000)
            )
            connection = selected_p5_can_connection(
                profile,
                bus_id=0x12,
                diagnostic_mode=bytes(16),
                controller_category_flags=20,
                source_build=18,
            )
            from scripts.monitor_p5 import SelectedP5Monitor

            routed = selected_normal_monitor_from_cache(
                MonitorSupportCache(profile, support, "native-routed", source_build=18),
                (1,),
                {26: True, 73: True},
                communication_protocol=0x12,
                attribute_3_31=None,
                interface_id=7,
                excluded=0,
                standard_values=(),
                max_request=16,
                max_reply=16,
                parameter_6=2000,
                active_alias_pid=0,
                dynamic_requested=True,
            )
            assert isinstance(routed, SelectedP5Monitor)
            from scripts.data_monitor import selected_dual_target

            target = selected_dual_target(
                profile,
                routed,
                ecu="selected-dual",
                bus_id=0x12,
                diagnostic_mode=bytes(16),
                controller_category_flags=20,
                source_build=18,
                retry_limit=2,
                send_timeout=1000,
                receive_timeout=200,
                map_values=(50, 0, 0),
            )
            self.assertEqual(
                (
                    target.request_id,
                    target.response_id,
                    target.command_id,
                    target.entry_parameter,
                ),
                (7, 15, 1, 7),
            )
            with self.assertRaisesRegex(MonitorError, "source builds"):
                selected_dual_target(
                    profile,
                    routed,
                    ecu="selected-dual",
                    bus_id=0x12,
                    diagnostic_mode=bytes(16),
                    controller_category_flags=20,
                    source_build=12,
                    retry_limit=2,
                    send_timeout=1000,
                    receive_timeout=200,
                    map_values=(50, 0, 0),
                )
            self.assertIsInstance(routed, SelectedP5Monitor)
            assert isinstance(routed, SelectedP5Monitor)
            self.assertEqual(
                (routed.commands, routed.frame_sizes), (plan.commands, plan.frame_sizes)
            )
            self.assertEqual(len(queries), 10)
            setup = p5_can_lifecycle(
                routed, connection, connected_device=4, routine_info=1, recording=True
            )
            from dataclasses import replace

            with self.assertRaisesRegex(MonitorError, "source builds"):
                p5_can_lifecycle(
                    replace(plan, source_build=12),
                    connection,
                    connected_device=4,
                    routine_info=1,
                    recording=True,
                )

            with self.assertRaisesRegex(MonitorError, "source identity"):
                p5_can_lifecycle(
                    plan,
                    replace(
                        connection,
                        connection=replace(
                            connection.connection,
                            source_identity=("other-management-db",),
                        ),
                    ),
                    connected_device=4,
                    routine_info=1,
                    recording=True,
                )
            wire = []

            def exchange(request, *, deadline, cancelled):
                command, _ = decode_vim_command(request)
                wire.append(command)
                if command == 0x197F:
                    empty = NativeCoreBuffer((1, 0), b"")
                    reply = NativeMonitorReply(
                        0,
                        NativeDmciList(
                            (1, 0),
                            (
                                (
                                    7,
                                    NativeCoreBuffer(
                                        (1, 0), struct.pack("<I", 0xFFFFFFFE) + b"AB"
                                    ),
                                ),
                            ),
                        ),
                        (empty, empty, empty, empty, empty),
                        0,
                    ).encode()
                else:
                    reply = bytes(4) + (
                        struct.pack("<I", 1) if command == 0x247F else b""
                    )
                return NativeVimReply(command | 0x80, 6, reply).encode()

            client = NativeVimClient(
                exchange,
                capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
            )
            packets = run_monitor_commands(
                setup,
                client,
                interface_id=7,
                frame_sizes=plan.frame_sizes,
                phase=0,
                packet_limit=1,
            )
            self.assertEqual(
                (packets[0].timestamp_raw, packets[0].payload), (0xFFFFFFFE, b"AB")
            )
            self.assertEqual(
                wire,
                (
                    [
                        0x287F,
                        0x137F,
                        0x2D7F,
                        0x1D7F,
                        0x247F,
                        0x297F,
                        0x2A7F,
                        0x187F,
                        0x197F,
                        0x1A7F,
                        0x147F,
                        0x127F,
                    ]
                ),
            )

    def test_native_dmci_rejects_nonfinite_runtime_and_cleanup_clocks(self):
        from scripts.drive_recorder import (
            NativeVimClient,
            NativeVimReply,
            decode_vim_command,
        )
        from scripts.toyota_session import SessionError

        for invalid in (float("nan"), float("inf"), -float("inf")):
            calls = []
            client = NativeVimClient(
                lambda request, *, calls=calls, **kwargs: calls.append(request),
                capabilities=frozenset(),
            )
            plan = MonitorSetup(
                (MonitorCommand(0x107, (1,)),), (), (MonitorCommand(0x108, ()),)
            )
            with self.assertRaisesRegex(SessionError, "finite"):
                run_monitor_commands(
                    plan,
                    client,
                    interface_id=1,
                    frame_sizes=((0, 1),),
                    phase=0,
                    packet_limit=1,
                    clock=lambda invalid=invalid: invalid,
                )
            self.assertEqual(calls, [])
            ticks = iter((0.0, 0.0, invalid, invalid, invalid))

            def exchange(request, *, calls=calls, **kwargs):
                calls.append(request)
                command, _ = decode_vim_command(request)
                return NativeVimReply(command | 0x80, 6, bytes(4)).encode()

            client = NativeVimClient(
                exchange,
                capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
            )
            with self.assertRaisesRegex(SessionError, "finite"):
                run_monitor_commands(
                    plan,
                    client,
                    interface_id=1,
                    frame_sizes=((0, 1),),
                    phase=0,
                    packet_limit=1,
                    clock=lambda ticks=ticks: next(ticks),
                )
            self.assertEqual(len(calls), 1)  # Invalid cleanup clocks send nothing.

    def test_dynamic_packed_signal_offsets_and_preallocation_budget(self):
        from unittest.mock import patch

        from scripts.data_monitor import monitor_composite_layouts

        definitions = P5Definitions(
            (1, 2, 3),
            (
                P5Range(1, 7, 1, 0x100, 0, 0, 0),
                P5Range(19, 23, 2, 0x100, 0, 0, 0),
                P5Range(9, 15, 3, 0x200, 0, 0, 0),
            ),
            (),
            "authored",
        )
        selection = p5_dynamic_sources(definitions, (0x100, 0x200))
        plan = pack_dynamic_dids(
            b"\x2c\x01\0\0",
            selection.sources,
            (DynamicSlot(0xF300, 3),),
            max_request=16,
            max_reply=6,
        )
        self.assertEqual(
            p5_dynamic_layouts(selection, plan),
            (((1, 0, 9, 15), (2, 0, 19, 23), (3, 0, 1, 7)), ((0, 3),)),
        )
        partial = pack_dynamic_dids(
            b"\x2c\x01\0\0",
            selection.sources,
            (DynamicSlot(0xF300, 1),),
            max_request=16,
            max_reply=6,
        )
        with self.assertRaisesRegex(MonitorError, "fallback"):
            p5_dynamic_layouts(selection, partial)
        # Tiny aliased groups must fail before sorting/materializing child spans.
        group = MonitorGroup(9, ((9, 0, 1), (9, 1, 1)), None)
        oversized = MonitorDefinitions((), (), (group, group, group), "authored")
        with (
            patch("scripts.data_monitor.MAX_ITEMS", 4),
            self.assertRaisesRegex(MonitorError, "aggregate"),
        ):
            monitor_composite_layouts(oversized, (), (), ())

    def test_dynamic_registration_native_retry_validation_and_host_faults(self):
        from scripts.monitor_support import MonitorSupportCache
        from scripts.profiles import SelectedFrame
        from scripts.toyota import CommandFrame, ToyotaCodecError
        from scripts.toyota_session import Cancelled

        templates = {0xD4: b"\x2c\x03\0\0", 0xD3: b"\x2c\x01\0\0", 0xCA: b"\x22\0\0"}
        profile = cast(
            VehicleProfile,
            SimpleNamespace(
                category=1,
                category_record=bytes(76),
                exception_ids=(),
                database=SimpleNamespace(sha256="authored"),
                ecu_database_sha256="authored",
                catalog=SimpleNamespace(management=SimpleNamespace(sha256="authored")),
                frame_records=lambda function: (
                    SelectedFrame(
                        CommandFrame(templates[function]),
                        bytes(16),
                        bytes(8),
                        bytes(16),
                        "authored",
                    ),
                ),
                validate_frame=lambda selected: self.assertIn(
                    selected,
                    tuple(
                        SelectedFrame(
                            CommandFrame(template),
                            bytes(16),
                            bytes(8),
                            bytes(16),
                            "authored",
                        )
                        for template in templates.values()
                    ),
                ),
            ),
        )
        source = DynamicSource(0x1234, ((2, 3),))
        slots = tuple(DynamicSlot(0xF300 + i, 1) for i in range(3))
        for build in (12, 18):
            for present, expected in ((False, 0x90051019), (True, 0xA0050422)):
                calls = []

                def empty_exchange(query, calls=calls):
                    calls.append(query.request)
                    return b"\x6c"

                empty_cache = MonitorSupportCache(
                    profile, empty_exchange, "empty", source_build=build
                )
                outcome = register_dynamic_dids(
                    empty_cache,
                    (),
                    slots,
                    max_request=8,
                    max_reply=6,
                    source_rows_present=present,
                )
                self.assertEqual(outcome.status, expected)
                self.assertEqual(outcome.clear_ids, (0xF300, 0xF301, 0xF302))
                self.assertFalse(outcome.disable_packet_ecu)
                self.assertEqual(
                    calls, [b"\x2c\x03\xf3" + bytes((i,)) for i in range(3)]
                )
        for fault in ("none", "clear", "define", "validate", "host", "cancel"):
            with self.subTest(fault=fault):
                calls = []

                def exchange(query, fault=fault, calls=calls):
                    request = query.request
                    calls.append(request)
                    if fault == "host":
                        raise OSError("host transport")
                    if fault == "cancel":
                        raise Cancelled("cancelled")
                    if (
                        fault == "clear"
                        and request[:2] == b"\x2c\x03"
                        or fault == "define"
                        and request[:4] == b"\x2c\x01\xf3\0"
                        or fault == "validate"
                        and request[:1] == b"\x22"
                    ):
                        raise ToyotaCodecError("native status", 0xA0050401)
                    return bytes((request[0] + 0x40,))

                cache = MonitorSupportCache(profile, exchange, "ecu", source_build=18)
                if fault in ("host", "cancel"):
                    with self.assertRaises(OSError if fault == "host" else Cancelled):
                        register_dynamic_dids(
                            cache, (source,), slots, max_request=8, max_reply=6
                        )
                    self.assertEqual(len(calls), 1)
                    continue
                outcome = register_dynamic_dids(
                    cache, (source,), slots, max_request=8, max_reply=6
                )
                self.assertEqual(
                    calls[:3], [b"\x2c\x03\xf3" + bytes((i,)) for i in range(3)]
                )
                if fault != "clear":
                    self.assertEqual(outcome.clear_ids, (0xF300, 0xF301, 0xF302))
                if fault == "clear":
                    self.assertEqual(outcome.clear_ids, ())
                    self.assertEqual(
                        (outcome.status, outcome.disable_packet_ecu), (0xA0050422, True)
                    )
                    self.assertEqual(len(calls), 3)
                    self.assertEqual(len(outcome.failed_clears), 3)
                elif fault == "validate":
                    self.assertEqual(
                        (outcome.status, outcome.plan.read_ids), (0xA0050422, ())
                    )
                    self.assertEqual(outcome.failed_validation, (0xF300, 0xA0050401))
                    self.assertEqual(calls[-1], b"\x22\xf3\0")
                    self.assertEqual(len(calls), 5)  # No invented D4 rollback.
                    self.assertFalse(outcome.disable_packet_ecu)
                else:
                    did = 0xF301 if fault == "define" else 0xF300
                    self.assertEqual(outcome.status, 0)
                    self.assertEqual(outcome.plan.read_ids, (did,))
                    self.assertEqual(calls[3], b"\x2c\x01\xf3\0\x12\x34\x02\x03")
                    if fault == "define":
                        self.assertEqual(calls[4], b"\x2c\x01\xf3\x01\x12\x34\x02\x03")
                        self.assertEqual(
                            outcome.failed_definitions, ((0xF300, 0xA0050401),)
                        )
                    self.assertEqual(calls[-1], b"\x22" + did.to_bytes(2, "big"))

        calls = []
        cache = MonitorSupportCache(
            profile,
            lambda q: calls.append(q.request) or bytes((q.request[0] + 0x40,)),
            "e",
        )
        outcome = register_dynamic_dids(
            cache,
            (source, DynamicSource(0x5678, ((1, 1),))),
            slots[:1],
            max_request=8,
            max_reply=6,
        )
        self.assertEqual(outcome.status, 0x9005100A)
        self.assertEqual(outcome.plan.remaining, (DynamicSource(0x5678, ((1, 1),)),))
        with self.assertRaises(MonitorError):
            register_dynamic_dids(cache, (source,), slots, max_request=-1, max_reply=6)
        self.assertEqual(len(calls), 3)
        for build, failure in (
            (12, "clear"),
            (18, "clear"),
            (12, "validate"),
            (18, "validate"),
        ):
            calls = []

            def versioned_exchange(query, *, calls=calls, failure=failure):
                request = query.request
                calls.append(request)
                if (
                    failure == "clear"
                    and request == b"\x2c\x03\xf3\0"
                    or failure == "validate"
                    and request[:1] == b"\x22"
                ):
                    raise ToyotaCodecError("native status", 0xA0050401)
                return bytes((request[0] + 0x40,))

            cache = MonitorSupportCache(
                profile, versioned_exchange, "versioned", source_build=build
            )
            outcome = register_dynamic_dids(
                cache, (source,), slots, max_request=8, max_reply=6
            )
            if failure == "clear" and build == 12:
                self.assertEqual(
                    (len(calls), outcome.status, outcome.disable_packet_ecu),
                    (1, 0xA0050422, True),
                )
            elif failure == "clear":
                self.assertEqual(
                    (len(calls), outcome.status, outcome.plan.read_ids),
                    (5, 0, (0xF301,)),
                )
            else:
                self.assertEqual(
                    (len(calls), outcome.status, outcome.disable_packet_ecu),
                    (5, 0xA0050422, False),
                )

    def test_native_dmci_polling_bytes_and_cleanup(self):
        from scripts.drive_recorder import (
            NativeCoreBuffer,
            NativeDmciList,
            NativeMonitorReply,
            NativeVimClient,
            NativeVimReply,
            decode_vim_command,
        )
        from scripts.toyota_session import Limits

        plan = MonitorSetup(
            (), (MonitorCommand(0x10C, ()),), (MonitorCommand(0x10E, ()),)
        )
        raw = struct.pack("<IBIB", 0xFFFFFFFE, 65, 1, 66)
        for fault in ("none", "read", "overrun", "foreign", "budget", "stop"):
            with self.subTest(fault=fault):
                calls = []
                chunks = iter((raw[:3], raw[3:]))
                empty = NativeCoreBuffer((1, 0), b"")

                def exchange(
                    request,
                    *,
                    deadline,
                    cancelled,
                    calls=calls,
                    fault=fault,
                    chunks=chunks,
                    empty=empty,
                ):
                    command, _payload = decode_vim_command(request)
                    calls.append(command)
                    if command == 0x197F:
                        if fault == "read":
                            raise OSError("read fault")
                        chunk = raw + raw if fault == "overrun" else next(chunks)
                        response = NativeMonitorReply(
                            0,
                            NativeDmciList(
                                (1, 0),
                                (
                                    (
                                        20 if fault == "foreign" else 19,
                                        NativeCoreBuffer((1, 0), chunk),
                                    ),
                                ),
                            ),
                            (empty, empty, empty, empty, empty),
                            0,
                        ).encode()
                    else:
                        if command == 0x1A7F and fault == "stop":
                            raise OSError("stop fault")
                        response = bytes(4)
                    return NativeVimReply(command | 0x80, 6, response).encode()

                client = NativeVimClient(
                    exchange,
                    capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                )
                if fault == "none":
                    packets = run_monitor_commands(
                        plan,
                        client,
                        interface_id=19,
                        frame_sizes=((0, 1),),
                        phase=0,
                        packet_limit=2,
                        limits=Limits(exchanges=1 if fault == "budget" else 5),
                    )
                    self.assertEqual(
                        [(p.timestamp_raw, p.payload) for p in packets],
                        [(0xFFFFFFFE, b"A"), (1, b"B")],
                    )
                    self.assertEqual(calls, [0x187F, 0x197F, 0x197F, 0x1A7F])
                else:
                    with self.assertRaises((MonitorError, OSError, ValueError)):
                        run_monitor_commands(
                            plan,
                            client,
                            interface_id=19,
                            frame_sizes=((0, 1),),
                            phase=0,
                            packet_limit=2,
                            limits=Limits(exchanges=1 if fault == "budget" else 5),
                        )
                    self.assertEqual(calls[-1], 0x1A7F)

    def test_native_command_alias_budget_precedes_materialization(self):
        from unittest.mock import patch

        from scripts.drive_recorder import NativeDmciCommand, NativeVimClient

        shared = tuple((value, value) for value in range(8))
        command = MonitorCommand(0x119, (1, 7, shared, 16, (), 2000))
        plan = MonitorSetup((command, command), (), ())

        def forbidden_exchange(request, *, deadline, cancelled):
            raise AssertionError("Preflight must reject before I/O")

        client = NativeVimClient(forbidden_exchange, capabilities=frozenset())
        with (
            patch("scripts.data_monitor.MAX_ITEMS", 40),
            patch.object(
                NativeDmciCommand,
                "from_neutral",
                side_effect=AssertionError("Materialized"),
            ) as build,
        ):
            with self.assertRaisesRegex(MonitorError, "aggregate field budget"):
                run_monitor_commands(
                    plan,
                    client,
                    interface_id=7,
                    frame_sizes=((0, 1),),
                    phase=0,
                    packet_limit=1,
                )
            self.assertEqual(build.call_count, 0)

    def test_native_dmci_cancel_deadline_and_preflight(self):
        from scripts.drive_recorder import (
            NativeVimClient,
            NativeVimReply,
            RecorderCancelled,
            decode_vim_command,
        )
        from scripts.toyota_session import Limits

        for fault in ("cancel", "deadline", "negative_count", "invalid_stop"):
            with self.subTest(fault=fault):
                state = {"tick": 0.0, "cancelled": False}
                calls = []

                def exchange(
                    request,
                    *,
                    deadline,
                    cancelled,
                    fault=fault,
                    state=state,
                    calls=calls,
                ):
                    wire, _payload = decode_vim_command(request)
                    calls.append(wire)
                    if wire == 0x187F:
                        state["cancelled"] = fault == "cancel"
                        if fault == "deadline":
                            state["tick"] = 2.0
                    return NativeVimReply(
                        wire | 0x80,
                        6,
                        bytes(8) if fault == "negative_count" else bytes(4),
                    ).encode()

                client = NativeVimClient(
                    exchange,
                    capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                    clock=lambda state=state: float(state["tick"]),
                )
                plan = MonitorSetup(
                    (MonitorCommand(0x114, (1, 2, 3)),)
                    if fault == "negative_count"
                    else (),
                    (MonitorCommand(0x10C, ()),),
                    (MonitorCommand(0x999 if fault == "invalid_stop" else 0x10E, ()),),
                )
                with self.assertRaises((RecorderCancelled, TimeoutError, ValueError)):
                    run_monitor_commands(
                        plan,
                        client,
                        interface_id=19,
                        frame_sizes=((0, 1),),
                        phase=0,
                        packet_limit=1,
                        limits=Limits(seconds=1),
                        cancelled=lambda state=state: bool(state["cancelled"]),
                        clock=lambda state=state: float(state["tick"]),
                    )
                if fault == "invalid_stop":
                    self.assertEqual(calls, [])
                else:
                    self.assertEqual(calls[-1], 0x1A7F)

    def test_native_p4_support_and_a1_packing(self):
        definitions = MonitorDefinitions(
            (1, 2),
            (
                MonitorRange(0, 15, 1, 0x10, 0, 0, 0),
                MonitorRange(0, 7, 2, 0x20, 1, 0, 0),
            ),
            (),
            "authored",
        )
        # ANY enabled bit marks both bytes in the first signal span.
        plan = pack_p4(
            definitions,
            {0x10: b"\x80\0\0", 0x20: b"\x01\0"},
            category_flags=6,
            capabilities=5,
            excluded=0,
            max_request=9,
            max_reply=20,
        )
        self.assertEqual(plan.mode_mask, 4)
        self.assertEqual(plan.setup_requests, (bytes.fromhex("a10610020102200101"),))
        self.assertEqual(plan.response_frames, ((0x606, 3),))
        self.assertEqual(plan.frames[0].selected_bytes, (0, 1))
        fallback = pack_p4(
            definitions,
            {0x10: b"\x80\0\0", 0x20: b"\x01\0"},
            category_flags=6,
            capabilities=0x25,
            excluded=4,
            max_request=9,
            max_reply=20,
        )
        self.assertEqual(fallback.mode_mask, 1)
        self.assertEqual(fallback.setup_requests, (bytes.fromhex("a1011020"),))
        polling = pack_p4(
            definitions,
            {0x10: b"\x80\0\0", 0x20: b"\x01\0"},
            category_flags=6,
            capabilities=0x20,
            excluded=0,
            max_request=9,
            max_reply=20,
        )
        self.assertEqual(
            polling.setup_requests, (bytes.fromhex("211020"), bytes.fromhex("610302"))
        )
        with self.assertRaises(MonitorError) as caught:
            pack_p4(
                definitions,
                {0x10: b"\0\0\0", 0x20: b"\x01\0"},
                category_flags=6,
                capabilities=5,
                excluded=0,
                max_request=9,
                max_reply=20,
            )
        self.assertEqual(caught.exception.code, 0xC005100C)
        optional = MonitorDefinitions(
            (1,), (MonitorRange(0, 7, 1, 1, 0, 0, 1),), (), "authored"
        )
        result = pack_p4(
            optional,
            {},
            category_flags=6,
            capabilities=4,
            excluded=0,
            max_request=9,
            max_reply=20,
        )
        self.assertEqual(result.ranges[0].runtime_flag, 1)
        self.assertEqual(result.setup_requests, ())

    def test_native_composite_layouts_and_pickup_bit_quirks(self):
        definitions = MonitorDefinitions(
            (30,),
            (
                MonitorRange(0, 2, 10, 5, 0, 0, 0),
                MonitorRange(8, 9, 20, 8, 0, 0, 0),
            ),
            (MonitorGroup(30, ((30, 1, 10), (30, 2, 20)), 3),),
            "authored",
        )
        packing = pack_p4(
            definitions,
            {5: b"\xff", 8: b"\0\xff"},
            category_flags=4,
            capabilities=4,
            excluded=0,
            max_request=10,
            max_reply=10,
        )
        base = p4_signal_layouts(packing)
        self.assertEqual(base, ((10, 6, 0, 2), (20, 6, 8, 9)))
        layouts, frames, pickup = p4_composite_layouts(
            definitions, packing, base, ((6, 2),)
        )
        self.assertEqual(layouts[-1], (30, 7, 0, 7))
        self.assertEqual(frames, ((6, 2), (7, 1)))
        self.assertEqual(pickup, ((0, 3), (8, 2), (-1, 3)))
        self.assertEqual(
            pickup_packet(bytes.fromhex("e080"), 0, pickup, p4=True),
            bytes.fromhex("e080f0"),
        )
        # Native P4 adds32 BEFORE its -1 sentinel comparison, so padding reads
        # timestamp byte3. P5 explicitly zero-fills the original -1 marker.
        self.assertEqual(
            pickup_packet(bytes.fromhex("e080"), 0xFFFFFFFF, pickup, p4=True),
            bytes.fromhex("e080f7"),
        )
        self.assertEqual(
            pickup_packet(bytes.fromhex("e080"), 0xFFFFFFFF, pickup, p4=False),
            bytes.fromhex("e080f0"),
        )
        self.assertEqual(
            pickup_packet(bytes.fromhex("abcd"), 0, ((0, 16),), p4=True),
            bytes.fromhex("abcdabab"),
        )
        self.assertEqual(
            pickup_packet(bytes.fromhex("abcd"), 0, ((0, 16),), p4=False),
            bytes.fromhex("abcdabcd"),
        )
        self.assertEqual(pickup_packet(b"A", 0, ((0xFFFFFFFF, 8),), p4=False), b"A\0")
        self.assertEqual(
            pickup_packet(b"A", 0, ((0xFFFFFFDF, 8),), p4=True, previous=b"Z"), b"AZ"
        )
        self.assertEqual(
            pickup_packet(
                b"AB", 0, ((17, 16), (0, 8)), p4=True, previous=bytes.fromhex("800000")
            ),
            bytes.fromhex("4142010041"),
        )
        event = MonitorEvent.p4(1, (12,), (2,))
        event.pickup_spans = ((0, 16),)
        self.assertEqual(
            event.accept(bytes.fromhex("610cabcd"), 5), (5, bytes.fromhex("abcdabab"))
        )
        with self.assertRaisesRegex(MonitorError, "aligned"):
            pickup_packet(b"A", 0, ((0, 7),), p4=True)

    def test_selected_native_connection_fields_and_override(self):
        protocol = bytearray(28)
        struct.pack_into("<H", protocol, 2, 7)
        struct.pack_into("<7H", protocol, 6, 0x720, 0x700, 0x55, 0, 64, 96, 0)
        can = bytearray(28)
        can[:2] = bytes((3, 4))
        struct.pack_into("<H", can, 12, 5)
        queries = []
        profile = cast(
            VehicleProfile,
            SimpleNamespace(
                category=1,
                protocol_info=lambda bus: bytes(protocol),
                comm_info_can_records=lambda key: queries.append(key) or (bytes(can),),
            ),
        )
        result = selected_p4_connection(
            profile, bus_id=0x12, diagnostic_mode=bytes(16), controller_category_flags=6
        )
        self.assertEqual(queries, [7])
        self.assertEqual(
            (result.address.request_id, result.address.response_id), (0x700, 0x708)
        )
        self.assertEqual(
            (
                result.maximum_request,
                result.maximum_reply,
                result.parameter_word,
                result.can_word,
                result.can_parameter,
                result.can_byte_0,
                result.can_byte_1,
            ),
            (64, 96, 100, 0x55, 5, 3, 4),
        )
        diagnostic = bytearray(16)
        struct.pack_into("<I", diagnostic, 8, 0x12345678)
        changed = selected_p4_connection(
            profile,
            bus_id=0x12,
            diagnostic_mode=bytes(diagnostic),
            controller_category_flags=6,
        )
        self.assertEqual(changed.address.request_id, 0x12345678)
        with self.assertRaises(MonitorError):
            selected_p4_connection(
                profile,
                bus_id=0,
                diagnostic_mode=bytes(16),
                controller_category_flags=6,
            )

    def test_native_p4_address_branches(self):
        vectors = (
            (0x11, (0x8010F0, 0xFFFFFFFF, 0xC020F0)),
            (0x51, (0x8010F0, 0xFFFFFFFF, 0xC020F0)),
            (0x21, (0x686AF0, 0x486B10, 0xFFFFFFFF)),
            (0x31, (0xC020F0, 0x80F010, 0xFFFFFFFF)),
            (0x12, (0x10, 0x18, 0xFFFFFFFF)),
            (0x22, (0x80001055, 0x80001855, 0xFFFFFFFF)),
            (0x32, (0x20, 0x18, 0xFFFFFFFF)),
            (5, (0x10, 0xFFFFFFFF, 0xFFFFFFFF)),
            (12, (0x10, 0xFFFFFFFF, 0xFFFFFFFF)),
            (6, (0x616AF0, 0x416B10, 0xFFFFFFFF)),
            (7, (0x686AF0, 0x486B10, 0xFFFFFFFF)),
            (0x18, (0xD8DA10F0, 0xD8DAF010, 0xFFFFFFFF)),
            (0x38, (0xD8DB20F0, 0xD8DAF010, 0xFFFFFFFF)),
        )
        for bus, expected in vectors:
            with self.subTest(bus=bus):
                address = p4_monitor_address(
                    bus_id=bus,
                    category_flags=6,
                    default_request=0x20,
                    target=0x10,
                    can_word=0x55,
                )
                self.assertEqual(
                    (address.request_id, address.response_id, address.functional_id),
                    expected,
                )
        self.assertEqual(
            p4_monitor_address(
                bus_id=0x11,
                category_flags=0x86,
                default_request=0,
                target=0x10,
                can_word=0,
            ).request_id,
            0x8010F1,
        )
        with self.assertRaises(MonitorError):
            p4_monitor_address(
                bus_id=3, category_flags=6, default_request=0, target=0, can_word=0
            )

    def test_selected_dynamic_runs_and_versioned_slots(self):
        from scripts.monitor_support import MonitorSupportCache
        from scripts.profiles import SelectedFrame
        from scripts.toyota import CommandFrame

        definitions = P5Definitions(
            (1, 2, 3, 4, 5),
            (
                P5Range(0, 7, 1, 0x100, 0, 0, 0),
                P5Range(16, 23, 2, 0x100, 0, 0, 0),
                P5Range(8, 31, 3, 0x200, 0, 0, 0),
                P5Range(0, 2047, 4, 0x300, 0, 0, 0),
                P5Range(0, 7, 5, 0x400, 1, 0, 0),
            ),
            (),
            "authored",
        )
        selection = p5_dynamic_sources(definitions, (0x100, 0x200, 0x300))
        self.assertEqual(
            [(s.did, s.runs) for s in selection.sources],
            [(0x200, ((2, 3),)), (0x400, ((1, 1),)), (0x100, ((1, 1), (3, 1)))],
        )
        self.assertEqual(selection.ineligible_dids, (0x300,))
        category = bytearray(76)
        category[72] = 0x34
        table = tuple(
            struct.pack("<HHHBB", did, capacity, 0, 0, 0)
            for did, capacity in ((0xF300, 7), (0xF301, 8), (0xF300, 99))
        )
        profile = cast(
            VehicleProfile,
            Mock(
                spec=VehicleProfile,
                category=1,
                category_record=bytes(category),
                exception_ids=(),
                database=SimpleNamespace(sha256="authored"),
                ecu_database_sha256="authored",
                catalog=SimpleNamespace(management=SimpleNamespace(sha256="authored")),
                records=lambda slot: table,
                frame_records=lambda function: (
                    SelectedFrame(
                        CommandFrame(b"\x22" + function.to_bytes(2, "big")),
                        bytes(16),
                        bytes(8),
                        bytes(16),
                        "authored",
                    ),
                ),
                validate_frame=lambda selected: self.assertIn(
                    selected,
                    tuple(
                        SelectedFrame(
                            CommandFrame(b"\x22" + function.to_bytes(2, "big")),
                            bytes(16),
                            bytes(8),
                            bytes(16),
                            "authored",
                        )
                        for function in (0x114, 0x115)
                    ),
                ),
            ),
        )
        for count, expected_status in ((2, 0), (0, 0xA0050422)):
            requests = []

            def exchange(query, requests=requests, count=count):
                requests.append(query.request)
                value = count if query.request[-1] == 0x14 else 3
                return b"\x62" + query.request[1:3] + value.to_bytes(2, "big")

            cache = MonitorSupportCache(profile, exchange, "e")
            if expected_status:
                with self.assertRaises(MonitorError) as error:
                    selected_dynamic_slots(cache, source_build=18)
                self.assertEqual(error.exception.code, expected_status)
                self.assertEqual(requests, [b"\x22\x01\x14"])
            else:
                self.assertEqual(
                    selected_dynamic_slots(cache, source_build=18),
                    (DynamicSlot(0xF300, 3), DynamicSlot(0xF301, 3)),
                )
                self.assertEqual(requests, [b"\x22\x01\x14", b"\x22\x01\x15"])
            requests.clear()
            with self.assertRaisesRegex(MonitorError, "source build"):
                selected_dynamic_slots(cache, source_build=12, enabled_dynamic_dids=())
            cache = MonitorSupportCache(profile, exchange, "e", source_build=12)
            old = selected_dynamic_slots(
                cache, source_build=12, enabled_dynamic_dids=(0xF301, 0xF300)
            )
            self.assertEqual(old, (DynamicSlot(0xF301, 8), DynamicSlot(0xF300, 7)))
            self.assertEqual(requests, [])

    def test_native_p5_polling_selection(self):
        ranges = (
            P5Range(8, 23, 1, 0xF190, 0, 0, 0),
            P5Range(0, 7, 2, 0xF190, 0, 0, 0),
            P5Range(0, 15, 3, 0x100, 1, 0, 0),
            P5Range(0, 7, 4, 0x200, 0, 0, 1),
        )
        definitions = P5Definitions((1, 2, 3, 4), ranges, (), "authored")
        packing = pack_p5_polling(
            definitions, (0xF190,), {26: False, 73: True}, excluded=0
        )
        self.assertEqual(packing.data_ids, ((0xF190, 3), (0x100, 2)))
        self.assertEqual(packing.frame_sizes, ((0, 3), (1, 2)))
        self.assertEqual(packing.layouts, ((1, 0, 8, 23), (2, 0, 0, 7), (3, 1, 0, 15)))
        self.assertEqual(packing.ranges[-1].runtime_flag, 1)
        event = MonitorEvent.p5(
            tuple(did for did, _ in packing.data_ids),
            tuple(size for _, size in packing.data_ids),
        )
        self.assertIsNone(event.accept(bytes.fromhex("62f190aabbcc"), 100))
        self.assertEqual(
            event.accept(bytes.fromhex("6201001234"), 101),
            (101, bytes.fromhex("aabbcc1234")),
        )
        with self.assertRaises(MonitorError):
            pack_p5_polling(definitions, (), {26: True, 73: False}, excluded=0)
        with self.assertRaises(MonitorError):
            pack_p5_polling(definitions, (), {26: False, 73: True}, excluded=0)
        with self.assertRaises(MonitorError):
            pack_p5_polling(definitions, (), {}, excluded=0)

    def test_native_p5_db23e_descriptors_and_metadata(self):
        row = bytearray(64)
        struct.pack_into(
            "<IIIIIII", row, 4, 11, 22, 0x11223344, 0x55667788, 0, 71, 0x99AABBCC
        )
        struct.pack_into("<I", row, 32, 0x80000008)
        struct.pack_into("<H", row, 36, 0x1234)
        struct.pack_into("<HHHH", row, 42, 2, 3, 10, 0)
        struct.pack_into("<H", row, 54, 0xF190)
        row[58:60] = bytes((21, 1))
        phy = bytearray(24)
        struct.pack_into("<IIIH", phy, 0, 3, 4, 5, 2)
        phy[20:22] = bytes((3, 2))
        category = bytearray(76)
        category[72] = 0x34
        profile = cast(
            VehicleProfile,
            SimpleNamespace(
                category=1,
                category_record=bytes(category),
                database=SimpleNamespace(sha256="authored"),
                ecu_database_sha256="authored",
                records=lambda slot: {
                    62: (bytes(row),),
                    13: (bytes(phy),),
                    14: (),
                    15: (),
                }[slot],
                signal_did_lsb_records=lambda pid: (bytes(20),),
                catalog=SimpleNamespace(
                    management=SimpleNamespace(version=0x0100032F),
                    language=SimpleNamespace(resolve=lambda key: str(key)),
                ),
            ),
        )
        definition = selected_p5_definitions(profile, (0x1234,))
        item = definition.ranges[0]
        self.assertEqual(
            (item.frame_id, item.flags, item.start_bit, item.end_bit),
            (0xF190, 0x80000008, 3, 10),
        )
        result = selected_p5_signal_metadata(
            profile,
            ((0x1234, 2, 3, 10),),
            source_build=18,
            active_alias_pid=0x1234,
            lsb_observations={0x1234: (7, 8, 0xDEADBEEF)},
        )[0]
        self.assertEqual(
            (result.pid, result.name, result.short_name, result.selector),
            (0x2134, "71", b"", 21),
        )
        self.assertEqual(
            (
                result.multiplier,
                result.divisor,
                result.sign_mode,
                result.precision,
                result.minimum_raw,
                result.maximum_raw,
            ),
            (7, 8, 3, 2, 11, 22),
        )
        self.assertEqual(result.extended, (0x99AABBCC, 0x11223344, 0x55667788))
        struct.pack_into("<I", row, 32, 0x80000000)
        plan = selected_p5_polling_monitor(
            profile,
            (0x1234,),
            (0xF190,),
            {26: False, 73: True},
            interface_id=7,
            excluded=0,
            standard_values=(),
            parameter_6=2000,
            source_build=18,
            active_alias_pid=0,
            lsb_observations={0x1234: (7, 8, 9)},
        )
        self.assertEqual(plan.commands.setup[0].command_id, 0x119)
        self.assertEqual(
            plan.commands.setup[0].values, (1, 7, ((0xF190, 2),), 2, (), 2000)
        )
        self.assertEqual(plan.signals[0].pid, 0x1234)

        protocol = bytearray(28)
        struct.pack_into("<H", protocol, 2, 99)
        struct.pack_into("<HH", protocol, 6, 8, 7)
        struct.pack_into("<HH", protocol, 14, 32, 64)
        struct.pack_into("<H", protocol, 20, 9)
        can = bytearray(28)
        can[:2] = bytes((3, 4))
        struct.pack_into("<I", can, 4, 500000)
        struct.pack_into("<H", can, 12, 17)
        selected_buses = []
        connection_profile = cast(
            VehicleProfile,
            SimpleNamespace(
                category=1,
                protocol_info=lambda bus: selected_buses.append(bus) or bytes(protocol),
                comm_info_can_records=lambda key: (bytes(can),) if key == 99 else (),
            ),
        )
        connection = selected_p5_can_connection(
            connection_profile,
            bus_id=0x62,
            diagnostic_mode=bytes(16),
            controller_category_flags=0x14,
            source_build=18,
        )
        from dataclasses import replace

        authored_identity = ("authored-source-context",)
        plan = replace(
            plan,
            definitions=replace(plan.definitions, source_identity=authored_identity),
        )
        connection = replace(
            connection,
            connection=replace(
                connection.connection, source_identity=authored_identity
            ),
        )
        self.assertEqual(selected_buses, [0x62])
        self.assertEqual(
            (connection.entry_parameter, connection.connection.parameter_word),
            (7, 180000),
        )
        complete = p5_can_lifecycle(
            plan, connection, connected_device=4, routine_info=2, recording=False
        )
        self.assertEqual(
            tuple(c.command_id for c in complete.setup),
            (0x118, 0x107, 0x11E, 0x111, 0x111, 0x114, 0x114, 0x119),
        )
        self.assertEqual(
            complete.setup[0].values,
            (1, 0x36, 0xE0000000, 0x1FFFFFFF, 0xC6, 0x40030, 1, 2, 10),
        )
        self.assertEqual(complete.setup[1].values, (3,))
        self.assertEqual(complete.setup[2].values, (1,))
        self.assertEqual(complete.setup[4].values, (8, 9, 17, 3, 4))
        self.assertEqual(complete.setup[6].values, (8, 9, 180000))
        recorded = p5_can_lifecycle(
            plan, connection, connected_device=4, routine_info=None, recording=True
        )
        self.assertEqual(
            tuple(c.command_id for c in recorded.setup),
            (0x118, 0x107, 0x11E, 0x111, 0x114, 0x119),
        )
        self.assertEqual(recorded.setup[2].values, (0,))
        self.assertEqual(
            p5_can_lifecycle(
                plan, connection, connected_device=8, routine_info=None, recording=True
            ),
            recorded,
        )
        with self.assertRaisesRegex(MonitorError, "recording writer"):
            p5_can_lifecycle(
                plan, connection, connected_device=8, routine_info=None, recording=False
            )

        old = p5_can_lifecycle(
            replace(plan, source_build=12),
            replace(connection, source_build=12),
            connected_device=4,
            routine_info=2,
            recording=False,
        )
        self.assertEqual(old, complete)
        from scripts.drive_recorder import NativeDmciCommand

        for command in complete.setup + complete.start + complete.stop:
            NativeDmciCommand.from_neutral(command.command_id, command.values).encode()

        with self.assertRaisesRegex(MonitorError, "LSB"):
            selected_p5_signal_metadata(
                profile, ((0x1234, 2, 3, 10),), source_build=18, active_alias_pid=0
            )
        old = selected_p5_signal_metadata(
            profile, ((0x1234, 2, 3, 10),), source_build=12, active_alias_pid=0
        )[0]
        self.assertEqual((old.multiplier, old.divisor), (3, 4))

        with self.assertRaises(MonitorError):
            selected_p5_definitions(profile, (1,))

    def test_shared_native_voltage_calibration_state(self):
        from scripts.monitor_dlc12 import DLC12VoltageObservation, DLC12VoltageState

        freeze = bytearray(84)
        struct.pack_into("<H", freeze, 56, 1)
        struct.pack_into("<H", freeze, 60, 2)
        phy = bytearray(24)
        struct.pack_into("<IIIH", phy, 0, 2, 4, 100, 2)
        profile = cast(
            VehicleProfile,
            SimpleNamespace(
                category=0x68,
                category_record=bytes(76),
                records=lambda slot: {
                    10: (bytes(freeze),),
                    13: (bytes(phy),),
                    14: (),
                    15: (),
                }[slot],
                catalog=SimpleNamespace(
                    language=SimpleNamespace(resolve=lambda key: "")
                ),
            ),
        )
        successful = DLC12VoltageObservation(
            0,
            True,
            tuple((True, value.to_bytes(2, "little")) for value in (8, 12, 16, 20)),
        )
        for mode, cached, observation, expected, error in (
            (0, None, None, 100, None),
            (1, None, successful, 93, None),
            (1, None, DLC12VoltageObservation(1, False, ()), 100, 0x90051203),
            (
                1,
                None,
                DLC12VoltageObservation(1, True, ((False, b""),)),
                100,
                0x90051204,
            ),
            (2, 777, None, 777, None),
            (2, None, None, 100, None),
        ):
            with self.subTest(mode=mode, error=error):
                state = DLC12VoltageState(mode, cached)
                signal = selected_signal_metadata(
                    profile,
                    ((1, 0, 0, 7),),
                    voltage_state=state,
                    voltage_observations=None
                    if observation is None
                    else {1: observation},
                )[0]
                self.assertEqual(signal.offset, expected)
                self.assertEqual(state.errors, () if error is None else ((1, error),))
                if mode == 1:
                    self.assertEqual(state.cached_offset, expected)
        with self.assertRaises(MonitorError):
            selected_signal_metadata(
                profile, ((1, 0, 0, 7),), voltage_state=DLC12VoltageState(1)
            )

    def test_native_12_18_pattern_metadata_offsets(self):
        freeze = bytearray(84)
        struct.pack_into("<H", freeze, 56, 1)
        struct.pack_into("<H", freeze, 60, 2)
        struct.pack_into("<H", freeze, 70, 77)
        phy = bytearray(24)
        struct.pack_into("<IIIHH", phy, 0, 1, 1, 0, 2, 3)
        unit = bytearray(12)
        struct.pack_into("<IHH", unit, 0, 8, 3, 9)
        for size in (20, 24):
            with self.subTest(native_record_size=size):
                pattern = bytearray(size)
                struct.pack_into("<I", pattern, 0, 123)
                if size == 20:
                    struct.pack_into("<H", pattern, 4, 77)
                    struct.pack_into("<H", pattern, 10, 65535)
                else:
                    struct.pack_into("<I", pattern, 4, 0x12345678)
                    struct.pack_into("<H", pattern, 12, 77)
                profile = cast(
                    VehicleProfile,
                    SimpleNamespace(
                        category=999,
                        category_record=bytes(76),
                        records=lambda slot, pattern=pattern: {
                            10: (bytes(freeze),),
                            13: (bytes(phy),),
                            14: (bytes(pattern),),
                            15: (bytes(unit),),
                        }[slot],
                        catalog=SimpleNamespace(language=SimpleNamespace(resolve=str)),
                    ),
                )
                item = selected_signal_metadata(profile, ((1, 0, 0, 7),))[0]
                self.assertEqual(
                    item.patterns,
                    ((77, "123", 65535 if size == 20 else 0x12345678, 0),),
                )
                self.assertEqual((item.unit, item.unit_id), ("8", 9))

    def test_native_signal_lsb_overwrite_and_extended_wire_order(self):
        freeze = bytearray(84)
        struct.pack_into("<III", freeze, 24, 11, 22, 0x11223344)
        struct.pack_into("<I", freeze, 36, 0x55667788)
        struct.pack_into("<I", freeze, 52, 0x99AABBCC)
        struct.pack_into("<HH", freeze, 56, 1, 0)
        struct.pack_into("<H", freeze, 60, 2)
        phy = bytearray(24)
        struct.pack_into("<IIIH", phy, 0, 3, 4, 5, 2)
        category = bytearray(76)
        category[72] = 4
        profile = cast(
            VehicleProfile,
            SimpleNamespace(
                category=1,
                category_record=bytes(category),
                records=lambda slot: {
                    10: (bytes(freeze),),
                    13: (bytes(phy),),
                    14: (),
                    15: (),
                }[slot],
                signal_lsb_records=lambda key: (bytes(20),),
                catalog=SimpleNamespace(
                    language=SimpleNamespace(resolve=lambda key: "")
                ),
            ),
        )
        signal = selected_signal_metadata(
            profile, ((1, 0, 0, 7),), lsb_observations={1: (7, 8, 0xDEADBEEF)}
        )[0]
        self.assertEqual((signal.multiplier, signal.divisor), (7, 8))
        self.assertEqual(signal.extended, (0x99AABBCC, 0x11223344, 0x55667788))
        with self.assertRaisesRegex(MonitorError, "LSB"):
            selected_signal_metadata(profile, ((1, 0, 0, 7),))

    def test_packet_cache_a3_wire_fault_updates_same_session_next_check(self):
        from scripts.frame_transport import J2534Result, NativeMessage
        from scripts.monitor_legacy import check_legacy_monitor
        from tests.test_monitor_legacy import SelectedSupportIntegration

        fixture = SelectedSupportIntegration()
        for build in (12, 18):
            backend = fixture.run_backend()
            invoke = backend.invoke
            reads = [0]

            def exchange(
                operation,
                fields,
                *,
                deadline,
                cancelled,
                backend=backend,
                invoke=invoke,
                reads=reads,
            ):
                result = invoke(
                    operation, fields, deadline=deadline, cancelled=cancelled
                )
                if operation == "write_messages":
                    reads[0] = 0
                    if backend.request == b"\xa3":
                        return J2534Result(code=7)
                if operation != "read_messages":
                    return result
                reads[0] += 1
                if backend.request == b"\xa3":
                    return J2534Result(code=9)
                if backend.request == b"\xa2\x04":
                    payload = (
                        b"\xe2\x11\xaa\xbb" if reads[0] == 1 else b"\xe2\x11\xcc\xdd"
                    )
                    return J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(
                                4,
                                0,
                                0,
                                1234,
                                0,
                                bytes(
                                    (0x80 + len(payload), 0xF0, backend.response_source)
                                )
                                + payload,
                            ),
                        ),
                    )
                return result

            backend.invoke = exchange
            communication = fixture.run_communication(3, build, backend)
            assert isinstance(communication.profile, VehicleProfile)
            session = SelectedMonitorSession(
                communication.profile, source_build=build, shared_interface=0
            )
            target = selected_legacy_check_target(
                communication, (17,), fixture.observed(10, 11), monitor_session=session
            )
            try:
                first = check_legacy_monitor(
                    (target,),
                    family="P3",
                    command_kind=0x42,
                    allocation=65536,
                    connected_device=8,
                    command_ecu=42,
                    monitor_session=session,
                    clock=lambda: 0,
                )
                self.assertEqual((first.excluded, first.measurements[0].mode), (0, 2))
                self.assertEqual(session.disabled_packet_ecus, (42,))
                assert target.packet_cache is not None
                self.assertEqual(target.packet_cache.disabled, [42])
                next_check = check_legacy_monitor(
                    (target,),
                    family="P3",
                    command_kind=0x42,
                    allocation=65536,
                    connected_device=8,
                    command_ecu=42,
                    monitor_session=session,
                    clock=lambda: 0,
                )
                self.assertEqual(
                    (next_check.excluded, next_check.measurements[0].mode), (3, 0x10)
                )
                self.assertEqual(session.disabled_packet_ecus, (42,))
            finally:
                communication.disconnect()

    def test_packet_wire_fault_changes_shared_next_check_policy(self):
        from scripts.frame_transport import J2534Result, NativeMessage
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
            check_legacy_monitor,
        )
        from tests.test_monitor_legacy import SelectedSupportIntegration

        fixture = SelectedSupportIntegration()
        for build in (12, 18):
            backend = fixture.run_backend()
            invoke = backend.invoke
            reads = [0]

            def exchange(
                operation,
                fields,
                *,
                deadline,
                cancelled,
                backend=backend,
                invoke=invoke,
                reads=reads,
            ):
                result = invoke(
                    operation, fields, deadline=deadline, cancelled=cancelled
                )
                if operation == "write_messages":
                    reads[0] = 0
                if operation != "read_messages" or backend.request[0] not in (
                    0xA1,
                    0xA2,
                    0xA3,
                ):
                    return result
                reads[0] += 1
                if backend.request[0] == 0xA2:
                    return J2534Result(code=7)
                if backend.request[0] == 0xA3 and reads[0] > 1:
                    return J2534Result(code=9)
                payload = (
                    b"\xe1" + backend.request[1:]
                    if backend.request[0] == 0xA1
                    else b"\xe3"
                )
                return J2534Result(
                    count=1,
                    messages=(
                        NativeMessage(
                            4,
                            0,
                            0,
                            1234,
                            0,
                            bytes((0x80 + len(payload), 0xF0, backend.response_source))
                            + payload,
                        ),
                    ),
                )

            backend.invoke = exchange
            communication = fixture.run_communication(3, build, backend)
            assert isinstance(communication.profile, VehicleProfile)
            session = SelectedMonitorSession(
                communication.profile, source_build=build, shared_interface=0
            )
            observed = fixture.observed(8, 11)
            target = selected_legacy_check_target(communication, (17,), observed)

            def check(target=target, session=session):
                return check_legacy_monitor(
                    (target,),
                    family="P3",
                    command_kind=0x42,
                    allocation=65536,
                    connected_device=8,
                    command_ecu=42,
                    monitor_session=session,
                    clock=lambda: 0,
                )

            before = check()
            self.assertEqual((before.excluded, before.measurements[0].mode), (0, 1))
            controller = LegacyMonitorController(
                family="P3",
                connected_device=8,
                monitor_session=session,
                clock=lambda: 0,
            )
            controller.queue = LegacyCommandQueue()
            controller.queue.put(
                LegacyControlMessage(
                    56, (LegacyRunTarget(communication, (17,), observed),)
                )
            )
            try:
                result = controller.run_one()
                assert result is not None
                self.assertEqual(result.status, 0)
                assert controller._worker is not None
                worker = controller._worker
                self.assertEqual(worker.native_worker_class, "packet")
                for _ in range(12):
                    code = worker.step()
                    if code != 0xE0000100:
                        break
                self.assertEqual(code, 0xE0000104)
                self.assertTrue(
                    any(name == "read_messages" for name, _ in backend.calls)
                )
                self.assertEqual(session.disabled_packet_ecus, (42,))
            finally:
                controller.close()
            try:
                after = check()
                self.assertEqual(
                    (after.excluded, after.measurements[0].mode), (3, 0x10)
                )
            finally:
                communication.disconnect()

    def test_selected_management_only_session_and_connection_identity(self):
        from scripts.data_monitor import selected_p4_connection
        from scripts.monitor_support import monitor_source_identity
        from scripts.profiles import ProtocolProfile
        from tests.test_monitor_legacy import SelectedSupportIntegration

        for build in (12, 18):
            profile = SelectedSupportIntegration().native_profile(3, source_build=build)
            primary = ProtocolProfile(
                profile.catalog,
                profile.category_record,
                profile.exception_ids,
                profile.vehicle_name_key,
            )
            session = SelectedMonitorSession(primary, source_build=build)
            session.check(profile, source_build=build)
            session.disable_packet_ecu(42)
            self.assertEqual(session.disabled_packet_ecus, (42,))
            connection = selected_p4_connection(
                primary,
                bus_id=0x11,
                diagnostic_mode=bytes(16),
                controller_category_flags=3,
            )
            self.assertEqual(
                connection.source_identity, monitor_source_identity(primary, "")
            )
            self.assertIsNone(connection.source_identity[1])
            self.assertFalse(hasattr(primary, "database"))

    def test_selected_session_add_is_native_unique_and_context_bound(self):
        from dataclasses import replace
        from unittest.mock import patch

        from tests.test_monitor_packet_a8 import profile

        source = profile()
        session = SelectedMonitorSession(
            source, source_build=18, disabled_packet_ecus=(7, 7)
        )
        session.disable_packet_ecu(42)
        session.disable_packet_ecu(42)
        self.assertEqual(session.disabled_packet_ecus, (7, 7, 42))
        with patch("scripts.data_monitor.MAX_ITEMS", 3):
            session.disable_packet_ecu(42)
            with self.assertRaisesRegex(MonitorError, "item budget"):
                session.disable_packet_ecu(43)
        with self.assertRaisesRegex(MonitorError, "changed"):
            session.check(replace(source, vehicle_name_key=123), source_build=18)
        with self.assertRaisesRegex(MonitorError, "changed"):
            session.check(source, source_build=12)
        source.catalog.management = replace(
            source.catalog.management, sha256="different"
        )
        with self.assertRaisesRegex(MonitorError, "changed"):
            session.disable_packet_ecu(44)

    def test_normal_worker_factory_routes_a8_packet_and_pair(self):
        from scripts.frame_transport import DriverProperties, J2534Result, NativeMessage
        from scripts.frame_transport_variants import create_lower_transport
        from scripts.monitor_j2534 import DirectJ2534Worker
        from scripts.monitor_poll import NormalPollingWorker
        from tests.test_monitor_packet_a8 import profile, selected

        class Backend:
            def __init__(self):
                self.request = b""
                self.reads = 0
                self.calls = []

            def invoke(self, operation, fields, *, deadline, cancelled):
                self.calls.append(operation)
                if operation == "connect":
                    return J2534Result(handle=7)
                if operation == "start_message_filter":
                    return J2534Result(handle=100 + len(self.calls))
                if operation == "write_messages":
                    self.request = fields["messages"][0].data[4:]
                    self.reads = 0
                    return J2534Result(count=1)
                if operation == "read_messages":
                    self.reads += 1
                    if self.request == b"\xa3" and self.reads > 1:
                        return J2534Result(code=9)
                    payload = (
                        b"\xe1" + self.request[1:]
                        if self.request[0] == 0xA1
                        else b"\xe2\x01AB"
                        if self.request[0] == 0xA2
                        else b"\x61\x0cAB"
                        if self.request[0] == 0x21
                        else b"\xe3"
                        if self.request[0] == 0xA3
                        else bytes((self.request[0] | 0x40,)) + self.request[1:]
                    )
                    return J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(
                                6, 0, 0, 1234000, 0, b"\x00\x00\x07\xe8" + payload
                            ),
                        ),
                    )
                return J2534Result()

        for build in (12, 18):
            for functions in ((8,), (12,)):
                source = profile(build)
                plan = selected(source, build=build, functions=functions)
                connection = selected_p4_connection(
                    source,
                    bus_id=0x12,
                    diagnostic_mode=bytes(16),
                    controller_category_flags=9,
                )
                backend = Backend()
                operations = create_lower_transport(
                    source,
                    plan.packing.setup_requests[0],
                    backend,
                    native_build=cast(Literal[12, 18], build),
                    bus_id=0x12,
                    driver=DriverProperties(0, b"04.04", "authored"),
                    device_kind=8,
                    clock=lambda: 0,
                )
                session = SelectedMonitorSession(source, source_build=build)
                worker = selected_normal_monitor_worker(
                    operations,
                    plan,
                    connection,
                    clock=lambda: 0,
                    ticks=lambda: 1234,
                    monitor_session=session,
                )
                if isinstance(worker, DirectJ2534Worker):
                    self.assertEqual(
                        worker.disable_packet_ecu, session.disable_packet_ecu
                    )
                self.assertIsInstance(
                    worker,
                    DirectJ2534Worker if functions == (8,) else NormalPollingWorker,
                )
                capture = worker.run(1)
                self.assertEqual(capture.packets[0].payload, b"AB")
                self.assertIsNone(operations.channel)
                self.assertEqual(session.disabled_packet_ecus, ())
                self.assertEqual(backend.calls.count("disconnect"), 1)
                settings = selected_monitor_buffer(
                    plan,
                    phase=0,
                    allocation_size=4096,
                    name=b"a8",
                    text_encoding="utf-8",
                )
                self.assertTrue(settings.signal_table)

    def test_variable_join_rejects_unbound_targets_before_io(self):
        from scripts.frame_transport import NativeFrameOperations

        with self.assertRaisesRegex(MonitorError, "concrete selected targets"):
            selected_variable_monitor_runtime(
                (),
                cast("NativeFrameOperations", object()),
                command_kind=7,
                command_ecu=1,
                allocation=4096,
                standard_values=(),
                names=(),
                text_encoding="utf-8",
                phase=0,
            )

    def test_selected_p5_export_preserves_native_constructor_slots(self):
        from scripts.drive_recorder import (
            NativeMonitorPacket,
            NativeRecorderCapture,
            decode_command,
        )
        from scripts.monitor_support import MonitorSupportCache
        from scripts.snapshot import (
            MonitorBuffer,
            decode_monitor_buffer,
            decode_signal_item,
            decode_signal_table,
            encode_monitor_buffer,
            monitor_packets,
        )
        from tests.test_monitor_p5 import authored_exchange, authored_profile, producer

        for build in (12, 18):
            cache = MonitorSupportCache(
                authored_profile(build),
                authored_exchange([]),
                "ecu",
                source_build=build,
            )
            plan = producer(cache, routines=(0x9C42,))
            self.assertEqual([item.pid for item in plan.signals], [1, 4, 3, 0x2134, 0])
            self.assertEqual(plan.default_signal_slots, (4,))
            settings = selected_monitor_buffer(
                plan,
                phase=0,
                allocation_size=4096,
                name=b"selected",
                text_encoding="utf-8",
            )
            signals = decode_command(settings.signal_table)["signals"]
            assert isinstance(signals, tuple)
            self.assertEqual(
                tuple(item.data for item in signals[4].strings), (b"",) * 3
            )
            self.assertTrue(all(item.strings[1].data == b"" for item in signals))
            self.assertEqual(
                signals[3].strings[0].data, plan.signals[3].name.encode() + b"\0"
            )
            payload = bytes(sum(size for _, size in plan.frame_sizes))
            capture = NativeRecorderCapture(1234, (NativeMonitorPacket(1234, payload),))
            metadata = MonitorBuffer(
                b"selected",
                bytes(16),
                b"",
                b"",
                b"",
                b"",
                0,
                (),
                plan.definitions.selected_ids,
                b"",
                (),
            )
            saved = capture.monitor_buffer(settings, metadata, phase=0, block_packets=1)
            saved = decode_monitor_buffer(encode_monitor_buffer(saved))
            restored = [
                decode_signal_item(bytes.fromhex(value))
                for value in decode_signal_table(saved.signal_table)["items_hex"]
            ]
            self.assertEqual(
                (restored[4].name, restored[4].short_name, restored[4].unit),
                (b"", b"", b""),
            )
            self.assertEqual(restored[3].pid, 0x2134)
            self.assertTrue(all(item.short_name == b"" for item in restored))
            self.assertEqual(len(monitor_packets(saved)), 1)

    def test_legacy_check_target_binds_retained_native_channel(self):
        from typing import Literal

        from scripts.frame_transport import J2534Result, NativeMessage
        from scripts.monitor_j2534 import NativePacketPrimitives
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )
        from tests.test_monitor_j2534 import authored_operations

        for build in (12, 18):
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
                "selected",
                bus_id=operations.bus_id,
                source_build=build,
                clock=lambda: 10,
            )
            target = selected_legacy_check_target(communication, (17,), {})
            self.assertIs(target.transaction, communication)
            self.assertIs(target.support_stream, communication)
            self.assertEqual(
                (target.packet_ecu, target.packet_protocol, target.source_build),
                (42, 0x12, build),
            )
            assert target.packet_cache is not None
            primitive = target.packet_cache.primitive
            assert isinstance(primitive, NativePacketPrimitives)
            self.assertIs(primitive.communication, communication)
            frames = target.packet_cache.get_packet_frame(
                target.packet_ecu,
                target.packet_protocol,
                source_identity=communication.cache.identity,
            )
            self.assertEqual(
                [(frame.sequence, frame.payload) for frame in frames], [(0x11, b"\xaa")]
            )
            writes = [
                fields["messages"][0].data[4:]
                for name, fields in observed.calls
                if name == "write_messages"
            ]
            self.assertIn(b"\xa2\x04", writes)
            self.assertIn(b"\xa3", writes)
            self.assertFalse(communication.closed)
            self.assertEqual(communication.cleanup_status, 0)
            for ids in ((), (-1,), (65536,)):
                with self.assertRaises(MonitorError):
                    selected_legacy_check_target(communication, ids, {})
            with self.assertRaises(MonitorError):
                selected_legacy_check_target(
                    cast(NativeCommunication, object()), (17,), {}
                )

    def test_normal_router_keeps_variable_provider_distinct(self):
        import tempfile
        from pathlib import Path

        from scripts.monitor_support import MonitorSupportCache
        from scripts.monitor_variable import SelectedVariableMonitor
        from tests.test_monitor_variable import authored_profile

        with tempfile.TemporaryDirectory() as directory:
            profile = authored_profile(Path(directory) / "variable")
            calls = []

            class Stream:
                def send(self, call):
                    calls.append(call.query.request)
                    return 0

                def receive(self, call):
                    calls.append(b"")
                    return (
                        (0, b"\x53\x00\x09\x02\x80\x00")
                        if len(calls) == 2
                        else (0x91010009, b"")
                    )

            def unexpected(query):
                self.fail("Variable support must use the typed native stream")

            cache = MonitorSupportCache(
                profile,
                unexpected,
                "variable",
                bus_id=0x12,
                stream=Stream(),
                source_build=18,
            )
            observed = {key: False for key in (22, 12, 25, 11, 26, 29, 27, 28, 35)}
            observed[22] = True
            plan = selected_normal_monitor_from_cache(
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
                parameter_6=0,
                active_alias_pid=0,
                dynamic_requested=False,
            )
            self.assertIsInstance(plan, SelectedVariableMonitor)
            self.assertEqual(plan.source_build, 18)
            self.assertEqual(plan.commands.setup[0].command_id, 0x109)
            self.assertEqual(calls, [b"\x13", b"", b""])

    def test_p5_runtime_disable_byte_is_exactly_one(self):
        definitions = P5Definitions(
            (1, 2),
            (
                P5Range(0, 7, 1, 0x100, 0, 0, 0, runtime_flag=3),
                P5Range(0, 7, 2, 0x100, 0, 0, 0, runtime_flag=1),
            ),
            (),
            "authored",
        )
        packing = pack_p5_polling(
            definitions, (0x100,), {26: False, 73: True}, excluded=0
        )
        self.assertEqual(packing.layouts, ((1, 0, 0, 7),))
        selection = p5_dynamic_sources(definitions, (0x100,))
        plan = pack_dynamic_dids(
            b"\x2c\x01\0\0",
            selection.sources,
            (DynamicSlot(0xF300, 1),),
            max_request=8,
            max_reply=4,
        )
        self.assertEqual(p5_dynamic_layouts(selection, plan)[0], ((1, 0, 0, 7),))

    def test_native_metadata_lsb_helper_has_per_signal_lifetime(self):
        from tests.test_signal_lsb import SignalLSBTests

        fixture = SignalLSBTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        producer = fixture.make()
        # An earlier helper's negative local discovery must not poison a new
        # native metadata invocation; its shared wire response cache survives.
        producer._pids = {}
        metadata = selected_signal_metadata(
            fixture.profile,
            ((9, 0, 0, 7), (9, 1, 0, 7)),
            lsb_producer=producer,
        )
        self.assertEqual(
            [(item.multiplier, item.divisor) for item in metadata], [(45, 1), (45, 1)]
        )
        self.assertEqual(
            [query.request for query in fixture.calls], [b"\x21\x00", b"\x21\x01"]
        )
        self.assertEqual(len(fixture.stream.calls), 3)

    def test_normal_router_preserves_distinct_a8_packet_provider(self):
        from scripts.monitor_packet_a8 import SelectedPacketA8Monitor
        from scripts.monitor_support import MonitorSupportCache
        from tests.test_monitor_packet_a8 import observed, profile

        for build in (12, 18):
            calls = []

            def exchange(query, calls=calls):
                calls.append(query.request)
                return b"\x61\x0cAB"

            cache = MonitorSupportCache(
                profile(build), exchange, "a8", source_build=build
            )
            keywords: dict = {
                "communication_protocol": 0x12,
                "attribute_3_31": None,
                "interface_id": 0x7E0,
                "excluded": 0,
                "standard_values": (),
                "max_request": 8,
                "max_reply": 8,
                "parameter_6": 0,
                "active_alias_pid": 0,
                "dynamic_requested": False,
            }
            with self.assertRaisesRegex(MonitorError, "explicit ECU"):
                selected_normal_monitor_from_cache(
                    cache, (17,), observed(8), **keywords
                )
            self.assertEqual(calls, [])
            plan = selected_normal_monitor_from_cache(
                cache, (17,), observed(8), native_ecu=42, **keywords
            )
            self.assertIsInstance(plan, SelectedPacketA8Monitor)
            assert isinstance(plan, SelectedPacketA8Monitor)
            self.assertEqual(plan.packing.family, "A8")
            self.assertEqual(plan.source_build, build)
            self.assertEqual(plan.packing.setup_requests, (b"\xa1\x01\x0c\xff",))
            self.assertEqual(calls, [b"\x21\x0c"])

    def test_selected_authored_ddb_to_concrete_p4_metadata(self):
        import tempfile
        from dataclasses import replace
        from pathlib import Path

        from scripts.demo import create_demo
        from scripts.profiles import VehicleCatalog

        with tempfile.TemporaryDirectory() as tmp:
            root = create_demo(Path(tmp) / "authored")
            profile = VehicleCatalog(root / "Techstream_DB_NA").build_profile(1)
            category = bytearray(profile.category_record)
            category[72] = 6
            profile = replace(profile, category_record=bytes(category))
            observed = {key: False for key in (22, 12, 25, 11, 26, 29, 27, 28, 35)}
            observed[22] = True
            plan = selected_p4_monitor(
                profile,
                (1,),
                {12: b"\xff\xff"},
                observed,
                interface_id=7,
                excluded=0,
                max_request=10,
                max_reply=10,
                standard_values=(),
                source_build=12,
            )
            self.assertEqual(plan.source_build, 12)
            with self.assertRaisesRegex(MonitorError, "source build"):
                selected_p4_monitor(
                    profile,
                    (1,),
                    {12: b"\xff\xff"},
                    observed,
                    interface_id=7,
                    excluded=0,
                    max_request=10,
                    max_reply=10,
                    standard_values=(),
                    source_build=True,
                )
            self.assertEqual(plan.frame_sizes, ((6, 2),))
            signal = plan.signals[0]
            self.assertEqual(
                (signal.pid, signal.frame_index, signal.start_bit, signal.end_bit),
                (1, 6, 0, 15),
            )
            self.assertEqual(
                (signal.name, signal.unit, signal.multiplier, signal.divisor),
                ("Engine speed", "rpm", 1, 4),
            )
            self.assertEqual(
                plan.commands.setup[0].values[:3],
                (1, 7, ((6, bytes.fromhex("0c020102")),)),
            )
            from scripts.drive_recorder import NativeDmciCommand

            can_row = bytearray(28)
            struct.pack_into("<I", can_row, 4, 500000)
            connection = SelectedMonitorConnection(
                1,
                0x12,
                MonitorAddress(7, 15, 0xFFFFFFFF),
                10,
                10,
                100,
                0,
                0,
                1,
                2,
                bytes(28),
                bytes(can_row),
                source_identity=plan.definitions.source_identity,
            )
            complete = p4_can_lifecycle(
                plan, connection, connected_device=4, interrupt_send_timing=True
            )
            self.assertEqual(
                p4_can_lifecycle(
                    plan,
                    connection,
                    connected_device=8,
                    interrupt_send_timing=True,
                    recording=True,
                ),
                complete,
            )
            with self.assertRaisesRegex(MonitorError, "recording writer"):
                p4_can_lifecycle(
                    plan,
                    connection,
                    connected_device=8,
                    interrupt_send_timing=True,
                    recording=False,
                )
            with self.assertRaisesRegex(MonitorError, "source identity"):
                p4_can_lifecycle(
                    plan,
                    replace(connection, source_identity=("other-system-db",)),
                    connected_device=4,
                    interrupt_send_timing=True,
                )
            self.assertEqual(
                [c.command_id for c in complete.setup],
                [0x101, 0x107, 0x111, 0x114, 0x116, 0x109],
            )
            self.assertEqual(
                complete.setup[0].values,
                (1, 0x36, 0xE0000000, 0x1FFFFFFF, 0xC6, 0x40030, 1, 2, 10),
            )
            self.assertEqual(complete.setup[2].values, (7, 15, 50, 1, 2))
            self.assertEqual(
                [c.command_id for c in complete.stop], [0x10E, 0x108, 0x104]
            )
            iso_row = bytearray(56)
            struct.pack_into("<I", iso_row, 0, 10400)
            struct.pack_into("<H", iso_row, 4, 7)
            for position in range(8, 50, 2):
                struct.pack_into("<H", iso_row, position, position + 100)
            configs = p4_iso_configs(bytes(iso_row), bus_id=0x11)
            self.assertEqual(len(configs), 23)
            self.assertEqual(
                configs[:5], ((1, 10400), (6, 130), (7, 128), (8, 134), (9, 132))
            )
            self.assertEqual(configs[-3:], ((20, 146), (21, 148), (0x1000A, 0)))
            proto = bytearray(28)
            struct.pack_into("<H", proto, 2, 7)
            iso_connection = replace(
                connection,
                bus_id=0x11,
                protocol_record=bytes(proto),
                can_record=None,
                can_parameter=0,
                can_byte_0=0,
                can_byte_1=0,
            )
            iso = p4_iso_lifecycle(
                plan,
                iso_connection,
                bytes(iso_row),
                connected_device=4,
                init_mode=2,
                parameter_c0=123,
                interrupt_send_timing=False,
            )
            self.assertEqual(
                p4_iso_lifecycle(
                    plan,
                    iso_connection,
                    bytes(iso_row),
                    connected_device=8,
                    init_mode=2,
                    parameter_c0=123,
                    interrupt_send_timing=False,
                    recording=True,
                ),
                iso,
            )
            self.assertEqual(
                iso.setup[0].values, (b"ComIso32.dll\0", configs, 1, 0xC6, 123, 0)
            )
            self.assertEqual(
                [c.command_id for c in iso.setup], [0x100, 0x107, 0x111, 0x114, 0x109]
            )

            for command in complete.setup + complete.start + complete.stop:
                NativeDmciCommand.from_neutral(
                    command.command_id, command.values
                ).encode()
            from scripts.drive_recorder import (
                DMCI_WIRE_COMMANDS,
                NativeCoreBuffer,
                NativeDmciList,
                NativeMonitorReply,
                NativeVimClient,
                NativeVimReply,
                decode_vim_command,
            )

            wire_calls = []
            empty = NativeCoreBuffer((1, 0), b"")

            def exchange(request, *, deadline, cancelled):
                wire, _payload = decode_vim_command(request)
                wire_calls.append(wire)
                if wire == DMCI_WIRE_COMMANDS[0x10D]:
                    response = NativeMonitorReply(
                        0,
                        NativeDmciList(
                            (1, 0),
                            (
                                (
                                    7,
                                    NativeCoreBuffer(
                                        (1, 0), struct.pack("<I", 9) + b"AB"
                                    ),
                                ),
                            ),
                        ),
                        (empty, empty, empty, empty, empty),
                        0,
                    ).encode()
                else:
                    response = bytes(4) + (
                        struct.pack("<I", 1)
                        if wire == DMCI_WIRE_COMMANDS[0x114]
                        else b""
                    )
                return NativeVimReply(wire | 0x80, 6, response).encode()

            client = NativeVimClient(
                exchange,
                capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
            )
            packets = run_monitor_commands(
                complete,
                client,
                interface_id=7,
                frame_sizes=plan.frame_sizes,
                phase=0,
                packet_limit=1,
            )
            self.assertEqual(
                [(p.timestamp_raw, p.payload) for p in packets], [(9, b"AB")]
            )
            self.assertEqual(
                wire_calls,
                [
                    DMCI_WIRE_COMMANDS[c]
                    for c in (
                        0x101,
                        0x107,
                        0x111,
                        0x114,
                        0x116,
                        0x109,
                        0x10C,
                        0x10D,
                        0x10E,
                        0x108,
                        0x104,
                    )
                ],
            )

    def test_native_p4_phase4_and_phase6_support_holes_differ(self):
        definitions = MonitorDefinitions(
            (1,), (MonitorRange(16, 23, 1, 1, 0, 0, 0),), (), "authored"
        )
        for phase, length, start in ((4, 2, 8), (6, 3, 16)):
            packing = pack_p4(
                definitions,
                {1: b"\0\x01\x01"},
                category_flags=phase,
                capabilities=1,
                excluded=0,
                max_request=9,
                max_reply=9,
            )
            self.assertEqual(packing.frames[0].full_length, length)
            self.assertEqual(p4_signal_layouts(packing), ((1, 1, start, start + 7),))

    def test_native_legacy_null_initialization_preserves_both_calls(self):
        calls = []

        class Provider:
            def send(self, ecu, request, **kwargs):
                calls.append(("send", ecu, request, kwargs))
                return 0x90020321

            def receive(self, ecu, **kwargs):
                calls.append(("receive", ecu, kwargs))
                return MonitorReceive(b"", 0, 0x90020323)

        result = legacy_initialize(
            Provider(), "selected", send_timeout=50, receive_timeout=100, protocol=0x12
        )
        self.assertEqual(result, (0x90020321, MonitorReceive(b"", 0, 0x90020323)))
        self.assertEqual(
            calls,
            [
                (
                    "send",
                    "selected",
                    None,
                    {"timeout": 50, "protocol": 0x12, "initialize": True},
                ),
                (
                    "receive",
                    "selected",
                    {
                        "buffer": False,
                        "maximum": 0,
                        "timeout": 100,
                        "argument_5": 0,
                        "flags": 100,
                    },
                ),
            ],
        )

    def test_native_p5_mixed_setup_and_packet(self):
        clear_setup = p5_setup_commands(
            interface_id=7,
            buffer_468=1,
            total_length=2,
            standard_values=((9, 10),),
            data_ids=(),
            dtc_requests=(),
            routines=(RoutineMonitor(b"\x31\x03\x12\x34", 2, (), (), ()),),
            parameter_6=2000,
            clear_ids=(0xF300, 0xABCD),
        )
        self.assertEqual(
            clear_setup.setup[0], MonitorCommand(0x11A, (7, b"\x00\xf3\xcd\xab"))
        )
        self.assertEqual(clear_setup.setup[1].values[6:8], (2, ((9, 10),)))
        routine = RoutineMonitor(bytes.fromhex("31031234"), 2, (0x1234,), (0xFFFF,), ())
        setup = p5_setup_commands(
            interface_id=7,
            buffer_468=8,
            total_length=5,
            standard_values=((1, 2),),
            data_ids=((0x1234, 1),),
            dtc_requests=(bytes.fromhex("1902ff"),),
            routines=(routine,),
            parameter_6=3,
            dtc_patterns=(7,),
        )
        self.assertEqual(
            [item.command_id for item in setup.setup], [0x119, 0x10B, 0x11C]
        )
        self.assertEqual(setup.setup[0].values, (8, 7, ((0x1234, 1),), 5, ((1, 2),), 3))
        self.assertEqual(
            setup.setup[1].values, (8, 7, 7, bytes.fromhex("1902ff"), 0, ())
        )
        self.assertEqual(
            setup.setup[2].values,
            (
                8,
                7,
                bytes.fromhex("31031234"),
                2,
                ((0x1234,),),
                ((0xFFFF,),),
                0,
                (),
                3,
                (),
            ),
        )
        event = P5MonitorEvent(
            ((0x1234, 1),), (bytes.fromhex("1902ff"),), (routine,), routine_info=False
        )
        self.assertEqual(event.request, bytes.fromhex("221234"))
        self.assertIsNone(event.accept(bytes.fromhex("621234aa"), 1))
        self.assertEqual(event.request, bytes.fromhex("1902ff"))
        self.assertIsNone(event.accept(bytes.fromhex("5902ff0102030405060708"), 2))
        self.assertEqual(event.request, routine.request)
        self.assertEqual(
            event.accept(bytes.fromhex("710312341234"), 3),
            (3, bytes.fromhex("aa00021234")),
        )
        self.assertTrue(
            routine.check_status(bytes.fromhex("710312341234"), routine_info=False)
        )
        self.assertFalse(
            routine.check_status(
                bytes.fromhex("710312341234"), routine_info=False, abnormal=True
            )
        )
        self.assertTrue(
            routine.check_status(bytes.fromhex("71031234001234"), routine_info=True)
        )
        byte_status = RoutineMonitor(routine.request, 1, (0xAB34,), (), ())
        self.assertTrue(
            byte_status.check_status(bytes.fromhex("7103123434"), routine_info=False)
        )
        with self.assertRaisesRegex(MonitorError, "truncated"):
            P5MonitorEvent((), (), (routine,), routine_info=True).accept(
                bytes.fromhex("710312341234"), 0
            )
        empty = RoutineMonitor(routine.request, 1, (), (), ())
        self.assertFalse(empty.check_status(b"", routine_info=False))
        unsupported = P5MonitorEvent(
            (), (bytes.fromhex("1902ff"),), (), routine_info=False, dtc_patterns=(7,)
        )
        with self.assertRaises(MonitorError) as error:
            unsupported.accept(b"\x59", 0)
        self.assertEqual(error.exception.code, 0xE0000102)
        self.assertEqual(unsupported.index, 0)

    def test_native_p4_neutral_setup_commands(self):
        definitions = MonitorDefinitions(
            (1,), (MonitorRange(0, 7, 1, 0x10, 0, 0, 0),), (), "authored"
        )
        packing = pack_p4(
            definitions,
            {0x10: b"\x80"},
            category_flags=6,
            capabilities=4,
            excluded=0,
            max_request=9,
            max_reply=9,
        )
        plan = p4_setup_commands(
            packing,
            interface_id=7,
            buffer_468=8,
            total_length=1,
            standard_values=((9, 10),),
            attribute_2_23=False,
        )
        self.assertEqual(plan.setup[0].command_id, 0x109)
        self.assertEqual(
            plan.setup[0].values, (8, 7, ((6, b"\x10\x01\x01"),), 1, ((9, 10),), 3000)
        )
        self.assertEqual(
            [item.command_id for item in plan.start + plan.stop], [0x10C, 0x10E]
        )
        packing = pack_p4(
            definitions,
            {0x10: b"\x80"},
            category_flags=6,
            capabilities=0x20,
            excluded=0,
            max_request=9,
            max_reply=9,
        )
        plan = p4_setup_commands(
            packing,
            interface_id=7,
            buffer_468=8,
            total_length=1,
            standard_values=(),
            attribute_2_23=True,
        )
        self.assertEqual(plan.setup[0].command_id, 0x10A)
        self.assertEqual(
            plan.setup[0].values, (8, 7, 6, ((0x10, 1),), 1, (), 3, 0xFFFFFFFF)
        )

    def test_native_clear_uses_selected_d4_first_template(self):
        from scripts.toyota import CommandFrame

        calls = []

        def selected(function):
            calls.append(function)
            return (CommandFrame(bytes.fromhex("2c03aaaa55")), CommandFrame(b"ignored"))

        profile = cast(VehicleProfile, SimpleNamespace(command_frames=selected))
        self.assertEqual(
            clear_dynamic_requests(profile, (0x1234, 0xF201)),
            (bytes.fromhex("2c03123455"), bytes.fromhex("2c03f20155")),
        )
        self.assertEqual(calls, [0xD4])

    def test_dynamic_length_measured_once_for_many_rejected_slots(self):
        from unittest.mock import PropertyMock, patch

        source = DynamicSource(1, ((1, 1), (2, 1)))
        with patch.object(
            DynamicSource, "length", new_callable=PropertyMock, return_value=2
        ) as length:
            result = pack_dynamic_dids(
                b"\x2c\1\0\0",
                (source,),
                (DynamicSlot(1, 0),) * 100,
                max_request=8,
                max_reply=8,
            )
            self.assertEqual(result.remaining, (source,))
            self.assertEqual(length.call_count, 1)

    def test_native_dynamic_did_packing_order_and_capacity(self):
        sources = (
            DynamicSource(0x1234, ((1, 2), (4, 1))),
            DynamicSource(0x5678, ((2, 4),)),
            DynamicSource(0x9ABC, ((1, 1),)),
        )
        plan = pack_dynamic_dids(
            b"\x2c\x01\0\0",
            sources,
            (DynamicSlot(0xF201, 2), DynamicSlot(0xF202, 2)),
            max_request=12,
            max_reply=10,
        )
        self.assertEqual(
            plan.requests,
            (
                bytes.fromhex("2c01f201567802049abc0101"),
                bytes.fromhex("2c01f2021234010212340401"),
            ),
        )
        self.assertEqual(plan.read_ids, (0xF201, 0xF202))
        self.assertEqual(plan.read_lengths, (5, 3))
        self.assertEqual(plan.remaining, ())
        short = pack_dynamic_dids(
            b"\x2c\x01\0\0", sources, (DynamicSlot(1, 1),), max_request=12, max_reply=10
        )
        self.assertEqual([source.did for source in short.remaining], [0x9ABC, 0x1234])

    def test_native_observed_capability_branches(self):
        observed = {
            value: False for value in (0x16, 10, 8, 9, 12, 25, 11, 26, 29, 27, 28, 35)
        }
        with self.assertRaises(MonitorError) as caught:
            monitor_capabilities(observed)
        self.assertEqual(caught.exception.code, 0x90051007)
        observed.update({0x16: True, 12: True, 29: True, 35: True})
        del observed[10], observed[8], observed[9], observed[27], observed[28]
        result = monitor_capabilities(observed)
        self.assertEqual(result.mask, 5 | 0x20 | 0x2000)
        self.assertTrue(result.attribute_2_23)
        self.assertEqual(result.queried, (22, 12, 25, 11, 26, 29, 35))
        del observed[35]
        with self.assertRaisesRegex(MonitorError, "observation"):
            monitor_capabilities(observed)

    def test_native_monitor_exchange_cycle_and_fault_bounds(self):
        from scripts.toyota_session import Cancelled, Limits, SessionError

        requests = []

        def exchange(ecu, request):
            requests.append((ecu, request))
            return b"\x62" + request[1:] + b"A"

        result = exchange_cycle(
            MonitorEvent.p5((1, 2), (1, 1)),
            exchange,
            "selected",
            tick_ms=lambda: 77,
            clock=lambda: 0.0,
        )
        self.assertEqual(result, (77, b"AA"))
        self.assertEqual(
            requests, [("selected", b"\x22\0\1"), ("selected", b"\x22\0\2")]
        )
        with self.assertRaisesRegex(SessionError, "budget"):
            exchange_cycle(
                MonitorEvent.p5((1, 2), (1, 1)),
                exchange,
                "selected",
                tick_ms=lambda: 0,
                limits=Limits(exchanges=1),
                clock=lambda: 0.0,
            )
        with self.assertRaises(Cancelled):
            exchange_cycle(
                MonitorEvent.p5((1,), (1,)),
                exchange,
                "selected",
                tick_ms=lambda: 0,
                cancelled=lambda: True,
            )
        ticks = iter((0.0, 0.0, 20.0))
        with self.assertRaisesRegex(SessionError, "deadline"):
            exchange_cycle(
                MonitorEvent.p5((1,), (1,)),
                exchange,
                "selected",
                tick_ms=lambda: 0,
                clock=lambda: next(ticks),
            )

    def test_native_mode_and_dmci_idmap_argument_transform(self):
        self.assertEqual(monitor_mode(9, 2, None), 0)
        self.assertEqual(monitor_mode(0x38, 0, True), 2)
        self.assertEqual(monitor_mode(0x38, 0, False), 0)
        self.assertEqual(monitor_mode(0x89, 2, None), 1)
        self.assertEqual(monitor_mode(10, 1, None), 1)
        with self.assertRaisesRegex(MonitorError, "observed"):
            monitor_mode(0x38, 0, None)
        self.assertEqual(
            dmci_id_map_fields(0x7E0, 0x7E8, 0, 10, 20), (0x7E0, 0x7E8, 50, 10, 20)
        )
        self.assertEqual(
            dmci_id_map_fields(0x800007E0, 1, 0, 0, -1),
            (0x800007E0, 1, 1000, 0, 0xFFFFFFFF),
        )
        self.assertEqual(dmci_id_map_fields(1, 2, -1, 3, 4), (1, 2, 0xFFFFFFFF, 3, 4))

    def test_native_monitor_event_cycles_and_short_reply_storage(self):
        event = MonitorEvent.p4(1, (12, 13), (2, 1))
        self.assertEqual(event.request, b"\x21\x0c")
        self.assertIsNone(event.accept(b"\x61\x0cAB", 100))
        self.assertEqual(event.request, b"\x21\x0d")
        packet = event.accept(b"\x61\x0dC", 110)
        self.assertEqual(packet, (110, b"ABC"))
        self.assertIsNone(event.accept(b"\x61\x0cD", 120))
        # Native copies min(reply payload, expected size) into retained storage.
        self.assertEqual(event.accept(b"\x61\x0dE", 130), (130, b"DBE"))
        before = event.request
        with self.assertRaisesRegex(MonitorError, "service"):
            event.accept(b"\x41\x0cA", 140)
        self.assertEqual(event.request, before)

    def test_native_p5_event_and_p4_type6_header(self):
        event = MonitorEvent.p5((0x1234,), (2,))
        self.assertEqual(event.request, b"\x22\x12\x34")
        self.assertEqual(
            event.accept(b"\x62\x12\x34XY", 0xFFFFFFFF), (0xFFFFFFFF, b"XY")
        )
        self.assertEqual(event.accept(b"\x62\x12\x34Z", 1), (1, b"Z\0"))
        event = MonitorEvent.p4(6, (1,), (2,))
        self.assertEqual(event.accept(b"\x61AB", 3), (3, b"AB"))
        for reply in (b"", b"\x61"):
            with self.assertRaisesRegex(MonitorError, "header"):
                MonitorEvent.p4(1, (2,), (1,)).accept(reply, 0)

    def test_native_p4_and_p5_request_builders(self):
        for kind, expected in (
            (0, b"\x01\x0c"),
            (1, b"\x21\x0c"),
            (2, b"\x01\x0c\x01"),
            (3, b"\x21\x0c\x01"),
            (6, b"\x21\x0c"),
        ):
            self.assertEqual(
                p4_monitor_requests(kind, (12, 13)),
                (expected, expected[:1] + bytes([13]) + expected[2:]),
            )
        self.assertEqual(
            p5_monitor_requests((0x1234, 0xABCD)), (b"\x22\x12\x34", b"\x22\xab\xcd")
        )
        for kind in (4, 5, 7):
            with self.assertRaises(MonitorError):
                p4_monitor_requests(kind, (1,))
        for bad in ((), (65536,), (-1,), (True,)):
            with self.assertRaises(MonitorError):
                p5_monitor_requests(bad)

    def test_selected_native_ranges_and_multipid_padding(self):
        def row(key, start, end, frame, flags=0):
            data = bytearray(84)
            struct.pack_into("<H", data, 56, key)
            struct.pack_into("<HH", data, 62, start, end)
            data[77:80] = bytes((7, flags, frame))
            return bytes(data)

        links = [
            struct.pack("<HHH3xB2x", 30, 1, 10, 4),
            struct.pack("<HHH3xB2x", 30, 2, 20, 2),
        ]
        rows = (row(10, 0, 2, 5), row(20, 8, 9, 8), row(30, 0, 0, 0, 16))
        profile = cast(
            VehicleProfile,
            SimpleNamespace(
                records=lambda slot: rows if slot == 10 else tuple(links),
                database=SimpleNamespace(sha256="authored"),
                ecu_database_sha256="authored",
            ),
        )
        definitions = selected_definitions(profile, (30, 10))
        self.assertEqual(definitions.selected_ids, (30, 10))
        self.assertEqual([item.signal_id for item in definitions.ranges], [10, 20])
        self.assertEqual([item.composite_flags for item in definitions.ranges], [4, 2])
        self.assertEqual(definitions.groups[0].padding_ordinal, 3)
        self.assertEqual(definitions.groups[0].links, ((30, 1, 10), (30, 2, 20)))
        with self.assertRaisesRegex(MonitorError, "absent"):
            selected_definitions(profile, (99,))

    def test_native_provider_dispatch(self):
        expected = {
            1: "DataMonitorDLC12.dll",
            2: "DataMonitorDLC12.dll",
            3: "DataMonitorPhase3.dll",
            5: "DataMonitorPhase3.dll",
            6: "DataMonitorPhase4.dll",
            7: "DataMonitorDKIso9141.dll",
            8: "DataMonitorPhase4.dll",
            10: "DataMonitorPSA_DT.dll",
            18: "DataMonitorPhase3.dll",
            19: "DataMonitorPSA_DT.dll",
            20: "DataMonitorPhase5_DT.dll",
            21: "DataMonitorPhase5_DT.dll",
        }
        for phase, name in expected.items():
            self.assertEqual(select_provider(phase | 0x80, 1, None), name)
        self.assertEqual(select_provider(4, 1, True), "DM_ActVariable_DT.dll")
        self.assertEqual(select_provider(4, 1, False), "DataMonitorPhase4.dll")
        for protocol in range(16):
            self.assertEqual(
                select_provider(9, protocol, None),
                "DataMonitorPhase4.dll"
                if protocol in (2, 8)
                else "DataMonitorPhase3.dll",
            )
        for phase in (0, *range(11, 18), 22, 31):
            with self.assertRaises(MonitorError):
                select_provider(phase, 1, None)
        with self.assertRaisesRegex(MonitorError, "observed"):
            select_provider(4, 1, None)


class SelectedLegacyRuntimeTests(unittest.TestCase):
    def test_selected_legacy_factory_actual_run_and_recording_lifetime(self):
        from itertools import product

        from scripts.data_monitor import (
            complete_selected_legacy_recording,
            selected_legacy_monitor_runtime,
        )
        from scripts.drive_recorder import (
            DrsFile,
            NativeCoreString,
            NativeTriggerInfo,
            NativeTriggerParameters,
            NativeVehicleSelection,
        )
        from scripts.monitor_legacy import LegacyRunTarget
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )
        from scripts.profiles import ProtocolProfile
        from tests.test_monitor_legacy import SelectedSupportIntegration

        fixture = SelectedSupportIntegration()
        selection = NativeVehicleSelection(
            (1, 0),
            NativeCoreString((1, 0), b"\0"),
            ((1, 0), (1, 0), (1, 0)),
            (),
            (),
            (),
            (0, 0),
        )
        system = {
            "identifier": 0,
            "strings": [{"core": [1, 0], "data_hex": ""}] * 2,
            "value_raw": 0,
        }
        parameters = NativeTriggerParameters((1, 0), 1, 0, (1, 0), (), (1, 0), ())
        for build in (12, 18):
            for phase, function, family in ((3, 11, "P3"), (7, 26, "DK")):
                with self.subTest(build=build, phase=phase):
                    backend = fixture.run_backend()
                    comm = fixture.run_communication(phase, build, backend)
                    target = LegacyRunTarget(comm, (17,), fixture.observed(function))
                    controller, message = selected_legacy_monitor_runtime(
                        (target,),
                        command_id=9,
                        command_ecu=42,
                        connected_device=8,
                        clock=lambda: 0,
                    )
                    self.assertEqual(backend.calls, [])
                    self.assertEqual(controller.family, family)
                    try:
                        controller.run_one()
                        self.assertIsNone(message.exception)
                        assert message.result is not None
                        self.assertEqual(message.result.status, 0)
                        for _ in range(4):
                            controller.poll()
                            if controller.capture().capture.packets:
                                break
                        self.assertEqual(
                            controller.capture().capture.packets[0].payload, b"\xaa\xbb"
                        )
                    finally:
                        controller.close()
                        comm.close()
            for device, trigger_type, with_primary in product(
                (4, 8), (1, 7), (False, True)
            ):
                with self.subTest(
                    build=build, device=device, trigger_type=trigger_type, command=87
                ):
                    backend = fixture.run_backend()
                    comm = fixture.run_communication(
                        3, build, backend, recording_protocol=True
                    )
                    assert isinstance(comm.operations, NativeFrameController)
                    prototype = comm.operations.operations
                    comm = NativeCommunication.from_backend(
                        comm.profile,
                        backend,
                        "engine",
                        first_request=b"\x21\x00",
                        driver=prototype.driver,
                        device_kind=device,
                        bus_id=comm.bus_id,
                        source_build=build,
                        clock=lambda: 0,
                    )
                    primary = None
                    if with_primary:
                        prototype_primary = fixture.run_communication(
                            3, build, backend, category=43
                        )
                        selected_profile = prototype_primary.profile
                        primary_profile = ProtocolProfile(
                            selected_profile.catalog,
                            selected_profile.category_record,
                            selected_profile.exception_ids,
                            selected_profile.vehicle_name_key,
                        )
                        primary_comm = NativeCommunication.from_backend(
                            primary_profile,
                            backend,
                            "primary",
                            first_request=b"\x21\x00",
                            driver=prototype.driver,
                            device_kind=device,
                            bus_id=0x11,
                            source_build=build,
                            clock=lambda: 0,
                        )
                        primary = LegacyRunTarget(
                            primary_comm, (), {}, allocation_size=0
                        )
                    controller, message = selected_legacy_monitor_runtime(
                        (LegacyRunTarget(comm, (17,), fixture.observed(11)),),
                        command_id=87,
                        command_ecu=43 if with_primary else 42,
                        primary=primary,
                        connected_device=device,
                        selection=selection,
                        system_information=system,
                        trigger=NativeTriggerInfo((1, 0), trigger_type, 1, 0),
                        parameters=parameters,
                        init_mode=1,
                        parameter_c0=77,
                        enable_mode=0x10,
                        shared_interface=3,
                        clock=lambda: 0,
                    )
                    self.assertEqual(backend.calls, [])
                    recording = complete_selected_legacy_recording(controller, message)
                    self.assertEqual(DrsFile.parse(recording.encode()), recording)
                    self.assertTrue(comm.closed)
                    if primary is not None:
                        self.assertTrue(primary.communication.closed)
                        self.assertIsNone(controller.buffers[0])
                        self.assertEqual(
                            controller.targets[1].communication.profile.category, 42
                        )
                    mode_groups = {table.table_id for table in recording.tables} & {
                        0x21,
                        0x22,
                        0x23,
                        0x24,
                    }
                    self.assertEqual(
                        mode_groups,
                        {0x21, 0x22, 0x23, 0x24} if trigger_type == 7 else set(),
                    )
                    self.assertLess(
                        controller.trace.index(("drs-end", 0x12)),
                        controller.trace.index(("finish", 87)),
                    )
                    writes = [
                        fields["messages"][0].data[3:]
                        for name, fields in backend.calls
                        if name == "write_messages"
                    ]
                    self.assertEqual(writes, [b"\x21\x00", b"\x09\x02"])
                    self.assertEqual(
                        sum(name == "connect" for name, _ in backend.calls), 1
                    )
                    self.assertEqual(
                        sum(name == "disconnect" for name, _ in backend.calls), 1
                    )

    def test_selected_legacy_factory_preserves_primary_and_unsupported(self):
        from scripts.data_monitor import selected_legacy_monitor_runtime
        from scripts.monitor_j2534 import NativeMonitorSourceFault
        from scripts.monitor_legacy import LegacyRunTarget
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )
        from scripts.profiles import ProtocolProfile
        from tests.test_monitor_legacy import SelectedSupportIntegration

        fixture = SelectedSupportIntegration()
        for build in (12, 18):
            backend = fixture.run_backend()
            primary_comm = fixture.run_communication(3, build, backend, category=43)
            profile = primary_comm.profile
            primary_profile = ProtocolProfile(
                profile.catalog,
                profile.category_record,
                profile.exception_ids,
                profile.vehicle_name_key,
            )
            assert isinstance(primary_comm.operations, NativeFrameController)
            primary_comm = NativeCommunication.from_backend(
                primary_profile,
                backend,
                "primary",
                first_request=b"\x21\x00",
                driver=primary_comm.operations.operations.driver,
                device_kind=8,
                bus_id=0x11,
                source_build=build,
                clock=lambda: 0,
            )
            self.assertFalse(hasattr(primary_comm.profile, "database"))
            data_comm = fixture.run_communication(
                3,
                build,
                backend,
                category=42,
                diagnostic_mode=bytes(8) + (0x18).to_bytes(4, "little") + bytes(4),
            )
            target = LegacyRunTarget(data_comm, (17,), fixture.observed(11))
            with self.assertRaisesRegex(MonitorError, "actual command ECU"):
                selected_legacy_monitor_runtime(
                    (target,), command_id=56, command_ecu=43, connected_device=8
                )
            self.assertEqual(backend.calls, [])
            controller, message = selected_legacy_monitor_runtime(
                (target,),
                command_id=56,
                command_ecu=43,
                connected_device=8,
                primary=LegacyRunTarget(primary_comm, (), {}, allocation_size=0),
                shared_interface=3,
                clock=lambda: 0,
            )
            try:
                with self.assertRaises(NativeMonitorSourceFault):
                    controller.run_one()
                self.assertIsInstance(message.exception, NativeMonitorSourceFault)
                self.assertEqual(
                    tuple(t.communication.profile.category for t in controller.targets),
                    (43, 42),
                )
                self.assertIsNone(controller.buffers[0])
            finally:
                controller.close()
                primary_comm.close()
                data_comm.close()

    def test_recording_completion_rejects_foreign_prepared_message_before_io(self):
        from scripts.data_monitor import (
            complete_selected_legacy_recording,
            selected_legacy_monitor_runtime,
        )
        from scripts.drive_recorder import (
            NativeCoreString,
            NativeTriggerInfo,
            NativeTriggerParameters,
            NativeVehicleSelection,
        )
        from scripts.monitor_legacy import LegacyRunTarget
        from tests.test_monitor_legacy import SelectedSupportIntegration

        fixture = SelectedSupportIntegration()
        selection = NativeVehicleSelection(
            (1, 0),
            NativeCoreString((1, 0), b"\0"),
            ((1, 0), (1, 0), (1, 0)),
            (),
            (),
            (),
            (0, 0),
        )
        system = {
            "identifier": 0,
            "strings": [{"core": [1, 0], "data_hex": ""}] * 2,
            "value_raw": 0,
        }
        for build in (12, 18):
            prepared = []
            try:
                for _ in range(2):
                    backend = fixture.run_backend()
                    comm = fixture.run_communication(
                        3, build, backend, recording_protocol=True
                    )
                    controller, message = selected_legacy_monitor_runtime(
                        (LegacyRunTarget(comm, (17,), fixture.observed(11)),),
                        command_id=87,
                        command_ecu=42,
                        connected_device=8,
                        shared_interface=3,
                        init_mode=1,
                        parameter_c0=77,
                        enable_mode=0x10,
                        clock=lambda: 0,
                        selection=selection,
                        system_information=system,
                        trigger=NativeTriggerInfo((1, 0), 1, 1, 0),
                        parameters=NativeTriggerParameters(
                            (1, 0), 1, 0, (1, 0), (), (1, 0), ()
                        ),
                    )
                    prepared.append((controller, message, comm, backend))
                controller_a, _, comm_a, backend_a = prepared[0]
                _, message_b, comm_b, backend_b = prepared[1]
                with self.assertRaises(MonitorError):
                    complete_selected_legacy_recording(controller_a, message_b)
                self.assertEqual(backend_a.calls, [])
                self.assertEqual(backend_b.calls, [])
                self.assertFalse(comm_a.closed)
                self.assertFalse(comm_b.closed)
                for controller, message, comm, _ in prepared:
                    complete_selected_legacy_recording(controller, message)
                    self.assertTrue(comm.closed)
            finally:
                for controller, _, comm, _ in prepared:
                    controller.close()
                    comm.close()

    def test_selected_recording_outer_fault_cancel_and_dk_cleanup(self):
        from scripts.data_monitor import (
            complete_selected_legacy_recording,
            selected_legacy_monitor_runtime,
        )
        from scripts.drive_recorder import (
            NativeCoreString,
            NativeTriggerInfo,
            NativeTriggerParameters,
            NativeVehicleSelection,
        )
        from scripts.monitor_legacy import LegacyRunTarget
        from scripts.toyota_session import Cancelled
        from tests.test_monitor_legacy import SelectedSupportIntegration

        fixture = SelectedSupportIntegration()
        selection = NativeVehicleSelection(
            (1, 0),
            NativeCoreString((1, 0), b"\0"),
            ((1, 0), (1, 0), (1, 0)),
            (),
            (),
            (),
            (0, 0),
        )
        system_information = {
            "identifier": 0,
            "strings": [{"core": [1, 0], "data_hex": ""}] * 2,
            "value_raw": 0,
        }
        trigger = NativeTriggerInfo((1, 0), 1, 1, 0)
        parameters = NativeTriggerParameters((1, 0), 1, 0, (1, 0), (), (1, 0), ())
        for build in (12, 18):
            for fault in (
                RuntimeError("outer VIN host fault"),
                Cancelled("outer VIN cancelled"),
            ):
                with self.subTest(build=build, fault=type(fault)):
                    backend = fixture.run_backend()
                    invoke = backend.invoke

                    def fail_vin(
                        operation,
                        fields,
                        *,
                        deadline,
                        cancelled,
                        backend=backend,
                        fault=fault,
                        invoke=invoke,
                    ):
                        if (
                            operation == "read_messages"
                            and backend.request == b"\x09\x02"
                        ):
                            raise fault
                        return invoke(
                            operation, fields, deadline=deadline, cancelled=cancelled
                        )

                    backend.invoke = fail_vin
                    comm = fixture.run_communication(
                        3, build, backend, recording_protocol=True
                    )
                    controller, message = selected_legacy_monitor_runtime(
                        (LegacyRunTarget(comm, (17,), fixture.observed(11)),),
                        command_id=87,
                        command_ecu=42,
                        connected_device=8,
                        shared_interface=3,
                        init_mode=1,
                        parameter_c0=77,
                        enable_mode=0x10,
                        clock=lambda: 0,
                        selection=selection,
                        system_information=system_information,
                        trigger=trigger,
                        parameters=parameters,
                    )
                    with self.assertRaises(type(fault)) as caught:
                        complete_selected_legacy_recording(controller, message)
                    self.assertIs(caught.exception, fault)
                    self.assertTrue(comm.closed)
                    self.assertTrue(controller.closed)
                    assert controller.recording_writer is not None
                    assert controller.queue is not None
                    self.assertIsNone(controller.recording_writer.result)
                    self.assertTrue(controller.queue.finish_event.is_set())
            backend = fixture.run_backend()
            comm = fixture.run_communication(7, build, backend, recording_protocol=True)
            controller, message = selected_legacy_monitor_runtime(
                (LegacyRunTarget(comm, (17,), fixture.observed(26)),),
                command_id=87,
                command_ecu=42,
                connected_device=8,
                clock=lambda: 0,
                selection=selection,
                system_information=system_information,
                trigger=trigger,
                parameters=parameters,
            )
            with self.assertRaises(MonitorError) as caught:
                complete_selected_legacy_recording(controller, message)
            self.assertEqual(caught.exception.code, 0x90050405)
            self.assertTrue(comm.closed)
            self.assertEqual(backend.calls, [])


def run_selected_variable_single(
    *,
    failure=False,
    cancel=False,
    connected_device=8,
    build=18,
    duplicate=False,
    null_controller=False,
):
    import struct
    import tempfile
    from dataclasses import replace
    from pathlib import Path

    from scripts.data_monitor import (
        MonitorError,
        SelectedMonitorSession,
        selected_legacy_check_target,
        selected_variable_monitor_runtime,
    )
    from scripts.diagnostic_db import Section
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
    from scripts.frame_transport import DriverProperties, J2534Result, NativeMessage
    from scripts.monitor_j2534 import DirectJ2534Worker
    from scripts.native_communication import NativeCommunication, NativeFrameController
    from scripts.profiles import ProtocolProfile
    from scripts.snapshot import (
        MonitorBuffer,
        decode_monitor_buffer,
        encode_monitor_buffer,
        monitor_samples,
    )
    from scripts.toyota import VariableTable
    from scripts.toyota_session import Cancelled, Limits
    from tests.test_monitor_variable import authored_profile

    with tempfile.TemporaryDirectory() as directory:
        profile = authored_profile(Path(directory) / "selected")
        database = profile.catalog.management
        table = VariableTable(database.sections[0].payload, database.sections[0].count)
        values = [table.get(i) for i in (1, 2)] + [b"\x10\x01", b"\x3e"]
        offset, directory_bytes = 0, b""
        for value in values:
            directory_bytes += struct.pack("<IH", offset, len(value))
            offset += len(value)
        sections = dict(database.sections)
        sections[0] = Section(0, 0, 4, False, directory_bytes + b"".join(values))
        sections[17] = replace(
            sections[17],
            count=4,
            payload=sections[17].payload + struct.pack("<8H", 11, 3, 0, 0, 12, 4, 0, 0),
        )
        sections[18] = replace(
            sections[18],
            count=3,
            payload=sections[18].payload
            + struct.pack(
                "<16H", 1, 0x67, 0, 11, 0, 0, 0, 0, 1, 0x7F, 0, 12, 0, 0, 0, 0
            ),
        )
        if build == 12:
            protocol = sections[13].payload
            sections[13] = replace(
                sections[13], payload=protocol[:22] + bytes((protocol[24], 0))
            )
        if null_controller:
            for slot, width, key_offset in (
                (13, 24 if build == 12 else 28, 0),
                (16, 76, 68),
                (18, 16, 0),
            ):
                original = sections[slot]
                appended = []
                for offset in range(0, len(original.payload), width):
                    row = bytearray(original.payload[offset : offset + width])
                    struct.pack_into("<H", row, key_offset, 2)
                    appended.append(bytes(row))
                sections[slot] = replace(
                    original,
                    count=original.count * 2,
                    payload=original.payload + b"".join(appended),
                )
        profile.catalog.management = replace(
            database,
            sections=sections,
            version=0x0100030C if build == 12 else 0x0100032F,
        )

        class Backend:
            def __init__(self):
                self.request = b""
                self.reads = 0
                self.calls = []

            def invoke(self, operation, fields, *, deadline, cancelled):
                self.calls.append(operation)
                if operation == "connect":
                    return J2534Result(handle=7)
                if operation == "start_message_filter":
                    return J2534Result(handle=100 + len(self.calls))
                if operation == "write_messages":
                    self.request = fields["messages"][0].data[4:]
                    self.reads = 0
                    return J2534Result(count=1)
                if operation == "read_messages":
                    self.reads += 1
                    if self.request == b"\x13":
                        if self.reads > 1:
                            return J2534Result(code=9)
                        payload = b"\x53\0\11\2\x80\x80"
                    elif self.request == b"\x21\x09":
                        if failure:
                            return J2534Result(code=7)
                        payload = b"\x61\x09AB"
                    else:
                        payload = bytes((self.request[0] | 0x40,)) + self.request[1:]
                    return J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(
                                6, 0, 0, 1234000, 0, b"\x00\x00\x07\xe8" + payload
                            ),
                        ),
                    )
                return J2534Result()

        backend = Backend()
        cancelled_state = [False]
        communication = NativeCommunication.from_backend(
            profile,
            backend,
            "variable",
            first_request=b"\x13",
            driver=DriverProperties(0, b"04.04", "authored"),
            device_kind=connected_device,
            bus_id=0x12,
            source_build=build,
            clock=lambda: 0,
            cancelled=lambda: cancelled_state[0],
        )
        assert isinstance(communication.operations, NativeFrameController)
        lower = communication.operations.operations
        observed = {
            key: key == 12 for key in (22, 10, 8, 9, 12, 25, 11, 26, 29, 27, 28, 35)
        }
        target = selected_legacy_check_target(communication, (4,), observed)
        controller_communication = None
        if null_controller:
            category = bytearray(profile.category_record)
            struct.pack_into("<H", category, 68, 2)
            controller_profile = ProtocolProfile(
                profile.catalog,
                bytes(category),
                profile.exception_ids,
                profile.vehicle_name_key,
            )
            assert controller_profile.ecu_database_sha256 is None
            controller_communication = NativeCommunication.from_backend(
                controller_profile,
                backend,
                "controller",
                first_request=b"\x13",
                driver=lower.driver,
                device_kind=connected_device,
                bus_id=0x12,
                source_build=build,
                clock=lambda: 0,
            )
        session = SelectedMonitorSession(
            profile, source_build=build, shared_interface=0
        )
        wire_calls = []

        def dmci_exchange(request, *, deadline, cancelled):
            wire, body = decode_vim_command(request)
            wire_calls.append(wire)
            if wire == DMCI_WIRE_COMMANDS[0x10D]:
                assert (
                    body
                    == NativeDmciCommand(
                        0x10D, (NativeDmciList((1, 0), ((profile.category,),)),)
                    ).encode()
                )
                empty = NativeCoreBuffer((1, 0), b"")
                payload = NativeMonitorReply(
                    0,
                    NativeDmciList(
                        (1, 0),
                        (
                            (
                                profile.category,
                                NativeCoreBuffer((1, 0), struct.pack("<I", 9) + b"AB"),
                            ),
                        ),
                    ),
                    (
                        empty,
                        NativeCoreBuffer(
                            (1, 0), struct.pack("<IIIB", 0x7E0, 0x123, 0xE0000103, 0)
                        )
                        if failure
                        else empty,
                        empty,
                        empty,
                        empty,
                    ),
                    0,
                ).encode()
            else:
                payload = bytes(4)
            return NativeVimReply(wire | 0x80, 6, payload).encode()

        client = NativeVimClient(
            dmci_exchange,
            capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
        )
        try:
            runtime = selected_variable_monitor_runtime(
                (target, target) if duplicate else (target,),
                client if connected_device == 4 else lower,
                connected_device=connected_device,
                command_kind=0x42 if duplicate or null_controller else 7,
                command_ecu=2 if null_controller else 1,
                controller_communication=controller_communication,
                allocation=4096,
                standard_values=((), ()) if duplicate else ((),),
                names=(b"overwritten", b"variable") if duplicate else (b"variable",),
                text_encoding="utf-8",
                phase=0,
                clock=lambda: 0,
                ticks=lambda: 1234,
                limits=Limits(exchanges=256),
                cancelled=lambda: cancelled_state[0],
                monitor_session=session,
            )
        except MonitorError as error:
            assert null_controller and connected_device == 8
            assert error.code == 0xE0000102
            assert controller_communication is not None
            assert communication.closed and controller_communication.closed
            assert lower.channel is None
            return {
                "build": build,
                "connected_device": connected_device,
                "boundary": "native-null-controller-no-event",
                "code": error.code,
            }
        if null_controller:
            assert controller_communication is not None
            assert runtime.native_slot_categories == (2, 1)
            assert runtime.get_fault(0) == 0
            assert controller_communication.closed
        if connected_device == 8:
            assert isinstance(runtime.worker, DirectJ2534Worker)
            assert runtime.worker.disable_packet_ecu == session.disable_packet_ecu
        assert len(runtime.targets) == 1
        assert runtime.targets[0].buffer.name.data.rstrip(b"\0") == b"variable"
        assert communication.closed and lower.channel is None
        cancelled_state[0] = cancel
        try:
            try:
                captures = runtime.run((1,))
            finally:
                runtime.close()
        except (MonitorError, RecorderCancelled, Cancelled) as error:
            assert failure or cancel
            assert lower.channel is None
            assert session.disabled_packet_ecus == ()  # Variable8610 constructs BASE.
            if cancel:
                assert isinstance(error, (RecorderCancelled, Cancelled))
                assert runtime.faults == [0]
            else:
                assert isinstance(error, MonitorError) and any(runtime.faults)
            return {
                "build": build,
                "connected_device": connected_device,
                "boundary": "cancel" if cancel else "native-read-fault",
                "error": type(error).__name__,
                "faults": runtime.faults,
                "calls": backend.calls,
            }
        assert not failure and not cancel
        assert len(captures) == 1 and captures[0].packets[0].payload == b"AB"
        expected_channels = 1 if connected_device == 4 else 2
        assert (
            backend.calls.count("connect")
            == backend.calls.count("disconnect")
            == expected_channels
        )
        if connected_device == 4:
            assert DMCI_WIRE_COMMANDS[0x10D] in wire_calls
            assert DMCI_WIRE_COMMANDS[0x104] in wire_calls
        metadata = MonitorBuffer(
            b"variable", bytes(16), b"", b"", b"", b"", 0, (), (4,), b"", ()
        )
        saved = captures[0].monitor_buffer(
            runtime.targets[0].buffer, metadata, phase=0, block_packets=1
        )
        saved = decode_monitor_buffer(encode_monitor_buffer(saved))
        samples = monitor_samples(saved, encoding="utf-8")
        assert len(samples) == 1
        return {
            "build": build,
            "connected_device": connected_device,
            "duplicate_registration": duplicate,
            "calls": backend.calls,
            "wire_calls": wire_calls,
            "samples": samples,
            "physical": "PHYSICAL_UNCONFIRMED",
        }


def run_selected_variable_multi(
    *,
    build=18,
    foreign_context=False,
    source_changed=False,
    live_source_channel=False,
    cancel=False,
    host_failure=False,
    native_fault=False,
    with_voltage=False,
):
    """Build authored selected profiles and exercise the real joined factory."""
    import struct
    import tempfile
    from copy import copy
    from dataclasses import replace
    from pathlib import Path

    from scripts.data_monitor import (
        MonitorError,
        selected_legacy_check_target,
        selected_variable_monitor_runtime,
    )
    from scripts.diagnostic_db import Section
    from scripts.drive_recorder import (
        RecorderCancelled,
    )
    from scripts.frame_transport import (
        DriverProperties,
        J2534Result,
        NativeFrameOperations,
        NativeMessage,
    )
    from scripts.native_communication import NativeCommunication, NativeFrameController
    from scripts.snapshot import (
        MonitorBuffer,
        decode_monitor_buffer,
        encode_monitor_buffer,
        monitor_samples,
    )
    from scripts.toyota_session import Cancelled, Limits
    from tests.test_monitor_variable import authored_profile

    with tempfile.TemporaryDirectory() as directory:
        base = authored_profile(Path(directory) / "selected")
        database = base.catalog.management
        sections = dict(database.sections)
        values = [b"\2\12\0", b"\x13", b"\x10\x01", b"\x3e"]
        offset, entries = 0, []
        for value in values:
            entries.append(struct.pack("<IH", offset, len(value)))
            offset += len(value)
        sections[0] = Section(0, 0, 4, False, b"".join(entries + values))
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
        if build == 12:
            protocol = sections[13].payload
            sections[13] = replace(
                sections[13], payload=protocol[:22] + bytes((protocol[24], 0))
            )
        manager = replace(
            database,
            sections=sections,
            version=0x0100030C if build == 12 else 0x0100032F,
        )

        profiles = []
        category_ids = (42, 43, 0x68) if with_voltage else (42, 43)
        for category_id in category_ids:
            selected_sections = dict(manager.sections)
            for slot, width, key_offset in (
                (13, 24 if build == 12 else 28, 0),
                (16, 76, 68),
                (18, 16, 0),
            ):
                section = selected_sections[slot]
                payload = bytearray(section.payload)
                for row_offset in range(0, len(payload), width):
                    struct.pack_into(
                        "<H", payload, row_offset + key_offset, category_id
                    )
                selected_sections[slot] = replace(section, payload=bytes(payload))
            catalog = copy(base.catalog)
            catalog.management = replace(manager, sections=selected_sections)
            record = bytearray(base.category_record)
            struct.pack_into("<H", record, 68, category_id)
            if category_id == 43:
                record[72] = 6
            profiles.append(
                replace(base, catalog=catalog, category_record=bytes(record))
            )

        class Backend:
            def __init__(self):
                self.request = b""
                self.reads = 0
                self.calls = []
                self.events = []
                self.host_fault = TimeoutError("Injected MultiMon host read timeout")

            def invoke(self, operation, fields, *, deadline, cancelled):
                self.calls.append(operation)
                self.events.append((operation, fields))
                if operation == "connect":
                    return J2534Result(handle=7)
                if operation == "start_message_filter":
                    return J2534Result(handle=100 + len(self.calls))
                if operation == "write_messages":
                    self.request = fields["messages"][0].data[4:]
                    self.reads = 0
                    return J2534Result(count=1)
                if operation == "read_messages":
                    self.reads += 1
                    if host_failure and self.request == b"\x21\x09":
                        raise self.host_fault
                    if native_fault and self.request == b"\x21\x09":
                        return J2534Result(code=7)
                    if self.request == b"\x13":
                        if self.reads > 1:
                            return J2534Result(code=9)
                        payload = b"\x53\0\11\2\x80\x80"
                    elif self.request == b"\x21\x09":
                        payload = b"\x61\x09AB"
                    else:
                        payload = bytes((self.request[0] | 0x40,)) + self.request[1:]
                    return J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(
                                6, 0, 0, 1234000, 0, b"\x00\x00\x07\xe8" + payload
                            ),
                        ),
                    )
                return J2534Result()

        backend = Backend()
        driver = DriverProperties(0, b"04.04", "authored")
        communications = tuple(
            NativeCommunication.from_backend(
                profile,
                backend,
                f"engine{profile.category}",
                first_request=b"\x13",
                driver=driver,
                device_kind=8,
                bus_id=0x12,
                source_build=build,
                clock=lambda: 0,
            )
            for profile in profiles
        )
        observed = {
            key: key == 12 for key in (22, 10, 8, 9, 12, 25, 11, 26, 29, 27, 28, 35)
        }
        check_targets = tuple(
            selected_legacy_check_target(communication, (4,), observed)
            for communication in communications
        )
        primary = communications[0]
        assert isinstance(primary.operations, NativeFrameController)
        operations = primary.operations.operations
        cancellation = [False]
        selected_operations = operations
        foreign_backend = None
        live_operations = None
        if live_source_channel:
            live_operations = NativeFrameOperations(
                primary.profile,
                operations.plan,
                backend,
                native_build=cast(Literal[12, 18], build),
                bus_id=operations.bus_id,
                driver=operations.driver,
                device_kind=8,
                diagnostic_mode=operations.diagnostic_mode,
                clock=lambda: 0,
            )
            assert live_operations.open(deadline=10, setup=False) == 0
            selected_operations = live_operations
        elif foreign_context or source_changed:
            selected_operations = copy(operations)
        if foreign_context:
            foreign_backend = Backend()
            selected_operations.backend = foreign_backend
        if source_changed:
            setattr(selected_operations, "native_build", 12)  # noqa: B010 - inject invalid observed build
        try:
            runtime = selected_variable_monitor_runtime(
                check_targets,
                selected_operations,
                connected_device=8,
                command_kind=0x42,
                command_ecu=42,
                allocation=4096,
                standard_values=tuple(() for _ in check_targets),
                names=tuple(
                    f"engine{target.profile.category}\0".encode()
                    for target in check_targets
                ),
                text_encoding="utf-8",
                phase=0,
                clock=lambda: 0,
                ticks=lambda: 1234,
                limits=Limits(exchanges=256),
                cancelled=lambda: cancellation[0],
                voltage_state=(
                    __import__(
                        "scripts.monitor_dlc12", fromlist=["DLC12VoltageState"]
                    ).DLC12VoltageState(0)
                    if with_voltage
                    else None
                ),
            )
        except MonitorError as error:
            if live_source_channel:
                assert "fresh device8 source context" in str(error)
                assert all(communication.closed for communication in communications)
                assert live_operations is not None and live_operations.channel == 7
                assert live_operations.owns_channel
                assert backend.calls.count("disconnect") == len(communications)
                assert live_operations.close(deadline=10) == 0
                return {
                    "build": build,
                    "boundary": "live-source-channel-retained",
                    "channels_closed": True,
                }
            assert (foreign_context or source_changed) and "contexts differ" in str(
                error
            )
            assert all(communication.closed for communication in communications)
            assert operations.channel is None
            assert foreign_backend is None or foreign_backend.calls == []
            return {
                "build": build,
                "boundary": (
                    "foreign-backend-rejected"
                    if foreign_context
                    else "changed-source-rejected"
                ),
                "support_channels_closed": True,
                "foreign_backend_calls": []
                if foreign_backend is None
                else foreign_backend.calls,
            }
        from scripts.monitor_poll import MultiMonitorPollingWorker

        assert isinstance(runtime.worker, MultiMonitorPollingWorker)
        assert tuple(target.cache.profile.category for target in runtime.targets) == (
            (42, 43, 0x68) if with_voltage else (42, 43)
        )
        assert tuple(
            item.category_flags for item in runtime.worker.operations.targets
        ) == (
            4,
            6,
        )
        assert all(communication.closed for communication in communications)
        assert operations.channel is None
        if with_voltage:
            try:
                runtime.run((1, 1, 1))
            except MonitorError as error:
                runtime.close()
                assert "GetError=0xffffffff" in str(error)
                assert all(communication.closed for communication in communications)
                assert operations.channel is None
                return {
                    "build": build,
                    "boundary": "mixed-voltage-source-failure",
                    "route": type(runtime.worker).__name__,
                    "targets": [
                        target.cache.profile.category for target in runtime.targets
                    ],
                    "lower_targets": [
                        item.command_id for item in runtime.worker.operations.targets
                    ],
                    "code": error.code,
                    "captures": 0,
                }
            raise AssertionError("Mixed voltage path must retain its source failure")
        multi_lower = runtime.worker.operations
        native_lower = multi_lower.operations
        original_send = native_lower.send
        initialization_modes = []
        entry_calls = []
        original_entry = multi_lower.entry_comm_system_info

        def observe_entry(category, bus, entry, *, deadline):
            entry_calls.append((category, bus, entry))
            return original_entry(category, bus, entry, deadline=deadline)

        multi_lower.entry_comm_system_info = observe_entry

        def observe_send(request, **kwargs):
            initialization_modes.append(kwargs.get("initialization_mode"))
            return original_send(request, **kwargs)

        native_lower.send = observe_send
        cancellation[0] = cancel
        try:
            captures = runtime.run((1, 1))
        except TimeoutError as error:
            assert host_failure and error is backend.host_fault
            runtime.close()
            assert native_lower.channel is None
            assert backend.calls.count("connect") == backend.calls.count("disconnect")
            return {
                "build": build,
                "boundary": "host-exception",
                "error_identity_preserved": error is backend.host_fault,
                "channels_closed": True,
            }
        except MonitorError as error:
            assert native_fault and error.code == 0xE0000108
            runtime.close()
            assert native_lower.channel is None
            assert backend.calls.count("connect") == backend.calls.count("disconnect")
            return {
                "build": build,
                "boundary": "native-read-fault",
                "code": error.code,
                "primitive_read_code": 7,
                "error_type": type(error).__name__,
                "host_exception_conversion": False,
                "channels_closed": True,
            }
        except (RecorderCancelled, Cancelled) as error:
            assert cancel
            runtime.close()
            assert native_lower.channel is None
            assert backend.calls.count("connect") == backend.calls.count("disconnect")
            return {
                "build": build,
                "boundary": "cancelled",
                "error": type(error).__name__,
                "channels_closed": True,
            }
        finally:
            native_lower.send = original_send
        runtime.close()
        assert len(captures) == 2
        assert all(capture.packets[0].payload == b"AB" for capture in captures)
        assert backend.calls.count("connect") == backend.calls.count("disconnect") == 3
        samples = []
        for target, capture in zip(runtime.targets, captures):
            metadata = MonitorBuffer(
                target.buffer.name.data,
                bytes(16),
                b"",
                b"",
                b"",
                b"",
                0,
                (),
                (4,),
                b"",
                (),
            )
            saved = capture.monitor_buffer(
                target.buffer, metadata, phase=0, block_packets=1
            )
            samples.append(
                monitor_samples(
                    decode_monitor_buffer(encode_monitor_buffer(saved)),
                    encoding="utf-8",
                )
            )
        return {
            "build": build,
            "route": type(runtime.worker).__name__,
            "targets": [target.cache.profile.category for target in runtime.targets],
            "target_flags": [
                item.category_flags for item in runtime.worker.operations.targets
            ],
            "controller_flags": primary.profile.category_record[72],
            "backend_calls": backend.calls,
            "connect_arguments": [
                dict(fields)
                for operation, fields in backend.events
                if operation == "connect"
            ],
            "multi_entry_calls": entry_calls,
            "multi_control_events": [
                operation for operation, _ in multi_lower.control.observations
            ],
            "multi_refresh_ioctls": [
                fields.get("ioctl_id")
                for operation, fields in backend.events
                if operation == "ioctl"
            ],
            "multi_send_modes": initialization_modes,
            "samples": samples,
            "physical": "PHYSICAL_UNCONFIRMED",
        }


class DeferredVariableMultiMonTests(unittest.TestCase):
    def test_real_selected_support_factory_reaches_multi_and_reparsed_samples(self):
        for build in (12, 18):
            with self.subTest(build=build):
                result = run_selected_variable_multi(build=build)
                self.assertEqual(result["route"], "MultiMonitorPollingWorker")
                self.assertEqual(result["targets"], [42, 43])
                self.assertEqual(result["controller_flags"], 4)
                self.assertEqual(result["target_flags"], [4, 6])
                self.assertEqual(
                    result["connect_arguments"][-1],
                    {"protocol_id": 6, "flags": 0, "baud_rate": 0},
                )
                self.assertEqual(
                    [entry[0] for entry in result["multi_entry_calls"]], [42, 43]
                )
                self.assertGreaterEqual(
                    result["multi_control_events"].count("set_config"), 1
                )
                self.assertTrue(result["multi_send_modes"])
                self.assertTrue(all(mode == 2 for mode in result["multi_send_modes"]))
                self.assertEqual(len(result["samples"]), 2)
                self.assertEqual(
                    [sample[0]["values"][0]["display"] for sample in result["samples"]],
                    ["4176", "4176"],
                )

    def test_joined_factory_rejects_foreign_backend_and_keeps_null_outcome(self):
        foreign = run_selected_variable_multi(foreign_context=True)
        self.assertEqual(foreign["boundary"], "foreign-backend-rejected")
        self.assertTrue(foreign["support_channels_closed"])
        self.assertEqual(foreign["foreign_backend_calls"], [])
        changed_source = run_selected_variable_multi(source_changed=True)
        self.assertEqual(changed_source["boundary"], "changed-source-rejected")
        self.assertTrue(changed_source["support_channels_closed"])
        null_result = run_selected_variable_single(
            build=18, connected_device=8, null_controller=True
        )
        self.assertEqual(null_result["boundary"], "native-null-controller-no-event")
        self.assertEqual(null_result["code"], 0xE0000102)
        voltage = run_selected_variable_multi(with_voltage=True)
        self.assertEqual(voltage["boundary"], "mixed-voltage-source-failure")
        self.assertEqual(voltage["captures"], 0)

    def test_joined_factory_cancellation_closes_multi_channel(self):
        result = run_selected_variable_multi(build=18, cancel=True)
        self.assertEqual(result["boundary"], "cancelled")
        self.assertTrue(result["channels_closed"])

    def test_joined_factory_preserves_multi_host_exception_identity(self):
        result = run_selected_variable_multi(build=18, host_failure=True)
        self.assertEqual(result["boundary"], "host-exception")
        self.assertTrue(result["error_identity_preserved"])
        self.assertTrue(result["channels_closed"])

    def test_joined_factory_preserves_native_read_fault_and_closes_channel(self):
        for build in (12, 18):
            with self.subTest(build=build):
                result = run_selected_variable_multi(build=build, native_fault=True)
                self.assertEqual(result["boundary"], "native-read-fault")
                self.assertEqual(result["code"], 0xE0000108)
                self.assertEqual(result["primitive_read_code"], 7)
                self.assertEqual(result["error_type"], "MonitorError")
                self.assertFalse(result["host_exception_conversion"])
                self.assertTrue(result["channels_closed"])

    def test_joined_factory_retains_separately_owned_live_input_channel(self):
        result = run_selected_variable_multi(live_source_channel=True)
        self.assertEqual(result["boundary"], "live-source-channel-retained")
        self.assertTrue(result["channels_closed"])


if __name__ == "__main__":
    unittest.main()
