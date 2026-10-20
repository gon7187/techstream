"""Authored vectors for native mixed Phase5 mapping and command composition."""

import struct
import unittest
from dataclasses import replace
from types import SimpleNamespace
from typing import cast

from scripts.data_monitor import (
    DynamicOutcome,
    DynamicPlan,
    DynamicSource,
    MonitorError,
    P5DynamicSelection,
    P5MonitorEvent,
    P5Range,
    RoutineMonitor,
    p5_setup_commands,
)
from scripts.diagnostic_db import parse_database
from scripts.drive_recorder import NativeDmciCommand
from scripts.monitor_p5 import (
    P5ControllerError,
    mixed_p5_layouts,
    selected_p5_monitor_from_cache,
)
from scripts.monitor_support import MonitorSupportCache
from scripts.profiles import VehicleCatalog, VehicleProfile
from scripts.toyota import ToyotaCodecError
from scripts.toyota_session import Cancelled, SessionError


def authored_profile(build=18):
    def database(kind, sections):
        header = bytearray(36 + 4 * (max(sections) + 1))
        header[8:10] = bytes((kind, max(sections) + 1))
        header[10:28] = b"DiagTool DataCtrl\0"
        struct.pack_into("<I", header, 28, 0x0100030C if build == 12 else 0x0100032F)
        body = bytearray()
        for slot, (count, payload) in sorted(sections.items()):
            struct.pack_into("<I", header, 36 + slot * 4, len(header) + len(body))
            body += struct.pack("<BBII", slot, 0, count, len(payload)) + payload
        return parse_database(bytes(header + body))

    category = bytearray(76)
    struct.pack_into("<H", category, 68, 7)
    payloads = (
        bytes.fromhex("22ff00"),
        bytes.fromhex("2c030000"),
        bytes.fromhex("2c010000"),
        bytes.fromhex("220000"),
        bytes.fromhex("1902ff"),
        bytes.fromhex("31030000"),
        b"\x02",
        b"\x03",
        b"\x02\x03",
        b"\x02",
        b"\x03",
    )
    directory, blob = bytearray(), bytearray()
    for payload in payloads:
        directory += struct.pack("<IH", len(blob), len(payload))
        blob += payload
    functions = b"".join(
        sorted(
            (
                struct.pack("<8H", 7, key, 1, index, 0, index, 0, 0)
                for index, key in enumerate((0xC8, 0xD4, 0xD3, 0xCA, 0x19, 0xD7), 1)
            ),
            key=lambda row: struct.unpack_from("<H", row, 2)[0],
        )
    )
    settings = bytearray(16)
    struct.pack_into("<H", settings, 10, 1)
    management = database(
        1,
        {
            0: (11, directory + blob),
            17: (
                6,
                b"".join(
                    struct.pack("<4H", index, index, 0, 0) for index in range(1, 7)
                ),
            ),
            18: (6, functions),
            29: (1, settings),
        },
    )
    monitors = []
    for pid, did, flags, end in (
        (1, 1, 0, 7),
        (2, 2, 0, 7),
        (3, 0x777, 8, 15),
        (4, 0, 16, 0),
    ):
        row = bytearray(64)
        struct.pack_into("<I", row, 24, pid)
        struct.pack_into("<I", row, 32, flags)
        struct.pack_into("<H", row, 36, pid)
        struct.pack_into("<HHH", row, 42, 1, 0, end)
        struct.pack_into("<H", row, 54, did)
        monitors.append(bytes(row))
    phy = bytearray(24)
    struct.pack_into("<II", phy, 0, 1, 1)
    struct.pack_into("<H", phy, 12, 1)
    children = b"".join(
        struct.pack("<6H", 4, index, index, 0, 0, 0) for index in (1, 2)
    )
    routines, displays = [], []
    for index, key in enumerate((0x9C40, 0x9C41, 0x9C42)):
        row = bytearray(60 if build == 12 else 64)
        struct.pack_into("<II", row, 8, 200 + index, 1000 + index)
        struct.pack_into("<HH", row, 28, 0x500 + index, key)
        shift = 2 if build == 12 else 0
        struct.pack_into("<HH", row, 46 - shift, 100, 101)
        struct.pack_into("<H", row, 54 - shift, 300 + index)
        routines.append(bytes(row))
        display = bytearray(20)
        struct.pack_into("<IHH", display, 0, 400 + index, 300 + index, 1)
        struct.pack_into("<H", display, 10, 7 + index)
        displays.append(bytes(display))
    diagnostic = database(
        2,
        {
            13: (1, phy),
            14: (0, b""),
            15: (0, b""),
            19: (1, struct.pack("<4H", 3, 0x19, 0, 0)),
            26: (2, children),
            62: (4, b"".join(monitors)),
            71: (3, b"".join(routines)),
            72: (
                2,
                struct.pack("<6H", 100, 10, 0, 0, 0, 0)
                + struct.pack("<6H", 101, 11, 0, 0, 0, 0),
            ),
            73: (3, b"".join(displays)),
            81: (1, struct.pack("<4H", 0xF300, 1, 0, 0)),
        },
    )
    catalog = cast(
        VehicleCatalog,
        SimpleNamespace(
            management=management,
            language=SimpleNamespace(resolve=lambda key: str(key)),
        ),
    )
    return VehicleProfile(catalog, bytes(category), diagnostic)


def producer(
    cache, ids=(1, 2, 3, 4), dynamic=True, routines=(), observed=None, excluded=0
):
    return selected_p5_monitor_from_cache(
        cache,
        ids,
        {26: True, 73: True} if observed is None else observed,
        interface_id=7,
        excluded=excluded,
        standard_values=(),
        parameter_6=200,
        active_alias_pid=0,
        dynamic_requested=dynamic,
        max_request=64,
        max_reply=64,
        routine_ids=routines,
    )


def authored_exchange(calls, *, fail_validate=False):
    def exchange(query):
        calls.append(query.request)
        function = int.from_bytes(query.selected.function_record[2:4], "little")
        if function == 0xC8:
            if query.request == bytes.fromhex("22ff00"):
                upper = bytearray(32)
                upper[0], upper[30] = 0x80, 0x10
                return b"\x62\0\0" + upper
            return b"\x62\0\0\xc0"
        if function == 0xD4:
            return bytes.fromhex("6c03f300")
        if function == 0xD3:
            return bytes.fromhex("6c01f300")
        if fail_validate:
            raise ToyotaCodecError("authored CA failure", 0xA0040201)
        return bytes.fromhex("62f300a1")

    return exchange


class MixedP5Tests(unittest.TestCase):
    def test_optional_composite_child_preserves_native_default_slots(self):
        from scripts.diagnostic_db import Section

        profile = authored_profile()
        children = bytearray(profile.database.sections[26].payload)
        children[12 + 9] = 1
        profile = replace(
            profile,
            database=replace(
                profile.database,
                sections={
                    **profile.database.sections,
                    26: Section(26, 0, 2, False, bytes(children)),
                },
            ),
        )
        exchange = authored_exchange([])

        def optional_missing(query):
            if query.request == bytes.fromhex("220000"):
                return b"\x62\0\0\x80"
            return exchange(query)

        cache = MonitorSupportCache(profile, optional_missing, "ecu")
        result = producer(cache, ids=(4,))
        self.assertEqual(result.pickup_spans, ((0, 8), (-1, 8)))
        self.assertEqual([signal.pid for signal in result.signals], [4, 0, 0])
        self.assertEqual(result.default_signal_slots, (1, 2))
        self.assertEqual(result.frame_sizes, ((0, 1), (1, 2)))

    def test_real_normal_router_consumes_mixed_producer(self):
        from scripts.data_monitor import selected_normal_monitor_from_cache
        from scripts.monitor_p5 import SelectedP5Monitor

        for build in (12, 18):
            profile = authored_profile(build)
            category = bytearray(profile.category_record)
            category[72] = 20
            cache = MonitorSupportCache(
                replace(profile, category_record=bytes(category)),
                authored_exchange([]),
                "ecu",
                source_build=build,
            )
            result = selected_normal_monitor_from_cache(
                cache,
                (1, 2, 3, 4),
                {26: True, 73: True},
                communication_protocol=0x12,
                attribute_3_31=None,
                interface_id=7,
                excluded=0,
                standard_values=(),
                max_request=64,
                max_reply=64,
                parameter_6=200,
                active_alias_pid=0,
                dynamic_requested=True,
                routine_ids=(0x9C42,),
            )
            self.assertIsInstance(result, SelectedP5Monitor)
            assert isinstance(result, SelectedP5Monitor)
            self.assertEqual(result.dtc_requests, (bytes.fromhex("190208"),))
            self.assertEqual(len(result.routines), 2)
            self.assertEqual(
                result.frame_sizes, ((0, 1), (1, 1), (2, 2), (3, 2), (4, 2))
            )
            self.assertTrue(result.definitions.source_identity)

    def test_dtc_source_collision_uses_first_normal_did_frame(self):
        from scripts.diagnostic_db import Section

        profile = authored_profile()
        rows = bytearray(profile.database.sections[62].payload)
        struct.pack_into("<H", rows, 46, 15)
        struct.pack_into("<H", rows, 128 + 54, 1)
        extra = bytearray(rows[128:192])
        struct.pack_into("<H", extra, 36, 5)
        diagnostic = replace(
            profile.database,
            sections={
                **profile.database.sections,
                62: Section(62, 0, 5, False, bytes(rows + extra)),
                19: Section(
                    19,
                    0,
                    2,
                    False,
                    profile.database.sections[19].payload
                    + struct.pack("<4H", 5, 0x19, 0, 2),
                ),
            },
        )
        cache = MonitorSupportCache(
            replace(profile, database=diagnostic), authored_exchange([]), "ecu"
        )
        result = producer(cache, ids=(1, 2, 3, 5), dynamic=False)
        self.assertEqual(result.frame_sizes, ((0, 2), (1, 1), (2, 2)))
        self.assertEqual(
            [
                (item.pid, item.frame_index, item.start_bit, item.end_bit)
                for item in result.signals
            ],
            [(1, 0, 0, 15), (2, 1, 0, 7), (3, 0, 0, 15), (5, 0, 0, 15)],
        )
        self.assertEqual(result.dtc_patterns, (2,))

    def test_dtc_join_validates_all_selected_frame_variables_without_settings(self):
        from scripts.diagnostic_db import Section
        from scripts.monitor_p5 import _dtc_request

        for build in (12, 18):
            profile = authored_profile(build)
            original = profile.catalog.management
            profile.catalog.management = replace(
                original,
                sections={
                    slot: section
                    for slot, section in original.sections.items()
                    if slot != 29
                },
            )
            self.assertEqual(_dtc_request(profile, 3), (bytes.fromhex("190208"), 0))
            frames = original.sections[17].payload
            invalid_later = frames[:40] + struct.pack("<4H", 5, 5, 12, 0) + frames[40:]
            profile.catalog.management = replace(
                original,
                sections={
                    **original.sections,
                    17: Section(17, 0, 7, False, invalid_later),
                },
            )
            with self.assertRaises(ToyotaCodecError) as caught:
                _dtc_request(profile, 3)
            self.assertEqual(caught.exception.code, 0xA0030102)

    def test_complete_direct_excluded_and_unavailable_mode_branches(self):
        for build in (12, 18):
            for excluded, dynamic, expected_mode in (
                (0, True, 4),
                (4, True, 0x20),
                (0, False, 0x20),
            ):
                calls = []
                cache = MonitorSupportCache(
                    authored_profile(build),
                    authored_exchange(calls),
                    "ecu",
                    source_build=build,
                )
                result = producer(cache, ids=(1,), dynamic=dynamic, excluded=excluded)
                self.assertEqual(result.mode, expected_mode)
                self.assertEqual(
                    result.packing.data_ids, ((0xF300 if expected_mode == 4 else 1, 1),)
                )
                self.assertEqual(
                    any(request.startswith(b"\x2c") for request in calls),
                    expected_mode == 4,
                )
            calls = []
            cache = MonitorSupportCache(
                authored_profile(build),
                authored_exchange(calls),
                "ecu",
                source_build=build,
            )
            with self.assertRaises(P5ControllerError) as caught:
                producer(cache, ids=(1, 2), observed={26: True, 73: False})
            self.assertEqual(caught.exception.code, 0x9005100A)
            self.assertEqual(caught.exception.outcome.plan.read_ids, (0xF300,))
            self.assertEqual(calls[-1], bytes.fromhex("22f300"))
            calls = []
            cache = MonitorSupportCache(
                authored_profile(build),
                authored_exchange(calls),
                "ecu",
                source_build=build,
            )
            with self.assertRaises(MonitorError) as caught:
                producer(cache, ids=(1,), observed={26: False, 73: False})
            self.assertEqual(caught.exception.code, 0x90051007)
            self.assertTrue(calls)
            self.assertFalse(any(request.startswith(b"\x2c") for request in calls))

    def test_all_ineligible_dynamic_rows_use_direct_without_disable(self):
        from scripts.diagnostic_db import Section

        for build in (12, 18):
            profile = authored_profile(build)
            rows = bytearray(profile.database.sections[62].payload)
            struct.pack_into("<HH", rows, 44, 2040, 2047)
            diagnostic = replace(
                profile.database,
                sections={
                    **profile.database.sections,
                    62: Section(62, 0, 4, False, bytes(rows)),
                },
            )
            calls = []
            cache = MonitorSupportCache(
                replace(profile, database=diagnostic),
                authored_exchange(calls),
                "ecu",
                source_build=build,
            )
            result = producer(cache, ids=(1,))
            assert result.packing.outcome is not None
            self.assertEqual(result.packing.outcome.status, 0xA0050422)
            self.assertFalse(result.packing.outcome.disable_packet_ecu)
            self.assertEqual(result.packing.data_ids, ((1, 256),))
            self.assertEqual(calls[-1], bytes.fromhex("2c03f300"))
            self.assertFalse(any(request.startswith(b"\x2c\x01") for request in calls))

    def test_rid_work_and_payload_budgets_fail_closed(self):
        from unittest.mock import patch

        from scripts.monitor_p5 import p5_routine_signal_metadata

        calls = []
        profile = authored_profile()
        cache = MonitorSupportCache(profile, authored_exchange(calls), "ecu")
        with (
            patch("scripts.monitor_p5.MAX_DYNAMIC_COMPARISONS", 1),
            self.assertRaisesRegex(MonitorError, "work budget"),
        ):
            producer(cache, routines=(0x9C40,))
        self.assertEqual(calls, [])
        with (
            patch("scripts.monitor_p5.MAX_BYTES", 1),
            self.assertRaisesRegex(MonitorError, "byte budget"),
        ):
            p5_routine_signal_metadata(profile, 0x9C40, 1, 1, source_build=18)

    def test_dtc_only_native_empty_did_error_keeps_clear_chronology(self):
        for build in (12, 18):
            for dynamic in (True, False):
                calls = []
                cache = MonitorSupportCache(
                    authored_profile(build),
                    authored_exchange(calls),
                    "ecu",
                    source_build=build,
                )
                with self.assertRaises(MonitorError) as caught:
                    producer(cache, ids=(3,), dynamic=dynamic)
                self.assertEqual(
                    caught.exception.code, 0x90051019 if dynamic else 0x90051010
                )
                if dynamic:
                    self.assertEqual(calls[-1], bytes.fromhex("2c03f300"))
                else:
                    self.assertFalse(
                        any(request.startswith(b"\x2c") for request in calls)
                    )

    def test_last_dtc_descriptor_wins_and_different_source_fails_mapping(self):
        from scripts.diagnostic_db import Section

        for source in (0x777, 0x888):
            profile = authored_profile()
            row = bytearray(profile.database.sections[62].payload[128:192])
            struct.pack_into("<H", row, 36, 5)
            struct.pack_into("<H", row, 54, source)
            diagnostic = replace(
                profile.database,
                sections={
                    **profile.database.sections,
                    62: Section(
                        62, 0, 5, False, profile.database.sections[62].payload + row
                    ),
                    19: Section(
                        19,
                        0,
                        2,
                        False,
                        profile.database.sections[19].payload
                        + struct.pack("<4H", 5, 0x19, 0, 2),
                    ),
                },
            )
            cache = MonitorSupportCache(
                replace(profile, database=diagnostic), authored_exchange([]), "ecu"
            )
            with self.assertRaises(MonitorError) as caught:
                producer(cache, ids=(1, 2, 3, 5))
            self.assertEqual(
                caught.exception.code, 0x90051004 if source == 0x888 else 0x90051018
            )
            result = producer(cache, ids=(1, 2, 5))
            self.assertEqual(result.dtc_patterns, (2,))
            self.assertEqual([signal.pid for signal in result.signals], [1, 2, 5])
            self.assertEqual(len(result.dtc_requests), 1)

    def test_mixed_runtime_read_fault_still_stops(self):
        from scripts.data_monitor import run_monitor_commands
        from scripts.drive_recorder import (
            NativeVimClient,
            NativeVimReply,
            decode_vim_command,
        )

        cache = MonitorSupportCache(authored_profile(), authored_exchange([]), "ecu")
        selected = producer(cache, routines=(0x9C42,))
        calls = []

        def exchange(request, *, deadline, cancelled):
            command, _ = decode_vim_command(request)
            calls.append(command)
            if command == 0x197F:
                raise OSError("authored monitor read failed")
            return NativeVimReply(command | 0x80, 6, bytes(4)).encode()

        client = NativeVimClient(
            exchange, capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"})
        )
        with self.assertRaisesRegex(OSError, "authored monitor read failed"):
            run_monitor_commands(
                selected.commands,
                client,
                interface_id=7,
                frame_sizes=selected.frame_sizes,
                phase=0,
                packet_limit=1,
            )
        self.assertEqual(calls[-1], 0x1A7F)

    def test_unsafe_pair_parent_width_rejected(self):
        from scripts.diagnostic_db import Section

        profile = authored_profile()
        displays = bytearray(profile.database.sections[73].payload)
        struct.pack_into("<H", displays, 40 + 10, 7)
        diagnostic = replace(
            profile.database,
            sections={
                **profile.database.sections,
                73: Section(73, 0, 3, False, bytes(displays)),
            },
        )
        cache = MonitorSupportCache(
            replace(profile, database=diagnostic), authored_exchange([]), "ecu"
        )
        with self.assertRaisesRegex(MonitorError, "Unsafe native RID"):
            producer(cache, routines=(0x9C42,))

    def test_nonzero_dtc_pattern_survives_selected_ddb_wire_and_native_error(self):
        from scripts.diagnostic_db import Section

        profile = authored_profile()
        retrieval = bytearray(profile.database.sections[19].payload)
        retrieval[6] = 3
        diagnostic = replace(
            profile.database,
            sections={
                **profile.database.sections,
                19: Section(19, 0, 1, False, bytes(retrieval)),
            },
        )
        cache = MonitorSupportCache(
            replace(profile, database=diagnostic), authored_exchange([]), "ecu"
        )
        result = producer(cache)
        self.assertEqual(result.dtc_patterns, (3,))
        command = next(
            command for command in result.commands.setup if command.command_id == 0x10B
        )
        self.assertEqual(command.values[2], 3)
        NativeDmciCommand.from_neutral(command.command_id, command.values)
        event = P5MonitorEvent(
            (),
            result.dtc_requests,
            (),
            routine_info=False,
            dtc_patterns=result.dtc_patterns,
        )
        with self.assertRaises(MonitorError) as caught:
            event.accept(bytes.fromhex("59020811223344"), 1)
        self.assertEqual(caught.exception.code, 0xE0000102)
        self.assertEqual(event.index, 0)

    def test_registration_cancel_keeps_actual_prefix_without_rollback(self):
        calls, cancelled = [], [False]
        exchange = authored_exchange(calls)

        def cancel_on_define(query):
            result = exchange(query)
            if query.request.startswith(b"\x2c\x01"):
                cancelled[0] = True
            return result

        cache = MonitorSupportCache(
            authored_profile(), cancel_on_define, "ecu", cancelled=lambda: cancelled[0]
        )
        with self.assertRaises(Cancelled):
            producer(cache)
        self.assertTrue(calls[-1].startswith(b"\x2c\x01"))
        self.assertEqual(sum(request.startswith(b"\x2c\x03") for request in calls), 1)
        self.assertNotIn(bytes.fromhex("22f300"), calls)

    def test_failed_clear_disables_packet_and_falls_back(self):
        for build in (12, 18):
            calls = []
            exchange = authored_exchange(calls)

            def fail_clear(query, calls=calls, exchange=exchange):
                if query.request.startswith(b"\x2c\x03"):
                    calls.append(query.request)
                    raise ToyotaCodecError("authored failed clear", 0xA0040201)
                return exchange(query)

            cache = MonitorSupportCache(
                authored_profile(build), fail_clear, "ecu", source_build=build
            )
            result = producer(cache)
            assert result.packing.outcome is not None
            self.assertTrue(result.packing.outcome.disable_packet_ecu)
            self.assertEqual(result.packing.data_ids, ((1, 1), (2, 1)))
            self.assertEqual(calls[-1], bytes.fromhex("2c03f300"))

    def test_actual_rid_and_paired_status_metadata_both_builds(self):
        for build in (12, 18):
            for key, count, size in ((0x9C40, 1, 1), (0x9C42, 2, 2)):
                with self.subTest(build=build, key=key):
                    calls = []
                    cache = MonitorSupportCache(
                        authored_profile(build),
                        authored_exchange(calls),
                        "ecu",
                        source_build=build,
                    )
                    result = producer(cache, routines=(key,))
                    self.assertEqual(len(result.routines), count)
                    self.assertEqual(result.frame_sizes[-2:], ((3, size), (4, 2)))
                    self.assertEqual(
                        [item.pid for item in result.signals], [1, 4, 3, 0x2134, 0]
                    )
                    self.assertEqual(result.default_signal_slots, (4,))
                    signal = result.signals[3]
                    self.assertEqual(
                        (signal.pid, signal.frame_index, signal.end_bit),
                        (0x2134, 3, size * 8 - 1),
                    )
                    self.assertEqual(
                        (
                            signal.name,
                            signal.selector,
                            signal.multiplier,
                            signal.divisor,
                        ),
                        (str(200 + key - 0x9C40), 1, 1, 1),
                    )
                    if count == 2:
                        self.assertEqual(
                            [r.request.hex() for r in result.routines],
                            ["31030500", "31030501"],
                        )
                        self.assertEqual(result.routines[0].stop, (3,))
                        self.assertEqual(result.routines[0].normal, ())
                        self.assertEqual(signal.minimum_raw, 0x0203)
                    else:
                        self.assertEqual(result.routines[0].normal, (2,))
                    for command in result.commands.setup:
                        NativeDmciCommand.from_neutral(
                            command.command_id, command.values
                        )

    def test_selected_pair_packet_native_wire_capture_and_playback(self):
        from scripts.data_monitor import run_monitor_commands
        from scripts.drive_recorder import (
            NativeCoreBuffer,
            NativeDmciList,
            NativeMonitorPacket,
            NativeMonitorReply,
            NativeRecorderCapture,
            NativeVimClient,
            NativeVimReply,
            decode_vim_command,
            native_monitor_buffer,
        )
        from scripts.snapshot import (
            MonitorBuffer,
            decode_signal_item,
            decode_signal_table,
            monitor_packets,
        )

        cache = MonitorSupportCache(authored_profile(), authored_exchange([]), "ecu")
        selected = producer(cache, routines=(0x9C42,))
        event = P5MonitorEvent(
            selected.packing.data_ids,
            selected.dtc_requests,
            selected.routines,
            routine_info=False,
            dtc_patterns=selected.dtc_patterns,
        )
        event.pickup_spans = selected.pickup_spans
        replies = ("62f300a1", "620002b2", "59020811223344", "7103050002", "7103050103")
        packet = None
        for tick, reply in enumerate(replies, 1):
            packet = event.accept(bytes.fromhex(reply), tick)
        self.assertEqual(packet, (5, bytes.fromhex("a1b200010203a1b2")))
        assert packet is not None
        calls = []

        def exchange(request, *, deadline, cancelled):
            command, _ = decode_vim_command(request)
            calls.append(command)
            if command == 0x197F:
                empty = NativeCoreBuffer((1, 0), b"")
                payload = NativeMonitorReply(
                    0,
                    NativeDmciList(
                        (1, 0),
                        (
                            (
                                7,
                                NativeCoreBuffer(
                                    (1, 0), struct.pack("<I", packet[0]) + packet[1]
                                ),
                            ),
                        ),
                    ),
                    (empty, empty, empty, empty, empty),
                    0,
                ).encode()
            else:
                payload = bytes(4)
            return NativeVimReply(command | 0x80, 6, payload).encode()

        client = NativeVimClient(
            exchange, capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"})
        )
        actual = run_monitor_commands(
            selected.commands,
            client,
            interface_id=7,
            frame_sizes=selected.frame_sizes,
            phase=0,
            packet_limit=1,
        )
        self.assertEqual((actual[0].timestamp_raw, actual[0].payload), packet)
        self.assertEqual(calls[-3:], [0x187F, 0x197F, 0x1A7F])
        settings = native_monitor_buffer(
            7,
            selected.signals,
            selected.frame_sizes,
            (1, 2, 3, 4, 0x2134),
            phase=0,
            allocation_size=4096,
            name=b"authored",
            text_encoding="utf-8",
            default_signal_slots=selected.default_signal_slots,
            unassigned_short_name_slots=tuple(range(len(selected.signals))),
        )
        capture = NativeRecorderCapture(5, (NativeMonitorPacket(*packet),))
        metadata = MonitorBuffer(
            b"authored",
            bytes(16),
            b"mixed",
            b"",
            b"",
            b"",
            0,
            (),
            (1, 2, 3, 4, 0x2134),
            b"",
            (),
        )
        saved = capture.monitor_buffer(settings, metadata, phase=0, block_packets=1)
        playback = monitor_packets(saved)
        self.assertEqual(playback[0]["timestamp_raw"], 5)
        self.assertEqual(
            b"".join(
                bytes.fromhex(frame["data_hex"]) for frame in playback[0]["frames"]
            ),
            packet[1],
        )
        signal = decode_signal_item(
            bytes.fromhex(decode_signal_table(saved.signal_table)["items_hex"][3])
        )
        self.assertEqual(
            (signal.pid, signal.frame_index, signal.end_bit), (0x2134, 3, 15)
        )
        self.assertEqual(signal.short_name, b"")
        slots = tuple(
            decode_signal_item(bytes.fromhex(raw))
            for raw in decode_signal_table(saved.signal_table)["items_hex"]
        )
        self.assertEqual(len(slots), 5)
        self.assertEqual([slot.pid for slot in slots], [1, 4, 3, 0x2134, 0])
        self.assertTrue(all(slot.short_name == b"" for slot in slots))
        empty = slots[4]
        self.assertEqual((empty.name, empty.short_name, empty.unit), (b"", b"", b""))
        self.assertEqual(
            (
                empty.multiplier,
                empty.divisor,
                empty.minimum_raw,
                empty.maximum_raw,
                empty.extended,
            ),
            (1, 1, 1, 0, (0, 1, 0)),
        )

    def test_actual_ddb_mixed_producer_both_source_builds(self):
        for build in (12, 18):
            with self.subTest(build=build):
                profile = authored_profile(build)
                calls = []
                cache = MonitorSupportCache(
                    profile, authored_exchange(calls), "ecu", source_build=build
                )
                result = producer(cache)
                self.assertEqual(result.mode, 0x20)
                self.assertEqual(result.packing.data_ids, ((0xF300, 1), (2, 1)))
                self.assertEqual(result.frame_sizes, ((0, 1), (1, 1), (2, 2), (3, 2)))
                self.assertEqual(result.dtc_requests, (bytes.fromhex("190208"),))
                self.assertEqual(result.pickup_spans, ((0, 8), (8, 8)))
                self.assertEqual([item.pid for item in result.signals], [4, 2, 3, 0])
                self.assertEqual(result.default_signal_slots, (3,))
                empty = result.signals[3]
                self.assertEqual(
                    (
                        empty.selector,
                        empty.minimum_raw,
                        empty.maximum_raw,
                        empty.extended,
                    ),
                    (0, 1, 0, (0, 1, 0)),
                )
                self.assertEqual(
                    [command.command_id for command in result.commands.setup],
                    [0x119, 0x10B, 0x11A, 0x112],
                )
                self.assertEqual(result.commands.setup[2].values, (7, b"\0\xf3"))
                self.assertEqual(
                    calls[-3:],
                    [
                        bytes.fromhex("2c03f300"),
                        bytes.fromhex("2c01f30000010101"),
                        bytes.fromhex("22f300"),
                    ],
                )
                self.assertEqual(
                    result.definitions.source_sha256, profile.database.sha256
                )

    def test_actual_validation_failure_falls_back_to_original_dids(self):
        calls = []
        cache = MonitorSupportCache(
            authored_profile(), authored_exchange(calls, fail_validate=True), "ecu"
        )
        result = producer(cache)
        self.assertEqual(result.packing.data_ids, ((1, 1), (2, 1)))
        assert result.packing.outcome is not None
        self.assertEqual(result.packing.outcome.status, 0xA0050422)
        self.assertEqual(sum(request.startswith(b"\x2c\x03") for request in calls), 1)

    def test_cancelled_and_mutated_source_fail_before_exchange(self):
        calls = []
        profile = authored_profile()
        cache = MonitorSupportCache(profile, authored_exchange(calls), "ecu")
        cache.cancelled = lambda: True
        with self.assertRaises(Cancelled):
            producer(cache)
        self.assertEqual(calls, [])
        cache.cancelled = lambda: False
        cache.profile = replace(profile, exception_ids=(5,))
        with self.assertRaises(SessionError):
            producer(cache)
        self.assertEqual(calls, [])

    def setUp(self):
        self.a = DynamicSource(0x100, ((2, 2),))
        self.b = DynamicSource(0x101, ((1, 1),))
        self.ranges = (
            P5Range(8, 23, 1, 0x100, 0, 0, 0),
            P5Range(0, 7, 2, 0x101, 0, 0, 0),
            P5Range(2040, 2047, 3, 0x102, 0, 0, 0),
            P5Range(0, 7, 4, 0x103, 0, 0, 1, 1),
        )
        self.selection = P5DynamicSelection(
            (self.a, self.b),
            (0x102,),
            ((0x100, 3), (0x101, 1), (0x102, 256)),
            self.ranges,
        )

    def test_partial_dynamic_then_direct_and_ineligible_keep_native_order(self):
        plan = DynamicPlan((b"definition",), (0xF300,), (2,), ((self.a,),), (self.b,))
        outcome = DynamicOutcome(0x9005100A, plan, (), (), None, False)
        result = mixed_p5_layouts(self.selection, outcome)
        self.assertEqual(result.data_ids, ((0xF300, 2), (0x101, 1), (0x102, 256)))
        self.assertEqual(result.frame_sizes, ((0, 2), (1, 1), (2, 256)))
        self.assertEqual(
            result.layouts, ((1, 0, 0, 15), (2, 1, 0, 7), (3, 2, 2040, 2047))
        )
        self.assertIs(result.outcome, outcome)

    def test_failed_validation_drops_mapping_without_rollback(self):
        outcome = DynamicOutcome(
            0xA0050422,
            DynamicPlan((), (), (), (), (self.a, self.b)),
            (),
            (),
            (0xF300, 7),
            False,
        )
        result = mixed_p5_layouts(self.selection, outcome)
        self.assertEqual(result.data_ids, self.selection.full_lengths)
        self.assertEqual(
            result.layouts, ((1, 0, 8, 23), (2, 1, 0, 7), (3, 2, 2040, 2047))
        )
        assert result.outcome is not None
        self.assertFalse(result.outcome.disable_packet_ecu)

    def test_complete_dynamic_cross_source_offsets(self):
        selection = replace(
            self.selection,
            ineligible_dids=(),
            full_lengths=((0x100, 3), (0x101, 1)),
            ranges=self.ranges[:2],
        )
        plan = DynamicPlan((b"definition",), (0xF301,), (3,), ((self.b, self.a),), ())
        result = mixed_p5_layouts(
            selection, DynamicOutcome(0, plan, (), (), None, False)
        )
        self.assertEqual(result.layouts, ((1, 0, 8, 23), (2, 0, 0, 7)))
        self.assertEqual(result.data_ids, ((0xF301, 3),))

    def test_invented_or_duplicate_dynamic_source_fails(self):
        for sources in (((self.a, self.a),), ((DynamicSource(5, ((1, 1),)),),)):
            plan = DynamicPlan(
                (b"definition",),
                (0xF300,),
                (sum(s.length for s in sources[0]),),
                sources,
                (),
            )
            with self.subTest(sources=sources), self.assertRaises(MonitorError):
                mixed_p5_layouts(
                    self.selection, DynamicOutcome(0, plan, (), (), None, False)
                )

    def test_mixed_typed_commands_and_literal_packet(self):
        routine = RoutineMonitor(bytes.fromhex("31031234"), 1, (2,), (3,), ())
        setup = p5_setup_commands(
            interface_id=7,
            buffer_468=9,
            total_length=5,
            standard_values=((4, 5),),
            data_ids=((0x100, 2),),
            dtc_requests=(bytes.fromhex("190208"),),
            routines=(routine,),
            parameter_6=200,
        )
        self.assertEqual([c.command_id for c in setup.setup], [0x119, 0x10B, 0x11C])
        self.assertEqual(setup.setup[1].values[4:], (0, ()))
        self.assertEqual(setup.setup[2].values[6:8], (0, ()))
        for command in setup.setup + setup.start + setup.stop:
            NativeDmciCommand.from_neutral(command.command_id, command.values)
        event = P5MonitorEvent(
            ((0x100, 2),), (bytes.fromhex("190208"),), (routine,), routine_info=False
        )
        self.assertEqual(event.request, bytes.fromhex("220100"))
        self.assertIsNone(event.accept(bytes.fromhex("620100abcd"), 1))
        self.assertEqual(event.request, bytes.fromhex("190208"))
        self.assertIsNone(event.accept(bytes.fromhex("59020811223344"), 2))
        self.assertEqual(
            event.accept(bytes.fromhex("7103123402"), 3),
            (3, bytes.fromhex("abcd000102")),
        )
        self.assertTrue(
            routine.check_status(bytes.fromhex("7103123402"), routine_info=False)
        )
        self.assertFalse(
            routine.check_status(
                bytes.fromhex("7103123402"), routine_info=False, abnormal=True
            )
        )

    def test_short_dtc_reply_native_zero_and_bad_service_does_not_advance(self):
        event = P5MonitorEvent((), (bytes.fromhex("190208"),), (), routine_info=False)
        with self.assertRaises(MonitorError):
            event.accept(b"\x58", 1)
        self.assertEqual(event.index, 0)
        self.assertEqual(event.accept(b"\x59", 2), (2, b"\0\0"))
        self.assertEqual(event.accept(b"\x59\x01", 3), (3, b"\0\0"))


if __name__ == "__main__":
    unittest.main()
