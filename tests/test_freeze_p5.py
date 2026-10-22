"""Authored selected-DDB vectors for Common P5 FFD association."""

import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Literal, cast

from scripts.diagnostic_db import parse_database
from scripts.freeze_p5 import (
    P5DataIdObservation,
    P5FreezeState,
    P5SnapshotRequest,
    P5Value,
)
from scripts.monitor_support import MonitorSupportCache
from scripts.profiles import VehicleCatalog, VehicleProfile
from scripts.toyota import ToyotaCodecError
from scripts.toyota_session import Cancelled, Limits, NativeStatus, SessionError


def database(build, kind, sections):
    header = bytearray(36 + 4 * (max(sections) + 1))
    header[8:10] = bytes((kind, max(sections) + 1))
    header[10:28] = b"DiagTool DataCtrl\0"
    struct.pack_into("<I", header, 28, 0x0100030C if build == 12 else 0x0100032F)
    body = bytearray()
    for slot, (count, payload) in sorted(sections.items()):
        struct.pack_into("<I", header, 36 + slot * 4, len(header) + len(body))
        body += struct.pack("<BBII", slot, 0, count, len(payload)) + payload
    return parse_database(bytes(header + body))


def profile(
    build=18,
    *,
    mode=0,
    second=True,
    unit=True,
    pattern=False,
    signals=None,
    count=None,
    category_id=7,
    ffd_mode=None,
    ffd_variable=b"\x12\x34",
    bit_base=0,
    frame_function=0xCF,
    frame_request=None,
):
    category = bytearray(76)
    struct.pack_into("<H", category, 68, category_id)
    physical = bytearray(24)
    struct.pack_into("<IIIHH", physical, 0, 2, 1, 3, 1, 1)
    unit_row = struct.pack("<I4H", 20, 1, 9, 0, 0)
    monitors = []
    for pid in range(1, (count + 1) if count is not None else 3 if second else 2):
        row = bytearray(64)
        struct.pack_into("<IIII", row, 4, 0, 255, 50, 60)
        struct.pack_into("<I", row, 24, 100 + pid)
        struct.pack_into("<I", row, 32, 2)
        struct.pack_into("<H", row, 36, pid)
        if ffd_mode is not None:
            struct.pack_into("<H", row, 40, 3)
        struct.pack_into(
            "<3H", row, 42, 1, bit_base + (pid - 1) * 8, bit_base + pid * 8 - 1
        )
        struct.pack_into("<H", row, 56, 0x1234)
        row[58] = 2
        if pattern:
            struct.pack_into("<H", row, 50, 3)
        monitors.append(bytes(row))
    did = bytearray(8)
    struct.pack_into("<H", did, 2, 0x1234)
    did[4], did[6] = count or 2, mode
    pat = bytearray(20 if build == 12 else 24)
    struct.pack_into("<I", pat, 0, 200)
    if build == 12:
        struct.pack_into("<H", pat, 4, 3)
        struct.pack_into("<HH", pat, 10, 4, 5)
    else:
        struct.pack_into("<IIH", pat, 4, 4, 5, 3)
    signal_groups, signal_checks = bytearray(), bytearray()
    for signal, pids in sorted((signals or {}).items()):
        group = bytearray(12)
        struct.pack_into("<H", group, 4, signal)
        group[8] = signal
        signal_groups += group
        for pid in pids:
            signal_checks += struct.pack("<4H", signal, pid, 0, 0)
    sections = {
        0: (len(signals or {}), signal_groups),
        1: (len(signal_checks) // 8, signal_checks),
        13: (1, physical),
        14: (int(pattern), bytes(pat) if pattern else b""),
        15: (int(unit), unit_row if unit else b""),
        61: (1, did),
        62: (len(monitors), b"".join(monitors)),
        65: (0, b""),
    }
    if ffd_mode is not None:
        bits = bytearray(struct.pack("<6H", 3, 2, 0, 0, 0, 0))
        bits[11] = ffd_mode
        sections[80] = (1, bits)
    diagnostic = database(
        build,
        2,
        sections,
    )
    settings = bytearray(16)
    struct.pack_into("<H", settings, 10, 1)
    request = bytes.fromhex("190400000001") if frame_request is None else frame_request
    directory = struct.pack("<IH", 0, len(request))
    variable_blob = request
    if ffd_mode is not None:
        directory += struct.pack("<IH", len(request), len(ffd_variable))
        variable_blob += ffd_variable
    management = database(
        build,
        1,
        {
            0: (1 + int(ffd_mode is not None), directory + variable_blob),
            17: (1, struct.pack("<4H", 1, 1, 0, 0)),
            18: (1, struct.pack("<8H", 7, frame_function, 1, 1, 0, 1, 0, 0)),
            29: (1, settings),
        },
    )
    catalog = cast(
        VehicleCatalog,
        SimpleNamespace(
            management=management,
            language=SimpleNamespace(resolve=lambda key: f"label{key}"),
        ),
    )
    return VehicleProfile(catalog, bytes(category), diagnostic)


def state(build: Literal[12, 18] = 18, **kwargs):
    selected = profile(build, **kwargs)

    def exchange(query):
        raise AssertionError(f"Unexpected primitive query {query}")

    cache = MonitorSupportCache(selected, exchange, "authored", source_build=build)
    return P5FreezeState(selected, source_build=build, cache=cache)


class FreezeP5Tests(unittest.TestCase):
    def test_stored_native_first_frame_and_concrete_association(self):
        selected = profile(
            count=3,
            signals={0x4D: (1,), 0x4E: (2,), 0x4F: (3,)},
            frame_function=0x113,
            frame_request=bytes.fromhex("1903ff"),
        )
        calls = []

        def exchange(query):
            calls.append(query.request)
            return bytes.fromhex("590301123456000112340a0302")

        cache = MonitorSupportCache(selected, exchange, "authored")
        actual = P5FreezeState(selected, source_build=18, cache=cache, subaru=True)
        self.assertTrue(actual.comm_execute_stored())
        self.assertEqual(
            (calls, actual.stored_numbers), ([bytes.fromhex("1903ff")], [255])
        )
        actual.analyze_stored_received()
        diagnostic = actual.diagnostic(0x123456)
        assert diagnostic is not None
        self.assertTrue(diagnostic.stored_all)
        self.assertEqual(
            (diagnostic.existence_flags, diagnostic.extended_numbers), (1, [1])
        )
        self.assertEqual(
            [signal.values[0].value for signal in diagnostic.signals], [10, 3, 2]
        )
        self.assertEqual(
            [signal.values[0].kind for signal in diagnostic.signals], [1, 1, 1]
        )

    def test_stored_fallback_tolerated_and_short_receive_keep_success_state(self):
        for initial in (NativeStatus(0x91010009), b"\x59\x03"):
            selected = profile(
                frame_function=0x113, frame_request=bytes.fromhex("1903ff")
            )
            replies = iter((initial, b"\x59\x03\x01\x00", NativeStatus(0xA0040202)))
            calls = []

            def exchange(query, calls=calls, replies=replies):
                calls.append(query.request)
                reply = next(replies)
                if isinstance(reply, Exception):
                    raise reply
                return reply

            cache = MonitorSupportCache(selected, exchange, "authored")
            actual = P5FreezeState(selected, source_build=18, cache=cache, subaru=True)
            self.assertTrue(actual.comm_execute_stored())
            self.assertEqual(
                calls,
                [bytes.fromhex(value) for value in ("1903ff", "190301", "190302")],
            )
            self.assertEqual(
                (actual.snapshot_frames, actual.stored_numbers),
                ([b"\x59\x03\x01\x00"], [1]),
            )
            actual.init_freeze_data()
            self.assertEqual(actual.snapshot_frames, [])
            self.assertEqual(actual.stored_numbers, [1])
            self.assertTrue(actual.snapshot_success)

    def test_stored_fallback_stops_at254_and_cancel_before_io(self):
        selected = profile(frame_function=0x113, frame_request=bytes.fromhex("1903ff"))
        calls = []

        def exchange(query):
            calls.append(query.request)
            if len(calls) == 1:
                raise NativeStatus(0x91010009)
            return b"\x59\x03\x01\x00"

        cache = MonitorSupportCache(
            selected, exchange, "authored", limits=Limits(exchanges=300)
        )
        actual = P5FreezeState(selected, source_build=18, cache=cache, subaru=True)
        actual.comm_execute_stored()
        self.assertEqual(
            (len(calls), actual.stored_numbers), (255, list(range(1, 255)))
        )
        actual.native_cancel_value = 1
        with self.assertRaises(ToyotaCodecError) as failure:
            actual.comm_execute_stored()
        self.assertEqual(failure.exception.code, 0xA0040003)
        self.assertEqual(len(calls), 255)

    def test_stored_stage_fault_does_not_publish_partial_diagnostics(self):
        selected = profile(
            count=3,
            unit=False,
            signals={0x4D: (1,), 0x4E: (2,), 0x4F: (3,)},
            frame_function=0x113,
            frame_request=bytes.fromhex("1903ff"),
        )
        cache = MonitorSupportCache(
            selected,
            lambda query: bytes.fromhex("590301123456000112340a0302"),
            "authored",
        )
        actual = P5FreezeState(selected, source_build=18, cache=cache, subaru=True)
        existing = actual.add_diagnostic(7)
        actual.comm_execute_stored()
        with self.assertRaises(ToyotaCodecError):
            actual.analyze_stored_received()
        self.assertEqual(actual.diagnostics, [existing])
        self.assertEqual(actual.support, {1: True})

    def test_stored_fatal_fallback_retains_prior_actual_capture(self):
        selected = profile(frame_function=0x113, frame_request=bytes.fromhex("1903ff"))
        replies = iter(
            (NativeStatus(0x91010009), b"\x59\x03\x01\x00", NativeStatus(0xA0000002))
        )

        def exchange(query):
            reply = next(replies)
            if isinstance(reply, Exception):
                raise reply
            return reply

        cache = MonitorSupportCache(selected, exchange, "authored")
        actual = P5FreezeState(selected, source_build=18, cache=cache, subaru=True)
        with self.assertRaises(ToyotaCodecError) as failure:
            actual.comm_execute_stored()
        self.assertEqual(failure.exception.code, 0xA0000002)
        self.assertEqual(
            (actual.snapshot_frames, actual.stored_numbers, actual.snapshot_success),
            ([b"\x59\x03\x01\x00"], [1], True),
        )

    def test_stored_zero_count_all_request_has_metadata_but_no_guessed_values(self):
        selected = profile(
            count=3,
            signals={0x4D: (1,), 0x4E: (2,), 0x4F: (3,)},
            frame_function=0x113,
            frame_request=bytes.fromhex("1903ff"),
        )
        cache = MonitorSupportCache(
            selected, lambda query: bytes.fromhex("5903011234560000"), "authored"
        )
        actual = P5FreezeState(selected, source_build=18, cache=cache, subaru=True)
        actual.comm_execute_stored()
        actual.analyze_stored_received()
        diagnostic = actual.diagnostic(0x123456)
        assert diagnostic is not None
        self.assertEqual(
            (diagnostic.existence_flags, diagnostic.signals, diagnostic.stored_all),
            (1, [], True),
        )
        normal = state(12)
        for operation in (normal.comm_execute_stored, normal.analyze_stored_received):
            with self.assertRaises(ValueError):
                operation()

    def test_stored_existing_dtc_merge_preserves_native_extended_list_direction(self):
        selected = profile(
            count=3,
            signals={0x4D: (1,), 0x4E: (2,), 0x4F: (3,)},
            frame_function=0x113,
            frame_request=bytes.fromhex("1903ff"),
        )
        cache = MonitorSupportCache(
            selected,
            lambda query: bytes.fromhex("590301123456000112340a0302"),
            "authored",
        )
        actual = P5FreezeState(selected, source_build=18, cache=cache, subaru=True)
        actual.set_timestamp_odometer_pid_ids()
        target = actual.add_diagnostic(0x123456, status=8)
        assert target is not None
        actual.analyze_record(
            0x123456, 1, (P5DataIdObservation(0x1234, bytes((5, 1, 1))),)
        )
        target.extended_numbers[:] = [7]
        actual.comm_execute_stored()
        actual.analyze_stored_received()
        self.assertIs(actual.diagnostic(0x123456), target)
        self.assertEqual(
            (target.status, target.extended_numbers, target.stored_all), (8, [7], True)
        )
        self.assertEqual([value.value for value in target.signals[0].values], [5, 10])
        self.assertEqual(
            [value.value for value in actual._values(target.timestamps[0])], [5, 10]
        )
        self.assertEqual(target.existence_flags, 1)

    def test_stored_confirmed_uses_first_zero_101f_index_and_first_matching_sample(
        self,
    ):
        selected = profile(second=False)
        sections = {
            key: (section.count, section.payload)
            for key, section in selected.database.sections.items()
        }
        row = bytearray(sections[62][1])
        struct.pack_into("<H", row, 56, 0x101F)
        sections[62] = (1, bytes(row))
        selected = replace(selected, database=database(18, 2, sections))
        cache = MonitorSupportCache(selected, lambda query: b"", "authored")
        actual = P5FreezeState(selected, source_build=18, cache=cache, subaru=True)
        target = actual.add_diagnostic(1)
        assert target is not None
        metadata = actual.signal_metadata(bytes(row))
        from scripts.freeze_p5 import P5FreezeSignal

        target.signals.append(
            P5FreezeSignal(
                metadata,
                [
                    P5Value(9, -126, 0x10),
                    P5Value(0, -125, 0x10),
                    P5Value(8, -125, 0x10),
                ],
            )
        )
        target.extended_numbers[:] = [1]
        actual.set_stored_confirmed(target)
        self.assertEqual(
            [value.kind for value in target.signals[0].values], [0x10, 1, 0x10]
        )

    def test_diagnostic_group_bound_uses_exact_source_and_observed_cache_bus(self):
        for build, bus, limit in (
            (12, 0x14, 0x3FF),
            (18, 1, 0x3FF),
            (18, None, 0x3FF),
            (18, 0x14, 0x3FFF),
        ):
            selected = profile(build)

            def exchange(_query):
                self.fail("Empty snapshot numbers must not perform I/O")

            cache = MonitorSupportCache(
                selected, exchange, "authored", source_build=build, bus_id=bus
            )
            actual = P5FreezeState(
                selected,
                source_build=cast(Literal[12, 18], build),
                cache=cache,
                subaru=build == 18,
            )
            self.assertEqual(actual.diagnostic_limit, limit)
            first = actual.add_diagnostic(1)
            assert first is not None
            actual.diagnostics[:] = [first] * (limit - 1)
            self.assertIsNotNone(actual.add_diagnostic(2))
            with self.assertRaisesRegex(SessionError, "diagnostic count"):
                actual.add_diagnostic(3)
            if build == 18:
                requests = (P5SnapshotRequest(1, []),) * limit
                self.assertFalse(actual.comm_execute_snapshot(requests))
                with self.assertRaises(TypeError):
                    actual.comm_execute_snapshot(requests + (P5SnapshotRequest(1, []),))
                with self.assertRaises(TypeError):
                    actual.analyze_snapshot_received(
                        requests + (P5SnapshotRequest(1, []),)
                    )
            cache.bus_id = 2 if bus != 2 else 3
            with self.assertRaises(SessionError):
                actual.add_diagnostic(4)

    def test_invalid_observed_bus_rejected_at_freeze_boundary(self):
        for bus in (True, -1, 0x10000):
            selected = profile()
            cache = MonitorSupportCache(
                selected, lambda _query: b"", "authored", bus_id=bus
            )
            with self.assertRaises(ValueError):
                P5FreezeState(selected, source_build=18, cache=cache)

    def test_capture_byte_budget_preserves_all_actual_responses(self):
        selected = profile()
        # Original18 CCommFrameData.Init sets receive WORD+2A to 0x1000.
        response = b"\x59" + bytes(4095)

        def exchange(_query):
            return response

        cache = MonitorSupportCache(
            selected,
            exchange,
            "authored",
            source_build=18,
            limits=Limits(exchanges=4200),
        )
        actual = P5FreezeState(selected, source_build=18, cache=cache, subaru=True)
        requests = tuple(P5SnapshotRequest(1, [1] * 255) for _ in range(16)) + (
            P5SnapshotRequest(1, [1] * 17),
        )
        with self.assertRaisesRegex(SessionError, "captured response budget"):
            actual.comm_execute_snapshot(requests)
        self.assertEqual(
            (len(actual.snapshot_frames), cache.calls, actual.snapshot_success),
            (4096, 4097, True),
        )
        self.assertEqual(actual.snapshot_frames, [response] * 4096)
        self.assertEqual(actual._snapshot_bytes, 16 * 1024 * 1024)
        self.assertEqual(sum(map(len, actual.snapshot_frames)), actual._snapshot_bytes)
        actual.init_freeze_data()
        self.assertEqual((actual.snapshot_frames, actual._snapshot_bytes), ([], 0))

    def test_snapshot_oversized_receive_is_tolerated_without_losing_prior_frames(self):
        selected = profile()
        first = b"\x59" + bytes(4095)
        replies = iter((first, b"\x59" + bytes(65534)))

        def exchange(_query):
            return next(replies)

        cache = MonitorSupportCache(selected, exchange, "authored", source_build=18)
        actual = P5FreezeState(selected, source_build=18, cache=cache, subaru=True)
        requests = (P5SnapshotRequest(1, [1, 2]),)
        self.assertTrue(actual.comm_execute_snapshot(requests))
        self.assertEqual(requests[0].numbers, [1])
        self.assertEqual(actual.ignored_errors, [(2, 0xA0040202)])
        self.assertEqual(actual.snapshot_frames, [first])
        self.assertEqual((actual._snapshot_bytes, cache.calls), (4096, 2))

    def test_retained_value_budget_reserves_native_three_value_association(self):
        actual = state(second=False)
        diagnostic = actual.add_diagnostic(1)
        actual.analyze_record(1, 1, (P5DataIdObservation(0x1234, b"\x07"),))
        assert diagnostic is not None
        diagnostic.signals[0].values[:] = [P5Value(7, -126, 1)] * 65534
        with self.assertRaises(SessionError):
            actual.set_freeze_data(
                diagnostic, actual.profile.records(62)[0], P5Value(8, -125, 2)
            )
        self.assertEqual(len(diagnostic.signals[0].values), 65534)

    def test_native_snapshot_cancel_is_literal_one_and_separate_from_host_policy(self):
        for flag in (1, 2):
            selected = profile()
            calls = []

            def exchange(query, calls=calls):
                calls.append(query.request)
                return bytes.fromhex("590400000100")

            cache = MonitorSupportCache(selected, exchange, "authored", source_build=18)
            actual = P5FreezeState(
                selected,
                source_build=18,
                cache=cache,
                subaru=True,
                native_cancel_value=flag,
            )
            requests = (P5SnapshotRequest(1, [1]),)
            if flag == 1:
                with self.assertRaises(ToyotaCodecError) as failure:
                    actual.comm_execute_snapshot(requests)
                self.assertEqual(failure.exception.code, 0xA0040003)
                self.assertEqual((calls, requests[0].numbers), ([], [1]))
            else:
                self.assertTrue(actual.comm_execute_snapshot(requests))
                self.assertEqual(len(calls), 1)

    def test_native_wide_dword_shift_wrap_and_reversed_range_status(self):
        for build in (12, 18):
            for start, end, payload, expected in (
                (0, 47, bytes.fromhex("ff0100000000"), 0xFF01),
                (7, 9, bytes.fromhex("a040"), 1),
                (16, 7, b"ab", None),
            ):
                selected = profile(build, second=False)
                sections = {
                    key: (section.count, section.payload)
                    for key, section in selected.database.sections.items()
                }
                row = bytearray(sections[62][1])
                struct.pack_into("<HH", row, 44, start, end)
                sections[62] = (1, bytes(row))
                selected = replace(selected, database=database(build, 2, sections))

                def exchange(_query):
                    self.fail("No primitive I/O expected")

                cache = MonitorSupportCache(
                    selected, exchange, "authored", source_build=build
                )
                actual = P5FreezeState(selected, source_build=build, cache=cache)
                diagnostic = actual.add_diagnostic(1)
                assert diagnostic is not None
                if expected is None:
                    with self.assertRaises(ToyotaCodecError) as failure:
                        actual.analyze_record(
                            1, 1, (P5DataIdObservation(0x1234, payload),)
                        )
                    self.assertEqual(failure.exception.code, 0xC0000001)
                    self.assertEqual(
                        (diagnostic.signals, actual.support), ([], {1: True})
                    )
                else:
                    actual.analyze_record(1, 1, (P5DataIdObservation(0x1234, payload),))
                    self.assertEqual(diagnostic.signals[0].values[0].value, expected)

    def test_standalone_metadata_keeps_native_word_width_wrap(self):
        selected = profile(second=False)
        sections = {
            key: (section.count, section.payload)
            for key, section in selected.database.sections.items()
        }
        row = bytearray(sections[62][1])
        struct.pack_into("<HH", row, 44, 0xFFFF, 0)
        sections[62] = (1, bytes(row))
        selected = replace(selected, database=database(18, 2, sections))

        def exchange(_query):
            self.fail("No primitive I/O expected")

        cache = MonitorSupportCache(selected, exchange, "authored", source_build=18)
        actual = P5FreezeState(selected, source_build=18, cache=cache)
        metadata = actual.signal_metadata(selected.records(62)[0])
        self.assertEqual(metadata.width, 2)
        self.assertEqual(metadata.render(P5Value(1, 0, 1))["value"], 5)

    def test_subaru_partial_unknown_did_retains_prior_associations_and_flags(self):
        selected = profile(signals={0x4D: (1,), 0x4E: (2,), 0x4F: (3,)}, count=3)

        def exchange(_query):
            return bytes.fromhex("590412345600010212340a03025555")

        cache = MonitorSupportCache(selected, exchange, "authored", source_build=18)
        actual = P5FreezeState(selected, source_build=18, cache=cache, subaru=True)
        requests = (P5SnapshotRequest(0x123456, [1]),)
        actual.comm_execute_snapshot(requests)
        actual.analyze_snapshot_received(requests)
        self.assertEqual(actual.snapshot_partial, [(0, 13)])
        self.assertEqual(actual.diagnostics[0].existence_flags, 1)
        self.assertEqual(
            [signal.values[0].value for signal in actual.diagnostics[0].signals],
            [10, 3, 2],
        )

    def test_metadata_missing_physical_pattern_and_table_fail_before_wire(self):
        for slot in (13, 14, 15):
            selected = profile(pattern=True)
            sections = {
                key: (section.count, section.payload)
                for key, section in selected.database.sections.items()
            }
            sections[slot] = (0, b"")
            selected = replace(selected, database=database(18, 2, sections))

            def exchange(_query):
                self.fail("Missing metadata must fail before primitive I/O")

            cache = MonitorSupportCache(selected, exchange, "authored", source_build=18)
            actual = P5FreezeState(selected, source_build=18, cache=cache)
            diagnostic = actual.add_diagnostic(1)
            with self.assertRaises(ToyotaCodecError) as failure:
                actual.analyze_record(1, 1, (P5DataIdObservation(0x1234, b"ab"),))
            self.assertEqual(failure.exception.code, 0xC0040101)
            assert diagnostic is not None
            self.assertEqual(
                (diagnostic.existence_flags, diagnostic.signals, cache.calls),
                (1, [], 0),
            )

    def test_absent_metadata_tables_keep_native_missing_table_status(self):
        for slot in (13, 14, 15, 62):
            selected = profile(pattern=True)
            sections = {
                key: (section.count, section.payload)
                for key, section in selected.database.sections.items()
                if key != slot
            }
            selected = replace(selected, database=database(18, 2, sections))

            def exchange(_query):
                self.fail("Absent table must fail before primitive I/O")

            cache = MonitorSupportCache(selected, exchange, "authored", source_build=18)
            actual = P5FreezeState(selected, source_build=18, cache=cache)
            diagnostic = actual.add_diagnostic(1)
            with self.assertRaises(ToyotaCodecError) as failure:
                actual.analyze_record(1, 1, (P5DataIdObservation(0x1234, b"ab"),))
            self.assertEqual(failure.exception.code, 0xA0030107)
            assert diagnostic is not None
            self.assertEqual(
                (diagnostic.existence_flags, diagnostic.signals, cache.calls),
                (1, [], 0),
            )

    def test_signal_pid_setup_preserves_earlier_fields_on_missing_later_group(self):
        actual = state(signals={0x1C: (1,), 0x1D: (2,)})
        with self.assertRaises(ToyotaCodecError):
            actual.set_timestamp_odometer_pid_ids()
        self.assertEqual(actual.signal_pids, {0x1C: (1,), 0x1D: (2,)})

    def test_group_without_anchor_discards_companions_and_display_order_is_selected(
        self,
    ):
        actual = state()
        diagnostic = actual.add_diagnostic(1)
        actual.analyze_record(1, 0x10, (P5DataIdObservation(0x1234, b"ab"),))
        assert diagnostic is not None
        diagnostic.signals.reverse()
        actual.sort_display_order(diagnostic)
        self.assertEqual([signal.pid for signal in diagnostic.signals], [1, 2])
        actual.sort_multi_data_by_timestamp(diagnostic)
        self.assertEqual(diagnostic.signals, [])

    def test_actual_ffd_metadata_retains_changed_lsb_with_fresh_native_temp(self):
        from tests.test_signal_lsb import selected

        with tempfile.TemporaryDirectory() as directory:
            selected_profile = selected(
                Path(directory), flags=0x14, p5=True, p5_pids=(9, 10)
            )
            for build in (12, 18):
                events = []

                def exchange(query, events=events):
                    events.append(query.request)
                    return {
                        b"\x22\0\0": b"\x62\0\0\x40",
                        b"\x22\x01\0": b"\x62\x01\0\x80",
                        b"\x22\x01\x01": b"\x62\x01\x01\x06",
                    }[query.request]

                cache = MonitorSupportCache(
                    selected_profile, exchange, "authored-lsb", source_build=build
                )
                actual = P5FreezeState(
                    selected_profile, source_build=build, cache=cache
                )
                for row in selected_profile.records(62):
                    metadata = actual.signal_metadata(row)
                    self.assertEqual(
                        (metadata.multiplier, metadata.divisor, metadata.threshold),
                        (45, 1, 255),
                    )
                    self.assertEqual(metadata.threshold_high, 99)
                self.assertEqual(
                    events,
                    [
                        b"\x22\0\0",
                        b"\x22\x01\0",
                        b"\x22\x01\x01",
                        b"\x22\x01\x01",
                        b"\x22\x01\x01",
                    ],
                )

    def test_ssr_pid_list_preserves_native_wordlist_duplicates(self):
        selected = profile(second=False)
        sections = {
            slot: (section.count, section.payload)
            for slot, section in selected.database.sections.items()
        }
        sections[62] = (2, selected.database.sections[62].payload * 2)
        selected = replace(selected, database=database(18, 2, sections))

        def exchange(_query):
            raise AssertionError("No wire query expected")

        cache = MonitorSupportCache(selected, exchange, "authored", source_build=18)
        actual = P5FreezeState(selected, source_build=18, cache=cache)
        diagnostic = actual.add_diagnostic(1)
        self.assertEqual(actual.get_pid_ids(0x1234), (1, 1))
        actual.analyze_record(1, 1, (P5DataIdObservation(0x1234, b"\x07"),))
        assert diagnostic is not None
        self.assertEqual(
            [value.value for value in diagnostic.signals[0].values], [7, 7]
        )

    def test_native_search_zero_and_first_duplicate(self):
        values = [P5Value(8, -1, 1), P5Value(9, -1, 1), P5Value(0, 0, 0)]
        self.assertEqual(P5FreezeState.search_multi_data(values, 1, -1), 0)
        self.assertEqual(P5FreezeState.search_multi_data(values, 0, 0), -1)
        self.assertEqual(P5FreezeState.search_ffd_type(values, 1), (0, 1))
        self.assertEqual(P5FreezeState.search_ffd_type(values, 0), ())
        observations = (P5DataIdObservation(1, b"a"), P5DataIdObservation(1, b"b"))
        self.assertEqual(P5FreezeState.search_data_id(1, observations), 0)
        self.assertEqual(P5FreezeState.search_data_id(0, observations), -1)

    def test_identity_change_and_foreign_definition_rejected_before_mutation(self):
        actual = state()
        diagnostic = actual.add_diagnostic(1)
        assert diagnostic is not None
        foreign = bytearray(actual.profile.records(62)[0])
        foreign[59] = 2
        with self.assertRaises(ValueError):
            actual.set_freeze_data(diagnostic, bytes(foreign), P5Value(1, 0, 1))
        actual.profile = replace(actual.profile, vehicle_name_key=99)
        with self.assertRaises(SessionError):
            actual.analyze_record(1, 1, (P5DataIdObservation(1, b"a"),))
        self.assertEqual((diagnostic.signals, actual.support), ([], {}))

    def test_selected_ffd_support_variable_and_ignored_mode_failures_both_builds(self):
        for build in (12, 18):
            for mode, data, expected, ignored in (
                (7, b"\x80\x01", True, []),
                (7, b"\x00\x01", False, []),
                (6, b"\x80\x01", False, [(1, 0xC0040102), (2, 0xC0040102)]),
            ):
                actual = state(build, ffd_mode=mode)
                diagnostic = actual.add_diagnostic(1)
                actual.analyze_record(1, 1, (P5DataIdObservation(0x1234, data),))
                assert diagnostic is not None
                self.assertEqual(bool(diagnostic.signals), expected)
                self.assertEqual(actual.support, {1: expected, 2: expected})
                self.assertEqual(actual.ignored_errors, ignored)
            for variable in (b"", b"\x12", b"\x00\x01"):
                actual = state(build, ffd_mode=7, ffd_variable=variable)
                actual.add_diagnostic(1)
                actual.analyze_record(1, 1, (P5DataIdObservation(0x1234, b"\x80\x01"),))
                self.assertEqual(actual.support, {1: False, 2: False})

    def test_absolute_bcd_and_odometer_keep_raw_on_invalid_special_value(self):
        signals = {key: (0,) for key in (0x1C, 0x1D, 0x27, 0x28, *range(0x3C, 0x42))}
        signals[0x3C] = (1,)
        actual = state(signals=signals, second=False)
        actual.set_timestamp_odometer_pid_ids()
        diagnostic = actual.add_diagnostic(1)
        actual.analyze_record(1, 1, (P5DataIdObservation(0x1234, b"\x38"),))
        actual.analyze_record(1, 2, (P5DataIdObservation(0x1234, b"\x3a"),))
        assert diagnostic is not None
        self.assertEqual(
            [value.value for value in diagnostic.signals[0].values], [0x38, 0x3A]
        )
        self.assertEqual(
            [value.value for value in diagnostic.absolute[0x3C].values], [38]
        )
        actual.set_timestamp_odometer_flags(diagnostic)
        self.assertEqual(diagnostic.absolute_flags, 1)
        signals[0x3C], signals[0x28] = (0,), (1,)
        odometer = state(signals=signals, second=False)
        odometer.set_timestamp_odometer_pid_ids()
        odo_diagnostic = odometer.add_diagnostic(1)
        for value in (0, 7, 9):
            odometer.analyze_record(
                1, 1, (P5DataIdObservation(0x1234, bytes((value,))),)
            )
        assert odo_diagnostic is not None and odo_diagnostic.odometer is not None
        self.assertEqual(
            [value.value for value in odo_diagnostic.odometer.values], [7, 9]
        )

    def test_original18_selector_cache_masks_and_replaces_special_timestamps(self):
        signals = {key: (0,) for key in (0x1C, 0x1D, 0x27, 0x28, *range(0x3C, 0x42))}
        signals.update({0x49: (1,), 0x4A: (2,)})
        actual = state(signals=signals, category_id=0x190)
        actual.set_timestamp_odometer_pid_ids()
        diagnostic = actual.add_diagnostic(1)
        assert diagnostic is not None
        rows = actual.profile.records(62)
        actual.set_freeze_data(diagnostic, rows[0], P5Value(2, -126, 1))
        actual.set_freeze_data(diagnostic, rows[1], P5Value(0xAA123456, -126, 1))
        second, third = diagnostic.timestamps[1:]
        assert second is not None and third is not None
        self.assertEqual((second.values[0].value, third.values[0].value), (0x123456, 2))
        actual.sort_multi_data_by_ffd_type(diagnostic)
        self.assertEqual(second.values, [])
        actual.set_freeze_data(diagnostic, rows[1], P5Value(9, -125, 2))
        self.assertIs(diagnostic.timestamps[1], second)
        self.assertEqual(second.values, [P5Value(9, -125, 2)])
        actual.set_freeze_data(diagnostic, rows[0], P5Value(4, -125, 2))
        actual.set_freeze_data(diagnostic, rows[1], P5Value(8, -125, 2))
        self.assertEqual(len(second.values), 1)
        self.assertEqual(diagnostic.signals[1].values[-1].value, 8)

    def test_missing_third_timestamp_removes_companion_values_only(self):
        signals = {key: (0,) for key in (0x1C, 0x1D, 0x27, 0x28, *range(0x3C, 0x42))}
        signals.update({0x1C: (1,), 0x1D: (2,)})
        actual = state(signals=signals)
        actual.set_timestamp_odometer_pid_ids()
        diagnostic = actual.add_diagnostic(1)
        for number in (1, 0x10):
            actual.analyze_record(
                1, number, (P5DataIdObservation(0x1234, b"\x01\x02"),)
            )
        assert diagnostic is not None
        actual.sort_multi_data_by_timestamp(diagnostic)
        self.assertEqual([value.kind for value in diagnostic.signals[0].values], [1])
        self.assertEqual(diagnostic.signals[0].values[0].index, 0)
        self.assertEqual(actual._values(diagnostic.timestamps[0]), [])

    def test_subaru_tolerated_statuses_remove_numbers_and_fatal_preserves_partial(self):
        for status in (
            0x91010009,
            0x90020321,
            0x90020323,
            0xA0040201,
            0xC0040001,
            0xA0040202,
            0x90020327,
            0x91020320,
            0x91020310,
            0x91020322,
        ):
            selected = profile()

            def failed(_query, status=status):
                raise NativeStatus(status)

            cache = MonitorSupportCache(selected, failed, "authored", source_build=18)
            actual = P5FreezeState(selected, source_build=18, cache=cache, subaru=True)
            requests = (P5SnapshotRequest(1, [1, 2]),)
            self.assertFalse(actual.comm_execute_snapshot(requests))
            self.assertEqual(
                (requests[0].numbers, actual.snapshot_frames, cache.calls), ([], [], 2)
            )
        calls = []

        def partial(query):
            calls.append(query.request)
            if len(calls) == 2:
                raise NativeStatus(0xA0000002)
            return bytes.fromhex("590400000100")

        selected = profile()
        cache = MonitorSupportCache(selected, partial, "authored", source_build=18)
        actual = P5FreezeState(selected, source_build=18, cache=cache, subaru=True)
        with self.assertRaises(ToyotaCodecError):
            actual.comm_execute_snapshot((P5SnapshotRequest(1, [1, 2]),))
        self.assertEqual(
            (len(actual.snapshot_frames), actual.snapshot_success), (1, True)
        )
        actual.init_freeze_data()
        self.assertEqual(actual.snapshot_frames, [])

    def test_subaru_exchange_budget_stops_before_second_io(self):
        selected = profile()
        calls = []

        def exchange(query):
            calls.append(query.request)
            return bytes.fromhex("590400000100")

        cache = MonitorSupportCache(
            selected, exchange, "authored", source_build=18, limits=Limits(exchanges=1)
        )
        actual = P5FreezeState(selected, source_build=18, cache=cache, subaru=True)
        with self.assertRaises(SessionError):
            actual.comm_execute_snapshot((P5SnapshotRequest(1, [1, 2]),))
        self.assertEqual((len(calls), len(actual.snapshot_frames)), (1, 1))

    def test_native_paired_state_sort_and_indices_both_builds(self):
        for build in (12, 18):
            signals = {0x1C: (1,), 0x1D: (2,), 0x27: (3,), 0x28: (0,)}
            if build == 18:
                signals.update({key: (0,) for key in range(0x3C, 0x42)})
            actual = state(build, count=3, signals=signals)
            actual.set_timestamp_odometer_pid_ids()
            diagnostic = actual.add_diagnostic(1)
            for number, data in (
                (1, b"\x14\x05\x01"),
                (0x10, b"\x0a\x03\x02"),
                (0x11, b"\x1e\x09\x03"),
            ):
                actual.analyze_record(1, number, (P5DataIdObservation(0x1234, data),))
            assert diagnostic is not None
            actual.sort_multi_data_by_timestamp(diagnostic)
            timestamp = diagnostic.timestamps[0]
            assert timestamp is not None
            self.assertEqual(
                [(value.value, value.index, value.kind) for value in timestamp.values],
                [(10, -1, 0x10), (20, 0, 1), (30, 1, 0x10)],
            )
            self.assertEqual(
                [value.index for value in diagnostic.signals[0].values], [-1, 0, 1]
            )
            actual.set_timestamp_odometer_flags(diagnostic)
            self.assertEqual(diagnostic.timestamp_flags, 1)

    def test_native_sort_cumulative_end_keeps_singleton_in_next_sort_window(self):
        for build in (12, 18):
            signals = {0x1C: (1,), 0x1D: (2,), 0x27: (3,), 0x28: (0,)}
            if build == 18:
                signals.update({key: (0,) for key in range(0x3C, 0x42)})
            actual = state(build, count=3, signals=signals)
            actual.set_timestamp_odometer_pid_ids()
            diagnostic = actual.add_diagnostic(1)
            for number, timestamp in ((1, 30), (2, 20), (0x50, 10)):
                actual.analyze_record(
                    1,
                    number,
                    (P5DataIdObservation(0x1234, bytes((timestamp, 0, 0))),),
                )
            assert diagnostic is not None
            actual.sort_multi_data_by_timestamp(diagnostic)
            # 12:5f9d0 /18:84dd0 advances end for every group, start only if >1.
            self.assertEqual(
                [value.value for value in actual._values(diagnostic.timestamps[0])],
                [10, 20, 30],
            )
            self.assertEqual(
                [value.kind for value in diagnostic.signals[0].values],
                [0x50, 2, 1],
            )

    def test_subaru_snapshot_wire_and_selected_associations(self):
        selected = profile(signals={0x4D: (1,), 0x4E: (2,), 0x4F: (3,)}, count=3)
        calls = []

        def exchange(query):
            calls.append(query.request)
            return bytes.fromhex("590412345600010112340a0302")

        cache = MonitorSupportCache(selected, exchange, "authored", source_build=18)
        actual = P5FreezeState(selected, source_build=18, cache=cache, subaru=True)
        requests = (P5SnapshotRequest(0x123456, [1]),)
        self.assertTrue(actual.comm_execute_snapshot(requests))
        self.assertEqual(calls, [bytes.fromhex("190412345601")])
        actual.analyze_snapshot_received(requests)
        self.assertEqual(actual.snapshot_partial, [])
        self.assertEqual(actual.diagnostics[0].existence_flags, 1)
        self.assertEqual(
            [item.values[0].value for item in actual.diagnostics[0].signals], [10, 3, 2]
        )
        self.assertEqual(
            [item.values[0].index for item in actual.diagnostics[0].signals], [0, 0, 0]
        )

    def test_selected_metadata_and_values_both_original_builds(self):
        for build in (12, 18):
            with self.subTest(build=build):
                actual = state(build, pattern=True)
                diagnostic = actual.add_diagnostic(0x123456)
                self.assertIsNotNone(diagnostic)
                assert diagnostic is not None
                observed = P5DataIdObservation(0x1234, b"\x04\x09")
                actual.analyze_record(0x123456, 1, (observed,))
                self.assertEqual(diagnostic.existence_flags, 1)
                self.assertEqual(diagnostic.normal_numbers, [1])
                self.assertEqual(
                    [(item.pid, item.values) for item in diagnostic.signals],
                    [(1, [P5Value(4, -126, 1)]), (2, [P5Value(9, -126, 1)])],
                )
                metadata = diagnostic.signals[0].metadata
                self.assertEqual(
                    (metadata.name, metadata.unit, metadata.unit_id),
                    ("label101", "label20", 9),
                )
                self.assertEqual(
                    (
                        metadata.multiplier,
                        metadata.divisor,
                        metadata.threshold,
                        metadata.threshold_high,
                    ),
                    (2, 1, 50, 60),
                )
                self.assertEqual(metadata.patterns, ((3, "label200", 4, 5),))
                self.assertEqual(
                    metadata.render(diagnostic.signals[0].values[0])["value"], 11
                )

    def test_absent_diagnostic_is_native_noop(self):
        actual = state()
        actual.analyze_record(1, 1, (P5DataIdObservation(0x1234, b"ab"),))
        self.assertEqual((actual.diagnostics, actual.support), ([], {}))

    def test_short_reply_retains_first_pid_and_skips_second(self):
        actual = state()
        diagnostic = actual.add_diagnostic(1)
        actual.analyze_record(1, 1, (P5DataIdObservation(0x1234, b"\x7f"),))
        assert diagnostic is not None
        self.assertEqual([item.pid for item in diagnostic.signals], [1])
        self.assertEqual(actual.support, {1: True})

    def test_support_cache_reuses_false_and_true(self):
        actual = state(mode=1, bit_base=8)
        diagnostic = actual.add_diagnostic(1)
        actual.analyze_record(1, 1, (P5DataIdObservation(0x1234, b"\x00\x01\x05"),))
        self.assertEqual(actual.support, {1: False, 2: True})
        actual.analyze_record(1, 2, (P5DataIdObservation(0x1234, b"\xff\xff\xff"),))
        assert diagnostic is not None
        self.assertEqual([item.pid for item in diagnostic.signals], [2])
        self.assertEqual(
            [item.value for item in diagnostic.signals[0].values], [5, 255]
        )
        self.assertEqual(actual.ignored_errors, [])

    def test_native_preceding_byte_underflow_is_host_failure(self):
        actual = state(mode=1)
        diagnostic = actual.add_diagnostic(1)
        with self.assertRaises(SessionError):
            actual.analyze_record(1, 1, (P5DataIdObservation(0x1234, b"\x01\x02"),))
        assert diagnostic is not None
        self.assertEqual((diagnostic.signals, actual.support), ([], {}))

    def test_missing_unit_fails_after_existence_and_support_mutation(self):
        actual = state(unit=False)
        diagnostic = actual.add_diagnostic(1)
        with self.assertRaises(ToyotaCodecError) as failure:
            actual.analyze_record(1, 1, (P5DataIdObservation(0x1234, b"ab"),))
        self.assertEqual(failure.exception.code, 0xC0040101)
        assert diagnostic is not None
        self.assertEqual(
            (diagnostic.existence_flags, diagnostic.signals, actual.support),
            (1, [], {1: True}),
        )

    def test_type_flags_and_dtc_template_literal(self):
        actual = state()
        diagnostic = actual.add_diagnostic(1)
        for number in (1, 2, 0x10, 0x30, 0x50):
            actual.set_ffd_exist_flag(1, number)
        actual.set_ffd_exist_flag(1, 14, extended=True)
        assert diagnostic is not None
        self.assertEqual(diagnostic.existence_flags, 0x200011)
        self.assertEqual(
            actual.set_dtc(bytes.fromhex("190400000000aa"), 0x123456, 7),
            bytes.fromhex("190412345607aa"),
        )
        for request, number in ((b"12", None), (b"12345", 1), (b"123456", 0)):
            with self.assertRaises(ToyotaCodecError):
                actual.set_dtc(request, 1, number)

    def test_build_and_source_binding_cancel_and_typed_boundaries(self):
        actual = state()
        with self.assertRaises(SessionError):
            P5FreezeState(profile(), source_build=12, cache=actual.cache)
        twelve = state(12)
        with self.assertRaises(ValueError):
            P5FreezeState(
                twelve.profile, source_build=12, cache=twelve.cache, subaru=True
            )
        for did, data in ((0, b"a"), (1, b""), (1, b"a" * 256)):
            with self.assertRaises(ValueError):
                P5DataIdObservation(did, data)
        actual.cache.cancelled = lambda: True
        with self.assertRaises(Cancelled):
            actual.analyze_record(1, 1, (P5DataIdObservation(1, b"a"),))


if __name__ == "__main__":
    unittest.main()
