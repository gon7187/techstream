"""Authored literal support wire, faults, source identity and bounded chronology."""

import struct
import unittest
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock

from scripts.monitor_support import (
    MonitorSupportCache,
    PacketFrame,
    PacketFrameCache,
    mode35_frame_map,
    monitor_source_identity,
)
from scripts.profiles import (
    ProtocolProfile,
    SelectedFrame,
    VehicleCatalog,
    VehicleProfile,
)
from scripts.toyota import CommandFrame, ToyotaCodecError
from scripts.toyota_session import Cancelled, Limits, SessionError


def profile(rows, request=b"\x21\x00"):
    selected = Mock(spec=VehicleProfile)
    selected.ecu_database_sha256 = "authored-diag"
    selected.vehicle_name_key = None
    selected.category = 7
    selected.category_record = b"authored-category"
    selected.exception_ids = (3,)
    selected.database = SimpleNamespace(
        sha256="authored-diag", sections=dict.fromkeys(rows)
    )
    selected.catalog = SimpleNamespace(
        management=SimpleNamespace(sha256="authored-management", version=0x0100032F)
    )
    selected.records.side_effect = lambda slot: tuple(rows.get(slot, ()))
    selected._signal_rows.side_effect = lambda slot: selected.records(slot)
    selected.pid_records.side_effect = lambda pid: VehicleProfile.pid_records(
        selected, pid
    )
    selected.frame_records.side_effect = lambda function: (
        SelectedFrame(
            CommandFrame(request),
            bytes((function & 255,)),
            b"comm",
            b"settings",
            "authored",
        ),
    )
    return selected


def pid(value, length=1):
    return bytes((0, 0, value, length, 0, 0, 0, 0))


def sup(base, mode=1):
    return bytes((0, 0, 0, 0, base, mode, 0, 0))


def freeze(pid, identifier, first, last):
    data = bytearray(84)
    data[79], data[83] = pid, identifier
    struct.pack_into("<HH", data, 62, first, last)
    return bytes(data)


class SupportTests(unittest.TestCase):
    def test_management_only_identity_and_ecu_guards(self):
        selected = profile({})
        protocol = ProtocolProfile(selected.catalog, bytes(80))
        exchange = Mock(side_effect=AssertionError("ECU-only operation performed I/O"))
        cache = MonitorSupportCache(protocol, exchange, "management-only")
        self.assertIsNone(cache.identity[1])
        cache.check_context()
        for operation in (
            cache.valid_ids,
            cache.enabled_pids,
            cache.mode35,
            cache.support_bits,
            cache.data_ids,
            lambda: cache.subaru_did_support((1,)),
            lambda: cache.data_id_support_status(1),
            lambda: cache.check_support_pid(1),
        ):
            with (
                self.subTest(operation=operation),
                self.assertRaisesRegex(SessionError, "no ECU database"),
            ):
                operation()
        exchange.assert_not_called()

    def test_ordered_pid_entries_preserve_bitmap_and_definition_occurrences(self):
        for build in (12, 18):
            selected = profile(
                {3: (sup(0), sup(0)), 6: (pid(1, 2), pid(1, 9))}, b"\x01\0"
            )
            exchange = Mock(return_value=bytes.fromhex("410080"))
            cache = MonitorSupportCache(
                selected, exchange, "ordered-bitmap", source_build=build
            )
            self.assertEqual(
                cache.enabled_pid_entries(family="normal"), ((1, 2), (1, 2))
            )
            self.assertEqual(cache.valid_id_entries(), ((1, 2), (1, 2)))
            self.assertEqual(cache.enabled_pids(family="normal"), {1: 2})
            self.assertEqual(exchange.call_count, 1)
            selected = profile({6: (pid(1, 2), pid(1, 9))})
            exchange = Mock(
                side_effect=AssertionError(
                    "Static duplicate definitions require no I/O"
                )
            )
            cache = MonitorSupportCache(
                selected, exchange, "ordered-fallback", source_build=build
            )
            self.assertEqual(cache.valid_id_entries(), ((1, 2), (1, 9)))
            self.assertEqual(cache.enabled_pid_entries(family="ext"), ((1, 2), (1, 9)))
            self.assertEqual(cache.valid_ids(), {1: 2})
            exchange.assert_not_called()

    def test_valid_ext_mode_zero_falls_back_but_normal_still_queries(self):
        for build in (12, 18):
            selected = profile({3: (sup(0, 0),), 6: (pid(1, 2), pid(1, 9))}, b"\x01\0")
            exchange = Mock(return_value=bytes.fromhex("410080"))
            cache = MonitorSupportCache(
                selected, exchange, "mode-zero", source_build=build
            )
            self.assertEqual(cache.valid_id_entries(), ((1, 2), (1, 9)))
            exchange.assert_not_called()
            self.assertEqual(cache.enabled_pid_entries(family="normal"), ((1, 2),))
            exchange.assert_called_once()

    def test_pid_length_metadata_errors_follow_bitmap(self):
        for build in (12, 18):
            for family in ("valid_ext", "normal"):
                selected = profile({3: (sup(0),), 6: (pid(1),) * 32768}, b"\x01\0")
                chronology = []
                selected.records.side_effect = lambda slot, chronology=chronology: (
                    chronology.append(("table", slot))
                    or ((sup(0),) if slot == 3 else (pid(1),) * 32768)
                )

                def exchange(query, chronology=chronology):
                    chronology.append(("wire", query.request))
                    return b"\x41\0\x80"

                cache = MonitorSupportCache(
                    selected, exchange, "phase", source_build=build
                )
                with self.assertRaises(ToyotaCodecError) as raised:
                    cache.enabled_pid_entries(family=family)
                self.assertEqual(raised.exception.code, 0xA0030110)
                self.assertLess(
                    chronology.index(("wire", b"\x01\0")),
                    chronology.index(("table", 6)),
                )

    def test_supported_pid_query_sizes_only_the_first_selected_group(self):
        for build in (12, 18):
            for family in ("valid_ext", "normal"):
                rows = tuple(row for value in range(256) for row in (pid(value),) * 128)
                selected = profile({3: (sup(0),), 6: rows}, b"\x01\0")
                exchange = Mock(return_value=b"\x41\0\x80")
                cache = MonitorSupportCache(
                    selected, exchange, "selected-count", source_build=build
                )
                self.assertEqual(
                    cache.enabled_pid_entries(family=family), ((0, 1), (1, 1))
                )
                exchange.assert_called_once()
                selected = profile(
                    {3: (sup(0),), 6: (pid(1, 2), pid(2, 3), pid(1, 9))}, b"\x01\0"
                )
                cache = MonitorSupportCache(
                    selected,
                    Mock(return_value=b"\x41\0\xc0"),
                    "first-group",
                    source_build=build,
                )
                self.assertEqual(
                    cache.enabled_pid_entries(family=family), ((1, 2), (2, 3))
                )

    def test_valid_ext_checks_support_count_before_mode_zero_filter(self):
        selected = profile({3: (sup(0, 0),) * 32768, 6: (pid(1),)}, b"\x01\0")
        exchange = Mock(
            side_effect=AssertionError("Record count failure must precede I/O")
        )
        cache = MonitorSupportCache(selected, exchange, "mode-zero-count")
        with self.assertRaises(ToyotaCodecError) as raised:
            cache.valid_id_entries()
        self.assertEqual(raised.exception.code, 0xA0030110)
        exchange.assert_not_called()

    def test_valid_ext_skipped_continuation_does_not_fall_back(self):
        selected = profile({3: (sup(32, 2),), 6: (pid(1),) * 32768}, b"\x01\0")
        exchange = Mock(side_effect=AssertionError("No selected initial page"))
        cache = MonitorSupportCache(selected, exchange, "skipped-page")
        self.assertEqual(cache.valid_id_entries(), ())
        selected.records.assert_called_once_with(3)
        exchange.assert_not_called()

    def test_ordered_pid_output_count_is_not_limited_to_word(self):
        selected = profile(
            {3: (sup(0),) * 257, 6: tuple(pid(value) for value in range(256))},
            b"\x01\0",
        )
        exchange = Mock(return_value=b"\x41\0" + bytes((255,)) * 32)
        cache = MonitorSupportCache(
            selected, exchange, "ordered-dword", limits=Limits(seconds=60)
        )
        entries = cache.enabled_pid_entries(family="normal")
        self.assertEqual(len(entries), 65792)
        self.assertEqual(entries[:256], tuple((value, 1) for value in range(256)))
        self.assertEqual(entries[-256:], entries[:256])
        self.assertEqual(exchange.call_count, 1)

    def test_native_record_setter_rejects_count_above_positive_short(self):
        for build in (12, 18):
            selected = profile({6: (pid(2),) * 32767})
            exchange = Mock(
                side_effect=AssertionError("Static definitions need no I/O")
            )
            cache = MonitorSupportCache(
                selected, exchange, "record-count", source_build=build
            )
            self.assertEqual(cache.valid_ids(), {2: 1})
            selected.records.side_effect = lambda slot: (
                (pid(2),) * 32768 if slot == 6 else ()
            )
            with self.assertRaises(ToyotaCodecError) as raised:
                cache.valid_ids()
            self.assertEqual(raised.exception.code, 0xA0030110)
            exchange.assert_not_called()

    def test_first_frame_consumer_uses_positive_native_short_count(self):
        for source_build in (12, 18):
            for count in (256, 257, 32767):
                selected = profile({}, b"\x22\0\0")
                selected.category_record = bytes(96)
                first = selected.frame_records(0xC8)[0]
                selected.frame_records.side_effect = None
                selected.frame_records.return_value = (first,) * count
                exchange = Mock(return_value=b"\x62\0\0\0")
                cache = MonitorSupportCache(
                    selected, exchange, "first", source_build=source_build
                )
                self.assertEqual(cache.data_ids().suppressed_errors, ())
                self.assertEqual(exchange.call_count, 1)
                self.assertEqual(exchange.call_args.args[0].request, b"\x22\0\0")
                with self.assertRaises(ToyotaCodecError):
                    cache._template(0xC8)
            selected.frame_records.return_value = (first,) * 32768
            with self.assertRaises(ToyotaCodecError) as raised:
                cache._frames(0xC8)
            self.assertEqual(raised.exception.code, 0xC0040102)

    def test_extended_native_receive_capacity_is_4096_and_bad_reply_is_not_cached(self):
        selected = profile({}, bytes.fromhex("220000"))
        replies = iter(
            (b"\x62" + bytes(4096), b"\x62" + bytes(4095), b"\x62" + bytes(65534))
        )
        calls = []

        def exchange(query):
            calls.append(query)
            return next(replies)

        cache = MonitorSupportCache(selected, exchange, "Ext-capacity")
        frame = selected.frame_records(0xCA)[0]
        with self.assertRaises(ToyotaCodecError) as raised:
            cache.transaction(frame, frame.frame.request, extended=True)
        self.assertEqual(raised.exception.code, 0xA0040202)
        self.assertFalse(cache.response_cached(frame.frame.request))
        self.assertEqual(
            len(cache.transaction(frame, frame.frame.request, extended=True)), 4096
        )
        self.assertEqual(len(calls), 2)
        self.assertEqual(
            len(
                cache.transaction(
                    frame, bytes.fromhex("220001"), extended=True, capacity=65535
                )
            ),
            65535,
        )
        self.assertEqual(calls[-1].capacity, 65535)
        # Native response lookup ignores capacity; it is an I/O field, not a key.
        self.assertEqual(
            len(
                cache.transaction(
                    frame, bytes.fromhex("220001"), extended=True, capacity=1
                )
            ),
            65535,
        )
        self.assertEqual(len(calls), 3)

    def test_exact_support_bitmap_and_first_definition(self):
        selected = profile(
            {
                3: (sup(0), sup(32, 2)),
                6: (pid(0), pid(1, 2), pid(1, 9), pid(32), pid(33)),
            }
        )
        calls = []

        def exchange(query):
            calls.append(query)
            return {b"\x21\x00": b"\x61\x00\x80\0\0\x01", b"\x21\x20": b"\x61\x20\x80"}[
                query.request
            ]

        cache = MonitorSupportCache(selected, exchange, "ecu-7")
        self.assertEqual(cache.valid_ids(), {0: 1, 1: 2, 32: 1, 33: 1})
        self.assertEqual([q.request for q in calls], [b"\x21\0", b"\x21\x20"])
        self.assertEqual(cache.valid_ids(), {0: 1, 1: 2, 32: 1, 33: 1})
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0].selected.settings_record, b"settings")

    def test_db_fallback_queries_only_zero_length_and_ignores_exact_statuses(self):
        selected = profile({6: (pid(2, 0), pid(3, 4), pid(4, 0))})
        calls = []

        def exchange(query):
            calls.append(query.request)
            if query.request == b"\x21\x04":
                raise ToyotaCodecError("authored unsupported", 0x90020321)
            return b"\x61\x02\xaa\xbb\xcc"

        self.assertEqual(
            MonitorSupportCache(selected, exchange, "e").valid_ids(), {2: 3, 3: 4}
        )
        self.assertEqual(calls, [b"\x21\x02", b"\x21\x04"])

    def test_dynamic_pid_length_subtracts_full_request_both_source_builds(self):
        for source_build in (12, 18):
            for family in ("normal", "ext"):
                for kind, request, bitmap, data in (
                    (1, "2100", "610080", "6101aabb"),
                    (3, "21000000", "610080000000", "61000001aabb"),
                ):
                    with self.subTest(
                        source_build=source_build, family=family, kind=kind
                    ):
                        selected = profile(
                            {3: (sup(0),), 6: (pid(1, 0),)}, bytes.fromhex(request)
                        )
                        calls = []

                        def exchange(query, calls=calls, bitmap=bitmap, data=data):
                            calls.append(query.request)
                            return bytes.fromhex(bitmap if len(calls) == 1 else data)

                        cache = MonitorSupportCache(
                            selected, exchange, "dynamic", source_build=source_build
                        )
                        self.assertEqual(
                            cache.enabled_pids(family=family, kind=kind), {1: 2}
                        )
                        self.assertEqual(len(calls), 2)
                        self.assertEqual(calls[-1][-1], 1)

    def test_no_frame_number_derives_reply_header_from_base_pid_length(self):
        for source_build in (12, 18):
            for length, reply, expected in (
                (4, "610080000000", {0: 4, 1: 2}),
                (4, "61000780000000", {0: 4, 1: 2}),
                (0, "61000780000000", {0: 4, 1: 2}),
            ):
                with self.subTest(
                    source_build=source_build, length=length, reply=reply
                ):
                    selected = profile(
                        {3: (sup(0),), 6: (pid(0, length), pid(1, 2))}, b"\x21\0\0"
                    )
                    exchange = Mock(return_value=bytes.fromhex(reply))
                    cache = MonitorSupportCache(
                        selected, exchange, "no-frame", source_build=source_build
                    )
                    self.assertEqual(
                        cache.enabled_pids(family="no_frame_number", kind=3, control=7),
                        expected,
                    )
                    self.assertEqual(exchange.call_count, 1)
                    self.assertEqual(exchange.call_args.args[0].request, b"\x21\0\x07")
            for rows in ((pid(0, 1),), (pid(1, 2),)):
                cache = MonitorSupportCache(
                    profile({3: (sup(0),), 6: rows}, b"\x21\0\0"),
                    Mock(return_value=bytes.fromhex("610080000000")),
                    "no-frame-invalid",
                    source_build=source_build,
                )
                with self.assertRaises(ToyotaCodecError) as raised:
                    cache.enabled_pids(family="no_frame_number", kind=3, control=7)
                self.assertEqual(raised.exception.code, 0xA0040202)

    def test_no_frame_number_four_byte_and_nonfreeze_source_branches(self):
        for source_build in (12, 18):
            for kind in (1, 2, 3):
                definitions = (
                    {7: (bytes((0, 0, 0, 0, 2, 2, 0, 0)),)}
                    if kind == 2
                    else {6: (pid(1 if kind == 3 else 2, 2),)}
                )
                selected = profile(
                    {3: (sup(0),), 4: (sup(0),), **definitions}, b"\x21\0\0\0"
                )
                reply = "610080000000" if kind == 3 else "610000000000"
                exchange = Mock(return_value=bytes.fromhex(reply))
                cache = MonitorSupportCache(
                    selected, exchange, "four-byte", source_build=source_build
                )
                self.assertEqual(
                    cache.enabled_pids(family="no_frame_number", kind=kind, control=7),
                    {1 if kind == 3 else 2: 2},
                )
                self.assertEqual(
                    exchange.call_args.args[0].request,
                    bytes.fromhex("21070000" if kind == 3 else "21000000"),
                )
            cache = MonitorSupportCache(
                profile({3: (sup(0),), 6: (pid(1, 2),)}, b"\x21\0"),
                Mock(return_value=bytes.fromhex("610080")),
                "nonfreeze",
                source_build=source_build,
            )
            with self.assertRaises(ToyotaCodecError) as raised:
                cache.enabled_pids(family="no_frame_number", kind=1)
            self.assertEqual(raised.exception.code, 0xC0040001)

    def test_mode35_page_escape_prefix_truncation_and_cache(self):
        rows = (freeze(12, 1, 0, 7), freeze(12, 2, 8, 15), freeze(13, 4, 0, 7))
        selected = profile({10: rows}, b"\x35\0\0\0\1")
        calls = []

        def exchange(query):
            calls.append(query.request)
            if query.request == b"\x35\0\0\0\1":
                return b"\x75\0\0\0\0\0\x04\x0c\x01\x02\xff"
            return b"\x75\0\xff\0\0\0\x04\x0d\x04\x09\x04"

        cache = MonitorSupportCache(selected, exchange, "e")
        self.assertEqual(cache.mode35(), {12: b"\1\2", 13: b"\4"})
        self.assertEqual(cache.mode35(), {12: b"\1\2", 13: b"\4"})
        self.assertEqual(calls, [b"\x35\0\0\0\1", b"\x35\0\0\0\2"])
        self.assertEqual(cache.frame_map(12).total_bits, 16)

    def test_mode35_shared_status_and_category_isolation(self):
        for build in (12, 18):
            for missing in (False, True):
                rows = {} if missing else {10: (freeze(12, 1, 0, 7),)}
                selected = profile(rows, bytes.fromhex("3500000001"))
                exchange = Mock(return_value=bytes.fromhex("7500ff000000020c01"))
                owner = MonitorSupportCache(
                    selected, exchange, "owner", source_build=build
                )
                sibling = MonitorSupportCache(
                    selected, exchange, "alias", source_build=build
                )
                sibling.share_discovery_cache(owner)
                for cache in (owner, sibling, owner):
                    if missing:
                        with self.assertRaises(ToyotaCodecError) as raised:
                            cache.mode35()
                        self.assertEqual(raised.exception.code, 0xA0030107)
                    else:
                        self.assertEqual(cache.mode35(), {12: b"\x01"})
                self.assertEqual(exchange.call_count, 1)
                other = profile(
                    {10: (freeze(12, 1, 0, 7),)}, bytes.fromhex("3500000001")
                )
                other.category = 8
                separate = MonitorSupportCache(
                    other, exchange, "other", source_build=build
                )
                separate.share_discovery_cache(owner)
                self.assertEqual(separate.mode35(), {12: b"\x01"})
                self.assertEqual(exchange.call_count, 2)
                selected.exception_ids = (4,)
                with self.assertRaisesRegex(SessionError, "identity"):
                    sibling.mode35()

    def test_mode35_early_template_failure_is_not_cached(self):
        selected = profile({10: ()}, b"\x35")
        exchange = Mock(side_effect=AssertionError("Invalid template must not send"))
        cache = MonitorSupportCache(selected, exchange, "early-error")
        for _ in range(2):
            with self.assertRaises(ToyotaCodecError) as raised:
                cache.mode35()
            self.assertEqual(raised.exception.code, 0xC0040102)
        self.assertEqual(selected.frame_records.call_count, 2)
        exchange.assert_not_called()

    def test_mode35_local_temp_never_reads_or_replaces_ever_or_other_temp(self):
        selected = profile({10: (freeze(3, 9, 0, 7),)}, bytes.fromhex("3500000001"))
        replies = iter(
            bytes.fromhex("7500ff0000000203" + item) for item in ("07", "08", "09")
        )
        calls = []

        def exchange(query):
            calls.append(query.request)
            return next(replies)

        cache = MonitorSupportCache(selected, exchange, "mode35-scope")
        frame = selected.frame_records(0xCB)[0]
        request = frame.frame.request
        temporary = cache.transaction(frame, request, cached=False, temporary=True)
        ever = cache.transaction(frame, request)
        self.assertEqual(cache.mode35(), {3: bytes((9,))})
        self.assertEqual(cache.transaction(frame, request), ever)
        self.assertEqual(
            cache.transaction(frame, request, cached=False, temporary=True), temporary
        )
        self.assertEqual(calls, [request, request, request])

    def test_budget_cancel_source_and_truncated_pages_fail(self):
        selected = profile({6: (pid(2, 0), pid(3, 0))})
        exchange = Mock(return_value=b"\x61\0\xaa")
        cache = MonitorSupportCache(
            selected, exchange, "e", limits=Limits(exchanges=1, seconds=5)
        )
        with self.assertRaises(SessionError):
            cache.valid_ids()
        self.assertEqual(exchange.call_count, 1)
        cache = MonitorSupportCache(selected, exchange, "e")
        selected.exception_ids = (4,)
        with self.assertRaisesRegex(SessionError, "identity"):
            cache.valid_ids()
        with self.assertRaises(Cancelled):
            MonitorSupportCache(selected, exchange, "e", cancelled=lambda: True)
        selected = profile({10: ()}, b"\x35\0\0\0\1")
        with self.assertRaises(ToyotaCodecError):
            MonitorSupportCache(selected, lambda _: b"\x75", "e").mode35()

    def test_packed_geometry_and_missing_identifier(self):
        rows = (freeze(12, 1, 0, 0), freeze(12, 2, 1, 1), freeze(12, 3, 16, 23))
        result = mode35_frame_map(12, b"\1\2\3", rows)
        self.assertEqual(result.positions, (7, 6, 8))
        self.assertEqual(result.widths, (1, 1, 8))
        self.assertEqual(result.total_bits, 16)
        self.assertEqual(result.position(rows[0]), (7, 7))
        with self.assertRaises(ToyotaCodecError):
            mode35_frame_map(12, b"\4", rows)

    def test_native_mixed_signed_offset_comparison(self):
        rows = (freeze(12, 2, 9, 9), freeze(12, 2, 1, 1))
        result = mode35_frame_map(12, bytes((2,)), rows)
        self.assertEqual(result.widths, (8,))
        self.assertEqual(result.total_bits, 8)

    def test_send_only_success_caches_empty_and_native_fault_cannot_hide_cancel(self):
        selected = profile({})
        frame = selected.frame_records(1)[0]
        calls = []
        cache = MonitorSupportCache(
            selected, lambda query: calls.append(query.request) or b"", "send-only"
        )
        self.assertEqual(cache.transaction(frame, b""), b"")
        self.assertTrue(cache.response_cached(b""))
        with self.assertRaises(ToyotaCodecError) as raised:
            cache.transaction(frame, b"")
        self.assertEqual(raised.exception.code, 0x91010009)
        self.assertEqual(calls, [b""])
        state = [False]

        def cancelled_timeout(query):
            state[0] = True
            raise ToyotaCodecError("native timeout at cancellation", 0x91010009)

        cache = MonitorSupportCache(
            selected, cancelled_timeout, "cancel-fault", cancelled=lambda: state[0]
        )
        with self.assertRaises(Cancelled):
            cache.transaction(frame, b"\x21\0")
        state[0] = False
        self.assertFalse(cache.response_cached(b"\x21\0"))

    def test_mutable_observation_is_rejected_before_caching(self):
        selected = profile({6: (pid(1, 0),)})
        raw = bytearray.fromhex("6101aa")
        cache = MonitorSupportCache(selected, Mock(return_value=raw), "e")
        with self.assertRaisesRegex(TypeError, "immutable"):
            cache.valid_ids()
        self.assertEqual(cache._responses, {})

    def test_native_cache_first_reply_ignores_function_timer_and_option_changes(self):
        selected = profile({6: (pid(1),)})
        exchange = Mock(return_value=b"\x61\1\xaa")
        cache = MonitorSupportCache(selected, exchange, "e")
        first = selected.frame_records(15)[0]
        second = SelectedFrame(
            CommandFrame(b"\x21\1"),
            b"other-function",
            b"other-comm",
            b"other-timers",
            "authored",
        )
        self.assertEqual(
            cache.transaction(first, b"\x21\1", native_parameter=7), b"\x61\1\xaa"
        )
        self.assertEqual(
            cache.transaction(second, b"\x21\1", native_parameter=9), b"\x61\1\xaa"
        )
        self.assertEqual(exchange.call_count, 1)
        self.assertEqual(exchange.call_args.args[0].native_parameter, 7)
        selected.category_record = b"changed-protocol"
        with self.assertRaisesRegex(SessionError, "identity"):
            cache.transaction(first, b"\x21\1")


class SupportStreamDriver:
    def __init__(self, receives, sends=(0,)):
        self.receives, self.sends = list(receives), list(sends)
        self.events = []

    def send(self, query):
        self.events.append(("send", query))
        return self.sends.pop(0)

    def receive(self, query):
        self.events.append(("receive", query))
        return self.receives.pop(0)


class StreamTests(unittest.TestCase):
    def test_shared_discovery_support_slots_and_category_are_separate(self):
        for build in (12, 18):
            selected = self.selected()
            stream = SupportStreamDriver(
                [
                    (0, bytes.fromhex("42000101aa")),
                    (0x91010009, b""),
                    (0, bytes.fromhex("41000201bb")),
                    (0x91010009, b""),
                    (0, bytes.fromhex("42000301cc")),
                    (0x91010009, b""),
                ],
                sends=(0, 0, 0),
            )
            owner = MonitorSupportCache(
                selected, Mock(), "owner", source_build=build, stream=stream, bus_id=9
            )
            sibling = MonitorSupportCache(
                selected, Mock(), "alias", source_build=build, stream=stream, bus_id=10
            )
            sibling.share_discovery_cache(owner)
            self.assertEqual(owner.support_bits(2), {1: b"\xaa"})
            self.assertEqual(sibling.support_bits(2), {1: b"\xaa"})
            self.assertEqual(sibling.support_bits(1), {2: b"\xbb"})
            other = self.selected()
            other.category = 8
            separate = MonitorSupportCache(
                other, Mock(), "other", source_build=build, stream=stream, bus_id=9
            )
            separate.share_discovery_cache(owner)
            self.assertEqual(separate.support_bits(2), {3: b"\xcc"})
            self.assertEqual(owner.support_bits(2), {1: b"\xaa"})
            separate.invalidate_a8(2)
            self.assertEqual(owner.support_bits(2), {1: b"\xaa"})
            self.assertEqual(len(stream.events), 9)
            foreign = self.selected()
            foreign.exception_ids = (9,)
            rejected = MonitorSupportCache(
                foreign, Mock(), "foreign", source_build=build
            )
            with self.assertRaisesRegex(SessionError, "another selected source"):
                rejected.share_discovery_cache(owner)

    def test_ordered_support_chunks_and_p4_dids_keep_duplicates(self):
        for build in (12, 18):
            selected = self.selected(
                {3: (sup(0),), 7: (bytes((0, 0, 0, 0, 1, 0, 0, 0)),)}
            )
            stream = SupportStreamDriver(
                [(0, bytes.fromhex("42000103aabbcc0101ff")), (0x91010009, b"")]
            )
            cache = MonitorSupportCache(
                selected,
                Mock(),
                "ordered-did",
                source_build=build,
                stream=stream,
                bus_id=9,
            )
            self.assertEqual(
                cache.support_bit_entries(2),
                ((1, bytes.fromhex("aabbcc")), (1, b"\xff")),
            )
            self.assertEqual(cache.support_bits(2), {1: bytes.fromhex("aabbcc")})
            self.assertEqual(
                cache.enabled_pid_entries(family="p4", kind=2), ((1, 3), (1, 3))
            )
            self.assertEqual(cache.enabled_pids(family="p4", kind=2), {1: 3})
            self.assertEqual(len(stream.events), 3)

    def test_pcs_operation_uses_its_own_template_bitmap_and_raw_lengths(self):
        from dataclasses import replace

        for build in (12, 18):
            for kind, request, wire, reply, expected in (
                (1, "2100", "2100", "6100c0", {1: 3, 2: 1}),
                (3, "120000", "120007", "520007c0", {1: 3, 2: 1}),
                (3, "12000000", "12070000", "5207c0000000", {1: 3, 2: 1}),
                (1, "21000000", "21000000", "6100c0000000", {2: 1}),
            ):
                selected = self.selected({3: (sup(0), sup(32, 2))})
                selected.pcs_operation_pid_records.return_value = (
                    bytes((0, 0, 99, 8)),
                )
                original = selected.frame_records.side_effect
                request_bytes = bytes.fromhex(request)

                def frames(
                    function, original=original, request=request_bytes, kind=kind
                ):
                    frame = original(function)[0]
                    return (
                        (replace(frame, frame=CommandFrame(request)),)
                        if function == (15 if kind == 1 else 14)
                        else (frame,)
                    )

                selected.frame_records.side_effect = frames
                stream = SupportStreamDriver(
                    [(0, bytes.fromhex("41000103aabbcc0201ff")), (0x91010009, b"")]
                )
                exchange = Mock(return_value=bytes.fromhex(reply))
                cache = MonitorSupportCache(
                    selected,
                    exchange,
                    "pcs",
                    source_build=build,
                    stream=stream,
                    bus_id=9,
                )
                self.assertEqual(
                    cache.pcs_operation_pids(kind=kind, control=7), expected
                )
                actual = exchange.call_args.args[0]
                self.assertEqual(
                    actual.selected.function_record, bytes((15 if kind == 1 else 14,))
                )
                self.assertEqual(actual.request, bytes.fromhex(wire))
                self.assertEqual(exchange.call_count, 1)
                selected.pcs_operation_pid_records.assert_called_with()
                self.assertEqual(
                    cache.pcs_operation_pids(kind=kind, control=7), expected
                )
                self.assertEqual(exchange.call_count, 1)
                self.assertEqual(
                    cache.pcs_operation_pids(kind=kind, control=7, force=True), expected
                )
                self.assertEqual(exchange.call_count, 2)

    def test_pcs_operation_empty_db256_skips_raw_stream_and_rejects_kind2(self):
        selected = self.selected({3: (sup(0),)})
        selected.pcs_operation_pid_records.return_value = ()
        exchange = Mock(return_value=bytes.fromhex("610080"))
        cache = MonitorSupportCache(selected, exchange, "empty-pcs")
        self.assertEqual(cache.pcs_operation_pids(), {})
        with self.assertRaises(ToyotaCodecError) as raised:
            cache.pcs_operation_pids(kind=2)
        self.assertEqual(raised.exception.code, 0xC0040001)
        self.assertEqual(exchange.call_count, 1)

    def selected(self, rows=None, retries=1):
        selected = profile(rows or {})
        selected.protocol_info.return_value = None
        settings = bytearray(16)
        struct.pack_into("<II", settings, 0, 1000, 200)
        settings[14] = retries
        selected.frame_records.side_effect = lambda function: (
            SelectedFrame(
                CommandFrame(
                    bytes((1 if function == 19 else 2 if function == 20 else 0x21, 0))
                ),
                bytes((function,)),
                b"comm",
                bytes(settings),
                "authored",
            ),
        )
        return selected

    def test_stream_literal_receive_chunks_first_match_and_terminal_timeout(self):
        selected = self.selected()
        stream = SupportStreamDriver(
            [(0, b"A\x00\x0c\x02\xaa\xbb\x0c\x01\xff\x0d\x01\xcc"), (0x91010009, b"")]
        )
        cache = MonitorSupportCache(selected, Mock(), "e", stream=stream, bus_id=9)
        self.assertEqual(cache.support_bits(), {12: b"\xaa\xbb", 13: b"\xcc"})
        self.assertEqual(cache.support_bits(), {12: b"\xaa\xbb", 13: b"\xcc"})
        self.assertEqual(len(stream.events), 3)
        send = stream.events[0][1]
        self.assertEqual(
            (
                send.query.request,
                send.parameter4,
                send.parameter5,
                send.parameter6,
                send.parameter7,
            ),
            (b"\x01\x00", 1000, 9, 0, 1),
        )
        receive = stream.events[1][1]
        self.assertEqual(
            (receive.capacity, receive.parameter4, receive.parameter5, receive.wait_ms),
            (255, 200, 0, 100),
        )

    def test_stream_retries_without_resend_after_valid_page(self):
        selected = self.selected(retries=1)
        stream = SupportStreamDriver(
            [(0, b"A\x00\x0c\x01\xaa"), (0x90020323, b""), (0x91010009, b"")]
        )
        cache = MonitorSupportCache(selected, Mock(), "e", stream=stream, bus_id=9)
        self.assertEqual(cache.support_bits(), {12: b"\xaa"})
        self.assertEqual(
            [e[0] for e in stream.events], ["send", "receive", "receive", "receive"]
        )

    def test_p4_only_queries_bit_stream_for_dynamic_zero_length(self):
        selected = self.selected({3: (sup(0),), 6: (pid(1, 0), pid(2, 3))})
        events = []

        def exchange(query):
            events.append(query.request)
            return b"a\x00\xc0"

        stream = SupportStreamDriver([(0, b"A\x00\x01\x02\xaa\xbb"), (0x91010009, b"")])
        cache = MonitorSupportCache(selected, exchange, "e", stream=stream, bus_id=9)
        self.assertEqual(cache.enabled_pids(family="p4"), {1: 2, 2: 3})
        self.assertEqual(events, [b"!\x00"])
        self.assertEqual(len(stream.events), 3)

    def test_a8_dynamic_zero_length_uses_native_request_subtraction_both_builds(self):
        for build in (12, 18):
            selected = self.selected({3: (sup(0),), 6: (pid(1, 0),)})
            stream = SupportStreamDriver(
                [(0, bytes.fromhex("4100000180")), (0x91010009, b"")]
            )
            calls = []

            def exchange(query, calls=calls):
                calls.append(query.request)
                return bytes.fromhex("6101aabb")

            cache = MonitorSupportCache(
                selected,
                exchange,
                "A8-dynamic",
                stream=stream,
                bus_id=9,
                source_build=build,
            )
            self.assertEqual(cache.enabled_pids(family="a8"), {1: 2})
            self.assertEqual(calls, [bytes.fromhex("2101")])

    def test_a8_reads_bitmap_from_actual_stream(self):
        selected = self.selected({3: (sup(0),), 6: (pid(1, 2), pid(2, 3))})
        stream = SupportStreamDriver([(0, b"A\x00\x00\x01\xc0"), (0x91010009, b"")])
        exchange = Mock(side_effect=AssertionError("A8 sends no 21 bitmap query"))
        cache = MonitorSupportCache(selected, exchange, "e", stream=stream, bus_id=9)
        self.assertEqual(cache.enabled_pids(family="a8"), {1: 2, 2: 3})
        exchange.assert_not_called()

    def test_failure_cached_without_manufactured_empty_support(self):
        selected = self.selected(retries=0)
        stream = SupportStreamDriver([(0x91010009, b"")])
        cache = MonitorSupportCache(selected, Mock(), "e", stream=stream, bus_id=9)
        for _ in range(2):
            with self.assertRaises(ToyotaCodecError) as raised:
                cache.support_bits()
            self.assertEqual(raised.exception.code, 0x91010009)
        self.assertEqual(len(stream.events), 2)

    def test_native_no_retry_uses_de_template_and_selected_retry_count(self):
        selected = self.selected(retries=1)
        stream = SupportStreamDriver(
            [(0x91010009, b""), (0, bytes.fromhex("61000c01aa")), (0x91010009, b"")],
            sends=(0, 0),
        )
        cache = MonitorSupportCache(
            selected, Mock(), "no-retry", stream=stream, bus_id=9
        )
        self.assertEqual(cache.support_bits(no_retry=True), {12: b"\xaa"})
        sends = [event[1] for event in stream.events if event[0] == "send"]
        self.assertEqual(len(sends), 2)
        self.assertTrue(
            all(send.query.selected.function_record == b"\xde" for send in sends)
        )
        self.assertEqual(cache.support_bits(), {12: b"\xaa"})
        self.assertEqual(len(stream.events), 5)

    def test_version12_uses_unconverted_receive_timer(self):
        selected = self.selected()
        selected.catalog.management.version = 0x0100030C
        selected.protocol_info.side_effect = AssertionError(
            "Version12 has no timeout conversion lookup"
        )
        stream = SupportStreamDriver([(0, b"\x41\0\x0c\1\xaa"), (0x91010009, b"")])
        cache = MonitorSupportCache(
            selected, Mock(), "e", source_build=12, stream=stream, bus_id=9
        )
        self.assertEqual(cache.support_bits(), {12: b"\xaa"})
        self.assertEqual(stream.events[1][1].parameter4, 200)

    def test_normal_unsupported_probe_initializes_with_null_send_ignoring_status(self):
        selected = self.selected({3: (sup(0),), 6: (pid(1),)})
        stream = SupportStreamDriver([], sends=(0x90020001,))
        exchange = Mock(side_effect=ToyotaCodecError("authored timeout", 0x91010009))
        cache = MonitorSupportCache(selected, exchange, "e", stream=stream, bus_id=9)
        self.assertEqual(cache.enabled_pids(family="normal"), {})
        send = stream.events[0][1]
        self.assertIsNone(send.request)
        self.assertEqual(
            (send.parameter4, send.parameter5, send.parameter6, send.parameter7),
            (1000, 9, 1, 1),
        )

    def test_native_did_rows_are_eight_bytes_and_lengths_use_byte5(self):
        selected = self.selected({4: (sup(0),), 7: (bytes((0, 0, 0, 0, 1, 3, 0, 0)),)})
        exchange = Mock(return_value=b"\x42\0\x80")
        cache = MonitorSupportCache(selected, exchange, "e")
        # Override function14 template to its literal positive service pair.
        selected.frame_records.side_effect = lambda function: (
            SelectedFrame(
                CommandFrame(b"\x02\0"),
                bytes((function,)),
                b"comm",
                bytes(16),
                "authored",
            ),
        )
        self.assertEqual(cache.enabled_pids(family="normal", kind=2), {1: 3})
        self.assertEqual(exchange.call_count, 1)

    def test_version18_can_timeout_uses_first_selected_native_record(self):
        selected = self.selected()
        protocol = bytearray(28)
        struct.pack_into("<H", protocol, 2, 4)
        protocol[26] = 1
        selected.protocol_info.return_value = bytes(protocol)
        can = bytearray(28)
        struct.pack_into("<H", can, 14, 789)
        selected.comm_info_can_records.return_value = (bytes(can),)
        stream = SupportStreamDriver([(0, b"\x41\0\x0c\1\xaa"), (0x91010009, b"")])
        cache = MonitorSupportCache(selected, Mock(), "e", stream=stream, bus_id=9)
        self.assertEqual(cache.support_bits(), {12: b"\xaa"})
        self.assertEqual(stream.events[1][1].parameter4, 789)
        selected.comm_info_can_records.assert_called_once_with(4)

    def test_p4_ignore_wrapper_has_exact_broader_communication_status_set(self):
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
            with self.subTest(status=hex(status)):
                selected = self.selected({3: (sup(0), sup(32)), 6: (pid(33, 2),)})
                stream = SupportStreamDriver([], sends=(0,))

                def exchange(query, error_code=status):
                    if query.request == b"\x21\0":
                        raise ToyotaCodecError("authored recoverable", error_code)
                    return b"\x61\x20\x80"

                cache = MonitorSupportCache(
                    selected, exchange, "e", stream=stream, bus_id=9
                )
                self.assertEqual(cache.enabled_pids(family="p4_ignore"), {33: 2})
                self.assertIsNone(stream.events[0][1].request)

    def test_valid_ext_timeout_initializes_before_next_support_page(self):
        selected = self.selected({3: (sup(0), sup(32)), 6: (pid(33, 2),)})
        stream = SupportStreamDriver([], sends=(0,))

        def exchange(query):
            if query.request == b"\x21\0":
                raise ToyotaCodecError("authored timeout", 0x91010009)
            return b"\x61\x20\x80"

        cache = MonitorSupportCache(selected, exchange, "e", stream=stream, bus_id=9)
        self.assertEqual(cache.valid_ids(), {33: 2})
        self.assertIsNone(stream.events[0][1].request)

    def test_valid_ext_requires_a_data_byte_beyond_receive_offset(self):
        selected = self.selected({3: (sup(0),), 6: (pid(0),)})
        cache = MonitorSupportCache(selected, Mock(return_value=b"\x61\0"), "e")
        with self.assertRaises(ToyotaCodecError) as raised:
            cache.valid_ids()
        self.assertEqual(raised.exception.code, 0xA0040202)

    def test_native_error_cache_replays_timeout_without_reinitializing(self):
        selected = self.selected({3: (sup(0),), 6: (pid(1),)})
        stream = SupportStreamDriver([], sends=(0,))
        exchange = Mock(
            side_effect=ToyotaCodecError("authored no response", 0x90020323)
        )
        cache = MonitorSupportCache(selected, exchange, "e", stream=stream, bus_id=9)
        self.assertEqual(cache.enabled_pids(family="normal"), {})
        self.assertEqual(cache.enabled_pids(family="normal"), {})
        self.assertEqual(exchange.call_count, 1)
        self.assertEqual(len(stream.events), 1)
        frame = selected.frame_records(15)[0]
        with self.assertRaises(ToyotaCodecError) as raised:
            cache.transaction(frame, b"\x21\0")
        self.assertEqual(raised.exception.code, 0x91010009)


class OperationBudgetEverTests(unittest.TestCase):
    def test_explicit_native_ever_owner_shares_source_not_display_name(self):
        selected = profile({})
        frame = selected.frame_records(15)[0]
        owner_exchange = Mock(return_value=bytes.fromhex("610180"))
        owner = MonitorSupportCache(selected, owner_exchange, "first-bus-name")
        sibling_exchange = Mock(
            side_effect=AssertionError("Native Ever hit must not query second bus")
        )
        sibling = MonitorSupportCache(selected, sibling_exchange, "second-bus-name")
        sibling.share_ever_cache(owner)
        self.assertEqual(owner.transaction(frame, b"\x21\x01"), bytes.fromhex("610180"))
        self.assertEqual(
            sibling.transaction(frame, b"\x21\x01"), bytes.fromhex("610180")
        )
        sibling_exchange.assert_not_called()
        self.assertEqual(owner_exchange.call_count, 1)
        sibling.share_ever_cache(owner)
        independent = MonitorSupportCache(
            selected, Mock(return_value=bytes.fromhex("610180")), "other-owner"
        )
        independent.transaction(frame, b"\x21\x01")
        with self.assertRaisesRegex(SessionError, "already populated"):
            independent.share_ever_cache(owner)
        with self.assertRaisesRegex(SessionError, "another selected source"):
            MonitorSupportCache(
                selected, Mock(), "wrong-build", source_build=12
            ).share_ever_cache(owner)


class SelectedVehicleStorageTests(unittest.TestCase):
    @staticmethod
    def caches(*categories):
        catalog = cast(
            VehicleCatalog,
            SimpleNamespace(management=SimpleNamespace(sha256="selected-management")),
        )
        category_rows = {
            category: bytes(68) + category.to_bytes(2, "little") + bytes(10)
            for category in categories
        }
        catalog.build_protocol_profile = lambda category, exception_ids=(): (
            ProtocolProfile(catalog, category_rows[category], tuple(exception_ids))
        )

        def make(category, exchange):
            selected = profile({})
            selected.catalog = catalog
            selected.category = category
            selected.category_record = category_rows[category]
            selected.vehicle_name_key = 42
            selected.exception_ids = (3,)
            return MonitorSupportCache(selected, exchange, "selected-ecu"), selected

        return catalog, make

    def test_selected_category_alias_reads_literal_ever_and_temp_stays_local(self):
        catalog, make = self.caches(7)
        owner_exchange = Mock(return_value=b"\x61\x01\x80")
        owner, _ = make(7, owner_exchange)
        target_exchange = Mock(return_value=b"\x61\x02\x80")
        target, selected = make(7, target_exchange)
        scope = monitor_source_identity(
            catalog.build_protocol_profile(7, exception_ids=(3,)), "selected-ecu"
        )[1:]
        owner._responses[(*scope, b"\x21\x01")] = b"\x61\x01\x80"
        target._bind_selected_vehicle_storage(
            owner,
            protocol_profile=catalog.build_protocol_profile(7, exception_ids=(3,)),
        )
        self.assertIs(target._responses, owner._responses)
        frame = selected.frame_records(15)[0]
        self.assertEqual(target.transaction(frame, b"\x21\x01"), b"\x61\x01\x80")
        self.assertEqual(target_exchange.call_count, 0)
        target.transaction(frame, b"\x21\x02", cached=False, temporary=True)
        self.assertNotIn((*target._response_scope, b"\x21\x02"), owner._responses)
        self.assertEqual(target_exchange.call_count, 1)

    def test_selected_category_alias_retains_support_and_mode35_status(self):
        catalog, make = self.caches(7)
        owner, _ = make(7, Mock())
        target, _ = make(7, Mock(side_effect=AssertionError("cached discovery")))
        scope = monitor_source_identity(
            catalog.build_protocol_profile(7, exception_ids=(3,)), "selected-ecu"
        )[1:]
        owner._support_bits[(*scope, 2)] = (0, ((1, b"\xaa"),))
        owner._mode35[scope] = (0xA0030107, ())
        target._bind_selected_vehicle_storage(
            owner,
            protocol_profile=catalog.build_protocol_profile(7, exception_ids=(3,)),
        )
        self.assertEqual(target.support_bits(2), {1: b"\xaa"})
        with self.assertRaises(ToyotaCodecError) as raised:
            target.mode35()
        self.assertEqual(raised.exception.code, 0xA0030107)

    def test_different_category_misses_and_full_source_guard_precedes_hit(self):
        catalog, make = self.caches(7, 8)
        calls = []

        def exchange(query):
            calls.append(query.request)
            return b"\x61\x01\x80"

        owner, _ = make(7, exchange)
        other, other_profile = make(8, exchange)
        category7_scope = monitor_source_identity(
            catalog.build_protocol_profile(7, exception_ids=(3,)), "selected-ecu"
        )[1:]
        owner._responses[(*category7_scope, b"\x21\x01")] = b"\x61\x01\x80"
        other._bind_selected_vehicle_storage(
            owner,
            protocol_profile=catalog.build_protocol_profile(8, exception_ids=(3,)),
        )
        frame = other_profile.frame_records(15)[0]
        self.assertEqual(other.transaction(frame, b"\x21\x01"), b"\x61\x01\x80")
        self.assertEqual(calls, [b"\x21\x01"])
        other_profile.ecu_database_sha256 = "changed-after-hit"
        with self.assertRaisesRegex(SessionError, "identity changed"):
            other.transaction(frame, b"\x21\x01")
        self.assertEqual(calls, [b"\x21\x01"])

    def test_foreign_catalog_and_populated_target_reject_before_alias(self):
        catalog, make = self.caches(7)
        owner, _ = make(7, Mock())
        target, selected = make(7, Mock(return_value=b"\x61\x01\x80"))
        _, foreign_make = self.caches(7)
        foreign, _ = foreign_make(7, Mock())
        with self.assertRaisesRegex(SessionError, "another source"):
            target._bind_selected_vehicle_storage(
                foreign,
                protocol_profile=catalog.build_protocol_profile(7, exception_ids=(3,)),
            )
        self.assertIsNot(target._responses, owner._responses)
        frame = selected.frame_records(15)[0]
        target.transaction(frame, b"\x21\x01")
        with self.assertRaisesRegex(SessionError, "populated"):
            target._bind_selected_vehicle_storage(
                owner,
                protocol_profile=catalog.build_protocol_profile(7, exception_ids=(3,)),
            )

    def test_generic_sibling_inherits_namespace_using_its_own_category(self):
        catalog, make = self.caches(7, 8)
        owner, _ = make(7, Mock())
        bound, _ = make(7, Mock())
        bound._bind_selected_vehicle_storage(
            owner,
            protocol_profile=catalog.build_protocol_profile(7, exception_ids=(3,)),
        )
        calls = []
        sibling, selected = make(
            8,
            lambda query: calls.append(query.request) or b"\x61\x01\x80",
        )
        sibling.share_ever_cache(bound)
        sibling.share_discovery_cache(bound)
        expected_scope = monitor_source_identity(
            catalog.build_protocol_profile(8, exception_ids=(3,)), "selected-ecu"
        )[1:]
        self.assertTrue(sibling._native_storage_namespace)
        self.assertEqual(sibling._response_scope, expected_scope)
        self.assertEqual(sibling._discovery_scope, expected_scope)
        self.assertEqual(
            sibling.transaction(selected.frame_records(15)[0], b"\x21\x01"),
            b"\x61\x01\x80",
        )
        self.assertEqual(calls, [b"\x21\x01"])


class OperationBudgetTests(unittest.TestCase):
    def test_active_temporary_observations_keep_order_empty_and_scope_identity(self):
        selected = profile({})
        frame = selected.frame_records(15)[0]
        exchange = Mock(
            side_effect=[
                b"\x61\x02\xaa",
                ToyotaCodecError("authored no response", 0x90020323),
            ]
        )
        cache = MonitorSupportCache(selected, exchange, "capture")
        with cache.temporary_scope():
            cache.transaction(frame, b"\x21\x02", cached=False, temporary=True)
            with self.assertRaises(ToyotaCodecError):
                cache.transaction(frame, b"\x21\x01", cached=False, temporary=True)
            cache.transaction(frame, b"\x21\x02", cached=False, temporary=True)
            captured = cache.temporary_observations()
            self.assertEqual(
                captured, ((b"\x21\x02", b"\x61\x02\xaa"), (b"\x21\x01", b""))
            )
            with cache.temporary_scope():
                self.assertEqual(cache.temporary_observations(), ())
            self.assertEqual(cache.temporary_observations(), captured)
            selected.exception_ids = (4,)
            with self.assertRaises(SessionError):
                cache.temporary_observations()
            selected.exception_ids = (3,)
        self.assertEqual(cache.temporary_observations(), ())
        self.assertEqual(captured, ((b"\x21\x02", b"\x61\x02\xaa"), (b"\x21\x01", b"")))
        self.assertEqual(exchange.call_count, 2)

    def test_nonfinite_initial_clock_and_deadline_overflow_fail_before_io(self):
        for initial, seconds in (
            (float("nan"), 10),
            (float("inf"), 10),
            (-float("inf"), 10),
            (1e308, 1e308),
        ):
            exchange = Mock()
            readings = iter((initial, 1.0, 1.0))
            with self.assertRaises(SessionError):
                MonitorSupportCache(
                    profile({}),
                    exchange,
                    "clock",
                    clock=lambda readings=readings: next(readings),
                    limits=Limits(seconds=seconds),
                )
            exchange.assert_not_called()
            driver = PacketDriver([], [])
            readings = iter((initial, 1.0, 1.0))
            packet = PacketFrameCache(
                driver,
                source_identity=("clock",),
                send_timer=1,
                receive_timer=1,
                retries=0,
                clock=lambda readings=readings: next(readings),
                limits=Limits(seconds=seconds),
            )
            with self.assertRaises(SessionError):
                packet.get_packet_frame(7, 9, source_identity=("clock",))
            self.assertEqual(driver.events, [])
        readings = iter((0.0, 0.0, 1e308, 1.0))
        cache = MonitorSupportCache(
            profile({}),
            Mock(),
            "overflow",
            clock=lambda readings=readings: next(readings),
        )
        with self.assertRaises(SessionError):
            cache.begin_operation(limits=Limits(seconds=1e308))

    def test_new_operation_retains_native_cache_but_rejects_changed_context(self):
        selected = profile({6: (pid(1, 0),)})
        now = [0.0]
        calls = []

        def exchange(query):
            calls.append(query.request)
            return bytes.fromhex("6101aa")

        cache = MonitorSupportCache(
            selected,
            exchange,
            "operation",
            limits=Limits(seconds=1),
            clock=lambda: now[0],
        )
        self.assertEqual(cache.valid_ids(), {1: 1})
        now[0] = 2
        cache.begin_operation()
        self.assertEqual(cache.valid_ids(), {1: 1})
        self.assertEqual(len(calls), 1)
        self.assertEqual(cache.calls, 0)
        selected.category_record += b"changed"
        with self.assertRaises(SessionError):
            cache.begin_operation()


class DataIdSupportTests(unittest.TestCase):
    def test_dword_designation_count_keeps_seed_and_expansion_duplicates(self):
        selected = self.selected()
        exchange = Mock(return_value=bytes.fromhex("62f30080"))
        cache = MonitorSupportCache(
            selected, exchange, "dword-designation", limits=Limits(seconds=60)
        )
        result = cache.data_ids(family="designation", designation=(0xF300,) * 65536)
        self.assertEqual(result.identifiers, (0xF300,) * 65536 + (0xF301,) * 65536)
        self.assertEqual(exchange.call_count, 1)

        class Overflow(tuple):
            def __len__(self):
                return 0x100000000

        with self.assertRaisesRegex(ValueError, "DWORD count"):
            cache.data_ids(family="designation", designation=Overflow())
        with self.assertRaisesRegex(ValueError, "DWORD count"):
            cache.data_ids(family="no_cache", excluded=Overflow())
        with self.assertRaisesRegex(ValueError, "DWORD count"):
            cache.subaru_did_support(Overflow())

    def test_automatic_mazda_ignores_helper_failure_and_caches_partial_output(self):
        from dataclasses import replace

        for source_build in (12, 18):
            for family in (
                ("normal", "with_bus_id", "no_cache")
                if source_build == 18
                else ("normal",)
            ):
                for partial in (False, True):
                    selected = self.selected()
                    category = bytearray(selected.category_record)
                    category[72] = 21
                    selected.category_record = bytes(category)
                    if partial:
                        selected.database.sections[61] = None
                        selected.records.side_effect = lambda slot: (
                            (bytes.fromhex("0000341200000000"),) if slot == 61 else ()
                        )
                        selected.catalog.management = replace(
                            selected.catalog.management, sections={}
                        )
                    else:
                        selected.frame_records.side_effect = ValueError(
                            "No selected function communication frames"
                        )
                    exchange = Mock(return_value=bytes.fromhex("621234aabb"))
                    cache = MonitorSupportCache(
                        selected, exchange, "mazda-auto", source_build=source_build
                    )
                    result = cache.data_ids(family=family)
                    self.assertEqual(result.identifiers, (0x1234,) if partial else ())
                    self.assertEqual(result.lengths, ())
                    self.assertEqual(result.suppressed_errors, ())
                    self.assertEqual(cache._data_id_lengths, {})
                    self.assertEqual(cache.data_ids(family=family), result)
                    self.assertEqual(exchange.call_count, 1 if partial else 0)
                    with self.assertRaises(ToyotaCodecError) as raised:
                        cache.data_ids(family="mazda")
                    self.assertEqual(
                        raised.exception.code, 0xA0030107 if partial else 0xC0040101
                    )

    def selected(self, rows=None):
        from scripts.diagnostic_db import Database, Section

        selected = profile(rows or {}, b"\x22\0\0")
        selected.category_record = bytes(73)
        selected.catalog.management = Database(
            1, 0x0100032F, "authored-management", {20: Section(20, 0, 0, False, b"")}
        )
        return selected

    def test_build12_missing_families_are_not_silently_executed_as_build18(self):
        selected = self.selected()
        exchange = Mock(side_effect=AssertionError("Absent build12 API must not query"))
        cache = MonitorSupportCache(selected, exchange, "build12", source_build=12)
        for family in ("with_bus_id", "subaru", "no_cache"):
            with self.subTest(family=family), self.assertRaises(SessionError):
                cache.data_ids(family=family)
        with self.assertRaises(SessionError):
            cache.subaru_did_support((0x201,))
        with self.assertRaises(SessionError):
            cache.data_id_support_status(0x101)
        self.assertEqual(
            cache.send_support_comm(0x104, 0x101, 0, 0, 0).status, 0xC0040102
        )
        self.assertEqual(
            cache.send_support_comm(0x10E, 0x201, 0, 0, 0).status, 0xC0040102
        )
        exchange.assert_not_called()

    def test_c8_root_groups_literal_wire_and_partial_cache(self):
        selected = self.selected()
        calls = []

        def exchange(query):
            calls.append(query)
            if query.request == bytes.fromhex("220000"):
                return bytes.fromhex("62000040")  # upper group0100
            raise ToyotaCodecError("authored group unsupported", 0x90020321)

        cache = MonitorSupportCache(selected, exchange, "did")
        result = cache.data_ids()
        self.assertEqual(result.identifiers, (0x100,))
        self.assertEqual(
            result.suppressed_errors, ((bytes.fromhex("220100"), 0x90020321),)
        )
        self.assertEqual([q.request.hex() for q in calls], ["220000", "220100"])
        self.assertTrue(all(q.extended for q in calls))
        self.assertEqual(cache.data_ids(), result)
        self.assertEqual(len(calls), 2)

    def test_designation_bitmap_start_one_and_last_continuation_excluded(self):
        selected = self.selected()
        calls = []

        def exchange(query):
            calls.append(query.request)
            return bytes.fromhex("62010080") + bytes(30) + b"\x03"

        result = MonitorSupportCache(selected, exchange, "did").data_ids(
            family="designation", designation=(0x100,)
        )
        self.assertEqual(calls, [bytes.fromhex("220100")])
        self.assertEqual(result.identifiers, (0x100, 0x101, 0x1FF))

    def test_mazda_subaru_selected_candidates_and_observed_lengths(self):
        first, second = bytearray(8), bytearray(12)
        struct.pack_into("<H", first, 2, 0x1234)
        struct.pack_into("<H", second, 2, 0xABCD)
        selected = self.selected({61: (bytes(first),), 67: (bytes(second),)})
        calls = []

        def exchange(query):
            calls.append(query.request)
            if query.request == bytes.fromhex("221234"):
                return bytes.fromhex("621234aabb")
            raise ToyotaCodecError("authored absent DID", 0x90020321)

        cache = MonitorSupportCache(selected, exchange, "did")
        result = cache.data_ids(family="subaru")
        self.assertEqual(result.identifiers, (0x1234,))
        self.assertEqual(result.lengths, ((0x1234, 2),))
        self.assertEqual(calls, [bytes.fromhex("221234"), bytes.fromhex("22abcd")])
        self.assertEqual(cache.data_ids(family="subaru").identifiers, (0x1234,))
        self.assertEqual(len(calls), 2)
        # Mazda uses successful length membership but retries failed candidates.
        self.assertEqual(cache.data_ids(family="mazda").identifiers, ())
        self.assertEqual(calls[-1], bytes.fromhex("22abcd"))

    def test_subaru_support_continuation_pages_and_attempted_timeout_cache(self):
        selected = self.selected()
        calls = []

        def exchange(query):
            calls.append(query.request)
            if query.request == bytes.fromhex("220200"):
                return bytes.fromhex("62020080000001")
            raise ToyotaCodecError("authored terminal timeout", 0x91010009)

        cache = MonitorSupportCache(selected, exchange, "subaru-pages")
        result = cache.subaru_did_support((0x241, 0x1001))
        self.assertEqual(result.identifiers, (0x201, 0x220))
        self.assertEqual([request.hex() for request in calls], ["220200", "220220"])
        self.assertEqual(
            result.suppressed_errors, ((bytes.fromhex("220220"), 0x91010009),)
        )
        self.assertEqual(
            cache.subaru_did_support((0x241,)).identifiers, result.identifiers
        )
        self.assertEqual(len(calls), 2)
        self.assertEqual(cache.data_ids().identifiers, result.identifiers)

    def test_no_cache_class_uses_own_enable_cache_temp_wire_and_excluded_groups(self):
        selected = self.selected()
        calls = []

        def exchange(query):
            calls.append(query.request)
            return (
                bytes.fromhex("62000040")
                if len(calls) == 1
                else bytes.fromhex("62000020")
                if len(calls) == 2
                else bytes.fromhex("62020000")
            )

        cache = MonitorSupportCache(selected, exchange, "separate")
        self.assertEqual(
            cache.data_ids(family="no_cache", excluded=(0x100,)).identifiers, (0x100,)
        )
        self.assertEqual(cache.data_ids().identifiers, (0x200,))
        cache.begin_operation()
        self.assertEqual(cache.data_ids(family="no_cache").identifiers, (0x100,))
        self.assertEqual(
            [request.hex() for request in calls], ["220000", "220000", "220200"]
        )

    def test_no_cache_default_local_and_explicit_supplied_response_instances(self):
        for supplied in (False, True):
            selected = self.selected()
            exchange = Mock(
                side_effect=[bytes.fromhex("62000040"), bytes.fromhex("62000020")]
            )
            cache = MonitorSupportCache(selected, exchange, "no-cache-scope")
            frame = selected.frame_records(0xC8)[0]
            instance = cache.new_temporary_cache()
            if supplied:
                with cache.temporary_scope(instance):
                    cache.transaction(
                        frame, frame.frame.request, cached=False, temporary=True
                    )
            else:
                cache.transaction(
                    frame, frame.frame.request, cached=False, temporary=True
                )
            result = cache.data_ids(
                family="no_cache",
                excluded=(0x100, 0x200),
                response_cache=instance if supplied else None,
            )
            self.assertEqual(result.identifiers, (0x100,) if supplied else (0x200,))
            self.assertEqual(exchange.call_count, 1 if supplied else 2)
            self.assertEqual(
                cache.response_cached(frame.frame.request, temporary=True), not supplied
            )
            foreign = MonitorSupportCache(
                selected, Mock(), "foreign"
            ).new_temporary_cache()
            with self.assertRaisesRegex(SessionError, "another selected context"):
                cache.data_ids(family="no_cache", response_cache=foreign)
            with self.assertRaises(ValueError):
                cache.data_ids(response_cache=instance)

    def test_designation_temporary_cache_is_local_to_one_native_instance(self):
        selected = self.selected()
        calls = []

        def exchange(query):
            calls.append(query.request)
            return bytes.fromhex("62010080")

        cache = MonitorSupportCache(selected, exchange, "designation")
        for _ in range(2):
            self.assertEqual(
                cache.data_ids(
                    family="designation", designation=(0x100, 0x100)
                ).identifiers,
                (0x100, 0x100, 0x101, 0x101),
            )
        self.assertEqual(calls, [bytes.fromhex("220100"), bytes.fromhex("220100")])

    def test_custom_sign_item_candidates_use_actual_selected_management_rows(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        selected = self.selected()
        sign = bytearray(12)
        struct.pack_into("<H", sign, 4, 12)
        item = bytearray(52)
        struct.pack_into("<H", item, 8, 12)
        struct.pack_into("<H", item, 12, 7)
        struct.pack_into("<HHH", item, 38, 0x1111, 0x2222, 0x1111)
        selected.catalog.management = replace(
            selected.catalog.management,
            sections={
                20: Section(20, 0, 1, False, bytes(sign)),
                21: Section(21, 0, 1, False, bytes(item)),
            },
        )
        selected.custom_item_records.side_effect = lambda key: (
            VehicleProfile.custom_item_records(selected, key)
        )
        calls = []

        def exchange(query):
            calls.append(query.request)
            return b"\x62" + query.request[1:] + b"\x01"

        result = MonitorSupportCache(selected, exchange, "custom").data_ids(
            family="subaru"
        )
        self.assertEqual(result.identifiers, (0x1111, 0x2222))
        self.assertEqual([request.hex() for request in calls], ["221111", "222222"])
        self.assertEqual(result.lengths, ((0x1111, 1), (0x2222, 1)))

    def test_mazda_final_custom_probe_status_keeps_committed_lengths(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        for build in (12, 18):
            for automatic in (False, True):
                selected = self.selected()
                category = bytearray(selected.category_record)
                category[72] = 21
                selected.category_record = bytes(category)
                sign, item = bytearray(12), bytearray(52)
                struct.pack_into("<H", sign, 4, 12)
                struct.pack_into("<H", item, 8, 12)
                struct.pack_into("<H", item, 12, 7)
                struct.pack_into("<HHH", item, 38, 0x1234, 0x1234, 0x5678)
                selected.catalog.management = replace(
                    selected.catalog.management,
                    sections={
                        20: Section(20, 0, 1, False, bytes(sign)),
                        21: Section(21, 0, 1, False, bytes(item)),
                    },
                )
                selected.custom_item_records.side_effect = (
                    lambda key, selected=selected: VehicleProfile.custom_item_records(
                        selected, key
                    )
                )
                calls = []

                def exchange(query, calls=calls):
                    calls.append(query.request)
                    if query.request == bytes.fromhex("221234"):
                        return bytes.fromhex("621234aa")
                    raise ToyotaCodecError("authored final custom timeout", 0x91010009)

                cache = MonitorSupportCache(
                    selected, exchange, "custom-status", source_build=build
                )
                if automatic:
                    result = cache.data_ids()
                    self.assertEqual(result.identifiers, (0x1234,))
                    self.assertEqual(result.lengths, ((0x1234, 1),))
                else:
                    with self.assertRaises(ToyotaCodecError) as raised:
                        cache.data_ids(family="mazda")
                    self.assertEqual(raised.exception.code, 0x91010009)
                self.assertEqual(cache._data_id_lengths[7], {0x1234: 1})
                self.assertEqual(
                    calls, [bytes.fromhex("221234"), bytes.fromhex("225678")]
                )

    def test_c8_cancellation_is_not_native_suppressed_success(self):
        selected = self.selected()
        state = [False]

        def exchange(query):
            state[0] = True
            return bytes.fromhex("62000080")

        cache = MonitorSupportCache(
            selected, exchange, "did", cancelled=lambda: state[0]
        )
        with self.assertRaises(Cancelled):
            cache.data_ids()


class P5PidSupportTests(unittest.TestCase):
    def test_native_reverse_range_and_unsafe_storage_are_distinct(self):
        selected = self.selected(condition=9)
        cache = MonitorSupportCache(
            selected, Mock(return_value=bytes.fromhex("62555580")), "native-storage"
        )
        with self.assertRaises(ToyotaCodecError) as raised:
            cache._p5_condition_value(bytes.fromhex("5555"), 8, 0)
        self.assertEqual(raised.exception.code, 0xC0000001)
        with self.assertRaises(SessionError):
            cache._p5_condition_value(bytes.fromhex("5555"), 0, 8)
        bit = bytearray(16)
        bit[13:15] = bytes((7, 1))
        selected.data_id_bit_records.return_value = (bytes(bit),)
        selected.data_id_bit_variable.return_value = b"\x55"
        with self.assertRaises(SessionError):
            cache._p5_condition(selected.records(62)[0], (0x1280,), 18)

    def test_enabled_did_count_is_dword_and_first_zero_signal_is_not_skipped(self):
        selected = self.selected()
        cache = MonitorSupportCache(
            selected, Mock(return_value=bytes.fromhex("62128000")), "enabled-dword"
        )
        self.assertTrue(cache.check_support_pid(100, enabled_dids=(0x1280,) * 65536))
        selected = self.selected(condition=9)
        parent = selected.records(62)[0]
        target = bytearray(parent)
        struct.pack_into("<HH", target, 36, 0, 0)
        struct.pack_into("<H", target, 54, 0x5555)
        later = bytearray(target)
        struct.pack_into("<H", later, 36, 3)
        selected.records.side_effect = lambda slot: (
            (parent, bytes(target), bytes(later)) if slot == 62 else ()
        )
        bit = bytearray(16)
        bit[13:15] = bytes((7, 1))
        selected.data_id_bit_records.return_value = (bytes(bit),)
        selected.data_id_bit_variable.return_value = bytes.fromhex("5555")
        exchange = Mock(side_effect=AssertionError("FIRST PID0 must not query"))
        cache = MonitorSupportCache(selected, exchange, "pid-zero")
        target_check = Mock(side_effect=AssertionError("FIRST PID0 must not recurse"))
        cache.check_support_pid = target_check
        with self.assertRaises(ToyotaCodecError) as raised:
            cache._p5_condition(parent, (0x5555,), 18)
        self.assertEqual(raised.exception.code, 0xC0050101)
        exchange.assert_not_called()
        target_check.assert_not_called()

    def selected(self, *, mode=0, condition=0):
        row = bytearray(64)
        struct.pack_into("<H", row, 36, 100)
        struct.pack_into("<H", row, 38, condition)
        struct.pack_into("<H", row, 46, 0)
        struct.pack_into("<H", row, 54, 0x1280)
        definition = bytearray(8)
        struct.pack_into("<H", definition, 2, 0x1280)
        definition[6] = mode
        selected = profile({62: (bytes(row),), 61: (bytes(definition),)}, b"\x22\0\0")
        selected.category_record = bytes(73)
        return selected

    def test_native_mode1_tests_did_echo_byte_and_raw_cache_then_override(self):
        selected = self.selected(mode=1)
        calls = []

        def exchange(query):
            calls.append(query.request)
            return bytes.fromhex("62128000")

        cache = MonitorSupportCache(selected, exchange, "p5")
        self.assertTrue(cache.check_support_pid(100, enabled_dids=(0x1280,)))
        self.assertTrue(cache.check_support_pid(100, enabled_dids=()))
        self.assertEqual(calls, [bytes.fromhex("221280")])
        with self.assertRaises(ValueError):
            cache.check_support_pid(100, enabled_dids=(), source_build=12)

    def test_native_static_bit_condition_and_exact_selector_for_both_builds(self):
        for build in (12, 18):
            with self.subTest(build=build):
                selected = self.selected(condition=9)
                bit = bytearray(12 if build == 12 else 16)
                bit[11 if build == 12 else 13] = 7
                selected.data_id_bit_records.return_value = (bytes(bit),)
                selected.data_id_bit_variable.return_value = bytes.fromhex("abcd")
                calls = []

                def exchange(query, calls=calls):
                    calls.append(query.request)
                    return (
                        bytes.fromhex("62128000")
                        if query.request == bytes.fromhex("221280")
                        else bytes.fromhex("62abcd80")
                    )

                cache = MonitorSupportCache(
                    selected, exchange, "p5", source_build=build
                )
                self.assertTrue(cache.check_support_pid(100, enabled_dids=(0x1280,)))
                self.assertTrue(cache.check_support_pid(100, enabled_dids=()))
                self.assertEqual(
                    calls, [bytes.fromhex("221280"), bytes.fromhex("22abcd")]
                )

    def test_dynamic_condition_requeries_value_after_cached_support(self):
        selected = self.selected(condition=9)
        parent = selected.records(62)[0]
        target = bytearray(64)
        struct.pack_into("<H", target, 36, 3)
        struct.pack_into("<H", target, 54, 0x5555)
        first = selected.records(61)[0]
        second = bytearray(8)
        struct.pack_into("<H", second, 2, 0x5555)
        selected.database.sections.update({61: None, 62: None})
        selected.records.side_effect = lambda slot: (
            (parent, bytes(target)) if slot == 62 else (first, bytes(second))
        )
        bit = bytearray(16)
        struct.pack_into("<H", bit, 10, 1)
        bit[13:15] = bytes((7, 1))
        selected.data_id_bit_records.return_value = (bytes(bit),)
        selected.data_id_bit_variable.return_value = bytes.fromhex("5555")
        calls = []
        values = iter((b"\0",))

        def exchange(query):
            calls.append(query.request)
            if len(calls) <= 2:
                return (
                    b"\x62"
                    + query.request[1:]
                    + (b"\x80" if len(calls) == 2 else b"\0")
                )
            return bytes.fromhex("625555") + next(values)

        cache = MonitorSupportCache(selected, exchange, "dynamic")
        enabled = (0x1280, 0x5555)
        self.assertTrue(cache.check_support_pid(100, enabled_dids=enabled))
        self.assertTrue(cache.check_support_pid(100, enabled_dids=enabled))
        cache.begin_operation()
        self.assertFalse(cache.check_support_pid(100, enabled_dids=enabled))
        self.assertEqual(
            [request.hex() for request in calls],
            ["221280", "225555", "225555"],
        )

    def test_comparison_distinguishes_unavailable_value_from_numeric_zero(self):
        for comparison in (1, 2):
            for observed in (b"\x62\x55\x55", b"\x62\x55\x55\0", 0x90020323):
                selected = self.selected(condition=9)
                parent = selected.records(62)[0]
                target = bytearray(64)
                struct.pack_into("<HH", target, 36, 3, 0)
                struct.pack_into("<H", target, 54, 0x5555)
                selected.records.side_effect = (
                    lambda slot, parent=parent, target=bytes(target): (
                        (parent, target) if slot == 62 else ()
                    )
                )
                bit = bytearray(16)
                bit[13:15] = bytes((7, comparison))
                selected.data_id_bit_records.return_value = (bytes(bit),)
                selected.data_id_bit_variable.return_value = bytes.fromhex("5555")

                def exchange(query, observed=observed):
                    if isinstance(observed, int):
                        raise ToyotaCodecError(
                            "authored unavailable condition", observed
                        )
                    return observed

                cache = MonitorSupportCache(selected, exchange, "unavailable-value")
                cache.check_support_pid = Mock(return_value=True)
                supported = cache._p5_condition(parent, (0x5555,), 18)
                equal = isinstance(observed, bytes) and len(observed) > 3
                self.assertEqual(supported, equal if comparison == 1 else not equal)

    def test_comparison_variable_width_is_checked_after_target_support(self):
        selected = self.selected(condition=9)
        parent = selected.records(62)[0]
        target = bytearray(parent)
        struct.pack_into("<HH", target, 36, 3, 0)
        struct.pack_into("<H", target, 54, 0x5555)
        selected.records.side_effect = lambda slot: (
            (parent, bytes(target)) if slot == 62 else ()
        )
        bit = bytearray(16)
        bit[13:15] = bytes((7, 2))
        selected.data_id_bit_records.return_value = (bytes(bit),)
        selected.data_id_bit_variable.return_value = bytes.fromhex("555500")
        exchange = Mock(
            side_effect=AssertionError("Invalid variable must not issue C9")
        )
        cache = MonitorSupportCache(selected, exchange, "variable-width")
        target_check = Mock(return_value=True)
        cache.check_support_pid = target_check
        with self.assertRaises(ToyotaCodecError) as raised:
            cache._p5_condition(parent, (0x5555,), 18)
        self.assertEqual(raised.exception.code, 0xC0040102)
        target_check.assert_called_once()
        selected.frame_records.assert_called_once_with(0xC9)
        target_check.return_value = False
        self.assertTrue(cache._p5_condition(parent, (0x5555,), 18))
        selected.frame_records.assert_called_once_with(0xC9)
        exchange.assert_not_called()

    def test_unsupported_did_caches_false_but_mode_override_is_applied_later(self):
        selected = self.selected()
        row = bytearray(selected.records(62)[0])
        row[59] = 1
        selected.records.side_effect = lambda slot: (bytes(row),) if slot == 62 else ()
        exchange = Mock(side_effect=AssertionError("Unsupported DID must not query"))
        cache = MonitorSupportCache(selected, exchange, "p5")
        self.assertFalse(cache.check_support_pid(100, enabled_dids=()))
        self.assertTrue(
            cache.check_support_pid(100, enabled_dids=(), raw_support=False)
        )


class MultiReceiveTests(unittest.TestCase):
    def cache(self, receives, sends=(0,), *, retries=0, limits=None):
        selected = StreamTests().selected(retries=retries)
        selected.protocol_info.return_value = None
        stream = SupportStreamDriver(receives, sends=sends)
        cache = MonitorSupportCache(
            selected, Mock(), "multi", stream=stream, bus_id=7, limits=limits
        )
        return cache, selected.frame_records(0x86)[0], stream

    def test_preserves_complete_ordered_responses_then_terminal_timeout(self):
        cache, frame, stream = self.cache(
            [
                (0, bytes.fromhex("6101aa")),
                (0, bytes.fromhex("6102bb")),
                (0x91010009, b""),
            ]
        )
        result = cache.multi_receive(frame)
        self.assertEqual(
            (result.status, result.replies),
            (0, (bytes.fromhex("6101aa"), bytes.fromhex("6102bb"))),
        )
        self.assertEqual(
            [event[0] for event in stream.events],
            ["send", "receive", "receive", "receive"],
        )
        self.assertEqual(
            (stream.events[0][1].parameter4, stream.events[0][1].parameter5), (1000, 7)
        )
        self.assertEqual(stream.events[1][1].parameter4, 200)

    def test_initial_timeout_retries_but_error_after_response_cannot_resend(self):
        cache, frame, stream = self.cache(
            [(0x91010009, b""), (0, b"\x61\x01"), (0x90020321, b"")],
            sends=(0, 0),
            retries=2,
        )
        result = cache.multi_receive(frame, native_parameter=12)
        self.assertEqual((result.status, result.replies), (0x90020321, (b"\x61\x01",)))
        self.assertEqual([event[0] for event in stream.events].count("send"), 2)
        self.assertEqual(stream.events[0][1].parameter5, 12)

    def test_90020323_immediate_and_budget_is_not_suppressed(self):
        cache, frame, stream = self.cache([(0x90020323, b"")], retries=2)
        self.assertEqual(cache.multi_receive(frame).status, 0x90020323)
        self.assertEqual(len(stream.events), 2)
        cache, frame, _ = self.cache([(0, b"\x61")], limits=Limits(exchanges=2))
        with self.assertRaises(SessionError):
            cache.multi_receive(frame)


class SendSupportCommTests(unittest.TestCase):
    def test_raw_stream_predicate_and_missing_identifier_keep_native_boolean(self):
        selected = StreamTests().selected()
        stream = SupportStreamDriver(
            [(0, bytes.fromhex("41000c02aabb")), (0x91010009, b"")]
        )
        cache = MonitorSupportCache(
            selected, Mock(), "predicate", stream=stream, bus_id=9
        )
        result = cache.send_support_comm(0x13, 12, 1, 0xF0, 0xB0)
        self.assertEqual(
            (result.status, result.supported, result.ignored_failure), (0, True, False)
        )
        self.assertFalse(cache.send_support_comm(0x13, 13, 1, 0xF0, 0xB0).supported)
        self.assertEqual(cache.send_support_comm(0x15, 1, 0, 255, 1).status, 0xC0040102)
        self.assertEqual(len(stream.events), 3)

    def test_6b_actual_position_map_expansion_and_force_request_invalidation(self):
        selected = StreamTests().selected()
        stream = SupportStreamDriver(
            [(0, bytes.fromhex("41000c03010100")), (0x91010009, b"")]
        )
        calls = []

        def exchange(query):
            calls.append(query.request)
            return bytes.fromhex("610caabb")

        cache = MonitorSupportCache(
            selected, exchange, "compressed", stream=stream, bus_id=9
        )
        result = cache.send_support_comm(0x6B, 12, 2, 255, 0)
        self.assertTrue(result.supported)
        self.assertFalse(result.cache_hit)
        self.assertTrue(cache.send_support_comm(0x6B, 12, 1, 255, 0xBB).cache_hit)
        self.assertTrue(
            cache.send_support_comm(0x6B, 12, 1, 255, 0xBB, force=True).supported
        )
        self.assertEqual(calls, [bytes.fromhex("210c"), bytes.fromhex("210c")])

    def test_ca_ushort_position_mask_value_and_error_flag(self):
        selected = profile({}, bytes.fromhex("220000"))
        calls = []

        def exchange(query):
            calls.append(query)
            return bytes.fromhex("621234") + bytes(256) + b"\xaf"

        cache = MonitorSupportCache(selected, exchange, "wide")
        result = cache.send_support_comm(0xCA, 0x1234, 256, 15, 7, with_value=True)
        self.assertEqual((result.status, result.supported, result.value), (0, True, 15))
        self.assertTrue(calls[0].extended)
        self.assertEqual(calls[0].request.hex(), "221234")

        def timeout(query):
            raise ToyotaCodecError("authored timeout", 0x91010009)

        failed = MonitorSupportCache(selected, timeout, "failed").send_support_comm(
            0xCA, 0x1234, 0, 255, 1
        )
        self.assertEqual(
            (failed.status, failed.ignored_failure, failed.cache_hit),
            (0x91010009, True, False),
        )

    def test_104_uses_distinct_ca0101_and_ca_group_temporary_native_stages(self):
        selected = profile({}, bytes.fromhex("220000"))
        calls = []

        def exchange(query):
            calls.append(query.request)
            return (
                bytes.fromhex("62010140")
                if query.request == bytes.fromhex("220101")
                else bytes.fromhex("62010080")
            )

        cache = MonitorSupportCache(selected, exchange, "data-id-status", bus_id=9)
        self.assertTrue(
            cache.send_support_comm(0x104, 0x101, 0, 0, 0, native_parameter=9).supported
        )
        self.assertEqual(calls, [bytes.fromhex("220101"), bytes.fromhex("220100")])
        self.assertFalse(cache.response_cached(bytes.fromhex("220101")))
        self.assertEqual(cache.data_id_support_status(0x102), 1)
        self.assertEqual(len(calls), 2)  # the passed native CCommCachePlus shares TEMP


class CommSupportTests(unittest.TestCase):
    @staticmethod
    def row(identifier, *, expected=1, predicate=1, chain=0):
        row = bytearray(24)
        struct.pack_into("<6H", row, 0, 55, 0, 1, 0xCA, identifier, 7)
        row[18:24] = bytes((255, expected, 9, chain, 0, predicate))
        return bytes(row)

    def selected(self, rows):
        selected = profile({}, bytes.fromhex("220000"))
        selected.communication_support_records.return_value = tuple(rows)
        selected.communication_settings.return_value = struct.pack("<4I", 123, 0, 0, 0)
        return selected

    def test_ordered_and_or_skips_failed_tail_and_successful_alternatives(self):
        selected = self.selected(
            [
                self.row(1),
                self.row(2, chain=2),
                self.row(3, chain=2),
                self.row(4),
            ]
        )
        calls = []

        def exchange(query):
            calls.append(query)
            return (
                query.request[:1].replace(b"\x22", b"\x62")
                + query.request[1:]
                + bytes((query.request[-1] == 3,))
            )

        cache = MonitorSupportCache(selected, exchange, "logic", bus_id=9)
        self.assertTrue(cache.get_comm_support_bit(55).supported)
        self.assertEqual([q.request.hex() for q in calls], ["220001", "220003"])
        self.assertTrue(all(q.native_parameter == 9 for q in calls))
        self.assertTrue(cache.get_comm_support_bit(55).supported)
        self.assertEqual(len(calls), 2)

    def test_out_value_survives_later_predicate_that_does_not_write_it(self):
        second = bytearray(self.row(2))
        struct.pack_into("<H", second, 6, 0x75)
        selected = self.selected([self.row(0x1234), bytes(second)])
        selected.frame_records.side_effect = lambda function: (
            SelectedFrame(
                CommandFrame(bytes.fromhex("220000" if function == 0xCA else "2100")),
                b"function",
                b"comm",
                bytes(16),
                "authored",
            ),
        )
        replies = iter((bytes.fromhex("621234a5"), bytes.fromhex("610201")))
        cache = MonitorSupportCache(
            selected, lambda query: next(replies), "out-value", bus_id=9
        )
        result = cache.get_comm_support_bit(55, with_value=True)
        self.assertEqual((result.supported, result.value), (True, 0xA5))

    def test_failure_predicate_initializes_only_uncached_native_timeout(self):
        selected = self.selected([self.row(1, predicate=5)])
        stream = SupportStreamDriver([], sends=[0x90020328])
        calls = []

        def exchange(query):
            calls.append(query.request)
            raise ToyotaCodecError("authored timeout", 0x91010009)

        cache = MonitorSupportCache(
            selected, exchange, "fault", bus_id=9, stream=stream
        )
        self.assertTrue(cache.get_comm_support_bit(55).supported)
        self.assertTrue(cache.get_comm_support_bit(55).supported)
        self.assertEqual(calls, [bytes.fromhex("220001")])
        self.assertEqual(len(stream.events), 1)
        initialization = stream.events[0][1]
        self.assertEqual(
            (
                initialization.request,
                initialization.parameter4,
                initialization.parameter5,
                initialization.parameter6,
                initialization.parameter7,
            ),
            (None, 123, 9, 1, 1),
        )

    def test_actual_serialized_db130_to_native_common_both_source_builds(self):
        from test_native_communication import Primitives, Reply, serialized_profile
        from test_profiles import encode_database

        from scripts.diagnostic_db import parse_database
        from scripts.native_communication import NativeCommunication

        for version in (12, 18):
            with self.subTest(version=version):
                selected = serialized_profile(
                    version=version, request=bytes.fromhex("220000")
                )
                sections = {
                    slot: (part.count, part.payload)
                    for slot, part in selected.catalog.management.sections.items()
                }
                count, functions = sections[18]
                sections[18] = (
                    count + 1,
                    functions + struct.pack("<8H", 42, 0xCA, 1, 0, 0, 0, 0, 0),
                )
                row = bytearray(self.row(0x1234, expected=0xA5))
                struct.pack_into("<H", row, 10, 42)
                row[20] = 0x12
                sections[48] = (1, bytes(row))
                encoded = bytearray(encode_database(1, sections))
                struct.pack_into("<I", encoded, 28, selected.catalog.management.version)
                selected.catalog.management = parse_database(bytes(encoded))
                lower = Primitives([Reply(0, bytes.fromhex("621234a5"))])
                runtime = NativeCommunication(
                    selected,
                    lower,
                    "literal-DB130",
                    bus_id=0x12,
                    source_build=version,
                    clock=lambda: 0.0,
                )
                runtime.no_init = runtime.no_session = True
                self.assertTrue(runtime.cache.get_comm_support_bit(55).supported)
                self.assertTrue(runtime.cache.get_comm_support_bit(55).supported)
                self.assertEqual((runtime.no_init, runtime.no_session), (True, True))
                self.assertEqual(lower.calls[0][2]["initialization_mode"], 1)
                self.assertFalse(lower.calls[0][2]["no_session"])
                self.assertEqual(
                    [entry[0] for entry in lower.calls], ["send", "receive"]
                )
                self.assertEqual(lower.calls[0][1], bytes.fromhex("221234"))
                self.assertEqual(lower.calls[1][1]["maximum"], 0x1000)
                self.assertIn(
                    selected.catalog.management.sha256,
                    selected.frame_records(0xCA)[0].provenance,
                )

                second = bytearray(row)
                struct.pack_into("<H", second, 8, 0x1235)
                sections[48] = (2, bytes(row + second))
                encoded = bytearray(encode_database(1, sections))
                struct.pack_into("<I", encoded, 28, selected.catalog.management.version)
                selected.catalog.management = parse_database(bytes(encoded))
                lower = Primitives(
                    [
                        Reply(0, bytes.fromhex("621234a5")),
                        Reply(0, bytes.fromhex("621235a5")),
                    ]
                )
                bounded = NativeCommunication(
                    selected,
                    lower,
                    "bounded-DB130",
                    bus_id=0x12,
                    source_build=version,
                    limits=Limits(exchanges=3),
                    clock=lambda: 0.0,
                )
                with self.assertRaises(SessionError):
                    bounded.cache.get_comm_support_bit(55)
                self.assertEqual(
                    [entry[0] for entry in lower.calls], ["send", "receive", "send"]
                )
                self.assertEqual(bounded.cache.calls, 3)

    def test_get_104_rows_share_one_local_temp_and_calls_restore_outer(self):
        first, second = bytearray(self.row(0x101)), bytearray(self.row(0x102))
        struct.pack_into("<H", first, 6, 0x104)
        struct.pack_into("<H", second, 6, 0x104)
        selected = self.selected([bytes(first), bytes(second)])
        calls = []

        def exchange(query):
            calls.append(query.request)
            if len(calls) == 1:
                return bytes.fromhex("62010100")
            return bytes.fromhex(
                "62010140" if query.request == bytes.fromhex("220101") else "620100c0"
            )

        cache = MonitorSupportCache(selected, exchange, "104-local", bus_id=9)
        frame = selected.frame_records(0xCA)[0]
        cache.transaction(
            frame, bytes.fromhex("220101"), cached=False, temporary=True, extended=True
        )
        self.assertTrue(cache.get_comm_support_bit(55).supported)
        self.assertTrue(cache.get_comm_support_bit(55).supported)
        self.assertEqual(
            [query.hex() for query in calls],
            ["220101", "220101", "220100", "220101", "220100"],
        )
        self.assertEqual(cache.data_id_support_status(0x101), 0)
        self.assertEqual(len(calls), 5)
        self.assertFalse(cache.response_cached(bytes.fromhex("220101")))

    def test_concrete_connection_uses_one_fresh_local_temp_per_get(self):
        from test_native_communication import Primitives, Reply, serialized_profile
        from test_profiles import encode_database

        from scripts.diagnostic_db import parse_database
        from scripts.native_communication import NativeCommunication

        for version in (12, 18):
            with self.subTest(version=version):
                selected = serialized_profile(
                    version=version, flags=0x14, request=bytes.fromhex("220000")
                )
                sections = {
                    slot: (part.count, part.payload)
                    for slot, part in selected.catalog.management.sections.items()
                }
                count, frames = sections[17]
                sections[17] = (count, struct.pack("<4H", 1, 5, 6, 7) + frames[8:])
                row = bytearray(self.row(1))
                struct.pack_into("<H", row, 2, 1)
                struct.pack_into("<H", row, 10, 42)
                row[20] = 0x12
                sections[48] = (1, bytes(row))
                encoded = bytearray(encode_database(1, sections))
                struct.pack_into("<I", encoded, 28, selected.catalog.management.version)
                selected.catalog.management = parse_database(bytes(encoded))
                one_call = [Reply(0, bytes.fromhex("62000001"))]
                if version == 12:
                    one_call.append(Reply(0x91010009))
                lower = Primitives(one_call * 2)
                runtime = NativeCommunication(
                    selected,
                    lower,
                    "connection-DB130",
                    bus_id=0x12,
                    source_build=version,
                    clock=lambda: 0.0,
                )
                for _ in range(2):
                    self.assertTrue(
                        runtime.cache.get_comm_support_bit(55, temporary=True).supported
                    )
                self.assertEqual(
                    [entry[1] for entry in lower.calls if entry[0] == "send"],
                    [bytes.fromhex("220000")] * 2,
                )
                self.assertFalse(
                    runtime.cache.response_cached(
                        bytes.fromhex("220000"), temporary=True
                    )
                )
                self.assertFalse(runtime.cache.response_cached(bytes.fromhex("220000")))

    def test_nested_local_temporary_scopes_restore_original_cache_after_failure(self):
        calls = []
        selected = profile({}, bytes.fromhex("220001"))

        def exchange(query):
            calls.append(query.request)
            return bytes.fromhex("620001") + bytes((len(calls),))

        cache = MonitorSupportCache(selected, exchange, "local-TEMP")
        frame = selected.frame_records(0xCA)[0]
        read = lambda: cache.transaction(
            frame, frame.frame.request, cached=False, temporary=True
        )
        self.assertEqual(read()[-1], 1)
        with cache.temporary_scope():
            self.assertEqual(read()[-1], 2)
            with (
                self.assertRaisesRegex(RuntimeError, "authored"),
                cache.temporary_scope(),
            ):
                self.assertEqual(read()[-1], 3)
                raise RuntimeError("authored")
            self.assertEqual(read()[-1], 2)
        self.assertEqual(read()[-1], 1)
        self.assertEqual(len(calls), 3)

    def test_retained_native_temp_instances_share_no_replies_and_preserve_ever(self):
        selected = profile({}, bytes.fromhex("220001"))
        calls = []

        def exchange(query):
            calls.append(query.request)
            return bytes.fromhex("620001") + bytes((len(calls),))

        cache = MonitorSupportCache(selected, exchange, "retained")
        frame = selected.frame_records(0xCA)[0]
        first, second = cache.new_temporary_cache(), cache.new_temporary_cache()
        cache.transaction(frame, frame.frame.request)  # shared Ever value1
        for instance, expected in ((first, 2), (second, 3), (first, 2)):
            with cache.temporary_scope(instance):
                reply = cache.transaction(
                    frame, frame.frame.request, cached=False, temporary=True
                )
                self.assertEqual(reply[-1], expected)
        self.assertEqual(cache.transaction(frame, frame.frame.request)[-1], 1)
        other = MonitorSupportCache(
            selected, exchange, "another-ECU"
        ).new_temporary_cache()
        with self.assertRaises(SessionError), cache.temporary_scope(other):
            self.fail("A foreign native TEMP instance must not bind")
        self.assertEqual(len(calls), 3)

    def test_bad_function_is_fatal_and_host_cancellation_is_not_native_failure(self):
        zero_target = bytearray(self.row(1))
        struct.pack_into("<H", zero_target, 10, 0)
        exchange_spy = Mock()
        with self.assertRaises(SessionError):
            MonitorSupportCache(
                self.selected([bytes(zero_target)]),
                exchange_spy,
                "zero-target",
                bus_id=9,
            ).get_comm_support_bit(55)
        exchange_spy.assert_not_called()
        row = bytearray(self.row(1, predicate=5))
        struct.pack_into("<H", row, 6, 0x15)
        with self.assertRaises(ToyotaCodecError) as raised:
            MonitorSupportCache(
                self.selected([bytes(row)]), Mock(), "bad", bus_id=9
            ).get_comm_support_bit(55)
        self.assertEqual(raised.exception.code, 0xC0040102)
        cancelled = [False]

        def exchange(query):
            cancelled[0] = True
            raise ToyotaCodecError("authored timeout", 0x91010009)

        cache = MonitorSupportCache(
            self.selected([self.row(1, predicate=5)]),
            exchange,
            "cancel",
            bus_id=9,
            cancelled=lambda: cancelled[0],
        )
        with self.assertRaises(Cancelled):
            cache.get_comm_support_bit(55)


class SelectedP4Integration(unittest.TestCase):
    def test_real_authored_ddb_raw_support_stream_to_p4_setup_and_geometry(self):
        import tempfile
        from dataclasses import replace
        from pathlib import Path

        from scripts.data_monitor import selected_p4_from_exchange
        from scripts.demo import _ddb, create_demo
        from scripts.diagnostic_db import parse_database
        from scripts.profiles import VehicleCatalog

        with tempfile.TemporaryDirectory() as temporary:
            root = create_demo(Path(temporary) / "authored")
            path = root / "Techstream_DB_NA" / "Toyota.ddb"
            database = parse_database(path.read_bytes())
            sections = {
                slot: (item.count, item.payload)
                for slot, item in database.sections.items()
            }
            count, rows = sections[18]
            sections[18] = (
                count + 1,
                rows[:16] + struct.pack("<8H", 1, 0x13, 1, 4, 0, 1, 0, 0) + rows[16:],
            )
            path.write_bytes(_ddb(1, sections))
            selected = VehicleCatalog(root / "Techstream_DB_NA").build_profile(1)
            category = bytearray(selected.category_record)
            category[72] = 6
            selected = replace(selected, category_record=bytes(category))
            stream = SupportStreamDriver(
                [(0, b"\x41\0\x0c\2\xff\xff"), (0x91010009, b"")]
            )
            functions: dict[int, bool] = dict.fromkeys(
                (22, 12, 25, 11, 26, 29, 27, 28, 35), False
            )
            functions[22] = True
            result = selected_p4_from_exchange(
                selected,
                (1,),
                Mock(side_effect=AssertionError("P4 uses primitive13 stream")),
                "selected-p4",
                functions,
                source_build=18,
                support_stream=stream,
                bus_id=7,
                interface_id=7,
                excluded=0,
                max_request=10,
                max_reply=10,
                standard_values=(),
            )
            self.assertEqual(result.frame_sizes, ((6, 2),))
            self.assertEqual(
                result.commands.setup[0].values[:3],
                (1, 7, ((6, bytes.fromhex("0c020102")),)),
            )
            signal = result.signals[0]
            self.assertEqual(
                (signal.name, signal.pid, signal.start_bit, signal.end_bit),
                ("Engine speed", 1, 0, 15),
            )
            send = stream.events[0][1]
            self.assertEqual(
                (send.query.request, send.parameter4, send.parameter5),
                (b"\x01\0", 1000, 7),
            )
            self.assertEqual(stream.events[1][1].parameter4, 1000)


class SelectedP5Integration(unittest.TestCase):
    def test_actual_serialized_ddb_c8_to_p5_setup_and_native_suppressed_fault(self):
        import tempfile
        from pathlib import Path

        from scripts.data_monitor import MonitorError, selected_p5_polling_from_cache
        from scripts.demo import _ddb, create_demo
        from scripts.diagnostic_db import parse_database
        from scripts.profiles import VehicleCatalog

        with tempfile.TemporaryDirectory() as temporary:
            root = create_demo(Path(temporary) / "authored")
            management_path = root / "Techstream_DB_NA" / "Toyota.ddb"
            management = parse_database(management_path.read_bytes())
            sections = {
                slot: (part.count, part.payload)
                for slot, part in management.sections.items()
            }
            count, rows = sections[18]
            sections[18] = (
                count + 1,
                rows + struct.pack("<8H", 1, 0xC8, 1, 3, 0, 1, 0, 0),
            )
            count, categories = sections[16]
            category = bytearray(categories)
            category[72] = 20
            sections[16] = (count, bytes(category))
            management_path.write_bytes(_ddb(1, sections))
            ecu_path = root / "Techstream_DB_NA" / "DemoEngine.ddb"
            ecu = parse_database(ecu_path.read_bytes())
            sections = {
                slot: (part.count, part.payload) for slot, part in ecu.sections.items()
            }
            row = bytearray(64)
            struct.pack_into("<I", row, 24, 4)
            struct.pack_into("<H", row, 36, 1)
            struct.pack_into("<H", row, 42, 1)
            struct.pack_into("<HH", row, 44, 0, 15)
            struct.pack_into("<H", row, 54, 0x101)
            sections[62] = (1, bytes(row))
            ecu_path.write_bytes(_ddb(2, sections))
            selected = VehicleCatalog(root / "Techstream_DB_NA").build_profile(1)
            calls = []

            def exchange(query):
                calls.append(query)
                return {
                    bytes.fromhex("22000000"): bytes.fromhex("62000040"),
                    bytes.fromhex("22010000"): bytes.fromhex("62010080"),
                }[query.request]

            cache = MonitorSupportCache(
                selected, exchange, "p5-adapter", source_build=18
            )
            result = selected_p5_polling_from_cache(
                cache,
                (1,),
                {26: False, 73: True},
                interface_id=7,
                excluded=0,
                standard_values=(),
                parameter_6=2000,
                active_alias_pid=0,
            )
            self.assertEqual(
                [query.request.hex() for query in calls], ["22000000", "22010000"]
            )
            self.assertTrue(all(query.extended for query in calls))
            self.assertEqual(result.frame_sizes, ((0, 2),))
            self.assertEqual(
                result.commands.setup[0].values, (1, 7, ((0x101, 2),), 2, (), 2000)
            )
            self.assertEqual(
                (
                    result.signals[0].name,
                    result.signals[0].start_bit,
                    result.signals[0].end_bit,
                ),
                ("Engine speed", 0, 15),
            )

            faults = []

            def unsupported(query):
                faults.append(query.request)
                raise ToyotaCodecError("authored C8 unavailable", 0x90020321)

            cache = MonitorSupportCache(
                selected, unsupported, "p5-fault", source_build=18
            )
            with self.assertRaises(MonitorError):
                selected_p5_polling_from_cache(
                    cache,
                    (1,),
                    {26: False, 73: True},
                    interface_id=7,
                    excluded=0,
                    standard_values=(),
                    parameter_6=2000,
                    active_alias_pid=0,
                )
            self.assertEqual(faults, [bytes.fromhex("22000000")])
            self.assertEqual(
                cache.data_ids().suppressed_errors,
                ((bytes.fromhex("22000000"), 0x90020321),),
            )


class FrameOriginTests(unittest.TestCase):
    def test_foreign_actual_frame_rejected_before_cold_or_cached_io_and_multi(self):
        from dataclasses import replace

        from test_native_communication import serialized_profile
        from test_profiles import encode_database

        from scripts.diagnostic_db import parse_database

        own = serialized_profile(request=bytes.fromhex("221234"))
        foreign = serialized_profile(request=bytes.fromhex("221234"))
        sections = {
            slot: (part.count, part.payload)
            for slot, part in foreign.catalog.management.sections.items()
        }
        count, settings = sections[29]
        settings = bytearray(settings)
        struct.pack_into("<I", settings, 0, 31337)
        sections[29] = (count, bytes(settings))
        encoded = bytearray(encode_database(1, sections))
        struct.pack_into("<I", encoded, 28, foreign.catalog.management.version)
        foreign.catalog.management = parse_database(bytes(encoded))
        valid, other = own.direct_frame(0, 1), foreign.direct_frame(0, 1)
        calls = []
        stream = SupportStreamDriver([])

        def exchange(query):
            calls.append(query)
            return bytes((query.request[0] | 0x40,)) + query.request[1:] + b"\xa5"

        cache = MonitorSupportCache(own, exchange, "bound", stream=stream, bus_id=0x12)
        for observed in (other, replace(other, provenance=valid.provenance)):
            with self.assertRaises(ValueError):
                cache.transaction(observed, observed.frame.request)
            with self.assertRaises(ValueError):
                cache.multi_receive(observed)
        self.assertEqual((calls, stream.events), ([], []))
        self.assertEqual(
            cache.transaction(valid, valid.frame.request), bytes.fromhex("621234a5")
        )
        with self.assertRaises(ValueError):
            cache.transaction(other, other.frame.request)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].source_identity, cache.identity)
        # A literal request override is permitted with original selected metadata.
        self.assertEqual(
            cache.transaction(valid, bytes.fromhex("221235")), bytes.fromhex("621235a5")
        )
        self.assertEqual(calls[-1].request, bytes.fromhex("221235"))
        self.assertEqual(
            cache.transaction(valid, bytes.fromhex("310102")), bytes.fromhex("710102a5")
        )
        cache.profile = replace(own, vehicle_name_key=9)
        replacement = cache.profile.direct_frame(0, 1)
        with self.assertRaises(SessionError):
            cache.transaction(replacement, replacement.frame.request)
        self.assertEqual(len(calls), 3)
        from test_native_communication import Primitives

        from scripts.native_communication import NativeCommunication

        parent = MonitorSupportCache(own, exchange, "parent", bus_id=0x12)
        primitives = Primitives()
        target = NativeCommunication(
            replace(own, vehicle_name_key=9), primitives, "other-vehicle", bus_id=0x12
        )
        with self.assertRaises(SessionError), parent.target_operation(target):
            self.fail("Foreign vehicle target must not enter the native operation")
        self.assertEqual(primitives.calls, [])


class LegacyFreezeSupportTests(unittest.TestCase):
    def test_wide_pid_bit_uses_native_dword_shift_wrap_both_builds(self):
        from test_native_communication import Primitives, Reply

        from scripts.native_communication import NativeCommunication

        for build in (12, 18):
            selected, row = self.selected(build, first=0, last=32)
            lower = Primitives([Reply(0, bytes.fromhex("61058000000080"))])
            runtime = NativeCommunication(
                selected, lower, "wide-pid-bit", bus_id=0x12, source_build=build
            )
            self.assertTrue(
                runtime.cache.check_freeze_pid(row, {1: 1}, pid_lengths={5: 1})
            )

    def selected(self, version, *, selector=2, identifier=b"\x05", first=0, last=0):
        from dataclasses import replace

        from test_native_communication import serialized_profile
        from test_profiles import encode_database

        from scripts.diagnostic_db import parse_database

        selected = serialized_profile(
            version=version, request=b"\x21\x00", check=b"\x61"
        )
        sections = {
            slot: (part.count, part.payload)
            for slot, part in selected.catalog.management.sections.items()
        }
        values = (
            b"\x10\x01",
            b"\x81",
            b"\x3e",
            b"\x81",
            b"\x21\x00",
            b"\xff",
            b"\x61",
            identifier,
        )
        directory, storage = bytearray(), bytearray()
        for value in values:
            directory += struct.pack("<IH", len(storage), len(value))
            storage += value
        sections[0] = (len(values), bytes(directory + storage))
        count, functions = sections[18]
        sections[18] = (
            count + 1,
            functions
            + struct.pack(
                "<8H", 42, {2: 0x10, 3: 0x69, 4: 0x6A}[selector], 1, 0, 0, 0, 0, 0
            ),
        )
        count, functions = sections[18]
        ordered = sorted(
            (functions[i : i + 16] for i in range(0, len(functions), 16)),
            key=lambda row: (
                struct.unpack_from("<H", row, 0)[0],
                struct.unpack_from("<H", row, 2)[0],
                struct.unpack_from("<H", row, 10)[0],
            ),
        )
        sections[18] = (count, b"".join(ordered))
        encoded = bytearray(encode_database(1, sections))
        struct.pack_into("<I", encoded, 28, selected.catalog.management.version)
        selected.catalog.management = parse_database(bytes(encoded))
        freeze_row = bytearray(84)
        freeze_row[79] = 1
        struct.pack_into("<H", freeze_row, 58, 9)
        struct.pack_into("<H", freeze_row, 64, 7)
        bit = struct.pack("<5H2B", 9, 8, 0, first, last, 0, selector)
        encoded = bytearray(
            encode_database(2, {8: (1, bit), 10: (1, bytes(freeze_row))})
        )
        struct.pack_into("<I", encoded, 28, selected.catalog.management.version)
        return replace(selected, database=parse_database(bytes(encoded))), bytes(
            freeze_row
        )

    def test_two_pid_maps_actual_selected_bit_and_ever_cache_both_builds(self):
        from test_native_communication import Primitives, Reply

        from scripts.native_communication import NativeCommunication

        for version in (12, 18):
            selected, row = self.selected(version)
            lower = Primitives([Reply(0, bytes.fromhex("610580"))])
            runtime = NativeCommunication(
                selected,
                lower,
                "legacy-freeze",
                bus_id=0x12,
                source_build=version,
                clock=lambda: 0.0,
            )
            cache = runtime.cache
            self.assertFalse(cache.check_freeze_pid(row, {1: 1}, pid_lengths={}))
            self.assertFalse(cache.check_freeze_pid(row, {}, pid_lengths={5: 1}))
            self.assertEqual(lower.calls, [])
            self.assertTrue(cache.check_freeze_pid(row, {1: 1}, pid_lengths={5: 1}))
            self.assertTrue(cache.check_freeze_pid(row, {1: 1}, pid_lengths={5: 1}))
            sends = [call for call in lower.calls if call[0] == "send"]
            self.assertEqual(len(sends), 1)
            self.assertEqual(sends[0][1], bytes.fromhex("2105"))
            foreign = bytearray(row)
            foreign[79] = 2
            with self.assertRaises(SessionError):
                cache.check_freeze_pid(bytes(foreign), {2: 1}, pid_lengths={5: 1})

    def test_selected_pid_bit_group_and_eager_variables_both_builds(self):
        from dataclasses import replace

        from test_native_communication import Primitives, Reply
        from test_profiles import encode_database

        from scripts.diagnostic_db import parse_database
        from scripts.native_communication import NativeCommunication

        for version in (12, 18):
            selected, row = self.selected(version)
            first = selected.pid_bit_records(9)[0]
            other = struct.pack("<5H2B", 10, 65535, 0, 0, 0, 0, 2)
            invalid = struct.pack("<5H2B", 9, 65535, 0, 0, 0, 0, 2)

            def database(bits, freeze=row, version=selected.database.version):
                encoded = bytearray(
                    encode_database(
                        2, {8: (len(bits), b"".join(bits)), 10: (1, freeze)}
                    )
                )
                struct.pack_into("<I", encoded, 28, version)
                return parse_database(bytes(encoded))

            selected = replace(selected, database=database((first, other)))
            lower = Primitives([Reply(0, bytes.fromhex("610580"))])
            runtime = NativeCommunication(
                selected, lower, "first-pid-bit", bus_id=0x12, source_build=version
            )
            self.assertTrue(
                runtime.cache.check_freeze_pid(row, {1: 1}, pid_lengths={5: 1})
            )
            self.assertEqual(selected.pid_bit_records(9), (first,))
            selected = replace(selected, database=database((first, invalid, other)))
            lower = Primitives()
            runtime = NativeCommunication(
                selected, lower, "eager-pid-bit", bus_id=0x12, source_build=version
            )
            with self.assertRaises(ToyotaCodecError) as raised:
                runtime.cache.check_freeze_pid(row, {1: 1}, pid_lengths={5: 1})
            self.assertEqual(raised.exception.code, 0xA0030102)
            self.assertEqual(lower.calls, [])

    def test_selector4_two_byte_request_and_four_byte_header_both_builds(self):
        from test_native_communication import Primitives, Reply

        from scripts.native_communication import NativeCommunication

        for version in (12, 18):
            selected, row = self.selected(version, selector=4, identifier=b"\x12\x34")
            lower = Primitives([Reply(0, bytes.fromhex("7434000080"))])
            runtime = NativeCommunication(
                selected, lower, "two-byte-pid-bit", bus_id=0x12, source_build=version
            )
            self.assertTrue(runtime.cache.check_freeze_pid(row, {1: 1}, pid_lengths={}))
            sends = [call for call in lower.calls if call[0] == "send"]
            # Native CommandDataLib.GetAt wraps each out-of-range position to node0.
            self.assertEqual(sends[0][1], bytes.fromhex("3400"))

    def test_known_failure_is_false_cached_and_null_did_list_is_explicit(self):
        from test_native_communication import Primitives, Reply

        from scripts.native_communication import NativeCommunication

        selected, row = self.selected(18)
        lower = Primitives([Reply(0x90020323)])
        runtime = NativeCommunication(
            selected, lower, "legacy-timeout", bus_id=0x12, clock=lambda: 0.0
        )
        self.assertFalse(
            runtime.cache.check_freeze_pid(row, {1: 1}, pid_lengths={5: 1})
        )
        self.assertFalse(
            runtime.cache.check_freeze_pid(row, {1: 1}, pid_lengths={5: 1})
        )
        self.assertEqual(len([call for call in lower.calls if call[0] == "send"]), 1)
        selected, row = self.selected(18, selector=3)
        lower = Primitives()
        runtime = NativeCommunication(
            selected, lower, "legacy-null", bus_id=0x12, clock=lambda: 0.0
        )
        with self.assertRaisesRegex(SessionError, "NULL DID list"):
            runtime.cache.check_freeze_pid(row, {1: 1}, pid_lengths={5: 1})
        self.assertEqual(lower.calls, [])


class PacketDriver:
    def __init__(self, sends, receives):
        self.sends, self.receives = list(sends), list(receives)
        self.events = []

    def send(
        self,
        ecu: int,
        request: bytes,
        parameter4: int,
        parameter5: int,
        parameter6: int,
        parameter7: int,
    ) -> int:
        self.events.append(
            ("send", (ecu, request, parameter4, parameter5, parameter6, parameter7))
        )
        return self.sends.pop(0)

    def receive(self, query):
        self.events.append(("receive", query))
        return self.receives.pop(0)

    def interrupt(self, enabled):
        self.events.append(("interrupt", enabled))


class PacketTests(unittest.TestCase):
    def cache(self, driver, **kwargs):
        return PacketFrameCache(
            driver,
            source_identity=("authored", 7),
            send_timer=123,
            receive_timer=456,
            retries=1,
            **kwargs,
        )

    def test_native_init_first_settings_and_native_fallback_both_builds(self):
        from test_native_communication import serialized_profile
        from test_profiles import encode_database

        from scripts.diagnostic_db import parse_database
        from scripts.monitor_support import monitor_source_identity

        for version in (12, 18):
            selected = serialized_profile(version=version)
            sections = {
                slot: (part.count, part.payload)
                for slot, part in selected.catalog.management.sections.items()
            }
            first = bytearray(sections[29][1])
            struct.pack_into("<II", first, 0, 123, 456)
            first[14] = 3
            second = bytearray(first)
            struct.pack_into("<II", second, 0, 9000, 8000)
            sections[29] = (2, bytes(first + second))
            encoded = bytearray(encode_database(1, sections))
            struct.pack_into("<I", encoded, 28, selected.catalog.management.version)
            selected.catalog.management = parse_database(bytes(encoded))
            driver = PacketDriver(
                [0, 0],
                [
                    (0, bytes.fromhex("e211aa")),
                    (0, bytes.fromhex("e211")),
                    (0x91010009, b""),
                ],
            )
            cache = PacketFrameCache.from_profile(selected, driver, "native42")
            self.assertEqual(
                (cache.send_timer, cache.receive_timer, cache.retries), (123, 456, 3)
            )
            self.assertEqual(
                cache.get_packet_frame(
                    42,
                    0x12,
                    source_identity=monitor_source_identity(selected, "native42"),
                ),
                (PacketFrame(17, b"\xaa"),),
            )
            self.assertEqual(
                driver.events[0], ("send", (42, bytes.fromhex("a204"), 123, 0x12, 0, 0))
            )
            self.assertEqual(driver.events[1][1].parameter4, 456)
            del sections[29]
            encoded = bytearray(encode_database(1, sections))
            struct.pack_into("<I", encoded, 28, selected.catalog.management.version)
            selected.catalog.management = parse_database(bytes(encoded))
            count = len(driver.events)
            with self.assertRaisesRegex(
                SessionError, "selected source/context changed"
            ):
                cache.get_packet_frame(42, 0x12, source_identity=cache.identity)
            self.assertEqual(len(driver.events), count)
            driver = PacketDriver([], [])
            fallback = PacketFrameCache.from_profile(selected, driver, "native42")
            self.assertEqual(
                (fallback.send_timer, fallback.receive_timer, fallback.retries),
                (1000, 200, 2),
            )
            self.assertEqual(driver.events, [])

    def test_literal_a2_a3_sequence_cache_and_drain(self):
        driver = PacketDriver(
            [0, 0],
            [
                (0, b"\x00"),
                (0, b"\xe2\x10"),
                (0, b"\xe2\x11\xaa"),
                (0, b"\xe2\x12\xbb\xcc"),
                (0, b"\xe2\x11"),
                (0, b"\xe3"),
                (0x91010009, b""),
            ],
        )
        cache = self.cache(driver)
        result = cache.get_packet_frame(7, 9, source_identity=("authored", 7))
        self.assertEqual(
            result, (PacketFrame(17, b"\xaa"), PacketFrame(18, b"\xbb\xcc"))
        )
        self.assertEqual(driver.events[0], ("send", (7, b"\xa2\x04", 123, 9, 0, 0)))
        self.assertIn(("send", (7, b"\xa3", 123, 9, 0, 0)), driver.events)
        self.assertEqual(driver.events[-1], ("interrupt", False))
        count = len(driver.events)
        self.assertEqual(
            cache.get_packet_frame(7, 99, source_identity=("authored", 7)), result
        )
        self.assertEqual(len(driver.events), count)
        with self.assertRaises(SessionError):
            cache.get_packet_frame(7, 9, source_identity=("other", 7))

    def test_receive_failure_retries_and_preserves_native_error(self):
        driver = PacketDriver([0, 0], [(0x91010009, b""), (0x91010009, b"")])
        with self.assertRaises(ToyotaCodecError) as raised:
            self.cache(driver).get_packet_frame(7, 0, source_identity=("authored", 7))
        self.assertEqual(raised.exception.code, 0xA1050307)
        self.assertEqual(sum(event[0] == "send" for event in driver.events), 2)

    def test_a3_failure_disables_shared_ecu_before_drain_and_restores_interrupt(self):
        driver = PacketDriver(
            [0, 0x90020001],
            [(0, b"\xe2\x11\xaa"), (0, b"\xe2\x11"), (0x91010009, b"")],
        )
        cache = self.cache(
            driver,
            disable_packet_ecu=lambda ecu: driver.events.append(("disable", ecu)),
        )
        self.assertEqual(
            cache.get_packet_frame(7, 9, source_identity=cache.identity),
            (PacketFrame(17, b"\xaa"),),
        )
        self.assertEqual(cache.disabled, [7])
        self.assertEqual(driver.events[-3:][0], ("disable", 7))
        self.assertEqual(driver.events[-2][0], "receive")
        self.assertEqual(driver.events[-1], ("interrupt", False))
        count = len(driver.events)
        cache.get_packet_frame(7, 9, source_identity=cache.identity)
        self.assertEqual(len(driver.events), count)

        driver = PacketDriver([0, 9], [(0, b"\xe2\x11\xaa"), (0, b"\xe2\x11")])

        def failed_shared_update(ecu):
            raise SessionError("authored source-bound shared state failure")

        cache = self.cache(driver, disable_packet_ecu=failed_shared_update)
        with self.assertRaises(SessionError):
            cache.get_packet_frame(7, 9, source_identity=cache.identity)
        self.assertEqual(driver.events[-1], ("interrupt", False))
        self.assertEqual(cache.entries, [])

    def test_uncertain_interrupt_enable_fault_still_attempts_disable(self):
        class FaultyInterrupt(PacketDriver):
            enabled = False

            def interrupt(self, enabled):
                super().interrupt(enabled)
                self.enabled = enabled
                if enabled:
                    raise OSError("authored setter failed after enabling")

        driver = FaultyInterrupt([0], [(0, b"\xe2\x11\xaa"), (0, b"\xe2\x11")])
        cache = self.cache(driver)
        with self.assertRaises(OSError):
            cache.get_packet_frame(7, 9, source_identity=("authored", 7))
        self.assertEqual(
            driver.events[-2:], [("interrupt", True), ("interrupt", False)]
        )
        self.assertFalse(driver.enabled)
        self.assertEqual(cache.entries, [])

    def test_drain_budget_restores_interrupt_and_does_not_cache(self):
        driver = PacketDriver([0, 0], [(0, b"\xe2\x11\xaa"), (0, b"\xe2\x11")])
        cache = self.cache(driver, limits=Limits(exchanges=4, seconds=5))
        with self.assertRaises(SessionError):
            cache.get_packet_frame(7, 0, source_identity=("authored", 7))
        self.assertEqual(driver.events[-1], ("interrupt", False))
        self.assertEqual(cache.entries, [])


if __name__ == "__main__":
    unittest.main()
