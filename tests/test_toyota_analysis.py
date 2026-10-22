"""Authored selected DDB and diagnostic chronology; no OEM resources or device."""

import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from scripts.monitor_support import MonitorSupportCache
from scripts.profiles import VehicleCatalog
from scripts.toyota import ToyotaCodecError
from scripts.toyota_analysis import (
    DcmP5Analysis,
    RoBAnalysis,
    dcm_marker,
    marker_order_p5,
    read_dcm_ram,
    read_dcm_variable_ram,
    rob_lsb,
    rob_marker,
    rob_marker_order,
    rob_timing,
)
from scripts.toyota_session import Cancelled, SessionError


def database(kind, sections, *, version=0x0100032F):
    header = bytearray(36 + 4 * (max(sections) + 1))
    header[8:10] = bytes((kind, max(sections) + 1))
    header[10:28] = b"DiagTool DataCtrl\0"
    struct.pack_into("<I", header, 28, version)
    body = bytearray()
    for slot, (count, payload) in sorted(sections.items()):
        struct.pack_into("<I", header, 36 + slot * 4, len(header) + len(body))
        body += struct.pack("<BBII", slot, 0, count, len(payload)) + payload
    return bytes(header + body)


def operation(code, function=1, content=2):
    return struct.pack("<II4H", function, content, 0x201, code, 0, 0)


def record(code, data=b"\x00" * 10):
    return code.to_bytes(2, "big") + data


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        category = bytearray(76)
        category[:18] = "demo.ddb\0".encode("utf-16le")
        struct.pack_into("<H", category, 68, 42)
        module = bytearray(88)
        name = "GetAnlWkFctDcm35_DT.dll\0".encode("utf-16le")
        module[: len(name)] = name
        struct.pack_into("<H", module, 80, 42)
        module[86] = 0xD7
        settings = bytearray(16)
        struct.pack_into("<H", settings, 10, 1)
        management = {
            0: (1, struct.pack("<IH", 0, 3) + b"\x22\0\0"),
            16: (1, category),
            17: (1, struct.pack("<4H", 2, 1, 0, 0)),
            18: (1, struct.pack("<8H", 42, 0xCA, 1, 2, 0, 1, 0, 0)),
            19: (1, module),
            29: (1, settings),
        }
        (root / "Toyota.ddb").write_bytes(database(1, management))
        strings, blob, directory = (
            ("Function", "Content", "Signal", "Off", "On"),
            b"",
            b"",
        )
        for text in strings:
            encoded = (text + "\0").encode("utf-16le")
            directory += struct.pack("<IH", len(blob), len(encoded))
            blob += encoded
        (root / "M_English.ddb").write_bytes(database(4, {0: (5, directory + blob)}))
        signal = bytearray(24)
        struct.pack_into("<I", signal, 12, 3)
        struct.pack_into("<HH", signal, 16, 0x201, 7)
        networks = []
        for index in range(4):
            row = bytearray(16)
            struct.pack_into("<3H", row, 4, index, index, 10)
            row[14] = index + 1
            networks.append(bytes(row))
        patterns = b"".join(
            struct.pack("<II6H", 4 + v, 0, 10, v, 0, 0, 0, 0) for v in (0, 1)
        )
        self.sections = {
            114: (1, signal),
            116: (3, operation(1) + operation(2) + operation(3)),
            117: (4, b"".join(networks)),
            37: (2, patterns),
        }
        (root / "demo.ddb").write_bytes(database(2, self.sections))
        self.profile = VehicleCatalog(root).build_profile(42)
        self.calls = []
        self.payload = record(1) + b"\xff" * 12 + record(2) + record(3)
        self.replies = {
            b"\x22\x01\x01": b"\x62\x01\x01\x20",
            b"\x22\x02\x00": b"\x62\x02\x00\x80",
        }
        self.cache = MonitorSupportCache(
            self.profile, self.exchange, "authored-dcm", bus_id=7
        )

    def exchange(self, query):
        self.calls.append(query.request)
        return self.replies.get(query.request, b"\x62\x02\x01" + self.payload)

    def test_selected_ddb_actual_support_read_decode(self):
        result = DcmP5Analysis(self.profile, self.cache).run()
        self.assertEqual(result.native_status, 0)
        self.assertEqual(
            self.calls, [b"\x22\x01\x01", b"\x22\x02\x00", b"\x22\x02\x01"]
        )
        (group,) = result.groups
        self.assertEqual(
            (group.data_id, group.display_id, group.name), (0x201, 7, "Signal")
        )
        self.assertEqual([r.operation_code for r in group.records], [1, 3, 2])
        self.assertEqual(group.records[0].function_name, "Function")
        self.assertEqual(group.received_payload, self.payload)
        self.assertEqual(result.selected_identity[1], self.profile.database.sha256)
        self.assertEqual(result.language_sha256, self.profile.catalog.language.sha256)

    def native_connection(self, replies):
        from test_native_communication import DRIVER, J2534Fixture, serialized_profile

        from scripts.diagnostic_db import parse_database
        from scripts.frame_transport import J2534Result, NativeMessage
        from scripts.native_communication import NativeCommunication

        profile = serialized_profile(request=b"\x22\0\0", mask=b"", check=b"")
        sections = {
            slot: (section.count, section.payload)
            for slot, section in profile.catalog.management.sections.items()
        }
        count, functions = sections[18]
        sections[18] = (
            count + 1,
            functions + struct.pack("<8H", 42, 0xCA, 1, 0, 0, 1, 0, 0),
        )
        sections[19] = (1, self.profile.catalog.management.sections[19].payload)
        profile.catalog.management = parse_database(database(1, sections))
        profile.catalog.language = self.profile.catalog.language
        profile = replace(profile, database=self.profile.database)
        backend = J2534Fixture(
            [
                J2534Result(
                    count=1,
                    messages=(NativeMessage(6, 0, 0, 0, 0, b"\0\0\x07\xe8" + reply),),
                )
                for reply in replies
            ]
        )
        connection = NativeCommunication.from_backend(
            profile,
            backend,
            "native-dcm",
            first_request=b"\x22\0\0",
            driver=DRIVER,
            device_kind=8,
            bus_id=0x12,
            source_build=18,
            clock=lambda: 0.0,
        )
        connection.no_init = True
        return connection, backend

    def test_actual_native_controller_disconnect_lifecycle(self):
        connection, backend = self.native_connection(
            [b"\x62\x01\x01\x20", b"\x62\x02\x00\x80", b"\x62\x02\x01" + self.payload]
        )
        result = DcmP5Analysis.from_communication(connection).run()
        self.assertEqual(result.disconnect_status, 0)
        self.assertEqual(
            [r.operation_code for r in result.groups[0].records], [1, 3, 2]
        )
        self.assertTrue(connection.closed)
        self.assertTrue(
            any(operation == "disconnect" for operation, _ in backend.calls)
        )

    def test_actual_native_controller_disconnect_after_business_failure(self):
        connection, backend = self.native_connection([b"\x62\x01\x01\0"])
        provider = DcmP5Analysis.from_communication(connection)
        with self.assertRaises(ToyotaCodecError) as caught:
            provider.run()
        self.assertEqual(caught.exception.code, 0x90040501)
        self.assertEqual(provider.cleanup_status, 0)
        self.assertTrue(connection.closed)
        self.assertTrue(
            any(operation == "disconnect" for operation, _ in backend.calls)
        )

    def test_each_execute_owns_fresh_temporary_history_cache(self):
        engine = DcmP5Analysis(self.profile, self.cache)
        first = engine.run()
        self.payload = record(2) + b"\xff" * 12
        second = engine.run()
        self.assertEqual(first.groups[0].records[0].operation_code, 1)
        self.assertEqual(second.groups[0].records[0].operation_code, 2)
        self.assertEqual(self.calls.count(b"\x22\x02\x01"), 2)

    def test_two_dids_share_native_support_cache_within_execute(self):
        from scripts.diagnostic_db import Section

        first = bytes(self.profile.database.sections[114].payload)
        second = bytearray(first)
        struct.pack_into("<H", second, 16, 0x202)
        self.profile.database.sections[114] = Section(114, 0, 2, False, first + second)
        self.replies[b"\x22\x02\x00"] = b"\x62\x02\x00\xc0"
        self.replies[b"\x22\x02\x02"] = b"\x62\x02\x02" + b"\xff" * 12
        result = DcmP5Analysis(self.profile, self.cache).run()
        self.assertEqual([g.data_id for g in result.groups], [0x201, 0x202])
        self.assertEqual(
            self.calls,
            [b"\x22\x01\x01", b"\x22\x02\x00", b"\x22\x02\x01", b"\x22\x02\x02"],
        )

    def test_duplicate_opcode_definition_fails_native_count_guard(self):
        from scripts.diagnostic_db import Section

        payload = self.profile.database.sections[116].payload
        self.profile.database.sections[116] = Section(
            116, 0, 4, False, operation(1) + payload
        )
        with self.assertRaises(ToyotaCodecError) as caught:
            DcmP5Analysis(self.profile, self.cache).decode(
                0x201, record(1) + b"\xff" * 12
            )
        self.assertEqual(caught.exception.code, 0xC0040102)

    def test_marker_and_native_no_marker_edge(self):
        self.assertEqual(marker_order_p5(record(1) + record(2)), (1,))
        self.assertEqual(marker_order_p5(b"\xff" * 12 + record(1)), (1,))
        self.assertEqual(marker_order_p5(b""), ())
        self.assertEqual(
            marker_order_p5(record(1) + b"\xff" * 12 + record(2) + b"tail"), (0, 2)
        )
        self.assertTrue(dcm_marker(b"abcd" + b"\xff" * 4))
        self.assertFalse(dcm_marker(b"\xff" * 4 + b"abcd"))
        self.assertFalse(rob_marker(()))
        self.assertTrue(rob_marker((b"", b"\xff\xff")))
        self.assertFalse(rob_marker((b"\xff", b"\x00")))
        self.assertEqual(
            rob_marker_order(((b"a",), (b"\xff",), (b"b",), (b"\xff",))), (0, 3, 2)
        )
        self.assertEqual(rob_marker_order(((b"a",), (b"b",))), (1,))

    def test_rob_lsb_native_low_dword_signed_divisor_and_shift(self):
        phy = struct.pack("<Iii6H", 3, 2, 500, 0, 0, 0, 0, 0, 0)
        self.assertEqual(rob_lsb(5, phy, 0, 7), (7, 384))
        self.assertEqual(rob_lsb(5, phy, 0, 31), (7, 1))
        phy = struct.pack("<Iii6H", 3, -2, 500, 0, 0, 0, 0, 0, 0)
        self.assertEqual(rob_lsb(5, phy, 0, 7), (0xFFFFFFF9, 0xFFFFFE80))
        phy = struct.pack("<Iii6H", 0xFFFFFFFF, 0, 500, 0, 0, 0, 0, 0, 0)
        self.assertEqual(rob_lsb(2, phy, 0, 7), (0xFFFFFFFE, 0xFFFFFF00))
        with self.assertRaises(ToyotaCodecError):
            rob_lsb(2, phy, 8, 7)

    def test_rob_native_wrap_generation_and_unsigned_arithmetic(self):
        timing = rob_timing(
            ((8, 1), (9, 1), (4, 2), (1, 2)),
            current_ticks=3,
            modulus=10,
            current_generation=1,
        )
        self.assertEqual(timing.happened, (5, 14, None, None))
        self.assertEqual(timing.passed, (18, 9, 4, 1))
        self.assertEqual((timing.max_wraps, timing.current_after_reset), (2, 23))
        timing = rob_timing(
            ((8, 1), (4, 2), (2, 1)), current_ticks=3, modulus=10, current_generation=1
        )
        self.assertEqual(timing.happened, (5, None, None))
        timing = rob_timing(
            ((0xFFFFFFFF, 0),),
            current_ticks=0,
            modulus=0,
            current_generation=0,
            previous_max_wraps=2,
        )
        self.assertEqual(timing.happened, (1,))
        self.assertEqual(timing.max_wraps, 2)
        self.assertEqual(
            rob_timing(
                (),
                current_ticks=3,
                modulus=10,
                current_generation=1,
                previous_max_wraps=2,
            ).current_after_reset,
            23,
        )
        with self.assertRaises(ToyotaCodecError):
            rob_timing(((True, 0),), current_ticks=0, modulus=0, current_generation=0)

    def test_bcd_and_network_metadata(self):
        engine = DcmP5Analysis(self.profile, self.cache)
        raw = record(1, b"\x02\x06\x20\x26\x10\x20\x12\x34\x00\x00")
        group = engine.decode(0x201, raw + b"\xff" * 12)
        self.assertTrue(group.records[0].time_valid)
        self.assertEqual(group.records[0].time_values, (20, 26, 10, 20, 12, 34, 0))
        raw = record(1, b"\x02\x06\xfa\x26\x10\x20\x12\x34\x01\xa0")
        (item,) = engine.decode(0x201, raw + b"\xff" * 12).records
        self.assertFalse(item.time_valid)
        self.assertEqual(item.time_values, ())
        self.assertTrue(item.network_valid)
        self.assertEqual(item.network_status, ("On", "Off", "On", "Off"))

    def test_eager_unused_pattern_text_fault_and_null_used_name(self):
        from scripts.diagnostic_db import Section

        payload = bytearray(self.profile.database.sections[37].payload)
        struct.pack_into("<I", payload, 4, 999)
        self.profile.database.sections[37] = Section(37, 0, 2, False, bytes(payload))
        with self.assertRaises(ToyotaCodecError) as caught:
            self.profile.work_factor_records(37, 10, 0)
        self.assertEqual(caught.exception.code, 0xA0030102)
        payload = operation(1, content=0) + operation(2) + operation(3)
        self.profile.database.sections[116] = Section(116, 0, 3, False, payload)
        with self.assertRaises(ToyotaCodecError) as caught:
            DcmP5Analysis(self.profile, self.cache).decode(
                0x201, record(1) + b"\xff" * 12
            )
        self.assertEqual(caught.exception.code, 0xC0040102)

    def test_source_bound_rob_shared_metadata_version_and_overlay(self):
        from scripts.diagnostic_db import Section

        item = bytearray(20)
        struct.pack_into("<I", item, 0, 1)
        struct.pack_into("<H", item, 4, 7)
        item[18] = 1
        changed_item = bytearray(item)
        struct.pack_into("<I", changed_item, 0, 2)
        struct.pack_into("<H", changed_item, 14, 9)
        changed_item[19] = 2
        for version, flag in ((0x0100030C, 5), (0x0100032F, 7)):
            row = bytearray(8)
            struct.pack_into("<H", row, 2, 7)
            row[4] = 1
            changed = bytearray(row)
            struct.pack_into("<H", changed, 0, 9)
            changed[4], changed[flag] = 2, 2
            profile = replace(
                self.profile,
                exception_ids=(9,),
                database=replace(
                    self.profile.database,
                    version=version,
                    sections={
                        **self.profile.database.sections,
                        90: Section(90, 0, 2, False, bytes(row + changed)),
                        115: Section(115, 0, 2, False, bytes(item + changed_item)),
                    },
                ),
            )
            self.assertEqual(profile.rob_data_id_records(7), (bytes(changed),))
            self.assertEqual(profile.rob_data_id_records(8), ())
            if version == 0x0100032F:
                self.assertEqual(
                    profile.work_factor_records(115, 7, 1), (bytes(changed_item),)
                )
                self.assertEqual(profile.work_factor_records(115, 7, 257), ())
            else:
                with self.assertRaises(ValueError):
                    profile.work_factor_records(115, 7, 1)

    def test_unknown_opcode_is_not_invented(self):
        group = DcmP5Analysis(self.profile, self.cache).decode(
            0x201, record(99) + b"\xff" * 12
        )
        self.assertEqual(group.records, ())

    def test_unsupported_upper_fails_and_supported_upper_no_lower_is_empty(self):
        self.replies[b"\x22\x01\x01"] = b"\x62\x01\x01\0"
        with self.assertRaises(ToyotaCodecError) as caught:
            DcmP5Analysis(self.profile, self.cache).run()
        self.assertEqual(caught.exception.code, 0x90040501)
        self.cache.begin_operation()
        self.replies[b"\x22\x01\x01"] = b"\x62\x01\x01\x20"
        self.replies[b"\x22\x02\x00"] = b"\x62\x02\x00\0"
        self.assertEqual(DcmP5Analysis(self.profile, self.cache).run().groups, ())

    def test_short_history_is_recorded_as_native_skip(self):
        self.replies[b"\x22\x02\x01"] = b"\x62\x02\x01"
        result = DcmP5Analysis(self.profile, self.cache).run()
        self.assertEqual(result.skipped, ((0x201, 0xA0040202),))
        self.assertEqual(result.groups, ())

    def test_source_cancel_deadline_and_bounds(self):
        self.cache.cancelled = lambda: True
        with self.assertRaises(Cancelled):
            DcmP5Analysis(self.profile, self.cache).run()
        self.assertEqual(self.calls, [])
        self.cache.cancelled = lambda: False
        self.cache.deadline = 0
        with self.assertRaises(SessionError):
            DcmP5Analysis(self.profile, self.cache).run()
        with self.assertRaises(ToyotaCodecError):
            marker_order_p5(bytes(4094))
        other = replace(self.profile, exception_ids=(9,))
        with self.assertRaises(SessionError):
            DcmP5Analysis(other, self.cache)
        old = MonitorSupportCache(self.profile, self.exchange, "old", source_build=12)
        with self.assertRaises(SessionError):
            DcmP5Analysis(self.profile, old)

    def test_language_source_cannot_change_during_analysis(self):
        provider = DcmP5Analysis(self.profile, self.cache)
        self.profile.catalog.language.sha256 = "changed-language"
        with self.assertRaises(SessionError):
            provider.run()
        self.assertEqual(self.calls, [])

    def test_p5_selected_bus_cannot_change(self):
        provider = DcmP5Analysis(self.profile, self.cache)
        self.cache.bus_id = 0x14
        with self.assertRaises(SessionError):
            provider.run()
        self.assertEqual(self.calls, [])

    def test_wrong_module_fails_before_exchange(self):
        from scripts.diagnostic_db import Section

        module = bytearray(self.profile.catalog.management.sections[19].payload)
        module[:80] = "other.dll\0".encode("utf-16le").ljust(80, b"\0")
        self.profile.catalog.management = replace(
            self.profile.catalog.management,
            sections={
                **self.profile.catalog.management.sections,
                19: Section(19, 0, 1, False, bytes(module)),
            },
        )
        cache = MonitorSupportCache(
            self.profile, self.exchange, "authored-dcm", bus_id=7
        )
        with self.assertRaises(SessionError):
            DcmP5Analysis(self.profile, cache)
        self.assertEqual(self.calls, [])


class RoBTests(unittest.TestCase):
    def setUp(self):
        base = AnalysisTests()
        base.setUp()
        self.addCleanup(base.doCleanups)
        self.profile, self.sections = base.profile, base.sections
        root = self.profile.catalog.root
        management = {
            slot: (section.count, section.payload)
            for slot, section in self.profile.catalog.management.sections.items()
        }
        module = bytearray(88)
        name = "GetRoBP5_AnlzWkFct_DT.dll\0".encode("utf-16le")
        module[: len(name)] = name
        struct.pack_into("<H", module, 80, 42)
        module[86] = 0xD6
        requests = (b"\x22\0\0", b"\x31\x01", b"\x31\x02\0\0", b"\x31\x03\0\0\0\0")
        directory, blob = b"", b""
        for request in requests:
            directory += struct.pack("<IH", len(blob), len(request))
            blob += request
        management[0] = (4, directory + blob)
        management[17] = (
            4,
            b"".join(struct.pack("<4H", index, index, 0, 0) for index in range(1, 5)),
        )
        management[18] = (
            4,
            b"".join(
                struct.pack("<8H", 42, function, 1, index, 0, 1, 0, 0)
                for index, function in enumerate((0xCA, 0xF3, 0xF4, 0xF5), 1)
            ),
        )
        management[19] = (1, bytes(module))
        (root / "Toyota.ddb").write_bytes(database(1, management))
        signal = bytearray(self.sections[114][1])
        signal[:6] = "R1\0".encode("utf-16le")
        groups, checks, monitors = [], [], []
        for index, key in enumerate((0x19, 0x1A, 0x1B), 1):
            group = bytearray(12)
            struct.pack_into("<IH", group, 0, 3, index)
            group[8] = key
            groups.append(group)
            checks.append(struct.pack("<4H", index, index, 0, 0))
            monitor = bytearray(64)
            struct.pack_into(
                "<I", monitor, 0, 999999
            )  # Native SetRecString never reads this field.
            struct.pack_into("<I", monitor, 24, 3)
            struct.pack_into("<H", monitor, 36, index)
            struct.pack_into("<3H", monitor, 42, 1, (index - 1) * 8, index * 8 - 1)
            struct.pack_into("<H", monitor, 54, 0x201)
            monitors.append(monitor)
        physical = bytearray(24)
        struct.pack_into("<II", physical, 0, 1, 1)
        struct.pack_into("<HH", physical, 12, 1, 1)
        items = []
        for did, kind, first in (
            (0x1001, 1, 0),
            (0x1001, 2, 8),
            (0x1002, 3, 0),
            (0x1002, 4, 8),
        ):
            item = bytearray(20)
            struct.pack_into("<I5H", item, 0, 1, did, first, first + 7, 1, 10)
            item[18] = kind
            items.append(item)
        self.sections.update(
            {
                0: (3, b"".join(groups)),
                1: (3, b"".join(checks)),
                13: (1, physical),
                15: (1, struct.pack("<I4H", 4, 1, 0, 0, 0)),
                62: (3, b"".join(monitors)),
                114: (1, signal),
                115: (4, b"".join(items)),
            }
        )
        self.sections[37] = (1, struct.pack("<II6H", 2, 3, 10, 1, 7, 0, 0, 0))
        (root / "demo.ddb").write_bytes(database(2, self.sections))
        self.profile = VehicleCatalog(root).build_profile(42)
        self.calls = []
        self.replies = {
            b"\x22\x02\x01": b"\x62\x02\x01\x01\x64\x02",
            b"\x31\x01": b"\x71\x01\x02\x01",
            b"\x31\x02\x02\x01": b"\x71\x02\x02\x01\0\x01\0\x02\0\x03",
            b"\x31\x03\x02\x01\0\x01": self.history(b"\x01\x01", b"\x5a\x02"),
            b"\x31\x03\x02\x01\0\x02": self.history(b"\xff\xff", b"\xff\xff"),
            b"\x31\x03\x02\x01\0\x03": self.history(b"\x02\x00", b"\x50\x02"),
        }
        self.cache = MonitorSupportCache(
            self.profile, self.exchange, "authored-rob", bus_id=7
        )

    @staticmethod
    def history(first, second):
        return (
            b"\x71\x03\x02\x01\0\0\x02\x10\x01\x02" + first + b"\x10\x02\x02" + second
        )

    def exchange(self, query):
        self.calls.append(query)
        value = self.replies[query.request]
        if isinstance(value, Exception):
            raise value
        return value

    def test_actual_dcm_a1_ram_stride_any_success_and_bounds(self):
        from scripts.diagnostic_db import Section

        management = self.profile.catalog.management
        functions = bytearray(management.sections[18].payload)
        # F4 template length4 is too short for A1; use F5 length6 selector/address.
        struct.pack_into("<H", functions, 3 * 16 + 2, 0xA1)
        functions = b"".join(
            sorted(
                (bytes(functions[i : i + 16]) for i in range(0, len(functions), 16)),
                key=lambda row: struct.unpack_from("<H", row, 2)[0],
            )
        )
        management.sections[18] = Section(18, 0, 4, False, functions)
        raw = b"\x00\x01\x09\0" + struct.pack("<I", 0x1234)
        first = b"\x31\x09\x04\0\x12\x34"
        second = b"\x31\x09\x04\0\x12\x36"
        self.replies[first] = ToyotaCodecError("literal RAM negative", 0x90020323)
        self.replies[second] = b"\x71" + second[1:] + b"abcd"
        captured = read_dcm_ram(self.cache, raw)
        self.assertEqual(captured.native_status, 0)
        self.assertEqual(captured.words, ((0x1236, b"abcd"),))
        self.assertEqual(captured.failures, ((0x1234, 0x90020323),))
        self.assertEqual([q.request for q in self.calls], [first, second])
        self.replies[second] = b"\x71" + second[1:] + b"abc"
        self.assertEqual(read_dcm_ram(self.cache, raw).native_status, 0xA0040201)
        self.assertEqual(read_dcm_ram(self.cache, b"\xff\0" + bytes(6)).words, ())
        with self.assertRaises(SessionError):
            read_dcm_ram(self.cache, b"\x00\xff" + bytes(6))
        self.cache.cancelled = lambda: True
        with self.assertRaises(Cancelled):
            read_dcm_ram(self.cache, raw)

    def test_actual_variable_dcm_a1_alignment_chunking_and_cache(self):
        from scripts.diagnostic_db import Section

        management = self.profile.catalog.management
        functions = bytearray(management.sections[18].payload)
        struct.pack_into("<H", functions, 3 * 16 + 2, 0xA1)
        functions = b"".join(
            sorted(
                (bytes(functions[i : i + 16]) for i in range(0, len(functions), 16)),
                key=lambda row: struct.unpack_from("<H", row, 2)[0],
            )
        )
        management.sections[18] = Section(18, 0, 4, False, functions)
        raw = b"\x00\x02\x09\x02" + struct.pack("<I", 0x1234)
        requests = (
            b"\x31\x09\x03\x12\x34",
            b"\x31\x09\x04\x12\x35",
            b"\x31\x09\x03\x12\x37",
        )
        for request, data in zip(requests, (b"abc", b"Xdef", b"ghi"), strict=True):
            self.replies[request] = b"\x71" + request[1:] + data
        captured = read_dcm_variable_ram(self.cache, raw, 3)
        self.assertEqual(
            captured.words, ((0x1234, b"abc"), (0x1235, b"def"), (0x1237, b"ghi"))
        )
        self.assertEqual([q.request for q in self.calls], list(requests))
        read_dcm_variable_ram(self.cache, raw, 3)
        self.assertEqual(len(self.calls), 3)
        # First56-byte chunk failure skips remaining chunks but advances address.
        raw = b"\x01\x01\x09\x02" + struct.pack("<I", 0x2000)
        first = b"\x31\x09\x38\x20\0"
        self.replies[first] = ToyotaCodecError("literal chunk failure", 0x90020323)
        next_first = b"\x31\x09\x38\x20\x39"
        next_last = b"\x31\x09\x01\x20\x71"
        self.replies[next_first] = b"\x71" + next_first[1:] + b"a" * 56
        self.replies[next_last] = b"\x71" + next_last[1:] + b"b"
        captured = read_dcm_variable_ram(self.cache, raw, 57)
        self.assertEqual(captured.native_status, 0)
        self.assertEqual(captured.words, ((0x2039, b"a" * 56 + b"b"),))
        self.assertEqual(captured.failures, ((0x2000, 0x90020323),))
        self.assertNotIn(b"\x31\x09\x01\x20\x38", [q.request for q in self.calls])

    def test_original12_selected_ram_uses_independently_matched_bodies(self):
        root = self.profile.catalog.root
        management = {
            slot: (section.count, section.payload)
            for slot, section in self.profile.catalog.management.sections.items()
        }
        functions = bytearray(management[18][1])
        struct.pack_into("<H", functions, 3 * 16 + 2, 0xA1)
        management[18] = (
            4,
            b"".join(
                sorted(
                    (
                        bytes(functions[i : i + 16])
                        for i in range(0, len(functions), 16)
                    ),
                    key=lambda row: struct.unpack_from("<H", row, 2)[0],
                )
            ),
        )
        (root / "Toyota.ddb").write_bytes(database(1, management, version=0x0100030C))
        (root / "demo.ddb").write_bytes(
            database(2, {13: self.sections[13]}, version=0x0100030C)
        )
        profile = VehicleCatalog(root).build_profile(42)
        cache = MonitorSupportCache(
            profile, self.exchange, "authored12-ram", source_build=12, bus_id=7
        )
        raw = b"\x01\x01\x09\x02" + struct.pack("<I", 0x1234)
        for address in (0x1234, 0x1238):
            request = b"\x31\x09\x04" + address.to_bytes(3, "big")
            self.replies[request] = b"\x71" + request[1:] + b"abcd"
        self.assertEqual(
            read_dcm_ram(cache, raw).words, ((0x1234, b"abcd"), (0x1238, b"abcd"))
        )
        for address in (0x1234, 0x1238):
            request = b"\x31\x09\x04" + address.to_bytes(2, "big")
            self.replies[request] = b"\x71" + request[1:] + b"efgh"
        self.assertEqual(
            read_dcm_variable_ram(cache, raw, 4).words,
            ((0x1234, b"efgh"), (0x1238, b"efgh")),
        )

    def test_actual_current_enum_history_metadata_timing(self):
        result = RoBAnalysis(self.profile, self.cache).run()
        self.assertEqual([query.request for query in self.calls], list(self.replies))
        self.assertTrue(
            all(query.extended and query.native_parameter == 0 for query in self.calls)
        )
        assert result.current is not None
        self.assertEqual(tuple(v.value for v in result.current.values), (1, 100, 2))
        self.assertEqual(result.current.modulus, 256)
        self.assertEqual(result.current.adjusted_ticks, 100)
        group = result.groups[0]
        self.assertEqual(
            (group.data_id, group.display_id, group.name), (0x201, 7, "R1:Signal")
        )
        self.assertEqual([row.operation_code for row in group.records], [1, 2])
        self.assertEqual([row.happened for row in group.records], [10, 20])
        self.assertEqual([row.passed for row in group.records], [90, 80])
        self.assertEqual(
            (
                group.records[0].operation_label,
                group.records[0].help,
                group.records[0].help_type,
            ),
            ("0x01:Content", "Signal", 7),
        )
        self.assertEqual(
            (group.records[1].operation_label, group.records[1].help_type), ("0x02", 1)
        )
        self.assertEqual(group.records[0].values[1].format, 4)
        self.assertEqual(group.records[0].values[1].unit, "Off")

    def test_ro_b_current_cache_is_local_to_execute(self):
        provider = RoBAnalysis(self.profile, self.cache)
        first = provider.run()
        self.replies[b"\x22\x02\x01"] = b"\x62\x02\x01\x01\x6e\x02"
        second = provider.run()
        assert first.current is not None and second.current is not None
        self.assertEqual(
            (first.current.values[1].value, second.current.values[1].value), (100, 110)
        )
        self.assertEqual([q.request for q in self.calls].count(b"\x22\x02\x01"), 2)
        self.assertEqual([row.happened for row in second.groups[0].records], [20, 30])

    def test_bus14_uses_native_word_capacity_without_altering_selection(self):
        cache = MonitorSupportCache(
            self.profile, self.exchange, "authored-rob14", bus_id=0x14
        )
        result = RoBAnalysis(self.profile, cache).run()
        self.assertEqual(
            [row.operation_code for row in result.groups[0].records], [1, 2]
        )
        self.assertIsNone(self.calls[0].capacity)
        self.assertTrue(all(query.capacity == 65535 for query in self.calls[1:]))
        for query in self.calls:
            self.profile.validate_frame(query.selected)

    def test_metadata_only_no_current_and_no_history_queries(self):
        result = RoBAnalysis(self.profile, self.cache).run(mode=2, current_flag=0)
        self.assertEqual([q.request for q in self.calls], [b"\x31\x01"])
        self.assertIsNone(result.current)
        self.assertEqual(result.groups[0].records, ())

    def test_native_skippable_f4_and_f5_errors(self):
        self.replies[b"\x31\x02\x02\x01"] = ToyotaCodecError(
            "literal negative", 0xA0040202
        )
        result = RoBAnalysis(self.profile, self.cache).run(current_flag=0)
        self.assertEqual((result.groups, result.skipped), ((), ((0x201, 0xA0040202),)))
        self.replies[b"\x31\x02\x02\x01"] = b"\x71\x02\x02\x01\0\x01"
        self.replies[b"\x31\x03\x02\x01\0\x01"] = ToyotaCodecError(
            "literal negative", 0xC0040001
        )
        result = RoBAnalysis(self.profile, self.cache).run(current_flag=0)
        self.assertEqual(result.groups[0].records, ())
        self.assertEqual(result.skipped, ((1, 0xC0040001),))

    def test_malformed_or_duplicate_did_history_is_omitted(self):
        provider = RoBAnalysis(self.profile, self.cache)
        self.assertIsNone(
            provider._history(self.history(b"\x01\x01", b"\x5a\x02")[:-1])
        )
        self.assertIsNone(
            provider._decode(((0x1001, b"\x01\x01"), (0x1001, b"\x01\x01")))
        )
        self.assertEqual(provider._history(b"\0" * 6), None)
        self.assertIsNone(provider._decode(((0x1001, b"\x01"), (0x1002, b"\x5a\x02"))))

    def native_rob_connection(self, *, ethernet=False):
        from test_frame_transport_variants import EthernetPrimitive, ethernet_profile
        from test_native_communication import DRIVER, J2534Fixture, serialized_profile

        from scripts.diagnostic_db import parse_database
        from scripts.frame_transport import J2534Result, NativeMessage
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )

        build = 12 if self.profile.database.version == 0x0100030C else 18
        profile = (
            ethernet_profile()
            if ethernet
            else serialized_profile(
                version=build, request=b"\x22\0\0", mask=b"", check=b""
            )
        )
        base_variables = profile.catalog.management.sections[0].count
        management = {
            slot: (section.count, section.payload)
            for slot, section in profile.catalog.management.sections.items()
        }
        from scripts.toyota import VariableTable

        values = []
        for source in (profile.catalog.management, self.profile.catalog.management):
            section = source.sections[0]
            table = VariableTable(section.payload, section.count)
            values.extend(table.get(index) for index in range(1, section.count + 1))
        directory, blob = b"", b""
        for value in values:
            directory += struct.pack("<IH", len(blob), len(value))
            blob += value
        management[0] = (len(values), directory + blob)
        comm = bytearray(self.profile.catalog.management.sections[17].payload)
        for offset in range(0, len(comm), 8):
            frame_id, request_id = struct.unpack_from("<HH", comm, offset)
            struct.pack_into(
                "<HH", comm, offset, frame_id + 10, request_id + base_variables
            )
        count, payload = management[17]
        management[17] = (count + 4, payload + comm)
        functions = bytearray(self.profile.catalog.management.sections[18].payload)
        for offset in range(0, len(functions), 16):
            frame_id = struct.unpack_from("<H", functions, offset + 6)[0]
            struct.pack_into("<H", functions, offset + 6, frame_id + 10)
        count, payload = management[18]
        combined = payload + functions
        if ethernet:
            startup = next(
                payload[i : i + 16]
                for i in range(0, len(payload), 16)
                if struct.unpack_from("<H", payload, i + 2)[0] == 0x106
            )
            d1 = bytearray(startup)
            struct.pack_into("<H", d1, 2, 0xD1)
            combined += d1
            count += 1
        management[18] = (
            count + 4,
            b"".join(
                sorted(
                    (combined[i : i + 16] for i in range(0, len(combined), 16)),
                    key=lambda row: struct.unpack_from("<H", row, 2)[0],
                )
            ),
        )
        section = self.profile.catalog.management.sections[29]
        management[29] = (section.count, section.payload)
        section = self.profile.catalog.management.sections[19]
        management[19] = (section.count, section.payload)
        category = bytearray(profile.category_record)
        if self.profile.category_record[72]:
            category[72] = self.profile.category_record[72]
        management[16] = (1, bytes(category))
        profile.catalog.management = parse_database(
            database(1, management, version=0x0100030C if build == 12 else 0x0100032F)
        )
        profile.catalog.language = self.profile.catalog.language
        profile = replace(
            profile, database=self.profile.database, category_record=bytes(category)
        )
        if ethernet:
            backend = EthernetPrimitive()
            backend.response(b"\x50\x01")
            for reply in self.replies.values():
                backend.response(reply)
            backend.response(b"\x50\x01")
        else:
            backend = J2534Fixture(
                [
                    J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(6, 0, 0, 0, 0, b"\0\0\x07\xe8" + reply),
                        ),
                    )
                    for reply in self.replies.values()
                ]
            )
        connection = NativeCommunication.from_backend(
            profile,
            backend,
            "native-rob",
            first_request=b"\x22\0\0",
            driver=DRIVER,
            device_kind=8,
            bus_id=0x14 if ethernet else 0x12,
            source_build=build,
            clock=backend.clock
            if isinstance(backend, EthernetPrimitive)
            else lambda: 0.0,
        )
        connection.no_init = True
        if isinstance(backend, EthernetPrimitive):
            assert isinstance(connection.operations, NativeFrameController)
            connection.operations.operations.wait = backend.wait
        return connection, backend

    def test_actual_native_controller_ro_b_business(self):
        connection, backend = self.native_rob_connection()
        try:
            result = RoBAnalysis(connection.profile, connection.cache).run()
            self.assertEqual(
                [row.operation_code for row in result.groups[0].records], [1, 2]
            )
            self.assertFalse(connection.closed)
        finally:
            self.assertEqual(connection.disconnect(), 0)
        self.assertEqual(
            sum(operation == "write_messages" for operation, _ in backend.calls), 6
        )

    def test_actual_ro_b_ethernet_bus14_capacity_path(self):
        self.replies[b"\x31\x01"] += b"\0\0" * 2048
        connection, backend = self.native_rob_connection(ethernet=True)
        try:
            result = RoBAnalysis(connection.profile, connection.cache).run()
            self.assertEqual(
                [row.operation_code for row in result.groups[0].records], [1, 2]
            )
        finally:
            self.assertEqual(connection.disconnect(), 0)
        self.assertTrue(
            any(
                operation == "read_bytes" and fields["count"] > 4096
                for operation, fields, _ in backend.calls
            )
        )

    def test_eager_current_unused_selected_label_fails_before_read(self):
        from scripts.diagnostic_db import Section

        original = self.profile.database.sections[62].payload
        extra = bytearray(original[:64])
        struct.pack_into("<I", extra, 24, 999999)
        self.profile.database.sections[62] = Section(
            62, 0, 4, False, original[:64] + extra + original[64:]
        )
        with self.assertRaises(ToyotaCodecError) as caught:
            RoBAnalysis(self.profile, self.cache).run()
        self.assertEqual(caught.exception.code, 0xA0030102)
        self.assertEqual(self.calls, [])

    def test_native_null_format_labels_and_fixed_buffer_limit(self):
        from scripts.diagnostic_db import Section

        signal = bytearray(self.profile.database.sections[114].payload)
        struct.pack_into("<I", signal, 12, 0)
        self.profile.database.sections[114] = Section(114, 0, 1, False, bytes(signal))
        pattern = bytearray(self.profile.database.sections[37].payload)
        struct.pack_into("<I", pattern, 0, 0)
        self.profile.database.sections[37] = Section(37, 0, 1, False, bytes(pattern))
        provider = RoBAnalysis(self.profile, self.cache)
        result = provider.run()
        self.assertEqual(result.groups[0].name, "R1:(null)")
        self.assertEqual(result.groups[0].records[0].operation_label, "0x01:(null)")
        self.assertEqual(provider._format("a" * 255), "a" * 255)
        for text in ("a" * 256, "bad\0text", "日本語"):
            with self.assertRaises(SessionError):
                provider._format(text)
        japanese = RoBAnalysis(self.profile, self.cache, ansi_encoding="cp932")
        self.assertEqual(japanese._format("日" * 127), "日" * 127)
        with self.assertRaises(SessionError):
            japanese._format("日" * 128)

    def test_second_marker_stops_reads_and_direct_repeats(self):
        key = b"\x31\x02\x02\x01"
        self.replies[key] += b"\0\x04"
        self.replies[b"\x31\x03\x02\x01\0\x03"] = self.history(b"\xff\xff", b"\xff\xff")
        provider = RoBAnalysis(self.profile, self.cache)
        first = provider.run(current_flag=0)
        second = provider.run(current_flag=0)
        self.assertEqual([row.operation_code for row in first.groups[0].records], [1])
        self.assertEqual(first.groups, second.groups)
        self.assertEqual([q.request for q in self.calls].count(b"\x31\x01"), 2)
        self.assertEqual(len(self.calls), 10)

    def test_ro_b_selected_bus_and_encoding_cannot_change(self):
        provider = RoBAnalysis(self.profile, self.cache)
        self.cache.bus_id = 0x14
        with self.assertRaises(SessionError):
            provider.run()
        self.cache.bus_id = 7
        provider.ansi_encoding = "cp932"
        with self.assertRaises(SessionError):
            provider.run()
        self.assertEqual(self.calls, [])

    def test_fault_cancel_source_and_current_bounds(self):
        provider = RoBAnalysis(self.profile, self.cache)
        with self.assertRaises(ToyotaCodecError):
            provider.run(mode=0)
        self.cache.cancelled = lambda: True
        with self.assertRaises(Cancelled):
            provider.run()
        self.cache.cancelled = lambda: False
        self.replies[b"\x22\x02\x01"] = b"\x62\x02\x01\x01"
        with self.assertRaises(ToyotaCodecError) as caught:
            provider.run()
        self.assertEqual(caught.exception.code, 0xA0040202)
        self.profile.catalog.language.sha256 = "changed"
        with self.assertRaises(SessionError):
            provider.run()


class DcmTests(unittest.TestCase):
    def setUp(self):
        from test_monitor_support import SupportStreamDriver

        base = AnalysisTests()
        base.setUp()
        self.addCleanup(base.doCleanups)
        root = base.profile.catalog.root
        management = {
            slot: (s.count, s.payload)
            for slot, s in base.profile.catalog.management.sections.items()
        }
        category = bytearray(management[16][1])
        category[72] = 4
        management[16] = (1, bytes(category))
        module = bytearray(88)
        encoded = "GetAnlWkFctDcmP4_DT.dll\0".encode("utf-16le")
        module[: len(encoded)] = encoded
        struct.pack_into("<H", module, 80, 42)
        module[86] = 0x78
        management[19] = (1, bytes(module))
        requests = (b"\x01\0", b"\x21\0", b"\x21\0", b"\x23\0\x04\0\0")
        directory, blob = b"", b""
        for request in requests:
            directory += struct.pack("<IH", len(blob), len(request))
            blob += request
        management[0] = (4, directory + blob)
        management[17] = (
            4,
            b"".join(struct.pack("<4H", i, i, 0, 0) for i in range(1, 5)),
        )
        management[18] = (
            4,
            b"".join(
                struct.pack("<8H", 42, function, 1, i, 0, 1, 0, 0)
                for function, i in sorted(zip((0x13, 0x0F, 0x6B, 0xA1), range(1, 5)))
            ),
        )
        (root / "Toyota.ddb").write_bytes(database(1, management))
        freezes = []
        for logical, pid, first, last in (
            (1, 0x61, 0, 7),
            (2, 0x61, 8, 15),
            (3, 0x61, 16, 23),
            (4, 0x61, 24, 39),
        ):
            row = bytearray(84)
            struct.pack_into("<I", row, 48, 3)
            struct.pack_into("<H", row, 56, logical)
            struct.pack_into("<HH", row, 62, first, last)
            row[79] = pid
            freezes.append(bytes(row))
        signal = bytearray(28)
        struct.pack_into("<IH", signal, 0, 3, 7)
        struct.pack_into("<4H", signal, 8, 1, 2, 3, 4)
        item = bytearray(40)
        struct.pack_into("<5I", item, 0, 2, 1, 3, 1, 4)
        struct.pack_into("<HHH", item, 20, 7, 0, 7)
        struct.pack_into("<H", item, 30, 10)
        self.sections = {
            3: (1, bytes(8)),
            6: (1, bytes((0, 0, 0x61, 5, 0, 0, 0, 0))),
            10: (4, b"".join(freezes)),
            35: (1, signal),
            36: (1, item),
            37: (1, struct.pack("<II6H", 2, 3, 10, 5, 0, 0, 0, 0)),
        }
        self.root = root
        (root / "demo.ddb").write_bytes(database(2, self.sections))
        self.profile = VehicleCatalog(root).build_profile(42)
        self.calls = []
        self.replies: dict[bytes, bytes | ToyotaCodecError] = {
            b"\x21\0": b"\x61\0" + bytes(12) + b"\x80",
            b"\x21\x61": b"\x61\x61\x01\x02\x00\x12\x34",
            b"\x23\0\x04\x12\x34": b"\x63\0\x04\x12\x34\x01\x02\x03\x04",
            b"\x23\0\x04\x12\x38": b"\x63\0\x04\x12\x38" + b"\xff" * 4,
            b"\x23\0\x04\x12\x3c": b"\x63\0\x04\x12\x3c\x02\x03\x04\x05",
        }
        self.stream = SupportStreamDriver(
            [(0, b"\x41\0\x61\x05" + b"\xff" * 5), (0x91010009, b"")]
        )
        self.cache = MonitorSupportCache(
            self.profile, self.exchange, "authored-dcm-p4", bus_id=7, stream=self.stream
        )

    def exchange(self, query):
        self.calls.append(query)
        reply = self.replies[query.request]
        if isinstance(reply, Exception):
            raise reply
        return reply

    def test_actual_selected_pid_ram_and_item_business(self):
        from scripts.toyota_analysis import DcmAnalysis

        result = DcmAnalysis(self.profile, self.cache).run(2)
        self.assertEqual(result.native_status, 0)
        self.assertEqual(
            [q.request for q in self.calls],
            [
                b"\x21\0",
                b"\x21\x61",
                b"\x23\0\x04\x12\x34",
                b"\x23\0\x04\x12\x38",
                b"\x23\0\x04\x12\x3c",
            ],
        )
        (group,) = result.groups
        self.assertEqual((group.pid, group.name, group.format), (0x61, "Signal", 0))
        self.assertEqual([r.address for r in group.records], [0x1234, 0x123C])
        self.assertEqual(
            [(r.items[0].value, r.items[0].content) for r in group.records],
            [(5, "Content"), (7, "")],
        )
        self.assertTrue(
            all(q.capacity == 255 for q in self.calls if q.request == b"\x21\x61")
        )
        self.assertEqual(result.source_build, 18)

    def plain_context(self, *, p4=False):
        management = {
            slot: (section.count, section.payload)
            for slot, section in self.profile.catalog.management.sections.items()
        }
        category = bytearray(management[16][1])
        category[72] = 4 if p4 else 3
        management[16] = (1, bytes(category))
        module = bytearray(management[19][1])
        module[:80] = bytes(80)
        name = (
            "GetAnlzWrkFctP4_DT.dll\0" if p4 else "GetAnlzWrkFctP3_DT.dll\0"
        ).encode("utf-16le")
        module[: len(name)] = name
        module[86] = 0x6F
        management[19] = (1, bytes(module))
        (self.root / "Toyota.ddb").write_bytes(database(1, management))
        groups, checks = [], []
        for signal, logical in ((0x18, 2), (0x19, 1), (0x1A, 1), (0x1B, 3)):
            group = bytearray(12)
            struct.pack_into("<IH", group, 0, 1, signal)
            group[8] = signal
            groups.append(bytes(group))
            checks.append(struct.pack("<4H", signal, logical, 0, 0))
        freezes = bytearray(self.sections[10][1])
        for offset in range(0, len(freezes), 84):
            struct.pack_into("<H", freezes, offset + 60, 1)
        items = []
        for kind, first, last, reference in (
            (1, 0, 7, 0),
            (2, 0, 7, 0),
            (3, 8, 15, 2),
            (4, 16, 23, 0),
        ):
            item = bytearray(40)
            struct.pack_into("<5I", item, 0, 1, 1, 0, 1, 4)
            struct.pack_into("<6H", item, 20, 7, first, last, 0, reference, 10)
            item[34] = kind
            items.append(bytes(item))
        self.sections.update(
            {
                0: (4, b"".join(groups)),
                1: (4, b"".join(checks)),
                10: (4, bytes(freezes)),
                36: (4, b"".join(items)),
                37: (1, struct.pack("<II6H", 2, 3, 10, 1, 7, 0, 0, 0)),
                13: (1, struct.pack("<iiI6H", 2, 1, 3, 1, 1, 0, 0, 0, 0)),
                15: (1, struct.pack("<I4H", 4, 1, 0, 0, 0)),
            }
        )
        (self.root / "demo.ddb").write_bytes(database(2, self.sections))
        self.profile = VehicleCatalog(self.root).build_profile(42)
        for index, payload in enumerate(
            (b"\x01\x01\0\0", b"\xff" * 4, b"\x01\x01\0\0")
        ):
            for half in range(2):
                request = b"\x23\0\0" + (0x1234 + index * 4 + half * 2).to_bytes(
                    2, "big"
                )
                self.replies[request] = (
                    b"\x63" + request[1:] + payload[half * 2 : half * 2 + 2]
                )
            if p4:
                request = b"\x23\0\x04" + (0x1234 + index * 4).to_bytes(2, "big")
                self.replies[request] = b"\x63" + request[1:] + payload
        self.cache = MonitorSupportCache(
            self.profile,
            self.exchange,
            "plain-p3",
            bus_id=7,
            stream=self.stream if p4 else None,
        )

    def test_plain_p4_normal_selected_current_generic_pid_and_history(self):
        from scripts.toyota_analysis import PlainAnalysis

        self.plain_context(p4=True)
        result = PlainAnalysis(self.profile, self.cache).run()
        self.assertEqual(result.native_status, 0)
        self.assertEqual([row.value for row in result.current], [1, 4, 0])
        self.assertEqual(
            [row.value for row in result.groups[0].items], [1, 2, 0, 1, 2, 0]
        )
        self.assertEqual(len(self.calls), 5)

    def test_plain_p4_missing_optional_rows_use_native_defaults(self):
        from scripts.diagnostic_db import Section
        from scripts.toyota_analysis import PlainAnalysis

        self.plain_context(p4=True)
        section = self.profile.database.sections[36]
        # Keep content/type3 only: unlike P3, P4 supplies default type2/reset.
        rows = tuple(
            section.payload[i : i + 40] for i in range(0, len(section.payload), 40)
        )
        payload = b"".join(row for row in rows if row[34] in (1, 3))
        self.profile.database.sections[36] = Section(36, 0, 2, False, payload)
        result = PlainAnalysis(self.profile, self.cache).run()
        self.assertEqual(result.native_status, 0)
        items = result.groups[0].items
        self.assertEqual([row.value for row in items], [0, 2, 0] * 2)
        self.assertEqual([row.format for row in items], [0x4000, 1, 0x4000] * 2)
        self.assertEqual([row.content for row in items], ["Content", "Signal", "7"] * 2)

    def test_plain_p4_empty_definitions_fail_before_current_pid(self):
        from scripts.diagnostic_db import Section
        from scripts.toyota_analysis import PlainAnalysis

        self.plain_context(p4=True)
        self.profile.database.sections[35] = Section(35, 0, 0, False, b"")
        result = PlainAnalysis(self.profile, self.cache).run()
        self.assertEqual(result.native_status, 0xC0040101)
        self.assertEqual(
            (result.current, result.groups, result.calendar), ((), (), (0,) * 6)
        )
        self.assertEqual([query.request for query in self.calls], [b"\x21\0"])

    def test_plain_p4_unknown_mode_and_invalid_fixed_length_skip_ram_natively(self):
        from scripts.diagnostic_db import Section
        from scripts.toyota_analysis import PlainAnalysis

        for mode, length in ((5, 4), (3, 5), (99, 2)):
            with self.subTest(mode=mode, length=length):
                self.setUp()
                self.plain_context(p4=True)
                definition = bytearray(self.sections[35][1])
                struct.pack_into("<H", definition, 22, mode)
                definition[25] = length
                self.profile.database.sections[35] = Section(
                    35, 0, 1, False, bytes(definition)
                )
                result = PlainAnalysis(self.profile, self.cache).run()
                self.assertEqual((result.native_status, result.groups), (0, ()))
                self.assertEqual(
                    [query.request for query in self.calls], [b"\x21\0", b"\x21\x61"]
                )
                if mode == 5:
                    self.assertEqual(
                        (result.current, result.calendar, result.coefficient),
                        ((), (0,) * 6, 0),
                    )
                else:
                    self.assertEqual([row.value for row in result.current], [1, 4, 0])

    def plain_ts_context(self, *, selected=True, record_length=4):
        self.plain_context(p4=True)
        groups = self.sections[0][1]
        checks = self.sections[1][1]
        for signal, logical in ((0x1C, 1), (0x1D, 2)):
            group = bytearray(12)
            struct.pack_into("<IH", group, 0, 1, signal)
            group[8] = signal
            groups += bytes(group)
            checks += struct.pack("<4H", signal, logical, 0, 0)
        signal = bytearray(self.sections[35][1])
        if selected:
            struct.pack_into("<H", signal, 22, 4)
        signal[25] = record_length
        item = bytearray(self.sections[36][1][:40])
        struct.pack_into("<HH", item, 22, 8, 15)
        item[34] = 0x18
        freezes = bytearray(self.sections[10][1])
        for offset in range(0, len(freezes), 84):
            freezes[offset + 76] = 2
        self.sections[10] = (4, bytes(freezes))
        self.sections.update(
            {
                0: (6, groups),
                1: (6, checks),
                14: (0, b""),
                35: (1, bytes(signal)),
                36: (5, self.sections[36][1] + bytes(item)),
            }
        )
        (self.root / "demo.ddb").write_bytes(database(2, self.sections))
        if record_length != 4:
            self.replies = {
                request: reply
                for request, reply in self.replies.items()
                if not request.startswith(b"\x23")
            }
            for index in range(3):
                request = bytes((0x23, 0, record_length)) + (
                    0x1234 + index * record_length
                ).to_bytes(2, "big")
                payload = (
                    b"\xff" * record_length
                    if index == 1
                    else b"\x01\x01" + bytes(record_length - 2)
                )
                self.replies[request] = b"\x63" + request[1:] + payload
        self.profile = VehicleCatalog(self.root).build_profile(42)
        self.cache = MonitorSupportCache(
            self.profile, self.exchange, "plain-ts", bus_id=7, stream=self.stream
        )

    def test_plain_ts_selected_metadata_current_and_history_primitives(self):
        from scripts.toyota_analysis import PlainAnalysis, read_dcm_ram

        self.plain_ts_context(selected=False)
        provider = PlainAnalysis(self.profile, self.cache)
        with self.cache.temporary_scope():
            provider._masks = self.cache.support_bits(1)
            provider._enabled = self.cache.enabled_pids(family="p4", kind=1, control=0)
            current = provider._current_timestamp()
            self.assertEqual((current.dword00, current.auxiliary), (1, (1, 0)))
            self.assertEqual(
                [row.values for row in current.freezes], [((1, 0),), ((2, 0),), ()]
            )
            self.assertEqual(current.freezes[0].name, "Signal")
            self.assertEqual(
                (current.freezes[0].width, current.freezes[0].multiplier), (8, 2)
            )
            capture = read_dcm_ram(
                self.cache, bytes((1, 2, 0, 0)) + struct.pack("<I", 0x1234)
            )
            history = provider._history_timestamp(self.sections[35][1], capture)
        self.assertEqual([row.address for row in history], [0x123C, 0x1234])
        self.assertTrue(all(row.format == 8 for row in history))
        first = history[0].timestamp
        self.assertEqual((first.dword00, first.auxiliary), (1, (1, 0)))
        self.assertEqual(
            (first.freezes[0].multiplier, first.freezes[0].divisor), (1, 1)
        )
        self.assertEqual(first.freezes[1].divisor, 10)
        self.assertEqual(first.freezes[2].values, ())

    def test_plain_ts_selected_execute_partial_ram_and_default_missing_component(self):
        from scripts.diagnostic_db import Section
        from scripts.toyota_analysis import PlainAnalysis

        self.plain_ts_context()
        self.replies[b"\x23\0\x04\x12\x3c"] = ToyotaCodecError("read fault", 0x90020321)
        # Remove type18 only; native still emits kind2 with OR4000.
        rows = self.sections[36][1]
        self.profile.database.sections[36] = Section(36, 0, 4, False, rows[:160])
        result = PlainAnalysis(self.profile, self.cache).run()
        self.assertEqual(
            (result.native_status, result.groups, result.current), (0, (), ())
        )
        group = result.ts_groups[0]
        self.assertEqual([row.address for row in group.items], [0x1234])
        self.assertEqual(group.items[0].format, 0x4008)
        self.assertEqual(group.items[0].timestamp.freezes[1].values, ())
        self.assertEqual(result.current_timestamp.freezes[0].values, ((1, 0),))

    def test_plain_ts_current_abnormal_or_eager_metadata_fault_clears_both(self):
        from scripts.diagnostic_db import Section
        from scripts.toyota_analysis import PlainAnalysis, PlainTimestamp

        for failure in ("abnormal", "unit"):
            with self.subTest(failure=failure):
                self.setUp()
                self.plain_ts_context(selected=False)
                if failure == "abnormal":
                    self.replies[b"\x21\x61"] = b"\x61\x61\x01\xff\0\x12\x34"
                else:
                    row = bytearray(self.sections[15][1])
                    struct.pack_into("<I", row, 0, 0xFFFFFFFF)
                    self.profile.database.sections[15] = Section(
                        15, 0, 2, False, self.sections[15][1] + bytes(row)
                    )
                provider = PlainAnalysis(self.profile, self.cache)
                with self.cache.temporary_scope():
                    provider._masks = self.cache.support_bits(1)
                    provider._enabled = self.cache.enabled_pids(
                        family="p4", kind=1, control=0
                    )
                    self.assertEqual(provider._current_timestamp(), PlainTimestamp())

    def plain_psc_context(self, *, adjust=False):
        from test_monitor_support import SupportStreamDriver

        if adjust:
            self.plain_adjust_context()
        else:
            self.plain_context(p4=True)
        from scripts.diagnostic_db import parse_database

        path = self.root / "Toyota.ddb"
        parsed = parse_database(path.read_bytes())
        sections = {
            slot: (row.count, row.payload) for slot, row in parsed.sections.items()
        }
        module = bytearray(sections[19][1])
        module[:80] = bytes(80)
        name = "GetAnlWkFctP4PSC_DT.dll\0".encode("utf-16le")
        module[: len(name)] = name
        sections[19] = (1, bytes(module))
        path.write_bytes(database(1, sections))
        if adjust:
            freezes = bytearray(self.sections[10][1])
            for offset in range(0, len(freezes), 84):
                freezes[offset + 79] = 0x29
            self.sections[10] = (4, bytes(freezes))
            self.sections[6] = (1, bytes((0, 0, 0x29, 5, 0, 0, 0, 0)))
            (self.root / "demo.ddb").write_bytes(database(2, self.sections))
            self.replies[b"\x21\0"] = b"\x61\0" + bytes(5) + b"\x80"
            self.replies = {
                b"\x21\x29" if request == b"\x21\x61" else request: b"\x61\x29"
                + reply[2:]
                if request == b"\x21\x61" and isinstance(reply, bytes)
                else reply
                for request, reply in self.replies.items()
            }
            self.stream = SupportStreamDriver(
                [(0, b"\x41\0\x29\x05" + b"\xff" * 5), (0x91010009, b"")]
            )
        self.profile = VehicleCatalog(self.root).build_profile(42)
        self.cache = MonitorSupportCache(
            self.profile, self.exchange, "plain-psc", bus_id=7, stream=self.stream
        )

    def test_plain_psc_base_history_and_strict_reset_metadata(self):
        from scripts.diagnostic_db import Section
        from scripts.toyota_analysis import PlainAnalysis

        self.plain_psc_context()
        result = PlainAnalysis(self.profile, self.cache).run()
        self.assertEqual(result.native_status, 0)
        self.assertEqual([row.value for row in result.current], [1, 4, 0])
        self.assertEqual([row.value for row in result.groups[0].items], [1, 2, 0] * 2)
        self.assertEqual(len(self.calls), 5)
        self.setUp()
        self.plain_psc_context()
        section = self.profile.database.sections[36]
        payload = b"".join(
            section.payload[i : i + 40]
            for i in range(0, len(section.payload), 40)
            if section.payload[i + 34] != 4
        )
        self.profile.database.sections[36] = Section(36, 0, 3, False, payload)
        failed = PlainAnalysis(self.profile, self.cache).run()
        self.assertEqual(failed.native_status, 0xC0040102)
        self.assertEqual(failed.groups, ())

    def test_plain_p4_and_psc_phase3_current_keep_p4_history(self):
        from scripts.toyota_analysis import PlainAnalysis

        for psc in (False, True):
            with self.subTest(psc=psc):
                self.setUp()
                self.plain_psc_context() if psc else self.plain_context(p4=True)
                category = bytearray(self.profile.category_record)
                category[72] = 3
                sections = {
                    slot: (row.count, row.payload)
                    for slot, row in self.profile.catalog.management.sections.items()
                }
                sections[16] = (1, bytes(category))
                (self.root / "Toyota.ddb").write_bytes(database(1, sections))
                self.profile = VehicleCatalog(self.root).build_profile(42)
                self.cache = MonitorSupportCache(
                    self.profile, self.exchange, "phase3", bus_id=7, stream=self.stream
                )
                result = PlainAnalysis(self.profile, self.cache).run()
                self.assertEqual(result.native_status, 0)
                self.assertEqual([row.value for row in result.current], [1, 4, 0])
                self.assertEqual(
                    [row.value for row in result.groups[0].items], [1, 2, 0] * 2
                )
                pid_query = next(
                    query for query in self.calls if query.request == b"\x21\x61"
                )
                self.assertIsNone(pid_query.capacity)
                self.assertEqual(
                    sum(query.request.startswith(b"\x23") for query in self.calls), 3
                )

    def test_plain_psc_pid29_adjust_dispatch_and_failed_record(self):
        from scripts.toyota_analysis import PlainAnalysis

        self.plain_psc_context(adjust=True)
        self.replies[b"\x23\0\x04\x12\x34"] = ToyotaCodecError("read fault", 0x90020321)
        result = PlainAnalysis(self.profile, self.cache).run()
        self.assertEqual(result.native_status, 0)
        self.assertEqual(result.groups[0].pid, 0x29)
        self.assertEqual(len(result.groups[0].items), 15)
        self.assertEqual(
            [row.format for row in result.groups[0].items[3:6]], [0x2000] * 3
        )
        self.assertEqual([row.value for row in result.current], [1, 10, 0])

    def plain_adjust_context(self):
        self.plain_context(p4=True)
        directory, blob = b"", b""
        for text in ("Function", "Content12", "Signal", "Off", "On"):
            encoded = (text + "\0").encode("utf-16le")
            directory += struct.pack("<IH", len(blob), len(encoded))
            blob += encoded
        (self.root / "M_English.ddb").write_bytes(
            database(4, {0: (5, directory + blob)})
        )
        signal = bytearray(self.sections[35][1])
        struct.pack_into("<H", signal, 22, 99)
        self.sections[35] = (1, bytes(signal))
        self.sections[37] = (
            3,
            b"".join(
                struct.pack("<II6H", 2, 3, 10, opcode, 7, 0, 0, 0)
                for opcode in (1, 7, 0xE1)
            ),
        )
        (self.root / "demo.ddb").write_bytes(database(2, self.sections))
        self.profile = VehicleCatalog(self.root).build_profile(42)
        self.replies[b"\x21\x61"] = b"\x61\x61\x01\x05\0\x12\x34"
        for index, opcode in enumerate((0xE1, 7, 1, 1, 1, 0xFF)):
            request = b"\x23\0\x04" + (0x1234 + index * 4).to_bytes(2, "big")
            payload = b"\xff" * 4 if opcode == 0xFF else bytes((opcode, 1, 0, 0))
            self.replies[request] = b"\x63" + request[1:] + payload
        self.cache = MonitorSupportCache(
            self.profile, self.exchange, "plain-adjust", bus_id=7, stream=self.stream
        )

    def test_plain_p4_adjust_five_record_reorder_flags_and_narrow_content(self):
        from scripts.toyota_analysis import PlainAnalysis

        self.plain_adjust_context()
        result = PlainAnalysis(self.profile, self.cache).run()
        self.assertEqual(result.native_status, 0)
        self.assertEqual([row.value for row in result.current], [1, 10, 0])
        (group,) = result.groups
        self.assertEqual(group.display_type, 99)
        self.assertEqual(len(group.items), 15)
        self.assertEqual(
            [group.items[i].address for i in range(0, 15, 3)],
            [0x1238, 0x1234, 0x1244, 0x1240, 0x123C],
        )
        self.assertEqual(
            [row.format for row in group.items[:3]], [0x8000, 0x8001, 0x8000]
        )
        self.assertEqual(group.items[3].content, "Content70")
        self.assertEqual(group.items[4].content, "Signal")

    def test_plain_p4_adjust_partial_ram_keeps_failed_triplet_and_short_block(self):
        from scripts.toyota_analysis import PlainAnalysis

        self.plain_adjust_context()
        self.replies[b"\x23\0\x04\x12\x34"] = ToyotaCodecError(
            "Authored single-word fault", 0x90020323
        )
        result = PlainAnalysis(self.profile, self.cache).run()
        self.assertEqual(result.native_status, 0)
        group = result.groups[0]
        self.assertEqual(len(group.capture.words), 6)
        self.assertEqual(group.capture.words[0], (0x1234, bytes(4) + b"\x01\0\0\0"))
        self.assertEqual([row.format for row in group.items[3:6]], [0x2000] * 3)
        self.assertEqual([row.address for row in group.items[3:6]], [0] * 3)
        self.setUp()
        self.plain_adjust_context()
        self.replies[b"\x23\0\x04\x12\x44"] = ToyotaCodecError(
            "Authored newest-word fault", 0x90020323
        )
        result = PlainAnalysis(self.profile, self.cache).run()
        self.assertEqual(result.current[1].value, 10)
        self.assertEqual(
            [row.format for row in result.groups[0].items[6:9]], [0x2000] * 3
        )
        self.assertEqual(result.groups[0].items[10].value, 5)
        self.setUp()
        self.plain_adjust_context()
        self.replies[b"\x21\x61"] = b"\x61\x61\x01\x04\0\x12\x34"
        self.replies[b"\x23\0\x04\x12\x44"] = b"\x63\0\x04\x12\x44" + b"\xff" * 4
        result = PlainAnalysis(self.profile, self.cache).run()
        self.assertEqual(result.native_status, 0)
        self.assertEqual(result.groups[0].items, ())

    def test_plain_adjust_native_narrow_text_bounds_and_observed_encoding(self):
        from scripts.toyota_analysis import PlainAnalysis, PlainWorkFactorItem

        self.plain_adjust_context()
        provider = PlainAnalysis(self.profile, self.cache)
        base = PlainWorkFactorItem(0, 1, "", "", 0, "", 0, b"")
        rows = [base] * 15
        rows[9] = replace(base, opcode=7)
        rows[12] = replace(base, opcode=0xE1, content="A12B345C")
        self.assertEqual(provider._adjust_items(tuple(rows))[3].content, "A70B70C")
        rows[12] = replace(rows[12], content="x" * 256)
        with self.assertRaises(SessionError):
            provider._adjust_items(tuple(rows))
        rows[12] = replace(rows[12], content="日12")
        with self.assertRaises(SessionError):
            provider._adjust_items(tuple(rows))
        observed = PlainAnalysis(self.profile, self.cache, ansi_encoding="cp932")
        self.assertEqual(observed._adjust_items(tuple(rows))[3].content, "日70")
        rows[9] = replace(rows[9], opcode=12)
        rows[12] = replace(rows[12], content="1" + "日" * 127)
        with self.assertRaisesRegex(SessionError, "splits an ANSI character"):
            observed._adjust_items(tuple(rows))
        with self.assertRaises(SessionError):
            PlainAnalysis(self.profile, self.cache, ansi_encoding="utf-16le")

    def test_plain_p3_selected_execute_current_history_and_pattern_carrier(self):
        from scripts.toyota_analysis import PlainAnalysis

        self.plain_context()
        result = PlainAnalysis(self.profile, self.cache).run()
        self.assertEqual(result.native_status, 0)
        self.assertEqual([row.value for row in result.current], [1, 4, 0])
        self.assertEqual(result.coefficient, 2)
        self.assertEqual([row.format for row in result.current], [0, 4, 0])
        self.assertEqual(len(result.calendar), 6)
        (group,) = result.groups
        self.assertEqual(
            (group.identifier, group.display_type, group.pid, group.name),
            (0, 3, 0x61, "Signal"),
        )
        self.assertEqual([row.value for row in group.items], [1, 2, 0, 1, 2, 0])
        self.assertEqual(
            [row.content for row in group.items], ["Content", "Signal", "7"] * 2
        )
        self.assertEqual([row.format for row in group.items], [0, 1, 0] * 2)
        self.assertEqual(
            [row.address for row in group.items], [0x1234] * 3 + [0x123C] * 3
        )
        self.assertEqual(len(self.calls), 8)

    def test_plain_original12_18_actual_native_stack_and_cleanup(self):
        import json

        from scripts.command_api import (
            SOURCE_SHA256,
            CommandAPI,
            CommandSource,
            PlainFacadeFreezeMetadata,
        )
        from scripts.diagnostic_db import parse_database
        from scripts.frame_transport import J2534Result
        from scripts.toyota_analysis import PlainAnalysis

        for build, variant in (
            (12, 0),
            (18, 0),
            (12, 1),
            (18, 1),
            (12, 99),
            (18, 99),
            (12, 2),
            (18, 2),
            (12, 29),
            (18, 29),
            (12, 4),
            (18, 4),
            (12, 45),
            (18, 45),
        ):
            p4, adjust = bool(variant), variant in (99, 29)
            with self.subTest(build=build, variant=variant):
                self.setUp()
                if variant in (4, 45):
                    self.plain_ts_context(record_length=5 if variant == 45 else 4)
                elif variant in (2, 29):
                    self.plain_psc_context(adjust=adjust)
                elif adjust:
                    self.plain_adjust_context()
                else:
                    self.plain_context(p4=p4)
                if build == 12:
                    for filename, kind in (
                        ("Toyota.ddb", 1),
                        ("demo.ddb", 2),
                        ("M_English.ddb", 4),
                    ):
                        path = self.root / filename
                        parsed = parse_database(path.read_bytes())
                        sections = {
                            slot: (section.count, section.payload)
                            for slot, section in parsed.sections.items()
                        }
                        path.write_bytes(database(kind, sections, version=0x0100030C))
                    self.profile = VehicleCatalog(self.root).build_profile(42)
                fixture = RoBTests()
                fixture.profile = self.profile
                fixture.replies = {
                    key: value
                    for key, value in self.replies.items()
                    if key.startswith(
                        (
                            b"\x21",
                            bytes((0x23, 0, 5 if variant == 45 else 4))
                            if p4
                            else b"\x23\0\0",
                        )
                    )
                }
                if p4:
                    fixture.replies = {
                        b"stream": b"\x41\0"
                        + bytes((0x29 if variant == 29 else 0x61, 5))
                        + b"\xff" * 5,
                        **fixture.replies,
                    }
                connection, backend = fixture.native_rob_connection()
                if p4:
                    backend.replies.insert(1, J2534Result(code=9))
                try:
                    provider = PlainAnalysis(connection.profile, connection.cache)
                    wrong_build = 18 if build == 12 else 12
                    if variant in (4, 45):
                        provider.cache.cancelled = lambda: True
                        with self.assertRaises(Cancelled):
                            CommandAPI(
                                CommandSource(build, SOURCE_SHA256[build])
                            ).get_analyze_work_factor(provider)
                        self.assertEqual(backend.calls, [])
                        provider.cache.cancelled = lambda: False
                    with self.assertRaises(ValueError):
                        CommandAPI(
                            CommandSource(wrong_build, SOURCE_SHA256[wrong_build])
                        ).get_analyze_work_factor(provider)
                    self.assertEqual(backend.calls, [])
                    api = CommandAPI(CommandSource(build, SOURCE_SHA256[build]))
                    result = api.get_analyze_work_factor(provider)
                    self.assertEqual(result.return_code, 0)
                    if variant in (4, 45):
                        self.assertEqual(
                            (
                                result.groups,
                                result.current,
                                result.calendar,
                                result.coefficient,
                            ),
                            ((), (), (0,) * 6, 0),
                        )
                        self.assertEqual(len(result.ts_groups), 1)
                        self.assertEqual(
                            [row.address for row in result.ts_groups[0].items],
                            [0x123E if variant == 45 else 0x123C, 0x1234],
                        )
                        self.assertEqual(
                            [row.format for row in result.ts_groups[0].items], [8, 8]
                        )
                        timestamp = result.current_timestamp
                        self.assertEqual(timestamp.scalars, (1, 2, 0))
                        self.assertEqual(timestamp.auxiliary, (1, 0))
                        first, second = timestamp.metadata[:2]
                        history_metadata = (
                            result.ts_groups[0].items[0].timestamp.metadata[0]
                        )
                        assert isinstance(first, PlainFacadeFreezeMetadata)
                        assert isinstance(second, PlainFacadeFreezeMetadata)
                        assert isinstance(history_metadata, PlainFacadeFreezeMetadata)
                        self.assertEqual(first.values[0].display, "5")
                        self.assertEqual(second.values[0].display, "7")
                        self.assertEqual(
                            history_metadata.values[0].display, "-TypeErr-"
                        )
                    else:
                        self.assertEqual(
                            [row.value for row in result.groups[0].items],
                            [7, 5, 0, 225, 5, 0, 1, 5, 0, 1, 5, 0, 1, 5, 0]
                            if adjust
                            else [1, 2, 0, 1, 2, 0],
                        )
                        self.assertEqual(
                            [row.value for row in result.current],
                            [1, 10, 0] if adjust else [1, 4, 0],
                        )
                        if adjust:
                            self.assertEqual(
                                result.groups[0].items[3].content, "Content70"
                            )
                        self.assertEqual(
                            (result.ts_groups, result.current_timestamp.scalars),
                            ((), (0, 0, 0)),
                        )
                    report = json.loads(json.dumps(api.plain_analysis_report(result)))
                    self.assertEqual(report["operation"], "GetAnalyzeWorkFactorAPI")
                    self.assertEqual(report["source"]["version"], build)
                finally:
                    self.assertEqual(connection.disconnect(), 0)
                self.assertEqual(
                    sum(name == "write_messages" for name, _ in backend.calls),
                    9 if adjust else 6 if p4 else 8,
                )
                fixture.replies = {
                    key: (b"\x7f\x23\x12" if key.startswith(b"\x23") else value)
                    for key, value in fixture.replies.items()
                    if not key.startswith(b"\x23")
                    or p4
                    or int.from_bytes(key[2:], "big")
                    in tuple(0x1234 + index * 4 for index in range(6 if adjust else 3))
                }
                connection, backend = fixture.native_rob_connection()
                if p4:
                    backend.replies.insert(1, J2534Result(code=9))
                try:
                    failed = api.get_analyze_work_factor(
                        PlainAnalysis(connection.profile, connection.cache),
                        previous=result,
                    )
                    self.assertEqual(failed.return_code, 0x90020321)
                    self.assertEqual(failed.groups, result.groups)
                    self.assertEqual(failed.current, result.current)
                    self.assertEqual(failed.ts_groups, result.ts_groups)
                    self.assertEqual(failed.current_timestamp, result.current_timestamp)
                finally:
                    self.assertEqual(connection.disconnect(), 0)
                self.assertEqual(
                    sum(name == "write_messages" for name, _ in backend.calls),
                    9 if adjust else 6 if p4 else 5,
                )

    def test_plain_selected_metadata_fault_cancel_and_context_guards(self):
        from scripts.diagnostic_db import Section
        from scripts.toyota_analysis import PlainAnalysis

        self.plain_context()
        provider = PlainAnalysis(self.profile, self.cache)
        self.cache.cancelled = lambda: True
        with self.assertRaises(Cancelled):
            provider.run()
        self.assertEqual(self.calls, [])
        self.cache.cancelled = lambda: False
        original = self.profile.database.sections[36]
        self.profile.database.sections[36] = Section(
            36, 0, 3, False, original.payload[:120]
        )
        result = provider.run()
        self.assertEqual((result.native_status, result.groups), (0xC0040102, ()))
        self.cache.bus_id = 8
        before = len(self.calls)
        with self.assertRaises(SessionError):
            provider.run()
        self.assertEqual(len(self.calls), before)

    def test_plain_init_error_is_not_current_time_unavailable_success(self):
        from scripts.toyota_analysis import PlainAnalysis

        self.plain_context()
        self.replies[b"\x21\0"] = ToyotaCodecError("Authored init failure", 0xC0050414)
        result = PlainAnalysis(self.profile, self.cache).run()
        self.assertEqual(
            (result.native_status, result.current, result.groups), (0xC0050414, (), ())
        )

    def test_native_ram_partial_failure_and_total_failure_status(self):
        from scripts.toyota_analysis import DcmAnalysis

        self.replies[b"\x23\0\x04\x12\x34"] = ToyotaCodecError("literal", 0x90020323)
        result = DcmAnalysis(self.profile, self.cache).run(2)
        self.assertEqual(result.native_status, 0)
        self.assertEqual([r.address for r in result.groups[0].records], [0x123C])
        for request in tuple(self.replies):
            if request.startswith(b"\x23"):
                self.replies[request] = ToyotaCodecError("literal", 0x90020323)
        result = DcmAnalysis(self.profile, self.cache).run(2)
        self.assertEqual((result.native_status, result.groups), (0x90020323, ()))

    def test_selected_guards_cancellation_and_unrecovered_branch(self):
        from scripts.toyota_analysis import DcmAnalysis

        provider = DcmAnalysis(self.profile, self.cache)
        with self.assertRaisesRegex(SessionError, "variable"):
            provider.run(4)
        self.assertEqual(self.calls, [])
        with self.assertRaises(ToyotaCodecError):
            provider.run(True)
        self.cache.cancelled = lambda: True
        with self.assertRaises(Cancelled):
            provider.run(2)

    def current_context(self):
        groups, checks = [], []
        for signal in range(0x1E, 0x23):
            group = bytearray(12)
            struct.pack_into("<IH", group, 0, 1, signal)
            group[8] = signal
            groups.append(group)
            checks.append(struct.pack("<4H", signal, 1, 0, 0))
        physical = struct.pack("<iiI6H", 2, 1, 3, 1, 1, 0, 0, 0, 0)
        freezes = bytearray(self.sections[10][1])
        struct.pack_into("<H", freezes, 60, 1)
        self.sections.update(
            {
                0: (5, b"".join(groups)),
                1: (5, b"".join(checks)),
                10: (4, freezes),
                13: (1, physical),
                15: (1, struct.pack("<I4H", 4, 1, 0, 0, 0)),
            }
        )
        (self.root / "demo.ddb").write_bytes(database(2, self.sections))
        self.profile = VehicleCatalog(self.root).build_profile(42)
        self.cache = MonitorSupportCache(
            self.profile, self.exchange, "current-dcm", bus_id=7, stream=self.stream
        )

    def test_current_five_selected_signals_and_swallowed_pid_fault(self):
        from scripts.toyota_analysis import DcmAnalysis

        self.current_context()
        provider = DcmAnalysis(self.profile, self.cache)
        result = provider.run(1)
        self.assertEqual(
            [(v.name, v.value, v.unit, v.format) for v in result.current],
            [("Function", 5, "Off", 4)] * 5,
        )
        self.assertEqual(result.groups, ())
        self.assertEqual([q.request for q in self.calls], [b"\x21\0", b"\x21\x61"])
        from scripts.command_api import SOURCE_SHA256, CommandAPI, CommandSource
        from scripts.frame_transport import J2534Result

        fixture = RoBTests()
        fixture.profile = self.profile
        fixture.replies = {b"stream": b"\x41\0\x61\x05" + b"\xff" * 5, **self.replies}
        connection, backend = fixture.native_rob_connection()
        backend.replies.insert(1, J2534Result(code=9))
        try:
            api = CommandAPI(CommandSource(18, SOURCE_SHA256[18]))
            output = api.get_analyze_work_factor_dcm(
                DcmAnalysis(connection.profile, connection.cache), mode=1
            )
            self.assertEqual((output.return_code, output.current_valid), (0, 1))
            self.assertEqual(output.current_words, (5,) * 5)
        finally:
            self.assertEqual(connection.disconnect(), 0)
        self.replies[b"\x21\x61"] = ToyotaCodecError("literal", 0x90020323)
        result = provider.run(1)
        self.assertEqual(
            [(v.value, v.unit, v.format) for v in result.current], [(0, "", 0x4004)] * 5
        )

    def test_actual_native_j2534_support_pid_ram_to_dcm(self):
        from scripts.frame_transport import J2534Result
        from scripts.toyota_analysis import DcmAnalysis

        fixture = RoBTests()
        fixture.profile = self.profile
        fixture.replies = {b"stream": b"\x41\0\x61\x05" + b"\xff" * 5, **self.replies}
        connection, backend = fixture.native_rob_connection()
        backend.replies.insert(1, J2534Result(code=9))
        try:
            result = DcmAnalysis(connection.profile, connection.cache).run(2)
            self.assertEqual(result.native_status, 0)
            self.assertEqual(
                [r.items[0].value for r in result.groups[0].records], [5, 7]
            )
            self.assertFalse(connection.closed)
        finally:
            self.assertEqual(connection.disconnect(), 0)
        self.assertEqual(sum(op == "write_messages" for op, _ in backend.calls), 6)

    def test_native_j2534_dcm_to_public_command_consumer(self):
        import json

        from scripts.command_api import SOURCE_SHA256, CommandAPI, CommandSource
        from scripts.frame_transport import J2534Result
        from scripts.toyota_analysis import DcmAnalysis

        fixture = RoBTests()
        fixture.profile = self.profile
        fixture.replies = {b"stream": b"\x41\0\x61\x05" + b"\xff" * 5, **self.replies}
        connection, backend = fixture.native_rob_connection()
        backend.replies.insert(1, J2534Result(code=9))
        api = CommandAPI(CommandSource(18, SOURCE_SHA256[18]))
        try:
            result = api.get_analyze_work_factor_dcm(
                DcmAnalysis(connection.profile, connection.cache), mode=0
            )
            self.assertEqual(result.return_code, 0)
            # Native flat facade omits records with fewer than nine items.
            self.assertEqual(result.flat_records, ())
            report = json.loads(json.dumps(api.analysis_report(result)))
            self.assertEqual(report["operation"], "GetAnalyzeWorkFactorDcmAPI")
            self.assertEqual(report["source_sha256"], SOURCE_SHA256[18])
        finally:
            self.assertEqual(connection.disconnect(), 0)
        self.assertEqual(sum(op == "write_messages" for op, _ in backend.calls), 6)

    def test_variable_execute_actual_selected_ram_journal_and_rich_consumer(self):
        for build in (18, 12):
            with self.subTest(build=build):
                self.setUp()
                self.variable_execute_case(build)

    def test_battery_variable_execute_actual_selected_lower_and_consumer(self):
        for build in (12, 18):
            with self.subTest(build=build):
                self.setUp()
                self.variable_execute_case(build, battery=True)

    def variable_execute_case(self, build, *, battery=False):
        from test_monitor_support import SupportStreamDriver

        from scripts.command_api import SOURCE_SHA256, CommandAPI, CommandSource
        from scripts.toyota_analysis import DcmAnalysis, DcmLog

        self.current_context()
        family = "BT-03" if battery else "DCM-02"
        if battery:
            management = {
                slot: (section.count, section.payload)
                for slot, section in self.profile.catalog.management.sections.items()
            }
            module = bytearray(management[19][1])
            module[:80] = bytes(80)
            name = "GetAnlWkFctBTP4_DT.dll\0".encode("utf-16le")
            module[: len(name)] = name
            management[19] = (1, bytes(module))
            (self.root / "Toyota.ddb").write_bytes(database(1, management))
        signal = bytearray(self.sections[35][1])
        struct.pack_into("<H", signal, 22, 8)
        signal[24:26] = b"\x01\x04"
        item = bytearray(self.sections[36][1])
        item[36] = 1
        self.sections[35], self.sections[36] = (1, signal), (1, item)
        (self.root / "demo.ddb").write_bytes(database(2, self.sections))
        if build == 12:
            from scripts.diagnostic_db import parse_database

            for filename, kind in (
                ("Toyota.ddb", 1),
                ("demo.ddb", 2),
                ("M_English.ddb", 4),
            ):
                path = self.root / filename
                original = parse_database(path.read_bytes())
                sections = {
                    slot: (section.count, section.payload)
                    for slot, section in original.sections.items()
                }
                path.write_bytes(database(kind, sections, version=0x0100030C))
        self.profile = VehicleCatalog(self.root).build_profile(42)
        stream = SupportStreamDriver(
            [(0, b"\x41\0\x61\x05" + b"\xff" * 5), (0x91010009, b"")]
        )
        cache = MonitorSupportCache(
            self.profile,
            self.exchange,
            "variable-dcm",
            bus_id=7,
            stream=stream,
            source_build=build,
        )
        journal = DcmLog(self.root / "journal", 9, family=family)
        provider = DcmAnalysis(self.profile, cache, journal=journal)
        if battery:
            with self.assertRaisesRegex(SessionError, "Journal mapping"):
                DcmAnalysis(
                    self.profile, cache, journal=DcmLog(self.root / "wrong", 9)
                ).run(4)
            self.assertEqual(self.calls, [])
        result = provider.run(4)
        self.assertEqual(result.native_status, 0)
        self.assertEqual([r.items[0].value for r in result.groups[0].records], [5, 7])
        self.assertEqual(
            [r.items[0].format for r in result.groups[0].records], [8, 0x8008]
        )
        path = result.journal_path
        assert path is not None
        self.assertTrue(path.name.startswith(family + "_"))
        content = path.read_bytes()
        self.assertTrue(
            content.startswith(b"Car ID:9\r\nECU ID:42\r\nBUS ID:7\r\n\r\n")
        )
        self.assertIn(
            b"TST:23,00,04,12,34\r\nECU:63,00,04,12,34,01,02,03,04\r\n", content
        )
        self.assertEqual(content.count(b"TST:"), 4)
        api = CommandAPI(CommandSource(build, SOURCE_SHA256[build]))
        output = api.get_analyze_work_factor_dcm(provider, mode=2)
        self.assertEqual(output.return_code, 0)
        self.assertEqual(len(output.groups), 1)
        self.assertEqual(output.current_words, (5,) * 5)

        from scripts.frame_transport import J2534Result

        fixture = RoBTests()
        fixture.profile = self.profile
        fixture.replies = {b"stream": b"\x41\0\x61\x05" + b"\xff" * 5, **self.replies}
        connection, backend = fixture.native_rob_connection()
        backend.replies.insert(1, J2534Result(code=9))
        try:
            native = api.get_analyze_work_factor_dcm(
                DcmAnalysis(
                    connection.profile,
                    connection.cache,
                    journal=DcmLog(self.root / "native-journal", 9, family=family),
                ),
                mode=2,
            )
            self.assertEqual(native.return_code, 0)
            self.assertEqual(len(native.groups), 1)
            self.assertEqual(native.current_words, (5,) * 5)
        finally:
            self.assertEqual(connection.disconnect(), 0)

        bad = self.root / "blocked-journal"
        bad.write_bytes(b"authored")
        failed = api.get_analyze_work_factor_dcm(
            DcmAnalysis(self.profile, cache, journal=DcmLog(bad, 9, family=family)),
            mode=2,
            previous=output,
        )
        self.assertEqual(failed, replace(output, return_code=0x90040F01))

    def test_native_dcm_qsort_and_journal_rotation_bounds(self):
        from scripts.toyota_analysis import DcmLog, _dcm_sort

        rows = tuple(struct.pack("<HH", 1, index) for index in range(3))
        self.assertEqual(
            [struct.unpack_from("<H", row, 2)[0] for row in _dcm_sort(rows, 0)],
            [1, 2, 0],
        )
        equal = tuple(struct.pack("<HH", 1, index) for index in range(10))
        self.assertEqual(
            [struct.unpack_from("<H", row, 2)[0] for row in _dcm_sort(equal, 0)],
            [5, 1, 2, 3, 4, 0, 6, 7, 8, 9],
        )
        mixed = tuple(
            struct.pack("<H", value) for value in (9, 4, 8, 5, 2, 0, 3, 1, 7, 6)
        )
        self.assertEqual(
            [struct.unpack("<H", row)[0] for row in _dcm_sort(mixed, 0)],
            list(range(10)),
        )
        directory = self.root / "journal"
        directory.mkdir()
        for index in range(11):
            (directory / f"DCM-02_01012020{index:06d}.log").write_bytes(b"authored")
        status, path = DcmLog(directory, 0).write(42, 7, ((bytes(range(64)), b""),))
        self.assertEqual(status, 0)
        self.assertEqual(len(tuple(directory.glob("*.log"))), 10)
        assert path is not None
        text = path.read_bytes()
        self.assertIn(b"3E\r\nECU:\r\n", text)
        self.assertNotIn(b"3F", text)
        battery = self.root / "battery-journal"
        battery.mkdir()
        for index in range(11):
            (battery / f"BT-03_01012020{index:06d}.log").write_bytes(b"authored")
        upper = battery / "BT-03_01012019000000.LOG"
        upper.write_bytes(b"authored")
        status, path = DcmLog(battery, 0, family="BT-03").write(42, 7, ())
        self.assertEqual(status, 0)
        self.assertTrue(upper.exists())
        self.assertEqual(len(tuple(battery.iterdir())), 11)
        self.assertFalse((battery / "BT-03_01012020000000.log").exists())
        assert path is not None
        self.assertTrue(path.name.startswith("BT-03_"))
        with self.assertRaises(ValueError):
            DcmLog(battery, 0, family="arbitrary")
        bad = self.root / "not-a-directory"
        bad.write_bytes(b"authored")
        self.assertEqual(DcmLog(bad, 0).write(42, 7, ()), (0x90040F01, None))

    def test_original12_fixed_execute_and_actual_native_lower(self):
        from scripts.diagnostic_db import parse_database
        from scripts.frame_transport import J2534Result
        from scripts.toyota_analysis import DcmAnalysis

        catalog = self.profile.catalog
        management = {
            slot: (section.count, section.payload)
            for slot, section in catalog.management.sections.items()
        }
        language = {
            slot: (section.count, section.payload)
            for slot, section in parse_database(
                (self.root / "M_English.ddb").read_bytes()
            ).sections.items()
        }
        (self.root / "Toyota.ddb").write_bytes(
            database(1, management, version=0x0100030C)
        )
        (self.root / "demo.ddb").write_bytes(
            database(2, self.sections, version=0x0100030C)
        )
        (self.root / "M_English.ddb").write_bytes(
            database(4, language, version=0x0100030C)
        )
        self.profile = VehicleCatalog(self.root).build_profile(42)
        fixture = RoBTests()
        fixture.profile = self.profile
        fixture.replies = {b"stream": b"\x41\0\x61\x05" + b"\xff" * 5, **self.replies}
        connection, backend = fixture.native_rob_connection()
        backend.replies.insert(1, J2534Result(code=9))
        from scripts.command_api import SOURCE_SHA256, CommandAPI, CommandSource

        try:
            provider = DcmAnalysis(connection.profile, connection.cache)
            with self.assertRaises(ValueError):
                CommandAPI(
                    CommandSource(18, SOURCE_SHA256[18])
                ).get_analyze_work_factor_dcm(provider)
            self.assertEqual(backend.calls, [])
            result = provider.run(2)
            self.assertEqual(result.native_status, 0)
            self.assertEqual(result.source_build, 12)
            self.assertEqual(
                result.source_sha256,
                "d697f922c182ec4274bed1fd6939440b8cacffc21e0450cd44a6576d179702ba",
            )
            self.assertEqual(
                [r.items[0].value for r in result.groups[0].records], [5, 7]
            )
            with self.assertRaisesRegex(SessionError, "journal mapping"):
                provider.run(4)
        finally:
            self.assertEqual(connection.disconnect(), 0)

        connection, backend = fixture.native_rob_connection()
        backend.replies.insert(1, J2534Result(code=9))
        api = CommandAPI(CommandSource(12, SOURCE_SHA256[12]))
        try:
            output = api.get_analyze_work_factor_dcm(
                DcmAnalysis(connection.profile, connection.cache), mode=0
            )
            self.assertEqual((output.return_code, output.flat_records), (0, ()))
            report = api.analysis_report(output)
            self.assertEqual(report["source_version"], 12)
            self.assertEqual(report["source_sha256"], SOURCE_SHA256[12])
        finally:
            self.assertEqual(connection.disconnect(), 0)

    def test_selected_dcm24_variable_preserves_distinct_read_failure_policy(self):
        from test_monitor_support import SupportStreamDriver

        from scripts.command_api import SOURCE_SHA256, CommandAPI, CommandSource
        from scripts.frame_transport import J2534Result
        from scripts.toyota_analysis import DcmAnalysis, DcmLog

        self.current_context()
        management = {
            slot: (section.count, section.payload)
            for slot, section in self.profile.catalog.management.sections.items()
        }
        module = bytearray(management[19][1])
        module[:80] = bytes(80)
        name = "GetAnlWkFctDcm24_DT.dll\0".encode("utf-16le")
        module[: len(name)] = name
        management[19] = (1, bytes(module))
        (self.root / "Toyota.ddb").write_bytes(database(1, management))
        signal = bytearray(self.sections[35][1])
        signal[24:26] = b"\x01\x04"
        self.sections[35] = (1, signal)
        (self.root / "demo.ddb").write_bytes(database(2, self.sections))
        self.profile = VehicleCatalog(self.root).build_profile(42)
        fixture = RoBTests()
        fixture.profile = self.profile
        fixture.replies = {b"stream": b"\x41\0\x61\x05" + b"\xff" * 5, **self.replies}
        connection, backend = fixture.native_rob_connection()
        backend.replies.insert(1, J2534Result(code=9))
        try:
            provider = DcmAnalysis(
                connection.profile,
                connection.cache,
                journal=DcmLog(self.root / "dcm24-journal", 9),
            )
            with self.assertRaises(ValueError):
                CommandAPI(
                    CommandSource(12, SOURCE_SHA256[12])
                ).get_analyze_work_factor_dcm(provider, mode=2)
            self.assertEqual(backend.calls, [])
            result = provider.run(4)
            self.assertEqual(result.native_status, 0)
            self.assertEqual(
                result.source_sha256,
                "65dee471c46438f8b097833eb9a1df90b252a5b7162fc7de473ef99b4e638b68",
            )
            self.assertEqual(
                [r.items[0].value for r in result.groups[0].records], [5, 7]
            )
        finally:
            self.assertEqual(connection.disconnect(), 0)
        connection, backend = fixture.native_rob_connection()
        backend.replies.insert(1, J2534Result(code=9))
        api = CommandAPI(CommandSource(18, SOURCE_SHA256[18]))
        try:
            output = api.get_analyze_work_factor_dcm(
                DcmAnalysis(
                    connection.profile,
                    connection.cache,
                    journal=DcmLog(self.root / "dcm24-public", 9),
                ),
                mode=2,
            )
            self.assertEqual(output.return_code, 0)
            self.assertEqual(len(output.groups), 1)
            self.assertEqual(output.current_words, (5,) * 5)
        finally:
            self.assertEqual(connection.disconnect(), 0)
        for request in tuple(self.replies):
            if request.startswith(b"\x23"):
                self.replies[request] = ToyotaCodecError("literal", 0x90020323)
        stream = SupportStreamDriver(
            [(0, b"\x41\0\x61\x05" + b"\xff" * 5), (0x91010009, b"")]
        )
        cache = MonitorSupportCache(
            self.profile, self.exchange, "dcm24", bus_id=7, stream=stream
        )
        result = DcmAnalysis(
            self.profile, cache, journal=DcmLog(self.root / "dcm24-journal", 9)
        ).run(4)
        self.assertEqual(result.native_status, 0)
        self.assertEqual(len(result.groups), 1)
        self.assertEqual(result.groups[0].records, ())
        output = api.get_analyze_work_factor_dcm(
            DcmAnalysis(
                self.profile, cache, journal=DcmLog(self.root / "fault-journal", 9)
            ),
            mode=2,
        )
        self.assertEqual(output.return_code, 0)
        self.assertEqual(len(output.groups), 1)
        self.assertEqual(output.groups[0].records, ())
        signal[24] = 0
        self.sections[35] = (1, signal)
        (self.root / "demo.ddb").write_bytes(database(2, self.sections))
        self.profile = VehicleCatalog(self.root).build_profile(42)
        stream = SupportStreamDriver(
            [(0, b"\x41\0\x61\x05" + b"\xff" * 5), (0x91010009, b"")]
        )
        cache = MonitorSupportCache(
            self.profile, self.exchange, "dcm24", bus_id=7, stream=stream
        )
        result = DcmAnalysis(
            self.profile, cache, journal=DcmLog(self.root / "unused-journal", 9)
        ).run(4)
        self.assertEqual(
            (result.native_status, result.groups, result.journal_path), (0, (), None)
        )

    def test_plain_ts_direct_ram_variable_byte_length_and_ceil_stride(self):
        from scripts.toyota_analysis import read_dcm_ram

        raw = bytes((0, 2, 0, 0)) + struct.pack("<I", 0x1234)
        self.replies = {
            b"\x23\0\x05" + address.to_bytes(2, "big"): b"\x63\0\x05"
            + address.to_bytes(2, "big")
            + bytes((index, 1, 2, 3, 4))
            for index, address in enumerate((0x1234, 0x1237, 0x123A))
        }
        result = read_dcm_ram(self.cache, raw, record_length=5)
        self.assertEqual(result.native_status, 0)
        self.assertEqual(
            [address for address, _ in result.words], [0x1234, 0x1237, 0x123A]
        )
        self.assertTrue(all(len(payload) == 5 for _, payload in result.words))
        self.assertEqual(len(self.calls), 3)
        for length in (0, 256, True):
            with self.assertRaises(ToyotaCodecError):
                read_dcm_ram(self.cache, raw, record_length=length)
        self.assertEqual(len(self.calls), 3)

    def test_plain_p3_ram_halfwords_and_dword_count255(self):
        from scripts.toyota_analysis import read_plain_p3_ram

        calls = []

        def exchange(query):
            calls.append(query.request)
            return (
                bytes((query.request[0] | 0x40,))
                + query.request[1:]
                + (b"ab" if len(calls) & 1 else b"cd")
            )

        cache = MonitorSupportCache(self.profile, exchange, "plain-p3", bus_id=7)
        raw = b"\x01\x01\x03\0" + struct.pack("<I", 0x1234)
        result = read_plain_p3_ram(cache, raw)
        self.assertEqual(
            calls,
            [
                b"\x23\x03\0\x12\x34",
                b"\x23\x03\0\x12\x36",
                b"\x23\x03\0\x12\x38",
                b"\x23\x03\0\x12\x3a",
            ],
        )
        self.assertEqual(
            result.words, ((0x1234, b"abcd" + bytes(4)), (0x1238, b"abcd" + bytes(4)))
        )
        cache.limits = replace(cache.limits, exchanges=516)
        raw = raw[:1] + b"\xff" + raw[2:]
        result = read_plain_p3_ram(cache, raw)
        self.assertEqual(len(result.words), 256)
        self.assertEqual(len(calls), 516)
        cache.cancelled = lambda: True
        with self.assertRaises(Cancelled):
            read_plain_p3_ram(cache, raw)

    def test_analysis_rejects_management_only_profile_before_metadata_or_io(self):
        from scripts.profiles import ProtocolProfile
        from scripts.toyota_analysis import DcmAnalysis, PlainAnalysis

        cache = MonitorSupportCache(self.profile, self.exchange, "toyota", bus_id=7)
        management_only = object.__new__(ProtocolProfile)
        for provider in (DcmP5Analysis, RoBAnalysis, DcmAnalysis, PlainAnalysis):
            with (
                self.subTest(provider=provider.__name__),
                self.assertRaisesRegex(SessionError, "Toyota metadata"),
            ):
                provider(management_only, cache)
        self.assertEqual(self.calls, [])

    def test_plain_p3_ram_partial_fault_skips_half_and_retains_last_error(self):
        from scripts.toyota_analysis import read_plain_p3_ram

        calls = []
        failures = {0x1234: 0x90020327, 0x1239: 0x91010009}

        def exchange(query):
            calls.append(query.request)
            address = int.from_bytes(query.request[2:], "big")
            if address in failures:
                raise ToyotaCodecError("Authored RAM fault", failures[address])
            return b"\x63" + query.request[1:] + b"ab"

        cache = MonitorSupportCache(self.profile, exchange, "plain-p3-fault", bus_id=7)
        raw = b"\0\x02\x03\0" + struct.pack("<I", 0x1234)
        result = read_plain_p3_ram(cache, raw)
        self.assertEqual(
            [int.from_bytes(request[2:], "big") for request in calls],
            [0x1234, 0x1236, 0x1237, 0x1238, 0x1239],
        )
        self.assertEqual(result.native_status, 0)
        self.assertEqual(result.words, ((0x1236, b"abab" + bytes(4)),))
        self.assertEqual(result.failures, ((0x1234, 0x90020327), (0x1239, 0x91010009)))
        failures[0x1236] = 0xA0040201
        result = read_plain_p3_ram(cache, raw)
        self.assertEqual((result.native_status, result.words), (0x91010009, ()))
        calls.clear()
        result = read_plain_p3_ram(cache, b"\xff\0" + bytes(6))
        self.assertEqual((result.native_status, calls), (0, []))
        cache.source_build = 12
        with self.assertRaises(SessionError):
            read_plain_p3_ram(cache, raw)
        self.assertEqual(calls, [])

    def test_dcm_narrow_cross_byte_field_is_not_generic_helper(self):
        from scripts.toyota_analysis import _dcm_bits, _rob_bits

        self.assertEqual(_dcm_bits(b"\x03\x80", 6, 8), 7)
        self.assertNotEqual(_rob_bits(b"\x03\x80", 6, 8), 7)


if __name__ == "__main__":
    unittest.main()
