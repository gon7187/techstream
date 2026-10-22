"""Authored native bytes, with independent literal expected field values."""

import json
import struct
import unittest
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast
from unittest.mock import create_autospec, patch

from scripts import snapshot, tse_reports
from scripts.database_resources import (
    AdsDecodedRecord,
    AdsRawRecord,
    AdsValueSeries,
    DdrAttribute,
    DdrAttributeCapture,
    DdrCapture,
    DdrCapturedRecord,
    DdrEcuContext,
    DdrP5Case,
    DdrP5DataIdReader,
    DdrP5Header,
    DdrP5RawCapture,
    DdrP5Report,
    DdrP5SupportValue,
    DdrPacketLog,
    DdrPartialReportError,
    DdrRecordSamples,
    DdrTimelineSamples,
    DdrValueSeries,
    NativeRamReader,
    RamFrame,
    RamReplay,
    ads_bits,
    apply_ddr_invalid_conditions,
    apply_ddr_marker_flags,
    apply_ddr_p5_time_values,
    bind_ads_ddr_report,
    bind_ddr_report,
    bind_ddr_report_header,
    cancel_ads_security,
    capture_ddr_attributes,
    capture_ddr_bulk_payload,
    capture_ddr_bulk_record_samples,
    capture_ddr_p5_raw_records,
    capture_ddr_p5_records,
    capture_ddr_p5_saved_log,
    capture_ddr_record_samples,
    capture_ddr_records,
    capture_ddr_records_saved_log,
    capture_ddr_saved_log,
    capture_ddr_timeline_samples,
    capture_file,
    capture_internal_ddr_report,
    capture_section,
    create_ram_examples,
    ddr_bits,
    ddr_bulk_record_eligible,
    ddr_p5_case_identifiers,
    ddr_report_support_values,
    ddr_saved_information,
    ddr_timeline_values,
    decode_ads_ddr_record,
    decode_ddr_bulk_payload,
    decode_ddr_p5_detail,
    decode_ddr_p5_header,
    encode_ram_recording,
    format_ads_ddr_info,
    format_ddr_capture,
    format_ddr_info,
    format_ddr_p5_capture,
    initial_ddr_attribute_plan,
    initial_ddr_p5_attribute_plan,
    mark_ddr_unchecked,
    ordered_ddr_series,
    parse_ads_record_packet,
    prepare_ddr_session,
    propagate_ddr_invalid_flags,
    ram_payload,
    ram_request,
    select_comm_pid_target,
    select_ddr_attribute,
    selected_ads_security_key,
    selected_ddr_less_a8_attribute,
    selected_ddr_record_plan,
    selected_ddr_signal_definition,
    transform_ads_ddr_record,
    transform_ddr_record,
    trim_ddr_p5_case_payload,
)
from scripts.monitor_support import MonitorSupportCache
from scripts.native_communication import NativeCommunication
from scripts.profiles import VehicleCatalog
from scripts.snapshot import SnapshotError
from scripts.toyota import CommandFrame, ToyotaCodecError
from scripts.toyota_session import Cancelled, Limits, NativeStatus, SessionError

# Native <u32 id,u32 type,u16 version>, two MIL screen lists. All five lengths u16.
MIL = bytes.fromhex(
    "ffffffff10ffffff0010"
    "0100 010041 010042 010043 020000ff 0300726177"
    "0100 0000 0000 0000 010080 0000"
)
MARKET = bytes.fromhex(
    "ffffffff10ffffff01100100 0300656375 0200 78563412 03000000 00ff80ffffffff 00000000"
)


class DatabaseResourceTests(unittest.TestCase):
    def test_native_file_selection_provenance_and_source_preservation(self):
        for family, feature, raw in (
            ("MILMessage", 0x271B, MIL),
            ("MktMonRam", 0x2731, MARKET),
            ("MktMonRamSSR", 0x2735, MARKET),
        ):
            template = snapshot.create_tse_header(
                snapshot.TSEHeader(
                    "TSE", 0, 0x102C, 0, 0, 0, 0, b"", b"", (), (feature,), b""
                )
            )
            fragments = tuple(
                raw if entry["tag"] == family else b""
                for entry in template.metadata["index_entries"]
            )
            file = snapshot.assemble_tse(template, fragments)
            before = file.source
            result = capture_file(file, family, source="authored_synthetic")
            self.assertEqual(result.raw, raw)
            self.assertEqual(result.file_sha256, sha256(before).hexdigest())
            self.assertEqual(result.offset, file.metadata["global_index"][family])
            self.assertEqual(file.source, before)
            with self.assertRaises(SnapshotError):
                capture_file(template, family, source="authored_synthetic")

    def test_mil_distinct_lists_and_exact_opaque_bytes(self):
        result = capture_section("MILMessage", MIL, source="authored_synthetic")
        self.assertEqual(result.raw, MIL)
        self.assertEqual(result.resources[0].strings, (b"A", b"B", b"C"))
        self.assertEqual(result.resources[0].buffers, (b"\x00\xff", b"raw"))
        self.assertEqual(result.resources[1].path, (1, 0))
        self.assertEqual(result.resources[1].buffers, (b"\x80", b""))
        self.assertEqual(result.summary()["payload_semantics"], "unresolved")
        self.assertEqual(
            result.summary()["native_semantics"], "mil-message-information"
        )
        self.assertEqual(
            [row["role"] for row in result.summary()["resources"]],
            ["message_screen", "confirmation_screen"],
        )

    def test_market_normal_and_ssr_pass_through(self):
        for family in ("MktMonRam", "MktMonRamSSR"):
            result = capture_section(family, MARKET, source="recorded_unverified")
            self.assertEqual(result.resources[0].identifier, 0x12345678)
            self.assertEqual(result.resources[0].strings, (b"ecu",))
            self.assertEqual(result.resources[0].buffers, (b"\x00\xff\x80",))
            self.assertEqual(result.resources[1].identifier, 0xFFFFFFFF)
            self.assertEqual(result.resources[1].buffers, (b"",))
            self.assertEqual(result.summary()["resources"][0]["buffers"][0]["size"], 3)

    def test_empty_named_market_group_is_not_lost(self):
        raw = bytes.fromhex("ffffffff10ffffff0010 0100 0300656375 0000")
        result = capture_section("MktMonRam", raw, source="authored_synthetic")
        self.assertEqual(result.resources[0].strings, (b"ecu",))
        self.assertEqual(result.resources[0].buffers, ())
        self.assertEqual(result.raw, raw)

    def test_legacy_market_has_no_identifier(self):
        raw = bytes.fromhex("ffffffff10ffffff0010 0100 0000 0100 01000000 ff")
        result = capture_section("MktMonRam", raw, source="authored_synthetic")
        self.assertIsNone(result.resources[0].identifier)
        self.assertEqual(result.resources[0].buffers, (b"\xff",))

    def test_all_prefix_truncations_and_trailing_bytes_rejected(self):
        for family, raw in (("MILMessage", MIL), ("MktMonRam", MARKET)):
            for length in range(len(raw)):
                with (
                    self.subTest(family=family, length=length),
                    self.assertRaises(SnapshotError),
                ):
                    capture_section(family, raw[:length], source="authored_synthetic")
            with self.assertRaises(SnapshotError):
                capture_section(family, raw + b"\x00", source="authored_synthetic")

    def test_bad_length_and_unknown_family_source(self):
        for family, source in (
            ("unknown", "authored_synthetic"),
            ("MILMessage", "physical"),
        ):
            with self.assertRaises(ValueError):
                capture_section(family, MIL, source=source)
        with self.assertRaises(SnapshotError):
            capture_section(
                "MktMonRam", MARKET[:23] + b"\xff" * 4, source="authored_synthetic"
            )

    def test_cancel_before_and_after_parse(self):
        for after in (0, 1, 3):
            count = 0

            def cancelled(after=after):
                nonlocal count
                count += 1
                return count > after

            with self.assertRaises(InterruptedError):
                capture_section(
                    "MILMessage", MIL, source="authored_synthetic", cancelled=cancelled
                )
        self.assertEqual(MIL[-3:], b"\x80\x00\x00")


class RamExamplesTests(unittest.TestCase):
    def test_production_authored_example_roundtrip_and_cancellation(self):
        files = create_ram_examples()
        self.assertEqual(
            set(files),
            {"Toyota.ddb", "M_English.ddb", "demo.ddb", "ram.json", "ram-example.json"},
        )
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for name, raw in files.items():
                (root / name).write_bytes(raw)
            profile = VehicleCatalog(root).build_profile(42)
            replay = RamReplay.load(profile, root / "ram.json")
            self.assertEqual(replay.replay.source, "authored_synthetic")
            self.assertEqual(replay.reader.read(256, 8), bytes(range(8)))
            replay.assert_complete()
            replay = RamReplay.load(profile, root / "ram.json", cancelled=lambda: True)
            with self.assertRaises(Cancelled):
                replay.reader.read(256, 8)
            self.assertEqual(replay.reader.transactions, ())
            self.assertEqual(replay.replay.position, 0)


class DdrPacketLogTests(unittest.TestCase):
    def test_native12_source_modes_have_separate_upper_bound_and_literal_tail(self):
        from scripts.frame_transport import NativeFrameOperations, packet_log_record

        operations = create_autospec(NativeFrameOperations, instance=True)
        operations.native_build = 12
        with TemporaryDirectory() as directory:
            log = DdrPacketLog(Path(directory), operations)
            for kind, filename in (
                (0, "OperationFFD.log"),
                (2, "DDR.log"),
                (14, "FCM_SerialNo.log"),
                (19, "LCSOperationFFD.log"),
            ):
                self.assertEqual(log.start(kind), 0)
                self.assertEqual(log.path.name, filename)
                writer, _ = operations.set_packet_log.call_args.args
                writer(packet_log_record(bytes.fromhex("00ffaa")))
                self.assertEqual(log.start(kind), 0)
                self.assertEqual(log.start(20), 0x90020706)
                self.assertEqual(log.stop(), 0)
                self.assertEqual(log.path.read_bytes(), b"00FFAA")
            self.assertEqual(log.start(20), 0x90020701)
            self.assertEqual(log.start(26), 0x90020701)

    def test_native_mode_filenames_reuse_rejection_and_closed_mode_transition(self):
        from scripts.frame_transport import NativeFrameOperations

        operations = create_autospec(NativeFrameOperations, instance=True)
        operations.native_build = 18
        with TemporaryDirectory() as directory:
            log = DdrPacketLog(Path(directory), operations)
            self.assertEqual(log.start_comm_log(0), 0)
            self.assertEqual(log.path.name, "OperationFFD.log")
            writer, _ = operations.set_packet_log.call_args.args
            writer(b"first")
            self.assertEqual(log.start_comm_log(0), 0)
            self.assertEqual(log.start_comm_log(3), 0x90020706)
            self.assertEqual(log.path.name, "OperationFFD.log")
            self.assertEqual(log.stop_comm_log(), 0)
            self.assertEqual(log.path.read_bytes(), b"first")
            for kind, filename in (
                (1, "ImageFFD.log"),
                (2, "DDR.log"),
                (3, "AbsoluteTimeStamp.log"),
                (20, "MarkMonRam_SSR.log"),
                (26, "RCImageFFD.log"),
            ):
                self.assertEqual(log.start_comm_log(kind), 0)
                self.assertEqual(log.path.name, filename)
                self.assertEqual(log.stop_comm_log(), 0)
            calls = operations.set_packet_log.call_count
            self.assertEqual(log.start_comm_log(27), 0x90020701)
            self.assertEqual(log.start_comm_log(65535), 0x90020701)
            self.assertEqual(operations.set_packet_log.call_count, calls)
            for bad in (-1, 65536, True):
                with self.assertRaises(ValueError):
                    log.start_comm_log(bad)

    def test_native_change_log_kind_keeps_save_flag_and_closes_before_create(self):
        from scripts.frame_transport import NativeFrameOperations

        operations = create_autospec(NativeFrameOperations, instance=True)
        operations.native_build = 18
        with TemporaryDirectory() as directory:
            log = DdrPacketLog(Path(directory), operations)
            self.assertEqual(log.change(22), 0)
            operations.set_packet_log.assert_not_called()
            self.assertEqual(log.change(27), 0x90020701)
            self.assertEqual(log.start(22), 0)
            old = log.path
            writer, _ = operations.set_packet_log.call_args.args
            writer(b"first\\n")
            self.assertEqual(log.change(23), 0)
            self.assertTrue(log.active)
            self.assertEqual(old.name, "ADSOperationFFD.log")
            self.assertEqual(old.read_bytes(), b"first")
            self.assertEqual(log.path.name, "ADSOperationFFD_Eng.log")
            writer, _ = operations.set_packet_log.call_args.args
            writer(b"second\\n")
            self.assertEqual(log.stop(), 0)
            self.assertEqual(log.path.read_bytes(), b"second")
            self.assertEqual(log.start(22), 0)
            with patch.object(Path, "open", side_effect=OSError("create failed")):
                self.assertEqual(log.change(23), 0x90020706)
            self.assertTrue(log.active)  # native IsCommLogSave remains1
            self.assertIsNone(log._file)
            self.assertEqual(log.stop(), 0)
            operations.native_build = 12
            native12 = DdrPacketLog(Path(directory), operations)
            self.assertEqual(native12.change(20), 0x90020701)
            self.assertEqual(native12.change(19), 0)

    def test_native_log_size_and_pointer_rewind_truncates_reuses_byte_budget(self):
        from scripts.frame_transport import NativeFrameOperations

        for build in (12, 18):
            operations = create_autospec(NativeFrameOperations, instance=True)
            operations.native_build = build
            with TemporaryDirectory() as directory:
                log = DdrPacketLog(Path(directory), operations, max_bytes=8)
                self.assertEqual(log.get_comm_log_file_size(), (0x90020706, None))
                self.assertEqual(log.set_comm_log_file_pointer(0), 0x90020706)
                self.assertEqual(log.start(1), 0)
                writer, _ = operations.set_packet_log.call_args.args
                writer(b"ABCD")
                assert log._file is not None
                log._file.seek(1)
                self.assertEqual(log.get_size(), (0, 4))
                self.assertEqual(log._file.tell(), 1)
                self.assertEqual(log.set_pointer(2), 0)
                self.assertEqual(log.path.read_bytes(), b"AB")
                self.assertEqual(log.written, 2)
                writer(b"CD")
                self.assertEqual(log.path.read_bytes(), b"ABCD")
                self.assertEqual(log.set_pointer(6), 0)
                writer(b"EF")
                self.assertEqual(log.path.read_bytes(), b"ABCD\x00\x00EF")
                self.assertEqual(log.get_size(), (0, 8))
                with self.assertRaises(OSError):
                    writer(b"G")
                for offset in (9, 0x80000000, 0xFFFFFFFF):
                    self.assertEqual(log.set_pointer(offset), 0x90020706)
                self.assertEqual(log.get_size(), (0, 8))
                with self.assertRaises(ValueError):
                    log.set_pointer(True)
                with patch(
                    "scripts.database_resources.fstat",
                    side_effect=OSError("size failed"),
                ):
                    self.assertEqual(log.get_size(), (0x90020706, None))
                self.assertEqual(log.set_pointer(0), 0)
                self.assertEqual(log.get_size(), (0, 0))
                self.assertEqual(log.stop(), 0)
                self.assertEqual(log.path.read_bytes(), b"")

    def test_native_create_reuse_packet_hook_and_exact_final_suffix_strip(self):
        from scripts.frame_transport import NativeFrameOperations, packet_log_record

        operations = create_autospec(NativeFrameOperations, instance=True)
        operations.native_build = 18
        with TemporaryDirectory() as directory:
            log = DdrPacketLog(Path(directory), operations)
            self.assertFalse(log.path.exists())
            self.assertEqual(log.start(), 0)
            writer, _ = operations.set_packet_log.call_args.args
            writer(packet_log_record(bytes.fromhex("2177")))
            self.assertEqual(log.start(), 0)
            self.assertEqual(operations.set_packet_log.call_count, 1)
            writer(packet_log_record(bytes.fromhex("6177a5")))
            self.assertEqual(log.path.read_bytes(), b"2177\\n6177A5\\n")
            self.assertEqual(log.stop(), 0)
            self.assertEqual(log.path.read_bytes(), b"2177\\n6177A5")
            operations.set_packet_log.assert_called_with(None, None)
            self.assertFalse(log.active)
            self.assertEqual(log.stop(), 0)
            self.assertEqual(log.start(), 0)
            self.assertEqual(log.path.read_bytes(), b"")
            self.assertEqual(log.stop(), 0)

    def test_native_error_pointer_stop_status_and_host_byte_bound(self):
        from scripts.frame_transport import NativeFrameOperations

        operations = create_autospec(NativeFrameOperations, instance=True)
        operations.native_build = 18
        with TemporaryDirectory() as directory:
            log = DdrPacketLog(Path(directory), operations, max_bytes=3)
            self.assertEqual(log.start(), 0)
            writer, failure = operations.set_packet_log.call_args.args
            writer(b"A\\n")
            with self.assertRaises(OSError):
                writer(b"B")
            failure()
            self.assertEqual(log.stop(), 0x90020706)
            self.assertEqual(log.path.read_bytes(), b"A")
            self.assertEqual(log.stop(), 0)
            self.assertEqual(log.start(), 0)
            writer, _ = operations.set_packet_log.call_args.args
            writer(b"A\n")
            self.assertEqual(log.stop(), 0)
            self.assertEqual(log.path.read_bytes(), b"A\n")

    def test_native_start_open_failure_leaves_logger_unbound(self):
        from scripts.frame_transport import NativeFrameOperations

        operations = create_autospec(NativeFrameOperations, instance=True)
        operations.native_build = 18
        with TemporaryDirectory() as directory:
            blocked = Path(directory) / "file"
            blocked.write_bytes(b"preserved")
            log = DdrPacketLog(blocked, operations)
            self.assertEqual(log.start(), 0x90020706)
            self.assertEqual(blocked.read_bytes(), b"preserved")
            self.assertFalse(log.active)
            self.assertEqual(log.stop(), 0)
            operations.set_packet_log.assert_not_called()


def authored_database(kind, sections):
    header = bytearray(36 + 4 * (max(sections) + 1))
    header[8:10] = bytes((kind, max(sections) + 1))
    header[10:28] = b"DiagTool DataCtrl\0"
    struct.pack_into("<I", header, 28, 0x0100032F)
    body = bytearray()
    for slot, (count, payload) in sorted(sections.items()):
        struct.pack_into("<I", header, 36 + slot * 4, len(header) + len(body))
        body += struct.pack("<BBII", slot, 0, count, len(payload)) + payload
    return bytes(header + body)


class NativeRamTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        category = bytearray(76)
        category[:18] = "demo.ddb\0".encode("utf-16le")
        struct.pack_into("<H", category, 68, 42)
        category[72] = 3
        target_category = bytearray(category)
        struct.pack_into("<H", target_category, 68, 43)
        target_category[72] = 20
        template = bytes.fromhex("91000000000000")
        setting = bytes.fromhex("44332211000000000000010000000000")
        monitor = bytearray(48)
        struct.pack_into("<H", monitor, 24, 7)
        struct.pack_into("<4H", monitor, 28, 0, 11, 0, 15)
        trigger = bytearray(36)
        struct.pack_into("<H", trigger, 16, 2)
        struct.pack_into("<H", trigger, 22, 40)
        trigger[30:32] = b"\x02\x03"
        addresses = []
        for identifier in (1, 2, 7):
            row = bytearray(16)
            struct.pack_into("<IH", row, 0, 5, identifier)
            row[10:12] = b"\x02\x01"
            addresses.append(bytes(row))
        timeline_address = bytearray(16)
        struct.pack_into("<IH", timeline_address, 0, 8, 7)
        timeline_address[10:12] = b"\x02\x02"
        addresses.append(bytes(timeline_address))
        attribute = bytearray(44)
        struct.pack_into("<4H", attribute, 16, 118, 42, 0, 15)
        attribute[38:40] = b"\x07\x77"
        ordinary_attribute = bytearray(attribute)
        struct.pack_into("<H", ordinary_attribute, 16, 101)
        legacy_attribute = bytearray(ordinary_attribute)
        struct.pack_into("<H", legacy_attribute, 16, 102)
        legacy_attribute[39] = 0xB1
        local_target = bytearray(ordinary_attribute)
        struct.pack_into("<H", local_target, 16, 143)
        struct.pack_into("<H", local_target, 24, 9)
        remote_target = bytearray(local_target)
        struct.pack_into("<H", remote_target, 18, 43)
        struct.pack_into("<H", remote_target, 24, 0)
        struct.pack_into("<H", remote_target, 34, 0x5678)
        remote_target[38] = 2
        cutoff_attributes = bytearray()
        for logical, pid in ((170, 0xAA), (171, 0xAB)):
            cutoff = bytearray(ordinary_attribute)
            struct.pack_into("<H", cutoff, 16, logical)
            cutoff[39] = pid
            cutoff_attributes += cutoff
        support_row = bytearray(24)
        struct.pack_into("<6H", support_row, 0, 9, 0, 1, 0xCA, 0x1234, 43)
        support_row[18:24] = bytes((255, 1, 2, 0, 0, 1))
        preparations = (
            bytes.fromhex("27010000"),
            bytes.fromhex("27021000"),
            bytes.fromhex("27030000"),
            bytes.fromhex("27042000"),
        )
        templates = (template, b"\x21\x00", *preparations, bytes.fromhex("220000"))
        variable_headers = bytearray()
        variable_data = bytearray()
        for item in templates:
            variable_headers += struct.pack("<IH", len(variable_data), len(item))
            variable_data += item
        rows = {
            0: (
                len(templates),
                bytes(variable_headers + variable_data),
            ),
            16: (2, bytes(category + target_category)),
            17: (7, b"".join(struct.pack("<4H", i, i, 0, 0) for i in range(1, 8))),
            18: (
                7,
                struct.pack("<8H", 42, 0x6B, 1, 2, 0, 0, 0, 0)
                + struct.pack("<8H", 42, 0xA1, 1, 1, 0, 0, 0, 0)
                + b"".join(
                    struct.pack("<8H", 42, 0xC1 + i, 1, 3 + i, 0, 0, 0, 0)
                    for i in range(4)
                )
                + struct.pack("<8H", 43, 0xCA, 1, 7, 0, 0, 0, 0),
            ),
            29: (1, setting),
            48: (1, bytes(support_row)),
            54: (
                7,
                bytes(
                    ordinary_attribute
                    + legacy_attribute
                    + attribute
                    + local_target
                    + remote_target
                    + cutoff_attributes
                ),
            ),
        }
        self.management_rows = rows
        (root / "Toyota.ddb").write_bytes(authored_database(1, rows))
        (root / "M_English.ddb").write_bytes(authored_database(4, {0: (0, b"")}))
        (root / "demo.ddb").write_bytes(
            authored_database(
                2,
                {
                    10: (0, b""),
                    50: (1, bytes(monitor)),
                    51: (1, bytes(trigger)),
                    52: (4, b"".join(addresses)),
                    53: (0, b""),
                },
            )
        )
        self.profile = VehicleCatalog(root).build_profile(42)
        self.frame = RamFrame(bytes.fromhex("1122a5cc78563412"))
        self.calls = []

    def reply(self, query):
        self.calls.append(query)
        data = bytes((query.frame.address + n) & 255 for n in range(query.request[2]))
        return bytes((query.request[0] | 0x40,)) + query.request[1:] + data

    def reader(self, **kwargs):
        return NativeRamReader(
            self.profile,
            kwargs.pop("exchange", self.reply),
            ecu="authored-ecu",
            frame=self.frame,
            block_size=kwargs.pop("block_size", 24),
            **kwargs,
        )

    def test_EndTrim_build12_18_actual_io_tail_failures_no_cache_and_cancel(self):
        @dataclass
        class Reply:
            code: int
            data: bytes

        class Operations:
            def __init__(self):
                self.request = b""
                self.requests = []

            def send(self, request, **kwargs):
                self.request = request
                self.requests.append(request)
                return 0

            def receive(self, **kwargs):
                address = int.from_bytes(self.request[3:], "big")
                if address == 9:
                    return Reply(0x90020321, b"partial")
                if address == 13:
                    return Reply(0, b"malformed")
                return Reply(
                    0,
                    b"\xd1"
                    + self.request[1:]
                    + bytes(range(address, address + self.request[2])),
                )

            def close(self):
                pass

        for build in (12, 18):
            operations = Operations()
            channel = NativeCommunication(
                self.profile, operations, "authored-ecu", bus_id=2, source_build=build
            )
            reader = NativeRamReader.from_communication(
                channel, frame=RamFrame(bytes.fromhex("0100010005000000")), block_size=4
            )
            self.assertEqual(
                reader.read_end_trim(10), bytes((5, 6, 7, 8)) + b"\xff" * 6
            )
            expected = [
                bytes.fromhex(raw)
                for raw in ("91010400000005", "91010400000009", "9101020000000d")
            ]
            self.assertEqual(operations.requests, expected)
            self.assertEqual(reader.transactions[1].reply, b"partial")
            self.assertEqual(
                [row.status for row in reader.transactions], [0, 0x90020321, 0xA0040201]
            )
            self.assertEqual(
                reader.read_end_trim(10), bytes((5, 6, 7, 8)) + b"\xff" * 6
            )
            self.assertEqual(operations.requests, expected * 2)
            self.assertEqual(reader._cache, {})
            if build == 12:
                with self.assertRaises(NotImplementedError):
                    reader.read(5, 1)
            operations.requests.clear()
            with self.assertRaises(Cancelled):
                reader.read_end_trim(
                    10,
                    cancelled=lambda operations=operations: bool(operations.requests),
                )
            self.assertEqual(operations.requests, expected[:1])
            self.assertEqual(reader.read_end_trim(0, cancelled=lambda: True), b"")
            boundary = NativeRamReader.from_communication(
                channel, frame=reader.frame.at(0xFFFFFFFB), block_size=4
            )
            with self.assertRaises(ToyotaCodecError) as error:
                boundary.read_end_trim(4)
            self.assertEqual(error.exception.code, 0xA0041201)
            self.assertEqual(operations.requests, expected[:1])
            for invalid in (-1, True, snapshot.MAX_BYTES + 1):
                with self.assertRaises(ValueError):
                    reader.read_end_trim(invalid)

    def test_internal_DDR_rejects_unbound_controller_and_nonToyota_before_IO(self):
        calls = []

        class Operations:
            def send(self, request, **kwargs):
                calls.append(request)
                raise AssertionError("Unexpected primitive I/O")

            def receive(self, **kwargs):
                raise AssertionError("Unexpected primitive I/O")

            def close(self):
                pass

        channel = NativeCommunication(
            self.profile, Operations(), "authored", bus_id=0x12
        )
        with self.assertRaises(ValueError):
            capture_internal_ddr_report(channel, p5=False)
        channel.profile = cast(Any, object())
        with self.assertRaises(TypeError):
            NativeRamReader.from_communication(channel, frame=self.frame, block_size=4)
        self.assertEqual(calls, [])

    def test_ddr_preparation_native_order_zero_short_and_fault(self):
        calls = []
        replies = iter(
            bytes.fromhex(x) for x in ("67030001", "6704", "6701ffff", "6702")
        )

        def exchange(query):
            calls.append(query)
            return next(replies)

        cache = MonitorSupportCache(self.profile, exchange, "authored-ecu")
        prepare_ddr_session(cache)
        self.assertEqual(
            [q.request.hex() for q in calls],
            ["27030000", "27041ffe", "27010000", "27021000"],
        )
        self.assertTrue(
            all(
                q.selected.settings_record
                == self.profile.frame_records(0xC1)[0].settings_record
                for q in calls
            )
        )
        calls.clear()
        cache = MonitorSupportCache(
            self.profile,
            lambda q: calls.append(q) or bytes.fromhex("67000000"),
            "authored-ecu",
        )
        prepare_ddr_session(cache)
        prepare_ddr_session(cache)
        self.assertEqual([q.request.hex() for q in calls], ["27030000", "27010000"] * 2)
        cache = MonitorSupportCache(
            self.profile, lambda q: bytes.fromhex("6700"), "authored-ecu"
        )
        with self.assertRaises(ToyotaCodecError) as caught:
            prepare_ddr_session(cache)
        self.assertEqual(caught.exception.code, 0xA0040202)
        selected = self.profile.frame_records(0xC3)[0]
        masked = replace(
            selected,
            frame=CommandFrame(selected.frame.request, b"\xff\xff", b"\x67\x04"),
        )
        cache = MonitorSupportCache(
            self.profile, lambda q: bytes.fromhex("67030000"), "authored-ecu"
        )
        with (
            patch.object(type(self.profile), "frame_records", return_value=(masked,)),
            self.assertRaises(ToyotaCodecError) as caught,
        ):
            prepare_ddr_session(cache)
        self.assertEqual(caught.exception.code, 0xA0040201)
        with (
            patch.object(
                type(self.profile), "frame_records", side_effect=ValueError("absent")
            ),
            self.assertRaises(ToyotaCodecError) as caught,
        ):
            prepare_ddr_session(cache)
        self.assertEqual(caught.exception.code, 0xC0040102)
        calls.clear()

        def fail(query):
            calls.append(query)
            raise NativeStatus(0x90020323, b"partial")

        cache = MonitorSupportCache(self.profile, fail, "authored-ecu")
        with self.assertRaises(NativeStatus):
            prepare_ddr_session(cache)
        self.assertEqual(len(calls), 1)

    def test_selected_ddr_resources_to_native_scalar_capture(self):
        plan = selected_ddr_record_plan(self.profile, 2, b"\x02\x03")
        self.assertEqual(plan.table_slots, (50, 51, 52, 53))
        self.assertEqual(len(plan.prefix_address_records), 2)
        self.assertEqual(plan.trigger_record[30:32], b"\x02\x03")
        reader = NativeRamReader(
            self.profile,
            self.reply,
            ecu="authored-ecu",
            frame=RamFrame(bytes.fromhex("0100040000000000")),
            block_size=24,
        )
        raw, value = plan.samples[0].capture(
            reader, base_address=0x1010, record_index=0
        )
        self.assertEqual(raw, bytes.fromhex("1516"))
        self.assertEqual(value, 0x151)
        self.assertEqual(self.calls[0].request, bytes.fromhex("91041800001008"))
        raw, value = plan.samples[0].capture(
            reader, base_address=0x10000, record_index=1
        )
        self.assertEqual(raw, bytes.fromhex("0506"))
        self.assertEqual(value, 0x50)
        self.assertEqual(self.calls[-1].request, bytes.fromhex("91041800020000"))
        for base, index in ((0, 256), (0xFFFFFFFF, 1)):
            with self.assertRaises(ValueError):
                plan.samples[0].capture(reader, base_address=base, record_index=index)
        with self.assertRaises(ToyotaCodecError) as caught:
            selected_ddr_record_plan(self.profile, 4, b"\x02\x03")
        self.assertEqual(caught.exception.code, 0xA0041001)
        with self.assertRaises(ToyotaCodecError):
            selected_ddr_record_plan(self.profile, 2, b"\x02\x04")
        with self.assertRaises(ValueError):
            plan.samples[0].capture(self.reader(), base_address=0, record_index=0)

    def test_bulk_record_uses_literal_real24_read_and_shared_selected_resources(self):
        raw = bytearray(24)
        raw[:2] = bytes.fromhex("0203")
        raw[5:7] = bytes.fromhex("abcd")
        calls = []

        def exchange(query):
            calls.append(query)
            return b"\xd1" + query.request[1:] + bytes(raw)

        reader = NativeRamReader(
            self.profile,
            exchange,
            ecu="authored-ecu",
            frame=RamFrame(bytes.fromhex("0100020000000000")),
            block_size=24,
        )
        result = capture_ddr_bulk_record_samples(reader, spec_value=2, address=0x100)
        assert result is not None
        self.assertEqual(result.raw, bytes(raw))
        self.assertEqual(result.record_length, 40)
        self.assertEqual(result.record.values, ((7, bytes.fromhex("abcd"), 0xABC),))
        self.assertEqual([query.request.hex() for query in calls], ["91021800000100"])
        selected_rows = self.profile.ddr_records
        outside = bytearray(result.record.plan.samples[0].address_record)
        struct.pack_into("<IH", outside, 0, 24, 999)

        def rows(slot, *keys):
            selected = selected_rows(slot, *keys)
            return (
                selected + (bytes(outside),)
                if slot == 52 and keys == (2, 1)
                else selected
            )

        with patch.object(type(self.profile), "ddr_records", side_effect=rows):
            bulk_plan = selected_ddr_record_plan(
                self.profile, 2, bytes.fromhex("0203"), bulk=True
            )
            self.assertEqual([sample.monitor_id for sample in bulk_plan.samples], [7])
            with self.assertRaises(ToyotaCodecError):
                selected_ddr_record_plan(self.profile, 2, bytes.fromhex("0203"))
        replay = RamReplay(
            self.profile, encode_ram_recording(reader, source="authored_synthetic")
        )
        self.assertEqual(
            capture_ddr_bulk_record_samples(replay.reader, spec_value=2, address=0x100),
            result,
        )
        replay.assert_complete()
        raw[:2] = bytes.fromhex("0204")
        self.assertIsNone(
            capture_ddr_bulk_record_samples(reader, spec_value=2, address=0x100)
        )

        def failure(query):
            raise NativeStatus(0x90020323, b"partial")

        reader.exchange = failure
        self.assertIsNone(
            capture_ddr_bulk_record_samples(reader, spec_value=2, address=0x100)
        )
        self.assertEqual(reader.transactions[-1].reply, b"partial")
        self.assertEqual(reader.transactions[-1].status, 0x90020323)

    def test_bulk_payload_actual_scalar_and_packed_or_byte_strided_timelines(self):
        prefix = bytearray(24)
        prefix[:2], prefix[5:7] = bytes.fromhex("0203"), bytes.fromhex("abcd")
        header_reader = NativeRamReader(
            self.profile,
            lambda query: b"\xd1" + query.request[1:] + bytes(prefix),
            ecu="authored-ecu",
            frame=RamFrame(bytes.fromhex("0100020000000000")),
            block_size=24,
        )
        header = capture_ddr_bulk_record_samples(
            header_reader, spec_value=2, address=0x100
        )
        assert header is not None
        raw = bytes.fromhex("abcd12345678") + bytes(10)
        calls = []

        def exchange(query):
            calls.append(query)
            return b"\xd1" + query.request[1:] + raw

        reader = NativeRamReader(
            self.profile,
            exchange,
            ecu="authored-ecu",
            frame=header_reader.frame,
            block_size=56,
        )
        selected_rows = self.profile.ddr_records
        scalar = bytearray(header.record.plan.samples[0].address_record)
        struct.pack_into("<I", scalar, 0, 26)
        timeline = bytearray(selected_rows(52, 2, 2)[0])
        struct.pack_into("<I", timeline, 0, 24)

        def rows(slot, *keys):
            found = selected_rows(slot, *keys)
            if slot == 52 and keys == (2, 1):
                return found + (bytes(scalar),)
            return (bytes(timeline),) if slot == 52 and keys == (2, 2) else found

        with patch.object(type(self.profile), "ddr_records", side_effect=rows):
            captured = capture_ddr_bulk_payload(reader, header)
            assert captured is not None
            self.assertEqual(captured.raw, raw)
            self.assertEqual(
                captured.record.values[-1], (7, bytes.fromhex("1234"), 0x123)
            )
            self.assertEqual(captured.timelines[0].values, (0xABC, 0x123))
            self.assertEqual(
                [query.request.hex() for query in calls], ["91021000000118"]
            )
            replay = RamReplay(
                self.profile, encode_ram_recording(reader, source="authored_synthetic")
            )
            self.assertEqual(capture_ddr_bulk_payload(replay.reader, header), captured)
            replay.assert_complete()
            struct.pack_into("<H", timeline, 6, 4)
            strided = decode_ddr_bulk_payload(self.profile, header, raw)
            self.assertEqual(strided.timelines[0].values, (0xABC, 0x567))
            struct.pack_into("<H", timeline, 6, 20)
            with self.assertRaises(ToyotaCodecError) as caught:
                decode_ddr_bulk_payload(self.profile, header, raw)
            self.assertEqual(caught.exception.code, 0xC0040102)
            with self.assertRaises(ValueError):
                decode_ddr_bulk_payload(self.profile, header, raw[:-1])
            with self.assertRaises(Cancelled):
                decode_ddr_bulk_payload(
                    self.profile, header, raw, cancelled=lambda: True
                )

        def failure(query):
            raise NativeStatus(0x90020323, b"partial")

        reader.exchange = failure
        self.assertIsNone(capture_ddr_bulk_payload(reader, header))
        self.assertEqual(reader.transactions[-1].reply, b"partial")

    def test_normal_ddr_observed_header_selects_and_captures_record_samples(self):
        calls = []
        payload = bytearray(56)
        payload[:2] = b"\x02\x03"
        payload[5:7] = bytes.fromhex("abcd")

        def exchange(query):
            calls.append(query)
            return b"\xd1" + query.request[1:] + bytes(payload)

        reader = NativeRamReader(
            self.profile,
            exchange,
            ecu="authored-ecu",
            frame=RamFrame(bytes.fromhex("0100040000000000")),
            block_size=56,
        )
        result = capture_ddr_record_samples(
            reader, spec_value=2, base_address=0, record_index=0
        )
        assert result is not None
        self.assertEqual(result.header, b"\x02\x03")
        self.assertEqual(result.values, ((7, bytes.fromhex("abcd"), 0xABC),))
        self.assertEqual(result.ordered_values, result.values)
        reordered = replace(
            result,
            plan=replace(result.plan, monitor_order=(17, 7, 7, 55)),
            values=((7, b"a", 1), (17, b"b", 2), (7, b"c", 3)),
        )
        self.assertEqual(
            reordered.ordered_values, ((17, b"b", 2), (7, b"a", 1), (7, b"a", 1))
        )
        with_headers = replace(
            result, plan=replace(result.plan, monitor_order=(2, 7, 1, 2))
        )
        self.assertEqual(
            with_headers.ordered_values,
            (
                (2, b"\x03", 3),
                (7, bytes.fromhex("abcd"), 0xABC),
                (1, b"\x02", 2),
                (2, b"\x03", 3),
            ),
        )
        self.assertFalse(result.marker_present)
        self.assertTrue(replace(result, values=((17, b"\x55", 0x155),)).marker_present)
        for identifier in (16, 37, 54, 59, 70, 99):
            self.assertFalse(
                replace(result, values=((identifier, b"\x55", 0x55),)).marker_present
            )
        self.assertEqual([q.request.hex() for q in calls], ["91043800000000"])
        payload[:2] = b"\x02\x04"
        self.assertIsNone(
            capture_ddr_record_samples(
                reader, spec_value=2, base_address=0, record_index=0
            )
        )
        self.assertEqual(len(calls), 2)
        replay = RamReplay(
            self.profile, encode_ram_recording(reader, source="authored_synthetic")
        )
        self.assertEqual(
            capture_ddr_record_samples(
                replay.reader, spec_value=2, base_address=0, record_index=0
            ),
            result,
        )
        self.assertIsNone(
            capture_ddr_record_samples(
                replay.reader, spec_value=2, base_address=0, record_index=0
            )
        )
        replay.assert_complete()
        with self.assertRaises(ValueError):
            capture_ddr_record_samples(
                self.reader(), spec_value=2, base_address=0, record_index=0
            )
        reader = NativeRamReader(
            self.profile,
            exchange,
            ecu="authored-ecu",
            frame=RamFrame(bytes.fromhex("0100040000000000")),
            block_size=56,
            limits=Limits(exchanges=1),
        )
        with self.assertRaises(SessionError):
            capture_ddr_record_samples(
                reader, spec_value=2, base_address=55, record_index=0
            )
        self.assertEqual(len(reader.transactions), 1)

    def test_selected_ddr_timeline_acquisition_and_native_record_skip_on_ram_failure(
        self,
    ):
        payload = bytearray(56)
        payload[:2] = b"\x02\x03"
        payload[5:7] = bytes.fromhex("abcd")
        payload[8:12] = bytes.fromhex("abcd1234")
        reader = NativeRamReader(
            self.profile,
            lambda q: b"\xd1" + q.request[1:] + bytes(payload),
            ecu="authored-ecu",
            frame=RamFrame(bytes.fromhex("0100040000000000")),
            block_size=56,
        )
        record = capture_ddr_record_samples(
            reader, spec_value=2, base_address=0, record_index=0
        )
        assert record is not None
        timelines = capture_ddr_timeline_samples(
            reader, record, base_address=0, record_index=0
        )
        assert timelines is not None
        self.assertEqual(len(timelines), 1)
        self.assertEqual(timelines[0].plan.monitor_id, 7)
        self.assertEqual(timelines[0].raw, bytes.fromhex("abcd1234"))
        self.assertEqual(timelines[0].values, (0xABC, 0x123))
        self.assertEqual(len(reader.transactions), 2)
        replay = RamReplay(
            self.profile, encode_ram_recording(reader, source="authored_synthetic")
        )
        replay_record = capture_ddr_record_samples(
            replay.reader, spec_value=2, base_address=0, record_index=0
        )
        assert replay_record is not None
        self.assertEqual(
            capture_ddr_timeline_samples(
                replay.reader, replay_record, base_address=0, record_index=0
            ),
            timelines,
        )
        replay.assert_complete()

        def fail(query):
            raise NativeStatus(0x90020323, b"partial")

        reader.exchange = fail
        self.assertIsNone(
            capture_ddr_timeline_samples(reader, record, base_address=0, record_index=0)
        )
        self.assertIsNone(
            capture_ddr_record_samples(
                reader, spec_value=2, base_address=0, record_index=0
            )
        )
        self.assertEqual(reader.transactions[-1].status, 0x90020323)

    def test_ddr_big_endian_inclusive_bits_and_invalid_ranges(self):
        self.assertEqual(ddr_bits(bytes.fromhex("a5f0"), 4, 11), 0x5F)
        self.assertEqual(ddr_bits(bytes.fromhex("ffffffff"), 0, 31), 0xFFFFFFFF)
        for raw, start, end in (
            (b"", 0, 0),
            (bytes(5), 0, 0),
            (b"x", -1, 0),
            (b"x", 5, 4),
            (b"x", 0, 8),
        ):
            with self.assertRaises(ValueError):
                ddr_bits(raw, start, end)

    def test_ddr_native_timeline_windows_nonbyte_stride_and_byte_offset_wrap(self):
        monitor = bytearray(48)
        struct.pack_into("<4H", monitor, 28, 0, 3, 0, 3)
        self.assertEqual(
            ddr_timeline_values(bytes.fromhex("a5f0"), 4, bytes(monitor)),
            (10, 5, 15, 0),
        )
        struct.pack_into("<4H", monitor, 28, 0, 11, 0, 11)
        self.assertEqual(
            ddr_timeline_values(bytes.fromhex("abcdef"), 2, bytes(monitor)),
            (0xABC, 0xCDE),
        )
        struct.pack_into("<4H", monitor, 28, 0, 31, 0, 31)
        raw = b"\x01\x02\x03\x04" + bytes(252) + bytes.fromhex("deadbeef")
        values = ddr_timeline_values(raw, 65, bytes(monitor))
        self.assertEqual(values[0], 0x01020304)
        self.assertEqual(values[-1], 0x01020304)
        self.assertEqual(ddr_timeline_values(b"\0", 0, bytes(monitor)), ())
        for bad in (raw[:-1], raw + b"\0", bytes(281)):
            with self.assertRaises(ValueError):
                ddr_timeline_values(bad, 65, bytes(monitor))

    def test_source_bound_recording_roundtrip_and_regular_file_load(self):
        reader = self.reader()
        expected = reader.read(0x12345678, 30)
        raw = encode_ram_recording(reader, source="authored_synthetic")
        replay = RamReplay(self.profile, raw)
        self.assertEqual(replay.reader.read(0x12345678, 30), expected)
        replay.assert_complete()
        with TemporaryDirectory() as directory:
            path = Path(directory) / "capture.json"
            path.write_bytes(raw)
            loaded = RamReplay.load(self.profile, path)
            self.assertEqual(loaded.reader.read(0x12345678, 30), expected)
            self.assertEqual(path.read_bytes(), raw)
        with self.assertRaises(ValueError):
            RamReplay.load(self.profile, "/dev/null")

    def test_recording_rejects_foreign_sources_duplicate_keys_and_wrong_order(self):
        reader = self.reader()
        reader.read(0x12345678, 1, real=True)
        raw = encode_ram_recording(reader, source="recorded_unverified")
        document = json.loads(raw)
        for field in (
            "vehicle_ddb_sha256",
            "management_ddb_sha256",
            "function_record",
            "settings_record",
        ):
            changed = json.loads(raw)
            changed["binding"][field] = "ff"
            with self.assertRaises(ValueError):
                RamReplay(self.profile, json.dumps(changed).encode())
        with self.assertRaises(ValueError):
            RamReplay(self.profile, b'{"schema":"duplicate",' + raw[1:])
        with self.assertRaises(ValueError):
            RamReplay(self.profile, raw + b" " + b"{}").reader.read(0, 1)
        with self.assertRaises(ValueError):
            encode_ram_recording(reader, source="physically_verified")
        replay = RamReplay(self.profile, raw)
        with self.assertRaises(ValueError):
            replay.reader.read(0x12345679, 1, real=True)
        self.assertEqual(document["exchange"]["source"], "recorded_unverified")

    def test_native_error_recording_replays_original_partial_reply(self):
        def fail(query):
            raise NativeStatus(0xA0040003, b"partial")

        reader = self.reader(exchange=fail)
        with self.assertRaises(NativeStatus):
            reader.read(0x1000, 1, real=True)
        replay = RamReplay(
            self.profile, encode_ram_recording(reader, source="authored_synthetic")
        )
        with self.assertRaises(NativeStatus) as caught:
            replay.reader.read(0x1000, 1, real=True)
        self.assertEqual(caught.exception.code, 0xA0040003)
        self.assertEqual(caught.exception.reply, b"partial")
        replay.assert_complete()

    def test_pcs_native_fill_consecutive_failures_recovery_and_recorded_replay(self):
        def fail(query):
            raise NativeStatus(0x90020323, b"partial")

        reader = self.reader(exchange=fail)
        self.assertEqual(reader.read(0x1000, 1, pcs=True), b"\xff")
        # A cache hit does not reset the native consecutive-failure flag.
        self.assertEqual(reader.read(0x1000, 1, pcs=True), b"\xff")
        with self.assertRaises(NativeStatus):
            reader.read(0x1020, 1, pcs=True)
        self.assertEqual([x.status for x in reader.transactions], [0x90020323] * 2)
        reader.exchange = self.reply
        self.assertEqual(reader.read(0x1040, 1, pcs=True), b"\x40")
        reader.exchange = fail
        self.assertEqual(reader.read(0x1060, 1, pcs=True), b"\xff")

        calls = []

        def first_failure(query):
            calls.append(query)
            if len(calls) == 1:
                raise NativeStatus(0x90020323, b"partial")
            return self.reply(query)

        reader = self.reader(exchange=first_failure)
        expected = b"\xff" * 24 + bytes.fromhex("18191a1b1c1d")
        self.assertEqual(reader.read(0x1000, 30, real=True, pcs=True), expected)
        replay = RamReplay(
            self.profile, encode_ram_recording(reader, source="authored_synthetic")
        )
        self.assertEqual(replay.reader.read(0x1000, 30, real=True, pcs=True), expected)
        replay.assert_complete()
        cancelled = [False]

        def cancelled_failure(query):
            cancelled[0] = True
            raise NativeStatus(0x90020323, b"partial")

        reader = self.reader(exchange=cancelled_failure, cancelled=lambda: cancelled[0])
        with self.assertRaises(Cancelled):
            reader.read(0x1000, 1, pcs=True)
        self.assertEqual(reader.transactions[0].status, 0x90020323)

    def test_join_series_orders_combined_first_matches_and_preserves_duplicates(self):
        plan = selected_ddr_record_plan(self.profile, 2, bytes.fromhex("0203"))
        plan = replace(plan, monitor_order=(1, 8, 7, 8, 99))
        record = DdrRecordSamples(
            b"\x02\x03", plan, ((7, b"\x09", 9), (7, b"\x0a", 10))
        )
        timeline_plan = replace(plan.samples[0], monitor_id=8)
        timeline = DdrTimelineSamples(timeline_plan, b"\x04\x05", (4, 5))
        rows = ordered_ddr_series(record, (timeline,))
        self.assertEqual(
            [(row.identifier, row.kind, row.samples) for row in rows],
            [
                (1, 1, ((2, 0),)),
                (8, 2, ((4, 0), (5, 0))),
                (7, 1, ((9, 0),)),
                (8, 2, ((4, 0), (5, 0))),
            ],
        )
        flagged = mark_ddr_unchecked(rows)
        self.assertEqual(
            [row.samples for row in flagged],
            [
                ((2, 0),),
                ((4, 1), (5, 1)),
                ((9, 1),),
                ((4, 1), (5, 1)),
            ],
        )
        with self.assertRaises(ValueError):
            ordered_ddr_series(
                record, (replace(timeline, plan=replace(timeline_plan, category=999)),)
            )

    def test_full_transform_selects_serialized_condition_bytes_and_mutation(self):
        root = self.profile.catalog.root
        original = self.profile
        for expected, flag in ((1, 2), (2, 0)):
            condition = struct.pack("<IHHI4B", expected, 7, 7, 0, 2, 1, 0, 0)
            (root / "demo.ddb").write_bytes(
                authored_database(
                    2,
                    {
                        10: (0, b""),
                        50: (1, original.records(50)[0]),
                        51: (1, original.records(51)[0]),
                        52: (4, b"".join(original.records(52))),
                        53: (1, condition),
                    },
                )
            )
            profile = VehicleCatalog(root).build_profile(42)
            plan = selected_ddr_record_plan(profile, 2, b"\x02\x03")
            record = DdrRecordSamples(
                b"\x02\x03", plan, ((7, b"\x01", 1), (17, b"\x55", 0x55))
            )
            rows = transform_ddr_record(profile, record, ())
            self.assertEqual(rows, (DdrValueSeries(7, 1, ((1, flag),)),))
            with self.assertRaises(ValueError):
                transform_ddr_record(original, record, ())

    def test_signal_definition_uses_selected_name_phy_unit_patterns_and_exact_rows(
        self,
    ):
        root = self.profile.catalog.root
        source = self.profile
        monitor = bytearray(source.records(50)[0])
        struct.pack_into("<6I", monitor, 0, 11, 12, 0, 13, 14, 1)
        struct.pack_into("<H", monitor, 26, 21)
        struct.pack_into("<H", monitor, 38, 9)
        monitor[44] = 4
        physical = bytearray(24)
        struct.pack_into("<3I2H", physical, 0, 2, 3, 4, 21, 22)
        physical[20:22] = bytes((2, 3))
        unit = struct.pack("<I4H", 2, 22, 7, 0, 0)
        pattern = bytearray(24)
        struct.pack_into("<2I", pattern, 0, 3, 5)
        struct.pack_into("<H", pattern, 12, 9)
        labels = [
            text.encode("utf-16le") + b"\0\0" for text in ("Angle", "deg", "Shown")
        ]
        offset, indices = 0, bytearray()
        for label in labels:
            indices += struct.pack("<IH", offset, len(label))
            offset += len(label)
        (root / "M_English.ddb").write_bytes(
            authored_database(4, {0: (3, bytes(indices) + b"".join(labels))})
        )
        (root / "demo.ddb").write_bytes(
            authored_database(
                2,
                {
                    10: (0, b""),
                    13: (1, bytes(physical)),
                    14: (1, bytes(pattern)),
                    15: (1, unit),
                    50: (1, bytes(monitor)),
                    51: (1, source.records(51)[0]),
                    52: (4, b"".join(source.records(52))),
                    53: (0, b""),
                },
            )
        )
        profile = VehicleCatalog(root).build_profile(42)
        plan = selected_ddr_record_plan(profile, 2, b"\x02\x03")
        definition = selected_ddr_signal_definition(profile, plan, 7)
        self.assertEqual(
            (
                definition.name_id,
                definition.name,
                definition.unit,
                definition.unit_code,
            ),
            (1, "Angle", "deg", 7),
        )
        self.assertEqual(
            (
                definition.selector,
                definition.exponent,
                definition.sign_mode,
                definition.bit_width,
            ),
            (4, 3, 2, 12),
        )
        self.assertEqual(
            (definition.coefficients, definition.limits, definition.conversion),
            ((2, 3, 4), (13, 14), (11, 12)),
        )
        self.assertEqual(definition.patterns, ((9, "Shown", 5),))
        self.assertEqual(definition.physical_record, bytes(physical))
        self.assertEqual(definition.pattern_records, (bytes(pattern),))
        all_monitors = []
        for identifier in (1, 2, 3, 7, 37, 38, 1001):
            item = bytearray(monitor)
            struct.pack_into("<H", item, 24, identifier)
            all_monitors.append(bytes(item))
        trigger = bytearray(source.records(51)[0])
        struct.pack_into("<4I", trigger, 0, 11, 12, 1, 3)
        struct.pack_into("<HH", trigger, 16, 1, 1)
        other_trigger = bytearray(trigger)
        other_trigger[30:32] = bytes((4, 5))
        (root / "demo.ddb").write_bytes(
            authored_database(
                2,
                {
                    10: (0, b""),
                    13: (1, bytes(physical)),
                    14: (1, bytes(pattern)),
                    15: (1, unit),
                    50: (7, b"".join(all_monitors)),
                    51: (2, bytes(trigger + other_trigger)),
                    52: (4, b"".join(source.records(52))),
                    53: (0, b""),
                },
            )
        )
        formatted_profile = VehicleCatalog(root).build_profile(42)
        formatted_plan = selected_ddr_record_plan(formatted_profile, 2, b"\x02\x03")
        captured = DdrCapturedRecord(
            0,
            0,
            0x1000,
            DdrRecordSamples(b"\x02\x03", formatted_plan, ()),
            (),
            (
                DdrValueSeries(1, 1, ((2, 0),)),
                DdrValueSeries(2, 1, ((3, 0),)),
                DdrValueSeries(3, 1, ((99, 1),)),
                DdrValueSeries(7, 1, ((1, 2),)),
                DdrValueSeries(37, 1, ((4, 0),)),
                DdrValueSeries(38, 1, ((5, 0),)),
                DdrValueSeries(1001, 2, ((10, 0), (11, 1), (12, 2), (13, 0))),
            ),
        )
        info = format_ddr_info(formatted_profile, captured)
        self.assertEqual(
            (info.header_a, info.header_b), (((2, 0), (4, 0)), ((3, 0), (5, 0)))
        )
        self.assertEqual((info.conversion, info.counts), ((11, 12), (1, 1, 2)))
        self.assertEqual(
            [(row.name, row.memo) for row in info.triggers], [("Angle", "Shown")] * 2
        )
        self.assertEqual(info.scalar_signals[0].samples, ((1, 2),))
        self.assertEqual(info.extra_signal.samples, ((99, 1),))
        self.assertEqual(info.timeline_main[0].samples, ((10, 0), (13, 0)))
        self.assertEqual(info.timeline_side[0].samples, ((11, 1), (12, 2)))
        self.assertEqual(info.source_sha256, formatted_profile.database.sha256)
        attribute_plan = initial_ddr_attribute_plan(formatted_profile)
        attribute_plan = replace(
            attribute_plan,
            slots=tuple(
                replace(slot, supported=True) if slot.logical_id == 171 else slot
                for slot in attribute_plan.slots
            ),
        )
        capture = DdrCapture(
            DdrAttributeCapture(
                attribute_plan, ((103, 17), (118, 2), (171, 0xFFFFFFFF)), 2, 1
            ),
            (captured,),
            (),
        )
        report = format_ddr_capture(formatted_profile, capture)
        self.assertEqual(report.information, (info,))
        self.assertEqual((report.logical103, report.specification), (17, 2))
        self.assertEqual(report.attributes[-1], (171, True, 0x1FFFFFFF))
        with (
            patch(
                "scripts.database_resources._ddr_monitor_catalog",
                side_effect=ToyotaCodecError(
                    "authored final catalog failure", 0xC0040101
                ),
            ),
            self.assertRaises(DdrPartialReportError) as failure,
        ):
            format_ddr_capture(formatted_profile, capture)
        self.assertEqual(failure.exception.code, 0xC0040101)
        self.assertEqual(
            failure.exception.partial_report, replace(report, monitor_catalog=())
        )
        first_support, second_support = ddr_report_support_values(report)
        self.assertEqual(
            (first_support.logical_id, first_support.present, first_support.value),
            (170, False, 0),
        )
        self.assertEqual(
            (second_support.logical_id, second_support.present, second_support.value),
            (171, True, 0x1FFFFFFF),
        )
        empty_support = ddr_report_support_values(
            replace(report, attributes=(), information=())
        )
        self.assertEqual(
            [(value.present, value.value) for value in empty_support],
            [(False, 0), (False, 0)],
        )

        from tests.test_tse_reports import minimal

        for version in (0x1004, 0x1005, 0x1009, 0x1027):
            layout = tse_reports._section_layout("DDRData", 0x272A, version)
            original = tse_reports.ReportSection(
                "DDRData", 0x272A, 0, version, (minimal(layout.item),)
            )
            section = bind_ddr_report(original, report, encoding="ascii")
            content = section.records[0][
                1 + 2 * (version > 0x1004) + 4 * (version >= 0x1009)
            ]
            self.assertEqual(len(content), 1)
            stored_catalog = section.records[0][
                2 + 2 * (version > 0x1004) + 4 * (version >= 0x1009)
            ]
            self.assertEqual(
                [(item[0], item[1], item[3], item[10]) for item in stored_catalog],
                [
                    (
                        item.identifier,
                        item.name.encode("ascii"),
                        item.unit.encode("ascii"),
                        item.unit_code,
                    )
                    for item in report.monitor_catalog
                ],
            )
            main_info, validity = content[0]
            self.assertEqual(
                main_info[:5], ((2, 4), (3, 5), (1, 1), (b"Angle", b"Angle"), ())
            )
            self.assertEqual(main_info[5], (11, 12, 0, 0, 0, 0, (), 0, 0, 0, 0))
            self.assertEqual(main_info[11], 4)  # signed-affine GetValue, not raw1
            self.assertEqual(main_info[12][-1], ((1, b"\x01", 0),))
            self.assertEqual(main_info[24][-1], ((99, b"c", 0),))
            numeric = replace(
                info.extra_signal,
                definition=replace(info.extra_signal.definition, selector=2),
            )
            converted, _ = ddr_saved_information(
                replace(info, extra_signal=numeric), version=version, encoding="ascii"
            )
            self.assertEqual(converted[24][-1], ((99, b" 0.070", 0),))
            narrow = replace(info.extra_signal, samples=((0x80, 1),))
            converted, _ = ddr_saved_information(
                replace(info, extra_signal=narrow), version=version, encoding="ascii"
            )
            self.assertEqual(converted[24][-1], ((0x80, b"\x80", 0),))

            self.assertEqual(main_info[25][0][-1], ((11, b"\x0b", 0), (12, b"\x0c", 0)))
            self.assertEqual(main_info[26][0][-1], ((10, b"\x0a", 0), (13, b"\x0d", 0)))
            self.assertEqual(validity[10], 2)  # ID7 validity stored separately
            self.assertEqual(validity[21], (1,))  # extra ID3
            self.assertEqual(validity[22], ((1, 2),))
            self.assertEqual(validity[23], ((0, 0),))
            raw_section = tse_reports.encode_section(section)
            decoded = tse_reports.decode_section("DDRData", raw_section)
            view = tse_reports.view_section(decoded, encoding="ascii")
            self.assertEqual(
                [
                    row["maximum_recording_count"]
                    for row in view["ddr_headers"]
                    if "maximum_recording_count" in row
                ],
                [17],
            )
            header_rows = [row for row in view["ddr_headers"] if "key_cycle_raw" in row]
            pair_path = [
                0,
                1 + 2 * (version > 0x1004) + 4 * (version >= 0x1009),
                0,
            ]
            self.assertEqual(len(header_rows), 1)
            key_cycle = header_rows[0]
            self.assertEqual(
                key_cycle,
                {
                    "source_path": pair_path,
                    "key_cycle_raw": 4,
                    "key_cycle_precision_raw": main_info[12][5],
                    "key_cycle_invalidity_raw": 2,
                    "key_cycle_display": "-",
                    "key_cycle_value_source_path": pair_path + [0, 11],
                    "key_cycle_precision_source_path": pair_path + [0, 12, 5],
                    "key_cycle_invalidity_source_path": pair_path + [1, 10],
                },
            )

            for raw_name, source_name in (
                ("key_cycle_raw", "key_cycle_value_source_path"),
                ("key_cycle_precision_raw", "key_cycle_precision_source_path"),
                ("key_cycle_invalidity_raw", "key_cycle_invalidity_source_path"),
            ):
                value = decoded.records
                for index in key_cycle[source_name]:
                    value = value[index]
                self.assertEqual(value, key_cycle[raw_name])
            self.assertEqual(
                [
                    (item["normal_logical_id"], item["present_raw"], item["value_raw"])
                    for item in view["ddr_attributes"]
                ],
                [
                    (identifier, int(present), value)
                    for identifier, present, value in report.attributes
                ],
            )
            block = 7 + 2 * (version > 0x1004) + 4 * (version >= 0x1009)
            self.assertEqual(decoded.records[0][block - 1], 2)
            self.assertEqual(tse_reports.encode_section(decoded), raw_section)
            self.assertNotEqual(section, original)
            restored = list(section.records[0])
            for position in (block - 6, block - 5, block - 4, block - 1, block):
                restored[position] = original.records[0][position]
            self.assertEqual(tuple(restored), original.records[0])
        with self.assertRaises(UnicodeEncodeError):
            ddr_saved_information(
                replace(info, triggers=(replace(info.triggers[0], name="Ж"),)),
                version=0x1027,
                encoding="ascii",
            )
        with self.assertRaises(ValueError):
            bind_ddr_report_header(original, replace(report, attributes=()))
        with self.assertRaises(ValueError):
            bind_ddr_report_header(original, report, record_index=1)
        self.assertEqual(
            [item.identifier for item in report.monitor_catalog], [3, 37, 38, 1001]
        )
        empty = format_ddr_capture(formatted_profile, replace(capture, records=()))
        self.assertEqual(
            (
                empty.information,
                empty.logical103,
                empty.attributes,
                empty.monitor_catalog,
            ),
            ((), None, (), ()),
        )
        hidden = bytearray(all_monitors[3])
        hidden[43] = 2
        all_monitors[3] = bytes(hidden)
        (root / "demo.ddb").write_bytes(
            authored_database(
                2,
                {
                    10: (0, b""),
                    13: (1, bytes(physical)),
                    14: (1, bytes(pattern)),
                    15: (1, unit),
                    50: (7, b"".join(all_monitors)),
                    51: (2, bytes(trigger + other_trigger)),
                    52: (4, b"".join(source.records(52))),
                    53: (0, b""),
                },
            )
        )
        hidden_profile = VehicleCatalog(root).build_profile(42)
        hidden_plan = selected_ddr_record_plan(hidden_profile, 2, b"\x02\x03")
        hidden_capture = replace(
            captured, record=replace(captured.record, plan=hidden_plan)
        )
        self.assertEqual(
            format_ddr_info(hidden_profile, hidden_capture).scalar_signals, ()
        )
        self.assertEqual(
            format_ddr_info(hidden_profile, hidden_capture, saved_log=True)
            .scalar_signals[0]
            .samples,
            ((1, 2),),
        )
        invalid_timeline = replace(captured.series[-1], samples=((10, 0),))
        with self.assertRaises(ToyotaCodecError):
            format_ddr_info(
                formatted_profile,
                replace(captured, series=captured.series[:-1] + (invalid_timeline,)),
            )
        with self.assertRaises(ValueError):
            format_ddr_info(profile, captured)
        with self.assertRaises(ToyotaCodecError):
            selected_ddr_signal_definition(profile, plan, 99)
        with self.assertRaises(ValueError):
            selected_ddr_signal_definition(source, plan, 7)

        p5_monitors = list(formatted_profile.records(50))
        for identifier in (111, 117):
            item = bytearray(monitor)
            struct.pack_into("<H", item, 24, identifier)
            p5_monitors.append(bytes(item))
        p5_monitors.sort(key=lambda row: int.from_bytes(row[24:26], "little"))
        (root / "demo.ddb").write_bytes(
            authored_database(
                2,
                {
                    10: (0, b""),
                    13: (1, bytes(physical)),
                    14: (1, bytes(pattern)),
                    15: (1, unit),
                    110: (9, b"".join(p5_monitors)),
                    111: (2, bytes(trigger + other_trigger)),
                    112: (4, b"".join(source.records(52))),
                    113: (0, b""),
                },
            )
        )
        p5_profile = VehicleCatalog(root).build_profile(42)
        p5_record = decode_ddr_p5_header(
            p5_profile, 10, bytes.fromhex("0203000000000000")
        )
        assert p5_record is not None
        p5_header = DdrP5Header(
            0x1401, 0, 8, bytes.fromhex("0203000000000000"), p5_record
        )
        p5_case = DdrP5Case(
            p5_header,
            (0x1501,),
            b"raw",
            b"buffer",
            p5_record,
            (),
            captured.series
            + (
                DdrValueSeries(111, 1, ((38, 0),)),
                DdrValueSeries(117, 1, ((0x101, 2),)),
            ),
        )
        p5_attributes = initial_ddr_p5_attribute_plan(p5_profile)
        p5_attributes = replace(
            p5_attributes,
            slots=tuple(
                replace(slot, supported=True) if slot.logical_id in (170, 171) else slot
                for slot in p5_attributes.slots
            ),
        )
        p5_capture = DdrP5RawCapture(
            DdrAttributeCapture(
                p5_attributes,
                ((103, 17), (118, 10), (170, 0xFFFFFFFF), (171, 0xFFFFFFFF)),
                10,
                1,
            ),
            (p5_header,),
            (p5_case,),
            (),
        )
        p5_report = format_ddr_p5_capture(p5_profile, p5_capture)
        self.assertEqual(p5_report.information[0].bytes, ((117, 1, 2), (111, 38, 0)))
        self.assertEqual(
            (
                p5_report.csv_110.logical_id,
                p5_report.csv_110.present,
                p5_report.csv_110.value,
            ),
            (170, True, 0xFFFFFFFF),
        )
        self.assertEqual(
            (
                p5_report.csv_128.logical_id,
                p5_report.csv_128.present,
                p5_report.csv_128.value,
            ),
            (171, True, 0x1FFFFFFF),
        )
        self.assertEqual((p5_report.logical103, p5_report.specification), (17, 10))
        saved_p5 = bind_ddr_report(original, p5_report, encoding="ascii")
        block = 7 + 2 * (original.version > 0x1004) + 4 * (original.version >= 0x1009)
        saved_pairs = saved_p5.records[0][block]
        self.assertEqual(saved_pairs[:22], (0,) * 22)
        self.assertEqual(saved_pairs[22:], (1, 0xFFFFFFFF, 1, 0x1FFFFFFF))
        self.assertEqual(saved_p5.records[0][block - 1], 10)
        p5_information = saved_p5.records[0][block - 6][0]
        self.assertEqual(p5_information[0][-7:], (1, 38, 0, 0, 0, 0, 0))
        self.assertEqual(p5_information[1][-7:], (2, 0, 0, 0, 0, 0, 0))
        self.assertEqual(p5_report.information[0].extra_signal.definition.name, "Angle")
        empty_p5 = format_ddr_p5_capture(p5_profile, replace(p5_capture, cases=()))
        self.assertEqual((empty_p5.information, empty_p5.logical103), ((), 17))
        with self.assertRaises(ValueError):
            format_ddr_p5_capture(formatted_profile, p5_capture)
        management = dict(self.management_rows)
        primary_row = bytearray(p5_profile.comm_pid_records(171)[0])
        struct.pack_into("<H", primary_row, 16, 177)
        management[54] = (management[54][0] + 1, management[54][1] + bytes(primary_row))
        (root / "Toyota.ddb").write_bytes(authored_database(1, management))
        primary_profile = VehicleCatalog(root).build_profile(42)
        primary_attributes = initial_ddr_p5_attribute_plan(primary_profile)
        primary_attributes = replace(
            primary_attributes,
            slots=tuple(
                replace(slot, supported=True)
                if slot.logical_id in (170, 171, 177)
                else slot
                for slot in primary_attributes.slots
            ),
        )
        primary_capture = replace(
            p5_capture,
            attributes=replace(
                p5_capture.attributes,
                plan=primary_attributes,
                observations=p5_capture.attributes.observations + ((177, 0xF1234567),),
            ),
        )
        primary_report = format_ddr_p5_capture(primary_profile, primary_capture)
        self.assertEqual(
            primary_report.csv_128, DdrP5SupportValue(177, True, 0x11234567)
        )
        self.assertEqual(
            ddr_report_support_values(primary_report),
            (primary_report.csv_110, primary_report.csv_128),
        )
        with (
            patch(
                "scripts.database_resources._ddr_monitor_catalog",
                side_effect=ToyotaCodecError(
                    "authored final catalog failure", 0xC0040101
                ),
            ),
            self.assertRaises(DdrPartialReportError) as failure,
        ):
            format_ddr_p5_capture(primary_profile, primary_report.capture)
        self.assertEqual(failure.exception.code, 0xC0040101)
        self.assertEqual(
            failure.exception.partial_report,
            replace(primary_report, monitor_catalog=()),
        )
        empty_p5 = replace(
            primary_report,
            information=(),
            csv_110=DdrP5SupportValue(170, False, 0),
            csv_128=DdrP5SupportValue(171, False, 0),
        )
        self.assertEqual(
            [
                (item.present, item.value)
                for item in ddr_report_support_values(empty_p5)
            ],
            [(False, 0), (False, 0)],
        )
        saved_primary = bind_ddr_report(original, primary_report, encoding="ascii")
        self.assertEqual(saved_primary.records[0][block][-2:], (1, 0x11234567))

    def test_p5_ddr_did_primitive_uses_actual_selected_CA_support_and_local_temp(self):
        from scripts.monitor_support import DataIdSupport

        rows = dict(self.management_rows)
        functions = bytearray(rows[18][1])
        struct.pack_into("<H", functions, len(functions) - 16, 42)
        rows[18] = (rows[18][0], bytes(functions))
        root = self.profile.catalog.root
        (root / "Toyota.ddb").write_bytes(authored_database(1, rows))
        profile = VehicleCatalog(root).build_profile(42)
        calls = []

        def exchange(query):
            calls.append(query)
            return b"\x62" + query.request[1:] + b"\xff\x80"

        cache = MonitorSupportCache(profile, exchange, "authored-ecu", bus_id=2)
        with patch.object(
            cache, "data_ids", return_value=DataIdSupport((0x1401, 0x1402))
        ):
            reader = DdrP5DataIdReader(cache)
        reader.check_ddr_support()
        self.assertIsNone(reader.read(0x1700))
        self.assertEqual(calls, [])
        self.assertEqual(reader.read(0x1401), b"\xff\x80")
        self.assertEqual(reader.read(0x1401), b"\xff\x80")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].request, bytes.fromhex("221401"))
        self.assertEqual(calls[0].native_parameter, 2)
        self.assertEqual(
            [item.cache_hit for item in reader.transactions], [False, True]
        )
        with patch.object(cache, "data_ids", return_value=DataIdSupport((0x1401,))):
            other = DdrP5DataIdReader(cache)
        with self.assertRaises(ToyotaCodecError):
            other.check_ddr_support()
        self.assertEqual(other.read(0x1401), b"\xff\x80")
        self.assertEqual(len(calls), 2)
        cache.exchange = lambda query: bytes.fromhex("621402")
        with self.assertRaises(ToyotaCodecError) as caught:
            reader.read(0x1402)
        self.assertEqual(caught.exception.code, 0xA0040202)
        self.assertEqual(reader.transactions[-1].reply, bytes.fromhex("621402"))
        self.assertEqual(reader.transactions[-1].status, 0xA0040202)
        cache.exchange = lambda query: (_ for _ in ()).throw(
            NativeStatus(0x90020321, b"partial")
        )
        # Caller rejection does not erase a successful lower TEMP exchange.
        with self.assertRaises(ToyotaCodecError):
            reader.read(0x1402)
        with patch.object(
            cache, "data_ids", return_value=DataIdSupport((0x1401, 0x1402))
        ):
            failed_reader = DdrP5DataIdReader(cache)
        with self.assertRaises(NativeStatus):
            failed_reader.read(0x1402)
        self.assertEqual(failed_reader.transactions[-1].reply, b"partial")
        self.assertEqual(failed_reader.transactions[-1].status, 0x90020321)
        cache.source_build = 12
        with self.assertRaises(SessionError):
            reader.read(0x1401)

    def test_p5_reader_no_init_is_applied_to_actual_communication_and_restored(self):
        rows = dict(self.management_rows)
        functions = bytearray(rows[18][1])
        struct.pack_into("<H", functions, len(functions) - 16, 42)
        rows[18] = (7, bytes(functions))
        root = self.profile.catalog.root
        (root / "Toyota.ddb").write_bytes(authored_database(1, rows))
        profile = VehicleCatalog(root).build_profile(42)
        observed = []

        @dataclass
        class Reply:
            code: int
            data: bytes

        class Operations:
            def send(self, request, **kwargs):
                observed.append(
                    (request, kwargs["initialization_mode"], kwargs["no_session"])
                )
                return 0

            def receive(self, **kwargs):
                return Reply(0, bytes.fromhex("621401aa"))

            def close(self):
                pass

        communication = NativeCommunication(
            profile, Operations(), "authored-ecu", bus_id=2
        )
        reader = DdrP5DataIdReader(communication.cache, enable_list=False, no_init=True)
        with communication.communication_flags(no_init=False, no_session=True):
            self.assertEqual(reader._read(0x1401, supported=False), b"\xaa")
            self.assertEqual(
                (communication.no_init, communication.no_session), (False, True)
            )
        self.assertEqual(observed, [(bytes.fromhex("221401"), 2, False)])
        self.assertEqual(
            (communication.no_init, communication.no_session), (False, False)
        )
        self.assertEqual(reader.transactions[0].payload, b"\xaa")
        with self.assertRaises(ValueError):
            DdrP5DataIdReader(
                communication.cache, enable_list=False, no_init=cast(Any, 1)
            )

    def test_ADS_no_enable_list_global_group_data_order_and_TEMP(self):
        rows = dict(self.management_rows)
        functions = bytearray(rows[18][1])
        struct.pack_into("<H", functions, len(functions) - 16, 42)
        rows[18] = (7, bytes(functions))
        root = self.profile.catalog.root
        (root / "Toyota.ddb").write_bytes(authored_database(1, rows))
        profile = VehicleCatalog(root).build_profile(42)
        calls = []
        values = {0x0101: bytes.fromhex("00000008"), 0x1C00: b"\x01", 0x1C08: b"\x00"}

        def exchange(query):
            calls.append(query.request)
            return (
                b"\x62"
                + query.request[1:3]
                + values[int.from_bytes(query.request[1:3], "big")]
            )

        cache = MonitorSupportCache(profile, exchange, "authored-ecu", bus_id=2)
        with patch.object(
            cache,
            "data_ids",
            side_effect=AssertionError("No enable-list producer in this native path"),
        ):
            reader = DdrP5DataIdReader(cache, enable_list=False)
        self.assertEqual(reader.read_no_enable_list(0x1C08, 1), (1, b""))
        self.assertEqual(reader.read_no_enable_list(0x1C08, 6), (2, b"\x00"))
        self.assertEqual(reader.read_no_enable_list(0x1C08, 7), (2, b"\x00"))
        self.assertEqual(
            calls, [bytes.fromhex(value) for value in ("220101", "221c00", "221c08")]
        )
        self.assertEqual(
            [row.cache_hit for row in reader.transactions],
            [False, False, False, True, True, True],
        )
        for control in (0, 8, 256, True):
            with self.assertRaises(ValueError):
                reader.read_no_enable_list(0x1C08, control)
        with self.assertRaises(ToyotaCodecError):
            reader.read_no_enable_list(0x1C00, 2)
        values[0x0101] = bytes(3)
        values[0x1C00] = bytes(1)
        other = DdrP5DataIdReader(cache, enable_list=False)
        self.assertEqual(other.read_no_enable_list(0x1C08, 1), (0, b""))
        self.assertEqual(other.read_no_enable_list(0x1C08, 6), (0, b""))
        self.assertEqual(calls[-2:], [bytes.fromhex("220101"), bytes.fromhex("221c00")])

    def test_ADS_security_selected_frames_NIST_block_append_zero_and_short_seed(self):
        rows = dict(self.management_rows)
        functions = rows[18][1]
        rows[18] = (
            9,
            functions[:-16]
            + struct.pack("<8H", 42, 0x109, 1, 3, 0, 0, 0, 0)
            + struct.pack("<8H", 42, 0x10A, 1, 4, 0, 0, 0, 0)
            + functions[-16:],
        )
        root = self.profile.catalog.root
        (root / "Toyota.ddb").write_bytes(authored_database(1, rows))
        profile = VehicleCatalog(root).build_profile(42)
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        seed = bytes.fromhex("00112233445566778899aabbccddeeff")
        calls = []

        def exchange(query):
            calls.append(query.request)
            return b"\x67\x01" + seed if query.request[1] == 1 else b"\x67\x02"

        cache = MonitorSupportCache(profile, exchange, "authored-ecu", bus_id=2)
        result = cancel_ads_security(cache, key)
        self.assertEqual(
            result.key_request,
            bytes.fromhex("2702100069c4e0d86a7b0430d8cdb78070b4c55a"),
        )
        self.assertEqual(result.seed_reply, b"\x67\x01" + seed)
        self.assertEqual(result.key_reply, b"\x67\x02")
        self.assertEqual(calls, [bytes.fromhex("27010000"), result.key_request])
        zero = MonitorSupportCache(
            profile, lambda query: b"\x67\x01" + bytes(16), "authored-ecu", bus_id=2
        )
        self.assertIsNone(cancel_ads_security(zero, key).key_request)
        self.assertEqual(zero.calls, 1)
        for length in (0, 15, 17):
            short = MonitorSupportCache(
                profile,
                lambda query, length=length: b"\x67\x01" + bytes(length),
                "authored-ecu",
                bus_id=2,
            )
            with self.assertRaises(ToyotaCodecError) as caught:
                cancel_ads_security(short, key)
            self.assertEqual(caught.exception.code, 0xA0040202)
        with self.assertRaises(ValueError):
            selected_ads_security_key(b"MZ")
        with self.assertRaises(ValueError):
            cancel_ads_security(cache, bytes(15))

    def test_ADS_grouped_DID_parser_duplicate_first_zero_and_partial_suffix(self):
        raw = bytes(8) + bytes.fromhex("04 200101aa 200101bb 000001cc 200200")
        packet = parse_ads_record_packet(raw)
        self.assertEqual(
            [(row.identifier, row.raw) for row in packet.groups[0].rows],
            [(0x2001, b"\xaa")],
        )
        self.assertFalse(packet.incomplete)
        self.assertEqual(packet.consumed, len(raw))
        inferred = parse_ads_record_packet(
            bytes(8) + bytes.fromhex("00 200101aa 200202bbcc")
        )
        self.assertEqual(
            [row.raw for row in inferred.groups[0].rows], [b"\xaa", b"\xbb\xcc"]
        )
        partial = parse_ads_record_packet(
            bytes(8) + bytes.fromhex("02 200101aa 200202bb")
        )
        self.assertTrue(partial.incomplete)
        self.assertEqual(partial.groups[0].rows[0].raw, b"\xaa")
        self.assertEqual(partial.raw[-4:], bytes.fromhex("200202bb"))
        self.assertTrue(parse_ads_record_packet(bytes(7)).incomplete)
        self.assertEqual(parse_ads_record_packet(bytes(8)).groups, ())
        with self.assertRaises(ValueError):
            parse_ads_record_packet(bytes(65536))

    def test_ADS_raw_capture_real_selected_security_ready_behavior_and_record_frames(
        self,
    ):
        templates = tuple(
            bytes.fromhex(value)
            for value in (
                "2701",
                "2702",
                "220000",
                "310b",
                "310c0000",
                "310d000000000000",
            )
        )
        offset, headers = 0, bytearray()
        for value in templates:
            headers += struct.pack("<IH", offset, len(value))
            offset += len(value)
        category = bytearray(self.profile.category_record)
        category[72] = 20
        rows = {
            0: (6, bytes(headers) + b"".join(templates)),
            16: (1, bytes(category)),
            17: (
                6,
                b"".join(
                    struct.pack("<4H", index, index, 0, 0) for index in range(1, 7)
                ),
            ),
            18: (
                6,
                b"".join(
                    struct.pack("<8H", 42, function, 1, index, 0, 0, 0, 0)
                    for function, index in (
                        (0xCA, 3),
                        (0x109, 1),
                        (0x10A, 2),
                        (0x10B, 4),
                        (0x10C, 5),
                        (0x10D, 6),
                    )
                ),
            ),
            29: self.management_rows[29],
        }
        behavior = bytearray(44)
        struct.pack_into("<H", behavior, 32, 0x1234)
        behavior[40:42] = bytes((2, 3))
        definitions = []
        for logical, first_bit, last_bit in (
            (12, 0, 7),
            (13, 8, 39),
            (17, 40, 47),
            (18, 48, 55),
            (19, 56, 63),
            (200, 64, 127),
        ):
            item = bytearray(60)
            struct.pack_into("<H", item, 36, logical)
            struct.pack_into("<3H", item, 40, 21, first_bit, last_bit)
            struct.pack_into("<H", item, 52, 0x2001)
            if logical == 200:
                struct.pack_into("<I", item, 24, 1)
                item[54] = 3
            item[59] = 1
            definitions.append(bytes(item))
        physical = struct.pack("<3I2H8x", 1, 0, 0, 21, 22)
        unit = struct.pack("<I4H", 0, 22, 7, 0, 0)
        root = self.profile.catalog.root
        (root / "Toyota.ddb").write_bytes(authored_database(1, rows))
        (root / "demo.ddb").write_bytes(
            authored_database(
                2,
                {
                    10: (0, b""),
                    13: (1, physical),
                    14: (0, b""),
                    15: (1, unit),
                    90: (1, struct.pack("<4H", 0, 0x2001, 0, 0)),
                    133: (1, bytes(behavior)),
                    134: (6, b"".join(definitions)),
                    135: (0, b""),
                },
            )
        )
        label = "RPM".encode("utf-16le") + bytes(2)
        (root / "M_English.ddb").write_bytes(
            authored_database(4, {0: (1, struct.pack("<IH", 0, len(label)) + label)})
        )
        profile = VehicleCatalog(root).build_profile(42)
        calls = []
        marker_value = 0x55

        def exchange(query):
            request = query.request
            calls.append(request)
            if request == bytes.fromhex("2701"):
                return bytes.fromhex("6701") + bytes(16)
            if request[0] == 0x22:
                did = int.from_bytes(request[1:3], "big")
                return (
                    b"\x62"
                    + request[1:3]
                    + {
                        0x0101: bytes.fromhex("00000008"),
                        0x1C00: b"\x01",
                        0x1C08: b"\x00",
                    }[did]
                )
            if request[1] == 0x0B:
                return bytes.fromhex("710b12345678")
            if request[1] == 0x0C:
                return bytes.fromhex("710c1234") + b"".join(
                    number.to_bytes(4, "big") for number in (0x20001, 2, 1, 0x10002, 2)
                )
            identifier = int.from_bytes(request[4:8], "big")
            if identifier == 2:
                raise NativeStatus(0x90020321, b"partial")
            suffix = bytes.fromhex(
                "012001100000000017020355fedcba9876543210"
                if identifier == 1
                else "00200202bbcc"
            )
            if identifier == 1:
                suffix = suffix[:11] + bytes((marker_value,)) + suffix[12:]
            return b"\x71" + request[1:] + suffix

        cache = MonitorSupportCache(profile, exchange, "authored-ecu", bus_id=2)
        from scripts.command_api import SOURCE_SHA256, CommandAPI, CommandSource

        source = CommandSource(18, SOURCE_SHA256[18])
        report = CommandAPI(source).selected_ads_ddr_report(cache, bytes(16))
        before = tuple(calls)
        with self.assertRaises(Cancelled):
            CommandAPI(source, cancelled=lambda: True).selected_ads_ddr_report(
                cache, bytes(16)
            )
        native12 = MonitorSupportCache(
            profile, exchange, "authored-ecu", bus_id=2, source_build=12
        )
        with self.assertRaises(ValueError):
            CommandAPI(source).selected_ads_ddr_report(native12, bytes(16))
        with self.assertRaises(NotImplementedError):
            CommandAPI(CommandSource(12, SOURCE_SHA256[12])).selected_ads_ddr_report(
                native12, bytes(16)
            )
        self.assertEqual(tuple(calls), before)
        captured = report.capture
        self.assertEqual(len(report.information), 1)
        self.assertEqual(report.information[0].header_a, ((2, 0),))
        self.assertEqual(report.information[0].header_b, ((3, 0),))
        self.assertEqual(report.information[0].counts, (0, 0, 1))
        self.assertEqual(
            report.information[0].main_signals[-1].samples, ((0xFEDCBA9876543210, 0),)
        )
        self.assertEqual(
            report.information[0].main_signals[-1].definition.bit_width, 64
        )
        self.assertEqual(len(report.monitor_catalog), 6)
        from tests.test_tse_reports import minimal

        self.ads_pipeline_sections = {}
        for version in (0x1009, 0x100A, 0x1027):
            layout = tse_reports._section_layout("DDRData", 0x272A, version)
            original = tse_reports.ReportSection(
                "DDRData", 0x272A, 0, version, (minimal(layout.item),)
            )
            saved = bind_ads_ddr_report(original, report, encoding="ascii")
            self.ads_pipeline_sections[f"ads-{version:04x}"] = saved
            raw_saved = tse_reports.encode_section(saved)
            decoded_saved = tse_reports.decode_section("DDRData", raw_saved)
            self.assertEqual(decoded_saved, saved)
            main_info, validity = decoded_saved.records[0][20][0]
            self.assertEqual(main_info[0:2], ((2,), (3,)))
            self.assertEqual(main_info[6:8], (0, 0))
            self.assertEqual(main_info[10], 23)
            main_signals = main_info[21 if version < 0x100A else 20]
            self.assertEqual(main_signals[-1][0], 200)
            self.assertEqual(main_signals[-1][6][5], 64)
            self.assertEqual(
                main_signals[-1][-1], ((0xFEDCBA9876543210, b"76543210", 0),)
            )
            self.assertEqual(validity[18 if version < 0x100A else 17][-1], (0,))
            self.assertEqual(len(decoded_saved.records[0][22]), 6)
            self.assertEqual(tse_reports.encode_section(decoded_saved), raw_saved)
            named = tse_reports.view_section(decoded_saved, encoding="ascii")
            parameter = next(
                row
                for row in named["parameters"]
                if row["identifier_raw"] == 200 and row["values"]
            )
            self.assertEqual(parameter["name"], "RPM")
            self.assertEqual(
                parameter["values"],
                [
                    {
                        "raw": 0xFEDCBA9876543210,
                        "display": "76543210",
                        "flags_raw": 0,
                        "display_source": "stored-native-text",
                        "invalidity_raw": 0,
                        "invalidity_check": False,
                        "invalidity_source_path": [
                            0,
                            20,
                            0,
                            1,
                            18 if version < 0x100A else 17,
                            5,
                            0,
                        ],
                        "stored_display": "76543210",
                    }
                ],
            )
            restored = list(saved.records[0])
            for position in (20, 21, 22):
                restored[position] = original.records[0][position]
            self.assertEqual(tuple(restored), original.records[0])
            for cut in range(1, 10):
                with self.assertRaises(SnapshotError):
                    tse_reports.decode_section("DDRData", raw_saved[:-cut])
            with self.assertRaises(SnapshotError):
                tse_reports.decode_section("DDRData", raw_saved + b"\x00")
        self.ads_pipeline_databases = {
            filename: (root / filename).read_bytes()
            for filename in ("Toyota.ddb", "demo.ddb", "M_English.ddb")
        }
        self.assertEqual(len(captured.records), 1)
        self.assertEqual(captured.records[0].identifiers, (1, 0x10002))
        self.assertEqual(captured.records[0].behavior_records, (bytes(behavior),))
        self.assertEqual(
            [row[1].groups[0].rows[0].raw for row in captured.records[0].packets],
            [bytes.fromhex("0000000017020355fedcba9876543210"), b"\xbb\xcc"],
        )
        self.assertEqual(captured.transactions[-1].status, 0x90020321)
        self.assertEqual(captured.transactions[-1].reply, b"partial")
        self.assertEqual(
            calls,
            [
                bytes.fromhex(value)
                for value in (
                    "2701",
                    "220101",
                    "221c00",
                    "221c08",
                    "310b",
                    "310c1234",
                    "310d123400000001",
                    "310d123400010002",
                    "310d123400000002",
                )
            ],
        )

        # Change an actual primitive marker byte: native transforms now mark
        # channel200 nonzero while preserving raw64/sampletype/stored text.
        marker_value = 0x54
        invalid_cache = MonitorSupportCache(profile, exchange, "authored-ecu", bus_id=2)
        invalid_report = CommandAPI(source).selected_ads_ddr_report(
            invalid_cache, bytes(16)
        )
        self.assertEqual(
            invalid_report.information[0].main_signals[-1].samples,
            ((0xFEDCBA9876543210, 1),),
        )
        invalid_saved = bind_ads_ddr_report(original, invalid_report, encoding="ascii")
        self.ads_pipeline_sections["ads-nonzero-1027"] = invalid_saved
        # A separately authored saved-data mutation removes the recorded mask,
        # exercising native default-invalid bounds rather than a capture stub.
        row = list(saved.records[0])
        info, checks = row[20][0]
        checks = list(checks)
        nested = list(checks[17])
        nested[-1] = ()
        checks[17] = tuple(nested)
        row[20] = ((info, tuple(checks)),)
        missing_saved = replace(saved, records=(tuple(row),))
        self.ads_pipeline_sections["ads-missing-1027"] = missing_saved
        for section, expected_mask in ((invalid_saved, 1), (missing_saved, None)):
            decoded = tse_reports.decode_section(
                "DDRData", tse_reports.encode_section(section)
            )
            named = tse_reports.view_section(decoded, encoding="ascii")
            channel = next(
                item
                for item in named["parameters"]
                if item["identifier_raw"] == 200 and item["values"]
            )
            value = channel["values"][0]
            self.assertEqual(value["raw"], 0xFEDCBA9876543210)
            self.assertEqual(value["flags_raw"], 0)
            self.assertEqual(value["stored_display"], "76543210")
            self.assertEqual(value["invalidity_raw"], expected_mask)
            self.assertTrue(value["invalidity_check"])
            self.assertIsNone(value["display"])
            self.assertEqual(value["invalid_display_resource"], "DISPLAY_VALUE_INVALID")
            self.assertTrue(channel["native_channel_suppressed"])

    def test_ADS_selected_uint64_decoder_selector_validation_and_missing_flag3(self):
        root = self.profile.catalog.root
        behavior = bytearray(44)
        struct.pack_into("<H", behavior, 32, 0x1234)
        behavior[40:42] = bytes((2, 3))
        definitions = []
        for identifier, start, end, did in (
            (12, 0, 7, 0x2001),
            (13, 8, 39, 0x2001),
            (17, 40, 47, 0x2001),
            (18, 48, 55, 0x2001),
            (19, 56, 63, 0x2001),
            (200, 64, 127, 0x2001),
            (201, 0, 7, 0x2002),
        ):
            row = bytearray(60)
            struct.pack_into("<H", row, 36, identifier)
            struct.pack_into("<2H", row, 42, start, end)
            struct.pack_into("<H", row, 52, did)
            row[59] = 1
            definitions.append(bytes(row))
        rob = bytearray(8)
        struct.pack_into("<H", rob, 2, 0x2001)
        (root / "demo.ddb").write_bytes(
            authored_database(
                2,
                {
                    10: (0, b""),
                    90: (1, bytes(rob)),
                    133: (1, bytes(behavior)),
                    134: (7, b"".join(definitions)),
                    135: (0, b""),
                },
            )
        )
        profile = VehicleCatalog(root).build_profile(42)
        value = 0xFEDCBA9876543210
        data = bytes.fromhex("0000000017020355") + value.to_bytes(8, "big")
        packet = parse_ads_record_packet(
            bytes(8) + bytes((1, 0x20, 1, len(data))) + data
        )
        captured = AdsRawRecord(0x1234, (bytes(behavior),), 1, (1,), ((1, packet),))
        decoded = decode_ads_ddr_record(profile, captured)
        assert decoded is not None
        self.assertEqual(
            [(row.identifier, row.samples) for row in decoded.series],
            [
                (12, ((0, 0),)),
                (13, ((23, 0),)),
                (17, ((2, 0),)),
                (18, ((3, 0),)),
                (19, ((0x55, 0),)),
                (200, ((value, 0),)),
                (201, ((0, 3),)),
            ],
        )
        # Optional DB259 reference resolves management variable2 (DID2100),
        # requires type7 and a nonzero selected bit in the SAME packet group.
        referenced = list(definitions)
        monitor = bytearray(referenced[5])
        struct.pack_into("<H", monitor, 38, 7)
        referenced[5] = bytes(monitor)
        bit = bytearray(struct.pack("<5H2B", 7, 2, 0, 0, 0, 0, 7))
        for byte, separate, kind, expected in (
            (0x80, False, 7, (value, 0)),
            (0, False, 7, (0, 3)),
            (0x80, True, 7, (0, 3)),
            (0x80, False, 6, (0, 3)),
        ):
            bit[11] = kind
            (root / "demo.ddb").write_bytes(
                authored_database(
                    2,
                    {
                        10: (0, b""),
                        89: (1, bytes(bit)),
                        90: (1, bytes(rob)),
                        133: (1, bytes(behavior)),
                        134: (7, b"".join(referenced)),
                        135: (0, b""),
                    },
                )
            )
            selected = VehicleCatalog(root).build_profile(42)
            primary = bytes((0x20, 1, len(data))) + data
            condition = bytes((0x21, 0, 1, byte))
            raw = bytes(8) + (
                bytes((1,)) + primary + bytes((1,)) + condition
                if separate
                else bytes((2,)) + primary + condition
            )
            joined = decode_ads_ddr_record(
                selected,
                replace(captured, packets=((1, parse_ads_record_packet(raw)),)),
            )
            assert joined is not None
            self.assertEqual(joined.series[5].samples, (expected,))
        self.assertEqual(ads_bits(bytes.fromhex("fffedcba9876543210"), 0, 71), value)
        self.assertEqual(ads_bits(b"\xaa\x55", 3, 11), 0xA5)
        invalid = bytearray(data)
        invalid[5] = 4
        invalid_packet = parse_ads_record_packet(
            bytes(8) + bytes((1, 0x20, 1, len(invalid))) + invalid
        )
        self.assertIsNone(
            decode_ads_ddr_record(
                profile, replace(captured, packets=((1, invalid_packet),))
            )
        )
        secondary = replace(
            captured,
            identifiers=(1, 0x10001),
            packets=((1, packet), (0x10001, invalid_packet)),
        )
        kept = decode_ads_ddr_record(profile, secondary)
        assert kept is not None
        self.assertEqual(kept.series[5].samples, ((value, 0),))
        with self.assertRaises(ValueError):
            decode_ads_ddr_record(self.profile, captured)
        with self.assertRaises(ValueError):
            ads_bits(b"\x00", 0, 8)

    def test_ADS_transform_counts_uint64_conditions_scalar_propagation_and_BCD(self):
        root = self.profile.catalog.root
        definitions = []
        for identifier, kind in (
            (5, 0),
            (6, 0),
            (7, 0),
            (12, 0),
            (13, 1),
            (17, 1),
            (18, 1),
            (19, 1),
            (200, 1),
            (201, 1),
            (202, 1),
        ):
            row = bytearray(60)
            struct.pack_into("<H", row, 36, identifier)
            row[59] = kind
            struct.pack_into("<I", row, 24, 1)
            struct.pack_into("<3H", row, 40, 21, 0, 63)
            if identifier == 202:
                row[55] = 2
            definitions.append(bytes(row))
        condition_a = bytearray(24)
        struct.pack_into("<Q2H", condition_a, 0, 0xFEDCBA9876543210, 200, 200)
        condition_a[16:18] = bytes((2, 1))
        condition_b = bytearray(24)
        struct.pack_into("<Q2H", condition_b, 0, 0, 202, 5)
        condition_b[16:18] = bytes((2, 1))
        behavior = bytearray(44)
        struct.pack_into("<4I", behavior, 12, 1, 99, 11, 12)
        struct.pack_into("<I", behavior, 28, 3)
        struct.pack_into("<H", behavior, 32, 1)
        behavior[40:42] = bytes((2, 3))
        second_behavior = bytearray(behavior)
        second_behavior[40] = 4
        physical = struct.pack("<3I2H8x", 2, 3, 4, 21, 22)
        unit = struct.pack("<I4H", 2, 22, 7, 0, 0)
        labels = [
            text.encode("utf-16le") + b"\0\0" for text in ("Angle", "deg", "Memo")
        ]
        offset, indices = 0, bytearray()
        for label in labels:
            indices += struct.pack("<IH", offset, len(label))
            offset += len(label)
        (root / "M_English.ddb").write_bytes(
            authored_database(4, {0: (3, bytes(indices) + b"".join(labels))})
        )
        (root / "demo.ddb").write_bytes(
            authored_database(
                2,
                {
                    10: (0, b""),
                    13: (1, physical),
                    14: (0, b""),
                    15: (1, unit),
                    133: (2, bytes(behavior + second_behavior)),
                    134: (len(definitions), b"".join(definitions)),
                    135: (2, bytes(condition_a + condition_b)),
                },
            )
        )
        profile = VehicleCatalog(root).build_profile(42)
        samples = {
            5: ((1000000, 0),),
            6: ((0x38, 0),),
            7: ((0x13, 0),),
            12: ((0, 0),),
            13: ((100, 0), (90, 0), (110, 0), (120, 0)),
            17: ((2, 0), (2, 0), (2, 0), (4, 0)),
            18: ((3, 0), (3, 0), (3, 2), (3, 0)),
            19: ((0x55, 0), (0x55, 0), (0, 0), (0x55, 0)),
            200: ((0xFEDCBA9876543210, 0),) * 4,
            201: ((0, 3),) * 4,
            202: ((12, 0),) * 4,
        }
        rows = tuple(
            AdsValueSeries(
                struct.unpack_from("<H", row, 36)[0],
                row[59],
                samples[struct.unpack_from("<H", row, 36)[0]],
                row,
            )
            for row in definitions
        )
        record = AdsDecodedRecord(
            profile.database.sha256,
            profile.category,
            profile.exception_ids,
            AdsRawRecord(1, (), 1, (), ()),
            rows,
        )
        result = transform_ads_ddr_record(profile, record)
        assert result is not None
        self.assertEqual(result.header, bytes((2, 3)))
        self.assertEqual(result.counts, (1, 1, 2))
        values = {row.identifier: row.samples for row in result.series}
        self.assertNotIn(201, values)
        self.assertEqual(values[5], ((1000000, 2),))
        self.assertEqual(values[6], ((38, 0),))
        self.assertEqual(values[7], ((0x13, 2),))
        self.assertEqual(values[18], ((3, 0), (3, 0), (3, 1), (3, 0)))
        self.assertEqual(
            values[200],
            (
                (0xFEDCBA9876543210, 2),
                (0xFEDCBA9876543210, 2),
                (0xFEDCBA9876543210, 1),
                (0xFEDCBA9876543210, 2),
            ),
        )
        # Scalar invalid reference marks all target samples, including flag1.
        self.assertEqual(values[202], ((12, 2),) * 4)
        info = format_ads_ddr_info(profile, result)
        self.assertEqual(
            (info.header_a, info.header_b), (((2, 0), (4, 0)), ((3, 0), (3, 0)))
        )
        self.assertEqual((info.conversion, info.counts), ((11, 12), (1, 1, 2)))
        self.assertEqual(
            [(item.name, item.memo) for item in info.triggers], [("Angle", "Memo")] * 2
        )
        self.assertEqual(info.triggers[0].memo_id, 99)
        self.assertEqual(info.bytes, ((6, 38, 0), (7, 0x13, 2)))
        self.assertEqual(info.mode, (0, 0))
        main = {row.definition.identifier: row for row in info.main_signals}
        side = {row.definition.identifier: row for row in info.side_signals}
        self.assertNotIn(202, main)
        self.assertEqual(main[200].samples, ((0xFEDCBA9876543210, 2),) * 2)
        self.assertEqual(
            side[200].samples, ((0xFEDCBA9876543210, 2), (0xFEDCBA9876543210, 1))
        )
        self.assertEqual(
            (
                main[200].definition.name,
                main[200].definition.unit,
                main[200].definition.bit_width,
            ),
            ("Angle", "deg", 64),
        )
        unchecked = replace(
            record,
            series=tuple(
                replace(row, samples=((0, 0),) * 4) if row.identifier == 19 else row
                for row in rows
            ),
        )
        other = transform_ads_ddr_record(profile, unchecked)
        assert other is not None
        unknown = {row.identifier: row.samples for row in other.series}
        self.assertEqual(unknown[6], ((0x38, 1),))
        self.assertEqual(unknown[17], ((2, 0), (2, 1), (2, 1), (4, 1)))
        with self.assertRaises(ValueError):
            transform_ads_ddr_record(
                profile, replace(record, series=(replace(rows[0], kind=1),) + rows[1:])
            )
        with self.assertRaises(Cancelled):
            transform_ads_ddr_record(profile, record, cancelled=lambda: True)
        with self.assertRaises(ValueError):
            transform_ads_ddr_record(self.profile, record)

    def test_p5_selected_header_case_queries_and_distinct_timeline_bytes(self):
        root = self.profile.catalog.root
        trigger = bytearray(self.profile.records(51)[0])
        struct.pack_into("<6H", trigger, 16, 2, 0, 0, 8, 3, 4)
        monitors = []
        for identifier, selector, width in ((7, 0, 8), (1001, 0x22, 16), (1002, 0, 4)):
            row = bytearray(48)
            struct.pack_into("<H", row, 24, identifier)
            struct.pack_into("<4H", row, 28, 0, width - 1, 0, width - 1)
            row[44] = selector
            monitors.append(bytes(row))
        addresses = []
        for identifier, offset, kind, stride in (
            (1, 0, 1, 0),
            (2, 1, 1, 0),
            (7, 2, 1, 0),
            (1001, 8, 2, 2),
            (1002, 12, 2, 0),
        ):
            row = bytearray(16)
            struct.pack_into("<IHH", row, 0, offset, identifier, stride)
            row[10:12] = bytes((2, kind))
            addresses.append(bytes(row))
        case_rows = []
        for header_did, did, index in (
            (0x1401, 0x1501, 7),
            (0x1401, 0x1502, 7),
            (0x1401, 0x1503, 8),
            (0x1402, 0x1601, 7),
        ):
            row = bytearray(12)
            struct.pack_into("<2H", row, 0, header_did, did)
            row[8] = index
            case_rows.append(bytes(row))
        (root / "demo.ddb").write_bytes(
            authored_database(
                2,
                {
                    10: (0, b""),
                    108: (1, struct.pack("<4H", 0x1401, 8, 0, 0)),
                    109: (4, b"".join(case_rows)),
                    110: (3, b"".join(monitors)),
                    111: (1, bytes(trigger)),
                    112: (5, b"".join(addresses)),
                    113: (0, b""),
                },
            )
        )
        profile = VehicleCatalog(root).build_profile(42)
        header = bytes.fromhex("02037f0000000000")
        record = decode_ddr_p5_header(profile, 10, header)
        assert record is not None
        self.assertEqual(record.plan.table_slots, (110, 111, 112, 113))
        self.assertEqual(record.values, ((7, b"\x7f", 127),))
        self.assertIsNone(decode_ddr_p5_header(profile, 10, b"\xff" * 8))
        payload = header + bytes.fromhex("12345678ab")
        timelines = decode_ddr_p5_detail(profile, record, payload)
        self.assertEqual(
            [item.values for item in timelines], [(0x3412, 0x7856), (10, 11)]
        )
        self.assertEqual(timelines[0].raw, bytes.fromhex("12345678"))
        self.assertEqual(
            ddr_p5_case_identifiers(profile, 10, 0x1401, 0, (0x1501, 0x1502)),
            (0x1501, 0x1502),
        )
        self.assertEqual(
            ddr_p5_case_identifiers(profile, 10, 0x1401, 1, (0x1503,)), (0x1503,)
        )
        self.assertEqual(ddr_p5_case_identifiers(profile, 10, 0x1401, 0, (0x1501,)), ())
        self.assertEqual(
            ddr_p5_case_identifiers(profile, 10, 0x1401, 249, (0x1501,)), ()
        )
        with self.assertRaises(ToyotaCodecError):
            ddr_p5_case_identifiers(profile, 10, 0x1410, 0, ())
        self.assertEqual(
            trim_ddr_p5_case_payload(record, bytes(range(12))),
            bytes((0, 1, 2, 5, 6, 7, 8, 9, 10, 11, 0, 0)),
        )
        self.assertIsNone(trim_ddr_p5_case_payload(record, bytes(7)))
        for raw in (payload[:-1], payload[:9]):
            with self.assertRaises(ToyotaCodecError):
                decode_ddr_p5_detail(profile, record, raw)
        with self.assertRaises(Cancelled):
            decode_ddr_p5_detail(profile, record, payload, cancelled=lambda: True)
        with self.assertRaises(ValueError):
            decode_ddr_p5_detail(self.profile, record, payload)
        with self.assertRaises(ToyotaCodecError):
            decode_ddr_p5_header(profile, 2, header)
        with self.assertRaises(ValueError):
            decode_ddr_p5_header(profile, 10, bytes(513))

        # Run actual selected CA acquisition, not a replacement capture implementation.
        from scripts.monitor_support import DataIdSupport

        rows = dict(self.management_rows)
        categories = bytearray(rows[16][1])
        categories[72] = 20
        rows[16] = (2, bytes(categories))
        functions = bytearray(rows[18][1])
        struct.pack_into("<H", functions, len(functions) - 16, 42)
        rows[18] = (7, bytes(functions))
        attrs = []
        for logical, did in ((118, 0x14F0), (177, 0x1401)):
            row = bytearray(44)
            struct.pack_into("<4H", row, 16, logical, 42, 0, 15)
            struct.pack_into("<H", row, 34, did)
            row[38] = 2
            attrs.append(bytes(row))
        rows[54] = (2, b"".join(attrs))
        (root / "Toyota.ddb").write_bytes(authored_database(1, rows))
        struct.pack_into("<2H", trigger, 24, 0, 0)
        for identifier, offset in ((17, 3), (111, 4)):
            monitor = bytearray(48)
            struct.pack_into("<H", monitor, 24, identifier)
            struct.pack_into("<4H", monitor, 28, 0, 7, 0, 7)
            monitors.append(bytes(monitor))
            address = bytearray(16)
            struct.pack_into("<IH", address, 0, offset, identifier)
            address[10:12] = bytes((2, 1))
            addresses.append(bytes(address))
        monitors.sort(key=lambda row: int.from_bytes(row[24:26], "little"))
        addresses.sort(
            key=lambda row: (row[10], row[11], int.from_bytes(row[4:6], "little"))
        )
        condition = bytearray(16)
        struct.pack_into("<2H", condition, 4, 9999, 9999)
        condition[12:14] = bytes((2, 1))
        header = bytes.fromhex("02037f5538000000")
        payload = header + bytes.fromhex("12345678ab")
        (root / "demo.ddb").write_bytes(
            authored_database(
                2,
                {
                    10: (0, b""),
                    108: (1, struct.pack("<4H", 0x1401, 8, 0, 0)),
                    109: (4, b"".join(case_rows)),
                    110: (5, b"".join(monitors)),
                    111: (1, bytes(trigger)),
                    112: (7, b"".join(addresses)),
                    113: (1, bytes(condition)),
                },
            )
        )
        profile = VehicleCatalog(root).build_profile(42)
        calls = []
        values = {
            0x14F0: bytes.fromhex("000a"),
            0x1401: header * 2,
            0x1501: payload[:8],
            0x1502: payload[8:],
            0x1503: b"\xff" * 13,
        }

        def exchange(query):
            calls.append(query.request)
            if query.request[0] == 0x27:
                return bytes.fromhex("67010000")
            return (
                b"\x62"
                + query.request[1:3]
                + values[int.from_bytes(query.request[1:3], "big")]
            )

        cache = MonitorSupportCache(profile, exchange, "authored-ecu", bus_id=2)
        with patch.object(
            cache,
            "data_ids",
            return_value=DataIdSupport(tuple(sorted((*values, 0x1402)))),
        ):
            captured = capture_ddr_p5_raw_records(cache)
        self.assertEqual(captured.attributes.spec_value, 10)
        self.assertEqual([row.index for row in captured.headers], [0, 1])
        self.assertEqual(len(captured.cases), 1)
        self.assertEqual(captured.cases[0].raw, payload)
        self.assertEqual(captured.cases[0].timelines[0].values, (0x3412, 0x7856))
        transformed_cache = MonitorSupportCache(
            profile, exchange, "authored-ecu", bus_id=2
        )
        with patch.object(
            transformed_cache,
            "data_ids",
            return_value=DataIdSupport(tuple(sorted((*values, 0x1402)))),
        ):
            transformed = capture_ddr_p5_records(transformed_cache)
        self.assertEqual(
            [(row.identifier, row.samples) for row in transformed.cases[0].series],
            [
                (7, ((127, 0),)),
                (17, ((0x55, 0),)),
                (111, ((38, 0),)),
                (1001, ((0x3412, 0), (0x7856, 0))),
                (1002, ((10, 0), (11, 0))),
            ],
        )
        self.assertEqual(transformed.cases[0].raw[4], 0x38)
        self.assertEqual(
            [row.did for row in captured.transactions], [0x1401, 0x1501, 0x1502, 0x1503]
        )
        self.assertEqual(
            calls,
            2
            * [
                bytes.fromhex(value)
                for value in (
                    "27010000",
                    "2214f0",
                    "221401",
                    "221401",
                    "221501",
                    "221502",
                    "221503",
                )
            ],
        )

    def test_selected92_normal_and_P5_primitives_to_saved_named_parameters(self):
        from scripts.command_api import SOURCE_SHA256, CommandAPI, CommandSource
        from tests.test_tse_reports import minimal

        root = self.profile.catalog.root
        self.pipeline_sections = {}
        self.pipeline_requests = {}
        self.pipeline_databases = {}
        self.pipeline_reports = {}
        self.pipeline_replies = {}
        for p5 in (False, True):
            rows = dict(self.management_rows)
            category = bytearray(self.profile.category_record)
            category[72] = 20  # Actual selected CommDid path, without PID-bit mocks.
            rows[16] = (1, bytes(category))
            templates = (
                bytes.fromhex("91000000000000"),
                bytes.fromhex("2100"),
                bytes.fromhex("27010000"),
                bytes.fromhex("27021000"),
                bytes.fromhex("27030000"),
                bytes.fromhex("27042000"),
                bytes.fromhex("220000"),
            )
            storage, directory = bytearray(), bytearray()
            for raw in templates:
                directory += struct.pack("<IH", len(storage), len(raw))
                storage += raw
            rows[0] = (len(templates), bytes(directory + storage))
            functions = (
                (0xA1, 1),
                (0x6B, 2),
                (0xC1, 3),
                (0xC2, 4),
                (0xC3, 5),
                (0xC4, 6),
                (0xCA, 7),
                (0xC8, 7),
            )
            rows[18] = (
                len(functions),
                b"".join(
                    struct.pack("<8H", 42, function, 1, variable, 0, 0, 0, 0)
                    for function, variable in sorted(functions)
                ),
            )
            attributes = []
            fields = (
                ((118, 0x14F0, 0, 15, 0), (103, 0x1401, 16, 31, 0))
                if p5
                else (
                    (101, 0x14B1, 0, 15, 0xB1),
                    (103, 0x14B1, 16, 31, 0xB1),
                    (104, 0x14B1, 32, 63, 0xB1),
                    (105, 0x14B1, 64, 79, 0xB1),
                    (118, 0x14F0, 0, 15, 0),
                    (136, 0x1421, 0, 7, 0x21),
                    (137, 0x1421, 8, 15, 0x21),
                )
            )
            for logical, did, first, last, pid in sorted(fields):
                row = bytearray(44)
                struct.pack_into("<4H", row, 16, logical, 42, first, last)
                struct.pack_into("<H", row, 34, did)
                row[38:40] = bytes((2, pid))
                attributes.append(bytes(row))
            rows[54] = (len(attributes), b"".join(attributes))
            (root / "Toyota.ddb").write_bytes(authored_database(1, rows))
            label = "RPM".encode("utf-16le") + bytes(2)
            (root / "M_English.ddb").write_bytes(
                authored_database(
                    4, {0: (1, struct.pack("<IH", 0, len(label)) + label)}
                )
            )
            monitors, addresses = [], []
            for identifier, offset, kind in (
                (1, 0, 1),
                (2, 1, 1),
                (3, 2, 1),
                (7, 3, 1),
                (1001, 8, 2),
            ):
                monitor = bytearray(48)
                struct.pack_into("<I", monitor, 20, 1)
                struct.pack_into("<2H", monitor, 24, identifier, 21)
                struct.pack_into("<4H", monitor, 28, 0, 7, 0, 7)
                monitor[44] = 2
                monitors.append(bytes(monitor))
                address = bytearray(16)
                struct.pack_into("<IH", address, 0, offset, identifier)
                address[10:12] = bytes((2, kind))
                addresses.append(bytes(address))
            trigger = bytearray(36)
            struct.pack_into("<4I", trigger, 0, 1, 1, 1, 1)
            struct.pack_into("<3H", trigger, 16, 1, 0, 1)
            struct.pack_into("<H", trigger, 22, 8)
            trigger[30:32] = bytes((2, 3))
            tables = {
                10: (0, b""),
                13: (1, struct.pack("<3I2H8x", 1, 1, 0, 21, 22)),
                14: (0, b""),
                15: (1, struct.pack("<I4H", 0, 22, 7, 0, 0)),
            }
            bank = 110 if p5 else 50
            tables.update(
                {
                    bank: (len(monitors), b"".join(monitors)),
                    bank + 1: (1, bytes(trigger)),
                    bank + 2: (len(addresses), b"".join(addresses)),
                    bank + 3: (0, b""),
                }
            )
            if p5:
                tables[108] = (1, struct.pack("<4H", 0x1401, 8, 0, 0))
                case = bytearray(12)
                struct.pack_into("<2H", case, 0, 0x1401, 0x1501)
                tables[109] = (1, bytes(case))
            (root / "demo.ddb").write_bytes(authored_database(2, tables))
            profile = VehicleCatalog(root).build_profile(42)
            payload = bytes.fromhex("0203412a000000001234")
            replies = {
                bytes.fromhex("221421"): bytes.fromhex("621421a001"),
                bytes.fromhex("2214f0"): bytes.fromhex(
                    "6214f0000a" if p5 else "6214f00002"
                ),
                bytes.fromhex("2214b1"): bytes.fromhex("6214b100010009000000000001"),
                bytes.fromhex("221401"): bytes.fromhex("621401") + payload[:8],
                bytes.fromhex("221501"): bytes.fromhex("621501") + payload,
            }

            def bitmap(indices):
                raw = bytearray(32)
                for index in indices:
                    raw[index // 8] |= 0x80 >> (index % 8)
                return bytes(raw)

            replies[bytes.fromhex("220000")] = bytes.fromhex("620000") + bitmap(
                (20, 21)
            )
            replies[bytes.fromhex("221400")] = bytes.fromhex("621400") + bitmap(
                (0, 1, 239)
            )
            replies[bytes.fromhex("221500")] = bytes.fromhex("621500") + bitmap((0,))
            requests = []

            @dataclass
            class Reply:
                code: int
                data: bytes

            class Operations:
                request = b""
                log = requests
                memory = payload
                responses = replies

                def send(self, request, **kwargs):
                    self.request = request
                    self.log.append(request)
                    return 0

                def receive(self, **kwargs):
                    if self.request[0] == 0x27:
                        return Reply(0, bytes.fromhex("67010000"))
                    if self.request[0] == 0x91:
                        address = int.from_bytes(self.request[3:7], "big")
                        data = (self.memory + bytes(56))[
                            address : address + self.request[2]
                        ]
                        return Reply(0, b"\xd1" + self.request[1:] + data)
                    return Reply(0, self.responses[self.request])

                def close(self):
                    pass

            channel = NativeCommunication(
                profile, Operations(), "authored-ecu", bus_id=2
            )
            api = CommandAPI(CommandSource(18, SOURCE_SHA256[18]))
            report = (
                api.selected_ddr_p5_report(channel.cache)
                if p5
                else api.selected_ddr_report(channel)
            )
            self.assertEqual(len(report.information), 1)
            self.assertEqual(
                report.information[0].scalar_signals[0].samples, ((42, 1),)
            )
            layout = tse_reports._section_layout("DDRData", 0x272A, 0x1027)
            template = tse_reports.ReportSection(
                "DDRData", 0x272A, 0, 0x1027, (minimal(layout.item),)
            )
            saved = bind_ddr_report(template, report, encoding="ascii")
            wire = tse_reports.encode_section(saved)
            decoded = tse_reports.decode_section("DDRData", wire)
            self.assertEqual(decoded, saved)
            named = tse_reports.view_section(decoded, encoding="ascii")
            parameter = next(
                row
                for row in named["parameters"]
                if row["identifier_raw"] == 7 and row["values"]
            )
            self.assertEqual(parameter["name"], "RPM")
            self.assertEqual(parameter["values"][0]["raw"], 42)
            self.assertEqual(parameter["values"][0]["display"], "42")
            timeline = next(
                item
                for item in named["parameters"]
                if item["identifier_raw"] == 1001
                and item["values"]
                and item["values"][0]["raw"] == 18
            )
            self.assertTrue(timeline["native_channel_suppressed"])
            value = timeline["values"][0]
            self.assertEqual(value["invalidity_raw"], 1)
            self.assertTrue(value["invalidity_check"])
            self.assertEqual(value["flags_raw"], 0)
            self.assertEqual(value["stored_display"], "18")
            self.assertIsNone(value["display"])
            self.assertEqual(value["invalid_display_resource"], "DISPLAY_VALUE_INVALID")

            name = "p5" if p5 else "normal"
            self.pipeline_reports[name] = report
            self.pipeline_replies[name] = {
                "ram_payload_hex": payload.hex(),
                "security_reply_hex": "67010000",
                "responses_hex": {
                    request.hex(): response.hex()
                    for request, response in replies.items()
                },
            }
            self.pipeline_sections[name] = saved
            self.pipeline_requests[name] = [request.hex() for request in requests]
            self.pipeline_databases[name] = {
                filename: (root / filename).read_bytes()
                for filename in ("Toyota.ddb", "demo.ddb", "M_English.ddb")
            }
            expected = (
                [
                    "27010000",
                    "220000",
                    "221400",
                    "221500",
                    "2214f0",
                    "221401",
                    "221401",
                    "221501",
                ]
                if p5
                else [
                    "27030000",
                    "27010000",
                    "221421",
                    "2214f0",
                    "2214b1",
                    "91043800000000",
                    "91043800000000",
                ]
            )
            self.assertEqual(self.pipeline_requests[name], expected)
            self.assertEqual(report.information[0].timeline_main[0].samples, ((18, 1),))
            self.assertEqual(report.information[0].timeline_side[0].samples, ((52, 1),))
            if not p5:
                internal_operations = Operations()
                internal_operations.log = []
                internal_channel = NativeCommunication(
                    profile, internal_operations, "authored-ecu", bus_id=2
                )
                internal = capture_ddr_attributes(
                    internal_channel.cache, saved_log=True, internal_image=True
                )
                self.assertEqual(internal.group_count, 0)
                self.assertEqual(
                    [request.hex() for request in internal_operations.log],
                    ["27030000", "27010000", "221421", "2214f0"],
                )
                self.assertNotIn(101, dict(internal.observations))
                with self.assertRaises(ValueError):
                    capture_ddr_attributes(internal_channel.cache, internal_image=True)

    def test_p5_attribute_exact45_order_selected_DID_group_and_shared_TEMP(self):
        from scripts.monitor_support import TemporaryResponseCache

        rows = dict(self.management_rows)
        categories = bytearray(rows[16][1])
        categories[72] = 20
        rows[16] = (2, bytes(categories))
        functions = bytearray(rows[18][1])
        struct.pack_into("<H", functions, len(functions) - 16, 42)
        rows[18] = (7, bytes(functions))
        attrs = []
        for logical in (118, 177, 208, 209, 211, 212, 214, 215):
            row = bytearray(44)
            struct.pack_into("<4H", row, 16, logical, 42, 0, 15)
            struct.pack_into("<H", row, 34, 0x1401)
            row[38:40] = bytes((2, 0xAB))
            attrs.append(bytes(row))
        rows[54] = (len(attrs), b"".join(attrs))
        root = self.profile.catalog.root
        (root / "Toyota.ddb").write_bytes(authored_database(1, rows))
        profile = VehicleCatalog(root).build_profile(42)
        plan = initial_ddr_p5_attribute_plan(profile)
        self.assertEqual(len(plan.slots), 45)
        self.assertTrue(plan.p5)
        self.assertEqual(
            tuple(row.logical_id for row in plan.slots[:7]),
            (118, 101, 102, 103, 170, 171, 177),
        )
        self.assertEqual(plan.slots[0].initial_pid, 0x1401)
        for spec, disabled in (
            (10, (208, 209, 211, 212, 214, 215)),
            (13, (211, 212, 214, 215)),
            (14, (214, 215)),
            (15, ()),
        ):
            selected = plan.for_specification(spec)
            self.assertEqual(
                tuple(row.logical_id for row in selected.slots if not row.enabled),
                disabled,
            )
        calls = []
        cache = MonitorSupportCache(
            profile,
            lambda query: calls.append(query.request) or bytes.fromhex("621401000a"),
            "authored-ecu",
            bus_id=2,
        )
        instances: dict[int, TemporaryResponseCache] = {}
        self.assertEqual(plan.read_one(cache, 118, temporary_instances=instances), 10)
        selected = plan.for_specification(10)
        selected, observations = selected.read_group(
            cache, 0x1401, temporary_instances=instances
        )
        self.assertEqual(observations, ((118, 10), (177, 10)))
        self.assertEqual(calls, [bytes.fromhex("221401")])
        # A separate native command instance must issue a new exchange.
        self.assertEqual(selected.read_one(cache, 118, temporary_instances={}), 10)
        self.assertEqual(len(calls), 2)
        with self.assertRaises(ToyotaCodecError):
            plan.for_specification(2)

    def test_p5_time_BCD_conversion_ranges_first_only_and_flag_preservation(self):
        samples = tuple(
            DdrValueSeries(identifier, 1, ((raw, flag), (99, 0)))
            for identifier, raw, flag in (
                (111, 0x38, 1),
                (112, 0x12, 2),
                (113, 0, 0),
                (114, 0x24, 1),
                (115, 0x5A, 0),
                (116, 0x59, 0),
                (111, 0x39, 0),
            )
        )
        result = apply_ddr_p5_time_values(samples)
        self.assertEqual(
            [row.samples[0] for row in result],
            [(38, 1), (12, 2), (0, 2), (0x24, 2), (0x5A, 2), (59, 0), (0x39, 0)],
        )
        self.assertTrue(all(row.samples[1] == (99, 0) for row in result))
        self.assertEqual(samples[0].samples[0], (0x38, 1))
        with self.assertRaises(ToyotaCodecError):
            apply_ddr_p5_time_values((DdrValueSeries(111, 1, ()),))

    def test_native_marker_numbering_pair_existence_and_legacy_ranges(self):
        plan = selected_ddr_record_plan(self.profile, 2, bytes.fromhex("0203"))
        trigger = bytearray(plan.trigger_record)
        struct.pack_into("<HHH", trigger, 16, 0, 0, 2)
        record = DdrRecordSamples(
            b"\x02\x03", replace(plan, trigger_record=bytes(trigger)), ()
        )
        rows = (
            DdrValueSeries(19, 1, ((0, 0),)),
            DdrValueSeries(37, 1, ((0x102, 0),)),
            DdrValueSeries(38, 1, ((0x203, 0),)),
            DdrValueSeries(1001, 2, tuple((index, 0) for index in range(12))),
        )
        queries = []
        with patch.object(
            type(self.profile),
            "ddr_records",
            side_effect=lambda *args: queries.append(args) or (),
        ):
            out = apply_ddr_marker_flags(self.profile, record, rows)
        self.assertEqual(queries, [(plan.table_slots[1], 2, 3)])
        # Ten repeated ID19 marker rows occupy ten timeline positions.
        self.assertEqual([flag for _, flag in out[3].samples], [1] * 10 + [0, 0])
        self.assertEqual(out[1].samples, ((0x102, 2),))
        self.assertEqual(out[2].samples, ((0x203, 2),))
        with self.assertRaises(ToyotaCodecError):
            apply_ddr_marker_flags(
                self.profile,
                record,
                rows[:-1] + (replace(rows[-1], samples=((0, 0),)),),
            )
        struct.pack_into("<HHH", trigger, 16, 2, 1, 1)
        record = replace(record, plan=replace(plan, trigger_record=bytes(trigger)))
        legacy = (
            DdrValueSeries(18, 1, ((0x55, 0),)),
            DdrValueSeries(19, 1, ((0, 0),)),
            DdrValueSeries(20, 1, ((0, 0),)),
            DdrValueSeries(1001, 2, ((7, 0), (8, 0), (9, 0), (10, 0))),
        )
        out = apply_ddr_marker_flags(self.profile, record, legacy)
        self.assertEqual(out[-1].samples, ((7, 0), (8, 1), (9, 1), (10, 1)))
        self.assertEqual(
            apply_ddr_marker_flags(
                self.profile, record, (DdrValueSeries(17, 1, ((0, 0),)),) + legacy
            )[-1],
            legacy[-1],
        )

    def test_native_invalid_conditions_chain_flags_reference_and_id13_limit(self):
        plan = selected_ddr_record_plan(self.profile, 2, bytes.fromhex("0203"))

        def condition(expected, current, reference, chain=1, comparison=1):
            return struct.pack(
                "<IHHI4B", expected, current, reference, 0, chain, comparison, 0, 0
            )

        rows = (
            DdrValueSeries(7, 2, ((9, 0), (8, 0), (9, 1))),
            DdrValueSeries(8, 1, ((4, 0),)),
            DdrValueSeries(13, 1, ((1000000, 0),)),
            DdrValueSeries(13, 1, ((1000001, 0),)),
        )
        conditions = {
            7: (
                condition(9, 7, 7),
                condition(4, 7, 8, 2),
                condition(999, 7, 999, 2),
            )
        }
        with patch.object(
            type(self.profile),
            "ddr_records",
            side_effect=lambda slot, key: conditions.get(key, ()),
        ):
            out = apply_ddr_invalid_conditions(self.profile, plan, rows)
        self.assertEqual(out[0].samples, ((9, 2), (8, 0), (9, 1)))
        self.assertEqual(out[2].samples, ((1000000, 2),))
        self.assertEqual(out[3].samples, ((1000001, 0),))
        self.assertEqual(rows[0].samples, ((9, 0), (8, 0), (9, 1)))
        for reference in (DdrValueSeries(8, 2, ((4, 0),)), DdrValueSeries(8, 1, ())):
            with (
                patch.object(
                    type(self.profile),
                    "ddr_records",
                    return_value=(condition(4, 7, 8),),
                ),
                self.assertRaises(ToyotaCodecError),
            ):
                apply_ddr_invalid_conditions(self.profile, plan, (rows[0], reference))
        with (
            patch.object(
                type(self.profile),
                "ddr_records",
                return_value=(condition(4, 7, 8, comparison=3),),
            ),
            self.assertRaises(ToyotaCodecError),
        ):
            apply_ddr_invalid_conditions(self.profile, plan, rows)
        with self.assertRaises(Cancelled):
            apply_ddr_invalid_conditions(self.profile, plan, (), cancelled=lambda: True)
        with self.assertRaises(ValueError):
            apply_ddr_invalid_conditions(
                self.profile, replace(plan, category=999), rows
            )
        for pairs in (((True, 0),), ((-1, 0),), ((0, 0x100000000),)):
            with self.assertRaises(ValueError):
                DdrValueSeries(7, 1, pairs)

    def test_native_invalid_pending_queue_propagates_exact_indices_and_scalar_scope(
        self,
    ):
        plan = selected_ddr_record_plan(self.profile, 2, bytes.fromhex("0203"))

        def condition(current, reference, chain=2):
            return struct.pack("<IHHI4B", 0, current, reference, 0, chain, 1, 0, 0)

        conditions = {1002: (condition(1002, 1001),), 1003: (condition(1003, 1002),)}
        rows = (
            DdrValueSeries(1001, 2, ((10, 0), (11, 2))),
            DdrValueSeries(1002, 2, ((20, 0), (21, 0))),
            DdrValueSeries(1003, 2, ((30, 0), (31, 0))),
        )
        with (
            patch.object(
                type(self.profile), "records", return_value=sum(conditions.values(), ())
            ),
            patch.object(
                type(self.profile),
                "ddr_records",
                side_effect=lambda slot, key: conditions.get(key, ()),
            ),
        ):
            out = propagate_ddr_invalid_flags(self.profile, plan, rows)
        self.assertEqual(
            [row.samples for row in out],
            [
                ((10, 0), (11, 2)),
                ((20, 0), (21, 2)),
                ((30, 0), (31, 2)),
            ],
        )
        scalar_rows = (
            DdrValueSeries(7, 1, ((9, 2),)),
            DdrValueSeries(1002, 2, ((20, 0), (21, 1))),
        )
        with (
            patch.object(
                type(self.profile), "records", return_value=(condition(1002, 7),)
            ),
            patch.object(
                type(self.profile),
                "ddr_records",
                side_effect=lambda slot, key: (
                    (condition(1002, 7),) if key == 1002 else ()
                ),
            ),
        ):
            self.assertEqual(
                propagate_ddr_invalid_flags(self.profile, plan, scalar_rows)[1].samples,
                ((20, 2), (21, 2)),
            )
        with (
            patch.object(type(self.profile), "records", return_value=()),
            self.assertRaises(ToyotaCodecError),
        ):
            propagate_ddr_invalid_flags(self.profile, plan, rows)
        with (
            patch.object(
                type(self.profile), "records", return_value=(condition(1002, 1001),)
            ),
            self.assertRaises(Cancelled),
        ):
            propagate_ddr_invalid_flags(self.profile, plan, (), cancelled=lambda: True)

    def test_record_scheduler_runs_selected_native_communication_and_sorts_raw_keys(
        self,
    ):
        root = self.profile.catalog.root
        monitors = self.profile.records(50)
        monitor10 = bytearray(monitors[0])
        struct.pack_into("<H", monitor10, 24, 10)
        addresses = self.profile.records(52)
        address10 = bytearray(addresses[2])
        struct.pack_into("<IH", address10, 0, 7, 10)
        (root / "demo.ddb").write_bytes(
            authored_database(
                2,
                {
                    10: (0, b""),
                    50: (2, monitors[0] + bytes(monitor10)),
                    51: (1, self.profile.records(51)[0]),
                    52: (5, b"".join(addresses[:3]) + bytes(address10) + addresses[3]),
                    53: (0, b""),
                },
            )
        )
        profile = VehicleCatalog(root).build_profile(42)
        attributes = DdrAttributeCapture(
            initial_ddr_attribute_plan(profile),
            ((101, 1), (104, 0x1000), (105, 3)),
            2,
            1,
        )
        memory = {}
        for index, scalar in ((0, 0x20), (1, 0x20), (2, 0x10)):
            base = 0x1000 + (index << 16)
            memory.update(
                {
                    base: 2,
                    base + 1: 3,
                    base + 5: 0,
                    base + 6: scalar,
                    base + 7: 0,
                    base + 8: 0x30,
                }
            )

        @dataclass
        class Reply:
            code: int
            data: bytes

        class Operations:
            request = b""

            def send(self, request, **kwargs):
                self.request = request
                return 0

            def receive(self, **kwargs):
                address = int.from_bytes(self.request[3:7], "big")
                data = bytes(
                    memory.get(address + index, 0) for index in range(self.request[2])
                )
                return Reply(0, b"\xd1" + self.request[1:] + data)

            def close(self):
                pass

        channel = NativeCommunication(profile, Operations(), "authored-ecu", bus_id=2)
        with patch(
            "scripts.database_resources.capture_ddr_attributes", return_value=attributes
        ):
            capture = capture_ddr_records(channel)
        self.assertEqual([row.record_index for row in capture.records], [2, 1, 0])
        self.assertEqual(
            [[row.samples for row in item.series] for item in capture.records],
            [
                [((1, 1),), ((3, 1),)],
                [((2, 1),), ((3, 1),)],
                [((2, 1),), ((3, 1),)],
            ],
        )
        self.assertEqual(
            [item.query.frame.address for item in capture.transactions],
            [0xFF8, 0xFF8, 0x10FF8, 0x10FF8, 0x20FF8, 0x20FF8],
        )
        self.assertTrue(all(item.query.bus_id == 2 for item in capture.transactions))
        self.assertEqual(channel.cache.calls, 6)
        self.assertEqual(attributes.observations[-1], (105, 3))

    def test_bulk_scheduler_keeps_header_payload_unknown_header_wire_order(self):
        root = self.profile.catalog.root
        source = self.profile
        (root / "demo.ddb").write_bytes(
            authored_database(
                2,
                {
                    10: (0, b""),
                    **{
                        slot + 42: (
                            len(source.records(slot)),
                            b"".join(source.records(slot)),
                        )
                        for slot in (50, 51, 52, 53)
                    },
                },
            )
        )
        profile = VehicleCatalog(root).build_profile(42)
        attributes = DdrAttributeCapture(
            initial_ddr_attribute_plan(profile),
            ((101, 1), (104, 0x1FFE0), (170, 0xFFFF)),
            6,
            1,
        )
        cache = MonitorSupportCache(
            profile, lambda query: b"", "authored-ecu", bus_id=2
        )
        channel = create_autospec(NativeCommunication, instance=True)
        channel.profile, channel.cache = profile, cache
        channel.ecu, channel.bus_id, channel.source_build = "authored-ecu", 2, 18
        channel.limits, channel.clock, channel.cancelled = (
            cache.limits,
            cache.clock,
            cache.cancelled,
        )
        requests = []

        def exchange(query):
            requests.append(query.request)
            address = int.from_bytes(query.request[3:7], "big")
            data = bytearray(query.request[2])
            if address == 0x1FFE0:
                data[:2] = b"\x02\x03"
                data[5:7] = b"\x00\x10"
            return b"\xd1" + query.request[1:] + bytes(data)

        cache.exchange = exchange
        with patch(
            "scripts.database_resources.capture_ddr_attributes", return_value=attributes
        ):
            capture = capture_ddr_records(channel)
        self.assertEqual(
            [int.from_bytes(request[3:7], "big") for request in requests],
            [0x1FFE0, 0x1FFF8, 0x20008],
        )
        self.assertEqual(
            [item.query.frame.address for item in capture.transactions],
            [0x1FFE0, 0x1FFF8, 0x20008],
        )
        self.assertEqual(len(capture.records), 1)
        self.assertIsNone(capture.records[0].record_index)
        self.assertEqual(capture.records[0].series[0].samples, ((1, 1),))

    def test_saved_log_native_order_start_failure_and_error_precedence(self):
        from scripts.frame_transport import NativeFrameOperations
        from scripts.native_communication import ConnectionResult

        operations = create_autospec(NativeFrameOperations, instance=True)
        operations.native_build = 18
        channel = NativeCommunication(
            self.profile, operations, "authored-ecu", bus_id=2
        )
        attributes = DdrAttributeCapture(
            initial_ddr_attribute_plan(self.profile), (), 2, 0
        )
        result = DdrCapture(attributes, (), ())
        with TemporaryDirectory() as directory:
            log = DdrPacketLog(Path(directory), operations)
            events = []
            for start_status, acquisition_status, stop_status, expected in (
                (0, 0, 0, 0),
                (0x90020706, 0, 0, 0x90020706),
                (0, 0xA0041001, 0x90020706, 0xA0041001),
                (0, 0, 0x90020706, 0x90020706),
            ):
                events.clear()

                def acquire(*args, acquisition_status=acquisition_status, **kwargs):
                    events.append(("capture", kwargs["ecu_specific"]))
                    if acquisition_status:
                        raise NativeStatus(acquisition_status)
                    return result

                with (
                    patch.object(
                        log,
                        "start",
                        side_effect=lambda status=start_status: (
                            events.append("start") or status
                        ),
                    ),
                    patch.object(
                        log,
                        "stop",
                        side_effect=lambda status=stop_status: (
                            events.append("stop") or status
                        ),
                    ),
                    patch.object(
                        channel.cache,
                        "invalidate_a8",
                        side_effect=lambda kind: events.append(("invalidate", kind)),
                    ),
                    patch.object(
                        channel,
                        "connection_no_buffer",
                        side_effect=lambda: (
                            events.append("connect") or ConnectionResult(0, False, None)
                        ),
                    ),
                    patch(
                        "scripts.database_resources.capture_ddr_records",
                        side_effect=acquire,
                    ),
                ):
                    if expected:
                        with self.assertRaises(NativeStatus) as caught:
                            capture_ddr_records_saved_log(channel, log)
                        self.assertEqual(caught.exception.code, expected)
                    else:
                        self.assertIs(
                            capture_ddr_records_saved_log(channel, log), result
                        )
                self.assertEqual(
                    events[:4],
                    [
                        "start",
                        ("invalidate", 1),
                        "connect",
                        ("capture", (DdrEcuContext(42, 2),)),
                    ],
                )
                self.assertEqual(events[4:], [] if start_status else ["stop"])

    def test_saved_log_formatter_error_occurs_before_stop_and_retains_primary_status(
        self,
    ):
        from scripts.frame_transport import NativeFrameOperations
        from scripts.native_communication import ConnectionResult

        operations = create_autospec(NativeFrameOperations, instance=True)
        operations.native_build = 18
        channel = NativeCommunication(
            self.profile, operations, "authored-ecu", bus_id=2
        )
        result = DdrCapture(
            DdrAttributeCapture(initial_ddr_attribute_plan(self.profile), (), 2, 0),
            (),
            (),
        )
        events = []

        def formatting(*args, **kwargs):
            events.append(("format", kwargs["saved_log"]))
            raise NativeStatus(0xC0040101)

        with TemporaryDirectory() as directory:
            log = DdrPacketLog(Path(directory), operations)
            with (
                patch.object(log, "start", return_value=0),
                patch.object(
                    log, "stop", side_effect=lambda: events.append("stop") or 0x90020706
                ),
                patch.object(
                    channel,
                    "connection_no_buffer",
                    return_value=ConnectionResult(0, True, None),
                ),
                patch(
                    "scripts.database_resources.capture_ddr_records",
                    return_value=result,
                ),
                patch(
                    "scripts.database_resources.format_ddr_capture",
                    side_effect=formatting,
                ),
                self.assertRaises(NativeStatus) as caught,
            ):
                capture_ddr_saved_log(channel, log)
        self.assertEqual(caught.exception.code, 0xC0040101)
        self.assertEqual(events, [("format", True), "stop"])

    def test_p5_saved_log_disconnect_precedes_Stop_and_primary_status_survives(self):
        from scripts.native_communication import ConnectionResult, NativeFrameController
        from tests.test_frame_transport import (
            DriverPrimitive,
            native_operations,
            selected_profile,
        )

        attributes = DdrAttributeCapture(
            initial_ddr_p5_attribute_plan(self.profile), (), 10, 1
        )
        raw = DdrP5RawCapture(attributes, (), (), ())
        report = DdrP5Report(
            raw,
            (),
            None,
            None,
            DdrP5SupportValue(170, False, 0),
            DdrP5SupportValue(171, False, 0),
            (),
        )
        for start_status, body_status, stop_status, expected in (
            (0, 0, 0, 0),
            (0x90020706, 0, 0, 0x90020706),
            (0, 0, 0x90020706, 0x90020706),
            (0, 0xC0040101, 0x90020706, 0xC0040101),
        ):
            events = []
            controller_profile = selected_profile(2)
            backend = DriverPrimitive()
            controller = NativeFrameController(
                native_operations(backend, bus=2, profile=controller_profile)
            )
            channel = NativeCommunication(
                self.profile, controller, "authored-ecu", bus_id=2
            )

            def body(*args, events=events, body_status=body_status, **kwargs):
                events.append(("body", kwargs["ecu_specific"]))
                if body_status:
                    raise NativeStatus(body_status)
                return report

            with TemporaryDirectory() as directory:
                log = DdrPacketLog(Path(directory), controller)
                with (
                    patch.object(
                        log,
                        "start",
                        side_effect=lambda kind, events=events, start_status=start_status: (
                            events.append(("start", kind)) or start_status
                        ),
                    ),
                    patch.object(
                        log,
                        "stop",
                        side_effect=lambda events=events, stop_status=stop_status: (
                            events.append("stop") or stop_status
                        ),
                    ),
                    patch.object(
                        channel,
                        "connection_no_buffer",
                        side_effect=lambda events=events: (
                            events.append("connect") or ConnectionResult(0, True, None)
                        ),
                    ),
                    patch.object(
                        controller,
                        "disconnect",
                        side_effect=lambda flag, events=events, **kwargs: (
                            events.append(("disconnect", flag)) or 0x90020301
                        ),
                    ),
                    patch(
                        "scripts.database_resources.capture_ddr_p5_report",
                        side_effect=body,
                    ),
                    patch.object(channel.cache, "invalidate_a8") as invalidate,
                ):
                    if expected:
                        with self.assertRaises(NativeStatus) as caught:
                            capture_ddr_p5_saved_log(channel, log)
                        self.assertEqual(caught.exception.code, expected)
                    else:
                        self.assertIs(capture_ddr_p5_saved_log(channel, log), report)
                    invalidate.assert_not_called()
            self.assertEqual(
                events[:3], [("start", 2), "connect", ("body", (DdrEcuContext(42, 2),))]
            )
            self.assertEqual(
                events[3:], [("disconnect", 1)] + ([] if start_status else ["stop"])
            )

    def test_bulk_record_raw_cutoff_exact_mask_signed_wrap_and_presence(self):
        attributes = initial_ddr_attribute_plan(self.profile)
        plan = selected_ddr_record_plan(self.profile, 2, bytes.fromhex("0203"))
        record = DdrRecordSamples(
            bytes.fromhex("0203"), plan, ((7, b"\x0a", 10), (10, b"\x14", 20))
        )
        for observed, expected in (
            ({170: 0xFFFF}, True),
            ({170: 11, 171: 0}, False),
            ({170: 9, 171: 0}, True),
            ({170: 10, 171: 21}, False),
            ({170: 10, 171: 0xE0000013}, True),
            ({170: 0xFFFFFFFF, 171: 0}, True),
        ):
            self.assertEqual(
                ddr_bulk_record_eligible(attributes, observed, record), expected
            )
        disabled = replace(
            attributes,
            slots=tuple(
                replace(slot, enabled=False) if slot.logical_id == 170 else slot
                for slot in attributes.slots
            ),
        )
        self.assertTrue(ddr_bulk_record_eligible(disabled, {}, record))
        with self.assertRaises(ValueError):
            ddr_bulk_record_eligible(attributes, {170: 10}, record)
        with self.assertRaises(ValueError):
            ddr_bulk_record_eligible(
                replace(attributes, vehicle_sha256="changed"), {}, record
            )

    def test_actual_normal_attribute_chronology_and_legacy_policy(self):
        rows = dict(self.management_rows)
        ordinary = rows[54][1][:44]
        attributes = bytearray()
        for logical, pid, first, last in (
            (101, 0xB1, 0, 15),
            (102, 0xB1, 0, 15),
            (118, 0x22, 0, 15),
            (136, 0x21, 8, 15),
            (137, 0x21, 0, 7),
        ):
            row = bytearray(ordinary)
            struct.pack_into("<4H", row, 16, logical, 42, first, last)
            row[39] = pid
            attributes += row
        rows[54] = (5, bytes(attributes))
        root = self.profile.catalog.root
        (root / "Toyota.ddb").write_bytes(authored_database(1, rows))
        profile = VehicleCatalog(root).build_profile(42)
        calls = []

        def exchange(query):
            calls.append(query.request)
            if query.request[0] == 0x27:
                return b"\x67" + query.request[1:2] + b"\0\0"
            return {
                b"\x21\x21": bytes.fromhex("612103a0"),
                b"\x21\x22": bytes.fromhex("61220002"),
                b"\x21\xb1": bytes.fromhex("61b10001"),
            }[query.request]

        cache = MonitorSupportCache(profile, exchange, "authored", clock=lambda: 0.0)
        with patch.object(
            cache,
            "support_bits",
            return_value={
                0x21: b"\1\1",
                0x22: b"\1\1",
                0xB1: b"\1\0",
            },
        ):
            result = capture_ddr_attributes(cache)
        self.assertEqual(
            calls,
            [
                bytes.fromhex(item)
                for item in (
                    "27030000",
                    "27010000",
                    "2121",
                    "2122",
                    "21b1",
                )
            ],
        )
        self.assertEqual(result.spec_value, 2)
        self.assertEqual(result.group_count, 1)
        self.assertEqual(
            result.observations, ((137, 3), (136, 0xA0), (118, 2), (101, 1), (102, 1))
        )
        self.assertTrue(result.plan.group_supported(0xB1))
        self.assertEqual(
            [slot.logical_id for slot in result.plan.slots if slot.less_a8], [101, 102]
        )
        cache = MonitorSupportCache(
            profile, exchange, "authored", clock=lambda: 0.0, limits=Limits(exchanges=2)
        )
        before = len(calls)
        with self.assertRaises(SessionError):
            capture_ddr_attributes(cache)
        self.assertEqual(len(calls) - before, 2)

    def test_saved_log_attribute_temp_is_shared_across_native_phases_only(self):
        rows = dict(self.management_rows)
        ordinary = rows[54][1][:44]
        attributes = bytearray()
        for logical, pid, first, last in (
            (101, 0xB1, 0, 15),
            (102, 0xB1, 0, 15),
            (118, 0xB1, 0, 15),
            (136, 0x21, 8, 15),
            (137, 0x21, 0, 7),
        ):
            row = bytearray(ordinary)
            struct.pack_into("<4H", row, 16, logical, 42, first, last)
            row[39] = pid
            attributes += row
        rows[54] = (5, bytes(attributes))
        root = self.profile.catalog.root
        (root / "Toyota.ddb").write_bytes(authored_database(1, rows))
        profile = VehicleCatalog(root).build_profile(42)
        calls = []

        def exchange(query):
            calls.append(query.request)
            if query.request[0] == 0x27:
                return b"\x67" + query.request[1:2] + b"\0\0"
            return {
                b"\x21\x21": bytes.fromhex("612103a0"),
                b"\x21\xb1": bytes.fromhex("61b10002"),
            }[query.request]

        for saved, expected in ((False, 2), (True, 1)):
            calls.clear()
            cache = MonitorSupportCache(
                profile, exchange, "authored", clock=lambda: 0.0
            )
            with patch.object(
                cache, "support_bits", return_value={0x21: b"\1\1", 0xB1: b"\1\1"}
            ):
                result = capture_ddr_attributes(cache, saved_log=saved)
                self.assertEqual(result.group_count, 2)
                self.assertEqual(calls.count(bytes.fromhex("21b1")), expected)
                # A second saved-log invocation constructs another native local TEMP.
                if saved:
                    capture_ddr_attributes(cache, saved_log=True)
                    self.assertEqual(calls.count(bytes.fromhex("21b1")), 2)

    def test_attribute_phase_rejects_unproven_build_before_preparation(self):
        calls = []
        cache = MonitorSupportCache(
            self.profile,
            lambda query: (calls.append(query), b"")[1],
            "authored",
            source_build=12,
        )
        with self.assertRaises(ValueError):
            capture_ddr_attributes(cache)
        self.assertEqual(calls, [])
        cache = MonitorSupportCache(
            self.profile, lambda query: (calls.append(query), b"")[1], "authored"
        )
        with self.assertRaises(ValueError):
            capture_ddr_attributes(cache, ecu_specific=("invalid",))  # type: ignore[arg-type]
        self.assertEqual(calls, [])

    def test_native_specification_presence_dispatch_is_separate_from_support(self):
        plan = initial_ddr_attribute_plan(self.profile)
        for spec in (2, 3, 5):
            disabled = plan.for_specification(spec)
            self.assertFalse(
                next(slot for slot in disabled.slots if slot.logical_id == 170).enabled
            )
            self.assertFalse(
                next(slot for slot in disabled.slots if slot.logical_id == 171).enabled
            )
            self.assertTrue(
                next(slot for slot in disabled.slots if slot.logical_id == 118).enabled
            )
        self.assertTrue(all(slot.enabled for slot in plan.for_specification(6).slots))
        for spec in (0, 4, 10, 13, True):
            with self.assertRaises(ToyotaCodecError) as caught:
                plan.for_specification(spec)
            self.assertEqual(caught.exception.code, 0xA0041001)

    def test_native12_internal_schema_specs_and_support_selection_are_distinct(self):
        from types import SimpleNamespace

        from scripts.profiles import VehicleProfile

        profile12 = replace(
            self.profile,
            database=replace(self.profile.database, version=0x0100030C),
        )
        plan = initial_ddr_attribute_plan(profile12)
        self.assertEqual(plan.source_build, 12)
        for spec in (6, 7, 8):
            selected = plan.for_specification(spec)
            self.assertTrue(
                next(slot for slot in selected.slots if slot.logical_id == 170).enabled
            )
            self.assertTrue(
                next(slot for slot in selected.slots if slot.logical_id == 171).enabled
            )
        disabled = plan.for_specification(2)
        self.assertFalse(
            next(slot for slot in disabled.slots if slot.logical_id == 170).enabled
        )
        self.assertFalse(
            next(slot for slot in disabled.slots if slot.logical_id == 171).enabled
        )
        for spec in (9, 11, 12):
            with self.assertRaises(ToyotaCodecError):
                plan.for_specification(spec)

        row = bytearray(self.management_rows[54][1][:44])
        struct.pack_into("<H", row, 24, 9)
        other = bytearray(row)
        struct.pack_into("<H", other, 24, 10)
        last = bytearray(row)
        struct.pack_into("<H", last, 24, 11)
        category = bytearray(self.profile.category_record)
        category[72] = 20
        cache = MonitorSupportCache(
            profile12, lambda query: b"", "native12", source_build=12
        )
        with (
            patch.object(
                VehicleProfile,
                "comm_pid_records",
                return_value=(bytes(row), bytes(other), bytes(last)),
            ),
            patch.object(
                VehicleProfile,
                "category_records",
                return_value=(bytes(category),),
            ),
            patch.object(
                cache,
                "get_comm_support_bit",
                side_effect=(
                    ToyotaCodecError("skip candidate", 0x90020323),
                    SimpleNamespace(supported=True),
                    SimpleNamespace(supported=True),
                ),
            ) as support,
        ):
            selected = select_comm_pid_target(cache, 101)
        self.assertIsNotNone(selected)
        assert selected is not None
        self.assertEqual(selected.record, bytes(other))
        self.assertEqual([item.args[0] for item in support.call_args_list], [9, 10])
        support.assert_any_call(
            9, connections=None, temporary=False, force=False, with_value=False
        )
        with (
            patch.object(
                VehicleProfile,
                "comm_pid_records",
                return_value=(bytes(row),),
            ),
            patch.object(
                VehicleProfile,
                "category_records",
                return_value=(bytes(category),),
            ),
            patch.object(
                cache,
                "get_comm_support_bit",
                side_effect=AssertionError("bus-mismatched row must be skipped"),
            ),
        ):
            self.assertIsNone(
                select_comm_pid_target(cache, 101, ecu_specific=(DdrEcuContext(42, 8),))
            )

        invalid = bytearray(category)
        invalid[72] = 52
        with (
            patch.object(
                VehicleProfile,
                "comm_pid_records",
                return_value=(bytes(row),),
            ),
            patch.object(
                VehicleProfile,
                "category_records",
                return_value=(bytes(invalid),),
            ),
            patch.object(
                cache,
                "get_comm_support_bit",
                side_effect=AssertionError("native12 kind52 must reject pre-query"),
            ),
            self.assertRaises(ToyotaCodecError),
        ):
            select_comm_pid_target(cache, 101)

        with self.assertRaises(NotImplementedError):
            capture_ddr_attributes(cache, saved_log=True)

    def test_native12_less_a8_uses_literal_non_byte_aligned_bits(self):
        from scripts.profiles import VehicleProfile

        profile12 = replace(
            self.profile,
            database=replace(self.profile.database, version=0x0100030C),
        )
        row = bytearray(self.management_rows[54][1][:44])
        struct.pack_into("<4H", row, 16, 101, 42, 3, 10)
        row[39] = 0xB1
        attribute = DdrAttribute(
            101,
            bytes(row),
            profile12.category_record,
            profile12.catalog.management.sha256,
            profile12.exception_ids,
            less_a8=True,
        )
        calls = []

        def exchange(query):
            calls.append(query)
            return b"\x61\xb1\xb2\x6c"

        cache = MonitorSupportCache(profile12, exchange, "native12", source_build=12)
        with patch.object(
            VehicleProfile, "comm_pid_records", return_value=(bytes(row),)
        ):
            self.assertEqual(attribute.read(cache), 0x93)
        self.assertEqual(calls[0].request, b"\x21\xb1")
        self.assertEqual(calls[0].native_parameter, 7)

    def test_required_flags_are_separate_from_observed_legacy_less_a8_override(self):
        initial = initial_ddr_attribute_plan(self.profile)
        self.assertTrue(all(not slot.less_a8 for slot in initial.slots))
        self.assertFalse(initial.group_supported(0xB1))
        self.assertFalse(initial.group_supported(0xB2))
        self.assertIs(initial.with_legacy_group_override(3), initial)
        self.assertIs(initial.with_legacy_group_override(2, 0), initial)
        with self.assertRaises(ValueError):
            initial.with_legacy_group_override(2)
        legacy = initial.with_legacy_group_override(2, 3)
        self.assertTrue(legacy.group_supported(0xB1))
        self.assertEqual(
            [slot.logical_id for slot in legacy.slots if slot.less_a8], [102]
        )
        cache = MonitorSupportCache(
            self.profile, lambda query: bytes.fromhex("61b1a5f0"), "authored-ecu"
        )
        with patch.object(cache, "support_bits", return_value={0xB1: b"\x01\x00"}):
            _, ordinary = initial.read_group(cache, 0xB1)
            _, direct = legacy.read_group(cache, 0xB1)
        self.assertEqual(ordinary, ((102, 0xA500),))
        self.assertEqual(direct, ((102, 0xA5F0),))

    def test_selected_db136_db130_to_actual_mapped_native_target_and_fault_budget(self):
        @dataclass
        class Reply:
            code: int
            data: bytes

        class Operations:
            def __init__(self):
                self.calls = []
                self.replies = [
                    Reply(0, bytes.fromhex("62123400")),
                    Reply(0, bytes.fromhex("625678abcd")),
                ]
                self.status = 0

            def send(self, request, **kwargs):
                self.calls.append(("send", request, kwargs))
                return self.status

            def receive(self, **kwargs):
                self.calls.append(("receive", kwargs))
                return self.replies.pop(0)

            def close(self):
                pass

        target_profile = self.profile.catalog.build_profile(43)
        operations = Operations()
        target = NativeCommunication(
            target_profile, operations, "target43", bus_id=2, clock=lambda: 0.0
        )
        parent = MonitorSupportCache(
            self.profile,
            lambda query: self.fail("source ECU must not perform target I/O"),
            "source42",
            bus_id=7,
            clock=lambda: 0.0,
            limits=Limits(exchanges=5),
        )
        selected = select_comm_pid_target(
            parent,
            143,
            connections={(43, 2): target},
            ecu_specific=(DdrEcuContext(42, 7), DdrEcuContext(43, 2)),
        )
        assert selected is not None
        self.assertEqual(int.from_bytes(selected.record[18:20], "little"), 43)
        with parent.target_operation(target):
            self.assertEqual(selected.read(target.cache), 0xABCD)
        self.assertEqual(
            [entry[1] for entry in operations.calls if entry[0] == "send"],
            [bytes.fromhex("221234"), bytes.fromhex("225678")],
        )
        self.assertEqual(parent.calls, 4)
        target.cache.begin_operation()
        operations.status = 0x90020322
        with (
            parent.target_operation(target),
            self.assertRaises(ToyotaCodecError) as caught,
        ):
            selected.read(target.cache)
        self.assertEqual(caught.exception.code, 0x90020322)
        self.assertEqual(parent.calls, 5)
        before = len(operations.calls)
        with self.assertRaises(SessionError), parent.target_operation(target):
            selected.read(target.cache)
        self.assertEqual(len(operations.calls), before)

    def test_actual_attribute_plan_preserves_presence_support_and_group_cache(self):
        calls = []

        def exchange(query):
            calls.append(query)
            return bytes.fromhex("6177a5f0")

        cache = MonitorSupportCache(self.profile, exchange, "authored-ecu")
        initial = initial_ddr_attribute_plan(self.profile)
        self.assertEqual(len(initial.slots), 41)
        self.assertEqual(
            [slot.logical_id for slot in initial.slots if slot.candidates],
            [101, 102, 118, 170, 171],
        )
        with self.assertRaises(ToyotaCodecError) as caught:
            initial.validate_required()
        self.assertEqual(caught.exception.code, 0xA0041001)
        selected = initial.check_support(cache, ecu_specific=(DdrEcuContext(42, 7),))
        selected.validate_required()
        with patch.object(cache, "support_bits", return_value={0x77: b"\x01\x01"}):
            after, values = selected.read_group(cache, 0x77)
            self.assertEqual(values, ((101, 0xA5F0), (118, 0xA5F0)))
            self.assertEqual(len(calls), 1)
            self.assertEqual(after.read_one(cache, 118), 0xA5F0)
            self.assertEqual(len(calls), 2)
        unsupported = replace(initial.slots[0], initial_pid=0xB2)
        plan = replace(initial, slots=(unsupported,))
        disabled, values = plan.read_group(cache, 0xB2)
        self.assertEqual(values, ())
        self.assertFalse(disabled.slots[0].enabled)
        self.assertEqual(len(calls), 2)
        # An unsupported ordinary group still reads native index zero.
        plan = replace(initial, slots=(initial.slots[0],))
        with patch.object(cache, "support_bits", return_value={0x77: b"\x01\x01"}):
            _, values = plan.read_group(cache, 0x77)
        self.assertEqual(values, ((101, 0xA5F0),))
        self.assertEqual(len(calls), 3)
        with self.assertRaises(ValueError):
            replace(initial, management_sha256="changed").read_group(cache, 0x77)

    def test_native_target_selection_and_normal_attribute_share_selected_decoder(self):
        calls = []

        def transaction(query):
            calls.append(query)
            return bytes.fromhex("6177a5")

        cache = MonitorSupportCache(self.profile, transaction, "authored-ecu")
        attribute = select_ddr_attribute(cache, 101)
        assert attribute is not None
        with patch.object(cache, "support_bits", return_value={0x77: b"\x01\x00"}):
            self.assertEqual(attribute.read(cache), 0xA500)
            self.assertEqual(attribute.read(cache), 0xA500)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].request, bytes.fromhex("2177"))
        self.assertEqual(calls[0].native_parameter, 7)
        with self.assertRaises(ValueError):
            replace(attribute, management_sha256="changed").read(cache)
        cache.begin_operation()
        with (
            patch.object(cache, "support_bits", return_value={0x77: b"\xff"}),
            self.assertRaises(ToyotaCodecError),
        ):
            attribute.read(cache)
        self.assertIsNotNone(
            select_ddr_attribute(cache, 101, ecu_specific=(DdrEcuContext(42, 7),))
        )
        self.assertIsNone(
            select_ddr_attribute(cache, 101, ecu_specific=(DdrEcuContext(42, 263),))
        )
        self.assertIsNone(
            select_ddr_attribute(cache, 101, ecu_specific=(DdrEcuContext(65578, 7),))
        )
        with self.assertRaises(ValueError):
            DdrEcuContext(42, 65536)
        selected = attribute.record
        unsupported = bytearray(selected)
        struct.pack_into("<H", unsupported, 24, 9)
        with patch.object(
            type(self.profile),
            "comm_pid_records",
            return_value=(bytes(unsupported), selected),
        ):
            with patch.object(
                cache,
                "get_comm_support_bit",
                side_effect=ToyotaCodecError("observed", 0x90020323),
            ) as support:
                result = select_ddr_attribute(cache, 101)
                assert result is not None
                self.assertEqual(result.record, selected)
                support.assert_called_once_with(
                    9, connections=None, temporary=False, force=False, with_value=False
                )
            with (
                patch.object(
                    cache, "get_comm_support_bit", side_effect=Cancelled("cancelled")
                ),
                self.assertRaises(Cancelled),
            ):
                select_ddr_attribute(cache, 101)
        target = bytearray(attribute.category_record)
        target[72] = 20
        with (
            patch.object(
                type(self.profile),
                "comm_pid_records",
                return_value=(bytes(unsupported),),
            ),
            patch.object(
                type(self.profile), "category_records", return_value=(bytes(target),)
            ),
            patch.object(
                cache,
                "get_comm_support_bit",
                side_effect=AssertionError("native DDR type20 bypass must not query"),
            ),
        ):
            bypassed = select_ddr_attribute(cache, 101)
            assert bypassed is not None
            self.assertEqual(bypassed.category_record[72], 20)
        target[72] = 2
        with patch.object(
            type(self.profile), "category_records", return_value=(bytes(target),)
        ):
            with self.assertRaises(ToyotaCodecError) as caught:
                select_ddr_attribute(cache, 101)
            self.assertEqual(caught.exception.code, 0xC0040102)
        less = select_ddr_attribute(cache, 118)
        assert less is not None
        cache.begin_operation()
        cache.exchange = lambda query: bytes.fromhex("6177a5f0")
        self.assertFalse(less.less_a8)
        with patch.object(cache, "support_bits", return_value={0x77: b"\x01\x00"}):
            self.assertEqual(less.read(cache), 0xA500)

    def test_less_a8_selected_attribute_uses_shared_exact_cache_without_expansion(self):
        attribute = selected_ddr_less_a8_attribute(self.profile, 102)
        self.assertIsNotNone(attribute)
        assert attribute is not None
        calls = []

        def transaction(query):
            calls.append(query)
            return bytes.fromhex("61b1a5f0")

        cache = MonitorSupportCache(self.profile, transaction, "authored-ecu")
        self.assertEqual(attribute.read(cache), 0xA5F0)
        self.assertEqual(attribute.read(cache), 0xA5F0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].request, bytes.fromhex("21b1"))
        self.assertEqual(calls[0].native_parameter, 7)
        cache.transaction(attribute.selected, attribute.request)
        self.assertEqual(len(calls), 2)
        cache.begin_operation()
        self.assertEqual(attribute.read(cache), 0xA5F0)
        self.assertEqual(len(calls), 3)
        self.assertIsNone(selected_ddr_less_a8_attribute(self.profile, 137))
        for logical in (101, 118):
            with self.assertRaises(ValueError):
                selected_ddr_less_a8_attribute(self.profile, logical)
        with self.assertRaises(ToyotaCodecError) as caught:
            attribute.decode(bytes.fromhex("61b1a5"))
        self.assertEqual(caught.exception.code, 0xA0040202)

    def test_native_communication_factory_runs_selected_send_receive_and_records_bus(
        self,
    ):
        @dataclass
        class Reply:
            code: int
            data: bytes

        class Operations:
            def __init__(self):
                self.request = b""
                self.calls = []
                self.reply_code = 0

            def send(self, request, **kwargs):
                self.request = request
                self.calls.append((request, kwargs))
                return 0

            def receive(self, **kwargs):
                if self.reply_code:
                    return Reply(code=self.reply_code, data=b"partial")
                data = bytes(range(self.request[2]))
                return Reply(code=0, data=b"\xd1" + self.request[1:] + data)

            def close(self):
                pass

        operations = Operations()
        communication = NativeCommunication(
            self.profile, operations, "authored-ecu", bus_id=2
        )
        reader = NativeRamReader.from_communication(
            communication, frame=self.frame, block_size=24
        )
        self.assertEqual(reader.read(0x1000, 3, real=True), bytes.fromhex("000102"))
        self.assertEqual(operations.calls[0][0], bytes.fromhex("91a50300001000"))
        self.assertEqual(operations.calls[0][1]["timeout"], 0x11223344)
        self.assertEqual(reader.transactions[0].query.bus_id, 2)
        raw = encode_ram_recording(reader, source="authored_synthetic")
        replay = RamReplay(self.profile, raw)
        self.assertEqual(replay.reader.bus_id, 2)
        self.assertEqual(
            replay.reader.read(0x1000, 3, real=True), bytes.fromhex("000102")
        )
        replay.assert_complete()
        operations.reply_code = 0x90020321
        failed = NativeRamReader.from_communication(
            communication, frame=self.frame, block_size=24
        )
        with self.assertRaises(NativeStatus) as caught:
            failed.read(0x2000, 1, real=True)
        self.assertEqual(caught.exception.reply, b"partial")
        self.assertEqual(failed.transactions[0].status, 0x90020321)

    def test_literal_native_request_and_response_echo(self):
        request = ram_request(bytes.fromhex("91000000000000"), self.frame, 3)
        self.assertEqual(request, bytes.fromhex("91a50312345678"))
        self.assertEqual(
            ram_payload(request, bytes.fromhex("d1a5031234567800ff80")),
            bytes.fromhex("00ff80"),
        )
        for offset in range(7):
            bad = bytearray(bytes.fromhex("d1a5031234567800ff80"))
            bad[offset] ^= 1
            with self.assertRaises(ToyotaCodecError) as caught:
                ram_payload(request, bytes(bad))
            self.assertEqual(caught.exception.code, 0xA0040201)

    def test_selected_ddb_cached_alignment_and_byte_exact_output(self):
        reader = self.reader()
        data = reader.read(0x12345678, 30)
        self.assertEqual(
            [q.frame.address for q in self.calls], [0x12345670, 0x12345688]
        )
        self.assertEqual(data, bytes(range(0x78, 0x96)))
        self.assertEqual(
            self.calls[0].selected.function_record[:4], bytes.fromhex("2a00a100")
        )
        self.assertEqual(
            self.calls[0].selected.settings_record[:4], bytes.fromhex("44332211")
        )
        self.assertIn(
            self.profile.catalog.management.sha256, self.calls[0].selected.provenance
        )
        self.assertEqual(reader.read(0x1234567A, 4), bytes.fromhex("7a7b7c7d"))
        self.assertEqual(len(self.calls), 2)

    def test_real_read_bypasses_cache_and_trims_last_chunk(self):
        reader = self.reader()
        self.assertEqual(
            reader.read(0x12345678, 30, real=True), bytes(range(0x78, 0x96))
        )
        self.assertEqual(
            [(q.frame.address, q.request[2]) for q in self.calls],
            [(0x12345678, 24), (0x12345690, 6)],
        )
        reader.read(0x12345678, 1, real=True)
        self.assertEqual(len(self.calls), 3)

    def test_native_status_and_malformed_reply_do_not_populate_cache(self):
        reader = self.reader(
            exchange=lambda query: (_ for _ in ()).throw(
                NativeStatus(0xA0040003, b"partial")
            )
        )
        with self.assertRaises(NativeStatus) as caught:
            reader.read(0x1000, 1)
        self.assertEqual(caught.exception.code, 0xA0040003)
        self.assertEqual(reader.transactions[0].reply, b"partial")
        reader.exchange = lambda query: b"short"
        with self.assertRaises(ToyotaCodecError):
            reader.read(0x1000, 1)
        self.assertEqual(reader.transactions[1].status, 0xA0040201)
        self.assertEqual(reader.transactions[1].reply, b"short")
        reader.exchange = self.reply
        self.assertEqual(reader.read(0x1000, 1), b"\0")

    def test_budget_cancel_deadline_and_native_address_overflow(self):
        with self.assertRaises(SessionError):
            self.reader(limits=Limits(exchanges=1)).read(0x1000, 25, real=True)
        with self.assertRaises(Cancelled):
            self.reader(cancelled=lambda: True).read(0, 1)
        ticks = iter((0.0, 11.0))
        with self.assertRaises(SessionError):
            self.reader(clock=lambda: next(ticks)).read(0, 1)
        with self.assertRaises(SessionError):
            self.reader(clock=lambda: float("nan")).read(0, 1)
        reader = self.reader()
        reader.profile = replace(self.profile, exception_ids=(5,))
        with self.assertRaises(SessionError):
            reader.read(0, 1)
        self.assertEqual(reader.transactions, ())
        with self.assertRaises(ToyotaCodecError) as caught:
            self.reader().read(0xFFFFFFFE, 1, real=True)
        self.assertEqual(caught.exception.code, 0xA0041201)

    def test_input_and_cache_budget_bounds(self):
        for size in (0, 256, True):
            with self.assertRaises(ValueError):
                self.reader(block_size=size)
        for address, size in ((-1, 1), (0x100000000, 1), (0, 0), (0, 65536)):
            with self.assertRaises(ValueError):
                self.reader().read(address, size)
        with self.assertRaises(ToyotaCodecError) as caught:
            ram_request(b"1234", self.frame, 1)
        self.assertEqual(caught.exception.code, 0xC0040102)
        with patch.object(snapshot, "MAX_BYTES", 24), self.assertRaises(SessionError):
            self.reader().read(0x1000, 25)


if __name__ == "__main__":
    unittest.main()
