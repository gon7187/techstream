"""Authored native-layout vectors; no vendor recording is redistributed."""

import struct
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.snapshot import (
    DM_MAGIC,
    DRS_MAGIC,
    Cursor,
    DualCapture,
    DualECU,
    DualSection,
    Flag,
    MonitorBuffer,
    SignalItem,
    SnapshotError,
    Table,
    TableFile,
    TSEDataList,
    TSEDataListSection,
    TSEFile,
    TSEHeader,
    assemble_tse,
    compress,
    create_tse_header,
    decode_active_metadata,
    decode_frame_table,
    decode_monitor_buffer,
    decode_packet_stream,
    decode_ring_buffer,
    decode_signal_item,
    decode_signal_table,
    decode_system_information,
    decode_tse_datalist_section,
    decode_tse_dual_section,
    decompress,
    dumps,
    encode_monitor_buffer,
    encode_signal_item,
    encode_system_information,
    encode_tse_datalist_section,
    encode_tse_dual_section,
    load,
    monitor_packets,
    monitor_samples,
    parse,
    parse_tables,
    playback,
    recorded_bits,
    replace_tse_datalist,
    replace_tse_monitor_section,
    tse_monitors,
)


class SnapshotTests(unittest.TestCase):
    def test_original_table_layout(self):
        raw = bytes.fromhex("020000800100020005000000018161626302000000ffff")
        snapshot = parse(raw)
        self.assertEqual(
            snapshot,
            TableFile(DM_MAGIC, 1, 2, (Table(0x8101, b"abc"), Table(65535, b""))),
        )
        self.assertEqual(dumps(snapshot), raw)
        self.assertEqual(snapshot.to_dict()["format"], "native-dm")

    def test_drs_envelope_and_duplicate_order_preserved(self):
        record = TableFile(DRS_MAGIC, 3, 4, (Table(2, b"a"), Table(2, b"b")))
        self.assertEqual(parse(dumps(record)), record)

    def test_truncations_and_invalid_sizes(self):
        valid = dumps(TableFile(DM_MAGIC, 0, 0, (Table(1, b"abc"),)))
        for end in list(range(8)) + list(range(9, len(valid))):
            with self.subTest(end=end), self.assertRaises(SnapshotError):
                parse(valid[:end])
        for value in (0, 1, 0xFFFFFFFF):
            with self.subTest(value=value), self.assertRaises(SnapshotError):
                parse_tables(struct.pack("<I", value))
        with self.assertRaises(SnapshotError):
            parse(b"not native")

    def test_bounded_file_load(self):
        import os

        with TemporaryDirectory() as directory:
            path = Path(directory) / "record.dm"
            path.write_bytes(dumps(TableFile(DM_MAGIC, 1, 2, ())))
            self.assertEqual(load(path).version, 1)
            fifo = Path(directory) / "record.fifo"
            os.mkfifo(fifo)
            for invalid in (fifo, Path(directory), Path("/dev/null")):
                with (
                    self.subTest(path=invalid),
                    self.assertRaisesRegex(SnapshotError, "regular file"),
                ):
                    load(invalid)

    def test_native_compression_literal_vector(self):
        self.assertEqual(compress(b"ABC"), bytes.fromhex("030000004307414243"))
        self.assertEqual(decompress(bytes.fromhex("030000004307414243")), b"ABC")

    def test_native_compression_overlap_match(self):
        # Literal ABC at ring 0xfee, then six-byte overlapping match at 0xfee.
        self.assertEqual(
            decompress(bytes.fromhex("090000004307414243eef3")), b"ABCABCABC"
        )

    def test_compression_roundtrip_and_failures(self):
        for value in (b"", bytes(range(256)), b"hello" * 101, b"\x00" * 20):
            self.assertEqual(decompress(compress(value)), value)
        for value in (
            b"",
            b"1234",
            bytes.fromhex("0300000047034142"),
            bytes.fromhex("030000000003414243"),
            bytes.fromhex("0300000000000000"),
            compress(b"ABC") + b"x",
            bytes.fromhex("ffffffff0000"),
        ):
            with self.subTest(value=value), self.assertRaises(SnapshotError):
                decompress(value)

    @staticmethod
    def monitor():
        indexes = [0] * 256
        lengths = [0] * 256
        indexes[:2] = [5, 8]
        lengths[5], lengths[8] = 2, 1
        frames = struct.pack("<HHI256H256HI", 2, 0, 2, *indexes, *lengths, 0)
        packets = struct.pack("<I", 100) + b"AB1" + struct.pack("<I", 120) + b"CD2"
        # Wrap the first packet over the physical end of the ring.
        image = packets[5:] + packets[:5]
        ring = (
            struct.pack(
                "<HHIH7I", 1, 0, 0, 1, len(image), 0, 9, 9, 9, len(image), len(image)
            )
            + image
        )
        return MonitorBuffer(
            b"engine",
            bytes(16),
            b"capture",
            frames,
            struct.pack("<HHI", 1, 0, 0),
            ring,
            100,
            (Flag(120, b"event"),),
            (5, 8),
            b"note",
            (8,),
        )

    def test_monitor_native_fields_roundtrip(self):
        record = self.monitor()
        raw = encode_monitor_buffer(record)
        self.assertEqual(decode_monitor_buffer(raw), record)
        self.assertEqual(
            decode_monitor_buffer(raw).to_dict()["flags"][0]["position"], 120
        )
        for end in range(len(raw)):
            with self.subTest(end=end), self.assertRaises(SnapshotError):
                decode_monitor_buffer(raw[:end])
        with self.assertRaises(SnapshotError):
            decode_monitor_buffer(raw + b"x")

    def test_native_frame_ring_packet_timeline(self):
        record = self.monitor()
        frames = decode_frame_table(record.frame_table)
        self.assertEqual(frames["indexes"][:2], [5, 8])
        self.assertEqual(decode_signal_table(record.signal_table)["items_hex"], [])
        self.assertEqual(decode_ring_buffer(record.ring_buffer)["phase"], 0)
        packets = monitor_packets(record)
        self.assertEqual([packet["timestamp_raw"] for packet in packets], [100, 120])
        self.assertEqual(
            packets[0]["frames"],
            [{"index": 5, "data_hex": "4142"}, {"index": 8, "data_hex": "31"}],
        )

    def test_system_information_native_string_headers(self):
        raw = bytes.fromhex("785634120100020003006162630300040000000500")
        record = decode_system_information(raw)
        self.assertEqual(record["strings"][0], {"core": [1, 2], "data_hex": "616263"})
        self.assertEqual(encode_system_information(record), raw)
        with self.assertRaises(SnapshotError):
            decode_system_information(raw[:-1])

    @staticmethod
    def tse_index(version=0x102C):
        def tagged(name, value=0):
            return name.encode().ljust(12, b"\0") + struct.pack("<I", value)

        if version == 0x1000:
            return (
                b"\x9aS\xdb\x12TSE\0"
                + struct.pack("<IHHII", 4, version, 0, 1, 0)
                + bytes(4 * 4 + 2 + 4 + 80)
            )
        header = b"\x9aS\xdb\x12TSE\0" + struct.pack(
            "<IHHIIHHH", 4, version, 0, 0, 0, 0, 0, 0
        )
        names = (
            "IniCarInfo",
            "ConfCarInfo",
            "MultiPID",
            "FuncName",
            "HealthCheck",
            "TimeStamp",
            "ROBCommon",
            "MILMessage",
            "CanBus",
            "DualData",
            "DDRData",
            "OpeFFD",
            "ImgFFD",
            "ECUInfo",
        )
        header += b"".join(tagged(name) for name in names) + struct.pack("<H", 1)
        names = (
            "EcuData",
            "DataList",
            "DTCMon",
            "DTCP5",
            "ATest",
            "ATestD",
            "DrvRec",
            "SysChk",
            "FuelCon",
            "OpeHis",
            "ROB",
            "Oscillo",
            "ABSHis",
            "ICSHis",
            "AFO2Sn",
            "PSDHis",
            "PreFFD",
            "OpeInope",
        )
        header += b"".join(tagged(name + "0042") for name in names)
        header += tagged("MktMonRam")
        if version >= 0x102C:
            header += tagged("MktMonRamSSR")
        if version >= 0x102B:
            header += tagged("TMRRep")
        header += tagged("ErrRep")
        return header + bytes([0x80]) + bytes(79)

    def test_native_header_constructor_all_version_boundaries(self):
        for version in range(0x1000, 0x102D):
            features = (0x2711, 0x2730 if version <= 0x1026 else 0x2990)
            header = TSEHeader(
                "TSE",
                1,
                version,
                2,
                0x80000001 if version <= 0x1026 else 0x1234,
                0x5678,
                9 if version >= 0x1006 else None,
                b"authored30" if version >= 0x1007 else None,
                b"authored44" if version >= 0x100F else None,
                (1, 65535),
                features,
                bytes(80) if version <= 0x1026 else b"",
            )
            prefix = create_tse_header(header)
            self.assertEqual(prefix.version, version)
            self.assertEqual(prefix.file_type, 1)
            self.assertEqual(prefix.metadata["supported_feature_ids"], list(features))
            self.assertEqual(prefix.metadata["systems_mask"], header.systems_mask)
            self.assertEqual(len(prefix.metadata["ecu_index"]), 2)
            self.assertEqual(prefix.body_offset, len(prefix.source))
            if version >= 0x1024:
                self.assertEqual(
                    [ecu["ecu_id_raw"] for ecu in prefix.metadata["ecu_index"]],
                    [1, 65535],
                )
        latest = TSEHeader(
            "TSE", 4, 0x102C, 0, 0, 0, 0, b"", b"", (42,), (0x2711,), b""
        )
        self.assertEqual(create_tse_header(latest).source, self.tse_index())
        oldest = TSEHeader(
            "TSE", 4, 0x1000, 0, 1, 0, None, None, None, (), (0x2711,), bytes(80)
        )
        self.assertEqual(create_tse_header(oldest).source, self.tse_index(0x1000))

    def test_native_header_constructor_rejects_inapplicable_metadata(self):
        from dataclasses import replace

        header = TSEHeader(
            "TSE", 4, 0x102C, 0, 0, 0, 0, b"", b"", (42,), (0x2714,), b""
        )
        for changes in (
            {"kind": "FAKE"},
            {"version": 0x102D},
            {"file_type": True},
            {"language": None},
            {"field_30": None},
            {"field_44": None},
            {"reserved": bytes(80)},
            {"ecu_ids": (42, 42)},
            {"ecu_ids": (65536,)},
            {"feature_ids": (0x2991,)},
            {"feature_ids": (0x2714, 0x2714)},
        ):
            with self.subTest(changes=changes), self.assertRaises(SnapshotError):
                create_tse_header(replace(header, **changes))
        legacy = TSEHeader(
            "TSE", 1, 0x1000, 0, 1, 0, None, None, None, (), (0x2711,), bytes(80)
        )
        for changes in (
            {"language": 0},
            {"field_30": b""},
            {"field_44": b""},
            {"systems_mask": 0},
            {"feature_ids": (0x2731,)},
            {"reserved": b""},
        ):
            with self.subTest(changes=changes), self.assertRaises(SnapshotError):
                create_tse_header(replace(legacy, **changes))

    def test_original_tse_index_latest_and_legacy(self):
        for version in (0x1000, 0x102A, 0x102B, 0x102C):
            raw = self.tse_index(version)
            snapshot = parse(raw)
            self.assertIsInstance(snapshot, TSEFile)
            self.assertEqual(dumps(snapshot), raw)
            self.assertEqual(snapshot.to_dict()["coverage"], "native-index-only")
            if isinstance(snapshot, TSEFile):
                self.assertEqual(snapshot.metadata["supported_feature_ids"], [0x2711])
                self.assertEqual(snapshot.body_offset, len(raw))
        raw = self.tse_index()
        for end in range(len(raw)):
            with self.subTest(end=end), self.assertRaises(SnapshotError):
                parse(raw[:end])

    def test_tse_opaque_body_does_not_claim_playback(self):
        raw = self.tse_index() + b"opaque-body"
        snapshot = parse(raw)
        self.assertEqual(dumps(snapshot), raw)
        self.assertEqual(snapshot.to_dict()["monitor_count"], 0)
        damaged = raw.replace(b"DataList0042", b"DataList0000")
        with self.assertRaises(SnapshotError):
            parse(damaged)

    @staticmethod
    def signal(version=4):
        return SignalItem(
            version,
            0,
            12,
            5,
            0,
            15,
            b"Authored RPM",
            b"RPM",
            b"rpm",
            2,
            1,
            0,
            1,
            4,
            0,
            1,
            0,
            0xFFFFFFFF,
            ((1, b"one", 0, 0),),
            (42, 0, 0) if version > 1 else None,
        )

    def test_native_signal_item_versions_and_corruption(self):
        for version in (1, 2, 3, 4):
            signal = self.signal(version)
            raw = encode_signal_item(signal)
            self.assertEqual(decode_signal_item(raw), signal)
            for end in range(len(raw)):
                with (
                    self.subTest(version=version, end=end),
                    self.assertRaises(SnapshotError),
                ):
                    decode_signal_item(raw[:end])
            with self.assertRaises(SnapshotError):
                decode_signal_item(raw + b"x")

    def test_native_scalar_playback_and_plot_adapter(self):
        record = self.monitor()
        signal = encode_signal_item(self.signal())
        record = MonitorBuffer(
            record.name,
            record.information,
            record.description,
            record.frame_table,
            struct.pack("<HHII", 1, 0, 1, len(signal)) + signal,
            record.ring_buffer,
            record.marker,
            record.flags,
            record.selected_ids,
            record.comment,
            record.additional_ids,
        )
        samples = monitor_samples(record)
        self.assertEqual([sample["timestamp_raw"] for sample in samples], [100, 120])
        self.assertEqual(samples[0]["values"][0]["raw"], 0x4142)
        self.assertEqual(samples[0]["values"][0]["value"], (0x4142 // 4) / 10)
        self.assertEqual(samples[0]["values"][0]["unit"], "rpm")
        capture = TableFile(
            DM_MAGIC,
            1,
            0,
            (Table(0x8101, encode_monitor_buffer(record)),),
        )
        reopened = parse(dumps(capture))
        report = playback(reopened)
        self.assertEqual(report["samples"], samples)
        self.assertEqual(report["interpolation"], "none")
        from scripts.plot import sample_chart

        self.assertIn("<svg", sample_chart(report["samples"], "12"))
        with self.assertRaises(SnapshotError):
            playback(parse(self.tse_index()))

    def test_native_snapshot_symbolic_unknown_and_null_display(self):
        from dataclasses import replace

        for (
            selector,
            patterns,
            expected_kind,
            expected_display,
            expected_status,
        ) in (
            (
                1,
                ((999, b"enabled", 0x4142 // 4, 0),),
                "symbolic",
                "enabled",
                "ok",
            ),
            (1, (), "symbolic", "-No Data-", "unresolved"),
            (0, (), "unresolved", "-TypeErr-", "unresolved"),
            (
                28,
                (),
                "numeric",
                "-No Data-",
                "unavailable",
            ),
        ):
            signal = replace(self.signal(), selector=selector, patterns=patterns)
            if selector == 28:
                signal = replace(signal, end_bit=31)
                # A standalone frame containing IEEE754 NaN, in native MSB order.
                frame = bytearray(self.monitor().frame_table)
                struct.pack_into("<H", frame, 8 + 512 + 5 * 2, 4)
                packet = struct.pack("<I", 100) + bytes.fromhex("7fc00000") + b"1"
                ring = (
                    struct.pack(
                        "<HHIH7I",
                        1,
                        0,
                        0,
                        1,
                        len(packet),
                        0,
                        0,
                        0,
                        0,
                        len(packet),
                        len(packet),
                    )
                    + packet
                )
                record = replace(
                    self.monitor(), frame_table=bytes(frame), ring_buffer=ring
                )
            else:
                record = self.monitor()
            encoded = encode_signal_item(signal)
            record = replace(
                record,
                signal_table=struct.pack("<HHII", 1, 0, 1, len(encoded)) + encoded,
            )
            value = monitor_samples(record)[0]["values"][0]
            with self.subTest(selector=selector, patterns=patterns):
                self.assertIsNone(value["value"])
                self.assertEqual(value["kind"], expected_kind)
                self.assertEqual(value["display"], expected_display)
                self.assertEqual(value["status"], expected_status)

    def test_repeated_long_display_labels_share_storage(self):
        from dataclasses import replace
        from unittest.mock import patch

        signal = replace(
            self.signal(),
            selector=1,
            multiplier=0,
            offset=1,
            precision=0,
            name=b"n" * 16384,
            unit=b"u" * 16384,
            patterns=((999, b"l" * 16384, 1, 0),),
        )
        encoded = encode_signal_item(signal)
        record = replace(
            self.monitor(),
            signal_table=struct.pack("<HHII", 1, 0, 1, len(encoded)) + encoded,
        )
        samples = monitor_samples(record)
        for key in ("name", "unit", "display"):
            self.assertIs(samples[0]["values"][0][key], samples[1]["values"][0][key])
        signal = replace(signal, patterns=signal.patterns * 3)
        encoded = encode_signal_item(signal)
        record = replace(
            record, signal_table=struct.pack("<HHII", 1, 0, 1, len(encoded)) + encoded
        )
        with (
            patch("scripts.snapshot.MAX_TABLES", 3),
            self.assertRaisesRegex(SnapshotError, "metadata count"),
        ):
            monitor_samples(record)

    def test_repeated_text_report_budget_precedes_rendering(self):
        from dataclasses import replace
        from unittest.mock import patch

        signal = replace(
            self.signal(),
            name=b"n" * 300,
            unit=b"u" * 300,
            patterns=((1, b"l" * 300, 0, 0),),
        )
        encoded = encode_signal_item(signal)
        record = replace(
            self.monitor(),
            signal_table=struct.pack("<HHII", 1, 0, 1, len(encoded)) + encoded,
        )
        with (
            patch("scripts.snapshot.MAX_BYTES", 2048),
            patch(
                "scripts.signal_display.render_signal",
                side_effect=AssertionError("must not render"),
            ),
            self.assertRaisesRegex(SnapshotError, "report text"),
        ):
            monitor_samples(record)

    def test_saved_thresholds_use_extended_fields_not_display_bounds(self):
        from dataclasses import replace

        for version in (1, 4):
            signal = replace(
                self.signal(version),
                selector=13,
                minimum_raw=0xFFFFFFFF,
                maximum_raw=0xFFFFFFFF,
                patterns=((999, b"lower", 0, 0), (999, b"upper", 1, 0)),
                extended=(42, 0x100, 0x40) if version > 1 else None,
            )
            encoded = encode_signal_item(signal)
            record = replace(
                self.monitor(),
                signal_table=struct.pack("<HHII", 1, 0, 1, len(encoded)) + encoded,
            )
            value = monitor_samples(record)[0]["values"][0]
            self.assertEqual(value["display"], "upper")
            self.assertIsInstance(value["value"], float)

    def test_recorded_monitor_float64_uses_native_zero_argument_bridge(self):
        from dataclasses import replace

        # The recorded monitor table/details pass ConvertData words6/7 as zero,
        # even when the extracted DWORD or display thresholds are nonzero.
        signal = replace(self.signal(), selector=29, extended=(42, 0xFFFFFFFF, 7))
        encoded = encode_signal_item(signal)
        record = replace(
            self.monitor(),
            signal_table=struct.pack("<HHII", 1, 0, 1, len(encoded)) + encoded,
        )
        value = monitor_samples(record)[0]["values"][0]
        self.assertNotEqual(value["raw"], 0)
        self.assertEqual(value["value"], 0.0)
        self.assertEqual(value["display"], "0.0")
        self.assertEqual(value["display_words_raw"], [0, 0])
        self.assertEqual(
            value["display_word_source"], "native-recorded-monitor-zero-arguments"
        )
        self.assertEqual(value["status"], "ok")

    def test_packet_frame_aggregate_limit_before_reading(self):
        from unittest.mock import patch

        # Two packets and two frames individually fit limit3, aggregate4 does not.
        with (
            patch("scripts.snapshot.MAX_TABLES", 3),
            patch.object(Cursor, "unpack", side_effect=AssertionError("must not read")),
            self.assertRaisesRegex(SnapshotError, "decoded packet frame count"),
        ):
            decode_packet_stream(bytes(12), ((1, 1), (2, 1)))

    def test_recorded_consumer_bit_assembly(self):
        self.assertEqual(recorded_bits(bytes.fromhex("ff80"), 7, 8), 3)
        self.assertEqual(recorded_bits(bytes.fromhex("ff12345680"), 1, 32), 0x2468AD)
        self.assertEqual(recorded_bits(bytes.fromhex("80"), 0, 7, 129), 0xFFFFFFFF)
        self.assertEqual(recorded_bits(bytes.fromhex("89abcdef"), 0, 31), 0x89ABCDEF)
        with self.assertRaises(SnapshotError):
            recorded_bits(b"a", 0, 8)

    def test_tse_alias_records_share_decoded_storage(self):
        from dataclasses import replace
        from unittest.mock import patch

        base = self.tse_index()
        first, last = base.index(b"EcuData0042"), base.index(b"MktMonRam")
        copies = 8
        head = bytearray(base[:first] + base[first:last] * copies + base[last:])
        struct.pack_into("<H", head, first - 2, copies)
        head[-80:] = bytes(80)
        head[-80] = 0x10
        monitor = replace(self.monitor(), ring_buffer=bytes(16 * 1024))
        item = TSEDataList(monitor, (), 1, (), bytes(90), bytes(80))
        section = TSEDataListSection(0xFFFFFFFF, 0xFFFFFF05, 0x1021, (item,))
        raw = encode_tse_datalist_section(section)
        index = parse(bytes(head))
        assert isinstance(index, TSEFile)
        for entry in index.metadata["index_entries"]:
            if entry["tag"].startswith("DataList"):
                struct.pack_into("<I", head, entry["position"], len(head))
            elif entry["tag"] == "ErrRep":
                struct.pack_into("<I", head, entry["position"], len(head) + len(raw))
        capture = parse(bytes(head) + raw)
        assert isinstance(capture, TSEFile)
        with patch(
            "scripts.snapshot.decode_tse_datalist_section",
            wraps=decode_tse_datalist_section,
        ) as decoder:
            records = tse_monitors(capture)
            self.assertEqual(decoder.call_count, 1)
        self.assertEqual(len(records), copies)
        self.assertEqual(
            len({id(entry["record"].monitor.ring_buffer) for entry in records}), 1
        )
        with (
            patch("scripts.snapshot.MAX_TABLES", copies - 1),
            self.assertRaisesRegex(SnapshotError, "monitor count"),
        ):
            tse_monitors(capture)

    def test_writer_budget_precedes_aliased_record_join(self):
        from dataclasses import replace
        from unittest.mock import patch

        item = TSEDataList(self.monitor(), (), 1, (), bytes(90), bytes(80))
        section = TSEDataListSection(0xFFFFFFFF, 0xFFFFFF05, 0x1021, (item,))
        one_size = len(encode_tse_datalist_section(section))
        with (
            patch("scripts.snapshot.MAX_BYTES", one_size + 1),
            self.assertRaisesRegex(SnapshotError, "encoded native record"),
        ):
            encode_tse_datalist_section(replace(section, records=(item, item)))
        with (
            patch("scripts.snapshot.MAX_BYTES", 8),
            self.assertRaisesRegex(SnapshotError, "compressed block"),
        ):
            compress(b"abc")

    def test_native_pid_standard_value_baseline(self):
        from dataclasses import replace

        signal = encode_signal_item(self.signal())
        record = self.monitor()
        frames = bytearray(record.frame_table[:-4])
        struct.pack_into("<H", frames, 0, 2)
        frames += struct.pack("<IIIII", 2, 12, 0x4100, 12, 99)
        record = replace(
            record,
            frame_table=bytes(frames),
            signal_table=struct.pack("<HHII", 1, 0, 1, len(signal)) + signal,
        )
        value = monitor_samples(record)[0]["values"][0]
        self.assertEqual(value["raw_bits"], 0x4142)
        self.assertEqual(value["baseline_raw"], 0x4100)
        self.assertEqual(value["raw"], 0x42)
        self.assertEqual(value["value"], (0x42 // 4) / 10)

    def test_sample_amplification_rejected_before_conversion(self):
        from dataclasses import replace
        from unittest.mock import patch

        signal = encode_signal_item(replace(self.signal(), patterns=()))
        table = struct.pack("<HHI", 1, 0, 3) + 3 * (
            struct.pack("<I", len(signal)) + signal
        )
        record = replace(self.monitor(), signal_table=table)
        # Two packets times three signal items exceeds this deliberately small
        # aggregate budget, while each individual native collection fits.
        with (
            patch("scripts.snapshot.MAX_TABLES", 4),
            patch(
                "scripts.signal_display.render_signal",
                side_effect=AssertionError("must not allocate values"),
            ),
            self.assertRaisesRegex(SnapshotError, "sample value count"),
        ):
            monitor_samples(record)

    def test_original_tse_datalist_codec_and_offset_edit(self):
        from dataclasses import replace

        record = self.monitor()
        signal = encode_signal_item(self.signal())
        record = replace(
            record, signal_table=struct.pack("<HHII", 1, 0, 1, len(signal)) + signal
        )
        item = TSEDataList(record, ((12, 42),), 1, (bytes(84),), bytes(90), bytes(80))
        section = TSEDataListSection(0xFFFFFFFF, 0xFFFFFF05, 0x1021, (item,))
        raw = encode_tse_datalist_section(section)
        self.assertEqual(decode_tse_datalist_section(raw), section)
        for end in range(len(raw)):
            with self.subTest(end=end), self.assertRaises(SnapshotError):
                decode_tse_datalist_section(raw[:end])
        prefix = bytearray(self.tse_index())
        parsed = parse(bytes(prefix))
        assert isinstance(parsed, TSEFile)
        prefix[-80] = 0x10  # native feature 0x2714, DataList.
        # Native ECUInfo version0x1005 metadata; all strings/IDs are authored.
        ecu = (
            struct.pack("<HHH", 42, 0, 6)
            + b"Engine"
            + struct.pack("<IIH", 0, 42, 6)
            + b"Engine"
            + bytes(3)
            + bytes(80)
        )
        body = struct.pack("<IIHH", 0xFFFFFFFF, 0xFFFFFF04, 0x1005, 1) + ecu
        start, end = len(prefix) + len(body), len(prefix) + len(body) + len(raw)
        after = False
        for entry in parsed.metadata["index_entries"]:
            tag = entry["tag"]
            if tag == "EcuData0042":
                value = len(prefix) + 12
            elif tag == "DataList0042":
                value, after = start, True
            elif after:
                value = end
            else:
                value = len(prefix)
            struct.pack_into("<I", prefix, entry["position"], value)
        opaque_tail = b"authored unsupported companion body"
        capture = parse(bytes(prefix) + body + raw + opaque_tail)
        assert isinstance(capture, TSEFile)
        # Full native file creation uses production header and body writers.
        template = create_tse_header(
            TSEHeader("TSE", 1, 0x102C, 0, 0, 0, 0, b"", b"", (42,), (0x2714,), b"")
        )
        fragments = tuple(
            body[:12]
            if entry["tag"] == "ECUInfo"
            else body[12:]
            if entry["tag"] == "EcuData0042"
            else raw
            if entry["tag"] == "DataList0042"
            else opaque_tail
            if entry["tag"] == "ErrRep"
            else b""
            for entry in template.metadata["index_entries"]
        )
        assembled = assemble_tse(template, fragments)
        self.assertEqual(playback(assembled)["samples"], monitor_samples(record))
        self.assertTrue(assembled.source.endswith(opaque_tail))
        with self.assertRaises(SnapshotError):
            assemble_tse(template, fragments[:-1])
        with self.assertRaises(SnapshotError):
            assemble_tse(template, tuple(b"" for _ in fragments))
        self.assertEqual(tse_monitors(capture)[0]["ecu_id_raw"], 42)
        self.assertEqual(playback(capture)["samples"], monitor_samples(record))
        changed_section = replace(
            section,
            records=(
                replace(
                    item, monitor=replace(record, comment=b"longer authored comment")
                ),
            ),
        )
        with self.assertRaises(SnapshotError):
            replace_tse_datalist(
                capture, 0, replace(changed_section, type_raw=0xFFFFFF08)
            )
        changed = replace_tse_datalist(capture, 0, changed_section)
        self.assertGreater(len(dumps(changed)), len(dumps(capture)))
        self.assertEqual(tse_monitors(changed)[0]["record"], changed_section.records[0])
        self.assertEqual(playback(changed)["samples"], playback(capture)["samples"])
        self.assertTrue(changed.source.endswith(opaque_tail))
        self.assertEqual(changed.source[: len(prefix)].count(b"DataList0042"), 1)

    def test_native_dual_capture_roundtrip_and_playback(self):
        from dataclasses import replace

        monitor = self.monitor()
        signal = encode_signal_item(self.signal())
        monitor = replace(
            monitor, signal_table=struct.pack("<HHII", 1, 0, 1, len(signal)) + signal
        )
        ecus = tuple(
            DualECU(
                identifier,
                name,
                b"authored",
                0,
                (12,),
                monitor.frame_table,
                monitor.signal_table,
                monitor.ring_buffer,
                (12,),
                ((12, identifier),),
            )
            for identifier, name in ((42, b"Engine"), (43, b"Transmission"))
        )
        record = DualCapture(
            1,
            b"dual",
            bytes(16),
            b"fixture",
            100,
            monitor.flags,
            (bytes(88),),
            (bytes(20),),
            bytes(20),
            ecus,
        )
        section = DualSection(0x1027, (record,))
        raw = encode_tse_dual_section(section)
        self.assertEqual(decode_tse_dual_section(raw), section)
        for end in range(len(raw)):
            with self.subTest(end=end), self.assertRaises(SnapshotError):
                decode_tse_dual_section(raw[:end])
        source = self.tse_index()
        prefix = bytearray(source[:254] + bytes(2) + source[544:])
        parsed = parse(bytes(prefix))
        assert isinstance(parsed, TSEFile)
        prefix[-80:] = bytes(80)
        prefix[-78] = 4  # native feature0x2726, DualData.
        after = False
        for entry in parsed.metadata["index_entries"]:
            value = len(prefix) + len(raw) if after else len(prefix)
            if entry["tag"] == "DualData":
                after = True
            struct.pack_into("<I", prefix, entry["position"], value)
        capture = parse(bytes(prefix) + raw)
        assert isinstance(capture, TSEFile)
        self.assertEqual(
            [item["ecu_id_raw"] for item in tse_monitors(capture)], [42, 43]
        )
        self.assertEqual(playback(capture, 1)["family"], "DualData")
        self.assertEqual(playback(capture, 1)["samples"], monitor_samples(monitor))
        self.assertEqual(dumps(capture), bytes(prefix) + raw)
        changed = replace_tse_monitor_section(
            capture,
            "DualData",
            replace(
                section,
                records=(replace(record, description=b"longer edited description"),),
            ),
        )
        self.assertEqual(playback(changed)["samples"], playback(capture)["samples"])
        with self.assertRaises(SnapshotError):
            replace_tse_monitor_section(capture, "DualData", section, 1)

    @staticmethod
    def active_metadata(version=0x1021):
        def blob(value):
            return struct.pack("<H", len(value)) + value

        result = struct.pack("<I", 7) + blob(b"Actuator")
        if version > 0x1007:
            result += struct.pack("<I", 8)
        result += blob(b"saved descriptor")
        result += struct.pack("<HIIHII", 1, 1, 2, 1, 3, 4)
        result += blob(b"parameter") + struct.pack("<II", 5, 6)
        result += struct.pack("<HI", 1, 12) + blob(b"signal") + bytes((1, 2))
        result += bytes(17) + struct.pack("<HI", 1, 13) + blob(b"pattern")
        result += struct.pack("<IIB", 10, 20, 1) + bytes(16)
        result += bytes(17) + struct.pack("<HI", 1, 14) + blob(b"command")
        result += blob(b"REQ") + blob(b"RES") + bytes((2,)) + bytes(16)
        result += struct.pack("<IH", 21, 22)
        if version >= 0x1021:
            result += struct.pack("<IHH", 23, 1, 12)
        return result

    def test_active_test_saved_metadata_and_capture(self):
        from dataclasses import replace

        for version in (0x1007, 0x1008, 0x1021):
            metadata = self.active_metadata(version)
            report = decode_active_metadata(metadata, version)
            self.assertEqual(
                report["operations"][0]["parameters"][0]["limits_raw"], (5, 6)
            )
            self.assertEqual(
                report["signals"][0]["descriptors"][1]["items"][0]["request_hex"],
                b"REQ".hex(),
            )
            for end in range(len(metadata)):
                with (
                    self.subTest(version=version, end=end),
                    self.assertRaises(SnapshotError),
                ):
                    decode_active_metadata(metadata[:end], version)
            item = TSEDataList(
                self.monitor(), (), 0, (), bytes(90), bytes(80), metadata
            )
            section = TSEDataListSection(0xFFFFFFFF, 0xFFFFFF07, version, (item,))
            raw = encode_tse_datalist_section(section)
            self.assertEqual(decode_tse_datalist_section(raw), section)
            with self.assertRaises(SnapshotError):
                encode_tse_datalist_section(replace(section, type_raw=0xFFFFFF05))
            dual = DualCapture(
                2,
                b"active dual",
                bytes(16),
                b"fixture",
                100,
                (),
                (),
                (),
                bytes(20),
                (),
                metadata,
            )
            dual_section = DualSection(version, (dual,), 0xFFFFFF21)
            raw_dual = encode_tse_dual_section(dual_section)
            self.assertEqual(decode_tse_dual_section(raw_dual), dual_section)
            for end in range(len(raw_dual)):
                with (
                    self.subTest(version=version, end=end),
                    self.assertRaises(SnapshotError),
                ):
                    decode_tse_dual_section(raw_dual[:end])

    def test_native_legacy_monitor_versions(self):
        for version in (0x1000, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005, 0x1006):
            views = (
                (bytes(84 if version >= 0x1004 else 82),) if version >= 0x1002 else ()
            )
            chart = bytes(90 if version >= 0x1003 else 54) if version >= 0x1002 else b""
            item = TSEDataList(
                self.monitor(),
                ((12, 42),),
                0 if version >= 0x1004 else None,
                views,
                chart,
                bytes(80),
            )
            for kind in (0xFFFFFF05, 0xFFFFFF07, 0xFFFFFF08):
                section = TSEDataListSection(0xFFFFFFFF, kind, version, (item,))
                self.assertEqual(
                    decode_tse_datalist_section(encode_tse_datalist_section(section)),
                    section,
                )
            ecu = DualECU(
                42,
                b"Engine",
                b"fixture",
                0 if version >= 0x1003 else None,
                (12,),
                b"f",
                b"s",
                b"r",
                (12,),
                ((12, 42),),
            )
            record = DualCapture(
                1,
                b"dual",
                bytes(16),
                b"fixture",
                100,
                (),
                (bytes(88 if version >= 0x1004 else 86),),
                (),
                bytes(20 if version >= 0x1002 else 16),
                (ecu,),
            )
            for kind in (0xFFFFFF19, 0xFFFFFF21):
                section_dual = DualSection(version, (record,), kind)
                self.assertEqual(
                    decode_tse_dual_section(encode_tse_dual_section(section_dual)),
                    section_dual,
                )

    def test_raw_native_packet_stream_adapter(self):
        data = struct.pack("<I", 100) + b"AB1" + struct.pack("<I", 120) + b"CD2"
        packets = decode_packet_stream(data, ((5, 2), (8, 1)))
        self.assertEqual(packets, monitor_packets(self.monitor()))
        for malformed in ((), ((256, 1),), ((1, 0),), ((True, 1),)):
            with self.subTest(layout=malformed), self.assertRaises(SnapshotError):
                decode_packet_stream(data, malformed)
        with self.assertRaises(SnapshotError):
            decode_packet_stream(data[:-1], ((5, 2), (8, 1)))

    def test_native_compact_ring_recording(self):
        from dataclasses import replace

        record = self.monitor()
        packets = struct.pack("<I", 100) + b"AB1" + struct.pack("<I", 120) + b"CD2"
        ring = struct.pack("<HHIH7I", 1, 0, 0, 1, 100, 86, 0, 0, 14, 14, 14) + packets
        self.assertEqual(
            [
                item["timestamp_raw"]
                for item in monitor_packets(replace(record, ring_buffer=ring))
            ],
            [100, 120],
        )

    @staticmethod
    def one_byte_frame_record(ring, frame_ids=(5,)):
        from dataclasses import replace

        indexes, lengths = [0] * 256, [0] * 256
        for position, frame_id in enumerate(frame_ids):
            indexes[position], lengths[frame_id] = frame_id, 1
        frame = struct.pack(
            "<HHI256H256HI", 3, 0, len(frame_ids), *indexes, *lengths, 0
        )
        return replace(SnapshotTests.monitor(), frame_table=frame, ring_buffer=ring)

    def test_native_saturated_nonmultiple_allocation_discards_only_stale_tail(self):
        from scripts.recorder_buffer import NativeRecorderRing

        ring = NativeRecorderRing(4096, 5)
        for timestamp in range(1, 821):
            ring.append(timestamp, bytes([timestamp % 256]))
        record = self.one_byte_frame_record(ring.serialize(0))
        self.assertEqual(decode_ring_buffer(record.ring_buffer)["written"], 4096)
        packets = monitor_packets(record)
        self.assertEqual(
            [packet["timestamp_raw"] for packet in packets], list(range(2, 821))
        )
        self.assertEqual(
            [packet["frames"][0]["data_hex"] for packet in packets],
            [bytes([t % 256]).hex() for t in range(2, 821)],
        )

    def test_persisted_full_ring_equality_keeps_native_rotated_written_count(self):
        from scripts.recorder_buffer import NativeRecorderRing

        ring = NativeRecorderRing(10, 5)
        ring.append(10, b"a")
        ring.append(20, b"b")
        self.assertEqual(len(ring.packets()), 1)
        packets = monitor_packets(self.one_byte_frame_record(ring.serialize(0)))
        self.assertEqual([packet["timestamp_raw"] for packet in packets], [20, 10])
        corrupted = bytearray(ring.serialize(0))
        struct.pack_into("<I", corrupted, 14, 1)
        with self.assertRaisesRegex(SnapshotError, "inside a packet"):
            monitor_packets(self.one_byte_frame_record(bytes(corrupted)))

    def test_native_compact_positive_complement_includes_stored_tail(self):
        from scripts.recorder_buffer import NativeRecorderRing

        for capacity, block_packets, timestamps in (
            (10, 1, (10, 20)),
            (20, 2, (10, 20, 30, 40)),
        ):
            with self.subTest(block_packets=block_packets):
                ring = NativeRecorderRing(capacity, 5, block_packets)
                for timestamp in timestamps:
                    ring.append(timestamp, bytes([timestamp]))
                ring.set_record_area(0, len(timestamps) * 5)
                ring.set_complement(5)
                serial = ring.serialize(1)
                decoded = decode_ring_buffer(serial)
                self.assertGreater(
                    len(bytes.fromhex(decoded["image_hex"])), decoded["capacity"]
                )
                packets = monitor_packets(self.one_byte_frame_record(serial))
                expected = (
                    list(timestamps)
                    + [timestamps[-block_packets] + 5]
                    + list(timestamps[-block_packets + 1 :])
                    if block_packets > 1
                    else list(timestamps) + [timestamps[-1] + 5]
                )
                self.assertEqual(
                    [packet["timestamp_raw"] for packet in packets], expected
                )
                self.assertEqual(
                    [packet["frames"][0]["index"] for packet in packets],
                    [5] * len(expected),
                )

    def test_persisted_phase_one_block_two_keeps_payload_without_guessed_slot(self):
        from scripts.recorder_buffer import NativeRecorderRing

        ring = NativeRecorderRing(11, 5, 2, phase=1)
        ring.append(10, b"a")
        ring.append(20, b"b")
        ring.set_record_area(0, 10)
        for mode in (0, 1):
            with self.subTest(mode=mode):
                packets = monitor_packets(
                    self.one_byte_frame_record(ring.serialize(mode), (5, 8))
                )
                self.assertEqual([p["timestamp_raw"] for p in packets], [10, 20])
                self.assertEqual([p["payload_hex"] for p in packets], ["61", "62"])
                self.assertTrue(
                    all(
                        p["frames"] == []
                        and p["frame_identity"] == "unresolved-native-slot"
                        for p in packets
                    )
                )

    def test_native_gui_block_two_aliases_last_packet_and_wraps_time_sum(self):
        from dataclasses import replace

        from scripts.recorder_buffer import NativeRecorderRing

        first_signal = replace(self.signal(), end_bit=7, patterns=())
        later_signal = replace(first_signal, pid=13, frame_index=8)
        for phase in (0, 1):
            with self.subTest(phase=phase):
                ring = NativeRecorderRing(31, 5, 2, phase=phase)
                for timestamp, payload in (
                    (0x80000001, b"\x0a"),
                    (0x80000003, b"\x14"),
                    (0x80000005, b"\x1e"),
                ):
                    ring.append(timestamp, payload)
                ring.set_record_area(0, 15)
                record = self.one_byte_frame_record(
                    ring.serialize(1), (5, 8) if phase else (5,)
                )
                signals = (first_signal, later_signal) if phase else (first_signal,)
                encoded = [encode_signal_item(signal) for signal in signals]
                record = replace(
                    record,
                    signal_table=struct.pack("<HHI", 1, 0, len(encoded))
                    + b"".join(struct.pack("<I", len(item)) + item for item in encoded),
                )
                raw_packets = monitor_packets(record)
                self.assertEqual(
                    [p["timestamp_raw"] for p in raw_packets],
                    [0x80000001, 0x80000003, 0x80000005],
                )
                samples = monitor_samples(record)
                self.assertEqual(
                    len(samples), 1
                )  # incomplete final block has no GUI sample.
                self.assertEqual(samples[0]["timestamp_raw"], 3)
                self.assertEqual(samples[0]["values"][0]["raw_bits"], 20)
                if phase:
                    unavailable = samples[0]["values"][1]
                    self.assertEqual(unavailable["status"], "unavailable-native-frame")
                    self.assertIsNone(unavailable["raw_bits"])
                    self.assertIsNone(unavailable["value"])
                    invalid_metadata = encode_signal_item(
                        replace(later_signal, precision=10)
                    )
                    malformed = replace(
                        record,
                        signal_table=struct.pack(
                            "<HHII", 1, 0, 1, len(invalid_metadata)
                        )
                        + invalid_metadata,
                    )
                    with self.assertRaisesRegex(
                        SnapshotError, "unsupported signal precision"
                    ):
                        monitor_samples(malformed)
                invalid = encode_signal_item(replace(first_signal, end_bit=8))
                damaged = replace(
                    record,
                    signal_table=struct.pack("<HHII", 1, 0, 1, len(invalid)) + invalid,
                )
                with self.assertRaisesRegex(
                    SnapshotError, "invalid recorded signal bit range"
                ):
                    monitor_samples(damaged)
                self.assertEqual(monitor_packets(record), raw_packets)

    def test_native_gui_slot_table_bounds_preserve_raw_packets(self):
        from dataclasses import replace

        from scripts.recorder_buffer import NativeRecorderRing

        ring = NativeRecorderRing(41, 5, 8)
        for offset in range(8):
            ring.append(0xF0000000 + offset, bytes([offset]))
        ring.set_record_area(0, 40)
        signal = encode_signal_item(replace(self.signal(), end_bit=7, patterns=()))
        record = replace(
            self.one_byte_frame_record(ring.serialize(1)),
            signal_table=struct.pack("<HHII", 1, 0, 1, len(signal)) + signal,
        )
        sample = monitor_samples(record)[0]
        self.assertEqual(sample["timestamp_raw"], 0x10000007)
        self.assertEqual(sample["values"][0]["raw_bits"], 7)
        for count in (0, 9):
            serial = bytearray(record.ring_buffer)
            struct.pack_into("<H", serial, 8, count)
            changed = replace(record, ring_buffer=bytes(serial))
            self.assertEqual(len(monitor_packets(changed)), 8)
            if count:
                with self.assertRaisesRegex(SnapshotError, "eight-slot table"):
                    monitor_samples(changed)
            else:
                self.assertEqual(monitor_samples(changed), [])

    def test_native_ring_partial_tail_and_invalid_complement_fail_closed(self):
        from scripts.recorder_buffer import NativeRecorderRing

        ring = NativeRecorderRing(13, 5)
        ring.append(10, b"a")
        ring.set_record_area(0, 4)
        with self.assertRaisesRegex(SnapshotError, "inside a packet"):
            monitor_packets(self.one_byte_frame_record(ring.serialize(1)))
        ring.set_record_area(0, 5)
        serial = bytearray(ring.serialize(1))
        struct.pack_into("<I", serial, 14, 7)  # selected6 but stored5, missing a byte.
        with self.assertRaisesRegex(SnapshotError, "omits selected"):
            monitor_packets(self.one_byte_frame_record(bytes(serial)))
        ring = NativeRecorderRing(5, 5)
        ring.append(10, b"a")
        ring.set_record_area(0, 5)
        ring.set_complement(1)
        serial = bytearray(ring.serialize(1))
        for offset, value in ((10, 0xFFFFFFFF), (18, 1), (34, 0xFFFFFFFF)):
            damaged = bytearray(serial)
            struct.pack_into("<I", damaged, offset, value)
            with self.subTest(offset=offset), self.assertRaises(SnapshotError):
                monitor_packets(self.one_byte_frame_record(bytes(damaged)))

    def test_native_unallocated_ring_has_only_ten_byte_header(self):
        from dataclasses import replace

        header = bytes.fromhex("01000000000000000200")
        self.assertEqual(
            decode_ring_buffer(header),
            {
                "version": 1,
                "revision": 0,
                "phase": 0,
                "block_packets": 2,
                "buffer_allocated": False,
                "image_hex": "",
            },
        )
        self.assertEqual(
            monitor_packets(
                replace(self.monitor(), frame_table=b"", ring_buffer=header)
            ),
            [],
        )
        for extra in range(1, 28):
            with self.subTest(size=10 + extra), self.assertRaises(SnapshotError):
                decode_ring_buffer(header + bytes(extra))

    def test_ring_corruption_and_unknown_phase(self):
        record = self.monitor()
        for offset, value in (
            (4, 2),
            (10, 0xFFFFFFFF),
            (14, 0xFFFFFFFF),
            (34, 0xFFFFFFFF),
        ):
            damaged = bytearray(record.ring_buffer)
            struct.pack_into("<I", damaged, offset, value)
            changed = MonitorBuffer(
                record.name,
                record.information,
                record.description,
                record.frame_table,
                record.signal_table,
                bytes(damaged),
                record.marker,
                record.flags,
                record.selected_ids,
                record.comment,
                record.additional_ids,
            )
            with self.subTest(offset=offset), self.assertRaises(SnapshotError):
                monitor_packets(changed)


if __name__ == "__main__":
    unittest.main()
