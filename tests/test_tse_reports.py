"""Authored native layout vectors; contains no vendor captures or text."""

from __future__ import annotations

import io
import struct
import unittest
import zipfile
from dataclasses import replace
from typing import Any
from unittest.mock import patch

from scripts import snapshot
from scripts import tse_reports as report


def header(version=0x1000):
    return struct.pack("<IIH", 7, 0xFFFFFF31, version)


def blob(value=b""):
    return struct.pack("<H", len(value)) + value


def signal():
    # 7fd30 mode1: word, three strings, two bytes, descriptor, patterns.
    descriptor = struct.pack("<IIIHBH", 11, 12, 13, 14, 15, 16)
    descriptor += bytes(2) + struct.pack("<4I", 17, 18, 19, 20)
    return (
        struct.pack("<H", 23)
        + blob(b"name")
        + blob(b"unit")
        + blob(b"desc")
        + b"\x03\x04"
        + descriptor
        + bytes(2)
    )


def minimal(layout: Any, expand: int = 0, scope: tuple = ()) -> Any:
    if type(layout) is int:
        return 0
    if isinstance(layout, report._Raw):
        return bytes(layout.size)
    if isinstance(layout, report._Blob):
        return b""
    if isinstance(layout, report._Named):
        return minimal(layout.layout, expand, scope)
    if isinstance(layout, report._Dynamic):
        return minimal(layout.resolve(scope), expand, scope)
    if isinstance(layout, report._Array):
        return (minimal(layout.item, expand - 1),) if expand > 0 else ()
    if isinstance(layout, report._Monitor):
        monitor = snapshot.MonitorBuffer(
            b"", b"", b"", b"", b"", b"", 0, (), (), b"", ()
        )
        return snapshot.TSEDataList(
            monitor,
            (),
            None if layout.version < 0x1004 else 0,
            (),
            b""
            if layout.version < 0x1002
            else bytes(54 if layout.version < 0x1003 else 90),
            b"",
        )
    values = []
    for item in layout:
        values.append(minimal(item, expand, tuple(values)))
    return tuple(values)


class ReportTests(unittest.TestCase):
    def test_ads_uint64_named_values_survive_full_ddr_section(self):
        version = 0x1009
        layout = report._section_layout("DDRData", 0xFFFFFF31, version)
        record = list(minimal(layout.item))
        ads = list(minimal(report._layout("b2190", version)))
        descriptor = (1, 1, 0, 0, 0, 64, (), 0, 0, 0xFFFFFFFF, 0)
        sample = (0xFEDCBA9876543210, b"native ADS display", 0xA5)
        ads[-1] = (
            23,
            b"ADS name",
            b"ADS short",
            b"ADS unit",
            3,
            4,
            descriptor,
            (sample,),
        )
        record[20] = ((tuple(ads), minimal(report._layout("b2560", version))),)
        section = report.ReportSection(
            "DDRData", 7, 0xFFFFFF31, version, (tuple(record),), 1
        )
        wire = report.encode_section(section)
        decoded = report.decode_section("DDRData", wire)
        self.assertEqual(report.encode_section(decoded), wire)
        values = report.view_section(decoded, encoding="ascii")["parameters"]
        item = next(item for item in values if item["identifier_raw"] == 23)
        self.assertEqual(
            (item["name"], item["short_name"], item["unit"]),
            ("ADS name", "ADS short", "ADS unit"),
        )
        self.assertEqual(
            item["values"],
            [
                {
                    "raw": sample[0],
                    "display": "native ADS display",
                    "flags_raw": 0xA5,
                    "display_source": "stored-native-text",
                }
            ],
        )

    def test_ddr_series_invalidity_masks_use_position_and_native_missing_default(self):
        # API/GUI stored mask joins are retained in49/ddr-saved-signal-mask-map;
        # native5eec70 defaults missing entries toTRUE, formatter5ee8f0 replaces text.
        for ads, version in (
            (False, 0x1000),
            (False, 0x1027),
            (True, 0x1009),
            (True, 0x100A),
            (True, 0x1027),
        ):
            with self.subTest(ads=ads, version=version):
                root = list(
                    minimal(report._section_layout("DDRData", 0xFFFFFF31, version).item)
                )
                info = list(
                    minimal(report._layout("b2190" if ads else "b1340", version))
                )
                masks = list(
                    minimal(report._layout("b2560" if ads else "b1760", version))
                )
                side_slot = (20 if version < 0x100A else 19) if ads else 25
                mask_slot = (17 if version < 0x100A else 16) if ads else 22
                signal_layout = (
                    report._layout("85d30", version)
                    if ads
                    else report._signal(version, 7, False)
                )

                def signal(identifier, layout=signal_layout):
                    fields = list(minimal(layout))
                    fields[0], fields[1] = identifier, b"Series"
                    fields[-1] = tuple((n + 10, b"stored", 0xA5) for n in range(4))
                    return tuple(fields)

                info[side_slot] = tuple(signal(n + 100) for n in range(5))
                info[side_slot + 1] = tuple(signal(n + 200) for n in range(5))
                masks[mask_slot] = ((0, 2), (0,), (1,), (1,))
                masks[mask_slot + 1] = ((1, 0, 255), (2,), (0,), (2,))
                root[20 if ads else 7 if version >= 0x1009 else 1] = (
                    (tuple(info), tuple(masks)),
                )
                section = report.ReportSection(
                    "DDRData", 7, 0xFFFFFF31, version, (tuple(root),), 1
                )
                wire = report.encode_section(section)
                decoded = report.decode_section("DDRData", wire)
                rows = report.view_section(decoded, encoding="ascii")["parameters"]
                row = next(row for row in rows if row["identifier_raw"] == 200)
                self.assertFalse(row["native_channel_suppressed"])
                self.assertEqual(
                    [sample["invalidity_raw"] for sample in row["values"]],
                    [1, 0, 255, None],
                )
                self.assertEqual(
                    [sample["invalidity_check"] for sample in row["values"]],
                    [True, False, True, True],
                )
                self.assertEqual(
                    [sample["display"] for sample in row["values"]],
                    [None, "stored", None, None],
                )
                for sample in row["values"]:
                    self.assertEqual(sample["stored_display"], "stored")
                    self.assertEqual(sample["flags_raw"], 0xA5)
                    if sample["invalidity_raw"] is None:
                        self.assertIsNone(sample["invalidity_source_path"])
                    else:
                        node = decoded.records
                        for index in sample["invalidity_source_path"]:
                            node = node[index]
                        self.assertEqual(node, sample["invalidity_raw"])
                    if sample["invalidity_check"]:
                        self.assertEqual(
                            sample["invalid_display_resource"], "DISPLAY_VALUE_INVALID"
                        )
                for identifier in (101, 201, 102, 202):
                    self.assertFalse(
                        next(
                            row for row in rows if row["identifier_raw"] == identifier
                        )["native_channel_suppressed"]
                    )
                for identifier in (103, 203, 104, 204):
                    self.assertTrue(
                        next(
                            row for row in rows if row["identifier_raw"] == identifier
                        )["native_channel_suppressed"]
                    )
                self.assertEqual(report.encode_section(decoded), wire)

    def test_ddr_flat_masks_do_not_inherit_nested_invalid_resource_policy(self):
        for ads, version in ((False, 0x1000), (True, 0x1009), (True, 0x100A)):
            with self.subTest(ads=ads, version=version):
                root = list(
                    minimal(report._section_layout("DDRData", 0xFFFFFF31, version).item)
                )
                info = list(
                    minimal(report._layout("b2190" if ads else "b1340", version))
                )
                masks = list(
                    minimal(report._layout("b2560" if ads else "b1760", version))
                )
                signal = list(minimal(report._signal(version, 7, False)))
                signal[0], signal[-1] = (
                    303,
                    ((1, b"stored", 7), (2, b"stored", 8), (3, b"stored", 9)),
                )
                info[11 if ads else 24] = tuple(signal)
                masks[8 if ads else 21] = 1 if ads and version == 0x1009 else (0, 2)
                root[20 if ads else 1] = ((tuple(info), tuple(masks)),)
                section = report.ReportSection(
                    "DDRData", 7, 0xFFFFFF31, version, (tuple(root),), 1
                )
                raw = report.encode_section(section)
                decoded = report.decode_section("DDRData", raw)
                rows = report.view_section(decoded, encoding="ascii")["parameters"]
                values = next(row for row in rows if row["identifier_raw"] == 303)[
                    "values"
                ]
                self.assertTrue(
                    all("invalidity_check" not in sample for sample in values)
                )
                self.assertEqual(
                    [sample["display"] for sample in values], ["stored"] * 3
                )
                self.assertEqual([sample["flags_raw"] for sample in values], [7, 8, 9])
                self.assertEqual(report.encode_section(decoded), raw)

    def test_ads_extended_signal_original_uint64_sample_wire(self):
        # Original85d30 calls85e10: WORD count, uint64, string, BYTE.
        descriptor = struct.pack("<IIIHBH", 11, 12, 13, 14, 15, 16)
        descriptor += bytes(2) + struct.pack("<4I", 17, 18, 19, 20)
        metadata = (
            23,
            b"name",
            b"unit",
            b"desc",
            3,
            4,
            (11, 12, 13, 14, 15, 16, (), 17, 18, 19, 20),
        )
        samples = ((0xFEDCBA9876543210, b"native text", 0xA5), (0x100000000, b"", 0))
        prefix = struct.pack("<H", 23) + blob(b"name") + blob(b"unit")
        prefix += blob(b"desc") + bytes((3, 4)) + descriptor
        for rows in ((), samples):
            wire = prefix + struct.pack("<H", len(rows))
            wire += b"".join(
                struct.pack("<Q", raw) + blob(text) + bytes((kind,))
                for raw, text, kind in rows
            )
            layout = report._layout("85d30", 0x1009)
            codec = report._Codec(wire)
            decoded = codec.node(layout)
            self.assertEqual(decoded, metadata + (rows,))
            assert codec.cursor is not None
            self.assertEqual(codec.cursor.position, len(wire))
            encoder = report._Codec()
            encoder.node(layout, decoded)
            self.assertEqual(bytes(encoder.output), wire)
            for end in range(len(wire)):
                with (
                    self.subTest(rows=len(rows), end=end),
                    self.assertRaises(report.ReportError),
                ):
                    report._Codec(wire[:end]).node(layout)

    def test_dtc_detail_original_reader_wire(self):
        # 912f0 reads count/BYTE, then915d0 reads count/3DWORD/2strings.
        # These bytes deliberately do not use the layout-driven encoder.
        wire = (
            struct.pack("<HBHIII", 1, 0xA5, 1, 0x11223344, 0x55667788, 0x99AABBCC)
            + blob(b"detail name")
            + blob(b"detail value")
        )
        layout = report._layout("912f0", 0x1009)
        codec = report._Codec(wire)
        decoded = codec.node(layout)
        expected = (
            (
                0xA5,
                (
                    (
                        0x11223344,
                        0x55667788,
                        0x99AABBCC,
                        b"detail name",
                        b"detail value",
                    ),
                ),
            ),
        )
        self.assertEqual(decoded, expected)
        assert codec.cursor is not None
        self.assertEqual(codec.cursor.position, len(wire))
        encoder = report._Codec()
        encoder.node(layout, decoded)
        self.assertEqual(bytes(encoder.output), wire)
        for end in range(len(wire)):
            with self.subTest(end=end), self.assertRaises(report.ReportError):
                report._Codec(wire[:end]).node(layout)

    def test_mil_screen_text_format_category_and_fixed_buffer_bounds(self):
        rows = (
            (b"body", b"prefix ", b" suffix", b"TEXT\0", b"Critical\0"),
            (b"confirm", b"before", b"after", b"HTML\0", b"Confirmation\0"),
        )
        wire = header() + b"".join(
            struct.pack("<H", 1) + b"".join(blob(value) for value in row)
            for row in rows
        )
        section = self.assert_vector("MILMessage", wire)
        view = report.view_section(section, encoding="ascii")
        self.assertEqual(
            view["messages"],
            [
                {
                    "source_path": [0, 0],
                    "screen": "message",
                    "text": "body",
                    "prefix": "prefix ",
                    "suffix": " suffix",
                    "format": "TEXT",
                    "category": "Critical",
                },
                {
                    "source_path": [1, 0],
                    "screen": "confirmation",
                    "text": "confirm",
                    "prefix": "before",
                    "suffix": "after",
                    "format": "HTML",
                    "category": "Confirmation",
                },
            ],
        )
        for field in (3, 4):
            malformed = list(rows[0])
            malformed[field] = b"x" * 17
            with self.subTest(field=field), self.assertRaises(report.ReportError):
                report.decode_section(
                    "MILMessage",
                    header()
                    + b"\x01\0"
                    + b"".join(blob(value) for value in malformed)
                    + b"\0\0",
                )

    def assert_vector(self, family, data):
        value = report.decode_section(family, data)
        self.assertEqual(report.encode_section(value), data)
        for end in range(len(data)):
            with (
                self.subTest(family=family, end=end),
                self.assertRaises(report.ReportError),
            ):
                report.decode_section(family, data[:end])
        with self.assertRaises(report.ReportError):
            report.decode_section(family, data + b"!")
        return value

    def test_native_global_field_vectors(self):
        ini = (
            header()
            + blob(b"authored")
            + struct.pack("<HII", 1, 123, 456)
            + blob(b"entry")
        )
        ini += (
            struct.pack("<HH", 1, 23)
            + blob(b"a")
            + struct.pack("<HH", 1, 45)
            + blob(b"b")
        )
        ini += struct.pack("<HH", 8, 9) + bytes(range(80))
        value = self.assert_vector("IniCarInfo", ini)
        self.assertEqual(value.records[1][0], (123, 456, b"entry"))
        conf = (
            header()
            + blob() * 9
            + struct.pack("<I", 123)
            + blob(b"config")
            + struct.pack("<I", 456)
            + bytes(80)
        )
        self.assert_vector("ConfCarInfo", conf)
        functions = (
            header() + struct.pack("<HII", 1, 0x2716, 0xFFFFFFFF) + blob(b"function")
        )
        self.assertEqual(
            self.assert_vector("FuncName", functions).records[0][1], 0xFFFFFFFF
        )
        mil = (
            header()
            + struct.pack("<H", 1)
            + blob(b"one")
            + blob(b"two")
            + blob(b"three")
            + blob(b"\0\xff")
            + blob(b"raw")
            + bytes(2)
        )
        self.assert_vector("MILMessage", mil)
        market = (
            header(0x1001)
            + struct.pack("<H", 1)
            + blob(b"group")
            + struct.pack("<HI", 1, 0x12345678)
            + struct.pack("<I", 3)
            + b"raw"
        )
        self.assert_vector("MktMonRam", market)
        self.assert_vector("MktMonRamSSR", market)
        self.assert_vector("ROBCommon", header() + bytes(2) + bytes(80))

    def test_native_embedded_image_is_retained_without_extraction(self):
        image = (
            blob(b"../authored.bin")
            + struct.pack("<I", 4)
            + b"\0\xff\x12\x34"
            + struct.pack("<I", 4)
        )
        value = self.assert_vector(
            "ImgFFD", header() + struct.pack("<HI", 1, 99) + image
        )
        self.assertEqual(value.records[0][1][1], b"\0\xff\x12\x34")
        self.assert_vector(
            "OpeFFD", report.encode_section(replace(value, family="OpeFFD"))
        )

    def test_lzma_attachment_dictionary_preflight_before_decoder_allocation(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_LZMA) as archive:
            archive.writestr("authored", b"payload")
        raw = stream.getvalue()
        attachment = report.Attachment(b"image", raw, len(raw))
        self.assertEqual(report.unpack_attachment(attachment)[0]["data"], b"payload")
        name_size, extra_size = struct.unpack_from("<2H", raw, 26)
        start = 30 + name_size + extra_size
        self.assertEqual(struct.unpack_from("<H", raw, start + 2)[0], 5)
        for field, width, value in ((start + 5, "I", 0xFFFFFFFF), (start + 2, "H", 6)):
            damaged = bytearray(raw)
            struct.pack_into("<" + width, damaged, field, value)
            with (
                patch.object(zipfile, "LZMADecompressor") as decoder,
                self.assertRaises(report.ReportError),
            ):
                report.unpack_attachment(
                    report.Attachment(b"image", bytes(damaged), len(raw))
                )
            decoder.assert_not_called()

    def test_native_zip_attachment_conversion_and_bounds(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("../authored.txt", b"in-memory payload")
        archive_bytes = output.getvalue()
        image = (b"authored.zip", archive_bytes + b"opaque padding", len(archive_bytes))
        section = report.ReportSection("ImgFFD", 1, 0, 0x1000, ((7, image),))
        attachment = report.attachments(section)[0]
        members = report.unpack_attachment(attachment)
        self.assertEqual(members[0]["name"], "../authored.txt")
        self.assertEqual(members[0]["data"], b"in-memory payload")
        self.assertEqual(attachment.stored_bytes, image[1])
        for value in (
            replace(attachment, stored_size=len(image[1]) + 1),
            replace(attachment, stored_bytes=b"bad", stored_size=3),
        ):
            with self.assertRaises(report.ReportError):
                report.unpack_attachment(value)
        corrupt = bytearray(archive_bytes)
        offset = corrupt.find(b"PK\x03\x04")
        struct.pack_into("<I", corrupt, offset + 14, 0x12345678)
        # Central CRC is authoritative for ZipFile; corrupt compressed payload.
        corrupt[44] ^= 0x80
        with self.assertRaises(report.ReportError):
            report.unpack_attachment(
                report.Attachment(b"bad", bytes(corrupt), len(corrupt))
            )
        many = io.BytesIO()
        with zipfile.ZipFile(many, "w") as archive:
            for index in range(5):
                archive.writestr(str(index), b"")
        raw = many.getvalue()
        with (
            patch.object(report, "MAX_NODES", 2),
            patch.object(zipfile, "ZipFile") as opened,
        ):
            with self.assertRaises(report.ReportError):
                report.unpack_attachment(report.Attachment(b"many", raw, len(raw)))
            opened.assert_not_called()
        with patch.object(report, "MAX_BYTES", len(archive_bytes)):
            bomb = io.BytesIO()
            with zipfile.ZipFile(
                bomb, "w", compression=zipfile.ZIP_DEFLATED
            ) as archive:
                archive.writestr("large", bytes(10000))
            raw = bomb.getvalue()
            with self.assertRaises(report.ReportError):
                report.unpack_attachment(report.Attachment(b"large", raw, len(raw)))

    def test_ope_inope_assembly_vector_and_signal_modes(self):
        # a6824: common mode2; a6a5b native signal mode1 omits a wide ID.
        common = (
            struct.pack("<H", 41)
            + blob(b"event")
            + blob(b"date")
            + blob(b"description")
        )
        signal_bytes = signal()
        inner = blob(b"item") + struct.pack("<IBBBII", 5, 6, 7, 8, 9, 10)
        inner += signal_bytes + struct.pack("<III", 11, 12, 13) + signal_bytes
        inner += struct.pack("<I", 14) + signal_bytes + bytes(2)
        limits = (
            struct.pack("<III", 1, 2, 3)
            + signal_bytes
            + struct.pack("<III", 4, 5, 6)
            + signal_bytes
        )
        raw = (
            header()
            + struct.pack("<H", 1)
            + common
            + struct.pack("<H", 1)
            + inner
            + limits
            + bytes(2)
        )
        value = self.assert_vector("OpeInope", raw)
        self.assertEqual(value.records[0][1][0][7][0], 23)
        self.assertEqual(value.records[0][1][0][7][1], b"name")

    def test_all_report_families_version_boundaries_and_truncation(self):
        versions = (
            0x1000,
            0x1001,
            0x1002,
            0x1003,
            0x1004,
            0x1005,
            0x1006,
            0x1008,
            0x1009,
            0x100A,
            0x100B,
            0x100C,
            0x1011,
            0x1012,
            0x1015,
            0x1016,
            0x1017,
            0x1018,
            0x101C,
            0x101E,
            0x101F,
            0x1020,
            0x1021,
            0x1022,
            0x1026,
            0x1027,
        )
        for family in report.GLOBAL_FEATURES | report.ECU_FEATURES:
            family_versions = (
                (
                    0x1000,
                    0x100A,
                    0x100C,
                    0x2000,
                    0x2001,
                    0x2002,
                    0x2003,
                    0x2004,
                    0x2005,
                    0x2006,
                    0x2008,
                    0x2009,
                )
                if family in ("ErrRep", "TMRRep")
                else versions
            )
            if family in ("SysChk", "FuelCon"):
                family_versions = tuple(v for v in family_versions if v <= 0x1021)
            for version in family_versions:
                for context in (0, 1) if family == "DTCMon" else (0,):
                    with self.subTest(family=family, version=version, context=context):
                        layout = report._section_layout(family, 0, version, context)
                        value = report.ReportSection(
                            family, 7, 0, version, minimal(layout, 1), context
                        )
                        raw = report.encode_section(value)
                        self.assertEqual(
                            report.decode_section(family, raw, context_mode=context),
                            value,
                        )
                        for end in (0, 4, 8, 10, len(raw) - 1):
                            with self.assertRaises(report.ReportError):
                                report.decode_section(
                                    family, raw[:end], context_mode=context
                                )

    def test_every_truncation_of_nonempty_recovered_family_records(self):
        for family in report.GLOBAL_FEATURES | report.ECU_FEATURES:
            version = (
                0x2009
                if family in ("ErrRep", "TMRRep")
                else 0x1021
                if family in ("SysChk", "FuelCon")
                else 0x1027
            )
            with self.subTest(family=family):
                layout = report._section_layout(family, 0, version)
                value = report.ReportSection(family, 7, 0, version, minimal(layout, 2))
                self.assert_vector(family, report.encode_section(value))

    def test_named_parameter_rows_preserve_stored_display_and_encoding(self):
        fields = list(minimal(report._signal(0x1000, full=False)))
        fields[1:4] = ["Двигатель".encode("cp1251"), b"Engine", b"rpm"]
        fields[4] = 2
        fields[-1] = ((10, b"stored display", 7),)
        section = report.ReportSection("MultiPID", 7, 0, 0x1000, (tuple(fields),))
        view = report.view_section(section, encoding="cp1251")
        row = view["parameters"][0]
        self.assertEqual(
            (row["name"], row["short_name"], row["unit"]),
            ("Двигатель", "Engine", "rpm"),
        )
        self.assertEqual(row["values"][0]["display"], "stored display")
        self.assertEqual(row["values"][0]["flags_raw"], 7)
        self.assertEqual(row["source_path"], [0])
        for encoding in ("utf-8", "no-such-codec"):
            with self.assertRaises(report.ReportError):
                report.view_section(section, encoding=encoding)
        with (
            patch.object(report, "MAX_BYTES", 200),
            self.assertRaises(report.ReportError),
        ):
            report.view_section(section, encoding="cp1251")

    def test_dtc_freeze_frame_fields_are_not_labeled_diagnostic_status(self):
        # AllDTCReadModule parameter0x36 is FrameNo; GUI50bd9d/50c97d
        # aggregates the state/type copied through40e4a0 to7e0f0's wirefields.
        for version in (0x1000, 0x1004, 0x1009, 0x1027):
            layout = report._section_layout("DTCMon", 0, version)
            records = list(minimal(layout, 1))
            record = list(records[0])
            dtc = list(minimal(report._dtc(version)))
            description = 2 + int(version > 0x1003)
            dtc[1], dtc[description] = b"P1234", b"Authored DTC"
            dtc[description + 1], dtc[description + 2] = 0x12345678, 7
            record[1] = (tuple(dtc),)
            records[0] = tuple(record)
            section = report.ReportSection("DTCMon", 7, 0, version, tuple(records))
            decoded = report.decode_section("DTCMon", report.encode_section(section))
            row = report.view_section(decoded, encoding="ascii")["dtcs"][0]
            self.assertEqual(row["freeze_frame_state_raw"], 0x12345678)
            self.assertEqual(row["freeze_frame_number_raw"], 7)
            self.assertNotIn("diagnostic_type_raw", row)
            self.assertNotIn("status", row)

    def test_dtc_freeze_frame_check_matches_native_exact_one_predicate(self):
        # CommandAPI56ff7/572d1 logs TRUE only for native DWORD+30 == 1;
        # normal57670 -> compact+10 -> GUI40b3d0 -> saved+30 preserves it.
        for version in (0x1000, 0x1004, 0x1027):
            for state in (0, 1, 2, 3, 0x10001, 0xFFFFFFFF):
                with self.subTest(version=version, state=state):
                    records = list(
                        minimal(report._section_layout("DTCMon", 0, version), 1)
                    )
                    record = list(records[0])
                    dtc = list(minimal(report._dtc(version)))
                    index = 2 + int(version > 0x1003)
                    dtc[index + 1] = state
                    record[1] = (tuple(dtc),)
                    records[0] = tuple(record)
                    section = report.ReportSection(
                        "DTCMon", 7, 0, version, tuple(records)
                    )
                    raw = report.encode_section(section)
                    decoded = report.decode_section("DTCMon", raw)
                    row = report.view_section(decoded, encoding="ascii")["dtcs"][0]
                    self.assertEqual(row["freeze_frame_state_raw"], state)
                    self.assertIs(row["freeze_frame_data_check"], state == 1)
                    self.assertEqual(report.encode_section(decoded), raw)

    def test_dtc_freeze_frame_marker_follows_native_icon_string_field(self):
        # GUI40b816 compact+1c -> frontend+bc; GFC7e66e finalBLOB.
        # CDTCView8d40bd maps !/!!/!!! to icons174/175/176; retain others.
        for version in (0x1000, 0x1004, 0x1009, 0x1027):
            for marker in (b"!", b"!!", b"!!!", b"?", b"", b"!extra"):
                with self.subTest(version=version, marker=marker):
                    records = list(
                        minimal(report._section_layout("DTCMon", 0, version), 1)
                    )
                    record = list(records[0])
                    dtc = list(minimal(report._dtc(version)))
                    dtc[-2], dtc[-1] = marker, 0xA5
                    record[1] = (tuple(dtc),)
                    records[0] = tuple(record)
                    section = report.ReportSection(
                        "DTCMon", 7, 0, version, tuple(records)
                    )
                    raw = report.encode_section(section)
                    decoded = report.decode_section("DTCMon", raw)
                    row = report.view_section(decoded, encoding="ascii")["dtcs"][0]
                    self.assertEqual(row["freeze_frame_marker"], marker.decode("ascii"))
                    self.assertEqual(row["metadata_flags_raw"], 0xA5)
                    self.assertEqual(report.encode_section(decoded), raw)

    def test_dtc_numeric_status_flags_follow_literal_wire_and_paired_writer(self):
        # API583b5 pairs compact34/38/3c/40 with current/history/pending/permanent
        # strings; GUI40b7f2 and GFC7e0f0 retain the four DWORDs separately.
        for version in (0x1000, 0x1003, 0x1004, 0x1006, 0x1009, 0x1027):
            with self.subTest(version=version):
                permanent = version > 0x1002
                wire = struct.pack("<H", 19) + blob(b"P1234")
                if version > 0x1003:
                    wire += struct.pack("<I" if version >= 0x1009 else "<H", 23)
                wire += blob(b"DTC") + struct.pack("<IB", 2, 7) + blob(b"comment")
                if version > 0x1005:
                    wire += struct.pack("<H", 0)
                markers = (b"X", b"history", b"", b"permanent")
                wire += b"".join(
                    blob(item) for item in markers[: 4 if permanent else 3]
                )
                flags = (1, 2, 0xFFFFFFFF, 0)
                wire += struct.pack(
                    "<4I" if permanent else "<3I", *flags[: 4 if permanent else 3]
                )
                wire += blob(b"!!!") + bytes((0xA5,))
                layout = report._dtc(version)
                codec = report._Codec(wire)
                dtc = codec.node(layout)
                assert codec.cursor is not None
                self.assertEqual(codec.cursor.position, len(wire))
                encoder = report._Codec()
                encoder.node(layout, dtc)
                self.assertEqual(bytes(encoder.output), wire)
                records = list(minimal(report._section_layout("DTCMon", 0, version), 1))
                record = list(records[0])
                record[1] = (dtc,)
                records[0] = tuple(record)
                section = report.ReportSection("DTCMon", 7, 0, version, tuple(records))
                raw = report.encode_section(section)
                decoded = report.decode_section("DTCMon", raw)
                row = report.view_section(decoded, encoding="ascii")["dtcs"][0]
                self.assertEqual(
                    row["status_flags_raw"],
                    {
                        "current": 1,
                        "history": 2,
                        "pending": 0xFFFFFFFF,
                        "permanent": 0 if permanent else None,
                    },
                )
                self.assertEqual(row["status_markers"]["pending"], "")
                self.assertEqual(row["metadata_flags_raw"], 0xA5)
                self.assertEqual(report.encode_section(decoded), raw)

    def test_dtc_marker_columns_use_native_pending_history_order(self):
        # GUI9d6bf3 maps compact24/2c/28/30 to columns17/18/19/20;
        # GUI9d2355 assigns Current/Pending/History/Permanent headers.
        for version in (0x1000, 0x1003, 0x1004, 0x1006, 0x1009, 0x1027):
            layout = report._section_layout("DTCMon", 0, version)
            records = list(minimal(layout, 1))
            record = list(records[0])
            dtc_layout = report._dtc(version)
            dtc = list(minimal(dtc_layout))
            index = 6 + int(version > 0x1003)
            if isinstance(dtc_layout.layout[index], report._Array):
                index += 1
            count = 4 if version > 0x1002 else 3
            dtc[index : index + count] = (
                b"current marker",
                b"history marker",
                b"pending marker",
                b"permanent marker",
            )[:count]
            record[1] = (tuple(dtc),)
            records[0] = tuple(record)
            section = report.ReportSection("DTCMon", 7, 0, version, tuple(records))
            raw = report.encode_section(section)
            decoded = report.decode_section("DTCMon", raw)
            markers = report.view_section(decoded, encoding="ascii")["dtcs"][0][
                "status_markers"
            ]
            self.assertEqual(markers["current"], "current marker")
            self.assertEqual(markers["history"], "history marker")
            self.assertEqual(markers["pending"], "pending marker")
            self.assertEqual(
                markers["permanent"],
                "permanent marker" if version > 0x1002 else None,
            )
            self.assertEqual(report.encode_section(decoded), raw)

    def test_extended_symbolic_report_uses_native_comparison_value(self):
        layout = report._section_layout("DTCMon", 0, 0x1009, 1)
        records = list(minimal(layout, 1))
        record = list(records[0])
        fields = list(minimal(report._signal(0x1009, full=True, extended=True)))
        fields[2:5] = [b"Switch", b"SW", b""]
        fields[5] = 1
        fields[7] = (
            1,
            1,
            0,
            0,
            0,
            8,
            ((99, b"OFF", 0, 0, 0), (99, b"ON", 1, 0, 0)),
            255,
            0,
            255,
            0,
        )
        fields[8] = ((1, 0),)
        record[-3] = ((tuple(fields), 123, 456),)
        records[0] = tuple(record)
        section = report.ReportSection("DTCMon", 7, 0, 0x1009, tuple(records), 1)
        view = report.view_section(section, encoding="ascii")
        self.assertEqual(view["parameters"][0]["values"][0]["display"], "ON")
        # Saved pattern ID99 is not the comparison key. Bound the cross product
        # before any value rendering for a hostile aliased metadata table.
        fields[7] = fields[7][:6] + (fields[7][6] * 200,) + fields[7][7:]
        fields[8] *= 400
        record[-3] = ((tuple(fields), 123, 456),)
        records[0] = tuple(record)
        with self.assertRaises(report.ReportError):
            report.view_section(
                replace(section, records=tuple(records)), encoding="ascii"
            )

    def test_native_context_one_signal_tail_vector(self):
        # 92530 reads 80b80's signal followed by a versioned ID and uint16.
        for version, width in ((0x1008, "H"), (0x1009, "I")):
            raw = (
                struct.pack("<H", 1)
                + signal()
                + struct.pack("<" + width + "H", 123, 456)
            )
            layout = report._layout("92530", version, full=False)
            reader = report._Codec(raw)
            value = reader.node(layout)
            assert reader.cursor is not None
            reader.cursor.end()
            self.assertEqual(value[0][1:], (123, 456))
            writer = report._Codec()
            writer.node(layout, value)
            self.assertEqual(bytes(writer.output), raw)

    def test_health_group_name_follows_concrete_native_record_producer(self):
        for version in (0x1000, 0x1027):
            fields = list(minimal(report._health(version)))
            detail_layout = report._health_detail(version, 0)
            detail = list(minimal(detail_layout))
            index = next(
                i
                for i, part in enumerate(detail_layout)
                if isinstance(part, report._Array)
                and isinstance(part.item, report._Named)
                and part.item.kind == "health-system"
            )
            system = list(minimal(detail_layout[index].item))
            system[2] = b"Native ECU group"
            system[5 if version > 0x100F else 4] = b"Distinct ECU name"
            detail[index] = (tuple(system),)
            fields[-1] = tuple(detail)
            row = list(
                minimal(report._section_layout("HealthCheck", 0x2712, version).item)
            )
            row[1] = tuple(fields)
            section = report.ReportSection(
                "HealthCheck", 0x2712, 0, version, (tuple(row),)
            )
            decoded = self.assert_vector("HealthCheck", report.encode_section(section))
            named = report.view_section(decoded, encoding="ascii")["systems"][0]
            self.assertEqual(named["group_name"], "Native ECU group")
            self.assertEqual(named["short_name"], named["group_name"])
            self.assertEqual(named["name"], "Distinct ECU name")

    def test_health_group_type_uses_native_low_word_classifier(self):
        cases = (
            (0, 0),
            (1, 1),
            (2, 2),
            (3, 3),
            (4, 1),
            (0xFFFF, 3),
            (0x10000, 0),
            (0xFFFFFFFF, 3),
        )
        for version in (0x1000, 0x1027):
            with self.subTest(version=version):
                fields = list(minimal(report._health(version)))
                layout = report._health_detail(version, 0)
                detail = list(minimal(layout))
                index = next(
                    i
                    for i, part in enumerate(layout)
                    if isinstance(part, report._Array)
                    and isinstance(part.item, report._Named)
                    and part.item.kind == "health-system"
                )
                rows = []
                for raw, _ in cases:
                    system = list(minimal(layout[index].item))
                    system[1] = raw
                    rows.append(tuple(system))
                detail[index] = tuple(rows)
                fields[-1] = tuple(detail)
                row = list(
                    minimal(report._section_layout("HealthCheck", 0x2712, version).item)
                )
                row[1] = tuple(fields)
                section = report.ReportSection(
                    "HealthCheck", 0x2712, 0, version, (tuple(row),)
                )
                decoded = self.assert_vector(
                    "HealthCheck", report.encode_section(section)
                )
                systems = report.view_section(decoded, encoding="ascii")["systems"]
                self.assertEqual(
                    [row["ecu_group_type"] for row in systems],
                    [expected for _, expected in cases],
                )
                self.assertEqual(
                    [row["header_values_raw"][1] for row in systems],
                    [raw for raw, _ in cases],
                )

    def test_health_selector_and_parameter_identifier_width(self):
        version = 0x1027
        layout = report._health(version)
        fields = list(minimal(layout))
        fields[2] = 1
        fields[-1] = minimal(report._health_detail(version, 1), 1)
        value = tuple(fields)
        writer = report._Codec()
        writer.node(layout, value)
        reader = report._Codec(bytes(writer.output))
        self.assertEqual(reader.node(layout), value)
        assert reader.cursor is not None
        reader.cursor.end()
        # Native84420 flavor2 always reads a uint32, even though its ordinary
        # signal flavor uses the older uint16 identifier encoding.
        parameters = report._history_parameters(0x1019, 2)
        writer = report._Codec()
        writer.node(parameters, ((b"a", b"b", 1, 2, 3, 4, 0x12345678, 5),))
        self.assertIn(b"\x78\x56\x34\x12", writer.output)

    def test_error_caption_note_calendar_and_image_source_paths(self):
        for family in ("ErrRep", "TMRRep"):
            for version in (0x1000, 0x100C, 0x2000, 0x2003, 0x2004, 0x2008, 0x2009):
                layout = report._section_layout(family, 0, version)
                row = list(minimal(layout, 1)[0])
                first = 1 + 2 * (version > 0x2007) + 2 * (version > 0x2008)
                strings = first + 2 + (version > 0x100B) + (version > 0x1009)
                row[first : first + 2] = (b"20261020", b"123456")
                if version > 0x1009:
                    row[first + 2 + (version > 0x100B)] = 0xFFFFFFFE
                row[strings + 2], row[strings + 3] = (
                    b"Authored caption",
                    b"Authored note",
                )
                row[strings] = b"Authored log identifier"
                row[strings + 1] = b"Authored event cause"
                if version > 0x100B:
                    row[first + 2] = struct.pack(
                        "<8H", 2026, 10, 2, 20, 12, 34, 56, 789
                    )
                if version >= 0x2000:
                    images = strings + 4 + (version >= 0x2003) + (version > 0x2005)
                    row[images + 1] = (17, 23) + tuple(
                        f"contact-{n}".encode() for n in range(7)
                    )
                    words = 11 if version > 0x2004 else 10
                    row[images + 2] = (0,) * words + tuple(
                        f"preference-{n}".encode() for n in range(12)
                    )
                    application = list(row[images + 3])
                    application[:3] = (b"18.00.000", b"tool-version", b"os-build")
                    if version > 0x2003:
                        application[3:] = (b"Authored VIM", b"firmware", b"dll", b"api")
                    row[images + 3] = tuple(application)
                section = report.ReportSection(family, 1, 0, version, (tuple(row),))
                view = report.view_section(section, encoding="ascii")
                self.assertEqual(
                    view["error_reports"][0]["caption"], "Authored caption"
                )
                self.assertEqual(view["error_reports"][0]["note"], "Authored note")
                self.assertEqual(
                    view["error_reports"][0]["event_cause"], "Authored event cause"
                )
                self.assertEqual(
                    view["error_reports"][0]["log_identifier"],
                    "Authored log identifier",
                )
                self.assertEqual(view["error_reports"][0]["date_text"], "20261020")
                self.assertEqual(view["error_reports"][0]["time_text"], "123456")
                self.assertEqual(
                    view["error_reports"][0]["tick_count_ms"],
                    0xFFFFFFFE if version > 0x1009 else None,
                )
                if version >= 0x2000:
                    item = view["error_reports"][0]
                    self.assertEqual(item["contact"]["user_name"], "contact-0")
                    self.assertEqual(item["contact"]["dealer_type_raw"], 17)
                    self.assertEqual(item["contact"]["default_brand_id_raw"], 23)
                    self.assertEqual(item["contact"]["shop_url"], "contact-6")
                    self.assertEqual(item["hotkeys"]["menu_1"], "preference-0")
                    self.assertEqual(item["hotkeys"]["snapshot"], "preference-10")
                    self.assertEqual(item["saved_file_directory"], "preference-11")
                    self.assertEqual(item["application_product_version"], "18.00.000")
                    self.assertEqual(item["communication_tool_version"], "tool-version")
                    self.assertEqual(item["denso_os_build"], "os-build")
                    if version > 0x2003:
                        self.assertEqual(
                            item["device"],
                            {
                                "name": "Authored VIM",
                                "firmware_version": "firmware",
                                "dll_version": "dll",
                                "api_version": "api",
                            },
                        )
                    else:
                        self.assertNotIn("device", item)
                if version > 0x100B:
                    self.assertEqual(
                        view["error_reports"][0]["system_time_raw"][7], 789
                    )
                self.assertTrue(
                    all(image["source_path"][0] == 0 for image in view["images"])
                )

    def test_error_preferences_follow_named_profile_producer(self):
        # ER6c00..6d0d/117a2 joins GUIc2a228..c2a538 named profile keys.
        for family in ("ErrRep", "TMRRep"):
            for version in (0x2000, 0x2004, 0x2005, 0x2009):
                layout = report._section_layout(family, 0, version)
                row = list(minimal(layout, 1)[0])
                first = 1 + 2 * (version > 0x2007) + 2 * (version > 0x2008)
                strings = first + 4
                images = strings + 4 + (version >= 0x2003) + (version > 0x2005)
                words = 11 if version > 0x2004 else 10
                row[images + 2] = tuple(range(11, 11 + words)) + (b"",) * 12
                section = report.ReportSection(family, 1, 0, version, (tuple(row),))
                encoded = report.encode_section(section)
                decoded = report.decode_section(family, encoded)
                settings = report.view_section(decoded, encoding="ascii")[
                    "error_reports"
                ][0]["settings"]
                self.assertEqual(settings["vehicle_brand_id_raw"], 11)
                self.assertEqual(settings["font_size"], 12)
                self.assertEqual(settings["language_id_raw"], 13)
                self.assertEqual(
                    settings["unit_selectors_raw"],
                    {
                        "vehicle_speed": 14,
                        "temperature": 15,
                        "weight": 16,
                        "air_flow": 17,
                        "air_pressure": 18,
                        "vapor_pressure": 19,
                        "fuel_pressure": 20,
                    },
                )
                self.assertEqual(
                    settings["additional_selector_raw"], 21 if words == 11 else None
                )
                self.assertEqual(report.encode_section(decoded), encoded)

    def test_named_function_labels_preserve_native_lookup_identifiers(self):
        section = report.ReportSection(
            "FuncName", 1, 0, 0x1000, ((42, 7, b"Authored function"),)
        )
        self.assertEqual(
            report.view_section(section, encoding="ascii")["functions"],
            [
                {
                    "source_path": [0],
                    "identifiers_raw": (42, 7),
                    "name": "Authored function",
                }
            ],
        )

    def test_memory_capture_native_labels_sizes_and_versioned_identifiers(self):
        for family in ("MktMonRam", "MktMonRamSSR"):
            for version in (0x1000, 0x1001):
                blocks = tuple(
                    (n, b"abc") if version > 0x1000 else (b"abc",) for n in (3, 7)
                )
                section = report.ReportSection(
                    family, 1, 0, version, ((b"Saved capture", blocks),)
                )
                row = report.view_section(section, encoding="ascii")["memory_captures"][
                    0
                ]
                self.assertEqual(row["name"], "Saved capture")
                self.assertEqual(row["total_bytes"], 6)
                self.assertEqual(row["block_count"], 2)
                self.assertEqual(
                    row["blocks"][1],
                    {"identifier_raw": 7 if version > 0x1000 else None, "size": 3},
                )
                with (
                    patch.object(report, "MAX_BYTES", 100),
                    self.assertRaises(report.ReportError),
                ):
                    report.view_section(section, encoding="ascii")

    def test_ddr_header_support_value_pairs_follow_command_producer(self):
        for version in (0x1004, 0x1005, 0x1009, 0x1027):
            with self.subTest(version=version):
                layout = report._section_layout("DDRData", 0x272A, version)
                row = list(minimal(layout.item))
                index = 7 + 2 * (version > 0x1004) + 4 * (version >= 0x1009)
                pairs = tuple(
                    value for i in range(13) for value in (i % 2, 0xF0000000 + i)
                )
                row[index] = pairs
                row[index - 4] = 12345
                row[index - 1] = 11877
                section = report.ReportSection(
                    "DDRData", 0x272A, 0, version, (tuple(row),)
                )
                decoded = self.assert_vector("DDRData", report.encode_section(section))
                view = report.view_section(decoded, encoding="ascii")
                self.assertEqual(
                    view["ddr_headers"],
                    [
                        {
                            "source_path": [0, index - 4],
                            "maximum_recording_count": 12345,
                        },
                        {
                            "source_path": [0, index - 1],
                            "specification_number_raw": 11877,
                        },
                    ],
                )
                entries = view["ddr_attributes"]
                # P5 may fill the final171 slot from logical177; the wire has no ID.
                self.assertNotIn("logical_id_raw", entries[-1])
                self.assertEqual(
                    entries,
                    [
                        {
                            "source_path": [0, index, 2 * i],
                            "normal_logical_id": 159 + i,
                            "present_raw": i % 2,
                            "value_raw": 0xF0000000 + i,
                        }
                        for i in range(13)
                    ],
                )

    def test_operation_history_content_time_fields_follow_native_producer(self):
        for version in (0x1000, 0x1004, 0x1027):
            with self.subTest(version=version):
                layout = report._section_layout("OpeHis", 0x2720, version)
                row = list(minimal(layout.item))
                event = list(minimal(layout.item[2].item))
                event[-2] = b"Factor"
                event[-1] = (
                    (91, 0xA5, b"Contents", b"Auxiliary", 12345, b"Saved text", 7),
                )
                row[2] = (tuple(event),)
                section = report.ReportSection(
                    "OpeHis", 0x2720, 0, version, (tuple(row),)
                )
                decoded = self.assert_vector("OpeHis", report.encode_section(section))
                entries = report.view_section(decoded, encoding="ascii")[
                    "history_contents"
                ]
                self.assertEqual(
                    entries,
                    [
                        {
                            "source_path": [0, 2, 0, len(event) - 1, 0],
                            "identifier_raw": 91,
                            "metadata_byte_raw": 0xA5,
                            "contents": "Contents",
                            "strings": ["Contents", "Auxiliary", "Saved text"],
                            "time_info_raw": 12345,
                            "display_type_raw": 7,
                        }
                    ],
                )

    def test_operation_history_current_summary_literal_wire_consumer(self):
        cases = [
            (
                (0xFFFFFFFF, 93784, 0x80000000),
                (0, 4, 0),
                ("-1", "1d 02h 03m", "-2147483648"),
                None,
            ),
            ((7, 0, 8), (0, 4, 0), ("7", "00h 00m", "8"), None),
            ((7, 59, 8), (0, 4, 0), ("7", "00h 00m", "8"), None),
            ((7, 60, 8), (0, 4, 0), ("7", "00h 01m", "8"), None),
            ((7, 86399, 8), (0, 4, 0), ("7", "23h 59m", "8"), None),
            ((7, 0xFFFFFFFF, 8), (0, 4, 0), ("7", "49710d 06h 28m", "8"), None),
            ((7, 60, 8), (0x4001, 4, 0), ("-", "00h 01m", "8"), None),
            ((7, 60, 8), (0, 0xC000, 0x4000), ("7", "-", "-"), None),
            ((7, 60, 8), (0x4000, 0x8000, 0), (None, None, None), "STRING_QUESTION"),
            ((7, 60, 8), (0, 0x8001, 0), ("7", None, "8"), None),
            ((7, 60, 8), (4, 4, 1), (None, "00h 01m", None), None),
        ]
        for index in range(3):
            flags = [0, 4, 0]
            flags[index] = 0x8000
            cases.append(((7, 60, 8), tuple(flags), (None,) * 3, "STRING_QUESTION"))
        for version in (0x1000, 0x1004, 0x1027):
            for values, flags, displays, resource in cases:
                with self.subTest(version=version, flags=flags, values=values):
                    # Native A4C10 sixWORD/BYTE, A4CD0 string/DWORD/string/WORD.
                    wire = struct.pack("<6HB", 2026, 10, 21, 1, 2, 3, 0xFF)
                    if version >= 0x1004:
                        wire += struct.pack("<H", 3)
                    wire += b"".join(
                        blob(b"Name")
                        + struct.pack("<I", value)
                        + blob(b"Unit")
                        + struct.pack("<H", flag)
                        for value, flag in zip(values, flags)
                    )
                    codec = report._Codec(wire)
                    stored = codec.node(report._layout("a4c10", version))
                    assert codec.cursor is not None
                    self.assertEqual(codec.cursor.position, len(wire))
                    layout = report._section_layout("OpeHis", 0x2720, version)
                    row = list(minimal(layout.item))
                    row[1] = stored
                    section = report.ReportSection(
                        "OpeHis", 0x2720, 0, version, (tuple(row),)
                    )
                    raw = report.encode_section(section)
                    decoded = report.decode_section("OpeHis", raw)
                    view = report.view_section(decoded, encoding="ascii")
                    entries = view["history_time_information"]
                    self.assertEqual(
                        tuple(item["current_summary_display"] for item in entries),
                        displays,
                    )
                    for index, entry in enumerate(entries):
                        self.assertEqual(entry["time_info_raw"], values[index])
                        self.assertEqual(entry["display_type_raw"], flags[index])
                        self.assertEqual(entry["current_summary_resource"], resource)
                        expected_source = (
                            "native-current-summary-resource"
                            if resource
                            else (
                                "native-current-summary-format"
                                if displays[index] is not None
                                else "native-current-summary-unresolved"
                            )
                        )
                        self.assertEqual(
                            entry["current_summary_display_source"], expected_source
                        )
                    self.assertEqual(
                        view["history_headers"][0]["normal_coefficient_low_byte_raw"],
                        0xFF,
                    )
                    self.assertEqual(
                        view["history_headers"][0]["metadata_byte_raw"], 0xFF
                    )
                    self.assertEqual(report.encode_section(decoded), raw)

    def test_operation_history_current_summary_preserves_count_boundary(self):
        for count in (0, 1, 4):
            layout = report._section_layout("OpeHis", 0x2720, 0x1004)
            row = list(minimal(layout.item))
            stored = list(row[1])
            stored[7] = tuple(
                (b"Name", 7, b"Unit", 0x8000 if i == 3 else 0) for i in range(count)
            )
            row[1] = tuple(stored)
            section = report.ReportSection("OpeHis", 0x2720, 0, 0x1004, (tuple(row),))
            wire = report.encode_section(section)
            decoded = report.decode_section("OpeHis", wire)
            entries = report.view_section(decoded, encoding="ascii")[
                "history_time_information"
            ]
            self.assertEqual(len(entries), count)
            for index, entry in enumerate(entries):
                if index < 3:
                    self.assertEqual(entry["current_summary_resource"], None)
                    self.assertEqual(
                        entry["current_summary_display"], None if index == 1 else "7"
                    )
                else:
                    self.assertNotIn("current_summary_display", entry)
                    self.assertEqual(entry["display_type_raw"], 0x8000)
            self.assertEqual(report.encode_section(decoded), wire)

    def test_operation_history_current_time_native_producer(self):
        for version in (0x1000, 0x1004, 0x1027):
            with self.subTest(version=version):
                layout = report._section_layout("OpeHis", 0x2720, version)
                row = list(minimal(layout.item))
                stored = list(row[1])
                stored[:7] = [2026, 10, 20, 23, 59, 58, 0xA5]
                stored[7] = tuple(
                    (b"Time", 101 + i, b"Display", 7 + i) for i in range(3)
                )
                row[1] = tuple(stored)
                section = report.ReportSection(
                    "OpeHis", 0x2720, 0, version, (tuple(row),)
                )
                wire = report.encode_section(section)
                decoded = self.assert_vector("OpeHis", wire)
                view = report.view_section(decoded, encoding="ascii")
                self.assertEqual(
                    view["history_time_information"],
                    [
                        {
                            "source_path": [0, 1, 7, i],
                            "strings": ["Time", "Display"],
                            "time_info_raw": 101 + i,
                            "display_type_raw": 7 + i,
                            "current_summary_display": None,
                            "current_summary_resource": None,
                            "current_summary_display_source": "native-current-summary-unresolved",
                        }
                        for i in range(3)
                    ],
                )
                entries = view["history_headers"]
                self.assertEqual(
                    entries,
                    [
                        {
                            "source_path": [0, 1],
                            "current_time": {
                                "year": 2026,
                                "month": 10,
                                "day": 20,
                                "hour": 23,
                                "minute": 59,
                                "second": 58,
                            },
                            "metadata_byte_raw": 0xA5,
                            "normal_coefficient_low_byte_raw": 0xA5,
                        }
                    ],
                )

    def test_ini_choices_follow_select_car_type_vin10_response(self):
        section = report.ReportSection(
            "IniCarInfo",
            1,
            0,
            0x1000,
            (
                b"Authored identity",
                ((0x12345678, 0x87654321, b"Choice A"),),
                ((0xFFFF, b"Choice B"),),
                ((17, b"Choice C"),),
                0,
                0,
                bytes(80),
            ),
        )
        rows = report.view_section(section, encoding="ascii")["vehicle"]
        self.assertEqual(rows[0]["name"], "selection_identity")
        self.assertEqual(rows[0]["value"], "Authored identity")
        self.assertEqual(rows[1]["identifiers_raw"], (0x12345678, 0x87654321))
        self.assertEqual(rows[2]["identifiers_raw"], (0xFFFF,))
        self.assertEqual(rows[3]["source_path"], [3, 0, 1])
        self.assertEqual(rows[3]["value"], "Choice C")
        self.assertEqual(rows[0]["field"], "vin_code")
        self.assertEqual(rows[1]["field"], "selection_name")
        self.assertEqual(rows[1]["category_id_raw"], 0x12345678)
        self.assertEqual(rows[1]["selection_id_raw"], 0x87654321)
        self.assertEqual(rows[2]["field"], "car_information")
        self.assertEqual(rows[2]["information_id_raw"], 0xFFFF)
        self.assertEqual(rows[3]["field"], "option_name")
        self.assertEqual(rows[3]["selection_id_raw"], 17)
        wire = report.encode_section(section)
        decoded = report.decode_section("IniCarInfo", wire)
        self.assertEqual(
            report.view_section(decoded, encoding="ascii")["vehicle"], rows
        )

    def test_named_vehicle_fields_follow_native_converter_version_branches(self):
        for version in (0x1000, 0x100C, 0x100D, 0x1027):
            layout = report._section_layout("ConfCarInfo", 0, version)
            values = list(minimal(layout))
            values[2], values[10] = b"2019", b"Authored vehicle"
            if version > 0x100C:
                values[15], values[16] = b"Authored engine", b"2020"
            section = report.ReportSection("ConfCarInfo", 1, 0, version, tuple(values))
            rows = report.view_section(section, encoding="ascii")["vehicle"]
            self.assertEqual(
                rows[0],
                {
                    "source_path": [10],
                    "name": "vehicle_type",
                    "value": "Authored vehicle",
                },
            )
            self.assertEqual(rows[1]["value"], "2019")
            self.assertEqual(len(rows), 4 if version > 0x100C else 2)
            if version > 0x100C:
                self.assertEqual(rows[2]["value"], "Authored engine")
                self.assertEqual(rows[3]["value"], "2020")

    def test_named_native_monitor_playback_and_history_labels(self):
        indexes = [0] * 256
        lengths = [0] * 256
        indexes[0], lengths[5] = 5, 2
        frames = struct.pack("<HHI256H256HI", 2, 0, 1, *indexes, *lengths, 0)
        packet = struct.pack("<I", 100) + b"\x00\x2a"
        ring = (
            struct.pack(
                "<HHIH7I", 1, 0, 0, 1, len(packet), 0, 0, 0, 0, len(packet), len(packet)
            )
            + packet
        )
        signal = snapshot.SignalItem(
            4,
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
            1,
            0,
            0,
            0,
            0xFFFFFFFF,
            (),
            (42, 0, 0),
        )
        encoded = snapshot.encode_signal_item(signal)
        monitor = snapshot.MonitorBuffer(
            b"capture",
            b"",
            b"authored",
            frames,
            struct.pack("<HHII", 1, 0, 1, len(encoded)) + encoded,
            ring,
            100,
            (),
            (5,),
            b"",
            (),
        )
        datalist = snapshot.TSEDataList(monitor, (), None, (), b"", b"")
        section = report.ReportSection("SysChk", 1, 0, 0x1000, ((datalist, bytes(80)),))
        view = report.view_section(section, encoding="ascii")
        graph = view["monitors"][0]
        self.assertEqual(graph["name"], "capture")
        self.assertEqual(graph["samples"][0]["timestamp_raw"], 100)
        self.assertEqual(graph["samples"][0]["values"][0]["raw"], 42)
        self.assertEqual(graph["signals"][0]["unit"], "rpm")
        with (
            patch.object(report, "MAX_BYTES", len(report.encode_section(section)) + 1),
            patch.object(snapshot, "monitor_samples") as playback,
            self.assertRaises(report.ReportError),
        ):
            report.view_section(section, encoding="ascii")
        playback.assert_not_called()
        for family in ("Oscillo", "AFO2Sn"):
            layout = report._section_layout(family, 0, 0x1000)
            fields = list(minimal(layout, 1)[0])
            fields[5] = (
                (
                    44,
                    b"scope",
                    b"authored",
                    (5,),
                    frames,
                    monitor.signal_table,
                    ring,
                    (5,),
                    (),
                ),
            )
            scope = report.ReportSection(family, 1, 0, 0x1000, (tuple(fields),))
            graph = report.view_section(scope, encoding="ascii")["monitors"][0]
            self.assertEqual(graph["capture_identifier_raw"], 44)
            self.assertEqual(graph["samples"][0]["values"][0]["raw"], 42)
        layout = report._section_layout("ABSHis", 0, 0x1000, 0)
        row = list(minimal(layout, 2)[0])
        event = list(row[1][0])
        event[0] = b"Stored event name"
        row[1] = (tuple(event),)
        history = report.ReportSection("ABSHis", 1, 0, 0x1000, (tuple(row),))
        self.assertEqual(
            report.view_section(history, encoding="ascii")["events"][0]["name"],
            "Stored event name",
        )

    def test_strict_malformed_counts_versions_and_aggregate_budgets(self):
        for version in (0xFFF, 0x1028):
            with self.assertRaises(report.ReportError):
                report.decode_section("FuncName", header(version) + bytes(2))
        with self.assertRaises(report.ReportError):
            report.decode_section("unknown", header() + bytes(2))
        with self.assertRaises(report.ReportError):
            report.decode_section("FuncName", header() + b"\xff\xff")
        with self.assertRaises(report.ReportError):
            report.decode_section("FuncName", header() + bytes(2), context_mode=True)
        item = report.decode_section(
            "FuncName", header() + struct.pack("<HIIH", 1, 3, 4, 0)
        )
        with (
            patch.object(report, "MAX_BYTES", 12),
            self.assertRaises(report.ReportError),
        ):
            report.decode_section("FuncName", report.encode_section(item))
        with (
            patch.object(report, "MAX_NODES", 3),
            self.assertRaises(report.ReportError),
        ):
            report.encode_section(item)
        with (
            patch.object(report, "MAX_BYTES", 100),
            self.assertRaises(report.ReportError),
        ):
            item.to_dict()
        aliased = replace(item, records=item.records * 100)
        with (
            patch.object(report, "MAX_NODES", 100),
            self.assertRaises(report.ReportError),
        ):
            report.encode_section(aliased)
        with self.assertRaises(report.ReportError):
            report.encode_section(replace(item, records=((True, 4, b""),)))

    def test_aliased_ecu_sections_share_decode_and_file_type_controls_context(self):
        template = snapshot.create_tse_header(
            snapshot.TSEHeader(
                "TSE", 4, 0x102C, 0, 0, 0, 0, b"", b"", (1, 2), (0x2716,), b""
            )
        )
        layout = report._section_layout("DTCMon", 0, 0x100C, 1)
        section = report.ReportSection("DTCMon", 7, 0, 0x100C, minimal(layout, 1), 1)
        raw = report.encode_section(section)
        fragments = tuple(
            raw if e["tag"].startswith("DTCMon") else b""
            for e in template.metadata["index_entries"]
        )
        file = snapshot.assemble_tse(template, fragments)
        entries = [
            e for e in file.metadata["index_entries"] if e["tag"].startswith("DTCMon")
        ]
        data = bytearray(file.source)
        struct.pack_into("<I", data, entries[1]["position"], entries[0]["offset"])
        # Keep the now-unreferenced second body outside the first section fence.
        # An unrelated indexed terminal section supplies its original boundary.
        terminal = next(
            e for e in file.metadata["index_entries"] if e["tag"] == "ErrRep"
        )
        struct.pack_into("<I", data, terminal["position"], entries[1]["offset"])
        aliased = snapshot.parse_tse(bytes(data))
        with patch.object(
            report, "decode_section", wraps=report.decode_section
        ) as decode:
            items = report.reports(aliased)
            self.assertEqual(decode.call_count, 1)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["context_mode"], 1)
        self.assertEqual(items[0]["records"], items[1]["records"])
        updated = report.replace_section(aliased, section, 0)
        self.assertEqual(updated.source, aliased.source)

    def test_native_mil_and_ddr_index_names_follow_writer_and_export_bridges(self):
        # 680f0: MILMessage index+70; DDRData index+80.
        # b67e0/4c8a0 sets271b message lists; afa30 reads272a capture list.
        mil = report.ReportSection(
            "MILMessage",
            7,
            0xFFFFFF31,
            0x1000,
            (((b"a", b"b", b"c", b"binary1", b"binary2"),), ()),
        )
        ddr = report.ReportSection(
            "DDRData",
            8,
            0xFFFFFF31,
            0x1000,
            minimal(report._section_layout("DDRData", 0xFFFFFF31, 0x1000), 1),
        )
        self.assertEqual(len(report.view_section(ddr, encoding="ascii")["captures"]), 1)
        payloads = {
            "MILMessage": report.encode_section(mil),
            "DDRData": report.encode_section(ddr),
        }
        for features, expected in (
            ((0x271B,), ("MILMessage",)),
            ((0x272A,), ("DDRData",)),
            ((0x271B, 0x272A), ("MILMessage", "DDRData")),
        ):
            template = snapshot.create_tse_header(
                snapshot.TSEHeader(
                    "TSE", 1, 0x102C, 0, 0, 0, 0, b"", b"", (), features, b""
                )
            )
            file = snapshot.assemble_tse(
                template,
                tuple(
                    payloads.get(e["tag"].rstrip("\0"), b"")
                    for e in template.metadata["index_entries"]
                ),
            )
            self.assertEqual(
                tuple(row["family"] for row in report.reports(file)), expected
            )
            for family in expected:
                offset, section = report.select_report_section(file, family)
                self.assertEqual(offset, file.metadata["global_index"][family])
                self.assertEqual(report.encode_section(section), payloads[family])
            for family in payloads.keys() - set(expected):
                with self.assertRaises(report.ReportError):
                    report.select_report_section(file, family)

    def test_index_feature_gates_replacement_and_later_offsets(self):
        template = snapshot.create_tse_header(
            snapshot.TSEHeader(
                "TSE", 1, 0x102C, 0, 0, 0, 0, b"", b"", (), (0x2711, 0x2725), b""
            )
        )
        ini = header() + blob() + bytes(6) + bytes(4) + bytes(80)
        conf = header() + blob() * 9 + bytes(4) + blob() + bytes(4) + bytes(80)
        func = header() + struct.pack("<HII", 1, 3, 4) + blob(b"old")
        payloads = {"IniCarInfo": ini, "ConfCarInfo": conf, "FuncName": func}
        file = snapshot.assemble_tse(
            template,
            tuple(
                payloads.get(e["tag"].rstrip("\0"), b"")
                for e in template.metadata["index_entries"]
            ),
        )
        self.assertEqual([r["family"] for r in report.reports(file)], list(payloads))
        offset, selected = report.select_report_section(file, "ConfCarInfo")
        self.assertEqual(offset, file.metadata["global_index"]["ConfCarInfo"])
        self.assertEqual(report.encode_section(selected), conf)
        invalid_families: tuple[Any, ...] = ([], {}, None, b"ConfCarInfo", True)
        for invalid_family in invalid_families:
            with self.assertRaises(report.ReportError):
                report.select_report_section(file, invalid_family)
        for family, ecu in (
            ("HealthCheck", None),
            ("ConfCarInfo", 0),
            ("DTCMon", True),
        ):
            with self.assertRaises(report.ReportError):
                report.select_report_section(file, family, ecu)
        section = report.decode_section("ConfCarInfo", conf)
        values = list(section.records)
        values[0] = b"longer authored field"
        updated = report.replace_section(file, replace(section, records=tuple(values)))
        self.assertEqual(
            report.reports(updated)[-1]["records"], report.reports(file)[-1]["records"]
        )
        self.assertGreater(
            updated.metadata["global_index"]["FuncName"],
            file.metadata["global_index"]["FuncName"],
        )
        with self.assertRaises(report.ReportError):
            report.replace_section(file, replace(section, family="HealthCheck"))
        with (
            patch.object(report, "MAX_BYTES", 500),
            self.assertRaises(report.ReportError),
        ):
            report.reports(file)


class AllDTCXMLTests(unittest.TestCase):
    def fixture(self):
        return b"<Report><Version>1</Version><VehicleInfo><VehicleName>Authored</VehicleName></VehicleInfo><AllDiag><array-ECUInfo><ECUInfo><ECUId>42</ECUId><ECUName>ECU A</ECUName><array-DTCInfo><DTCInfo><DTCTypeId>3</DTCTypeId><DTCTypeName>Stored category</DTCTypeName><DTCDispValue>P0123</DTCDispValue><DTCName>Authored fault</DTCName><StatusGridName>Stored status</StatusGridName><array-FFDInfo><FFDInfo><FrameNo>2</FrameNo><FFDType>7</FFDType></FFDInfo></array-FFDInfo></DTCInfo></array-DTCInfo></ECUInfo><ECUInfo><ECUId>-2</ECUId><array-DTCInfo><DTCInfo><DTCTypeId>4</DTCTypeId></DTCInfo></array-DTCInfo></ECUInfo></array-ECUInfo></AllDiag></Report>"

    def test_native_parameter_and_nine_export_adapters(self):
        reader = report.parse_all_dtc_xml(self.fixture())
        self.assertEqual(reader.get_parameter_length_w(0), 4)
        self.assertEqual(reader.get_parameter_length_a(0), 2)
        self.assertEqual(reader.get_parameter_w(0, 4), b"1\x00\x00\x00")
        self.assertEqual(reader.get_parameter_a(0, 2), b"1\x00")
        self.assertEqual(reader.get_parameter(19, (0, 0, 1)), -2)
        self.assertEqual(reader.get_parameter_w(19, 4, (0, 0, 1)), b"\xfe\xff\xff\xff")
        self.assertEqual(reader.get_dtc_number(3), ((42, 1), (0xFFFFFFFE, 0)))
        with self.assertRaises(report.ReportError):
            reader.get_parameter_a(0, 1)
        self.assertEqual(reader.get_api_last_error(), 1)
        self.assertEqual(reader.get_parameter_a(0, 2), b"1\x00")
        self.assertEqual(reader.get_api_last_error(), 1)
        with self.assertRaises(report.ReportError):
            reader.get_parameter_length_w(19)
        self.assertEqual(reader.get_api_last_error(), 2)
        # Native length dispatch rejects the numeric kind before looking up
        # its absent Index node, so missing numeric parameters still give2.
        with self.assertRaises(report.ReportError):
            reader.get_parameter_length_w(3)
        self.assertEqual(reader.get_api_last_error(), 2)
        with self.assertRaises(report.ReportError):
            reader.get_parameter(118)
        self.assertEqual(reader.get_api_last_error(), 4)
        reader.close_xml()
        reader.close_xml()
        with self.assertRaises(report.ReportError):
            reader.get_parameter(0)
        self.assertEqual(reader.get_api_last_error(), 5)
        reader.open_bytes(self.fixture())
        self.assertEqual(reader.get_parameter(0), "1")

    def test_all_118_native_schema_parameters(self):
        import xml.etree.ElementTree as ET

        root = ET.Element("Report")
        for parameter, (path, kind) in enumerate(report.ALL_DTC_PARAMETERS):
            node = root
            for part in path.split("/"):
                found = node.find(part)
                node = ET.SubElement(node, part) if found is None else found
            value = "7" if kind in (5, 6) else "true" if kind == 10 else "Authored"
            if parameter == 2:
                value = bytes((251 - b) & 255 for b in b"Authored").hex().encode().hex()
            node.text = value
        reader = report.parse_all_dtc_xml(ET.tostring(root))
        for parameter, (_, kind) in enumerate(report.ALL_DTC_PARAMETERS):
            with self.subTest(parameter=parameter):
                value = reader.get_parameter(parameter)
                self.assertEqual(
                    value, 7 if kind in (5, 6) else True if kind == 10 else "Authored"
                )
                data = reader.get_parameter_w(parameter, 100)
                self.assertEqual(
                    len(data), 4 if kind in (5, 6) else 1 if kind == 10 else 18
                )

    def test_native_file_open_w_a_close_and_load_adapters(self):
        import tempfile
        from pathlib import Path

        data = b"\xfe\xff" + self.fixture().decode().encode("utf-16be")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "日本.xml"
            path.write_bytes(data)
            reader = report.AllDTCXML()
            reader.open_xml_w(str(path))
            self.assertEqual(reader.source, data)
            self.assertEqual(reader.get_parameter(0), "1")
            reader.close_xml()
            reader.open_xml_a(str(path).encode("cp932"))
            self.assertEqual(reader.get_parameter(19), 42)
            reader.close_xml()
            loaded = report.load_all_dtc_xml(str(path))
            self.assertEqual(loaded.source, data)
            self.assertEqual(loaded.get_dtc_number(3), ((42, 1), (0xFFFFFFFE, 0)))
            with self.assertRaises(report.ReportError):
                reader.open_xml_a(b"\x81")
            path.write_bytes(self.fixture())
            with self.assertRaises(report.ReportError):
                report.load_all_dtc_xml(str(path))
            self.assertEqual(
                report.load_all_dtc_xml(str(path), native_file=False).get_parameter(0),
                "1",
            )

    def test_msxml_descendant_patterns_and_first_complete_path(self):
        data = b"<Outer><Group><Version>A</Version><Version>B</Version><AllDiag><array-ECUInfo><ECUInfo/></array-ECUInfo></AllDiag></Group><Second><AllDiag><array-ECUInfo><ECUInfo><ECUId>42</ECUId><ECUName>Deep ECU</ECUName></ECUInfo></array-ECUInfo></AllDiag><VehicleInfo><VehicleName>Deep vehicle</VehicleName></VehicleInfo></Second><Version>C</Version></Outer>"
        reader = report.parse_all_dtc_xml(data)
        self.assertEqual(reader.get_parameter(0), "A")
        self.assertEqual(reader.get_parameter(0, (1,)), "B")
        # The first matching AllDiag prefix lacks ECUId. Native takes the
        # first complete selected path, not the first prefix unconditionally.
        self.assertEqual(reader.get_parameter(19), 42)
        view = report.view_all_dtc_xml(reader)
        self.assertEqual(view["vehicle"]["VehicleName"], "Deep vehicle")
        self.assertEqual(view["ecus"][1]["ECUName"], "Deep ECU")
        with self.assertRaises(report.ReportError):
            reader.get_dtc_number(1)
        self.assertEqual(reader.get_api_last_error(), 3)
        native = report.parse_all_dtc_xml(
            b"\xfe\xff" + data.decode().encode("utf-16be"), native_file=True
        )
        self.assertEqual(native.get_parameter(19), 42)
        # Complete results follow document order even when selected prefix
        # subtrees overlap; an outer prefix's later child must not win.
        nested = report.parse_all_dtc_xml(
            b"<AllDiag><Nested><AllDiag><array-ECUInfo><ECUInfo><ECUId>1</ECUId></ECUInfo></array-ECUInfo></AllDiag></Nested><array-ECUInfo><ECUInfo><ECUId>2</ECUId></ECUInfo></array-ECUInfo></AllDiag>"
        )
        self.assertEqual(nested.get_parameter(19), 1)

    def test_msxml_query_work_budget_is_shared_across_prefixes(self):
        data = b"<R>" + b"<X/>" * 30 + b"<Version>ok</Version></R>"
        reader = report.parse_all_dtc_xml(data)
        with (
            patch.object(report, "MAX_NODES", 1),
            self.assertRaisesRegex(report.ReportError, "work budget"),
        ):
            reader.get_parameter(0)
        self.assertEqual(reader.source, data)
        self.assertEqual(reader.get_parameter(0), "ok")

    def test_named_xml_view_aggregate_budget_preserves_source(self):
        reader = report.parse_all_dtc_xml(self.fixture())
        for limit in ("MAX_NODES", "MAX_BYTES"):
            with patch.object(report, limit, 10), self.assertRaises(report.ReportError):
                report.view_all_dtc_xml(reader)
            self.assertEqual(reader.source, self.fixture())
            self.assertEqual(reader.get_parameter(0), "1")
        self.assertEqual(report.view_all_dtc_xml(reader)["ecus"][0]["ECUName"], "ECU A")

    def test_parser_unsupported_encodings_fail_with_report_error(self):
        for encoding in ("utf-7", "cp932", "shift_jis"):
            data = (
                "<?xml version='1.0' encoding='"
                + encoding
                + "'?><Report><Version>1</Version></Report>"
            ).encode(encoding)
            with self.subTest(encoding=encoding), self.assertRaises(report.ReportError):
                report.parse_all_dtc_xml(data)

    def test_manufacture_empty_and_embedded_native_terminator(self):
        for payload, expected in ((b"", ""), (b"A\0B", "A"), (b"\0B", "")):
            encoded = bytes((251 - byte) & 255 for byte in payload).hex().encode().hex()
            reader = report.parse_all_dtc_xml(
                (
                    "<Report><ManufactureInfo>"
                    + encoded
                    + "</ManufactureInfo></Report>"
                ).encode()
            )
            self.assertEqual(reader.get_parameter(2), expected)
            self.assertEqual(reader.get_parameter_length_w(2), len(payload) * 2 + 2)
            self.assertEqual(
                reader.get_parameter_length_a(2), len(expected.encode("cp932")) + 1
            )
            self.assertEqual(
                reader.get_parameter_w(2, len(payload) * 2 + 2),
                expected.encode("utf-16le") + b"\0\0",
            )
            self.assertEqual(
                reader.get_parameter_a(2, len(expected.encode("cp932")) + 1),
                expected.encode("cp932") + b"\0",
            )

    def test_native_scalar_conversion_boundaries(self):
        for text, expected_signed, expected_unsigned in (
            ("", 0, 0),
            ("-2", -2, 0xFFFFFFFE),
            ("4294967296", 0x7FFFFFFF, 0xFFFFFFFF),
            ("-4294967296", -0x80000000, 0xFFFFFFFF),
            (" +12", 12, 12),
        ):
            data = (
                "<Report><Index>"
                + text
                + "</Index><AllDiag><array-ECUInfo><ECUInfo><ECUId>"
                + text
                + "</ECUId><array-DTCInfo><DTCInfo><DTCUndecordedValue>"
                + text
                + "</DTCUndecordedValue></DTCInfo></array-DTCInfo></ECUInfo></array-ECUInfo></AllDiag></Report>"
            ).encode()
            reader = report.parse_all_dtc_xml(data)
            with self.subTest(text=text):
                self.assertEqual(reader.get_parameter(3), expected_signed)
                self.assertEqual(reader.get_parameter(38), expected_unsigned)
                self.assertEqual(reader.get_dtc_number(1), ((expected_unsigned, 0),))
        for text in ("TRUE", "tr ue", "2", "fals e"):
            reader = report.parse_all_dtc_xml(
                (
                    "<Report><AllDiag><array-ECUInfo><ECUInfo><array-FunctionInfo><FunctionInfo><ErrorInfo>"
                    + text
                    + "</ErrorInfo></FunctionInfo></array-FunctionInfo></ECUInfo></array-ECUInfo></AllDiag></Report>"
                ).encode()
            )
            with self.assertRaises(report.ReportError):
                reader.get_parameter(32)
        for text in ("12x", "1 2", "9" * 129):
            reader = report.parse_all_dtc_xml(
                ("<Report><Index>" + text + "</Index></Report>").encode()
            )
            with self.assertRaises(report.ReportError):
                reader.get_parameter(3)

    def test_msxml_dom_text_trim_cdata_space_and_line_endings(self):
        cases = (
            ("<Comment> \t A  B \r\n C \t </Comment>", "A  B \n C"),
            ("<Comment> a  <x>  b  </x>  c </Comment>", "a b c"),
            ("<Comment xml:space='preserve'> a  b </Comment>", " a  b "),
            ("<Comment xml:space='PRESERVE'> a  b </Comment>", "a  b"),
            ("<Comment><![CDATA[ a  b ]]></Comment>", " a  b "),
            ("<Comment> a <![CDATA[ b ]]> c </Comment>", "a  b  c"),
            ("<Comment>a <![CDATA[]]></Comment>", "a "),
            ("<Comment> \u00a0 a \u00a0 </Comment>", "\u00a0 a \u00a0"),
            ("<Comment xml:space='preserve'>a&#13;b&#13;&#10;c</Comment>", "a\nb\nc"),
        )
        for fragment, expected in cases:
            with self.subTest(fragment=fragment):
                reader = report.parse_all_dtc_xml(
                    ("<Report>" + fragment + "</Report>").encode()
                )
                self.assertEqual(reader.get_parameter(4), expected)
                self.assertEqual(
                    reader.get_parameter_length_w(4),
                    len(expected.encode("utf-16le")) + 2,
                )
        reader = report.parse_all_dtc_xml(
            b"<Report xml:space='preserve'><Group><Comment> a  b </Comment></Group><Second xml:space='default'><Comment> a  b </Comment></Second></Report>"
        )
        self.assertEqual(reader.get_parameter(4), " a  b ")
        long_text = "a  b" * 4096
        reader = report.parse_all_dtc_xml(
            ("<Report><Comment> " + long_text + " </Comment></Report>").encode()
        )
        self.assertEqual(reader.get_parameter(4), long_text)

    def test_xql_string_predicate_uses_trim_without_xml_space(self):
        for fragment, expected in (
            ("<DTCTypeId> 3 </DTCTypeId>", 1),
            ("<DTCTypeId xml:space='preserve'> 3 </DTCTypeId>", 1),
            ("<DTCTypeId><![CDATA[ 3 ]]></DTCTypeId>", 0),
        ):
            data = (
                "<AllDiag><array-ECUInfo><ECUInfo><ECUId>42</ECUId><array-DTCInfo><DTCInfo>"
                + fragment
                + "</DTCInfo></array-DTCInfo></ECUInfo></array-ECUInfo></AllDiag>"
            ).encode()
            self.assertEqual(
                report.parse_all_dtc_xml(data).get_dtc_number(3), ((42, expected),)
            )
        reader = report.parse_all_dtc_xml(
            b"<Report><Index> 12 </Index><AllDiag><array-ECUInfo><ECUInfo><array-FunctionInfo><FunctionInfo><ErrorInfo> true </ErrorInfo></FunctionInfo></array-FunctionInfo></ECUInfo></array-ECUInfo></AllDiag></Report>"
        )
        self.assertEqual(reader.get_parameter(3), 12)
        self.assertIs(reader.get_parameter(32), True)
        self.assertEqual(
            report.parse_all_dtc_xml(
                b"\xfe\xff" + self.fixture().decode().encode("utf-16be") + b"\0\0",
                native_file=True,
            ).get_parameter(0),
            "1",
        )

    def test_scalar_descendant_text_matches_native_com_get_text(self):
        reader = report.parse_all_dtc_xml(
            b"<AllDiag><array-ECUInfo><ECUInfo><ECUId>4<x>2</x></ECUId><array-DTCInfo><DTCInfo><DTCTypeId>3<x/></DTCTypeId></DTCInfo></array-DTCInfo></ECUInfo></array-ECUInfo></AllDiag>"
        )
        self.assertEqual(reader.get_parameter(19), 42)
        self.assertEqual(reader.get_dtc_number(3), ((42, 1),))

    def test_xml_encoding_manufacture_and_named_view(self):
        reader = report.parse_all_dtc_xml(
            b"\xfe\xff" + self.fixture().decode().encode("utf-16be"), native_file=True
        )
        view = report.view_all_dtc_xml(reader)
        self.assertEqual(view["vehicle"]["VehicleName"], "Authored")
        dtc = view["ecus"][0]["dtcs"][0]
        self.assertEqual(dtc["DTCDispValue"], "P0123")
        self.assertEqual(dtc["StatusGridName"], "Stored status")
        text = "日本"
        encoded = (
            bytes((251 - b) & 255 for b in text.encode("cp932")).hex().encode().hex()
        )
        reader = report.parse_all_dtc_xml(
            (
                "<Report><ManufactureInfo>"
                + encoded
                + "</ManufactureInfo><Comment>日本</Comment><Version/></Report>"
            ).encode()
        )
        self.assertEqual(reader.get_parameter(2), text)
        self.assertEqual(reader.get_parameter_length_w(2), 10)
        with self.assertRaises(report.ReportError):
            reader.get_parameter_w(2, 6)
        self.assertEqual(
            reader.get_parameter_w(2, 10), text.encode("utf-16le") + b"\0\0"
        )
        self.assertEqual(reader.get_parameter_a(4, 5), text.encode("cp932") + b"\0")
        self.assertEqual(reader.get_parameter_length_w(0), 0)
        self.assertEqual(reader.get_parameter_w(0, 2), b"\0\0")

    def test_xml_boundaries_truncations_and_no_external_entities(self):
        data = self.fixture()
        for length in range(len(data)):
            with self.subTest(length=length), self.assertRaises(report.ReportError):
                report.parse_all_dtc_xml(data[:length])
        for bad in (
            b"<!DOCTYPE a [<!ENTITY x 'xx'>]><a>&x;</a>",
            b"<a xmlns='urn:x'/>",
            b"<a>" * 65 + b"</a>" * 65,
        ):
            with self.assertRaises(report.ReportError):
                report.parse_all_dtc_xml(bad)
        with (
            patch.object(report, "MAX_NODES", 2),
            self.assertRaises(report.ReportError),
        ):
            report.parse_all_dtc_xml(data)
        with (
            patch.object(report, "MAX_BYTES", 10),
            self.assertRaises(report.ReportError),
        ):
            report.parse_all_dtc_xml(data)
        reader = report.parse_all_dtc_xml(data)
        invalid_indexes: Any = ([0], (True,), (-1,), (0,) * 21)
        for indexes in invalid_indexes:
            with self.assertRaises(report.ReportError):
                reader.get_parameter(0, indexes)
        with self.assertRaises(report.ReportError):
            reader.get_dtc_number(3, capacity=1)
        with self.assertRaises(report.ReportError):
            reader.open_bytes(data)
        for bad in (data, b"\xfe\xffx", b"\xfe\xff\xd8\x00"):
            with self.assertRaises(report.ReportError):
                report.parse_all_dtc_xml(bad, native_file=True)


if __name__ == "__main__":
    unittest.main()
