"""Authored native legacy stream controls; contains no OEM records."""

import struct
import unittest

from scripts.snapshot import compress
from scripts.tse_conversion import (
    MAX_BYTES,
    LegacyList,
    TSEConversionError,
    _conversion_table,
    _ConvertedDTC,
    _decode_block,
    _freeze_signal,
    _function_info,
    _merge_dtc_rows,
    _Reader,
    _reply,
    convert_legacy,
    convert_legacy_dc_dtcs,
    convert_legacy_dc_freezes,
    convert_legacy_ecu_dtcs,
    convert_legacy_ecu_freezes,
    convert_legacy_signal,
    decode_legacy,
    decode_legacy_object,
)

# Native common metadata's size excludes its own DWORD. All strings are empty.
METADATA = bytes.fromhex(
    "34000000 3412 0000 0000 "
    "0000000000000000 00000000000000000000000000000000 00000000 "
    "0000 0000 0000 0000000000000000 0000 0000"
)
TIME = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
AD = (
    bytes.fromhex("5c0000000300")
    + METADATA
    + TIME
    + bytes.fromhex("0100000041 020000004243 03000000444546")
)


def outer(inner: bytes, *, flag: int = 0, payload: bytes | None = None) -> bytes:
    # Original writer RVA 19a30 duplicates the prefix through the first blob.
    first = 26 + int.from_bytes(inner[6:10], "little")
    end = first + 4 + int.from_bytes(inner[first : first + 4], "little")
    payload = inner if payload is None else payload
    return inner[:end] + struct.pack("<II", flag, len(payload)) + payload


def blob(value: bytes) -> bytes:
    return struct.pack("<I", len(value)) + value


def dc() -> bytes:
    prefix = b"\0\0\0\0\x06\0" + METADATA + TIME
    body = b"".join(blob(value) for value in (b"A", b"B", b"C", b"D"))
    body += struct.pack("<III", 0x11223344, 1, 7) + blob(b"detail") + blob(b"item")
    body += struct.pack("<II", 0x55667788, 0)
    body += struct.pack("<II", 0xAABBCCDD, 1) + blob(b"multi")
    for number in range(5):
        body += struct.pack("<I", number + 10) + blob(bytes([number]))
    body += struct.pack("<III", 99, 1, 17) + blob(b"extra") + blob(b"last")
    body += blob(b"E") + blob(b"F")
    inner = prefix + body
    return struct.pack("<I", len(inner) - 4) + inner[4:]


class TSEConversionInputTests(unittest.TestCase):
    def test_complete_ad_dc_conversion_and_actual_native_consumers(self):
        from scripts import snapshot, tse_reports

        h = bytes.fromhex("01000000")
        base = h + bytes(20)
        empty = h + bytes(4)
        func = h + struct.pack("<HH", 1, 0) + h + bytes(2) + empty
        function_info = base + h + struct.pack("<I", 1) + func
        signal = h + struct.pack("<H", 100) + (h + bytes(2)) * 3 + bytes((4, 0))
        signal += (
            h
            + struct.pack("<III", 1, 1, 0)
            + empty
            + bytes(16)
            + struct.pack("<HBH", 0, 0, 32)
        )
        signal += h + struct.pack("<I", 1) + h + struct.pack("<IB", 65, 1)
        signal_list = h + struct.pack("<I", 1) + signal
        frame = base + struct.pack("<BHI", 2, 0x1234, 1) + signal_list
        detail = h + struct.pack("<III", 7, 70, 1)
        detail_ids = base + b"\x02" + h + struct.pack("<I", 1) + detail
        detail_frame = base + struct.pack("<I", 7) + signal_list
        ecu = bytes.fromhex("02000000") + struct.pack("<I", 0x11223344) + h + bytes(3)
        ecu += (
            empty
            + bytes(9)
            + function_info
            + empty
            + h
            + struct.pack("<I", 1)
            + frame
            + h
            + struct.pack("<I", 1)
            + detail_ids
            + h
            + struct.pack("<I", 1)
            + detail_frame
            + empty * 2
        )
        connection = base + h + struct.pack("<I", 1) + ecu + bytes(10)
        ad = bytes(4) + bytes.fromhex("0300") + METADATA + TIME
        ad += blob(b"") + blob(connection) + blob(b"")
        dc_inner = bytes(4) + bytes.fromhex("0600") + METADATA + TIME + bytes(16)
        dc_inner += struct.pack("<III", 0, 1, 0) + blob(
            bytes(20) + bytes.fromhex("023412")
        )
        dc_inner += blob(bytes(20) + struct.pack("<I", 1) + signal_list)
        dc_inner += bytes(8) + struct.pack("<II", 0, 1)
        dc_inner += blob(bytes(20) + h + struct.pack("<I", 1) + detail)
        for slot in range(5):
            dc_inner += struct.pack("<I", 99 + slot) + blob(
                bytes(20) + signal_list if slot == 0 else b""
            )
        dc_inner += bytes(8)
        dc_inner += blob(b"") + blob(function_info)
        caller_time = bytes(range(16, 32))
        for extension, inner in ((".AD", ad), (".DC", dc_inner)):
            wire = convert_legacy(
                outer(inner),
                extension=extension,
                codepage="cp1252",
                caller_time=caller_time,
            )
            file = snapshot.parse_tse(wire)
            self.assertEqual(
                (file.file_type, file.version, file.revision), (8, 0x1013, 0)
            )
            self.assertEqual(
                file.metadata["supported_feature_ids"], [0x2711, 0x2713, 0x2716]
            )
            entries = file.metadata["index_entries"]
            for index, entry in enumerate(entries):
                end = (
                    entries[index + 1]["offset"]
                    if index + 1 < len(entries)
                    else len(wire)
                )
                body = wire[entry["offset"] : end]
                if entry["tag"] in ("IniCarInfo", "ConfCarInfo", "DTCMon"):
                    decoded = tse_reports.decode_section(entry["tag"], body)
                    if entry["tag"] == "ConfCarInfo":
                        self.assertIn(caller_time, decoded.records)
                        self.assertEqual(
                            decoded.records[-1][:2],
                            (3 if extension == ".AD" else 6).to_bytes(2, "little"),
                        )
                    if entry["tag"] == "DTCMon":
                        self.assertEqual(
                            (decoded.version, len(decoded.records)), (0x1007, 1)
                        )
                        self.assertEqual(
                            decoded.records[0][0], (0x1000, b"Data 1", caller_time, b"")
                        )
                        standard = decoded.records[0][2]
                        self.assertEqual(standard[0][:3], (0x1234, 2, 1))
                        self.assertEqual(standard[0][3][0][-1], ((65, b"A", 1),))
                        self.assertEqual(
                            decoded.records[0][4], ((2, ((7, 70, 1, b"", b"!"),)),)
                        )
                        detailed = decoded.records[0][5]
                        self.assertEqual(
                            detailed[0][:3], (2, 7 if extension == ".AD" else 1, 0)
                        )
                        self.assertEqual(detailed[0][3][0][-1], ((65, b"A", 1),))
        unsupported_func = h + struct.pack("<HH", 2, 0) + h + bytes(2) + empty
        skipped = ecu.replace(func, unsupported_func, 1)
        two_ecus = base + h + struct.pack("<I", 2) + skipped + ecu + bytes(10)
        inner = bytes(4) + bytes.fromhex("0300") + METADATA + TIME
        inner += blob(b"") + blob(two_ecus) + blob(b"")
        result = snapshot.parse_tse(
            convert_legacy(
                outer(inner),
                extension=".AD",
                codepage="cp1252",
                caller_time=caller_time,
            )
        )
        report = next(
            item for item in result.metadata["index_entries"] if item["tag"] == "DTCMon"
        )
        body = snapshot.tse_section(result, report["offset"])
        self.assertEqual(
            tse_reports.decode_section("DTCMon", body).records[0][0][1], b"Data 2"
        )

    def test_native_dtc_selection_swaps_and_duplicate_merger(self):
        # Native selection sort is not stable: sorting [2a,2b,1c] yields c,b,a.
        rows = [
            _ConvertedDTC(identifier, code, b"", value, flag, (), states, marker, state)
            for identifier, code, value, flag, states, marker, state in (
                (2, b"a", 1, 2, (1, 0, 0, 0), b"!!", 3),
                (2, b"b", 1, 3, (0, 1, 0, 0), b"!!!", 4),
                (1, b"c", 0, 0, (0, 0, 0, 0), b"", 1),
            )
        ]
        output = _merge_dtc_rows(rows, _Reader(b"", None))
        self.assertEqual([row.code for row in rows], [b"c", b"b", b"a"])
        self.assertEqual(output[:7], bytes.fromhex("0200 0100 010063"))
        self.assertIn(bytes.fromhex("0200 010062 0000 0000 01000000 03"), output)
        self.assertTrue(output.endswith(bytes.fromhex("0300212121 04")))

    def test_ad_and_dc_dtc_roots_same_real_source_records(self):
        h = bytes.fromhex("01000000")
        empty = h + bytes(4)
        base = h + bytes(20)

        def wide(text):
            raw = (text + "\0").encode("utf-16-le")
            return h + struct.pack("<H", len(raw)) + raw

        dtc = h + wide("P0001") + wide("Name") + struct.pack("<IB", 1, 2)
        dtc += wide("DTC-NONE") + bytes.fromhex("3412")
        group = base + struct.pack("<I", 1) + h + struct.pack("<I", 1) + dtc + bytes(4)
        frame = base + struct.pack("<BHI", 2, 0, 1) + empty
        ecu = bytes.fromhex("02000000") + bytes(4) + h + bytes(3) + empty + bytes(9)
        ecu += base + empty + h + struct.pack("<I", 1) + group
        ecu += h + struct.pack("<I", 1) + frame + empty * 4
        ad_output = convert_legacy_ecu_dtcs(ecu, codepage="cp1252")
        send = bytes(20) + bytes.fromhex("020000")
        receive = bytes(20) + struct.pack("<I", 1) + empty
        inner = bytes(4) + bytes.fromhex("0600") + METADATA + TIME
        inner += blob(b"") + blob(group) + blob(b"") + blob(b"")
        inner += struct.pack("<III", 0, 1, 0) + blob(send) + blob(receive) + bytes(32)
        inner = struct.pack("<I", len(inner) - 4) + inner[4:]
        source = decode_legacy(outer(inner), extension=".DC")
        dc_output = convert_legacy_dc_dtcs(source, codepage="cp1252")
        self.assertEqual(ad_output, dc_output)
        self.assertTrue(
            ad_output.startswith(
                bytes.fromhex("0100 3412 05005030303031 0000 04004e616d65 01000000 02")
            )
        )
        self.assertTrue(ad_output.endswith(bytes.fromhex("0300212121 04")))
        pending_group = bytearray(group)
        struct.pack_into("<I", pending_group, 24, 4)
        pending_ecu = ecu.replace(group, bytes(pending_group), 1)
        none_output = convert_legacy_ecu_dtcs(pending_ecu, codepage="ascii")
        self.assertIn(struct.pack("<II", 999, 1), none_output)
        japanese = pending_ecu.replace(wide("DTC-NONE"), wide("日本"), 1)
        japanese_output = convert_legacy_ecu_dtcs(japanese, codepage="ascii")
        # Comparison is native wcscmp, so this unused wide string needs no ACP.
        self.assertNotEqual(japanese_output, none_output)
        null_description = pending_ecu.replace(wide("DTC-NONE"), h + bytes(2), 1)
        with self.assertRaisesRegex(TSEConversionError, "NULL wide string"):
            convert_legacy_ecu_dtcs(null_description, codepage="ascii")

    def test_real_scalar_is_called_with_normalized_source_labels(self):
        from scripts.legacy_scalar import convert_legacy_scalar

        h = bytes.fromhex("01000000")
        name = "Тест\0".encode("utf-16-le")
        label = "Да\0".encode("utf-16-le")
        wire = h + bytes.fromhex("3412") + h + struct.pack("<H", len(name)) + name
        wire += (h + bytes(2)) * 2 + bytes((1, 0))
        wire += h + struct.pack("<III", 1, 1, 0) + h + struct.pack("<I", 1)
        wire += bytes.fromhex("02000000") + struct.pack("<I", 42)
        wire += h + struct.pack("<H", len(label)) + label + bytes(9)
        wire += bytes(16) + struct.pack("<HBH", 0, 0, 32)
        wire += h + struct.pack("<I", 1) + h + struct.pack("<IB", 42, 5)
        actual = convert_legacy_signal(
            wire, codepage="cp1251", scalar=convert_legacy_scalar
        )
        self.assertIn("Тест".encode("cp1251"), actual)
        self.assertTrue(
            actual.endswith(
                bytes.fromhex("2a000000 0200") + "Да".encode("cp1251") + b"\x05"
            )
        )
        with self.assertRaisesRegex(TSEConversionError, "source ACP"):
            convert_legacy_signal(wire, codepage="ascii", scalar=convert_legacy_scalar)
        with self.assertRaisesRegex(TSEConversionError, "cancelled"):
            convert_legacy_signal(
                wire,
                codepage="cp1251",
                scalar=convert_legacy_scalar,
                cancelled=lambda: True,
            )

    def test_all_three_dc_freeze_roots_real_saved_replies(self):
        from scripts.legacy_scalar import convert_legacy_scalar

        h = bytes.fromhex("01000000")
        empty = h + bytes(4)
        send = bytes(20) + bytes.fromhex("023412")
        receive = bytes(20) + struct.pack("<I", 9) + empty
        multi = bytes(20) + bytes((4, 5)) + empty
        ids = bytes(20) + h + struct.pack("<I", 2)
        ids += h + struct.pack("<III", 7, 70, 1) + h + struct.pack("<III", 8, 80, 0)
        inner = bytes(4) + bytes.fromhex("0600") + METADATA + TIME + bytes(16)
        inner += struct.pack("<III", 0, 1, 7) + blob(send) + blob(receive)
        inner += struct.pack("<III", 0, 1, 3) + blob(b"") + blob(multi)
        inner += struct.pack("<II", 0, 1) + blob(ids)
        for index in range(5):
            inner += struct.pack("<I", 20 + index) + blob(
                bytes(20) + empty if index == 0 else b""
            )
        inner += bytes(16)
        inner = struct.pack("<I", len(inner) - 4) + inner[4:]
        source = decode_legacy(outer(inner), extension=".DC")
        actual = convert_legacy_dc_freezes(
            source, codepage="cp1252", scalar=convert_legacy_scalar
        )
        self.assertEqual(actual.standard, bytes.fromhex("0100 3412 02 09000000 0000"))
        self.assertEqual(actual.multi, bytes.fromhex("0100 03 0000 04 05"))
        self.assertEqual(
            actual.details,
            bytes.fromhex("0100 02 0100 07000000 46000000 01000000 0000 010021"),
        )
        self.assertEqual(
            actual.detailed, bytes.fromhex("0100 02 01000000 00000000 0000")
        )
        # Native summary checks DWORD==1, but slot selection checks BYTE==1.
        odd_ids = bytearray(ids)
        struct.pack_into("<I", odd_ids, 40, 0x101)
        altered = inner.replace(blob(ids), blob(bytes(odd_ids)), 1)
        odd = convert_legacy_dc_freezes(
            decode_legacy(outer(altered), extension=".DC"),
            codepage="cp1252",
            scalar=convert_legacy_scalar,
        )
        self.assertEqual(odd.details, bytes.fromhex("0100 02 0000"))
        self.assertEqual(odd.detailed, actual.detailed)
        for count in (6, 20, 21):
            extended = ids[:24] + struct.pack("<I", count) + ids[28:]
            extended += (h + bytes(12)) * (count - 2)
            altered = inner.replace(blob(ids), blob(extended), 1)
            altered = struct.pack("<I", len(altered) - 4) + altered[4:]
            source = decode_legacy(outer(altered), extension=".DC")
            if count <= 20:
                self.assertEqual(
                    convert_legacy_dc_freezes(
                        source, codepage="cp1252", scalar=convert_legacy_scalar
                    ),
                    actual,
                )
            else:
                with self.assertRaisesRegex(TSEConversionError, "twenty-byte"):
                    convert_legacy_dc_freezes(
                        source, codepage="cp1252", scalar=convert_legacy_scalar
                    )

    def test_all_three_ad_freeze_roots_actual_arrays(self):
        from scripts.legacy_scalar import convert_legacy_scalar

        h = bytes.fromhex("01000000")
        empty = h + bytes(4)
        base = h + bytes(20)

        def items(*records):
            return h + struct.pack("<I", len(records)) + b"".join(records)

        def detail(identifier, value, active):
            return h + struct.pack("<III", identifier, value, active)

        normal = base + struct.pack("<BHI", 2, 0x1234, 9) + empty
        multi = base + bytes((3, 4, 5)) + empty
        ids = (
            base + b"\x06" + items(detail(7, 70, 1), detail(8, 80, 1), detail(9, 90, 0))
        )
        frame = base + struct.pack("<I", 7) + empty
        ecu = bytes.fromhex("02000000") + bytes(4) + h + bytes(3) + empty + bytes(9)
        ecu += base + empty  # FunctionInfo
        ecu += empty + items(normal) + items(ids) + items(frame) + items(multi) + empty
        actual = convert_legacy_ecu_freezes(
            ecu, codepage="cp1252", scalar=convert_legacy_scalar
        )
        self.assertEqual(actual.standard, bytes.fromhex("0100 3412 02 09000000 0000"))
        self.assertEqual(actual.multi, bytes.fromhex("0100 03 0000 04 05"))
        self.assertEqual(
            actual.details,
            bytes.fromhex(
                "0100 06 0200 07000000 46000000 01000000 0000 010021 "
                "08000000 50000000 01000000 0000 010021"
            ),
        )
        self.assertEqual(
            actual.detailed,
            bytes.fromhex("0200 06 07000000 00000000 0000 06 07000000 00000000 0000"),
        )

    def test_native_base_member_order_and_connection_tree(self):
        header = bytes.fromhex("01000000")
        base = struct.pack("<5I", 11, 12, 13, 14, 15)
        count = header + struct.pack("<HB", 0x1234, 7)
        ecu = header + struct.pack("<I", 0x44332211) + header + bytes(2) + b"\x08"
        ecu += header + struct.pack("<I", 1) + count
        ecu += struct.pack("<IHHB", 19, 20, 21, 22)
        connection = header + base + header + struct.pack("<I", 1) + ecu
        connection += struct.pack("<IIH", 25, 26, 27)
        result = decode_legacy_object(connection, "Connection")
        self.assertEqual(result.source, connection)
        self.assertEqual(
            tuple(result.member(i) for i in (8, 16, 20, 24, 28)), (11, 12, 13, 14, 15)
        )
        items = result.member(0x20)
        assert isinstance(items, LegacyList)
        self.assertEqual(len(items.records), 1)
        item = items.records[0]
        self.assertEqual(item.member(8), 0x44332211)
        self.assertEqual(item.member(0x3E), 21)
        counts = item.member(0x24)
        assert isinstance(counts, LegacyList)
        self.assertEqual(counts.records[0].member(8), 0x1234)
        self.assertEqual(counts.records[0].member(10), 7)
        for stop in range(len(connection)):
            with self.subTest(stop=stop), self.assertRaises(TSEConversionError):
                decode_legacy_object(connection[:stop], "Connection")

    def test_native_ecu_v2_all_seven_nested_families(self):
        h = bytes.fromhex("01000000")
        base = h + bytes(20)
        empty = h + bytes(4)
        ecu = bytes.fromhex("02000000") + bytes(4) + h + bytes(2) + bytes(1)
        ecu += empty + bytes(9)
        ecu += base + empty  # EcuFuncListInfo with empty Func list.
        for _ in range(6):
            ecu += empty
        result = decode_legacy_object(ecu, "ECU")
        for offset in (0x78, 0x8C, 0xA0, 0xB4, 0xC8, 0xDC):
            values = result.member(offset)
            assert isinstance(values, LegacyList)
            self.assertEqual(values.records, ())

    def test_multifreeze_three_unaligned_bytes_and_field_order(self):
        wire = bytes.fromhex("01000000") + struct.pack("<5I", 1, 2, 3, 4, 5)
        wire += bytes.fromhex("1122330100000000000000")
        result = decode_legacy_object(wire, "MultiFreezeList")
        self.assertEqual(
            tuple(result.member(i) for i in (0x20, 0x21, 0x22)), (0x11, 0x22, 0x33)
        )
        self.assertEqual(result.source, wire)

    def test_literal_shared_signal_conversion_actual_native_output(self):
        wire = bytes.fromhex(
            "01000000 3412 "
            "01000000 0400 41000000 01000000 0400 58000000 01000000 0400 55000000 "
            "02 08 "
            "01000000 01000000 02000000 03000000 01000000 00000000 "
            "04000000 05000000 06000000 07000000 1000 03 0200 "
            "01000000 02000000 01000000 44332211 55 01000000 88776655 aa"
        )
        calls = []

        def scalar(
            selector, value, table, precision, mode, *, codepage, decimal_point=b"."
        ):
            calls.append(
                (selector, value, table.coefficients_raw, precision, mode, codepage)
            )
            return b"value\0ignored" if len(calls) == 1 else None

        actual = convert_legacy_signal(wire, codepage="cp1252", scalar=scalar)
        expected = bytes.fromhex(
            "3412 010041 0000 010055 0208 "
            "01000000 02000000 03000000 1000 03 0200 0000 "
            "04000000 05000000 06000000 07000000 "
            "0200 44332211 050076616c7565 55 88776655 0000 aa"
        )
        self.assertEqual(actual, expected)
        self.assertEqual(
            calls,
            [
                (2, 0x11223344, (1, 2, 3), 8, 3, "cp1252"),
                (2, 0x55667788, (1, 2, 3), 8, 3, "cp1252"),
            ],
        )
        for stop in range(len(wire)):
            with self.subTest(stop=stop), self.assertRaises(TSEConversionError):
                convert_legacy_signal(wire[:stop], codepage="cp1252", scalar=scalar)

    def test_literal_conversion_table_runtime_field_join(self):
        wire = bytes.fromhex(
            "01000000 02000000 03000000 ffffffff "
            "01000000 01000000 "
            "02000000 07000000 01000000 0300 4f4e00 00000000 0a000000 05 "
            "08000000 09000000 0a000000 0b000000 1000 03 0200"
        )
        reader = _Reader(wire, None)
        table = _conversion_table(reader)
        self.assertEqual(reader.pos, len(wire))
        self.assertEqual(table.source, wire)
        self.assertEqual(table.coefficients_raw, (2, 3, 0xFFFFFFFF))
        self.assertEqual(table.fields_30_3c_raw, (8, 9, 10, 11))
        self.assertEqual(
            (table.field_14_raw, table.field_16_raw, table.field_18_raw), (16, 3, 2)
        )
        item = table.displays[0]
        self.assertEqual(
            (item.header_raw, item.effective_version, item.value_raw), ((2, 0), 2, 7)
        )
        self.assertEqual(
            (item.text_raw, item.bounds_raw, item.flag_raw), (b"ON\0", (0, 10), 5)
        )
        for stop in range(len(wire)):
            with self.subTest(stop=stop), self.assertRaises(TSEConversionError):
                _conversion_table(_Reader(wire[:stop], None))

    def test_legacy_newer_version_becomes_zero_and_nullable_string(self):
        prefix = (
            bytes.fromhex("01000000") + bytes(12) + bytes.fromhex("0100000001000000")
        )
        suffix = bytes(16 + 5)
        for version in (1, 3):
            item = struct.pack("<HHIHHHII", version, 9, 8, 1, 0, 0, 4, 5)
            table = _conversion_table(_Reader(prefix + item + suffix, None))
            self.assertEqual(table.displays[0].header_raw, (version, 9))
            self.assertEqual(
                table.displays[0].effective_version, 1 if version == 1 else 0
            )
            self.assertIsNone(table.displays[0].text_raw)
            self.assertEqual(table.displays[0].flag_raw, 0)

    def test_literal_freeze_signal_and_nested_runtime_fields(self):
        wire = bytes.fromhex(
            "01000000 3412 "
            "01000000 0200 4100 01000000 0000 01000000 0300 750078 "
            "02 08 "
            "01000000 01000000 01000000 00000000 01000000 00000000 "
            "00000000 00000000 00000000 00000000 0000 00 0000 "
            "01000000 01000000 01000000 44332211 55"
        )
        reader = _Reader(wire, None)
        signal = _freeze_signal(reader)
        self.assertEqual((reader.pos, signal.source), (len(wire), wire))
        self.assertEqual(signal.identifier_raw, 0x1234)
        self.assertEqual(signal.string_fields_raw, (b"A\0", None, b"u\0x"))
        self.assertEqual((signal.selector_raw, signal.field_3d_raw), (2, 8))
        self.assertEqual(signal.conversion.coefficients_raw, (1, 1, 0))
        self.assertEqual(
            (signal.multi_data[0].value_raw, signal.multi_data[0].flag_raw),
            (0x11223344, 0x55),
        )
        for stop in range(len(wire)):
            with self.subTest(stop=stop), self.assertRaises(TSEConversionError):
                _freeze_signal(_Reader(wire[:stop], None))

    def test_literal_reply_families_and_unaligned_send(self):
        header = bytes.fromhex("01000000 02000000 03000000 04000000 ffffffff")
        empty_list = bytes.fromhex("01000700 00000000")
        cases = (
            ("CGetDiagCodeRcv", b"", ()),
            ("CGetDiagDetailIdListRcv", b"", ()),
            ("CGetDiagDetailRcv", b"", ()),
            ("CGetEcuFuncListRcv", b"", ()),
            ("CGetPendingCodeRcv", b"", ()),
            ("CGetFrzFrmDatRcv", bytes.fromhex("78563412"), (0x12345678,)),
            ("CGetMultiFrzFrmDatRcv", bytes.fromhex("1280"), (0x12, 0x80)),
        )
        for kind, prefix, expected in cases:
            wire = header + prefix + empty_list
            reader = _Reader(wire, None)
            reply = _reply(reader, kind)
            self.assertEqual((reader.pos, reply.source), (len(wire), wire))
            self.assertEqual(reply.header_raw, (1, 2, 3, 4, 0xFFFFFFFF))
            self.assertEqual(reply.prefix_fields_raw, expected)
            self.assertEqual(reply.list_data, LegacyList((1, 7), ()))
            for stop in range(len(wire)):
                with (
                    self.subTest(kind=kind, stop=stop),
                    self.assertRaises(TSEConversionError),
                ):
                    _reply(_Reader(wire[:stop], None), kind)
        send = _reply(
            _Reader(header + bytes.fromhex("127856"), None), "CGetFrzFrmDatSnd"
        )
        self.assertEqual(
            (len(send.source), send.prefix_fields_raw), (23, (0x12, 0x5678))
        )
        self.assertIsNone(send.list_data)
        detail_wire = header + bytes.fromhex(
            "01000000 01000000 01000000 07000000 08000000 01000000"
        )
        detail_reply = _reply(_Reader(detail_wire, None), "CGetDiagDetailIdListRcv")
        assert detail_reply.list_data is not None
        self.assertEqual(detail_reply.list_data.records[0].member(8), 7)
        self.assertEqual(detail_reply.list_data.records[0].member(0xC), 8)
        self.assertEqual(detail_reply.list_data.records[0].member(0x10), 1)

    def test_literal_function_info_and_native_field_order(self):
        wire = bytes.fromhex(
            "01000200 01000000 02000000 03000000 04000000 05000000 "
            "01000000 01000000 "
            "01000000 3412 7856 01000000 0200 5800 "
            "01000000 01000000 01000000 cdab 44332211"
        )
        reader = _Reader(wire, None)
        info = _function_info(reader)
        self.assertEqual((reader.pos, info.source), (len(wire), wire))
        self.assertEqual(info.header_raw, (1, 2))
        self.assertEqual(info.base_fields_raw, (1, 2, 3, 4, 5))
        function = info.functions[0]
        self.assertEqual(
            (function.identifier_raw, function.field_1c_raw, function.text_raw),
            (0x1234, 0x5678, b"X\0"),
        )
        self.assertEqual(
            (function.details[0].identifier_raw, function.details[0].value_raw),
            (0xABCD, 0x11223344),
        )
        for stop in range(len(wire)):
            with self.subTest(stop=stop), self.assertRaises(TSEConversionError):
                _function_info(_Reader(wire[:stop], None))

    def test_literal_ad_and_source_preservation(self):
        self.assertEqual((len(METADATA), len(AD)), (56, 96))
        source = outer(AD)
        result = decode_legacy(source, extension=".ad")
        self.assertEqual(result.source, source)
        self.assertEqual(result.inner, AD)
        self.assertEqual(result.blobs, (b"A", b"BC", b"DEF"))
        self.assertEqual(result.metadata_raw, METADATA)
        self.assertEqual(result.time_raw, TIME)
        self.assertEqual(
            (result.groups, result.multi_group, result.trailing), ((), None, b"")
        )

    def test_dc_collections_and_five_items(self):
        inner = dc()
        result = decode_legacy(outer(inner), extension=".DC")
        self.assertEqual(result.blobs, (b"A", b"B", b"C", b"D", b"E", b"F"))
        self.assertEqual(result.groups[0].header_raw, 0x11223344)
        self.assertEqual(result.groups[0].records, ((7, b"detail", b"item"),))
        self.assertEqual(result.groups[1].records, ())
        self.assertEqual(result.groups[2].records, ((17, b"extra", b"last"),))
        self.assertIsNotNone(result.multi_group)
        assert result.multi_group is not None
        self.assertEqual(result.multi_group.header_raw, 0xAABBCCDD)
        self.assertEqual(
            result.multi_group.records,
            ((b"multi", tuple((number + 10, bytes([number])) for number in range(5))),),
        )

    def test_compression_and_nonzero_flag(self):
        source = outer(AD, flag=2, payload=compress(AD))
        result = decode_legacy(source, extension=".AD")
        self.assertEqual((result.inner, result.compression_raw), (AD, 2))

    def test_native_incomplete_token_tail_is_accepted(self):
        # Native RVA 1c74 stops on this lone match byte after output 'A'.
        encoded = bytes.fromhex("0100000041014100")
        self.assertEqual(_decode_block(encoded, 1, _Reader(b"", None)), b"A")
        # 96 literals exhaust a complete flag group; a final empty flag is valid.
        source = outer(AD, flag=1, payload=compress(AD) + b"\xff")
        self.assertEqual(decode_legacy(source, extension=".AD").inner, AD)

    def test_native_overlapping_match(self):
        # Literal A followed by a length-three reference to FEE (including overlap).
        encoded = bytes.fromhex("04000000410141eef0")
        self.assertEqual(_decode_block(encoded, 4, _Reader(b"", None)), b"AAAA")

    def test_declared_prefix_can_be_shorter_than_safe_decoded_allocation(self):
        encoded = bytes.fromhex("0100000041034142")
        self.assertEqual(_decode_block(encoded, 2, _Reader(b"", None)), b"A")
        with self.assertRaisesRegex(TSEConversionError, "overwrite"):
            _decode_block(encoded, 1, _Reader(b"", None))

    def test_declared_checksum_and_dictionary_guards(self):
        for encoded, message in (
            (bytes.fromhex("01000000400141"), "checksum mismatch"),
            (bytes.fromhex("02000000410141"), "uninitialized output"),
            (bytes.fromhex("0300000000000000"), "uninitialized dictionary"),
        ):
            with (
                self.subTest(encoded=encoded),
                self.assertRaisesRegex(TSEConversionError, message),
            ):
                _decode_block(encoded, 4, _Reader(b"", None))

    def test_raw_size_is_preserved_without_invented_validation(self):
        source = bytearray(outer(AD))
        struct.pack_into("<I", source, 83 + 4, 0xFFFFFFFF)
        result = decode_legacy(bytes(source), extension=".AD")
        self.assertEqual(result.inner, AD)
        self.assertEqual(result.compressed_size_raw, 0xFFFFFFFF)

    def test_inner_and_outer_opaque_tails(self):
        source = outer(AD + b"inner-tail", flag=1, payload=compress(AD + b"inner-tail"))
        # Allocation is controlled by the outer prefix, independently of inner size.
        source = struct.pack("<I", len(AD) + 10 - 4) + source[4:] + b"outer-tail"
        result = decode_legacy(source, extension=".AD")
        self.assertEqual(
            (result.trailing, result.outer_trailing), (b"inner-tail", b"outer-tail")
        )
        self.assertEqual(result.source, source)

    def test_all_input_truncations_fail(self):
        source = outer(AD, flag=1, payload=compress(AD))
        for stop in range(len(source)):
            with self.subTest(stop=stop), self.assertRaises(TSEConversionError):
                decode_legacy(source[:stop], extension=".AD")

    def test_mutated_record_type_fails(self):
        source = bytearray(outer(AD))
        source[83 + 8 + 4] = 6
        with self.assertRaisesRegex(TSEConversionError, "record type"):
            decode_legacy(bytes(source), extension=".AD")

    def test_record_count_budget_precedes_materialization(self):
        inner = bytearray(dc())
        first_group = 6 + 56 + 16 + 4 * 5
        struct.pack_into("<I", inner, first_group + 4, 0xFFFFFFFF)
        with self.assertRaisesRegex(TSEConversionError, "record count"):
            decode_legacy(outer(bytes(inner)), extension=".DC")

    def test_byte_budget_and_cancellation(self):
        with self.assertRaisesRegex(TSEConversionError, "byte budget"):
            decode_legacy(bytes(MAX_BYTES + 1), extension=".AD")
        with self.assertRaisesRegex(TSEConversionError, "cancelled"):
            decode_legacy(outer(AD), extension=".AD", cancelled=lambda: True)
        calls = 0

        def cancelled():
            nonlocal calls
            calls += 1
            return calls > 1

        with self.assertRaisesRegex(TSEConversionError, "cancelled"):
            _decode_block(compress(bytes(9000)), 9000, _Reader(b"", cancelled))
        self.assertEqual(calls, 2)

    def test_exact_record_budget_boundary(self):
        # 100,000 native I/blob/blob records, all identifiers and blobs empty.
        prefix = bytes(4) + b"\x06\0" + METADATA + TIME + bytes(16)
        body = struct.pack("<II", 7, 100_000) + bytes(12 * 100_000)
        body += bytes(8 * 3 + 8)
        inner = prefix + body
        inner = struct.pack("<I", len(inner) - 4) + inner[4:]
        result = decode_legacy(outer(inner), extension=".DC")
        self.assertEqual(len(result.groups[0].records), 100_000)
        self.assertEqual(result.groups[0].records[-1], (0, b"", b""))

    def test_nested_display_count_budget_precedes_reads(self):
        wire = bytes.fromhex("01000000") + bytes(12) + bytes.fromhex("01000000")
        wire += struct.pack("<I", 100_001)
        with self.assertRaisesRegex(TSEConversionError, "record count"):
            _conversion_table(_Reader(wire, None))

    def test_cancellation_during_matches_that_skip_exact_check_boundary(self):
        # Output lengths stay odd: 1 + 18*n never equals a 4096-byte boundary.
        tokens = [b"A"] + [bytes.fromhex("eeff")] * 500
        encoded = bytearray(struct.pack("<IB", 4999, 0x41))
        for start in range(0, len(tokens), 8):
            encoded.append(1 if start == 0 else 0)
            encoded.extend(b"".join(tokens[start : start + 8]))
        calls = 0

        def cancelled():
            nonlocal calls
            calls += 1
            return calls == 2

        with self.assertRaisesRegex(TSEConversionError, "cancelled"):
            _decode_block(bytes(encoded), 5000, _Reader(b"", cancelled))
        self.assertEqual(calls, 2)

    def test_extension_and_callback_boundary(self):
        for extension in ("AD", ".TSE", ".ÄD"):
            with self.assertRaises(TSEConversionError):
                decode_legacy(outer(AD), extension=extension)
        with self.assertRaises(TSEConversionError):
            decode_legacy(outer(AD), extension=".AD", cancelled=4)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
