import struct
import unittest

from scripts.diagnostic_db import Language, decode_lzss, parse_database


def database_bytes(kind, sections, version=0x0100032F):
    header = bytearray(36 + 4 * (max(sections) + 1))
    header[8:10] = bytes((kind, max(sections) + 1))
    header[10:28] = b"DiagTool DataCtrl\0"
    struct.pack_into("<I", header, 28, version)
    body = bytearray()
    for slot, (count, payload, compressed) in sorted(sections.items()):
        struct.pack_into("<I", header, 36 + slot * 4, len(header) + len(body))
        body += (
            struct.pack(
                "<BBHI" if version == 0x01000137 else "<BBII",
                slot,
                compressed,
                count,
                len(payload),
            )
            + payload
        )
    return bytes(header + body)


class DiagnosticDatabaseTests(unittest.TestCase):
    def test_support_active_tests_and_vehicle_lookup_keep_variants(self):
        language = Language(parse_database(database_bytes(4, {0: (0, b"", 0)})))
        rows = []
        for exception_id in (5, 9):
            row = bytearray(92)
            row[:10] = "Demo\0".encode("utf-16le")
            struct.pack_into("<H", row, 56, 42)
            struct.pack_into("<H", row, 72, exception_id)
            row[82], row[87] = 3, 2
            rows.append(row)
        support = struct.pack("<H2xBB2x", 7, 42, 0)
        db = parse_database(
            database_bytes(2, {3: (1, support, 0), 11: (2, b"".join(rows), 0)})
        )
        records = db.records_for_key(11, 42, language)
        self.assertEqual([r["exception_id"] for r in records], [5, 9])
        self.assertEqual(records[0]["short_name_hex"], bytes(rows[0][:32]).hex())
        self.assertEqual(records[0]["selector"], 3)
        self.assertEqual(db.records_for_key(11, 99, language), [])
        self.assertEqual(db.named_records(3, language)[0]["key"], 42)
        vehicle = struct.pack("<IHHI", 0, 123, 0, 0)
        management = parse_database(database_bytes(1, {43: (1, vehicle, 0)}))
        self.assertEqual(management.records_for_key(43, 123, language)[0]["name"], "")
        with self.assertRaises(ValueError):
            parse_database(database_bytes(2, {11: (1, bytes(91), 0)})).named_records(
                11, language
            )

    def test_lzss_overlap_and_rejects_bad_streams(self):
        stream = struct.pack("<IB", 6, 0x63) + b"\x07abc\xee\xf0"
        self.assertEqual(decode_lzss(stream), b"abcabc")
        for bad in (
            stream[:-1],
            stream + b"\x00",
            stream[:4],
            struct.pack("<IB", 6, 0) + stream[5:],
            struct.pack("<IB", 5, 0x63) + stream[5:],
            struct.pack("<IB", 3, 0) + b"\x00\x00\x00",
            struct.pack("<IB", 100_000_000, 0),
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                decode_lzss(bad)

    def test_sections_current_and_legacy_and_corruption(self):
        for version in (0x01000137, 0x01000225, 0x0100032F):
            original = database_bytes(2, {5: (2, bytes(56), 0)}, version)
            db = parse_database(original)
            self.assertEqual(db.kind, 2)
            self.assertEqual(db.sections[5].rows(28), [bytes(28), bytes(28)])
            with self.assertRaises(ValueError):
                db.sections[5].rows(27)
            for offset in (10, 28, 36 + 5 * 4, len(original) - 57):
                data = bytearray(original)
                data[offset] ^= 0xFF
                with (
                    self.subTest(version=version, offset=offset),
                    self.assertRaises(ValueError),
                ):
                    parse_database(bytes(data))
            with self.assertRaises(ValueError):
                parse_database(original[:-1])

    def test_language_uses_one_based_ids_and_strict_pool_bounds(self):
        pool = "Wheel Speed\0%\0".encode("utf-16le")
        payload = struct.pack("<IHIH", 0, 24, 24, 4) + pool
        language = Language(parse_database(database_bytes(4, {0: (2, payload, 0)})))
        self.assertEqual(language.resolve(0), "")
        self.assertEqual(language.resolve(1), "Wheel Speed")
        self.assertEqual(language.resolve(2), "%")
        with self.assertRaises(ValueError):
            language.resolve(3)
        for bad in (
            payload[:-1],
            payload + b"\0\0",
            struct.pack("<I", 2) + payload[4:],
        ):
            with self.assertRaises(ValueError):
                Language(parse_database(database_bytes(4, {0: (2, bad, 0)})))

    def test_semantic_fields_preserve_dtc_code_and_resolve_text(self):
        pool = "Fault\0Comment\0".encode("utf-16le")
        language = Language(
            parse_database(
                database_bytes(
                    4, {0: (2, struct.pack("<IHIH", 0, 12, 12, 16) + pool, 0)}
                )
            )
        )
        row = bytearray(28)
        row[:12] = "C120C\0".encode("utf-16le")
        struct.pack_into("<IIHH", row, 12, 1, 2, 300, 7)
        row[27] = 2
        db = parse_database(database_bytes(2, {5: (1, row, 0)}))
        records = db.named_records(5, language)
        self.assertEqual(records[0]["code"], "C120C")
        self.assertEqual(records[0]["name"], "Fault")
        self.assertEqual(records[0]["comment"], "Comment")
        self.assertEqual(records[0]["key"], 300)
        self.assertEqual(records[0]["exception_id"], 7)
        self.assertEqual(records[0]["exception_flag"], 2)


if __name__ == "__main__":
    unittest.main()
