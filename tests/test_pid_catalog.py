import struct
import tempfile
import unittest
from pathlib import Path

from scripts.pid_catalog import list_groups, parse_group, show_group


def catalog_bytes(short_name=""):
    header = bytearray(66)
    struct.pack_into("<HH", header, 4, 2, 52)
    struct.pack_into("<H", header, 64, 1)
    name = "Engine SPD".encode("utf-16le")
    unit = "rpm".encode("utf-16le")
    opaque = short_name.encode("utf-16le")
    row = struct.pack("<H", len(name)) + name
    row += struct.pack("<H", len(opaque)) + opaque + struct.pack("<H", len(unit))
    row += unit + bytes.fromhex("2000000000000000")
    data = header + row + bytes(16) + struct.pack("<H", 4) + bytes(8)
    struct.pack_into("<I", data, 0, len(data) - 6)
    struct.pack_into("<I", data, 40, len(data) - 2)
    return bytes(data)


class PidCatalogTests(unittest.TestCase):
    def test_real_record_structure(self):
        self.assertEqual(
            parse_group(catalog_bytes()),
            [
                {
                    "name": "Engine SPD",
                    "unit": "rpm",
                    "short_name": "",
                    "parameter_id": "32",
                    "unit_conversion_category": "0",
                    "saved_list_field": "0",
                    "metadata_hex": "2000000000000000",
                }
            ],
        )

    def test_short_name_and_native_parameter_keys(self):
        record = parse_group(catalog_bytes("9"))[0]
        self.assertEqual(record["short_name"], "9")
        self.assertEqual(record["unit"], "rpm")
        data = bytearray(catalog_bytes())
        struct.pack_into("<IHH", data, len(data) - 26 - 8, 0x12340020, 10, 7)
        record = parse_group(bytes(data))[0]
        self.assertEqual(record["parameter_id"], "32")
        self.assertEqual(record["unit_conversion_category"], "10")
        self.assertEqual(record["saved_list_field"], "7")

    def test_malformed_input(self):
        original = catalog_bytes()
        changes = [
            (4, b"\x03"),
            (66, b"\xff\xff"),
            (66, b"\x13\x00"),
            (68, b"\x00\xd8"),
            (88, b"\xff\xff"),
        ]
        for offset, replacement in changes:
            data = bytearray(original)
            data[offset : offset + len(replacement)] = replacement
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                parse_group(bytes(data))
        for data in (original[:-1], original + b"x", b"", original[:70]):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                parse_group(data)
        data = bytearray(original)
        struct.pack_into("<H", data, 64, 2)
        with self.assertRaises(ValueError):
            parse_group(bytes(data))
        data = bytearray(original)
        data[-1] = 1
        with self.assertRaises(ValueError):
            parse_group(bytes(data))

    def test_paths_and_real_file_loading(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "root"
            root.mkdir()
            (root / "group.CT").write_bytes(catalog_bytes())
            outside = base / "outside.CT"
            outside.write_bytes(catalog_bytes())
            (root / "escape.CT").symlink_to(outside)
            (root / "escape-dir").symlink_to(base, target_is_directory=True)
            self.assertEqual(list_groups(root), ["group.CT"])
            with self.assertRaises(ValueError):
                list_groups(root / "group.CT")
            self.assertEqual(show_group(root, "group.CT")["records"][0]["unit"], "rpm")
            for group in (
                "../outside.CT",
                str(outside),
                "escape.CT",
                "escape-dir/outside.CT",
            ):
                with self.subTest(group=group), self.assertRaises(ValueError):
                    show_group(root, group)


if __name__ == "__main__":
    unittest.main()
