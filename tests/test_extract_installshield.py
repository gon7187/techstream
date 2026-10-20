import json
import struct
import tempfile
import unittest
from pathlib import Path

from scripts.extract_installshield import extract


def installer(
    unicode=False, member_path="Disk1\\file.txt", truncated=False, member_paths=None
):
    header = bytearray(1024)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x80)
    header[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", header, 0x86, 1)
    struct.pack_into("<H", header, 0x94, 224)
    struct.pack_into("<H", header, 0x98, 0x10B)
    struct.pack_into("<I", header, 0x98 + 92, 16)
    struct.pack_into("<II", header, 0x178 + 16, 512, 512)
    encoding = "utf-16-le" if unicode else "ascii"
    paths = member_paths if member_paths is not None else [member_path]
    overlay = struct.pack("<I", len(paths)) if unicode else b""
    for path in paths:
        name = path.replace("\\", "/").rsplit("/", 1)[-1]
        record = "".join(value + "\0" for value in [name, path, "0.0.0.0", "5"]).encode(
            encoding
        )
        overlay += record + b"hello"
    if truncated:
        overlay = overlay[:-1]
    padding = bytes(-(len(header) + len(overlay)) % 8)
    certificate = struct.pack("<IHH", 8, 0x200, 2)
    cert_offset = len(header) + len(overlay) + len(padding)
    struct.pack_into("<II", header, 0x98 + 128, cert_offset, len(certificate))
    return bytes(header) + overlay + padding + certificate


class ExtractInstallShieldTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "Setup.exe"
        self.output = self.root / "output"

    def test_ascii_records_and_certificate_boundary(self):
        self.source.write_bytes(installer())
        extract(self.source, self.output)
        self.assertEqual((self.output / "Disk1/file.txt").read_bytes(), b"hello")
        manifest = json.loads((self.output / "manifest.json").read_text())
        self.assertEqual(
            manifest["members"][0]["sha256"],
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )
        offset = manifest["members"][0]["offset"]
        self.assertEqual(self.source.read_bytes()[offset : offset + 5], b"hello")

    def test_counted_utf16_records(self):
        self.source.write_bytes(installer(unicode=True))
        result = extract(self.source, self.output)
        self.assertEqual(result["format"], "utf16-counted")
        self.assertEqual((self.output / "Disk1/file.txt").read_bytes(), b"hello")

    def test_truncated_payload_rejected_before_writes(self):
        for wide in (False, True):
            with self.subTest(wide=wide):
                data = bytearray(installer(unicode=wide))
                needle = "5\0".encode("utf-16-le" if wide else "ascii")
                offset = data.index(needle, 1024)
                data[offset : offset + len(needle)] = "9\0".encode(
                    "utf-16-le" if wide else "ascii"
                )
                # Declared9bytes:5payloadbytes plus <=7alignment padding would mask
                # truncation, so bound the archive exactly at its shortened payload.
                cert = struct.unpack_from("<I", data, 0x98 + 128)[0]
                struct.pack_into("<II", data, 0x98 + 128, 0, 0)
                self.source.write_bytes(data[: cert - 7])
                with self.assertRaises(ValueError):
                    extract(self.source, self.output)
                self.assertFalse(self.output.exists())

    def test_path_traversal_rejected_before_writes(self):
        for member_path in (
            "..\\file.txt",
            "C:\\file.txt",
            "\\file.txt",
            "Disk1\\..\\file.txt",
        ):
            with self.subTest(member_path=member_path):
                self.source.write_bytes(installer(member_path=member_path))
                with self.assertRaises(ValueError):
                    extract(self.source, self.output)
                self.assertFalse(self.output.exists())

    def test_existing_files_are_not_overwritten(self):
        self.source.write_bytes(installer())
        target = self.output / "Disk1/file.txt"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"original")
        with self.assertRaises(ValueError):
            extract(self.source, self.output)
        self.assertEqual(target.read_bytes(), b"original")

    def test_file_directory_collisions_are_rejected_before_writes(self):
        cases = (
            ["Disk1\\file.txt", "Disk1\\file.txt\\next.txt"],
            ["Disk1\\file.txt\\next.txt", "Disk1\\file.txt"],
            ["manifest.json\\file.txt"],
        )
        for index, paths in enumerate(cases):
            for wide in (False, True):
                with self.subTest(paths=paths, wide=wide):
                    output = self.root / f"collision-{index}-{wide}"
                    self.source.write_bytes(installer(unicode=wide, member_paths=paths))
                    with self.assertRaises((ValueError, OSError)):
                        extract(self.source, output)
                    self.assertFalse(output.exists())

    def test_existing_non_directory_parent_is_rejected_before_writes(self):
        self.output.mkdir()
        (self.output / "blocked").write_bytes(b"original")
        self.source.write_bytes(
            installer(member_paths=["Disk1\\file.txt", "blocked\\next.txt"])
        )
        with self.assertRaises((ValueError, OSError)):
            extract(self.source, self.output)
        self.assertFalse((self.output / "Disk1").exists())
        self.assertEqual((self.output / "blocked").read_bytes(), b"original")

    def test_escaping_symlink_is_rejected_before_writes(self):
        self.source.write_bytes(installer())
        self.output.mkdir()
        (self.output / "Disk1").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            extract(self.source, self.output)
        self.assertFalse((self.root / "file.txt").exists())

    def test_generic_pe_overlay_is_not_accepted(self):
        data = installer()
        header = bytearray(data[:1024])
        struct.pack_into("<II", header, 0x98 + 128, 0, 0)
        self.source.write_bytes(
            header + b"just some ordinary strings\0not an archive\0"
        )
        with self.assertRaises(ValueError):
            extract(self.source, self.output)
        self.assertFalse(self.output.exists())
