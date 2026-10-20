import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts.build_offline_profile import build_profile


def xor(data):
    return bytes(value ^ 255 for value in data)


class OfflineProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "application"
        self.source.mkdir()
        self.output = self.root / "offline"
        (self.source / "IT3System.ini").write_bytes(
            b"[Other]\r\nTISFunction=1\r\n[AvailableFunction]\r\n TISFunction = 1 ; keep\r\n"
        )
        self.config = b"[URLs]\r\nURL=https://remote.example:8443/path?a=$09&next=https%3A%2F%2Fremote.example\r\nLocal=http://localhost:8087/a\r\nIP=http://127.0.0.1/a\r\nIPv6=http://[::1]/a\r\n"
        (self.source / "region.ini").write_bytes(xor(self.config))
        (self.source / "app.exe").write_bytes(b"MZ opaque binary\0")

    def test_complete_copy_changes_only_requested_fields_and_preserves_encoding(self):
        before = {p.name: p.read_bytes() for p in self.source.iterdir()}
        manifest = build_profile(self.source, self.output)
        self.assertEqual(
            (self.output / "IT3System.ini").read_bytes(),
            before["IT3System.ini"].replace(b" = 1 ;", b" = 0 ;"),
        )
        expected = self.config.replace(
            b"://remote.example:8443/", b"://127.0.0.1:8443/"
        )
        self.assertEqual((self.output / "region.ini").read_bytes(), xor(expected))
        self.assertEqual((self.output / "app.exe").read_bytes(), before["app.exe"])
        self.assertEqual(
            {p.name: p.read_bytes() for p in self.source.iterdir()}, before
        )
        self.assertEqual(
            manifest["verification"]["direct_external_http_destinations"], 0
        )
        self.assertEqual(manifest["verification"]["tis_function"], 0)
        on_disk = json.loads(
            (self.output / "offline-profile-manifest.json").read_text()
        )
        self.assertEqual(manifest, on_disk)
        changed = {row["path"]: row for row in manifest["changed_files"]}
        self.assertEqual(
            changed["region.ini"]["original_sha256"],
            hashlib.sha256(before["region.ini"]).hexdigest(),
        )
        self.assertEqual(
            changed["region.ini"]["result_sha256"],
            hashlib.sha256(xor(expected)).hexdigest(),
        )

    def test_existing_or_nested_output_rejected_before_writes(self):
        self.output.mkdir()
        for target in (self.output, self.source / "nested"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                build_profile(self.source, target)
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertFalse((self.source / "nested").exists())

    def test_symlink_input_rejected_before_writes(self):
        (self.source / "link").symlink_to(self.source / "app.exe")
        with self.assertRaises(ValueError):
            build_profile(self.source, self.output)
        self.assertFalse(self.output.exists())

    def test_unknown_configuration_encoding_fails_closed(self):
        (self.source / "unknown.ini").write_bytes(b"\x80\0\x95garbage")
        with self.assertRaises(ValueError):
            build_profile(self.source, self.output)
        self.assertFalse(self.output.exists())
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["application"])

    def test_missing_required_flag_fails_without_output(self):
        (self.source / "IT3System.ini").write_bytes(
            b"[AvailableFunction]\r\nOther=1\r\n"
        )
        with self.assertRaises(ValueError):
            build_profile(self.source, self.output)
        self.assertFalse(self.output.exists())

    def test_utf16_config_preserves_bom_and_newlines(self):
        (self.source / "wide.ini").write_bytes(
            b"\xff\xfe"
            + "[URL]\r\nX=https://external.example/a?x=1\r\n".encode("utf-16-le")
        )
        build_profile(self.source, self.output)
        self.assertEqual(
            (self.output / "wide.ini").read_bytes(),
            b"\xff\xfe" + "[URL]\r\nX=https://127.0.0.1/a?x=1\r\n".encode("utf-16-le"),
        )

    def test_parent_traversal_cannot_hide_nested_output(self):
        (self.source / "existing").mkdir()
        with self.assertRaises(ValueError):
            build_profile(self.source, self.source / "existing/../nested")
        self.assertFalse((self.source / "nested").exists())

    def test_nonregular_input_rejected_before_copy(self):
        os.mkfifo(self.source / "pipe")
        with self.assertRaises(ValueError):
            build_profile(self.source, self.output)
        self.assertFalse(self.output.exists())

    def test_duplicate_flag_is_rejected(self):
        path = self.source / "IT3System.ini"
        path.write_bytes(path.read_bytes() + b"TISFunction=1\r\n")
        with self.assertRaises(ValueError):
            build_profile(self.source, self.output)
        self.assertFalse(self.output.exists())

    def test_other_loopback_addresses_are_preserved(self):
        content = b"[URLs]\r\nOther=http://127.0.0.2:8086/path?q=$09\r\n"
        (self.source / "other.ini").write_bytes(content)
        build_profile(self.source, self.output)
        self.assertEqual((self.output / "other.ini").read_bytes(), content)
