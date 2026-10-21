"""Controls for the explicit private-evidence skip boundary."""

import json
import tempfile
import unittest
from pathlib import Path

from tests.private_evidence import (
    read_private_bytes,
    read_private_json,
    read_private_text,
    require_private,
)


class PrivateEvidenceTests(unittest.TestCase):
    def test_missing_private_path_skips_with_precise_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "analysis/evidence/no-car-999/absent.json"
            with self.assertRaises(unittest.SkipTest) as caught:
                require_private(missing)
            self.assertIn("Private OEM evidence unavailable", str(caught.exception))
            self.assertIn("no-car-999", str(caught.exception))

    def test_non_private_path_is_rejected_instead_of_silently_skipped(self):
        with self.assertRaises(AssertionError):
            require_private("README.md")

    def test_readers_return_exact_private_bytes_text_and_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "analysis/evidence/no-car-999"
            root.mkdir(parents=True)
            binary = root / "sample.bin"
            binary.write_bytes(b"\x00\xffprivate")
            text = root / "sample.json"
            text.write_text(json.dumps({"value": 7}), encoding="utf-8")

            self.assertEqual(read_private_bytes(binary), b"\x00\xffprivate")
            self.assertEqual(read_private_text(text), '{"value": 7}')
            self.assertEqual(read_private_json(text), {"value": 7})


if __name__ == "__main__":
    unittest.main()
