"""Regular-file validation precedes reading or opening special-device drivers."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.local_files import read_regular


class LocalFileTests(unittest.TestCase):
    def test_regular_file_links_and_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(b"abcd")
            link = path.with_name("link")
            link.symlink_to(path)
            for item in (path, link):
                self.assertEqual(read_regular(item, limit=4), b"abcd")
                with self.assertRaises(ValueError):
                    read_regular(item, limit=3)
            path.write_bytes(b"")
            self.assertEqual(read_regular(path, limit=0), b"")
            for limit in (-1, True):
                with self.assertRaises(ValueError):
                    read_regular(path, limit=limit)
            with self.assertRaises(ValueError):
                read_regular(Path(directory), limit=100)

    def test_fifo_is_rejected_without_blocking_and_device_is_never_opened_for_read(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fifo"
            os.mkfifo(path)
            process = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "from scripts.local_files import read_regular; "
                        "import sys; read_regular(sys.argv[1], limit=100)"
                    ),
                    str(path),
                ],
                capture_output=True,
                timeout=3,
                check=False,
            )
            self.assertNotEqual(process.returncode, 0)
            self.assertIn(b"regular file", process.stderr)
        with (
            patch(
                "scripts.local_files.open", side_effect=AssertionError("device read")
            ),
            self.assertRaisesRegex(ValueError, "regular file"),
        ):
            read_regular("/dev/zero", limit=100)

    def test_pinned_inode_cannot_be_replaced_by_a_fifo_between_validation_and_read(
        self,
    ):
        original_fstat = os.fstat
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(b"original")

            def replace_after_stat(descriptor):
                result = original_fstat(descriptor)
                path.unlink()
                os.mkfifo(path)
                return result

            with patch("scripts.local_files.os.fstat", side_effect=replace_after_stat):
                self.assertEqual(read_regular(path, limit=8), b"original")
