import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts.session_cli import replay_session, save_report


class SessionCLITests(unittest.TestCase):
    def test_poll_and_calibration_examples_are_complete_and_decoded(self):
        examples = Path(__file__).resolve().parents[1] / "examples"
        report = replay_session(
            examples / "live-session.json", operation="poll", samples=12
        )
        self.assertEqual(len(report["samples"]), 12)
        self.assertEqual(report["samples"][0]["values"][1]["value"], 800)
        self.assertEqual(report["samples"][5]["values"][1]["value"], 3000)
        calibration = replay_session(
            examples / "calibration-session.json", operation="calibration"
        )
        self.assertEqual(calibration["calibration_ids"], ["DEMO-CAL-0001"])
        self.assertEqual(calibration["cvns"], ["DEADBEEF"])

    def test_report_never_replaces_source_recording_or_alias(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "recording.json"
            source.write_text("preserve recording", encoding="utf-8")
            linked = root / "alias.json"
            linked.symlink_to(source)
            hard = root / "hard.json"
            os.link(source, hard)
            for target in (source, linked, hard):
                with self.subTest(target=target), self.assertRaises(ValueError):
                    save_report(target, {}, source=source)
                self.assertEqual(source.read_text(), "preserve recording")

    def test_example_decodes_bytes_and_report_roundtrips(self):
        example = (
            Path(__file__).resolve().parents[1] / "examples/diagnostic-session.json"
        )
        report = replay_session(example)
        self.assertEqual(report["source"], "authored_synthetic")
        self.assertEqual(report["physical_status"], "PHYSICAL_UNCONFIRMED")
        self.assertEqual(len(report["ecus"]), 2)
        self.assertEqual(report["ecus"][0]["stored_dtcs"], ["P0133", "P0420"])
        self.assertEqual(report["ecus"][0]["status"], "ok")
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "session.json"
            destination.write_text("earlier report", encoding="utf-8")
            save_report(destination, report)
            self.assertEqual(json.loads(destination.read_text()), report)
            self.assertEqual(list(Path(temporary).iterdir()), [destination])


if __name__ == "__main__":
    unittest.main()
