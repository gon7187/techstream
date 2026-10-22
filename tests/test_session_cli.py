import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts.session_cli import parse_pids, replay_session, save_report


class SessionCLITests(unittest.TestCase):
    def test_nonregular_recording_is_rejected_without_opening(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "recording.json"
            os.mkfifo(path)
            with self.assertRaisesRegex(ValueError, "ordinary local"):
                replay_session(path)

    def test_pid_selection_and_recorded_freeze_requests(self):
        self.assertEqual(parse_pids("0C, 0x0D"), [12, 13])
        self.assertIsNone(parse_pids("  "))
        for text in ("0C,0c", "100", "-1", "garbage"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_pids(text)
        recording = {
            "schema": "techstream-native-replay-v1",
            "source": "authored_synthetic",
            "ecus": ["engine"],
            "transactions": [
                {"ecu": "engine", "request": "020000", "response": "42000000080000"},
                {"ecu": "engine", "request": "020d00", "response": "420d0032"},
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "freeze.json"
            path.write_text(json.dumps(recording), encoding="utf-8")
            report = replay_session(
                path, operation="parameters", pids=[13], freeze=True
            )
            self.assertEqual(report["service"], 2)
            self.assertEqual(report["values"][0]["value"], 50)
            with self.assertRaises(ValueError):
                replay_session(path, operation="parameters", pids=[12], freeze=True)
            recording["transactions"].pop()
            path.write_text(json.dumps(recording), encoding="utf-8")
            self.assertEqual(
                replay_session(path, operation="support", service=2)["supported_pids"],
                [13],
            )

    def test_extended_operations_decode_real_ordered_recordings(self):
        cases = {
            "monitors": [("0600", "460080000000"), ("0601", "4601010a03e8000007d0")],
            "support": [("0100", "410000080000")],
            "parameters": [
                ("0100", "410000180000"),
                ("010c", "410c1f40"),
                ("010d", "410d32"),
            ],
            "vehicle_info": [
                ("0900", "490040000000"),
                ("0902", "490201" + b"SYNTHET1C00000000".hex()),
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "recording.json"
            for mode, exchanges in cases.items():
                recording = {
                    "schema": "techstream-native-replay-v1",
                    "source": "authored_synthetic",
                    "ecus": ["engine"],
                    "transactions": [
                        {"ecu": "engine", "request": request, "response": response}
                        for request, response in exchanges
                    ],
                }
                path.write_text(json.dumps(recording), encoding="utf-8")
                with self.subTest(mode=mode):
                    report = replay_session(path, operation=mode)
                    self.assertEqual(report["physical_status"], "PHYSICAL_UNCONFIRMED")
                    self.assertEqual(report["source"], "authored_synthetic")
                    if mode == "monitors":
                        self.assertEqual(report["status"], "ok")
                        self.assertEqual(report["results"][0]["value"], 0.122)
                    elif mode == "support":
                        self.assertEqual(report["supported_pids"], [13])
                    elif mode == "parameters":
                        self.assertEqual(
                            [value["value"] for value in report["values"]], [2000, 50]
                        )
                    else:
                        self.assertEqual(report["values"]["02"], "SYNTHET1C00000000")
                    with self.assertRaises(ValueError):
                        replay_session(path, operation=mode, ecu="not-recorded")
                    with self.assertRaises(ValueError):
                        replay_session(path, cancelled=lambda: True, operation=mode)
                    recording["transactions"].append(recording["transactions"][-1])
                    path.write_text(json.dumps(recording), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        replay_session(path, operation=mode)

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
            second = root / "second.json"
            second.write_text("preserve second source", encoding="utf-8")
            with self.assertRaises(ValueError):
                save_report(second, {}, source=source, sources=(source, second))
            self.assertEqual(second.read_text(), "preserve second source")

    def test_multi_source_preflight_and_write_failure_preserve_all_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second = root / "first", root / "second"
            first.write_bytes(b"first source")
            second.write_bytes(b"second source")
            alias, hard = root / "alias", root / "hard"
            alias.symlink_to(second)
            os.link(second, hard)
            for destination in (second, alias, hard):
                with (
                    self.subTest(destination=destination),
                    self.assertRaises(ValueError),
                ):
                    save_report(destination, {}, sources=(first, second))
            output = root / "report.json"
            output.write_bytes(b"existing report")
            with self.assertRaises(OSError):
                save_report(output, {}, sources=(first, root / "missing"))
            self.assertEqual(output.read_bytes(), b"existing report")
            with self.assertRaises(OSError):
                save_report(root, {}, sources=(first, second))
            self.assertEqual(first.read_bytes(), b"first source")
            self.assertEqual(second.read_bytes(), b"second source")

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
