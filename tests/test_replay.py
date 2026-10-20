import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.diagnostics import DiagnosticError, Session
from scripts.replay import (
    Recorder,
    Replay,
    ReplayError,
    ReplayExhausted,
    ReplayMismatch,
)


def document():
    return {
        "schema": "techstream-native-replay-v1",
        "source": "authored_synthetic",
        "ecus": ["engine"],
        "transactions": [{"ecu": "engine", "request": "0105", "response": "41057b"}],
    }


class ReplayTests(unittest.TestCase):
    def test_exact_order_and_exhaustion(self):
        replay = Replay(document())
        for ecu, request in (("other", b"\x01\x05"), ("engine", b"\x01\x0d")):
            with self.assertRaises(ReplayMismatch):
                replay.exchange(ecu, request)
            self.assertEqual(replay.remaining, 1)
        with self.assertRaises(ReplayMismatch):
            replay.assert_complete()
        self.assertEqual(
            replay.exchange("engine", b"\x01\x05"), bytes.fromhex("41057b")
        )
        replay.assert_complete()
        with self.assertRaises(ReplayExhausted):
            replay.exchange("engine", b"\x01\x05")

    def test_writes_rejected_before_backend(self):
        replay = Replay(document())
        with self.assertRaises(DiagnosticError):
            replay.exchange("engine", b"\x04")
        self.assertEqual(replay.remaining, 1)
        doc = document()
        doc["transactions"][0]["request"] = "04"
        with self.assertRaises(DiagnosticError):
            Replay(doc)

    def test_malformed_hex_and_schema(self):
        for value in ("", "0", "gg", "01 05", "00" * 4096, 12, None):
            doc = document()
            doc["transactions"][0]["response"] = value
            with self.subTest(value=str(value)[:10]), self.assertRaises(ReplayError):
                Replay(doc)
        for field, value in (
            ("schema", "future"),
            ("source", "real_vehicle"),
            ("ecus", []),
            ("ecus", ["engine", "engine"]),
            ("transactions", []),
        ):
            doc = document()
            doc[field] = value
            with self.subTest(field=field), self.assertRaises(ReplayError):
                Replay(doc)
        doc = document()
        doc["unexpected"] = True
        with self.assertRaises(ReplayError):
            Replay(doc)
        doc = document()
        doc["transactions"][0]["ecu"] = "not_configured"
        with self.assertRaises(ReplayError):
            Replay(doc)

    def test_uncorrelated_and_malformed_protocol_rejected(self):
        for response in ("410d7b", "4105", "7f0912", "41057b00"):
            doc = document()
            doc["transactions"][0]["response"] = response
            with self.subTest(response=response), self.assertRaises(ReplayError):
                Replay(doc)
        for request, response in (("03", "4302"), ("0902", "49020100")):
            doc = document()
            doc["transactions"][0].update(request=request, response=response)
            with self.assertRaises(ReplayError):
                Replay(doc)
        doc = document()
        doc["transactions"][0]["response"] = "7f0112"
        replay = Replay(doc)
        self.assertEqual(
            replay.exchange("engine", b"\x01\x05"), bytes.fromhex("7f0112")
        )

    def test_oversize_json_rejected_before_parse(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "big.json"
            with path.open("wb") as stream:
                stream.truncate(16 * 1024 * 1024 + 1)
            with self.assertRaises(ReplayError):
                Replay.load(path)

    def test_duplicate_keys_and_bad_json(self):
        for raw in ('{"schema":1,"schema":2}', "[", "[]", "null"):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "bad.json"
                path.write_text(raw)
                with self.assertRaises(ReplayError):
                    Replay.load(path)

    def test_record_roundtrip_and_no_overwrite(self):
        replay = Replay(document())
        recorder = Recorder(replay.exchange)
        value = Session(recorder.exchange).poll("engine", [5])[0]["values"][0]
        self.assertEqual(value["value"], 83)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            recorder.save(path)
            saved = Replay.load(path)
            self.assertEqual(saved.source, "recorded_unverified")
            self.assertEqual(
                Session(saved.exchange).poll("engine", [5])[0]["values"][0], value
            )
            saved.assert_complete()
            before = path.read_bytes()
            with self.assertRaises(FileExistsError):
                recorder.save(path)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(json.loads(before)["ecus"], ["engine"])

    def test_record_rejects_invalid_backend_data(self):
        for response in (b"", b"x" * 4096, "41057b"):
            recorder = Recorder(lambda ecu, request, response=response: response)  # type: ignore[arg-type]
            with self.assertRaises(ReplayError):
                recorder.exchange("engine", b"\x01\x05")
            self.assertEqual(recorder.transactions, [])

    def test_calibration_and_extra_pid_record_replay(self):
        doc = document()
        doc["transactions"] = [
            {"ecu": "engine", "request": "0900", "response": "490014000000"},
            {
                "ecu": "engine",
                "request": "0904",
                "response": "490401" + b"SYNTHETIC".ljust(16, b"\x00").hex(),
            },
            {"ecu": "engine", "request": "0906", "response": "49060100000123"},
            {"ecu": "engine", "request": "0104", "response": "4104ff"},
        ]
        replay = Replay(doc)
        recorder = Recorder(replay.exchange)
        result = Session(recorder.exchange).calibration("engine")
        self.assertEqual(result["calibration_ids"], ["SYNTHETIC"])
        self.assertEqual(
            Session(recorder.exchange).poll("engine", [4])[0]["values"][0]["value"], 100
        )
        replay.assert_complete()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "calibration.json"
            recorder.save(path)
            saved = Replay.load(path)
            self.assertEqual(Session(saved.exchange).calibration("engine"), result)
            Session(saved.exchange).poll("engine", [4])
            saved.assert_complete()
        for request, response in (
            ("0900", "490000"),
            ("0904", "49040100"),
            ("0906", "49060200000000"),
        ):
            doc = document()
            doc["transactions"][0].update(request=request, response=response)
            with self.assertRaises(ReplayError):
                Replay(doc)

    def test_input_document_is_copied(self):
        doc = document()
        replay = Replay(doc)
        changed = copy.deepcopy(doc)
        changed["ecus"].append("other")
        doc["ecus"].append("other")
        doc["transactions"][0]["response"] = "410500"
        self.assertEqual(replay.ecus, ["engine"])
        self.assertEqual(
            replay.exchange("engine", b"\x01\x05"), bytes.fromhex("41057b")
        )


if __name__ == "__main__":
    unittest.main()
