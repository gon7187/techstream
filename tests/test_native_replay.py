"""Authored native PDU records, native statuses and selected-resource execution."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.demo import create_demo
from scripts.native_replay import NativeReplay, replay_profile
from scripts.profiles import VehicleCatalog
from scripts.toyota import CommandFrame
from scripts.toyota_session import CommandSpec, NativeStatus, ToyotaSession


def document():
    return {
        "schema": "techstream-native-exchange-v1",
        "source": "authored_synthetic",
        "ecus": ["engine"],
        "support": {"engine": {"pid_lengths": {"0c": 2}, "did_lengths": None}},
        "transactions": [{"ecu": "engine", "request": "010c", "response": "410c1f40"}],
    }


class NativeReplayTests(unittest.TestCase):
    def test_explicit_recorder_byte_bound_preserves_default_pdu_and_aggregate_limits(
        self,
    ):
        source = document()
        response = b"x" * 65536
        source["transactions"] = [
            {"ecu": "engine", "request": "01", "response": response.hex()}
        ]
        with self.assertRaises(ValueError):
            NativeReplay(source)
        replay = NativeReplay(source, max_pdu_bytes=len(response))
        self.assertEqual(replay.exchange("engine", b"\x01"), response)
        replay.assert_complete()
        for bound in (0, -1, True, 16 * 1024 * 1024 + 1):
            with self.subTest(bound=bound), self.assertRaises(ValueError):
                NativeReplay(source, max_pdu_bytes=bound)

    def test_strict_order_copied_observations_and_exhaustion(self):
        original = document()
        replay = NativeReplay(original)
        original["transactions"][0]["response"] = "corrupt"
        original["support"]["engine"]["pid_lengths"]["0c"] = 3
        observation, _ = replay.observations("engine")
        self.assertEqual(observation, {12: 2})
        assert observation is not None
        observation[12] = 9
        self.assertEqual(replay.observations("engine")[0], {12: 2})
        for ecu, request in (("other", b"\x01\x0c"), ("engine", b"\x01\0")):
            with self.assertRaisesRegex(ValueError, "mismatch"):
                replay.exchange(ecu, request)
            self.assertEqual(replay.position, 0)
        self.assertEqual(replay.exchange("engine", b"\x01\x0c"), b"\x41\x0c\x1f\x40")
        replay.assert_complete()
        with self.assertRaisesRegex(ValueError, "exhausted"):
            replay.exchange("engine", b"\x01\x0c")

    def test_receive_only_and_native_status_execute_through_real_session(self):
        source = document()
        source["transactions"] = [
            {"ecu": "engine", "request": "18", "response": "58010203040506"},
            {"ecu": "engine", "request": "", "response": "5807080000"},
        ]
        replay = NativeReplay(source)
        session = ToyotaSession(
            replay.exchange, "engine", {"dtc": CommandSpec(CommandFrame(b"\x18"))}
        )
        self.assertEqual(session.dtcs("dtc"), [0x0102, 0x0304, 0x0506, 0x0708])
        replay.assert_complete()
        source["transactions"] = [
            {
                "ecu": "engine",
                "request": "18",
                "status": 0x91010009,
                "partial_response": "5801",
            }
        ]
        replay = NativeReplay(source)
        with self.assertRaises(NativeStatus) as error:
            replay.exchange("engine", b"\x18")
        self.assertEqual(error.exception.code, 0x91010009)
        self.assertEqual(error.exception.reply, b"\x58\x01")
        replay.assert_complete()

    def test_unobserved_support_is_not_an_observed_empty_support_list(self):
        source = document()
        source["support"] = {}
        self.assertEqual(NativeReplay(source).observations("engine"), (None, None))
        source["support"] = {"engine": {"pid_lengths": {}, "did_lengths": {}}}
        self.assertEqual(NativeReplay(source).observations("engine"), ({}, {}))

    def test_malformed_schema_native_status_hex_and_observations_rejected(self):
        cases = []
        for field, value in (
            ("schema", "other"),
            ("source", "physically_verified"),
            ("ecus", ["engine", "engine"]),
            ("ecus", ["bad\nname"]),
            ("support", {"other": {"pid_lengths": {}, "did_lengths": None}}),
            ("transactions", []),
        ):
            source = document()
            source[field] = value
            cases.append(source)
        for field, value in (
            ("request", "0"),
            ("request", "01 0c"),
            ("response", "xy"),
            ("response", 42),
            ("ecu", "other"),
        ):
            source = document()
            source["transactions"][0][field] = value
            cases.append(source)
        for value in (0, -1, True, 0x100000000, "77"):
            source = document()
            source["transactions"] = [
                {
                    "ecu": "engine",
                    "request": "18",
                    "status": value,
                    "partial_response": "",
                }
            ]
            cases.append(source)
        for value in ({"0C": 2}, {"0c": -1}, {"0c": True}, {"100": 1}, []):
            source = document()
            source["support"]["engine"]["pid_lengths"] = value
            cases.append(source)
        for source in cases:
            with self.subTest(source=source), self.assertRaises(ValueError):
                NativeReplay(source)

    def test_cancel_and_file_json_boundaries(self):
        replay = NativeReplay(document(), lambda: True)
        with self.assertRaises(InterruptedError):
            replay.exchange("engine", b"\x01\x0c")
        self.assertEqual(replay.position, 0)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "recording.json"
            for raw in (
                b'{"schema":1,"schema":2}',
                b"[]",
                b"[" * 2000,
                b"\xff",
                b" " * (16 * 1024 * 1024 + 1),
            ):
                path.write_bytes(raw)
                with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                    NativeReplay.load(path)

    def test_selected_native_readiness_and_signal_recordings_are_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            application = create_demo(root / "data")
            profile = VehicleCatalog(application / "Techstream_DB_NA").build_profile(1)
            path = root / "recording.json"
            source = document()
            source["transactions"].insert(
                0, {"ecu": "engine", "request": "210c", "response": "610c80"}
            )
            path.write_text(json.dumps(source))
            for operation in ("readiness", "data_list"):
                report = replay_profile(
                    profile, path, operation=operation, signal_keys=(1,)
                )
                self.assertEqual(report["result"]["signals"][0]["value"]["value"], 2000)
                self.assertEqual(report["source"], "authored_synthetic")
                self.assertEqual(report["physical_status"], "PHYSICAL_UNCONFIRMED")
            source = document()
            source["support"] = {}
            path.write_text(json.dumps(source))
            with self.assertRaisesRegex(ValueError, "observations"):
                replay_profile(profile, path)
            source = document()
            source["transactions"].insert(
                0, {"ecu": "engine", "request": "210c", "response": "610c80"}
            )
            source["transactions"] += copy.deepcopy(source["transactions"])
            path.write_text(json.dumps(source))
            with self.assertRaisesRegex(ValueError, "unconsumed"):
                replay_profile(profile, path)


if __name__ == "__main__":
    unittest.main()
