import unittest
from pathlib import Path

from scripts.diagnostics import (
    Cancelled,
    DiagnosticError,
    NegativeResponse,
    Session,
    correlate,
    decode_calibration_ids,
    decode_cvns,
    decode_dtc,
    decode_dtcs,
    decode_pid,
    decode_readiness,
    decode_vin,
    supported_pids,
    validate_request,
)
from scripts.replay import Replay

ROOT = Path(__file__).resolve().parents[1]


class DecoderTests(unittest.TestCase):
    def test_dtc_categories_and_count(self):
        self.assertEqual(
            decode_dtcs(bytes.fromhex("0401335234a123ffff")),
            ["P0133", "C1234", "B2123", "U3FFF"],
        )
        self.assertEqual(decode_dtcs(b"\x00"), [])
        self.assertIsNone(decode_dtc(b"\x00\x00"))
        for data in (b"", b"\x01", b"\x01\x00\x00", b"\x00\x00\x00"):
            with self.subTest(data=data), self.assertRaises(DiagnosticError):
                decode_dtcs(data)

    def test_values(self):
        self.assertEqual(decode_pid(5, b"\x00")["value"], -40)
        self.assertEqual(decode_pid(5, b"\xff")["value"], 215)
        self.assertEqual(decode_pid(12, bytes.fromhex("1f40"))["value"], 2000)
        self.assertEqual(decode_pid(12, b"\xff\xff")["value"], 16383.75)
        self.assertEqual(decode_pid(13, b"\x32")["value"], 50)
        self.assertEqual(decode_pid(17, b"\xff")["value"], 100)
        with self.assertRaises(DiagnosticError):
            decode_pid(12, b"\x01")

    def test_extra_numeric_pid_boundaries(self):
        expected = {
            0x04: (b"\xff", 100),
            0x06: (b"\x00", -100),
            0x07: (b"\x80", 0),
            0x08: (b"\xff", 99.21875),
            0x09: (b"\x40", -50),
            0x0A: (b"\xff", 765),
            0x0B: (b"\xff", 255),
            0x0E: (b"\x00", -64),
            0x0F: (b"\xff", 215),
            0x10: (b"\xff\xff", 655.35),
            0x1F: (b"\xff\xff", 65535),
        }
        for pid, (payload, value) in expected.items():
            with self.subTest(pid=pid):
                self.assertEqual(decode_pid(pid, payload)["value"], value)
                self.assertEqual(
                    correlate(bytes([1, pid]), bytes([0x41, pid]) + payload), payload
                )
                self.assertEqual(
                    correlate(bytes([2, pid, 0]), bytes([0x42, pid, 0]) + payload),
                    payload,
                )
                with self.assertRaises(DiagnosticError):
                    correlate(bytes([1, pid]), bytes([0x41, pid]) + payload + b"\x00")

    def test_calibration_record_decoders(self):
        data = (
            b"\x02"
            + b"SYNTHETIC-A".ljust(16, b"\x00")
            + b"SYNTHETIC-B".ljust(16, b"\x00")
        )
        self.assertEqual(decode_calibration_ids(data), ["SYNTHETIC-A", "SYNTHETIC-B"])
        self.assertEqual(
            decode_cvns(bytes.fromhex("0200000123deadbeef")), ["00000123", "DEADBEEF"]
        )
        for data in (
            b"",
            b"\x00",
            b"\x01SHORT",
            b"\x01" + b"\x00" * 16,
            b"\x01" + b"A\x00B".ljust(16, b"\x00"),
            b"\x01" + b"\xff" * 16,
        ):
            with self.subTest(data=data[:8]), self.assertRaises(DiagnosticError):
                decode_calibration_ids(data)
        for data in (b"", b"\x00", b"\x02\x01\x02\x03\x04"):
            with self.assertRaises(DiagnosticError):
                decode_cvns(data)

    def test_vin(self):
        self.assertEqual(decode_vin(b"\x01SYNTHET1C00000000"), "SYNTHET1C00000000")
        for data in (
            b"\x01SHORT",
            b"\x02SYNTHET1C00000000",
            b"\x01SYNTHETIC00000000",
            b"\x01" + b"\xff" * 17,
        ):
            with self.subTest(data=data), self.assertRaises(DiagnosticError):
                decode_vin(data)

    def test_readiness_support_is_not_completion(self):
        result = decode_readiness(bytes.fromhex("82176501"))
        self.assertTrue(result["mil_on"])
        self.assertEqual(result["dtc_count"], 2)
        rows = {row["name"]: row for row in result["monitors"]}
        self.assertFalse(rows["misfire"]["complete"])
        self.assertFalse(rows["catalyst"]["complete"])
        self.assertTrue(rows["oxygen_sensor"]["complete"])
        self.assertIsNone(rows["heated_catalyst"]["complete"])
        diesel = decode_readiness(bytes.fromhex("00080000"))
        self.assertEqual(diesel["ignition"], "compression")
        self.assertIn("particulate_filter", [row["name"] for row in diesel["monitors"]])

    def test_support_bits(self):
        self.assertEqual(supported_pids(bytes.fromhex("80000001")), [1, 32])

    def test_correlation(self):
        self.assertEqual(correlate(b"\x01\x05", b"\x41\x05\x60"), b"\x60")
        for response in (
            b"",
            b"\x41\x0d\x60",
            b"\x41\x05",
            b"\x41\x05\x60\x00",
            b"\x7f\x09\x11",
            b"\x00" * 4096,
        ):
            with (
                self.subTest(response=response[:8]),
                self.assertRaises(DiagnosticError),
            ):
                correlate(b"\x01\x05", response)
        with self.assertRaises(NegativeResponse) as error:
            correlate(b"\x01\x05", bytes.fromhex("7f0112"))
        self.assertEqual(error.exception.code, 0x12)

    def test_request_allowlist(self):
        for request in (
            b"\x04",
            b"\x08\x01",
            b"\x22\xf1\x90",
            b"\x2e\xf1\x90",
            b"\x01\xff",
            b"\x02\x05\x01",
            b"\x03\x00",
            b"",
            "0105",
        ):
            with self.subTest(request=request), self.assertRaises(DiagnosticError):
                validate_request(request)  # type: ignore[arg-type]


class SessionTests(unittest.TestCase):
    def test_complete_synthetic_scenario(self):
        replay = Replay.load(ROOT / "examples/diagnostic-session.json")
        session = Session(replay.exchange)
        report = session.health_check(replay.ecus)
        self.assertEqual(report["physical_status"], "PHYSICAL_UNCONFIRMED")
        engine, transmission = report["ecus"]
        self.assertEqual(engine["status"], "ok")
        self.assertEqual(engine["stored_dtcs"], ["P0133", "P0420"])
        self.assertEqual(engine["pending_dtcs"], ["P0171"])
        self.assertEqual(engine["permanent_dtcs"], ["P0420"])
        self.assertEqual(engine["freeze_dtc"], "P0133")
        self.assertEqual(engine["freeze"][1]["value"], 2250)
        self.assertEqual(transmission["stored_dtcs"], [])
        self.assertEqual(transmission["freeze"], [])
        replay.assert_complete()
        rows = [
            {
                "ecu": "engine",
                "request": f"01{pid:02x}",
                "response": f"41{pid:02x}" + data,
            }
            for rpm in ("0c80", "0ce4")
            for pid, data in ((5, "7b"), (12, rpm), (13, "00"), (17, "20"))
        ]
        replay = Replay(
            {
                "schema": "techstream-native-replay-v1",
                "source": "authored_synthetic",
                "ecus": ["engine"],
                "transactions": rows,
            }
        )
        session = Session(replay.exchange)
        samples = session.poll("engine", samples=2)
        self.assertEqual(samples[0]["values"][1]["value"], 800)
        self.assertEqual(samples[1]["values"][1]["value"], 825)
        replay.assert_complete()

    def test_cancellation_before_and_after_exchange(self):
        calls = []
        session = Session(
            lambda ecu, request: calls.append(request) or b"\x41\x05\x60", lambda: True
        )
        with self.assertRaises(Cancelled):
            session.read("engine", b"\x01\x05")
        self.assertEqual(calls, [])
        session = Session(
            lambda ecu, request: calls.append(request) or b"\x41\x05\x60",
            lambda: bool(calls),
        )
        with self.assertRaises(Cancelled):
            session.read("engine", b"\x01\x05")

    def test_timeout_and_negative_response_are_partial(self):
        def exchange(ecu, request):
            if request == b"\x09\x02":
                raise TimeoutError("no VIN reply")
            if request in (b"\x01\x00", b"\x02\x00\x00"):
                return bytes([request[0] + 64]) + request[1:] + b"\x00" * 4
            return bytes([0x7F, request[0], 0x12])

        result = Session(exchange).health_check(["engine", "other"])
        for ecu in result["ecus"]:
            self.assertEqual(ecu["status"], "partial")
            self.assertEqual(ecu["live"], [])
            self.assertNotIn("vin", ecu)
            self.assertEqual(ecu["errors"][0]["type"], "TimeoutError")

    def test_poll_sample_times_and_clock_validation(self):
        moments = iter((10.0, 10.0, 10.25))
        session = Session(
            lambda ecu, request: b"\x41\x05\x60",
            clock=lambda moments=moments: next(moments),
        )
        samples = session.poll("engine", [5], samples=2)
        self.assertEqual([sample["elapsed_seconds"] for sample in samples], [0, 0.25])
        for values in ((float("nan"),), (10.0, 9.0), (10.0, float("inf"))):
            moments = iter(values)
            session = Session(
                lambda ecu, request: b"\x41\x05\x60",
                clock=lambda moments=moments: next(moments),
            )
            with self.assertRaises(DiagnosticError):
                session.poll("engine", [5])

    def test_calibration_support_and_partial_errors(self):
        requests = []

        def exchange(ecu, request):
            requests.append(request)
            return {
                b"\x09\x00": bytes.fromhex("490014000000"),
                b"\x09\x04": b"\x49\x04\x01" + b"SYNTHETIC-CAL".ljust(16, b"\x00"),
                b"\x09\x06": bytes.fromhex("49060100000123"),
            }[request]

        result = Session(exchange).calibration("engine")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["supported_info_types"], [4, 6])
        self.assertEqual(result["calibration_ids"], ["SYNTHETIC-CAL"])
        self.assertEqual(result["cvns"], ["00000123"])
        self.assertEqual(requests, [b"\x09\x00", b"\x09\x04", b"\x09\x06"])
        result = Session(
            lambda ecu, request: bytes.fromhex("490000000000")
        ).calibration("engine")
        self.assertNotIn("calibration_ids", result)
        self.assertNotIn("cvns", result)
        result = Session(lambda ecu, request: bytes.fromhex("7f0912")).calibration(
            "engine"
        )
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["errors"][0]["type"], "NegativeResponse")

    def test_streaming_poll_is_lazy_and_cancellable(self):
        calls = []
        cancelled = False
        session = Session(
            lambda ecu, request: calls.append(request) or b"\x41\x04\xff",
            lambda: cancelled,
        )
        samples = session.iter_poll("engine", [4], samples=10000)
        self.assertEqual(calls, [])
        self.assertEqual(next(samples)["values"][0]["value"], 100)
        self.assertEqual(len(calls), 1)
        cancelled = True
        with self.assertRaises(Cancelled):
            next(samples)
        self.assertEqual(len(calls), 1)

    def test_invalid_plan_never_exchanges(self):
        def unexpected(ecu, request):
            self.fail("invalid plan reached exchange")

        session = Session(unexpected)
        for ecus in ([], ["a", "a"], ["bad/ecu"], "abc", [["bad"]]):
            with self.assertRaises(DiagnosticError):
                session.health_check(ecus)  # type: ignore[arg-type]
        for samples in (0, 10001, True):
            with self.assertRaises(DiagnosticError):
                session.poll("engine", samples=samples)
        for pids in ([], [5, 5], [255], [5.0]):
            with self.assertRaises(DiagnosticError):
                session.poll("engine", pids=pids)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
