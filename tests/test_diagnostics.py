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
                    correlate(
                        bytes([1, pid]),
                        bytes([0x41, pid])
                        + payload
                        + (b"\x00\x00" if pid in (6, 7, 8, 9) else b"\x00"),
                    )

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


class ExtendedOBDTests(unittest.TestCase):
    @staticmethod
    def bitmap(base, pids):
        return sum(1 << (32 - (pid - base)) for pid in pids).to_bytes(4, "big")

    def test_continuation_all_eight_pages_and_highest_pid(self):
        calls = []

        def exchange(ecu, request):
            calls.append(request)
            base = request[1]
            pids = [base + 1, base + 32] if base < 224 else [255]
            return bytes([0x41, base]) + self.bitmap(base, pids)

        self.assertEqual(
            Session(exchange).support("engine"), [1, 33, 65, 97, 129, 161, 193, 255]
        )
        self.assertEqual(len(calls), 8)
        self.assertEqual(supported_pids(b"\x00\x00\x00\x02", 224), [255])
        self.assertEqual(supported_pids(b"\x80\x00\x00\x00", 32), [33])
        with self.assertRaises(DiagnosticError):
            supported_pids(b"\x00\x00\x00\x01", 224)

    def test_monitor_multiple_records_signed_and_not_completed(self):
        import struct

        from scripts.diagnostics import decode_monitor_records

        records = b"".join(
            struct.pack(">BBBHHH", 0x3C, tid, scale, *values)
            for tid, scale, values in (
                (128, 0xFE, (0xFFFC, 0xFFF8, 4)),
                (129, 0x24, (0, 0, 0)),
                (130, 0x16, (400, 400, 400)),
                (131, 0x24, (21, 0, 20)),
                (132, 0x80, (1, 0, 2)),
            )
        )
        decoded = decode_monitor_records(0x3C, records)
        self.assertEqual(
            [row["status"] for row in decoded],
            ["pass", "not_completed", "pass", "fail", "unresolved_scaling"],
        )
        self.assertEqual(decoded[0]["value"], -1)
        self.assertEqual(decoded[0]["minimum"], -2)
        self.assertEqual(decoded[2]["value"], 0)
        self.assertNotIn("value", decoded[-1])
        self.assertEqual(correlate(b"\x06\x3c", b"\x46" + records), records)

    def test_every_defined_scaling_signed_boundaries(self):
        import struct

        from scripts.diagnostics import MONITOR_SCALES, decode_monitor_records

        self.assertEqual(len(MONITOR_SCALES), 92)
        for scaling in MONITOR_SCALES:
            with self.subTest(scaling=scaling):
                values = (
                    (0, 0x8000, 0x7FFF)
                    if scaling & 128
                    else (1, 0, 1 if scaling == 0x2E else 0xFFFF)
                )
                row = decode_monitor_records(
                    1, struct.pack(">BBBHHH", 1, 128, scaling, *values)
                )[0]
                self.assertEqual(row["status"], "pass")
                self.assertLessEqual(row["minimum"], row["value"])
                self.assertLessEqual(row["value"], row["maximum"])
        row = decode_monitor_records(1, bytes.fromhex("01800b03e8000007d0"))[0]
        self.assertEqual((row["value"], row["maximum"], row["unit"]), (1, 2, "V"))
        row = decode_monitor_records(1, bytes.fromhex("01803980000000ffff"))[0]
        self.assertEqual(row["value"], 0)
        row = decode_monitor_records(1, bytes.fromhex("018020010000000100"))[0]
        self.assertEqual(row["value"], 1)

    def test_monitor_bounds_repeated_mid_and_duplicate_tid(self):
        from scripts.diagnostics import decode_monitor_records

        good = bytes.fromhex("018001000a00000014")
        for bad in (
            b"",
            good[:-1],
            good + b"\x00",
            b"\x02" + good[1:],
            good + good,
            bytes.fromhex("018001000a00140000"),
            bytes.fromhex("01802e000200000001"),
            bytes.fromhex("010001000100000001"),
            bytes.fromhex("01ff01000100000001"),
        ):
            with self.subTest(bad=bad.hex()), self.assertRaises(DiagnosticError):
                decode_monitor_records(1, bad)
        with self.assertRaises(DiagnosticError):
            correlate(b"\x06\x00", b"\x46\x00\x00")
        with self.assertRaises(DiagnosticError):
            correlate(b"\x06\x01", b"\x47" + good)
        for response in (b"\x7f\x05\x12", b"\x7f\x06", b"\x7f\x06\x12\x00"):
            with self.assertRaises(DiagnosticError):
                correlate(b"\x06\x01", response)
        with self.assertRaises(NegativeResponse):
            correlate(b"\x06\x01", b"\x7f\x06\x78")

    def test_monitor_support_gating_and_failure_retention(self):
        requests = []

        def exchange(ecu, request):
            requests.append(request)
            if request == b"\x06\x00":
                return b"\x46\x00" + self.bitmap(0, [1, 2])
            if request == b"\x06\x01":
                raise TimeoutError("synthetic timeout")
            return bytes.fromhex("46028080000100000002")

        report = Session(exchange).monitors("engine")
        self.assertEqual(requests, [b"\x06\x00", b"\x06\x01", b"\x06\x02"])
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["errors"][0]["type"], "TimeoutError")
        self.assertEqual(report["results"][0]["status"], "unresolved_scaling")
        self.assertEqual(
            Session(lambda e, r: b"\x7f\x06\x11").monitors("engine")["status"],
            "partial",
        )
        with self.assertRaises(Cancelled):
            Session(lambda e, r: b"", cancelled=lambda: True).monitors("engine")

    def test_compound_o2_and_evap_are_separate_fields(self):
        from scripts.diagnostics import decode_parameter

        narrow = decode_parameter(0x14, b"\xc8\xff")
        self.assertEqual(narrow["voltage"], 1)
        self.assertIsNone(narrow["fuel_trim"])
        self.assertEqual(decode_parameter(0x14, b"\x00\x80")["fuel_trim"], 0)
        wide = decode_parameter(0x24, bytes.fromhex("80002000"))
        self.assertEqual((wide["equivalence_ratio"], wide["voltage"]), (1, 1))
        current = decode_parameter(0x34, bytes.fromhex("80007fff"))
        self.assertEqual(current["current"], -1 / 256)
        self.assertEqual(decode_parameter(0x32, b"\x80\x00")["value"], -8192)
        self.assertEqual(decode_parameter(0x32, b"\x7f\xff")["value"], 8191.75)
        self.assertTrue(decode_parameter(0x1D, b"\x04")["sensors"][2]["present"])
        self.assertEqual(decode_parameter(0x1D, b"\x04")["sensors"][2]["bank"], 2)
        readiness = decode_parameter(0x41, b"\x00\x07\x01\x01")
        self.assertNotIn("mil_on", readiness)
        self.assertFalse(readiness["monitors"][3]["complete"])
        self.assertEqual(
            decode_parameter(3, b"\x02\x00")["fuel_systems"][0]["status"], "closed_loop"
        )
        self.assertEqual(decode_parameter(0x1C, b"\x0a")["obd_requirement"], "JOBD")
        self.assertTrue(decode_parameter(0x1E, b"\x01")["pto_active"])
        for pid, payload in ((0x14, b""), (0x24, b"\x00" * 3), (0x32, b"\x00")):
            with self.assertRaises(DiagnosticError):
                decode_parameter(pid, payload)

    def test_all_defined_parameters_have_decoders_and_exact_lengths(self):
        from scripts.diagnostics import PID_SIZES, decode_parameter

        for pid, length in PID_SIZES.items():
            with self.subTest(pid=pid):
                decode_parameter(pid, bytes(length))
                with self.assertRaises(DiagnosticError):
                    decode_parameter(pid, bytes(length + 2))

    def test_parameter_support_queries_separate_freeze_and_live(self):
        calls = []

        def exchange(ecu, request):
            calls.append(request)
            if request[1] == 0:
                return bytes([request[0] + 0x40]) + request[1:] + self.bitmap(0, [0x14])
            return bytes([request[0] + 0x40]) + request[1:] + b"\xc8\x80"

        session = Session(exchange)
        self.assertEqual(
            session.parameters("engine", [0x14])["values"][0]["voltage"], 1
        )
        self.assertEqual(session.parameters("engine", [0x14], True)["service"], 2)
        self.assertIn(b"\x02\x14\x00", calls)
        with self.assertRaises(DiagnosticError):
            session.parameters("engine", [0x24])
        self.assertNotIn(b"\x01\x24", calls)

    def test_legacy_mode05_explicit_non_can_and_exact_lengths(self):
        from scripts.diagnostics import decode_oxygen_test

        self.assertEqual(decode_oxygen_test(1, b"\xc8")["value"], 1)
        self.assertEqual(decode_oxygen_test(5, b"\x64\x00\xff")["value"], 0.4)
        for tid, payload in (
            (1, b"\x00\x00\x00"),
            (5, b"\x00"),
            (5, b"\x01\xff\x00"),
            (11, b"\x00"),
        ):
            with self.assertRaises(DiagnosticError):
                decode_oxygen_test(tid, payload)
        calls = []

        def exchange(ecu, request):
            calls.append(request)
            return (
                b"\x45"
                + request[1:]
                + (
                    self.bitmap(0, [1, 5])
                    if request[1] == 0
                    else b"\xc8"
                    if request[1] == 1
                    else b"\x01\x00\x02"
                )
            )

        session = Session(exchange)
        with self.assertRaises(DiagnosticError):
            session.oxygen_tests("engine")
        self.assertEqual(calls, [])
        report = session.oxygen_tests("engine", protocol="iso9141")
        self.assertEqual(len(report["results"]), 2)
        self.assertEqual(report["results"][1]["status"], "pass")
        for request in (
            bytes.fromhex("050000"),
            bytes.fromhex("050003"),
            bytes.fromhex("050b01"),
            b"\x08",
            b"\x04",
        ):
            with self.assertRaises(DiagnosticError):
                validate_request(request)

    def test_information_counter_layout_and_ecu_field_padding(self):
        import struct

        from scripts.diagnostics import decode_ecu_names, decode_information

        names = b"\x01" + b"ECM\x00-" + b"EngineControl".ljust(15, b"\x00")
        self.assertEqual(decode_ecu_names(names), ["ECM-EngineControl"])
        for bad in (
            names.replace(b"-", b":"),
            b"\x01" + b"E\x00CM-" + b"EngineControl".ljust(15, b"\x00"),
        ):
            with self.assertRaises(DiagnosticError):
                decode_ecu_names(bad)
        for pid, count in ((8, 16), (8, 20), (11, 16), (11, 18)):
            values = bytes([count]) + struct.pack(">" + "H" * count, *range(count))
            report = decode_information(pid, values)
            self.assertEqual(report["counters"]["ignition_cycles"], 1)
            self.assertEqual(len(report["counters"]), count)
        for count in (0, 15, 17, 19):
            with self.assertRaises(DiagnosticError):
                decode_information(8, bytes([count]) + bytes(count * 2))
        serial = b"\x01" + b"12345".rjust(17, b"\x00")
        self.assertEqual(decode_information(13, serial), "12345")
        self.assertEqual(decode_information(15, serial), "12345")
        with self.assertRaises(DiagnosticError):
            decode_information(13, b"\x01" + b"0" * 16 + b"I")


class ScalingContextTests(unittest.TestCase):
    def test_sae_configuration_examples_and_zero_default(self):
        from scripts.diagnostics import decode_parameter

        configured = decode_parameter(
            0x24, bytes.fromhex("7d009c40"), bytes([4, 16, 0, 0])
        )
        self.assertAlmostEqual(configured["equivalence_ratio"], 1.953154802777142)
        self.assertAlmostEqual(configured["voltage"], 9.76577401388571)
        self.assertEqual(
            decode_parameter(0x34, bytes.fromhex("00009c40"), bytes([0, 0, 64, 0]))[
                "current"
            ],
            14.125,
        )
        self.assertEqual(
            decode_parameter(0x34, bytes.fromhex("00005c40"), bytes([0, 0, 64, 0]))[
                "current"
            ],
            -17.875,
        )
        self.assertEqual(
            decode_parameter(0x24, bytes.fromhex("80002000"), bytes(4)),
            decode_parameter(0x24, bytes.fromhex("80002000")),
        )
        self.assertEqual(
            decode_parameter(0x10, b"\xff\xff", configuration_50=bytes([100, 0, 0, 0]))[
                "value"
            ],
            1000,
        )
        self.assertEqual(
            decode_parameter(0x0B, b"\xff", bytes([0, 0, 0, 77]))["value"], 770
        )
        self.assertEqual(decode_parameter(0xA6, b"\xff" * 4)["value"], 429496729.5)
        for bad in (b"", b"\x01" * 3, b"\x01" * 5):
            with self.assertRaises(DiagnosticError):
                decode_parameter(0x24, bytes(4), bad)

    def test_parameters_reads_advertised_configuration_before_dependent_signal(self):
        from scripts.diagnostics import decode_parameter

        calls = []

        def exchange(ecu, request):
            calls.append(request)
            pid = request[1]
            if pid in (0, 32, 64):
                pids = {0: [32], 32: [0x24, 64], 64: [0x4F]}[pid]
                return b"\x41" + bytes([pid]) + ExtendedOBDTests.bitmap(pid, pids)
            return (
                b"\x41"
                + bytes([pid])
                + (bytes([4, 16, 0, 0]) if pid == 0x4F else bytes.fromhex("7d009c40"))
            )

        result = Session(exchange).parameters("engine", [0x24])
        self.assertEqual(calls, [bytes([1, pid]) for pid in (0, 32, 64, 0x4F, 0x24)])
        self.assertEqual(
            result["values"][0],
            decode_parameter(0x24, bytes.fromhex("7d009c40"), bytes([4, 16, 0, 0])),
        )

    def test_optional_second_trim_byte_is_not_zero_filled(self):
        from scripts.diagnostics import decode_parameter

        row = decode_parameter(6, b"\x80\x40")
        self.assertEqual([r["bank"] for r in row["fuel_trims"]], [1, 3])
        self.assertEqual([r["value"] for r in row["fuel_trims"]], [0, -50])
        for pid in range(0x55, 0x59):
            self.assertEqual(
                len(decode_parameter(pid, b"\x80")["secondary_oxygen_trims"]), 1
            )
            self.assertEqual(
                len(decode_parameter(pid, b"\x80\x40")["secondary_oxygen_trims"]), 2
            )
            with self.assertRaises(DiagnosticError):
                correlate(bytes([1, pid]), bytes([0x41, pid]) + b"\x80" * 3)


class SensorSupportTests(unittest.TestCase):
    def test_compound_support_is_not_invented_measurement(self):
        from scripts.diagnostics import decode_parameter

        maf = decode_parameter(0x66, bytes.fromhex("010020ffff"))
        self.assertEqual(maf["sensors"][0]["value"], 1)
        self.assertIsNone(maf["sensors"][1]["value"])
        iat = decode_parameter(0x68, bytes([0x21, 40, 255, 255, 255, 255, 41]))
        self.assertEqual(len(iat["sensors"]), 6)
        self.assertEqual(iat["sensors"][0]["value"], 0)
        self.assertEqual(iat["sensors"][5]["value"], 1)
        self.assertIsNone(iat["sensors"][1]["value"])
        with self.assertRaises(DiagnosticError):
            decode_parameter(0x68, bytes(3))
        self.assertEqual(decode_parameter(0x51, b"\x04")["fuel_type"], "diesel")
        self.assertEqual(
            decode_parameter(0x5F, b"\x0e")["emission_requirement"], "EURO_IV_B1"
        )
        aux = decode_parameter(0x65, b"\x01\x01")["auxiliary_status"]
        self.assertTrue(aux[0]["active"])
        self.assertIsNone(aux[1]["active"])


class LateStandardPIDTests(unittest.TestCase):
    def test_every_standard_pid_through_87_has_semantic_decoder(self):
        from scripts.diagnostics import PID_SIZES, decode_parameter

        self.assertTrue(all(pid in PID_SIZES for pid in range(0x88)))
        for pid in range(0x69, 0x88):
            size = PID_SIZES[pid]
            with self.subTest(pid=f"{pid:02X}"):
                row = decode_parameter(pid, bytes(size))
                self.assertGreater(len(row), 2)
                for length in (size - 1, size + 1):
                    with self.assertRaises(DiagnosticError):
                        correlate(bytes([1, pid]), bytes([0x41, pid]) + bytes(length))

    def test_egr_wide_temperature_and_compressor_wide_pressure(self):
        from scripts.diagnostics import decode_parameter

        egr = decode_parameter(0x69, bytes.fromhex("3fff8080ff0080"))["fields"]
        self.assertEqual(egr[0]["value"], 100)
        self.assertEqual(egr[2]["value"], 0)
        self.assertEqual(egr[4]["value"], 0)
        temp = decode_parameter(0x6B, bytes([0x10, 255, 0, 0, 0]))["fields"]
        self.assertEqual(temp[0]["value"], 980)
        self.assertTrue(temp[0]["wide_range"])
        self.assertIsNone(temp[1]["value"])
        pressure = decode_parameter(0x6F, bytes([0x08, 0, 255]))["fields"]
        self.assertEqual(pressure[1]["value"], 2040)
        self.assertIsNone(pressure[0]["value"])

    def test_pressure_temperature_offsets_and_control_status(self):
        from scripts.diagnostics import decode_parameter

        fuel = decode_parameter(0x6D, bytes.fromhex("3f00010002280003000429"))["fields"]
        self.assertEqual([field["value"] for field in fuel], [10, 20, 0, 30, 40, 1])
        boost = decode_parameter(0x70, bytes.fromhex("3f00200040006000800e"))["fields"]
        self.assertEqual(
            [field["value"] for field in boost], [1, 2, 3, 4, "closed_loop", "fault"]
        )
        vgt = decode_parameter(0x71, bytes.fromhex("3fff00ff0009"))["fields"]
        self.assertEqual(
            [field["value"] for field in vgt],
            [100, 0, 100, 0, "open_loop", "closed_loop"],
        )
        dpf = decode_parameter(0x7A, bytes.fromhex("07ff9c006400c8"))["fields"]
        self.assertEqual([field["value"] for field in dpf], [-1, 1, 2])
        turbine = decode_parameter(0x75, bytes.fromhex("0f28290190019a"))["fields"]
        self.assertEqual([field["value"] for field in turbine], [0, 1, 0, 1])
        reagent = decode_parameter(0x85, bytes.fromhex("0f00c80190ff0000003c"))[
            "fields"
        ]
        self.assertEqual([field["value"] for field in reagent], [1, 2, 100, 60])
        pm = decode_parameter(0x86, bytes.fromhex("03005000a0"))["fields"]
        self.assertEqual([field["value"] for field in pm], [1, 2])

    def test_runtime_optional_aecd_timer_preserves_unavailable(self):
        import struct

        from scripts.diagnostics import decode_parameter

        payload = b"\x01" + struct.pack(">II", 123, 0xFFFFFFFF) + bytes(32)
        for pid, first in ((0x81, 1), (0x82, 6)):
            fields = decode_parameter(pid, payload)["fields"]
            self.assertEqual(fields[0]["name"], f"aecd_{first}_timer_1")
            self.assertEqual(fields[0]["value"], 123)
            self.assertIsNone(fields[1]["value"])
            self.assertTrue(fields[1]["supported"])
            self.assertFalse(fields[1]["available"])
            self.assertFalse(fields[2]["supported"])
        runtime = decode_parameter(
            0x7F, b"\x07" + struct.pack(">III", 1, 2, 0xFFFFFFFF)
        )["fields"]
        self.assertEqual([field["value"] for field in runtime], [1, 2, 0xFFFFFFFF])

    def test_all_late_compound_unadvertised_fields_null_and_record_bounds(self):
        from scripts.diagnostics import LATE_COMPOUNDS, PID_SIZES, decode_parameter

        for pid in LATE_COMPOUNDS:
            with self.subTest(pid=pid):
                size = PID_SIZES[pid]
                row = decode_parameter(pid, b"\x00" + b"\xff" * (size - 1))
                self.assertTrue(all(field["value"] is None for field in row["fields"]))
                decoded = decode_parameter(pid, b"\xff" * size)
                self.assertTrue(all(field["supported"] for field in decoded["fields"]))

    def test_legacy_manufacturer_test_scaling_ranges(self):
        from scripts.diagnostics import decode_oxygen_test

        for tid, expected, unit in (
            (0x21, 0.4, "s"),
            (0x30, 4, "s"),
            (0x41, 0.5, "V"),
            (0x50, 5, "V"),
            (0x61, 10, "Hz"),
            (0x70, 100, "count"),
        ):
            row = decode_oxygen_test(tid, bytes([100, 0, 200]))
            self.assertEqual((row["value"], row["unit"]), (expected, unit))
            self.assertEqual(row["name"], "manufacturer_defined")
            validate_request(bytes([5, tid, 1]))
        with self.assertRaises(DiagnosticError):
            validate_request(bytes([5, 0x81, 1]))


class MonitorMetadataTests(unittest.TestCase):
    def test_manufacturer_description_unknown_makes_report_partial(self):
        for response, expected in (
            ("46018001000a00000014", "partial"),
            ("4601010a03e8000007d0", "ok"),
        ):
            replies = iter((bytes.fromhex("460080000000"), bytes.fromhex(response)))
            result = Session(lambda e, r, replies=replies: next(replies)).monitors(
                "engine"
            )
            self.assertEqual(result["status"], expected)
            self.assertEqual(result["results"][0]["status"], "pass")
            if expected == "partial":
                self.assertEqual(
                    result["errors"][0]["type"], "UnresolvedTestDefinition"
                )


class SemanticDefinitionTests(unittest.TestCase):
    def test_known_monitor_tid_scale_and_mid_contradictions(self):
        from scripts.diagnostics import decode_monitor_records

        for mid, data in (
            (1, "010b24000100000002"),
            (1, "010101000100000002"),
            (0xA2, "a20b01000100000002"),
        ):
            with self.assertRaises(DiagnosticError):
                decode_monitor_records(mid, bytes.fromhex(data))
        self.assertEqual(
            decode_monitor_records(0xA2, bytes.fromhex("a20b24000100000002"))[0][
                "test_name"
            ],
            "EWMA_misfire_count",
        )

    def test_unknown_enum_definition_makes_parameter_report_partial(self):
        responses = iter(
            bytes.fromhex(x)
            for x in ("410000000001", "412000000001", "414000008000", "4151ff")
        )
        report = Session(lambda e, r: next(responses)).parameters("engine", [0x51])
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["values"][0]["fuel_type"], "reserved")
        self.assertEqual(report["errors"][0]["type"], "UnresolvedDefinition")

    def test_known_scale_unknown_legacy_test_name_is_partial(self):
        replies = iter(
            bytes.fromhex(x)
            for x in ("45000100000001", "45200180000000", "452101010002")
        )
        report = Session(lambda e, r: next(replies)).oxygen_tests(
            "engine", protocol="iso9141"
        )
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["unresolved_tids"], ["21"])
        self.assertEqual(report["results"][0]["value"], 0.004)


if __name__ == "__main__":
    unittest.main()
