import struct
import tempfile
import unittest
from pathlib import Path

from scripts.profiles import VehicleCatalog
from scripts.readiness import NO_SUPPORT_SIGNAL, ReadinessSession
from scripts.toyota import MISSING_RECORD, SHORT_REPLY, ToyotaCodecError
from scripts.toyota_session import Cancelled, Limits, NativeStatus, SessionError


def database(kind, sections):
    header = bytearray(36 + 4 * (max(sections) + 1))
    header[8:10] = bytes([kind, max(sections) + 1])
    header[10:28] = b"DiagTool DataCtrl\0"
    struct.pack_into("<I", header, 28, 0x0100032F)
    body = bytearray()
    for slot, (count, payload) in sorted(sections.items()):
        struct.pack_into("<I", header, 36 + slot * 4, len(header) + len(body))
        body += struct.pack("<BBII", slot, 0, count, len(payload)) + payload
    return bytes(header + body)


def freeze(key, pid, first, last, *, ready=True, support=1):
    row = bytearray(84)
    struct.pack_into("<I", row, 52, 0x12345678)
    struct.pack_into("<H", row, 56, key)
    struct.pack_into("<HHH", row, 60, 1, first, last)
    row[76] = 2
    row[77] = support
    row[78] = 32 if ready else 0
    row[79] = pid
    return bytes(row)


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        category = bytearray(76)
        category[:20] = "demo.ddb\0".encode("utf-16le").ljust(20, b"\0")
        struct.pack_into("<H", category, 68, 42)
        variables = struct.pack("<IH", 0, 2) + b"\x01\x00"
        settings = bytearray(16)
        struct.pack_into("<H", settings, 10, 1)
        functions = b"".join(
            struct.pack("<8H", 42, fn, 1, 1, 0, 1, 0, 0) for fn in (0x10, 0x6B)
        )
        management = {
            0: (1, variables),
            16: (1, bytes(category)),
            17: (1, struct.pack("<4H", 1, 1, 0, 0)),
            18: (2, functions),
            29: (1, bytes(settings)),
        }
        (self.root / "Toyota.ddb").write_bytes(database(1, management))
        (self.root / "M_English.ddb").write_bytes(database(4, {0: (0, b"")}))
        physical = bytearray(24)
        struct.pack_into("<iiiHH", physical, 0, 2, 1, -4, 1, 0)
        self.physical = bytes(physical)
        self.rows = (
            freeze(10, 1, 0, 3),
            freeze(11, 1, 4, 7, support=2),
            freeze(12, 0x88, 8, 15, ready=False),
        )
        self.write_ecu(self.rows)

    def write_ecu(self, rows, physical=None):
        if physical is None:
            physical = self.physical
        (self.root / "demo.ddb").write_bytes(
            database(2, {10: (len(rows), b"".join(rows)), 13: (1, physical)})
        )
        self.profile = VehicleCatalog(self.root).build_profile(42)

    def test_selected_native_flags_cache_and_independent_support(self):
        calls = []
        engine = ReadinessSession(
            self.profile,
            lambda e, r: calls.append(r) or bytes.fromhex("4101a507"),
            "engine",
            {},
        )
        report = engine.readiness()
        self.assertEqual(calls, [b"\x01\x01"])
        self.assertEqual([row["signal_key"] for row in report["signals"]], [10, 11])
        self.assertEqual([row["value"]["value"] for row in report["signals"]], [16, 6])
        self.assertEqual(
            [row["native_support"] for row in report["signals"]], [True, False]
        )
        self.assertEqual(report["signals"][0]["native_34"], 0x12345678)
        self.assertNotIn("complete", report["signals"][0])
        self.assertEqual(report["native_status"], 0)
        engine.readiness()
        self.assertEqual(len(calls), 2)

    def test_selected_original_pattern_and_unit_render_without_enum_number(self):
        encoded = "Ready\0".encode("utf-16le")
        language = struct.pack("<IH", 0, len(encoded)) + encoded
        (self.root / "M_English.ddb").write_bytes(database(4, {0: (1, language)}))
        row = bytearray(self.rows[0])
        row[76] = 1
        struct.pack_into("<H", row, 70, 3)
        pattern = bytearray(24)
        struct.pack_into("<II", pattern, 0, 1, 16)
        struct.pack_into("<H", pattern, 12, 3)
        unit = struct.pack("<IHHHBB", 0, 0, 0, 0, 0, 0)
        (self.root / "demo.ddb").write_bytes(
            database(
                2,
                {
                    10: (1, bytes(row)),
                    13: (1, self.physical),
                    14: (1, bytes(pattern)),
                    15: (1, unit),
                },
            )
        )
        profile = VehicleCatalog(self.root).build_profile(42)
        report = ReadinessSession(
            profile, lambda e, r: bytes.fromhex("4101a5"), "engine", {}
        ).readiness()
        value = report["signals"][0]["value"]
        self.assertEqual(value["display"], "Ready")
        self.assertIsNone(value["value"])
        self.assertEqual(value["unit"], "")
        self.assertEqual(report["status"], "ok")
        report = ReadinessSession(
            profile, lambda e, r: bytes.fromhex("4101b5"), "engine", {}
        ).readiness()
        self.assertEqual(report["status"], "partial")
        self.assertIsNone(report["signals"][0]["value"]["value"])

    def test_original_definition_drives_pid_above_87_without_raw_only_success(self):
        calls = []
        engine = ReadinessSession(
            self.profile,
            lambda e, r: calls.append(r) or bytes.fromhex("4188a507"),
            "engine",
            {},
        )
        result = engine.data_list([12])
        self.assertEqual(calls, [b"\x01\x88"])
        self.assertEqual(result["signals"][0]["value"]["value"], 10)
        self.assertEqual(result["signals"][0]["value"]["display"], "10")
        self.assertEqual(result["signals"][0]["pid"], 0x88)

    def test_native_wrong_length_omission_and_all_missing_status(self):
        self.write_ecu((self.rows[0], freeze(11, 2, 0, 3)))

        def exchange(ecu, request):
            return b"\x41\x01" if request[1] == 1 else bytes.fromhex("4102a5")

        result = ReadinessSession(self.profile, exchange, "engine", {}).readiness()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["omitted"][0]["native_status"], SHORT_REPLY)
        self.assertEqual(len(result["signals"]), 1)
        with self.assertRaises(ToyotaCodecError) as error:
            ReadinessSession(
                self.profile, lambda e, r: b"\x41\x01", "engine", {}
            ).readiness()
        self.assertEqual(error.exception.code, NO_SUPPORT_SIGNAL)

    def test_missing_join_and_missing_signal_fail_before_exchange(self):
        calls = []
        physical = bytearray(self.physical)
        struct.pack_into("<H", physical, 12, 2)
        self.write_ecu(self.rows, bytes(physical))
        engine = ReadinessSession(
            self.profile, lambda e, r: calls.append(r) or b"", "engine", {}
        )
        with self.assertRaises(ToyotaCodecError) as error:
            engine.readiness()
        self.assertEqual(error.exception.code, MISSING_RECORD)
        self.assertEqual(calls, [])
        with self.assertRaises(ToyotaCodecError):
            engine.data_list([999])
        with self.assertRaises(ValueError):
            engine.data_list([10, 10])

    def test_cancellation_deadline_and_total_exchange_budget(self):
        calls = []
        engine = ReadinessSession(
            self.profile,
            lambda e, r: calls.append(r) or b"",
            "engine",
            {},
            cancelled=lambda: True,
        )
        with self.assertRaises(Cancelled):
            engine.readiness()
        self.assertEqual(calls, [])
        self.write_ecu((self.rows[0], freeze(11, 2, 0, 3)))
        engine = ReadinessSession(
            self.profile,
            lambda e, r: bytes([0x41, r[1], 0xA5]),
            "engine",
            {},
            limits=Limits(exchanges=1),
        )
        with self.assertRaises(SessionError):
            engine.readiness()
        now = [0.0]

        def slow(ecu, request):
            now[0] = 2.0
            return bytes([0x41, request[1], 0xA5])

        with self.assertRaises(SessionError):
            ReadinessSession(
                self.profile,
                slow,
                "engine",
                {},
                clock=lambda: now[0],
                limits=Limits(seconds=1),
            ).readiness()

    def test_non_length_native_errors_propagate_without_zero_values(self):
        def broken(ecu, request):
            raise NativeStatus(0xC0040001)

        with self.assertRaises(NativeStatus):
            ReadinessSession(self.profile, broken, "engine", {}).readiness()
        with self.assertRaises(ToyotaCodecError):
            ReadinessSession(
                self.profile, lambda e, r: b"\x42\x01\x00", "engine", {}
            ).readiness()
        with self.assertRaises(TimeoutError):
            ReadinessSession(
                self.profile,
                lambda e, r: (_ for _ in ()).throw(TimeoutError()),
                "engine",
                {},
            ).readiness()

    def test_failed_exchange_still_checks_cancellation_and_deadline(self):
        for cancel in (False, True):
            now = [0.0]
            stopped = [False]

            def failing(ecu, request, now=now, stopped=stopped, cancel=cancel):
                now[0] = 2.0
                stopped[0] = cancel
                raise TimeoutError("backend failed after I/O")

            with self.assertRaises(Cancelled if cancel else SessionError):
                ReadinessSession(
                    self.profile,
                    failing,
                    "engine",
                    {},
                    clock=lambda now=now: now[0],
                    cancelled=lambda stopped=stopped: stopped[0],
                    limits=Limits(seconds=1),
                ).readiness()

    def test_no_readiness_rows_and_bad_observation_inputs(self):
        self.write_ecu((freeze(12, 0x88, 0, 7, ready=False),))
        with self.assertRaises(ToyotaCodecError) as error:
            ReadinessSession(self.profile, lambda e, r: b"", "engine", {}).readiness()
        self.assertEqual(error.exception.code, NO_SUPPORT_SIGNAL)
        invalid: list[dict[int, int]] = [
            {True: 1},
            {1: True},
            {256: 1},
            {1: 256},
            {1: -1},
        ]
        for observations in invalid:
            with self.assertRaises(ValueError):
                ReadinessSession(self.profile, lambda e, r: b"", "engine", observations)


if __name__ == "__main__":
    unittest.main()
