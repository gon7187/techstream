"""Literal authored native inputs; never execute the original binaries."""

import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import SHA_12_TY, SHA_18_TY, SHA_PLUS_TY, TYSourceError
from scripts.utility_ex_ty_retained_11 import (
    _ads,
    _aes_block,
    _asect,
    _put,
    _run,
    run_body,
    supported_exports,
)
from tests.test_utility_ex_fchv_actions import Context


class Retained11Tests(unittest.TestCase):
    def context(self, sha=SHA_18_TY):
        ctx: Any = Context(sha)
        ctx.queue = []
        ctx.on_request = None

        def exchange(request):
            ctx.events.append(("exchange", request))
            if ctx.fault:
                raise ctx.fault
            if ctx.on_request:
                ctx.on_request(request)
            return ctx.queue.pop(0)

        ctx.exchange = exchange
        return ctx

    def test_admission(self):
        self.assertEqual(len(supported_exports(SHA_12_TY)), 8)
        self.assertEqual(len(supported_exports(SHA_18_TY)), 21)
        self.assertEqual(supported_exports("unknown"), ())
        with self.assertRaises(TYSourceError):
            _run("Ex2ADS_03_SendMessage", (bytearray(20),), self.context())

    def test_identity(self):
        ctx = self.context()
        with self.assertRaises(TYSourceError):
            run_body("Ex2ITS_01_SendMessage", (), ctx)
        self.assertEqual(ctx.events, [])

    def test_its01_three_sources_and_malformed(self):
        for sha in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY):
            ctx = self.context(sha)
            ctx.queue = [(0, b"\x00\xf1")]
            self.assertEqual(_run("Ex2ITS_01_SendMessage", (), ctx), 0)
            self.assertIn(("exchange", b"\x3b\xf1\x01"), ctx.events)
            self.assertEqual(ctx.events[-1], ("finalize",))
            ctx.queue = [(0, b"\x7b\x00")]
            self.assertEqual(_run("Ex2ITS_01_SendMessage", (), ctx), 3)

    def test_dr_fields_and_short_second_preserve_first(self):
        ctx = self.context()
        ctx.queue = [
            (0, bytes.fromhex("6101aa1122")),
            (0, bytes.fromhex("61030102030405aabbccdd")),
        ]
        data = bytearray(10)
        self.assertEqual(_run("Ex2DR_01_GetDataList", (data,), ctx), 0)
        self.assertEqual(data.hex(), "aabbccdd0102030405aa")
        ctx.queue = [(0, bytes.fromhex("6101ee1122")), (0, b"short")]
        self.assertEqual(_run("Ex2DR_01_GetDataList", (data,), ctx), 3)
        self.assertEqual(data[9], 0xEE)
        self.assertEqual(data[:9].hex(), "aabbccdd0102030405")

    def test_its02_exact_wire_and_mapping(self):
        ctx = self.context()
        ctx.queue = [(0, bytes.fromhex("71011007"))]
        self.assertEqual(_run("Ex2ITS_02_SendMessage", (), ctx), 0)
        self.assertIn(("exchange", bytes.fromhex("31011007")), ctx.events)
        ctx.queue = [(47, b"")]
        self.assertEqual(_run("Ex2ITS_02_SendMessage", (), ctx), 1000)
        self.assertEqual(ctx.events[-1], ("finalize",))

    def test_dseat_every_native_start_and_retention(self):
        for sha in (SHA_18_TY, SHA_PLUS_TY):
            for n, identifier in enumerate((1, 3, 5, 6), 1):
                ctx = self.context(sha)
                request = bytes((0x31, 1, 0x11, identifier))
                ctx.queue = [(0, b"\x71" + request[1:])]
                self.assertEqual(
                    _run(f"Ex2DSEAT_{n:02}_SendMessage", (bytearray(5),), ctx), 0
                )
                self.assertIn(("exchange", request), ctx.events)
                self.assertNotIn(("finalize",), ctx.events)

    def test_dseat_poll_version_difference_and_terminal_codes(self):
        for sha, identifier in ((SHA_18_TY, 1), (SHA_PLUS_TY, 3)):
            for result, expected in ((2, 0), (4, 1000)):
                ctx = self.context(sha)
                data = bytearray(b"\x01\0\0\0\0")
                request = bytes((0x31, 3, 0x11, identifier))
                ctx.queue = [(0, b"\x71" + request[1:] + bytes((result,)))]
                self.assertEqual(
                    _run("Ex2DSEAT_01_SendMessage", (data,), ctx), expected
                )
                self.assertEqual(ctx.events[-2:], [("session", 1), ("finalize",)])

    def test_mutable_poll_stop_and_fault_cleanup(self):
        ctx = self.context()
        data = bytearray(b"\x01\0\0\0\0")
        ctx.queue = [(0, bytes.fromhex("7103110101"))]
        ctx.on_request = lambda _: data.__setitem__(4, 1)
        self.assertEqual(_run("Ex2DSEAT_01_SendMessage", (data,), ctx), 0)
        ctx.fault = RuntimeError("authored native fault")
        data[4] = 0
        with self.assertRaisesRegex(RuntimeError, "native fault"):
            _run("Ex2DSEAT_01_SendMessage", (data,), ctx)
        self.assertEqual(ctx.events[-2:], [("session", 1), ("finalize",)])

    def hn_data(self):
        data = bytearray(900)
        for at, did, position, length in (
            (0, 1, 2, 2),
            (24, 2, 2, 2),
            (48, 3, 2, 2),
            (96, 4, 2, 1),
            (120, 5, 2, 1),
            (144, 6, 2, 25),
        ):
            data[at] = did
            _put(data, at + 16, position)
            _put(data, at + 20, length)
        _put(data, 88, 3)
        return data

    def test_hnfcm_each_target_wire_and_sleep(self):
        for sha in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY):
            for n, mask in ((1, 32), (2, 64), (3, 128)):
                ctx = self.context(sha)
                data = self.hn_data()
                ctx.queue = [(0, b"\x70\x05"), (0, bytes((0x61, 2, mask, 0)))]
                if n == 3:
                    ctx.queue.append((0, bytes.fromhex("610300a7")))
                self.assertEqual(_run(f"Ex2HNFCM_02_LearnTarget{n}", (data,), ctx), 0)
                self.assertIn(("exchange", bytes((0x30, 5, 0, mask))), ctx.events)
                self.assertIn(("sleep", 10000), ctx.events)
                self.assertEqual(data[899], 0xA7 if n == 3 else 0)
                self.assertEqual(ctx.events[-1], ("finalize",))

    def test_hnfcm_all_and_incomplete_result_cleanup(self):
        ctx = self.context()
        data = self.hn_data()
        ctx.queue = [
            (0, b"\x70\x04"),
            (0, bytes.fromhex("61010800")),
            (0, bytes.fromhex("610300a8")),
        ]
        self.assertEqual(_run("Ex2HNFCM_02_LearnTargetAll", (data,), ctx), 0)
        self.assertEqual(data[899], 0xA8)
        ctx.queue = [
            (0, b"\x70\x05"),
            (0, bytes.fromhex("61020000")),
            (19, b""),
            (0, bytes.fromhex("610300aa")),
        ]
        self.assertEqual(_run("Ex2HNFCM_02_LearnTarget1", (data,), ctx), 9999)
        self.assertEqual(data[899], 0xAA)
        self.assertIn(("exchange", b"\x30"), ctx.events)

    def test_hnfcm_camera_inline_and_malformed(self):
        ctx = self.context()
        data = self.hn_data()
        reply = b"\xe9\x06" + bytes(range(25))
        ctx.queue = [(0, reply)]
        self.assertEqual(_run("Ex2HNFCM_02_ReadCameraData", (data,), ctx), 0)
        self.assertEqual(bytes(data[0x368:0x383]), reply)
        ctx.queue = [(0, b"short")]
        self.assertEqual(_run("Ex2HNFCM_02_ReadCameraData", (data,), ctx), 3)
        self.assertEqual(bytes(data[0x368:0x383]), reply)
        with self.assertRaises(ValueError):
            _run("Ex2HNFCM_02_ReadCameraData", (bytearray(898),), ctx)

    def test_hnfcm_support_snapshots_and_descriptor_fields(self):
        ctx = self.context()
        data = bytearray(872)
        for base, count, stride in ((0, 4, 24), (96, 2, 24), (144, 13, 56)):
            for index in range(count):
                at = base + index * stride
                data[at] = 7
                data[at + 2] = 4
                _put(data, at + 12, 1)
        raw = bytes((7, 3, 4, 0, 8)).ljust(0x1020, b"\0")
        offsets = tuple(0 if n == 7 else 0x1020 for n in range(256))
        ctx.support_snapshot = lambda kind: (0, raw, offsets)
        self.assertEqual(_run("Ex2HNFCM_02_SupportCheck", (data,), ctx), 0)
        self.assertEqual(data[16:24], bytes.fromhex("0200000002000000"))
        data[2] = 8
        self.assertEqual(_run("Ex2HNFCM_02_SupportCheck", (data,), ctx), 22)
        self.assertEqual(data[16:20], b"\xff" * 4)

    def test_asect_terminal_retention_all_phases(self):
        for sha in (SHA_18_TY, SHA_PLUS_TY):
            for action, phase, expected in (
                (0, 1, 1009),
                (1, 3, 1010),
                (2, 5, 1003),
                (3, 6, 1011),
                (4, 8, 1012),
                (8, 1, 1009),
                (9, 6, 1011),
            ):
                ctx = self.context(sha)
                data = bytearray(7)
                _put(data, 0, action)
                if action == 0:
                    ctx.queue.append((0, b"\x54"))
                if action != 9:
                    ctx.queue.append((0, bytes.fromhex("7101119a")))
                ctx.queue.append((0, bytes.fromhex("7103119a") + bytes((1, phase, 0))))
                self.assertEqual(_asect((data,), ctx), expected)
                self.assertNotIn(("finalize",), ctx.events)

    def test_asect_recoverable_retry_fatal_and_complete_cleanup(self):
        for action, payload, expected, retained in (
            (1, (1, 2, 7), 1013, True),
            (5, (2, 16, 0), 1015, False),
            (3, (1, 5, 4), 1006, False),
        ):
            ctx = self.context()
            data = bytearray(7)
            _put(data, 0, action)
            ctx.queue = [
                (0, bytes.fromhex("7101119a")),
                (0, bytes.fromhex("7103119a") + bytes(payload)),
            ]
            if expected == 1006:
                ctx.queue.append((77, b""))
            self.assertEqual(_asect((data,), ctx), expected)
            self.assertEqual(("finalize",) in ctx.events, not retained)
            self.assertEqual(data[6], payload[2])
        ctx = self.context()
        data = bytearray(7)
        _put(data, 0, 2)
        ctx.queue = [
            (0, bytes.fromhex("7101119a")),
            (0, bytes.fromhex("7103119a010402")),
            (0, bytes.fromhex("7101119a")),
            (0, bytes.fromhex("7103119a010500")),
        ]
        self.assertEqual(_asect((data,), ctx), 1003)
        self.assertNotIn(("finalize",), ctx.events)

    def test_asect_exit_noop_cancel_fault_and_nrc(self):
        ctx = self.context()
        data = bytearray(7)
        _put(data, 0, 10)
        self.assertEqual(_asect((data,), ctx), 1016)
        self.assertEqual(ctx.events[-2:], [("session", 1), ("finalize",)])
        ctx = self.context()
        _put(data, 0, 6)
        ctx.queue = [(0, bytes.fromhex("7101119a"))]
        self.assertEqual(_asect((data,), ctx), 1009)
        self.assertNotIn(("finalize",), ctx.events)
        ctx = self.context()
        _put(data, 0, 0)
        ctx.queue = [(0, b"\x54"), (7, b"")]
        self.assertEqual(_asect((data,), ctx), 1005)
        ctx = self.context()
        _put(data, 0, 11)
        ctx.on_sleep = lambda: _put(data, 0, 9)
        ctx.queue = [(0, bytes.fromhex("7103119a010500"))]
        self.assertEqual(_asect((data,), ctx), 0)
        self.assertNotIn(("finalize",), ctx.events)
        ctx.cancelled = True
        _put(data, 0, 11)
        with self.assertRaises(Cancelled):
            _asect((data,), ctx)
        self.assertEqual(ctx.events[-1], ("finalize",))

    def test_native_aes_ecb_nist_block(self):
        self.assertEqual(
            _aes_block(
                bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
                bytes.fromhex("00112233445566778899aabbccddeeff"),
            ).hex(),
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        )

    def ads_data(self, number, action):
        data = bytearray(0x103C)
        _put(data, 8 if number == 4 else 0x1038 if number == 8 else 0, action)
        return data

    def test_ads04_retained_setup_wire_and_poll(self):
        for sha in (SHA_18_TY, SHA_PLUS_TY):
            ctx = self.context(sha)
            data = self.ads_data(4, 0)
            data[4:6] = b"\xaa\xbb"
            ctx.queue = [
                (0, bytes.fromhex("6220030102")),
                (0, bytes.fromhex("6220040304")),
                (0, bytes.fromhex("6e2003")),
                (0, bytes.fromhex("6e2004")),
                (0, bytes.fromhex("71011007")),
            ]
            self.assertEqual(_ads("Ex2ADS_04_SendMessage", (data,), ctx), 0)
            self.assertIn(("exchange", bytes.fromhex("2e2003aa02")), ctx.events)
            self.assertNotIn(("finalize",), ctx.events)
            _put(data, 8, 1)
            ctx.queue = [(0, bytes.fromhex("7103100702"))]
            self.assertEqual(_ads("Ex2ADS_04_SendMessage", (data,), ctx), 0)
            self.assertEqual(ctx.events[-2:], [("session", 1), ("finalize",)])

    def test_ads05_and07_start_poll_stop(self):
        for number, routine, expected in (
            (5, bytes.fromhex("011014"), 0),
            (7, bytes.fromhex("01110f"), 1004),
        ):
            ctx = self.context()
            data = self.ads_data(number, 0)
            ctx.queue = [(0, b"\x71" + routine)]
            self.assertEqual(
                _ads(f"Ex2ADS_{number:02}_SendMessage", (data,), ctx), expected
            )
            self.assertNotIn(("finalize",), ctx.events)
            _put(data, 0, 1)
            poll = b"\x71\x03" + routine[1:] + b"\x02"
            ctx.queue = [(0, poll)]
            self.assertEqual(
                _ads(f"Ex2ADS_{number:02}_SendMessage", (data,), ctx),
                0 if number == 5 else 1006,
            )
            self.assertEqual(ctx.events[-1], ("finalize",))
            if number == 5:
                self.assertIn(("exchange", bytes.fromhex("31011014ffff")), ctx.events)

    def test_ads06_read_write_malformed_and_status(self):
        ctx = self.context()
        data = self.ads_data(6, 0)
        ctx.queue = [(0, bytes.fromhex("62230c01ab"))]
        self.assertEqual(_ads("Ex2ADS_06_SendMessage", (data,), ctx), 0)
        self.assertEqual(data[4:6], bytes.fromhex("01ab"))
        self.assertEqual(data[0x1024:0x1028], bytes.fromhex("02000000"))
        _put(data, 0, 1)
        ctx.queue = [(0, bytes.fromhex("6e230c"))]
        self.assertEqual(_ads("Ex2ADS_06_SendMessage", (data,), ctx), 0)
        self.assertIn(("exchange", bytes.fromhex("2e230c01ab")), ctx.events)
        ctx.queue = [(0, bytes.fromhex("6e230d"))]
        self.assertEqual(_ads("Ex2ADS_06_SendMessage", (data,), ctx), 3)
        ctx.queue = [(77, b"")]
        self.assertEqual(_ads("Ex2ADS_06_SendMessage", (data,), ctx), 77)

    def test_ads08_gate_bits_and_secure_readback(self):
        ctx = self.context()
        data = self.ads_data(8, 0)
        ctx.queue = [
            (0, bytes.fromhex("6201010000000080") + bytes(27)),
            (0, bytes.fromhex("62200004") + bytes(31)),
            (0, bytes.fromhex("6220060180")),
        ]
        self.assertEqual(_ads("Ex2ADS_08_SendMessage", (data,), ctx), 0)
        self.assertEqual(data[:16], bytes((1,)) + bytes(14) + bytes((1,)))
        self.assertEqual(data[16:18], bytes.fromhex("0180"))
        _put(data, 0x1038, 1)
        data[0x1030:0x1032] = bytes((0, 1))
        ctx.queue = [
            (0, b"\x67\x03" + bytes(16)),
            (0, bytes.fromhex("6e2006")),
            (0, bytes.fromhex("6220060181")),
        ]
        self.assertEqual(_ads("Ex2ADS_08_SendMessage", (data,), ctx), 0)
        self.assertIn(("exchange", bytes.fromhex("2e20060181")), ctx.events)

    def test_ads09_output_and_10_big_endian_write(self):
        ctx = self.context()
        data = self.ads_data(9, 1)
        ctx.queue = [(0, bytes.fromhex("62200601aabb"))]
        self.assertEqual(_ads("Ex2ADS_09_SendMessage", (data,), ctx), 0)
        self.assertEqual(data[4:9], bytes.fromhex("030001aabb"))
        data = self.ads_data(10, 1)
        data[4:10] = bytes.fromhex("20300002aabb")
        ctx.queue = [
            (0, b"\x67\x03" + bytes(16)),
            (0, bytes.fromhex("6e2030")),
            (0, bytes.fromhex("622030aabb")),
        ]
        self.assertEqual(_ads("Ex2ADS_10_SendMessage", (data,), ctx), 0)
        self.assertIn(("exchange", bytes.fromhex("2e2030aabb")), ctx.events)
        ctx.queue = [
            (0, b"\x67\x03" + bytes(16)),
            (0, bytes.fromhex("6e2030")),
            (0, bytes.fromhex("622030aabc")),
        ]
        self.assertEqual(_ads("Ex2ADS_10_SendMessage", (data,), ctx), 99)

    def test_ads_fault_cancel_security_malformed_cleanup(self):
        ctx = self.context()
        data = self.ads_data(8, 1)
        ctx.queue = [(0, b"\x67\x02" + bytes(16))]
        self.assertEqual(_ads("Ex2ADS_08_SendMessage", (data,), ctx), 3)
        ctx.fault = RuntimeError("authored native failure")
        with self.assertRaises(RuntimeError):
            _ads("Ex2ADS_08_SendMessage", (data,), ctx)
        self.assertEqual(ctx.events[-1], ("finalize",))
        ctx = self.context()
        data = self.ads_data(5, 1)
        ctx.on_sleep = lambda: setattr(ctx, "cancelled", True)
        with self.assertRaises(Cancelled):
            _ads("Ex2ADS_05_SendMessage", (data,), ctx)
        self.assertEqual(ctx.events[-1], ("finalize",))

    def test_security_nonzero_seed_uses_explicit_byod_constant(self):
        ctx = self.context()
        data = self.ads_data(10, 1)
        data[4:10] = bytes.fromhex("20300002aabb")
        seed = bytes.fromhex("00112233445566778899aabbccddeeff")
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        ctx.queue = [
            (0, b"\x67\x03" + seed),
            (0, bytes.fromhex("6704")),
            (0, bytes.fromhex("6e2030")),
            (0, bytes.fromhex("622030aabb")),
        ]
        with patch(
            "scripts.utility_ex_ty_retained_11._module_data", return_value=key
        ) as projection:
            self.assertEqual(_ads("Ex2ADS_10_SendMessage", (data,), ctx), 0)
        projection.assert_called_once_with(ctx.module_bytes, 0xF87D8, 16)
        self.assertIn(
            ("exchange", bytes.fromhex("270469c4e0d86a7b0430d8cdb78070b4c55a")),
            ctx.events,
        )

    def original_modules(self):
        root = Path(__file__).resolve().parents[1]
        modules = (
            "techstream-12-application/Techstream_Bin/UtilityEx2TY.dll",
            "techstream-18-application/Techstream_Bin/UtilityEx2TY.dll",
            "gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll",
        )
        paths = [root / "artifacts/extracted" / name for name in modules]
        if not all(path.is_file() for path in paths):
            self.skipTest("Private original source identity images unavailable")
        return [path.read_bytes() for path in paths]

    def test_actual97_aggregator_selected_same_buffer_and_context(self):
        from scripts import utility_ex_ty

        for source in self.original_modules():
            import hashlib

            ctx = self.context(hashlib.sha256(source).hexdigest())
            ctx.module_bytes = source
            ctx.queue = [
                (0, bytes.fromhex("6101a71122")),
                (0, bytes.fromhex("61030102030405aabbccdd")),
            ]
            data = bytearray(10)
            self.assertEqual(
                utility_ex_ty.run_body("Ex2DR_01_GetDataList", (data,), ctx), 0
            )
            self.assertEqual(data.hex(), "aabbccdd0102030405a7")
            self.assertEqual(ctx.events[0], ("comm", "selected"))

    def test_actual83_selected_wrapper_scheduler(self):
        from scripts.utility_ex import UtilityExContext, UtilityExEngine
        from tests.test_utility_ex import Host

        for source in self.original_modules():
            host = Host()
            host.values[0x6F] = 4
            ctx = UtilityExContext(source, host, None, None)
            wire = self.context(ctx.module_sha256)
            wire.queue = [(0, bytes.fromhex("7bf1"))]
            ctx._communication["selected"] = wire
            engine = UtilityExEngine(ctx)
            self.assertEqual(engine.invoke("Ex2ITS_01_SendMessage"), 15)
            self.assertEqual(engine.worker.timeout_ms, 10000)
            self.assertEqual(engine.worker.get_status(), 0)
            self.assertIn(("exchange", bytes.fromhex("3bf101")), wire.events)
            ctx._parameters[0x6F] = 0
            self.assertEqual(engine.invoke("Ex2ITS_01_SendMessage"), 99)

    def literal_vector(self, export, wire):
        if export == "Ex2ITS_01_SendMessage":
            wire.queue = [(0, bytes.fromhex("7bf1"))]
            return (), 0
        if export == "Ex2ITS_02_SendMessage":
            wire.queue = [(0, bytes.fromhex("71011007"))]
            return (), 0
        if export == "Ex2DR_01_GetDataList":
            wire.queue = [
                (0, bytes.fromhex("6101a71122")),
                (0, bytes.fromhex("61030102030405aabbccdd")),
            ]
            return (bytearray(10),), 0
        if export.startswith("Ex2DSEAT"):
            identifier = (1, 3, 5, 6)[int(export[9:11]) - 1]
            wire.queue = [(0, bytes((0x71, 1, 0x11, identifier)))]
            return (bytearray(5),), 0
        if export.startswith("Ex2HNFCM"):
            data = self.hn_data()
            if export.endswith("SupportCheck"):
                raw = bytes((0, 1, 1)).ljust(0x1020, b"\0")
                wire.support_snapshot = lambda _: (0, raw, (0,) * 256)
                return (bytearray(872),), 0
            if export.endswith("ReadCameraData"):
                wire.queue = [(0, b"\xe9\x06" + bytes(25))]
                return (data,), 0
            all_targets = export.endswith("All")
            mask = 8 if all_targets else {"1": 32, "2": 64, "3": 128}[export[-1]]
            wire.queue = [
                (0, bytes((0x70, 4 if all_targets else 5))),
                (0, bytes((0x61, 1 if all_targets else 2, mask, 0))),
            ]
            if all_targets or export.endswith("3"):
                wire.queue.append((0, bytes.fromhex("610300a7")))
            return (data,), 0
        if export.startswith("Ex2ASECT"):
            data = bytearray(7)
            _put(data, 0, 6)
            wire.queue = [(0, bytes.fromhex("7101119a"))]
            return (data,), 1009
        number = int(export[7:9])
        data = self.ads_data(number, 1 if number in (9, 10) else 0)
        if number == 4:
            wire.queue = [
                (0, bytes.fromhex("62200301")),
                (0, bytes.fromhex("62200401")),
                (0, bytes.fromhex("6e2003")),
                (0, bytes.fromhex("6e2004")),
                (0, bytes.fromhex("71011007")),
            ]
        elif number == 5:
            wire.queue = [(0, bytes.fromhex("71011014"))]
        elif number == 6:
            wire.queue = [(0, bytes.fromhex("62230c01"))]
        elif number == 7:
            wire.queue = [(0, bytes.fromhex("7101110f"))]
        elif number == 8:
            wire.queue = [
                (0, bytes.fromhex("6201010000000080") + bytes(27)),
                (0, bytes.fromhex("62200004") + bytes(31)),
                (0, bytes.fromhex("6220060180")),
            ]
        elif number == 9:
            wire.queue = [(0, bytes.fromhex("62200601a7"))]
        else:
            data[4:10] = bytes.fromhex("20300002aabb")
            wire.queue = [
                (0, b"\x67\x03" + bytes(16)),
                (0, bytes.fromhex("6e2030")),
                (0, bytes.fromhex("622030aabb")),
            ]
        return (data,), 1004 if number == 7 else 0

    def test_actual97_all50_exact_pairs_consumed(self):
        import hashlib

        from scripts import utility_ex_ty

        count = 0
        for source in self.original_modules():
            sha = hashlib.sha256(source).hexdigest()
            for export in supported_exports(sha):
                with self.subTest(source=sha, export=export):
                    wire = self.context(sha)
                    wire.module_bytes = source
                    args, expected = self.literal_vector(export, wire)
                    self.assertEqual(
                        utility_ex_ty.run_body(export, args, wire), expected
                    )
                    self.assertEqual(wire.queue, [])
                    count += 1
        self.assertEqual(count, 50)

    def test_host_exception_identity_survives_secondary_cleanup_faults(self):
        ctx = self.context()
        data = self.ads_data(8, 1)
        original = LookupError("authored HOST identity")
        ctx.fault = original
        ctx.session = lambda *args, **kwargs: (
            0
            if args[0] == 3
            else (_ for _ in ()).throw(RuntimeError("secondary session failure"))
        )
        ctx.finalize = lambda: (_ for _ in ()).throw(
            RuntimeError("secondary finalize failure")
        )
        with self.assertRaises(LookupError) as caught:
            _ads("Ex2ADS_08_SendMessage", (data,), ctx)
        self.assertIs(caught.exception, original)

    def test_actual83_all50_public_wrappers(self):
        import hashlib
        import json

        from scripts.utility_ex import UtilityExContext, UtilityExEngine
        from tests.test_utility_ex import Host

        root = Path(__file__).resolve().parents[1]
        packet = json.loads(
            (
                root / "analysis/evidence/no-car-130/reviewed-wrapper-packet.json"
            ).read_text()
        )
        modules = {
            hashlib.sha256(source).hexdigest(): source
            for source in self.original_modules()
        }
        count = 0
        for row in packet["rows"]:
            with self.subTest(source=row["source_sha256"], export=row["export"]):
                source = modules[row["source_sha256"]]
                host = Host()
                host.values[0x6F] = row["modes"][0]
                ctx = UtilityExContext(source, host, None, None)
                wire = self.context(ctx.module_sha256)
                args, expected = self.literal_vector(row["export"], wire)
                for selector in (
                    "selected",
                    "native:101392d0",
                    "native:1011d4f0",
                    "native:10134b78",
                    "native:1011e618",
                ):
                    ctx._communication[selector] = wire
                engine = UtilityExEngine(ctx)
                self.assertEqual(engine.invoke(row["export"], args), 15)
                self.assertEqual(engine.worker.timeout_ms, 10000)
                self.assertEqual(engine.worker.get_status(), expected)
                self.assertEqual(wire.queue, [])
                count += 1
        self.assertEqual(count, 50)

    def test_extended_prerequisite_normal_failure_stops_all_owned_calls(self):
        exports = (
            "Ex2DSEAT_01_SendMessage",
            "Ex2ITS_02_SendMessage",
            "Ex2ASECT_01_SendMessage",
        ) + tuple(f"Ex2ADS_{n:02}_SendMessage" for n in range(4, 11))
        for sha in (SHA_18_TY, SHA_PLUS_TY):
            for export in exports:
                for action in (
                    (0, 1)
                    if export
                    in (
                        "Ex2ADS_08_SendMessage",
                        "Ex2ADS_09_SendMessage",
                        "Ex2ADS_10_SendMessage",
                    )
                    else (0,)
                ):
                    with self.subTest(sha=sha, export=export, action=action):
                        ctx = self.context(sha)
                        if export.startswith("Ex2ADS"):
                            args = (self.ads_data(int(export[7:9]), action),)
                        elif export.startswith("Ex2ITS"):
                            args = ()
                        else:
                            args = (bytearray(7),)
                        ctx.queue = (
                            [(0, b"\x54")] if export.startswith("Ex2ASECT") else []
                        ) + [(71, b"")]

                        def session(
                            mode,
                            keepalive=1,
                            *,
                            normal_first=False,
                            stop_on_error=False,
                            selected=ctx,
                        ):
                            if mode == 3:
                                self.assertTrue(normal_first)
                                status, _ = selected.exchange(b"\x10\x01")
                                if status:
                                    return status
                                status, _ = selected.exchange(b"\x10\x03")
                                return status
                            return 0

                        ctx.session = session
                        expected = (
                            2000 if export == "Ex2ADS_10_SendMessage" and action else 71
                        )
                        self.assertEqual(_run(export, args, ctx), expected)
                        requests = [
                            event[1] for event in ctx.events if event[0] == "exchange"
                        ]
                        self.assertNotIn(b"\x10\x03", requests)
                        self.assertFalse(
                            any(request[0] == 0x31 for request in requests)
                        )
                        self.assertEqual(ctx.queue, [])

    def test_ambient_caller_exception_does_not_hide_sole_cleanup_failure(self):
        vectors = (
            ("Ex2ITS_01_SendMessage", (), [(3, b"")]),
            ("Ex2ITS_02_SendMessage", (), [(3, b"")]),
            ("Ex2DSEAT_01_SendMessage", (bytearray(5),), [(3, b"")]),
            ("Ex2HNFCM_02_ReadCameraData", (bytearray(899),), [(3, b"")]),
            ("Ex2ASECT_01_SendMessage", (bytearray(b"\x0a\0\0\0\0\0\0"),), []),
            ("Ex2ADS_06_SendMessage", (self.ads_data(6, 0),), [(3, b"")]),
        )
        for export, args, queue in vectors:
            with self.subTest(export=export):
                ctx = self.context()
                ctx.queue = queue
                failure = RuntimeError("sole cleanup failure")

                def finalize(error=failure):
                    raise error

                ctx.finalize = finalize
                try:
                    raise ValueError("unrelated ambient caller exception")
                except ValueError:
                    with self.assertRaises(RuntimeError) as caught:
                        _run(export, args, ctx)
                self.assertIs(caught.exception, failure)

    def test_cancel_and_bad_buffer(self):
        ctx = self.context()
        ctx.cancelled = True
        with self.assertRaises(Cancelled):
            _run("Ex2ITS_01_SendMessage", (), ctx)
        self.assertEqual(ctx.events[-1], ("finalize",))
        ctx = self.context()
        for data in (bytes(10), bytearray(4), 1):
            with self.assertRaises(ValueError):
                _run("Ex2DSEAT_01_SendMessage", (data,), ctx)
        self.assertEqual(ctx.events, [])


if __name__ == "__main__":
    unittest.main()
