"""Authored literal traces: no OEM bytes or execution are required."""

from __future__ import annotations

import struct
import unittest
from unittest.mock import patch

from scripts import utility_ex_ty_retained_05 as body
from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import SHA_12_TY, SHA_18_TY, SHA_PLUS_TY, TYSourceError
from tests.test_utility_ex_ty import Comm, Context


class RetainedComm(Comm):
    def session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int:
        self.events.append(("session", mode, keepalive, normal_first))
        return 0

    def select_target(self, identifier: int, second: int = 0) -> None:
        self.events.append(("target", identifier, second))


class RetainedTests(unittest.TestCase):
    def call(
        self,
        name: str,
        replies: list[tuple[int, bytes]],
        buf: bytearray | None = None,
        sha: str = SHA_18_TY,
    ) -> tuple[int, Context, bytearray]:
        c = Context(replies)
        c.controller = RetainedComm(replies)
        c.module_sha256 = sha
        b = bytearray(20) if buf is None else buf
        with patch.object(body.hashlib, "sha256") as digest:
            digest.return_value.hexdigest.return_value = sha
            result = body.run_body(name, (b,), c)
        self.assertFalse(c.controller.replies)
        return result, c, b

    def test_exact_pair_scope(self) -> None:
        self.assertEqual(
            sum(len(body.supported_exports(sha)) for sha in body.SOURCES), 37
        )
        self.assertEqual(body.supported_exports("bad"), ())
        self.assertNotIn(body.PSA[0], body.supported_exports(SHA_PLUS_TY))

    def test_psa_fys_read_byte_identity(self) -> None:
        identity = bytearray(24)
        identity[0:2] = b"\x61\x80"
        identity[20:23] = b"FYS"
        buf = bytearray(b"\0\0\0\0\xaa\xbb\xcc\xdd")
        status, c, output = self.call(
            body.PSA[0],
            [(0, bytes(identity)), (0, b"\x61\xd0" + b"\0" * 7 + b"\xfd")],
            buf,
        )
        self.assertEqual(status, 0)
        self.assertIs(output, buf)
        self.assertEqual(buf[4:], b"\x0d\xbb\xcc\xdd")
        self.assertEqual(
            [x for x in c.controller.events if isinstance(x, bytes)],
            [b"\x21\x80", b"\x21\xd0"],
        )
        self.assertEqual(c.controller.events[-1], "finalize")

    def test_psa_fallback_and_write_exact_branch(self) -> None:
        for sha in (SHA_12_TY, SHA_18_TY):
            reply = b"\x61\x80" + bytes(22)
            status, _, buf = self.call(
                body.PSA[0], [(0, reply), (0, b"\x61\xca\x26")], sha=sha
            )
            self.assertEqual((status, buf[4]), (0, 6))
            for setting, identifier in ((1, 0xDF), (0, 0xE0), (2, 0xE0)):
                buf = bytearray(8)
                struct.pack_into("<I", buf, 0, setting)
                status, c, _ = self.call(
                    body.PSA[1], [(0, bytes((0x7B, identifier)))], buf, sha
                )
                self.assertEqual(status, 0)
                self.assertIn(bytes((0x3B, identifier, 0)), c.controller.events)

    def test_psa_malformed_and_native_failure(self) -> None:
        for replies, result in (([(0, b"\x61")], 3), ([(17, b"")], 17)):
            status, c, _ = self.call(body.PSA[0], replies)
            self.assertEqual(status, result)
            self.assertEqual(c.controller.events[-1], "finalize")

    def test_stb_active_native_fault_cleanup_and_retention(self) -> None:
        for sha in body.SOURCES:
            status, c, _ = self.call(
                body.STB04[2],
                [
                    (0, b"\x50"),
                    (0, b"\x7b\x01"),
                    (19, b""),
                    (0, b"\x7b\x02"),
                    (0, b"\x50\x01"),
                ],
                sha=sha,
            )
            self.assertEqual(status, 19)
            frames = [x for x in c.controller.events if isinstance(x, bytes)]
            self.assertEqual(
                frames,
                [
                    b"\x10\x40",
                    b"\x3b\x01\x01\0",
                    body.DRIVE,
                    b"\x3b\x01\0\0",
                    b"\x10\x01",
                ],
            )
            self.assertEqual(c.state["native_global:" + body.RESULT[sha]], 19)
            self.assertEqual(c.controller.events.count("finalize"), 5)

    def test_stb_restart_success_retains_session(self) -> None:
        status, c, _ = self.call(body.STB04[3], [(0, b"\x70\x02")])
        self.assertEqual(status, 0)
        self.assertEqual(
            [x for x in c.controller.events if isinstance(x, bytes)], [body.DRIVE]
        )

    def test_stb_exit_ignores_native_cleanup_results(self) -> None:
        status, c, _ = self.call(body.STB04[4], [(29, b""), (18, b"")])
        self.assertEqual(status, 0)
        self.assertEqual(c.controller.events.count("finalize"), 2)

    def test_stb_pre_already_calibrated_and_malformed(self) -> None:
        for final, expected in (
            (b"\x61\x83\0\0\x01", 0),
            (b"\x61\x83\0\0\x02", 3),
            (b"\x61\x82\0\0\x01", 3),
        ):
            status, _, _ = self.call(
                body.STB03[1], [(0, b"\x53\0"), (0, b"\x53\0"), (0, final)]
            )
            self.assertEqual(status, expected)

    def test_stb_pre_clear_failure_resets(self) -> None:
        status, c, _ = self.call(
            body.STB03[1],
            [
                (0, b"\x53\0"),
                (0, b"\x53\x01\x59\xa7"),
                (0, b"\x61\x83\0\0\0"),
                (0, b"\x50"),
                (42, b""),
                (0, b"\x50"),
            ],
        )
        self.assertEqual(status, 42)
        self.assertEqual(
            [x for x in c.controller.events if isinstance(x, bytes)][-2:],
            [b"\xa6\x01", b"\x10\x01"],
        )

    def test_stb_start_native_fault_uses_both_resets(self) -> None:
        status, c, _ = self.call(
            body.STB03[2],
            [
                (0, b"\x50"),
                (0, b"\x7b\x01"),
                (0, b"\x50"),
                (12, b""),
                (0, b"\x50"),
                (0, b"\x50"),
            ],
        )
        self.assertEqual(status, 12)
        self.assertEqual(
            [x for x in c.controller.events if isinstance(x, bytes)][-2:],
            [b"\x10\x01", b"\x10\x01"],
        )

    def test_stb_execute_scans_each_byte_and_always_resets(self) -> None:
        for dtc, expected in (
            (b"\x53\x01\x59\xa9", 6),
            (b"\x53\0", 0),
            (b"\x53\x02", 3),
        ):
            status, c, _ = self.call(body.STB03[3], [(0, dtc), (12, b""), (13, b"")])
            self.assertEqual(status, expected)
            self.assertEqual(c.controller.events.count("finalize"), 3)

    def test_support_native_lookup_and_bounds(self) -> None:
        offsets = [0x1020] * 256
        offsets[2] = 0
        status, record = body._record(
            bytes((2, 6, 255, 255, 255, 255, 255, 255)), tuple(offsets), 2
        )
        self.assertEqual(status, 0)
        self.assertEqual([body._required(record, i) for i in range(3, 9)], [0] * 6)
        self.assertEqual(body._record(b"\0", tuple(offsets), 2)[0], 99)
        self.assertEqual(body._record(b"", tuple(offsets), 1)[0], 22)

    def test_rcam_support_and_source_masks(self) -> None:
        for sha in (SHA_18_TY, SHA_PLUS_TY):
            first = b"\x71\x01\x10\x01\0\0\x80" + bytes(29)
            second = b"\x71\x01\x10\0\0\0\x18" + bytes(29)
            status, c, buf = self.call(body.RCAM[0], [(0, first), (0, second)], sha=sha)
            self.assertEqual(
                (status, struct.unpack_from("<I", buf, 4)[0]), (0, 0xC0000000)
            )
            self.assertEqual(c.controller.events[-1], "finalize")
            self.assertIn(("session", 1, 1, False), c.controller.events)

    def test_rcam_acquire_retain_and_caller_cancel_close_session_only(self) -> None:
        for sha in (SHA_18_TY, SHA_PLUS_TY):
            buf = bytearray(13)
            struct.pack_into("<II", buf, 0, 1, 0x80000000)
            status, c, _ = self.call(body.RCAM[0], [(0, b"\x71\x01\x10\x14")], buf, sha)
            self.assertEqual(status, 0)
            self.assertNotIn("finalize", c.controller.events)
            self.assertTrue(c.state["ty_retained05:rcam_connected"])
            self.assertIn(b"\x31\x01\x10\x14\xff\xff", c.controller.events)
            struct.pack_into("<III", buf, 0, 2, 0, 1)
            status, c, _ = self.call(body.RCAM[0], [], buf, sha)
            self.assertEqual(status, 0)
            self.assertIn(("session", 1, 1, False), c.controller.events)
            self.assertNotIn("finalize", c.controller.events)

    def test_rcam_missing_mask_retains_action1_only(self) -> None:
        for action in (1, 3):
            buf = bytearray(13)
            struct.pack_into("<I", buf, 0, action)
            status, c, _ = self.call(body.RCAM[0], [], buf)
            self.assertEqual(status, 22)
            self.assertEqual("finalize" in c.controller.events, action == 3)

    def test_rcam_poll_first_stage_keeps_session_second_stage_closes(self) -> None:
        for action in (2, 4):
            buf = bytearray(13)
            struct.pack_into("<I", buf, 0, action)
            status, c, _ = self.call(
                body.RCAM[0], [(0, b"\x62\x11\x27\0\0\0\0\x01")], buf
            )
            self.assertEqual(status, 0)
            self.assertEqual("finalize" in c.controller.events, action == 4)
            self.assertEqual(
                ("session", 1, 1, False) in c.controller.events, action == 4
            )

    def test_rcam_data_read_write_borrowed_buffer_and_seed_transform(self) -> None:
        for sha in (SHA_18_TY, SHA_PLUS_TY):
            buf = bytearray(0x102C)
            status, c, output = self.call(
                body.RCAM[1], [(0, b"\x62\x20\x30\xaa\xbb\xcc")], buf, sha
            )
            self.assertEqual(status, 0)
            self.assertIs(output, buf)
            self.assertEqual(buf[:7], b"\x03\0\0\0\xaa\xbb\xcc")
            struct.pack_into("<I", buf, 0x1028, 1)
            buf[0x1024] = 1
            status, c, output = self.call(
                body.RCAM[1],
                [
                    (0, b"\x67\x03\x01\x02\x03\x04\x05\x06"),
                    (0, b"\x67\x04"),
                    (0, b"\x6e\x20\x30"),
                ],
                buf,
                sha,
            )
            self.assertEqual(status, 0)
            # Each update consumes the already-mutated key array; original seed selects rotation/index.
            self.assertIn(b"\x27\x04\x04\x07\x0a\x0d\x1a\x64", c.controller.events)
            self.assertIn(b"\x2e\x20\x30\xaa\x3b\xcc", c.controller.events)
            self.assertEqual(buf[5], 0xBB)

    def test_rcam_data_write_native_failure_maps_to_2000(self) -> None:
        buf = bytearray(0x102C)
        struct.pack_into("<I", buf, 0, 2)
        struct.pack_into("<I", buf, 0x1028, 1)
        status, c, _ = self.call(
            body.RCAM[1], [(0, b"\x67\x03" + bytes(6)), (29, b"")], buf
        )
        self.assertEqual(status, 2000)
        self.assertEqual(c.controller.events[-1], "finalize")

    def test_rcam03_retention_and_poll_terminal_status(self) -> None:
        for sha in (SHA_18_TY, SHA_PLUS_TY):
            buf = bytearray(13)
            status, c, _ = self.call(body.RCAM[2], [], buf, sha)
            self.assertEqual(status, 1000)
            self.assertEqual(c.controller.events[-1], "finalize")
            struct.pack_into("<I", buf, 0, 1)
            buf[8], buf[11], buf[12] = 7, 8, 9
            status, c, _ = self.call(body.RCAM[2], [(0, b"\x71\x01\x11\x31")], buf, sha)
            self.assertEqual(status, 0)
            self.assertNotIn("finalize", c.controller.events)
            self.assertIn(b"\x31\x01\x11\x31\x07\x08\x09", c.controller.events)
            struct.pack_into("<I", buf, 0, 2)
            status, c, _ = self.call(
                body.RCAM[2],
                [(0, b"\x71\x03\x11\x31\0"), (0, b"\x71\x03\x11\x31\x03")],
                buf,
                sha,
            )
            self.assertEqual(status, 1008)
            self.assertEqual(c.controller.events[-1], "finalize")

    def test_full_support_checks_mutate_original_buffer_in_place(self) -> None:
        def snapshot(kind: int, flags: bytes) -> tuple[int, bytes, tuple[int, ...]]:
            offsets = [0x1020] * 256
            offsets[kind] = 0
            return 0, bytes((kind, len(flags))) + flags, tuple(offsets)

        for sha in body.SOURCES:
            for active in (False, True):
                c = Context()
                c.module_sha256 = sha
                c.controller = RetainedComm([])
                snapshots = [snapshot(1, b"\xff\xff")]
                if not active:
                    snapshots.append(snapshot(0x83, b"\xff\xff\xff"))
                snapshots.append(snapshot(2, b"\xff" * 6))
                buf = bytearray(20)
                export = body.STB04[0] if active else body.STB03[0]
                with (
                    patch.object(
                        c.controller, "support_snapshot", side_effect=snapshots
                    ),
                    patch.object(body.hashlib, "sha256") as digest,
                ):
                    digest.return_value.hexdigest.return_value = sha
                    self.assertEqual(body.run_body(export, (buf,), c), 0)
                self.assertEqual(struct.unpack_from("<II", buf, 0), (2, 9))
                if not active:
                    self.assertEqual(struct.unpack_from("<I", buf, 8)[0], 5)
                self.assertEqual(
                    c.controller.events.count("finalize"), 2 if active else 3
                )

    def test_rcam02_native_allocation_edges_preserve_ui_and_length(self) -> None:
        for sha in (SHA_18_TY, SHA_PLUS_TY):
            buf = bytearray(b"Z" * 0x102C)
            struct.pack_into("<I", buf, 0x1028, 0)
            tail = bytes(buf[0x1021:])
            status, _, output = self.call(
                body.RCAM[1], [(0, b"\x62\x20\x30" + b"A" * 0x101D)], buf, sha
            )
            self.assertEqual(status, 0)
            self.assertIs(output, buf)
            self.assertEqual(len(buf), 0x102C)
            self.assertEqual(buf[0x1021:], tail)
            self.assertEqual(struct.unpack_from("<I", buf)[0], 0x101D)
            c = Context()
            c.module_sha256 = sha
            c.controller = RetainedComm([(0, b"\x62\x20\x30" + b"A" * 0x101E)])
            struct.pack_into("<I", buf, 0x1028, 0)
            before = bytes(buf)
            with patch.object(body.hashlib, "sha256") as digest:
                digest.return_value.hexdigest.return_value = sha
                with self.assertRaisesRegex(ValueError, "reply exceeds"):
                    body.run_body(body.RCAM[1], (buf,), c)
            self.assertEqual(bytes(buf), before)
            self.assertEqual(c.controller.events[-1], "finalize")
            struct.pack_into("<I", buf, 0, 0x101D)
            struct.pack_into("<I", buf, 0x1028, 1)
            status, c, _ = self.call(
                body.RCAM[1],
                [(0, b"\x67\x03" + bytes(6)), (0, b"\x6e\x20\x30")],
                buf,
                sha,
            )
            self.assertEqual(status, 0)
            self.assertEqual(
                len([x for x in c.controller.events if isinstance(x, bytes)][-1]),
                0x1020,
            )
            struct.pack_into("<I", buf, 0, 0x101E)
            c = Context()
            c.module_sha256 = sha
            c.controller = RetainedComm([])
            with patch.object(body.hashlib, "sha256") as digest:
                digest.return_value.hexdigest.return_value = sha
                with self.assertRaisesRegex(ValueError, "2..4125"):
                    body.run_body(body.RCAM[1], (buf,), c)
            self.assertFalse(any(isinstance(x, bytes) for x in c.controller.events))
            self.assertEqual(c.controller.events[-1], "finalize")

    def test_actual97_consumer_with_original_image_identity(self) -> None:
        from pathlib import Path
        from typing import cast

        from scripts.utility_ex import UtilityEx2TY, UtilityExContext
        from scripts.utility_ex_comm import UtilityExComm
        from scripts.utility_ex_ty import supported_exports
        from tests.test_utility_ex import Host

        paths = {
            SHA_12_TY: "artifacts/extracted/techstream-12-application/Techstream_Bin/UtilityEx2TY.dll",
            SHA_18_TY: "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll",
            SHA_PLUS_TY: "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll",
        }
        if not all(Path(path).is_file() for path in paths.values()):
            self.skipTest("Optional BYOD original TY images unavailable")
        for sha, path in paths.items():
            context = UtilityExContext(Path(path).read_bytes(), Host(), None, None)
            self.assertEqual(context.module_sha256, sha)
            comm = RetainedComm([(29, b""), (18, b"")])
            context._communication["selected"] = cast(UtilityExComm, comm)
            engine = UtilityEx2TY(context)
            self.assertTrue(
                set(body.supported_exports(sha)).issubset(supported_exports(sha))
            )
            buf = bytearray(20)
            self.assertEqual(engine.run_body(body.STB04[4], (buf,)), 0)
            self.assertEqual(comm.events.count("finalize"), 2)
            if sha != SHA_PLUS_TY:
                comm.replies = [(0, b"\x7b\xe0")]
                self.assertEqual(engine.run_body(body.PSA[1], (buf,)), 0)
                self.assertIn(b"\x3b\xe0\0", comm.events)
            else:
                fixed = RetainedComm([])
                context._communication["native:101392d0"] = cast(UtilityExComm, fixed)
                self.assertEqual(engine.run_body(body.RCAM[2], (buf,)), 1000)
                self.assertEqual(fixed.events[-1], "finalize")

    def test_all37_actual83_wrappers_thread_status_and97_positive_bodies(self) -> None:
        from pathlib import Path
        from typing import cast

        from scripts.utility_ex import UtilityEx2TY, UtilityExContext
        from scripts.utility_ex_comm import UtilityExComm
        from tests.test_utility_ex import Host

        paths = {
            SHA_12_TY: "artifacts/extracted/techstream-12-application/Techstream_Bin/UtilityEx2TY.dll",
            SHA_18_TY: "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll",
            SHA_PLUS_TY: "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll",
        }
        if not all(Path(path).is_file() for path in paths.values()):
            self.skipTest("Optional BYOD original TY images unavailable")

        def snap(kind: int, payload: bytes) -> tuple[int, bytes, tuple[int, ...]]:
            offsets = [0x1020] * 256
            offsets[kind] = 0
            return 0, bytes((kind, len(payload))) + payload, tuple(offsets)

        cases = {
            body.STB03[0]: ([], 0),
            body.STB03[1]: ([b"\x53\0", b"\x53\0", b"\x61\x83\0\0\x01"], 0),
            body.STB03[2]: ([b"\x50", b"\x7b\x01", b"\x50", b"\x50", b"\x70\x02"], 0),
            body.STB03[3]: ([b"\x53\0", b"\x50", b"\x50"], 0),
            body.STB04[0]: ([], 0),
            body.STB04[1]: ([b"\x53\0", b"\x53\0"], 0),
            body.STB04[2]: ([b"\x50", b"\x7b\x01", b"\x70\x02"], 0),
            body.STB04[3]: ([b"\x70\x02"], 0),
            body.STB04[4]: ([b"\x7b\x02", b"\x50\x01"], 0),
            body.PSA[0]: ([b"\x61\x80" + bytes(22), b"\x61\xca\x07"], 0),
            body.PSA[1]: ([b"\x7b\xe0"], 0),
            body.RCAM[0]: (
                [
                    b"\x71\x01\x10\x01\0\0\x80" + bytes(29),
                    b"\x71\x01\x10\0\0\0\x18" + bytes(29),
                ],
                0,
            ),
            body.RCAM[1]: ([b"\x62\x20\x30\xaa\xbb"], 0),
            body.RCAM[2]: ([], 1000),
        }
        count = 0
        for sha, path in paths.items():
            image = Path(path).read_bytes()
            for export in body.supported_exports(sha):
                with self.subTest(sha=sha, export=export):
                    replies, expected = cases[export]
                    context = UtilityExContext(image, Host(), None, None)
                    context._parameters[0x6F] = (
                        19 if export in body.PSA else 20 if export in body.RCAM else 4
                    )
                    comm = RetainedComm([(0, frame) for frame in replies])
                    for selector in ("selected", "native:1011d4f0", "native:101392d0"):
                        context._communication[selector] = cast(UtilityExComm, comm)
                    snapshots = [snap(1, b"\xff\xff")]
                    if export == body.STB03[0]:
                        snapshots.append(snap(0x83, b"\xff" * 3))
                    snapshots.append(snap(2, b"\xff" * 6))
                    engine = UtilityEx2TY(context)
                    buf = bytearray(0x102C if export == body.RCAM[1] else 20)
                    with patch.object(comm, "support_snapshot", side_effect=snapshots):
                        self.assertEqual(engine.invoke(export, (buf,)), 15)
                        self.assertEqual(engine.worker.timeout_ms, 10000)
                        self.assertEqual(engine.worker.get_status(), expected)
                    self.assertFalse(comm.replies)
                    self.assertEqual(
                        context.state["native_global:" + body.RESULT[sha]], expected
                    )
                    context._parameters[0x6F] = 0
                    self.assertEqual(engine.invoke(export, (buf,)), 99)
                    count += 1
        self.assertEqual(count, 37)

    def test_identity_boundary_cancellation_and_cleanup_on_host_fault(self) -> None:
        c = Context()
        c.module_sha256 = SHA_18_TY
        with self.assertRaises(TYSourceError):
            body.run_body(body.PSA[0], (bytearray(8),), c)
        self.assertEqual(c.events, [])
        c.cancelled = True
        with patch.object(body.hashlib, "sha256") as digest:
            digest.return_value.hexdigest.return_value = SHA_18_TY
            with self.assertRaises(Cancelled):
                body.run_body(body.PSA[0], (bytearray(8),), c)
            c.cancelled = False
            with (
                patch.object(
                    c.controller, "exchange", side_effect=OSError("host fault")
                ),
                self.assertRaises(OSError),
            ):
                body.run_body(body.PSA[0], (bytearray(8),), c)
        self.assertEqual(c.controller.events[-1], "finalize")


if __name__ == "__main__":
    unittest.main()
