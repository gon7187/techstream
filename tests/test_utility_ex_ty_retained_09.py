"""Authored native protocol and mutable-buffer traces, with no OEM execution."""

from __future__ import annotations

import hashlib
import unittest
from collections import deque
from typing import cast
from unittest.mock import patch

from scripts import utility_ex_ty_retained_09 as body
from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import SHA_12_TY, SHA_18_TY, TYSourceError
from tests.test_utility_ex_ty import Comm, Context


class Controller(Comm):
    def __init__(self, replies: list[tuple[int, bytes]] | None = None):
        super().__init__(replies or [])
        self.sessions: deque[int] = deque()
        self.snapshots: deque[tuple[int, bytes, tuple[int, ...]]] = deque()

    def session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int:
        if normal_first:
            status = self.session(1, keepalive)
            if status:
                return status
        self.events.append(("session", mode, keepalive))
        return self.sessions.popleft() if self.sessions else 0

    def support_snapshot(self, kind: int) -> tuple[int, bytes, tuple[int, ...]]:
        self.events.append(("snapshot", kind))
        return self.snapshots.popleft()


class RetainedContext(Context):
    def __init__(self, controller: Controller):
        super().__init__()
        self.controller = controller

    def native_sleep(self, ms: int, /) -> None:
        self.sleep(ms)


def snapshot(identifier: int, record: bytes) -> tuple[int, bytes, tuple[int, ...]]:
    offsets = [0x1020] * 256
    offsets[identifier] = 0
    return 0, bytes((identifier, len(record))) + record, tuple(offsets)


def data(action: int, size: int = 0x31) -> bytearray:
    result = bytearray(size)
    result[:4] = action.to_bytes(4, "little")
    return result


class RetainedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = Controller()
        self.ctx = RetainedContext(self.controller)
        self.authored_sha = hashlib.sha256(self.ctx.module_bytes).hexdigest()
        self.version = patch.object(body, "SHA_PLUS_TY", self.authored_sha)
        self.version.start()
        self.addCleanup(self.version.stop)

    def run_export(self, export: str, arg: bytearray | None = None) -> int:
        return body.run_body(export, () if arg is None else (arg,), self.ctx)

    def test_exact_pair_inventory(self) -> None:
        self.assertEqual(len(body.supported_exports(SHA_12_TY)), 8)
        self.assertEqual(len(body.supported_exports(SHA_18_TY)), 15)
        self.assertEqual(len(body.supported_exports(self.authored_sha)), 14)
        self.assertEqual(body.supported_exports("unknown"), ())
        self.assertNotIn(body.PSAALM, body.supported_exports(self.authored_sha))

    def test_source_identity_and_unowned_pair_fail_before_comm(self) -> None:
        self.ctx.module_bytes += b"tamper"
        with self.assertRaises(TYSourceError):
            self.run_export(body.HNPCS[0], data(5))
        self.assertEqual(self.ctx.events, [])
        self.ctx.module_bytes = b"authored TY module"
        with self.assertRaises(TYSourceError):
            self.run_export(body.PSAALM)

    def test_bad_buffers_and_lengths(self) -> None:
        for export in (*body.HNPCS, *body.DMC, *body.HNAHB, *body.SIS):
            with self.subTest(export=export), self.assertRaises(ValueError):
                self.run_export(export, bytearray())
        with self.assertRaises(ValueError):
            self.run_export(body.HNPCS[0], data(0x1021))
        self.assertEqual(self.controller.events[-1], "finalize")

    def test_hnpcs_exact_requests_and_success_status(self) -> None:
        for export, length, request, echo, result in (
            (body.HNPCS[0], 5, b"\x30\xa7\0\x80\0", 0xA7, 0),
            (body.HNPCS[2], 6, b"\x3b\x43\0\0\xff\0", 0x43, 0),
            (body.HNPCS[4], 2, b"\x3b\x42", 0x42, 1001),
        ):
            value = data(length)
            if export == body.HNPCS[4]:
                value[4:8] = length.to_bytes(4, "little")
            self.controller.replies = [(0, bytes((0x70, echo)))]
            self.assertEqual(self.run_export(export, value), result)
            self.assertIn(request, self.controller.events)
            self.assertEqual(self.controller.events[-1], "finalize")

    def test_hnpcs_failure_restores_and_preserves_status(self) -> None:
        self.controller.replies = [(7, b""), (0, b"\x70")]
        self.assertEqual(self.run_export(body.HNPCS[0], data(5)), 7)
        self.assertEqual(
            [x for x in self.controller.events if isinstance(x, bytes)],
            [b"\x30\xa7\0\x80\0", b"\x30"],
        )

    def test_hnpcs_echo_short_wrong_and_native_errors(self) -> None:
        for status, reply, result in (
            (0, b"", 3),
            (0, b"\x7b\x00", 3),
            (0, b"\x7b\x43\0", 3),
            (2, b"", 2),
        ):
            self.controller.replies = [(status, reply)]
            self.assertEqual(self.run_export(body.HNPCS[2], data(6)), result)

    def test_hnpcs_counter_buffer(self) -> None:
        value = data(0xFEFE)
        self.controller.replies = [(0, b"\xe9\x42\x17\x33\x29")]
        self.assertEqual(self.run_export(body.HNPCS[5], value), 0)
        self.assertEqual(value[:2], b"\x17\x29")
        for reply in (b"\xe9\x42", b"\xe9\x41\0\0\0"):
            self.controller.replies = [(0, reply)]
            self.assertEqual(self.run_export(body.HNPCS[5], value), 3)

    def test_support_counts_masks_and_retained_outputs(self) -> None:
        cases = (
            (body.HNPCS[1], 0xA7, b"\x80", 4),
            (body.HNPCS[3], 0x43, b"\xfc\xf0\xff\xff", 6),
        )
        for export, identifier, record, count in cases:
            self.controller.snapshots.append(snapshot(identifier, record))
            value = data(99)
            self.assertEqual(self.run_export(export, value), 0)
            self.assertEqual(int.from_bytes(value[:4], "little"), count)
            self.controller.snapshots.append(snapshot(identifier, bytes(len(record))))
            self.assertEqual(self.run_export(export, value), 22)
            self.assertEqual(int.from_bytes(value[:4], "little"), count)
        value = data(7)
        self.controller.snapshots.extend(
            (snapshot(0x42, b"\xff\0\xff"), snapshot(0x42, b"\xff\x01\xff"))
        )
        self.assertEqual(self.run_export(body.HNPCS[6], value), 0)
        self.assertEqual(
            (
                int.from_bytes(value[4:8], "little"),
                int.from_bytes(value[8:12], "little"),
            ),
            (4, 5),
        )

    def test_support_absent_bounds_and_hnahb_output(self) -> None:
        self.controller.snapshots.append((0, b"", (0x1020,) * 256))
        self.assertEqual(self.run_export(body.HNPCS[1], data(9)), 22)
        offsets = [0x1020] * 256
        offsets[0xA7] = 0x101F
        self.controller.snapshots.append((0, b"", tuple(offsets)))
        self.assertEqual(self.run_export(body.HNPCS[1], data(9)), 99)
        self.controller.snapshots.append(snapshot(1, b"\x20\0\x11"))
        value = data(0)
        self.assertEqual(self.run_export(body.HNAHB[0], value), 0)
        self.assertEqual(int.from_bytes(value[:4], "little"), 3)
        self.controller.replies = [(0, b"\x7b")]
        self.assertEqual(self.run_export(body.HNAHB[1], value), 0)
        self.assertIn(b"\x3b\x01\x20\0\0", self.controller.events)

    def test_init_error_and_fault_cleanup(self) -> None:
        self.controller.initial_status = 13
        self.assertEqual(self.run_export(body.HNPCS[2], data(6)), 13)
        self.controller.initial_status = 0
        with (
            patch.object(
                self.controller, "exchange", side_effect=OSError("native fault")
            ),
            self.assertRaises(OSError),
        ):
            self.run_export(body.HNPCS[2], data(6))
        self.assertEqual(self.controller.events[-1], "finalize")

    def test_cancel_before_and_during_operation(self) -> None:
        self.ctx.cancelled = True
        with self.assertRaises(Cancelled):
            self.run_export(body.HNPCS[2], data(6))
        self.assertEqual(self.controller.events, [])
        self.ctx.cancelled = False
        self.ctx.cancel_on_sleep = True
        with self.assertRaises(Cancelled):
            self.run_export(body.DMC[0], data(1))
        self.assertEqual(self.controller.events[-1], "finalize")

    def test_dmc_retained_start_and_terminal_poll(self) -> None:
        self.controller.replies = [(0, b"\x71\x01\x10\x15")]
        self.assertEqual(self.run_export(body.DMC[0], data(0)), 0)
        self.assertNotIn("finalize", self.controller.events)
        self.controller.replies = [
            (0, b"\x71\x03\x10\x15\x01"),
            (0, b"\x71\x03\x10\x15\x02"),
        ]
        self.assertEqual(self.run_export(body.DMC[0], data(1)), 0)
        self.assertEqual(self.controller.events[-2:], [("session", 1, 1), "finalize"])

    def test_dmc_poll_error_and_native_cancel(self) -> None:
        for reply in (b"\x71\x03\x10\x15\x03", b"\x71\x03\x10\x14\x02", b""):
            self.controller.replies = [(0, reply)]
            self.assertEqual(self.run_export(body.DMC[0], data(1)), 1008)
        value = data(1)
        value[4] = 1
        self.assertEqual(self.run_export(body.DMC[0], value), 0)

    def test_dmc_read_mutates_same_buffer_and_length(self) -> None:
        value = data(0, 0x1024)
        self.controller.replies = [(0, b"\x62\x20\x03\x10\x90")]
        self.assertEqual(self.run_export(body.DMC[1], value), 0)
        self.assertEqual(value[:5], b"\x62\x20\x03\x10\x90")
        self.assertEqual(int.from_bytes(value[0x1020:0x1024], "little"), 5)
        self.assertEqual(self.controller.events[-1], "finalize")

    def test_dmc_security_mutating_key_transform_and_write(self) -> None:
        value = data(0, 0x1024)
        value[:5] = b"\x62\x20\x03\x10\x90"
        value[0x1020:0x1024] = (5).to_bytes(4, "little")
        seed = bytes(range(1, 17))
        self.controller.replies = [
            (0, b"\x67\x03" + seed),
            (0, b"\x67\x04"),
            (0, b"\x6e\x20\x03"),
        ]
        self.assertEqual(self.run_export(body.DMC[2], value), 1000)
        packets = [v for v in self.controller.events if isinstance(v, bytes)]
        self.assertEqual(packets[1].hex(), "270404070a0d1a6778492e33646d76ef4c84")
        self.assertEqual(packets[2], b"\x2e\x20\x03\x10\x10")
        self.assertEqual(value[4], 0x90)

    def test_dmc_zero_seed_skips_key_and_write_failure_maps(self) -> None:
        value = data(0, 0x1024)
        value[0x1020:0x1024] = (5).to_bytes(4, "little")
        self.controller.replies = [(0, b"\x67\x03" + bytes(16)), (7, b"")]
        self.assertEqual(self.run_export(body.DMC[2], value), 1001)
        self.assertEqual(
            len([v for v in self.controller.events if isinstance(v, bytes)]), 2
        )

    def test_sis01_retained_start_and_terminal_status(self) -> None:
        self.controller.replies = [(0, b"\x71\x01\x11\x01")]
        self.assertEqual(self.run_export(body.SIS[0], data(0)), 0)
        self.assertNotIn("finalize", self.controller.events)
        value = data(1)
        self.controller.replies = [
            (0, b"\x71\x03\x11\x01\x01"),
            (0, b"\x71\x03\x11\x01\x03"),
            (0, b"\x62\x10\x05\x80"),
        ]
        self.assertEqual(self.run_export(body.SIS[0], value), 2205)
        self.assertEqual(value[4], 0x80)
        self.assertEqual(self.controller.events[-1], "finalize")

    def test_sis02_support_cache_and_identifier_reads(self) -> None:
        value = data(0)
        self.controller.replies = [
            (0, b"\x62\x01\x01" + b"\0\0\x80" + bytes(29)),
            (0, b"\x62\x10\0" + b"\0\x70" + bytes(30)),
            (0, b"\x62\x10\x0a" + b"ABCDEF"),
            (0, b"\x62\x10\x0b" + b"0123456789abcdef"),
        ]
        self.assertEqual(self.run_export(body.SIS[1], value), 0)
        self.assertEqual(value[4:26], b"ABCDEF0123456789abcdef")
        self.assertEqual(value[0x28:0x2D], b"\x01\x01\x03\x03\x03")
        self.controller.replies = [
            (0, b"\x62\x10\x0a" + b"GHIJKL"),
            (0, b"\x62\x10\x0b" + bytes(16)),
        ]
        self.assertEqual(self.run_export(body.SIS[1], value), 0)
        self.assertEqual(value[4:10], b"GHIJKL")

    def test_sis02_start_registration_and_retention(self) -> None:
        value = data(1)
        value[0x28:0x2D] = b"\x01\x01\x03\x03\x03"
        self.controller.replies = [
            (0, b"\x62\x10\x0c\0\0\0"),
            (0, b"\x71\x01\x10\x01" + b"\0\0\x40" + bytes(29)),
            (0, b"\x71\x01\x11\0" + b"\x60" + bytes(31)),
            (0, b"\x71\x01\x11\x02"),
        ]
        self.assertEqual(self.run_export(body.SIS[1], value), 0)
        self.assertEqual(value[0x2D:0x31], b"\x01\x01\x03\x03")
        self.assertNotIn("finalize", self.controller.events)
        self.assertIn(b"\x31\x01\x11\x02\x01", self.controller.events)

    def test_sis02_poll_status_branches(self) -> None:
        for action, high, result in (
            (2, 0x20, 2005),
            (2, 0x80, 2006),
            (6, 0x50, 2007),
            (6, 0x80, 2008),
        ):
            self.controller.replies = [
                (0, bytes((0x71, 3, 0x11, 2 if action == 2 else 3, 3))),
                (0, bytes((0x62, 0x10, 12, high, 0x55, 0x66))),
            ]
            value = data(action)
            self.assertEqual(self.run_export(body.SIS[1], value), result)
            if high == 0x80:
                self.assertEqual(value[0x23], 0x66)
            self.assertEqual(self.controller.events[-1], "finalize")

    def test_sis02_status_and_completion_branches(self) -> None:
        for action, high, result in (
            (3, 0x90, 0),
            (3, 0, 2001),
            (3, 0xA0, 2000),
            (4, 0x90, 0),
            (8, 0x60, 2009),
            (8, 0x70, 2010),
            (8, 0x80, 2011),
            (8, 0xF0, 2012),
        ):
            value = data(action)
            value[0x28:0x2D] = b"\x01\x01\x03\x03\x03"
            self.controller.replies = [(0, bytes((0x62, 0x10, 12, high, 100, 0x55)))]
            self.assertEqual(self.run_export(body.SIS[1], value), result)
            if high in (0x80, 0xA0):
                self.assertEqual(value[0x23], 0x55)
        for action in (2, 4, 6, 8):
            value = data(action)
            value[0x24] = 1
            self.assertEqual(self.run_export(body.SIS[1], value), 2013)

    def test_sis_native_cancel_wins_over_inflight_terminal_result(self) -> None:
        value = data(8)
        exchange = self.controller.exchange
        self.controller.replies = [(0, b"\x62\x10\x0c\x80\0\x55")]

        def cancel_on_reply(request: bytes) -> tuple[int, bytes]:
            value[0x24] = 1
            return exchange(request)

        with patch.object(self.controller, "exchange", side_effect=cancel_on_reply):
            self.assertEqual(self.run_export(body.SIS[1], value), 2013)
        self.assertEqual(value[0x23], 0x55)
        self.assertEqual(self.controller.events[-1], "finalize")

    def test_sis02_write_zero_interleave_and_unknown_action(self) -> None:
        value = data(5)
        value[0x1A:0x22] = b"12345678"
        self.controller.replies = [(0, b"\x71\x01\x11\x03")]
        self.assertEqual(self.run_export(body.SIS[1], value), 0)
        self.assertIn(
            b"\x31\x01\x11\x03\x001\x002\x003\x004\x005\x006\x007\x008",
            self.controller.events,
        )
        self.assertEqual(self.run_export(body.SIS[1], data(7)), 0)
        self.assertEqual(self.run_export(body.SIS[1], data(99)), 0)

    def test_classic_versions_keep_clear_length_in_first_dword(self) -> None:
        self.version.stop()
        for constant, setter in (
            ("SHA_12_TY", "native_rva:b940"),
            ("SHA_18_TY", "native_rva:12180"),
        ):
            with patch.object(body, constant, self.authored_sha):
                self.controller.replies = [(0, b"\x7b\x42")]
                value = data(2, 4)
                self.assertEqual(self.run_export(body.HNPCS[4], value), 1001)
                self.assertIn((setter, 150), self.controller.events)
                self.assertIn(b"\x3b\x42", self.controller.events)

    def test_support_malformed_table_and_native_boundary_fault(self) -> None:
        self.controller.snapshots.append((0, b"", ()))
        with self.assertRaises(ValueError):
            self.run_export(body.HNPCS[1], data(0))
        offsets = [0x1020] * 256
        offsets[0xA7] = 0x101E
        raw = bytes(0x101F) + b"\x01"
        self.controller.snapshots.append((0, raw, tuple(offsets)))
        with self.assertRaises(ValueError):
            self.run_export(body.HNPCS[1], data(0))
        self.assertEqual(self.controller.events[-1], "finalize")

    def test_dmc_initial_session_read_and_security_failures(self) -> None:
        self.controller.initial_status = 13
        self.assertEqual(self.run_export(body.DMC[1], data(0, 0x1024)), 13)
        self.controller.initial_status = 0
        self.controller.sessions.append(7)
        self.assertEqual(self.run_export(body.DMC[1], data(0, 0x1024)), 7)
        self.controller.replies = [(0, b"\x62\x20\x03")]
        self.assertEqual(self.run_export(body.DMC[1], data(0, 0x1024)), 3)
        self.controller.replies = [(0, b"\x67\x02" + bytes(16))]
        self.assertEqual(self.run_export(body.DMC[2], data(0, 0x1024)), 3)
        self.assertEqual(self.controller.events[-2:], [("session", 1, 1), "finalize"])
        with (
            patch.object(
                self.controller, "exchange", side_effect=OSError("native I/O fault")
            ),
            self.assertRaises(OSError),
        ):
            self.run_export(body.DMC[1], data(0, 0x1024))
        self.assertEqual(self.controller.events[-1], "finalize")

    def test_sis_lifecycle_error_paths_do_not_restore_unentered_session(self) -> None:
        self.controller.initial_status = 13
        self.assertEqual(self.run_export(body.SIS[0], data(0)), 13)
        self.assertEqual(self.controller.events[-1], "finalize")
        self.controller.events.clear()
        self.assertEqual(self.run_export(body.SIS[1], data(0)), 13)
        self.assertNotIn("finalize", self.controller.events)
        self.controller.initial_status = 0
        self.controller.sessions.append(7)
        self.assertEqual(self.run_export(body.SIS[1], data(3)), 7)
        self.assertEqual(self.controller.events[-2:], [("session", 1, 1), "finalize"])

    def test_sis_unsupported_capability_and_inflight_fault_finalize(self) -> None:
        value = data(0)
        self.controller.replies = [(0, b"\x62\x01\x01" + bytes(32))]
        self.assertEqual(self.run_export(body.SIS[1], value), 3)
        self.assertEqual(value[0x28:0x2A], b"\x01\x02")
        self.assertEqual(self.controller.events[-2:], [("session", 1, 1), "finalize"])
        with (
            patch.object(
                self.controller, "exchange", side_effect=OSError("native I/O fault")
            ),
            self.assertRaises(OSError),
        ):
            self.run_export(body.SIS[1], data(8))
        self.assertEqual(self.controller.events[-1], "finalize")

    def test_normal_session_failure_prevents_extended_and_routine_all_variants(
        self,
    ) -> None:
        self.version.stop()
        for constant in ("SHA_18_TY", "SHA_PLUS_TY"):
            with patch.object(body, constant, self.authored_sha):
                for export in (body.DMC[0], *body.SIS):
                    self.controller.events.clear()
                    self.controller.sessions.append(71)
                    self.assertEqual(self.run_export(export, data(0)), 71)
                    self.assertIn(("session", 1, 1), self.controller.events)
                    self.assertNotIn(("session", 3, 1), self.controller.events)
                    self.assertFalse(
                        any(
                            isinstance(event, bytes) for event in self.controller.events
                        )
                    )

    def test_primary_host_and_cancel_identity_survive_every_cleanup_fault(self) -> None:
        for primary in (ValueError("primary HOST fault"), Cancelled("primary cancel")):
            for export, value in (
                (body.HNPCS[2], data(6)),
                (body.DMC[1], data(0, 0x1024)),
                (body.SIS[1], data(8)),
            ):
                finalized: list[str] = []

                def finalize(finalized: list[str] = finalized) -> None:
                    finalized.append("finalize")
                    raise RuntimeError("secondary finalize fault")

                def session(
                    mode: int,
                    keepalive: int = 1,
                    *,
                    normal_first: bool = False,
                    stop_on_error: bool = False,
                    restore_fault: bool = export == body.SIS[1],
                ) -> int:
                    if mode == 1 and restore_fault:
                        raise RuntimeError("secondary restore fault")
                    return 0

                with (
                    patch.object(self.controller, "exchange", side_effect=primary),
                    patch.object(self.controller, "finalize", side_effect=finalize),
                    patch.object(self.controller, "session", side_effect=session),
                ):
                    with self.assertRaises(type(primary)) as raised:
                        self.run_export(export, value)
                    self.assertIs(raised.exception, primary)
                self.assertEqual(finalized, ["finalize"])

    def test_cleanup_without_primary_reports_first_fault_and_attempts_finalize(
        self,
    ) -> None:
        primary = OSError("restore failed")
        with (
            patch.object(self.controller, "session", side_effect=primary),
            patch.object(
                self.controller, "finalize", side_effect=RuntimeError("finalize failed")
            ) as finalized,
        ):
            with self.assertRaises(OSError) as raised:
                body._close(self.controller, restore=True)
            self.assertIs(raised.exception, primary)
            finalized.assert_called_once_with()

    def test_unrelated_caller_exception_does_not_hide_cleanup_failure(self) -> None:
        cleanup = OSError("cleanup failed")
        self.controller.replies = [(0, b"\x7b\x43")]
        try:
            raise RuntimeError("already handled caller fault")
        except RuntimeError:
            with patch.object(self.controller, "finalize", side_effect=cleanup):
                with self.assertRaises(OSError) as raised:
                    self.run_export(body.HNPCS[2], data(6))
                self.assertIs(raised.exception, cleanup)

    def test_actual83_wrapper_thread_status_and_result_global_source_only(self) -> None:
        from scripts.utility_ex import SOURCES, UtilityEx2TY, UtilityExContext
        from scripts.utility_ex_comm import UtilityExComm
        from tests.test_utility_ex import Host

        host = Host()
        with patch.dict(SOURCES, {self.authored_sha: "TYPlus"}):
            context = UtilityExContext(self.ctx.module_bytes, host, None, None)
            context._communication["selected"] = cast(UtilityExComm, self.controller)
            engine = UtilityEx2TY(context)
            self.controller.replies = [(0, b"\x7b\x43")]
            self.assertEqual(engine.invoke(body.HNPCS[2], (data(6),)), 15)
            self.assertEqual(engine.worker.get_status(), 0)
            self.assertEqual(context.state["native_global:10134ab8"], 0)
            host.values[0x6F] = 0
            context.refresh_parameters()
            self.assertEqual(engine.invoke(body.HNPCS[2], (data(6),)), 99)
            with self.assertRaises(ValueError):
                engine.invoke(body.HNPCS[2], ())

    def test_actual97_aggregator_preserves_context_and_buffer(self) -> None:
        from scripts.utility_ex_ty import run_body, supported_exports

        value = data(0)
        self.controller.replies = [(0, b"\xe9\x42\x17\x33\x29")]
        self.assertIn(body.HNPCS[5], supported_exports(self.authored_sha))
        self.assertEqual(run_body(body.HNPCS[5], (value,), self.ctx), 0)
        self.assertEqual(value[:2], b"\x17\x29")
        self.assertEqual(self.ctx.events[0], ("comm", "selected"))

    def test_psaalm_classic_exact_two_byte_echo(self) -> None:
        self.version.stop()
        with patch.object(body, "SHA_12_TY", self.authored_sha):
            for reply, result in (
                (b"\x7b\x85", 0),
                (b"\x7b\x84", 3),
                (b"\x7b\x85\0", 3),
            ):
                self.controller.replies = [(0, reply)]
                self.assertEqual(self.run_export(body.PSAALM), result)
            self.assertIn(b"\x3b\x85", self.controller.events)
            self.assertIn(("sleep", 100), self.ctx.events)


if __name__ == "__main__":
    unittest.main()
