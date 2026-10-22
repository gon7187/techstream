"""Authored literal transport traces for retained TY bodies, without OEM execution."""

from __future__ import annotations

import calendar
import io
import threading
import time
import unittest
import zipfile
from collections import deque
from typing import Any
from unittest.mock import patch

from scripts import utility_ex_ty_retained_02 as ty
from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import SHA_12_TY, SHA_18_TY, SHA_PLUS_TY, TYSourceError


class Comm:
    def __init__(
        self,
        trace: tuple[tuple[bytes, int, bytes], ...]
        | list[tuple[bytes, int, bytes]] = (),
    ) -> None:
        self.trace = deque(trace)
        self.events: list[object] = []
        self.open_status = 0
        self.sessions: deque[int] = deque()
        self.snapshots: deque[tuple[int, bytes, tuple[int, ...]]] = deque()

    def initialize(self, mode: int = 0) -> int:
        self.events.append(("open", mode))
        return self.open_status

    def configure(self, key: str, value: int) -> None:
        self.events.append((key, value))

    def select_protocol(self, kind: int) -> int:
        self.events.append(("protocol", kind))
        return 0

    def configure_target(self, *args: int) -> None:
        self.events.append(("target", args))

    def read_target(self) -> tuple[int, int]:
        return 0x700, 0

    def finalize(self) -> None:
        self.events.append("close")

    def exchange(self, request: bytes) -> tuple[int, bytes]:
        self.events.append(request)
        expected, status, reply = self.trace.popleft()
        assert request == expected, (request.hex(), expected.hex())
        return status, reply

    def support_snapshot(self, kind: int) -> tuple[int, bytes, tuple[int, ...]]:
        self.events.append(("support", kind))
        return self.snapshots.popleft()

    def session(self, mode: int, keepalive: int = 1, **options: object) -> int:
        self.events.append(("session", mode, keepalive, options))
        return self.sessions.popleft() if self.sessions else 0


class Context:
    def __init__(self, comm: Comm, sha: str = SHA_18_TY, mode: int = 20) -> None:
        self.controller = comm
        self.module_sha256 = sha
        self.module_bytes = b"authored-host-fixture"
        self.state: dict[str, object] = {}
        self.mode = mode
        self.clock = 0
        self.cancelled = False
        self.selectors: list[str] = []
        self.sleep_hook: Any = None

    def comm(self, kind: str, /) -> Any:
        self.selectors.append(kind)
        return self.controller

    def is_cancelled(self) -> bool:
        return self.cancelled

    def sleep(self, ms: int, /) -> None:
        self.clock += ms
        if self.sleep_hook:
            self.sleep_hook(ms)

    def native_sleep(self, ms: int, /) -> None:
        self.sleep(ms)
        if self.cancelled:
            raise Cancelled("Injected native Sleep interruption")

    def set_parameter(self, key: int, value: int) -> int:
        self.controller.events.append(("parameter", key, value))
        return 1

    def write_parameters(self) -> int:
        self.controller.events.append("write_parameters")
        return 1

    def refresh_parameters(self) -> None:
        self.controller.events.append("refresh_parameters")

    def ticks(self) -> int:
        return self.clock & 0xFFFFFFFF


class VCIBFiles:
    def __init__(self) -> None:
        self.data: dict[str, bytes] = {}
        self.allocations: set[object] = set()
        self.free = 1 << 40
        self.write_failures = 0
        self.zip_failures = 0
        self.deleted: list[str] = []
        self.count_stuck = False
        self.allocation_fail = False
        self.shell_flags: list[int] = []

    def local_time(self) -> ty.NativeDate:
        return 2026, 10, 20, 12, 34, 56

    def mktime(self, value: ty.NativeDate) -> int:
        return calendar.timegm(value)

    def gmtime(self, seconds: int) -> ty.NativeDate:
        return tuple(time.gmtime(seconds)[:6])  # type: ignore[return-value]

    def localtime(self, seconds: int) -> ty.NativeDate:
        return self.gmtime(seconds)

    def decode_ansi(self, value: bytes) -> str:
        return value.decode("ascii")

    def common_application_data(self) -> str:
        return "C:\\ProgramData"

    def allocate(self, size: int) -> object | None:
        if self.allocation_fail:
            return None
        token = object()
        self.allocations.add(token)
        return token

    def release(self, allocation: object) -> None:
        self.allocations.remove(allocation)

    def mkdir(self, path: str) -> None:
        pass

    def write(self, path: str, value: bytes) -> int:
        if self.write_failures:
            self.write_failures -= 1
            return 0
        self.data[path] = value
        return len(value)

    def read(self, path: str) -> bytes:
        return self.data[path]

    def exists(self, path: str) -> bool:
        return path in self.data

    def delete(self, path: str) -> None:
        self.deleted.append(path)
        self.data.pop(path, None)

    def files(self, directory: str, suffix: str) -> tuple[str, ...]:
        prefix = directory.rstrip("\\") + "\\"
        return tuple(
            path
            for path in self.data
            if path.startswith(prefix) and path.lower().endswith(suffix.lower())
        )

    def free_space(self, directory: str) -> int:
        return self.free

    def zip_open(self, path: str, *, update: bool) -> object:
        stream = io.BytesIO(self.data.get(path, b""))
        archive = zipfile.ZipFile(
            stream, "a" if path in self.data else "w", compression=zipfile.ZIP_DEFLATED
        )
        return path, stream, archive

    def zip_add(
        self, handle: Any, path: str, name: str, *, shell_flags: int = 0
    ) -> None:
        self.shell_flags.append(shell_flags)
        if self.zip_failures:
            self.zip_failures -= 1
            raise OSError("Injected archive entry failure")
        handle[2].writestr(name, self.data[path])

    def zip_count(self, handle: Any) -> int:
        return 0 if self.count_stuck else len(handle[2].infolist())

    def zip_close(self, handle: Any) -> None:
        path, stream, archive = handle
        archive.close()
        self.data[path] = stream.getvalue()


def vcib_block(sha: str, host: VCIBFiles) -> ty.VCIBBlock:
    layout = ty._VCIB_LAYOUTS[sha]
    block = ty.VCIBBlock(bytearray(layout.log_kind + 4), host)  # type: ignore[arg-type]
    directory = host.common_application_data() + "\\GTSPlus\\InterfaceBoxLogFile\\"
    for offset, path in (
        (4, host.common_application_data() + "\\"),
        (layout.directory, directory),
    ):
        value = path.encode("utf-16-le" if sha == SHA_PLUS_TY else "ascii")
        block.data[offset : offset + len(value)] = value
    block.data[layout.start : layout.start + 6] = bytes((26, 1, 1, 26, 12, 31))
    return block


def literal(request: str, reply: str = "", status: int = 0) -> tuple[bytes, int, bytes]:
    return bytes.fromhex(request), status, bytes.fromhex(reply)


class RetainedTests(unittest.TestCase):
    def invoke(self, export: str, args: tuple[object, ...], context: Context) -> int:
        # Authored bytes remain explicitly HOST; only this identity-check seam is isolated.
        with patch.object(ty.hashlib, "sha256") as digest:
            digest.return_value.hexdigest.return_value = context.module_sha256
            return ty.run_body(export, args, context)  # type: ignore[arg-type]

    def test_host_identity_is_rejected_before_any_communication(self) -> None:
        comm = Comm()
        with self.assertRaises(TYSourceError):
            ty.run_body(ty.FRD4, (), Context(comm))  # type: ignore[arg-type]
        self.assertEqual(comm.events, [])

    def test_unknown_build_never_advertises(self) -> None:
        self.assertEqual(ty.supported_exports("HOST"), ())
        self.assertNotIn(ty.FRD4, ty.supported_exports(SHA_12_TY))

    def test_evb_literal_all_three_source_versions(self) -> None:
        for sha in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY):
            with self.subTest(sha=sha):
                comm = Comm([literal("3b2301", "7b23")])
                context = Context(comm, sha, 4)
                self.assertEqual(self.invoke(ty.EVB, (), context), 0)
                self.assertEqual(context.clock, 10000)
                self.assertEqual(comm.events[-1], "close")
                self.assertFalse(comm.trace)

    def test_evb_length_fault_and_initialize_fault(self) -> None:
        for reply in ("", "7b", "7b2301"):
            comm = Comm([literal("3b2301", reply)])
            self.assertEqual(self.invoke(ty.EVB, (), Context(comm, mode=4)), 3)
        comm = Comm()
        comm.open_status = 27
        self.assertEqual(self.invoke(ty.EVB, (), Context(comm, mode=4)), 27)
        self.assertEqual(comm.events, [("open", 0), "close"])

    def test_evb_cancel_during_native_wait_closes(self) -> None:
        comm = Comm()
        context = Context(comm, mode=4)
        context.sleep_hook = lambda ms: setattr(context, "cancelled", True)
        with self.assertRaises(Cancelled):
            self.invoke(ty.EVB, (), context)
        self.assertEqual(comm.events[-1], "close")

    def test_wrapper_mode_and_arity(self) -> None:
        comm = Comm()
        self.assertEqual(self.invoke(ty.VCIB5, (), Context(comm, mode=21)), 99)
        with self.assertRaises(ValueError):
            self.invoke(ty.FRD4, (1,), Context(comm))
        with self.assertRaises(ValueError):
            self.invoke(ty.FRD5, (bytearray(5),), Context(comm))
        self.assertEqual(comm.events, [])

    def test_frd4_read_modify_verify_both_builds(self) -> None:
        for sha in (SHA_18_TY, SHA_PLUS_TY):
            comm = Comm(
                [
                    literal("220204", "620204aa60bb"),
                    literal("2e0204aa40bb", "6e0204"),
                    literal("220204", "620204aa40bb"),
                ]
            )
            self.assertEqual(self.invoke(ty.FRD4, (), Context(comm, sha)), 0)
            self.assertFalse(comm.trace)
            self.assertEqual(comm.events[-1], "close")

    def test_frd4_no_bit_and_failed_verification(self) -> None:
        comm = Comm([literal("220204", "620204aa00")])
        self.assertEqual(self.invoke(ty.FRD4, (), Context(comm)), 1005)
        comm = Comm(
            [
                literal("220204", "620204aa20"),
                literal("2e0204aa00", "6e0204"),
                literal("220204", "620204aa20"),
            ]
        )
        self.assertEqual(self.invoke(ty.FRD4, (), Context(comm)), 3)

    def test_frd3_preserves_buffer_identity_and_full_reply_copy(self) -> None:
        block = ty.TYRetainedBlock(bytearray(0x1028))
        block.data[0x1024] = 0xAB
        identity = id(block.data)
        comm = Comm(
            [
                literal("2220f0", "6220f00102030405"),
                literal("2e20f0010203ab05", "6e20f0"),
            ]
        )
        self.assertEqual(self.invoke(ty.FRD3, (block,), Context(comm)), 0)
        self.assertEqual(id(block.data), identity)
        self.assertEqual(block.data[:8], bytes.fromhex("6220f00102030405"))
        self.assertEqual(block.u32(0x1020), 8)
        self.assertEqual(block.data[0x1024], 0xAB)

    def test_frd5_start_retains_and_poll_releases_same_manager(self) -> None:
        comm = Comm(
            [
                literal("3101110602", "71011106"),
                literal("31031106", "7103110601"),
                literal("31031106", "7103110602"),
            ]
        )
        context = Context(comm)
        block = ty.TYRetainedBlock(bytearray(5))
        self.assertEqual(self.invoke(ty.FRD5, (block,), context), 0)
        self.assertNotIn("close", comm.events)
        block.put32(0, 1)
        self.assertEqual(self.invoke(ty.FRD5, (block,), context), 0)
        self.assertEqual(context.clock, 400)
        self.assertEqual(comm.events.count(("open", 0)), 1)
        self.assertEqual(comm.events[-1], "close")
        self.assertEqual(len(set(context.selectors)), 1)

    def test_frd5_ui_stop_is_re_read_after_wait(self) -> None:
        comm = Comm(
            [literal("31031106", "7103110601"), literal("3101110600", "71011106")]
        )
        context = Context(comm)
        block = ty.TYRetainedBlock(bytearray(5))
        block.put32(0, 1)
        context.sleep_hook = lambda ms: block.data.__setitem__(4, 1)
        self.assertEqual(self.invoke(ty.FRD5, (block,), context), 0)
        self.assertEqual(context.clock, 400)

    def test_frd5_native_fault_mappings(self) -> None:
        for stop, trace, expected in (
            (1, [literal("3101110600", status=7)], 1007),
            (0, [literal("31031106", status=7), literal("3101110600", status=8)], 1008),
            (0, [literal("31031106", "7103110603")], 1006),
            (
                0,
                [literal("31031106", "7103110609"), literal("3101110600", "71011106")],
                1006,
            ),
        ):
            comm = Comm(trace)
            block = ty.TYRetainedBlock(bytearray(5))
            block.put32(0, 1)
            block.data[4] = stop
            self.assertEqual(self.invoke(ty.FRD5, (block,), Context(comm)), expected)
            self.assertEqual(comm.events[-1], "close")

    def test_vcib5_two_support_masks(self) -> None:
        first = bytearray(32)
        first[2] = 0x80
        second = bytearray(32)
        second[3] = 8
        comm = Comm(
            [
                (b"\x22\x01\x01", 0, b"\x62\x01\x01" + first),
                (b"\x22\x10\x00", 0, b"\x62\x10\x00" + second),
            ]
        )
        self.assertEqual(
            self.invoke(ty.VCIB5, (ty.TYRetainedBlock(bytearray(20)),), Context(comm)),
            0,
        )
        self.assertEqual(Context(comm).mode, 20)

    def test_vcib5_copies_received_dwords_not_decompiler_zeroes(self) -> None:
        for sha, manager in (
            (SHA_18_TY, "native:1011e618"),
            (SHA_PLUS_TY, "native:10134b78"),
        ):
            payload = bytes(range(1, 17))
            comm = Comm([(b"\x22\x10\x1d", 0, b"\x62\x10\x1d" + payload)])
            context = Context(comm, sha)
            block = ty.TYRetainedBlock(bytearray(20))
            block.put32(0, 1)
            self.assertEqual(self.invoke(ty.VCIB5, (block,), context), 0)
            self.assertEqual(block.data[4:], payload)
            self.assertEqual(context.selectors, [manager])

    def test_vcib5_short_reply_leaves_output_untouched(self) -> None:
        block = ty.TYRetainedBlock(bytearray(b"\x01\x00\x00\x00" + b"x" * 16))
        comm = Comm([literal("22101d", "62101d0102")])
        self.assertEqual(self.invoke(ty.VCIB5, (block,), Context(comm)), 3)
        self.assertEqual(block.data[4:], b"x" * 16)

    def test_fas_start_retains_then_result_releases(self) -> None:
        comm = Comm(
            [literal("31011102", "71011102"), literal("31031102", "7103110202")]
        )
        context = Context(comm)
        block = ty.TYRetainedBlock(bytearray(12))
        block.put32(0, 1)
        self.assertEqual(self.invoke(ty.FAS, (block,), context), 0)
        self.assertNotIn("close", comm.events)
        block.put32(0, 2)
        self.assertEqual(self.invoke(ty.FAS, (block,), context), 0)
        self.assertEqual(comm.events[-1], "close")

    def test_fas_secondary_did_result_keeps_native_esi(self) -> None:
        block = ty.TYRetainedBlock(bytearray(12))
        block.put32(0, 2)
        comm = Comm(
            [
                literal("31031102", "7103110203"),
                literal("221002", "62100200"),
                literal("221003", "621003fc04"),
            ]
        )
        self.assertEqual(self.invoke(ty.FAS, (block,), Context(comm)), 2000)
        self.assertEqual(block.data[4], 4)

    def test_frd1_three_build_start_and_result_lifecycle(self) -> None:
        for sha in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY):
            comm = Comm(
                [
                    literal("3101110105", "71011101"),
                    literal("31031101", "7103110101"),
                    literal("31031101", "7103110103"),
                    literal("221005", "62100538"),
                ]
            )
            context = Context(comm, sha)
            block = ty.TYRetainedBlock(bytearray(12))
            self.assertEqual(self.invoke(ty.FRD1, (block,), context), 1007)
            self.assertNotIn("close", comm.events)
            block.put32(4, 1)
            self.assertEqual(self.invoke(ty.FRD1, (block,), context), 1006)
            self.assertEqual(block.data[0], 7)
            self.assertEqual(comm.events[-1], "close")
            self.assertEqual(context.clock, 1100)

    def test_frd1_nrc_and_restore_precedence(self) -> None:
        comm = Comm([literal("3101110105", "7f3122", 26)])
        comm.sessions.extend((0, 17))
        self.assertEqual(
            self.invoke(ty.FRD1, (ty.TYRetainedBlock(bytearray(12)),), Context(comm)),
            17,
        )

    def test_dp2_active_literal_three_versions(self) -> None:
        for sha in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY):
            block = ty.TYRetainedBlock(bytearray(20))
            for offset, value in ((0, 6), (4, 4), (8, 2), (12, 3)):
                block.put32(offset, value)
            comm = Comm(
                [
                    literal("3028ff11", "7028"),
                    literal("2128", "612811000000"),
                    literal("30", status=7),
                ]
            )
            self.assertEqual(
                self.invoke(ty.DP2_13_ACTIVE, (block,), Context(comm, sha, 4)), 0
            )
            self.assertEqual(block.data[16:20], bytes.fromhex("11000000"))
            self.assertFalse(comm.trace)

    def test_dp2_active_native_fault_and_cancel_cleanup(self) -> None:
        block = ty.TYRetainedBlock(bytearray(20))
        for offset, value in ((0, 6), (4, 4), (8, 2), (12, 3)):
            block.put32(offset, value)
        comm = Comm(
            [
                literal("3028ff11", "7028"),
                literal("2128", "612800000008"),
                literal("30"),
            ]
        )
        self.assertEqual(
            self.invoke(ty.DP2_13_ACTIVE, (block,), Context(comm, mode=4)), 9002
        )
        comm = Comm([literal("3028ff11", "7028"), literal("30")])
        context = Context(comm, mode=4)
        context.sleep_hook = lambda ms: setattr(context, "cancelled", True)
        with self.assertRaises(Cancelled):
            self.invoke(ty.DP2_13_ACTIVE, (block,), context)
        self.assertEqual(comm.events[-1], "close")

    def test_dp2_support_real_snapshot_packing(self) -> None:
        raw = bytearray(0x1020)
        raw[:11] = bytes((0x28, 9, 1, 255, 0, 1, 0, 1, 127, 127, 248))
        offsets = [0x1020] * 256
        offsets[0x28] = 0
        second = bytearray(0x1020)
        second[:4] = bytes((0x28, 2, 255, 1))
        for sha in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY):
            comm = Comm()
            comm.snapshots.extend(
                ((0, bytes(raw), tuple(offsets)), (0, bytes(second), tuple(offsets)))
            )
            block = ty.TYRetainedBlock(bytearray(16))
            self.assertEqual(
                self.invoke(ty.DP2_13_SUPPORT, (block,), Context(comm, sha, 4)), 0
            )
            self.assertEqual(
                [block.u32(offset) for offset in (0, 4, 8, 12)], [9, 5, 3, 6]
            )

    def test_dp2_14_native_read_and_seven_row_additive_command(self) -> None:
        block = ty.TYRetainedBlock(bytearray(0x10F0))
        block.put32(0, 2)
        block.put32(0x102C, 1)
        comm = Comm([literal("2103", "61038102")])
        self.assertEqual(self.invoke(ty.DP2_14, (block,), Context(comm, mode=4)), 0)
        self.assertEqual(block.data[4:6], bytes.fromhex("8102"))
        block.put32(0x102C, 2)
        block.put32(0x1024, 2)
        for index, weight in ((0, 4), (1, 8)):
            row = 0x1030 + 28 * index
            for offset, value in (
                (0, 0),
                (4, 0x80),
                (8, 1),
                (12, 1),
                (16, weight),
                (20, 1),
            ):
                block.put32(row + offset, value)
        comm = Comm([literal("3b02000c", "7b02")])
        self.assertEqual(self.invoke(ty.DP2_14, (block,), Context(comm, mode=4)), 0)

    def test_frd2_get_setting_copies_exact_variable_data(self) -> None:
        for sha in (SHA_18_TY, SHA_PLUS_TY):
            comm = Comm([literal("222093", "622093010203")])
            block = ty.TYRetainedBlock(bytearray(0x1030))
            block.put32(0, 1)
            self.assertEqual(ty._frd2(block, Context(comm, sha)), 0)  # type: ignore[arg-type]
            self.assertEqual(block.u32(12), 3)
            self.assertEqual(block.data[16:19], bytes.fromhex("010203"))
            self.assertIn(("parameter", 0xAB, 15), comm.events)
            self.assertIn(("target", (0x750, 15, 0, 0, 0)), comm.events)
            self.assertEqual(comm.events[-1], "close")

    def test_frd2_write_compare_and_optional_restart(self) -> None:
        comm = Comm(
            [
                literal("2e20930182", "6e2093"),
                literal("222093", "6220930182"),
                literal("310111ff", "710111ff"),
                literal("310311ff", "710311ff01"),
                literal("310311ff", "710311ff02"),
            ]
        )
        block = ty.TYRetainedBlock(bytearray(0x1030))
        for offset, value in ((0, 2), (4, 1), (8, 0x80000000), (12, 2)):
            block.put32(offset, value)
        block.data[16:18] = bytes((1, 2))
        context = Context(comm)
        self.assertEqual(ty._frd2(block, context), 0)  # type: ignore[arg-type]
        self.assertEqual(comm.events.count("close"), 2)
        self.assertEqual(context.clock, 600)
        self.assertEqual(context.selectors, ["native:1011d4f0", "native:1011c400"])

    def test_vcib3_retains_action3_then_action2_uses_two_zero_bytes(self) -> None:
        comm = Comm(
            [
                literal("310111080000", "71011108"),
                literal("31031108", "7103110802"),
                literal("31031108", "7103110801"),
            ]
        )
        context = Context(comm)
        block = ty.TYRetainedBlock(bytearray(8))
        block.put32(0, 3)
        self.assertEqual(ty._vcib3(comm, block, context), 0)  # type: ignore[arg-type]
        self.assertNotIn("close", comm.events)
        block.put32(0, 2)
        self.assertEqual(ty._vcib3(comm, block, context), 0)  # type: ignore[arg-type]
        self.assertEqual(context.clock, 200)
        self.assertEqual(comm.events.count(("open", 0)), 1)
        self.assertEqual(comm.events[-1], "close")

    def test_vcib3_native_failure_mapping(self) -> None:
        comm = Comm([literal("31011107", status=7)])
        block = ty.TYRetainedBlock(bytearray(8))
        block.put32(0, 1)
        self.assertEqual(ty._vcib3(comm, block, Context(comm)), 2001)  # type: ignore[arg-type]
        self.assertEqual(comm.events[-1], "close")

    def test_dp2_probe_four_absent_targets_restores_both_globals(self) -> None:
        comm = Comm([literal("3e00", status=7)] * 4)
        block = ty.TYRetainedBlock(bytearray(64))
        self.assertEqual(ty._dp2_probe(comm, block, False), 0)  # type: ignore[arg-type]
        targets = [
            event
            for event in comm.events
            if isinstance(event, tuple) and event[0] == "target"
        ]
        self.assertEqual(
            targets,
            [("target", (0x750, value, 0, 0, 0)) for value in (0x41, 0x42, 0x81, 0x82)]
            + [("target", (0x700, 0, 0, 0, 0))],
        )
        self.assertEqual(comm.events[-1], ("protocol", 16))
        self.assertEqual(comm.events.count("close"), 4)
        self.assertEqual(block.data[32:52], bytes(20))

    def test_dp2_did_native_sentinel_and_support_flags(self) -> None:
        bitmap = bytearray(32)
        bitmap[2] = 0x80
        mode = bytearray(32)
        mode[0] = 0x60
        for twelve in (False, True):
            comm = Comm(
                [
                    (b"\x22\x01\x01", 0, b"\x62\x01\x01" + bitmap),
                    (b"\x22\x10\x00", 0, b"\x62\x10\x00" + mode),
                    literal("221002", "62100220"),
                    literal("221003", "6210030040"),
                ]
            )
            block = ty.TYRetainedBlock(bytearray(64))
            offset = 36 if twelve else 24
            flags = 32 if twelve else 19
            block.put32(offset, 10011)
            self.assertEqual(ty._dp2_did(comm, block, twelve), 10012)  # type: ignore[arg-type]
            self.assertEqual(block.u32(offset), 10012)
            self.assertEqual(block.data[flags : flags + 2], b"\x01\x01")
            count = len(comm.events)
            self.assertEqual(ty._dp2_did(comm, block, twelve), 10012)  # type: ignore[arg-type]
            self.assertEqual(len(comm.events), count)

    def test_actual97_aggregator_consumer_preserves_native_block(self) -> None:
        from scripts.utility_ex_ty import run_body as selected_run_body
        from scripts.utility_ex_ty import supported_exports

        comm = Comm(
            [literal("3101110602", "71011106"), literal("31031106", "7103110602")]
        )
        context = Context(comm)
        block = ty.TYRetainedBlock(bytearray(5))
        with patch.object(ty.hashlib, "sha256") as digest:
            digest.return_value.hexdigest.return_value = SHA_18_TY
            self.assertIn(ty.FRD5, supported_exports(SHA_18_TY))
            self.assertEqual(selected_run_body(ty.FRD5, (block,), context), 0)  # type: ignore[arg-type]
            block.put32(0, 1)
            self.assertEqual(selected_run_body(ty.FRD5, (block,), context), 0)  # type: ignore[arg-type]
        self.assertEqual(context.selectors, ["native:1011d4f0"] * 2)
        self.assertFalse(comm.trace)

    def test_dp2_front_uds_real_angle_and_version_sleep_delta(self) -> None:
        for sha, expected_ms in (
            (SHA_12_TY, 400),
            (SHA_18_TY, 1100),
            (SHA_PLUS_TY, 1100),
        ):
            comm = Comm(
                [
                    literal("3101110103", "71011101"),
                    literal("31031101", "7103110103"),
                    literal("221005", "62100538"),
                ]
            )
            block = ty.TYRetainedBlock(bytearray(44))
            context = Context(comm, sha)
            context.sleep_hook = lambda ms, block=block: block.data.__setitem__(
                17, 0xF2
            )
            self.assertEqual(ty._dp2_front_uds(comm, block, context), 9000)  # type: ignore[arg-type]
            self.assertEqual(block.data[16], 7)
            self.assertEqual(context.clock, expected_ms)

    def test_dp2_active_start_result_retains_actual_manager(self) -> None:
        for sha in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY):
            comm = Comm(
                [
                    literal("3101110104", "71011101"),
                    literal("31031101", "7103110102"),
                    literal("22100d", "62100d1234"),
                ]
            )
            block = ty.TYRetainedBlock(bytearray(44))
            context = Context(comm, sha)
            self.assertEqual(ty._dp2_active_uds(comm, block, context), 10008)  # type: ignore[arg-type]
            self.assertNotIn("close", comm.events)
            block.put32(24, 1)
            self.assertEqual(ty._dp2_active_uds(comm, block, context), 0)  # type: ignore[arg-type]
            self.assertEqual(block.data[21:23], bytes.fromhex("1234"))
            self.assertEqual(comm.events[-1], "close")
            self.assertEqual(comm.events.count(("open", 0)), 1)

    def test_dp2_classic_front_two_phase_state(self) -> None:
        block = ty.TYRetainedBlock(bytearray(20))
        for offset, value in ((0, 2), (4, 3), (8, 2), (12, 1)):
            block.put32(offset, value)
        comm = Comm(
            [
                literal("3028ff08", "7028"),
                literal("2128", "61280040"),
                literal("2128", "61280000"),
                literal("30"),
            ]
        )
        context = Context(comm, mode=4)
        self.assertEqual(ty._dp2_front_classic(comm, block, context), 0)  # type: ignore[arg-type]
        self.assertEqual(context.clock, 1100)

    def test_dp2_native_option_and_pending_stop(self) -> None:
        block = ty.TYRetainedBlock(bytearray(44))
        block.put32(36, 10012)
        block.put32(40, 1)
        block.data[32:34] = b"\x01\x01"
        self.assertEqual(ty._dp2_option(block, True), 12)
        block.put32(28, 1)
        comm = Comm([literal("31031101", "7103110101")])
        self.assertEqual(ty._dp2_poll(comm, Context(comm), block, active=True), 10009)  # type: ignore[arg-type]

    def test_native_result_publication_follows_cleanup_and_skips_inline(self) -> None:
        for sha, address in (
            (SHA_12_TY, "100ab770"),
            (SHA_18_TY, "10118e38"),
            (SHA_PLUS_TY, "10134ab8"),
        ):
            comm = Comm([literal("3b2301", "7b23")])
            context = Context(comm, sha, 4)
            key = "native_global:" + address
            context.state[key] = 1234
            observed: list[object] = []
            with patch.object(
                comm,
                "finalize",
                side_effect=lambda observed=observed, context=context, key=key: (
                    observed.append(context.state[key])
                ),
            ):
                self.assertEqual(self.invoke(ty.EVB, (), context), 0)
            self.assertEqual(observed, [1234])
            self.assertEqual(context.state[key], 0)
            context.mode = 21
            self.assertEqual(self.invoke(ty.EVB, (), context), 99)
            self.assertEqual(context.state[key], 0)
        context = Context(Comm(), SHA_12_TY, 20)
        context.state["native_global:100ab770"] = 1234
        self.assertEqual(self.invoke(ty.DP2_11_SUPPORT, (), context), 0)
        self.assertEqual(context.state["native_global:100ab770"], 1234)
        self.assertEqual(context.selectors, [])

    def test_bsm_target_enable_native_outcome_restore_both_builds(self) -> None:
        for sha in (SHA_18_TY, SHA_PLUS_TY):
            comm = Comm(
                [
                    literal("222055", "6220550000"),
                    literal("2e20550001", "6e2055"),
                    literal("222055", "6220550001"),
                    literal("3101110103", "71011101"),
                    literal("31031101", "7103110103"),
                    literal("221005", "62100538"),
                    literal("222055", "6220550001"),
                    literal("2e20550000", "6e2055"),
                    literal("222055", "6220550000"),
                ]
            )
            block = ty.TYRetainedBlock(bytearray(84))
            block.put32(36, 1)
            context = Context(comm, sha)
            context.sleep_hook = lambda ms, block=block: block.data.__setitem__(
                17, 0xF2
            )
            self.assertEqual(ty._dp2_bsm(comm, block, context), 9000)  # type: ignore[arg-type]
            self.assertEqual(block.data[16], 7)
            self.assertEqual(
                [block.u32(offset) for offset in (52, 56, 60, 64)], [1, 1, 9000, 0]
            )
            self.assertFalse(comm.trace)
            self.assertEqual(context.clock, 1100)

    def test_dealership_offset_start_retains_enable_then_result_restores(self) -> None:
        comm = Comm(
            [
                literal("222055", "6220550000"),
                literal("2e20550001", "6e2055"),
                literal("222055", "6220550001"),
                literal("3101110104", "71011101"),
                literal("31031101", "7103110102"),
                literal("22100d", "62100d1234"),
                literal("222055", "6220550001"),
                literal("2e20550000", "6e2055"),
                literal("222055", "6220550000"),
            ]
        )
        block = ty.TYRetainedBlock(bytearray(84))
        block.put32(48, 1)
        context = Context(comm)
        self.assertEqual(ty._dp2_offset(comm, block, context), 10008)  # type: ignore[arg-type]
        self.assertEqual(comm.events.count("close"), 1)
        block.put32(24, 1)
        self.assertEqual(ty._dp2_offset(comm, block, context), 0)  # type: ignore[arg-type]
        self.assertEqual(block.data[21:23], bytes.fromhex("1234"))
        self.assertEqual(
            [block.u32(offset) for offset in (64, 68, 76, 80)], [1, 1, 0, 0]
        )
        self.assertFalse(comm.trace)
        self.assertEqual(comm.events.count("close"), 3)

    def test_radar_restore_fault_precedence_and_empty_selection(self) -> None:
        block = ty.TYRetainedBlock(bytearray(84))
        comm = Comm()
        with self.assertRaises(ValueError):
            ty._dp2_targets(comm, block, active=False, enable=True)  # type: ignore[arg-type]
        block.put32(36, 1)
        comm = Comm([literal("222055", status=7)])
        self.assertEqual(
            ty._dp2_targets(comm, block, active=False, enable=False),  # type: ignore[arg-type]
            10016,
        )
        block.put32(52, 1)
        block.put32(56, 1)
        block.put32(60, 9000)
        comm = Comm([literal("222055", status=7)])
        self.assertEqual(ty._dp2_targets(comm, block, active=False, enable=False), 7)  # type: ignore[arg-type]

    def test_vcib_event_full_start_transfer_archive_cleanup_both_sources(self) -> None:
        for sha in (SHA_18_TY, SHA_PLUS_TY):
            host = VCIBFiles()
            block = vcib_block(sha, host)
            layout = ty._VCIB_LAYOUTS[sha]
            block.put32(layout.log_kind, 1)
            comm = Comm(
                [
                    literal("221b01", "621b0101"),
                    literal("221a01", "621a0101"),
                    literal("221a02", "621a024142"),
                    literal("221b02", "621b024344"),
                ]
            )
            context = Context(comm, sha)
            controller = ty._VCIB(block, context, comm)  # type: ignore[arg-type]
            for action in (1, 2):
                block.put32(0, action)
                self.assertEqual(controller.run(), 0)
            self.assertNotIn("close", comm.events)
            self.assertEqual(
                len(host.files(controller.path(layout.directory), ".dat")), 2
            )
            block.put32(0, 6)
            self.assertEqual(controller.run(), 0)
            self.assertEqual(comm.events[-1], "close")
            archives = [
                value for key, value in host.data.items() if key.endswith(".zip")
            ]
            self.assertEqual(len(archives), 1)
            with zipfile.ZipFile(io.BytesIO(archives[0])) as archive:
                self.assertEqual(
                    {name: archive.read(name) for name in archive.namelist()},
                    {
                        "20261020123456_1A02.dat": b"AB",
                        "20261020123456_1B02.dat": b"CD",
                    },
                )
            self.assertEqual(host.files(controller.path(layout.directory), ".dat"), ())
            self.assertEqual(host.allocations, set())
            self.assertEqual(context.clock, 0 if sha == SHA_PLUS_TY else 800)

    def test_vcib_date_table_rejects_calendar_fault_and_preserves_bcd_semantics(
        self,
    ) -> None:
        for sha in (SHA_18_TY, SHA_PLUS_TY):
            host = VCIBFiles()
            block = vcib_block(sha, host)
            layout = ty._VCIB_LAYOUTS[sha]
            payload = bytearray(6000)
            payload[:18] = bytes.fromhex("260228123456260230123456260c31120000")
            comm = Comm(
                [(bytes.fromhex("221c01"), 0, bytes.fromhex("621c01") + payload)]
            )
            context = Context(comm, sha)
            controller = ty._VCIB(block, context, comm)  # type: ignore[arg-type]
            block.put32(0, 3)
            self.assertEqual(controller.run(), 0)
            self.assertEqual(block.u32(layout.count), 2)
            self.assertEqual(
                block.data[layout.flags : layout.flags + 3], b"\x01\x00\x01"
            )
            self.assertEqual(
                block.data[layout.dates : layout.dates + 6],
                bytes((26, 2, 28, 12, 34, 56)),
            )
            self.assertEqual(host.allocations, set())

    def test_vcib_trace_identifier_boundary_map_and_selected1001_count(self) -> None:
        host = VCIBFiles()
        block = vcib_block(SHA_PLUS_TY, host)
        layout = ty._VCIB_LAYOUTS[SHA_PLUS_TY]
        for index in (0, 254, 509, 764, 1000):
            block.data[layout.selected + index] = 1
        identifiers = (0x1C02, 0x1D01, 0x1E01, 0x1F01)
        comm = Comm(
            [
                (
                    b"\x22" + value.to_bytes(2, "big"),
                    0,
                    b"\x62" + value.to_bytes(2, "big") + b"x",
                )
                for value in identifiers
            ]
        )
        controller = ty._VCIB(block, Context(comm, SHA_PLUS_TY), comm)  # type: ignore[arg-type]
        block.put32(0, 5)
        self.assertEqual(controller.run(), 0)
        self.assertEqual(
            int.from_bytes(block.data[layout.total : layout.total + 2], "little"), 5
        )
        block.put32(0, 4)
        self.assertEqual(controller.run(), 0)
        self.assertFalse(comm.trace)
        self.assertEqual(len(host.files(controller.path(layout.directory), ".tgz")), 4)
        block.put32(0, 6)
        self.assertEqual(controller.run(), 0)
        self.assertEqual(len(host.files(controller.path(layout.directory), ".tgz")), 0)

    def test_vcib_native_disk_threshold_allocation_and_shell_timeout(self) -> None:
        host = VCIBFiles()
        block = vcib_block(SHA_18_TY, host)
        comm = Comm()
        context = Context(comm)
        controller = ty._VCIB(block, context, comm)  # type: ignore[arg-type]
        controller.stamp()
        host.write_failures = 1
        host.free = 2
        self.assertEqual(controller.store(0x1A02, b"xx", 4), 2004)
        host.allocation_fail = True
        self.assertEqual(controller.fetch(0x1A02, 1, 1), (3, b""))
        self.assertEqual(comm.events, [])
        host.allocation_fail = False
        host.free = 10000
        host.count_stuck = True
        block.put32(0, 2)
        block.put32(controller.layout.log_kind, 1)
        self.assertTrue(controller.write_file(0x1A02, b"data"))
        self.assertEqual(controller.archive18(), 2001)
        self.assertEqual(context.clock, 2400)
        self.assertEqual(host.shell_flags, [0x414])
        self.assertFalse(any(path.endswith(".zip") for path in host.data))

    def test_vcib_missing_host_and_failed_empty_zip_fail_closed(self) -> None:
        with self.assertRaises(TypeError):
            ty.VCIBBlock(bytearray(9000), None)  # type: ignore[arg-type]
        host = VCIBFiles()
        block = vcib_block(SHA_18_TY, host)
        controller = ty._VCIB(block, Context(Comm()), Comm())  # type: ignore[arg-type]
        controller.stamp()
        block.put32(controller.layout.log_kind, 1)
        host.write_failures = 1
        self.assertEqual(controller.archive18(), 2001)
        self.assertEqual(len(host.deleted), 1)
        self.assertFalse(any(path.endswith(".zip") for path in host.data))

    def test_vcib_managed_zip_three_retries_delete_partial_archives(self) -> None:
        host = VCIBFiles()
        block = vcib_block(SHA_PLUS_TY, host)
        controller = ty._VCIB(block, Context(Comm(), SHA_PLUS_TY), Comm())  # type: ignore[arg-type]
        controller.stamp()
        block.put32(0, 2)
        block.put32(controller.layout.log_kind, 1)
        self.assertTrue(controller.write_file(0x1A02, b"payload"))
        host.zip_failures = 2
        self.assertEqual(controller.archive_plus(), 0)
        self.assertEqual(len(host.deleted), 2)
        archives = [value for path, value in host.data.items() if path.endswith(".zip")]
        with zipfile.ZipFile(io.BytesIO(archives[0])) as archive:
            self.assertEqual(archive.read("20261020123456_1A02.dat"), b"payload")
        host.free = 6
        self.assertEqual(controller.archive_plus(), 2004)

    def test_host_cancel_pending_continuation_preserves_ui_flag_and_closes(
        self,
    ) -> None:
        comm = Comm([literal("31031101", "7103110101")])
        context = Context(comm)
        block = ty.TYRetainedBlock(bytearray(44))
        block.put32(24, 1)
        context.sleep_hook = lambda ms: setattr(context, "cancelled", True)
        with (
            patch.object(context, "native_sleep", side_effect=context.sleep),
            self.assertRaises(Cancelled),
        ):
            ty._dp2_active_uds(comm, block, context)  # type: ignore[arg-type]
        self.assertEqual(block.u32(28), 0)
        self.assertEqual(comm.events[-1], "close")
        self.assertFalse(comm.trace)

    def test_vcib_support_bits_and_partial_primary_failure_contract(self) -> None:
        for sha in (SHA_18_TY, SHA_PLUS_TY):
            host = VCIBFiles()
            block = vcib_block(sha, host)
            layout = ty._VCIB_LAYOUTS[sha]
            values = []
            for identifier in (0x0101, 0x1A00, 0x1B00, 0x1C00):
                payload = bytearray(32)
                payload[3 if identifier == 0x0101 else 0] = (
                    0x38 if identifier == 0x0101 else 0x80
                )
                values.append(
                    (
                        b"\x22" + identifier.to_bytes(2, "big"),
                        0,
                        b"\x62" + identifier.to_bytes(2, "big") + payload,
                    )
                )
            comm = Comm(values)
            context = Context(comm, sha)
            controller = ty._VCIB(block, context, comm)  # type: ignore[arg-type]
            self.assertEqual(controller.run(), 0)
            self.assertFalse(comm.trace)
            block.data[layout.primary] = 2
            block.put32(0, 2)
            comm.trace.extend(
                [literal("221a02", "621a0278"), literal("221a03", status=7)]
            )
            controller.stamp()
            self.assertEqual(controller.primary(), 0)
            self.assertEqual(controller.get(4), 1)
            self.assertEqual(controller.get(7), 0)
            self.assertEqual(
                int.from_bytes(
                    block.data[layout.progress : layout.progress + 2], "little"
                ),
                2,
            )
            self.assertEqual(host.allocations, set())

    def test_vcib_enough_free_space_three_write_failures_and_uint32_total(self) -> None:
        host = VCIBFiles()
        block = vcib_block(SHA_18_TY, host)
        controller = ty._VCIB(block, Context(Comm()), Comm())  # type: ignore[arg-type]
        controller.stamp()
        host.write_failures = 3
        self.assertEqual(controller.store(0x1A02, b"payload", 4), 0)
        self.assertEqual(controller.get(4), 0)
        controller.put(0, 0xFFFFFFFF)
        self.assertEqual(controller.store(0x1A02, b"xx", 4), 0)
        self.assertEqual(controller.get(0), 1)

    def test_actual97_vcib_consumer_runs_all_three_lifecycle_exports(self) -> None:
        from scripts.utility_ex_ty import run_body as selected_run_body

        host = VCIBFiles()
        block = vcib_block(SHA_PLUS_TY, host)
        layout = ty._VCIB_LAYOUTS[SHA_PLUS_TY]
        block.put32(layout.log_kind, 1)
        comm = Comm(
            [
                literal("221b01", "621b0101"),
                literal("221a01", "621a0101"),
                literal("221a02", "621a0278"),
                literal("221b02", "621b0279"),
            ]
        )
        context = Context(comm, SHA_PLUS_TY)
        with patch.object(ty.hashlib, "sha256") as digest:
            digest.return_value.hexdigest.return_value = SHA_PLUS_TY
            for action in (1, 2, 6):
                block.put32(0, action)
                self.assertEqual(selected_run_body(ty.VCIB2, (block,), context), 0)  # type: ignore[arg-type]
        self.assertEqual(context.selectors, ["native:10134b78"] * 3)
        self.assertEqual(context.state["native_global:10134ab8"], 0)
        self.assertEqual(len([path for path in host.data if path.endswith(".zip")]), 1)
        self.assertFalse(comm.trace)

    def test_actual83_vcib18_and_plus_scheduler_admits_complete_lifecycle(self) -> None:
        from scripts.utility_ex import UtilityExContext, UtilityExEngine
        from tests.test_utility_ex import Host

        for sha, manager, result_global in (
            (SHA_18_TY, "native:1011e618", "native_global:10118e38"),
            (SHA_PLUS_TY, "native:10134b78", "native_global:10134ab8"),
        ):
            with self.subTest(source=sha):
                files = VCIBFiles()
                block = vcib_block(sha, files)
                block.put32(ty._VCIB_LAYOUTS[sha].log_kind, 1)
                comm = Comm(
                    [
                        literal("221b01", "621b0101"),
                        literal("221a01", "621a0101"),
                        literal("221a02", "621a0278"),
                        literal("221b02", "621b0279"),
                    ]
                )
                host = Host()
                host.values[0x6F] = 20
                with patch.object(ty.hashlib, "sha256") as digest:
                    digest.return_value.hexdigest.return_value = sha
                    context = UtilityExContext(
                        b"authored VCIB wrapper fixture", host, None, None
                    )
                    engine = UtilityExEngine(context)
                    with patch.object(context, "comm", return_value=comm) as selected:
                        for action in (1, 2, 6):
                            block.put32(0, action)
                            self.assertEqual(engine.invoke(ty.VCIB2, (block,)), 15)
                            self.assertEqual(engine.worker.get_status(), 0)
                        self.assertEqual(
                            [call.args for call in selected.call_args_list],
                            [(manager,)] * 3,
                        )
                    self.assertEqual(context.state[result_global], 0)
                self.assertFalse(comm.trace)
                self.assertEqual(len([p for p in files.data if p.endswith(".zip")]), 1)

    def test_actual83_selected_scheduler_and97_retained_consumer(self) -> None:
        from scripts.utility_ex import UtilityExContext, UtilityExEngine
        from tests.test_utility_ex import Host

        host = Host()
        host.values[0x6F] = 20
        comm = Comm(
            [literal("3101110602", "71011106"), literal("31031106", "7103110602")]
        )
        block = ty.TYRetainedBlock(bytearray(5))
        with patch.object(ty.hashlib, "sha256") as digest:
            digest.return_value.hexdigest.return_value = SHA_18_TY
            context = UtilityExContext(b"authored83-lifecycle-input", host, None, None)
            engine = UtilityExEngine(context)
            with patch.object(context, "comm", return_value=comm) as selected_comm:
                self.assertEqual(engine.invoke(ty.FRD5, (block,)), 15)
                self.assertEqual(engine.worker.get_status(), 0)
                self.assertNotIn("close", comm.events)
                block.put32(0, 1)
                self.assertEqual(engine.invoke(ty.FRD5, (block,)), 15)
                self.assertEqual(engine.worker.get_status(), 0)
                self.assertEqual(
                    selected_comm.call_args_list[0].args, ("native:1011d4f0",)
                )
                self.assertEqual(
                    selected_comm.call_args_list[1].args, ("native:1011d4f0",)
                )
            self.assertEqual(context.state["native_global:10118e38"], 0)
        self.assertFalse(comm.trace)
        self.assertEqual(comm.events[-1], "close")

    def test_actual83_97_108_132_retained_pair_reaches_raw_sdk(self) -> None:
        from scripts.j2534_2026 import NativeMessage, PrimitiveResult
        from scripts.utility_ex import UtilityExContext, UtilityExEngine
        from tests.test_utility_ex import Host

        host = Host()
        host.values.update({0x6F: 20, 0x70: 0x12, 0x74: 0x7E0})
        host.data[500] = bytes.fromhex("0100000020a10700")
        calls: list[object] = []
        filters = iter((51, 52))
        # The native session3 helper starts its real keepalive worker, which
        # sends 3e00 concurrently. Answer each thread's own request instead of
        # sharing one reply iterator between the worker and the caller.
        requests = threading.local()

        def connect(protocol: int, flags: int, output: bytearray) -> PrimitiveResult:
            calls.append(("connect", protocol, flags))
            output[:] = (42).to_bytes(4, "little")
            return PrimitiveResult()

        def start_filter(*args: Any) -> PrimitiveResult:
            args[-1][:] = next(filters).to_bytes(4, "little")
            return PrimitiveResult()

        def write(
            channel: int, messages: Any, count: Any, timeout: int
        ) -> PrimitiveResult:
            payload = messages[0].data
            calls.append(payload)
            request = payload[4:]
            seen = getattr(requests, "seen", None)
            if seen is None:
                seen = requests.seen = {}
            seen[request] = seen.get(request, 0) + 1
            requests.last = request
            return PrimitiveResult()

        def read(
            channel: int, messages: Any, count: Any, timeout: int
        ) -> PrimitiveResult:
            request = getattr(requests, "last", None)
            if request == b"\x3e\x00":
                reply = b"\x7e\x00"
            elif request == b"\x10\x01":
                reply = b"\x50\x01"
            elif request == b"\x10\x03":
                reply = b"\x50\x03"
            elif request == b"\x31\x01\x11\x06\x02":
                reply = b"\x71\x01\x11\x06"
            elif request == b"\x31\x03\x11\x06":
                count = requests.seen[request]
                reply = b"\x71\x03\x11\x06" + (b"\x01" if count == 1 else b"\x02")
            else:
                raise AssertionError(
                    f"read without a matching native request: {request!r}"
                )
            messages[0] = NativeMessage(6, bytes.fromhex("000007e8") + reply)
            return PrimitiveResult()

        names = (
            "PassThruConnect",
            "PassThruOemConnect",
            "PassThruDisconnect",
            "PassThruIoctl",
            "PassThruGetLastError",
            "PassThruWriteMsgs",
            "PassThruReadMsgs",
            "PassThruStartPeriodicMsg",
            "PassThruStopPeriodicMsg",
            "PassThruStartMsgFilter",
            "PassThruStopMsgFilter",
            "PassThruSetProgrammingVoltage",
            "PassThruReadVersion",
            "J2534CtrlInitialize",
            "J2534CtrlFinalize",
        )
        exports: dict[str, Any] = dict.fromkeys(names, lambda *args: PrimitiveResult())
        exports.update(
            {
                "PassThruConnect": connect,
                "PassThruStartMsgFilter": start_filter,
                "PassThruWriteMsgs": write,
                "PassThruReadMsgs": read,
                "PassThruDisconnect": lambda channel: (
                    calls.append(("disconnect", channel)),
                    PrimitiveResult(),
                )[1],
            }
        )
        with patch.object(ty.hashlib, "sha256") as digest:
            digest.return_value.hexdigest.return_value = SHA_18_TY
            context = UtilityExContext(
                b"authored raw SDK fixture", host, None, None, driver_exports=exports
            )
            engine = UtilityExEngine(context)
            block = ty.TYRetainedBlock(bytearray(5))
            self.assertEqual(engine.invoke(ty.FRD5, (block,)), 15)
            self.assertEqual(engine.worker.get_status(), 0)
            self.assertNotIn(("disconnect", 42), calls)
            block.put32(0, 1)
            self.assertEqual(engine.invoke(ty.FRD5, (block,)), 15)
            self.assertEqual(engine.worker.get_status(), 0)
            self.assertEqual(context.state["native_global:10118e38"], 0)
        self.assertEqual(calls[0], ("connect", 6, 0))
        self.assertEqual(calls[-1], ("disconnect", 42))
        self.assertEqual(
            [
                value
                for value in calls
                if isinstance(value, bytes) and value[4:] != bytes.fromhex("3e00")
            ],
            [
                bytes.fromhex("000007e0" + value)
                for value in (
                    "1001",
                    "1003",
                    "3101110602",
                    "31031106",
                    "31031106",
                    "1001",
                )
            ],
        )

    def test_exact51_public_pairs_and_unknown_build_never_advertised(self) -> None:
        self.assertEqual(len(ty.supported_exports(SHA_12_TY)), 9)
        for sha in (SHA_18_TY, SHA_PLUS_TY):
            exports = ty.supported_exports(sha)
            self.assertEqual(len(exports), 21)
            self.assertIn(ty.VCIB2, exports)
            self.assertNotIn("Ex2VCIB_99_Invented", exports)


if __name__ == "__main__":
    unittest.main()
