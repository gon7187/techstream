"""Authored retained TY wire/UI traces; no OEM execution or vehicle fixtures."""

from __future__ import annotations

import hashlib
import struct
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from scripts import utility_ex_ty_retained_03 as native
from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import TYSourceError

AUTHORED = b"authored retained TY offline module"
SYNTHETIC_SHA = hashlib.sha256(AUTHORED).hexdigest()


class Comm:
    def __init__(self) -> None:
        self.events: list[object] = []
        self.frames: list[tuple[bytes, int, bytes] | BaseException] = []
        self.initial_status = 0
        self.native_error = 0
        self.snapshots: list[tuple[int, bytes, tuple[int, ...]]] = []

    def initialize(self, mode: int = 0) -> int:
        self.events.append(("init", mode))
        return self.initial_status

    def finalize(self) -> None:
        self.events.append("close")

    def exchange(self, request: bytes) -> tuple[int, bytes]:
        self.events.append(request)
        item = self.frames.pop(0)
        if isinstance(item, BaseException):
            raise item
        expected, status, response = item
        if request != expected:
            raise AssertionError((request, expected))
        return status, response

    def configure(self, field: str, value: int) -> None:
        self.events.append((field, value))

    def configure_target(
        self,
        first: int,
        second: int = 0,
        third: int = 0,
        fourth: int = 0,
        fifth: int = 0,
    ) -> None:
        self.events.append(("target", first, second, third, fourth, fifth))

    def select_target(self, identifier: int, second: int = 0) -> None:
        self.events.append(("select", identifier, second))

    def select_protocol(self, kind: int) -> int:
        raise AssertionError(kind)

    def read_target(self) -> tuple[int, int]:
        raise AssertionError("read target")

    def read_dtcs(self, mode: int = 0x80, capacity: int = 0x1000) -> tuple[int, bytes]:
        raise AssertionError("read dtcs")

    def session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int:
        self.events.append(("session", mode, keepalive))
        return 0

    def configure_keepalive(
        self, interval_ms: int, request: bytes, response_size: int, flags: int
    ) -> None:
        self.events.append(
            ("keepalive_setup", interval_ms, request, response_size, flags)
        )

    def keepalive(self, enabled: bool, wait: bool = False) -> int:
        self.events.append(("keepalive", enabled, wait))
        return 0

    def read_field(self, field: str) -> int:
        self.events.append(("field", field))
        return self.native_error

    def support_snapshot(self, kind: int) -> tuple[int, bytes, tuple[int, ...]]:
        self.events.append(("snapshot", kind))
        return self.snapshots.pop(0)


class Context:
    def __init__(self, sha: str = SYNTHETIC_SHA) -> None:
        self.module_sha256, self.module_bytes = sha, AUTHORED
        self.state: dict[str, object] = {}
        self.managers: dict[str, Comm] = {}
        self.cancelled = False
        self.time = 0
        self.sleeps: list[int] = []
        self.mode = 3

    def comm(self, kind: str) -> Comm:
        return self.managers.setdefault(kind, Comm())

    def is_cancelled(self) -> bool:
        return self.cancelled

    def sleep(self, ms: int) -> None:
        self.sleeps.append(ms)
        self.time += ms

    def native_sleep(self, milliseconds: int) -> None:
        self.sleep(milliseconds)

    def ticks(self) -> int:
        return self.time

    def set_parameter(self, key: int, value: int) -> int:
        raise AssertionError("broker mutation")

    def write_parameters(self) -> int:
        raise AssertionError("broker write")

    def refresh_parameters(self) -> None:
        raise AssertionError("broker refresh")


def dword(data: bytearray, offset: int, value: int | None = None) -> int:
    if value is not None:
        struct.pack_into("<I", data, offset, value)
    return struct.unpack_from("<I", data, offset)[0]


class RetainedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(native, "SHA_18_TY", SYNTHETIC_SHA))
        self.ctx = Context()
        self.comm = self.ctx.comm("selected")
        self.buffer = bytearray(0x204C)

    def run_export(self, export: str) -> int:
        return native.run_body(export, (self.buffer,), self.ctx)

    def frame(
        self, request: bytes, reply: bytes, status: int = 0, comm: Comm | None = None
    ) -> None:
        (comm or self.comm).frames.append((request, status, reply))

    def exit_frame(self) -> None:
        self.frame(b"\x82", b"", 77)

    def plus_image(self) -> Comm:
        image = bytearray(0xE2000)
        struct.pack_into("<I", image, 0x3C, 0x80)
        struct.pack_into("<H", image, 0x86, 1)
        struct.pack_into("<H", image, 0x94, 0)
        struct.pack_into("<IIII", image, 0x98 + 8, len(image), 0, len(image), 0)
        image[0xE0CB0:0xE0CB9] = b"AUTHORED\0"
        struct.pack_into("<III", image, 0xE0CCC, 8, 0, 0)
        self.ctx.module_bytes = bytes(image)
        self.ctx.module_sha256 = hashlib.sha256(image).hexdigest()
        self.stack.enter_context(
            patch.object(native, "SHA_PLUS_TY", self.ctx.module_sha256)
        )
        return self.ctx.comm("native:101392d0")

    def begin_frames(self, comm: Comm) -> None:
        self.frame(b"\x22\x10\x10", b"\x62\x10\x10AUTHORED\0", comm=comm)
        self.frame(b"\x27\x11", b"\x67\x11" + bytes(16), comm=comm)

    def test_exact_pair_union_and_unknown_sources(self) -> None:
        # Original exact identities, independent of authored context identity.
        from scripts.utility_ex_ty import SHA_12_TY, SHA_18_TY, SHA_PLUS_TY

        with patch.object(native, "SHA_18_TY", SHA_18_TY):
            self.assertEqual(
                sum(
                    len(native.supported_exports(sha))
                    for sha in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY)
                ),
                47,
            )
            self.assertNotIn(native.SZABS, native.supported_exports(SHA_18_TY))
            self.assertNotIn(native.MODERN[0], native.supported_exports(SHA_12_TY))
        self.assertEqual(native.supported_exports("0" * 64), ())

    def test_identity_and_unassigned_pair_fail_before_io(self) -> None:
        self.ctx.module_bytes += b"tamper"
        with self.assertRaises(TYSourceError):
            self.run_export(native.OCC05[4])
        with self.assertRaises(TYSourceError):
            self.run_export("Ex2DOOR_01_StartConnectionHistoryClear")
        self.assertEqual(self.comm.events, [])

    def test_buffer_boundary_and_cancellation(self) -> None:
        for args in ((), (bytes(64),), (bytearray(4),), (bytearray(64), 1)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                native.run_body(native.OCC05[4], args, self.ctx)
        self.ctx.cancelled = True
        with self.assertRaises(Cancelled):
            self.run_export(native.OCC05[4])
        self.assertFalse(self.comm.events)

    def test_sensor_native_output_identity_and_close(self) -> None:
        self.frame(b"\x21\0", b"\x61\0\0\1\x40")
        self.exit_frame()
        image = self.buffer
        self.assertEqual(self.run_export(native.OCC05[4]), 0)
        self.assertIs(self.buffer, image)
        self.assertEqual(dword(image, 0x34), 1)
        self.assertEqual(self.comm.events[-2:], [b"\x82", "close"])

    def test_sensor_preserves_false_output_and_native_error(self) -> None:
        dword(self.buffer, 0x34, 99)
        self.frame(b"\x21\0", b"\x61\0\0\1\x20")
        self.exit_frame()
        self.assertEqual(self.run_export(native.OCC05[4]), 0)
        self.assertEqual(dword(self.buffer, 0x34), 99)
        self.frame(b"\x21\0", b"\x7f\x21\x22", 7)
        self.exit_frame()
        self.assertEqual(self.run_export(native.OCC05[4]), 7)

    def test_sensor_short_and_host_fault_cleanup(self) -> None:
        self.frame(b"\x21\0", b"\x61\0")
        self.exit_frame()
        self.assertEqual(self.run_export(native.OCC05[4]), 3)
        error = RuntimeError("authored host failure")
        self.comm.frames.append(error)
        self.exit_frame()
        with self.assertRaisesRegex(RuntimeError, "authored host failure"):
            self.run_export(native.OCC05[4])
        self.assertEqual(self.comm.events[-1], "close")

    def test_occ_ranges_retain_connection(self) -> None:
        for export, ids, offset, phase in (
            (native.OCC05[1], (0xD1, 0xD2), 0x10, 3),
            (native.OCC05[2], (0xCF, 0xD0), 8, 2),
        ):
            with self.subTest(export=export):
                for identifier, value in zip(ids, (b"abcd", b"efgh"), strict=True):
                    self.frame(
                        bytes((0x21, identifier)), bytes((0x61, identifier)) + value
                    )
                self.frame(b"\x21\x18", b"\x61\x18WXYZ")
                self.assertEqual(self.run_export(export), 0)
                self.assertEqual(self.buffer[offset : offset + 8], b"efghabcd")
                self.assertEqual(self.buffer[0x28:0x2C], b"WXYZ")
                self.assertEqual(dword(self.buffer, 0x2C), 1)
        self.assertNotIn("close", self.comm.events)

    def test_occ_range_bad_echo_keeps_partial_output_and_phase(self) -> None:
        self.frame(b"\x21\xd1", b"\x61\xd1abcd")
        self.frame(b"\x21\xd2", b"\x61\xd3efgh")
        self.exit_frame()
        self.assertEqual(self.run_export(native.OCC05[1]), 3)
        self.assertEqual(self.buffer[0x14:0x18], b"abcd")
        self.assertEqual(dword(self.buffer, 0x2C), 3)

    def test_recline_optional_ranges(self) -> None:
        for identifier in (0xC1, 0xC2):
            self.frame(bytes((0x21, identifier)), bytes((0x61, identifier)) + b"abcd")
        self.frame(b"\x21\xc3", b"\x61\xc3U")
        self.frame(b"\x21\xc6", b"\x61\xc6U")
        for identifier in (0xC4, 0xC5, 0xC7, 0xC8):
            self.frame(bytes((0x21, identifier)), bytes((0x61, identifier)) + b"efgh")
        self.frame(b"\x21\x18", b"\x61\x18WXYZ")
        self.assertEqual(self.run_export(native.OCC05[3]), 0)
        self.assertEqual(self.buffer[0x33], 0x11)
        self.assertEqual(self.buffer[0x18:0x28], b"efgh" * 4)

    def test_zero_point_seed_carry_and_response_output(self) -> None:
        self.frame(b"\x27\1\x5d\xc2", b"\x67\1\x12\x34")
        self.frame(b"\x27\2\x4f\x6f", b"\x67\2\xaa")
        self.frame(b"\xa5\1\xaa", b"\xe5\1xyz")
        self.assertEqual(self.run_export(native.OCC05[6]), 0)
        self.assertEqual(self.buffer[0x30:0x33], b"xyz")
        self.assertEqual(dword(self.buffer, 0x2C), 5)
        self.assertNotIn("close", self.comm.events)

    def test_zero_point_reinit_fault_phase(self) -> None:
        self.comm.initial_status = 22
        dword(self.buffer, 0x34, 1)
        self.exit_frame()
        self.assertEqual(self.run_export(native.OCC05[6]), 22)
        self.assertEqual(dword(self.buffer, 0x2C), 6)

    def test_occ06_negative81_maps1000_and_sleeps(self) -> None:
        dword(self.buffer, 0, 1)
        self.frame(b"\x27\3\x5d\xc2", b"\x67\3\0\0\0")
        self.frame(b"\x3b\x11\xaa", b"\x7f\x3b\x81", 7)
        self.assertEqual(self.run_export(native.OCC06[1]), 1000)
        self.assertEqual(self.ctx.sleeps, [100])
        self.assertEqual(self.comm.events[-1], "close")

    def test_occ06_ack_ignores_service_byte_as_native(self) -> None:
        dword(self.buffer, 0, 1)
        self.frame(b"\x27\3\x5d\xc2", b"\x67\3\0\0\0")
        self.frame(b"\x3b\x11\xaa", b"\x99\x11")
        self.assertEqual(self.run_export(native.OCC06[1]), 0)

    def test_acc_read_fixed_buffer_and_exact_length(self) -> None:
        dword(self.buffer, 0x38, 56)
        payload = bytes(range(56))
        self.frame(b"\x21\xfb", b"\x61\xfb" + payload)
        self.assertEqual(self.run_export(native.ACC[1]), 0)
        self.assertEqual(self.buffer[:56], payload)
        self.frame(b"\x21\xfb", b"\x61\xfb" + payload + b"X")
        self.assertEqual(self.run_export(native.ACC[1]), 3)

    def test_acc_clear_native_length_and_ack(self) -> None:
        dword(self.buffer, 0x3C, 1)
        self.frame(b"\x3b\xfa\x80", b"\x7b\xfa")
        self.assertEqual(self.run_export(native.ACC[0]), 0)
        self.frame(b"\x3b\xfa\x80", b"\x00\xfa")
        self.assertEqual(self.run_export(native.ACC[0]), 3)

    def test_support_native_record_count_and_missing(self) -> None:
        offsets = [0x1020] * 256
        offsets[0x11] = 0
        self.comm.snapshots.append((0, b"\x11\3\xff\0\1", tuple(offsets)))
        self.assertEqual(self.run_export(native.OCC06[0]), 0)
        self.assertEqual(dword(self.buffer, 0), 2)
        self.comm.snapshots.append((0, bytes(0x1020), tuple([0x1020] * 256)))
        self.assertEqual(self.run_export(native.OCC06[0]), 22)

    def test_mg2_sessions_and_echo(self) -> None:
        comm = self.ctx.comm("native:1011d4f0")
        self.frame(b"\x31\1\x11\x14", b"\x71\1\x11\x14", comm=comm)
        self.assertEqual(self.run_export(native.MODERN[1]), 0)
        self.assertEqual(
            [e for e in comm.events if isinstance(e, tuple) and e[0] == "session"],
            [("session", 1, 1)] * 3,
        )
        self.assertEqual(comm.events[-1], "close")

    def test_mg3_write_error_native6b_maps2001(self) -> None:
        comm = self.ctx.comm("native:1011d4f0")
        self.buffer[4:8] = b"1234"
        comm.native_error = 0x6B
        self.frame(b"\x2e\x20\6" + b"1234", b"\x7f\x2e\x31", 7, comm)
        self.assertEqual(self.run_export(native.MODERN[2]), 2001)
        self.assertEqual(comm.events[-2:], [("session", 1, 1), "close"])

    def test_mg3_compare_native_dword(self) -> None:
        comm = self.ctx.comm("native:1011d4f0")
        dword(self.buffer, 0, 1)
        self.buffer[4:8] = b"1234"
        self.frame(b"\x22\x20\6", b"\x62\x20\6" + b"1234", comm=comm)
        self.assertEqual(self.run_export(native.MODERN[2]), 0)
        self.assertNotIn(("session", 3, 1), comm.events)

    def test_mg4_output_length_and_comparison(self) -> None:
        comm = self.ctx.comm("native:1011d4f0")
        dword(self.buffer, 0, 2)
        self.frame(b"\x22\x20\6", b"\x62\x20\6" + b"123456", comm=comm)
        self.assertEqual(self.run_export(native.MODERN[3]), 0)
        self.assertEqual(dword(self.buffer, 0x1024), 6)
        self.assertEqual(self.buffer[4:10], b"123456")
        dword(self.buffer, 0, 1)
        dword(self.buffer, 0x2048, 6)
        self.buffer[0x1028:0x102E] = b"123456"
        self.frame(b"\x22\x20\6", b"\x62\x20\6" + b"123456", comm=comm)
        self.assertEqual(self.run_export(native.MODERN[3]), 0)

    def test_adx_retained_start_poll_and_cancel(self) -> None:
        comm = self.ctx.comm("native:1011e618")
        self.frame(b"\x31\1\x10\7", b"\x71\1\x10\7", comm=comm)
        self.assertEqual(self.run_export(native.MODERN[4]), 0)
        self.assertNotIn("close", comm.events)
        dword(self.buffer, 0, 1)
        self.frame(b"\x31\3\x10\7", b"\x71\3\x10\7\1", comm=comm)
        self.frame(b"\x31\3\x10\7", b"\x71\3\x10\7\2", comm=comm)
        self.assertEqual(self.run_export(native.MODERN[4]), 0)
        self.assertEqual(self.ctx.sleeps, [200, 200])
        dword(self.buffer, 4, 1)
        self.assertEqual(self.run_export(native.MODERN[4]), 2001)
        self.assertEqual(comm.events[-1], "close")

    def test_occ07_poll_bit_unpack_ignores_reserved(self) -> None:
        comm = self.ctx.comm("native:1011d4f0")
        dword(self.buffer, 0, 1)
        self.frame(b"\x31\3\x11\3", b"\x71\3\x11\3\3" + b"\xaa" * 10, comm=comm)
        self.assertEqual(self.run_export(native.MODERN[0]), 2207)
        self.assertEqual(self.buffer[5:13], b"\1" * 8)
        self.assertEqual(self.buffer[13], 0)
        self.assertEqual(self.buffer[16], 0)
        self.assertEqual(comm.events[-1], "close")

    def test_szabs_source_exclusion(self) -> None:
        with self.assertRaises(TYSourceError):
            self.run_export(native.SZABS)

    def test_szabs_routine_and_wait(self) -> None:
        with (
            patch.object(native, "SHA_18_TY", "unused"),
            patch.object(native, "SHA_PLUS_TY", SYNTHETIC_SHA),
        ):
            comm = self.ctx.comm("native:101392d0")
            dword(self.buffer, 0, 19)
            self.frame(b"\x31\1\xc1\0\2", b"\x71\1\xc1\0", comm=comm)
            self.assertEqual(self.run_export(native.SZABS), 0)
            self.assertEqual(self.ctx.sleeps, [20000])
            self.assertNotIn("close", comm.events)

    def test_szabs_dtc_gate_allowed_and_denied(self) -> None:
        with (
            patch.object(native, "SHA_18_TY", "unused"),
            patch.object(native, "SHA_PLUS_TY", SYNTHETIC_SHA),
        ):
            comm = self.ctx.comm("native:101392d0")
            dword(self.buffer, 0, 20)
            self.frame(b"\x19\2\x09", b"\x59\2\xff\x53\x87\x54\1", comm=comm)
            self.frame(b"\x31\1\xc0\x21\1", b"\x71\1\xc0\x21", comm=comm)
            self.frame(b"\x31\1\xc0\x10", b"\x71\1\xc0\x10", comm=comm)
            self.assertEqual(self.run_export(native.SZABS), 0)
            self.frame(b"\x19\2\x09", b"\x59\2\xff\x11\x22\x33\1", comm=comm)
            self.assertEqual(self.run_export(native.SZABS), 2004)
            self.assertEqual(comm.events[-1], "close")

    def test_szabs_cycles_native_progress(self) -> None:
        with (
            patch.object(native, "SHA_18_TY", "unused"),
            patch.object(native, "SHA_PLUS_TY", SYNTHETIC_SHA),
        ):
            comm = self.ctx.comm("native:101392d0")
            dword(self.buffer, 0, 13)
            dword(self.buffer, 8, 5)
            for _ in range(2):
                for value in (5, 15, 5, 0):
                    self.frame(
                        bytes((0x31, 1, 0xC2, 0, value)), b"\x71\1\xc2\0", comm=comm
                    )
            for value in (4, 0):
                self.frame(bytes((0x31, 1, 0xC2, 1, value)), b"\x71\1\xc2\1", comm=comm)
            self.assertEqual(self.run_export(native.SZABS), 0)
            self.assertEqual(dword(self.buffer, 8), 2)
            self.assertEqual(self.ctx.sleeps, [1000, 3000, 1000] * 2 + [5000])

    def test_actual97_consumer_preserves_abi_image(self) -> None:
        from scripts.utility_ex_ty import run_body

        self.frame(b"\x21\0", b"\x61\0\0\1\x40")
        self.exit_frame()
        image = self.buffer
        self.assertEqual(run_body(native.OCC05[4], (image,), self.ctx), 0)
        self.assertEqual(dword(image, 0x34), 1)
        self.exit_frame()
        self.assertEqual(run_body(native.OCC05[0], (), self.ctx), 0)

    def test_mg4_write_uses_second_native_payload(self) -> None:
        comm = self.ctx.comm("native:1011d4f0")
        self.buffer[4:8] = b"NOPE"
        dword(self.buffer, 0x2048, 5)
        self.buffer[0x1028:0x102D] = b"RIGHT"
        self.frame(b"\x2e\x20\6RIGHT", b"\x6e\x20\6", comm=comm)
        self.assertEqual(self.run_export(native.MODERN[3]), 0)

    def test_occ07_zero_seed_skips_key_request(self) -> None:
        comm = self.ctx.comm("native:1011d4f0")
        self.frame(b"\x27\7\x5d\xc2", b"\x67\7\0\0", comm=comm)
        self.frame(b"\x31\1\x11\3", b"\x71\1\x11\3", comm=comm)
        self.assertEqual(self.run_export(native.MODERN[0]), 2204)
        self.assertNotIn("close", comm.events)

    def test_szabs_native_write_values_7_12_17(self) -> None:
        with (
            patch.object(native, "SHA_18_TY", "unused"),
            patch.object(native, "SHA_PLUS_TY", SYNTHETIC_SHA),
        ):
            comm = self.ctx.comm("native:101392d0")
            for action, value in ((7, 1), (12, 3), (17, 15)):
                with self.subTest(action=action):
                    dword(self.buffer, 0, action)
                    dword(self.buffer, 0xC, 2)
                    self.frame(
                        bytes((0x2E, 0x70, 0x10, value)), b"\x6e\x70\x10", comm=comm
                    )
                    self.assertEqual(self.run_export(native.SZABS), 0)
                    self.assertEqual(comm.events[-1], "close")

    def test_szabs_read_progress_18_six_cycles(self) -> None:
        with (
            patch.object(native, "SHA_18_TY", "unused"),
            patch.object(native, "SHA_PLUS_TY", SYNTHETIC_SHA),
        ):
            comm = self.ctx.comm("native:101392d0")
            dword(self.buffer, 0, 18)
            for _ in range(6):
                self.frame(b"\x31\1\xc1\4", b"\x71\1\xc1\4", comm=comm)
                self.frame(
                    b"\x22\x10\0", b"\x62\x10\0" + bytes(0x28) + b"\1", comm=comm
                )
                self.frame(
                    b"\x22\x10\0", b"\x62\x10\0" + bytes(0x5F) + b"\0", comm=comm
                )
            self.frame(b"\x2e\x70\x10\x1f", b"\x6e\x70\x10", comm=comm)
            self.frame(b"\x2e\x70\0\x13", b"\x6e\x70\0", comm=comm)
            self.assertEqual(self.run_export(native.SZABS), 0)
            self.assertEqual(dword(self.buffer, 0x10), 6)
            self.assertFalse(comm.frames)

    def test_szabs_aes_and_explicit_keepalive_setup(self) -> None:
        # A synthetic PE carries authored identity/key bytes. AES-128 zero-key
        # block 000...001 has independent published known-answer 58e2...455a.
        comm = self.plus_image()
        self.frame(b"\x22\x10\x10", b"\x62\x10\x10AUTHORED\0", comm=comm)
        self.frame(b"\x27\x11", b"\x67\x11" + bytes(15) + b"\1", comm=comm)
        key = bytes.fromhex("58e2fccefa7e3061367f1d57a4e7455a")
        self.frame(b"\x27\x12" + key, b"\x67\x12", comm=comm)
        self.assertEqual(self.run_export(native.SZABS), 0)
        self.assertIn(("keepalive_setup", 2000, b"\x3e\0", 2, 0), comm.events)
        self.assertIn(("keepalive", True, False), comm.events)
        self.assertNotIn("close", comm.events)

    def test_actual83_public_wrapper_and_worker_status(self) -> None:
        from typing import cast

        from scripts.utility_ex import SOURCES, UtilityExContext, UtilityExEngine
        from scripts.utility_ex_comm import UtilityExComm

        class Host:
            mode = 3

            def get_parameter(self, key: int) -> int:
                return self.mode if key == 0x6F else 0

            def get_data_size(self, key: int) -> int:
                return 0

            def get_data(self, key: int) -> bytes:
                return b""

            def set_parameter(self, key: int, value: int) -> int:
                return 1

            def write_parameters(self) -> int:
                return 1

            def ticks(self) -> int:
                return 0

            def sleep(self, milliseconds: int) -> None:
                raise AssertionError("unexpected worker sleep")

        host = Host()
        with patch.dict(SOURCES, {SYNTHETIC_SHA: "TY18"}):
            context = UtilityExContext(AUTHORED, host, None, None)
            context._communication["selected"] = cast(UtilityExComm, self.comm)
            engine = UtilityExEngine(context)
            self.frame(b"\x21\0", b"\x61\0\0\1\x40")
            self.exit_frame()
            self.assertEqual(engine.invoke(native.OCC05[4], (self.buffer,)), 15)
            self.assertEqual(engine.invoke("Ex2GetThreadStatus"), 0)
            self.assertEqual(dword(self.buffer, 0x34), 1)
            self.assertEqual(engine.worker.timeout_ms, 10000)
            self.exit_frame()
            self.assertEqual(engine.invoke(native.OCC05[0], ()), 15)
            self.assertEqual(engine.invoke("Ex2GetThreadStatus"), 0)
            host.mode = 4
            context.refresh_parameters()
            count = len(self.comm.events)
            self.assertEqual(engine.invoke(native.OCC05[4], (self.buffer,)), 99)
            self.assertEqual(len(self.comm.events), count)

    def test_result_global_published_after_cleanup_not_before(self) -> None:
        key = "native_global:10118e38"
        self.ctx.state[key] = 91
        observed: list[object] = []
        finalize = self.comm.finalize

        def observe() -> None:
            observed.append(self.ctx.state[key])
            finalize()

        with patch.object(self.comm, "finalize", observe):
            self.comm.initial_status = 22
            self.exit_frame()
            self.assertEqual(self.run_export(native.OCC05[4]), 22)
            self.assertEqual(observed, [91])
            self.assertEqual(self.ctx.state[key], 22)
            self.comm.initial_status = 0
            self.frame(b"\x21\0", b"\x7f\x21\x22", 7)
            self.exit_frame()
            self.assertEqual(self.run_export(native.OCC05[4]), 7)
            self.assertEqual(observed, [91, 22])
            self.assertEqual(self.ctx.state[key], 7)
        self.frame(b"\x21\x18", b"\x61\x18abcd")
        self.assertEqual(self.run_export(native.OCC05[5]), 0)
        self.assertEqual(self.ctx.state[key], 0)
        self.assertEqual(observed, [91, 22])

    def test_result_global_variant_selection_and_fault_nonpublication(self) -> None:
        for constant, key in (
            ("SHA_12_TY", "native_global:100ab770"),
            ("SHA_PLUS_TY", "native_global:10134ab8"),
        ):
            with (
                self.subTest(source=constant),
                patch.object(native, "SHA_18_TY", "unused"),
                patch.object(native, constant, SYNTHETIC_SHA),
            ):
                self.ctx.state.clear()
                self.exit_frame()
                self.assertEqual(native.run_body(native.OCC05[0], (), self.ctx), 0)
                self.assertEqual(self.ctx.state, {key: 0})
        self.ctx.state = {"native_global:10118e38": 123}
        error = RuntimeError("authored host fault")
        self.comm.frames.append(error)
        self.exit_frame()
        with self.assertRaises(RuntimeError) as raised:
            self.run_export(native.OCC05[4])
        self.assertIs(raised.exception, error)
        self.assertEqual(self.ctx.state["native_global:10118e38"], 123)

    def test_szabs_dual_start_has_separate_setup_and_security(self) -> None:
        comm = self.plus_image()
        second = self.ctx.comm("native:10135c58")
        dword(self.buffer, 0, 1)
        self.begin_frames(comm)
        self.begin_frames(second)
        self.assertEqual(self.run_export(native.SZABS), 0)
        self.assertIn(("target", 0x770, 0, 0, 0, 0), comm.events)
        self.assertIn(("target", 0x773, 0, 0, 0, 0), second.events)
        self.assertNotIn("close", comm.events)
        self.assertNotIn("close", second.events)

    def test_szabs_safety_and_clear_branches(self) -> None:
        comm = self.plus_image()
        for action in (2, 3):
            with self.subTest(action=action):
                dword(self.buffer, 0, action)
                self.begin_frames(comm)
                self.frame(b"\x2e\x70\0\0", b"\x6e\x70\0", comm=comm)
                self.frame(b"\x22\x10\0", b"\x62\x10\0" + bytes(0x29), comm=comm)
                if action == 3:
                    self.frame(b"\x31\1\xc0\x16", b"\x71\1\xc0\x16", comm=comm)
                    self.frame(b"\x22\x10\0", b"\x62\x10\0" + bytes(0xA8), comm=comm)
                    self.frame(b"\x14\xff\xff\xff", b"\x54", comm=comm)
                    self.frame(b"\x31\1\xc4\3", b"\x71\1\xc4\3", comm=comm)
                self.assertEqual(self.run_export(native.SZABS), 0)
                self.assertEqual(comm.events[-1], "close")
                self.assertFalse(comm.frames)

    def test_szabs_start_and_continuation_routines(self) -> None:
        comm = self.plus_image()
        for action, low in ((4, 1), (8, 2), (5, 1), (9, 2), (10, 2), (15, 1)):
            with self.subTest(action=action):
                dword(self.buffer, 0, action)
                if action in (4, 8):
                    self.begin_frames(comm)
                sub = 2 if action == 10 else 1
                self.frame(
                    bytes((0x31, sub, 0xC1, low)),
                    bytes((0x71, sub, 0xC1, low)),
                    comm=comm,
                )
                self.assertEqual(self.run_export(native.SZABS), 0)
                self.assertFalse(comm.frames)
        for action in (6, 16):
            dword(self.buffer, 0, action)
            self.frame(b"\x31\2\xc1\1", b"\x71\2\xc1\1", comm=comm)
            self.assertEqual(self.run_export(native.SZABS), 0)
        self.assertEqual(self.ctx.sleeps, [60000, 60000])

    def test_szabs_dual_actuator_progress_and_stop(self) -> None:
        comm = self.plus_image()
        second = self.ctx.comm("native:10135c58")
        dword(self.buffer, 0, 14)
        self.frame(b"\x31\1\xc0Q", b"\x71\1\xc0Q", comm=second)
        for _ in range(2):
            for value in (0x50, 0xF0, 0x50, 0):
                self.frame(bytes((0x31, 1, 0xC2, 0, value)), b"\x71\1\xc2\0", comm=comm)
        for value in (4, 0):
            self.frame(bytes((0x31, 1, 0xC2, 1, value)), b"\x71\1\xc2\1", comm=comm)
        self.frame(b"\x31\2\xc0Q", b"\x71\2\xc0Q", comm=second)
        self.assertEqual(self.run_export(native.SZABS), 0)
        self.assertEqual(dword(self.buffer, 0xC), 1)
        self.assertEqual(dword(self.buffer, 0x10), 2)
        self.assertFalse(comm.frames)
        self.assertFalse(second.frames)
        self.assertNotIn("close", second.events)

    def test_szabs_wait_flag_cancel_and_final_mask(self) -> None:
        comm = self.plus_image()
        dword(self.buffer, 0, 11)
        dword(self.buffer, 0x18, 1)
        self.assertEqual(self.run_export(native.SZABS), 0)
        self.assertFalse(comm.events)
        dword(self.buffer, 0, 17)
        self.frame(b"\x2e\x70\x10\x0f", b"\x6e\x70\x10", comm=comm)
        self.assertEqual(self.run_export(native.SZABS), 2001)
        self.assertNotIn("close", comm.events)
        dword(self.buffer, 0, 21)
        self.frame(b"\x22\x10\0", b"\x62\x10\0" + bytes(0xA7) + b"\x0f", comm=comm)
        self.frame(b"\x31\1\xc0\x21\0", b"\x71\1\xc0\x21", comm=comm)
        self.frame(b"\x31\1\xc0\x15", b"\x71\1\xc0\x15", comm=comm)
        self.frame(b"\x14\xff\xff\xff", b"\x54", comm=comm)
        self.assertEqual(self.run_export(native.SZABS), 0)
        self.assertEqual(self.ctx.sleeps[-1], 120000)
        self.assertEqual(comm.events[-1], "close")

    def test_mid_wait_cancel_closes_and_keeps_prior_result(self) -> None:
        comm = self.ctx.comm("native:1011e618")
        dword(self.buffer, 0, 1)
        key = "native_global:10118e38"
        self.ctx.state[key] = 123

        def cancel(milliseconds: int) -> None:
            self.ctx.cancelled = True

        with (
            patch.object(self.ctx, "native_sleep", cancel),
            self.assertRaises(Cancelled),
        ):
            self.run_export(native.MODERN[4])
        self.assertEqual(comm.events, ["close"])
        self.assertEqual(self.ctx.state[key], 123)

    def test_occ07_completion_cleanup_error_replaces2207(self) -> None:
        comm = self.ctx.comm("native:1011d4f0")
        dword(self.buffer, 0, 1)
        self.frame(b"\x31\3\x11\3", b"\x71\3\x11\3\3" + b"\xaa" * 10, comm=comm)
        with patch.object(comm, "session", return_value=22):
            self.assertEqual(self.run_export(native.MODERN[0]), 22)
        self.assertEqual(self.ctx.state["native_global:10118e38"], 22)
        self.assertEqual(comm.events[-1], "close")

    def test_adx_reloads_live_cancel_after_normal_session(self) -> None:
        comm = self.ctx.comm("native:1011e618")
        dword(self.buffer, 0, 1)
        self.frame(b"\x31\3\x10\7", b"\x71\3\x10\7\2", comm=comm)

        def normal(
            mode: int,
            keepalive: int = 1,
            *,
            normal_first: bool = False,
            stop_on_error: bool = False,
        ) -> int:
            self.assertEqual((mode, stop_on_error), (1, True))
            dword(self.buffer, 4, 1)
            return 0

        with patch.object(comm, "session", normal):
            self.assertEqual(self.run_export(native.MODERN[4]), 2001)

    def test_aes_missing_backend_is_native_crypto_failure(self) -> None:
        import ctypes.util

        with patch.object(ctypes.util, "find_library", return_value=None):
            self.assertIsNone(native._aes128_block(bytes(16), bytes(16)))
        with self.assertRaises(ValueError):
            native._aes128_block(bytes(15), bytes(16))

    def test_szabs_dtc_partial_record_reads_native_zero_tail(self) -> None:
        comm = self.plus_image()
        dword(self.buffer, 0, 20)
        self.frame(b"\x19\2\x09", b"\x59\2\xff\x11\x22\x33", comm=comm)
        self.frame(b"\x31\1\xc0\x21\1", b"\x71\1\xc0\x21", comm=comm)
        self.frame(b"\x31\1\xc0\x10", b"\x71\1\xc0\x10", comm=comm)
        self.assertEqual(self.run_export(native.SZABS), 0)


if __name__ == "__main__":
    unittest.main()
