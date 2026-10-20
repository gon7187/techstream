"""Authored literal native buffers and frame traces, without OEM execution."""

from __future__ import annotations

import struct
import unittest
from unittest.mock import patch

from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import SHA_12_TY, SHA_18_TY, SHA_PLUS_TY, TYSourceError
from scripts.utility_ex_ty_retained_06 import (
    FC04,
    FC05,
    HAL,
    IC,
    MGR,
    _fc04,
    _fc05,
    _fc05_support,
    _fc05_threshold,
    _hal,
    _ic,
    _mgr,
    _module_data,
    run_body,
    supported_exports,
)
from tests.test_utility_ex_ty import Comm, Context


class NativeComm(Comm):
    def __init__(self, replies: list[tuple[int, bytes]]) -> None:
        super().__init__(replies)
        self.dtc: tuple[int, bytes] = (0, b"\x58\x00")
        self.snapshot: tuple[int, bytes, tuple[int, ...]] = (0, b"", ())
        self.session_statuses: list[int] = []
        self.fault = False

    def select_target(self, identifier: int, second: int = 0) -> None:
        self.events.append(("target", identifier, second))

    def read_dtcs(self, mode: int = 0x80, capacity: int = 0x1000) -> tuple[int, bytes]:
        self.events.append(("dtc", mode, capacity))
        return self.dtc

    def support_snapshot(self, kind: int) -> tuple[int, bytes, tuple[int, ...]]:
        self.events.append(("snapshot", kind))
        return self.snapshot

    def session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int:
        self.events.append(("session", mode, keepalive))
        return self.session_statuses.pop(0) if self.session_statuses else 0

    def exchange(self, request: bytes) -> tuple[int, bytes]:
        if self.fault:
            self.fault = False
            raise OSError("authored lower fault")
        return super().exchange(request)


class NativeContext(Context):
    def __init__(self, comm: NativeComm, sha: str = SHA_18_TY) -> None:
        super().__init__()
        self.controller = comm
        self.module_sha256 = sha
        self.clock = 0
        self.cancelled = False
        self.sleeps: list[int] = []
        self.stop_buffer: bytearray | None = None

    def is_cancelled(self) -> bool:
        return self.cancelled

    def sleep(self, ms: int) -> None:
        self.sleeps.append(ms)
        self.clock = (self.clock + ms) & 0xFFFFFFFF
        if self.stop_buffer is not None:
            struct.pack_into("<I", self.stop_buffer, 0x60, 0)

    def native_sleep(self, ms: int) -> None:
        self.sleep(ms)

    def ticks(self) -> int:
        return self.clock


def fc_buffer() -> bytearray:
    data = bytearray(100)
    for offset, echo, count in (
        (0x20, 0x22, 1),
        (0x30, 0x33, 2),
        (0x40, 0x44, 1),
        (0x50, 0x55, 2),
    ):
        struct.pack_into("<IIII", data, offset, echo, count, 2, count)
    return data


class Retained06Tests(unittest.TestCase):
    def test_exact_identity_and_unsupported_pairs(self) -> None:
        self.assertEqual(len(supported_exports(SHA_18_TY)), 16)
        self.assertEqual(len(supported_exports(SHA_12_TY)), 13)
        self.assertEqual(supported_exports("0" * 64), ())
        context = NativeContext(NativeComm([]))
        with self.assertRaises(TYSourceError):
            run_body(IC, (bytearray(104),), context)
        self.assertEqual(context.controller.events, [])
        context.module_sha256 = "0" * 64
        with self.assertRaises(TYSourceError):
            run_body("Ex2DOOR_01_StartConnectionHistoryClear", (), context)

    def test_native_buffer_validation_before_channel(self) -> None:
        context = NativeContext(NativeComm([]))
        with patch("scripts.utility_ex_ty_retained_06.hashlib.sha256") as digest:
            digest.return_value.hexdigest.return_value = SHA_18_TY
            for args in ((), (bytes(104),), (bytearray(103),)):
                with self.assertRaises(ValueError):
                    run_body(IC, args, context)
        self.assertEqual(context.controller.events, [])

    def test_ic_literal_copy_and_all_normal_result(self) -> None:
        responses = [(0, bytes((0x62, 0xDB, 0x70 + i)) + bytes(10)) for i in range(10)]
        responses.append((0, b"\x62\xdd\x00\x12\x34\x56\x78"))
        for sha in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY):
            with self.subTest(sha=sha):
                comm = NativeComm(responses)
                context = NativeContext(comm, sha)
                data = bytearray(b"\xff" * 110)
                self.assertEqual(_ic(comm, data, context), 1001)
                self.assertEqual(data[:104], bytes(100) + b"\x12\x34\x56\x78")
                self.assertEqual(data[104:], b"\xff" * 6)
                self.assertEqual(comm.events[-1], "finalize")

    def test_ic_flags_status_echo_short_and_partial_retention(self) -> None:
        for offset, flag in (
            (5, 1),
            (6, 2),
            (6, 0x20),
            (7, 0x60),
            (7, 0x80),
            (7, 0x10),
            (7, 1),
            (8, 0x80),
            (8, 4),
            (9, 1),
        ):
            record = bytearray(10)
            record[offset] = flag
            comm = NativeComm(
                [(0, b"\x62\xdb\x70" + record)]
                + [(0, bytes((0x62, 0xDB, 0x70 + i)) + bytes(10)) for i in range(1, 10)]
                + [(0, b"\x62\xdd\x00" + bytes(4))]
            )
            self.assertEqual(_ic(comm, bytearray(104), NativeContext(comm)), 0)
        for response, expected in (
            ((9, b""), 9),
            ((0, b"\x62\xdb\x71" + bytes(10)), 3),
            ((0, b"\x62\xdb\x70"), 3),
        ):
            comm = NativeComm([response])
            data = bytearray(b"\xaa" * 104)
            self.assertEqual(_ic(comm, data, NativeContext(comm)), expected)
            self.assertEqual(data, b"\xaa" * 104)
            self.assertEqual(comm.events[-1], "finalize")

    def test_ic_cancellation_and_lower_exception_finalize(self) -> None:
        comm = NativeComm([])
        context = NativeContext(comm)
        context.cancelled = True
        with self.assertRaises(Cancelled):
            _ic(comm, bytearray(104), context)
        self.assertEqual(comm.events[-1], "finalize")
        comm = NativeComm([])
        comm.fault = True
        with self.assertRaises(OSError):
            _ic(comm, bytearray(104), NativeContext(comm))
        self.assertEqual(comm.events[-1], "finalize")

    def test_fc_start_literal_frames_targets_delays_and_cleanup(self) -> None:
        comm = NativeComm(
            [(0, bytes((0x70, echo))) for echo in (0x44, 0x55, 0x22, 0x33)]
            + [(0, b"\x70"), (0, b"\x70")]
        )
        context = NativeContext(comm, SHA_PLUS_TY)
        self.assertEqual(_fc04(FC04[2], fc_buffer(), context), 0)
        self.assertEqual(context.sleeps, [30000])
        frames = [event for event in comm.events if isinstance(event, bytes)]
        self.assertEqual(
            frames,
            [
                b"\x30\x44\xff\x01",
                b"\x30\x55\xff\x02\x02",
                b"\x30\x22\xff\x32",
                b"\x30\x33\xff\x07\xd0",
                b"\x30",
                b"\x30",
            ],
        )
        self.assertIn(("native_rva:142f0", 150), comm.events)
        self.assertEqual(comm.events.count("finalize"), 6)

    def test_fc_keepalive_mutable_stop_and_fault_cleanup(self) -> None:
        data = fc_buffer()
        struct.pack_into("<I", data, 0x60, 1)
        comm = NativeComm(
            [(0, b"\x70\x22"), (0, b"\x70\x44"), (0, b"\x70"), (0, b"\x70")]
        )
        context = NativeContext(comm)
        context.stop_buffer = data
        self.assertEqual(_fc04(FC04[1], data, context), 0)
        self.assertEqual(context.sleeps, [3000])
        comm = NativeComm([(0, b"\x70"), (0, b"\x70")])
        comm.fault = True
        with self.assertRaises(OSError):
            _fc04(FC04[2], fc_buffer(), NativeContext(comm))
        self.assertEqual(comm.events.count("finalize"), 3)

    def test_fc_status_retry_and_malformed_echo(self) -> None:
        data = bytearray(100)
        struct.pack_into("<IIII", data, 0, 0x50, 2, 2, 2)
        comm = NativeComm([(0, b"\x61\x50\x00\x00"), (0, b"\x61\x50\x00\x03")])
        context = NativeContext(comm)
        self.assertEqual(_fc04(FC04[4], data, context), 0)
        self.assertEqual(context.sleeps, [1000, 1000])
        comm = NativeComm([(0, b"\x61\x51\x00\x03")])
        self.assertEqual(_fc04(FC04[4], data, NativeContext(comm)), 3)

    def test_hal_height_literal_success_and_failure_dtc_priority(self) -> None:
        data = bytearray(struct.pack("<II", 2, 1))
        comm = NativeComm([(0, b"\x70\x04")])
        self.assertEqual(_hal(HAL[1], data, NativeContext(comm)), 0)
        self.assertIn(b"\x30\x04\x00\x80\x08", comm.events)
        comm = NativeComm([(7, b"")])
        comm.dtc = (0, b"\x58\x02\xa4\x2d\xa4\x20")
        context = NativeContext(comm)
        self.assertEqual(_hal(HAL[1], data, context), 9001)
        self.assertEqual(context.sleeps, [1500])

    def test_hal_support_snapshot_and_dtc_nested_priority(self) -> None:
        comm = NativeComm([])
        comm.snapshot = (0, b"\x01\x01\x40", (0x1020, 0))
        comm.dtc = (0, b"\x58\x02\xa4\x20\xa4\x43")
        data = bytearray(4)
        self.assertEqual(_hal(HAL[2], data, NativeContext(comm)), 9104)
        self.assertEqual(struct.unpack("<I", data)[0], 1)
        comm.dtc = (0, b"\x58\x00")
        self.assertEqual(_hal(HAL[2], data, NativeContext(comm)), 1003)

    def test_hal03_all_source_dtc_priorities_single_and_competing(self) -> None:
        priority = (
            (0xA443, 9104),
            (0xC100, 9109),
            (0xC142, 9110),
            (0xC293, 9111),
            (0xC242, 9112),
            (0xA420, 1000),
            (0xA455, 9105),
            (0xA42C, 9107),
            (0xA42D, 9108),
        )
        for sha in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY):
            for index, (code, expected) in enumerate(priority):
                for codes in ((code,), tuple(item[0] for item in priority[index:])):
                    with self.subTest(source=sha, codes=codes):
                        comm = NativeComm([])
                        comm.snapshot = (0, b"\x01\x01\x40", (0x1020, 0))
                        comm.dtc = (
                            0,
                            bytes((0x58, len(codes)))
                            + b"".join(
                                value.to_bytes(2, "big") for value in reversed(codes)
                            ),
                        )
                        self.assertEqual(
                            _hal(HAL[2], bytearray(4), NativeContext(comm, sha)),
                            expected,
                        )
                        self.assertEqual(comm.events[-1], "finalize")

    def test_mgr_literal_write_read_and_native_buffer_retention(self) -> None:
        comm = NativeComm([(0, b"\x6e\x20\x07")])
        self.assertEqual(
            _mgr(
                MGR[1],
                bytearray(struct.pack("<II", 0, 0x44332211)),
                NativeContext(comm),
            ),
            0,
        )
        self.assertIn(b"\x2e\x20\x07\x11\x22\x33\x44", comm.events)
        data = bytearray(b"\xaa" * 0x204C)
        struct.pack_into("<I", data, 0, 2)
        comm = NativeComm([(0, b"\x62\x20\x07\x11\x22\x33\x44")])
        self.assertEqual(_mgr(MGR[2], data, NativeContext(comm)), 0)
        self.assertEqual(data[4:12], b"\x11\x22\x33\x44\0\0\0\0")
        self.assertEqual(struct.unpack_from("<I", data, 0x1024)[0], 4)
        self.assertEqual(data[0x1028:], b"\xaa" * (0x204C - 0x1028))

    def test_mgr_session_restore_precedence_and_nrc_mapping(self) -> None:
        comm = NativeComm([(0, b"\x71\x01\x11\x12")])
        comm.session_statuses = [0, 0, 12]
        self.assertEqual(_mgr(MGR[0], bytearray(), NativeContext(comm)), 12)
        comm = NativeComm([(7, b"")])
        comm.native_error = 0x6B
        self.assertEqual(_mgr(MGR[1], bytearray(8), NativeContext(comm)), 2001)
        self.assertEqual(comm.events[-1], "finalize")

    def test_fc_support_literal_inout_offsets_and_counts(self) -> None:
        data = bytearray(100)
        for at in (0, 0x20, 0x30, 0x40, 0x50):
            data[at : at + 4] = bytes((1, 0, 1, 0))
            struct.pack_into("<I", data, at + 4, 1)
        comm = NativeComm([])
        comm.snapshot = (0, b"\x01\x02\x01\x02", (0x1020, 0))
        self.assertEqual(_fc04(FC04[0], data, NativeContext(comm)), 0)
        for at in (0, 0x20, 0x30, 0x40, 0x50):
            self.assertEqual(struct.unpack_from("<II", data, at + 8), (2, 2))
        self.assertEqual(comm.events.count("finalize"), 3)
        comm.snapshot = (0, b"\x01\x02\x02\x02", (0x1020, 0))
        self.assertEqual(_fc04(FC04[0], data, NativeContext(comm)), 22)

    def test_fc_confirm_ten_alternations_and_timeout(self) -> None:
        comm = NativeComm(
            [(0, bytes((0x70, echo))) for echo in (0x44, 0x55, 0x22, 0x33)]
            + [(0, b"\x70\x22")] * 10
            + [(0, b"\x70")] * 2
        )
        context = NativeContext(comm)
        self.assertEqual(_fc04(FC04[3], fc_buffer(), context), 0)
        self.assertEqual(context.sleeps, [4000] * 10)
        data = bytearray(100)
        struct.pack_into("<IIII", data, 0, 0x50, 2, 2, 2)
        comm = NativeComm([(0, b"\x61\x50\x00\x00")] * 120)
        context = NativeContext(comm)
        self.assertEqual(_fc04(FC04[4], data, context), 9999)
        self.assertEqual(len(context.sleeps), 120)

    def test_fc05_support_literal_descriptor_and_control_types(self) -> None:
        table = struct.pack("<IIII", 0x63, 0, 1, 1) * 44
        limits = b"".join(struct.pack("<IIII", 0x63, i, 10, 0) for i in range(10))
        for control, expected in ((15, 11), (3, 10)):
            comm = NativeComm([])
            offsets = [0x1020] * 256
            offsets[0x63], offsets[0xC6] = 0, 4
            comm.snapshot = (
                0,
                b"\x63\x02\x01\x01" + bytes((0xC6, 2, control, control)),
                tuple(offsets),
            )
            data = bytearray(0x309)
            context = NativeContext(comm)
            self.assertEqual(
                _fc05_support(comm, data, context, table, 44, 0x2C0, limits), 0
            )
            self.assertEqual(data[0x308], expected)
            self.assertEqual(struct.unpack_from("<I", data, 0x2FC)[0], 5)
            self.assertEqual(struct.unpack_from("<I", data, 4)[0], 1)
            self.assertEqual(struct.unpack_from("<I", data, 8)[0], 2)
            self.assertEqual(struct.unpack_from("<I", data, 0x2F8)[0], 0)

    def test_fc_initial_fault_preserves_native_stop_and_default_type_writes(
        self,
    ) -> None:
        comm = NativeComm([(0, b"\x70"), (0, b"\x70")])
        comm.initial_status = 37
        self.assertEqual(_fc04(FC04[2], fc_buffer(), NativeContext(comm)), 37)
        self.assertEqual(
            [event for event in comm.events if isinstance(event, bytes)],
            [b"\x30", b"\x30"],
        )
        comm = NativeComm([])
        comm.initial_status = 37
        data = bytearray(0x309)
        with patch(
            "scripts.utility_ex_ty_retained_06._module_data",
            side_effect=[bytes(704), bytes(160)],
        ):
            self.assertEqual(_fc05(FC05[0], data, NativeContext(comm)), 37)
        self.assertEqual(data[0x308], 10)
        self.assertEqual(data[:0x308], bytes(0x308))
        self.assertEqual(comm.events[-1], "finalize")

    def test_fc05_threshold_boundaries_and_pe_validation(self) -> None:
        data = bytearray(0x309)
        data[13:15] = b"\x00\x64"
        limits = struct.pack("<IIII", 0x63, 0, 100, 0) * 4
        self.assertEqual(_fc05_threshold(data, limits, 0x63, False), 98)
        data[14] = 99
        self.assertEqual(_fc05_threshold(data, limits, 0x63, False), 0)
        with self.assertRaises(TYSourceError):
            _module_data(b"not an original PE", 0, 16)

    def test_fc05_poll_decode_activation_and_stop_from_native_buffer(self) -> None:
        table = struct.pack("<IIII", 0x63, 0, 1, 1) * 44
        limits = struct.pack("<IIII", 0x70, 0, 0, 0) * 10
        data = bytearray(0x309)
        data[0] = 0x63
        struct.pack_into("<III", data, 4, 1, 2, 1)
        struct.pack_into("<II", data, 0x2C0, 0x63, 1)
        struct.pack_into("<IIII", data, 0x2F8, 0, 4, 1, 2)
        comm = NativeComm(
            [(0, b"\x61\x63\x01"), (0, b"\x70\xc6"), (0, b"\x61\x63\x01"), (0, b"\x70")]
        )
        context = NativeContext(comm)
        original_exchange = comm.exchange

        def exchange(request: bytes) -> tuple[int, bytes]:
            result = original_exchange(request)
            context.clock += 3000
            if request[:2] == b"\x30\xc6":
                struct.pack_into("<I", data, 0x304, 0)
            return result

        comm.exchange = exchange
        with patch(
            "scripts.utility_ex_ty_retained_06._module_data",
            side_effect=[table, limits],
        ):
            self.assertEqual(_fc05(FC05[1], data, context), 0)
        self.assertEqual(data[13:15], b"\0\x01")
        self.assertIn(b"\x30\xc6\0\x02", comm.events)
        self.assertEqual(comm.events[-2:], [b"\x30", "finalize"])


if __name__ == "__main__":
    unittest.main()
