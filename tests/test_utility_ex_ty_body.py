"""Authored frame traces exercise source-derived FCM algorithms without OEM code."""

from __future__ import annotations

import unittest
from collections import deque
from unittest.mock import patch

from scripts.utility_ex_ty import SHA_12_TY, SHA_18_TY, SHA_PLUS_TY, TYSourceError
from scripts.utility_ex_ty_body import (
    AC_RESET,
    AC_RETAINED,
    APP_IR,
    BDY51,
    BDY52,
    BDY53,
    BDY_KEY,
    BDY_SEARCH,
    DCM_ACTIVATION,
    DCM_FOTA,
    DCM_REMOTE,
    DCM_SOFTWARE,
    EXPORTS_18,
    FCM_PCS_CHECK,
    FCM_PCS_STOP,
    MM_DIAGNOSTIC,
    MM_DISC,
    MM_HISTORY,
    MM_PAIRING,
    MM_SUPPORT,
    MM_VALET,
    MS2SMRT_ENABLE,
    MS2SMRT_ERASE,
    MS2SMRT_READ,
    MS2SMRT_STATUS,
    PLG3,
    PLG_CLASSIC,
    SMRT33_POLL,
    SMRT33_START,
    SMRT35_CHECK,
    SMRT35_GET,
    SMRT35_REGET,
    SMRT35_STOP,
    SMRT62,
    SMRT_EXPORTS,
    _ac_battery_clear,
    _ac_classic,
    _ac_command,
    _ac_retained,
    _bdy51,
    _bdy51_support,
    _bdy52,
    _bdy52_write,
    _bdy53,
    _bdy_dtc,
    _bdy_key,
    _bdy_search,
    _classic_entry,
    _classic_mask,
    _csn_reset,
    _csn_tire,
    _dcm_activation,
    _dcm_authentication,
    _dcm_bub,
    _dcm_clear,
    _dcm_enable,
    _dcm_fota,
    _dcm_information,
    _dcm_nrc,
    _dcm_pausing,
    _dcm_read,
    _dcm_remote,
    _dcm_setting,
    _fcm_info,
    _ir_projector,
    _mm_check,
    _mm_data_list,
    _mm_history,
    _mm_image,
    _mm_information,
    _mm_media,
    _mm_reset,
    _mm_retained,
    _mm_support,
    _mm_valet,
    _ms2smrt_enable,
    _ms2smrt_erase,
    _ms2smrt_read,
    _ms2smrt_status,
    _pairing,
    _plg3,
    _plg_classic,
    _plg_poll,
    _plg_result,
    _plg_start,
    _plg_support,
    _poll,
    _radar_start,
    _routine,
    _smrt,
    _smrt62,
    _start,
    run_body,
    supported_exports,
)
from tests.test_utility_ex_ty import Comm, Context


class BodyComm(Comm):
    def __init__(self, replies: list[tuple[int, bytes]]) -> None:
        super().__init__(replies)
        self.session_results: deque[int] = deque()
        self.session_options: list[tuple[bool, bool]] = []

    def session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int:
        self.events.append(("session", mode, keepalive))
        self.session_options.append((normal_first, stop_on_error))
        return self.session_results.popleft() if self.session_results else 0


class BodyContext(Context):
    def __init__(self, comm: BodyComm) -> None:
        super().__init__()
        self.controller = comm
        self.clock = 0

    def sleep(self, ms: int) -> None:
        self.clock += ms

    def ticks(self) -> int:
        return self.clock & 0xFFFFFFFF


class BodyTests(unittest.TestCase):
    def test_mm_data_list_validates_all_thirty_capabilities(self) -> None:
        for malformed, expected in ((False, 0), (True, 22)):
            comm = BodyComm([(0, b"\x61\x64" + bytes(range(30)))])

            def snapshot(
                kind: int, malformed=malformed
            ) -> tuple[int, bytes, tuple[int, ...]]:
                offsets = [4128] * 256
                offsets[0x64] = 0
                return (
                    0,
                    b"\x64\x1e" + b"\xff" * 29 + (b"\0" if malformed else b"\xff"),
                    tuple(offsets),
                )

            comm.support_snapshot = snapshot
            data = bytearray(b"X" * 30)
            self.assertEqual(_mm_data_list(comm, data), expected)
            self.assertEqual(data, b"X" * 30 if malformed else bytes(range(30)))
            self.assertEqual(comm.events[-1], "finalize")

    def test_mm_check_result_flag_priority_cancel_and_stop(self) -> None:
        for flags, expected in (
            (bytes(10), 0),
            (b"\x02\x01" + bytes(8), 2001),
            (b"\x02\0" + bytes(4) + b"\x01" + bytes(3), 2002),
        ):
            if not flags[0]:
                flags = b"\x02" + flags[1:]
            data = bytearray(8)
            data[4] = 1
            comm = BodyComm([(0, b"\x71\x03\x11\x06" + flags)])
            self.assertEqual(_mm_check(comm, data, BodyContext(comm)), expected)
            self.assertNotIn(b"\x31\x02\x11\x06", comm.events)
            self.assertEqual(comm.events[-1], "finalize")
        data[0] = 1
        comm = BodyComm([(7, b"")])
        self.assertEqual(_mm_check(comm, data, BodyContext(comm)), 0)
        self.assertIn(b"\x31\x02\x11\x06", comm.events)
        data[0] = 0
        comm = BodyComm([(0, b"\x71\x03\x11\x06\x02"), (7, b"")])
        self.assertEqual(_mm_check(comm, data, BodyContext(comm)), 2000)

    def test_mm_reset_retained_start_native_result_and_cancel(self) -> None:
        comm = BodyComm([(0, b"\x71\x01\x11\x15")])
        context = BodyContext(comm)
        data = bytearray(8)
        self.assertEqual(_mm_reset(comm, data, context), 1005)
        self.assertIn(b"\x31\x01\x11\x15\0", comm.events)
        self.assertNotIn("finalize", comm.events)
        data[0] = 1
        for frames, cancel, expected in (
            ([(0, b"\x71\x03\x11\x15\0"), (0, b"\x71\x03\x11\x15\x02")], 0, 1002),
            ([(0, b"\x71\x03\x11\x15\x03"), (7, b"")], 0, 1007),
            ([(7, b""), (0, b"\x71\x02\x11\x15")], 0, 1007),
            ([(7, b"")], 1, 7),
        ):
            comm = BodyComm(frames)
            data[4:8] = cancel.to_bytes(4, "little")
            self.assertEqual(_mm_reset(comm, data, BodyContext(comm)), expected)
            self.assertEqual(comm.events[-1], "finalize")

    def test_mm_media_partial_output_survives_second_read_failure(self) -> None:
        data = bytearray(b"X" * 13)
        comm = BodyComm([(0, b"\x62\x10\x14" + bytes(range(10))), (7, b"")])
        self.assertEqual(_mm_media(comm, data), 7)
        self.assertEqual(data, bytes(range(10)) + b"XXX")
        self.assertEqual(comm.events[-2:], [("session", 1, 1), "finalize"])
        comm = BodyComm(
            [(0, b"\x62\x10\x14" + bytes(range(10))), (0, b"\x62\x10\x15ABC")]
        )
        self.assertEqual(_mm_media(comm, data), 0)
        self.assertEqual(data[10:], b"ABC")

    def test_mm_retained_routine_and_explicit_restore(self) -> None:
        comm = BodyComm([(0, b"\x71\x01\x11\x08")])
        data = bytearray(4)
        context = BodyContext(comm)
        self.assertEqual(_mm_retained(comm, data, context), 0)
        self.assertIn(b"\x31\x01\x11\x08\0\x01", comm.events)
        self.assertNotIn("finalize", comm.events)
        self.assertEqual(context.clock, 200)
        data[0] = 1
        comm.session_results.append(7)
        self.assertEqual(_mm_retained(comm, data, context), 7)
        self.assertEqual(comm.events[-1], "finalize")

    def test_mm_valet_metadata_command_and_diagnostic_reply_length(self) -> None:
        comm = BodyComm([])

        def snapshot(kind: int) -> tuple[int, bytes, tuple[int, ...]]:
            self.assertEqual(kind, 2)
            offsets = [4128] * 256
            offsets[0x55] = 0
            return 0, b"\x55\x03\x01\0\x01", tuple(offsets)

        comm.support_snapshot = snapshot
        data = bytearray(4)
        self.assertEqual(_mm_valet(comm, data, MM_VALET[0]), 0)
        self.assertEqual(data, b"\x02\0\0\0")
        comm = BodyComm([(0, b"\x70\x55")])
        self.assertEqual(_mm_valet(comm, data, MM_VALET[1]), 0)
        self.assertIn(b"\x30\x55\0\x01\0", comm.events)
        for reply, expected in ((b"\x50", 0), (b"\x50\x70", 3)):
            comm = BodyComm([(0, reply)])
            self.assertEqual(_mm_valet(comm, bytearray(), MM_DIAGNOSTIC), expected)
            self.assertEqual(comm.events[-1], "finalize")

    def test_mm_information_support_and_exact_selected_fields(self) -> None:
        comm = BodyComm([])

        def snapshot(kind: int) -> tuple[int, bytes, tuple[int, ...]]:
            offsets = [4128] * 256
            offsets[0x52], offsets[0x53] = 0, 12
            return (
                0,
                b"\x52\x0a" + b"\xff" * 10 + b"\x53\x03\xff\xff\xff",
                tuple(offsets),
            )

        comm.support_snapshot = snapshot
        data = bytearray(25)
        data[8:12] = (1).to_bytes(4, "little")
        self.assertEqual(_mm_information(comm, data, True), 0)
        self.assertEqual(data[:8], b"\x0a\0\0\0\x03\0\0\0")
        comm = BodyComm([(0, b"\x61\x52" + bytes(range(10))), (0, b"\x61\x53ABC")])
        self.assertEqual(_mm_information(comm, data, False), 0)
        self.assertEqual(data[12:25], bytes(range(10)) + b"ABC")
        self.assertEqual(comm.events[-1], "finalize")
        data[8:12] = bytes(4)
        data[22:25] = b"XYZ"
        comm = BodyComm([(0, b"\x61\x52" + bytes(range(10)))])
        self.assertEqual(_mm_information(comm, data, False), 0)
        self.assertEqual(data[22:25], b"XYZ")

    def test_mm_image_support_and_command_poll_output(self) -> None:
        comm = BodyComm([])

        def snapshot(kind: int) -> tuple[int, bytes, tuple[int, ...]]:
            offsets = [4128] * 256
            offsets[0x54] = 0
            payload = b"\x03\0\xff\x07" if kind == 1 else b"\x01\0\x01"
            return 0, bytes((0x54, len(payload))) + payload, tuple(offsets)

        comm.support_snapshot = snapshot
        data = bytearray(24)
        self.assertEqual(_mm_image(comm, data, True, BodyContext(comm)), 0)
        self.assertEqual(
            [int.from_bytes(data[i : i + 4], "little") for i in (0, 4, 8, 16)],
            [3, 255, 3, 2],
        )
        comm = BodyComm(
            [(0, b"\x61\x54\0\x11\x22"), (0, b"\x70\x54"), (0, b"\x61\x54\x02\x33\x44")]
        )
        context = BodyContext(comm)
        self.assertEqual(_mm_image(comm, data, False, context), 0)
        self.assertEqual(data[12:15], b"\x02\x33\x44")
        self.assertEqual(data[20:24], bytes(4))
        self.assertIn(b"\x30\x54\0\x01\0", comm.events)
        self.assertEqual(context.events.count(("native_sleep", 100)), 5)
        self.assertNotIn(("native_sleep", 0), context.events)

    def test_mm_image_existing_operation_avoids_command_and_native_timeout_flag(
        self,
    ) -> None:
        data = bytearray(24)
        data[8:12] = (1).to_bytes(4, "little")
        comm = BodyComm([(0, b"\x61\x54\x01")] * 31)
        context = BodyContext(comm)
        self.assertEqual(_mm_image(comm, data, False, context), 0)
        self.assertEqual(data[20:24], b"\x01\0\0\0")
        self.assertEqual(context.clock, 15000)
        self.assertTrue(
            all(
                not isinstance(event, bytes) or event == b"\x21\x54"
                for event in comm.events
            )
        )
        self.assertEqual(comm.events[-1], "finalize")

    def test_mm_history_support_produces_native_sparse_consumer_metadata(self) -> None:
        comm = BodyComm([(0, b"\x61\x63\x11\x22")])

        def snapshot(kind: int) -> tuple[int, bytes, tuple[int, ...]]:
            offsets = [4128] * 256
            offsets[0x63], offsets[0x41] = 0, 6
            return 0, b"\x63\x04\xff\0\xff\0\x41\x01\x80", tuple(offsets)

        comm.support_snapshot = snapshot
        data = bytearray(136)
        self.assertEqual(_mm_support(comm, data, False), 0)
        self.assertEqual(data[:6], b"\x63\x04\xff\0\xff\0")
        self.assertEqual(data[64:68], b"\x02\0\0\0")
        self.assertEqual(data[132:136], b"\x01\0\0\0")
        self.assertEqual(_mm_history(comm, data, False), 0)
        self.assertEqual(data[68:74], b"\x61\x63\x11\0\x22\0")

    def test_mm_disc_support_packs_valid_pairs_and_optional_six_byte_groups(
        self,
    ) -> None:
        comm = BodyComm([])

        def snapshot(kind: int) -> tuple[int, bytes, tuple[int, ...]]:
            offsets = [4128] * 256
            offsets[0x61] = 0
            payload = bytes((0xFF, 0xFF, 0, 0, 0, 0, 0, 0)) + b"\xff" * 8
            return 0, bytes((0x61, len(payload))) + payload, tuple(offsets)

        comm.support_snapshot = snapshot
        data = bytearray(b"\xa5" * 4220)
        self.assertEqual(_mm_support(comm, data, True), 0)
        self.assertEqual(int.from_bytes(data[4128:4132], "little"), 12)
        self.assertEqual(
            [
                int.from_bytes(data[i : i + 4], "little")
                for i in (4132, 4136, 4144, 4148, 4152)
            ],
            [2, 3, 4, 5, 6],
        )
        self.assertEqual(data[4140:4144], b"\xa5" * 4)
        self.assertEqual(data[4216:4220], bytes(4))

    def test_dcm_remote_support_produces_selected_native_metadata(self) -> None:
        comm = BodyComm([])
        comm.select_target = lambda identifier, second=0: comm.events.append(
            ("target", identifier, second)
        )

        def snapshot(kind: int) -> tuple[int, bytes, tuple[int, ...]]:
            offsets = [4128] * 256
            offsets[0xC2], offsets[0xC4] = 0, 5
            raw = (
                b"\xc2\x03\xff\0\x01\xc4\x02\x01\0"
                if kind == 1
                else b"\xc2\x03\xff\0\0\xc4\x03\x30\0\0"
            )
            return 0, raw, tuple(offsets)

        comm.support_snapshot = snapshot
        data = bytearray(30)
        self.assertEqual(_dcm_remote(comm, data, DCM_REMOTE[0]), 0)
        self.assertEqual(
            [int.from_bytes(data[i : i + 4], "little") for i in range(0, 16, 4)],
            [2, 1, 3, 3],
        )
        self.assertEqual(
            comm.events[:3],
            [("target", 0x750, 0xC7), ("native_global:100f8194", 150), ("init", 0)],
        )

    def test_dcm_remote_c2_nrc_exception_and_readback_order(self) -> None:
        data = bytearray(30)
        for offset in (0, 4, 8, 12):
            data[offset : offset + 4] = (1).to_bytes(4, "little")
        data[20] = 0xA5
        data[24:28] = (1).to_bytes(4, "little")
        comm = BodyComm(
            [
                (7, b"\x7f\x3b\x22"),
                (0, b"\x7b\xc4"),
                (0, b"\x61\xc2\x03"),
                (0, b"\x61\xc4\x04"),
            ]
        )
        comm.select_target = lambda identifier, second=0: None
        self.assertEqual(_dcm_remote(comm, data, DCM_REMOTE[2]), 0)
        self.assertEqual(data[28:30], b"\x03\x04")
        self.assertIn(b"\x3b\xc2\xa5", comm.events)
        self.assertIn(b"\x3b\xc4\x20", comm.events)
        comm = BodyComm([(0, b"\x7b\xc2"), (7, b"\x7f\x3b\x22")])
        comm.select_target = lambda identifier, second=0: None
        self.assertEqual(_dcm_remote(comm, data, DCM_REMOTE[2]), 7)
        self.assertEqual(comm.events[-1], "finalize")
        comm = BodyComm([(0, b"\x61\xc4\x05")])
        comm.select_target = lambda identifier, second=0: None
        self.assertEqual(_dcm_remote(comm, data, DCM_REMOTE[1]), 0)
        self.assertEqual(data[29], 5)

    def test_dcm_fota_metadata_start_and_status_poll(self) -> None:
        comm = BodyComm([])

        def snapshot(kind: int) -> tuple[int, bytes, tuple[int, ...]]:
            offsets = [4128] * 256
            if kind == 1:
                offsets[0x26], offsets[0x33] = 0, 22
                raw = b"\x26\x14" + b"\xff" * 20 + b"\x33\x02\xff\xff"
            else:
                offsets[0x33] = 0
                raw = b"\x33\x03\xff\xff\0"
            return 0, raw, tuple(offsets)

        comm.support_snapshot = snapshot
        data = bytearray(48)
        self.assertEqual(_dcm_fota(comm, data, DCM_FOTA[0], BodyContext(comm)), 0)
        self.assertEqual(
            [int.from_bytes(data[i : i + 4], "little") for i in range(0, 20, 4)],
            [2, 2, 20, 2, 3],
        )
        comm = BodyComm([(0, b"\x7b\x33")])
        self.assertEqual(_dcm_fota(comm, data, DCM_FOTA[1], BodyContext(comm)), 0)
        self.assertIn(b"\x3b\x33\x01\0\0", comm.events)
        comm = BodyComm([(0, b"\x61\x33\x01\x09"), (0, b"\x61\x33\x02\x0a")])
        context = BodyContext(comm)
        self.assertEqual(_dcm_fota(comm, data, DCM_FOTA[2], context), 0)
        self.assertEqual(data[20:22], b"\x02\x0a")
        self.assertEqual(context.clock, 1000)
        data[44:48] = (2).to_bytes(4, "little")
        comm = BodyComm([(0, b"\x61\x33\x01\x09")])
        self.assertEqual(_dcm_fota(comm, data, DCM_FOTA[2], BodyContext(comm)), 0)
        self.assertEqual(data[20:22], b"\x01\x09")
        self.assertEqual(comm.events[-1], "finalize")

    def test_dcm_activation_optional_support_and_exact_commands(self) -> None:
        comm = BodyComm([])

        def snapshot(kind: int) -> tuple[int, bytes, tuple[int, ...]]:
            offsets = [4128] * 256
            offsets[0x9A], offsets[0x9B] = 0, 5
            return (
                (7, b"", tuple(offsets))
                if kind == 1
                else (0, b"\x9a\x03\xff\0\0\x9b\x02\xff\0", tuple(offsets))
            )

        comm.support_snapshot = snapshot
        data = bytearray(20)
        data[8:12] = (123).to_bytes(4, "little")
        self.assertEqual(
            _dcm_activation(comm, data, DCM_ACTIVATION[0], BodyContext(comm)), 0
        )
        self.assertEqual(data[:12], b"\x03\0\0\0\x02\0\0\0\0\0\0\0")
        for selector, request in (
            (1, b"\x3b\x9a\x30\0\0"),
            (2, b"\x3b\x9b\x01\0"),
            (3, b"\x3b\x9a\x31\0\0"),
            (0, b"\x3b\0"),
        ):
            data[12] = selector
            comm = BodyComm([(0, bytes((0x7B, request[1], 0)))])
            self.assertEqual(
                _dcm_activation(comm, data, DCM_ACTIVATION[1], BodyContext(comm)), 2009
            )
            self.assertIn(request, comm.events)
        comm = BodyComm([(7, b"")])
        self.assertEqual(
            _dcm_activation(comm, data, DCM_ACTIVATION[1], BodyContext(comm)), 7
        )

    def test_dcm_activation_poll_bits_cancel_and_host_deadline(self) -> None:
        data = bytearray(20)
        data[8:12] = (1).to_bytes(4, "little")
        for selector, value in ((1, 0x40), (2, 0x10), (3, 0)):
            data[12] = selector
            comm = BodyComm([(0, b"\x61\x99" + bytes((value,)))])
            context = BodyContext(comm)
            self.assertEqual(_dcm_activation(comm, data, DCM_ACTIVATION[2], context), 0)
            self.assertEqual(context.clock, 500)
            self.assertEqual(comm.events[-1], "finalize")
        data[12] = 255
        data[16:20] = (1).to_bytes(4, "little")
        comm = BodyComm([(0, b"\x61\x99\0")])
        self.assertEqual(
            _dcm_activation(comm, data, DCM_ACTIVATION[2], BodyContext(comm)), 0
        )
        data[16:20] = bytes(4)
        comm = BodyComm([(0, b"\x61\x99\0")] * 360)
        context = BodyContext(comm)
        with self.assertRaises(TimeoutError):
            _dcm_activation(comm, data, DCM_ACTIVATION[2], context)
        self.assertEqual(comm.events[-1], "finalize")

    def test_dcm_bub_selected_target_metadata_and_exact_write(self) -> None:
        comm = BodyComm([])
        comm.select_target = lambda identifier, second=0: comm.events.append(
            ("target", identifier, second)
        )

        def snapshot(kind: int) -> tuple[int, bytes, tuple[int, ...]]:
            self.assertEqual(kind, 3)
            offsets = [4128] * 256
            offsets[0x34] = 0
            return 0, b"\x34\x03\xff\0\0", tuple(offsets)

        comm.support_snapshot = snapshot
        data = bytearray(4)
        self.assertEqual(_dcm_bub(comm, data, True), 0)
        self.assertEqual(data, b"\x03\0\0\0")
        self.assertEqual(comm.events[0], ("target", 0x750, 0xC7))
        for reply, expected in ((b"\x7b\x34", 0), (b"\x7b\x35", 3), (b"\x7b\x34\0", 3)):
            comm = BodyComm([(0, reply)])
            self.assertEqual(_dcm_bub(comm, data, False), expected)
            self.assertIn(b"\x3b\x34\x01\0\0", comm.events)
            self.assertEqual(comm.events[-1], "finalize")

    def test_dcm_authentication_support_producer_and_exact_nrc(self) -> None:
        comm = BodyComm([(0, b"\x61\x35\x01\x00")])

        def snapshot(kind: int) -> tuple[int, bytes, tuple[int, ...]]:
            identifier = 0x35 if kind == 1 else 0x38
            offsets = [4128] * 256
            offsets[identifier] = 0
            payload = b"\xff\x00\x01" if kind == 1 else b"\x01\x00\x00"
            return 0, bytes((identifier, len(payload))) + payload, tuple(offsets)

        comm.support_snapshot = snapshot
        data = bytearray(12)
        self.assertEqual(_dcm_authentication(comm, data), 9100)
        self.assertEqual(data[:8], b"\x02\0\0\0\x03\0\0\0")
        data[8:12] = (1).to_bytes(4, "little")
        for response, expected in (
            ((0, b"\x7b\x38"), 0),
            ((7, b"\x7f\x3b\x22"), 9101),
            ((7, b"\x7f\x3b\x22\0"), 7),
            ((0, b"\x7b\x39"), 3),
        ):
            comm = BodyComm([response])
            self.assertEqual(_dcm_authentication(comm, data), expected)
            self.assertIn(b"\x3b\x38\x01\0\0", comm.events)
            self.assertEqual(comm.events[-1], "finalize")

    def test_dcm_pausing_native_support_and_cancellation(self) -> None:
        data = bytearray(8)
        comm = BodyComm([])

        def snapshot(kind: int) -> tuple[int, bytes, tuple[int, ...]]:
            offsets = [4128] * 256
            offsets[0xC9] = 0
            return (
                0,
                (b"\xc9\x03\x01\x00\x80" if kind == 3 else b"\xc9\x04\xff\x00\x10\x00"),
                tuple(offsets),
            )

        comm.support_snapshot = snapshot
        self.assertEqual(_dcm_pausing(comm, data, True), 0)
        self.assertEqual(data, b"\x03\0\0\0\x02\0\0\0")
        comm = BodyComm([(0, b"\x61\xc9\x01\x00"), (0, b"\x7b\xc9")])
        self.assertEqual(_dcm_pausing(comm, data, False), 0)
        self.assertIn(b"\x3b\xc9\0\0\0", comm.events)
        comm = BodyComm([(0, b"\x61\xc9\x00\x00")])
        self.assertEqual(_dcm_pausing(comm, data, False), 1003)
        self.assertEqual(comm.events[-1], "finalize")
        comm = BodyComm([(0, b"\x61\xc9\x01")])
        self.assertEqual(_dcm_pausing(comm, data, False), 3)

    def test_dcm_information_native_jump_tables_and_complete_output_clear(self) -> None:
        for action, state, expected in (
            (0, 2, 1011),
            (0, 0x11, 1016),
            (0, 0xF0, 1012),
            (3, 1, 1013),
            (3, 2, 1011),
            (3, 0x11, 1016),
            (3, 0xF0, 1014),
            (3, 0, 1015),
        ):
            comm = BodyComm([(0, bytes((0x62, 0x20, 1, state)))])
            data = bytearray(4092)
            data[:4] = action.to_bytes(4, "little")
            self.assertEqual(_dcm_information(comm, data, BodyContext(comm)), expected)
            self.assertEqual(comm.events[-1], "finalize")
        for action, state in ((0, 1), (3, 0x10), (2, 0x11)):
            comm = BodyComm(
                [
                    (0, bytes((0x62, 0x20, 1, state))),
                    (0, b"\x62\xf1\x81\x02" + bytes(range(20))),
                ]
            )
            data = bytearray(b"\xff" * 4092)
            data[:4] = action.to_bytes(4, "little")
            data[4088:4092] = bytes(4)
            self.assertEqual(
                _dcm_information(comm, data, BodyContext(comm)),
                1018 if action == 2 else 0,
            )
            self.assertEqual(data[4], 2)
            self.assertEqual(data[5:37], bytes(range(20)) + bytes(12))
            self.assertEqual(data[37:4085], bytes(4048))
            self.assertEqual(data[4085:4088], b"\xff" * 3)

    def test_plus_dcm_information_action_zero_reads_every_state_except_two(
        self,
    ) -> None:
        for state, expected in ((0, 0), (0x11, 0), (0xF0, 0), (2, 1011)):
            frames = [(0, b"\x62\x20\x01" + bytes((state,)))]
            if state != 2:
                frames.append((0, b"\x62\xf1\x81\0"))
            comm = BodyComm(frames)
            context = BodyContext(comm)
            context.module_sha256 = SHA_PLUS_TY
            self.assertEqual(_dcm_information(comm, bytearray(4092), context), expected)
            self.assertEqual(comm.events[-1], "finalize")

    def test_dcm_information_retention_cancel_and_error_precedence(self) -> None:
        comm = BodyComm([(0, b"\x6e\x20\x01")])
        data = bytearray(4092)
        data[:4] = (1).to_bytes(4, "little")
        self.assertEqual(_dcm_information(comm, data, BodyContext(comm)), 0)
        self.assertIn(b"\x2e\x20\x01\x01\x00", comm.events)
        self.assertNotIn("finalize", comm.events)
        data[:4] = (2).to_bytes(4, "little")
        data[4088:4092] = (1).to_bytes(4, "little")
        self.assertEqual(_dcm_information(comm, data, BodyContext(comm)), 0)
        self.assertEqual(comm.events[-1], "finalize")
        comm = BodyComm([(0, b"\x62\x20\x01\x01"), (7, b"")])
        comm.session_results.extend((0, 9))
        data[:4] = bytes(4)
        self.assertEqual(_dcm_information(comm, data, BodyContext(comm)), 7)
        self.assertEqual(data[4:4085], bytes(4081))
        comm = BodyComm([])
        comm.initial_status = 2
        self.assertEqual(_dcm_information(comm, data, BodyContext(comm)), 2)
        self.assertNotIn("finalize", comm.events)

    def test_bdy53_count_guard_and_registration_readback(self) -> None:
        data = bytearray(15)
        data[:4] = (4).to_bytes(4, "little")
        data[4:8] = (5).to_bytes(4, "little")
        for frames, expected in (
            ([(0, b"\x61\x82\x00\x00\x00")], 9000),
            (
                [
                    (0, b"\x61\x82\x00\x00\x10"),
                    (0, b"\x7b\x85"),
                    (0, b"\x61\x82\x20\x00\x10"),
                ],
                0,
            ),
        ):
            comm = BodyComm(frames)
            self.assertEqual(_bdy53(comm, data, BDY53[1], BodyContext(comm)), expected)
            self.assertEqual(comm.events[-1], "finalize")
        self.assertEqual(data[12:15], b"\x01\x01\x00")

    def test_bdy53_always_clears_dtc_and_preserves_native_priority(self) -> None:
        data = bytearray(15)
        data[:4] = (4).to_bytes(4, "little")
        data[4:8] = (5).to_bytes(4, "little")
        for codes, expected in (
            ((), 0),
            ((0x9401,), 9001),
            ((0x9402, 0x9401), 9000),
            ((0x9405,), 9001),
        ):
            comm = BodyComm(
                [(0, b"\x61\x82\x20\x00\x10"), (0, b"\x7b\x85"), (0, b"\x54")]
            )
            dtcs = (
                b"\x53"
                + bytes((len(codes),))
                + b"".join(code.to_bytes(2, "big") for code in codes)
            )
            with patch.object(comm, "read_dtcs", return_value=(0, dtcs)):
                self.assertEqual(
                    _bdy53(comm, data, BDY53[2], BodyContext(comm)), expected
                )
            self.assertIn(b"\x14", comm.events)
            self.assertEqual(comm.events[-1], "finalize")

    def test_bdy53_native81001_timeout_checks_both_flags(self) -> None:
        data = bytearray(15)
        data[:4] = (4).to_bytes(4, "little")
        data[4:8] = (5).to_bytes(4, "little")
        comm = BodyComm([(0, b"\x61\x82\x20\x20\x10")] * 163 + [(0, b"\x7b\x85")])
        ctx = BodyContext(comm)
        self.assertEqual(_bdy53(comm, data, BDY53[2], ctx), 9000)
        self.assertEqual(ctx.clock, 81500)
        self.assertFalse(comm.replies)
        self.assertEqual(comm.events[-1], "finalize")

    def test_bdy52_start_readback_failure_resets_native_command(self) -> None:
        data = bytearray(16)
        data[:4] = (5).to_bytes(4, "little")
        data[4:8] = (6).to_bytes(4, "little")
        comm = BodyComm([(0, b"\x7b\x83"), (7, b"\x7f\x21\x22"), (0, b"\x7b\x83")])
        self.assertEqual(_bdy52(comm, data, BDY52[2], BodyContext(comm)), 7)
        self.assertIn(b"\x3b\x83\x80" + bytes(5), comm.events)
        self.assertIn(b"\x3b\x83" + bytes(6), comm.events)
        self.assertEqual(comm.events[-1], "finalize")
        self.assertEqual(_bdy52_write(BodyComm([(0, b"\x7b\x00")]), True), 3)

    def test_bdy52_two_waits_dtc_and_final_count(self) -> None:
        data = bytearray(16)
        data[:4] = (5).to_bytes(4, "little")
        data[4:8] = (6).to_bytes(4, "little")
        for dtcs, expected in ((b"\x53\x00", 0), (b"\x53\x01\x94\x02", 9000)):
            replies = [
                (0, b"\x61\x82\x40\x20\x00\x10"),
                (0, b"\x61\x82\x00\x00\x00\x10"),
                (0, b"\x61\x82\x00\x00\x00\x10"),
                (0, b"\x7b\x83"),
            ]
            replies.append(
                (0, b"\x54") if expected else (0, b"\x61\x82\x00\x00\x00\x10")
            )
            comm = BodyComm(replies)
            ctx = BodyContext(comm)
            with patch.object(comm, "read_dtcs", return_value=(0, dtcs)) as dtc:
                self.assertEqual(_bdy52(comm, data, BDY52[3], ctx), expected)
                dtc.assert_called_once_with(0x81, 0x1000)
            self.assertEqual(ctx.clock, 1600)
            self.assertEqual(comm.events[-1], "finalize")

    def test_bdy52_strict_native_timeout_and_reset_status_precedence(self) -> None:
        data = bytearray(16)
        data[:4] = (5).to_bytes(4, "little")
        data[4:8] = (6).to_bytes(4, "little")
        for reset_status, expected in ((0, 9000), (7, 7)):
            comm = BodyComm(
                [(0, b"\x61\x82\x00\x20\x00\x10")] * 131 + [(reset_status, b"\x7b\x83")]
            )
            ctx = BodyContext(comm)
            self.assertEqual(_bdy52(comm, data, BDY52[3], ctx), expected)
            self.assertEqual(ctx.clock, 65500)
            self.assertFalse(comm.replies)
            self.assertEqual(comm.events[-1], "finalize")

    def test_bdy51_source_support_produces_selected_native_offsets(self) -> None:
        offsets = [4128] * 256
        offsets[0x82] = offsets[0x83] = 0
        data = bytearray(12)
        raw = b"\x82\x06\xc4\x24\x0f\x00\xf0\xf0"
        comm = BodyComm([])
        with patch.object(
            comm,
            "support_snapshot",
            side_effect=(
                (0, raw, tuple(offsets)),
                (0, b"\x83\x01\x40", tuple(offsets)),
            ),
        ) as getter:
            self.assertEqual(_bdy51_support(comm, data), 0)
            self.assertEqual(
                [int.from_bytes(data[n : n + 4], "little") for n in (0, 4, 8)],
                [5, 7, 3],
            )
            self.assertEqual(
                [call.args for call in getter.call_args_list], [(1,), (3,)]
            )
        self.assertEqual(comm.events[-1], "finalize")
        raw = b"\x82\x06\xc4\x24\x0f\x00\xf0\x00"
        data = bytearray(12)
        with patch.object(
            comm, "support_snapshot", return_value=(0, raw, tuple(offsets))
        ):
            self.assertEqual(_bdy51_support(comm, data), 22)
        self.assertEqual(int.from_bytes(data[:4], "little"), 5)
        self.assertEqual(data[4:], bytes(8))

    def test_classic_support_parser_native_sentinel_and_safe_extent(self) -> None:
        offsets = [4128] * 256
        self.assertEqual(_classic_entry(b"", tuple(offsets), 0x82), (22, b""))
        offsets[0x82] = 4127
        self.assertEqual(_classic_entry(b"", tuple(offsets), 0x82), (99, b""))
        offsets[0x82] = 0
        self.assertEqual(
            _classic_entry(b"\x82\x02\xc4\x24", tuple(offsets), 0x82), (0, b"\xc4\x24")
        )
        self.assertEqual(_classic_mask(b"\xc4\x24", 4, 0x24), (0, 3))
        self.assertEqual(_classic_mask(b"\xc4\x04", 4, 0x24)[0], 22)
        self.assertEqual(_classic_mask(b"\xc4", 4, 0x24)[0], 22)
        with self.assertRaises(TYSourceError):
            _classic_entry(bytes(4129), tuple(offsets), 0x82)

    def test_bdy23_start_two_targets_native_mask_and_retention(self) -> None:
        for count, expected in ((1, 1000), (7, 1000), (0, 3), (8, 3)):
            frames = [(0, b"\x62\x10\x13" + bytes((count,)))]
            if expected == 1000:
                frames.append((0, b"\x71\x01\x11\x12"))
            comm = BodyComm(frames)
            with (
                patch.object(comm, "select_target") as target,
                patch.object(comm, "select_protocol", return_value=99) as protocol,
            ):
                self.assertEqual(
                    _bdy_search(comm, bytearray(), BDY_SEARCH[0], BodyContext(comm)),
                    expected,
                )
                protocol.assert_called_once_with(0x11)
                self.assertEqual(target.call_args_list[0].args, (0x750, 0xB5))
                if expected == 1000:
                    self.assertEqual(target.call_args_list[1].args, (0x750, 0x40))
                    self.assertIn(
                        b"\x31\x01\x11\x12\x01" + bytes(((1 << (count + 1)) - 2,)),
                        comm.events,
                    )
                    self.assertEqual(comm.events.count("finalize"), 1)
                    self.assertNotEqual(comm.events[-1], "finalize")
                else:
                    self.assertEqual(comm.events[-1], "finalize")

    def test_bdy23_result_one_hot_classification_and_retained_session(self) -> None:
        data = bytearray(12)
        comm = BodyComm(
            [
                (0, b"\x71\x03\x11\x12\x00"),
                (0, b"\x71\x03\x11\x12\x08"),
                (0, b"\x71\x02\x11\x12"),
                (0, b"\x62\x22\xf0\x00\x00\x02\x00\x00\x00\x00"),
            ]
        )
        self.assertEqual(_bdy_search(comm, data, BDY_SEARCH[1], BodyContext(comm)), 0)
        self.assertEqual(data[0], 3)
        self.assertEqual(data[3], 2)
        self.assertNotIn("finalize", comm.events)
        data[8:12] = (1).to_bytes(4, "little")
        comm = BodyComm([])
        self.assertEqual(
            _bdy_search(comm, data, BDY_SEARCH[1], BodyContext(comm)), 1001
        )
        self.assertFalse(comm.events)

    def test_bdy23_multibit_and_bad_state_clean_up(self) -> None:
        for mask, expected, extra in (
            (6, 1002, []),
            (2, 3, [(0, b"\x62\x22\xf0" + bytes(7))]),
        ):
            comm = BodyComm(
                [(0, b"\x71\x03\x11\x12" + bytes((mask,))), (0, b"\x71\x02\x11\x12")]
                + extra
            )
            self.assertEqual(
                _bdy_search(comm, bytearray(12), BDY_SEARCH[1], BodyContext(comm)),
                expected,
            )
            self.assertEqual(comm.events[-2:], [("session", 1, 1), "finalize"])

    def test_bdy23_send_toggles_exact_selected_byte_and_reads_back(self) -> None:
        data = bytearray((3, 0, 1, 1, 0, 0, 0, 0))
        comm = BodyComm(
            [(0, b"\x6e\x22\xf0"), (0, b"\x62\x22\xf0\x00\x01\x02\x00\x00\x00\x00")]
        )
        ctx = BodyContext(comm)
        self.assertEqual(_bdy_search(comm, data, BDY_SEARCH[2], ctx), 0)
        self.assertIn(b"\x2e\x22\xf0\x00\x01\x02\x00\x00\x00\x00", comm.events)
        self.assertEqual(ctx.clock, 200)
        self.assertEqual(comm.events[-1], "finalize")

    def test_bdy21_22_count_native_outputs_and_precedence(self) -> None:
        for erasure in (False, True):
            export = f"Ex2BDY_{22 if erasure else 21}_KeyNumGet"
            data = bytearray((0xAA, 0xBB))
            comm = BodyComm(
                [
                    (0, b"\x71\x01\x11\x06"),
                    (0, b"\x71\x03\x11\x06A\x01B\x07"),
                    (0, b"\x71\x02\x11\x06"),
                ]
            )
            comm.session_results.extend((0, 0, 9))
            self.assertEqual(_bdy_key(comm, data, export, BodyContext(comm)), 9)
            self.assertEqual(data, b"\x07\xbb" if erasure else b"\x03\x07")
            self.assertIn(
                b"\x31\x01\x11\x06" + bytes((1 if erasure else 2,)), comm.events
            )
            self.assertEqual(comm.events[-1], "finalize")

    def test_bdy21_22_start_stop_end_native_retention(self) -> None:
        for family, suffix in ((21, "KeyRegistration"), (22, "KeyCodeErasure")):
            comm = BodyComm([(0, b"\x71\x01\x11\x06")])
            self.assertEqual(
                _bdy_key(
                    comm,
                    bytearray(),
                    f"Ex2BDY_{family}_Start{suffix}",
                    BodyContext(comm),
                ),
                0,
            )
            self.assertNotIn("finalize", comm.events)
            for prefix, expected in (("Stop", 1002), ("Timeover", 1004), ("End", 7)):
                comm = BodyComm([(7, b"\x7f\x31\x22")])
                self.assertEqual(
                    _bdy_key(
                        comm,
                        bytearray(),
                        f"Ex2BDY_{family}_{prefix}{suffix}",
                        BodyContext(comm),
                    ),
                    expected,
                )
                self.assertEqual(comm.events[-2:], [("session", 1, 1), "finalize"])

    def test_bdy21_22_completion_and_cancel_keep_controller(self) -> None:
        for erasure in (False, True):
            for cancel, expected in ((0, 1000), (1, 1001), (2, 1003)):
                data = bytearray((0, 0, 0))
                data[1 if erasure else 2] = cancel
                export = f"Ex2BDY_{22 if erasure else 21}_" + (
                    "KeyCodeErasure" if erasure else "KeyRegistration"
                )
                comm = BodyComm(
                    [
                        (0, b"\x71\x03\x11\x06A\x00B\x04"),
                        (0, b"\x71\x03\x11\x06A\x01B\x05"),
                    ]
                )
                self.assertEqual(
                    _bdy_key(comm, data, export, BodyContext(comm)), expected
                )
                self.assertNotIn("finalize", comm.events)
                self.assertEqual(data[1], cancel if erasure else 5 if not cancel else 0)
                self.assertEqual(len(comm.replies), int(bool(cancel)))

    def test_bdy21_22_malformed_poll_stops_and_releases(self) -> None:
        comm = BodyComm([(0, b"\x71\x03\x11\x06ABC"), (0, b"\x71\x02\x11\x06")])
        self.assertEqual(
            _bdy_key(
                comm, bytearray(3), "Ex2BDY_21_KeyRegistration", BodyContext(comm)
            ),
            3,
        )
        self.assertEqual(comm.events[-1], "finalize")
        fault = OSError("initiating frame fault")
        comm = BodyComm([])
        with (
            patch.object(comm, "exchange", side_effect=fault),
            self.assertRaises(OSError) as caught,
        ):
            _bdy_key(comm, bytearray(3), "Ex2BDY_21_KeyRegistration", BodyContext(comm))
        self.assertIs(caught.exception, fault)
        self.assertEqual(comm.events[-1], "finalize")

    def test_ac28_start_retains_raw_session_and_returns1005(self) -> None:
        comm = BodyComm(
            [(0, b"\x50\x01ABCD"), (0, b"\x50\x03ABCD"), (0, b"\x71\x01\x11\x08")]
        )
        ctx = BodyContext(comm)
        self.assertEqual(_ac_retained(comm, bytearray(8), ctx), 1005)
        self.assertNotIn("finalize", comm.events)
        self.assertNotIn(("session", 3, 1), comm.events)
        self.assertEqual(ctx.clock, 100)

    def test_ac28_poll_result_cancel_and_restore_ignored(self) -> None:
        for reply, result in (
            (b"\x71\x03\x11\x08\x02", 0),
            (b"\x71\x03\x11\x08\x03", 1007),
        ):
            data = bytearray(8)
            data[4:8] = (1).to_bytes(4, "little")
            comm = BodyComm(
                [(0, b"\x71\x03\x11\x08\x01"), (0, reply), (7, b"\x7f\x10\x22")]
            )
            ctx = BodyContext(comm)
            self.assertEqual(_ac_retained(comm, data, ctx), result)
            self.assertEqual(ctx.clock, 150)
            self.assertEqual(comm.events[-1], "finalize")
        data[0] = 1
        comm = BodyComm([(0, b"\x50\x01ABCD")])
        self.assertEqual(_ac_retained(comm, data, BodyContext(comm)), 0)
        self.assertEqual(comm.events[-1], "finalize")

    def test_ac28_start_malformed_session_and_failed_routine_cleanup(self) -> None:
        comm = BodyComm([(0, b"\x50\x01")])
        self.assertEqual(_ac_retained(comm, bytearray(8), BodyContext(comm)), 3)
        self.assertEqual(comm.events[-1], "finalize")
        comm = BodyComm(
            [
                (0, b"\x50\x01ABCD"),
                (0, b"\x50\x03ABCD"),
                (7, b"\x7f\x31\x22"),
                (0, b"\x50\x01ABCD"),
            ]
        )
        self.assertEqual(_ac_retained(comm, bytearray(8), BodyContext(comm)), 7)
        self.assertEqual(comm.events[-1], "finalize")

    def test_ms2smrt07_enable_error_and_restore_precedence(self) -> None:
        data = bytearray((1).to_bytes(4, "little"))
        for writes, restores, expected in (
            ([(0, b"\x6e\x11\xb2")], [(0, b"\x50\x01ABCD")], 0),
            ([(0, b"\x6e\x11\xb2")], [(5, b"")], 3000),
            ([(7, b"\x7f\x2e\x31")] * 4, [(5, b"")], 7),
        ):
            comm = BodyComm(writes + restores)
            self.assertEqual(_ms2smrt_enable(comm, data, BodyContext(comm)), expected)
            self.assertNotIn(("init", 0), comm.events)
            self.assertEqual(comm.events[-1], "finalize")
        comm = BodyComm([(0, b"\x50\x01ABCD")])
        self.assertEqual(
            _ms2smrt_enable(
                comm, bytearray((2).to_bytes(4, "little")), BodyContext(comm)
            ),
            0,
        )

    def test_ms2smrt07_support_false_and_support_fault(self) -> None:
        for replies, expected in (
            ([(0, b"\x62\x10\x00" + bytes(4))], 3),
            ([(5, b"")], 5),
        ):
            comm = BodyComm(replies)
            self.assertEqual(
                _ms2smrt_enable(comm, bytearray(4), BodyContext(comm)), expected
            )
            self.assertEqual(comm.events[-1], "finalize")

    def test_ms2smrt05_support_alternatives_and_output_flag(self) -> None:
        for secondary, alternate, expected in (
            (False, False, 22),
            (True, False, 0),
            (False, True, 0),
        ):
            frames = []
            for cursor in range(0x1000, 0x12C0, 32):
                payload = bytearray((0, 0, 0, int(cursor < 0x12A0)))
                if cursor == 0x12A0:
                    payload[2] |= 0x20
                if cursor == 0x1220 and alternate:
                    payload[2] |= 0x20
                frames.append((0, b"\x62" + cursor.to_bytes(2, "big") + payload))
            frames.append(
                (0, b"\x62\x20\x00\x00\x00\x00" + bytes((0x20 if secondary else 0,)))
            )
            data = bytearray(16)
            comm = BodyComm(frames)
            with patch.object(comm, "configure_target"):
                self.assertEqual(
                    _ms2smrt_status(comm, data, BodyContext(comm)), expected
                )
            self.assertEqual(int.from_bytes(data[4:8], "little"), int(alternate))
            self.assertFalse(comm.replies)

    def test_ms2smrt05_poll_complete_unknown_and_nrc(self) -> None:
        data = bytearray(16)
        data[:4] = (1).to_bytes(4, "little")
        data[8:12] = (0x1233).to_bytes(4, "little")
        for frames, expected, error in (
            (
                [
                    (0, b"\x62\x12\x33\xff"),
                    (0, b"\x62\x12\xb3\x00"),
                    (0, b"\x62\x12\xb3\xff"),
                ],
                0,
                0,
            ),
            ([(0, b"\x62\x12\x33\x00")], 1000, 0),
            ([(7, b"\x7f\x22\x31")] * 4, 7, 0x31),
        ):
            comm = BodyComm(frames)
            with patch.object(comm, "configure_target") as target:
                self.assertEqual(
                    _ms2smrt_status(comm, data, BodyContext(comm)), expected
                )
                target.assert_called_once_with(0x7B4)
            self.assertEqual(int.from_bytes(data[12:16], "little"), error)
            self.assertEqual(comm.events[-1], "finalize")

    def test_ms2smrt05_native_absolute_deadline(self) -> None:
        data = bytearray(16)
        data[:4] = (1).to_bytes(4, "little")
        comm = BodyComm([(0, b"\x62\x00\x00\xff"), (0, b"\x62\x12\xb3\x00")])
        ctx = BodyContext(comm)
        with (
            patch.object(comm, "configure_target"),
            patch.object(ctx, "ticks", side_effect=(0, 60001)),
        ):
            self.assertEqual(_ms2smrt_status(comm, data, ctx), 2000)
        self.assertEqual(comm.events[-1], "finalize")

    def test_ms2smrt08_support_walk_and_selected_bit(self) -> None:
        data = bytearray(4248)
        replies = [
            (0, b"\x62" + value.to_bytes(2, "big") + b"\x00\x00\x00\x01")
            for value in range(0x1000, 0x1360, 32)
        ]
        replies.append((0, b"\x62\x13\x60\x00\x00\x00\x40"))
        comm = BodyComm(replies)
        self.assertEqual(_ms2smrt_read(comm, data, BodyContext(comm)), 0)
        self.assertEqual(data[111], 0x40)
        self.assertEqual(comm.events[-1], "finalize")
        comm = BodyComm([(0, b"\x62\x10\x00\x00\x00\x00\x00")])
        self.assertEqual(_ms2smrt_read(comm, bytearray(4248), BodyContext(comm)), 1000)

    def test_ms2smrt08_retry_and_raw_reply_copy(self) -> None:
        data = bytearray(4248)
        data[4244:4248] = (1).to_bytes(4, "little")
        comm = BodyComm([(2, b""), (7, b"\x7f\x22\x22"), (0, b"\x62\x13\x7aA")])
        ctx = BodyContext(comm)
        self.assertEqual(_ms2smrt_read(comm, data, ctx), 0)
        self.assertEqual(data[112:117], b"\x62\x13\x7aA\x00")
        self.assertEqual(sum(e == b"\x22\x13\x7a" for e in comm.events), 3)
        comm = BodyComm([(7, b"\x7f\x22\x31")] * 4)
        ctx = BodyContext(comm)
        self.assertEqual(_ms2smrt_read(comm, data, ctx), 7)
        self.assertEqual(int.from_bytes(data[4240:4244], "little"), 0x31)
        self.assertEqual(ctx.state["native_global:1012ae38"], 0x31)

    def test_ms2smrt09_pending_completion_deadline_and_restore(self) -> None:
        pending = (0, b"\x71\x03\x50\x00\x00\x01")
        complete = (0, b"\x71\x03\x50\x00\x00\x02")
        comm = BodyComm(
            [(0, b"\x71\x01\x50\x00"), pending, pending, complete, (0, b"\x50\x01ABCD")]
        )
        ctx = BodyContext(comm)
        self.assertEqual(_ms2smrt_erase(comm, bytearray(12), ctx), 0)
        self.assertEqual(ctx.clock, 100)
        comm = BodyComm(
            [(0, b"\x71\x01\x50\x00")] + [pending] * 101 + [(0, b"\x50\x01ABCD")]
        )
        ctx = BodyContext(comm)
        self.assertEqual(_ms2smrt_erase(comm, bytearray(12), ctx), 2000)
        self.assertEqual(ctx.clock, 10000)
        data = bytearray(12)
        comm = BodyComm(
            [(0, b"\x71\x01\x50\x00"), (0, b"\x71\x03\x50\x00\x12\x34")]
            + [(7, b"\x7f\x10\x22")] * 4
        )
        self.assertEqual(_ms2smrt_erase(comm, data, BodyContext(comm)), 3)
        self.assertEqual(int.from_bytes(data[8:12], "little"), 0x1234)
        self.assertEqual(comm.events[-1], "finalize")

    def test_ms2smrt09_stop_discards_restore_failure(self) -> None:
        data = bytearray(12)
        data[:4] = (1).to_bytes(4, "little")
        comm = BodyComm([(7, b"\x7f\x10\x22")] * 4)
        self.assertEqual(_ms2smrt_erase(comm, data, BodyContext(comm)), 0)
        self.assertEqual(comm.events[-1], "finalize")

    def test_smrt62_support_read_and_restore_precedence(self) -> None:
        data = bytearray(4140)
        comm = BodyComm([(0, b"\x62\x10\x23\x01"), (0, b"\x62\x20\x3dABC")])
        self.assertEqual(_smrt62(comm, data, SMRT62[0], BodyContext(comm)), 0)
        self.assertEqual(data[8:11], b"ABC")
        self.assertEqual(int.from_bytes(data[4136:4140], "little"), 3)
        self.assertEqual(comm.events[-1], "finalize")
        comm = BodyComm([(0, b"\x62\x10\x23\x02")])
        self.assertEqual(_smrt62(comm, data, SMRT62[0], BodyContext(comm)), 1000)
        self.assertEqual(len([e for e in comm.events if isinstance(e, bytes)]), 1)
        comm = BodyComm([(0, b"\x62\x10\x23\x00"), (0, b"\x62\x20\x3dAB")])
        comm.session_results.extend((0, 0, 77))
        self.assertEqual(_smrt62(comm, data, SMRT62[0], BodyContext(comm)), 77)

    def test_smrt62_start_native_pointer_mask_and_retention(self) -> None:
        data = bytearray(4140)
        data[:4] = (2).to_bytes(4, "little")
        data[8:12] = b"A?BC"
        data[4136:4140] = (4).to_bytes(4, "little")
        comm = BodyComm([(0, b"\x6e\x20\x3d"), (0, b"\x71\x01\x15\x04")])
        ctx = BodyContext(comm)
        self.assertEqual(_smrt62(comm, data, SMRT62[1], ctx), 0)
        self.assertIn(b"\x2e\x20\x3dA\x20BC", comm.events)
        self.assertNotIn("finalize", comm.events)
        self.assertEqual(ctx.clock, 200)
        comm = BodyComm([(0, b"\x6e\x20\x00")])
        self.assertEqual(_smrt62(comm, data, SMRT62[1], BodyContext(comm)), 3)
        self.assertEqual(comm.events[-2:], [("session", 1, 1), "finalize"])

    def test_smrt62_terminate_cancel_and_error_precedence(self) -> None:
        for result, cancel, restore, expected in (
            (0, 0, 9, 9),
            (7, 0, 9, 7),
            (7, 1, 9, 1001),
        ):
            data = bytearray(8)
            data[4:8] = cancel.to_bytes(4, "little")
            comm = BodyComm([(result, b"\x71\x02\x15\x04")])
            comm.session_results.append(restore)
            self.assertEqual(
                _smrt62(comm, data, SMRT62[2], BodyContext(comm)), expected
            )
            self.assertEqual(comm.events[-1], "finalize")

    def test_smrt62_fault_finalizes(self) -> None:
        comm = BodyComm([])
        with (
            patch.object(comm, "exchange", side_effect=OSError("frame fault")),
            self.assertRaisesRegex(OSError, "frame fault"),
        ):
            _smrt62(comm, bytearray(4140), SMRT62[0], BodyContext(comm))
        self.assertEqual(comm.events[-1], "finalize")

    def test_smrt12_exact_pending_setter_and_retained_start(self) -> None:
        comm = BodyComm([(0, b"\xe5\xb8")])
        ctx = BodyContext(comm)
        ctx.module_sha256 = SHA_12_TY
        self.assertEqual(_smrt(SMRT33_START, comm, bytearray(), ctx), 0)
        self.assertIn(("native_rva:b940", 100), comm.events)
        self.assertNotIn("finalize", comm.events)

    def test_exact_build_manifest(self) -> None:
        self.assertEqual(supported_exports(SHA_18_TY), EXPORTS_18)
        self.assertEqual(
            supported_exports(SHA_12_TY),
            (*SMRT_EXPORTS, *MM_SUPPORT, MM_HISTORY, MM_DISC),
        )
        self.assertEqual(
            set(supported_exports(SHA_PLUS_TY)),
            {
                *(
                    f"Ex2DCM_{number}_SendMessage"
                    for number in (30, 36, 37, 39, 40, 41, 43, 44, 45)
                ),
                *BDY_KEY,
                AC_RETAINED,
                MS2SMRT_STATUS,
                MS2SMRT_ENABLE,
                MS2SMRT_READ,
                MS2SMRT_ERASE,
                *SMRT62,
                *APP_IR,
                MM_PAIRING,
                *AC_RESET,
                *MM_SUPPORT,
                MM_HISTORY,
                MM_DISC,
            },
        )
        for other in ("", "f" * 64):
            self.assertEqual(supported_exports(other), ())

    def test_start_retains_extended_session(self) -> None:
        comm = BodyComm([(0, b"\x71\x01\x12\x09")])
        self.assertEqual(_start(comm, False), 0)
        self.assertEqual(
            comm.events[-3:],
            [("session", 1, 1), ("session", 3, 1), b"\x31\x01\x12\x09"],
        )
        self.assertNotIn("finalize", comm.events)
        self.assertIn(("native_1064", 0), comm.events)

    def test_initialization_and_session_faults(self) -> None:
        comm = BodyComm([])
        comm.initial_status = 7
        self.assertEqual(_start(comm, False), 7)
        self.assertEqual(comm.events, [("init", 0), "finalize"])
        comm = BodyComm([])
        comm.session_results.extend([9])
        self.assertEqual(_start(comm, True), 9)
        self.assertEqual(comm.events[-2:], [("session", 1, 1), "finalize"])

    def test_pcs_start_fault_stops_and_restores(self) -> None:
        comm = BodyComm([(8, b""), (0, b"\x71\x02\x16\x0c")])
        self.assertEqual(_start(comm, True), 1004)
        self.assertEqual(
            comm.events[-4:],
            [b"\x31\x01\x16\x0c", b"\x31\x02\x16\x0c", ("session", 1, 1), "finalize"],
        )

    def test_routine_length_echo_and_transport(self) -> None:
        for response in (b"", b"\x71\x03\x12\x09", b"\x71\x03\x13\x09\x02"):
            self.assertEqual(_routine(BodyComm([(0, response)]), 3, b"\x12\x09")[0], 3)
        self.assertEqual(_routine(BodyComm([(8, b"")]), 3, b"\x12\x09")[0], 8)

    def test_navi_poll_pending_complete_and_failures(self) -> None:
        for reply, result in (
            (b"\x71\x03\x12\x09\x02", 1000),
            (b"\x71\x03\x12\x09\x03", 1002),
            (b"", 3),
        ):
            comm = BodyComm([(0, b"\x71\x03\x12\x09\x00"), (0, reply)])
            ctx = BodyContext(comm)
            self.assertEqual(_poll(comm, bytearray(4), False, ctx), result)
            self.assertEqual(ctx.clock, 400)
            self.assertEqual(comm.events[-2:], [("session", 1, 1), "finalize"])

    def test_pcs_poll_branch_difference(self) -> None:
        for value, result in ((0, 1002), (2, 1000), (3, 1002)):
            replies = [
                (0, b"\x71\x03\x16\x0c\x01"),
                (0, bytes((0x71, 3, 0x16, 0x0C, value))),
            ]
            if result == 1002:
                replies.append((0, b"\x71\x02\x16\x0c"))
            comm = BodyComm(replies)
            self.assertEqual(_poll(comm, bytearray(4), True, BodyContext(comm)), result)
            self.assertEqual(b"\x31\x02\x16\x0c" in comm.events, result == 1002)
            self.assertEqual(comm.events[-1], "finalize")

    def test_native_cancel_difference(self) -> None:
        for pcs in (False, True):
            comm = BodyComm([])
            self.assertEqual(
                _poll(comm, bytearray(b"\x01\0\0\0"), pcs, BodyContext(comm)), 1001
            )
            self.assertEqual("finalize" in comm.events, not pcs)

    def test_host_deadline_and_exception_cleanup(self) -> None:
        comm = BodyComm(
            [(0, b"\x71\x03\x16\x0c\x01")] * 900 + [(0, b"\x71\x02\x16\x0c")]
        )
        with self.assertRaises(TimeoutError):
            _poll(comm, bytearray(4), True, BodyContext(comm))
        self.assertEqual(
            comm.events[-3:], [b"\x31\x02\x16\x0c", ("session", 1, 1), "finalize"]
        )

    def test_pairing_maps_setup_failure_and_preserves_command_status(self) -> None:
        comm = BodyComm([])
        comm.initial_status = 7
        self.assertEqual(_pairing(comm, BodyContext(comm)), 1000)
        self.assertEqual(comm.events[-1], "finalize")
        comm = BodyComm([(0, b"\x71\x01\x11\x10")])
        ctx = BodyContext(comm)
        self.assertEqual(_pairing(comm, ctx), 0)
        self.assertEqual(ctx.clock, 200)
        self.assertEqual(
            comm.events[-3:], [b"\x31\x01\x11\x10\x00", ("session", 1, 1), "finalize"]
        )

    def test_ir_phases_have_distinct_status_precedence(self) -> None:
        for step, value in ((1, 0), (2, 2), (3, 1), (4, 0)):
            for request_status in (0, 7):
                for restore_status in (0, 9):
                    with self.subTest(
                        step=step, request=request_status, restore=restore_status
                    ):
                        comm = BodyComm([(request_status, b"\x71\x01\x17\x02")])
                        comm.session_results.extend([0, 0, restore_status])
                        result = _ir_projector(comm, step)
                        expected = (
                            (1005 if request_status or restore_status else 0)
                            if step == 1
                            else (1001 if request_status else 1000)
                            if step == 2
                            else request_status or restore_status
                        )
                        self.assertEqual(result, expected)
                        self.assertIn(
                            b"\x31\x01\x17\x02" + bytes((value,)), comm.events
                        )
                        self.assertEqual(comm.events[-1], "finalize")
            comm = BodyComm([])
            comm.initial_status = 8
            self.assertEqual(_ir_projector(comm, step), 1001 if step == 2 else 8)

    def test_plg_support_exact_lengths_bits_outputs_and_restore_status(self) -> None:
        available = bytearray(35)
        available[:3] = b"\x62\x01\x01"
        available[5] = 1
        for first, second, expected in (
            (0, 0, 1009),
            (1, 0, 0),
            (0, 1, 0),
            (1, 1, 1009),
        ):
            config = bytearray(35)
            config[:3] = b"\x62\x17\x00"
            config[4] = first * 16
            config[7] = second * 2
            comm = BodyComm([(0, bytes(available)), (0, bytes(config))])
            data = bytearray(24)
            self.assertEqual(_plg_support(comm, data), expected)
            self.assertEqual(data[16:20], first.to_bytes(4, "little"))
            self.assertEqual(data[20:24], second.to_bytes(4, "little"))
            self.assertEqual(comm.events[-1], "finalize")
        comm = BodyComm([(0, bytes(available[:-1]))])
        self.assertEqual(_plg_support(comm, bytearray(24)), 3)

    def test_plg_start_pending_negative_and_cleanup(self) -> None:
        for status, reply, expected, stop in (
            (0, b"\x71\x01\x11\x0f", 0, False),
            (7, b"\x7f\x31\x22", 10001, False),
            (7, b"", 7, True),
        ):
            comm = BodyComm([(status, reply), (0, b"")])
            self.assertEqual(_plg_start(comm), expected)
            self.assertEqual(b"\x31\x02\x11\x0f" in comm.events, stop)
            self.assertEqual("finalize" in comm.events, bool(status))
        comm = BodyComm([])
        comm.session_results.append(7)
        self.assertEqual(_plg_start(comm), 10000)

    def test_plg_poll_native_timeout_completion_and_cancel(self) -> None:
        for pending, expected in ((1, 0), (220, 3)):
            comm = BodyComm(
                [(0, b"\x71\x03\x11\x0f\x01")] * pending
                + [(0, b"\x71\x03\x11\x0f\x02"), (7, b"")]
            )
            ctx = BodyContext(comm)
            self.assertEqual(_plg_poll(comm, ctx), expected)
            self.assertEqual(ctx.clock, 2200 if expected == 0 else 22000)
            self.assertEqual(comm.events[-1], "finalize")
        comm = BodyComm([(0, b"")])
        ctx = BodyContext(comm)
        ctx.cancelled = True
        with self.assertRaises(Exception) as caught:
            _plg_poll(comm, ctx)
        self.assertEqual(type(caught.exception).__name__, "Cancelled")
        self.assertEqual(comm.events[-1], "finalize")

    def test_plg_diagnosis_selects_did_and_result_offset(self) -> None:
        for first in (0, 1):
            for value, result in (
                (1, 10002),
                (5, 10003),
                (6, 10003),
                (0, 10004),
                (7, 10004),
            ):
                data = bytearray(24)
                data[16:20] = first.to_bytes(4, "little")
                identifier = b"\x17\x0c" if first else b"\x17\x27"
                comm = BodyComm(
                    [(0, b"\x62" + identifier + b"\x99" * first + bytes((value,)))]
                )
                self.assertEqual(_plg_result(comm, data), result)
                self.assertIn(b"\x22" + identifier, comm.events)
                self.assertNotIn(("native_1064", 0), comm.events)

    def test_radar_checks_both_support_bits_before_start(self) -> None:
        for first, second, result in ((0, 64, 1003), (128, 0, 1004), (128, 64, 0)):
            comm = BodyComm(
                [
                    (0, b"\x62\x10\xa0\0" + bytes((first,))),
                    (0, b"\x62\x10\x17\0" + bytes((second,))),
                    (0, b"\x71\x01\x11\x0e"),
                ]
            )
            self.assertEqual(_radar_start(comm), result)
            self.assertEqual(b"\x31\x01\x11\x0e" in comm.events, not result)
            self.assertEqual("finalize" in comm.events, bool(result))
        comm = BodyComm([(0, b"\x71\x03\x11\x0e\x02")])
        self.assertEqual(
            _poll(comm, bytearray(4), False, BodyContext(comm), b"\x11\x0e"), 1000
        )

    def test_dcm_id_zeroes_outputs_and_copies_only_payload(self) -> None:
        data = bytearray(b"x" * 4132)
        comm = BodyComm([(0, b"\x5a\x85AB")])
        self.assertEqual(_dcm_read(comm, data, False), 0)
        self.assertEqual(data[:8], b"\x02\0\0\0AB\0\0")
        self.assertIn(("native_global:100f8194", 150), comm.events)
        self.assertEqual(comm.events[-1], "finalize")
        data[:] = b"x" * len(data)
        comm = BodyComm([(0, b"\x5a\x85A")])
        self.assertEqual(_dcm_read(comm, data, False), 3)
        self.assertFalse(any(data))

    def test_dcm_software_copies_native_reply_even_on_error(self) -> None:
        for status, reply, expected in (
            (0, b"\x61\x26ABC", 0),
            (7, b"\x61\x26ABC", 7),
            (0, b"\x61\x27ABC", 3),
        ):
            data = bytearray(43)
            data[:4] = (2).to_bytes(4, "little")
            data[8:12] = (3).to_bytes(4, "little")
            comm = BodyComm([(status, reply)])
            self.assertEqual(_dcm_read(comm, data, True), expected)
            self.assertEqual(data[22:25], b"ABC")
            self.assertEqual(data[25:43], bytes(18))

    def test_dcm_clear_response_and_restoration_precedence(self) -> None:
        for value, result in ((0, 0), (1, 2005)):
            comm = BodyComm(
                [(0, b"\x6e\x20\x61"), (0, b"\x62\x20\x61" + bytes((value,)))]
            )
            comm.session_results.extend([0, 9])
            data = bytearray(1)
            self.assertEqual(_dcm_clear(comm, data), result)
            self.assertEqual(data[0], value)
            self.assertEqual(comm.events[-2:], [("session", 1, 1), "finalize"])
        comm = BodyComm([(0, b"\x6e\x20\x61\x00")])
        self.assertEqual(_dcm_clear(comm, bytearray(1)), 3)

    def test_ac_clear_timing_pending_timeout_and_restore(self) -> None:
        for value, expected in ((2, 0), (0, 1005), (1, 1005)):
            count = 601 if value == 1 else 1
            comm = BodyComm(
                [(0, b"\x71\x01\x11\x05")]
                + [(0, b"\x71\x03\x11\x05" + bytes((value,)))] * count
            )
            ctx = BodyContext(comm)
            self.assertEqual(_ac_battery_clear(comm, ctx), expected)
            self.assertEqual(ctx.clock, 30150 if value == 1 else 700)
            self.assertEqual(comm.events[-1], "finalize")
        comm = BodyComm([(0, b"\x71\x01\x11\x05"), (0, b"\x71\x03\x11\x05\x02")])
        comm.session_results.extend([0, 0, 8])
        self.assertEqual(_ac_battery_clear(comm, BodyContext(comm)), 8)

    def test_ac_commands_native_action_and_result_precedence(self) -> None:
        for routine in (1, 6, 7):
            for request_status in (0, 8):
                comm = BodyComm([(request_status, bytes((0x71, 1, 0x11, routine)))])
                comm.session_results.extend([0, 0, 9])
                ctx = BodyContext(comm)
                expected = (
                    (1005 if routine == 1 else 2205)
                    if request_status
                    else (9 if routine == 1 else 0)
                )
                self.assertEqual(_ac_command(comm, ctx, routine), expected)
                self.assertEqual(ctx.clock, 150)
                self.assertIn(bytes((0x31, 1, 0x11, routine)), comm.events)
                self.assertEqual(comm.events[-1], "finalize")
        comm = BodyComm([])
        self.assertEqual(_ac_command(comm, BodyContext(comm), 6, action=2), 0)
        self.assertEqual(comm.events[-1], "finalize")
        self.assertFalse(any(isinstance(e, bytes) for e in comm.events))

    def test_plg3_support_flags_and_native_retained_values(self) -> None:
        data = bytearray(28)
        data[16:20] = (9).to_bytes(4, "little")
        comm = BodyComm([(0, b"\x71\x01\x11\x00\0\x40" + bytes(30))])
        self.assertEqual(_plg3(comm, data, BodyContext(comm)), 0)
        self.assertEqual(int.from_bytes(data[24:28], "little"), 1)
        self.assertEqual(int.from_bytes(data[16:20], "little"), 9)
        self.assertEqual(comm.session_options, [(True, False), (False, True)])
        self.assertEqual(comm.events[-1], "finalize")

    def test_plg3_selected_start_retains_session_and_error_stops_both(self) -> None:
        for failing in (False, True):
            data = bytearray(45)
            data[:4] = (1).to_bytes(4, "little")
            data[8:12] = (1).to_bytes(4, "little")
            data[12] = 1
            data[44] = 0xAB
            comm = BodyComm(
                [
                    (0, b"\x71\x01\x11\x7e"),
                    (7 if failing else 0, b"\x71\x01\x11\x2b"),
                    (0, b""),
                    (0, b""),
                ]
            )
            ctx = BodyContext(comm)
            self.assertEqual(_plg3(comm, data, ctx), 2000 if failing else 0)
            self.assertEqual(ctx.clock, 1500)
            self.assertIn(b"\x31\x01\x11\x2b\xab", comm.events)
            self.assertEqual("finalize" in comm.events, failing)
            if failing:
                self.assertEqual(
                    comm.events[-4:],
                    [
                        b"\x31\x02\x11\x2b",
                        b"\x31\x02\x11\x7e",
                        ("session", 1, 1),
                        "finalize",
                    ],
                )

    def test_plg3_poll_complete_invalid_result_and_native_cancel(self) -> None:
        for value, cancel, expected, finalized in (
            (1, 0, 0, False),
            (2, 0, 3, True),
            (0, 1, 0, True),
        ):
            data = bytearray(28)
            data[:4] = (2).to_bytes(4, "little")
            data[4:8] = cancel.to_bytes(4, "little")
            comm = BodyComm(
                [(0, b"\x71\x03\x11\x2a" + bytes((value,))), (0, b""), (0, b"")]
            )
            self.assertEqual(_plg3(comm, data, BodyContext(comm)), expected)
            self.assertEqual("finalize" in comm.events, finalized)

    def test_smrt_sparse_support_order_and_termination(self) -> None:
        for export in (SMRT35_GET, SMRT35_REGET):
            frames = [(0, b"\x61\x07\xc0\x1e")]
            if export == SMRT35_REGET:
                frames.insert(0, (9, b""))
            comm = BodyComm(frames)
            data = bytearray(6)
            self.assertEqual(_smrt(export, comm, data, BodyContext(comm)), 0)
            self.assertEqual(data, b"\x80\x88\xe0\xe8\xf0\xd8")
            self.assertEqual(comm.events[-1], "finalize")
        comm = BodyComm([(9, b"")])
        self.assertEqual(_smrt(SMRT35_STOP, comm, bytearray(), BodyContext(comm)), 0)
        self.assertEqual(comm.events[-1], "finalize")

    def test_smrt_registration_start_and_poll_native_timeout(self) -> None:
        comm = BodyComm([(0, b"\xe5\xb8")])
        self.assertEqual(_smrt(SMRT33_START, comm, bytearray(), BodyContext(comm)), 0)
        self.assertIn(b"\xa5\xb8\x80" + bytes(5), comm.events)
        self.assertNotIn("finalize", comm.events)
        for frame, expected in (
            (b"\x61\x21\0\0" + bytes(4), 0),
            (b"\x61\x21\0\x04" + bytes(4), 1003),
            (b"", 3),
        ):
            comm = BodyComm([(0, frame), (9, b"")])
            self.assertEqual(
                _smrt(SMRT33_POLL, comm, bytearray(), BodyContext(comm)), expected
            )
            self.assertEqual(comm.events[-1], "finalize")
        comm = BodyComm([(0, b"\x61\x21\x20\0" + bytes(4))] * 63 + [(9, b"")])
        ctx = BodyContext(comm)
        self.assertEqual(_smrt(SMRT33_POLL, comm, bytearray(), ctx), 1002)
        self.assertEqual(ctx.clock, 31500)

    def test_smrt_communication_native_cancel_retains_controller(self) -> None:
        for flag_offset in (8, 12):
            data = bytearray(16)
            data[flag_offset] = 1
            comm = BodyComm([])
            self.assertEqual(_smrt(SMRT35_CHECK, comm, data, BodyContext(comm)), 1001)
            self.assertNotIn("finalize", comm.events)
        data = bytearray(16)
        data[6] = 0x88
        comm = BodyComm([(7, b"")])
        self.assertEqual(_smrt(SMRT35_CHECK, comm, data, BodyContext(comm)), 7)
        self.assertIn(b"\xa5\xb2\0\x88" + bytes(4), comm.events)
        self.assertNotIn("finalize", comm.events)

    def bdy(
        self,
        name: str,
        *,
        mode: int = 0x44,
        flags: int = 0,
        keys: int = 0,
        fresh: int = 0,
        registered: int = 0,
        old: int = 0,
        previous: int = 0,
        total: int = 0,
    ) -> tuple[int, bytearray, BodyComm]:
        data = bytearray(40)
        data[:4] = (5).to_bytes(4, "little")
        data[4:8] = (8).to_bytes(4, "little")
        data[20:24] = old.to_bytes(4, "little")
        data[24:28] = total.to_bytes(4, "little")
        data[28:32] = previous.to_bytes(4, "little")
        comm = BodyComm(
            [
                (0, bytes((0x61, 0x82, mode, flags, keys, fresh, registered, 0))),
                (0, bytes(2)),
            ]
        )
        result = _bdy51("Ex2BDY_51_" + name, comm, data, BodyContext(comm))
        return result, data, comm

    def test_bdy_new_registration_count_and_mode_branches(self) -> None:
        for name in ("NewKeyRegistration", "OtherKeyRegistration"):
            result, data, comm = self.bdy(name, fresh=0x30)
            self.assertEqual(result, 1009)
            self.assertEqual(int.from_bytes(data[28:32], "little"), 3)
            self.assertNotIn("finalize", comm.events)
            self.assertEqual(
                self.bdy(name, fresh=0xF0)[0], 1010
            )  # /15 yields 16, not 15.
            self.assertEqual(self.bdy(name, mode=0x44)[0], 1007)
            self.assertEqual(self.bdy(name, mode=0x40)[0], 1008)
            self.assertEqual(self.bdy(name, mode=0)[0], 1006)

    def test_bdy_key_counts_and_owner_confirmation(self) -> None:
        self.assertEqual(self.bdy("ChkNumberOfTotalKeyRegistered", flags=0x20)[0], 1005)
        result, data, _ = self.bdy("ChkNumberOfTotalKeyRegistered", keys=3)
        self.assertEqual(result, 1004)
        self.assertEqual(int.from_bytes(data[24:28], "little"), 3)
        self.assertEqual(self.bdy("ChkNumberOfTotalKeyRegistered")[0], 1003)
        for count, expected in ((0, 1000), (1, 1001), (6, 1002)):
            self.assertEqual(
                self.bdy("ChkNumberOfKeyRegistered", registered=count * 16)[0], expected
            )
        self.assertEqual(self.bdy("OwnerConfirmation", mode=0x40)[0], 1008)
        self.assertEqual(self.bdy("OwnerConfirmation", keys=0)[0], 1003)
        result, data, _ = self.bdy("OwnerConfirmation", keys=2, total=3)
        self.assertEqual(result, 1015)
        self.assertEqual(int.from_bytes(data[24:28], "little"), 2)
        self.assertEqual(self.bdy("OwnerConfirmation", keys=3, total=3)[0], 1016)

    def test_bdy_post_checks_and_interval(self) -> None:
        self.assertEqual(self.bdy("StatusCheckInterval")[0], 1023)
        self.assertEqual(self.bdy("StatusChkAfterKeyRegist", mode=0x40)[0], 1014)
        self.assertEqual(
            self.bdy("StatusChkAfterKeyRegist", mode=0, registered=0x20, previous=2)[0],
            1011,
        )
        self.assertEqual(
            self.bdy("StatusChkAfterKeyRegist", mode=0, registered=0x60, previous=6)[0],
            1012,
        )
        self.assertEqual(
            self.bdy("StatusChkAfterKeyRegist", mode=0, registered=0x20, previous=1)[0],
            1013,
        )
        self.assertEqual(
            self.bdy("StatusChkAfterOwnerConfirmation", mode=0x40)[0], 1008
        )
        self.assertEqual(self.bdy("StatusChkAfterOwnerConfirmation")[0], 1017)
        self.assertEqual(self.bdy("StatusChkAfterOwnerConfirmation", flags=4)[0], 1019)

    def test_bdy_request_lifecycle(self) -> None:
        for name in ("RequestKeyRegistration", "RequestKeyRegistEnd"):
            for keep in (False, True):
                data = bytearray(40)
                data[32] = int(keep)
                comm = BodyComm([(0, bytes(2))])
                self.assertEqual(
                    _bdy51("Ex2BDY_51_" + name, comm, data, BodyContext(comm)), 1020
                )
                self.assertEqual(
                    "finalize" in comm.events, name.endswith("End") and not keep
                )
                self.assertEqual(
                    comm.events[-1] == "finalize", name.endswith("End") and not keep
                )
        comm = BodyComm([])
        self.assertEqual(
            _bdy51("Ex2BDY_51_ExitCommunication", comm, bytearray(), BodyContext(comm)),
            1024,
        )

    def test_bdy_key_removal_cancellation_and_native_deadline(self) -> None:
        for name in BDY51:
            if not name.endswith("Before_Remove_Key"):
                continue
            data = bytearray(40)
            data[4:8] = (8).to_bytes(4, "little")
            data[36] = 1
            comm = BodyComm([(0, b"\x61\x82\x40" + bytes(5))])
            result = _bdy51(name, comm, data, BodyContext(comm))
            self.assertEqual(result, 1026 if "NewKey" in name else 1025)
            self.assertNotIn("finalize", comm.events)
        data = bytearray(40)
        data[4:8] = (8).to_bytes(4, "little")
        comm = BodyComm([(0, b"\x61\x82\x44" + bytes(5))] * 610)
        ctx = BodyContext(comm)
        self.assertEqual(
            _bdy51("Ex2BDY_51_NewKeyRegistration_Before_Remove_Key", comm, data, ctx),
            1027,
        )
        self.assertEqual(ctx.clock, 61000)
        self.assertNotIn("finalize", comm.events)

    def test_bdy_registered_key_dtc_precedence_and_clear(self) -> None:
        self.assertEqual(self.bdy("StatusChkRegisteredKey", mode=0x40)[0], 1008)
        self.assertEqual(self.bdy("StatusChkRegisteredKey", mode=0x44)[0], 1018)
        for codes, expected in (
            (b"\x94\x02\x94\x01", 1021),
            (b"\x94\x01", 1022),
            (b"\x94\x05", 1022),
            (b"\x01\x94", 1006),
        ):
            comm = BodyComm([(0, b"\x53" + bytes((len(codes) // 2,)) + codes)])
            self.assertEqual(_bdy_dtc(comm), expected)
        for code, result in ((0x9402, 1019), (0x9401, 1022), (0x1234, 1006)):
            data = bytearray(40)
            data[4:8] = (8).to_bytes(4, "little")
            comm = BodyComm(
                [
                    (0, b"\x61\x82\0" + bytes(5)),
                    (0, b"\x53\x01" + code.to_bytes(2, "big")),
                    (0, b"\x54"),
                    (0, bytes(2)),
                ]
            )
            self.assertEqual(
                _bdy51(
                    "Ex2BDY_51_StatusChkRegisteredKey", comm, data, BodyContext(comm)
                ),
                result,
            )
            self.assertEqual(comm.events[-1], "finalize")

    def test_mm_history_expands_selected_sparse_mask(self) -> None:
        data = bytearray(b"x" * 131)
        data[1] = 5
        data[2:7] = b"\x01\0\x01\0\x01"
        data[64:68] = (3).to_bytes(4, "little")
        comm = BodyComm([(0, b"\x61\x63ABC")])
        self.assertEqual(_mm_history(comm, data, False), 0)
        self.assertEqual(data[68:75], b"\x61\x63A\0B\0C")
        self.assertEqual(data[75:131], bytes(56))
        self.assertEqual(comm.events[-1], "finalize")

    def test_mm_disc_copies_transport_reply_before_length_error(self) -> None:
        for status, reply, expected in (
            (0, b"\x61\x61AB", 0),
            (0, b"\x61\x61A", 3),
            (7, b"FAULT", 7),
        ):
            data = bytearray(4132)
            data[4128:4132] = (4).to_bytes(4, "little")
            comm = BodyComm([(status, reply)])
            self.assertEqual(_mm_history(comm, data, True), expected)
            self.assertEqual(data[: len(reply)], reply)
            self.assertEqual(comm.events[-1], "finalize")

    def test_mm09_mm10_exact_build_fields_and_registry(self) -> None:
        from scripts.utility_ex_ty_body import _mm_pending_field

        expected = {
            SHA_12_TY: "native_rva:b940",
            SHA_PLUS_TY: "native_rva:142f0",
            SHA_18_TY: "native_global:100f8194",
        }
        for source, field in expected.items():
            self.assertEqual(_mm_pending_field(source), field)
            comm = BodyComm([])
            offsets = [4128] * 256
            offsets[0x63] = 0
            comm.support_snapshot = lambda kind, offsets=offsets: (
                0,
                b"\x63\x01\xff",
                tuple(offsets),
            )
            self.assertEqual(_mm_support(comm, bytearray(136), False, field), 0)
            self.assertIn((field, 150), comm.events)
            comm = BodyComm([(0, b"\x61\x63A")])
            data = bytearray(131)
            data[1] = 1
            data[2] = 1
            data[64:68] = (1).to_bytes(4, "little")
            self.assertEqual(_mm_history(comm, data, False, field), 0)
            self.assertIn((field, 150), comm.events)
        self.assertEqual(
            set(supported_exports(SHA_12_TY)) - set(SMRT_EXPORTS),
            {MM_SUPPORT[0], MM_SUPPORT[1], MM_HISTORY, MM_DISC},
        )
        for source in (SHA_12_TY, SHA_PLUS_TY):
            exports = supported_exports(source)
            self.assertTrue(
                {MM_SUPPORT[0], MM_SUPPORT[1], MM_HISTORY, MM_DISC} <= set(exports)
            )
        self.assertEqual(
            supported_exports(SHA_PLUS_TY)[-4:], (*MM_SUPPORT, MM_HISTORY, MM_DISC)
        )
        self.assertFalse(
            {MM_SUPPORT[0], MM_SUPPORT[1], MM_HISTORY, MM_DISC}
            & set(supported_exports("0" * 64))
        )

    def test_mm10_seven_groups_and_sparse_partial_store_order(self) -> None:
        comm = BodyComm([])
        offsets = [4128] * 256
        offsets[0x61] = 0
        payload = bytearray(56)
        for first in range(3, 59, 8):
            payload[first - 3 : first + 5] = b"\xff" * 8
        comm.support_snapshot = lambda kind: (
            0,
            b"\x61" + bytes((len(payload),)) + payload,
            tuple(offsets),
        )
        data = bytearray(b"\xa5" * 4220)
        self.assertEqual(_mm_support(comm, data, True, "native_rva:b940"), 0)
        self.assertEqual(int.from_bytes(data[4128:4132], "little"), 58)
        self.assertEqual(data[4216:4220], bytes(4))
        self.assertEqual(int.from_bytes(data[4132:4136], "little"), 2)
        self.assertEqual(int.from_bytes(data[4204:4208], "little"), 50)

        offsets[0x61] = 0
        payload = bytearray(8)
        payload[:2] = b"\xff\xff"
        payload[2] = 0xFF
        comm = BodyComm([])
        comm.support_snapshot = lambda kind: (
            0,
            b"\x61\x08" + payload,
            tuple(offsets),
        )
        data = bytearray(b"\xa5" * 4220)
        self.assertEqual(_mm_support(comm, data, True), 0)
        self.assertEqual(int.from_bytes(data[4128:4132], "little"), 4)
        self.assertEqual(data[4140:4144], b"\xa5" * 4)
        self.assertEqual(comm.events[-1], "finalize")

    def test_mm09_failed_producer_does_not_commit_output(self) -> None:
        for payload in (None, b"\0\0"):
            comm = BodyComm([])
            offsets = [4128] * 256
            if payload is not None:
                offsets[0x63] = 0
            raw = b"" if payload is None else b"\x63\x02" + payload
            comm.support_snapshot = lambda kind, raw=raw, offsets=offsets: (
                0,
                raw,
                tuple(offsets),
            )
            data = bytearray(b"\xa5" * 136)
            self.assertEqual(_mm_support(comm, data, False), 22)
            self.assertEqual(data, b"\xa5" * 136)
            self.assertEqual(comm.events[-1], "finalize")

    def test_mm09_mm10_faults_finalize_and_preserve_sdk_exception(self) -> None:
        comm = BodyComm([])
        comm.initial_status = 9
        self.assertEqual(_mm_history(comm, bytearray(131), False), 9)
        self.assertEqual(comm.events, [("init", 0), "finalize"])

        comm = BodyComm([])
        failure = OSError("selected SDK fault")

        def fail_exchange(request: bytes) -> tuple[int, bytes]:
            raise failure

        comm.exchange = fail_exchange
        with self.assertRaises(OSError) as caught:
            _mm_history(comm, bytearray(131), False)
        self.assertIs(caught.exception, failure)
        self.assertEqual(comm.events[-1], "finalize")

    def test_public_argument_bounds_fail_before_controller_access(self) -> None:
        ctx = BodyContext(BodyComm([]))
        cases = [
            (SMRT35_GET, (bytearray(5),)),
            (BDY51[0], (bytearray(39),)),
            (FCM_PCS_CHECK, (bytearray(3),)),
            (PLG3, (bytearray(28),)),
            (MM_DISC, (bytearray(4131),)),
        ]
        cases[3][1][0][:4] = (1).to_bytes(4, "little")
        software = bytearray(43)
        software[8:12] = (22).to_bytes(4, "little")
        cases.append((DCM_SOFTWARE, (software,)))
        history = bytearray(131)
        history[1] = 62
        cases.append((MM_HISTORY, (history,)))
        bdy = bytearray(40)
        bdy[:4] = (0xFFFFFFFF).to_bytes(4, "little")
        cases.append((BDY51[0], (bdy,)))
        with patch(
            "scripts.utility_ex_ty_body.supported_exports", return_value=EXPORTS_18
        ):
            for export, args in cases:
                with self.subTest(export=export), self.assertRaises(ValueError):
                    run_body(export, args, ctx)
        self.assertFalse(ctx.events)
        self.assertFalse(ctx.controller.events)

    def test_frame_exception_propagates_with_cleanup(self) -> None:
        comm = BodyComm([(0, b"\x71\x02\x16\x0c")])
        ctx = BodyContext(comm)
        with (
            patch.object(
                ctx, "native_sleep", side_effect=OSError("injected clock fault")
            ),
            self.assertRaisesRegex(OSError, "clock fault"),
        ):
            _poll(comm, bytearray(4), True, ctx)
        self.assertEqual(comm.events[-1], "finalize")
        comm = BodyComm([])
        with (
            patch.object(comm, "exchange", side_effect=OSError("injected frame fault")),
            self.assertRaisesRegex(OSError, "frame fault"),
        ):
            _dcm_read(comm, bytearray(4132), False)
        self.assertEqual(comm.events[-1], "finalize")

    def test_plg_classic_lid_guard_command_and_status_mapping(self) -> None:
        for value, expected in ((0, 0), (0x20, 1001)):
            data = bytearray(16)
            data[:4] = (2).to_bytes(4, "little")
            data[4:8] = (1).to_bytes(4, "little")
            comm = BodyComm([(0, bytes((0x61, 0x25, value))), (0, b"\x7b\x24")])
            self.assertEqual(_plg_classic(PLG_CLASSIC[0], comm, data), expected)
            self.assertEqual(b"\x3b\x24\x01" in comm.events, not expected)
            self.assertEqual(comm.events[-1], "finalize")
        comm = BodyComm([(7, b"")])
        self.assertEqual(_plg_classic(PLG_CLASSIC[0], comm, bytearray(16)), 1010)
        for code, result in (
            (0x80, 1002),
            (0x81, 1003),
            (0x82, 1004),
            (0x83, 1005),
            (0x84, 1009),
            (0x85, 1006),
            (0x86, 1007),
            (0x87, 1008),
            (0, 1009),
        ):
            data = bytearray(16)
            data[8:12] = (2).to_bytes(4, "little")
            data[12:16] = (1).to_bytes(4, "little")
            comm = BodyComm([(0, bytes((0x61, 0x7F, code)))])
            self.assertEqual(_plg_classic(PLG_CLASSIC[2], comm, data), result)

    def test_fcm13_exact_did_payload_and_fault_output_clearing(self) -> None:
        for reply, expected in (
            (b"\x62\x10\xd2" + b"ABCDEFGHIJKLMNOP", 0),
            (b"\x62\x10\xd2" + bytes(15), 3),
            (b"\x62\x10\xd3" + bytes(16), 3),
        ):
            comm = BodyComm([(0, reply)])
            comm.session_results.extend([0, 7])
            data = bytearray(b"x" * 16)
            self.assertEqual(_fcm_info(comm, data), expected)
            self.assertEqual(data, b"ABCDEFGHIJKLMNOP" if not expected else bytes(16))
            self.assertEqual(comm.session_options, [(True, False), (False, True)])
            self.assertEqual(comm.events[-1], "finalize")

    def test_dcm_write_readback_and_restore_status_precedence(self) -> None:
        for value, expected in ((0, 0), (1, 0), (2, 3)):
            comm = BodyComm(
                [(0, b"\x6e\x20\x40"), (0, b"\x62\x20\x40" + bytes((value,)))]
            )
            data = bytearray((1, 9))
            self.assertEqual(_dcm_setting(comm, data), expected)
            self.assertEqual(data[1], value)
            self.assertIn(b"\x2e\x20\x40\x01", comm.events)
            self.assertEqual(comm.events[-1], "finalize")
        comm = BodyComm([(7, b"")])
        comm.session_results.extend([0, 0, 9])
        self.assertEqual(_dcm_setting(comm, bytearray(2)), 9)

    def test_dcm_enable_and_routine_have_different_restore_precedence(self) -> None:
        for routine in (False, True):
            comm = BodyComm([(0, b"\x71\x01\x11\x03" if routine else b"\x6e\x20\x04")])
            comm.session_results.extend([0, 9])
            self.assertEqual(_dcm_enable(comm, routine), 0 if routine else 9)
            self.assertEqual(comm.session_options, [(True, False), (False, True)])
            self.assertEqual(comm.events[-1], "finalize")

    def test_dcm37_uses_mapped_native_nrc_field_and_cleans_up(self) -> None:
        for mapped, expected in ((0x69, 0x69), (0x22, 7), (999, 7)):
            comm = BodyComm([(7, b"\x7f\x2e\x22")])
            with patch.object(
                comm, "read_field", return_value=mapped, create=True
            ) as getter:
                self.assertEqual(_dcm_nrc(comm), expected)
                getter.assert_called_once_with("native_10b0")
            self.assertEqual(comm.events[-1], "finalize")
        comm = BodyComm([(7, b"\x7f\x2e\x22")])
        with patch.object(comm, "read_field", None), self.assertRaises(TYSourceError):
            _dcm_nrc(comm)
        self.assertEqual(comm.events[-1], "finalize")

    def test_ac_classic_selected_size_and_exact_echo(self) -> None:
        for history, identifier in ((False, 0x16), (True, 0xDA)):
            for size in (0, 1, 5):
                comm = BodyComm([(0, bytes((0x7B, identifier)))])
                self.assertEqual(_ac_classic(comm, size, history), 0)
                request = next(e for e in comm.events if isinstance(e, bytes))
                self.assertEqual(len(request), size + 2)
                self.assertEqual(request[:2], bytes((0x3B, identifier)))
                if size:
                    self.assertEqual(request[2:], b"\x01" + bytes(size - 1))
                self.assertEqual(comm.events[-1], "finalize")
            comm = BodyComm([(0, b"\x7b\0")])
            self.assertEqual(_ac_classic(comm, 1, history), 3)

    def test_csn_reset_action_guard_and_native_cleanup(self) -> None:
        comm = BodyComm([(0, b"\x71\x01\x11\x05")])
        comm.session_results.extend([0, 9])
        self.assertEqual(_csn_reset(comm, 0), 0)
        self.assertEqual(comm.session_options, [(True, False), (False, True)])
        self.assertEqual(comm.events[-1], "finalize")
        comm = BodyComm([])
        self.assertEqual(_csn_reset(comm, 1), 0)
        self.assertFalse(any(isinstance(e, bytes) for e in comm.events))

    def test_csn_tire_read_output_and_sparse_mask_write(self) -> None:
        data = bytearray(8266)
        data[:4] = (2).to_bytes(4, "little")
        comm = BodyComm([(0, b"\x61\x18\xa5\x7f")])
        self.assertEqual(_csn_tire(comm, data, False), 0)
        self.assertEqual(data[4136:4140], b"\x61\x18\xa5\x7f")
        self.assertEqual(data[8264], 0xA0)
        data[4:8] = (4).to_bytes(4, "little")
        data[8:12] = b"\xff\0\x0f\xf0"
        data[4138:4141] = b"\x12\x34\x56"
        data[8265] = 0x80
        comm = BodyComm([(0, b"\x7b\x18")])
        self.assertEqual(_csn_tire(comm, data, True), 0)
        self.assertIn(b"\x3b\x18\x92\0\x04\x50", comm.events)
        self.assertEqual(comm.events[-1], "finalize")

    def test_public_source_guards_and_dispatch(self) -> None:
        ctx = BodyContext(BodyComm([]))
        with self.assertRaises(TYSourceError):
            run_body(FCM_PCS_STOP, (), ctx)
        # Only hash routing is substituted: original algorithms consume authored primitives.
        with patch(
            "scripts.utility_ex_ty_body.supported_exports", return_value=EXPORTS_18
        ):
            ctx.module_bytes += b"tamper"
            with self.assertRaises(TYSourceError):
                run_body(FCM_PCS_STOP, (), ctx)
            ctx.module_bytes = ctx.module_bytes[:-6]
            with self.assertRaises(ValueError):
                run_body(FCM_PCS_STOP, (1, 2), ctx)
            ctx.controller.replies = [(9, b"")]
            self.assertEqual(run_body(FCM_PCS_STOP, (), ctx), 1003)
            self.assertEqual(ctx.controller.events[-1], "finalize")


if __name__ == "__main__":
    unittest.main()
