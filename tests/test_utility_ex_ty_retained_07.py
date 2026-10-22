"""Authored native buffer/wire vectors; no OEM execution, device or network."""

from __future__ import annotations

import hashlib
import struct
import unittest
from unittest.mock import patch

from scripts import utility_ex_ty_retained_07 as body
from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import SHA_12_TY, SHA_PLUS_TY, TYSourceError
from tests.test_utility_ex_ty import Context as BaseContext


class Context(BaseContext):
    def __init__(self, replies: list[tuple[int, bytes]] | None = None) -> None:
        super().__init__(replies)
        self.state["host:x87_control_word"] = 0x027F
        self.state["host:mxcsr"] = 0x1F80

    def native_sleep(self, milliseconds: int) -> None:
        self.sleep(milliseconds)


class Retained07Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = hashlib.sha256(b"authored TY module").hexdigest()
        self.sources = patch.object(
            body, "_SOURCES", (SHA_12_TY, self.identity, SHA_PLUS_TY)
        )
        self.pending = patch.dict(body._PENDING, {self.identity: "native_rva:b940"})
        self.sources.start()
        self.pending.start()
        self.addCleanup(self.sources.stop)
        self.addCleanup(self.pending.stop)

    def call(self, name: str, context: Context, data: bytearray) -> int:
        return body.run_body(name, (data,), context)

    def data(self, *values: int, size: int = 96) -> bytearray:
        data = bytearray(size)
        for index, value in enumerate(values):
            struct.pack_into("<I", data, index * 4, value)
        return data

    def snapshot(self, records: dict[int, bytes]) -> tuple[int, bytes, tuple[int, ...]]:
        data = bytearray(0x1020)
        offsets = [0x1020] * 256
        cursor = 0
        for identifier, value in records.items():
            offsets[identifier] = cursor
            data[cursor : cursor + 2] = bytes((identifier, len(value)))
            data[cursor + 2 : cursor + 2 + len(value)] = value
            cursor += len(value) + 2
        return 0, bytes(data), tuple(offsets)

    def install_snapshots(
        self, context: Context, values: list[tuple[int, bytes, tuple[int, ...]]]
    ) -> None:
        def snapshot(kind: int) -> tuple[int, bytes, tuple[int, ...]]:
            context.controller.events.append(("snapshot", kind))
            return values.pop(0)

        context.controller.support_snapshot = snapshot

    def test_exact_pair_domain_exclusion(self) -> None:
        self.assertEqual(len(body.supported_exports(self.identity)), 18)
        self.assertEqual(len(body.supported_exports(SHA_12_TY)), 9)
        self.assertEqual(body.supported_exports("0" * 64), ())
        self.assertNotIn(
            "Ex2DOOR_01_StartConnectionHistoryClear",
            body.supported_exports(SHA_PLUS_TY),
        )

    def test_literal_res03_zero_padding_and_ack(self) -> None:
        context = Context([(0, b"\x7b\x62")])
        self.assertEqual(
            self.call("Ex2RES_03_InitialRegistrationRequest", context, self.data(4)), 0
        )
        self.assertEqual(
            context.controller.events,
            [("init", 0), ("native_rva:b940", 150), b"\x3b\x62\x40\0\0\0", "finalize"],
        )

    def test_res_remote_ack_requires_service_and_exact_length(self) -> None:
        for reply, expected in (
            (b"\x7b\x62", 0),
            (b"\0\x62", 3),
            (b"\x7b\x62\0", 3),
            (b"", 3),
        ):
            context = Context([(0, reply)])
            self.assertEqual(
                self.call("Ex2RES_04_RemoteStartRegistration", context, self.data(2)),
                expected,
            )
            self.assertIn(b"\x3b\x62\x08\0", context.controller.events)
            self.assertEqual(context.controller.events[-1], "finalize")

    def test_res_support_counts_nonzero_bytes(self) -> None:
        context = Context()
        self.install_snapshots(context, [self.snapshot({0x62: b"\x40\0\x02"})])
        data = self.data()
        self.assertEqual(self.call("Ex2RES_03_SupportCheck", context, data), 0)
        self.assertEqual(struct.unpack_from("<I", data)[0], 2)
        self.assertEqual(context.controller.events[-1], "finalize")

    def test_missing_and_malformed_support(self) -> None:
        for snap, expected in (
            (self.snapshot({}), 22),
            ((0, b"\x62\xff", tuple([0] * 256)), 99),
            ((17, b"", ()), 17),
        ):
            context = Context()
            self.install_snapshots(context, [snap])
            self.assertEqual(
                self.call("Ex2RES_03_SupportCheck", context, self.data()), expected
            )

    def test_gs_status_preserves_nonstatus_buffer_fields(self) -> None:
        context = Context([(0, b"\x61\x27\x83\x00")])
        data = self.data(4, 9, 0xAABBCC00)
        self.assertEqual(self.call("Ex2GS_01_CheckShutterStatus", context, data), 0)
        self.assertEqual(data[8:12], b"\x01\xcc\xbb\xaa")
        self.assertEqual(
            context.controller.events[:2], [("native_rva:b940", 150), ("init", 0)]
        )

    def test_gs_fault_still_copies_received_status(self) -> None:
        context = Context([(18, b"\0\0\x03")])
        data = self.data(4)
        self.assertEqual(self.call("Ex2GS_01_CheckShutterStatus", context, data), 18)
        self.assertEqual(data[8], 1)
        self.assertEqual(context.controller.events[-1], "finalize")

    def test_gs_shift_inverts_status_and_maps_write_fault(self) -> None:
        context = Context([(0, b"\x7b\x27"), (0, b"\x61\x27\x01")])
        self.assertEqual(
            self.call("Ex2GS_01_ShiftMode", context, self.data(3, 3, 0)), 0
        )
        self.assertIn(b"\x3b\x27\x01", context.controller.events)
        context = Context([(17, b"")])
        self.assertEqual(
            self.call("Ex2GS_01_ShiftMode", context, self.data(3, 3, 1)), 10000
        )
        self.assertIn(b"\x3b\x27\x00", context.controller.events)

    def test_gs_support_retains_lengths(self) -> None:
        context = Context()
        self.install_snapshots(
            context,
            [self.snapshot({0x27: b"\x01\0\x01"}), self.snapshot({0x27: b"\x01\x05"})],
        )
        data = self.data()
        self.assertEqual(self.call("Ex2GS_01_SupportCheck", context, data), 0)
        self.assertEqual(struct.unpack_from("<II", data), (4, 4))

    def test_gs02_support_composes_three_descriptors(self) -> None:
        context = Context()
        self.install_snapshots(
            context,
            [
                self.snapshot({0x21: b"\xff\x01", 0x26: b"\x40\0\x01"}),
                self.snapshot({1: b"\x40\x01"}),
            ],
        )
        data = self.data()
        self.assertEqual(self.call("Ex2GS_02_SendMessage", context, data), 0)
        self.assertEqual(struct.unpack_from("<III", data), (2, 2, 2))

    def test_gs02_poll_release_and_native_status(self) -> None:
        context = Context(
            [(0, b"\x61\x21\0"), (0, b"\x70\x01"), (0, b"\x61\x26\x40"), (9, b"")]
        )
        self.assertEqual(
            self.call("Ex2GS_02_SendMessage", context, self.data(1, 1, 1, 1)), 9005
        )
        self.assertEqual(context.controller.events[-2:], [b"\x30", "finalize"])
        self.assertIn(b"\x30\x01\0\x40", context.controller.events)

    def test_gs02_cancellation_releases_actuator(self) -> None:
        context = Context([(0, b"\x61\x21\0"), (0, b"\x70\x01"), (0, b"")])
        context.cancel_on_sleep = True
        with self.assertRaises(Cancelled):
            self.call("Ex2GS_02_SendMessage", context, self.data(1, 1, 1, 1))
        self.assertEqual(context.controller.events[-2:], [b"\x30", "finalize"])

    def test_init_fault_cleanup_and_host_identity(self) -> None:
        context = Context()
        context.controller.initial_status = 51
        self.assertEqual(self.call("Ex2RES_03_SupportCheck", context, self.data()), 51)
        self.assertEqual(context.controller.events, [("init", 0), "finalize"])
        context = Context()
        context.module_bytes += b"wrong"
        with self.assertRaises(TYSourceError):
            self.call("Ex2RES_03_SupportCheck", context, self.data())
        self.assertEqual(context.events, [])

    def test_invalid_buffer_and_transmit_bounds(self) -> None:
        context = Context()
        with self.assertRaises(ValueError):
            self.call("Ex2RES_03_SupportCheck", context, bytearray(3))
        with self.assertRaises(ValueError):
            self.call(
                "Ex2RES_03_InitialRegistrationRequest", context, self.data(0x1020)
            )
        self.assertEqual(context.controller.events[-1], "finalize")

    def test_pcm_literal_wire_and_zero_divisor(self) -> None:
        context = Context(
            [
                (0, b"\x90\x01"),
                (0, b"\x62\xda\xb4\x01"),
                (0, b"\x62\xda\xd8" + bytes(32)),
            ]
        )
        self.assertEqual(self.call("Ex2PCM_04_SendMessage", context, self.data()), 1001)
        self.assertEqual(
            context.controller.events[-3:],
            [b"\x22\xda\xb4", b"\x22\xda\xd8", "finalize"],
        )

    def test_pcm_computation_and_output_layout(self) -> None:
        values = (0, 100, 100, 100, 100, 1, 1, 1)
        payload = b"".join(value.to_bytes(4, "big") for value in values)
        context = Context(
            [(0, b"\x90\x01"), (0, b"\x62\xda\xb4\x01"), (0, b"\x62\xda\xd8" + payload)]
        )
        data = self.data()
        self.assertEqual(self.call("Ex2PCM_04_SendMessage", context, data), 0)
        self.assertEqual(struct.unpack_from("<dd", data, 8), (100.0, 0.0))
        self.assertEqual(data[24:28], (100).to_bytes(4, "big"))

    def sil_context(self, replies: list[tuple[int, bytes]]) -> Context:
        context = Context(replies)
        context.state.update(
            {
                "native_global:1013fa48": 123,
                "native_global:1013fa38": 456,
                "native_global:1013fa3c": 789,
            }
        )
        return context

    def assert_sil_restored(self, context: Context, data: bytearray) -> None:
        self.assertEqual(struct.unpack_from("<III", data, 0x54), (123, 456, 789))
        self.assertEqual(context.state["native_global:1013fab0"], 0)
        self.assertEqual(context.state["native_global:1013fab4"], 123)
        self.assertEqual(context.state["native_global:1013fa38"], 456)
        self.assertEqual(context.state["native_global:1013fa3c"], 789)
        self.assertEqual(context.controller.events[-1], "finalize")

    def test_sil_support_descriptor_flag_and_restore(self) -> None:
        context = self.sil_context([])
        self.install_snapshots(context, [self.snapshot({0x12: b"\x01\x02\0\x02"})])
        data = self.data()
        self.assertEqual(self.call("Ex2RES_04_SupportCheck_SIL", context, data), 0)
        self.assertEqual(struct.unpack_from("<III", data, 12), (3, 3, 1))
        self.assert_sil_restored(context, data)
        context = self.sil_context([])
        self.install_snapshots(context, [self.snapshot({})])
        data = self.data()
        self.assertEqual(self.call("Ex2RES_04_SupportCheck_SIL", context, data), 0)
        self.assertEqual(struct.unpack_from("<I", data, 20)[0], 0)
        self.assert_sil_restored(context, data)

    def test_sil_support_function_reads_descriptor_bit(self) -> None:
        context = self.sil_context([(0, b"\x61\x12\0\x02\0")])
        data = self.data()
        struct.pack_into("<II", data, 12, 3, 3)
        self.assertEqual(
            self.call("Ex2RES_04_GetSupportFunction_SIL", context, data), 0
        )
        self.assertEqual(struct.unpack_from("<I", data, 24)[0], 1)
        self.assert_sil_restored(context, data)

    def test_sil_ecu_info_two_mutable_outputs(self) -> None:
        context = self.sil_context([(0, b"xxABCDEFGH"), (0, b"\x67\x07abcdef")])
        data = self.data()
        self.assertEqual(self.call("Ex2RES_04_GetEcuInfo_SIL", context, data), 0)
        self.assertEqual(data[0x2D:0x3B], b"ABCDEFGHabcdef")
        self.assert_sil_restored(context, data)

    def test_sil_send_key_native_rejection(self) -> None:
        for reply, expected in (
            (b"\x67\x08\x34", 0),
            (b"\x67\x08\x35", 9528),
            (b"\x67\x08", 3),
        ):
            context = self.sil_context([(0, reply)])
            data = self.data()
            data[0x3B:0x3E] = b"abc"
            struct.pack_into("<I", data, 0x48, 3)
            self.assertEqual(
                self.call("Ex2RES_04_SendKey_SIL", context, data), expected
            )
            self.assertIn(b"\x27\x08abc", context.controller.events)
            self.assert_sil_restored(context, data)

    def test_sil_keepalive_stop_and_cancel_restore(self) -> None:
        context = self.sil_context([(0, b"\x61\0abcd")])
        data = self.data()
        struct.pack_into("<I", data, 0x4C, 1)
        self.assertEqual(self.call("Ex2RES_04_KeepAlive_SIL", context, data), 0)
        self.assert_sil_restored(context, data)
        context = self.sil_context([(0, b"\x61\0abcd")])
        context.cancel_on_sleep = True
        data = self.data()
        with self.assertRaises(Cancelled):
            self.call("Ex2RES_04_KeepAlive_SIL", context, data)
        self.assert_sil_restored(context, data)

    def test_ldr09_retained_channel_then_completion(self) -> None:
        context = Context(
            [
                (0, b"\x90\x01"),
                (0, b"\x90\x03"),
                (0, b"\x71\x01\x11\x01"),
                (0, b"\x71\x03\x11\x01\x02"),
                (0, b"\x90\x01"),
            ]
        )
        data = self.data()
        self.assertEqual(self.call("Ex2LDR_09_SendMessage", context, data), 0)
        self.assertNotIn("finalize", context.controller.events)
        self.assertTrue(context.state["retained07:ldr09:active"])
        struct.pack_into("<I", data, 0, 1)
        self.assertEqual(self.call("Ex2LDR_09_SendMessage", context, data), 0)
        self.assertFalse(context.state["retained07:ldr09:active"])
        self.assertEqual(context.controller.events[-1], "finalize")

    def test_ldr09_error_code_and_output(self) -> None:
        context = Context(
            [
                (0, b"\x90\x01"),
                (0, b"\x90\x03"),
                (17, b""),
                (0, b"\x62\x10\x05\x88"),
                (0, b"\x90\x01"),
            ]
        )
        data = self.data()
        self.assertEqual(self.call("Ex2LDR_09_SendMessage", context, data), 2002)
        self.assertEqual(data[4], 0x88)
        self.assertEqual(context.controller.events[-1], "finalize")

    def test_ldr10_and11_support_native_bit_checks(self) -> None:
        for number in (10, 11):
            replies = []
            for _ in range(3):
                replies += [
                    (0, b"\x90\x01"),
                    (0, b"\x90\x03"),
                    (0, b"\x62\x01\x01\0\0\x80" + bytes(29)),
                    (0, b"\x62\x10\0\x60\x60" + bytes(30)),
                    (0, bytes((0x62, 0x10, 2 if number == 10 else 3, 0x80))),
                    (0, b"\x90\x01"),
                ]
            context = Context(replies)
            self.assertEqual(
                self.call(
                    f"Ex2LDR_{number:02}_SendMessage", context, self.data(size=0x3070)
                ),
                0,
            )
            self.assertEqual(
                [
                    x
                    for x in context.controller.events
                    if isinstance(x, tuple) and x[0] == "native_lower_38"
                ],
                [
                    ("native_lower_38", 263),
                    ("native_lower_38", 264),
                    ("native_lower_38", 265),
                ],
            )

    def test_ldr12_read_modify_write_verify_four_targets(self) -> None:
        replies = []
        for _ in range(4):
            replies += [
                (0, b"\x90\x01"),
                (0, b"\x90\x03"),
                (0, b"\x62\x02\x04\x01\x02"),
                (0, b"\x6e\x02\x04"),
                (0, b"\x62\x02\x04\x01\x42"),
                (0, b"\x90\x01"),
            ]
        context = Context(replies)
        self.assertEqual(self.call("Ex2LDR_12_SendMessage", context, self.data(1)), 0)
        self.assertEqual(context.controller.events.count(b"\x2e\x02\x04\x01\x42"), 4)
        self.assertEqual(context.controller.events[-1], "finalize")

    def test_gs02_three_byte_actuator_ack_native_codes(self) -> None:
        for tail, expected in ((0, 9005), (1, 3)):
            context = Context([(0, b"\x61\x21\0"), (0, bytes((0x70, 1, tail)))])
            self.assertEqual(
                self.call("Ex2GS_02_SendMessage", context, self.data(1, 1, 1, 1)),
                expected,
            )
            self.assertNotIn(b"\x30", context.controller.events)
            self.assertEqual(context.controller.events[-1], "finalize")

    def test_gs02_strict_twentyfive_second_boundary(self) -> None:
        context = Context(
            [(0, b"\x61\x21\0"), (0, b"\x70\x01")]
            + [(0, b"\x61\x26\0")] * 26
            + [(0, b"")]
        )
        self.assertEqual(
            self.call("Ex2GS_02_SendMessage", context, self.data(1, 1, 1, 1)), 0
        )
        self.assertEqual(context.clock, 26000)
        self.assertEqual(context.controller.events.count(b"\x21\x26"), 26)
        self.assertEqual(context.controller.events[-2:], [b"\x30", "finalize"])

    def test_res04_support_outputs_and_optional_ecu_pattern(self) -> None:
        context = Context()
        self.install_snapshots(
            context,
            [
                self.snapshot({0x21: b"\xf0\x0f\0"}),
                self.snapshot({0x62: b"\x08\0\0\0"}),
            ],
        )
        data = self.data()
        self.assertEqual(self.call("Ex2RES_04_SupportCheck", context, data), 0)
        self.assertEqual(struct.unpack_from("<III", data), (4, 2, 1))
        context = Context([(0, b"\x61\x21\xc1\x1c")])
        data = self.data(0, 2)
        struct.pack_into("<I", data, 0x50, 1)
        self.assertEqual(self.call("Ex2RES_04_SupportCheck", context, data), 9008)

    def test_sil_snapshot_fault_sets_flag_and_restores(self) -> None:
        context = self.sil_context([])
        self.install_snapshots(context, [(71, b"", ())])
        data = self.data()
        struct.pack_into("<I", data, 20, 1)
        self.assertEqual(self.call("Ex2RES_04_SupportCheck_SIL", context, data), 71)
        self.assertEqual(struct.unpack_from("<I", data, 20)[0], 0)
        self.assert_sil_restored(context, data)

    def test_ldr10_reads_variable_lengths_and_native_word_descriptors(self) -> None:
        replies = []
        for index in range(3):
            replies += [
                (0, b"\x90\x01"),
                (0, b"\x90\x03"),
                (0, b"\x62\x10\x02\0" + bytes((0x80 if index == 1 else 0,))),
                (
                    0,
                    bytes((0x62, 0x10, 0xB if index == 1 else 0xA))
                    + b"ABCDEF"[: 6 if index == 1 else 5],
                ),
                (9, b""),
            ]
        context = Context(replies)
        data = self.data(1, size=0x3070)
        self.assertEqual(self.call("Ex2LDR_10_SendMessage", context, data), 0)
        self.assertEqual(struct.unpack_from("<HHH", data, 0x3064), (5, 6, 5))
        self.assertEqual(
            struct.unpack_from("<HHH", data, 0x306A), (0x100A, 0x100B, 0x100A)
        )
        for index in range(3):
            self.assertEqual(data[4 + index * 0x1020 : 9 + index * 0x1020], b"ABCDE")

    def test_ldr11_write_verify_and_mismatch_cleanup(self) -> None:
        for mismatch in (False, True):
            replies = []
            data = self.data(1, size=0x3070)
            for index in range(3):
                data[8 + index * 0x1020 : 13 + index * 0x1020] = b"abcde"
                replies += [
                    (0, b"\x90\x01"),
                    (0, b"\x90\x03"),
                    (0, b"\x71\x01\x11\x04"),
                    (0, b"\x71\x03\x11\x04\x02"),
                    (0, b"\x62\x10\x0b" + (b"xbcde!" if mismatch else b"abcde!")),
                    (0, b"\x62\x10\x03\0\0"),
                    (0, b"\x90\x01"),
                ]
            context = Context(replies)
            self.assertEqual(
                self.call("Ex2LDR_11_SendMessage", context, data),
                2000 if mismatch else 0,
            )
            self.assertIn(b"\x31\x01\x11\x04\x01abcde", context.controller.events)
            self.assertEqual(context.controller.events[-1], "finalize")

    def test_ldr12_suffix_ack_and_verification_mismatch(self) -> None:
        context = Context(
            [
                (0, b"\x90\x01"),
                (0, b"\x90\x03"),
                (0, b"\x62\x02\x04\x01\x02"),
                (0, b"\x6e\x02\x04extra"),
                (0, b"\x62\x02\x04\x01\x02"),
                (0, b"\x90\x01"),
            ]
        )
        self.assertEqual(
            self.call("Ex2LDR_12_SendMessage", context, self.data(1)), 2000
        )
        self.assertEqual(context.controller.events[-1], "finalize")

    def test_actual97_aggregate_dispatch_preserves_output_identity(self) -> None:
        from scripts.utility_ex_ty import run_body

        context = Context([(0, b"\x61\x27\x01")])
        data = self.data(3)
        self.assertEqual(run_body("Ex2GS_01_CheckShutterStatus", (data,), context), 0)
        self.assertEqual(data[8], 1)

    def test_pcm_x87_precision_is_explicit_and_changes_halfway_output(self) -> None:
        context = Context()
        values = dict.fromkeys(range(24, 56, 4), 7)
        values[40] = 0
        context.state["host:x87_control_word"] = 0x027F
        self.assertEqual(body._pcm_calculate(context, values)[0], 10.0)
        context.state["host:x87_control_word"] = 0x037F
        self.assertEqual(body._pcm_calculate(context, values)[0], 0.0)
        context.state.pop("host:x87_control_word")
        with self.assertRaises(TYSourceError):
            body._pcm_calculate(context, values)

    def test_binary_instruction_rounding_ties_and_directions(self) -> None:
        from fractions import Fraction

        halfway = Fraction(17, 16)
        self.assertEqual(body._binary(halfway, 4, 0), Fraction(1))
        self.assertEqual(body._binary(halfway, 4, 1), Fraction(1))
        self.assertEqual(body._binary(halfway, 4, 2), Fraction(9, 8))
        self.assertEqual(body._binary(-halfway, 4, 1), Fraction(-9, 8))
        self.assertEqual(body._binary(-halfway, 4, 2), Fraction(-1))
        self.assertEqual(body._binary(-halfway, 4, 3), Fraction(-1))

    def test_ldr_session_helpers_preserve_normal_first_and_error_stop(self) -> None:
        context = Context(
            [
                (0, b"\x90\x01"),
                (0, b"\x90\x03"),
                (17, b""),
                (0, b"\x62\x10\x05\x88"),
                (17, b""),
            ]
        )
        original = context.controller.session
        calls: list[tuple[int, bool, bool]] = []

        def session(
            mode: int,
            keepalive: int = 1,
            *,
            normal_first: bool = False,
            stop_on_error: bool = False,
        ) -> int:
            calls.append((mode, normal_first, stop_on_error))
            return original(
                mode, keepalive, normal_first=normal_first, stop_on_error=stop_on_error
            )

        context.controller.session = session
        self.assertEqual(self.call("Ex2LDR_09_SendMessage", context, self.data()), 2002)
        self.assertIn((3, True, False), calls)
        self.assertEqual(calls[-1], (1, False, True))
        self.assertEqual(context.controller.events[-1], "finalize")

    def test_pcm_missing_environment_fails_after_retaining_calibration_outputs(
        self,
    ) -> None:
        payload = b"".join(
            value.to_bytes(4, "big") for value in (0, 100, 100, 100, 100, 1, 1, 1)
        )
        context = Context(
            [(0, b"\x90\x01"), (0, b"\x62\xda\xb4\x01"), (0, b"\x62\xda\xd8" + payload)]
        )
        context.state.pop("host:x87_control_word")
        data = self.data()
        with self.assertRaises(TYSourceError):
            self.call("Ex2PCM_04_SendMessage", context, data)
        self.assertEqual(data[24:28], (100).to_bytes(4, "big"))
        self.assertEqual(context.controller.events[-1], "finalize")

    def test_pcm_plus_requires_mxcsr_and_reserved_precision_fails(self) -> None:
        context = Context()
        context.module_sha256 = SHA_PLUS_TY
        values = dict.fromkeys(range(24, 56, 4), 100)
        values[40] = 0
        self.assertIsInstance(body._pcm_calculate(context, values)[0], float)
        context.state.pop("host:mxcsr")
        with self.assertRaises(TYSourceError):
            body._pcm_calculate(context, values)
        context.state["host:x87_control_word"] = 0x017F
        with self.assertRaises(TYSourceError):
            body._pcm_calculate(context, values)

    def test_host_exchange_exception_identity_survives_finalization(self) -> None:
        context = Context()
        failure = RuntimeError("authored primitive failure")

        def exchange(request: bytes) -> tuple[int, bytes]:
            raise failure

        context.controller.exchange = exchange
        with self.assertRaises(RuntimeError) as raised:
            self.call("Ex2RES_03_InitialRegistrationRequest", context, self.data(4))
        self.assertIs(raised.exception, failure)
        self.assertEqual(context.controller.events[-1], "finalize")

    def test_sil_factory_host_exception_identity_restores_globals(self) -> None:
        context = self.sil_context([])
        failure = RuntimeError("authored controller factory failure")

        def factory(kind: str):
            raise failure

        context.comm = factory
        data = self.data()
        with self.assertRaises(RuntimeError) as raised:
            self.call("Ex2RES_04_KeepAlive_SIL", context, data)
        self.assertIs(raised.exception, failure)
        self.assertEqual(struct.unpack_from("<III", data, 0x54), (123, 456, 789))
        self.assertEqual(context.state["native_global:1013fab0"], 0)
        self.assertEqual(context.state["native_global:1013fab4"], 123)
        self.assertEqual(context.state["native_global:1013fa38"], 456)
        self.assertEqual(context.state["native_global:1013fa3c"], 789)

    def test_ldr_nondata_actions_do_not_require_large_output_buffers(self) -> None:
        for export in ("Ex2LDR_10_SendMessage", "Ex2LDR_11_SendMessage"):
            context = Context()
            self.assertEqual(self.call(export, context, self.data(2, size=4)), 0)
            self.assertEqual(context.controller.events[-1], "finalize")
            with self.assertRaises(ValueError):
                self.call(export, Context(), self.data(1, size=4))

    def test_pcm_unmasked_inexact_environment_is_explicitly_unavailable(self) -> None:
        context = Context()
        values = dict.fromkeys(range(24, 56, 4), 7)
        values[40] = 0
        context.state["host:x87_control_word"] = 0x025F
        with self.assertRaises(TYSourceError):
            body._pcm_calculate(context, values)
        context.state["host:x87_control_word"] = 0x027F
        context.module_sha256 = SHA_PLUS_TY
        context.state["host:mxcsr"] = 0x0F80
        with self.assertRaises(TYSourceError):
            body._pcm_calculate(context, values)


if __name__ == "__main__":
    unittest.main()
