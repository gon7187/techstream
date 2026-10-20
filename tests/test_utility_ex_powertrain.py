"""Authored synthetic transport observations for source-bound NK ECD bodies."""

import unittest
from collections.abc import Iterable
from typing import Any

from scripts.utility_ex_powertrain import (
    NK12,
    NK18,
    NK_DS4,
    NK_GTSPLUS,
    run_body,
    supported_operations,
)


class Context:
    module_sha256 = NK18
    mode = 4

    def __init__(
        self,
        replies: Iterable[tuple[int, bytes] | Exception] = (),
        *,
        initialize: int = 0,
    ):
        self.replies = iter(replies)
        self.events: list[tuple[Any, ...]] = []
        self.cancelled = False
        self.init_status = initialize
        self.parameters: dict[int, int] = {}
        self.state: dict[str, object] = {}
        self.snapshots: list[tuple[int, bytes, tuple[int, ...]]] = []
        self.cached: dict[int, tuple[bytes, tuple[int, ...]]] = {}
        self.snapshot: tuple[int, bytes, tuple[int, ...]] = (
            0,
            bytes(0x1020),
            (0x1020,) * 256,
        )

    def comm(self, kind):
        self.events.append(("comm", kind))
        return self

    def initialize(self, mode=0):
        self.events.append(("initialize", mode))
        return self.init_status

    def finalize(self):
        self.events.append(("finalize",))

    def select_target(self, identifier, second=0):
        self.events.append(("select_target", identifier, second))

    def read_target(self):
        self.events.append(("read_target",))
        return (7, 9)

    def configure(self, field: str, value: int) -> None:
        self.events.append(("configure", field, value))

    def support_snapshot(self, kind):
        self.events.append(("support_snapshot", kind))
        return self.snapshots.pop(0) if self.snapshots else self.snapshot

    def refresh_support_cache(self, kind):
        self.events.append(("refresh_support_cache", kind))
        status, data, offsets = (
            self.snapshots.pop(0) if self.snapshots else self.snapshot
        )
        if status == 0:
            self.cached[kind] = (data, offsets)
        return status

    def cached_support(self, kind):
        self.events.append(("cached_support", kind))
        return self.cached.get(kind)

    def support_length(self, kind, selector):
        self.events.append(("support_length", kind, selector))
        snapshot = self.cached.get(kind)
        if snapshot is None:
            return 0
        data, offsets = snapshot
        offset = offsets[selector & 255]
        return 0 if offset == 0x1020 else data[offset + 1]

    def exchange(self, request: bytes) -> tuple[int, bytes]:
        self.events.append(("exchange", request))
        reply = next(self.replies)
        if isinstance(reply, Exception):
            raise reply
        return reply

    def sleep(self, ms):
        self.events.append(("sleep", ms))

    def native_sleep(self, ms):
        self.events.append(("native_sleep", ms))

    def start_selected_cmn(
        self, interval_ms, skip_response_validation=0, request=None, length=0
    ):
        self.events.append(
            (
                "start_selected_cmn",
                interval_ms,
                skip_response_validation,
                request,
                length,
            )
        )
        return 15

    def ticks(self) -> int:
        self.events.append(("ticks",))
        return 0xFFFFFFFE

    def broker(self, key: int) -> int:
        return self.parameters[key]

    def is_cancelled(self):
        return self.cancelled


class PowertrainTests(unittest.TestCase):
    def test_str52_get_data_info_requires_two_literal_queries(self):
        context = Context(
            [(0, b"\x5a\x08" + bytes(range(8))), (0, b"\x67\x07" + bytes(range(6)))]
        )
        data, seed = bytearray(10), bytearray(8)
        self.assertEqual(run_body("Ex2STR_52_GetDataInfo", (seed, data), context), 0)
        self.assertEqual(data, bytearray(bytes(range(8)) + b"\0\0"))
        self.assertEqual(seed, bytearray(bytes(range(6)) + b"\0\0"))
        self.assertEqual(
            [event[1] for event in context.events if event[0] == "exchange"],
            [b"\x1a\x84", b"\x27\x07"],
        )

    def test_str52_full_word_mode_and_profile_preserve_sticky_scope(self):
        context = Context([(0, b"\x61\x12\0\x02"), (0, b"\x61\0")])
        support = bytearray(0x1020)
        support[1:5] = b"\x03\x01\x02\x01"
        offsets = [0x1020] * 256
        offsets[0x12] = 0
        context.snapshot = (0, bytes(support), tuple(offsets))
        context.mode = 20
        context.state.update(
            {
                "native_global:1015eb4c": 7,
                "native_global:1015eb50": 9,
                "native_global:1015eb54": 1,
            }
        )
        data = bytearray(8)
        clock = bytearray(4)
        seed = bytearray(6)
        args = (seed, 20, data, clock, 0x104)
        self.assertEqual(run_body("Ex2STR_52_GetSupportInfo", args, context), 4406)
        self.assertEqual(context.state["native_global:1015eb54"], 1)
        self.assertTrue(any(event[0] == "initialize" for event in context.events))
        self.assertNotIn(("finalize",), context.events)

    def test_str52_key_uses_declared_bytes_and_always_cleans_up(self):
        context = Context([(0, b"\x67\x08\x34")])
        key = bytes(range(12))
        context.state.update(
            {
                "native_global:1014a7d0": key,
                "native_global:1014a7d4": 4,
                "native_global:1015eb4c": 7,
                "native_global:1015eb50": 9,
                "native_global:1015eb54": 1,
            }
        )
        self.assertEqual(run_body("EX2STR_52_SendTheKey", (b"stale", 1), context), 0)
        self.assertIn(("exchange", b"\x27\x08\0\1\2\3"), context.events)
        self.assertLess(
            context.events.index(("configure", "native_rva:170a0", 0)),
            context.events.index(("select_target", 7, 9)),
        )
        self.assertEqual(context.state["native_global:1015eb54"], 0)

    def test_str52_profile_comparison_uses_full_dword_and_retains_override(self):
        context = Context([(0, b"\x61\x12\0\x02"), (0, b"\x61\0")])
        support = bytearray(0x1020)
        support[1:5] = b"\x03\x01\x02\x01"
        offsets = [0x1020] * 256
        offsets[0x12] = 0
        context.snapshot = (0, bytes(support), tuple(offsets))
        context.mode = 20
        args = (bytearray(6), 20, bytearray(8), bytearray(4), 0x204)
        self.assertEqual(run_body("Ex2STR_52_GetSupportInfo", args, context), 4406)
        self.assertEqual(context.state["native_global:1015eb4c"], 7)
        self.assertEqual(context.state["native_global:1015eb50"], 9)
        self.assertEqual(context.state["native_global:1015eb54"], 1)
        self.assertLess(
            context.events.index(("configure", "native_rva:170a0", 0x101506D0)),
            context.events.index(("configure", "native_rva:170b0", 0x104)),
        )

    def test_str52_data_and_seed_alias_keeps_native_write_order(self):
        context = Context([(0, b"\x5a\x08" + b"D" * 8), (0, b"\x67\x07" + b"S" * 6)])
        output = bytearray(b"." * 8)
        self.assertEqual(
            run_body("Ex2STR_52_GetDataInfo", (output, output), context), 0
        )
        self.assertEqual(output, bytearray(b"S" * 6 + b"DD"))

    def test_str52_minimum_data_replies_and_host_exception_identity(self):
        context = Context(
            [
                (0, b"\x5a\x0a" + bytes(range(10))),
                (0, b"\x67\x07" + bytes(range(7))),
            ]
        )
        data, seed = bytearray(b"." * 10), bytearray(b"." * 8)
        self.assertEqual(run_body("Ex2STR_52_GetDataInfo", (seed, data), context), 0)
        self.assertEqual(data, bytearray(bytes(range(8)) + b".."))
        self.assertEqual(seed, bytearray(bytes(range(6)) + b".."))

        fault = OSError("selected SDK failed")
        context = Context([fault])
        with self.assertRaises(OSError) as caught:
            run_body("Ex2STR_52_GetDataInfo", (bytearray(6), bytearray(8)), context)
        self.assertIs(caught.exception, fault)
        self.assertIn(("finalize",), context.events)

    def test_str52_key_failure_status_and_exact_size(self):
        for reply, expected in ((b"\x67\x08\x00", 4405), (b"\x67\x08\x34\0", 3)):
            with self.subTest(reply=reply):
                context = Context([(0, reply)])
                self.assertEqual(
                    run_body("EX2STR_52_SendTheKey", (b"key", 3), context),
                    expected,
                )
                self.assertIn(("finalize",), context.events)

    def test_supply_pump_body_and_restoration(self):
        context = Context([(0, b"\x7b\x06")])
        self.assertEqual(run_body("Ex2ECD_InitialSupplyPump", (), context), 0)
        self.assertEqual(
            context.events,
            [
                ("comm", "selected"),
                ("configure", "native_rva:17320", 1),
                ("configure", "native_rva:172f0", 1),
                ("initialize", 19),
                ("exchange", b"\x3b\x06\x01"),
                ("finalize",),
                ("configure", "native_rva:17320", 100),
                ("configure", "native_rva:172f0", 3),
            ],
        )

    def test_build12_uses_its_own_config_helpers(self):
        context = Context([(0, b"\x7b\x06")])
        context.module_sha256 = NK12
        self.assertEqual(run_body("Ex2ECD_InitialSupplyPump", (), context), 0)
        self.assertIn(("configure", "native_rva:fa90", 1), context.events)
        self.assertIn(("configure", "native_rva:fa80", 3), context.events)
        context = Context([(0, b"\x7b\x01")])
        context.module_sha256 = NK12
        self.assertEqual(run_body("Ex2ECD_12_InitAFSensorLearn", (1,), context), 0)
        self.assertIn(("configure", "native_rva:fa60", 150), context.events)

    def test_fault_does_not_become_success(self):
        for status, reply, expected in [
            (27, b"", 27),
            (0, b"\x7b", 3),
            (0, b"\x7b\x07", 3),
        ]:
            with self.subTest(status=status, reply=reply):
                context = Context([(status, reply)])
                self.assertEqual(
                    run_body("Ex2ECD_InitialSupplyPump", (), context), expected
                )
                self.assertIn(("finalize",), context.events)

    def test_af_argument_is_native_low_byte(self):
        context = Context([(0, b"\x7b\x23")])
        self.assertEqual(run_body("Ex2ECD_12_InitAFSensorLearn", (0x123,), context), 0)
        self.assertIn(("exchange", b"\x3b\x23\0\0\0\0"), context.events)
        self.assertIn(("configure", "native_rva:172d0", 100), context.events)

    def test_support_bitmap_and_extension(self):
        for reply, extension, expected in [
            (b"\x7b\0\0\0\x40\x08", [], 0x85),
            (b"\x7b\0\0\0\x40\x09", [(0, b"\x7b\x20\0\x04\0\0")], 0x87),
        ]:
            with self.subTest(reply=reply):
                context = Context([(0, reply), *extension])
                output = bytearray([0x80])
                self.assertEqual(
                    run_body("Ex2ECD_12_GetSupportInfo", (output,), context), 0
                )
                self.assertEqual(output[0], expected)
                requests = [e[1] for e in context.events if e[0] == "exchange"]
                self.assertEqual(
                    requests, [b"\x3b\0"] + ([b"\x3b\x20"] if extension else [])
                )

    def test_support_fault_preserves_existing_output(self):
        output = bytearray([0x80])
        self.assertEqual(
            run_body(
                "Ex2ECD_12_GetSupportInfo",
                (output,),
                Context([(0, b"\x7b\x01\0\0\0\0")]),
            ),
            3,
        )
        self.assertEqual(output, bytearray([0x80]))

    def test_zfc_selected_cylinders(self):
        context = Context([(0, b"\x7b\x19"), (0, b"\x7b\x19")])
        self.assertEqual(
            run_body("Ex2ECD_22_ClearZFCLearningValues", (0x81,), context), 0
        )
        self.assertEqual(
            [e[1] for e in context.events if e[0] == "exchange"],
            [b"\x3b\x19\0\x01" + b"\0" * 7, b"\x3b\x19\0\x08" + b"\0" * 7],
        )
        self.assertEqual(context.events.count(("sleep", 100)), 2)

    def test_zfc_stops_at_first_fault(self):
        context = Context([(2, b"")])
        self.assertEqual(
            run_body("Ex2ECD_22_ClearZFCLearningValues", (255,), context), 2
        )
        self.assertEqual(len([e for e in context.events if e[0] == "exchange"]), 1)

    def test_cancel_and_init_failure(self):
        context = Context()
        context.cancelled = True
        self.assertEqual(run_body("Ex2ECD_InitialSupplyPump", (), context), 99)
        self.assertFalse(any(e[0] == "initialize" for e in context.events))
        context = Context(initialize=7)
        self.assertEqual(run_body("Ex2ECD_12_InitAFSensorLearn", (1,), context), 7)
        self.assertEqual(context.events[-1], ("finalize",))

    def test_exception_restores_timing_and_finalizes(self):
        context = Context([RuntimeError("synthetic driver fault")])
        with self.assertRaisesRegex(RuntimeError, "synthetic driver fault"):
            run_body("Ex2ECD_12_InitAFSensorLearn", (1,), context)
        self.assertEqual(
            context.events[-2:], [("configure", "native_rva:172d0", 100), ("finalize",)]
        )

    def test_wrong_identity_mode_and_open_bodies(self):
        context = Context()
        context.module_sha256 = "0" * 64
        with self.assertRaises(ValueError):
            run_body("Ex2ECD_InitialSupplyPump", (), context)
        context.module_sha256 = NK18
        with self.assertRaises(NotImplementedError):
            run_body("Ex2STR_RegKey", (), context)
        context.mode = 3
        self.assertEqual(run_body("Ex2ECD_InitialSupplyPump", (), context), 99)
        self.assertEqual(context.events, [])

    def test_ds4_source_variant_and_extended_bit_offset(self):
        for byte2, byte3, expected in [(4, 0, 0), (0, 4, 2)]:
            context = Context(
                [(0, b"\x7b\0\0\0\0\1"), (0, bytes((0x7B, 0x20, byte2, byte3, 0, 0)))]
            )
            context.module_sha256 = NK_DS4
            output = bytearray(1)
            self.assertEqual(
                run_body("Ex2ECD_12_GetSupportInfo", (output,), context), 0
            )
            self.assertEqual(output[0], expected)
            self.assertIn(("configure", "native_rva:32410", 150), context.events)

    def test_registration_success_keeps_selected_comm_open(self):
        context = Context([(0, b"\xe5\x99")])
        context.mode = 3
        self.assertEqual(run_body("Ex2STR_ChangeRegistMode", (), context), 0)
        self.assertNotIn(("finalize",), context.events)
        self.assertIn(("exchange", b"\xa5\x99\x04\0"), context.events)

    def test_registration_fallback_and_cleanup(self):
        for value, expected in [(0, 1000), (0x80, 1001)]:
            context = Context([(0, b"\xe5\x99\0"), (0, bytes((0x61, 3, value)))])
            context.mode = 3
            self.assertEqual(run_body("Ex2STR_ChangeRegistMode", (), context), expected)
            self.assertEqual(context.events[-1], ("finalize",))
            self.assertIn(("configure", "native_rva:172f0", 4), context.events)

    def test_registration_faults(self):
        for status, reply, expected in [
            (27, b"", 27),
            (0, b"\xe5\x99\1", 3),
            (0, b"\xe5\x98", 3),
        ]:
            context = Context([(status, reply)])
            context.mode = 3
            self.assertEqual(run_body("Ex2STR_ChangeRegistMode", (), context), expected)
            self.assertIn(("finalize",), context.events)

    def test_ds4_crank_initialization_and_conditional_extension(self):
        for flag in (0, 0x10):
            context = Context(
                [
                    (0, b"\x7b\x11"),
                    (0, bytes((0x7B, 0, 0, 0, 0, flag))),
                    *([(0, b"\x7b\x1c")] if flag else []),
                ]
            )
            context.module_sha256 = NK_DS4
            self.assertEqual(run_body("Ex2ECD_11_InitCrankTimeValue", (), context), 0)
            requests = [e[1] for e in context.events if e[0] == "exchange"]
            self.assertEqual(
                requests[:2], [b"\x3b\x11" + b"\x80\0" * 18 + b"\0", b"\x3b\0"]
            )
            self.assertEqual(len(requests), 3 if flag else 2)
            if flag:
                self.assertEqual(requests[-1], b"\x3b\x1c" + b"\x80\0" * 18 + b"\0")
            self.assertEqual(context.events[-1], ("finalize",))

    def test_ds4_ash_value_branch_packets(self):
        for flag, request in [
            (1, b"\x3b\x18" + b"\0" * 14),
            (0, b"\x3b\x27" + b"\0" * 5),
        ]:
            context = Context(
                [(0, bytes((0x7B, 0, 0, 0, flag, 0))), (0, bytes((0x7B, request[1])))]
            )
            context.module_sha256 = NK_DS4
            self.assertEqual(run_body("Ex2ECD_23_ClearDPFAshValue", (), context), 0)
            self.assertIn(("exchange", request), context.events)
        for status, reply in [(2, b""), (0, b"\x7b\1\0\0\0\0")]:
            context = Context([(status, reply)])
            context.module_sha256 = NK_DS4
            self.assertEqual(run_body("Ex2ECD_23_ClearDPFAshValue", (), context), 0x8FC)
            self.assertEqual(context.events[-1], ("finalize",))

    def test_gtsplus_exact_source_variant(self):
        context = Context([(0, b"\x7b\x06")])
        context.module_sha256 = NK_GTSPLUS
        self.assertEqual(run_body("Ex2ECD_InitialSupplyPump", (), context), 0)
        self.assertIn(("configure", "native_rva:33360", 1), context.events)
        self.assertIn(("configure", "native_rva:33390", 3), context.events)
        context = Context([(0, b"\x7b\0\0\0\1\0"), (0, b"\x7b\x18")])
        context.module_sha256 = NK_GTSPLUS
        self.assertEqual(run_body("Ex2ECD_23_ClearDPFAshValue", (), context), 0)
        self.assertIn(("configure", "native_rva:33320", 150), context.events)

    def test_preset_read_all_exact_variants(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            context = Context([(0, b"\xe9\x5a\xa5\xff")])
            context.module_sha256 = module
            output = bytearray(1)
            self.assertEqual(
                run_body("Ex2ECD_26_ReadPresetValue", (output,), context), 0
            )
            self.assertEqual(output, bytearray([0xA5]))
            self.assertEqual(context.events[-1], ("finalize",))

    def test_preset_write_readback_ignores_top_bit(self):
        context = Context([(0, b"\x7b\x5a"), (0, b"\xe9\x5a\x85")])
        self.assertEqual(run_body("Ex2ECD_26_WritePresetValue", (0x105,), context), 0)
        self.assertIn(("exchange", b"\x3b\x5a\5"), context.events)
        self.assertEqual(context.events.count(("sleep", 100)), 1)

    def test_preset_write_three_mismatches(self):
        context = Context([(0, b"\x7b\x5a"), *[(0, b"\xe9\x5a\x06")] * 3])
        self.assertEqual(run_body("Ex2ECD_26_WritePresetValue", (5,), context), 0xA28)
        self.assertEqual(context.events.count(("sleep", 100)), 3)
        self.assertEqual(context.events[-1], ("finalize",))

    def test_preset_fault_and_native_cancel_result(self):
        output = bytearray([0x55])
        context = Context([(0, b"\xe9\x5a")])
        self.assertEqual(run_body("Ex2ECD_26_ReadPresetValue", (output,), context), 3)
        self.assertEqual(output, bytearray([0x55]))
        context = Context([(0, b"\x7b\x5a")])
        context.cancelled = True
        self.assertEqual(run_body("Ex2ECD_26_WritePresetValue", (5,), context), 0)
        self.assertEqual(context.events.count(("sleep", 100)), 0)

    def test_clear_learning_typed_bitmap_and_fault_mapping(self):
        context = Context([(0, b"\x7b\x10"), (0, b"\x7b\x10")])
        self.assertEqual(
            run_body("Ex2ECD_25_ClearLearningValues", (bytes([0x81]),), context), 0
        )
        self.assertEqual(
            [e[1] for e in context.events if e[0] == "exchange"],
            [b"\x3b\x10\x01" + b"\0" * 16, b"\x3b\x10\x08" + b"\0" * 16],
        )
        context = Context(initialize=7)
        self.assertEqual(
            run_body("Ex2ECD_25_ClearLearningValues", (b"\1",), context), 4
        )
        context = Context([(2, b"")])
        self.assertEqual(
            run_body("Ex2ECD_25_ClearLearningValues", (b"\xff",), context), 2
        )
        self.assertEqual(len([e for e in context.events if e[0] == "exchange"]), 1)

    def test_pump_restores_limits_when_finalization_raises(self):
        class BrokenFinalizer(Context):
            def finalize(self):
                raise RuntimeError("synthetic finalization failure")

        context = BrokenFinalizer([(0, b"\x7b\x06")])
        with self.assertRaisesRegex(RuntimeError, "synthetic finalization failure"):
            run_body("Ex2ECD_InitialSupplyPump", (), context)
        self.assertEqual(
            context.events[-2:],
            [
                ("configure", "native_rva:17320", 100),
                ("configure", "native_rva:172f0", 3),
            ],
        )

    def test_original_crank_and_ash_asm_bound_variants(self):
        for module in (NK12, NK18):
            context = Context([(0, b"\x7b\x11"), (0, b"\x7b\0\0\0\0\0")])
            context.module_sha256 = module
            self.assertEqual(run_body("Ex2ECD_11_InitCrankTimeValue", (), context), 0)
            context = Context([(0, b"\x7b\0\0\0\0\0"), (0, b"\x7b\x27")])
            context.module_sha256 = module
            self.assertEqual(run_body("Ex2ECD_23_ClearDPFAshValue", (), context), 0)

    def test_master_key_native_status_branches_all_variants(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for status, reply, expected in [
                (0, b"\x61", 100),
                (0, b"\x61\3", 100),
                (0, b"\x61\3\x80", 0),
                (0, b"\x61\3\xc0", 100),
                (0, b"\x61\3\0", 100),
                (0, b"\x61\4", 3),
                (27, b"", 27),
            ]:
                with self.subTest(module=module, reply=reply):
                    context = Context([(status, reply)])
                    context.mode = 3
                    context.module_sha256 = module
                    self.assertEqual(
                        run_body("Ex2STR_ConfMasKey", (), context), expected
                    )
                    self.assertIn(("exchange", b"\x21\x03"), context.events)
                    self.assertEqual(context.events[-1], ("finalize",))

    def test_id_code_context_packet_and_retained_session(self):
        for key_type, request in [
            (1, b"\xa5\x99\x80\0"),
            (0x65, b"\xa5\x99\x80\0"),
            (1001, b"\xa5\x99\x80\0"),
            (1101, b"\xa5\x99\x80\0"),
            (2, b"\xa5\x99\x80"),
        ]:
            context = Context([(0, b"\xe5\x99")])
            context.mode = 3
            context.parameters[0xBF] = key_type
            self.assertEqual(run_body("Ex2STR_CheckIDCode", (), context), 0)
            self.assertIn(("exchange", request), context.events)
            self.assertNotIn(("finalize",), context.events)

    def test_id_code_variant_error_codes_and_native_echo_branch(self):
        for export, expected in [
            ("Ex2STR_CheckIDCode", 0x41A),
            ("Ex2STR_02_CheckIDCode", 100),
        ]:
            context = Context([(0, b"\xe5\x98\0")])
            context.mode = 3
            context.parameters[0xBF] = 2
            self.assertEqual(run_body(export, (), context), expected)
            self.assertEqual(context.events[-1], ("finalize",))

    def test_code_support_words_preserve_wire_order_and_allow_extension(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for export, selector in (
                ("Ex2ECD_14_CheckCodeSupportInfo", 0),
                ("Ex2ECD_14_CheckCodeSupportWID20Info", 32),
                ("Ex2ECD_31_CheckCodeSupportInfo", 0),
            ):
                with self.subTest(module=module, export=export):
                    context = Context([(0, bytes((0xE9, selector, 0x80, 1, 2, 3, 99)))])
                    context.module_sha256 = module
                    context.cancelled = (
                        True  # Native direct body does not test cancellation.
                    )
                    output = bytearray(b"old!")
                    self.assertEqual(run_body(export, (output,), context), 0)
                    self.assertEqual(output, b"\x80\x01\x02\x03")
                    self.assertIn(("exchange", bytes((0xA9, selector))), context.events)
                    self.assertEqual(context.events[-1], ("finalize",))

    def test_code_support_word_faults_never_publish(self):
        export = "Ex2ECD_14_CheckCodeSupportInfo"
        for status, reply, expected in (
            (8, b"", 8),
            (0, b"\xe9\0abcd"[:5], 3),
            (0, b"\xe9\x20abcd", 3),
        ):
            output = bytearray(b"old!")
            context = Context([(status, reply)])
            self.assertEqual(run_body(export, (output,), context), expected)
            self.assertEqual(output, b"old!")
        output = bytearray(4)
        context = Context(initialize=17)
        self.assertEqual(run_body(export, (output,), context), 17)
        self.assertEqual(
            context.events, [("comm", "selected"), ("initialize", 0), ("finalize",)]
        )
        context = Context([RuntimeError("synthetic")])
        with self.assertRaises(RuntimeError):
            run_body(export, (output,), context)
        self.assertEqual(
            context.events[-2:], [("configure", "native_rva:172d0", 100), ("finalize",)]
        )
        for bad in (b"abcd", bytearray(3), bytearray(5), 0):
            with self.assertRaises(ValueError):
                run_body(export, (bad,), Context())

    def test_mileage_support_bits_native_empty_error_and_preservation(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for initial, b4, b5, expected, status in (
                (0, 1, 0x80, 3, 0),
                (0, 0, 0, 0, 2400),
                (0x40, 0, 0, 0x40, 0),
                (0, 1, 0, 2, 0),
                (0, 0, 0x80, 1, 0),
            ):
                context = Context([(0, bytes((0x7B, 0, 0, 0, b4, b5)))])
                context.module_sha256 = module
                output = bytearray((initial,))
                self.assertEqual(
                    run_body("Ex2ECD_24_GetCodeSupportInfo", (output,), context), status
                )
                self.assertEqual(output[0], expected)
        for reply in (b"\x7b\0", b"\x7b\x01\0\0\x01\x80", b"\x7b\0\0\0\x01\x80extra"):
            output = bytearray((0x80,))
            self.assertEqual(
                run_body(
                    "Ex2ECD_24_GetCodeSupportInfo", (output,), Context([(0, reply)])
                ),
                3,
            )
            self.assertEqual(output[0], 0x80)

    def test_str_initialize_lifecycle_and_fault(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for status in (0, 23):
                context = Context(initialize=status)
                context.mode = 3
                context.module_sha256 = module
                context.cancelled = True
                self.assertEqual(run_body("Ex2STR_Init", (), context), status)
                self.assertEqual(
                    context.events,
                    [("comm", "selected"), ("initialize", 0), ("finalize",)],
                )

    def test_registration_master_bit_and_variant_abi(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            args = (0xFFFFFFFF,) if module in (NK12, NK18) else ()
            for reply, expected in (
                (b"\x61\x03\x80", 0),
                (b"\x61\x03\x40", 480),
                (b"\x61\x03", 3),
                (b"\x61\x02\x80", 3),
            ):
                context = Context([(0, reply)])
                context.mode = 3
                context.module_sha256 = module
                self.assertEqual(
                    run_body("Ex2STR_RegMasKeyConf", args, context), expected
                )
                self.assertEqual(context.events[-1], ("finalize",))
            context = Context(initialize=19)
            context.mode = 3
            context.module_sha256 = module
            self.assertEqual(run_body("Ex2STR_RegMasKeyConf", args, context), 19)
            self.assertEqual(
                context.events[-3:],
                [
                    (
                        "configure",
                        {
                            NK12: "native_rva:fa90",
                            NK18: "native_rva:17320",
                            NK_DS4: "native_rva:32450",
                            NK_GTSPLUS: "native_rva:33360",
                        }[module],
                        100,
                    ),
                    (
                        "configure",
                        {
                            NK12: "native_rva:fa80",
                            NK18: "native_rva:172f0",
                            NK_DS4: "native_rva:32480",
                            NK_GTSPLUS: "native_rva:33390",
                        }[module],
                        3,
                    ),
                    ("finalize",),
                ],
            )
            with self.assertRaises(ValueError):
                run_body("Ex2STR_RegMasKeyConf", () if args else (0,), context)

    def test_registered_key_counts_before_initializes_after_reuses_session(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for export in ("Ex2STR_GetRegKeyNumBefore", "Ex2STR_GetRegKeyNumAfter"):
                context = Context([(0, b"\x61\x04\xabextra")])
                context.mode, context.module_sha256 = 3, module
                a, b = bytearray(b"old!"), bytearray(b"old!")
                self.assertEqual(run_body(export, (a, b), context), 0)
                self.assertEqual((a, b), (b"\x0a\0\0\0", b"\x0b\0\0\0"))
                self.assertEqual(
                    any(e[0] == "initialize" for e in context.events),
                    export.endswith("Before"),
                )
                self.assertEqual(context.events[-1], ("finalize",))
                # Aliased native DWORD outputs preserve write order.
                context = Context([(0, b"\x61\x04\xab")])
                context.mode, context.module_sha256 = 3, module
                self.assertEqual(run_body(export, (a, a), context), 0)
                self.assertEqual(a, b"\x0b\0\0\0")

    def test_registered_key_counts_fault_zeroes_only_before(self):
        for export in ("Ex2STR_GetRegKeyNumBefore", "Ex2STR_GetRegKeyNumAfter"):
            for status, reply, expected in (
                (7, b"", 7),
                (0, b"\x61\x04", 3),
                (0, b"\x61\x03\xff", 3),
            ):
                context = Context([(status, reply)])
                context.mode = 3
                a, b = bytearray(b"old!"), bytearray(b"old!")
                self.assertEqual(run_body(export, (a, b), context), expected)
                self.assertEqual(a, b"\0" * 4 if export.endswith("Before") else b"old!")
                self.assertEqual(a, b)
        context = Context(initialize=8)
        context.mode = 3
        a, b = bytearray(b"old!"), bytearray(b"old!")
        self.assertEqual(run_body("Ex2STR_GetRegKeyNumBefore", (a, b), context), 8)
        self.assertEqual((a, b), (bytes(4), bytes(4)))
        self.assertFalse(any(e[0] == "configure" for e in context.events))

    def test_ec31_read_all_selected_branches_wire_layout_and_native_padding(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            specifications = [
                (0x80, 2, 1, 2, 50, 2),
                (0x40, 6, 0x34, 0x35, 32, 2),
                (0x20, 7, 0x55, 0x56, 8, 3),
                (0x10, 9, 0x76, 0x77, 4, 2),
                (8, 14, 0x7B, 0x7C, 4, 2),
                (4, 15, 0x80, 0x81, 24, 2),
                (2, 18, 0x99, 0x9A, 22, 2),
            ]
            if module != NK12:
                specifications.append((1, 21, 0xB0, 0xB1, 4, 2))
            for bit, selector, marker, offset, size, header in specifications:
                count = 4 if selector == 7 else 1
                payload = bytes(range(size))
                replies = [
                    (
                        0,
                        bytes((0xE9, selector))
                        + (bytes((i,)) if header == 3 else b"")
                        + payload,
                    )
                    for i in range(1, count + 1)
                ]
                context = Context(replies)
                context.module_sha256 = module
                record = bytearray([0xCC]) * (176 if module == NK12 else 181)
                record[0] = bit
                self.assertEqual(run_body("Ex2ECD_31_ReadCode", (record,), context), 0)
                self.assertEqual(record[marker], selector)
                self.assertEqual(
                    record[offset : offset + size * count], payload * count
                )
                self.assertEqual(context.events[-1], ("finalize",))
                self.assertEqual(
                    [e[1] for e in context.events if e[0] == "exchange"],
                    [
                        bytes((0xA9, selector)) + (bytes((i,)) if header == 3 else b"")
                        for i in range(1, count + 1)
                    ],
                )
        context = Context([(0, b"\xe9\x15ab")])
        record = bytearray(181)
        record[0] = 1
        self.assertEqual(run_body("Ex2ECD_31_ReadCode", (record,), context), 0)
        self.assertEqual(record[0xB1:0xB5], b"ab\0\0")

    def test_ec31_read_stop_mapping_init_cancel_and_12_absent_branch(self):
        for status, reply in (
            (2, b""),
            (0, b"\xe9\x03" + bytes(50)),
            (0, b"\xe9\x02short"),
        ):
            context = Context([(status, reply)])
            record = bytearray([0xCC]) * 181
            record[0] = 0xFF
            self.assertEqual(run_body("Ex2ECD_31_ReadCode", (record,), context), 1406)
            self.assertEqual(record[1:], bytes([0xCC]) * 180)
            self.assertEqual(sum(e[0] == "exchange" for e in context.events), 1)
        context = Context(initialize=5)
        self.assertEqual(run_body("Ex2ECD_31_ReadCode", (bytearray(181),), context), 5)
        context = Context()
        context.cancelled = True
        self.assertEqual(run_body("Ex2ECD_31_ReadCode", (bytearray(181),), context), 99)
        self.assertFalse(any(e[0] == "initialize" for e in context.events))
        context = Context()
        context.module_sha256 = NK12
        record = bytearray(176)
        record[0] = 1
        self.assertEqual(run_body("Ex2ECD_31_ReadCode", (record,), context), 0)
        self.assertFalse(any(e[0] == "exchange" for e in context.events))

    def test_ec31_partial_output_survives_later_fault_and_exception_cleanup(self):
        context = Context([(0, b"\xe9\x02" + b"a" * 50), (7, b"")])
        record = bytearray([0xCC]) * 181
        record[0] = 0xC0
        self.assertEqual(run_body("Ex2ECD_31_ReadCode", (record,), context), 1406)
        self.assertEqual(record[1], 2)
        self.assertEqual(record[2:52], b"a" * 50)
        self.assertEqual(record[52:], bytes([0xCC]) * 129)
        context = Context([RuntimeError("synthetic")])
        with self.assertRaises(RuntimeError):
            run_body("Ex2ECD_31_ReadCode", (record,), context)
        self.assertEqual(
            context.events[-2:], [("configure", "native_rva:172d0", 100), ("finalize",)]
        )

    def test_online_support_is_literal_read_query_and_native_conditional_output(self):
        export = "_Ex2STR_43_CheckOnlineSupport@4"
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for bit, expected in ((0, 0), (0x80, 1)):
                context = Context([(0, bytes((0x61, 0x12, bit, 2)))])
                context.module_sha256 = module
                context.cancelled = True
                output = bytearray(b"old!")
                self.assertEqual(run_body(export, (output,), context), 4311)
                self.assertEqual(output, expected.to_bytes(4, "little"))
                self.assertIn(("native_sleep", 100), context.events)
                self.assertIn(("exchange", b"\x21\x12"), context.events)
            output = bytearray(b"old!")
            context = Context([(0, b"\x61\x12\x80\0")])
            context.module_sha256 = module
            self.assertEqual(run_body(export, (output,), context), 0)
            self.assertEqual(output, b"old!")
        for status, reply, expected in (
            (7, b"", 7),
            (0, b"\x61\x12\x80", 3),
            (0, b"\x61\x13\x80\x02", 3),
        ):
            output = bytearray(b"old!")
            context = Context([(status, reply)])
            self.assertEqual(run_body(export, (output,), context), expected)
            self.assertEqual(output, b"old!")
            self.assertEqual(context.events[-1], ("finalize",))
        context = Context(initialize=18)
        self.assertEqual(run_body(export, (bytearray(4),), context), 18)
        self.assertNotIn(("native_sleep", 100), context.events)

    def test_cylinder_count_uses_literal_support_record_position(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for cylinder in (3, 4, 6, 8):
                context = Context([(0, b"\x61\xc1\0\0" + bytes((cylinder,)))])
                context.module_sha256 = module
                data = bytearray(0x1020)
                offsets = [0x1020] * 256
                offsets[0xC1] = 7
                data[8], data[9], data[11], data[22] = 14, 0x80, 0x80, 0xFF
                context.snapshot = (0, bytes(data), tuple(offsets))
                output = bytearray((0xAA,))
                self.assertEqual(
                    run_body("Ex2ECD_22_GetCylinderNum", (output,), context), 0
                )
                self.assertEqual(output[0], cylinder)
                self.assertIn(("support_snapshot", 1), context.events)
                self.assertIn(("exchange", b"\x21\xc1"), context.events)
                self.assertEqual(context.events[-1], ("finalize",))

    def test_cylinder_support_failure_and_malformed_query_preserve_output(self):
        export = "Ex2ECD_22_GetCylinderNum"
        context = Context()
        output = bytearray((0xAA,))
        self.assertEqual(run_body(export, (output,), context), 1501)
        self.assertFalse(any(e[0] == "exchange" for e in context.events))
        context = Context()
        context.snapshot = (27, bytes(0x1020), (0x1020,) * 256)
        self.assertEqual(run_body(export, (output,), context), 27)
        for reply in (b"\x61\xc1", b"\x61\xc1\x05", b"\x61\xc2\x04"):
            context = Context([(0, reply)])
            data = bytearray(0x1020)
            offsets = [0x1020] * 256
            offsets[0xC1] = 0
            data[1], data[15] = 14, 0xFF
            context.snapshot = (0, bytes(data), tuple(offsets))
            self.assertEqual(run_body(export, (output,), context), 3)
            self.assertEqual(output[0], 0xAA)
        context = Context(initialize=9)
        self.assertEqual(run_body(export, (output,), context), 9)
        self.assertFalse(any(e[0] == "configure" for e in context.events))

    def test_cylinder_info_dword_variants_preserve_distinct_native_errors_and_timing(
        self,
    ):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for export, unsupported, invalid, timed in (
                ("Ex2ECD_13_ReadCylinderInfo", 1300, 1301, True),
                ("Ex2ECD_17_ReadCylinderInfo", 1700, 1701, False),
            ):
                output = bytearray(b"old!")
                context = Context()
                context.module_sha256 = module
                self.assertEqual(run_body(export, (output,), context), unsupported)
                self.assertEqual(output, b"old!")
                for cylinder in (3, 4, 6, 8):
                    context = Context([(0, bytes((0x61, 0xC1, cylinder)))])
                    context.module_sha256 = module
                    data = bytearray(0x1020)
                    offsets = [0x1020] * 256
                    offsets[0xC1] = 0
                    data[1], data[15] = 14, 0xFF
                    context.snapshot = (0, bytes(data), tuple(offsets))
                    self.assertEqual(
                        run_body(export, (output,), context),
                        invalid if cylinder == 3 else 0,
                    )
                    if cylinder != 3:
                        self.assertEqual(output, cylinder.to_bytes(4, "little"))
                    self.assertEqual(
                        any(e[0] == "configure" for e in context.events), timed
                    )
                    self.assertEqual(context.events[-1], ("finalize",))

    def test_cylinder_snapshot_boundary_errors_and_host_fault_cleanup(self):
        export = "Ex2ECD_22_GetCylinderNum"
        output = bytearray((0xAA,))
        for offset in (0x1020, 0x101F, 0x1011):
            context = Context()
            offsets = [0x1020] * 256
            offsets[0xC1] = offset
            context.snapshot = (0, bytes(0x1020), tuple(offsets))
            self.assertEqual(run_body(export, (output,), context), 1501)
            self.assertEqual(output[0], 0xAA)
        context = Context()
        context.snapshot = (0, bytes(1), (0,) * 256)
        with self.assertRaises(ValueError):
            run_body(export, (output,), context)
        self.assertEqual(
            context.events[-2:], [("configure", "native_rva:172d0", 100), ("finalize",)]
        )

    def test_wait_erase_retained_session_poll_and_confirm(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for export in ("Ex2STR_WaitCompEraseKey", "Ex2STR_02_WaitCompEraseKey"):
                context = Context(
                    [(0, b"\x61\x06\x40"), (0, b"\x61\x06\0"), (0, b"\x61\x04\x10")]
                )
                context.mode, context.module_sha256 = 3, module
                self.assertEqual(run_body(export, (), context), 0)
                self.assertEqual(
                    [e[1] for e in context.events if e[0] == "exchange"],
                    [b"\x21\x06", b"\x21\x06", b"\x21\x04"],
                )
                self.assertFalse(any(e[0] == "initialize" for e in context.events))
                self.assertEqual(context.events[-1], ("finalize",))

    def test_wait_erase_variant_errors_and_cancel_preserve_last_poll(self):
        for export, malformed, timeout, mismatch in (
            ("Ex2STR_WaitCompEraseKey", 1051, 1052, 1053),
            ("Ex2STR_02_WaitCompEraseKey", 101, 102, 103),
        ):
            for status, reply, expected in (
                (2, b"", timeout),
                (7, b"", malformed),
                (0, b"\x61\x06", malformed),
                (0, b"\x61\x07\0", malformed),
            ):
                context = Context([(status, reply)])
                context.mode = 3
                self.assertEqual(run_body(export, (), context), expected)
            context = Context([(0, b"\x61\x06\0"), (0, b"\x61\x04\x11")])
            context.mode = 3
            self.assertEqual(run_body(export, (), context), mismatch)
            context = Context()
            context.mode, context.cancelled = 3, True
            self.assertEqual(run_body(export, (), context), 99)
            self.assertFalse(any(e[0] == "exchange" for e in context.events))

            class CancelOnBusy(Context):
                def exchange(self, request):
                    reply = super().exchange(request)
                    self.cancelled = True
                    return reply

            context = CancelOnBusy([(0, b"\x61\x06\x40")])
            context.mode = 3
            self.assertEqual(run_body(export, (), context), 171)
            self.assertEqual(context.events[-1], ("finalize",))

    def test_registration_key_status_then_count_keeps_only_successful_session(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            context = Context([(0, b"\x61\x03\0\0"), (0, b"\x61\x04\x42")])
            context.mode, context.module_sha256 = 3, module
            output = bytearray((0xAA,))
            self.assertEqual(run_body("Ex2STR_GetRegistKey", (output,), context), 0)
            self.assertEqual(output[0], 0x42)
            self.assertNotIn(("finalize",), context.events)
            for reply, status in ((b"\x61\x03\0\x80", 1002), (b"\x61\x03\0", 3)):
                context = Context([(0, reply)])
                context.mode, context.module_sha256 = 3, module
                output[0] = 0xAA
                self.assertEqual(
                    run_body("Ex2STR_GetRegistKey", (output,), context), status
                )
                self.assertEqual(output[0], 0xAA)
                self.assertEqual(context.events[-1], ("finalize",))

    def test_registration_completion_poll_native_return_and_output(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            context = Context(
                [(0, b"\x61\x06\x40"), (0, b"\x61\x06\0"), (0, b"\x61\x04\x21")]
            )
            context.mode, context.module_sha256 = 3, module
            output = bytearray((0xAA,))
            self.assertEqual(
                run_body("Ex2STR_WaitCompRegistKey", (output,), context), 0
            )
            self.assertEqual(output[0], 0x21)
            self.assertEqual(context.events[-1], ("finalize",))
        for status, reply, expected in (
            (2, b"", 1003),
            (7, b"", 1004),
            (0, b"\x61\x06", 1004),
        ):
            context = Context([(status, reply)])
            context.mode = 3
            self.assertEqual(
                run_body("Ex2STR_WaitCompRegistKey", (bytearray(1),), context), expected
            )

        class CancelOnBusy(Context):
            def exchange(self, request):
                reply = super().exchange(request)
                self.cancelled = True
                return reply

        context = CancelOnBusy([(0, b"\x61\x06\x40")])
        context.mode = 3
        output = bytearray((0xAA,))
        self.assertEqual(run_body("Ex2STR_WaitCompRegistKey", (output,), context), 0)
        self.assertEqual(output[0], 0xAA)
        self.assertEqual(context.events[-1], ("finalize",))

    def test_registration_area_native_retry_and_retained_success(self):
        class Retry(Context):
            def __init__(self, statuses, reply=b"\x61\x03\0\0"):
                super().__init__([(0, reply)])
                self.statuses = iter(statuses)

            def initialize(self, mode=0):
                self.events.append(("initialize", mode))
                return next(self.statuses)

        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            context = Retry([7, 0])
            context.mode, context.module_sha256 = 3, module
            self.assertEqual(run_body("Ex2STR_ConfRegArea", (), context), 0)
            self.assertIn(("native_sleep", 2000), context.events)
            self.assertEqual(sum(e[0] == "initialize" for e in context.events), 2)
            self.assertNotIn(("finalize",), context.events)
            context = Retry([7, 9])
            context.mode, context.module_sha256 = 3, module
            self.assertEqual(run_body("Ex2STR_ConfRegArea", (), context), 9)
            self.assertEqual(sum(e[0] == "initialize" for e in context.events), 2)
        context = Retry([0], b"\x61\x03\0\x80")
        context.mode = 3
        self.assertEqual(run_body("Ex2STR_ConfRegArea", (), context), 440)
        self.assertEqual(
            context.events[-3:],
            [
                ("finalize",),
                ("configure", "native_rva:17320", 100),
                ("configure", "native_rva:172f0", 3),
            ],
        )
        context = Context()
        context.mode, context.cancelled = 3, True
        self.assertEqual(run_body("Ex2STR_ConfRegArea", (), context), 5)
        self.assertFalse(any(e[0] == "initialize" for e in context.events))

    def test_registration_mode_native_cancel_is_checked_only_after_busy(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            context = Context([(0, b"\x61\x06\x40"), (0, b"\x61\x06\0")])
            context.mode, context.module_sha256 = 3, module
            self.assertEqual(run_body("Ex2STR_ConfRegMode", (), context), 0)
            self.assertNotIn(("finalize",), context.events)
            for value, expected in ((0, 0), (0x40, 5)):
                context = Context([(0, bytes((0x61, 6, value)))])
                context.mode, context.module_sha256, context.cancelled = 3, module, True
                self.assertEqual(run_body("Ex2STR_ConfRegMode", (), context), expected)
                self.assertEqual(("finalize",) in context.events, bool(expected))
        for status, reply, expected in (
            (7, b"", 7),
            (0, b"\x61\x06", 3),
            (0, b"\x61\x05\0", 3),
        ):
            context = Context([(status, reply)])
            context.mode = 3
            self.assertEqual(run_body("Ex2STR_ConfRegMode", (), context), expected)
            self.assertEqual(context.events[-1], ("finalize",))

    def test_change_erase_mode_literal_request_defaults_and_retained_success(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for reply, expected in (
                (b"\xe5\x99", 0),
                (b"\xe5\x99\0", 12),
                (b"\xe5\x99\x01", 3),
                (b"\xe5\x98", 3),
            ):
                context = Context([(0, reply)])
                context.mode, context.module_sha256 = 3, module
                self.assertEqual(run_body("Ex2STR_CngEraseMode", (), context), expected)
                self.assertIn(("exchange", b"\xa5\x99\x80"), context.events)
                self.assertEqual(("finalize",) in context.events, bool(expected))
                self.assertTrue(
                    any(e[0] == "configure" and e[2] == 10000 for e in context.events)
                )
                self.assertTrue(
                    any(e[0] == "configure" and e[2] == 0 for e in context.events)
                )
        context = Context(initialize=9)
        context.mode = 3
        self.assertEqual(run_body("Ex2STR_CngEraseMode", (), context), 9)
        self.assertEqual(context.events[-1], ("finalize",))
        self.assertIn(("configure", "native_rva:172e0", 0), context.events)

    def test_immobilizer_initialization_native_fallback_targets_and_session(self):
        class Attempts(Context):
            def __init__(self, statuses):
                super().__init__()
                self.statuses = iter(statuses)

            def initialize(self, mode=0):
                self.events.append(("initialize", mode))
                return next(self.statuses)

        for module, first, second in (
            (NK12, 0x100E6368, 0x100E6240),
            (NK18, 0x1014C0B0, 0x1014AEF0),
            (NK_DS4, 0x101B554C, 0x101B4208),
            (NK_GTSPLUS, 0x101C0674, 0x101BF318),
        ):
            for statuses, expected, finalizes in (
                ([0], 0, 0),
                ([7, 0], 0, 1),
                ([7, 9], 9, 2),
            ):
                context = Attempts(statuses)
                context.mode, context.module_sha256, context.cancelled = 3, module, True
                self.assertEqual(run_body("Ex2STR_InitImbi", (), context), expected)
                self.assertIn(("select_target", 0x10, 0), context.events)
                self.assertTrue(
                    any(e[0] == "configure" and e[2] == first for e in context.events)
                )
                self.assertEqual(context.events.count(("finalize",)), finalizes)
                if len(statuses) > 1:
                    self.assertIn(("native_sleep", 300), context.events)
                    self.assertIn(("select_target", 0x13, 0), context.events)
                    self.assertTrue(
                        any(
                            e[0] == "configure" and e[2] == second
                            for e in context.events
                        )
                    )
                self.assertEqual(
                    ("select_target", 0xC1, 0) in context.events, bool(expected)
                )

    def test_immobilizer_erase_mode_resets_literal_target_override_and_session(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for reply, expected in (
                (b"\xe5\x99", 0),
                (b"\xe5\x99\0", 401),
                (b"\xe5\x99\x01", 402),
                (b"\xe5\x98", 3),
            ):
                context = Context([(0, reply)])
                context.mode, context.module_sha256 = 3, module
                self.assertEqual(
                    run_body("Ex2STR_CngEraseModeImbi", (), context), expected
                )
                self.assertIn(("exchange", b"\xa5\x99\0"), context.events)
                self.assertIn(("select_target", 0xC1, 0), context.events)
                self.assertFalse(any(e[0] == "initialize" for e in context.events))
                self.assertEqual(context.events[-1], ("finalize",))
        context = Context([OSError("authored")])
        context.mode = 3
        with self.assertRaises(OSError):
            run_body("Ex2STR_CngEraseModeImbi", (), context)
        self.assertEqual(
            context.events[-3:],
            [
                ("select_target", 0xC1, 0),
                ("configure", "native_rva:170a0", 0),
                ("finalize",),
            ],
        )

    def test_factory_termination_native_cleanup_request_and_cancel_branch(self):
        export = "Ex2STR_16_Foced_Termination_Of_FM"
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for status, reply, expected, requests in (
                (0, b"\xe5\x99", 0, [b"\xa5\x99\x01\0", b"\x82"]),
                (7, b"", 7, [b"\xa5\x99\x01\0", b"\x82"]),
                (1601, b"", 1601, [b"\xa5\x99\x01\0"]),
                (0, b"\xe5\x99\0", 3, [b"\xa5\x99\x01\0", b"\x82"]),
            ):
                context = Context([(status, reply), (99, b"")])
                context.mode, context.module_sha256 = 3, module
                self.assertEqual(run_body(export, (), context), expected)
                self.assertEqual(
                    [e[1] for e in context.events if e[0] == "exchange"], requests
                )
                self.assertEqual(context.events[-1], ("finalize",))
            context = Context([(99, b"")])
            context.mode, context.module_sha256, context.cancelled = 3, module, True
            self.assertEqual(run_body(export, (), context), 0)
            self.assertEqual(
                [e[1] for e in context.events if e[0] == "exchange"], [b"\x82"]
            )
            self.assertFalse(any(e[0] == "initialize" for e in context.events))
        context = Context(initialize=17)
        context.mode = 3
        self.assertEqual(run_body(export, (), context), 1601)
        self.assertEqual(context.events[-1], ("finalize",))

    def test_str41_retained_queries_literal_wires_and_global_counts(self):
        for module, key in (
            (NK12, "100f5b44"),
            (NK18, "1015eb2c"),
            (NK_DS4, "101c5d10"),
            (NK_GTSPLUS, "101dd618"),
        ):
            context = Context(
                [
                    (0, b"\x61\x16\x20"),
                    (0, b"\x61\x14\x10"),
                    (0, b"\x61\x12\0"),
                    (0, b"\x61\x13\0\0"),
                    (0, b"\x61\x14\x92"),
                ]
            )
            context.module_sha256 = module
            context.cancelled = True
            output = bytearray(b"old!")
            self.assertEqual(
                run_body("Ex2STR_41_GetCurrentMode", (output,), context), 0
            )
            self.assertEqual(output, b"\1\0\0\0")
            self.assertEqual(run_body("Ex2STR_41_GetRegKeyNum", (), context), 0x100F)
            context.state["native_global:" + key] = 0xABCD5678
            self.assertEqual(run_body("Ex2STR_41_GetCurrentStatus", (), context), 0)
            self.assertEqual(context.state["native_global:" + key], 0xABCD0209)
            self.assertFalse(
                any(e[0] in ("initialize", "finalize") for e in context.events)
            )
            self.assertEqual(
                [e[1] for e in context.events if e[0] == "exchange"],
                [b"\x21\x16", b"\x21\x14", b"\x21\x12", b"\x21\x13", b"\x21\x14"],
            )

    def test_str41_query_errors_preserve_outputs_and_finalization_contracts(self):
        for export, replies, expected, finalize in (
            ("Ex2STR_41_GetCurrentMode", [(0, b"\x61\x15\x20")], 3, True),
            ("Ex2STR_41_GetRegKeyNum", [(0, b"\x61\x14\x02")], 0x100E, False),
            ("Ex2STR_41_GetRegKeyNum", [(0x100E, b"")], 0x100E, False),
            ("Ex2STR_41_GetRegKeyNum", [(27, b"")], 27, True),
            ("Ex2STR_41_GetCurrentStatus", [(0, b"\x61\x12\1")], 0x100B, True),
            (
                "Ex2STR_41_GetCurrentStatus",
                [(0, b"\x61\x12\0"), (0, b"\x61\x13\0\x80")],
                0x100C,
                True,
            ),
            (
                "Ex2STR_41_GetCurrentStatus",
                [(0, b"\x61\x12\0"), (0, b"\x61\x13\0")],
                3,
                True,
            ),
        ):
            context = Context(replies)
            output = bytearray(b"old!")
            self.assertEqual(
                run_body(export, (output,) if export.endswith("Mode") else (), context),
                expected,
            )
            self.assertEqual(output, b"old!")
            self.assertEqual(("finalize",) in context.events, finalize)
        for export in (
            "Ex2STR_41_GetCurrentMode",
            "Ex2STR_41_GetRegKeyNum",
            "Ex2STR_41_GetCurrentStatus",
        ):
            context = Context([OSError("query failed")])
            with self.assertRaises(OSError):
                run_body(
                    export, (bytearray(4),) if export.endswith("Mode") else (), context
                )
            self.assertEqual(context.events[-1], ("finalize",))

    def test_str41_mode_repeat_native_comparison_and_cancel_lifetime(self):
        for module, counts, refs in (
            (NK12, "100f5b44", ("100e5d48", "100e5d4c")),
            (NK18, "1015eb2c", ("1014a790", "1014a794")),
            (NK_DS4, "101c5d10", ("101b1aec", "101b1af0")),
            (NK_GTSPLUS, "101dd618", ("101bcbec", "101bcbf0")),
        ):
            for current, expected, wanted in (
                (0x32, 0, 1),
                (0x23, 0, 0),
                (0x22, 0x100D, None),
            ):
                context = Context(
                    [
                        (0, b"\x61\x16\x20"),
                        (0, b"\x61\x16\0"),
                        (0, bytes((0x61, 0x14, current))),
                    ]
                )
                context.module_sha256 = module
                context.state["native_global:" + counts] = 0x202
                output, kind = bytearray(b"old!"), bytearray(b"kind")
                self.assertEqual(
                    run_body("Ex2STR_41_GetCurrentModeRepeat", (output, kind), context),
                    expected,
                )
                self.assertEqual(output, bytes(4))
                self.assertEqual(
                    kind, b"kind" if wanted is None else wanted.to_bytes(4, "little")
                )
                self.assertIs(context.state["native_global:" + refs[0]], output)
                self.assertIs(context.state["native_global:" + refs[1]], kind)
                self.assertEqual(context.events[-1], ("finalize",))
            context = Context()
            context.module_sha256 = module
            context.cancelled = True
            output, kind = bytearray(4), bytearray(b"kind")
            self.assertEqual(
                run_body("Ex2STR_41_GetCurrentModeRepeat", (output, kind), context), 99
            )
            self.assertEqual(output, b"\1\0\0\0")
            self.assertNotIn(("finalize",), context.events)
            context.mode = 3
            other = bytearray(4)
            # The native wrapper stores references before entering this body.
            context.state["native_global:" + refs[0]] = other
            context.state["native_global:" + refs[1]] = kind
            self.assertEqual(
                run_body("Ex2STR_41_GetCurrentModeRepeat", (other, kind), context), 99
            )
            self.assertIs(context.state["native_global:" + refs[0]], other)
            self.assertEqual(other, bytes(4))

    def test_str41_repeat_cancellation_after_query_keeps_last_status(self):
        context = Context([(0, b"\x61\x16\x20")])
        exchange = context.exchange

        def cancel(request):
            result = exchange(request)
            context.cancelled = True
            return result

        context.exchange = cancel
        output, kind = bytearray(4), bytearray(4)
        self.assertEqual(
            run_body("Ex2STR_41_GetCurrentModeRepeat", (output, kind), context), 0
        )
        self.assertEqual(output, b"\1\0\0\0")
        self.assertNotIn(("finalize",), context.events)
        context = Context([OSError("repeat failed")])
        with self.assertRaises(OSError):
            run_body("Ex2STR_41_GetCurrentModeRepeat", (output, kind), context)
        self.assertEqual(context.events[-1], ("finalize",))

    def test_str41_result_literal_protocol_gate_and_old_asm_bit_branch(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for status, payload, expected in (
                (0, b"\x61\x13\x80", 0),
                (0, b"\x61\x13\0", 0x1009),
                (0, b"\x61\x13", 3),
                (27, b"", 27),
            ):
                context = Context([(status, payload)])
                context.module_sha256 = module
                context.parameters[0x70] = 0x11
                context.cancelled = True
                self.assertEqual(
                    run_body("Ex2STR_41_ResultTransponderID", (), context), expected
                )
                self.assertEqual(context.events[-1], ("finalize",))
                self.assertIn(("initialize", 0), context.events)
            context = Context()
            context.module_sha256 = module
            context.parameters[0x70] = 0x12
            self.assertEqual(run_body("Ex2STR_41_ResultTransponderID", (), context), 99)
            self.assertEqual(context.events, [])

    def test_str41_repeat_status_native_count_history_and_lifecycle(self):
        for module, key, tail in (
            (NK12, "100f5b44", "100f5b48"),
            (NK18, "1015eb2c", "1015eb30"),
            (NK_DS4, "101c5d10", "101c5d14"),
            (NK_GTSPLUS, "101dd618", "101dd61c"),
        ):
            for final, expected, baseline in (
                (0x32, 0, b"\2\2"),
                (0x33, 0x1013, b"\3\2"),
            ):
                context = Context(
                    [
                        (0, b"\x61\x14\x32"),
                        (0, b"\x61\x14\x32"),
                        (0, bytes((0x61, 0x15, final))),
                    ]
                )
                context.module_sha256 = module
                context.state["native_global:" + key] = 0x202
                output, master, secondary = (
                    bytearray(b"old!"),
                    bytearray(b"M"),
                    bytearray(b"S"),
                )
                self.assertEqual(
                    run_body(
                        "Ex2STR_41_GetCurrentStatusRepeat",
                        (output, master, secondary),
                        context,
                    ),
                    expected,
                )
                self.assertEqual(output, b"old!")
                self.assertEqual(master + secondary, baseline)
                self.assertEqual(
                    context.state["native_global:" + tail],
                    (final >> 4) | ((final & 15) << 8),
                )
                self.assertNotIn(("finalize",), context.events)
            context = Context(
                [(0, b"\x61\x14\x22"), (0, b"\x61\x12\0"), (0, b"\x61\x16\0")]
            )
            context.module_sha256 = module
            context.state["native_global:" + key] = 0x202
            output, master, secondary = (
                bytearray(b"old!"),
                bytearray(b"M"),
                bytearray(b"S"),
            )
            self.assertEqual(
                run_body(
                    "Ex2STR_41_GetCurrentStatusRepeat",
                    (output, master, secondary),
                    context,
                ),
                0x1012,
            )
            self.assertEqual(output, bytes(4))
            self.assertEqual(master + secondary, b"MS")
            self.assertNotIn(("finalize",), context.events)

    def test_str41_repeat_status_cancel_fault_and_native_force_branch(self):
        export = "Ex2STR_41_GetCurrentStatusRepeat"
        outputs = (bytearray(4), bytearray(b"M"), bytearray(b"S"))
        context = Context()
        context.cancelled = True
        self.assertEqual(run_body(export, outputs, context), 99)
        self.assertNotIn(("finalize",), context.events)
        self.assertEqual(outputs[1] + outputs[2], b"MS")
        for status in (27, 0x1012, 0x1013):
            context = Context([(status, b"")])
            self.assertEqual(run_body(export, outputs, context), status)
            self.assertEqual(("finalize",) in context.events, status == 27)
        context = Context(
            [
                (0, b"\x61\x14\x22"),
                (0, b"\x61\x12\1"),
                (0, b"\x61\x14\x22"),
                (0, b"\x61\x15\x22"),
            ]
        )
        context.state["native_global:1015eb2c"] = 0x202
        self.assertEqual(run_body(export, outputs, context), 0)
        self.assertEqual(outputs[1] + outputs[2], b"\2\2")
        context = Context([OSError("repeat status failed")])
        with self.assertRaises(OSError):
            run_body(export, outputs, context)
        self.assertEqual(context.events[-1], ("finalize",))

    def test_str41_registration_full_word_modes_commands_and_timestamps(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for mode, request in ((1, b"\x3b\x01\0\0\x40\0"), (0x101, b"\x3b\x01\x20")):
                context = Context([(0, b"\x7b\x01"), (0, b"\x61\0")])
                context.module_sha256 = module
                clock = bytearray(b"time")
                self.assertEqual(
                    run_body("Ex2STR_41_RegTransponderID", (mode, 4, clock), context), 0
                )
                self.assertIn(("exchange", request), context.events)
                self.assertEqual(clock, b"\xfe\xff\xff\xff" if mode == 1 else b"time")
                self.assertNotIn(("finalize",), context.events)
            context = Context([(0, b"\x61\0"), (0, b"\x61\x14\x32"), (0, b"\x7b\x01")])
            context.module_sha256 = module
            clock, mode_output = bytearray(4), bytearray(b"mode")
            self.assertEqual(
                run_body(
                    "Ex2STR_41_StartCommunication", (6, clock, mode_output, 1), context
                ),
                0,
            )
            self.assertEqual(clock, b"\xfe\xff\xff\xff")
            self.assertEqual(mode_output, b"mode")
            self.assertIn(("exchange", b"\x3b\x01\0\0\x80" + bytes(3)), context.events)
            self.assertNotIn(("finalize",), context.events)

    def test_str41_new_key_timeout_fallback_and_native_errors(self):
        for status, reply, fallback, expected, finalized in (
            (2, b"", (), 0x1011, False),
            (0, b"\x7b\x01", (), 0, False),
            (0, b"\x7b\x02", ((0, b"\x61\x16\x20"),), 0x1010, False),
            (27, b"", ((7, b""),), 7, True),
        ):
            context = Context([(0, b"\x61\x14\x32"), (status, reply), *fallback])
            output = bytearray(b"mode")
            self.assertEqual(
                run_body("Ex2STR_41_RegNewKey", (output, 0), context), expected
            )
            self.assertEqual(output, b"\1\0\0\0" if expected == 0x1010 else b"mode")
            self.assertEqual(("finalize",) in context.events, finalized)
        for status, reply, expected in (
            (0, b"\x7b\x02", 0x100A),
            (27, b"", 0x100A),
            (2, b"", 2),
            (5, b"", 5),
        ):
            context = Context([(status, reply)])
            self.assertEqual(
                run_body("Ex2STR_41_RegTransponderID", (0, 0, None), context), expected
            )
            self.assertEqual(context.events[-1], ("finalize",))
        context = Context()
        context.cancelled = True
        clock = bytearray(4)
        self.assertEqual(
            run_body("Ex2STR_41_RegTransponderID", (1, 0x100, clock), context), 99
        )
        self.assertEqual(context.state["native_global:1015eb38"], 0x100)
        self.assertEqual(context.events[-1], ("finalize",))

    def test_str41_keepalive_check_uint32_wrap_timestamp_and_error(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            context = Context([(0, b"\x61\0")])
            context.module_sha256 = module
            context.parameters[0x70] = 0x11
            ticks = iter((0x700, 0x701))
            context.ticks = lambda ticks=ticks: next(ticks)
            exchange = context.exchange

            def cancel(request, *, exchange=exchange, context=context):
                result = exchange(request)
                context.cancelled = True
                return result

            context.exchange = cancel
            timestamp = bytearray((0xFFFFFF00).to_bytes(4, "little"))
            self.assertEqual(
                run_body("Ex2STR_41_StartKeepAliveCheck", (timestamp,), context), 0
            )
            self.assertEqual(timestamp, (0x701).to_bytes(4, "little"))
            self.assertFalse(
                any(event[0] in ("initialize", "finalize") for event in context.events)
            )
            for status, reply in ((27, b""), (0, b"\x61\1")):
                context = Context([(status, reply)])
                context.module_sha256 = module
                context.parameters[0x70] = 0x11
                timestamp = bytearray(4)
                self.assertEqual(
                    run_body("Ex2STR_41_StartKeepAliveCheck", (timestamp,), context),
                    0x1016,
                )
                self.assertEqual(timestamp, b"\xfe\xff\xff\xff")
                self.assertNotIn(("finalize",), context.events)
        context = Context()
        context.parameters[0x70] = 0x11
        context.cancelled = True
        timestamp = bytearray(b"time")
        self.assertEqual(
            run_body("Ex2STR_41_StartKeepAliveCheck", (timestamp,), context), 99
        )
        self.assertEqual(timestamp, b"time")
        context = Context([OSError("keepalive failed")])
        context.parameters[0x70] = 0x11
        with self.assertRaises(OSError):
            run_body("Ex2STR_41_StartKeepAliveCheck", (bytearray(4),), context)
        self.assertEqual(context.events[-1], ("finalize",))

    def test_ec19_support_exact_reply_and_cancel_before_exchange_all_images(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for name, selector in (
                ("Ex2ECD_19_CheckCodeSupportInfo", 0),
                ("Ex2ECD_19_CheckCodeSupportWID20Info", 0x20),
            ):
                for payload, expected in (
                    (bytes((0xE9, selector)) + b"abcd", 0),
                    (bytes((0xE9, selector)) + b"abcde", 3),
                    (b"\xe9\x22abcd", 3),
                ):
                    context = Context([(0, payload)])
                    context.module_sha256 = module
                    output = bytearray(b"old!")
                    self.assertEqual(run_body(name, (output,), context), expected)
                    self.assertEqual(output, b"abcd" if expected == 0 else b"old!")
                    self.assertIn(("exchange", bytes((0xA9, selector))), context.events)
                    self.assertEqual(context.events[-1], ("finalize",))
                context = Context()
                context.module_sha256 = module
                context.cancelled = True
                output = bytearray(b"old!")
                self.assertEqual(run_body(name, (output,), context), 0)
                self.assertEqual(output, b"old!")
                self.assertIn(("initialize", 0), context.events)
                self.assertFalse(
                    any(event[0] == "exchange" for event in context.events)
                )

    def test_ec_wid20_record_offsets_and_preserved_flags_all_images(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            context = Context([(0, b"\xe9\x20abcdextra")])
            context.module_sha256 = module
            context.cancelled = True
            record = bytearray(b"prefix123tail")
            self.assertEqual(
                run_body("Ex2ECD_16_GetCodeSupportWID20", (record,), context), 0
            )
            self.assertEqual(record, b"prefiabcdtail")
            for name, offset, count, initial, expected, wanted in (
                (
                    "Ex2ECD_15_CheckCodeSupportWID20Info",
                    16,
                    4,
                    b"\x04\0",
                    0,
                    b"\x05\x80",
                ),
                (
                    "Ex2ECD_15_CheckCodeSupportWID20Info",
                    16,
                    2,
                    b"\x04\0",
                    1501,
                    b"\x04\0",
                ),
                ("Ex2ECD_15_CheckCodeSupportWID20Info", 16, 0, b"\x08\0", 0, b"\x08\0"),
                ("Ex2ECD_20_CheckCodeSupportWID20Info", 32, 2, b"\x80", 0, b"\x82"),
                ("Ex2ECD_20_CheckCodeSupportWID20Info", 32, 1, b"\0", 2000, b"\0"),
            ):
                context = Context([(0, b"\x7b\x20\x02\x04\0\0")])
                context.module_sha256 = module
                context.cancelled = True
                record = bytes(offset) + bytes((count,))
                output = bytearray(initial)
                self.assertEqual(run_body(name, (record, output), context), expected)
                self.assertEqual(output, wanted)
                self.assertEqual(context.events[-1], ("finalize",))
        context = Context([(0, b"\x7b\x20\2\4\0\0extra")])
        output = bytearray(b"\0\0")
        self.assertEqual(
            run_body(
                "Ex2ECD_15_CheckCodeSupportWID20Info",
                (bytes(16) + b"\4", output),
                context,
            ),
            3,
        )
        self.assertEqual(output, bytes(2))

    def test_learning_mode_retained_session_and_distinct_nrc22_errors(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for name, nrc in (
                ("Ex2ECD_09_ChgNormalLearningMode", 902),
                ("Ex2ECD_10_ChgDetailLearningMode", 1002),
            ):
                for status, reply, expected in (
                    (0, b"\x7b\x10", 0),
                    (7, b"\x7f\x3b\x22", nrc),
                    (7, b"\x7f\x3b\x31", 7),
                    (0, b"\x7b\x10\0", 3),
                ):
                    context = Context([(status, reply)])
                    context.module_sha256 = module
                    context.cancelled = True
                    self.assertEqual(run_body(name, (0x101,), context), expected)
                    self.assertIn(("exchange", b"\x3b\x10\xaa\1"), context.events)
                    self.assertFalse(
                        any(event[0] == "initialize" for event in context.events)
                    )
                    self.assertEqual(("finalize",) in context.events, expected != 0)
            for name in ("Ex2ECD_09_EraseDiagCode", "Ex2ECD_10_EraseDiagCode"):
                for mode in (1, 0x101):
                    context = Context([(0, b"\x44")])
                    context.module_sha256 = module
                    context.cancelled = True
                    self.assertEqual(run_body(name, (mode,), context), 0)
                    self.assertEqual(("initialize", 0) in context.events, mode == 1)
                    self.assertEqual(
                        context.events[-2:], [("exchange", b"\4"), ("finalize",)]
                    )
        context = Context([(0, b"\x44\0")])
        self.assertEqual(run_body("Ex2ECD_09_EraseDiagCode", (0,), context), 3)

    def test_str43_state_recovery_native_fault_mapping_and_finalization(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for status, reply, expected, recover in (
                (0, b"\x61\x14\0", 0, False),
                (0, b"\x61\x14\1", 0x10D3, False),
                (2, b"", 0x10D1, True),
                (5, b"", 0x10D1, True),
                (27, b"", 0x10D2, True),
                (0, b"\x61\x13\0", 0x10D2, True),
            ):
                context = Context([(status, reply)], initialize=27)
                context.module_sha256 = module
                context.cancelled = True
                self.assertEqual(
                    run_body("Ex2STR_43_CheckRegisteredKeyNum", (), context), expected
                )
                self.assertEqual(
                    context.events.count(("finalize",)), 2 if recover else 1
                )
                self.assertEqual(("initialize", 0) in context.events, recover)
                if recover:
                    self.assertEqual(context.events[-3][0], "initialize")
            context = Context()
            context.module_sha256 = module
            self.assertEqual(run_body("Ex2STR_43_StartCommunication", (), context), 0)
            self.assertNotIn(("finalize",), context.events)
            context = Context(initialize=27)
            context.module_sha256 = module
            self.assertEqual(run_body("Ex2STR_43_StartCommunication", (), context), 27)
            self.assertEqual(context.events[-1], ("finalize",))

    def test_str43_mode_thread_cancel_keeps_session_but_errors_recover(self):
        context = Context([(0, b"\x61\x16\x20")])
        exchange = context.exchange

        def cancel(request):
            result = exchange(request)
            context.cancelled = True
            return result

        context.exchange = cancel
        self.assertEqual(run_body("Ex2STR_43_CheckModeThread", (), context), 0)
        self.assertNotIn(("finalize",), context.events)
        context = Context()
        context.cancelled = True
        self.assertEqual(run_body("Ex2STR_43_CheckModeThread", (), context), 0x10D2)
        self.assertEqual(context.events[-1], ("finalize",))
        context = Context([(0, b"\x61\x16\0")])
        self.assertEqual(run_body("Ex2STR_43_CheckModeThread", (), context), 0x10D2)
        self.assertEqual(context.events.count(("finalize",)), 2)
        context = Context([OSError("STR43 failed")])
        with self.assertRaises(OSError):
            run_body("Ex2STR_43_CheckModeThread", (), context)
        self.assertEqual(context.events[-1], ("finalize",))

    def test_native_switch_confirmation_exact_tables_all_images(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for name in (
                "Ex2STR_20_ComfirmSwitchAccOff",
                "Ex2STR_20_ComfirmSwitchAccOffIgOn",
                "Ex2STR_22_ComfirmSwitchAccOffIgOn",
            ):
                replies = [(0, b"\x61\x21\x02"), (0, b"\x61\x21\0")]
                if name.endswith("IgOn"):
                    replies += [(0, b"\x61\x21\0"), (0, b"\x61\x21\x08")]
                context = Context(replies)
                context.module_sha256 = module
                self.assertEqual(run_body(name, (), context), 0)
                self.assertFalse(
                    any(
                        event[0] in ("initialize", "finalize")
                        for event in context.events
                    )
                )
                self.assertEqual(
                    sum(event[0] == "exchange" for event in context.events),
                    len(replies),
                )
                context = Context()
                context.module_sha256 = module
                context.cancelled = True
                self.assertEqual(run_body(name, (), context), 0)
                self.assertFalse(
                    any(event[0] == "exchange" for event in context.events)
                )

    def test_switch_confirmation_cancel_preserves_mismatch_status(self):
        for name, expected in (
            ("Ex2STR_20_ComfirmSwitchAccOff", 504),
            ("Ex2STR_22_ComfirmSwitchAccOffIgOn", 2204),
        ):
            context = Context([(0, b"\x61\x21\2")])
            exchange = context.exchange

            def cancel(request, *, exchange=exchange, context=context):
                result = exchange(request)
                context.cancelled = True
                return result

            context.exchange = cancel
            self.assertEqual(run_body(name, (), context), expected)
            self.assertNotIn(("finalize",), context.events)
        context = Context([(0, b"\x61\x20\0")])
        self.assertEqual(run_body("Ex2STR_20_ComfirmSwitchAccOff", (), context), 3)
        self.assertNotIn(("finalize",), context.events)
        context = Context([OSError("switch failed")])
        with self.assertRaises(OSError):
            run_body("Ex2STR_20_ComfirmSwitchAccOff", (), context)
        self.assertEqual(context.events[-1], ("finalize",))

    def test_switch_support_concrete_cache_primitives_and_native_lifecycle(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for name, selector, mask, first_error, second_error in (
                ("Ex2STR_20_GetSupportBitInfo", 0xC1, 0xC0, 501, 502),
                ("Ex2STR_22_GetSupportInfo", 0xA4, 2, 2201, 2202),
            ):
                first = self.str41_snapshot(
                    ((0x21, b"\x0a"), (0x22, b"\x80"), (0x24, b"\xff" * 4))
                )
                context = Context()
                context.module_sha256 = module
                context.cancelled = True
                context.snapshots = [
                    first,
                    self.str41_snapshot(((selector, bytes((mask,))),)),
                ]
                self.assertEqual(run_body(name, (), context), 0)
                self.assertEqual(
                    [
                        event
                        for event in context.events
                        if event[0] == "refresh_support_cache"
                    ],
                    [("refresh_support_cache", 1), ("refresh_support_cache", 3)],
                )
                self.assertNotIn(("finalize",), context.events)
                context = Context()
                context.module_sha256 = module
                self.assertEqual(run_body(name, (), context), first_error)
                self.assertEqual(
                    ("finalize",) in context.events, name.startswith("Ex2STR_22")
                )
                context = Context()
                context.module_sha256 = module
                context.snapshots = [first, self.str41_snapshot(((selector, b"\0"),))]
                self.assertEqual(run_body(name, (), context), second_error)
                self.assertEqual(
                    ("finalize",) in context.events, name.startswith("Ex2STR_22")
                )
        context = Context()
        context.snapshot = (80, bytes(0x1020), (0x1020,) * 256)
        self.assertEqual(run_body("Ex2STR_20_GetSupportBitInfo", (), context), 80)
        self.assertNotIn(("finalize",), context.events)
        context = Context(initialize=27)
        self.assertEqual(run_body("Ex2STR_20_GetSupportBitInfo", (), context), 27)
        self.assertNotIn(("finalize",), context.events)

    def test_str41_42_starters_bind_actual_shared_cmn_parameters(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for name in ("Ex2STR_41_StartKeepAlive", "Ex2STR_42_StartKeepAlive"):
                context = Context()
                context.module_sha256 = module
                context.parameters[0x70] = 0x11
                context.cancelled = True
                self.assertEqual(run_body(name, (), context), 15)
                self.assertEqual(
                    context.events, [("start_selected_cmn", 2000, 0, None, 0)]
                )
            context = Context()
            context.module_sha256 = module
            context.parameters[0x70] = 0x12
            self.assertEqual(run_body("Ex2STR_41_StartKeepAlive", (), context), 99)
            self.assertEqual(context.events, [])

    def test_additional_cmn_starters_literal_payload_and_mode3_limits(self):
        for module, retry, pending in (
            (NK12, "fa80", "fa90"),
            (NK18, "172f0", "17320"),
            (NK_DS4, "32480", "32450"),
            (NK_GTSPLUS, "33390", "33360"),
        ):
            for name in ("Ex2STR_20_StartKeepAlive", "Ex2STR_22_StartKeepAlive"):
                context = Context()
                context.module_sha256 = module
                context.cancelled = True
                self.assertEqual(run_body(name, (), context), 15)
                self.assertEqual(
                    context.events, [("start_selected_cmn", 2000, 1, b"\x3e", 1)]
                )
            for name in ("Ex2STR_55_StartKeepAlive", "Ex2STR_56_StartKeepAlive"):
                context = Context()
                context.module_sha256 = module
                if module == NK12:
                    with self.assertRaises(NotImplementedError):
                        run_body(name, (), context)
                else:
                    self.assertEqual(run_body(name, (), context), 15)
                    self.assertEqual(
                        context.events, [("start_selected_cmn", 2000, 0, None, 0)]
                    )
            context = Context()
            context.module_sha256 = module
            context.mode = 3
            self.assertEqual(
                run_body("Ex2STR_StartKeepAlive", (0xFFFFFFFF,), context), 15
            )
            self.assertEqual(
                context.events,
                [
                    ("comm", "selected"),
                    ("configure", "native_rva:" + retry, 4),
                    ("configure", "native_rva:" + pending, 1),
                    ("start_selected_cmn", 0xFFFFFFFF, 0, None, 0),
                ],
            )
            context = Context()
            context.module_sha256 = module
            self.assertEqual(run_body("Ex2STR_StartKeepAlive", (20,), context), 99)
            self.assertFalse(context.events)

    def test_ecd_keepalive_has_only_protocol_guard_and_ignores_busy_status(self):
        class BusyContext(Context):
            def start_selected_cmn(
                self, interval_ms, skip_response_validation=0, request=None, length=0
            ):
                super().start_selected_cmn(
                    interval_ms, skip_response_validation, request, length
                )
                return 16

        for module, retry, pending in (
            (NK12, "fa80", "fa90"),
            (NK18, "172f0", "17320"),
            (NK_DS4, "32480", "32450"),
            (NK_GTSPLUS, "33390", "33360"),
        ):
            for name in ("Ex2ECD_09_StartKeepAlive", "Ex2ECD_10_StartKeepAlive"):
                for protocol in (0x11, 0x21, 0x51):
                    context = BusyContext()
                    context.module_sha256 = module
                    context.mode = 0xFFFFFFFF
                    context.parameters[0x70] = protocol
                    context.cancelled = True
                    self.assertEqual(run_body(name, (), context), 0)
                    self.assertEqual(
                        context.events,
                        [
                            ("comm", "selected"),
                            ("configure", "native_rva:" + retry, 0),
                            ("configure", "native_rva:" + pending, 0),
                            ("start_selected_cmn", 2000, 1, b"\x21\x0c", 2),
                        ],
                    )
                context = BusyContext()
                context.module_sha256 = module
                context.parameters[0x70] = 0x12
                self.assertEqual(run_body(name, (), context), 99)
                self.assertEqual(context.events, [])

    def test_switch_registration_cached_length_padding_and_old_unused_word(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for name in ("Ex2STR_20_StartKeyRegist", "Ex2STR_20_EndKeyRegist"):
                context = Context([(0, b"\x7b\xc1"), (0, b"\x61\x22\x80")])
                context.module_sha256 = module
                context.cancelled = True
                _, data, offsets = self.str41_snapshot(((0xC1, b"\xc0\0\0\0"),))
                context.cached[3] = data, offsets
                ending = name.endswith("EndKeyRegist")
                args = ()
                self.assertEqual(run_body(name, args, context), 0)
                self.assertIn(
                    (
                        "exchange",
                        b"\x3b\xc1" + bytes((0x80 if ending else 0x40,)) + bytes(3),
                    ),
                    context.events,
                )
                self.assertFalse(
                    any(
                        event[0] in ("initialize", "finalize")
                        for event in context.events
                    )
                )
                self.assertEqual(("sleep", 1000) in context.events, not ending)
                context = Context()
                context.module_sha256 = module
                self.assertEqual(run_body(name, args, context), 82)
                self.assertFalse(
                    any(event[0] == "exchange" for event in context.events)
                )
        for first_status, first_reply, second_status, second_reply, expected in (
            (7, b"\x7f\x3b\x22", 0, b"", 507),
            (27, b"", 0, b"", 27),
            (0, b"\x7b\xc1", 27, b"", 506),
            (0, b"\x7b\xc1", 0, b"\x61\x22\0", 503),
        ):
            context = Context(
                [(first_status, first_reply), (second_status, second_reply)]
            )
            _, data, offsets = self.str41_snapshot(((0xC1, b"\xc0"),))
            context.cached[3] = data, offsets
            self.assertEqual(
                run_body("Ex2STR_20_StartKeyRegist", (), context), expected
            )
            self.assertNotIn(("finalize",), context.events)

    def test_str43_keepalive_exact_post12_export_continues_after_native_error(self):
        name = "_Ex2STR_43_StartKeepAliveThread@4"
        self.assertNotIn(name, supported_operations(NK12))
        for module in (NK18, NK_DS4, NK_GTSPLUS):
            context = Context([(27, b""), (0, b"\x7e")])
            context.module_sha256 = module
            ticks = iter((4096, 4097, 8197, 8198))
            context.ticks = lambda ticks=ticks: next(ticks)
            exchange = context.exchange

            def cancel_after_second(request, *, exchange=exchange, context=context):
                result = exchange(request)
                if result[0] == 0:
                    context.cancelled = True
                return result

            context.exchange = cancel_after_second
            clock = bytearray(4)
            self.assertEqual(run_body(name, (clock,), context), 0)
            self.assertEqual(clock, (8198).to_bytes(4, "little"))
            self.assertEqual(
                [event for event in context.events if event[0] == "exchange"],
                [("exchange", b"\x3e")] * 2,
            )
            self.assertNotIn(("finalize",), context.events)
            context = Context()
            context.module_sha256 = module
            context.cancelled = True
            self.assertEqual(run_body(name, (clock,), context), 99)
            self.assertFalse(any(event[0] == "exchange" for event in context.events))
        context = Context()
        context.module_sha256 = NK12
        with self.assertRaises(NotImplementedError):
            run_body(name, (bytearray(4),), context)

    def test_switch_key_counts_literal_order_partial_commit_and_alias(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for name, expected in (
                ("Ex2STR_20_GetTheKeyNumber", (15, 23)),
                ("Ex2STR_22_GetKeyNumber", (5, 3)),
            ):
                context = Context([(0, b"\x61\x24\x21\x43\x65\xf7")])
                context.module_sha256 = module
                context.cancelled = True
                master, secondary = (
                    bytearray((10).to_bytes(4, "little")),
                    bytearray((20).to_bytes(4, "little")),
                )
                self.assertEqual(run_body(name, (master, secondary), context), 0)
                self.assertEqual(
                    (
                        int.from_bytes(master, "little"),
                        int.from_bytes(secondary, "little"),
                    ),
                    expected,
                )
                self.assertNotIn(("finalize",), context.events)
                context = Context([(0, b"\x61\x24\x21\x43\x85\xf7")])
                context.module_sha256 = module
                master, secondary = (
                    bytearray((10).to_bytes(4, "little")),
                    bytearray((20).to_bytes(4, "little")),
                )
                older = name.startswith("Ex2STR_20")
                self.assertEqual(
                    run_body(name, (master, secondary), context), 505 if older else 2203
                )
                self.assertEqual(
                    (
                        int.from_bytes(master, "little"),
                        int.from_bytes(secondary, "little"),
                    ),
                    (10, 23) if older else (10, 20),
                )
                self.assertEqual(("finalize",) in context.events, not older)
            context = Context([(0, b"\x61\x24\x21\x43\x65\xf7")])
            context.module_sha256 = module
            shared = bytearray(b"\xff" * 4)
            self.assertEqual(
                run_body("Ex2STR_20_GetTheKeyNumber", (shared, shared), context), 0
            )
            self.assertEqual(shared, (7).to_bytes(4, "little"))
            context = Context([(0, b"\x61\x24\x21\x43\x65\xf7")])
            context.module_sha256 = module
            self.assertEqual(
                run_body("Ex2STR_22_GetKeyNumber", (shared, shared), context), 0
            )
            self.assertEqual(shared, (3).to_bytes(4, "little"))

    def test_switch_registration_count_increase_status_error_and_cancel(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for reply, status, wanted in (
                (b"\x61\x24\x21\x43\x65\xf7", 0, (5, 3, 4, 3)),
                (b"\x61\x24\x21\x43\x85\xf7", 505, (99, 98, 4, 3)),
                (b"\x61\x24\0\0\0\0", 503, (99, 98, 4, 3)),
            ):
                context = Context([(0, reply), (0, b"\x61\x22\0")])
                context.module_sha256 = module
                record = bytearray(
                    b"".join(value.to_bytes(4, "little") for value in (99, 98, 4, 3))
                )
                self.assertEqual(
                    run_body("Ex2STR_20_KeyRegist", (record,), context), status
                )
                self.assertEqual(
                    record, b"".join(value.to_bytes(4, "little") for value in wanted)
                )
                self.assertNotIn(("finalize",), context.events)
            context = Context()
            context.module_sha256 = module
            context.cancelled = True
            record = bytearray(range(16))
            self.assertEqual(run_body("Ex2STR_20_KeyRegist", (record,), context), 0)
            self.assertFalse(any(event[0] == "exchange" for event in context.events))
            self.assertEqual(record, bytearray(range(16)))

    def test_reductant_support_cache_kinds_and_literal_fields(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for first, second, expected in (
                (b"\0\0\xff\xff\xff\xff", b"\x44\x44", 0),
                (b"\0\0\xff\xff\0\xff", b"\x44\x44", 3011),
                (b"\0\0\xff\xff\xff\xff", b"\x44\x04", 3012),
            ):
                context = Context()
                context.module_sha256 = module
                context.cancelled = True
                context.snapshots = [
                    self.str41_snapshot(((0x4B, first),)),
                    self.str41_snapshot(((0x50, second),)),
                ]
                self.assertEqual(
                    run_body("Ex2ECD_50_GetSupportInfo", (), context), expected
                )
                kinds = [
                    event[1]
                    for event in context.events
                    if event[0] == "refresh_support_cache"
                ]
                self.assertEqual(kinds, [1] if expected == 3011 else [1, 2])
                self.assertEqual(context.events[-1], ("finalize",))
                self.assertFalse(
                    any(event[0] == "exchange" for event in context.events)
                )
            context = Context(initialize=31)
            context.module_sha256 = module
            self.assertEqual(run_body("Ex2ECD_50_GetSupportInfo", (), context), 31)
            self.assertEqual(context.events[-1], ("finalize",))

    def test_str53_single_source_wire_timestamps_outputs_and_lifetime(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for name, payloads, expected, requests, finalized in (
                (
                    "Ex2STR_53_GetKeySWStatus_Single",
                    (b"\x61\x16\0", b"\x61\x11\0"),
                    0,
                    (b"\x21\x16", b"\x21\x11"),
                    False,
                ),
                (
                    "Ex2STR_53_GetKeySWStatus_Single",
                    (b"\x61\x16\0", b"\x61\x11\x20"),
                    4501,
                    (b"\x21\x16", b"\x21\x11"),
                    True,
                ),
                (
                    "Ex2STR_53_GetKeyStatus_Single",
                    (b"\x61\x16\0", b"\x61\x11\x20", b"\x61\x17\xa3"),
                    0,
                    (b"\x21\x16", b"\x21\x11", b"\x21\x17"),
                    False,
                ),
                (
                    "Ex2STR_53_GetKeyStatus_Single",
                    (b"\x61\x16\0", b"\x61\x11\0"),
                    4501,
                    (b"\x21\x16", b"\x21\x11"),
                    True,
                ),
                (
                    "Ex2STR_53_GetImmobilizerMode_Single",
                    (b"\x61\x16\x20", b"\x61\x17\xa3"),
                    0,
                    (b"\x21\x16", b"\x21\x17"),
                    True,
                ),
                (
                    "Ex2STR_53_GetImmobilizerMode_Single",
                    (b"\x61\x16\0",),
                    4502,
                    (b"\x21\x16",),
                    True,
                ),
            ):
                context = Context((0, reply) for reply in payloads)
                context.module_sha256 = module
                clock, high, low = (
                    bytearray(4),
                    bytearray(b"\x77\x88"),
                    bytearray(b"\x66"),
                )
                args = (clock,) if "SWStatus" in name else (clock, high, low)
                self.assertEqual(run_body(name, args, context), expected)
                self.assertEqual(clock, b"\xfe\xff\xff\xff")
                self.assertEqual(
                    tuple(
                        event[1] for event in context.events if event[0] == "exchange"
                    ),
                    requests,
                )
                self.assertEqual(("finalize",) in context.events, finalized)
                if expected == 0 and "SWStatus" not in name:
                    self.assertEqual((high, low), (b"\x0a\x88", b"\x03"))
                else:
                    self.assertEqual((high, low), (b"\x77\x88", b"\x66"))
            context = Context([(0, b"\x61\x11\x20"), (0, b"\x61\x17\xa3")])
            context.module_sha256 = module
            clock = bytearray((0xFFFFFC17).to_bytes(4, "little"))
            self.assertEqual(
                run_body(
                    "Ex2STR_53_GetKeyStatus_Single", (clock, clock, clock), context
                ),
                0,
            )
            self.assertEqual(clock, b"\x03\xfc\xff\xff")
            self.assertNotIn(("exchange", b"\x21\x16"), context.events)
            context = Context([(0, b"\x61\x99\0")])
            context.module_sha256 = module
            clock = bytearray(4)
            self.assertEqual(
                run_body("Ex2STR_53_GetKeySWStatus_Single", (clock,), context), 3
            )
            self.assertEqual(clock, b"\xfe\xff\xff\xff")
            self.assertEqual(context.events[-1], ("finalize",))
            context = Context()
            context.module_sha256 = module
            context.cancelled = True
            clock = bytearray(4)
            self.assertEqual(
                run_body("Ex2STR_53_GetKeySWStatus_Single", (clock,), context), 99
            )
            self.assertEqual(clock, bytearray(4))
            self.assertEqual(context.events[-1], ("finalize",))

    def test_str53_poll_literal_retry_cancel_and_wrapper_global_references(self):
        class CancelAfterReply(Context):
            def exchange(self, request):
                result = super().exchange(request)
                if len([event for event in self.events if event[0] == "exchange"]) == 3:
                    self.cancelled = True
                return result

        for module, base in (
            (NK12, 0x100E5D58),
            (NK18, 0x1014A7B0),
            (NK_DS4, 0x101B1AD0),
            (NK_GTSPLUS, 0x101BCBD0),
        ):
            for name, replies, wanted in (
                (
                    "Ex2STR_53_GetKeySWStatus",
                    (b"\x61\x16\0", b"\x61\x11\x20", b"\x61\x11\0"),
                    (0, 0),
                ),
                (
                    "Ex2STR_53_GetKeyStatus",
                    (b"\x61\x16\0", b"\x61\x11\0", b"\x61\x11\x20", b"\x61\x17\xa3"),
                    (10, 3),
                ),
                (
                    "Ex2STR_53_GetImmobilizerMode",
                    (b"\x61\x16\x20", b"\x61\x17\xa3", b"\x61\x17\xb4"),
                    (11, 4),
                ),
            ):
                context = (
                    CancelAfterReply((0, reply) for reply in replies)
                    if "Immobilizer" in name
                    else Context((0, reply) for reply in replies)
                )
                context.module_sha256 = module
                clock, high, low = bytearray(4), bytearray(1), bytearray(1)
                args = (clock,) if "SWStatus" in name else (clock, high, low)
                self.assertEqual(run_body(name, args, context), 0)
                self.assertEqual((high[0], low[0]), wanted)
                self.assertEqual(clock, b"\xfe\xff\xff\xff")
                self.assertNotIn(("finalize",), context.events)
                if len(args) == 3:
                    for index, arg in enumerate(args):
                        self.assertIs(
                            context.state[f"native_global:{base + index * 4:08x}"], arg
                        )
                    context.mode = 3
                    self.assertEqual(run_body(name, args, context), 99)
                    self.assertIs(context.state[f"native_global:{base:08x}"], clock)
                context = Context()
                context.module_sha256 = module
                context.cancelled = True
                self.assertEqual(run_body(name, args, context), 99)
                self.assertEqual(context.events[-1], ("finalize",))
            context = CancelAfterReply([(0, b"\x61\x11\x20")] * 3)
            context.module_sha256 = module
            clock = bytearray(b"\xfe\xff\xff\xff")
            self.assertEqual(
                run_body("Ex2STR_53_GetKeySWStatus", (clock,), context), 4501
            )
            self.assertNotIn(("finalize",), context.events)
            context = Context([(7, b"\x7f\x21\x31")])
            context.module_sha256 = module
            self.assertEqual(
                run_body("Ex2STR_53_GetKeySWStatus", (bytearray(4),), context), 7
            )
            self.assertEqual(context.events[-1], ("finalize",))

    def test_str53_onexit_retains_only_after_successful_tick_exchange(self):
        class CancelOnCheck(Context):
            checks = 0

            def is_cancelled(self):
                self.checks += 1
                return self.checks > 1

        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for clock_value, replies, expected, finalizes in (
                (0, [(0, b"\x61\x16\0")], 0, False),
                (0xFFFFFFFE, [], 99, True),
                (0, [(5, b"")], 5, True),
            ):
                context = CancelOnCheck(replies)
                context.module_sha256 = module
                clock = bytearray(clock_value.to_bytes(4, "little"))
                self.assertEqual(
                    run_body("Ex2STR_53_GetImmobilizerMode_OnExit", (clock,), context),
                    expected,
                )
                self.assertEqual(("finalize",) in context.events, finalizes)

    def test_shared_native_fields_override_stale_worker_arguments_and_remain_live(self):
        for module, repeat_refs, status_refs, reg_base, str53_base in (
            (
                NK12,
                ("100e5d48", "100e5d4c"),
                ("100e5d10", "100e5d14", "100e5d18"),
                0x100E5D70,
                0x100E5D58,
            ),
            (
                NK18,
                ("1014a790", "1014a794"),
                ("1014a738", "1014a73c", "1014a740"),
                0x1014A7D8,
                0x1014A7B0,
            ),
            (
                NK_DS4,
                ("101b1aec", "101b1af0"),
                ("101b1af4", "101b1af8", "101b1afc"),
                0x101B1A80,
                0x101B1AD0,
            ),
            (
                NK_GTSPLUS,
                ("101bcbec", "101bcbf0"),
                ("101bcbf4", "101bcbf8", "101bcbfc"),
                0x101BCB80,
                0x101BCBD0,
            ),
        ):
            context = Context()
            context.module_sha256 = module
            context.cancelled = True
            stale = (bytearray(4), bytearray(4))
            latest = (bytearray(4), bytearray(4))
            for key, value in zip(repeat_refs, latest):
                context.state["native_global:" + key] = value
            self.assertEqual(
                run_body("Ex2STR_41_GetCurrentModeRepeat", stale, context), 99
            )
            self.assertEqual(stale[0], bytes(4))
            self.assertEqual(latest[0], b"\1\0\0\0")
            context = Context()
            context.module_sha256 = module
            context.cancelled = True
            status_latest = (bytearray(4), bytearray(1), bytearray(1))
            for key, value in zip(status_refs, status_latest):
                context.state["native_global:" + key] = value
            self.assertEqual(
                run_body(
                    "Ex2STR_41_GetCurrentStatusRepeat",
                    (bytearray(4), bytearray(1), bytearray(1)),
                    context,
                ),
                99,
            )
            for key, value in zip(status_refs, status_latest):
                self.assertIs(context.state["native_global:" + key], value)
            context = Context()
            context.module_sha256 = module
            context.cancelled = True
            latest_reg = (1, 0, 3, bytearray(4))
            for index, value in enumerate(latest_reg):
                context.state[f"native_global:{reg_base + index * 4:x}"] = value
            self.assertEqual(
                run_body("Ex2STR_41_RegTransponderID", (0, 0, None), context), 99
            )
            for index, value in enumerate(latest_reg):
                self.assertIs(
                    context.state[f"native_global:{reg_base + index * 4:x}"], value
                )
            context = Context([(0, b"\x61\x11\x20"), (0, b"\x61\x17\xa3")])
            context.module_sha256 = module
            latest_clock, high, low = (
                bytearray(b"\xfe\xff\xff\xff"),
                bytearray(1),
                bytearray(1),
            )
            for index, value in enumerate((latest_clock, high, low)):
                context.state[f"native_global:{str53_base + index * 4:08x}"] = value
            stale3 = (bytearray(4), bytearray(1), bytearray(1))
            self.assertEqual(run_body("Ex2STR_53_GetKeyStatus", stale3, context), 0)
            self.assertEqual((high, low), (b"\x0a", b"\x03"))
            self.assertEqual(stale3, (bytearray(4), bytearray(1), bytearray(1)))
            late_mode = bytearray(4)

            class RewriteOutput(Context):
                def exchange(
                    self, request, *, reference=repeat_refs[0], output=late_mode
                ):
                    result = super().exchange(request)
                    self.state["native_global:" + reference] = output
                    return result

            context = RewriteOutput([(0, b"\x61\x16\0"), (0, b"\x61\x14\x10")])
            context.module_sha256 = module
            original = (bytearray(4), bytearray(4))
            self.assertEqual(
                run_body("Ex2STR_41_GetCurrentModeRepeat", original, context), 0
            )
            self.assertEqual(original[0], b"\1\0\0\0")
            self.assertEqual(late_mode, bytes(4))
            self.assertIs(context.state["native_global:" + repeat_refs[0]], late_mode)

    def test_str43_support_literal_metadata_outputs_and_aliased_global_bytes(self):
        for module, backing, length_shift, option_shift in (
            (NK12, "100f5b58", 8, 0),
            (NK18, "1015eb48", 0, 0),
            (NK_DS4, "101c5d14", 16, 24),
            (NK_GTSPLUS, "101dd61c", 16, 24),
        ):
            for first_option, command, expected, wanted in (
                (2, b"\x44\xff", 4302, (2, 1, 2, 0x40)),
                (4, b"\x04\xff", 4301, (2, 0, 0x77, 0x66)),
                (2, b"\x44\x7f", 4303, (2, 1, 2, 0x66)),
            ):
                context = Context()
                context.module_sha256 = module
                context.cancelled = True
                context.state["native_global:" + backing] = (
                    0xA5A51234 if module in (NK_DS4, NK_GTSPLUS) else 0
                )
                context.snapshots = [
                    self.str41_snapshot(
                        (
                            (0x12, bytes((0x80, first_option))),
                            (0x14, b"\xff"),
                            (0x16, b"\x20"),
                        )
                    ),
                    self.str41_snapshot(((1, command),)),
                ]
                args = (
                    bytearray(4),
                    bytearray(4),
                    bytearray(b"\x77"),
                    bytearray(b"\x66"),
                )
                self.assertEqual(
                    run_body("Ex2STR_43_GetSupportInfo", args, context), expected
                )
                self.assertEqual(
                    (
                        int.from_bytes(args[0], "little"),
                        int.from_bytes(args[1], "little"),
                        args[2][0],
                        args[3][0],
                    ),
                    wanted,
                )
                value = context.state["native_global:" + backing]
                assert isinstance(value, int)
                self.assertEqual((value >> length_shift) & 255, 2)
                if module != NK18:
                    self.assertEqual((value >> option_shift) & 255, first_option)
                else:
                    self.assertEqual(
                        context.state["native_global:1015eb40"], first_option
                    )
                if module in (NK_DS4, NK_GTSPLUS):
                    self.assertEqual(value & 0xFFFF, 0x1234)
                self.assertEqual(context.events[-1], ("finalize",))
            context = Context(initialize=27)
            context.module_sha256 = module
            context.state["native_global:" + backing] = 5 << length_shift
            args = (bytearray(4), bytearray(b"flag"), bytearray(b"a"), bytearray(b"b"))
            self.assertEqual(run_body("Ex2STR_43_GetSupportInfo", args, context), 27)
            self.assertEqual(
                args,
                (
                    bytearray(b"\5\0\0\0"),
                    bytearray(b"flag"),
                    bytearray(b"a"),
                    bytearray(b"b"),
                ),
            )
            if module in (NK_DS4, NK_GTSPLUS):
                context = Context(initialize=27)
                context.module_sha256 = module
                context.state["native_global:" + backing] = 0xA503FFFF
                self.assertEqual(
                    run_body(
                        "Ex2STR_41_GetRegKeySupportInfo",
                        (bytearray(4), bytearray(4), bytearray(1)),
                        context,
                    ),
                    27,
                )
                self.assertEqual(context.state["native_global:" + backing], 0xA5030000)

    def test_str43_seed_exact_response_mode_output_and_native_retention(self):
        for module, option_key, option_value in (
            (NK12, "100f5b58", 0xC0),
            (NK18, "1015eb40", 0xC0),
            (NK_DS4, "101c5d14", 0xC0000000),
            (NK_GTSPLUS, "101dd61c", 0xC0000000),
        ):
            for mode_reply, seed_reply, expected, mode_value, seed_value in (
                (b"\x61\x12\x80\x80", b"\x67\x05ABCDEF", 4309, 432, b"ABCDEF"),
                (b"\x61\x12\x80", b"\x67\x05ABCDEF", 4309, 431, b"ABCDEF"),
                (b"\x61\x12\0", b"", 4308, 431, b"old!AB"),
                (b"\x61\x12\x80", b"\x67\x05ABCDEFG", 3, 431, b"\0\0\0\0AB"),
            ):
                context = Context([(0, mode_reply), (0, seed_reply)])
                context.module_sha256 = module
                context.state["native_global:" + option_key] = option_value
                seed, mode = bytearray(b"old!AB"), bytearray(4)
                self.assertEqual(
                    run_body("Ex2STR_43_ReqSecuritySeed", (seed, mode), context),
                    expected,
                )
                self.assertEqual(seed, seed_value)
                self.assertEqual(int.from_bytes(mode, "little"), mode_value)
                self.assertEqual(("finalize",) in context.events, expected != 4309)
                requests = [
                    event[1] for event in context.events if event[0] == "exchange"
                ]
                self.assertEqual(
                    requests,
                    [b"\x21\x12"] if expected == 4308 else [b"\x21\x12", b"\x27\x05"],
                )
            context = Context(initialize=4309)
            context.module_sha256 = module
            seed, mode = bytearray(b"old!AB"), bytearray(b"mode")
            self.assertEqual(
                run_body("Ex2STR_43_ReqSecuritySeed", (seed, mode), context), 4309
            )
            self.assertNotIn(("finalize",), context.events)
            self.assertEqual((seed, mode), (b"old!AB", b"mode"))

    def test_str43_clear_literal_key_reply_commands_and_one_mode_query(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            for mode, payloads, expected, requests in (
                (
                    1,
                    ((0, b"\x7b\x01"), (0, b"\x61\x16\x20\xff")),
                    0,
                    (b"\x3b\x01\0\3\x08\0\0", b"\x21\x16"),
                ),
                (
                    0,
                    ((0, b"\x67\x06\x34"), (0, b"\x7b\x01"), (0, b"\x61\x16\x20")),
                    0,
                    (b"\x27\x06ABCDEF", b"\x3b\x01\x04\x03", b"\x21\x16"),
                ),
                (0x101, ((0, b"\x67\x06\0"),), 22, (b"\x27\x06ABCDEF",)),
                (1, ((7, b"\x7f\x3b\x31"),), 4304, (b"\x3b\x01\0\3\x08\0\0",)),
            ):
                context = Context(payloads)
                context.module_sha256 = module
                self.assertEqual(
                    run_body("Ex2STR_43_ClearAllKey", (b"ABCDEF", mode, 5), context),
                    expected,
                )
                self.assertEqual(
                    tuple(
                        event[1] for event in context.events if event[0] == "exchange"
                    ),
                    requests,
                )
                self.assertEqual(("finalize",) in context.events, expected != 0)
                self.assertFalse(
                    any(event[0] == "initialize" for event in context.events)
                )
            context = Context()
            context.module_sha256 = module
            context.cancelled = True
            self.assertEqual(
                run_body("Ex2STR_43_ClearAllKey", (None, 1, 5), context), 99
            )
            self.assertEqual(context.events[-1], ("finalize",))

    def test_native_minimum_queries_accept_tail_while_commands_remain_exact(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            context = Context([(0, b"\x61\x24\x21\x43\x65\xf7extra")])
            context.module_sha256 = module
            first, second = bytearray(4), bytearray(4)
            self.assertEqual(
                run_body("Ex2STR_22_GetKeyNumber", (first, second), context), 0
            )
            self.assertEqual((first, second), (b"\5\0\0\0", b"\3\0\0\0"))
            context = Context([(0, b"\x7b\x10extra")])
            context.module_sha256 = module
            self.assertEqual(
                run_body("Ex2ECD_09_ChgNormalLearningMode", (1,), context), 3
            )

    def test_switch_key_count_host_exception_cleanup(self):
        for name in ("Ex2STR_20_GetTheKeyNumber", "Ex2STR_22_GetKeyNumber"):
            context = Context([OSError("key count failed")])
            with self.assertRaises(OSError):
                run_body(name, (bytearray(4), bytearray(4)), context)
            self.assertEqual(context.events[-1], ("finalize",))

    @staticmethod
    def str41_snapshot(records):
        data = bytearray(0x1020)
        offsets = [0x1020] * 256
        used = 0
        for selector, payload in records:
            offsets[selector] = used
            record = bytes((selector, len(payload))) + payload
            data[used : used + len(record)] = record
            used += len(record)
        return 0, bytes(data), tuple(offsets)

    def test_str41_support_native_producer_and_end_consumer_all_images(self):
        for module, length, mode, counts in (
            (NK12, "100f5b50", "100f5b4c", "100f5b44"),
            (NK18, "1015eb38", "1015eb34", "1015eb2c"),
            (NK_DS4, "101c5d0c", "101c5d08", "101c5d10"),
            (NK_GTSPLUS, "101dd614", "101dd610", "101dd618"),
        ):
            context = Context(
                [
                    (0, b"\x61\x12\0\x02"),
                    (0, b"\x61\x16\x20"),
                    (0, b"\x61\x14\xa3"),
                    (0, b"\x7b\x01"),
                ]
            )
            context.module_sha256 = module
            context.cancelled = True  # No native cancellation predicate in this body.
            context.snapshots = [
                self.str41_snapshot(
                    (
                        (0x12, b"\x01\x02"),
                        (0x13, b"\x80\x80"),
                        (0x14, b"\xff"),
                        (0x15, b"\xff"),
                        (0x16, b"\x20"),
                    )
                ),
                self.str41_snapshot(((1, b"\x40\0\0\0\0\0"),)),
            ]
            output, size, raw = bytearray(b"old!"), bytearray(b"size"), bytearray(b"?")
            self.assertEqual(
                run_body(
                    "Ex2STR_41_GetRegKeySupportInfo", (output, size, raw), context
                ),
                0x1014,
            )
            self.assertEqual((output, size, raw), (b"\1\0\0\0", b"\6\0\0\0", b"\xa3"))
            self.assertEqual(context.state["native_global:" + length], 6)
            self.assertEqual(context.state["native_global:" + mode], 1)
            self.assertEqual(context.state["native_global:" + counts], 0x30A)
            self.assertNotIn(("finalize",), context.events)
            self.assertEqual(run_body("Ex2STR_41_EndFactoryMode", (0,), context), 0)
            self.assertIn(("exchange", b"\x3b\x01\x08" + bytes(5)), context.events)
            self.assertEqual(context.events[-1], ("finalize",))

    def test_str41_support_fault_branches_and_native_session_retention(self):
        first = self.str41_snapshot(
            (
                (0x12, b"\x01\0"),
                (0x13, b"\x80\x80"),
                (0x14, b"\xff"),
                (0x15, b"\xff"),
                (0x16, b"\x20"),
            )
        )
        for raw, expected in ((0, 0x1008), (0x12, 0x1015)):
            context = Context([(0, bytes((0x61, 0x14, raw)))])
            context.snapshots = [first, self.str41_snapshot(((1, b"\x28"),))]
            outputs = (bytearray(b"old!"), bytearray(b"size"), bytearray(b"?"))
            self.assertEqual(
                run_body("Ex2STR_41_GetRegKeySupportInfo", outputs, context), expected
            )
            self.assertEqual(outputs, (b"old!", b"size", b"?"))
            self.assertEqual(("finalize",) in context.events, raw != 0)
        context = Context()
        self.assertEqual(
            run_body(
                "Ex2STR_41_GetRegKeySupportInfo",
                (bytearray(4), bytearray(4), bytearray(1)),
                context,
            ),
            0x1005,
        )
        self.assertNotIn(("finalize",), context.events)
        context = Context()
        context.snapshots = [first, self.str41_snapshot(((1, b"\x20"),))]
        self.assertEqual(
            run_body(
                "Ex2STR_41_GetRegKeySupportInfo",
                (bytearray(4), bytearray(4), bytearray(1)),
                context,
            ),
            0x1006,
        )
        self.assertNotIn(("finalize",), context.events)
        context = Context([OSError("support query host failure")])
        context.snapshots = [first, self.str41_snapshot(((1, b"\x68"),))]
        with self.assertRaisesRegex(OSError, "host failure"):
            run_body(
                "Ex2STR_41_GetRegKeySupportInfo",
                (bytearray(4), bytearray(4), bytearray(1)),
                context,
            )
        self.assertEqual(context.events[-1], ("finalize",))

    def test_str42_support_produces_source_local_length_for_erasure(self):
        def snapshot(records):
            data = bytearray(0x1020)
            offsets = [0x1020] * 256
            used = 0
            for selector, payload in records:
                offsets[selector] = used
                record = bytes((selector, len(payload))) + payload
                data[used : used + len(record)] = record
                used += len(record)
            return 0, bytes(data), tuple(offsets)

        for module, key in (
            (NK12, "native_global:100f5b54"),
            (NK18, "native_global:1015eb3c"),
            (NK_DS4, "native_global:101c5d18"),
            (NK_GTSPLUS, "native_global:101dd620"),
        ):
            context = Context([(0, b"\x7b\x01")])
            context.module_sha256 = module
            context.snapshots = [
                snapshot(((0x14, b"\xff"), (0x16, b"\x20"))),
                snapshot(((1, b"\x80\0\0"),)),
            ]
            self.assertEqual(run_body("Ex2STR_42_ChkIDSupportInfo", (), context), 0)
            self.assertEqual(context.state[key], 3)
            self.assertEqual(context.events[-1], ("finalize",))
            context.events.clear()
            self.assertEqual(run_body("Ex2STR_42_TransponderIDErasure", (), context), 0)
            self.assertIn(("exchange", b"\x3b\x01\x80\0\0"), context.events)
            self.assertNotIn(("finalize",), context.events)
            context = Context()
            context.module_sha256 = module
            self.assertEqual(run_body("Ex2STR_42_ChkIDSupportInfo", (), context), 700)
            context.snapshots = [
                snapshot(((0x14, b"\xff"), (0x16, b"\x20"))),
                snapshot(((1, b"\0\0"),)),
            ]
            self.assertEqual(run_body("Ex2STR_42_ChkIDSupportInfo", (), context), 701)
            self.assertEqual(context.state[key], 2)

    def test_str42_condition_poll_and_exact_native_faults(self):
        for module in (NK12, NK18, NK_DS4, NK_GTSPLUS):
            context = Context(
                [(0, b"\x61\x16\x20"), (0, b"\x61\x16\0"), (0, b"\x61\x14\x10")]
            )
            context.module_sha256, context.cancelled = module, True
            self.assertEqual(run_body("Ex2STR_42_ChkModeCondition", (), context), 0)
            self.assertFalse(any(e[0] == "initialize" for e in context.events))
            self.assertEqual(context.events[-1], ("finalize",))
            self.assertEqual(context.events.count(("native_sleep", 100)), 3)
        for status, reply, expected in (
            (2, b"", 702),
            (7, b"", 703),
            (0, b"\x61\x16", 703),
        ):
            self.assertEqual(
                run_body("Ex2STR_42_ChkModeCondition", (), Context([(status, reply)])),
                expected,
            )
        context = Context([(0, b"\x61\x16\0"), (0, b"\x61\x14\x11")])
        self.assertEqual(run_body("Ex2STR_42_ChkModeCondition", (), context), 704)

    def test_str41_end_factory_mode_preserves_full_word_selector_and_native_length(
        self,
    ):
        for module, field in (
            (NK12, "native_global:100f5b50"),
            (NK18, "native_global:1015eb38"),
            (NK_DS4, "native_global:101c5d0c"),
            (NK_GTSPLUS, "native_global:101dd614"),
        ):
            for mode, length, request in (
                (0, 0, b"\x3b\x01\x08"),
                (1, 0, b"\x3b\x01\x08\0\0"),
                (0x101, 0, b"\x3b\x01\x08"),
                (0, 4, b"\x3b\x01\x08\0\0\0"),
            ):
                context = Context([(0, b"\x7b\x01")])
                context.module_sha256 = module
                context.state[field] = length
                self.assertEqual(
                    run_body("Ex2STR_41_EndFactoryMode", (mode,), context), 0
                )
                self.assertIn(("exchange", request), context.events)
                self.assertFalse(any(e[0] == "initialize" for e in context.events))
                self.assertEqual(context.events[-1], ("finalize",))
        for status, reply, expected in (
            (7, b"\x7f\x3b\x22", 26),
            (7, b"\x7f\x3b\x31", 7),
            (0, b"\x7b\x01\0", 3),
            (0, b"\x7b\x02", 3),
        ):
            context = Context([(status, reply)])
            self.assertEqual(
                run_body("Ex2STR_41_EndFactoryMode", (0,), context), expected
            )

    def test_argument_boundaries(self):
        for arguments in [(), (True,), (-1,), (0x100000000,), (1, 2)]:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                run_body("Ex2ECD_12_InitAFSensorLearn", arguments, Context())
        for output in [b"\0", bytearray(), bytearray(2), 1]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                run_body("Ex2ECD_12_GetSupportInfo", (output,), Context())


if __name__ == "__main__":
    unittest.main()
