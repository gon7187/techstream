"""Authored controller traces; no vehicle, proprietary fixture, or OEM execution."""

from __future__ import annotations

import hashlib
import importlib
import unittest
from dataclasses import replace
from unittest.mock import patch

from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import (
    EXPORTS_18_TY,
    EXTRA_EXPORTS_18_TY,
    EXTRA_EXPORTS_PLUS_TY,
    SHA_12_TY,
    SHA_18_TY,
    SHA_PLUS_TY,
    TYEngine,
    TYMessage,
    TYSourceError,
    elapsed_ticks,
    load_contract,
    run_body,
    supported_exports,
)

# Independently authored protocol shapes distinguish sessions and routines.
SYNTHETIC = replace(
    load_contract(SHA_18_TY),
    source_sha256=hashlib.sha256(b"authored TY module").hexdigest(),
    comm_kind="synthetic",
    frames={
        **load_contract(SHA_18_TY).frames,
        "session_normal": b"\x90\x01",
        "session_extended": b"\x90\x02",
        "door_clear": b"\x80\x01\x02\x03\x04",
        "fchv_enable": b"\x80\x01\x03\x01\x08",
        "fchv_drive": b"\x80\x01\x03\x02\x09",
        "fchv_stop_drive": b"\x80\x02\x03\x02",
        "fchv_start_read": b"\x80\x01\x03\x03",
        "fchv_stop_read": b"\x80\x02\x03\x03",
        "fchv_read": b"\x70\x02\x03",
    },
)


class Comm:
    def __init__(self, replies: list[tuple[int, bytes]]) -> None:
        self.replies = replies[:]
        self.events: list[object] = []
        self.initial_status = 0
        self.native_error = 0

    def initialize(self, mode: int = 0) -> int:
        self.events.append(("init", mode))
        return self.initial_status

    def finalize(self) -> None:
        self.events.append("finalize")

    def configure(self, field: str, value: int) -> None:
        self.events.append((field, value))

    def cleanup_exchange(self, request: bytes) -> tuple[int, bytes]:
        raise AssertionError("unexpected host cleanup exchange")

    def cleanup_session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int:
        raise AssertionError("unexpected host cleanup session")

    def configure_target(
        self,
        first: int,
        second: int = 0,
        third: int = 0,
        fourth: int = 0,
        fifth: int = 0,
    ) -> None:
        raise AssertionError("unexpected native target configuration")

    def select_protocol(self, kind: int) -> int:
        raise AssertionError("unexpected native protocol selection")

    def read_target(self) -> tuple[int, int]:
        raise AssertionError("unexpected native target read")

    def read_dtcs(self, mode: int = 0x80, capacity: int = 0x1000) -> tuple[int, bytes]:
        raise AssertionError("unexpected native DTC read")

    def select_target(self, identifier: int, second: int = 0) -> None:
        raise AssertionError("unexpected native target selection")

    def read_field(self, field: str) -> int:
        self.events.append(("read_field", field))
        if field != "native_10b0":
            raise AssertionError("unexpected native field read")
        return self.native_error

    def support_snapshot(self, kind: int) -> tuple[int, bytes, tuple[int, ...]]:
        raise AssertionError("unexpected support snapshot")

    def session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int:
        if normal_first:
            status = self.session(1)
            if status:
                return status
        status, reply = self.exchange(bytes((0x90, mode)))
        if not status and len(reply) < 2:
            return 3
        if not status and reply[1] != mode:
            return 7
        return status

    def exchange(self, request: bytes) -> tuple[int, bytes]:
        self.events.append(request)
        if not self.replies:
            raise AssertionError("unexpected native exchange")
        return self.replies.pop(0)


class Context:
    def __init__(self, replies: list[tuple[int, bytes]] | None = None) -> None:
        self.state: dict[str, object] = {}
        self.mode = 20
        self.module_bytes = b"authored TY module"
        self.module_sha256 = SYNTHETIC.source_sha256
        self.controller = Comm(replies or [])
        self.events: list[object] = []
        self.cancelled = False
        self.cancel_on_sleep = False
        self.clock = 0
        self.set_status = 1
        self.write_status = 1

    def comm(self, kind: str) -> Comm:
        self.events.append(("comm", kind))
        return self.controller

    def is_cancelled(self) -> bool:
        return self.cancelled

    def sleep(self, ms: int) -> None:
        self.events.append(("sleep", ms))
        self.clock += ms
        if self.cancel_on_sleep:
            self.cancelled = True

    def ticks(self) -> int:
        return self.clock & 0xFFFFFFFF

    def native_sleep(self, milliseconds: int) -> None:
        self.events.append(("native_sleep", milliseconds))
        self.clock += milliseconds

    def set_parameter(self, key: int, value: int) -> int:
        self.events.append(("set", key, value))
        return self.set_status

    def write_parameters(self) -> int:
        self.events.append("write")
        return self.write_status

    def refresh_parameters(self) -> None:
        self.events.append("refresh")


class TYTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = TYEngine(SYNTHETIC)

    def call(self, name: str, context: Context, *args: object) -> int:
        return self.engine.run_body(name, args, context)

    def test_door_exact_chronology(self) -> None:
        context = Context(
            [(0, b"x\x01"), (0, b"x\x02"), (0, b"x\x01\x02\x03"), (19, b"")]
        )
        self.assertEqual(self.call(EXPORTS_18_TY[0], context), 0)
        self.assertEqual(
            context.controller.events,
            [
                ("init", 0),
                ("native_1080", 0),
                ("native_1084", 180000),
                ("native_1064", 0),
                b"\x90\x01",
                b"\x90\x02",
                b"\x80\x01\x02\x03\x04",
                b"\x90\x01",
                "finalize",
            ],
        )
        self.assertEqual(context.events[1:], [("sleep", 200), ("sleep", 100)])

    def test_door_fault_still_restores_and_closes(self) -> None:
        for reply in ((17, b""), (0, b"x\x01\x02"), (0, b"x\x01\xff\x03")):
            with self.subTest(reply=reply):
                context = Context([(0, b"x\x01"), (0, b"x\x02"), reply, (0, b"x\x01")])
                self.assertEqual(self.call(EXPORTS_18_TY[0], context), 1000)
                self.assertEqual(
                    context.controller.events[-2:], [b"\x90\x01", "finalize"]
                )

    def test_door_initialize_fault_and_session_echo(self) -> None:
        context = Context()
        context.controller.initial_status = 23
        self.assertEqual(self.call(EXPORTS_18_TY[0], context), 23)
        self.assertEqual(context.controller.events, [("init", 0), "finalize"])
        context = Context([(0, b"x\xff")])
        self.assertEqual(self.call(EXPORTS_18_TY[0], context), 7)
        self.assertEqual(context.controller.events[-1], "finalize")

    def test_cancel_between_session_and_wire_closes(self) -> None:
        context = Context([(0, b"x\x01"), (0, b"x\x02")])
        context.cancel_on_sleep = True
        with self.assertRaises(Cancelled):
            self.call(EXPORTS_18_TY[0], context)
        self.assertEqual(context.controller.events[-1], "finalize")
        self.assertNotIn(b"\x80\x01\x02\x03\x04", context.controller.events)

    def test_broker_failures_preserve_chronology(self) -> None:
        for set_status, write_status, expected in (
            (0, 1, ["set"]),
            (1, 0, ["set", "write"]),
            (1, 1, ["set", "write", "refresh"]),
        ):
            with self.subTest(set_status=set_status, write_status=write_status):
                context = Context()
                context.set_status, context.write_status = set_status, write_status
                self.assertEqual(
                    self.call(EXPORTS_18_TY[1], context, 7),
                    0 if len(expected) == 3 else 2001,
                )
                self.assertEqual(
                    [e[0] if isinstance(e, tuple) else e for e in context.events],
                    expected,
                )

    def test_native_wrap_and_send_threshold(self) -> None:
        self.assertEqual(elapsed_ticks(3, 0xFFFFFFFE), 4)
        self.assertEqual(elapsed_ticks(100, 80), 20)
        context = Context()
        context.clock = 3
        self.assertEqual(self.call(EXPORTS_18_TY[2], context, 0xFFFFFFFE, 4), 1)
        self.assertEqual(self.call(EXPORTS_18_TY[2], context, 0xFFFFFFFE, 5), 0)
        with self.assertRaises(ValueError):
            elapsed_ticks(-1, 0)

    def test_fchv_enable_leaves_initialized_controller(self) -> None:
        context = Context([(0, b"x\x01"), (0, b"x\x02"), (0, b"x\x01\x03\x01")])
        self.assertEqual(self.call(EXPORTS_18_TY[3], context, TYMessage(0)), 0)
        self.assertNotIn("finalize", context.controller.events)
        self.assertEqual(
            context.controller.events[-3:],
            [b"\x90\x01", b"\x90\x02", b"\x80\x01\x03\x01\x08"],
        )

    def test_fchv_enable_fault_restores_session_then_closes(self) -> None:
        context = Context([(0, b"x\x01"), (0, b"x\x02"), (8, b""), (0, b"x\x01")])
        self.assertEqual(self.call(EXPORTS_18_TY[3], context, TYMessage(0)), 2000)
        self.assertEqual(context.controller.events[-2:], [b"\x90\x01", "finalize"])

    def test_fchv_drive_fault_attempts_stop(self) -> None:
        context = Context([(8, b""), (9, b"")])
        self.assertEqual(self.call(EXPORTS_18_TY[3], context, TYMessage(1)), 2001)
        self.assertEqual(
            context.controller.events, [b"\x80\x01\x03\x02\x09", b"\x80\x02\x03\x02"]
        )
        self.assertFalse(context.events[1:])

    def test_fchv_stop_discards_native_status(self) -> None:
        context = Context([(99, b"")])
        self.assertEqual(self.call(EXPORTS_18_TY[3], context, TYMessage(2)), 0)
        self.assertNotIn("finalize", context.controller.events)

    def test_fchv_read_poll_ready_maps_selection_and_stops(self) -> None:
        for selection, expected in (
            (1, 2020),
            (2, 2030),
            (3, 2031),
            (5, 2032),
            (99, 2004),
        ):
            with self.subTest(selection=selection):
                replies = [
                    (0, b"x\x01\x03\x03"),
                    (0, b"x\x02\x03\0\0"),
                    (0, b"x\x02\x03\0\x40"),
                    (7, b""),
                ]
                if selection in (5, 99):
                    replies.append((0, b"x\x01"))
                context = Context(replies)
                self.assertEqual(
                    self.call(EXPORTS_18_TY[3], context, TYMessage(3, selection)),
                    expected,
                )
                self.assertIn(b"\x80\x02\x03\x03", context.controller.events)
                self.assertEqual(
                    "finalize" in context.controller.events, selection in (5, 99)
                )

    def test_fchv_selection_four_runs_drive_after_ready(self) -> None:
        context = Context(
            [
                (0, b"x\x01\x03\x03"),
                (0, b"x\x02\x03\0\x40"),
                (0, b"x\x02\x03\x03"),
                (0, b"x\x01\x03\x02"),
            ]
        )
        self.assertEqual(self.call(EXPORTS_18_TY[3], context, TYMessage(3, 4)), 2030)
        self.assertEqual(context.controller.events[-1], b"\x80\x01\x03\x02\x09")

    def test_fchv_short_read_maps_fault_and_stop_is_not_retried(self) -> None:
        context = Context(
            [(0, b"x\x01\x03\x03"), (0, b"x\x02\x03"), (0, b"x\x02\x03\x03")]
        )
        self.assertEqual(self.call(EXPORTS_18_TY[3], context, TYMessage(3, 1)), 2002)
        self.assertEqual(len(context.controller.replies), 0)

    def test_fchv_timeout_is_from_first_successful_read(self) -> None:
        contract = replace(
            SYNTHETIC, numbers={**SYNTHETIC.numbers, "fchv_timeout_ms": 400}
        )
        context = Context(
            [(0, b"x\x01\x03\x03"), *[(0, b"x\x02\x03\0\0")] * 3, (0, b"x\x02\x03\x03")]
        )
        self.assertEqual(
            TYEngine(contract).run_body(EXPORTS_18_TY[3], (TYMessage(3, 2),), context),
            2001,
        )
        self.assertEqual(context.clock, 600)

    def test_exact_source_and_unknown_exports_fail_before_io(self) -> None:
        context = Context()
        context.module_sha256 = "f" * 64
        with self.assertRaises(TYSourceError):
            self.call(EXPORTS_18_TY[0], context)
        with self.assertRaises(TYSourceError):
            load_contract(context.module_sha256)
        with self.assertRaises(TYSourceError):
            run_body(EXPORTS_18_TY[0], (), context)
        context = Context()
        with self.assertRaises(TYSourceError):
            self.call("Ex2FCHV_17_SendMessage", context, TYMessage(0))
        self.assertEqual(context.events, [])

    def test_exact_variant_manager_contracts(self) -> None:
        self.assertEqual(load_contract(SHA_18_TY).comm_kind, "native:1011d4f0")
        self.assertEqual(load_contract(SHA_PLUS_TY).comm_kind, "native:101392d0")
        self.assertEqual(
            load_contract(SHA_PLUS_TY).exports,
            EXPORTS_18_TY
            + EXTRA_EXPORTS_PLUS_TY
            + (
                "Ex2FCHV_05_SendMessage",
                "Ex2FCHV_06_SendMessage",
                "Ex2FCHV_07_SupportCheck",
                "Ex2FCHV_08_SupportCheck",
                "Ex2FCHV_09_SendMessage",
                "Ex2FCHV_07_Overwrite",
                "Ex2FCHV_02_ReadData",
                "Ex2HF_01_Com_TanksNumberValueClear",
                "Ex2ROOF_01_ImpactDetectionInfoClear",
                "Ex2IG_02_SendMessage",
                "Ex2IG_01_DisableAutoPowerOffFunc",
                "Ex2MIR_01_SendMessage",
                "Ex2SAS_02_SendMessage",
                "Ex2MS2MM_01_SendMessage",
                "Ex2MS2BSRL_01_SendMessage",
                "Ex2MSW_01_SendMessage",
                "Ex2DMOT_01_SendMessage",
                "Ex2EV_02_SendMessage",
            ),
        )
        self.assertNotEqual(load_contract(SHA_PLUS_TY).source_sha256, SHA_18_TY)

    def test_matching_claim_with_modified_module_bytes_fails(self) -> None:
        context = Context()
        context.module_bytes += b"tamper"
        with self.assertRaises(TYSourceError):
            self.call(EXPORTS_18_TY[0], context)
        self.assertEqual(context.events, [])

    def test_fchv_default_action_restores_session_and_closes(self) -> None:
        context = Context([(17, b"")])
        self.assertEqual(self.call(EXPORTS_18_TY[3], context, TYMessage(99)), 0)
        self.assertEqual(context.controller.events, [b"\x90\x01", "finalize"])

    def test_fchv_cancel_during_poll_closes_controller(self) -> None:
        context = Context([(0, b"x\x01\x03\x03")])
        context.cancel_on_sleep = True
        with self.assertRaises(Cancelled):
            self.call(EXPORTS_18_TY[3], context, TYMessage(3, 1))
        self.assertEqual(context.controller.events[-1], "finalize")

    def test_registry_dispatch_preserves_output_reference(self) -> None:
        context = Context()
        output = bytearray(4)

        def mutate(export, args, selected):
            self.assertIs(selected, context)
            self.assertIs(args[0], output)
            output[0] = 71
            return 23

        with (
            patch(
                "scripts.utility_ex_ty_powertrain.supported_exports",
                return_value=("authored.operation",),
            ),
            patch(
                "scripts.utility_ex_ty_powertrain.run_body", side_effect=mutate
            ) as body,
        ):
            self.assertIn(
                "authored.operation", supported_exports(context.module_sha256)
            )
            self.assertEqual(run_body("authored.operation", (output,), context), 23)
            self.assertEqual(output[0], 71)
            body.assert_called_once()
            context.module_bytes += b"changed"
            with self.assertRaises(TYSourceError):
                run_body("authored.operation", (output,), context)
            body.assert_called_once()

    def test_fchv_provider_join_preserves_native_mutable_arguments(self) -> None:
        context = Context()
        output = bytearray(4)

        def operation(export, args, selected):
            self.assertIs(selected, context)
            self.assertIs(args[0], output)
            output[:] = b"ABCD"
            return 27

        with (
            patch(
                "scripts.utility_ex_fchv.supported_exports",
                return_value=("authored.fchv",),
            ),
            patch("scripts.utility_ex_fchv.run_body", side_effect=operation),
        ):
            self.assertIn("authored.fchv", supported_exports(context.module_sha256))
            self.assertEqual(run_body("authored.fchv", (output,), context), 27)
            self.assertEqual(output, bytearray(b"ABCD"))

    def test_fchv01_provider_join_preserves_native_buffer(self) -> None:
        context = Context()
        output = bytearray(28)

        def operation(export, args, selected):
            self.assertIs(selected, context)
            self.assertIs(args[0], output)
            output[-1] = 91
            return 27

        with (
            patch(
                "scripts.utility_ex_fchv_01.supported_exports",
                return_value=("authored.fchv01",),
            ),
            patch("scripts.utility_ex_fchv_01.run_body", side_effect=operation),
        ):
            self.assertIn("authored.fchv01", supported_exports(context.module_sha256))
            self.assertEqual(run_body("authored.fchv01", (output,), context), 27)
            self.assertEqual(output[-1], 91)

    def test_fchv_actions_provider_join_preserves_native_buffer(self) -> None:
        context = Context()
        output = bytearray(28)

        def operation(export, args, selected):
            self.assertIs(selected, context)
            self.assertIs(args[0], output)
            output[-1] = 91
            return 27

        with (
            patch(
                "scripts.utility_ex_fchv_actions.supported_exports",
                return_value=("authored.fchvactions",),
            ),
            patch("scripts.utility_ex_fchv_actions.run_body", side_effect=operation),
        ):
            self.assertIn(
                "authored.fchvactions", supported_exports(context.module_sha256)
            )
            self.assertEqual(run_body("authored.fchvactions", (output,), context), 27)
            self.assertEqual(output[-1], 91)

    def test_candidate_provider_joins(self) -> None:
        for module in (
            "utility_ex_ms2",
            "utility_ex_fchv_plus",
            "utility_ex_ty_retained_01",
            "utility_ex_ty_retained_02",
            "utility_ex_ty_retained_03",
            "utility_ex_ty_retained_04",
            "utility_ex_ty_retained_05",
            "utility_ex_ty_retained_06",
            "utility_ex_ty_retained_07",
            "utility_ex_ty_retained_08",
            "utility_ex_ty_retained_09",
            "utility_ex_ty_retained_10",
            "utility_ex_ty_retained_11",
            "utility_ex_ty_retained_12",
        ):
            context = Context()
            output = bytearray(28)
            export = "authored." + module

            def operation(
                name,
                args,
                selected,
                expected_export=export,
                expected_context=context,
                expected_output=output,
            ):
                self.assertEqual(name, expected_export)
                self.assertIs(selected, expected_context)
                self.assertIs(args[0], expected_output)
                expected_output[-1] = 91
                return 27

            with (
                patch(f"scripts.{module}.supported_exports", return_value=(export,)),
                patch(f"scripts.{module}.run_body", side_effect=operation),
            ):
                self.assertIn(export, supported_exports(context.module_sha256))
                self.assertEqual(run_body(export, (output,), context), 27)
                self.assertEqual(output[-1], 91)

    def test_ready_retained_pairs_do_not_shadow_core_or_each_other(self) -> None:
        for sha in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY):
            covered = set(load_contract(sha).exports)
            for number in range(1, 13):
                provider = importlib.import_module(
                    f"scripts.utility_ex_ty_retained_{number:02}"
                )
                names = provider.supported_exports(sha)
                self.assertFalse(covered.intersection(names), (sha, number))
                self.assertEqual(len(names), len(set(names)))
                covered.update(names)

    def test_fchv16_native_buffer_consumes_two_dwords(self) -> None:
        data = bytearray((2).to_bytes(4, "little") + (9).to_bytes(4, "little"))
        original = bytes(data)
        context = Context([(23, b"")])
        self.assertEqual(self.call(EXPORTS_18_TY[3], context, data), 0)
        self.assertEqual(bytes(data), original)

    def test_fchv10_support_sets_only_matching_output_dwords(self) -> None:
        data = bytearray(508)
        for offset in range(0, 504, 24):
            data[offset + 8] = 0x80
            data[offset + 12 : offset + 16] = (9).to_bytes(4, "little")
        data[8] = 0x20
        context = Context(
            [
                (0, b"x\x01"),
                (0, b"x\x02"),
                (0, bytes.fromhex("621bbc200000000000")),
                (19, b""),
            ]
        )
        self.assertEqual(self.call(EXTRA_EXPORTS_18_TY[0], context, data), 19)
        self.assertEqual(int.from_bytes(data[12:16], "little"), 1)
        self.assertEqual(int.from_bytes(data[36:40], "little"), 9)
        self.assertEqual(context.controller.events[-2:], [b"\x90\x01", "finalize"])

    def test_fchv10_write_uses_selected_entries_in_order_and_stops_on_fault(
        self,
    ) -> None:
        data = bytearray(508)
        data[504:508] = (1).to_bytes(4, "little")
        for offset, value in ((0, 17), (24, 18), (48, 19)):
            data[offset] = value
            data[offset + 16 : offset + 20] = (1).to_bytes(4, "little")
        context = Context(
            [
                (0, b"x\x01"),
                (0, b"x\x02"),
                (0, bytes.fromhex("71011185")),
                (27, b""),
                (0, b"x\x01"),
            ]
        )
        self.assertEqual(self.call(EXTRA_EXPORTS_18_TY[0], context, data), 27)
        requests = [e for e in context.controller.events if isinstance(e, bytes)]
        self.assertIn(bytes.fromhex("3101118511"), requests)
        self.assertIn(bytes.fromhex("3101118512"), requests)
        self.assertNotIn(bytes.fromhex("3101118513"), requests)

    def test_fchv10_invalid_support_index_rejected_before_init(self) -> None:
        data = bytearray(508)
        data[4:8] = (0x1020).to_bytes(4, "little")
        context = Context()
        with self.assertRaises(ValueError):
            self.call(EXTRA_EXPORTS_18_TY[0], context, data)
        self.assertEqual(context.events, [])

    def test_fchv13_cleanup_wire_exception_finalizes_exactly_once(self) -> None:
        context = Context()
        data = bytearray((2).to_bytes(4, "little"))
        with self.assertRaises(AssertionError):
            self.call("Ex2FCHV_13_SendMessage", context, data)
        self.assertEqual(context.controller.events.count("finalize"), 1)

    def test_fchv13_start_uses_three_distinct_native_payloads(self) -> None:
        context = Context(
            [
                (0, b"x\x01"),
                (0, b"x\x02"),
                (0, bytes.fromhex("6f281c03")),
                (0, bytes.fromhex("6f280e03")),
                (0, bytes.fromhex("6f280903")),
            ]
        )
        self.assertEqual(self.call(EXTRA_EXPORTS_18_TY[1], context, bytearray(4)), 0)
        self.assertEqual(
            context.controller.events[-3:],
            [
                bytes.fromhex("2f281c0300010001"),
                bytes.fromhex("2f280e030fa080"),
                bytes.fromhex("2f2809033280"),
            ],
        )
        self.assertNotIn("finalize", context.controller.events)

    def test_fchv13_start_fault_restores_all_three_outputs(self) -> None:
        context = Context(
            [
                (0, b"x\x01"),
                (0, b"x\x02"),
                (17, b""),
                (9, b""),
                (9, b""),
                (9, b""),
                (19, b""),
            ]
        )
        self.assertEqual(self.call(EXTRA_EXPORTS_18_TY[1], context, bytearray(4)), 1008)
        self.assertEqual(
            context.controller.events[-5:],
            [
                bytes.fromhex("2f281c000001"),
                bytes.fromhex("2f280e0080"),
                bytes.fromhex("2f28090080"),
                b"\x90\x01",
                "finalize",
            ],
        )

    def test_fchv14_maps_routine_fault_but_ignores_restore_status(self) -> None:
        for routine, expected in (
            ((0, bytes.fromhex("71011188")), 0),
            ((17, b""), 1005),
        ):
            context = Context([(0, b"x\x01"), (0, b"x\x02"), routine, (19, b"")])
            self.assertEqual(self.call(EXTRA_EXPORTS_18_TY[2], context), expected)
            self.assertEqual(
                context.controller.events[-3:],
                [bytes.fromhex("3101118801"), b"\x90\x01", "finalize"],
            )

    def test_already_cancelled_end_still_releases_retained_controller(self) -> None:
        context = Context()
        context.cancelled = True
        with self.assertRaises(Cancelled):
            self.call("Ex2FCHV_02_EndExtendedSession", context, bytearray())
        self.assertEqual(context.controller.events, ["finalize"])

    def test_actual_same_rva_end_aliases_restore_then_close(self) -> None:
        for export in EXTRA_EXPORTS_18_TY[3:]:
            context = Context([(17, b"")])
            self.assertEqual(self.call(export, context, bytearray()), 1003)
            self.assertEqual(context.controller.events, [b"\x90\x01", "finalize"])

    def test_ms2bsrl_output_status_mapping_and_three_second_boundary(self) -> None:
        for result, expected in ((0, 0), (9, 2002), (12, 2000), (13, 2001), (1, 99)):
            data = bytearray(b"xxx")
            context = Context(
                [
                    (0, bytes.fromhex("71010141")),
                    (0, bytes.fromhex("71030141") + bytes((result,)) + b"ABCxx"),
                ]
            )
            self.assertEqual(
                self.call("Ex2MS2BSRL_01_SendMessage", context, data), expected
            )
            self.assertEqual(data, bytearray(b"ABC" if result == 0 else bytes(3)))
            self.assertIn(("sleep", 3000), context.events)
            self.assertEqual(context.controller.events[-1], "finalize")

    def test_ms2bsrl_fault_and_source_global_publication(self) -> None:
        for status, native, expected in (
            (2, 0, 2004),
            (7, 0x69, 2005),
            (7, 0x31, 2003),
            (27, 0, 2003),
        ):
            context = Context([(status, bytes.fromhex("7f3169"))])
            context.controller.native_error = native
            data = bytearray(b"xxx")
            self.assertEqual(
                self.call("Ex2MS2BSRL_01_SendMessage", context, data), expected
            )
            self.assertNotIn(("sleep", 3000), context.events)
            self.assertEqual(context.events.count(("sleep", 0)), int(status in (2, 7)))
            self.assertEqual(
                context.state, {"native_global:1012ae38": 0x69} if status == 7 else {}
            )

    def test_plus_ms2bsrl_identifier_reverses_two_native_results(self) -> None:
        for result in (12, 13):
            for identifier in (0, 0x2DA):
                context = Context(
                    [
                        (0, bytes.fromhex("71010141")),
                        (0, bytes.fromhex("71030141") + bytes((result,)) + b"ABCxx"),
                    ]
                )
                data = bytearray(b"xxxZ" + identifier.to_bytes(4, "little"))
                expected = 2000 + ((result == 13) != (identifier == 0x2DA))
                with patch(
                    "scripts.utility_ex_ty.SHA_PLUS_TY", SYNTHETIC.source_sha256
                ):
                    self.assertEqual(
                        self.call("Ex2MS2BSRL_01_SendMessage", context, data), expected
                    )
                self.assertEqual(
                    data[3:], bytearray(b"Z" + identifier.to_bytes(4, "little"))
                )
        context = Context([(7, b"x")])
        with patch("scripts.utility_ex_ty.SHA_PLUS_TY", SYNTHETIC.source_sha256):
            self.assertEqual(
                self.call("Ex2MS2BSRL_01_SendMessage", context, bytearray(8)), 2003
            )
        self.assertEqual(context.state, {"native_global:10153554": 0})

    def test_selected_fixed_native_commands_keep_exact_response_predicates(
        self,
    ) -> None:
        for export, request, accepted in (
            ("Ex2MSW_01_SendMessage", b"\xa6\x00", b"x"),
            ("Ex2DMOT_01_SendMessage", b"\xa6\x00", b"x"),
            ("Ex2EV_02_SendMessage", b"\x3b\x22\x01", b"\x7b\x22"),
        ):
            for reply, expected in (
                ((0, accepted), 0),
                ((0, accepted + b"x"), 3),
                ((0, b""), 3),
                ((27, b""), 27),
            ):
                context = Context([reply])
                self.assertEqual(self.call(export, context), expected)
                self.assertIn(("comm", "selected"), context.events)
                self.assertEqual(
                    context.controller.events,
                    [("init", 0), ("native_rva:12180", 150), request, "finalize"],
                )
        context = Context([(0, b"\x7b\x23")])
        self.assertEqual(self.call("Ex2EV_02_SendMessage", context), 3)

    def test_ms2mm_exact_four_byte_response_without_session(self) -> None:
        for reply, expected in (
            ((0, bytes.fromhex("71010050")), 0),
            ((0, bytes.fromhex("7101005000")), 3),
            ((0, bytes.fromhex("71010051")), 3),
            ((27, b""), 27),
        ):
            context = Context([reply])
            self.assertEqual(self.call("Ex2MS2MM_01_SendMessage", context), expected)
            self.assertEqual(
                [e for e in context.controller.events if isinstance(e, bytes)],
                [bytes.fromhex("31010050")],
            )
            self.assertEqual(context.controller.events[-1], "finalize")

    def test_sas02_always_restores_and_finalizes_without_settle(self) -> None:
        for result, expected in (
            ((0, bytes.fromhex("71011101")), 0),
            ((0, bytes.fromhex("710111")), 3),
            ((27, b""), 27),
        ):
            context = Context([(0, b"x\x01"), (0, b"x\x02"), result, (19, b"")])
            self.assertEqual(self.call("Ex2SAS_02_SendMessage", context), expected)
            self.assertIn(bytes.fromhex("31011101"), context.controller.events)
            self.assertEqual(context.controller.events[-2:], [b"\x90\x01", "finalize"])
            self.assertFalse(
                any(
                    isinstance(event, tuple) and event[0] == "sleep"
                    for event in context.events
                )
            )

    def test_mir_start_retains_session_but_fault_restores(self) -> None:
        for result, expected in (((0, bytes.fromhex("71011101")), 0), ((27, b""), 27)):
            replies = [(0, b"x\x01"), (0, b"x\x02"), result]
            if expected:
                replies.append((19, b""))
            context = Context(replies)
            self.assertEqual(
                self.call("Ex2MIR_01_SendMessage", context, bytearray(4)), expected
            )
            self.assertEqual("finalize" in context.controller.events, bool(expected))

    def test_mir_polls_pending_then_maps_completion(self) -> None:
        for result, expected in (
            ((0, bytes.fromhex("7103110102")), 0),
            ((0, bytes.fromhex("7103110100")), 1007),
            ((0, bytes.fromhex("71031101")), 3),
            ((27, b""), 27),
        ):
            context = Context([(0, bytes.fromhex("7103110101")), result, (19, b"")])
            data = bytearray((1).to_bytes(4, "little") + bytes(4))
            self.assertEqual(
                self.call("Ex2MIR_01_SendMessage", context, data), expected
            )
            self.assertEqual(context.events.count(("sleep", 10)), 2)
            self.assertEqual(context.controller.events[-1], "finalize")

    def test_mir_start_and_poll_use_one_retained_controller(self) -> None:
        context = Context(
            [
                (0, b"x\x01"),
                (0, b"x\x02"),
                (0, bytes.fromhex("71011101")),
                (0, bytes.fromhex("7103110102")),
                (19, b""),
            ]
        )
        data = bytearray(8)
        self.assertEqual(self.call("Ex2MIR_01_SendMessage", context, data), 0)
        self.assertNotIn("finalize", context.controller.events)
        data[:4] = (1).to_bytes(4, "little")
        self.assertEqual(self.call("Ex2MIR_01_SendMessage", context, data), 0)
        self.assertEqual(context.controller.events.count(("init", 0)), 1)
        self.assertEqual(context.controller.events.count("finalize"), 1)

    def test_mir_native_cancel_and_host_exception_close(self) -> None:
        data = bytearray((1).to_bytes(4, "little") * 2)
        context = Context([(19, b"")])
        self.assertEqual(self.call("Ex2MIR_01_SendMessage", context, data), 0)
        self.assertNotIn(("sleep", 10), context.events)
        self.assertEqual(context.controller.events[-1], "finalize")
        data[4:8] = bytes(4)
        context = Context()
        with self.assertRaises(AssertionError):
            self.call("Ex2MIR_01_SendMessage", context, data)
        self.assertEqual(context.controller.events[-1], "finalize")

    def test_plus_gwy02_timeout_mode22_restores_classic_object(self) -> None:
        context = Context([(27, b"")])
        context.mode = 22
        with patch("scripts.utility_ex_ty.SHA_PLUS_TY", SYNTHETIC.source_sha256):
            self.assertEqual(
                self.call("Ex2GWY_02_TimeoutInit", context, bytearray()), 1003
            )
        self.assertEqual(context.events, [("comm", "native:1013e7d0")])
        self.assertEqual(context.controller.events, [b"\x90\x01", "finalize"])

    def test_ig01_selected_protocol_length_and_cleanup(self) -> None:
        for reply, expected in (
            ((0, b"x"), 0),
            ((0, b""), 3),
            ((0, b"xx"), 3),
            ((27, b""), 27),
        ):
            context = Context([reply])
            self.assertEqual(
                self.call("Ex2IG_01_DisableAutoPowerOffFunc", context), expected
            )
            self.assertIn(("comm", "selected"), context.events)
            self.assertEqual(
                context.controller.events,
                [("init", 0), ("native_rva:12180", 150), b"\x10\x70", "finalize"],
            )
        self.assertEqual(
            load_contract(SHA_12_TY).exports,
            (
                "Ex2IG_01_DisableAutoPowerOffFunc",
                "Ex2MSW_01_SendMessage",
                "Ex2DMOT_01_SendMessage",
                "Ex2EV_02_SendMessage",
            ),
        )

    def test_ig01_source_selected_setter_and_init_fault(self) -> None:
        context = Context([(0, b"x")])
        with patch("scripts.utility_ex_ty.SHA_PLUS_TY", SYNTHETIC.source_sha256):
            self.assertEqual(self.call("Ex2IG_01_DisableAutoPowerOffFunc", context), 0)
        self.assertIn(("native_rva:142f0", 150), context.controller.events)
        context = Context()
        context.controller.initial_status = 27
        self.assertEqual(self.call("Ex2IG_01_DisableAutoPowerOffFunc", context), 27)
        self.assertEqual(context.controller.events, [("init", 0), "finalize"])

    def test_ig02_already_enabled_skips_write_and_wait(self) -> None:
        context = Context(
            [(0, b"x\x01"), (0, b"x\x02"), (0, bytes.fromhex("6220010040")), (19, b"")]
        )
        self.assertEqual(self.call("Ex2IG_02_SendMessage", context), 0)
        self.assertNotIn(("sleep", 500), context.events)
        self.assertEqual(
            [e.hex() for e in context.controller.events if isinstance(e, bytes)],
            ["9001", "9002", "222001", "9001"],
        )

    def test_ig02_preserves_payload_sets_flag_and_rechecks(self) -> None:
        for final, expected in (
            ((0, bytes.fromhex("6220010142")), 0),
            ((0, bytes.fromhex("6220010102")), 1000),
            ((27, b""), 27),
            ((0, b"x"), 3),
        ):
            context = Context(
                [
                    (0, b"x\x01"),
                    (0, b"x\x02"),
                    (0, bytes.fromhex("62200101020304")),
                    (0, bytes.fromhex("6e2001")),
                    final,
                    (19, b""),
                ]
            )
            self.assertEqual(self.call("Ex2IG_02_SendMessage", context), expected)
            self.assertIn(bytes.fromhex("2e200101420304"), context.controller.events)
            self.assertIn(("sleep", 500), context.events)
            self.assertEqual(context.controller.events[-1], "finalize")

    def test_ig02_write_fault_skips_recheck(self) -> None:
        context = Context(
            [
                (0, b"x\x01"),
                (0, b"x\x02"),
                (0, bytes.fromhex("6220010000")),
                (27, b""),
                (19, b""),
            ]
        )
        self.assertEqual(self.call("Ex2IG_02_SendMessage", context), 27)
        self.assertNotIn(("sleep", 500), context.events)
        self.assertEqual(context.controller.events[-1], "finalize")

    def test_plus_ig02_mode22_selects_exact_classic_object_and_mask(self) -> None:
        context = Context(
            [
                (0, b"x\x01"),
                (0, b"x\x02"),
                (0, bytes.fromhex("6221030202")),
                (0, bytes.fromhex("6e2103")),
                (0, bytes.fromhex("6221030203")),
                (19, b""),
            ]
        )
        context.mode = 22
        with patch("scripts.utility_ex_ty.SHA_PLUS_TY", SYNTHETIC.source_sha256):
            self.assertEqual(self.call("Ex2IG_02_SendMessage", context), 0)
        self.assertIn(("comm", "native:1013e7d0"), context.events)
        self.assertIn(bytes.fromhex("2e21030203"), context.controller.events)

    def test_roof_clear_maps_native_error_and_always_settles(self) -> None:
        for reply, expected in (
            ((0, bytes.fromhex("7101b022")), 0),
            ((7, b""), 0x31),
            ((27, b""), 27),
            ((0, bytes.fromhex("7101b023")), 3),
        ):
            context = Context([(0, b"x\x01"), (0, b"x\x02"), reply, (19, b"")])
            context.controller.native_error = 0x31
            self.assertEqual(
                self.call("Ex2ROOF_01_ImpactDetectionInfoClear", context), expected
            )
            self.assertEqual(context.events.count(("sleep", 200)), 2)
            self.assertEqual(
                ("read_field", "native_10b0") in context.controller.events,
                reply[0] == 7,
            )
            self.assertEqual(context.controller.events[-2:], [b"\x90\x01", "finalize"])

    def test_hf_clear_success_settles_but_fault_does_not(self) -> None:
        for reply, expected in (
            ((0, bytes.fromhex("6e2001")), 0),
            ((27, b""), 27),
            ((0, bytes.fromhex("6e2002")), 3),
        ):
            context = Context([(0, b"x\x01"), (0, b"x\x02"), reply, (19, b"")])
            self.assertEqual(
                self.call("Ex2HF_01_Com_TanksNumberValueClear", context), expected
            )
            self.assertIn(bytes.fromhex("2e20011f"), context.controller.events)
            self.assertEqual(("sleep", 50) in context.events, expected == 0)
            self.assertEqual(context.controller.events[-1], "finalize")

    def test_fchv02_read_data_starts_at_third_record_then_sets_cycle_flag(self) -> None:
        data = bytearray(300)
        for index in range(5):
            offset = index * 56
            data[offset : offset + 2] = bytes((0x20, 0x97 + index))
            data[offset + 12 : offset + 16] = (2).to_bytes(4, "little")
            data[offset + 44 : offset + 48] = (1).to_bytes(4, "little")
        context = Context()
        original_exchange = context.controller.exchange
        for index in (2, 3, 4, 0, 1):
            context.controller.replies.append(
                (0, bytes((0x62, 0x20, 0x97 + index)) + b"ABCD")
            )

        def finish(request: bytes) -> tuple[int, bytes]:
            result = original_exchange(request)
            if request == bytes.fromhex("222098"):
                data[284:288] = (1).to_bytes(4, "little")
            return result

        context.controller.exchange = finish
        self.assertEqual(self.call("Ex2FCHV_02_ReadData", context, data), 0)
        self.assertEqual(
            [e.hex() for e in context.controller.events if isinstance(e, bytes)],
            ["222099", "22209a", "22209b", "222097", "222098"],
        )
        self.assertEqual(data[296:300], (1).to_bytes(4, "little"))
        self.assertEqual(data[48:50], b"AB")
        self.assertNotIn("finalize", context.controller.events)
        self.assertIn(("sleep", 200), context.events)

    def test_fchv02_read_data_fault_does_not_close_retained_session(self) -> None:
        for reply, expected in (((27, b""), 27), ((0, b"x"), 3)):
            data = bytearray(300)
            data[112:114] = bytes.fromhex("2099")
            data[156:160] = (1).to_bytes(4, "little")
            context = Context([reply])
            self.assertEqual(self.call("Ex2FCHV_02_ReadData", context, data), expected)
            self.assertNotIn("finalize", context.controller.events)
        data[124:128] = (5).to_bytes(4, "little")
        context = Context()
        with self.assertRaises(ValueError):
            self.call("Ex2FCHV_02_ReadData", context, data)
        self.assertEqual(context.events, [])

    def test_fchv02_read_data_host_fault_closes(self) -> None:
        data = bytearray(300)
        data[156:160] = (1).to_bytes(4, "little")
        context = Context()
        with self.assertRaises(AssertionError):
            self.call("Ex2FCHV_02_ReadData", context, data)
        self.assertEqual(context.controller.events[-1], "finalize")

    def test_fchv07_overwrite_is_native_unsupported_result_without_io(self) -> None:
        context = Context()
        self.assertEqual(self.call("Ex2FCHV_07_Overwrite", context, bytearray()), 1000)
        self.assertEqual(context.events, [])
        with self.assertRaises(ValueError):
            self.call("Ex2FCHV_07_Overwrite", context, None, None)

    def test_fchv09_uses_enable_byte_and_preserves_input(self) -> None:
        for response, expected in (
            ((0, bytes.fromhex("6e2005")), 0),
            ((0, bytes.fromhex("6e2004")), 2000),
            ((27, b""), 2000),
        ):
            data = bytearray(b"ABtail")
            context = Context([(0, b"x\x01"), (0, b"x\x02"), response, (19, b"")])
            self.assertEqual(
                self.call("Ex2FCHV_09_SendMessage", context, data), expected
            )
            self.assertIn(bytes.fromhex("2e2005014142"), context.controller.events)
            self.assertEqual(data, bytearray(b"ABtail"))
            self.assertEqual(context.controller.events[-1], "finalize")
        with self.assertRaises(ValueError):
            self.call("Ex2FCHV_09_SendMessage", Context(), bytearray(1))

    def test_fchv_support_aliases_set_only_supported_output_flags(self) -> None:
        gate = bytearray(bytes.fromhex("620101") + bytes(32))
        gate[7] = 0x80
        response = bytearray(bytes.fromhex("622000") + bytes(32))
        response[3:6] = bytes((8, 0, 0x80))
        for export in ("Ex2FCHV_07_SupportCheck", "Ex2FCHV_08_SupportCheck"):
            context = Context(
                [
                    (0, b"x\x01"),
                    (0, b"x\x02"),
                    (0, bytes(gate)),
                    (0, bytes(response)),
                    (19, b""),
                ]
            )
            data = bytearray((9).to_bytes(4, "little") * 5)
            self.assertEqual(self.call(export, context, data), 0)
            self.assertEqual(
                [int.from_bytes(data[i : i + 4], "little") for i in range(0, 20, 4)],
                [9, 9, 1, 9, 1],
            )
            self.assertEqual(context.controller.events[-1], "finalize")

    def test_fchv_support_gate_fault_preserves_flags_and_restores(self) -> None:
        for gate in (
            (27, b""),
            (0, bytes.fromhex("620101") + bytes(32)),
            (0, bytes.fromhex("620101") + bytes(33)),
            (0, b""),
        ):
            context = Context([(0, b"x\x01"), (0, b"x\x02"), gate, (19, b"")])
            data = bytearray(b"x" * 20)
            self.assertEqual(
                self.call("Ex2FCHV_07_SupportCheck", context, data),
                27 if gate[0] else 3,
            )
            self.assertEqual(data, bytearray(b"x" * 20))
            self.assertNotIn(bytes.fromhex("222000"), context.controller.events)
            self.assertEqual(context.controller.events[-2:], [b"\x90\x01", "finalize"])

    def test_fchv05_success_retains_controller_and_checks_result(self) -> None:
        context = Context(
            [
                (0, b"x\x01"),
                (0, b"x\x02"),
                (0, bytes.fromhex("7101111b")),
                (0, bytes.fromhex("7103111b01")),
            ]
        )
        self.assertEqual(self.call("Ex2FCHV_05_SendMessage", context, bytearray(8)), 0)
        self.assertNotIn("finalize", context.controller.events)
        self.assertEqual(context.events[-1], ("sleep", 200))

    def test_fchv05_cancel_flag_restores_and_finalizes(self) -> None:
        data = bytearray(8)
        context = Context(
            [(0, b"x\x01"), (0, b"x\x02"), (0, bytes.fromhex("7101111b")), (19, b"")]
        )

        def cancel_on_sleep(ms: int) -> None:
            data[4:8] = (1).to_bytes(4, "little")

        context.sleep = cancel_on_sleep
        self.assertEqual(self.call("Ex2FCHV_05_SendMessage", context, data), 2001)
        self.assertNotIn(bytes.fromhex("3103111b"), context.controller.events)
        self.assertEqual(context.controller.events[-2:], [b"\x90\x01", "finalize"])

    def test_fchv05_result_fault_maps_and_cleans_up(self) -> None:
        for result in (
            (27, b""),
            (0, bytes.fromhex("7103111b00")),
            (0, bytes.fromhex("7103111b")),
        ):
            context = Context(
                [
                    (0, b"x\x01"),
                    (0, b"x\x02"),
                    (0, bytes.fromhex("7101111b")),
                    result,
                    (19, b""),
                ]
            )
            self.assertEqual(
                self.call("Ex2FCHV_05_SendMessage", context, bytearray(8)), 2002
            )
            self.assertEqual(context.controller.events[-1], "finalize")

    def test_fchv05_init_fault_stop_and_noop(self) -> None:
        context = Context()
        context.controller.initial_status = 27
        self.assertEqual(
            self.call("Ex2FCHV_05_SendMessage", context, bytearray(8)), 2000
        )
        self.assertEqual(context.controller.events[-1], "finalize")
        context = Context([(27, b"")])
        data = bytearray((1).to_bytes(4, "little") + bytes(4))
        self.assertEqual(self.call("Ex2FCHV_05_SendMessage", context, data), 0)
        self.assertEqual(context.controller.events, [b"\x90\x01", "finalize"])
        context = Context()
        data[:4] = (2).to_bytes(4, "little")
        self.assertEqual(self.call("Ex2FCHV_05_SendMessage", context, data), 0)
        self.assertEqual(context.events, [])

    def test_fchv06_read_mutates_only_two_bytes_and_propagates_restore(self) -> None:
        data = bytearray(b"zzXY" + (1).to_bytes(4, "little") + b"tail")
        context = Context(
            [(0, b"x\x01"), (0, b"x\x02"), (0, bytes.fromhex("6220041234")), (19, b"")]
        )
        self.assertEqual(self.call("Ex2FCHV_06_SendMessage", context, data), 19)
        self.assertEqual(
            data, bytearray(b"\x12\x34XY" + (1).to_bytes(4, "little") + b"tail")
        )
        self.assertEqual(
            context.controller.events[-3:],
            [bytes.fromhex("222004"), b"\x90\x01", "finalize"],
        )

    def test_fchv06_write_ignores_restore_but_maps_fault(self) -> None:
        for reply, expected in (
            ((0, bytes.fromhex("6e2004")), 0),
            ((0, bytes.fromhex("6e2005")), 2000),
            ((27, b""), 2000),
        ):
            data = bytearray(b"ABxx" + bytes(4))
            context = Context([(0, b"x\x01"), (0, b"x\x02"), reply, (19, b"")])
            self.assertEqual(
                self.call("Ex2FCHV_06_SendMessage", context, data), expected
            )
            self.assertIn(bytes.fromhex("2e20044142"), context.controller.events)
            self.assertEqual(context.controller.events[-1], "finalize")

    def test_fchv06_bad_read_does_not_clobber_output(self) -> None:
        for reply in (
            (0, bytes.fromhex("62200412")),
            (0, bytes.fromhex("6220051234")),
            (27, b""),
        ):
            data = bytearray(b"ABxx" + (1).to_bytes(4, "little"))
            original = bytes(data)
            context = Context([(0, b"x\x01"), (0, b"x\x02"), reply, (19, b"")])
            expected = 27 if reply[0] else 3
            self.assertEqual(
                self.call("Ex2FCHV_06_SendMessage", context, data), expected
            )
            self.assertEqual(bytes(data), original)

    def test_fchv06_unknown_action_and_initialize_fault(self) -> None:
        for action, initial in ((9, 0), (1, 27)):
            context = Context()
            context.controller.initial_status = initial
            data = bytearray(4) + bytearray(action.to_bytes(4, "little"))
            self.assertEqual(
                self.call("Ex2FCHV_06_SendMessage", context, data), initial
            )
            self.assertFalse(
                any(isinstance(e, bytes) for e in context.controller.events)
            )
            self.assertEqual(context.controller.events[-1], "finalize")
        with self.assertRaises(ValueError):
            self.call("Ex2FCHV_06_SendMessage", Context(), bytearray(7))

    def test_fchv06_host_fault_finalizes(self) -> None:
        context = Context()
        with self.assertRaises(AssertionError):
            self.call("Ex2FCHV_06_SendMessage", context, bytearray(8))
        self.assertEqual(context.controller.events[-1], "finalize")

    def test_plus_fchv10_gates_and_clear_only_semantics(self) -> None:
        data = bytearray(508)
        for offset in range(0, 504, 24):
            data[offset + 8] = 0x80
            data[offset + 12 : offset + 16] = (9).to_bytes(4, "little")
        data[8] = 0x20
        first = bytearray(bytes.fromhex("620101") + bytes(32))
        first[6] = 0x10
        second = bytearray(bytes.fromhex("621b00") + bytes(32))
        second[26] = 0x10
        context = Context(
            [
                (0, b"x\x01"),
                (0, b"x\x02"),
                (0, bytes(first)),
                (0, bytes(second)),
                (0, bytes.fromhex("621bbc200000000000")),
                (19, b""),
            ]
        )
        with patch("scripts.utility_ex_ty.SHA_PLUS_TY", SYNTHETIC.source_sha256):
            self.assertEqual(self.call(EXTRA_EXPORTS_18_TY[0], context, data), 19)
        self.assertEqual(int.from_bytes(data[12:16], "little"), 9)
        self.assertEqual(data[36:40], bytes(4))
        self.assertIn(bytes.fromhex("220101"), context.controller.events)
        self.assertIn(bytes.fromhex("221b00"), context.controller.events)

    def test_plus_fchv10_missing_gate_preserves_records_and_restore_status(
        self,
    ) -> None:
        data = bytearray(508)
        data[12:16] = (9).to_bytes(4, "little")
        original = bytes(data)
        for reply, expected in (
            ((0, bytes.fromhex("620101") + bytes(32)), 19),
            ((27, b""), 27),
            ((0, b"x"), 3),
        ):
            context = Context([(0, b"x\x01"), (0, b"x\x02"), reply, (19, b"")])
            with patch("scripts.utility_ex_ty.SHA_PLUS_TY", SYNTHETIC.source_sha256):
                self.assertEqual(
                    self.call(EXTRA_EXPORTS_18_TY[0], context, data), expected
                )
            self.assertEqual(bytes(data), original)
            self.assertNotIn(bytes.fromhex("221bbc"), context.controller.events)
            self.assertEqual(context.controller.events[-1], "finalize")

    def test_invalid_inputs_do_not_touch_controller(self) -> None:
        context = Context()
        for export, args in (
            (EXPORTS_18_TY[0], (1,)),
            (EXPORTS_18_TY[1], (True,)),
            (EXPORTS_18_TY[2], (0, -1)),
            (EXPORTS_18_TY[3], (0,)),
        ):
            with self.subTest(export=export), self.assertRaises(ValueError):
                self.engine.run_body(export, args, context)
        self.assertEqual(context.events, [])
        with self.assertRaises(ValueError):
            TYMessage(-1)


if __name__ == "__main__":
    unittest.main()
