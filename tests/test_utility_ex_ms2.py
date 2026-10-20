"""Literal MS2 source vectors; no OEM code or device transport executes."""

from __future__ import annotations

import struct
import threading
import unittest
from collections import deque
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

from scripts import utility_ex_ms2 as ms2
from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import (
    SHA_12_TY,
    SHA_18_TY,
    SHA_PLUS_TY,
    TYContext,
    TYSourceError,
)


class Comm:
    def __init__(self, replies: list[tuple[int, bytes]] | None = None) -> None:
        self.replies = deque(replies or [])
        self.calls: list[object] = []
        self.init_status = 0
        self.session_status = 0
        self.field = 0
        self.fault = False
        self.timing_status = 0

    def initialize(self, mode: int = 0) -> int:
        self.calls.append(("initialize", mode))
        return self.init_status

    def finalize(self) -> None:
        self.calls.append("finalize")

    def configure(self, field: str, value: int) -> None:
        self.calls.append(("configure", field, value))

    def configure_target(
        self,
        first: int,
        second: int = 0,
        third: int = 0,
        fourth: int = 0,
        fifth: int = 0,
    ) -> None:
        self.calls.append(("configure_target", first, second, third, fourth, fifth))

    def exchange(self, request: bytes) -> tuple[int, bytes]:
        self.calls.append(request)
        if self.fault:
            raise OSError("synthetic driver fault")
        if not self.replies:
            raise AssertionError("unexpected diagnostic request")
        return self.replies.popleft()

    def session(self, mode: int, keepalive: int = 1, **kwargs: bool) -> int:
        self.calls.append(("session", mode, keepalive, kwargs))
        return self.session_status

    def read_dtcs(self, mode: int = 0x80, capacity: int = 0x1000) -> tuple[int, bytes]:
        self.calls.append(("read_dtcs", mode, capacity))
        return self.replies.popleft()

    def select_diagnostic_mode(self, kind: int) -> int:
        self.calls.append(("select_diagnostic_mode", kind))
        return 0

    def select_protocol(self, kind: int) -> int:
        self.calls.append(("select_protocol", kind))
        return 0

    def read_field(self, field: str) -> int:
        self.calls.append(("read_field", field))
        return self.field

    def configure_keepalive(
        self, interval_ms: int, request: bytes, response_size: int, flags: int
    ) -> None:
        self.calls.append(
            ("configure_keepalive", interval_ms, request, response_size, flags)
        )

    def keepalive(self, enabled: bool, wait: bool = False) -> int:
        self.calls.append(("keepalive", enabled, wait))
        return self.timing_status


class Context:
    def __init__(
        self, source: str = SHA_18_TY, replies: list[tuple[int, bytes]] | None = None
    ) -> None:
        self._worker = None
        self._cancel = threading.Event()
        self.module_sha256 = source
        self.module_bytes = b""
        self.mode = 52
        self.state: dict[str, object] = {}
        self.communication = Comm(replies)
        self.communications: dict[str, Comm] = {}
        self.cancel = False
        self.sleeps: list[int] = []
        self.selected: list[str] = []
        self.on_sleep = lambda: None

    def comm(self, kind: str) -> object:
        self.selected.append(kind)
        return self.communications.get(kind, self.communication)

    def is_cancelled(self) -> bool:
        return self.cancel

    def sleep(self, ms: int) -> None:
        self.sleeps.append(ms)
        self.on_sleep()

    def ticks(self) -> int:
        return sum(self.sleeps)

    def native_sleep(self, ms: int) -> None:
        self.sleep(ms)


def call(export: str, context: Context, argument: object) -> int:
    return ms2.run_body(
        export,
        () if export == "Ex2MS2ABS_05_SendMessage" else (argument,),
        cast(TYContext, context),
    )


def data(action: int, length: int = 12) -> bytearray:
    return bytearray(action.to_bytes(4, "little") + bytes(length - 4))


class MS2Tests(unittest.TestCase):
    def test_exact_sources_and_disjoint_ownership(self) -> None:
        self.assertEqual(ms2.supported_exports(SHA_12_TY), ())
        self.assertEqual(ms2.supported_exports("0" * 64), ())
        self.assertEqual(len(ms2.supported_exports(SHA_18_TY)), 38)
        self.assertEqual(len(ms2.supported_exports(SHA_PLUS_TY)), 38)
        self.assertFalse(
            any(
                "MS2MM" in x or "MS2BSRL" in x or "SMRT" in x
                for x in ms2.supported_exports(SHA_18_TY)
            )
        )
        with self.assertRaises(TYSourceError):
            call("Ex2MS2MM_01_SendMessage", Context(), data(0))

    def test_actual_ty_dispatch_join_preserves_argument_identity(self) -> None:
        from scripts.utility_ex_ty import run_body, supported_exports

        c = Context(replies=[(0, bytes.fromhex("62102b0002"))])
        argument = data(1)
        self.assertIn("Ex2MS2ABS_01_SendMessage", supported_exports(c.module_sha256))
        # Synthetic identity bypass is explicit; dispatch and mutable output are real.
        with patch(
            "scripts.utility_ex_ty.hashlib.sha256",
            return_value=SimpleNamespace(hexdigest=lambda: c.module_sha256),
        ):
            self.assertEqual(
                run_body("Ex2MS2ABS_01_SendMessage", (argument,), cast(TYContext, c)), 0
            )
        self.assertEqual(int.from_bytes(argument[8:12], "little"), 2612)

    def test_actual_public_worker_executes_all_admitted_source_pairs(self) -> None:
        from scripts.utility_ex import UtilityExContext, UtilityExEngine

        for source in (SHA_18_TY, SHA_PLUS_TY):
            for export in ms2.supported_exports(source):
                c = Context(source)
                expected = 0
                argument: object = data(99)
                arguments: tuple[object, ...] = (argument,)
                if export.endswith("CheckPressureSensorValue"):
                    arguments, expected = (0x7F8B,), 1
                elif "ABS_05" in export:
                    arguments, expected = (), 2001
                    c.communication.replies.append((5, b""))
                elif "EFI_04" in export:
                    argument = bytearray(0xE4)
                    argument[0xE0:0xE4] = (1).to_bytes(4, "little")
                    arguments = (argument,)
                elif "RAB_01" in export:
                    argument = bytearray(36)
                    argument[32:36] = (1).to_bytes(4, "little")
                    arguments, expected = (argument,), 1004
                    c.communication.replies.extend(
                        (0, bytes.fromhex(x))
                        for x in ("6210a100", "6210a300", "6210a500")
                    )
                elif "BDY_01" in export:
                    arguments = (data(99, 100),)
                elif "SAS_02" in export:
                    arguments = (data(99, 23),)
                elif "EFI_01" in export:
                    argument = bytearray(0x4094)
                    argument[0x4090:0x4094] = (2).to_bytes(4, "little")
                    arguments = (argument,)
                elif "EFI_02" in export:
                    arguments, expected = (), 5
                    c.communication.replies.append((5, b""))
                elif "GWY" in export:
                    arguments, expected = (data(3),), 3000
                    c.communication.replies.append((0, bytes.fromhex("500100000000")))
                elif "PWD" in export:
                    expected = 1003
                # Newly recovered controllers replay a literal native init failure through
                # the real outer worker; direct branch positives are checked separately.
                sizes = {
                    "MET_01": 0x18C,
                    "MET_02": 0x21C,
                    "TPW_01": 6,
                    "DCM_01": 20,
                    "DCM_02": 6,
                    "ABS_04": 4,
                    "AT_01": 4,
                    "AT_02": 64,
                    "RAB_02": 0x7F8 if source == SHA_18_TY else 0xA00,
                    "EFI_03": 8,
                    "EFI_05": 0x88,
                    "EFI_06": 24,
                    "SAS_01": 72,
                    "SAS_03": 0x103C,
                    "IG_01": 44,
                    "EMPS_01": 8,
                    "EMPS_02": 8,
                    "EYES_01": 0x104,
                    "EYES_02": 4,
                    "EYES_03": 8,
                    "EYES_04": 20,
                    "EYES_05": 0x4A4,
                    "EYES_06": 0x188,
                    "EYES_07": 0x15C if source == SHA_18_TY else 0x27C,
                }
                for name, length in sizes.items():
                    if name in export:
                        argument = bytearray(length)
                        if name == "MET_02":
                            argument[0x210:0x214] = (1).to_bytes(4, "little")
                        if name in ("EYES_04", "EFI_06"):
                            argument[:4] = (1).to_bytes(4, "little")
                        arguments, expected = (
                            (argument,),
                            2000 if name == "AT_01" else 57,
                        )
                        c.communication.init_status = 57
                        break
                engine = UtilityExEngine(cast(UtilityExContext, c))
                with (
                    self.subTest(source=source[:12], export=export),
                    patch(
                        "scripts.utility_ex_ty.hashlib.sha256",
                        return_value=SimpleNamespace(
                            hexdigest=lambda selected=source: selected
                        ),
                    ),
                ):
                    immediate = engine.invoke(export, arguments)
                    if export.endswith("CheckPressureSensorValue"):
                        self.assertEqual(immediate, expected)
                    else:
                        self.assertEqual(immediate, 15)
                        self.assertEqual(engine.invoke("Ex2GetThreadStatus"), expected)

    def test_met02_support_and_conditional_cleanup(self) -> None:
        for source in (SHA_18_TY, SHA_PLUS_TY):
            c = Context(source, [(0, bytes.fromhex("62100000000000"))])
            argument = bytearray(0x21C)
            self.assertEqual(call("Ex2MS2MET_02_SendMessage", c, argument), 3)
            self.assertNotIn("finalize", c.communication.calls)
            argument[0x210:0x214] = (1).to_bytes(4, "little")
            c.communication.replies.append((7, b"\x7f\x22\x31"))
            self.assertEqual(call("Ex2MS2MET_02_SendMessage", c, argument), 1000)
            self.assertIn(("configure", "native_1098", 4), c.communication.calls)
            self.assertEqual(c.communication.calls.count("finalize"), 2)

    def test_met02_record_writes_and_final_marker_native_status_mapping(self) -> None:
        for native, expected in ((0, 0), (5, 3), (7, 1001)):
            c = Context(
                replies=[
                    (0, bytes.fromhex("62100080000000")),
                    (0, bytes.fromhex("6e1001")),
                    (native, bytes.fromhex("6e10c2")),
                ]
            )
            argument = bytearray(0x21C)
            for offset, value in (
                (0, 0x1001),
                (8, 1),
                (0x180, 1),
                (0x184, 0x1001),
                (0x204, 1),
                (0x208, 0x1001),
                (0x218, 2),
            ):
                argument[offset : offset + 4] = value.to_bytes(4, "little")
            argument[4] = 0x5A
            self.assertEqual(call("Ex2MS2MET_02_SendMessage", c, argument), expected)
            self.assertIn(bytes.fromhex("2e10015a"), c.communication.calls)
            self.assertIn(bytes.fromhex("2e10c200"), c.communication.calls)
            self.assertEqual(int.from_bytes(argument[0x210:0x214], "little"), 1)
            self.assertIn("finalize", c.communication.calls)

    def test_met02_host_fault_always_finalizes_both(self) -> None:
        c = Context()
        c.communication.fault = True
        with self.assertRaises(OSError):
            call("Ex2MS2MET_02_SendMessage", c, bytearray(0x21C))
        self.assertEqual(c.communication.calls.count("finalize"), 2)

    def test_sas01_three_manager_source_order_and_default_restore(self) -> None:
        for source, secondary, vin in (
            (SHA_18_TY, "native:1011c400", "native:1011b310"),
            (SHA_PLUS_TY, "native:10135c58", "native:10136e10"),
        ):
            c = Context(source)
            other, vin_manager = Comm(), Comm()
            c.communications[secondary] = other
            c.communications[vin] = vin_manager
            argument = data(99, 72)
            self.assertEqual(call("Ex2MS2SAS_01_SendMessage", c, argument), 0)
            self.assertIn(
                ("configure_keepalive", 1000, b"\x3e\x00", 1, 0xF0),
                c.communication.calls,
            )
            self.assertIn(("select_diagnostic_mode", 3), vin_manager.calls)
            self.assertIn(
                ("configure_target", 0x7A2, 0, 0x7DF, 0, 0x7E0), vin_manager.calls
            )
            self.assertEqual(int.from_bytes(argument[64:68], "little"), 1)
            self.assertEqual(other.calls[-1], "finalize")
            self.assertEqual(vin_manager.calls[-1], "finalize")

    def test_sas01_support_uses_secondary_then_primary_and_maps_errors(self) -> None:
        c = Context()
        secondary = Comm([(0, bytes.fromhex("62020000000000"))])
        c.communications["native:1011c400"] = secondary
        self.assertEqual(call("Ex2MS2SAS_01_SendMessage", c, data(0, 72)), 1001)
        self.assertIn(bytes.fromhex("220200"), secondary.calls)
        self.assertFalse(any(isinstance(item, bytes) for item in c.communication.calls))
        c = Context(replies=[(0, bytes.fromhex("62105eff"))])
        self.assertEqual(call("Ex2MS2SAS_01_SendMessage", c, data(1, 72)), 1002)

    def test_sas01_vin_copy_protocol_switch_and_invalid_all_zero(self) -> None:
        c = Context(replies=[(0, bytes.fromhex("62105e00"))])
        vin = Comm([(0, b"\x49\x02\x01" + bytes(17)), (0, b"\x49\x0a\x01a\0b")])
        c.communications["native:1011b310"] = vin
        argument = data(1, 72)
        self.assertEqual(call("Ex2MS2SAS_01_SendMessage", c, argument), 1004)
        self.assertEqual(argument[40:43], b"a b")
        self.assertIn(("select_diagnostic_mode", 2), vin.calls)
        self.assertEqual(vin.calls.count("finalize"), 2)

    def test_dcm01_io_control_native_nrc_mapping_retains(self) -> None:
        for source in (SHA_18_TY, SHA_PLUS_TY):
            c = Context(source, [(7, b"\x7f\x2f\x69")])
            c.communication.field = 0x69
            argument = bytearray(20)
            argument[16:20] = (3).to_bytes(4, "little")
            argument[11] = 0xA5
            self.assertEqual(call("Ex2MS2DCM_01_SendMessage", c, argument), 2000)
            self.assertIn(bytes.fromhex("2f104603a5"), c.communication.calls)
            self.assertNotIn("finalize", c.communication.calls)

    def test_dcm01_return_control_polls_until_all_zero_then_finalizes(self) -> None:
        c = Context(
            replies=[
                (0, bytes.fromhex("6f104500")),
                (0, bytes.fromhex("62104501")),
                (0, bytes.fromhex("62104500")),
            ]
        )
        argument = bytearray(20)
        argument[:2] = (0x8000).to_bytes(2, "little")
        argument[16:20] = (5).to_bytes(4, "little")
        self.assertEqual(call("Ex2MS2DCM_01_SendMessage", c, argument), 0)
        self.assertEqual(c.communication.calls.count(bytes.fromhex("221045")), 2)
        self.assertEqual(c.communication.calls[-1], "finalize")

    def test_dcm01_monitor_observes_live_stop_and_native_signed_flag(self) -> None:
        for flag, expected in ((1, 2004), (0x80, 2002)):
            c = Context()
            argument = bytearray(20)
            argument[16:20] = (6).to_bytes(4, "little")
            c.on_sleep = lambda selected=argument, value=flag: selected.__setitem__(
                12, value
            )
            self.assertEqual(call("Ex2MS2DCM_01_SendMessage", c, argument), expected)
            self.assertEqual(c.sleeps, [100])
            self.assertEqual(argument[4:8], bytes.fromhex("ff0fff0f"))
            self.assertNotIn("finalize", c.communication.calls)

    def test_at02_initial_measurements_and_native_state_guard(self) -> None:
        for second, expected in ((0xFF, 0), (0, 2000)):
            c = Context(
                replies=[
                    (0, bytes([0x62, identifier >> 8, identifier & 255, value]))
                    for identifier, value in (
                        (0x10D2, 10),
                        (0x1622, second),
                        (0x1623, 20),
                        (0x1624, 15),
                    )
                ]
            )
            argument = data(1, 64)
            self.assertEqual(call("Ex2MS2AT_02_SendMessage", c, argument), expected)
            self.assertEqual(argument[4], 10)
            self.assertNotIn("finalize", c.communication.calls)
            if second == 0xFF:
                self.assertEqual(argument[5:8], bytes([0xFF, 20, 15]))

    def test_at02_native_status_poll_retains_pending_or_success(self) -> None:
        for value, expected, retained in (
            (0, 2002, True),
            (255, 0, True),
            (1, 2003, False),
        ):
            c = Context(replies=[(0, bytes([0x62, 0x11, 0xFA, value]))])
            self.assertEqual(call("Ex2MS2AT_02_SendMessage", c, data(3, 64)), expected)
            self.assertEqual("finalize" not in c.communication.calls, retained)

    def test_at02_stable_sensor_uses_one_second_timer_without_invented_sleep(
        self,
    ) -> None:
        c = Context(replies=[(0, bytes.fromhex("621205ff"))] * 3)
        ticks = iter((0, 500, 1000))
        c.ticks = lambda: next(ticks)
        argument = data(4, 64)
        self.assertEqual(call("Ex2MS2AT_02_SendMessage", c, argument), 0)
        self.assertEqual(c.sleeps, [])
        self.assertNotIn("finalize", c.communication.calls)

    def test_at02_cancel_and_native_raw_error_cleanup(self) -> None:
        c = Context(replies=[(7, b"\x7f\x22\x31")])
        self.assertEqual(call("Ex2MS2AT_02_SendMessage", c, data(3, 64)), 7)
        self.assertEqual(c.state, {})
        self.assertIn("finalize", c.communication.calls)
        c = Context()
        c.cancel = True
        with self.assertRaises(Cancelled):
            call("Ex2MS2AT_02_SendMessage", c, data(4, 64))

    def test_emps_source_specific_support_patterns_and_dtc_exclusions(self) -> None:
        for source, expected in ((SHA_18_TY, 1011), (SHA_PLUS_TY, 0)):
            c = Context(
                source,
                [(0, bytes.fromhex("5a5c95000199")), (0, bytes.fromhex("53015525"))],
            )
            self.assertEqual(call("Ex2MS2EMPS_01_SendMessage", c, data(0, 8)), expected)
            self.assertEqual(c.selected, ["selected"])
            self.assertEqual(c.communication.calls[-1], "finalize")
        c = Context(
            replies=[(0, bytes.fromhex("5a2c95000100")), (0, bytes.fromhex("53015516"))]
        )
        self.assertEqual(call("Ex2MS2EMPS_01_SendMessage", c, data(0, 8)), 1012)

    def test_emps01_session_retains_and_final_dtc_status_restores(self) -> None:
        c = Context(replies=[(0, b"")])
        self.assertEqual(call("Ex2MS2EMPS_01_SendMessage", c, data(2, 8)), 0)
        self.assertNotIn("finalize", c.communication.calls)
        for records, expected in (
            ("53015515", 1009),
            ("53015599", 1010),
            ("53015525", 0),
        ):
            c = Context(replies=[(0, bytes.fromhex(records)), (0, b"")])
            self.assertEqual(call("Ex2MS2EMPS_01_SendMessage", c, data(4, 8)), expected)
            self.assertIn(b"\x10\x01", c.communication.calls)

    def test_emps02_dtc_guard_result_output_and_raw_error_quirks(self) -> None:
        for record, expected in ((0x5534, 1003), (0x5582, 1004), (0x5500, 1005)):
            c = Context(
                replies=[
                    (0, b"\x53\x01" + record.to_bytes(2, "big")),
                    (0, bytes.fromhex("e90377")),
                ]
            )
            argument = data(1, 8)
            self.assertEqual(call("Ex2MS2EMPS_02_SendMessage", c, argument), expected)
            if expected == 1005:
                self.assertEqual(argument[4], 0x77)
        c = Context(replies=[(7, bytes.fromhex("7f3b10"))])
        self.assertEqual(call("Ex2MS2EMPS_02_SendMessage", c, data(3, 8)), 1010)
        self.assertEqual(c.state, {})

    def test_met02_legacy_security_abi_reads_thirty_two_source_bytes(self) -> None:
        c = Context(replies=[(0, bytes.fromhex("6e10c2"))])
        argument = bytearray(0x21C)
        argument[0x218:0x21C] = (1).to_bytes(4, "little")
        with (
            patch.object(ms2.security, "source_key", return_value=bytes(32)) as key,
            patch.object(ms2.security, "security_access", return_value=0) as access,
        ):
            self.assertEqual(call("Ex2MS2MET_02_SendMessage", c, argument), 0)
            self.assertEqual(key.call_args.args[1:], (0xDBD70, 32))
            self.assertEqual(access.call_args.kwargs["mode"], 2)
            self.assertEqual(access.call_args.kwargs["expected_capability"], 0)
            self.assertEqual(access.call_args.kwargs["direction"], 2)
        self.assertNotIn("finalize", c.communication.calls)
        self.assertIn(("keepalive", True, False), c.communication.calls)

    def test_sas01_security_abi_uses_aes_source_key_and_capability_two(self) -> None:
        c = Context(replies=[(0, bytes.fromhex("6e105e"))])
        with (
            patch.object(ms2.security, "source_key", return_value=bytes(16)) as key,
            patch.object(ms2.security, "security_access", return_value=0) as access,
        ):
            self.assertEqual(call("Ex2MS2SAS_01_SendMessage", c, data(2, 72)), 0)
            self.assertEqual(key.call_args.args[1:], (0xDBD90, 16))
            self.assertEqual(access.call_args.kwargs["mode"], 1)
            self.assertEqual(access.call_args.kwargs["expected_capability"], 2)
            self.assertEqual(access.call_args.kwargs["direction"], 2)
        self.assertNotIn(("keepalive", True, False), c.communication.calls)

    def test_ig01_source_stack_copy_layout_preserves_byod_key_and_residual(
        self,
    ) -> None:
        for source in (SHA_18_TY, SHA_PLUS_TY):
            c = Context(
                source,
                [
                    (0, bytes.fromhex(reply))
                    for reply in ("62300000000001", "62302040000001", "62304040000000")
                ],
            )
            key = bytes(range(16))  # Synthetic public bytes, not original key material.
            c.state["native_stack:100b0fc0:uninitialized_1c"] = b"TEST"
            argument = bytearray(44)
            with (
                patch.object(ms2.security, "source_immediate_key", return_value=key),
                patch.object(ms2.security, "security_access", return_value=0),
            ):
                self.assertEqual(call("Ex2MS2IG_01_SendMessage", c, argument), 0)
            bitmap = bytes.fromhex("000000014000000140000000")
            expected = bitmap + (
                key + bytes.fromhex("22300000")
                if source == SHA_18_TY
                else b"TEST" + key
            )
            self.assertEqual(argument[:32], expected)

    def test_dual_cleanup_attempts_both_and_preserves_original_host_exception(
        self,
    ) -> None:
        c = Context()
        other = Comm()
        c.communications["native:1011a220"] = other
        c.communication.fault = True
        with (
            patch.object(
                c.communication, "finalize", side_effect=RuntimeError("cleanup failure")
            ),
            self.assertRaisesRegex(OSError, "synthetic driver fault") as raised,
        ):
            call("Ex2MS2ABS_04_SendMessage", c, data(1))
        self.assertEqual(other.calls[-1], "finalize")
        self.assertIn(
            "MS2 finalization raised RuntimeError", raised.exception.__notes__
        )
        c = Context(replies=[(0, bytes.fromhex("62108600"))])
        c.communications["native:1011a220"] = other = Comm()
        with (
            patch.object(
                c.communication, "finalize", side_effect=RuntimeError("cleanup failure")
            ),
            self.assertRaisesRegex(RuntimeError, "cleanup failure"),
        ):
            call("Ex2MS2ABS_04_SendMessage", c, data(1))
        self.assertEqual(other.calls[-1], "finalize")

    def test_pressure_boundaries_signed_and_bool_return(self) -> None:
        for source in (SHA_18_TY, SHA_PLUS_TY):
            c = Context(source)
            for value, expected in (
                (-1, 0),
                (0x7F8A, 0),
                (0x7F8B, 1),
                (0x11EF67, 1),
                (0x11EF68, 0),
                (0x7FFFFFFF, 0),
            ):
                self.assertEqual(
                    call("Ex2MS2ABS_01_CheckPressureSensorValue", c, value), expected
                )
            self.assertEqual(c.selected, [])
            for value in (True, 1.0, 1 << 32):
                with self.assertRaises(ValueError):
                    call("Ex2MS2ABS_01_CheckPressureSensorValue", c, value)

    def test_argument_validation_before_io(self) -> None:
        c = Context()
        for argument in (bytes(12), bytearray(11), None):
            with self.assertRaises(ValueError):
                call("Ex2MS2ABS_01_SendMessage", c, argument)
        self.assertFalse(c.selected)

    def test_abs_pressure_signed_output_and_retained_manager(self) -> None:
        for source, manager, global_key in (
            (SHA_18_TY, "native:1011d4f0", "native_global:1012ae20"),
            (SHA_PLUS_TY, "native:101392d0", "native_global:1015353c"),
        ):
            c = Context(source, [(0, bytes.fromhex("62102bfffe"))])
            argument = data(1)
            self.assertEqual(call("Ex2MS2ABS_01_SendMessage", c, argument), 0)
            self.assertEqual(
                int.from_bytes(argument[8:12], "little", signed=True), -2612
            )
            self.assertEqual(c.selected, [manager])
            self.assertEqual(c.state[global_key], 1)
            self.assertNotIn("finalize", c.communication.calls)
            self.assertIn(bytes.fromhex("22102b"), c.communication.calls)

    def test_abs_pressure_malformed_echo_cleans_up(self) -> None:
        c = Context(replies=[(0, bytes.fromhex("62102c0001"))])
        argument = data(1)
        argument[8:] = b"keep"
        self.assertEqual(call("Ex2MS2ABS_01_SendMessage", c, argument), 3)
        self.assertEqual(argument[8:], b"keep")
        self.assertEqual(c.state["native_global:1012ae20"], 0)
        self.assertEqual(c.communication.calls[-1], "finalize")

    def test_abs_support_continuation_and_missing(self) -> None:
        for second, expected in (("62102000200000", 0), ("62102000000000", 3)):
            c = Context(
                replies=[
                    (0, bytes.fromhex("62100000000001")),
                    (0, bytes.fromhex(second)),
                ]
            )
            self.assertEqual(call("Ex2MS2ABS_01_SendMessage", c, data(0)), expected)
            self.assertEqual(
                [x for x in c.communication.calls if isinstance(x, bytes)],
                [bytes.fromhex("221000"), bytes.fromhex("221020")],
            )
            self.assertEqual(c.communication.calls[-1], "finalize")

    def test_abs_poll_observes_mutable_stop_every_ten_ms(self) -> None:
        for flag, expected in ((1, 2003), (2, 0)):
            c = Context()
            argument = data(2)

            def stop(target: bytearray = argument, value: int = flag) -> None:
                target[4:8] = value.to_bytes(4, "little")

            c.on_sleep = stop
            self.assertEqual(call("Ex2MS2ABS_01_SendMessage", c, argument), expected)
            self.assertEqual(c.sleeps, [10])
            self.assertEqual("finalize" in c.communication.calls, expected != 0)

    def test_abs_poll_cancellation_finalizes_and_resets_global(self) -> None:
        c = Context()
        c.on_sleep = lambda: setattr(c, "cancel", True)
        with self.assertRaises(Cancelled):
            call("Ex2MS2ABS_01_SendMessage", c, data(2))
        self.assertEqual(c.communication.calls[-1], "finalize")
        self.assertEqual(c.state["native_global:1012ae20"], 0)

    def test_abs_start_retention_sleep_and_finish(self) -> None:
        c = Context(
            replies=[
                (0, bytes.fromhex("71010203")),
                (0, bytes.fromhex("710302030001")),
                (0, bytes.fromhex("710302030002")),
            ]
        )
        self.assertEqual(call("Ex2MS2ABS_01_SendMessage", c, data(3)), 0)
        self.assertEqual(call("Ex2MS2ABS_01_SendMessage", c, data(4)), 0)
        self.assertEqual(call("Ex2MS2ABS_01_SendMessage", c, data(5)), 0)
        self.assertEqual(sum(x == ("initialize", 0) for x in c.communication.calls), 1)
        self.assertEqual(c.sleeps, [4200, 5000])
        self.assertEqual(c.communication.calls[-1], "finalize")

    def test_abs04_actual_security_two_managers_and_byod_operand_projection(
        self,
    ) -> None:
        from scripts import utility_ex_security as security

        key = bytes(range(16))
        seed = bytes.fromhex("00112233445566778899aabbccddeeff")
        cipher = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

        def setup(capability: int) -> list[tuple[int, bytes]]:
            return [
                (0, bytes.fromhex(x))
                for x in ("500100000000", "500300000000", "62024000018000", "62025080")
            ] + [(0, bytes((0x62, 2, 0x51, capability)))]

        for source in (SHA_18_TY, SHA_PLUS_TY):
            c = Context(
                source,
                [(0, bytes.fromhex("62025000"))]
                + setup(2)
                + [(0, b"\x67\x01" + seed), (0, b"\x67\x02")],
            )
            other = Comm(
                setup(4)
                + [
                    (0, b"\x67\x07" + seed),
                    (0, b"\x67\x08"),
                    (0, bytes.fromhex("71010200")),
                ]
            )
            other_name = "native:1011a220" if source == SHA_18_TY else "native:1013d6a8"
            c.communications[other_name] = other
            image = bytearray(0x100200)
            struct.pack_into("<I", image, 0x3C, 0x80)
            struct.pack_into("<H", image, 0x86, 1)
            struct.pack_into("<IIII", image, 0xA0, 0x100000, 0, 0x100000, 0x200)
            for operands in (ms2._ABS04_KEYS[source], security._PRELIMINARY[source]):
                offset = 0
                for rva, width in operands:
                    image[0x200 + rva : 0x200 + rva + width] = key[
                        offset : offset + width
                    ]
                    offset += width
            c.module_bytes = bytes(image)
            with patch(
                "scripts.utility_ex_security.hashlib.sha256",
                return_value=SimpleNamespace(
                    hexdigest=lambda selected=source: selected
                ),
            ):
                self.assertEqual(call("Ex2MS2ABS_04_SendMessage", c, data(2)), 0)
            self.assertIn(b"\x27\x02" + cipher, c.communication.calls)
            self.assertIn(b"\x27\x08" + cipher, other.calls)
            self.assertIn(bytes.fromhex("31010200"), other.calls)
            self.assertNotIn(bytes.fromhex("31010200"), c.communication.calls)
            self.assertEqual(c.communication.calls[-1], "finalize")
            self.assertEqual(other.calls[-1], "finalize")
            self.assertFalse(other.replies)
            self.assertFalse(c.communication.replies)

    def test_abs04_native_status_boundaries_and_dual_cleanup(self) -> None:
        for value, expected in ((0, 0), (1, 2000), (10, 2000), (11, 99), (255, 99)):
            c = Context(replies=[(0, bytes.fromhex("621086") + bytes([value]))])
            other = Comm()
            c.communications["native:1011a220"] = other
            self.assertEqual(call("Ex2MS2ABS_04_SendMessage", c, data(1)), expected)
            self.assertEqual(other.calls[-1], "finalize")
            self.assertIn(("configure_target", 0x763, 0, 0, 0, 0), other.calls)

    def test_at01_resume_literal_custom_routine_and_pending(self) -> None:
        for source in (SHA_18_TY, SHA_PLUS_TY):
            c = Context(
                source,
                [
                    (0, bytes.fromhex(x))
                    for x in ("7101ff00", "7103ff000001", "7103ff000002")
                ],
            )
            other = Comm()
            c.communications[
                "native:1011a220" if source == SHA_18_TY else "native:1013d6a8"
            ] = other
            self.assertEqual(call("Ex2MS2AT_01_SendMessage", c, data(1)), 0)
            self.assertEqual(
                [x for x in c.communication.calls if isinstance(x, bytes)],
                [
                    bytes.fromhex("3101ff000001"),
                    bytes.fromhex("3103ff00"),
                    bytes.fromhex("3103ff00"),
                ],
            )
            self.assertEqual(other.calls[-1], "finalize")

    def test_at01_native_failure_retains_both_managers(self) -> None:
        c = Context(replies=[(7, bytes.fromhex("7f3131"))])
        other = Comm()
        c.communications["native:1011a220"] = other
        self.assertEqual(call("Ex2MS2AT_01_SendMessage", c, data(1)), 2002)
        self.assertNotIn("finalize", c.communication.calls)
        self.assertNotIn("finalize", other.calls)
        self.assertEqual(c.state, {})

    def test_rab02_source_specific_control_offset_and_five_word_packet(self) -> None:
        for source, size in ((SHA_18_TY, 0x7F8), (SHA_PLUS_TY, 0xA00)):
            c = Context(
                source,
                [
                    (0, bytes.fromhex("62101e1234")),
                    (0, bytes.fromhex("6210a7000110a8000210a9000310aa000410ab0005")),
                ],
            )
            argument = bytearray(size)
            argument[-4:] = (1).to_bytes(4, "little")
            self.assertEqual(call("Ex2MS2RAB_02_SendMessage", c, argument), 0)
            self.assertEqual(
                [
                    int.from_bytes(argument[i : i + 4], "little")
                    for i in range(4, 28, 4)
                ],
                [0x1234, 1, 2, 3, 4, 5],
            )
            self.assertIn(
                bytes.fromhex("2210a710a810a910aa10ab"), c.communication.calls
            )

    def test_rab02_typed_record_and_native_zero_padded_copy(self) -> None:
        c = Context(replies=[(0, bytes.fromhex("6210ac") + b"x" * (0x5CE - 3))])
        argument = bytearray(0x7F8)
        argument[-4:] = (2).to_bytes(4, "little")
        selected = ms2.MS2RAB02Message(argument, 0x10010AC, SHA_18_TY)
        self.assertEqual(call("Ex2MS2RAB_02_SendMessage", c, selected), 0)
        self.assertEqual(argument[28 : 28 + 0x5CE], b"x" * (0x5CE - 3) + bytes(3))
        self.assertIn(bytes.fromhex("2210ac"), c.communication.calls)
        c = Context()
        with self.assertRaises(ValueError):
            call("Ex2MS2RAB_02_SendMessage", c, argument)
        self.assertEqual(c.selected, [])

    def test_efi03_start_result_states_and_native_retention(self) -> None:
        for result, expected, retain in (
            (0, 1007, True),
            (1, 1007, True),
            (2, 0, False),
            (16, 1011, True),
            (0x3010, 1010, True),
            (0x3011, 1012, True),
            (3, 3, False),
        ):
            replies = [
                (0, bytes.fromhex("71018011")),
                (0, bytes.fromhex("71038011") + result.to_bytes(2, "big")),
            ]
            if result == 2:
                replies.append((0, bytes.fromhex("71028011")))
            c = Context(replies=replies)
            argument = data(0, 8)
            argument[4:] = (2).to_bytes(4, "little")
            self.assertEqual(call("Ex2MS2EFI_03_SendMessage", c, argument), expected)
            self.assertEqual("finalize" in c.communication.calls, not retain)

    def test_efi03_live_stop_flag_and_discriminator(self) -> None:
        c = Context(replies=[(0, bytes.fromhex("710380110001"))])
        argument = data(0, 8)
        argument[4:] = (3).to_bytes(4, "little")
        c.on_sleep = lambda: argument.__setitem__(
            slice(0, 4), (1).to_bytes(4, "little")
        )
        self.assertEqual(call("Ex2MS2EFI_03_SendMessage", c, argument), 1005)
        self.assertNotIn("finalize", c.communication.calls)
        self.assertEqual(c.sleeps, [1])
        for value, expected in ((0, 1001), (1, 0), (4, 0), (5, 1004), (6, 3)):
            c = Context(replies=[(0, bytes.fromhex("6213d8") + bytes([value]))])
            argument = data(0, 8)
            argument[4:] = (1).to_bytes(4, "little")
            self.assertEqual(call("Ex2MS2EFI_03_SendMessage", c, argument), expected)

    def test_efi05_native_record_widths_and_retained_write_stage(self) -> None:
        for source in (SHA_18_TY, SHA_PLUS_TY):
            c = Context(
                source, [(0, bytes.fromhex(x)) for x in ("6e13d2", "6e13d3", "6e13e4")]
            )
            argument = data(2, 0x84 + 40)
            for offset, identifier, width, value in (
                (0x84, 0x13D2, 1, 0x123456),
                (0x90, 0x13D3, 2, 0x123456),
                (0x9C, 0x13E4, 3, 0x123456),
            ):
                struct.pack_into("<III", argument, offset, identifier, width, value)
            self.assertEqual(call("Ex2MS2EFI_05_SendMessage", c, argument), 0)
            self.assertEqual(
                [x for x in c.communication.calls if isinstance(x, bytes)],
                [
                    bytes.fromhex("2e13d256"),
                    bytes.fromhex("2e13d33456"),
                    bytes.fromhex("2e13e4123456"),
                ],
            )
            self.assertNotIn("finalize", c.communication.calls)

    def test_efi05_unterminated_native_list_fails_before_manager(self) -> None:
        c = Context()
        argument = data(2, 0x84 + 12)
        struct.pack_into("<III", argument, 0x84, 0x13D2, 1, 1)
        with self.assertRaises(ValueError):
            call("Ex2MS2EFI_05_SendMessage", c, argument)
        self.assertEqual(c.selected, [])

    def test_efi06_obd_vin_read_and_comparison_counter(self) -> None:
        vin = b"0123456789ABCDEFG"
        c = Context(
            replies=[
                (0, bytes.fromhex("4100")),
                (0, bytes.fromhex("490040000000")),
                (0, bytes.fromhex("490201") + vin),
            ]
        )
        argument = data(1, 24)
        self.assertEqual(call("Ex2MS2EFI_06_SendMessage", c, argument), 0)
        self.assertEqual(argument[6:24], vin + b"\0")
        self.assertIn(("select_diagnostic_mode", 3), c.communication.calls)
        self.assertIn(("configure_target", 0x7DF, 0, 0, 0, 0), c.communication.calls)
        for counter, expected in ((0, 1003), (1, 1003), (2, 1010), (255, 1003)):
            c = Context(
                replies=[(0, bytes.fromhex("4100")), (0, bytes.fromhex("490201") + vin)]
            )
            argument = data(5, 24)
            argument[5] = counter
            self.assertEqual(call("Ex2MS2EFI_06_SendMessage", c, argument), expected)
            self.assertEqual(argument[5], (counter + 1) & 255)

    def test_efi06_did_mask_and_required_native_target(self) -> None:
        c = Context(replies=[(0, bytes.fromhex("620228ff"))])
        argument = data(2, 24)
        self.assertEqual(call("Ex2MS2EFI_06_SendMessage", c, argument), 0)
        self.assertEqual(argument[4], 0x60)
        c = Context()
        with self.assertRaises(TYSourceError):
            call("Ex2MS2EFI_06_SendMessage", c, data(0))
        self.assertEqual(c.communication.calls[-1], "finalize")

    def test_sas03_dtc_prefix_guard_and_report_copy(self) -> None:
        for prefix, expected in (
            (0x978C, 1018),
            (0x9796, 1018),
            (0x9783, 0),
            (0x1234, 0),
        ):
            report = bytes.fromhex("590202") + prefix.to_bytes(2, "big") + bytes((0, 1))
            c = Context(
                replies=[
                    (0, bytes.fromhex("500100000000")),
                    (0, bytes.fromhex("500300000000")),
                    (0, report),
                    (0, bytes.fromhex("500100000000")),
                ]
            )
            argument = bytearray(0x103C)
            struct.pack_into("<I", argument, 0x1038, 1)
            self.assertEqual(call("Ex2MS2SAS_03_SendMessage", c, argument), expected)
            self.assertEqual(argument[: len(report)], report)
            self.assertEqual(c.communication.calls[-1], "finalize")

    def test_sas03_native_signed_measurement_tolerance_and_output(self) -> None:
        for source, control in (
            (SHA_18_TY, "host:x87_control_word"),
            (SHA_PLUS_TY, "host:mxcsr"),
        ):
            for raw, expected in ((-2500, 0), (2500, 0), (-2501, 1014), (2501, 1014)):
                c = Context(
                    source,
                    [
                        (
                            0,
                            bytes.fromhex("621054")
                            + raw.to_bytes(4, "big", signed=True),
                        )
                    ],
                )
                c.state[control] = 0x37F if source == SHA_18_TY else 0x1F80
                argument = bytearray(0x103C)
                struct.pack_into("<I", argument, 0x1038, 3)
                self.assertEqual(
                    call("Ex2MS2SAS_03_SendMessage", c, argument), expected
                )
                self.assertEqual(
                    struct.unpack_from("<d", argument, 0x1028)[0], raw * 0.001
                )

    def test_ig01_typed_record_stop_allows_zero_padded_echo_quirk(self) -> None:
        for source in (SHA_18_TY, SHA_PLUS_TY):
            c = Context(source, [(0, bytes.fromhex("6f3022"))])
            argument = bytearray(44)
            struct.pack_into("<I", argument, 40, 3)
            selected = ms2.MS2IG01Message(argument, 0x3022, source)
            self.assertEqual(call("Ex2MS2IG_01_SendMessage", c, selected), 0)
            self.assertIn(bytes.fromhex("2f302200"), c.communication.calls)
            self.assertEqual(c.communication.calls[-1], "finalize")

    def test_ig01_mutable_stop_observation_retains_session(self) -> None:
        c = Context()
        argument = bytearray(44)
        struct.pack_into("<I", argument, 40, 2)
        c.on_sleep = lambda: struct.pack_into("<I", argument, 36, 1)
        selected = ms2.MS2IG01Message(argument, 0x3022, SHA_18_TY)
        self.assertEqual(call("Ex2MS2IG_01_SendMessage", c, selected), 0)
        self.assertEqual(c.sleeps, [200])
        self.assertNotIn("finalize", c.communication.calls)
        with self.assertRaises(ValueError):
            call("Ex2MS2IG_01_SendMessage", Context(), argument)

    def test_abs02_start_poll_delay_and_error_mapping(self) -> None:
        c = Context(
            replies=[(0, bytes.fromhex("71010204")), (0, bytes.fromhex("710302040002"))]
        )
        self.assertEqual(call("Ex2MS2ABS_02_SendMessage", c, data(0)), 0)
        self.assertEqual(call("Ex2MS2ABS_02_SendMessage", c, data(2)), 0)
        self.assertEqual(c.sleeps, [3200])
        c = Context()
        c.communication.session_status = 7
        c.communication.field = 0x69
        self.assertEqual(call("Ex2MS2ABS_02_SendMessage", c, data(0)), 2000)
        self.assertEqual(c.communication.calls[-1], "finalize")

    def test_abs03_value_ranges(self) -> None:
        for reply, expected in (
            ("621029000d", 2000),
            ("621029fff3", 2000),
            ("621029000c", 0),
        ):
            c = Context(
                replies=[
                    (0, bytes.fromhex(reply)),
                    (0, bytes.fromhex("62102d11")),
                    (0, bytes.fromhex("62102cef")),
                ]
            )
            self.assertEqual(call("Ex2MS2ABS_03_SendMessage", c, data(1)), expected)
            self.assertEqual("finalize" in c.communication.calls, expected != 0)

    def test_abs05_nonmatching_nrc_and_native_errors(self) -> None:
        c = Context()
        c.communication.session_status = 7
        self.assertEqual(call("Ex2MS2ABS_05_SendMessage", c, data(0)), 2002)
        c = Context(replies=[(5, b"")])
        self.assertEqual(call("Ex2MS2ABS_05_SendMessage", c, data(0)), 2001)

    def test_efi01_support_bitmap_partial_support_and_output(self) -> None:
        c = Context(
            replies=[
                (0, bytes.fromhex(x))
                for x in (
                    "62100000000001",
                    "62102040000001",
                    "62104000000001",
                    "62106080000000",
                )
            ]
        )
        argument = bytearray(0x4094)
        self.assertEqual(call("Ex2MS2EFI_01_SendMessage", c, argument), 0)
        self.assertEqual(
            argument[:16], bytes.fromhex("00000001400000010000000180000000")
        )
        self.assertEqual(c.communication.calls[-1], "finalize")

    def test_efi01_read_selected_blocks_preserves_unvisited_outputs_on_failure(
        self,
    ) -> None:
        c = Context(
            replies=[
                (0, bytes.fromhex("621022ff")),
                (0, bytes.fromhex("6210610102030405")),
                (5, b""),
            ]
        )
        argument = bytearray(b"x" * 0x4094)
        argument[:16] = bytes.fromhex("000000004000000000000000a0000000")
        argument[0x4090:0x4094] = (1).to_bytes(4, "little")
        self.assertEqual(call("Ex2MS2EFI_01_SendMessage", c, argument), 5)
        self.assertEqual(argument[16:24], bytes.fromhex("6210610102030405"))
        self.assertEqual(argument[16 + 0x1020 : 16 + 3 * 0x1020], bytes(2 * 0x1020))
        self.assertEqual(argument[16 + 3 * 0x1020 : 0x4090], b"x" * 0x1020)
        self.assertEqual(c.communication.calls[-1], "finalize")

    def test_efi01_state_discriminator_and_short_reply(self) -> None:
        for reply, expected in (("62102200", 1000), ("62102201", 3), ("621022", 3)):
            c = Context(replies=[(0, bytes.fromhex(reply))])
            argument = bytearray(0x4094)
            argument[0x4090:0x4094] = (1).to_bytes(4, "little")
            self.assertEqual(call("Ex2MS2EFI_01_SendMessage", c, argument), expected)

    def test_efi04_sparse_compact_values_and_native_widths(self) -> None:
        for source in (SHA_18_TY, SHA_PLUS_TY):
            c = Context(
                source,
                [(0, bytes.fromhex("6213d912")), (0, bytes.fromhex("6213e4123456"))],
            )
            argument = bytearray(0xE4)
            for pid in (0x13D9, 0x13E4):
                argument[((pid & 0xFFF) - 1) >> 3] |= 0x80 >> ((pid - 1) & 7)
            argument[0xE0:0xE4] = (1).to_bytes(4, "little")
            self.assertEqual(call("Ex2MS2EFI_04_SendMessage", c, argument), 0)
            self.assertEqual(
                argument[0x80:0x90], bytes.fromhex("d913000012000000e413000056341200")
            )
            self.assertEqual(argument[0x90:0xE0], bytes(0x50))
            self.assertEqual(c.communication.calls[-1], "finalize")

    def test_efi04_unsupported_map_and_native_error(self) -> None:
        c = Context(replies=[(0, bytes.fromhex("62100000000000"))])
        self.assertEqual(call("Ex2MS2EFI_04_SendMessage", c, bytearray(0xE4)), 1000)
        c = Context(replies=[(5, b"")])
        self.assertEqual(call("Ex2MS2EFI_04_SendMessage", c, bytearray(0xE4)), 5)

    def test_rab01_three_paired_records_and_tail_output(self) -> None:
        for source in (SHA_18_TY, SHA_PLUS_TY):
            c = Context(
                source,
                [
                    (0, bytes.fromhex(x))
                    for x in (
                        "6210a101",
                        "6210a21234",
                        "6210a300",
                        "6210a509",
                        "6210a6abcd",
                        "62101efffe",
                    )
                ],
            )
            argument = bytearray(b"x" * 36)
            argument[32:36] = (1).to_bytes(4, "little")
            self.assertEqual(call("Ex2MS2RAB_01_SendMessage", c, argument), 0)
            self.assertEqual(
                [
                    int.from_bytes(argument[i : i + 4], "little")
                    for i in range(0, 32, 4)
                ],
                [1, 0x1234, 0, 0, 9, 0xABCD, 0, 0xFFFE],
            )
            self.assertEqual(c.communication.calls[-1], "finalize")

    def test_rab01_empty_records_and_native_failure(self) -> None:
        c = Context(
            replies=[
                (0, bytes.fromhex(x)) for x in ("6210a100", "6210a300", "6210a500")
            ]
        )
        argument = bytearray(36)
        argument[32:36] = (1).to_bytes(4, "little")
        self.assertEqual(call("Ex2MS2RAB_01_SendMessage", c, argument), 1004)
        c = Context(replies=[(7, bytes.fromhex("7f2231"))])
        self.assertEqual(call("Ex2MS2RAB_01_SendMessage", c, bytearray(36)), 7)
        self.assertEqual(c.sleeps, [0])

    def test_bdy_read_failure_publishes_literal_55_and_continues(self) -> None:
        c = Context(
            replies=[(7, bytes.fromhex("7f2231")), (0, bytes.fromhex("62200112"))]
        )
        argument = data(2, 100)
        argument[4] = 1
        argument[4 + 30] = 1
        self.assertEqual(call("Ex2MS2BDY_01_SendMessage", c, argument), 0)
        self.assertEqual(argument[51], 0x55)
        self.assertEqual(argument[51 + 30], 0x12)
        self.assertEqual(c.communication.calls[-1], "finalize")

    def test_bdy_write_then_refresh_and_invalid_selection(self) -> None:
        c = Context(
            SHA_PLUS_TY, [(0, bytes.fromhex("6e2018")), (0, bytes.fromhex("6220180a"))]
        )
        argument = data(1, 100)
        argument[4 + 46] = 1
        argument[98:100] = bytes((46, 0x0A))
        self.assertEqual(call("Ex2MS2BDY_01_SendMessage", c, argument), 0)
        self.assertEqual(
            [x for x in c.communication.calls if isinstance(x, bytes)],
            [bytes.fromhex("2e20180a"), bytes.fromhex("222018")],
        )
        self.assertEqual(argument[97], 10)
        c = Context()
        argument[98] = 47
        with self.assertRaises(ValueError):
            call("Ex2MS2BDY_01_SendMessage", c, argument)
        self.assertEqual(c.selected, [])

    def test_bdy_support_failure_maps_2000_without_clobbering_ui_mask(self) -> None:
        c = Context(replies=[(5, b"")])
        argument = data(0, 100)
        argument[4:51] = b"x" * 47
        self.assertEqual(call("Ex2MS2BDY_01_SendMessage", c, argument), 2000)
        self.assertEqual(argument[4:51], b"x" * 47)

    def test_sas02_vin_exact_length_and_distinct_output_offset(self) -> None:
        for source in (SHA_18_TY, SHA_PLUS_TY):
            for status_byte, expected in ((0, 0), (255, 0), (1, 3)):
                c = Context(
                    source,
                    [
                        (0, bytes.fromhex("62f190") + b"0123456789ABCDEFG"),
                        (0, bytes.fromhex("62105e") + bytes([status_byte])),
                    ],
                )
                argument = data(1, 23)
                argument[21:23] = b"xy"
                self.assertEqual(
                    call("Ex2MS2SAS_02_SendMessage", c, argument), expected
                )
                self.assertEqual(argument[4:21], b"0123456789ABCDEFG")
                self.assertEqual(argument[21], ord("x"))
                self.assertEqual(
                    argument[22], status_byte if not expected else ord("y")
                )
                self.assertEqual(c.communication.calls[-1], "finalize")

    def test_sas02_long_vin_rejected_before_output_or_next_request(self) -> None:
        c = Context(replies=[(0, bytes.fromhex("62f190") + b"0123456789ABCDEFGx")])
        argument = data(1, 23)
        argument[4:] = b"x" * 19
        self.assertEqual(call("Ex2MS2SAS_02_SendMessage", c, argument), 3)
        self.assertEqual(argument[4:], b"x" * 19)

    def test_met01_native_a000_support_and_record_layout(self) -> None:
        for source in (SHA_18_TY, SHA_PLUS_TY):
            c = Context(
                source,
                [
                    (0, bytes.fromhex(x))
                    for x in (
                        "62a00040000001",
                        "62a02001000000",
                        "62a00212",
                        "62a02834",
                    )
                ],
            )
            argument = bytearray(0x18C)
            self.assertEqual(call("Ex2MS2MET_01_SendMessage", c, argument), 0)
            self.assertEqual(
                argument[:24],
                bytes.fromhex("02a00000120000000100000028a000003400000001000000"),
            )
            self.assertEqual(int.from_bytes(argument[0x180:0x184], "little"), 2)
            self.assertEqual(int.from_bytes(argument[0x184:0x188], "little"), 1)
            self.assertEqual(
                [x for x in c.communication.calls if isinstance(x, bytes)][:2],
                [bytes.fromhex("22a000"), bytes.fromhex("22a020")],
            )

    def test_met01_existing_record_bound_and_native_error(self) -> None:
        c = Context(replies=[(5, b"")])
        self.assertEqual(call("Ex2MS2MET_01_SendMessage", c, bytearray(0x18C)), 1000)
        c = Context()
        argument = bytearray(0x18C)
        argument[0x180:0x184] = (33).to_bytes(4, "little")
        with self.assertRaises(ValueError):
            call("Ex2MS2MET_01_SendMessage", c, argument)
        self.assertEqual(c.selected, [])

    def test_tpw_selected_read_copies_actual_native_bytes(self) -> None:
        for source, setter in (
            (SHA_18_TY, "native_rva:12180"),
            (SHA_PLUS_TY, "native_rva:142f0"),
        ):
            c = Context(source, [(0, bytes.fromhex("61061234"))])
            argument = data(0, 6)
            self.assertEqual(call("Ex2MS2TPW_01_SendMessage", c, argument), 0)
            self.assertEqual(argument[4:6], bytes.fromhex("1234"))
            self.assertEqual(c.selected, ["selected"])
            self.assertIn(("configure", setter, 150), c.communication.calls)
            self.assertEqual(c.communication.calls[-1], "finalize")

    def test_tpw_five_ids_exact_native_gaps_and_control(self) -> None:
        c = Context(SHA_PLUS_TY, [(0, bytes.fromhex("7b0e"))])
        argument = data(1, 36)
        argument[8:12] = (5).to_bytes(4, "little")
        argument[12:16] = (1).to_bytes(4, "little")
        argument[16:36] = bytes(range(1, 21))
        self.assertEqual(call("Ex2MS2TPW_01_SendMessage", c, argument), 0)
        expected = bytes.fromhex(
            "3b0e00050000010203040000050607080000090a0b0c00000d0e0f10000011121314"
        )
        self.assertIn(expected, c.communication.calls)
        self.assertEqual(c.communication.calls[-1], "finalize")

    def test_tpw_native_error_and_host_fault_preserve_exception_type(self) -> None:
        c = Context(replies=[(7, bytes.fromhex("7f2131"))])
        self.assertEqual(call("Ex2MS2TPW_01_SendMessage", c, data(0, 6)), 7)
        self.assertEqual(c.sleeps, [])
        self.assertEqual(c.state, {})
        c = Context()
        c.communication.fault = True
        with self.assertRaises(OSError):
            call("Ex2MS2TPW_01_SendMessage", c, data(0, 6))
        self.assertEqual(c.communication.calls[-1], "finalize")

    def test_dcm02_exact_setting_write_refresh_and_mapping(self) -> None:
        for source in (SHA_18_TY, SHA_PLUS_TY):
            for replies, expected in (
                ([(0, bytes.fromhex("6e10e5")), (0, bytes.fromhex("62103207"))], 0),
                ([(7, bytes.fromhex("7f2e31"))], 2000),
                ([(0, bytes.fromhex("6e10e5")), (5, b"")], 2001),
            ):
                c = Context(source, replies)
                argument = data(2, 6)
                argument[4:6] = bytes((3, 9))
                self.assertEqual(
                    call("Ex2MS2DCM_02_SendMessage", c, argument), expected
                )
                self.assertIn(bytes.fromhex("2e10e503"), c.communication.calls)
                self.assertEqual(argument[5], 7 if expected == 0 else 9)
                self.assertEqual(c.communication.calls[-1], "finalize")
                self.assertEqual(
                    sum(
                        isinstance(x, tuple) and x[0] == "session" and x[1] == 1
                        for x in c.communication.calls
                    ),
                    2,
                )

    def test_dcm02_read_preserves_adjacent_input(self) -> None:
        c = Context(replies=[(0, bytes.fromhex("621032ff"))])
        argument = data(1, 6)
        argument[4] = 0x42
        self.assertEqual(call("Ex2MS2DCM_02_SendMessage", c, argument), 0)
        self.assertEqual(argument[4:], bytes((0x42, 255)))

    def test_efi02_literal_poll_and_terminal_status(self) -> None:
        for source in (SHA_18_TY, SHA_PLUS_TY):
            for result, expected in ((2, 0), (16, 1000), (3, 3)):
                c = Context(
                    source,
                    [
                        (0, bytes.fromhex("71018010")),
                        (0, bytes.fromhex("710380100000")),
                        (0, bytes.fromhex("710380100001")),
                        (0, bytes.fromhex("71038010") + result.to_bytes(2, "big")),
                    ],
                )
                self.assertEqual(
                    ms2.run_body("Ex2MS2EFI_02_SendMessage", (), cast(TYContext, c)),
                    expected,
                )
                self.assertEqual(
                    [x for x in c.communication.calls if isinstance(x, bytes)],
                    [bytes.fromhex("31018010")] + [bytes.fromhex("31038010")] * 3,
                )
                self.assertEqual(c.communication.calls[-1], "finalize")

    def test_efi02_cleanup_overrides_business_error(self) -> None:
        c = Context(replies=[(7, bytes.fromhex("7f3131"))])
        original = c.communication.exchange

        def exchange(request: bytes) -> tuple[int, bytes]:
            value = original(request)
            c.communication.session_status = 17
            return value

        c.communication.exchange = exchange
        self.assertEqual(
            ms2.run_body("Ex2MS2EFI_02_SendMessage", (), cast(TYContext, c)), 17
        )
        self.assertEqual(c.sleeps, [])
        self.assertEqual(c.communication.calls[-1], "finalize")

    def test_pwd_literal_payload_difference_and_pending_poll(self) -> None:
        for operation, request in (("01", "3101ff000000"), ("02", "3101ff000002")):
            for source in (SHA_18_TY, SHA_PLUS_TY):
                c = Context(
                    source,
                    [
                        (0, bytes.fromhex("7101ff00")),
                        (0, bytes.fromhex("7103ff000001")),
                        (0, bytes.fromhex("7103ff000002")),
                    ],
                )
                self.assertEqual(
                    call(f"Ex2MS2PWD_{operation}_SendMessage", c, data(0)), 0
                )
                self.assertEqual(
                    [x for x in c.communication.calls if isinstance(x, bytes)],
                    [
                        bytes.fromhex(request),
                        bytes.fromhex("3103ff00"),
                        bytes.fromhex("3103ff00"),
                    ],
                )
                self.assertEqual(c.communication.calls[-1], "finalize")

    def test_pwd_initial_failure_retains_and_poll_other_error_cleans(self) -> None:
        for replies, expected, retain in (
            ([(7, bytes.fromhex("7f3131"))], 1002, True),
            ([(0, bytes.fromhex("7101ff00")), (5, b"")], 1002, True),
            ([(0, bytes.fromhex("7101ff00")), (3, b"")], 1001, False),
            (
                [(0, bytes.fromhex("7101ff00")), (0, bytes.fromhex("7103ff000003"))],
                1001,
                False,
            ),
        ):
            c = Context(replies=replies)
            self.assertEqual(call("Ex2MS2PWD_01_SendMessage", c, data(1)), expected)
            self.assertEqual("finalize" in c.communication.calls, not retain)

    def test_pwd_cancel_and_host_fault_cleanup(self) -> None:
        c = Context()
        c.cancel = True
        with self.assertRaises(Cancelled):
            call("Ex2MS2PWD_01_SendMessage", c, data(0))
        self.assertEqual(c.communication.calls, [])
        c = Context()
        c.communication.fault = True
        with self.assertRaises(OSError):
            call("Ex2MS2PWD_01_SendMessage", c, data(0))
        self.assertEqual(c.communication.calls[-1], "finalize")

    def test_pwd_abort_and_initialize_error(self) -> None:
        c = Context()
        self.assertEqual(call("Ex2MS2PWD_02_SendMessage", c, data(5)), 1003)
        c = Context()
        c.communication.init_status = 17
        self.assertEqual(call("Ex2MS2PWD_02_SendMessage", c, data(0)), 17)
        self.assertEqual(c.communication.calls, [("initialize", 0), "finalize"])

    def test_gwy_read_status_and_nrc_output(self) -> None:
        for status, reply, expected, output in (
            (0, "62103b12", 1000, 0),
            (7, "7f2231", 7, 0x31),
            (5, "", 5, 0x78),
            (0, "62103c12", 3, 0),
        ):
            c = Context(replies=[(status, bytes.fromhex(reply))])
            argument = data(1)
            self.assertEqual(call("Ex2MS2GWY_01_SendMessage", c, argument), expected)
            self.assertEqual(int.from_bytes(argument[8:12], "little"), output)
            self.assertEqual(c.communication.calls[-1], "finalize")

    def test_gwy_start_session_timing_and_retention(self) -> None:
        c = Context(
            replies=[
                (0, bytes.fromhex("500100000000")),
                (0, bytes.fromhex("500300000000")),
                (0, bytes.fromhex("7101020c")),
            ]
        )
        self.assertEqual(call("Ex2MS2GWY_01_SendMessage", c, data(2)), 2000)
        self.assertIn(("keepalive", True, True), c.communication.calls)
        self.assertNotIn("finalize", c.communication.calls)
        self.assertIn(("configure", "native_1064", 4), c.communication.calls)

    def test_gwy_session_timing_precedes_length_and_echo_validation(self) -> None:
        c = Context(replies=[(0, bytes.fromhex("500100000000")), (0, b"x")])
        c.communication.timing_status = 17
        self.assertEqual(call("Ex2MS2GWY_01_SendMessage", c, data(2)), 17)
        self.assertIn(("keepalive", True, True), c.communication.calls)

    def test_gwy_delayed_restore_ignores_native_status(self) -> None:
        c = Context(replies=[(7, bytes.fromhex("7f1031"))])
        self.assertEqual(call("Ex2MS2GWY_01_SendMessage", c, data(3)), 3000)
        self.assertEqual(c.sleeps, [5000, 0])
        self.assertNotIn(("initialize", 0), c.communication.calls)


if __name__ == "__main__":
    unittest.main()
