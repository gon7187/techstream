"""Authored wire/status controls and exact supplied source identity checks."""

import hashlib
import math
import struct
import unittest
from collections.abc import Callable, Iterator
from pathlib import Path
from unittest.mock import patch

from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import TYSourceError
from scripts.utility_ex_ty_powertrain import (
    _ECT_MEMORY,
    _ECT_ROUTINES,
    _EFI55_TABLES,
    AMT_HISTORY_READ,
    AMT_HISTORY_SUPPORT,
    AMT_HISTORY_WRITE,
    ASG_INITIAL,
    ASG_STATUS,
    ASG_STATUS_004,
    ASG_STATUS_TIMEOUT,
    ECD_ASH_CLEAR,
    ECD_CHAR,
    ECD_DUMMY59,
    ECD_DUMMY60,
    ECD_HEX,
    ECD_RESET55,
    ECO_STARTS_RESET,
    EFI52_SWITCH,
    EFI53_ROUTINE,
    EFI59_ROUTINE,
    EFI61_SUPPORT,
    EFI61_WRITE,
    EFI62_VALUES,
    EFI_FREQUENCY_READ,
    EFI_FREQUENCY_WRITE,
    EFI_LEARNING_RESET,
    EFI_PM_READ,
    EFI_PM_RESULT,
    EFI_PM_START,
    EFI_PM_STOP,
    EFI_PM_SUPPORT,
    EFI_PM_WAIT_STOP,
    EFI_SESSION_TRANSITION,
    EFI_THROTTLE_LEARN,
    HNSCR_ADJUST,
    HNSCR_RESET,
    HV10_JUDGE,
    HV10_READ,
    HV10_SUPPORT,
    HV10_WAIT,
    HV12_AFTER,
    HV12_DTC_STATUS,
    HV12_SUPPORT,
    HV12_UPDATE,
    HV14_SUPPORT,
    HV14_TEMPERATURE,
    HV14_VOLTAGE,
    HV_ACCELERATOR,
    HV_ACCELERATOR_CLEAR,
    HV_BATTERY_CLEAR,
    HV_BATTERY_RESET,
    HV_BATTERY_WRITE,
    HV_HISTORY_READ,
    HV_HISTORY_RESET,
    HV_READY_CANCEL,
    HV_SERVICE,
    PSA_ECD_RESET,
    PSA_EFI_RESET,
    PSA_TRANSMITTER,
    PSA_VALVE_CHECK,
    PSA_WHEEL_ADDITIONAL,
    PSA_WHEEL_MAIN,
    PSA_WHEEL_READ,
    PSA_WHEEL_READ2,
    SHA_12,
    SHA_18,
    SHA_PLUS,
    _amt_history,
    _amt_history_support,
    _asg_learned_flag,
    _asg_learning,
    _asg_support,
    _char_to_int,
    _dsg,
    _ecd_reset,
    _ect_bulk,
    _ect_checksum,
    _ect_initialize,
    _ect_memory,
    _ect_prefixed,
    _ect_routine,
    _efi52_switch,
    _efi53_routine,
    _efi55_table,
    _efi59_routine,
    _efi61_values,
    _efi62_values,
    _efi_learning_reset,
    _efi_session_transition,
    _efi_throttle,
    _engine_starts_reset,
    _frequency,
    _hex_to_bytes,
    _hnscr_adjust,
    _hnscr_reset,
    _hv10_selected,
    _hv12_selected,
    _hv14_selected,
    _hv_accelerator,
    _hv_battery_field,
    _hv_history,
    _hv_reset,
    _oil,
    _pm_read,
    _pm_result,
    _pm_start,
    _pm_wait_stop,
    _reset,
    _transmitter,
    _water,
    _wheel_clear,
    _wheel_write,
    direct_exports,
    run_body,
    supported_exports,
)
from tests.private_evidence import require_private


class Context:
    def __init__(self, source=SHA_18, *, status=0, response=b"\x51\0", init_status=0):
        self.module_sha256 = source
        self.module_bytes = b"authored"
        self.mode = 19
        self.state: dict[str, object] = {}
        self.events = []
        self.status, self.response, self.init_status = status, response, init_status
        self.cancelled = False
        self.dtcs: tuple[int, bytes] | None = None
        self.native_error = 0
        self.fault: BaseException | None = None
        self.finalize_fault: BaseException | None = None
        self.replies: Iterator[tuple[int, bytes]] | None = None
        self.sessions: Iterator[int] | None = None
        self.inits: Iterator[int] | None = None
        self.snapshots: Iterator[tuple[int, bytes, tuple[int, ...]]] | None = None

    def comm(self, kind):
        self.events.append(("comm", kind))
        return self

    def is_cancelled(self):
        return self.cancelled

    def initialize(self, mode=0):
        self.events.append(("initialize", mode))
        return next(self.inits) if self.inits is not None else self.init_status

    def configure(self, field, value):
        self.events.append(("configure", field, value))

    def exchange(self, request):
        self.events.append(("exchange", request))
        if self.fault:
            raise self.fault
        return (
            next(self.replies)
            if self.replies is not None
            else (self.status, self.response)
        )

    def cleanup_exchange(self, request: bytes) -> tuple[int, bytes]:
        raise AssertionError("Unexpected cleanup exchange")

    def cleanup_session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int:
        raise AssertionError("Unexpected cleanup session")

    def session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int:
        self.events.append(("session", mode, keepalive, normal_first, stop_on_error))
        return next(self.sessions) if self.sessions is not None else 0

    def sleep(self, ms: int) -> None:
        raise AssertionError("Literal native Sleep must use native_sleep")

    def native_sleep(self, ms: int) -> None:
        self.events.append(("native_sleep", ms))

    def ticks(self) -> int:
        return 0

    def set_parameter(self, key: int, value: int) -> int:
        raise AssertionError("Reset operation must not change broker parameters")

    def write_parameters(self) -> int:
        raise AssertionError("Reset operation must not write broker parameters")

    def refresh_parameters(self) -> None:
        raise AssertionError("Reset operation must not refresh broker parameters")

    def support_snapshot(self, kind: int) -> tuple[int, bytes, tuple[int, ...]]:
        self.events.append(("support_snapshot", kind))
        if self.fault is not None:
            raise self.fault
        if self.snapshots is None:
            raise AssertionError("Unexpected support snapshot")
        return next(self.snapshots)

    def read_field(self, field: str) -> int:
        if field not in ("native_10b0", "native_10a4"):
            raise AssertionError("Unexpected native field read")
        self.events.append(("read_field", field))
        return self.native_error

    def select_target(self, identifier: int, second: int = 0) -> None:
        raise AssertionError("Unexpected target selection")

    def configure_target(
        self,
        first: int,
        second: int = 0,
        third: int = 0,
        fourth: int = 0,
        fifth: int = 0,
    ) -> None:
        raise AssertionError("Unexpected target configuration")

    def select_protocol(self, kind: int) -> int:
        raise AssertionError("Unexpected protocol selection")

    def read_target(self) -> tuple[int, int]:
        raise AssertionError("Unexpected target read")

    def read_dtcs(self, mode: int = 0x80, capacity: int = 0x1000) -> tuple[int, bytes]:
        self.events.append(("read_dtcs", mode, capacity))
        if self.fault is not None:
            raise self.fault
        if self.dtcs is None:
            raise AssertionError("Unexpected DTC read")
        return self.dtcs

    def finalize(self) -> None:
        self.events.append(("finalize",))
        if self.finalize_fault is not None:
            raise self.finalize_fault


class Host:
    def __init__(self, mode: int):
        self.mode, self.elapsed = mode, 0
        self.waits: list[int] = []

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
        return self.elapsed & 0xFFFFFFFF

    def sleep(self, milliseconds: int) -> None:
        self.waits.append(milliseconds)
        self.elapsed += milliseconds


class PowertrainTests(unittest.TestCase):
    def test_cleanup_preserves_operation_error_and_exposes_sole_cleanup_failure_inside_except(
        self,
    ):
        calls = (
            lambda c: _reset(PSA_EFI_RESET, (bytearray(4),), c),
            lambda c: _water((bytearray(5),), c),
            lambda c: _ect_initialize((bytearray(4),), c),
            lambda c: _engine_starts_reset((), c),
            lambda c: _oil(False, (bytearray(4),), c),
            lambda c: _wheel_clear((), c),
            lambda c: _dsg(PSA_WHEEL_READ, (bytearray(20),), c),
            lambda c: _wheel_write(PSA_WHEEL_MAIN, (bytearray(16),), c),
            lambda c: _transmitter((bytearray(9),), c),
            lambda c: _hnscr_reset((), c),
            lambda c: _hnscr_adjust((bytearray(122),), c),
            lambda c: _efi_learning_reset((), c),
            lambda c: _asg_support((bytearray(24),), c),
            lambda c: _amt_history_support((bytearray(148),), c),
            lambda c: _amt_history(False, (bytearray(52),), c),
            lambda c: _asg_learning(ASG_INITIAL, (bytearray(36),), c),
            lambda c: _asg_learned_flag((bytearray(28),), c),
            lambda c: _pm_wait_stop((bytearray(8),), c),
            lambda c: _pm_start((bytearray(1),), c),
            lambda c: _pm_result(EFI_PM_RESULT, (bytearray(16),), c),
            lambda c: _pm_result(EFI_PM_STOP, (), c),
            lambda c: _pm_read(EFI_PM_SUPPORT, (bytearray(19),), c),
            lambda c: _ecd_reset(ECD_RESET55, (), c),
            lambda c: _frequency(False, (bytearray(1),), c),
        )
        for call in calls:
            operation, cleanup = RuntimeError("operation"), OSError("cleanup")
            context = Context()
            context.fault, context.finalize_fault = operation, cleanup
            try:
                call(context)
            except RuntimeError as actual:
                self.assertIs(actual, operation)
            else:
                self.fail("Operation HOST failure was suppressed")
            self.assertEqual(context.events.count(("finalize",)), 1)
        context = Context(init_status=19)
        cleanup = OSError("sole cleanup failure")
        context.finalize_fault = cleanup
        try:
            raise ValueError("unrelated caller exception")
        except ValueError:
            with self.assertRaises(OSError) as caught:
                _reset(PSA_EFI_RESET, (bytearray(1),), context)
        self.assertIs(caught.exception, cleanup)
        context = Context()
        context.cancelled, context.finalize_fault = True, cleanup
        with self.assertRaises(Cancelled):
            _reset(PSA_EFI_RESET, (bytearray(1),), context)
        self.assertEqual(context.events.count(("finalize",)), 1)

    def test_exact_public_hnscr02_support_start_end_variant_sequence(self):
        from scripts.utility_ex import UtilityEx2TY, UtilityExContext

        for source, path in (
            (
                SHA_18,
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll",
            ),
            (
                SHA_PLUS,
                "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll",
            ),
        ):
            if not Path(path).exists():
                self.skipTest("Exact supplied source absent")
            context = UtilityExContext(Path(path).read_bytes(), Host(20), None, None)
            engine = UtilityEx2TY(context)
            control = Context(source)
            control.replies = iter(
                (
                    (0, b"\x62\1\1\0\0\x80"),
                    (0, b"\x62\x10\0" + b"\xff" * 6),
                    (0, b"\x71\1\x11\1x"),
                    (17, b""),
                )
            )
            output = bytearray(122)
            with patch.object(context, "comm", return_value=control):
                for action in (0, 1, 3):
                    output[:4] = action.to_bytes(4, "little")
                    self.assertEqual(engine.invoke(HNSCR_ADJUST, (output,)), 15)
                    self.assertEqual(engine.worker.get_status(), 0)
            self.assertEqual(
                output[14:25],
                bytes(
                    0 if source == SHA_PLUS and index == 6 else 1 for index in range(11)
                ),
            )
            self.assertEqual(control.events.count(("initialize", 0)), 2)
            self.assertEqual(control.events.count(("finalize",)), 2)
            self.assertIn(("exchange", b"\x31\2\x11\1"), control.events)

    def test_hnscr02_all_eight_actions_native_mutation_and_cleanup(self):
        for source in (SHA_18, SHA_PLUS):

            def data(action):
                output = bytearray(b"Z" * 122)
                output[:4] = action.to_bytes(4, "little")
                return output

            context = Context(source)
            context.replies = iter(
                ((0, b"\x62\1\1\0\0\x80"), (0, b"\x62\x10\0" + b"\xff" * 6))
            )
            output = data(0)
            self.assertEqual(_hnscr_adjust((output,), context), 0)
            self.assertEqual(
                output[14:25],
                bytes(
                    0 if source == SHA_PLUS and index == 6 else 1 for index in range(11)
                ),
            )
            self.assertEqual(output[116:122], bytes(6))
            self.assertEqual(context.events[-1], ("finalize",))
            self.assertIn(("session", 1, 1, False, True), context.events)
            context = Context(response=b"\x71\1\x11\1x")
            output = data(1)
            self.assertEqual(_hnscr_adjust((output,), context), 0)
            self.assertEqual(output[14:25], b"Z" * 11)
            self.assertNotIn(("finalize",), context.events)
            self.assertIn(("native_sleep", 30), context.events)
            for action, low in ((3, 1), (6, 2)):
                context = Context(status=19)
                self.assertEqual(_hnscr_adjust((data(action),), context), 0)
                self.assertIn(("exchange", bytes((0x31, 2, 0x11, low))), context.events)
                self.assertEqual(context.events[-1], ("finalize",))
            for selector, payload in (
                (0, b"\0\x48\2\x21"),
                (1, b"\1\x68\0\xda"),
                (2, b"\x09\xd8\0\x4e"),
                (3, bytes(4)),
            ):
                context = Context(source)
                context.replies = iter(
                    ((0, b"\x71\3\x11\1\0\x12\x34"), (0, b"\x71\1\x11\2x"))
                )
                output = data(4)
                output[8:12] = selector.to_bytes(4, "little")
                self.assertEqual(_hnscr_adjust((output,), context), 0)
                self.assertIn(("exchange", b"\x31\1\x11\2" + payload), context.events)
                self.assertNotIn(("finalize",), context.events)
            for action, low in ((4, 1), (7, 2)):
                context = Context(response=bytes((0x71, 3, 0x11, low, 1, 0x12, 0x34)))
                output = data(action)
                self.assertEqual(_hnscr_adjust((output,), context), 1001)
                self.assertEqual(output[120:122], b"\x34\x12")
                self.assertEqual(context.events[-1], ("finalize",))
            self.assertEqual(
                _hnscr_adjust((bytearray((99, 0, 0, 0)),), Context(source)), 0
            )

    def test_hnscr02_poll_order_one_two_byte_values_ready_and_cancel(self):
        for source in (SHA_18, SHA_PLUS):
            for action, marker in ((2, 0x80), (5, 0x40)):
                output = bytearray(122)
                output[:4] = action.to_bytes(4, "little")
                output[14:25] = b"\1" * 11
                indexes = [
                    index
                    for index in (2, 3, 4, 5, 6, 8, 9, 10, 0, 1, 7)
                    if index not in ((1,) if action == 2 else (0, 8))
                ]
                lows = (0x23, 0x24, 6, 7, 8, 11, 13, 42, 14, 18, 23)
                replies = [
                    (
                        0,
                        bytes((0x62, 0x10, lows[index]))
                        + (b"ab" if index in (6, 9) else b"c"),
                    )
                    for index in indexes
                ]
                replies += [(0, bytes((0x62, 0x1A, 1, 0, marker)))]
                context = Context(source)
                context.replies = iter(replies)
                self.assertEqual(_hnscr_adjust((output,), context), 0)
                self.assertEqual(output[13], 1)
                self.assertEqual(
                    int.from_bytes(output[116:120], "little"), len(indexes)
                )
                for slot, index in enumerate(indexes):
                    self.assertEqual(
                        output[28 + 8 * slot : 30 + 8 * slot],
                        b"ab" if index in (6, 9) else b"\0c",
                    )
                    self.assertEqual(
                        int.from_bytes(output[32 + 8 * slot : 36 + 8 * slot], "little"),
                        index,
                    )
                self.assertNotIn(("finalize",), context.events)
                output[12] = 1
                context = Context(source)
                self.assertEqual(_hnscr_adjust((output,), context), 1000)
                self.assertFalse(any(e[0] == "exchange" for e in context.events))
                self.assertNotIn(("finalize",), context.events)
            for action in range(8):
                context = Context(source)
                context.fault = RuntimeError("wire fault")
                output = bytearray(122)
                output[:4] = action.to_bytes(4, "little")
                with self.assertRaises(RuntimeError):
                    _hnscr_adjust((output,), context)
                self.assertEqual(context.events[-1], ("finalize",))

    def test_new_hv_efi_component_fault_cancel_and_cleanup_identity_matrix(self):
        for source in (SHA_12, SHA_18, SHA_PLUS):
            cases = [
                (
                    _hv_reset,
                    (
                        HV_HISTORY_RESET,
                        (),
                    ),
                ),
                (
                    _hv_reset,
                    (
                        HV_BATTERY_RESET,
                        (),
                    ),
                ),
                (
                    _hv_reset,
                    (
                        HV_READY_CANCEL,
                        (),
                    ),
                ),
                (
                    _hv_reset,
                    (
                        HV_SERVICE,
                        (),
                    ),
                ),
                (_hv12_selected, (HV12_SUPPORT, (bytearray(12),))),
                (_hv12_selected, (HV12_DTC_STATUS, (bytearray(8),))),
                (_hv12_selected, (HV12_AFTER, (bytearray(),))),
                (_hv12_selected, (HV12_UPDATE, (bytearray(),))),
            ]
            cases.extend(
                (_hv10_selected, (export, (bytearray(26),)))
                for export in (HV10_SUPPORT, HV10_READ, HV10_WAIT, HV10_JUDGE)
            )
            if source != SHA_12:
                cases.extend(
                    (
                        (_hv_history, ((bytearray(68),),)),
                        (_efi_throttle, ((bytearray(),),)),
                        (_ect_prefixed, ((bytearray(35),),)),
                        (_ect_bulk, ((bytearray(4098),),)),
                        (_ect_checksum, ((bytearray(4),),)),
                    )
                )
                for action in (0, 1):
                    for export in _ECT_ROUTINES:
                        data = bytearray(5)
                        data[:4] = action.to_bytes(4, "little")
                        cases.append((_ect_routine, (export, (data,))))
                    for export in _ECT_MEMORY:
                        data = bytearray(4136)
                        data[:4] = action.to_bytes(4, "little")
                        cases.append((_ect_memory, (export, (data,))))
                for action in (0, 1, 2):
                    data = bytearray(16)
                    data[12:16] = action.to_bytes(4, "little")
                    cases.append((_hv_accelerator, ((data,),)))
                    for export, size, offset in (
                        (HV_BATTERY_WRITE, 80, 76),
                        (HV_BATTERY_CLEAR, 16, 12),
                    ):
                        data = bytearray(size)
                        data[offset : offset + 4] = action.to_bytes(4, "little")
                        cases.append((_hv_battery_field, (export, (data,))))
                    data = bytearray(28)
                    data[:4] = action.to_bytes(4, "little")
                    data[12:28] = (1).to_bytes(4, "little") * 4
                    cases.append((_efi62_values, ((data,),)))
            for function, args in cases:
                for primary in (RuntimeError("operation"), Cancelled("cancellation")):
                    context = Context(source)
                    context.fault = primary
                    context.finalize_fault = OSError("secondarycleanup")
                    with self.subTest(
                        source=source[:12],
                        function=function.__name__,
                        kind=type(primary).__name__,
                    ):
                        with self.assertRaises(type(primary)) as caught:
                            function(*args, context)
                        self.assertIs(caught.exception, primary)
                        self.assertEqual(context.events.count(("finalize",)), 1)
            context = Context(source)
            primary = RuntimeError("sessionHOST")
            context.finalize_fault = OSError("cleanup")
            with (
                patch.object(context, "session", side_effect=primary),
                self.assertRaises(RuntimeError) as caught,
            ):
                _efi_session_transition((bytearray(),), context)
            self.assertIs(caught.exception, primary)
            self.assertEqual(context.events.count(("finalize",)), 1)

    @staticmethod
    def production_ty18_sdk(mode, replies, on_sleep=None):
        from scripts.j2534_2026 import NativeMessage, PrimitiveResult
        from scripts.utility_ex import _DRIVER_SLOTS, UtilityExContext

        path = Path(
            "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll"
        )
        require_private(path)
        calls = []
        filters, incoming = iter(range(11, 99)), iter(replies)

        def connect(protocol, flags, output):
            calls.append(("connect", protocol, flags))
            output[:] = (42).to_bytes(4, "little")
            return PrimitiveResult()

        def start_filter(channel, kind, mask, pattern, flow, output):
            calls.append(("filter", kind))
            output[:] = next(filters).to_bytes(4, "little")
            return PrimitiveResult()

        def write(channel, messages, count, timeout):
            calls.append(("write", messages[0].data, timeout))
            return PrimitiveResult()

        def read(channel, messages, count, timeout):
            reply = next(incoming)
            if isinstance(reply, BaseException):
                raise reply
            if isinstance(reply, PrimitiveResult):
                return reply
            messages[0] = (
                reply
                if isinstance(reply, NativeMessage)
                else NativeMessage(6, b"\0\0\x07\xe8" + reply)
            )
            return PrimitiveResult()

        def stop_filter(channel, identifier):
            calls.append(("stop_filter", identifier))
            return PrimitiveResult()

        def disconnect(channel):
            calls.append(("disconnect", channel))
            return PrimitiveResult()

        exports: dict[str, Callable[..., object]] = dict.fromkeys(
            _DRIVER_SLOTS.values(), lambda *args: PrimitiveResult()
        )
        exports.update(
            {
                "PassThruConnect": connect,
                "PassThruStartMsgFilter": start_filter,
                "PassThruWriteMsgs": write,
                "PassThruReadMsgs": read,
                "PassThruStopMsgFilter": stop_filter,
                "PassThruDisconnect": disconnect,
            }
        )

        class SDKHost(Host):
            def get_parameter(self, key):
                return {
                    0x6F: mode,
                    0x70: 0x12,
                    0x74: 0x7E0,
                    0xD3: 0xFFFFFFFF,
                    0xDD: 0xFFFFFFFF,
                }.get(key, 0)

            def get_data_size(self, key):
                return 8 if key == 500 else 0

            def get_data(self, key):
                return (
                    (1).to_bytes(4, "little") + (500000).to_bytes(4, "little")
                    if key == 500
                    else b""
                )

            def set_parameter(self, key, value):
                return 0

            def write_parameters(self):
                return 0

            def sleep(self, milliseconds):
                super().sleep(milliseconds)
                if on_sleep is not None:
                    on_sleep(milliseconds)

        context = UtilityExContext(
            path.read_bytes(), SDKHost(mode), None, None, driver_exports=exports
        )
        return context, calls

    def test_exact_public_hv_reset_through_production_ty18_can_sdk(self):
        from scripts.utility_ex import UtilityEx2TY

        path = Path(
            "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll"
        )
        if not path.is_file():
            self.skipTest("Exact supplied source absent")
        for export, identifier in ((HV_HISTORY_RESET, 0x31), (HV_BATTERY_RESET, 0x1F)):
            for response, expected in (
                (bytes((0x7B, identifier)), 0),
                (b"\x7b\x00", 3),
                (RuntimeError("SDK read HOST failure"), None),
                (Cancelled("SDK cancellation"), None),
            ):
                context, calls = self.production_ty18_sdk(4, (response,))
                engine = UtilityEx2TY(context)
                self.assertEqual(engine.invoke(export, ()), 15)
                if isinstance(response, BaseException):
                    with self.assertRaises(type(response)) as raised:
                        engine.worker.get_status()
                    self.assertIs(raised.exception, response)
                else:
                    self.assertEqual(engine.worker.get_status(), expected)
                self.assertIn(
                    ("write", b"\0\0\x07\xe0" + bytes((0x3B, identifier, 1)), 1000),
                    calls,
                )
                self.assertEqual(calls[0], ("connect", 6, 0))
                self.assertEqual(
                    calls[-3:],
                    [("stop_filter", 11), ("stop_filter", 12), ("disconnect", 42)],
                )
                if not isinstance(response, BaseException):
                    self.assertEqual(context.state["native_global:10118e38"], expected)
                self.assertEqual(context.state["native_global:1011f760"], 0)

    def test_public_hv14_reads_real_ty18_sdk_positive_fault_and_cancel(self):
        from scripts.utility_ex import UtilityEx2TY

        path = Path(
            "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll"
        )
        if not path.is_file():
            self.skipTest("Exact supplied source absent")
        for export, echo, size, length_offset, output_offset, request in (
            (HV14_TEMPERATURE, 0x87, 16, 4, 8, b"\x21\x87"),
            (HV14_VOLTAGE, 0x81, 25, 0, 16, b"\x21\x81"),
        ):
            positive = b"\x61" + bytes((echo,)) + bytes(32 if echo == 0x87 else 16)
            malformed = b"\x61" + bytes((echo ^ 1,)) + positive[2:]
            for response, expected in (
                (positive, 0),
                (malformed, 3),
                (RuntimeError("SDK read HOST failure"), None),
                (Cancelled("SDK cancellation"), None),
            ):
                context, calls = self.production_ty18_sdk(4, (response,))
                engine = UtilityEx2TY(context)
                data = bytearray(b"D" * size)
                data[length_offset : length_offset + 4] = len(positive).to_bytes(
                    4, "little"
                )
                before = bytes(data)
                self.assertEqual(engine.invoke(export, (data,)), 15)
                if isinstance(response, BaseException):
                    with self.assertRaises(type(response)) as raised:
                        engine.worker.get_status()
                    self.assertIs(raised.exception, response)
                    self.assertEqual(bytes(data), before)
                else:
                    self.assertEqual(engine.worker.get_status(), expected)
                    if expected:
                        self.assertEqual(bytes(data), before)
                    else:
                        self.assertNotEqual(
                            bytes(data[output_offset : output_offset + 8]),
                            before[output_offset : output_offset + 8],
                        )
                    self.assertEqual(context.state["native_global:10118e38"], expected)
                self.assertIn(("write", b"\0\0\x07\xe0" + request, 1000), calls)
                self.assertEqual(
                    calls[-3:],
                    [("stop_filter", 11), ("stop_filter", 12), ("disconnect", 42)],
                )
                self.assertEqual(context.state["native_global:1011f760"], 0)

    def test_public_hv14_support_uses_real_ty18_sdk_multiframe_a8(self):
        from scripts.j2534_2026 import NativeMessage, PrimitiveResult
        from scripts.utility_ex import UtilityEx2TY

        path = Path(
            "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll"
        )
        if not path.is_file():
            self.skipTest("Exact supplied source absent")
        payload81 = bytes([0xFF] * 16 + [0x20])
        payload87 = bytes([0xFF] * 32 + [0x40])
        frame = (
            b"\xe8\x01\x81"
            + bytes((len(payload81),))
            + payload81
            + b"\x87"
            + bytes((len(payload87),))
            + payload87
        )
        reply = NativeMessage(6, b"\0\0\x07\xe8" + frame)
        context, calls = self.production_ty18_sdk(4, (reply, PrimitiveResult(status=9)))
        engine = UtilityEx2TY(context)
        data = bytearray(b"A" * 16)
        self.assertEqual(engine.invoke(HV14_SUPPORT, (data,)), 15)
        self.assertEqual(engine.worker.get_status(), 0)
        self.assertEqual(int.from_bytes(data[:4], "little"), 19)
        self.assertEqual(int.from_bytes(data[4:8], "little"), 35)
        self.assertEqual(data[8:], b"A" * 8)
        writes = [call[1][4:] for call in calls if call[0] == "write"]
        self.assertEqual(writes, [b"\xa8\x01"])
        self.assertEqual(
            calls[-3:],
            [("stop_filter", 11), ("stop_filter", 12), ("disconnect", 42)],
        )
        self.assertEqual(context.state["native_global:10118e38"], 0)
        self.assertEqual(context.state["native_global:1011f760"], 0)

    def test_public_four_ect_memory_operations_real_sdk_and_native_timeout(self):
        from scripts.utility_ex import UtilityEx2TY

        for export, low in _ECT_MEMORY.items():
            replies = (
                b"\x50\1",
                b"\x50\3",
                bytes((0x62, 0x23, low)) + b"ABCD",
                b"\x50\1",
                b"\x50\1",
                b"\x50\3",
                bytes((0x6E, 0x23, low)),
                b"\x50\1",
            )
            context, calls = self.production_ty18_sdk(20, replies)
            engine = UtilityEx2TY(context)
            data = bytearray(4136)
            self.assertEqual(engine.invoke(export, (data,)), 15)
            self.assertEqual(engine.worker.get_status(), 0)
            self.assertEqual(data[4:12], (4).to_bytes(4, "little") + b"ABCD")
            self.assertEqual(data[12:], bytes(4124))
            data[:4] = (1).to_bytes(4, "little")
            self.assertEqual(engine.invoke(export, (data,)), 15)
            self.assertEqual(engine.worker.get_status(), 0)
            writes = [c for c in calls if c[0] == "write"]
            self.assertEqual(
                [c[1][4:] for c in writes],
                [
                    b"\x10\1",
                    b"\x10\3",
                    bytes((0x22, 0x23, low)),
                    b"\x10\1",
                    b"\x10\1",
                    b"\x10\3",
                    bytes((0x2E, 0x23, low)) + b"ABCD",
                    b"\x10\1",
                ],
            )
            self.assertEqual(
                {c[2] for c in writes},
                {2000 if export == "Ex2ECT_08_SendMessage" else 0x3FC},
            )
            self.assertEqual(calls.count(("disconnect", 42)), 2)

    def test_public_seven_ect_routines_real_fixed_sdk_positive_fault_cancel(self):
        from scripts.utility_ex import UtilityEx2TY

        for export, low in _ECT_ROUTINES.items():
            for terminal in (
                2,
                3,
                RuntimeError("ECT SDK HOST"),
                Cancelled("ECT SDK cancel"),
            ):
                poll = (
                    terminal
                    if isinstance(terminal, BaseException)
                    else bytes((0x71, 3, 0x11, low, terminal))
                )
                replies = (
                    b"\x50\1",
                    b"\x50\3",
                    bytes((0x71, 1, 0x11, low)),
                    poll,
                    bytes((0x71, 2, 0x11, low)),
                    b"\x50\1",
                )
                context, calls = self.production_ty18_sdk(20, replies)
                engine = UtilityEx2TY(context)
                comm = context.comm("native:1011d4f0")
                self.addCleanup(comm.finalize)
                data = bytearray(5)
                self.assertEqual(engine.invoke(export, (data,)), 15)
                self.assertEqual(engine.worker.get_status(), 0)
                self.assertTrue(comm._fixed_lifecycle().worker_active)
                data[:4] = (1).to_bytes(4, "little")
                self.assertEqual(engine.invoke(export, (data,)), 15)
                if isinstance(terminal, BaseException):
                    with self.assertRaises(type(terminal)) as raised:
                        engine.worker.get_status()
                    self.assertIs(raised.exception, terminal)
                else:
                    self.assertEqual(
                        engine.worker.get_status(), 0 if terminal == 2 else 3
                    )
                self.assertFalse(comm._fixed_lifecycle().worker_active)
                requests = [c[1][4:] for c in calls if c[0] == "write"]
                self.assertEqual(
                    requests[:4],
                    [
                        b"\x10\1",
                        b"\x10\3",
                        bytes((0x31, 1, 0x11, low)),
                        bytes((0x31, 3, 0x11, low)),
                    ],
                )
                if not isinstance(terminal, BaseException):
                    self.assertEqual(
                        requests[4:], [bytes((0x31, 2, 0x11, low)), b"\x10\1"]
                    )
                self.assertEqual(calls.count(("disconnect", 42)), 1)
                self.assertEqual(data, bytearray((1).to_bytes(4, "little") + b"\0"))

    def test_public_efi59_retained_ten_records_real_fixed_sdk(self):
        from scripts.utility_ex import UtilityEx2TY

        results = b"\2" + b"\3" * 8 + b"\4"
        replies = (
            b"\x50\1",
            b"\x50\3",
            b"\x71\1\x11\x4a",
            b"\x71\1\x11\x4a",
            b"\x71\3\x11\x4a" + results,
            b"\x7f\x31\x33",
            b"\x50\1",
        )
        context, calls = self.production_ty18_sdk(20, replies)
        engine = UtilityEx2TY(context)
        comm = context.comm("native:1011d4f0")
        self.addCleanup(comm.finalize)
        data = bytearray(128)
        for i in range(10):
            data[i * 12] = i + 10
            data[i * 12 + 4 : i * 12 + 8] = int(i in (0, 9)).to_bytes(4, "little")
        self.assertEqual(engine.invoke(EFI59_ROUTINE, (data,)), 15)
        self.assertEqual(engine.worker.get_status(), 0)
        self.assertTrue(comm._fixed_lifecycle().worker_active)
        self.assertFalse(any(c[0] == "disconnect" for c in calls))
        data[120:124] = (1).to_bytes(4, "little")
        self.assertEqual(engine.invoke(EFI59_ROUTINE, (data,)), 15)
        self.assertEqual(engine.worker.get_status(), 0)
        self.assertEqual(data[1:120:12], results)
        self.assertFalse(comm._fixed_lifecycle().worker_active)
        self.assertEqual(
            [c[1][4:] for c in calls if c[0] == "write"],
            [
                b"\x10\1",
                b"\x10\3",
                b"\x31\1\x11\x4a\x0a",
                b"\x31\1\x11\x4a\x13",
                b"\x31\3\x11\x4a",
                b"\x31\2\x11\x4a",
                b"\x10\1",
            ],
        )
        self.assertEqual(calls.count(("connect", 6, 0)), 1)
        self.assertEqual(calls.count(("disconnect", 42)), 1)

    def test_public_efi52_real_fixed_sdk_observes_native_ui_buffer_stop(self):
        from scripts.utility_ex import UtilityEx2TY

        data = bytearray((1).to_bytes(4, "little") + bytes(3))

        def on_sleep(milliseconds):
            if milliseconds == 1000:
                data[4] = 1

        context, calls = self.production_ty18_sdk(
            20,
            (b"\x50\1", b"\x50\3", b"\x62\x20\x2b\0", b"\x6e\x20\x2b", b"\x50\1"),
            on_sleep,
        )
        engine = UtilityEx2TY(context)
        self.assertEqual(engine.invoke(EFI52_SWITCH, (data,)), 15)
        self.assertEqual(engine.worker.get_status(), 0)
        self.assertEqual(data, bytes(4) + b"\1\1\0")
        self.assertEqual(
            [c[1][4:] for c in calls if c[0] == "write"],
            [b"\x10\1", b"\x10\3", b"\x22\x20\x2b", b"\x2e\x20\x2b\1", b"\x10\1"],
        )
        self.assertEqual(
            calls[-3:], [("stop_filter", 11), ("stop_filter", 12), ("disconnect", 42)]
        )

    def test_public_efi53_retained_routine_real_fixed_sdk(self):
        from scripts.utility_ex import UtilityEx2TY

        replies = (
            b"\x50\1",
            b"\x50\3",
            b"\x62\x20\x2b\1",
            b"\x71\1\x11\x40",
            b"\x71\3\x11\x40\1",
            b"\x71\3\x11\x40\2",
            b"\x50\1",
        )
        context, calls = self.production_ty18_sdk(20, replies)
        engine = UtilityEx2TY(context)
        comm = context.comm("native:1011d4f0")
        self.addCleanup(comm.finalize)
        data = bytearray(9)
        self.assertEqual(engine.invoke(EFI53_ROUTINE, (data,)), 15)
        self.assertEqual(engine.worker.get_status(), 0)
        self.assertTrue(comm._fixed_lifecycle().worker_active)
        self.assertFalse(any(c[0] == "disconnect" for c in calls))
        data[:4] = (1).to_bytes(4, "little")
        self.assertEqual(engine.invoke(EFI53_ROUTINE, (data,)), 15)
        self.assertEqual(engine.worker.get_status(), 0)
        self.assertFalse(comm._fixed_lifecycle().worker_active)
        self.assertEqual(calls.count(("connect", 6, 0)), 1)
        self.assertEqual(calls.count(("disconnect", 42)), 1)
        self.assertEqual(
            [c[1][4:] for c in calls if c[0] == "write"],
            [
                b"\x10\1",
                b"\x10\3",
                b"\x22\x20\x2b",
                b"\x31\1\x11\x40\2\x65",
                b"\x31\3\x11\x40",
                b"\x31\3\x11\x40",
                b"\x10\1",
            ],
        )
        self.assertEqual(data, bytearray((1).to_bytes(4, "little") + bytes(5)))

    def test_public_efi62_all_actions_real_fixed_sdk_and_partial_caller_state(self):
        from scripts.utility_ex import UtilityEx2TY

        support = bytearray(32)
        support[5:7] = b"\1\x80"
        replies = (
            b"\x50\1",
            b"\x50\3",
            b"\x62\x20\0" + support,
            b"\x50\1",
            b"\x50\1",
            b"\x50\3",
            b"\x62\x20\x30ABCD",
            b"\x62\x20\x31EFGH",
            b"\x50\1",
            b"\x50\1",
            b"\x50\3",
            b"\x6e\x20\x30",
            b"\x6e\x20\x31",
            b"\x50\1",
        )
        context, calls = self.production_ty18_sdk(20, replies)
        engine = UtilityEx2TY(context)
        data = bytearray(28)
        for action in (0, 1, 2):
            data[:4] = action.to_bytes(4, "little")
            if action == 2:
                data[20:28] = (1).to_bytes(4, "little") * 2
            self.assertEqual(engine.invoke(EFI62_VALUES, (data,)), 15)
            self.assertEqual(engine.worker.get_status(), 0)
        self.assertEqual(data[4:12], b"ABCDEFGH")
        self.assertEqual(data[12:20], (1).to_bytes(4, "little") * 2)
        requests = [call[1][4:] for call in calls if call[0] == "write"]
        self.assertEqual(
            requests,
            [
                b"\x10\1",
                b"\x10\3",
                b"\x22\x20\0",
                b"\x10\1",
                b"\x10\1",
                b"\x10\3",
                b"\x22\x20\x30",
                b"\x22\x20\x31",
                b"\x10\1",
                b"\x10\1",
                b"\x10\3",
                b"\x2e\x20\x30ABCD",
                b"\x2e\x20\x31EFGH",
                b"\x10\1",
            ],
        )
        self.assertEqual(calls.count(("disconnect", 42)), 3)
        self.assertEqual(
            [c[1] for c in calls if c[0] == "stop_filter"], list(range(11, 17))
        )
        self.assertFalse(
            context.comm("native:1011d4f0")._fixed_lifecycle().worker_active
        )

    def test_public_efi54_real_fixed_sdk_positive_fault_and_cancel(self):
        from scripts.utility_ex import UtilityEx2TY

        for reply, expected in (
            (b"\x71\1\x11\x93", 0),
            (b"\x71\1\x12\x93", 3),
            (RuntimeError("fixed SDK HOST"), None),
            (Cancelled("fixed SDK cancel"), None),
        ):
            context, calls = self.production_ty18_sdk(20, (b"\x50\1", reply))
            engine = UtilityEx2TY(context)
            data = bytearray(b"argument")
            self.assertEqual(engine.invoke(EFI_THROTTLE_LEARN, (data,)), 15)
            if isinstance(reply, BaseException):
                with self.assertRaises(type(reply)) as raised:
                    engine.worker.get_status()
                self.assertIs(raised.exception, reply)
            else:
                self.assertEqual(engine.worker.get_status(), expected)
            self.assertEqual(data, b"argument")
            self.assertEqual(
                [c[1] for c in calls if c[0] == "write"],
                [b"\0\0\x07\xe0\x10\1", b"\0\0\x07\xe0\x31\1\x11\x93"],
            )
            self.assertEqual(
                calls[-3:],
                [("stop_filter", 11), ("stop_filter", 12), ("disconnect", 42)],
            )

    def test_public_efi58_retained_start_then44_closes_real_fixed_sdk(self):
        from scripts.utility_ex import UtilityEx2TY

        context, calls = self.production_ty18_sdk(
            20, (b"\x50\1", b"\x50\3", b"\x71\1\x11\x3e", b"\x50\1")
        )
        engine = UtilityEx2TY(context)
        data = bytearray((1,))
        self.assertEqual(engine.invoke(EFI_PM_START, (data,)), 15)
        self.assertEqual(engine.worker.get_status(), 0)
        self.assertFalse(any(call[0] == "disconnect" for call in calls))
        comm = context.comm("native:1011d4f0")
        self.addCleanup(comm.finalize)
        self.assertTrue(comm._fixed_lifecycle().worker_active)
        self.assertEqual(engine.invoke(EFI_SESSION_TRANSITION, (bytearray(),)), 15)
        self.assertEqual(engine.worker.get_status(), 0)
        requests = [call[1] for call in calls if call[0] == "write"]
        self.assertEqual(
            requests,
            [
                b"\0\0\x07\xe0\x10\1",
                b"\0\0\x07\xe0\x10\3",
                b"\0\0\x07\xe0\x31\1\x11\x3e\0",
                b"\0\0\x07\xe0\x10\1",
            ],
        )
        self.assertEqual(data, bytearray((1,)))
        self.assertFalse(comm._fixed_lifecycle().worker_active)
        self.assertEqual(
            calls[-3:], [("stop_filter", 11), ("stop_filter", 12), ("disconnect", 42)]
        )

    def test_hv_battery_field_support_write_clear_verify_and_native_limits(self):
        def snapshot(pid, payload):
            offsets = [4128] * 256
            offsets[pid] = 0
            return (
                0,
                (bytes((pid, len(payload))) + payload).ljust(4128, b"\0"),
                tuple(offsets),
            )

        for source in (SHA_18, SHA_PLUS):
            for export, size, action_offset in (
                (HV_BATTERY_WRITE, 80, 76),
                (HV_BATTERY_CLEAR, 16, 12),
            ):
                data = bytearray(size)
                context = Context(source)
                context.snapshots = iter(
                    (snapshot(0xB0, bytes(45) + b"\x01"), snapshot(0x44, bytes(12)))
                )
                self.assertEqual(_hv_battery_field(export, (data,), context), 0)
                self.assertEqual(data[:12], b"\2\0\0\0\1\0\0\0\x0c\0\0\0")
                data[action_offset : action_offset + 4] = (1).to_bytes(4, "little")
                if export == HV_BATTERY_WRITE:
                    data[21:23] = b"\x12\x34"
                context = Context(source, response=b"\0\x44")
                self.assertEqual(_hv_battery_field(export, (data,), context), 0)
                request = bytearray(b"\x3b\x44\x08" + bytes(11))
                if export == HV_BATTERY_WRITE:
                    request[11:13] = b"\x12\x34"
                self.assertIn(("exchange", bytes(request)), context.events)
                data[action_offset : action_offset + 4] = (2).to_bytes(4, "little")
                desired = b"\x12\x34" if export == HV_BATTERY_WRITE else bytes(2)
                for reply, result in (
                    (b"\0\xb0" + desired, 0),
                    (b"\0\xb0XX", 3),
                    (b"\0\xb1" + desired, 3),
                    (b"\0\xb0", 3),
                ):
                    context = Context(source, response=reply)
                    self.assertEqual(
                        _hv_battery_field(export, (data,), context), result
                    )
                    self.assertIn(("native_sleep", 3000), context.events)
                    self.assertEqual(context.events[-1], ("finalize",))
                data[action_offset : action_offset + 4] = (3).to_bytes(4, "little")
                context = Context(source)
                self.assertEqual(_hv_battery_field(export, (data,), context), 0)
                self.assertFalse(any(e[0] == "exchange" for e in context.events))
            data = bytearray(80)
            data[8:12] = (62).to_bytes(4, "little")
            data[76:80] = (1).to_bytes(4, "little")
            context = Context(source)
            with self.assertRaises(ValueError):
                _hv_battery_field(HV_BATTERY_WRITE, (data,), context)
            self.assertEqual(context.events[-1], ("finalize",))

    def test_hv19_distinct_support_masks_request_and_zero_verify(self):
        for source in (SHA_18, SHA_PLUS):
            raw = bytearray(4128)
            raw[:47] = b"\xb0\x2d" + bytes(43) + b"\xff\xff"
            offsets = [4128] * 256
            offsets[0xB0] = 0
            command = bytearray(4128)
            command[:4] = b"\x41\2\x08\x08"
            command_offsets = [4128] * 256
            command_offsets[0x41] = 0
            context = Context(source)
            context.snapshots = iter(
                (
                    (0, bytes(raw), tuple(offsets)),
                    (0, bytes(command), tuple(command_offsets)),
                )
            )
            data = bytearray(16)
            self.assertEqual(_hv_accelerator((data,), context, clearing=True), 0)
            self.assertEqual(data[:12], b"\2\0\0\0\2\0\0\0\2\0\0\0")
            data[12:16] = (1).to_bytes(4, "little")
            context = Context(source, response=b"\0\x41")
            self.assertEqual(_hv_accelerator((data,), context, clearing=True), 0)
            self.assertIn(("exchange", b"\x3b\x41\x08\x08"), context.events)
            data[12:16] = (2).to_bytes(4, "little")
            for reply, result in (
                (b"\0\xb0\0\0", 0),
                (b"\0\xb0\x10\x68", 1001),
                (b"\0\xb1\0\0", 3),
            ):
                context = Context(source, response=reply)
                self.assertEqual(
                    _hv_accelerator((data,), context, clearing=True), result
                )
                self.assertEqual(context.events[-1], ("finalize",))

    def test_hv_accelerator_support_all_actions_partial_outputs_and_padding(self):
        def snapshot(pid, payload):
            raw = bytes((pid, len(payload))) + payload
            offsets = [4128] * 256
            offsets[pid] = 0
            return 0, raw.ljust(4128, b"\0"), tuple(offsets)

        payload = bytes(41) + b"\xff\xff"
        for source in (SHA_18, SHA_PLUS):
            context = Context(source)
            context.snapshots = iter(
                (snapshot(0xB0, payload), snapshot(0x41, b"\x10\x10\0"))
            )
            data = bytearray(16)
            self.assertEqual(_hv_accelerator((data,), context), 0)
            self.assertEqual(data[:12], b"\2\0\0\0\2\0\0\0\3\0\0\0")
            context = Context(source)
            context.snapshots = iter((snapshot(0xB0, payload), (17, b"", ())))
            data = bytearray(b"Z" * 12 + bytes(4))
            self.assertEqual(_hv_accelerator((data,), context), 17)
            self.assertEqual(data[:12], b"\2\0\0\0\2\0\0\0ZZZZ")
            context = Context(source)
            context.snapshots = iter((snapshot(0xB0, bytes(43)),))
            data = bytearray(b"Z" * 12 + bytes(4))
            self.assertEqual(_hv_accelerator((data,), context), 22)
            self.assertEqual(data[:12], b"\2\0\0\0ZZZZZZZZ")
            for count in (0, 1, 2, 4):
                context = Context(source, response=b"\0\x41")
                data = bytearray(16)
                data[8:12], data[12:16] = (
                    count.to_bytes(4, "little"),
                    (1).to_bytes(4, "little"),
                )
                self.assertEqual(_hv_accelerator((data,), context), 0)
                request = (b"\x3b\x41\x10\x10" + bytes(4))[: count + 2]
                self.assertIn(("exchange", request), context.events)
            for response, expected in (
                (b"\0\xb0\x10\x68", 0),
                (b"\0\xb0\x10\x67", 1001),
                (b"\0\xb1\x10\x68", 3),
                (b"\0\xb0", 3),
            ):
                context = Context(source, response=response)
                data = bytearray(
                    (2).to_bytes(4, "little") * 2 + bytes(4) + (2).to_bytes(4, "little")
                )
                self.assertEqual(_hv_accelerator((data,), context), expected)
                self.assertIn(("native_sleep", 3000), context.events)
                self.assertEqual(context.events[-1], ("finalize",))
            context = Context(source)
            data = bytearray(bytes(12) + (3).to_bytes(4, "little"))
            self.assertEqual(_hv_accelerator((data,), context), 0)
            self.assertFalse(any(e[0] == "exchange" for e in context.events))

    def test_hv_history_exact_mutation_partial_and_host_bounds(self):
        for source in (SHA_18, SHA_PLUS):
            for payload in (b"A", bytes(range(61)), bytes(range(70))):
                context = Context(source, response=b"\x00\x44" + payload)
                data = bytearray(b"Z" * 80)
                self.assertEqual(_hv_history((data,), context), 0)
                expected = bytearray(b"Z" * 80)
                expected[:61] = bytes(61)
                expected[: len(payload)] = payload
                expected[64:68] = len(payload).to_bytes(4, "little")
                self.assertEqual(data, expected)
                self.assertEqual(context.events[-1], ("finalize",))
            for status, response, result in (
                (17, b"\0\x44X", 17),
                (0, b"\0\x44", 3),
                (0, b"\0\x45X", 3),
            ):
                context = Context(source, status=status, response=response)
                data = bytearray(b"Z" * 68)
                self.assertEqual(_hv_history((data,), context), result)
                self.assertEqual(data, bytearray(b"Z" * 68))
            context = Context(source, response=b"\0\x44" + bytes(69))
            data = bytearray(b"Z" * 68)
            with self.assertRaises(ValueError):
                _hv_history((data,), context)
            self.assertEqual(data, bytearray(b"Z" * 68))
            self.assertEqual(context.events[-1], ("finalize",))

    def test_hv10_support_optional93_partial_metadata_and_native_statuses(self):
        for source in (SHA_12, SHA_18, SHA_PLUS):
            primary = bytearray(26)
            primary[15:17], primary[25] = b"\xff\xff", 0x80
            secondary = bytes(19) + b"\x80"
            raw = (
                bytes((0x92, len(primary)))
                + primary
                + bytes((0x93, len(secondary)))
                + secondary
            )
            offsets = [4128] * 256
            offsets[0x92], offsets[0x93] = 0, 28
            context = Context(source)
            context.snapshots = iter(
                ((0, bytes(raw).ljust(4128, b"\0"), tuple(offsets)),)
            )
            data = bytearray(b"Z" * 26)
            self.assertEqual(_hv10_selected(HV10_SUPPORT, (data,), context), 0)
            self.assertEqual(
                [int.from_bytes(data[i : i + 4], "little") for i in range(0, 20, 4)],
                [2, 2, 4, 5, 3],
            )
            self.assertEqual(data[20:], b"\x80\x80ZZZZ")
            offsets[0x93] = 4128
            context = Context(source)
            context.snapshots = iter(
                ((0, bytes(raw).ljust(4128, b"\0"), tuple(offsets)),)
            )
            data = bytearray(b"Z" * 26)
            self.assertEqual(_hv10_selected(HV10_SUPPORT, (data,), context), 0)
            self.assertEqual(data[4:8], bytes(4))
            self.assertEqual(data[16:22], b"ZZZZ\0\x80")
            for final, expected in (
                (0x13, 17000),
                (1, 12000),
                (0x14, 12000),
                (0, 10000),
            ):
                context = Context(source, response=bytes((0, 0x92, 3, final, 0x80)))
                data = bytearray(26)
                data[:4], data[8:12], data[21] = (
                    (2).to_bytes(4, "little"),
                    (4).to_bytes(4, "little"),
                    0x80,
                )
                self.assertEqual(_hv10_selected(HV10_READ, (data,), context), expected)
                self.assertEqual(data[22:25], bytes((3, final, 0x80)))
            context = Context(source, status=3, response=b"")
            data = bytearray(26)
            data[:4] = (2).to_bytes(4, "little")
            self.assertEqual(_hv10_selected(HV10_READ, (data,), context), 1460)
            self.assertEqual(data[22:25], bytes(3))

    def test_hv10_wait_wrap_deadline_and_judgement_secondary_read(self):
        for source in (SHA_12, SHA_18, SHA_PLUS):
            data = bytearray(26)
            data[:4] = (2).to_bytes(4, "little")
            context = Context(source, response=b"\0\x92\0\0")
            ticks = iter(
                (
                    0xFFFFFF00,
                    (0xFFFFFF00 + 661000) & 0xFFFFFFFF,
                    (0xFFFFFF00 + 661001) & 0xFFFFFFFF,
                )
            )
            context.ticks = ticks.__next__
            self.assertEqual(_hv10_selected(HV10_WAIT, (data,), context), 12000)
            self.assertEqual(context.events.count(("exchange", b"\x21\x92")), 2)
            self.assertEqual(context.events.count(("native_sleep", 1000)), 1)
            for first, mask, expected in (
                (3, 0, 13000),
                (4, 0, 11000),
                (0, 0, 10000),
                (4, 0x80, 11000),
            ):
                data = bytearray(26)
                data[:4], data[4:8], data[16:20], data[20] = (
                    (2).to_bytes(4, "little"),
                    (2).to_bytes(4, "little"),
                    (3).to_bytes(4, "little"),
                    mask,
                )
                context = Context(source)
                context.replies = iter(
                    ((0, bytes((0, 0x92, first, 0))), (0, b"\0\x93\xff"))
                )
                self.assertEqual(_hv10_selected(HV10_JUDGE, (data,), context), expected)
                self.assertEqual(data[25], mask)
                self.assertEqual(context.events[-1], ("finalize",))

    def test_ect13_source_specific_prefix_layout_wrap_and_error_mapping(self):
        for source, mode in ((SHA_18, 20), (SHA_PLUS, 20), (SHA_PLUS, 22)):
            data = bytearray(35)
            data[4:7], data[34] = b"ABC", 3
            context = Context(source)
            context.mode = mode
            if source == SHA_18:
                context.replies = iter(((0, b"\0\x23\4"),))
                expected = b"\x2e\x23\4" + bytes(46) + b"ABC"
            elif mode == 22:
                context.replies = iter(
                    ((0, b"\0\x94\x21\0\4\2xx\0"), (0, b"\0\x94\x21"))
                )
                expected = b"\x2e\x94\x21\0\6" + bytes(3) + b"ABC"
            else:
                context.replies = iter(((0, b"\0\x23\4\2xx\0"), (0, b"\0\x23\4")))
                expected = b"\x2e\x23\4" + bytes(3) + b"ABC"
            saved = bytes(data)
            self.assertEqual(_ect_prefixed((data,), context), 0)
            self.assertEqual(data, saved)
            self.assertIn(("exchange", expected), context.events)
        data = bytearray(260)
        data[34] = 255
        context = Context(SHA_PLUS)
        context.replies = iter(((0, b"\0\x23\4\xff" + bytes(256)), (7, b"")))
        context.native_error = 0x66
        self.assertEqual(_ect_prefixed((data,), context), 1006)
        self.assertIn(("exchange", b"\x2e\x23\4" + bytes(255)), context.events)
        data = bytearray(35)
        data[34] = 31
        context = Context(SHA_18)
        with self.assertRaises(ValueError):
            _ect_prefixed((data,), context)
        self.assertEqual(context.events[-1], ("finalize",))

    def test_ect15_word_length_capacity_and_raw_payload_preservation(self):
        for source in (SHA_18, SHA_PLUS):
            for count in (0, 4, 4092):
                data = bytearray(4098)
                data[4:4096] = bytes(range(256)) * 15 + bytes(range(252))
                data[4096:4098] = count.to_bytes(2, "little")
                saved = bytes(data)
                context = Context(source, response=b"\0\x23\x08")
                self.assertEqual(_ect_bulk((data,), context), 0)
                self.assertIn(
                    ("exchange", b"\x2e\x23\x08" + data[4 : 4 + count]), context.events
                )
                self.assertEqual(data, saved)
            data[4096:4098] = (4093).to_bytes(2, "little")
            with self.assertRaises(ValueError):
                _ect_bulk((data,), Context(source))

    def test_ect16_version_selector_lengths_and_xor_checksums(self):
        for source, selector, count, positions in (
            (SHA_18, 0, 112, {82: 0xA5}),
            (SHA_PLUS, 1, 112, {82: 0xA5}),
            (SHA_PLUS, 2, 71, {38: 0xA5}),
            (SHA_PLUS, 0, 133, {38: 0xA5, 77: 0x6B}),
        ):
            context = Context(source)
            raw = bytes(range(count))
            context.replies = iter(((0, b"\0\x23\3" + raw), (0, b"\0\x23\3")))
            data = bytearray(selector.to_bytes(4, "little"))
            self.assertEqual(_ect_checksum((data,), context), 0)
            expected = bytearray(raw)
            zero = 80 if count == 112 else 36
            expected[zero : zero + 2] = bytes(2)
            for position, value in positions.items():
                expected[position] = value
            self.assertIn(("exchange", b"\x2e\x23\3" + expected), context.events)
            self.assertIn(("native_sleep", 200), context.events)
            self.assertEqual(data, selector.to_bytes(4, "little"))

    def test_ect_memory_read_zero_fill_wire_failure_length_and_raw_write(self):
        for source in (SHA_18, SHA_PLUS):
            for export, low in _ECT_MEMORY.items():
                for status, reply, result in (
                    (0, bytes((0, 0x23, low)) + b"ABCD", 0),
                    (17, b"", 17),
                    (0, bytes((0, 0x23, low)), 3),
                    (0, b"\0\x24\0ABC", 3),
                ):
                    data = bytearray(b"Z" * 4140)
                    data[:4] = bytes(4)
                    context = Context(source, status=status, response=reply)
                    self.assertEqual(_ect_memory(export, (data,), context), result)
                    self.assertEqual(
                        data[4:8], (4).to_bytes(4, "little") if result == 0 else b"ZZZZ"
                    )
                    self.assertEqual(
                        data[8:4136],
                        b"ABCD" + bytes(4124) if result == 0 else bytes(4128),
                    )
                    self.assertEqual(data[4136:], b"ZZZZ")
                    if export == "Ex2ECT_08_SendMessage":
                        setter = (
                            "native_rva:1a890"
                            if source == SHA_18
                            else "native_rva:1e280"
                        )
                        self.assertIn(("configure", setter, 2000), context.events)
                data = bytearray(
                    (1).to_bytes(4, "little") + (4).to_bytes(4, "little") + b"ABCD"
                )
                saved = bytes(data)
                context = Context(source, response=bytes((0, 0x23, low)))
                self.assertEqual(_ect_memory(export, (data,), context), 0)
                self.assertEqual(data, saved)
                self.assertIn(
                    ("exchange", bytes((0x2E, 0x23, low)) + b"ABCD"), context.events
                )
                self.assertEqual(
                    context.events[-2:],
                    [("session", 1, 1, False, False), ("finalize",)],
                )

    def test_ect04_plus_p6_read_keeps_echoed_did_and_length(self):
        context = Context(SHA_PLUS, response=b"\0\x94\x21ABCD")
        context.mode = 22
        data = bytearray(4136)
        self.assertEqual(_ect_memory("Ex2ECT_04_SendMessage", (data,), context), 0)
        self.assertEqual(data[4:8], (6).to_bytes(4, "little"))
        self.assertEqual(data[8:14], b"\x94\x21ABCD")
        self.assertIn(("comm", "native:1013e7d0"), context.events)
        data[:4] = (1).to_bytes(4, "little")
        context = Context(SHA_PLUS, response=b"\0\x94\x21")
        context.mode = 22
        self.assertEqual(_ect_memory("Ex2ECT_04_SendMessage", (data,), context), 0)
        self.assertIn(("exchange", b"\x2e\x94\x21\x94\x21ABCD"), context.events)

    def test_ect_seven_literal_routines_retention_poll_all_terminals(self):
        for source in (SHA_18, SHA_PLUS):
            for export, low in _ECT_ROUTINES.items():
                data = bytearray(5)
                context = Context(source, response=bytes((0, 1, 0x11, low)))
                self.assertEqual(_ect_routine(export, (data,), context), 0)
                self.assertFalse(any(e[0] == "finalize" for e in context.events))
                self.assertIn(("exchange", bytes((0x31, 1, 0x11, low))), context.events)
                for result, expected in ((2, 0), (3, 3), (0xFF, 3)):
                    context = Context(source)
                    context.replies = iter(
                        (
                            (0, bytes((0, 3, 0x11, low, 0))),
                            (0, bytes((0, 3, 0x11, low, 1))),
                            (0, bytes((0, 3, 0x11, low, result))),
                            (17, b""),
                        )
                    )
                    data[:4] = (1).to_bytes(4, "little")
                    self.assertEqual(_ect_routine(export, (data,), context), expected)
                    self.assertEqual(context.events.count(("native_sleep", 200)), 3)
                    self.assertEqual(
                        context.events[-2:],
                        [("session", 1, 1, False, False), ("finalize",)],
                    )
                data[4] = 1
                context = Context(source, status=17)
                self.assertEqual(_ect_routine(export, (data,), context), 0)
                self.assertEqual(
                    [e[1] for e in context.events if e[0] == "exchange"],
                    [bytes((0x31, 2, 0x11, low))],
                )

    def test_ect01_plus_p6_distinct_scope_pending_errors_and_extra_header(self):
        for wire_error, native_error in ((7, 0x68), (7, 0x6A), (28, 0)):
            context = Context(SHA_PLUS)
            context.mode = 22
            context.native_error = native_error
            context.replies = iter(
                ((wire_error, b""), (0, b"\0\3\x11\x8bX\2"), (17, b""))
            )
            data = bytearray((1).to_bytes(4, "little") + b"\0")
            self.assertEqual(_ect_routine("Ex2ECT_01_SendMessage", (data,), context), 0)
            self.assertEqual(context.events.count(("native_sleep", 200)), 2)
            self.assertEqual(
                context.events[-2:],
                [("configure", "native_10a4", native_error), ("finalize",)],
            )
        context = Context(SHA_PLUS, response=b"\0\1\x11\x8b")
        context.mode = 22
        self.assertEqual(
            _ect_routine("Ex2ECT_01_SendMessage", (bytearray(5),), context), 3
        )
        self.assertEqual(context.events[-1], ("finalize",))

    def test_ect01_p6_host_failure_restores_field_before_cleanup(self):
        for primary in (RuntimeError("wire HOST"), Cancelled("wire cancellation")):
            context = Context(SHA_PLUS)
            context.mode, context.native_error = 22, 71
            context.fault, context.finalize_fault = primary, OSError("cleanup")
            data = bytearray((1).to_bytes(4, "little") + b"\0")
            with self.assertRaises(type(primary)) as caught:
                _ect_routine("Ex2ECT_01_SendMessage", (data,), context)
            self.assertIs(caught.exception, primary)
            self.assertEqual(
                context.events[-2:],
                [("configure", "native_10a4", 71), ("finalize",)],
            )
            self.assertEqual(context.events.count(("finalize",)), 1)

    def test_efi55_exact_tables_prefix_compare_and_ignored_tail(self):
        self.assertEqual(tuple(map(len, _EFI55_TABLES)), (109, 112))
        for source in (SHA_18, SHA_PLUS):
            for selector in (0, 1, 2, 0xFFFFFFFF):
                second = selector == 2
                payload = _EFI55_TABLES[second]
                prefix = 83 if second else 81
                for mutation, result in ((None, 0), (prefix - 1, 1000), (prefix, 0)):
                    copied = bytearray(payload)
                    if mutation is not None:
                        copied[mutation] ^= 0xFF
                    context = Context(source)
                    context.replies = iter(
                        ((0, b"\0\x23\3"), (0, b"\0\x23\3" + copied))
                    )
                    context.sessions = iter((0, 17))
                    data = bytearray(selector.to_bytes(4, "little"))
                    self.assertEqual(_efi55_table((data,), context), result)
                    self.assertEqual(data, selector.to_bytes(4, "little"))
                    self.assertIn(("exchange", b"\x2e\x23\3" + payload), context.events)
                    self.assertIn(("native_sleep", 200), context.events)
                    self.assertEqual(
                        context.events[-2:],
                        [("session", 1, 1, False, False), ("finalize",)],
                    )

    def test_efi61_support_exact_vs_p6_minimum_and_nonzero_selection_zero_writes(self):
        for source, mode in ((SHA_18, 20), (SHA_PLUS, 20), (SHA_PLUS, 22)):
            for extra in (b"", b"X"):
                context = Context(source)
                context.mode = mode
                reply = bytearray(35)
                reply[1:3] = b"\xa1\x20" if mode == 22 else b"\x20\0"
                if mode == 22:
                    reply[9] = 0xC0
                else:
                    reply[8:10] = b"\1\x80"
                context.response = bytes(reply) + extra
                context.sessions = iter((0, 17))
                data = bytearray(b"Z" * 8)
                expected = 0 if mode == 22 or not extra else 3
                self.assertEqual(
                    _efi61_values(EFI61_SUPPORT, (data,), context), expected
                )
                self.assertEqual(
                    data, (1).to_bytes(4, "little") * 2 if expected == 0 else b"Z" * 8
                )
                self.assertEqual(context.events[-1], ("finalize",))
            context = Context(source)
            context.mode = mode
            context.replies = iter(((0, b"\0\x20\x30"), (0, b"\0\x20\x31")))
            data = bytearray(b"Z" * 24)
            data[16:24] = (2).to_bytes(4, "little") + (0xFFFFFFFF).to_bytes(4, "little")
            saved = bytes(data)
            self.assertEqual(_efi61_values(EFI61_WRITE, (data,), context), 0)
            self.assertEqual(data, saved)
            self.assertEqual(
                [e[1] for e in context.events if e[0] == "exchange"],
                [b"\x2e\x20\x30" + bytes(4), b"\x2e\x20\x31" + bytes(4)],
            )

    def test_efi59_ten_record_retention_poll_and_native_stop_scope(self):
        for source in (SHA_18, SHA_PLUS):
            for selected in ((), (0,), (5,), (0, 5, 9)):
                data = bytearray(b"Z" * 128)
                data[120:128] = bytes(8)
                for i in range(10):
                    data[i * 12] = i + 10
                    data[i * 12 + 4 : i * 12 + 8] = int(i in selected).to_bytes(
                        4, "little"
                    )
                saved = bytes(data)
                context = Context(source, response=b"\0\1\x11\x4a")
                self.assertEqual(_efi59_routine((data,), context), 0)
                self.assertEqual(data, saved)
                self.assertFalse(any(e[0] == "finalize" for e in context.events))
                self.assertEqual(
                    [e[1] for e in context.events if e[0] == "exchange"],
                    [bytes((0x31, 1, 0x11, 0x4A, i + 10)) for i in selected],
                )
                data[120:124] = (1).to_bytes(4, "little")
                context = Context(source)
                pending = bytes(10)
                result = bytes(4 if i % 2 else 2 for i in range(10))
                context.replies = (
                    iter(
                        (
                            (0, b"\0\3\x11\x4a" + pending),
                            (0, b"\0\3\x11\x4a" + result),
                            (17, b""),
                        )
                    )
                    if selected
                    else iter(((0, b"\0\3\x11\x4a" + result), (17, b"")))
                )
                self.assertEqual(_efi59_routine((data,), context), 0)
                self.assertEqual(data[1:120:12], result)
                self.assertEqual(
                    context.events[-2:],
                    [("session", 1, 1, False, False), ("finalize",)],
                )
            data = bytearray(128)
            data[4:8] = (1).to_bytes(4, "little")
            data[120:124] = (1).to_bytes(4, "little")
            for status, reply, expected in (
                (0, b"\0\3\x11\x4a" + b"\3" * 10, 1008),
                (17, b"", 17),
                (0, b"\0\3\x11\x4a" + b"\2" * 9, 3),
            ):
                context = Context(source)
                context.replies = iter(((status, reply), (19, b"")))
                self.assertEqual(_efi59_routine((data,), context), expected)
                self.assertIn(("exchange", b"\x31\2\x11\x4a"), context.events)
            data[124:128] = (1).to_bytes(4, "little")
            context = Context(source, status=17)
            self.assertEqual(_efi59_routine((data,), context), 0)
            self.assertEqual(
                [e[1] for e in context.events if e[0] == "exchange"],
                [b"\x31\2\x11\x4a"],
            )

    def test_efi52_low_byte_stop_toggle_outputs_and_failed_action_flag(self):
        for source, mode in ((SHA_18, 20), (SHA_PLUS, 20), (SHA_PLUS, 22)):
            for initial, reply, status, expected_action in (
                (0, b"\0\x20\x2b", 0, 0),
                (1, b"\0\x20\x2b", 0, 0),
                (0, b"\0\x20\x2a", 0, 2),
                (1, b"", 17, 2),
            ):
                context = Context(source)
                context.mode = mode
                context.replies = iter(
                    ((0, bytes((0, 0x20, 0x2B, initial))), (status, reply))
                )
                data = bytearray((1).to_bytes(4, "little") + b"\0ZZ")

                def sleep(ms, *, context=context, data=data):
                    context.events.append(("native_sleep", ms))
                    data[4] = 1

                context.native_sleep = sleep
                expected = status or (3 if expected_action == 2 else 0)
                self.assertEqual(_efi52_switch((data,), context), expected)
                self.assertEqual(int.from_bytes(data[:4], "little"), expected_action)
                self.assertEqual(data[5:7], bytes((1, initial)))
                self.assertIn(
                    ("exchange", bytes((0x2E, 0x20, 0x2B, int(initial == 0)))),
                    context.events,
                )
                self.assertEqual(
                    context.events[-2:],
                    [("session", 1, 1, False, False), ("finalize",)],
                )
            context = Context(source, response=b"\0\x20\x2b\2")
            context.mode = mode
            data = bytearray(7)
            self.assertEqual(_efi52_switch((data,), context), 1000)
            self.assertEqual(data, bytes(7))
            context = Context(source)
            context.mode = mode
            data = bytearray(b"ZZZZ\1ZZ")
            self.assertEqual(_efi52_switch((data,), context), 0)
            self.assertFalse(any(e[0] == "exchange" for e in context.events))
            self.assertEqual(data, b"ZZZZ\1ZZ")

    def test_efi53_retained_start_poll_all_results_and_p6_busy_scope(self):
        for source, mode in ((SHA_18, 20), (SHA_PLUS, 20), (SHA_PLUS, 22)):
            for value, expected in ((1, 0), (0, 1000)):
                context = Context(source, response=bytes((0, 0x20, 0x2B, value)))
                context.mode = mode
                data = bytearray(9)
                self.assertEqual(_efi53_routine((data,), context), expected)
                self.assertEqual(
                    context.events.count(("finalize",)), 0 if value == 1 else 1
                )
            for value, expected in ((2, 0), (0, 2000), (3, 2000)):
                context = Context(source)
                context.mode = mode
                data = bytearray((1).to_bytes(4, "little") + bytes(5))
                start = b"\0\1\x11\x40" + (b"X" if mode == 22 else b"")
                terminal = (
                    b"\0\3\x11\x40" + (b"X" if mode == 22 else b"") + bytes((value,))
                )
                pending = (7, b"\x7f\x31\x21") if mode == 22 else (0, b"\0\3\x11\x40\1")
                context.replies = iter(((0, start), pending, (0, terminal)))
                context.native_error = 99
                self.assertEqual(_efi53_routine((data,), context), expected)
                self.assertIn(("exchange", b"\x31\1\x11\x40\2\x65"), context.events)
                self.assertEqual(context.events.count(("native_sleep", 200)), 2)
                self.assertEqual(
                    context.events[-2:],
                    [("session", 1, 1, False, False), ("finalize",)],
                )
                if mode == 22:
                    self.assertEqual(
                        context.events.count(("configure", "native_10a4", 0)), 2
                    )
                    self.assertEqual(
                        context.events.count(("configure", "native_10a4", 99)), 2
                    )
            context = Context(source, response=b"\0\1\x11\x40X")
            context.mode = mode
            data = bytearray(
                (1).to_bytes(4, "little") + (1).to_bytes(4, "little") + b"\1"
            )
            self.assertEqual(_efi53_routine((data,), context), 0)
            self.assertIn(("exchange", b"\x31\1\x11\x40\0\x65"), context.events)
            self.assertEqual(context.events.count(("native_sleep", 200)), 1)
            self.assertFalse(
                any(e == ("exchange", b"\x31\3\x11\x40") for e in context.events)
            )

    def test_efi62_all_actions_distinct_classic_support_and_partial_reads(self):
        for source, mode in ((SHA_18, 20), (SHA_PLUS, 20), (SHA_PLUS, 22)):
            context = Context(source)
            context.mode = mode
            payload = bytearray(32)
            if mode == 22:
                payload[6] = 0xC0
                context.response = b"\0\xa1\x20" + payload
            else:
                payload[5:7] = b"\1\x80"
                context.response = b"\0\x20\0" + payload
            data = bytearray(28)
            self.assertEqual(_efi62_values((data,), context), 0)
            self.assertEqual(data[12:20], (1).to_bytes(4, "little") * 2)
            self.assertEqual(
                context.events[-2:], [("session", 1, 1, False, False), ("finalize",)]
            )
            data[:4] = (1).to_bytes(4, "little")
            context = Context(source)
            context.mode = mode
            context.replies = iter(((0, b"\0\x20\x30ABCD"), (17, b"")))
            self.assertEqual(_efi62_values((data,), context), 17)
            self.assertEqual(data[4:12], b"ABCD" + bytes(4))
            data[:4] = (2).to_bytes(4, "little")
            data[8:12], data[20:28] = b"EFGH", (1).to_bytes(4, "little") * 2
            context = Context(source)
            context.mode = mode
            context.replies = iter(((0, b"\0\x20\x30"), (0, b"\0\x20\x31")))
            self.assertEqual(_efi62_values((data,), context), 0)
            self.assertIn(("exchange", b"\x2e\x20\x30ABCD"), context.events)
            self.assertIn(("exchange", b"\x2e\x20\x31EFGH"), context.events)
            self.assertIn(("session", 3, 1, True, False), context.events)
            data[:4] = (1).to_bytes(4, "little")
            context = Context(source)
            context.mode = mode
            context.sessions = iter((17,))
            self.assertEqual(_efi62_values((data,), context), 17)
            self.assertEqual(data[4:12], bytes(8))

    def test_efi44_transition_exact_manager_and_ignored_native_error(self):
        for source in (SHA_12, SHA_18, SHA_PLUS):
            for mode in (20, 21, 22) if source == SHA_PLUS else (20, 21):
                context = Context(source)
                context.mode = mode
                context.sessions = iter((17,))
                data = bytearray(b"preserved")
                self.assertEqual(_efi_session_transition((data,), context), 0)
                self.assertEqual(data, b"preserved")
                self.assertEqual(
                    context.events[-2:],
                    [("session", 1, 1, False, False), ("finalize",)],
                )
                expected = (
                    "native:1013e7d0"
                    if source == SHA_PLUS and mode == 22
                    else {
                        SHA_12: "native:100aed50",
                        SHA_18: "native:1011d4f0",
                        SHA_PLUS: "native:101392d0",
                    }[source]
                )
                self.assertEqual(context.events[0], ("comm", expected))

    def test_efi54_normal_session_routine_echo_and_native_error_field(self):
        for source in (SHA_18, SHA_PLUS):
            for status, reply, expected in (
                (0, b"\0\1\x11\x93", 0),
                (0, b"\0\1\x11\x93X", 0),
                (0, b"\0\1\x11", 3),
                (0, b"\0\1\x12\x93", 3),
                (7, b"", 0x69),
                (17, b"", 17),
            ):
                context = Context(source, status=status, response=reply)
                context.native_error = 0x69
                data = bytearray(b"ignored")
                self.assertEqual(_efi_throttle((data,), context), expected)
                self.assertEqual(data, b"ignored")
                self.assertIn(("session", 1, 1, False, False), context.events)
                self.assertEqual(context.events[-1], ("finalize",))
                self.assertEqual(
                    context.events.count(("session", 1, 1, False, False)), 1
                )

    def test_public_hv12_support_inline_constants_exact_mode_delta(self):
        from scripts.utility_ex import UtilityEx2TY, UtilityExContext

        for source, path in (
            (
                SHA_12,
                "artifacts/extracted/techstream-12-application/Techstream_Bin/UtilityEx2TY.dll",
            ),
            (
                SHA_18,
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll",
            ),
            (
                SHA_PLUS,
                "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll",
            ),
        ):
            if not Path(path).is_file():
                self.skipTest("Exact supplied source absent")
            for mode in (19, 20, 21, 22, 23):
                context = UtilityExContext(
                    Path(path).read_bytes(), Host(mode), None, None
                )
                engine = UtilityEx2TY(context)
                data = bytearray(b"unchanged")
                expected = (
                    180000
                    if mode in (20, 21) or (source == SHA_PLUS and mode == 22)
                    else 99
                )
                self.assertEqual(engine.invoke(HV12_SUPPORT, (data,)), expected)
                self.assertEqual(data, b"unchanged")
                self.assertFalse(engine.worker.running)
                self.assertNotIn("native_global:10118e38", context.state)
                with self.assertRaises(ValueError):
                    engine.invoke(HV12_SUPPORT, ())

    def test_hv12_selected_support_dtc_eeprom_status_and_update_deltas(self):
        for source in (SHA_12, SHA_18, SHA_PLUS):
            raw = bytearray(4128)
            raw[:19] = b"\x92\x11" + bytes(16) + b"\xff"
            offsets = [4128] * 256
            offsets[0x92] = 0
            context = Context(source)
            context.snapshots = iter(((0, bytes(raw), tuple(offsets)),))
            data = bytearray(b"Z" * 12)
            self.assertEqual(_hv12_selected(HV12_SUPPORT, (data,), context), 0)
            self.assertEqual(data, b"\2\0\0\0ZZZZ\3\0\0\0")
            for dtcs, expected in (
                ((0, b"\x53\0"), 140000),
                ((0, b"\x53\1"), 130000),
                ((17, b"\x53\1"), 17),
            ):
                context = Context(source)
                context.dtcs = dtcs
                self.assertEqual(
                    _hv12_selected(HV12_AFTER, (bytearray(),), context), expected
                )
            for status, reply, expected, value in (
                (0, b"\0\x92\x13", 110000, 0x13),
                (0, b"\0\x92\x14", 150000, 0x14),
                (0, b"\0\x92\x12", 170000, 0x12),
                (3, b"", 1460, 0),
                (17, b"\0\x92\x12", 17, 0x12),
            ):
                context = Context(source, status=status, response=reply)
                context.dtcs = 0, b"\x53\0"
                data = bytearray((2).to_bytes(4, "little") + b"ZZZZ")
                self.assertEqual(
                    _hv12_selected(HV12_DTC_STATUS, (data,), context), expected
                )
                self.assertEqual(data[4:8], value.to_bytes(4, "little"))
                self.assertIn(("native_sleep", 1000), context.events)
                self.assertLess(
                    next(
                        i for i, e in enumerate(context.events) if e[0] == "configure"
                    ),
                    next(
                        i for i, e in enumerate(context.events) if e[0] == "initialize"
                    ),
                )
            for status, reply, expected in (
                (0, b"\0\x1f", 120000),
                (0, b"\0\x1fextra", 120000),
                (0, b"\0\x1e", 130000),
                (17, b"", 130000),
            ):
                context = Context(source, status=status, response=reply)
                self.assertEqual(
                    _hv12_selected(HV12_UPDATE, (bytearray(),), context), expected
                )
                self.assertIn(
                    ("exchange", b"\x3b\x1f" + bytes((source == SHA_PLUS,))),
                    context.events,
                )
                self.assertEqual(context.events[-1], ("finalize",))

    def test_hv11_hv13_length_only_and_unsliced_native_delay(self):
        for source in (SHA_12, SHA_18, SHA_PLUS):
            for export, identifier in ((HV_SERVICE, 0x21), (HV_READY_CANCEL, 0x23)):
                for status, reply, result in (
                    (0, b"\x00\xff", 0),
                    (0, b"", 3),
                    (0, bytes(3), 3),
                    (17, b"", 17),
                ):
                    context = Context(source, status=status, response=reply)
                    self.assertEqual(_hv_reset(export, (), context), result)
                    self.assertIn(
                        ("exchange", bytes((0x3B, identifier, 1))), context.events
                    )
                    waits = [e for e in context.events if e[0] == "native_sleep"]
                    self.assertEqual(
                        waits,
                        [("native_sleep", 10000)] if export == HV_READY_CANCEL else [],
                    )
                    self.assertEqual(context.events[-1], ("finalize",))
                context = Context(source, init_status=17)
                self.assertEqual(_hv_reset(export, (), context), 17)
                self.assertFalse(
                    any(e[0] in ("exchange", "native_sleep") for e in context.events)
                )

    def test_hv_reset_literal_reply_cleanup_fault_and_cancellation(self):
        for source in (SHA_12, SHA_18, SHA_PLUS):
            for export, identifier in (
                (HV_HISTORY_RESET, 0x31),
                (HV_BATTERY_RESET, 0x1F),
            ):
                for status, reply, expected in (
                    (0, bytes((0, identifier)), 0),
                    (0, bytes((0x7B, identifier)), 0),
                    (0, bytes((0x7B, identifier, 0)), 3),
                    (0, b"", 3),
                    (0, bytes((0x7B, identifier ^ 1)), 3),
                    (17, b"", 17),
                ):
                    with self.subTest(source=source[:12], export=export, reply=reply):
                        context = Context(source, status=status, response=reply)
                        self.assertEqual(_hv_reset(export, (), context), expected)
                        self.assertIn(
                            ("exchange", bytes((0x3B, identifier, 1))), context.events
                        )
                        self.assertEqual(context.events[-1], ("finalize",))
                context = Context(source, init_status=19)
                self.assertEqual(_hv_reset(export, (), context), 19)
                self.assertFalse(any(e[0] == "exchange" for e in context.events))
                for fault in (Cancelled("cancel"), RuntimeError("primary")):
                    context = Context(source)
                    context.fault = fault
                    context.finalize_fault = OSError("cleanup")
                    with self.assertRaises(type(fault)) as raised:
                        _hv_reset(export, (), context)
                    self.assertIs(raised.exception, fault)
                    self.assertEqual(context.events.count(("finalize",)), 1)
                context = Context(source)
                context.cancelled = True
                with self.assertRaises(Cancelled):
                    _hv_reset(export, (), context)
                self.assertEqual(context.events[-1], ("finalize",))

    def test_all_admitted_source_export_pairs_through_public_wrappers_on_lower_fault(
        self,
    ):
        from scripts.utility_ex import UtilityEx2TY, UtilityExContext

        no_args = {
            ECO_STARTS_RESET,
            "Ex2PSADSG_01_ClearWheelIdentifires",
            ECD_ASH_CLEAR,
            ECD_RESET55,
            EFI_PM_STOP,
            EFI_LEARNING_RESET,
            HNSCR_RESET,
            HV_HISTORY_RESET,
            HV_BATTERY_RESET,
            HV_READY_CANCEL,
            HV_SERVICE,
        }
        for source, path in (
            (
                SHA_12,
                "artifacts/extracted/techstream-12-application/Techstream_Bin/UtilityEx2TY.dll",
            ),
            (
                SHA_18,
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll",
            ),
            (
                SHA_PLUS,
                "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll",
            ),
        ):
            if not Path(path).exists():
                self.skipTest("Exact supplied source absent")
            for export in supported_exports(source):
                with self.subTest(source=source[:12], export=export):
                    mode = (
                        4
                        if export.startswith(("Ex2ASG_02_", "Ex2AMT_01_"))
                        or export
                        in (
                            EFI_LEARNING_RESET,
                            HV_HISTORY_RESET,
                            HV_BATTERY_RESET,
                            HV10_SUPPORT,
                            HV10_READ,
                            HV10_WAIT,
                            HV10_JUDGE,
                            HV12_SUPPORT,
                            HV12_DTC_STATUS,
                            HV12_UPDATE,
                            HV12_AFTER,
                            HV14_SUPPORT,
                            HV14_TEMPERATURE,
                            HV14_VOLTAGE,
                            HV_READY_CANCEL,
                            HV_SERVICE,
                            HV_HISTORY_READ,
                            HV_BATTERY_WRITE,
                            HV_BATTERY_CLEAR,
                            HV_ACCELERATOR,
                            HV_ACCELERATOR_CLEAR,
                        )
                        else 19
                        if export.startswith("Ex2PSA")
                        else 20
                    )
                    context = UtilityExContext(
                        Path(path).read_bytes(), Host(mode), None, None
                    )
                    engine = UtilityEx2TY(context)
                    control = Context(source, status=17, init_status=17)
                    args = () if export in no_args else (bytearray(8192),)
                    expected = (
                        0
                        if export in (EFI_PM_STOP, EFI_SESSION_TRANSITION)
                        else 1001
                        if export == ECD_DUMMY59
                        else 1000
                        if export == ECD_DUMMY60
                        else 17
                    )
                    if export == ECD_CHAR:
                        args = (ord("F"),)
                        expected = 15
                    elif export == ECD_HEX:
                        args = (
                            "12\0".encode("utf-16-le")
                            if source == SHA_PLUS
                            else b"12\0",
                            bytearray(1),
                            1,
                        )
                        expected = 0
                    with patch.object(context, "comm", return_value=control):
                        actual = engine.invoke(export, args)
                        if export not in (ECD_CHAR, ECD_HEX):
                            self.assertEqual(actual, 15)
                            actual = engine.worker.get_status()
                        self.assertEqual(actual, expected)

    def test_hnscr_reset_normal_first_keepalive_restore_and_exact_echo(self):
        for source in (SHA_18, SHA_PLUS):
            for status, reply, expected in (
                (0, b"\0\1\x12\1x", 0),
                (0, b"\0\1\x12\1", 3),
                (0, b"\0\1\x13\1x", 3),
                (19, b"", 19),
            ):
                context = Context(source, status=status, response=reply)
                context.sessions = iter((0, 17))
                self.assertEqual(_hnscr_reset((), context), expected)
                self.assertIn(("session", 3, 1, True, False), context.events)
                self.assertIn(("session", 1, 1, False, True), context.events)
                self.assertIn(("native_sleep", 30), context.events)
                self.assertEqual(context.events[-1], ("finalize",))
            context = Context(source)
            context.sessions = iter((19,))
            self.assertEqual(_hnscr_reset((), context), 19)
            self.assertFalse(any(e[0] == "exchange" for e in context.events))
            self.assertEqual(context.events[-1], ("finalize",))

    def test_efi_learning_reset_setter_before_initialize_length_only_replies_and_delays(
        self,
    ):
        for source in (SHA_12, SHA_18, SHA_PLUS):
            context = Context(source)
            context.replies = iter(((0, b"xy"), (0, b"z")))
            self.assertEqual(_efi_learning_reset((), context), 0)
            self.assertEqual(
                [e[0] for e in context.events[:3]], ["comm", "configure", "initialize"]
            )
            self.assertEqual(
                [e[1] for e in context.events if e[0] == "exchange"],
                [b"\x3b\x1e\x5a", b"\x04"],
            )
            self.assertEqual(
                [e[1] for e in context.events if e[0] == "native_sleep"], [1000, 2000]
            )
            self.assertEqual(context.events[-1], ("finalize",))
            for first, second, expected, sleeps in (
                ((19, b""), (0, b"z"), 19, []),
                ((0, b"x"), (0, b"z"), 3, []),
                ((0, b"xy"), (19, b""), 19, [1000]),
                ((0, b"xy"), (0, b"zz"), 3, [1000]),
            ):
                context = Context(source)
                context.replies = iter((first, second))
                self.assertEqual(_efi_learning_reset((), context), expected)
                self.assertEqual(
                    [e[1] for e in context.events if e[0] == "native_sleep"], sleeps
                )
                self.assertEqual(context.events[-1], ("finalize",))
            context = Context(source, init_status=19)
            self.assertEqual(_efi_learning_reset((), context), 19)
            self.assertEqual(
                [e[0] for e in context.events],
                ["comm", "configure", "initialize", "finalize"],
            )

    def test_exact_public_amt_workers_variant_layout_and_native_mode_guard(self):
        from scripts.utility_ex import UtilityEx2TY, UtilityExContext

        for source, path, count in (
            (
                SHA_12,
                "artifacts/extracted/techstream-12-application/Techstream_Bin/UtilityEx2TY.dll",
                34,
            ),
            (
                SHA_18,
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll",
                46,
            ),
            (
                SHA_PLUS,
                "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll",
                46,
            ),
        ):
            if not Path(path).exists():
                self.skipTest("Exact supplied source absent")
            raw, offsets = bytearray(4128), [4128] * 256
            raw[:4] = b"\xa1\2ab"
            offsets[0xA1] = 0
            control = Context(source)
            control.snapshots = iter(((0, bytes(raw), tuple(offsets)),) * 2)
            control.replies = iter(
                ((0, b"\0\xa1" + bytes(range(count))), (0, b"\0\xa1"))
            )
            host = Host(4)
            context = UtilityExContext(Path(path).read_bytes(), host, None, None)
            engine = UtilityEx2TY(context)
            data = bytearray(156)
            with patch.object(context, "comm", return_value=control):
                for export in (AMT_HISTORY_SUPPORT, AMT_HISTORY_READ):
                    self.assertEqual(engine.invoke(export, (data,)), 15)
                    self.assertEqual(engine.worker.get_status(), 0)
                self.assertEqual(data[:count], bytes(range(count)))
                data[144:148], data[152:156] = (
                    (2).to_bytes(4, "little"),
                    (3).to_bytes(4, "little"),
                )
                self.assertEqual(engine.invoke(AMT_HISTORY_WRITE, (data,)), 15)
                self.assertEqual(engine.worker.get_status(), 0)
            request = b"\x3b\xa1" + bytes(range(count if source == SHA_12 else 2))
            self.assertIn(("exchange", request), control.events)
            self.assertEqual(control.events.count(("finalize",)), 3)
            host.mode = 20
            context.refresh_parameters()
            self.assertEqual(engine.invoke(AMT_HISTORY_READ, (data,)), 99)

    def test_amt_support_variant_layout_partial_updates_and_retained_length(self):
        def snapshot(payload):
            raw, offsets = bytearray(4128), [4128] * 256
            offsets[0xA1] = 0
            raw[: len(payload) + 2] = bytes((0xA1, len(payload))) + payload
            return bytes(raw), tuple(offsets)

        for source, count, first, size in (
            (SHA_12, 34, 40, 108),
            (SHA_18, 46, 52, 148),
            (SHA_PLUS, 46, 52, 148),
        ):
            context = Context(source)
            context.snapshots = iter(((0, *snapshot(b"abc")), (0, *snapshot(b"de"))))
            data = bytearray(b"Z" * size)
            self.assertEqual(_amt_history_support((data,), context), 0)
            self.assertEqual(data[first : first + count], b"abc" + bytes(count - 3))
            self.assertEqual(
                data[first + count : first + count * 2], b"de" + bytes(count - 2)
            )
            self.assertEqual(data[:first], b"Z" * first)
            if source != SHA_12:
                self.assertEqual(int.from_bytes(data[144:148], "little"), 2)
            context = Context(source)
            context.snapshots = iter(((0, *snapshot(b"abc")), (19, b"", ())))
            data = bytearray(b"Z" * size)
            self.assertEqual(_amt_history_support((data,), context), 19)
            self.assertEqual(data[first : first + count], b"abc" + bytes(count - 3))
            self.assertEqual(data[first + count : first + count * 2], b"Z" * count)
            if source != SHA_12:
                self.assertEqual(int.from_bytes(data[144:148], "little"), 3)
            self.assertEqual(context.events[-1], ("finalize",))
            context = Context(source)
            context.snapshots = iter(((0, *snapshot(bytes(count + 1))),))
            with self.assertRaises(ValueError):
                _amt_history_support((bytearray(size),), context)
            self.assertEqual(context.events[-1], ("finalize",))

    def test_asg_support_two_snapshots_exact_positions_and_partial_failure(self):
        def snapshot(records):
            raw, offsets = bytearray(4128), [4128] * 256
            cursor = 0
            for pid, payload in records:
                offsets[pid] = cursor
                raw[cursor : cursor + len(payload) + 2] = (
                    bytes((pid, len(payload))) + payload
                )
                cursor += len(payload) + 2
            return bytes(raw), tuple(offsets)

        primary = snapshot(
            ((0x89, b"\0\0" + b"\xff" * 8), (0x8A, b"\0\0" + b"\xff" * 38))
        )
        command = snapshot(((0x42, b"\x40\x40\0\1"),))
        for source in (SHA_12, SHA_18, SHA_PLUS):
            context = Context(source)
            context.snapshots = iter(((0, *primary), (0, *command)))
            data = bytearray(24)
            self.assertEqual(_asg_support((data,), context), 0)
            self.assertEqual(
                [int.from_bytes(data[i : i + 4], "little") for i in range(0, 24, 4)],
                [10, 6, 40, 21, 33, 6],
            )
            self.assertEqual(
                [e for e in context.events if e[0] == "support_snapshot"],
                [("support_snapshot", 1), ("support_snapshot", 2)],
            )
            self.assertEqual(context.events[-1], ("finalize",))
            context = Context(source)
            context.snapshots = iter(((0, *primary), (17, b"", ())))
            data = bytearray(b"Z" * 24)
            self.assertEqual(_asg_support((data,), context), 17)
            self.assertEqual(data[20:24], b"ZZZZ")
            self.assertNotEqual(data[:20], b"Z" * 20)
            context = Context(source)
            context.snapshots = iter(
                ((0, *primary), (0, *snapshot(((0x42, b"\x40\x01"),))))
            )
            self.assertEqual(_asg_support((bytearray(24),), context), 22)
            context = Context(source)
            # Native checks89 before touching the malformed8A record.
            offsets = [4128] * 256
            offsets[0x8A] = 4127
            context.snapshots = iter(((0, bytes(4128), tuple(offsets)),))
            data = bytearray(b"Z" * 24)
            self.assertEqual(_asg_support((data,), context), 22)
            self.assertEqual(data, b"Z" * 24)
            context = Context(source)
            context.snapshots = iter(((0, b"", ()),))
            with self.assertRaises(ValueError):
                _asg_support((bytearray(24),), context)
            self.assertEqual(context.events[-1], ("finalize",))

    def test_amt_history_exact_variant_copy_lengths_and_unconditional_error_output(
        self,
    ):
        for source, count in ((SHA_12, 34), (SHA_18, 46), (SHA_PLUS, 46)):
            for status, reply, expected in (
                (0, b"\x00\xa1abcdef", 0),
                (0, b"\x00\xa0abcdef", 3),
                (19, b"\x00\xa1abcdef", 19),
                (0, b"", 3),
            ):
                context = Context(source, status=status, response=reply)
                data = bytearray(b"Z" * (count + 10))
                self.assertEqual(_amt_history(False, (data,), context), expected)
                self.assertEqual(data[:count], reply[2:].ljust(count, b"\0"))
                self.assertEqual(data[count : count + 2], b"ZZ")
                self.assertEqual(
                    int.from_bytes(data[count + 2 : count + 6], "little"), len(reply)
                )
                self.assertEqual(data[count + 6 :], b"ZZZZ")
                self.assertEqual(context.events[-1], ("finalize",))
            data = bytearray(range(156))
            if source == SHA_12:
                context = Context(source, response=b"\0\xa1")
                self.assertEqual(_amt_history(True, (data,), context), 0)
                self.assertIn(
                    ("exchange", b"\x3b\xa1" + bytes(range(34))), context.events
                )
            else:
                for kind, length, size in (
                    (0, 99, 2),
                    (2, 8, 12),
                    (3, 8, 10),
                    (2, 44, 48),
                    (3, 46, 48),
                ):
                    context = Context(source, response=b"\0\xa1")
                    data[152:156] = kind.to_bytes(4, "little")
                    data[144:148] = data[148:152] = length.to_bytes(4, "little")
                    self.assertEqual(_amt_history(True, (data,), context), 0)
                    self.assertIn(
                        ("exchange", (b"\x3b\xa1" + bytes(range(46)))[:size]),
                        context.events,
                    )
                data[152:156] = (2).to_bytes(4, "little")
                data[148:152] = (45).to_bytes(4, "little")
                context = Context(source)
                with self.assertRaises(ValueError):
                    _amt_history(True, (data,), context)
                self.assertEqual(context.events, [])

    def test_asg_initial_learning_retry_counter_wire_bytes_and_retained_manager(self):
        for source in (SHA_12, SHA_18, SHA_PLUS):
            data = bytearray(36)
            for offset, value in ((0, 4), (4, 2), (8, 5), (12, 1), (16, 2), (20, 7)):
                data[offset : offset + 4] = value.to_bytes(4, "little")
            context = Context(source)
            context.replies = iter(((19, b""), (0, b"xx"), (0, b"abCD"), (0, b"abcde")))
            self.assertEqual(_asg_learning(ASG_INITIAL, (data,), context), 0)
            self.assertEqual(data[28:30], b"DC")
            self.assertEqual(data[24:28], b"bcde")
            self.assertEqual(data[30], 1)
            self.assertEqual(int.from_bytes(data[32:36], "little"), 1)
            self.assertEqual(
                context.events.count(("exchange", b"\x30\x42\0\x40\x40\0\0")), 2
            )
            self.assertIn(("native_sleep", 100), context.events)
            self.assertIn(("native_sleep", 3000), context.events)
            self.assertNotIn(("finalize",), context.events)
            for status in (5, 1460, 19):
                context = Context(source, status=status, response=b"")
                data = bytearray(36)
                self.assertEqual(_asg_learning(ASG_INITIAL, (data,), context), status)
                self.assertEqual(
                    int.from_bytes(data[32:36], "little"), 2 if status == 19 else 0
                )
                self.assertEqual(context.events[-1], ("finalize",))

    def test_asg_retention_terminal_flags_initialization_faults_and_bounds(self):
        for source in (SHA_12, SHA_18, SHA_PLUS):
            for value, flag, close in (
                (127, 0, True),
                (127, 1, False),
                (255, 1, True),
                (2, 0, False),
            ):
                context = Context(source)
                context.replies = iter(((0, b"abcd"), (0, bytes((0, value, 2, 3, 4)))))
                data = bytearray(36)
                for offset, field in ((0, 4), (4, 2), (8, 5), (12, 1), (16, 2)):
                    data[offset : offset + 4] = field.to_bytes(4, "little")
                data[31] = flag
                self.assertEqual(_asg_learning(ASG_STATUS, (data,), context), 0)
                self.assertEqual(("finalize",) in context.events, close)
            for flag in (0, 1):
                data = bytearray(36)
                data[30], data[32] = flag, 2
                context = Context(source)
                self.assertEqual(_asg_learning(ASG_INITIAL, (data,), context), 0)
                self.assertFalse(any(e[0] == "exchange" for e in context.events))
                self.assertEqual(("finalize",) in context.events, flag == 0)
            for export in (ASG_INITIAL, ASG_STATUS, ASG_STATUS_TIMEOUT, ASG_STATUS_004):
                context = Context(source)
                context.fault = RuntimeError("wire fault")
                with self.assertRaises(RuntimeError):
                    _asg_learning(export, (bytearray(36),), context)
                self.assertEqual(context.events[-1], ("finalize",))
            for offset, value in ((4, 4127), (12, 4128), (16, 4126), (20, 4129)):
                data = bytearray(36)
                data[offset : offset + 4] = value.to_bytes(4, "little")
                context = Context(source)
                with self.assertRaises(ValueError):
                    _asg_learning(ASG_STATUS, (data,), context)
                self.assertEqual(context.events, [])

    def test_asg_status_distinct_initialization_finalize_and_partial_outputs(self):
        for source in (SHA_12, SHA_18, SHA_PLUS):
            for export in (ASG_STATUS, ASG_STATUS_TIMEOUT, ASG_STATUS_004):
                for flag in (0, 1):
                    context = Context(
                        source, init_status=19 if export == ASG_STATUS_TIMEOUT else 0
                    )
                    context.replies = iter(((0, b"abcd"), (0, b"a\x7fcde")))
                    data = bytearray(36)
                    for offset, value in ((0, 4), (4, 2), (8, 5), (12, 1), (16, 2)):
                        data[offset : offset + 4] = value.to_bytes(4, "little")
                    data[30], data[31] = flag, 1
                    self.assertEqual(_asg_learning(export, (data,), context), 0)
                    self.assertEqual(data[28:30], b"dc")
                    self.assertEqual(data[24:28], b"\x7fcde")
                    self.assertEqual(
                        ("finalize",) in context.events, export == ASG_STATUS_TIMEOUT
                    )
                    self.assertEqual(
                        context.events.count(("initialize", 0)),
                        1 if export == ASG_STATUS_004 or flag else 0,
                    )
            context = Context(source, init_status=19)
            self.assertEqual(
                _asg_learning(ASG_STATUS_004, (bytearray(36),), context), 19
            )
            self.assertEqual(context.events.count(("initialize", 0)), 10)
            self.assertEqual(context.events.count(("native_sleep", 1000)), 10)
            context = Context(source, status=19, response=b"abcd")
            data = bytearray(36)
            data[4] = 2
            data[24:30] = b"ZZZZZZ"
            self.assertEqual(_asg_learning(ASG_STATUS, (data,), context), 19)
            self.assertEqual(data[24:30], b"ZZZZdc")
            self.assertEqual(context.events[-1], ("finalize",))

    def test_asg_learned_flag_raw_indexes_output_on_wire_error_and_bounds(self):
        for source in (SHA_12, SHA_18, SHA_PLUS):
            for status, expected_length, expected in (
                (0, 5, 0),
                (0, 6, 3),
                (19, 5, 19),
            ):
                context = Context(source, status=status, response=b"abcde")
                data = bytearray(32)
                data[8:12] = expected_length.to_bytes(4, "little")
                data[12:16] = (1).to_bytes(4, "little")
                data[16:20] = (3).to_bytes(4, "little")
                self.assertEqual(_asg_learned_flag((data,), context), expected)
                self.assertEqual(data[24:28], b"bde\0")
                self.assertIn(("exchange", b"\x21\x8a"), context.events)
                self.assertEqual(context.events[-1], ("finalize",))
            context = Context(source, init_status=19)
            data = bytearray(28)
            data[24:28] = b"keep"
            self.assertEqual(_asg_learned_flag((data,), context), 19)
            self.assertEqual(data[24:28], b"keep")
            for offset, value in ((12, 4128), (16, 4126), (12, 0xFFFFFFFF)):
                data = bytearray(28)
                data[offset : offset + 4] = value.to_bytes(4, "little")
                context = Context(source)
                with self.assertRaises(ValueError):
                    _asg_learned_flag((data,), context)
                self.assertEqual(context.events, [])

    def test_exact_public_pm_worker_sequence_retained_connection_and_errors(self):
        from scripts.utility_ex import UtilityEx2TY, UtilityExContext

        for source, path in (
            (
                SHA_18,
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll",
            ),
            (
                SHA_PLUS,
                "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll",
            ),
        ):
            if not Path(path).exists():
                self.skipTest("Exact supplied source absent")
            host = Host(20)
            context = UtilityExContext(Path(path).read_bytes(), host, None, None)
            engine = UtilityEx2TY(context)
            control = Context(source)
            control.replies = iter(
                (
                    (0, b"\x62\x11\0" + bytes(14) + b"\x0c" + bytes(17)),
                    (0, b"\x71\1\x11\x3e"),
                    (0, b"\x71\3\x11\x3e\2"),
                    (0, b"\x62\x11\x75a"),
                    (0, b"\x62\x11\x76b"),
                    (0, b"\x71\3\x11\x3e\2"),
                    (0, b"\x62\x12\x1a\4"),
                    (19, b""),
                )
            )
            data = bytearray(19)
            with patch.object(context, "comm", return_value=control):
                for export, args, expected in (
                    (EFI_PM_SUPPORT, (data,), 0),
                    (EFI_PM_START, (data,), 0),
                    (EFI_PM_RESULT, (data,), 0),
                    (EFI_PM_READ, (data,), 0),
                    (EFI_PM_WAIT_STOP, (bytearray(8),), 1007),
                    (EFI_PM_STOP, (), 0),
                ):
                    self.assertEqual(engine.invoke(export, args), 15)
                    self.assertEqual(engine.worker.get_status(), expected)
            self.assertEqual(data[16:19], b"\x0cab")
            self.assertEqual(control.events.count(("initialize", 0)), 3)
            self.assertEqual(control.events.count(("finalize",)), 4)
            context = UtilityExContext(Path(path).read_bytes(), Host(20), None, None)
            engine = UtilityEx2TY(context)
            control = Context(source)
            control.fault = RuntimeError("injected lower fault")
            with patch.object(context, "comm", return_value=control):
                self.assertEqual(engine.invoke(EFI_PM_START, (bytearray(1),)), 15)
                with self.assertRaisesRegex(RuntimeError, "injected lower fault"):
                    engine.worker.get_status()
            self.assertEqual(control.events[-1], ("finalize",))

    def test_pm_wait_stop_reason_mapping_native_retention_and_fault_cleanup(self):
        for source in (SHA_18, SHA_PLUS):
            for reason, expected in (
                (1, 1013),
                (3, 1014),
                (4, 1007),
                (5, 1008),
                (6, 1009),
                (7, 1010),
                (8, 1011),
                (9, 1012),
                (0, 3),
            ):
                context = Context(source)
                context.replies = iter(
                    (
                        (0, b"\x71\3\x11\x3e\1"),
                        (0, b"\x71\3\x11\x3e\2"),
                        (0, bytes((0x62, 0x12, 0x1A, reason))),
                    )
                )
                self.assertEqual(_pm_wait_stop((bytearray(8),), context), expected)
                self.assertEqual(context.events[-1], ("finalize",))
            for wire_status, expected in ((2, 1001), (19, 19), (1002, 1002)):
                context = Context(source)
                context.replies = iter(((wire_status, b""), (19, b"")))
                self.assertEqual(_pm_wait_stop((bytearray(8),), context), expected)
                self.assertEqual(("finalize",) in context.events, wire_status != 1002)
                self.assertIn(("exchange", b"\x31\2\x11\x3e"), context.events)
            context = Context(source)
            data = bytearray(8)
            data[4] = 1
            self.assertEqual(_pm_wait_stop((data,), context), 1002)
            self.assertEqual(
                context.events,
                [
                    (
                        "comm",
                        "native:1011d4f0" if source == SHA_18 else "native:101392d0",
                    )
                ],
            )
            context = Context(source)
            context.fault = RuntimeError("wire fault")
            with self.assertRaises(RuntimeError):
                _pm_wait_stop((bytearray(8),), context)
            self.assertEqual(context.events[-1], ("finalize",))

    def test_pm_start_retains_exact_manager_and_all_native_error_mapping(self):
        for source in (SHA_18, SHA_PLUS):
            context = Context(source, response=b"\x71\1\x11\x3e")
            self.assertEqual(_pm_start((bytearray(b"\1"),), context), 0)
            self.assertNotIn(("finalize",), context.events)
            self.assertEqual(len([e for e in context.events if e[0] == "session"]), 2)
            self.assertIn(("exchange", b"\x31\1\x11\x3e\0"), context.events)
            for reason in range(3, 11):
                context = Context(source)
                context.native_error = 0x69
                context.replies = iter(
                    ((19, b""), (17, b""), (0, bytes((0x62, 0x12, 0x1A, reason))))
                )
                context.sessions = iter((0, 0, 23))
                self.assertEqual(
                    _pm_start((bytearray(b"\0"),), context),
                    1007 + reason - 4 if 4 <= reason <= 9 else 3,
                )
                self.assertEqual(context.events[-1], ("finalize",))
                self.assertIn(("exchange", b"\x31\1\x11\x3e\xff"), context.events)
            for native_error, expected in ((0x6B, 1006), (0, 19)):
                context = Context(source)
                context.native_error = native_error
                context.replies = iter(((19, b""), (0, b"")))
                self.assertEqual(_pm_start((bytearray(1),), context), expected)
                self.assertEqual(context.events.count(("read_field", "native_10b0")), 2)
                self.assertEqual(context.events[-1], ("finalize",))
            context = Context(source)
            context.native_error = 0x69
            context.replies = iter(((19, b""), (0, b""), (17, b"")))
            self.assertEqual(_pm_start((bytearray(1),), context), 17)
            self.assertEqual(context.events[-1], ("finalize",))

    def test_pm_result_persistent_lifecycle_stop_and_native_cancel_flag(self):
        for source in (SHA_18, SHA_PLUS):
            context = Context(source)
            context.replies = iter(((0, b"\x71\3\x11\x3e\1"), (0, b"\x71\3\x11\x3e\2")))
            context.sessions = iter((19,))
            data = bytearray(16)
            self.assertEqual(_pm_result(EFI_PM_RESULT, (data,), context), 0)
            self.assertEqual(data[8:12], b"\1\0\0\0")
            self.assertEqual(context.events.count(("native_sleep", 200)), 2)
            self.assertFalse(any(e[0] == "initialize" for e in context.events))
            self.assertEqual(context.events[-1], ("finalize",))
            context = Context(source)
            data = bytearray(16)
            data[12] = 1
            self.assertEqual(_pm_result(EFI_PM_RESULT, (data,), context), 3)
            self.assertFalse(any(e[0] == "exchange" for e in context.events))
            for status, reply, expected in (
                (19, b"", 19),
                (0, b"\x71\3\x11\x3e", 3),
                (0, b"\x71\3\x11\x3f\2", 3),
            ):
                context = Context(source, status=status, response=reply)
                self.assertEqual(
                    _pm_result(EFI_PM_RESULT, (bytearray(16),), context), expected
                )
                self.assertEqual(context.events[-1], ("finalize",))
            context = Context(source, status=19)
            self.assertEqual(_pm_result(EFI_PM_STOP, (), context), 0)
            self.assertEqual(
                context.events,
                [
                    (
                        "comm",
                        "native:1011d4f0" if source == SHA_18 else "native:101392d0",
                    ),
                    ("exchange", b"\x31\2\x11\x3e"),
                ],
            )

    def test_pm_support_exact_length_and_selected_flags_compact_partial_outputs(self):
        for source in (SHA_18, SHA_PLUS):
            context = Context(
                source, response=b"\x62\x11\0" + bytes(14) + b"\x0c" + bytes(17)
            )
            context.sessions = iter((0, 0, 19))
            data = bytearray(19)
            self.assertEqual(_pm_read(EFI_PM_SUPPORT, (data,), context), 0)
            self.assertEqual(data[16], 12)
            self.assertEqual(context.events[-1], ("finalize",))
            for bits, expected_requests, expected_output in (
                (0, [], b"ZZ"),
                (4, [0x76], b"aZ"),
                (8, [0x75], b"aZ"),
                (12, [0x75, 0x76], b"ab"),
            ):
                context = Context(source)
                context.replies = iter(
                    (0, bytes((0x62, 0x11, identifier, ord("a") + index)))
                    for index, identifier in enumerate(expected_requests)
                )
                data = bytearray(17) + bytearray(b"ZZ")
                data[16] = bits
                self.assertEqual(_pm_read(EFI_PM_READ, (data,), context), 0)
                self.assertEqual(data[17:19], expected_output)
                self.assertEqual(
                    [e[1] for e in context.events if e[0] == "exchange"],
                    [
                        bytes((0x22, 0x11, identifier))
                        for identifier in expected_requests
                    ],
                )
            context = Context(source)
            context.replies = iter(((0, b"\x62\x11\x75a"), (19, b"")))
            data = bytearray(17) + bytearray(b"ZZ")
            data[16] = 12
            self.assertEqual(_pm_read(EFI_PM_READ, (data,), context), 19)
            self.assertEqual(data[17:], b"aZ")
            for export, response in (
                (EFI_PM_SUPPORT, b"\x62\x11\0" + bytes(31)),
                (EFI_PM_READ, b"\x62\x11\x74a"),
            ):
                context = Context(source, response=response)
                data = bytearray(19)
                data[16] = 8
                self.assertEqual(_pm_read(export, (data,), context), 3)
                self.assertEqual(data[16], 8)

    def test_exact_public_worker_wrapper_aggregator_body_and_mutable_output(self):
        from scripts.utility_ex import UtilityEx2TY, UtilityExContext

        for version in ("12", "18"):
            path = Path(
                f"artifacts/extracted/techstream-{version}-application/Techstream_Bin/UtilityEx2TY.dll"
            )
            if not path.exists():
                self.skipTest("Exact supplied source absent")
            host = Host(19)
            context = UtilityExContext(path.read_bytes(), host, None, None)
            engine = UtilityEx2TY(context)
            control = Context(context.module_sha256)
            control.replies = iter(((0, b"\x61\xb3" + b"Z" * 36), (0, b"\x74\2")))
            data = bytearray(40)
            data[20:24] = b"keep"
            with patch.object(context, "comm", return_value=control):
                self.assertEqual(engine.invoke(PSA_WHEEL_ADDITIONAL, (data,)), 15)
                self.assertEqual(engine.worker.get_status(), 0)
            self.assertEqual(host.waits, [1000, 1000])
            self.assertEqual(data[20:24], b"keep")
            self.assertEqual(data[:20], b"Z" * 20)
            self.assertEqual(control.events[-1], ("finalize",))
            host.mode = 20
            context.refresh_parameters()
            self.assertEqual(engine.invoke(PSA_WHEEL_ADDITIONAL, (data,)), 99)
            with self.assertRaises(ValueError):
                engine.invoke(PSA_WHEEL_ADDITIONAL, ())

    def test_new_bodies_through_exact_source_aggregator(self):
        from scripts.utility_ex_ty import run_body as aggregate_body

        for source, path in (
            (
                SHA_12,
                "artifacts/extracted/techstream-12-application/Techstream_Bin/UtilityEx2TY.dll",
            ),
            (
                SHA_18,
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll",
            ),
            (
                SHA_PLUS,
                "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll",
            ),
        ):
            if not Path(path).exists():
                self.skipTest("Exact supplied source absent")
            cases = []
            if source in (SHA_12, SHA_18):
                cases += [
                    (
                        PSA_WHEEL_MAIN,
                        bytearray(range(16)),
                        [(0, b"\x61\xb3" + bytes(36)), (0, b"\x74\2")],
                    ),
                    (
                        PSA_WHEEL_ADDITIONAL,
                        bytearray(40),
                        [(0, b"\x61\xb3" + bytes(36)), (0, b"\x74\2")],
                    ),
                    (
                        PSA_TRANSMITTER,
                        bytearray(9),
                        [(0, b"\x71\xb4\1"), (0, b"\x71\xb4\2")],
                    ),
                ]
            if source in (SHA_18, SHA_PLUS):
                cases += [
                    (EFI_FREQUENCY_READ, bytearray(1), [(0, b"\x62\x20\x2e\4")]),
                    (EFI_FREQUENCY_WRITE, bytearray(5), [(0, b"\x6e\x20\x2e")]),
                    (ECD_ASH_CLEAR, None, [(0, b"\x6e\x20\x14")]),
                    (ECD_RESET55, None, [(0, b"\x6e\x20\x17")]),
                ]
            for export, data, replies in cases:
                context = Context(source)
                context.module_bytes = Path(path).read_bytes()
                context.replies = iter(replies)
                self.assertEqual(
                    aggregate_body(export, () if data is None else (data,), context), 0
                )
                self.assertEqual(context.events[-1], ("finalize",))

    def test_ecd_resets_exact_source_echo_restore_error_precedence(self):
        for source in (SHA_18, SHA_PLUS):
            for export, request in (
                (ECD_ASH_CLEAR, b"\x2e\x20\x14" + bytes(5)),
                (ECD_RESET55, b"\x2e\x20\x17" + bytes(4)),
            ):
                for status, reply, restore, expected in (
                    (0, b"\0" + request[1:3], 0, 0),
                    (0, b"\0" + request[1:3] + b"tail", 0, 0),
                    (0, b"\0\x20", 0, 3),
                    (19, b"", 0, 19),
                    (19, b"", 17, 17),
                ):
                    context = Context(source, status=status, response=reply)
                    context.sessions = iter((0, 0, restore))
                    self.assertEqual(_ecd_reset(export, (), context), expected)
                    self.assertIn(("exchange", request), context.events)
                    self.assertEqual(context.events[-1], ("finalize",))
                context = Context(source, init_status=19)
                self.assertEqual(_ecd_reset(export, (), context), 19)
                self.assertEqual(context.events[-1], ("finalize",))
                context = Context(source)
                context.fault = RuntimeError("wire fault")
                with self.assertRaises(RuntimeError):
                    _ecd_reset(export, (), context)
                self.assertEqual(context.events[-1], ("finalize",))

    def test_frequency_exact_frames_output_and_discarded_restore_status(self):
        for source in (SHA_18, SHA_PLUS):
            for value in (0, 1, 2, 3, 4, 5, 255):
                context = Context(source, response=bytes((0, 0x20, 0x2E, value)))
                context.sessions = iter((0, 0, 19))
                data = bytearray(b"Z-tail")
                self.assertEqual(
                    _frequency(False, (data,), context), 0 if value <= 4 else 3
                )
                self.assertEqual(data, bytes((value,)) + b"-tail")
                self.assertIn(("exchange", b"\x22\x20\x2e"), context.events)
                self.assertEqual(context.events[-1], ("finalize",))
            for value in (0, 1, 5, 255):
                context = Context(source, response=b"\0\x20\x2e")
                data = bytearray((0, 0, 0, 0, value))
                self.assertEqual(_frequency(True, (data,), context), 0)
                self.assertIn(
                    ("exchange", bytes((0x2E, 0x20, 0x2E, (value - 1) & 255))),
                    context.events,
                )
            for write in (False, True):
                for status, reply, expected in (
                    (17, b"", 17),
                    (0, b"\x62\x20", 3),
                    (0, b"\x62\x21\x2e\0", 3),
                ):
                    context = Context(source, status=status, response=reply)
                    data = bytearray(b"Z-tail")
                    self.assertEqual(_frequency(write, (data,), context), expected)
                    self.assertEqual(data, b"Z-tail")
                context = Context(source)
                context.sessions = iter((0, 7))
                self.assertEqual(_frequency(write, (bytearray(5),), context), 7)
                self.assertFalse(any(e[0] == "exchange" for e in context.events))
                self.assertEqual(context.events[-1], ("finalize",))

    def test_wheel_main_zero_guard_and_write_reply_branches(self):
        for source in (SHA_12, SHA_18):
            for occupied, status, reply, expected in (
                (True, 0, b"", 0x2337),
                (False, 0, b"\x00\x02", 0),
                (False, 0, b"\x74\x02\x00", 3),
                (False, 17, b"\x74\x02", 17),
            ):
                context = Context(source)
                current = bytearray(36)
                current[15] = int(occupied)
                context.replies = iter(((0, b"\x61\xb3" + current), (status, reply)))
                data = bytearray(range(16))
                self.assertEqual(
                    _wheel_write(PSA_WHEEL_MAIN, (data,), context), expected
                )
                requests = [e[1] for e in context.events if e[0] == "exchange"]
                self.assertEqual(len(requests), 1 if occupied else 2)
                if not occupied:
                    self.assertEqual(
                        requests[1].hex(),
                        "34b200000010000102030405060708090a0b0c0d0e0f0826",
                    )
                self.assertEqual(data, bytearray(range(16)))
                self.assertEqual(context.events[-1], ("finalize",))

    def test_wheel_additional_read_modify_write_all_selectors(self):
        for source in (SHA_12, SHA_18):
            for selector in (0, 1, 2, 3, 4, 5, 0xFFFFFFFF):
                data = bytearray(range(36)) + selector.to_bytes(4, "little")
                context = Context(source)
                context.replies = iter(((0, b"\x00\xb3" + b"Z" * 36), (0, b"\x00\x02")))
                self.assertEqual(
                    _wheel_write(PSA_WHEEL_ADDITIONAL, (data,), context), 0
                )
                expected = bytearray(b"Z" * 36) + selector.to_bytes(4, "little")
                if selector <= 4:
                    offset = 16 if selector == 4 else 20 + 4 * selector
                    expected[offset : offset + 4] = bytes(range(offset, offset + 4))
                self.assertEqual(data, expected)
                requests = [e[1] for e in context.events if e[0] == "exchange"]
                self.assertEqual(len(requests), 1 if selector > 4 else 2)
                if selector <= 4:
                    self.assertEqual(requests[1][1], 0xB4 if selector == 4 else 0xB3)
                    self.assertEqual(
                        requests[1][6:-2],
                        expected[16:20] if selector == 4 else expected[20:36],
                    )
                self.assertEqual(context.events[-1], ("finalize",))

    def test_transmitter_poll_terminal_results_error_and_native_timeout(self):
        for source in (SHA_12, SHA_18):
            for result in (2, 4, 6, 8, 10, 16, 34):
                context = Context(source)
                context.replies = iter(
                    (
                        (0, b"\x00\xb4\x01"),
                        (0, b"\x00\xb4\x01"),
                        (0, bytes((0, 0xB4, result))),
                    )
                )
                data = bytearray((3, 0, 0, 0, 0, 0, 0, 0, 99))
                self.assertEqual(_transmitter((data,), context), 0)
                self.assertEqual(data[4:], bytes((0, 0, 0, 0, result)))
                self.assertIn(("exchange", b"\x31\xb4\0\3"), context.events)
            for status, reply, expected in (
                (9, b"", 0x2330),
                (0, b"\x71\xb4\3", 0x2330),
                (0, b"\x71\xb4\1", 9999),
            ):
                context = Context(source)
                context.replies = iter(((0, b"\x71\xb4\1"), (status, reply)))
                ticks = iter((0xFFFFFF00, (0xFFFFFF00 + 120000) & 0xFFFFFFFF))
                context.ticks = ticks.__next__
                data = bytearray(9)
                data[8] = 99
                self.assertEqual(_transmitter((data,), context), expected)
                self.assertEqual(data[4:], b"\0\0\0\0c")
                self.assertIn(("exchange", b"\x31\xb4\0\0"), context.events)
                self.assertEqual(context.events[-1], ("finalize",))

    def test_wheel_writer_fault_cancel_initialization_and_read_failure(self):
        for function, export in (
            (_wheel_write, PSA_WHEEL_MAIN),
            (_wheel_write, PSA_WHEEL_ADDITIONAL),
        ):
            for source in (SHA_12, SHA_18):
                context = Context(source, init_status=19)
                data = bytearray(40)
                self.assertEqual(function(export, (data,), context), 19)
                self.assertEqual(context.events[-1], ("finalize",))
                for failure in (Cancelled("cancel"), RuntimeError("wire fault")):
                    context = Context(source)
                    context.fault = failure
                    with self.assertRaises(type(failure)):
                        function(export, (data,), context)
                    self.assertEqual(context.events[-1], ("finalize",))
                for status, reply, expected in (
                    (19, b"", 19),
                    (0, b"\x61\xb3", 3),
                    (0, b"\x61\xb2" + bytes(36), 3),
                ):
                    context = Context(source, status=status, response=reply)
                    self.assertEqual(function(export, (data,), context), expected)
                    self.assertEqual(data, bytearray(40))
        context = Context()
        context.cancelled = True
        with self.assertRaises(Cancelled):
            _transmitter((bytearray(9),), context)
        self.assertEqual(context.events[-1], ("finalize",))

    def test_wheel_clear_exact_two_frames_and_early_failure(self):
        for source in (SHA_12, SHA_18):
            context = Context(source, response=b"\x74\x02")
            self.assertEqual(_wheel_clear((), context), 0)
            self.assertEqual(
                [event[1].hex() for event in context.events if event[0] == "exchange"],
                ["34b300000010" + "00" * 16 + "24ad", "34b400000004000000008c73"],
            )
            self.assertEqual(context.events.count(("native_sleep", 1000)), 2)
            for status, reply, expected in (
                (9, b"", 9),
                (0, b"\x74\x02\0", 3),
                (0, b"\x74\0", 3),
            ):
                context = Context(source, status=status, response=reply)
                self.assertEqual(_wheel_clear((), context), expected)
                self.assertEqual(
                    sum(event[0] == "exchange" for event in context.events), 1
                )
                self.assertEqual(context.events[-1], ("finalize",))
            context = Context(source)
            context.replies = iter(((0, b"\x74\x02"), (9, b"")))
            self.assertEqual(_wheel_clear((), context), 9)
            self.assertEqual(context.events[-1], ("finalize",))

    def test_full_wheel_read_has_distinct_error_and_output_rules(self):
        for source in (SHA_12, SHA_18):
            for status, reply, expected in (
                (0, b"\0\xb3" + bytes(range(36)), 0),
                (7, b"", 7),
                (0, b"\x61\xb3", 3),
                (0, bytes(range(38)), 3),
            ):
                data = bytearray(b"X" * 40)
                context = Context(source, status=status, response=reply)
                self.assertEqual(_dsg(PSA_WHEEL_READ2, (data,), context), expected)
                self.assertEqual(data[:36], reply[2:] if not expected else b"X" * 36)
                self.assertEqual(data[36:], b"X" * 4)
                self.assertEqual(context.events[-1], ("finalize",))

    def test_wheel_read_error_copy_length_and_header_precedence(self):
        for source in (SHA_12, SHA_18):
            for status, reply, expected, copied in (
                (0, b"\x61\xb3" + bytes(range(36)), 0, True),
                (7, bytes(range(38)), 7, True),
                (7, bytes(range(37)), 3, False),
                (0, bytes(range(38)), 3, False),
            ):
                with self.subTest(source=source, status=status, length=len(reply)):
                    data = bytearray(b"X" * 24)
                    context = Context(source, status=status, response=reply)
                    self.assertEqual(_dsg(PSA_WHEEL_READ, (data,), context), expected)
                    self.assertEqual(data[:20], reply[18:38] if copied else b"X" * 20)
                    self.assertEqual(data[20:], b"X" * 4)
                    self.assertIn(("exchange", b"\x21\xb3"), context.events)
                    self.assertEqual(context.events[-1], ("finalize",))

    def test_valve_check_shared_stop_flags_and_error_mutation(self):
        for source in (SHA_12, SHA_18):
            data = bytearray(16)
            context = Context(source, response=b"\x61\xd3\x82")

            def stop_after_poll(ms, context=context, data=data):
                context.events.append(("native_sleep", ms))
                data[8:12] = (1).to_bytes(4, "little")

            context.native_sleep = stop_after_poll
            self.assertEqual(_dsg(PSA_VALVE_CHECK, (data,), context), 0)
            self.assertEqual(data[0], 0x82)
            self.assertEqual(data[4:8], b"\x01\0\0\0")
            self.assertEqual(data[12:16], b"\x01\0\0\0")
            self.assertIn(("native_sleep", 40), context.events)
            for status, reply, output in (
                (9, b"\x61\xd3\x40", 0xAA),
                (0, b"\x61\0\x40", 0x40),
                (0, b"", 0),
            ):
                data = bytearray(16)
                data[0] = 0xAA
                context = Context(source, status=status, response=reply)
                self.assertEqual(_dsg(PSA_VALVE_CHECK, (data,), context), status or 3)
                self.assertEqual(data[0], output)
                self.assertEqual(data[12:16], bytes(4))
                self.assertEqual(context.events[-1], ("finalize",))
            data[8:12] = (256).to_bytes(4, "little")
            context = Context(source)
            self.assertEqual(_dsg(PSA_VALVE_CHECK, (data,), context), 0)
            self.assertFalse(any(event[0] == "exchange" for event in context.events))

    def test_reset_full_dword_action_mapping_all_variants(self):
        for source in (SHA_12, SHA_18):
            for action, selector in (
                (0, 0),
                (1, 0xAD),
                (2, 0xAE),
                (3, 0xA0),
                (257, 0),
                (0xFFFFFFFF, 0),
            ):
                with self.subTest(source=source, action=action):
                    context = Context(source)
                    self.assertEqual(
                        _reset(
                            PSA_ECD_RESET,
                            (bytearray(action.to_bytes(4, "little")),),
                            context,
                        ),
                        0,
                    )
                    self.assertIn(("exchange", bytes((0x11, selector))), context.events)
                    self.assertEqual(context.events[-1], ("finalize",))
                    self.assertEqual(
                        context.events[2],
                        (
                            "configure",
                            "native_rva:b940"
                            if source == SHA_12
                            else "native_rva:12180",
                            150,
                        ),
                    )

    def test_efi_reads_only_first_input_byte_and_preserves_buffer(self):
        context = Context()
        buffer = bytearray(b"\xae\xff\xff\xff")
        self.assertEqual(_reset(PSA_EFI_RESET, (buffer,), context), 0)
        self.assertIn(("exchange", b"\x11\xae"), context.events)
        self.assertEqual(buffer, bytearray(b"\xae\xff\xff\xff"))

    def test_status_length_echo_and_unconditional_finalize(self):
        for status, response, expected in (
            (0, b"\x51\0", 0),
            (0, b"\x51\1", 3),
            (0, b"\x51", 3),
            (0, b"\x51\0\0", 3),
            (16, b"", 16),
        ):
            context = Context(status=status, response=response)
            self.assertEqual(
                _reset(PSA_EFI_RESET, (bytearray(b"\1"),), context), expected
            )
            self.assertEqual(context.events[-1], ("finalize",))
        context = Context(init_status=5)
        self.assertEqual(_reset(PSA_EFI_RESET, (bytearray(b"\1"),), context), 5)
        self.assertFalse(any(e[0] == "exchange" for e in context.events))
        self.assertEqual(context.events[-1], ("finalize",))

    def test_cancel_host_fault_input_bounds_and_source_guard(self):
        context = Context()
        context.cancelled = True
        with self.assertRaises(Cancelled):
            _reset(PSA_EFI_RESET, (bytearray(b"\1"),), context)
        self.assertEqual(context.events[-1], ("finalize",))
        context = Context()
        context.fault = OSError("Authored fault")
        with self.assertRaises(OSError):
            _reset(PSA_EFI_RESET, (bytearray(b"\1"),), context)
        self.assertEqual(context.events[-1], ("finalize",))
        for args in ((), (b"\1",), (bytearray(),), (bytearray(65537),)):
            with self.assertRaises(ValueError):
                _reset(PSA_EFI_RESET, args, Context())
        context = Context()
        with self.assertRaises(TYSourceError):
            run_body(PSA_EFI_RESET, (bytearray(b"\1"),), context)
        self.assertEqual(context.events, [])
        self.assertEqual(supported_exports(hashlib.sha256(b"authored").hexdigest()), ())

    def test_water_poll_retains_output_retry_delay_and_zero_filled_native_read(self):
        for source in (SHA_12, SHA_18):
            context = Context(source)
            context.replies = iter(
                (
                    (0, b"\x61\xff"),
                    (0, b"\x61\xff\0\0\0\x79"),
                    (0, b"\x61\xff\0\0\0\x7a"),
                )
            )
            data = bytearray(b"AAAA\xffZ")
            self.assertEqual(_water((data,), context), 0)
            self.assertEqual(data, bytearray(b"AAAA\x7aZ"))
            self.assertEqual(
                [e for e in context.events if e[0] == "native_sleep"],
                [("native_sleep", 2000), ("native_sleep", 250), ("native_sleep", 250)],
            )
            self.assertEqual(context.events[-1], ("finalize",))
        for status, reply, expected in ((16, b"", 16), (0, b"\x61\0", 3)):
            context = Context(status=status, response=reply)
            data = bytearray(5)
            self.assertEqual(_water((data,), context), expected)
            self.assertEqual(data[4], 0)

    def test_ect_negative22_overrides_native_status_and_preserves_other_errors(self):
        for source in (SHA_12, SHA_18):
            for status, reply, expected in (
                (3, b"\x7f\x11\x22", 9010),
                (0, b"\x7f\x11\x22", 9010),
                (16, b"", 16),
                (0, b"\x51\0", 0),
                (0, b"\x51\1", 3),
            ):
                context = Context(source, status=status, response=reply)
                self.assertEqual(_ect_initialize((bytearray(),), context), expected)
                self.assertIn(("exchange", b"\x11\xff"), context.events)
                self.assertIn(("native_sleep", 1000), context.events)
                self.assertEqual(context.events[-1], ("finalize",))

    def test_engine_start_reset_session_status_precedence_each_exact_source(self):
        for source in (SHA_12, SHA_18, SHA_PLUS):
            for sessions, wire_status, reply, expected in (
                ((0, 0, 0), 0, b"\x6e\x20\x02", 0),
                ((5,), 0, b"", 5),
                ((0, 7), 0, b"", 7),
                ((0, 0, 0), 16, b"", 16),
                ((0, 0, 0), 0, b"\x6e\x20", 3),
                ((0, 0, 9), 16, b"", 9),
            ):
                with self.subTest(source=source, sessions=sessions, expected=expected):
                    context = Context(source, status=wire_status, response=reply)
                    context.sessions = iter(sessions)
                    self.assertEqual(_engine_starts_reset((), context), expected)
                    self.assertEqual(context.events[-1], ("finalize",))
                    self.assertEqual(
                        [e[1] for e in context.events if e[0] == "session"],
                        [1, 3, 1][: len(sessions)],
                    )
                    if len(sessions) == 3:
                        self.assertIn(
                            ("exchange", b"\x2e\x20\x02\0\0\0"), context.events
                        )
                    else:
                        self.assertFalse(
                            any(e[0] == "exchange" for e in context.events)
                        )
        context = Context(init_status=16)
        self.assertEqual(_engine_starts_reset((), context), 16)
        self.assertEqual(context.events[-1], ("finalize",))

    def test_engine_start_reset_byod_public_entry_three_variants(self):
        for source, path in (
            (
                SHA_12,
                "artifacts/extracted/techstream-12-application/Techstream_Bin/UtilityEx2TY.dll",
            ),
            (
                SHA_18,
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll",
            ),
            (
                SHA_PLUS,
                "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll",
            ),
        ):
            context = Context(source, response=b"\x6e\x20\x02")
            if not Path(path).exists():
                self.skipTest("Exact BYOD source is not supplied")
            context.module_bytes = Path(path).read_bytes()
            self.assertEqual(run_body(ECO_STARTS_RESET, (), context), 0)

    def test_oil_read_preserves_raw_native_byte_order_and_unmodified_tail(self):
        for source in (SHA_12, SHA_18):
            context = Context(source, response=b"\x61\xd1\xda\x78\x56\x34\x12")
            data = bytearray(b"AAAA-tail")
            self.assertEqual(_oil(False, (data,), context), 0)
            self.assertEqual(data, bytearray(b"\x78\x56\x34\x12-tail"))
            self.assertIn(("exchange", b"\x21\xd1\xda"), context.events)
            context = Context(source, response=b"\x61\xd1\xda\1")
            data = bytearray(b"AAAA")
            self.assertEqual(_oil(False, (data,), context), 3)
            self.assertEqual(data, bytearray(b"AAAA"))

    def test_oil_write_real_native_crc_and_error_status(self):
        for source in (SHA_12, SHA_18):
            for status, reply, expected in (
                (0, b"\x74\x02", 0),
                (0, b"\x74\x04", 9023),
                (0, b"\x74\x0a", 9023),
                (0, b"\x74\x01", 3),
                (0, b"\x74", 3),
                (16, b"", 16),
            ):
                context = Context(source, status=status, response=reply)
                data = bytearray(b"\1\2\3\4")
                self.assertEqual(_oil(True, (data,), context), expected)
                self.assertIn(
                    ("exchange", bytes.fromhex("34d100000005da01020304e1ad")),
                    context.events,
                )
                self.assertEqual(data, bytearray(b"\1\2\3\4"))
                self.assertEqual(context.events[-1], ("finalize",))

    def test_native_hex_partial_output_odd_capacity_and_wide_low_bytes(self):
        for wide, source, expected in (
            (False, b"12aF\0", b"\x12\xaf"),
            (True, "12aF\0".encode("utf-16-le"), b"\x12\xaf"),
            (True, b"A\1F\1\0\0", b"\xaf"),
        ):
            output = bytearray(b"ZZZZ")
            self.assertEqual(_hex_to_bytes((source, output, 4), wide=wide), 0)
            self.assertEqual(output, expected + b"Z" * (4 - len(expected)))
        for source, capacity, prefix in (
            (b"12G4\0", 4, b"\x12"),
            (b"1\0", 4, b""),
            (b"1234\0", 1, b""),
            (b"\0", -1, b""),
        ):
            output = bytearray(b"ZZZZ")
            self.assertEqual(
                _hex_to_bytes((source, output, capacity), wide=False), 0xFFFFFFFF
            )
            self.assertEqual(output, prefix + b"Z" * (4 - len(prefix)))
        with self.assertRaises(ValueError):
            _hex_to_bytes((b"1234", bytearray(2), 2), wide=False)
        self.assertEqual(_hex_to_bytes((b"\0", bytearray(), 0), wide=False), 0)
        self.assertEqual(
            [
                _char_to_int(v)
                for v in (ord("0"), ord("9"), ord("A"), ord("f"), ord("G"), 0x141, -1)
            ],
            [0, 9, 10, 15, -1, 10, -1],
        )

    def test_direct_and_dummy_public_entrypoints_are_source_distinct(self):
        for source, path in (
            (
                SHA_18,
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll",
            ),
            (
                SHA_PLUS,
                "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll",
            ),
        ):
            if not Path(path).exists():
                self.skipTest("Exact supplied source absent")
            context = Context(source)
            context.module_bytes = Path(path).read_bytes()
            self.assertEqual(run_body(ECD_CHAR, (ord("G"),), context), -1)
            output = bytearray(2)
            text = "BEEF\0".encode("utf-16-le") if source == SHA_PLUS else b"BEEF\0"
            self.assertEqual(run_body(ECD_HEX, (text, output, 2), context), 0)
            self.assertEqual(output, bytearray.fromhex("beef"))
            self.assertEqual(run_body(ECD_DUMMY59, (bytearray(),), context), 1001)
            self.assertEqual(run_body(ECD_DUMMY60, (bytearray(),), context), 1000)
            self.assertEqual(context.events, [])
            self.assertEqual(set(direct_exports(source)), {ECD_CHAR, ECD_HEX})
        self.assertEqual(direct_exports(SHA_12), ())

    def test_exact_byod_identity_real_entrypoint_both_supplied_versions(self):
        for source, version in ((SHA_12, "12"), (SHA_18, "18")):
            context = Context(source)
            path = Path(
                f"artifacts/extracted/techstream-{version}-application/Techstream_Bin/UtilityEx2TY.dll"
            )
            if not path.exists():
                self.skipTest("Exact BYOD TY sources are not supplied")
            context.module_bytes = path.read_bytes()
            self.assertEqual(run_body(PSA_EFI_RESET, (bytearray(b"\xae"),), context), 0)
            with self.assertRaises(TYSourceError):
                run_body("Ex2ECD_27_GetOilPressure", (), context)

    @staticmethod
    def hv14_snapshot(payload81=None, payload87=None):
        raw = bytearray(4128)
        offsets = [4128] * 256
        for pid, offset, payload in (
            (0x81, 0, payload81),
            (0x87, 128, payload87),
        ):
            if payload is not None:
                offsets[pid] = offset
                raw[offset + 1] = len(payload)
                raw[offset + 2 : offset + 2 + len(payload)] = payload
        return bytes(raw), tuple(offsets)

    def test_hv14_support_all_48_mask_positions_and_delayed_length_publication(self):
        good81 = bytes([0xFF] * 16 + [0x10, 0])
        good87 = bytes([0xFF] * 32 + [1, 2, 0])
        for source in (SHA_12, SHA_18, SHA_PLUS):
            raw, offsets = self.hv14_snapshot(good81, good87)
            context = Context(source)
            context.snapshots = iter(((0, raw, offsets),))
            data = bytearray(b"Q" * 32)
            self.assertEqual(_hv14_selected(HV14_SUPPORT, (data,), context), 0)
            self.assertEqual(int.from_bytes(data[:4], "little"), 19)
            self.assertEqual(int.from_bytes(data[4:8], "little"), 36)
            self.assertEqual(data[8:], b"Q" * 24)
            self.assertEqual(context.events.count(("support_snapshot", 1)), 1)
            self.assertEqual(context.events.count(("finalize",)), 1)

            for pid, length, position in (
                *((0x81, 16, index) for index in range(16)),
                *((0x87, 32, index) for index in range(32)),
            ):
                damaged = bytearray(good81 if pid == 0x81 else good87)
                damaged[position] = 0xFE
                raw_bad, offsets_bad = self.hv14_snapshot(
                    bytes(damaged) if pid == 0x81 else good81,
                    bytes(damaged) if pid == 0x87 else good87,
                )
                data = bytearray(b"Z" * 16)
                context = Context(source)
                context.snapshots = iter(((0, raw_bad, offsets_bad),))
                self.assertEqual(_hv14_selected(HV14_SUPPORT, (data,), context), 22)
                self.assertEqual(data, bytearray(b"Z" * 16))
                self.assertEqual(context.events.count(("finalize",)), 1)

            # Native checks PID81 masks before attempting PID87 bounds parsing.
            bad81 = bytearray(good81)
            bad81[3] = 0xFE
            raw_mixed, offsets_mixed = self.hv14_snapshot(bytes(bad81), good87)
            bad_offsets = list(offsets_mixed)
            bad_offsets[0x87] = 4127
            context = Context(source)
            context.snapshots = iter(((0, raw_mixed, tuple(bad_offsets)),))
            data = bytearray(b"P" * 8)
            self.assertEqual(_hv14_selected(HV14_SUPPORT, (data,), context), 22)
            self.assertEqual(data, bytearray(b"P" * 8))

            for payload81, payload87 in ((None, good87), (good81, None)):
                raw_missing, offsets_missing = self.hv14_snapshot(payload81, payload87)
                context = Context(source)
                context.snapshots = iter(((0, raw_missing, offsets_missing),))
                data = bytearray(b"M" * 8)
                before = bytes(data)
                self.assertEqual(_hv14_selected(HV14_SUPPORT, (data,), context), 22)
                self.assertEqual(bytes(data), before)
            raw_bad, offsets_bad = self.hv14_snapshot(good81, good87)
            for pid in (0x81, 0x87):
                bad_offsets = list(offsets_bad)
                bad_offsets[pid] = 4127
                context = Context(source)
                context.snapshots = iter(((0, raw_bad, tuple(bad_offsets)),))
                data = bytearray(b"M" * 8)
                before = bytes(data)
                self.assertEqual(_hv14_selected(HV14_SUPPORT, (data,), context), 99)
                self.assertEqual(bytes(data), before)

    def test_hv14_temperature_minimum_endian_zero_padding_and_echo_checks(self):
        for source in (SHA_12, SHA_18, SHA_PLUS):
            words = [0x1234, 0x0102, *range(0x200, 0x20E)]
            reply = b"\x00\x87" + b"".join(word.to_bytes(2, "big") for word in words)
            data = bytearray(b"T" * 24)
            data[4:8] = len(reply).to_bytes(4, "little")
            context = Context(source, response=reply)
            self.assertEqual(_hv14_selected(HV14_TEMPERATURE, (data,), context), 0)
            self.assertEqual(struct.unpack("<d", data[8:16])[0], 0x0102 / 256 - 50)
            self.assertEqual(data[:8], b"T" * 4 + len(reply).to_bytes(4, "little"))
            self.assertEqual(data[16:], b"T" * 8)

            short = bytearray(b"S" * 24)
            short[4:8] = (2).to_bytes(4, "little")
            context = Context(source, response=b"\0\x87")
            self.assertEqual(_hv14_selected(HV14_TEMPERATURE, (short,), context), 0)
            self.assertEqual(struct.unpack("<d", short[8:16])[0], -50.0)

            for bad_reply, declared, expected in (
                (reply + b"x", len(reply), 3),
                (reply[:-1], len(reply), 3),
                (b"\0\x86", 2, 3),
                (b"\0\x87", 1, 3),
            ):
                bad = bytearray(b"B" * 24)
                bad[4:8] = declared.to_bytes(4, "little")
                before = bytes(bad)
                context = Context(source, response=bad_reply)
                self.assertEqual(
                    _hv14_selected(HV14_TEMPERATURE, (bad,), context), expected
                )
                self.assertEqual(bytes(bad), before)

    def test_hv14_voltage_all_low_masks_group_average_nan_and_exact_reply(self):
        words = (100, 200, 300, 400, 500, 600, 700, 800)
        reply = b"\x00\x81" + b"".join(word.to_bytes(2, "big") for word in words)
        for source in (SHA_12, SHA_18, SHA_PLUS):
            for mask in range(16):
                data = bytearray(b"V" * 25)
                data[:4] = len(reply).to_bytes(4, "little")
                data[24] = 0xF0 | mask
                context = Context(source, response=reply)
                self.assertEqual(_hv14_selected(HV14_VOLTAGE, (data,), context), 0)
                result = struct.unpack("<d", data[16:24])[0]
                included = [group for group in range(4) if not mask & (1 << group)]
                if not included:
                    self.assertTrue(math.isnan(result))
                else:
                    total = sum(sum(words[g * 2 : g * 2 + 2]) for g in included)
                    self.assertEqual(result, total * (5 / 4096) / len(included))
                self.assertEqual(data[4:16], b"V" * 12)
                self.assertEqual(data[24], 0xF0 | mask)

            for bad_reply, declared in (
                (reply + b"x", len(reply)),
                (reply[:-1], len(reply)),
                (b"\0\x80", 2),
                (reply, len(reply) - 1),
            ):
                data = bytearray(b"B" * 25)
                data[:4] = declared.to_bytes(4, "little")
                before = bytes(data)
                context = Context(source, response=bad_reply)
                self.assertEqual(_hv14_selected(HV14_VOLTAGE, (data,), context), 3)
                self.assertEqual(bytes(data), before)

    def test_hv14_exact_source_aggregator_and_wrapper_mode_arity(self):
        from scripts.utility_ex import UtilityEx2TY, UtilityExContext
        from scripts.utility_ex_ty import run_body as aggregate_body

        for source, path in (
            (
                SHA_12,
                "artifacts/extracted/techstream-12-application/Techstream_Bin/UtilityEx2TY.dll",
            ),
            (
                SHA_18,
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll",
            ),
            (
                SHA_PLUS,
                "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityEx2TY.dll",
            ),
        ):
            require_private(path)
            image = Path(path).read_bytes()
            context = Context(source)
            context.module_bytes = image
            temperature = b"\0\x87" + b"\x01\0" * 16
            data = bytearray(16)
            data[4:8] = len(temperature).to_bytes(4, "little")
            context.response = temperature
            self.assertEqual(aggregate_body(HV14_TEMPERATURE, (data,), context), 0)
            voltage = b"\0\x81" + b"\x01\0" * 8
            data = bytearray(25)
            data[:4] = len(voltage).to_bytes(4, "little")
            context.response = voltage
            self.assertEqual(aggregate_body(HV14_VOLTAGE, (data,), context), 0)
            good81 = bytes([0xFF] * 16)
            good87 = bytes([0xFF] * 32)
            raw, offsets = self.hv14_snapshot(good81, good87)
            context.snapshots = iter(((0, raw, offsets),))
            self.assertEqual(aggregate_body(HV14_SUPPORT, (bytearray(8),), context), 0)

            engine = UtilityEx2TY(UtilityExContext(image, Host(4), None, None))
            for export, size in (
                (HV14_SUPPORT, 8),
                (HV14_TEMPERATURE, 16),
                (HV14_VOLTAGE, 25),
            ):
                if export not in supported_exports(source):
                    self.fail(f"{source} missing {export}")
                with self.assertRaises(ValueError):
                    engine.invoke(export, ())
                wrong_mode = UtilityEx2TY(UtilityExContext(image, Host(19), None, None))
                self.assertEqual(wrong_mode.invoke(export, (bytearray(size),)), 99)
                self.assertFalse(wrong_mode.worker.running)

    def test_hv14_init_native_host_cancel_cleanup_and_bounds(self):
        cases = (
            (HV14_SUPPORT, bytearray(8)),
            (HV14_TEMPERATURE, bytearray(16)),
            (HV14_VOLTAGE, bytearray(25)),
        )
        for source in (SHA_12, SHA_18, SHA_PLUS):
            for export, data in cases:
                context = Context(source, init_status=17)
                before = bytes(data)
                self.assertEqual(_hv14_selected(export, (data,), context), 17)
                self.assertEqual(bytes(data), before)
                self.assertFalse(
                    any(
                        event[0] in ("exchange", "support_snapshot")
                        for event in context.events
                    )
                )
                self.assertFalse(
                    any(event[0] == "configure" for event in context.events)
                )
                self.assertEqual(context.events.count(("finalize",)), 1)

                context = Context(source, status=18)
                if export == HV14_SUPPORT:
                    context.snapshots = iter(((18, b"", ()),))
                data = bytearray(
                    25
                    if export == HV14_VOLTAGE
                    else 16
                    if export == HV14_TEMPERATURE
                    else 8
                )
                before = bytes(data)
                self.assertEqual(_hv14_selected(export, (data,), context), 18)
                self.assertEqual(bytes(data), before)

                for primary in (RuntimeError("wire HOST"), Cancelled("cancel")):
                    context = Context(source)
                    context.fault = primary
                    context.finalize_fault = OSError("cleanup")
                    data = bytearray(
                        25
                        if export == HV14_VOLTAGE
                        else 16
                        if export == HV14_TEMPERATURE
                        else 8
                    )
                    with self.assertRaises(type(primary)) as caught:
                        _hv14_selected(export, (data,), context)
                    self.assertIs(caught.exception, primary)
                    self.assertEqual(context.events.count(("finalize",)), 1)

                context = Context(source)
                data = bytearray(
                    25
                    if export == HV14_VOLTAGE
                    else 16
                    if export == HV14_TEMPERATURE
                    else 8
                )
                with (
                    patch.object(context, "is_cancelled", return_value=True),
                    self.assertRaises(Cancelled),
                ):
                    _hv14_selected(export, (data,), context)
                self.assertFalse(
                    any(event[0] == "initialize" for event in context.events)
                )
                self.assertEqual(context.events.count(("finalize",)), 1)

                context = Context(source)
                data = bytearray(
                    25
                    if export == HV14_VOLTAGE
                    else 16
                    if export == HV14_TEMPERATURE
                    else 8
                )
                before = bytes(data)
                with (
                    patch.object(context, "is_cancelled", side_effect=(False, True)),
                    self.assertRaises(Cancelled),
                ):
                    _hv14_selected(export, (data,), context)
                self.assertEqual(bytes(data), before)
                self.assertFalse(
                    any(
                        event[0] in ("exchange", "support_snapshot")
                        for event in context.events
                    )
                )
                self.assertEqual(context.events.count(("initialize", 0)), 1)
                self.assertEqual(context.events.count(("finalize",)), 1)

                minimum = (
                    25
                    if export == HV14_VOLTAGE
                    else 16
                    if export == HV14_TEMPERATURE
                    else 8
                )
                with self.assertRaises(ValueError):
                    _hv14_selected(export, (bytearray(minimum - 1),), Context(source))
        for source in (SHA_12, SHA_18, SHA_PLUS):
            for export, size in (
                (HV14_SUPPORT, 8),
                (HV14_TEMPERATURE, 16),
                (HV14_VOLTAGE, 25),
            ):
                self.assertIn(export, supported_exports(source))
                context = Context(source)
                with self.assertRaises(ValueError):
                    run_body(export, (), context)


if __name__ == "__main__":
    unittest.main()
