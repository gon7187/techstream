"""Authored native byte/layout/branch vectors; no original image is distributed."""

from __future__ import annotations

import unittest
from collections.abc import Callable
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

from scripts import utility_ex_ty_retained_12 as retained
from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import (
    SHA_12_TY,
    SHA_18_TY,
    SHA_PLUS_TY,
    TYContext,
    TYSourceError,
)


def words(*values: int) -> bytearray:
    return bytearray(b"".join(value.to_bytes(4, "little") for value in values))


class Comm:
    def __init__(self) -> None:
        self.events: list[object] = []
        self.replies: list[tuple[int, bytes]] = []
        self.sessions: list[int] = []
        self.initial = 0
        self.snapshot: tuple[int, bytes, tuple[int, ...]] = (
            0,
            b"\x04\x03\x80\x00\x80",
            (0x1020,) * 4 + (0,),
        )

    def initialize(self, mode: int = 0) -> int:
        self.events.append(("initialize", mode))
        return self.initial

    def finalize(self) -> None:
        self.events.append("finalize")

    def configure(self, field: str, value: int) -> None:
        self.events.append((field, value))

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
        self.events.append(("session", mode, keepalive, stop_on_error))
        return self.sessions.pop(0) if self.sessions else 0

    def exchange(self, request: bytes) -> tuple[int, bytes]:
        self.events.append(request)
        if self.replies:
            return self.replies.pop(0)
        if request == b"\x19\x02\x01":
            return 0, b"\x59\x02\x01"
        if request.startswith(b"\x30"):
            return 0, b"\x70\x04"
        return 0, bytes((request[0] | 0x40,)) + request[1:] + b"\x02\x00\x00"

    def support_snapshot(self, kind: int) -> tuple[int, bytes, tuple[int, ...]]:
        self.events.append(("support_snapshot", kind))
        return self.snapshot


class Context:
    def __init__(self, source: str = SHA_18_TY, mode: int = 20) -> None:
        self.module_sha256 = source
        self.module_bytes = b"authored synthetic retained TY image"
        self.mode = mode
        self.state: dict[str, object] = {}
        self.controller = Comm()
        self.selectors: list[str] = []
        self.clock = 0
        self.cancelled = False
        self.on_sleep: Callable[[int], None] | None = None
        self.sleeps: list[int] = []

    def comm(self, kind: str) -> Comm:
        self.selectors.append(kind)
        return self.controller

    def ticks(self) -> int:
        return self.clock & 0xFFFFFFFF

    def sleep(self, milliseconds: int) -> None:
        self.sleeps.append(milliseconds)
        self.clock += milliseconds
        if self.on_sleep:
            self.on_sleep(milliseconds)

    def native_sleep(self, milliseconds: int) -> None:
        self.sleep(milliseconds)

    def is_cancelled(self) -> bool:
        return self.cancelled


def run(export: str, data: bytearray | None, context: Context) -> int:
    # Only image authentication is replaced; all authored wire and body code runs.
    with patch.object(
        retained.hashlib,
        "sha256",
        return_value=SimpleNamespace(hexdigest=lambda: context.module_sha256),
    ):
        return retained.run_body(
            export, () if data is None else (data,), cast(TYContext, context)
        )


class RetainedTests(unittest.TestCase):
    def test_exact_pair_partition_and_identity(self) -> None:
        self.assertEqual(
            sum(
                len(retained.supported_exports(s))
                for s in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY)
            ),
            46,
        )
        self.assertEqual(retained.supported_exports("unknown"), ())
        for name in (
            "Ex2GWY_02_TimeoutInit",
            "Ex2GWY_03_EndInitErr",
            "Ex2SBW_01_EndExtendedSession",
            "Ex2STRACT_03_EndExtendedSession",
        ):
            self.assertNotIn(name, retained.supported_exports(SHA_18_TY))
        context = Context()
        with self.assertRaises(TYSourceError):
            retained.run_body("Ex2EOM_01_ModeTransition", (), cast(TYContext, context))
        self.assertEqual(context.selectors, [])

    def test_each_exact_pair_literal_positive_path(self) -> None:
        for source in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY):
            for export in retained.supported_exports(source):
                with self.subTest(source=source, export=export):
                    context = Context(source, 4 if "LAMP_01" in export else 20)
                    data: bytearray | None = words(0, 0, 1, 0, 0)
                    if export == "Ex2LAMP_01_HeightSensorInitializationRequest":
                        data = words(5, 3)
                        expected = 0
                    elif export == "Ex2LAMP_01_SupportCheck":
                        expected = 0
                    elif export in ("Ex2GWY_02_CheckTheDtc",):
                        expected = 1000
                    elif export in (
                        "Ex2GWY_02_StartInit",
                        "Ex2STRACT_03_StartTestMode",
                    ):
                        expected = 1002
                    elif export in (
                        "Ex2GWY_02_ErrorInit",
                        "Ex2STRACT_03_StartZeroPointAdjustment",
                        "Ex2LAMP_04_SendMessage",
                    ):
                        expected = 1004
                    elif export in ("Ex2GWY_03_StartInitResult",):
                        expected = 1001
                    elif export == "Ex2STRACT_03_EndExtendedSessionFinal":
                        expected = 1005
                    elif export == "Ex2ABG_02_CheckLoadSpecInfo":
                        expected = 1000
                    else:
                        expected = 0
                    if export == "Ex2EOM_01_ModeTransition":
                        data = None
                    self.assertEqual(run(export, data, context), expected)
                    self.assertIn(expected, context.state.values())

    def test_source_mode_and_native_mode22_manager(self) -> None:
        for source in (SHA_18_TY, SHA_PLUS_TY):
            context = Context(source, 22)
            self.assertEqual(
                run("Ex2GWY_02_StartSession", words(0), context),
                0 if source == SHA_PLUS_TY else 99,
            )
            self.assertEqual(
                context.selectors, ["native:1013e7d0"] if source == SHA_PLUS_TY else []
            )
        context = Context(SHA_PLUS_TY, 22)
        self.assertEqual(run("Ex2GWY_03_StartInit", words(0), context), 99)

    def test_gateway_retains_then_finalizes_and_status_preservation(self) -> None:
        context = Context()
        self.assertEqual(run("Ex2GWY_02_StartSession", words(0), context), 0)
        self.assertNotIn("finalize", context.controller.events)
        context.controller.sessions = [7]
        self.assertEqual(run("Ex2GWY_02_EndInit", words(0), context), 7)
        self.assertEqual(context.controller.events[-1], "finalize")
        self.assertIn(b"\x14\xff\xff\xff", context.controller.events)

    def test_gateway_dtc_record_stride_and_native_cleanup_fault(self) -> None:
        context = Context()
        context.controller.replies = [(0, b"\x59\x02\x01\xc0\x00\x00\x01")]
        self.assertEqual(run("Ex2GWY_02_CheckTheDtc", words(0), context), 1001)
        context = Context()
        context.controller.sessions = [0, 0, 7]
        self.assertEqual(run("Ex2GWY_02_CheckTheDtc", words(0), context), 7)

    def test_gateway_init_identifier_byte_order_and_multiple_polling(self) -> None:
        data = words(0, 2, 0, 25, 1)
        data[6:10] = b"\x34\x12\x78\x56"
        context = Context()
        self.assertEqual(run("Ex2GWY_02_StartInit", data, context), 1002)
        self.assertEqual(
            [e for e in context.controller.events if isinstance(e, bytes)],
            [
                b"\x31\x01\x12\x34",
                b"\x31\x03\x12\x34",
                b"\x31\x01\x56\x78",
                b"\x31\x03\x56\x78",
            ],
        )
        self.assertEqual(context.sleeps, [200, 200, 25])
        self.assertNotIn("finalize", context.controller.events)

    def test_gateway_init_timeout_and_bad_status(self) -> None:
        data = words(0, 1, 0, 0, 1)
        data[6:8] = b"\x14\x11"
        context = Context()
        context.controller.replies = [
            (0, b"\x71\x01\x11\x14"),
            (0, b"\x71\x03\x11\x14\x01"),
        ]
        context.on_sleep = lambda _: setattr(context, "clock", 180000)
        self.assertEqual(run("Ex2GWY_02_StartInit", data, context), 5)
        context = Context()
        context.controller.replies = [
            (0, b"\x71\x01\x11\x14"),
            (0, b"\x71\x03\x11\x14\x03"),
        ]
        self.assertEqual(run("Ex2GWY_02_StartInit", data, context), 99)

    def test_gateway_result_live_status_and_fault_mapping(self) -> None:
        for status, reply, expected in (
            (7, b"", 1002),
            (0, b"\x71\x03\x11\x14\x03", 1002),
            (0, b"\x71\x03\x11\x14\x01", 5),
        ):
            context = Context()
            context.controller.replies = [(status, reply)]
            self.assertEqual(
                run("Ex2GWY_03_StartInitResult", words(1002), context), expected
            )

    def test_stract_support_native_output_identity_masks_and_cleanup(self) -> None:
        context = Context()
        data = words(9, 9, 0xAABBCCDD)
        context.controller.replies = [
            (0, b"\x71\x01\x10\x01\x00\x00\x40"),
            (0, b"\x71\x01\x11\x00\x20\x80"),
        ]
        self.assertEqual(run("Ex2STRACT_01_SupportCheck", data, context), 0)
        self.assertEqual(data, words(1, 1, 0xAABBCCDD))
        self.assertIn(("session", 1, 1, True), context.controller.events)
        context = Context()
        context.controller.replies = [(0, b"\x71\x01\x10\x01\x00\x00\x00")]
        data = words(9, 9)
        self.assertEqual(run("Ex2STRACT_01_SupportCheck", data, context), 0)
        self.assertEqual(data, words(0, 0))

    def test_stract_mode_transition_live_host_handshake_and_error(self) -> None:
        for source in (SHA_18_TY, SHA_PLUS_TY):
            context = Context(source)
            data = words(1, 1, 0)
            context.on_sleep = lambda _, data=data: data.__setitem__(
                slice(8, 12), b"\x01\x00\x00\x00"
            )
            self.assertEqual(run("Ex2STRACT_01_ModeTransition", data, context), 0)
            self.assertEqual(
                [e for e in context.controller.events if isinstance(e, bytes)],
                [b"\x31\x01\x11\x09", b"\x31\x01\x10\x02", b"\x31\x01\x11\x03"],
            )
            self.assertEqual(context.sleeps, [200])
        context = Context()
        context.controller.replies = [(7, b"")]
        self.assertEqual(
            run("Ex2STRACT_01_ModeTransition", words(0, 1, 1), context), 1007
        )

    def test_stract_clear_and_zero_faults_release_retained_manager(self) -> None:
        for export in (
            "Ex2STRACT_03_ClearZeroPointAdjustment",
            "Ex2STRACT_03_StartZeroPointAdjustment",
        ):
            for status in (7, 1001, 1002):
                context = Context()
                context.controller.replies = [(status, b"")]
                self.assertEqual(run(export, words(0), context), status)
                self.assertIn("finalize", context.controller.events)

    def test_stract_testmode_native_poll_status_and_host_stop(self) -> None:
        context = Context()
        self.assertEqual(run("Ex2STRACT_03_StartTestMode", words(1), context), 1001)
        self.assertNotIn("finalize", context.controller.events)
        context = Context()
        context.controller.replies = [
            (0, b"\x71\x01\x10\x02"),
            (0, b"\x71\x03\x10\x02\x03"),
        ]
        self.assertEqual(run("Ex2STRACT_03_StartTestMode", words(0), context), 1000)
        self.assertIn("finalize", context.controller.events)

    def test_stract04_dispatch_and_preserved_success_retention(self) -> None:
        context = Context()
        self.assertEqual(run("Ex2STRACT_04_SendMessage", words(1, 0), context), 0)
        self.assertNotIn("finalize", context.controller.events)
        for action, expected in ((2, 0), (3, 99)):
            context = Context()
            self.assertEqual(
                run("Ex2STRACT_04_SendMessage", words(action, 0), context), expected
            )
            self.assertIn("finalize", context.controller.events)
        context = Context()
        context.controller.replies = [(7, b"")]
        self.assertEqual(run("Ex2STRACT_04_SendMessage", words(2, 0), context), 1008)

    def test_lamp04_plus_terminal_status_and_18_host_finish(self) -> None:
        for source in (SHA_18_TY, SHA_PLUS_TY):
            context = Context(source)
            data = words(0, 1)
            if source == SHA_18_TY:
                context.on_sleep = lambda _, data=data: data.__setitem__(0, 1)
            self.assertEqual(run("Ex2LAMP_04_SendMessage", data, context), 0)
            self.assertIn("finalize", context.controller.events)
        context = Context(SHA_PLUS_TY)
        context.controller.replies = [(0, b"\x71\x03\x11\x04\x03")]
        self.assertEqual(run("Ex2LAMP_04_SendMessage", words(0, 1), context), 3)

    def test_lamp1_native_support_offsets_and_source_delta(self) -> None:
        for source in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY):
            context = Context(source, 4)
            data = words(0xAAAAAAAA, 0xBBBBBBBB)
            self.assertEqual(run("Ex2LAMP_01_SupportCheck", data, context), 0)
            self.assertEqual(data, words(5, 3))
            expected = 0
            self.assertEqual(
                run("Ex2LAMP_01_HeightSensorInitializationRequest", data, context),
                expected,
            )
            self.assertIn(b"\x30\x04\x00\x80\x80", context.controller.events)
            self.assertEqual(b"\x30" in context.controller.events, bool(expected))
            self.assertEqual(context.sleeps, [] if source == SHA_12_TY else [2000])

    def test_lamp1_malformed_missing_bitmap_and_native_fault(self) -> None:
        for snapshot, expected in (
            ((0, b"", (0x1020,) * 5), 22),
            ((0, b"\x04\x03", (0,) * 5), 99),
            ((0, b"\x04\x03\x80\x00\x00", (0,) * 5), 22),
            ((7, b"", ()), 7),
        ):
            context = Context(SHA_PLUS_TY, 4)
            context.controller.snapshot = snapshot
            data = words(5, 3)
            self.assertEqual(run("Ex2LAMP_01_SupportCheck", data, context), expected)
            self.assertEqual(data, words(5, 3))

    def test_abg_retains_then_live_completion_cleanup_and_native_delay(self) -> None:
        context = Context()
        self.assertEqual(run("Ex2ABG_02_StartLoadSpecInfo", words(0), context), 0)
        self.assertEqual(context.sleeps, [5000, 50, 50])
        self.assertNotIn("finalize", context.controller.events)
        self.assertEqual(run("Ex2ABG_02_CheckLoadSpecInfo", words(1), context), 1001)
        self.assertEqual(context.sleeps[-1], 50)
        self.assertEqual(context.controller.events[-1], "finalize")

    def test_abg_fault_and_status_projection(self) -> None:
        for value, expected in ((0, 1002), (2, 1000), (3, 1002)):
            context = Context()
            context.controller.replies = [(0, b"\x71\x03\x10\x07" + bytes((value,)))]
            self.assertEqual(
                run("Ex2ABG_02_CheckLoadSpecInfo", words(0), context), expected
            )
        context = Context()
        context.controller.replies = [(7, b"")]
        self.assertEqual(run("Ex2ABG_02_CheckLoadSpecInfo", words(0), context), 7)

    def test_eom_short_reply_echo_and_fault_preservation(self) -> None:
        for status, reply, expected in (
            (0, b"\x71\x01\x11", 3),
            (0, b"\x71\x01\x11\x81", 3),
            (7, b"", 7),
            (0, b"\x71\x01\x11\x80", 0),
        ):
            context = Context()
            context.controller.replies = [(status, reply)]
            self.assertEqual(run("Ex2EOM_01_ModeTransition", None, context), expected)
            self.assertEqual(context.controller.events[-1], "finalize")

    def test_invalid_buffers_precede_controller_acquisition(self) -> None:
        for export, data in (
            ("Ex2GWY_02_StartInit", bytearray(19)),
            ("Ex2STRACT_01_ModeTransition", bytearray(11)),
            ("Ex2LAMP_01_HeightSensorInitializationRequest", words(0xFFFFFFFF, 1)),
        ):
            context = Context(mode=4 if "LAMP_01" in export else 20)
            with self.assertRaises(ValueError):
                run(export, data, context)
            self.assertEqual(context.selectors, [])

    def test_cancellation_live_wait_releases_manager(self) -> None:
        context = Context()
        context.on_sleep = lambda _: setattr(context, "cancelled", True)
        with self.assertRaises(Cancelled):
            run("Ex2STRACT_01_ModeTransition", words(0, 0, 0), context)
        self.assertIn("finalize", context.controller.events)
        context = Context()
        context.cancelled = True
        with self.assertRaises(Cancelled):
            run("Ex2EOM_01_ModeTransition", None, context)
        self.assertEqual(context.selectors, [])

    def test_lamp_reply_success_and_malformed_release_all_sources(self) -> None:
        for source in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY):
            for reply, expected in (
                (b"\x70\x04", 0),
                (b"\x70\x05", 3),
                (b"\x70", 3),
                (b"\x70\x04\x00", 3),
            ):
                context = Context(source, 4)
                context.controller.replies = [(0, reply)]
                self.assertEqual(
                    run(
                        "Ex2LAMP_01_HeightSensorInitializationRequest",
                        words(5, 3),
                        context,
                    ),
                    expected,
                )
                self.assertEqual(
                    context.controller.events.count(b"\x30"), int(bool(expected))
                )

    def test_lamp_fixed_stack_bounds_before_controller_acquisition(self) -> None:
        for size, index in ((0x1020, 3), (0x101E, 3), (5, 0x101F)):
            context = Context(SHA_18_TY, 4)
            with self.assertRaises(ValueError):
                run(
                    "Ex2LAMP_01_HeightSensorInitializationRequest",
                    words(size, index),
                    context,
                )
            self.assertEqual(context.selectors, [])
        context = Context(SHA_18_TY, 4)
        self.assertEqual(
            run(
                "Ex2LAMP_01_HeightSensorInitializationRequest",
                words(0x101D, 0x101E),
                context,
            ),
            0,
        )
        context = Context(SHA_18_TY, 4)
        self.assertEqual(
            run(
                "Ex2LAMP_01_HeightSensorInitializationRequest",
                words(5, 0x101E),
                context,
            ),
            0,
        )

    def test_primary_host_and_cancel_identity_survive_cleanup_faults_once(self) -> None:
        for export, data in (
            ("Ex2EOM_01_ModeTransition", None),
            ("Ex2STRACT_01_ModeTransition", words(0, 0, 1)),
            ("Ex2LAMP_04_SendMessage", words(0, 1)),
            ("Ex2ABG_02_CheckLoadSpecInfo", words(0)),
        ):
            for primary in (
                ValueError("primary HOST fault"),
                Cancelled("primary cancellation"),
            ):
                context = Context()
                comm = context.controller
                original_session = comm.session

                def session(
                    mode: int,
                    keepalive: int = 1,
                    *,
                    normal_first: bool = False,
                    stop_on_error: bool = False,
                    context: Context = context,
                    original_session: Callable[..., int] = original_session,
                ) -> int:
                    if stop_on_error or mode == 1 and context.clock:
                        raise RuntimeError("secondary session cleanup fault")
                    return original_session(
                        mode,
                        keepalive,
                        normal_first=normal_first,
                        stop_on_error=stop_on_error,
                    )

                def finalize(comm: Comm = comm) -> None:
                    comm.events.append("finalize")
                    raise RuntimeError("secondary manager cleanup fault")

                with (
                    patch.object(comm, "exchange", side_effect=primary),
                    patch.object(comm, "session", side_effect=session),
                    patch.object(comm, "finalize", side_effect=finalize),
                    self.assertRaises(type(primary)) as caught,
                ):
                    run(export, data, context)
                self.assertIs(caught.exception, primary)
                self.assertEqual(comm.events.count("finalize"), 1)

    def test_first_cleanup_fault_survives_later_finalizer_fault(self) -> None:
        context = Context()
        primary = RuntimeError("normal session cleanup fault")
        with (
            patch.object(context.controller, "session", side_effect=primary),
            patch.object(
                context.controller,
                "finalize",
                side_effect=ValueError("secondary finalizer fault"),
            ) as finalized,
            self.assertRaises(RuntimeError) as caught,
        ):
            run("Ex2GWY_02_ErrorInit", words(0), context)
        self.assertIs(caught.exception, primary)
        self.assertEqual(finalized.call_count, 1)

    def test_unrelated_caller_exception_cannot_hide_sole_cleanup_fault(self) -> None:
        for export, data in (
            ("Ex2EOM_01_ModeTransition", None),
            ("Ex2GWY_02_ErrorInit", words(0)),
            ("Ex2LAMP_04_SendMessage", words(1, 1)),
        ):
            context = Context()
            cleanup = RuntimeError("sole manager cleanup fault")
            try:
                raise ValueError("unrelated caller exception")
            except ValueError:
                with (
                    patch.object(
                        context.controller, "finalize", side_effect=cleanup
                    ) as finalized,
                    self.assertRaises(RuntimeError) as caught,
                ):
                    run(export, data, context)
            self.assertIs(caught.exception, cleanup)
            self.assertEqual(finalized.call_count, 1)

        context = Context()
        cleanup = RuntimeError("sole session cleanup fault")
        try:
            raise ValueError("unrelated caller exception")
        except ValueError:
            with (
                patch.object(context.controller, "session", side_effect=cleanup),
                self.assertRaises(RuntimeError) as caught,
            ):
                run("Ex2GWY_02_ErrorInit", words(0), context)
        self.assertIs(caught.exception, cleanup)
        self.assertEqual(context.controller.events.count("finalize"), 1)


if __name__ == "__main__":
    unittest.main()
