"""Authored literal EYES controller vectors; OEM modules never execute."""

from __future__ import annotations

import struct
import tempfile
import unittest
from collections import deque
from pathlib import Path
from typing import cast
from unittest.mock import patch

from scripts import utility_ex_ms2_eyes as eyes
from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import SHA_18_TY, SHA_PLUS_TY, TYContext, TYSourceError


class Comm:
    def __init__(self) -> None:
        self.calls: list[object] = []
        self.replies: deque[tuple[int, bytes]] = deque()
        self.initial = self.normal = 0
        self.fault: BaseException | None = None
        self.final_fault: BaseException | None = None

    def initialize(self, mode: int = 0) -> int:
        self.calls.append(("initialize", mode))
        return self.initial

    def configure(self, field: str, value: int) -> None:
        self.calls.append((field, value))

    def configure_target(self, *values: int) -> None:
        self.calls.append(("target", *values))

    def select_diagnostic_mode(self, value: int) -> int:
        self.calls.append(("diagnostic_mode", value))
        return 0

    def keepalive(self, enabled: bool, wait: bool = False) -> int:
        self.calls.append(("keepalive", enabled, wait))
        return 0

    def session(self, mode: int, keepalive: int = 1, **options: bool) -> int:
        self.calls.append(("session", mode, options))
        return self.normal

    def exchange(self, frame: bytes) -> tuple[int, bytes]:
        self.calls.append(frame)
        if self.fault is not None:
            raise self.fault
        if not self.replies:
            raise AssertionError(f"Unexpected authored wire {frame.hex()}")
        return self.replies.popleft()

    def finalize(self) -> None:
        self.calls.append("finalize")
        if self.final_fault is not None:
            raise self.final_fault


class Context:
    def __init__(self, source: str = SHA_18_TY) -> None:
        self.module_sha256 = source
        self.module_bytes = b"authored no OEM image"
        self.state: dict[str, object] = {}
        self.mode = 52
        self.cancel = False
        self.clock = 0
        self.sleeps: list[int] = []
        self.primary, self.secondary, self.auxiliary = Comm(), Comm(), Comm()
        self.selected: list[str] = []

    def comm(self, kind: str) -> object:
        self.selected.append(kind)
        layout = eyes._LAYOUT[self.module_sha256]
        return (
            self.secondary
            if kind == layout[0]
            else self.auxiliary
            if kind == layout[1]
            else self.primary
        )

    def is_cancelled(self) -> bool:
        return self.cancel

    def ticks(self) -> int:
        return self.clock

    def native_sleep(self, duration: int) -> None:
        self.sleeps.append(duration)
        self.clock += duration


SOURCES = (SHA_18_TY, SHA_PLUS_TY)
IDS = tuple(range(0x3081, 0x308E))


def message(number: int, action: int = 0) -> bytearray:
    data = bytearray(
        {1: 0x104, 2: 4, 3: 8, 4: 20, 5: 0x4A4, 6: 0x188, 7: 0x27C}[number]
    )
    struct.pack_into("<I", data, 0, action)
    return data


def read_reply(identifier: int, payload: bytes) -> tuple[int, bytes]:
    return 0, b"\x62" + identifier.to_bytes(2, "big") + payload


def routine_reply(identifier: int, sub: int, payload: bytes = b"") -> tuple[int, bytes]:
    return 0, b"\x71" + bytes([sub]) + identifier.to_bytes(2, "big") + payload


class EyesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.auth = patch.object(eyes.security, "_authenticate").start()
        self.security = patch.object(eyes, "_auth", return_value=0).start()
        self.tables = patch.object(eyes, "_ids", return_value=IDS).start()
        self.addCleanup(patch.stopall)

    def run_body(self, number: int, context: Context, data: bytearray) -> int:
        return eyes.invoke_export(
            f"Ex2MS2EYES_{number:02}_SendMessage", cast(TYContext, context), data
        )

    def test_exact_source_and_argument_guards(self) -> None:
        self.assertEqual(len(eyes.supported_exports(SHA_18_TY)), 7)
        self.assertEqual(eyes.supported_exports("other"), ())
        for number in range(1, 8):
            for source in SOURCES:
                context = Context(source)
                with (
                    self.subTest(number=number, source=source),
                    self.assertRaises(ValueError),
                ):
                    self.run_body(number, context, bytearray(3))
                self.assertEqual(context.selected, [])
        patch.stopall()
        with self.assertRaises(TYSourceError):
            self.run_body(2, Context(), message(2))

    def test_all14_initialization_failure_closes_each_native_manager(self) -> None:
        for source in SOURCES:
            for number in range(1, 8):
                context = Context(source)
                context.primary.initial = 19
                with self.subTest(source=source, number=number):
                    self.assertEqual(
                        self.run_body(
                            number, context, message(number, 1 if number == 4 else 0)
                        ),
                        19,
                    )
                    self.assertEqual(context.primary.calls.count("finalize"), 1)
                    if number != 1:
                        self.assertEqual(context.secondary.calls, ["finalize"])
                    if number == 5:
                        self.assertEqual(context.auxiliary.calls, ["finalize"])

    def test_all14_host_fault_identity_and_cleanup_fault_precedence(self) -> None:
        for source in SOURCES:
            for number in range(1, 8):
                context = Context(source)
                fault = OSError("authored driver failure")
                context.primary.fault = fault
                context.primary.final_fault = RuntimeError("cleanup failed")
                data = message(number, 1 if number in (4, 7) else 0)
                if number == 6:
                    struct.pack_into("<I", data, 0x184, 1)
                with (
                    self.subTest(source=source, number=number),
                    self.assertRaises(OSError) as raised,
                ):
                    self.run_body(number, context, data)
                self.assertIs(raised.exception, fault)
                self.assertEqual(context.primary.calls.count("finalize"), 1)

    def test_cancel_before_manager_selection(self) -> None:
        for source in SOURCES:
            for number in range(1, 8):
                context = Context(source)
                context.cancel = True
                with (
                    self.subTest(source=source, number=number),
                    self.assertRaises(Cancelled),
                ):
                    self.run_body(number, context, message(number))
                self.assertEqual(context.selected, [])

    def test_first_cleanup_fault_propagates_without_business_fault(self) -> None:
        context = Context()
        context.primary.initial = 19
        fault = OSError("finalize failure")
        context.primary.final_fault = fault
        context.secondary.final_fault = RuntimeError("second cleanup failure")
        with self.assertRaises(OSError) as raised:
            self.run_body(2, context, message(2))
        self.assertIs(raised.exception, fault)
        self.assertEqual(context.secondary.calls, ["finalize"])

    def test_eyes01_both_support_banks_preserve_input_and_outputs(self) -> None:
        for source in SOURCES:
            context, data = Context(source), message(1)
            # Support0200 and0220 advertise0223/0224;3000 advertises3001.
            context.primary.replies.extend(
                [
                    read_reply(0x200, b"\0\0\0\x01"),
                    read_reply(0x220, b"\x30\0\0\0"),
                    read_reply(0x3000, b"\x80\0\0\0"),
                    read_reply(0x3000, b"\0\0\0\x01"),
                    read_reply(0x3020, b"\0\0\0\x01"),
                    read_reply(0x3040, b"\x80\0\0\0"),
                ]
            )
            self.assertEqual(self.run_body(1, context, data), 0)
            self.assertEqual(struct.unpack_from("<2I", data), (1, 1))
            self.assertFalse(context.primary.replies)

    def test_eyes01_pair_skip_3020_and_partial_count(self) -> None:
        context, data = Context(), message(1)
        struct.pack_into("<2I", data, 8, 1, 1)
        identifiers = [
            identifier for identifier in range(0x3001, 0x302A) if identifier != 0x3020
        ]
        for identifier in identifiers:
            context.primary.replies.append(
                read_reply(
                    identifier,
                    b"\x01" if identifier & 1 and identifier < 0x3020 else b"\x12\x34",
                )
            )
        self.assertEqual(self.run_body(1, context, data), 0)
        self.assertEqual(struct.unpack_from("<I", data, 0x100)[0], 20)
        self.assertNotIn(b"\x22\x30\x20", context.primary.calls)

    def test_eyes02_poll_stop_restore_and_invalid_reply(self) -> None:
        for source in SOURCES:
            context = Context(source)
            context.primary.replies.extend(
                [
                    routine_reply(0x2003, 1),
                    routine_reply(0x2003, 3, b"\1"),
                    routine_reply(0x2003, 3, b"\2"),
                    routine_reply(0x2003, 2),
                ]
            )
            self.assertEqual(self.run_body(2, context, message(2)), 0)
            self.assertEqual(context.sleeps, [100])
            self.assertIn(b"\x31\2\x20\3", context.primary.calls)
            context = Context(source)
            context.primary.replies.extend(
                [routine_reply(0x2003, 1), routine_reply(0x2003, 3, b"\3")]
            )
            self.assertEqual(self.run_body(2, context, message(2)), 3)

    def test_eyes02_abort_and_auth_failure(self) -> None:
        context = Context()
        self.assertEqual(self.run_body(2, context, message(2, 1)), 1004)
        context = Context()
        self.security.return_value = 7
        self.assertEqual(self.run_body(2, context, message(2)), 1001)
        self.assertFalse(any(isinstance(call, bytes) for call in context.primary.calls))

    def test_eyes03_retains_then_finishes_with_output(self) -> None:
        for source in SOURCES:
            context = Context(source)
            context.primary.replies.extend(
                [
                    (0, b"\x50\1\0\0\0\0"),
                    (0, b"\x50\3\0\0\0\0"),
                    read_reply(0x221, b"\0"),
                    read_reply(0x231, b"\0"),
                    routine_reply(0x1001, 1),
                    routine_reply(0x1001, 3, b"\x10\x02"),
                    routine_reply(0x100F, 1),
                ]
            )
            self.assertEqual(self.run_body(3, context, message(3)), 0)
            self.assertNotIn("finalize", context.primary.calls)
            data = message(3, 1)
            context.primary.replies.extend(
                [
                    routine_reply(0x100F, 3, b"\x15\0"),
                    routine_reply(0x1001, 2),
                    (0, b"\x50\1\0\0\0\0"),
                ]
            )
            self.assertEqual(self.run_body(3, context, data), 0)
            self.assertEqual(struct.unpack_from("<I", data, 4)[0], 0x1500)
            self.assertEqual(context.primary.calls.count("finalize"), 1)

    def test_eyes04_start_progress_retention_and_finish(self) -> None:
        for source in SOURCES:
            context, data = Context(source), message(4, 1)
            context.primary.replies.extend(
                [
                    (0, b"\x50\1\0\0\0\0"),
                    (0, b"\x50\3\0\0\0\0"),
                    read_reply(0x221, b"\0"),
                    read_reply(0x231, b"\0"),
                    routine_reply(0x1001, 1),
                    routine_reply(0x1001, 3, b"\x10\2"),
                ]
            )
            self.assertEqual(self.run_body(4, context, data), 1000)
            self.assertEqual(struct.unpack_from("<4I", data, 4), (1, 1, 0, 0x1002))
            self.assertNotIn("finalize", context.primary.calls)
            struct.pack_into("<I", data, 0, 2)
            context.primary.replies.extend(
                [routine_reply(0x1002, 1), routine_reply(0x1002, 3, b"\x14\x0f")]
            )
            self.assertEqual(self.run_body(4, context, data), 5000)
            self.assertNotIn("finalize", context.primary.calls)
            struct.pack_into("<I", data, 0, 3)
            context.primary.replies.extend(
                [routine_reply(0x100E, 1), routine_reply(0x100E, 3, b"\x15\0")]
            )
            self.assertEqual(self.run_body(4, context, data), 0)
            self.assertNotIn("finalize", context.primary.calls)
            struct.pack_into("<I", data, 0, 4)
            context.primary.replies.extend(
                [
                    routine_reply(0x1008, 1),
                    routine_reply(0x1008, 3, b"\x13\0"),
                    routine_reply(0x1001, 2),
                    (0, b"\x50\1\0\0\0\0"),
                ]
            )
            self.assertEqual(self.run_body(4, context, data), 0)
            self.assertEqual(context.primary.calls.count("finalize"), 1)

    def test_eyes04_timeout_publishes_latch_and_cleans(self) -> None:
        context, data = Context(), message(4, 4)
        context.primary.replies.append(routine_reply(0x1008, 1))
        context.primary.replies.extend([routine_reply(0x1008, 3, b"\x10\1")] * 601)
        self.assertEqual(self.run_body(4, context, data), 8000)
        self.assertEqual(struct.unpack_from("<I", data, 12)[0], 1)
        self.assertEqual(context.clock, 60000)

    def test_eyes05_vin_records_and_all_zero_status(self) -> None:
        for source in SOURCES:
            context, data = Context(source), message(5, 1)
            context.auxiliary.replies.append((0, b"\x49\2\1" + b"A" * 17))
            context.primary.replies.extend(
                read_reply(identifier, bytes([i + 1]))
                for i, identifier in enumerate(IDS)
            )
            self.assertEqual(self.run_body(5, context, data), 0)
            self.assertEqual(data[4:22], b"A" * 17 + b"\0")
            self.assertEqual(struct.unpack_from("<I", data, 0x198)[0], 13)
            self.assertEqual(struct.unpack_from("<I", data, 0x4A0)[0], 13)
            self.assertEqual(data[0x18:0x24], data[0x320:0x32C])
            context, data = Context(source), message(5, 2)
            context.primary.replies.extend(
                read_reply(identifier, b"\0") for identifier in IDS
            )
            self.assertEqual(self.run_body(5, context, data), 9800)
            self.assertNotIn("finalize", context.primary.calls)
            self.assertIn("finalize", context.auxiliary.calls)

    def test_eyes05_write_compare_retry_and_retained_vin_mismatch(self) -> None:
        context, data = Context(), message(5, 4)
        for i, identifier in enumerate(IDS):
            struct.pack_into("<3I", data, 0x320 + i * 12, identifier, i + 1, 1)
            context.primary.replies.append((0, b"\x6e" + identifier.to_bytes(2, "big")))
        context.primary.replies.extend(
            read_reply(identifier, bytes([i + 1])) for i, identifier in enumerate(IDS)
        )
        self.assertEqual(self.run_body(5, context, data), 1004)
        self.assertEqual(
            sum(
                isinstance(call, bytes) and call[0] == 0x2E
                for call in context.primary.calls
            ),
            13,
        )
        context, data = Context(), message(5, 3)
        context.auxiliary.replies.append((0, b"\x49\2\1" + b"B" * 17))
        self.assertEqual(self.run_body(5, context, data), 1018)
        self.assertNotIn("finalize", context.primary.calls)

    def test_eyes06_capture_records_and_partial_failure(self) -> None:
        for source in SOURCES:
            context, data = Context(source), message(6)
            struct.pack_into("<I", data, 0x184, 1)
            context.primary.replies.extend(
                read_reply(identifier, b"\x12\x34") for identifier in IDS[:3]
            )
            context.primary.replies.append((19, b""))
            self.assertEqual(self.run_body(6, context, data), 19)
            self.assertEqual(struct.unpack_from("<I", data, 0x180)[0], 3)
            self.assertEqual(data[4:6], b"\x12\x34")
            self.assertEqual(context.primary.calls.count("finalize"), 1)

    def test_eyes07_summary_globals_and_changed_flag(self) -> None:
        for source in SOURCES:
            context = Context(source)
            with patch.object(
                eyes, "_data", return_value=struct.pack("<2H", 0x4001, 0x5001)
            ):
                for values in ((1, 0), (0, 1)):
                    data = message(7)
                    context.primary.replies.extend(
                        read_reply(start + i, struct.pack("<H", values[group]))
                        for group, start in enumerate((0x4001, 0x5001))
                        for i in range(4)
                    )
                    self.assertEqual(self.run_body(7, context, data), 0)
                    self.assertEqual(struct.unpack_from("<2I", data, 24), values)
                self.assertEqual(struct.unpack_from("<I", data, 32)[0], 1)
                base = cast(int, eyes._LAYOUT[source][9])
                self.assertEqual(context.state[f"native_global:{base:08x}"], 1)

    def test_eyes07_capture_header_and_save_retries(self) -> None:
        for source in SOURCES:
            context, data = Context(source), message(7, 1)
            context.primary.replies.append(read_reply(0xF100, b"ABC"))
            table = bytes(140)
            with (
                patch.object(
                    eyes,
                    "_data",
                    side_effect=lambda ctx, rva, size, table=table: (
                        table if size == 140 else b"seed"
                    ),
                ),
                patch.object(eyes, "_save_capture", side_effect=[2004, 0]) as save,
            ):
                self.assertEqual(self.run_body(7, context, data), 0)
                capture = save.call_args.args[2]
                self.assertEqual(capture[:3], b"PRE")
                self.assertEqual(capture[6], 1)
                self.assertEqual(capture[12:16], bytes(4))
                self.assertEqual(capture[16:19], b"ABC")
                self.assertEqual(save.call_count, 2)

    def test_eyes07_read_failure_retains_managers(self) -> None:
        context = Context()
        context.primary.replies.append((19, b""))
        self.assertEqual(self.run_body(7, context, message(7, 1)), 2002)
        self.assertNotIn("finalize", context.primary.calls)
        self.assertNotIn("finalize", context.secondary.calls)

    def test_nrc_retries_and_global_are_source_specific(self) -> None:
        for source in SOURCES:
            context = Context(source)
            context.primary.replies.extend([(7, b"\x7f\x31\x22")] * 30)
            status, _ = eyes._routine(
                cast(TYContext, context), cast(eyes.TYComm, context.primary), 0x1001, 1
            )
            self.assertEqual(status, 7)
            key = "1012ae38" if source == SHA_18_TY else "10153554"
            self.assertEqual(context.state["native_global:" + key], 0x22)
            self.assertEqual(len(context.sleeps), 30)

    def test_rc4_published_vector_and_round_trip(self) -> None:
        data = bytearray(b"Plaintext")
        eyes._rc4(data, b"Key")
        self.assertEqual(data.hex(), "bbf316e8d940af0ad3")
        eyes._rc4(data, b"Key")
        self.assertEqual(data, b"Plaintext")

    def test_capture_file_sink_encoding_and_collision_preservation(self) -> None:
        for source in SOURCES:
            context, data = Context(source), message(7, 1)
            with tempfile.TemporaryDirectory() as folder:
                wide = source == SHA_PLUS_TY
                encoded = (folder + "\0").encode("utf-16-le" if wide else "ascii")
                data[0x38 : 0x38 + len(encoded)] = encoded
                suffix = ".pre\0".encode("utf-16-le" if wide else "ascii")
                with patch.object(eyes, "_data", return_value=suffix):
                    self.assertEqual(
                        eyes._save_capture(cast(TYContext, context), data, b"authored"),
                        0,
                    )
                    files = list(Path(folder).iterdir())
                    self.assertEqual(len(files), 1)
                    self.assertEqual(files[0].read_bytes(), b"authored")
                    self.assertEqual(
                        eyes._save_capture(
                            cast(TYContext, context), data, b"replacement"
                        ),
                        2004,
                    )
                    self.assertEqual(files[0].read_bytes(), b"authored")

    def test_eyes05_compare_is_bounded_to_eleven_native_attempts(self) -> None:
        context, data = Context(), message(5, 4)
        for index, identifier in enumerate(IDS):
            struct.pack_into("<3I", data, 0x320 + index * 12, identifier, 1, 1)
        for _ in range(11):
            context.primary.replies.extend(
                (0, b"\x6e" + identifier.to_bytes(2, "big")) for identifier in IDS
            )
            context.primary.replies.extend(
                read_reply(identifier, b"\2") for identifier in IDS
            )
        self.assertEqual(self.run_body(5, context, data), 1001)
        self.assertEqual(
            sum(isinstance(call, bytes) for call in context.primary.calls), 286
        )
        self.assertEqual(context.primary.calls.count("finalize"), 1)

    def test_cancellation_during_poll_finalizes_both_managers(self) -> None:
        class CancelOnSleep(Context):
            def native_sleep(self, duration: int) -> None:
                super().native_sleep(duration)
                self.cancel = True

        for source in SOURCES:
            context = CancelOnSleep(source)
            context.primary.replies.extend(
                [routine_reply(0x2003, 1), routine_reply(0x2003, 3, b"\1")]
            )
            with self.assertRaises(Cancelled):
                self.run_body(2, context, message(2))
            self.assertEqual(context.primary.calls.count("finalize"), 1)
            self.assertEqual(context.secondary.calls.count("finalize"), 1)

    def test_empty_capture_directory_never_writes_to_working_directory(self) -> None:
        for source in SOURCES:
            context, data = Context(source), message(7, 1)
            self.assertEqual(
                eyes._save_capture(cast(TYContext, context), data, b"authored"), 2004
            )

    def test_eyes05_broadcast_api_is_distinct_from_lower_protocol(self) -> None:
        context = Context()
        context.primary.replies.extend([read_reply(0x3000, bytes(4))])
        self.assertEqual(self.run_body(5, context, message(5)), 3)
        self.assertEqual(
            context.auxiliary.calls[:2],
            [("diagnostic_mode", 3), ("target", 0x7A2, 0, 0x7DF, 0, 0x7E0)],
        )

    def test_capture_base_csp_40_bit_default_keeps_eleven_zero_salt_bytes(self) -> None:
        # Authored seed/zero plaintext; independent OpenSSL RC4 legacy-provider vector.
        expected = bytes.fromhex(
            "8d8cae4c92f4f63466b6461d2bb43275756760222018400caf47677180c816b5"
        )
        for source in SOURCES:
            context, data = Context(source), message(7, 1)
            struct.pack_into("<I", data, 40, 1)
            context.primary.replies.append(read_reply(0xF100, b"ABC"))
            with (
                patch.object(
                    eyes,
                    "_data",
                    side_effect=lambda ctx, rva, size: (
                        bytes(140) if size == 140 else b"seed"
                    ),
                ),
                patch.object(eyes, "_save_capture", return_value=0) as save,
            ):
                self.assertEqual(self.run_body(7, context, data), 0)
                self.assertEqual(save.call_args.args[2][256:288], expected)

    def test_direct_read_nrc_publishes_without_retry_helper_sleep(self) -> None:
        for source in SOURCES:
            context = Context(source)
            context.primary.replies.append((7, b"\x7f\x22\x31"))
            status, _ = eyes._read(
                cast(TYContext, context), cast(eyes.TYComm, context.primary), 0x3001
            )
            self.assertEqual(status, 7)
            self.assertEqual(context.sleeps, [])
            global_key = "1012ae38" if source == SHA_18_TY else "10153554"
            self.assertEqual(context.state["native_global:" + global_key], 0x31)


if __name__ == "__main__":
    unittest.main()
