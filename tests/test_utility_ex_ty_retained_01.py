"""Literal, authored packet vectors; never load or execute an OEM module."""

from __future__ import annotations

import json
import unittest
from collections import deque
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

from scripts import utility_ex_ty_retained_01 as retained
from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import SHA_12_TY, SHA_18_TY, SHA_PLUS_TY, TYSourceError
from tests.private_evidence import require_private


class Comm:
    def __init__(self, replies: list[tuple[int, bytes]]):
        self.replies = deque(replies)
        self.events: list[object] = []
        self.init_status = 0
        self.fault = False

    def initialize(self, mode: int = 0) -> int:
        self.events.append(("initialize", mode))
        return self.init_status

    def finalize(self) -> None:
        self.events.append("finalize")

    def configure(self, field: str, value: int) -> None:
        self.events.append((field, value))

    def select_target(self, first: int, second: int = 0) -> None:
        self.events.append(("select", first, second))

    def exchange(self, request: bytes) -> tuple[int, bytes]:
        self.events.append(request)
        if self.fault:
            raise OSError("authored lower fault")
        if not self.replies:
            raise AssertionError(f"Unexpected request {request.hex()}")
        return self.replies.popleft()

    def support_snapshot(self, kind: int) -> tuple[int, bytes, tuple[int, ...]]:
        self.events.append(("snapshot", kind))
        payload = bytearray()
        offsets = [0x1020] * 256
        entries = (
            ((0x26, b"\xff\xff"), (0x27, b"\xff\xff"), (0x23, b"\x01\x01\xff"))
            if kind == 1
            else ((1, b"\x80"),)
        )
        for identifier, values in entries:
            offsets[identifier] = len(payload)
            payload.extend(bytes((identifier, len(values))) + values)
        return 0, bytes(payload), tuple(offsets)


class Context:
    def __init__(
        self, export: str, replies: list[tuple[int, bytes]], source: str = SHA_18_TY
    ):
        self.module_sha256 = source
        self.module_bytes = b"authored source identity fixture"
        self.state: dict[str, object] = {}
        self.mode = 19 if "PSABSI" in export else 4
        self.communication = Comm(replies)
        self.clock = 0
        self.cancel = False
        self.on_sleep: Callable[[int], None] = lambda milliseconds: None

    def is_cancelled(self) -> bool:
        return self.cancel

    def ticks(self) -> int:
        return self.clock & 0xFFFFFFFF

    def native_sleep(self, milliseconds: int) -> None:
        self.clock += milliseconds
        self.on_sleep(milliseconds)

    def comm(self, kind: str) -> Comm:
        if kind != "selected":
            raise AssertionError("Wrong manager")
        return self.communication


def packet(content: bytes, sequence: int = 1, more: bool = False) -> bytes:
    return (
        b"\x75\xc0"
        + bytes((0x80 if more else 0xFF,))
        + sequence.to_bytes(3, "big")
        + bytes((len(content),))
        + content
        + b"\0\0"
    )


def fixture(export: str) -> tuple[bytearray, list[tuple[int, bytes]], int]:
    data = bytearray(0x207C if export.endswith("WriteVIN") else 44)
    values: list[bytes]
    result = 0
    if export.endswith("InitializeAllMemory"):
        values = [b"\xe6"]
    elif export.endswith(("DTCRead", "SupportCheck")):
        values = [b"\x53\0"]
    elif export.endswith("LearnZeroPos"):
        data[:20] = b"\x02\0\0\0\x03\0\0\0\x04\0\0\0\x04\0\0\0\x04\0\0\0"
        values = [b"\x70\x01", b"\x61\x23\0", b"\x61\x26\0\0", b"\x61\x27\0\0"]
    elif export.endswith("01_SendMessage"):
        values = [b"\x71\xaa\x01", b"\x71\xaa\x02"]
    elif export.endswith(("ExitEconomyMode", "SetMode", "ForcingOfGaugingRequest")):
        values = [b"\x71\xad\x01", b"\x71\xad\x02"]
    elif export.endswith("GetMode"):
        values = [packet(b"\0\x28\xff\xff"), b"\x61\xc0\x29"]
    elif export.endswith("BSIStatusCheck"):
        values = [
            packet(b"\x07\x1a\x1e\xff\xff"),
            b"\x61\xc7" + (b"\0" if "_05_" in export else b"\x02"),
        ]
        if "_07_" in export:
            result = 0x232A
    elif export.endswith("ExitCommunication"):
        values = []
    elif export.endswith("KeyRegister"):
        data[40] = 0x25
        values = [b"\x71\xa2\x01", b"\x71\xa2\x02"]
    elif export.endswith("UnlockRequest"):
        data[12] = 1
        values = [b"\x61\xc7\0", b"\x71\xa0\x01", b"\x71\xa0\x02"]
        if "_07_" in export:
            values += [b"\x50\x81", b"\x50\xc0"]
    elif export.endswith("ProgramADCCode"):
        data[9:13] = b"1234"
        values = [b"\x71\xa1\x01", b"\x71\xa1\x02"]
    elif export.endswith("GetVIN"):
        values = [b"\x61\xb0ABCDEFGHIJKLMNOPQ"]
    elif export.endswith("WriteVIN"):
        data[:17] = b"ABCDEFGHIJKLMNOPQ"
        values = [
            b"\x61\x80abcde",
            b"\x61\xfe" + bytes(range(24)),
            b"\x67\x83\0\0\0\0",
            b"\x7b\xb0",
        ]
    else:
        raise AssertionError(export)
    return data, [(0, value) for value in values], result


def invoke(export: str, context: Context, data: bytearray) -> int:
    argument = (
        (data,)
        if export
        in {
            "Ex2PSABSI_03_GetMode",
            "Ex2PSABSI_03_SetMode",
            "Ex2PSABSI_05_BSIStatusCheck",
            "Ex2PSABSI_05_KeyRegister",
            "Ex2PSABSI_05_UnlockRequest",
            "Ex2PSABSI_06_BSIStatusCheck",
            "Ex2PSABSI_06_ProgramADCCode",
            "Ex2PSABSI_07_BSIStatusCheck",
            "Ex2PSABSI_07_UnlockRequest",
            "Ex2PSABSI_08_GetVIN",
            "Ex2PSABSI_08_WriteVIN",
            "Ex2RWG_01_SupportCheck",
            "Ex2RWG_01_LearnZeroPos",
        }
        else ()
    )
    with patch.object(
        retained.hashlib,
        "sha256",
        return_value=SimpleNamespace(hexdigest=lambda: context.module_sha256),
    ):
        return retained.run_body(export, argument, cast(retained.Context, context))


class RetainedTests(unittest.TestCase):
    def test_exact_assigned_pairs_and_literal_positive_branches(self):
        require_private("analysis/evidence/no-car-120/assigned-source-pairs.json")
        pairs = json.loads(
            Path("analysis/evidence/no-car-120/assigned-source-pairs.json").read_text()
        )["pairs"]
        expected = {(item["source_sha256"], item["export"]) for item in pairs}
        actual = {
            (source, export)
            for source in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY)
            for export in retained.supported_exports(source)
        }
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 41)
        self.assertEqual(retained.supported_exports("0" * 64), ())
        for source, export in sorted(expected):
            with self.subTest(source=source[:12], export=export):
                data, replies, result = fixture(export)
                context = Context(export, replies, source)
                self.assertEqual(invoke(export, context, data), result)
                self.assertFalse(context.communication.replies)
                self.assertEqual(
                    context.state[retained._RESULT_GLOBALS[source]], result
                )
                retained_connection = (
                    export.endswith("KeyRegister")
                    or export == "Ex2PSABSI_05_UnlockRequest"
                )
                self.assertEqual(
                    "finalize" not in context.communication.events, retained_connection
                )
                if export.endswith("KeyRegister"):
                    self.assertIn(b"\x31\xa2\0\x25", context.communication.events)
                if export.endswith("GetMode"):
                    self.assertEqual(data[0], 0x29)
                if export.endswith("GetVIN"):
                    self.assertEqual(data[:18], b"ABCDEFGHIJKLMNOPQ\0")
                if export.endswith("SupportCheck"):
                    self.assertEqual(
                        data[:20],
                        bytes.fromhex("0400000005000000040000000400000004000000"),
                    )

    def test_actual97_and83_selected_dispatch_with_original_identity(self):
        from scripts.utility_ex import UtilityEx2TY, UtilityExContext
        from scripts.utility_ex_ty import run_body
        from tests.test_utility_ex import Host

        require_private("analysis/evidence/no-car-83/source-queue.json")
        rows = json.loads(
            Path("analysis/evidence/no-car-83/source-queue.json").read_text()
        )
        for source in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY):
            image_path = Path(
                next(row["input_path"] for row in rows if row["sha256"] == source)
            )
            image = image_path.read_bytes()
            for export in retained.supported_exports(source):
                with self.subTest(source=source[:12], export=export):
                    data, replies, expected = fixture(export)
                    arguments = (
                        (data,)
                        if export
                        not in (
                            "Ex2PSABSI_01_SendMessage",
                            "Ex2PSABSI_02_ExitEconomyMode",
                            "Ex2PSABSI_04_ForcingOfGaugingRequest",
                            "Ex2PSABSI_05_ExitCommunication",
                            "Ex2EVP_01_InitializeAllMemory",
                        )
                        else ()
                    )
                    host = Host()
                    host.values[0x6F] = 19 if "PSABSI" in export else 4
                    context = UtilityExContext(image, host, None, None)
                    communication = Comm(replies)
                    original_data = data[:]
                    with patch.object(context, "comm", return_value=communication):
                        self.assertEqual(run_body(export, arguments, context), expected)
                    self.assertFalse(communication.replies)
                    expected_data = data[:]
                    data[:] = original_data
                    public_host = Host()
                    public_host.values[0x6F] = host.values[0x6F]
                    public_context = UtilityExContext(image, public_host, None, None)
                    public_comm = Comm(replies)
                    engine = UtilityEx2TY(public_context)
                    with patch.object(public_context, "comm", return_value=public_comm):
                        self.assertEqual(engine.invoke(export, arguments), 15)
                        worker = engine.worker._thread
                        self.assertIsNotNone(worker)
                        assert worker is not None
                        worker.join(2)
                        self.assertFalse(worker.is_alive())
                        self.assertEqual(engine.worker.get_status(), expected)
                    self.assertEqual(data, expected_data)
                    self.assertEqual(public_comm.events, communication.events)
                    self.assertFalse(public_comm.replies)
                    self.assertEqual(
                        public_context.state[retained._RESULT_GLOBALS[source]], expected
                    )

    def test_identity_wrong_mode_arguments_and_excluded_pair(self):
        export = "Ex2EVP_01_InitializeAllMemory"
        context = Context(export, [])
        with self.assertRaises(TYSourceError):
            retained.run_body(export, (), cast(retained.Context, context))
        context.mode = 5
        self.assertEqual(invoke(export, context, bytearray()), 99)
        self.assertEqual(context.communication.events, [])
        with self.assertRaises(TYSourceError):
            invoke(export, Context(export, [], SHA_12_TY), bytearray())
        with self.assertRaises(ValueError):
            invoke(
                "Ex2PSABSI_05_KeyRegister",
                Context("Ex2PSABSI_05_KeyRegister", []),
                bytearray(43),
            )

    def test_literal_negative_response_fallback_and_forcing_mappings(self):
        export = "Ex2PSABSI_02_ExitEconomyMode"
        context = Context(
            export, [(7, b"\x7f\x31\x12"), (0, b"\x71\xad\x01"), (0, b"\x71\xad\x02")]
        )
        self.assertEqual(invoke(export, context, bytearray()), 0)
        self.assertIn(b"\x31\xad\0\0\xc8\x01", context.communication.events)
        export = "Ex2PSABSI_04_ForcingOfGaugingRequest"
        for nrc, result in ((0x12, 0x2330), (0x22, 0x2331)):
            context = Context(export, [(7, bytes((0x7F, 0x31, nrc)))])
            self.assertEqual(invoke(export, context, bytearray()), result)
            self.assertEqual(
                context.communication.events[:4],
                [
                    ("initialize", 0),
                    ("native_rva:12180", 150),
                    ("native_rva:121d0", 150),
                    ("native_rva:12200", 1000),
                ],
            )

    def test_poll_timeout_wraparound_malformed_and_native_fault(self):
        export = "Ex2PSABSI_01_SendMessage"
        context = Context(export, [(0, b"\x71\xaa\x01")] + [(0, b"\x71\xaa\x01")] * 21)
        context.clock = 0xFFFFFF00
        self.assertEqual(invoke(export, context, bytearray()), 0x238D)
        for reply in (b"", b"\x71\xab\x01", b"\x71\xaa"):
            context = Context(export, [(0, reply)])
            self.assertEqual(invoke(export, context, bytearray()), 3)
            self.assertEqual(context.communication.events[-1], "finalize")
        context = Context(export, [])
        context.communication.fault = True
        with self.assertRaisesRegex(OSError, "authored lower fault"):
            invoke(export, context, bytearray())
        self.assertEqual(context.communication.events[-1], "finalize")

    def test_key_registration_retention_and_status_map(self):
        export = "Ex2PSABSI_05_KeyRegister"
        for value, result in (
            (8, 0x2340),
            (16, 0x2341),
            (17, 0x2342),
            (18, 0x2343),
            (19, 0x2344),
            (4, 0x2345),
            (255, 0x2346),
            (254, 0x2347),
            (32, 0x2348),
            (240, 0x2349),
            (99, 0x234A),
        ):
            data, replies, _ = fixture(export)
            replies[-1] = (0, bytes((0x71, 0xA2, value)))
            context = Context(export, replies)
            self.assertEqual(invoke(export, context, data), result)
            self.assertNotIn("finalize", context.communication.events)
            self.assertNotIn(("initialize", 0), context.communication.events)
        context = Context("Ex2PSABSI_05_ExitCommunication", [])
        self.assertEqual(
            invoke("Ex2PSABSI_05_ExitCommunication", context, bytearray()), 0
        )
        self.assertEqual(context.communication.events, ["finalize"])

    def test_program_adc_publishes_native_global_before_cleanup(self):
        export = "Ex2PSABSI_06_ProgramADCCode"
        for source, key in (
            (SHA_12_TY, "native_global:100ab770"),
            (SHA_18_TY, "native_global:10118e38"),
        ):
            for initial_status in (0, 71):
                data, replies, _ = fixture(export)
                context = Context(export, replies, source)
                context.communication.init_status = initial_status

                def cleanup(context=context, key=key, initial_status=initial_status):
                    self.assertEqual(context.state[key], initial_status)
                    context.communication.events.append("finalize")

                with patch.object(
                    context.communication, "finalize", side_effect=cleanup
                ):
                    self.assertEqual(invoke(export, context, data), initial_status)

    def test_native_poll_error_mappings_and_retained_locked_branch(self):
        for export, identifier, mappings in (
            (
                "Ex2PSABSI_05_UnlockRequest",
                0xA0,
                {0: 0x2336, 254: 0x2336, 16: 0x2339, 4: 0x233A, 32: 0x233A, 9: 0x2338},
            ),
            (
                "Ex2PSABSI_06_ProgramADCCode",
                0xA1,
                {0: 0x2337, 254: 0x2337, 16: 0x2338, 9: 0x2339},
            ),
            ("Ex2PSABSI_07_UnlockRequest", 0xA0, {4: 0x232E, 16: 0x232F, 9: 0x2330}),
        ):
            for value, expected in mappings.items():
                data, replies, _ = fixture(export)
                index = 2 if "Unlock" in export else 1
                replies[index] = (0, bytes((0x71, identifier, value)))
                replies = replies[: index + 1]
                context = Context(export, replies)
                self.assertEqual(invoke(export, context, data), expected)
                self.assertEqual(context.communication.events[-1], "finalize")
        export = "Ex2PSABSI_05_UnlockRequest"
        data, _, _ = fixture(export)
        context = Context(export, [(0, b"\x61\xc7\x01")])
        self.assertEqual(invoke(export, context, data), 0x2330)
        self.assertNotIn("finalize", context.communication.events)

    def test_unlock_retry_count_and_seven_retained_status(self):
        export = "Ex2PSABSI_05_UnlockRequest"
        data, replies, _ = fixture(export)
        retained._put(data, 20, 2)
        replies[-1] = (0, b"\x71\xa0\x04")
        context = Context(export, replies)
        self.assertEqual(invoke(export, context, data), 0x233B)
        self.assertEqual(retained._u32(data, 20), 3)
        self.assertEqual(context.communication.events[-1], "finalize")
        export = "Ex2PSABSI_07_UnlockRequest"
        data, replies, _ = fixture(export)
        replies[-2] = (77, b"")
        context = Context(export, replies)
        # The reset attempt does not replace successful unlock business status.
        self.assertEqual(invoke(export, context, data), 0)
        self.assertEqual(context.communication.events[-1], "finalize")

    def test_security_mutable_host_handshake_and_cancel(self):
        export = "Ex2PSABSI_08_WriteVIN"
        data, replies, _ = fixture(export)
        retained._put(data, 0x2068, 5000)
        replies[2] = (0, b"\x67\x83\x01\x02\x03\x04")
        replies.insert(3, (0, b"\x67\x84"))
        context = Context(export, replies)

        def action(milliseconds: int):
            if milliseconds == 2000:
                self.assertEqual(retained._u32(data, 0x206C), 0x1771)
                data[0x2078:0x207C] = b"KEY!"
                retained._put(data, 0x2068, 0x138A)

        context.on_sleep = action
        self.assertEqual(invoke(export, context, data), 0)
        self.assertIn(b"\x27\x84KEY!", context.communication.events)
        self.assertEqual(retained._u32(data, 0x206C), 0x1772)
        self.assertEqual(retained._u32(data, 0x2068), 5000)
        context = Context(
            export,
            [
                (0, b"\x61\x80abcde"),
                (0, b"\x61\xfe" + bytes(24)),
                (0, b"\x67\x83\x01\x02\x03\x04"),
            ],
        )
        data = bytearray(0x207C)
        retained._put(data, 0x2068, 5000)
        context.on_sleep = lambda ms: setattr(context, "cancel", ms == 2000)
        with self.assertRaises(Cancelled):
            invoke(export, context, data)
        self.assertEqual(context.communication.events[-1], "finalize")

    def test_rwg_initialize_error_stops_before_finalize_all_sources(self):
        export = "Ex2RWG_01_LearnZeroPos"
        for source in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY):
            data, _, _ = fixture(export)
            context = Context(export, [(71, b"")], source)
            context.communication.init_status = 29
            self.assertEqual(invoke(export, context, data), 29)
            self.assertEqual(
                context.communication.events, [("initialize", 0), b"\x30", "finalize"]
            )
            self.assertEqual(context.state[retained._RESULT_GLOBALS[source]], 29)

    def test_final_descriptor_marker_uses_ff_tail_and_writes_zero_length(self):
        content = b"\x00\x28\xff\x07"
        self.assertEqual(
            retained._field(content, 0xC7, 0x1E, retained._STATUS_FIELDS),
            (3, 0, 255, 0),
        )
        export = "Ex2PSABSI_05_BSIStatusCheck"
        data = bytearray(range(28))
        expected = data[:]
        expected[:4] = bytes(4)
        expected[12] = 255
        context = Context(export, [(0, packet(content))])
        self.assertEqual(invoke(export, context, data), 3)
        self.assertEqual(data, expected)

    def test_descriptor_double_ff_terminates_marker_table(self):
        for content in (
            b"\x00\x28\xff\xff\x00\x15\xff",
            b"\x00\x28\xff\xff\x07\x1a\xff",
        ):
            self.assertEqual(
                retained._field(content, 0xC0, 0x28, retained._MODE_FIELDS),
                (0, 0, 255, 1),
            )
            self.assertEqual(
                retained._field(content, 0xC7, 0x1A, retained._STATUS_FIELDS),
                (3, 0, 255, None),
            )

    def test_rwg_asm_loop_survives_decompiler_loss(self):
        for source in (SHA_12_TY, SHA_18_TY, SHA_PLUS_TY):
            export = "Ex2RWG_01_LearnZeroPos"
            data, _, _ = fixture(export)
            replies = [(0, b"\x70\x01")]
            for _ in range(20):
                replies += [
                    (0, b"\x61\x23\xff"),
                    (0, b"\x61\x26\0\0"),
                    (0, b"\x61\x27\0\0"),
                ]
            replies += [(99, b"")]
            context = Context(export, replies, source)
            self.assertEqual(invoke(export, context, data), 1000)
            self.assertEqual(context.communication.events[-2:], [b"\x30", "finalize"])
            self.assertEqual(context.clock, 10000)

    def test_missing_descriptor_keeps_native_output_fields(self):
        export = "Ex2PSABSI_03_GetMode"
        data = bytearray.fromhex("112233445566778899aabbccddeeff00")
        before = data[:]
        context = Context(export, [(0, packet(b"\x07\xff\xff"))])
        self.assertEqual(invoke(export, context, data), 3)
        self.assertEqual(data, before)
        self.assertEqual(
            retained._field(b"\x07\x1a", 0xC7, 0x1A, {0x1A: 1}), (0, 0, 1, 1)
        )

    def test_descriptor_segments_fields_and_native_faults(self):
        context = Context(
            "Ex2PSABSI_03_GetMode",
            [(0, packet(bytes(17), more=True)), (0, packet(b"\xff\xff", 2))],
        )
        status, content = retained._download(
            cast(retained.TYComm, context.communication),
            cast(retained.Context, context),
        )
        self.assertEqual((status, len(content)), (0, 19))
        self.assertEqual(
            context.communication.events, [b"\x35\xc0\0\0\1\x11", b"\x35\xc0\0\0\2\x11"]
        )
        self.assertEqual(
            retained._field(b"\x07\x1a\x1e\xff\xff", 0xC7, 0x1E, {0x1A: 1, 0x1E: 1}),
            (0, 0, 2, 1),
        )
        self.assertEqual(
            retained._field(b"\x07\x1a\x1e\xff\xff", 0xC7, 0x1E, {}), (3, 0, 255, 0)
        )
        context = Context("Ex2PSABSI_03_GetMode", [(0, packet(b"\0\x28\xff\xff", 2))])
        self.assertEqual(
            retained._download(
                cast(retained.TYComm, context.communication),
                cast(retained.Context, context),
            )[0],
            3,
        )


if __name__ == "__main__":
    unittest.main()
