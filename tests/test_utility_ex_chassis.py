"""Authored synthetic wire observations; never loads an OEM module."""

from __future__ import annotations

import hashlib
import threading
import unittest
from collections import deque
from collections.abc import Callable
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import utility_ex_chassis as chassis
from tests.private_evidence import require_private

SYNTHETIC = b"authored chassis test identity, not an executable"
SYNTHETIC_SHA = hashlib.sha256(SYNTHETIC).hexdigest()


class FakeComm:
    def __init__(self, replies: list[tuple[int, bytes]]):
        self.replies = deque(replies)
        self.events: list[tuple[object, ...]] = []
        self.init_status = 0
        self.target: tuple[int, int] = (0, 0)
        self.protocol = 6
        self.support_cache: dict[
            tuple[int, int, int, int], tuple[bytes, tuple[int, ...]]
        ] = {}
        self.sessions: deque[int] = deque()
        self.snapshots: deque[tuple[int, bytes, tuple[int, ...]]] = deque()
        self.append_status = 99
        self.appended: list[tuple[bytes, int]] = []
        self.fault: Exception | None = None

    def keepalive(self, enabled: bool, wait: bool = False) -> int:
        self.events.append(("keepalive", enabled, wait))
        return 0

    def initialize(self, mode: int = 0) -> int:
        self.events.append(("initialize", mode))
        return self.init_status

    def cancellation_counters(self) -> dict[str, int]:
        return {
            "native_rva:" + key: 0
            for key in ("17340", "17350", "17360", "17370", "17380")
        }

    def read_target(self) -> tuple[int, int]:
        return self.target

    def select_target(self, identifier: int, second: int = 0) -> None:
        self.target = identifier, second
        self.events.append(("select_target", identifier, second))

    def configure_target(
        self,
        first: int,
        second: int = 0,
        third: int = 0,
        fourth: int = 0,
        fifth: int = 0,
    ) -> None:
        self.events.append(("configure_target", first, second, third, fourth, fifth))

    def configure_parameters(self, parameters: tuple[tuple[int, int], ...]) -> None:
        self.events.append(("configure_parameters", parameters))

    def select_protocol(self, kind: int) -> int:
        self.events.append(("select_protocol", kind))
        return 0

    def select_diagnostic_mode(self, mode: int) -> int:
        self.events.append(("select_diagnostic_mode", mode))
        return 0

    def selected_protocol(self) -> int:
        return self.protocol

    def refresh_support_cache(self, kind: int) -> int:
        status, raw, offsets = self.support_snapshot(kind)
        if status == 0:
            self.support_cache[(*self.target, self.protocol, kind)] = raw, offsets
        return status

    def append_support_profile(self, raw: bytes, kind: int) -> int:
        self.appended.append((raw, kind))
        self.events.append(("append_support_profile", raw, kind))
        if self.append_status == 81:
            return 81
        offsets = [0x1020] * 256
        offset = 0
        backing = raw.ljust(0x1021, b"\0")
        while offset < len(raw):
            offsets[backing[offset]] = offset
            offset += 2 + backing[offset + 1]
        self.support_cache.setdefault(
            (*self.target, self.protocol, kind),
            (raw.ljust(0x1020, b"\0"), tuple(offsets)),
        )
        return 99

    def cached_support(self, kind: int) -> tuple[bytes, tuple[int, ...]] | None:
        return self.support_cache.get((*self.target, self.protocol, kind))

    def support_snapshot(self, kind: int) -> tuple[int, bytes, tuple[int, ...]]:
        self.events.append(("support_snapshot", kind))
        return self.snapshots.popleft()

    def session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int:
        self.events.append(("session", mode, keepalive, normal_first, stop_on_error))
        return self.sessions.popleft() if self.sessions else 0

    def cleanup_session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int:
        self.events.append(
            ("cleanup_session", mode, keepalive, normal_first, stop_on_error)
        )
        return self.sessions.popleft() if self.sessions else 0

    def finalize(self) -> None:
        self.events.append(("finalize",))

    def configure(self, field: str, value: int) -> None:
        self.events.append(("configure", field, value))

    def exchange(self, request: bytes) -> tuple[int, bytes]:
        self.events.append(("exchange", request))
        if self.fault:
            raise self.fault
        return self.replies.popleft()


class FakeContext:
    mode = 3
    module_sha256 = SYNTHETIC_SHA
    module_bytes = SYNTHETIC

    def __init__(self, replies: list[tuple[int, bytes]]):
        self.driver = FakeComm(replies)
        self.state: dict[str, object] = {}
        self.cancelled = False
        self.clock = 1000
        self.sleeps: list[int] = []
        self.cancel_after_sleep = 0
        self.sleep_fault: Exception | None = None
        self.kinds: list[str] = []
        self.parameters: dict[int, int] = {}
        self.parameter_events: list[tuple[object, ...]] = []

    def native_parameter(self, key: int) -> int:
        return self.parameters.get(key, 0)

    def set_parameter(self, key: int, value: int) -> int:
        self.parameters[key] = value
        self.parameter_events.append(("set", key, value))
        return 0

    def write_parameters(self) -> int:
        self.parameter_events.append(("write",))
        return 0

    def refresh_parameters(self) -> None:
        self.parameter_events.append(("refresh",))

    def broker(self, key: int) -> int:
        return 0

    def is_cancelled(self) -> bool:
        return self.cancelled

    def sleep(self, ms: int) -> None:
        self.sleeps.append(ms)
        if self.sleep_fault:
            raise self.sleep_fault
        self.clock = (self.clock + ms) & 0xFFFFFFFF
        if self.cancel_after_sleep and len(self.sleeps) >= self.cancel_after_sleep:
            self.cancelled = True

    def ticks(self) -> int:
        return self.clock

    def comm(self, kind: str) -> FakeComm:
        self.kinds.append(kind)
        return self.driver


class ChassisTests(unittest.TestCase):
    def _smrt55_context(
        self, name: str, replies: list[tuple[int, bytes]]
    ) -> tuple[FakeContext, str, tuple[str, str, str, str]]:
        digest_name = {
            "NK18_SHA256": (
                "native:1014f5e0",
                "native_global:1014a5b0",
                "native_global:1014a694",
                "native_global:1014a695",
            ),
            "NK_DS4_SHA256": (
                "native:101b6758",
                "native_global:101b19ac",
                "native_global:101b19b0",
                "native_global:101b19b1",
            ),
            "NK_GTS_SHA256": (
                "native:101c18a0",
                "native_global:101bcaac",
                "native_global:101bcab0",
                "native_global:101bcab1",
            ),
        }[name]
        blob = ("smrt55 " + name).encode()
        digest = hashlib.sha256(blob).hexdigest()
        context = FakeContext(replies)
        context.mode = 20
        context.module_bytes = blob
        context.module_sha256 = digest
        return context, digest, digest_name

    def test_smrt55_exact_cohort_identity_arity_and_nk12_absence(self) -> None:
        operations = (
            "ConfirmDIDRIDSupport",
            "GetKeyDiagInfo",
            "CHKSupportStatus",
            "SetKeyDiag",
            "SetKeyDiag2",
            "TermKeyDiag",
            "TermKeyDiag2",
        )
        self.assertEqual(
            {
                name
                for name in chassis.supported_exports(chassis.NK18_SHA256)
                if name.startswith("Ex2SMRT_55_")
            },
            {"Ex2SMRT_55_" + name for name in operations},
        )
        self.assertFalse(
            any(
                name.startswith("Ex2SMRT_55_")
                for name in chassis.supported_exports(chassis.NK12_SHA256)
            )
        )
        for digest_name in ("NK18_SHA256", "NK_DS4_SHA256", "NK_GTS_SHA256"):
            _context, digest, identity = self._smrt55_context(digest_name, [])
            with (
                patch.object(chassis, digest_name, digest),
                patch.dict(chassis._SMRT55_SOURCE, {digest: identity}),
            ):
                self.assertEqual(
                    {
                        name
                        for name in chassis.supported_exports(digest)
                        if name.startswith("Ex2SMRT_55_")
                    },
                    {"Ex2SMRT_55_" + name for name in operations},
                )

    def test_smrt55_confirm_reads_pointer_after_first_probe_and_captures_it(
        self,
    ) -> None:
        context, digest, identity = self._smrt55_context("NK18_SHA256", [])
        _, pointer, _, _ = identity
        first, captured, later = bytearray(b"old!"), bytearray(4), bytearray(4)
        context.state[pointer] = first
        replies = {
            b"\x22\x01\x01": (0, b"\0\x01\x01\0\0\0\0\x80"),
            b"\x22\x20\0": (0, b"\0\x20\0\0\0\0\0\x03"),
            b"\x31\x01\x10\x01": (0, b"\0\x01\x10\x01\0\0\x04"),
            b"\x31\x01\x15\0": (0, b"\0\x01\x15\0\x80"),
        }

        def exchange(request: bytes) -> tuple[int, bytes]:
            context.driver.events.append(("exchange", request))
            if request == b"\x22\x01\x01":
                context.state[pointer] = captured
            elif request == b"\x22\x20\0":
                context.state[pointer] = later
            return replies[request]

        context.driver.exchange = exchange
        with (
            patch.object(chassis, "NK18_SHA256", digest),
            patch.dict(chassis._SMRT55_SOURCE, {digest: identity}),
        ):
            self.assertEqual(
                chassis.run_body("Ex2SMRT_55_ConfirmDIDRIDSupport", (first,), context),
                0,
            )
        self.assertEqual(first, bytearray(b"old!"))
        self.assertEqual(int.from_bytes(captured, "little"), 1)
        self.assertEqual(later, bytearray(4))
        self.assertEqual(
            context.driver.events[-2:],
            [("cleanup_session", 1, 1, False, True), ("finalize",)],
        )

    def test_smrt55_get_flags_partial_write_survives_normal_error(self) -> None:
        context, digest, identity = self._smrt55_context(
            "NK18_SHA256", [(0, b"\0\x20\x27\xaa\xcc\x55\xdd")]
        )
        context.driver.sessions.extend((0, 7))
        _, _, key_a, key_b = identity
        with (
            patch.object(chassis, "NK18_SHA256", digest),
            patch.dict(chassis._SMRT55_SOURCE, {digest: identity}),
        ):
            self.assertEqual(
                chassis.run_body("Ex2SMRT_55_GetKeyDiagInfo", (), context), 199
            )
        self.assertEqual((context.state[key_a], context.state[key_b]), (0xAA, 0x55))
        self.assertEqual(
            [
                event
                for event in context.driver.events
                if event[0] in ("session", "cleanup_session")
            ],
            [
                ("session", 3, 1, True, False),
                ("cleanup_session", 1, 1, False, True),
            ],
        )
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_smrt55_set2_hidden_byte_wait_order_and_term_retention(self) -> None:
        context, digest, identity = self._smrt55_context(
            "NK18_SHA256",
            [
                (0, b"\0\x20\x27"),
                (0, b"\0\x20\x28"),
                (0, b"\0\x01\x15\x01"),
                (0, b"\0\x02\x15\x01"),
            ],
        )
        _, _, key_a, key_b = identity
        context.state[key_a], context.state[key_b] = 0xA1, 0xB2
        with (
            patch.object(chassis, "NK18_SHA256", digest),
            patch.dict(chassis._SMRT55_SOURCE, {digest: identity}),
        ):
            self.assertEqual(
                chassis.run_body("Ex2SMRT_55_SetKeyDiag2", (0x1FF, 0x102, 0), context),
                0,
            )
            self.assertNotIn(("finalize",), context.driver.events)
            self.assertEqual(chassis.run_body("Ex2SMRT_55_TermKeyDiag", (), context), 0)
        requests = [
            event[1] for event in context.driver.events if event[0] == "exchange"
        ]
        self.assertEqual(
            requests,
            [
                b"\x2e\x20\x27\xa1\xff\xb2\0",
                b"\x2e\x20\x28\x02",
                b"\x31\x01\x15\x01",
                b"\x31\x02\x15\x01",
            ],
        )
        self.assertEqual(context.sleeps, [100, 100, 100])
        self.assertEqual(
            sum(event[0] == "finalize" for event in context.driver.events), 1
        )

    def test_smrt55_cancelled_term_uses_cleanup_normal_session(self) -> None:
        context, digest, identity = self._smrt55_context(
            "NK18_SHA256",
            [
                (0, b"\0\x20\x27"),
                (0, b"\0\x01\x15\x01"),
            ],
        )
        _, _, key_a, key_b = identity
        context.state[key_a], context.state[key_b] = 0xA1, 0xB2
        with (
            patch.object(chassis, "NK18_SHA256", digest),
            patch.dict(chassis._SMRT55_SOURCE, {digest: identity}),
        ):
            self.assertEqual(
                chassis.run_body("Ex2SMRT_55_SetKeyDiag", (0x5A, 0), context), 0
            )
            context.cancelled = True
            self.assertEqual(
                chassis.run_body("Ex2SMRT_55_TermKeyDiag", (), context), 199
            )
        self.assertIn(("cleanup_session", 1, 1, False, True), context.driver.events)
        self.assertIn(("configure", "native_rva:18840", 1), context.driver.events)
        self.assertIn(("configure", "native_rva:18840", 0), context.driver.events)
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_smrt55_setters_capture_b_then_a_across_variants(self) -> None:
        class InterleavedState(dict[str, object]):
            def __init__(self, key_a: str, key_b: str) -> None:
                super().__init__({key_a: 0xA1, key_b: 0xB2})
                self.key_a = key_a
                self.key_b = key_b
                self.reads: list[str] = []

            def get(self, key: str, default: object = None) -> object:
                self.reads.append(key)
                value = super().get(key, default)
                if key == self.key_b and len(self.reads) == 1:
                    self[self.key_a] = 0xC3
                    self[self.key_b] = 0xD4
                return value

        for source in ("NK18_SHA256", "NK_DS4_SHA256", "NK_GTS_SHA256"):
            for export, arguments, expected in (
                ("Ex2SMRT_55_SetKeyDiag", (0x5A, 0), b"\x2e\x20\x27\xc3\x5a\xb2\0"),
                (
                    "Ex2SMRT_55_SetKeyDiag2",
                    (0x5A, 0x77, 0),
                    b"\x2e\x20\x27\xc3\x5a\xb2\0",
                ),
            ):
                context, digest, identity = self._smrt55_context(
                    source,
                    (
                        [
                            (0, b"\0\x20\x27"),
                            (0, b"\0\x20\x28"),
                            (0, b"\0\x01\x15\x01"),
                        ]
                        if export.endswith("SetKeyDiag2")
                        else [(0, b"\0\x20\x27"), (0, b"\0\x01\x15\x01")]
                    ),
                )
                _, _, key_a, key_b = identity
                state = InterleavedState(key_a, key_b)
                context.state = state
                with (
                    patch.object(chassis, source, digest),
                    patch.dict(chassis._SMRT55_SOURCE, {digest: identity}),
                ):
                    self.assertEqual(chassis.run_body(export, arguments, context), 0)
                requests = [
                    event[1]
                    for event in context.driver.events
                    if event[0] == "exchange"
                ]
                self.assertEqual(requests[0], expected)
                self.assertEqual(state.reads[:2], [key_b, key_a])

    def test_smrt55_nk18_public_raw_sdk_retained_lifecycles(self) -> None:
        from scripts.j2534_2026 import NativeMessage, PrimitiveResult
        from scripts.utility_ex import UtilityExContext as SourceContext
        from scripts.utility_ex import UtilityExEngine
        from scripts.utility_ex_comm import SHA_18_NK

        path = Path(
            "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityExNK2.dll"
        )
        if not path.is_file():
            self.skipTest("Exact supplied NK18 static image unavailable")

        class Host:
            def __init__(self) -> None:
                self.tick = 0

            def get_parameter(self, key: int) -> int:
                return {
                    0x6F: 20,
                    0x70: 18,
                    0x74: 0x7E0,
                    0xD3: 0xFFFFFFFF,
                    0xDD: 0xFFFFFFFF,
                }.get(key, 0)

            def get_data_size(self, key: int) -> int:
                return 8 if key == 500 else 0

            def get_data(self, key: int) -> bytes:
                return (
                    (1).to_bytes(4, "little") + (500000).to_bytes(4, "little")
                    if key == 500
                    else b""
                )

            def set_parameter(self, key: int, value: int) -> int:
                return 0

            def write_parameters(self) -> int:
                return 0

            def ticks(self) -> int:
                return self.tick

            def sleep(self, milliseconds: int) -> None:
                self.tick = (self.tick + milliseconds) & 0xFFFFFFFF

        replies: deque[bytes] = deque()
        writes: list[bytes] = []
        cleanup: list[tuple[str, int]] = []
        filters = iter(range(51, 1000))

        def connect(protocol, flags, output):
            output[:] = (42).to_bytes(4, "little")
            return PrimitiveResult()

        def start_filter(channel, kind, mask, pattern, flow, output):
            output[:] = next(filters).to_bytes(4, "little")
            return PrimitiveResult()

        def response(request: bytes) -> bytes:
            if request == b"\x10\x03":
                return b"\x50\x03"
            if request == b"\x10\x01":
                return b"\x50\x01"
            if request == b"\x3e\0":
                return b"\x7e\0"
            if request == b"\x22\x01\x01":
                return b"\x62\x01\x01" + bytes(4) + b"\x80"
            if request == b"\x22\x20\0":
                return b"\x62\x20\0" + bytes(4) + b"\x03"
            if request == b"\x31\x01\x10\x01":
                return b"\x71\x01\x10\x01\0\0\x04"
            if request == b"\x31\x01\x15\0":
                return b"\x71\x01\x15\0\x80"
            if request == b"\x22\x20\x27":
                return b"\x62\x20\x27\xa1\0\xb2\0"
            if request[:3] == b"\x2e\x20\x27":
                return b"\x6e\x20\x27"
            if request[:3] == b"\x2e\x20\x28":
                return b"\x6e\x20\x28"
            if request == b"\x31\x01\x15\x01":
                return b"\x71\x01\x15\x01"
            if request == b"\x31\x02\x15\x01":
                return b"\x71\x02\x15\x01"
            raise AssertionError(f"Unexpected NK18 raw request: {request.hex()}")

        def write(channel, messages, count, timeout):
            request = messages[0].data[4:]
            writes.append(messages[0].data)
            replies.append(response(request))
            return PrimitiveResult()

        def read(channel, messages, count, timeout):
            messages[0] = NativeMessage(6, b"\0\0\x07\xe8" + replies.popleft())
            return PrimitiveResult()

        def stop_filter(channel, identifier):
            cleanup.append(("stop_filter", identifier))
            return PrimitiveResult()

        def disconnect(channel):
            cleanup.append(("disconnect", channel))
            return PrimitiveResult()

        names = (
            "PassThruConnect",
            "PassThruOemConnect",
            "PassThruDisconnect",
            "PassThruIoctl",
            "PassThruGetLastError",
            "PassThruWriteMsgs",
            "PassThruReadMsgs",
            "PassThruStartPeriodicMsg",
            "PassThruStopPeriodicMsg",
            "PassThruStartMsgFilter",
            "PassThruStopMsgFilter",
            "PassThruSetProgrammingVoltage",
            "PassThruReadVersion",
            "J2534CtrlInitialize",
            "J2534CtrlFinalize",
        )
        exports: dict[str, Callable[..., object]] = dict.fromkeys(
            names, lambda *arguments: PrimitiveResult()
        )
        exports.update(
            PassThruConnect=connect,
            PassThruStartMsgFilter=start_filter,
            PassThruWriteMsgs=write,
            PassThruReadMsgs=read,
            PassThruStopMsgFilter=stop_filter,
            PassThruDisconnect=disconnect,
        )
        context = SourceContext(
            path.read_bytes(), Host(), None, None, driver_exports=exports
        )
        engine = UtilityExEngine(context)
        source_identity = patch.object(chassis, "NK18_SHA256", SHA_18_NK)
        source_identity.start()
        self.addCleanup(source_identity.stop)
        try:
            output = bytearray(4)
            self.assertEqual(
                engine.invoke("Ex2SMRT_55_ConfirmDIDRIDSupport", (output,)), 15
            )
            self.assertEqual(engine.worker.get_status(), 0, writes)
            self.assertEqual(int.from_bytes(output, "little"), 1)

            self.assertEqual(engine.invoke("Ex2SMRT_55_GetKeyDiagInfo"), 0)
            self.assertEqual(
                (
                    context.state["native_global:1014a694"],
                    context.state["native_global:1014a695"],
                ),
                (0xA1, 0xB2),
            )
            self.assertEqual(engine.invoke("Ex2SMRT_55_CHKSupportStatus", (1, 0)), 0)

            disconnected = sum(item[0] == "disconnect" for item in cleanup)
            self.assertEqual(engine.invoke("Ex2SMRT_55_SetKeyDiag", (0x5A, 0)), 0)
            self.assertEqual(
                sum(item[0] == "disconnect" for item in cleanup), disconnected
            )
            self.assertEqual(engine.invoke("Ex2SMRT_55_TermKeyDiag"), 0)

            disconnected = sum(item[0] == "disconnect" for item in cleanup)
            self.assertEqual(
                engine.invoke("Ex2SMRT_55_SetKeyDiag2", (0x5B, 0x77, 0)), 0
            )
            self.assertEqual(
                sum(item[0] == "disconnect" for item in cleanup), disconnected
            )
            self.assertEqual(engine.invoke("Ex2SMRT_55_TermKeyDiag2"), 199)
            self.assertEqual(replies, deque())
            before_cancelled_term = len(writes)
            self.assertEqual(engine.invoke("Ex2SMRT_55_SetKeyDiag", (0x5C, 0)), 0)
            context._cancel.set()
            self.assertEqual(engine.invoke("Ex2SMRT_55_TermKeyDiag"), 199)
            self.assertEqual(
                [
                    message[4:]
                    for message in writes[before_cancelled_term:]
                    if message[4:] != b"\x3e\0"
                ],
                [
                    b"\x10\x01",
                    b"\x10\x03",
                    b"\x2e\x20\x27\xa1\x5c\xb2\0",
                    b"\x31\x01\x15\x01",
                    b"\x10\x01",
                ],
            )
            requests = [message[4:] for message in writes]
            for required in (
                b"\x22\x01\x01",
                b"\x22\x20\0",
                b"\x31\x01\x10\x01",
                b"\x31\x01\x15\0",
                b"\x22\x20\x27",
                b"\x2e\x20\x27\xa1\x5a\xb2\0",
                b"\x31\x02\x15\x01",
                b"\x2e\x20\x28\x77",
            ):
                self.assertIn(required, requests)
            self.assertEqual(
                requests[-3:],
                [
                    b"\x2e\x20\x27\xa1\x5c\xb2\0",
                    b"\x31\x01\x15\x01",
                    b"\x10\x01",
                ],
            )
        finally:
            context.comm("native:1014f5e0").finalize()

    def test_smrt55_chk_is_any_mode_and_does_not_create_comm(self) -> None:
        for mode in (3, 4, 20, 22, 0xDEADBEEF):
            context, digest, identity = self._smrt55_context("NK18_SHA256", [])
            context.mode = mode
            _, _, key_a, key_b = identity
            context.state[key_a], context.state[key_b] = 0x82, 0xF4
            with (
                patch.object(chassis, "NK18_SHA256", digest),
                patch.dict(chassis._SMRT55_SOURCE, {digest: identity}),
            ):
                self.assertEqual(
                    chassis.run_body(
                        "Ex2SMRT_55_CHKSupportStatus", (0x102, 0), context
                    ),
                    0,
                )
                self.assertEqual(
                    chassis.run_body("Ex2SMRT_55_CHKSupportStatus", (4, 2), context), 0
                )
                self.assertEqual(
                    chassis.run_body("Ex2SMRT_55_CHKSupportStatus", (1, 2), context), 99
                )
                self.assertEqual(
                    chassis.run_body("Ex2SMRT_55_CHKSupportStatus", (1, 1), context), 22
                )
                self.assertEqual(
                    chassis.run_body("Ex2SMRT_55_CHKSupportStatus", (1, 99), context),
                    22,
                )
            self.assertEqual(context.kinds, [])
            self.assertEqual(context.driver.events, [])

    def test_smrt55_exception_keeps_host_error_and_finalizes_once(self) -> None:
        context, digest, identity = self._smrt55_context("NK18_SHA256", [])
        context.driver.fault = RuntimeError("55 exchange host fault")
        with (
            patch.object(chassis, "NK18_SHA256", digest),
            patch.dict(chassis._SMRT55_SOURCE, {digest: identity}),
            self.assertRaisesRegex(RuntimeError, "55 exchange host fault"),
        ):
            chassis.run_body(
                "Ex2SMRT_55_ConfirmDIDRIDSupport", (bytearray(4),), context
            )
        self.assertEqual(
            sum(event[0] == "finalize" for event in context.driver.events), 1
        )

    def test_smrt63_support_optional6350_6351(self) -> None:
        for first, optional, expected in [
            (0x40, None, 6350),
            (0xC0, 0, 6350),
            (0xC0, 0x40, 6351),
        ]:
            replies = [
                (0, b"b\1\1\0\0" + bytes([first])),
                (0, b"b\x11\0\x80"),
                (0, b"q\1\x10\1\0\0\2"),
                (0, b"q\1\x16\0\x20"),
            ]
            if optional is not None:
                replies.append((0, b"b\x10\0\0\0" + bytes([optional])))
            c = FakeContext(replies)
            c.mode = 20
            out = bytearray(4)
            self.assertEqual(
                chassis.run_body("Ex2SMRT_63_GetSupportInfo", (out,), c), 0
            )
            self.assertEqual(int.from_bytes(out, "little"), expected)
            self.assertFalse(c.driver.replies)

    def test_smrt63_distinct_terminal_status_table_and_counter_not_written(
        self,
    ) -> None:
        for fields, expected in [
            ({9: 1}, 6301),
            ({13: 1, 22: 1}, 6302),
            ({14: 1}, 6303),
            ({13: 1}, 6305),
            ({}, 6305),
            ({22: 1}, 6306),
        ]:
            reply = bytearray(b"b\x11\1" + bytes(21))
            for index, value in fields.items():
                reply[index] = value
            c = FakeContext([(0, bytes(reply))])
            c.mode = 20
            counter = bytearray((1000).to_bytes(4, "little"))
            self.assertEqual(
                chassis.run_body("Ex2SMRT_63_GetKeyStatus", (counter,), c), expected
            )
            self.assertEqual(counter, (1000).to_bytes(4, "little"))
            self.assertEqual(
                [e[1] for e in c.driver.events if e[0] == "exchange"], [b"\x22\x11\1"]
            )

    def test_smrt63_counter960_only_after_pending_and_cancellation_retains0(
        self,
    ) -> None:
        pending = b"b\x11\1\0\0\1" + bytes(18)
        c = FakeContext([(0, pending), (0, b"")])
        c.mode = 20
        self.assertEqual(
            chassis.run_body(
                "Ex2SMRT_63_GetKeyStatus", (bytearray((960).to_bytes(4, "little")),), c
            ),
            6304,
        )
        self.assertEqual(
            [e[1] for e in c.driver.events if e[0] == "exchange"],
            [b"\x22\x11\1", b"\x31\2\x16\3"],
        )
        c = FakeContext([(0, pending)])
        c.mode = 20
        c.cancel_after_sleep = 1
        self.assertEqual(
            chassis.run_body(
                "Ex2SMRT_63_GetKeyStatus", (bytearray((959).to_bytes(4, "little")),), c
            ),
            0,
        )
        self.assertFalse(any(e[0] == "finalize" for e in c.driver.events))

    def test_smrt63_counter_read_after_wire_and_cancel_can_override_terminal(
        self,
    ) -> None:
        for pending in (True, False):
            reply = bytearray(b"b\x11\1" + bytes(21))
            reply[5 if pending else 9] = 1
            c = FakeContext([(0, bytes(reply)), (0, b"")])
            c.mode = 20
            counter = bytearray(4)
            exchange = c.driver.exchange

            def update_counter(
                request: bytes,
                exchange: Callable[[bytes], tuple[int, bytes]] = exchange,
                counter: bytearray = counter,
                pending: bool = pending,
                c: FakeContext = c,
            ) -> tuple[int, bytes]:
                result = exchange(request)
                if request == b"\x22\x11\1":
                    counter[:] = (960).to_bytes(4, "little")
                    if not pending:
                        c.cancelled = True
                return result

            c.driver.exchange = update_counter
            self.assertEqual(
                chassis.run_body("Ex2SMRT_63_GetKeyStatus", (counter,), c), 6304
            )
            self.assertEqual(counter, (960).to_bytes(4, "little"))

    def test_smrt63_precancel_single_stop_and_fault_closes(self) -> None:
        c = FakeContext([(0, b"")])
        c.mode = 20
        c.cancelled = True
        self.assertEqual(
            chassis.run_body("Ex2SMRT_63_GetKeyStatus", (bytearray(4),), c), 99
        )
        self.assertEqual(
            [e[1] for e in c.driver.events if e[0] == "exchange"], [b"\x31\2\x16\3"]
        )
        self.assertEqual(sum(e[0] == "finalize" for e in c.driver.events), 1)
        c = FakeContext([])
        c.mode = 20
        c.driver.fault = RuntimeError("63 poll fault")
        with self.assertRaisesRegex(RuntimeError, "63 poll fault"):
            chassis.run_body("Ex2SMRT_63_GetKeyStatus", (bytearray(4),), c)
        self.assertEqual(c.driver.events[-1], ("finalize",))

    def test_smrt50_three_exact_source_managers_short_setters_and_absence12(
        self,
    ) -> None:
        self.assertNotIn(
            "Ex2SMRT_50_GetSupportInfo", chassis.supported_exports(chassis.NK12_SHA256)
        )
        for constant, scope, short in [
            ("NK18_SHA256", "native:1014f5e0", "18840"),
            ("NK_DS4_SHA256", "native:101b6758", "32b90"),
            ("NK_GTS_SHA256", "native:101c18a0", "33aa0"),
        ]:
            blob = ("source50" + constant).encode()
            digest = hashlib.sha256(blob).hexdigest()
            with patch.object(chassis, constant, digest):
                c = FakeContext([])
                c.mode = 20
                c.module_bytes = blob
                c.module_sha256 = digest
                self.assertEqual(
                    chassis.run_body("Ex2SMRT_50_EndExtendSession", (), c), 0
                )
                self.assertEqual(c.kinds, [scope])
                self.assertEqual(
                    c.driver.events,
                    [
                        ("configure", "native_rva:" + short, 1),
                        ("session", 1, 1, False, False),
                        ("configure", "native_rva:" + short, 0),
                        ("finalize",),
                    ],
                )

    def test_smrt50_support_optional5050_5051_and_no_optional_probe(self) -> None:
        for first, optional, expected in [
            (0x40, None, 5050),
            (0xC0, 0, 5050),
            (0xC0, 0x40, 5051),
        ]:
            replies = [
                (0, b"b\x01\x01\0\0" + bytes([first])),
                (0, b"b\x11\0\x80"),
                (0, b"q\1\x10\1\0\0\2"),
                (0, b"q\1\x16\0\x20"),
            ]
            if optional is not None:
                replies.append((0, b"b\x10\0\0\0" + bytes([optional])))
            c = FakeContext(replies)
            c.mode = 20
            out = bytearray(4)
            self.assertEqual(
                chassis.run_body("Ex2SMRT_50_GetSupportInfo", (out,), c), 0
            )
            self.assertEqual(int.from_bytes(out, "little"), expected)
            self.assertEqual(
                c.driver.events[-2:], [("session", 1, 1, False, True), ("finalize",)]
            )
            self.assertFalse(c.driver.replies)

    def test_smrt50_support5099_short_cleanup_and_session5098(self) -> None:
        c = FakeContext([(0, b"b\x01\x01\0\0\x80")])
        c.mode = 20
        out = bytearray(b"xxxx")
        self.assertEqual(chassis.run_body("Ex2SMRT_50_GetSupportInfo", (out,), c), 5099)
        self.assertEqual(out, b"xxxx")
        self.assertEqual(
            c.driver.events[-4:],
            [
                ("configure", "native_rva:18840", 1),
                ("session", 1, 1, False, False),
                ("configure", "native_rva:18840", 0),
                ("finalize",),
            ],
        )
        c = FakeContext([])
        c.mode = 20
        c.driver.sessions.append(7)
        self.assertEqual(chassis.run_body("Ex2SMRT_50_GetSupportInfo", (out,), c), 5098)
        self.assertEqual(c.driver.events[-1], ("finalize",))

    def test_smrt50_key_status_table_and_cleanup_omits_stop_for_native_states(
        self,
    ) -> None:
        for fields, expected in [
            ({9: 1}, 5001),
            ({13: 1, 22: 1}, 5002),
            ({14: 1}, 5003),
            ({}, 5005),
            ({22: 1}, 5002),
            ({13: 1, 14: 1}, 5005),
        ]:
            reply = bytearray(b"b\x11\1" + bytes(21))
            for index, value in fields.items():
                reply[index] = value
            c = FakeContext([(0, bytes(reply))])
            c.mode = 20
            self.assertEqual(
                chassis.run_body("Ex2SMRT_50_KeyCodeReset", (), c), expected
            )
            self.assertEqual(
                [e[1] for e in c.driver.events if e[0] == "exchange"], [b"\x22\x11\1"]
            )
            self.assertEqual(c.driver.events[-1], ("finalize",))

    def test_smrt50_precancel_preserves_duplicate_native_stop_cleanup(self) -> None:
        c = FakeContext([(0, b""), (0, b"")])
        c.mode = 20
        c.cancelled = True
        self.assertEqual(chassis.run_body("Ex2SMRT_50_KeyCodeReset", (), c), 99)
        self.assertEqual(
            [e[1] for e in c.driver.events if e[0] == "exchange"], [b"\x31\2\x16\3"] * 2
        )
        self.assertEqual(sum(e[0] == "finalize" for e in c.driver.events), 2)
        c = FakeContext([(0, b"b\x11\1\0\0\1" + bytes(18)), (0, b"")])
        c.mode = 20
        c.cancel_after_sleep = 1
        self.assertEqual(chassis.run_body("Ex2SMRT_50_KeyCodeReset", (), c), 0)
        self.assertEqual(sum(e[0] == "finalize" for e in c.driver.events), 1)

    def test_smrt50_start_retains_end_direct_closes_and_wire_fault_closes(self) -> None:
        c = FakeContext([(0, b"q\1\x16\3")])
        c.mode = 20
        self.assertEqual(chassis.run_body("Ex2SMRT_50_StartKeyErasure", (), c), 0)
        self.assertFalse(
            any(e[0] in ("initialize", "finalize") for e in c.driver.events)
        )
        self.assertEqual(chassis.run_body("Ex2SMRT_50_StartKeepAlive", (), c), 0)
        self.assertEqual(
            c.driver.events[-2:], [("initialize", 0), ("keepalive", True, False)]
        )
        self.assertEqual(chassis.run_body("Ex2SMRT_50_EndExtendSession", (), c), 0)
        self.assertEqual(c.driver.events[-1], ("finalize",))
        c = FakeContext([])
        c.mode = 20
        c.driver.fault = RuntimeError("50 driver fault")
        with self.assertRaisesRegex(RuntimeError, "50 driver fault"):
            chassis.run_body("Ex2SMRT_50_StartKeyErasure", (), c)
        self.assertEqual(c.driver.events[-1], ("finalize",))

    @staticmethod
    def good53() -> list[tuple[int, bytes]]:
        first = bytearray(b"b\x01\x01" + bytes(31))
        first[5] = first[33] = 0x40
        third = bytearray(b"b\xf1\0" + bytes(18))
        third[20] = 0x10
        return [
            (0, bytes(first)),
            (0, b"b\x11\0\x40"),
            (0, bytes(third)),
            (0, b"b\x11\x02" + bytes(5) + b"\1"),
        ]

    def test_smrt53_online_retention_challenge_partial_outputs_and_send(self) -> None:
        c = FakeContext(
            self.good53()
            + [
                (0, b"b\xf1\x8c" + bytes(10) + b"12345678"),
                (0, b"g\x09ABCDEF"),
                (0, b"g\x0a"),
            ]
        )
        c.mode = 20
        status = bytearray(b"xxxx")
        challenge = bytearray(8)
        seed = bytearray(6)
        self.assertEqual(
            self.run_export(
                "Ex2SMRT_53_Online_Certification", c, status, 1, challenge, seed, 0
            ),
            0,
        )
        self.assertEqual((challenge, seed), (b"12345678", b"ABCDEF"))
        self.assertEqual(status, b"xxxx")
        self.assertFalse(any(e[0] == "finalize" for e in c.driver.events))
        self.assertEqual(
            self.run_export("Ex2SMRT_53_SendTheKey", c, b"keyTAIL", status, 3), 0
        )
        self.assertEqual(
            c.driver.events[-3:],
            [
                ("exchange", b"\x27\x0akey"),
                ("finalize",),
                ("configure_target", 0, 0, 0, 0, 0),
            ],
        )
        _, flag = chassis._fields53(c, "SendTheKey")
        self.assertEqual(c.state[f"native_global:{flag:08x}"], 1)

    def test_smrt53_online4006_retains_and_101_sets4003(self) -> None:
        c = FakeContext(self.good53())
        c.mode = 20
        status = bytearray(4)
        self.assertEqual(
            self.run_export(
                "Ex2SMRT_53_Online_Certification",
                c,
                status,
                0,
                None,
                None,
                0x1C2,
            ),
            4006,
        )
        self.assertFalse(
            any(e[0] in ("finalize", "configure_target") for e in c.driver.events)
        )
        replies = self.good53()
        replies[-1] = (0, b"b\x11\x02" + bytes(6))
        c = FakeContext(replies)
        c.mode = 20
        status = bytearray(4)
        self.assertEqual(
            self.run_export(
                "Ex2SMRT_53_Online_Certification",
                c,
                status,
                1,
                bytearray(8),
                bytearray(6),
                0,
            ),
            101,
        )
        self.assertEqual(int.from_bytes(status, "little"), 4003)
        self.assertEqual(
            c.driver.events[-2:], [("finalize",), ("configure_target", 0, 0, 0, 0, 0)]
        )

    def test_smrt53_support109_session_failure4005_and_init_no_output(self) -> None:
        for kind in ("support", "session", "init"):
            c = FakeContext([(0, b"b\x01\x01" + bytes(31))])
            c.mode = 20
            status = bytearray(b"xxxx")
            if kind == "session":
                c.driver.sessions.append(7)
            if kind == "init":
                c.driver.init_status = 14
            expected = {"support": 109, "session": 7, "init": 14}[kind]
            self.assertEqual(
                self.run_export(
                    "Ex2SMRT_53_Online_Certification",
                    c,
                    status,
                    1,
                    bytearray(8),
                    bytearray(6),
                    0,
                ),
                expected,
            )
            self.assertEqual(
                status,
                b"xxxx"
                if kind == "init"
                else (4005 if kind == "session" else 4001).to_bytes(4, "little"),
            )
            self.assertEqual(
                c.driver.events[-2:],
                [("finalize",), ("configure_target", 0, 0, 0, 0, 0)],
            )

    def test_smrt53_101_only_last_status_probe_sets4003(self) -> None:
        for replies in [[(101, b"")], self.good53() + [(101, b"")]]:
            c = FakeContext(replies)
            c.mode = 20
            status = bytearray(4)
            self.assertEqual(
                self.run_export(
                    "Ex2SMRT_53_Online_Certification",
                    c,
                    status,
                    1,
                    bytearray(8),
                    bytearray(6),
                    0x1C2,
                ),
                101,
            )
            self.assertEqual(status, (4001).to_bytes(4, "little"))

    def test_smrt53_followup_preserves_partial_challenge_on_seed_failure(self) -> None:
        c = FakeContext([(0, b"b\xf1\x8c" + bytes(10) + b"12345678"), (3, b"")])
        c.mode = 20
        status, challenge, seed = bytearray(4), bytearray(8), bytearray(b"xxxxxx")
        self.assertEqual(
            self.run_export(
                "Ex2SMRT_53_Online_Certification_007", c, status, challenge, seed
            ),
            3,
        )
        self.assertEqual(
            (status, challenge, seed),
            ((4001).to_bytes(4, "little"), b"12345678", b"xxxxxx"),
        )
        self.assertFalse(any(e[0] == "initialize" for e in c.driver.events))

    def test_smrt53_send4007_leaves_status_and_wire_fault_closes(self) -> None:
        for reply, expected in [(b"", 4007), (b"g\x0b", 4007), (b"g\x0aextra", 0)]:
            c = FakeContext([(0, reply)])
            c.mode = 20
            status = bytearray(b"xxxx")
            self.assertEqual(
                self.run_export("Ex2SMRT_53_SendTheKey", c, b"", status, 0), expected
            )
            self.assertEqual(status, b"xxxx")
            self.assertEqual(c.driver.events[-1], ("finalize",))
        c = FakeContext([])
        c.mode = 20
        c.driver.fault = RuntimeError("53 primitive fault")
        with self.assertRaisesRegex(RuntimeError, "53 primitive fault"):
            self.run_export(
                "Ex2SMRT_53_Online_Certification",
                c,
                bytearray(4),
                1,
                bytearray(8),
                bytearray(6),
                0,
            )
        self.assertEqual(
            c.driver.events[-2:], [("finalize",), ("configure_target", 0, 0, 0, 0, 0)]
        )

    def test_smrt56_all_support_predicates_and_ordered_cleanup(self) -> None:
        good = [
            b"b\x01\x01\0\0\x80",
            b"b\x10\0\0\0\x40",
            b"q\x01\x10\x01\0\0\1",
            b"q\x01\x17\0\x80",
        ]
        for failure in range(-1, 4):
            replies = list(good)
            if failure >= 0:
                replies[failure] = replies[failure][:-1] + b"\0"
            c = FakeContext([(0, reply) for reply in replies])
            c.mode = 20
            self.assertEqual(
                chassis.run_body("Ex2SMRT_56_ConfirmDIDRIDSupport", (), c),
                0 if failure < 0 else 6001 + failure,
            )
            self.assertEqual(
                [e[1] for e in c.driver.events if e[0] == "exchange"],
                [
                    row[0]
                    for row in chassis._SUPPORT56[: 4 if failure < 0 else failure + 1]
                ],
            )
            self.assertEqual(
                c.driver.events[-2:], [("session", 1, 1, False, True), ("finalize",)]
            )

    def test_smrt56_support_session_error6000_has_no_second_cleanup(self) -> None:
        c = FakeContext([])
        c.mode = 20
        c.driver.sessions.append(7)
        self.assertEqual(
            chassis.run_body("Ex2SMRT_56_ConfirmDIDRIDSupport", (), c), 6000
        )
        self.assertEqual(
            c.driver.events,
            [("initialize", 0), ("session", 3, 1, True, False), ("finalize",)],
        )
        c = FakeContext([])
        c.mode = 20
        c.cancelled = True
        self.assertEqual(chassis.run_body("Ex2SMRT_56_ConfirmDIDRIDSupport", (), c), 99)
        self.assertEqual(
            c.driver.events, [("session", 1, 1, False, True), ("finalize",)]
        )

    def test_smrt56_start_retains_success_and_closes_bad_echo(self) -> None:
        for reply, status in [
            (b"q\x01\x17\1", 0),
            (b"q\x01\x17\2", 3),
            (b"q\x01\x17", 3),
        ]:
            c = FakeContext([(0, reply)])
            c.mode = 20
            self.assertEqual(
                chassis.run_body("Ex2SMRT_56_StartFingerprintMode", (), c), status
            )
            self.assertIn(("keepalive", True, False), c.driver.events)
            self.assertEqual(
                any(e[0] == "finalize" for e in c.driver.events), status != 0
            )
        c = FakeContext([])
        c.mode = 20
        c.driver.fault = RuntimeError("fingerprint wire")
        with self.assertRaisesRegex(RuntimeError, "fingerprint wire"):
            chassis.run_body("Ex2SMRT_56_StartFingerprintMode", (), c)
        self.assertEqual(c.driver.events[-1], ("finalize",))

    def test_smrt56_termination_always6005_without_initialize(self) -> None:
        for cancelled in (False, True):
            c = FakeContext([(7, b"")])
            c.mode = 20
            c.cancelled = cancelled
            self.assertEqual(
                chassis.run_body("Ex2SMRT_56_TerminateFingerprintMode", (), c), 6005
            )
            self.assertFalse(any(e[0] == "initialize" for e in c.driver.events))
            self.assertEqual(
                [e[1] for e in c.driver.events if e[0] == "exchange"],
                [] if cancelled else [b"\x31\x02\x17\1"],
            )
            self.assertEqual(
                c.driver.events[-2:], [("session", 1, 1, False, True), ("finalize",)]
            )

    def test_smrt56_end_argument1_only_initializes_and_cancel_returns0(self) -> None:
        for marker in (0, 1, 2):
            c = FakeContext([])
            c.mode = 20
            c.driver.sessions.append(7)
            self.assertEqual(
                chassis.run_body("Ex2SMRT_56_EndExtendedSession", (marker,), c), 0
            )
            self.assertEqual(
                any(e[0] == "initialize" for e in c.driver.events), marker == 1
            )
        c = FakeContext([])
        c.mode = 20
        c.cancelled = True
        self.assertEqual(chassis.run_body("Ex2SMRT_56_EndExtendedSession", (1,), c), 0)
        self.assertEqual(c.driver.events, [("finalize",)])

    def test_smrt58_cancel_between_polls_retains_pending_and_no_stop(self) -> None:
        c = FakeContext([(0, b"q\x01\x13\x05"), (0, b"q\x03\x13\x05\1")])
        c.mode = 20
        exchange = c.driver.exchange

        def cancel_after_pending(request: bytes) -> tuple[int, bytes]:
            reply = exchange(request)
            if request[1] == 3:
                c.cancelled = True
            return reply

        c.driver.exchange = cancel_after_pending
        self.assertEqual(chassis.run_body("Ex2SMRT_58_StartIFBOXComIDReg", (), c), 5802)
        self.assertEqual(
            [e[1] for e in c.driver.events if e[0] == "exchange"],
            [b"\x31\x01\x13\x05", b"\x31\x03\x13\x05"],
        )
        c = FakeContext([])
        c.mode = 20
        c.cancelled = True
        self.assertEqual(chassis.run_body("Ex2SMRT_58_EndExtendedSession", (), c), 99)
        self.assertEqual(c.driver.events, [("finalize",)])

    def test_smrt58_three_source_manager_identity_and_nk12_absence(self) -> None:
        self.assertNotIn(
            "Ex2SMRT_58_StartIFBOXComIDReg",
            chassis.supported_exports(chassis.NK12_SHA256),
        )
        for constant, scope in [
            ("NK18_SHA256", "native:1014f5e0"),
            ("NK_DS4_SHA256", "native:101b6758"),
            ("NK_GTS_SHA256", "native:101c18a0"),
        ]:
            blob = ("source58" + constant).encode()
            digest = hashlib.sha256(blob).hexdigest()
            with patch.object(chassis, constant, digest):
                c = FakeContext([(0, b"q\x01\x13\x05"), (0, b"q\x03\x13\x05\2")])
                c.mode = 20
                c.module_bytes = blob
                c.module_sha256 = digest
                self.assertEqual(
                    chassis.run_body("Ex2SMRT_58_StartIFBOXComIDReg", (), c), 0
                )
                self.assertEqual(c.kinds, [scope])
                c = FakeContext([])
                c.mode = 20
                c.module_bytes = blob
                c.module_sha256 = digest
                c.driver.init_status = 13
                self.assertEqual(
                    chassis.run_body("Ex2SMRT_58_EndExtendedSession", (), c), 13
                )
                self.assertEqual(c.driver.events, [("initialize", 0), ("finalize",)])

    def test_smrt58_complete_pending_bad_echo_and_failure_cleanup(self) -> None:
        for replies, expected, requests in [
            (
                [
                    (0, b"q\x01\x13\x05"),
                    (0, b"q\x03\x13\x05\0"),
                    (0, b"q\x03\x13\x05\x02"),
                ],
                0,
                [1, 3, 3],
            ),
            (
                [(0, b"q\x01\x13\x05"), (0, b"q\x03\x13\x05\x03"), (7, b"")],
                5801,
                [1, 3, 2],
            ),
            ([(0, b"bad")], 5800, [1]),
            ([(0, b"q\x01\x13\x05"), (7, b""), (0, b"")], 5801, [1, 3, 2]),
        ]:
            c = FakeContext(replies)
            c.mode = 20
            self.assertEqual(
                chassis.run_body("Ex2SMRT_58_StartIFBOXComIDReg", (), c), expected
            )
            self.assertEqual(
                [e[1] for e in c.driver.events if e[0] == "exchange"],
                [bytes((0x31, sub, 0x13, 5)) for sub in requests],
            )
            self.assertEqual(
                c.driver.events[-2:], [("session", 1, 1, False, False), ("finalize",)]
            )
            self.assertIn(("keepalive", True, False), c.driver.events)

    def test_smrt58_unsigned_timeout_and_cancel_during_wait(self) -> None:
        c = FakeContext([(0, b"q\x01\x13\x05"), (0, b"q\x03\x13\x05\1"), (0, b"")])
        c.mode = 20
        c.clock = 0xFFFFFF00
        self.advance_clock_on_exchange(c, 30000)
        self.assertEqual(chassis.run_body("Ex2SMRT_58_StartIFBOXComIDReg", (), c), 5801)
        self.assertEqual(
            [e[1] for e in c.driver.events if e[0] == "exchange"][-1],
            b"\x31\x02\x13\x05",
        )
        c = FakeContext([(0, b"q\x01\x13\x05")])
        c.mode = 20
        c.cancel_after_sleep = 1
        self.assertEqual(chassis.run_body("Ex2SMRT_58_StartIFBOXComIDReg", (), c), 5801)
        self.assertEqual(
            [e[1] for e in c.driver.events if e[0] == "exchange"], [b"\x31\x01\x13\x05"]
        )

    def test_smrt58_end_session_ignores_native_session_error_and_fault_closes(
        self,
    ) -> None:
        c = FakeContext([])
        c.mode = 20
        c.driver.sessions.append(7)
        self.assertEqual(chassis.run_body("Ex2SMRT_58_EndExtendedSession", (), c), 0)
        c = FakeContext([])
        c.mode = 20
        c.driver.fault = RuntimeError("request fault")
        with self.assertRaisesRegex(RuntimeError, "request fault"):
            chassis.run_body("Ex2SMRT_58_StartIFBOXComIDReg", (), c)
        self.assertEqual(c.driver.events[-1], ("finalize",))

    def test_smrt48_support_all_sixteen_masks_and_refresh_failure(self) -> None:
        for masks, status in [
            (b"\xff" * 16, 0),
            (b"\xff" * 15 + b"\xfe", 4800),
            (b"\xff" * 15, 4800),
        ]:
            c = FakeContext([])
            c.mode = 4
            raw = b"\xcc" + bytes([len(masks)]) + masks
            offsets = [0x1020] * 256
            offsets[0xCC] = 0
            c.driver.snapshots.append((0, raw.ljust(0x1020, b"\0"), tuple(offsets)))
            self.assertEqual(
                chassis.run_body("Ex2SMRT_48_GetSupportInfo", (), c), status
            )
            self.assertEqual(
                c.driver.events[-2:],
                [("configure", "native_rva:172d0", 100), ("finalize",)],
            )
        c = FakeContext([])
        c.mode = 4
        c.driver.snapshots.append((7, b"", ()))
        self.assertEqual(chassis.run_body("Ex2SMRT_48_GetSupportInfo", (), c), 7)

    def test_smrt48_native_init_and_diagnostic_mode_failures(self) -> None:
        for mode in (4, 20):
            c = FakeContext([])
            c.driver.init_status = 7
            self.assertEqual(
                chassis.run_body("Ex2SMRT_48_ReadVINCode", (mode, bytearray(17)), c), 14
            )
        c = FakeContext([(0, b"~\0")])
        c.driver.select_diagnostic_mode = Mock(return_value=13)
        self.assertEqual(
            chassis.run_body("Ex2SMRT_48_ReadVINCode", (20, bytearray(17)), c), 4805
        )
        self.assertEqual(
            c.driver.select_diagnostic_mode.call_args_list, [((3,),), ((1,),)]
        )

    def test_smrt48_all_later_sources_exact_selected_override_setters(self) -> None:
        self.assertNotIn(
            "Ex2SMRT_48_ReadVINCode", chassis.supported_exports(chassis.NK12_SHA256)
        )
        for constant, override, setter in [
            ("NK18_SHA256", 0x1014AE60, "170a0"),
            ("NK_DS4_SHA256", 0x101B66D8, "323d0"),
            ("NK_GTS_SHA256", 0x101C1818, "332e0"),
        ]:
            blob = ("authored48" + constant).encode()
            digest = hashlib.sha256(blob).hexdigest()
            with patch.object(chassis, constant, digest):
                c = FakeContext([(0, b"~"), (0, b"I\x02\x01V")])
                c.module_bytes = blob
                c.module_sha256 = digest
                self.assertEqual(
                    chassis.run_body("Ex2SMRT_48_ReadVINCode", (4, bytearray(17)), c),
                    4802,
                )
                self.assertIn(
                    ("configure", "native_rva:" + setter, override), c.driver.events
                )

    def test_smrt48_vin_argument_mode_and_classic_partial_copy(self) -> None:
        c = FakeContext([(0, b"\x7e"), (0, b"\x49\x02\x01ABC")])
        c.mode = 99
        c.driver.target = (0x750, 7)
        out = bytearray(b"x" * 20)
        self.assertEqual(chassis.run_body("Ex2SMRT_48_ReadVINCode", (4, out), c), 4802)
        self.assertEqual(out, b"ABC" + b"x" * 17)
        self.assertEqual(c.driver.target, (0x750, 7))
        self.assertEqual(c.kinds, ["selected"])
        self.assertEqual(
            c.driver.events[-3:],
            [
                ("configure", "native_rva:170a0", 0),
                ("configure", "native_rva:170b0", 0),
                ("select_target", 0x750, 7),
            ],
        )

    def test_smrt48_classic_probe_fallback_and_read_error_does_not_retry(self) -> None:
        for replies, targets in [
            (
                [(3, b""), (3, b""), (0, b"x"), (0, b"I\x02\x01" + b"v" * 30)],
                [0x7E0, 0x7D2, 0x7E2, 0],
            ),
            ([(0, b"x"), (0, b"wrong")], [0x7E0, 0]),
        ]:
            c = FakeContext(replies)
            out = bytearray(17)
            status = chassis.run_body("Ex2SMRT_48_ReadVINCode", (4, out), c)
            self.assertEqual(status, 4802 if len(targets) == 4 else 4803)
            self.assertEqual(
                [e[1] for e in c.driver.events if e[0] == "select_target"], targets
            )
            if status == 4802:
                self.assertEqual(out, b"v" * 17)

    def test_smrt48_fixed_functional_fallback_and_live_parameter_restore(self) -> None:
        c = FakeContext([(0, b"~\0"), (3, b""), (0, b"b\xf8\x02" + b"VIN" * 8)])
        c.parameters[0xAB] = 0x12345678
        c.mode = 99
        out = bytearray(17)
        self.assertEqual(chassis.run_body("Ex2SMRT_48_ReadVINCode", (20, out), c), 4802)
        self.assertEqual(out, b"VINVINVINVINVINVI")
        self.assertEqual(c.parameters[0xAB], 0x12345678)
        self.assertEqual(
            c.parameter_events,
            [
                ("set", 0xAB, 0),
                ("write",),
                ("refresh",),
                ("set", 0xAB, 0x12345678),
                ("write",),
                ("refresh",),
            ],
        )
        self.assertEqual(
            [e[1] for e in c.driver.events if e[0] == "exchange"],
            [b">\0", b"\x09\x02", b"\x22\xf8\x02"],
        )
        self.assertEqual(
            sum(e[0] == "configure_parameters" for e in c.driver.events), 3
        )
        self.assertEqual(
            c.driver.events[-2:],
            [("select_protocol", 0), ("select_diagnostic_mode", 1)],
        )

    def test_smrt48_fixed_physical_branch_and_no_vehicle(self) -> None:
        for second, expected in [((0, b"~\0"), 4802), ((3, b""), 4801)]:
            c = FakeContext([(3, b""), second, (0, b"b\xf1\x90Z")])
            out = bytearray(b"x" * 17)
            self.assertEqual(
                chassis.run_body("Ex2SMRT_48_ReadVINCode", (20, out), c), expected
            )
            self.assertIn(("configure_target", 0x7D2, 0, 0, 500000, 0), c.driver.events)
            if expected == 4802:
                self.assertEqual(out, b"Z" + b"x" * 16)

    def test_smrt48_cancel_and_invalid_selector_order(self) -> None:
        c = FakeContext([])
        self.assertEqual(chassis.run_body("Ex2SMRT_48_ReadVINCode", (3, None), c), 99)
        self.assertFalse(c.kinds)
        c.cancelled = True
        c.parameters[0xAB] = 9
        self.assertEqual(
            chassis.run_body("Ex2SMRT_48_ReadVINCode", (20, bytearray(17)), c), 99
        )
        self.assertEqual(c.parameters[0xAB], 9)
        self.assertEqual(
            c.driver.events,
            [("finalize",), ("select_protocol", 0), ("select_diagnostic_mode", 1)],
        )

    def test_smrt48_fixed_host_fault_restores_live_broker(self) -> None:
        c = FakeContext([])
        c.driver.fault = RuntimeError("raw driver failed")
        c.parameters[0xAB] = 13
        with self.assertRaisesRegex(RuntimeError, "raw driver failed"):
            chassis.run_body("Ex2SMRT_48_ReadVINCode", (20, bytearray(17)), c)
        self.assertEqual(c.parameters[0xAB], 13)
        self.assertEqual(
            c.driver.events[-3:],
            [("finalize",), ("select_protocol", 0), ("select_diagnostic_mode", 1)],
        )

    def test_smrt48_serial_validation_and_timeout_restoration(self) -> None:
        for reply, expected in [
            (b"a\xcc" + bytes(range(16)), 4804),
            (b"a\xcd" + bytes(16), 3),
            (b"a\xcc" + bytes(15), 3),
        ]:
            c = FakeContext([(0, reply)])
            c.mode = 4
            out = bytearray(b"x" * 16)
            self.assertEqual(
                chassis.run_body("Ex2SMRT_48_GetTheDigitalKeySerialNo", (out,), c),
                expected,
            )
            self.assertEqual(out, bytes(range(16)) if expected == 4804 else b"x" * 16)
            self.assertEqual(
                c.driver.events[-2:],
                [("configure", "native_rva:172d0", 100), ("finalize",)],
            )

    def test_smrt48_actual_fixed_facade_functional_and_physical_vin(self) -> None:
        from scripts.j2534_2026 import NativeMessage, PrimitiveResult
        from scripts.utility_ex import UtilityExContext as SourceContext
        from scripts.utility_ex import UtilityExEngine
        from scripts.utility_ex_comm import SHA_18_NK

        path = Path(
            "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityExNK2.dll"
        )
        require_private(path)

        class Host:
            def __init__(self) -> None:
                self.parameters = {
                    0x6F: 3,
                    0x70: 18,
                    0x74: 0x7E0,
                    0xD3: 0xFFFFFFFF,
                    0xDD: 0xFFFFFFFF,
                    0xAB: 0xBEEF,
                }
                self.tick = 0
                self.events: list[tuple[object, ...]] = []

            def get_parameter(self, key: int) -> int:
                return self.parameters.get(key, 0)

            def set_parameter(self, key: int, value: int) -> int:
                self.events.append(("set", key, value))
                self.parameters[key] = value
                return 0

            def write_parameters(self) -> int:
                self.events.append(("write",))
                return 0

            def get_data_size(self, key: int) -> int:
                return 8 if key == 500 else 0

            def get_data(self, key: int) -> bytes:
                return (
                    (1).to_bytes(4, "little") + (500000).to_bytes(4, "little")
                    if key == 500
                    else b""
                )

            def ticks(self) -> int:
                self.tick += 1
                return self.tick

            def sleep(self, milliseconds: int) -> None:
                self.tick += milliseconds

        for payloads, expected_writes in [
            ([b"~\0", b"I\x02\x01VIN"], [(0x700, b">\0"), (0x7DF, b"\x09\x02")]),
            (
                [b"~", b"~\0", b"b\xf1\x90VIN"],
                [(0x700, b">\0"), (0x7D2, b">\0"), (0x7D2, b"\x22\xf1\x90")],
            ),
            (
                [b"~\0", b"I\x03\x01wrong", b"b\xf8\x02VIN"],
                [(0x700, b">\0"), (0x7DF, b"\x09\x02"), (0x7DF, b"\x22\xf8\x02")],
            ),
        ]:
            with (
                self.subTest(requests=expected_writes),
                patch.object(chassis, "NK18_SHA256", SHA_18_NK),
            ):
                replies = deque(payloads)
                writes: list[bytes] = []
                cleanup: list[tuple[str, int]] = []
                next_filter = iter(range(51, 100))

                def connect(protocol, flags, output):
                    output[:] = (42).to_bytes(4, "little")
                    return PrimitiveResult()

                def start_filter(
                    channel, kind, mask, pattern, flow, output, next_filter=next_filter
                ):
                    output[:] = next(next_filter).to_bytes(4, "little")
                    return PrimitiveResult()

                def write(
                    channel,
                    messages,
                    count,
                    timeout,
                    writes=writes,
                ):
                    writes.append(messages[0].data)
                    return PrimitiveResult()

                def read(
                    channel, messages, count, timeout, writes=writes, replies=replies
                ):
                    target = int.from_bytes(writes[-1][:4], "big")
                    response = {0x700: 0x708, 0x7DF: 0x7E8, 0x7D2: 0x7DA}[target]
                    messages[0] = NativeMessage(
                        6, response.to_bytes(4, "big") + replies.popleft()
                    )
                    return PrimitiveResult()

                def stop_filter(channel, identifier, cleanup=cleanup):
                    cleanup.append(("stop", identifier))
                    return PrimitiveResult()

                def disconnect(channel, cleanup=cleanup):
                    cleanup.append(("disconnect", channel))
                    return PrimitiveResult()

                names = (
                    "PassThruConnect",
                    "PassThruOemConnect",
                    "PassThruDisconnect",
                    "PassThruIoctl",
                    "PassThruGetLastError",
                    "PassThruWriteMsgs",
                    "PassThruReadMsgs",
                    "PassThruStartPeriodicMsg",
                    "PassThruStopPeriodicMsg",
                    "PassThruStartMsgFilter",
                    "PassThruStopMsgFilter",
                    "PassThruSetProgrammingVoltage",
                    "PassThruReadVersion",
                    "J2534CtrlInitialize",
                    "J2534CtrlFinalize",
                )
                exports: dict[str, Callable[..., object]] = dict.fromkeys(
                    names, lambda *args: PrimitiveResult()
                )
                exports.update(
                    PassThruConnect=connect,
                    PassThruStartMsgFilter=start_filter,
                    PassThruWriteMsgs=write,
                    PassThruReadMsgs=read,
                    PassThruStopMsgFilter=stop_filter,
                    PassThruDisconnect=disconnect,
                )
                host = Host()
                context = SourceContext(
                    path.read_bytes(), host, None, None, driver_exports=exports
                )
                out = bytearray(b"x" * 17)
                try:
                    engine = UtilityExEngine(context)
                    self.assertEqual(
                        engine.invoke("Ex2SMRT_48_ReadVINCode", (20, out)), 15
                    )
                    self.assertEqual(engine.worker.get_status(), 4802)
                    self.assertEqual(out, b"VIN" + b"x" * 14)
                    self.assertEqual(
                        writes,
                        [
                            target.to_bytes(4, "big") + payload
                            for target, payload in expected_writes
                        ],
                    )
                    self.assertFalse(replies)
                    self.assertEqual(host.parameters[0xAB], 0xBEEF)
                    self.assertEqual(
                        host.events,
                        [
                            ("set", 0xAB, 0),
                            ("write",),
                            ("set", 0xAB, 0xBEEF),
                            ("write",),
                        ],
                    )
                    self.assertEqual(
                        sum(event[0] == "disconnect" for event in cleanup),
                        len(payloads)
                        - (
                            1
                            if len(payloads) == 3 and expected_writes[1][0] == 0x7D2
                            else 0
                        ),
                    )
                finally:
                    context.comm("native:1014f5e0").finalize()

    def test_abs36_actual_source_context_fixed_facade_and_raw_sdk_trace(self) -> None:
        from scripts.j2534_2026 import NativeMessage, PrimitiveResult
        from scripts.utility_ex import UtilityExContext as SourceContext
        from scripts.utility_ex import UtilityExEngine
        from scripts.utility_ex_comm import SHA_18_NK

        path = Path(
            "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityExNK2.dll"
        )
        if not path.is_file():
            self.skipTest("Exact supplied NK18 static image unavailable")

        class Host:
            def __init__(self) -> None:
                self.tick = 0

            def get_parameter(self, key: int) -> int:
                return {
                    0x6F: 20,
                    0x70: 18,
                    0x74: 0x7E0,
                    0xD3: 0xFFFFFFFF,
                    0xDD: 0xFFFFFFFF,
                }.get(key, 0)

            def get_data_size(self, key: int) -> int:
                return 8 if key == 500 else 0

            def get_data(self, key: int) -> bytes:
                return (
                    (1).to_bytes(4, "little") + (500000).to_bytes(4, "little")
                    if key == 500
                    else b""
                )

            def set_parameter(self, key: int, value: int) -> int:
                return 0

            def write_parameters(self) -> int:
                return 0

            def ticks(self) -> int:
                self.tick = (self.tick + 1) & 0xFFFFFFFF
                return self.tick

            def sleep(self, milliseconds: int) -> None:
                self.tick = (self.tick + milliseconds) & 0xFFFFFFFF

        cases: list[tuple[str, int, list[bytes], list[bytes]]] = []
        for reply, expected in (
            (b"\x62\x20\x02\x40\0", 0),
            (b"\x62\x20\x02\0\0", 3600),
            (b"\x62\x20\x03\x40\0", 3),
            (b"\x7f\x22\x33", 7),
        ):
            count = 3 if reply.startswith(b"\x7f") else 1
            cases.append(
                (
                    "Ex2ABS_36_SupportInfo",
                    expected,
                    [b"\x22\x20\x02"] * count,
                    [reply] * count,
                )
            )
        did = b"\x62\x10\x2d" + bytes(8) + b"\x20\0"
        cases.extend(
            (
                (
                    "Ex2ABS_35_ConfDIDBitInfo",
                    0,
                    [b"\x22\x10\x2d", b"\x22\x28\x01"],
                    [did, b"\x62\x28\x01\xff\0\x20"],
                ),
                (
                    "Ex2ABS_35_ConfDIDBitInfo",
                    1000,
                    [b"\x22\x10\x2d"],
                    [did[:11] + b"\0\x20"],
                ),
                (
                    "Ex2ABS_35_ConfPlumbigStatus",
                    1004,
                    [b"\x22\x10\x2d"],
                    [did[:-1] + b"\x20"],
                ),
            )
        )
        stages = "AABBBBAAC" * 2 + "DE"
        cases.append(
            (
                "Ex2ABS_35_SolenoidDriving",
                0,
                [chassis._ABS35_REQUESTS[stage] for stage in stages],
                [b"\x6f" + chassis._ABS35_REQUESTS[stage][1:4] for stage in stages],
            )
        )
        cases.append(
            (
                "Ex2SMRT_58_StartIFBOXComIDReg",
                0,
                [b"\x31\x01\x13\x05", b"\x31\x03\x13\x05"],
                [b"\x71\x01\x13\x05", b"\x71\x03\x13\x05\x02"],
            )
        )
        cases.extend(
            [
                (
                    "Ex2SMRT_56_ConfirmDIDRIDSupport",
                    0,
                    [row[0] for row in chassis._SUPPORT56],
                    [
                        b"b\x01\x01\0\0\x80",
                        b"b\x10\0\0\0\x40",
                        b"q\x01\x10\x01\0\0\1",
                        b"q\x01\x17\0\x80",
                    ],
                ),
                (
                    "Ex2SMRT_56_StartFingerprintMode",
                    0,
                    [b"\x31\x01\x17\1", b"\x31\x02\x17\1"],
                    [b"q\x01\x17\1", b"q\x02\x17\1"],
                ),
            ]
        )
        cases.append(
            (
                "Ex2SMRT_53_Online_Certification",
                0,
                [
                    b"\x22\x01\x01",
                    b"\x22\x11\0",
                    b"\x22\xf1\0",
                    b"\x22\x11\x02",
                    b"\x22\xf1\x8c",
                    b"\x27\x09",
                    b"\x27\x0akey",
                ],
                [reply for _, reply in self.good53()]
                + [b"b\xf1\x8c" + bytes(10) + b"12345678", b"g\x09ABCDEF", b"g\x0a"],
            )
        )
        poll50 = bytearray(b"b\x11\1" + bytes(21))
        poll50[9] = 1
        cases.extend(
            [
                (
                    "Ex2SMRT_50_GetSupportInfo",
                    0,
                    [
                        b"\x22\1\1",
                        b"\x22\x11\0",
                        b"\x31\1\x10\1",
                        b"\x31\1\x16\0",
                        b"\x22\x10\0",
                    ],
                    [
                        b"b\1\1\0\0\xc0",
                        b"b\x11\0\x80",
                        b"q\1\x10\1\0\0\2",
                        b"q\1\x16\0\x20",
                        b"b\x10\0\0\0\x40",
                    ],
                ),
                (
                    "Ex2SMRT_50_StartKeyErasure",
                    0,
                    [b"\x31\1\x16\3", b"\x22\x11\1"],
                    [b"q\1\x16\3", bytes(poll50)],
                ),
            ]
        )
        poll63 = bytearray(b"b\x11\1" + bytes(21))
        poll63[22] = 1
        cases.extend(
            [
                (
                    "Ex2SMRT_63_GetSupportInfo",
                    0,
                    [
                        b"\x22\1\1",
                        b"\x22\x11\0",
                        b"\x31\1\x10\1",
                        b"\x31\1\x16\0",
                        b"\x22\x10\0",
                    ],
                    [
                        b"b\1\1\0\0\xc0",
                        b"b\x11\0\x80",
                        b"q\1\x10\1\0\0\2",
                        b"q\1\x16\0\x20",
                        b"b\x10\0\0\0\x40",
                    ],
                ),
                (
                    "Ex2SMRT_63_StartKeyErasure",
                    0,
                    [b"\x31\1\x16\3", b"\x22\x11\1"],
                    [b"q\1\x16\3", bytes(poll63)],
                ),
            ]
        )
        for export, expected, requests, body_replies in cases:
            with (
                self.subTest(export=export, expected=expected),
                patch.object(chassis, "NK18_SHA256", SHA_18_NK),
            ):
                prefix = (
                    []
                    if export.startswith("Ex2SMRT_58_")
                    or export.endswith("StartFingerprintMode")
                    or export
                    in ("Ex2SMRT_50_StartKeyErasure", "Ex2SMRT_63_StartKeyErasure")
                    else [b"\x50\x01", b"\x50\x03"]
                )
                suffix = [] if export.startswith("Ex2SMRT_53_") else [b"\x50\x01"]
                replies = deque(prefix + body_replies + suffix)
                pending_reply: deque[bytes] = deque()
                writes: list[bytes] = []
                cleanup: list[tuple[str, int]] = []
                filters = iter((51, 52))

                def connect(protocol, flags, output):
                    output[:] = (42).to_bytes(4, "little")
                    return PrimitiveResult()

                def start_filter(
                    channel, kind, mask, pattern, flow, output, filters=filters
                ):
                    output[:] = next(filters).to_bytes(4, "little")
                    return PrimitiveResult()

                def write(
                    channel,
                    messages,
                    count,
                    timeout,
                    writes=writes,
                    pending_reply=pending_reply,
                    replies=replies,
                ):
                    message = messages[0].data
                    writes.append(message)
                    request = message[4:]
                    pending_reply.append(
                        b"\x7e\0" if request == b"\x3e\0" else replies.popleft()
                    )
                    return PrimitiveResult()

                def read(
                    channel, messages, count, timeout, pending_reply=pending_reply
                ):
                    messages[0] = NativeMessage(
                        6, b"\0\0\x07\xe8" + pending_reply.popleft()
                    )
                    return PrimitiveResult()

                def stop_filter(channel, identifier, cleanup=cleanup):
                    cleanup.append(("stop_filter", identifier))
                    return PrimitiveResult()

                def disconnect(channel, cleanup=cleanup):
                    cleanup.append(("disconnect", channel))
                    return PrimitiveResult()

                names = (
                    "PassThruConnect",
                    "PassThruOemConnect",
                    "PassThruDisconnect",
                    "PassThruIoctl",
                    "PassThruGetLastError",
                    "PassThruWriteMsgs",
                    "PassThruReadMsgs",
                    "PassThruStartPeriodicMsg",
                    "PassThruStopPeriodicMsg",
                    "PassThruStartMsgFilter",
                    "PassThruStopMsgFilter",
                    "PassThruSetProgrammingVoltage",
                    "PassThruReadVersion",
                    "J2534CtrlInitialize",
                    "J2534CtrlFinalize",
                )
                exports: dict[str, Callable[..., object]] = dict.fromkeys(
                    names, lambda *arguments: PrimitiveResult()
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
                context = SourceContext(
                    path.read_bytes(), Host(), None, None, driver_exports=exports
                )
                try:
                    if export.startswith(("Ex2SMRT_50_", "Ex2SMRT_63_")):
                        family = 50 if export.startswith("Ex2SMRT_50_") else 63
                        engine = UtilityExEngine(context)
                        if export.endswith("GetSupportInfo"):
                            out = bytearray(4)
                            self.assertEqual(engine.invoke(export, (out,)), 15)
                            self.assertEqual(engine.worker.get_status(), 0)
                            self.assertEqual(
                                int.from_bytes(out, "little"),
                                5051 if family == 50 else 6351,
                            )
                        else:
                            self.assertEqual(
                                engine.invoke(f"Ex2SMRT_{family}_StartKeepAlive"), 0
                            )
                            self.assertEqual(engine.invoke(export), 15)
                            self.assertEqual(engine.worker.get_status(), 0)
                            self.assertFalse(cleanup)
                            counter = bytearray(4)
                            terminal = (
                                "Ex2SMRT_50_KeyCodeReset"
                                if family == 50
                                else "Ex2SMRT_63_GetKeyStatus"
                            )
                            self.assertEqual(
                                engine.invoke(
                                    terminal, () if family == 50 else (counter,)
                                ),
                                15,
                            )
                            self.assertEqual(
                                engine.worker.get_status(),
                                5001 if family == 50 else 6306,
                            )
                            self.assertEqual(counter, bytes(4))
                    elif export.startswith("Ex2SMRT_53_"):
                        engine = UtilityExEngine(context)
                        status, challenge, seed = (
                            bytearray(b"xxxx"),
                            bytearray(8),
                            bytearray(6),
                        )
                        self.assertEqual(
                            engine.invoke(export, (status, 1, challenge, seed, 0x1C2)),
                            15,
                        )
                        self.assertEqual(engine.worker.get_status(), 0)
                        self.assertFalse(cleanup)
                        self.assertTrue(
                            context.comm("native:1014f5e0")
                            ._fixed_lifecycle()
                            .worker_active
                        )
                        self.assertEqual((challenge, seed), (b"12345678", b"ABCDEF"))
                        self.assertEqual(
                            engine.invoke("Ex2SMRT_53_SendTheKey", (b"key", status, 3)),
                            15,
                        )
                        self.assertEqual(engine.worker.get_status(), 0)
                        self.assertEqual(status, b"xxxx")
                    else:
                        self.assertEqual(
                            chassis.run_body(export, (), context), expected
                        )
                    if export.endswith("StartFingerprintMode"):
                        self.assertFalse(cleanup)
                        self.assertTrue(
                            context.comm("native:1014f5e0")
                            ._fixed_lifecycle()
                            .worker_active
                        )
                        self.assertEqual(
                            chassis.run_body(
                                "Ex2SMRT_56_TerminateFingerprintMode", (), context
                            ),
                            6005,
                        )
                    self.assertEqual(
                        [message for message in writes if message[4:] != b"\x3e\0"],
                        [
                            b"\0\0\x07\xe0" + payload
                            for payload in (
                                [b"\x10\x01", b"\x10\x03"] if prefix else []
                            )
                            + requests
                            + ([b"\x10\x01"] if suffix else [])
                        ],
                    )
                    self.assertEqual(
                        cleanup,
                        [("stop_filter", 51), ("stop_filter", 52), ("disconnect", 42)],
                    )
                    self.assertEqual(len(replies), 0)
                finally:
                    context.comm("native:1014f5e0").finalize()

    def advance_clock_on_exchange(
        self, context: FakeContext, milliseconds: int
    ) -> None:
        original = context.driver.exchange

        def exchange(request: bytes) -> tuple[int, bytes]:
            result = original(request)
            context.clock += milliseconds
            return result

        context.driver.exchange = exchange

    def setUp(self) -> None:
        # Only the immutable input identity is synthetic; production guard stays.
        identity = patch.object(chassis, "NK18_SHA256", SYNTHETIC_SHA)
        identity.start()
        self.addCleanup(identity.stop)

    def run_export(self, name: str, context: FakeContext, *args: object) -> int:
        if (
            name.startswith("Ex2SMRT_53_")
            and context.module_sha256 != chassis.NK12_SHA256
        ):
            operation = name.removeprefix("Ex2SMRT_53_")
            base, _ = chassis._fields53(context, operation)
            for index, value in enumerate(args):
                context.state[f"native_global:{base + index * 4:08x}"] = value
        if (
            name.startswith("Ex2SMRT_47_")
            and context.module_sha256 != chassis.NK12_SHA256
        ):
            operation = name.removeprefix("Ex2SMRT_47_")
            bases = {
                chassis.NK18_SHA256: (0x1014A598, 0x1014A678),
                chassis.NK_DS4_SHA256: (0x101B1944, 0x101B195C),
                chassis.NK_GTS_SHA256: (0x101BCA44, 0x101BCA5C),
            }[context.module_sha256]
            base = bases[int(operation == "GetSupportInfo")]
            fields = (
                tuple((index, index) for index in range(4))
                if operation == "GetSupportInfo"
                else tuple((index, index) for index in range(6))
                if operation == "KeyCodeChk"
                else ((1, 0),)
                if operation == "GetKeyStatus_NomalChk"
                else ()
            )
            for index, argument in fields:
                if argument < len(args):
                    context.state[f"native_global:{base + index * 4:08x}"] = args[
                        argument
                    ]
        if (
            name.startswith("Ex2SMRT_46_")
            and context.module_sha256 != chassis.NK12_SHA256
        ):
            operation = name.removeprefix("Ex2SMRT_46_")
            bases = {
                chassis.NK18_SHA256: (0x1014A6B0, 0x1014A530),
                chassis.NK_DS4_SHA256: (0x101B1914, 0x101B1934),
                chassis.NK_GTS_SHA256: (0x101BCA14, 0x101BCA34),
            }[context.module_sha256]
            base = bases[int(operation == "GetSupportInfo")]
            fields = (
                tuple((index, index) for index in range(4))
                if operation == "GetSupportInfo"
                else tuple((index + 2, index) for index in range(6))
                if operation == "KeyCodeChk"
                else ((3, 0),)
                if operation == "GetKeyStatus"
                else ()
            )
            for index, argument in fields:
                if argument < len(args):
                    context.state[f"native_global:{base + index * 4:08x}"] = args[
                        argument
                    ]
        if (
            name.startswith("Ex2SMRT_45_")
            and context.module_sha256 != chassis.NK12_SHA256
        ):
            operation = name.removeprefix("Ex2SMRT_45_")
            bases = {
                chassis.NK18_SHA256: (0x1014A618, 0x1014A6E0),
                chassis.NK_DS4_SHA256: (0x101B18F8, 0x101B18E8),
                chassis.NK_GTS_SHA256: (0x101BC9F8, 0x101BC9E8),
            }[context.module_sha256]
            base = bases[int(operation == "GetSupportInfo")]
            fields = (
                tuple(
                    (index, index)
                    for index in range(4 if operation == "GetSupportInfo" else 6)
                )
                if operation in ("GetSupportInfo", "StartOwnersKeyReg")
                else ((4, 0),)
                if operation.startswith("GetKeyStatus_")
                else ()
            )
            for index, argument in fields:
                if argument < len(args):
                    context.state[f"native_global:{base + index * 4:08x}"] = args[
                        argument
                    ]
        if name.startswith("Ex2SMRT_42_"):
            base = {
                chassis.NK18_SHA256: 0x1014A640,
                chassis.NK12_SHA256: 0x100E5C90,
                chassis.NK_DS4_SHA256: 0x101B18C8,
                chassis.NK_GTS_SHA256: 0x101BC9C8,
            }[context.module_sha256]
            fields = {
                "GetKeyNum": ((0, 0), (3, 1)),
                "GetKeyStatus": ((1, 1), (3, 0)),
                "KeyCodeErasure": ((3, 0),),
                "KeyCodeErasureChk": tuple((index, index) for index in range(8)),
            }.get(name.removeprefix("Ex2SMRT_42_"), ())
            for index, argument in fields:
                if argument < len(args):
                    context.state[f"native_global:{base + index * 4:08x}"] = args[
                        argument
                    ]
        if name.startswith("Ex2SMRT_41_"):
            # Authored native wrapper preparation; production preparation belongs to83.
            operation = name.removeprefix("Ex2SMRT_41_")
            bases = {
                chassis.NK18_SHA256: (0x1014A5C0, 0x1014A588, 0x1014A5B8, 0x1014A688),
                chassis.NK12_SHA256: (0x100E5C68, 0x100E5C50, 0x100E5C60, 0x100E5CB8),
                chassis.NK_DS4_SHA256: (0x101B19BC, 0x101B19E0, 0x101B19F0, 0x101B19F8),
                chassis.NK_GTS_SHA256: (0x101BCABC, 0x101BCAE0, 0x101BCAF0, 0x101BCAF8),
            }[context.module_sha256]
            op_index = (
                "Online_Certification",
                "Online_Certification_008",
                "KeepAlive",
                "SendTheKey",
            ).index(operation)
            if len(args) == (9, 4, 2, 3)[op_index]:
                indices = (
                    tuple(range(len(args)))
                    if op_index
                    else (0, 1, 2, 3, 4, 8) + ((5,) if args[8] else (6, 7))
                )
                for index in indices:
                    context.state[
                        f"native_global:{bases[op_index] + index * 4:08x}"
                    ] = args[index]
        return chassis.run_body(name, args, context)

    def exchanged(self, context: FakeContext) -> list[bytes]:
        return [event[1] for event in context.driver.events if event[0] == "exchange"]  # type: ignore[misc]

    def test_exact_identity_and_unknown_export_fail_before_comm(self) -> None:
        context = FakeContext([])
        for name in ("Ex2ABS_Unknown", "Ex2ABS_99_NativeOperation"):
            with self.assertRaises(chassis.UnsupportedChassisOperation):
                self.run_export(name, context)
        context.module_bytes = b"mutated"
        with self.assertRaises(chassis.UnsupportedChassisOperation):
            self.run_export("Ex2SMRT_03_ModeEntry", context)
        self.assertEqual(context.kinds, [])

    def test_mode_guard_and_argument_validation_precede_comm(self) -> None:
        context = FakeContext([])
        context.mode = 4
        self.assertEqual(self.run_export("Ex2SMRT_03_ModeEntry", context), 99)
        for arguments in ((bytearray(3), bytearray(4)), (b"1234", bytearray(4))):
            with self.assertRaises(ValueError):
                self.run_export("Ex2SMRT_03_GetEntryKey", context, *arguments)
        with self.assertRaises(ValueError):
            self.run_export("Ex2ABS_BeginAirBleed_TRC", context, True)
        self.assertEqual(context.kinds, [])

    def test_abs_loop_bytes_and_cancel_retains_driver(self) -> None:
        cases = (
            ("Ex2ABS_BeginAirBleed_TRC", 0x226, b"\x30\x05\x01\x01", 2000),
            ("Ex2ABS_BeginSolenoidDrive_TRC", 0x228, b"\x30\x22\x0c\x0c\0", 2000),
            ("Ex2ABS_BeginSolenoidDrive_ABS", 0x231, b"\x30\x21\x08\x08", 2000),
        )
        for name, selection, request, delay in cases:
            with self.subTest(name=name):
                context = FakeContext([(0, bytes((0x70, request[1])))])
                context.cancel_after_sleep = 1
                self.assertEqual(self.run_export(name, context, selection), 0)
                self.assertEqual(self.exchanged(context), [request])
                self.assertEqual(context.sleeps, [delay])
                self.assertNotIn(("finalize",), context.driver.events)
                self.assertEqual(context.kinds, ["selected"])

    def test_abs_native_init_failure_and_driver_fault_cleanup(self) -> None:
        context = FakeContext([])
        context.driver.init_status = 14
        self.assertEqual(self.run_export("Ex2ABS_BeginAirBleed_TRC", context, 0), 14)
        self.assertEqual(self.exchanged(context), [])
        self.assertIn(("finalize",), context.driver.events)
        context = FakeContext([])
        context.driver.fault = OSError("wire fault")
        with self.assertRaises(OSError):
            self.run_export("Ex2ABS_BeginAirBleed_TRC", context, 0)
        self.assertIn(("configure", "native_rva:172f0", 3), context.driver.events)
        self.assertIn(("configure", "native_rva:17320", 100), context.driver.events)
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_abs_malformed_echo_three_byte_branch_and_transport_status(self) -> None:
        for reply, expected in (
            (b"\x70\xff", 3),
            (b"\x70\xff\0", 12),
            (b"\x70\x05\1", 3),
            (b"\x71\x05", 3),
            (b"", 3),
        ):
            context = FakeContext([(0, reply)])
            self.assertEqual(
                self.run_export("Ex2ABS_BeginAirBleed_TRC", context, 0), expected
            )
        context = FakeContext([(27, b"")])
        self.assertEqual(self.run_export("Ex2ABS_BeginAirBleed_TRC", context, 0), 27)

    def test_abs01_selection_echo_and_native_retention(self) -> None:
        for selection, request in (
            (0x226, b"\x30\x21\x02\x02"),
            (0x227, b"\x30\x21\x08\x08"),
            (0, b"\x30\x22\x0c\x0c"),
            (0xFFFFFFFF, b"\x30\x22\x0c\x0c"),
        ):
            context = FakeContext([(0, bytes((0x70, request[1])))])
            context.cancel_after_sleep = 1
            self.assertEqual(
                self.run_export("Ex2ABS_01_BeginSolenoidDrive", context, selection), 0
            )
            self.assertEqual(self.exchanged(context), [request])
            self.assertEqual(context.sleeps, [2000])
            self.assertNotIn(("finalize",), context.driver.events)
        for reply, expected in ((b"\x70\x21\0", 12), (b"\x70\xff\0", 3)):
            context = FakeContext([(0, reply)])
            self.assertEqual(
                self.run_export("Ex2ABS_01_BeginSolenoidDrive", context, 0x226),
                expected,
            )
            self.assertNotIn(("finalize",), context.driver.events)
        context = FakeContext([])
        context.driver.init_status = 21
        self.assertEqual(self.run_export("Ex2ABS_01_BeginSolenoidDrive", context, 0), 4)
        self.assertNotIn(("finalize",), context.driver.events)
        context = FakeContext([])
        context.cancelled = True
        self.assertEqual(
            self.run_export("Ex2ABS_01_BeginSolenoidDrive", context, 0), 99
        )
        self.assertEqual(context.driver.events, [])
        context = FakeContext([])
        context.driver.fault = OSError("wire fault")
        with self.assertRaises(OSError):
            self.run_export("Ex2ABS_01_BeginSolenoidDrive", context, 0)
        self.assertEqual(
            context.driver.events[-3:],
            [
                ("configure", "native_rva:17320", 100),
                ("configure", "native_rva:172f0", 3),
                ("finalize",),
            ],
        )

    def uds_context(self, replies: list[tuple[int, bytes]]) -> FakeContext:
        context = FakeContext(replies)
        context.mode = 20
        return context

    def test_source_specific_export_admission(self) -> None:
        self.assertNotIn(
            "Ex2ABS_36_SupportInfo", chassis.supported_exports(chassis.NK12_SHA256)
        )
        for digest in (
            chassis.NK18_SHA256,
            chassis.NK_DS4_SHA256,
            chassis.NK_GTS_SHA256,
        ):
            self.assertIn("Ex2ABS_36_SupportInfo", chassis.supported_exports(digest))
        self.assertEqual(chassis.supported_exports("unknown"), frozenset())

    def test_abs35_support_bits_use_distinct_reply_offsets(self) -> None:
        first = b"\x62\x10\x2d" + bytes(8) + b"\x20\0"
        second = b"\x62\x28\x01\xff\0\x20"
        for first_reply, second_reply, expected in (
            (first, second, 0),
            (first[:11] + b"\0\x20", second, 1000),
            (first, second[:3] + b"\0\0\x20", 1001),
            (first, second[:5] + b"\0", 1001),
            (first[:12], second, 3),
            (first, b"\x62\x28\x02\xff\0\x20", 3),
        ):
            context = self.uds_context([(0, first_reply), (0, second_reply)])
            self.assertEqual(
                self.run_export("Ex2ABS_35_ConfDIDBitInfo", context), expected
            )
            self.assertEqual(self.exchanged(context)[0], b"\x22\x10\x2d")
            self.assertEqual(context.driver.events[-1], ("finalize",))
            self.assertEqual(
                ("configure", "native_rva:18840", 1) in context.driver.events,
                expected != 0,
            )

    def test_abs35_plumbing_1003_1004_are_successful_native_results(self) -> None:
        for bit, expected in ((0, 1003), (0x20, 1004)):
            context = self.uds_context(
                [(0, b"\x62\x10\x2d" + bytes(9) + bytes((bit,)))]
            )
            self.assertEqual(
                self.run_export("Ex2ABS_35_ConfPlumbigStatus", context), expected
            )
            self.assertEqual(
                [e for e in context.driver.events if e[0] == "session"],
                [("session", 3, 1, True, False), ("session", 1, 1, False, True)],
            )
            self.assertFalse(any(e[0] == "configure" for e in context.driver.events))

    def test_abs35_full_solenoid_two_rounds_and_source_timing(self) -> None:
        stages = "AABBBBAAC" * 2 + "DE"
        replies = [
            (0, b"\x6f" + chassis._ABS35_REQUESTS[stage][1:4] + b"extra")
            for stage in stages
        ]
        context = self.uds_context(replies)
        self.assertEqual(self.run_export("Ex2ABS_35_SolenoidDriving", context), 0)
        self.assertEqual(
            self.exchanged(context),
            [chassis._ABS35_REQUESTS[stage] for stage in stages],
        )
        self.assertEqual(context.clock, 36000)
        self.assertEqual(sum(context.sleeps), 35000)
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_abs35_solenoid_failure_phase_selects_only_native_cleanup(self) -> None:
        stages = "AABBBBAAC" * 2 + "DE"
        for index, cleanup in ((0, "C"), (8, ""), (9, "C"), (18, "E"), (19, "")):
            replies = [
                (0, b"\x6f" + chassis._ABS35_REQUESTS[stage][1:4])
                for stage in stages[:index]
            ] + [(17, b"")]
            if cleanup:
                replies.append((27, b""))
            context = self.uds_context(replies)
            self.assertEqual(self.run_export("Ex2ABS_35_SolenoidDriving", context), 17)
            self.assertEqual(
                self.exchanged(context),
                [
                    chassis._ABS35_REQUESTS[stage]
                    for stage in stages[: index + 1] + cleanup
                ],
            )
            self.assertIn(("configure", "native_rva:18840", 1), context.driver.events)
            self.assertIn(("configure", "native_rva:18840", 0), context.driver.events)
            self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_abs35_precancel_skips_waits_but_preserves_all_commands(self) -> None:
        stages = "AABBBBAAC" * 2 + "DE"
        context = self.uds_context(
            [(0, b"\x6f" + chassis._ABS35_REQUESTS[stage][1:4]) for stage in stages]
        )
        context.cancelled = True
        self.assertEqual(self.run_export("Ex2ABS_35_SolenoidDriving", context), 0)
        self.assertEqual(len(self.exchanged(context)), 20)
        self.assertEqual(context.sleeps, [])

    def test_abs35_session_errors_map1002_and_skip_fallback(self) -> None:
        for statuses, replies in (
            ([17], []),
            ([0, 17], [(0, b"\x62\x10\x2d" + bytes(9) + b"\x20")]),
        ):
            context = self.uds_context(replies)
            context.driver.sessions.extend(statuses)
            self.assertEqual(
                self.run_export("Ex2ABS_35_ConfPlumbigStatus", context), 1002
            )
            self.assertNotIn(
                ("configure", "native_rva:18840", 1), context.driver.events
            )
            self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.uds_context([(17, b"")])
        context.driver.init_status = 17
        self.assertEqual(self.run_export("Ex2ABS_35_SolenoidDriving", context), 17)
        self.assertEqual(self.exchanged(context), [chassis._ABS35_REQUESTS["C"]])

    def test_abs35_host_fault_closes_without_inventing_native_result(self) -> None:
        context = self.uds_context([(0, b"\x6f\x28\x01\x03")])
        fault = TimeoutError("authored sleep failure")
        context.sleep_fault = fault
        with self.assertRaises(TimeoutError) as raised:
            self.run_export("Ex2ABS_35_SolenoidDriving", context)
        self.assertIs(raised.exception, fault)
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_abs35_three_exact_sources_and_nk12_exclusion(self) -> None:
        self.assertNotIn(
            "Ex2ABS_35_SolenoidDriving", chassis.supported_exports(chassis.NK12_SHA256)
        )
        for constant, scope, setter in (
            ("NK18_SHA256", "native:1014f5e0", "native_rva:18840"),
            ("NK_DS4_SHA256", "native:101b6758", "native_rva:32b90"),
            ("NK_GTS_SHA256", "native:101c18a0", "native_rva:33aa0"),
        ):
            blob = ("authored ABS35 " + constant).encode()
            digest = hashlib.sha256(blob).hexdigest()
            with patch.object(chassis, constant, digest):
                context = self.uds_context([(0, b"\x62\x10\x2d" + bytes(10))])
                context.module_bytes, context.module_sha256 = blob, digest
                self.assertEqual(
                    self.run_export("Ex2ABS_35_ConfDIDBitInfo", context), 1000
                )
                self.assertEqual(context.kinds, [scope])
                self.assertIn(("configure", setter, 1), context.driver.events)

    def test_abs36_exact_variant_scope_and_configuration_guards(self) -> None:
        for constant, scope, setter in (
            ("NK18_SHA256", "native:1014f5e0", "native_rva:18840"),
            ("NK_DS4_SHA256", "native:101b6758", "native_rva:32b90"),
            ("NK_GTS_SHA256", "native:101c18a0", "native_rva:33aa0"),
        ):
            blob = ("authored ABS36 " + constant).encode()
            digest = hashlib.sha256(blob).hexdigest()
            with (
                self.subTest(variant=constant),
                patch.object(chassis, constant, digest),
            ):
                context = self.uds_context([(17, b"")])
                context.module_bytes, context.module_sha256 = blob, digest
                context.cancelled = True
                self.assertEqual(
                    self.run_export("Ex2ABS_36_Stop_ECBProhibitCtrl", context), 17
                )
                self.assertEqual(context.kinds, [scope])
                self.assertIn(("configure", setter, 1), context.driver.events)
                self.assertIn(("configure", setter, 0), context.driver.events)
                context = FakeContext([])
                context.module_bytes, context.module_sha256 = blob, digest
                self.assertEqual(self.run_export("Ex2ABS_36_SupportInfo", context), 99)
                self.assertEqual(context.kinds, [])
        blob = b"authored NK12 without ABS36"
        digest = hashlib.sha256(blob).hexdigest()
        with patch.object(chassis, "NK12_SHA256", digest):
            context = self.uds_context([])
            context.module_bytes, context.module_sha256 = blob, digest
            with self.assertRaises(chassis.UnsupportedChassisOperation):
                self.run_export("Ex2ABS_36_SupportInfo", context)
            self.assertEqual(context.kinds, [])

    def test_abs36_support_and_session_failures(self) -> None:
        for reply, expected in (
            (b"\x62\x20\x02\x40\0", 0),
            (b"\x62\x20\x02\0\0", 0xE10),
            (b"\x62\x20\x02\x40", 3),
            (b"\x62\x20\x03\x40\0", 3),
        ):
            context = self.uds_context([(0, reply)])
            self.assertEqual(
                self.run_export("Ex2ABS_36_SupportInfo", context), expected
            )
            self.assertEqual(context.kinds, ["native:1014f5e0"])
            self.assertEqual(self.exchanged(context), [b"\x22\x20\x02"])
            self.assertEqual(context.driver.events[-1], ("finalize",))
            self.assertIn(("session", 3, 1, True, False), context.driver.events)
            if expected:
                self.assertIn(
                    ("configure", "native_rva:18840", 1), context.driver.events
                )
                self.assertIn(
                    ("configure", "native_rva:18840", 0), context.driver.events
                )
        context = self.uds_context([])
        context.driver.sessions.append(7)
        self.assertEqual(self.run_export("Ex2ABS_36_SupportInfo", context), 0xE11)
        self.assertEqual(self.exchanged(context), [])
        context = self.uds_context([(0, b"\x62\x20\x02\x40\0")])
        context.driver.sessions.extend((0, 3))
        self.assertEqual(self.run_export("Ex2ABS_36_SupportInfo", context), 0xE11)

    def test_abs36_starts_retain_success_and_recover_failures(self) -> None:
        for operation, start, stop, delay, error in (
            ("Start_ECBProhibitCtrl", b"\x31\x01\x11\x35", b"\x31\x02\x11\x35", 0, 12),
            ("Start_ZeroDownDrive", b"\x31\x01\x11\x32", b"\x31\x02\x11\x32", 3000, 12),
            (
                "Change_DealerMode",
                b"\x31\x01\x11\x0c\x01",
                b"\x31\x01\x11\x0c\0",
                0,
                0xE14,
            ),
        ):
            name = "Ex2ABS_36_" + operation
            context = self.uds_context([(0, b"\x71" + start[1:4])])
            self.assertEqual(self.run_export(name, context), 0)
            self.assertEqual(self.exchanged(context), [start])
            self.assertNotIn(("finalize",), context.driver.events)
            context = self.uds_context([(12, b""), (19, b"")])
            self.assertEqual(self.run_export(name, context), error)
            self.assertEqual(self.exchanged(context), [start, stop])
            self.assertEqual(context.sleeps, [delay] if delay else [])
            self.assertEqual(context.driver.events[-1], ("finalize",))
            context = self.uds_context([])
            context.driver.init_status = 0xE11
            self.assertEqual(self.run_export(name, context), 0xE11)
            self.assertEqual(
                ("finalize",) in context.driver.events,
                operation == "Start_ZeroDownDrive",
            )

    def test_abs36_stop_workers_always_close_and_stoproutine_ignores_native_status(
        self,
    ) -> None:
        for operation, command in (
            ("Stop_ECBProhibitCtrl", b"\x31\x02\x11\x35"),
            ("Change_NormalMode", b"\x31\x01\x11\x0c\0"),
            ("StopRoutine", b"\x31\x02\x11\x32"),
        ):
            context = self.uds_context([(17, b"")])
            self.assertEqual(
                self.run_export("Ex2ABS_36_" + operation, context),
                0 if operation == "StopRoutine" else 17,
            )
            self.assertEqual(self.exchanged(context), [command])
            self.assertEqual(context.driver.events[-1], ("finalize",))
            self.assertEqual(
                context.sleeps, [20000] if operation == "StopRoutine" else []
            )
            if operation == "StopRoutine":
                self.assertNotIn(("initialize", 0), context.driver.events)

    def test_abs36_motor_uses_full_response_length_and_verifies_bit(self) -> None:
        for bit, expected in ((0, 0), (0x40, 0xE13)):
            source = b"\x62\x20\x02\xaa\xff\x12\x34"
            context = self.uds_context(
                [
                    (0, source),
                    (0, b"\x6e\x20\x02"),
                    (0, b"\x62\x20\x02\0" + bytes((bit,))),
                ]
            )
            self.assertEqual(
                self.run_export("Ex2ABS_36_Motor_Deactivate", context), expected
            )
            self.assertEqual(
                self.exchanged(context),
                [b"\x22\x20\x02", b"\x2e\x20\x02\xaa\x80\x12\x34", b"\x22\x20\x02"],
            )
            self.assertEqual(context.sleeps, [1000])
            self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.uds_context([(0, b"\x62\x20\x02\0\0")])
        context.sleep_fault = TimeoutError("host deadline")
        context.driver.replies.append((0, b"\x6e\x20\x02"))
        with self.assertRaises(TimeoutError):
            self.run_export("Ex2ABS_36_Motor_Deactivate", context)
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_abs37_refresh_start_stop_and_cleanup_semantics(self) -> None:
        name = "Ex2ABS_37_ForcedActuatorRefresh"
        context = self.uds_context([(0, b"\x71\x01\x11\x38")])
        self.assertEqual(self.run_export(name, context), 0)
        self.assertEqual(context.driver.events[-1], ("finalize",))
        self.assertNotIn(("session", 1, 1, False, False), context.driver.events)
        context = self.uds_context([(0, b"\x71\xff\x11\x38"), (27, b"")])
        self.assertEqual(self.run_export(name, context), 3)
        self.assertEqual(
            self.exchanged(context), [b"\x31\x01\x11\x38", b"\x31\x02\x11\x38"]
        )
        self.assertIn(("session", 1, 1, False, False), context.driver.events)
        context = self.uds_context([])
        context.driver.sessions.append(7)
        self.assertEqual(self.run_export(name, context), 1000)
        self.assertEqual(self.exchanged(context), [])
        context = self.uds_context([(19, b"")])
        context.driver.init_status = 11
        self.assertEqual(self.run_export(name + "Stop", context), 19)
        self.assertEqual(self.exchanged(context), [b"\x31\x02\x11\x38"])
        self.assertIn(("session", 1, 1, False, False), context.driver.events)

    def test_abs37_confirm_poll_native_results_and_cleanup(self) -> None:
        for value, expected in ((2, 0), (3, 1002), (255, 1002)):
            replies = [
                (0, b"\x71\x03\x11\x38\0"),
                (0, b"\x71\x03\x11\x38\x01"),
                (0, b"\x71\x03\x11\x38" + bytes((value,))),
            ]
            if expected:
                replies.append((17, b""))
            context = self.uds_context(replies)
            self.assertEqual(
                self.run_export("Ex2ABS_37_ConfirmRoutineResult", context), expected
            )
            self.assertEqual(context.sleeps, [1000] * 3)
            self.assertEqual(self.exchanged(context)[:3], [b"\x31\x03\x11\x38"] * 3)
            self.assertEqual(
                self.exchanged(context)[3:], [b"\x31\x02\x11\x38"] if expected else []
            )
            self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_abs37_cancellation_and_fault_finalize_without_invented_stop(self) -> None:
        for operation in (
            "ForcedActuatorRefresh",
            "ForcedActuatorRefreshStop",
            "ConfirmRoutineResult",
        ):
            context = self.uds_context([])
            context.cancelled = True
            self.assertEqual(self.run_export("Ex2ABS_37_" + operation, context), 0)
            self.assertEqual(context.driver.events, [("finalize",)])
        context = self.uds_context([])
        context.cancel_after_sleep = 1
        self.assertEqual(self.run_export("Ex2ABS_37_ConfirmRoutineResult", context), 99)
        self.assertEqual(context.driver.events, [("initialize", 0), ("finalize",)])
        context = self.uds_context([])
        context.sleep_fault = TimeoutError("host deadline")
        with self.assertRaises(TimeoutError):
            self.run_export("Ex2ABS_37_ConfirmRoutineResult", context)
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def abs38_support_replies(self) -> list[tuple[int, bytes]]:
        return [
            (0, b"\x62\x01\x01" + bytes(4) + b"\x80"),
            (0, b"\x62\x20\0\x40"),
            (0, b"\x62\x20\x02\xe0\x99\x55"),
            (0, b"\x71\x01\x10\x01\0\0\x40"),
            (0, b"\x71\x01\x11\0" + bytes(6) + b"\x48"),
        ]

    def test_abs38_five_support_queries_masks_and_cached_payload(self) -> None:
        context = self.uds_context(self.abs38_support_replies())
        self.assertEqual(self.run_export("Ex2ABS_38_GetSupportInfo", context, 1), 0)
        self.assertEqual(context.state["nk.chassis.abs38_cache"], b"\xe0\x99\x55")
        for index in range(5):
            replies = self.abs38_support_replies()
            data = replies[index][1]
            replies[index] = (0, data[:-1] + b"\0")
            if index == 2:
                replies[index] = (0, data[:3] + bytes(len(data) - 3))
            context = self.uds_context(replies)
            self.assertEqual(
                self.run_export("Ex2ABS_38_GetSupportInfo", context, 1), 1200 + index
            )
            self.assertEqual(len(self.exchanged(context)), index + 1)
            self.assertEqual(context.driver.events[-1], ("finalize",))
        replies = self.abs38_support_replies()
        replies[2] = (0, b"\x62\x20\x02\xc0\0")
        context = self.uds_context(replies)
        self.assertEqual(self.run_export("Ex2ABS_38_GetSupportInfo", context, 0), 0)

    def test_abs38_retained_starts_keep_errno_and_faults_report_native_error(
        self,
    ) -> None:
        for operation, routine, delay in (
            ("ECBProhibitionControl", 0x35, 0),
            ("AccumulatorZeroDown", 0x32, 3000),
        ):
            output = bytearray(b"old!")
            context = self.uds_context([(0, bytes((0x71, 1, 0x11, routine)))])
            self.assertEqual(
                self.run_export("Ex2ABS_38_" + operation, context, output), 0
            )
            self.assertEqual(output, b"old!")
            self.assertNotIn(("finalize",), context.driver.events)
            context = self.uds_context([(17, b""), (19, b"")])
            self.assertEqual(
                self.run_export("Ex2ABS_38_" + operation, context, output), 1206
            )
            self.assertEqual(int.from_bytes(output, "little"), 17)
            self.assertEqual(context.sleeps, [1000, delay] if delay else [1000])
            self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_abs38_vacuum_uses_retained_cache_and_exact_three_byte_write_reply(
        self,
    ) -> None:
        for kind, mask in ((1, 0xE0), (0, 0xC0)):
            output = bytearray(b"old!")
            context = self.uds_context(
                [
                    (0, b"\x71\x02\x11\x35"),
                    (0, b"\x6e\x20\x02"),
                    (0, b"\x62\x20\x02\0\0"),
                ]
            )
            context.state["nk.chassis.abs38_cache"] = b"\xee\xff\x12\x34"
            self.assertEqual(
                self.run_export("Ex2ABS_38_VacuumFillingFlg", context, output, kind), 0
            )
            self.assertEqual(
                self.exchanged(context)[1],
                b"\x2e\x20\x02" + bytes((mask, 0x40, 0x12, 0x34)),
            )
            self.assertEqual(context.sleeps, [1000, 1000])
            self.assertNotIn(("initialize", 0), context.driver.events)
            self.assertEqual(output, b"old!")
        output = bytearray(4)
        context = self.uds_context([(0, b"\x71\x02\x11\x35"), (0, b"\x6e\x20\x02\0")])
        self.assertEqual(
            self.run_export("Ex2ABS_38_VacuumFillingFlg", context, output, 1), 1206
        )
        self.assertEqual(output, b"\x03\0\0\0")
        self.assertEqual(len(self.exchanged(context)), 2)

    def test_abs38_stop_optional_errno_and_session_error_mapping(self) -> None:
        context = self.uds_context([(17, b"")])
        self.assertEqual(
            self.run_export("Ex2ABS_38_StopTheRoutine", context, None), 1206
        )
        self.assertNotIn(("initialize", 0), context.driver.events)
        context = self.uds_context([(0, b"\x71\x02\x11\x32")])
        context.driver.sessions.append(7)
        self.assertEqual(
            self.run_export("Ex2ABS_38_StopTheRoutine", context, bytearray(4)), 1205
        )
        context = self.uds_context([])
        context.driver.sessions.append(7)
        self.assertEqual(self.run_export("Ex2ABS_38_GetSupportInfo", context, 1), 1205)
        self.assertEqual(self.exchanged(context), [])

    def test_abs38_errno_preserves_native_signed_word(self) -> None:
        output = bytearray(4)
        context = self.uds_context([(-1, b"")])
        self.assertEqual(
            self.run_export("Ex2ABS_38_StopTheRoutine", context, output), 1206
        )
        self.assertEqual(output, b"\xff" * 4)

    def test_abs38_cancellation_cleanup_and_host_deadline(self) -> None:
        context = self.uds_context([])
        context.cancelled = True
        self.assertEqual(self.run_export("Ex2ABS_38_GetSupportInfo", context, 1), 99)
        self.assertEqual(
            context.driver.events, [("session", 1, 1, False, True), ("finalize",)]
        )
        context = self.uds_context([])
        context.sleep_fault = TimeoutError("host deadline")
        with self.assertRaises(TimeoutError):
            self.run_export("Ex2ABS_38_AccumulatorZeroDown", context, bytearray(4))
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def context40(self) -> FakeContext:
        context = FakeContext([])
        context.mode = 4
        raw = b"\x21\x02\xff\xff\x22\x02\x0f\x0f".ljust(0x1020, b"\0")
        offsets = [0x1020] * 256
        offsets[0x21], offsets[0x22] = 0, 4
        context.driver.snapshots.append((0, raw, tuple(offsets)))
        return context

    def start40(self, error: int = 0) -> FakeContext:
        context = self.context40()
        self.assertEqual(self.run_export("Ex2ABS_40_GetSupportInfo", context), 0)
        context.driver.events.clear()

        def exchange(request: bytes) -> tuple[int, bytes]:
            context.driver.events.append(("exchange", request))
            return error, b"\x70" + request[1:2]

        context.driver.exchange = exchange
        return context

    def test_abs40_support_caches_exact_profile_and_checks_four_masks(self) -> None:
        context = self.context40()
        self.assertEqual(self.run_export("Ex2ABS_40_GetSupportInfo", context), 0)
        self.assertIn(("support_snapshot", 2), context.driver.events)
        self.assertEqual(context.driver.events[-1], ("finalize",))
        for offset in (2, 3, 6, 7):
            context = self.context40()
            status, raw, offsets = context.driver.snapshots.popleft()
            raw = raw[:offset] + b"\0" + raw[offset + 1 :]
            context.driver.snapshots.append((status, raw, offsets))
            self.assertEqual(self.run_export("Ex2ABS_40_GetSupportInfo", context), 1100)

    def test_abs40_stage25_executes_native_sequence_and_timing_across_tick_wrap(
        self,
    ) -> None:
        context = self.start40()
        context.clock = 0xFFFFFFF0
        stage = bytearray((25).to_bytes(4, "little"))
        stop = bytearray((1).to_bytes(4, "little"))
        self.assertEqual(
            self.run_export("Ex2ABS_40_VSCLine_AirBleeding", context, stage, stop), 0
        )
        requests = self.exchanged(context)
        self.assertEqual(int.from_bytes(stage, "little"), 26)
        self.assertEqual((context.clock - 0xFFFFFFF0) & 0xFFFFFFFF, 42000)
        for request, count in (
            (b"\x30\x22\x02\x03\x03", 3),
            (b"\x30\x22\x02\x0f\x0f", 12),
            (b"\x30\x21\x01\xff\xff", 5),
            (b"\x30\x21\x02\xff\0", 5),
            (b"\x30\x22\0\x0c\0", 1),
            (b"\x30\x22\0\x0f\0", 1),
        ):
            self.assertEqual(requests.count(request), count)
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_abs40_all_phase_errors_aggregate_and_do_not_advance_stage(self) -> None:
        context = self.start40(19)
        stage, stop = bytearray((25).to_bytes(4, "little")), bytearray(4)
        self.assertEqual(
            self.run_export("Ex2ABS_40_VSCLine_AirBleeding", context, stage, stop), 1355
        )
        self.assertEqual(int.from_bytes(stage, "little"), 25)
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_abs40_frame_codec_omits_unsupported_zero_bytes_and_rejects_nonzero(
        self,
    ) -> None:
        context = self.start40()
        key = next(iter(context.driver.support_cache))
        raw, offsets = context.driver.support_cache[key]
        raw = raw[:2] + b"\xff\0" + raw[4:]
        context.driver.support_cache[key] = (raw, offsets)
        self.assertEqual(
            chassis._command40(context, context.driver, b"\x30\x21\x02\xff\0"), 0
        )
        self.assertEqual(self.exchanged(context), [b"\x30\x21\x02\xff"])
        self.assertEqual(
            chassis._command40(context, context.driver, b"\x30\x21\x02\xff\x01"), 82
        )
        self.assertEqual(len(self.exchanged(context)), 1)

    def test_abs40_cache_uses_actual_native_target_protocol_and_allocation_status(
        self,
    ) -> None:
        for target, protocol in (((0x40, 0), 6), ((0, 0), 1)):
            context = self.start40()
            context.driver.target, context.driver.protocol = target, protocol
            with self.assertRaises(chassis.UnsupportedChassisOperation):
                self.run_export(
                    "Ex2ABS_40_VSCLine_AirBleeding",
                    context,
                    bytearray((25).to_bytes(4, "little")),
                    bytearray(4),
                )
            self.assertEqual(self.exchanged(context), [])

        for status in (80, 81):
            context = self.context40()
            context.driver.snapshots.clear()
            context.driver.snapshots.append((status, b"", ()))
            self.assertEqual(
                self.run_export("Ex2ABS_40_GetSupportInfo", context), status
            )
            self.assertIn(("configure", "native_rva:172d0", 100), context.driver.events)
            self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_abs40_missing_cache_cancel_invalid_stage_and_host_deadline(self) -> None:
        stage, stop = bytearray((25).to_bytes(4, "little")), bytearray(4)
        context = self.context40()
        with self.assertRaises(chassis.UnsupportedChassisOperation):
            self.run_export("Ex2ABS_40_VSCLine_AirBleeding", context, stage, stop)
        self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.context40()
        context.cancelled = True
        self.assertEqual(self.run_export("Ex2ABS_40_GetSupportInfo", context), 99)
        self.assertEqual(context.driver.events, [("finalize",)])
        context = self.context40()
        self.assertEqual(
            self.run_export(
                "Ex2ABS_40_VSCLine_AirBleeding", context, bytearray(4), stop
            ),
            0,
        )
        self.assertEqual(self.exchanged(context), [])
        context = self.start40()
        context.sleep_fault = TimeoutError("host deadline")
        with self.assertRaises(TimeoutError):
            self.run_export("Ex2ABS_40_VSCLine_AirBleeding", context, stage, stop)
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def replies50(self) -> list[tuple[int, bytes]]:
        result = []
        for prefix, length, bits in (
            (b"\x62\x01\x01", 8, ((5, 0x80), (7, 0x80))),
            (b"\x62\x10\0", 9, ((8, 8),)),
            (b"\x62\x10\x2d", 16, ((15, 0x40),)),
            (b"\x62\x20\0", 4, ((3, 0x40),)),
            (b"\x62\x20\x02", 7, ((3, 0x80), (4, 0xAB), (5, 0x12), (6, 0x34))),
            (b"\x71\x01\x10\x01", 7, ((6, 0x40),)),
            (b"\x71\x01\x11\0", 18, ((10, 8), (16, 4), (17, 0x80))),
        ):
            reply = bytearray(prefix).ljust(length, b"\0")
            for position, mask in bits:
                reply[position] = mask
            result.append((0, bytes(reply)))
        return result

    def test_abs50_support_queries_masks_and_retained_reset_payload(self) -> None:
        context = self.uds_context(self.replies50())
        self.assertEqual(self.run_export("Ex2ABS_50_ConfSupportInfo", context), 0)
        self.assertEqual(context.state["nk.chassis.abs50_cache"], b"\x80\xab\x12\x34")
        self.assertEqual(len(self.exchanged(context)), 7)
        for index, position in (
            (0, 5),
            (0, 7),
            (1, 8),
            (2, 15),
            (3, 3),
            (4, 3),
            (5, 6),
            (6, 10),
            (6, 16),
            (6, 17),
        ):
            replies = self.replies50()
            reply = bytearray(replies[index][1])
            reply[position] = 0
            replies[index] = 0, bytes(reply)
            context = self.uds_context(replies)
            self.assertEqual(
                self.run_export("Ex2ABS_50_ConfSupportInfo", context), 0x11F9
            )
            self.assertEqual(len(self.exchanged(context)), index + 1)
            self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.uds_context([])
        context.driver.init_status = 17
        self.assertEqual(self.run_export("Ex2ABS_50_ConfSupportInfo", context), 0x11FF)
        context = self.uds_context([])
        context.driver.sessions.append(7)
        self.assertEqual(self.run_export("Ex2ABS_50_ConfSupportInfo", context), 0x11F8)

    def test_abs50_rear_ecb_steps_retain_native_success_and_mutate_stage(self) -> None:
        for operation, reply, expected, delay in (
            ("RearAirBleeding", b"\x71\x01\x11\x69", 0x125D, [1000]),
            ("RearAirBleeding_Next_1", b"\x71\x02\x11\x69", 0x125E, []),
            ("RearAirBleeding_Next_2", b"\x71\x01\x11\x69", 0x125F, [20000, 1000]),
            ("ECBProhibitionControl", b"\x71\x01\x11\x35", 0, [1000]),
            ("ECBProhibitionControl_Next", b"\x71\x02\x11\x35", 0x125C, []),
        ):
            context = self.uds_context([(0, reply)])
            output = bytearray(4)
            arguments = (output,) if operation == "RearAirBleeding" else ()
            self.assertEqual(
                self.run_export("Ex2ABS_50_" + operation, context, *arguments), expected
            )
            self.assertEqual(context.sleeps, delay)
            self.assertNotIn(("finalize",), context.driver.events)
            if arguments:
                self.assertEqual(output, b"\x04\0\0\0")
            else:
                self.assertNotIn(("initialize", 0), context.driver.events)

    def test_abs50_step_failures_cleanup_and_native_retained_status_branch(
        self,
    ) -> None:
        for operation, retained, stop in (
            ("RearAirBleeding", 0x125D, b"\x31\x02\x11\x69"),
            ("RearAirBleeding_Next_1", 0x125E, None),
            ("RearAirBleeding_Next_2", 0x125F, b"\x31\x02\x11\x69"),
            ("ECBProhibitionControl_Next", 0x125C, None),
        ):
            for status in (17, retained):
                context = self.uds_context(
                    [(status, b"")] + ([(19, b"")] if stop else [])
                )
                arguments = (bytearray(4),) if operation == "RearAirBleeding" else ()
                self.assertEqual(
                    self.run_export("Ex2ABS_50_" + operation, context, *arguments),
                    status,
                )
                self.assertEqual(
                    ("finalize",) in context.driver.events, status != retained
                )
                if stop:
                    self.assertEqual(self.exchanged(context)[-1], stop)

    def test_abs50_slm_poll_completion_timeout_and_wire_fault_mapping(self) -> None:
        busy = b"\x62\x10\x2d" + bytes(13) + b"\x40"
        ready = busy[:-1] + b"\0"
        context = self.uds_context([(0, b"\x71\x01\x11\x66"), (0, busy), (0, ready)])
        self.assertEqual(self.run_export("Ex2ABS_50_SLM2Refresh", context), 0)
        self.assertEqual(context.sleeps, [1000, 1000])
        self.assertEqual(self.exchanged(context)[0], b"\x31\x01\x11\x66\x02")
        self.assertNotIn(("finalize",), context.driver.events)
        context = self.uds_context([(0, b"\x71\x01\x11\x66")] + [(0, busy)] * 30)
        context.clock = 0xFFFFF000
        self.assertEqual(self.run_export("Ex2ABS_50_SLM2Refresh", context), 0x11FB)
        self.assertEqual(len(context.sleeps), 30)
        context = self.uds_context([(17, b""), (19, b"")])
        self.assertEqual(self.run_export("Ex2ABS_50_SLM2Refresh", context), 0x11FA)
        self.assertEqual(self.exchanged(context)[-1], b"\x31\x02\x11\x66")
        context = self.uds_context([(0, b"\x71\x01\x11\x66"), (17, b"")])
        self.assertEqual(self.run_export("Ex2ABS_50_SLM2Refresh", context), 0x11FE)

    def test_abs50_cached_reset_exact_echo_and_verification_flag(self) -> None:
        for flag, expected in ((0, 0), (0x80, 0x11FC)):
            context = self.uds_context(
                [(0, b"\x6e\x20\x02"), (0, b"\x62\x20\x02\0" + bytes((flag,)))]
            )
            context.state["nk.chassis.abs50_cache"] = b"\x80\xab\x12\x34"
            self.assertEqual(
                self.run_export("Ex2ABS_50_VacuumFillingIncompleteFlagReset", context),
                expected,
            )
            self.assertEqual(self.exchanged(context)[0], b"\x2e\x20\x02\x80\0\x12\x34")
            self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.uds_context([(0, b"\x6e\x20\x02\0")])
        self.assertEqual(
            self.run_export("Ex2ABS_50_VacuumFillingIncompleteFlagReset", context), 3
        )
        self.assertEqual(context.sleeps, [])

    def test_abs50_plus_mode22_uses_distinct_manager_and_refreshes_vacuum_cache(
        self,
    ) -> None:
        blob = b"authored Plus mode22 ABS50"
        digest = hashlib.sha256(blob).hexdigest()
        with patch.object(chassis, "NK_GTS_SHA256", digest):
            context = self.uds_context(
                [
                    (0, b"\x62\x20\x02\x80\xab\x12\x34"),
                    (0, b"\x6e\x20\x02"),
                    (0, b"\x62\x20\x02\0\0"),
                ]
            )
            context.module_bytes, context.module_sha256, context.mode = blob, digest, 22
            context.state["nk.chassis.abs50_cache"] = b"old cached classic payload"
            self.assertEqual(
                self.run_export("Ex2ABS_50_VacuumFillingIncompleteFlagReset", context),
                0,
            )
            self.assertEqual(context.kinds, ["native:101c6da0"])
            self.assertEqual(
                self.exchanged(context),
                [b"\x22\x20\x02", b"\x2e\x20\x02\x80\0\x12\x34", b"\x22\x20\x02"],
            )
            self.assertEqual(
                context.state["nk.chassis.abs50_cache22"], b"\x80\xab\x12\x34"
            )
            context = self.uds_context([])
            context.module_bytes, context.module_sha256, context.mode = blob, digest, 22
            self.assertEqual(self.run_export("Ex2ABS_50_ConfSupportInfo", context), 99)
            self.assertEqual(context.kinds, [])
            context = self.uds_context([(0, b"\x71\x02\x11\x35")])
            context.module_bytes, context.module_sha256, context.mode = blob, digest, 22
            self.assertEqual(
                self.run_export("Ex2ABS_50_ECBProhibitionControl_Next", context), 0x125C
            )
            self.assertEqual(context.kinds, ["native:101c6da0"])
        context = self.uds_context([])
        context.mode = 22
        self.assertEqual(
            self.run_export("Ex2ABS_50_ECBProhibitionControl", context), 99
        )
        self.assertEqual(context.kinds, [])

    def test_abs50_timeout_end_and_cancellation_cleanup_contracts(self) -> None:
        context = self.uds_context([(17, b"")])
        self.assertEqual(
            self.run_export("Ex2ABS_50_RearAirBleeding_Timeout", context), 0x11FD
        )
        self.assertNotIn(("finalize",), context.driver.events)
        context = self.uds_context([])
        context.cancelled = True
        self.assertEqual(
            self.run_export("Ex2ABS_50_EndExtendedSession", context), 0x11F8
        )
        self.assertEqual(context.driver.events, [("finalize",)])
        context = self.uds_context([])
        context.cancelled = True
        self.assertEqual(self.run_export("Ex2ABS_50_ConfSupportInfo", context), 99)
        self.assertEqual(
            context.driver.events, [("session", 1, 1, False, True), ("finalize",)]
        )
        context = self.uds_context([(0, b"\x71\x01\x11\x66")])
        context.sleep_fault = TimeoutError("host deadline")
        with self.assertRaises(TimeoutError):
            self.run_export("Ex2ABS_50_SLM2Refresh", context)
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def context14(self) -> FakeContext:
        context = FakeContext([])
        context.mode = 4
        raw = (
            b"\x21\x05\xaa\xaa\x01\0\x02\x22\x05\x03\x03\0\x01\x01\x03\x03\x02\x02\x01"
        )
        offsets = [0x1020] * 256
        offsets[0x21], offsets[0x22], offsets[3] = 0, 7, 14
        context.driver.snapshots.append((0, raw.ljust(0x1020, b"\0"), tuple(offsets)))
        return context

    def test_smrt42_public_busy_wrapper_overwrite_reads_after_initialize(self) -> None:
        from scripts.utility_ex import UtilityExContext, UtilityExEngine
        from scripts.utility_ex_comm import SHA_18_NK

        images = (
            (
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityExNK2.dll",
                0x1014A640,
            ),
            (
                "artifacts/extracted/techstream-12-application/Techstream_Bin/UtilityExNK2.dll",
                0x100E5C90,
            ),
            (
                "artifacts/extracted/gtsplus-application/Setup_PF/DS4/bin/UtilityExNK2_DS4.dll",
                0x101B18C8,
            ),
            (
                "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityExNK2.dll",
                0x101BC9C8,
            ),
        )
        require_private(*(path for path, _ in images))
        with patch.object(chassis, "NK18_SHA256", SHA_18_NK):
            for path, base in images:
                with self.subTest(source=path):
                    host = Mock()
                    host.get_parameter.side_effect = lambda key: 4 if key == 0x6F else 0
                    host.ticks.return_value = 1000
                    context = UtilityExContext(
                        Path(path).read_bytes(), host, None, None
                    )
                    engine = UtilityExEngine(context)
                    fixture = self.context42([(0, b"\x61\xd1\0\0\x30\x20")])
                    driver = fixture.driver
                    entered, release, done = (
                        threading.Event(),
                        threading.Event(),
                        threading.Event(),
                    )

                    def initialize(
                        entered: threading.Event = entered,
                        release: threading.Event = release,
                    ) -> int:
                        entered.set()
                        if not release.wait(2):
                            raise TimeoutError(
                                "Authored initialization release missing"
                            )
                        return 0

                    old, replacement, retained = (
                        bytearray(b"A"),
                        bytearray(b"B"),
                        bytearray(b"C"),
                    )
                    with (
                        patch.object(UtilityExContext, "comm", return_value=driver),
                        patch.object(driver, "initialize", side_effect=initialize),
                        patch.object(driver, "finalize", side_effect=done.set),
                    ):
                        context._parameters[0x6F] = 3
                        self.assertEqual(
                            engine.invoke("Ex2SMRT_42_GetKeyStatus", (11, retained)), 99
                        )
                        context._parameters[0x6F] = 4
                        try:
                            self.assertEqual(
                                engine.invoke("Ex2SMRT_42_GetKeyNum", (old, 12)), 15
                            )
                            self.assertTrue(entered.wait(2))
                            self.assertEqual(
                                engine.invoke(
                                    "Ex2SMRT_42_GetKeyNum", (replacement, 11)
                                ),
                                16,
                            )
                        finally:
                            release.set()
                        self.assertTrue(done.wait(2))
                        self.assertEqual(engine.worker.get_status(), 0)
                    self.assertEqual(
                        (old, replacement, retained), (b"A", b"\x02", b"\x03")
                    )
                    self.assertIs(
                        context.state[f"native_global:{base:08x}"], replacement
                    )
                    self.assertIs(
                        context.state[f"native_global:{base + 4:08x}"], retained
                    )

    def test_smrt50_63_public_direct_thread_contracts_all_three_sources(self) -> None:
        from scripts.utility_ex import UtilityExContext, UtilityExEngine
        from scripts.utility_ex_comm import SHA_18_NK

        sources = [
            (
                "NK18_SHA256",
                SHA_18_NK,
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityExNK2.dll",
            ),
            (
                "NK_DS4_SHA256",
                chassis.NK_DS4_SHA256,
                "artifacts/extracted/gtsplus-application/Setup_PF/DS4/bin/UtilityExNK2_DS4.dll",
            ),
            (
                "NK_GTS_SHA256",
                chassis.NK_GTS_SHA256,
                "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityExNK2.dll",
            ),
        ]
        require_private(*(path for _, _, path in sources))
        for constant, digest, path in sources:
            for family in (50, 63):
                with (
                    self.subTest(source=constant, family=family),
                    patch.object(chassis, constant, digest),
                ):
                    host = Mock()
                    host.get_parameter.side_effect = lambda key: (
                        20 if key == 0x6F else 0
                    )
                    host.ticks.return_value = 1000
                    context = UtilityExContext(
                        Path(path).read_bytes(), host, None, None
                    )
                    engine = UtilityExEngine(context)
                    reply = bytearray(b"b\x11\1" + bytes(21))
                    reply[9] = 1
                    driver = FakeComm([(0, b"q\1\x16\3"), (0, bytes(reply))])
                    with patch.object(UtilityExContext, "comm", return_value=driver):
                        self.assertEqual(
                            engine.invoke(f"Ex2SMRT_{family}_StartKeepAlive"), 0
                        )
                        self.assertEqual(
                            engine.invoke(f"Ex2SMRT_{family}_StartKeyErasure"), 15
                        )
                        self.assertEqual(engine.worker.get_status(), 0)
                        self.assertFalse(any(e[0] == "finalize" for e in driver.events))
                        self.assertEqual(
                            engine.invoke(
                                "Ex2SMRT_50_KeyCodeReset"
                                if family == 50
                                else "Ex2SMRT_63_GetKeyStatus",
                                () if family == 50 else (bytearray(4),),
                            ),
                            15,
                        )
                        self.assertEqual(
                            engine.worker.get_status(), 5001 if family == 50 else 6301
                        )
                        self.assertEqual(
                            engine.invoke(f"Ex2SMRT_{family}_EndExtendSession"), 0
                        )
                    self.assertFalse(driver.replies)
                    self.assertEqual(sum(e[0] == "finalize" for e in driver.events), 2)

    def test_smrt53_public_worker_captures_before_busy_wrapper_overwrite(self) -> None:
        from scripts.utility_ex import UtilityExContext, UtilityExEngine
        from scripts.utility_ex_comm import SHA_18_NK

        sources = [
            (
                "NK18_SHA256",
                SHA_18_NK,
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityExNK2.dll",
            ),
            (
                "NK_DS4_SHA256",
                chassis.NK_DS4_SHA256,
                "artifacts/extracted/gtsplus-application/Setup_PF/DS4/bin/UtilityExNK2_DS4.dll",
            ),
            (
                "NK_GTS_SHA256",
                chassis.NK_GTS_SHA256,
                "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityExNK2.dll",
            ),
        ]
        require_private(*(path for _, _, path in sources))
        for constant, digest, path in sources:
            with self.subTest(source=constant), patch.object(chassis, constant, digest):
                host = Mock()
                host.get_parameter.side_effect = lambda key: 20 if key == 0x6F else 0
                host.ticks.return_value = 1000
                context = UtilityExContext(Path(path).read_bytes(), host, None, None)
                engine = UtilityExEngine(context)
                driver = FakeComm(
                    self.good53()
                    + [(0, b"b\xf1\x8c" + bytes(10) + b"12345678"), (0, b"g\x09ABCDEF")]
                )
                first = (bytearray(4), 1, bytearray(8), bytearray(6), 0x1C2)
                replacement = (bytearray(4), 0, bytearray(8), bytearray(6), 0)
                entered, release = threading.Event(), threading.Event()

                def initialize(
                    entered: threading.Event = entered,
                    release: threading.Event = release,
                ) -> int:
                    entered.set()
                    if not release.wait(2):
                        raise TimeoutError("53 initialize release missing")
                    return 0

                with (
                    patch.object(UtilityExContext, "comm", return_value=driver),
                    patch.object(driver, "initialize", side_effect=initialize),
                ):
                    context._parameters[0x6F] = 3
                    self.assertEqual(
                        engine.invoke("Ex2SMRT_53_Online_Certification", replacement),
                        99,
                    )
                    base, _ = chassis._fields53(context, "Online_Certification")
                    self.assertIs(
                        context.state[f"native_global:{base:08x}"], replacement[0]
                    )
                    context._parameters[0x6F] = 20
                    try:
                        self.assertEqual(
                            engine.invoke("Ex2SMRT_53_Online_Certification", first), 15
                        )
                        self.assertTrue(entered.wait(2))
                        self.assertEqual(
                            engine.invoke(
                                "Ex2SMRT_53_Online_Certification", replacement
                            ),
                            16,
                        )
                    finally:
                        release.set()
                    self.assertEqual(engine.worker.get_status(), 0)
                self.assertEqual((first[2], first[3]), (b"12345678", b"ABCDEF"))
                self.assertEqual((replacement[2], replacement[3]), (bytes(8), bytes(6)))
                self.assertFalse(
                    any(e[0] in ("finalize", "configure_target") for e in driver.events)
                )

    def test_smrt56_58_public_workers_three_exact_sources(self) -> None:
        from scripts.utility_ex import UtilityExContext, UtilityExEngine
        from scripts.utility_ex_comm import SHA_18_NK

        sources = [
            (
                "NK18_SHA256",
                SHA_18_NK,
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityExNK2.dll",
            ),
            (
                "NK_DS4_SHA256",
                chassis.NK_DS4_SHA256,
                "artifacts/extracted/gtsplus-application/Setup_PF/DS4/bin/UtilityExNK2_DS4.dll",
            ),
            (
                "NK_GTS_SHA256",
                chassis.NK_GTS_SHA256,
                "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityExNK2.dll",
            ),
        ]
        require_private(*(path for _, _, path in sources))
        for constant, digest, path in sources:
            with self.subTest(source=constant), patch.object(chassis, constant, digest):
                host = Mock()
                host.get_parameter.side_effect = lambda key: 20 if key == 0x6F else 0
                host.ticks.return_value = 1000
                context = UtilityExContext(Path(path).read_bytes(), host, None, None)
                engine = UtilityExEngine(context)
                driver = FakeComm(
                    [
                        (0, b"q\x01\x17\1"),
                        (0, b"q\x02\x17\1"),
                        (0, b"q\x01\x13\x05"),
                        (0, b"q\x03\x13\x05\2"),
                    ]
                )
                with patch.object(UtilityExContext, "comm", return_value=driver):
                    self.assertEqual(
                        engine.invoke("Ex2SMRT_56_StartFingerprintMode"), 15
                    )
                    self.assertEqual(engine.worker.get_status(), 0)
                    self.assertFalse(any(e[0] == "finalize" for e in driver.events))
                    self.assertEqual(
                        engine.invoke("Ex2SMRT_56_TerminateFingerprintMode"), 15
                    )
                    self.assertEqual(engine.worker.get_status(), 6005)
                    # Source wait uses hostclock, so this authored host advances50 per tick.
                    host.ticks.side_effect = iter(range(1000, 100000, 50))
                    self.assertEqual(engine.invoke("Ex2SMRT_58_StartIFBOXComIDReg"), 15)
                    self.assertEqual(engine.worker.get_status(), 0)
                self.assertFalse(driver.replies)
                self.assertEqual(sum(e[0] == "finalize" for e in driver.events), 2)

    def test_smrt48_public_argument_dispatch_three_exact_sources(self) -> None:
        from scripts.utility_ex import UtilityExContext, UtilityExEngine
        from scripts.utility_ex_comm import SHA_18_NK

        sources = [
            (
                "NK18_SHA256",
                SHA_18_NK,
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityExNK2.dll",
            ),
            (
                "NK_DS4_SHA256",
                chassis.NK_DS4_SHA256,
                "artifacts/extracted/gtsplus-application/Setup_PF/DS4/bin/UtilityExNK2_DS4.dll",
            ),
            (
                "NK_GTS_SHA256",
                chassis.NK_GTS_SHA256,
                "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityExNK2.dll",
            ),
        ]
        require_private(*(path for _, _, path in sources))
        for constant, digest, path in sources:
            for selector in (4, 20):
                with (
                    self.subTest(source=constant, selector=selector),
                    patch.object(chassis, constant, digest),
                ):
                    host = Mock()
                    host.get_parameter.side_effect = lambda key: 3 if key == 0x6F else 0
                    host.ticks.return_value = 1000
                    host.set_parameter.return_value = 0
                    host.write_parameters.return_value = 0
                    context = UtilityExContext(
                        Path(path).read_bytes(), host, None, None
                    )
                    engine = UtilityExEngine(context)
                    driver = FakeComm(
                        [(0, b"~" if selector == 4 else b"~\0"), (0, b"I\x02\x01VIN")]
                    )
                    out = bytearray(b"x" * 17)
                    with patch.object(UtilityExContext, "comm", return_value=driver):
                        self.assertEqual(
                            engine.invoke("Ex2SMRT_48_ReadVINCode", (3, None)), 99
                        )
                        self.assertEqual(
                            engine.invoke("Ex2SMRT_48_ReadVINCode", (selector, out)), 15
                        )
                        self.assertEqual(engine.worker.get_status(), 4802)
                    self.assertEqual(context.mode, 3)
                    self.assertEqual(out, b"VIN" + b"x" * 14)
                    self.assertEqual(
                        [e[1] for e in driver.events if e[0] == "exchange"],
                        [b">" if selector == 4 else b">\0", b"\x09\x02"],
                    )

    def test_smrt46_47_public_worker_three_exact_source_variants(self) -> None:
        from scripts.utility_ex import UtilityExContext, UtilityExEngine
        from scripts.utility_ex_comm import SHA_18_NK

        sources = [
            (
                "NK18_SHA256",
                SHA_18_NK,
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityExNK2.dll",
            ),
            (
                "NK_DS4_SHA256",
                chassis.NK_DS4_SHA256,
                "artifacts/extracted/gtsplus-application/Setup_PF/DS4/bin/UtilityExNK2_DS4.dll",
            ),
            (
                "NK_GTS_SHA256",
                chassis.NK_GTS_SHA256,
                "artifacts/extracted/gtsplus-application/Setup_PF/GTSPlus/bin/UtilityExNK2.dll",
            ),
        ]
        require_private(*(path for _, _, path in sources))
        for family in (46, 47):
            for constant, digest, path in sources:
                with (
                    self.subTest(family=family, source=constant),
                    patch.object(chassis, constant, digest),
                ):
                    host = Mock()
                    host.get_parameter.side_effect = lambda key: 4 if key == 0x6F else 0
                    host.ticks.return_value = 1000
                    context = UtilityExContext(
                        Path(path).read_bytes(), host, None, None
                    )
                    engine = UtilityExEngine(context)
                    fixture = (self.context46 if family == 46 else self.context47)(
                        [(0, b"\x61\xd1\0\x40\0")]
                    )
                    done = threading.Event()
                    with (
                        patch.object(
                            UtilityExContext, "comm", return_value=fixture.driver
                        ),
                        patch.object(fixture.driver, "finalize", side_effect=done.set),
                    ):
                        export = (
                            "Ex2SMRT_46_GetKeyStatus"
                            if family == 46
                            else "Ex2SMRT_47_GetKeyStatus_NomalChk"
                        )
                        self.assertEqual(engine.invoke(export, (1,)), 15)
                        self.assertTrue(done.wait(2))
                        self.assertEqual(engine.worker.get_status(), 0)
                    self.assertEqual(
                        [e[1] for e in fixture.driver.events if e[0] == "exchange"],
                        [b"\x21\xd1"],
                    )

    def test_smrt45_public_busy_wrapper_preserves_progress_read_points(self) -> None:
        from scripts.utility_ex import UtilityExContext, UtilityExEngine
        from scripts.utility_ex_comm import SHA_18_NK

        path = Path(
            "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityExNK2.dll"
        )
        require_private(path)
        host = Mock()
        host.get_parameter.side_effect = lambda key: 4 if key == 0x6F else 0
        host.ticks.return_value = 1000
        context = UtilityExContext(path.read_bytes(), host, None, None)
        engine = UtilityExEngine(context)
        fixture = self.context45([(0, b"\x7b\x87"), (0, b"\x61\xd1\0\x40\0")])
        driver = fixture.driver
        first, second = bytearray(4), bytearray(4)
        entered, release, done = threading.Event(), threading.Event(), threading.Event()

        def initialize() -> int:
            entered.set()
            if not release.wait(2):
                raise TimeoutError("Authored initialization release missing")
            return 0

        with (
            patch.object(chassis, "NK18_SHA256", SHA_18_NK),
            patch.object(UtilityExContext, "comm", return_value=driver),
            patch.object(driver, "initialize", side_effect=initialize),
            patch.object(driver, "finalize", side_effect=done.set),
        ):
            try:
                self.assertEqual(
                    engine.invoke(
                        "Ex2SMRT_45_StartOwnersKeyReg",
                        (b"old1", b"old3", 4, 4, 0, first),
                    ),
                    15,
                )
                self.assertTrue(entered.wait(2))
                self.assertEqual(
                    engine.invoke(
                        "Ex2SMRT_45_StartOwnersKeyReg", (b"", b"", 0, 0, 0, second)
                    ),
                    16,
                )
            finally:
                release.set()
            self.assertTrue(done.wait(2))
            self.assertEqual(engine.worker.get_status(), 4503)
        self.assertEqual(first, (450).to_bytes(4, "little"))
        self.assertEqual(second, (451).to_bytes(4, "little"))
        self.assertEqual(driver.appended[-2:], [(b"", 1), (b"", 3)])

    def context47(self, replies: list[tuple[int, bytes]]) -> FakeContext:
        context = self.context45(replies)
        context.driver.support_cache.pop((0, 0, 6, 3))
        context.driver.append_support_profile(b"\x87\x06\x20" + bytes(5), 3)
        return context

    def test_smrt47_query_modes_and_error_bit_priority(self) -> None:
        for mode, data in (
            (1, b"\0\x40\0"),
            (2, b"\0\0\0"),
            (3, b"\x08\0\0"),
            (4, b"\0\0\0"),
            (0, b"\0\0\0"),
        ):
            context = self.context47([(0, b"\x61\xd1" + data)])
            self.assertEqual(
                self.run_export("Ex2SMRT_47_GetKeyStatus_NomalChk", context, mode), 0
            )
            self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.context47([(0, b"\x61\xd1\x08\x40\x10"), (17, b"")])
        self.assertEqual(
            self.run_export("Ex2SMRT_47_GetKeyStatus_NomalChk", context, 1), 4702
        )
        self.assertEqual(self.exchanged(context)[-1], b"\x3b\x87" + bytes(6))

    def test_smrt47_timeout_modes_and_only4706_avoids_stop(self) -> None:
        for mode, data, expected in (
            (1, b"\0\0\0", 4703),
            (2, b"\0\x40\0", 4706),
            (3, b"\0\0\0", 4704),
            (4, b"\x08\0\0", 4705),
        ):
            context = self.context47([(0, b"\x61\xd1" + data), (17, b"")])
            original = context.driver.exchange

            def exchange(
                request: bytes,
                context: FakeContext = context,
                original: Callable[[bytes], tuple[int, bytes]] = original,
            ) -> tuple[int, bytes]:
                if request == b"\x21\xd1":
                    context.clock += 30000
                return original(request)

            with patch.object(context.driver, "exchange", side_effect=exchange):
                self.assertEqual(
                    self.run_export("Ex2SMRT_47_GetKeyStatus_NomalChk", context, mode),
                    expected,
                )
            self.assertEqual(len(self.exchanged(context)), 1 if expected == 4706 else 2)

    def test_smrt47_mode2_cancel_inside_reply_skips_error_and_stop(self) -> None:
        context = self.context47([])

        def exchange(request: bytes) -> tuple[int, bytes]:
            context.cancelled = True
            return 0, b"\x61\xd1\0\0\x10"

        with patch.object(context.driver, "exchange", side_effect=exchange):
            self.assertEqual(
                self.run_export("Ex2SMRT_47_GetKeyStatus_NomalChk", context, 2), 4701
            )
        self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.context47([])
        context.cancelled = True
        self.assertEqual(
            self.run_export("Ex2SMRT_47_GetKeyStatus_NomalChk", context, 1), 99
        )
        self.assertEqual(self.exchanged(context), [])

    def test_smrt47_registration_two_modes_and_stop_after_precancel(self) -> None:
        context = self.context47(
            [(0, b"\x61\xd1\x08\0\0"), (0, b"\x61\xd1\0\0\0"), (27, b"")]
        )
        self.assertEqual(
            self.run_export("Ex2SMRT_47_GetKeyStatus_RegistrationChk", context), 0
        )
        self.assertEqual(context.state["native_global:1014a59c"], 4)
        self.assertEqual(
            self.exchanged(context), [b"\x21\xd1", b"\x21\xd1", b"\x3b\x87" + bytes(6)]
        )
        context = self.context47([(17, b"")])
        context.cancelled = True
        self.assertEqual(
            self.run_export("Ex2SMRT_47_GetKeyStatus_RegistrationChk", context), 99
        )
        self.assertEqual(self.exchanged(context), [b"\x3b\x87" + bytes(6)])
        context = self.context47([])
        context.driver.init_status = 17
        self.assertEqual(
            self.run_export("Ex2SMRT_47_GetKeyStatus_RegistrationChk", context), 17
        )
        self.assertEqual(self.exchanged(context), [])

    def test_smrt47_check_maps_request_failure_and_stops_poll_failure(self) -> None:
        for reply, expected, count in ((b"\x7b\x87\0", 4700, 1), (b"\x7b\x87", 3, 3)):
            context = self.context47([(0, reply), (0, b"\x61\xd2"), (17, b"")])
            self.assertEqual(
                self.run_export(
                    "Ex2SMRT_47_KeyCodeChk", context, 123, 1, b"", b"", 0, 0
                ),
                expected,
            )
            self.assertEqual(self.exchanged(context)[0], b"\x3b\x87\x20" + bytes(5))
            self.assertEqual(len(self.exchanged(context)), count)
        context = self.context47([(0, b"\x7b\x87"), (0, b"\x61\xd1\0\x40\0")])
        self.assertEqual(
            self.run_export("Ex2SMRT_47_KeyCodeChk", context, 0, 1, None, None, 0, 0), 0
        )
        self.assertEqual(context.driver.appended[-2:], [(b"", 1), (b"", 3)])

    def test_smrt47_support_mask20_native99_and_unconditional_set(self) -> None:
        for mask, expected in ((0x20, 0), (0x40, 99)):
            context = self.context47([])
            context.driver.support_cache.pop((0, 0, 6, 3))
            context.driver.append_support_profile(bytes((0x87, 6, mask)) + bytes(5), 3)
            for kind in (1, 3):
                snapshot = context.driver.cached_support(kind)
                assert snapshot is not None
                context.driver.snapshots.append((0, *snapshot))
            output = bytearray(b"KEEP")
            self.assertEqual(
                self.run_export(
                    "Ex2SMRT_47_GetSupportInfo",
                    context,
                    bytearray(20),
                    bytearray(20),
                    bytearray(4),
                    output,
                ),
                expected,
            )
            self.assertEqual(
                output, (8).to_bytes(4, "little") if expected == 0 else b"KEEP"
            )
        context = self.context47([])
        context.driver.init_status = 17
        self.assertEqual(
            self.run_export("Ex2SMRT_47_SetSupportInfo", context, b"ab", b"cd", 2, 1),
            17,
        )
        self.assertEqual(context.driver.appended[-2:], [(b"ab", 1), (b"c", 3)])

    def test_smrt47_stop_init_error14_ignored_reply_and_host_cleanup(self) -> None:
        context = self.context47([])
        context.driver.init_status = 17
        self.assertEqual(self.run_export("Ex2SMRT_47_StopKeyCodeReset", context), 14)
        context = self.context47([(27, b"")])
        self.assertEqual(self.run_export("Ex2SMRT_47_StopKeyCodeReset", context), 0)
        context = self.context47([])
        context.driver.fault = OSError("authored host fault")
        with self.assertRaises(OSError):
            self.run_export("Ex2SMRT_47_StopKeyCodeReset", context)
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_smrt47_three_source_shared_offsets_and_nk12_absence(self) -> None:
        self.assertNotIn(
            "Ex2SMRT_47_GetSupportInfo", chassis.supported_exports(chassis.NK12_SHA256)
        )
        for constant, base in (
            ("NK18_SHA256", 0x1014A598),
            ("NK_DS4_SHA256", 0x101B1944),
            ("NK_GTS_SHA256", 0x101BCA44),
        ):
            blob = ("authored SMRT47 " + constant).encode()
            digest = hashlib.sha256(blob).hexdigest()
            with patch.object(chassis, constant, digest):
                context = self.context47([(0, b"\x61\xd1\0\x40\0")])
                context.module_bytes, context.module_sha256 = blob, digest
                self.assertEqual(
                    self.run_export("Ex2SMRT_47_GetKeyStatus_NomalChk", context, 1), 0
                )
                self.assertEqual(context.state[f"native_global:{base + 4:08x}"], 1)

    def context46(self, replies: list[tuple[int, bytes]]) -> FakeContext:
        context = self.context45(replies)
        context.driver.support_cache.pop((0, 0, 6, 3))
        context.driver.append_support_profile(b"\x87\x06\x40" + bytes(5), 3)
        return context

    def test_smrt46_query_modes_and_error_bit_priority(self) -> None:
        for mode, data in (
            (1, b"\0\x40\0"),
            (2, b"\0\0\0"),
            (3, b"\x08\0\0"),
            (4, b"\0\0\0"),
            (0, b"\0\0\0"),
        ):
            context = self.context46([(0, b"\x61\xd1" + data)])
            self.assertEqual(
                self.run_export("Ex2SMRT_46_GetKeyStatus", context, mode), 0
            )
            self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.context46([(0, b"\x61\xd1\x08\x40\x10"), (17, b"")])
        self.assertEqual(self.run_export("Ex2SMRT_46_GetKeyStatus", context, 1), 4602)
        self.assertEqual(self.exchanged(context)[-1], b"\x3b\x87" + bytes(6))

    def test_smrt46_timeout_modes_and_only4606_avoids_stop(self) -> None:
        for mode, data, expected in (
            (1, b"\0\0\0", 4603),
            (2, b"\0\x40\0", 4606),
            (3, b"\0\0\0", 4604),
            (4, b"\x08\0\0", 4605),
        ):
            context = self.context46([(0, b"\x61\xd1" + data), (17, b"")])
            original = context.driver.exchange

            def exchange(
                request: bytes,
                context: FakeContext = context,
                original: Callable[[bytes], tuple[int, bytes]] = original,
            ) -> tuple[int, bytes]:
                if request == b"\x21\xd1":
                    context.clock += 30000
                return original(request)

            with patch.object(context.driver, "exchange", side_effect=exchange):
                self.assertEqual(
                    self.run_export("Ex2SMRT_46_GetKeyStatus", context, mode), expected
                )
            self.assertEqual(len(self.exchanged(context)), 1 if expected == 4606 else 2)

    def test_smrt46_mode2_cancel_inside_reply_skips_error_and_stop(self) -> None:
        context = self.context46([])

        def exchange(request: bytes) -> tuple[int, bytes]:
            context.cancelled = True
            return 0, b"\x61\xd1\0\0\x10"

        with patch.object(context.driver, "exchange", side_effect=exchange):
            self.assertEqual(
                self.run_export("Ex2SMRT_46_GetKeyStatus", context, 2), 4601
            )
        self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.context46([])
        context.cancelled = True
        self.assertEqual(self.run_export("Ex2SMRT_46_GetKeyStatus", context, 1), 99)
        self.assertEqual(self.exchanged(context), [])

    def test_smrt46_registration_two_modes_and_stop_after_precancel(self) -> None:
        context = self.context46(
            [(0, b"\x61\xd1\x08\0\0"), (0, b"\x61\xd1\0\0\0"), (27, b"")]
        )
        self.assertEqual(
            self.run_export("Ex2SMRT_46_GetKeyStatus_RegistrationChk", context), 0
        )
        self.assertEqual(context.state["native_global:1014a6bc"], 4)
        self.assertEqual(
            self.exchanged(context), [b"\x21\xd1", b"\x21\xd1", b"\x3b\x87" + bytes(6)]
        )
        context = self.context46([(17, b"")])
        context.cancelled = True
        self.assertEqual(
            self.run_export("Ex2SMRT_46_GetKeyStatus_RegistrationChk", context), 99
        )
        self.assertEqual(self.exchanged(context), [b"\x3b\x87" + bytes(6)])
        context = self.context46([])
        context.driver.init_status = 17
        self.assertEqual(
            self.run_export("Ex2SMRT_46_GetKeyStatus_RegistrationChk", context), 17
        )
        self.assertEqual(self.exchanged(context), [])

    def test_smrt46_check_maps_request_failure_and_stops_poll_failure(self) -> None:
        for reply, expected, count in ((b"\x7b\x87\0", 4600, 1), (b"\x7b\x87", 3, 3)):
            context = self.context46([(0, reply), (0, b"\x61\xd2"), (17, b"")])
            self.assertEqual(
                self.run_export(
                    "Ex2SMRT_46_KeyCodeChk", context, 123, 1, b"", b"", 0, 0
                ),
                expected,
            )
            self.assertEqual(self.exchanged(context)[0], b"\x3b\x87\x40" + bytes(5))
            self.assertEqual(len(self.exchanged(context)), count)
        context = self.context46([(0, b"\x7b\x87"), (0, b"\x61\xd1\0\x40\0")])
        self.assertEqual(
            self.run_export("Ex2SMRT_46_KeyCodeChk", context, 0, 1, None, None, 0, 0), 0
        )
        self.assertEqual(context.driver.appended[-2:], [(b"", 1), (b"", 3)])

    def test_smrt46_support_mask40_native99_and_unconditional_set(self) -> None:
        for mask, expected in ((0x40, 0), (0x80, 99)):
            context = self.context46([])
            context.driver.support_cache.pop((0, 0, 6, 3))
            context.driver.append_support_profile(bytes((0x87, 6, mask)) + bytes(5), 3)
            for kind in (1, 3):
                snapshot = context.driver.cached_support(kind)
                assert snapshot is not None
                context.driver.snapshots.append((0, *snapshot))
            output = bytearray(b"KEEP")
            self.assertEqual(
                self.run_export(
                    "Ex2SMRT_46_GetSupportInfo",
                    context,
                    bytearray(20),
                    bytearray(20),
                    bytearray(4),
                    output,
                ),
                expected,
            )
            self.assertEqual(
                output, (8).to_bytes(4, "little") if expected == 0 else b"KEEP"
            )
        context = self.context46([])
        context.driver.init_status = 17
        self.assertEqual(
            self.run_export("Ex2SMRT_46_SetSupportInfo", context, b"ab", b"cd", 2, 1),
            17,
        )
        self.assertEqual(context.driver.appended[-2:], [(b"ab", 1), (b"c", 3)])

    def test_smrt46_stop_init_error14_ignored_reply_and_host_cleanup(self) -> None:
        context = self.context46([])
        context.driver.init_status = 17
        self.assertEqual(self.run_export("Ex2SMRT_46_StopKeyCodeReset", context), 14)
        context = self.context46([(27, b"")])
        self.assertEqual(self.run_export("Ex2SMRT_46_StopKeyCodeReset", context), 0)
        context = self.context46([])
        context.driver.fault = OSError("authored host fault")
        with self.assertRaises(OSError):
            self.run_export("Ex2SMRT_46_StopKeyCodeReset", context)
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_smrt46_three_source_shared_offsets_and_nk12_absence(self) -> None:
        self.assertNotIn(
            "Ex2SMRT_46_GetSupportInfo", chassis.supported_exports(chassis.NK12_SHA256)
        )
        for constant, base in (
            ("NK18_SHA256", 0x1014A6B0),
            ("NK_DS4_SHA256", 0x101B1914),
            ("NK_GTS_SHA256", 0x101BCA14),
        ):
            blob = ("authored SMRT46 " + constant).encode()
            digest = hashlib.sha256(blob).hexdigest()
            with patch.object(chassis, constant, digest):
                context = self.context46([(0, b"\x61\xd1\0\x40\0")])
                context.module_bytes, context.module_sha256 = blob, digest
                self.assertEqual(
                    self.run_export("Ex2SMRT_46_GetKeyStatus", context, 1), 0
                )
                self.assertEqual(context.state[f"native_global:{base + 12:08x}"], 1)

    def context45(self, replies: list[tuple[int, bytes]]) -> FakeContext:
        context = FakeContext(replies)
        context.mode = 4
        context.driver.append_support_profile(b"\xd1\x03\x08\x40\x10\xd2\x02\0\x80", 1)
        context.driver.append_support_profile(b"\x87\x06\x80" + bytes(5), 3)
        return context

    def test_smrt45_support_outputs_and_distinct_native_mask_failure_codes(
        self,
    ) -> None:
        for kind, mask, expected in ((1, 8, 0), (1, 0, 4510), (3, 0, 4511)):
            context = self.context45([])
            context.driver.support_cache.clear()
            raw1 = bytes(
                (0xD1, 3, mask if kind == 1 else 8, 0x40, 0x10, 0xD2, 2, 0, 0x80)
            )
            raw3 = bytes((0x87, 6, mask if kind == 3 else 0x80)) + bytes(5)
            context.driver.append_support_profile(raw1, 1)
            context.driver.append_support_profile(raw3, 3)
            for k in (1, 3):
                snapshot = context.driver.cached_support(k)
                assert snapshot is not None
                context.driver.snapshots.append((0, *snapshot))
            first, second, len1, len3 = (
                bytearray(b"A" * 20),
                bytearray(b"B" * 20),
                bytearray(b"KEEP"),
                bytearray(b"HOLD"),
            )
            self.assertEqual(
                self.run_export(
                    "Ex2SMRT_45_GetSupportInfo", context, first, second, len1, len3
                ),
                expected,
            )
            self.assertEqual(first[:9], raw1 if expected != 4510 else b"A" * 9)
            self.assertEqual(
                len1, (9).to_bytes(4, "little") if expected != 4510 else b"KEEP"
            )
            self.assertEqual(
                len3, (8).to_bytes(4, "little") if expected == 0 else b"HOLD"
            )
            self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_smrt45_start_status_progress_and_shared_cache_native_append(self) -> None:
        context = self.context45([(0, b"\x7b\x87"), (0, b"\x61\xd1\0\x40\0")])
        progress = bytearray(4)
        self.assertEqual(
            self.run_export(
                "Ex2SMRT_45_StartOwnersKeyReg", context, b"", b"", 0, 0, 0, progress
            ),
            4503,
        )
        self.assertEqual(progress, (451).to_bytes(4, "little"))
        self.assertEqual(context.state["native_global:1014a630"], 4503)
        self.assertEqual(
            self.exchanged(context), [b"\x3b\x87\x80" + bytes(5), b"\x21\xd1"]
        )
        self.assertEqual(context.driver.appended[-2:], [(b"", 1), (b"", 3)])
        self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.context45([])
        context.cancelled = True
        progress = bytearray(4)
        self.assertEqual(
            self.run_export(
                "Ex2SMRT_45_StartOwnersKeyReg", context, None, None, 0, 0, 0, progress
            ),
            99,
        )
        self.assertEqual(progress, (450).to_bytes(4, "little"))
        self.assertNotIn(("initialize", 0), context.driver.events)
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_smrt45_terminal_states_and_stop_branches_all_table_modes(self) -> None:
        for operation, mode, data, expected, stop in (
            ("StatusNormal", 0, b"\0\0\0", 4500, False),
            ("StatusNormal", 1, b"\0\0\x10", 4502, True),
            ("WaitComp", 2, b"\x08\0\0", 4504, False),
            ("WaitComp", 3, b"\0\0\x10", 4502, True),
            ("RegNormal", 2, b"\0\0\0", 4500, True),
            ("RegNormal", 3, b"\0\0\x10", 4502, True),
        ):
            context = self.context45([(0, b"\x61\xd1" + data), (0, b"\x7b\x87")])
            self.assertEqual(
                self.run_export("Ex2SMRT_45_GetKeyStatus_" + operation, context, mode),
                expected,
            )
            self.assertEqual(len(self.exchanged(context)), 2 if stop else 1)
            self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_smrt45_pending_cancel_and_transport_fault_classification(self) -> None:
        for operation, data in (
            ("StatusNormal", b"\0\x40\0"),
            ("WaitComp", b"\0\0\0"),
            ("RegNormal", b"\x08\0\0"),
        ):
            context = self.context45([(0, b"\x61\xd1" + data)])
            context.cancel_after_sleep = 1
            mode = 2 if operation == "RegNormal" else 0
            self.assertEqual(
                self.run_export("Ex2SMRT_45_GetKeyStatus_" + operation, context, mode),
                0,
            )
            self.assertEqual(len(self.exchanged(context)), 1)
            self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.context45([(17, b""), (0, b"\x7b\x87")])
        self.assertEqual(
            self.run_export("Ex2SMRT_45_GetKeyStatus_StatusNormal", context, 0), 17
        )
        self.assertEqual(context.state["native_global:1014a630"], 4506)
        self.assertEqual(self.exchanged(context)[-1], b"\x3b\x87" + bytes(6))

    def test_smrt45_thirty_second_timeout_preserves_operation_stop_distinction(
        self,
    ) -> None:
        for operation, mode, data, stop in (
            ("StatusNormal", 0, b"\0\x40\0", False),
            ("WaitComp", 0, b"\0\0\0", True),
            ("RegNormal", 2, b"\x08\0\0", False),
        ):
            context = self.context45([(0, b"\x61\xd1" + data), (0, b"\x7b\x87")])
            original = context.driver.exchange

            def exchange(
                request: bytes,
                context: FakeContext = context,
                original: Callable[[bytes], tuple[int, bytes]] = original,
            ) -> tuple[int, bytes]:
                if request == b"\x21\xd1":
                    context.clock += 30000
                return original(request)

            with patch.object(context.driver, "exchange", side_effect=exchange):
                self.assertEqual(
                    self.run_export(
                        "Ex2SMRT_45_GetKeyStatus_" + operation, context, mode
                    ),
                    4505,
                )
            self.assertEqual(len(self.exchanged(context)), 2 if stop else 1)
        context = self.context45(
            [(0, b"\x7b\x87"), (0, b"\x61\xd1\0\0\0"), (0, b"\x7b\x87")]
        )
        original = context.driver.exchange

        def start_exchange(request: bytes) -> tuple[int, bytes]:
            if request == b"\x21\xd1":
                context.clock += 30000
            return original(request)

        with patch.object(context.driver, "exchange", side_effect=start_exchange):
            self.assertEqual(
                self.run_export(
                    "Ex2SMRT_45_StartOwnersKeyReg",
                    context,
                    b"",
                    b"",
                    0,
                    0,
                    0,
                    bytearray(4),
                ),
                4505,
            )
        self.assertEqual(self.exchanged(context)[-1], b"\x3b\x87" + bytes(6))

    def test_smrt45_unsupported_mode_and_host_exception_restore_and_close(self) -> None:
        context = self.context45([])
        with self.assertRaises(ValueError):
            self.run_export("Ex2SMRT_45_GetKeyStatus_StatusNormal", context, 4)
        self.assertEqual(
            context.driver.events[-2:],
            [("configure", "native_rva:172d0", 100), ("finalize",)],
        )
        context = self.context45([])
        context.driver.fault = OSError("authored host fault")
        with self.assertRaises(OSError):
            self.run_export("Ex2SMRT_45_StopOwnersKeyReg", context)
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_smrt45_native_set_appends_after_init_error_and_exact_stop_reply(
        self,
    ) -> None:
        context = self.context45([])
        context.driver.init_status = 17
        self.assertEqual(
            self.run_export("Ex2SMRT_45_SetSupportInfo", context, b"abc", b"def", 2, 1),
            17,
        )
        self.assertEqual(context.driver.appended[-2:], [(b"ab", 1), (b"d", 3)])
        for reply, expected in ((b"\x7b\x87", 0), (b"\x7b\x87\0", 3), (b"\x7b\x88", 3)):
            context = self.context45([(0, reply)])
            self.assertEqual(
                self.run_export("Ex2SMRT_45_StopOwnersKeyReg", context), expected
            )

    def test_smrt45_source_specific_absence_and_modern_global_status(self) -> None:
        self.assertNotIn(
            "Ex2SMRT_45_GetSupportInfo", chassis.supported_exports(chassis.NK12_SHA256)
        )
        for constant, base in (
            ("NK18_SHA256", 0x1014A618),
            ("NK_DS4_SHA256", 0x101B18F8),
            ("NK_GTS_SHA256", 0x101BC9F8),
        ):
            blob = ("authored SMRT45 " + constant).encode()
            digest = hashlib.sha256(blob).hexdigest()
            with patch.object(chassis, constant, digest):
                context = self.context45([(0, b"\x61\xd1\x08\0\0")])
                context.module_bytes, context.module_sha256 = blob, digest
                self.assertEqual(
                    self.run_export("Ex2SMRT_45_GetKeyStatus_WaitComp", context, 2),
                    4504,
                )
                self.assertEqual(context.state[f"native_global:{base + 24:08x}"], 4504)

    def context42(self, replies: list[tuple[int, bytes]]) -> FakeContext:
        context = FakeContext(replies)
        context.mode = 4
        context.driver.append_support_profile(
            b"\xd1\x06\xc0\x04\0\0\xf0\xf0\xd2\x02\0\x20", 1
        )
        context.driver.append_support_profile(b"\x81\x08\xc0" + bytes(7), 3)
        return context

    def test_smrt42_support_copy_masks_partial_outputs_and_length_wrap(self) -> None:
        for mask, expected in ((0xC0, 0), (0x80, 99)):
            context = self.context42([])
            raw = bytes((0xD1, 6, mask, 4, 0, 0, 0xF0, 0xF0, 0xD2, 2, 0, 0x20))
            context.driver.support_cache.clear()
            context.driver.append_support_profile(raw, 1)
            snapshot1 = context.driver.cached_support(1)
            assert snapshot1 is not None
            context.driver.append_support_profile(b"\x81\x06\x30" + bytes(5), 3)
            snapshot3 = context.driver.cached_support(3)
            assert snapshot3 is not None
            context.driver.snapshots.extend(((0, *snapshot1), (0, *snapshot3)))
            first, second, len1, len3 = (
                bytearray(32),
                bytearray(32),
                bytearray(4),
                bytearray(b"KEEP"),
            )
            self.assertEqual(
                self.run_export(
                    "Ex2SMRT_42_GetSupportInfo", context, first, second, len1, len3
                ),
                expected,
            )
            self.assertEqual(first[:12], raw)
            self.assertEqual(len1, (12).to_bytes(4, "little"))
            self.assertEqual(
                len3, (8).to_bytes(4, "little") if expected == 0 else b"KEEP"
            )
            self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.context42([])
        context.driver.support_cache.clear()
        context.driver.append_support_profile(
            b"\xd1\xff" + bytes(255) + b"\xd2\x02\0\x20", 1
        )
        snapshot = context.driver.cached_support(1)
        assert snapshot is not None
        context.driver.snapshots.append((0, *snapshot))
        first, length = bytearray(5), bytearray(4)
        self.assertEqual(
            self.run_export(
                "Ex2SMRT_42_GetSupportInfo",
                context,
                first,
                bytearray(),
                length,
                bytearray(4),
            ),
            99,
        )
        self.assertEqual(first, b"\xd1\xd2\x02\0\x20")
        self.assertEqual(length, (5).to_bytes(4, "little"))

    def test_smrt42_set_support_appends_even_when_initialize_fails(self) -> None:
        context = FakeContext([])
        context.mode, context.driver.init_status = 4, 17
        context.driver.append_status = 81
        raw1, raw3 = b"\xd1\x01\x01TAIL", b"\x81\x01\x80"
        self.assertEqual(
            self.run_export("Ex2SMRT_42_SetSupportInfo", context, raw1, raw3, 3, 3), 17
        )
        self.assertEqual(context.driver.appended, [(raw1[:3], 1), (raw3, 3)])
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_smrt42_count_modes_share_retained_struct_fields(self) -> None:
        context = self.context42([(0, b"\x61\xd1\x80\0\x30\x70")])
        first, second = bytearray(b"A"), bytearray(b"B")
        context.state["native_global:1014a644"] = second
        self.assertEqual(self.run_export("Ex2SMRT_42_GetKeyNum", context, first, 11), 0)
        self.assertEqual((first, second), (b"\x07", b"\x03"))
        context.driver.replies.append((0, b"\x61\xd1\0\0\xf0\x90"))
        self.assertEqual(self.run_export("Ex2SMRT_42_GetKeyNum", context, first, 12), 0)
        self.assertEqual(first, b"\0")
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_smrt42_mode12_rereads_write_pointer_but_clamps_captured_pointer(
        self,
    ) -> None:
        context = self.context42([])
        first, replacement = bytearray(b"\x09"), bytearray(b"R")

        def exchange(request: bytes) -> tuple[int, bytes]:
            context.state["native_global:1014a640"] = replacement
            return 0, b"\x61\xd1\0\0\0\xf0"

        with patch.object(context.driver, "exchange", side_effect=exchange):
            self.assertEqual(
                self.run_export("Ex2SMRT_42_GetKeyNum", context, first, 12), 0
            )
        self.assertEqual((first, replacement), (b"\0", b"\x0f"))

    def test_smrt42_increase_poll_updates_baseline_and_retains_status_session(
        self,
    ) -> None:
        context = self.context42(
            [(0, b"\x61\xd1\x80\0\x20\0"), (0, b"\x61\xd1\x80\0\x40\0")]
        )
        baseline = bytearray(b"\x03")
        self.assertEqual(
            self.run_export("Ex2SMRT_42_GetKeyStatus", context, 8, baseline), 0
        )
        self.assertEqual(baseline, b"\x04")
        self.assertEqual(context.sleeps, [1])
        self.assertNotIn(("initialize", 0), context.driver.events)
        self.assertNotIn(("finalize",), context.driver.events)

    def test_smrt42_pending_cancel_and_state_failure_cleanup_differ(self) -> None:
        for state, cancel, expected, stop in (
            (0x80, True, 3200, False),
            (0, False, 3201, True),
        ):
            context = self.context42(
                [(0, bytes((0x61, 0xD1, state, 0, 0, 0))), (17, b"")]
            )
            context.cancel_after_sleep = int(cancel)
            self.assertEqual(
                self.run_export("Ex2SMRT_42_GetKeyStatus", context, 9, bytearray(1)),
                expected,
            )
            self.assertEqual(
                any(req.startswith(b"\x3b\x81") for req in self.exchanged(context)),
                stop,
            )
            self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.context42([])
        context.cancelled = True
        self.assertEqual(
            self.run_export("Ex2SMRT_42_GetKeyNum", context, bytearray(1), 12), 99
        )
        self.assertEqual(self.exchanged(context), [])
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_smrt42_check_command_padding_marker_and_success_retention(self) -> None:
        for marker, flag in ((4004, 0x30), (4005, 0x80)):
            context = self.context42([(0, b"\x7b\x81"), (0, b"\x61\xd1\0\0\x30\x20")])
            first, second = bytearray(1), bytearray(1)
            raw1, raw3 = b"\xd1\0", b"\x81\0"
            self.assertEqual(
                self.run_export(
                    "Ex2SMRT_42_KeyCodeErasureChk",
                    context,
                    first,
                    second,
                    marker,
                    11,
                    raw1,
                    raw3,
                    len(raw1),
                    len(raw3),
                ),
                0,
            )
            self.assertEqual(
                self.exchanged(context),
                [bytes((0x3B, 0x81, flag)) + bytes(7), b"\x21\xd1"],
            )
            self.assertEqual((first, second), (b"\x02", b"\x03"))
            self.assertNotIn(("finalize",), context.driver.events)
            self.assertEqual(context.driver.appended[-2:], [(raw1, 1), (raw3, 3)])

    def test_smrt42_check_request_failure_skips_stop_but_poll_failure_stops(
        self,
    ) -> None:
        for response, expected, exchanges in (
            (b"\x7b\x81\0", 3204, 1),
            (b"\x7b\x81", 3, 3),
        ):
            context = self.context42([(0, response), (0, b"\x61\xd2"), (17, b"")])
            self.assertEqual(
                self.run_export(
                    "Ex2SMRT_42_KeyCodeErasureChk",
                    context,
                    bytearray(1),
                    bytearray(1),
                    4004,
                    11,
                    b"",
                    b"",
                    0,
                    0,
                ),
                expected,
            )
            self.assertEqual(len(self.exchanged(context)), exchanges)
            self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.context42([])
        context.driver.support_cache.clear()
        self.assertEqual(
            self.run_export(
                "Ex2SMRT_42_KeyCodeErasureChk",
                context,
                bytearray(1),
                bytearray(1),
                4004,
                11,
                b"",
                b"",
                0,
                0,
            ),
            3204,
        )
        self.assertEqual(self.exchanged(context), [])

    def test_smrt42_erase_60second_timeout_and_completion_stop(self) -> None:
        for state, bit, advance, expected in (
            (0, 0, 0, 0),
            (0, 4, 0, 3203),
            (0x80, 0, 60000, 3202),
        ):
            context = self.context42(
                [
                    (0, b"\x7b\x81"),
                    (0, bytes((0x61, 0xD1, state, bit, 0, 0))),
                    (17, b""),
                ]
            )
            original = context.driver.exchange

            def exchange(
                request: bytes,
                context: FakeContext = context,
                advance: int = advance,
                original: Callable[[bytes], tuple[int, bytes]] = original,
            ) -> tuple[int, bytes]:
                if request == b"\x21\xd1":
                    context.clock += advance
                return original(request)

            with patch.object(context.driver, "exchange", side_effect=exchange):
                self.assertEqual(
                    self.run_export("Ex2SMRT_42_KeyCodeErasure", context, 10), expected
                )
            requests = self.exchanged(context)
            self.assertEqual(requests[0], b"\x3b\x81\x04" + bytes(7))
            self.assertEqual(requests[-1], b"\x3b\x81" + bytes(8))
            self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_smrt42_all_four_native_structs_and_mask_length_padding(self) -> None:
        for constant, base, setter in (
            ("NK12_SHA256", 0x100E5C90, "native_rva:fa60"),
            ("NK18_SHA256", 0x1014A640, "native_rva:172d0"),
            ("NK_DS4_SHA256", 0x101B18C8, "native_rva:32410"),
            ("NK_GTS_SHA256", 0x101BC9C8, "native_rva:33320"),
        ):
            blob = ("authored SMRT42 " + constant).encode()
            digest = hashlib.sha256(blob).hexdigest()
            with (
                self.subTest(variant=constant),
                patch.object(chassis, constant, digest),
            ):
                context = self.context42([(0, b"\x61\xd1\0\0\x20\x10"), (17, b"")])
                context.module_bytes, context.module_sha256 = blob, digest
                second = bytearray(1)
                context.state[f"native_global:{base + 4:08x}"] = second
                first = bytearray(1)
                self.assertEqual(
                    self.run_export("Ex2SMRT_42_GetKeyNum", context, first, 11), 0
                )
                self.assertEqual((first, second), (b"\x01", b"\x02"))
                self.assertIn(("configure", setter, 150), context.driver.events)
                # Kind3 padding counts all mask bytes, including zero mask bytes.
                self.assertEqual(
                    self.run_export("Ex2SMRT_42_TerminateKeyCodeErasure", context), 0
                )
                self.assertEqual(self.exchanged(context)[-1], b"\x3b\x81" + bytes(8))

    def test_smrt42_terminate_ignores_native_stop_and_host_fault_closes(self) -> None:
        context = self.context42([(27, b"")])
        self.assertEqual(
            self.run_export("Ex2SMRT_42_TerminateKeyCodeErasure", context), 0
        )
        self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.context42([(17, b"")])
        context.driver.init_status = 17
        self.assertEqual(self.run_export("Ex2SMRT_42_KeyCodeErasure", context, 10), 17)
        self.assertEqual(self.exchanged(context), [b"\x3b\x81" + bytes(8)])
        context = self.context42([])
        context.driver.fault = OSError("authored wire fault")
        with self.assertRaises(OSError):
            self.run_export("Ex2SMRT_42_GetKeyStatus", context, 11, bytearray(1))
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def args41(
        self, *, flag: int = 1, trigger: int = 1, marker: int = 4005
    ) -> tuple[object, ...]:
        return (
            bytearray(marker.to_bytes(4, "little")),
            trigger,
            bytearray(b"\xaa" * 9),
            bytearray(4),
            bytearray(b"\xbb" * 8),
            3,
            4,
            b"\xd2\x02\x01\x01",
            flag,
        )

    def test_smrt41_online_direct_full_outputs_and_no_business_early_cancel(
        self,
    ) -> None:
        context = FakeContext(
            [
                (0, b"\x61\xd2\0\x80"),
                (0, b"\x5a\x08" + bytes(range(8))),
                (0, b"\x67\x09" + bytes(range(8, 14))),
                (0, b"\x7e\xff"),
            ]
        )
        context.mode, context.cancelled = 4, True
        arguments = self.args41()
        self.assertEqual(
            self.run_export("Ex2SMRT_41_Online_Certification", context, *arguments), 0
        )
        self.assertEqual(arguments[0], (4005).to_bytes(4, "little"))
        self.assertEqual(arguments[2], bytes(range(8)) + b"\xaa")
        self.assertEqual(arguments[3], (1000).to_bytes(4, "little"))
        self.assertEqual(arguments[4], bytes(range(8, 14)) + b"\xbb\xbb")
        self.assertEqual(
            self.exchanged(context), [b"\x21\xd2", b"\x1a\x84", b"\x27\x09", b"\x3e"]
        )
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_smrt41_public_worker_busy_overwrite_respects_native_read_points(
        self,
    ) -> None:
        from scripts.utility_ex import UtilityExContext, UtilityExEngine
        from scripts.utility_ex_comm import SHA_18_NK

        host = Mock()
        host.get_parameter.side_effect = lambda key: 4 if key == 0x6F else 0
        host.ticks.return_value = 1000
        entered, release = threading.Event(), threading.Event()
        driver = FakeComm([(0, b"\x61\xd2\0\x80\x40")])
        first, second, third = (
            self.args41(marker=1234),
            list(self.args41()),
            self.args41(flag=0),
        )
        second[5] = 4

        def initialize() -> int:
            entered.set()
            if not release.wait(2):
                raise TimeoutError(
                    "Authored concurrent wrapper did not release initialize"
                )
            return 0

        with patch.object(chassis, "NK18_SHA256", SHA_18_NK):
            image_path = Path(
                "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityExNK2.dll"
            )
            require_private(image_path)
            image = image_path.read_bytes()
            context = UtilityExContext(image, host, None, None)
            engine = UtilityExEngine(context)
            with (
                patch.object(UtilityExContext, "comm", return_value=driver),
                patch.object(driver, "initialize", side_effect=initialize),
            ):
                try:
                    self.assertEqual(
                        engine.invoke("Ex2SMRT_41_Online_Certification", first), 15
                    )
                    self.assertTrue(entered.wait(2))
                    self.assertEqual(
                        engine.invoke("Ex2SMRT_41_Online_Certification", tuple(second)),
                        16,
                    )
                    self.assertEqual(
                        engine.invoke("Ex2SMRT_41_Online_Certification", third), 16
                    )
                finally:
                    release.set()
                self.assertEqual(engine.worker.stop(2000), 0)
        # Captured output and branch flag survive the busy wrapper writes. The
        # selected direct offset is read after initialize and sees the newer 4.
        self.assertEqual(first[0], (4003).to_bytes(4, "little"))
        self.assertEqual(second[0], (4005).to_bytes(4, "little"))
        self.assertEqual(third[0], (4005).to_bytes(4, "little"))
        self.assertEqual(driver.appended, [])
        self.assertEqual(
            [event for event in driver.events if event[0] == "exchange"],
            [("exchange", b"\x21\xd2")],
        )

    def test_smrt41_state_classification_trigger_and_caller_marker(self) -> None:
        for value, trigger, marker, expected, output in (
            (0, 1, 4005, 0, 4002),
            (0x40, 1, 4005, 0, 4003),
            (0x80, 0, 4005, 4006, 4005),
            (0x80, 1, 1234, 0, 1234),
        ):
            context = FakeContext([(0, bytes((0x61, 0xD2, 0, value)))])
            context.mode = 4
            arguments = self.args41(trigger=trigger, marker=marker)
            self.assertEqual(
                self.run_export("Ex2SMRT_41_Online_Certification", context, *arguments),
                expected,
            )
            self.assertEqual(arguments[0], output.to_bytes(4, "little"))
            self.assertEqual(self.exchanged(context), [b"\x21\xd2"])
        context = FakeContext([(0, b"\x61\xd2")])
        context.mode = 4
        arguments = self.args41()
        self.assertEqual(
            self.run_export("Ex2SMRT_41_Online_Certification", context, *arguments), 3
        )
        self.assertEqual(arguments[0], (4001).to_bytes(4, "little"))

    def test_smrt41_table_append_return_ignored_and_first_profile_selected(
        self,
    ) -> None:
        context = FakeContext([(0, b"\x61\xd2\x40\x80")])
        context.mode = 4
        context.driver.append_support_profile(b"\xd2\x02\0\x01", 1)
        context.driver.append_status = 81
        arguments = self.args41(flag=0)
        self.assertEqual(
            self.run_export("Ex2SMRT_41_Online_Certification", context, *arguments), 0
        )
        self.assertEqual(arguments[0], (4003).to_bytes(4, "little"))
        self.assertEqual(len(context.driver.appended), 2)
        self.assertEqual(self.exchanged(context), [b"\x21\xd2"])
        context = FakeContext(
            [
                (0, b"\x61\xd2\0\x80"),
                (0, b"\x5a\x08" + bytes(8)),
                (0, b"\x67\x09" + bytes(6)),
                (0, b"\x7e"),
            ]
        )
        context.mode = 4
        self.assertEqual(
            self.run_export(
                "Ex2SMRT_41_Online_Certification", context, *self.args41(flag=0)
            ),
            0,
        )
        self.assertEqual(context.driver.appended, [(b"\xd2\x02\x01\x01", 1)])

    def test_smrt41_008_partial_outputs_and_failure_status(self) -> None:
        for replies, expected, challenge_written, seed_written, tick_written in (
            ([(17, b"")], 17, False, False, False),
            ([(0, b"\x5a\x07" + bytes(8))], 3, False, False, False),
            (
                [(0, b"\x5a\x08" + bytes(8)), (0, b"\x67\x08" + bytes(6))],
                3,
                True,
                False,
                False,
            ),
            (
                [(0, b"\x5a\x08" + bytes(8)), (0, b"\x67\x09" + bytes(6)), (17, b"")],
                17,
                True,
                True,
                True,
            ),
        ):
            context = FakeContext(replies)
            context.mode = 4
            arguments = (
                bytearray(4),
                bytearray(b"\xaa" * 8),
                bytearray(4),
                bytearray(b"\xbb" * 6),
            )
            self.assertEqual(
                self.run_export(
                    "Ex2SMRT_41_Online_Certification_008", context, *arguments
                ),
                expected,
            )
            self.assertEqual(arguments[0], (4001).to_bytes(4, "little"))
            self.assertEqual(
                arguments[1], bytes(8) if challenge_written else b"\xaa" * 8
            )
            self.assertEqual(arguments[3], bytes(6) if seed_written else b"\xbb" * 6)
            self.assertEqual(
                arguments[2], (1000 if tick_written else 0).to_bytes(4, "little")
            )
            self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_smrt41_send_key_exact_length_reply_status_and_init_failure(self) -> None:
        for reply, expected in (
            (b"\x67\x0a\x34", 0),
            (b"\x67\x0a\0", 4007),
            (b"\x67\x09\x34", 3),
            (b"\x67\x0a\x34\0", 3),
        ):
            context = FakeContext([(0, reply)])
            context.mode = 4
            output = bytearray((4005).to_bytes(4, "little"))
            self.assertEqual(
                self.run_export(
                    "Ex2SMRT_41_SendTheKey", context, b"\x11\x22\x33", output, 2
                ),
                expected,
            )
            self.assertEqual(self.exchanged(context), [b"\x27\x0a\x11\x22"])
            self.assertEqual(output, (4001 if expected else 4005).to_bytes(4, "little"))
        context = FakeContext([])
        context.mode, context.driver.init_status = 4, 17
        output = bytearray((4005).to_bytes(4, "little"))
        self.assertEqual(
            self.run_export("Ex2SMRT_41_SendTheKey", context, b"", output, 0), 17
        )
        self.assertEqual(output, (4005).to_bytes(4, "little"))

    def test_smrt41_keepalive_four_second_unsigned_threshold_and_precancel(
        self,
    ) -> None:
        for clock, requests in ((0xE9F, []), (0xEA0, [b"\x3e"])):
            context = FakeContext([(0, b"\x7e")])
            context.mode, context.clock, context.cancel_after_sleep = 4, clock, 1
            timestamp, output = (
                bytearray((0xFFFFFF00).to_bytes(4, "little")),
                bytearray(4),
            )
            self.assertEqual(
                self.run_export("Ex2SMRT_41_KeepAlive", context, timestamp, output), 0
            )
            self.assertEqual(self.exchanged(context), requests)
            self.assertEqual(
                timestamp, (clock if requests else 0xFFFFFF00).to_bytes(4, "little")
            )
        context = FakeContext([])
        context.mode, context.cancelled = 4, True
        self.assertEqual(
            self.run_export(
                "Ex2SMRT_41_KeepAlive", context, bytearray(4), bytearray(4)
            ),
            99,
        )
        self.assertEqual(context.driver.events, [("finalize",)])
        context = FakeContext([(17, b"")])
        context.mode, context.clock = 4, 5000
        output = bytearray(4)
        self.assertEqual(
            self.run_export("Ex2SMRT_41_KeepAlive", context, bytearray(4), output), 17
        )
        self.assertEqual(output, (4001).to_bytes(4, "little"))

    def test_smrt41_null_zero_key_buffer_and_metadata_missing_ordinal(self) -> None:
        context = FakeContext([(0, b"\x67\x0a\x34")])
        context.mode = 4
        self.assertEqual(
            self.run_export("Ex2SMRT_41_SendTheKey", context, None, bytearray(4), 0), 0
        )
        self.assertEqual(self.exchanged(context), [b"\x27\x0a"])
        context = FakeContext([(0, b"\x61\xd2\x80")])
        context.mode = 4
        arguments = list(self.args41(flag=0))
        arguments[6], arguments[7] = 0, None
        self.assertEqual(
            self.run_export("Ex2SMRT_41_Online_Certification", context, *arguments), 3
        )
        self.assertEqual(arguments[0], (4001).to_bytes(4, "little"))
        self.assertEqual(context.driver.appended, [(b"", 1)])

    def test_smrt41_all_four_source_keys_and_host_bounds(self) -> None:
        for constant in (
            "NK12_SHA256",
            "NK18_SHA256",
            "NK_DS4_SHA256",
            "NK_GTS_SHA256",
        ):
            blob = ("authored SMRT41 " + constant).encode()
            digest = hashlib.sha256(blob).hexdigest()
            with (
                self.subTest(variant=constant),
                patch.object(chassis, constant, digest),
            ):
                context = FakeContext([(0, b"\x67\x0a\x34")])
                context.mode = 4
                context.module_bytes, context.module_sha256 = blob, digest
                self.assertEqual(
                    self.run_export(
                        "Ex2SMRT_41_SendTheKey", context, b"\x11", bytearray(4), 1
                    ),
                    0,
                )
                self.assertEqual(context.driver.events[-1], ("finalize",))
        context = FakeContext([])
        context.mode = 4
        with self.assertRaises(ValueError):
            self.run_export("Ex2SMRT_41_SendTheKey", context, b"\x11", bytearray(4), 2)
        self.assertEqual(context.kinds, [])
        context.driver.fault = OSError("authored SMRT41 fault")
        with self.assertRaises(OSError):
            self.run_export("Ex2SMRT_41_SendTheKey", context, b"\x11", bytearray(4), 1)
        self.assertEqual(
            context.driver.events[-2:],
            [("configure", "native_rva:172d0", 100), ("finalize",)],
        )

    def context_flow01(self, back: int = 15, front: int = 10) -> FakeContext:
        context = FakeContext([(0, b"\x61\x08\x07")])
        context.mode = 4
        raw = bytes((0x22, 5, back, back, 1, 0, 1, 0x21, 4, front, front, 0, 1)).ljust(
            0x1020, b"\0"
        )
        offsets = [0x1020] * 256
        offsets[0x22], offsets[0x21] = 0, 7
        context.driver.snapshots.append((0, raw, tuple(offsets)))
        return context

    def test_abs01_type_masks_partial_count_writes_and_gating_state(self) -> None:
        for back, front, expected, counts in (
            (15, 10, 0, (1, 2)),
            (15, 0, 0, (0xAAAAAAAA, 2)),
            (12, 10, 0, (1, 2)),
            (12, 0, 100, (0xAAAAAAAA, 2)),
            (0, 10, 100, (0xAAAAAAAA, 0xAAAAAAAA)),
        ):
            context = self.context_flow01(back, front)
            output = bytearray(b"\xaa" * 8 + b"\xcc")
            self.assertEqual(
                self.run_export("Ex2ABS_01_Conf_typeof_AirBleeding", context, output),
                expected,
            )
            self.assertEqual(
                tuple(
                    int.from_bytes(output[offset : offset + 4], "little")
                    for offset in (0, 4)
                ),
                counts,
            )
            self.assertEqual(output[8], 0xCC)
            self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.context_flow01()
        context.driver.replies.clear()
        context.driver.replies.append((0, b"\x61\x08\x06"))
        output = bytearray(b"\xaa" * 8)
        self.assertEqual(
            self.run_export("Ex2ABS_01_Conf_typeof_AirBleeding", context, output), 222
        )
        self.assertEqual(output, b"\xaa" * 8)
        self.assertEqual(len(context.driver.snapshots), 1)

    def test_abs01_bleed_selection_padding_and_all_native_statuses_retain(self) -> None:
        for selection, sub, mask, padding in (
            (0x226, 0x21, 2, 1),
            (0x227, 0x21, 8, 1),
            (0x228, 0x22, 12, 2),
            (0x229, 0x22, 12, 2),
            (0, 0x22, 0, 2),
        ):
            context = FakeContext([(0, bytes((0x70, sub, 0)))])
            context.mode = 4
            counts = bytearray(b"\x01\0\0\0\x02\0\0\0")
            self.assertEqual(
                self.run_export("Ex2ABS_01_Bleed_The_Air", context, selection, counts),
                12,
            )
            self.assertEqual(
                self.exchanged(context),
                [bytes((0x30, sub, 0, mask, mask)) + bytes(padding)],
            )
            self.assertNotIn(("finalize",), context.driver.events)
        context = FakeContext([])
        context.mode, context.driver.init_status = 4, 17
        self.assertEqual(
            self.run_export("Ex2ABS_01_Bleed_The_Air", context, 0x226, bytearray(8)), 17
        )
        self.assertNotIn(("finalize",), context.driver.events)

    def test_abs01_flow_true_arity_two_and_structure_all_four_sources(self) -> None:
        for constant in (
            "NK12_SHA256",
            "NK18_SHA256",
            "NK_DS4_SHA256",
            "NK_GTS_SHA256",
        ):
            blob = ("authored ABS01 flow " + constant).encode()
            digest = hashlib.sha256(blob).hexdigest()
            with (
                self.subTest(variant=constant),
                patch.object(chassis, constant, digest),
            ):
                context = self.context_flow01()
                context.module_bytes, context.module_sha256 = blob, digest
                output = bytearray(8)
                self.assertEqual(
                    self.run_export(
                        "Ex2ABS_01_Conf_typeof_AirBleeding", context, output
                    ),
                    0,
                )
                context.driver.replies.append((0, b"\x70\x21"))
                self.assertEqual(
                    self.run_export("Ex2ABS_01_Bleed_The_Air", context, 0x226, output),
                    0,
                )
                with self.assertRaises(ValueError):
                    self.run_export("Ex2ABS_01_Bleed_The_Air", context, 0x226)

    def test_abs01_flow_bounds_and_host_fault_cleanup(self) -> None:
        context = FakeContext([])
        context.mode = 4
        counts = bytearray(b"\xff" * 8)
        with self.assertRaises(ValueError):
            self.run_export("Ex2ABS_01_Bleed_The_Air", context, 0x226, counts)
        self.assertEqual(context.kinds, [])
        context.driver.fault = OSError("authored ABS01 transport")
        with self.assertRaises(OSError):
            self.run_export("Ex2ABS_01_Bleed_The_Air", context, 0x226, bytearray(8))
        self.assertEqual(context.driver.events[-1], ("finalize",))
        self.assertIn(("configure", "native_rva:172d0", 100), context.driver.events)

    def context25(self) -> FakeContext:
        context = FakeContext([])
        context.mode = 4
        for raw, sub in (
            (b"\xbf\x01\x01", 0xBF),
            (b"\x2e\x06\0\0\x08\x08\0\x01", 0x2E),
        ):
            offsets = [0x1020] * 256
            offsets[sub] = 0
            context.driver.snapshots.append(
                (0, raw.ljust(0x1020, b"\0"), tuple(offsets))
            )
        return context

    def test_abs25_support_two_shared_profiles_and_compressed_request(self) -> None:
        context = self.context25()
        self.assertEqual(self.run_export("Ex2ABS_25_GetSupportInfo", context), 0)
        self.assertEqual(len(context.driver.support_cache), 2)
        context.driver.replies.append((0, b"\x70\x2e"))
        self.assertEqual(self.run_export("Ex2ABS_25_ForcedActuatorRefresh", context), 0)
        self.assertEqual(self.exchanged(context), [b"\x30\x2e\0\x08\x08\0"])
        context = self.context25()
        status, raw, offsets = context.driver.snapshots.pop()
        raw = raw[:4] + b"\0" + raw[5:]
        context.driver.snapshots.append((status, raw, offsets))
        self.assertEqual(self.run_export("Ex2ABS_25_GetSupportInfo", context), 912)
        context = self.context25()
        status, raw, offsets = context.driver.snapshots.popleft()
        context.driver.snapshots.appendleft((status, bytes(0x1020), offsets))
        self.assertEqual(self.run_export("Ex2ABS_25_GetSupportInfo", context), 911)

    def test_abs25_refresh_status12_ignores_echo_and_stops_on_fault(self) -> None:
        context = self.context25()
        self.assertEqual(self.run_export("Ex2ABS_25_GetSupportInfo", context), 0)
        context.driver.replies.extend(((0, b"\x70\xff\0"), (17, b"")))
        self.assertEqual(
            self.run_export("Ex2ABS_25_ForcedActuatorRefresh", context), 12
        )
        self.assertEqual(self.exchanged(context)[-1], b"\x30")
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_abs25_confirm_old_cleanup_and_modern_omission_are_source_bound(
        self,
    ) -> None:
        for constant in (
            "NK12_SHA256",
            "NK18_SHA256",
            "NK_DS4_SHA256",
            "NK_GTS_SHA256",
        ):
            blob = ("authored ABS25 " + constant).encode()
            digest = hashlib.sha256(blob).hexdigest()
            with (
                self.subTest(variant=constant),
                patch.object(chassis, constant, digest),
            ):
                context = self.context25()
                context.module_bytes, context.module_sha256 = blob, digest
                context.driver.replies.extend(((17, b""), (0, b"\x70")))
                self.assertEqual(
                    self.run_export("Ex2ABS_25_ConfirmActivatingFlg", context), 17
                )
                expected = (
                    [b"\x21\xbf", b"\x30"]
                    if constant in ("NK12_SHA256", "NK18_SHA256")
                    else [b"\x21\xbf"]
                )
                self.assertEqual(self.exchanged(context), expected)
                self.assertEqual(context.sleeps, [100] * 10)
                self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_abs25_pending_success_cancel_and_host_fault(self) -> None:
        context = self.context25()
        context.driver.replies.extend(((0, b"\x61\xbf\x01"), (0, b"\x61\xbf\0")))
        self.assertEqual(self.run_export("Ex2ABS_25_ConfirmActivatingFlg", context), 0)
        self.assertEqual(context.clock, 3000)
        self.assertEqual(self.exchanged(context), [b"\x21\xbf"] * 2)
        for operation in ("ForcedActuatorRefresh", "ConfirmActivatingFlg"):
            context = self.context25()
            context.cancelled = True
            self.assertEqual(self.run_export("Ex2ABS_25_" + operation, context), 0)
            self.assertEqual(context.driver.events, [("finalize",)])
        context = self.context25()
        context.sleep_fault = TimeoutError("authored ABS25 deadline")
        with self.assertRaises(TimeoutError):
            self.run_export("Ex2ABS_25_ConfirmActivatingFlg", context)
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_abs22_support_shared_cache_mask_failures_and_wire_error(self) -> None:
        for relay, solenoid, expected in ((2, 255, 0), (0, 255, 801), (2, 0, 802)):
            context = FakeContext([])
            context.mode = 4
            raw = bytes((3, 2, relay, relay, 0x21, 2, solenoid, solenoid)).ljust(
                0x1020, b"\0"
            )
            offsets = [0x1020] * 256
            offsets[3], offsets[0x21] = 0, 4
            context.driver.snapshots.append((0, raw, tuple(offsets)))
            self.assertEqual(
                self.run_export("Ex2ABS_22_GetDIDSupport", context), expected
            )
            self.assertIn((0, 0, 6, 2), context.driver.support_cache)
            self.assertEqual(
                context.driver.events[-2:],
                [("configure", "native_rva:172d0", 100), ("finalize",)],
            )
        context = FakeContext([])
        context.mode = 4
        context.driver.snapshots.append((80, b"", ()))
        self.assertEqual(self.run_export("Ex2ABS_22_GetDIDSupport", context), 80)

    def test_abs22_two_round_sequence_twenty_one_seconds_and_ignored_stop_fault(
        self,
    ) -> None:
        context = FakeContext([(0, b"\x70\x21")] * 10 + [(0, b"\x70\x03"), (17, b"")])
        context.mode = 4
        self.assertEqual(self.run_export("Ex2ABS_22_AirBleeding", context), 0)
        cycle = [
            b"\x30\x21\x02\xff\x55",
            b"\x30\x21\x02\xff\xff",
            b"\x30\x21\x02\xff\xff",
            b"\x30\x21\x02\xff\x55",
            b"\x30\x21\0\xff\0",
        ]
        self.assertEqual(
            self.exchanged(context), cycle * 2 + [b"\x30\x03\x05\x02\x02", b"\x30"]
        )
        self.assertEqual(context.clock, 22000)
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_abs22_long_echo_response_and_status12_do_not_fall_through(self) -> None:
        for reply, expected in (
            (b"\x70\x21\0\xff", 12),
            (b"\x70\xff\x01", 3),
            (b"\x70", 3),
        ):
            context = FakeContext([(0, reply)])
            context.mode = 4
            self.assertEqual(
                self.run_export("Ex2ABS_22_AirBleeding", context), expected
            )
            self.assertEqual(len(self.exchanged(context)), 1)
            self.assertEqual(context.driver.events[-1], ("finalize",))
        context = FakeContext([(0, b"\x70\x21\x01\xff"), (17, b"")])
        context.mode = 4
        self.assertEqual(self.run_export("Ex2ABS_22_AirBleeding", context), 17)
        self.assertEqual(len(self.exchanged(context)), 2)

    def test_abs22_cancel_skips_waits_and_stop_has_no_length_predicate(self) -> None:
        context = FakeContext(
            [(0, b"\x70\x21")] * 10 + [(0, b"\x70\x03"), (0, b"\x70\xff")]
        )
        context.mode, context.cancelled = 4, True
        self.assertEqual(self.run_export("Ex2ABS_22_AirBleeding", context), 0)
        self.assertEqual(context.sleeps, [])
        context = FakeContext([(0, b"\x70\xff\0")])
        context.mode = 4
        self.assertEqual(self.run_export("Ex2ABS_22_StopActiveTest", context), 0)
        for field, value in (
            ("172d0", 100),
            ("17320", 100),
            ("172f0", 3),
            ("17ba0", 0),
        ):
            self.assertIn(
                ("configure", "native_rva:" + field, value), context.driver.events
            )

    def test_abs22_host_fault_and_initialize_failure_finalize_without_stop(
        self,
    ) -> None:
        context = FakeContext([(0, b"\x70\x21")])
        context.mode = 4
        context.sleep_fault = TimeoutError("authored ABS22 deadline")
        with self.assertRaises(TimeoutError):
            self.run_export("Ex2ABS_22_AirBleeding", context)
        self.assertEqual(self.exchanged(context), [b"\x30\x21\x02\xff\x55"])
        self.assertEqual(context.driver.events[-1], ("finalize",))
        context = FakeContext([])
        context.mode, context.driver.init_status = 4, 17
        self.assertEqual(self.run_export("Ex2ABS_22_StopActiveTest", context), 17)
        self.assertEqual(self.exchanged(context), [])

    def context15(self) -> FakeContext:
        context = FakeContext([])
        context.mode = 4
        for raw, locations in (
            (b"\xbf\x01\x01", {0xBF: 0}),
            (
                b"\x2d\x07\x40\x40\x10\x10\x01\0\x01\x2e\x05\x38\x38\x01\x01\0",
                {0x2D: 0, 0x2E: 9},
            ),
        ):
            offsets = [0x1020] * 256
            for sub, offset in locations.items():
                offsets[sub] = offset
            context.driver.snapshots.append(
                (0, raw.ljust(0x1020, b"\0"), tuple(offsets))
            )
        return context

    def test_abs15_support_two_snapshots_and_padding_counts_on_mask_error(self) -> None:
        context = self.context15()
        self.assertEqual(self.run_export("Ex2ABS_15_GetSupportInfo", context), 0)
        self.assertEqual(context.state["nk.chassis.abs15_count_45"], 2)
        self.assertEqual(context.state["nk.chassis.abs15_count_46"], 2)
        self.assertEqual(
            [
                event
                for event in context.driver.events
                if event[0] == "support_snapshot"
            ],
            [("support_snapshot", 1), ("support_snapshot", 2)],
        )
        context = self.context15()
        status, raw, offsets = context.driver.snapshots.pop()
        raw = raw[:2] + b"\0" + raw[3:]
        context.driver.snapshots.append((status, raw, offsets))
        self.assertEqual(self.run_export("Ex2ABS_15_GetSupportInfo", context), 1501)
        self.assertEqual(context.state["nk.chassis.abs15_count_45"], 2)
        context = self.context15()
        status, raw, offsets = context.driver.snapshots.popleft()
        context.driver.snapshots.appendleft((status, bytes(0x1020), offsets))
        self.assertEqual(self.run_export("Ex2ABS_15_GetSupportInfo", context), 1500)
        self.assertEqual(len(context.driver.snapshots), 1)

    def test_abs15_all_five_patterns_status12_and_input_bounds(self) -> None:
        payloads = (
            b"\x2e\0\x08\x08",
            b"\x2e\0\x10\x10",
            b"\x2e\0\x20\x20",
            b"\x2d\0\x40\x40",
            b"\x2d\0\0\0\x10\x10",
        )
        for index, payload in enumerate(payloads):
            context = self.context15()
            context.state.update(
                {"nk.chassis.abs15_count_45": 1, "nk.chassis.abs15_count_46": 2}
            )
            context.driver.replies.append((0, b"\x70" + payload[:1] + b"\0"))
            self.assertEqual(
                self.run_export("Ex2ABS_15_StartAirBleeding", context, index), 12
            )
            padding = 2 if index < 3 else 3 if index == 3 else 1
            self.assertEqual(
                self.exchanged(context), [b"\x30" + payload + bytes(padding)]
            )
            self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.context15()
        with self.assertRaises(ValueError):
            self.run_export("Ex2ABS_15_StartAirBleeding", context, 5)
        self.assertEqual(context.kinds, [])

    def test_abs15_execute_fifteen_second_transition_pending_then_complete(
        self,
    ) -> None:
        context = self.context15()
        context.driver.replies.extend(
            [(0, b"\x70\x2e")]
            + [(0, b"\x61\xbf\x01")] * 15
            + [(0, b"\x70\x2e"), (0, b"\x61\xbf\0"), (17, b"")]
        )
        self.assertEqual(self.run_export("Ex2ABS_15_ExecuteAirBleeding", context), 0)
        self.assertEqual(context.clock, 16000)
        self.assertEqual(self.exchanged(context)[0], b"\x30\x2e\0\x10\x10")
        self.assertEqual(
            self.exchanged(context)[-3:], [b"\x30\x2e\0\x20\x20", b"\x21\xbf", b"\x30"]
        )
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_abs15_cancellation_counter_map_all_four_sources(self) -> None:
        for constant, keys in (
            ("NK12_SHA256", ("fab0", "fac0", "fad0", "fae0", "faf0")),
            ("NK18_SHA256", ("17340", "17350", "17360", "17370", "17380")),
            ("NK_DS4_SHA256", ("321b0", "321a0", "321c0", "321e0", "321f0")),
            ("NK_GTS_SHA256", ("330c0", "330b0", "330d0", "330f0", "33100")),
        ):
            for native, values, expected in (
                (27, (0, 3, 3, 0, 0), 28),
                (27, (1, 3, 3, 0, 0), 0),
                (27, (0, 2, 3, 0, 0), 0),
                (2, (0, 0, 0, 1, 2), 0),
                (2, (0, 0, 0, 2, 2), 2),
            ):
                blob = ("authored ABS15 " + constant).encode()
                digest = hashlib.sha256(blob).hexdigest()
                with (
                    self.subTest(variant=constant, native=native, values=values),
                    patch.object(chassis, constant, digest),
                ):
                    context = self.context15()
                    context.module_bytes, context.module_sha256 = blob, digest

                    def exchange(
                        request: bytes,
                        context: FakeContext = context,
                        native: int = native,
                    ) -> tuple[int, bytes]:
                        context.cancelled = True
                        return native, b""

                    counters = {
                        "native_rva:" + key: value for key, value in zip(keys, values)
                    }
                    context.driver.exchange = exchange
                    context.driver.cancellation_counters = lambda counters=counters: (
                        counters
                    )
                    self.assertEqual(
                        self.run_export("Ex2ABS_15_ChkPatternFlg", context), expected
                    )
                    self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_abs15_direct_mode_commands_poll_reinitialize_and_error_cleanup(
        self,
    ) -> None:
        for operation, reply, request, status in (
            ("ShiftTestMode", b"\x50", b"\x10\x40", 0),
            ("ShiftNormalMode", b"\x50\x01", b"\x10\x01", 3),
            ("EndActiveTest", b"\x70", b"\x30", 0),
        ):
            context = self.context15()
            context.driver.replies.append((0, reply))
            self.assertEqual(self.run_export("Ex2ABS_15_" + operation, context), status)
            self.assertEqual(self.exchanged(context), [request])
        context = self.context15()
        context.driver.replies.extend(((0, b"\x61\xbf\x01"), (0, b"\x61\xbf\0")))
        self.assertEqual(self.run_export("Ex2ABS_15_ChkPatternFlg", context), 0)
        self.assertEqual(
            sum(event == ("initialize", 0) for event in context.driver.events), 2
        )
        context = self.context15()
        context.cancelled = True
        context.driver.replies.append((0, b"\x70"))
        self.assertEqual(self.run_export("Ex2ABS_15_ExecuteAirBleeding", context), 99)
        self.assertEqual(self.exchanged(context), [b"\x30"])

    def test_abs15_phase_two_cancel_pending_differs_from_check_worker(self) -> None:
        context = self.context15()
        context.cancel_after_sleep = 1
        context.driver.replies.extend(
            (
                (0, b"\x70\x2e"),
                (0, b"\x61\xbf\0"),
                (0, b"\x70\x2e"),
                (0, b"\x61\xbf\x01"),
                (0, b"\x70"),
            )
        )
        self.assertEqual(self.run_export("Ex2ABS_15_ExecuteAirBleeding", context), 0)
        self.assertEqual(self.exchanged(context)[-1], b"\x30")
        context = self.context15()
        context.cancel_after_sleep = 1
        context.driver.replies.append((0, b"\x61\xbf\x01"))
        self.assertEqual(self.run_export("Ex2ABS_15_ChkPatternFlg", context), 1503)
        context = self.context15()
        context.driver.replies.append((0, b"\x61\xbf\x01"))
        context.sleep_fault = TimeoutError("authored ABS15 deadline")
        with self.assertRaises(TimeoutError):
            self.run_export("Ex2ABS_15_ChkPatternFlg", context)
        self.assertEqual(
            context.driver.events[-2:],
            [("configure", "native_rva:172d0", 100), ("finalize",)],
        )

    def context05(self) -> FakeContext:
        context = FakeContext([])
        context.mode = 4
        raw = b"\x32\x05\x40\x40\x01\0\x02\x2d\x04\x20\x20\0\x01\x2e\x04\0\0\x01\x01"
        offsets = [0x1020] * 256
        offsets[0x32], offsets[0x2D], offsets[0x2E] = 0, 7, 13
        context.driver.snapshots.append((0, raw.ljust(0x1020, b"\0"), tuple(offsets)))
        return context

    def test_abs05_two_flags_and_three_padding_counts(self) -> None:
        context = self.context05()
        outputs = (bytearray(4), bytearray(4))
        self.assertEqual(
            self.run_export("Ex2ABS_05_GetDIDSupportInfo", context, *outputs), 0
        )
        self.assertEqual(outputs, (bytearray(b"\x01\0\0\0"), bytearray(b"\x01\0\0\0")))
        self.assertEqual(
            [
                context.state[f"nk.chassis.abs05_count_{sub}"]
                for sub in (0x2E, 0x2D, 0x32)
            ],
            [2, 1, 2],
        )
        self.assertEqual(
            context.driver.events[-2:],
            [("configure", "native_rva:172d0", 100), ("finalize",)],
        )
        context = self.context05()
        status, raw, offsets = context.driver.snapshots.pop()
        raw = raw[:2] + b"\x00" + raw[3:]
        context.driver.snapshots.append((status, raw, offsets))
        self.assertEqual(
            self.run_export("Ex2ABS_05_GetDIDSupportInfo", context, *outputs), 0
        )
        self.assertEqual(outputs[0], bytes(4))
        self.assertEqual(outputs[1], b"\x01\0\0\0")

    def test_abs05_native_fault_preserves_exact_partial_outputs(self) -> None:
        for initialize, expected in (
            (17, (b"\xaa" * 4, b"\xbb" * 4)),
            (0, (b"\x01\0\0\0", b"\xbb" * 4)),
        ):
            context = self.context05()
            context.driver.init_status = initialize
            context.driver.snapshots.clear()
            context.driver.snapshots.append((17, b"", ()))
            outputs = (bytearray(b"\xaa" * 4), bytearray(b"\xbb" * 4))
            self.assertEqual(
                self.run_export("Ex2ABS_05_GetDIDSupportInfo", context, *outputs), 17
            )
            self.assertEqual(outputs, expected)
            self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.context05()
        status, raw, offsets = context.driver.snapshots.pop()
        altered = list(offsets)
        altered[0x2D] = 0x1020
        context.driver.snapshots.append((status, raw, tuple(altered)))
        outputs = (bytearray(4), bytearray(4))
        with self.assertRaises(ValueError):
            self.run_export("Ex2ABS_05_GetDIDSupportInfo", context, *outputs)
        self.assertEqual(outputs[0], b"\x01\0\0\0")
        self.assertEqual(outputs[1], bytes(4))
        self.assertEqual(context.state["nk.chassis.abs05_count_46"], 2)
        self.assertEqual(
            context.driver.events[-2:],
            [("configure", "native_rva:172d0", 100), ("finalize",)],
        )

    def test_abs03_full_twelve_second_sequence_and_timeout_restore(self) -> None:
        context = FakeContext(
            [(0, b"\x70\x21")] * 5 + [(17, b""), (0, b"\x70\x03"), (0, b"\x70")]
        )
        context.mode = 4
        self.assertEqual(self.run_export("Ex2ABS_03_ADSV2PDecompAirBleed", context), 0)
        self.assertEqual(
            self.exchanged(context),
            [b"\x30\x21\0\xaa\xaa"] * 5 + [b"\x30", b"\x30\x03\0\x02\x02", b"\x30"],
        )
        self.assertEqual(context.clock, 13000)
        self.assertEqual(
            sum(
                event == ("configure", "native_rva:172d0", 150)
                for event in context.driver.events
            ),
            6,
        )
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_abs03_fault_status_four_cleanup_and_precancel(self) -> None:
        for status, requests in ((4, 1), (17, 2), (0, 2)):
            context = FakeContext([(status, b"\x70\xff"), (0, b"\x70")])
            context.mode = 4
            self.assertEqual(
                self.run_export("Ex2ABS_03_ADSV2PDecompAirBleed", context), status or 3
            )
            self.assertEqual(len(self.exchanged(context)), requests)
            self.assertEqual(context.driver.events[-1], ("finalize",))
        context = FakeContext([(0, b"\x70")])
        context.mode, context.cancelled = 4, True
        self.assertEqual(self.run_export("Ex2ABS_03_ADSV2PDecompAirBleed", context), 99)
        self.assertEqual(self.exchanged(context), [b"\x30"])
        self.assertNotIn(("initialize", 0), context.driver.events)
        context = FakeContext([])
        context.mode, context.driver.init_status = 4, 17
        self.assertEqual(self.run_export("Ex2ABS_03_ADSV2PDecompAirBleed", context), 4)
        self.assertEqual(self.exchanged(context), [])

    def test_abs03_output_byte_reply_predicates_and_mode_three_noop(self) -> None:
        for reply, status in (
            (b"\x61\x08\x91\xff", 0),
            (b"\x61\x07\x91", 3),
            (b"\x61\x08", 3),
        ):
            context = FakeContext([(0, reply)])
            context.mode = 4
            output = bytearray(b"\xaa\xbb")
            self.assertEqual(
                self.run_export("Ex2ABS_03_ActuatorCheck", context, output), status
            )
            self.assertEqual(output, b"\x91\xbb" if status == 0 else b"\xaa\xbb")
            self.assertEqual(context.driver.events[-1], ("finalize",))
        context = FakeContext([])
        self.assertEqual(self.run_export("Ex2ABS_03_ActuatorCheck", context, None), 0)
        self.assertEqual(context.kinds, [])
        context.mode = 4
        with self.assertRaises(ValueError):
            self.run_export("Ex2ABS_03_ActuatorCheck", context, None)
        self.assertEqual(context.kinds, [])

    def test_abs03_cancelled_waits_still_execute_source_cleanup_sequence(self) -> None:
        context = FakeContext(
            [(0, b"\x70\x21")] * 5 + [(0, b"\x70"), (0, b"\x70\x03"), (0, b"\x70")]
        )
        context.mode, context.cancel_after_sleep = 4, 1
        self.advance_clock_on_exchange(context, 1000)
        self.assertEqual(self.run_export("Ex2ABS_03_ADSV2PDecompAirBleed", context), 0)
        self.assertEqual(context.sleeps, [100])
        self.assertEqual(
            self.exchanged(context)[-3:], [b"\x30", b"\x30\x03\0\x02\x02", b"\x30"]
        )
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_abs03_host_deadline_closes_and_restores_timeout(self) -> None:
        context = FakeContext([(0, b"\x70\x21")])
        context.mode = 4
        context.sleep_fault = TimeoutError("authored ABS03 deadline")
        with self.assertRaises(TimeoutError):
            self.run_export("Ex2ABS_03_ADSV2PDecompAirBleed", context)
        self.assertIn(("configure", "native_rva:172d0", 100), context.driver.events)
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_abs14_support_counts_snapshot_masks_and_partial_native_update(
        self,
    ) -> None:
        context = self.context14()
        self.assertEqual(self.run_export("Ex2ABS_14_GetDIDSupportInfo", context), 0)
        self.assertEqual(
            [context.state[f"nk.chassis.abs14_count_{sub}"] for sub in (0x21, 0x22, 3)],
            [2, 2, 1],
        )
        self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.context14()
        status, raw, offsets = context.driver.snapshots.popleft()
        context.driver.snapshots.append((status, raw[:9] + b"\0" + raw[10:], offsets))
        self.assertEqual(self.run_export("Ex2ABS_14_GetDIDSupportInfo", context), 140)
        self.assertEqual(context.state["nk.chassis.abs14_count_33"], 2)
        self.assertNotIn("nk.chassis.abs14_count_34", context.state)

    def test_abs14_relay_count_length_echo_and_no_three_byte_success_branch(
        self,
    ) -> None:
        for operation, value in (("StartRelayDrive", 2), ("StopRelayDrive", 0)):
            context = self.context14()
            context.state["nk.chassis.abs14_count_3"] = 2
            context.driver.replies.append((0, b"\x70\x03"))
            self.assertEqual(self.run_export("Ex2ABS_14_" + operation, context), 0)
            self.assertEqual(
                self.exchanged(context), [bytes((0x30, 3, 0, 2, value, 0, 0))]
            )
            self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.context14()
        context.driver.replies.extend(((0, b"\x70\x03\0"), (0, b"\x70")))
        self.assertEqual(self.run_export("Ex2ABS_14_StartRelayDrive", context), 3)
        self.assertEqual(self.exchanged(context)[-1], b"\x30")

    def test_abs14_stop_selection_cleanup_and_invalid_input(self) -> None:
        for selection, group in ((1, 1), (2, 2), (3, 2), (4, 1)):
            context = self.context14()
            context.state["nk.chassis.abs14_count_34"] = 1
            context.driver.replies.append((0, b"\x70\x22"))
            self.assertEqual(
                self.run_export("Ex2ABS_14_StopSolenoidDrive_VSC", context, selection),
                0,
            )
            self.assertEqual(
                self.exchanged(context), [bytes((0x30, 0x22, 0, group, 0, 0))]
            )
        context = self.context14()
        context.driver.replies.extend(((0, b"\x70\xff\0"), (0, b"\x70")))
        self.assertEqual(
            self.run_export("Ex2ABS_14_StopSolenoidDrive_VSC", context, 1), 3
        )
        self.assertEqual(self.exchanged(context)[-1], b"\x30")
        for name in ("StartSolenoidDrive", "StopSolenoidDrive_VSC"):
            context = self.context14()
            self.assertEqual(self.run_export("Ex2ABS_14_" + name, context, 0), 99)
            self.assertEqual(context.driver.events, [])

    def test_abs14_drive_four_second_phase_then_group_drive_and_cancel(self) -> None:
        for selection, mask, group in (
            (1, 2, 1),
            (2, 8, 2),
            (3, 0x20, 2),
            (4, 0x80, 1),
        ):
            context = self.context14()

            def exchange(
                request: bytes, context: FakeContext = context
            ) -> tuple[int, bytes]:
                context.driver.events.append(("exchange", request))
                if request[1] == 0x22:
                    context.cancelled = True
                return 0, b"\x70" + request[1:2]

            context.driver.exchange = exchange
            self.assertEqual(
                self.run_export("Ex2ABS_14_StartSolenoidDrive", context, selection), 0
            )
            self.assertEqual(
                self.exchanged(context),
                [
                    bytes((0x30, 0x21, 0, mask, mask)),
                    bytes((0x30, 0x21, 0, mask, mask)),
                    bytes((0x30, 0x21, 0, mask, 0)),
                    bytes((0x30, 0x22, 0, group, group)),
                ],
            )
            self.assertEqual(context.clock, 5000)
            self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_abs14_four_exact_source_identities_and_cleanup_setters(self) -> None:
        for constant, setter in (
            ("NK12_SHA256", "native_rva:fa60"),
            ("NK18_SHA256", "native_rva:172d0"),
            ("NK_DS4_SHA256", "native_rva:32410"),
            ("NK_GTS_SHA256", "native_rva:33320"),
        ):
            blob = ("authored ABS14 " + constant).encode()
            digest = hashlib.sha256(blob).hexdigest()
            with (
                self.subTest(variant=constant),
                patch.object(chassis, constant, digest),
            ):
                context = self.context14()
                context.module_bytes, context.module_sha256 = blob, digest
                context.driver.replies.append((0, b"\x70"))
                self.assertEqual(
                    self.run_export("Ex2ABS_14_EndAirBleeding", context), 0
                )
                self.assertEqual(context.kinds, ["selected"])
                self.assertIn(("configure", setter, 150), context.driver.events)
                self.assertIn(("configure", setter, 100), context.driver.events)
                context.mode = 3
                context.driver.events.clear()
                self.assertEqual(
                    self.run_export("Ex2ABS_14_EndAirBleeding", context), 99
                )
                self.assertEqual(context.driver.events, [])

    def test_abs14_native_error_and_host_fault_cleanup(self) -> None:
        context = self.context14()
        context.driver.init_status = 17
        context.driver.replies.append((0, b"\x70"))
        self.assertEqual(self.run_export("Ex2ABS_14_StartRelayDrive", context), 17)
        self.assertEqual(self.exchanged(context), [b"\x30"])
        context = self.context14()
        context.cancelled = True
        self.assertEqual(
            self.run_export("Ex2ABS_14_StartSolenoidDrive", context, 1), 99
        )
        self.assertEqual(context.driver.events, [("finalize",)])
        context = self.context14()
        context.driver.replies.append((0, b"\x70\x21"))
        context.sleep_fault = TimeoutError("host deadline")
        with self.assertRaises(TimeoutError):
            self.run_export("Ex2ABS_14_StartSolenoidDrive", context, 1)
        self.assertEqual(context.driver.events[-1], ("finalize",))
        context = self.context14()
        context.driver.replies.append((0, b"\x70\0"))
        self.assertEqual(self.run_export("Ex2ABS_14_EndAirBleeding", context), 3)
        self.assertIn(("configure", "native_rva:172d0", 100), context.driver.events)

    def test_resurrection_after_first_success_retains_later_native_errors(self) -> None:
        context = FakeContext([(0, b"\x70\x0a"), (2, b"")])
        context.cancel_after_sleep = 2
        self.assertEqual(
            self.run_export("Ex2ABS_BeginAirBleed_Resurrection", context, 0x227), 2
        )
        self.assertEqual(self.exchanged(context), [b"\x30\x0a\x40\2"] * 2)
        self.assertEqual(context.sleeps, [1000, 1000])
        self.assertEqual(context.driver.events[-1], ("finalize",))
        context = FakeContext([(2, b"")])
        self.assertEqual(
            self.run_export("Ex2ABS_BeginAirBleed_Resurrection", context, 0), 2
        )
        self.assertEqual(context.sleeps, [])

    def test_direct_and_worker_stop_differ_in_cleanup_and_repetition(self) -> None:
        for name, selection, request in (
            ("Ex2ABS_EndAirBleed_TRC", 0x227, b"\x30\5\2\0"),
            ("Ex2ABS_EndSolenoidDrive_TRC", 0x229, b"\x30\x22\x0c\0\0"),
            ("Ex2ABS_EndSolenoidDrive_ABS", 0x232, b"\x30\x21\x20\0"),
        ):
            with self.subTest(name=name):
                context = FakeContext([(0, bytes((0x70, request[1])))])
                self.assertEqual(self.run_export(name, context, selection, 0), 0)
                self.assertEqual(self.exchanged(context), [request])
                self.assertNotIn(("finalize",), context.driver.events)
                context = FakeContext([(0, bytes((0x70, request[1]))), (2, b"")])
                self.assertEqual(self.run_export(name, context, selection, 1), 2)
                self.assertEqual(self.exchanged(context), [request, request])
                self.assertEqual(context.sleeps, [2000])
                self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_entry_counts_outputs_state_and_family_limits(self) -> None:
        for family, expected in (("03", 103), ("08", 0)):
            context = FakeContext([(0, b"\x61\xe5\x15\x13")])
            first, second = bytearray(4), bytearray(4)
            self.assertEqual(
                self.run_export(
                    f"Ex2SMRT_{family}_GetEntryKey", context, first, second
                ),
                expected,
            )
            self.assertEqual(
                (int.from_bytes(first, "little"), int.from_bytes(second, "little")),
                (5, 3),
            )
            self.assertEqual(context.state["nk.chassis.master_count"], 5)
            self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_entry_count_error_does_not_mutate_outputs_or_cache(self) -> None:
        for response in ((0, b"\x61\xe5"), (0, b"\x61\xe4\1\2"), (2, b"")):
            context = FakeContext([response])
            output = bytearray(b"same")
            status = self.run_export(
                "Ex2SMRT_03_GetEntryKey", context, output, bytearray(4)
            )
            self.assertEqual(status, response[0] or 3)
            self.assertEqual(output, b"same")
            self.assertEqual(context.state, {})

    def test_mode_entry_retains_session_end_closes_without_reinit(self) -> None:
        for family in ("03", "08"):
            context = FakeContext([(0, b"\xe5\xb2"), (0, b"\xe5\xb2")])
            self.assertEqual(self.run_export(f"Ex2SMRT_{family}_ModeEntry", context), 0)
            self.assertEqual(context.state["nk.chassis.entry_tick"], 1000)
            self.assertNotIn(("finalize",), context.driver.events)
            self.assertEqual(self.run_export(f"Ex2SMRT_{family}_ModeEnd", context), 0)
            self.assertEqual(self.exchanged(context), [b"\xa5\xb2\x20", b"\xa5\xb2\0"])
            self.assertEqual(context.driver.events.count(("initialize", 0)), 1)
            self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_mode_malformed_or_init_failure_closes(self) -> None:
        for reply in (b"", b"\xe5\xb3", b"\xe5\xb2\0"):
            context = FakeContext([(0, reply)])
            self.assertEqual(self.run_export("Ex2SMRT_03_ModeEntry", context), 3)
            self.assertEqual(context.driver.events[-1], ("finalize",))
        context = FakeContext([])
        context.driver.init_status = 17
        self.assertEqual(self.run_export("Ex2SMRT_08_ModeEntry", context), 17)
        self.assertEqual(context.state, {})

    def test_master_check_polls_subflag_with_tick_wait(self) -> None:
        context = FakeContext([(0, b"\x61\xe5\1\x10"), (0, b"\x61\xe5\1\0")])
        context.state["nk.chassis.entry_tick"] = 1000
        self.assertEqual(self.run_export("Ex2SMRT_03_MasterKeyCheck", context), 0)
        self.assertEqual(context.sleeps, [30, 30, 30, 20, 35])
        self.assertNotIn(("finalize",), context.driver.events)

    def test_smart_complete_all03_business_results(self) -> None:
        for master, sub, expected in (
            (6, 0, 103),
            (1, 3, 103),
            (0x11, 1, 100),
            (5, 2, 101),
            (3, 1, 102),
            (2, 2, 102),
        ):
            context = FakeContext([(0, bytes((0x61, 0xE5, master, sub)))])
            context.state.update(
                {"nk.chassis.master_count": 2, "nk.chassis.sub_count": 1}
            )
            self.assertEqual(
                self.run_export("Ex2SMRT_03_CompleteCheck", context, 0), expected
            )
            self.assertEqual(("finalize",) in context.driver.events, expected == 103)

    def test_smart_complete08_uses_master_flag_and_mode(self) -> None:
        for master, sub, mode, expected in (
            (6, 0, 0x6C, 103),
            (0x11, 0, 0x6C, 100),
            (5, 0, 0x6C, 101),
            (3, 0, 0x6C, 102),
            (0x11, 0, 0, 104),
        ):
            context = FakeContext([(0, bytes((0x61, 0xE5, master, sub)))])
            context.state["nk.chassis.master_count"] = 2
            self.assertEqual(
                self.run_export("Ex2SMRT_08_CompleteCheck", context, 0, mode), expected
            )

    def test_smart_poll_cancel_and_host_deadline_cleanup(self) -> None:
        context = FakeContext([(0, b"\x61\xe5\1\0")])
        context.state.update({"nk.chassis.master_count": 2, "nk.chassis.sub_count": 1})
        context.cancel_after_sleep = 1
        self.assertEqual(self.run_export("Ex2SMRT_03_CompleteCheck", context, 0), 0)
        self.assertNotIn(("finalize",), context.driver.events)
        context = FakeContext([(0, b"\x61\xe5\1\x10")])
        context.sleep_fault = TimeoutError("host deadline")
        with self.assertRaises(TimeoutError):
            self.run_export("Ex2SMRT_08_MasterKeyCheck", context)
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_key32_native_count_statuses_and_zero_fill_boundary(self) -> None:
        for nibble, expected in (
            (0x10, 3000),
            (0x20, 3005),
            (0x30, 3006),
            (0x40, 3007),
            (0x50, 3008),
            (0x60, 3009),
        ):
            context = FakeContext([(0, b"\x61\x21" + bytes(5) + bytes((nibble | 7,)))])
            self.assertEqual(
                self.run_export("Ex2SMRT_32_GetRegKeyNum", context), expected
            )
            self.assertEqual(context.driver.events[-1], ("finalize",))
        for reply, expected in (
            (b"\x61\x21" + bytes(5), 3009),
            (b"\x61\x21" + bytes(4), 3),
            (b"\x61\x20" + bytes(6), 3),
        ):
            context = FakeContext([(0, reply)])
            self.assertEqual(
                self.run_export("Ex2SMRT_32_GetRegKeyNum", context), expected
            )

    def test_erase_get_has_no_registration_count_limit_or_shared_cache(self) -> None:
        context = FakeContext([(0, b"\x61\xe5\7\3")])
        first, second = bytearray(4), bytearray(4)
        self.assertEqual(
            self.run_export("Ex2SMRT_EraseGetKey", context, first, second), 0
        )
        self.assertEqual(
            (int.from_bytes(first, "little"), int.from_bytes(second, "little")), (7, 3)
        )
        self.assertEqual(context.state, {})
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_erase_entry_and_end_retain_native_session_on_success(self) -> None:
        context = FakeContext([(0, b"\xe5\xb3"), (0, b"\xe5\xb3")])
        self.assertEqual(self.run_export("Ex2SMRT_EraseModeEntry", context), 0)
        self.assertEqual(self.run_export("Ex2SMRT_EraseModeEnd", context), 0)
        self.assertEqual(self.exchanged(context), [b"\xa5\xb3\xc0", b"\xa5\xb3\0"])
        self.assertNotIn(("finalize",), context.driver.events)
        self.assertEqual(context.driver.events.count(("initialize", 0)), 1)

    def test_erase_mode_status_polls_flag_and_restores_timeout(self) -> None:
        context = FakeContext([(0, b"\x61\xe5\1\x10"), (0, b"\x61\xe5\1\0")])
        self.assertEqual(self.run_export("Ex2SMRT_EraseModeStatus", context), 0)
        self.assertEqual(context.sleeps, [100])
        self.assertIn(
            ("configure", "native_rva:172d0", 0xFFFFFFFF), context.driver.events
        )
        self.assertIn(("configure", "native_rva:172d0", 100), context.driver.events)
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_erase_key_status_observation_then_sends_mode_end(self) -> None:
        context = FakeContext(
            [(0, b"\x61\xe5\2\1"), (0, b"\x61\xe5\1\0"), (0, b"\xe5\xb3")]
        )
        self.assertEqual(self.run_export("Ex2SMRT_EraseKeyStatus", context), 0)
        self.assertEqual(
            self.exchanged(context), [b"\x21\xe5", b"\x21\xe5", b"\xa5\xb3\0"]
        )
        self.assertEqual(context.sleeps, [100])
        self.assertEqual(context.state["nk.chassis.progress_timeout"], 0)

    def test_erase_cancel_before_observation_and_timeout_setter(self) -> None:
        context = FakeContext([])
        context.cancelled = True
        self.assertEqual(self.run_export("Ex2SMRT_EraseModeStatus", context), 8)
        self.assertEqual(self.exchanged(context), [])
        context = FakeContext([])
        self.assertEqual(self.run_export("Ex2SMRT_SetProgressTimeOutFlg", context), 0)
        self.assertEqual(context.kinds, [])
        self.assertEqual(self.run_export("Ex2SMRT_EraseKeyStatus", context), 8)
        self.assertEqual(context.state["nk.chassis.progress_timeout"], 0)

    def test_erase_timeout_after_observation_sends_end_and_reports103(self) -> None:
        context = FakeContext([(0, b"\x61\xe5\2\1"), (0, b"\xe5\xb3")])
        original_sleep = context.sleep

        def timeout_during_sleep(ms: int) -> None:
            original_sleep(ms)
            self.run_export("Ex2SMRT_SetProgressTimeOutFlg", context)

        context.sleep = timeout_during_sleep
        self.assertEqual(self.run_export("Ex2SMRT_EraseKeyStatus", context), 103)
        self.assertEqual(self.exchanged(context)[-1], b"\xa5\xb3\0")
        self.assertEqual(context.state["nk.chassis.progress_timeout"], 0)

    def test_erase_read_fault_restores_timeout_and_closes(self) -> None:
        context = FakeContext([])
        context.driver.fault = OSError("wire failure")
        with self.assertRaises(OSError):
            self.run_export("Ex2SMRT_EraseModeStatus", context)
        self.assertIn(("finalize",), context.driver.events)
        self.assertEqual(
            context.driver.events[-1], ("configure", "native_rva:172d0", 100)
        )

    def test12_source_mapping_and_selected_address_are_distinct_from_init_flag(
        self,
    ) -> None:
        synthetic12 = b"authored12 source identity"
        digest12 = hashlib.sha256(synthetic12).hexdigest()
        with patch.object(chassis, "NK12_SHA256", digest12):
            context = FakeContext([(0, b"\x61\xe5\1\0")])
            context.module_bytes = synthetic12
            context.module_sha256 = digest12
            self.assertEqual(
                self.run_export(
                    "Ex2SMRT_03_GetEntryKey", context, bytearray(4), bytearray(4)
                ),
                0,
            )
            self.assertIn(
                ("configure", "native_global:ea978", 64), context.driver.events
            )
            self.assertIn(
                ("configure", "native_global:ea97c", 0), context.driver.events
            )
            self.assertIn(("initialize", 0), context.driver.events)
            context = FakeContext([(2, b"")])
            context.module_bytes = synthetic12
            context.module_sha256 = digest12
            self.assertEqual(self.run_export("Ex2ABS_BeginAirBleed_TRC", context, 0), 2)
            for field, value in (
                ("fa60", 100),
                ("fa80", 1),
                ("fa90", 1),
                ("fa80", 3),
                ("fa90", 100),
            ):
                self.assertIn(
                    ("configure", "native_rva:" + field, value), context.driver.events
                )

    def test_host_fault_during_erase_termination_closes_and_resets_flag(self) -> None:
        context = FakeContext([(0, b"\x61\xe5\1\0")])
        original = context.driver.exchange

        def fault_on_termination(request: bytes) -> tuple[int, bytes]:
            if request[0] == 0xA5:
                raise OSError("termination receive failed")
            return original(request)

        context.driver.exchange = fault_on_termination
        with self.assertRaises(OSError):
            self.run_export("Ex2SMRT_EraseKeyStatus", context)
        self.assertEqual(context.driver.events[-1], ("finalize",))
        self.assertEqual(context.state["nk.chassis.progress_timeout"], 0)

    def test_ds4_gts_exact_profile_config_mapping(self) -> None:
        for constant, delay, retry, pending, address, extended in (
            ("NK_DS4_SHA256", "32410", "32480", "32450", "1b8ad8", "1b8adc"),
            ("NK_GTS_SHA256", "33320", "33390", "33360", "1c8008", "1c800c"),
        ):
            with self.subTest(source=constant):
                content = ("authored " + constant).encode()
                digest = hashlib.sha256(content).hexdigest()
                with patch.object(chassis, constant, digest):
                    context = FakeContext([(0, b"\x61\xe5\1\0")])
                    context.module_bytes = content
                    context.module_sha256 = digest
                    self.assertEqual(
                        self.run_export(
                            "Ex2SMRT_03_GetEntryKey",
                            context,
                            bytearray(4),
                            bytearray(4),
                        ),
                        0,
                    )
                    self.assertIn(
                        ("configure", "native_global:" + address, 64),
                        context.driver.events,
                    )
                    self.assertIn(
                        ("configure", "native_global:" + extended, 0),
                        context.driver.events,
                    )
                    context = FakeContext([(2, b"")])
                    context.module_bytes = content
                    context.module_sha256 = digest
                    self.assertEqual(
                        self.run_export("Ex2ABS_BeginAirBleed_TRC", context, 0), 2
                    )
                    for field, value in (
                        (delay, 100),
                        (retry, 1),
                        (pending, 1),
                        (retry, 3),
                        (pending, 100),
                    ):
                        self.assertIn(
                            ("configure", "native_rva:" + field, value),
                            context.driver.events,
                        )

    def test_key32_support_real_sequence_and_fail_closed_bit_checks(self) -> None:
        replies = [
            (0, b"\x61\x20\x80"),
            (0, b"\x61\xe0\0\1\x08"),
            (0, b"\x61\xf0\0\x44\0\0\0\xf0"),
            (0, b"\x61\xf5\xc0"),
            (0, b"\xe5\xb0\4"),
        ]
        context = FakeContext(replies)
        self.assertEqual(self.run_export("Ex2SMRT_32_GetSupportInfo", context), 0)
        self.assertEqual(
            self.exchanged(context),
            [b"\x21\x20", b"\x21\xe0", b"\x21\xf0", b"\x21\xf5", b"\xa5\xb0"],
        )
        self.assertEqual(context.driver.events[-1], ("finalize",))
        for index in range(5):
            broken = list(replies)
            payload = broken[index][1]
            broken[index] = (0, payload[:2] + bytes(len(payload) - 2))
            context = FakeContext(broken)
            self.assertEqual(self.run_export("Ex2SMRT_32_GetSupportInfo", context), 99)
            self.assertEqual(len(self.exchanged(context)), index + 1)
        for index in range(5):
            broken = list(replies)
            broken[index] = (0, b"\x61")
            context = FakeContext(broken)
            self.assertEqual(self.run_export("Ex2SMRT_32_GetSupportInfo", context), 3)

    def test_key32_start_keeps_session_and_checks_both_commands(self) -> None:
        context = FakeContext([(0, b"\xe5\xb6"), (0, b"\x61\x21" + bytes(4))])
        self.assertEqual(self.run_export("Ex2SMRT_32_StartEraseMode", context), 0)
        self.assertEqual(
            self.exchanged(context), [b"\xa5\xb6\x80" + bytes(5), b"\x21\x21"]
        )
        self.assertNotIn(("finalize",), context.driver.events)
        context = FakeContext([(0, b"\xe5\xb6"), (0, b"\x61\x21" + bytes(3))])
        self.assertEqual(self.run_export("Ex2SMRT_32_StartEraseMode", context), 3)

    def test_key32_end_ignores_wire_status_restores_short_mode_and_closes(self) -> None:
        context = FakeContext([(27, b"")])
        self.assertEqual(self.run_export("Ex2SMRT_32_EndEraseMode", context, 7), 0)
        self.assertEqual(self.exchanged(context), [b"\xa5\xb6" + bytes(6)])
        for field, value in (
            ("17ba0", 1),
            ("17ba0", 0),
            ("172d0", 100),
            ("17320", 100),
            ("172f0", 3),
        ):
            self.assertIn(
                ("configure", "native_rva:" + field, value), context.driver.events
            )
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_key32_end_preserves_exact_source_wrapper_arity(self) -> None:
        for constant in (
            "NK12_SHA256",
            "NK18_SHA256",
            "NK_DS4_SHA256",
            "NK_GTS_SHA256",
        ):
            blob = ("authored wrapper identity " + constant).encode()
            digest = hashlib.sha256(blob).hexdigest()
            legacy = constant in ("NK12_SHA256", "NK18_SHA256")
            with (
                self.subTest(variant=constant),
                patch.object(chassis, constant, digest),
            ):
                context = FakeContext([(19, b"")])
                context.module_sha256, context.module_bytes = digest, blob
                wrong = () if legacy else (7,)
                with self.assertRaises(ValueError):
                    self.run_export("Ex2SMRT_32_EndEraseMode", context, *wrong)
                self.assertEqual(context.kinds, [])
                arguments = (7,) if legacy else ()
                self.assertEqual(
                    self.run_export("Ex2SMRT_32_EndEraseMode", context, *arguments), 0
                )
                self.assertEqual(self.exchanged(context), [b"\xa5\xb6" + bytes(6)])
                self.assertEqual(context.driver.events[-1], ("finalize",))
                context = FakeContext([])
                context.module_sha256, context.module_bytes = digest, blob
                context.mode = 4
                self.assertEqual(
                    self.run_export("Ex2SMRT_32_EndEraseMode", context, *arguments), 99
                )
                self.assertEqual(context.kinds, [])

    def test_key32_status003_success_retains_session_error_ends_it(self) -> None:
        context = FakeContext([(0, b"\x61\x21" + bytes(4))])
        self.assertEqual(
            self.run_export("Ex2SMRT_32_GetTheKeyStatus_003", context), 3001
        )
        self.assertNotIn(("finalize",), context.driver.events)
        context = FakeContext([(0, b"\x61\x21"), (2, b"")])
        self.assertEqual(self.run_export("Ex2SMRT_32_GetTheKeyStatus_003", context), 3)
        self.assertEqual(self.exchanged(context)[-1], b"\xa5\xb6" + bytes(6))
        context = FakeContext([(3001, b"")])
        self.assertEqual(
            self.run_export("Ex2SMRT_32_GetTheKeyStatus_003", context), 3001
        )
        self.assertNotIn(("finalize",), context.driver.events)

    def test_key32_status005_count_and_elapsed_branches(self) -> None:
        for nibble, flag, elapsed, expected in (
            (0x10, 0, 0, 3002),
            (0, 4, 30001, 3003),
            (0, 0, 30001, 3004),
        ):
            context = FakeContext(
                [(0, bytes((0x61, 0x21, 0, flag, 0, 0, 0, nibble))), (0, b"ignored")]
            )
            self.advance_clock_on_exchange(context, elapsed)
            self.assertEqual(
                self.run_export("Ex2SMRT_32_GetTheKeyStatus_005", context), expected
            )
            self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_key32_cancellation_still_sends_native_end_and_host_fault_restores(
        self,
    ) -> None:
        context = FakeContext([(2, b"")])
        context.cancelled = True
        self.assertEqual(self.run_export("Ex2SMRT_32_GetTheKeyStatus_003", context), 0)
        self.assertEqual(self.exchanged(context), [b"\xa5\xb6" + bytes(6)])
        context = FakeContext([])
        context.driver.fault = OSError("wire failure")
        with self.assertRaises(OSError):
            self.run_export("Ex2SMRT_32_EndEraseMode", context, 0)
        self.assertIn(("configure", "native_rva:17ba0", 0), context.driver.events)
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_key32_timeout12_nibble_delta_from18_bit_test(self) -> None:
        synthetic12 = b"authored12 mask difference"
        digest12 = hashlib.sha256(synthetic12).hexdigest()
        with patch.object(chassis, "NK12_SHA256", digest12):
            for use12, expected in ((False, 3003), (True, 3004)):
                context = FakeContext([(0, b"\x61\x21\0\5" + bytes(4)), (0, b"")])
                if use12:
                    context.module_bytes = synthetic12
                    context.module_sha256 = digest12
                self.advance_clock_on_exchange(context, 30001)
                self.assertEqual(
                    self.run_export("Ex2SMRT_32_GetTheKeyStatus_005", context), expected
                )

    def structure31(self, mode: int, initialize: int = 0, close: int = 0) -> bytearray:
        return bytearray(
            initialize.to_bytes(4, "little")
            + close.to_bytes(4, "little")
            + bytes((mode, 0, 0, 0, 0))
        )

    def test_key31_support_masks_status_mapping_and_init_failure(self) -> None:
        replies = [
            (0, b"\x61\x20\x80"),
            (0, b"\x61\xe0\0\1\x08"),
            (0, bytes((0x61, 0xF0, 0xC0, 0x64, 0x8F, 0, 0xF0, 0xF0))),
            (0, b"\x61\xf5\xc0"),
            (0, b"\xe5\xb0\4"),
        ]
        context = FakeContext(replies)
        self.assertEqual(self.run_export("Ex2SMRT_31_GetSupportInfo", context), 0)
        for index in range(5):
            broken = list(replies)
            broken[index] = (0, broken[index][1][:2] + bytes(len(broken[index][1]) - 2))
            context = FakeContext(broken)
            self.assertEqual(
                self.run_export("Ex2SMRT_31_GetSupportInfo", context),
                3102 if index == 4 else 3101,
            )
        context = FakeContext([])
        context.driver.init_status = 4
        self.assertEqual(self.run_export("Ex2SMRT_31_GetSupportInfo", context), 3103)
        self.assertEqual(self.exchanged(context), [])
        self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_key31_status_writes_native_fields_and_clamps_counts(self) -> None:
        for payload, expected in (
            (bytes((0x40, 4, 2, 0, 0x30, 0x50)), b"\5\2\3\1"),
            (bytes((0x40, 0, 15, 0, 0xF0, 0xF0)), bytes(4)),
        ):
            context = FakeContext([(0, b"\x61\x21" + payload)])
            structure = self.structure31(1, 1, 1)
            self.assertEqual(
                self.run_export("Ex2SMRT_31_GetTheKeyStatus", context, structure), 0
            )
            self.assertEqual(structure[9:13], expected)
            self.assertIn(("initialize", 0), context.driver.events)
            self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_key31_status_all_six_poll_modes(self) -> None:
        cases = (
            (2, bytes((0, 0x20, 0, 0, 0, 0)), bytes(6), 0),
            (3, bytes((0x40, 0x40, 0, 0, 0, 0)), bytes((0x40, 0, 0, 0, 0, 0)), 0),
            (4, bytes((0x40, 0, 0, 0, 0x10, 0)), bytes((0x40, 0, 0, 0, 0x20, 0)), 0),
            (5, bytes((0x40, 0, 0, 0, 0, 0)), bytes(6), 3109),
            (6, bytes(6), bytes((0, 0, 0x80, 0, 0, 0)), 0),
            (7, bytes((0x40, 0, 2, 0, 0, 0)), bytes((0x40, 0, 1, 0, 0, 0)), 0),
        )
        for mode, first, second, expected in cases:
            with self.subTest(mode=mode):
                context = FakeContext(
                    [(0, b"\x61\x21" + first), (0, b"\x61\x21" + second)]
                )
                structure = self.structure31(mode, close=1)
                self.assertEqual(
                    self.run_export("Ex2SMRT_31_GetTheKeyStatus", context, structure),
                    expected,
                )
                self.assertEqual(len(self.exchanged(context)), 2)

    def test_key31_read_errors_map_and_choose_native_cleanup(self) -> None:
        for mode, close, expected, closed in ((1, 0, 3105, True), (3, 1, 3104, False)):
            context = FakeContext([(2, b"")])
            structure = self.structure31(mode, close=close)
            self.assertEqual(
                self.run_export("Ex2SMRT_31_GetTheKeyStatus", context, structure),
                expected,
            )
            self.assertEqual(structure[9:13], bytes(4))
            self.assertEqual(("finalize",) in context.driver.events, closed)

    def test_key31_failed_init_preserves_outputs_cancel_before_init_has99(self) -> None:
        context = FakeContext([])
        context.driver.init_status = 7
        structure = self.structure31(1, 1, 1)
        structure[9:13] = b"keep"
        self.assertEqual(
            self.run_export("Ex2SMRT_31_GetTheKeyStatus", context, structure), 3103
        )
        self.assertEqual(structure[9:13], b"keep")
        context = FakeContext([])
        context.cancelled = True
        structure = self.structure31(3, 2, 0)
        self.assertEqual(
            self.run_export("Ex2SMRT_31_GetTheKeyStatus", context, structure), 99
        )
        self.assertEqual(context.driver.events, [])

    def test_key31_request_and_checked_termination_keep_or_close_session(self) -> None:
        flag = bytearray(4)
        context = FakeContext([(0, b"\xe5\xb6"), (0, b"\xe5\xb6")])
        self.assertEqual(
            self.run_export("Ex2SMRT_31_RequestKeyCodeRegistration", context, flag), 0
        )
        self.assertEqual(
            self.run_export("Ex2SMRT_31_TerminateKeyCodeRegistration", context, flag), 0
        )
        self.assertEqual(
            self.exchanged(context),
            [b"\xa5\xb6\x40" + bytes(5), b"\xa5\xb6" + bytes(6)],
        )
        self.assertNotIn(("finalize",), context.driver.events)
        for name, expected in (
            ("RequestKeyCodeRegistration", 3107),
            ("TerminateKeyCodeRegistration", 3108),
        ):
            context = FakeContext([(0, b"\xe5\xff")])
            self.assertEqual(
                self.run_export("Ex2SMRT_31_" + name, context, flag), expected
            )
            self.assertEqual(context.driver.events[-1], ("finalize",))

    def test_key31_no_check_termination_and_malformed_input(self) -> None:
        for name in (
            "TerminateKeyCodeRegistrationNoChk",
            "TerminateKeyCodeRegistrationNoChkOnce",
        ):
            context = FakeContext([(27, b"")])
            self.assertEqual(self.run_export("Ex2SMRT_31_" + name, context), 0)
            self.assertEqual(context.driver.events[-1], ("finalize",))
        context = FakeContext([])
        with self.assertRaises(ValueError):
            self.run_export("Ex2SMRT_31_GetTheKeyStatus", context, bytearray(12))
        with self.assertRaises(ValueError):
            self.run_export("Ex2SMRT_31_RequestKeyCodeRegistration", context, b"\0" * 4)
        self.assertEqual(context.kinds, [])

    def test_key31_preserves_trailing_storage_and_cancelled_pending_status(
        self,
    ) -> None:
        context = FakeContext([(0, b"\x61\x21" + bytes(6))])
        structure = self.structure31(1) + b"extra"
        self.assertEqual(
            self.run_export("Ex2SMRT_31_GetTheKeyStatus", context, structure), 0
        )
        self.assertEqual(structure[13:], b"extra")
        context = FakeContext([(0, b"\x61\x21\0\x20" + bytes(4))])
        original = context.driver.exchange

        def cancel_after_read(request: bytes) -> tuple[int, bytes]:
            result = original(request)
            context.cancelled = True
            return result

        context.driver.exchange = cancel_after_read
        self.assertEqual(
            self.run_export("Ex2SMRT_31_GetTheKeyStatus", context, self.structure31(2)),
            3199,
        )


if __name__ == "__main__":
    unittest.main()
