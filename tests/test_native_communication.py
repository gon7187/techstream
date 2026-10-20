"""Literal selected Common transactions, with no device or vendor execution."""

import struct
import tempfile
import unittest
from dataclasses import dataclass, replace
from pathlib import Path

from test_frame_transport import DRIVER, selected_profile
from test_frame_transport_variants import EthernetPrimitive, ethernet_profile
from test_profiles import encode_database

from scripts.diagnostic_db import parse_database
from scripts.frame_transport import J2534Result, NativeMessage
from scripts.native_communication import (
    NO_RESPONSE,
    PARTIAL_RESPONSE,
    TIMEOUT,
    NativeCommunication,
    NativeFrameController,
    receive_timeout,
    wwh_request_state,
)
from scripts.profiles import ProtocolProfile
from scripts.support import ProtocolCandidate
from scripts.toyota import ToyotaCodecError
from scripts.toyota_session import Cancelled, Limits, NativeFrameSend, SessionError


@dataclass
class Reply:
    code: int | None
    data: bytes = b""


class Primitives:
    def __init__(self, replies=(), sends=()):
        self.replies, self.sends = list(replies), list(sends)
        self.calls = []

    def send(self, request, **kwargs):
        self.calls.append(("send", request, kwargs))
        return self.sends.pop(0) if self.sends else 0

    def receive(self, **kwargs):
        self.calls.append(("receive", kwargs))
        return self.replies.pop(0)

    def close(self):
        self.calls.append(("close",))


class J2534Fixture:
    def __init__(self, replies, write_codes=(), disconnect_codes=()):
        self.disconnect_codes = list(disconnect_codes)
        self.write_codes = list(write_codes)
        self.replies = list(replies)
        self.calls = []
        self.handle = 100

    def invoke(self, operation, fields, *, deadline, cancelled):
        self.calls.append((operation, dict(fields)))
        if operation == "connect":
            return J2534Result(handle=41)
        if operation == "disconnect" and self.disconnect_codes:
            return J2534Result(code=self.disconnect_codes.pop(0))
        if operation == "start_message_filter":
            self.handle += 1
            return J2534Result(handle=self.handle)
        if operation == "write_messages":
            code = self.write_codes.pop(0) if self.write_codes else 0
            return J2534Result(code=code, count=0 if code else 1)
        if operation == "read_messages":
            return self.replies.pop(0)
        return J2534Result()


def frame(request=b"\x22\xf1\x90", retries=0, mask=b"", check=b""):
    return serialized_profile(
        request=request, retries=retries, mask=mask, check=check
    ).direct_frame(0, 1)


def serialized_profile(
    *,
    version=18,
    bus=0x12,
    flags=1,
    request=b"\x22\xf1\x90",
    mask=b"\xff",
    check=b"\x62",
    retries=0,
):
    profile = selected_profile(bus=bus, version=version, flags=flags)
    sections = {
        slot: (section.count, section.payload)
        for slot, section in profile.catalog.management.sections.items()
    }
    values = (b"\x10\x01", b"\x81", b"\x3e", b"\x81", request, mask, check)
    directory, storage = bytearray(), bytearray()
    for value in values:
        directory += struct.pack("<IH", len(storage), len(value))
        storage += value
    sections[0] = (len(values), bytes(directory + storage))
    count, frames = sections[17]
    sections[17] = (count + 1, frames + struct.pack("<4H", 0, 5, 6, 7))
    settings = bytearray(16)
    struct.pack_into("<II", settings, 0, 120, 350)
    struct.pack_into("<H", settings, 10, 1)
    settings[14] = retries
    sections[29] = (1, bytes(settings))
    serialized = bytearray(encode_database(1, sections))
    struct.pack_into("<I", serialized, 28, profile.catalog.management.version)
    profile.catalog.management = parse_database(bytes(serialized))
    return profile


class CommonTransactions(unittest.TestCase):
    def test_management_only_protocol_profile_probes_without_an_ecu_database(self):
        for version, fault in (
            (version, fault) for version in (12, 18) for fault in (False, True)
        ):
            with self.subTest(version=version, fault=fault):
                full = serialized_profile(version=version, request=b"")
                profile = ProtocolProfile(full.catalog, full.category_record)
                self.assertFalse(hasattr(profile, "database"))
                backend = J2534Fixture(
                    []
                    if fault
                    else [
                        J2534Result(
                            count=1,
                            messages=(
                                NativeMessage(
                                    6, 0, 0, 0, 0, bytes.fromhex("000007e85001")
                                ),
                            ),
                        )
                    ],
                    write_codes=(5,) if fault else (),
                )
                cancelled = [False]
                runtime = NativeCommunication.from_backend(
                    profile,
                    backend,
                    "management-only",
                    first_request=b"",
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x12,
                    source_build=version,
                    clock=lambda: 0.0,
                    cancelled=lambda cancelled=cancelled: cancelled[0],
                )
                self.assertIsNone(runtime.cache.identity[1])
                selection = runtime.check_protocol([ProtocolCandidate(42, 0x12, 1)])
                self.assertEqual(selection is None, fault)
                before = len(backend.calls)
                cancelled[0] = True
                with self.assertRaises(Cancelled):
                    runtime.check_protocol([ProtocolCandidate(42, 0x12, 1)])
                self.assertEqual(len(backend.calls), before)
                cancelled[0] = False
                runtime.close()

    def test_completed_rebuild_connect_failure_allows_next_selected_constructor(self):
        class FailedSecondConnect(J2534Fixture):
            connects = 0
            block_cleanup = False

            def invoke(self, operation, fields, *, deadline, cancelled):
                if operation == "connect":
                    self.connects += 1
                    if self.connects == 2:
                        self.calls.append((operation, dict(fields)))
                        return J2534Result(
                            code=5, handle=77 if self.block_cleanup else None
                        )
                if (
                    operation == "disconnect"
                    and fields["channel_id"] == 77
                    and self.block_cleanup
                ):
                    self.calls.append((operation, dict(fields)))
                    return J2534Result(code=5)
                return super().invoke(
                    operation, fields, deadline=deadline, cancelled=cancelled
                )

        for version, block_cleanup in (
            (version, block) for version in (12, 18) for block in (False, True)
        ):
            with self.subTest(version=version, block_cleanup=block_cleanup):
                profile = serialized_profile(version=version)
                sections = {
                    slot: (section.count, section.payload)
                    for slot, section in profile.catalog.management.sections.items()
                }
                _, can = sections[13]
                iso = bytearray(can)
                iso[22 if version == 12 else 24] = 0x11
                sections[13] = 2, bytes(iso) + can
                encoded = bytearray(encode_database(1, sections))
                struct.pack_into("<I", encoded, 28, profile.catalog.management.version)
                profile.catalog.management = parse_database(bytes(encoded))
                backend = FailedSecondConnect([])
                backend.block_cleanup = block_cleanup
                owner = NativeCommunication.from_backend(
                    profile,
                    backend,
                    "retained-before-probe",
                    first_request=b"\x22\xf1\x90",
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x12,
                    source_build=version,
                    clock=lambda: 0.0,
                )
                iso_context = owner.protocol_context(profile, bus_id=0x11)
                can_send = NativeFrameSend(
                    "SendIntNoInit", 42, b"\x22\xf1\x90", 1000, 0x12
                )
                self.assertEqual(owner.send_native(can_send), 0)
                self.assertEqual(
                    iso_context.send_native(
                        NativeFrameSend(
                            "SendIntNoInit", 42, b"\x22\xf1\x90", 1000, 0x11
                        )
                    ),
                    0x91010005,
                )
                self.assertEqual(
                    owner.send_native(can_send), 0x90020701 if block_cleanup else 0
                )
                self.assertEqual(backend.connects, 2 if block_cleanup else 3)
                writes = [
                    fields["messages"][0].data
                    for op, fields in backend.calls
                    if op == "write_messages"
                ]
                self.assertEqual(
                    writes,
                    [bytes.fromhex("000007e022f190")] * (1 if block_cleanup else 2),
                )
                backend.block_cleanup = False
                self.assertEqual(owner.close(), 0)
                self.assertEqual(
                    sum(op == "disconnect" for op, _ in backend.calls),
                    4 if block_cleanup else 2,
                )

    def test_shared_controller_ever_cache_ignores_display_name_and_bus_variant(self):
        for version in (12, 18):
            with self.subTest(version=version):
                profile = serialized_profile(version=version)
                backend = J2534Fixture(
                    [
                        J2534Result(
                            count=1,
                            messages=(
                                NativeMessage(6, 0, 0, 0, 0, bytes.fromhex(payload)),
                            ),
                        )
                        for payload in ("000007e85001", "000007e862f19042")
                    ]
                )
                owner = NativeCommunication.from_backend(
                    profile,
                    backend,
                    "display-one",
                    first_request=b"\x22\xf1\x90",
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x12,
                    source_build=version,
                    clock=lambda: 0.0,
                )
                assert isinstance(owner.operations, NativeFrameController)
                owner.operations.operations.force_initialization = True
                sibling = owner.share_context(
                    profile, "display-two", bus_id=0x62, first_request=b"\x22\xf1\x90"
                )
                selected = profile.direct_frame(0, 1)
                self.assertEqual(
                    owner.cache.transaction(selected, selected.frame.request),
                    b"\x62\xf1\x90\x42",
                )
                before = len(backend.calls)
                self.assertEqual(
                    sibling.cache.transaction(
                        selected, selected.frame.request, native_parameter=0x62
                    ),
                    b"\x62\xf1\x90\x42",
                )
                self.assertTrue(sibling.cache.cache_hit)
                self.assertEqual(len(backend.calls), before)
                writes = [
                    fields["messages"][0].data
                    for op, fields in backend.calls
                    if op == "write_messages"
                ]
                self.assertEqual(
                    writes,
                    [bytes.fromhex("000007e01001"), bytes.fromhex("000007e022f190")],
                )
                foreign = serialized_profile(version=version, request=b"\x22\xf1\x91")
                with self.assertRaisesRegex(SessionError, "another selected source"):
                    owner.share_context(
                        foreign, "foreign", bus_id=0x12, first_request=b"\x22\xf1\x91"
                    )
                owner.close()

    def test_no_buffer_local_flags_are_fresh_but_supplied_nonempty_cache_retains_flags(
        self,
    ):
        for version, empty, temporary in (
            (version, empty, temporary)
            for version in (12, 18)
            for empty in (False, True)
            for temporary in (False, True)
        ):
            with self.subTest(version=version, empty=empty, temporary=temporary):
                profile = serialized_profile(
                    version=version, request=b"" if empty else b"\x22\xf1\x90"
                )
                payloads = ["000007e85001"] if empty or not temporary else []
                if not empty:
                    payloads.append("000007e862f19042")
                backend = J2534Fixture(
                    [
                        J2534Result(
                            count=1,
                            messages=(
                                NativeMessage(6, 0, 0, 0, 0, bytes.fromhex(payload)),
                            ),
                        )
                        for payload in payloads
                    ]
                    + [J2534Result(code=9)]
                )
                runtime = NativeCommunication.from_backend(
                    profile,
                    backend,
                    "no-buffer-flags",
                    first_request=b"\x22\xf1\x90",
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x12,
                    source_build=version,
                    clock=lambda: 0.0,
                )
                assert isinstance(runtime.operations, NativeFrameController)
                runtime.operations.operations.force_initialization = True
                runtime.no_init = runtime.no_session = True
                self.assertTrue(
                    runtime.connection_no_buffer(temporary=temporary).connected
                )
                self.assertEqual((runtime.no_init, runtime.no_session), (True, True))
                writes = [
                    fields["messages"][0].data
                    for op, fields in backend.calls
                    if op == "write_messages"
                ]
                expected = (
                    [bytes.fromhex("000007e01001")] if empty or not temporary else []
                )
                if not empty:
                    expected.append(bytes.fromhex("000007e022f190"))
                self.assertEqual(writes, expected)
                runtime.close()

    def test_standard_connect_records_actual_bytes_and_cache_hit_does_not_drain(self):
        for version in (12, 18):
            with self.subTest(version=version):
                profile = serialized_profile(version=version)
                backend = J2534Fixture(
                    [
                        J2534Result(
                            count=1,
                            messages=(
                                NativeMessage(
                                    6, 0, 0, 0, 0, bytes.fromhex("000007e862f19042")
                                ),
                            ),
                        )
                    ]
                )
                runtime = NativeCommunication.from_backend(
                    profile,
                    backend,
                    "connection",
                    first_request=b"\x22\xf1\x90",
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x12,
                    source_build=version,
                    clock=lambda: 0.0,
                )
                assert isinstance(runtime.operations, NativeFrameController)
                runtime.no_init = runtime.no_session = True
                runtime.operations.operations.force_initialization = True
                backend.replies.insert(
                    0,
                    J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(6, 0, 0, 0, 0, bytes.fromhex("000007e85001")),
                        ),
                    ),
                )
                actual = runtime.connection_check()
                self.assertEqual((runtime.no_init, runtime.no_session), (True, True))
                self.assertEqual(
                    (actual.status, actual.connected, actual.cache_hit),
                    (0, True, False),
                )
                (entry,) = runtime.connection_entries
                self.assertEqual(
                    (
                        entry.category,
                        entry.variant,
                        entry.supported,
                        entry.protocol,
                        entry.request,
                        entry.reply,
                    ),
                    (42, 0x12, 1, 1, b"\x22\xf1\x90", b"\x62\xf1\x90\x42"),
                )
                before = len(backend.calls)
                self.assertTrue(runtime.connection_check().cache_hit)
                selected = runtime.check_protocol([ProtocolCandidate(42, 0x12, 1)])
                self.assertIsNotNone(selected)
                assert selected is not None
                self.assertEqual(selected.protocol, 0)
                self.assertEqual(len(backend.calls), before)
                self.assertEqual(
                    sum(op == "read_messages" for op, _ in backend.calls), 2
                )
                sibling = runtime.protocol_context(profile, bus_id=0x12)
                runtime.connect_set(42, 0, 0x12, 2)
                self.assertEqual(runtime.connection_entries, (entry,))
                sibling.connect_set(42, 0, 0x32, 4)
                runtime.connect_set(42, -1, 0x22, 5, overwrite=True)
                rewritten, appended = runtime.connection_entries
                self.assertEqual(
                    (
                        rewritten.variant,
                        rewritten.supported,
                        rewritten.protocol,
                        rewritten.request,
                        rewritten.reply,
                    ),
                    (0x22, -1, 5, entry.request, entry.reply),
                )
                self.assertEqual(
                    (appended.variant, appended.request, appended.reply),
                    (0x32, b"", b""),
                )
                sibling.clear_connection_buffer()
                self.assertEqual(runtime.connection_entries, ())
                backend.replies.extend(
                    (
                        J2534Result(
                            count=1,
                            messages=(
                                NativeMessage(
                                    6, 0, 0, 0, 0, bytes.fromhex("000007e862f19042")
                                ),
                            ),
                        ),
                        J2534Result(code=9),
                    )
                )
                self.assertTrue(runtime.connection_no_buffer().connected)
                self.assertEqual(runtime.connection_entries, ())
                backend.replies.extend(
                    J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(6, 0, 0, 0, 0, bytes.fromhex(payload)),
                        ),
                    )
                    for payload in ("000007e862f19011", "000007e862f19012")
                )
                self.assertTrue(runtime.comm_connection().connected)
                self.assertTrue(runtime.comm_connection().connected)
                self.assertEqual(
                    [item.reply[-1] for item in runtime.connection_entries],
                    [0x11, 0x12],
                )
                runtime.close()

    def test_standard_connection_mask_mismatch_is_retained_native_negative(self):
        profile = serialized_profile(check=b"\x63")
        backend = J2534Fixture(
            [
                J2534Result(
                    count=1,
                    messages=(
                        NativeMessage(6, 0, 0, 0, 0, bytes.fromhex("000007e862f19042")),
                    ),
                )
            ]
        )
        runtime = NativeCommunication.from_backend(
            profile,
            backend,
            "negative",
            first_request=b"\x22\xf1\x90",
            driver=DRIVER,
            device_kind=8,
            bus_id=0x12,
            source_build=18,
            clock=lambda: 0.0,
        )
        first = runtime.connection_check()
        self.assertEqual(
            (first.status, first.connected, first.cache_hit), (0, False, False)
        )
        (entry,) = runtime.connection_entries
        self.assertEqual((entry.supported, entry.reply), (0, b"\x62\xf1\x90\x42"))
        before = len(backend.calls)
        second = runtime.connection_check()
        self.assertEqual(
            (second.status, second.connected, second.cache_hit), (0, False, True)
        )
        self.assertEqual(len(backend.calls), before)
        runtime.close()

    def test_standard_connection_undefined_receive_count_never_fabricates_entry(self):
        for empty in (False, True):
            with self.subTest(empty=empty):
                profile = serialized_profile(request=b"" if empty else b"\x22\xf1\x90")
                backend = J2534Fixture(
                    [
                        J2534Result(
                            count=1,
                            messages=(
                                NativeMessage(
                                    6, 0, 0, 0, 0, bytes.fromhex("000007e85001")
                                ),
                            ),
                        )
                    ]
                    if empty
                    else [],
                    write_codes=() if empty else (5,),
                )
                runtime = NativeCommunication.from_backend(
                    profile,
                    backend,
                    "undefined",
                    first_request=b"\x22\xf1\x90",
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x12,
                    source_build=18,
                    clock=lambda: 0.0,
                )
                with self.assertRaisesRegex(
                    SessionError, "receive count is source-undefined"
                ):
                    runtime.connection_check()
                self.assertEqual(runtime.connection_entries, ())
                runtime.close()

    def test_protocol_cache_miss_executes_actual_null_initialization_probe(self):
        for version, fault in (
            (version, fault) for version in (12, 18) for fault in (False, True)
        ):
            with self.subTest(version=version, fault=fault):
                profile = serialized_profile(version=version, request=b"")
                backend = J2534Fixture(
                    []
                    if fault
                    else [
                        J2534Result(
                            count=1,
                            messages=(
                                NativeMessage(
                                    6, 0, 0, 0, 0, bytes.fromhex("000007e85001")
                                ),
                            ),
                        )
                    ],
                    write_codes=(5,) if fault else (),
                )
                runtime = NativeCommunication.from_backend(
                    profile,
                    backend,
                    "probe",
                    first_request=b"",
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x12,
                    source_build=version,
                    clock=lambda: 0.0,
                )
                context = runtime.protocol_context(profile, bus_id=0x12)
                contexts = {(42, 0x12): context}
                candidates = [ProtocolCandidate(42, 0x12, 1)]
                if not fault:
                    candidates.append(ProtocolCandidate(99, 0x32, 1))
                selection = runtime.check_protocol(candidates, contexts=contexts)
                self.assertEqual(selection is None, fault)
                writes = [
                    fields["messages"][0].data
                    for op, fields in backend.calls
                    if op == "write_messages"
                ]
                self.assertEqual(writes, [bytes.fromhex("000007e01001")])
                if fault:
                    (entry,) = runtime.connection_entries
                    self.assertEqual(
                        (entry.supported, entry.protocol, entry.request, entry.reply),
                        (0, 1, b"", b""),
                    )
                    before = len(backend.calls)
                    self.assertIsNone(
                        runtime.check_protocol(candidates, contexts=contexts)
                    )
                    self.assertEqual(len(backend.calls), before)
                else:
                    self.assertEqual(runtime.connection_entries, ())
                runtime.close()

    def test_shared_controller_activates_selected_cache_misses_and_retains_one_channel(
        self,
    ):
        for version in (12, 18):
            with self.subTest(version=version):
                owner_profile = serialized_profile(version=version)
                target_profile = replace(owner_profile)
                backend = J2534Fixture(
                    [
                        J2534Result(
                            count=1,
                            messages=(
                                NativeMessage(6, 0, 0, 0, 0, bytes.fromhex(payload)),
                            ),
                        )
                        for payload in (
                            "000007e862f1900a",
                            "000007e862f1910b",
                            "000007e862f1920c",
                        )
                    ]
                )
                owner = NativeCommunication.from_backend(
                    owner_profile,
                    backend,
                    "owner",
                    first_request=b"\x22\xf1\x90",
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x12,
                    source_build=version,
                    clock=lambda: 0.0,
                )
                target = owner.share_context(
                    target_profile, "target", bus_id=0x12, first_request=b"\x22\xf1\x91"
                )
                assert isinstance(owner.operations, NativeFrameController)
                self.assertIs(owner.operations, target.operations)
                owner.begin_operation()
                target.begin_operation()
                own_frame, target_frame = (
                    owner_profile.direct_frame(0, 1),
                    target_profile.direct_frame(0, 1),
                )
                self.assertEqual(
                    owner.cache.transaction(own_frame, own_frame.frame.request),
                    b"\x62\xf1\x90\x0a",
                )
                self.assertEqual(
                    target.cache.transaction(target_frame, b"\x22\xf1\x91"),
                    b"\x62\xf1\x91\x0b",
                )
                self.assertIs(owner.operations.profile, target_profile)
                before_receive = len(backend.calls)
                with self.assertRaisesRegex(SessionError, "inactive shared context"):
                    owner.receive_native(maximum=255, timeout=0)
                self.assertEqual(len(backend.calls), before_receive)
                self.assertEqual(
                    owner.cache.transaction(own_frame, own_frame.frame.request),
                    b"\x62\xf1\x90\x0a",
                )
                self.assertIs(owner.operations.profile, target_profile)
                self.assertEqual(
                    owner.execute(own_frame, b"\x22\xf1\x92").response,
                    b"\x62\xf1\x92\x0c",
                )
                self.assertIs(owner.operations.profile, owner_profile)
                self.assertEqual(sum(op == "connect" for op, _ in backend.calls), 1)
                self.assertEqual(
                    sum(op == "write_messages" for op, _ in backend.calls), 3
                )
                self.assertEqual(owner.disconnect(1), 0)
                self.assertIsNone(owner.operations.operations.channel)

    def test_ethernet_context_checks_actual_session_and_reopens_only_non_two(self):
        for state, code, direct in (
            (state, code, direct)
            for state, code in ((2, 0), (2, 9), (0, 0), (0, 9))
            for direct in (False, True)
        ):
            with self.subTest(state=state, code=code, direct=direct):

                class SessionBackend(EthernetPrimitive):
                    def __init__(self, state, code):
                        super().__init__()
                        self.state, self.code = state, code

                    def invoke_ethernet(
                        self, operation, fields, *, deadline, cancelled
                    ):
                        if (
                            operation == "channel_ioctl"
                            and fields["ioctl_id"] == 0x8023
                        ):
                            self.calls.append((operation, fields, deadline))
                            return J2534Result(
                                code=self.code, data=struct.pack("<I", self.state)
                            )
                        return super().invoke_ethernet(
                            operation, fields, deadline=deadline, cancelled=cancelled
                        )

                profile = ethernet_profile()
                sections = {
                    slot: (section.count, section.payload)
                    for slot, section in profile.catalog.management.sections.items()
                }
                encoded = bytearray(encode_database(1, sections))
                struct.pack_into("<I", encoded, 28, profile.catalog.management.version)
                profile.catalog.management = parse_database(bytes(encoded))
                backend = SessionBackend(state, code)
                runtime = NativeCommunication.from_backend(
                    profile,
                    backend,
                    "ethernet-context",
                    first_request=b"\x22",
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x14,
                    source_build=18,
                    clock=backend.clock,
                )
                controller = runtime.operations
                assert isinstance(controller, NativeFrameController)
                controller.operations.wait = backend.wait
                self.assertEqual(controller.operations.open(), 0)
                original_lower = controller.operations
                if state != 2:
                    backend.replies.extend(EthernetPrimitive().replies)
                    backend.voltages.extend((100, 6000, 10000))
                    backend.bytes_replies.append(b"\x02\xfd\x00\x06" + bytes(13))
                status = (
                    controller.send(
                        b"\x22",
                        timeout=1000,
                        initialization_mode=2,
                        clear_rx=1,
                        deadline=runtime.deadline,
                    )
                    if direct
                    else runtime.send_native(
                        NativeFrameSend(
                            "SendIntNoInit", profile.category, b"\x22", 1000, 0x14
                        )
                    )
                )
                self.assertEqual(
                    status, (0x91010000 | code) if state == 2 and code else 0
                )
                self.assertIs(controller.operations, original_lower)
                self.assertEqual(
                    sum(op == "physical_connect" for op, _, _ in backend.calls),
                    1 if state == 2 else 2,
                )
                self.assertEqual(runtime.disconnect(), 0)

    def test_ethernet_session_helper_enables_actual_d1_close_exchange(self):
        original = ethernet_profile()
        sections = {
            slot: (section.count, section.payload)
            for slot, section in original.catalog.management.sections.items()
        }
        count, rows = sections[18]
        d1 = bytearray(rows[-16:])
        struct.pack_into("<H", d1, 2, 0xD1)
        sections[18] = (
            count + 1,
            b"".join(
                sorted(
                    [rows[i : i + 16] for i in range(0, len(rows), 16)] + [bytes(d1)],
                    key=lambda row: struct.unpack_from("<H", row, 2)[0],
                )
            ),
        )
        encoded = bytearray(encode_database(1, sections))
        struct.pack_into("<I", encoded, 28, original.catalog.management.version)
        original.catalog.management = parse_database(bytes(encoded))
        backend = EthernetPrimitive()
        runtime = NativeCommunication.from_backend(
            original,
            backend,
            "ethernet-helper",
            first_request=b"\x22",
            driver=DRIVER,
            device_kind=8,
            bus_id=0x14,
            source_build=18,
            clock=backend.clock,
        )
        controller = runtime.operations
        assert isinstance(controller, NativeFrameController)
        controller.operations.wait = backend.wait
        self.assertEqual(controller.operations.open(), 0)
        backend.response(b"\x50\x01")
        self.assertEqual(controller._session_command(0x106, 2, runtime.deadline), 0)
        self.assertEqual(controller.operations.preinit_d1_suppressed, 0)
        backend.response(b"\x50\x01")
        self.assertEqual(runtime.disconnect(), 0)
        payloads = [
            fields["messages"][0].data[12:]
            for operation, fields, _ in backend.calls
            if operation == "queue_messages"
            and fields["messages"][0].data[:4] == b"\x02\xfd\x80\x01"
        ]
        self.assertEqual(payloads, [b"\x10\x01", b"\x10\x01"])

    def test_bound_native_log_modes_record_actual_lower_and_stop_after_disconnect(self):
        from scripts.database_resources import DdrPacketLog

        for version, kind, name in (
            (12, 0, "OperationFFD"),
            (12, 3, "AbsoluteTimeStamp"),
            (18, 0, "OperationFFD"),
            (18, 3, "AbsoluteTimeStamp"),
            (18, 0x14, "MarkMonRam_SSR"),
        ):
            with (
                self.subTest(version=version, kind=kind),
                tempfile.TemporaryDirectory() as directory,
            ):
                profile = serialized_profile(version=version)
                backend = J2534Fixture([])
                runtime = NativeCommunication.from_backend(
                    profile,
                    backend,
                    "logged",
                    first_request=b"\x22\xf1\x90",
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x12,
                    source_build=version,
                    clock=lambda: 0.0,
                )
                assert isinstance(runtime.operations, NativeFrameController)
                logger = DdrPacketLog(Path(directory), runtime.operations)
                runtime.bind_comm_log(logger)
                self.assertEqual(runtime.start_comm_log(kind), 0)
                self.assertEqual(
                    runtime.send_native(
                        NativeFrameSend(
                            "SendIntNoInit",
                            profile.category,
                            b"\x22\xf1\x90",
                            1000,
                            0x12,
                        )
                    ),
                    0,
                )
                self.assertEqual(runtime.disconnect(), 0)
                self.assertEqual(runtime.stop_comm_log(), 0)
                self.assertEqual(logger.path.name, name + ".log")
                self.assertIn(b"22F190", logger.path.read_bytes().replace(b" ", b""))

    def test_raw_selected_ddb_reaches_actual_lower_without_positive_sid_check(self):
        for version in (12, 18):
            with self.subTest(version=version):
                profile = serialized_profile(version=version)
                backend = J2534Fixture(
                    [
                        J2534Result(
                            count=1,
                            messages=(
                                NativeMessage(
                                    6, 0, 0, 0, 0, bytes.fromhex("000007e81399")
                                ),
                            ),
                        )
                    ]
                )
                runtime = NativeCommunication.from_backend(
                    profile,
                    backend,
                    "raw",
                    first_request=b"\x22\xf1\x90",
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x12,
                    source_build=version,
                    clock=lambda: 0.0,
                )
                result = runtime.execute_raw(profile.direct_frame(0, 1))
                self.assertEqual((result.status, result.response), (0, b"\x13\x99"))
                self.assertEqual(runtime.disconnect(), 0)

    def test_raw_exchange_retries_all_errors_without_positive_sid_validation(self):
        profile = serialized_profile(retries=2)
        runtime, lower = self.runtime(
            [Reply(NO_RESPONSE), Reply(0, b"\x13\x99")],
            sends=[5, 0, 0],
            profile=profile,
        )
        result = runtime.execute_raw(profile.direct_frame(0, 1))
        self.assertEqual(
            (result.status, result.response, result.attempts), (0, b"\x13\x99", 3)
        )
        self.assertEqual(
            [call[0] for call in lower.calls],
            ["send", "send", "receive", "send", "receive"],
        )

    def test_raw_empty_reply_retries_and_capacity_is_bounded_before_io(self):
        profile = serialized_profile(retries=1)
        runtime, lower = self.runtime([Reply(0), Reply(0, b"\x01")], profile=profile)
        selected = profile.direct_frame(0, 1)
        with self.assertRaisesRegex(ValueError, "capacity is BYTE"):
            runtime.execute_raw(selected, capacity=256)
        self.assertEqual(lower.calls, [])
        result = runtime.execute_raw(selected, capacity=1)
        self.assertEqual(
            (result.status, result.response, result.attempts), (0, b"\x01", 2)
        )

    def test_actual_ethernet_selected_service_drives_wire_and_initialization(self):
        for service, target in ((1, 0x7DF), (0x22, 0x7E0)):
            with self.subTest(service=service):
                original = ethernet_profile()
                sections = {
                    slot: (section.count, section.payload)
                    for slot, section in original.catalog.management.sections.items()
                }
                encoded = bytearray(encode_database(1, sections))
                struct.pack_into("<I", encoded, 28, original.catalog.management.version)
                original.catalog.management = parse_database(bytes(encoded))
                backend = EthernetPrimitive()
                runtime = NativeCommunication.from_backend(
                    original,
                    backend,
                    "ethernet",
                    first_request=bytes((service,)),
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x14,
                    source_build=18,
                    clock=backend.clock,
                )
                controller = runtime.operations
                assert isinstance(controller, NativeFrameController)
                controller.operations.wait = backend.wait
                controller.operations.force_initialization = True
                self.assertEqual(
                    runtime.send_native(
                        NativeFrameSend(
                            "SendInt" if service == 1 else "SendIntNoInit",
                            original.category,
                            bytes((service,)),
                            1000,
                            0x14,
                        )
                    ),
                    0,
                )
                queues = [
                    fields
                    for operation, fields, _ in backend.calls
                    if operation == "queue_messages"
                    and fields["messages"][0].protocol_id == 0x8208
                ]
                self.assertEqual(
                    queues[-1]["messages"][0].data[-3:],
                    target.to_bytes(2, "big") + bytes((service,)),
                )
                self.assertEqual(
                    len(queues), 2
                )  # Routing activation and business data.
                self.assertEqual(controller.operations.current_service, service)
                self.assertEqual(runtime.disconnect(), 0)

    def runtime(
        self,
        replies=(),
        sends=(),
        *,
        profile=None,
        request=b"\x22\xf1\x90",
        retries=0,
        **kwargs,
    ):
        lower = Primitives(replies, sends)
        runtime = NativeCommunication(
            profile
            or serialized_profile(
                request=request, retries=retries, mask=b"", check=b""
            ),
            lower,
            "authored-ecu",
            bus_id=0x12,
            clock=lambda: 0.0,
            **kwargs,
        )
        return runtime, lower

    def test_positive_selected_send_receive_literal_timeouts(self):
        runtime, lower = self.runtime([Reply(0, b"\x62\xf1\x90\x42")])
        result = runtime.execute(frame())
        self.assertEqual(
            (result.status, result.response, result.attempts),
            (0, b"\x62\xf1\x90\x42", 1),
        )
        self.assertEqual(
            lower.calls[0],
            (
                "send",
                b"\x22\xf1\x90",
                {
                    "timeout": 120,
                    "initialization_mode": 1,
                    "clear_rx": 1,
                    "no_session": False,
                    "deadline": 10.0,
                },
            ),
        )
        self.assertEqual(
            lower.calls[1],
            (
                "receive",
                {
                    "maximum": 255,
                    "timeout": 350,
                    "argument_5": 0,
                    "flags": 100,
                    "deadline": 10.0,
                },
            ),
        )

    def test_wrong_sid_retries_then_succeeds_and_negative_not_exposed(self):
        runtime, lower = self.runtime(
            [Reply(0, b"\x7f\x22\x31"), Reply(0, b"\x62\x01")], retries=1
        )
        result = runtime.execute(frame(retries=1))
        self.assertEqual((result.status, result.attempts), (0, 2))
        self.assertEqual([call[0] for call in lower.calls], ["send", "receive"] * 2)
        runtime, _ = self.runtime([Reply(0, b"\x7f\x22\x31")])
        self.assertEqual(runtime.execute(frame()).response, b"")

    def test_native_terminal_no_response_and_partial_copy(self):
        runtime, lower = self.runtime([Reply(NO_RESPONSE, b"bad")], retries=3)
        result = runtime.execute(frame(retries=3))
        self.assertEqual(
            (result.status, result.response, result.attempts), (NO_RESPONSE, b"", 1)
        )
        self.assertEqual(len(lower.calls), 2)
        runtime, _ = self.runtime([Reply(PARTIAL_RESPONSE, b"\x62\x01")])
        result = runtime.execute(frame())
        self.assertEqual(
            (result.status, result.response), (PARTIAL_RESPONSE, b"\x62\x01")
        )

    def test_send_fault_does_not_read_and_retries_are_exact(self):
        runtime, lower = self.runtime(sends=[0x123, 0x124], retries=1)
        result = runtime.execute(frame(retries=1))
        self.assertEqual((result.status, result.attempts), (0x124, 2))
        self.assertTrue(all(call[0] == "send" for call in lower.calls))

    def test_empty_request_is_null_initialization_no_receive(self):
        runtime, lower = self.runtime(request=b"")
        result = runtime.execute(frame(b""), initialization_control=1)
        self.assertEqual(result.status, 0)
        self.assertEqual(lower.calls[0][0:2], ("send", None))
        self.assertEqual(len(lower.calls), 1)

    def test_no_init_no_session_precedence(self):
        runtime, lower = self.runtime([Reply(0, b"\x62"), Reply(0, b"\x62")])
        runtime.no_init = True
        runtime.execute(frame())
        runtime.no_session = True
        runtime.execute(frame())
        self.assertEqual(
            [
                call[2]["initialization_mode"]
                for call in lower.calls
                if call[0] == "send"
            ],
            [2, 2],
        )

    def test_cancel_budget_cleanup_and_closed_state(self):
        state = [False]
        runtime, lower = self.runtime(cancelled=lambda: state[0])
        state[0] = True
        with self.assertRaises(Cancelled):
            runtime.execute(frame())
        self.assertEqual(lower.calls, [])
        runtime, lower = self.runtime(limits=Limits(exchanges=1))
        with self.assertRaises(SessionError):
            runtime.execute(frame())
        runtime.close()
        runtime.close()
        self.assertEqual(sum(call[0] == "close" for call in lower.calls), 1)
        with self.assertRaises(SessionError):
            runtime.execute(frame())

    def test_exception_exit_still_enforces_cancellation_and_deadline(self):
        for operation in ("send", "receive"):
            for policy in ("cancel", "deadline"):
                with self.subTest(operation=operation, policy=policy):
                    state = [False]
                    now = [0.0]
                    lower = Primitives()
                    runtime = NativeCommunication(
                        serialized_profile(mask=b"", check=b""),
                        lower,
                        "ecu",
                        bus_id=0x12,
                        cancelled=lambda state=state: state[0],
                        clock=lambda now=now: now[0],
                    )

                    def failure(*args, policy=policy, state=state, now=now, **kwargs):
                        if policy == "cancel":
                            state[0] = True
                        else:
                            now[0] = 11.0
                        raise ToyotaCodecError("authored primitive fault", 0x1234)

                    setattr(lower, operation, failure)
                    with self.assertRaises(
                        Cancelled if policy == "cancel" else SessionError
                    ):
                        runtime.execute(frame())

    def test_primary_host_timeout_survives_post_io_deadline_check(self):
        for operation in ("send", "receive"):
            now = [0.0]
            lower = Primitives()
            runtime = NativeCommunication(
                serialized_profile(mask=b"", check=b""),
                lower,
                "ecu",
                bus_id=0x12,
                clock=lambda now=now: now[0],
            )
            original = TimeoutError("parent operation deadline")

            def failure(*args, now=now, original=original, **kwargs):
                now[0] = 11.0
                raise original

            setattr(lower, operation, failure)
            with self.assertRaises(TimeoutError) as caught:
                runtime.execute(frame())
            self.assertIs(caught.exception, original)

    def test_malformed_lower_status_never_becomes_success(self):
        for malformed in (None, False, -1, 1 << 32):
            for operation in ("send", "receive"):
                with self.subTest(status=malformed, operation=operation):
                    runtime, _ = (
                        self.runtime(sends=[malformed])
                        if operation == "send"
                        else self.runtime([Reply(malformed)])
                    )
                    with self.assertRaisesRegex(ValueError, "malformed status"):
                        runtime.execute(frame())

    def test_receive_overflow_is_not_silently_truncated(self):
        runtime, _ = self.runtime([Reply(0, b"\x62" * 256)])
        with self.assertRaisesRegex(ValueError, "capacity"):
            runtime.execute(frame())

    def test_extended_common_retains_word_request_and_native_capacity(self):
        request = b"\x22" + bytes(300)
        reply = b"\x62" + bytes(300)
        runtime, lower = self.runtime([Reply(0, reply)], request=request)
        result = runtime.execute(frame(request), extended=True)
        self.assertEqual(result.response, reply)
        self.assertEqual(lower.calls[0][1], request)
        self.assertEqual(lower.calls[1][1]["maximum"], 0x1000)
        with self.assertRaisesRegex(ValueError, "BYTE"):
            runtime.execute(frame(request))

    def test_serialized_ddb_connection_then_ever_hit_both_versions(self):
        for version in (12, 18):
            with self.subTest(version=version):
                profile = serialized_profile(version=version)
                runtime, lower = self.runtime(
                    [Reply(0, b"\x62\x01"), Reply(TIMEOUT)],
                    profile=profile,
                    source_build=version,
                )
                result = runtime.connection_no_buffer()
                self.assertEqual(
                    (result.status, result.connected, result.cache_hit),
                    (0, True, False),
                )
                self.assertIsNotNone(result.selected)
                assert result.selected is not None
                self.assertIn(
                    profile.catalog.management.sha256, result.selected.provenance
                )
                self.assertEqual(result.selected.function_record, b"")
                self.assertEqual(lower.calls[-1][1]["maximum"], 0xFFF)
                self.assertEqual(lower.calls[-1][1]["timeout"], 0)
                result = runtime.connection_no_buffer()
                self.assertEqual(
                    (result.status, result.connected, result.cache_hit), (0, True, True)
                )
                self.assertEqual(len(lower.calls), 3)

    def test_connection_mask_mismatch_status_zero_drain(self):
        runtime, lower = self.runtime(
            [Reply(0, b"\x62\x01"), Reply(TIMEOUT)],
            profile=serialized_profile(mask=b"\xff\xff", check=b"\x62\x02"),
        )
        result = runtime.connection_no_buffer()
        self.assertEqual((result.status, result.connected), (0, False))
        self.assertEqual(len(lower.calls), 3)

    def test_connection_drain_fault_clears_connected_and_cleanup_remains_possible(self):
        runtime, lower = self.runtime(
            [Reply(0, b"\x62"), Reply(0xBADC0DE)], profile=serialized_profile()
        )
        result = runtime.connection_no_buffer()
        self.assertEqual((result.status, result.connected), (0xBADC0DE, False))
        runtime.close()
        self.assertEqual(lower.calls[-1], ("close",))

    def test_connection_psa_skips_drain_and_force_removes_ever_only(self):
        runtime, lower = self.runtime(
            [Reply(0, b"\x62"), Reply(0, b"\x62")],
            profile=serialized_profile(flags=0x14),
        )
        self.assertTrue(runtime.connection_no_buffer().connected)
        self.assertTrue(runtime.connection_no_buffer().cache_hit)
        self.assertFalse(runtime.connection_no_buffer(force=True).cache_hit)
        self.assertEqual([call[0] for call in lower.calls], ["send", "receive"] * 2)

    def test_version_twelve_extended_ignores_no_session_flag(self):
        request = b"\x22" + bytes(300)
        runtime, lower = self.runtime(
            [Reply(0, b"\x62"), Reply(0, b"\x62")], source_build=12, request=request
        )
        runtime.no_session = True
        runtime.execute(frame(request), extended=True)
        runtime.no_init = True
        runtime.execute(frame(request), extended=True)
        self.assertEqual(
            [
                call[2]["initialization_mode"]
                for call in lower.calls
                if call[0] == "send"
            ],
            [1, 2],
        )

    def test_connection_negative_cache_normalizes_later_hit_to_timeout(self):
        runtime, lower = self.runtime(
            [Reply(NO_RESPONSE)], profile=serialized_profile(flags=0x14)
        )
        first = runtime.connection_no_buffer()
        second = runtime.connection_no_buffer()
        self.assertEqual(
            (first.status, first.connected, first.cache_hit),
            (NO_RESPONSE, False, False),
        )
        self.assertEqual(
            (second.status, second.connected, second.cache_hit), (TIMEOUT, False, True)
        )
        self.assertEqual(len(lower.calls), 2)

    def test_connection_operation_clears_temp_and_preserves_ever(self):
        runtime, lower = self.runtime(
            [Reply(0, b"\x62")] * 3, profile=serialized_profile(flags=0x14)
        )
        runtime.connection_no_buffer()
        runtime.connection_no_buffer(temporary=True)
        self.assertTrue(runtime.connection_no_buffer(temporary=True).cache_hit)
        runtime.begin_operation()
        self.assertTrue(runtime.connection_no_buffer().cache_hit)
        self.assertFalse(runtime.connection_no_buffer(temporary=True).cache_hit)
        self.assertEqual(len(lower.calls), 6)

    def test_version_twelve_connection_always_drains_category_four_sid_one(self):
        for version in (12, 18):
            profile = serialized_profile(
                version=version, flags=4, request=b"\x01", check=b"\x41"
            )
            replies = [Reply(0, b"\x41")]
            if version == 12:
                replies.append(Reply(TIMEOUT))
            runtime, lower = self.runtime(
                replies, profile=profile, source_build=version
            )
            result = runtime.connection_no_buffer()
            self.assertTrue(result.connected)
            self.assertEqual(len(lower.calls), 3 if version == 12 else 2)

    def test_connection_category_four_empty_request_skips_drain(self):
        runtime, lower = self.runtime(profile=serialized_profile(flags=4, request=b""))
        result = runtime.connection_no_buffer()
        self.assertEqual((result.status, result.connected), (0, True))
        self.assertEqual([call[0] for call in lower.calls], ["send"])

    def test_connection_selection_failure_has_status_and_no_primitives(self):
        runtime, lower = self.runtime(profile=serialized_profile())
        result = runtime.connection_no_buffer(999, 1)
        self.assertEqual(result.status, 0xC0040101)
        self.assertIsNone(result.selected)
        self.assertEqual(lower.calls, [])
        result = runtime.connection_no_buffer(0, 999)
        self.assertEqual(result.status, 0xC0040102)
        self.assertEqual(lower.calls, [])

    def test_behavior_code_segmented_word_ids_and_timeout_after_partial(self):
        profile = serialized_profile(request=b"\x22\x00", check=b"\x12\x34")
        runtime, lower = self.runtime(
            [
                Reply(0, b"\x62\x00\x03\x12\x34"),
                Reply(0, b"\x62\x00\x03\xab\xcd"),
                Reply(TIMEOUT),
            ],
            profile=profile,
        )
        result = runtime.is_behavior_code(0, 1)
        self.assertEqual(
            (result.status, result.supported, result.ignored_failure), (0, True, False)
        )
        self.assertEqual(result.identifiers, (0x1234, 0xABCD))
        self.assertEqual(
            [call[0] for call in lower.calls], ["send", "receive", "receive", "receive"]
        )

    def test_behavior_negative_and_truncated_have_native_ignore_flag(self):
        for reply, expected in (
            (Reply(NO_RESPONSE), NO_RESPONSE),
            (Reply(0, b"\x7f\x22\x31"), 0xA0040201),
            (Reply(0, b"\x62\x00"), 0xA0040202),
        ):
            with self.subTest(code=expected):
                runtime, lower = self.runtime([reply], profile=serialized_profile())
                result = runtime.is_behavior_code(0, 1)
                self.assertEqual(
                    (result.status, result.supported, result.ignored_failure),
                    (expected, False, True),
                )
                self.assertEqual(len(lower.calls), 2)

    def test_serialized_ddb_through_actual_lower_typed_j2534_and_cleanup(self):
        for version in (12, 18):
            with self.subTest(version=version):
                profile = serialized_profile(version=version)
                wire = NativeMessage(6, 0, 0, 0, 0, bytes.fromhex("000007e862f19042"))
                backend = J2534Fixture(
                    [J2534Result(count=1, messages=(wire,)), J2534Result(code=9)]
                )
                runtime = NativeCommunication.from_backend(
                    profile,
                    backend,
                    "actual-lower-ecu",
                    first_request=profile.direct_frame(0, 1).frame.request,
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x12,
                    source_build=version,
                    clock=lambda: 0.0,
                )
                self.assertEqual(backend.calls, [])
                result = runtime.connection_no_buffer()
                self.assertEqual(
                    (result.status, result.connected, result.response),
                    (0, True, b"\x62\xf1\x90\x42"),
                )
                writes = [
                    fields
                    for operation, fields in backend.calls
                    if operation == "write_messages"
                ]
                self.assertEqual(len(writes), 1)
                self.assertEqual(
                    writes[0]["messages"][0].data, bytes.fromhex("000007e022f190")
                )
                self.assertEqual(writes[0]["timeout"], 120)
                runtime.close()
                self.assertEqual(backend.calls[-1], ("disconnect", {"channel_id": 41}))

    def test_actual_lower_explicit_write_fault_retries_on_retained_channel(self):
        profile = serialized_profile(retries=1)
        wire = NativeMessage(6, 0, 0, 0, 0, bytes.fromhex("000007e862f19042"))
        backend = J2534Fixture(
            [J2534Result(count=1, messages=(wire,)), J2534Result(code=9)],
            write_codes=[5, 0],
        )
        runtime = NativeCommunication.from_backend(
            profile,
            backend,
            "retry-ecu",
            first_request=b"\x22\xf1\x90",
            driver=DRIVER,
            device_kind=8,
            bus_id=0x12,
            source_build=18,
            clock=lambda: 0.0,
        )
        result = runtime.connection_no_buffer()
        self.assertEqual((result.status, result.connected), (0, True))
        names = [operation for operation, _ in backend.calls]
        self.assertEqual(names.count("connect"), 1)
        self.assertEqual(names.count("write_messages"), 2)
        self.assertEqual(names.count("read_messages"), 2)
        runtime.close()

    def test_actual_typed_j2534_ram_reader_recording_and_replay_consumer(self):
        from scripts.database_resources import (
            DdrPacketLog,
            NativeRamReader,
            RamFrame,
            RamReplay,
            encode_ram_recording,
        )

        profile = serialized_profile(request=bytes.fromhex("91000000000000"))
        management = profile.catalog.management
        sections = {
            slot: (section.count, section.payload)
            for slot, section in management.sections.items()
        }
        count, functions = sections[18]
        sections[18] = (
            count + 1,
            functions + struct.pack("<8H", 42, 0xA1, 1, 0, 0, 0, 0, 0),
        )
        profile.catalog.management = parse_database(encode_database(1, sections))
        wire = NativeMessage(
            6, 0, 0, 0, 0, bytes.fromhex("000007e8d1040300000000000102")
        )
        backend = J2534Fixture([J2534Result(count=1, messages=(wire,))])
        runtime = NativeCommunication.from_backend(
            profile,
            backend,
            "ddr-ecu",
            first_request=bytes.fromhex("91000000000000"),
            driver=DRIVER,
            device_kind=8,
            bus_id=0x12,
            source_build=18,
            clock=lambda: 0.0,
        )
        assert isinstance(runtime.operations, NativeFrameController)
        with tempfile.TemporaryDirectory() as folder:
            packet_log = DdrPacketLog(Path(folder), runtime.operations.operations)
            self.assertEqual(packet_log.start(), 0)
            reader = NativeRamReader.from_communication(
                runtime,
                frame=RamFrame(bytes.fromhex("0100040000000000")),
                block_size=56,
            )
            self.assertEqual(reader.read(0, 3, real=True), bytes.fromhex("000102"))
            writes = [
                fields
                for operation, fields in backend.calls
                if operation == "write_messages"
            ]
            self.assertEqual(
                writes[0]["messages"][0].data, bytes.fromhex("000007e091040300000000")
            )
            recording = encode_ram_recording(reader, source="authored_synthetic")
            replay = RamReplay(profile, recording)
            self.assertEqual(
                replay.reader.read(0, 3, real=True), bytes.fromhex("000102")
            )
            replay.assert_complete()
            self.assertEqual(packet_log.stop(), 0)
            self.assertEqual(
                packet_log.path.read_bytes(), b"91040300000000\\nD1040300000000000102"
            )
        runtime.close()

    def test_registered_low_a_idle_worker_uses_selected_58_and_clears_context(self):
        from test_monitor_psa import authored_profile

        from scripts.monitor_psa import PSAJ2534Provider

        for version in (12, 18):
            with tempfile.TemporaryDirectory() as directory:
                profile = authored_profile(Path(directory) / "fixture", version=version)
                sections = {
                    slot: (section.count, section.payload)
                    for slot, section in profile.catalog.management.sections.items()
                }
                count, functions = sections[18]
                sections[18] = (
                    count + 1,
                    functions + struct.pack("<8H", 1, 0x58, 1, 3, 0, 1, 0, 0),
                )
                count, rows = sections[18]
                sections[18] = (
                    count,
                    b"".join(
                        sorted(
                            (
                                rows[offset : offset + 16]
                                for offset in range(0, len(rows), 16)
                            ),
                            key=lambda row: struct.unpack_from("<HH", row),
                        )
                    ),
                )
                encoded = bytearray(encode_database(1, sections))
                struct.pack_into("<I", encoded, 28, profile.catalog.management.version)
                profile.catalog.management = parse_database(bytes(encoded))
                now = [10.0]
                backend = J2534Fixture(
                    [
                        J2534Result(
                            count=1,
                            messages=(
                                NativeMessage(6, 0, 0, 0, 0, bytes.fromhex(data)),
                            ),
                        )
                        for data in ("000007c0eabb", "000007c0610c1234", "000007c0eabb")
                    ]
                )
                provider = PSAJ2534Provider(
                    profile,
                    backend,
                    "idle",
                    bus_id=0x1A,
                    request=bytes.fromhex("210c"),
                    native_build=version,
                    driver=DRIVER,
                    clock=lambda now=now: now[0],
                )
                provider.open()
                self.assertEqual(
                    provider.send(
                        "idle",
                        bytes.fromhex("210c"),
                        timeout=1000,
                        protocol=0x1A,
                        initialize=True,
                    ),
                    0,
                )
                controller = provider.controller
                assert controller._idle_thread is not None
                self.assertTrue(controller._idle_thread.is_alive())
                provider.receive(
                    "idle",
                    buffer=True,
                    maximum=4096,
                    timeout=200,
                    argument_5=0,
                    flags=100,
                )
                self.assertEqual(controller.stop_idle(), 0)
                now[0] = 13.1
                self.assertEqual(controller._idle_cycle(), 0)
                self.assertEqual(controller.current_category, 0)
                self.assertEqual(provider.operations.current_category, 0)
                writes = [
                    fields["messages"][0].data
                    for operation, fields in backend.calls
                    if operation == "write_messages"
                ]
                self.assertEqual(
                    writes,
                    [
                        bytes.fromhex(data)
                        for data in ("000007e0aabb", "000007e0210c", "000007e0aabb")
                    ],
                )
                provider.close()

    def test_actual_psa_cross_ecu_equal_parameters_retains_diagnostic_session(self):
        for version in (12, 18):
            profiles = []
            for category in (42, 43):
                profile = serialized_profile(version=version, flags=0x14)
                sections = {
                    slot: (section.count, section.payload)
                    for slot, section in profile.catalog.management.sections.items()
                }
                category_record = bytearray(profile.category_record)
                struct.pack_into("<H", category_record, 68, category)
                sections[16] = (1, bytes(category_record))
                count, protocol = sections[13]
                protocol = bytearray(protocol)
                struct.pack_into("<H", protocol, 0, category)
                sections[13] = (count, bytes(protocol))
                count, functions = sections[18]
                functions = bytearray(functions)
                for offset in range(0, len(functions), 16):
                    struct.pack_into("<H", functions, offset, category)
                functions += struct.pack("<8H", category, 0xD1, 0, 1, 0, 0, 0, 0)
                functions += struct.pack("<8H", category, 0xD2, 0, 2, 0, 0, 0, 0)
                sections[18] = (count + 2, bytes(functions))
                encoded = bytearray(encode_database(1, sections))
                struct.pack_into("<I", encoded, 28, profile.catalog.management.version)
                profile.catalog.management = parse_database(bytes(encoded))
                profiles.append(
                    replace(profile, category_record=bytes(category_record))
                )
            profile, target = profiles
            backend = J2534Fixture(
                [
                    J2534Result(
                        count=1,
                        messages=(NativeMessage(6, 0, 0, 0, 0, bytes.fromhex(data)),),
                    )
                    for data in (
                        "000007e85001",
                        "000007e8c1",
                        "000007e862f19042",
                        "000007e862f19043",
                    )
                ]
            )
            if version == 12:
                backend.replies.insert(3, J2534Result(code=9))
            old = NativeCommunication.from_backend(
                profile,
                backend,
                "first",
                first_request=b"\x22\xf1\x90",
                driver=DRIVER,
                device_kind=8,
                bus_id=0x12,
                source_build=version,
                clock=lambda: 0.0,
            )
            self.assertTrue(old.connection_no_buffer().connected)
            controller = old.operations
            assert isinstance(controller, NativeFrameController)
            lower = controller.operations
            self.assertEqual(controller.session_state, 3)
            self.assertEqual(
                controller.change_context(
                    target,
                    bus_id=0x12,
                    first_request=b"\x22\xf1\x90",
                    request=b"\x22\xf1\x90",
                    deadline=10.0,
                ),
                0,
            )
            self.assertIs(controller.operations, lower)
            current = NativeCommunication(
                target,
                controller,
                "second",
                bus_id=0x12,
                source_build=version,
                clock=lambda: 0.0,
            )
            self.assertEqual(
                current.execute(target.direct_frame(0, 1)).response,
                bytes.fromhex("62f19043"),
            )
            writes = [
                fields["messages"][0].data
                for operation, fields in backend.calls
                if operation == "write_messages"
            ]
            self.assertEqual(
                writes,
                [
                    bytes.fromhex(data)
                    for data in (
                        "000007e01001",
                        "000007e081",
                        "000007e022f190",
                        "000007e022f190",
                    )
                ],
            )
            self.assertEqual(controller.session_state, 3)
            current.close()
            old.close()

    def test_actual_disconnect_flag_one_retains_psa_selected_d1_close(self):
        for version in (12, 18):
            for flag in (0, 1):
                profile = serialized_profile(version=version, flags=0x14)
                sections = {
                    slot: (section.count, section.payload)
                    for slot, section in profile.catalog.management.sections.items()
                }
                count, functions = sections[18]
                sections[18] = (
                    count + 1,
                    functions + struct.pack("<8H", 42, 0xD1, 0, 1, 0, 0, 0, 0),
                )
                encoded = bytearray(encode_database(1, sections))
                struct.pack_into("<I", encoded, 28, profile.catalog.management.version)
                profile.catalog.management = parse_database(bytes(encoded))
                backend = J2534Fixture(
                    [
                        J2534Result(
                            count=1,
                            messages=(
                                NativeMessage(
                                    6, 0, 0, 0, 0, bytes.fromhex("000007e85001")
                                ),
                            ),
                        )
                    ]
                )
                runtime = NativeCommunication.from_backend(
                    profile,
                    backend,
                    "disconnect",
                    first_request=b"\x22\xf1\x90",
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x12,
                    source_build=version,
                    clock=lambda: 0.0,
                )
                runtime.send_native(
                    NativeFrameSend(
                        "SendIntNoInitNoSession", 42, b"\x22\xf1\x90", 1000, 0x12
                    )
                )
                controller = runtime.operations
                assert isinstance(controller, NativeFrameController)
                controller.operations.set_preinit_d1_suppressed(0)
                self.assertEqual(runtime.disconnect(flag, deadline=5.0), 0)
                writes = [
                    fields["messages"][0].data
                    for operation, fields in backend.calls
                    if operation == "write_messages"
                ]
                expected = [bytes.fromhex("000007e022f190")]
                if flag == 1:
                    expected.append(bytes.fromhex("000007e01001"))
                self.assertEqual(writes, expected)
                self.assertIsNone(controller.operations.channel)
                self.assertEqual(runtime.disconnect(flag), 0)

    def test_actual_failed_disconnect_retains_retry_without_repeating_business_write(
        self,
    ):
        backend = J2534Fixture([], disconnect_codes=(5, 0))
        runtime = NativeCommunication.from_backend(
            serialized_profile(),
            backend,
            "cleanup",
            first_request=b"\x22\xf1\x90",
            driver=DRIVER,
            device_kind=8,
            bus_id=0x12,
            source_build=18,
            clock=lambda: 0.0,
        )
        runtime.send_native(
            NativeFrameSend("SendIntNoInit", 42, b"\x22\xf1\x90", 1000, 0x12)
        )
        self.assertEqual(runtime.close(), 0x91010005)
        self.assertTrue(runtime.closed)
        before = len(backend.calls)
        with self.assertRaises(SessionError):
            runtime.execute(frame())
        self.assertEqual(len(backend.calls), before)
        self.assertEqual(runtime.close(), 0)
        self.assertEqual(sum(op == "disconnect" for op, _ in backend.calls), 2)
        self.assertEqual(sum(op == "write_messages" for op, _ in backend.calls), 1)
        self.assertEqual(runtime.close(), 0)
        self.assertEqual(sum(op == "disconnect" for op, _ in backend.calls), 2)

    def test_scoped_flags_and_explicit_extended_query_capacity(self):
        reply = b"\x62" + bytes(4096)
        runtime, lower = self.runtime([Reply(0, reply)])
        runtime.no_init = runtime.no_session = True
        with runtime.communication_flags(no_init=False, no_session=False):
            actual = runtime.cache.transaction(
                runtime.profile.direct_frame(0, 1),
                b"\x22\xf1\x90",
                extended=True,
                capacity=0xFFFF,
                cached=False,
            )
            self.assertEqual(actual, reply)
        self.assertEqual((runtime.no_init, runtime.no_session), (True, True))
        self.assertEqual(lower.calls[0][2]["initialization_mode"], 1)
        self.assertEqual(lower.calls[1][1]["maximum"], 0xFFFF)
        with (
            self.assertRaisesRegex(ValueError, "authored"),
            runtime.communication_flags(no_init=False, no_session=True),
        ):
            raise ValueError("authored")
        self.assertEqual((runtime.no_init, runtime.no_session), (True, True))

    def test_failed_native_context_reconstruction_never_revives_old_channel(self):
        for version in (12, 18):
            profile = serialized_profile(version=version)
            missing = serialized_profile(version=version, bus=0x32)
            backend = J2534Fixture([])
            runtime = NativeCommunication.from_backend(
                profile,
                backend,
                "old",
                first_request=b"\x22\xf1\x90",
                driver=DRIVER,
                device_kind=8,
                bus_id=0x12,
                source_build=version,
                clock=lambda: 0.0,
            )
            runtime.send_native(
                NativeFrameSend("SendIntNoInit", 42, b"\x22\xf1\x90", 1000, 0x12)
            )
            controller = runtime.operations
            assert isinstance(controller, NativeFrameController)
            self.assertEqual(
                controller.change_context(
                    missing,
                    bus_id=0x22,
                    first_request=b"\x22\xf1\x90",
                    request=b"\x22\xf1\x90",
                    deadline=10.0,
                ),
                0x90020104,
            )
            before = len(backend.calls)
            self.assertEqual(
                runtime.send_native(
                    NativeFrameSend("SendIntNoInit", 42, b"\x22\xf1\x90", 1000, 0x12)
                ),
                0x90020701,
            )
            self.assertEqual(len(backend.calls), before)
            self.assertIsNone(controller.operations.channel)
            runtime.close()

    def test_actual_change_context_reuses_or_rebuilds_selected_lower(self):
        for version in (12, 18):
            for target_bus, rebuild in ((0x22, True), (0x32, False)):
                profile = serialized_profile(version=version)
                target = serialized_profile(version=version, bus=target_bus)
                backend = J2534Fixture(
                    [
                        J2534Result(
                            count=1,
                            messages=(
                                NativeMessage(
                                    6,
                                    0,
                                    0,
                                    0,
                                    0,
                                    bytes.fromhex(
                                        "000007e80062f19042"
                                        if target_bus == 0x22
                                        else "000007e862f19042"
                                    ),
                                ),
                            ),
                        )
                    ]
                )
                old = NativeCommunication.from_backend(
                    profile,
                    backend,
                    "first",
                    first_request=b"\x22\xf1\x90",
                    driver=DRIVER,
                    device_kind=8,
                    bus_id=0x12,
                    source_build=version,
                    clock=lambda: 0.0,
                )
                old.send_native(
                    NativeFrameSend("SendIntNoInit", 42, b"\x22\xf1\x90", 1000, 0x12)
                )
                controller = old.operations
                assert isinstance(controller, NativeFrameController)
                prior_lower = controller.operations
                logged = bytearray()

                def writer(data, logged=logged):
                    logged.extend(data)
                    return len(data)

                controller.set_packet_log(writer)
                self.assertEqual(
                    controller.change_context(
                        target,
                        bus_id=target_bus,
                        first_request=b"\x22\xf1\x90",
                        request=b"\x22\xf1\x90",
                        deadline=10.0,
                    ),
                    0,
                )
                self.assertEqual(controller.operations is prior_lower, not rebuild)
                self.assertEqual(
                    sum(operation == "connect" for operation, _ in backend.calls),
                    2 if rebuild else 1,
                )
                before = len(backend.calls)
                with self.assertRaises(SessionError):
                    old.execute(profile.direct_frame(0, 1))
                self.assertEqual(len(backend.calls), before)
                current = NativeCommunication(
                    target,
                    controller,
                    "second",
                    bus_id=target_bus,
                    source_build=version,
                    clock=lambda: 0.0,
                )
                current.no_init = True
                self.assertEqual(
                    current.execute(target.direct_frame(0, 1)).response,
                    bytes.fromhex("62f19042"),
                )
                self.assertEqual(logged, b"22F190\\n62F19042\\n")
                controller.set_packet_log(None)
                current.send_native(
                    NativeFrameSend("SendIntNoInit", 42, b"\x31\x01", 1000, target_bus)
                )
                self.assertEqual(logged, b"22F190\\n62F19042\\n")
                if version == 18:
                    from scripts.database_resources import DdrPacketLog

                    with tempfile.TemporaryDirectory() as directory:
                        packet_log = DdrPacketLog(Path(directory), controller)
                        self.assertEqual(packet_log.start(), 0)
                        self.assertEqual(
                            controller.change_context(
                                profile,
                                bus_id=0x12,
                                first_request=b"\x31\x01",
                                request=b"\x31\x01",
                                deadline=10.0,
                            ),
                            0,
                        )
                        old.send_native(
                            NativeFrameSend(
                                "SendIntNoInit", 42, b"\x31\x01", 1000, 0x12
                            )
                        )
                        self.assertEqual(packet_log.stop(), 0)
                        self.assertEqual(packet_log.path.read_bytes(), b"3101")
                        old.send_native(
                            NativeFrameSend(
                                "SendIntNoInit", 42, b"\x31\x01", 1000, 0x12
                            )
                        )
                        self.assertEqual(packet_log.path.read_bytes(), b"3101")
                current.close()
                old.close()

    def test_actual_bus_1c_null_wakeup_retains_sentinel_and_skips_base_null_send(self):
        for version in (12, 18):
            profile = serialized_profile(version=version, bus=0x1C)
            backend = J2534Fixture(
                [
                    J2534Result(
                        count=1, messages=(NativeMessage(3, 0, 0, 0, 0, b"\x03\x67"),)
                    )
                ]
            )
            runtime = NativeCommunication.from_backend(
                profile,
                backend,
                "iso-1c",
                first_request=b"\x22\xf1\x90",
                driver=DRIVER,
                device_kind=8,
                bus_id=0x1C,
                source_build=version,
                clock=lambda: 0.0,
            )
            self.assertEqual(
                runtime.send_native(
                    NativeFrameSend("SendIntNoInit", 42, None, 1000, 0x1C)
                ),
                0,
            )
            controller = runtime.operations
            assert isinstance(controller, NativeFrameController)
            self.assertTrue(controller.legacy_initialized)
            self.assertEqual(controller.legacy_service, 10000)
            writes = [
                fields["messages"][0].data
                for operation, fields in backend.calls
                if operation == "write_messages"
            ]
            self.assertEqual(writes, [bytes.fromhex("03e0")])  # Native125d0 wakeup.
            self.assertEqual(
                runtime.send_native(
                    NativeFrameSend("SendIntNoInit", 42, b"\x22\xf1\x90", 1000, 0x1C)
                ),
                0,
            )
            self.assertFalse(controller.legacy_initialized)
            self.assertEqual(controller.legacy_service, 0x22)
            before = len(backend.calls)
            self.assertEqual(
                runtime.send_native(
                    NativeFrameSend("SendIntNoInit", 42, b"\x31\x01", 1000, 0x1C)
                ),
                0x90020104,
            )
            self.assertFalse(
                any(
                    operation == "write_messages"
                    for operation, _ in backend.calls[before:]
                )
            )
            self.assertEqual(controller.legacy_service, 0x22)
            runtime.close()

    def test_actual_tester_dd_base_send_receive_and_stop(self):
        for version in (12, 18):
            profile = serialized_profile(version=version, flags=0x14)
            sections = {
                slot: (section.count, section.payload)
                for slot, section in profile.catalog.management.sections.items()
            }
            count, functions = sections[18]
            sections[18] = (
                count + 1,
                functions + struct.pack("<8H", 42, 0xDD, 0, 1, 0, 0, 0, 0),
            )
            encoded = bytearray(encode_database(1, sections))
            struct.pack_into("<I", encoded, 28, profile.catalog.management.version)
            profile.catalog.management = parse_database(bytes(encoded))
            backend = J2534Fixture(
                [
                    J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(6, 0, 0, 0, 0, bytes.fromhex("000007e85001")),
                        ),
                    ),
                ]
            )
            runtime = NativeCommunication.from_backend(
                profile,
                backend,
                "tester",
                first_request=b"\x22\xf1\x90",
                driver=DRIVER,
                device_kind=8,
                bus_id=0x12,
                source_build=version,
                clock=lambda: 0.0,
            )
            controller = runtime.operations
            assert isinstance(controller, NativeFrameController)
            runtime.send_native(
                NativeFrameSend(
                    "SendIntNoInitNoSession", 42, b"\x22\xf1\x90", 1000, 0x12, 0, 1
                )
            )
            self.assertEqual(controller.start_tester(), 0)
            assert controller._tester_thread is not None
            self.assertTrue(controller._tester_thread.is_alive())
            # Frozen clock keeps the worker asleep; execute one literal native cycle.
            controller._tester_cycle()
            self.assertEqual(controller.session_state, 3 if version == 18 else 0)
            self.assertEqual(controller.current_service, 0x22)
            writes = [
                fields["messages"][0].data
                for operation, fields in backend.calls
                if operation == "write_messages"
            ]
            self.assertEqual(
                writes, [bytes.fromhex("000007e022f190"), bytes.fromhex("000007e01001")]
            )
            backend.write_codes.append(9)
            read_count = sum(
                operation == "read_messages" for operation, _ in backend.calls
            )
            controller._tester_cycle()
            self.assertEqual(
                (controller.session_state, controller._tester_mode), (0, 1)
            )
            self.assertEqual(
                sum(operation == "read_messages" for operation, _ in backend.calls),
                read_count,
            )
            if version == 18:
                backend.replies.append(
                    J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(
                                6, 0, 0, 0, 0, bytes.fromhex("000007e87f1011")
                            ),
                        ),
                    )
                )
                controller._tester_cycle()
                self.assertEqual(
                    (controller.session_state, controller._tester_mode), (0, 0)
                )
            thread = controller._tester_thread
            assert thread is not None
            self.assertEqual(controller.stop_tester(), 0)
            self.assertFalse(thread.is_alive())
            before = len(backend.calls)
            runtime.close()
            self.assertFalse(
                any(
                    operation == "write_messages"
                    for operation, _ in backend.calls[before:]
                )
            )

    def test_actual_psa_service_outer_sends_d1_d2_then_selected_payload(self):
        profile = serialized_profile(flags=0x14)
        sections = {
            slot: (section.count, section.payload)
            for slot, section in profile.catalog.management.sections.items()
        }
        count, functions = sections[18]
        sections[18] = (
            count + 2,
            functions
            + struct.pack("<8H", 42, 0xD1, 0, 1, 0, 0, 0, 0)
            + struct.pack("<8H", 42, 0xD2, 0, 2, 0, 0, 0, 0),
        )
        profile.catalog.management = parse_database(encode_database(1, sections))
        replies = [
            NativeMessage(6, 0, 0, 0, 0, bytes.fromhex(data))
            for data in ("000007e85001", "000007e8c1", "000007e862f19042")
        ]
        backend = J2534Fixture(
            [J2534Result(count=1, messages=(reply,)) for reply in replies]
        )
        runtime = NativeCommunication.from_backend(
            profile,
            backend,
            "psa-ecu",
            first_request=b"\x22\xf1\x90",
            driver=DRIVER,
            device_kind=8,
            bus_id=0x12,
            source_build=18,
            clock=lambda: 0.0,
        )
        result = runtime.connection_no_buffer()
        self.assertEqual((result.status, result.connected), (0, True))
        writes = [
            fields["messages"][0].data
            for operation, fields in backend.calls
            if operation == "write_messages"
        ]
        self.assertEqual(
            writes,
            [
                bytes.fromhex("000007e01001"),
                bytes.fromhex("000007e081"),
                bytes.fromhex("000007e022f190"),
            ],
        )
        assert isinstance(runtime.operations, NativeFrameController)
        self.assertEqual(runtime.operations.session_state, 3)
        self.assertEqual(runtime.operations.operations.current_service, 0x22)
        runtime.close()

    def test_actual_psa_family_transition_runs_one_d1_and_changes_header(self):
        profile = serialized_profile(flags=0x14)
        sections = {
            slot: (section.count, section.payload)
            for slot, section in profile.catalog.management.sections.items()
        }
        count, functions = sections[18]
        sections[18] = (
            count + 2,
            functions
            + struct.pack("<8H", 42, 0xD1, 0, 1, 0, 0, 0, 0)
            + struct.pack("<8H", 42, 0xD2, 0, 2, 0, 0, 0, 0),
        )
        profile.catalog.management = parse_database(encode_database(1, sections))
        packets = (
            "000007e85001",
            "000007e8c1",
            "000007e862f19042",
            "000007e85001",
            "000007e84100",
        )
        backend = J2534Fixture(
            [
                J2534Result(
                    count=1,
                    messages=(NativeMessage(6, 0, 0, 0, 0, bytes.fromhex(packet)),),
                )
                for packet in packets
            ]
        )
        runtime = NativeCommunication.from_backend(
            profile,
            backend,
            "psa-transition",
            first_request=b"\x22\xf1\x90",
            driver=DRIVER,
            device_kind=8,
            bus_id=0x12,
            source_build=18,
            clock=lambda: 0.0,
        )
        self.assertTrue(runtime.connection_no_buffer().connected)
        result = runtime.execute(profile.direct_frame(0, 1), b"\x01\x00")
        self.assertEqual((result.status, result.response), (0, b"\x41\x00"))
        writes = [
            fields["messages"][0].data.hex()
            for operation, fields in backend.calls
            if operation == "write_messages"
        ]
        self.assertEqual(
            writes,
            [
                "000007e01001",
                "000007e081",
                "000007e022f190",
                "000007e01001",
                "000007df0100",
            ],
        )
        assert isinstance(runtime.operations, NativeFrameController)
        self.assertEqual(runtime.operations.session_state, 0)
        runtime.close()

    def test_actual_psa_no_session_bypasses_session_commands(self):
        profile = serialized_profile(flags=0x14)
        wire = NativeMessage(6, 0, 0, 0, 0, bytes.fromhex("000007e862f19042"))
        backend = J2534Fixture([J2534Result(count=1, messages=(wire,))])
        runtime = NativeCommunication.from_backend(
            profile,
            backend,
            "psa-no-session",
            first_request=b"\x22\xf1\x90",
            driver=DRIVER,
            device_kind=8,
            bus_id=0x12,
            source_build=18,
            clock=lambda: 0.0,
        )
        runtime.no_session = True
        result = runtime.connection_no_buffer(temporary=True)
        self.assertEqual(result.status, 0)
        assert isinstance(runtime.operations, NativeFrameController)
        self.assertTrue(runtime.operations.operations.last_no_session)
        self.assertEqual(runtime.operations.session_state, 0)
        self.assertEqual(
            sum(operation == "write_messages" for operation, _ in backend.calls), 1
        )
        runtime.close()

    def test_actual_psa_sid_one_selects_functional_header_without_no_session_equivalence(
        self,
    ):
        profile = serialized_profile(flags=0x14, request=b"\x01\x00", check=b"\x41")
        wire = NativeMessage(6, 0, 0, 0, 0, bytes.fromhex("000007e8410001"))
        backend = J2534Fixture([J2534Result(count=1, messages=(wire,))])
        runtime = NativeCommunication.from_backend(
            profile,
            backend,
            "psa-functional",
            first_request=b"\x01\x00",
            driver=DRIVER,
            device_kind=8,
            bus_id=0x12,
            source_build=18,
            clock=lambda: 0.0,
        )
        result = runtime.connection_no_buffer()
        self.assertEqual((result.status, result.connected), (0, True))
        writes = [
            fields["messages"][0].data
            for operation, fields in backend.calls
            if operation == "write_messages"
        ]
        self.assertEqual(writes, [bytes.fromhex("000007df0100")])
        assert isinstance(runtime.operations, NativeFrameController)
        self.assertEqual(runtime.operations.session_state, 0)
        self.assertFalse(runtime.operations.operations.last_no_session)
        runtime.close()

    def test_wwh_classifier_literal_native_patterns(self):
        for payload, state in (
            (b"", 1),
            (bytes.fromhex("14ffff33"), 4),
            (bytes.fromhex("14ffff00"), 1),
            (bytes.fromhex("1942"), 3),
            (bytes.fromhex("190400000000"), 3),
            (bytes.fromhex("190600000090"), 3),
            (bytes.fromhex("1906000000f0"), 1),
            (bytes.fromhex("22f490"), 4),
            (bytes.fromhex("22f390"), 1),
            (bytes.fromhex("3101e000"), 3),
        ):
            self.assertEqual(wwh_request_state(payload), state)

    def test_actual_wwh_source18_selects_classifier_state_and_functional_address(self):
        for version in (12, 18):
            profile = serialized_profile(
                version=version, flags=0x14, request=bytes.fromhex("22f490")
            )
            management = profile.catalog.management
            sections = {
                slot: (section.count, section.payload)
                for slot, section in management.sections.items()
            }
            info = bytearray(24)
            struct.pack_into("<HH", info, 8, 42, 0x27)
            sections[26] = (1, bytes(info))
            count, prot = sections[13]
            prot = bytearray(prot)
            struct.pack_into("<H", prot, 20, 0x7EA)
            sections[13] = (count, bytes(prot))
            image = bytearray(encode_database(1, sections))
            struct.pack_into("<I", image, 28, management.version)
            profile.catalog.management = parse_database(bytes(image))
            wire = NativeMessage(6, 0, 0, 0, 0, bytes.fromhex("000007ea62f49042"))
            replies = [J2534Result(count=1, messages=(wire,))]
            if version == 12:
                replies.append(J2534Result(code=9))
            backend = J2534Fixture(replies)
            runtime = NativeCommunication.from_backend(
                profile,
                backend,
                "wwh-ecu",
                first_request=bytes.fromhex("22f490"),
                driver=DRIVER,
                device_kind=8,
                bus_id=0x12,
                source_build=version,
                clock=lambda: 0.0,
            )
            result = runtime.connection_no_buffer()
            self.assertEqual((result.status, result.connected), (0, True))
            assert isinstance(runtime.operations, NativeFrameController)
            lower = runtime.operations.operations
            self.assertEqual(
                lower.native_variant, "psa_wwh" if version == 18 else "psa"
            )
            writes = [
                fields["messages"][0].data
                for operation, fields in backend.calls
                if operation == "write_messages"
            ]
            self.assertEqual(
                writes,
                [
                    bytes.fromhex(
                        "000007df22f490" if version == 18 else "000007e022f490"
                    )
                ],
            )
            if version == 18:
                self.assertEqual(lower.request_state, 4)
            runtime.close()

    def test_foreign_selected_metadata_rejected_before_primitive(self):
        runtime, lower = self.runtime()
        with self.assertRaises(ValueError):
            runtime.execute(frame(retries=1))
        self.assertEqual(lower.calls, [])

    def test_actual_lower_null_connection_forces_initialization_and_no_application_write(
        self,
    ):
        profile = serialized_profile(flags=4, request=b"")
        startup = NativeMessage(6, 0, 0, 0, 0, bytes.fromhex("000007e85001"))
        backend = J2534Fixture([J2534Result(count=1, messages=(startup,))])
        runtime = NativeCommunication.from_backend(
            profile,
            backend,
            "null-init-ecu",
            first_request=b"\x10\x01",
            driver=DRIVER,
            device_kind=8,
            bus_id=0x12,
            source_build=18,
            clock=lambda: 0.0,
        )
        result = runtime.connection_no_buffer()
        self.assertEqual((result.status, result.connected), (0, True))
        writes = [
            fields
            for operation, fields in backend.calls
            if operation == "write_messages"
        ]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0]["messages"][0].data, bytes.fromhex("000007e01001"))
        self.assertEqual(writes[0]["timeout"], 1000)
        runtime.close()

    def test_actual_lower_packet_log_hooks_record_sent_and_received_payloads(self):
        profile = serialized_profile()
        wire = NativeMessage(6, 0, 0, 0, 0, bytes.fromhex("000007e862f19042"))
        backend = J2534Fixture(
            [J2534Result(count=1, messages=(wire,)), J2534Result(code=9)]
        )
        runtime = NativeCommunication.from_backend(
            profile,
            backend,
            "logged-ecu",
            first_request=b"\x22\xf1\x90",
            driver=DRIVER,
            device_kind=8,
            bus_id=0x12,
            source_build=18,
            clock=lambda: 0.0,
        )
        assert isinstance(runtime.operations, NativeFrameController)
        logs = []

        def write(data):
            logs.append(data)
            return len(data)

        runtime.operations.operations.set_packet_log(write)
        result = runtime.connection_no_buffer()
        self.assertEqual(result.status, 0)
        self.assertEqual(logs, [b"22F190\\n", b"62F19042\\n"])
        runtime.close()

    def test_timeout_conversion_18_only_optional_join(self):
        profile = selected_profile()
        selected = profile.protocol_info(0x12)
        assert selected is not None
        prot = bytearray(selected)
        prot[26] = 1
        profile.catalog.management.sections[13] = replace(
            profile.catalog.management.sections[13], payload=bytes(prot)
        )
        can = bytearray(profile.catalog.management.sections[14].payload)
        struct.pack_into("<H", can, 14, 777)
        profile.catalog.management.sections[14] = replace(
            profile.catalog.management.sections[14], payload=bytes(can)
        )
        self.assertEqual(receive_timeout(profile, b"\x01", 0x12, 350, 18), 777)
        self.assertEqual(receive_timeout(profile, b"\x01", 0x12, 350, 12), 350)
        self.assertEqual(receive_timeout(profile, b"\x22", 0x12, 350, 18), 350)


if __name__ == "__main__":
    unittest.main()
