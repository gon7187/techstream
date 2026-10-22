"""Authored selected-profile wire and workflow regressions."""

import copy
import json
import struct
import tempfile
import unittest
from dataclasses import dataclass, replace
from pathlib import Path
from unittest.mock import patch

from scripts.database_resources import DdrPacketLog
from scripts.diagnostic_db import Language, Section, parse_database
from scripts.frame_transport import DriverProperties, J2534Result, NativeMessage
from scripts.freeze_p5 import (
    P5Diagnostic,
    P5FreezeSignal,
    P5FreezeState,
    P5SnapshotRequest,
    P5Value,
)
from scripts.monitor_support import (
    MonitorSupportCache,
    SupportQuery,
    SupportReceive,
    SupportSend,
)
from scripts.native_communication import NativeCommunication, NativeFrameController
from scripts.profiles import VehicleCatalog
from scripts.toyota import ToyotaCodecError
from scripts.toyota_session import (
    Cancelled,
    Limits,
    NativeFrameSend,
    NativeStatus,
    SessionError,
)
from scripts.toyota_workflows import (
    SavedLogInput,
    ToyotaWorkflows,
    WorkflowLabel,
    WorkflowObservations,
    WorkflowRecording,
    analyze_each_p5_reply,
    analyze_predictive_p5_replies,
    create_example_files,
    load_psd_label,
    merge_p5_diagnostics,
    parse_each_p5_reply,
    parse_operation_p5_reply,
    replay_workflow,
    select_comm_did_target,
    selected_saved_logs,
)


def database(kind, sections):
    header = bytearray(36 + 4 * (max(sections) + 1))
    header[8:10] = bytes((kind, max(sections) + 1))
    header[10:28] = b"DiagTool DataCtrl\0"
    struct.pack_into("<I", header, 28, 0x0100032F)
    body = bytearray()
    for slot, (count, payload) in sorted(sections.items()):
        struct.pack_into("<I", header, 36 + slot * 4, len(header) + len(body))
        body += struct.pack("<BBII", slot, 0, count, len(payload)) + payload
    return bytes(header + body)


@dataclass
class NativeReply:
    code: int
    data: bytes


class ToyotaWorkflowTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.frames = [(42, 1, 0, 1, b"\x14\xaa", b"", b"")]
        self.timers = [struct.pack("<I4H", 30, 42, 1, 0, 0)]
        self.settings = [(1, 0x11223344), (2, 0x55667788)]
        self.clock = [0.0]
        self.calls = []
        self.functions = {}
        self.details = []
        self.build()

    def build(self):
        category = bytearray(76)
        category[:18] = "demo.ddb\0".encode("utf-16le")
        struct.pack_into("<H", category, 68, 42)
        category[72] = getattr(self, "category_flags", 0)
        variables, comm, functions = [], [], []
        for identifier, (
            cat,
            function,
            order,
            setting,
            request,
            mask,
            check,
        ) in enumerate(sorted(self.frames), 1):
            refs = []
            for value in (request, mask, check):
                variables.append(value)
                refs.append(len(variables))
            comm.append(struct.pack("<4H", identifier, *refs))
            functions.append(
                struct.pack("<8H", cat, function, setting, identifier, 0, order, 0, 0)
            )
        offset, index = 0, bytearray()
        for value in variables:
            index += struct.pack("<IH", offset, len(value))
            offset += len(value)
        settings = []
        for key, native_word in self.settings:
            row = bytearray(16)
            struct.pack_into("<I", row, 0, native_word)
            struct.pack_into("<H", row, 10, key)
            settings.append(bytes(row))
        sections = {
            0: (len(variables), bytes(index) + b"".join(variables)),
            16: (1, bytes(category)),
            17: (len(comm), b"".join(comm)),
            18: (len(functions), b"".join(functions)),
            29: (len(settings), b"".join(settings)),
            27: (len(self.details), b"".join(self.details)),
        }
        if self.timers is not None:
            sections[25] = (len(self.timers), b"".join(self.timers))
        (self.root / "Toyota.ddb").write_bytes(database(1, sections))
        (self.root / "M_English.ddb").write_bytes(database(4, {0: (0, b"")}))
        (self.root / "demo.ddb").write_bytes(database(2, {10: (0, b"")}))
        self.profile = VehicleCatalog(self.root).build_profile(42)

    def workflow(
        self,
        exchange=None,
        *,
        native_send=None,
        cancelled=lambda: False,
        observations=None,
        native_get_mode=None,
        native_set_mode=None,
        support_exchange=None,
        support_stream=None,
    ):
        def default(ecu, request):
            self.calls.append((ecu, request))
            return bytes([request[0] | 0x40]) + request[1:]

        return ToyotaWorkflows.from_profile(
            self.profile,
            exchange or default,
            ecu="authored-ecu",
            observations=observations or WorkflowObservations(42, 7, self.functions),
            native_send=native_send,
            native_get_mode=native_get_mode,
            native_set_mode=native_set_mode,
            support_exchange=support_exchange,
            support_stream=support_stream,
            cancelled=cancelled,
            clock=lambda: self.clock[0],
            sleep=lambda seconds: self.clock.__setitem__(0, self.clock[0] + seconds),
        )

    def test_plain_clear_uses_selected_frame_timer_and_native_flag(self):
        self.assertEqual(
            self.workflow().clear_dtc(), {"native_status": 0, "native_clear_flag": 1}
        )
        self.assertEqual(self.calls, [("authored-ecu", bytes.fromhex("14aa"))])
        self.assertAlmostEqual(self.clock[0], 0.03)
        self.assertEqual(
            self.workflow(
                observations=WorkflowObservations(42, 7, {}, source_version=12)
            ).clear_dtc()["native_clear_flag"],
            1,
        )

    def test_native_communication_factory_preserves_selected_frames_and_budget(self):
        events = []

        class Lower:
            def send(self, request, **arguments):
                events.append(("send", request, arguments))
                return 0

            def receive(self, **arguments):
                events.append(("receive", arguments))
                return NativeReply(code=0, data=bytes.fromhex("54aa"))

            def close(self):
                events.append(("close",))

        communication = NativeCommunication(
            self.profile, Lower(), "authored-ecu", bus_id=7, clock=lambda: self.clock[0]
        )
        workflow = ToyotaWorkflows.from_communication(
            communication,
            observations=WorkflowObservations(42, 7, {}),
            sleep=lambda seconds: self.clock.__setitem__(0, self.clock[0] + seconds),
        )
        self.assertEqual(
            workflow.clear_dtc(), {"native_status": 0, "native_clear_flag": 1}
        )
        self.assertEqual([event[0] for event in events], ["send", "receive"])
        self.assertEqual(events[0][1], bytes.fromhex("14aa"))
        self.assertEqual(events[0][2]["timeout"], 0x11223344)
        self.assertEqual(workflow._remaining, 254)
        self.assertIs(workflow._support(), communication.cache)
        selected = workflow.session.commands["0001:0"].selected
        assert selected is not None and communication.last_result is not None
        self.assertIs(selected.frame, communication.last_result.selected.frame)
        workflow.session.commands["explicit-capacity"] = replace(
            workflow.session.commands["0001:0"],
            extended=True,
            receive_capacity=65535,
        )
        workflow.session.execute("explicit-capacity")
        self.assertEqual(events[-1][1]["maximum"], 65535)
        events.clear()
        constrained = ToyotaWorkflows.from_communication(
            communication,
            observations=WorkflowObservations(42, 7, {}),
            limits=Limits(exchanges=1),
            sleep=lambda _seconds: None,
        )
        with self.assertRaises(SessionError):
            constrained.clear_dtc()
        self.assertEqual([event[0] for event in events], ["send"])
        with self.assertRaises(ValueError):
            ToyotaWorkflows.from_communication(
                communication, observations=WorkflowObservations(42, 8, {})
            )

    def test_native_communication_rejects_management_only_profile_before_io(self):
        events = []

        class Lower:
            def send(self, request, **_arguments):
                events.append(("send", request))
                return 0

            def receive(self, **_arguments):
                events.append(("receive",))
                return NativeReply(code=0, data=b"")

            def close(self):
                events.append(("close",))

        profile = self.profile.catalog.build_protocol_profile(42)
        communication = NativeCommunication(
            profile, Lower(), "authored-ecu", bus_id=7, clock=lambda: self.clock[0]
        )
        with self.assertRaisesRegex(TypeError, "selected VehicleProfile"):
            ToyotaWorkflows.from_communication(
                communication, observations=WorkflowObservations(42, 7, {})
            )
        self.assertEqual(events, [])

    def test_session_and_native_communication_do_not_multiply_selected_retries(self):
        self.frames = [(42, 0xE4, 0, 1, bytes.fromhex("21000000"), b"", b"")]
        self.build()
        management = self.profile.catalog.management
        settings = bytearray(management.sections[29].payload)
        settings[14] = 1
        self.profile.catalog.management = replace(
            management,
            sections={
                **management.sections,
                29: replace(management.sections[29], payload=bytes(settings)),
            },
        )
        requests = []

        class Lower:
            def send(self, request, **_arguments):
                requests.append(request)
                return 0x91010009

            def receive(self, **_arguments):
                raise AssertionError("Failed send must not receive")

            def close(self):
                pass

        communication = NativeCommunication(
            self.profile,
            Lower(),
            "authored-ecu",
            bus_id=7,
            clock=lambda: self.clock[0],
        )
        workflow = ToyotaWorkflows.from_communication(
            communication,
            observations=WorkflowObservations(42, 7, {}),
        )
        workflow._begin()
        name = workflow._register(0xE4)[0]
        freeze = bytearray(84)
        struct.pack_into("<HH", freeze, 62, 0, 7)
        freeze[79] = 2
        with self.assertRaises(ToyotaCodecError) as caught:
            workflow.session.freeze_operation_p4(
                name,
                bytes(freeze),
                1,
                4,
                b"\x01",
                retries=1,
            )
        self.assertEqual(caught.exception.code, 0x91010009)
        self.assertEqual(requests, [bytes.fromhex("21010402")] * 2)

    def test_workflow_through_actual_typed_frame_transport(self):
        self.category_flags = 1
        self.frames += [
            (42, function, 0, 1, request, b"", b"")
            for function, request in (
                (0x67, b"\x10\x01"),
                (0x68, b"\x81"),
                (0x7F, b"\x3e"),
                (0x98, b"\x81"),
            )
        ]
        self.build()
        protocol, can = bytearray(28), bytearray(28)
        struct.pack_into("<6H", protocol, 0, 42, 1, 0x33, 0x7DF, 0x7E0, 0xAB)
        protocol[24] = 0x12
        struct.pack_into("<IIHHH", can, 0, 0x1234, 500000, 1, 0, 20)
        struct.pack_into("<H", can, 18, 9)
        management = self.profile.catalog.management
        self.profile.catalog.management = replace(
            management,
            sections={
                **management.sections,
                13: Section(13, 0, 1, False, bytes(protocol)),
                14: Section(14, 0, 1, False, bytes(can)),
            },
        )
        calls = []

        class Backend:
            def invoke(self, operation, fields, *, deadline, cancelled):
                calls.append((operation, dict(fields)))
                if operation == "connect":
                    return J2534Result(handle=41)
                if operation == "start_message_filter":
                    return J2534Result(handle=102)
                if operation == "write_messages":
                    return J2534Result(count=1)
                if operation == "read_messages":
                    return J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(6, 0, 0, 0, 0, bytes.fromhex("000007e854aa")),
                        ),
                    )
                return J2534Result()

        communication = NativeCommunication.from_backend(
            self.profile,
            Backend(),
            "authored-ecu",
            first_request=bytes.fromhex("14aa"),
            driver=DriverProperties(0, b"04.04", "authored-version-reply"),
            device_kind=8,
            bus_id=0x12,
            source_build=18,
            clock=lambda: self.clock[0],
        )
        workflow = ToyotaWorkflows.from_communication(
            communication,
            observations=WorkflowObservations(42, 0x12, {}),
            sleep=lambda seconds: self.clock.__setitem__(0, self.clock[0] + seconds),
        )
        self.assertFalse(calls)
        self.assertEqual(workflow.clear_dtc()["native_clear_flag"], 1)
        writes = [
            fields for operation, fields in calls if operation == "write_messages"
        ]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0]["messages"][0].data, bytes.fromhex("000007e014aa"))
        communication.close()
        self.assertIn("disconnect", [operation for operation, _fields in calls])

    def test_can_continuation_retains_actual_selected_transport_without_empty_send(
        self,
    ):
        self.category_flags = 1
        self.frames = [(42, 10, 0, 1, b"\x18", b"", b"")]
        self.frames += [
            (42, function, 0, 1, request, b"", b"")
            for function, request in ((0x67, b"\x10\x01"), (0x7F, b"\x3e"))
        ]
        self.build()
        for build in (12, 18):
            for mode in (
                "ordinary",
                "extended",
                "timeout",
                "continuation_retry",
                "initial_retry_spent",
                "fault",
                "partial_metadata",
                "cancel",
            ):
                with self.subTest(build=build, mode=mode):
                    profile = copy.deepcopy(self.profile)
                    protocol, can = bytearray(28 if build == 18 else 24), bytearray(28)
                    struct.pack_into(
                        "<6H", protocol, 0, 42, 1, 0x33, 0x7DF, 0x7E0, 0xAB
                    )
                    protocol[24 if build == 18 else 22] = 0x12
                    struct.pack_into("<IIHHH", can, 0, 0x1234, 500000, 1, 0, 20)
                    struct.pack_into("<H", can, 18 if build == 18 else 16, 9)
                    management = profile.catalog.management
                    settings = bytearray(management.sections[29].payload)
                    for at in range(0, len(settings), 16):
                        struct.pack_into("<I", settings, at + 4, 100)
                        settings[at + 14] = int(
                            mode in ("continuation_retry", "initial_retry_spent")
                        )
                    sections = {
                        **management.sections,
                        13: Section(13, 0, 1, False, bytes(protocol)),
                        14: Section(14, 0, 1, False, bytes(can)),
                        29: replace(management.sections[29], payload=bytes(settings)),
                    }
                    serialized = bytearray(
                        database(
                            1,
                            {
                                slot: (section.count, section.payload)
                                for slot, section in sections.items()
                            },
                        )
                    )
                    struct.pack_into(
                        "<I", serialized, 28, 0x0100030C if build == 12 else 0x0100032F
                    )
                    profile.catalog.management = parse_database(bytes(serialized))
                    rows = []
                    for code in (0x1234, 0x2345):
                        row = bytearray(28)
                        text = ("P1234\0" if code == 0x1234 else "P2345\0").encode(
                            "utf-16le"
                        )
                        row[:12] = text
                        if mode == "partial_metadata" and code == 0x2345:
                            row[:2] = bytes.fromhex("00d8")
                        struct.pack_into("<H", row, 20, code)
                        row[26] = 1
                        rows.append(bytes(row))
                    definitions = bytearray(database(2, {5: (2, b"".join(rows))}))
                    struct.pack_into(
                        "<I", definitions, 28, 0x0100030C if build == 12 else 0x0100032F
                    )
                    profile = replace(
                        profile, database=parse_database(bytes(definitions))
                    )
                    actions = {
                        "ordinary": [
                            bytes.fromhex("58021234"),
                            bytes.fromhex("58022345"),
                        ],
                        "extended": [
                            bytes.fromhex("58011234"),
                            bytes.fromhex("58012345"),
                            bytes.fromhex("5800"),
                        ],
                        "timeout": [bytes.fromhex("58011234"), 9],
                        "continuation_retry": [
                            bytes.fromhex("58021234"),
                            9,
                            bytes.fromhex("58012345"),
                        ],
                        "initial_retry_spent": [9, bytes.fromhex("58021234"), 9],
                        "fault": [bytes.fromhex("58021234"), 0xDEADBEEF],
                        "partial_metadata": [
                            bytes.fromhex("58021234"),
                            bytes.fromhex("58022345"),
                        ],
                        "cancel": [
                            bytes.fromhex("58021234"),
                            bytes.fromhex("58022345"),
                        ],
                    }[mode]
                    cancelled = [False]

                    class Backend:
                        def __init__(
                            self, actions=actions, mode=mode, cancellation=cancelled
                        ):
                            self.actions = actions
                            self.mode = mode
                            self.cancellation = cancellation
                            self.request = b""
                            self.writes = []
                            self.reads = []

                        def invoke(self, operation, fields, *, deadline, cancelled):
                            if operation == "connect":
                                return J2534Result(handle=41)
                            if operation == "start_message_filter":
                                return J2534Result(handle=102)
                            if operation == "write_messages":
                                self.request = fields["messages"][0].data[4:]
                                self.writes.append(self.request)
                                return J2534Result(count=1)
                            if operation == "read_messages":
                                if fields["timeout"] == 0:
                                    return J2534Result(code=9)
                                if self.request == b"\x10\x01":
                                    reply = bytes.fromhex("5001")
                                else:
                                    self.reads.append(dict(fields))
                                    reply = self.actions.pop(0) if self.actions else 9
                                    if self.mode == "cancel" and len(self.reads) == 2:
                                        self.cancellation[0] = True
                                    if isinstance(reply, int):
                                        return J2534Result(code=reply)
                                return J2534Result(
                                    count=1,
                                    messages=(
                                        NativeMessage(
                                            6,
                                            0,
                                            0,
                                            0,
                                            0,
                                            bytes.fromhex("000007e8") + reply,
                                        ),
                                    ),
                                )
                            return J2534Result()

                    backend = Backend()
                    communication = NativeCommunication.from_backend(
                        profile,
                        backend,
                        "authored-ecu",
                        first_request=b"\x18",
                        driver=DriverProperties(0, b"04.04", "authored-version-reply"),
                        device_kind=8,
                        bus_id=0x12,
                        source_build=build,
                        cancelled=lambda cancelled=cancelled: cancelled[0],
                        clock=lambda: self.clock[0],
                    )
                    workflow = ToyotaWorkflows.from_communication(
                        communication,
                        observations=WorkflowObservations(
                            42, 0x12, {}, source_version=build
                        ),
                        cancelled=lambda cancelled=cancelled: cancelled[0],
                    )
                    self.assertIs(workflow.session.native_communication, communication)
                    workflow._begin(source12_verified=True)
                    name = workflow._register(10)[0]
                    output = {}

                    def read_codes(
                        workflow=workflow,
                        name=name,
                        mode=mode,
                        settings=settings,
                        profile=profile,
                        output=output,
                    ):
                        return workflow.session.dtcs_can(
                            name,
                            extended=mode in ("extended", "timeout"),
                            retries=settings[14],
                            selected_profile=profile,
                            output=output,
                        )

                    if mode == "partial_metadata":
                        with self.assertRaises(UnicodeDecodeError):
                            read_codes()
                    elif mode in ("initial_retry_spent", "fault"):
                        with self.assertRaises(ToyotaCodecError):
                            read_codes()
                    elif mode == "cancel":
                        with self.assertRaises(Cancelled):
                            read_codes()
                    else:
                        codes = read_codes()
                        self.assertEqual(
                            codes, [0x1234] if mode == "timeout" else [0x1234, 0x2345]
                        )
                    self.assertEqual(
                        output["codes"],
                        [0x1234]
                        if mode
                        in (
                            "timeout",
                            "partial_metadata",
                            "initial_retry_spent",
                            "fault",
                            "cancel",
                        )
                        else [0x1234, 0x2345],
                    )
                    self.assertTrue(
                        all(read["timeout"] == 100 for read in backend.reads)
                    )
                    self.assertTrue(
                        any(event["receive_only"] for event in workflow.session.trace)
                    )
                    self.assertNotIn(b"", backend.writes)
                    self.assertEqual(
                        backend.writes.count(b"\x18"),
                        2 if mode == "initial_retry_spent" else 1,
                    )
                    self.assertFalse(actions)
                    cancelled[0] = False
                    communication.close()

    def test_operation_p5_full_native_log_connection_and_error_precedence(self):
        self.category_flags = 1
        self.frames = [
            (42, 0x66, 0, 1, b"\x22\x00", b"", b""),
            (42, 0xD0, 0, 1, bytes.fromhex("191000"), b"", b""),
        ]
        self.frames += [
            (42, function, 0, 1, request, b"", b"")
            for function, request in (
                (0x67, b"\x10\x01"),
                (0x68, b"\x81"),
                (0x7F, b"\x3e"),
                (0x98, b"\x81"),
            )
        ]
        self.build()
        protocol, can = bytearray(28), bytearray(28)
        struct.pack_into("<6H", protocol, 0, 42, 1, 0x33, 0x7DF, 0x7E0, 0xAB)
        protocol[24] = 0x12
        struct.pack_into("<IIHHH", can, 0, 0x1234, 500000, 1, 0, 20)
        struct.pack_into("<H", can, 18, 9)
        management = self.profile.catalog.management
        frames = management.sections[17]
        settings = bytearray(management.sections[29].payload)
        struct.pack_into("<I", settings, 4, 100)
        self.profile.catalog.management = replace(
            management,
            sections={
                **management.sections,
                13: Section(13, 0, 1, False, bytes(protocol)),
                14: Section(14, 0, 1, False, bytes(can)),
                29: replace(management.sections[29], payload=bytes(settings)),
                17: replace(
                    frames,
                    count=frames.count + 1,
                    payload=frames.payload + struct.pack("<4H", 0, 0, 0, 0),
                ),
            },
        )
        mode: list[str | None] = [None]
        cancel_flag = [False]

        class Backend:
            def __init__(self):
                self.calls = []
                self.requests = []
                self.request = b""

            def invoke(self, operation, fields, *, deadline, cancelled):
                self.calls.append(operation)
                if operation == "disconnect" and mode[0] in (
                    "cleanup",
                    "fatal_cleanup",
                ):
                    raise OSError("authored disconnect failure")
                if operation == "connect":
                    return J2534Result(handle=41)
                if operation == "start_message_filter":
                    return J2534Result(handle=102)
                if operation == "write_messages":
                    self.request = fields["messages"][0].data[4:]
                    self.requests.append(self.request)
                    if (
                        mode[0] in ("fatal", "fatal_cleanup")
                        and self.request == b"\xab\x11"
                    ):
                        return J2534Result(code=0xDEADBEEF)
                    if mode[0] == "cancel" and self.request == b"\xab\x11":
                        cancel_flag[0] = True
                    return J2534Result(count=1)
                if operation == "read_messages":
                    if fields["timeout"] == 0 and mode[0] != "flood":
                        return J2534Result(code=9)
                    response = {
                        b"\xab\x11": bytes.fromhex("eb110102"),
                        bytes.fromhex("ab120102"): bytes.fromhex("eb1201020001"),
                        bytes.fromhex("ab1301020001"): bytes.fromhex(
                            "eb1301020001010501021234"
                        ),
                    }.get(
                        self.request,
                        bytes((self.request[0] | 0x40,)) + self.request[1:],
                    )
                    return J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(
                                6, 0, 0, 0, 0, bytes.fromhex("000007e8") + response
                            ),
                        ),
                    )
                return J2534Result()

        def make_context(folder, max_bytes=32 * 1024 * 1024, source_build=18):
            backend = Backend()
            profile = self.profile
            if source_build == 12:
                profile = copy.deepcopy(profile)
                management = profile.catalog.management
                protocol12 = bytearray(management.sections[13].payload[:24])
                protocol12[22] = 0x12
                can12 = bytearray(management.sections[14].payload)
                struct.pack_into("<H", can12, 16, 9)
                profile.catalog.management = replace(
                    management,
                    version=0x0100030C,
                    sections={
                        **management.sections,
                        13: replace(management.sections[13], payload=bytes(protocol12)),
                        14: replace(management.sections[14], payload=bytes(can12)),
                    },
                )
            communication = NativeCommunication.from_backend(
                profile,
                backend,
                "authored-ecu",
                first_request=bytes.fromhex("221007"),
                driver=DriverProperties(0, b"04.04", "authored-version-reply"),
                device_kind=8,
                bus_id=0x12,
                source_build=source_build,
                clock=lambda: self.clock[0],
            )
            assert isinstance(communication.operations, NativeFrameController)
            logger = DdrPacketLog(folder, communication.operations, max_bytes=max_bytes)
            communication.bind_comm_log(logger)
            workflow = ToyotaWorkflows.from_communication(
                communication,
                observations=WorkflowObservations(
                    42, 0x12, {}, source_version=source_build
                ),
                cancelled=lambda: cancel_flag[0],
            )
            return backend, logger, workflow

        backend, logger, workflow = make_context(self.root / "happy")
        result = workflow.operation_freeze_p5()
        lifecycle = result["lifecycle"]
        assert isinstance(lifecycle, dict)
        self.assertEqual(lifecycle["connection_status"], 0)
        self.assertEqual(lifecycle["disconnect_status"], 0)
        self.assertEqual(result["outer_lifecycle"], "native")
        self.assertIn("disconnect", backend.calls)
        self.assertFalse(logger.active)
        self.assertEqual(logger.path.name, "OperationFFD.log")
        self.assertIn(b"AB", logger.path.read_bytes())
        self.assertTrue(any(request == b"\xab\x11" for request in backend.requests))
        backend12, logger12, workflow12 = make_context(
            self.root / "operation12", source_build=12
        )
        result12 = workflow12.operation_freeze_p5()
        self.assertEqual(result12["outer_lifecycle"], "native")
        self.assertEqual(logger12.path.name, "OperationFFD.log")
        self.assertFalse(logger12.active)
        self.assertIn("disconnect", backend12.calls)
        self.assertEqual(
            [request for request in backend12.requests if request[:1] == b"\xab"],
            [
                bytes.fromhex("ab11"),
                bytes.fromhex("ab120102"),
                bytes.fromhex("ab1301020001"),
            ],
        )
        # Standalone Each's conditional log14 does not invent a connection or
        # disconnect lifecycle; all fourteen D0 probes still use the typed IO.
        self.each_profile()
        backend, logger, workflow = make_context(self.root / "each")
        result = workflow.each_freeze_p5(P5Diagnostic(0x123456, {}), log_enabled=True)
        self.assertEqual(result["outer_lifecycle"], "native_conditional_log")
        self.assertEqual(logger.path.name, "MarkMonRam_SSR.log")
        self.assertFalse(logger.active)
        self.assertNotIn("disconnect", backend.calls)
        self.assertEqual(
            len(
                [
                    request
                    for request in backend.requests
                    if request[:2] == bytes.fromhex("1910")
                ]
            ),
            14,
        )
        assert workflow._communication is not None
        workflow._communication.close()
        backend, logger, workflow = make_context(self.root / "separate-outer")
        other_backend, other_logger, other_workflow = make_context(
            self.root / "separate-target"
        )
        with self.assertRaisesRegex(SessionError, "share one native frame controller"):
            workflow.execute_absolute_pid_logs(
                [], contexts={(42, 0x12): other_workflow}
            )
        self.assertFalse(backend.calls)
        self.assertFalse(other_backend.calls)
        self.assertFalse(logger.path.exists())
        self.assertFalse(other_logger.path.exists())
        # Saved PID/routine exports share mode3 but retain their own selected
        # category validation after the actual connection check.
        for operation in ("execute_absolute_pid_logs", "execute_absolute_routine_logs"):
            backend, logger, workflow = make_context(self.root / operation)
            with self.assertRaises((SessionError, ToyotaCodecError)):
                getattr(workflow, operation)([], contexts={})
            self.assertEqual(logger.path.name, "AbsoluteTimeStamp.log")
            self.assertFalse(logger.active)
            self.assertIn("disconnect", backend.calls)
        # Native log failure does not skip data acquisition or its cleanup.
        bad = self.root / "bad"
        bad.write_bytes(b"blocked")
        backend, logger, workflow = make_context(bad)
        with self.assertRaises(ToyotaCodecError) as caught:
            workflow.operation_freeze_p5()
        self.assertEqual(caught.exception.code, 0x90020706)
        self.assertIn(b"\xab\x11", backend.requests)
        self.assertIn("disconnect", backend.calls)
        # A real body failure wins over start failure, with the channel released.
        mode[0] = "fatal"
        backend, logger, workflow = make_context(bad)
        with self.assertRaises(ToyotaCodecError) as caught:
            workflow.operation_freeze_p5()
        self.assertEqual(caught.exception.code, 0xDFADBEEF)
        self.assertIn("disconnect", backend.calls)
        mode[0] = "fatal_cleanup"
        backend, logger, workflow = make_context(self.root / "body-and-cleanup-fault")
        with self.assertRaises(ToyotaCodecError) as caught:
            workflow.operation_freeze_p5()
        self.assertEqual(caught.exception.code, 0xDFADBEEF)
        lifecycle = workflow.native_output["lifecycle"]
        assert isinstance(lifecycle, dict)
        self.assertEqual(lifecycle["cleanup_error"]["type"], "OSError")
        self.assertTrue(lifecycle["cleanup_pending"])
        self.assertFalse(logger.active)
        mode[0] = "cleanup"
        backend, logger, workflow = make_context(self.root / "cleanup-fault")
        with self.assertRaises(OSError):
            workflow.operation_freeze_p5()
        self.assertFalse(logger.active)
        # Host exceptions from stop also cannot replace the active body fault.
        mode[0] = None
        backend, logger, workflow = make_context(self.root / "host-stop-fault")
        assert workflow._communication is not None
        with (
            patch.object(
                workflow._communication,
                "stop_comm_log",
                side_effect=OSError("authored stop failure"),
            ),
            self.assertRaises(ToyotaCodecError) as caught,
            workflow._comm_log(0),
        ):
            raise ToyotaCodecError("authored body failure", 0xA0040201)
        self.assertEqual(caught.exception.code, 0xA0040201)
        logging = workflow.native_output["communication_log"]
        assert isinstance(logging, dict)
        self.assertEqual(logging["stop_error"]["type"], "OSError")
        logger.stop()
        # A saved packet write error is returned by Stop after successful body.
        mode[0] = None
        backend, logger, workflow = make_context(self.root / "short-log", max_bytes=1)
        with self.assertRaises(ToyotaCodecError) as caught:
            workflow.operation_freeze_p5()
        self.assertEqual(caught.exception.code, 0x90020706)
        self.assertFalse(logger.active)
        self.assertIn("disconnect", backend.calls)

        mode[0] = "cancel"
        backend, logger, workflow = make_context(self.root / "cancel")
        with self.assertRaises(Cancelled):
            workflow.operation_freeze_p5()
        self.assertIn("disconnect", backend.calls)
        self.assertFalse(logger.active)
        cancel_flag[0] = False
        # A never-ending drain exhausts the shared bound with its proper host
        # error, while finally still disconnects and closes the actual log.
        mode[0] = "flood"
        backend, logger, workflow = make_context(self.root / "flood")
        workflow.limits = Limits(exchanges=3)
        with self.assertRaises(SessionError):
            workflow.operation_freeze_p5()
        self.assertIn("disconnect", backend.calls)
        self.assertFalse(logger.active)

    def test_operation_p4_probe_pattern_and_fatal_timeout(self):
        self.frames = [
            (170, 0xE4, 0, 1, bytes.fromhex("1200aa00"), b"", b""),
            (170, 0x13, 0, 1, bytes.fromhex("0100"), b"", b""),
            (170, 0xE3, 0, 1, bytes.fromhex("18000000"), b"", b""),
        ]
        self.build()
        category = bytearray(self.profile.category_record)
        struct.pack_into("<H", category, 68, 170)
        group, check, freeze, pattern, operation = (
            bytearray(n) for n in (12, 8, 84, 24, 8)
        )
        struct.pack_into("<H", group, 4, 5)
        group[8] = 37
        struct.pack_into("<HH", check, 0, 5, 9)
        struct.pack_into("<H", freeze, 56, 9)
        struct.pack_into("<HH", freeze, 62, 0, 7)
        struct.pack_into("<H", freeze, 70, 6)
        freeze[79] = 2
        struct.pack_into("<I", pattern, 4, 99)
        struct.pack_into("<H", pattern, 12, 6)
        operation[5], operation[7] = 3, 129
        self.profile = replace(
            self.profile,
            category_record=bytes(category),
            database=replace(
                self.profile.database,
                sections={
                    0: Section(0, 0, 1, False, bytes(group)),
                    1: Section(1, 0, 1, False, bytes(check)),
                    10: Section(10, 0, 1, False, bytes(freeze)),
                    14: Section(14, 0, 1, False, bytes(pattern)),
                    54: Section(54, 0, 1, False, bytes(operation)),
                },
            ),
        )
        observed = WorkflowObservations(170, 7, {}, pid_positions={2: b"\x01"})

        def reply(ecu, request):
            self.calls.append((ecu, request))
            return bytes.fromhex("5200010000")

        result = self.workflow(reply, observations=observed).operation_freeze_p4()
        self.assertEqual(result, {"native_status": 0, "operations": [], "status": "ok"})
        self.assertEqual(self.calls, [("authored-ecu", bytes.fromhex("1203aa02"))])

        native18 = self.profile
        pattern12 = bytearray(20)
        struct.pack_into("<HH", pattern12, 4, 6, 0)
        struct.pack_into("<H", pattern12, 10, 99)
        self.profile = replace(
            self.profile,
            database=replace(
                self.profile.database,
                version=0x0100030C,
                sections={
                    **self.profile.database.sections,
                    14: Section(14, 0, 1, False, bytes(pattern12)),
                },
            ),
        )
        self.calls.clear()
        self.assertEqual(
            self.workflow(
                reply, observations=replace(observed, source_version=12)
            ).operation_freeze_p4(),
            result,
        )
        self.assertEqual(self.calls, [("authored-ecu", bytes.fromhex("1203aa02"))])
        self.profile = native18

        def timeout(_ecu, _request):
            raise NativeStatus(0x91010009)

        with self.assertRaises(ToyotaCodecError) as error:
            self.workflow(timeout, observations=observed).operation_freeze_p4()
        self.assertEqual(error.exception.code, 0x91010009)
        cancelled = [False]

        def cancel(_ecu, _request):
            cancelled[0] = True
            return bytes.fromhex("5200010000")

        with self.assertRaises(Cancelled):
            self.workflow(
                cancel,
                observations=observed,
                cancelled=lambda cancelled=cancelled: cancelled[0],
            ).operation_freeze_p4()

        # Matching probe then concrete raw-support/bitmap discovery and a
        # measured signal. Auxiliary groups are natively absent flags.
        struct.pack_into("<I", pattern, 4, 1)
        group38 = bytearray(group)
        group38[8] = 38
        struct.pack_into("<H", group38, 4, 6)
        check38 = struct.pack("<4H", 6, 9, 0, 0)
        physical, unit = bytearray(24), bytearray(12)
        struct.pack_into("<IIIHH", physical, 0, 2, 1, 0, 7, 1)
        struct.pack_into("<HH", unit, 4, 1, 4)
        struct.pack_into("<H", freeze, 60, 7)
        freeze[76], freeze[78] = 2, 2
        sections = dict(self.profile.database.sections)
        sections.update(
            {
                3: Section(3, 0, 1, False, bytes.fromhex("0000000000010000")),
                6: Section(6, 0, 1, False, bytes.fromhex("0000020100000000")),
                0: Section(0, 0, 2, False, bytes(group + group38)),
                1: Section(1, 0, 2, False, bytes(check) + check38),
                10: Section(10, 0, 1, False, bytes(freeze)),
                14: Section(14, 0, 1, False, bytes(pattern)),
                13: Section(13, 0, 1, False, bytes(physical)),
                15: Section(15, 0, 1, False, bytes(unit)),
            }
        )
        self.profile = replace(
            self.profile, database=replace(self.profile.database, sections=sections)
        )
        events = []

        class Stream:
            def __init__(self):
                self.replies = iter(
                    [(0, bytes.fromhex("4100020101")), (0x91010009, b"")]
                )

            def send(self, call):
                events.append(("send", call.query.request))
                return 0

            def receive(self, call):
                events.append(("receive", call.query.request))
                return next(self.replies)

        def data(_ecu, request):
            events.append(("data", request))
            return bytes.fromhex("5200010000")

        def support(query):
            events.append(("support", query.request))
            return bytes.fromhex("580040000000")

        result = self.workflow(
            data,
            observations=observed,
            support_exchange=support,
            support_stream=Stream(),
        ).operation_freeze_p4()
        operations = result["operations"]
        assert isinstance(operations, list)
        self.assertEqual(len(operations), 1)
        self.assertEqual(operations[0]["signals"][0]["value"], 2)
        self.assertEqual(
            operations[0]["native_fields"],
            {"20": 0, "24": 1, "c0": 0, "c4": 1, "160": 0, "signals": {}},
        )
        self.assertEqual(
            events,
            [
                ("data", bytes.fromhex("1203aa02")),
                ("send", bytes.fromhex("0100")),
                ("receive", bytes.fromhex("0100")),
                ("receive", bytes.fromhex("0100")),
                ("support", bytes.fromhex("18030000")),
                ("data", bytes.fromhex("1203aa02")),
            ],
        )
        native18 = self.profile
        pattern12 = bytearray(20)
        struct.pack_into("<H", pattern12, 4, 6)
        struct.pack_into("<H", pattern12, 10, 1)
        self.profile = replace(
            self.profile,
            database=replace(
                self.profile.database,
                version=0x0100030C,
                sections={
                    **self.profile.database.sections,
                    14: Section(14, 0, 1, False, bytes(pattern12)),
                },
            ),
        )
        expected_events = list(events)
        events.clear()
        result12 = self.workflow(
            data,
            observations=replace(observed, source_version=12),
            support_exchange=support,
            support_stream=Stream(),
        ).operation_freeze_p4()
        self.assertEqual(result12, result)
        self.assertEqual(events, expected_events)
        self.profile = native18

        sends = []

        def native_send(ecu, call):
            sends.append((ecu, call.operation, call.arguments))
            return 0xA0040202

        workflow = self.workflow(
            timeout, observations=observed, native_send=native_send
        )
        workflow._begin()
        with self.assertRaises(ToyotaCodecError) as fault:
            workflow._operation_sample(bytes(freeze), 3, {}, initialize_timeout=True)
        self.assertEqual(fault.exception.code, 0x91010009)
        self.assertEqual(
            sends, [("authored-ecu", "SendInt", (170, None, 0, 0x11223344, 7, 1, 1))]
        )

    def test_operation_p4_and_ics02_actual_factory_both_builds(self):
        for family, category_id in (("plain", 170), ("ics", 469)):
            self.frames = [
                (category_id, function, 0, 1, request, b"", b"")
                for function, request in (
                    (0xE4, bytes.fromhex("1200aa00")),
                    (0x13, b"\x01\x00"),
                    (0xE3, bytes.fromhex("18000000")),
                    (0x67, b"\x10\x01"),
                    (0x7F, b"\x3e"),
                )
            ]
            self.build()
            category = bytearray(self.profile.category_record)
            struct.pack_into("<H", category, 68, category_id)
            category[72] = 1
            plans = (
                ((129, 37, 38, category_id),)
                if family == "plain"
                else (
                    (129, 52, 55, 4001),
                    (128, 53, 56, 4000),
                    (132, 54, 57, 4002),
                    (133, 58, 59, 4003),
                    (134, 75, 76, 4004),
                )
            )
            groups: list[bytes] = []
            checks: list[bytes] = []
            freezes: list[bytes] = []
            operations: list[bytes] = []
            for index, (control, probe, measured, _label) in enumerate(plans, 1):
                for key, signal in ((index, probe), (index + len(plans), measured)):
                    group = bytearray(12)
                    struct.pack_into("<H", group, 4, key)
                    group[8] = signal
                    groups.append(bytes(group))
                    checks.append(struct.pack("<4H", key, index, 0, 0))
                freeze, operation = bytearray(84), bytearray(8)
                struct.pack_into("<H", freeze, 56, index)
                struct.pack_into("<H", freeze, 60, 7)
                struct.pack_into("<HH", freeze, 62, 0, 7)
                struct.pack_into("<H", freeze, 70, 6)
                freeze[76], freeze[78], freeze[79] = 2, 2, 2
                freezes.append(bytes(freeze))
                struct.pack_into("<H", operation, 2, index)
                operation[5], operation[7] = 3, control
                operations.append(bytes(operation))
            physical, unit = bytearray(24), bytearray(12)
            struct.pack_into("<IIIHH", physical, 0, 3, 1, 0, 7, 1)
            struct.pack_into("<HH", unit, 4, 1, 4)
            for build in (12, 18):
                for mode in ("normal", "probe_timeout", "cancel"):
                    with self.subTest(family=family, build=build, mode=mode):
                        profile = copy.deepcopy(self.profile)
                        management = profile.catalog.management
                        categories = [bytes(category)]
                        if family == "ics":
                            for identifier in range(4000, 4005):
                                row = bytearray(76)
                                struct.pack_into("<H", row, 68, identifier)
                                categories.append(bytes(row))
                        protocol, can = (
                            bytearray(28 if build == 18 else 24),
                            bytearray(28),
                        )
                        struct.pack_into(
                            "<6H", protocol, 0, category_id, 1, 0x33, 0x7DF, 0x7E0, 0xAB
                        )
                        protocol[24 if build == 18 else 22] = 0x12
                        struct.pack_into("<IIHHH", can, 0, 0x1234, 500000, 1, 0, 20)
                        struct.pack_into("<H", can, 18 if build == 18 else 16, 9)
                        settings = bytearray(management.sections[29].payload)
                        for at in range(0, len(settings), 16):
                            struct.pack_into("<I", settings, at + 4, 100)
                        sections = {
                            **management.sections,
                            13: Section(13, 0, 1, False, bytes(protocol)),
                            14: Section(14, 0, 1, False, bytes(can)),
                            16: Section(
                                16, 0, len(categories), False, b"".join(categories)
                            ),
                            29: replace(
                                management.sections[29], payload=bytes(settings)
                            ),
                        }
                        payload = bytearray(
                            database(
                                1,
                                {
                                    slot: (row.count, row.payload)
                                    for slot, row in sections.items()
                                },
                            )
                        )
                        struct.pack_into(
                            "<I", payload, 28, 0x0100030C if build == 12 else 0x0100032F
                        )
                        profile.catalog.management = parse_database(bytes(payload))
                        pattern = bytearray(20 if build == 12 else 24)
                        if build == 12:
                            struct.pack_into("<H", pattern, 4, 6)
                            struct.pack_into("<H", pattern, 10, 1)
                        else:
                            struct.pack_into("<I", pattern, 4, 1)
                            struct.pack_into("<H", pattern, 12, 6)
                        payload = bytearray(
                            database(
                                2,
                                {
                                    0: (
                                        len(groups),
                                        b"".join(
                                            sorted(
                                                groups,
                                                key=lambda row: struct.unpack_from(
                                                    "B", row, 8
                                                )[0],
                                            )
                                        ),
                                    ),
                                    1: (
                                        len(checks),
                                        b"".join(
                                            sorted(
                                                checks,
                                                key=lambda row: struct.unpack_from(
                                                    "<H", row
                                                )[0],
                                            )
                                        ),
                                    ),
                                    3: (1, bytes.fromhex("0000000000010000")),
                                    6: (1, bytes.fromhex("0000020100000000")),
                                    10: (len(freezes), b"".join(freezes)),
                                    13: (1, bytes(physical)),
                                    14: (1, bytes(pattern)),
                                    15: (1, bytes(unit)),
                                    54: (len(operations), b"".join(operations)),
                                },
                            )
                        )
                        struct.pack_into(
                            "<I", payload, 28, 0x0100030C if build == 12 else 0x0100032F
                        )
                        profile = replace(
                            profile,
                            category_record=bytes(category),
                            database=parse_database(bytes(payload)),
                        )
                        stopped = [False]

                        class Backend:
                            def __init__(self, mode=mode, stopped=stopped):
                                self.mode = mode
                                self.stopped = stopped
                                self.request = b""
                                self.writes = []
                                self.reads = 0

                            def invoke(self, operation, fields, *, deadline, cancelled):
                                if operation == "connect":
                                    return J2534Result(handle=41)
                                if operation == "start_message_filter":
                                    return J2534Result(handle=102)
                                if operation == "write_messages":
                                    self.request = fields["messages"][0].data[4:]
                                    self.writes.append(self.request)
                                    self.reads = 0
                                    return J2534Result(count=1)
                                if operation == "read_messages":
                                    if fields["timeout"] == 0:
                                        return J2534Result(code=9)
                                    self.reads += 1
                                    if self.request == b"\x10\x01":
                                        reply = bytes.fromhex("5001")
                                    elif self.request == b"\x01\x00":
                                        if self.reads > 1:
                                            return J2534Result(code=9)
                                        reply = bytes.fromhex("4100020101")
                                    elif self.request[0] == 0x18:
                                        reply = bytes.fromhex("580040000000")
                                    else:
                                        if self.mode == "probe_timeout":
                                            return J2534Result(code=9)
                                        if self.mode == "cancel":
                                            self.stopped[0] = True
                                        reply = bytes.fromhex("5200010000")
                                    return J2534Result(
                                        count=1,
                                        messages=(
                                            NativeMessage(
                                                6,
                                                0,
                                                0,
                                                0,
                                                0,
                                                bytes.fromhex("000007e8") + reply,
                                            ),
                                        ),
                                    )
                                return J2534Result()

                        backend = Backend()
                        communication = NativeCommunication.from_backend(
                            profile,
                            backend,
                            "authored-ecu",
                            first_request=bytes.fromhex("1200aa00"),
                            driver=DriverProperties(
                                0, b"04.04", "authored-version-reply"
                            ),
                            device_kind=8,
                            bus_id=0x12,
                            source_build=build,
                            cancelled=lambda stopped=stopped: stopped[0],
                            clock=lambda: self.clock[0],
                        )
                        workflow = ToyotaWorkflows.from_communication(
                            communication,
                            observations=WorkflowObservations(
                                category_id, 0x12, {}, source_version=build
                            ),
                            cancelled=lambda stopped=stopped: stopped[0],
                        )
                        execute = (
                            workflow.operation_freeze_p4
                            if family == "plain"
                            else workflow.operation_freeze_ics02
                        )
                        if mode == "cancel":
                            with self.assertRaises(Cancelled):
                                execute()
                        elif mode == "probe_timeout" and family == "plain":
                            with self.assertRaises(ToyotaCodecError) as raised:
                                execute()
                            self.assertEqual(raised.exception.code, 0x91010009)
                        else:
                            result = execute()
                            actual = result["operations"]
                            assert isinstance(actual, list)
                            expected_count = (
                                1 if family == "plain" else 4 if build == 12 else 5
                            )
                            self.assertEqual(
                                len(actual),
                                0 if mode == "probe_timeout" else expected_count,
                            )
                            if actual:
                                self.assertTrue(
                                    all(
                                        row["signals"][0]["value"] == 3
                                        for row in actual
                                    )
                                )
                            if family == "ics":
                                self.assertEqual(
                                    result["native_fields"],
                                    {"34": int(build == 18 and mode == "normal")},
                                )
                        requested = [row for row in backend.writes if row[0] == 0x12]
                        if family == "ics":
                            controls = [129, 128, 132, 133] + (
                                [134] if build == 18 else []
                            )
                            self.assertEqual(
                                sorted({row[2] for row in requested}),
                                sorted(controls[:1] if mode == "cancel" else controls),
                            )
                        else:
                            self.assertTrue(
                                all(
                                    row == bytes.fromhex("1203aa02")
                                    for row in requested
                                )
                            )
                        self.assertNotIn(b"", backend.writes)
                        stopped[0] = False
                        communication.close()

    def test_operation_force_support_ignores_mode_shortcuts(self):
        freeze = bytearray(84)
        freeze[77], freeze[79] = 1, 2
        struct.pack_into("<HH", freeze, 62, 0, 7)
        self.assertTrue(ToyotaWorkflows._freeze_supported_p4(bytes(freeze), {}, {}))
        self.assertFalse(
            ToyotaWorkflows._freeze_supported_p4(bytes(freeze), {}, {}, force=True)
        )
        freeze[77] = 2
        self.assertTrue(
            ToyotaWorkflows._freeze_supported_p4(
                bytes(freeze), {2: 1}, {2: b"\x01"}, force=True
            )
        )

    def test_saved_did_target_selection_uses_actual_category_and_bus(self):
        management = self.profile.catalog.management
        category = bytearray(self.profile.category_record)
        category[72] = 4
        second = bytearray(category)
        struct.pack_into("<H", second, 68, 43)
        rows = []
        for target, bus, order in ((42, 7, 0), (43, 8, 1)):
            row = bytearray(24)
            struct.pack_into("<HH", row, 0, 2, target)
            struct.pack_into("<H", row, 16, order)
            row[20] = bus
            rows.append(bytes(row))
        self.profile.catalog.management = replace(
            management,
            sections={
                **management.sections,
                16: Section(16, 0, 2, False, bytes(category + second)),
                62: Section(62, 0, 2, False, b"".join(rows)),
            },
        )
        workflow = self.workflow()
        workflow._begin()
        cache = workflow._support()
        selected = select_comm_did_target(cache, 2, targets=((43, 8),))
        assert selected is not None
        self.assertEqual(selected.record, rows[1])
        self.assertEqual(selected.category_record, bytes(second))
        self.assertIsNone(select_comm_did_target(cache, 2, targets=((43, 7),)))
        first = select_comm_did_target(cache, 2)
        assert first is not None
        self.assertEqual(first.record, rows[0])
        self.assertFalse(self.calls)
        second[72] = 20
        self.profile.catalog.management = replace(
            self.profile.catalog.management,
            sha256="0" * 64,
            sections={
                **self.profile.catalog.management.sections,
                16: Section(16, 0, 2, False, bytes(category + second)),
            },
        )
        # Context source mutation is rejected before selecting another target.
        with self.assertRaises(SessionError):
            select_comm_did_target(cache, 2, targets=((43, 8),))

    def assert_saved_native_outer(self, profiles, *, routine):
        """Actual serialized DDB, one retained controller, two selected ECU caches."""
        profiles = copy.deepcopy(profiles)
        protocols = []
        for profile in profiles:
            row = bytearray(28)
            struct.pack_into(
                "<6H",
                row,
                0,
                profile.category,
                1,
                0x33,
                0x7DF,
                0x7E0 + profile.category - 0xD4,
                0xAB,
            )
            row[24] = 0x12
            protocols.append(bytes(row))
        can = bytearray(28)
        struct.pack_into("<IIHHH", can, 0, 0x1234, 500000, 1, 0, 20)
        struct.pack_into("<H", can, 18, 9)
        management = profiles[0].catalog.management
        frames = management.sections[17]
        settings = bytearray(management.sections[29].payload)
        for at in range(0, len(settings), 16):
            struct.pack_into("<I", settings, at + 4, 100)
        profiles[0].catalog.management = replace(
            management,
            sections={
                **management.sections,
                29: replace(management.sections[29], payload=bytes(settings)),
                13: Section(13, 0, len(protocols), False, b"".join(protocols)),
                14: Section(14, 0, 1, False, bytes(can)),
                17: replace(
                    frames,
                    count=frames.count + 1,
                    payload=frames.payload + struct.pack("<4H", 0, 0, 0, 0),
                ),
            },
        )
        overlaid = profiles[0].catalog.management
        profiles[0].catalog.management = parse_database(
            database(
                1,
                {
                    slot: (section.count, section.payload)
                    for slot, section in overlaid.sections.items()
                },
            )
        )
        self.assertNotEqual(profiles[0].catalog.management.sha256, management.sha256)

        class Backend:
            def __init__(self):
                self.calls = []
                self.writes = []
                self.request = b""
                self.address = b""
                self.reads = 0

            def invoke(self, operation, fields, *, deadline, cancelled):
                self.calls.append(operation)
                if operation == "connect":
                    return J2534Result(handle=41)
                if operation == "start_message_filter":
                    return J2534Result(handle=102)
                if operation == "write_messages":
                    data = fields["messages"][0].data
                    self.address, self.request = data[:4], data[4:]
                    self.reads = 0
                    self.writes.append((self.address, self.request))
                    return J2534Result(count=1)
                if operation == "read_messages":
                    if fields["timeout"] == 0:
                        return J2534Result(code=9)
                    request = self.request
                    self.reads += 1
                    if request[0] in (1, 2) and self.reads > 1:
                        return J2534Result(code=9)
                    if request[0] in (0x10, 0x3E):
                        reply = bytes([request[0] | 0x40]) + request[1:]
                    elif routine:
                        payload = {
                            bytes.fromhex("31011001"): bytes.fromhex("000040"),
                            bytes.fromhex("31011100"): b"\x10",
                        }.get(request, bytes.fromhex("0101"))
                        reply = b"\x71" + request[1:4] + payload
                    else:
                        reply = {
                            b"\x01\x00": bytes.fromhex("4100020101"),
                            b"\x02\x00": bytes.fromhex("420003020101"),
                        }.get(
                            request,
                            bytes.fromhex("700301")
                            if request[0] == 0x30
                            else bytes.fromhex("610201"),
                        )
                    return J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(
                                6,
                                0,
                                0,
                                0,
                                0,
                                (int.from_bytes(self.address, "big") + 8).to_bytes(
                                    4, "big"
                                )
                                + reply,
                            ),
                        ),
                    )
                return J2534Result()

        backend = Backend()
        owner = NativeCommunication.from_backend(
            profiles[0],
            backend,
            "authored-ecu",
            first_request=b"\x21\x00",
            driver=DriverProperties(0, b"04.04", "authored-version-reply"),
            device_kind=8,
            bus_id=0x12,
            source_build=18,
            clock=lambda: self.clock[0],
        )
        child = owner.share_context(
            profiles[1], "authored-ecu", bus_id=0x12, first_request=b"\x21\x00"
        )
        assert isinstance(owner.operations, NativeFrameController)
        logger = DdrPacketLog(
            self.root / ("saved-routine" if routine else "saved-pid"), owner.operations
        )
        owner.bind_comm_log(logger)
        contexts = {
            (profile.category, 0x12): ToyotaWorkflows.from_communication(
                communication,
                observations=WorkflowObservations(
                    profile.category, 0x12, {}, source_version=18
                ),
            )
            for profile, communication in zip(profiles, (owner, child), strict=True)
        }
        workflow = contexts[(0xD4, 0x12)]
        method = (
            workflow.execute_absolute_routine_logs
            if routine
            else workflow.execute_absolute_pid_logs
        )
        result = method([SavedLogInput(1)], contexts=contexts)
        logs, lifecycle = result["logs"], result["lifecycle"]
        assert isinstance(logs, list) and isinstance(lifecycle, dict)
        self.assertEqual(logs[0]["components"], dict.fromkeys(range(1, 13), 1))
        self.assertEqual(lifecycle["disconnect_status"], 0)
        self.assertEqual(backend.calls.count("connect"), 1)
        self.assertEqual(backend.calls.count("disconnect"), 1)
        self.assertEqual(
            {address for address, _request in backend.writes},
            {bytes.fromhex("000007e0"), bytes.fromhex("000007e1")},
        )
        self.assertFalse(logger.active)
        self.assertFalse(owner._cleanup_pending)

    def test_saved_pid_global_plan_and_reads_keep_same_requests_per_ecu(self):
        self.frames = [
            (0xD4, 0x9D, 0, 1, b"\x30", b"", b""),
            (0xD4, 0x6B, 0, 1, b"\x21\x00", b"", b""),
            (0xD5, 0x6B, 0, 1, b"\x21\x00", b"", b""),
            (0xD4, 0x13, 0, 1, b"\x01\x00", b"", b""),
            (0xD4, 0x14, 0, 1, b"\x02\x00", b"", b""),
            (0xD5, 0x13, 0, 1, b"\x01\x00", b"", b""),
        ]
        self.frames += [
            (category, function, 0, 1, request, b"", b"")
            for category in (0xD4, 0xD5)
            for function, request in ((0x67, b"\x10\x01"), (0x7F, b"\x3e"))
        ]
        self.build()
        categories = []
        for category_id in (0xD4, 0xD5):
            row = bytearray(self.profile.category_record)
            struct.pack_into("<H", row, 68, category_id)
            row[72] = 4
            categories.append(bytes(row))
        did = bytearray(24)
        struct.pack_into("<HH", did, 0, 2, 0xD4)
        did[14], did[20], did[21] = 4, 0x12, 3
        pids = []
        for index, logical_id in enumerate(range(0x8F, 0x9B)):
            row = bytearray(44)
            struct.pack_into("<III", row, 0, 1, 1, 0)
            struct.pack_into("<4H", row, 16, logical_id, 0xD4 + (index % 2), 0, 7)
            row[38], row[39] = 0x12, 2
            pids.append(bytes(row))
        management = self.profile.catalog.management
        self.profile.catalog.management = replace(
            management,
            sections={
                **management.sections,
                16: Section(16, 0, 2, False, b"".join(categories)),
                62: Section(62, 0, 1, False, bytes(did)),
                54: Section(54, 0, 12, False, b"".join(pids)),
            },
        )
        profiles = [replace(self.profile, category_record=row) for row in categories]
        events = []
        masked = [False]

        class Lower:
            def __init__(self, category):
                self.category = category
                self.request = b""
                self.reads = 0

            def send(self, request, **_arguments):
                events.append((self.category, "send", request))
                self.request = request
                self.reads = 0
                return 0x91010009 if masked[0] and request[0] == 0x30 else 0

            def receive(self, **_arguments):
                self.reads += 1
                events.append((self.category, "receive", self.request))
                if self.request in (b"\x01\x00", b"\x02\x00"):
                    if self.reads > 1:
                        return NativeReply(0x91010009, b"")
                    return NativeReply(
                        0,
                        bytes.fromhex("4100020101")
                        if self.request[0] == 1
                        else bytes.fromhex("420003020101"),
                    )
                return NativeReply(
                    0,
                    bytes.fromhex("700301")
                    if self.request[0] == 0x30
                    else bytes.fromhex("610201"),
                )

            def close(self):
                pass

        contexts = {}
        for profile in profiles:
            communication = NativeCommunication(
                profile,
                Lower(profile.category),
                "same-authored-ecu-label",
                bus_id=0x12,
                clock=lambda: self.clock[0],
            )
            contexts[(profile.category, 0x12)] = ToyotaWorkflows.from_communication(
                communication,
                observations=WorkflowObservations(profile.category, 0x12, {}),
            )
        workflow = contexts[(0xD4, 0x12)]
        with self.assertRaises(SessionError):
            workflow.selected_absolute_pid_plan({(0xD4, 0x12): workflow})
        self.assertFalse(events)
        original_metadata: dict[str, object] = {"origin": "first"}
        first = SavedLogInput(1, original_metadata)
        original_metadata["origin"] = "changed-after-copy"
        result = workflow.absolute_pid_logs(
            [first, SavedLogInput(1, {"origin": "second"})], contexts=contexts
        )
        logs = result["logs"]
        assert isinstance(logs, list)
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["components"], dict.fromkeys(range(1, 13), 1))
        self.assertEqual(logs[0]["metadata"], {"origin": "first"})
        sends = [
            (category, request)
            for category, kind, request in events
            if kind == "send" and request == b"\x21\x02"
        ]
        self.assertEqual(sends, [(0xD4, b"\x21\x02"), (0xD5, b"\x21\x02")])
        self.assertIn((0xD4, "send", bytes.fromhex("3003040001")), events)
        self.assert_saved_native_outer(profiles, routine=False)
        events.clear()
        masked[0] = True
        result = workflow.absolute_pid_logs([SavedLogInput(1)], contexts=contexts)
        self.assertEqual(result["logs"], [])
        self.assertEqual(
            sum(
                kind == "send" and request == b"\x21\x02"
                for _category, kind, request in events
            ),
            2,
        )
        recursive = {}
        recursive["self"] = recursive
        with self.assertRaises(ValueError):
            SavedLogInput(1, recursive)

    def test_operation_p5_literal_phases_and_word_decode(self):
        self.frames = [(42, 0x66, 0, 1, b"\x22\x00", b"", b"")]
        self.build()
        events = []
        failures: list[bool | str] = [False]
        cancelled = [False]

        class Lower:
            def send(self, request, **arguments):
                events.append((request, arguments["initialization_mode"]))
                self.request = request
                if failures[0] == "cancel":
                    cancelled[0] = True
                if failures[0] and request.startswith(b"\xab\x13"):
                    return 0xC0040001 if failures[0] == "fatal" else 0x91010009
                return 0

            def receive(self, **_arguments):
                if self.request == bytes.fromhex("ab11"):
                    reply = bytes.fromhex("eb110102")
                elif self.request == bytes.fromhex("ab120102"):
                    # Native unsigned sort/dedup; zero/high-byte entries still read.
                    reply = bytes.fromhex("eb12010200020101000100010000")
                elif self.request.startswith(bytes.fromhex("ab13")):
                    reply = bytes.fromhex("eb1301020001030501021234050102567805020101")
                else:
                    reply = bytes([self.request[0] | 0x40]) + self.request[1:]
                return NativeReply(0, reply)

            def close(self):
                pass

        communication = NativeCommunication(
            self.profile,
            Lower(),
            "authored-ecu",
            bus_id=7,
            clock=lambda: self.clock[0],
        )
        workflow = ToyotaWorkflows.from_communication(
            communication,
            observations=WorkflowObservations(42, 7, {}),
        )
        result = workflow.operation_freeze_p5_core()
        self.assertEqual(
            events[:5],
            [
                (bytes.fromhex("221007"), 2),
                (bytes.fromhex("221f01"), 2),
                (bytes.fromhex("221f02"), 2),
                (bytes.fromhex("221f03"), 2),
                (bytes.fromhex("ab11"), 1),
            ],
        )
        self.assertEqual(
            [request.hex() for request, _mode in events[6:]],
            [
                "ab1301020000",
                "ab1301020001",
                "ab1301020002",
                "ab1301020101",
            ],
        )
        self.assertEqual(result["status"], "partial")
        self.assertEqual(
            result["trip_times"],
            [
                {
                    "operation": 0x102,
                    "snapshot": number,
                    "raw_trip_time_words": [0x1234],
                    "unit": None,
                    "metadata": "native_constructor_defaults",
                }
                for number in (1, 2)
            ],
        )
        events.clear()
        failures[0] = True
        communication.no_init = communication.no_session = True
        result = workflow.operation_freeze_p5_core()
        self.assertEqual(result["trip_times"], [])
        self.assertEqual(
            [request.hex() for request, _mode in events[6:]],
            [
                "ab1301020000",
                "ab1301020001",
            ],
        )
        self.assertTrue(communication.no_init)
        self.assertTrue(communication.no_session)
        failures[0] = "fatal"
        with self.assertRaises(ToyotaCodecError) as caught:
            workflow.operation_freeze_p5_core()
        self.assertEqual(caught.exception.code, 0xC0040001)
        self.assertTrue(communication.no_init)
        self.assertTrue(communication.no_session)
        failures[0] = "cancel"
        workflow.cancelled = lambda: cancelled[0]
        with self.assertRaises(SessionError):
            workflow.operation_freeze_p5_core()
        self.assertTrue(communication.no_init)
        self.assertTrue(communication.no_session)
        zero_count = bytes.fromhex("eb1301020001000501021234")
        self.assertEqual(
            parse_operation_p5_reply(zero_count)["trip_time_words"], [0x1234]
        )
        self.assertEqual(
            parse_operation_p5_reply(zero_count, source_version=12)["trip_time_words"],
            [],
        )
        with self.assertRaises(ValueError):
            parse_operation_p5_reply(zero_count, source_version=13)
        parsed = parse_operation_p5_reply(bytes.fromhex("eb13010200010105010212"))
        self.assertEqual(parsed["status"], "partial")
        self.assertEqual(parsed["trip_time_words"], [])
        self.assertEqual(
            parse_operation_p5_reply(bytes.fromhex("eb1301020001000501021234"))[
                "trip_time_words"
            ],
            [0x1234],
        )

    def each_profile(self):
        physical = struct.pack("<IIIHH8x", 2, 1, 3, 1, 1)
        unit = struct.pack("<I4H", 0, 1, 9, 0, 0)
        monitor = bytearray(64)
        struct.pack_into("<I", monitor, 8, 255)
        struct.pack_into("<I", monitor, 32, 2)
        struct.pack_into("<H", monitor, 36, 1)
        struct.pack_into("<3H", monitor, 42, 1, 0, 7)
        struct.pack_into("<H", monitor, 56, 0x1234)
        monitor[58] = 2
        did = bytearray(8)
        struct.pack_into("<H", did, 2, 0x1234)
        did[4] = 1
        signals = (0x1C, 0x1D, 0x27, 0x28, *range(0x3C, 0x42))
        groups = []
        for signal in signals:
            row = bytearray(12)
            struct.pack_into("<H", row, 4, signal)
            row[8] = signal
            groups.append(bytes(row))
        checks = b"".join(struct.pack("<4H", signal, 2, 0, 0) for signal in signals)
        self.profile = replace(
            self.profile,
            database=parse_database(
                database(
                    2,
                    {
                        0: (len(signals), b"".join(groups)),
                        1: (len(signals), checks),
                        13: (1, physical),
                        14: (0, b""),
                        15: (1, unit),
                        61: (1, did),
                        62: (1, monitor),
                        65: (0, b""),
                    },
                )
            ),
        )

    def test_each_reply_resolves_actual_p5_definitions_and_keeps_partial_values(self):
        self.each_profile()
        workflow = self.workflow()
        workflow._begin()
        state = P5FreezeState(self.profile, source_build=18, cache=workflow._support())
        # One complete DID followed by a truncated DID in the same record.
        parsed = analyze_each_p5_reply(
            state,
            bytes.fromhex("590412345600010212340104456702ff"),
            requested_number=1,
        )
        self.assertEqual(parsed["status"], "partial")
        self.assertEqual(parsed["reason"], "data_id_value_truncated")
        diagnostic = state.diagnostic(0x123456)
        assert diagnostic is not None
        self.assertEqual(diagnostic.normal_numbers, [1])
        self.assertEqual(diagnostic.signals[0].values[0].value, 4)
        self.assertEqual(diagnostic.signals[0].values[0].index, -126)
        self.assertEqual(
            diagnostic.signals[0].metadata.render(diagnostic.signals[0].values[0])[
                "value"
            ],
            11,
        )
        self.assertFalse(self.calls)
        # Native existence mutation survives a later selected metadata failure.
        state = P5FreezeState(self.profile, source_build=18, cache=workflow._support())
        self.profile.database.sections.pop(15)
        with self.assertRaises(ToyotaCodecError) as caught:
            analyze_each_p5_reply(
                state,
                bytes.fromhex("590412345600010112340104"),
                requested_number=1,
            )
        self.assertEqual(caught.exception.code, 0xA0030107)
        diagnostic = state.diagnostic(0x123456)
        assert diagnostic is not None
        self.assertEqual(diagnostic.normal_numbers, [1])

    def test_each_p5_core_aggregate_fallback_pruning_and_existing_diagnostics(self):
        self.frames = [(42, 0xCF, 0, 1, bytes.fromhex("1904000000ff"), b"", b"")]
        self.build()
        self.each_profile()
        events = []
        failures = {}
        replies = {}
        cancelled = [False]

        class Lower:
            def send(self, request, **arguments):
                events.append((request, arguments["initialization_mode"]))
                self.request = request
                return failures.get(request, 0)

            def receive(self, **_arguments):
                return NativeReply(
                    0,
                    replies.get(
                        self.request,
                        bytes.fromhex("5904")
                        + self.request[2:5]
                        + bytes.fromhex("00010112340104"),
                    ),
                )

            def close(self):
                pass

        communication = NativeCommunication(
            self.profile, Lower(), "authored-ecu", bus_id=7, clock=lambda: self.clock[0]
        )
        workflow = ToyotaWorkflows.from_communication(
            communication,
            observations=WorkflowObservations(42, 7, {}),
            cancelled=lambda cancelled=cancelled: cancelled[0],
        )
        state = P5FreezeState(self.profile, source_build=18, cache=communication.cache)
        first = P5SnapshotRequest(0x123456, [1, 2])
        second = P5SnapshotRequest(0x234567, [1])
        communication.no_init = True
        failures[bytes.fromhex("1904123456ff")] = 0x91010009
        failures[bytes.fromhex("190412345602")] = 0xA0040202
        result = workflow.each_freeze_p5_core(state, (first, second))
        self.assertEqual(
            [request.hex() for request, mode in events],
            ["1904123456ff", "190412345601", "190412345602", "190423456701"],
        )
        self.assertTrue(all(mode == 1 for _, mode in events))
        self.assertTrue(communication.no_init)
        self.assertEqual(first.numbers, [1])
        self.assertEqual(second.numbers, [1])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(len(state.snapshot_frames), 2)
        diagnostic = state.diagnostic(0x123456)
        assert diagnostic is not None
        self.assertEqual(diagnostic.signals[0].values[0].value, 4)
        # The GetDiag4E30 consumer cannot invent a diagnostic or existence bit.
        events.clear()
        failures.clear()
        state = P5FreezeState(self.profile, source_build=18, cache=communication.cache)
        state.add_diagnostic(0x123456)
        first = P5SnapshotRequest(0x123456, [1, 2])
        second = P5SnapshotRequest(0x234567, [1])
        result = workflow.each_freeze_p5_core(
            state, (first, second), create_diagnostics=False
        )
        self.assertEqual(first.numbers, [255])
        self.assertEqual(second.numbers, [255])
        self.assertEqual(len(state.diagnostics), 1)
        diagnostic = state.diagnostic(0x123456)
        assert diagnostic is not None
        self.assertEqual(diagnostic.normal_numbers, [])
        diagnostic = state.diagnostic(0x123456)
        assert diagnostic is not None
        self.assertEqual(diagnostic.signals[0].values[0].value, 4)
        # A later aggregate masked fault removes only that native request.
        failures[bytes.fromhex("1904234567ff")] = 0x91010009
        result = workflow.each_freeze_p5_core(state, (first, second))
        self.assertEqual(result["requests"], [{"code": 0x123456, "numbers": [255]}])
        self.assertEqual(result["status"], "partial")
        # Fatal status never promotes captured bytes to analyzed values.
        failures[bytes.fromhex("1904123456ff")] = 0xDEADBEEF
        with self.assertRaises(ToyotaCodecError) as caught:
            workflow.each_freeze_p5_core(state, (first,))
        self.assertEqual(caught.exception.code, 0xDEADBEEF)
        self.assertTrue(communication.no_init)
        failures.clear()
        cancelled[0] = True
        with self.assertRaises(Cancelled):
            workflow.each_freeze_p5_core(state, (first,))
        self.assertTrue(communication.no_init)

        # Original12 uses its own Common state with the same recovered CF
        # algorithm; the selected DDB format does not select the source build.
        cancelled[0] = False
        communication12 = NativeCommunication(
            self.profile,
            Lower(),
            "authored-ecu",
            source_build=12,
            bus_id=7,
            clock=lambda: self.clock[0],
        )
        workflow12 = ToyotaWorkflows.from_communication(
            communication12,
            observations=WorkflowObservations(42, 7, {}, source_version=12),
        )
        state12 = P5FreezeState(
            self.profile, source_build=12, cache=communication12.cache
        )
        result = workflow12.each_freeze_p5_core(
            state12, (P5SnapshotRequest(0x123456, [1]),)
        )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(state12.diagnostics[0].normal_numbers, [1])

        # Source18's bus14 CE producer permits3FFF groups; the shared Each
        # consumer cannot impose the ordinary3FF group ceiling on that caller.
        communication14 = NativeCommunication(
            self.profile,
            Lower(),
            "authored-ecu",
            source_build=18,
            bus_id=0x14,
            clock=lambda: self.clock[0],
        )
        workflow14 = ToyotaWorkflows.from_communication(
            communication14, observations=WorkflowObservations(42, 0x14, {})
        )
        state14 = P5FreezeState(
            self.profile, source_build=18, cache=communication14.cache
        )
        requests = tuple(P5SnapshotRequest(index, []) for index in range(0x400))
        self.assertEqual(
            workflow14.each_freeze_p5_core(state14, requests)["native_status"], 0
        )
        with self.assertRaises(TypeError):
            workflow12.each_freeze_p5_core(state12, requests)
        with self.assertRaisesRegex(ValueError, "no conditional log flag"):
            workflow12.each_freeze_p5(P5Diagnostic(0x123456, {}), log_enabled=True)
        too_many = tuple(P5SnapshotRequest(index, []) for index in range(0x4000))
        with self.assertRaises(TypeError):
            workflow14.each_freeze_p5_core(state14, too_many)

    def test_predictive_p5_core_scans_matching_dtc_only_and_merges(self):
        self.frames = [
            (42, 0xD0, 0, 1, bytes.fromhex("191000"), b"", b""),
            (42, 0xCF, 0, 1, bytes.fromhex("1904000000ff"), b"", b""),
        ]
        self.build()
        self.each_profile()
        events = []
        fail: list[str | None] = [None]

        class Lower:
            def send(self, request, **arguments):
                self.number = request[2]
                self.request = request
                events.append(self.number)
                if fail[0] == "fatal":
                    return 0xDEADBEEF
                if self.number == 2:
                    return 0x91010009
                return 0

            def receive(self, **_arguments):
                if self.request[:2] == bytes.fromhex("1904"):
                    return NativeReply(0, bytes.fromhex("590412345600010112340104"))
                # Prefix2 + number/DTC/status/count + self-describing DID.
                # Only base1 matches; its sixteen later snapshots are probed.
                code = "123456" if self.number in (1, 0x10) else "654321"
                number = "01" if self.number == 1 else "10"
                return NativeReply(
                    0, bytes.fromhex("5910" + number + code + "000112340104")
                )

            def close(self):
                pass

        communication = NativeCommunication(
            self.profile, Lower(), "authored-ecu", bus_id=7, clock=lambda: self.clock[0]
        )
        workflow = ToyotaWorkflows.from_communication(
            communication, observations=WorkflowObservations(42, 7, {})
        )
        state = P5FreezeState(self.profile, source_build=18, cache=communication.cache)
        result = workflow.predictive_freeze_p5_core(state, 0x123456)
        self.assertEqual(events, [*range(1, 15), *range(16, 32)])
        self.assertEqual(result["accepted_numbers"], [1, 16])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(len(state.snapshot_frames), 2)
        diagnostic = state.diagnostic(0x123456)
        assert diagnostic is not None
        self.assertEqual(diagnostic.diag_type, 8)
        self.assertEqual(diagnostic.extended_numbers, [1])
        self.assertEqual([value.value for value in diagnostic.signals[0].values], [4])
        self.assertIsNone(state.diagnostic(0x654321))
        # Existing PID metadata survives the separate native temporary merge.
        original_metadata = diagnostic.signals[0].metadata
        workflow.predictive_freeze_p5_core(state, 0x123456)
        self.assertIs(diagnostic.signals[0].metadata, original_metadata)
        self.assertEqual(len(diagnostic.signals[0].values), 2)
        events.clear()
        result = workflow.each_freeze_p5(
            P5Diagnostic(0x123456, {"code": 0x123456}, normal_numbers=[1, 0x10, 0x50])
        )
        self.assertTrue(result["matched"])
        phases, output = result["phases"], result["diagnostic"]
        assert isinstance(phases, list) and isinstance(output, dict)
        self.assertEqual(len(phases), 2)
        self.assertEqual(output["normal_numbers"], [1])
        self.assertEqual(output["extended_numbers"], [1])
        self.assertEqual(events[0], 0x12)
        self.assertEqual(events[1:], [*range(1, 15), *range(16, 32)])
        prior = len(events)
        with self.assertRaises(ValueError):
            workflow.each_freeze_p5(P5Diagnostic(0x123456, {"invalid": float("nan")}))
        self.assertEqual(len(events), prior)
        fail[0] = "fatal"
        with self.assertRaises(ToyotaCodecError) as caught:
            workflow.predictive_freeze_p5_core(state, 0x123456)
        self.assertEqual(caught.exception.code, 0xDEADBEEF)
        self.assertFalse(communication.no_init)

    def test_p5_merge_copies_native_7c_set_reset_and_new_diagnostics(self):
        self.each_profile()
        for build in (12, 18):
            with self.subTest(build=build):
                cache = MonitorSupportCache(
                    self.profile, lambda call: b"", "authored-ecu", source_build=build
                )
                state = P5FreezeState(self.profile, source_build=build, cache=cache)
                temporary = P5FreezeState(self.profile, source_build=build, cache=cache)
                incoming = temporary.add_diagnostic(0x123456, diag_type=8)
                assert incoming is not None
                incoming.stored_all = True
                incoming.extended_numbers[:] = [1]
                merge_p5_diagnostics(state, temporary)
                existing = state.diagnostic(0x123456)
                assert existing is not None
                self.assertTrue(existing.stored_all)
                self.assertIsNot(existing, incoming)
                incoming.stored_all = False
                incoming.extended_numbers[:] = [2]
                merge_p5_diagnostics(state, temporary)
                self.assertFalse(existing.stored_all)
                self.assertEqual(existing.extended_numbers, [2])
                incoming.stored_all = True
                merge_p5_diagnostics(state, temporary)
                self.assertTrue(existing.stored_all)
                # Each D0 producer must populate the same typed native field.
                reply = bytes.fromhex("591001123456000112340104")
                analyze_predictive_p5_replies(state, ((reply, 255),))
                self.assertTrue(existing.stored_all)
                analyze_predictive_p5_replies(state, ((reply, 1),))
                self.assertFalse(existing.stored_all)
                foreign = P5FreezeState(
                    self.profile,
                    source_build=build,
                    cache=MonitorSupportCache(
                        self.profile, lambda call: b"", "other-ecu", source_build=build
                    ),
                )
                with self.assertRaises(SessionError):
                    merge_p5_diagnostics(state, foreign)
                self.assertFalse(existing.stored_all)
                incoming.stored_all = True
                cache.cancelled = lambda: True
                with self.assertRaises(Cancelled):
                    merge_p5_diagnostics(state, temporary)
                self.assertFalse(existing.stored_all)

    def test_predictive_native_merge_keeps_safe_prefix_before_bad_native_index(self):
        self.each_profile()
        workflow = self.workflow()
        workflow._begin()
        state = P5FreezeState(self.profile, source_build=18, cache=workflow._support())
        temporary = P5FreezeState(self.profile, source_build=18, cache=state.cache)
        analyze_each_p5_reply(
            state, bytes.fromhex("590412345600010112340104"), requested_number=1
        )
        diagnostic = state.diagnostic(0x123456)
        assert diagnostic is not None
        first = diagnostic.signals[0].metadata
        second = replace(first, pid=2)
        diagnostic.signals[:] = [
            P5FreezeSignal(second, [P5Value(80, 0, 1)]),
            P5FreezeSignal(first, [P5Value(90, 0, 1)]),
        ]
        incoming = temporary.add_diagnostic(0x123456, diag_type=8)
        assert incoming is not None
        incoming.stored_all = True
        incoming.signals[:] = [
            P5FreezeSignal(first, [P5Value(11, 0, 1)]),
            P5FreezeSignal(second, [P5Value(21, 0, 1), P5Value(22, 1, 1)]),
        ]
        with self.assertRaisesRegex(SessionError, "source value index"):
            merge_p5_diagnostics(state, temporary)
        self.assertEqual(
            [value.value for value in diagnostic.signals[1].values], [90, 11]
        )
        self.assertEqual([value.value for value in diagnostic.signals[0].values], [80])
        self.assertEqual(diagnostic.diag_type, 8)
        self.assertTrue(diagnostic.stored_all)

    def test_saved_routine_global_contexts_no_init_and_per_log_cache(self):
        self.frames = [
            (category, function, 0, 1, request, b"", b"")
            for category in (0xD4, 0xD5)
            for function, request in (
                (0xCC, bytes.fromhex("31010000")),
                (0xD7, bytes.fromhex("31030000")),
            )
        ]
        self.frames += [
            (category, 0x67, 0, 1, b"\x10\x01", b"", b"") for category in (0xD4, 0xD5)
        ]
        self.build()
        categories = []
        for category_id in (0xD4, 0xD5):
            row = bytearray(self.profile.category_record)
            struct.pack_into("<H", row, 68, category_id)
            row[72] = 0x14
            categories.append(bytes(row))
        rows = []
        for logical_id in range(1, 13):
            row = bytearray(36)
            struct.pack_into("<III", row, 0, 1, 1, 0)
            struct.pack_into("<4H", row, 16, logical_id, 0xD4 + logical_id % 2, 0, 7)
            if logical_id == 3:
                struct.pack_into("<HH", row, 20, 8, 15)
            struct.pack_into("<H", row, 30, 0x1104)
            row[32] = 0x12
            rows.append(bytes(row))
        management = self.profile.catalog.management
        self.profile.catalog.management = replace(
            management,
            sections={
                **management.sections,
                16: Section(16, 0, 2, False, b"".join(categories)),
                88: Section(88, 0, 12, False, b"".join(rows)),
            },
        )
        events = []
        bad_bcd = [False]

        class Lower:
            def __init__(self, category):
                self.category = category
                self.request = b""

            def send(self, request, **arguments):
                events.append(
                    (self.category, request, arguments["initialization_mode"])
                )
                self.request = request
                return 0

            def receive(self, **_arguments):
                if self.request == bytes.fromhex("31011001"):
                    payload = bytes.fromhex("000040")
                elif self.request == bytes.fromhex("31011100"):
                    payload = bytes.fromhex("10")
                else:
                    payload = bytes.fromhex("01fa" if bad_bcd[0] else "0101")
                return NativeReply(0, bytes([0x71]) + self.request[1:4] + payload)

            def close(self):
                pass

        contexts = {}
        for row in categories:
            profile = replace(self.profile, category_record=row)
            communication = NativeCommunication(
                profile,
                Lower(profile.category),
                "same-label",
                bus_id=0x12,
                clock=lambda: self.clock[0],
            )
            contexts[(profile.category, 0x12)] = ToyotaWorkflows.from_communication(
                communication,
                observations=WorkflowObservations(profile.category, 0x12, {}),
            )
        workflow = contexts[(0xD4, 0x12)]
        result = workflow.absolute_routine_logs(
            [SavedLogInput(1), SavedLogInput(1)], contexts=contexts
        )
        logs = result["logs"]
        assert isinstance(logs, list)
        self.assertEqual(logs[0]["components"], dict.fromkeys(range(1, 13), 1))
        self.assertEqual(len(events), 8)  # two probes, command, status per ECU
        self.assertTrue(all(mode == 2 for _category, _request, mode in events))
        for context in contexts.values():
            assert context._communication is not None
            self.assertFalse(context._communication.no_init)
        self.assertEqual(
            sorted(
                request.hex() for category, request, _mode in events if category == 0xD5
            ),
            ["31011001", "31011100", "310111040001", "31031104"],
        )
        self.assert_saved_native_outer(
            [replace(self.profile, category_record=row) for row in categories],
            routine=True,
        )
        events.clear()
        bad_bcd[0] = True
        result = workflow.absolute_routine_logs([SavedLogInput(1)], contexts=contexts)
        self.assertEqual(result["logs"], [])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(
            result["omissions"],
            [{"log_number": 1, "logical_id": 3, "native_code": 0xA0040208}],
        )
        for context in contexts.values():
            assert context._communication is not None
            self.assertFalse(context._communication.no_init)
        bad_bcd[0] = False
        management = self.profile.catalog.management
        payload = management.sections[18].payload
        selected_rows = [
            payload[at : at + 16]
            for at in range(0, len(payload), 16)
            if struct.unpack_from("<HH", payload, at) != (0xD5, 0xD7)
        ]
        self.profile.catalog.management = replace(
            management,
            sections={
                **management.sections,
                18: Section(18, 0, len(selected_rows), False, b"".join(selected_rows)),
            },
        )
        events.clear()
        result = workflow.absolute_routine_logs([SavedLogInput(1)], contexts=contexts)
        self.assertEqual(result["logs"], [])
        self.assertEqual(
            result["omissions"],
            [{"log_number": 1, "logical_id": 1, "native_code": 0xC0040101}],
        )
        # D7 absence is observed after the successful native CC selector.
        self.assertEqual(events[-1], (0xD5, bytes.fromhex("310111040001"), 2))
        self.assertEqual(len(events), 5)

    def test_ics02_five_literal_plans_and_probe_fault_omission(self):
        self.frames = [(42, 0xE4, 0, 1, bytes.fromhex("1200aa00"), b"", b"")]
        self.build()
        groups: list[bytes] = []

        def group_key(row: bytes) -> int:
            return row[8]

        checks, freezes, operations = [], [], []
        plans = ((129, 52), (128, 53), (132, 54), (133, 58), (134, 75))
        for index, (selector, signal) in enumerate(plans, 1):
            group, freeze, operation = bytearray(12), bytearray(84), bytearray(8)
            struct.pack_into("<H", group, 4, index)
            group[8] = signal
            groups.append(bytes(group))
            checks.append(struct.pack("<4H", index, index, 0, 0))
            struct.pack_into("<H", freeze, 56, index)
            struct.pack_into("<HH", freeze, 62, 0, 7)
            struct.pack_into("<H", freeze, 70, 6)
            freeze[79] = 2
            freezes.append(bytes(freeze))
            struct.pack_into("<H", operation, 2, index)
            operation[5], operation[7] = 3, selector
            operations.append(bytes(operation))
        pattern = bytearray(24)
        struct.pack_into("<I", pattern, 4, 99)
        struct.pack_into("<H", pattern, 12, 6)
        self.profile = replace(
            self.profile,
            database=replace(
                self.profile.database,
                sections={
                    0: Section(0, 0, 5, False, b"".join(groups)),
                    1: Section(1, 0, 5, False, b"".join(checks)),
                    10: Section(10, 0, 5, False, b"".join(freezes)),
                    14: Section(14, 0, 1, False, bytes(pattern)),
                    54: Section(54, 0, 5, False, b"".join(operations)),
                },
            ),
        )
        observed = WorkflowObservations(42, 7, {}, pid_positions={2: b"\x01"})
        calls = []

        def reply(_ecu, request):
            calls.append(request)
            if request[2] == 132:
                raise NativeStatus(0xA0040201)
            return bytes.fromhex("5200010000")

        result = self.workflow(reply, observations=observed).operation_freeze_ics02()
        self.assertEqual(
            result,
            {
                "native_status": 0,
                "operations": [],
                "native_fields": {"34": 0},
                "status": "ok",
            },
        )
        self.assertEqual(
            calls, [bytes((0x12, 3, selector, 2)) for selector, _ in plans]
        )
        native18 = self.profile
        pattern12 = bytearray(20)
        struct.pack_into("<H", pattern12, 4, 6)
        struct.pack_into("<H", pattern12, 10, 99)
        self.profile = replace(
            self.profile,
            database=replace(
                self.profile.database,
                version=0x0100030C,
                sections={
                    **self.profile.database.sections,
                    14: Section(14, 0, 1, False, bytes(pattern12)),
                },
            ),
        )
        calls.clear()
        result12 = self.workflow(
            reply, observations=replace(observed, source_version=12)
        ).operation_freeze_ics02()
        self.assertEqual(result12, result)
        self.assertEqual(
            calls, [bytes((0x12, 3, selector, 2)) for selector, _ in plans[:4]]
        )
        self.profile = native18

        supported = bytearray(freezes[0])
        self.assertTrue(ToyotaWorkflows._ics_support(bytes(supported), {2: b"\x01"}))
        with self.assertRaises(ToyotaCodecError) as missing:
            ToyotaWorkflows._ics_support(bytes(supported), {})
        self.assertEqual(missing.exception.code, 0x90040501)
        struct.pack_into("<I", pattern, 4, 1)
        for index, signal in enumerate((55, 56, 57, 59, 76), 1):
            group = bytearray(12)
            struct.pack_into("<H", group, 4, index + 5)
            group[8] = signal
            groups.append(bytes(group))
            checks.append(struct.pack("<4H", index + 5, index, 0, 0))
        updated = []
        for freeze in freezes:
            row = bytearray(freeze)
            struct.pack_into("<H", row, 60, 7)
            row[76], row[78] = 2, 2
            updated.append(bytes(row))
        physical, unit = bytearray(24), bytearray(12)
        struct.pack_into("<IIIHH", physical, 0, 3, 1, 0, 7, 1)
        struct.pack_into("<HH", unit, 4, 1, 4)
        sections = dict(self.profile.database.sections)
        sections.update(
            {
                0: Section(0, 0, 10, False, b"".join(sorted(groups, key=group_key))),
                1: Section(1, 0, 10, False, b"".join(checks)),
                10: Section(10, 0, 5, False, b"".join(updated)),
                13: Section(13, 0, 1, False, bytes(physical)),
                15: Section(15, 0, 1, False, bytes(unit)),
                14: Section(14, 0, 1, False, bytes(pattern)),
            }
        )
        self.profile = replace(
            self.profile, database=replace(self.profile.database, sections=sections)
        )
        management = self.profile.catalog.management
        categories = [self.profile.category_record]
        for category_id in range(4000, 4005):
            category = bytearray(76)
            struct.pack_into("<H", category, 68, category_id)
            categories.append(bytes(category))
        self.profile.catalog.management = replace(
            management,
            sections={
                **management.sections,
                16: Section(16, 0, 6, False, b"".join(categories)),
            },
        )
        # Raw support discovery requires selected function13 on the same ECU.
        # Add that function using the existing test DDB encoder, retaining the
        # already selected authored signal resources above.
        selected_database = self.profile.database
        selected_management = self.profile.catalog.management
        self.frames.append((42, 0x13, 0, 1, bytes.fromhex("0100"), b"", b""))
        self.build()
        self.profile = replace(self.profile, database=selected_database)
        self.profile.catalog.management = replace(
            self.profile.catalog.management,
            sections={
                **self.profile.catalog.management.sections,
                16: selected_management.sections[16],
            },
        )
        events = []

        class Stream:
            def __init__(self):
                self.responses = iter(
                    [(0, bytes.fromhex("4100020101")), (0x91010009, b"")]
                )

            def send(self, call):
                events.append(("send", call.query.request))
                return 0

            def receive(self, call):
                events.append(("receive", call.query.request))
                return next(self.responses)

        def positive(_ecu, request):
            events.append(("data", request))
            return bytes.fromhex("5200010000")

        result = self.workflow(
            positive, observations=observed, support_stream=Stream()
        ).operation_freeze_ics02()
        actual = result["operations"]
        assert isinstance(actual, list)
        self.assertEqual(
            [row["control"] for row in actual], [selector for selector, _ in plans]
        )
        self.assertEqual([row["signals"][0]["value"] for row in actual], [3] * 5)
        self.assertEqual([row["name_id"] for row in actual], [0] * 5)
        self.assertEqual([row["native_fields"]["24"] for row in actual], [1] * 5)
        self.assertEqual(sum(kind == "data" for kind, _ in events), 10)
        count = [0]

        def short(_ecu, _request):
            count[0] += 1
            if count[0] == 2:
                raise NativeStatus(0xA0040202)
            return bytes.fromhex("5200010000")

        result = self.workflow(
            short, observations=observed, support_stream=Stream()
        ).operation_freeze_ics02()
        actual = result["operations"]
        assert isinstance(actual, list)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(actual[0]["signals"][0]["raw"], 0)
        self.assertEqual(
            actual[0]["signals"][0]["native_default"],
            "CCmdEcuData_ctor_DWORD10_zero_after_A0040202",
        )
        sections = dict(self.profile.database.sections)
        extra_groups = []
        extra_checks = []
        for index, signal in enumerate(range(66, 72), 20):
            group = bytearray(12)
            struct.pack_into("<H", group, 4, index)
            group[8] = signal
            extra_groups.append(bytes(group))
            extra_checks.append(struct.pack("<4H", index, 1, 0, 0))
        sections[0] = Section(
            0,
            0,
            16,
            False,
            b"".join(sorted(groups + extra_groups, key=group_key)),
        )
        sections[1] = Section(1, 0, 16, False, b"".join(checks + extra_checks))
        self.profile = replace(
            self.profile, database=replace(self.profile.database, sections=sections)
        )
        events.clear()
        workflow = self.workflow(positive, observations=observed)
        workflow._begin()
        fields, any_sample = workflow._ics_auxiliary(
            3, 129, {2: b"\x01"}, extended=True, budget=[0]
        )
        self.assertTrue(any_sample)
        self.assertEqual(fields["210"], 1)
        auxiliary = fields["signals"]
        assert isinstance(auxiliary, dict)
        self.assertEqual(list(auxiliary), ["34c", "3e4", "47c", "514", "5ac", "644"])
        self.assertEqual(events, [("data", bytes.fromhex("12038102"))])

    def test_timer_resource_absence_and_empty_key_remain_distinct(self):
        for timers, expected in ((None, 0xA0030107), ([], 0xC0040101)):
            self.timers = timers
            self.build()
            with self.assertRaises(ToyotaCodecError) as caught:
                self.workflow().clear_dtc()
            self.assertEqual(caught.exception.code, expected)
            self.assertFalse(self.calls)

    def test_clear_timeout_mapping_and_transport_cancellation(self):
        def timeout(_ecu, _request):
            raise NativeStatus(0x91010009)

        with self.assertRaises(ToyotaCodecError) as caught:
            self.workflow(timeout).clear_dtc()
        self.assertEqual(caught.exception.code, 0x90040501)
        stop = [False]

        def cancel(_ecu, _request):
            stop[0] = True
            raise NativeStatus(0x91010009)

        with self.assertRaises(Cancelled):
            self.workflow(cancel, cancelled=lambda: stop[0]).clear_dtc()

    def test_mazda_fixed_function_uses_each_rows_own_setting_and_send_only_status(self):
        self.frames += [
            (0x394, 0xF2, 0, 1, b"\x14\x01", b"", b""),
            (0x394, 0xF2, 1, 2, b"\x14\x02", b"", b""),
        ]
        self.build()
        calls = []

        def native(ecu, call):
            calls.append((ecu, call.operation, call.arguments))
            return 19 if len(calls) == 1 else 0

        result = self.workflow(native_send=native).clear_dtc_mazda()
        self.assertEqual(result, {"native_status": 0, "send_statuses": [19, 0]})
        self.assertFalse(self.calls)
        self.assertEqual(
            [call[2] for call in calls],
            [
                (0x394, b"\x14\x01", 2, 0x11223344, 50, 0, 1),
                (0x394, b"\x14\x02", 2, 0x55667788, 50, 0, 1),
            ],
        )
        calls.clear()
        result12 = self.workflow(
            native_send=native,
            observations=WorkflowObservations(42, 7, {}, source_version=12),
        ).clear_dtc_mazda()
        self.assertEqual(result12["send_statuses"], [19, 0])
        with self.assertRaises(SessionError):
            self.workflow().clear_dtc_mazda()

    def test_psa_observed_reset_sequence_and_first_frame_mask(self):
        self.frames += [
            (42, function, 0, 1, bytes([sid, 1]), b"\xf0", b"\xff")
            for function, sid in (
                (0xC5, 0x10),
                (0x67, 0x11),
                (0xC6, 0x12),
                (0xC7, 0x13),
            )
        ]
        self.build()
        self.functions = {(1, 0x40, 0): 0, (0x10, 0x44, 0): 0, (1, 0x41, 0): 0}

        def exchange(ecu, request):
            self.calls.append((ecu, request))
            return b"\xff\x01" if request[0] != 0x14 else b"\x54\xaa"

        with self.assertRaises(ToyotaCodecError) as caught:
            self.workflow(exchange).clear_dtc_psa()
        self.assertEqual(caught.exception.code, 0xA0040201)  # SID fails before mask.
        self.frames = [
            (c, f, o, s, r, b"\xf0" if f != 1 else m, b"\x5f" if f != 1 else k)
            for c, f, o, s, r, m, k in self.frames
        ]
        self.build()
        self.calls.clear()
        self.assertEqual(self.workflow().clear_dtc_psa()["native_clear_flag"], 1)
        self.assertEqual(
            [r[0] for _, r in self.calls], [0x10, 0x11, 0x12, 0x13, 0x14, 0x10, 0x11]
        )

        self.calls.clear()
        self.assertEqual(
            self.workflow(
                observations=WorkflowObservations(
                    42, 7, self.functions, source_version=12
                )
            ).clear_dtc_psa()["native_clear_flag"],
            1,
        )
        self.assertEqual(
            [r[0] for _, r in self.calls], [0x10, 0x11, 0x12, 0x13, 0x14, 0x10, 0x11]
        )

    def test_mazda_later_metadata_failure_preserves_first_send_chronology(self):
        self.frames += [
            (0x394, 0xF2, 0, 1, b"\x14\x01", b"", b""),
            (0x394, 0xF2, 1, 99, b"\x14\x02", b"", b""),
        ]
        self.build()
        sent = []

        def native(_ecu, call):
            sent.append(call.request)
            return 0

        with self.assertRaises(ToyotaCodecError) as caught:
            self.workflow(native_send=native).clear_dtc_mazda()
        self.assertEqual(caught.exception.code, 0xC0040102)
        self.assertEqual(sent, [b"\x14\x01"])

    def test_absent_function_cache_is_not_an_observed_empty_tree(self):
        with self.assertRaises(SessionError):
            self.workflow(observations=WorkflowObservations(42, 7)).clear_dtc_psa()
        self.assertEqual(self.workflow().clear_dtc_psa()["native_clear_flag"], 1)

    def test_p4_fallback_literal_function_and_original_error_when_absent(self):
        def exchange(ecu, request):
            self.calls.append((ecu, request))
            if request == b"\x14\xaa":
                raise NativeStatus(0x90020321)
            return b"\x54\xbb"

        with self.assertRaises(ToyotaCodecError) as caught:
            self.workflow(exchange).clear_dtc_p4()
        self.assertEqual(caught.exception.code, 0x90020321)
        self.frames += [(42, 0x102, 0, 1, b"\x14\xbb", b"", b"")]
        self.build()
        self.calls.clear()
        self.assertEqual(self.workflow(exchange).clear_dtc_p4()["native_clear_flag"], 1)
        self.assertEqual(
            [request for _, request in self.calls], [b"\x14\xaa", b"\x14\xbb"]
        )

    def test_p4_feature_one_only_falls_back_on_timeout(self):
        self.frames += [(42, 0x102, 0, 1, b"\x14\xbb", b"", b"")]
        self.build()
        observation = WorkflowObservations(42, 0x22, {(0x1E, 0x15, 0x14): 1})
        status = [0x90020321]

        def exchange(ecu, request):
            self.calls.append((ecu, request))
            if request == b"\x14\xaa":
                raise NativeStatus(status[0])
            return b"\x54\xbb"

        with self.assertRaises(ToyotaCodecError) as caught:
            self.workflow(exchange, observations=observation).clear_dtc_p4()
        self.assertEqual(caught.exception.code, status[0])
        self.assertEqual(len(self.calls), 1)
        status[0] = 0x91010009
        self.calls.clear()
        self.assertEqual(
            self.workflow(exchange, observations=observation).clear_dtc_p4()[
                "native_clear_flag"
            ],
            1,
        )
        self.assertEqual(len(self.calls), 2)

    def test_v12_p4_has_no_address_or_fallback_and_preserves_timeout(self):
        self.profile.catalog.management = replace(
            self.profile.catalog.management, version=0x0100030C
        )
        observed = WorkflowObservations(42, 0x22, source_version=12)
        self.assertEqual(
            self.workflow(observations=observed).clear_dtc_p4()["native_clear_flag"], 1
        )
        self.assertEqual([request.hex() for _, request in self.calls], ["14aa"])

        def timeout(_ecu, _request):
            raise NativeStatus(0x91010009)

        with self.assertRaises(ToyotaCodecError) as caught:
            self.workflow(timeout, observations=observed).clear_dtc_p4()
        self.assertEqual(caught.exception.code, 0x91010009)

    def test_p4_alternate_category_install_then_frame_failure_restores_mode(self):
        details = bytearray(24)
        struct.pack_into("<3H", details, 4, 42, 1, 0x57)
        self.details = [bytes(details)]
        self.build()
        management = self.profile.catalog.management
        sections = dict(management.sections)
        target = bytearray(self.profile.category_record)
        struct.pack_into("<H", target, 68, 43)
        target[72] = 9
        sections[16] = Section(16, 0, 2, False, self.profile.category_record + target)
        protocol = bytearray(28)
        struct.pack_into("<H", protocol, 0, 42)
        struct.pack_into("<H", protocol, 8, 2)
        protocol[24] = 0x12
        sections[13] = Section(13, 0, 1, False, bytes(protocol))
        sections[72] = Section(72, 0, 1, False, struct.pack("<HBB", 10, 3, 0))
        sections[73] = Section(
            73, 0, 1, False, struct.pack("<IH6B", 43, 0, 0x12, 0, 3, 5, 0, 0)
        )
        self.profile.catalog.management = replace(management, sections=sections)
        old, seed = b"\xee" * 16, b"\xab" * 16
        events = []

        def get_mode(ecu):
            events.append(("get", ecu))
            return old

        def set_mode(ecu, mode):
            events.append(("set", ecu, mode))

        observation = WorkflowObservations(42, 0x12, {}, mode_seed=seed)
        with self.assertRaises(ToyotaCodecError) as caught:
            self.workflow(
                observations=observation,
                native_get_mode=get_mode,
                native_set_mode=set_mode,
            ).clear_dtc_p4()
        self.assertEqual(caught.exception.code, 0xC0040101)
        self.assertFalse(self.calls)
        mode = bytearray(seed)
        struct.pack_into("<H", mode, 0, 1)
        struct.pack_into("<IIHH", mode, 4, 43, 10, 5, 9)
        self.assertEqual(
            events,
            [
                ("get", "authored-ecu"),
                ("set", "authored-ecu", bytes(mode)),
                ("set", "authored-ecu", old),
            ],
        )
        self.assertEqual(bytes(mode[2:4]), seed[2:4])

    def test_first_saved_log_metadata_is_retained(self):
        first = SavedLogInput(12, {"source": "first"})
        self.assertEqual(
            selected_saved_logs(
                [first, SavedLogInput(12, {"source": "later"}), SavedLogInput(13)]
            ),
            (first, SavedLogInput(13)),
        )

    def test_legacy_multi_freeze_exact_feature_fallback_and_frame_patch(self):
        self.frames += [(42, 6, 0, 1, b"\x17\x00\x00", bytes.fromhex("00ffff"), b"")]
        self.build()
        observed = WorkflowObservations(
            42, 7, {(1, 6, 4): 1, (1, 6, 6): 0, (1, 6, 5): 0x20}
        )

        def exchange(ecu, request):
            self.calls.append((ecu, request))
            return bytes.fromhex("571234")

        result = self.workflow(exchange, observations=observed).is_multi_freeze(
            3, 0x1234
        )
        self.assertTrue(result["available"])
        self.assertEqual(result["frame_number"], 0x23)
        self.assertEqual(self.calls, [("authored-ecu", bytes.fromhex("170023"))])
        self.calls.clear()
        result12 = self.workflow(
            exchange, observations=replace(observed, source_version=12)
        ).is_multi_freeze(3, 0x1234)
        self.assertTrue(result12["available"])
        self.assertEqual(self.calls, [("authored-ecu", bytes.fromhex("170023"))])
        with self.assertRaises(ToyotaCodecError) as caught:
            self.workflow(exchange).is_multi_freeze(3, 0x1234)
        self.assertEqual(caught.exception.code, 0xC0040601)

    def test_legacy_multi_info_selected_mask_and_zero_short_circuit(self):
        self.frames += [
            (42, 0x71, 0, 1, b"\x21", b"\x00\x0f", b""),
            (42, 0x73, 0, 1, b"\x22", b"\x00\xf0", b""),
            (42, 6, 0, 1, b"\x17\x00\x00", bytes.fromhex("00ffff"), b""),
        ]
        self.build()
        replies = {
            b"\x21": b"\x61\x01",
            b"\x22": b"\x62\x20",
            bytes.fromhex("170023"): bytes.fromhex("571234"),
        }

        def exchange(ecu, request):
            self.calls.append((ecu, request))
            return replies[request]

        self.assertTrue(self.workflow(exchange).is_multi_freeze(3, 0x1234)["available"])
        self.assertEqual(
            [request.hex() for _, request in self.calls], ["21", "22", "170023"]
        )
        replies[b"\x21"] = b"\x61\x00"
        self.calls.clear()
        self.assertFalse(
            self.workflow(exchange).is_multi_freeze(3, 0x1234)["available"]
        )
        self.assertEqual(len(self.calls), 1)
        replies[b"\x21"] = b"\x61"
        with self.assertRaises(ToyotaCodecError) as caught:
            self.workflow(exchange).is_multi_freeze(3, 0x1234)
        self.assertEqual(caught.exception.code, 0xA0040202)

    def test_multi_v2_descending_nibbles_preserves_alias_and_masked_unwritten_word(
        self,
    ):
        self.frames += [(42, 6, 0, 1, b"\x17\x00\x00", bytes.fromhex("00ffff"), b"")]
        self.build()
        observed = WorkflowObservations(
            42, 7, {(1, 6, 4): 2, (1, 6, 5): 0x30, (1, 6, 6): 0x50}
        )

        def exchange(ecu, request):
            self.calls.append((ecu, request))
            if request[-1] == 0x43:
                raise NativeStatus(0xA0040201)
            return bytes.fromhex("571234")

        result = self.workflow(exchange, observations=observed).is_multi_freeze_v2(
            3, 0x1234
        )
        self.assertEqual(result["native_numbers"], [3, 0x53, 0x33])
        self.assertTrue(result["available"])
        self.assertEqual(
            [request.hex() for _, request in self.calls], ["170053", "170043", "170033"]
        )
        # Circular signed chronology crosses zero, skipping the zero frame.
        observed = WorkflowObservations(
            42, 7, {(1, 6, 4): 2, (1, 6, 5): 0xE0, (1, 6, 6): 0x20}
        )
        self.calls.clear()
        result = self.workflow(exchange, observations=observed).is_multi_freeze_v2(
            3, 0x1234
        )
        self.assertEqual(
            [request[-1] for _, request in self.calls], [0x23, 0x13, 0xF3, 0xE3]
        )
        self.assertEqual(result["native_numbers"], [3, 0x23, 0x13, 0xF3, 0xE3])
        self.calls.clear()
        result12 = self.workflow(
            exchange, observations=replace(observed, source_version=12)
        ).is_multi_freeze_v2(3, 0x1234)
        self.assertEqual(result12["native_numbers"], [3, 0x23, 0x13, 0xF3, 0xE3])
        self.assertEqual(
            [request[-1] for _, request in self.calls], [0x23, 0x13, 0xF3, 0xE3]
        )
        # Old unsigned-nibble iteration incorrectly sent30/20/10 here.
        observed = WorkflowObservations(
            42, 7, {(1, 6, 4): 2, (1, 6, 5): 0x10, (1, 6, 6): 0x30}
        )
        self.calls.clear()
        result = self.workflow(exchange, observations=observed).is_multi_freeze_v2(
            3, 0x1234
        )
        self.assertEqual(result["native_numbers"], [3])
        self.assertFalse(result["available"])
        self.assertFalse(self.calls)
        observed = WorkflowObservations(
            42, 7, {(1, 6, 4): 2, (1, 6, 5): 0, (1, 6, 6): 0}
        )
        self.calls.clear()
        self.assertEqual(
            self.workflow(exchange, observations=observed).is_multi_freeze_v2(3, 0)[
                "native_numbers"
            ],
            [],
        )
        self.assertFalse(self.calls)

    def test_vgrs_c1555_runs_additional_function_after_clear(self):
        self.frames += [
            (42, 0x0A, 0, 1, b"\x18", b"", b""),
            (42, 2, 0, 1, b"\x15", b"", b""),
        ]
        self.build()
        dtc = [b"\x58\x55\x55"]

        def exchange(ecu, request):
            self.calls.append((ecu, request))
            return (
                dtc[0]
                if request == b"\x18"
                else bytes([request[0] | 0x40]) + request[1:]
            )

        self.assertTrue(self.workflow(exchange).clear_dtc_vgrs()["c1555_observed"])
        self.assertEqual([r[0] for _, r in self.calls], [0x18, 0x14, 0x15])
        self.calls.clear()
        self.assertTrue(
            self.workflow(
                exchange,
                observations=WorkflowObservations(42, 7, {}, source_version=12),
            ).clear_dtc_vgrs()["c1555_observed"]
        )
        self.assertEqual([r[0] for _, r in self.calls], [0x18, 0x14, 0x15])
        dtc[0] = b"\x58\x00\x00"
        self.calls.clear()
        self.assertFalse(self.workflow(exchange).clear_dtc_vgrs()["c1555_observed"])
        self.assertEqual([r[0] for _, r in self.calls], [0x18, 0x14])
        dtc[0] = b"\x58\x55\x55"

        def followup_failure(ecu, request):
            if request == b"\x15":
                raise NativeStatus(0x91010009)
            return exchange(ecu, request)

        workflow = self.workflow(followup_failure)
        with self.assertRaises(ToyotaCodecError):
            workflow.clear_dtc_vgrs()
        self.assertEqual(workflow.native_output, {"native_clear_flag": 1})

    def test_absolute_freeze_requires_raw_value_status_and_original_pattern(self):
        self.frames += [
            (42, 0x11, 0, 1, b"\x12\x00\x00", b"", b""),
            (42, 0x18, 0, 1, b"\x18\x00\x00", b"", b""),
        ]
        self.build()
        group = bytearray(12)
        struct.pack_into("<H", group, 4, 7)
        group[8] = 4
        freeze = bytearray(84)
        struct.pack_into("<H", freeze, 56, 9)
        struct.pack_into("<HH", freeze, 62, 0, 7)
        struct.pack_into("<H", freeze, 70, 6)
        freeze[79] = 2
        pattern = bytearray(24)
        struct.pack_into("<II", pattern, 0, 1, 1)
        struct.pack_into("<H", pattern, 12, 6)
        original = self.profile.database
        self.profile = replace(
            self.profile,
            database=replace(
                original,
                sections={
                    0: Section(0, 0, 1, False, bytes(group)),
                    1: Section(1, 0, 1, False, struct.pack("<4H", 7, 9, 0, 0)),
                    2: Section(2, 0, 2, False, bytes.fromhex("0000030000000400")),
                    10: Section(10, 0, 1, False, bytes(freeze)),
                    14: Section(14, 0, 1, False, bytes(pattern)),
                },
            ),
        )
        label = "Authored frame\0".encode("utf-16le")
        self.profile.catalog.language = Language(
            parse_database(
                database(4, {0: (1, struct.pack("<IH", 0, len(label)) + label)})
            )
        )

        def old_profile(value, *, wide=False):
            pattern12 = bytearray(20)
            struct.pack_into("<I", pattern12, 0, 1)
            struct.pack_into("<H", pattern12, 4, 6)
            struct.pack_into("<H", pattern12, 10, value)
            sections = {
                **self.profile.database.sections,
                14: Section(14, 0, 1, False, bytes(pattern12)),
            }
            if wide:
                freeze12 = bytearray(freeze)
                struct.pack_into("<H", freeze12, 64, 31)
                sections[10] = Section(10, 0, 1, False, bytes(freeze12))
            return replace(
                self.profile,
                database=replace(
                    self.profile.database, version=0x0100030C, sections=sections
                ),
            )

        def exchange(ecu, request):
            self.calls.append((ecu, request))
            if request[0] == 0x12:
                return b"\x52" + request[1:] + b"\x01"
            return (
                b"\x58\x00"
                + request[2:]
                + (b"\x00\x00" if request[2] == 3 else b"\x00\x01")
            )

        self.assertEqual(
            self.workflow(exchange).is_absolute_freeze(),
            {
                "native_status": 0,
                "frames": [
                    {"frame_number": 3, "ordinal": 1, "label": "Authored frame"}
                ],
            },
        )
        self.assertEqual(
            [request.hex() for _, request in self.calls],
            ["120203", "180003", "120204", "180004"],
        )
        native18_profile = self.profile
        self.profile = old_profile(1)
        self.calls.clear()
        self.assertEqual(
            self.workflow(
                exchange,
                observations=WorkflowObservations(42, 7, {}, source_version=12),
            ).is_absolute_freeze()["frames"],
            [{"frame_number": 3, "ordinal": 1, "label": "Authored frame"}],
        )
        self.assertEqual(
            [request.hex() for _, request in self.calls],
            ["120203", "180003", "120204", "180004"],
        )
        self.profile = native18_profile
        selected_database, language = (
            self.profile.database,
            self.profile.catalog.language,
        )
        self.frames = [
            (42, 0x11, 0, 1, b"\x12\x00\x00\x00", b"", b""),
            (42, 0x13, 0, 1, b"\x01\x00", b"", b""),
        ]
        self.build()
        self.profile = replace(self.profile, database=selected_database)
        self.profile.catalog.language = language
        struct.pack_into("<I", pattern, 4, 255)
        self.profile = replace(
            self.profile,
            database=replace(
                selected_database,
                sections={
                    **selected_database.sections,
                    14: Section(14, 0, 1, False, bytes(pattern)),
                },
            ),
        )
        self.calls.clear()

        def exchange_p4(ecu, request):
            self.calls.append((ecu, request))
            if request[1] == 4:
                raise NativeStatus(0x90020321)
            return bytes.fromhex("5200010000")

        observed = WorkflowObservations(42, 7, {}, pid_positions={2: b"\x01"})
        self.assertEqual(
            self.workflow(exchange_p4, observations=observed).is_absolute_freeze_p4(),
            {
                "native_status": 0,
                "frames": [
                    {"frame_number": 3, "ordinal": 1, "label": "Authored frame"}
                ],
            },
        )
        self.assertEqual(
            [request.hex() for _, request in self.calls], ["12030002", "12040002"]
        )
        # Native12 compares a WORD pattern with DI, even when raw DWORD is wider.
        native18_profile = self.profile
        old_pattern = bytearray(20)
        struct.pack_into("<I", old_pattern, 0, 1)
        struct.pack_into("<HH", old_pattern, 4, 6, 0)
        struct.pack_into("<H", old_pattern, 10, 1)
        self.profile = replace(
            self.profile,
            database=replace(
                self.profile.database,
                version=0x0100030C,
                sections={
                    **self.profile.database.sections,
                    14: Section(14, 0, 1, False, bytes(old_pattern)),
                },
            ),
        )
        old_workflow = self.workflow(observations=replace(observed, source_version=12))
        self.assertEqual(
            old_workflow._pattern_label(bytes(freeze), 0x10001), "Authored frame"
        )
        self.assertTrue(old_workflow._operation_pattern_matches(bytes(freeze), 0x10001))
        self.assertFalse(
            old_workflow._operation_pattern_matches(bytes(freeze), 0x10002)
        )
        self.profile = native18_profile
        native18_profile = self.profile
        self.profile = old_profile(1, wide=True)
        self.calls.clear()

        def old_p4_data(ecu, request):
            self.calls.append((ecu, request))
            if request[1] == 4:
                raise NativeStatus(0x90020321)
            return bytes.fromhex("5200000100010000")

        full12 = self.workflow(
            old_p4_data,
            observations=replace(
                observed, source_version=12, pid_positions={2: b"\x01" * 4}
            ),
        ).is_absolute_freeze_p4()
        self.assertEqual(
            full12["frames"],
            [{"frame_number": 3, "ordinal": 1, "label": "Authored frame"}],
        )
        self.assertEqual(
            [request.hex() for _, request in self.calls], ["12030002", "12040002"]
        )
        self.profile = native18_profile
        duplicate = replace(
            self.profile.database,
            sections={
                **self.profile.database.sections,
                2: Section(2, 0, 3, False, bytes.fromhex("000003000000040000000300")),
            },
        )
        base = self.profile
        self.profile = replace(base, database=duplicate)
        self.calls.clear()
        duplicated = self.workflow(
            exchange_p4, observations=observed
        ).is_absolute_freeze_p4()
        self.assertEqual(
            duplicated["frames"],
            [
                {"frame_number": 3, "ordinal": 1, "label": "Authored frame"},
                {"frame_number": 3, "ordinal": 3, "label": "Authored frame"},
            ],
        )
        self.assertEqual(
            [request.hex() for _, request in self.calls], ["12030002", "12040002"]
        )
        self.profile = base
        with self.assertRaises(ToyotaCodecError) as absent_stream:
            self.workflow(exchange_p4).is_absolute_freeze_p4()
        self.assertEqual(absent_stream.exception.code, 0xC0040601)
        self.calls.clear()
        events = []

        class Stream:
            def __init__(self):
                self.replies = iter(
                    [(0, bytes.fromhex("4100020101")), (0x91010009, b"")]
                )

            def send(self, call):
                events.append(("send", call.query.request))
                return 0

            def receive(self, call):
                events.append(("receive", call.query.request))
                return next(self.replies)

        def late_data(ecu, request):
            events.append(("data", request))
            return exchange_p4(ecu, request)

        late = self.workflow(late_data, support_stream=Stream()).is_absolute_freeze_p4()
        late_frames = late["frames"]
        assert isinstance(late_frames, list)
        self.assertEqual(late_frames[0]["frame_number"], 3)
        self.assertEqual(
            events,
            [
                ("data", bytes.fromhex("12030002")),
                ("send", b"\x01\x00"),
                ("receive", b"\x01\x00"),
                ("receive", b"\x01\x00"),
                ("data", bytes.fromhex("12040002")),
            ],
        )
        self.frames += [(42, 0x18, 0, 1, b"\x18\x00\x00\x00", b"", b"")]
        self.build()
        struct.pack_into("<I", pattern, 4, 1)
        self.profile = replace(
            self.profile,
            database=replace(
                selected_database,
                sections={
                    **selected_database.sections,
                    14: Section(14, 0, 1, False, bytes(pattern)),
                },
            ),
        )
        self.profile.catalog.language = language
        self.calls.clear()

        def exchange_dk(ecu, request):
            self.calls.append((ecu, request))
            return (
                bytes.fromhex("5200010000")
                if request[0] == 0x12
                else bytes.fromhex("58000000")
            )

        self.assertEqual(
            self.workflow(exchange_dk).is_absolute_freeze_dk(),
            {
                "native_status": 0,
                "frames": [
                    {"frame_number": 3, "ordinal": 255, "label": "Authored frame"},
                    {"frame_number": 4, "ordinal": 254, "label": "Authored frame"},
                ],
            },
        )
        self.assertEqual(
            [request.hex() for _, request in self.calls],
            ["12030002", "18030000", "12040002", "18040000"],
        )
        native18_profile = self.profile
        self.profile = old_profile(1)
        self.calls.clear()
        full12 = self.workflow(
            exchange_dk, observations=WorkflowObservations(42, 7, {}, source_version=12)
        ).is_absolute_freeze_dk()
        self.assertEqual(
            full12["frames"],
            [
                {"frame_number": 3, "ordinal": 255, "label": "Authored frame"},
                {"frame_number": 4, "ordinal": 254, "label": "Authored frame"},
            ],
        )
        self.assertEqual(
            [request.hex() for _, request in self.calls],
            ["12030002", "18030000", "12040002", "18040000"],
        )
        self.profile = native18_profile
        self.profile = replace(
            self.profile,
            database=replace(
                self.profile.database,
                sections={
                    k: v for k, v in self.profile.database.sections.items() if k != 14
                },
            ),
        )
        with self.assertRaises(ToyotaCodecError) as caught:
            self.workflow(exchange_p4, observations=observed).is_absolute_freeze_p4()
        self.assertEqual(caught.exception.code, 0xA0030107)

    def test_psd_actual_support_stream_bitmap_data_and_reverse_order(self):
        self.frames += [
            (42, 0x13, 0, 1, b"\x01\x00", b"", b""),
            (42, 0x63, 0, 1, b"\x18\x00\x00\x00", b"", b""),
            (42, 0x11, 0, 1, b"\x12\x00\x00\x00", b"", b""),
        ]
        self.build()
        freeze = bytearray(84)
        struct.pack_into("<HH", freeze, 62, 0, 7)
        freeze[78], freeze[79] = 2, 2
        selected = self.profile.database
        self.profile = replace(
            self.profile,
            database=replace(
                selected,
                sections={
                    3: Section(3, 0, 1, False, bytes.fromhex("0000000000010000")),
                    6: Section(6, 0, 1, False, bytes.fromhex("0000020100000000")),
                    10: Section(10, 0, 1, False, bytes(freeze)),
                },
            ),
        )
        events = []

        class Stream:
            def __init__(self):
                self.replies = iter(
                    [(0, bytes.fromhex("4100020101")), (0x91010009, b"")]
                )

            def send(self, call):
                events.append(
                    ("send", call.query.request, call.parameter4, call.parameter5)
                )
                return 0

            def receive(self, call):
                events.append(("receive", call.query.request))
                return next(self.replies)

        def support(query):
            events.append(("support", query.request))
            return bytes.fromhex("5800400000")

        def exchange(ecu, request):
            events.append(("data", ecu, request))
            return bytes.fromhex("5200010000")

        observed = WorkflowObservations(
            42, 7, {(7, 0x45, 10): 2, (7, 0x45, 11): 3, (7, 0x45, 12): 4}
        )
        result = self.workflow(
            exchange,
            observations=observed,
            support_exchange=support,
            support_stream=Stream(),
        ).is_psd_freeze(native_label=WorkflowLabel.authored("Authored PSD frame"))
        self.assertEqual(
            result["frames"],
            [
                {"frame_number": 4, "ordinal": 50, "label": "Authored PSD frame"},
                {"frame_number": 3, "ordinal": 51, "label": "Authored PSD frame"},
            ],
        )
        self.assertEqual(
            events,
            [
                ("send", b"\x01\x00", 0x11223344, 7),
                ("receive", b"\x01\x00"),
                ("receive", b"\x01\x00"),
                ("support", bytes.fromhex("18030000")),
                ("data", "authored-ecu", bytes.fromhex("12030002")),
                ("support", bytes.fromhex("18040000")),
                ("data", "authored-ecu", bytes.fromhex("12040002")),
            ],
        )

        expected_events = list(events)
        events.clear()
        result12 = self.workflow(
            exchange,
            observations=replace(observed, source_version=12),
            support_exchange=support,
            support_stream=Stream(),
        ).is_psd_freeze(
            native_label=WorkflowLabel.authored("Authored PSD frame", version=12)
        )
        self.assertEqual(result12["frames"], result["frames"])
        self.assertEqual(events, expected_events)

    def test_active_p5_distinct_metadata_optional_children_unit_carry_and_native_defaults(
        self,
    ):
        self.frames += [(42, 0xC8, 0, 1, bytes.fromhex("220000"), b"", b"")]
        self.build()
        monitors, physicals, children = [], [], []
        for signal, physical_key, unit_key in ((9, 7, 1), (10, 8, 99)):
            row, physical, child = bytearray(64), bytearray(24), bytearray(12)
            struct.pack_into("<IIIII", row, 4, 4, 8, 17, 99, 0x123402)
            struct.pack_into("<III", row, 24, 1, 77, 0x50)
            struct.pack_into("<H", row, 36, signal)
            struct.pack_into("<HHH", row, 42, physical_key, 0, 7)
            monitors.append(bytes(row))
            struct.pack_into("<IIIHH", physical, 0, 2, 1, 5, physical_key, unit_key)
            physical[21] = 3
            physicals.append(bytes(physical))
            struct.pack_into("<HHH", child, 0, signal, 0, signal)
            child[9] = 1
            children.append(bytes(child))
        unit = bytearray(12)
        struct.pack_into("<IHH", unit, 0, 2, 1, 4)
        self.profile = replace(
            self.profile,
            database=replace(
                self.profile.database,
                sections={
                    13: Section(13, 0, 2, False, b"".join(physicals)),
                    15: Section(15, 0, 1, False, bytes(unit)),
                    26: Section(26, 0, 2, False, b"".join(children)),
                    62: Section(62, 0, 2, False, b"".join(monitors)),
                },
            ),
        )
        labels = [
            "Authored signal\0".encode("utf-16le"),
            "authored-unit\0".encode("utf-16le"),
        ]
        pool = struct.pack(
            "<IHIH", 0, len(labels[0]), len(labels[0]), len(labels[1])
        ) + b"".join(labels)
        self.profile.catalog.language = Language(
            parse_database(database(4, {0: (2, pool)}))
        )
        calls = []

        def support(query):
            calls.append(query.request)
            return bytes.fromhex("62000000")

        result = self.workflow(support_exchange=support).active_test_monitors()
        self.assertEqual(calls, [bytes.fromhex("220000")])
        self.assertEqual(result["status"], "partial")
        signals = result["signals"]
        assert isinstance(signals, list)
        self.assertEqual([item["signal_id"] for item in signals], [9, 10])
        self.assertEqual(
            [item["unit"] for item in signals], ["authored-unit", "authored-unit"]
        )
        self.assertEqual(signals[0]["short_name"], "")
        self.assertEqual(signals[0]["multiplier"], 2)
        self.assertEqual(signals[0]["precision"], 3)
        self.assertEqual(
            signals[0]["native_fields"],
            {"3c": 77, "40": 0x123402, "54": 17, "58": 99, "5c": 4, "60": 8},
        )
        self.assertEqual(
            signals[1]["native_defaults"], ["unit_retained_from_previous_record"]
        )
        # Rebuild both selected databases before the actual concrete factory.
        for build, flags, overflow in (
            (12, 1, False),
            (12, 0x21, False),
            (18, 1, False),
            (12, 1, True),
            (18, 1, True),
        ):
            with self.subTest(build=build, flags=flags, overflow=overflow):
                selected = copy.deepcopy(self.profile)
                category = bytearray(selected.category_record)
                category[72] = flags
                protocol, can = bytearray(28 if build == 18 else 24), bytearray(28)
                struct.pack_into("<6H", protocol, 0, 42, 1, 0x33, 0x7DF, 0x7E0, 0xAB)
                protocol[24 if build == 18 else 22] = 0x12
                struct.pack_into("<IIHHH", can, 0, 0x1234, 500000, 1, 0, 20)
                struct.pack_into("<H", can, 18 if build == 18 else 16, 9)
                # Actual lower construction needs selected initialization frames.
                management = selected.catalog.management
                variables = management.sections[0]
                old_count = variables.count
                index_size = old_count * 6
                index = bytearray(variables.payload[:index_size])
                pool = bytearray(variables.payload[index_size:])
                frames, functions = (
                    bytearray(management.sections[17].payload),
                    bytearray(management.sections[18].payload),
                )
                for function, request in ((0x67, b"\x10\x01"), (0x7F, b"\x3e")):
                    identifiers = []
                    for value in (request, b"", b""):
                        index += struct.pack("<IH", len(pool), len(value))
                        pool += value
                        identifiers.append(len(index) // 6)
                    frame_id = len(frames) // 8 + 1
                    frames += struct.pack("<4H", frame_id, *identifiers)
                    functions += struct.pack(
                        "<8H", 42, function, 1, frame_id, 0, 0, 0, 0
                    )
                functions = bytearray(
                    b"".join(
                        sorted(
                            (
                                bytes(functions[at : at + 16])
                                for at in range(0, len(functions), 16)
                            ),
                            key=lambda row: (
                                struct.unpack_from("<H", row, 0)[0],
                                struct.unpack_from("<H", row, 2)[0],
                                struct.unpack_from("<H", row, 10)[0],
                            ),
                        )
                    )
                )
                settings = bytearray(management.sections[29].payload)
                for at in range(0, len(settings), 16):
                    struct.pack_into("<I", settings, at + 4, 100)
                sections = {
                    **management.sections,
                    0: Section(0, 0, len(index) // 6, False, bytes(index + pool)),
                    13: Section(13, 0, 1, False, bytes(protocol)),
                    14: Section(14, 0, 1, False, bytes(can)),
                    16: Section(16, 0, 1, False, bytes(category)),
                    17: Section(17, 0, len(frames) // 8, False, bytes(frames)),
                    18: Section(18, 0, len(functions) // 16, False, bytes(functions)),
                    29: replace(management.sections[29], payload=bytes(settings)),
                }
                payload = bytearray(
                    database(
                        1,
                        {
                            slot: (row.count, row.payload)
                            for slot, row in sections.items()
                        },
                    )
                )
                struct.pack_into(
                    "<I", payload, 28, 0x0100030C if build == 12 else 0x0100032F
                )
                selected.catalog.management = parse_database(bytes(payload))
                if overflow:
                    overflow_rows = bytearray(32768 * 64)
                    for index in range(32768):
                        struct.pack_into("<H", overflow_rows, index * 64 + 36, index)
                    selected = replace(
                        selected,
                        database=replace(
                            selected.database,
                            sections={
                                **selected.database.sections,
                                62: Section(62, 0, 32768, False, bytes(overflow_rows)),
                            },
                        ),
                    )
                payload = bytearray(
                    database(
                        2,
                        {
                            slot: (row.count, row.payload)
                            for slot, row in selected.database.sections.items()
                        },
                    )
                )
                struct.pack_into(
                    "<I", payload, 28, 0x0100030C if build == 12 else 0x0100032F
                )
                selected = replace(
                    selected,
                    category_record=bytes(category),
                    database=parse_database(bytes(payload)),
                )

                class Backend:
                    def __init__(self):
                        self.request = b""
                        self.writes = []

                    def invoke(self, operation, fields, *, deadline, cancelled):
                        if operation == "connect":
                            return J2534Result(handle=41)
                        if operation == "start_message_filter":
                            return J2534Result(handle=102)
                        if operation == "write_messages":
                            self.request = fields["messages"][0].data[4:]
                            self.writes.append(self.request)
                            return J2534Result(count=1)
                        if operation == "read_messages":
                            if fields["timeout"] == 0:
                                return J2534Result(code=9)
                            reply = (
                                bytes.fromhex("5001")
                                if self.request == b"\x10\x01"
                                else bytes.fromhex("62000000")
                            )
                            return J2534Result(
                                count=1,
                                messages=(
                                    NativeMessage(
                                        6, 0, 0, 0, 0, bytes.fromhex("000007e8") + reply
                                    ),
                                ),
                            )
                        return J2534Result()

                backend = Backend()
                communication = NativeCommunication.from_backend(
                    selected,
                    backend,
                    "authored-ecu",
                    first_request=bytes.fromhex("220000"),
                    driver=DriverProperties(0, b"04.04", "authored-version-reply"),
                    device_kind=8,
                    bus_id=0x12,
                    source_build=build,
                    clock=lambda: self.clock[0],
                )
                workflow = ToyotaWorkflows.from_communication(
                    communication,
                    observations=WorkflowObservations(
                        42, 0x12, {}, source_version=build
                    ),
                )
                if overflow:
                    with self.assertRaises(ToyotaCodecError) as raised:
                        workflow.active_test_monitors()
                    self.assertEqual(raised.exception.code, 0xA0030110)
                else:
                    actual = workflow.active_test_monitors()
                    self.assertEqual(actual["signals"], signals)
                self.assertEqual(backend.writes, [bytes.fromhex("220000")])
                communication.close()
        missing = bytearray(children[1])
        missing[9] = 0
        self.profile = replace(
            self.profile,
            database=replace(
                self.profile.database,
                sections={
                    **self.profile.database.sections,
                    26: Section(26, 0, 2, False, children[0] + bytes(missing)),
                    13: Section(13, 0, 0, False, b""),
                },
            ),
        )
        result = self.workflow(support_exchange=support).active_test_monitors()
        signals = result["signals"]
        assert isinstance(signals, list)
        self.assertEqual([item["signal_id"] for item in signals], [9])
        self.assertEqual(
            (
                signals[0]["multiplier"],
                signals[0]["divisor"],
                signals[0]["offset"],
                signals[0]["precision"],
            ),
            (1, 1, 0, 0),
        )
        self.assertEqual(signals[0]["native_defaults"], ["physical_empty_group"])

    def recording_document(self, events, operation="clear_dtc", arguments=None):
        return {
            "schema": "techstream-toyota-workflow-v1",
            "source": "authored_synthetic",
            "operation": operation,
            "arguments": {} if arguments is None else arguments,
            "context": {
                "ecu": "authored-ecu",
                "category": 42,
                "category_record": self.profile.category_record.hex(),
                "exceptions": list(self.profile.exception_ids),
                "database_sha256": self.profile.database.sha256,
                "management_sha256": self.profile.catalog.management.sha256,
                "native_id": 42,
                "bus_id": 7,
                "source_build": 18,
                "functions": [],
                "targets": [],
                "pid_positions": None,
                "mode_seed": None,
                "limits": {"seconds": 1, "exchanges": 32},
            },
            "events": events,
        }

    def test_production_authored_example_replays_without_tests_or_overwrite(self):
        directory = self.root / "production-demo"
        inputs = create_example_files(directory)
        profile = VehicleCatalog(directory).build_profile(42)
        report = replay_workflow(profile, directory / "workflow.json")
        self.assertEqual(inputs["category"], 42)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["event_count"], 1)
        self.assertEqual(report["source"], "authored_synthetic")
        with self.assertRaises(FileExistsError):
            create_example_files(directory)

    def test_workflow_recording_factory_literal_clear_and_selected_source_guard(self):
        event = {
            "operation": "exchange",
            "arguments": {"ecu": "authored-ecu", "request": "14aa"},
            "status": 0,
            "response": "54aa",
        }
        document = self.recording_document([event])
        path = self.root / "workflow.json"
        path.write_text(json.dumps(document))
        report = replay_workflow(self.profile, path)
        self.assertEqual(report["result"], {"native_status": 0, "native_clear_flag": 1})
        self.assertEqual(report["event_count"], 1)
        self.assertEqual(report["source"], "authored_synthetic")
        self.assertEqual(report["physical_status"], "PHYSICAL_UNCONFIRMED")
        failed_document = copy.deepcopy(document)
        failed_document["events"][0]["status"] = 0x91010009
        path.write_text(json.dumps(failed_document))
        failed = replay_workflow(self.profile, path)
        self.assertEqual(failed["status"], "failed")
        failed_error = failed["error"]
        assert isinstance(failed_error, dict)
        self.assertEqual(failed_error["native_code"], 0x90040501)
        self.assertEqual(failed["events_remaining"], 0)
        path.write_text(json.dumps(document))
        cancelled = replay_workflow(self.profile, path, cancelled=lambda: True)
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(cancelled["events_remaining"], 1)
        changed = copy.deepcopy(document)
        changed["context"]["management_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "different selected profile"):
            WorkflowRecording(self.profile, changed)
        changed = copy.deepcopy(document)
        changed["events"][0]["status"] = False
        with self.assertRaises(ValueError):
            WorkflowRecording(self.profile, changed)
        recording = WorkflowRecording(self.profile, document)
        with self.assertRaisesRegex(ValueError, "primitive mismatch"):
            recording.exchange("authored-ecu", b"\x14\xab")
        self.assertEqual(recording.position, 0)
        with self.assertRaisesRegex(ValueError, "unconsumed"):
            recording.assert_complete()
        path.write_text('{"schema":1,"schema":2}')
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            replay_workflow(self.profile, path)

    def test_workflow_recording_mixed_native_arguments_partial_reply_and_cleanup_cancel(
        self,
    ):
        frame = self.profile.frame_records(1)[0]
        query = SupportQuery(
            "authored-ecu", b"\x14\xaa", frame, (self.profile.database.sha256,)
        )
        selected = {
            "ecu": "authored-ecu",
            "request": "14aa",
            "function_record": frame.function_record.hex(),
            "communication_record": frame.communication_record.hex(),
            "settings_record": frame.settings_record.hex(),
        }
        old, new = bytes(range(16)), bytes(range(16, 32))
        events = [
            {
                "operation": "support",
                "arguments": selected,
                "status": 0,
                "response": "54aa",
            },
            {
                "operation": "send",
                "arguments": {**selected, "parameters": [4, 5, 6, 7]},
                "status": 0xA0040201,
                "response": "",
            },
            {
                "operation": "receive",
                "arguments": {**selected, "parameters": [255, 7, 0, 100]},
                "status": 0x91010009,
                "response": "53aa",
            },
            {
                "operation": "native_send",
                "arguments": {
                    "ecu": "authored-ecu",
                    "native_operation": "SendIntNoInit",
                    "arguments": [42, "12", 1, 4, 5, 6, 7],
                },
                "status": 0xA0040202,
                "response": "",
            },
            {
                "operation": "get_mode",
                "arguments": {"ecu": "authored-ecu"},
                "status": 0,
                "response": old.hex(),
            },
            {
                "operation": "set_mode",
                "arguments": {
                    "ecu": "authored-ecu",
                    "mode": new.hex(),
                    "cleanup": False,
                },
                "status": 0,
                "response": "",
            },
            {
                "operation": "set_mode",
                "arguments": {
                    "ecu": "authored-ecu",
                    "mode": old.hex(),
                    "cleanup": True,
                },
                "status": 0,
                "response": "",
            },
        ]
        stopped = [False]
        recording = WorkflowRecording(
            self.profile,
            self.recording_document(events),
            cancelled=lambda stopped=stopped: stopped[0],
        )
        with self.assertRaisesRegex(ValueError, "primitive mismatch"):
            recording.send(SupportSend(query, 4, 5, 6, 7))
        self.assertEqual(recording.support(query), b"\x54\xaa")
        self.assertEqual(recording.send(SupportSend(query, 4, 5, 6, 7)), 0xA0040201)
        self.assertEqual(
            recording.receive(SupportReceive(query, 255, 7)), (0x91010009, b"\x53\xaa")
        )
        self.assertEqual(
            recording.native_send(
                "authored-ecu",
                NativeFrameSend("SendIntNoInit", 42, b"\x12", 4, 5, 6, 7),
            ),
            0xA0040202,
        )
        self.assertEqual(recording.get_mode("authored-ecu"), old)
        recording.set_mode("authored-ecu", new)
        stopped[0] = True
        recording.cleanup_set_mode("authored-ecu", old)
        recording.assert_complete()

    def test_native_label_loader_rejects_unverified_module_without_guessing(self):
        path = self.root / "authored.dll"
        path.write_bytes(b"MZ" + b"\0" * 1024)
        with self.assertRaisesRegex(ValueError, "not a verified original"):
            load_psd_label(path)
        with self.assertRaises(ValueError):
            WorkflowLabel.authored("")

    def test_each_p5_self_describing_records_keep_first_duplicate_and_bounds(self):
        header = bytes.fromhex("5904010203ff")
        parsed = parse_each_p5_reply(
            header + bytes.fromhex("01031234012a1234012b1111001001223302abcd"),
            requested_number=1,
        )
        self.assertEqual(parsed["code"], 0x010203)
        self.assertEqual(
            parsed["records"],
            [
                {
                    "number": 1,
                    "kind": 1,
                    "index": -126,
                    "data_ids": [{"did": 0x1234, "data": "2a"}],
                    "complete": True,
                },
                {
                    "number": 16,
                    "kind": 16,
                    "index": -111,
                    "data_ids": [{"did": 0x2233, "data": "abcd"}],
                    "complete": True,
                },
            ],
        )
        zero = header + bytes.fromhex("01001234012a2233012b")
        self.assertEqual(parse_each_p5_reply(zero, requested_number=1)["status"], "ok")
        self.assertEqual(
            parse_each_p5_reply(zero, requested_number=255)["reason"],
            "zero_count_for_all_records_request",
        )
        malformed = parse_each_p5_reply(
            header + bytes.fromhex("01021234012a223302ff"), requested_number=1
        )
        self.assertEqual(malformed["status"], "partial")
        self.assertEqual(malformed["reason"], "data_id_value_truncated")
        self.assertEqual(malformed["unparsed_tail"], "223302ff")
        self.assertEqual(
            parse_each_p5_reply(header, requested_number=1),
            {"code": None, "records": [], "status": "empty"},
        )
        self.assertEqual(
            parse_each_p5_reply(header + bytes.fromhex("8000"), requested_number=1)[
                "reason"
            ],
            "native_ffd_type_unknown",
        )
        zero_id = parse_each_p5_reply(
            header + bytes.fromhex("0101000001ff"), requested_number=1
        )
        self.assertEqual(
            zero_id["records"],
            [{"number": 1, "kind": 1, "index": -126, "data_ids": [], "complete": True}],
        )
        with self.assertRaises(ValueError):
            parse_each_p5_reply(bytes(65536), requested_number=1)

    def test_multi_p4_actual_factory_both_source_builds(self):
        self.category_flags = 1
        self.frames = [
            (42, function, 0, 1, request, b"", b"")
            for function, request in (
                (0x11, bytes.fromhex("12000000")),
                (0x13, b"\x01\x00"),
                (0x67, b"\x10\x01"),
                (0x7F, b"\x3e"),
            )
        ]
        self.build()
        freeze, physical, unit = bytearray(84), bytearray(24), bytearray(12)
        struct.pack_into("<HH", freeze, 56, 9, 0)
        struct.pack_into("<H", freeze, 60, 7)
        struct.pack_into("<HH", freeze, 62, 0, 7)
        freeze[76], freeze[79] = 2, 2
        struct.pack_into("<IIIHH", physical, 0, 2, 1, 0, 7, 1)
        struct.pack_into("<HH", unit, 4, 1, 4)
        for build in (12, 18):
            for mode in ("normal", "masked", "cancel"):
                with self.subTest(build=build, mode=mode):
                    profile = copy.deepcopy(self.profile)
                    protocol, can = bytearray(28 if build == 18 else 24), bytearray(28)
                    struct.pack_into(
                        "<6H", protocol, 0, 42, 1, 0x33, 0x7DF, 0x7E0, 0xAB
                    )
                    protocol[24 if build == 18 else 22] = 0x12
                    struct.pack_into("<IIHHH", can, 0, 0x1234, 500000, 1, 0, 20)
                    struct.pack_into("<H", can, 18 if build == 18 else 16, 9)
                    management = profile.catalog.management
                    settings = bytearray(management.sections[29].payload)
                    for at in range(0, len(settings), 16):
                        struct.pack_into("<I", settings, at + 4, 100)
                    sections = {
                        **management.sections,
                        13: Section(13, 0, 1, False, bytes(protocol)),
                        14: Section(14, 0, 1, False, bytes(can)),
                        29: replace(management.sections[29], payload=bytes(settings)),
                    }
                    payload = bytearray(
                        database(
                            1,
                            {
                                slot: (row.count, row.payload)
                                for slot, row in sections.items()
                            },
                        )
                    )
                    struct.pack_into(
                        "<I", payload, 28, 0x0100030C if build == 12 else 0x0100032F
                    )
                    profile.catalog.management = parse_database(bytes(payload))
                    payload = bytearray(
                        database(
                            2,
                            {
                                10: (1, bytes(freeze)),
                                13: (1, bytes(physical)),
                                14: (0, b""),
                                15: (1, bytes(unit)),
                            },
                        )
                    )
                    struct.pack_into(
                        "<I", payload, 28, 0x0100030C if build == 12 else 0x0100032F
                    )
                    profile = replace(profile, database=parse_database(bytes(payload)))
                    stopped = [False]

                    class Backend:
                        def __init__(self, mode=mode, stopped=stopped):
                            self.mode = mode
                            self.stopped = stopped
                            self.request = b""
                            self.writes = []
                            self.reads = 0

                        def invoke(self, operation, fields, *, deadline, cancelled):
                            if operation == "connect":
                                return J2534Result(handle=41)
                            if operation == "start_message_filter":
                                return J2534Result(handle=102)
                            if operation == "write_messages":
                                self.request = fields["messages"][0].data[4:]
                                self.writes.append(self.request)
                                self.reads = 0
                                return J2534Result(count=1)
                            if operation == "read_messages":
                                if fields["timeout"] == 0:
                                    return J2534Result(code=9)
                                self.reads += 1
                                if self.request == b"\x10\x01":
                                    reply = bytes.fromhex("5001")
                                elif self.request == b"\x01\x00":
                                    if self.reads > 1:
                                        return J2534Result(code=9)
                                    reply = bytes.fromhex("4100020101")
                                else:
                                    if self.request[1] == 0xF3:
                                        if self.mode == "masked":
                                            return J2534Result(code=9)
                                        if self.mode == "cancel":
                                            self.stopped[0] = True
                                    reply = bytes.fromhex("5200050000")
                                return J2534Result(
                                    count=1,
                                    messages=(
                                        NativeMessage(
                                            6,
                                            0,
                                            0,
                                            0,
                                            0,
                                            bytes.fromhex("000007e8") + reply,
                                        ),
                                    ),
                                )
                            return J2534Result()

                    backend = Backend()
                    communication = NativeCommunication.from_backend(
                        profile,
                        backend,
                        "authored-ecu",
                        first_request=bytes.fromhex("12000000"),
                        driver=DriverProperties(0, b"04.04", "authored-version-reply"),
                        device_kind=8,
                        bus_id=0x12,
                        source_build=build,
                        cancelled=lambda stopped=stopped: stopped[0],
                        clock=lambda: self.clock[0],
                    )
                    observed = WorkflowObservations(
                        42,
                        0x12,
                        {(1, 6, 4): 2, (1, 6, 5): 0xE0, (1, 6, 6): 0x10},
                        source_version=build,
                    )
                    workflow = ToyotaWorkflows.from_communication(
                        communication,
                        observations=observed,
                        cancelled=lambda stopped=stopped: stopped[0],
                    )
                    if mode == "cancel":
                        with self.assertRaises(Cancelled):
                            workflow.multi_freeze_p4([9], 3)
                    else:
                        result = workflow.multi_freeze_p4([9], 3)
                        signals = result["signals"]
                        assert isinstance(signals, list)
                        samples = signals[0]["samples"]
                        self.assertEqual(
                            [row["frame_number"] for row in samples],
                            [0xE3, 3, 0x13]
                            if mode == "masked"
                            else [0xE3, 0xF3, 3, 0x13],
                        )
                        self.assertEqual(
                            [row["native_index"] for row in samples],
                            [-2, 0, 1] if mode == "masked" else [-2, -1, 0, 1],
                        )
                        self.assertTrue(
                            all(
                                row["raw"] == 5 and row["value"] == 10
                                for row in samples
                            )
                        )
                    data_requests = [
                        request for request in backend.writes if request[0] == 0x12
                    ]
                    self.assertEqual(
                        [request[1] for request in data_requests],
                        [0xE3, 0xF3] if mode == "cancel" else [0xE3, 0xF3, 3, 0x13],
                    )
                    self.assertEqual(backend.writes.count(b"\x01\x00"), 1)
                    self.assertNotIn(b"", backend.writes)
                    stopped[0] = False
                    communication.close()

    def test_multi_p4_selected_metadata_ascending_filter_and_masked_fault(self):
        self.frames += [(42, 0x11, 0, 1, bytes.fromhex("12000000"), b"", b"")]
        self.build()
        freeze, physical, unit = bytearray(84), bytearray(24), bytearray(12)
        struct.pack_into("<I", freeze, 48, 1)
        struct.pack_into("<HHHH", freeze, 56, 9, 0, 7, 0)
        struct.pack_into("<HH", freeze, 62, 0, 7)
        freeze[76], freeze[79] = 2, 2
        struct.pack_into("<IIIHH", physical, 0, 2, 1, 0, 7, 1)
        struct.pack_into("<HH", unit, 4, 1, 4)
        self.profile = replace(
            self.profile,
            database=replace(
                self.profile.database,
                sections={
                    10: Section(10, 0, 1, False, bytes(freeze)),
                    13: Section(13, 0, 1, False, bytes(physical)),
                    14: Section(14, 0, 0, False, b""),
                    15: Section(15, 0, 1, False, bytes(unit)),
                },
            ),
        )
        text = "Authored signal\0".encode("utf-16le")
        self.profile.catalog.language = Language(
            parse_database(
                database(4, {0: (1, struct.pack("<IH", 0, len(text)) + text)})
            )
        )
        observed = WorkflowObservations(
            42,
            7,
            {(1, 6, 4): 2, (1, 6, 5): 0x10, (1, 6, 6): 0x20},
            pid_positions={2: b"\x01"},
        )

        def exchange(ecu, request):
            self.calls.append((ecu, request))
            if request[1] == 0x23:
                raise NativeStatus(0x91010009)
            return bytes.fromhex("5200050000")

        workflow = self.workflow(exchange, observations=observed)
        result = workflow.multi_freeze_p4([9], 3, frame_filter=bytes.fromhex("1323"))
        self.assertEqual(
            [request.hex() for _, request in self.calls], ["12130002", "12230002"]
        )
        self.assertEqual(result["native_start_index"], 1)
        self.assertEqual(result["native_end_index"], 2)
        signals = result["signals"]
        assert isinstance(signals, list)
        self.assertEqual(signals[0]["name"], "Authored signal")
        self.assertEqual(
            signals[0]["samples"],
            [
                {
                    "frame_number": 0x13,
                    "native_index": 1,
                    "raw": 5,
                    "value": 10,
                    "display": "10",
                    "kind": "numeric",
                    "status": "ok",
                }
            ],
        )
        self.calls.clear()
        circular = replace(
            observed, functions={(1, 6, 4): 2, (1, 6, 5): 0xE0, (1, 6, 6): 0x10}
        )
        circular_result = self.workflow(
            exchange, observations=circular
        ).multi_freeze_p4([9], 3)
        self.assertEqual(
            [request[1] for _, request in self.calls], [0xE3, 0xF3, 3, 0x13]
        )
        self.assertEqual(circular_result["native_start_index"], -2)
        self.assertEqual(circular_result["native_end_index"], 1)
        circular_signals = circular_result["signals"]
        assert isinstance(circular_signals, list)
        self.assertEqual(
            [sample["native_index"] for sample in circular_signals[0]["samples"]],
            [-2, -1, 0, 1],
        )
        self.calls.clear()
        self.assertEqual(
            workflow.multi_freeze_p4([], 3), {"native_status": 0, "signals": []}
        )
        self.assertFalse(self.calls)
        self.clock[0] = 30.0
        repeated = workflow.multi_freeze_p4([9], 3, frame_filter=b"\x13")
        self.assertEqual(repeated["status"], "ok")
        self.calls.clear()
        original = self.profile
        freeze[76] = 255
        self.profile = replace(
            original,
            database=replace(
                original.database,
                sections={
                    **original.database.sections,
                    10: Section(10, 0, 1, False, bytes(freeze)),
                },
            ),
        )
        unknown = self.workflow(exchange, observations=observed).multi_freeze_p4(
            [9], 3, frame_filter=b"\x13"
        )
        self.assertEqual(unknown["status"], "partial")
        unknown_signals = unknown["signals"]
        assert isinstance(unknown_signals, list)
        self.assertIsNone(unknown_signals[0]["samples"][0]["value"])
        self.profile = original
        stopped = [False]

        def stop_after_data(ecu, request):
            stopped[0] = True
            return exchange(ecu, request)

        self.calls.clear()
        with self.assertRaises(Cancelled):
            self.workflow(
                stop_after_data,
                observations=observed,
                cancelled=lambda stopped=stopped: stopped[0],
            ).multi_freeze_p4([9], 3)
        self.assertEqual(len(self.calls), 1)
        self.calls.clear()
        self.profile = replace(
            self.profile,
            database=replace(
                self.profile.database,
                sections={
                    **self.profile.database.sections,
                    15: Section(15, 0, 0, False, b""),
                },
            ),
        )
        with self.assertRaises(ToyotaCodecError) as missing:
            self.workflow(exchange, observations=observed).multi_freeze_p4([9], 3)
        self.assertEqual(missing.exception.code, 0xC0040101)
        self.assertFalse(self.calls)

        self.frames += [
            (42, 15, 0, 1, b"\x21\x00", b"", b""),
            (42, 0x13, 0, 1, b"\x13", b"", b""),
            (42, 0x6B, 0, 1, b"\x21\x00", b"", b""),
        ]
        self.category_flags = 4
        self.build()
        freeze[76] = 2
        lsb = bytearray(20)
        struct.pack_into("<IIHHH", lsb, 0, 3, 4, 9, 0, 7)
        lsb[17] = 1
        self.profile = replace(
            self.profile,
            database=replace(
                original.database,
                sections={
                    **original.database.sections,
                    3: Section(3, 0, 1, False, bytes.fromhex("0000000000010000")),
                    6: Section(6, 0, 1, False, bytes.fromhex("0000010100000000")),
                    39: Section(39, 0, 1, False, bytes(lsb)),
                },
            ),
        )
        self.profile.catalog.language = original.catalog.language
        events = []

        class Stream:
            def __init__(self):
                self.replies = iter(
                    ((0, bytes.fromhex("53000101ff")), (0x91010009, b""))
                )

            def send(self, call):
                events.append(("send", call.query.request))
                return 0

            def receive(self, call):
                events.append(("receive", call.query.request))
                return next(self.replies)

        def support(query):
            events.append(("support", query.request))
            return bytes.fromhex("610080" if query.request == b"\x21\0" else "610106")

        def data(ecu, request):
            events.append(("data", request))
            return exchange(ecu, request)

        lsb_result = self.workflow(
            data,
            observations=observed,
            support_stream=Stream(),
            support_exchange=support,
        ).multi_freeze_p4([9], 3, frame_filter=b"\x13")
        lsb_signals = lsb_result["signals"]
        assert isinstance(lsb_signals, list)
        self.assertEqual(lsb_signals[0]["samples"][0]["value"], 22)
        self.assertEqual(
            events,
            [
                ("send", b"\x13"),
                ("receive", b"\x13"),
                ("receive", b"\x13"),
                ("support", b"\x21\x00"),
                ("support", b"\x21\x01"),
                ("data", bytes.fromhex("12130002")),
            ],
        )


if __name__ == "__main__":
    unittest.main()
