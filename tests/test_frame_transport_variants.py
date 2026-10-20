"""Authored lower-class inputs and typed primitive transcripts; no driver loading."""

import struct
import unittest
from dataclasses import replace
from typing import Literal
from unittest.mock import patch

from test_frame_transport import DRIVER, DriverPrimitive, selected_profile

from scripts.diagnostic_db import Section
from scripts.frame_transport import (
    FrameTransportError,
    J2534Result,
    NativeMessage,
    get_comm_frame,
)
from scripts.frame_transport_variants import (
    EthernetOperations,
    EthernetResources,
    ExtendedCanOperations,
    Iso9141Operations,
    RawCanOperations,
    create_lower_transport,
    lower_frame_plan,
)
from scripts.profiles import ProtocolProfile


def ethernet_profile():
    profile = selected_profile(0x14)
    sections = dict(profile.catalog.management.sections)
    for slot, payload in (
        (85, struct.pack("<6H", 1, 1, 5000, 100, 9950, 5050)),
        (86, struct.pack("<6H", 1, 0xE80, 3000, 2000, 2000, 2000)),
    ):
        sections[slot] = Section(slot, 0, 1, False, payload)
    functions = bytearray(sections[18].payload)
    struct.pack_into("<H", functions, 2, 0x106)
    sections[18] = replace(sections[18], payload=bytes(functions[16:] + functions[:16]))
    catalog = object.__new__(type(profile.catalog))
    catalog.management = replace(profile.catalog.management, sections=sections)
    return replace(profile, catalog=catalog)


def ethernet_operations(backend=None, **options):
    backend = backend or EthernetPrimitive()
    transport = create_lower_transport(
        ethernet_profile(),
        b"\x22\xf1\x90",
        backend,
        native_build=18,
        bus_id=0x14,
        driver=DRIVER,
        device_kind=8,
        clock=backend.clock,
        wait=backend.wait,
        cancelled=backend.cancelled,
        **options,
    )
    assert isinstance(transport, EthernetOperations)
    return transport, backend


class EthernetPrimitive(DriverPrimitive):
    def __init__(self):
        discovery = bytes.fromhex("c0a80164345800000004") + bytes(36)
        super().__init__(
            [message(b"", status=0x10000), message(discovery, protocol=0x8205)]
        )
        self.voltages = [100, 6000, 10000]
        self.bytes_replies: list[bytes | J2534Result] = [
            b"\x02\xfd\x00\x06" + bytes(13)
        ]
        self.logical_handle = 20
        self.session_result = J2534Result(data=struct.pack("<I", 2))
        self.ethernet_failure: str | None = None
        self.boundary_operation: str | None = None
        self.boundary: (
            Literal[
                "cancelled_before",
                "cancelled_after",
                "deadline_before",
                "deadline_after",
            ]
            | None
        ) = None

    def invoke_ethernet(self, operation, fields, *, deadline, cancelled):
        self.calls.append((operation, fields, deadline))
        if operation == self.ethernet_failure:
            raise OSError("authored Ethernet failure")
        boundary = self.boundary if operation == self.boundary_operation else None
        if boundary and boundary.endswith("_before"):
            return J2534Result(host_boundary=boundary)
        if operation == "logical_connect":
            self.logical_handle += 1
            return J2534Result(handle=self.logical_handle, host_boundary=boundary)
        if operation == "physical_connect":
            return J2534Result(handle=7, host_boundary=boundary)
        if operation == "channel_ioctl" and fields["ioctl_id"] == 0x8023:
            return self.session_result
        if operation == "read_messages":
            value = self.replies.pop(0) if self.replies else J2534Result(code=9)
            return (
                value
                if isinstance(value, J2534Result)
                else J2534Result(count=1, messages=(value,), host_boundary=boundary)
            )
        if operation == "queue_messages":
            return J2534Result(count=1, host_boundary=boundary)
        if operation == "read_bytes":
            value = self.bytes_replies.pop(0)
            if isinstance(value, J2534Result):
                return value
            return J2534Result(count=len(value), data=value, host_boundary=boundary)
        if operation == "device_ioctl" and fields["ioctl_id"] == 3:
            return J2534Result(
                data=struct.pack("<I", self.voltages.pop(0)), host_boundary=boundary
            )
        return J2534Result(host_boundary=boundary)

    def response(self, payload, *, source=0x7E0, ack=True):
        if ack:
            self.bytes_replies.append(
                b"\x02\xfd\x80\x02" + bytes(4) + source.to_bytes(2, "big") + bytes(3)
            )
        body = source.to_bytes(2, "big") + b"\x0e\x80" + payload
        self.bytes_replies.append(b"\x02\xfd\x80\x01" + len(body).to_bytes(4, "big"))
        self.bytes_replies.extend(body[i : i + 4128] for i in range(0, len(body), 4128))


def operations(
    bus=0x18,
    *,
    version=18,
    device=8,
    interface_word=0,
    backend=None,
    init_flags=3,
    request=b"\x22\xf1\x90",
):
    backend = backend or DriverPrimitive()
    profile = selected_profile(bus, version=version, flags=0x81, init_flags=init_flags)
    instance = create_lower_transport(
        profile,
        request,
        backend,
        native_build=12 if version == 12 else 18,
        bus_id=bus,
        driver=DRIVER,
        device_kind=device,
        interface_word=interface_word,
        clock=backend.clock,
        wait=backend.wait,
        cancelled=backend.cancelled,
    )
    return instance, backend


def message(data, *, protocol=5, status=0):
    return NativeMessage(protocol, status, 0, 17, len(data), data)


class EthernetTests(unittest.TestCase):
    def test_rebind_rejoins_actual_selected_ethernet_and_software_records(self):
        transport, backend = ethernet_operations()
        self.assertEqual(transport.open(), 0)
        profile = ethernet_profile()
        sections = dict(profile.catalog.management.sections)
        protocol = bytearray(sections[13].payload)
        struct.pack_into("<H", protocol, 2, 3)
        sections[13] = replace(sections[13], payload=bytes(protocol))
        sections[85] = replace(
            sections[85], payload=struct.pack("<6H", 3, 4, 222, 333, 444, 555)
        )
        sections[86] = replace(
            sections[86], payload=struct.pack("<6H", 4, 0xE81, 777, 888, 999, 111)
        )
        catalog = object.__new__(type(profile.catalog))
        catalog.management = replace(profile.catalog.management, sections=sections)
        profile = replace(profile, catalog=catalog)
        plan = lower_frame_plan(
            profile, b"\x22", native_build=18, bus_id=0x14, driver=DRIVER, device_kind=8
        )
        count = len(backend.calls)
        transport.rebind(profile, plan, bus_id=0x14)
        self.assertEqual(len(backend.calls), count)
        self.assertEqual(transport.source_address, 0xE81)
        self.assertEqual(transport.ethernet_record, sections[85].payload)
        self.assertEqual(transport.software_record, sections[86].payload)
        self.assertEqual(transport._frame_message(b"\x22").data[8:10], b"\x0e\x81")
        self.assertEqual(transport.close(), 0)

    def test_native_virtual14c_preserves_status_and_actual_output_state(self):
        for result, expected in (
            (J2534Result(data=struct.pack("<I", 2)), (0, 2)),
            (J2534Result(code=6, data=struct.pack("<I", 7)), (0x91010006, 7)),
            (J2534Result(code=6), (0x91010006, 0)),
        ):
            transport, backend = ethernet_operations()
            self.assertEqual(transport.session_state(), (0, 0))
            self.assertEqual(backend.calls, [])
            self.assertEqual(transport.open(), 0)
            backend.session_result = result
            self.assertEqual(transport.session_state(), expected)
            self.assertEqual(backend.calls[-1][0], "channel_ioctl")
            self.assertEqual(
                dict(backend.calls[-1][1]),
                {
                    "channel_id": 23,
                    "ioctl_id": 0x8023,
                    "input": None,
                    "output_capacity": 4,
                },
            )
            self.assertEqual(transport.close(), 0)

    def test_missing_virtual14c_success_output_faults_owned_session(self):
        transport, backend = ethernet_operations()
        self.assertEqual(transport.open(), 0)
        backend.session_result = J2534Result()
        with self.assertRaises(OSError):
            transport.session_state()
        self.assertTrue(transport.poisoned)
        self.assertIsNone(transport.channel)
        self.assertEqual(transport.logical_channels, [])

    def test_virtual158_releases_channels_without_native_d1_exchange(self):
        transport, backend = ethernet_operations()
        self.assertEqual(transport.open(), 0)
        transport.preinit_d1_suppressed = 0
        with patch.object(
            transport,
            "pre_initialize",
            side_effect=AssertionError("virtual158 must not run D1"),
        ):
            self.assertEqual(transport.release_channels(), 0)
        releases = [
            (op, fields["channel_id"])
            for op, fields, _ in backend.calls
            if op in ("logical_disconnect", "physical_disconnect")
        ]
        self.assertEqual(
            releases,
            [
                ("logical_disconnect", 23),
                ("logical_disconnect", 22),
                ("logical_disconnect", 21),
                ("physical_disconnect", 7),
            ],
        )
        self.assertEqual(transport.preinit_d1_suppressed, 0)
        self.assertIsNone(transport.channel)

    def test_sc_operations_never_fall_through_to_ordinary_j2534_api(self):
        class SCOnly(EthernetPrimitive):
            def invoke(self, operation, fields, *, deadline, cancelled):
                raise AssertionError("SC native class must call its actual SC exports")

        transport, _ = ethernet_operations(SCOnly())
        self.assertEqual(transport.open(), 0)
        self.assertEqual(transport.close(), 0)

    def test_physical_connect_and_disconnect_host_boundaries(self):
        for operation in ("physical_connect", "physical_disconnect"):
            for boundary in (
                "cancelled_before",
                "cancelled_after",
                "deadline_before",
                "deadline_after",
            ):
                transport, backend = ethernet_operations()
                if operation == "physical_disconnect":
                    self.assertEqual(transport.open(), 0)
                backend.boundary_operation, backend.boundary = operation, boundary
                with self.assertRaises(
                    InterruptedError
                    if boundary.startswith("cancelled")
                    else TimeoutError
                ):
                    transport.open() if operation == "physical_connect" else transport.close()
                if operation == "physical_connect":
                    releases = [
                        op for op, _, _ in backend.calls if op == "physical_disconnect"
                    ]
                    self.assertEqual(len(releases), int(boundary.endswith("_after")))
                    self.assertIsNone(transport.channel)
                else:
                    self.assertEqual(
                        transport.channel, None if boundary.endswith("_after") else 7
                    )
                backend.boundary_operation = None
                self.assertEqual(transport.close(), 0)

    def test_failed_child_release_retains_parent_and_can_retry(self):
        class FailedRelease(EthernetPrimitive):
            failed = True

            def invoke_ethernet(self, operation, fields, *, deadline, cancelled):
                if operation == "logical_disconnect" and self.failed:
                    self.failed = False
                    return J2534Result(code=6)
                return super().invoke_ethernet(
                    operation, fields, deadline=deadline, cancelled=cancelled
                )

        transport, backend = ethernet_operations(FailedRelease())
        self.assertEqual(transport.open(), 0)
        self.assertEqual(transport.close(), 0x91010006)
        self.assertEqual(transport.logical_channels, [21, 22, 23])
        self.assertFalse(any(op == "physical_disconnect" for op, _, _ in backend.calls))
        self.assertEqual(transport.close(), 0)
        self.assertEqual(transport.logical_channels, [])

    def test_service_family_controls_native_target_response_and_init(self):
        transport, _ = ethernet_operations()
        transport.set_service_context(1)
        self.assertEqual(transport._frame_message(b"\x01").data[10:12], b"\x07\xdf")
        self.assertEqual(transport._response_address(), 0)
        transport.force_initialization = True
        self.assertFalse(transport._needs_initialize(9000))
        transport.set_service_context(0x22)
        self.assertEqual(transport._frame_message(b"\x22").data[10:12], b"\x07\xe0")
        self.assertTrue(transport._needs_initialize(0))

    def test_native_configuration_and_discovery_failures_retain_owned_handles(self):
        transport, backend = ethernet_operations()
        backend.replies[1] = message(bytes(45), protocol=0x8205)
        self.assertEqual(transport.open(), 0x91020306)
        self.assertEqual(transport.logical_channels, [21, 22])
        self.assertEqual(transport.close(), 0)
        self.assertIsNone(transport.channel)

    def test_unconfirmed_queue_and_byte_counts_fault_clean_resources(self):
        class MalformedCount(EthernetPrimitive):
            bad_operation = "queue_messages"

            def invoke_ethernet(self, operation, fields, *, deadline, cancelled):
                if operation == self.bad_operation:
                    if operation == "read_bytes":
                        return J2534Result(count=2, data=b"\0")
                    return J2534Result(count=0)
                return super().invoke_ethernet(
                    operation, fields, deadline=deadline, cancelled=cancelled
                )

        for operation in ("queue_messages", "read_bytes"):
            backend = MalformedCount()
            backend.bad_operation = "disabled"
            transport, _ = ethernet_operations(backend)
            self.assertEqual(transport.open(), 0)
            backend.bad_operation = operation
            with self.assertRaises(OSError):
                if operation == "queue_messages":
                    transport.send(b"\x22", timeout=1, initialization_mode=2)
                else:
                    transport.receive(maximum=32, timeout=1)
            self.assertIsNone(transport.channel)
            self.assertEqual(transport.logical_channels, [])

    def test_pending_time_and_cancellation_are_distinct_boundaries(self):
        transport, backend = ethernet_operations()
        self.assertEqual(transport.open(), 0)
        transport.last_send_tick = int(backend.now * 1000) - 180000
        backend.response(b"\x7f\x22\x78")
        self.assertEqual(transport.receive(maximum=32, timeout=1).code, 0x90020323)
        self.assertFalse(transport.poisoned)
        backend.boundary_operation, backend.boundary = "read_bytes", "deadline_after"
        backend.bytes_replies = [bytes(13)]
        with self.assertRaises(TimeoutError):
            transport.receive(maximum=32, timeout=1)
        self.assertTrue(transport.poisoned)
        self.assertIsNone(transport.channel)

    def test_packet_log_contains_only_application_bytes(self):
        transport, backend = ethernet_operations()
        records = []
        transport.set_packet_log(lambda value: records.append(value) or len(value))
        self.assertEqual(transport.open(), 0)
        self.assertEqual(records, [])
        self.assertEqual(
            transport.send(b"\x22\xf1\x90", timeout=1, initialization_mode=2), 0
        )
        backend.response(b"\x62\xf1\x90")
        self.assertEqual(transport.receive(maximum=32, timeout=1).code, 0)
        self.assertEqual(records, [b"22F190\\n", b"62F190\\n"])

    def test_d1_close_helper_only_after_native_function_send(self):
        transport, backend = ethernet_operations()
        self.assertEqual(transport.open(), 0)
        profile = transport.profile
        sections = dict(profile.catalog.management.sections)
        functions = sections[18].payload
        d1 = bytearray(functions[:16])
        struct.pack_into("<H", d1, 2, 0xD1)
        sections[18] = replace(
            sections[18], count=5, payload=functions[:-16] + d1 + functions[-16:]
        )
        catalog = object.__new__(type(profile.catalog))
        catalog.management = replace(profile.catalog.management, sections=sections)
        transport.profile = replace(profile, catalog=catalog)
        transport.last_activity = transport._tick()
        backend.response(b"\x50\x01")
        self.assertEqual(transport.send_function(0x106), 0)
        self.assertEqual(transport.preinit_d1_suppressed, 0)
        backend.response(b"\xc1")
        count = len([op for op, _, _ in backend.calls if op == "queue_messages"])
        self.assertEqual(transport.close(), 0)
        self.assertEqual(
            len([op for op, _, _ in backend.calls if op == "queue_messages"]), count + 1
        )

    def test_faulted_clock_still_releases_native_resources(self):
        transport, backend = ethernet_operations()
        self.assertEqual(transport.open(), 0)
        backend.now = float("nan")
        transport.poisoned = True
        self.assertEqual(transport.close(), 0)
        self.assertEqual(transport.logical_channels, [])
        self.assertIsNone(transport.channel)

    def test_source_selected_join_and_complete_open_close(self):
        transport, backend = ethernet_operations()
        self.assertIsInstance(transport, EthernetOperations)
        self.assertEqual(transport.open(), 0)
        physical = next(
            fields for op, fields, _ in backend.calls if op == "physical_connect"
        )
        self.assertEqual(
            dict(physical),
            {
                "protocol_id": 0x800F,
                "flags": 0,
                "baud_rate": 100000000,
                "resources": EthernetResources(1, (3, 11, 12, 13)),
            },
        )
        logical = [fields for op, fields, _ in backend.calls if op == "logical_connect"]
        self.assertEqual(
            [fields["protocol_id"] for fields in logical], [0x8203, 0x8205, 0x8206]
        )
        self.assertEqual(
            logical[0]["input"], b"\x01" + struct.pack("<I", 10000) + bytes(16)
        )
        self.assertEqual(logical[2]["input"], bytes.fromhex("00c05834c0a80164"))
        resources = [
            fields["input"]
            for op, fields, _ in backend.calls
            if op == "device_ioctl" and fields["ioctl_id"] == 3
        ]
        self.assertEqual(
            resources,
            [
                EthernetResources(1, (8,)),
                EthernetResources(1, (8,)),
                EthernetResources(1, (16,)),
            ],
        )
        self.assertEqual(
            transport.plan.send.data, bytes.fromhex("02fd8001000000070e8007e022f190")
        )
        self.assertEqual(transport.close(), 0)
        self.assertEqual(
            [
                fields["channel_id"]
                for op, fields, _ in backend.calls
                if op == "logical_disconnect"
            ],
            [23, 22, 21],
        )
        self.assertIsNone(transport.channel)
        count = len(backend.calls)
        self.assertEqual(transport.close(), 0)
        self.assertEqual(len(backend.calls), count)

    def test_native_voltage_failure_maps_to_session_error_before_connect(self):
        transport, backend = ethernet_operations()
        backend.voltages = [2000]
        self.assertEqual(transport.open(), 0x91020306)
        self.assertFalse(any(op == "physical_connect" for op, _, _ in backend.calls))

    def test_source_receive_ack_header_payload_and_large_chunks(self):
        for payload in (b"\x62\xf1\x90", b"\x62" + bytes(65534)):
            transport, backend = ethernet_operations()
            self.assertEqual(transport.open(), 0)
            self.assertEqual(
                transport.send(b"\x22", timeout=1, initialization_mode=2), 0
            )
            backend.response(payload)
            reply = transport.receive(maximum=65535, timeout=1)
            self.assertEqual(
                (reply.code, reply.source_id, reply.data), (0, 0x7E0, payload)
            )
            counts = [
                fields["count"] for op, fields, _ in backend.calls if op == "read_bytes"
            ]
            self.assertEqual(counts[:3], [17, 13, 8])
            self.assertTrue(all(count <= 4128 for count in counts))
            self.assertEqual(transport.close(), 0)

    def test_negative_pending_skips_next_ack_and_busy_requeues(self):
        transport, backend = ethernet_operations()
        self.assertEqual(transport.open(), 0)
        self.assertEqual(transport.send(b"\x22", timeout=1, initialization_mode=2), 0)
        backend.response(b"\x7f\x22\x78")
        backend.response(b"\x7f\x22\x21", ack=False)
        backend.response(b"\x62\xf1\x90")
        reply = transport.receive(maximum=32, timeout=1)
        self.assertEqual((reply.code, reply.data), (0, b"\x62\xf1\x90"))
        queues = [fields for op, fields, _ in backend.calls if op == "queue_messages"]
        self.assertEqual(queues[-1]["messages"], queues[-2]["messages"])
        reads = [
            (fields["count"], fields["timeout"])
            for op, fields, _ in backend.calls
            if op == "read_bytes"
        ]
        self.assertIn((8, 9950), reads)
        self.assertEqual([count for count, _ in reads], [17, 13, 8, 7, 8, 7, 13, 8, 7])

    def test_malformed_ack_header_counts_and_timeout_status(self):
        for reply, status in (
            (b"\0" * 12, 0x91020324),
            (b"\0" * 13, 0x81020000),
            (J2534Result(code=16), 0x91010009),
            (b"\x02\xfd\x80\x02" + bytes(9), 0x91020325),
        ):
            transport, backend = ethernet_operations()
            self.assertEqual(transport.open(), 0)
            backend.bytes_replies = [reply]
            self.assertEqual(transport.receive(maximum=16, timeout=1).code, status)

    def test_busy_retry_is_native_bounded(self):
        transport, backend = ethernet_operations()
        self.assertEqual(transport.open(), 0)
        self.assertEqual(transport.send(b"\x22", timeout=1, initialization_mode=2), 0)
        for _ in range(256):
            backend.response(b"\x7f\x22\x21")
        self.assertEqual(transport.receive(maximum=16, timeout=1).code, 0x90020323)
        self.assertEqual(
            len([op for op, _, _ in backend.calls if op == "queue_messages"]), 258
        )

    def test_init_request106_response_matches_service_and_send_bounds(self):
        transport, backend = ethernet_operations()
        self.assertEqual(transport.open(), 0)
        backend.response(b"\x50\x01")
        self.assertEqual(transport.send(None, timeout=1, initialization_mode=0), 0)
        self.assertEqual(transport.previous_payload, b"\x10\x01")
        self.assertEqual(
            transport.send(bytes(4117), timeout=1, initialization_mode=2), 0x91020310
        )

    def test_logical_connect_host_boundary_owns_only_actual_outcome(self):
        for boundary in (
            "cancelled_before",
            "cancelled_after",
            "deadline_before",
            "deadline_after",
        ):
            transport, backend = ethernet_operations()
            backend.boundary_operation = "logical_connect"
            backend.boundary = boundary
            with self.assertRaises(
                InterruptedError if boundary.startswith("cancelled") else TimeoutError
            ):
                transport.open()
            disconnected = [
                fields["channel_id"]
                for op, fields, _ in backend.calls
                if op == "logical_disconnect"
            ]
            self.assertEqual(disconnected, [21] if boundary.endswith("_after") else [])
            self.assertIsNone(transport.channel)
            self.assertEqual(transport.logical_channels, [])

    def test_cleanup_host_boundary_preserves_or_releases_actual_handle(self):
        for boundary in (
            "cancelled_before",
            "cancelled_after",
            "deadline_before",
            "deadline_after",
        ):
            transport, backend = ethernet_operations()
            self.assertEqual(transport.open(), 0)
            backend.boundary_operation = "logical_disconnect"
            backend.boundary = boundary
            with self.assertRaises(
                InterruptedError if boundary.startswith("cancelled") else TimeoutError
            ):
                transport.close()
            self.assertEqual(
                transport.logical_channels,
                [21, 22] if boundary.endswith("_after") else [21, 22, 23],
            )
            backend.boundary_operation = None
            self.assertEqual(transport.close(), 0)
            self.assertIsNone(transport.channel)

    def test_queue_fault_and_cancel_close_every_owned_channel(self):
        for boundary in (None, "cancelled_after"):
            transport, backend = ethernet_operations()
            self.assertEqual(transport.open(), 0)
            if boundary:
                backend.boundary_operation, backend.boundary = (
                    "queue_messages",
                    boundary,
                )
            else:
                backend.ethernet_failure = "queue_messages"
            with self.assertRaises(InterruptedError if boundary else OSError):
                transport.send(b"\x22", timeout=1, initialization_mode=2)
            self.assertTrue(transport.poisoned)
            self.assertEqual(transport.logical_channels, [])
            self.assertIsNone(transport.channel)


class VariantTests(unittest.TestCase):
    def test_management_only_profile_constructs_actual_owned_lower_variants(self):
        for version in (12, 18):
            for bus in (0x13, 0x18, 0x1C):
                selected = selected_profile(bus, version=version)
                profile = ProtocolProfile(selected.catalog, selected.category_record)
                self.assertFalse(hasattr(profile, "database"))
                backend = DriverPrimitive()
                transport = create_lower_transport(
                    profile,
                    b"",
                    backend,
                    native_build=version,
                    bus_id=bus,
                    driver=DRIVER,
                    device_kind=8,
                    clock=backend.clock,
                    wait=backend.wait,
                    cancelled=backend.cancelled,
                )
                self.assertIs(transport.profile, profile)
                self.assertEqual(backend.calls, [])
                self.assertEqual(transport.open(setup=False), 0)
                if bus == 0x1C:
                    self.assertEqual(
                        transport.send(None, timeout=1, initialization_mode=0), 0
                    )
                    self.assertFalse(
                        any(op == "write_messages" for op, _, _ in backend.calls)
                    )
                self.assertEqual(transport.close(), 0)
        selected = ethernet_profile()
        profile = ProtocolProfile(selected.catalog, selected.category_record)
        backend = EthernetPrimitive()
        transport = create_lower_transport(
            profile,
            b"",
            backend,
            native_build=18,
            bus_id=0x14,
            driver=DRIVER,
            device_kind=8,
            clock=backend.clock,
            wait=backend.wait,
            cancelled=backend.cancelled,
        )
        self.assertEqual(transport.open(), 0)
        self.assertIs(transport.profile, profile)
        self.assertFalse(hasattr(transport.profile, "database"))
        self.assertEqual(transport.close(), 0)

    def test_empty_native_constructor_seed_is_metadata_without_invented_request(self):
        for version in (12, 18):
            for bus, expected in (
                (0x13, bytes.fromhex("000007e0")),
                (0x18, bytes.fromhex("18dae0f100")),
                (0x1C, b"\x02"),
            ):
                transport, backend = operations(bus, version=version, request=b"")
                self.assertEqual(backend.calls, [])
                self.assertEqual(transport.plan.send.data, expected)
                transport.adopt_channel(7)
                self.assertEqual(
                    transport.send(None, timeout=1, initialization_mode=1), 0x90020701
                )
                self.assertEqual(backend.calls, [])
        plan = lower_frame_plan(
            ethernet_profile(),
            b"",
            native_build=18,
            bus_id=0x14,
            driver=DRIVER,
            device_kind=8,
        )
        self.assertEqual(plan.send.data, bytes.fromhex("02fd8001000000040e8007e0"))

    def test_null_mode0_iso_probe_uses_native_initialization_without_payload(self):
        transport, backend = operations(0x1C, request=b"")
        transport.adopt_channel(7)
        self.assertEqual(transport.send(None, timeout=1, initialization_mode=0), 0)
        self.assertEqual(
            [
                fields["ioctl_id"]
                for operation, fields, _ in backend.calls
                if operation == "ioctl"
            ],
            [8, 0x10005],
        )
        self.assertFalse(
            any(operation == "write_messages" for operation, _, _ in backend.calls)
        )

    def test_pure_get_comm_frame_export_still_rejects_empty_request(self):
        with self.assertRaises(FrameTransportError):
            get_comm_frame(selected_profile(0x12), b"", bus_id=0x12, driver=DRIVER)

    def test_low3_uses_native_raw_bytes_fixed_baud_and_one_filter(self):
        for version in (12, 18):
            transport, backend = operations(0x13, version=version)
            backend.config_failures = [6]
            self.assertEqual(transport.open(), 0)
            values = [(item.parameter, item.value) for item in transport.plan.configs]
            self.assertEqual(
                values,
                [(1, 500000)],  # Native translator omits these proprietary IDs.
            )
            filters = [
                fields
                for op, fields, _ in backend.calls
                if op == "start_message_filter"
            ]
            self.assertEqual(len(filters), 1)
            self.assertEqual(filters[0]["mask"].data, bytes.fromhex("00000760"))
            self.assertEqual(filters[0]["pattern"].data, bytes.fromhex("00000150"))
            self.assertEqual(transport.plan.startup_request, b"")
            self.assertEqual(transport.close(), 0)

    def test_build12_and18_direct_override_transcripts_match(self):
        for version in (12, 18):
            for bus in (0x18, 0x28, 0x38, 0x48):
                raw, _ = operations(bus, version=version)
                framed = raw._frame_message(b"\x22\xf1\x90")
                self.assertEqual(raw._decode_message(framed).data, b"\x22\xf1\x90")
            iso, backend = operations(0x1C, version=version)
            iso.adopt_channel(7)
            self.assertEqual(iso._initialize(100), 0)
            self.assertEqual(
                [
                    fields["ioctl_id"]
                    for op, fields, _ in backend.calls
                    if op == "ioctl"
                ],
                [8, 0x10005],
            )

    def test_low8_constructor_selection_both_builds(self):
        for version in (12, 18):
            for device, interface_word, protocol in (
                (2, 0, 5),
                (8, 0, 5),
                (8, 1, 6),
                (4, 0, 6),
            ):
                with self.subTest(
                    version=version, device=device, interface=interface_word
                ):
                    transport, backend = operations(
                        version=version, device=device, interface_word=interface_word
                    )
                    self.assertIsInstance(transport, ExtendedCanOperations)
                    self.assertEqual(transport.open(setup=False), 0)
                    fields = backend.calls[0][1]
                    self.assertEqual(
                        (fields["protocol_id"], fields["flags"]), (protocol, 0x100)
                    )
                    self.assertEqual(transport.plan.send.data[:4], b"\x18\xda\xe0\xf1")
                    self.assertEqual(transport._protocol_family(), 6)

    def test_export_still_rejects_low8(self):
        with self.assertRaises(FrameTransportError) as caught:
            get_comm_frame(selected_profile(0x18), b"\x22", bus_id=0x18, driver=DRIVER)
        self.assertEqual(caught.exception.status, 0x90020101)

    def test_extended_headers_are_not_ordinary_can(self):
        for bus, tat in ((0x18, 0xDA), (0x28, 0xCE), (0x38, 0xDB), (0x48, 0xCD)):
            raw, _ = operations(bus)
            frame = raw._frame_message(b"\x10\x01")
            self.assertEqual(frame.data[0:2], bytes((0x18, tat)))
            self.assertEqual(
                frame.data[4:], b"\x02\x10\x01" + (b"\0" if bus == 0x28 else b"")
            )
            self.assertEqual(frame.tx_flags, 0x100)
            wrapped, _ = operations(bus, interface_word=1)
            self.assertEqual(
                wrapped._frame_message(b"\x10\x01").data[4:],
                (b"\xab" if bus == 0x28 else b"") + b"\x10\x01",
            )
            self.assertEqual(wrapped.plan.send.tx_flags, 0x140)

    def test_extended_inverse_bounds_source_and_status(self):
        for interface, header in (
            (0, b"\x18\xda\xf1\x10\x03"),
            (1, b"\x18\xda\xf1\x10"),
        ):
            transport, _ = operations(interface_word=interface)
            response = message(header + b"\x62\xf1\x90")
            decoded = transport._decode_message(response, maximum=3)
            self.assertEqual(
                (decoded.data, decoded.source_id, decoded.timestamp),
                (b"\x62\xf1\x90", 0x10, 17),
            )
            self.assertEqual(
                transport._decode_message(response, maximum=2).code, 0x90020601
            )
            self.assertEqual(transport._decode_message(message(b"")).code, 0x90020601)
            self.assertFalse(
                transport._drop_message(replace(response, rx_status=0x100))
            )
            self.assertTrue(transport._drop_message(replace(response, rx_status=0x101)))
            for nrc, status in (
                (0x78, 0x90020323),
                (0x21, 0x90020326),
                (0x31, 0x90020321),
            ):
                self.assertEqual(
                    transport._validate_message(
                        message(header + bytes((0x7F, 0x22, nrc)))
                    ),
                    status,
                )

    def test_extended_filters_literal_addresses(self):
        transport, _ = operations()
        filters = transport._can_filters()
        self.assertEqual([item.filter_type for item in filters], [1, 3])
        self.assertEqual(filters[0].mask.data, bytes.fromhex("1fffff00"))
        self.assertEqual(filters[0].pattern.data, bytes.fromhex("18daf100"))
        self.assertEqual(filters[1].mask.data, bytes.fromhex("00ffffff"))
        self.assertEqual(filters[1].pattern.data, bytes.fromhex("18daf7e0"))
        self.assertEqual(filters[1].flow_control.data, bytes.fromhex("18dfe0f1"))
        self.assertTrue(all(item.mask.protocol_id == 5 for item in filters))

    def test_functional_extended_filters(self):
        transport, _ = operations(0x38, device=4)
        filters = transport._can_filters()
        self.assertEqual(len(filters), 17)
        transport, _ = operations(0x38, device=8)
        self.assertEqual(len(transport._can_filters()), 1)

    def test_low3_bypasses_negative_validator(self):
        backend = DriverPrimitive(
            [
                message(b"\0\0\x07\xe8\x7f\x22\x78", status=1),
                message(b"\0\0\x07\xe8\x7f\x22\x78"),
            ]
        )
        transport, _ = operations(0x13, backend=backend)
        self.assertIsInstance(transport, RawCanOperations)
        self.assertEqual(transport.open(setup=False), 0)
        result = transport.receive(maximum=3, timeout=100)
        self.assertEqual((result.code, result.data), (0, b"\x7f\x22\x78"))
        self.assertEqual(transport.plan.connect.protocol_id, 5)
        self.assertEqual(
            len([call for call in backend.calls if call[0] == "read_messages"]), 2
        )

    def test_low3_timeout_and_invalid_arguments(self):
        transport, _ = operations(0x13)
        self.assertEqual(transport.receive(maximum=4, timeout=1).code, 0x90020701)
        transport.adopt_channel(7)
        self.assertEqual(transport.receive(maximum=4, timeout=1).code, 0x91010009)
        with self.assertRaises(ValueError):
            transport.receive(maximum=-1, timeout=1)

    def test_lowC_connect_header_decode_validate(self):
        transport, backend = operations(0x1C)
        self.assertIsInstance(transport, Iso9141Operations)
        self.assertEqual(transport.open(), 0)
        self.assertEqual(backend.calls[0][1]["protocol_id"], 0x1000D)
        frame = transport._frame_message(b"\x22\xf1\x90")
        self.assertEqual((frame.protocol_id, frame.data), (3, b"\x05\x22\xf1\x90"))
        self.assertEqual(transport._validate_message(frame), 0)
        self.assertEqual(
            transport._validate_message(message(b"\x06\x22\xf1\x90")), 0x91020324
        )
        self.assertEqual(
            transport._decode_message(frame, maximum=3).data, b"\x22\xf1\x90"
        )
        self.assertEqual(transport._decode_message(frame, maximum=2).code, 0x90020601)
        configs = backend.calls[1][1]["input"]
        self.assertEqual(
            [(item.parameter, item.value) for item in configs][-1], (0x1000A, 0)
        )
        self.assertIn(25, [item.parameter for item in configs])

    def test_lowC_init_modes_select_proprietary_ioctls(self):
        for modes, expected in ((1, 0x10005), (2, 0x10004), (3, 0x10005), (0, None)):
            transport, backend = operations(0x1C, init_flags=modes)
            transport.adopt_channel(7)
            code = transport._initialize(100)
            ioctls = [call[1]["ioctl_id"] for call in backend.calls]
            self.assertEqual(ioctls, [8, expected] if expected else [])
            self.assertEqual(code, 0 if expected else 0x90020304)

    def test_lowC_wakeup_checks_service67(self):
        for response, expected in ((b"\x03\x67", 0), (b"\x03\x68", 0x90020328)):
            backend = DriverPrimitive([message(response, protocol=3)])
            transport, _ = operations(0x1C, backend=backend)
            transport.adopt_channel(7)
            self.assertEqual(transport.prepare_bus_session(), expected)
            outgoing = next(
                call[1]["messages"][0]
                for call in backend.calls
                if call[0] == "write_messages"
            )
            self.assertEqual(outgoing.data, b"\x03\xe0")

    def test_raw_high20_native_extra_count_byte_round_trip(self):
        transport, _ = operations(0x28)
        outgoing = transport._frame_message(b"\x22\xf1\x90")
        self.assertEqual(outgoing.data, b"\x18\xce\xe0\xf1\x03\x22\xf1\x90\0")
        self.assertEqual(transport._decode_message(outgoing).data, b"\x22\xf1\x90")
        self.assertEqual(transport.plan.send.data, outgoing.data)

    def test_raw_setup_does_not_retry_or_strip_last_config(self):
        backend = DriverPrimitive()
        backend.config_failures = [6]
        transport, _ = operations(backend=backend)
        self.assertEqual(transport.open(), 0x91010006)
        self.assertIsNone(transport.channel)
        self.assertEqual(len([call for call in backend.calls if call[0] == "ioctl"]), 1)

    def test_lowC_initialization_retry_status_and_delay(self):
        class InitFailures(DriverPrimitive):
            def invoke(self, operation, fields, *, deadline, cancelled):
                result = super().invoke(
                    operation, fields, deadline=deadline, cancelled=cancelled
                )
                if operation == "ioctl" and fields["ioctl_id"] in (0x10004, 0x10005):
                    return J2534Result(code=7)
                return result

        for mode, delay in ((1, 1.2), (2, 0)):
            backend = InitFailures()
            transport, _ = operations(0x1C, backend=backend, init_flags=mode)
            transport.adopt_channel(7)
            self.assertEqual(transport._initialize(100), 0x91010009)
            self.assertAlmostEqual(backend.now, 10 + delay)
            self.assertEqual(
                len([call for call in backend.calls if call[0] == "ioctl"]), 5
            )

    def test_low4_requires_explicit_primitive_backend_before_io(self):
        backend = DriverPrimitive()
        with self.assertRaises(TypeError):
            operations(0x14, backend=backend)
        self.assertEqual(backend.calls, [])

    def test_original12_has_no_low4_constructor(self):
        with self.assertRaises(FrameTransportError) as caught:
            operations(0x14, version=12)
        self.assertEqual(caught.exception.status, 0x90020201)

    def test_source_build_and_header_guards(self):
        with self.assertRaises(ValueError):
            lower_frame_plan(
                selected_profile(0x18, version=12),
                b"\x22",
                native_build=18,
                bus_id=0x18,
                driver=DRIVER,
                device_kind=8,
            )
        with self.assertRaises(FrameTransportError):
            operations(0x58)
        with self.assertRaises(ValueError):
            operations(interface_word=-1)

    def test_write_fault_and_cancel_clean_owned_channel(self):
        for option, exception in (
            ("fault_at", OSError),
            ("cancel_at", InterruptedError),
        ):
            backend = DriverPrimitive(**{option: 2})
            transport, _ = operations(backend=backend)
            transport.open(setup=False)
            with self.assertRaises(exception):
                transport.send(b"\x22", timeout=1, initialization_mode=2, clear_rx=0)
            self.assertIsNone(transport.channel)
            self.assertTrue(transport.poisoned)
            self.assertIn("disconnect", [call[0] for call in backend.calls])

    def test_delegates_existing_low6_and_low9(self):
        for bus, protocol in ((0x16, 2), (0x19, 4)):
            transport, _ = operations(bus)
            self.assertEqual(transport.plan.send.protocol_id, protocol)


if __name__ == "__main__":
    unittest.main()
