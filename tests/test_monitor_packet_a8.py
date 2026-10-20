"""Authored flag9 CAN sources and literal primitive observations only."""

import struct
import unittest
from collections.abc import Mapping
from dataclasses import replace
from itertools import product
from typing import Any, Literal, cast

from scripts.data_monitor import MonitorError, selected_p4_connection
from scripts.diagnostic_db import Database, Language, Section
from scripts.frame_transport import (
    DriverProperties,
    FrameTransportError,
    J2534Result,
    NativeFrameOperations,
    NativeMessage,
    get_comm_frame,
)
from scripts.frame_transport_variants import create_lower_transport
from scripts.monitor_packet_a8 import (
    PacketA8Event,
    pack_packet_a8,
    packet_a8_can_lifecycle,
    packet_a8_commands,
    run_packet_a8_dmci,
    selected_packet_a8_from_cache,
    selected_packet_a8_from_exchange,
    selected_packet_a8_monitor,
    selected_packet_a8_worker,
)
from scripts.monitor_poll import NormalPollingWorker
from scripts.monitor_support import Limits, MonitorSupportCache, PacketFrameCache
from scripts.profiles import VehicleCatalog, VehicleProfile
from scripts.toyota import ToyotaCodecError
from scripts.toyota_session import Cancelled, SessionError


def profile(build: Literal[12, 18] = 18, bus: int = 0x12) -> VehicleProfile:
    category = bytearray(76)
    struct.pack_into("<H", category, 68, 42)
    category[72] = 9
    prot = bytearray(24 if build == 12 else 28)
    struct.pack_into(
        "<6H", prot, 0, 42, 1, 0x33, 0x7DF, 0x10 if bus == 0x18 else 0x7E0, 0xAB
    )
    struct.pack_into("<HHH", prot, 14, 8, 8, 100)
    prot[22 if build == 12 else 24] = bus
    can = bytearray(28)
    struct.pack_into("<IIHHH", can, 0, 0x1234, 500000, 1, 0, 20)
    struct.pack_into("<H", can, 16 if build == 12 else 18, 1)
    variables = struct.pack("<IHIHIH", 0, 2, 2, 1, 3, 2) + b"\x10\x01\x3e\x21\x00"
    functions = b"".join(
        struct.pack("<8H", 42, fn, 0, index, 0, 0, 0, 0)
        for fn, index in ((15, 3), (0x67, 1), (0x7F, 2))
    )
    frames = b"".join(struct.pack("<4H", i, i, 0, 0) for i in (1, 2, 3))
    sections = {
        slot: Section(slot, 0, count, False, data)
        for slot, count, data in (
            (0, 3, variables),
            (13, 1, bytes(prot)),
            (14, 1, bytes(can)),
            (16, 1, bytes(category)),
            (17, 3, frames),
            (18, 3, functions),
            (29, 1, bytes(16)),
        )
    }
    management = Database(
        1, 0x0100030C if build == 12 else 0x0100032F, f"authored-mgmt-{build}", sections
    )
    freeze = bytearray(84)
    struct.pack_into("<HHHHH", freeze, 56, 17, 0, 2, 0, 15)
    freeze[78:80] = bytes((1, 12))
    phy = struct.pack("<IIIH", 1, 4, 0, 2) + bytes(10)
    db = Database(
        2,
        management.version,
        f"authored-ecu-{build}",
        {
            slot: Section(slot, 0, count, False, data)
            for slot, count, data in (
                (6, 1, bytes((0, 0, 12, 0, 1, 2, 0, 0))),
                (10, 1, bytes(freeze)),
                (13, 1, phy),
                (14, 0, b""),
                (15, 0, b""),
            )
        },
    )
    catalog = object.__new__(VehicleCatalog)
    catalog.management = management
    catalog.language = Language(
        Database(
            4,
            management.version,
            "authored-language",
            {0: Section(0, 0, 0, False, b"")},
        )
    )
    return VehicleProfile(catalog, bytes(category), db)


def observed(*functions):
    return {
        key: key in functions for key in (22, 10, 8, 9, 12, 25, 11, 26, 29, 27, 28, 35)
    }


def selected(p, *, build=18, functions=(8,), support=None, maximum=8, frames=None):
    return selected_packet_a8_monitor(
        p,
        (17,),
        {12: 2} if support is None else support,
        observed(*functions),
        source_build=build,
        communication_protocol=0x12,
        interface_id=0x7E0,
        excluded=0,
        maximum_request=maximum,
        maximum_reply=8,
        cached_frames=frames,
    )


class PacketA8Tests(unittest.TestCase):
    def test_original_builds_selected_metadata_and_commands(self):
        for build in (12, 18):
            p = profile(build)
            plan = selected(p, build=build)
            self.assertEqual(plan.packing.family, "A8")
            self.assertEqual(plan.packing.setup_requests, (b"\xa1\x01\x0c\xff",))
            self.assertEqual(plan.frame_sizes, ((1, 2),))
            self.assertEqual(
                (
                    plan.signals[0].pid,
                    plan.signals[0].start_bit,
                    plan.signals[0].end_bit,
                ),
                (17, 0, 15),
            )
            self.assertEqual(
                plan.commands.setup[0].values,
                (42, 0x7E0, ((1, b"\x0c\xff"),), 2, (), 3000),
            )
            self.assertEqual(plan.source_build, build)

    def test_support_actual_ext_transaction(self):
        for build in (12, 18):
            p, calls = profile(build), []

            def exchange(query, calls=calls):
                calls.append(query)
                return b"\x61\x0cAB"

            result = selected_packet_a8_from_exchange(
                p,
                (17,),
                exchange,
                "authored-ecu",
                observed(8),
                source_build=build,
                communication_protocol=0x12,
                interface_id=0x7E0,
                excluded=0,
                maximum_request=8,
                maximum_reply=8,
                native_ecu=42,
            )
            self.assertEqual(result.packing.setup_requests, (b"\xa1\x01\x0c\xff",))
            self.assertEqual([q.request for q in calls], [b"\x21\x0c"])

    def test_existing_cache_retains_budget_and_query_cache(self):
        calls = []

        def exchange(query):
            calls.append(query.request)
            return b"\x61\x0cAB"

        cache = MonitorSupportCache(profile(), exchange, "ecu", clock=lambda: 1)
        initial_deadline = cache.deadline
        for _ in range(2):
            result = selected_packet_a8_from_cache(
                cache,
                (17,),
                observed(8),
                communication_protocol=0x12,
                interface_id=0x7E0,
                excluded=0,
                max_request=8,
                max_reply=8,
                native_ecu=42,
            )
            self.assertEqual(result.packing.family, "A8")
            self.assertEqual(cache.deadline, initial_deadline)
        self.assertEqual(calls, [b"\x21\x0c"])
        with self.assertRaises(MonitorError):
            selected_packet_a8_from_cache(
                cache,
                (17,),
                observed(8),
                communication_protocol=0x12,
                interface_id=0x7E0,
                excluded=0,
                max_request=8,
                max_reply=8,
                native_ecu=43,
            )
        self.assertEqual(calls, [b"\x21\x0c"])

    def test_mode2_source_packing_and_native_wrapper_rejection(self):
        p, attempts = pack_packet_a8(
            ((12, 2),),
            {12: 2},
            {12: (True, 2)},
            ((0x11, 2),),
            capabilities=2,
            excluded=0,
            maximum_request=8,
            maximum_reply=8,
        )
        self.assertEqual(
            (p.setup_requests, p.frame_sizes, attempts),
            ((b"\xa1\x04",), ((0x11, 2),), ((2, 0),)),
        )
        with self.assertRaises(MonitorError) as raised:
            packet_a8_commands(
                p,
                interface_id=1,
                buffer_468=42,
                standard_values=(),
                attribute_2_23=False,
            )
        self.assertEqual(raised.exception.code, 0xC005100D)

    def test_pair_datatype_attribute_and_native_fallback(self):
        for attr, expected in ((False, 1), (True, 6)):
            plan = selected_packet_a8_monitor(
                profile(),
                (17,),
                {12: 2},
                observed(12, *((35,) if attr else ())),
                source_build=18,
                communication_protocol=0x12,
                interface_id=0x7E0,
                excluded=0,
                maximum_request=8,
                maximum_reply=8,
                cached_frames=None,
            )
            self.assertEqual(plan.commands.setup[0].values[2], expected)
            self.assertEqual(plan.commands.setup[0].values[7], 0xFFFFFFFF)
        plan = selected(profile(), functions=(8, 12), maximum=3)
        self.assertEqual(plan.attempts, ((1, 0xA0050422), (0x20, 0)))

    def test_auxiliary_selected_join_then_literal_wrapper_descriptor(self):
        p = profile()
        original = p.database.sections[10]
        auxiliary = bytearray(original.payload)
        struct.pack_into("<H", auxiliary, 56, 18)
        struct.pack_into("<HH", auxiliary, 62, 0, 7)
        auxiliary[78:80] = bytes((8, 1))
        sections = dict(p.database.sections)
        sections[10] = Section(10, 0, 2, False, bytes(auxiliary) + original.payload)
        with self.assertRaises(MonitorError) as raised:
            selected_packet_a8_monitor(
                replace(p, database=replace(p.database, sections=sections)),
                (17, 18),
                {12: 2},
                observed(12),
                source_build=18,
                communication_protocol=0x12,
                interface_id=0x7E0,
                excluded=0,
                maximum_request=8,
                maximum_reply=8,
                cached_frames=None,
            )
        self.assertEqual(raised.exception.code, 0xA0030107)
        sections[19] = Section(19, 0, 1, False, struct.pack("<HHI", 18, 15, 0))
        result = selected_packet_a8_monitor(
            replace(p, database=replace(p.database, sections=sections)),
            (17, 18),
            {12: 2},
            observed(8, 12),
            source_build=18,
            communication_protocol=0x12,
            interface_id=0x7E0,
            excluded=0,
            maximum_request=8,
            maximum_reply=8,
            cached_frames=None,
        )
        self.assertEqual(result.packing.mode, 0x20)
        self.assertEqual(result.frame_sizes, ((0, 2), (1, 1)))
        self.assertEqual(result.commands.setup[0].values[3], ((0, 2),))
        rejected = replace(
            result.packing,
            setup_requests=result.packing.setup_requests[:-1] + (b"\x13\x00",),
        )
        with self.assertRaises(MonitorError) as raised:
            packet_a8_commands(
                rejected,
                interface_id=0x7E0,
                buffer_468=42,
                standard_values=(),
                attribute_2_23=False,
            )
        self.assertEqual(raised.exception.code, 0xC005100E)

    def test_packet_dmp4_exact_lengths_not_p3_sequence(self):
        event = PacketA8Event(b"\x0c\xff", ((1, 2),))
        self.assertEqual(event.get_snd_frame(1), b"\xa1\x01\x0c\xff")
        self.assertEqual(event.check_rcv_frame(b"\xe1\x01\x0c\xff", 1), 0xE0000100)
        self.assertEqual(event.get_snd_frame(2), b"\xa2\x01")
        for reply in (b"\xe2", b"\xe2\x11AB", b"\xe2\x01A", b"\xe2\x01ABC"):
            self.assertEqual(event.check_rcv_frame(reply, 3), 0xE0000104)
            self.assertEqual(event.packets, [])
        self.assertEqual(event.check_rcv_frame(b"\xe2\x01AB", 4), 0xE0000100)
        self.assertEqual(event.check_rcv_frame(b"\xe2\x06CDextra", 5), 0xE0000100)
        self.assertEqual([p.payload for p in event.packets], [b"AB", b"CD"])
        self.assertEqual(event.stop(), 0xE0000100)
        self.assertEqual(event.get_snd_frame(6), b"\xa3")
        self.assertEqual(event.check_rcv_frame(b"\xe3", 7), 0xE0000100)

    def test_packet_pickup_retains_raw_length(self):
        event = PacketA8Event(b"\x0c\xff", ((1, 4),), pickup_spans=((0, 16),))
        self.assertEqual(event.check_rcv_frame(b"\xe2\x01AB", 5), 0xE0000100)
        self.assertEqual(event.packets[0].payload, b"ABAB")
        event = PacketA8Event(b"\x0c\xff", ((1, 4),), pickup_spans=((0, 16),))
        self.assertEqual(event.check_rcv_frame(b"\xe2\x01\xab\xcd", 5), 0xE0000100)
        self.assertEqual(event.packets[0].payload, b"\xab\xcd\xab\xcd")
        event = PacketA8Event(b"\x0c\xff", ((1, 4),), pickup_spans=((0xFFFFFFFF, 16),))
        self.assertEqual(event.check_rcv_frame(b"\xe2\x01AB", 5), 0xE0000100)
        self.assertEqual(event.packets[0].payload, b"AB\x00\x00")

    def test_wrong_sources_and_malformed_inputs(self):
        p = profile()
        for kwargs in ({"source_build": 26}, {"communication_protocol": 0x11}):
            values = {
                "source_build": 18,
                "communication_protocol": 0x12,
                "interface_id": 1,
                "excluded": 0,
                "maximum_request": 8,
                "maximum_reply": 8,
                "cached_frames": None,
            }
            values.update(kwargs)
            with self.assertRaises(MonitorError):
                selected_packet_a8_monitor(p, (17,), {12: 2}, observed(8), **values)
        cat = bytearray(p.category_record)
        cat[72] = 4
        with self.assertRaises(MonitorError):
            selected(replace(p, category_record=bytes(cat)))
        with self.assertRaises(MonitorError):
            selected(p, support={12: -1})
        with self.assertRaises(Cancelled):
            selected_packet_a8_from_exchange(
                p,
                (17,),
                lambda q: b"",
                "ecu",
                observed(8),
                source_build=18,
                communication_protocol=0x12,
                interface_id=1,
                excluded=0,
                maximum_request=8,
                maximum_reply=8,
                native_ecu=42,
                cancelled=lambda: True,
            )

    def test_support_fault_and_foreign_packet_cache_fail_closed(self):
        p = profile()

        def exchange(query):
            raise ToyotaCodecError("Authored support failure", 0xC0040101)

        args: dict[str, Any] = {
            "source_build": 18,
            "communication_protocol": 0x12,
            "interface_id": 0x7E0,
            "excluded": 0,
            "maximum_request": 8,
            "maximum_reply": 8,
            "native_ecu": 42,
        }
        with self.assertRaises(ToyotaCodecError) as raised:
            selected_packet_a8_from_exchange(
                p, (17,), exchange, "ecu", observed(8), **args
            )
        self.assertEqual(raised.exception.code, 0xC0040101)

        class Primitive:
            def send(
                self, ecu, request, parameter4, parameter5, parameter6, parameter7
            ):
                raise AssertionError("Foreign cache reached transport")

            def receive(self, receive, /):
                raise AssertionError("Foreign cache reached transport")

            def interrupt(self, enabled):
                raise AssertionError("Foreign cache reached transport")

        cache = PacketFrameCache(
            Primitive(),
            source_identity=("other",),
            send_timer=1,
            receive_timer=1,
            retries=0,
        )
        with self.assertRaises(SessionError):
            selected_packet_a8_from_exchange(
                p,
                (17,),
                lambda q: b"\x61\x0cAB",
                "ecu",
                observed(10, 12),
                packet_cache=cache,
                **args,
            )

    def test_direct_typed_lower_original_builds_and_fault_cleanup(self):
        class Primitives:
            def __init__(self, failure=0, timestamp_us=1234):
                self.timestamp_us = timestamp_us
                self.protocol = 6
                self.calls = []
                self.request = b""
                self.failure = failure
                self.stopped_reads = 0

            def invoke(
                self,
                operation: str,
                fields: Mapping[str, object],
                *,
                deadline,
                cancelled,
            ):
                self.calls.append((operation, fields))
                if operation == "connect":
                    return J2534Result(handle=7)
                if operation == "start_message_filter":
                    return J2534Result(handle=100 + len(self.calls))
                if operation == "write_messages":
                    message = cast(tuple[NativeMessage, ...], fields["messages"])[0]
                    self.protocol = message.protocol_id
                    self.request = message.data[5 if self.protocol == 5 else 4 :]
                    return J2534Result(count=1)
                if operation == "read_messages":
                    if self.request == b"\x10\x01":
                        payload = b"\x50\x01"
                    elif self.request[0] == 0xA1:
                        payload = b"\xe1" + self.request[1:]
                    elif self.request[0] == 0x21:
                        if self.failure:
                            return J2534Result(code=self.failure)
                        payload = b"\x61\x0cAB"
                    elif self.request[0] == 0xA2:
                        if self.failure:
                            return J2534Result(code=self.failure)
                        payload = b"\xe2\x01AB"
                    else:
                        self.stopped_reads += 1
                        if self.stopped_reads > 1:
                            return J2534Result(code=9)
                        payload = b"\xe3"
                    return J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(
                                self.protocol,
                                0,
                                0,
                                self.timestamp_us,
                                0,
                                (
                                    b"\x18\xda\xf0\x10"
                                    if bus == 0x18
                                    else b"\x00\x00\x07\xe8"
                                )
                                + (
                                    bytes((len(payload),))
                                    if self.protocol == 5
                                    else b""
                                )
                                + payload,
                            ),
                        ),
                    )
                return J2534Result()

        routes = ((0x12, 0, (8,)), (0x12, 0, (12,)), (0x18, 0, (8,)), (0x18, 1, (8,)))
        for build, failure, route, timestamp_us in product(
            (12, 18), (0, 7), routes, (0, 999, 1000, 1234, 1234999)
        ):
            bus, interface_word, functions = route
            with self.subTest(
                build=build, failure=failure, route=route, timestamp_us=timestamp_us
            ):
                p = profile(build, bus)
                plan = selected_packet_a8_from_exchange(
                    p,
                    (17,),
                    lambda q: b"\x61\x0cAB",
                    "ecu",
                    observed(*functions),
                    source_build=build,
                    communication_protocol=bus,
                    interface_id=selected_p4_connection(
                        p,
                        bus_id=bus,
                        diagnostic_mode=bytes(16),
                        controller_category_flags=9,
                    ).address.request_id,
                    excluded=0,
                    maximum_request=8,
                    maximum_reply=8,
                    native_ecu=42,
                )
                connection = selected_p4_connection(
                    p,
                    bus_id=bus,
                    diagnostic_mode=bytes(16),
                    controller_category_flags=9,
                )
                driver = DriverProperties(0, b"04.04", "authored-driver")
                observed_calls = Primitives(failure, timestamp_us)
                operations = create_lower_transport(
                    p,
                    plan.packing.setup_requests[0],
                    observed_calls,
                    native_build=build,
                    bus_id=bus,
                    driver=driver,
                    device_kind=8,
                    interface_word=interface_word,
                    clock=lambda: 0,
                )
                if bus == 0x18:
                    with self.assertRaises(FrameTransportError) as rejected:
                        get_comm_frame(
                            p, plan.packing.setup_requests[0], bus_id=bus, driver=driver
                        )
                    self.assertEqual(rejected.exception.status, 0x90020101)
                    wrong_class = NativeFrameOperations(
                        p,
                        operations.plan,
                        observed_calls,
                        native_build=build,
                        bus_id=bus,
                        driver=driver,
                        device_kind=8,
                        clock=lambda: 0,
                    )
                    with self.assertRaisesRegex(
                        MonitorError, "extended CAN lower class"
                    ):
                        selected_packet_a8_worker(wrong_class, plan, connection)
                    self.assertEqual(observed_calls.calls, [])
                worker = (
                    selected_packet_a8_worker(
                        operations,
                        plan,
                        connection,
                        clock=lambda: 0,
                        limits=Limits(exchanges=100),
                    )
                    if functions == (8,)
                    else NormalPollingWorker(
                        operations, plan, connection, clock=lambda: 0, max_steps=100
                    )
                )
                if failure:
                    with self.assertRaises(MonitorError):
                        worker.run(1)
                else:
                    capture = worker.run(1)
                    self.assertEqual(
                        [(v.timestamp_ms, v.payload) for v in capture.packets],
                        # Runtime12 1ae0 /18 1d50 converts burst microseconds to ms.
                        [(timestamp_us // 1000 if functions == (8,) else 0, b"AB")],
                    )
                self.assertIsNone(operations.channel)
                self.assertEqual(observed_calls.calls[-1][0], "disconnect")

    def test_dmci_actual_bytes_packets_and_cleanup(self):
        from scripts.drive_recorder import (
            DMCI_WIRE_COMMANDS,
            NativeCoreBuffer,
            NativeDmciList,
            NativeMonitorReply,
            NativeVimClient,
            NativeVimReply,
            decode_vim_command,
        )

        for build, response_key in product((12, 18), (42, 0x7E0)):
            p = profile(build)
            plan = selected(p, build=build)
            connection = selected_p4_connection(
                p, bus_id=0x12, diagnostic_mode=bytes(16), controller_category_flags=9
            )
            self.assertEqual(
                packet_a8_can_lifecycle(
                    plan,
                    connection,
                    connected_device=8,
                    interrupt_send_timing=True,
                    recording=True,
                ),
                packet_a8_can_lifecycle(
                    plan, connection, connected_device=4, interrupt_send_timing=True
                ),
            )
            with self.assertRaises(MonitorError):
                packet_a8_can_lifecycle(
                    plan, connection, connected_device=8, interrupt_send_timing=True
                )
            calls = []

            def exchange(request, *, deadline, cancelled, calls=calls):
                wire, payload = decode_vim_command(request)
                calls.append(wire)
                if wire == DMCI_WIRE_COMMANDS[0x10D]:
                    self.assertEqual(payload, struct.pack("<HHII", 1, 0, 1, 42))
                    self.assertNotEqual(
                        connection.ecu_id, connection.address.request_id
                    )
                empty = NativeCoreBuffer((1, 0), b"")
                response = (
                    NativeMonitorReply(
                        0,
                        NativeDmciList(
                            (1, 0),
                            (
                                (
                                    response_key,
                                    NativeCoreBuffer(
                                        (1, 0), struct.pack("<I", 77) + b"AB"
                                    ),
                                ),
                            ),
                        ),
                        (empty, empty, empty, empty, empty),
                        0,
                    ).encode()
                    if wire == DMCI_WIRE_COMMANDS[0x10D]
                    else bytes(4)
                    + (
                        struct.pack("<I", 1)
                        if wire == DMCI_WIRE_COMMANDS[0x114]
                        else b""
                    )
                )
                return NativeVimReply(wire | 0x80, 6, response).encode()

            client = NativeVimClient(
                exchange,
                capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
            )

            def run():
                return run_packet_a8_dmci(
                    plan,
                    connection,
                    client,
                    connected_device=4,
                    interrupt_send_timing=True,
                    packet_limit=1,
                )

            if response_key == 42:
                packets = run()
                self.assertEqual(
                    [(p.timestamp_raw, p.payload) for p in packets], [(77, b"AB")]
                )
            else:
                with self.assertRaisesRegex(MonitorError, "Unexpected or duplicate"):
                    run()
            self.assertEqual(
                calls[-3:], [DMCI_WIRE_COMMANDS[k] for k in (0x10E, 0x108, 0x104)]
            )
            with self.assertRaises(MonitorError):
                packet_a8_can_lifecycle(
                    plan,
                    replace(
                        connection, protocol_record=bytes(24 if build == 18 else 28)
                    ),
                    connected_device=4,
                    interrupt_send_timing=False,
                )


if __name__ == "__main__":
    unittest.main()
