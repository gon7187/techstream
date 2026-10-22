"""Literal authored Dual wire/state vectors; no OEM binary/device is executed."""

import struct
import unittest
from dataclasses import replace
from types import SimpleNamespace
from typing import Literal, cast

from scripts.data_monitor import (
    DynamicSlot,
    DynamicSource,
    MonitorCommand,
    MonitorError,
    MonitorReceive,
    MonitorSetup,
    RoutineMonitor,
    p5_setup_commands,
    pack_dynamic_dids,
)
from scripts.drive_recorder import NativeDrsError, NativeMessage
from scripts.frame_transport import DriverProperties
from scripts.monitor_dual import (
    DualActiveEvent,
    DualControl,
    DualMonitorRuntime,
    DualPacket,
    DualRing,
    DualState,
    DualTarget,
    NativeDualControl,
    NativeDualPrimitives,
    NativeDualTransport,
    OscRead,
    OscSetup,
    osc_sampling_increment,
)
from scripts.profiles import ProtocolProfile, VehicleProfile
from scripts.toyota_session import Cancelled, NativeFrameSend


class Provider:
    def __init__(self, replies=(), statuses=()):
        self.replies = list(replies)
        self.statuses = list(statuses)
        self.sent = []
        self.receives = []

    def native_send(self, ecu: str, call: NativeFrameSend) -> int:
        self.sent.append((ecu, call.operation, call.arguments))
        return self.statuses.pop(0) if self.statuses else 0

    def send(self, ecu, request, *, timeout, protocol, initialize):
        raise AssertionError("Dual SendProc must use the literal seven-argument ABI")

    def receive(self, ecu, *, buffer, maximum, timeout, argument_5, flags):
        self.receives.append((ecu, buffer, maximum, timeout, argument_5, flags))
        if not self.replies:
            raise AssertionError("Unexpected native receive")
        return self.replies.pop(0)


class Tick:
    def __init__(self, start=100):
        self.value = start

    def __call__(self):
        self.value += 1
        return self.value


class Osc:
    def __init__(self, reads=(), codes=()):
        self.calls = []
        self.reads = list(reads)
        self.codes = list(codes)

    def command(self, command):
        self.calls.append((command, None))
        return self.codes.pop(0) if self.codes else 0

    def set_parameter(self, parameter, data):
        self.calls.append((parameter, data))
        return self.codes.pop(0) if self.codes else 0

    def read_buffer(self, maximum):
        self.calls.append(("read", maximum))
        return self.reads.pop(0) if self.reads else OscRead(b"", 0, 0)


def target(request=0x700, response=0x708, *, p5=False, **kwargs):
    return DualTarget(
        f"ecu-{request:x}", request, response, 2, 20 if p5 else 3, 99, 1, **kwargs
    )


def p4(request=0x700, ids=(0x10,), sizes=(2,), data_type=1):
    return MonitorSetup(
        (
            MonitorCommand(
                0x10A,
                (
                    99,
                    request,
                    data_type,
                    tuple(zip(ids, sizes)),
                    sum(sizes),
                    (),
                    3,
                    0xFFFFFFFF,
                ),
            ),
        ),
        (MonitorCommand(0x10C, ()),),
        (MonitorCommand(0x10E, ()),),
    )


def p5(request=0x700, ids=((0x1234, 2),), dtc=(), routines=()):
    return p5_setup_commands(
        interface_id=request,
        buffer_468=99,
        total_length=sum(size for _, size in ids),
        standard_values=(),
        data_ids=ids,
        dtc_requests=dtc,
        routines=routines,
        parameter_6=1,
    )


def reply(data, source=0x708, code=0):
    return MonitorReceive(bytes.fromhex(data), source, code)


def runtime(provider, targets=None, **kwargs):
    chosen = targets or (target(),)
    return DualMonitorRuntime(
        chosen,
        provider,
        tick_ms=kwargs.pop("tick_ms", Tick()),
        clock=kwargs.pop("clock", lambda: 0.0),
        native_send=provider.native_send,
        **kwargs,
    )


class DualMonitorTests(unittest.TestCase):
    def test_exact_cleanup_call_limit_allows_final_empty_check_without_extra_io(self):
        from unittest.mock import patch

        provider = Provider(statuses=(9, 9))
        monitor = runtime(provider, (target(p5=True),))
        monitor.configure(0x700, p5())
        monitor.active.p5_start(
            bytes.fromhex("000103"), bytes.fromhex("000100"), delay=0, kind=0
        )
        monitor.active.p5_start(
            bytes.fromhex("000203"), bytes.fromhex("000200"), delay=0, kind=0
        )
        monitor.start()
        with patch("scripts.monitor_dual.MAX_ITEMS", 2):
            monitor.stop()
        self.assertIsNone(monitor.cleanup_error)
        self.assertEqual(
            [x[2][1].hex() for x in provider.sent], ["2f000100", "2f000200"]
        )
        self.assertEqual([x.received.code for x in monitor.cleanup_failures], [9, 9])
        monitor.stop()
        self.assertEqual(len(provider.sent), 2)

    def test_cleanup_trace_budget_is_independent_and_osc_stop_still_executes(self):
        from unittest.mock import patch

        osc = Osc()
        setup = OscSetup(b"12345678", b"\x04abc", b"5678", b"9", b"\x04xyz")
        provider = Provider(
            tuple(
                reply(x)
                for x in (
                    "62 f1 86 01",
                    "50 01",
                    "50 03",
                    "6f 00 01 03",
                    "62 12 34 aa bb",
                    "6f 00 01 00",
                )
            )
        )
        monitor = runtime(
            provider,
            (target(p5=True),),
            osc_provider=osc,
            osc_setup=setup,
            command_cache={
                (0x700, 0xDD): bytes.fromhex("22f186"),
                (0x700, 0xD1): bytes.fromhex("1001"),
                (0x700, 0xD2): bytes.fromhex("1003"),
            },
        )
        monitor.configure(0x700, p5())
        monitor.active.p5_start(
            bytes.fromhex("000103"), bytes.fromhex("000100"), delay=0, kind=0
        )
        with patch("scripts.monitor_dual.MAX_BYTES", 20):
            self.assertEqual(monitor.run_packets()[0].payload, b"\xaa\xbb")
        self.assertIsNone(monitor.cleanup_error)
        self.assertEqual(
            sum(
                len(x.request) + len(x.received.data)
                for x in monitor.auxiliary_exchanges
            ),
            15,
        )
        self.assertEqual(
            [x.request for x in monitor.cleanup_exchanges], [bytes.fromhex("2f000100")]
        )
        self.assertEqual(
            [x[2][1].hex() for x in provider.sent],
            ["22f186", "1001", "1003", "2f000103", "221234", "2f000100"],
        )
        self.assertEqual(
            osc.calls[-5:],
            [(3, None), (11, None), (10, b"\x04xyz"), ("read", 0x1068), (1, None)],
        )

    def test_version12_no_init_byte_length_boundary_and_version18_ushort(self):
        for version, length in ((12, 255), (12, 256), (18, 256)):
            with self.subTest(version=version, length=length):
                chosen = replace(target(), protocol=0x22)
                provider = Provider(
                    tuple(
                        reply(x)
                        for x in (
                            ("70",)
                            if version == 12 and length == 256
                            else ("70 01", "61 10 aa", "70")
                        )
                    )
                )
                monitor = runtime(
                    provider, (chosen,), version=version, connected_device=4
                )
                monitor.configure(0x700, p4(sizes=(1,)))
                monitor.active.p4_start(b"\x99" * (length - 1))
                if version == 12 and length == 256:
                    with self.assertRaisesRegex(MonitorError, "BYTE length"):
                        monitor.run_packets()
                    self.assertEqual([x[2][1] for x in provider.sent], [b"\x30"])
                else:
                    self.assertEqual(monitor.run_packets()[0].payload, b"\xaa")
                    self.assertEqual(len(provider.sent[0][2][1]), length)

    def test_authored_ddb_selected_producer_to_dual_wire_and_native_ring(self):
        import tempfile
        from pathlib import Path

        from scripts.data_monitor import selected_p4_monitor
        from scripts.demo import create_demo
        from scripts.drive_recorder import NativeMonitorPacketReader
        from scripts.profiles import VehicleCatalog

        with tempfile.TemporaryDirectory() as tmp:
            root = create_demo(Path(tmp) / "authored")
            profile = VehicleCatalog(root / "Techstream_DB_NA").build_profile(1)
            category = bytearray(profile.category_record)
            category[72] = 4
            profile = replace(profile, category_record=bytes(category))
            observed = {
                key: False for key in (22, 10, 8, 9, 12, 25, 11, 26, 29, 27, 28, 35)
            }
            observed[12] = True
            selected = selected_p4_monitor(
                profile,
                (1,),
                {12: b"\xff\xff"},
                observed,
                interface_id=0x700,
                excluded=0,
                max_request=10,
                max_reply=10,
                standard_values=(),
            )
            calls = []
            provider = Provider((reply("61 0c aa bb"),))
            chosen = replace(target(), command_id=profile.category, entry_parameter=0)
            monitor = runtime(
                provider, (chosen,), driver_control=lambda call: calls.append(call) or 0
            )
            monitor.configure(0x700, selected.commands)
            packets = monitor.run_packets()
            self.assertEqual(provider.sent[0][2], (1, b"\x21\x0c", 2, 1000, 2, 0, 1))
            self.assertEqual(calls[1].arguments, (1, 2, 0, 3))
            reader = NativeMonitorPacketReader(selected.frame_sizes, phase=0)
            recovered = reader.feed(packets[0].native_bytes)
            reader.finish()
            self.assertEqual(recovered[0].payload, b"\xaa\xbb")
            self.assertEqual(recovered[0].timestamp_ms, packets[0].timestamp_raw)
            self.assertEqual(
                (selected.signals[0].name, selected.signals[0].unit),
                ("Engine speed", "rpm"),
            )

    def test_literal_p4_wire_seven_arguments_and_cycle_storage(self):
        provider = Provider((reply("61 10 aa bb"), reply("61 20 cc")))
        monitor = runtime(provider)
        monitor.configure(0x700, p4(ids=(0x10, 0x20), sizes=(2, 1)))
        packets = monitor.run_packets()
        self.assertEqual([x.payload for x in packets], [b"\xaa\xbb\xcc"])
        self.assertEqual(
            provider.sent,
            [
                ("ecu-700", "SendIntExtDualMon", (99, b"\x21\x10", 2, 1000, 2, 0, 1)),
                ("ecu-700", "SendIntExtDualMon", (99, b"\x21\x20", 2, 1000, 2, 0, 1)),
            ],
        )
        self.assertEqual(provider.receives, [("ecu-700", True, 4096, 200, 0, 100)] * 2)
        self.assertEqual(
            monitor.transitions,
            [
                DualState.SELECT,
                DualState.SEND,
                DualState.RECEIVE,
                DualState.SELECT,
                DualState.SEND,
                DualState.RECEIVE,
                DualState.SELECT,
                DualState.STOPPED,
            ],
        )
        self.assertEqual(
            packets[0].native_bytes[:4], packets[0].timestamp_raw.to_bytes(4, "little")
        )

    def test_native112_pickup_setup_reaches_p4_and_p5_ring_packets(self):
        import struct

        for phase5 in (False, True):
            with self.subTest(phase5=phase5):
                provider = Provider(
                    tuple(
                        reply(x)
                        for x in (
                            ("50 03", "62 12 34 aa bb") if phase5 else ("61 10 aa bb",)
                        )
                    )
                )
                monitor = runtime(
                    provider,
                    (target(p5=phase5),),
                    command_cache={(0x700, 0xDD): b"\x10\x03"} if phase5 else {},
                )
                setup = p5() if phase5 else p4()
                setup = replace(
                    setup,
                    setup=setup.setup
                    + (MonitorCommand(0x112, (0x700, struct.pack("<II", 0, 8))),),
                )
                monitor.configure(0x700, setup)
                self.assertEqual(monitor.run_packets()[0].payload, b"\xaa\xbb\xaa")

    def test_native112_rejects_wrong_target_truncation_and_outside_source(self):
        import struct

        for address, payload in (
            (0x701, struct.pack("<II", 0, 8)),
            (0x700, b"x"),
            (0x700, struct.pack("<II", 0x100000, 8)),
        ):
            with self.subTest(address=address, payload=payload):
                monitor = runtime(Provider())
                setup = p4()
                setup = replace(
                    setup,
                    setup=setup.setup + (MonitorCommand(0x112, (address, payload)),),
                )
                with self.assertRaises(MonitorError):
                    monitor.configure(0x700, setup)

    def test_p4_byte_ordinal_exact256_pairs_and_reject257_before_assignment(self):
        provider = Provider(
            tuple(
                MonitorReceive(bytes((0x61, pid, pid)), 0x708, 0) for pid in range(256)
            )
        )
        monitor = runtime(provider)
        monitor.configure(0x700, p4(ids=tuple(range(256)), sizes=(1,) * 256))
        self.assertEqual(monitor.run_packets()[0].payload, bytes(range(256)))
        self.assertEqual(len(provider.sent), 256)
        monitor = runtime(Provider())
        with self.assertRaisesRegex(MonitorError, "at most256 pairs"):
            monitor.configure(
                0x700, p4(ids=tuple(pid % 256 for pid in range(257)), sizes=(1,) * 257)
            )
        with self.assertRaisesRegex(MonitorError, "all target setups"):
            monitor.start()

    def test_target_rotation_only_after_complete_cycle_no_alignment(self):
        a, b = target(), target(0x701, 0x709)
        provider = Provider(
            (reply("61 10 11"), reply("61 20 22"), reply("61 30 33", 0x709))
        )
        ticks = iter((10, 25, 99))
        monitor = runtime(provider, (a, b), tick_ms=lambda: next(ticks))
        monitor.configure(a.request_id, p4(ids=(0x10, 0x20), sizes=(1, 1)))
        monitor.configure(b.request_id, p4(0x701, ids=(0x30,), sizes=(1,)))
        packets = monitor.run_packets()
        self.assertEqual(
            [(x.target_id, x.timestamp_raw, x.payload) for x in packets],
            [(0x700, 25, b"\x11\x22"), (0x701, 99, b"\x33")],
        )
        self.assertEqual(
            [x[0] for x in provider.sent], ["ecu-700", "ecu-700", "ecu-701"]
        )

    def test_unmatched_source_waits_without_resending(self):
        provider = Provider((reply("61 10 ff", 0x709), reply("61 10 5a")))
        monitor = runtime(provider)
        monitor.configure(0x700, p4(sizes=(1,)))
        self.assertEqual(monitor.run_packets()[0].payload, b"\x5a")
        self.assertEqual(len(provider.sent), 1)
        self.assertEqual(len(provider.receives), 2)

    def test_all_native_address_filter_branches(self):
        vectors = (
            (0x80000700, 0x1234500, 2, 0x345),
            (0xC0000700, 0x12345678, 8, 0x78),
            (0x700, 0x12345678, 2, 0x12345678),
            (0x700, 0x12345678, 3, 0x78),
        )
        for request, response, protocol, expected in vectors:
            with self.subTest(request=request, protocol=protocol):
                self.assertEqual(
                    replace(
                        target(),
                        request_id=request,
                        response_id=response,
                        protocol=protocol,
                    ).receive_id,
                    expected,
                )

    def test_literal_p5_mixed_did_dtc_routine(self):
        routine = RoutineMonitor(bytes.fromhex("31 03 12 34"), 2, (), (), ())
        provider = Provider(
            (
                reply("50 03"),
                reply("62 12 34 aa bb"),
                reply("59 02 ff 01 02 03 04 05 06 07 08"),
                reply("71 03 12 34 11 22"),
            )
        )
        monitor = runtime(
            provider, (target(p5=True),), command_cache={(0x700, 0xDD): b"\x10\x03"}
        )
        monitor.configure(
            0x700, p5(dtc=(bytes.fromhex("19 02 ff"),), routines=(routine,))
        )
        packet = monitor.run_packets()[0]
        self.assertEqual(packet.payload, bytes.fromhex("aa bb 00 02 11 22"))
        self.assertEqual(
            [x[2][1] for x in provider.sent],
            [
                bytes.fromhex(x)
                for x in ("10 03", "22 12 34", "19 02 ff", "31 03 12 34")
            ],
        )

    def test_idmap_third_field_does_not_schedule(self):
        provider = Provider((reply("61 10 11"), reply("61 10 22")))
        chosen = replace(target(), map_values=(1000, 0, 0))
        monitor = runtime(provider, (chosen,), tick_ms=Tick(0))
        monitor.configure(0x700, p4(sizes=(1,)))
        packets = monitor.run_packets(2)
        self.assertEqual([x.timestamp_raw for x in packets], [1, 2])

    def test_literal_retry_after_send_and_receive_faults(self):
        provider = Provider(
            (reply("", code=0x90020001), reply("61 10 5a")), statuses=(9, 0, 0)
        )
        monitor = runtime(provider, (replace(target(), retry_limit=3),))
        monitor.configure(0x700, p4(sizes=(1,)))
        self.assertEqual(monitor.run_packets()[0].payload, b"\x5a")
        self.assertEqual(len(provider.sent), 3)

    def test_p4_fault_mapping_transport_negative_and_parser(self):
        for data_type, wire, provider_code, expected in (
            (1, "", 7, 0xE0000108),
            (0, "", 7, 0xE0000102),
            (1, "7f 21 31", 0x90020321, 0xE000010E),
            (0, "7f 01 22", 0x90020323, 0xE0000102),
            (1, "62 10", 0, 0xE0000108),
        ):
            with self.subTest(data_type=data_type, provider_code=provider_code):
                provider = Provider((reply(wire, code=provider_code),))
                monitor = runtime(provider)
                monitor.configure(0x700, p4(sizes=(1,), data_type=data_type))
                with self.assertRaises(MonitorError) as failure:
                    monitor.run_packets()
                self.assertEqual(failure.exception.code, expected)
                self.assertIn(DualState.ERROR, monitor.transitions)
                self.assertEqual(monitor.state, DualState.STOPPED)
                self.assertEqual(
                    monitor.faults[-1].detail,
                    int(wire.split()[-1], 16)
                    if provider_code in (0x90020321, 0x90020323)
                    else 0,
                )

    def test_p5_three_fault_kinds_and_negative_codes(self):
        for kind in (0x22, 0x19, 0x31):
            for negative in (False, True):
                with self.subTest(kind=kind, negative=negative):
                    observed = 0x90020321 if negative else 7
                    provider = Provider(
                        (reply("50 03"), reply("7f 22 31", code=observed))
                    )
                    monitor = runtime(
                        provider,
                        (target(p5=True),),
                        command_cache={(0x700, 0xDD): b"\x10\x03"},
                    )
                    routine = RoutineMonitor(
                        bytes.fromhex("31 03 12 34"), 1, (), (), ()
                    )
                    setup = p5(
                        ids=((0x1234, 1),) if kind == 0x22 else (),
                        dtc=(b"\x19\x02",) if kind == 0x19 else (),
                        routines=(routine,) if kind == 0x31 else (),
                    )
                    monitor.configure(0x700, setup)
                    with self.assertRaises(MonitorError) as failure:
                        monitor.run_packets()
                    self.assertEqual(
                        failure.exception.code,
                        {0x22: 0xE0000301, 0x19: 0xE0000801, 0x31: 0xE0000509}[kind]
                        + negative,
                    )

    def test_connect_device_four_no_init_branch(self):
        provider = Provider((reply("61 10 01"),))
        chosen = replace(target(), protocol=0x22)
        monitor = runtime(provider, (chosen,), connected_device=4)
        monitor.configure(0x700, p4(sizes=(1,)))
        monitor.run_packets()
        self.assertEqual(provider.sent[0][1], "SendIntNoInitNoSession")
        self.assertEqual(provider.sent[0][2][4], 0x22)

    def test_missing_selected_p5_recovery_cache_fails_closed(self):
        monitor = runtime(Provider(), (target(p5=True),))
        monitor.configure(0x700, p5())
        with self.assertRaisesRegex(MonitorError, "lacks commandDD"):
            monitor.run_packets()
        self.assertEqual(monitor.state, DualState.STOPPED)

    def test_11a_clears_all_selected_slots_including_unused_ids_in_both_builds(self):
        for version in (12, 18):
            with self.subTest(version=version):
                provider = Provider(
                    tuple(
                        reply(x)
                        for x in (
                            "50 03 00 03",
                            "6c 03 f2 02",
                            "6c 03 f2 01",
                            "6c 03 f2 03",
                        )
                    )
                )
                monitor = runtime(
                    provider,
                    (target(p5=True),),
                    version=version,
                    command_cache={
                        (0x700, 0xDD): b"\x10\x03",
                        (0x700, 0xD4): bytes.fromhex("2c 03 00 00 99"),
                    },
                )
                selection = p5(ids=((0xF201, 2),))
                monitor.configure(
                    0x700,
                    replace(
                        selection,
                        setup=selection.setup
                        + (
                            MonitorCommand(
                                0x11A, (0x700, bytes.fromhex("02 f2 01 f2 03 f2"))
                            ),
                        ),
                    ),
                )
                monitor.start()
                monitor.stop()
                self.assertEqual(
                    [call[2][1] for call in provider.sent],
                    [
                        b"\x10\x03",
                        bytes.fromhex("2c 03 f2 02 99"),
                        bytes.fromhex("2c 03 f2 01 99"),
                        bytes.fromhex("2c 03 f2 03 99"),
                    ],
                )

    def test_11a_validation_is_atomic_and_dynamic_requires_explicit_clear_ids(self):
        provider = Provider()
        monitor = runtime(provider, (target(p5=True),))
        selection = p5(ids=((0xF201, 2),))
        monitor.configure(0x700, selection)
        for values in (
            (0x710, b"\x01\xf2"),
            (0x700, b"\x01"),
            (0x700, b""),
            (0x700, bytes(512)),
        ):
            with self.subTest(values=values), self.assertRaises(MonitorError):
                monitor.configure(
                    0x700,
                    replace(
                        selection,
                        setup=selection.setup + (MonitorCommand(0x11A, values),),
                    ),
                )
        plan = pack_dynamic_dids(
            bytes.fromhex("2c 01 00 00"),
            (DynamicSource(0x1234, ((1, 2),)),),
            (DynamicSlot(0xF201, 1),),
            max_request=8,
            max_reply=5,
        )
        profile = cast(
            VehicleProfile,
            SimpleNamespace(
                command_frames=lambda command: (
                    SimpleNamespace(request=bytes.fromhex("2c 03 00 00")),
                )
            ),
        )
        with self.assertRaisesRegex(MonitorError, "explicit cleared IDs"):
            monitor.dynamic(0x700, plan, profile)
        # Failed11A leaves the previous valid monitor usable and adds no D4 cleanup.
        monitor.start()
        monitor.stop()
        self.assertEqual(provider.sent, [])

    def test_dynamic_cache_recovery_and_cleanup_literal_order(self):
        profile = cast(
            VehicleProfile,
            SimpleNamespace(
                command_frames=lambda command: (
                    SimpleNamespace(request=bytes.fromhex("2c 03 00 00 99")),
                )
            ),
        )
        plan = pack_dynamic_dids(
            bytes.fromhex("2c 01 00 00"),
            (DynamicSource(0x1234, ((1, 2),)),),
            (DynamicSlot(0xF201, 1),),
            max_request=8,
            max_reply=5,
        )
        provider = Provider(
            tuple(
                reply(x)
                for x in (
                    "7f 10 11",
                    "50 01",
                    "50 03",
                    "6c 03 f2 01",
                    "6c 01 f2 01",
                    "62 f2 01 aa bb",
                    "6c 03 f2 01",
                )
            )
        )
        monitor = runtime(
            provider,
            (target(p5=True),),
            command_cache={
                (0x700, 0xDD): bytes.fromhex("10 01"),
                (0x700, 0xD1): bytes.fromhex("10 01"),
                (0x700, 0xD2): bytes.fromhex("10 03"),
            },
        )
        monitor.configure(0x700, p5(ids=((0xF201, 2),)))
        monitor.dynamic(0x700, plan, profile, clear_ids=plan.read_ids)
        self.assertEqual(monitor.run_packets()[0].payload, b"\xaa\xbb")
        self.assertEqual(
            [x[2][1] for x in provider.sent],
            [
                bytes.fromhex(x)
                for x in (
                    "10 01",
                    "10 01",
                    "10 03",
                    "2c 03 f2 01 99",
                    "2c 01 f2 01 12 34 01 02",
                    "22 f2 01",
                    "2c 03 f2 01 99",
                )
            ],
        )

    def test_cancel_after_send_and_repeat(self):
        cancelled = [False]
        provider = Provider((reply("61 10 5a"),))
        monitor = runtime(provider, cancelled=lambda: cancelled[0])
        monitor.configure(0x700, p4(sizes=(1,)))
        monitor.start()
        self.assertEqual(monitor.step(), DualState.SEND)
        cancelled[0] = True
        with self.assertRaises(Cancelled):
            monitor.step()
        self.assertEqual(provider.sent, [])
        self.assertEqual(monitor.state, DualState.STOPPED)
        cancelled[0] = False
        self.assertEqual(monitor.run_packets()[0].payload, b"\x5a")

    def test_cancel_rechecked_after_blocking_provider(self):
        cancelled = [False]
        provider = Provider()
        monitor = runtime(provider, cancelled=lambda: cancelled[0])
        monitor.configure(0x700, p4())
        original = monitor.native_send
        assert original is not None

        def cancel_send(ecu, call):
            code = original(ecu, call)
            cancelled[0] = True
            return code

        monitor.native_send = cancel_send
        with self.assertRaises(Cancelled):
            monitor.run_packets()
        self.assertEqual(provider.receives, [])

    def test_deadline_and_wrong_source_are_bounded(self):
        provider = Provider((reply("61 10 aa", 99),) * 50)
        monitor = runtime(provider, maximum_steps=8)
        monitor.configure(0x700, p4(sizes=(1,)))
        with self.assertRaisesRegex(MonitorError, "budget"):
            monitor.run_packets()
        self.assertEqual(monitor.state, DualState.STOPPED)
        now = [0.0]
        monitor = runtime(Provider(), clock=lambda: now[0])
        monitor.configure(0x700, p4())
        monitor.start()
        now[0] = 31
        with self.assertRaisesRegex(MonitorError, "deadline"):
            monitor.step()

    def test_p4_retains_short_cycle_tail_p5_clears(self):
        provider = Provider(tuple(reply(x) for x in ("61 10 aa bb", "61 10 cc")))
        monitor = runtime(provider)
        monitor.configure(0x700, p4())
        self.assertEqual(
            [x.payload for x in monitor.run_packets(2)], [b"\xaa\xbb", b"\xcc\xbb"]
        )
        provider = Provider(
            tuple(reply(x) for x in ("50 03", "62 12 34 aa bb", "62 12 34 cc"))
        )
        monitor = runtime(
            provider, (target(p5=True),), command_cache={(0x700, 0xDD): b"\x10\x03"}
        )
        monitor.configure(0x700, p5())
        self.assertEqual(
            [x.payload for x in monitor.run_packets(2)], [b"\xaa\xbb", b"\xcc\0"]
        )

    def test_ring_roundtrip_overflow_and_drain(self):
        ring = DualRing(12)
        packet = DualPacket(0x700, "ecu", 0x12345678, b"abcd")
        ring.append(packet)
        with self.assertRaises(MonitorError) as failure:
            ring.append(packet)
        self.assertEqual(failure.exception.code, 0xE0000101)
        self.assertEqual(ring.drain(), (packet,))
        self.assertEqual(ring.size, 0)
        ring.append(packet)
        self.assertEqual(ring.drain()[0].native_bytes, b"\x78\x56\x34\x12abcd")

    def test_runtime_ring_failure_maps_native_error(self):
        provider = Provider((reply("61 10 aa bb"),))
        monitor = runtime(provider, ring_bytes=5)
        monitor.configure(0x700, p4())
        with self.assertRaises(MonitorError) as failure:
            monitor.run_packets()
        self.assertEqual(failure.exception.code, 0xE0000108)

    def test_p4_active_order_delay_and_stop_wire(self):
        provider = Provider(tuple(reply(x) for x in ("70 01", "61 10 55", "70")))
        monitor = runtime(provider)
        monitor.configure(0x700, p4(sizes=(1,)))
        monitor.active.p4_start(b"\x99")
        packets = monitor.run_packets()
        self.assertEqual(packets[0].payload, b"\x55")
        self.assertEqual(
            [x[2][1] for x in provider.sent], [b"\x30\x99", b"\x21\x10", b"\x30"]
        )

    def test_rejected_timed_io_start_does_not_mutate_either_queue(self):
        active = DualActiveEvent(True)
        active.p5_start(
            bytes.fromhex("00 01 03"), bytes.fromhex("00 01 00"), delay=1, kind=0
        )
        before = (
            [item.request for item in active.items],
            [item.request for item in active.stop_items],
        )
        with self.assertRaisesRegex(MonitorError, "mixed timed IO"):
            active.p5_start(
                bytes.fromhex("00 02 03"), bytes.fromhex("00 02 00"), delay=1, kind=0
            )
        self.assertEqual(
            (
                [item.request for item in active.items],
                [item.request for item in active.stop_items],
            ),
            before,
        )

    def test_retained_stop_bytes_share_active_queue_budget_and_move_on_stop(self):
        from unittest.mock import patch

        active = DualActiveEvent(True)
        with patch("scripts.monitor_dual.MAX_BYTES", 16):
            active.p5_start(
                bytes.fromhex("01 00 01"), bytes.fromhex("02 00 01"), delay=0, kind=1
            )
            active.p5_start(
                bytes.fromhex("01 00 02"), bytes.fromhex("02 00 02"), delay=0, kind=1
            )
            active.accept(bytes.fromhex("71 01 00 01"), 1)
            active.advance()
            before = (
                [item.request for item in active.items],
                [item.request for item in active.stop_items],
            )
            with self.assertRaisesRegex(MonitorError, "stop queue exceeds budget"):
                active.p5_start(
                    bytes.fromhex("01 00 03"),
                    bytes.fromhex("02 00 03"),
                    delay=0,
                    kind=1,
                )
            self.assertEqual(
                (
                    [item.request for item in active.items],
                    [item.request for item in active.stop_items],
                ),
                before,
            )
            active.stop()
            self.assertEqual(
                [item.request for item in active.items],
                [bytes.fromhex("31 02 00 01"), bytes.fromhex("31 02 00 02")],
            )
            self.assertEqual(active.stop_items, [])

    def test_full_p4_start_queue_cleanup_needs_no_extra_payload_budget(self):
        from unittest.mock import patch

        for cancel in (False, True):
            with self.subTest(cancel=cancel):
                provider = Provider((reply("70"),))
                monitor = runtime(provider, cancelled=lambda cancel=cancel: cancel)
                monitor.configure(0x700, p4())
                with patch("scripts.monitor_dual.MAX_BYTES", 4):
                    monitor.active.p4_start(b"\x11\x22\x33")
                    if cancel:
                        with self.assertRaises(Cancelled):
                            monitor.run_packets()
                    else:
                        monitor.start()
                        monitor.stop()
                self.assertEqual([item[2][1] for item in provider.sent], [b"\x30"])
                self.assertIsNone(monitor.cleanup_error)

    def test_p4_active_timer_state(self):
        active = DualActiveEvent(False)
        active.p4_start(b"\x99", 20)
        active.accept(b"\x70\x01", 100)
        assert active.current is not None
        self.assertEqual(active.current.state, 3)
        self.assertEqual(active.current.due, 120)
        active.stop()
        active.advance()
        assert active.current is not None
        self.assertEqual(active.current.request, b"\x30")
        active.accept(b"\x70", 121)
        self.assertEqual(active.current.state, 5)

    def test_p5_active_routine_native_order_and_stop(self):
        provider = Provider(
            tuple(
                reply(x)
                for x in ("50 03", "71 01 12 34", "62 12 34 aa bb", "71 02 12 34")
            )
        )
        monitor = runtime(
            provider, (target(p5=True),), command_cache={(0x700, 0xDD): b"\x10\x03"}
        )
        monitor.configure(0x700, p5())
        monitor.active.p5_start(
            bytes.fromhex("01 12 34"), bytes.fromhex("02 12 34"), delay=0, kind=1
        )
        self.assertEqual(monitor.run_packets()[0].payload, b"\xaa\xbb")
        self.assertEqual(
            [x[2][1] for x in provider.sent],
            [
                bytes.fromhex(x)
                for x in ("10 03", "31 01 12 34", "22 12 34", "31 02 12 34")
            ],
        )

    def test_p4_active_parser_error_special_code(self):
        provider = Provider((reply("70 01 02"), reply("70")))
        monitor = runtime(provider)
        monitor.configure(0x700, p4())
        monitor.active.p4_start(b"\x99")
        with self.assertRaises(MonitorError) as failure:
            monitor.run_packets()
        self.assertEqual(failure.exception.code, 0xE00001CC)

    def test_osc_start_read_stop_primitives_and_native_timestamp(self):
        osc = Osc((OscRead(bytes.fromhex("01 02 03 04 05 06 07 08"), 1999, 0),))
        setup = OscSetup(b"12345678", b"\x04abc", b"5678", b"9", b"\x04xyz")
        provider = Provider((reply("61 10 aa"),))
        monitor = runtime(provider, osc_provider=osc, osc_setup=setup)
        monitor.configure(0x700, p4(sizes=(1,)))
        monitor.start()
        self.assertEqual(monitor.state, DualState.START_OSC)
        self.assertEqual(monitor.step(), DualState.SELECT)
        for _ in range(3):
            monitor.step()
        samples = monitor.osc_ring.drain()
        self.assertEqual(
            [(x.timestamp_raw, x.payload) for x in samples],
            [(1, bytes.fromhex("01 02 03 04")), (8, bytes.fromhex("05 06 07 08"))],
        )
        monitor.request_stop()
        self.assertEqual(monitor.step(), DualState.STOPPED)
        self.assertEqual(
            osc.calls,
            [
                (0, None),
                (9, b"12345678"),
                (10, b"\x04abc"),
                (6, b"5678"),
                (8, b"9"),
                (2, None),
                ("read", 0x1068),
                (3, None),
                (11, None),
                (10, b"\x04xyz"),
                ("read", 0x1068),
                (1, None),
            ],
        )

    def test_osc_sampling_table_is_native_not_a_scheduler_default(self):
        self.assertEqual(osc_sampling_increment(1), 62500000)
        self.assertEqual(osc_sampling_increment(21), 14)
        self.assertEqual(osc_sampling_increment(0), 610351)
        self.assertEqual(osc_sampling_increment(7), 610351)
        self.assertEqual(osc_sampling_increment(255), 610351)

    def test_osc_start_fault_enters_seventh_state(self):
        osc = Osc(codes=(0, 7))
        setup = OscSetup(b"12345678", b"\x04abc", b"5678", b"9", b"\x04xyz")
        monitor = runtime(Provider(), osc_provider=osc, osc_setup=setup)
        monitor.configure(0x700, p4())
        monitor.start()
        self.assertEqual(monitor.step(), DualState.OSC_ERROR)
        self.assertEqual(monitor.step(), DualState.STOPPED)
        self.assertEqual(monitor.faults[0].code, 0xE2001001)
        self.assertEqual(monitor.faults[0].detail, 9)
        self.assertEqual(monitor.faults[0].provider_code, 7)

    def test_osc_stop_preserves_first_native_fault_and_always_finishes_command(self):
        osc = Osc(codes=(0, 0, 0, 0, 0, 0, 7, 9))
        setup = OscSetup(b"12345678", b"\x04abc", b"5678", b"9", b"\x04xyz")
        monitor = runtime(
            Provider((reply("61 10 aa"),)), osc_provider=osc, osc_setup=setup
        )
        monitor.configure(0x700, p4(sizes=(1,)))
        with self.assertRaises(MonitorError) as failure:
            monitor.run_packets()
        self.assertEqual(failure.exception.code, 0xE2001000)
        self.assertEqual(monitor.faults[-1].detail, 3)
        self.assertEqual(monitor.faults[-1].provider_code, 7)
        self.assertEqual(osc.calls[-2:], [(3, None), (1, None)])

    def test_host_active_stop_failure_still_stops_osc_and_clears_dynamic_dids(self):
        class FailingProvider(Provider):
            def native_send(self, ecu, call):
                status = super().native_send(ecu, call)
                if call.request == b"\x30":
                    raise OSError("active stop failed")
                if call.request == b"\x10\x01":
                    raise OSError("dynamic recovery failed")
                return status

        provider = FailingProvider((reply("6c 03 f2 01", source=0x718),))
        osc = Osc()
        setup = OscSetup(b"12345678", b"\x04abc", b"5678", b"9", b"\x04xyz")
        monitor = runtime(
            provider,
            (target(), target(0x710, 0x718, p5=True)),
            osc_provider=osc,
            osc_setup=setup,
            command_cache={(0x710, 0xDD): b"\x10\x01"},
        )
        monitor.configure(0x700, p4())
        monitor.configure(0x710, p5(request=0x710, ids=((0xF201, 2),)))
        plan = pack_dynamic_dids(
            bytes.fromhex("2c 01 00 00"),
            (DynamicSource(0x1234, ((1, 2),)),),
            (DynamicSlot(0xF201, 1),),
            max_request=8,
            max_reply=5,
        )
        profile = cast(
            VehicleProfile,
            SimpleNamespace(
                command_frames=lambda command: (
                    SimpleNamespace(request=bytes.fromhex("2c 03 00 00")),
                )
            ),
        )
        monitor.dynamic(0x710, plan, profile, clear_ids=plan.read_ids)
        monitor.active.p4_start(b"\x99")
        monitor.start()
        monitor.step()
        with self.assertRaisesRegex(OSError, "active stop failed") as failure:
            monitor.stop()
        self.assertEqual(
            [call[2][1] for call in provider.sent],
            [b"\x30", b"\x10\x01", bytes.fromhex("2c 03 f2 01")],
        )
        self.assertEqual(
            osc.calls[-5:],
            [(3, None), (11, None), (10, b"\x04xyz"), ("read", 0x1068), (1, None)],
        )
        self.assertIn("dynamic recovery failed", " ".join(failure.exception.__notes__))
        self.assertEqual(monitor.state, DualState.STOPPED)

    def test_host_osc_stop_failure_still_attempts_final_command(self):
        class FailingOsc(Osc):
            def command(self, command):
                result = super().command(command)
                if command in (3, 1):
                    raise OSError(f"OSC operation {command} failed")
                return result

        osc = FailingOsc()
        setup = OscSetup(b"12345678", b"\x04abc", b"5678", b"9", b"\x04xyz")
        monitor = runtime(Provider(), osc_provider=osc, osc_setup=setup)
        monitor.configure(0x700, p4())
        monitor.start()
        monitor.step()
        with self.assertRaisesRegex(OSError, "OSC operation 3 failed") as failure:
            monitor.stop()
        self.assertEqual(osc.calls[-2:], [(3, None), (1, None)])
        self.assertIn("OSC operation 1 failed", " ".join(failure.exception.__notes__))

    def test_native_osc_stop_fault_precedes_final_host_exception(self):
        class FailingFinalOsc(Osc):
            def command(self, command):
                result = super().command(command)
                if command == 1:
                    raise OSError("final command failed")
                return result

        osc = FailingFinalOsc(codes=(0, 0, 0, 0, 0, 0, 7))
        setup = OscSetup(b"12345678", b"\x04abc", b"5678", b"9", b"\x04xyz")
        monitor = runtime(Provider(), osc_provider=osc, osc_setup=setup)
        monitor.configure(0x700, p4())
        monitor.start()
        monitor.step()
        with self.assertRaises(MonitorError) as failure:
            monitor.stop()
        self.assertEqual(failure.exception.code, 0xE2001000)
        self.assertEqual(monitor.faults[-1].provider_code, 7)
        self.assertIn("final command failed", " ".join(failure.exception.__notes__))
        self.assertEqual(osc.calls[-2:], [(3, None), (1, None)])

    def test_expired_main_deadline_first_cleanup_still_sends_native_stop(self):
        now = [0.0]
        provider = Provider((reply("70"),))
        monitor = runtime(provider, clock=lambda: now[0])
        monitor.configure(0x700, p4())
        monitor.active.p4_start(b"\x99")
        monitor.start()
        now[0] = 31.0
        monitor.stop()
        self.assertEqual([item[2][1] for item in provider.sent], [b"\x30"])
        self.assertIsNone(monitor.cleanup_error)
        monitor.stop()
        self.assertEqual(len(provider.sent), 1)

    def test_cancel_primary_survives_cleanup_deadline_and_explicit_retry(self):
        now = [0.0]
        cancelled = [True]
        first = [True]
        provider = Provider((reply("70"), reply("61 10 aa")))
        original = provider.native_send

        def slow_cleanup(ecu, call):
            code = original(ecu, call)
            if first[0]:
                now[0] += 3.0
                first[0] = False
            return code

        provider.native_send = slow_cleanup
        monitor = runtime(
            provider, clock=lambda: now[0], cancelled=lambda: cancelled[0]
        )
        monitor.configure(0x700, p4(sizes=(1,)))
        monitor.active.p4_start(b"\x99")
        with self.assertRaises(Cancelled):
            monitor.run_packets()
        self.assertEqual([item[2][1] for item in provider.sent], [b"\x30"])
        self.assertIn("cleanup deadline", monitor.cleanup_error or "")
        with self.assertRaisesRegex(MonitorError, "previous cleanup failed"):
            monitor.start()
        monitor.stop()
        self.assertIsNone(monitor.cleanup_error)
        cancelled[0] = False
        self.assertEqual(monitor.run_packets()[0].payload, b"\xaa")
        self.assertEqual(
            [item[2][1] for item in provider.sent], [b"\x30", b"\x30", b"\x21\x10"]
        )

    def test_cleanup_has_independent_primitive_and_byte_budgets(self):
        from unittest.mock import patch

        for field in ("MAX_ITEMS", "MAX_BYTES"):
            with self.subTest(field=field):
                provider = Provider((reply("70"),))
                monitor = runtime(provider, maximum_steps=1)
                monitor.configure(0x700, p4())
                monitor.active.p4_start(b"\x99")
                monitor.start()
                with (
                    patch("scripts.monitor_dual." + field, 1),
                    self.assertRaisesRegex(MonitorError, "cleanup.*budget"),
                ):
                    monitor.stop()
                self.assertEqual([item[2][1] for item in provider.sent], [b"\x30"])
                self.assertIsNotNone(monitor.cleanup_error)

    def test_osc_read_fault(self):
        osc = Osc((OscRead(b"", 0, 0, 9),))
        setup = OscSetup(b"12345678", b"\x04abc", b"5678", b"9", b"\x04xyz")
        monitor = runtime(
            Provider((reply("61 10 5a"),)), osc_provider=osc, osc_setup=setup
        )
        monitor.configure(0x700, p4(sizes=(1,)))
        with self.assertRaises(MonitorError) as failure:
            monitor.run_packets()
        self.assertEqual(failure.exception.code, 0xE2001003)

    def test_version12_rejects_absent_native_dtc_setup(self):
        monitor = runtime(Provider(), (target(p5=True),), version=12)
        with self.assertRaisesRegex(MonitorError, "Native12 Dual"):
            monitor.configure(0x700, p5(ids=(), dtc=(b"\x19\x02",)))
        with self.assertRaises(MonitorError):
            runtime(Provider(), version=13)

    def test_version12_does_not_synthesize_routine_negative_reply(self):
        routine = RoutineMonitor(bytes.fromhex("31 03 12 34"), 1, (), (), ())
        provider = Provider((reply("50 00 00 03"), reply("7f 31 24", code=0x90020321)))
        monitor = runtime(
            provider,
            (replace(target(p5=True), category_flags=0x34),),
            version=12,
            command_cache={(0x700, 0xDD): b"\x10\x03"},
        )
        monitor.configure(0x700, p5(ids=(), routines=(routine,)))
        with self.assertRaises(MonitorError) as failure:
            monitor.run_packets()
        self.assertEqual(failure.exception.code, 0xE000050A)

    def test_versioned_extended_session_status_and_sid_shortcut(self):
        for version in (12, 18):
            for data, code, extended12 in (
                ("50 03", 0, False),
                ("50 00 00 03", 9, True),
                ("51 00 00 03", 0, True),
            ):
                with self.subTest(version=version, data=data, code=code):
                    needs_shift = (
                        not extended12
                        if version == 12
                        else code != 0 or data.startswith("51")
                    )
                    observations = [reply(data, code=code)]
                    if needs_shift:
                        observations.extend((reply("50 01"), reply("50 03")))
                    observations.append(reply("62 12 34 aa bb"))
                    provider = Provider(observations)
                    monitor = runtime(
                        provider,
                        (target(p5=True),),
                        version=version,
                        command_cache={
                            (0x700, 0xDD): b"\x10\x01",
                            (0x700, 0xD1): b"\x10\x01",
                            (0x700, 0xD2): b"\x10\x03",
                        },
                    )
                    monitor.configure(0x700, p5())
                    self.assertEqual(monitor.run_packets()[0].payload, b"\xaa\xbb")
                    self.assertEqual(
                        [call[2][1] for call in provider.sent],
                        [b"\x10\x01"]
                        + ([b"\x10\x01", b"\x10\x03"] if needs_shift else [])
                        + [b"\x22\x12\x34"],
                    )

    def test_version12_redefines_after_all_clear_failures_version18_skips(self):
        profile = cast(
            VehicleProfile,
            SimpleNamespace(
                command_frames=lambda command: (
                    SimpleNamespace(request=bytes.fromhex("2c 03 00 00")),
                )
            ),
        )
        plan = pack_dynamic_dids(
            bytes.fromhex("2c 01 00 00"),
            (DynamicSource(0x1234, ((1, 2),)),),
            (DynamicSlot(0xF201, 1),),
            max_request=8,
            max_reply=5,
        )
        for version in (12, 18):
            with self.subTest(version=version):
                observations = [
                    reply("50 00 00 00", code=9),
                    reply("50 01"),
                    reply("50 03"),
                    reply("", code=9),
                ]
                if version == 12:
                    observations.append(reply("6c 01 f2 01"))
                observations.extend((reply("62 f2 01 aa bb"), reply("6c 03 f2 01")))
                provider = Provider(observations)
                monitor = runtime(
                    provider,
                    (target(p5=True),),
                    version=version,
                    command_cache={
                        (0x700, 0xDD): b"\x10\x01",
                        (0x700, 0xD1): b"\x10\x01",
                        (0x700, 0xD2): b"\x10\x03",
                    },
                )
                monitor.configure(0x700, p5(ids=((0xF201, 2),)))
                monitor.dynamic(0x700, plan, profile, clear_ids=plan.read_ids)
                self.assertEqual(monitor.run_packets()[0].payload, b"\xaa\xbb")
                self.assertEqual(
                    any(call[2][1] == plan.requests[0] for call in provider.sent),
                    version == 12,
                )

    def test_version12_normal_check_is_not_filtered_by_active_rid(self):
        for version in (12, 18):
            with self.subTest(version=version):
                routine = RoutineMonitor(
                    bytes.fromhex("31 03 12 34"), 1, (1,), (2,), ()
                )
                provider = Provider(
                    tuple(
                        reply(x)
                        for x in ("50 00 00 03", "71 01 99 99", "71 03 12 34 02")
                    )
                )
                monitor = runtime(
                    provider,
                    (target(p5=True),),
                    version=version,
                    command_cache={(0x700, 0xDD): b"\x10\x03"},
                )
                monitor.configure(0x700, p5(ids=(), routines=(routine,)))
                monitor.active.p5_start(
                    bytes.fromhex("01 99 99"),
                    bytes.fromhex("02 99 99"),
                    delay=0,
                    kind=1,
                )
                monitor.start()
                for _ in range(6):
                    monitor.step()
                self.assertEqual(
                    monitor.state,
                    DualState.STOPPED if version == 12 else DualState.SELECT,
                )
                self.assertEqual(
                    any(item.kind == "routine-abnormal" for item in monitor.notices),
                    version == 12,
                )
                self.assertEqual(
                    [packet.payload for packet in monitor.drain(0x700)],
                    [] if version == 12 else [b"\x02"],
                )

    def test_version18_zero_rid_bypasses_active_filter_as_initialized_native_flag(self):
        routine = RoutineMonitor(bytes.fromhex("31 03 00 00"), 1, (1,), (2,), ())
        provider = Provider(
            tuple(reply(x) for x in ("50 03", "71 01 99 99", "71 03 00 00 02"))
        )
        monitor = runtime(
            provider,
            (target(p5=True),),
            version=18,
            command_cache={(0x700, 0xDD): b"\x10\x03"},
        )
        monitor.configure(0x700, p5(ids=(), routines=(routine,)))
        monitor.active.p5_start(
            bytes.fromhex("01 99 99"), bytes.fromhex("02 99 99"), delay=0, kind=1
        )
        monitor.start()
        for _ in range(6):
            monitor.step()
        self.assertEqual(monitor.state, DualState.STOPPED)
        self.assertTrue(
            any(item.kind == "routine-abnormal" for item in monitor.notices)
        )
        self.assertEqual(monitor.drain(0x700), ())

    def test_native_driver_registration_and_ignored_status_observations(self):
        calls = []

        def control(call):
            calls.append((call.operation, call.arguments))
            return 7

        chosen = replace(target(), entry_parameter=0x1234)
        provider = Provider((reply("61 10 aa"),))
        monitor = runtime(provider, (chosen,), driver_control=control)
        monitor.configure(0x700, p4(sizes=(1,)))
        monitor.run_packets()
        monitor.close()
        self.assertEqual(
            calls,
            [
                ("ConnectDualMon", ()),
                ("EntryCommSystemInfo", (99, 2, 0x1234, 3)),
                ("Disconnect", (0,)),
            ],
        )
        self.assertEqual(
            [status for _, status in monitor.control_observations], [7, 7, 7]
        )

    def test_native18_security_release_requests_default_session_before_disconnect(self):
        controls = []
        provider = Provider((reply("61 10 aa"), reply("50 01")))
        monitor = runtime(
            provider,
            (replace(target(), entry_parameter=0),),
            driver_control=lambda call: controls.append(call.operation) or 0,
            command_cache={(0x700, 0xD1): b"\x10\x01"},
        )
        monitor.configure(0x700, p4(sizes=(1,)))
        monitor.set_security_release(0x700, True)
        monitor.run_packets()
        monitor.close()
        self.assertEqual(
            [call[2][1] for call in provider.sent], [b"\x21\x10", b"\x10\x01"]
        )
        self.assertEqual(controls[-1], "Disconnect")
        with self.assertRaises(MonitorError):
            monitor.set_security_release(0x701, True)
        with self.assertRaises(MonitorError):
            runtime(Provider(), version=12).set_security_release(0x700, True)

    def test_native_stop_kind_fault_triggers_exit_d1_for_both_versions(self):
        for version in (12, 18):
            with self.subTest(version=version):
                provider = Provider(
                    (reply("50 00 00 03"), reply("7f 2f 22", code=9), reply("50 01"))
                )
                monitor = runtime(
                    provider,
                    (target(p5=True),),
                    version=version,
                    command_cache={
                        (0x700, 0xDD): b"\x10\x03",
                        (0x700, 0xD1): b"\x10\x01",
                    },
                )
                monitor.configure(0x700, p5())
                monitor.active.p5_start(
                    bytes.fromhex("00 01 03"),
                    bytes.fromhex("00 01 00"),
                    delay=0,
                    kind=0,
                )
                monitor.active.stop()
                monitor.start()
                for _ in range(4):
                    monitor.step()
                self.assertEqual(monitor.faults[0].code, 0xE0000205)
                monitor.close()
                self.assertEqual(
                    [call[2][1] for call in provider.sent],
                    [b"\x10\x03", bytes.fromhex("2f 00 01 00"), b"\x10\x01"],
                )

    def test_native_p5_cleanup_fault_triggers_exit_d1_without_start_replay(self):
        for version in (12, 18):
            with self.subTest(version=version):
                provider = Provider(
                    (
                        reply("50 00 00 03"),
                        reply("71 01 99 99"),
                        reply("62 12 34 aa bb"),
                        reply("7f 31 22", code=9),
                        reply("50 01"),
                    )
                )
                monitor = runtime(
                    provider,
                    (target(p5=True),),
                    version=version,
                    command_cache={
                        (0x700, 0xDD): b"\x10\x03",
                        (0x700, 0xD1): b"\x10\x01",
                    },
                )
                monitor.configure(0x700, p5())
                monitor.active.p5_start(
                    bytes.fromhex("01 99 99"),
                    bytes.fromhex("02 99 99"),
                    delay=0,
                    kind=1,
                )
                self.assertEqual(monitor.run_packets()[0].payload, b"\xaa\xbb")
                monitor.close()
                self.assertEqual(
                    [call[2][1] for call in provider.sent],
                    [
                        bytes.fromhex(x)
                        for x in (
                            "10 03",
                            "31 01 99 99",
                            "22 12 34",
                            "31 02 99 99",
                            "10 01",
                        )
                    ],
                )
                self.assertEqual(monitor.cleanup_failures[0].received.code, 9)

    def test_missing_exit_d1_still_disconnects_and_reports_cache_failure(self):
        controls = []
        monitor = runtime(
            Provider((reply("61 10 aa"),)),
            (replace(target(), entry_parameter=0),),
            driver_control=lambda call: controls.append(call.operation) or 0,
        )
        monitor.configure(0x700, p4(sizes=(1,)))
        monitor.set_security_release(0x700, True)
        monitor.run_packets()
        with self.assertRaisesRegex(MonitorError, "lacks commandD1"):
            monitor.close()
        self.assertEqual(controls[-1], "Disconnect")
        self.assertIn("lacks commandD1", monitor.cleanup_error or "")
        monitor.close()
        self.assertEqual(controls.count("Disconnect"), 1)

    def test_close_disconnects_after_main_expiry_and_is_idempotent(self):
        now = [0.0]
        controls = []
        provider = Provider((reply("70"),))
        chosen = replace(target(), entry_parameter=0)
        monitor = runtime(
            provider,
            (chosen,),
            clock=lambda: now[0],
            driver_control=lambda call: controls.append(call.operation) or 0,
        )
        monitor.configure(0x700, p4())
        monitor.active.p4_start(b"\x99")
        monitor.start()
        now[0] = 31.0
        monitor.close()
        monitor.close()
        self.assertEqual(
            controls, ["ConnectDualMon", "EntryCommSystemInfo", "Disconnect"]
        )
        self.assertEqual([item[2][1] for item in provider.sent], [b"\x30"])
        self.assertIsNone(monitor.cleanup_error)

    def test_close_preserves_stop_deadline_failure_and_attempts_disconnect(self):
        now = [0.0]
        controls = []
        provider = Provider()
        original = provider.native_send

        def slow_stop(ecu, call):
            code = original(ecu, call)
            now[0] += 3.0
            return code

        provider.native_send = slow_stop

        def control(call):
            controls.append(call.operation)
            if call.operation == "Disconnect":
                raise RuntimeError("release failed")
            return 0

        monitor = runtime(
            provider,
            (replace(target(), entry_parameter=0),),
            clock=lambda: now[0],
            driver_control=control,
        )
        monitor.configure(0x700, p4())
        monitor.active.p4_start(b"\x99")
        monitor.start()
        with self.assertRaisesRegex(MonitorError, "cleanup deadline") as failure:
            monitor.close()
        self.assertEqual(controls[-1], "Disconnect")
        self.assertIn("release failed", monitor.cleanup_error or "")
        self.assertTrue(
            any(
                "disconnect also failed" in note for note in failure.exception.__notes__
            )
        )

    def test_ignored_native_stop_status_is_structured_cleanup_observation(self):
        provider = Provider((reply("61 10 aa"),), statuses=(0, 9))
        monitor = runtime(provider)
        monitor.configure(0x700, p4(sizes=(1,)))
        monitor.active.p4_start(b"\x99")
        # Hold the completed AT at native state4 so only its stop runs at shutdown.
        monitor.active.accept(b"\x70\x01", 1)
        self.assertEqual(monitor.run_packets()[0].payload, b"\xaa")
        self.assertEqual(
            [(item.request, item.received.code) for item in monitor.cleanup_failures],
            [(b"\x30", 9)],
        )
        self.assertEqual([item[2][1] for item in provider.sent], [b"\x21\x10", b"\x30"])

    def test_driver_registration_validated_before_any_control(self):
        calls = []
        monitor = runtime(
            Provider(), driver_control=lambda call: calls.append(call) or 0
        )
        monitor.configure(0x700, p4())
        with self.assertRaisesRegex(MonitorError, "entry parameter"):
            monitor.start()
        self.assertEqual(calls, [])

    def test_no_init_selection_calls_disconnect_each_target_switch(self):
        calls = []
        a = replace(target(), protocol=0x22)
        b = replace(target(0x701, 0x709), protocol=0x22)
        provider = Provider((reply("61 10 aa"), reply("61 10 bb", 0x709)))
        monitor = runtime(
            provider,
            (a, b),
            connected_device=4,
            driver_control=lambda call: (
                calls.append((call.operation, call.arguments)) or 0
            ),
        )
        monitor.configure(0x700, p4(sizes=(1,)))
        monitor.configure(0x701, p4(0x701, sizes=(1,)))
        monitor.run_packets()
        self.assertEqual(calls, [("Disconnect", (0,))] * 3)
        self.assertEqual(
            {item[1] for item in provider.sent}, {"SendIntNoInitNoSession"}
        )

    def test_timed_active_wait_does_not_block_monitor_cycle(self):
        provider = Provider(tuple(reply(x) for x in ("70 01", "61 10 aa", "70")))
        monitor = runtime(provider, tick_ms=Tick(100))
        monitor.configure(0x700, p4(sizes=(1,)))
        monitor.active.p4_start(b"\x99", 1000)
        self.assertEqual(monitor.run_packets()[0].payload, b"\xaa")
        self.assertEqual(
            [item[2][1] for item in provider.sent], [b"\x30\x99", b"\x21\x10", b"\x30"]
        )

    def test_cancel_during_receive_sends_only_native_stop(self):
        cancelled = [False]
        provider = Provider((reply("70 01"), reply("70"), reply("61 10 aa")))
        original = provider.receive
        first = [True]

        def cancel_receive(ecu, **kwargs):
            result = original(ecu, **kwargs)
            if first[0]:
                first[0] = False
                cancelled[0] = True
            return result

        provider.receive = cancel_receive
        monitor = runtime(provider, cancelled=lambda: cancelled[0])
        monitor.configure(0x700, p4(sizes=(1,)))
        monitor.active.p4_start(b"\x99")
        with self.assertRaises(Cancelled):
            monitor.run_packets()
        self.assertEqual([item[2][1] for item in provider.sent], [b"\x30\x99", b"\x30"])
        self.assertIsNone(monitor.cleanup_error)
        cancelled[0] = False
        self.assertEqual(monitor.run_packets()[0].payload, b"\xaa")

    def test_p5_at_fault_and_stop_fault_native_codes(self):
        for stop, negative, expected in (
            (False, False, 0xE0000501),
            (False, True, 0xE0000502),
            (True, False, 0xE0000205),
            (True, True, 0xE0000206),
        ):
            with self.subTest(stop=stop, negative=negative):
                provider = Provider(
                    (
                        reply("50 03"),
                        reply("7f 31 22", code=0x90020321 if negative else 9),
                        reply("71 02 12 34"),
                    )
                )
                monitor = runtime(
                    provider,
                    (target(p5=True),),
                    command_cache={(0x700, 0xDD): b"\x10\x03"},
                )
                monitor.configure(0x700, p5())
                if stop:
                    monitor.active.p5_start(
                        bytes.fromhex("01 12 03"),
                        bytes.fromhex("01 12 00"),
                        delay=0,
                        kind=0,
                    )
                    monitor.active.stop()
                else:
                    monitor.active.p5_start(
                        bytes.fromhex("01 12 34"),
                        bytes.fromhex("02 12 34"),
                        delay=0,
                        kind=1,
                    )
                monitor.start()
                for _ in range(4):
                    monitor.step()
                self.assertEqual(monitor.faults[0].code, expected)
                self.assertEqual(
                    monitor.state, DualState.SELECT if stop else DualState.STOPPED
                )

    def test_native_synthetic_routine_negative_only_selected_flag_and_code(self):
        routine = RoutineMonitor(bytes.fromhex("31 03 12 34"), 1, (), (), ())
        provider = Provider((reply("50 03"), reply("7f 31 24", code=0x90020321)))
        monitor = runtime(
            provider,
            (replace(target(p5=True), category_flags=0x34),),
            command_cache={(0x700, 0xDD): b"\x10\x03"},
        )
        monitor.configure(0x700, p5(ids=(), routines=(routine,)))
        self.assertEqual(monitor.run_packets()[0].payload, b"\0")
        self.assertEqual(monitor.faults, [])

    def test_osc_native_rollover_and_fraction(self):
        osc = Osc(
            (
                OscRead(bytes.fromhex("01 02 03 04"), 0xFFFFFFFE, 1),
                OscRead(bytes.fromhex("05 06 07 08"), 1, 0),
            )
        )
        setup = OscSetup(b"12345678", b"\x04abc", b"5678", b"9", b"\x04xyz")
        monitor = runtime(
            Provider((reply("61 10 aa"),)), osc_provider=osc, osc_setup=setup
        )
        monitor.configure(0x700, p4(sizes=(1,)))
        monitor.start()
        for _ in range(4):
            monitor.step()
        # Native keeps its own next-sample cursor, ignoring subsequent buffer stamps.
        self.assertEqual(
            [item.timestamp_raw for item in monitor.osc_ring.drain()],
            [4294967, 4294973],
        )

    def test_target_and_setup_trust_boundaries(self):
        for targets in ((), (target(), target()), (target(), target(), target())):
            with self.subTest(targets=targets), self.assertRaises(MonitorError):
                runtime(
                    Provider(), targets=targets or ()
                ) if targets else DualMonitorRuntime(
                    (), Provider(), tick_ms=Tick(), native_send=Provider().native_send
                )
        monitor = runtime(Provider())
        for setup in (
            MonitorSetup((), (), ()),
            p4(0x701),
            MonitorSetup((MonitorCommand(0x109, (99, 0x700)),), (), ()),
            MonitorSetup(
                (MonitorCommand(0x10A, (99, 0x700, 1, (("x", 1),), 1, (), 3, 0)),),
                (),
                (),
            ),
        ):
            with self.subTest(setup=setup), self.assertRaises(MonitorError):
                monitor.configure(0x700, setup)
        with self.assertRaises(MonitorError):
            monitor.start()

    def test_bad_provider_status_and_timestamp(self):
        provider = Provider(statuses=(True,))
        monitor = runtime(provider)
        monitor.configure(0x700, p4())
        with self.assertRaises(MonitorError):
            monitor.run_packets()
        monitor = runtime(Provider((reply("61 10 aa bb"),)), tick_ms=lambda: -1)
        monitor.configure(0x700, p4())
        with self.assertRaises(MonitorError):
            monitor.run_packets()


class DualPrimitiveBackend:
    def __init__(self, failures=()):
        self.calls = []
        self.failures = list(failures)

    def invoke(self, operation, fields, *, deadline, cancelled):
        self.calls.append((operation, dict(fields), deadline))
        if self.failures and self.failures[0][0] == operation:
            _, code = self.failures.pop(0)
            raise NativeDrsError(code)
        if operation == "read":
            return NativeMessage(6, 0, 0, 0, 0, b"")
        return 7 if operation == "connect" else 0


class NativeDualControlTests(unittest.TestCase):
    def test_runtime_source_reload_callbacks_cannot_publish_packet_or_sample(self):
        for boundary in (
            "send",
            "receive",
            "tick",
            "osc_command",
            "osc_read",
            "clock",
            "cancel",
        ):
            with self.subTest(boundary=boundary):
                profile, chosen = self.actual_profile()
                control, backend = self.control(
                    (chosen,), profiles={chosen.ecu: profile}
                )
                changed = [False]

                def mutate(profile=profile, changed=changed):
                    if not changed[0]:
                        self.reload_management(profile)
                        changed[0] = True

                class SourceProvider(Provider):
                    def native_send(
                        self, ecu, call, *, boundary=boundary, mutate=mutate
                    ):
                        code = super().native_send(ecu, call)
                        if boundary == "send":
                            mutate()
                        return code

                    def receive(
                        self, ecu, *, boundary=boundary, mutate=mutate, **kwargs
                    ):
                        result = super().receive(ecu, **kwargs)
                        if boundary == "receive":
                            mutate()
                        return result

                class SourceOsc(Osc):
                    def command(self, operation, *, boundary=boundary, mutate=mutate):
                        code = super().command(operation)
                        if boundary == "osc_command":
                            mutate()
                        return code

                    def read_buffer(
                        self,
                        maximum,
                        *,
                        boundary=boundary,
                        changed=changed,
                        mutate=mutate,
                    ):
                        if boundary == "osc_read" and not changed[0]:
                            mutate()
                            return OscRead(b"1234", 1000, 0)
                        return super().read_buffer(maximum)

                def tick(boundary=boundary, mutate=mutate):
                    if boundary == "tick":
                        mutate()
                    return 1000

                provider = SourceProvider(
                    (reply("61 10 aa bb", source=chosen.response_id),)
                )
                kwargs: dict[str, object] = {"driver_control": control, "tick_ms": tick}
                if boundary.startswith("osc_"):
                    kwargs.update(
                        osc_provider=SourceOsc(),
                        osc_setup=OscSetup(
                            b"12345678", b"\x04abc", b"5678", b"9", b"\x04xyz"
                        ),
                    )
                monitor = runtime(provider, (chosen,), **kwargs)
                monitor.configure(chosen.request_id, p4(request=chosen.request_id))
                if boundary in ("clock", "cancel"):
                    monitor.start()

                    def callback(boundary=boundary, mutate=mutate):
                        mutate()
                        return False if boundary == "cancel" else 0.0

                    if boundary == "clock":
                        monitor.clock = lambda: float(callback())
                    else:
                        monitor.cancelled = lambda: bool(callback())
                    with self.assertRaisesRegex(MonitorError, "source identity"):
                        monitor.step()
                else:
                    with self.assertRaisesRegex(MonitorError, "source identity"):
                        monitor.run_packets()
                self.assertTrue(changed[0])
                self.assertEqual(monitor.drain(chosen.request_id), ())
                self.assertEqual(monitor.osc_ring.drain(), ())
                with self.assertRaisesRegex(MonitorError, "source identity"):
                    monitor.close()
                self.assertIsNone(control.channel)
                self.assertEqual(backend.calls[-1][0], "disconnect")

    def test_full_observation_history_rolls_without_blocking_actual_disconnect(self):
        from unittest.mock import patch

        with patch("scripts.monitor_dual.MAX_ITEMS", 3):
            chosen = target(p5=True, entry_parameter=0x700)
            control, backend = self.control((chosen,))
            control(DualControl("ConnectDualMon", ()))
            self.entry(control, chosen)
            self.assertEqual(len(control.observations), 3)
            control(DualControl("Disconnect", (0,)))
            self.assertIsNone(control.channel)
            self.assertEqual(len(control.observations), 3)
            self.assertEqual(control.observations[-1], ("disconnect", 0))
            self.assertEqual(backend.calls[-1][0], "disconnect")

    def test_no_init_runtime_cannot_bypass_changed_selected_source_guard(self):
        chosen = replace(target(entry_parameter=0x700), protocol=0x22)
        profile = self.selection(chosen)
        control, backend = self.control(
            (chosen,), profiles={chosen.ecu: profile}, connected_device=4
        )
        provider = Provider((reply("61 10 aa bb"),))
        monitor = runtime(
            provider, (chosen,), connected_device=4, driver_control=control
        )
        monitor.configure(0x700, p4())
        monitor.start()
        cast(SimpleNamespace, profile.catalog.management).sha256 = "f" * 64
        with self.assertRaisesRegex(MonitorError, "source identity"):
            monitor.step()
            monitor.step()
        self.assertEqual(provider.sent, [])
        self.assertEqual(backend.calls, [])

    def actual_profile(self):
        from test_drive_recorder import NativeMonitorRecorderTests

        fixture = NativeMonitorRecorderTests()
        self.addCleanup(fixture.doCleanups)
        profile = fixture.vin_profile()
        chosen = DualTarget(
            "actual-authored",
            0x7E0,
            0x7E8,
            0x12,
            profile.category_record[72],
            profile.category,
            1,
            entry_parameter=0x7E0,
        )
        return profile, chosen

    @staticmethod
    def reload_management(profile):
        from scripts.demo import _ddb
        from scripts.diagnostic_db import parse_database

        old = profile.catalog.management
        sections = {
            key: (section.count, section.payload)
            for key, section in old.sections.items()
        }
        settings = bytearray(old.sections[29].payload)
        struct.pack_into("<I", settings, 0, 31337)
        sections[29] = (old.sections[29].count, bytes(settings))
        profile.catalog.management = parse_database(_ddb(old.kind, sections))
        assert profile.catalog.management.sha256 != old.sha256

    def test_reparsed_actual_management_source_rejected_before_connect(self):
        profile, chosen = self.actual_profile()
        control, backend = self.control((chosen,), profiles={chosen.ecu: profile})
        self.reload_management(profile)
        with self.assertRaisesRegex(MonitorError, "source identity"):
            control(DualControl("ConnectDualMon", ()))
        self.assertEqual(backend.calls, [])

    def test_source_reload_in_clock_and_cancel_callbacks_prevents_primitive(self):
        for callback in ("clock", "cancel"):
            with self.subTest(callback=callback):
                profile, chosen = self.actual_profile()
                control, backend = self.control(
                    (chosen,), profiles={chosen.ecu: profile}
                )
                changed = [False]

                def mutate(profile=profile, changed=changed):
                    if not changed[0]:
                        self.reload_management(profile)
                        changed[0] = True

                if callback == "clock":

                    def clock():
                        mutate()
                        return 0.0

                    control.clock = clock
                    cancelled = lambda: False
                else:

                    def cancelled():
                        mutate()
                        return False

                with self.assertRaisesRegex(MonitorError, "source identity"):
                    control.execute(
                        DualControl("ConnectDualMon", ()),
                        deadline=2,
                        cancelled=cancelled,
                    )
                self.assertEqual(backend.calls, [])

    def test_source_reload_after_connect_keeps_lease_and_cleanup_only_disconnects(self):
        profile, chosen = self.actual_profile()
        outer = self

        class Backend(DualPrimitiveBackend):
            def invoke(self, operation, fields, *, deadline, cancelled):
                result = super().invoke(
                    operation, fields, deadline=deadline, cancelled=cancelled
                )
                if operation == "connect":
                    outer.reload_management(profile)
                return result

        control, backend = self.control(
            (chosen,), profiles={chosen.ecu: profile}, backend=Backend()
        )
        with self.assertRaisesRegex(MonitorError, "source identity"):
            control.execute(
                DualControl("ConnectDualMon", ()), deadline=2, cancelled=lambda: False
            )
        self.assertEqual(control.channel, 7)
        with self.assertRaisesRegex(MonitorError, "source identity"):
            control.execute(
                DualControl("Disconnect", (0,)), deadline=2, cancelled=lambda: False
            )
        self.assertIsNone(control.channel)
        self.assertEqual([x[0] for x in backend.calls], ["connect", "disconnect"])

    def test_source_reload_during_d1_metadata_read_cannot_send_mixed_source_bytes(self):
        chosen = target(entry_parameter=0x700)
        profile = self.selection(chosen)

        def frames(key):
            if key == 0xD1:
                cast(SimpleNamespace, profile.catalog.management).sha256 = "f" * 64
            return (SimpleNamespace(request=b"\x10\x01"),)

        cast(SimpleNamespace, profile).command_frames = frames
        control, backend = self.control((chosen,), profiles={chosen.ecu: profile})
        control(DualControl("ConnectDualMon", ()))
        self.entry(control, chosen)
        control.before_send(chosen, deadline=2, cancelled=lambda: False)
        control.preinit_d1_suppressed = 0
        with self.assertRaisesRegex(MonitorError, "source identity"):
            control(DualControl("Disconnect", (0,)))
        self.assertEqual(
            [x[0] for x in backend.calls],
            ["connect", "set_config", "start_message_filter", "disconnect"],
        )
        self.assertIsNone(control.channel)

    def test_application_source_context_mutation_rejected_before_connect(self):
        control, backend = self.control()
        control.source_build = 12
        with self.assertRaisesRegex(MonitorError, "source context"):
            control(DualControl("ConnectDualMon", ()))
        self.assertEqual(backend.calls, [])

    def test_nonfinite_clock_with_external_deadline_cannot_invoke_backend(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(clock=value):
                control, backend = self.control(clock=lambda value=value: value)
                with self.assertRaisesRegex(MonitorError, "deadline"):
                    control.execute(
                        DualControl("ConnectDualMon", ()),
                        deadline=2,
                        cancelled=lambda: False,
                    )
                self.assertEqual(backend.calls, [])

    def test_version12_and18_optional_can_parameter_and_single23_wire(self):
        for version, optional, single in ((12, 99, 7), (18, 23, 99)):
            with self.subTest(version=version):
                chosen = target(p5=True, entry_parameter=0x700)
                profile = self.selection(chosen)
                can = bytearray(profile.comm_info_can_records(1)[0])
                struct.pack_into("<HHH", can, 18, 7, 99, 23)
                can[24] = can[26] = 1
                cast(SimpleNamespace, profile).comm_info_can_records = (
                    lambda key, can=can: (bytes(can),)
                )
                control, backend = self.control(
                    (chosen,), profiles={chosen.ecu: profile}, source_build=version
                )
                control(DualControl("ConnectDualMon", ()))
                self.assertEqual(self.entry(control, chosen), 0)
                parameters = [
                    call[1]["parameters"]
                    for call in backend.calls
                    if call[0] == "set_config"
                ]
                self.assertEqual(parameters[0][-1], (0x2A, optional))
                self.assertEqual(parameters[1], ((0x23, single),))

    def test_selected_entry_parameter_is_an_arbitrary_native_dword(self):
        for parameter in (0, 0x701, 0xFFFFFFFF):
            chosen = target(p5=True, entry_parameter=parameter)
            control, backend = self.control((chosen,))
            self.assertEqual(backend.calls, [])
            control(DualControl("ConnectDualMon", ()))
            self.assertEqual(self.entry(control, chosen), 0)
            self.assertEqual(
                control.selected[chosen.command_id][0].entry_parameter, parameter
            )

    def test_typed_control_fault_matrix_preserves_actual_resource_outcomes(self):
        from scripts.frame_transport import (
            J2534Result,
            _HostCancellation,
            _HostDeadline,
        )
        from scripts.frame_transport import NativeMessage as J2534Message

        for operation in (
            "connect",
            "start_message_filter",
            "write",
            "read",
            "disconnect",
        ):
            for boundary in (
                "cancelled_before",
                "deadline_before",
                "cancelled_after",
                "deadline_after",
            ):
                for code in (0, 9):
                    if boundary.endswith("_before") and code:
                        continue
                    with self.subTest(
                        operation=operation, boundary=boundary, code=code
                    ):
                        before = boundary.endswith("_before")
                        result = (
                            J2534Result(host_boundary=boundary)
                            if before
                            else J2534Result(
                                code=code,
                                handle=17
                                if operation in ("connect", "start_message_filter")
                                else None,
                                count=1 if operation in ("write", "read") else 0,
                                messages=(J2534Message(6, 0, 0, 0, 0, b"a"),)
                                if operation == "read"
                                else (),
                                host_boundary=boundary,
                            )
                        )

                        class Backend:
                            def invoke(
                                self,
                                operation,
                                fields,
                                *,
                                deadline,
                                cancelled,
                                result=result,
                            ):
                                return result

                        control, _ = self.control(
                            backend=NativeDualPrimitives(Backend())
                        )
                        control.channel = 7 if operation != "connect" else None
                        control.filter_handles = [11]
                        fields = {
                            "channel_id": 7,
                            "parameters": (),
                            "filter_type": 3,
                            "messages": (NativeMessage(6, 0, 0, 0, 0, b"a"),) * 3,
                            "message": NativeMessage(6, 0, 0, 0, 0, b"a"),
                            "timeout": 1,
                        }
                        expected = (
                            _HostCancellation
                            if boundary.startswith("cancelled")
                            else _HostDeadline
                        )
                        with self.assertRaises(expected):
                            control._call(operation, fields, 2, lambda: False)
                        self.assertFalse(control.poisoned)
                        if operation == "connect":
                            self.assertEqual(control.channel, None if before else 17)
                            self.assertEqual(
                                control.channel_generation, 0 if before else 1
                            )
                        elif operation == "disconnect":
                            self.assertEqual(
                                control.channel, None if not before and not code else 7
                            )
                        elif operation == "start_message_filter":
                            self.assertEqual(
                                control.filter_handles, [11] if before else [11, 17]
                            )

    def test_typed_unconfirmed_outcome_poison_precedes_after_boundary(self):
        from scripts.frame_transport import J2534Result, _HostCancellation

        class Backend:
            def invoke(self, operation, fields, *, deadline, cancelled):
                return J2534Result(host_boundary="cancelled_after")

        control, _ = self.control(backend=NativeDualPrimitives(Backend()))
        control.channel = 7
        with self.assertRaises(_HostCancellation):
            control._call("read", {"channel_id": 7, "timeout": 1}, 2, lambda: False)
        self.assertTrue(control.poisoned)

    def test_poisoned_control_resource_cleanup_does_not_send_session_requests(self):
        control, backend = self.control()
        control.channel = 7
        control.last_target = next(iter(control.selected))
        control.poisoned = True
        self.assertEqual(
            control.close_resources(deadline=2, cancelled=lambda: False), 0
        )
        self.assertEqual([call[0] for call in backend.calls], ["disconnect"])
        self.assertIsNone(control.channel)

    def test_disconnect_one_runs_ordinary_lower_close_and_p5_session_reconfiguration(
        self,
    ):
        for phase5 in (False, True):
            chosen = target(p5=phase5, entry_parameter=0x700)
            control, backend = self.control((chosen,))
            control(DualControl("ConnectDualMon", ()))
            self.entry(control, chosen)
            control.before_send(chosen, deadline=2, cancelled=lambda: False)
            if phase5:
                self.assertEqual(control(DualControl("Disconnect", (1,))), 0)
                self.assertEqual(
                    [call[0] for call in backend.calls][-3:],
                    ["set_config", "start_message_filter", "disconnect"],
                )
                self.assertEqual(control.current_service, 0x10)
            else:
                self.assertEqual(control(DualControl("Disconnect", (1,))), 0)
                self.assertFalse(
                    any(call[0] in ("write", "read") for call in backend.calls)
                )
            self.assertIsNone(control.channel)

    def test_native_close_session_family_and_variant_matrix(self):
        for version in (12, 18):
            for variant in ("dual", "multi"):
                for flag in (0, 1):
                    for service in (0, 1, 15, 16, 255):
                        with self.subTest(
                            version=version, variant=variant, flag=flag, service=service
                        ):
                            chosen = replace(
                                target(p5=True, entry_parameter=0xFFFFFFFF),
                                protocol=0x12,
                            )
                            control, backend = self.control(
                                (chosen,), source_build=version, source_variant=variant
                            )
                            control(
                                DualControl(
                                    "ConnectDualMon"
                                    if variant == "dual"
                                    else "ConnectMultiMon",
                                    (),
                                )
                            )
                            self.entry(control, chosen)
                            control.before_send(
                                chosen, deadline=2, cancelled=lambda: False
                            )
                            control.current_service = service
                            backend.calls.clear()
                            control(DualControl("Disconnect", (flag,)))
                            reconfigure = service < 16 or (
                                version == 18 and variant == "multi"
                            )
                            expected = (
                                ["set_config", "start_message_filter", "disconnect"]
                                if reconfigure
                                else ["disconnect"]
                            )
                            self.assertEqual(
                                [call[0] for call in backend.calls], expected
                            )
                            self.assertEqual(
                                control.current_service, 16 if reconfigure else service
                            )
                            self.assertEqual(
                                control.request_state,
                                int(reconfigure and version == 18),
                            )
                            self.assertIsNone(control.channel)

    def test_unknown_typed_backend_exception_keeps_lease_and_poison_for_resource_only_close(
        self,
    ):
        class Backend:
            def __init__(self):
                self.calls = []

            def invoke(self, operation, fields, *, deadline, cancelled):
                from scripts.frame_transport import J2534Result

                self.calls.append(operation)
                if operation != "disconnect":
                    raise InterruptedError("backend lost its primitive result")
                return J2534Result()

        raw = Backend()
        control, _ = self.control(backend=NativeDualPrimitives(raw))
        control.channel = 7
        with self.assertRaisesRegex(InterruptedError, "lost its primitive"):
            control._call("read", {"channel_id": 7, "timeout": 1}, 2, lambda: False)
        self.assertTrue(control.poisoned)
        self.assertEqual(control.channel, 7)
        self.assertEqual(
            control.close_resources(deadline=2, cancelled=lambda: False), 0
        )
        self.assertEqual(raw.calls, ["read_messages", "disconnect"])

    def test_disconnect_flag_controls_preinit_d1_independently_of_session_family(self):
        for version in (12, 18):
            for flag in (0, 1):
                for phase5 in (False, True):
                    with self.subTest(version=version, flag=flag, phase5=phase5):
                        chosen = replace(
                            target(p5=phase5, entry_parameter=0x700), protocol=0x12
                        )
                        control, backend = self.control((chosen,), source_build=version)
                        control(DualControl("ConnectDualMon", ()))
                        self.entry(control, chosen)
                        control.before_send(chosen, deadline=2, cancelled=lambda: False)
                        control.preinit_d1_suppressed = 0
                        control.current_service = 16
                        backend.calls.clear()
                        control(DualControl("Disconnect", (flag,)))
                        expected = (
                            ["disconnect"]
                            if phase5 and flag == 0
                            else ["write", "read", "disconnect"]
                        )
                        self.assertEqual([call[0] for call in backend.calls], expected)
                        self.assertEqual(
                            control.preinit_d1_suppressed, int(phase5 and flag == 0)
                        )

    def test_native_ordinary_filter_status_is_observed_and_ignored(self):
        chosen = target(p5=True, entry_parameter=0x700)
        control, backend = self.control(
            (chosen,), backend=DualPrimitiveBackend((("start_message_filter", 9),))
        )
        control(DualControl("ConnectDualMon", ()))
        self.assertEqual(self.entry(control, chosen), 0)
        self.assertIn(("start_message_filter", 0x91010009), control.observations)
        self.assertEqual(control.registered, [chosen.command_id])
        self.assertEqual(backend.calls[-1][0], "start_message_filter")

    def test_failed_disconnect_retains_lease_and_retry_does_not_reconnect(self):
        chosen = target(p5=True, entry_parameter=0x700)
        control, backend = self.control(
            (chosen,), backend=DualPrimitiveBackend((("disconnect", 9),))
        )
        control(DualControl("ConnectDualMon", ()))
        self.entry(control, chosen)
        with self.assertRaisesRegex(MonitorError, "channel release failed"):
            control(DualControl("Disconnect", (0,)))
        self.assertEqual(control.channel, 7)
        control(DualControl("Disconnect", (0,)))
        self.assertIsNone(control.channel)
        self.assertEqual(sum(x[0] == "connect" for x in backend.calls), 1)

    def test_lower_p4_disconnect_d1_needs_no_unrelated_startup_or_tester_metadata(self):
        chosen = replace(target(entry_parameter=0x700), protocol=0x12)
        profile = self.selection(chosen)
        tester_available = [True]
        calls = []

        def frames(key):
            calls.append(key)
            if key == 0xD1 or key == 0x7F and tester_available[0]:
                return (SimpleNamespace(request=b"\x10\x01"),)
            raise AssertionError(f"Unrelated metadata requested: {key:x}")

        cast(SimpleNamespace, profile).command_frames = frames
        control, backend = self.control((chosen,), profiles={chosen.ecu: profile})
        control(DualControl("ConnectDualMon", ()))
        self.entry(control, chosen)
        control.before_send(chosen, deadline=2, cancelled=lambda: False)
        control.preinit_d1_suppressed = 0
        tester_available[0] = False
        control(DualControl("Disconnect", (0,)))
        self.assertEqual(calls, [0x7F, 0xD1])
        self.assertEqual(
            [x[0] for x in backend.calls][-3:], ["write", "read", "disconnect"]
        )
        message = backend.calls[-3][1]["message"]
        self.assertEqual(
            message.encode(),
            struct.pack("<6I", 6, 0, 0x40, 0, 6, 0) + bytes.fromhex("000007001001"),
        )
        self.assertEqual(backend.calls[-2][1]["maximum"], 0x78)

    def selection(self, chosen, *, baud=500000, address=0x700, timing=23):
        protocol = bytearray(28)
        struct.pack_into("<H", protocol, 2, 1)
        struct.pack_into("<H", protocol, 8, address)
        struct.pack_into("<H", protocol, 10, 0xFA)
        can = bytearray(28)
        struct.pack_into("<II", can, 0, 0x12345678, baud)
        struct.pack_into("<H", can, 12, 200)
        struct.pack_into("<H", can, 16, 11)
        struct.pack_into("<H", can, 18, 12)
        struct.pack_into("<H", can, 22, timing)
        category = bytearray(76)
        category[72] = chosen.category_flags
        return cast(
            VehicleProfile,
            SimpleNamespace(
                category=chosen.command_id,
                category_record=bytes(category),
                database=SimpleNamespace(sha256="a" * 64),
                ecu_database_sha256="a" * 64,
                catalog=SimpleNamespace(management=SimpleNamespace(sha256="b" * 64)),
                exception_ids=(),
                protocol_info=lambda bus: bytes(protocol),
                comm_info_can_records=lambda key: (bytes(can),),
                command_frames=lambda key: (SimpleNamespace(request=b"\x10\x01"),),
            ),
        )

    def control(self, chosen=None, *, backend=None, **kwargs):
        chosen = chosen or (target(p5=True, entry_parameter=0x700),)
        backend = backend or DualPrimitiveBackend()
        profiles = kwargs.pop("profiles", {x.ecu: self.selection(x) for x in chosen})
        return NativeDualControl(
            chosen,
            profiles,
            backend,
            driver=DriverProperties(0, b"04.04", "authored observed driver"),
            source_build=kwargs.pop("source_build", 18),
            source_identity="authored selected application-build control vector",
            connected_device=kwargs.pop("connected_device", 8),
            diagnostic_mode=kwargs.pop("diagnostic_mode", bytes(16)),
            clock=kwargs.pop("clock", lambda: 0.0),
            **kwargs,
        ), backend

    def entry(self, control, chosen):
        args = (chosen.command_id, chosen.protocol, chosen.entry_parameter or 0)
        if control.source_variant == "dual":
            args += (chosen.category_flags,)
        return control(
            DualControl(
                "EntryCommSystemInfo",
                args,
            )
        )

    def test_actual_connect_config_filter_disconnect_packets(self):
        chosen = target(p5=True, entry_parameter=0x700)
        control, backend = self.control((chosen,))
        self.assertEqual(control(DualControl("ConnectDualMon", ())), 0)
        self.assertEqual(self.entry(control, chosen), 0)
        self.assertEqual(
            [x[0] for x in backend.calls],
            ["connect", "set_config", "start_message_filter"],
        )
        self.assertEqual(backend.calls[0][1], {"protocol_id": 6, "flags": 0})
        self.assertEqual(
            backend.calls[1][1]["parameters"],
            ((1, 500000), (0x10103, 0x12345678), (0x10106, 200), (0x2A, 23)),
        )
        messages = backend.calls[2][1]["messages"]
        self.assertEqual(
            tuple(x.encode() for x in messages),
            tuple(
                struct.pack("<6I", 6, 0, 0, 0, 4, 0) + bytes.fromhex(x)
                for x in ("ffffffff", "00000708", "00000700")
            ),
        )
        control.before_send(chosen, deadline=2, cancelled=lambda: False)
        control(DualControl("Disconnect", (0,)))
        control(DualControl("Disconnect", (0,)))
        self.assertEqual([x[0] for x in backend.calls][-1:], ["disconnect"])
        self.assertEqual(sum(x[0] == "disconnect" for x in backend.calls), 1)

    def test_first_config_fallback_drops_only_last_optional_parameter(self):
        chosen = target(p5=True, entry_parameter=0x700)
        backend = DualPrimitiveBackend((("set_config", 9),))
        control, _ = self.control((chosen,), backend=backend)
        control(DualControl("ConnectDualMon", ()))
        self.assertEqual(self.entry(control, chosen), 0)
        configs = [x[1]["parameters"] for x in backend.calls if x[0] == "set_config"]
        self.assertEqual(configs[0][:-1], configs[1])
        self.assertEqual(configs[0][-1], (0x2A, 23))
        self.assertIn(("set_config", 0x91010009), control.observations)

    def test_failed_both_configs_disconnects_and_entry_reports_native_status(self):
        chosen = target(p5=True, entry_parameter=0x700)
        control, backend = self.control(
            (chosen,),
            backend=DualPrimitiveBackend((("set_config", 9), ("set_config", 8))),
        )
        control(DualControl("ConnectDualMon", ()))
        self.assertEqual(self.entry(control, chosen), 0x91010008)
        self.assertEqual(
            [x[0] for x in backend.calls],
            ["connect", "set_config", "set_config", "disconnect"],
        )
        self.assertIsNone(control.channel)

    def test_device4_pass_filter_and_extended22_fallback_literal_five_bytes(self):
        chosen = replace(target(p5=True, entry_parameter=0x700), protocol=0x22)
        control, backend = self.control((chosen,), connected_device=4)
        control(DualControl("ConnectDualMon", ()))
        self.assertEqual(self.entry(control, chosen), 0)
        filters = [x[1] for x in backend.calls if x[0] == "start_message_filter"]
        self.assertEqual([x["filter_type"] for x in filters], [1, 3])
        self.assertEqual(filters[0]["messages"][0].data, bytes.fromhex("000007ff"))
        self.assertEqual(
            tuple(x.data for x in filters[1]["messages"]),
            tuple(bytes.fromhex(x) for x in ("ffffffffff", "00000708fa", "00000700fa")),
        )
        self.assertTrue(all(x.tx_flags == 0xC0 for x in filters[1]["messages"]))

    def test_secondary_target_configuration_refresh_before_each_native_send(self):
        first = target(p5=True, entry_parameter=0x700)
        second = replace(
            target(0x710, 0x718, p5=True, entry_parameter=0x700), command_id=100
        )
        profiles = {
            first.ecu: self.selection(first),
            second.ecu: self.selection(second, baud=250000),
        }
        control, backend = self.control((first, second), profiles=profiles)
        control(DualControl("ConnectDualMon", ()))
        self.entry(control, first)
        self.entry(control, second)
        self.assertTrue(control.refresh_configs)
        control.before_send(second, deadline=2, cancelled=lambda: False)
        control.before_send(first, deadline=2, cancelled=lambda: False)
        self.assertEqual(
            [x[1]["parameters"][0] for x in backend.calls if x[0] == "set_config"],
            [(1, 500000), (1, 250000), (1, 500000)],
        )

    def test_connect_cancellation_after_resource_creation_preserves_channel_for_cleanup(
        self,
    ):
        chosen = target(p5=True, entry_parameter=0x700)
        cancelled = [False]

        class Backend(DualPrimitiveBackend):
            def invoke(self, operation, fields, *, deadline, cancelled):
                result = super().invoke(
                    operation, fields, deadline=deadline, cancelled=cancelled
                )
                if operation == "connect":
                    stop[0] = True
                return result

        stop = cancelled
        control, backend = self.control((chosen,), backend=Backend())
        with self.assertRaises(Cancelled):
            control.execute(
                DualControl("ConnectDualMon", ()),
                deadline=2,
                cancelled=lambda: cancelled[0],
            )
        self.assertEqual(control.channel, 7)
        control.execute(
            DualControl("Disconnect", (0,)), deadline=2, cancelled=lambda: False
        )
        self.assertIsNone(control.channel)
        self.assertEqual(backend.calls[-1][0], "disconnect")

    def test_runtime_uses_concrete_control_and_selected_source_version(self):
        chosen = target(p5=True, entry_parameter=0x700)
        control, backend = self.control((chosen,))
        provider = Provider((reply("50 03"), reply("62 12 34 aa bb")))
        monitor = runtime(
            provider,
            (chosen,),
            driver_control=control,
            command_cache={(0x700, 0xDD): b"\x10\x03"},
        )
        monitor.configure(0x700, p5())
        self.assertEqual(monitor.run_packets()[0].payload, b"\xaa\xbb")
        monitor.close()
        self.assertEqual(
            [x[0] for x in backend.calls],
            [
                "connect",
                "set_config",
                "start_message_filter",
                "set_config",
                "start_message_filter",
                "disconnect",
            ],
        )
        with self.assertRaisesRegex(MonitorError, "application source"):
            runtime(Provider(), (chosen,), driver_control=control, version=12)


if __name__ == "__main__":
    unittest.main()


class NativeDualTransportTests(unittest.TestCase):
    def test_lower_owner_binding_is_atomic_and_cannot_be_replaced(self):
        import copy

        monitor, control, operations, _ = self.joined()
        plans = cast(NativeDualTransport, monitor.provider).plans
        control._lower = None
        with self.assertRaisesRegex(MonitorError, "frame plans"):
            NativeDualTransport(control, operations, {})
        self.assertIsNone(control._lower)
        control._lower = operations
        with self.assertRaisesRegex(MonitorError, "contexts differ"):
            NativeDualTransport(control, copy.copy(operations), plans)
        self.assertIs(control._lower, operations)

    def test_direct_native12_no_init_seam_rejects_ushort_length_before_io(self):
        monitor, control, _, backend = self.joined(version=12)
        chosen = next(iter(control.selected.values()))[0]
        transport = cast(NativeDualTransport, monitor.provider)
        with self.assertRaisesRegex(MonitorError, "BYTE length"):
            transport.send_frame(
                chosen,
                NativeFrameSend(
                    "SendIntNoInitNoSession",
                    chosen.command_id,
                    bytes(256),
                    1000,
                    chosen.protocol,
                ),
                deadline=2,
                cancelled=lambda: False,
            )
        self.assertEqual(backend.calls, [])

    def joined(
        self,
        *,
        version: Literal[12, 18] = 18,
        count=1,
        mutate=False,
        write_code=0,
        change_lower=False,
        management_only=False,
    ):
        from test_frame_transport import selected_profile

        from scripts.diagnostic_db import Section
        from scripts.frame_transport import (
            J2534Result,
            NativeFrameOperations,
            runtime_frame_plan,
        )
        from scripts.frame_transport import (
            NativeMessage as J2534Message,
        )

        profile = selected_profile(version=version, flags=3)
        settings = struct.pack("<II", 1000, 200) + bytes(8)
        profile.catalog.management = replace(
            profile.catalog.management,
            sections={
                **profile.catalog.management.sections,
                29: Section(29, 0, 1, False, settings),
            },
        )
        if management_only:
            profile = ProtocolProfile(
                profile.catalog,
                profile.category_record,
                profile.exception_ids,
                profile.vehicle_name_key,
            )
        chosen = DualTarget(
            "typed-ecu", 0x7E0, 0x7E8, 0x12, 3, 42, 1, entry_parameter=0x7E0
        )
        driver = DriverProperties(0, b"04.04", "authored observed driver")
        clock = lambda: 0.0

        class Backend:
            def __init__(self):
                self.calls = []

            def invoke(self, operation, fields, *, deadline, cancelled):
                self.calls.append((operation, fields, deadline))
                if operation == "connect":
                    return J2534Result(handle=7)
                if operation == "start_message_filter":
                    return J2534Result(handle=8)
                if operation == "write_messages":
                    if change_lower:
                        operations.plan = replace(operations.plan, address=0x777)
                    return J2534Result(code=write_code, count=count)
                if operation == "read_messages":
                    if mutate:
                        profile.catalog.management = replace(
                            profile.catalog.management, sha256="new-source"
                        )
                    return J2534Result(
                        count=1,
                        messages=(
                            J2534Message(
                                6, 0, 0, 0, 0, bytes.fromhex("000007e8 61 10 aa bb")
                            ),
                        ),
                    )
                return J2534Result()

        backend = Backend()
        control = NativeDualControl(
            (chosen,),
            {chosen.ecu: profile},
            NativeDualPrimitives(backend),
            driver=driver,
            source_build=version,
            source_identity="authored typed backend vector",
            connected_device=8,
            diagnostic_mode=bytes(16),
            clock=clock,
        )
        plan = runtime_frame_plan(
            profile,
            b"\x21\x10",
            native_build=version,
            native_variant="dual",
            bus_id=0x12,
            driver=driver,
        )
        operations = NativeFrameOperations(
            profile,
            plan,
            backend,
            native_build=version,
            bus_id=0x12,
            driver=driver,
            device_kind=8,
            native_variant="dual",
            clock=clock,
            wait=lambda seconds: None,
        )
        transport = NativeDualTransport(control, operations, {chosen.ecu: plan})
        monitor = DualMonitorRuntime(
            (chosen,),
            transport,
            version=version,
            clock=clock,
            tick_ms=Tick(),
            driver_control=control,
        )
        monitor.configure(chosen.request_id, p4(request=chosen.request_id))
        return monitor, control, operations, backend

    def test_management_only_profile_runs_typed_dual_without_an_ecu_database(self):
        for version in cast(tuple[Literal[12, 18], ...], (12, 18)):
            with self.subTest(version=version):
                monitor, control, operations, backend = self.joined(
                    version=version, management_only=True
                )
                self.assertIsInstance(operations.profile, ProtocolProfile)
                self.assertNotIsInstance(operations.profile, VehicleProfile)
                self.assertFalse(hasattr(operations.profile, "database"))
                self.assertEqual(monitor.run_packets()[0].payload, b"\xaa\xbb")
                monitor.close()
                self.assertIsNone(control.channel)
                self.assertEqual(
                    [call[0] for call in backend.calls].count("disconnect"), 1
                )

    def test_literal_dual_wrapper_ignores_parameter6_and_always_selects_mode_two(self):
        from unittest.mock import patch

        for version in cast(tuple[Literal[12, 18], ...], (12, 18)):
            for parameter6 in (-1, 0, 1, 2, 0x7FFFFFFF):
                with self.subTest(version=version, parameter6=parameter6):
                    monitor, control, operations, backend = self.joined(version=version)
                    monitor.start()
                    transport = cast(NativeDualTransport, monitor.provider)
                    chosen = next(iter(control.selected.values()))[0]
                    with patch.object(operations, "send", return_value=0) as send:
                        transport.send_frame(
                            chosen,
                            NativeFrameSend(
                                "SendIntExtDualMon",
                                chosen.command_id,
                                b"\x21\x10",
                                1000,
                                chosen.protocol,
                                parameter6,
                                -1,
                            ),
                            deadline=2,
                            cancelled=lambda: False,
                        )
                    self.assertEqual(send.call_args.kwargs["initialization_mode"], 2)
                    self.assertEqual(send.call_args.kwargs["clear_rx"], -1)
                    self.assertFalse(send.call_args.kwargs["no_session"])
                    control.close_resources(deadline=2, cancelled=lambda: False)
                    self.assertEqual(
                        [call[0] for call in backend.calls].count("disconnect"), 1
                    )

    def test_concrete_shared_channel_produces_packets_in_both_builds(self):
        for version in cast(tuple[Literal[12, 18], ...], (12, 18)):
            with self.subTest(version=version):
                monitor, control, operations, backend = self.joined(version=version)
                packets = monitor.run_packets()
                self.assertEqual(packets[0].payload, b"\xaa\xbb")
                self.assertEqual(
                    [call[0] for call in backend.calls].count("connect"), 1
                )
                writes = [
                    fields
                    for operation, fields, _ in backend.calls
                    if operation == "write_messages"
                ]
                self.assertEqual(
                    writes[0]["messages"][0].data, bytes.fromhex("000007e0 21 10")
                )
                self.assertEqual(writes[0]["channel_id"], 7)
                self.assertFalse(operations.owns_channel)
                monitor.close()
                self.assertIsNone(control.channel)
                self.assertEqual(
                    [call[0] for call in backend.calls].count("disconnect"), 1
                )

    def test_concrete_native_write_fault_enters_error_without_read(self):
        monitor, control, _, backend = self.joined(write_code=9)
        with self.assertRaises(MonitorError):
            monitor.run_packets()
        self.assertIn(DualState.ERROR, monitor.transitions)
        self.assertEqual(monitor.faults[-1].provider_code, 0x91010009)
        self.assertFalse(any(call[0] == "read_messages" for call in backend.calls))
        monitor.close()
        self.assertIsNone(control.channel)

    def test_concrete_callback_cannot_change_selected_lower_plan(self):
        monitor, control, _, backend = self.joined(change_lower=True)
        with self.assertRaisesRegex(MonitorError, "lower binding changed"):
            monitor.run_packets()
        self.assertTrue(control.poisoned)
        self.assertEqual(monitor.drain(0x7E0), ())
        self.assertFalse(any(call[0] == "read_messages" for call in backend.calls))
        monitor.close()
        self.assertIsNone(control.channel)

    def test_concrete_repeat_acquisition_rebinds_reused_channel_id(self):
        monitor, control, operations, backend = self.joined()
        self.assertEqual(monitor.run_packets()[0].payload, b"\xaa\xbb")
        operations.current_service = 255
        operations.request_state = 4
        operations.pending_count = 99
        self.assertEqual(monitor.run_packets()[0].payload, b"\xaa\xbb")
        self.assertEqual(operations.current_service, 0)
        self.assertEqual(operations.request_state, 0)
        self.assertEqual(operations.pending_count, 0)
        self.assertEqual(control.channel_generation, 2)
        monitor.close()
        self.assertIsNone(operations.channel)
        self.assertEqual([call[0] for call in backend.calls].count("connect"), 2)
        self.assertEqual([call[0] for call in backend.calls].count("disconnect"), 2)

    def test_concrete_write_requires_confirmed_count_and_releases_owned_channel(self):
        monitor, control, _, backend = self.joined(count=0)
        with self.assertRaisesRegex(OSError, "confirm its requested count"):
            monitor.run_packets()
        monitor.close()
        self.assertIsNone(control.channel)
        self.assertEqual([call[0] for call in backend.calls].count("disconnect"), 1)

    def test_concrete_read_source_change_cannot_publish_packet(self):
        monitor, control, _, backend = self.joined(mutate=True)
        with self.assertRaisesRegex(MonitorError, "source identity"):
            monitor.run_packets()
        self.assertEqual(monitor.drain(0x7E0), ())
        with self.assertRaisesRegex(MonitorError, "source identity"):
            monitor.close()
        self.assertIsNone(control.channel)
        self.assertEqual([call[0] for call in backend.calls].count("disconnect"), 1)
