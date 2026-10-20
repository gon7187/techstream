"""Literal synthetic low-level observations; no device or OEM execution."""

import unittest

from scripts.data_monitor import MonitorError, MonitorReceive
from scripts.monitor_legacy import (
    LegacyMonitorEvent,
    Phase3Stream,
    pack_legacy_pairs,
    pack_phase3_mode1,
)


class LegacyEvents(unittest.TestCase):
    def test_psa_short_replies_and_cycle_clear(self):
        event = LegacyMonitorEvent.psa(
            (3, 8), (2, 1), addition_frames=((8, b"\x01\x02"),)
        )
        self.assertEqual(event.request, b"\x21\x03")
        self.assertIsNone(event.accept(b"\x61\x03\xaa", 7))
        self.assertEqual(event.request, b"\x21\x08\x01\x02")
        self.assertEqual(event.accept(b"\x61\x08\xbb\xcc", 8), (8, b"\xaa\x00\xbb"))
        event.accept(b"\x61\x03", 9)
        self.assertEqual(event.accept(b"\x61\x08", 10), (10, b"\x00\x00\x00"))

    def test_dk_no_service_check_and_dtc_leading_nonzero_count(self):
        event = LegacyMonitorEvent.dk_iso9141((7,), (2,), dtc_request=b"\x03")
        self.assertEqual(event.request, b"\x2c\x07")
        self.assertIsNone(event.accept(b"\x99\xaa", 1))
        self.assertEqual(event.request, b"\x13\x03")
        self.assertEqual(event.accept(b"\x19\x22\x00\x33", 2), (2, b"\xaa\x00\x02"))

    def test_malformed_does_not_advance(self):
        for event, reply in (
            (LegacyMonitorEvent.psa((1,), (2,)), b"\x61"),
            (LegacyMonitorEvent.dk_iso9141((1,), (2,)), b""),
        ):
            with self.assertRaises(MonitorError):
                event.accept(reply, 0)
            self.assertEqual(event.index, 0)
        with self.assertRaises(MonitorError):
            LegacyMonitorEvent.psa((1,), (0,))

    def test_phase3_mode1_sorted_pid_and_ff_filler(self):
        plan = pack_phase3_mode1({9: 1, 2: 2}, maximum_request=8)
        self.assertEqual(plan.setup_requests, (b"\xa1\x01\x02\xff\x09",))
        self.assertEqual(plan.frame_sizes, ((1, 3),))
        self.assertEqual(plan.pid_layouts, ((2, 1, 0, 2), (9, 1, 2, 1)))
        with self.assertRaises(MonitorError) as caught:
            pack_phase3_mode1({1: 4, 2: 4}, maximum_request=8)
        self.assertEqual(caught.exception.code, 0x9005100A)

    def test_pairs_preserve_native_selected_order(self):
        plan = pack_legacy_pairs("PSA", ((9, 0), (3, 2)), {9: 3, 3: 2}, mode=0x20)
        self.assertEqual(plan.setup_requests, (b"\x21\x09\x03", b"\x61\x03\x02"))
        self.assertEqual(plan.frame_sizes, ((0, 3), (1, 2)))


class FakeProvider:
    def __init__(self, receives=(), sends=()):
        self.receives = iter(receives)
        self.sends = iter(sends)
        self.calls = []

    def send(self, ecu, request, **kwargs):
        self.calls.append(("send", ecu, request, kwargs))
        return next(self.sends, 0)

    def receive(self, ecu, **kwargs):
        self.calls.append(("receive", ecu, kwargs))
        return next(self.receives)


class Phase3Runtime(unittest.TestCase):
    def test_setup_ack_retry_and_receive(self):
        provider = FakeProvider(
            (
                MonitorReceive(b"", 4, 9),
                MonitorReceive(b"\xe1\x01\x02", 4, 0),
                MonitorReceive(b"\xe2\xaa\xbb", 4, 0),
            )
        )
        stream = Phase3Stream(
            provider,
            "ecu",
            source_id=4,
            protocol=3,
            request=b"\xa1\x01\x02",
            retries=1,
            send_timeout=20,
            receive_timeout=30,
            interval=10,
        )
        stream.start(tick_ms=lambda: 1)
        self.assertEqual(stream.state, 2)
        self.assertEqual(stream.poll(7), (7, b"\xaa\xbb"))
        self.assertEqual(stream.state, 4)
        self.assertEqual(len([x for x in provider.calls if x[0] == "send"]), 2)
        stream.resume(17)
        self.assertEqual(provider.calls[-1][2], b"\xa2\x01")
        stream.stop()
        self.assertEqual(provider.calls[-1][2], b"\xa3")
        self.assertEqual(stream.state, 6)

    def test_no_ack_branch_and_ignored_source(self):
        provider = FakeProvider(
            (MonitorReceive(b"\xe2\x11", 9, 0), MonitorReceive(b"\xe3", 4, 0))
        )
        stream = Phase3Stream(
            provider,
            "ecu",
            source_id=4,
            protocol=3,
            request=b"\xa1\x04",
            retries=0,
            send_timeout=20,
            receive_timeout=30,
            interval=0,
        )
        stream.start(tick_ms=lambda: 0)
        self.assertEqual(provider.calls, [])
        self.assertIsNone(stream.poll(1))
        stream.stop()
        self.assertIsNone(stream.poll(2))
        self.assertEqual(stream.state, 0)

    def test_fault_cancel_and_bounded_ack(self):
        provider = FakeProvider(sends=(99,))
        stream = Phase3Stream(
            provider,
            "ecu",
            source_id=4,
            protocol=3,
            request=b"\xa1\x01",
            retries=0,
            send_timeout=20,
            receive_timeout=30,
            interval=0,
        )
        with self.assertRaises(MonitorError) as caught:
            stream.start(tick_ms=lambda: 0)
        self.assertEqual(caught.exception.code, 99)
        with self.assertRaises(MonitorError):
            Phase3Stream(
                provider,
                "ecu",
                source_id=4,
                protocol=3,
                request=b"\xa1",
                retries=0,
                send_timeout=20,
                receive_timeout=30,
                interval=0,
            )
        from scripts.toyota_session import Cancelled

        with self.assertRaises(Cancelled):
            stream.start(tick_ms=lambda: 0, cancelled=lambda: True)


class DkProviderCycle(unittest.TestCase):
    def test_literal_retry_same_request_then_packet(self):
        from scripts.monitor_legacy import dk_monitor_cycle

        event = LegacyMonitorEvent.dk_iso9141((4,), (1,))
        provider = FakeProvider(
            (MonitorReceive(b"", 0, 1), MonitorReceive(b"\x00\xaa", 0, 0))
        )
        self.assertEqual(
            dk_monitor_cycle(
                event,
                provider,
                "ecu",
                protocol=9,
                send_timeout=10,
                receive_timeout=20,
                retry_limit=2,
                tick_ms=lambda: 77,
            ),
            (77, b"\xaa"),
        )
        self.assertEqual(
            [call[2] for call in provider.calls if call[0] == "send"],
            [b"\x2c\x04", b"\x2c\x04"],
        )
        self.assertEqual(
            provider.calls[0][3], {"timeout": 10, "protocol": 9, "initialize": True}
        )

    def test_dtc_receive_fault_is_not_retried(self):
        from scripts.monitor_legacy import dk_monitor_cycle

        event = LegacyMonitorEvent.dk_iso9141((), (), dtc_request=b"")
        provider = FakeProvider((MonitorReceive(b"", 0, 1),))
        with self.assertRaises(MonitorError) as caught:
            dk_monitor_cycle(
                event,
                provider,
                "ecu",
                protocol=9,
                send_timeout=10,
                receive_timeout=20,
                retry_limit=8,
                tick_ms=lambda: 0,
            )
        self.assertEqual(caught.exception.code, 0xE0040001)
        self.assertEqual(len(provider.calls), 2)


class LegacyCommands(unittest.TestCase):
    def test_literal_pair_commands(self):
        from scripts.monitor_legacy import legacy_pair_commands

        plan = pack_legacy_pairs("P3", ((3, 2),), {3: 2}, mode=0x100)
        setup = legacy_pair_commands(
            plan,
            interface_id=5,
            buffer_468=7,
            standard_values=((9, 10),),
            parameter_8=0x1234,
        )
        self.assertEqual(setup.setup[0].command_id, 0x10A)
        self.assertEqual(
            setup.setup[0].values, (7, 5, 3, ((3, 2),), 2, ((9, 10),), 3, 0x1234)
        )
        self.assertEqual(setup.start[0].command_id, 0x10C)
        self.assertEqual(setup.stop[0].command_id, 0x10E)


class SelectedProducer(unittest.TestCase):
    def test_selected_db_to_metadata_and_dmci(self):
        import struct
        from types import SimpleNamespace
        from typing import cast

        from scripts.monitor_legacy import selected_phase3_pairs
        from scripts.profiles import VehicleProfile

        freeze = bytearray(84)
        freeze[:4] = b"RPM\0"
        struct.pack_into("<H", freeze, 56, 17)
        struct.pack_into("<H", freeze, 60, 2)
        struct.pack_into("<HH", freeze, 62, 8, 15)
        freeze[78:80] = bytes((1, 9))
        phy = bytearray(24)
        struct.pack_into("<IIIH", phy, 0, 3, 4, 5, 2)
        category = bytearray(76)
        category[72] = 3
        profile = cast(
            VehicleProfile,
            SimpleNamespace(
                category=1,
                category_record=bytes(category),
                records=lambda slot: {
                    10: (bytes(freeze),),
                    13: (bytes(phy),),
                    14: (),
                    15: (),
                }[slot],
                ecu_database_sha256="authored",
                database=SimpleNamespace(sha256="authored"),
                catalog=SimpleNamespace(
                    management=SimpleNamespace(sha256="authored-management"),
                    language=SimpleNamespace(resolve=lambda key: ""),
                ),
            ),
        )
        observed = {
            key: key == 11 for key in (22, 10, 8, 9, 12, 25, 11, 26, 29, 27, 28, 35)
        }
        result = selected_phase3_pairs(
            profile,
            (17,),
            {9: 2},
            observed,
            mode=0x10,
            interface_id=5,
            parameter_8=0xFFFFFFFF,
            standard_values=(),
        )
        self.assertEqual(result.packing.setup_requests, (b"\x01\x09", b"\x41\x02"))
        self.assertEqual(
            (
                result.signals[0].pid,
                result.signals[0].frame_index,
                result.signals[0].start_bit,
                result.signals[0].end_bit,
            ),
            (17, 0, 8, 15),
        )
        self.assertEqual(result.signals[0].short_name, b"RPM")
        self.assertEqual(
            result.commands.setup[0].values, (1, 5, 0, ((9, 2),), 2, (), 3, 0xFFFFFFFF)
        )
        with self.assertRaises(MonitorError):
            selected_phase3_pairs(
                profile,
                (17,),
                {9: 1},
                observed,
                mode=0x10,
                interface_id=5,
                parameter_8=0xFFFFFFFF,
                standard_values=(),
            )


class FixedPackets(unittest.TestCase):
    def test_native_cache_matching_pid_scan(self):
        from scripts.monitor_legacy import pack_phase3_mode2

        plan = pack_phase3_mode2(
            (9,),
            {9: 1, 3: 2, 7: 2},
            {3: (True, 0), 7: (True, 1), 9: (True, 1)},
            ((5, 3), (8, 1)),
            maximum_reply=8,
        )
        self.assertEqual(plan.setup_requests, (b"\xa1\x04",))
        self.assertEqual(plan.pid_layouts, ((3, 5, 0, 2), (7, 5, 2, 1), (9, 8, 0, 1)))
        self.assertEqual(plan.frame_sizes, ((5, 3), (8, 1)))

    def test_native_fixed_packet_errors(self):
        from scripts.monitor_legacy import pack_phase3_mode2

        for definitions, frames, code in (
            ({1: (False, 1)}, ((2, 1),), 0x90051008),
            ({1: (True, 2)}, ((2, 1),), 0x90051013),
            ({1: (True, 1)}, ((2, 2),), 0x90051014),
            ({1: (True, 1)}, ((255, 1),), 0x90051009),
        ):
            with self.assertRaises(MonitorError) as caught:
                pack_phase3_mode2((1,), {1: 1}, definitions, frames, maximum_reply=8)
            self.assertEqual(caught.exception.code, code)


class Dlc12Producer(unittest.TestCase):
    def test_single_pid_and_exact_setup_priority(self):
        from scripts.monitor_legacy import dlc12_setup_commands, pack_dlc12_ranges

        plan = pack_dlc12_ranges(((8, 0, 7, 1), (9, 8, 23, 1)), capabilities=0x1800)
        self.assertEqual(plan.setup_requests, (b"\xa1\x01", b"\xe1\x03"))
        self.assertEqual(plan.frame_sizes, ((0, 3),))
        commands = dlc12_setup_commands(plan, interface_id=7, buffer_468=9)
        self.assertEqual(
            commands.setup[0].values, (9, 7, 0, ((1, 3),), 3, (), 3, 0xFFFFFFFF)
        )
        plan = pack_dlc12_ranges(((8, 0, 7, 1),), capabilities=0x1800, excluded=0x800)
        self.assertEqual(
            dlc12_setup_commands(plan, interface_id=7, buffer_468=9).setup[0].values[2],
            1,
        )

    def test_native_byte_end_wrap_and_invalid_source(self):
        from scripts.monitor_legacy import pack_dlc12_ranges

        self.assertEqual(
            pack_dlc12_ranges(
                ((8, 0, 300, 1), (9, 0, 100, 1)), capabilities=0x2000
            ).frame_sizes,
            ((0, 13),),
        )
        with self.assertRaises(MonitorError):
            pack_dlc12_ranges(((8, 0, 7, 2),), capabilities=0x2000)


class SelectedDlc12(unittest.TestCase):
    def test_profile_to_signal_and_setup(self):
        import struct
        from types import SimpleNamespace
        from typing import cast

        from scripts.monitor_legacy import selected_dlc12_monitor
        from scripts.profiles import VehicleProfile

        freeze = bytearray(84)
        struct.pack_into("<H", freeze, 56, 17)
        struct.pack_into("<H", freeze, 60, 2)
        struct.pack_into("<HH", freeze, 62, 8, 15)
        freeze[79] = 1
        phy = bytearray(24)
        struct.pack_into("<IIIH", phy, 0, 3, 4, 5, 2)
        profile = cast(
            VehicleProfile,
            SimpleNamespace(
                category=3,
                category_record=bytes(76),
                records=lambda slot: {
                    10: (bytes(freeze),),
                    13: (bytes(phy),),
                    14: (),
                    15: (),
                }[slot],
                ecu_database_sha256="authored",
                database=SimpleNamespace(sha256="authored"),
                catalog=SimpleNamespace(
                    management=SimpleNamespace(sha256="authored-management"),
                    language=SimpleNamespace(resolve=lambda key: ""),
                ),
            ),
        )
        observed = {
            key: key == 29 for key in (22, 10, 8, 9, 12, 25, 11, 26, 29, 27, 28, 35)
        }
        result = selected_dlc12_monitor(profile, (17,), observed, interface_id=9)
        self.assertEqual(result.packing.setup_requests, (b"\xa1\x01", b"\xe1\x02"))
        self.assertEqual(
            (
                result.signals[0].frame_index,
                result.signals[0].start_bit,
                result.signals[0].end_bit,
            ),
            (0, 8, 15),
        )
        self.assertEqual(
            result.commands.setup[0].values, (3, 9, 2, ((1, 2),), 2, (), 3, 0xFFFFFFFF)
        )


class DriverBoundaries(unittest.TestCase):
    def test_cancel_after_driver_send_before_receive(self):
        from scripts.monitor_legacy import dk_monitor_cycle
        from scripts.toyota_session import Cancelled

        provider = FakeProvider()
        event = LegacyMonitorEvent.dk_iso9141((1,), (1,))
        with self.assertRaises(Cancelled):
            dk_monitor_cycle(
                event,
                provider,
                "ecu",
                protocol=9,
                send_timeout=10,
                receive_timeout=20,
                retry_limit=2,
                tick_ms=lambda: 0,
                cancelled=lambda: bool(provider.calls),
            )
        self.assertEqual(len(provider.calls), 1)
        self.assertEqual(event.index, 0)

    def test_driver_budget_exhaustion_and_timeout_mapping(self):
        from scripts.monitor_legacy import dk_monitor_cycle

        for maximum_calls, sends, expected in (
            (0, (), None),
            (2, (0x90020328,), 0xE0001001),
        ):
            provider = FakeProvider(sends=sends)
            event = LegacyMonitorEvent.dk_iso9141((1,), (1,))
            with self.assertRaises(MonitorError) as caught:
                dk_monitor_cycle(
                    event,
                    provider,
                    "ecu",
                    protocol=9,
                    send_timeout=1,
                    receive_timeout=1,
                    retry_limit=1,
                    tick_ms=lambda: 0,
                    maximum_calls=maximum_calls,
                )
            self.assertEqual(caught.exception.code, expected)

    def test_unmatched_phase3_ack_bound(self):
        provider = FakeProvider((MonitorReceive(b"\xe1\x02", 4, 0),))
        stream = Phase3Stream(
            provider,
            "ecu",
            source_id=4,
            protocol=3,
            request=b"\xa1\x01",
            retries=0,
            send_timeout=1,
            receive_timeout=2,
            interval=0,
        )
        with self.assertRaises(MonitorError) as caught:
            stream.start(tick_ms=lambda: 0, maximum_receives=1)
        self.assertEqual(caught.exception.code, 0xA1050302)
        self.assertEqual(stream.state, 1)


class Dlc12Interface(unittest.TestCase):
    def test_selected_function6b_constructor_bytes(self):
        import struct
        from types import SimpleNamespace
        from typing import cast

        from scripts.diagnostic_db import Section
        from scripts.monitor_legacy import dlc12_interface_commands
        from scripts.profiles import VehicleProfile

        function = bytearray(16)
        struct.pack_into("<HHHHHH", function, 0, 3, 0x6B, 0, 7, 0, 0)
        communication = struct.pack("<HHHH", 7, 1, 2, 0)
        variables = struct.pack("<IHIH", 0, 1, 1, 2) + b"\xa7\x34\x12"
        management = SimpleNamespace(
            sha256="authored-management",
            kind=1,
            version=0x0100032F,
            sections={
                18: Section(18, 0, 1, False, bytes(function)),
                17: Section(17, 0, 1, False, communication),
                0: Section(0, 0, 2, False, variables),
            },
        )
        profile = cast(
            VehicleProfile,
            SimpleNamespace(
                category=3,
                exception_ids=(),
                catalog=SimpleNamespace(management=management),
            ),
        )
        result = dlc12_interface_commands(profile, connected_device=4)
        self.assertEqual(
            (result.setup[0].command_id, result.setup[0].values),
            (0x105, (0xA7, 0x1234)),
        )
        self.assertEqual(result.stop[0].command_id, 0x106)
        with self.assertRaises(MonitorError) as caught:
            dlc12_interface_commands(profile, connected_device=8)
        self.assertEqual(caught.exception.code, 0xC0051302)


class SelectedDk(unittest.TestCase):
    def test_selected_dk_mode200_to_actual_2c_packet(self):
        import struct
        from types import SimpleNamespace
        from typing import cast

        from scripts.monitor_legacy import dk_monitor_cycle, selected_dk_monitor
        from scripts.profiles import VehicleProfile

        freeze = bytearray(84)
        struct.pack_into("<H", freeze, 56, 17)
        struct.pack_into("<H", freeze, 60, 2)
        struct.pack_into("<HH", freeze, 62, 8, 15)
        freeze[79] = 9
        phy = bytearray(24)
        struct.pack_into("<IIIH", phy, 0, 3, 4, 5, 2)
        category = bytearray(76)
        category[72] = 7
        profile = cast(
            VehicleProfile,
            SimpleNamespace(
                category=3,
                exception_ids=(),
                category_record=bytes(category),
                records=lambda slot: {
                    10: (bytes(freeze),),
                    13: (bytes(phy),),
                    14: (),
                    15: (),
                }[slot],
                ecu_database_sha256="authored",
                database=SimpleNamespace(sha256="authored"),
                catalog=SimpleNamespace(
                    management=SimpleNamespace(sha256="authored-management"),
                    language=SimpleNamespace(resolve=lambda key: ""),
                ),
            ),
        )
        observed = {
            key: key == 26 for key in (22, 10, 8, 9, 12, 25, 11, 26, 29, 27, 28, 35)
        }
        result = selected_dk_monitor(profile, (17,), {9: 2}, observed)
        self.assertEqual(result.packing.setup_requests, (b"\x2c\x09", b"\x6c\x02"))
        provider = FakeProvider((MonitorReceive(b"\x6c\xaa\xbb", 0, 0),))
        self.assertEqual(
            dk_monitor_cycle(
                result.event,
                provider,
                "ecu",
                protocol=9,
                send_timeout=1,
                receive_timeout=1,
                retry_limit=3,
                tick_ms=lambda: 7,
            ),
            (7, b"\xaa\xbb"),
        )
        self.assertEqual(result.signals[0].frame_index, 0)
        self.assertEqual(result.signals[0].start_bit, 8)


class Phase3Packets(unittest.TestCase):
    def test_capture_byte_budget_includes_timestamp_at_exact_boundary(self):
        from unittest.mock import patch

        from scripts.monitor_legacy import Phase3PacketGenerator, run_phase3_stream

        provider = FakeProvider(
            (MonitorReceive(b"\xe2\x01\xaa\xbb", 7, 0), MonitorReceive(b"\xe3", 7, 0))
        )
        stream = Phase3Stream(
            provider,
            "engine",
            source_id=7,
            protocol=3,
            request=b"\xa1\x04",
            retries=0,
            send_timeout=9,
            receive_timeout=10,
            interval=30,
        )
        with patch("scripts.monitor_legacy.MAX_BYTES", 6):
            with self.assertRaises(MonitorError):
                run_phase3_stream(
                    stream,
                    Phase3PacketGenerator(((1, 2),)),
                    packet_limit=2,
                    tick_ms=lambda: 20,
                )
            self.assertFalse(provider.calls)
            self.assertEqual(
                run_phase3_stream(
                    stream,
                    Phase3PacketGenerator(((1, 2),)),
                    packet_limit=1,
                    tick_ms=lambda: 20,
                ),
                ((20, b"\xaa\xbb"),),
            )

    def test_actual_e2_frame_id_to_complete_packet(self):
        from scripts.monitor_legacy import Phase3PacketGenerator

        generator = Phase3PacketGenerator(((1, 2), (4, 1)))
        self.assertEqual(generator.append(b"\x01\xaa\xbb", 1), ())
        self.assertEqual(generator.append(b"\x04\xcc", 2), ((2, b"\xaa\xbb\xcc"),))
        self.assertEqual(generator.append(b"\x04\xdd", 3), ((3, b"\xaa\xbb\xdd"),))
        self.assertEqual(generator.append(b"\x88\x11", 4), ((4, b"\xaa\xbb\xdd"),))

    def test_no_invented_initial_cache_and_native_overflow_discard(self):
        from scripts.monitor_legacy import Phase3PacketGenerator

        generator = Phase3PacketGenerator(((1, 2), (4, 1)))
        with self.assertRaises(MonitorError):
            generator.append(b"\x04\xaa", 1)
        generator = Phase3PacketGenerator(((1, 2),))
        self.assertEqual(generator.append(b"\x01\xaa\xbb\xcc", 2), ((2, b"\xaa\xbb"),))

    def test_native_scheduler_starts_with_a2_then_timeout(self):
        provider = FakeProvider()
        stream = Phase3Stream(
            provider,
            "ecu",
            source_id=4,
            protocol=3,
            request=b"\xa1\x04",
            retries=0,
            send_timeout=1,
            receive_timeout=2,
            interval=10,
        )
        stream.start(tick_ms=lambda: 0)
        stream.advance(1)
        self.assertEqual(provider.calls[0][2], b"\xa2\x04")
        self.assertEqual(stream.deadline, 11)
        stream.advance(10)
        with self.assertRaises(MonitorError) as caught:
            stream.advance(11)
        self.assertEqual(caught.exception.code, 0xA1050308)

    def test_phase1_native_timestamp_complement_and_zero_fragment(self):
        from scripts.monitor_legacy import Phase3PacketGenerator

        ordinary = Phase3PacketGenerator(((1, 2),))
        self.assertEqual(ordinary.append(b"\x01", 9), ())
        self.assertEqual(ordinary.append(b"\x01\xaa\xbb", 10), ((10, b"\xaa\xbb"),))
        phase1 = Phase3PacketGenerator(((1, 6),), phase=1, initial_cache=b"abcdef")
        self.assertEqual(phase1.append(b"\x01XY", 10), ())
        # 4900 may complete once with timestamp bytes, then a second time from
        # the just-replaced same cache slot. The incoming fragment is discarded.
        expected = b"XY\x04\x03\x02\x01"
        self.assertEqual(
            phase1.append(b"\x02ignored"[:7], 0x01020304),
            ((10, expected), (10, expected)),
        )
        self.assertEqual(phase1.append(b"\x01abc", 11), ())
        self.assertEqual(phase1.append(b"\x01def", 12), ((12, b"abcdef"),))

    def test_bounded_native_stream_session_packets_and_cleanup(self):
        from scripts.monitor_legacy import Phase3PacketGenerator, run_phase3_stream
        from scripts.toyota_session import Limits

        provider = FakeProvider(
            (MonitorReceive(b"\xe2\x01\xaa\xbb", 7, 0), MonitorReceive(b"\xe3", 7, 0))
        )
        stream = Phase3Stream(
            provider,
            "engine",
            source_id=7,
            protocol=3,
            request=b"\xa1\x04",
            retries=0,
            send_timeout=9,
            receive_timeout=10,
            interval=30,
        )
        result = run_phase3_stream(
            stream,
            Phase3PacketGenerator(((1, 2),)),
            packet_limit=1,
            tick_ms=lambda: 20,
            limits=Limits(exchanges=2),
        )
        self.assertEqual(result, ((20, b"\xaa\xbb"),))
        self.assertEqual(stream.state, 0)
        self.assertEqual(
            [call[2] for call in provider.calls if call[0] == "send"],
            [b"\xa2\x04", b"\xa3"],
        )

    def test_stream_session_budget_still_drains_shutdown(self):
        from scripts.monitor_legacy import Phase3PacketGenerator, run_phase3_stream
        from scripts.toyota_session import Limits

        provider = FakeProvider(
            (MonitorReceive(b"", 7, 0x91010009), MonitorReceive(b"\xe3", 7, 0))
        )
        stream = Phase3Stream(
            provider,
            "engine",
            source_id=7,
            protocol=3,
            request=b"\xa1\x04",
            retries=0,
            send_timeout=9,
            receive_timeout=10,
            interval=30,
        )
        with self.assertRaises(MonitorError) as caught:
            run_phase3_stream(
                stream,
                Phase3PacketGenerator(((1, 2),)),
                packet_limit=1,
                tick_ms=lambda: 20,
                limits=Limits(exchanges=2),
            )
        self.assertIn("budget", str(caught.exception))
        self.assertEqual(stream.state, 0)

    def test_stream_session_cancel_after_send_still_sends_a3_and_drains_e3(self):
        from scripts.monitor_legacy import Phase3PacketGenerator, run_phase3_stream
        from scripts.toyota_session import Cancelled

        stopped = [False]

        class CancelAfterSend(FakeProvider):
            def send(self, ecu, request, **kwargs):
                result = super().send(ecu, request, **kwargs)
                if request == b"\xa2\x04":
                    stopped[0] = True
                return result

        provider = CancelAfterSend((MonitorReceive(b"\xe3", 7, 0),))
        stream = Phase3Stream(
            provider,
            "engine",
            source_id=7,
            protocol=3,
            request=b"\xa1\x04",
            retries=0,
            send_timeout=9,
            receive_timeout=10,
            interval=30,
        )
        with self.assertRaises(Cancelled):
            run_phase3_stream(
                stream,
                Phase3PacketGenerator(((1, 2),)),
                packet_limit=1,
                tick_ms=lambda: 20,
                cancelled=lambda: stopped[0],
            )
        self.assertEqual(stream.state, 0)
        self.assertEqual(
            [call[2] for call in provider.calls if call[0] == "send"],
            [b"\xa2\x04", b"\xa3"],
        )

    def test_stream_cleanup_has_absolute_deadline_even_when_native_tick_stalls(self):
        from scripts.monitor_legacy import Phase3PacketGenerator, run_phase3_stream
        from scripts.toyota_session import Limits

        now = [0.0]

        class SlowStop(FakeProvider):
            def send(self, ecu, request, **kwargs):
                result = super().send(ecu, request, **kwargs)
                if request == b"\xa3":
                    now[0] = 10.0
                return result

        provider = SlowStop(
            (MonitorReceive(b"\xe2\x01ab", 7, 0), MonitorReceive(b"\xe3", 7, 0))
        )
        stream = Phase3Stream(
            provider,
            "engine",
            source_id=7,
            protocol=3,
            request=b"\xa1\x04",
            retries=0,
            send_timeout=9,
            receive_timeout=10,
            interval=30,
        )
        with self.assertRaises(MonitorError) as caught:
            run_phase3_stream(
                stream,
                Phase3PacketGenerator(((1, 2),)),
                packet_limit=1,
                tick_ms=lambda: 20,
                clock=lambda: now[0],
                limits=Limits(seconds=1, exchanges=5),
            )
        self.assertIn("shutdown deadline", str(caught.exception))
        self.assertEqual(sum(call[0] == "receive" for call in provider.calls), 1)
        self.assertEqual(stream.state, 6)


class Phase3CompleteProducer(unittest.TestCase):
    def test_concrete_mode_fallback_and_mode2_pack_lengths(self):
        from scripts.monitor_legacy import phase3_setup_commands, select_phase3_packing

        selection = select_phase3_packing(
            ((3, 2),),
            {3: 2},
            {3: (True, 2)},
            None,
            capabilities=0x13,
            excluded=0,
            maximum_request=2,
            maximum_reply=8,
        )
        self.assertEqual(
            selection.attempts, ((1, 0xA0050422), (2, 0x90051012), (0x10, 0))
        )
        selection = select_phase3_packing(
            ((3, 2),),
            {3: 2},
            {3: (True, 2)},
            ((5, 2),),
            capabilities=2,
            excluded=0,
            maximum_request=8,
            maximum_reply=8,
        )
        setup = phase3_setup_commands(
            selection.packing,
            interface_id=9,
            buffer_468=7,
            standard_values=(),
            parameter_8=0xFFFFFFFF,
        )
        self.assertEqual(setup.setup[0].command_id, 0x109)
        self.assertEqual(setup.setup[0].values, (7, 9, ((4, b"\x02"),), 2, (), 3000))

    def test_selected_composite_to_real_pickup_command(self):
        import struct
        from types import SimpleNamespace
        from typing import cast

        from scripts.monitor_legacy import selected_phase3_monitor
        from scripts.profiles import VehicleProfile

        def row(pid, start, end, flags):
            result = bytearray(84)
            struct.pack_into("<H", result, 56, pid)
            struct.pack_into("<H", result, 60, 2)
            struct.pack_into("<HH", result, 62, start, end)
            result[78:80] = bytes((flags, 9))
            return bytes(result)

        rows = (row(10, 0, 2, 1), row(20, 8, 9, 1), row(30, 0, 0, 17))
        phy = bytearray(24)
        struct.pack_into("<IIIH", phy, 0, 3, 4, 5, 2)
        category = bytearray(76)
        category[72] = 3
        links = (struct.pack("<HHH6x", 30, 1, 10), struct.pack("<HHH6x", 30, 2, 20))
        profile = cast(
            VehicleProfile,
            SimpleNamespace(
                category=3,
                exception_ids=(),
                category_record=bytes(category),
                records=lambda slot: {
                    6: (),
                    10: rows,
                    13: (bytes(phy),),
                    14: (),
                    15: (),
                    26: links,
                }[slot],
                ecu_database_sha256="authored",
                database=SimpleNamespace(sha256="authored"),
                catalog=SimpleNamespace(
                    management=SimpleNamespace(sha256="authored-management"),
                    language=SimpleNamespace(resolve=lambda key: ""),
                ),
            ),
        )
        observed = {
            key: key == 11 for key in (22, 10, 8, 9, 12, 25, 11, 26, 29, 27, 28, 35)
        }
        result = selected_phase3_monitor(
            profile,
            (30,),
            {9: 2},
            observed,
            interface_id=9,
            excluded=0,
            maximum_request=8,
            maximum_reply=8,
            cached_frames=None,
            parameter_8=0xFFFFFFFF,
            standard_values=(),
        )
        self.assertEqual(result.frame_sizes, ((0, 2), (1, 1)))
        from scripts.monitor_legacy import phase3_measurement

        measurement = phase3_measurement(result)
        self.assertEqual(result.native_packing.frame_sizes, ((0, 2),))
        self.assertEqual(
            (measurement.cycle, measurement.packet_size, measurement.mode),
            (160, 6, 0x10),
        )
        self.assertEqual(result.pickup_spans, ((0, 3), (8, 2), (-1, 3)))
        self.assertEqual(result.commands.setup[0].values[4], 3)
        self.assertEqual(result.commands.setup[1].command_id, 0x112)
        self.assertEqual(
            result.commands.setup[1].values,
            (9, struct.pack("<6I", 0, 3, 8, 2, 0xFFFFFFFF, 3)),
        )
        self.assertEqual(
            (
                result.signals[-1].pid,
                result.signals[-1].frame_index,
                result.signals[-1].end_bit,
            ),
            (30, 1, 7),
        )


class AuxiliarySelected(unittest.TestCase):
    def test_actual_db213_to_first_function_and_dtc_setup(self):
        import struct
        from types import SimpleNamespace
        from typing import cast

        from scripts.diagnostic_db import Section
        from scripts.monitor_legacy import selected_phase3_monitor
        from scripts.profiles import VehicleProfile

        freeze = bytearray(84)
        struct.pack_into("<H", freeze, 56, 17)
        struct.pack_into("<H", freeze, 60, 2)
        struct.pack_into("<HH", freeze, 62, 0, 15)
        freeze[78:80] = bytes((9, 99))
        phy = bytearray(24)
        struct.pack_into("<IIIH", phy, 0, 3, 4, 5, 2)
        category = bytearray(76)
        category[72] = 3
        auxiliary = struct.pack("<HHHBB", 17, 0x99, 0, 1, 0)
        function = struct.pack("<6H4x", 3, 0x99, 0, 7, 0, 0)
        communication = struct.pack("<4H", 7, 1, 0, 0)
        variables = struct.pack("<IH", 0, 2) + b"\x13\x07"
        management = SimpleNamespace(
            sha256="authored-management",
            kind=1,
            version=0x0100032F,
            sections={
                18: Section(18, 0, 1, False, function),
                17: Section(17, 0, 1, False, communication),
                0: Section(0, 0, 1, False, variables),
            },
        )
        profile = cast(
            VehicleProfile,
            SimpleNamespace(
                category=3,
                exception_ids=(),
                category_record=bytes(category),
                records=lambda slot: {
                    6: (),
                    10: (bytes(freeze),),
                    13: (bytes(phy),),
                    14: (),
                    15: (),
                    19: (auxiliary,),
                }[slot],
                ecu_database_sha256="authored",
                database=SimpleNamespace(sha256="authored", sections={19: True}),
                catalog=SimpleNamespace(
                    management=management,
                    language=SimpleNamespace(resolve=lambda key: ""),
                ),
            ),
        )
        observed = {
            key: key == 11 for key in (22, 10, 8, 9, 12, 25, 11, 26, 29, 27, 28, 35)
        }
        result = selected_phase3_monitor(
            profile,
            (17,),
            {},
            observed,
            interface_id=9,
            excluded=0x10,
            maximum_request=8,
            maximum_reply=8,
            cached_frames=None,
            parameter_8=0xFFFFFFFF,
            standard_values=(),
        )
        self.assertEqual(result.attempts, ((0x10, 0x90051010),))
        self.assertEqual(result.frame_sizes, ((1, 2),))
        from scripts.monitor_legacy import phase3_measurement

        measurement = phase3_measurement(result)
        self.assertEqual(result.native_packing.frame_sizes, ((1, 2),))
        self.assertEqual((measurement.cycle, measurement.packet_size), (160, 6))
        self.assertEqual(result.commands.setup[0].command_id, 0x10B)
        self.assertEqual(result.commands.setup[0].values, (3, 9, 0, b"\x07", 2, ()))
        self.assertEqual(result.signals[0].frame_index, 1)

        # DK2160 uses the same selected DB213/DB112/DB111 retrieval fields.
        from scripts.monitor_legacy import selected_dk_monitor

        category[72] = 7
        dk_management = SimpleNamespace(
            sha256="authored-management",
            kind=management.kind,
            version=management.version,
            sections={
                **management.sections,
                18: Section(18, 0, 1, False, struct.pack("<6H4x", 7, 0x99, 0, 7, 0, 0)),
            },
        )
        dk_profile = cast(
            VehicleProfile,
            SimpleNamespace(
                **{
                    **vars(profile),
                    "category": 7,
                    "category_record": bytes(category),
                    "catalog": SimpleNamespace(
                        management=dk_management,
                        language=SimpleNamespace(resolve=lambda key: ""),
                    ),
                }
            ),
        )
        dk = selected_dk_monitor(
            dk_profile, (17,), {}, {key: key == 26 for key in observed}
        )
        self.assertEqual(dk.frame_sizes, ((1, 2),))
        self.assertEqual(dk.event.request, b"\x13\x07")
        self.assertEqual(dk.event.accept(b"\x19\x22\x00", 9), (9, b"\x02\x00"))
        self.assertEqual(dk.signals[0].frame_index, 1)


class SelectedSupportIntegration(unittest.TestCase):
    def profile(self, phase):
        import struct
        from types import SimpleNamespace
        from typing import cast

        from scripts.profiles import SelectedFrame, VehicleProfile
        from scripts.toyota import CommandFrame

        freeze = bytearray(84)
        struct.pack_into("<H", freeze, 56, 17)
        struct.pack_into("<H", freeze, 60, 2)
        struct.pack_into("<HH", freeze, 62, 0, 15)
        freeze[78:80] = bytes((1, 1))
        phy = bytearray(24)
        struct.pack_into("<IIIH", phy, 0, 3, 4, 5, 2)
        category = bytearray(76)
        category[72] = phase
        rows = {
            3: (bytes(8),),
            6: (bytes((0, 0, 1, 2, 1, 2, 0, 0)),),
            10: (bytes(freeze),),
            13: (bytes(phy),),
            14: (),
            15: (),
        }

        def frame_records(function):
            return (
                SelectedFrame(
                    CommandFrame(b"\x21\x00"),
                    bytes((function,)),
                    b"comm",
                    b"settings",
                    "authored",
                ),
            )

        def validate_frame(frame):
            if (
                type(frame) is not SelectedFrame
                or len(frame.function_record) != 1
                or frame != frame_records(frame.function_record[0])[0]
            ):
                raise ValueError("Foreign authored fixture frame")

        return cast(
            VehicleProfile,
            SimpleNamespace(
                category=phase,
                category_record=bytes(category),
                exception_ids=(),
                records=lambda slot: rows.get(slot, ()),
                frame_records=frame_records,
                validate_frame=validate_frame,
                ecu_database_sha256="authored",
                database=SimpleNamespace(
                    sha256="authored", sections=dict.fromkeys(rows)
                ),
                catalog=SimpleNamespace(
                    management=SimpleNamespace(sha256="authored-management"),
                    language=SimpleNamespace(resolve=lambda key: ""),
                ),
            ),
        )

    def native_profile(self, phase, *, source_build=18):
        import struct

        from scripts.diagnostic_db import Database, Language, Section
        from scripts.profiles import VehicleCatalog, VehicleProfile

        category = bytearray(76)
        struct.pack_into("<H", category, 68, 42)
        category[72] = phase
        protocol = bytearray(24 if source_build == 12 else 28)
        struct.pack_into("<5H", protocol, 0, 42, 1, 0x33, 0, 0x10)
        struct.pack_into("<HHH", protocol, 14, 8, 8, 100)
        protocol[22 if source_build == 12 else 24] = 0x11
        iso = bytearray(56)
        struct.pack_into("<IHH", iso, 0, 10400, 1, 3)
        for offset in range(8, 50, 2):
            struct.pack_into("<H", iso, offset, 100 + offset)
        management = Database(
            1,
            0x0100030C if source_build == 12 else 0x0100032F,
            "authored-management",
            {
                0: Section(
                    0, 0, 2, False, struct.pack("<IHIH", 0, 1, 1, 1) + b"\x81\x3e"
                ),
                13: Section(13, 0, 1, False, bytes(protocol)),
                15: Section(15, 0, 1, False, bytes(iso)),
                16: Section(16, 0, 1, False, bytes(category)),
                17: Section(
                    17, 0, 2, False, struct.pack("<8H", 1, 1, 0, 0, 2, 2, 0, 0)
                ),
                18: Section(
                    18,
                    0,
                    2,
                    False,
                    struct.pack("<8H", 42, 0x68, 0, 1, 0, 0, 0, 0)
                    + struct.pack("<8H", 42, 0x7F, 0, 2, 0, 0, 0, 0),
                ),
            },
        )
        base = self.profile(phase)
        sections = {
            slot: Section(
                slot, 0, len(base.records(slot)), False, b"".join(base.records(slot))
            )
            for slot in (3, 6, 10, 13, 14, 15)
        }
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
        return VehicleProfile(
            catalog,
            bytes(category),
            Database(2, management.version, "authored-diag", sections),
        )

    def observed(self, *enabled):
        return {
            key: key in enabled
            for key in (22, 10, 8, 9, 12, 25, 11, 26, 29, 27, 28, 35)
        }

    def support_profile(self, phase):
        from scripts.profiles import VehicleProfile

        profile = self.run_communication(phase, 18, self.run_backend()).profile
        assert isinstance(profile, VehicleProfile)
        return profile

    def test_actual_support_bitmap_to_p3_setup_and_dk_packet(self):
        from scripts.monitor_legacy import (
            selected_dk_from_exchange,
            selected_phase3_from_exchange,
        )

        calls = []

        def exchange(query):
            calls.append(query)
            return b"\x61\x00\x80"

        p3 = selected_phase3_from_exchange(
            self.support_profile(3),
            (17,),
            exchange,
            "engine",
            self.observed(11),
            interface_id=9,
            excluded=0,
            maximum_request=8,
            maximum_reply=8,
            parameter_8=0xFFFFFFFF,
            standard_values=(),
            native_ecu=7,
            packet_protocol=3,
        )
        self.assertEqual(p3.packing.setup_requests, (b"\x01\x01", b"\x41\x02"))
        self.assertEqual(p3.commands.setup[0].command_id, 0x10A)
        self.assertEqual(calls[0].request, b"\x21\x00")
        self.assertEqual(
            calls[0].selected.settings_record[:8], bytes.fromhex("e8030000c8000000")
        )
        dk = selected_dk_from_exchange(
            self.support_profile(7), (17,), exchange, "engine", self.observed(26)
        )
        self.assertEqual(dk.event.request, b"\x2c\x01")
        self.assertEqual(dk.event.accept(b"\x99\xaa\xbb", 8), (8, b"\xaa\xbb"))

    def test_actual_native_packet_cache_sequence_is_not_rebased(self):
        from scripts.monitor_legacy import selected_phase3_from_exchange
        from scripts.monitor_support import PacketFrameCache, monitor_source_identity

        class PacketDriver:
            def __init__(self):
                self.requests = []
                self.replies = iter(
                    ((0, b"\xe2\x11\xaa\xbb"), (0, b"\xe2\x11"), (0x91010009, b""))
                )
                self.interrupts = []

            def send(
                self, ecu, request, parameter4, parameter5, parameter6, parameter7
            ):
                self.requests.append(request)
                return 0

            def receive(self, receive):
                return next(self.replies)

            def interrupt(self, enabled):
                self.interrupts.append(enabled)

        driver = PacketDriver()
        cache = PacketFrameCache(
            driver,
            source_identity=monitor_source_identity(self.support_profile(3), "engine"),
            send_timer=123,
            receive_timer=456,
            retries=0,
        )
        result = selected_phase3_from_exchange(
            self.support_profile(3),
            (17,),
            lambda query: b"\x61\x00\x80",
            "engine",
            self.observed(10, 11),
            interface_id=9,
            excluded=0,
            maximum_request=8,
            maximum_reply=8,
            parameter_8=0xFFFFFFFF,
            standard_values=(),
            native_ecu=7,
            packet_protocol=3,
            packet_cache=cache,
        )
        self.assertEqual(result.attempts, ((2, 0),))
        self.assertEqual(result.frame_sizes, ((0x11, 2),))
        self.assertEqual(result.signals[0].frame_index, 0x11)
        self.assertEqual(driver.requests, [b"\xa2\x04", b"\xa3"])
        self.assertEqual(driver.interrupts, [True, False])
        self.assertEqual(result.commands.setup[0].values[2], ((4, b"\x02"),))

    def test_native_packet_query_failure_falls_back_with_original_status(self):
        from scripts.monitor_legacy import selected_phase3_from_exchange
        from scripts.monitor_support import PacketFrameCache, monitor_source_identity

        class FailedPacketDriver:
            def __init__(self):
                self.requests = []

            def send(
                self, ecu, request, parameter4, parameter5, parameter6, parameter7
            ):
                self.requests.append(request)
                return 0x90020328

            def receive(self, receive):
                raise AssertionError("A failed send must not receive")

            def interrupt(self, enabled):
                raise AssertionError("Failed setup must not enter drain")

        driver = FailedPacketDriver()
        cache = PacketFrameCache(
            driver,
            source_identity=monitor_source_identity(self.support_profile(3), "engine"),
            send_timer=123,
            receive_timer=456,
            retries=0,
        )
        result = selected_phase3_from_exchange(
            self.support_profile(3),
            (17,),
            lambda query: b"\x61\x00\x80",
            "engine",
            self.observed(10, 11),
            interface_id=9,
            excluded=0,
            maximum_request=8,
            maximum_reply=8,
            parameter_8=0xFFFFFFFF,
            standard_values=(),
            native_ecu=7,
            packet_protocol=3,
            packet_cache=cache,
        )
        self.assertEqual(result.attempts, ((2, 0x90020328), (0x10, 0)))
        self.assertEqual(driver.requests, [b"\xa2\x04"])

    def test_packet_cache_other_profile_is_rejected_before_transport(self):
        from scripts.monitor_legacy import selected_phase3_from_exchange
        from scripts.monitor_support import PacketFrameCache
        from scripts.toyota_session import SessionError

        class UnreachableDriver:
            def send(
                self, ecu, request, parameter4, parameter5, parameter6, parameter7
            ):
                raise AssertionError("Wrong source must fail before send")

            def receive(self, receive):
                raise AssertionError("Wrong source must fail before receive")

            def interrupt(self, enabled):
                raise AssertionError("Wrong source must fail before interrupt")

        cache = PacketFrameCache(
            UnreachableDriver(),
            source_identity=("engine", "different-db", "authored-management", 3, ()),
            send_timer=123,
            receive_timer=456,
            retries=0,
        )
        with self.assertRaises(SessionError):
            selected_phase3_from_exchange(
                self.profile(3),
                (17,),
                lambda query: b"\x61\x00\x80",
                "engine",
                self.observed(10, 11),
                interface_id=9,
                excluded=0,
                maximum_request=8,
                maximum_reply=8,
                parameter_8=0xFFFFFFFF,
                standard_values=(),
                native_ecu=7,
                packet_protocol=3,
                packet_cache=cache,
            )

    def test_support_timeout_runs_literal_null_init_before_next_bitmap(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.monitor_legacy import selected_phase3_from_exchange
        from scripts.toyota import ToyotaCodecError

        base = self.support_profile(3)
        freeze = bytearray(base.records(10)[0])
        freeze[79] = 33
        rows = {
            3: (bytes(8), bytes((0, 0, 0, 0, 32, 0, 0, 0))),
            6: (bytes((0, 0, 33, 2, 1, 2, 0, 0)),),
            10: (bytes(freeze),),
        }
        sections = dict(base.database.sections)
        sections.update(
            {
                slot: Section(slot, 0, len(values), False, b"".join(values))
                for slot, values in rows.items()
            }
        )
        selected = replace(base, database=replace(base.database, sections=sections))
        events = []

        def exchange(query):
            events.append(("query", query.request))
            if query.request == b"\x21\x00":
                raise ToyotaCodecError("authored timeout", 0x91010009)
            return b"\x61\x20\x80"

        class InitDriver:
            def send(self, send):
                events.append(
                    (
                        "init",
                        send.request,
                        send.parameter4,
                        send.parameter5,
                        send.parameter6,
                        send.parameter7,
                    )
                )
                return 0x90020328

            def receive(self, receive):
                raise AssertionError("InitEcu sends NULL without receiving")

        result = selected_phase3_from_exchange(
            selected,
            (17,),
            exchange,
            "engine",
            self.observed(11),
            interface_id=9,
            excluded=0,
            maximum_request=8,
            maximum_reply=8,
            parameter_8=0xFFFFFFFF,
            standard_values=(),
            native_ecu=7,
            packet_protocol=3,
            support_stream=InitDriver(),
            bus_id=9,
        )
        self.assertEqual(
            events,
            [
                ("query", b"\x21\x00"),
                ("init", None, 1000, 9, 1, 1),
                ("query", b"\x21\x20"),
            ],
        )
        self.assertEqual(result.packing.setup_requests, (b"\x01\x21", b"\x41\x02"))

    def test_dk_bit16_retains_direct_native_descriptor_without_p3_expansion(self):
        from types import SimpleNamespace
        from typing import cast

        from scripts.monitor_legacy import selected_dk_monitor
        from scripts.profiles import VehicleProfile

        base = self.profile(7)
        freeze = bytearray(base.records(10)[0])
        freeze[78] = 17

        def records(slot):
            if slot == 26:
                raise AssertionError("DK a650 does not query MultiPID DB21A")
            return (bytes(freeze),) if slot == 10 else base.records(slot)

        selected = cast(
            VehicleProfile, SimpleNamespace(**{**vars(base), "records": records})
        )
        result = selected_dk_monitor(selected, (17,), {1: 2}, self.observed(26))
        self.assertEqual(result.event.request, b"\x2c\x01")
        self.assertEqual(result.signals[0].frame_index, 0)
        self.assertEqual(result.frame_sizes, ((0, 2),))

    def test_dk_static_db206_fallback_requires_exact_byte77_one(self):
        from types import SimpleNamespace
        from typing import cast

        from scripts.monitor_legacy import selected_dk_monitor
        from scripts.profiles import VehicleProfile

        base = self.profile(7)
        freeze = bytearray(base.records(10)[0])
        freeze[77] = 1
        selected = cast(
            VehicleProfile,
            SimpleNamespace(
                **{
                    **vars(base),
                    "records": lambda slot: (
                        (bytes(freeze),) if slot == 10 else base.records(slot)
                    ),
                }
            ),
        )
        result = selected_dk_monitor(selected, (17,), {}, self.observed(26))
        self.assertEqual(result.event.request, b"\x2c\x01")
        self.assertEqual(result.event.accept(b"\x99\xaa\xbb", 5), (5, b"\xaa\xbb"))
        freeze[77] = 2
        with self.assertRaises(MonitorError) as caught:
            selected_dk_monitor(selected, (17,), {}, self.observed(26))
        self.assertEqual(caught.exception.code, 0xC0050414)

    def test_p3_selected_iso_vpw_pwm_constructor_lifecycle(self):
        import struct
        from types import SimpleNamespace
        from typing import cast

        from scripts.data_monitor import selected_p4_connection
        from scripts.diagnostic_db import Section
        from scripts.monitor_legacy import (
            phase3_interface_lifecycle,
            selected_phase3_monitor,
        )
        from scripts.profiles import VehicleProfile

        base = self.profile(3)
        prot = bytearray(28)
        struct.pack_into("<HH", prot, 0, 3, 7)
        struct.pack_into("<H", prot, 8, 0x10)
        struct.pack_into("<HHH", prot, 14, 8, 8, 100)
        iso = bytearray(range(56))
        struct.pack_into("<I", iso, 0, 9600)
        struct.pack_into("<H", iso, 4, 7)
        j1850 = bytearray(16)
        struct.pack_into("<H", j1850, 0, 7)
        struct.pack_into("<I", j1850, 8, 12345)
        selected = cast(
            VehicleProfile,
            SimpleNamespace(
                **{
                    **vars(base),
                    "protocol_info": lambda bus: bytes(prot),
                    "comm_info_iso_records": lambda key: (bytes(iso),),
                    "catalog": SimpleNamespace(
                        **{
                            **vars(base.catalog),
                            "management": SimpleNamespace(
                                sha256="authored-management",
                                sections={51: Section(51, 0, 1, False, bytes(j1850))},
                            ),
                        }
                    ),
                }
            ),
        )
        for bus, command in ((0x19, 0x100), (0x17, 0x102), (0x16, 0x103)):
            connection = selected_p4_connection(
                selected,
                bus_id=bus,
                diagnostic_mode=bytes(16),
                controller_category_flags=3,
            )
            plan = selected_phase3_monitor(
                selected,
                (17,),
                {1: 2},
                self.observed(11),
                interface_id=connection.address.request_id,
                excluded=0,
                maximum_request=8,
                maximum_reply=8,
                cached_frames=None,
                parameter_8=0xFFFFFFFF,
                standard_values=(),
            )
            lifecycle = phase3_interface_lifecycle(
                selected,
                plan,
                connection,
                connected_device=4,
                init_mode=2,
                parameter_c0=77,
            )
            from dataclasses import replace

            with self.assertRaises(MonitorError):
                phase3_interface_lifecycle(
                    selected,
                    replace(plan, source_identity=("foreign",)),
                    connection,
                    connected_device=4,
                    init_mode=2,
                    parameter_c0=77,
                )
            recording_lifecycle = phase3_interface_lifecycle(
                selected,
                plan,
                connection,
                connected_device=8,
                recording=True,
                init_mode=2,
                parameter_c0=77,
            )
            self.assertEqual(recording_lifecycle, lifecycle)
            with self.assertRaises(MonitorError):
                phase3_interface_lifecycle(
                    selected,
                    plan,
                    connection,
                    connected_device=8,
                    recording=False,
                    init_mode=2,
                    parameter_c0=77,
                )
            self.assertEqual(lifecycle.setup[0].command_id, command)
            self.assertEqual(lifecycle.setup[1].values, (0,))
            self.assertEqual(
                [item.command_id for item in lifecycle.stop], [0x10E, 0x108, 0x104]
            )
            if bus == 0x19:
                values = lifecycle.setup[0].values
                self.assertEqual(values[0], b"ComIso32.dll\0")
                configs = cast(tuple[tuple[int, int], ...], values[1])
                self.assertEqual(configs[0], (1, 9600))
                self.assertEqual(configs[-1], (0x1000A, 1))
                self.assertEqual(values[2:], (1, 0xC6, 77, 0))
            elif bus == 0x17:
                self.assertEqual(
                    lifecycle.setup[0].values, (b"ComVpw32.dll\0", 0xC6, 100)
                )
            else:
                self.assertEqual(
                    lifecycle.setup[0].values,
                    (
                        b"ComPwm32.dll\0",
                        b"\x6b",
                        ((4, 0xF1), (5, 12345), (0x10300, 0), (0x10301, 0)),
                        0xC6,
                        100,
                    ),
                )

    def test_selected_dk_lower_j2534_provider_to_literal_packet(self):
        from scripts.frame_transport import (
            DriverProperties,
            J2534Result,
            NativeFrameOperations,
            NativeMessage,
        )
        from scripts.monitor_legacy import (
            LegacyNativeProvider,
            dk_monitor_cycle,
            selected_dk_monitor,
            selected_legacy_j2534_frames,
        )

        selected = self.native_profile(7)
        plan = selected_dk_monitor(selected, (17,), {1: 2}, self.observed(26))
        driver = DriverProperties(0, b"04.04", "authored")
        constructor = selected_legacy_j2534_frames(
            selected,
            plan,
            ecu="engine",
            bus_id=0x11,
            driver=driver,
            diagnostic_mode=bytes(16),
            connected_device=8,
        )
        calls = []

        class Backend:
            def invoke(self, operation, fields, *, deadline, cancelled):
                calls.append((operation, fields))
                if operation == "connect":
                    return J2534Result(handle=9)
                if operation == "read_messages":
                    return J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(4, 0, 0, 20, 0, b"\x83\xf0\x10\x6c\xaa\xbb"),
                        ),
                    )
                return J2534Result(count=1)

        operations = NativeFrameOperations(
            selected,
            constructor.frames[0],
            Backend(),
            native_build=18,
            bus_id=0x11,
            driver=driver,
            device_kind=8,
            clock=lambda: 0,
        )
        operations.adopt_channel(9)
        provider = LegacyNativeProvider(operations, ecu="engine", deadline=10)
        self.assertEqual(
            dk_monitor_cycle(
                plan.event,
                provider,
                "engine",
                protocol=0x11,
                send_timeout=1000,
                receive_timeout=200,
                retry_limit=3,
                tick_ms=lambda: 20,
            ),
            (20, b"\xaa\xbb"),
        )
        self.assertEqual(
            [name for name, _ in calls], ["ioctl", "write_messages", "read_messages"]
        )
        before = len(calls)
        with self.assertRaises(MonitorError):
            provider.send(
                "other", b"\x2c\x01", timeout=1, protocol=0x11, initialize=True
            )
        self.assertEqual(len(calls), before)
        operations.diagnostic_mode = b"\x01" + bytes(15)
        with self.assertRaises(MonitorError):
            provider.receive(
                "engine", buffer=True, maximum=8, timeout=1, argument_5=0, flags=100
            )
        self.assertEqual(len(calls), before)
        operations.diagnostic_mode = bytes(16)
        invalid = provider.receive(
            "engine", buffer=False, maximum=8, timeout=1, argument_5=0, flags=100
        )
        self.assertEqual(invalid.code, 0x90020701)
        self.assertEqual(len(calls), before)
        from scripts.monitor_legacy import run_dk_native

        with self.assertRaises(MonitorError):
            run_dk_native(
                plan,
                operations,
                ecu="engine",
                retry_limit=3,
                packet_limit=1,
                clock=lambda: 0,
            )
        self.assertEqual(operations.channel, 9)
        self.assertEqual(len(calls), before)
        operations.close(deadline=10)
        calls.clear()
        with self.assertRaises(MonitorError):
            run_dk_native(
                plan,
                operations,
                ecu="engine",
                retry_limit=-1,
                packet_limit=1,
                clock=lambda: 0,
            )
        self.assertFalse(calls)
        from scripts.monitor_legacy import run_dk_native_capture

        selected_capture = run_dk_native_capture(
            plan,
            operations,
            ecu="engine",
            retry_limit=3,
            packet_limit=1,
            clock=lambda: 0,
        )
        self.assertEqual(
            [
                (packet.timestamp_ms, packet.payload)
                for packet in selected_capture.capture.packets
            ],
            [(0, b"\xaa\xbb")],
        )
        settings = selected_capture.monitor_buffer(
            phase=0, allocation_size=4096, name=b"DK\0", text_encoding="utf-8"
        )
        self.assertEqual(settings.value_before_buffer, selected.category)
        self.assertEqual(settings.selected_ids, ((1, 0, 17),))
        self.assertEqual(calls[0][0], "connect")
        self.assertEqual(calls[-1][0], "disconnect")
        self.assertIsNone(operations.channel)
        from unittest.mock import patch

        from scripts.toyota_session import Cancelled

        calls.clear()
        with (
            patch("scripts.monitor_legacy.MAX_BYTES", 5),
            self.assertRaises(MonitorError),
        ):
            run_dk_native(
                plan,
                operations,
                ecu="engine",
                retry_limit=3,
                packet_limit=1,
                clock=lambda: 0,
            )
        self.assertFalse(calls)
        for fault in (False, True):
            calls.clear()

            class InterruptBackend(Backend):
                def __init__(self, fault):
                    self.fault, self.stopped = fault, False

                def invoke(self, operation, fields, *, deadline, cancelled):
                    result = super().invoke(
                        operation, fields, deadline=deadline, cancelled=cancelled
                    )
                    if operation == "write_messages":
                        self.stopped = not self.fault
                        if self.fault:
                            return J2534Result(code=9)
                    return result

            backend = InterruptBackend(fault)
            interrupted = NativeFrameOperations(
                selected,
                constructor.frames[0],
                backend,
                native_build=18,
                bus_id=0x11,
                driver=driver,
                device_kind=8,
                clock=lambda: 0,
            )
            original_cancelled = interrupted.cancelled
            with (
                self.subTest(fault=fault),
                self.assertRaises(MonitorError if fault else Cancelled),
            ):
                run_dk_native(
                    plan,
                    interrupted,
                    ecu="engine",
                    retry_limit=3,
                    packet_limit=1,
                    cancelled=lambda backend=backend: backend.stopped,
                    clock=lambda: 0,
                )
            self.assertEqual(calls[-1][0], "disconnect")
            self.assertIsNone(interrupted.channel)
            self.assertIs(interrupted.cancelled, original_cancelled)
        capture_clock = [0.0]

        class BrokenClockBackend(Backend):
            def invoke(self, operation, fields, *, deadline, cancelled):
                result = super().invoke(
                    operation, fields, deadline=deadline, cancelled=cancelled
                )
                if operation == "read_messages":
                    capture_clock[0] = float("nan")
                return result

        broken_clock = NativeFrameOperations(
            selected,
            constructor.frames[0],
            BrokenClockBackend(),
            native_build=18,
            bus_id=0x11,
            driver=driver,
            device_kind=8,
            clock=lambda: 0,
        )
        with self.assertRaises(MonitorError):
            run_dk_native(
                plan,
                broken_clock,
                ecu="engine",
                retry_limit=3,
                packet_limit=1,
                clock=lambda: capture_clock[0],
            )
        self.assertIsNone(broken_clock.channel)
        self.assertEqual(calls[-1][0], "disconnect")

    def test_selected_p3_to_actual_native_worker_and_capture(self):
        from scripts.data_monitor import selected_p4_connection
        from scripts.frame_transport import (
            DriverProperties,
            J2534Result,
            NativeFrameOperations,
            NativeMessage,
        )
        from scripts.monitor_legacy import (
            selected_legacy_j2534_frames,
            selected_phase3_monitor,
            selected_phase3_native_worker,
        )

        for source_build in (12, 18):
            selected = self.native_profile(3, source_build=source_build)
            connection = selected_p4_connection(
                selected,
                bus_id=0x11,
                diagnostic_mode=bytes(16),
                controller_category_flags=3,
            )
            plan = selected_phase3_monitor(
                selected,
                (17,),
                {1: 2},
                self.observed(11),
                interface_id=connection.address.request_id,
                excluded=0,
                maximum_request=8,
                maximum_reply=8,
                cached_frames=None,
                parameter_8=0xFFFFFFFF,
                standard_values=(),
            )
            driver = DriverProperties(0, b"04.04", "authored")
            frames = selected_legacy_j2534_frames(
                selected,
                plan,
                ecu="engine",
                bus_id=0x11,
                driver=driver,
                diagnostic_mode=bytes(16),
                connected_device=8,
            )
            calls = []

            class Backend:
                def __init__(self, calls):
                    self.calls = calls
                    self.application_written = False
                    self.initialized = False

                def invoke(self, operation, fields, *, deadline, cancelled):
                    self.calls.append(operation)
                    if operation == "ioctl" and fields["ioctl_id"] == 5:
                        self.initialized = True
                        return J2534Result(
                            messages=(
                                NativeMessage(
                                    4, 0, 0, 0, 0, b"\x83\xf0\x10\xc1\x08\x08"
                                ),
                            )
                        )
                    if operation == "connect":
                        return J2534Result(handle=9)
                    if operation == "write_messages":
                        self.application_written = True
                    if operation == "read_messages":
                        if not self.application_written:
                            return J2534Result(code=0x10)
                        return J2534Result(
                            count=1,
                            messages=(
                                NativeMessage(
                                    4, 0, 0, 20, 0, b"\x84\xf0\x10\x41\x01\xaa\xbb"
                                ),
                            ),
                        )
                    return J2534Result(count=1)

            backend = Backend(calls)
            operations = NativeFrameOperations(
                selected,
                frames.frames[0],
                backend,
                native_build=source_build,
                bus_id=0x11,
                driver=driver,
                device_kind=8,
                clock=lambda: 10,
            )
            worker = selected_phase3_native_worker(
                plan, operations, ecu="engine", clock=lambda: 10
            )
            self.assertEqual(worker.default_source, 0x10)
            self.assertEqual(worker.response_id, 0xFFFFFFFF)
            self.assertFalse(worker.full_source)
            self.assertEqual(worker.attempts, 3)
            from scripts.monitor_legacy import run_phase3_native

            selected_capture = run_phase3_native(
                plan, operations, ecu="engine", packet_limit=1, clock=lambda: 10
            )
            capture = selected_capture.capture
            settings = selected_capture.monitor_buffer(
                phase=0, allocation_size=4096, name=b"P3\0", text_encoding="utf-8"
            )
            self.assertEqual(settings.value_before_buffer, selected.category)
            self.assertEqual(settings.selected_ids, ((1, 0, 17),))
            self.assertTrue(backend.initialized)
            self.assertTrue(capture.packets)
            self.assertEqual(capture.packets[0].payload, b"\xaa\xbb")
            self.assertEqual(calls[0], "connect")
            self.assertEqual(calls[-1], "disconnect")
            self.assertIsNone(operations.channel)

    def test_p3_can_preserves_native_phase0_source_mismatch_and_bound(self):
        import struct
        from copy import copy
        from dataclasses import replace

        from scripts.data_monitor import selected_p4_connection
        from scripts.diagnostic_db import Section
        from scripts.frame_transport import (
            DriverProperties,
            J2534Result,
            NativeFrameOperations,
            NativeMessage,
        )
        from scripts.monitor_legacy import (
            selected_legacy_j2534_frames,
            selected_phase3_monitor,
            selected_phase3_native_worker,
        )
        from scripts.toyota_session import Limits

        base = self.native_profile(3)
        catalog = copy(base.catalog)
        protocol = bytearray(catalog.management.sections[13].payload)
        struct.pack_into("<H", protocol, 8, 0x7E0)
        protocol[24] = 0x12
        can = bytearray(28)
        struct.pack_into("<IH", can, 4, 500000, 1)
        functions = bytearray(catalog.management.sections[18].payload)
        struct.pack_into("<H", functions, 2, 0x67)
        catalog.management = replace(
            catalog.management,
            sections={
                **catalog.management.sections,
                13: Section(13, 0, 1, False, bytes(protocol)),
                14: Section(14, 0, 1, False, bytes(can)),
                18: Section(18, 0, 2, False, bytes(functions)),
            },
        )
        selected = replace(base, catalog=catalog)
        connection = selected_p4_connection(
            selected,
            bus_id=0x12,
            diagnostic_mode=bytes(16),
            controller_category_flags=3,
        )
        plan = selected_phase3_monitor(
            selected,
            (17,),
            {1: 2},
            self.observed(11),
            interface_id=connection.address.request_id,
            excluded=0,
            maximum_request=8,
            maximum_reply=8,
            cached_frames=None,
            parameter_8=0xFFFFFFFF,
            standard_values=(),
        )
        driver = DriverProperties(0, b"04.04", "authored")
        constructor = selected_legacy_j2534_frames(
            selected,
            plan,
            ecu="engine",
            bus_id=0x12,
            driver=driver,
            diagnostic_mode=bytes(16),
            connected_device=8,
        )

        class Backend:
            def __init__(self):
                self.request = b""
                self.reads = 0

            def invoke(self, operation, fields, *, deadline, cancelled):
                if operation == "connect":
                    return J2534Result(handle=9)
                if operation == "start_message_filter":
                    return J2534Result(handle=3)
                if operation == "write_messages":
                    self.request = fields["messages"][0].data[4:]
                if operation == "read_messages":
                    self.reads += 1
                    reply = b"\xc1" if self.request == b"\x81" else b"\x41\x01\xaa\xbb"
                    return J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(6, 0, 0, 0, 0, b"\x00\x00\x07\xe8" + reply),
                        ),
                    )
                return J2534Result(count=1)

        backend = Backend()
        operations = NativeFrameOperations(
            selected,
            constructor.frames[0],
            backend,
            native_build=18,
            bus_id=0x12,
            driver=driver,
            device_kind=8,
            clock=lambda: 0,
        )
        worker = selected_phase3_native_worker(
            plan, operations, ecu="engine", clock=lambda: 0, limits=Limits(exchanges=10)
        )
        self.assertEqual(worker.response_id, 0x7E8)
        self.assertEqual(worker.default_source, 0x7E0)
        self.assertEqual(worker.expected_source(), 0xE8)
        with self.assertRaises(MonitorError) as caught:
            worker.run(1)
        self.assertEqual(caught.exception.code, 0xE0000101)
        self.assertEqual(backend.request, b"\x01\x01")
        self.assertGreater(backend.reads, 1)
        self.assertFalse(worker.capture().packets)
        self.assertIsNone(operations.channel)

    def test_selected_two_p3_targets_to_century_functional_captures(self):
        import struct
        from copy import copy
        from dataclasses import replace

        from scripts.data_monitor import selected_p4_connection
        from scripts.diagnostic_db import Section
        from scripts.frame_transport import (
            DriverProperties,
            J2534Result,
            NativeFrameOperations,
            NativeMessage,
        )
        from scripts.monitor_j2534 import (
            CenturyNativeFrameOperations,
            century_frame_plan,
        )
        from scripts.monitor_legacy import (
            selected_legacy_j2534_frames,
            selected_phase3_century_worker,
            selected_phase3_monitor,
        )

        class Backend:
            def __init__(self):
                self.calls = []
                self.responses = iter(
                    (b"\x84\xb5\x10\x41\x01\xaa\xbb", b"\x84\xb5\x18\x41\x01\xcc\xdd")
                )

            def invoke(self, operation, fields, *, deadline, cancelled):
                self.calls.append((operation, fields))
                if operation == "connect":
                    return J2534Result(handle=7)
                if operation == "read_messages":
                    return J2534Result(
                        count=1,
                        messages=(NativeMessage(4, 0, 0, 0, 0, next(self.responses)),),
                    )
                return J2534Result(count=1)

        backend = Backend()
        driver = DriverProperties(0, b"04.04", "authored")
        targets = []
        for source in (0x10, 0x18):
            base = self.native_profile(3)
            catalog = copy(base.catalog)
            protocol = bytearray(catalog.management.sections[13].payload)
            struct.pack_into("<HH", protocol, 6, 0x33, 0x10)
            catalog.management = replace(
                catalog.management,
                sha256="authored-management-shared",
                sections={
                    **catalog.management.sections,
                    13: Section(13, 0, 1, False, bytes(protocol)),
                },
            )
            profile = replace(base, catalog=catalog)
            diagnostic_mode = bytes(8) + source.to_bytes(4, "little") + bytes(4)
            connection = selected_p4_connection(
                profile,
                bus_id=0x11,
                diagnostic_mode=diagnostic_mode,
                controller_category_flags=3,
            )
            plan = selected_phase3_monitor(
                profile,
                (17,),
                {1: 2},
                self.observed(11),
                interface_id=connection.address.request_id,
                excluded=0,
                maximum_request=8,
                maximum_reply=8,
                cached_frames=None,
                parameter_8=connection.address.functional_id,
                standard_values=(),
            )
            constructor = selected_legacy_j2534_frames(
                profile,
                plan,
                ecu="engine",
                bus_id=0x11,
                driver=driver,
                diagnostic_mode=diagnostic_mode,
                connected_device=8,
                interface_count=2,
            )
            operations = NativeFrameOperations(
                profile,
                constructor.frames[0],
                backend,
                native_build=18,
                bus_id=0x11,
                driver=driver,
                device_kind=8,
                diagnostic_mode=diagnostic_mode,
                clock=lambda: 0,
            )
            targets.append((plan, operations))
        first = targets[0][1]
        functional = CenturyNativeFrameOperations(
            first.profile,
            century_frame_plan(
                first.profile,
                bus_id=0x11,
                driver=driver,
                diagnostic_mode=first.diagnostic_mode,
            ),
            backend,
            registered_response_ids=(0x10, 0x18),
            native_build=18,
            bus_id=0x11,
            driver=driver,
            device_kind=8,
            diagnostic_mode=first.diagnostic_mode,
            clock=lambda: 0,
        )
        functional.registered_response_ids = (0x10, 0x20)
        with self.assertRaises(MonitorError):
            selected_phase3_century_worker(
                (targets[0], targets[1]),
                functional,
                ecus=("engine", "secondary"),
                clock=lambda: 0,
            )
        self.assertFalse(backend.calls)
        functional.registered_response_ids = (0x10, 0x18)
        first_plan, first_operations = targets[0]
        command = first_plan.commands.setup[0]
        invalid_command = replace(command, values=command.values[:7] + (123,))
        invalid_plan = replace(
            first_plan,
            commands=replace(
                first_plan.commands,
                setup=(invalid_command,) + first_plan.commands.setup[1:],
            ),
        )
        with self.assertRaises(MonitorError):
            selected_phase3_century_worker(
                ((invalid_plan, first_operations), targets[1]),
                functional,
                ecus=("engine", "secondary"),
                clock=lambda: 0,
            )
        self.assertFalse(backend.calls)
        _, second_operations = targets[1]
        original_profile = second_operations.profile
        second_operations.profile = replace(original_profile, vehicle_name_key=123)
        try:
            with self.assertRaisesRegex(MonitorError, "vehicle context"):
                selected_phase3_century_worker(
                    (targets[0], targets[1]),
                    functional,
                    ecus=("engine", "secondary"),
                    clock=lambda: 0,
                )
            self.assertFalse(backend.calls)
        finally:
            second_operations.profile = original_profile
        worker = selected_phase3_century_worker(
            (targets[0], targets[1]),
            functional,
            ecus=("engine", "secondary"),
            clock=lambda: 0,
        )
        self.assertEqual(
            tuple(system.default_source for system in worker.systems), (0x10, 0x18)
        )
        self.assertEqual(
            tuple(system.response_id for system in worker.systems),
            (0xFFFFFFFF, 0xFFFFFFFF),
        )
        from scripts.monitor_legacy import run_phase3_century_capture

        selected_captures = run_phase3_century_capture(
            (targets[0], targets[1]),
            functional,
            ecus=("engine", "secondary"),
            cycles=1,
            clock=lambda: 0,
        )
        captures = tuple(result.capture for result in selected_captures)
        for index, result in enumerate(selected_captures):
            self.assertIs(result.plan, targets[index][0])
            settings = result.monitor_buffer(
                phase=0, allocation_size=4096, name=b"Century\0", text_encoding="utf-8"
            )
            self.assertEqual(settings.selected_ids, ((1, 0, 17),))
        self.assertEqual(
            tuple(capture.packets[0].payload for capture in captures),
            (b"\xaa\xbb", b"\xcc\xdd"),
        )
        writes = [
            fields["messages"][0].data
            for operation, fields in backend.calls
            if operation == "write_messages"
        ]
        self.assertEqual(writes, [b"\xc2\x33\xf0\x01\x01"])
        self.assertEqual(backend.calls[-1][0], "disconnect")
        self.assertIsNone(functional.channel)

    def test_native_check_packing_does_not_require_display_metadata(self):
        from dataclasses import replace

        from scripts.monitor_legacy import phase3_measurement, selected_phase3_packing

        base = self.native_profile(3)
        profile = replace(
            base,
            database=replace(
                base.database,
                sections={
                    key: value
                    for key, value in base.database.sections.items()
                    if key not in (13, 14, 15)
                },
            ),
        )
        definitions, selection, trigger = selected_phase3_packing(
            profile,
            (17,),
            {1: 2},
            self.observed(11),
            excluded=0,
            maximum_request=8,
            maximum_reply=8,
            cached_frames=None,
        )
        self.assertEqual(definitions.selected_ids, (17,))
        self.assertIsNone(trigger)
        measurement = phase3_measurement(selection.packing)
        self.assertEqual((measurement.cycle, measurement.packet_size), (160, 6))

    def test_check_measurements_and_native_device_policy(self):
        from scripts.monitor_legacy import (
            Phase3Measurement,
            check_legacy_packing,
            legacy_allocate_measurements,
            phase3_check_excluded,
        )

        p3 = check_legacy_packing(
            self.native_profile(3),
            (17,),
            {1: 2},
            self.observed(11),
            bus_id=0x11,
            family="P3",
        )
        dk = check_legacy_packing(
            self.native_profile(7),
            (17,),
            {1: 2},
            self.observed(26),
            bus_id=0x11,
            family="DK",
        )
        assert p3 is not None and dk is not None
        self.assertEqual(p3, Phase3Measurement(160, 6, 0, 0x10))
        self.assertEqual(dk, Phase3Measurement(160, 6, 0, 0x200))
        self.assertEqual(
            tuple(
                item.allocation for item in legacy_allocate_measurements(101, (p3, dk))
            ),
            (50, 51),
        )
        for device, expected in ((4, 0), (8, 3)):
            self.assertEqual(
                phase3_check_excluded(
                    (42,), command_kind=7, connected_device=device, command_ecu=42
                ),
                expected,
            )
        self.assertEqual(
            phase3_check_excluded(
                (42, 0x68), command_kind=0x42, connected_device=4, command_ecu=99
            ),
            0,
        )
        self.assertEqual(
            phase3_check_excluded(
                (42, 43), command_kind=0x42, connected_device=8, command_ecu=99
            ),
            3,
        )
        self.assertEqual(
            phase3_check_excluded(
                (42, 0x68),
                command_kind=0x42,
                connected_device=8,
                command_ecu=99,
                shared_interface=3,
            ),
            0,
        )
        self.assertEqual(
            phase3_check_excluded(
                (42,),
                command_kind=0x42,
                connected_device=8,
                command_ecu=99,
                shared_interface=4,
                disabled_packet_ecus=(99,),
            ),
            3,
        )
        self.assertEqual(
            phase3_check_excluded(
                (42,),
                command_kind=0x42,
                connected_device=8,
                command_ecu=99,
                shared_interface=4,
                disabled_packet_ecus=(42,),
            ),
            0,
        )
        with self.assertRaises(MonitorError) as error:
            phase3_check_excluded(
                (42,), command_kind=0x42, connected_device=8, command_ecu=99
            )
        self.assertEqual(error.exception.code, 0xC0040601)

    def run_communication(
        self,
        phase,
        build,
        backend,
        *,
        diagnostic_mode=bytes(16),
        functional_id=None,
        category=42,
        recording_protocol=False,
        did_active=False,
        management_only=False,
        clock=lambda: 0,
        limits=None,
    ):
        import struct
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.frame_transport import DriverProperties
        from scripts.native_communication import NativeCommunication

        profile = self.native_profile(phase, source_build=build)
        sections = dict(profile.catalog.management.sections)
        sections[0] = Section(
            0,
            0,
            3,
            False,
            struct.pack("<IHIHIH", 0, 1, 1, 1, 2, 2) + b"\x81\x3e\x21\x00",
        )
        sections[17] = replace(
            sections[17],
            count=3,
            payload=sections[17].payload + struct.pack("<4H", 3, 3, 0, 0),
        )
        sections[18] = replace(
            sections[18],
            count=3,
            payload=struct.pack("<8H", 42, 15, 0, 3, 0, 0, 0, 0) + sections[18].payload,
        )
        sections[29] = Section(
            29, 0, 1, False, struct.pack("<II4H", 1000, 200, 0, 0, 0, 0)
        )
        if recording_protocol:
            variables = (
                b"\x81",
                b"\x3e",
                b"\x21\x00",
                b"\x09\x02",
                b"\xff\xff\xff",
                b"\x10\x01",
                b"\x50\x01",
            )
            directory, image = bytearray(), bytearray()
            for value in variables:
                directory += struct.pack("<IH", len(image), len(value))
                image += value
            sections[0] = Section(0, 0, len(variables), False, bytes(directory + image))
            sections[17] = replace(
                sections[17],
                count=5,
                payload=sections[17].payload
                + struct.pack("<8H", 4, 4, 5, 5, 5, 6, 7, 7),
            )
            functions = ((3, 5), (5, 5), *((function, 4) for function in range(27, 40)))
            sections[18] = replace(
                sections[18],
                count=sections[18].count + len(functions),
                payload=sections[18].payload
                + b"".join(
                    struct.pack("<8H", 42, function, 0, frame, 0, 0, 0, 0)
                    for function, frame in functions
                ),
            )
            rows = tuple(
                sections[18].payload[i : i + 16]
                for i in range(0, len(sections[18].payload), 16)
            )
            sections[18] = replace(
                sections[18],
                payload=b"".join(
                    sorted(rows, key=lambda row: struct.unpack_from("<HH", row))
                ),
            )
        if did_active:
            variables = (b"\x81", b"\x3e", b"\x21\x00", b"\x02\x00")
            directory, image = bytearray(), bytearray()
            for value in variables:
                directory += struct.pack("<IH", len(image), len(value))
                image += value
            sections[0] = Section(0, 0, len(variables), False, bytes(directory + image))
            sections[17] = replace(
                sections[17],
                count=4,
                payload=sections[17].payload + struct.pack("<4H", 4, 4, 0, 0),
            )
            rows = tuple(
                sections[18].payload[i : i + 16]
                for i in range(0, len(sections[18].payload), 16)
            ) + (
                struct.pack("<8H", 42, 0x14, 0, 4, 0, 0, 0, 0),
                struct.pack("<8H", 42, 0x98, 0, 1, 0, 0, 0, 0),
            )
            sections[18] = replace(
                sections[18],
                count=5,
                payload=b"".join(
                    sorted(rows, key=lambda row: struct.unpack_from("<HH", row))
                ),
            )
            protocol = bytearray(sections[13].payload)
            protocol[22 if build == 12 else 24] = 0x17
            sections[13] = replace(sections[13], payload=bytes(protocol))
            j1850 = bytearray(16)
            struct.pack_into("<HI", j1850, 0, 1, 0)
            struct.pack_into("<I", j1850, 4, 41600)
            sections[51] = Section(51, 0, 1, False, bytes(j1850))
        if functional_id is not None:
            protocol = bytearray(sections[13].payload)
            struct.pack_into("<H", protocol, 6, functional_id)
            sections[13] = replace(sections[13], payload=bytes(protocol))
        for slot, width, key_offset in (
            (13, 24 if build == 12 else 28, 0),
            (16, 76, 68),
            (18, 16, 0),
        ):
            original = sections[slot]
            rows = []
            for selected_category in range(42, 46):
                for offset in range(0, len(original.payload), width):
                    row = bytearray(original.payload[offset : offset + width])
                    struct.pack_into("<H", row, key_offset, selected_category)
                    rows.append(bytes(row))
            sections[slot] = replace(original, count=len(rows), payload=b"".join(rows))
        selected_category_record = bytearray(profile.category_record)
        struct.pack_into("<H", selected_category_record, 68, category)
        profile = replace(profile, category_record=bytes(selected_category_record))
        profile.catalog.management = replace(
            profile.catalog.management, sections=sections
        )
        active, pattern = bytearray(92), bytearray(24)
        struct.pack_into("<H", active, 56, 34)
        struct.pack_into("<H", active, 64, 1)
        struct.pack_into("<H", active, 74, 2)
        active[82] = 0x55
        struct.pack_into("<H", pattern, 0, 1)
        profile = replace(
            profile,
            database=replace(
                profile.database,
                sections={
                    **profile.database.sections,
                    11: Section(11, 0, 1, False, bytes(active)),
                    12: Section(12, 0, 1, False, bytes(pattern)),
                },
            ),
        )
        selected_context = profile
        if management_only:
            from scripts.profiles import ProtocolProfile

            selected_context = ProtocolProfile(
                profile.catalog,
                profile.category_record,
                profile.exception_ids,
                profile.vehicle_name_key,
            )
        return NativeCommunication.from_backend(
            selected_context,
            backend,
            "engine",
            first_request=b"\x21\x00",
            driver=DriverProperties(0, b"04.04", "authored"),
            device_kind=8,
            bus_id=0x17 if did_active else 0x11,
            source_build=build,
            clock=clock,
            limits=limits,
            diagnostic_mode=diagnostic_mode,
        )

    def run_backend(self):
        from threading import Event

        from scripts.frame_transport import J2534Result, NativeMessage

        class Backend:
            def __init__(self):
                self.request = b""
                self.response_source = 0x10
                self.next_channel = 9
                self.calls = []
                self.data = Event()

            def invoke(self, operation, fields, *, deadline, cancelled):
                self.calls.append((operation, fields))
                if operation == "connect":
                    handle = self.next_channel
                    self.next_channel += 1
                    return J2534Result(handle=handle)
                if operation == "start_message_filter":
                    return J2534Result(handle=10)
                if operation == "write_messages":
                    self.request = fields["messages"][0].data[3:]
                    self.response_source = fields["messages"][0].data[1]
                if operation == "ioctl" and fields["ioctl_id"] == 5:
                    return J2534Result(
                        messages=(
                            NativeMessage(4, 0, 0, 0, 0, b"\x83\xf0\x10\xc1\x08\x08"),
                        )
                    )
                if operation == "read_messages":
                    payload = (
                        b"\x70\x55"
                        if self.request.startswith(b"\x30\x55")
                        else b"\x70"
                        if self.request == b"\x30"
                        else b"\x7d\x55"
                        if self.request.startswith(b"\x3d")
                        else b"\x48"
                        if self.request.startswith(b"\x08")
                        else b"\x61\x00\x80"
                        if self.request == b"\x21\x00"
                        else b"\x49\x02\x41"
                        if self.request == b"\x09\x02"
                        else b"\x41\x01\xaa\xbb"
                        if self.request == b"\x01\x01"
                        else b"\x6c\xaa\xbb"
                    )
                    if self.request != b"\x21\x00":
                        self.data.set()
                    return J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(
                                4,
                                0,
                                0,
                                1234,
                                0,
                                bytes((0x80 + len(payload), 0xF0, self.response_source))
                                + payload,
                            ),
                        ),
                    )
                return J2534Result(count=1)

        return Backend()

    def test_exported_run_queue_events_selected_lower_and_exit(self):
        import time

        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
        )

        for build in (12, 18):
            for family, phase, function in (
                ("P3", 3, 11),
                ("P3", 5, 11),
                ("P3", 9, 11),
                ("P3", 18, 11),
                ("DK", 7, 26),
            ):
                with self.subTest(build=build, family=family):
                    backend = self.run_backend()
                    communication = self.run_communication(phase, build, backend)
                    controller = LegacyMonitorController(
                        family=family, connected_device=8, clock=lambda: 0
                    )
                    queue = LegacyCommandQueue()
                    target = LegacyRunTarget(
                        communication, (17,), self.observed(function)
                    )
                    start = LegacyControlMessage(9, (target,))
                    queue.put(start)
                    self.assertEqual(controller.run(queue), 0)
                    try:
                        self.assertTrue(queue.finish_event.wait(2))
                        self.assertIsNone(start.exception)
                        self.assertIsNotNone(start.result)
                        assert start.result is not None
                        self.assertEqual(start.result.status, 0)
                        self.assertTrue(backend.data.wait(2))
                        until = time.monotonic() + 2
                        while not controller.packets[0] and time.monotonic() < until:
                            time.sleep(0.001)
                        stop = LegacyControlMessage(10)
                        queue.put(stop)
                        self.assertTrue(queue.finish_event.wait(2))
                        assert stop.result is not None
                        self.assertEqual(stop.result.status, 0)
                        capture = controller.capture()
                        self.assertTrue(capture.capture.packets)
                        self.assertEqual(
                            capture.capture.packets[0].payload, b"\xaa\xbb"
                        )
                        settings = capture.monitor_buffer(
                            phase=0,
                            allocation_size=65536,
                            name=b"",
                            text_encoding="ascii",
                        )
                        self.assertEqual(settings.selected_ids, ((1, 0, 17),))
                        from scripts.snapshot import (
                            MonitorBuffer,
                            TableFile,
                            decode_monitor_buffer,
                            monitor_packets,
                            parse,
                        )

                        metadata = MonitorBuffer(
                            b"", bytes(16), b"", b"", b"", b"", 0, (), (17,), b"", ()
                        )
                        serialized = controller.dm_bytes(
                            0,
                            metadata,
                            {
                                "identifier": 0,
                                "strings": [{"core": [1, 0], "data_hex": ""}] * 2,
                                "value_raw": 0,
                            },
                        )
                        decoded = parse(serialized)
                        assert isinstance(decoded, TableFile)
                        monitor = decode_monitor_buffer(decoded.tables[1].payload)
                        self.assertEqual(monitor.selected_ids, (17,))
                        self.assertEqual(
                            monitor_packets(monitor)[0]["frames"][0]["data_hex"], "aabb"
                        )
                        self.assertEqual(controller.active_mask, 0)
                        self.assertIn(("finish", 9), controller.trace)
                        self.assertIn(("finish", 10), controller.trace)
                    finally:
                        controller.close()
                        communication.disconnect()
                    self.assertTrue(controller.worker_exit.is_set())
                    self.assertIsNone(controller.failure)
                    self.assertEqual(backend.calls[-1][0], "disconnect")
                    released = [
                        fields["channel_id"]
                        for name, fields in backend.calls
                        if name == "disconnect"
                    ]
                    self.assertEqual(
                        sorted(released), list(range(9, backend.next_channel))
                    )
                    self.assertEqual(len(released), len(set(released)))

    def test_run_native_dmci_constructor_poll_cleanup_both_builds(self):
        import struct
        import time
        from threading import Event

        from scripts.drive_recorder import (
            NativeCoreBuffer,
            NativeDmciList,
            NativeMonitorReply,
            NativeVimClient,
            NativeVimReply,
            decode_vim_command,
        )
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
        )

        for build in (12, 18):
            for device, recording in ((4, False), (8, True)):
                with self.subTest(build=build, device=device):
                    backend = self.run_backend()
                    communication = self.run_communication(3, build, backend)
                    address = communication.profile.category
                    calls = []
                    received = Event()

                    def exchange(
                        request,
                        *,
                        deadline,
                        cancelled,
                        calls=calls,
                        address=address,
                        received=received,
                    ):
                        command, payload = decode_vim_command(request)
                        calls.append((command, payload))
                        if command == 0x197F:
                            self.assertEqual(
                                payload, bytes.fromhex("01000000010000002a000000")
                            )
                            empty = NativeCoreBuffer((1, 0), b"")
                            output = NativeMonitorReply(
                                0,
                                NativeDmciList(
                                    (1, 0),
                                    (
                                        (
                                            address,
                                            NativeCoreBuffer(
                                                (1, 0),
                                                struct.pack("<I", 1234) + b"\xaa\xbb",
                                            ),
                                        ),
                                    ),
                                ),
                                (empty, empty, empty, empty, empty),
                                0,
                            ).encode()
                            received.set()
                        elif command == 0x247F:
                            output = struct.pack("<II", 0, 1)
                        else:
                            output = bytes(4)
                        return NativeVimReply(command | 0x80, 6, output).encode()

                    client = NativeVimClient(
                        exchange,
                        capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                        clock=lambda: 0,
                    )
                    controller = LegacyMonitorController(
                        family="P3",
                        connected_device=device,
                        recording=recording,
                        client=client,
                        init_mode=1,
                        parameter_c0=77,
                        clock=lambda: 0,
                    )
                    queue = LegacyCommandQueue()
                    start = LegacyControlMessage(
                        9, (LegacyRunTarget(communication, (17,), self.observed(11)),)
                    )
                    queue.put(start)
                    controller.run(queue)
                    try:
                        self.assertTrue(queue.finish_event.wait(2))
                        assert start.result is not None
                        self.assertEqual(start.result.status, 0)
                        self.assertTrue(received.wait(2))
                        until = time.monotonic() + 2
                        while not controller.packets[0] and time.monotonic() < until:
                            time.sleep(0.001)
                        stop = LegacyControlMessage(10)
                        queue.put(stop)
                        self.assertTrue(queue.finish_event.wait(2))
                        assert stop.result is not None
                        self.assertEqual(stop.result.status, 0)
                        self.assertEqual(
                            controller.capture().capture.packets[0].payload, b"\xaa\xbb"
                        )
                        self.assertEqual(
                            [code for code, _ in calls][-3:], [0x1A7F, 0x147F, 0x127F]
                        )
                    finally:
                        controller.close()
                        communication.disconnect()
                    self.assertIsNone(controller.failure)

    def test_selected_monitor_session_disable_snapshot_reaches_check_and_run(self):
        from scripts.data_monitor import (
            SelectedMonitorSession,
            selected_legacy_check_target,
        )
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
            check_legacy_monitor,
        )

        for build in (12, 18):
            backend = self.run_backend()
            communication = self.run_communication(3, build, backend)
            from scripts.profiles import VehicleProfile

            assert isinstance(communication.profile, VehicleProfile)
            session = SelectedMonitorSession(
                communication.profile, source_build=build, shared_interface=0
            )
            target = selected_legacy_check_target(
                communication, (17,), self.observed(11)
            )
            try:
                before = check_legacy_monitor(
                    (target,),
                    family="P3",
                    command_kind=0x42,
                    allocation=65536,
                    connected_device=8,
                    command_ecu=42,
                    monitor_session=session,
                    clock=lambda: 0,
                )
                self.assertEqual(before.excluded, 0)
                controller = LegacyMonitorController(
                    family="P3",
                    connected_device=8,
                    monitor_session=session,
                    clock=lambda: 0,
                )
                controller.queue = LegacyCommandQueue()
                message = LegacyControlMessage(
                    56, (LegacyRunTarget(communication, (17,), self.observed(11)),)
                )
                controller.queue.put(message)
                result = controller.run_one()
                assert result is not None
                self.assertEqual(result.status, 0)
                assert controller._worker is not None
                self.assertEqual(
                    controller._worker.disable_packet_ecu, session.disable_packet_ecu
                )
                assert controller._worker.disable_packet_ecu is not None
                controller._worker.disable_packet_ecu(42)
                controller.close()
                after = check_legacy_monitor(
                    (target,),
                    family="P3",
                    command_kind=0x42,
                    allocation=65536,
                    connected_device=8,
                    command_ecu=42,
                    monitor_session=session,
                    clock=lambda: 0,
                )
                self.assertEqual(after.excluded, 3)
                self.assertEqual(session.disabled_packet_ecus, (42,))
            finally:
                communication.disconnect()

    def test_run87_concrete_writer_groups_finish_then_outer_metadata(self):
        from scripts.drive_recorder import (
            DrsFile,
            NativeCoreString,
            NativeDmciCommand,
            NativeTriggerInfo,
            NativeTriggerParameters,
            NativeVehicleSelection,
            decode_command,
        )
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyDrsWriter,
            LegacyMonitorController,
            LegacyRunTarget,
        )

        selection = NativeVehicleSelection(
            (1, 0),
            NativeCoreString((1, 0), b"\0"),
            ((1, 0), (1, 0), (1, 0)),
            (),
            (),
            (),
            (0, 0),
        )
        system = {
            "identifier": 0,
            "strings": [{"core": [1, 0], "data_hex": ""}] * 2,
            "value_raw": 0,
        }
        trigger = NativeTriggerInfo((1, 0), 1, 1, 0)
        parameters = NativeTriggerParameters((1, 0), 1, 0, (1, 0), (), (1, 0), ())
        for build in (12, 18):
            for device in (4, 8):
                for count in (1, 2, 3):
                    with self.subTest(build=build, device=device, count=count):
                        backend = self.run_backend()
                        communications = tuple(
                            self.run_communication(
                                3,
                                build,
                                backend,
                                category=42 + index,
                                recording_protocol=True,
                                diagnostic_mode=bytes(8)
                                + (0x10 + index * 8).to_bytes(4, "little")
                                + bytes(4),
                            )
                            for index in range(count)
                        )
                        writer = LegacyDrsWriter(selection, system, trigger, parameters)
                        controller = LegacyMonitorController(
                            family="P3",
                            connected_device=device,
                            recording_writer=writer,
                            init_mode=1,
                            parameter_c0=77,
                            shared_interface=3,
                            clock=lambda: 0,
                        )
                        queue = LegacyCommandQueue()
                        message = LegacyControlMessage(
                            87,
                            tuple(
                                LegacyRunTarget(comm, (17,), self.observed(11))
                                for comm in communications
                            ),
                            enable_mode=0x10,
                        )
                        queue.put(message)
                        controller.run(queue)
                        try:
                            self.assertTrue(queue.finish_event.wait(2))
                            assert message.result is not None
                            self.assertEqual(
                                (
                                    message.result.status,
                                    message.result.flags20,
                                    message.result.flags24,
                                ),
                                (0, 0x10, 1),
                            )
                            self.assertEqual(controller.active_mask, 0)
                            self.assertIsNone(writer.result)
                            trace = list(controller.trace)
                            self.assertLess(
                                trace.index(("drs-end", 0x12)),
                                trace.index(("finish", 87)),
                            )
                            before_outer = [
                                fields["messages"][0].data[3:]
                                for name, fields in backend.calls
                                if name == "write_messages"
                            ]
                            self.assertEqual(before_outer, [b"\x21\x00"] * count)
                            recording = controller.recording_file()
                            self.assertIs(recording, writer.result)
                            self.assertEqual(
                                DrsFile.parse(recording.encode()), recording
                            )
                            groups = {}
                            for table in recording.tables:
                                if table.table_id in (0x11, 0x12):
                                    children = decode_command(table)["children"]
                                    assert isinstance(children, tuple)
                                    groups[table.table_id] = tuple(
                                        NativeDmciCommand.parse(child).command_id
                                        for child in children
                                    )
                            self.assertEqual(
                                groups[0x11],
                                (0x100, 0x107) + (0x114, 0x10A) * count + (0x10C,),
                            )
                            self.assertEqual(groups[0x12], (0x10E, 0x108, 0x104))
                            writes = [
                                fields["messages"][0].data[3:]
                                for name, fields in backend.calls
                                if name == "write_messages"
                            ]
                            self.assertEqual(
                                writes, [b"\x21\x00"] * count + [b"\x09\x02"]
                            )
                        finally:
                            controller.close()
                            for comm in communications:
                                comm.disconnect()
                        released = [
                            fields["channel_id"]
                            for name, fields in backend.calls
                            if name == "disconnect"
                        ]
                        self.assertEqual(
                            sorted(released), list(range(9, backend.next_channel))
                        )

    def test_run87_preserves_first_original_buffer_identity_after_category_overwrite(
        self,
    ):
        from scripts.drive_recorder import (
            DrsFile,
            NativeCoreString,
            NativeTriggerInfo,
            NativeTriggerParameters,
            NativeVehicleSelection,
            UnsupportedRecorderOperation,
        )
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyDrsWriter,
            LegacyMonitorController,
            LegacyRunTarget,
        )

        selection = NativeVehicleSelection(
            (1, 0),
            NativeCoreString((1, 0), b"\0"),
            ((1, 0), (1, 0), (1, 0)),
            (),
            (),
            (),
            (0, 0),
        )
        system = {
            "identifier": 0,
            "strings": [{"core": [1, 0], "data_hex": ""}] * 2,
            "value_raw": 0,
        }
        trigger = NativeTriggerInfo((1, 0), 1, 1, 0)
        parameters = NativeTriggerParameters((1, 0), 1, 0, (1, 0), (), (1, 0), ())
        for build in (12, 18):
            for same_object in (False, True):
                with self.subTest(build=build, same_object=same_object):
                    backend = self.run_backend()
                    comm = self.run_communication(
                        3, build, backend, recording_protocol=True
                    )
                    first = LegacyRunTarget(
                        comm, (17,), self.observed(11), name=b"first"
                    )
                    later = (
                        first
                        if same_object
                        else LegacyRunTarget(
                            comm, (17,), self.observed(11), name=b"later"
                        )
                    )
                    writer = LegacyDrsWriter(selection, system, trigger, parameters)
                    controller = LegacyMonitorController(
                        family="P3",
                        connected_device=4,
                        recording_writer=writer,
                        init_mode=1,
                        parameter_c0=77,
                        shared_interface=3,
                        clock=lambda: 0,
                    )
                    queue = LegacyCommandQueue()
                    controller.queue = queue
                    message = LegacyControlMessage(87, (first, later), enable_mode=0x10)
                    queue.put(message)
                    try:
                        result = controller.run_one()
                        assert result is not None
                        self.assertEqual(result.status, 0)
                        self.assertTrue(queue.finish_event.is_set())
                        self.assertIs(controller._recording_original, first)
                        self.assertIs(controller.targets[0], later)
                        before_outer = len(backend.calls)
                        if same_object:
                            result_file = controller.recording_file()
                            self.assertEqual(
                                DrsFile.parse(result_file.encode()), result_file
                            )
                        else:
                            with self.assertRaises(
                                UnsupportedRecorderOperation
                            ) as caught:
                                controller.recording_file()
                            self.assertIs(writer.failure, caught.exception)
                            self.assertIsNone(writer.result)
                            self.assertEqual(len(backend.calls), before_outer)
                    finally:
                        controller.close()
                        comm.disconnect()
                    self.assertEqual(
                        sum(name == "connect" for name, _ in backend.calls),
                        sum(name == "disconnect" for name, _ in backend.calls),
                    )

    def test_run87_writer_host_fault_and_native_selection_failure_cleanup(self):
        from io import BytesIO

        from scripts.drive_recorder import (
            NativeCoreString,
            NativeTriggerInfo,
            NativeTriggerParameters,
            NativeVehicleSelection,
        )
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyDrsWriter,
            LegacyMonitorController,
            LegacyRunTarget,
        )

        marker = RuntimeError("authored seek fault")

        class FaultStream(BytesIO):
            failed = False

            def seek(self, offset, whence=0):
                if not self.failed:
                    self.failed = True
                    raise marker
                return super().seek(offset, whence)

        selection = NativeVehicleSelection(
            (1, 0),
            NativeCoreString((1, 0), b"\0"),
            ((1, 0), (1, 0), (1, 0)),
            (),
            (),
            (),
            (0, 0),
        )
        system = {
            "identifier": 0,
            "strings": [{"core": [1, 0], "data_hex": ""}] * 2,
            "value_raw": 0,
        }
        trigger = NativeTriggerInfo((1, 0), 1, 1, 0)
        parameters = NativeTriggerParameters((1, 0), 1, 0, (1, 0), (), (1, 0), ())
        for build in (12, 18):
            for fault in ("seek", "selection"):
                backend = self.run_backend()
                communication = self.run_communication(3, build, backend)
                writer = LegacyDrsWriter(
                    selection,
                    system,
                    trigger,
                    parameters,
                    stream=FaultStream() if fault == "seek" else None,
                )
                controller = LegacyMonitorController(
                    family="P3",
                    connected_device=8,
                    recording_writer=writer,
                    init_mode=1,
                    parameter_c0=77,
                    shared_interface=3,
                    clock=lambda: 0,
                )
                queue = LegacyCommandQueue()
                controller.queue = queue
                message = LegacyControlMessage(
                    87,
                    (LegacyRunTarget(communication, (17,), self.observed(11)),),
                    enable_mode=0x10 if fault == "seek" else 0,
                )
                queue.put(message)
                try:
                    if fault == "seek":
                        with self.assertRaises(RuntimeError) as caught:
                            controller.run_one()
                        self.assertIs(caught.exception, marker)
                        self.assertIs(message.exception, marker)
                        self.assertIs(writer.failure, marker)
                        self.assertEqual(
                            tuple(
                                command.command_id for command in writer.groups[0x12]
                            ),
                            (0x10E, 0x108, 0x104),
                        )
                    else:
                        result = controller.run_one()
                        assert result is not None
                        self.assertNotEqual(result.status, 0)
                        self.assertIsInstance(writer.failure, MonitorError)
                    self.assertTrue(queue.finish_event.is_set())
                    self.assertEqual(controller.active_mask, 0)
                    self.assertFalse(controller._created)
                    self.assertIsNone(writer.result)
                    with self.assertRaises(MonitorError):
                        controller.recording_file()
                finally:
                    controller.close()
                    communication.disconnect()

    def test_selected_p3_recording_produces_native_groups_from_retained_communication(
        self,
    ):
        from scripts.drive_recorder import (
            DrsFile,
            NativeCoreString,
            NativeDmciCommand,
            NativeMonitorBuffer,
            NativeTriggerInfo,
            NativeTriggerParameters,
            NativeVehicleSelection,
            decode_command,
        )
        from scripts.monitor_legacy import LegacyRunTarget, selected_phase3_recording
        from scripts.toyota_session import Cancelled

        selection = NativeVehicleSelection(
            (1, 0),
            NativeCoreString((1, 0), b"\0"),
            ((1, 0), (1, 0), (1, 0)),
            (),
            (),
            (),
            (0, 0),
        )
        system = {
            "identifier": 0,
            "strings": [{"core": [1, 0], "data_hex": ""}] * 2,
            "value_raw": 0,
        }
        trigger = NativeTriggerInfo((1, 0), 1, 1, 0)
        parameters = NativeTriggerParameters((1, 0), 1, 0, (1, 0), (), (1, 0), ())
        for build in (12, 18):
            for device in (4, 8):
                with self.subTest(build=build, device=device):
                    trigger = NativeTriggerInfo((1, 0), 7 if device == 4 else 1, 1, 0)
                    backend = self.run_backend()
                    communication = self.run_communication(
                        3, build, backend, recording_protocol=True
                    )
                    target = LegacyRunTarget(communication, (17,), self.observed(11))
                    try:
                        recording = selected_phase3_recording(
                            target,
                            selection,
                            system,
                            trigger,
                            parameters,
                            connected_device=device,
                            enable_mode=0x10,
                            init_mode=1,
                            parameter_c0=77,
                            shared_interface=3,
                            clock=lambda: 0,
                        )
                        self.assertEqual(DrsFile.parse(recording.encode()), recording)
                        groups = {}
                        for table in recording.tables:
                            if table.table_id in (0x11, 0x12):
                                children = decode_command(table)["children"]
                                assert isinstance(children, tuple)
                                groups[table.table_id] = tuple(
                                    NativeDmciCommand.parse(child).command_id
                                    for child in children
                                )
                            elif table.table_id == 2:
                                monitor = decode_command(table)["monitor"]
                                assert isinstance(monitor, NativeMonitorBuffer)
                                self.assertEqual(monitor.value_before_buffer, 42)
                                self.assertEqual(monitor.selected_ids, ((1, 0, 17),))
                                self.assertEqual(monitor.value_after_count, 1)
                        self.assertEqual(
                            groups[0x11], (0x100, 0x107, 0x114, 0x10A, 0x10C)
                        )
                        self.assertEqual(groups[0x12], (0x10E, 0x108, 0x104))
                        ids = tuple(table.table_id for table in recording.tables)
                        self.assertIn(0x27, ids)
                        self.assertEqual(0x21 in ids, trigger.trigger_type == 7)
                        for group in (0x21, 0x22, 0x23, 0x24):
                            self.assertEqual(group in ids, trigger.trigger_type == 7)
                        vin_group = next(
                            table
                            for table in recording.tables
                            if table.table_id == 0x27
                        )
                        children = decode_command(vin_group)["children"]
                        assert isinstance(children, tuple)
                        from scripts.drive_recorder import NativeMessage

                        messages = []
                        for child in children:
                            if child.table_id == 0x203:
                                outgoing = decode_command(child)["message"]
                                assert isinstance(outgoing, NativeMessage)
                                messages.append(outgoing.data)
                        self.assertEqual(messages, [b"\x82\x10\xf0\x09\x02"])
                        from scripts.drive_recorder import (
                            NativeDrsError,
                            NativeDrsExecutor,
                            RecorderCancelled,
                        )

                        class Playback:
                            def __init__(self, fault):
                                self.fault, self.calls, self.cancelled = (
                                    fault,
                                    [],
                                    False,
                                )

                            def invoke(self, operation, fields, *, deadline, cancelled):
                                self.calls.append((operation, fields))
                                if operation == "connect":
                                    self.cancelled = self.fault == "cancel"
                                    return 19
                                if operation == "read_messages":
                                    if self.fault == "read":
                                        raise NativeDrsError(9)
                                    return NativeMessage(
                                        4, 0, 0, 0, 0, b"\x83\xf0\x10\x49\x02\x41"
                                    )
                                return None

                        for fault in (None, "read", "cancel"):
                            playback = Playback(fault)
                            executor = NativeDrsExecutor(
                                DrsFile.parse(recording.encode()),
                                playback,
                                clock=lambda: 0,
                            )
                            if fault is None:
                                executor.execute_group(0x27)
                            else:
                                with self.assertRaises(
                                    NativeDrsError
                                    if fault == "read"
                                    else RecorderCancelled
                                ):
                                    executor.execute_group(
                                        0x27,
                                        cancelled=lambda playback=playback: (
                                            playback.cancelled
                                        ),
                                    )
                            self.assertIsNone(executor.channel)
                            self.assertEqual(playback.calls[0][0], "connect")
                            self.assertEqual(
                                playback.calls[-1], ("disconnect", {"channel_id": 19})
                            )

                        writes = [
                            fields["messages"][0].data[3:]
                            for name, fields in backend.calls
                            if name == "write_messages"
                        ]
                        self.assertEqual(writes, [b"\x21\x00", b"\x09\x02"])
                        from scripts.drive_recorder import NativeDrsError

                        missing = self.run_communication(3, build, self.run_backend())
                        try:
                            with self.assertRaises(NativeDrsError) as vin_missing:
                                selected_phase3_recording(
                                    LegacyRunTarget(missing, (17,), self.observed(11)),
                                    selection,
                                    system,
                                    NativeTriggerInfo((1, 0), 1, 1, 0),
                                    parameters,
                                    connected_device=device,
                                    enable_mode=0x10,
                                    init_mode=1,
                                    parameter_c0=77,
                                    shared_interface=3,
                                    clock=lambda: 0,
                                )
                            self.assertEqual(vin_missing.exception.code, 0xC0040101)
                        finally:
                            missing.disconnect()
                        with self.assertRaises(Cancelled):
                            selected_phase3_recording(
                                target,
                                selection,
                                system,
                                trigger,
                                parameters,
                                connected_device=device,
                                enable_mode=0x10,
                                init_mode=1,
                                parameter_c0=77,
                                shared_interface=3,
                                clock=lambda: 0,
                                cancelled=lambda: True,
                            )
                    finally:
                        communication.disconnect()

    def test_run_management_only_primary_is_real_null_registration_without_ecu_database(
        self,
    ):
        from scripts.monitor_j2534 import NativeMonitorSourceFault
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
        )
        from scripts.monitor_support import monitor_source_identity
        from scripts.profiles import ProtocolProfile, VehicleProfile

        for build in (12, 18):
            for family, phase, function in (("P3", 3, 11), ("DK", 7, 26)):
                for data in (False, True):
                    with self.subTest(build=build, family=family, data=data):
                        backend = self.run_backend()
                        primary_comm = self.run_communication(
                            phase, build, backend, category=43, management_only=True
                        )
                        data_comm = self.run_communication(phase, build, backend)
                        primary = LegacyRunTarget(primary_comm, (), {})
                        target = LegacyRunTarget(
                            data_comm, (17,) if data else (), self.observed(function)
                        )
                        controller = LegacyMonitorController(
                            family=family,
                            connected_device=8,
                            shared_interface=3,
                            clock=lambda: 0,
                        )
                        queue = LegacyCommandQueue()
                        controller.queue = queue
                        message = LegacyControlMessage(56, (target,), primary=primary)
                        queue.put(message)
                        try:
                            self.assertIs(type(primary_comm.profile), ProtocolProfile)
                            self.assertFalse(
                                isinstance(primary_comm.profile, VehicleProfile)
                            )
                            self.assertFalse(hasattr(primary_comm.profile, "database"))
                            self.assertIsNone(
                                monitor_source_identity(
                                    primary_comm.profile, primary_comm.ecu
                                )[1]
                            )
                            if family == "P3" and data:
                                with self.assertRaises(NativeMonitorSourceFault):
                                    controller.run_one()
                            else:
                                result = controller.run_one()
                                assert result is not None
                                self.assertEqual(result.status, 0)
                                if data:
                                    self.assertEqual(
                                        tuple(index for index, _ in controller.poll()),
                                        (1,),
                                    )
                                else:
                                    self.assertEqual(controller.poll(), ())
                                    self.assertEqual(backend.calls, [])
                            self.assertTrue(queue.finish_event.is_set())
                            self.assertIs(
                                controller.targets[0].communication.profile,
                                primary_comm.profile,
                            )
                            self.assertIsNone(controller.buffers[0])
                            self.assertIsNone(
                                controller.plans[0].definitions.source_sha256
                            )
                        finally:
                            controller.close()
                            primary_comm.disconnect()
                            data_comm.disconnect()
                        self.assertEqual(
                            sum(name == "connect" for name, _ in backend.calls),
                            sum(name == "disconnect" for name, _ in backend.calls),
                        )

    def test_management_only_single_system_uses_management_frames_and_refuses_signal_data(
        self,
    ):
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
        )

        for build in (12, 18):
            backend = self.run_backend()
            comm = self.run_communication(3, build, backend, management_only=True)
            target = LegacyRunTarget(comm, (), {})
            controller = LegacyMonitorController(
                family="P3", connected_device=8, clock=lambda: 0
            )
            queue = LegacyCommandQueue()
            controller.queue = queue
            try:
                queue.put(LegacyControlMessage(9, (target,)))
                result = controller.run_one()
                assert result is not None
                self.assertEqual(result.status, 0)
                self.assertEqual(backend.calls, [])
                queue.put(LegacyControlMessage(96, signal_id=0x44))
                result = controller.run_one()
                assert result is not None
                self.assertEqual(result.status, 0)
                for _ in range(6):
                    controller.poll()
                writes = [
                    fields["messages"][0].data[3:]
                    for name, fields in backend.calls
                    if name == "write_messages"
                ]
                self.assertIn(b"\x08\x44" + bytes(5), writes)
                self.assertEqual(controller.buffers, (None,))
                with self.assertRaises(MonitorError):
                    controller.capture()
                queue.put(LegacyControlMessage(10))
                controller.run_one()
                before = len(backend.calls)
                queue.put(
                    LegacyControlMessage(
                        9, (LegacyRunTarget(comm, (17,), self.observed(11)),)
                    )
                )
                result = controller.run_one()
                assert result is not None
                self.assertNotEqual(result.status, 0)
                self.assertEqual(len(backend.calls), before)
            finally:
                controller.close()
                comm.disconnect()
            self.assertEqual(
                sum(name == "connect" for name, _ in backend.calls),
                sum(name == "disconnect" for name, _ in backend.calls),
            )

    def test_run_duplicate_and_primary_context_are_validated_before_registration(self):
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
        )

        for family, phase in (("P3", 3), ("DK", 7)):
            for foreign_primary in (False, True):
                backend = self.run_backend()
                old = self.run_communication(phase, 12, backend)
                new = self.run_communication(phase, 18, backend)
                controller = LegacyMonitorController(
                    family=family,
                    connected_device=8,
                    shared_interface=3,
                    clock=lambda: 0,
                )
                queue = LegacyCommandQueue()
                controller.queue = queue
                old_target, new_target = (
                    LegacyRunTarget(comm, (), {}) for comm in (old, new)
                )
                message = LegacyControlMessage(
                    56,
                    (new_target,) if foreign_primary else (old_target, new_target),
                    primary=old_target if foreign_primary else None,
                )
                queue.put(message)
                try:
                    result = controller.run_one()
                    assert result is not None
                    self.assertNotEqual(result.status, 0)
                    self.assertEqual(controller.targets, ())
                    self.assertEqual(backend.calls, [])
                    self.assertTrue(queue.finish_event.is_set())
                finally:
                    controller.close()
                    old.disconnect()
                    new.disconnect()

    def test_run_native_primary_placeholder_category_overwrite_and_three_slot_limit(
        self,
    ):
        from scripts.monitor_j2534 import NativeMonitorSourceFault
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
        )

        for build in (12, 18):
            for family, phase, function in (("P3", 3, 11), ("DK", 7, 26)):
                for case in ("duplicate", "placeholder", "overflow"):
                    with self.subTest(build=build, family=family, case=case):
                        backend = self.run_backend()
                        communications = tuple(
                            self.run_communication(
                                phase, build, backend, category=category
                            )
                            for category in range(42, 46)
                        )
                        controller = LegacyMonitorController(
                            family=family,
                            connected_device=8,
                            shared_interface=3,
                            clock=lambda: 0,
                        )
                        queue = LegacyCommandQueue()
                        controller.queue = queue
                        if case == "duplicate":
                            targets = (
                                LegacyRunTarget(
                                    communications[0], (17,), self.observed(function)
                                ),
                                LegacyRunTarget(
                                    communications[0], (), self.observed(function)
                                ),
                            )
                            primary = None
                        elif case == "placeholder":
                            targets = (
                                LegacyRunTarget(
                                    communications[0], (17,), self.observed(function)
                                ),
                            )
                            primary = LegacyRunTarget(
                                communications[1], (), self.observed(function)
                            )
                        else:
                            targets = tuple(
                                LegacyRunTarget(comm, (), self.observed(function))
                                for comm in communications[:3]
                            )
                            primary = LegacyRunTarget(
                                communications[3], (), self.observed(function)
                            )
                        message = LegacyControlMessage(56, targets, primary=primary)
                        queue.put(message)
                        try:
                            if case == "placeholder" and family == "P3":
                                with self.assertRaises(NativeMonitorSourceFault):
                                    controller.run_one()
                                self.assertIsInstance(
                                    message.exception, NativeMonitorSourceFault
                                )
                            else:
                                result = controller.run_one()
                                assert result is not None
                                self.assertEqual(
                                    result.status,
                                    0xC0050001 if case == "overflow" else 0,
                                )
                            self.assertTrue(queue.finish_event.is_set())
                            if case == "duplicate":
                                self.assertEqual(len(controller.targets), 1)
                                self.assertEqual(controller.buffers, (None,))
                                self.assertEqual(
                                    controller.active_mask,
                                    0x80 if family == "P3" else 0x400,
                                )
                                self.assertEqual(backend.calls, [])
                            elif case == "placeholder":
                                self.assertEqual(
                                    tuple(
                                        target.communication.profile.category
                                        for target in controller.targets
                                    ),
                                    (43, 42),
                                )
                                self.assertIsNone(controller.buffers[0])
                                self.assertIsNotNone(controller.buffers[1])
                                if family == "DK":
                                    packets = controller.poll()
                                    self.assertEqual(
                                        tuple(index for index, _ in packets), (1,)
                                    )
                                    self.assertEqual(
                                        controller.capture(1)
                                        .capture.packets[0]
                                        .payload,
                                        b"\xaa\xbb",
                                    )
                            else:
                                self.assertEqual(backend.calls, [])
                        finally:
                            controller.close()
                            for comm in communications:
                                comm.disconnect()
                        self.assertEqual(
                            sum(name == "connect" for name, _ in backend.calls),
                            sum(name == "disconnect" for name, _ in backend.calls),
                        )

    def test_run_third_century_registration_returns_native_setup_failure(self):
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
        )

        for build in (12, 18):
            for ids in ((), (17,)):
                backend = self.run_backend()
                communications = tuple(
                    self.run_communication(
                        3,
                        build,
                        backend,
                        category=42 + index,
                        diagnostic_mode=bytes(8)
                        + source.to_bytes(4, "little")
                        + bytes(4),
                        functional_id=0x33,
                    )
                    for index, source in enumerate((0x10, 0x18, 0x20))
                )
                controller = LegacyMonitorController(
                    family="P3", connected_device=8, clock=lambda: 0
                )
                queue = LegacyCommandQueue()
                controller.queue = queue
                message = LegacyControlMessage(
                    56,
                    tuple(
                        LegacyRunTarget(comm, ids, self.observed(11))
                        for comm in communications
                    ),
                )
                queue.put(message)
                try:
                    result = controller.run_one()
                    assert result is not None
                    self.assertEqual(result.status, 0xA0050425)
                    self.assertIsNone(message.exception)
                    self.assertTrue(queue.finish_event.is_set())
                    self.assertEqual(controller.active_mask, 0)
                finally:
                    controller.close()
                    for communication in communications:
                        communication.disconnect()

    def test_run_century_absent_dm_registration_preserves_native_fault_boundary(self):
        from scripts.monitor_j2534 import CenturyJ2534Worker, NativeMonitorSourceFault
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
        )

        for build in (12, 18):
            for selection in (((), ()), ((), (17,)), ((17,), ())):
                with self.subTest(build=build, selection=selection):
                    backend = self.run_backend()
                    communications = tuple(
                        self.run_communication(
                            3,
                            build,
                            backend,
                            category=42 + index,
                            diagnostic_mode=bytes(8)
                            + source.to_bytes(4, "little")
                            + bytes(4),
                            functional_id=0x33,
                        )
                        for index, source in enumerate((0x10, 0x18))
                    )
                    controller = LegacyMonitorController(
                        family="P3", connected_device=8, clock=lambda: 0
                    )
                    queue = LegacyCommandQueue()
                    controller.queue = queue
                    message = LegacyControlMessage(
                        56,
                        tuple(
                            LegacyRunTarget(
                                comm,
                                ids,
                                self.observed(11),
                                allocation_size=65536 if ids else 0,
                            )
                            for comm, ids in zip(communications, selection, strict=True)
                        ),
                    )
                    before = len(backend.calls)
                    queue.put(message)
                    try:
                        if any(selection):
                            with self.assertRaises(NativeMonitorSourceFault) as caught:
                                controller.run_one()
                            self.assertIs(message.exception, caught.exception)
                            self.assertIsNone(message.result)
                            self.assertTrue(queue.finish_event.is_set())
                            self.assertEqual(controller.active_mask, 0)
                            self.assertEqual(
                                sum(
                                    name == "connect"
                                    for name, _ in backend.calls[before:]
                                ),
                                1,
                            )
                        else:
                            result = controller.run_one()
                            assert result is not None
                            self.assertEqual((result.status, result.flags20), (0, 0x80))
                            assert isinstance(controller._worker, CenturyJ2534Worker)
                            self.assertTrue(
                                all(
                                    system.event is None
                                    for system in controller._worker.systems
                                )
                            )
                            self.assertEqual(controller.poll(), ())
                            self.assertEqual(len(backend.calls), before)
                            active = LegacyControlMessage(11, signal_id=34, value=3)
                            queue.put(active)
                            result = controller.run_one()
                            assert result is not None
                            self.assertEqual(result.status, 0)
                            self.assertIsNone(active.exception)
                            self.assertTrue(queue.finish_event.is_set())
                            with self.assertRaises(NativeMonitorSourceFault):
                                controller.poll()
                            self.assertEqual(len(backend.calls), before)
                    finally:
                        controller.close()
                        for communication in communications:
                            communication.disconnect()

    def test_run_multi_dmci_retains_primary_constructor_and_active_flags(self):
        from dataclasses import replace

        from scripts.drive_recorder import (
            NativeVimClient,
            NativeVimReply,
            decode_vim_command,
        )
        from scripts.frame_transport import DriverProperties
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
        )
        from scripts.native_communication import NativeCommunication

        for build in (12, 18):
            backend = self.run_backend()
            primary = self.run_communication(3, build, backend)
            profile = primary.profile
            management = profile.catalog.management
            section = management.sections[16]
            payload = bytearray(section.payload)
            selected = None
            for offset in range(0, len(payload), 76):
                if int.from_bytes(payload[offset + 68 : offset + 70], "little") == 43:
                    payload[offset + 72] = 4
                    selected = bytes(payload[offset : offset + 76])
            assert selected is not None
            profile.catalog.management = replace(
                management,
                sections={
                    **management.sections,
                    16: replace(section, payload=bytes(payload)),
                },
            )
            secondary = NativeCommunication.from_backend(
                replace(profile, category_record=selected),
                backend,
                "engine",
                first_request=b"\x21\x00",
                driver=DriverProperties(0, b"04.04", "authored"),
                device_kind=8,
                bus_id=0x11,
                source_build=build,
                clock=lambda: 0,
            )
            calls = []

            def exchange(request, *, deadline, cancelled, calls=calls):
                command, body = decode_vim_command(request)
                calls.append((command, body))
                output = (
                    bytes.fromhex("0000000001000000") if command == 0x247F else bytes(4)
                )
                return NativeVimReply(command | 0x80, 6, output).encode()

            client = NativeVimClient(
                exchange,
                capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                clock=lambda: 0,
            )
            controller = LegacyMonitorController(
                family="P3",
                connected_device=4,
                client=client,
                init_mode=1,
                parameter_c0=77,
                clock=lambda: 0,
            )
            queue = LegacyCommandQueue()
            controller.queue = queue
            first = LegacyRunTarget(primary, (), {})
            second = LegacyRunTarget(secondary, (), {})
            try:
                start = LegacyControlMessage(56, (first, second))
                queue.put(start)
                result = controller.run_one()
                assert result is not None
                self.assertEqual(result.status, 0)
                active = LegacyControlMessage(11, (second,), signal_id=34, value=3)
                queue.put(active)
                result = controller.run_one()
                assert result is not None
                self.assertEqual(result.status, 0)
                self.assertIsNone(active.exception)
                self.assertEqual(
                    [body for command, body in calls if command == 0x1B7F],
                    [bytes.fromhex("f0108000010000000200000055030000")],
                )
                self.assertEqual(sum(command == 0x107F for command, _ in calls), 1)
                self.assertEqual(backend.calls, [])
            finally:
                controller.close()
                primary.disconnect()
                secondary.disconnect()

    def test_run_dmci_error_callback_retains_active_signal_across_stop_and_system(self):
        import struct

        from scripts.drive_recorder import (
            NativeCoreBuffer,
            NativeDmciList,
            NativeMonitorReply,
            NativeVimClient,
            NativeVimReply,
            decode_vim_command,
        )
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
        )

        for build in (12, 18):
            backend = self.run_backend()
            comm = self.run_communication(3, build, backend)
            calls = []

            def exchange(request, *, deadline, cancelled, calls=calls):
                command, payload = decode_vim_command(request)
                calls.append((command, payload))
                if command == 0x197F:
                    empty = NativeCoreBuffer((1, 0), b"")
                    detailed = NativeCoreBuffer(
                        (1, 0), struct.pack("<IIIB", 0, 0x12345678, 0xE00001CC, 0xA5)
                    )
                    output = NativeMonitorReply(
                        0,
                        NativeDmciList((1, 0), ()),
                        (empty, detailed, empty, empty, empty),
                        0,
                    ).encode()
                elif command == 0x247F:
                    output = struct.pack("<II", 0, 1)
                else:
                    output = bytes(4)
                return NativeVimReply(command | 0x80, 6, output).encode()

            client = NativeVimClient(
                exchange,
                capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                clock=lambda: 0,
            )
            controller = LegacyMonitorController(
                family="P3",
                connected_device=4,
                client=client,
                init_mode=1,
                parameter_c0=77,
                clock=lambda: 0,
            )
            queue = LegacyCommandQueue()
            controller.queue = queue
            target = LegacyRunTarget(comm, (17,), self.observed(11))

            def dispatch(message, queue=queue, controller=controller):
                queue.put(message)
                result = controller.run_one()
                assert result is not None
                self.assertEqual(result.status, 0)

            try:
                dispatch(LegacyControlMessage(9, (target,)))
                controller.poll()
                self.assertEqual(controller.notifications[-1].lparam, 0)
                dispatch(LegacyControlMessage(11, signal_id=34, value=3))
                controller.poll()
                notice = controller.notifications[-1]
                self.assertEqual(
                    (notice.message, notice.wparam, notice.lparam), (0x602, 0, 34)
                )
                dispatch(LegacyControlMessage(12))
                dispatch(LegacyControlMessage(96, signal_id=0x44))
                controller.poll()
                self.assertEqual(controller.notifications[-1].lparam, 34)
                dispatch(LegacyControlMessage(10))
                dispatch(LegacyControlMessage(9, (target,)))
                controller.poll()
                self.assertEqual(controller.notifications[-1].lparam, 0)
                self.assertIn(
                    (0x197F, bytes.fromhex("01000000010000002a000000")), calls
                )
            finally:
                controller.close()
                comm.disconnect()
            self.assertEqual(
                sum(name == "connect" for name, _ in backend.calls),
                sum(name == "disconnect" for name, _ in backend.calls),
            )

    def test_run_active_only_dmci_uses_polling_and_native_control_cleanup(self):
        import struct

        from scripts.drive_recorder import (
            NativeCoreBuffer,
            NativeDmciList,
            NativeMonitorReply,
            NativeVimClient,
            NativeVimReply,
            decode_vim_command,
        )
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
        )

        for build in (12, 18):
            backend = self.run_backend()
            communication = self.run_communication(3, build, backend)
            calls = []

            def exchange(request, *, deadline, cancelled, calls=calls):
                command, payload = decode_vim_command(request)
                calls.append((command, payload))
                if command == 0x197F:
                    self.assertEqual(payload, bytes.fromhex("0100000000000000"))
                    empty = NativeCoreBuffer((1, 0), b"")
                    output = NativeMonitorReply(
                        0,
                        NativeDmciList((1, 0), ()),
                        (empty, empty, empty, empty, empty),
                        0,
                    ).encode()
                elif command == 0x247F:
                    output = struct.pack("<II", 0, 1)
                else:
                    output = bytes(4)
                return NativeVimReply(command | 0x80, 6, output).encode()

            client = NativeVimClient(
                exchange,
                capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                clock=lambda: 0,
            )
            controller = LegacyMonitorController(
                family="P3",
                connected_device=4,
                client=client,
                init_mode=1,
                parameter_c0=77,
                clock=lambda: 0,
            )
            queue = LegacyCommandQueue()
            controller.queue = queue
            try:
                for message in (
                    LegacyControlMessage(
                        9, (LegacyRunTarget(communication, (), self.observed()),)
                    ),
                    LegacyControlMessage(11, signal_id=34, value=3),
                    LegacyControlMessage(96, signal_id=0x44),
                ):
                    queue.put(message)
                    result = controller.run_one()
                    assert result is not None
                    self.assertEqual(result.status, 0)
                self.assertEqual(controller.buffers, (None,))
                self.assertEqual(controller.poll(), ())
                stop = LegacyControlMessage(10)
                queue.put(stop)
                result = controller.run_one()
                assert result is not None
                self.assertEqual(result.status, 0)
                commands = [command for command, _ in calls]
                self.assertIn(0x1B7F, commands)
                self.assertIn(0x1F7F, commands)
                self.assertNotIn(0x167F, commands)
                self.assertNotIn(0x187F, commands)
                self.assertEqual(commands[-3:], [0x1C7F, 0x147F, 0x127F])
            finally:
                controller.close()
                communication.disconnect()

    def test_run_native_active_only_has_no_data_buffer_or_early_io(self):
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
        )

        for build in (12, 18):
            for family, phase, mode in (("P3", 3, 0x80), ("DK", 7, 0x400)):
                with self.subTest(build=build, family=family):
                    backend = self.run_backend()
                    communication = self.run_communication(phase, build, backend)
                    target = LegacyRunTarget(
                        communication, (), self.observed(), allocation_size=0
                    )
                    controller = LegacyMonitorController(
                        family=family, connected_device=8, clock=lambda: 0
                    )
                    queue = LegacyCommandQueue()
                    controller.queue = queue
                    try:
                        before = len(backend.calls)
                        start = LegacyControlMessage(9, (target,))
                        queue.put(start)
                        result = controller.run_one()
                        assert result is not None
                        self.assertEqual((result.status, result.flags20), (0, mode))
                        self.assertEqual(controller.buffers, (None,))
                        self.assertEqual(controller.poll(), ())
                        self.assertEqual(len(backend.calls), before)
                        with self.assertRaises(MonitorError):
                            controller.capture()
                        active = LegacyControlMessage(11, signal_id=34, value=3)
                        queue.put(active)
                        result = controller.run_one()
                        assert result is not None
                        self.assertEqual(result.status, 0)
                        for _ in range(8):
                            controller.poll()
                        writes = [
                            fields["messages"][0].data[3:]
                            for name, fields in backend.calls[before:]
                            if name == "write_messages"
                        ]
                        self.assertIn(
                            b"\x30\x55\x03" if family == "P3" else b"\x3d\x55", writes
                        )
                        self.assertFalse(
                            any(
                                write.startswith((b"\x01", b"\x2c", b"\xa1"))
                                for write in writes
                            )
                        )
                        self.assertEqual(controller.packets, [[]])
                    finally:
                        controller.close()
                        communication.disconnect()

    def test_p3_active_did_support_uses_actual_function14_stream_and_first_service(
        self,
    ):
        from scripts.frame_transport import J2534Result, NativeMessage
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
        )

        for build in (12, 18):
            for service_present in (False, True):
                with self.subTest(build=build, service_present=service_present):
                    backend = self.run_backend()
                    original = backend.invoke
                    reads = [0]

                    def invoke(
                        operation,
                        fields,
                        *,
                        deadline,
                        cancelled,
                        original=original,
                        backend=backend,
                        reads=reads,
                        service_present=service_present,
                    ):
                        if (
                            operation == "read_messages"
                            and backend.request == b"\x02\x00"
                        ):
                            reads[0] += 1
                            if reads[0] == 1:
                                payload = bytes(
                                    (
                                        0x42,
                                        0,
                                        0x55 if service_present else 0x56,
                                        3,
                                        0xAA,
                                        0xBB,
                                        0xCC,
                                    )
                                )
                                return J2534Result(
                                    count=1,
                                    messages=(
                                        NativeMessage(
                                            1,
                                            0,
                                            0,
                                            0,
                                            0,
                                            bytes((0x48, 0x6B, 0x10)) + payload,
                                        ),
                                    ),
                                )
                            return J2534Result(code=9)
                        return original(
                            operation, fields, deadline=deadline, cancelled=cancelled
                        )

                    backend.invoke = invoke
                    comm = self.run_communication(4, build, backend, did_active=True)
                    target = LegacyRunTarget(comm, (), {})
                    from scripts.drive_recorder import (
                        NativeVimClient,
                        NativeVimReply,
                        decode_vim_command,
                    )

                    calls = []

                    def exchange(request, *, deadline, cancelled, calls=calls):
                        command, payload = decode_vim_command(request)
                        calls.append((command, payload))
                        output = (
                            bytes.fromhex("0000000001000000")
                            if command == 0x247F
                            else bytes(4)
                        )
                        return NativeVimReply(command | 0x80, 6, output).encode()

                    client = NativeVimClient(
                        exchange,
                        capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
                        clock=lambda: 0,
                    )
                    controller = LegacyMonitorController(
                        family="P3",
                        connected_device=4,
                        client=client,
                        init_mode=1,
                        parameter_c0=77,
                        clock=lambda: 0,
                    )
                    queue = LegacyCommandQueue()
                    controller.queue = queue
                    try:
                        queue.put(LegacyControlMessage(9, (target,)))
                        result = controller.run_one()
                        assert result is not None
                        self.assertEqual(result.status, 0)
                        queue.put(
                            LegacyControlMessage(
                                11, (target,), signal_id=34, value=3, auxiliary=7
                            )
                        )
                        result = controller.run_one()
                        assert result is not None
                        self.assertEqual(
                            result.status, 0 if service_present else 0xC005100C
                        )
                        self.assertEqual(reads[0], 2)
                        self.assertTrue(queue.finish_event.is_set())
                        active = [
                            payload for command, payload in calls if command == 0x1B7F
                        ]
                        self.assertEqual(
                            active,
                            [bytes.fromhex("f06a6800010000000200000055030000")]
                            if service_present
                            else [],
                        )
                        writes = [
                            fields["messages"][0].data[3:]
                            for name, fields in backend.calls
                            if name == "write_messages"
                        ]
                        self.assertEqual(writes.count(b"\x02\x00"), 1)
                        self.assertNotIn(b"\x30\x55\x03", writes)
                    finally:
                        controller.close()
                        comm.disconnect()
                    self.assertEqual(
                        sum(name == "connect" for name, _ in backend.calls),
                        sum(name == "disconnect" for name, _ in backend.calls),
                    )

    def test_dk_native_completion_waits_preserve_queue_finish_and_timeout_codes(self):
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
        )
        from scripts.toyota_session import Limits

        for build in (12, 18):
            for active_only in (False, True):
                with self.subTest(build=build, active_only=active_only):
                    now = [0.0]
                    clock = lambda now=now: now[0]
                    limits = Limits(seconds=60)
                    backend = self.run_backend()
                    comm = self.run_communication(
                        7, build, backend, clock=clock, limits=limits
                    )
                    target = LegacyRunTarget(
                        comm, () if active_only else (17,), self.observed(26)
                    )
                    controller = LegacyMonitorController(
                        family="DK",
                        connected_device=8,
                        clock=clock,
                        limits=limits,
                    )
                    queue = LegacyCommandQueue()
                    controller.queue = queue
                    try:
                        self.assertTrue(
                            all(
                                event.is_set()
                                for event in controller.dk_events.values()
                            )
                        )
                        queue.put(LegacyControlMessage(9, (target,)))
                        result = controller.run_one()
                        assert result is not None
                        self.assertEqual(result.status, 0)
                        if active_only:
                            queue.put(
                                LegacyControlMessage(
                                    11, (target,), signal_id=34, value=3
                                )
                            )
                            result = controller.run_one()
                            assert result is not None
                            self.assertEqual(result.status, 0)
                            self.assertFalse(controller.dk_events["active"].is_set())
                        else:
                            self.assertFalse(controller.dk_events["data"].is_set())
                        message = LegacyControlMessage(12 if active_only else 10)
                        queue.put(message)
                        before = len(backend.calls)
                        self.assertIsNone(controller.run_one())
                        self.assertFalse(queue.finish_event.is_set())
                        self.assertIsNone(message.result)
                        now[0] = 9.999
                        self.assertIsNone(controller.run_one())
                        self.assertEqual(len(backend.calls), before)
                        now[0] = 10.0
                        result = controller.run_one()
                        assert result is not None
                        self.assertEqual(result.status, 0)
                        self.assertIs(message.result, result)
                        self.assertTrue(queue.finish_event.is_set())
                        self.assertEqual(
                            controller.notifications[-1].wparam, 0xC0050504
                        )
                        self.assertTrue(controller.dk_events["stopped"].is_set())
                        self.assertEqual(
                            controller.active_mask, 0x400 if active_only else 0
                        )
                    finally:
                        controller.close()
                        comm.disconnect()
                    connected = [
                        fields for name, fields in backend.calls if name == "connect"
                    ]
                    released = [
                        fields for name, fields in backend.calls if name == "disconnect"
                    ]
                    self.assertEqual(len(connected), len(released))

    def test_dk_native_fault_unblocks_wait_and_cooperative_exit_finishes_pending(self):
        from scripts.frame_transport import J2534Result
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
        )

        for build in (12, 18):
            for fault in (False, True):
                with self.subTest(build=build, fault=fault):
                    backend = self.run_backend()
                    comm = self.run_communication(7, build, backend)
                    controller = LegacyMonitorController(
                        family="DK", connected_device=8, clock=lambda: 0
                    )
                    queue = LegacyCommandQueue()
                    controller.queue = queue
                    try:
                        queue.put(
                            LegacyControlMessage(
                                9, (LegacyRunTarget(comm, (17,), self.observed(26)),)
                            )
                        )
                        controller.run_one()
                        message = LegacyControlMessage(10)
                        queue.put(message)
                        self.assertIsNone(controller.run_one())
                        if fault:
                            original = backend.invoke

                            def invoke(
                                operation,
                                fields,
                                *,
                                deadline,
                                cancelled,
                                original=original,
                            ):
                                if operation == "read_messages":
                                    return J2534Result(code=7)
                                return original(
                                    operation,
                                    fields,
                                    deadline=deadline,
                                    cancelled=cancelled,
                                )

                            backend.invoke = invoke
                            with self.assertRaises(MonitorError):
                                controller.poll()
                            self.assertTrue(
                                all(
                                    controller.dk_events[key].is_set()
                                    for key in ("active", "data", "failed")
                                )
                            )
                            self.assertFalse(queue.finish_event.is_set())
                            result = controller.run_one()
                            assert result is not None
                            self.assertEqual(result.status, 0)
                            self.assertEqual(tuple(controller.notifications), ())
                        else:
                            controller.close()
                            self.assertIsInstance(message.exception, MonitorError)
                            assert isinstance(message.exception, MonitorError)
                            self.assertEqual(message.exception.code, 0xA0050511)
                        self.assertTrue(queue.finish_event.is_set())
                        self.assertEqual(controller.active_mask, 0)
                    finally:
                        controller.close()
                        comm.disconnect()
                    self.assertEqual(
                        sum(name == "connect" for name, _ in backend.calls),
                        sum(name == "disconnect" for name, _ in backend.calls),
                    )

    def test_dk_pending_wait_cancellation_keeps_exact_exception_and_releases_channel(
        self,
    ):
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
        )
        from scripts.toyota_session import Cancelled

        for build in (12, 18):
            backend = self.run_backend()
            comm = self.run_communication(7, build, backend)
            cancelled = [False]
            controller = LegacyMonitorController(
                family="DK",
                connected_device=8,
                clock=lambda: 0,
                cancelled=lambda cancelled=cancelled: cancelled[0],
            )
            queue = LegacyCommandQueue()
            controller.queue = queue
            try:
                queue.put(
                    LegacyControlMessage(
                        9, (LegacyRunTarget(comm, (17,), self.observed(26)),)
                    )
                )
                controller.run_one()
                message = LegacyControlMessage(10)
                queue.put(message)
                self.assertIsNone(controller.run_one())
                cancelled[0] = True
                with self.assertRaises(Cancelled) as raised:
                    controller.run_one()
                self.assertIs(message.exception, raised.exception)
                self.assertTrue(queue.finish_event.is_set())
                self.assertEqual(controller.active_mask, 0)
            finally:
                controller.close()
                comm.disconnect()
            self.assertEqual(
                sum(name == "connect" for name, _ in backend.calls),
                sum(name == "disconnect" for name, _ in backend.calls),
            )

    def test_run_selected_active_system_and_stop_dispatch(self):
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
        )

        for build in (12, 18):
            for family, phase, function in (
                ("P3", 3, 11),
                ("P3", 5, 11),
                ("P3", 9, 11),
                ("P3", 18, 11),
                ("DK", 7, 26),
            ):
                with self.subTest(build=build, family=family):
                    backend = self.run_backend()
                    from scripts.toyota_session import Limits

                    now = [0.0]
                    clock = lambda now=now: now[0]
                    limits = Limits(seconds=60)
                    communication = self.run_communication(
                        phase, build, backend, clock=clock, limits=limits
                    )
                    target = LegacyRunTarget(
                        communication, (17,), self.observed(function)
                    )
                    controller = LegacyMonitorController(
                        family=family, connected_device=8, clock=clock, limits=limits
                    )
                    queue = LegacyCommandQueue()
                    controller.queue = queue

                    def dispatch(
                        message,
                        queue=queue,
                        controller=controller,
                        family=family,
                        now=now,
                    ):
                        queue.put(message)
                        result = controller.run_one()
                        if family == "DK" and message.command_id == 11:
                            self.assertIsNone(result)
                            self.assertFalse(queue.finish_event.is_set())
                            now[0] = 30.0
                            result = controller.run_one()
                            self.assertEqual(
                                controller.notifications[-1].wparam, 0xC0050503
                            )
                        assert result is not None
                        return result

                    try:
                        self.assertEqual(
                            dispatch(LegacyControlMessage(9, (target,))).status, 0
                        )
                        self.assertEqual(
                            dispatch(
                                LegacyControlMessage(
                                    11, (target,), signal_id=34, value=3
                                )
                            ).status,
                            0,
                        )
                        for _ in range(8):
                            controller.poll()
                        writes = [
                            fields["messages"][0].data[3:]
                            for name, fields in backend.calls
                            if name == "write_messages"
                        ]
                        self.assertIn(
                            b"\x30\x55\x03" if family == "P3" else b"\x3d\x55", writes
                        )
                        if family == "P3":
                            self.assertEqual(
                                dispatch(
                                    LegacyControlMessage(96, (target,), signal_id=0x44)
                                ).status,
                                0,
                            )
                            for _ in range(8):
                                controller.poll()
                            writes = [
                                fields["messages"][0].data[3:]
                                for name, fields in backend.calls
                                if name == "write_messages"
                            ]
                            self.assertIn(b"\x08\x44" + bytes(5), writes)
                        self.assertEqual(dispatch(LegacyControlMessage(12)).status, 0)
                        if family == "DK":
                            before = len(backend.calls)
                            self.assertEqual(controller.poll(), ())
                            self.assertEqual(len(backend.calls), before)
                        self.assertEqual(dispatch(LegacyControlMessage(10)).status, 0)
                        if family == "DK":
                            self.assertEqual(
                                dispatch(LegacyControlMessage(87, (target,))).status,
                                0x90050405,
                            )
                    finally:
                        controller.close()
                        communication.disconnect()

    def test_run_selected_multi_dk_destination_and_century_functional_buffers(self):
        from scripts.frame_transport import J2534Result, NativeMessage
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
        )

        for build in (12, 18):
            for family, phase, function in (("P3", 3, 11), ("DK", 7, 26)):
                with self.subTest(build=build, family=family):
                    backend = self.run_backend()
                    invoke = backend.invoke
                    replies = [0]

                    def functional(
                        operation,
                        fields,
                        *,
                        deadline,
                        cancelled,
                        invoke=invoke,
                        backend=backend,
                        replies=replies,
                    ):
                        result = invoke(
                            operation, fields, deadline=deadline, cancelled=cancelled
                        )
                        if (
                            operation == "read_messages"
                            and backend.request == b"\x01\x01"
                            and backend.response_source == 0x33
                        ):
                            reply = (
                                b"\x84\xb5\x10\x41\x01\xaa\xbb",
                                b"\x84\xb5\x18\x41\x01\xcc\xdd",
                            )[replies[0] % 2]
                            replies[0] += 1
                            return J2534Result(
                                count=1, messages=(NativeMessage(4, 0, 0, 0, 0, reply),)
                            )
                        return result

                    backend.invoke = functional
                    communications = tuple(
                        self.run_communication(
                            phase,
                            build,
                            backend,
                            category=42 + index,
                            diagnostic_mode=bytes(8)
                            + source.to_bytes(4, "little")
                            + bytes(4),
                            functional_id=0x33 if family == "P3" else None,
                        )
                        for index, source in enumerate(
                            (0x10, 0x18) if family == "P3" else (0x10, 0x10)
                        )
                    )
                    controller = LegacyMonitorController(
                        family=family, connected_device=8, clock=lambda: 0
                    )
                    queue = LegacyCommandQueue()
                    controller.queue = queue
                    start = LegacyControlMessage(
                        56,
                        tuple(
                            LegacyRunTarget(comm, (17,), self.observed(function))
                            for comm in communications
                        ),
                    )
                    queue.put(start)
                    try:
                        result = controller.run_one()
                        assert result is not None
                        self.assertEqual(result.status, 0)
                        for _ in range(12):
                            controller.poll()
                            if (
                                (controller.packets[0] and controller.packets[1])
                                if family == "P3"
                                else controller.packets[1]
                            ):
                                break
                        if family == "P3":
                            self.assertEqual(
                                controller.packets[0][0].payload, b"\xaa\xbb"
                            )
                            self.assertEqual(
                                controller.packets[1][0].payload, b"\xcc\xdd"
                            )
                        else:
                            self.assertEqual(controller.packets[0], [])
                            self.assertEqual(
                                controller.packets[1][0].payload, b"\xaa\xbb"
                            )
                        self.assertEqual(len(controller.buffers), 2)
                    finally:
                        controller.close()
                        for comm in communications:
                            comm.disconnect()
                    released = [
                        fields["channel_id"]
                        for name, fields in backend.calls
                        if name == "disconnect"
                    ]
                    self.assertEqual(
                        sorted(released), list(range(9, backend.next_channel))
                    )
                    self.assertEqual(len(released), len(set(released)))

    def test_run_native_fault_restart_and_queue_event_order(self):
        import time

        from scripts.frame_transport import J2534Result
        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
        )

        for build in (12, 18):
            for family, phase, function in (("P3", 3, 11), ("DK", 7, 26)):
                with self.subTest(build=build, family=family):
                    backend = self.run_backend()
                    communication = self.run_communication(phase, build, backend)
                    invoke = backend.invoke
                    failing = [True]

                    def fault(
                        operation,
                        fields,
                        *,
                        deadline,
                        cancelled,
                        invoke=invoke,
                        failing=failing,
                        backend=backend,
                    ):
                        result = invoke(
                            operation, fields, deadline=deadline, cancelled=cancelled
                        )
                        if (
                            failing[0]
                            and operation == "read_messages"
                            and backend.request in (b"\x01\x01", b"\x2c\x01")
                        ):
                            return J2534Result(code=7)
                        return result

                    backend.invoke = fault
                    target = LegacyRunTarget(
                        communication, (17,), self.observed(function)
                    )
                    queue = LegacyCommandQueue()
                    controller = LegacyMonitorController(
                        family=family,
                        connected_device=8,
                        shared_interface=3,
                        clock=lambda: 0,
                    )
                    controller.run(queue)
                    try:
                        start = LegacyControlMessage(9, (target,))
                        queue.put(start)
                        self.assertTrue(queue.finish_event.wait(2))
                        assert start.result is not None
                        self.assertEqual(
                            (
                                start.result.status,
                                start.result.flags24,
                                start.result.flags28,
                            ),
                            (0, 0, 1),
                        )
                        until = time.monotonic() + 2
                        while (
                            not controller.buffer_error() and time.monotonic() < until
                        ):
                            time.sleep(0.001)
                        self.assertNotEqual(controller.buffer_error(), 0)
                        until = time.monotonic() + 2
                        while controller.active_mask and time.monotonic() < until:
                            time.sleep(0.001)
                        self.assertEqual(controller.active_mask, 0)
                        assert controller._acquisition is not None
                        self.assertTrue(controller._acquisition.is_alive())
                        self.assertIsNone(controller.failure)
                        self.assertTrue(
                            any(name == "disconnect" for name, _ in backend.calls)
                        )
                        failing[0] = False
                        restart = LegacyControlMessage(56, (target,))
                        queue.put(restart)
                        self.assertTrue(queue.finish_event.wait(2))
                        assert restart.result is not None
                        self.assertEqual(
                            (
                                restart.result.status,
                                restart.result.flags24,
                                restart.result.flags28,
                            ),
                            (0, 1, 0),
                        )
                        until = time.monotonic() + 2
                        while not controller.packets[0] and time.monotonic() < until:
                            time.sleep(0.001)
                        self.assertEqual(controller.packets[0][0].payload, b"\xaa\xbb")
                        rejected = LegacyControlMessage(137)
                        queue.put(rejected)
                        self.assertTrue(queue.finish_event.wait(2))
                        assert rejected.result is not None
                        self.assertEqual(rejected.result.status, 0x90050405)
                        trace = list(controller.trace)
                        finish = trace.index(("finish", 137))
                        self.assertEqual(trace[finish + 1], ("error", 0x90050405))
                        self.assertEqual(trace[finish + 2], ("stopped", 0))
                    finally:
                        controller.close()
                        communication.disconnect()

        queue = LegacyCommandQueue(maximum=1)
        message = LegacyControlMessage(10)
        queue.put(message)
        with self.assertRaises(MonitorError):
            queue.put(message)
        with self.assertRaises(MonitorError):
            queue.put(LegacyControlMessage(10))
        self.assertIs(queue.get(), message)
        with self.assertRaises(MonitorError):
            queue.put(message)
        controller = LegacyMonitorController(family="P3", connected_device=8)
        controller.queue = queue
        empty = controller.run_one()
        assert empty is not None
        self.assertEqual(empty.status, 0xC0050404)
        self.assertEqual(
            list(controller.trace)[:2], [("finish", 0), ("error", 0xC0050404)]
        )
        self.assertTrue(queue.finish_event.is_set())
        controller.run_one(wait_status=0xFFFFFFFF)
        self.assertIn(("error", 0xA0050511), controller.trace)
        controller.run_one(wait_status=1)
        self.assertTrue(controller.worker_exit.is_set())
        controller.close()

    def test_run_host_failure_cancel_and_native_callbacks_preserve_cleanup(self):
        from threading import Event

        from scripts.monitor_legacy import (
            LegacyCommandQueue,
            LegacyControlMessage,
            LegacyMonitorController,
            LegacyRunTarget,
            legacy_error_notification,
        )
        from scripts.toyota_session import Cancelled

        for family, phase, function in (("P3", 3, 11), ("DK", 7, 26)):
            for scenario in ("host", "cancel"):
                backend = self.run_backend()
                communication = self.run_communication(phase, 18, backend)
                marker = RuntimeError("authored primitive failure")
                cancelled_flag = Event()
                invoke = backend.invoke

                def fault(
                    operation,
                    fields,
                    *,
                    deadline,
                    cancelled,
                    backend=backend,
                    invoke=invoke,
                    marker=marker,
                    scenario=scenario,
                    cancelled_flag=cancelled_flag,
                ):
                    result = invoke(
                        operation, fields, deadline=deadline, cancelled=cancelled
                    )
                    if operation == "read_messages" and backend.request in (
                        b"\x01\x01",
                        b"\x2c\x01",
                    ):
                        if scenario == "host":
                            raise marker
                        cancelled_flag.set()
                    return result

                backend.invoke = fault
                controller = LegacyMonitorController(
                    family=family,
                    connected_device=8,
                    clock=lambda: 0,
                    cancelled=cancelled_flag.is_set,
                )
                queue = LegacyCommandQueue()
                queue.put(
                    LegacyControlMessage(
                        9,
                        (
                            LegacyRunTarget(
                                communication, (17,), self.observed(function)
                            ),
                        ),
                    )
                )
                controller.run(queue)
                try:
                    self.assertTrue(controller.worker_exit.wait(2))
                    if scenario == "host":
                        self.assertIs(controller.failure, marker)
                    else:
                        self.assertIsInstance(controller.failure, Cancelled)
                    self.assertEqual(controller.active_mask, 0)
                    self.assertIn("disconnect", [name for name, _ in backend.calls])
                finally:
                    controller.close()
                    communication.disconnect()
                self.assertTrue(controller.worker_exit.is_set())
                assert (
                    controller._thread is not None
                    and controller._acquisition is not None
                )
                self.assertFalse(controller._thread.is_alive())
                self.assertFalse(controller._acquisition.is_alive())
        for error, status, family, expected in (
            (0, 0xE0000110, "P3", 0xA1050312),
            (0x1234, 0xE000FFFF, "DK", 0x34),
            (0, 0xE0030001, "DK", 0xA1050305),
        ):
            note = legacy_error_notification(error, status, family=family)
            assert note is not None
            self.assertEqual(note.wparam, expected)
        self.assertIsNone(legacy_error_notification(0, 0xE0000189, family="P3"))

    def test_actual_check_frontend_support_wire_allocation_fault_and_cancel(self):
        import struct
        from copy import copy
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.monitor_legacy import LegacyCheckTarget, check_legacy_monitor
        from scripts.toyota_session import Cancelled, Limits

        for build in (12, 18):
            for family, phase, function in (("P3", 3, 11), ("DK", 7, 26)):
                base = self.native_profile(phase, source_build=build)
                catalog = copy(base.catalog)
                sections = dict(catalog.management.sections)
                sections[0] = Section(
                    0,
                    0,
                    3,
                    False,
                    struct.pack("<IHIHIH", 0, 1, 1, 1, 2, 2) + b"\x81\x3e\x21\x00",
                )
                sections[17] = replace(
                    sections[17],
                    count=3,
                    payload=sections[17].payload + struct.pack("<4H", 3, 3, 0, 0),
                )
                sections[18] = replace(
                    sections[18],
                    count=3,
                    payload=struct.pack("<8H", 42, 15, 0, 3, 0, 0, 0, 0)
                    + sections[18].payload,
                )
                sections[29] = Section(
                    29, 0, 1, False, struct.pack("<II4H", 1000, 200, 0, 0, 0, 0)
                )
                catalog.management = replace(catalog.management, sections=sections)
                profile = replace(base, catalog=catalog)
                calls = []

                def exchange(query, calls=calls):
                    calls.append(query)
                    return b"\x61\x00\x80"

                target = LegacyCheckTarget(
                    profile,
                    (17,),
                    "engine",
                    0x11,
                    self.observed(function),
                    exchange,
                    source_build=build,
                )
                result = check_legacy_monitor(
                    (target, target),
                    family=family,
                    command_kind=0x42,
                    allocation=101,
                    connected_device=4,
                    command_ecu=42,
                    clock=lambda: 0,
                )
                self.assertTrue(result.available)
                self.assertEqual(
                    tuple(item.allocation for item in result.measurements), (50, 51)
                )
                self.assertEqual(
                    [query.request for query in calls], [b"\x21\x00", b"\x21\x00"]
                )
                self.assertEqual(
                    tuple(item.packet_size for item in result.measurements), (6, 6)
                )
                # The selected caller must reach the real retained lower channel.
                from scripts.data_monitor import selected_legacy_check_target
                from scripts.frame_transport import (
                    DriverProperties,
                    J2534Result,
                    NativeMessage,
                )
                from scripts.native_communication import NativeCommunication

                primitive_calls = []

                class Backend:
                    def __init__(
                        self,
                        *,
                        packet=False,
                        fault=False,
                        cancel=False,
                        calls=primitive_calls,
                    ):
                        self.calls = calls
                        self.packet, self.fault, self.cancel = packet, fault, cancel
                        self.request = b""
                        self.packet_reads = 0
                        self.cancelled = False

                    def invoke(self, operation, fields, *, deadline, cancelled):
                        self.calls.append((operation, fields))
                        if operation == "connect":
                            return J2534Result(handle=9)
                        if operation == "start_message_filter":
                            return J2534Result(handle=10)
                        if operation == "ioctl" and fields["ioctl_id"] == 5:
                            return J2534Result(
                                messages=(
                                    NativeMessage(
                                        4, 0, 0, 0, 0, b"\x83\xf0\x10\xc1\x08\x08"
                                    ),
                                )
                            )
                        if operation == "write_messages":
                            self.request = fields["messages"][0].data[3:]
                            self.cancelled = self.cancel
                        if operation == "read_messages":
                            if self.fault or self.request == b"\xa3":
                                return J2534Result(code=9)
                            payload = b"\x61\x00\x80"
                            if self.packet and self.request == b"\xa2\x04":
                                payload = b"\xe2\x11" + (
                                    b"\xaa\xbb" if self.packet_reads == 0 else b""
                                )
                                self.packet_reads += 1
                            return J2534Result(
                                count=1,
                                messages=(
                                    NativeMessage(
                                        4,
                                        0,
                                        0,
                                        1234,
                                        0,
                                        bytes((0x80 + len(payload), 0xF0, 0x10))
                                        + payload,
                                    ),
                                ),
                            )
                        return J2534Result(count=1)

                communication = NativeCommunication.from_backend(
                    profile,
                    Backend(),
                    "engine",
                    first_request=b"\x21\x00",
                    driver=DriverProperties(0, b"04.04", "authored"),
                    device_kind=8,
                    bus_id=0x11,
                    source_build=build,
                    clock=lambda: 0,
                )
                concrete = selected_legacy_check_target(
                    communication, (17,), self.observed(function)
                )
                try:
                    concrete_result = check_legacy_monitor(
                        (concrete, concrete),
                        family=family,
                        command_kind=0x42,
                        allocation=101,
                        connected_device=4,
                        command_ecu=42,
                        clock=lambda: 0,
                    )
                    self.assertEqual(concrete_result, result)
                    writes = [
                        fields["messages"][0].data
                        for operation, fields in primitive_calls
                        if operation == "write_messages"
                    ]
                    self.assertIn(b"\x82\x10\xf0\x21\x00", writes)
                    self.assertTrue(
                        any(name == "read_messages" for name, _ in primitive_calls)
                    )
                finally:
                    communication.disconnect()
                self.assertEqual(primitive_calls[-1][0], "disconnect")
                for fault, cancel in ((True, False), (False, True)):
                    backend = Backend(fault=fault, cancel=cancel)
                    failed_communication = NativeCommunication.from_backend(
                        profile,
                        backend,
                        "engine",
                        first_request=b"\x21\x00",
                        driver=DriverProperties(0, b"04.04", "authored"),
                        device_kind=8,
                        bus_id=0x11,
                        source_build=build,
                        clock=lambda: 0,
                        cancelled=lambda backend=backend: backend.cancelled,
                    )
                    failed_target = selected_legacy_check_target(
                        failed_communication, (17,), self.observed(function)
                    )
                    try:
                        with self.assertRaises(Cancelled if cancel else MonitorError):
                            check_legacy_monitor(
                                (failed_target,),
                                family=family,
                                command_kind=7,
                                allocation=100,
                                command_ecu=42,
                                clock=lambda: 0,
                                cancelled=lambda backend=backend: backend.cancelled,
                            )
                    finally:
                        failed_communication.disconnect()
                    self.assertEqual(primitive_calls[-1][0], "disconnect")
                if family == "P3":
                    packet_backend = Backend(packet=True)
                    packet_communication = NativeCommunication.from_backend(
                        profile,
                        packet_backend,
                        "engine",
                        first_request=b"\x21\x00",
                        driver=DriverProperties(0, b"04.04", "authored"),
                        device_kind=8,
                        bus_id=0x11,
                        source_build=build,
                        clock=lambda: 0,
                    )
                    packet_target = selected_legacy_check_target(
                        packet_communication, (17,), self.observed(10, 11)
                    )
                    try:
                        packet_result = check_legacy_monitor(
                            (packet_target,),
                            family=family,
                            command_kind=7,
                            allocation=100,
                            command_ecu=42,
                            clock=lambda: 0,
                        )
                        self.assertEqual(packet_result.measurements[0].mode, 2)
                        self.assertEqual(packet_result.measurements[0].packet_size, 6)
                        self.assertEqual(packet_backend.packet_reads, 2)
                    finally:
                        packet_communication.disconnect()
                    self.assertEqual(primitive_calls[-1][0], "disconnect")
                calls.clear()
                with self.assertRaises(Cancelled):
                    check_legacy_monitor(
                        (target,),
                        family=family,
                        command_kind=7,
                        allocation=100,
                        command_ecu=42,
                        cancelled=lambda: True,
                        clock=lambda: 0,
                    )
                self.assertFalse(calls)
                with self.assertRaisesRegex(MonitorError, "budget"):
                    check_legacy_monitor(
                        (target, target),
                        family=family,
                        command_kind=0x42,
                        allocation=100,
                        command_ecu=42,
                        limits=Limits(exchanges=1),
                        clock=lambda: 0,
                    )
                self.assertEqual(len(calls), 1)
                calls.clear()
                foreign = replace(
                    target, profile=replace(profile, vehicle_name_key=123)
                )
                with self.assertRaisesRegex(MonitorError, "vehicle context"):
                    check_legacy_monitor(
                        (target, foreign),
                        family=family,
                        command_kind=0x42,
                        allocation=100,
                        command_ecu=42,
                        clock=lambda: 0,
                    )
                self.assertFalse(calls)
                tick = [0.0]

                def late_exchange(query, tick=tick):
                    tick[0] = 2.0
                    return b"\x61\x00\x80"

                with self.assertRaisesRegex(MonitorError, "deadline"):
                    check_legacy_monitor(
                        (replace(target, transaction=late_exchange),),
                        family=family,
                        command_kind=7,
                        allocation=100,
                        command_ecu=42,
                        clock=lambda tick=tick: tick[0],
                        limits=Limits(seconds=1),
                    )

    def test_voltage_check_measures_descriptor_without_calling_false_sampler(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.monitor_legacy import (
            LegacyCheckTarget,
            Phase3Measurement,
            check_legacy_monitor,
        )

        for family in ("P3", "DK"):
            base = self.native_profile(3 if family == "P3" else 7)
            category = bytearray(base.category_record)
            category[68:70] = (0x68).to_bytes(2, "little")
            profile = replace(base, category_record=bytes(category))
            target = LegacyCheckTarget(
                profile,
                (17,),
                "voltage",
                0,
                {},
                lambda query: (_ for _ in ()).throw(
                    AssertionError("Voltage measurement must not poll support")
                ),
            )
            result = check_legacy_monitor(
                (target,),
                family=family,
                command_kind=7,
                allocation=100,
                connected_device=4,
                command_ecu=0x68,
                clock=lambda: 0,
            )
            self.assertEqual(result.measurements, (Phase3Measurement(4, 6, 100, 0x40),))
            freeze = bytearray(profile.database.sections[10].payload)
            freeze[64:66] = (7).to_bytes(2, "little")
            broken = replace(
                profile,
                database=replace(
                    profile.database,
                    sections={
                        **profile.database.sections,
                        10: Section(10, 0, 1, False, bytes(freeze)),
                    },
                ),
            )
            with self.assertRaises(MonitorError) as error:
                check_legacy_monitor(
                    (replace(target, profile=broken),),
                    family=family,
                    command_kind=7,
                    allocation=100,
                    command_ecu=0x68,
                    clock=lambda: 0,
                )
            self.assertEqual(error.exception.code, 0xC0050102)

    def test_dk_native_function_a7_first_settings_and_defaults(self):
        import struct
        from copy import copy
        from dataclasses import replace

        from scripts.diagnostic_db import Section
        from scripts.monitor_legacy import dk_monitor_timing

        selected = self.native_profile(7)
        self.assertEqual(dk_monitor_timing(selected), (1000, 200))
        catalog = copy(selected.catalog)
        functions = struct.pack("<8H", selected.category, 0xA7, 9, 0, 0, 0, 0, 0)
        settings = struct.pack("<IIHH4x", 123, 456, 0, 9)
        catalog.management = replace(
            catalog.management,
            sections={
                **catalog.management.sections,
                18: Section(18, 0, 1, False, functions),
                29: Section(29, 0, 2, False, settings + settings),
            },
        )
        # Native GetDbRecord consumes the first row; no exactly-one rule here.
        self.assertEqual(
            dk_monitor_timing(replace(selected, catalog=catalog)), (123, 456)
        )

    def test_dk_selected_constructor_to_actual_native_frame_and_packet(self):
        from scripts.frame_transport import DriverProperties
        from scripts.monitor_legacy import (
            selected_dk_monitor,
            selected_legacy_j2534_frames,
        )

        selected = self.native_profile(7)
        plan = selected_dk_monitor(selected, (17,), {1: 2}, self.observed(26))
        constructor = selected_legacy_j2534_frames(
            selected,
            plan,
            ecu="engine",
            bus_id=0x11,
            driver=DriverProperties(0, b"04.04", "authored"),
            diagnostic_mode=bytes(16),
            connected_device=8,
        )
        self.assertEqual(constructor.backend, "j2534_dk_iso9141")
        self.assertEqual(constructor.frames[0].connect.protocol_id, 4)
        self.assertEqual(constructor.frames[0].send.data, b"\x82\x10\xf0\x2c\x01")
        self.assertEqual(plan.event.accept(b"\x99\xaa\xbb", 10), (10, b"\xaa\xbb"))
        with self.assertRaises(MonitorError) as caught:
            selected_legacy_j2534_frames(
                selected,
                plan,
                ecu="engine",
                bus_id=0x11,
                driver=DriverProperties(0, b"04.04", "authored"),
                diagnostic_mode=bytes(16),
                connected_device=4,
            )
        self.assertEqual(caught.exception.code, 0xC0051302)

    def test_native_constructor_rejects_same_database_foreign_selection(self):
        from copy import copy
        from dataclasses import replace
        from unittest.mock import patch

        from scripts.frame_transport import DriverProperties
        from scripts.monitor_legacy import (
            selected_dk_monitor,
            selected_legacy_j2534_frames,
        )

        selected = self.native_profile(7)
        plan = selected_dk_monitor(selected, (17,), {1: 2}, self.observed(26))
        changed_category = bytearray(selected.category_record)
        changed_category[73] ^= 1
        catalog = copy(selected.catalog)
        catalog.management = replace(
            selected.catalog.management, sha256="foreign-management"
        )
        foreign = (
            replace(selected, exception_ids=(9,)),
            replace(selected, category_record=bytes(changed_category)),
            replace(selected, catalog=catalog),
        )
        with patch("scripts.frame_transport.get_comm_frame") as primitive:
            for profile in foreign:
                with (
                    self.subTest(identity=profile.exception_ids),
                    self.assertRaises(MonitorError),
                ):
                    selected_legacy_j2534_frames(
                        profile,
                        plan,
                        ecu="engine",
                        bus_id=0x11,
                        driver=DriverProperties(0, b"04.04", "authored"),
                        diagnostic_mode=bytes(16),
                        connected_device=8,
                    )
            primitive.assert_not_called()

    def test_actual_selected_p3_direct_constructor_and_dmci_rejection(self):
        from scripts.frame_transport import DriverProperties
        from scripts.monitor_legacy import (
            selected_legacy_j2534_frames,
            selected_phase3_monitor,
        )

        selected = self.native_profile(3)
        driver = DriverProperties(0, b"04.04", "authored")
        for enabled, backend, request in (
            (11, "j2534", b"\x01\x01"),
            (8, "j2534_packet", b"\xa1\x01\x01\xff"),
        ):
            plan = selected_phase3_monitor(
                selected,
                (17,),
                {1: 2},
                self.observed(enabled),
                interface_id=9,
                excluded=0,
                maximum_request=8,
                maximum_reply=8,
                cached_frames=None,
                parameter_8=0xFFFFFFFF,
                standard_values=(),
            )
            from scripts.monitor_legacy import phase3_measurement

            measurement = phase3_measurement(plan)
            self.assertEqual(measurement.cycle, 130 if enabled == 8 else 160)
            result = selected_legacy_j2534_frames(
                selected,
                plan,
                ecu="engine",
                bus_id=0x11,
                driver=driver,
                diagnostic_mode=bytes(16),
                connected_device=8,
            )
            self.assertEqual(result.family, "P3")
            self.assertEqual(result.backend, backend)
            self.assertEqual(
                result.frames[0].send.data,
                bytes((0x80 + len(request), 0x10, 0xF0)) + request,
            )
            with self.assertRaises(MonitorError) as caught:
                selected_legacy_j2534_frames(
                    selected,
                    plan,
                    ecu="engine",
                    bus_id=0x11,
                    driver=driver,
                    diagnostic_mode=bytes(16),
                    connected_device=4,
                )
            self.assertIn("DMCI", str(caught.exception))

    def test_native_p3_constructor_dispatch_and_voltage_router(self):
        import struct

        from scripts.monitor_dlc12 import DLC12VoltageState
        from scripts.monitor_instruments import SelectedInstrumentMonitor
        from scripts.monitor_legacy import (
            phase3_constructor_route,
            selected_legacy_monitor,
        )
        from scripts.profiles import VehicleProfile

        expected = (
            (8, False, 2, 0x10, 3, "j2534_century"),
            (8, False, 1, 2, 3, "j2534_packet"),
            (8, False, 1, 0x10, 5, "j2534_dk_kwp"),
            (8, False, 1, 0x10, 3, "j2534"),
            (8, True, 1, 0x10, 3, "com_iso"),
        )
        for device, recording, count, mask, flags, backend in expected:
            self.assertEqual(
                phase3_constructor_route(
                    connected_device=device,
                    recording=recording,
                    interface_count=count,
                    mode_mask=mask,
                    category_flags=flags,
                    bus_id=0x11,
                ),
                backend,
            )
        selected = self.native_profile(3)
        category = bytearray(selected.category_record)
        struct.pack_into("<H", category, 68, 0x68)
        voltage = VehicleProfile(selected.catalog, bytes(category), selected.database)
        result = selected_legacy_monitor(
            voltage,
            (17,),
            observed_functions={},
            communication_protocol=0x11,
            interface_id=0,
            voltage_state=DLC12VoltageState(0),
        )
        assert isinstance(result, SelectedInstrumentMonitor)
        self.assertEqual(result.mode, 0x40)
        self.assertEqual(result.descriptors, (b"\x04\x00\x00\x00\x01",))
        self.assertEqual(result.frame_sizes, ((0, 2),))

    def test_p3_selected_constructor_actual_comtol_packets_and_cleanup(self):
        import struct

        from scripts.data_monitor import selected_p4_connection
        from scripts.drive_recorder import (
            NativeCoreBuffer,
            NativeDmciList,
            NativeMonitorReply,
            NativeVimClient,
            NativeVimReply,
            decode_vim_command,
        )
        from scripts.monitor_legacy import run_phase3_dmci, selected_phase3_monitor

        selected = self.native_profile(3)
        connection = selected_p4_connection(
            selected,
            bus_id=0x11,
            diagnostic_mode=bytes(16),
            controller_category_flags=3,
        )
        plan = selected_phase3_monitor(
            selected,
            (17,),
            {1: 2},
            self.observed(11),
            interface_id=connection.address.request_id,
            excluded=0,
            maximum_request=8,
            maximum_reply=8,
            cached_frames=None,
            parameter_8=0xFFFFFFFF,
            standard_values=(),
        )
        calls = []

        def exchange(request, *, deadline, cancelled):
            command, payload = decode_vim_command(request)
            calls.append((command, payload))
            if command == 0x197F:
                self.assertEqual(payload, bytes.fromhex("01000000010000002a000000"))
                empty = NativeCoreBuffer((1, 0), b"")
                response = NativeMonitorReply(
                    0,
                    NativeDmciList(
                        (1, 0),
                        (
                            (
                                selected.category,
                                NativeCoreBuffer(
                                    (1, 0), struct.pack("<I", 0xFFFFFFFE) + b"\xaa\xbb"
                                ),
                            ),
                        ),
                    ),
                    (empty, empty, empty, empty, empty),
                    0,
                ).encode()
            elif command == 0x247F:
                response = struct.pack("<II", 0, 1)
            else:
                response = bytes(4)
            return NativeVimReply(command | 0x80, 6, response).encode()

        client = NativeVimClient(
            exchange, capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"})
        )
        packets = run_phase3_dmci(
            selected,
            plan,
            connection,
            client,
            connected_device=4,
            init_mode=1,
            parameter_c0=77,
            packet_limit=1,
        )
        self.assertEqual(
            [(p.timestamp_raw, p.payload) for p in packets], [(0xFFFFFFFE, b"\xaa\xbb")]
        )
        self.assertEqual(
            [command for command, _ in calls],
            [0x107F, 0x137F, 0x247F, 0x167F, 0x187F, 0x197F, 0x1A7F, 0x147F, 0x127F],
        )
        self.assertEqual(calls[1][1][-4:], bytes(4))

    def test_selected_router_uses_native_protocol_choice(self):
        from scripts.monitor_legacy import SelectedDkMonitor, selected_legacy_monitor

        result = selected_legacy_monitor(
            self.profile(7),
            (17,),
            observed_functions=self.observed(26),
            communication_protocol=3,
            interface_id=9,
            enabled_lengths={1: 2},
        )
        self.assertIsInstance(result, SelectedDkMonitor)
        with self.assertRaises(MonitorError):
            selected_legacy_monitor(
                self.profile(9),
                (17,),
                observed_functions=self.observed(11),
                communication_protocol=2,
                interface_id=9,
                enabled_lengths={1: 2},
            )

    def test_shutdown_requires_matching_e3_and_is_bounded(self):
        provider = FakeProvider(
            (MonitorReceive(b"\xe3", 99, 0), MonitorReceive(b"\xe3", 7, 0))
        )
        stream = Phase3Stream(
            provider,
            "engine",
            source_id=7,
            protocol=3,
            request=b"\xa1\x04",
            retries=0,
            send_timeout=9,
            receive_timeout=10,
            interval=30,
        )
        stream.start(tick_ms=lambda: 0)
        stream.shutdown(tick_ms=lambda: 20, maximum_receives=2)
        self.assertEqual(stream.state, 0)
        self.assertEqual(provider.calls[0][2], b"\xa3")
        failed = Phase3Stream(
            FakeProvider((MonitorReceive(b"", 7, 0x91010009),)),
            "engine",
            source_id=7,
            protocol=3,
            request=b"\xa1\x04",
            retries=0,
            send_timeout=9,
            receive_timeout=10,
            interval=30,
        )
        failed.start(tick_ms=lambda: 0)
        with self.assertRaises(MonitorError) as caught:
            failed.shutdown(tick_ms=lambda: 20, maximum_receives=1)
        self.assertEqual(caught.exception.code, 0xA1050303)


if __name__ == "__main__":
    unittest.main()
