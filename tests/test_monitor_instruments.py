"""Authored instrument descriptors and primitive observations, no hardware."""

import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from scripts.data_monitor import MonitorError
from scripts.demo import create_demo
from scripts.drive_recorder import NativeMonitorPacketReader, RecorderCancelled
from scripts.monitor_dlc12 import DLC12VoltageState
from scripts.monitor_instruments import (
    SAMPLING_PERIODS,
    DstiOscDriver,
    OscConfiguration,
    OscDriverCall,
    OscilloscopeRuntime,
    OscParameter,
    OscRead,
    VoltageMonitorInterface,
    selected_instrument_monitor,
)
from scripts.profiles import VehicleCatalog
from scripts.snapshot import MonitorBuffer, decode_packet_stream, monitor_packets


class Observations:
    def __init__(self, reads=(), statuses=None):
        self.calls = []
        self.reads = iter(reads)
        self.statuses = statuses or {}

    def command(self, command, *, deadline):
        self.calls.append(("command", command, None))
        return self.statuses.get(("command", command), 0)

    def set_parameter(self, parameter, data, *, deadline):
        self.calls.append(("set_parameter", parameter, data))
        return self.statuses.get(("set_parameter", parameter), 0)

    def read_buffer(self, maximum, *, deadline):
        self.calls.append(("read_buffer", maximum, None))
        return next(self.reads)


class InstrumentTests(unittest.TestCase):
    def test_timestamped_combined_read_zero_sentinel_retains_backing_capacity(self):
        calls = []

        def exchange(call, deadline):
            calls.append(call)
            return OscRead(0, b"\xaa\xbb\xcc\xdd", 1000)

        driver = DstiOscDriver(
            exchange, module_loaded=True, exports=DstiOscDriver.EXPORTS
        )
        self.assertEqual(driver.read_buffer(0, deadline=1).data, b"\xaa\xbb\xcc\xdd")
        self.assertEqual(calls, [OscDriverCall("DstiOscReadBuffer", maximum=0)])
        with self.assertRaisesRegex(MonitorError, "capacity"):
            driver.get_parameter(10, 0, deadline=1)
        large = DstiOscDriver(
            lambda *_: OscRead(0, bytes(0x41A0)),
            module_loaded=True,
            exports=DstiOscDriver.EXPORTS,
        )
        self.assertEqual(len(large.read_buffer(0, deadline=1).data), 0x41A0)
        with self.assertRaisesRegex(MonitorError, "capacity"):
            large.read_buffer(0x1068, deadline=1)
        with self.assertRaises(MonitorError):
            OscRead(0, bytes(0x41A4))
        runtime = OscilloscopeRuntime(
            Observations((OscRead(0, bytes(0x106C)),)),
            OscConfiguration(),
            clock=lambda: 0,
        )
        runtime.start()
        with self.assertRaisesRegex(MonitorError, "drain exceeds"):
            runtime.drain()

    def test_nonfinite_clocks_and_explicit_deadlines_reject_before_io(self):
        for value in (float("nan"), float("inf"), -float("inf")):
            with self.subTest(value=value):
                provider = Observations()
                runtime = OscilloscopeRuntime(
                    provider, OscConfiguration(), clock=lambda value=value: value
                )
                with self.assertRaisesRegex(MonitorError, "finite"):
                    runtime.start()
                self.assertEqual(provider.calls, [])
                runtime = OscilloscopeRuntime(
                    provider, OscConfiguration(), clock=lambda: 0
                )
                runtime.start()
                before = list(provider.calls)
                with self.assertRaisesRegex(MonitorError, "finite"):
                    runtime.drain(deadline=value)
                self.assertEqual(provider.calls, before)

    def test_nonfinite_clock_during_stop_preserves_native_fault(self):
        now = [0.0]

        class FaultClock(Observations):
            def command(self, command, *, deadline):
                status = super().command(command, deadline=deadline)
                if command == 3:
                    now[0] = float("nan")
                return status

        provider = FaultClock(statuses={("command", 3): 0x90020102})
        runtime = OscilloscopeRuntime(
            provider, OscConfiguration(), clock=lambda: now[0]
        )
        runtime.start()
        with self.assertRaisesRegex(MonitorError, "finite"):
            runtime.stop()
        self.assertEqual(runtime.state, "fault")
        self.assertEqual((runtime.error_word, runtime.error_parameter), (0x907F, 3))
        self.assertEqual(provider.calls[-1], ("command", 3, None))

    def profile(self, category=999):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = create_demo(Path(tmp.name) / "authored")
        profile = VehicleCatalog(root / "Techstream_DB_NA").build_profile(1)
        record = bytearray(profile.category_record)
        struct.pack_into("<H", record, 68, category)
        profile = replace(profile, category_record=bytes(record))
        first = profile.database.sections[10].payload[:84]
        rows = []
        for index in range(4 if category == 999 else 1):
            row = bytearray(first)
            struct.pack_into("<HH", row, 56, index + 1, 0)
            struct.pack_into(
                "<HH", row, 62, index * 8, index * 8 + 7 if category == 999 else 15
            )
            row[79] = index + 1
            rows.append(bytes(row))
        profile.database.sections[10] = replace(
            profile.database.sections[10], count=len(rows), payload=b"".join(rows)
        )
        return profile

    def test_selected_database_to_literal_parameters_and_playback(self):
        profile = self.profile()
        plan = selected_instrument_monitor(profile, (1, 2, 3, 4))
        self.assertEqual(
            plan.descriptors,
            (
                b"\0\x0b\x07\0",
                b"\x01\x0b\x07\x01",
                b"\x02\x0b\x07\x02",
                b"\x03\x0b\x07\x03",
            ),
        )
        self.assertEqual(plan.frame_sizes, ((0, 4),))
        self.assertEqual(
            [(x.pid, x.frame_index, x.start_bit, x.end_bit) for x in plan.signals],
            [(i + 1, 0, i * 8, i * 8 + 7) for i in range(4)],
        )
        config = OscConfiguration.selected(plan)
        provider = Observations((OscRead(0, b"\x11\x22\x33\x44", 100000),))
        runtime = OscilloscopeRuntime(provider, config)
        self.assertEqual(runtime.start(), 0)
        self.assertEqual(
            provider.calls,
            [
                ("command", 0, None),
                ("set_parameter", 9, bytes.fromhex("000b010b020b030b")),
                ("set_parameter", 10, b"\x07" * 4),
                ("set_parameter", 6, bytes(range(4))),
                ("set_parameter", 8, b"\x04"),
                ("command", 2, None),
            ],
        )
        self.assertEqual(runtime.drain(), 0)
        capture = runtime.capture(100)
        self.assertEqual(capture.packet_bytes(), bytes.fromhex("6400000011223344"))
        self.assertEqual(
            decode_packet_stream(capture.packet_bytes(), plan.frame_sizes)[0]["frames"][
                0
            ]["data_hex"],
            "11223344",
        )
        reader = NativeMonitorPacketReader(plan.frame_sizes, phase=0)
        packet = reader.feed(capture.packet_bytes())[0]
        settings = plan.monitor_buffer(
            allocation_size=4096, name=b"authored\0", text_encoding="utf-8"
        )
        self.assertEqual(settings.value_before_buffer, 999)
        self.assertEqual(packet.payload, b"\x11\x22\x33\x44")
        self.assertEqual(runtime.report()["physical"], "PHYSICAL_UNCONFIRMED")
        metadata = MonitorBuffer(
            b"capture", bytes(16), b"", b"", b"", b"", 0, (), plan.selected_ids, b"", ()
        )
        saved = capture.monitor_buffer(settings, metadata, phase=0, block_packets=1)
        self.assertEqual(monitor_packets(saved)[0]["frames"][0]["data_hex"], "11223344")

    def test_actual_named_driver_extension_bindings(self):
        calls = []

        def exchange(call, deadline):
            calls.append((call, deadline))
            if call.export == "DstiOscReadBuffer":
                return OscRead(0, b"ABCD", 1234, 55, 1)
            if call.export == "DstiOscGetParameter":
                return OscParameter(0, b"\x04")
            return 0

        driver = DstiOscDriver(
            exchange, module_loaded=True, exports=DstiOscDriver.EXPORTS
        )
        self.assertEqual(driver.command(2, deadline=10), 0)
        self.assertEqual(driver.set_parameter(8, b"\x04", deadline=10), 0)
        self.assertEqual(
            driver.get_parameter(8, 1, deadline=10), OscParameter(0, b"\x04")
        )
        self.assertEqual(
            driver.read_buffer(0x1068, deadline=10), OscRead(0, b"ABCD", 1234, 55, 1)
        )
        self.assertEqual(calls[0], (OscDriverCall("DstiOscCommand", 2), 10))
        self.assertEqual(
            calls[1], (OscDriverCall("DstiOscSetParameter", 8, b"\x04"), 10)
        )
        for loaded, exports, error in (
            (False, DstiOscDriver.EXPORTS, 0x90020101),
            (True, frozenset(), 0x90020102),
        ):
            unavailable = DstiOscDriver(exchange, module_loaded=loaded, exports=exports)
            self.assertEqual(unavailable.command(2, deadline=10), error)
            self.assertEqual(unavailable.read_buffer(4, deadline=10).status, error)
        malformed = DstiOscDriver(
            lambda *_: 0, module_loaded=True, exports=DstiOscDriver.EXPORTS
        )
        with self.assertRaisesRegex(MonitorError, "actual output"):
            malformed.read_buffer(4, deadline=10)
        with self.assertRaisesRegex(MonitorError, "capacity"):
            driver.read_buffer(3, deadline=10)

    def test_cancelled_stop_releases_and_preserves_error(self):
        flag = [False]
        provider = Observations()
        runtime = OscilloscopeRuntime(
            provider, OscConfiguration(), cancelled=lambda: flag[0]
        )
        runtime.start()
        flag[0] = True
        with self.assertRaises(RecorderCancelled):
            runtime.stop()
        self.assertEqual(provider.calls[-1], ("command", 1, None))
        self.assertEqual(runtime.state, "fault")

    def test_voltage_native_stub_and_real_metadata(self):
        profile = self.profile(0x68)
        plan = selected_instrument_monitor(
            profile, (1,), voltage_state=DLC12VoltageState(0)
        )
        self.assertEqual(plan.descriptors, (bytes.fromhex("0400000001"),))
        self.assertEqual(plan.frame_sizes, ((0, 2),))
        self.assertEqual(plan.mode, 0x40)
        self.assertEqual(VoltageMonitorInterface.get_error(), 0xFFFFFFFF)
        self.assertFalse(VoltageMonitorInterface.setup(4, 1, plan))
        self.assertFalse(VoltageMonitorInterface.start())
        self.assertFalse(VoltageMonitorInterface.stop())

    def test_stop_deadline_and_release_failure_preserve_primary_error(self):
        now = [0.0]

        class SlowRead(Observations):
            def read_buffer(self, maximum, *, deadline):
                now[0] += 10
                return OscRead(0, b"ABCD")

        provider = SlowRead()
        runtime = OscilloscopeRuntime(
            provider, OscConfiguration(), timeout=1, clock=lambda: now[0]
        )
        runtime.start()
        with self.assertRaisesRegex(MonitorError, "deadline"):
            runtime.stop()
        self.assertEqual(provider.calls[-1], ("command", 1, None))
        self.assertEqual(runtime.state, "fault")

        class BrokenRelease(Observations):
            def command(self, command, *, deadline):
                super().command(command, deadline=deadline)
                if command == 1:
                    raise OSError("release failed")
                return 0

        flag = [False]
        provider = BrokenRelease()
        runtime = OscilloscopeRuntime(
            provider, OscConfiguration(), cancelled=lambda: flag[0]
        )
        runtime.start()
        flag[0] = True
        with self.assertRaises(RecorderCancelled):
            runtime.stop()
        self.assertEqual(provider.calls[-1], ("command", 1, None))

    def test_ini_defaults_selection_and_channels(self):
        profile = self.profile()
        for invalid in (None, 0, 22, True, -1):
            plan = selected_instrument_monitor(
                profile,
                (1, 2, 3, 4),
                measure_time_range=invalid,
                forward_time_range=invalid,
            )
            self.assertEqual(plan.descriptors[0], b"\0\x0b\x07\0")
        with self.assertRaises(MonitorError):
            selected_instrument_monitor(profile, (1, 2, 3))
        with self.assertRaises(MonitorError):
            selected_instrument_monitor(profile, (1, 2, 3, 999))
        with self.assertRaises(MonitorError):
            OscConfiguration().set_volt_range(4, 1)

    def test_start_faults_exact_notification(self):
        for operation, parameter in (
            ("command", 0),
            ("set_parameter", 9),
            ("set_parameter", 10),
            ("set_parameter", 6),
            ("set_parameter", 8),
            ("command", 2),
        ):
            provider = Observations(statuses={(operation, parameter): 7})
            runtime = OscilloscopeRuntime(provider, OscConfiguration())
            self.assertEqual(runtime.start(), 7)
            self.assertEqual(provider.calls[-1][1], parameter)
            report = runtime.report()
            self.assertEqual(
                report["notification"],
                0xE2001000 if operation == "command" else 0xE2001001,
            )
            self.assertEqual(report["error_parameter"], parameter)

    def test_stop_replaces_forward_capture_and_always_releases(self):
        config = OscConfiguration()
        config.forward[:] = bytes((1, 2, 3, 4))
        config.reverse[:] = bytes((21, 2, 3, 4))
        provider = Observations(
            (OscRead(0, b"ABCD", 1000), OscRead(0, b"EFGHIJKL", 2000))
        )
        runtime = OscilloscopeRuntime(provider, config)
        self.assertEqual(runtime.start(), 0)
        self.assertEqual(runtime.drain(), 0)
        self.assertEqual(runtime.stop(), 0)
        self.assertEqual(
            [p.payload for p in runtime.capture().packets], [b"EFGH", b"IJKL"]
        )
        self.assertEqual(
            provider.calls[-5:],
            [
                ("command", 3, None),
                ("command", 11, None),
                ("set_parameter", 10, bytes((21, 2, 3, 4))),
                ("read_buffer", 0x1068, None),
                ("command", 1, None),
            ],
        )
        self.assertEqual(runtime.sampling_period, 14)
        for fail in (3, 11, 1):
            provider = Observations((OscRead(0, b""),), {("command", fail): 9})
            runtime = OscilloscopeRuntime(provider, config)
            runtime.start()
            self.assertEqual(runtime.stop(), 9)
            self.assertEqual(provider.calls[-1], ("command", 1, None))
            self.assertEqual(runtime.report()["error_parameter"], fail)

    def test_timestamp_fraction_and_wrap_vectors(self):
        config = OscConfiguration()
        config.forward[0] = 21
        provider = Observations(
            (OscRead(0, b"ABCD" * 100, 999, remaining=1), OscRead(0, b"EFGH", 123456))
        )
        runtime = OscilloscopeRuntime(provider, config)
        runtime.start()
        runtime.drain()
        self.assertEqual(
            [runtime.packets[i].timestamp_ms for i in (0, 71, 72, 100)], [0, 0, 1, 1]
        )
        config.forward[0] = 1
        provider = Observations((OscRead(0, b"ABCD" * 3, 0xFFFFFF00),))
        runtime = OscilloscopeRuntime(provider, config)
        runtime.start()
        runtime.drain()
        self.assertEqual(
            [x.timestamp_ms for x in runtime.packets], [4294967, 4295029, 4295092]
        )
        self.assertEqual(SAMPLING_PERIODS[1:4], (62500000, 31250000, 15625000))

    def test_read_fault_sink_failure_and_budgets(self):
        for observed in (OscRead(7, b""), OscRead(0, b"ABCD")):
            runtime = OscilloscopeRuntime(
                Observations((observed,)), OscConfiguration(), write_sample=lambda _: 8
            )
            runtime.start()
            self.assertEqual(runtime.drain(), 7 if observed.status else 8)
            self.assertEqual(runtime.report()["notification"], 0xE2001003)
            self.assertEqual(runtime.packets, [])
        runtime = OscilloscopeRuntime(
            Observations((OscRead(0, b"ABCD", remaining=1),)),
            OscConfiguration(),
            max_reads=1,
        )
        runtime.start()
        with self.assertRaisesRegex(MonitorError, "read budget"):
            runtime.drain()
        runtime = OscilloscopeRuntime(
            Observations((OscRead(0, b"ABCDEFGH"),)), OscConfiguration(), max_packets=1
        )
        runtime.start()
        with self.assertRaisesRegex(MonitorError, "packet budget"):
            runtime.drain()

    def test_malformed_cancel_deadline(self):
        for payload in (b"A", b"ABC", bytes(0x41A4)):
            with self.assertRaises(MonitorError):
                OscRead(0, payload)
        provider = Observations()
        runtime = OscilloscopeRuntime(
            provider, OscConfiguration(), cancelled=lambda: True
        )
        with self.assertRaises(RecorderCancelled):
            runtime.start()
        self.assertEqual(provider.calls, [])
        ticks = iter((0, 0, 9))
        runtime = OscilloscopeRuntime(
            provider, OscConfiguration(), timeout=1, clock=lambda: next(ticks)
        )
        with self.assertRaisesRegex(MonitorError, "deadline"):
            runtime.start()
        self.assertEqual(provider.calls, [("command", 0, None)])
        with self.assertRaises(MonitorError):
            OscilloscopeRuntime(provider, OscConfiguration(), timeout=float("nan"))


if __name__ == "__main__":
    unittest.main()
