"""Authored on-disk DDB and literal native LSB wire chronology."""

import struct
import tempfile
import unittest
from pathlib import Path
from typing import Any, Literal, cast

from scripts.frame_transport import NativeFrameReceive
from scripts.monitor_support import MonitorSupportCache
from scripts.profiles import VehicleCatalog
from scripts.signal_lsb import SignalLSB, _coefficients
from scripts.toyota import ToyotaCodecError
from scripts.toyota_session import Cancelled, Limits, SessionError


def database(kind, sections):
    header = bytearray(36 + 4 * (max(sections) + 1))
    header[8:10] = bytes((kind, max(sections) + 1))
    header[10:28] = b"DiagTool DataCtrl\0"
    struct.pack_into("<I", header, 28, 0x0100032F)
    body = bytearray()
    for slot, (count, data) in sorted(sections.items()):
        struct.pack_into("<I", header, 36 + slot * 4, len(header) + len(body))
        body += struct.pack("<BBII", slot, 0, count, len(data)) + data
    return bytes(header + body)


def selected(root, *, flags=4, lsb=True, begin=0, end=7, p5=False, p5_pids=(9,)):
    category = bytearray(76)
    category[:18] = "demo.ddb\0".encode("utf-16le")
    struct.pack_into("<H", category, 68, 42)
    category[72] = flags
    requests = (b"\x21\0", b"\x13", b"\x21\0", b"\x22\0\0", b"\x22\0\0")
    offsets, data = bytearray(), bytearray()
    for request in requests:
        offsets += struct.pack("<IH", len(data), len(request))
        data += request
    funcs = (15, 0x13, 0x6B, 0xC8, 0xCA)
    settings = bytearray(16)
    struct.pack_into("<IIH", settings, 0, 11, 12, 0)
    struct.pack_into("<H", settings, 10, 1)
    management = {
        0: (5, offsets + data),
        16: (1, category),
        17: (5, b"".join(struct.pack("<4H", i, i, 0, 0) for i in range(1, 6))),
        18: (
            5,
            b"".join(
                struct.pack("<8H", 42, func, 1, i, 0, 0, 0, 0)
                for i, func in enumerate(funcs, 1)
            ),
        ),
        29: (1, settings),
        20: (0, b""),
    }
    row = bytearray(20)
    struct.pack_into("<IIHHH", row, 0, 3, 4, 9, begin, end)
    row[17] = 1
    diag = {
        3: (1, bytes(4) + bytes((0, 1, 0, 0))),
        6: (1, bytes((0, 0, 1, 1, 0, 0, 0, 0))),
    }
    freeze = bytearray(84)
    struct.pack_into("<II", freeze, 32, 17, 99)
    struct.pack_into("<I", freeze, 52, 77)
    struct.pack_into("<5H", freeze, 56, 9, 0, 2, 0, 7)
    freeze[79] = 1
    physical = bytearray(24)
    struct.pack_into("<IIIHH", physical, 0, 2, 5, 0, 2, 0)
    physical[21] = 1
    diag.update(
        {
            10: (1, bytes(freeze)),
            13: (1, bytes(physical)),
            14: (0, b""),
            15: (1, bytes(12)),
        }
    )
    if lsb:
        diag[39] = (1, bytes(row))
    if p5:
        monitor = bytearray(64)
        struct.pack_into("<H", monitor, 36, 9)
        struct.pack_into("<HH", monitor, 44, 0, 7)
        struct.pack_into("<H", monitor, 54, 0x0101)
        struct.pack_into("<H", monitor, 42, 2)
        struct.pack_into("<II", monitor, 12, 17, 99)
        did_lsb = bytearray(20)
        struct.pack_into("<II4H", did_lsb, 0, 3, 4, 0x0101, 9, begin, end)
        diag[61] = (1, struct.pack("<HH4B", 0, 0x0101, 0, 0, 0, 0))
        monitors, lsb_rows = [], []
        for pid in p5_pids:
            struct.pack_into("<H", monitor, 36, pid)
            struct.pack_into("<H", did_lsb, 10, pid)
            monitors.append(bytes(monitor))
            lsb_rows.append(bytes(did_lsb))
        diag[62] = (len(monitors), b"".join(monitors))
        if lsb:
            diag[64] = (len(lsb_rows), b"".join(lsb_rows))

    (root / "Toyota.ddb").write_bytes(database(1, management))
    (root / "M_English.ddb").write_bytes(database(4, {0: (0, b"")}))
    (root / "demo.ddb").write_bytes(database(2, diag))
    return VehicleCatalog(root).build_profile(42)


class Stream:
    def __init__(self, events):
        self.calls = []
        self.events = events
        self.receives = iter(((0, b"\x53\0\x01\x01\xff"), (0x91010009, b"")))

    def send(self, send):
        self.calls.append(send)
        self.events.append(("send", send.query.request))
        return 0

    def receive(self, receive):
        self.calls.append(receive)
        result = next(self.receives)
        self.events.append(("receive", result))
        return result


class SignalLSBTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def make(
        self,
        *,
        payload=b"\x06",
        fault=None,
        source_build: Literal[12, 18] = 18,
        **kwargs,
    ):
        self.profile = selected(self.root, **kwargs)
        self.events = []
        self.stream, self.calls = Stream(self.events), []

        def exchange(query):
            self.calls.append(query)
            self.events.append(("exchange", query.request))
            if query.request == b"\x21\0":
                return b"\x61\0\x80"
            if fault:
                raise ToyotaCodecError("Authored native fault", fault)
            return b"\x61\x01" + payload

        self.cache = MonitorSupportCache(
            self.profile,
            exchange,
            "ecu42",
            stream=self.stream,
            bus_id=7,
            source_build=source_build,
        )
        return SignalLSB(self.cache, source_build=source_build)

    def observe(self, producer, **kwargs):
        values = {
            "exponent": 1,
            "width": 8,
            "multiplier": 2,
            "divisor": 5,
            "threshold": 17,
        }
        values.update(kwargs)
        return producer.p4(9, **values)

    def test_selected_ddb_literal_wire_reduction_and_cache(self):
        producer = self.make()
        self.assertEqual(self.observe(producer).values, (45, 1, 255))
        self.assertTrue(self.observe(producer).changed)
        self.assertEqual([q.request for q in self.calls], [b"\x21\0", b"\x21\x01"])
        self.assertEqual(len(self.stream.calls), 3)
        self.assertEqual(
            self.events,
            [
                ("send", b"\x13"),
                ("receive", (0, b"\x53\0\x01\x01\xff")),
                ("receive", (0x91010009, b"")),
                ("exchange", b"\x21\0"),
                ("exchange", b"\x21\x01"),
            ],
        )
        self.assertEqual(self.stream.calls[0].parameter4, 11)
        self.assertEqual(self.stream.calls[0].parameter5, 7)
        self.assertIn(self.profile.database.sha256, self.calls[1].source_identity)
        self.assertEqual(self.calls[1].selected.function_record[2:4], b"k\0")

    def test_actual_monitor_consumer_retains_post_lsb_threshold_overwrite(self):
        from scripts.data_monitor import selected_signal_metadata

        producer = self.make()
        result = selected_signal_metadata(
            self.profile, ((9, 0, 0, 7),), lsb_producer=producer
        )
        self.assertEqual((result[0].multiplier, result[0].divisor), (45, 1))
        self.assertEqual(result[0].extended, (77, 17, 99))

    def test_actual_freeze_consumer_retains_lsb_threshold(self):
        from scripts.toyota_workflows import ToyotaWorkflows, WorkflowObservations

        self.make()

        def unused_exchange(ecu, request):
            self.fail("LSB must use the typed chronological support provider")

        workflow = ToyotaWorkflows(
            self.profile,
            unused_exchange,
            ecu="ecu42",
            observations=WorkflowObservations(42, 7, source_version=18),
            support_exchange=self.cache.exchange,
            support_stream=self.stream,
        )
        workflow._begin()
        metadata = workflow._freeze_metadata(self.profile.records(10)[0])
        self.assertEqual((metadata.multiplier, metadata.divisor), (45, 1))
        self.assertEqual(metadata.extended, (77, 255, 99))

    def test_native_width_shift_wrap_and_zero_coefficient(self):
        producer = self.make()
        self.assertEqual(self.observe(producer, width=32).threshold, 0)
        self.assertEqual(self.observe(producer, exponent=19).values, (0, 4, 255))
        self.assertEqual(self.observe(producer, exponent=65535).values, (0, 4, 255))
        self.assertEqual(
            _coefficients(struct.pack("<II", 0xFFFFFFFF, 4), 0, 6), (3, 0xFFFFFFFE)
        )

    def test_missing_resource_or_ineligible_raw_flag_does_not_query(self):
        options_list: list[dict[str, Any]] = [{"lsb": False}, {"flags": 0x44}]
        for options in options_list:
            producer = self.make(**options)
            self.assertEqual(self.observe(producer).values, (2, 5, 17))
            self.assertEqual(self.calls, [])
            self.assertEqual(self.stream.calls, [])

    def test_zero_or_communication_failure_preserves_input(self):
        options_list: list[dict[str, Any]] = [
            {"payload": b"\0"},
            {"fault": 0x91010009},
            {"fault": 0xC0040001},
        ]
        for options in options_list:
            producer = self.make(**options)
            self.assertFalse(self.observe(producer).changed)

    def test_out_of_range_support_is_identity(self):
        producer = self.make(end=8)
        self.assertFalse(self.observe(producer).changed)
        self.assertEqual([q.request for q in self.calls], [b"\x21\0"])

    def test_cancel_deadline_budget_and_source_identity(self):
        producer = self.make()
        self.cache.cancelled = lambda: True
        with self.assertRaises(Cancelled):
            self.observe(producer)
        self.cache.cancelled = lambda: False
        self.cache.deadline = 0
        with self.assertRaises(SessionError):
            self.observe(producer)
        producer = self.make()
        self.cache.limits = Limits(exchanges=1)
        with self.assertRaises(SessionError):
            self.observe(producer)
        producer = self.make()
        self.cache.ecu = "other"
        with self.assertRaises(SessionError):
            self.observe(producer)

    def test_p5_selected_ddb_did_pages_support_and_lsb_wire(self):
        profile = selected(self.root, flags=0x14, p5=True)
        events = []

        def exchange(query):
            events.append(query.request)
            return {
                b"\x22\0\0": b"\x62\0\0\x40",
                b"\x22\x01\0": b"\x62\x01\0\x80",
                b"\x22\x01\x01": b"\x62\x01\x01\x06",
            }[query.request]

        cache = MonitorSupportCache(profile, exchange, "p5")
        producer = SignalLSB(cache, source_build=18)
        values = {
            "exponent": 1,
            "width": 8,
            "multiplier": 2,
            "divisor": 5,
            "threshold": 17,
        }
        result = producer.p5(9, **values)
        self.assertTrue(result.changed)
        self.assertEqual(result.values, (45, 1, 255))
        self.assertEqual(
            events, [b"\x22\0\0", b"\x22\x01\0", b"\x22\x01\x01", b"\x22\x01\x01"]
        )
        producer.p5(9, **values)
        self.assertEqual(len(events), 4)
        from scripts.data_monitor import selected_p5_signal_metadata

        metadata = selected_p5_signal_metadata(
            profile,
            ((9, 0, 0, 7),),
            source_build=18,
            active_alias_pid=0,
            lsb_producer=producer,
        )
        self.assertEqual((metadata[0].multiplier, metadata[0].divisor), (45, 1))
        self.assertEqual(metadata[0].extended[1:], (17, 99))

    def test_p5_native_instance_temp_reuse_and_fresh_same_did_signal(self):
        profile = selected(self.root, flags=0x14, p5=True, p5_pids=(9, 10))
        values = {
            "exponent": 1,
            "width": 8,
            "multiplier": 2,
            "divisor": 5,
            "threshold": 17,
        }
        for source_build in (12, 18):
            for fresh in (False, True):
                with self.subTest(source_build=source_build, fresh=fresh):
                    events = []

                    def exchange(query, events=events):
                        events.append(query.request)
                        return {
                            b"\x22\0\0": b"\x62\0\0\x40",
                            b"\x22\x01\0": b"\x62\x01\0\x80",
                            b"\x22\x01\x01": b"\x62\x01\x01\x06",
                        }[query.request]

                    cache = MonitorSupportCache(
                        profile,
                        exchange,
                        "p5-native-instance",
                        source_build=source_build,
                    )
                    producer = SignalLSB(cache, source_build=source_build)
                    self.assertEqual(producer.p5(9, **values).values, (45, 1, 255))
                    self.assertEqual(events.count(b"\x22\x01\x01"), 2)
                    if fresh:
                        producer = SignalLSB(cache, source_build=source_build)
                    self.assertEqual(producer.p5(10, **values).values, (45, 1, 255))
                    # New native LSB instances repeat the TEMP CA support check;
                    # the coefficient's Ever CA observation remains globally shared.
                    self.assertEqual(events.count(b"\x22\x01\x01"), 3 if fresh else 2)
                    before = len(events)
                    producer.p5(10, **values)
                    self.assertEqual(len(events), before)
                    self.assertFalse(
                        cache.response_cached(b"\x22\x01\x01", temporary=True)
                    )
                    self.assertTrue(cache.response_cached(b"\x22\x01\x01"))

    def test_p5_metadata_consumer_clones_native_temp_for_shared_did(self):
        from scripts.data_monitor import selected_p5_signal_metadata

        profile = selected(self.root, flags=0x14, p5=True, p5_pids=(9, 10))
        for source_build in (12, 18):
            with self.subTest(source_build=source_build):
                events = []

                def exchange(query, events=events):
                    events.append(query.request)
                    return {
                        b"\x22\0\0": b"\x62\0\0\x40",
                        b"\x22\x01\0": b"\x62\x01\0\x80",
                        b"\x22\x01\x01": b"\x62\x01\x01\x06",
                    }[query.request]

                cache = MonitorSupportCache(
                    profile, exchange, "p5-native-consumer", source_build=source_build
                )
                metadata = selected_p5_signal_metadata(
                    profile,
                    ((9, 0, 0, 7), (10, 0, 0, 7)),
                    source_build=source_build,
                    active_alias_pid=0,
                    lsb_producer=SignalLSB(cache, source_build=source_build),
                )
                self.assertEqual(
                    [(item.multiplier, item.divisor) for item in metadata],
                    [(45, 1), (45, 1)],
                )
                self.assertEqual(
                    [item.extended[1:] for item in metadata], [(17, 99), (17, 99)]
                )
                self.assertEqual(events.count(b"\x22\x01\x01"), 3)

    def test_native_lsb_cache_flags_are_local_and_restore_retained_context(self):
        from scripts.native_communication import NativeCommunication

        class Frames:
            def __init__(self):
                self.sends = []
                self.request = None
                self.raw_reads = 0

            def send(self, request, **fields):
                self.sends.append(fields)
                self.request = request
                return 0

            def receive(self, **fields):
                assert isinstance(self.request, bytes)
                if self.request == b"\x13":
                    self.raw_reads += 1
                    return NativeFrameReceive(
                        code=0 if self.raw_reads == 1 else 0x91010009,
                        data=b"\x53\0\x01\x01\xff" if self.raw_reads == 1 else b"",
                    )
                return NativeFrameReceive(
                    code=0,
                    data={
                        b"\x21\0": b"\x61\0\x80",
                        b"\x21\x01": b"\x61\x01\x06",
                        b"\x22\0\0": b"\x62\0\0\x40",
                        b"\x22\x01\0": b"\x62\x01\0\x80",
                        b"\x22\x01\x01": b"\x62\x01\x01\x06",
                    }[self.request],
                )

            def close(self):
                return 0

        for source_build in (12, 18):
            for p5 in (False, True):
                with self.subTest(source_build=source_build, p5=p5):
                    profile = selected(self.root, flags=0x14 if p5 else 4, p5=p5)
                    frames = Frames()
                    comm = NativeCommunication(
                        profile,
                        frames,
                        "native-lsb-flags",
                        bus_id=7,
                        source_build=source_build,
                    )
                    comm.no_init = comm.no_session = True
                    producer = SignalLSB(comm.cache, source_build=source_build)
                    method = producer.p5 if p5 else producer.p4
                    result = method(
                        9, exponent=1, width=8, multiplier=2, divisor=5, threshold=17
                    )
                    self.assertEqual(result.values, (45, 1, 255))
                    self.assertTrue(frames.sends)
                    self.assertTrue(
                        all(
                            row["initialization_mode"] == 1 and not row["no_session"]
                            for row in frames.sends
                        )
                    )
                    self.assertTrue(comm.no_init and comm.no_session)
                    comm.close()

    def test_original12_positive_p4_and_p5_paths(self):
        producer = self.make(source_build=12)
        self.assertEqual(self.observe(producer).values, (45, 1, 255))
        profile = selected(self.root, flags=0x14, p5=True)
        events = []

        def exchange(query):
            events.append(query.request)
            return {
                b"\x22\0\0": b"\x62\0\0\x40",
                b"\x22\x01\0": b"\x62\x01\0\x80",
                b"\x22\x01\x01": b"\x62\x01\x01\x06",
            }[query.request]

        cache = MonitorSupportCache(profile, exchange, "p5-12", source_build=12)
        result = SignalLSB(cache, source_build=12).p5(
            9, exponent=1, width=8, multiplier=2, divisor=5, threshold=17
        )
        self.assertEqual(result.values, (45, 1, 255))
        self.assertEqual(
            events, [b"\x22\0\0", b"\x22\x01\0", b"\x22\x01\x01", b"\x22\x01\x01"]
        )

    def test_p5_build18_raw34_uses_subaru_enumeration(self):
        profile = selected(self.root, flags=0x34, p5=True)
        events = []

        def exchange(query):
            events.append(query.request)
            self.assertEqual(query.request, b"\x22\x01\x01")
            return b"\x62\x01\x01\x06"

        cache = MonitorSupportCache(profile, exchange, "p5-34", source_build=18)
        producer = SignalLSB(cache, source_build=18)
        result = producer.p5(
            9, exponent=1, width=8, multiplier=2, divisor=5, threshold=17
        )
        self.assertEqual(result.values, (45, 1, 255))
        self.assertTrue(result.changed)
        self.assertEqual(events, [b"\x22\x01\x01"] * 3)

    def test_p5_build12_raw34_is_identity_even_with_new_database_format(self):
        producer = self.make(flags=0x34, source_build=12)
        observed = producer.p5(
            9, exponent=1, width=8, multiplier=2, divisor=5, threshold=17
        )
        self.assertFalse(observed.changed)
        self.assertEqual(self.calls, [])

    def test_template_cardinality_and_geometry_propagate(self):
        producer = self.make()
        # Alter the actual selected management table, preserving decoded DDB path.
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        management = self.profile.catalog.management
        functions = management.sections[18]
        payload = (
            functions.payload[:48]
            + struct.pack("<8H", 42, 0x6B, 1, 3, 0, 1, 0, 0)
            + functions.payload[48:]
        )
        self.profile.catalog.management = replace(
            management,
            sections={
                **management.sections,
                18: Section(18, 0, 6, False, bytes(payload)),
            },
        )
        with self.assertRaises(ToyotaCodecError):
            self.observe(producer)

    def test_malformed_selected_lsb_resource_and_late_cancellation(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        producer = self.make()
        original = self.profile.database
        object.__setattr__(
            self.profile,
            "database",
            replace(
                original,
                sections={**original.sections, 39: Section(39, 0, 1, False, bytes(19))},
            ),
        )
        with self.assertRaises(ValueError):
            self.observe(producer)
        producer = self.make()

        def cancelled_exchange(query):
            self.cache.cancelled = lambda: True
            return b"\x61\0\x80"

        self.cache.exchange = cancelled_exchange
        with self.assertRaises(Cancelled):
            self.observe(producer)

    def test_missing_lsb_wire_frame_propagates(self):
        from dataclasses import replace

        from scripts.diagnostic_db import Section

        producer = self.make()
        management = self.profile.catalog.management
        payload = bytearray(management.sections[18].payload)
        struct.pack_into("<H", payload, 16 * 2 + 2, 0xF0)
        self.profile.catalog.management = replace(
            management,
            sections={
                **management.sections,
                18: Section(18, 0, 5, False, bytes(payload)),
            },
        )
        with self.assertRaises(ValueError):
            self.observe(producer)

    def test_input_bounds_and_explicit_build(self):
        producer = self.make()
        for kwargs in ({"width": True}, {"exponent": 65536}, {"multiplier": -1}):
            with self.assertRaises(ValueError):
                self.observe(producer, **kwargs)
        for source in (True, 0x0100032F, "18"):
            with self.assertRaises(ValueError):
                SignalLSB(self.cache, source_build=cast(Any, source))


if __name__ == "__main__":
    unittest.main()
