"""Authored vectors for original executable SIL controllers."""

import unittest

from scripts.cuw_legacy_sil import (
    SilProtocolError,
    SilRaw,
    dcmprl_layout,
    emps_selection,
    m16c_regions,
)
from scripts.j2534_2026 import NativeMessage
from scripts.programming_2026_common import NativeRuntime2026


class Primitive:
    def __init__(self, reads=()):
        self.reads = iter(reads)
        self.events = []

    def __call__(self, event, remaining):
        self.events.append(event)
        if event["operation"] == "read_messages":
            return (NativeMessage(3, next(self.reads)),)
        if event["operation"] == "write_messages":
            return 1
        return None


class SilTests(unittest.TestCase):
    def raw(self, reads=()):
        primitive = Primitive(reads)
        return SilRaw(NativeRuntime2026(primitive), 3), primitive

    def test_baud_native_mapping(self):
        for selector, expected in enumerate((0, 1, 2, 3, 4, 6)):
            with self.subTest(selector=selector):
                raw, primitive = self.raw((b"\x3c", b"\x3c", b"\x3c"))
                raw.handshake(selector)
                writes = [
                    e["data"]
                    for e in primitive.events
                    if e["operation"] == "write_messages"
                ]
                self.assertEqual(writes, [b"\x60", bytes((expected,)), b"\x05"])

    def test_initial_command_errors(self):
        for response, code in ((b"\xff", 1), (b"\x00", 2)):
            raw, _ = self.raw((response,))
            with self.assertRaises(SilProtocolError) as caught:
                raw.handshake(0)
            self.assertEqual(caught.exception.code, code)

    def test_memory_probe_and_cached_variant(self):
        raw, primitive = self.raw(
            (b"badreply!!", b"\x3c123456789\x3c", b"\x3cabcdefgh!\x3c")
        )
        self.assertEqual(raw.memory(), b"12345678")
        self.assertTrue(raw.extended_memory)
        self.assertEqual(raw.memory(), b"abcdefgh")
        self.assertEqual(
            [e["data"] for e in primitive.events if e["operation"] == "write_messages"],
            [b"\x75", b"\x76", b"\x76"],
        )

    def test_invalid_memory_fails(self):
        raw, _ = self.raw((b"badreply!!", b"badreply!!!"))
        with self.assertRaises(SilProtocolError):
            raw.memory()

    def test_erase_and_blank_pending_are_distinct(self):
        raw, primitive = self.raw((b"\x3c", b"\x3c\x80\x3c", b"\x3c\x00\x3c"))
        self.assertTrue(raw.block("erase", 2))
        self.assertEqual(
            [e["data"] for e in primitive.events if e["operation"] == "write_messages"],
            [b"\x25\x01", b"\x50", b"\x50"],
        )
        raw, _ = self.raw((b"\x3c", b"\x3c\x01\x3c"))
        self.assertFalse(raw.block("blank", 1))

    def test_selected_metadata_geometry(self):
        self.assertEqual(emps_selection("13", "57"), (0x32, 0x100))
        self.assertEqual(emps_selection("14", "60"), (0x34, 0xC0))
        self.assertEqual(emps_selection("unknown", "unknown"), (0, 0))
        self.assertEqual(dcmprl_layout("32", 1), (0x6000, 0))
        self.assertEqual(dcmprl_layout("33", 1), (0x80000, 0))
        self.assertEqual(dcmprl_layout("34", 5), (0x40300E, 0x300E))
        self.assertEqual(dcmprl_layout("34", 6), (0x4031FC, 0x31FC))
        self.assertEqual(dcmprl_layout("34", 1), (0x400000, 0))
        self.assertEqual(
            m16c_regions(), ((0xFA000, 0x2000), (0xFC000, 0x2000), (0xFE000, 0x2000))
        )


class EmpsTests(unittest.TestCase):
    def transfer(self, replies, count=2):
        from scripts.cuw_legacy_sil import EmpsSIL

        primitive = Primitive(replies)
        raw = EmpsSIL(NativeRuntime2026(primitive), 3)
        return (
            raw,
            primitive,
            lambda: raw.transfer(bytes(1024 * count), count, image_size=1024 * count),
        )

    def test_native_packet_checksum(self):
        from scripts.cuw_legacy_sil import emps_packet

        packet = emps_packet(3, bytes(range(256)) * 4)
        self.assertEqual(len(packet), 1028)
        self.assertEqual(packet[:3], b"\x03\x04\x00")
        self.assertEqual(sum(packet) & 255, 255)

    def test_success_and_final_timeout(self):
        raw, primitive, run = self.transfer((b"\x01", b"\x02"))
        self.assertEqual(run(), 2)
        self.assertEqual(raw.transferred, 2048)
        self.assertEqual(
            [
                e["milliseconds"]
                for e in primitive.events
                if e["operation"] == "set_timeout"
            ],
            [1000, 10000],
        )

    def test_same_packet_retries_and_stale_previous_ack(self):
        raw, primitive, run = self.transfer(
            (b"\x82\x00", b"\x01", b"\x82\x00", b"\x02")
        )
        self.assertEqual(run(), 2)
        writes = [
            e["data"][0] for e in primitive.events if e["operation"] == "write_messages"
        ]
        self.assertEqual(writes, [0, 0, 1])
        self.assertEqual(raw.transferred, 3072)

    def test_retry_limits_and_wrong_final_status(self):
        for replies in ((b"\x82\x00",) * 4, (b"\x02",), (b"\x01", b"\x01"), (b"\x83",)):
            with self.subTest(replies=replies):
                _, _, run = self.transfer(replies)
                with self.assertRaises(SilProtocolError):
                    run()

    def test_stale_budget_is_separate_from_send_retry_budget(self):
        _, primitive, run = self.transfer(
            (b"\x01", b"\x82\x00", b"\x82\x00", b"\x82\x00", b"\x82\x00")
        )
        with self.assertRaises(SilProtocolError):
            run()
        self.assertEqual(
            len([e for e in primitive.events if e["operation"] == "write_messages"]), 2
        )


class RawFaultTests(unittest.TestCase):
    def test_three_status_attempts_are_original18_not_2026_four(self):
        primitive = Primitive((b"bad", b"bad", b"bad"))
        raw = SilRaw(NativeRuntime2026(primitive), 3)
        with self.assertRaises(SilProtocolError) as caught:
            raw.status()
        self.assertEqual(caught.exception.code, 4)
        self.assertEqual(
            len([e for e in primitive.events if e["operation"] == "write_messages"]), 3
        )

    def test_raw_discards_extra_and_preserves_native_rxstatus_policy(self):
        reads = iter((NativeMessage(3, b"abc", rx_status=2), NativeMessage(3, b"d")))

        def action(event, remaining):
            return (next(reads),)

        raw = SilRaw(NativeRuntime2026(action), 3)
        self.assertEqual(raw.read_exact(2), b"ab")
        self.assertEqual(raw.read_exact(1), b"d")

    def test_raw_rejects_bytes_only_and_excess_count(self):
        for frames in ((b"abc",), (NativeMessage(3, b"a"), NativeMessage(3, b"b"))):
            with self.subTest(frames=frames):
                raw = SilRaw(
                    NativeRuntime2026(lambda event, remaining, frames=frames: frames), 3
                )
                with self.assertRaises(ValueError):
                    raw.read_exact(1)

    def test_empty_read_is_bounded_by_deadline(self):
        now = [0.0]

        def action(event, remaining):
            now[0] += 1.0
            return ()

        raw = SilRaw(NativeRuntime2026(action, clock=lambda: now[0], timeout=2), 3)
        with self.assertRaises(TimeoutError):
            raw.read_exact(1)

    def test_cancel_after_send_restores_native_send_timeout(self):
        cancelled = [False]
        events = []

        def action(event, remaining):
            events.append(event)
            if event["operation"] == "write_messages":
                if event["data"] == b"\x41":
                    return 1
                cancelled[0] = True
                return 1
            if event["operation"] == "read_messages":
                return (NativeMessage(3, b"\x3c"),)
            return None

        raw = SilRaw(NativeRuntime2026(action, cancelled=lambda: cancelled[0]), 3)
        with self.assertRaises(InterruptedError):
            raw.write_block(bytes(1024), 0, 1024)
        self.assertEqual(
            events[-1], {"operation": "set_send_timeout", "milliseconds": 1000}
        )

    def test_full_write_verify_literal_chronology(self):
        data = bytes(range(256)) * 4
        primitive = Primitive(
            (b"\x3c", b"\x3c", b"\x3c\x40\x3c", b"\x3c\x00\x3c", b"\x3c")
            + (b"\x3c", b"\x3c\x00\x3c") * 4
        )
        raw = SilRaw(NativeRuntime2026(primitive), 3)
        raw.write_block(data, 0x123456, 1024)
        raw.verify_block(2, data, 1024, native_delay=False)
        writes = [
            e["data"] for e in primitive.events if e["operation"] == "write_messages"
        ]
        self.assertEqual(
            writes[:8],
            [
                b"\x41",
                b"\x12\x34\x56\xff" + data[:256],
                data[256:512],
                data[512:768],
                data[768:],
                b"\x50",
                b"\x50",
                b"\x15\x01",
            ],
        )
        self.assertEqual(raw.transferred, 2048)
        self.assertEqual(
            [e["percent"] for e in primitive.events if e["operation"] == "progress"],
            [12, 25, 38, 50, 62, 75, 88, 100],
        )


class M16CTests(unittest.TestCase):
    def raw(self, reads):
        from scripts.cuw_legacy_sil import M16CSIL

        primitive = Primitive(reads)
        base = primitive.__call__

        def action(event, remaining):
            if event["operation"] == "write_messages" and "messages" in event:
                primitive.events.append(event)
                return event["count"]
            return base(event, remaining)

        return M16CSIL(NativeRuntime2026(action), 3), primitive

    def test_password_is_atomic_two_messages(self):
        raw, primitive = self.raw((b"\x00\x0c",))
        raw.password(0x01020304)
        self.assertEqual(
            primitive.events[0],
            {
                "operation": "write_messages",
                "protocol_id": 3,
                "tx_flags": 0,
                "messages": (b"\xa0\xdf\xff\x0f\x07", b"\x01\x02\x03\x04\x00\x00\x00"),
                "count": 2,
            },
        )
        raw, _ = self.raw((b"\x80\x08",))
        with self.assertRaises(SilProtocolError):
            raw.password(0)

    def test_native_erase_address_byte_order_and_fault(self):
        raw, primitive = self.raw((b"\x00\x00", b"\x80\xff"))
        raw.erase(0xFBFFF)
        self.assertEqual(
            [e["data"] for e in primitive.events if e["operation"] == "write_messages"],
            [b"\xa6", b"\xa1\xbf\x0f\xd0", b"\xa4", b"\xa4"],
        )
        raw, _ = self.raw((b"\xb0\x00",))
        with self.assertRaises(SilProtocolError):
            raw.erase(0xFBFFF)

    def test_page_write_verify_pending_and_fault_masks(self):
        raw, primitive = self.raw((b"\x00\x00", b"\x80\x00", b"\xff", b"\x00"))
        raw.page(0xFA100, bytes(256), 256, verify=False)
        raw.page(0xFA100, bytes(256), 256, verify=True)
        batches = [e["messages"] for e in primitive.events if "messages" in e]
        self.assertEqual([b[0] for b in batches], [b"\xa2\xa1\x0f", b"\xa3\xa1\x0f"])
        self.assertEqual(raw.transferred, 512)
        for reply in (b"\x80\x02", b"\xb0\x00"):
            raw, _ = self.raw((reply,))
            with self.assertRaises(SilProtocolError):
                raw.page(0xFA000, bytes(256), 256, verify=False)
        raw, _ = self.raw((b"\x01",))
        with self.assertRaises(SilProtocolError):
            raw.page(0xFA000, bytes(256), 256, verify=True)

    def test_all_three_original_regions_program_and_verify(self):
        # password, then3 erase results and32(write,verify) page result pairs each.
        reads = [b"\x00\x0c"]
        for _ in range(3):
            reads.append(b"\x80\x00")
            reads.extend([b"\x80\x00", b"\x00"] * 32)
        raw, primitive = self.raw(reads)
        raw.program(bytes(0x6000), 0, image_size=0x6000)
        batches = [e["messages"] for e in primitive.events if "messages" in e]
        self.assertEqual(len(batches), 193)
        self.assertEqual(batches[1][0], b"\xa2\xa0\x0f")
        self.assertEqual(batches[65][0], b"\xa2\xc0\x0f")
        self.assertEqual(batches[129][0], b"\xa2\xe0\x0f")
        self.assertEqual(raw.transferred, 0xC000)


class KWPTests(unittest.TestCase):
    def test_native_cpass_byte_and_signed_category_are_one_field(self):
        for byte, signed in ((0, 0), (127, 127), (128, -128), (255, -1)):
            error = SilProtocolError(byte, 0x123456)
            self.assertEqual((error.code, error.native_code), (byte, signed))
            self.assertEqual(error.native_code & 0xFFFFFFFF, signed & 0xFFFFFFFF)
            error.native_code = 13
            self.assertEqual((error.code, error.native_code), (13, 13))
            error.code = byte
            self.assertEqual((error.code, error.native_code), (byte, signed))
        for invalid in (-129, 256, True):
            with self.assertRaises(ValueError):
                SilProtocolError(invalid, 0x123456)

    def test_native_cpass_category_rewritten_and_host_identity_preserved(self):
        from scripts.cuw_legacy_sil import SilKWP

        for error in (SilProtocolError(13, 0x123456), OSError("authored host fault")):
            events = []

            def primitive(event, remaining, error=error, events=events):
                events.append(event)
                if event["operation"] == "get_timeout":
                    return 321
                if event["operation"] == "write_messages":
                    raise error
                return None

            raw = SilKWP(NativeRuntime2026(primitive), 3)
            with self.assertRaises(type(error)) as caught:
                raw.exchange(b"\x82\xc7\xf1\x11\x01\x4c", minimum=3, error=15)
            self.assertIs(caught.exception, error)
            if isinstance(error, SilProtocolError):
                self.assertEqual((error.code, error.native_code), (15, 15))
            self.assertEqual(
                events[-1], {"operation": "set_timeout", "milliseconds": 321}
            )

    def raw(self, replies):
        from scripts.cuw_legacy_sil import DcmprlSIL

        primitive = Primitive(replies)

        def action(event, remaining):
            if event["operation"] == "get_timeout":
                primitive.events.append(event)
                return 1000
            return primitive(event, remaining)

        return DcmprlSIL(NativeRuntime2026(action), 3), primitive

    def test_pending_keeps_receiving_busy_resends_and_restores_timeout(self):
        raw, primitive = self.raw(
            (
                b"\x80\xf1\xc7\x7f\x11\x78",
                b"\x80\xf1\xc7\x7f\x11\x21",
                b"\x80\xf1\xc7\x51\x01",
            )
        )
        raw.reset()
        writes = [
            e["data"] for e in primitive.events if e["operation"] == "write_messages"
        ]
        self.assertEqual(writes, [b"\x82\xc7\xf1\x11\x01\x4c"] * 2)
        self.assertEqual(
            primitive.events[-1], {"operation": "set_timeout", "milliseconds": 1000}
        )

    def test_pending_overflow_sends_native_stop(self):
        raw, primitive = self.raw((b"\x80\xf1\xc7\x7f\x11\x78",) * 150)
        with self.assertRaises(SilProtocolError):
            raw.reset()
        writes = [
            e["data"] for e in primitive.events if e["operation"] == "write_messages"
        ]
        self.assertEqual(writes[-1], b"\x81\xc7\xf1\x82\xbb")
        self.assertEqual(len(writes), 2)

    def test_security_bytes_and_boundary_validation(self):
        raw, primitive = self.raw(
            (b"\x80\xf1\xc7\x67\x01\x01\x02", b"\x80\xf1\xc7\x67\x02")
        )
        raw.security()
        writes = [
            e["data"] for e in primitive.events if e["operation"] == "write_messages"
        ]
        self.assertEqual(writes[0][:-1], b"\x82\xc7\xf1\x27\x01")
        self.assertEqual(writes[1][:-1], b"\x84\xc7\xf1\x27\x02\x3d\x16")
        raw, _ = self.raw((b"\x80\xf1\xc7\x67\x00",))
        with self.assertRaises(SilProtocolError):
            raw.security()

    def test_sixty_byte_transfer_tail_sequence_checksum(self):
        raw, primitive = self.raw(
            (b"\x80\xf1\xc7\x76\x01", b"\x80\xf1\xc7\x76\x02", b"\x80\xf1\xc7\x77")
        )
        raw.transfer(bytes(range(61)), cpu_type="32", kind_of_ecu="8", image_size=61)
        writes = [
            e["data"] for e in primitive.events if e["operation"] == "write_messages"
        ]
        self.assertEqual(writes[0][:-1], b"\xbe\xc7\xf1\x36\x01" + bytes(range(60)))
        self.assertEqual(writes[1][:-1], b"\x83\xc7\xf1\x36\x02\x3c")
        self.assertEqual(writes[2][:-1], b"\x83\xc7\xf1\x37\x07\x26")
        self.assertEqual(raw.transferred, 122)
        self.assertEqual(raw.countdown, 15000)
        raw.finish_countdown()
        self.assertEqual(raw.countdown, 0)


class InitializationTests(unittest.TestCase):
    def test_original_location_prefix_and_rxstatus_padding_branch(self):
        for padding, reads in ((False, 0), (True, 1)):
            with self.subTest(padding=padding):
                events = []

                def action(event, remaining, events=events):
                    events.append(event)
                    if event["operation"] == "ioctl" and event["ioctl"] == 5:
                        return NativeMessage(3, b"authored", rx_status=0x10)
                    if event["operation"] == "read_messages":
                        return (NativeMessage(3, b"authored"),)
                    if event["operation"] == "write_messages":
                        return 1
                    return None

                raw = SilRaw(NativeRuntime2026(action), 3)
                raw.initialize(
                    bytes.fromhex("01020304aabbccdd"), 0x11223344, padding=padding
                )
                fast_init = next(
                    e for e in events if e["operation"] == "ioctl" and e["ioctl"] == 5
                )
                self.assertEqual(
                    fast_init["input"], bytes.fromhex("00000403020144332211")
                )
                self.assertEqual(
                    sum(e["operation"] == "read_messages" for e in events), reads
                )
                self.assertEqual(events[-1]["data"], b"\x3c")

    def test_primary_fault_survives_cleanup_fault(self):
        def action(event, remaining):
            if event["operation"] == "write_messages":
                raise SilProtocolError(13, 0x485798)
            if (
                event["operation"] == "set_send_timeout"
                and event["milliseconds"] == 1000
            ):
                raise OSError("authored cleanup failure")

        raw = SilRaw(NativeRuntime2026(action), 3)
        with self.assertRaises(SilProtocolError) as caught:
            raw._packet(bytes(256), 256)
        self.assertEqual(caught.exception.code, 13)
        self.assertTrue(
            any("restoration failed" in note for note in caught.exception.__notes__)
        )


class WideSILTests(unittest.TestCase):
    def test_source_native_wide_ranges(self):
        primitive = Primitive((b"\x3c", b"\x3c\x00\x3c"))
        raw = SilRaw(NativeRuntime2026(primitive), 3)
        self.assertTrue(raw.block("erase", 257, last=512))
        writes = [
            e["data"] for e in primitive.events if e["operation"] == "write_messages"
        ]
        self.assertEqual(writes, [b"\x26\x01\x00\x01\xff", b"\x50"])

    def test_native_memory_geometry_not_dll_parameter_table(self):
        from scripts.cuw_legacy_sil import sil_memory_geometry

        memory = bytes.fromhex("10000011ffff1003")
        self.assertEqual(sil_memory_geometry("unknown", memory), (16384,) * 8)
        self.assertEqual(sil_memory_geometry("19", memory), (4096,) * 32)


class OccupantKeyTests(unittest.TestCase):
    def test_short_key_native_modulo_subtraction(self):
        from scripts.cuw_legacy_sil import occupant_short_key

        self.assertEqual(occupant_short_key(b"\x00\x01", b"\x00\x00"), b"\xff\xfe")
        self.assertEqual(occupant_short_key(b"\x12\x34", b"\x56\x78"), b"\x44\x43")

    def test_long_key_in_place_native_order(self):
        from scripts.cuw_legacy_sil import occupant_long_key

        # Authoredvalues: byte1 references alreadyupdatedbyte0, byte3 maps7→1.
        self.assertEqual(
            occupant_long_key(bytes((1, 8, 6, 7, 255, 128)), bytes(6)),
            bytes((12, 28, 60, 140, 27, 13)),
        )


class OccupantWireTests(unittest.TestCase):
    def test_short_location_has_five_writes_four_zero_waits_and_seventeen_byte_ack(
        self,
    ):
        raw, primitive = self.raw((b"\x3c" + bytes(16),))
        raw.short_location_password(bytes.fromhex("01020304aabbccdd"), 0x12345678)
        self.assertEqual(
            [e["data"] for e in primitive.events if e["operation"] == "write_messages"],
            [b"\0", b"\0", b"\x02\x01", b"\x04\x03", b"\x78\x56\x34\x12", b"\x3c"],
        )
        self.assertEqual(
            [e["milliseconds"] for e in primitive.events if e["operation"] == "wait"],
            [0] * 4,
        )

    def test_finish_reads_leading_marker_without_status_request(self):
        raw, primitive = self.raw((b"\x01\x3c", b"\x3c\x00"))
        raw.finish()
        self.assertEqual(
            [e["data"] for e in primitive.events if e["operation"] == "write_messages"],
            [b"\x80"],
        )
        self.assertEqual(
            sum(e["operation"] == "read_messages" for e in primitive.events), 2
        )

    def test_fast_init_wait_precedes_optional_read(self):
        from scripts.cuw_legacy_sil import OccupantSIL

        for mode in (1, 3):
            for status, extra in ((2, True), (0x10, False)):
                with self.subTest(mode=mode, status=status):
                    events = []

                    def action(event, remaining, events=events, status=status):
                        events.append(event)
                        if event["operation"] == "ioctl" and event["ioctl"] == 5:
                            return NativeMessage(3, b"", rx_status=status)
                        if event["operation"] == "read_messages":
                            return (NativeMessage(3, b"authored"),)

                    OccupantSIL(NativeRuntime2026(action), 3).fast_init(
                        0x20, mode, padding=False
                    )
                    self.assertEqual(
                        [e["config"] for e in events[:3]],
                        [
                            ((1, 9600 if mode == 1 else 10400),),
                            ((0x14, 35 if mode == 1 else 25),),
                            ((0x15, 50),),
                        ],
                    )
                    self.assertEqual(events[3]["input"], b"\x81\x20\xf1\x81\x13")
                    self.assertEqual(events[4]["operation"], "wait")
                    self.assertEqual(events[4]["milliseconds"], 100)
                    self.assertEqual(len(events), 6 if extra else 5)

    def raw(self, replies):
        from scripts.cuw_legacy_sil import OccupantSIL

        primitive = Primitive(replies)

        def action(event, remaining):
            if event["operation"] == "get_timeout":
                return 1000
            return primitive(event, remaining)

        return OccupantSIL(NativeRuntime2026(action), 3), primitive

    def test_short_security_literal_header_and_key(self):
        raw, primitive = self.raw(
            (b"\x84\xf1\x20\x67\x01\x12\x34", b"\x83\xf1\x20\x67\x02\xaa")
        )
        raw.security_short(0x20, b"\x01\x02", b"\x56\x78")
        writes = [
            e["data"] for e in primitive.events if e["operation"] == "write_messages"
        ]
        self.assertEqual(
            [p[:-1] for p in writes],
            [b"\x84\x20\xf1\x27\x01\x01\x02", b"\x84\x20\xf1\x27\x02\x44\x43"],
        )

    def test_long_security_literal_header_and_key(self):
        raw, primitive = self.raw(
            (bytes.fromhex("88f120676101080607ff8000"), bytes.fromhex("83f120676234"))
        )
        raw.security_long(0x20, bytes(6))
        writes = [
            e["data"] for e in primitive.events if e["operation"] == "write_messages"
        ]
        self.assertEqual(writes[0][:-1], bytes.fromhex("8220f12761"))
        self.assertEqual(writes[1][:-1], bytes.fromhex("8820f127620c1c3c8c1b0d"))

    def test_invalid_material_fails_before_any_io(self):
        raw, primitive = self.raw(())
        with self.assertRaises(ValueError):
            raw.security_short(0x20, bytes(2), b"bad")
        self.assertEqual(primitive.events, [])


class NativeTransportMappingTests(unittest.TestCase):
    def test_m16c_read_timeout_maps_per_caller_but_write_error_propagates(self):
        from scripts.cuw_legacy_sil import M16CSIL
        from scripts.programming import NativeTransportError

        for code in (9, 16, 5):
            for operation, expected in (
                ("read_messages", 7 if code in (9, 16) else None),
                ("write_messages", None),
            ):
                with self.subTest(code=code, operation=operation):

                    def action(event, remaining, code=code, operation=operation):
                        if event["operation"] == operation:
                            raise NativeTransportError(code)
                        if event["operation"] == "write_messages":
                            return event["count"]
                        return None

                    raw = M16CSIL(NativeRuntime2026(action), 3)
                    if expected is None:
                        with self.assertRaises(NativeTransportError) as caught:
                            raw.password(0)
                        self.assertEqual(caught.exception.code, code)
                    else:
                        with self.assertRaises(SilProtocolError) as caught:
                            raw.password(0)
                        self.assertEqual(caught.exception.code, expected)

    def test_verify_timeout_maps15(self):
        from scripts.cuw_legacy_sil import M16CSIL
        from scripts.programming import NativeTransportError

        def action(event, remaining):
            if event["operation"] == "read_messages":
                raise NativeTransportError(9)
            if event["operation"] == "write_messages":
                return event["count"]
            return None

        raw = M16CSIL(NativeRuntime2026(action), 3)
        with self.assertRaises(SilProtocolError) as caught:
            raw.page(0xFA000, bytes(256), 256, verify=True)
        self.assertEqual(caught.exception.code, 15)


class EmpsExceptionTests(unittest.TestCase):
    def test_first_packet_write_read_mutation_and_recreate_flag(self):
        from scripts.cuw_legacy_engine import ExecutableJ2534Error
        from scripts.cuw_legacy_sil import EmpsSIL
        from scripts.programming import NativeTransportError

        for operation, status, recreate in (
            ("write_messages", 5, True),
            ("read_messages", 5, False),
            ("read_messages", 9, True),
            ("read_messages", 16, True),
        ):
            with self.subTest(operation=operation, status=status):

                def action(event, remaining, operation=operation, status=status):
                    if event["operation"] == operation:
                        raise NativeTransportError(status)
                    if event["operation"] == "write_messages":
                        return 1
                    return None

                raw = EmpsSIL(NativeRuntime2026(action), 3)
                with self.assertRaises(ExecutableJ2534Error) as caught:
                    raw.transfer(bytes(1024), 1, image_size=1024)
                self.assertEqual(caught.exception.native_code, 13)
                self.assertEqual(caught.exception.driver_status, status)
                self.assertEqual(raw.needs_recreate, recreate)

    def test_stale_receive_retains_original_error_category(self):
        from scripts.cuw_legacy_engine import ExecutableJ2534Error
        from scripts.cuw_legacy_sil import EmpsSIL
        from scripts.programming import NativeTransportError

        reads = iter((b"\x01", b"\x82\x00", NativeTransportError(9)))

        def action(event, remaining):
            if event["operation"] == "read_messages":
                value = next(reads)
                if isinstance(value, Exception):
                    raise value
                return (NativeMessage(3, value),)
            if event["operation"] == "write_messages":
                return 1
            return None

        raw = EmpsSIL(NativeRuntime2026(action), 3)
        with self.assertRaises(ExecutableJ2534Error) as caught:
            raw.transfer(bytes(2048), 2, image_size=2048)
        self.assertEqual(caught.exception.native_code, 1)
        self.assertEqual(caught.exception.driver_status, 9)
        self.assertFalse(raw.needs_recreate)


class DcmBlockAssemblyTests(unittest.TestCase):
    def test_native_geometry_uses_materialized_span_and_special_six_sizes(self):
        from scripts.cuw_legacy_sil import dcmprl_block_sizes

        self.assertEqual(dcmprl_block_sizes("31", 2500), (1024, 1024, 452))
        self.assertEqual(
            dcmprl_block_sizes("34", 2500), (1024, 1024, 1024, 1024, 4, 256)
        )
        self.assertEqual(dcmprl_block_sizes("31", 0), ())

    def test_dcm_fast_init_keeps_caller_baud_and_native_timing(self):
        from scripts.cuw_legacy_sil import DcmprlSIL

        for padding, expected_reads in ((False, 0), (True, 1)):
            events = []

            def primitive(event, remaining, events=events):
                events.append(event)
                if event["operation"] == "ioctl" and event["ioctl"] == 5:
                    return NativeMessage(3, b"", rx_status=0x10)
                if event["operation"] == "read_messages":
                    return (NativeMessage(3, b"authored"),)
                return None

            DcmprlSIL(NativeRuntime2026(primitive), 3).fast_init(padding=padding)
            configs = [
                event["config"]
                for event in events
                if event["operation"] == "ioctl" and event["ioctl"] == 2
            ]
            self.assertEqual(configs, [((0x14, 25),), ((0x15, 50),)])
            self.assertEqual(
                next(event["input"] for event in events if event.get("ioctl") == 5),
                bytes.fromhex("81c7f181ba"),
            )
            self.assertEqual(
                sum(event["operation"] == "read_messages" for event in events),
                expected_reads,
            )

    def test_routine_start_and_result_have_distinct_native_lengths(self):
        from scripts.cuw_legacy_sil import DcmprlSIL

        events = []
        replies = iter(
            (b"\x84\xf1\xc7\x71\x01\x02\x01", b"\x85\xf1\xc7\x71\x02\x02\x01\x01")
        )

        def primitive(event, remaining):
            events.append(event)
            if event["operation"] == "get_timeout":
                return 1000
            if event["operation"] == "read_messages":
                return (NativeMessage(3, next(replies)),)
            if event["operation"] == "write_messages":
                return 1
            return None

        raw = DcmprlSIL(NativeRuntime2026(primitive), 3)
        raw.routine(1, 0x0201)
        raw.routine(2, 0x0201)
        writes = [
            event["data"] for event in events if event["operation"] == "write_messages"
        ]
        self.assertEqual(
            writes,
            [
                b"\x84\xc7\xf1\x31\x01\x02\x01\x71",
                b"\x85\xc7\xf1\x31\x02\x02\x01\x01\x74",
            ],
        )

    def test_special_block_adjustment_is_added_before_prefix_sum(self):
        from scripts.cuw_legacy_sil import DcmprlSIL

        image = bytearray(0x4500)
        image[0x400E:0x4012] = b"TEST"
        events = []
        replies = iter(
            (b"\x80\xf1\xc7\x74\x30abc", b"\x80\xf1\xc7\x76x", b"\x80\xf1\xc7\x77")
        )

        def primitive(event, remaining):
            events.append(event)
            if event["operation"] == "get_timeout":
                return 1000
            if event["operation"] == "read_messages":
                return (NativeMessage(3, next(replies)),)
            if event["operation"] == "write_messages":
                return 1
            return None

        raw = DcmprlSIL(NativeRuntime2026(primitive), 3)
        raw.program_block(
            bytes(image),
            (1024, 1024, 1024, 1024, 4, 256),
            5,
            cpu_type="34",
            kind_of_ecu="8",
            image_size=4356,
        )
        writes = [
            event["data"] for event in events if event["operation"] == "write_messages"
        ]
        self.assertEqual(writes[0][6:12], bytes.fromhex("40400e000004"))
        self.assertEqual(writes[1][5:-1], b"TEST")
        self.assertEqual(writes[2][4:6], sum(b"TEST").to_bytes(2, "big"))
        self.assertEqual(raw.transferred, 8)
        self.assertEqual(raw.countdown, 15000)


class BootstrapTests(unittest.TestCase):
    def test_native_success_runs_all_three_hundred_probe_loops_at_first_rate(self):
        from collections import deque

        events, pending = [], deque()
        memory = bytes.fromhex("0000000003ff0100")

        def primitive(event, remaining):
            events.append(event)
            if event["operation"] == "write_messages":
                packet = event["data"]
                pending.append(
                    b"\x3c" + memory + b"\x3c"
                    if packet == b"\x75"
                    else b"\x3c\x00\x3c"
                    if packet == b"\x50"
                    else b"\x3c"
                )
                return 1
            if event["operation"] == "read_messages":
                return (NativeMessage(3, pending.popleft()),)
            return None

        raw = SilRaw(NativeRuntime2026(primitive), 3)
        self.assertEqual(raw.bootstrap("1", (9600, 19200, 38400), ()), memory)
        writes = [
            event["data"] for event in events if event["operation"] == "write_messages"
        ]
        self.assertEqual(writes.count(b"\x60"), 100)
        self.assertEqual(writes.count(b"\x75"), 100)
        self.assertEqual(writes.count(b"\x35\x00"), 100)
        self.assertEqual(writes.count(b"\x50"), 100)
        self.assertEqual(
            [event["config"] for event in events if event["operation"] == "ioctl"],
            [((1, 9600),)],
        )
        self.assertFalse(pending)

    def test_initial_ff_special_retry_occurs_once_at_second_and_third_rate(self):
        raw, primitive = SilTests().raw((b"\xff",) * 5)
        with self.assertRaises(SilProtocolError) as caught:
            raw.bootstrap("1", (9600, 19200, 38400), ())
        self.assertEqual(caught.exception.code, 21)
        self.assertEqual(
            [
                event["config"]
                for event in primitive.events
                if event["operation"] == "ioctl"
            ],
            [((1, 9600),), ((1, 19200),), ((1, 38400),)],
        )
        self.assertEqual(
            sum(event["operation"] == "write_messages" for event in primitive.events), 5
        )


class ProgramRangeTests(unittest.TestCase):
    def test_grouped_kind63_forces_erase_and_preserves_native_progress_denominator(
        self,
    ):
        from collections import deque

        events, pending, mode = [], deque(), ["", 0]

        def primitive(event, remaining):
            events.append(event)
            operation = event["operation"]
            if operation == "write_messages":
                packet = event["data"]
                if packet == b"\x50":
                    pending.append(b"\x3c\x00\x3c")
                elif packet in (b"\x41", b"\x45"):
                    mode[:] = ["write", 0]
                    pending.append(b"\x3c")
                elif packet.startswith(b"\x16") and len(packet) == 5:
                    mode[:] = ["verify", 0]
                    pending.append(b"\x3c")
                elif len(packet) in (256, 260):
                    mode[1] += 1
                    if mode[0] == "verify" or mode[1] % 4 == 0:
                        pending.append(b"\x3c")
                else:
                    pending.append(b"\x3c")
                return 1
            if operation == "read_messages":
                return (NativeMessage(3, pending.popleft()),)
            return None

        raw = SilRaw(NativeRuntime2026(primitive), 3)
        raw.extended_memory = True
        memory = bytes.fromhex("0000000007ff0100")
        raw.program_ranges(
            bytes(2048),
            memory,
            "1",
            "63",
            image_size=1024,
            native_delay=False,
            range_rows=(("1", ((1, 2),)),),
        )
        writes = [
            event["data"] for event in events if event["operation"] == "write_messages"
        ]
        self.assertFalse(
            any(packet.startswith(b"\x36") and len(packet) == 5 for packet in writes)
        )
        self.assertEqual(writes[0], bytes.fromhex("2600000001"))
        self.assertIn(bytes.fromhex("4800000001"), writes)
        self.assertIn(bytes.fromhex("1600000001"), writes)
        self.assertEqual(writes.count(b"\x41"), 1)
        self.assertEqual(writes.count(b"\x45"), 1)
        self.assertTrue(raw.writing_end_block)
        self.assertEqual(raw.transferred, 4096)
        progress = [event for event in events if event["operation"] == "progress"]
        self.assertEqual(progress[-1]["percent"], 200)
        self.assertFalse(pending)


class MemoryExceptionTests(unittest.TestCase):
    def test_initial75_read_catches_native_protocol_error_but_preserves_cached_identity(
        self,
    ):
        from scripts.cuw_legacy_engine import ExecutableForeignNativeError

        for error in (
            SilProtocolError(7, 0x123456),
            ExecutableForeignNativeError("authored native foreign exception"),
        ):
            with self.subTest(error=type(error).__name__):
                self.initial75_fallback(error)

    def initial75_fallback(self, error):
        events, reads = [], [0]

        def primitive(event, remaining):
            events.append(event)
            if event["operation"] == "write_messages":
                return 1
            if event["operation"] == "read_messages":
                reads[0] += 1
                if reads[0] != 2:
                    raise error
                return (NativeMessage(3, b"\x3c12345678!\x3c"),)
            return None

        raw = SilRaw(NativeRuntime2026(primitive), 3)
        self.assertEqual(raw.memory(), b"12345678")
        with self.assertRaises(type(error)) as caught:
            raw.memory()
        self.assertIs(caught.exception, error)
        self.assertEqual(
            [
                event["data"]
                for event in events
                if event["operation"] == "write_messages"
            ],
            [b"\x75", b"\x76", b"\x76"],
        )

    def test_initial75_read_native_failure_falls_back_but_cached_read_propagates(self):
        from scripts.cuw_legacy_engine import ExecutableJ2534Error
        from scripts.programming import NativeTransportError

        for status in (8, 9, 16):
            with self.subTest(status=status):
                events, reads = [], [0]

                def primitive(
                    event, remaining, events=events, reads=reads, status=status
                ):
                    events.append(event)
                    if event["operation"] == "write_messages":
                        return 1
                    if event["operation"] == "read_messages":
                        reads[0] += 1
                        if reads[0] != 2:
                            raise NativeTransportError(status)
                        return (NativeMessage(3, b"\x3c12345678!\x3c"),)
                    return None

                raw = SilRaw(NativeRuntime2026(primitive), 3)
                self.assertEqual(raw.memory(), b"12345678")
                self.assertTrue(raw.extended_memory)
                with self.assertRaises(ExecutableJ2534Error) as caught:
                    raw.memory()
                self.assertEqual(caught.exception.driver_status, status)
                self.assertEqual(
                    [
                        event["data"]
                        for event in events
                        if event["operation"] == "write_messages"
                    ],
                    [b"\x75", b"\x76", b"\x76"],
                )

    def test_initial75_write_native_failure_and_host_read_cancel_do_not_fall_back(self):
        from scripts.cuw_legacy_engine import ExecutableJ2534Error
        from scripts.programming import NativeTransportError

        for failing_operation, error in (
            ("write_messages", NativeTransportError(16)),
            ("read_messages", InterruptedError("authored cancellation")),
        ):
            events = []

            def primitive(
                event,
                remaining,
                events=events,
                failing_operation=failing_operation,
                error=error,
            ):
                events.append(event)
                if event["operation"] == failing_operation:
                    raise error
                if event["operation"] == "write_messages":
                    return 1
                return None

            raw = SilRaw(NativeRuntime2026(primitive), 3)
            with self.assertRaises(
                ExecutableJ2534Error
                if failing_operation == "write_messages"
                else InterruptedError
            ):
                raw.memory()
            self.assertEqual(
                [
                    event["data"]
                    for event in events
                    if event["operation"] == "write_messages"
                ],
                [b"\x75"],
            )


class VerifyExceptionChronologyTests(unittest.TestCase):
    def test_nonfinal_protocol_and_foreign_native_status_errors_propagate_identity(
        self,
    ):
        from scripts.cuw_legacy_engine import ExecutableForeignNativeError

        for error in (
            SilProtocolError(10, 0x123456),
            ExecutableForeignNativeError("authored foreign"),
        ):
            with self.subTest(error=type(error).__name__):
                reads = [0]

                def primitive(event, remaining, error=error, reads=reads):
                    if event["operation"] == "write_messages":
                        return 1
                    if event["operation"] == "read_messages":
                        reads[0] += 1
                        if reads[0] > 2:
                            raise error
                        return (NativeMessage(3, b"\x3c"),)
                    return None

                raw = SilRaw(NativeRuntime2026(primitive), 3)
                with self.assertRaises(type(error)) as caught:
                    raw.verify_block(1, bytes(512), 512, native_delay=False)
                self.assertIs(caught.exception, error)


if __name__ == "__main__":
    unittest.main()
