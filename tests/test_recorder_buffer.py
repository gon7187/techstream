"""Authored byte controls for native recorder allocation and serial state."""

import struct
import unittest

from scripts.recorder_buffer import (
    MAX_BUFFER_BYTES,
    U32,
    NativeRecorderRing,
    RecorderBufferError,
)


def packet(timestamp, value):
    return struct.pack("<I", timestamp) + bytes([value])


class RecorderBufferTests(unittest.TestCase):
    def test_literal_header_and_unread_state(self):
        ring = NativeRecorderRing(11, 5)
        ring.write(b"\x01\x00\x00\x00\xaa")
        self.assertEqual(
            (
                ring.free,
                ring.start,
                ring.read_position,
                ring.write_position,
                ring.written,
            ),
            (6, 0, 0, 5, 5),
        )
        self.assertEqual(
            ring.serialize(),
            bytes.fromhex(
                "01000000000000000100 0b00000006000000000000000000000005000000050000000b000000 01000000aa000000000000"
            ),
        )
        self.assertEqual(ring.read(5), b"\x01\0\0\0\xaa")
        self.assertEqual(ring.free, 11)
        self.assertEqual(ring.packet_bytes(), b"\x01\0\0\0\xaa")
        ring.write(b"")
        self.assertEqual((ring.free, ring.write_position), (11, 5))
        boundary = NativeRecorderRing(5, 5)
        boundary.append(1, b"a")
        boundary.write(b"")
        self.assertEqual(
            boundary.write_position, 5
        )  # Native zero write retains the end cursor.

    def test_equality_collision_is_not_a_host_deque(self):
        ring = NativeRecorderRing(10, 5)
        ring.append(10, b"a")
        ring.append(20, b"b")
        self.assertEqual((ring.start, ring.write_position, ring.written), (5, 10, 10))
        self.assertEqual(ring.packets(), (packet(20, ord("b")),))
        # WriteImage writes saturated history starting at oldest, even at equality.
        header = struct.unpack("<HHIH7I", ring.serialize()[:38])
        self.assertEqual(header[4:], (10, 0, 5, 5, 10, 10, 10))
        ring.append(30, b"c")
        self.assertEqual((ring.start, ring.write_position), (0, 5))
        self.assertEqual(ring.packets(), (packet(30, ord("c")),))

    def test_nonmultiple_capacity_wrap(self):
        ring = NativeRecorderRing(13, 5)
        for timestamp in range(1, 8):
            ring.append(timestamp, bytes([timestamp]))
        self.assertEqual((ring.start, ring.write_position, ring.written), (12, 9, 13))
        self.assertEqual(ring.packets(), (packet(6, 6), packet(7, 7)))
        ring.reset_seek()
        self.assertEqual(ring.read_position, 12)
        self.assertEqual(ring.free, 0)
        self.assertEqual(ring.read(10), packet(6, 6) + packet(7, 7))

    def test_failed_write_does_not_mutate(self):
        ring = NativeRecorderRing(10, 5)
        ring.write(packet(1, 2))
        before = (ring.image, ring.free, ring.start, ring.write_position)
        with self.assertRaises(RecorderBufferError):
            ring.write(b"123456")
        self.assertEqual(
            before, (ring.image, ring.free, ring.start, ring.write_position)
        )
        with self.assertRaises(RecorderBufferError):
            ring.read(6)
        self.assertEqual(
            before, (ring.image, ring.free, ring.start, ring.write_position)
        )

    def test_packet_batch_production_defers_consumer_without_losing_slot_cursor(self):
        ring = NativeRecorderRing(17, 5, 2)
        ring.append(10, b"a", consume=False)
        ring.append(20, b"b", consume=False)
        self.assertEqual(
            (ring.free, ring.read_position, ring.current_packet), (7, 0, 0)
        )
        self.assertEqual(ring.read(5), packet(10, ord("a")))
        self.assertEqual(ring.read(5), packet(20, ord("b")))
        self.assertEqual((ring.free, ring.read_position), (17, 10))
        self.assertEqual((ring.packet_slot(0), ring.packet_slot(5)), (0, 1))
        before = ring.image
        with self.assertRaises(RecorderBufferError):
            ring.append(30, b"c", consume=1)  # pyright: ignore[reportArgumentType]
        self.assertEqual(ring.image, before)

    def test_selected_mode_one_literal(self):
        ring = NativeRecorderRing(17, 5)
        for timestamp in (10, 20, 30):
            ring.append(timestamp, bytes([timestamp]))
        self.assertEqual(
            ring.select(15, 25), packet(10, 10) + packet(20, 20) + packet(30, 30)
        )
        expected = struct.pack("<HHIH7I", 1, 0, 0, 1, 17, 2, 0, 0, 15, 15, 15)
        self.assertEqual(
            ring.serialize(1),
            expected + packet(10, 10) + packet(20, 20) + packet(30, 30),
        )

    def test_block_packets_two_exact_selection(self):
        ring = NativeRecorderRing(31, 5, 2, phase=1)
        for timestamp in range(10, 70, 10):
            ring.append(timestamp, bytes([timestamp]))
        self.assertEqual(ring.current_packet, 0)
        self.assertEqual(ring.seek_timestamp(20, floor=True), (20, 10))
        self.assertEqual(
            ring.select_positions(10, 20),
            b"".join(packet(t, t) for t in (30, 40, 50, 60)),
        )
        self.assertEqual(struct.unpack("<HHIH", ring.serialize(1)[:10]), (1, 0, 1, 2))

    def test_block_two_cache_slots_survive_native_oldest_boundary(self):
        ring = NativeRecorderRing(20, 5, 2, phase=1)
        for t in range(1, 6):
            ring.append(t, bytes([t]))
        self.assertEqual(
            (ring.start, ring.write_position, ring.current_packet), (10, 5, 1)
        )
        self.assertEqual(tuple(ring.packet_slot(p) for p in (10, 15, 0)), (0, 1, 0))
        with self.assertRaises(RecorderBufferError):
            ring.packet_slot(5)
        with self.assertRaises(RecorderBufferError):
            ring.packet_slot(11)

    def test_wrapped_selected_region(self):
        ring = NativeRecorderRing(17, 5)
        for t in (1, 2, 3, 4):
            ring.append(t, bytes([t]))
        ring.set_record_area(10, 10)
        self.assertEqual(ring.serialize(1)[38:], packet(3, 3) + packet(4, 4))

    def test_positive_complement_appends_copy_with_u32_wrap(self):
        ring = NativeRecorderRing(30, 5)
        ring.append(U32 - 2, b"x")
        ring.set_record_area(0, 5)
        ring.calc_complement(1, 3, 0)
        self.assertEqual(
            ring.serialize(1)[38:], packet(U32 - 2, ord("x")) + packet(1, ord("x"))
        )
        self.assertEqual(
            struct.unpack("<7I", ring.serialize(1)[10:38]), (30, 25, 0, 0, 10, 10, 10)
        )

    def test_negative_complement_rewrites_last_block_only(self):
        ring = NativeRecorderRing(30, 5, 2)
        ring.append(2, b"a")
        ring.append(4, b"b")
        ring.set_record_area(0, 10)
        ring.set_complement(-3)
        self.assertEqual(
            ring.serialize(1)[38:], packet(U32, ord("a")) + packet(4, ord("b"))
        )
        self.assertEqual(ring.image[:10], packet(2, ord("a")) + packet(4, ord("b")))

    def test_timestamp_wrap_remains_raw_unsigned_native_comparison(self):
        ring = NativeRecorderRing(20, 5)
        ring.append(U32 - 1, b"a")
        ring.append(2, b"b")
        self.assertEqual(ring.approximate_time(1, False), U32 - 1)
        self.assertEqual(ring.packet_time(1), 2)
        self.assertEqual(ring.packet_time(4), U32)

    def test_complement_serial_allocation_can_exceed_original_capacity(self):
        ring = NativeRecorderRing(10, 5)
        ring.append(10, b"a")
        ring.append(20, b"b")
        ring.set_record_area(0, 10)
        ring.set_complement(5)
        serial = ring.serialize(1)
        self.assertEqual(struct.unpack("<7I", serial[10:38]), (10, 0, 0, 0, 15, 15, 15))
        self.assertEqual(
            serial[38:],
            packet(10, ord("a")) + packet(20, ord("b")) + packet(25, ord("b")),
        )

    def test_native_bytewise_control_across_reads_and_writes(self):
        # Independent literal byte loop mirrors pointer operations, not bulk slices.
        ring = NativeRecorderRing(17, 5)
        image = bytearray(17)
        start = read = write = written = 0
        free = 17
        for number in range(1, 101):
            data = packet(number, number)
            limit = start + 17 if start <= write else start
            if limit <= write + 5:
                start += 5
                if start >= 17:
                    start -= 17
            for byte in data:
                if write >= 17:
                    write = 0
                image[write] = byte
                write += 1
                written = min(17, written + 1)
            free -= 5
            ring.write(data)
            self.assertEqual(
                (ring.image, ring.start, ring.write_position, ring.written, ring.free),
                (bytes(image), start, write, written, free),
            )
            consumed = bytearray()
            for _ in data:
                if read >= 17:
                    read = 0
                consumed.append(image[read])
                read += 1
            if read >= 17:
                read -= 17
            free += 5
            self.assertEqual(ring.read(5), bytes(consumed))
            self.assertEqual((ring.read_position, ring.free), (read, free))

    def test_serial_complement_respects_host_byte_budget(self):
        ring = NativeRecorderRing(6, 5, max_bytes=6)
        ring.append(1, b"a")
        ring.set_record_area(0, 5)
        ring.set_complement(1)
        with self.assertRaisesRegex(RecorderBufferError, "host byte budget"):
            ring.serialize(1)
        self.assertEqual(ring.image, packet(1, ord("a")) + b"\0")
        ring.set_complement(1, 0)
        self.assertEqual(ring.serialize(1)[38:], packet(1, ord("a")))

    def test_packet_scan_and_materialization_budget(self):
        ring = NativeRecorderRing(31, 5, max_packets=2)
        for t in (1, 2, 3):
            ring.append(t, bytes([t]))
        for action in (
            ring.packets,
            lambda: ring.approximate_time(2, True),
            lambda: ring.absolute_position(2),
        ):
            with self.assertRaisesRegex(RecorderBufferError, "budget"):
                action()
        before = ring.image
        with self.assertRaisesRegex(RecorderBufferError, "budget"):
            ring.feed(((1, b"a"), (2, b"b"), (3, b"c")))
        self.assertEqual(ring.image, before)

    def test_native_source_distinguishes_sh3_unknown_interior_seek(self):
        for source in ("x86", "sh3"):
            with self.subTest(source=source):
                ring = NativeRecorderRing(31, 5, native_source=source)
                for timestamp in (10, U32, 20, 40):
                    ring.append(timestamp, b"a")
                before = ring.image
                if source == "x86":
                    self.assertEqual(ring.approximate_time(15, False), 1)
                    self.assertEqual(ring.approximate_time(15, True), 0)
                else:
                    with self.assertRaisesRegex(
                        RecorderBufferError, "Unknown SH3 native seek"
                    ):
                        ring.seek_timestamp(15, floor=True)
                self.assertEqual(ring.image, before)
        with self.assertRaisesRegex(
            RecorderBufferError, "Unknown native recorder source"
        ):
            NativeRecorderRing(31, 5, native_source="guessed")  # pyright: ignore[reportArgumentType]

    def test_cancelled_feed_preserves_written_prefix(self):
        ring = NativeRecorderRing(17, 5)
        calls = iter((False, True))
        with self.assertRaisesRegex(RecorderBufferError, "cancelled"):
            ring.feed(((1, b"a"), (2, b"b")), cancelled=lambda: next(calls))
        self.assertEqual(ring.packet_bytes(), packet(1, ord("a")))

    def test_host_limits_and_mutation_isolation(self):
        for args in ((0, 5), (MAX_BUFFER_BYTES + 1, 5), (10, 3), (10, 5, 3), (True, 5)):
            with self.subTest(args=args), self.assertRaises(RecorderBufferError):
                NativeRecorderRing(*args)
        ring = NativeRecorderRing(10, 5)
        data = bytearray(b"abcde")
        with self.assertRaises(RecorderBufferError):
            ring.write(data)  # pyright: ignore[reportArgumentType]
        self.assertEqual(ring.image, bytes(10))
        ring.append(1, b"a")
        ring.set_record_area(0, 5)
        ring.set_complement(1, 4)
        with self.assertRaises(RecorderBufferError):
            ring.serialize(1)
        ring.set_complement(1, 6)
        with self.assertRaises(RecorderBufferError):
            ring.serialize(1)


if __name__ == "__main__":
    unittest.main()
