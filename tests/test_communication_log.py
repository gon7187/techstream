"""Authored byte vectors derived from native stores; no OEM log content."""

import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import communication_log as log
from scripts import snapshot


class CommunicationLogTests(unittest.TestCase):
    def test_independent_native_vector_and_unknown_roundtrip(self):
        # RMViewer18 1ba85/1c4f0: magic/version/revision, size20/id8000.
        raw = bytes.fromhex("0300008001000000140000000080")
        raw += bytes.fromhex("feffffffea070a0014000c00220038001503")
        raw += bytes.fromhex("0b0000000301030000002201aabbcc")
        raw += bytes.fromhex("05000000efbe00ff7f")
        parsed = log.parse(raw)
        self.assertEqual(log.dumps(parsed), raw)
        self.assertEqual(
            log.decode_time(parsed.records[0]),
            log.LogTime(0xFFFFFFFE, (2026, 10, 20, 12, 34, 56, 789)),
        )
        events = list(log.replay(parsed))
        self.assertEqual(events[1]["elapsed_ms"], 5)
        self.assertIsNone(events[2]["tick"])
        self.assertEqual(events[2]["payload"], b"\x00\xff\x7f")

    def test_all_truncations_and_lengths(self):
        raw = log.dumps(
            log.CommunicationLogFile(1, 0, (log.LogTime(12, (0,) * 7).record(),))
        )
        for end in range(len(raw)):
            if end == 8:  # Structurally valid empty native container.
                continue
            with self.subTest(end=end), self.assertRaises(log.LogError):
                log.parse(raw[:end])
        for size in (0, 1, 0xFFFFFFFF):
            with self.subTest(size=size), self.assertRaises(log.LogError):
                log.parse(raw[:8] + struct.pack("<I", size) + raw[12:])
        for offset in (0, 4):
            changed = bytearray(raw)
            changed[offset] ^= 0x40
            with self.assertRaises(log.LogError):
                log.parse(bytes(changed))
        with self.assertRaises(log.LogError):
            log.parse(raw + b"\x00")
        with self.assertRaises(log.LogError):
            log.parse(bytearray(raw))  # type: ignore[arg-type]
        with self.assertRaises(log.LogError):
            log.parse(b"x" * (log.MAX_BYTES + 1))

    def test_native_unknown_revision_and_duplicate_order_preserved(self):
        records = (log.LogRecord(9, b"a"), log.LogRecord(9, b"b"))
        value = log.CommunicationLogFile(1, 0xABCD, records)
        self.assertEqual(log.parse(log.dumps(value)), value)
        self.assertEqual(value.to_dict()["revision"], 0xABCD)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authored.bin"
            path.write_bytes(log.dumps(value))
            self.assertEqual(log.load(path), value)

    def test_known_time_wrong_shape_rejected(self):
        for size in (0, 17, 19):
            with self.subTest(size=size), self.assertRaises(log.LogError):
                log.CommunicationLogFile(1, 0, (log.LogRecord(0x8000, bytes(size)),))
        for value in (-1, 1 << 32, True):
            with self.assertRaises(log.LogError):
                log.LogTime(value, (0,) * 7)
        with self.assertRaises(log.LogError):
            log.LogTime(0, (0,) * 8)
        with self.assertRaises(log.LogError):
            log.LogTime(0, (65536,) * 7)
        with self.assertRaises(log.LogError):
            list(
                log.replay(log.CommunicationLogFile(1, 0, (log.LogRecord(0x103, b""),)))
            )

    def test_clear_end_and_update_preserve_raw_systemtime_and_call_order(self):
        order = []
        ticks = iter((7, 8, 9))
        calendars = iter(
            (
                (2026, 10, 2, 20, 1, 2, 3, 4),
                (2026, 10, 5, 21, 2, 3, 4, 5),
                (2026, 10, 6, 22, 3, 4, 5, 6),
            )
        )

        def tick():
            order.append("tick")
            return next(ticks)

        def calendar():
            order.append("calendar")
            return next(calendars)

        queue = log.CommunicationLog(ticks=tick, local_time=calendar)
        queue.put_log(log.LogMessage(1, 4, b"old"))
        queue.clear()
        self.assertEqual(order, ["tick", "tick", "calendar", "calendar"])
        self.assertEqual(queue.get_log(), ())
        native = queue.get_log_time()
        self.assertEqual(len(native), 40)
        self.assertEqual(
            struct.unpack("<II16H", native),
            (7, 8, 2026, 10, 2, 20, 1, 2, 3, 4, 2026, 10, 5, 21, 2, 3, 4, 5),
        )
        message = log.LogMessage(1, 4, b"first", b"second", 30, 40, 50)
        queue.put_log(message)
        queue.update_log(0xFFFFFFFF, log.LogMessage(2, 4))
        self.assertEqual(queue.get_log(), (message,))
        replacement = log.LogMessage(2, 4, b"new", field30=0xFFFFFFFF)
        queue.update_log(0, replacement)
        self.assertEqual(queue.get_log(), (replacement,))
        queue.set_end_log_time()
        self.assertEqual(queue.end_tick, 9)
        exported = queue.export()
        self.assertEqual(
            log.decode_time(exported.records[0]),
            log.LogTime(7, (2026, 10, 22, 3, 4, 5, 6)),
        )
        self.assertEqual(
            log.decode_time(exported.records[1]),
            log.LogTime(9, (2026, 10, 21, 2, 3, 4, 5)),
        )
        self.assertEqual(log.parse(log.dumps(exported)), exported)

    def test_queue_and_file_memory_caps_atomic_replacement(self):
        queue = log.CommunicationLog()
        message = log.LogMessage(1, 4, b"1234")
        queue.put_log(message)
        with patch.object(log, "MAX_BYTES", 37):
            with self.assertRaises(log.LogError):
                queue.put_log(message)
            with self.assertRaises(log.LogError):
                queue.update_log(0, log.LogMessage(1, 4, b"x" * 10))
            self.assertEqual(queue.get_log(), (message,))
            queue.update_log(0, log.LogMessage(1, 4))
        with patch.object(log, "MAX_BYTES", 10), self.assertRaises(log.LogError):
            log.CommunicationLogFile(1, 0, (log.LogRecord(1, b""),))
        for index in (-1, True, 1 << 32):
            with self.assertRaises(log.LogError):
                queue.update_log(index, message)
        for args in ((1, 256), (True, 4)):
            with self.assertRaises(log.LogError):
                log.LogMessage(*args)

    def test_native_protocol4_and_status_record_vectors(self):
        value = log.LogMessage(1, 4, b"\x22\x01", b"\xaa", 17, 23, 99)
        self.assertEqual(
            log.encode_message(value),
            (log.LogRecord(0x103, b"\x17\0\0\0\x22\x01\xaa"),),
        )
        event = log.LogMessage(3, 6, b"ignored", b"\xcc\xdd\xee", 17, 23, 99)
        self.assertEqual(
            log.encode_message(event),
            (log.LogRecord(0x1105, struct.pack("<II", 23, 17) + b"\xcc\xdd"),),
        )
        with self.assertRaises(log.LogError):
            log.encode_message(log.LogMessage(3, 4, second=b"x"))
        with self.assertRaises(log.LogError):
            log.encode_message(log.LogMessage(4, 4))
        with self.assertRaises(log.LogError):
            log.encode_message(log.LogMessage(1, 1))

    def test_can_single_and_long_native_pci_padding_tick_reset(self):
        header = b"\x00\x00\x07\xe0\x08"
        short = log.encode_message(
            log.LogMessage(2, 11, header, b"\xaa\xbb", field2c=123)
        )
        self.assertEqual(
            short,
            (
                log.LogRecord(
                    0x205, struct.pack("<I", 123) + header + b"\xaa\xbb" + bytes(5)
                ),
            ),
        )
        long = log.encode_message(
            log.LogMessage(1, 6, header, bytes(range(16)), field2c=123)
        )
        self.assertEqual(len(long), 3)
        self.assertEqual(
            long[0].payload,
            struct.pack("<I", 123) + header[:4] + b"\x10\x08" + bytes(range(6)),
        )
        self.assertEqual(
            long[1].payload, bytes(4) + header[:4] + b"\x21" + bytes(range(6, 13))
        )
        self.assertEqual(
            long[2].payload,
            bytes(4) + header[:4] + b"\x22" + bytes(range(13, 16)) + bytes(4),
        )
        with self.assertRaises(log.LogError):
            log.encode_message(log.LogMessage(1, 6, b"bad", bytes(8)))
        with patch.object(log, "MAX_BYTES", 30), self.assertRaises(log.LogError):
            log.encode_message(log.LogMessage(1, 6, header, bytes(range(16))))

    def test_can_native_u16_sequence_wrap(self):
        header = b"abcd\x08"
        records = log.encode_message(
            log.LogMessage(1, 6, header, bytes(7 * 65536 + 10), field2c=99)
        )
        self.assertEqual(records[65535].payload[8], 0x2F)
        self.assertEqual(records[65536].payload[:4], bytes(4))
        self.assertEqual(records[65536].payload[8:10], b"\x10\x08")

    def test_export_rejects_before_expanding_remaining_messages(self):
        queue = log.CommunicationLog()
        message = log.LogMessage(1, 6, b"12345", b"x" * 100)
        for _ in range(5):
            queue.put_log(message)
        original = queue.get_log()
        with (
            patch.object(log, "MAX_BYTES", 1000),
            patch.object(log, "encode_message", wraps=log.encode_message) as encode,
        ):
            with self.assertRaises(log.LogError):
                queue.export()
            self.assertEqual(encode.call_count, 3)
        self.assertEqual(queue.get_log(), original)
        # Even the rejected message must not allocate a partial record list.
        for budgets in ({"max_bytes": 329}, {"max_records": 14}):
            with patch.object(log, "LogRecord") as record:
                with self.assertRaises(log.LogError):
                    log.encode_message(message, **budgets)
                record.assert_not_called()
        with (
            patch.object(snapshot, "MAX_TABLES", 20),
            patch.object(log, "encode_message", wraps=log.encode_message) as encode,
        ):
            with self.assertRaises(log.LogError):
                queue.export()
            self.assertEqual(encode.call_count, 2)
        self.assertEqual(queue.get_log(), original)

    def test_dlog_is_dm_not_communication_or_vlg(self):
        native_dm = snapshot.TableFile(
            snapshot.DM_MAGIC, 1, 0, (snapshot.Table(0x8101, b"opaque"),)
        )
        raw = snapshot.dumps(native_dm)
        self.assertEqual(log.parse_dlog(raw), native_dm)
        self.assertEqual(snapshot.dumps(log.parse_dlog(raw)), raw)
        for raw in (
            log.dumps(log.CommunicationLogFile(1, 0, ())),
            snapshot.dumps(snapshot.TableFile(snapshot.DRS_MAGIC, 1, 0, ())),
        ):
            with self.assertRaises(log.LogError):
                log.parse_dlog(raw)


if __name__ == "__main__":
    unittest.main()
