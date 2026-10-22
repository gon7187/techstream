import struct
import tempfile
import unittest
from pathlib import Path

from scripts.jlr import (
    MAX_PAYLOAD,
    JLRClient,
    StreamDecoder,
    discover_jlr,
    encode_frame,
    request,
    response,
)
from scripts.mongoose_protocol import MAX_PAYLOAD as TOYOTA_MAX_PAYLOAD
from scripts.mongoose_protocol import decode_frames


class ReplayTransport:
    def __init__(self):
        self.sent = []
        self.pending = []

    def write(self, frame):
        self.sent.append(frame)
        payload = decode_frames(frame)[0]
        target, source, opcode, sequence = struct.unpack_from("<4H", payload)
        header = struct.pack("<6HI", source, target, opcode | 0x8000, sequence, 0, 0, 0)
        reply = (
            header + bytes(8) + struct.pack("<I", 123)
            if opcode == 12
            else header + bytes(4)
        )
        if opcode == 0x100:
            reply = header[:12]
        # One asynchronous event and a split reply must not lose either.
        event = struct.pack("<6H", 0, 0x0501, 9, 0, 0, 0) + bytes(12)
        self.pending += [
            encode_frame(event) + encode_frame(reply)[:7],
            encode_frame(reply)[7:],
        ]

    def read(self, timeout_ms):
        return self.pending.pop(0) if self.pending else b""


class JLRTests(unittest.TestCase):
    def test_large_firmware_frame_has_jlr_scoped_framing(self):
        firmware = bytes(range(256)) * 32
        body = struct.pack("<4I", 2, 1, 108, len(firmware)) + firmware
        wire = request(1, 0x10A, 1, body)
        length, check = struct.unpack_from("<HH", wire)
        self.assertEqual(length, 8192 + 28)
        self.assertEqual(length ^ check, 0x51E6)
        decoder = StreamDecoder()
        decoded = []
        for offset in range(0, len(wire), 127):
            decoded.extend(decoder.feed(wire[offset : offset + 127]))
        self.assertEqual(decoded, [wire[4:]])
        self.assertEqual(decoder.pending, b"")
        self.assertEqual(TOYOTA_MAX_PAYLOAD, 6144)
        with self.assertRaises(ValueError):
            decode_frames(wire)

    def test_jlr_uint16_format_bound_and_pending_buffer(self):
        self.assertEqual(MAX_PAYLOAD, 65535)
        payload = b"x" * MAX_PAYLOAD
        wire = encode_frame(payload)
        self.assertEqual(StreamDecoder().feed(wire), [payload])
        decoder = StreamDecoder()
        self.assertEqual(decoder.feed(wire[:-1]), [])
        self.assertLessEqual(len(decoder.pending), MAX_PAYLOAD + 3)
        self.assertEqual(decoder.feed(wire[-1:]), [payload])
        with self.assertRaises(ValueError):
            encode_frame(bytes(65536))
        with self.assertRaises(ValueError):
            request(1, 3, 1, bytes(65524))
        with self.assertRaises(ValueError):
            StreamDecoder().feed(bytes(65540))

    def test_frame_stream_reassembly_and_resynchronization(self):
        first, second = encode_frame(b"abc"), encode_frame(b"xy")
        for stop in range(len(first)):
            decoder = StreamDecoder()
            self.assertEqual(decoder.feed(first[:stop]), [])
            self.assertEqual(decoder.feed(first[stop:] + second), [b"abc", b"xy"])
        self.assertEqual(StreamDecoder().feed(b"\xff\x00" + first), [b"abc"])

    def test_request_shape_and_strict_response_identity(self):
        frame = request(1, 3, 1)
        self.assertEqual(frame.hex(), "0c00ea51010000000300010000000000")
        reply = struct.pack("<6HII", 0, 1, 0x8003, 1, 0, 0, 0, 0)
        self.assertEqual(response(reply, 1, 3, 1), 0)
        for offset in (0, 2, 4, 6):
            bad = bytearray(reply)
            bad[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                response(bytes(bad), 1, 3, 1)
        with self.assertRaises(ValueError):
            response(reply[:15], 1, 3, 1)
        for seq in (0, 256):
            with self.assertRaises(ValueError):
                request(1, 3, seq)

    def test_transactions_preserve_unsolicited_events_and_sequence_wrap(self):
        transport = ReplayTransport()
        client = JLRClient(transport)
        self.assertEqual(client.get_value(0x2B), 123)
        self.assertEqual(len(client.events), 1)
        self.assertEqual(client.events[0][4:6], b"\x09\0")
        client.sequence = 255
        client.transact(1, 3)
        self.assertEqual(
            struct.unpack_from("<H", decode_frames(transport.sent[-1])[0], 6)[0], 1
        )
        self.assertEqual(len(client.transact(1, 0x100)), 12)

    def test_passive_descriptors_match_jlr_and_dynamic_bulk_endpoints(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            device = root / "1-2"
            device.mkdir()
            for name, text in {
                "idVendor": "18e1",
                "idProduct": "0104",
                "busnum": "1",
                "devnum": "3",
            }.items():
                (device / name).write_text(text)
            for number, endpoints in (
                (0, (("83", "03"),)),
                (1, (("86", "02"), ("04", "02"))),
            ):
                interface = root / f"1-2:1.{number}"
                interface.mkdir()
                (interface / "bInterfaceNumber").write_text(str(number))
                (interface / "bAlternateSetting").write_text("0")
                for endpoint, attributes in endpoints:
                    entry = interface / f"ep_{endpoint}"
                    entry.mkdir()
                    (entry / "bEndpointAddress").write_text(endpoint)
                    (entry / "bmAttributes").write_text(attributes)
            location = discover_jlr(root)[0]
            self.assertEqual(
                (
                    location.bus,
                    location.address,
                    location.input_endpoint,
                    location.output_endpoint,
                ),
                (1, 3, 0x86, 4),
            )
            (device / "idProduct").write_text("0100")
            self.assertEqual(discover_jlr(root), [])


if __name__ == "__main__":
    unittest.main()
