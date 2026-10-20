import struct
import unittest

from scripts.mongoose_protocol import (
    decode_frames,
    encode_frame,
    inspect_version_response,
    version_queries,
)


class MongooseProtocolTests(unittest.TestCase):
    @staticmethod
    def response(sequence=1, status=0, value=123):
        # Synthetic response from recovered assembly offsets; not a USB capture.
        payload = bytearray(28)
        struct.pack_into("<HHHH", payload, 0, 0, 1, 0x800C, sequence)
        struct.pack_into("<I", payload, 12, status)
        struct.pack_into("<I", payload, 24, value)
        return encode_frame(bytes(payload))

    def test_numeric_version_response_and_error_status(self):
        request = version_queries()[0]
        result = inspect_version_response(request, self.response())
        self.assertEqual(result["value"], 123)
        self.assertEqual(result["status"], 0)
        self.assertEqual(result["response_opcode"], 0x800C)
        payload_with_unknown_opcode = bytearray(decode_frames(self.response())[0])
        struct.pack_into("<H", payload_with_unknown_opcode, 4, 0xFFFF)
        self.assertEqual(
            inspect_version_response(
                request, encode_frame(bytes(payload_with_unknown_opcode))
            )["response_opcode"],
            0xFFFF,
        )
        payload = decode_frames(self.response(status=1))[0][:20]
        result = inspect_version_response(request, encode_frame(payload))
        self.assertEqual(result["status"], 1)
        self.assertNotIn("value", result)

    def test_byte_string_preserves_unknown_encoding(self):
        payload = bytearray(24) + b"\xffABC\0"
        struct.pack_into("<HHHH", payload, 0, 0, 1, 0x8013, 3)
        request = version_queries()[2]
        self.assertEqual(
            inspect_version_response(request, encode_frame(bytes(payload)))[
                "value_hex"
            ],
            "ff414243",
        )
        with self.assertRaisesRegex(ValueError, "NUL"):
            inspect_version_response(request, encode_frame(bytes(payload[:-1])))

    def test_response_requires_correlated_complete_frames_and_bounded_fields(self):
        request = version_queries()[0]
        response = self.response()
        for invalid in (self.response(sequence=2), response[:-1], response + response):
            with self.subTest(frame=invalid.hex()), self.assertRaises(ValueError):
                inspect_version_response(request, invalid)
        payload = bytearray(decode_frames(response)[0])
        for length in range(1, 28):
            with self.subTest(length=length), self.assertRaises(ValueError):
                inspect_version_response(request, encode_frame(bytes(payload[:length])))
        payload[0] = 2
        with self.assertRaisesRegex(ValueError, "correlate"):
            inspect_version_response(request, encode_frame(bytes(payload)))
        for bad in (request + request, encode_frame(b"x" * 16)):
            with self.assertRaises(ValueError):
                inspect_version_response(bad, response)

    def test_version_queries_match_driver_derived_layout(self):
        # Derived from monpm432.dll assembly, not captured or hardware-validated.
        expected = [
            "1000f651010000000c000100000000002b000000",
            "1000f651010000000c000200000000002a000000",
            "1000f65101000000130003000000000000000000",
        ]
        self.assertEqual([frame.hex() for frame in version_queries()], expected)

    def test_concatenated_frames_keep_exact_payloads(self):
        payloads = [b"\x00\xff\x01", bytes(range(256)), b"x" * 0x1800]
        frames = b"".join(encode_frame(payload) for payload in payloads)
        self.assertEqual(decode_frames(frames), payloads)
        self.assertEqual(decode_frames(b""), [])

    def test_rejects_invalid_length_checksum_and_truncation(self):
        frame = version_queries()[0]
        cases = [
            frame[:1],
            frame[:3],
            frame[:-1],
            frame + b"\x00",
            frame[:2] + bytes([frame[2] ^ 1]) + frame[3:],
            bytes.fromhex("0000e651"),
            bytes.fromhex("0118e749"),
        ]
        for data in cases:
            with self.subTest(data=data.hex()), self.assertRaises(ValueError):
                decode_frames(data)
        for payload in (b"", b"x" * 0x1801):
            with self.subTest(size=len(payload)), self.assertRaises(ValueError):
                encode_frame(payload)


if __name__ == "__main__":
    unittest.main()
