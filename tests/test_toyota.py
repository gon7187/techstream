"""Synthetic native consumer checks: no proprietary files or vehicle required."""

import struct
import unittest

from scripts.toyota import (
    INVALID_ARGUMENT,
    INVALID_RECORD,
    INVALID_REPLY,
    SHORT_REPLY,
    CommandFrame,
    ToyotaCodecError,
    VariableTable,
    data_list_request,
    freeze_payload_p3,
    freeze_request_p3,
    freeze_request_p5,
    mask_comm_error,
    parse_kwp_dtc_reply,
    pid_support_p3,
    vin_payload_can,
)


class ToyotaCodecTests(unittest.TestCase):
    def assert_status(self, expected, function, *args):
        with self.assertRaises(ToyotaCodecError) as caught:
            function(*args)
        self.assertEqual(caught.exception.code, expected)

    def test_variable_directory_and_native_frame_references(self):
        # One-based references; offsets relative to bytes after all directory rows.
        variables = VariableTable(
            struct.pack("<IHIHIH", 0, 3, 3, 2, 5, 2) + b"\x21\xaa\xbb\xff\xf0\x61\xa0",
            3,
        )
        frame = CommandFrame.from_record(struct.pack("<HHHH", 123, 1, 2, 3), variables)
        self.assertEqual(frame.request, b"\x21\xaa\xbb")
        self.assertEqual(frame.check_mask(b"\x61\xaf"), b"\x61\xaf")
        self.assertEqual(variables.get(0), b"")
        with self.assertRaises(ValueError):
            variables.get(4)
        self.assert_status(INVALID_RECORD, CommandFrame.from_record, b"123", variables)

    def test_variable_bounds_and_empty_reference(self):
        with self.assertRaises(ValueError):
            VariableTable(b"12345", 1)
        with self.assertRaises(ValueError):
            VariableTable(struct.pack("<IH", 2, 2) + b"abc", 1)
        self.assertEqual(
            VariableTable(struct.pack("<IH", 0xFFFFFFFF, 0), 1).get(1), b""
        )
        with self.assertRaises(ValueError):
            VariableTable(b"", -1)
        with self.assertRaises(ValueError):
            VariableTable(b"", 0).get(True)

    def test_database_check_is_not_masked_again(self):
        frame = CommandFrame(b"\x21", b"\xf0", b"\x61")
        self.assert_status(INVALID_REPLY, frame.check_mask, b"\x61")
        self.assert_status(
            SHORT_REPLY, CommandFrame(b"\x21", b"\xff", b"").check_mask, b"\x61"
        )
        frame = CommandFrame(b"\x21", b"\xff", b"\x61\x00")
        self.assertEqual(frame.check_mask(b"\x61"), b"\x61")
        self.assert_status(SHORT_REPLY, CommandFrame(b"\x21").check_reply, b"")
        self.assert_status(
            INVALID_REPLY, CommandFrame(b"\x21").check_reply, b"\x7f\x21\x78"
        )

    def test_kwp_codes_use_big_endian_and_terminate_at_zero(self):
        chunk = parse_kwp_dtc_reply(b"\x18", bytes.fromhex("58 12 34 ab cd 00 00"))
        self.assertEqual(chunk.codes, (0x1234, 0xABCD))
        self.assertTrue(chunk.zero_terminated)
        self.assertFalse(chunk.needs_more)
        self.assertEqual(chunk.ignored_tail, b"")
        chunk = parse_kwp_dtc_reply(b"\x18", bytes.fromhex("58 12 34"))
        self.assertEqual(chunk.codes, (0x1234,))
        self.assertFalse(chunk.needs_more)

    def test_kwp_continuation_and_odd_tail_follow_native_floor(self):
        chunk = parse_kwp_dtc_reply(b"\x18", bytes.fromhex("58 12 34 ab cd 56 78 ff"))
        self.assertEqual(chunk.codes, (0x1234, 0xABCD, 0x5678))
        self.assertTrue(chunk.needs_more)
        self.assertEqual(chunk.ignored_tail, b"\xff")
        self.assert_status(SHORT_REPLY, parse_kwp_dtc_reply, b"\x18", b"\x58")
        self.assert_status(SHORT_REPLY, parse_kwp_dtc_reply, b"\x18", b"\x58" * 9)
        self.assert_status(INVALID_REPLY, parse_kwp_dtc_reply, b"\x18", b"\x59\x00\x00")

    def test_communication_error_mask_exact_bits(self):
        for error, bit in ((0x91010009, 1), (0x90020321, 2), (0x90020323, 4)):
            self.assertEqual(mask_comm_error(error, bit), 0)
            self.assertEqual(mask_comm_error(error, 0), error)
        self.assertEqual(mask_comm_error(INVALID_REPLY, 0xFFFF), INVALID_REPLY)
        with self.assertRaises(ValueError):
            mask_comm_error(-1, 0)

    def test_freeze_templates_preserve_database_service_and_tail(self):
        row = bytearray(84)
        row[0x4F] = 0xA2
        self.assertEqual(
            freeze_request_p3(b"\x21\x00\x00\xcc", bytes(row), 7), b"\x21\xa2\x07\xcc"
        )
        self.assertEqual(
            freeze_request_p5(b"\x19\x04\x00\x00\x00\x00\xaa", 0x123456, 3),
            b"\x19\x04\x12\x34\x56\x03\xaa",
        )
        self.assertEqual(
            freeze_request_p5(b"\x19\x04\x00\x00\x00", 0xFFFFFF),
            b"\x19\x04\xff\xff\xff",
        )
        self.assert_status(INVALID_ARGUMENT, freeze_request_p5, b"\x19" * 6, 1, 0)
        self.assert_status(INVALID_RECORD, freeze_request_p5, b"\x19", 1)
        with self.assertRaises(ValueError):
            freeze_request_p5(b"\x19" * 5, 0x1000000)

    def test_freeze_extracts_raw_values_without_guessing_scaling(self):
        frame = CommandFrame(b"\x21\xa2\x07")
        self.assertEqual(freeze_payload_p3(frame, b"\x61\xa2\x07\x12\x34"), b"\x12\x34")
        self.assert_status(SHORT_REPLY, freeze_payload_p3, frame, b"\x61\xa2\x07")

    def test_data_list_request_uses_native_protocol_branch(self):
        self.assertEqual(data_list_request(b"\x21\x00\xaa", 0x87, 3), b"\x21\x87\xaa")
        for protocol in (0x14, 0x15, 0x34):
            self.assertEqual(
                data_list_request(b"\x22\x00\x00\xaa", 0x1234, protocol),
                b"\x22\x12\x34\xaa",
            )
        self.assert_status(INVALID_RECORD, data_list_request, b"\x22\x00", 0x1234, 0x14)
        with self.assertRaises(ValueError):
            data_list_request(b"\x21\x00", 256, 3)

    def test_support_mode_size_boundary_and_unresolved_gate(self):
        row = bytearray(84)
        struct.pack_into("<H", row, 0x40, 8)
        self.assertFalse(pid_support_p3(bytes(row), 1))
        self.assertTrue(pid_support_p3(bytes(row), 2))
        struct.pack_into("<H", row, 0x3A, 17)
        self.assertIsNone(pid_support_p3(bytes(row), 2))
        row[0x4D] = 1
        self.assertTrue(pid_support_p3(bytes(row), 0))
        row[0x4D] = 2
        self.assertFalse(pid_support_p3(bytes(row), 255))
        row[0x4D] = 3
        self.assert_status(0xA0040004, pid_support_p3, bytes(row), 2)

    def test_vin_native_prefix_and_zero_filter(self):
        frame = CommandFrame(b"\x09\x02")
        self.assertEqual(
            vin_payload_can(frame, b"\x49\x02\x01\x00\x00\x00ABC\x00D"), b"ABC\x00D"
        )
        self.assertEqual(vin_payload_can(frame, b"\x49\x02\x01A\x00BC"), b"ABC")
        self.assertEqual(vin_payload_can(frame, b"\x49\x02\x01"), b"")
        self.assert_status(SHORT_REPLY, vin_payload_can, frame, b"\x49\x02")


if __name__ == "__main__":
    unittest.main()
