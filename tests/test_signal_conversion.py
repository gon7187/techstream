import struct
import unittest

from scripts.signal_conversion import (
    affine,
    convert,
    extract_bits,
    format_scaled,
    signal_metadata,
)


class SignalConversionTests(unittest.TestCase):
    def test_signedness_division_order_and_x86_wrap(self):
        self.assertEqual(
            [affine(255, 1, 1, 0, 8, mode) for mode in (0, 1, 3)], [255, -1, -127]
        )
        self.assertEqual(affine(3, -1, 2, 7, 8, 0), 6)
        self.assertEqual(affine(7, 2, 0, 1, 8, 0), 15)
        self.assertEqual(affine(7, 2, -2, 1, 8, 0), -6)
        self.assertEqual(affine(0xFFFFFFFF, 2, 1, 0, 32, 0), -2)

    def test_nonlinear_serial_and_packed_selectors(self):
        self.assertEqual(convert(3000, 99, 7, 2, 16, 1, 24), 1500)
        self.assertEqual(convert(3001, 99, 7, 2, 16, 1, 24), 1508)
        self.assertEqual(convert(50, 99, 7, 2, 16, 1, 6), 550)
        self.assertEqual(convert(125, 1, 1, 0, 16, 0, 19), 0x205)
        self.assertEqual(convert(0x80, 1, 1, 0, 8, 0, 11), 1)
        self.assertEqual(convert(0x81, 1, 1, 0, 8, 0, 10), -1)

    def test_bit_ranges_and_display_precision(self):
        self.assertEqual(extract_bits(bytes.fromhex("abcd"), 4, 11), 0xBC)
        self.assertEqual(extract_bits(bytes.fromhex("abcd"), 0, 15, 1), 0xABCC)
        for start, end in ((8, 0), (0, 16), (-1, 4), (1, 32)):
            with self.assertRaises(ValueError):
                extract_bits(b"\0\0", start, end)
        self.assertEqual(format_scaled(-1234, 2), "-12.34")
        self.assertEqual(format_scaled(7, 3), " 0.007")
        with self.assertRaises(ValueError):
            format_scaled(-0x80000000, 2)

    def test_extraction_to_conversion_preserves_unsigned_dword(self):
        raw = extract_bits(bytes.fromhex("ffffffff"), 0, 31)
        self.assertEqual(raw, 0xFFFFFFFF)
        self.assertEqual(convert(raw, 1, 1, 0, 32, 0), -1)
        self.assertEqual(extract_bits(b"\0", 0, 7, 1), 0xFFFFFFFF)

    def test_real_field_offsets_and_key_mismatch(self):
        freeze, physical = bytearray(84), bytearray(24)
        struct.pack_into("<HHH", freeze, 60, 42, 0, 15)
        freeze[76] = 2
        struct.pack_into("<iiiHH", physical, 0, 25, 2, -100, 42, 9)
        physical[20:22] = bytes([1, 2])
        metadata = signal_metadata(bytes(freeze), bytes(physical))
        self.assertEqual(
            (metadata["decimal_precision"], metadata["selector"], metadata["unit_key"]),
            (2, 2, 9),
        )
        physical[12] = 43
        with self.assertRaises(ValueError):
            signal_metadata(bytes(freeze), bytes(physical))


if __name__ == "__main__":
    unittest.main()
