"""Authored scalar vectors derived from legacy-12 dispatch and x86 operations."""

import unittest
from dataclasses import replace

from scripts.legacy_scalar import LegacyScalarError, convert_legacy_scalar
from scripts.tse_conversion import LegacyConversionTable, LegacyDisplayInfo


def table(**changes: object) -> LegacyConversionTable:
    base = LegacyConversionTable(
        (1, 0), (1, 1, 0), (1, 0), (), (100, 10, 0, 0), 0, 0, 8, b""
    )
    return replace(base, **changes)


def display(key: int, text: bytes | None) -> LegacyDisplayInfo:
    return LegacyDisplayInfo((2, 0), 2, key, text, (0, 0), 0, b"")


def convert(
    selector: int,
    raw: int,
    conversion: LegacyConversionTable | None = None,
    precision: int = 0,
    override: int = 0,
) -> bytes | None:
    return convert_legacy_scalar(
        selector, raw, conversion or table(), precision, override, codepage="cp1252"
    )


class LegacyScalarTests(unittest.TestCase):
    def test_all_25_dispatch_entries(self) -> None:
        labels = table(displays=(display(129, b"label"),))
        expected = {
            1: b"label",
            2: b"129",
            3: b"81",
            4: b"\x81",
            5: b"P0081",
            6: b"182",
            7: b"129",
            8: b"129",
            9: b"129",
            10: b"129",
            11: b"129",
            12: b"-TypeErr-",
            13: b"129",
            14: b"-TypeErr-",
            15: b"-TypeErr-",
            16: b"-TypeErr-",
            17: b"-TypeErr-",
            18: b"-TypeErr-",
            19: b"02:09",
            20: b"label",
            21: b"129",
            22: b"label",
            23: b"129",
            24: b"64",
            25: b"-1",
        }
        for selector, wanted in expected.items():
            with self.subTest(selector=selector):
                self.assertEqual(convert(selector, 129, labels), wanted)
        self.assertEqual(convert(0, 1), b"-TypeErr-")
        self.assertEqual(convert(0x103, 129), b"81")

    def test_sign_modes_and_override(self) -> None:
        signed = table(field_16_raw=1)
        magnitude = table(field_16_raw=3)
        self.assertEqual(convert(2, 255, signed), b"-1")
        self.assertEqual(convert(2, 255, magnitude), b"-127")
        self.assertEqual(convert(2, 255, magnitude, override=1), b"-1")
        self.assertEqual(convert(2, 255, magnitude, override=2), b"-127")
        self.assertEqual(
            convert(2, 0x80000000, table(field_18_raw=0), override=1), b"-2147483648"
        )
        lookup = table(field_16_raw=0, displays=(display(255, b"unsigned"),))
        self.assertEqual(convert(1, 255, lookup, override=1), b"unsigned")

    def test_integer_scaling_and_wrap(self) -> None:
        self.assertEqual(
            convert(2, 5, table(coefficients_raw=(0xFFFFFFFF, 2, 0))), b"-2"
        )
        self.assertEqual(
            convert(2, 5, table(coefficients_raw=(1, 0xFFFFFFFF, 0))), b"-5"
        )
        self.assertEqual(
            convert(2, 0xFFFFFFFF, table(coefficients_raw=(1, 1, 1))), b"0"
        )
        self.assertEqual(
            convert(2, 0xFFFFFFFF, table(coefficients_raw=(2, 2, 0))), b"-1"
        )
        self.assertEqual(convert(2, 5, table(coefficients_raw=(1, 0, 0))), b"5")

    def test_precision_keeps_crt_space_and_low_word(self) -> None:
        self.assertEqual(convert(2, 1234, precision=2), b" 12.34")
        self.assertEqual(convert(2, 255, table(field_16_raw=1), 2), b"-0.01")
        self.assertEqual(convert(2, 0x80000000, precision=1), b"--214748364.-8")
        # The legacy ftol ABI uses EAX, so precision nine is NOT /1_000_000_000.
        self.assertEqual(convert(2, 141006541, precision=9), b" 1.000000001")
        self.assertEqual(convert(2, 121575220, precision=10), b" 1.0000000001")
        self.assertEqual(convert(2, 148661863, precision=17), b" -1.00000000000000001")
        self.assertEqual(convert(2, 42, precision=18), b" 42.000000000000000000")
        self.assertEqual(len(convert(2, 0, precision=252) or b""), 255)
        with self.assertRaises(LegacyScalarError):
            convert(2, 0, precision=253)

    def test_hex_character_dtc_and_time(self) -> None:
        self.assertEqual(convert(3, 0xAB, precision=4), b"00AB")
        self.assertEqual(convert(4, 0x12340000), b"")
        self.assertEqual(convert(4, 0xFFFF00FF), b"\xff")
        for bits, prefix in enumerate((b"P", b"C", b"B", b"U")):
            self.assertEqual(convert(5, (bits << 14) | 0x1234), prefix + b"1234")
        self.assertEqual(convert(19, 3599), b"59:59")
        self.assertEqual(convert(19, 0xFFFFFFFF), b"16777215:59")

    def test_bit_reversal_signed_and_idiv(self) -> None:
        self.assertEqual(convert(7, 0x4080), b"-1")
        self.assertEqual(convert(8, 0x1080), b"-1")
        self.assertEqual(convert(9, 0x4000), b"512")
        self.assertEqual(convert(10, 1), b"128")
        self.assertEqual(convert(11, 0x0100), b"32768")
        self.assertEqual(
            convert(10, 0x80, table(coefficients_raw=(0xFFFFFFFB, 2, 0))), b"-2"
        )
        with self.assertRaises(LegacyScalarError):
            convert(10, 0x80, table(coefficients_raw=(0x80000000, 0xFFFFFFFF, 0)))

    def test_lookup_null_empty_duplicate_and_nul(self) -> None:
        for labels in ((), (display(1, None),), (display(1, b""),)):
            self.assertEqual(convert(1, 1, table(displays=labels)), b"-No Data-")
        labels = (display(1, b"\x81\0tail"), display(1, b"later"))
        self.assertEqual(convert(20, 1, table(displays=labels)), b"\x81")
        with self.assertRaises(LegacyScalarError):
            convert(1, 1, table(displays=(display(1, b"x" * 256),)))

    def test_range_labels_and_numeric_gap(self) -> None:
        labels = table(displays=(display(0, b"low"), display(1, b"high")))
        self.assertEqual(convert(13, 10, labels), b"low")
        self.assertEqual(convert(13, 100, labels), b"high")
        self.assertEqual(convert(13, 11, labels), b"11")
        self.assertEqual(convert(13, 10, table(displays=(display(0, b""),))), b"")
        with self.assertRaises(LegacyScalarError):
            convert(13, 10, table(displays=(display(0, None),)))
        signed = replace(labels, field_16_raw=1, fields_30_3c_raw=(100, 0xFE, 0, 0))
        self.assertEqual(convert(13, 0xFD, signed), b"low")
        self.assertEqual(convert(13, 0xFF, signed), b"-1")
        self.assertEqual(convert(24, 3000), b"1500")
        self.assertEqual(convert(24, 3001), b"1508")
        self.assertEqual(convert(25, 1, table(coefficients_raw=(1, 1, 100))), b"1")
        self.assertEqual(convert(25, 129, table(coefficients_raw=(1, 1, 100))), b"99")

    def test_explicit_decimal_context(self) -> None:
        def numeric(decimal: bytes) -> bytes | None:
            return convert_legacy_scalar(
                2, 1234, table(), 2, 0, codepage="cp932", decimal_point=decimal
            )

        self.assertEqual(numeric(b","), b" 12,34")
        self.assertEqual(numeric(b"\x81"), b" 12\x8134")
        self.assertEqual(numeric(b"\0"), b" 12")
        self.assertEqual(numeric(b"%"), b" 12%02d")
        for invalid in (b"", b"..", "٫".encode()):
            with self.assertRaises(LegacyScalarError):
                numeric(invalid)

    def test_abi_rejects_invalid_inputs(self) -> None:
        for selector, raw, precision, override in (
            (-1, 0, 0, 0),
            (1, -1, 0, 0),
            (2, 0, 256, 0),
            (2, 0, 0, 256),
        ):
            with self.assertRaises(LegacyScalarError):
                convert(selector, raw, precision=precision, override=override)
        with self.assertRaises(LegacyScalarError):
            convert_legacy_scalar(2, 0, table(), 0, 0, codepage="unavailable-acp")


if __name__ == "__main__":
    unittest.main()
