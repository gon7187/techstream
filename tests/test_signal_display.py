import struct
import unittest
from typing import Any

from scripts.signal_display import render_signal


def render(raw, selector=2, **kwargs):
    fields: dict[str, Any] = {
        "selector": selector,
        "sign_mode": 0,
        "bits": 8,
        "multiplier": 1,
        "divisor": 1,
        "offset": 0,
        "precision": 0,
    }
    fields.update(kwargs)
    return render_signal(raw, **fields)


class SignalDisplayTests(unittest.TestCase):
    def test_numeric_and_symbolic_are_separate(self):
        self.assertEqual(render(1234, precision=2)["display"], " 12.34")
        self.assertEqual(
            render(2, 1, multiplier=2, patterns=((4, "Ready", 0, 0),))["display"],
            "Ready",
        )
        self.assertIsNone(render(2, 1)["value"])
        self.assertEqual(render(2, 1)["status"], "unresolved")
        self.assertEqual(render(2, 0)["display"], "-TypeErr-")
        self.assertIsNone(render(2, 0)["value"])

    def test_hex_character_dtc_and_time(self):
        self.assertEqual(render(0xAB, 3, precision=4)["display"], "00AB")
        self.assertEqual(render(65, 4)["display"], "A")
        self.assertEqual(render(0xC123, 5)["display"], "U0123")
        self.assertEqual(render(125, 19)["display"], "2:05")

    def test_threshold_labels_and_numeric_fallback(self):
        fields = {
            "minimum_raw": 10,
            "maximum_raw": 5,
            "patterns": ((0, "Low", 0, 0), (1, "High", 0, 0)),
        }
        self.assertEqual(render(5, 13, **fields)["display"], "Low")
        self.assertEqual(render(10, 13, **fields)["display"], "High")
        self.assertEqual(render(7, 13, **fields)["display"], "7")
        self.assertEqual(
            render(
                0xFF,
                13,
                sign_mode=1,
                minimum_raw=3,
                maximum_raw=0,
                patterns=((0, "negative", 0, 0),),
            )["display"],
            "negative",
        )
        self.assertEqual(render(4000, 24, **fields)["value"], 9500)

    def test_extended_numeric_dispatch(self):
        self.assertEqual(render(5, 21)["value"], 5)
        self.assertEqual(render(5, 26)["value"], -5)
        self.assertEqual(render(5, 25, offset=100)["value"], 5)
        self.assertEqual(render(0xFF, 25, offset=100)["value"], -27)
        self.assertEqual(render(5, 34)["value"], 5)

    def test_float_bit_patterns_and_native_invalid_ranges(self):
        word = struct.unpack("<I", struct.pack("<f", 1.25))[0]
        self.assertEqual(render(word, 28, precision=2)["display"], "1.25")
        for raw in (0x4F000000, 0x7FC00000, 0xCF000001, 0xFFFFFFFF):
            self.assertEqual(render(raw, 28)["status"], "unavailable")
            self.assertIsNone(render(raw, 28)["value"])
        low, high = struct.unpack("<II", struct.pack("<d", 1.25))
        self.assertEqual(
            render(0, 29, raw_words=(low, high), precision=2)["display"], "1.25"
        )
        self.assertEqual(render(0, 29)["status"], "unresolved")
        self.assertEqual(
            render(0, 29, raw_words=(1, 0xC1E00000))["status"], "unavailable"
        )

    def test_pattern_order_bounds_and_no_invented_sentinel(self):
        self.assertEqual(
            render(1, 1, patterns=((1, "first", 0, 0), (1, "second", 0, 0)))["display"],
            "first",
        )
        self.assertEqual(render(255)["value"], 255)
        self.assertEqual(
            render(0x80000000, bits=32, sign_mode=1)["display"], "-2147483648"
        )
        self.assertEqual(
            render(0x80000000, bits=32, sign_mode=1, precision=2)["display"],
            "--21474836.-48",
        )
        self.assertEqual(render(1000000000, precision=9)["display"], " 7.012954220")
        for kwargs in (
            {"raw": -1},
            {"raw": True},
            {"raw": 1, "bits": 0},
            {"raw": 1, "precision": 256},
            {"raw": 1, "patterns": ((1, "x", -1, 0),)},
        ):
            with self.assertRaises(ValueError):
                render(**kwargs)


if __name__ == "__main__":
    unittest.main()
