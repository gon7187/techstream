"""Authored format vectors; no Toyota artifacts or code are required."""

import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import cuw_modules as m
from scripts.cuw_modules import (
    ModuleProvider,
    _import_string,
    _Recovery,
    decode_aes_cbc,
    decode_byte_program,
    decode_bytes,
    decode_header,
    decode_huffman,
    decode_words,
    recover_module,
)


def inverse_schedule(key: bytes) -> bytes:
    # FIPS-197 forward expansion, independently expressed in byte arrays.
    def multiply(a, b):
        answer = 0
        while b:
            if b & 1:
                answer ^= a
            a = (a << 1) ^ (0x11B if a & 128 else 0)
            b >>= 1
        return answer

    def sbox(value):
        inverse = (
            0
            if not value
            else next(n for n in range(1, 256) if multiply(value, n) == 1)
        )
        bits = [(inverse >> n) & 1 for n in range(8)]
        return sum(
            (
                bits[n]
                ^ bits[(n - 4) % 8]
                ^ bits[(n - 1) % 8]
                ^ bits[(n - 2) % 8]
                ^ bits[(n - 3) % 8]
                ^ ((99 >> n) & 1)
            )
            << n
            for n in range(8)
        )

    rounds = len(key) // 4 + 6
    words = [list(key[n : n + 4]) for n in range(0, len(key), 4)]
    stride, rcon = len(words), 1
    while len(words) < 4 * (rounds + 1):
        word = words[-1][:]
        if len(words) % stride == 0:
            word = [sbox(x) for x in word[1:] + word[:1]]
            word[0] ^= rcon
            rcon = multiply(rcon, 2)
        elif stride > 6 and len(words) % stride == 4:
            word = [sbox(x) for x in word]
        words.append([a ^ b for a, b in zip(word, words[-stride], strict=True)])
    result = []
    for row in range(rounds, -1, -1):
        for word in words[row * 4 : row * 4 + 4]:
            if row not in (0, rounds):
                word = [
                    multiply(word[i], 14)
                    ^ multiply(word[(i + 1) % 4], 11)
                    ^ multiply(word[(i + 2) % 4], 13)
                    ^ multiply(word[(i + 3) % 4], 9)
                    for i in range(4)
                ]
            result.append(int.from_bytes(bytes(word), "big"))
    return struct.pack("<HH", len(key) * 8, rounds) + struct.pack(
        "<" + "I" * len(result), *result
    )


class ModuleTests(unittest.TestCase):
    def test_nist_aes_vectors_and_native_partial_tail(self):
        plain = bytes.fromhex("00112233445566778899aabbccddeeff")
        for key, cipher in [
            ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
            (
                "000102030405060708090a0b0c0d0e0f1011121314151617",
                "dda97ca4864cdfe06eaf70a0ec0d7191",
            ),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "8ea2b7ca516745bfeafc49904b496089",
            ),
        ]:
            with self.subTest(key_bits=len(key) * 4):
                schedule = inverse_schedule(bytes.fromhex(key))
                self.assertEqual(
                    decode_aes_cbc(bytes.fromhex(cipher) + b"tail", schedule),
                    plain + b"tail",
                )

    def test_cbc_chain(self):
        # NIST SP800-38A CBC vector with the first cipher block used as the IV.
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        cipher = bytes.fromhex(
            "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
        )
        expected_second = bytes.fromhex("ae2d8a571e03ac9c9eb76fac45af8e51")
        self.assertEqual(
            decode_aes_cbc(cipher, inverse_schedule(key))[16:], expected_second
        )

    def test_header_independent_encoder(self):
        values = [0x12345678, int.from_bytes(b"KONN", "little"), 17, 32, 128, 64, 64, 0]
        encoded, key = [values[0]], values[0]
        for index, value in enumerate(values[1:]):
            cipher = value ^ key
            encoded.append(cipher)
            key = ((cipher - index + key) ^ index**2) & 0xFFFFFFFF
        self.assertEqual(decode_header(struct.pack("<8I", *encoded)), tuple(values))
        for malformed in (b"", bytes(31), bytes(32)):
            with self.assertRaises(ValueError):
                decode_header(malformed)

    def test_word_known_vectors_and_tail(self):
        self.assertEqual(
            decode_words(bytes.fromhex("3322110066554433aabb"), 0x11223344).hex(),
            "0a1133110a007722aabb",
        )
        self.assertEqual(
            decode_words(bytes(8), 1, rotate=11), bytes.fromhex("00080000ff070000")
        )
        self.assertEqual(decode_words(b"abc", 0, rotate=13), b"abc")
        for seed in (-1, 1 << 32, True):
            with self.assertRaises(ValueError):
                decode_words(b"", seed)
        with self.assertRaises(ValueError):
            decode_words(b"", 0, rotate=12)

    def test_byte_roundtrip_with_independent_inverse(self):
        for rotation in (2, 3):
            original = bytes(range(256))
            rva = 0x123456
            seed = ((rva >> 8) + rva) & 255 if rotation == 3 else rva & 255
            encoded = bytearray()
            for index, value in enumerate(original):
                key = (seed + index) & 255
                for xor in (key, (key + 1) & 255, None):
                    value = ((value >> rotation) | (value << (8 - rotation))) & 255
                    if xor is not None:
                        value ^= xor
                encoded.append(value)
            self.assertEqual(
                decode_bytes(bytes(encoded), rva, rotate=rotation), original
            )

    def test_huffman_literals_and_input_bounds(self):
        table = b"".join(struct.pack("<HB", 0x8000 | index, 8) for index in range(256))
        self.assertEqual(decode_huffman(table, b"hello", 5), b"hello")
        self.assertEqual(decode_huffman(table, b"", 0), b"")
        for data, length in ((b"hello!", 5), (b"hi", 3)):
            with self.assertRaises(ValueError):
                decode_huffman(table, data, length)
        bad = bytearray(table)
        struct.pack_into("<HB", bad, ord("x") * 3, 0x8201, 8)
        with self.assertRaises(ValueError):
            decode_huffman(bytes(bad), b"x", 1)

    def test_huffman_control_tokens(self):
        table = bytearray(
            b"".join(struct.pack("<HB", 0x8000 | index, 8) for index in range(256))
        )
        for token, word in (
            (240, 0x8102),
            (241, 0x8201),
            (242, 0x8202),
            (243, 0x8301),
            (244, 0x8204),
        ):
            struct.pack_into("<HB", table, token * 3, word, 8)
        table = bytes(table)
        self.assertEqual(decode_huffman(table, b"ab" + bytes([240, 242]), 6), b"ababab")
        self.assertEqual(
            decode_huffman(table, b"ab" + bytes([240, ord("c"), 243]), 4), b"abca"
        )
        self.assertEqual(
            decode_huffman(table, b"abcd" + bytes([240, 244]), 12), b"abcdabcdabcd"
        )
        with self.assertRaises(ValueError):
            decode_huffman(table, b"ab" + bytes([240, 242]), 5)
        with self.assertRaises(ValueError):
            decode_huffman(table, bytes([243]), 1)

    def test_huffman_extended_tree_uses_little_endian_bits(self):
        table = bytearray(258 * 3)
        for index in range(256):
            struct.pack_into("<HB", table, index * 3, 0x8000 | index, 8)
        struct.pack_into("<HB", table, 0, 256, 8)
        struct.pack_into("<HB", table, 256 * 3, 0x8041, 9)
        struct.pack_into("<HB", table, 257 * 3, 0x8042, 9)
        self.assertEqual(decode_huffman(bytes(table), b"\0\0", 1), b"A")
        self.assertEqual(decode_huffman(bytes(table), b"\0\1", 1), b"B")
        with self.assertRaises(ValueError):
            decode_huffman(bytes(table), b"\0", 1)
        struct.pack_into("<HB", table, 256 * 3, 256, 8)
        with self.assertRaises(ValueError):
            decode_huffman(bytes(table), bytes(8), 1)

    def test_arithmetic_byte_program_is_not_native_execution(self):
        program = bytes.fromhex("90fec00403c0c8013407c3")
        source = bytes(range(256))
        expected = bytes(
            (((((value + 4) & 255) >> 1) | (((value + 4) & 255) << 7)) & 255) ^ 7
            for value in source
        )
        self.assertEqual(decode_byte_program(program, source), expected)
        for program in (
            b"",
            b"\xc3\xc3",
            b"\x90",
            b"\x8b\x00\xc3",
            b"\xe8\x00\x00\x00\x00\xc3",
            b"\xc0\x08\x01\xc3",
        ):
            with self.assertRaises(ValueError):
                decode_byte_program(program, b"abc")
        with self.assertRaises(InterruptedError):
            decode_byte_program(b"\xc3", b"", cancel=lambda: True)

    def test_cancellation_and_provider_boundary(self):
        for operation in (
            lambda: decode_words(bytes(32), 1, cancel=lambda: True),
            lambda: decode_bytes(b"", 0, cancel=lambda: True),
            lambda: decode_aes_cbc(
                b"", inverse_schedule(bytes(16)), cancel=lambda: True
            ),
        ):
            with self.assertRaises(InterruptedError):
                operation()
        provider = ModuleProvider(".")
        for name in ("", ".", "..", "../CUW.dll", "sub\\CUW.dll", "\0"):
            with self.assertRaises(ValueError):
                provider.inspect(name)
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "fifo.dll"
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                ModuleProvider(directory).inspect("fifo.dll")

    def test_recovery_rejects_malformed_regular_files_and_fifo(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "own.dll"
            path.write_bytes(b"not a PE")
            Path(str(path) + "._").write_bytes(bytes(128))
            with self.assertRaises(ValueError):
                recover_module(path)
            with self.assertRaises(InterruptedError):
                recover_module(path, cancel=lambda: True)
            fifo = Path(directory) / "fifo.dll"
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                ModuleProvider(directory).recover("fifo.dll")
            for name in ("../own.dll", "sub/own.dll", "", ".."):
                with self.assertRaises(ValueError):
                    ModuleProvider(directory).recover(name)

    def test_import_string_independent_authored_vector_and_bound(self):
        recovery = object.__new__(_Recovery)
        recovery.cancel = None
        # Independent encoding of an authored name. Native seed increments by 67.
        name, seed = b"example.dll", 23
        encoded = bytearray()
        for value in name:
            value = (value + seed) & 255
            encoded.append(((value << 4) | (value >> 4)) & 255)
            seed = (seed + 67) & 255
        recovery.image = encoded + bytes(1)
        self.assertEqual(_import_string(recovery, 0, 23), "example.dll")
        self.assertEqual(recovery.image, name + bytes(1))
        recovery.image = bytearray([1])
        with self.assertRaises(ValueError):
            _import_string(recovery, 0, 0)


class EngineMutations(unittest.TestCase):
    def fixture(self, descriptors=0, thunks=0):
        r = m._Recovery.__new__(m._Recovery)
        r.image = bytearray(0x40000)
        r.cancel = None
        r.original = b""
        r.sections = []
        r.optional = 0x100
        r.threshold = 0x40000
        r.aes_schedules = [b"", b""]
        r.huffman_tables = [b"", b""]
        r.companion = bytes(0x80) + bytes.fromhex("ffffffff")

        def word(at, val):
            struct.pack_into("<I", r.image, at, val)

        word(0x1000 + 0x21C4, 0x40)
        word(0x8000 + 0x5BC, 0x500)
        if descriptors:
            word(0x1000 + 0x21E8, 0x9000)
            word(0x1000 + 0x21EC, (descriptors + 1) * 20)
            for i in range(descriptors):
                struct.pack_into(
                    "<5I",
                    r.image,
                    0x9000 + i * 20,
                    0x10000,
                    0,
                    0,
                    0x20000 + i * 2,
                    0x10000,
                )
            for i in range(thunks):
                word(0x10000 + i * 4, 0x80000001 + i)
        return r

    def execute(self, r, outputs=(), scrubs=()):
        with (
            patch.object(
                m, "_recover_components", return_value=(0, 0, 0, 0x1000, 0x8000)
            ),
            patch.object(
                m,
                "_records",
                side_effect=lambda _r, p: list(outputs if p == 0x3210 else scrubs),
            ),
            patch.object(m, "_import_string", return_value="x"),
        ):
            return m._recover_engine(r)

    def test_positive_imports(self):
        r = self.fixture(2, 10)
        entry, imports, regions = self.execute(r)
        self.assertEqual(entry, 0x500)
        self.assertEqual(len(imports), 2)
        self.assertEqual(sum(len(x[1]) for x in imports), 20)
        self.assertEqual(regions, ())

    def test_aggregate_alias_thunk_rejected(self):
        with self.assertRaisesRegex(ValueError, "Aggregate import entry"):
            self.execute(self.fixture(65, 1024))

    def test_scrub_alias_rejected_before_any_zero_write(self):
        r = self.fixture()
        r.image[0x30000:0x30010] = b"X" * 16
        with self.assertRaisesRegex(ValueError, "zero regions overlap"):
            self.execute(r, scrubs=((0x30000, 16, 0, 0), (0x30008, 8, 0, 0)))
        self.assertEqual(r.read(0x30000, 16), b"X" * 16)

    def test_tail_out_of_input_rejected(self):
        with self.assertRaisesRegex(ValueError, "region exceeds"):
            self.execute(self.fixture(), outputs=((1000, 4, 0x30000, 4),))

    def test_output_alias_rejected(self):
        with (
            patch.object(m, "decode_aes_cbc", side_effect=lambda data, *a, **k: data),
            self.assertRaisesRegex(ValueError, "output regions overlap"),
        ):
            self.execute(
                self.fixture(), outputs=((0, 4, 0x30000, 4), (0, 4, 0x30002, 4))
            )

    def test_equal_tail_copies_without_huffman(self):
        with (
            patch.object(m, "decode_aes_cbc", side_effect=lambda data, *a, **k: data),
            patch.object(
                m, "decode_huffman", side_effect=AssertionError("equal region decoded")
            ),
        ):
            r = self.fixture()
            self.execute(r, outputs=((0, 4, 0x30000, 4),))
            self.assertEqual(r.read(0x30000, 4), bytes(4))

    def test_short_tail_calls_huffman(self):
        with (
            patch.object(m, "decode_aes_cbc", side_effect=lambda data, *a, **k: data),
            patch.object(m, "decode_huffman", return_value=b"A" * 8) as h,
        ):
            r = self.fixture()
            self.execute(r, outputs=((0, 4, 0x30000, 8),))
            h.assert_called_once()
            self.assertEqual(r.read(0x30000, 8), b"A" * 8)

    def test_cancel_before_output_write(self):
        r = self.fixture()
        r.cancel = lambda: True
        with (
            patch.object(m, "decode_aes_cbc", side_effect=lambda data, *a, **k: data),
            self.assertRaises(InterruptedError),
        ):
            self.execute(r, outputs=((0, 4, 0x30000, 4),))


if __name__ == "__main__":
    unittest.main()
