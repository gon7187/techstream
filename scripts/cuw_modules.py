"""Bounded static inspection of user-supplied CUW split modules."""

from __future__ import annotations

import hashlib
import struct
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from scripts.calibration_catalog import inspect_module as inspect_pe
from scripts.local_files import read_regular

MAX_BYTES = 64 * 1024 * 1024
Cancel = Callable[[], bool] | None


def _check(cancel: Cancel) -> None:
    if cancel is not None and cancel():
        raise InterruptedError("Module operation cancelled")


def _span(data: bytes | bytearray, offset: int, length: int) -> None:
    if offset < 0 or length < 0 or offset > len(data) - length:
        raise ValueError("Module region exceeds its input")


def _rol(value: int, count: int, bits: int = 32) -> int:
    return ((value << count) | (value >> (bits - count))) & ((1 << bits) - 1)


def decode_huffman(
    table: bytes, source: bytes, length: int, *, cancel: Cancel = None
) -> bytes:
    if not 0 <= length <= MAX_BYTES or len(source) > MAX_BYTES:
        raise ValueError("Huffman size limit exceeded")
    if not 768 <= len(table) <= 98304 or len(table) % 3:
        raise ValueError("Invalid Huffman table extent")
    _check(cancel)
    out = bytearray()
    bit = 0
    pending = 0
    tokens = 0

    def ent(index):
        if index < 0 or index * 3 + 3 > len(table):
            raise ValueError("table index")
        w, n = struct.unpack_from("<HB", table, index * 3)
        return w, n

    while len(out) < length:
        tokens += 1
        if tokens % 1024 == 0:
            _check(cancel)
        if tokens > length * 4 + 100:
            raise ValueError("limit")
        avail = int.from_bytes(source[bit // 8 : bit // 8 + 5], "little") >> (bit % 8)
        w, n = ent(avail & 255)
        if not w & 0x8000:
            shift = n
            for j in range(32):
                w, _ = ent((w & 0x7FFF) + ((avail >> shift) & 1))
                shift += 1
                if w & 0x8000:
                    break
            else:
                raise ValueError("tree cycle")
            n = shift
        if n == 0 or n > 32 or bit + n > len(source) * 8:
            raise ValueError("bits")
        bit += n
        kind = w & 0x300
        val = w & 255
        if kind == 0:
            out.append(val)
        elif kind == 0x100:
            if pending > 255:
                raise ValueError("prefix")
            pending = pending * 256 + val
        elif kind == 0x200:
            count = pending or 1
            pending = 0
            if val not in (1, 2, 4) or len(out) < val:
                raise ValueError("repeat")
            if count * val > length - len(out):
                raise ValueError("repeat limit")
            out.extend(out[-val:] * count)
        else:
            distance = pending + val
            pending = 0
            if val == 0 or distance > len(out):
                raise ValueError(("backref", bit, len(out), pending, val, distance))
            start = len(out) - distance
            out.extend(out[start : start + val])
        if len(out) > length:
            raise ValueError("output")
    if (bit + 7) // 8 != len(source):
        raise ValueError(("trailing", bit, len(source)))
    return bytes(out)


def decode_header(data: bytes, offset: int = 0) -> tuple[int, ...]:
    """Decode one input-seeded eight-word KONN record."""
    _span(data, offset, 32)
    key = struct.unpack_from("<I", data, offset)[0]
    result = [key]
    for index in range(7):
        value = struct.unpack_from("<I", data, offset + 4 + index * 4)[0]
        result.append(value ^ key)
        key = ((value - index + key) ^ (index * index)) & 0xFFFFFFFF
    if result[1] != int.from_bytes(b"KONN", "little"):
        raise ValueError("Split record has no KONN signature")
    return tuple(result)


def decode_words(
    data: bytes, seed: int, *, rotate: int = 0, cancel: Cancel = None
) -> bytes:
    """Apply observed feedback, ROL11 or ROL13 transforms to an explicit region."""
    if type(seed) is not int or not 0 <= seed <= 0xFFFFFFFF:
        raise ValueError("Word seed must be uint32")
    if rotate not in (0, 11, 13) or len(data) > MAX_BYTES:
        raise ValueError("Unsupported or oversized word region")
    _check(cancel)
    result = bytearray(data)
    key = seed if rotate else (seed + ~len(data)) & 0xFFFFFFFF
    for index in range(len(data) // 4):
        if index % 1024 == 0:
            _check(cancel)
        value = struct.unpack_from("<I", data, index * 4)[0]
        plain = value ^ key
        if rotate:
            plain = (_rol(plain, rotate) - index) & 0xFFFFFFFF
            key = (key + index) & 0xFFFFFFFF
        else:
            key = ((value + index + key) ^ (index * index)) & 0xFFFFFFFF
        struct.pack_into("<I", result, index * 4, plain)
    return bytes(result)


def decode_bytes(
    data: bytes, rva: int, *, rotate: int = 3, cancel: Cancel = None
) -> bytes:
    """Decode bounded byte regions; the seed is derived from their original RVA."""
    if rotate not in (2, 3) or not 0 <= rva <= 0xFFFFFFFF or len(data) > MAX_BYTES:
        raise ValueError("Unsupported byte region")
    seed = ((rva >> 8) + rva) & 255 if rotate == 3 else rva & 255
    result = bytearray(data)
    _check(cancel)
    for index, value in enumerate(data):
        if index % 4096 == 0:
            _check(cancel)
        key = (seed + index) & 255
        value = _rol(value, rotate, 8) ^ ((key + 1) & 255)
        value = _rol(value, rotate, 8) ^ key
        result[index] = _rol(value, rotate, 8)
    return bytes(result)


def inspect_module(path: str | Path, *, cancel: Cancel = None) -> dict:
    """Inspect PE contracts and an adjacent companion without loading any PE."""
    _check(cancel)
    source = Path(path)
    result = inspect_pe(source)
    companion_path = source.with_name(source.name + "._")
    if companion_path.exists():
        companion = read_regular(companion_path, limit=MAX_BYTES)
        records = []
        for index in range(4):
            _check(cancel)
            record = decode_header(companion, index * 32)
            records.append(
                {
                    "entry_rva": record[2],
                    "destination_rva": record[3],
                    "source_offset": record[4],
                    "length": record[5],
                    "encrypted_end_rva": record[6],
                }
            )
        result.update(
            companion_sha256=hashlib.sha256(companion).hexdigest(),
            companion_size=len(companion),
            split_records=records,
        )
    _check(cancel)
    return result


class ModuleProvider:
    """Resolve explicit basenames in the caller's original module directory."""

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def _path(self, name: str) -> Path:
        if not name or name in (".", "..") or any(c in name for c in ("/", "\\", "\0")):
            raise ValueError("A module basename is required")
        return self.root / name

    def recover(self, name: str, *, cancel: Cancel = None) -> RecoveredModule:
        return recover_module(self._path(name), cancel=cancel)

    def inspect(self, name: str, *, cancel: Cancel = None) -> dict:
        return inspect_module(self._path(name), cancel=cancel)


def _gf_multiply(left: int, right: int) -> int:
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        left = ((left << 1) ^ (0x11B if left & 128 else 0)) & 255
        right >>= 1
    return result


def _inverse_sbox() -> tuple[int, ...]:
    forward = []
    for value in range(256):
        result, power, exponent = 1, value, 254
        while exponent:
            if exponent & 1:
                result = _gf_multiply(result, power)
            power = _gf_multiply(power, power)
            exponent >>= 1
        result = (
            result
            ^ _rol(result, 1, 8)
            ^ _rol(result, 2, 8)
            ^ _rol(result, 3, 8)
            ^ _rol(result, 4, 8)
            ^ 99
        )
        forward.append(result)
    return tuple(forward.index(value) for value in range(256))


_AES_INVERSE = _inverse_sbox()
_AES_T0 = tuple(
    (_gf_multiply(x, 14) << 24)
    | (_gf_multiply(x, 9) << 16)
    | (_gf_multiply(x, 13) << 8)
    | _gf_multiply(x, 11)
    for x in _AES_INVERSE
)
_AES_TABLES = tuple(
    tuple(_rol(value, 32 - 8 * index) if index else value for value in _AES_T0)
    for index in range(4)
)


def decode_aes_cbc(data: bytes, schedule: bytes, *, cancel: Cancel = None) -> bytes:
    """Decode zero-IV CBC using an original file's expanded inverse key schedule.

    The native region contract transforms complete blocks and preserves its tail.
    No vendor key is embedded in this implementation.
    """
    if len(data) > MAX_BYTES or len(schedule) < 4:
        raise ValueError("Invalid AES input extent")
    bits, rounds = struct.unpack_from("<HH", schedule)
    if {128: 10, 192: 12, 256: 14}.get(bits) != rounds or len(schedule) != 4 + 16 * (
        rounds + 1
    ):
        raise ValueError("Invalid expanded AES inverse schedule")
    keys = struct.unpack_from("<" + "I" * (4 * (rounds + 1)), schedule, 4)
    output = bytearray(data)
    previous = bytes(16)
    _check(cancel)
    for offset in range(0, len(data) // 16 * 16, 16):
        if offset % 4096 == 0:
            _check(cancel)
        block = data[offset : offset + 16]
        state = [
            word ^ keys[index] for index, word in enumerate(struct.unpack(">4I", block))
        ]
        for round_index in range(1, rounds):
            state = [
                _AES_TABLES[0][state[index] >> 24]
                ^ _AES_TABLES[1][(state[(index - 1) % 4] >> 16) & 255]
                ^ _AES_TABLES[2][(state[(index - 2) % 4] >> 8) & 255]
                ^ _AES_TABLES[3][state[(index - 3) % 4] & 255]
                ^ keys[round_index * 4 + index]
                for index in range(4)
            ]
        state = [
            (
                (_AES_INVERSE[state[index] >> 24] << 24)
                | (_AES_INVERSE[(state[(index - 1) % 4] >> 16) & 255] << 16)
                | (_AES_INVERSE[(state[(index - 2) % 4] >> 8) & 255] << 8)
                | _AES_INVERSE[state[(index - 3) % 4] & 255]
            )
            ^ keys[rounds * 4 + index]
            for index in range(4)
        ]
        plain = struct.pack(">4I", *state)
        output[offset : offset + 16] = bytes(
            left ^ right for left, right in zip(plain, previous, strict=True)
        )
        previous = block
    return bytes(output)


class _Recovery:
    """One bounded mapped image; all arithmetic is over supplied file bytes."""

    def __init__(self, data: bytes, companion: bytes, cancel: Cancel):
        self.cancel = cancel
        self.original = data
        self.companion = companion
        self.image = bytearray()
        self._validate_pe()
        _span(companion, 0, 0x4E0)
        if len(companion) > MAX_BYTES or data[0x1000:0x14E0] != companion[:0x4E0]:
            raise ValueError("DLL and companion bootstrap headers do not match")
        record = decode_header(companion)
        self.destination, source, length = record[3:6]
        self.loader = record[6]
        encrypted = self.loader - self.destination + 0x2000
        if encrypted < 0 or encrypted > length:
            raise ValueError("Invalid split bootstrap encrypted extent")
        _span(companion, source, length)
        self.put(
            self.destination,
            decode_words(
                companion[source : source + encrypted], record[0], cancel=cancel
            )
            + companion[source + encrypted : source + length],
        )
        self._restore_directories()
        self.header_ranges = self._ranges(self.loader + 0x1288)
        self.stage2 = self.number(self.loader + 0x12C8)
        self._word_pair(
            self.loader + 0x12C8,
            self.number(self.loader + 0x1270) ^ self.checksum(self.loader + 0x12D8),
            11,
        )
        self._word_pair(self.stage2 + 0xB5C, self.number(self.stage2 + 0x938), 13)
        self.core = self.number(self.stage2 + 0x964) - 0x400
        self._prepare_tables()

    def _validate_pe(self) -> None:
        data = self.original
        if len(data) > MAX_BYTES:
            raise ValueError("PE file exceeds size limit")
        _span(data, 0, 64)
        if data[:2] != b"MZ":
            raise ValueError("A DOS/PE32 split module is required")
        self.pe = struct.unpack_from("<I", data, 60)[0]
        _span(data, self.pe, 24)
        if data[self.pe : self.pe + 4] != b"PE\0\0":
            raise ValueError("Invalid PE signature")
        if struct.unpack_from("<H", data, self.pe + 4)[0] != 0x14C:
            raise ValueError("An x86 split module is required")
        count = struct.unpack_from("<H", data, self.pe + 6)[0]
        optional_size = struct.unpack_from("<H", data, self.pe + 20)[0]
        self.optional = self.pe + 24
        _span(data, self.optional, optional_size)
        if (
            optional_size < 224
            or struct.unpack_from("<H", data, self.optional)[0] != 0x10B
        ):
            raise ValueError("Unsupported split module PE profile")
        size, headers = struct.unpack_from("<II", data, self.optional + 56)
        if (
            not 1 <= size <= MAX_BYTES
            or not 1 <= count <= 96
            or headers > min(size, len(data))
        ):
            raise ValueError("Invalid PE image limits")
        self.image = bytearray(size)
        self.image[:headers] = data[:headers]
        self.sections = []
        start = self.optional + optional_size
        _span(data, start, count * 40)
        for index in range(count):
            row = start + index * 40
            virtual, rva, raw_size, raw = struct.unpack_from("<4I", data, row + 8)
            _span(data, raw, raw_size)
            _span(self.image, rva, max(raw_size, virtual))
            if rva < headers or (raw_size and raw < start + 40 * count):
                raise ValueError("PE section overlaps headers")
            if any(
                rva < other[1] and other[0] < rva + max(raw_size, virtual)
                for other in self.sections
            ):
                raise ValueError("Overlapping PE virtual sections")
            self.sections.append((rva, rva + max(raw_size, virtual), row))
            self.put(rva, data[raw : raw + raw_size])

    def number(self, offset: int) -> int:
        _span(self.image, offset, 4)
        return struct.unpack_from("<I", self.image, offset)[0]

    def read(self, offset: int, length: int) -> bytes:
        _span(self.image, offset, length)
        return bytes(self.image[offset : offset + length])

    def put(self, offset: int, value: bytes) -> None:
        _check(self.cancel)
        _span(self.image, offset, len(value))
        self.image[offset : offset + len(value)] = value

    def _ranges(self, offset: int) -> list[tuple[int, int]]:
        ranges = []
        for index in range(64):
            rva, length = (
                self.number(offset + index * 8),
                self.number(offset + index * 8 + 4),
            )
            if not length:
                return ranges
            _span(self.image, rva, length)
            ranges.append((rva, length))
        raise ValueError("Unterminated protected range table")

    def _restore_directories(self) -> None:
        for target, source in (
            (self.pe + 0x80, 0x12EC),
            (self.optional + 0x6C, 0x12F0),
            (self.optional + 0x70, 0x12F8),
            (self.optional + 0x74, 0x12FC),
            (self.optional + 0x88, 0x1300),
            (self.optional + 0x8C, 0x1304),
        ):
            self.put(target, self.read(self.loader + source, 4))

    def checksum(self, *pairs: int) -> int:
        result = 0
        for rva, length in self.header_ranges:
            result ^= zlib.crc32(self.read(rva, length)) ^ length
        flags = self.number(self.loader + 0x1278)
        for pair in pairs:
            rva, length = self.number(pair), self.number(pair + 4)
            result ^= (
                zlib.crc32(self.read(rva, length)) ^ length
                if flags & 0x8000 and not self.number(self.loader + 0x1280) & 0x10
                else (~length) & 0xFFFFFFFF
            )
        return result

    def _word_pair(self, pair: int, seed: int, rotate: int) -> None:
        rva, length = self.number(pair), self.number(pair + 4)
        self.put(
            rva,
            decode_words(
                self.read(rva, length), seed, rotate=rotate, cancel=self.cancel
            ),
        )

    def _prepare_tables(self) -> None:
        count = self.number(self.core + 0x1478)
        if count > 16:
            raise ValueError("Protected byte-region count exceeds bounds")
        for index in range(count):
            record = self.core + 0x15E0 + index * 16
            flags, rva, length = (
                self.number(record),
                self.number(record + 4),
                self.number(record + 8),
            )
            if flags & 1:
                self.put(
                    rva, decode_bytes(self.read(rva, length), rva, cancel=self.cancel)
                )
            if flags & 2:
                for row in range(4096):
                    address = rva + row * 16
                    plain = decode_bytes(
                        self.read(address, 16), address, rotate=2, cancel=self.cancel
                    )
                    src, n, dest, expected = struct.unpack("<4I", plain)
                    if not n:
                        break
                    if n != expected:
                        raise ValueError("Protected copy lengths differ")
                    self.put(dest, self.read(src, n))
                else:
                    raise ValueError("Protected copy table exceeds bounds")
        self.threshold = self.number(self.core + 0x15D4)
        self.huffman_tables = []
        self.aes_schedules = []
        for group, result in ((0, self.huffman_tables), (1, self.aes_schedules)):
            for index in range(2):
                pair = self.core + 0x1588 + group * 32 + index * 8
                rva, length = self.number(pair), self.number(pair + 4)
                plain = decode_bytes(self.read(rva, length), rva, cancel=self.cancel)
                self.put(rva, plain)
                result.append(plain)

    def protected(
        self,
        descriptor: int,
        seed: int,
        transform: Callable[[bytes], bytes] | None = None,
    ) -> bytes:
        source, n, dest, length = (
            self.number(descriptor + 4 * index) for index in range(4)
        )
        index = int(dest >= self.threshold)
        value = decode_aes_cbc(
            self.read(source, n), self.aes_schedules[index], cancel=self.cancel
        )
        value = decode_words(value, seed, rotate=13, cancel=self.cancel)
        if transform is not None:
            value = transform(value)
        value = decode_huffman(
            self.huffman_tables[index], value, length, cancel=self.cancel
        )
        self.put(dest, value)
        return value


def decode_byte_program(
    program: bytes, source: bytes, *, cancel: Cancel = None
) -> bytes:
    """Interpret the recovered finite AL-arithmetic format, without a CPU VM.

    Only immediate byte arithmetic is accepted; memory, calls and branches fail.
    """
    if not 1 <= len(program) <= 95 or len(source) > MAX_BYTES:
        raise ValueError("Invalid arithmetic byte-program extent")
    operations = []
    cursor = 0
    while cursor < len(program):
        opcode = program[cursor]
        cursor += 1
        if opcode == 0x90:
            continue
        if opcode == 0xC3:
            if cursor != len(program):
                raise ValueError("Arithmetic program has trailing instructions")
            break
        if opcode in (0x04, 0x2C, 0x34):
            _span(program, cursor, 1)
            operations.append(
                ({0x04: "add", 0x2C: "sub", 0x34: "xor"}[opcode], program[cursor])
            )
            cursor += 1
        elif opcode in (0xFE, 0xF6):
            _span(program, cursor, 1)
            operation = {
                (0xFE, 0xC0): "inc",
                (0xFE, 0xC8): "dec",
                (0xF6, 0xD0): "not",
                (0xF6, 0xD8): "neg",
            }.get((opcode, program[cursor]))
            if operation is None:
                raise ValueError("Unsupported arithmetic byte operation")
            operations.append((operation, 0))
            cursor += 1
        elif opcode == 0xC0:
            _span(program, cursor, 2)
            if program[cursor] not in (0xC0, 0xC8):
                raise ValueError("Only AL rotations are accepted")
            operations.append(
                ("rol" if program[cursor] == 0xC0 else "ror", program[cursor + 1] & 7)
            )
            cursor += 2
        else:
            raise ValueError("Unsupported arithmetic byte-program instruction")
    else:
        raise ValueError("Arithmetic byte program has no terminal RET")
    lookup = []
    for original in range(256):
        value = original
        for operation, argument in operations:
            if operation == "add":
                value += argument
            elif operation == "sub":
                value -= argument
            elif operation == "xor":
                value ^= argument
            elif operation == "inc":
                value += 1
            elif operation == "dec":
                value -= 1
            elif operation == "not":
                value ^= 255
            elif operation == "neg":
                value = -value
            elif argument:
                value = _rol(value, argument if operation == "rol" else 8 - argument, 8)
            value &= 255
        lookup.append(value)
    result = bytearray(len(source))
    for index, value in enumerate(source):
        if index % 4096 == 0:
            _check(cancel)
        result[index] = lookup[value]
    _check(cancel)
    return bytes(result)


def _unmask_program(data: bytes) -> bytes:
    state = 1
    output = bytearray(data)
    for index, value in enumerate(data):
        for bit in range(8):
            value ^= (state & 1) << bit
            state = (state << 1) & 0xFFFFFFFF
            if state & 0x8000:
                state ^= 3
        output[index] = value
    return bytes(output)


_TRIANGULAR_92 = "93875cc9cf9222c5259da0f51e7fe23bc848d05a55f3b5b841d33b251cf8ee76"
_TRIANGULAR_112 = "0d1e97ab41870081338640d6c9fe73f31732daf93df352e2beba08b3cff77932"
_COMPLEMENT_256 = "9e9fa6fd79b7ffdda0cb19d0d6cc50d3acc846bde4e7c5b7443c72fac8e7d8a8"


def _recover_components(recovery: _Recovery) -> tuple[int, ...]:
    r = recovery
    second = r.stage2
    checksum = r.checksum(r.loader + 0x12E0)
    seed = r.number(second + 0x934)
    for index in range(3):
        node = r.protected(
            second + 0xA6C + 16 * index, r.number(second + 0x924 + 4 * index) ^ checksum
        )
        if hashlib.sha256(node).hexdigest() != _TRIANGULAR_92:
            raise ValueError("Unrecognized first key-node semantics")
        n = (index + 1) * 100
        seed = (seed + n * (n + 1) // 2) & 0xFFFFFFFF
    r.protected(second + 0xAAC, seed ^ checksum)
    first = r.number(second + 0xAAC + 8)
    checksum = r.checksum(second + 0x93C)
    r.protected(second + 0xABC, r.number(first + 0xCF8) ^ checksum)
    component2 = r.number(second + 0xABC + 8)
    checksum = r.checksum(second + 0x944)
    node = r.protected(second + 0xACC, r.number(component2 + 0x364) ^ checksum)
    if hashlib.sha256(node).hexdigest() != _COMPLEMENT_256:
        raise ValueError("Unrecognized guarded key-node semantics")
    r.protected(second + 0xADC, (~r.number(component2 + 0x368) & 0xFFFFFFFF) ^ checksum)
    component3 = r.number(second + 0xADC + 8)
    checksum = r.checksum(second + 0x944, second + 0x94C)
    seed = r.number(component3 + 0x920)
    for index in range(4):
        node = r.protected(
            second + 0xAEC + 16 * index,
            r.number(component3 + 0x910 + 4 * index) ^ checksum,
        )
        if hashlib.sha256(node).hexdigest() != _TRIANGULAR_112:
            raise ValueError("Unrecognized second key-node semantics")
        n = (index + 1) * 100
        seed = (seed + n * (n + 1) // 2) & 0xFFFFFFFF
    transform = None
    if not r.number(component2 + 0x374) & 0x40:
        length = r.read(component3 + 0x958 + 95, 1)[0]
        if not 1 <= length <= 95:
            raise ValueError("Invalid guarded arithmetic-program length")
        program = _unmask_program(r.read(component3 + 0x958, length))
        transform = lambda value: decode_byte_program(program, value, cancel=r.cancel)
    r.protected(second + 0xB2C, seed ^ checksum, transform)
    component4 = r.number(second + 0xB2C + 8)
    checksum = r.checksum(second + 0x944, second + 0x954)
    r.protected(second + 0xB3C, r.number(component4 + 0x21B8) ^ checksum)
    component5 = r.number(second + 0xB3C + 8)
    return first, component2, component3, component4, component5


@dataclass(frozen=True)
class RecoveredModule:
    """Inspection PE with preferred-base bytes; never a native execution API."""

    image: bytes
    source_sha256: str
    companion_sha256: str
    original_entry_rva: int
    imports: tuple[tuple[str, tuple[str | int, ...]], ...]
    restored_regions: tuple[tuple[int, int], ...]


def _records(r: _Recovery, pair: int) -> list[tuple[int, int, int, int]]:
    address, length = r.number(pair), r.number(pair + 4)
    if not 16 <= length <= 65536 or length % 16:
        raise ValueError("Invalid engine region-table extent")
    records = []
    for index in range(length // 16):
        offset = address + index * 16
        row = struct.unpack(
            "<4I", decode_bytes(r.read(offset, 16), offset, rotate=2, cancel=r.cancel)
        )
        if not row[1]:
            return records
        records.append(row)
    raise ValueError("Engine region table has no terminator")


def _import_string(r: _Recovery, address: int, seed: int) -> str:
    output = bytearray()
    for index in range(4096):
        value = r.read(address + index, 1)[0]
        if not value:
            r.put(address, bytes(output))
            return output.decode("ascii")
        value = (_rol(value, 4, 8) - seed) & 255
        output.append(value or (-seed & 255))
        seed = (seed + 0x43) & 255
    raise ValueError("Import name exceeds bounds")


def _recover_engine(r: _Recovery) -> tuple[int, tuple, tuple]:
    *_, component4, component5 = _recover_components(r)
    # The body is a static file format; native OS/anti-debug hooks are not run.
    program = None
    if not r.number(component4 + 0x21C4) & 0x40:
        address = component4 + 0x243C
        length = r.read(address + 95, 1)[0]
        if not 1 <= length <= 95:
            raise ValueError("Invalid engine arithmetic-program length")
        program = _unmask_program(r.read(address, length))
    _span(r.companion, 0x80, 4)
    tail = (~struct.unpack_from("<I", r.companion, 0x80)[0]) & 0xFFFFFFFF
    outputs = []
    records = _records(r, component4 + 0x2210)
    total = 0
    spans = []
    for source, length, dest, size in records:
        total += size
        if total > MAX_BYTES or any(
            dest < end and start < dest + size for start, end in spans
        ):
            raise ValueError("Engine output regions overlap or exceed total limit")
        spans.append((dest, dest + size))
        _span(r.companion, tail + source, length)
        _span(r.image, dest, size)
        if length > 65536 or size > 65536:
            raise ValueError("Engine region exceeds native scratch bounds")
        index = int(dest >= r.threshold)
        value = decode_aes_cbc(
            r.companion[tail + source : tail + source + length],
            r.aes_schedules[index],
            cancel=r.cancel,
        )
        if program is not None:
            value = decode_byte_program(program, value, cancel=r.cancel)
        # Native a2360 compares input/output sizes and copies equal-size regions.
        if length != size:
            value = decode_huffman(
                r.huffman_tables[index], value, size, cancel=r.cancel
            )
        outputs.append((dest, value))
    for dest, value in outputs:
        r.put(dest, value)
    scrub_ranges = []
    scrub_total = 0
    for start, size, _, _ in _records(r, component4 + 0x2218):
        _span(r.image, start, size)
        scrub_total += size
        if scrub_total > MAX_BYTES or any(
            start < end and previous < start + size for previous, end in scrub_ranges
        ):
            raise ValueError("Engine zero regions overlap or exceed total limit")
        scrub_ranges.append((start, start + size))
    for start, end in scrub_ranges:
        r.put(start, bytes(end - start))
    entry = r.number(component5 + 0x5BC)
    _span(r.image, entry, 1)
    import_rva, import_size = (
        r.number(component4 + 0x21E8),
        r.number(component4 + 0x21EC),
    )
    _span(r.image, import_rva, import_size)
    imports = []
    seen_names = set()
    import_entries = 0
    import_name_bytes = 0
    for index in range(min(4096, import_size // 20)):
        row = import_rva + index * 20
        original, _, _, name, iat = struct.unpack("<5I", r.read(row, 20))
        if not name:
            break
        dll = _import_string(r, name, name & 255)
        import_name_bytes += len(dll)
        symbols = []
        for offset in range(65536):
            value = r.number((original or iat) + offset * 4)
            if not value:
                break
            import_entries += 1
            if import_entries > 65536:
                raise ValueError("Aggregate import entry limit exceeded")
            if value & 0x80000000:
                symbols.append(value & 65535)
            elif value in seen_names:
                raise ValueError("Aliased encoded import name")
            else:
                symbol = _import_string(r, value + 2, value & 255)
                import_name_bytes += len(symbol)
                symbols.append(symbol)
                seen_names.add(value)
            if import_name_bytes > MAX_BYTES:
                raise ValueError("Aggregate import name limit exceeded")
        else:
            raise ValueError("Import thunk table has no terminator")
        imports.append((dll, tuple(symbols)))
    else:
        if import_rva or import_size:
            raise ValueError("Import descriptors have no terminator")
    r.put(r.optional + 16, struct.pack("<I", entry))
    r.put(r.optional + 104, r.read(component4 + 0x21E8, 8))
    r.put(r.optional + 136, r.read(component4 + 0x21F8, 8))
    # Inspection PE uses RVA=file offset, preserving all mapped bytes and sections.
    for start, end, row in r.sections:
        r.put(row + 16, struct.pack("<2I", end - start, start))
    return entry, tuple(imports), tuple((dest, len(value)) for dest, value in outputs)


def recover_module(path: str | Path, *, cancel: Cancel = None) -> RecoveredModule:
    """Recover a supplied split PE for static inspection without loading code.

    Only the observed 2026 loader profile is supported. Any other profile fails
    closed; neither imports nor entrypoints are executed or resolved on the host.
    """
    _check(cancel)
    path = Path(path)
    data = read_regular(path, limit=MAX_BYTES)
    companion = read_regular(Path(str(path) + "._"), limit=MAX_BYTES)
    recovery = _Recovery(data, companion, cancel)
    entry, imports, regions = _recover_engine(recovery)
    return RecoveredModule(
        bytes(recovery.image),
        hashlib.sha256(data).hexdigest(),
        hashlib.sha256(companion).hexdigest(),
        entry,
        imports,
        regions,
    )
