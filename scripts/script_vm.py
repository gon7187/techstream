"""Strict CSDF object inspector and bounded, side-effect-free VM subset.

Typed byte operations, variables and bounded control flow are evaluated.
No script library, diagnostic command or original binary is loaded.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import ctypes.util
import hashlib
import io
import json
import struct
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

MAX_SIZE = 16 * 1024 * 1024
UTILITY_LIBRARY_SHA256 = (
    "1953edf8821af8c7df612c383c756b87febb3ce7ba055744305ca5db4c2f37a6"
)
OPCODES = {
    0x11: "push_type_1",
    0x12: "push_type_2",
    0x13: "push_type_3",
    0x15: "push_type_4",
    0x20: "pop",
    0x30: "operator",
    0x40: "function",
    0x41: "jump",
    0x42: "call",
    0x43: "return",
    0x44: "exit",
    0x45: "conditional_jump",
}
OPERATORS = {
    0x01: "store",
    0x11: "add",
    0x12: "subtract",
    0x21: "shift_left",
    0x22: "shift_right",
    0x23: "bit_and",
    0x24: "bit_or",
    0x31: "concatenate",
    0x32: "array_reference",
    0x41: "equal",
    0x42: "not_equal",
    0x43: "less",
    0x44: "greater",
    0x45: "less_equal",
    0x46: "greater_equal",
}


@dataclass(frozen=True)
class Step:
    offset: int
    opcode: int
    payload: bytes

    def inspect(self) -> dict:
        result = {
            "offset": self.offset,
            "opcode": self.opcode,
            "operation": OPCODES.get(self.opcode, "unsupported"),
            "payload_hex": self.payload.hex(),
        }
        needed = {0x30: 1, 0x40: 3, 0x41: 2, 0x42: 2, 0x45: 2}.get(self.opcode, 0)
        if len(self.payload) < needed:
            raise ValueError(f"Truncated operand at CSDF offset {self.offset}")
        if self.opcode in (0x40, 0x41, 0x42, 0x45):
            result["operand_u16"] = int.from_bytes(self.payload[:2], "little")
        if self.opcode == 0x40:
            result["argument_count"] = self.payload[2]
        if self.opcode == 0x30:
            result["operator"] = self.payload[0]
            result["operator_name"] = OPERATORS.get(self.payload[0], "unsupported")
        return result


class _Reader:
    def __init__(self, data: bytes):
        if len(data) > MAX_SIZE:
            raise ValueError("CSDF exceeds 16 MiB")
        self.data, self.offset = data, 0

    def take(self, length: int) -> bytes:
        if self.offset + length > len(self.data):
            raise ValueError(f"Truncated CSDF at offset {self.offset}")
        result = self.data[self.offset : self.offset + length]
        self.offset += length
        return result

    def number(self, size: int) -> int:
        return int.from_bytes(self.take(size), "little")

    def name(self) -> bytes:
        return self.take(self.number(1))

    def step(self) -> Step:
        offset = self.offset
        opcode, length = self.take(2)
        result = Step(offset, opcode, self.take(length))
        result.inspect()
        return result


@dataclass(frozen=True)
class ScriptObject:
    variable_count: int
    identifiers: tuple[tuple[bytes, int], ...]
    libraries: tuple[bytes, ...]
    steps: tuple[Step, ...]

    def inspect(self) -> dict:
        return {
            "variable_count": self.variable_count,
            "identifiers": [
                {"name_hex": name.hex(), "id": key} for name, key in self.identifiers
            ],
            "libraries": [name.hex() for name in self.libraries],
            "steps": [step.inspect() for step in self.steps],
        }


@dataclass(frozen=True)
class UtilityResource:
    """Decrypted XML definitions, inspected without executing any action."""

    header: bytes
    root: ET.Element

    def inspect(self) -> dict:
        return {
            "header_hex": self.header.hex(),
            "root": self.root.tag,
            "element_counts": dict(
                Counter(element.tag for element in self.root.iter())
            ),
            "functions": [
                {
                    "name": function.findtext("NAME", ""),
                    "id": function.findtext("FUNCID", ""),
                    "blocks": [
                        dict(block.attrib) for block in function.findall("BLOCK")
                    ],
                }
                for function in self.root.findall("FUNCTION")
            ],
        }


def utility_resource_key(library: bytes) -> bytes:
    """Read the resource key from the exact locally supplied, verified library."""
    if hashlib.sha256(library).hexdigest() != UTILITY_LIBRARY_SHA256:
        raise ValueError(
            "Unrecognized utility resource library; key location is unproven"
        )
    return library[0x3A7D4:0x3A7F4]


def parse_utility_xml(data: bytes) -> UtilityResource:
    """Inspect the four-byte envelope plus UTF-16LE utility XML."""
    if not 6 <= len(data) <= MAX_SIZE or data[4:6] != b"\xff\xfe":
        raise ValueError("Invalid utility XML envelope or size")
    text = data[6:].decode("utf-16le")
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise ValueError("Utility XML document/entity declarations are unsupported")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError("Malformed utility XML") from exc
    return UtilityResource(data[:4], root)


def decode_utility_resource(data: bytes, key: bytes) -> UtilityResource:
    """Decrypt resource AES-ECB with an explicit local key; never load the DLL."""
    return parse_utility_xml(_decrypt_resource(data, key))


def decode_utility_list(data: bytes, key: bytes) -> list[list[str]]:
    """Read decrypted SRPLST CSV fields without guessing their meaning."""
    plaintext = _decrypt_resource(data, key).decode("ascii")
    if "\0" in plaintext:
        raise ValueError("NUL in utility list")
    try:
        rows = list(csv.reader(io.StringIO(plaintext), strict=True))
    except csv.Error as exc:
        raise ValueError("Malformed utility list CSV") from exc
    if not rows or any(len(row) != 4 for row in rows):
        raise ValueError("Utility list must contain four fields per row")
    return rows


def _decrypt_resource(data: bytes, key: bytes) -> bytes:
    if (
        not data
        or len(data) > MAX_SIZE
        or len(data) % 16
        or len(key) not in (16, 24, 32)
    ):
        raise ValueError("Invalid utility ciphertext length or AES key size")
    library = ctypes.util.find_library("crypto")
    if library is None:
        raise ValueError("System libcrypto is required for utility resource decoding")
    crypto = ctypes.CDLL(library)
    pointer = ctypes.c_void_p
    for name, args, result in (
        ("EVP_CIPHER_CTX_new", [], pointer),
        ("EVP_CIPHER_CTX_free", [pointer], None),
        (f"EVP_aes_{len(key) * 8}_ecb", [], pointer),
        (
            "EVP_DecryptInit_ex",
            [pointer, pointer, pointer, pointer, pointer],
            ctypes.c_int,
        ),
        ("EVP_CIPHER_CTX_set_padding", [pointer, ctypes.c_int], ctypes.c_int),
        (
            "EVP_DecryptUpdate",
            [pointer, pointer, pointer, pointer, ctypes.c_int],
            ctypes.c_int,
        ),
        ("EVP_DecryptFinal_ex", [pointer, pointer, pointer], ctypes.c_int),
    ):
        function = getattr(crypto, name)
        function.argtypes, function.restype = args, result
    context = crypto.EVP_CIPHER_CTX_new()
    if not context:
        raise ValueError("Could not allocate AES context")
    output = ctypes.create_string_buffer(len(data) + 16)
    key_buffer = ctypes.create_string_buffer(key)
    data_buffer = ctypes.create_string_buffer(data)
    length, final_length = ctypes.c_int(), ctypes.c_int()
    try:
        cipher = getattr(crypto, f"EVP_aes_{len(key) * 8}_ecb")()
        if (
            crypto.EVP_DecryptInit_ex(context, cipher, None, key_buffer, None) != 1
            or crypto.EVP_CIPHER_CTX_set_padding(context, 0) != 1
            or crypto.EVP_DecryptUpdate(
                context, output, ctypes.byref(length), data_buffer, len(data)
            )
            != 1
            or crypto.EVP_DecryptFinal_ex(
                context, ctypes.byref(output, length.value), ctypes.byref(final_length)
            )
            != 1
        ):
            raise ValueError("System libcrypto could not decode utility resource")
        decoded = output.raw[: length.value + final_length.value]
    finally:
        crypto.EVP_CIPHER_CTX_free(context)
        ctypes.memset(key_buffer, 0, len(key_buffer))
    padding = decoded[-1]
    if not 1 <= padding <= 16 or decoded[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid utility resource padding")
    return decoded[:-padding]


def parse_object(data: bytes) -> ScriptObject:
    """Read the raw object layout consumed by CSDFScript::LoadObjectFile.

    There is no magic signature. This is not an SRP/SRPLST decoder.
    Identifier/library names remain bytes: no source code page is assumed.
    """
    reader = _Reader(data)
    variable_count = reader.number(2)
    identifiers = tuple(
        (reader.name(), reader.number(2)) for _ in range(reader.number(2))
    )
    libraries = tuple(reader.name() for _ in range(reader.number(1)))
    steps = tuple(reader.step() for _ in range(reader.number(2)))
    if reader.offset != len(data):
        raise ValueError("Trailing CSDF object bytes")
    return ScriptObject(variable_count, identifiers, libraries, steps)


def parse_steps(data: bytes) -> tuple[Step, ...]:
    """Inspect an explicitly supplied step stream, without guessing its container."""
    reader = _Reader(data)
    result = []
    while reader.offset < len(data):
        result.append(reader.step())
    return tuple(result)


def _variable_index(payload: bytes, variables: list) -> int:
    if len(payload) < 2:
        raise ValueError("Truncated CSDF variable reference")
    index = int.from_bytes(payload[:2], "little")
    if index >= len(variables):
        raise ValueError("CSDF variable outside declared table")
    return index


def _resolve(value: tuple[int, bytes], variables: list) -> tuple[int, bytes]:
    tag, payload = value
    if tag not in (4, 5):
        return value
    stored = variables[_variable_index(payload, variables)]
    if stored is None:
        raise ValueError("CSDF variable read before assignment")
    if tag == 5:
        if len(payload) < 3:
            raise ValueError("Truncated CSDF array reference")
        offset = payload[2]
        return (1, stored[1][offset : offset + 1] or b"\0")
    return stored


def _scalar(value: tuple[int, bytes]) -> int:
    if value[0] != 1 or not value[1]:
        raise ValueError("CSDF arithmetic requires a nonempty type-1 byte value")
    return value[1][0]


def _retained_bytes(stack: list[tuple[int, bytes]], variables: list) -> int:
    return sum(len(value[1]) for value in stack) + sum(
        len(value[1]) for value in variables if value is not None
    )


def _operator(
    code: int, stack: list[tuple[int, bytes]], variables: list, max_bytes: int
) -> None:
    if code not in OPERATORS:
        raise ValueError(f"Unsupported CSDF operator 0x{code:02x}")
    if len(stack) < 2:
        raise ValueError("CSDF data stack underflow")
    right, left = stack.pop(), stack.pop()
    if code == 0x01:
        if left[0] not in (4, 5):
            raise ValueError("CSDF store requires a variable reference")
        index = _variable_index(left[1], variables)
        right = _resolve(right, variables)
        if left[0] == 4:
            variables[index] = right
        else:
            if len(left[1]) < 3:
                raise ValueError("Truncated CSDF array reference")
            value = _scalar(right)
            stored = variables[index]
            if stored is None:
                raise ValueError("CSDF array write before assignment")
            offset = left[1][2]
            data = bytearray(stored[1])
            if offset >= len(data):
                data.extend(bytes(offset + 1 - len(data)))
            data[offset] = value
            variables[index] = (stored[0], bytes(data))
        return
    if code == 0x32:
        if left[0] != 4:
            raise ValueError("CSDF array operator requires a variable reference")
        _variable_index(left[1], variables)
        offset = _scalar(_resolve(right, variables))
        stack.append((5, left[1][:2] + bytes([offset])))
        return
    left, right = _resolve(left, variables), _resolve(right, variables)
    if code == 0x31:
        if len(left[1]) + len(right[1]) > max_bytes - _retained_bytes(stack, variables):
            raise ValueError("CSDF aggregate byte budget exceeded before concatenation")
        stack.append((3, left[1] + right[1]))
        return
    if code in (0x41, 0x42):
        # Native mismatched tags produce false for both equal and not-equal.
        result = left[0] == right[0] and (
            (left[1] == right[1]) if code == 0x41 else (left[1] != right[1])
        )
    else:
        a, b = _scalar(left), _scalar(right)
        if code == 0x11:
            result = (a + b) & 255
        elif code == 0x12:
            result = (a - b) & 255
        elif code == 0x21:
            result = (a << (b & 31)) & 255
        elif code == 0x22:
            result = a >> (b & 31)
        elif code == 0x23:
            result = a & b
        elif code == 0x24:
            result = a | b
        elif code == 0x43:
            result = a < b
        elif code == 0x44:
            result = a > b
        elif code == 0x45:
            result = a <= b
        else:
            result = a >= b
    stack.append((1, bytes([result])))


def evaluate(
    script: ScriptObject, *, max_steps: int = 10000, max_bytes: int = MAX_SIZE
) -> tuple[tuple[int, bytes], ...]:
    """Evaluate recovered byte/variable/control operations; reject all others."""
    if type(max_steps) is not int or max_steps < 1:
        raise ValueError("max_steps must be a positive integer")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_SIZE:
        raise ValueError("max_bytes must be an integer between 1 and 16 MiB")
    if (
        type(script.variable_count) is not int
        or not 0 <= script.variable_count <= 65535
    ):
        raise ValueError("CSDF variable count must fit u16")
    stack: list[tuple[int, bytes]] = []
    calls: list[int] = []
    variables: list[tuple[int, bytes] | None] = [None] * script.variable_count
    pc = 0
    for _ in range(max_steps):
        if not 0 <= pc < len(script.steps):
            raise ValueError("CSDF program counter outside steps")
        step = script.steps[pc]
        step.inspect()
        opcode = step.opcode
        try:
            if opcode in (0x11, 0x12, 0x13, 0x15):
                stack.append(
                    ({0x11: 1, 0x12: 2, 0x13: 3, 0x15: 4}[opcode], step.payload)
                )
            elif opcode == 0x20:
                if not stack:
                    raise ValueError("CSDF data stack underflow")
                stack.pop()
            elif opcode == 0x30:
                _operator(step.payload[0], stack, variables, max_bytes)
            elif opcode == 0x45:
                if not stack:
                    raise ValueError("CSDF data stack underflow")
                condition = _resolve(stack.pop(), variables)[1]
                if not condition:
                    raise ValueError("Empty CSDF jump condition")
                if condition[0] == 0:
                    pc = struct.unpack_from("<H", step.payload)[0]
                    continue
            elif opcode == 0x44:
                return tuple(stack)
            elif opcode in (0x41, 0x42):
                if opcode == 0x42:
                    calls.append((pc + 1) & 0xFFFF)
                pc = struct.unpack_from("<H", step.payload)[0]
                continue
            elif opcode == 0x43:
                if not calls:
                    raise ValueError("CSDF call stack underflow")
                pc = calls.pop()
                continue
            else:
                raise ValueError(f"Unsupported CSDF evaluation opcode 0x{opcode:02x}")
            pc = (pc + 1) & 0xFFFF
        finally:
            if _retained_bytes(stack, variables) > max_bytes:
                raise ValueError("CSDF aggregate byte budget exceeded")
            if len(stack) > 4096 or len(calls) > 4096:
                raise ValueError("CSDF stack entry budget exceeded")
    raise ValueError("CSDF instruction budget exceeded")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument(
        "--steps", action="store_true", help="Input is a bare step stream"
    )
    parser.add_argument(
        "--utility-library",
        type=Path,
        help="Decode utility XML using this exact local IT3UtilityNeoNK.dll",
    )
    parser.add_argument(
        "--utility-list",
        action="store_true",
        help="Decode SRPLST CSV instead of SRP XML",
    )
    args = parser.parse_args()
    try:
        with args.path.open("rb") as source:
            data = source.read(MAX_SIZE + 1)
        if args.utility_library:
            if args.steps:
                raise ValueError("Choose either utility XML or bare steps")
            with args.utility_library.open("rb") as source:
                key = utility_resource_key(source.read(MAX_SIZE + 1))
            result = (
                decode_utility_list(data, key)
                if args.utility_list
                else decode_utility_resource(data, key).inspect()
            )
        else:
            if args.utility_list:
                raise ValueError("--utility-list requires --utility-library")
            result = (
                [step.inspect() for step in parse_steps(data)]
                if args.steps
                else parse_object(data).inspect()
            )
    except (OSError, ValueError) as exc:
        parser.exit(1, f"ERROR: {exc}\n")
    print(json.dumps(result, indent=2))
