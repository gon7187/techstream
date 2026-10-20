#!/usr/bin/env python3
"""Offline MongoosePro MFC frame and response inspection; no USB or ECU I/O.

Layout derived with REA from monpm432.dll SHA-256
56991bad7a4265adfd7f66c884a1684500739551c6421ad96f4b3a730f71a0b5.
See docs/mongoose-protocol.md for addresses, evidence and unverified fields.
"""

import argparse
import json
import struct

HEADER = struct.Struct("<HH")
MAGIC = 0x51E6
MAX_PAYLOAD = 0x1800


def encode_frame(payload: bytes) -> bytes:
    length = len(payload)
    if not 1 <= length <= MAX_PAYLOAD:
        raise ValueError(f"Payload length must be 1..{MAX_PAYLOAD}, got {length}")
    return HEADER.pack(length, length ^ MAGIC) + payload


def decode_frames(data: bytes) -> list[bytes]:
    """Decode complete SLP frames, without guessing a boundary or skipping bytes."""
    frames = []
    position = 0
    while position < len(data):
        if len(data) - position < HEADER.size:
            raise ValueError(f"Truncated frame header at byte {position}")
        length, check = HEADER.unpack_from(data, position)
        if not 1 <= length <= MAX_PAYLOAD or check != length ^ MAGIC:
            raise ValueError(f"Invalid frame length/check at byte {position}")
        start = position + HEADER.size
        end = start + length
        if end > len(data):
            raise ValueError(f"Truncated frame payload at byte {position}")
        frames.append(data[start:end])
        position = end
    return frames


def version_queries() -> list[bytes]:
    """Build the three requests called by PassThruReadVersion, starting sequence 1."""
    # The driver leaves alignment bytes 10..11 unwritten; use deterministic zeros.
    return [
        encode_frame(struct.pack("<HHHHHHI", 1, 0, command, sequence, 0, 0, value))
        for sequence, (command, value) in enumerate(
            ((0x0C, 0x2B), (0x0C, 0x2A), (0x13, 0)), start=1
        )
    ]


def inspect_version_response(
    request_frame: bytes, response_frame: bytes
) -> dict[str, int | str]:
    """Inspect one statically derived reply; opcode mapping is unconfirmed."""
    requests, responses = decode_frames(request_frame), decode_frames(response_frame)
    if len(requests) != 1 or len(responses) != 1:
        raise ValueError("Expected exactly one request frame and one response frame")
    request, response = requests[0], responses[0]
    if len(request) != 16:
        raise ValueError("Expected a 16-byte version request payload")
    sender, target, command, sequence, reserved = struct.unpack_from("<HHHHH", request)
    parameter = struct.unpack_from("<I", request, 12)[0]
    if (
        sender != 1
        or target != 0
        or reserved != 0
        or not 1 <= sequence <= 255
        or (command, parameter) not in ((0x0C, 0x2B), (0x0C, 0x2A), (0x13, 0))
    ):
        raise ValueError("Request does not match the recovered version query layout")
    if len(response) < 20:
        raise ValueError(
            "Response payload is shorter than the recovered 20-byte minimum"
        )
    if (
        struct.unpack_from("<H", response)[0] != target
        or struct.unpack_from("<H", response, 6)[0] != sequence
    ):
        raise ValueError("Response does not correlate with request target and sequence")
    result: dict[str, int | str] = {
        "sequence": sequence,
        "request_parameter": parameter,
        "response_opcode": struct.unpack_from("<H", response, 4)[0],
        "status": struct.unpack_from("<I", response, 12)[0],
    }
    if result["status"] != 0:
        return result
    if command == 0x0C:
        if len(response) < 28:
            raise ValueError(
                "Successful numeric response requires at least 28 payload bytes"
            )
        result["value"] = struct.unpack_from("<I", response, 24)[0]
    else:
        end = response.find(b"\0", 24)
        if end == -1:
            raise ValueError("Version byte string has no bounded NUL terminator")
        result["value_hex"] = response[24:end].hex()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("version-queries", help="Print derived frames; sends nothing")
    decode = commands.add_parser(
        "decode", help="Decode complete hex-encoded SLP frames"
    )
    decode.add_argument("hex_data")
    response = commands.add_parser(
        "version-response", help="Inspect a saved reply; sends nothing"
    )
    response.add_argument("request_hex")
    response.add_argument("response_hex")
    args = parser.parse_args()
    try:
        if args.command == "version-queries":
            result = {
                "status": "STATIC_DERIVED_PHYSICAL_UNCONFIRMED",
                "frames": [frame.hex() for frame in version_queries()],
            }
        elif args.command == "version-response":
            result = {
                "status": "STATIC_DERIVED_PHYSICAL_UNCONFIRMED",
                "notice": "Opcode mapping and string encoding are unconfirmed",
                "response": inspect_version_response(
                    bytes.fromhex(args.request_hex), bytes.fromhex(args.response_hex)
                ),
            }
        else:
            result = {
                "payloads": [
                    payload.hex()
                    for payload in decode_frames(bytes.fromhex(args.hex_data))
                ]
            }
    except ValueError as exc:
        parser.exit(1, f"ERROR: {exc}\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
