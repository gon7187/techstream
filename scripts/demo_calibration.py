"""Authored calibration examples for offline demonstrations; no executable code."""

import csv
import io
import struct
from collections.abc import Sequence


def table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(headers)
    writer.writerows(rows)
    return output.getvalue().encode("latin-1")


def version_resource() -> bytes:
    def node(key, value=b"", children=(), kind=0):
        data = bytes(6) + (key + "\0").encode("utf-16le")
        data += bytes(-len(data) % 4)
        data += value
        for child in children:
            data += bytes(-len(data) % 4) + child
        return (
            struct.pack(
                "<HHH", len(data), len(value) // 2 if kind else len(value), kind
            )
            + data[6:]
        )

    info = node(
        "StringFileInfo",
        children=(
            node(
                "040904b0",
                children=(
                    node("FileVersion", "1.0.0007.0\0".encode("utf-16le"), kind=1),
                ),
            ),
        ),
    )
    translation = node(
        "VarFileInfo", children=(node("Translation", struct.pack("<HH", 0x409, 1200)),)
    )
    return node("VS_VERSION_INFO", b"\xbd\x04\xef\xfe" + bytes(48), (info, translation))


def authored_pe() -> bytes:
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", data, 0x84, 0x14C, 1)
    struct.pack_into("<H", data, 0x94, 224)
    struct.pack_into("<H", data, 0x98, 0x10B)
    struct.pack_into("<I", data, 0xF4, 16)
    struct.pack_into("<II", data, 0xF8, 0x1000, 0x100)
    struct.pack_into("<II", data, 0x108, 0x1100, 0x400)
    data[0x178:0x180] = b".rdata\0\0"
    struct.pack_into("<IIII", data, 0x180, 0x600, 0x1000, 0x600, 0x200)
    struct.pack_into("<IIIII", data, 0x214, 1, 1, 0x1040, 0x1044, 0x1048)
    struct.pack_into("<IIH", data, 0x240, 0x1500, 0x1050, 0)
    data[0x250:0x25C] = b"StartGetCID\0"
    for relative, identifier, target in (
        (0, 16, 0x80000018),
        (24, 1, 0x80000030),
        (48, 0x409, 72),
    ):
        struct.pack_into("<HII", data, 0x300 + relative + 14, 1, identifier, target)
    resource = version_resource()
    struct.pack_into("<II", data, 0x348, 0x1200, len(resource))
    data[0x400 : 0x400 + len(resource)] = resource
    return bytes(data)


def create_calibration_examples() -> dict[str, bytes]:
    """Return a synthetic encoded parameter table and a static PE metadata fixture."""
    raw = table(
        [
            "ParamFileKeySystemProtocolMicon",
            "DLLFileNameForGetCID",
            "GetCANIDFunctionNameForGetCID",
            "CanIDForGetCID",
            "EnableDLLVersionInformation",
        ],
        [
            [
                "synthetic",
                "SyntheticCID.dll",
                "GetCanIDsFromParamForGetCID",
                "0100/0108",
                "1.0.0001.0\n-\n-\n-",
            ]
        ],
    )
    encoded = bytes(
        (nibble + 8) << 2 for byte in raw for nibble in (byte >> 4, byte & 15)
    )
    return {"synthetic.ini": encoded, "SyntheticCID.dll": authored_pe()}
