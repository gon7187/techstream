"""Generate authored synthetic CT/DDB resources without proprietary files."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from scripts.pid_catalog import TRAILER


def _ct(records: list[tuple[str, str, str, int]]) -> bytes:
    body = bytearray()
    for name, short_name, unit, key in records:
        for text in (name, short_name, unit):
            encoded = text.encode("utf-16le")
            body += struct.pack("<H", len(encoded)) + encoded
        body += struct.pack("<IHH", key, 0, 0)
    header = bytearray(66)
    size = len(header) + len(body) + len(TRAILER)
    struct.pack_into("<IHH", header, 0, size - 6, 2, 52)
    struct.pack_into("<I", header, 40, size - 2)
    struct.pack_into("<H", header, 64, len(records))
    return bytes(header + body + TRAILER)


def _ddb(kind: int, sections: dict[int, tuple[int, bytes]]) -> bytes:
    slots = max(sections) + 1
    header = bytearray(36 + 4 * slots)
    header[8:10] = bytes((kind, slots))
    header[10:28] = b"DiagTool DataCtrl\0"
    struct.pack_into("<I", header, 28, 0x0100032F)
    body = bytearray()
    for slot, (count, payload) in sorted(sections.items()):
        struct.pack_into("<I", header, 36 + 4 * slot, len(header) + len(body))
        body += struct.pack("<BBII", slot, 0, count, len(payload)) + payload
    return bytes(header + body)


def _language(strings: list[str]) -> bytes:
    entries, pool = bytearray(), bytearray()
    for text in strings:
        encoded = (text + "\0").encode("utf-16le")
        entries += struct.pack("<IH", len(pool), len(encoded))
        pool += encoded
    return _ddb(4, {0: (len(strings), bytes(entries + pool))})


def create_demo(destination: Path) -> Path:
    """Create a new directory; never overwrite an existing source or export."""
    destination.mkdir(parents=True, exist_ok=False)
    language = _language(
        [
            "Synthetic powertrain",
            "Synthetic diagnostic fault",
            "Authored example; no vehicle was connected",
            "Engine speed",
            "rpm",
            "Example state",
        ]
    )
    system = bytearray(76)
    name = "DemoEngine.ddb".encode("utf-16le")
    system[: len(name)] = name
    system[40:48] = "DEMO".encode("utf-16le")
    struct.pack_into("<I", system, 60, 1)
    trouble = bytearray(28)
    trouble[:12] = "P0300\0".encode("utf-16le")
    struct.pack_into("<IIH", trouble, 12, 2, 3, 1)
    freeze = bytearray(84)
    struct.pack_into("<I", freeze, 48, 4)
    struct.pack_into("<HHHHH", freeze, 56, 1, 0, 1, 0, 15)
    physical = bytearray(24)
    struct.pack_into("<iiiHH", physical, 0, 1, 4, 0, 1, 1)
    unit = bytearray(12)
    struct.pack_into("<IH", unit, 0, 5, 1)
    state = bytearray(24)
    struct.pack_into("<I", state, 0, 6)
    ecu = _ddb(
        2,
        {
            5: (1, bytes(trouble)),
            10: (1, bytes(freeze)),
            13: (1, bytes(physical)),
            14: (1, bytes(state)),
            15: (1, bytes(unit)),
        },
    )
    files: dict[str, bytes] = {}
    for region in ("NA", "EU", "JP"):
        prefix = f"Techstream_Data_{region}/PIDGroup/Demo"
        files[f"{prefix}/Engine.CT"] = _ct(
            [
                ("Engine speed", "Engine RPM", "rpm", 1),
                ("Coolant temperature", "Coolant", "°C", 2),
                ("Throttle position", "Throttle", "%", 3),
                ("Vehicle speed", "Speed", "km/h", 4),
            ]
        )
        files[f"{prefix}/Emissions.CT"] = _ct(
            [
                ("Engine speed", "Engine RPM", "rpm", 1),
                ("Calculated load", "Load", "%", 5),
            ]
        )
        db_prefix = f"Techstream_DB_{region}"
        files[f"{db_prefix}/M_English.ddb"] = language
        files[f"{db_prefix}/Toyota.ddb"] = _ddb(1, {16: (1, bytes(system))})
        files[f"{db_prefix}/DemoEngine.ddb"] = ecu
    for relative, payload in files.items():
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    manifest = {
        "format": "techstream-authored-demo-v1",
        "synthetic": True,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "files": {
            name: hashlib.sha256(data).hexdigest() for name, data in files.items()
        },
    }
    (destination / "demo-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        root = create_demo(args.output)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"demo: {exc}\n")
    print(f"Synthetic resources created: {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
