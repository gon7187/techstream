"""Read Techstream CT parameter snapshots and their native DDB identities."""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

from scripts.local_files import read_regular

DEFAULT_ROOT = (
    Path(__file__).resolve().parents[1]
    / "artifacts/extracted/techstream-18-application/Techstream_Data_NA/PIDGroup"
)
MAX_FILE_SIZE = 1024 * 1024
TRAILER = bytes(16) + struct.pack("<H", 4) + bytes(8)


def parse_group(data: bytes) -> list[dict[str, str]]:
    """Parse the observed CT v2/52 dialect; reject unknown headers and tails."""
    if not 92 <= len(data) <= MAX_FILE_SIZE:
        raise ValueError("CT file is truncated or exceeds the 1 MiB limit")
    count = struct.unpack_from("<H", data, 64)[0]
    header = bytearray(66)
    struct.pack_into("<IHH", header, 0, len(data) - 6, 2, 52)
    struct.pack_into("<I", header, 40, len(data) - 2)
    struct.pack_into("<H", header, 64, count)
    if data[:66] != header:
        raise ValueError("Unsupported CT header or inconsistent file length")
    end = len(data) - len(TRAILER)
    if data[end:] != TRAILER or count > (end - 66) // 14:
        raise ValueError("Unsupported CT trailer or impossible record count")
    offset = 66

    def take(size: int) -> bytes:
        nonlocal offset
        if offset + size > end:
            raise ValueError(f"Truncated CT record at offset {offset}")
        result = data[offset : offset + size]
        offset += size
        return result

    def text() -> str:
        size = struct.unpack("<H", take(2))[0]
        if size % 2:
            raise ValueError("Odd UTF-16LE byte length")
        try:
            value = take(size).decode("utf-16le")
        except UnicodeDecodeError as exc:
            raise ValueError("Invalid UTF-16LE text") from exc
        if "\0" in value:
            raise ValueError("Unexpected NUL in CT text")
        return value

    records = []
    for _ in range(count):
        name = text()
        if not name:
            raise ValueError("Unsupported empty CT record name")
        short_name = text()
        unit = text()
        metadata = take(8)
        parameter_id, unit_category, saved_list_field = struct.unpack("<IHH", metadata)
        records.append(
            {
                "name": name,
                "unit": unit,
                "short_name": short_name,
                "parameter_id": str(parameter_id & 0xFFFF),
                "unit_conversion_category": str(unit_category),
                "saved_list_field": str(saved_list_field),
                "metadata_hex": metadata.hex(),
            }
        )
    if offset != end:
        raise ValueError("Unexpected bytes after CT records")
    return records


def group_path(root: Path, group: str) -> Path:
    relative = Path(group)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError("Group must be a relative path inside the catalog root")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Catalog root must be a directory")
    target = root
    for part in relative.parts:
        target /= part
        if target.is_symlink():
            raise ValueError("Symlinks are not allowed in group paths")
    if not target.resolve(strict=True).is_relative_to(root):
        raise ValueError("Group escapes the catalog root")
    if target.suffix.upper() != ".CT" or not target.is_file():
        raise ValueError("Group must be a regular .CT file")
    return target


def list_groups(root: Path) -> list[str]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Catalog root must be a directory")
    groups = []
    for path in root.rglob("*"):
        if path.suffix.upper() != ".CT":
            continue
        relative = path.relative_to(root).as_posix()
        try:
            group_path(root, relative)
        except ValueError:
            continue
        groups.append(relative)
    return sorted(groups)


def show_group(root: Path, group: str) -> dict:
    path = group_path(root, group)
    data = read_regular(path, limit=MAX_FILE_SIZE)
    return {
        "group": path.relative_to(root.resolve()).as_posix(),
        "format": "techstream-ct-v2-52",
        "sha256": hashlib.sha256(data).hexdigest(),
        "metadata_notice": "DDB parameter ID and saved unit-conversion category; not ECU service PIDs or commands",
        "records": parse_group(data),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="List available .CT group paths")
    commands.add_parser("show", help="Read a real parameter group").add_argument(
        "group"
    )
    args = parser.parse_args()
    try:
        result = (
            list_groups(args.root)
            if args.command == "list"
            else show_group(args.root, args.group)
        )
    except (OSError, ValueError) as exc:
        print(f"pid_catalog: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
