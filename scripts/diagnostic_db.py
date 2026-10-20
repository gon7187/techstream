"""Native reader for Techstream DDB resources; no vendor executable is loaded.

Layouts and string IDs follow KgpDataCtrl.dll and DataCompress_DT.DLL.
See docs/ddb-format.md for exact consumers and the remaining field boundaries.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path

from scripts.signal_conversion import signal_metadata

MAX_SIZE = 64 * 1024 * 1024
VERSIONS = {0x01000137, 0x01000225, 0x0100032F}


def decode_lzss(payload: bytes) -> bytes:
    if len(payload) < 5:
        raise ValueError("Truncated compressed DDB header")
    wanted, checksum = struct.unpack_from("<IB", payload)
    if wanted > MAX_SIZE:
        raise ValueError("Decoded DDB section exceeds 64 MiB")
    ring, known = bytearray(4096), bytearray(4096)
    output = bytearray()
    cursor, write, observed = 5, 0xFEE, 0
    while cursor < len(payload):
        if len(output) == wanted:
            raise ValueError("Trailing compressed DDB bytes")
        flags = payload[cursor]
        cursor += 1
        for bit in range(8):
            if cursor == len(payload):
                break
            if len(output) == wanted:
                raise ValueError("Trailing compressed DDB bytes")
            if flags & (1 << bit):
                reference, length = None, 1
                literal = payload[cursor]
                cursor += 1
            else:
                if cursor + 2 > len(payload):
                    raise ValueError("Truncated LZSS reference")
                first, second = payload[cursor : cursor + 2]
                cursor += 2
                reference = first | ((second & 0xF0) << 4)
                length = (second & 15) + 3
                literal = 0
            if len(output) + length > wanted:
                raise ValueError("LZSS exceeds declared size")
            for i in range(length):
                if reference is not None:
                    position = (reference + i) & 4095
                    if not known[position]:
                        raise ValueError("LZSS references uninitialized ring data")
                    value = ring[position]
                else:
                    value = literal
                output.append(value)
                observed |= value
                ring[write], known[write] = value, 1
                write = (write + 1) & 4095
    if len(output) != wanted or observed != checksum:
        raise ValueError("DDB decoded length or OR checksum mismatch")
    return bytes(output)


@dataclass(frozen=True)
class Section:
    slot: int
    offset: int
    count: int
    compressed: bool
    payload: bytes

    def rows(self, width: int) -> list[bytes]:
        if width < 1 or len(self.payload) != self.count * width:
            raise ValueError(f"DDB section {self.slot}: inconsistent record width")
        return [self.payload[i : i + width] for i in range(0, len(self.payload), width)]


@dataclass(frozen=True)
class Database:
    kind: int
    version: int
    sha256: str
    sections: dict[int, Section]

    def signal_variants(self, row_index: int) -> list[dict[str, int]]:
        if self.kind != 2 or 10 not in self.sections or 13 not in self.sections:
            raise ValueError("ECU database has no Freeze/PhyData definitions")
        rows = self.sections[10].rows(84)
        if not 0 <= row_index < len(rows):
            raise ValueError("Freeze row is outside the database")
        freeze = rows[row_index]
        key = struct.unpack_from("<H", freeze, 60)[0]
        return [
            {
                **signal_metadata(freeze, physical),
                "physical_row": i,
                "exception_id": struct.unpack_from("<H", physical, 16)[0],
                "exception_flag": physical[22],
            }
            for i, physical in enumerate(self.sections[13].rows(24))
            if struct.unpack_from("<H", physical, 12)[0] == key
        ]

    def named_records(self, slot: int, language: Language) -> list[dict]:
        section = self.sections.get(slot)
        if section is None:
            return []
        # Only fields established by named getters/SetRecString are exposed.
        schemes = {
            (1, 3): (36, [], []),
            (1, 4): (20, [], []),
            (1, 43): (12, [], [("name", 0)]),
            (1, 16): (76, [("file", 0, 40), ("short_name", 40, 20)], [("name", 60)]),
            (1, 19): (88, [("file", 0, 80)], []),
            (2, 5): (28, [("code", 0, 12)], [("name", 12), ("comment", 16)]),
            (2, 6): (8, [], []),
            (2, 7): (8, [], []),
            (2, 2): (4, [], []),
            (2, 3): (8, [], []),
            (2, 4): (8, [], []),
            (2, 10): (84, [], [("name", 48)]),
            (2, 11): (92, [], [("name", 32)]),
            (2, 13): (24, [], []),
            (2, 14): (24, [], [("name", 0)]),
            (2, 15): (12, [], [("name", 0)]),
        }
        scheme = schemes.get((self.kind, slot))
        if scheme is None:
            raise ValueError(f"No semantic schema for DDB {self.kind}/{slot}")
        width, inline, references = scheme
        result = []
        for i, row in enumerate(section.rows(width)):
            entry = {"row": i, "raw_hex": row.hex()}
            if (self.kind, slot) == (2, 11):
                # GetMonShortName returns this prefix; its encoding is unproven.
                entry["short_name_hex"] = row[:32].hex()
            for name, offset, length in inline:
                entry[name] = (
                    row[offset : offset + length].decode("utf-16le").split("\0", 1)[0]
                )
            for name, offset in references:
                string_id = struct.unpack_from("<I", row, offset)[0]
                entry[name + "_id"] = string_id
                entry[name] = language.resolve(string_id)
            scalar = {
                (1, 3): [("match_flags", "I", 16)],
                (1, 4): [("key", "H", 4)],
                (1, 43): [("key", "H", 4)],
                (2, 2): [("exception_id", "H", 0), ("exception_flag", "B", 3)],
                (2, 3): [
                    ("key", "B", 4),
                    ("exception_id", "H", 0),
                    ("exception_flag", "B", 6),
                ],
                (2, 4): [
                    ("key", "B", 4),
                    ("exception_id", "H", 0),
                    ("exception_flag", "B", 6),
                ],
                (2, 11): [
                    ("key", "H", 56),
                    ("selector", "B", 82),
                    ("exception_id", "H", 72),
                    ("exception_flag", "B", 87),
                ],
                (2, 5): [
                    ("key", "H", 20),
                    ("exception_id", "H", 22),
                    ("exception_flag", "B", 27),
                ],
                (2, 6): [
                    ("key", "B", 2),
                    ("exception_id", "H", 0),
                    ("exception_flag", "B", 6),
                ],
                (2, 7): [
                    ("key", "B", 4),
                    ("exception_id", "H", 0),
                    ("exception_flag", "B", 6),
                ],
                (2, 10): [
                    ("key", "H", 56),
                    ("physical_key", "H", 60),
                    ("start_bit", "H", 62),
                    ("end_bit", "H", 64),
                    ("selector", "B", 76),
                ],
                (2, 13): [
                    ("multiplier", "i", 0),
                    ("divisor", "i", 4),
                    ("offset", "i", 8),
                    ("key", "H", 12),
                    ("unit_key", "H", 14),
                    ("exception_id", "H", 16),
                    ("sign_mode", "B", 20),
                    ("decimal_precision", "B", 21),
                    ("exception_flag", "B", 22),
                ],
                (2, 15): [("key", "H", 4), ("unit_conversion_category", "H", 6)],
            }.get((self.kind, slot), [])
            for name, fmt, offset in scalar:
                entry[name] = struct.unpack_from("<" + fmt, row, offset)[0]
            result.append(entry)
        return result

    def records_for_key(self, slot: int, key: int, language: Language) -> list[dict]:
        """Return every matching definition; this does not decide vehicle support."""
        records = self.named_records(slot, language)
        if records and "key" not in records[0]:
            raise ValueError("DDB table has no recovered lookup key")
        return [record for record in records if record["key"] == key]


def parse_database(data: bytes, cache: dict[str, bytes] | None = None) -> Database:
    if not 40 <= len(data) <= MAX_SIZE or data[10:28] != b"DiagTool DataCtrl\0":
        raise ValueError("Invalid DDB signature or file size")
    kind, slots = data[8:10]
    version = struct.unpack_from("<I", data, 28)[0]
    if version not in VERSIONS or kind not in range(1, 7) or not slots:
        raise ValueError("Unsupported DDB version or kind")
    header_size = 36 + slots * 4
    if header_size > len(data):
        raise ValueError("Truncated DDB section directory")
    offsets = struct.unpack_from(f"<{slots}I", data, 36)
    present = [(slot, offset) for slot, offset in enumerate(offsets) if offset]
    if not present or present[0][1] != header_size:
        raise ValueError("DDB sections do not start after the directory")
    fmt = "<BBHI" if version == 0x01000137 else "<BBII"
    section_size = struct.calcsize(fmt)
    sections = {}
    for i, (slot, offset) in enumerate(present):
        end = present[i + 1][1] if i + 1 < len(present) else len(data)
        if not header_size <= offset <= end - section_size <= len(data) - section_size:
            raise ValueError("Invalid DDB section extent")
        sid, flags, count, length = struct.unpack_from(fmt, data, offset)
        if sid != slot or flags not in (0, 1) or length != end - offset - section_size:
            raise ValueError("DDB section identity, flags or length mismatch")
        payload = data[offset + section_size : end]
        if flags:
            digest = hashlib.sha256(payload).hexdigest()
            decoded = cache.get(digest) if cache is not None else None
            if decoded is None:
                decoded = decode_lzss(payload)
                if cache is not None:
                    cache[digest] = decoded
            payload = decoded
        sections[slot] = Section(slot, offset, count, bool(flags), payload)
    return Database(kind, version, hashlib.sha256(data).hexdigest(), sections)


def read_database(path: Path, cache: dict[str, bytes] | None = None) -> Database:
    with path.open("rb") as source:
        return parse_database(source.read(MAX_SIZE + 1), cache)


class Language:
    def __init__(self, database: Database):
        if database.kind not in (4, 5, 6) or 0 not in database.sections:
            raise ValueError("DDB is not a string table")
        section = database.sections[0]
        payload, base, expected = section.payload, section.count * 6, 0
        if base > len(payload):
            raise ValueError("DDB string index exceeds payload")
        self.strings = []
        for i in range(section.count):
            offset, length = struct.unpack_from("<IH", payload, i * 6)
            if (
                offset != expected
                or length % 2
                or base + offset + length > len(payload)
            ):
                raise ValueError(f"Invalid DDB string index {i}")
            encoded = payload[base + offset : base + offset + length]
            if length and not encoded.endswith(b"\0\0"):
                raise ValueError(f"Unterminated DDB string {i}")
            self.strings.append(encoded.decode("utf-16le").rstrip("\0"))
            expected += length
        if base + expected != len(payload):
            raise ValueError("Trailing bytes in DDB string pool")
        self.sha256 = database.sha256

    def resolve(self, string_id: int) -> str:
        if not 0 <= string_id <= len(self.strings):
            raise ValueError(f"DDB string ID {string_id} outside language table")
        return self.strings[string_id - 1] if string_id else ""


class DiagnosticCatalog:
    """Resolve actual ECU filename fields, with no inferred vehicle compatibility."""

    def __init__(self, root: Path):
        self.root = root.resolve(strict=True)
        self.language = Language(read_database(self.root / "M_English.ddb"))
        self.management = read_database(self.root / "Toyota.ddb")
        if self.management.kind != 1:
            raise ValueError("Toyota.ddb is not a management database")
        unique = {}
        for record in self.management.named_records(16, self.language):
            name = record["file"]
            if not name:
                continue
            if (
                Path(name).name != name
                or "\\" in name
                or not name.lower().endswith(".ddb")
            ):
                raise ValueError("Invalid ECU database filename")
            unique.setdefault((name, record["name"]), record)
        self.systems = sorted(
            unique.values(),
            key=lambda row: (not bool(row["name"]), row["name"], row["file"]),
        )

    def read_system(self, filename: str) -> Database:
        if not any(record["file"] == filename for record in self.systems):
            raise ValueError("System is not listed in the management database")
        path = self.root / filename
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(self.root):
            raise ValueError("ECU database escapes source directory")
        database = read_database(path)
        if database.kind != 2:
            raise ValueError("Selected resource is not an ECU database")
        return database


def verify_databases(root: Path) -> dict:
    """Validate original structure, decompression, strings and implemented schemas."""
    files = sorted(root.glob("Techstream_DB_*/*.ddb"))
    if not files:
        raise ValueError("No Techstream_DB_*/*.ddb resources found")
    cache: dict[str, bytes] = {}
    languages = {}
    report = {
        "files": 0,
        "sections": 0,
        "compressed_sections": 0,
        "string_records": 0,
        "semantic_records": {},
        "errors": [],
    }
    for path in files:
        try:
            database = read_database(path, cache)
            report["files"] += 1
            report["sections"] += len(database.sections)
            report["compressed_sections"] += sum(
                section.compressed for section in database.sections.values()
            )
            if database.kind in (4, 5, 6):
                report["string_records"] += len(Language(database).strings)
            if database.kind in (1, 2):
                if path.parent not in languages:
                    languages[path.parent] = Language(
                        read_database(path.parent / "M_English.ddb", cache)
                    )
                slots = (
                    (3, 4, 16, 19, 43)
                    if database.kind == 1
                    else (2, 3, 4, 5, 6, 7, 10, 11, 13, 14, 15)
                )
                for slot in slots:
                    rows = database.named_records(slot, languages[path.parent])
                    key = f"{database.kind}/{slot}"
                    report["semantic_records"][key] = report["semantic_records"].get(
                        key, 0
                    ) + len(rows)
        except (OSError, ValueError) as exc:
            report["errors"].append({"file": str(path), "error": str(exc)})
    report["unique_compressed_sections"] = len(cache)
    report["decoder"] = "stdlib Python"
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Extracted application root to verify")
    parser.add_argument("--report", type=Path, help="Save JSON validation report")
    args = parser.parse_args()
    try:
        result = verify_databases(args.root)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"ERROR: {exc}\n")
    output = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.report:
        args.report.write_text(output, encoding="utf-8")
    print(output, end="")
    raise SystemExit(1 if result["errors"] else 0)
