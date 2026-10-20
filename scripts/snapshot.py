"""Bounded native Techstream snapshot containers and DataCompress blocks.

Only static, recovered wire layouts are interpreted; unknown table payloads stay bytes.
No OEM module is loaded or executed. See docs/snapshot-format.md for coverage.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from scripts.local_files import read_regular

MAX_BYTES = 32 * 1024 * 1024
MAX_TABLES = 100_000
DM_MAGIC = 0x80000002
DRS_MAGIC = 0x80000001


class SnapshotError(ValueError):
    """Invalid, truncated or unsupported native snapshot."""


class _ByteChunks(list[bytes]):
    """Bound writers before joining aliased record payloads into a large output."""

    def __init__(self, values: Iterable[bytes] = ()):
        super().__init__()
        self.size = 0
        self.extend(values)

    def append(self, value: bytes) -> None:
        if self.size + len(value) > MAX_BYTES:
            raise SnapshotError("encoded native record exceeds limit")
        self.size += len(value)
        super().append(value)

    def extend(self, values: Iterable[bytes]) -> None:
        for value in values:
            self.append(value)


class Cursor:
    """One bounds-checked cursor shared by native record decoders."""

    def __init__(self, data: bytes):
        if not isinstance(data, bytes) or len(data) > MAX_BYTES:
            raise SnapshotError("snapshot requires bytes within the 32 MiB limit")
        self.data = data
        self.position = 0

    def take(self, size: int) -> bytes:
        if type(size) is not int or not 0 <= size <= len(self.data) - self.position:
            raise SnapshotError(f"truncated record at byte {self.position}")
        start = self.position
        self.position += size
        return self.data[start : self.position]

    def unpack(self, fmt: str) -> tuple:
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))

    def end(self) -> None:
        if self.position != len(self.data):
            raise SnapshotError(f"unexpected trailing bytes at byte {self.position}")


@dataclass(frozen=True)
class Table:
    id: int
    payload: bytes

    def __post_init__(self) -> None:
        if type(self.id) is not int or not 0 <= self.id <= 0xFFFF:
            raise SnapshotError("table ID must fit uint16")
        if not isinstance(self.payload, bytes) or len(self.payload) > MAX_BYTES - 6:
            raise SnapshotError("table payload exceeds limit")

    def to_dict(self) -> dict:
        return {"id": self.id, "payload_hex": self.payload.hex()}


def parse_tables(data: bytes) -> tuple[Table, ...]:
    """Decode CFileReader tables (uint32 length includes uint16 ID)."""
    cursor = Cursor(data)
    result = []
    while cursor.position < len(data):
        if len(result) >= MAX_TABLES:
            raise SnapshotError("too many tables")
        (size,) = cursor.unpack("<I")
        if size < 2:
            raise SnapshotError("table length must include its two-byte ID")
        record = Cursor(cursor.take(size))
        (table_id,) = record.unpack("<H")
        result.append(Table(table_id, record.take(size - 2)))
    return tuple(result)


def encode_tables(tables: tuple[Table, ...] | list[Table]) -> bytes:
    if not isinstance(tables, (tuple, list)) or len(tables) > MAX_TABLES:
        raise SnapshotError("invalid table collection")
    size = 0
    chunks = []
    for table in tables:
        if not isinstance(table, Table):
            raise SnapshotError("expected Table")
        size += 6 + len(table.payload)
        if size > MAX_BYTES:
            raise SnapshotError("encoded tables exceed limit")
        chunks.append(
            struct.pack("<IH", len(table.payload) + 2, table.id) + table.payload
        )
    return b"".join(chunks)


@dataclass(frozen=True)
class TableFile:
    magic: int
    version: int
    revision: int
    tables: tuple[Table, ...]

    def __post_init__(self) -> None:
        if self.magic not in (DM_MAGIC, DRS_MAGIC):
            raise SnapshotError("unsupported table-file magic")
        for value in (self.version, self.revision):
            if type(value) is not int or not 0 <= value <= 0xFFFF:
                raise SnapshotError("table-file version fields must fit uint16")
        if not isinstance(self.tables, tuple) or len(self.tables) > MAX_TABLES:
            raise SnapshotError("invalid table collection")

    def to_dict(self) -> dict:
        return {
            "format": "native-dm" if self.magic == DM_MAGIC else "native-drs",
            "version": self.version,
            "revision": self.revision,
            "tables": [table.to_dict() for table in self.tables],
            "provenance": "native-static-layout",
        }


def parse(data: bytes) -> TableFile | TSEFile:
    cursor = Cursor(data)
    if data.startswith(b"\x9aS\xdb\x12"):
        return parse_tse(data)
    magic, version, revision = cursor.unpack("<IHH")
    return TableFile(magic, version, revision, parse_tables(cursor.take(len(data) - 8)))


def dumps(snapshot: TableFile | TSEFile) -> bytes:
    if isinstance(snapshot, TSEFile):
        return snapshot.source
    if not isinstance(snapshot, TableFile):
        raise SnapshotError("expected native TableFile")
    body = encode_tables(snapshot.tables)
    if len(body) > MAX_BYTES - 8:
        raise SnapshotError("snapshot exceeds limit")
    return (
        struct.pack("<IHH", snapshot.magic, snapshot.version, snapshot.revision) + body
    )


def load(path: str | Path) -> TableFile | TSEFile:
    try:
        return parse(read_regular(path, limit=MAX_BYTES))
    except ValueError as exc:
        raise SnapshotError(str(exc)) from exc


def compress(data: bytes) -> bytes:
    """Native DataEncode envelope using valid literal tokens.

    shortcut: literal-only encoding is larger than the native search-tree compressor;
    add match selection only if archive size matters, preserving this exact decoder.
    """
    Cursor(data)
    if len(data) + (len(data) + 7) // 8 + 5 > MAX_BYTES:
        raise SnapshotError("compressed block exceeds limit")
    checksum = 0
    encoded = bytearray(5)
    for start in range(0, len(data), 8):
        group = data[start : start + 8]
        for value in group:
            checksum |= value
        encoded.append((1 << len(group)) - 1)
        encoded.extend(group)
    struct.pack_into("<IB", encoded, 0, len(data), checksum)
    return bytes(encoded)


def decompress(data: bytes) -> bytes:
    """DataDecode's 4096-byte LZSS ring, little-endian size and bytewise OR."""
    cursor = Cursor(data)
    expected, checksum = cursor.unpack("<IB")
    if expected > MAX_BYTES:
        raise SnapshotError("decompressed size exceeds limit")
    ring = bytearray(4096)
    initialized = bytearray(4096)
    write = 0xFEE
    result = bytearray()
    flags = 0
    while len(result) < expected:
        flags >>= 1
        if not flags & 0x100:
            flags = cursor.take(1)[0] | 0xFF00
        if flags & 1:
            values = cursor.take(1)
            ring[write] = values[0]
            initialized[write] = 1
            write = (write + 1) & 0xFFF
            result.extend(values)
        else:
            low, high = cursor.take(2)
            offset, length = low | ((high & 0xF0) << 4), (high & 0xF) + 3
            if length > expected - len(result):
                raise SnapshotError("LZSS match exceeds declared output size")
            for index in range(length):
                source = (offset + index) & 0xFFF
                if not initialized[source]:
                    raise SnapshotError(
                        "LZSS reference reads uninitialized native dictionary"
                    )
                value = ring[source]
                result.append(value)
                ring[write] = value
                initialized[write] = 1
                write = (write + 1) & 0xFFF
    cursor.end()
    actual = 0
    for value in result:
        actual |= value
    if checksum != actual:
        raise SnapshotError("DataCompress OR checksum mismatch")
    return bytes(result)


def _blob(cursor: Cursor, fmt: str = "<H") -> bytes:
    (size,) = cursor.unpack(fmt)
    return cursor.take(size)


def _pack_blob(data: bytes, fmt: str = "<H") -> bytes:
    Cursor(data)
    limit = 0xFFFF if fmt == "<H" else MAX_BYTES
    if len(data) > limit:
        raise SnapshotError("native blob exceeds its length field")
    return struct.pack(fmt, len(data)) + data


@dataclass(frozen=True)
class Flag:
    position: int
    label: bytes


@dataclass(frozen=True)
class MonitorBuffer:
    """CDmMonBuffInfo 0x8101; text encoding and marker clock remain opaque."""

    name: bytes
    information: bytes
    description: bytes
    frame_table: bytes
    signal_table: bytes
    ring_buffer: bytes
    marker: int
    flags: tuple[Flag, ...]
    selected_ids: tuple[int, ...]
    comment: bytes
    additional_ids: tuple[int, ...]

    def to_dict(self) -> dict:
        return {
            "name_hex": self.name.hex(),
            "information_hex": self.information.hex(),
            "description_hex": self.description.hex(),
            "frame_table_hex": self.frame_table.hex(),
            "signal_table_hex": self.signal_table.hex(),
            "ring_buffer_hex": self.ring_buffer.hex(),
            "marker": self.marker,
            "flags": [
                {"position": flag.position, "label_hex": flag.label.hex()}
                for flag in self.flags
            ],
            "selected_ids": list(self.selected_ids),
            "comment_hex": self.comment.hex(),
            "additional_ids": list(self.additional_ids),
            "provenance": "native-static-layout",
        }


def decode_monitor_buffer(payload: bytes) -> MonitorBuffer:
    cursor = Cursor(payload)
    name, information, description = (_blob(cursor) for _ in range(3))
    if len(information) != 16:
        raise SnapshotError("CDmMonBuffInfo information must contain 16 bytes")
    frame_table, signal_table, ring_buffer = (_blob(cursor, "<I") for _ in range(3))
    (marker,) = cursor.unpack("<I")
    (count,) = cursor.unpack("<H")
    flags = []
    for _ in range(count):
        (position,) = cursor.unpack("<I")
        flags.append(Flag(position, _blob(cursor)))
    (count,) = cursor.unpack("<I")
    if count > MAX_TABLES:
        raise SnapshotError("too many selected signal IDs")
    selected = tuple(cursor.unpack("<H")[0] for _ in range(count))
    comment = _blob(cursor)
    (count,) = cursor.unpack("<H")
    additional = tuple(cursor.unpack("<H")[0] for _ in range(count))
    cursor.end()
    return MonitorBuffer(
        name,
        information,
        description,
        frame_table,
        signal_table,
        ring_buffer,
        marker,
        tuple(flags),
        selected,
        comment,
        additional,
    )


def encode_monitor_buffer(record: MonitorBuffer) -> bytes:
    try:
        if len(record.information) != 16:
            raise SnapshotError("CDmMonBuffInfo information must contain 16 bytes")
        chunks = _ByteChunks(
            [
                _pack_blob(value)
                for value in (record.name, record.information, record.description)
            ]
        )
        chunks.extend(
            _pack_blob(value, "<I")
            for value in (record.frame_table, record.signal_table, record.ring_buffer)
        )
        chunks.append(struct.pack("<IH", record.marker, len(record.flags)))
        for flag in record.flags:
            chunks.append(struct.pack("<I", flag.position) + _pack_blob(flag.label))
        if len(record.selected_ids) > MAX_TABLES:
            raise SnapshotError("too many selected signal IDs")
        chunks.append(struct.pack("<I", len(record.selected_ids)))
        chunks.extend(struct.pack("<H", value) for value in record.selected_ids)
        chunks.append(_pack_blob(record.comment))
        chunks.append(struct.pack("<H", len(record.additional_ids)))
        chunks.extend(struct.pack("<H", value) for value in record.additional_ids)
        result = b"".join(chunks)
        Cursor(result)
        return result
    except (struct.error, TypeError, AttributeError) as exc:
        raise SnapshotError(f"invalid native monitor buffer: {exc}") from exc


def decode_signal_table(payload: bytes) -> dict:
    """DatMonCommon table envelope; item bytes keep their native version layout."""
    cursor = Cursor(payload)
    version, revision, count = cursor.unpack("<HHI")
    if count > MAX_TABLES:
        raise SnapshotError("too many signal-table items")
    items = [_blob(cursor, "<I").hex() for _ in range(count)]
    cursor.end()
    return {"version": version, "revision": revision, "items_hex": items}


def decode_frame_table(payload: bytes) -> dict:
    cursor = Cursor(payload)
    version, revision, count = cursor.unpack("<HHI")
    indexes = list(cursor.unpack("<256H"))
    lengths = list(cursor.unpack("<256H"))
    values = []
    if version > 1:
        (value_count,) = cursor.unpack("<I")
        if value_count > MAX_TABLES:
            raise SnapshotError("too many frame standard values")
        values = [list(cursor.unpack("<II")) for _ in range(value_count)]
    cursor.end()
    if count > 256:
        raise SnapshotError("frame count exceeds native 256-entry table")
    return {
        "version": version,
        "revision": revision,
        "count": count,
        "indexes": indexes,
        "lengths": lengths,
        "standard_values": values,
    }


def decode_ring_buffer(payload: bytes) -> dict:
    """DatMonCommon CRingBuffer serialized storage, without guessing packet clocks."""
    cursor = Cursor(payload)
    version, revision, phase, block_packets = cursor.unpack("<HHIH")
    if cursor.position == len(payload):
        return {
            "version": version,
            "revision": revision,
            "phase": phase,
            "block_packets": block_packets,
            "buffer_allocated": False,
            "image_hex": "",
        }
    capacity, available, start, read, write, written, size = cursor.unpack("<7I")
    if capacity > MAX_BYTES or size > MAX_BYTES:
        raise SnapshotError("ring image exceeds host byte limit")
    image = cursor.take(size)
    cursor.end()
    if any(value > capacity for value in (available, start, read)):
        raise SnapshotError("ring pointer or size exceeds capacity")
    normalized = start == read == 0 and write == written == size
    selected_size = capacity - available
    complement_size = size - selected_size
    # WriteInvalidArea appends a last-block copy without enlarging capacity.
    if (size > capacity or write > capacity or written > capacity) and (
        not normalized or not 4 < complement_size <= selected_size
    ):
        raise SnapshotError("ring pointer or size exceeds native serialized area")
    return {
        "version": version,
        "revision": revision,
        "phase": phase,
        "block_packets": block_packets,
        "capacity": capacity,
        "start": start,
        "read": read,
        "write": write,
        "written": written,
        "available": available,
        "image_hex": image.hex(),
    }


def monitor_packets(record: MonitorBuffer) -> list[dict]:
    """Recover raw timestamped packets using native phase 0/1 frame sizing.

    Timestamps retain uint32 source units. This does not interpolate or invent PID
    conversions: signal dictionaries and conversion evidence are separate inputs.
    """
    ring = decode_ring_buffer(record.ring_buffer)
    if ring.get("buffer_allocated") is False:
        return []
    frames = decode_frame_table(record.frame_table)
    if ring["phase"] not in (0, 1):
        raise SnapshotError("native packet sizing is supported only for phase 0/1")
    indexes = frames["indexes"][: frames["count"]]
    if ring["phase"] == 1:
        indexes = indexes[:1]
    if not indexes or any(index >= 256 for index in indexes):
        raise SnapshotError("invalid packet frame indexes")
    lengths = [frames["lengths"][index] for index in indexes]
    if any(length == 0 for length in lengths):
        raise SnapshotError("packet contains a zero-length frame")
    packet_size = 4 + sum(lengths)
    image = bytes.fromhex(ring["image_hex"])
    valid = ring["capacity"] - ring["available"]
    normalized = ring["start"] == ring["read"] == 0 and ring["write"] == ring[
        "written"
    ] == len(image)
    if normalized:
        if len(image) < valid:
            raise SnapshotError("normalized ring omits selected bytes")
        complement_size = len(image) - valid
        if complement_size and not 4 < complement_size <= valid:
            raise SnapshotError(
                "native ring complement references outside selected bytes"
            )
        valid = len(image)
    if valid % packet_size:
        if (
            len(image) == ring["written"] == ring["capacity"]
            and ring["available"] == 0
            and not (normalized and complement_size)
        ):
            # Native GetPacketCount truncates a saturated allocation's stale tail.
            valid -= valid % packet_size
        else:
            raise SnapshotError("recorded ring area ends inside a packet")
    if valid // packet_size > MAX_TABLES:
        raise SnapshotError("too many recorded packets")
    if valid and ring["capacity"] == 0:
        raise SnapshotError("recorded ring area has no capacity")
    start = ring["start"]
    if start == ring["capacity"]:
        start = 0
    if len(image) == ring["capacity"]:
        ordered = image[start:] + image[:start]
    elif start + valid <= len(image):
        # Native WriteInvalidArea emits only the normalized recorded area.
        ordered = image[start : start + valid]
    else:
        raise SnapshotError("recorded ring area references unserialized bytes")
    packets = decode_packet_stream(
        ordered[:valid], tuple(zip(indexes, lengths, strict=True))
    )
    if ring["phase"] == 1 and ring["block_packets"] > 1:
        # Serialized rings omit the live cache cursor needed to name these frames.
        for packet in packets:
            packet["payload_hex"] = packet["frames"][0]["data_hex"]
            packet["frames"] = []
            packet["frame_identity"] = "unresolved-native-slot"
    return packets


def decode_packet_stream(
    data: bytes, frame_layout: tuple[tuple[int, int], ...]
) -> list[dict]:
    """Decode native timestamp+frame packets from an explicitly sized raw stream.

    Each layout entry is (native frame index, byte length). This is only the
    DatMon packet grammar; callers establish their own record/container context.
    No DRS-specific header or timestamp unit is inferred.
    """
    cursor = Cursor(data)
    if not isinstance(frame_layout, tuple) or not 1 <= len(frame_layout) <= 256:
        raise SnapshotError("native packet requires 1..256 frame layout entries")
    for frame in frame_layout:
        if (
            not isinstance(frame, tuple)
            or len(frame) != 2
            or type(frame[0]) is not int
            or not 0 <= frame[0] < 256
            or type(frame[1]) is not int
            or not 1 <= frame[1] <= 0xFFFF
        ):
            raise SnapshotError("invalid native packet frame layout")
    packet_size = 4 + sum(length for _, length in frame_layout)
    if len(data) % packet_size:
        raise SnapshotError("native packet stream ends inside a packet")
    if len(data) // packet_size > MAX_TABLES:
        raise SnapshotError("too many recorded packets")
    if len(data) // packet_size * len(frame_layout) > MAX_TABLES:
        raise SnapshotError("decoded packet frame count exceeds host limit")
    packets = []
    while cursor.position < len(data):
        (timestamp,) = cursor.unpack("<I")
        packets.append(
            {
                "timestamp_raw": timestamp,
                "frames": [
                    {"index": index, "data_hex": cursor.take(length).hex()}
                    for index, length in frame_layout
                ],
            }
        )
    return packets


@dataclass(frozen=True)
class TSEFile:
    """Native TSE/TMM/TMR index import with lossless, unmodified re-export.

    Payload schemas not decoded here are explicitly reported, never interpreted
    as empty captures. source is retained so imported files can be preserved.
    """

    source: bytes
    kind: str
    version: int
    file_type: int
    revision: int
    metadata: dict
    body_offset: int

    def to_dict(self) -> dict:
        monitors = (
            tse_monitors(self)
            if any(
                feature in self.metadata["supported_feature_ids"]
                for feature in (0x2714, 0x2715, 0x2717, 0x2726, 0x2728)
            )
            else []
        )
        return {
            "format": f"native-{self.kind.lower()}",
            "version": self.version,
            "file_type": self.file_type,
            "revision": self.revision,
            "metadata": self.metadata,
            "body_offset": self.body_offset,
            "body_bytes": len(self.source) - self.body_offset,
            "coverage": "native-index-and-datalist"
            if monitors
            else "native-index-only",
            "monitor_count": len(monitors),
            "unsupported_feature_ids": [
                feature
                for feature in self.metadata["supported_feature_ids"]
                if feature not in (0x2714, 0x2715, 0x2717, 0x2726, 0x2728)
            ],
            "unsupported": [
                "TSE report-family payload interpretation",
                "dual-ECU clock alignment",
            ],
            "provenance": "native-static-layout",
        }


_TSE_ECU_FIELDS = (
    ("EcuData", 4096),
    ("DataList", 4096),
    ("DTCMon", 4096),
    ("DTCP5", 4128),
    ("ATest", 4096),
    ("ATestD", 4110),
    ("DrvRec", 4096),
    ("SysChk", 4096),
    ("FuelCon", 4100),
    ("OpeHis", 4101),
    ("ROB", 4102),
    ("Oscillo", 4109),
    ("ABSHis", 4110),
    ("ICSHis", 4115),
    ("AFO2Sn", 4116),
)
_TSE_GLOBAL_LATE_FIELDS = (
    ("MktMonRam", 4135),
    ("MktMonRamSSR", 4140),
    ("TMRRep", 4139),
)
_TSE_GLOBAL_FIELDS = (
    ("IniCarInfo", 4096),
    ("ConfCarInfo", 4096),
    ("MultiPID", 4103),
    ("FuncName", 4103),
    ("HealthCheck", 4096),
    ("TimeStamp", 4101),
    ("ROBCommon", 4102),
    ("MILMessage", 4099),
    ("CanBus", 4103),
    ("DualData", 4104),
    ("DDRData", 4114),
    ("OpeFFD", 4131),
    ("ImgFFD", 4131),
    ("ECUInfo", 4096),
)
_TSE_ECU_LATE_FIELDS = (("PSDHis", 4134), ("PreFFD", 4135), ("OpeInope", 4138))


@dataclass(frozen=True)
class TSEHeader:
    """Explicit native header inputs; absent versioned fields must be None."""

    kind: str
    file_type: int
    version: int
    revision: int
    systems_mask: int
    unknown: int
    language: int | None
    field_30: bytes | None
    field_44: bytes | None
    ecu_ids: tuple[int, ...]
    feature_ids: tuple[int, ...]
    reserved: bytes


def create_tse_header(header: TSEHeader) -> TSEFile:
    """Construct the original native prefix for assemble_tse, without a template.

    Every metadata value is supplied explicitly. This creates an index prefix;
    actual ECUInfo/EcuData/report/monitor bytes are supplied to assemble_tse.
    Legacy systems_mask must agree with the declared feature bits. Modern
    versions retain the caller's independent systems_mask and use an 80-byte
    feature bitmap. No locale, vehicle profile or timestamp is inferred.
    """
    if not isinstance(header, TSEHeader) or header.kind not in ("TSE", "TMM", "TMR"):
        raise SnapshotError("expected explicit native TSE/TMM/TMR header")
    for value, maximum in (
        (header.file_type, 0xFFFFFFFF),
        (header.version, 0xFFFF),
        (header.revision, 0xFFFF),
        (header.systems_mask, 0xFFFFFFFF),
        (header.unknown, 0xFFFFFFFF),
    ):
        if type(value) is not int or not 0 <= value <= maximum:
            raise SnapshotError("native header integer is outside its wire width")
    version = header.version
    if not 0x1000 <= version <= 0x102C:
        raise SnapshotError("unsupported native TSE index version")
    if not isinstance(header.ecu_ids, tuple) or len(header.ecu_ids) > 4096:
        raise SnapshotError("invalid native ECU identifier collection")
    if any(
        type(value) is not int or not 0 <= value <= 0xFFFF for value in header.ecu_ids
    ):
        raise SnapshotError("native ECU identifiers must fit uint16")
    if len(set(header.ecu_ids)) != len(header.ecu_ids):
        raise SnapshotError("new native headers require distinct ECU identifiers")
    if not isinstance(header.feature_ids, tuple):
        raise SnapshotError("native feature identifiers must be a tuple")
    maximum_feature = 0x2711 + (32 if version <= 0x1026 else 640)
    if any(
        type(value) is not int or not 0x2711 <= value < maximum_feature
        for value in header.feature_ids
    ):
        raise SnapshotError("native feature does not fit this version's bitmap")
    if len(set(header.feature_ids)) != len(header.feature_ids):
        raise SnapshotError("native feature identifiers must be distinct")
    bitmap = bytearray(80)
    legacy = 0
    for feature in header.feature_ids:
        bit = feature - 0x2711
        bitmap[bit // 8] |= 0x80 >> (bit % 8)
        if bit < 32:
            legacy |= 1 << bit
    if version <= 0x1026 and header.systems_mask != legacy:
        raise SnapshotError("legacy systems_mask disagrees with declared features")
    if not isinstance(header.reserved, bytes) or len(header.reserved) != (
        80 if version <= 0x1026 else 0
    ):
        raise SnapshotError("invalid versioned native header reserved bytes")
    chunks = _ByteChunks(
        [
            b"\x9aS\xdb\x12" + header.kind.encode("ascii") + b"\0",
            struct.pack(
                "<IHHII",
                header.file_type,
                version,
                header.revision,
                header.systems_mask,
                header.unknown,
            ),
        ]
    )
    if version >= 0x1006:
        if type(header.language) is not int or not 0 <= header.language <= 0xFFFF:
            raise SnapshotError("native header language word is required")
        chunks.append(struct.pack("<H", header.language))
    elif header.language is not None:
        raise SnapshotError("this native header version has no language field")
    for value, minimum in ((header.field_30, 0x1007), (header.field_44, 0x100F)):
        if version >= minimum:
            if not isinstance(value, bytes):
                raise SnapshotError("versioned native header byte string is required")
            chunks.append(_pack_blob(value))
        elif value is not None:
            raise SnapshotError("unexpected byte string for this native header version")

    def field(name: str, minimum: int = 0x1000) -> None:
        if version >= 0x1024:
            chunks.append(name.encode("ascii").ljust(12, b"\0")[:12])
        if version >= minimum:
            chunks.append(bytes(4))

    for name, minimum in _TSE_GLOBAL_FIELDS:
        field(name, minimum)
    chunks.append(struct.pack("<H", len(header.ecu_ids)))
    for identifier in header.ecu_ids:
        suffix = f"{identifier:04d}" if version >= 0x1024 else ""
        for name, minimum in _TSE_ECU_FIELDS:
            field(name + suffix, minimum)
        for name, minimum in _TSE_ECU_LATE_FIELDS:
            if version >= minimum:
                field(name + suffix)
    for name, minimum in _TSE_GLOBAL_LATE_FIELDS:
        if version >= minimum:
            field(name)
    field("ErrRep")
    chunks.append(header.reserved if version <= 0x1026 else bytes(bitmap))
    return parse_tse(b"".join(chunks))


def parse_tse(data: bytes) -> TSEFile:
    """Decode the original GTSFileController versioned index, not its opaque body."""
    cursor = Cursor(data)
    signature = cursor.take(8)
    if signature[:4] != b"\x9aS\xdb\x12" or signature[4:] not in (
        b"TSE\0",
        b"TMM\0",
        b"TMR\0",
    ):
        raise SnapshotError("unsupported native TSE signature")
    file_type, version, revision = cursor.unpack("<IHH")
    if not 0x1000 <= version <= 0x102C:
        raise SnapshotError("unsupported native TSE index version")
    systems_mask, unknown = cursor.unpack("<II")
    language = cursor.unpack("<H")[0] if version >= 0x1006 else None
    strings = {}
    if version >= 0x1007:
        strings["field_30_hex"] = _blob(cursor).hex()
    if version >= 0x100F:
        strings["field_44_hex"] = _blob(cursor).hex()

    index_entries = []

    def field(name: str, minimum: int = 0x1000) -> int | None:
        # Native version 0x1024 added tags even for older, absent fields.
        if version >= 0x1024:
            tag = cursor.take(12)
            expected = name.encode("ascii").ljust(12, b"\0")[:12]
            if tag != expected:
                raise SnapshotError(
                    f"unexpected native index tag {tag!r}, expected {expected!r}"
                )
        if version < minimum:
            return None
        position = cursor.position
        value = cursor.unpack("<I")[0]
        index_entries.append({"tag": name, "position": position, "offset": value})
        return value

    globals_ = {name: field(name, minimum) for name, minimum in _TSE_GLOBAL_FIELDS}
    (count,) = cursor.unpack("<H")
    if count > 4096:
        raise SnapshotError("ECU index exceeds the host limit of 4096 entries")
    ecus = []
    fields = _TSE_ECU_FIELDS
    for _ in range(count):
        suffix = ""
        ecu = {}
        if version >= 0x1024:
            tag = cursor.take(12)
            match = re.fullmatch(rb"EcuData([0-9]{4,5})\x00*", tag)
            if match is None:
                raise SnapshotError("invalid native ECU index tag")
            suffix = match[1].decode("ascii")
            position = cursor.position
            ecu["EcuData"] = cursor.unpack("<I")[0]
            ecu["ecu_id_raw"] = int(suffix)
            index_entries.append(
                {
                    "tag": "EcuData" + suffix,
                    "position": position,
                    "offset": ecu["EcuData"],
                }
            )
            remaining = fields[1:]
        else:
            remaining = fields
        for name, minimum in remaining:
            ecu[name] = field(f"{name}{suffix}", minimum)
        for name, minimum in _TSE_ECU_LATE_FIELDS:
            if version >= minimum:
                ecu[name] = field(f"{name}{suffix}")
        ecus.append(ecu)
    for name, minimum in _TSE_GLOBAL_LATE_FIELDS:
        if version >= minimum:
            globals_[name] = field(name)
    globals_["ErrRep"] = field("ErrRep")
    reserved = cursor.take(80) if version <= 0x1026 else b""
    if version > 0x1026:
        supported = cursor.take(80)
    else:
        # FUN_1009a680 converts the legacy low-bit-first DWORD to MSB-first bytes.
        supported = bytes(
            sum(
                ((systems_mask >> (byte * 8 + bit)) & 1) << (7 - bit)
                for bit in range(8)
            )
            for byte in range(4)
        ) + bytes(76)
    features = [
        0x2711 + byte * 8 + bit
        for byte, value in enumerate(supported)
        for bit in range(8)
        if value & (0x80 >> bit)
    ]
    for entry in index_entries:
        if entry["offset"] and not cursor.position <= entry["offset"] <= len(data):
            raise SnapshotError(f"native index offset outside body: {entry['tag']}")
    return TSEFile(
        data,
        signature[4:7].decode("ascii"),
        version,
        file_type,
        revision,
        {
            "index_entries": index_entries,
            "systems_mask": systems_mask,
            "field_28": unknown,
            "language_raw": language,
            **strings,
            "global_index": globals_,
            "ecu_index": ecus,
            "reserved_hex": reserved.hex(),
            "supported_feature_ids": features,
        },
        cursor.position,
    )


def decode_system_information(payload: bytes) -> dict:
    """CDmSystemInfo 0x8100: DWORD, two CCmdString objects, WORD."""
    cursor = Cursor(payload)
    (identifier,) = cursor.unpack("<I")
    strings = []
    for _ in range(2):
        first, second = cursor.unpack("<HH")
        strings.append({"core": [first, second], "data_hex": _blob(cursor).hex()})
    (value,) = cursor.unpack("<H")
    cursor.end()
    return {"identifier": identifier, "strings": strings, "value_raw": value}


def encode_system_information(record: dict) -> bytes:
    try:
        if len(record["strings"]) != 2:
            raise SnapshotError("native system record requires two strings")
        chunks = _ByteChunks([struct.pack("<I", record["identifier"])])
        for value in record["strings"]:
            first, second = value["core"]
            chunks.append(struct.pack("<HH", first, second))
            chunks.append(_pack_blob(bytes.fromhex(value["data_hex"])))
        chunks.append(struct.pack("<H", record["value_raw"]))
        result = b"".join(chunks)
        Cursor(result)
        return result
    except (KeyError, ValueError, struct.error, TypeError) as exc:
        raise SnapshotError(f"invalid native system information: {exc}") from exc


@dataclass(frozen=True)
class SignalItem:
    version: int
    revision: int
    pid: int
    frame_index: int
    start_bit: int
    end_bit: int
    name: bytes
    short_name: bytes
    unit: bytes
    selector: int
    unit_id: int
    sign_mode: int
    multiplier: int
    divisor: int
    offset: int
    precision: int
    minimum_raw: int
    maximum_raw: int
    patterns: tuple[tuple[int, bytes, int, int], ...]
    extended: tuple[int, int, int] | None

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "revision": self.revision,
            "pid": self.pid,
            "frame_index": self.frame_index,
            "start_bit": self.start_bit,
            "end_bit": self.end_bit,
            "name_hex": self.name.hex(),
            "short_name_hex": self.short_name.hex(),
            "unit_hex": self.unit.hex(),
            "selector": self.selector,
            "unit_id": self.unit_id,
            "sign_mode": self.sign_mode,
            "multiplier": self.multiplier,
            "divisor": self.divisor,
            "offset": self.offset,
            "precision": self.precision,
            "minimum_raw": self.minimum_raw,
            "maximum_raw": self.maximum_raw,
            "patterns": [
                [value, label.hex(), low, high]
                for value, label, low, high in self.patterns
            ],
            "extended": list(self.extended) if self.extended is not None else None,
        }


def decode_signal_item(payload: bytes) -> SignalItem:
    cursor = Cursor(payload)
    version, revision, pid = cursor.unpack("<HHH")
    if not 1 <= version <= 4:
        raise SnapshotError("unsupported native SignalItem version")
    (frame_index,) = cursor.unpack("<H" if version >= 4 else "<B")
    start, end = cursor.unpack("<HH")
    name, short_name, unit = (_blob(cursor) for _ in range(3))
    (
        selector,
        unit_id,
        sign_mode,
        multiplier,
        divisor,
        offset,
        precision,
        minimum,
        maximum,
        count,
    ) = cursor.unpack("<HHBiiiHIII")
    if count > MAX_TABLES:
        raise SnapshotError("too many signal display patterns")
    patterns = []
    for _ in range(count):
        (value,) = cursor.unpack("<I")
        label = _blob(cursor)
        low, high = cursor.unpack("<II")
        patterns.append((value, label, low, high))
    extended = None
    if version > 1:
        (identifier,) = cursor.unpack("<H" if version == 2 else "<I")
        low, high = cursor.unpack("<II")
        extended = (identifier, low, high)
    cursor.end()
    return SignalItem(
        version,
        revision,
        pid,
        frame_index,
        start,
        end,
        name,
        short_name,
        unit,
        selector,
        unit_id,
        sign_mode,
        multiplier,
        divisor,
        offset,
        precision,
        minimum,
        maximum,
        tuple(patterns),
        extended,
    )


def encode_signal_item(record: SignalItem) -> bytes:
    try:
        if not 1 <= record.version <= 4 or len(record.patterns) > MAX_TABLES:
            raise SnapshotError("unsupported signal version or pattern count")
        chunks = _ByteChunks(
            [
                struct.pack("<HHH", record.version, record.revision, record.pid),
                struct.pack("<H" if record.version >= 4 else "<B", record.frame_index),
                struct.pack("<HH", record.start_bit, record.end_bit),
            ]
        )
        chunks.extend(
            _pack_blob(value) for value in (record.name, record.short_name, record.unit)
        )
        chunks.append(
            struct.pack(
                "<HHBiiiHIII",
                record.selector,
                record.unit_id,
                record.sign_mode,
                record.multiplier,
                record.divisor,
                record.offset,
                record.precision,
                record.minimum_raw,
                record.maximum_raw,
                len(record.patterns),
            )
        )
        for value, label, low, high in record.patterns:
            chunks.extend(
                (
                    struct.pack("<I", value),
                    _pack_blob(label),
                    struct.pack("<II", low, high),
                )
            )
        if record.version > 1:
            if record.extended is None:
                raise SnapshotError("extended signal fields required for version > 1")
            identifier, low, high = record.extended
            chunks.append(
                struct.pack("<H" if record.version == 2 else "<I", identifier)
            )
            chunks.append(struct.pack("<II", low, high))
        elif record.extended is not None:
            raise SnapshotError("version 1 has no extended signal fields")
        result = b"".join(chunks)
        Cursor(result)
        return result
    except (struct.error, TypeError, AttributeError, ValueError) as exc:
        raise SnapshotError(f"invalid native signal item: {exc}") from exc


def recorded_bits(payload: bytes, start: int, end: int, baseline: int = 0) -> int:
    """DatMonCommon GetRealData RVA 0x2d20 DWORD assembly and subtraction.

    This differs from the live CommandCommon bit extractor for narrow fields
    crossing a byte boundary and for five-byte source windows. x86 shifts wrap
    their count modulo 32, and the final right shift is signed.
    """
    if not 0 <= start <= end < len(payload) * 8 or end - start >= 32:
        raise SnapshotError("invalid recorded signal bit range")
    first, last = start // 8, end // 8
    assembled = 0
    for index in range(first, last + 1):
        assembled |= payload[index] << (((last - index) * 8) & 31)
    assembled &= 0xFFFFFFFF
    signed = assembled if assembled < 0x80000000 else assembled - 0x100000000
    value = (signed >> (7 - end % 8)) & ((1 << (end - start + 1)) - 1)
    return (value - baseline) & 0xFFFFFFFF


def monitor_samples(record: MonitorBuffer, *, encoding: str = "latin1") -> list[dict]:
    """Plot adapter joining serialized native signal metadata to recorded frames.

    Latin-1 is a reversible display policy, not a claim about the OEM locale.
    Raw names/units remain in signal reports; timestamps keep native source units.
    """
    try:
        from .signal_display import render_signal
    except ImportError:
        from signal_display import render_signal
    table = decode_signal_table(record.signal_table)
    standards = {}
    frame_layout = decode_frame_table(record.frame_table)
    for key, value in frame_layout["standard_values"]:
        standards.setdefault(key, value)
    signals = []
    metadata_count = 0
    for value in table["items_hex"]:
        signal = decode_signal_item(bytes.fromhex(value))
        metadata_count += 1 + len(signal.patterns)
        if metadata_count > MAX_TABLES:
            raise SnapshotError("decoded signal metadata count exceeds host limit")
        signals.append(signal)
    packets = monitor_packets(record)
    ring = decode_ring_buffer(record.ring_buffer)
    block_packets = ring["block_packets"]
    gui_phase_one = ring["phase"] == 1 and block_packets > 1
    if block_packets > 8:
        raise SnapshotError("native GUI packet slot count exceeds its eight-slot table")
    if block_packets == 0:
        packets = []
    elif block_packets > 1:
        grouped = []
        for end in range(block_packets, len(packets) + 1, block_packets):
            last = packets[end - 1]
            # GUI SetPacket slots alias one buffer; uint32 time sums wrap before DIV.
            grouped.append(
                {
                    "timestamp_raw": (
                        (last["timestamp_raw"] * block_packets) & 0xFFFFFFFF
                    )
                    // block_packets,
                    "frames": (
                        [
                            {
                                "index": frame_layout["indexes"][0],
                                "data_hex": last["payload_hex"],
                            }
                        ]
                        if gui_phase_one
                        else last["frames"]
                    ),
                }
            )
        packets = grouped
    if len(signals) * len(packets) > MAX_TABLES:
        raise SnapshotError("decoded sample value count exceeds host limit")
    if metadata_count * len(packets) > MAX_TABLES:
        raise SnapshotError("decoded display work exceeds host limit")
    # Decode labels once, so a long name/pattern reused by many packets remains
    # one string rather than amplifying a small recording into gigabytes.
    descriptors = [
        (
            signal,
            signal.name.rstrip(b"\0").decode(encoding),
            signal.unit.rstrip(b"\0").decode(encoding),
            tuple(
                # Serialized first DWORD is a shared pattern ID. Native
                # GetString compares object+1c, our serialized `low` DWORD.
                (match, label.rstrip(b"\0").decode(encoding), 0, high)
                for _identifier, label, match, high in signal.patterns
            ),
        )
        for signal in signals
    ]
    # Bound repeated text in the JSON-ready report too, not only shared Python
    # objects. Twelve bytes covers JSON surrogate escaping of one code point.
    text_budget = sum(
        1024
        + 12
        * (
            len(name)
            + len(unit)
            + max((len(label) for _, label, _, _ in patterns), default=0)
        )
        for _, name, unit, patterns in descriptors
    ) * len(packets)
    if text_budget > MAX_BYTES:
        raise SnapshotError("decoded sample report text exceeds host limit")
    samples = []
    for packet in packets:
        frames = {
            frame["index"]: bytes.fromhex(frame["data_hex"])
            for frame in packet["frames"]
        }
        if len(frames) != len(packet["frames"]):
            raise SnapshotError("recorded signal has ambiguous duplicate frame indexes")
        values = []
        for signal, name, unit, patterns in descriptors:
            if signal.precision > 9 or signal.selector > 255:
                raise SnapshotError("unsupported signal precision or selector")
            if signal.frame_index not in frames:
                if gui_phase_one:
                    values.append(
                        {
                            "pid": str(signal.pid),
                            "name": name,
                            "unit": unit,
                            "raw_bits": None,
                            "baseline_raw": standards.get(signal.pid, 0),
                            "raw": None,
                            "scaled_integer": None,
                            "display": "Unavailable",
                            "kind": "unknown",
                            "status": "unavailable-native-frame",
                            "selector": signal.selector,
                            "precision": signal.precision,
                            "display_words_raw": None,
                            "display_word_source": None,
                            "value": None,
                        }
                    )
                    continue
                raise SnapshotError(f"signal {signal.pid} refers to an absent frame")
            try:
                raw_bits = recorded_bits(
                    frames[signal.frame_index], signal.start_bit, signal.end_bit
                )
                # Native GUI passes SignalItem PID to SetExtractInfo(KGG);
                # CalcPickUpField 0x2ba0 selects the first matching standard.
                baseline = standards.get(signal.pid, 0)
                raw = (raw_bits - baseline) & 0xFFFFFFFF
                rendered = render_signal(
                    raw,
                    selector=signal.selector,
                    sign_mode=signal.sign_mode,
                    bits=signal.end_bit - signal.start_bit + 1,
                    multiplier=signal.multiplier,
                    divisor=signal.divisor,
                    offset=signal.offset,
                    precision=signal.precision,
                    patterns=patterns,
                    # GUI 0x5747db..0x574810 maps extended runtime64/68
                    # to ConvertData metadata30/34. Runtime5c/60 are separate.
                    # Version1 leaves constructor defaults64=1,68=0 intact.
                    minimum_raw=signal.extended[1] if signal.extended else 1,
                    maximum_raw=signal.extended[2] if signal.extended else 0,
                    extended=(signal.extended,) if signal.extended is not None else (),
                    # Recorded monitor main table 0x4e22ec and selected sample
                    # details 0x574810/5748d6 explicitly pass words6/7 as zero.
                    # This is their display behavior, not raw64 extraction.
                    raw_words=(0, 0) if signal.selector == 29 else None,
                )
                scaled = rendered["value"]
                value = (
                    (
                        scaled
                        if signal.selector in (28, 29)
                        else scaled / 10**signal.precision
                    )
                    if scaled is not None
                    else None
                )
            except (ValueError, OverflowError, ZeroDivisionError) as exc:
                raise SnapshotError(
                    f"signal {signal.pid} conversion failed: {exc}"
                ) from exc
            values.append(
                {
                    "pid": str(signal.pid),
                    "name": name,
                    "unit": unit,
                    "raw_bits": raw_bits,
                    "baseline_raw": baseline,
                    "raw": raw,
                    "scaled_integer": scaled if type(scaled) is int else None,
                    "display": rendered["display"],
                    "kind": rendered["kind"],
                    "status": rendered["status"],
                    "selector": signal.selector,
                    "precision": signal.precision,
                    "display_words_raw": [0, 0] if signal.selector == 29 else None,
                    "display_word_source": (
                        "native-recorded-monitor-zero-arguments"
                        if signal.selector == 29
                        else None
                    ),
                    "value": value,
                }
            )
        samples.append({"timestamp_raw": packet["timestamp_raw"], "values": values})
    return samples


def playback(
    snapshot: TableFile | TSEFile, buffer_index: int = 0, *, encoding: str = "latin1"
) -> dict:
    """Return recorded samples and plot data; never contact an ECU."""
    if isinstance(snapshot, TSEFile):
        records = tse_monitors(snapshot)
        if type(buffer_index) is not int or not 0 <= buffer_index < len(records):
            raise SnapshotError("native TSE DataList monitor buffer does not exist")
        item = records[buffer_index]
        record = item["record"].monitor
        return {
            "format": "native-tse",
            "buffer_index": buffer_index,
            "ecu_id_raw": item["ecu_id_raw"],
            "family": item["family"],
            "record_index": item["record_index"],
            "timestamp_units": "native-raw-unknown",
            "interpolation": "none",
            "signals": [
                decode_signal_item(bytes.fromhex(value)).to_dict()
                for value in decode_signal_table(record.signal_table)["items_hex"]
            ],
            "samples": monitor_samples(record, encoding=encoding),
            "flags": [
                {"position_raw": flag.position, "label_hex": flag.label.hex()}
                for flag in record.flags
            ],
            "marker_raw": record.marker,
            "provenance": "native-static-layout",
        }
    buffers = [table for table in snapshot.tables if table.id == 0x8101]
    if (
        snapshot.magic != DM_MAGIC
        or type(buffer_index) is not int
        or not 0 <= buffer_index < len(buffers)
    ):
        raise SnapshotError("native DM monitor buffer does not exist")
    record = decode_monitor_buffer(buffers[buffer_index].payload)
    return {
        "format": "native-dm",
        "buffer_index": buffer_index,
        "timestamp_units": "native-raw-unknown",
        "interpolation": "none",
        "signals": [
            decode_signal_item(bytes.fromhex(value)).to_dict()
            for value in decode_signal_table(record.signal_table)["items_hex"]
        ],
        "samples": monitor_samples(record, encoding=encoding),
        "flags": [
            {"position_raw": flag.position, "label_hex": flag.label.hex()}
            for flag in record.flags
        ],
        "marker_raw": record.marker,
        "provenance": "native-static-layout",
    }


def _read_active_metadata(cursor: Cursor, version: int) -> dict:
    """ActiveTest saved command descriptors; never execute these commands.

    GTSFileController 0x100838a0/83c10/83ea0/84310, with physical
    descriptors at 0x1007fe90/83280 and byte lists at 0x10081180.
    """
    identifier = cursor.unpack("<I")[0]
    name = _blob(cursor)
    extra = cursor.unpack("<I")[0] if version > 0x1007 else None
    description = _blob(cursor)
    operations = []
    for _ in range(cursor.unpack("<H")[0]):
        values = cursor.unpack("<II")
        parameters = []
        for _ in range(cursor.unpack("<H")[0]):
            pair = cursor.unpack("<II")
            label = _blob(cursor)
            limits = cursor.unpack("<II")
            parameters.append(
                {"values_raw": pair, "label_hex": label.hex(), "limits_raw": limits}
            )
        operations.append({"values_raw": values, "parameters": parameters})
    signals = []
    for _ in range(cursor.unpack("<H")[0]):
        signal_id = cursor.unpack("<I")[0]
        label = _blob(cursor)
        modes = cursor.unpack("<BB")
        descriptors = []
        for command in (False, True):
            core = cursor.take(17)
            items = []
            for _ in range(cursor.unpack("<H")[0]):
                item_id = cursor.unpack("<I")[0]
                item_label = _blob(cursor)
                if command:
                    body = {
                        "request_hex": _blob(cursor).hex(),
                        "response_hex": _blob(cursor).hex(),
                    }
                else:
                    body = {"limits_raw": cursor.unpack("<II")}
                items.append(
                    {
                        "id_raw": item_id,
                        "label_hex": item_label.hex(),
                        **body,
                        "mode_raw": cursor.unpack("<B")[0],
                    }
                )
            descriptors.append(
                {
                    "core_hex": core.hex(),
                    "items": items,
                    "tail_hex": cursor.take(16).hex(),
                }
            )
        signals.append(
            {
                "id_raw": signal_id,
                "label_hex": label.hex(),
                "modes_raw": modes,
                "descriptors": descriptors,
            }
        )
    tail = cursor.unpack("<IH")
    final = None
    if version >= 0x1021:
        final = {
            "value_raw": cursor.unpack("<I")[0],
            "ids": [cursor.unpack("<H")[0] for _ in range(cursor.unpack("<H")[0])],
        }
    return {
        "id_raw": identifier,
        "name_hex": name.hex(),
        "extra_raw": extra,
        "description_hex": description.hex(),
        "operations": operations,
        "signals": signals,
        "tail_raw": tail,
        "final": final,
    }


def decode_active_metadata(data: bytes, version: int) -> dict:
    """Inspect saved ActiveTest descriptors, retaining uninterpreted enum values."""
    if not 0x1007 <= version <= 0x1027:
        raise SnapshotError("unsupported native active metadata version")
    cursor = Cursor(data)
    result = _read_active_metadata(cursor, version)
    cursor.end()
    return result


@dataclass(frozen=True)
class TSEDataList:
    monitor: MonitorBuffer
    selected_pairs: tuple[tuple[int, int], ...]
    display_mode_raw: int | None
    views: tuple[bytes, ...]
    chart: bytes
    reserved: bytes
    active_metadata: bytes = b""


@dataclass(frozen=True)
class TSEDataListSection:
    identifier: int
    type_raw: int
    version: int
    records: tuple[TSEDataList, ...]


def _read_tse_datalist(
    cursor: Cursor, version: int, active: bool = False
) -> TSEDataList:
    name, information, description = (_blob(cursor) for _ in range(3))
    if len(information) > 16:
        raise SnapshotError("native common date/information field exceeds 16 bytes")
    frame, signals, ring = (_blob(cursor, "<I") for _ in range(3))
    (marker,) = cursor.unpack("<I")
    (count,) = cursor.unpack("<H")
    flags = []
    for _ in range(count):
        (position,) = cursor.unpack("<I")
        flags.append(Flag(position, _blob(cursor)))
    (count,) = cursor.unpack("<H")
    selected = tuple(cursor.unpack("<H")[0] for _ in range(count))
    (count,) = cursor.unpack("<H")
    pairs = tuple(
        cursor.unpack("<HI" if version >= 0x1006 else "<HH") for _ in range(count)
    )
    comment = _blob(cursor)
    mode = cursor.unpack("<H")[0] if version >= 0x1004 else None
    (count,) = cursor.unpack("<H")
    additional = tuple(cursor.unpack("<H")[0] for _ in range(count))
    views = ()
    chart = b""
    if version >= 0x1002:
        (count,) = cursor.unpack("<H")
        views = tuple(
            cursor.take(84 if version >= 0x1004 else 82) for _ in range(count)
        )
        chart = cursor.take(90 if version >= 0x1003 else 54)
    start = cursor.position
    if active and version > 0x1006:
        _read_active_metadata(cursor, version)
    active_metadata = cursor.data[start : cursor.position]
    reserved = cursor.take(80)
    monitor = MonitorBuffer(
        name,
        information,
        description,
        frame,
        signals,
        ring,
        marker,
        tuple(flags),
        selected,
        comment,
        additional,
    )
    return TSEDataList(monitor, pairs, mode, views, chart, reserved, active_metadata)


def decode_tse_datalist_section(data: bytes) -> TSEDataListSection:
    """Strict native DataList section, at its original section boundary.

    GTSFileController 0x1008e1c0 -> 0x1008e2a0 -> 0x1008e6a0.
    This is a native body codec, independent of locating sections in a TSE file.
    """
    cursor = Cursor(data)
    identifier, type_raw, version, count = cursor.unpack("<IIHH")
    if (
        identifier != 0xFFFFFFFF
        or type_raw not in (0xFFFFFF05, 0xFFFFFF07, 0xFFFFFF08)
        or not 0x1000 <= version <= 0x1021
    ):
        raise SnapshotError("unsupported native DataList section header")
    records = tuple(
        _read_tse_datalist(cursor, version, type_raw == 0xFFFFFF07)
        for _ in range(count)
    )
    cursor.end()
    return TSEDataListSection(identifier, type_raw, version, records)


def encode_tse_datalist_section(section: TSEDataListSection) -> bytes:
    try:
        if (
            section.identifier != 0xFFFFFFFF
            or section.type_raw not in (0xFFFFFF05, 0xFFFFFF07, 0xFFFFFF08)
            or not 0x1000 <= section.version <= 0x1021
        ):
            raise SnapshotError("unsupported native DataList section header")
        chunks = _ByteChunks(
            [
                struct.pack(
                    "<IIHH",
                    section.identifier,
                    section.type_raw,
                    section.version,
                    len(section.records),
                )
            ]
        )
        for record in section.records:
            monitor = record.monitor
            if len(monitor.information) > 16 or len(record.reserved) != 80:
                raise SnapshotError("invalid common information or reserved bytes")
            chunks.extend(
                _pack_blob(value)
                for value in (monitor.name, monitor.information, monitor.description)
            )
            chunks.extend(
                _pack_blob(value, "<I")
                for value in (
                    monitor.frame_table,
                    monitor.signal_table,
                    monitor.ring_buffer,
                )
            )
            chunks.append(struct.pack("<IH", monitor.marker, len(monitor.flags)))
            for flag in monitor.flags:
                chunks.append(struct.pack("<I", flag.position) + _pack_blob(flag.label))
            chunks.append(struct.pack("<H", len(monitor.selected_ids)))
            chunks.extend(struct.pack("<H", value) for value in monitor.selected_ids)
            chunks.append(struct.pack("<H", len(record.selected_pairs)))
            chunks.extend(
                struct.pack("<HI" if section.version >= 0x1006 else "<HH", *pair)
                for pair in record.selected_pairs
            )
            chunks.append(_pack_blob(monitor.comment))
            if section.version >= 0x1004:
                chunks.append(struct.pack("<H", record.display_mode_raw))
            elif record.display_mode_raw is not None:
                raise SnapshotError("legacy DataList has no display mode field")
            chunks.append(struct.pack("<H", len(monitor.additional_ids)))
            chunks.extend(struct.pack("<H", value) for value in monitor.additional_ids)
            if section.version >= 0x1002:
                if len(record.chart) != (90 if section.version >= 0x1003 else 54):
                    raise SnapshotError("invalid native chart configuration size")
                chunks.append(struct.pack("<H", len(record.views)))
                for view in record.views:
                    if len(view) != (84 if section.version >= 0x1004 else 82):
                        raise SnapshotError("invalid native view configuration size")
                    chunks.append(view)
                chunks.append(record.chart)
            elif record.chart or record.views:
                raise SnapshotError("legacy DataList has no chart/view fields")
            if section.type_raw == 0xFFFFFF07 and section.version > 0x1006:
                decode_active_metadata(record.active_metadata, section.version)
                chunks.append(record.active_metadata)
            elif record.active_metadata:
                raise SnapshotError("this native section has no active metadata")
            chunks.append(record.reserved)
        result = b"".join(chunks)
        Cursor(result)
        return result
    except (struct.error, TypeError, ValueError, AttributeError) as exc:
        raise SnapshotError(f"invalid native DataList section: {exc}") from exc


def tse_section(snapshot: TSEFile, offset: int) -> bytes:
    """Use native absolute index boundaries, preserving unsupported families."""
    if type(offset) is not int or not snapshot.body_offset <= offset <= len(
        snapshot.source
    ):
        raise SnapshotError("invalid native TSE section offset")
    offsets = [
        entry["offset"]
        for entry in snapshot.metadata["index_entries"]
        if entry["offset"] > offset
    ]
    end = min(offsets, default=len(snapshot.source))
    return snapshot.source[offset:end]


def tse_monitors(snapshot: TSEFile) -> list[dict]:
    families = [
        ("DataList", 0x2714, 0xFFFFFF05),
        ("DrvRec", 0x2715, 0xFFFFFF08),
        ("ATest", 0x2717, 0xFFFFFF07),
    ]
    supported = snapshot.metadata["supported_feature_ids"]
    if not any(
        feature in supported for feature in (0x2714, 0x2715, 0x2717, 0x2726, 0x2728)
    ):
        raise SnapshotError("native TSE has no recovered monitor feature")
    result = []
    record_count = 0
    section_cache: dict[tuple[int, int], TSEDataListSection | DualSection] = {}
    # Resolve boundaries once. Re-scanning the full ECU index for each section
    # would make a small aliased input quadratic in the number of index entries.
    offsets = sorted(
        {
            entry["offset"]
            for entry in snapshot.metadata["index_entries"]
            if snapshot.body_offset <= entry["offset"] <= len(snapshot.source)
        }
    )
    sections = {
        offset: snapshot.source[offset:end]
        for offset, end in zip(
            offsets, offsets[1:] + [len(snapshot.source)], strict=True
        )
    }

    def payload_at(offset: int) -> bytes:
        if offset not in sections:
            raise SnapshotError("native monitor has no valid indexed boundary")
        return sections[offset]

    for ecu_index, ecu in enumerate(snapshot.metadata["ecu_index"]):
        for family, feature, expected_type in families:
            if feature not in supported:
                continue
            offset = ecu[family]
            if not offset:
                raise SnapshotError(f"native TSE {family} has no indexed boundary")
            payload = payload_at(offset)
            header = Cursor(payload).unpack("<IIHH")
            record_count += header[3]
            if record_count > MAX_TABLES:
                raise SnapshotError("native TSE monitor count exceeds host limit")
            cache_key = (offset, expected_type)
            cached = section_cache.get(cache_key)
            if cached is None:
                cached = decode_tse_datalist_section(payload)
                section_cache[cache_key] = cached
            if not isinstance(cached, TSEDataListSection):
                raise SnapshotError("invalid native single monitor section")
            section = cached
            if section.type_raw != expected_type:
                raise SnapshotError("native monitor section type differs from index")
            for record_index, record in enumerate(section.records):
                result.append(
                    {
                        "ecu_index": ecu_index,
                        "ecu_id_raw": ecu.get("ecu_id_raw"),
                        "family": family,
                        "record_index": record_index,
                        "record": record,
                    }
                )
    dual_sources = []
    if 0x2726 in supported:
        dual_sources.append(
            ("DualData", snapshot.metadata["global_index"]["DualData"], 0xFFFFFF19)
        )
    if 0x2728 in supported:
        dual_sources.extend(
            ("ATestD", ecu["ATestD"], 0xFFFFFF21)
            for ecu in snapshot.metadata["ecu_index"]
        )
    for family, offset, expected_type in dual_sources:
        payload = payload_at(offset)
        record_count += Cursor(payload).unpack("<IIHH")[3]
        if record_count > MAX_TABLES:
            raise SnapshotError("native TSE monitor count exceeds host limit")
        cache_key = (offset, expected_type)
        cached = section_cache.get(cache_key)
        if cached is None:
            cached = decode_tse_dual_section(payload)
            section_cache[cache_key] = cached
        if not isinstance(cached, DualSection):
            raise SnapshotError("invalid native dual monitor section")
        dual = cached
        if dual.type_raw != expected_type:
            raise SnapshotError("native dual monitor section type differs from index")
        for record_index, capture in enumerate(dual.records):
            if len(result) + len(capture.ecus) > MAX_TABLES:
                raise SnapshotError("native TSE monitor count exceeds host limit")
            for ecu_index, ecu in enumerate(capture.ecus):
                monitor = MonitorBuffer(
                    ecu.name,
                    capture.information,
                    ecu.description,
                    ecu.frame_table,
                    ecu.signal_table,
                    ecu.ring_buffer,
                    capture.marker,
                    capture.flags,
                    ecu.selected_ids,
                    capture.description,
                    ecu.ids,
                )
                result.append(
                    {
                        "ecu_index": ecu_index,
                        "ecu_id_raw": ecu.identifier,
                        "family": family,
                        "record_index": record_index,
                        "record": TSEDataList(
                            monitor,
                            ecu.selected_pairs,
                            ecu.mode_raw,
                            (),
                            b"",
                            bytes(80),
                        ),
                    }
                )
    return result


def assemble_tse(template: TSEFile, sections: tuple[bytes, ...]) -> TSEFile:
    """Write a native file from its versioned header and ordered native sections.

    Supply one body fragment per original index entry, in that index's order;
    zero-length fragments represent absent sections. ECUInfo's section header
    and each EcuData record are separate indexed fragments. Metadata/feature
    declarations come from the supplied native template, never invented here.
    All absolute offsets are generated from actual fragment sizes, matching
    GTSFileController's native offset calculators 0x38a00/0x39f60.
    """
    if not isinstance(template, TSEFile):
        raise SnapshotError("expected a native TSE header template")
    original = parse_tse(template.source)
    entries = original.metadata["index_entries"]
    if not isinstance(sections, tuple) or len(sections) != len(entries):
        raise SnapshotError("one native body fragment per index entry is required")
    header = bytearray(original.source[: original.body_offset])
    chunks = _ByteChunks()
    for entry, payload in zip(entries, sections, strict=True):
        if not isinstance(payload, bytes):
            raise SnapshotError("native section fragments must be bytes")
        offset = len(header) + chunks.size
        if offset + len(payload) > MAX_BYTES:
            raise SnapshotError("assembled native TSE exceeds limit")
        struct.pack_into("<I", header, entry["position"], offset)
        chunks.append(payload)
    result = parse_tse(bytes(header) + b"".join(chunks))
    if any(
        feature in result.metadata["supported_feature_ids"]
        for feature in (0x2714, 0x2715, 0x2717, 0x2726, 0x2728)
    ):
        tse_monitors(result)
    return result


def replace_tse_datalist(
    snapshot: TSEFile, ecu_index: int, section: TSEDataListSection
) -> TSEFile:
    """Replace an existing DataList capture; preserve other native families."""
    return replace_tse_monitor_section(snapshot, "DataList", section, ecu_index)


def replace_tse_monitor_section(
    snapshot: TSEFile,
    family: str,
    section: TSEDataListSection | DualSection,
    ecu_index: int = 0,
) -> TSEFile:
    """Edit a recovered native section and relocate every later absolute offset.

    Absent features cannot be inserted. Uninterpreted companion sections remain
    byte-preserved. ECU selection applies to DataList/DrvRec/ATest/ATestD;
    DualData is the global section and requires ecu_index zero.
    """
    families = {
        "DataList": (0x2714, 0xFFFFFF05),
        "DrvRec": (0x2715, 0xFFFFFF08),
        "ATest": (0x2717, 0xFFFFFF07),
        "DualData": (0x2726, 0xFFFFFF19),
        "ATestD": (0x2728, 0xFFFFFF21),
    }
    if family not in families:
        raise SnapshotError("unsupported native monitor family")
    feature, expected_type = families[family]
    if feature not in snapshot.metadata["supported_feature_ids"]:
        raise SnapshotError("native monitor feature does not exist")
    if family == "DualData":
        if type(ecu_index) is not int or ecu_index != 0:
            raise SnapshotError("DualData uses a global section")
        start = snapshot.metadata["global_index"][family]
    else:
        if type(ecu_index) is not int or not 0 <= ecu_index < len(
            snapshot.metadata["ecu_index"]
        ):
            raise SnapshotError("native monitor ECU section does not exist")
        start = snapshot.metadata["ecu_index"][ecu_index][family]
    original = tse_section(snapshot, start)
    if family in ("DualData", "ATestD"):
        previous = decode_tse_dual_section(original)
        if not isinstance(section, DualSection):
            raise SnapshotError("expected a native dual monitor section")
        replacement = encode_tse_dual_section(section)
    else:
        previous = decode_tse_datalist_section(original)
        if not isinstance(section, TSEDataListSection):
            raise SnapshotError("expected a native single monitor section")
        replacement = encode_tse_datalist_section(section)
    if section.type_raw != expected_type or previous.type_raw != expected_type:
        raise SnapshotError("native monitor section type differs from index")
    end = start + len(original)
    delta = len(replacement) - len(original)
    if len(snapshot.source) + delta > MAX_BYTES:
        raise SnapshotError("edited native TSE exceeds limit")
    data = bytearray(snapshot.source[:start] + replacement + snapshot.source[end:])
    for entry in snapshot.metadata["index_entries"]:
        offset = entry["offset"]
        if offset >= end:
            struct.pack_into("<I", data, entry["position"], offset + delta)
    return parse_tse(bytes(data))


@dataclass(frozen=True)
class DualECU:
    identifier: int
    name: bytes
    description: bytes
    mode_raw: int | None
    ids: tuple[int, ...]
    frame_table: bytes
    signal_table: bytes
    ring_buffer: bytes
    selected_ids: tuple[int, ...]
    selected_pairs: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class DualCapture:
    identifier: int
    name: bytes
    information: bytes
    description: bytes
    marker: int
    flags: tuple[Flag, ...]
    views: tuple[bytes, ...]
    configuration: tuple[bytes, ...]
    configuration_tail: bytes
    ecus: tuple[DualECU, ...]
    active_metadata: bytes = b""


@dataclass(frozen=True)
class DualSection:
    version: int
    records: tuple[DualCapture, ...]
    type_raw: int = 0xFFFFFF19


def decode_tse_dual_section(data: bytes) -> DualSection:
    """Native DualData header and self-contained per-ECU monitor buffers."""
    cursor = Cursor(data)
    identifier, kind, version, count = cursor.unpack("<IIHH")
    if (
        identifier != 0xFFFFFFFF
        or kind not in (0xFFFFFF19, 0xFFFFFF21)
        or not 0x1000 <= version <= 0x1027
    ):
        raise SnapshotError("unsupported native DualData section header")
    records = []
    for _ in range(count):
        (record_id,) = cursor.unpack("<H")
        name, information, description = (_blob(cursor) for _ in range(3))
        if len(information) > 16:
            raise SnapshotError("dual capture information exceeds 16 bytes")
        (marker,) = cursor.unpack("<I")
        (flag_count,) = cursor.unpack("<H")
        flags = []
        for _ in range(flag_count):
            (position,) = cursor.unpack("<I")
            flags.append(Flag(position, _blob(cursor)))
        (view_count,) = cursor.unpack("<H")
        views = tuple(
            cursor.take(88 if version >= 0x1004 else 86) for _ in range(view_count)
        )
        (configuration_count,) = cursor.unpack("<H")
        configuration = tuple(
            cursor.take(20 if version >= 0x1002 else 16)
            for _ in range(configuration_count)
        )
        configuration_tail = cursor.take(20 if version >= 0x1002 else 16)
        (ecu_count,) = cursor.unpack("<H")
        ecus = []
        for _ in range(ecu_count):
            (ecu_id,) = cursor.unpack("<I")
            ecu_name, ecu_description = _blob(cursor), _blob(cursor)
            mode = cursor.unpack("<H")[0] if version >= 0x1003 else None
            (id_count,) = cursor.unpack("<H")
            ids = tuple(
                cursor.unpack("<H" if version >= 0x1001 else "<I")[0]
                for _ in range(id_count)
            )
            frame_table, signal_table, ring_buffer = (
                _blob(cursor, "<I") for _ in range(3)
            )
            (selected_count,) = cursor.unpack("<H")
            selected = tuple(cursor.unpack("<H")[0] for _ in range(selected_count))
            (pair_count,) = cursor.unpack("<H")
            pairs = tuple(
                cursor.unpack("<HI" if version >= 0x1005 else "<HH")
                for _ in range(pair_count)
            )
            ecus.append(
                DualECU(
                    ecu_id,
                    ecu_name,
                    ecu_description,
                    mode,
                    ids,
                    frame_table,
                    signal_table,
                    ring_buffer,
                    selected,
                    pairs,
                )
            )
        active_start = cursor.position
        if kind == 0xFFFFFF21 and version > 0x1006:
            _read_active_metadata(cursor, version)
        active_metadata = cursor.data[active_start : cursor.position]
        records.append(
            DualCapture(
                record_id,
                name,
                information,
                description,
                marker,
                tuple(flags),
                views,
                configuration,
                configuration_tail,
                tuple(ecus),
                active_metadata,
            )
        )
    cursor.end()
    return DualSection(version, tuple(records), kind)


def encode_tse_dual_section(section: DualSection) -> bytes:
    try:
        version = section.version
        if not 0x1000 <= version <= 0x1027 or section.type_raw not in (
            0xFFFFFF19,
            0xFFFFFF21,
        ):
            raise SnapshotError("unsupported native dual section version/type")
        chunks = _ByteChunks(
            [
                struct.pack(
                    "<IIHH", 0xFFFFFFFF, section.type_raw, version, len(section.records)
                )
            ]
        )
        for record in section.records:
            if len(record.information) > 16:
                raise SnapshotError("dual capture information exceeds 16 bytes")
            chunks.append(struct.pack("<H", record.identifier))
            chunks.extend(
                _pack_blob(value)
                for value in (record.name, record.information, record.description)
            )
            chunks.append(struct.pack("<IH", record.marker, len(record.flags)))
            for flag in record.flags:
                chunks.append(struct.pack("<I", flag.position) + _pack_blob(flag.label))
            for values, size in (
                (record.views, 88 if version >= 0x1004 else 86),
                (record.configuration, 20 if version >= 0x1002 else 16),
            ):
                chunks.append(struct.pack("<H", len(values)))
                for value in values:
                    if len(value) != size:
                        raise SnapshotError(
                            "invalid native dual view/configuration size"
                        )
                    chunks.append(value)
            if len(record.configuration_tail) != (20 if version >= 0x1002 else 16):
                raise SnapshotError("invalid native dual configuration tail")
            chunks.append(record.configuration_tail)
            chunks.append(struct.pack("<H", len(record.ecus)))
            for ecu in record.ecus:
                chunks.append(struct.pack("<I", ecu.identifier))
                chunks.extend(
                    _pack_blob(value) for value in (ecu.name, ecu.description)
                )
                if version >= 0x1003:
                    chunks.append(struct.pack("<H", ecu.mode_raw))
                elif ecu.mode_raw is not None:
                    raise SnapshotError("legacy dual ECU has no mode field")
                chunks.append(struct.pack("<H", len(ecu.ids)))
                chunks.extend(
                    struct.pack("<H" if version >= 0x1001 else "<I", value)
                    for value in ecu.ids
                )
                chunks.extend(
                    _pack_blob(value, "<I")
                    for value in (ecu.frame_table, ecu.signal_table, ecu.ring_buffer)
                )
                chunks.append(struct.pack("<H", len(ecu.selected_ids)))
                chunks.extend(struct.pack("<H", value) for value in ecu.selected_ids)
                chunks.append(struct.pack("<H", len(ecu.selected_pairs)))
                chunks.extend(
                    struct.pack("<HI" if version >= 0x1005 else "<HH", *pair)
                    for pair in ecu.selected_pairs
                )
            if section.type_raw == 0xFFFFFF21 and version > 0x1006:
                decode_active_metadata(record.active_metadata, version)
                chunks.append(record.active_metadata)
            elif record.active_metadata:
                raise SnapshotError("this native dual section has no active metadata")
        result = b"".join(chunks)
        Cursor(result)
        return result
    except (ValueError, TypeError, AttributeError, struct.error) as exc:
        raise SnapshotError(f"invalid native DualData section: {exc}") from exc
