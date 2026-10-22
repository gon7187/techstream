"""Bounded static CUW framing and Motorola S-record inspection; no vehicle I/O.

CUW framing follows Techstream 18 CUW 8.15.1 Cuw.exe's Calib parser.
A successful framing check does not certify firmware authenticity or compatibility.
"""

from __future__ import annotations

import configparser
import hashlib
import re
import struct
import zlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from itertools import pairwise
from types import MappingProxyType

MAX_FILE_SIZE = 64 * 1024 * 1024
MAX_RECORDS = 4096
SIGNATURE = b"\x00CALIBRATION\x00"
VERSIONS = frozenset((1, 3, 4, 5, 6, 7, 8, 9, 101, 102, 103))


@dataclass(frozen=True)
class CalibrationRecord:
    offset: int
    header: bytes
    data: bytes
    crc32: int

    def report(self) -> dict:
        return {
            "offset": self.offset,
            "header_hex": self.header.hex(),
            "size": len(self.data),
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "crc32": f"{self.crc32:08x}",
        }


@dataclass(frozen=True)
class CalibrationContainer:
    version: int
    digest: str
    attached: CalibrationRecord
    records: tuple[CalibrationRecord, ...]
    declared_count: int
    count_width: int

    def report(self) -> dict:
        metadata = None
        try:
            metadata = inspect_attached_metadata(self.attached.data)
        except ValueError:
            pass
        return {
            "format": "CUW",
            "metadata": metadata,
            "semantic_compatibility_validated": False,
            "version": self.version,
            "sha256": self.digest,
            "attached": self.attached.report(),
            "records": [record.report() for record in self.records],
            "declared_count": self.declared_count,
            "count_width": self.count_width,
            "framing_valid": True,
            "programming_authorized": False,
            "provenance": "static-native-framing; semantic compatibility unresolved",
        }


def _bounded(data: bytes) -> None:
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_FILE_SIZE:
        raise ValueError("Input must be nonempty bytes within 64 MiB")


def decode_cuw_text(data: bytes) -> bytes:
    """Decode CUW's native two-character nibble text representation.

    Each nibble is encoded as ((nibble +8)<<2) plus two discarded random bits.
    This is a file representation, not activation or security-key derivation.
    """
    _bounded(data)
    if len(data) % 2 or any(not 0x20 <= byte <= 0x5F for byte in data):
        raise ValueError("Invalid CUW nibble-text representation")
    return bytes(
        (((data[index] >> 2) - 8) << 4) | ((data[index + 1] >> 2) - 8)
        for index in range(0, len(data), 2)
    )


def crc16(data: bytes) -> int:
    """TCUWCRC.dll CalcCRC16: reflected 0x8408, init/final xor 0xffff."""
    value = 0xFFFF
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x8408 if value & 1 else 0)
    return value ^ 0xFFFF


def _record(data: bytes, position: int) -> tuple[CalibrationRecord, int]:
    start = position
    if position + 2 > len(data):
        raise ValueError("Truncated record header length")
    length = int.from_bytes(data[position : position + 2], "big")
    position += 2
    if position + length + 8 > len(data):
        raise ValueError("Truncated record header")
    header = data[position : position + length]
    position += length
    size, checksum = struct.unpack_from(">II", data, position)
    position += 8
    if size > len(data) - position:
        raise ValueError("Truncated record data")
    payload = data[position : position + size]
    if zlib.crc32(payload) != checksum:
        raise ValueError("Record CRC32 mismatch")
    return CalibrationRecord(start, header, payload, checksum), position + size


def _metadata_parser(data: bytes):
    _bounded(data)
    if len(data) > 1024 * 1024 or b"\x00" in data:
        raise ValueError("Invalid attached metadata size or NUL")
    parser = configparser.ConfigParser(
        interpolation=None, delimiters=("=",), comment_prefixes=(";",), strict=True
    )
    try:
        parser.read_string(data.decode("cp1252"))
    except (configparser.Error, UnicodeError) as exc:
        raise ValueError("Invalid attached INI metadata") from exc
    sections = {section.casefold(): section for section in parser.sections()}
    if len(sections) != len(parser.sections()) or parser.defaults():
        raise ValueError("Duplicate sections or inherited defaults")
    try:
        version = int(parser[sections["format"]]["version"])
    except (KeyError, ValueError) as exc:
        raise ValueError("Missing metadata Format Version") from exc
    if version not in (
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        101,
        102,
        103,
        104,
        105,
        106,
        107,
        206,
    ):
        raise ValueError("Unsupported attached metadata version")
    return parser, version


def inspect_attached_metadata(data: bytes) -> dict:
    """Read observed native INI fields; omit security/key fields from reports.

    The native reader uses section/key strings and case-insensitive INI lookups.
    This strict subset rejects duplicates and interpolation instead of silently
    choosing one. It does not establish ECU compatibility from a matching label.
    """
    parser, version = _metadata_parser(data)
    fields = {}
    allowed = {
        "numberofnode",
        "numberofcalibration",
        "numberoftargets",
        "numberoffiles",
        "numberoflogicalblock",
        "newcid",
        "cputype",
        "locationid",
        "ecutype",
        "contacttype",
        "vehicletype",
        "enginetype",
        "modelyear",
        "dataformat",
        "downloadaddress",
        "downloadmemsize",
        "eraseblock",
        "alfid",
        "reproMethod".casefold(),
        "filename",
        "numberofgateway",
    }
    counts = {key for key in allowed if key.startswith("numberof")}
    for section in parser.sections():
        if len(section) > 128 or len(parser[section]) > 1024:
            raise ValueError("Metadata field limit exceeded")
        values = {}
        for key, value in parser[section].items():
            if len(key) > 128 or len(value) > 4096:
                raise ValueError("Metadata field limit exceeded")
            if key in counts:
                try:
                    count = int(value)
                except ValueError as exc:
                    raise ValueError("Invalid metadata count") from exc
                if not 0 <= count <= MAX_RECORDS:
                    raise ValueError("Metadata count outside bounds")
            if key in allowed:
                values[key] = value
        if values:
            fields[section] = values
    return {
        "format_version": version,
        "count_width": 2 if version == 9 else 1,
        "fields": fields,
        "compatibility_validated": False,
        "provenance": "native INI field names; strict host parser",
    }


def parse_cuw(data: bytes) -> CalibrationContainer:
    """Validate exact framing and checksums; retain opaque metadata and payloads.

    Native metadata chooses a one- or two-byte count. Both framing variants are
    checked; ambiguous interpretations are rejected, never selected by guessing.
    The declared count may describe CPU images or file images depending on metadata.
    """
    _bounded(data)
    if len(data) < 22 or data[:13] != SIGNATURE:
        raise ValueError("Unrecognized CUW signature or truncated header")
    version = data[13]
    if version not in VERSIONS:
        raise ValueError("Unsupported CUW format version")
    checksum, length = struct.unpack_from(">II", data, 14)
    if length != len(data):
        raise ValueError("CUW total length mismatch")
    if zlib.crc32(data[18:]) != checksum:
        raise ValueError("CUW CRC32 mismatch")
    attached, position = _record(data, 22)
    candidates = []
    try:
        metadata = inspect_attached_metadata(attached.data)
    except ValueError:
        metadata = None
    for width in (1, 2):
        if metadata is not None and width != metadata["count_width"]:
            continue
        if position + width > len(data):
            continue
        count = int.from_bytes(data[position : position + width], "big")
        if count > MAX_RECORDS:
            continue
        cursor = position + width
        records = []
        try:
            while cursor < len(data):
                if len(records) == MAX_RECORDS:
                    raise ValueError("Too many CUW records")
                record, cursor = _record(data, cursor)
                records.append(record)
            # Native metadata can add an auxiliary image for each CPU image.
            if count <= len(records) <= 2 * count:
                candidates.append((width, count, tuple(records)))
        except ValueError:
            continue
    if len(candidates) != 1:
        raise ValueError("Invalid or ambiguous CUW record/count framing")
    width, count, records = candidates[0]
    return CalibrationContainer(
        version, hashlib.sha256(data).hexdigest(), attached, records, count, width
    )


def _parse_srecords(data: bytes, *, native_area: bool = False) -> dict:
    """Validate the native supported S0/1/2/3/5/7/8/9 family, strictly bounded.

    Host policy additionally rejects overlapping ranges, mixed data address widths,
    trailing records after termination and count/termination ordering errors.
    """
    _bounded(data)
    widths = {0: 2, 1: 2, 2: 3, 3: 4, 7: 4, 8: 3, 9: 2}
    records = []
    spans = []
    data_kind = None
    terminated = False
    count_seen = False
    entry = None
    for number, line in enumerate(data.splitlines(), 1):
        if len(records) >= MAX_RECORDS or len(line) > 514:
            raise ValueError("S-record limit exceeded")
        if not re.fullmatch(rb"S[01235789][0-9A-Fa-f]+", line):
            raise ValueError(f"Invalid S-record at line {number}")
        if terminated:
            raise ValueError("Record after termination")
        kind = line[1] - 48
        try:
            raw = bytes.fromhex(line[2:].decode("ascii"))
        except ValueError as exc:
            raise ValueError("Odd hexadecimal length") from exc
        if not raw or raw[0] != len(raw) - 1 or sum(raw) & 0xFF != 0xFF:
            raise ValueError("S-record length/checksum mismatch")
        width = len(raw) - 2 if kind == 5 else widths[kind]
        if width not in (2, 3, 4) or len(raw) < width + 2:
            raise ValueError("Invalid S-record address size")
        address = int.from_bytes(raw[1 : 1 + width], "big")
        payload = raw[1 + width : -1]
        if kind in (1, 2, 3):
            if count_seen or (
                data_kind is not None and kind != data_kind and not native_area
            ):
                raise ValueError("Mixed widths or data after count")
            if not payload or address + len(payload) > 1 << (width * 8):
                raise ValueError("Empty or overflowing S-record data")
            data_kind = kind
            spans.append((address, address + len(payload), payload))
        elif kind == 5:
            if count_seen or address != len(spans):
                raise ValueError("S5 count mismatch or duplicate")
            count_seen = True
        elif kind in (7, 8, 9):
            if payload or data_kind is None or kind != 10 - data_kind:
                raise ValueError("S-record termination mismatch")
            terminated = True
            entry = address
        elif (spans or records) and not native_area:
            raise ValueError("S0 must be the first record")
        records.append({"line": number, "kind": kind, "address": address})
    if not spans or not terminated:
        raise ValueError("S-record data and termination required")
    ordered = sorted(spans)
    if not native_area and any(left[1] > right[0] for left, right in pairwise(ordered)):
        raise ValueError("Overlapping S-record data")
    return {
        "format": "SREC",
        "sha256": hashlib.sha256(data).hexdigest(),
        "entry_address": entry,
        "records": records,
        "segments": [
            {
                "address": start,
                "size": end - start,
                "sha256": hashlib.sha256(p).hexdigest(),
            }
            for start, end, p in spans
        ],
        "programming_authorized": False,
        "provenance": "native-supported S-record family; strict host validation",
    }


def parse_srecords(data: bytes) -> dict:
    """Strict host inspection: uniform widths and no overlapping data records."""
    return _parse_srecords(data)


def inspect_calibration(data: bytes) -> dict:
    return (
        parse_cuw(data).report() if data.startswith(SIGNATURE) else parse_srecords(data)
    )


@dataclass(frozen=True)
class NativeLogicalArea:
    kind: str
    address: int
    length: int
    crc: bytes | None
    cmac: bytes = field(repr=False)
    digital_signature: bytes = field(repr=False)
    record: CalibrationRecord = field(repr=False)
    data: bytes = field(repr=False)


@dataclass(frozen=True)
class NativeLogicalBlock:
    node: int
    slot: int
    ecu_index: int
    new_cid: str
    targets: tuple[str, ...]
    required_spec: str
    method: str
    nonce: bytes = field(repr=False)
    areas: tuple[NativeLogicalArea, ...] = field(repr=False)
    node_values: Mapping[str, str] = field(repr=False)
    values: Mapping[str, str] = field(repr=False)


def materialize_native_srecord_area(data: bytes, address: int, size: int) -> bytes:
    """CUW18 MakeSendData: skip first S1, concatenate eligible record payloads.

    No holes are filled and no bytes are synthesized. Native copies whole records
    at/after the requested address; host rejects an overrun or incomplete area.
    S-record framing/checksums and strict host ordering rules are checked first.
    """
    if (
        type(address) is not int
        or type(size) is not int
        or not 0 <= address <= 0xFFFFFFFF
        or not 0 < size <= MAX_FILE_SIZE
        or address + size > 2**32
    ):
        raise ValueError("Bounded native S-record area geometry required")
    _parse_srecords(data, native_area=True)
    result = bytearray()
    first_s1 = True
    for line in data.splitlines():
        kind = line[1] - 48
        if kind not in (1, 2, 3):
            continue
        raw = bytes.fromhex(line[2:].decode("ascii"))
        width = kind + 1
        start = int.from_bytes(raw[1 : 1 + width], "big")
        payload = raw[1 + width : -1]
        if kind == 1 and first_s1:
            first_s1 = False
            continue
        if start < address:
            continue
        result.extend(payload)
        if len(result) >= size:
            if len(result) != size:
                raise ValueError("Native S-record area would overrun its buffer")
            return bytes(result)
    raise ValueError("Native S-record area is incomplete")


def bind_native_logical_records(
    container: CalibrationContainer,
) -> tuple[NativeLogicalBlock, ...]:
    """Bind CUW18 spec03/04 logical metadata to embedded records in native order.

    This is a pure structural binding. All nodes must use the recovered logical
    schema; mixed older CPU schemas fail explicitly. Native pre206 S-record
    materialization and shared whole-package archives are preserved. No external
    filename is opened, no observed identity or original signature is invented.
    """
    if not isinstance(container, CalibrationContainer):
        raise TypeError("Parsed immutable CUW container required")
    inspect_attached_metadata(container.attached.data)
    parser, version = _metadata_parser(container.attached.data)
    sections = {name.casefold(): parser[name] for name in parser.sections()}

    def section(name: str):
        try:
            return sections[name.casefold()]
        except KeyError as exc:
            raise ValueError(f"Missing native metadata section {name}") from exc

    def count(values, name: str, maximum: int):
        try:
            value = int(values[name])
        except (KeyError, ValueError) as exc:
            raise ValueError(f"Missing or invalid native count {name}") from exc
        if not 0 <= value <= maximum:
            raise ValueError(f"Native count outside host bounds: {name}")
        return value

    def hexadecimal(value: str, width: int | None = None) -> bytes:
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2})*", value):
            raise ValueError("Strict native hexadecimal field required")
        result = bytes.fromhex(value)
        if width is not None and len(result) != width:
            raise ValueError("Native hexadecimal field width mismatch")
        return result

    if version < 101 or version == 102:
        raise ValueError("This binder requires native node/logical-block metadata")
    node_count = count(section("Vehicle"), "numberofnode", 9)
    if not node_count:
        raise ValueError("Native logical metadata requires at least one node")
    records = iter(container.records)
    consumed = 0
    blocks = []
    cpu_base = 0
    method_codes = {
        "01": "whole",
        "05": "whole",
        "07": "delta",
        "08": "delta",
        "09": "compressed",
        "0A": "compressed",
    }
    # 4162ac reads present whole-package data early only for metadata206.
    kinds = (
        "ReproData",
        "EraseAndReproRoutine",
        "DeltaReproData",
        "DeltaEraseAndReproRoutine",
        "CompressionReproData",
        "CompressionEraseAndReproRoutine",
    )
    for node in range(1, node_count + 1):
        node_values = section(f"Node{node:02}")
        required_spec = node_values.get("requiredspecreprover", "")
        if required_spec not in ("03", "04"):
            raise ValueError(
                "Mixed or nonlogical native schema requires separate binder"
            )
        declared_blocks = count(node_values, "numberoflogicalblock", 16)
        cpu_ids: list[str] = []
        selected = []
        for slot in range(1, 17):
            name = f"LogicalBlock{node}{slot:02}"
            values = sections.get(name.casefold())
            if values is None or not values.get("newcid", ""):
                continue
            new_cid = values["newcid"]
            if (
                not new_cid.isascii()
                or not 0 < len(new_cid) <= 256
                or any(ord(c) < 32 for c in new_cid)
            ):
                raise ValueError("Bounded native NewCID required")
            if new_cid not in cpu_ids:
                cpu_ids.append(new_cid)
            targets = tuple(
                values.get(f"{index:02}_targetcalibration", "")
                for index in range(1, count(values, "numberoftargets", MAX_RECORDS) + 1)
            )
            if any(
                not target or not target.isascii() or len(target) > 256
                for target in targets
            ):
                raise ValueError("Missing or invalid native target calibration row")
            code = values.get("repromethod", "")
            if code not in method_codes:
                raise ValueError("Unknown native logical reprogramming method")
            nonce = hexadecimal(values.get("nonce", ""), 16)
            areas = []
            for kind in kinds:
                area_name = f"{kind}{node}{slot:02}"
                info = sections.get(area_name.casefold())
                if info is None or not info.get("length", ""):
                    continue
                address = int.from_bytes(
                    hexadecimal(info.get("startaddress", ""), 4), "big"
                )
                length = int.from_bytes(hexadecimal(info["length"], 4), "big")
                if not 0 < length <= MAX_FILE_SIZE or address + length > 2**32:
                    raise ValueError("Native logical area outside address/size bounds")
                if kind == "EraseAndReproRoutine" and version != 206:
                    whole = next(
                        (area for area in areas if area.kind == "ReproData"), None
                    )
                    if whole is None:
                        raise ValueError(
                            "Native whole-package fallback requires whole image record"
                        )
                    record = whole.record
                else:
                    try:
                        record = next(records)
                    except StopIteration as exc:
                        raise ValueError(
                            "Missing embedded native logical record"
                        ) from exc
                    consumed += 1
                if version != 206 and kind in (
                    "ReproData",
                    "EraseAndReproRoutine",
                    "DeltaEraseAndReproRoutine",
                    "CompressionEraseAndReproRoutine",
                ):
                    payload = materialize_native_srecord_area(
                        record.data, address, length
                    )
                else:
                    payload = record.data
                    if len(payload) != length:
                        raise ValueError(
                            "Native logical length differs from embedded payload"
                        )
                crc = hexadecimal(info.get("crc", ""))
                if crc and len(crc) != 4:
                    raise ValueError("Native logical CRC must contain four bytes")
                cmac = hexadecimal(info.get("cmac", ""))
                signature = hexadecimal(info.get("digitalsignature", ""))
                if cmac and len(cmac) != 16 or signature and len(signature) != 256:
                    raise ValueError("Native logical signature width mismatch")
                areas.append(
                    NativeLogicalArea(
                        kind,
                        address,
                        length,
                        crc or None,
                        cmac,
                        signature,
                        record,
                        payload,
                    )
                )
            selected.append(
                NativeLogicalBlock(
                    node,
                    slot,
                    cpu_base + cpu_ids.index(new_cid),
                    new_cid,
                    targets,
                    required_spec,
                    code,
                    nonce,
                    tuple(areas),
                    MappingProxyType(dict(node_values)),
                    MappingProxyType(dict(values)),
                )
            )
            if len(selected) == declared_blocks:
                break
        if len(selected) != declared_blocks:
            raise ValueError(
                "Native logical block count does not match populated slots"
            )
        blocks.extend(selected)
        cpu_base += len(cpu_ids)
    if consumed != len(container.records) or consumed != container.declared_count:
        raise ValueError("Native logical archive count/order does not match metadata")
    return tuple(blocks)


@dataclass(frozen=True)
class NativeCPUFile:
    index: int
    values: Mapping[str, str] = field(repr=False)
    record: CalibrationRecord | None = field(repr=False)


@dataclass(frozen=True)
class NativeCPU:
    index: int
    node: int
    section: str
    values: Mapping[str, str] = field(repr=False)
    node_values: Mapping[str, str] = field(repr=False)
    vehicle_values: Mapping[str, str] = field(repr=False)
    image: CalibrationRecord | None = field(repr=False)
    flash_code: CalibrationRecord | None = field(repr=False)
    image_areas: tuple[tuple[int, int], ...]
    write_routine_areas: tuple[tuple[int, int], ...]
    erase_routine_areas: tuple[tuple[int, int], ...]
    files: tuple[NativeCPUFile, ...] = field(repr=False)
    headers: Mapping[str, Mapping[str, str]] = field(repr=False)


def bind_native_cpu_records(container: CalibrationContainer) -> tuple[NativeCPU, ...]:
    """Bind the native older CPU/file schema, retaining original bounded fields.

    Pre101 metadata has no explicit node rows: node0 means its later native
    grouping is unresolved here, rather than inventing a physical association.
    Metadata9 contains file records; other supported CPU schemas contain CPU
    images followed by the declared optional flash-code images.
    """
    if not isinstance(container, CalibrationContainer):
        raise TypeError("Parsed immutable CUW container required")
    inspect_attached_metadata(container.attached.data)
    parser, version = _metadata_parser(container.attached.data)
    sections = {name.casefold(): parser[name] for name in parser.sections()}

    def section(name: str):
        try:
            return sections[name.casefold()]
        except KeyError as exc:
            raise ValueError(f"Missing native metadata section {name}") from exc

    def count(values, name: str, maximum: int, default: int | None = None):
        try:
            value = int(values[name]) if name in values else default
        except ValueError as exc:
            raise ValueError(f"Invalid native count {name}") from exc
        if value is None or not 0 <= value <= maximum:
            raise ValueError(f"Missing or out-of-bounds native count {name}")
        return value

    def geometry(name: str):
        values = sections.get(name.casefold(), {})
        result = []
        for index in range(
            1, count(values, "numberofareasettings", MAX_RECORDS, 0) + 1
        ):
            try:
                start = values[f"{index:02}_startaddress"]
                length = values[f"{index:02}_length"]
            except KeyError as exc:
                raise ValueError("Missing native CPU area geometry") from exc
            if not re.fullmatch(r"[0-9a-fA-F]{8}", start) or not re.fullmatch(
                r"[0-9a-fA-F]{8}", length
            ):
                raise ValueError("Native CPU areas require exact four-byte hex fields")
            address, size = int(start, 16), int(length, 16)
            if not 0 < size <= MAX_FILE_SIZE or address + size > 2**32:
                raise ValueError("Native CPU area outside host bounds")
            result.append((address, size))
        return tuple(result)

    vehicle = section("Vehicle")
    cpus = []
    if version < 101:
        nodes = ((0, vehicle, count(vehicle, "numberofcalibration", 99)),)
    else:
        nodes = tuple(
            (
                node,
                section(f"Node{node:02}"),
                count(section(f"Node{node:02}"), "numberofcalibration", 9),
            )
            for node in range(1, count(vehicle, "numberofnode", 9) + 1)
        )
    for node, node_values, calibration_count in nodes:
        if (
            version >= 101
            and version != 102
            and node_values.get("requiredspecreprover", "")
            in (
                "03",
                "04",
            )
        ):
            raise ValueError("Mixed logical schema requires its separate binder")
        for ordinal in range(1, calibration_count + 1):
            cpu_name = f"CPU{ordinal:02}" if version < 101 else f"CPU{node}{ordinal}"
            suffix = f"{ordinal:02}" if version < 101 else f"{node}{ordinal}"
            values = section(cpu_name)
            files = []
            for file_index in range(1, count(values, "numberoffiles", 999, 0) + 1):
                if len(cpus) >= 9:
                    raise ValueError("Native file-section CPU digit would wrap")
                file_values = section(f"File{len(cpus) + 1}{file_index:03}")
                files.append(
                    NativeCPUFile(file_index, MappingProxyType(dict(file_values)), None)
                )
            cpus.append(
                NativeCPU(
                    len(cpus),
                    node,
                    cpu_name,
                    MappingProxyType(dict(values)),
                    MappingProxyType(dict(node_values)),
                    MappingProxyType(dict(vehicle)),
                    None,
                    None,
                    geometry(f"CPUImage{suffix}"),
                    geometry(f"WriteRoutine{suffix}"),
                    geometry(f"EraseRoutine{suffix}"),
                    tuple(files),
                    MappingProxyType(
                        {
                            kind: MappingProxyType(
                                dict(sections.get(f"{prefix}{suffix}".casefold(), {}))
                            )
                            for kind, prefix in (
                                ("image", "CPUImage"),
                                ("flash_code", "FlashCode"),
                                ("write_routine", "WriteRoutine"),
                                ("erase_routine", "EraseRoutine"),
                            )
                        }
                    ),
                )
            )
    if not cpus:
        raise ValueError("Native CPU schema contains no CPU images")
    records = iter(container.records)
    consumed = 0

    def take():
        nonlocal consumed
        try:
            record = next(records)
        except StopIteration as exc:
            raise ValueError("Missing native CPU/file archive record") from exc
        consumed += 1
        return record

    from dataclasses import replace

    if version == 9:
        cpus = [
            replace(
                cpu, files=tuple(replace(info, record=take()) for info in cpu.files)
            )
            for cpu in cpus
        ]
        expected = consumed
    else:
        cpus = [replace(cpu, image=take()) for cpu in cpus]
        expected = len(cpus)
        cpus = [
            replace(cpu, flash_code=take())
            if version < 101 and cpu.values.get("flashcodename", "")
            else cpu
            for cpu in cpus
        ]
    if consumed != len(container.records) or container.declared_count != expected:
        raise ValueError("Native CPU/file archive count differs from metadata")
    return tuple(cpus)


# Native CUW18 historical name/ID tables, static426a9c and4280dc.
_HISTORICAL_CPU_TYPES = {
    "32b 192k": "0",
    "32b 256k": "1",
    "32b 320k": "2",
    "32b 384k": "3",
    "32bh 384k": "4",
    "32bh 512k": "5",
    "32bh 768k": "6",
    "32bl 384k": "7",
    "tx2": "8",
    "mpc565": "10",
    "pg2": "11",
    "32bhs 384k": "12",
    "32bhs 512k": "13",
    "32bhs 768k": "14",
    "forest-1": "15",
    "forest-2": "16",
    "m16c/26t": "17",
    "m16c/29t 96k": "18",
    "m16c/29t 120k(plug-in)": "19",
    "st10f275": "20",
    "32bhf": "21",
    "b32r-v85 512k": "22",
    "32b-c2 256k": "23",
    "32b-c2 512k": "24",
    "32b-c2 768k": "25",
    "tc1766": "26",
    "pec1 384k": "27",
    "sh72512": "28",
    "pic16f877a": "29",
    "pec2 512k": "30",
    "denso dcm": "31",
    "delphi dcm/host": "32",
    "delphi dcm/dsp": "33",
    "delphi dcm/pic": "34",
    "sh72264": "35",
    "sh72265": "36",
    "sh7142": "37",
    "apec0m": "38",
    "wega 768k": "39",
    "gp8": "40",
    "v850es(ccp) 256k": "41",
    "pace1t 384k": "42",
    "m32c/85 320k": "43",
    "v850e/gp2 384k": "44",
    "v850e/gp8 512k": "45",
    "f2171-97207 384k": "46",
    "m32r 512k": "47",
    "prl": "48",
    "mpc565can": "10",
}
_HISTORICAL_ECU_KINDS = {
    "eng & ect": "0",
    "hv": "1",
    "ths": "2",
    "mg": "3",
    "vsc/abs/ecb": "4",
    "fc": "5",
    "fchv": "6",
    "epb": "7",
    "prl": "8",
    "eng2": "9",
    "hv battery": "10",
    "dcm(telematics)": "11",
    "asg": "12",
    "emps": "13",
    "vgrs": "14",
    "ars": "15",
    "plug-in control": "16",
    "eng(dh)": "17",
    "ect(dh)": "18",
    "ect": "10000",
    "eng": "10001",
}


_HISTORICAL_LOCATION_KINDS = {
    19: "0",
    22: "1",
    25: "10000",
    0: "10001",
    26: "2",
    27: "3",
}


def _historical_location_kind(location: str) -> str:
    if not re.fullmatch(r"[0-9a-fA-F]{16}", location):
        raise ValueError("Native metadata1 requires original eight-byte LocationID")
    return _HISTORICAL_LOCATION_KINDS.get(int(location[4:8], 16), "")


def native_selection_metadata(
    container: CalibrationContainer, *, node: int = 1, cpu_index: int = 0
) -> dict:
    """Native CUW18 metadata inputs to catalog.select_metadata, without aliases.

    Modern CPU rows are generated with empty CPUType; spec03/04 rows group only
    NewCID/NodeIdx and bypass the older CPU header conversion. Empty KindOfECU
    is the native INI default, not a guessed family prefix. Older formats1–3
    require their separately recovered historical ECU-name conversion.
    """
    if (
        type(node) is not int
        or not 0 <= node <= 99
        or type(cpu_index) is not int
        or not 0 <= cpu_index < MAX_RECORDS
    ):
        raise ValueError("Bounded native node/CPU selection required")
    inspect_attached_metadata(container.attached.data)
    parser, version = _metadata_parser(container.attached.data)
    sections = {name.casefold(): parser[name] for name in parser.sections()}
    vehicle = sections.get("vehicle", {})
    protocol = "SIL" if version == 1 else vehicle.get("contacttype", "")
    if not protocol:
        raise ValueError("Native Vehicle ContactType missing")
    if version >= 101:
        if node < 1 or node > int(vehicle.get("numberofnode", "0")):
            raise ValueError("Selected native node does not exist")
        values = sections.get(f"node{node:02}", {})
        cpu_type = ""
        required_spec = values.get("requiredspecreprover", "")
        if not required_spec:
            raise ValueError("Native node reprogramming specification missing")
    else:
        cpus = bind_native_cpu_records(container)
        if cpu_index >= len(cpus):
            raise ValueError("Selected native CPU does not exist")
        if version == 1:
            cpu_type = _HISTORICAL_CPU_TYPES.get(
                vehicle.get("ecutype", "").casefold(), ""
            )
        elif version in (2, 3):
            cpu_type = _HISTORICAL_CPU_TYPES.get(
                cpus[cpu_index].values.get("ecutype", "").casefold(), ""
            )
            if cpu_type == "10" and protocol == "SIL":
                cpu_type = "9"
        else:
            cpu_type = cpus[cpu_index].values.get("cputype", "")
        required_spec = "02"
    return {
        "kind_of_ecu": (
            _historical_location_kind(cpus[0].values.get("locationid", ""))
            if version == 1
            else _HISTORICAL_ECU_KINDS.get(vehicle.get("kindofecu", "").casefold(), "")
            if version in (2, 3)
            else vehicle.get("kindofecu", "")
        ),
        "cpu_type": cpu_type,
        "contact_type": protocol,
        "required_spec": required_spec,
    }
