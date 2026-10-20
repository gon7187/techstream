"""Bounded CUW2026 metadata values recovered from the authenticated native corpus.

This module uses structural record value types, never the CUW18 metadata binders.
Field values containing authorization material are deliberately absent from repr.
"""

from __future__ import annotations

import configparser
import hashlib
import os
import re
import stat
import struct
import weakref
import zlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any

from scripts.calibration import (
    CalibrationContainer,
    CalibrationRecord,
    NativeCPU,
    NativeCPUFile,
)

MAX_SIZE = 64 * 1024 * 1024
MAX_RECORDS = 4096
CONTAINER_VERSIONS = frozenset((1, 3, 4, 5, 6, 7, 8, 9, 10, 12, 101, 102, 103, 104))
# CUW.dll RVA7a610, 22 DWORDs; these are literal Format.Version values.
METADATA_VERSIONS = frozenset(
    (
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        12,
        40,
        101,
        103,
        104,
        105,
        106,
        107,
        206,
        209,
        300,
        400,
        500,
    )
)
_EMPTY = MappingProxyType({})


def _hex(text: str, width: int | None = None) -> bytes:
    if (
        not isinstance(text, str)
        or len(text) > 8192
        or not re.fullmatch(r"(?:[0-9a-fA-F]{2})*", text)
    ):
        raise ValueError("Bounded even hexadecimal native field required")
    value = bytes.fromhex(text)
    if width is not None and len(value) != width:
        raise ValueError("Native hexadecimal field width differs")
    return value


def _fixed_metadata_bytes(text: str, width: int) -> bytes:
    """CBytes512 zeroed backing followed by the native fixed-prefix copy."""
    value = _hex(text)
    if len(value) > 512:
        raise ValueError("Native CBytes capacity512 exceeded")
    return value[:width].ljust(width, b"\0")


def _number(
    values: Mapping[str, str],
    name: str,
    *,
    base: int = 10,
    scale: int = 1,
    default: int = 0,
    maximum: int = 0xFFFFFFFF,
) -> int:
    text = values.get(name.casefold(), "")
    if not text:
        return default
    pattern = r"[0-9]{1,10}" if base == 10 else r"[0-9a-fA-F]{1,8}"
    if not re.fullmatch(pattern, text):
        raise ValueError("Strict bounded native numerical field required")
    value = int(text, base)
    if value > maximum:
        raise ValueError("Native numerical field outside bounds")
    return (value * scale) & 0xFFFFFFFF


def _ini_sections_2026(data: bytes) -> Mapping[str, Mapping[str, str]]:
    """Strict host INI reader; native names are case insensitive, no aliases."""
    if not isinstance(data, bytes) or not 0 < len(data) <= 1024 * 1024 or b"\0" in data:
        raise ValueError("Bounded native attached metadata required")
    parser = configparser.ConfigParser(
        interpolation=None, delimiters=("=",), comment_prefixes=(";",), strict=True
    )
    try:
        # CINI uses byte strings; Latin1 preserves every non-NUL input byte.
        parser.read_string(data.decode("latin1"))
    except (configparser.Error, UnicodeError) as exc:
        raise ValueError("Invalid native attached INI") from exc
    names = [name.casefold() for name in parser.sections()]
    if len(names) != len(set(names)) or parser.defaults() or len(names) > MAX_RECORDS:
        raise ValueError("Duplicate/inherited or excessive native sections")
    for name in parser.sections():
        if len(name) > 128 or len(parser[name]) > 1024:
            raise ValueError("Native section field bounds exceeded")
        for key, value in parser[name].items():
            if len(key) > 128 or len(value) > 8192:
                raise ValueError("Native field bounds exceeded")
    sections = MappingProxyType(
        {
            name.casefold(): MappingProxyType(dict(parser[name]))
            for name in parser.sections()
        }
    )
    return sections


def metadata_sections_2026(data: bytes) -> tuple[Mapping[str, Mapping[str, str]], int]:
    sections = _ini_sections_2026(data)
    version = _number(sections.get("format", _EMPTY), "version")
    if version not in METADATA_VERSIONS:
        raise ValueError("Unsupported CUW2026 metadata version")
    return sections, version


def parse_cuw_2026(data: bytes) -> CalibrationContainer | NativeUSBSource2026:
    """Validate record framing and CRCs before exposing any metadata or images."""
    if not isinstance(data, bytes) or not 22 <= len(data) <= MAX_SIZE:
        raise ValueError("Bounded CUW2026 container required")
    if data[:13] != b"\0CALIBRATION\0" or data[13] not in CONTAINER_VERSIONS:
        raise ValueError("Invalid CUW2026 signature")
    checksum, size = struct.unpack_from(">II", data, 14)
    if 22 <= size < len(data):
        return _usb_source_2026(data, size)
    if size != len(data) or zlib.crc32(data[18:]) != checksum:
        raise ValueError("CUW2026 length or CRC32 differs")

    def record(position: int):
        start = position
        if position + 2 > len(data):
            raise ValueError("Truncated native record length")
        length = int.from_bytes(data[position : position + 2], "big")
        position += 2
        if position + length + 8 > len(data):
            raise ValueError("Truncated native record header")
        header = data[position : position + length]
        position += length
        count, crc = struct.unpack_from(">II", data, position)
        position += 8
        if count > len(data) - position:
            raise ValueError("Truncated native record payload")
        payload = data[position : position + count]
        if zlib.crc32(payload) != crc:
            raise ValueError("Native record CRC32 differs")
        return CalibrationRecord(start, header, payload, crc), position + count

    attached, cursor = record(22)
    _, version = metadata_sections_2026(attached.data)
    width = 2 if version == 9 else 1
    if cursor + width > len(data):
        raise ValueError("Missing native record count")
    count = int.from_bytes(data[cursor : cursor + width], "big")
    cursor += width
    records = []
    while cursor < len(data):
        if len(records) >= MAX_RECORDS:
            raise ValueError("Native record budget exceeded")
        item, cursor = record(cursor)
        records.append(item)
    if not count <= len(records) <= count * 2:
        raise ValueError("Native declared record count differs")
    return CalibrationContainer(
        data[13],
        hashlib.sha256(data).hexdigest(),
        attached,
        tuple(records),
        count,
        width,
    )


@dataclass(frozen=True)
class Native2026Metadata:
    source_sha256: str
    format_version: int
    node: int
    cpu_index: int
    vehicle: Mapping[str, str] = field(repr=False)
    node_values: Mapping[str, str] = field(repr=False)
    sections: Mapping[str, Mapping[str, str]] = field(repr=False)
    cpus: tuple[NativeCPU, ...] = field(repr=False)
    logical_blocks: tuple = field(repr=False)
    source_container: Any = field(default=None, repr=False, compare=False)
    cpu_type_overrides: Mapping[int, str] = field(
        default_factory=lambda: _EMPTY, repr=False
    )
    cpu_rows: tuple[Mapping[str, str], ...] = field(default=(), repr=False)
    cpu_node_indices: tuple[int, ...] = field(default=(), repr=False)
    region: int = 0
    initial_shrink_flag: bool = False
    parser_cpu_rows: tuple[Mapping[str, str], ...] = field(default=(), repr=False)
    parser_general_parameters: Any = field(default=None, repr=False, compare=False)
    parser_parameters_validated: bool = False
    cpu_target_overrides: Mapping[int, tuple[NativeTarget2026, ...]] = field(
        default_factory=lambda: _EMPTY, repr=False
    )
    runtime_projection: NativeCPUProjection2026 | None = field(
        default=None, repr=False, compare=False
    )
    runtime_selected_cpu: int = 0
    runtime_node_dwords: Mapping[tuple[int, str], int] = field(
        default_factory=lambda: _EMPTY, repr=False
    )
    cpu_flash_size_overrides: Mapping[int, int] = field(
        default_factory=lambda: _EMPTY, repr=False
    )

    @property
    def cpu(self) -> NativeCPU:
        if not self.cpus:
            raise ValueError("Selected node has logical blocks rather than CPU rows")
        return self.cpus[self.cpu_index]

    @property
    def format_type(self) -> int:
        return self.format_version

    @property
    def is_controlled_by_scc(self) -> bool:
        return (
            type(self.source_container) is not NativeRecoveryHeaderSource2026
            and _number(self.sections.get("kindofcal", _EMPTY), "IsControlledBySCC")
            == 1
        )

    @property
    def is_blank_ecu(self) -> bool:
        return (
            type(self.source_container) is not NativeRecoveryHeaderSource2026
            and _number(self.sections.get("kindofcal", _EMPTY), "IsBlankECU") == 1
        )

    @property
    def is_non_field_fix(self) -> bool:
        return (
            type(self.source_container) is not NativeRecoveryHeaderSource2026
            and _number(self.sections.get("kindofcal", _EMPTY), "IsNonFieldFix") == 1
        )

    @property
    def date_of_issue_components(self) -> tuple[int, int, int] | None:
        return native_date_of_issue_components_2026(
            self.sections.get("vehicle", _EMPTY).get("dateofissue", "")
        )

    def node_hex_number(self, name: str, scale: int = 1) -> int:
        if type(scale) is not int or not 0 < scale <= 0xFFFFFFFF:
            raise ValueError("Unsigned nonzero native scale required")
        key = (self.node - 1, name.casefold())
        if key in self.runtime_node_dwords:
            return self.runtime_node_dwords[key]
        return (
            min(_number(self.node_values, name, base=16), 0x7FFFFFFF) * scale
        ) & 0xFFFFFFFF

    @property
    def wakeup_ms(self) -> int:
        return self.node_hex_number("WakeUpTimeAfterReset", 50)

    @property
    def interval_between_frame_ms(self) -> int:
        return self.node_hex_number("IntervalTimeBetweenFrame")

    @property
    def emissions_delay_ms(self) -> int:
        return self.node_hex_number("EmissionsRelatedSystem", 10)

    @property
    def wait_after_programming_ms(self) -> int:
        return self.node_hex_number("WaitTimeAfterProgrammingSession", 50)

    @property
    def charge_local_bus_start_ms(self) -> int:
        return self.node_hex_number("ChargeLocalBusEcuStartTimeAfterPowerOn", 50)

    @property
    def protocol_at_node(self) -> str:
        return self.node_values.get("protocol", "")

    def node_key_bytes(self, name: str) -> bytes:
        return _hex(self.node_values.get(name.casefold(), ""), 16)

    @property
    def service_auth_key_bytes(self) -> bytes:
        return self.node_key_bytes("ServiceAuthKey")

    @property
    def ecu_auth_key_bytes(self) -> bytes:
        return self.node_key_bytes("ECUAuthKey")

    @property
    def global_ecu_auth_key_bytes(self) -> bytes:
        return _hex(self.vehicle.get("ecuauthkey", ""), 16)

    @property
    def global_service_auth_key_bytes(self) -> bytes:
        return _hex(self.vehicle.get("serviceauthkey", ""), 16)

    @property
    def gateway_values(self) -> tuple[Mapping[str, str], ...]:
        count = _number(self.node_values, "NumberOfGateway", maximum=99)
        return tuple(
            MappingProxyType(
                {
                    field: self.node_values.get(f"{index:02}_{field}", "")
                    for field in (
                        "gatewaymode",
                        "gatewaydiagid",
                        "gatewaylogicaladdress",
                    )
                }
            )
            for index in range(1, count + 1)
        )

    @property
    def image_bytes(self) -> bytes:
        if self.cpu.image is None:
            raise ValueError("Selected native CPU has no archive image")
        if not isinstance(self.cpu.image, CalibrationRecord):
            raise TypeError(
                "Large native image requires authenticated streaming archive"
            )
        return self.cpu.image.data

    def report(self) -> dict:
        return {
            "source_sha256": self.source_sha256,
            "format_version": self.format_version,
            "node": self.node,
            "cpu_index": self.cpu_index,
            "cpu_count": native2026_cpu_count(self),
            "selected_node_cpu_count": native2026_node_cpu_count(self, self.node - 1)
            if self.format_version >= 101
            and type(self.source_container) is not NativeRecoveryHeaderSource2026
            else native2026_cpu_count(self),
            "logical_block_count": len(self.logical_blocks),
            "provenance": "authenticated CUW2026 field bindings",
        }


_issued_metadata: weakref.WeakValueDictionary[int, Native2026Metadata] = (
    weakref.WeakValueDictionary()
)


def _issue_metadata(metadata: Native2026Metadata) -> Native2026Metadata:
    _issued_metadata[id(metadata)] = metadata
    return metadata


def native2026_validate_runtime_metadata(
    metadata: Native2026Metadata,
) -> Native2026Metadata:
    """Return the exact issued parser/runtime state; reject copied or forged fields."""
    if (
        type(metadata) is not Native2026Metadata
        or _issued_metadata.get(id(metadata)) is not metadata
    ):
        raise ValueError("Issued native metadata state required")
    _validate_container_2026(metadata.source_container)
    if metadata.runtime_projection is not None:
        _validate_projection(metadata)
    return metadata


@dataclass(frozen=True)
class NativeHeaderArea2026:
    start_address: str = field(repr=False)
    length: str = field(repr=False)

    @property
    def address_bytes(self) -> bytes:
        return _hex(self.start_address)

    @property
    def length_bytes(self) -> bytes:
        return _hex(self.length)


@dataclass(frozen=True)
class NativeHeaderInfo2026:
    data_format_id: str
    areas: tuple[NativeHeaderArea2026, ...] = field(repr=False)

    @property
    def count(self) -> int:
        return len(self.areas)

    def numeric_areas(self) -> tuple[tuple[int, int], ...]:
        return tuple(
            (
                int.from_bytes(area.address_bytes, "big"),
                int.from_bytes(area.length_bytes, "big"),
            )
            for area in self.areas
        )


def _header_info(values: Mapping[str, str]) -> NativeHeaderInfo2026:
    count = _number(values, "NumberOfAreaSettings", maximum=99)
    return NativeHeaderInfo2026(
        values.get("dataformatid", ""),
        tuple(
            NativeHeaderArea2026(
                values.get(f"{index:02}_startaddress", ""),
                values.get(f"{index:02}_length", ""),
            )
            for index in range(1, count + 1)
        ),
    )


def _areas(values: Mapping[str, str]) -> tuple[tuple[int, int], ...]:
    info = _header_info(values)
    try:
        return info.numeric_areas()
    except ValueError:
        # Numeric compatibility view is absent when native structural strings
        # require operation-specific handling. The authoritative header is kept.
        return ()


def native2026_header_info(
    metadata: Native2026Metadata, kind: str = "image", *, cpu_index: int | None = None
) -> NativeHeaderInfo2026:
    """059a0 CFileHeaderInfo string fields; geometry conversion is a separate step."""
    if kind not in ("image", "flash_code", "write_routine", "erase_routine"):
        raise ValueError("Unknown native file-header kind")
    selected = (
        metadata
        if cpu_index is None
        else native2026_metadata_for_cpu(metadata, cpu_index)
    )
    values = selected.cpu.headers.get(kind, _EMPTY) if selected.cpus else _EMPTY
    return _header_info(values)


@dataclass(frozen=True)
class NativeRecoveryHeaderSource2026:
    raw: bytes = field(repr=False)
    digest: str
    cpu_capacity: int


@dataclass(frozen=True)
class NativeCompositeSource2026:
    """An issued19910 composition proof, never a serialized CUW byte stream."""

    left: Native2026Metadata = field(repr=False)
    right: Native2026Metadata = field(repr=False)
    digest: str
    metadata: Native2026Metadata | None = field(default=None, repr=False, compare=False)


_composite_sources: weakref.WeakValueDictionary[int, NativeCompositeSource2026] = (
    weakref.WeakValueDictionary()
)


@dataclass(frozen=True)
class NativeNodeSource2026:
    parent: Native2026Metadata = field(repr=False)
    node_index: int
    digest: str
    metadata: Native2026Metadata | None = field(default=None, repr=False, compare=False)


_node_sources: weakref.WeakValueDictionary[int, NativeNodeSource2026] = (
    weakref.WeakValueDictionary()
)


@dataclass(frozen=True)
class NativeUSBSource2026:
    """Original CUW prefix plus the source-owned USB file trailer."""

    prefix: CalibrationContainer = field(repr=False)
    raw: bytes | None = field(repr=False)
    digest: str
    declared_size: int
    free_space_requirement: int
    trailer_crc32: int
    backing: NativeUSBFileBacking2026 | None = field(
        default=None, repr=False, compare=False
    )

    @property
    def size(self) -> int:
        return (
            len(self.raw)
            if self.raw is not None
            else self.backing.size
            if self.backing is not None
            else 0
        )

    def close(self) -> None:
        if self.backing is not None:
            self.backing.close()

    def __enter__(self):
        _validate_container_2026(self)
        return self

    def __exit__(self, *args):
        self.close()

    @property
    def version(self):
        return self.prefix.version

    @property
    def attached(self):
        return self.prefix.attached

    @property
    def records(self):
        return self.prefix.records

    @property
    def count_width(self):
        return self.prefix.count_width

    @property
    def declared_count(self):
        return self.prefix.declared_count


_usb_sources: weakref.WeakValueDictionary[int, NativeUSBSource2026] = (
    weakref.WeakValueDictionary()
)


def _raise_usb_crc_error() -> None:
    from scripts.programming_2026_common import NativePassThruException2026

    # CUW.dll RVA7c810, raw CP932 source bytes used by32130 at source line0x647.
    source = (
        b"C:\\Shimojo\\local\\CUW.dll\\V1.15.0.3(\x83r\x83\x8b\x83h\x97p)"
        b"\\CUW\\CUW\\CPassThruCtrlr.cpp"
    ).decode("latin1")
    raise NativePassThruException2026(6, source, 0x647)


@dataclass(frozen=True)
class NativeUSBFileBacking2026:
    """Pinned regular-file identity for bounded passive USB copier source reads."""

    path: str = field(init=False, repr=False)
    fd: int = field(init=False, repr=False)
    identity: tuple[int, int, int, int, int] = field(init=False, repr=False)
    size: int = field(init=False)

    def __init__(self, path: str | os.PathLike[str]):
        object.__setattr__(self, "path", os.path.abspath(path))
        object.__setattr__(self, "fd", -1)
        probe = os.open(self.path, os.O_PATH | os.O_CLOEXEC)
        try:
            info = os.fstat(probe)
            if not stat.S_ISREG(info.st_mode) or not 22 <= info.st_size <= 0xFFFFFFFF:
                raise ValueError("Native USB source must be a bounded regular file")
            object.__setattr__(self, "identity", self._identity(info))
            object.__setattr__(self, "size", info.st_size)
            object.__setattr__(
                self,
                "fd",
                os.open(f"/proc/self/fd/{probe}", os.O_RDONLY | os.O_CLOEXEC),
            )
        finally:
            os.close(probe)
        self.verify()

    @staticmethod
    def _identity(info):
        return (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    def verify(self) -> None:
        if (
            self.fd < 0
            or self._identity(os.fstat(self.fd)) != self.identity
            or self._identity(os.stat(self.path)) != self.identity
        ):
            raise ValueError("Original native USB file source changed or closed")

    def read(self, offset: int, length: int) -> bytes:
        self.verify()
        if (
            type(offset) is not int
            or type(length) is not int
            or not 0 <= length <= 0x500000
            or not 0 <= offset <= self.size - length
        ):
            raise ValueError("Native USB file read exceeds bounded original source")
        data = os.pread(self.fd, length, offset)
        if len(data) != length:
            raise ValueError("Native USB file read was truncated")
        self.verify()
        return data

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            object.__setattr__(self, "fd", -1)

    def __del__(self):
        if hasattr(self, "fd"):
            self.close()


def native2026_usb_file_source(path: str | os.PathLike[str]) -> NativeUSBSource2026:
    """32130/2bc70 source capture throughUINT32_MAX with bounded file reads."""
    backing = NativeUSBFileBacking2026(path)
    try:
        header = backing.read(0, 22)
        size = int.from_bytes(header[18:22], "big")
        if not 22 <= size <= min(backing.size, MAX_SIZE):
            raise ValueError("Native USB CUW prefix exceeds its host/source bound")
        prefix_bytes = b"".join(
            backing.read(offset, min(0x500000, size - offset))
            for offset in range(0, size, 0x500000)
        )
        prefix = parse_cuw_2026(prefix_bytes)
        if type(prefix) is not CalibrationContainer:
            raise ValueError("Native USB file requires an ordinary CUW prefix")
        sections, version = metadata_sections_2026(prefix.attached.data)
        if (
            version != 12
            or sections.get("vehicle", _EMPTY).get("canidtx_phys_usdt", "") != "0795"
            or not prefix.records
            or len(prefix.records[0].data) < 12
        ):
            raise ValueError(
                "Native USB file requires metadata12/0795 and its CPU header"
            )
        digest = hashlib.sha256()
        crc = 0
        for offset in range(0, backing.size, 0x500000):
            chunk = backing.read(offset, min(0x500000, backing.size - offset))
            digest.update(chunk)
            if offset + len(chunk) > size:
                crc = zlib.crc32(chunk[max(0, size - offset) :], crc)
        expected = int.from_bytes(prefix.records[0].data[8:12], "big")
        if crc != expected:
            _raise_usb_crc_error()
        result = NativeUSBSource2026(
            prefix,
            None,
            digest.hexdigest(),
            size,
            int.from_bytes(prefix.records[0].data[:8], "big"),
            expected,
            backing,
        )
        _usb_sources[id(result)] = result
        return result
    except BaseException:
        backing.close()
        raise


def native2026_usb_source(data: bytes) -> NativeUSBSource2026:
    if not isinstance(data, bytes) or not 22 <= len(data) <= MAX_SIZE:
        raise ValueError("Bounded original native USB file bytes required")
    size = int.from_bytes(data[18:22], "big")
    if not 22 <= size <= len(data):
        raise ValueError("Native USB declared prefix exceeds its source")
    return _usb_source_2026(data, size)


def _usb_source_2026(data: bytes, size: int) -> NativeUSBSource2026:
    prefix = parse_cuw_2026(data[:size])
    if type(prefix) is not CalibrationContainer:
        raise ValueError("Native USB requires a single CUW prefix")
    sections, version = metadata_sections_2026(prefix.attached.data)
    if (
        version != 12
        or sections.get("vehicle", _EMPTY).get("canidtx_phys_usdt", "") != "0795"
    ):
        raise ValueError("CUW trailer requires the native USB metadata12 producer")
    if not prefix.records or len(prefix.records[0].data) < 12:
        raise ValueError("Native USB first CPU archive requires twelve header bytes")
    header = prefix.records[0].data
    expected = int.from_bytes(header[8:12], "big")
    if zlib.crc32(data[size:]) != expected:
        _raise_usb_crc_error()
    result = NativeUSBSource2026(
        prefix,
        data,
        hashlib.sha256(data).hexdigest(),
        size,
        int.from_bytes(header[:8], "big"),
        expected,
    )
    _usb_sources[id(result)] = result
    return result


@dataclass(frozen=True)
class NativeUSBSourceSpan2026:
    source_container: NativeUSBSource2026 = field(repr=False, compare=False)
    source_sha256: str
    offset: int
    length: int
    crc32: int
    free_space_requirement: int
    image_name: str = field(repr=False)

    def read(self, offset: int = 0, length: int | None = None) -> bytes:
        _validate_container_2026(self.source_container)
        if _usb_spans.get(id(self)) is not self:
            raise ValueError("Issued native USB source span required")
        size = min(0x500000, self.length - offset) if length is None else length
        if (
            type(offset) is not int
            or type(size) is not int
            or not 0 <= offset <= self.length
            or not 0 <= size <= self.length - offset
        ):
            raise ValueError("Native USB source read exceeds its trailer span")
        if self.source_container.raw is not None:
            return self.source_container.raw[
                self.offset + offset : self.offset + offset + size
            ]
        assert self.source_container.backing is not None
        return self.source_container.backing.read(self.offset + offset, size)

    def iter_chunks(self, chunk_size: int = 0x500000):
        _validate_container_2026(self.source_container)
        if _usb_spans.get(id(self)) is not self:
            raise ValueError("Issued native USB source span required")
        if type(chunk_size) is not int or not 1 <= chunk_size <= 0x500000:
            raise ValueError("Bounded native USB chunk size required")
        for offset in range(0, self.length, chunk_size):
            yield self.read(offset, min(chunk_size, self.length - offset))


_usb_spans: weakref.WeakValueDictionary[int, NativeUSBSourceSpan2026] = (
    weakref.WeakValueDictionary()
)


def native2026_usb_source_span(metadata: Native2026Metadata) -> NativeUSBSourceSpan2026:
    """32130→2bc70→508c0: capture the actual copier input, not CPU image bytes."""
    native2026_validate_runtime_metadata(metadata)
    source = metadata.source_container
    _validate_container_2026(source)
    if type(source) is not NativeUSBSource2026:
        raise ValueError("Issued original native USB source container required")
    result = NativeUSBSourceSpan2026(
        source,
        source.digest,
        source.declared_size,
        source.size - source.declared_size,
        source.trailer_crc32,
        source.free_space_requirement,
        native2026_cpu_values(native2026_metadata(source), 0).get("cpuimagename", ""),
    )
    _usb_spans[id(result)] = result
    return result


_recovery_headers: weakref.WeakValueDictionary[int, NativeRecoveryHeaderSource2026] = (
    weakref.WeakValueDictionary()
)


def _validate_container_2026(container: Any) -> None:
    if isinstance(container, NativeUSBSource2026):
        if (
            type(container) is not NativeUSBSource2026
            or _usb_sources.get(id(container)) is not container
        ):
            raise ValueError("Issued original native USB source required")
        _validate_container_2026(container.prefix)
        if container.backing is not None:
            container.backing.verify()
        return
    if isinstance(container, NativeNodeSource2026):
        if (
            type(container) is not NativeNodeSource2026
            or _node_sources.get(id(container)) is not container
        ):
            raise ValueError("Issued native node source required")
        _validate_container_2026(container.parent.source_container)
        return
    if isinstance(container, NativeCompositeSource2026):
        if (
            type(container) is not NativeCompositeSource2026
            or _composite_sources.get(id(container)) is not container
        ):
            raise ValueError("Issued native composite source required")
        _validate_container_2026(container.left.source_container)
        _validate_container_2026(container.right.source_container)
        return
    if isinstance(container, NativeRecoveryHeaderSource2026):
        if (
            type(container) is not NativeRecoveryHeaderSource2026
            or _recovery_headers.get(id(container)) is not container
        ):
            raise ValueError("Source-issued recovery header required")
        return
    if not isinstance(container, CalibrationContainer):
        from scripts.cuw_large import validate_large_container_2026

        validate_large_container_2026(container)
        return
    if (
        type(container.version) is not int
        or container.version not in CONTAINER_VERSIONS
        or type(container.count_width) is not int
        or container.count_width not in (1, 2)
        or type(container.declared_count) is not int
        or not 0 <= container.declared_count < 1 << (8 * container.count_width)
        or not isinstance(container.records, tuple)
        or len(container.records) > MAX_RECORDS
    ):
        raise ValueError("Invalid native container value type")
    body = bytearray()
    for index, item in enumerate((container.attached,) + container.records):
        if index == 1:
            body.extend(container.declared_count.to_bytes(container.count_width, "big"))
        if (
            not isinstance(item, CalibrationRecord)
            or not isinstance(item.header, bytes)
            or not isinstance(item.data, bytes)
            or len(item.header) > 65535
            or item.offset != 22 + len(body)
            or zlib.crc32(item.data) != item.crc32
        ):
            raise ValueError("Native container record provenance differs")
        body.extend(struct.pack(">H", len(item.header)))
        body.extend(item.header)
        body.extend(struct.pack(">II", len(item.data), item.crc32))
        body.extend(item.data)
        if len(body) > MAX_SIZE - 22:
            raise ValueError("Native container size exceeds host bound")
    if not container.records:
        body.extend(container.declared_count.to_bytes(container.count_width, "big"))
    suffix = struct.pack(">I", 22 + len(body)) + body
    raw = (
        b"\0CALIBRATION\0"
        + bytes((container.version,))
        + struct.pack(">I", zlib.crc32(suffix))
        + suffix
    )
    if hashlib.sha256(raw).hexdigest() != container.digest:
        raise ValueError("Native container source digest differs")


def _logical_node(values: Mapping[str, str]) -> bool:
    # CUW0dc90:02/10 CPU;03/04/01 logical. Unknown specs use parser's CPU branch.
    return values.get("requiredspecreprover", "") in ("03", "04", "01")


def decode_metadata_string_2026(value: str) -> str:
    """2dae0(param5=1): decode hexadecimal pairs, subtract the byte index."""
    if (
        not isinstance(value, str)
        or len(value) > 2048
        or not re.fullmatch(r"(?:[0-9A-Fa-f]{2})*", value)
    ):
        raise ValueError("Bounded encoded native metadata string required")
    result = bytes(
        (
            (
                (
                    (ord(value[index * 2]) - (7 if value[index * 2] > "9" else 0) - 48)
                    * 16
                )
                | (
                    ord(value[index * 2 + 1])
                    - (7 if value[index * 2 + 1] > "9" else 0)
                    - 48
                )
            )
            - index
        )
        & 255
        for index in range(len(value) // 2)
    )
    if b"\0" in result:
        raise ValueError(
            "Encoded native metadata string contains a C-string terminator"
        )
    return result.decode("latin1")


def encode_metadata_string_2026(value: str) -> str:
    """Inverse authored-data codec; callers supply their own explicit field value."""
    if not isinstance(value, str) or len(value) > 1024 or "\0" in value:
        raise ValueError("Bounded authored metadata string required")
    try:
        data = value.encode("latin1")
    except UnicodeError as exc:
        raise ValueError("Native byte-string field required") from exc
    return bytes((item + index) & 255 for index, item in enumerate(data)).hex().upper()


def native_date_of_issue_components_2026(value: str) -> tuple[int, int, int] | None:
    """2ddd0/MSVC time_get: numeric components, without a calendar cross-check.

    ASCII ctype whitespace is supported. Locale-dependent additional ctype bytes
    and the native user's %x output presentation remain separate contracts.
    """
    if not isinstance(value, str) or len(value) > 1024 or "\0" in value:
        raise ValueError("Bounded native date string required")
    whitespace = " \t\r\n\v\f"
    cursor = 0
    while cursor < len(value) and value[cursor] in whitespace:
        cursor += 1
    result = []
    for width, minimum, maximum in ((4, 0, 9999), (2, 1, 12), (2, 1, 31)):
        count = 0
        while cursor < len(value) and count < width and value[cursor] in whitespace:
            cursor += 1
            count += 1
        sign = 1
        if cursor < len(value) and value[cursor] in "+-":
            sign = -1 if value[cursor] == "-" else 1
            cursor += 1
        digits = ""
        while cursor < len(value) and count < width and "0" <= value[cursor] <= "9":
            digits += value[cursor]
            cursor += 1
            count += 1
        if not count:
            return None
        component = sign * int(digits or "0")
        if not minimum <= component <= maximum:
            return None
        result.append(component)
        if len(result) < 3:
            if cursor >= len(value) or value[cursor] != "-":
                return None
            cursor += 1
    return result[0], result[1], result[2]


def _decoded_fields(
    values: Mapping[str, str], names: tuple[str, ...]
) -> Mapping[str, str]:
    result = dict(values)
    for name in names:
        if result.get(name, ""):
            result[name] = decode_metadata_string_2026(result[name])
    return MappingProxyType(result)


def _native_cpu_populated(values: Mapping[str, str], version: int) -> bool:
    """06230 stops at the first CPU with no four identifiers or populated target."""
    if any(
        values.get(name, "")
        for name in ("locationid", "newcid", "cputype", "cpuimagename")
    ):
        return True
    count = _number(values, "NumberOfTargets", maximum=1000)
    for index in range(1, count + 1):
        prefix = f"{index:02}" if index < 100 else f"{index:04}"
        if values.get(f"{prefix}_targetcalibration", ""):
            return True
        if (
            version < 101
            and version not in (8, 9, 10, 12)
            and _number(values, f"{prefix}_TargetData", base=16)
        ):
            return True
    return False


def _cpu_targets(
    values: Mapping[str, str], version: int
) -> tuple[NativeTarget2026, ...]:
    """05e80 permits trailing empty slots, but no gaps or data without a name."""
    result = []
    empty_seen = False
    for index in range(1, _number(values, "NumberOfTargets", maximum=1000) + 1):
        prefix = f"{index:02}" if index < 100 else f"{index:04}"
        calibration = values.get(f"{prefix}_targetcalibration", "")
        if (version != 0 and not calibration.isascii()) or len(calibration) > 256:
            raise ValueError("Bounded native target calibration required")
        password = (
            0
            if version in (8, 9, 10, 12) or version >= 101
            else _number(values, f"{prefix}_TargetData", base=16)
        )
        if version != 0 and (
            (not calibration and password) or (calibration and empty_seen)
        ):
            raise ValueError("Native target array contains a gap or unnamed data")
        empty_seen |= not calibration
        result.append(NativeTarget2026(calibration, password))
    return tuple(result)


def native2026_metadata(
    container: Any, *, node: int = 1, cpu_index: int = 0, region: int = 0
) -> Native2026Metadata:
    """Select native metadata from a parsed container, retaining original fields."""
    if (
        type(node) is not int
        or not 0 <= node <= 16
        or type(cpu_index) is not int
        or not 0 <= cpu_index < MAX_RECORDS
        or type(region) is not int
        or not 0 <= region <= 3
    ):
        raise ValueError("Bounded native node/CPU selection required")
    _validate_container_2026(container)
    if type(container) in (NativeCompositeSource2026, NativeNodeSource2026):
        metadata = container.metadata
        if metadata is None or region != metadata.region:
            raise ValueError("Issued composite metadata region required")
        matches = [
            index
            for index in range(native2026_cpu_count(metadata))
            if native2026_node_index(metadata, index) == node - 1
        ]
        if not 0 <= cpu_index < len(matches):
            raise ValueError("Selected composite native CPU absent")
        return native2026_metadata_for_cpu(metadata, matches[cpu_index])
    if type(container) is NativeRecoveryHeaderSource2026:
        if node not in (0, 1):
            raise ValueError("Recovery header has no native node vector")
        return _recovery_header_metadata(container, cpu_index, region)
    sections, version = metadata_sections_2026(container.attached.data)
    if container.count_width != (2 if version == 9 else 1):
        raise ValueError("Native record count width differs from metadata version")
    vehicle = _decoded_fields(
        sections.get("vehicle", _EMPTY), ("ecuauthkey", "serviceauthkey")
    )
    if not vehicle:
        raise ValueError("Native Vehicle section absent")
    vehicle = dict(vehicle)
    vehicle["enginetype"] = vehicle.get("system", "") or vehicle.get("enginetype", "")
    if version == 2 and vehicle.get("modelyear", ""):
        # 06370 ASM6c75..6cae keeps signed strtol's remainder, then prints %02d.
        match = re.match(r"[ \t\r\n\v\f]*([+-]?)([0-9]+)", vehicle["modelyear"])
        if match is None:
            raise ValueError("Native metadata2 ModelYear decimal conversion failed")
        digits = match[2].lstrip("0") or "0"
        if len(digits) > 10:
            raise ValueError("Native metadata2 ModelYear signed32 overflow")
        year = int(digits) * (-1 if match[1] == "-" else 1)
        if not -0x80000000 <= year <= 0x7FFFFFFF:
            raise ValueError("Native metadata2 ModelYear signed32 overflow")
        remainder = abs(year) % 100 * (-1 if year < 0 else 1)
        value = f"{remainder:02d}"
        if len(value) > 2:
            raise ValueError("Native metadata2 ModelYear output exceeds its buffer")
        vehicle["modelyear"] = value
    flags = sections.get("kindofcal", _EMPTY)
    if _number(flags, "IsControlledBySCC") == 1 and _number(flags, "IsBlankECU") != 1:
        keys = ("vehicletype", "enginetype", "vehiclename", "modelyear")
        existing = tuple(vehicle.get(key, "") for key in keys)
        na = tuple(sections.get("vehicleforna", _EMPTY).get(key, "") for key in keys)
        eu = tuple(sections.get("vehicleforeuot", _EMPTY).get(key, "") for key in keys)
        selected = (na, eu, existing, eu)[region]
        if not any(selected):
            if all(existing):
                selected = existing
            elif all(na):
                selected = na
            elif all(eu):
                selected = eu
        vehicle.update(zip(keys, selected, strict=True))
    vehicle = MappingProxyType(vehicle)
    if version in (2, 3):
        try:
            vehicle = MappingProxyType(
                {**vehicle, "kindofecu": _ECU_NAMES_2026[vehicle.get("kindofecu", "")]}
            )
        except KeyError as exc:
            raise ValueError("Unknown native historical ECU name") from exc
    if version == 10 and _number(vehicle, "ByteNumberOfTransmitting", base=16) < 3:
        raise ValueError("Native metadata10 ByteNumberOfTransmitting must be at least3")
    node_count = _number(vehicle, "NumberOfNode", maximum=16)
    if version >= 101:
        if not 1 <= node <= node_count:
            raise ValueError("Selected native node does not exist")
        nodes = [
            (
                index,
                _decoded_fields(
                    sections.get(f"node{index:02}", _EMPTY),
                    ("ecuauthkey", "serviceauthkey"),
                ),
            )
            for index in range(1, node_count + 1)
        ]
    else:
        nodes = [(0, vehicle)]
    cpus = []
    declared_files = 0
    if version in (10, 12) and _number(vehicle, "NumberOfCalibration") != 1:
        raise ValueError("Native metadata10/12 requires exactly one CPU")
    for node_number, node_values in nodes:
        count = (
            0
            if version >= 101 and _logical_node(node_values)
            else _number(
                node_values, "NumberOfCalibration", maximum=99 if version < 101 else 9
            )
        )
        for ordinal in range(1, count + 1):
            suffix = f"{ordinal:02}" if version < 101 else f"{node_number}{ordinal}"
            name = f"CPU{suffix}"
            if name.casefold() not in sections:
                raise ValueError("Declared native CPU section absent")
            values = sections[name.casefold()]
            if version in (10, 12):
                # 06370 c4a0..cdd7 reads this distinct schema, not ordinary CPU keys.
                special = {
                    key: values.get(key, "")
                    for key in (
                        "cpuimagename",
                        "numberoftargets",
                        "newcid",
                        "startaddress",
                        "sizeofuncompresseddownloaddata",
                        "sizeofdownloaddata",
                        "seedkeyid",
                    )
                }
                for index in range(
                    1, _number(values, "NumberOfTargets", maximum=1000) + 1
                ):
                    prefix = f"{index:02}" if index < 100 else f"{index:04}"
                    special[f"{prefix}_targetcalibration"] = values.get(
                        f"{prefix}_targetcalibration", ""
                    )
                special.update(
                    {
                        "cputype": "",
                        "locationid": "",
                        "flashcodename": "",
                        "numberoffiles": "",
                        "newpassword": "",
                    }
                )
                special["seedkeyid"] = (
                    decode_metadata_string_2026(special["seedkeyid"])
                    if special["seedkeyid"]
                    else ""
                )
                values = MappingProxyType(special)
            elif version >= 101:
                read_names = {
                    "cpuimagename",
                    "newcid",
                    "compressionalgorithm",
                    "securityproperty2",
                    "seedkey",
                    "nonce",
                    "repromethod",
                    "offsetaddress",
                    "p4servermaxtime",
                    "numberoftargets",
                }
                read_names.update(
                    (f"{index:02}" if index < 100 else f"{index:04}")
                    + "_targetcalibration"
                    for index in range(
                        1, _number(values, "NumberOfTargets", maximum=1000) + 1
                    )
                )
                values = MappingProxyType(
                    {
                        **{
                            key: value
                            for key, value in values.items()
                            if key in read_names
                        },
                        "newpassword": "",
                        "cputype": "",
                        "locationid": "",
                        "flashcodename": "",
                        "numberoffiles": "",
                    }
                )
            else:
                read_names = {
                    "cpuimagename",
                    "flashcodename",
                    "newcid",
                    "locationid",
                    "ecutype" if version in (2, 3) else "cputype",
                    "numberoftargets",
                    "newpassword",
                    "nonce",
                    "seedkey",
                    "numberoftargethardwares",
                    "numberoffiles",
                }
                for index in range(
                    1, _number(values, "NumberOfTargets", maximum=1000) + 1
                ):
                    prefix = f"{index:02}" if index < 100 else f"{index:04}"
                    read_names.add(prefix + "_targetcalibration")
                    if version not in (8, 9):
                        read_names.add(prefix + "_targetdata")
                read_names.update(
                    f"{index:02}_targethardware"
                    for index in range(
                        1, _number(values, "NumberOfTargetHardwares", maximum=99) + 1
                    )
                )
                if version == 4:
                    read_names.update(
                        f"{index:02}_cpuimagename" for index in range(1, 5)
                    )
                    read_names.update(("cmacforflashcodedata", "cmacforcpuimagedata"))
                values = MappingProxyType(
                    {
                        **{
                            key: value
                            for key, value in values.items()
                            if key in read_names
                        },
                        "compressionalgorithm": "",
                        "securityproperty2": "",
                        "repromethod": "",
                        "offsetaddress": "",
                        "p4servermaxtime": "0",
                    }
                )
            if version in (2, 3):
                try:
                    cpu_type = _CPU_NAMES_2026[values.get("ecutype", "")]
                except KeyError as exc:
                    raise ValueError("Unknown native historical CPU name") from exc
                if cpu_type == "10" and vehicle.get("contacttype", "") == "SIL":
                    cpu_type = "9"
                values = MappingProxyType({**values, "cputype": cpu_type})
            if version not in (10, 12):
                encoded = ("nonce", "seedkey")
                if version < 101:
                    encoded += ("newpassword",)
                    if version == 4:
                        encoded += ("cmacforflashcodedata", "cmacforcpuimagedata")
                    if version not in (8, 9):
                        encoded += tuple(
                            (f"{index:02}" if index < 100 else f"{index:04}")
                            + "_targetdata"
                            for index in range(
                                1, _number(values, "NumberOfTargets", maximum=1000) + 1
                            )
                        )
                values = _decoded_fields(values, encoded)
            _cpu_targets(values, version)
            headers = MappingProxyType(
                {
                    kind: sections.get(f"{prefix}{suffix}".casefold(), _EMPTY)
                    if version not in (10, 12)
                    and (
                        kind != "flash_code"
                        if version >= 101
                        else kind in ("image", "flash_code")
                    )
                    else _EMPTY
                    for kind, prefix in (
                        ("image", "CPUImage"),
                        ("flash_code", "FlashCode"),
                        ("write_routine", "WriteRoutine"),
                        ("erase_routine", "EraseRoutine"),
                    )
                }
            )
            if version >= 101:
                # 06370 modern header branches never read DataFormatID.
                headers = MappingProxyType(
                    {
                        kind: MappingProxyType({**info, "dataformatid": ""})
                        for kind, info in headers.items()
                    }
                )
            elif version not in (10, 12):
                info = headers["flash_code"]
                headers = MappingProxyType(
                    {
                        **headers,
                        "flash_code": MappingProxyType(
                            {
                                key: ""
                                if re.fullmatch(r"[0-9]+_length", key)
                                else value
                                for key, value in info.items()
                            }
                        ),
                    }
                )
            files = tuple(
                NativeCPUFile(
                    index, sections.get(f"file{len(cpus) + 1}{index:03}", _EMPTY), None
                )
                for index in range(1, _number(values, "NumberOfFiles", maximum=258) + 1)
            )
            declared_files += len(files)
            if declared_files > 258:
                raise ValueError("Native global file count exceeds258")
            cpus.append(
                NativeCPU(
                    len(cpus),
                    node_number,
                    name,
                    values,
                    node_values,
                    vehicle,
                    None,
                    None,
                    _areas(headers["image"]),
                    _areas(headers["write_routine"]),
                    _areas(headers["erase_routine"]),
                    files,
                    headers,
                )
            )
    parser_rows = tuple(cpu.values for cpu in cpus)
    initial_shrink = all(
        any(
            target.calibration == cpu.values.get("newcid", "")
            for target in _cpu_targets(cpu.values, version)
        )
        for cpu in cpus
    )
    # 06230 global count terminates at the first empty row;165f0 uses that count.
    if not any(_logical_node(values) for _, values in nodes):
        populated = []
        for cpu in cpus:
            if not _native_cpu_populated(cpu.values, version):
                break
            populated.append(cpu)
        cpus = populated
    # Logical payload ordering is version dependent and is bound separately below.
    if version >= 101 and (
        any(_logical_node(values) for _, values in nodes)
        or not isinstance(container, CalibrationContainer)
    ):
        return _logical_metadata(
            container, sections, version, vehicle, nodes, node, cpu_index, cpus, region
        )
    cursor = 0

    def take():
        nonlocal cursor
        if cursor >= len(container.records):
            raise ValueError("Missing native CPU archive record")
        record = container.records[cursor]
        cursor += 1
        return record

    multiple_images = (
        tuple(
            (slot, cpus[0].values.get(f"{slot:02}_cpuimagename", ""))
            for slot in range(1, 5)
        )
        if version == 4 and cpus
        else ()
    )
    multiple_images = tuple((slot, name) for slot, name in multiple_images if name)
    if multiple_images:
        if len(cpus) > len(multiple_images):
            raise ValueError("Native CPU rows exceed the multi-image archive vector")
        files = tuple(
            NativeCPUFile(slot, MappingProxyType({"cpuimagename": name}), take())
            for slot, name in multiple_images
        )
        flash_code = take()
        cpus = [
            replace(
                cpu,
                image=files[index].record,
                files=files if index == 0 else (),
                flash_code=flash_code if index == 0 else None,
            )
            for index, cpu in enumerate(cpus)
        ]
        expected = len(files)
    elif version == 9:
        cpus = [
            replace(
                cpu, files=tuple(replace(info, record=take()) for info in cpu.files)
            )
            for cpu in cpus
        ]
        expected = cursor
    else:
        cpus = [replace(cpu, image=take()) for cpu in cpus]
        expected = len(cpus)
        cpus = [
            replace(cpu, flash_code=take())
            if version < 101 and cpu.values.get("flashcodename", "")
            else cpu
            for cpu in cpus
        ]
    if cursor != len(container.records) or expected != container.declared_count:
        raise ValueError("Native CPU archive order/count differs")
    if version == 9:
        cpus = [
            replace(cpu, files=tuple(_native9_file(info) for info in cpu.files))
            for cpu in cpus
        ]
    selected = tuple(cpu for cpu in cpus if version < 101 or cpu.node == node)
    if cpu_index >= len(selected):
        raise ValueError("Selected native CPU does not exist")
    values = dict(nodes).get(node, vehicle)
    return _issue_metadata(
        Native2026Metadata(
            container.digest,
            version,
            node,
            cpu_index,
            vehicle,
            values,
            sections,
            selected,
            (),
            container,
            cpu_rows=tuple(cpu.values for cpu in cpus),
            cpu_node_indices=tuple(max(0, cpu.node - 1) for cpu in cpus),
            region=region,
            initial_shrink_flag=initial_shrink,
            parser_cpu_rows=parser_rows,
        )
    )


def native2026_recovery_header(
    data: bytes, *, cpu_capacity: int, region: int = 0
) -> Native2026Metadata:
    """331b0→120e0 standalone SCUW header; no binary framing or image fabrication."""
    _ini_sections_2026(data)
    if type(cpu_capacity) is not int or not 0 <= cpu_capacity <= MAX_RECORDS:
        raise ValueError("Bounded actual configured CPU capacity required")
    source = NativeRecoveryHeaderSource2026(
        data, hashlib.sha256(data).hexdigest(), cpu_capacity
    )
    _recovery_headers[id(source)] = source
    return native2026_metadata(source, region=region)


def _recovery_header_metadata(
    source: NativeRecoveryHeaderSource2026, cpu_index: int, region: int
) -> Native2026Metadata:
    sections = _ini_sections_2026(source.raw)
    raw_vehicle = sections.get("vehicle", _EMPTY)
    vehicle = MappingProxyType(
        {
            key: raw_vehicle.get(key, "")
            for key in (
                "dateofissue",
                "vehicletype",
                "enginetype",
                "vehiclename",
                "modelyear",
                "contacttype",
            )
        }
    )
    declared = _number(raw_vehicle, "NumberOfCalibration", maximum=source.cpu_capacity)
    cpus = []
    parser_rows = []
    prefix_open = True
    for index in range(declared):
        # 120e0 snprintf_s uses capacity6 and _TRUNCATE, including at CPU100.
        name = f"cpu{index + 1}"[:5]
        original = sections.get(name, _EMPTY)
        count = _number(original, "NumberOfTargets", maximum=1000)
        values = {"newcid": original.get("newcid", ""), "numberoftargets": str(count)}
        for ordinal in range(1, count + 1):
            # Its capacity21 snprintf_s key truncates beyond two ordinal digits.
            prefix = f"{ordinal:02}" if ordinal < 100 else f"{ordinal:04}"
            values[prefix + "_targetcalibration"] = original.get(
                f"{ordinal:02}_targetcalibration"[:20], ""
            )
        row = MappingProxyType(values)
        parser_rows.append(row)
        prefix_open = prefix_open and _native_cpu_populated(row, 0)
        if prefix_open:
            cpus.append(
                NativeCPU(
                    index,
                    0,
                    name,
                    row,
                    _EMPTY,
                    vehicle,
                    None,
                    None,
                    (),
                    (),
                    (),
                    (),
                    _EMPTY,
                )
            )
    if cpu_index >= len(cpus) and (cpus or cpu_index):
        raise ValueError("Selected recovery header CPU absent")
    return _issue_metadata(
        Native2026Metadata(
            source.digest,
            500,
            0,
            cpu_index,
            vehicle,
            _EMPTY,
            sections,
            tuple(cpus),
            (),
            source,
            cpu_rows=tuple(cpu.values for cpu in cpus),
            cpu_node_indices=(0,) * len(cpus),
            region=region,
            parser_cpu_rows=tuple(parser_rows),
        )
    )


def native2026_selection_metadata(
    container: Any, *, node: int = 1, cpu_index: int = 0, region: int = 0
) -> dict:
    metadata = native2026_metadata(
        container, node=node, cpu_index=cpu_index, region=region
    )
    contact = metadata.vehicle.get("contacttype", "")
    if not contact:
        raise ValueError("Native Vehicle ContactType missing")
    required = (
        metadata.node_values.get("requiredspecreprover", "")
        if metadata.format_version >= 101
        else "02"
    )
    if not required:
        raise ValueError("Native node reprogramming specification missing")
    return {
        "kind_of_ecu": metadata.vehicle.get("kindofecu", ""),
        "cpu_type": native2026_cpu_type(metadata, 0),
        "contact_type": contact,
        "required_spec": required,
    }


@dataclass(frozen=True)
class NativeDatePresentation2026:
    """A platform formatter result bound to its exact parsed date and source."""

    value: bytes = field(repr=False)
    components: tuple[int, int, int]
    raw_date: str = field(repr=False)
    source_container: Any = field(repr=False, compare=False)


_date_presentations: weakref.WeakValueDictionary[int, NativeDatePresentation2026] = (
    weakref.WeakValueDictionary()
)


def native2026_date_presentation(
    metadata: Native2026Metadata,
    formatter: Callable[[tuple[int, int, int]], bytes],
) -> NativeDatePresentation2026:
    """2ddd0: supply exact parsed components to the native-locale platform primitive."""
    native2026_validate_runtime_metadata(metadata)
    _validate_container_2026(metadata.source_container)
    components = metadata.date_of_issue_components
    if components is None or not callable(formatter):
        raise ValueError("Valid native date and platform formatter required")
    value = formatter(components)
    if not isinstance(value, bytes) or len(value) >= 0x13 or b"\0" in value:
        raise ValueError("Bounded native date presentation bytes required")
    _validate_container_2026(metadata.source_container)
    result = NativeDatePresentation2026(
        value,
        components,
        metadata.sections.get("vehicle", _EMPTY).get("dateofissue", ""),
        metadata.source_container,
    )
    _date_presentations[id(result)] = result
    return result


def _file_output_buffer(value: bytes, size: int) -> bytearray:
    if not isinstance(value, bytes) or len(value) != size:
        raise ValueError("Exact immutable native file output buffer required")
    return bytearray(value)


def _file_output_string(
    output: bytearray, offset: int, capacity: int, value: str | bytes
) -> None:
    try:
        encoded = value.encode("latin1") if isinstance(value, str) else value
    except UnicodeError as exc:
        raise ValueError(
            "Native file output string must preserve original bytes"
        ) from exc
    if len(encoded) >= capacity or b"\0" in encoded:
        raise ValueError("Native file output string exceeds its field")
    output[offset : offset + len(encoded) + 1] = encoded + b"\0"


def native2026_file_header(
    metadata: Native2026Metadata,
    caller_header: bytes,
    *,
    date_presentation: NativeDatePresentation2026 | None = None,
) -> bytes:
    """5ccf0 parser fields only; engine flags and caller padding remain untouched."""
    native2026_validate_runtime_metadata(metadata)
    _validate_container_2026(metadata.source_container)
    output = _file_output_buffer(caller_header, 0x98)
    components = metadata.date_of_issue_components
    date = b""
    if date_presentation is not None:
        if (
            type(date_presentation) is not NativeDatePresentation2026
            or _date_presentations.get(id(date_presentation)) is not date_presentation
            or date_presentation.source_container is not metadata.source_container
            or date_presentation.components != components
            or date_presentation.raw_date
            != metadata.sections.get("vehicle", _EMPTY).get("dateofissue", "")
        ):
            raise ValueError("Source-issued native date presentation required")
        date = date_presentation.value
    elif components is not None:
        raise ValueError("Valid date requires a native-locale presentation")
    _file_output_string(output, 0, 0x13, date)
    for offset, name in (
        (0x13, "vehiclename"),
        (0x26, "modelyear"),
        (0x39, "vehicletype"),
        (0x4C, "enginetype"),
    ):
        _file_output_string(output, offset, 0x13, metadata.vehicle.get(name, ""))
    struct.pack_into("<I", output, 0x64, native2026_cpu_count(metadata))
    _file_output_string(output, 0x68, 0x21, metadata.vehicle.get("contacttype", ""))
    output[0x89] = metadata.is_controlled_by_scc
    output[0x8A] = metadata.is_non_field_fix
    struct.pack_into("<I", output, 0x94, metadata.format_version)
    return bytes(output)


def native2026_file_cpu(
    metadata: Native2026Metadata, global_cpu_index: int, caller_row: bytes
) -> bytes:
    """5ccf0 CPU fields;34680's trailing DWORD belongs to engine orchestration."""
    native2026_validate_runtime_metadata(metadata)
    _validate_container_2026(metadata.source_container)
    values = native2026_cpu_values(metadata, global_cpu_index)
    output = _file_output_buffer(caller_row, 0xBBAC)
    _file_output_string(output, 0, 0x24, values.get("newcid", ""))
    targets = native2026_cpu_targets(metadata, global_cpu_index)
    if len(targets) > 1000:
        raise ValueError("Native CPU output target capacity exceeded")
    node_values = (
        native2026_node_values(
            metadata, native2026_node_index(metadata, global_cpu_index)
        )
        if metadata.format_version >= 101
        and type(metadata.source_container) is not NativeRecoveryHeaderSource2026
        else _EMPTY
    )
    diagnostic_id = node_values.get("diagid", "") or node_values.get(
        "logicaladdress", ""
    )
    try:
        diagnostic_bytes = diagnostic_id.encode("latin1")[:6]
    except UnicodeError as exc:
        raise ValueError("Native diagnostic ID must preserve original bytes") from exc
    struct.pack_into("<I", output, 0x24, len(targets))
    for index, target in enumerate(targets):
        offset = 0x28 + index * 0x30
        _file_output_string(output, offset, 0x28, target.calibration)
        _file_output_string(output, offset + 0x28, 7, diagnostic_bytes)
    return bytes(output)


@dataclass(frozen=True)
class NativeLogicalArea2026:
    kind: str
    address: int
    length: int
    crc: bytes | None = field(repr=False)
    cmac: bytes = field(repr=False)
    digital_signature: bytes = field(repr=False)
    record: Any = field(repr=False)
    data: bytes | None = field(repr=False)
    values: Mapping[str, str] = field(repr=False)

    @property
    def address_bytes(self) -> bytes:
        return _hex(self.values.get("startaddress", ""))

    @property
    def transfer_length(self) -> int:
        return _number(self.values, "TransferLength", base=16)

    @property
    def check_data(self) -> bytes:
        return _hex(self.values.get("checkdata", ""))


@dataclass(frozen=True)
class NativeLogicalBlock2026:
    node: int
    slot: int
    cpu_index: int
    new_cid: str = field(repr=False)
    targets: tuple[str, ...] = field(repr=False)
    required_spec: str
    repro_method: str
    nonce: bytes = field(repr=False)
    areas: tuple[NativeLogicalArea2026, ...] = field(repr=False)
    node_values: Mapping[str, str] = field(repr=False)
    values: Mapping[str, str] = field(repr=False)

    @property
    def routine_response_pending_limit(self) -> int:
        # CUW dd60 +6f8 -> 18030 input+130 -> CalibrationFile5c10 +6d0.
        return (
            min(
                _number(
                    self.values,
                    "P4ServerMaxTime",
                    base=16,
                    default=3 if "p4servermaxtime" not in self.values else 0,
                ),
                0x7FFFFFFF,
            )
            * 60
        ) & 0xFFFFFFFF

    @property
    def did_subtype(self) -> int:
        return self.slot

    @property
    def device_info(self) -> bytes:
        return self.nonce

    @property
    def repro_method_type(self) -> int:
        return {
            "00": 1,
            "01": 1,
            "05": 1,
            "03": 2,
            "07": 2,
            "08": 2,
            "02": 3,
            "09": 3,
            "0A": 3,
        }.get(self.repro_method, 0)


def _logical_metadata(
    container, sections, version, vehicle, nodes, node, cpu_index, cpus, region
):
    blocks = []
    cursor = 0
    cpu_base = 0
    bound_cpus = []
    area_limit = MAX_SIZE if isinstance(container, CalibrationContainer) else 0xFFFFFFFF
    rewritten = None
    rewritten_cursor = 0
    if not isinstance(container, CalibrationContainer):
        from scripts.cuw_large import NativeLargeContainer2026

        if type(container) is NativeLargeContainer2026:
            # 2aad0 retains original length/CRC headers but replaces every payload
            # with324 bytes.189e0 imports ordinary CPU rows with16030 flag ZERO.
            rewritten = b"".join(
                struct.pack(">H", len(item.header))
                + item.header
                + struct.pack(">II", item.length, item.crc32)
                + item.descriptor
                for item in container.records
            )

    def take(*, logical: bool = True):
        nonlocal cursor, rewritten_cursor
        if cursor >= len(container.records):
            raise ValueError("Missing native logical archive record")
        record = container.records[cursor]
        cursor += 1
        if rewritten is not None:
            if isinstance(record, CalibrationRecord):
                raise ValueError("Native large original descriptor record required")
            start = rewritten_cursor
            if start + 2 > len(rewritten):
                raise ValueError("Native large rewritten record header is truncated")
            header_size = int.from_bytes(rewritten[start : start + 2], "big")
            payload_start = start + 2 + header_size + 8
            if payload_start > len(rewritten):
                raise ValueError("Native large rewritten record header is truncated")
            size, checksum = struct.unpack_from(">II", rewritten, payload_start - 8)
            imported_size = 0x144 if logical else size
            if imported_size > len(rewritten) - payload_start:
                raise ValueError(
                    "Native large CPU ImportData0: Data too big for storage"
                )
            payload = rewritten[payload_start : payload_start + imported_size]
            rewritten_cursor = payload_start + imported_size
            if not logical:
                if zlib.crc32(payload) != checksum:
                    raise ValueError("Native large CPU ImportData0 CRC differs")
                return CalibrationRecord(
                    record.offset,
                    rewritten[start + 2 : payload_start - 8],
                    payload,
                    checksum,
                )
            if (
                rewritten[start + 2 : payload_start - 8] != record.header
                or size != record.length
                or checksum != record.crc32
                or payload != record.descriptor
            ):
                raise ValueError(
                    "Native large logical descriptor lost original source correspondence"
                )
        return record

    for node_number, node_values in nodes:
        if not _logical_node(node_values):
            for cpu in (cpu for cpu in cpus if cpu.node == node_number):
                bound_cpus.append(
                    replace(cpu, index=cpu_base, image=take(logical=False))
                )
                cpu_base += 1
            continue
        count = _number(node_values, "NumberOfLogicalBlock", maximum=32)
        identifiers = []
        selected = []
        for slot in range(1, 33) if count else ():
            values = _decoded_fields(
                sections.get(f"logicalblock{node_number}{slot:02}", _EMPTY), ("nonce",)
            )
            new_cid = values.get("newcid", "")
            if not new_cid:
                continue
            if (
                len(new_cid) > 256
                or not new_cid.isascii()
                or any(ord(c) < 32 for c in new_cid)
            ):
                raise ValueError("Bounded native NewCID required")
            if new_cid not in identifiers:
                identifiers.append(new_cid)
            method = values.get("repromethod", "")
            if method not in ("00", "01", "02", "03", "05", "07", "08", "09", "0A"):
                raise ValueError("Unknown native logical method")
            targets = tuple(
                values.get(
                    f"{index:02}_targetcalibration"
                    if index < 100
                    else f"{index:04}_targetcalibration",
                    "",
                )
                for index in range(
                    1, _number(values, "NumberOfTargets", maximum=1000) + 1
                )
            )
            if any(not value.isascii() or len(value) > 256 for value in targets):
                raise ValueError("Bounded native target calibration required")
            # Native189e0 reads whole after routine only for Format.Version500.
            separate_routine = version in (206, 209, 400, 500) and method != "00"
            kinds = [
                "ReproData",
                "EraseAndReproRoutine",
                "DeltaReproData",
                "DeltaEraseAndReproRoutine",
                "CompressionReproData",
                "CompressionEraseAndReproRoutine",
                "DeltaOrCompressionReproData",
            ]
            if version == 500 and separate_routine:
                kinds[:2] = reversed(kinds[:2])
            bound = {}
            for kind in kinds:
                info = sections.get(f"{kind}{node_number}{slot:02}".casefold(), _EMPTY)
                if not info.get("length", ""):
                    continue
                address = int.from_bytes(_hex(info.get("startaddress", "")), "big")
                length = _number(info, "Length", base=16)
                if (
                    not 0 <= length <= area_limit
                    or not (0 if length == 0 else 1)
                    <= len(_hex(info.get("startaddress", "")))
                    <= 512
                ):
                    raise ValueError("Native logical area outside host bounds")
                if not length or (
                    kind == "EraseAndReproRoutine" and not separate_routine
                ):
                    record = None
                else:
                    record = take()
                crc = _hex(info.get("crc", ""))
                bound[kind] = NativeLogicalArea2026(
                    kind,
                    address,
                    length,
                    crc or None,
                    _hex(info.get("cmac", "")),
                    _hex(info.get("digitalsignature", "")),
                    record,
                    b""
                    if record is None
                    else record.data
                    if isinstance(record, CalibrationRecord)
                    else None,
                    info,
                )
            # These three sections contain geometry only;189e0 consumes no record.
            for kind in ("EraseMemory", "ReproDataSegment02", "ReproDataSegment03"):
                area_name = (f"{kind}{node_number}{slot:02}").casefold()
                info = sections.get(area_name, _EMPTY)
                if info.get("length", ""):
                    address = int.from_bytes(_hex(info.get("startaddress", "")), "big")
                    length = _number(info, "Length", base=16)
                    if (
                        not 0 <= length <= area_limit
                        or not (0 if length == 0 else 1)
                        <= len(_hex(info.get("startaddress", "")))
                        <= 512
                    ):
                        raise ValueError("Native logical geometry outside host bounds")
                    bound[kind] = NativeLogicalArea2026(
                        kind,
                        address,
                        length,
                        None,
                        _hex(info.get("cmac", "")),
                        _hex(info.get("digitalsignature", "")),
                        None,
                        b"",
                        info,
                    )
            selected.append(
                NativeLogicalBlock2026(
                    node_number,
                    slot,
                    cpu_base + identifiers.index(new_cid),
                    new_cid,
                    targets,
                    node_values.get("requiredspecreprover", ""),
                    method,
                    _fixed_metadata_bytes(values.get("nonce", ""), 16),
                    tuple(bound.values()),
                    node_values,
                    values,
                )
            )
            if len(selected) == count:
                break
        if len(selected) != count:
            raise ValueError("Native logical populated-slot count differs")
        blocks.extend(selected)
        cpu_base += len(identifiers)
    if cursor != len(container.records) or cursor != container.declared_count:
        raise ValueError("Native logical archive count/order differs")
    selected = tuple(block for block in blocks if block.node == node)
    selected_cpus = tuple(cpu for cpu in bound_cpus if cpu.node == node)
    rows = {cpu.index: cpu.values for cpu in bound_cpus}
    row_nodes = {cpu.index: cpu.node - 1 for cpu in bound_cpus}
    target_unions: dict[int, list[str]] = {}
    for block in blocks:
        rows.setdefault(
            block.cpu_index,
            MappingProxyType(
                {
                    "newcid": block.new_cid,
                    "cputype": "",
                    "locationid": "",
                    "p4servermaxtime": "0",
                }
            ),
        )
        row_nodes.setdefault(block.cpu_index, block.node - 1)
        targets = target_unions.setdefault(block.cpu_index, [])
        for target in block.targets:
            if target not in targets:
                targets.append(target)
    # 10970 merges first-seen distinct strings across blocks sharing a NewCID.
    # 05e80 validates the synthesized CPU array, not each block independently.
    for index, targets in target_unions.items():
        values = {**rows[index], "numberoftargets": str(len(targets))}
        values.update(
            {
                (f"{ordinal:02}" if ordinal < 100 else f"{ordinal:04}")
                + "_targetcalibration": target
                for ordinal, target in enumerate(targets, 1)
            }
        )
        _cpu_targets(values, version)
        rows[index] = MappingProxyType(values)
    initial_shrink = all(
        any(
            target.calibration == values.get("newcid", "")
            for target in _cpu_targets(values, version)
        )
        for values in rows.values()
    )
    effective_count = next(
        (
            index
            for index in range(cpu_base)
            if not _native_cpu_populated(rows[index], version)
        ),
        cpu_base,
    )
    if any(block.cpu_index >= effective_count for block in blocks):
        raise ValueError(
            "Native logical block references a CPU beyond the06230 exported vector"
        )
    selected_cpus = tuple(cpu for cpu in selected_cpus if cpu.index < effective_count)
    if cpu_index >= len(selected_cpus or selected):
        raise ValueError("Selected native CPU/logical block absent")
    return _issue_metadata(
        Native2026Metadata(
            container.digest,
            version,
            node,
            cpu_index,
            vehicle,
            dict(nodes)[node],
            sections,
            selected_cpus,
            selected,
            container,
            cpu_rows=tuple(rows[index] for index in range(effective_count)),
            cpu_node_indices=tuple(
                row_nodes[index] for index in range(effective_count)
            ),
            region=region,
            initial_shrink_flag=initial_shrink,
            parser_cpu_rows=tuple(rows[index] for index in range(cpu_base)),
        )
    )


@dataclass(frozen=True)
class NativeDownloadGeometry2026:
    start_address: bytes
    uncompressed_size: int
    download_size: int


def native2026_download_geometry(
    metadata: Native2026Metadata,
) -> NativeDownloadGeometry2026:
    """06370 c4a0..cdd7 fields exist exclusively in metadata10/12 CPU01."""
    if not isinstance(metadata, Native2026Metadata) or metadata.format_version not in (
        10,
        12,
    ):
        raise ValueError("Native download geometry requires CUW2026 metadata10/12")
    values = metadata.cpu.values
    address = _hex(values.get("startaddress", ""))
    if not 0 < len(address) <= 512:
        raise ValueError("Bounded variable native StartAddress bytes required")
    uncompressed = _number(values, "SizeOfUncompressedDownloadData", base=16)
    size = _number(values, "SizeOfDownloadData", base=16)
    if not 0 < size <= MAX_SIZE or not 0 <= uncompressed <= MAX_SIZE:
        raise ValueError("Native download geometry outside host bounds")
    return NativeDownloadGeometry2026(address, uncompressed, size)


@dataclass(frozen=True)
class NativeArchive2026:
    """The distinct native GetData/GetLength/GetFlashSize/GetHeader outputs."""

    data: bytes | None = field(repr=False)
    flash_size: int
    header: bytes = field(repr=False)
    records: tuple[tuple[int, bytes], ...] = field(repr=False)
    raw: bytes = field(repr=False)
    kind_records: tuple[tuple[int, int, bytes], ...] = field(default=(), repr=False)
    streamed: bool = False
    length_override: int | None = None
    backing: Any = field(default=None, repr=False, compare=False)

    @property
    def length(self) -> int:
        if self.length_override is not None:
            return self.length_override
        return len(self.raw) if self.data is None else len(self.data)

    @property
    def header_length(self) -> int:
        return len(self.header)

    @property
    def mapped_records(self) -> tuple[tuple[int, bytes], ...]:
        """Native retained record map; binary materializations have no map."""
        if self.data is not None:
            return ()
        if self.kind_records:
            # 6a9d0 exports S0 alongside data; S5 and termination are discarded.
            return tuple(
                (address, payload)
                for kind, address, payload in self.kind_records
                if kind in (0, 1, 2, 3)
            )
        return self.records

    @property
    def record_count(self) -> int:
        return len(self.mapped_records)


def materialize_srecords_2026(
    data: bytes, *, preserve: bool = False, checksum_mode: int = 1
) -> NativeArchive2026:
    """CUW6a9d0/6ae60: S0 bytes, sorted address map, FF-filled binary span.

    Host policy rejects overlapping rows and inconsistent termination/counts.
    Native target memory unsafety and silent overlap are not reproduced.
    """
    if (
        not isinstance(data, bytes)
        or not 0 < len(data) <= MAX_SIZE
        or type(preserve) is not bool
        or type(checksum_mode) is not int
        or checksum_mode not in (1, 2)
    ):
        raise ValueError("Bounded native S-record input required")
    widths = {0: 2, 1: 2, 2: 3, 3: 4, 5: 2, 7: 4, 8: 3, 9: 2}
    headers = []
    kind_records = []
    rows = []
    count_row = None
    terminated = False
    for index, line in enumerate(data.splitlines()):
        if (
            index >= 1000000
            or not line
            or len(line) > 514
            or len(line) < 4
            or line[:1] != b"S"
        ):
            raise ValueError("Native S-record line outside bounds")
        if terminated:
            raise ValueError("Native S-record data follows termination")
        try:
            kind = int(chr(line[1]), 10)
            raw = _hex(line[2:].decode("ascii"))
            width = widths[kind]
            if kind == 5:
                if not raw or raw[0] not in (3, 4, 5):
                    raise ValueError("Native S5 count must contain2,3or4 address bytes")
                width = raw[0] - 1
        except (KeyError, UnicodeError, ValueError) as exc:
            raise ValueError("Malformed native S-record") from exc
        if (
            not raw
            or len(raw) != raw[0] + 1
            or raw[0] < width + 1
            or sum(raw) & 255 != (255 if checksum_mode == 1 else 0)
        ):
            raise ValueError("Native S-record length/checksum differs")
        address = int.from_bytes(raw[1 : 1 + width], "big")
        payload = raw[1 + width : -1]
        kind_records.append((kind, address, payload))
        if kind == 0:
            headers.append(payload)
        elif kind in (1, 2, 3):
            if not payload or address + len(payload) > 2**32:
                raise ValueError("Native S-record payload outside address bounds")
            rows.append((address, payload))
        elif kind in (5, 6):
            if payload or count_row is not None:
                raise ValueError("Invalid repeated native S-record count")
            count_row = address
        else:
            if payload:
                raise ValueError("Native termination record contains data")
            terminated = True
    if not rows or count_row is not None and count_row != len(rows):
        raise ValueError("Native S-record data count differs")
    ordered = tuple(sorted(rows))
    start = ordered[0][0] if preserve else rows[0][0]
    end = (
        max(address + len(payload) for address, payload in ordered)
        if preserve
        else rows[-1][0] + len(rows[-1][1])
    )
    if end < start or any(
        address < start or address + len(payload) > end for address, payload in rows
    ):
        raise ValueError("Native S-record first/last span excludes data rows")
    if end - start > MAX_SIZE:
        raise ValueError("Native S-record materialization exceeds host limit")
    result = bytearray(b"\xff") * (end - start)
    previous_end = start
    for address, payload in ordered:
        if address < previous_end:
            raise ValueError("Overlapping native S-record data")
        result[address - start : address - start + len(payload)] = payload
        previous_end = address + len(payload)
    return NativeArchive2026(
        None if preserve else bytes(result),
        sum(len(payload) for _, payload in rows)
        - (
            next((len(payload) for kind, _, payload in kind_records if kind == 1), 0)
            if preserve
            else 0
        ),
        b"" if preserve else b"".join(headers),
        tuple(rows) if preserve else ordered,
        data,
        tuple(kind_records),
    )


def decode_lzf_hex_frames_2026(data: bytes) -> bytes:
    """CUW57b80 keeps encoded ZV frames; it performs no LZF decompression."""
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_SIZE:
        raise ValueError("Bounded native LZF hexadecimal input required")
    compact = data.replace(b"\r", b"").replace(b"\n", b"")
    if not re.fullmatch(rb"(?:[0-9A-Fa-f]{2})+", compact):
        raise ValueError("Strict even native LZF hexadecimal input required")
    decoded = bytes.fromhex(compact.decode("ascii"))
    cursor = 0
    while cursor < len(decoded):
        if decoded[cursor : cursor + 2] != b"ZV" or cursor + 5 > len(decoded):
            raise ValueError("Truncated native LZF frame")
        kind = decoded[cursor + 2]
        if compact[cursor * 2 : cursor * 2 + 6] not in (b"5A5600", b"5A5601"):
            raise ValueError("Exact native LZF frame prefix required")
        header = 5 if kind == 0 else 7 if kind == 1 else 0
        if not header or cursor + header > len(decoded):
            raise ValueError("Unknown/truncated native LZF frame type")
        size = int.from_bytes(decoded[cursor + 3 : cursor + 5], "big")
        if not size or cursor + header + size > len(decoded):
            raise ValueError("Truncated/empty native LZF frame payload")
        if kind == 1 and not int.from_bytes(decoded[cursor + 5 : cursor + 7], "big"):
            raise ValueError("Native compressed LZF frame has empty expanded size")
        cursor += header + size
    return decoded


def _native9_file(info: NativeCPUFile) -> NativeCPUFile:
    """37fd0 rewrites the exported file download address/size, retaining raw sections."""
    if not isinstance(info.record, CalibrationRecord):
        raise TypeError("Native metadata9 file record absent")
    alfid = info.values.get("alfid", "")
    if not re.fullmatch(r"[0-4][0-4]", alfid):
        raise ValueError("Native file ALFID widths require two hexadecimal digits <=4")
    values = dict(info.values)
    address = _number(values, "DownloadAddress", base=16, maximum=0x7FFFFFFF)
    length = _number(values, "DownloadMemsize", base=16, maximum=0x7FFFFFFF)
    if not values.get("downloadaddress", "") or not values.get("downloadmemsize", ""):
        raise ValueError("Explicit native file download address/size required")
    if info.record.data.startswith(b"S"):
        archive = materialize_srecords_2026(info.record.data)
        address = (address + archive.records[0][0]) & 0xFFFFFFFF
    values["downloadaddress"] = f"{address:0{int(alfid[1], 16) * 2}x}"
    values["downloadmemsize"] = f"{length:0{int(alfid[0], 16) * 2}x}"
    return replace(info, values=MappingProxyType(values))


def native2026_archive(
    metadata: Native2026Metadata,
    *,
    flash_code: bool = False,
    preserve_srecords: bool = False,
    file_index: int | None = None,
) -> NativeArchive2026:
    """378b0 native archive classification without external filenames or I/O."""
    native2026_validate_runtime_metadata(metadata)
    if not isinstance(metadata, Native2026Metadata) or type(flash_code) is not bool:
        raise TypeError("Native metadata and Boolean archive selector required")
    if metadata.runtime_projection is not None:
        _validate_projection(metadata)
        if not 0 <= metadata.runtime_selected_cpu < len(metadata.cpu_rows):
            raise ValueError("Selected native projected CPU is absent")
        if metadata.runtime_projection.classify_after_projection and metadata.cpus:
            # Initial32130 node filtering precedes378b0, unlike3e710 runtime moves.
            view = _issue_metadata(replace(metadata, runtime_projection=None))
            return native2026_archive(
                view,
                flash_code=flash_code,
                preserve_srecords=preserve_srecords,
                file_index=file_index,
            )
        original = metadata.runtime_projection.contexts[metadata.runtime_selected_cpu]
        archive = native2026_archive(
            original,
            flash_code=flash_code,
            preserve_srecords=preserve_srecords,
            file_index=file_index,
        )
        if (
            not flash_code
            and metadata.runtime_selected_cpu in metadata.cpu_flash_size_overrides
        ):
            archive = replace(
                archive,
                flash_size=metadata.cpu_flash_size_overrides[
                    metadata.runtime_selected_cpu
                ],
            )
        return archive
    if type(metadata.source_container) is NativeRecoveryHeaderSource2026:
        raise ValueError("Recovery header contains no native archive backing")
    if not metadata.cpus:
        if file_index is not None:
            raise ValueError("Logical CPU archive has no CPU file list")
        if metadata.source_container is not None:
            _validate_container_2026(metadata.source_container)
        # 189e0 owns logical records in +34, not the default CPU archives in +20.
        # 48670/36f30 update only the CPU archive's separate FlashSize field.
        total = (
            0
            if flash_code
            else native2026_logical_cpu_flash_size(
                metadata, native2026_global_cpu_index(metadata)
            )
        )
        return NativeArchive2026(None, total, b"", (), b"")
    if (
        metadata.format_version == 12
        and metadata.vehicle.get("canidtx_phys_usdt", "") == "0795"
        and type(metadata.source_container) is not NativeUSBSource2026
    ):
        raise ValueError(
            "Native USB external backing requires its source-span producer"
        )
    if metadata.format_version == 9 and not flash_code:
        index = 0 if file_index is None else file_index
        if type(index) is not int or not 0 <= index < len(metadata.cpu.files):
            raise ValueError("Selected native CPU file index absent")
        record = metadata.cpu.files[index].record
        if not isinstance(record, CalibrationRecord):
            raise ValueError("Native file archive record absent")
        if record.data.startswith(b"S"):
            return replace(materialize_srecords_2026(record.data), flash_size=0)
        return NativeArchive2026(record.data, 0, b"", (), record.data)
    multi4 = metadata.format_version == 4 and any(
        native2026_cpu_values(metadata, 0).get(f"{slot:02}_cpuimagename", "")
        for slot in range(1, 5)
    )
    if multi4 and not flash_code:
        index = metadata.cpu.index if file_index is None else file_index
        converted = metadata.cpus[0].files
        if type(index) is not int or not 0 <= index < len(converted):
            raise ValueError("Selected native CPU file index absent")
        record = converted[index].record
        if not isinstance(record, CalibrationRecord):
            raise ValueError("Native file archive record absent")
        # 38690 only transforms the CPU0 archived-file-list prefix of the vector.
        archive = materialize_srecords_2026(record.data)
        if index == 0:
            total = sum(
                materialize_srecords_2026(item.record.data).flash_size
                for item in converted
                if isinstance(item.record, CalibrationRecord)
            )
            archive = replace(archive, flash_size=total)
        # 17490 skips the ordinary archive copies for every multi4 row. Its
        # final loop exports only data/FlashSize, leaving length/header zero.
        return replace(archive, length_override=0, header=b"")
    if file_index is not None:
        raise ValueError("Native file index applies only to multi-image archives")
    record = metadata.cpu.flash_code if flash_code else metadata.cpu.image
    if record is None:
        if flash_code:
            return NativeArchive2026(None, 0, b"", (), b"")
        raise ValueError("Selected native archive absent")
    if not isinstance(record, CalibrationRecord):
        _validate_container_2026(metadata.source_container)
        raise TypeError("Large CPU archive classification is not a logical stream")
    data = record.data
    from scripts.cuw_large import NativeLargeContainer2026

    origin = metadata.source_container
    while type(origin) is NativeNodeSource2026:
        origin = origin.parent.source_container
    if type(origin) is NativeLargeContainer2026:
        # 32130 takes36f30 instead of378b0; that pass visits only logical nodes.
        return NativeArchive2026(data, 0, b"", (), data)
    if multi4 and flash_code:
        return replace(materialize_srecords_2026(data), flash_size=0, header=b"")
    if metadata.format_version in (10, 12) or ".vbf" in native2026_cpu_values(
        metadata, 0
    ).get("cpuimagename", ""):
        return NativeArchive2026(data, len(data), b"", (), data)
    if flash_code:
        mode = (
            2
            if metadata.vehicle.get("kindofecu", "") == "149"
            and metadata.cpu.values.get("cputype", "") == "311"
            else 1
        )
        archive = materialize_srecords_2026(data, checksum_mode=mode)
        return replace(archive, header=b"")
    if data.startswith(b"S"):
        return materialize_srecords_2026(data, preserve=preserve_srecords)
    if data.startswith(b":"):
        return materialize_intel_hex_2026(data)
    decoded = decode_lzf_hex_frames_2026(data)
    return NativeArchive2026(decoded, len(decoded), b"", (), data)


def materialize_intel_hex_2026(data: bytes) -> NativeArchive2026:
    """57060 retains data-address rows and exposes no contiguous GetData buffer."""
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_SIZE:
        raise ValueError("Bounded native Intel HEX input required")
    base = 0
    ended = False
    rows = []
    for index, line in enumerate(data.splitlines()):
        if index >= 1000000 or ended or not 11 <= len(line) <= 521 or line[:1] != b":":
            raise ValueError("Native Intel HEX record outside bounds/order")
        try:
            raw = _hex(line[1:].decode("ascii"))
        except (UnicodeError, ValueError) as exc:
            raise ValueError("Malformed native Intel HEX record") from exc
        if len(raw) != raw[0] + 5 or sum(raw) & 255:
            raise ValueError("Native Intel HEX count/checksum differs")
        address = int.from_bytes(raw[1:3], "big")
        kind = raw[3]
        payload = raw[4:-1]
        if kind == 0:
            absolute = base + address
            if not payload or absolute + len(payload) > 2**32:
                raise ValueError("Native Intel HEX data outside address bounds")
            rows.append((absolute, payload))
        elif kind == 1:
            if address or payload:
                raise ValueError("Invalid native Intel HEX EOF")
            ended = True
        elif kind in (2, 4):
            if address or len(payload) != 2:
                raise ValueError("Invalid native Intel HEX extended address")
            base = int.from_bytes(payload, "big") << (4 if kind == 2 else 16)
        elif kind in (3, 5):
            if address or len(payload) != 4:
                raise ValueError("Invalid native Intel HEX start address")
        else:
            raise ValueError("Unknown native Intel HEX record type")
    if not ended or not rows:
        raise ValueError("Native Intel HEX EOF/data absent")
    previous = -1
    for address, payload in sorted(rows):
        if address < previous:
            raise ValueError("Overlapping native Intel HEX data")
        previous = address + len(payload)
    return NativeArchive2026(
        None, sum(len(payload) for _, payload in rows), b"", tuple(rows), data
    )


# CUW2026 static constructor 10001050.c; exact case-sensitive names.
_CPU_NAMES_2026 = {
    "32B 192K": "0",
    "32B 256K": "1",
    "32B 320K": "2",
    "32B 384K": "3",
    "32BH 384K": "4",
    "32BH 512K": "5",
    "32BH 768K": "6",
    "32BL 384K": "7",
    "TX2": "8",
    "MPC565": "10",
    "PG2": "11",
    "32BHs 384K": "12",
    "32BHs 512K": "13",
    "32BHs 768K": "14",
    "FOREST-1": "15",
    "FOREST-2": "16",
    "M16C/26T": "17",
    "M16C/29T 96K": "18",
    "M16C/29T 120K(Plug-in)": "19",
    "ST10F275": "20",
    "32BHF": "21",
    "B32R-V85 512K": "22",
    "32B-C2 256K": "23",
    "32B-C2 512K": "24",
    "32B-C2 768K": "25",
    "TC1766": "26",
    "PEC1 384K": "27",
    "SH72512": "28",
    "PIC16F877A": "29",
    "PEC2 512K": "30",
    "Denso DCM": "31",
    "Delphi DCM/HOST": "32",
    "Delphi DCM/DSP": "33",
    "Delphi DCM/PIC": "34",
    "SH72264": "35",
    "SH72265": "36",
    "SH7142": "37",
    "APEC0M": "38",
    "WEGA 768K": "39",
    "GP8": "40",
    "V850ES(CCP) 256K": "41",
    "PACE1T 384K": "42",
    "M32C/85 320K": "43",
    "V850E/GP2 384K": "44",
    "V850E/GP8 512K": "45",
    "F2171-97207 384K": "46",
    "M32R 512K": "47",
    "PRL": "48",
    "MPC565CAN": "10",
}


# CUW2026 static constructor 10002400.c; exact case-sensitive names.
_ECU_NAMES_2026 = {
    "ENG & ECT": "0",
    "HV": "1",
    "THS": "2",
    "MG": "3",
    "VSC/ABS/ECB": "4",
    "FC": "5",
    "FCHV": "6",
    "EPB": "7",
    "PRL": "8",
    "ENG2": "9",
    "HV Battery": "10",
    "DCM(Telematics)": "11",
    "ASG": "12",
    "EMPS": "13",
    "VGRS": "14",
    "ARS": "15",
    "Plug-in Control": "16",
    "ENG(DH)": "17",
    "ECT(DH)": "18",
    "ECT": "10000",
    "ENG": "10001",
}


@dataclass(frozen=True)
class NativeTarget2026:
    calibration: str = field(repr=False)
    password: int = field(repr=False)


def native2026_cpu_targets(
    metadata: Native2026Metadata,
    cpu_index: int | None = None,
) -> tuple[NativeTarget2026, ...]:
    """Current CPU by default; an explicit index addresses the global CPU vector."""
    if not isinstance(metadata, Native2026Metadata):
        raise TypeError("Native CUW2026 metadata required")
    index = native2026_global_cpu_index(metadata) if cpu_index is None else cpu_index
    values = native2026_cpu_values(metadata, index)
    if index in metadata.cpu_target_overrides:
        return metadata.cpu_target_overrides[index]
    return _cpu_targets(
        values,
        0
        if type(metadata.source_container) is NativeRecoveryHeaderSource2026
        else metadata.format_version,
    )


def _with_cpu_targets(
    metadata: Native2026Metadata, index: int, targets: tuple[NativeTarget2026, ...]
) -> Native2026Metadata:
    native2026_validate_runtime_metadata(metadata)
    values = dict(native2026_cpu_values(metadata, index))
    values["numberoftargets"] = str(len(targets))
    for ordinal, target in enumerate(targets, 1):
        prefix = f"{ordinal:02}" if ordinal < 100 else f"{ordinal:04}"
        values[prefix + "_targetcalibration"] = target.calibration
        values[prefix + "_targetdata"] = f"{target.password:08X}"
    row = MappingProxyType(values)
    rows = tuple(
        row if current == index else native2026_cpu_values(metadata, current)
        for current in range(native2026_cpu_count(metadata))
    )
    return _issue_metadata(
        replace(
            metadata,
            cpu_rows=rows,
            cpus=tuple(
                replace(cpu, values=row) if cpu.index == index else cpu
                for cpu in metadata.cpus
            ),
            cpu_target_overrides=MappingProxyType(
                {**metadata.cpu_target_overrides, index: targets}
            ),
        )
    )


def native2026_append_current_target(
    metadata: Native2026Metadata, cpu_index: int, general_parameters: Any
) -> tuple[Native2026Metadata, int]:
    """17280→163c0: append current NewCID and its image-derived password DWORD."""
    native2026_validate_runtime_metadata(metadata)
    from scripts.programming_2026_common import NativeGeneralParameters2026

    _validate_container_2026(metadata.source_container)
    values = native2026_cpu_values(metadata, cpu_index)
    if type(general_parameters) is not NativeGeneralParameters2026:
        raise TypeError("Concrete native General parameter source required")
    if (
        metadata.parser_parameters_validated
        and metadata.parser_general_parameters.source_sha256
        != general_parameters.source_sha256
    ):
        raise ValueError("Target password General source differs from parser profile")
    kind, contact = (
        metadata.vehicle.get("kindofecu", ""),
        metadata.vehicle.get("contacttype", ""),
    )
    cpu_type = native2026_cpu_type(metadata, cpu_index)
    address = general_parameters.string_with_keys(
        kind, cpu_type, contact, "PasswordAddress"
    )
    order = general_parameters.long_with_keys(kind, cpu_type, contact, "ByteOrder")
    selected = native2026_metadata_for_cpu(metadata, cpu_index)
    preserve = False
    multi4 = metadata.format_version == 4 and any(
        native2026_cpu_values(metadata, 0).get(f"{slot:02}_cpuimagename", "")
        for slot in range(1, 5)
    )
    if (
        selected.cpus
        and metadata.format_version not in (9, 10, 12)
        and not multi4
        and ".vbf" not in native2026_cpu_values(metadata, 0).get("cpuimagename", "")
    ):
        preserve = general_parameters.boolean_with_keys(
            kind, cpu_type, contact, "FlagToHoldSFormatRecords"
        )
    password = native2026_archive_password(
        native2026_archive(selected, preserve_srecords=preserve),
        {"PasswordAddress": address, "ByteOrder": "0" if order == 0 else "1"},
    )
    targets = native2026_cpu_targets(metadata, cpu_index)
    # Native computes the password before its capacity comparison, even if full.
    if len(targets) >= 1000:
        return metadata, len(targets) - 1
    targets = (*targets, NativeTarget2026(values.get("newcid", ""), password))
    return _with_cpu_targets(metadata, cpu_index, targets), len(targets) - 1


def native2026_cpu_ids(metadata: Native2026Metadata) -> tuple[int, int, int, int]:
    """GetCPUIDandMSGID output parameters2,3,4,5, in native ABI order."""
    value = metadata.cpu.values.get("locationid", "")
    if len(value) != 16 or not re.fullmatch(r"[0-9a-fA-F]{16}", value):
        raise ValueError("Native location ID requires sixteen hexadecimal digits")
    return (
        int(value[8:12], 16),
        int(value[12:16], 16),
        int(value[4:8], 16),
        int(value[:4], 16),
    )


def native2026_logical_archive(
    metadata: Native2026Metadata, block: NativeLogicalBlock2026, kind: str
) -> NativeArchive2026:
    """189e0 archive ownership and378b0→41670/48670 materialization dispatch."""
    native2026_validate_runtime_metadata(metadata)
    if not isinstance(metadata, Native2026Metadata) or not any(
        block is item for item in metadata.logical_blocks
    ):
        raise ValueError("Source-bound selected native logical block required")
    if metadata.runtime_projection is not None:
        _validate_projection(metadata)
        for context in metadata.runtime_projection.contexts:
            original = next(
                (
                    item
                    for item in context.logical_blocks
                    if item.slot == block.slot
                    and item.new_cid == block.new_cid
                    and len(item.areas) == len(block.areas)
                    and all(
                        first.record is second.record
                        and first.kind == second.kind
                        and first.address == second.address
                        and first.length == second.length
                        for first, second in zip(item.areas, block.areas, strict=True)
                    )
                ),
                None,
            )
            if original is not None:
                return native2026_logical_archive(context, original, kind)
        raise ValueError("Projected logical block lost its original backing owner")
    area = next((area for area in block.areas if area.kind == kind), None)
    if area is None or area.record is None:
        return NativeArchive2026(None, 0, b"", (), b"")
    if not isinstance(area.record, CalibrationRecord):
        return _large_logical_archive(metadata, block, area)
    raw = area.record.data
    if metadata.format_version not in (206, 209, 400):
        transform = kind in (
            "DeltaEraseAndReproRoutine",
            "CompressionEraseAndReproRoutine",
        )
        if kind == "ReproData":
            transform = (
                not block.values.get("wholereprofilename", "").lower().endswith(".binx")
            )
        elif kind == "EraseAndReproRoutine":
            transform = (
                not block.values.get("eraseandreproroutinefilename", "")
                .lower()
                .endswith(".binx")
            )
        if transform:
            return materialize_srecords_2026(raw, preserve=True)
    # Raw logical archives retain native default FlashSize0; CPU total is separate.
    return NativeArchive2026(raw, 0, b"", (), raw)


def _large_logical_archive(
    metadata: Native2026Metadata,
    block: NativeLogicalBlock2026,
    area: NativeLogicalArea2026,
) -> NativeArchive2026:
    from scripts.cuw_large import materialize_large_record_2026

    # CUW36f30: descriptor groups are metadata addresses, never caller geometry.
    values = {item.kind: item for item in block.areas}

    def address(kind: str) -> int | None:
        item = values.get(kind)
        return None if item is None else item.address

    primary = address("ReproData")
    secondary = address("EraseAndReproRoutine")
    third = fourth = None
    if metadata.format_version == 500:
        if area.kind == "ReproData":
            if block.repro_method == "00":
                third = address("ReproDataSegment02")
                fourth = address("ReproDataSegment03")
            else:
                secondary = None
                third = address("ReproDataSegment02")
                fourth = address("ReproDataSegment03")
            binary = (
                block.values.get("wholereprofilename", "").lower().endswith(".binx")
            )
        elif area.kind == "EraseAndReproRoutine" and block.repro_method != "00":
            primary, secondary = secondary, None
            binary = (
                block.values.get("eraseandreproroutinefilename", "")
                .lower()
                .endswith(".binx")
            )
        elif area.kind == "DeltaOrCompressionReproData":
            primary = secondary = None
            binary = True
        else:
            raise ValueError("Large logical archive branch is not source-bound")
    elif metadata.format_version in (107, 209):
        if area.kind == "ReproData" and primary is not None:
            binary = metadata.format_version != 107
        elif metadata.format_version == 209 and area.kind == "EraseAndReproRoutine":
            primary = secondary = None
            binary = True
        else:
            raise ValueError("Large logical archive branch is not source-bound")
    else:
        raise ValueError("Unsupported native large logical metadata version")
    materialized = materialize_large_record_2026(
        metadata.source_container,
        area.record,
        addresses=(primary or 0, secondary, third, fourth),
        binary=binary,
    )
    return NativeArchive2026(
        materialized.descriptor,
        0,
        b"",
        (),
        materialized.descriptor,
        streamed=True,
        length_override=area.record.length,
        backing=materialized,
    )


def native2026_logical_cpu_flash_size(
    metadata: Native2026Metadata, cpu_index: int
) -> int:
    """13d20/48670 sum logical rows belonging to one actual deduplicated CPU."""
    if type(cpu_index) is not int or not 0 <= cpu_index < MAX_RECORDS:
        raise ValueError("Bounded native logical CPU index required")
    if metadata.source_container is not None:
        _validate_container_2026(metadata.source_container)
    native2026_cpu_values(metadata, cpu_index)
    if cpu_index in metadata.cpu_flash_size_overrides:
        return metadata.cpu_flash_size_overrides[cpu_index]
    if metadata.runtime_projection is not None:
        _validate_projection(metadata)
        original = metadata.runtime_projection.contexts[cpu_index]
        return native2026_logical_cpu_flash_size(
            original, native2026_global_cpu_index(original)
        )
    metadata = native2026_metadata_for_cpu(metadata, cpu_index)
    return (
        sum(
            _logical_block_flash_size(block)
            for block in metadata.logical_blocks
            if block.cpu_index == cpu_index
        )
        & 0xFFFFFFFF
    )


def _logical_block_flash_size(block: NativeLogicalBlock2026) -> int:
    lengths = {area.kind: area.length for area in block.areas}
    archived = {
        area.kind: 0
        if area.record is None
        else len(area.record.data)
        if isinstance(area.record, CalibrationRecord)
        else area.record.length
        for area in block.areas
    }
    if block.repro_method in ("02", "03"):
        size = lengths.get("EraseAndReproRoutine", 0) + archived.get(
            "DeltaOrCompressionReproData", 0
        )
    elif block.repro_method_type == 2:
        size = lengths.get("DeltaEraseAndReproRoutine", 0) + archived.get(
            "DeltaReproData", 0
        )
    elif block.repro_method_type == 3:
        size = lengths.get("CompressionEraseAndReproRoutine", 0) + archived.get(
            "CompressionReproData", 0
        )
    else:
        size = sum(
            lengths.get(kind, 0)
            for kind in (
                "ReproData",
                "EraseAndReproRoutine",
                "ReproDataSegment02",
                "ReproDataSegment03",
            )
        )
    return size & 0xFFFFFFFF


def native2026_global_cpu_index(metadata: Native2026Metadata) -> int:
    """Selected CPU-row index or the selected logical block's deduplicated CPU."""
    if metadata.runtime_projection is not None:
        _validate_projection(metadata)
        if not 0 <= metadata.runtime_selected_cpu < len(metadata.cpu_rows):
            raise ValueError("Selected native projected CPU is absent")
        return metadata.runtime_selected_cpu
    if metadata.cpus:
        return metadata.cpu.index
    if not 0 <= metadata.cpu_index < len(metadata.logical_blocks):
        raise ValueError("Selected native logical block absent")
    return metadata.logical_blocks[metadata.cpu_index].cpu_index


def native2026_cpu_file_flash_size(
    metadata: Native2026Metadata, cpu_index: int = 0
) -> int:
    """37fd0 CPU archive accumulator divides EACH file's data-byte count by two."""
    return sum(
        (
            materialize_srecords_2026(info.record.data).flash_size
            if info.record.data.startswith(b"S")
            else len(info.record.data)
        )
        // 2
        for info in native2026_cpu_files(metadata, cpu_index)
        if isinstance(info.record, CalibrationRecord)
    )


def native2026_file_index(metadata: Native2026Metadata, cpu_index: int = 0) -> int:
    """GetFileIdx: cumulative metadata9 file-vector base of the CPU row."""
    native2026_cpu_values(metadata, cpu_index)
    if metadata.format_version != 9:
        return 0
    return sum(len(native2026_cpu_files(metadata, index)) for index in range(cpu_index))


def native2026_cpu_files(
    metadata: Native2026Metadata, cpu_index: int = 0
) -> tuple[NativeCPUFile, ...]:
    """17490 exports file fields only for metadata9; indexes are zero-based."""
    native2026_cpu_values(metadata, cpu_index)
    if metadata.runtime_projection is not None:
        _validate_projection(metadata)
        context = metadata.runtime_projection.contexts[cpu_index]
        return native2026_cpu_files(context, native2026_global_cpu_index(context))
    return metadata.cpus[cpu_index].files if metadata.format_version == 9 else ()


def native2026_cpu_file_list_flag(
    metadata: Native2026Metadata, cpu_index: int = 0
) -> bool:
    """17490 exported CPU row+a0*index+78, independent of the number of files."""
    native2026_validate_runtime_metadata(metadata)
    native2026_cpu_values(metadata, cpu_index)
    return metadata.format_version == 9


def native2026_cpu_count(metadata: Native2026Metadata) -> int:
    """Global converted CPU rows, including10970 per-node NewCID deduplication."""
    if not isinstance(metadata, Native2026Metadata):
        raise TypeError("Native CUW2026 metadata required")
    if metadata.runtime_projection is not None:
        _validate_projection(metadata)
        return len(metadata.cpu_rows)
    if metadata.cpu_rows:
        return len(metadata.cpu_rows)
    if metadata.format_version < 101:
        return len(metadata.cpus)
    return sum(
        native2026_node_cpu_count(metadata, index)
        for index in range(native2026_node_count(metadata))
    )


def native2026_node_count(metadata: Native2026Metadata) -> int:
    """GetNumNode: historical formats export no node-info vector."""
    if metadata.runtime_projection is not None:
        _validate_projection(metadata)
        return len(metadata.runtime_projection.nodes)
    return (
        _number(metadata.vehicle, "NumberOfNode", maximum=16)
        if metadata.format_version >= 101
        and type(metadata.source_container) is not NativeRecoveryHeaderSource2026
        else 0
    )


def native2026_node_logical_block_count(
    metadata: Native2026Metadata, node_index: int = 0
) -> int:
    """CF node+7c:6370 node+98→18030 export+2c→CF5c10 import+7c."""
    native2026_validate_runtime_metadata(metadata)
    values = native2026_node_values(metadata, node_index)
    if metadata.runtime_projection is not None:
        return sum(
            block.node == node_index + 1 for block in metadata.runtime_projection.blocks
        )
    return (
        _number(values, "NumberOfLogicalBlock", maximum=32)
        if _logical_node(values)
        else 0
    )


def native2026_node_cpu_count(metadata: Native2026Metadata, node_index: int) -> int:
    """Zero-based native GetNumCPUImages(node), not logical block count."""
    values = native2026_node_values(metadata, node_index)
    if metadata.runtime_projection is not None or metadata.cpu_rows:
        return metadata.cpu_node_indices.count(node_index)
    if not _logical_node(values):
        return _number(values, "NumberOfCalibration", maximum=9)
    declared = _number(values, "NumberOfLogicalBlock", maximum=32)
    identifiers = set()
    populated = 0
    for slot in range(1, 33) if declared else ():
        identifier = metadata.sections.get(
            f"logicalblock{node_index + 1}{slot:02}", _EMPTY
        ).get("newcid", "")
        if identifier:
            identifiers.add(identifier)
            populated += 1
            if populated == declared:
                break
    return len(identifiers)


def _native2026_cpu_values(
    metadata: Native2026Metadata, cpu_index: int = 0
) -> Mapping[str, str]:
    """Global native CPU getter index, including10970 logical NewCID deduplication."""
    if (
        not isinstance(metadata, Native2026Metadata)
        or type(cpu_index) is not int
        or not 0 <= cpu_index < MAX_RECORDS
    ):
        raise ValueError("Bounded actual native CPU getter index required")
    if metadata.runtime_projection is not None:
        _validate_projection(metadata)
    if metadata.runtime_projection is not None or metadata.cpu_rows:
        if cpu_index >= len(metadata.cpu_rows):
            raise ValueError("Native CPU getter index absent")
        return metadata.cpu_rows[cpu_index]
    if metadata.format_version < 101:
        if cpu_index >= len(metadata.cpus):
            raise ValueError("Native CPU getter index absent")
        return metadata.cpus[cpu_index].values
    offset = 0
    for node in range(1, _number(metadata.vehicle, "NumberOfNode", maximum=16) + 1):
        values = metadata.sections.get(f"node{node:02}", _EMPTY)
        count = (
            0
            if _logical_node(values)
            else _number(values, "NumberOfCalibration", maximum=9)
        )
        if count:
            if offset <= cpu_index < offset + count:
                return metadata.sections[f"cpu{node}{cpu_index - offset + 1}"]
            offset += count
            continue
        identifiers = []
        populated = 0
        declared = (
            _number(values, "NumberOfLogicalBlock", maximum=32)
            if _logical_node(values)
            else 0
        )
        for slot in range(1, 33) if declared else ():
            info = metadata.sections.get(f"logicalblock{node}{slot:02}", _EMPTY)
            identifier = info.get("newcid", "")
            if identifier:
                populated += 1
                if identifier not in identifiers:
                    identifiers.append(identifier)
                if populated == declared:
                    break
        if offset <= cpu_index < offset + len(identifiers):
            return MappingProxyType(
                {
                    "newcid": identifiers[cpu_index - offset],
                    "locationid": "",
                    "cputype": "",
                }
            )
        offset += len(identifiers)
    raise ValueError("Native CPU getter index absent")


def native2026_cpu_values(
    metadata: Native2026Metadata, cpu_index: int = 0
) -> Mapping[str, str]:
    values = _native2026_cpu_values(metadata, cpu_index)
    if cpu_index in metadata.cpu_type_overrides:
        return MappingProxyType(
            {**values, "cputype": metadata.cpu_type_overrides[cpu_index]}
        )
    return values


_CID_MATCH_VIEW_PARENTS: dict[int, Native2026Metadata] = {}


def _record_cid_match_view(
    result: Native2026Metadata, parent: Native2026Metadata
) -> Native2026Metadata:
    if result is not parent:
        _CID_MATCH_VIEW_PARENTS[id(result)] = parent
        weakref.finalize(result, _CID_MATCH_VIEW_PARENTS.pop, id(result), None)
    return result


def native2026_with_cpu_type(
    metadata: Native2026Metadata, cpu_index: int, cpu_type: str
) -> Native2026Metadata:
    """6850 SetCPUType state transition; retain original metadata/source separately."""
    native2026_validate_runtime_metadata(metadata)
    native2026_cpu_values(metadata, cpu_index)
    if not isinstance(cpu_type, str) or len(cpu_type) > 512 or "\0" in cpu_type:
        raise ValueError("Bounded explicit native CPU type string required")
    overrides = MappingProxyType({**metadata.cpu_type_overrides, cpu_index: cpu_type})
    cpus = tuple(
        replace(cpu, values=MappingProxyType({**cpu.values, "cputype": cpu_type}))
        if cpu.index == cpu_index
        else cpu
        for cpu in metadata.cpus
    )
    result = _issue_metadata(replace(metadata, cpus=cpus, cpu_type_overrides=overrides))
    return _record_cid_match_view(result, metadata)


@dataclass(frozen=True)
class NativeCalibrationExport2026:
    cpu_types: tuple[str, ...]
    shrink_flag: bool


def native2026_with_parser_parameters(
    metadata: Native2026Metadata, general_parameters: Any
) -> Native2026Metadata:
    """a150/300b0: validate declared historical CPU M16C/FOREST profile flags."""
    native2026_validate_runtime_metadata(metadata)
    from scripts.programming_2026_common import NativeGeneralParameters2026

    if not isinstance(metadata, Native2026Metadata):
        raise TypeError("Native CUW2026 metadata required")
    if metadata.source_container is None:
        raise ValueError("Original native container required")
    _validate_container_2026(metadata.source_container)
    if type(general_parameters) is not NativeGeneralParameters2026:
        raise TypeError("Concrete native General parameter source required")
    lookup = general_parameters.boolean_with_keys
    if 0 < metadata.format_version < 101 and metadata.format_version not in (10, 12):
        kind = metadata.vehicle.get("kindofecu", "")
        contact = metadata.vehicle.get("contacttype", "")

        def flag(values: Mapping[str, str], name: str) -> bool:
            value = lookup(kind, values.get("cputype", ""), contact, name)
            if type(value) is not bool:
                raise TypeError("Native parameter Boolean required")
            return value

        # Every M16C flag is read; do not short-circuit missing later parameters.
        flags = tuple(
            flag(values, "M16CTypeFlag") for values in metadata.parser_cpu_rows
        )
        if any(flags) and not any(
            flag(values, "FORESTTypeFlag") for values in metadata.parser_cpu_rows
        ):
            raise ValueError("Native M16C calibration requires a FOREST CPU")
    return _issue_metadata(
        replace(
            metadata,
            parser_general_parameters=general_parameters,
            parser_parameters_validated=True,
        )
    )


def native2026_export_state(
    metadata: Native2026Metadata, *, shrink_flag: bool
) -> NativeCalibrationExport2026:
    """2d10 ExportData exports current CPU types and the runtime shrink flag only."""
    if type(shrink_flag) is not bool:
        raise TypeError("Explicit runtime Boolean shrink flag required")
    return NativeCalibrationExport2026(
        tuple(
            native2026_cpu_type(metadata, index)
            for index in range(native2026_cpu_count(metadata))
        ),
        shrink_flag,
    )


@dataclass(frozen=True)
class NativeCPUProjection2026:
    source: Any = field(repr=False, compare=False)
    contexts: tuple[Native2026Metadata, ...] = field(repr=False)
    blocks: tuple[NativeLogicalBlock2026, ...] = field(repr=False)
    nodes: tuple[Mapping[str, str], ...] = field(repr=False)
    classify_after_projection: bool = False


_CPU_PROJECTIONS: weakref.WeakValueDictionary[int, NativeCPUProjection2026] = (
    weakref.WeakValueDictionary()
)


def _validate_projection(metadata: Native2026Metadata) -> None:
    projection = metadata.runtime_projection
    if (
        projection is None
        or _issued_metadata.get(id(metadata)) is not metadata
        or _CPU_PROJECTIONS.get(id(projection)) is not projection
        or projection.source is not metadata.source_container
        or len(projection.contexts) != len(metadata.cpu_rows)
    ):
        raise ValueError("Issued native CPU projection and original source required")
    _validate_container_2026(metadata.source_container)


def _select_projection(metadata: Native2026Metadata, index: int) -> Native2026Metadata:
    projection = metadata.runtime_projection
    assert projection is not None
    original = projection.contexts[index]
    node = metadata.cpu_node_indices[index] + 1
    cpus = tuple(
        replace(
            context.cpu,
            index=ordinal,
            node=node,
            values=MappingProxyType(
                {
                    **metadata.cpu_rows[ordinal],
                    "cputype": metadata.cpu_type_overrides.get(
                        ordinal, metadata.cpu_rows[ordinal].get("cputype", "")
                    ),
                }
            ),
        )
        for ordinal, context in enumerate(projection.contexts)
        if context.cpus and metadata.cpu_node_indices[ordinal] + 1 == node
    )
    local = next((i for i, cpu in enumerate(cpus) if cpu.index == index), 0)
    logical_blocks = tuple(block for block in projection.blocks if block.node == node)
    if not cpus:
        local = next(
            (i for i, block in enumerate(logical_blocks) if block.cpu_index == index), 0
        )
    return _issue_metadata(
        replace(
            metadata,
            node=node,
            node_values=projection.nodes[node - 1]
            if projection.nodes
            else original.node_values,
            cpus=cpus,
            cpu_index=local,
            logical_blocks=logical_blocks,
            runtime_selected_cpu=index,
        )
    )


def _project_cpu_rows(
    metadata: Native2026Metadata, order: tuple[int, ...], targets: tuple[int, ...]
) -> Native2026Metadata:
    """16ae0/16fb0 preserve archive objects;19300→111e0 prunes logical backing."""
    native2026_validate_runtime_metadata(metadata)
    contexts = tuple(native2026_metadata_for_cpu(metadata, index) for index in order)
    rows = tuple(native2026_cpu_values(metadata, index) for index in order)
    nodes = tuple(native2026_node_index(metadata, index) for index in order)
    blocks: dict[tuple[int, int], NativeLogicalBlock2026] = {}
    for new_index, (old_index, context) in enumerate(zip(order, contexts, strict=True)):
        for block in context.logical_blocks:
            if block.cpu_index != old_index:
                continue
            if block.targets:
                selected = targets[new_index]
                old_targets = native2026_cpu_targets(metadata, old_index)
                if not 0 <= selected < len(old_targets):
                    raise ValueError("Native logical rebuild selected target is absent")
                if old_targets[selected].calibration not in block.targets:
                    continue
            blocks[(block.node, block.slot)] = replace(block, cpu_index=new_index)
    projection = NativeCPUProjection2026(
        metadata.source_container,
        contexts,
        tuple(blocks[key] for key in sorted(blocks)),
        tuple(
            native2026_node_values(metadata, index)
            for index in range(native2026_node_count(metadata))
        ),
    )
    _CPU_PROJECTIONS[id(projection)] = projection
    result = replace(
        metadata,
        cpu_rows=rows,
        cpu_node_indices=nodes,
        cpus=(),
        logical_blocks=(),
        cpu_type_overrides=MappingProxyType(
            {
                new: metadata.cpu_type_overrides[old]
                for new, old in enumerate(order)
                if old in metadata.cpu_type_overrides
            }
        ),
        cpu_target_overrides=MappingProxyType(
            {
                new: metadata.cpu_target_overrides[old]
                for new, old in enumerate(order)
                if old in metadata.cpu_target_overrides
            }
        ),
        cpu_flash_size_overrides=MappingProxyType(
            {
                new: metadata.cpu_flash_size_overrides[old]
                for new, old in enumerate(order)
                if old in metadata.cpu_flash_size_overrides
            }
        ),
        runtime_projection=projection,
        runtime_selected_cpu=0,
    )
    return _select_projection(result, 0) if order else _issue_metadata(result)


@dataclass(frozen=True)
class NativeCPUSelection2026:
    rebuilt_metadata: Native2026Metadata = field(repr=False)
    ordered_to_authored: tuple[int, ...]
    target_indices: tuple[int, ...]
    cpu_offset: int
    unmatched_identifiers: tuple[bytes, ...] = field(repr=False)
    unmatched_companions: tuple[bytes, ...] = field(repr=False)
    authored_cpu_count: int
    authored_target_indices: tuple[int, ...]


def native2026_is_logical_cpu(metadata: Native2026Metadata, cpu_index: int) -> bool:
    """19710: phase contact plus actual selected CPU node classification2."""
    native2026_validate_runtime_metadata(metadata)
    native2026_cpu_values(metadata, cpu_index)
    if metadata.vehicle.get("contacttype", "") not in (
        "P5-Unified",
        "Phase6",
        "Ethernet",
    ):
        return False
    if native2026_node_count(metadata) == 0:
        return False
    return _logical_node(
        native2026_node_values(metadata, native2026_node_index(metadata, cpu_index))
    )


@dataclass(frozen=True)
class NativeLogicalResume2026:
    metadata: Native2026Metadata = field(repr=False)
    remapped_cpu_index: int
    calculated_flash_size: int


def native2026_logical_resume_cpu(
    metadata: Native2026Metadata, cpu_index: int
) -> NativeLogicalResume2026:
    """3ffa0 option1b98 branch: mutate matching methods05/01 and nonzeroFlashSize."""
    if not native2026_is_logical_cpu(metadata, cpu_index):
        raise ValueError("Native logical resume requires19710 predicate")
    contexts = tuple(
        native2026_metadata_for_cpu(metadata, index)
        for index in range(native2026_cpu_count(metadata))
    )
    blocks = {}
    for context in contexts:
        for block in context.logical_blocks:
            blocks[(block.node, block.slot)] = block
    for key, block in tuple(blocks.items()):
        if block.cpu_index == cpu_index:
            lengths = {area.kind: area.values.get("length", "") for area in block.areas}
            if lengths.get("ReproData", ""):
                method = "01" if lengths.get("EraseAndReproRoutine", "") else "05"
                blocks[key] = replace(
                    block,
                    repro_method=method,
                    values=MappingProxyType({**block.values, "repromethod": method}),
                )
    projection = NativeCPUProjection2026(
        metadata.source_container,
        contexts,
        tuple(blocks[key] for key in sorted(blocks)),
        tuple(
            native2026_node_values(metadata, index)
            for index in range(native2026_node_count(metadata))
        ),
    )
    _CPU_PROJECTIONS[id(projection)] = projection
    total = (
        sum(
            _logical_block_flash_size(block)
            for block in blocks.values()
            if block.cpu_index == cpu_index
        )
        & 0xFFFFFFFF
    )
    overrides = dict(metadata.cpu_flash_size_overrides)
    if total:
        overrides[cpu_index] = total
    result = replace(
        metadata,
        runtime_projection=projection,
        cpu_flash_size_overrides=MappingProxyType(overrides),
    )
    result = _select_projection(result, cpu_index)
    if not result.logical_blocks:
        raise ValueError("Native logical resume node has no first logical block")
    return NativeLogicalResume2026(result, result.logical_blocks[0].cpu_index, total)


def native2026_project_node(
    metadata: Native2026Metadata, node_index: int
) -> Native2026Metadata:
    """32130→19300→13040→173d0: retain one node with target index zero."""
    native2026_validate_runtime_metadata(metadata)
    _validate_container_2026(metadata.source_container)
    values = native2026_node_values(metadata, node_index)
    order = tuple(
        index
        for index in range(native2026_cpu_count(metadata))
        if native2026_node_index(metadata, index) == node_index
    )
    selected = _project_cpu_rows(metadata, order, (0,) * len(order))
    assert selected.runtime_projection is not None
    blocks = tuple(
        replace(block, node=1) for block in selected.runtime_projection.blocks
    )
    values = MappingProxyType({**values, "numberoflogicalblock": str(len(blocks))})
    source = NativeNodeSource2026(
        metadata,
        node_index,
        hashlib.sha256(
            b"CUW13040\0"
            + bytes.fromhex(metadata.source_sha256)
            + struct.pack("<I", node_index)
        ).hexdigest(),
    )
    _node_sources[id(source)] = source
    projection = NativeCPUProjection2026(
        source, selected.runtime_projection.contexts, blocks, (values,), True
    )
    _CPU_PROJECTIONS[id(projection)] = projection
    dwords = {
        (0, name): value
        for (old_node, name), value in metadata.runtime_node_dwords.items()
        if old_node == node_index
    }
    result = replace(
        selected,
        source_container=source,
        source_sha256=source.digest,
        vehicle=MappingProxyType(
            {
                **metadata.vehicle,
                "numberofnode": "1",
                "contacttype": values.get("contacttype", ""),
            }
        ),
        cpu_node_indices=(0,) * len(order),
        runtime_projection=projection,
        runtime_node_dwords=MappingProxyType(dwords),
        cpu_flash_size_overrides=MappingProxyType(
            {
                index: sum(
                    _logical_block_flash_size(block)
                    for block in blocks
                    if block.cpu_index == index
                )
                & 0xFFFFFFFF
                for index, context in enumerate(selected.runtime_projection.contexts)
                if not context.cpus
            }
        ),
        node=1,
        node_values=values,
    )
    result = _select_projection(result, 0) if order else result
    result = _issue_metadata(result)
    object.__setattr__(source, "metadata", result)
    return result


def _phase6_pair_blocks(left: Native2026Metadata, right: Native2026Metadata):
    """19c00 first-node pair precheck, without composition or archive mutation."""
    for metadata in (left, right):
        native2026_validate_runtime_metadata(metadata)
        if native2026_node_count(metadata) == 0:
            raise ValueError("Not combinable: native first node is absent")
    left_node, right_node = native2026_node_values(left), native2026_node_values(right)
    if not _logical_node(left_node) or not _logical_node(right_node):
        raise ValueError("Not combinable: native first-node logical producer required")
    for key in ("protocol", "01_gatewaymode"):
        if left_node.get(key, "") != right_node.get(key, ""):
            raise ValueError("Not combinable: first-node identity differs")
    if any(
        _number(node, "NumberOfGateway", maximum=99) == 0
        for node in (left_node, right_node)
    ):
        raise ValueError("Native merge first gateway is absent")
    if _fixed_metadata_bytes(
        left_node.get("serviceauthkey", ""), 16
    ) != _fixed_metadata_bytes(right_node.get("serviceauthkey", ""), 16):
        raise ValueError("Not combinable: first-node service key differs")

    def all_blocks(metadata: Native2026Metadata) -> tuple[NativeLogicalBlock2026, ...]:
        blocks = {}
        for index in range(native2026_cpu_count(metadata)):
            for block in native2026_metadata_for_cpu(metadata, index).logical_blocks:
                blocks[(block.node, block.slot)] = block
        return tuple(blocks[key] for key in sorted(blocks))

    left_blocks = all_blocks(left)
    right_blocks = tuple(block for block in all_blocks(right) if block.node == 1)
    first_left = tuple(block for block in left_blocks if block.node == 1)
    for first in first_left:
        for second in right_blocks:
            if (
                first.slot == second.slot
                or first.new_cid == second.new_cid
                or first.new_cid in second.targets
                or second.new_cid in first.targets
            ):
                raise ValueError("Not combinable: logical block collision")
    return left_node, right_node, left_blocks, right_blocks, first_left


def native2026_validate_phase6_pair(
    left: Native2026Metadata, right: Native2026Metadata
) -> None:
    """19c00 only: validate actual pair sources without issuing a merged source."""
    _phase6_pair_blocks(left, right)


def native2026_merge_phase6(
    left: Native2026Metadata, right: Native2026Metadata
) -> Native2026Metadata:
    """4a850→19c00→19910: combine first-node logical owners, retaining LEFT header."""
    left_node, right_node, left_blocks, right_blocks, first_left = _phase6_pair_blocks(
        left, right
    )
    if left.region != right.region:
        raise ValueError("Native merge regions differ")
    if any(
        left_node.get(key, "") != right_node.get(key, "")
        for key in ("diagid", "logicaladdress")
    ):
        raise ValueError("Not combinable: first-node identity differs")
    merged_node = MappingProxyType(
        {**left_node, "numberoflogicalblock": str(len(first_left) + len(right_blocks))}
    )
    merged_blocks = tuple(
        sorted((*first_left, *right_blocks), key=lambda block: block.slot)
    )
    merged_blocks += tuple(block for block in left_blocks if block.node != 1)
    contexts = []
    rows: list[Mapping[str, str]] = []
    nodes = []
    remapped_blocks = []
    for node_index in range(native2026_node_count(left)):
        by_identifier: dict[str, int] = {}
        for block in (item for item in merged_blocks if item.node == node_index + 1):
            if block.new_cid not in by_identifier:
                new_index = len(rows)
                by_identifier[block.new_cid] = new_index
                owner = right if any(block is item for item in right_blocks) else left
                contexts.append(native2026_metadata_for_cpu(owner, block.cpu_index))
                rows.append(
                    MappingProxyType(
                        {
                            "newcid": block.new_cid,
                            "cputype": "",
                            "locationid": "",
                            "p4servermaxtime": "0",
                        }
                    )
                )
                nodes.append(node_index)
            new_index = by_identifier[block.new_cid]
            row = dict(rows[new_index])
            names = [
                item.calibration for item in _cpu_targets(row, left.format_version)
            ]
            names.extend(name for name in block.targets if name not in names)
            row["numberoftargets"] = str(len(names))
            for ordinal, name in enumerate(names, 1):
                row[
                    (f"{ordinal:02}" if ordinal < 100 else f"{ordinal:04}")
                    + "_targetcalibration"
                ] = name
            _cpu_targets(row, left.format_version)
            rows[new_index] = MappingProxyType(row)
            remapped_blocks.append(
                replace(
                    block,
                    cpu_index=new_index,
                    node_values=merged_node if node_index == 0 else block.node_values,
                )
            )
        # 19910 changes only node0; preserve ordinary CPU rows of all later nodes.
        if node_index:
            for old_index in range(native2026_cpu_count(left)):
                if native2026_node_index(left, old_index) == node_index:
                    context = native2026_metadata_for_cpu(left, old_index)
                    if context.cpus:
                        contexts.append(context)
                        rows.append(native2026_cpu_values(left, old_index))
                        nodes.append(node_index)
    source = NativeCompositeSource2026(
        left,
        right,
        hashlib.sha256(
            b"CUW19910\0"
            + bytes.fromhex(left.source_sha256)
            + bytes.fromhex(right.source_sha256)
        ).hexdigest(),
    )
    _composite_sources[id(source)] = source
    projection = NativeCPUProjection2026(
        source,
        tuple(contexts),
        tuple(remapped_blocks),
        (
            merged_node,
            *(
                native2026_node_values(left, index)
                for index in range(1, native2026_node_count(left))
            ),
        ),
    )
    _CPU_PROJECTIONS[id(projection)] = projection
    dwords = dict(left.runtime_node_dwords)
    flash_sizes: dict[int, int] = {}
    for block in remapped_blocks:
        flash_sizes[block.cpu_index] = (
            flash_sizes.get(block.cpu_index, 0) + _logical_block_flash_size(block)
        ) & 0xFFFFFFFF
    for name, scale in (
        ("WakeUpTimeAfterReset", 50),
        ("EmissionsRelatedSystem", 10),
        ("WaitTimeAfterProgrammingSession", 50),
    ):
        dwords[(0, name.casefold())] = max(
            replace(left, node=1, node_values=left_node).node_hex_number(name, scale),
            replace(right, node=1, node_values=right_node).node_hex_number(name, scale),
        )
    result = replace(
        left,
        source_sha256=source.digest,
        source_container=source,
        runtime_projection=projection,
        cpu_rows=tuple(rows),
        cpu_node_indices=tuple(nodes),
        cpu_target_overrides=_EMPTY,
        cpu_type_overrides=_EMPTY,
        cpu_flash_size_overrides=MappingProxyType(flash_sizes),
        runtime_node_dwords=MappingProxyType(dwords),
        cpus=(),
        logical_blocks=(),
    )
    result = _select_projection(result, 0) if rows else result
    result = _issue_metadata(result)
    object.__setattr__(source, "metadata", result)
    return result


@dataclass(frozen=True)
class NativeCIDMatch2026:
    metadata: Native2026Metadata = field(repr=False)
    general_parameters: Any = field(repr=False, compare=False)
    authored_target_indices: tuple[int, ...]
    unmatched_identifiers: tuple[bytes, ...] = field(repr=False)
    unmatched_companions: tuple[bytes, ...] = field(repr=False)
    authored_cpu_count: int
    check_target: bool


_CID_MATCHES: weakref.WeakValueDictionary[int, NativeCIDMatch2026] = (
    weakref.WeakValueDictionary()
)


def _validate_cid_match(match: NativeCIDMatch2026) -> None:
    if (
        type(match) is not NativeCIDMatch2026
        or _CID_MATCHES.get(id(match)) is not match
    ):
        raise ValueError("Issued native CID match required")
    native2026_validate_runtime_metadata(match.metadata)


def native2026_rebind_cid_match(
    match: NativeCIDMatch2026, metadata: Native2026Metadata
) -> NativeCIDMatch2026:
    """Rebind34e10 across issued6850 SetCPUType or CPU reselection views."""
    _validate_cid_match(match)
    native2026_validate_runtime_metadata(metadata)
    current = metadata
    while current is not match.metadata:
        parent = _CID_MATCH_VIEW_PARENTS.get(id(current))
        if parent is None:
            raise ValueError(
                "CID match rebind requires issued SetCPUType/reselection ancestry"
            )
        native2026_validate_runtime_metadata(parent)
        current = parent
    rebound = replace(match, metadata=metadata)
    _CID_MATCHES[id(rebound)] = rebound
    return rebound


def native2026_unrebuilt_selection(match: NativeCIDMatch2026) -> NativeCPUSelection2026:
    """Preserve34e10 authored state when36800 skips3e710."""
    _validate_cid_match(match)
    return NativeCPUSelection2026(
        match.metadata,
        tuple(range(match.authored_cpu_count)),
        match.authored_target_indices,
        0,
        match.unmatched_identifiers,
        match.unmatched_companions,
        match.authored_cpu_count,
        match.authored_target_indices,
    )


def native2026_cid_rebuild_allowed(metadata: Native2026Metadata) -> bool:
    """36800: firstCPU .vbf or nonempty indexed-image vector skips3e710."""
    native2026_validate_runtime_metadata(metadata)
    if native2026_cpu_count(metadata) == 0:
        return False
    if ".vbf" in native2026_cpu_values(metadata, 0).get("cpuimagename", ""):
        return False
    first = native2026_metadata_for_cpu(metadata, 0)
    return not (first.cpus and first.cpus[0].files)


def native2026_match_received_cids(
    metadata: Native2026Metadata,
    received_identifiers: tuple[bytes, ...],
    identifier_records: tuple[bytes, ...],
    general_parameters: Any,
    *,
    configuration: Any,
    shrink_flag: bool,
    received_hardware: bytes = b"",
) -> NativeCIDMatch2026:
    """34e10 authored snapshot only: no3ddf0/3e710/General lookup."""
    native2026_validate_runtime_metadata(metadata)
    from scripts.cuw_2026 import EngineConfiguration2026, configure_2026
    from scripts.programming_2026_common import NativeGeneralParameters2026

    _validate_container_2026(metadata.source_container)
    if (
        type(configuration) is not EngineConfiguration2026
        or configure_2026(configuration.arguments) != configuration
        or type(general_parameters) is not NativeGeneralParameters2026
        or type(shrink_flag) is not bool
    ):
        raise TypeError(
            "Issued native configuration, General source and shrink flag required"
        )
    if type(received_identifiers) is not tuple or type(identifier_records) is not tuple:
        raise TypeError("Exact received CID and companion record tuples required")
    if len(received_identifiers) != len(identifier_records):
        raise ValueError("Native CID/identifier-record vector counts differ")
    if len(received_identifiers) > MAX_RECORDS:
        raise ValueError("Received CID vector exceeds the host bound")
    if any(type(cid) is not bytes or b"\0" in cid for cid in received_identifiers):
        raise ValueError("Native received CID byte strings required")
    companions = []
    for record in identifier_records:
        if type(record) is not bytes or len(record) != 12 or b"\0" not in record[4:]:
            raise ValueError(
                "Native twelve-byte record requires bounded companion C string"
            )
        companions.append(record[4:].split(b"\0", 1)[0].decode("latin-1"))
    received = tuple(cid.decode("latin-1") for cid in received_identifiers)
    count = native2026_cpu_count(metadata)
    if count > configuration.cpu_maximum:
        raise ValueError("Metadata exceeds configured native CPU capacity")
    if type(received_hardware) is not bytes or b"\0" in received_hardware:
        raise ValueError("Exact native captured hardware byte string required")
    vbf = count > 0 and ".vbf" in native2026_cpu_values(metadata, 0).get(
        "cpuimagename", ""
    )
    hardware_only = False
    if vbf:
        values = native2026_cpu_values(metadata, 0)
        hardware_count = _number(values, "NumberOfTargetHardwares", maximum=99)
        hardware = received_hardware.decode("latin1")
        if not any(
            values.get(f"{slot:02}_targethardware", "") == hardware
            for slot in range(1, hardware_count + 1)
        ):
            raise ValueError(
                "Native VBF target hardware does not match captured hardware"
            )
        hardware_only = not received
    if not hardware_only and (configuration.flags[0] or metadata.is_blank_ecu):
        raise ValueError(
            "Native blank/D4f8 selection branch requires its source producer"
        )
    if len(received) < count and not hardware_only:
        raise ValueError(
            "Native constructor-zero selection has fewer received CIDs than CPUs"
        )
    if (
        metadata.parser_parameters_validated
        and metadata.parser_general_parameters.source_sha256
        != general_parameters.source_sha256
    ):
        raise ValueError("Selection General source differs from parser profile")
    ids = [native2026_new_calibration_id(metadata, i) for i in range(count)]
    contact = metadata.vehicle.get("contacttype", "")
    phased = contact in ("P5-Unified", "Phase6", "Ethernet")
    node_ids = []
    for i in range(count):
        context = native2026_metadata_for_cpu(metadata, i)
        node_ids.append(
            context.node_values.get("diagid", "")
            or context.node_values.get("logicaladdress", "")
        )

    def received_match(cid: str, cpu: int) -> bool:
        return any(
            value == cid and (not phased or companions[n] == node_ids[cpu])
            for n, value in enumerate(received)
        )

    selected = (
        ([0] + [-1] * (count - 1))
        if hardware_only
        else [
            next(
                (
                    n
                    for n, target in enumerate(native2026_cpu_targets(metadata, i))
                    if received_match(target.calibration, i)
                ),
                -1,
            )
            for i in range(count)
        ]
    )
    unmatched = (
        []
        if hardware_only
        else [(ids[i], node_ids[i]) for i in range(count) if selected[i] == -1]
    )
    if len(unmatched) != count and not shrink_flag:
        for i in range(count):
            pair = (ids[i], node_ids[i])
            if received_match(ids[i], i) and pair not in unmatched:
                unmatched.append(pair)
    match = NativeCIDMatch2026(
        metadata,
        general_parameters,
        tuple(selected),
        tuple(pair[0].encode("latin1") for pair in unmatched),
        tuple(pair[1].encode("latin1") for pair in unmatched) if phased else (),
        count,
        hardware_only or (count > 0 and len(unmatched) != count),
    )
    _CID_MATCHES[id(match)] = match
    return match


def native2026_rebuild_received_cids(
    metadata: Native2026Metadata,
    match: NativeCIDMatch2026,
    general_parameters: Any,
) -> NativeCPUSelection2026:
    """Source-gated3e710→3ddf0/reorder/prune/17280, after34e10 snapshot."""
    _validate_cid_match(match)
    if (
        metadata is not match.metadata
        or general_parameters is not match.general_parameters
    ):
        raise ValueError("CID rebuild requires original issued metadata and General")
    if not native2026_cid_rebuild_allowed(metadata):
        raise ValueError("Native36800 skips CID rebuild for this first CPU")
    count = match.authored_cpu_count
    selected = match.authored_target_indices
    ids = [native2026_new_calibration_id(metadata, i) for i in range(count)]
    contact = metadata.vehicle.get("contacttype", "")
    phased = contact in ("P5-Unified", "Phase6", "Ethernet")
    node_ids = []
    for i in range(count):
        context = native2026_metadata_for_cpu(metadata, i)
        node_ids.append(
            context.node_values.get("diagid", "")
            or context.node_values.get("logicaladdress", "")
        )
    unmatched = list(
        zip(
            (value.decode("latin1") for value in match.unmatched_identifiers),
            (value.decode("latin1") for value in match.unmatched_companions)
            if phased
            else ("" for _ in match.unmatched_identifiers),
            strict=True,
        )
    )
    kind = metadata.vehicle.get("kindofecu", "")
    desired = ids.copy()
    desired_nodes = node_ids.copy()
    offset = 0
    # Native M16C/FOREST lookups use NewCID membership without a companion.
    unmatched_ids = [pair[0] for pair in unmatched]
    for i in range(count):
        if (
            general_parameters.boolean_with_keys(
                kind, native2026_cpu_type(metadata, i), contact, "M16CTypeFlag"
            )
            and ids[i] not in unmatched_ids
        ):
            for j in range(count):
                if (
                    general_parameters.boolean_with_keys(
                        kind,
                        native2026_cpu_type(metadata, j),
                        contact,
                        "FORESTTypeFlag",
                    )
                    and ids[j] in unmatched_ids
                ):
                    desired.pop(j)
                    desired.insert(0, ids[j])
                    offset += 1
            break
    cursor = offset
    while cursor < len(desired):
        pair = (desired[cursor], desired_nodes[cursor])
        if pair in unmatched if phased else desired[cursor] in unmatched_ids:
            desired.pop(cursor)
            if phased:
                desired_nodes.pop(cursor)
        else:
            cursor += 1
    order = []
    for position, cid in enumerate(desired):
        matches = [
            i
            for i in range(count)
            if ids[i] == cid and (not phased or node_ids[i] == desired_nodes[position])
        ]
        if len(matches) != 1:
            raise ValueError("Native CPU reorder has an ambiguous or absent slot")
        order.append(matches[0])
    target_indices = tuple(selected[i] for i in order)
    rebuilt = _project_cpu_rows(metadata, tuple(order), target_indices)
    output_indices = list(target_indices)
    for i, selected_target in enumerate(target_indices):
        if selected_target == -1:
            rebuilt, output_indices[i] = native2026_append_current_target(
                rebuilt, i, general_parameters
            )
    return NativeCPUSelection2026(
        rebuilt,
        tuple(order),
        tuple(output_indices),
        offset,
        tuple(pair[0].encode("latin1") for pair in unmatched),
        tuple(pair[1].encode("latin1") for pair in unmatched) if phased else (),
        count,
        tuple(selected),
    )


def native2026_select_received_cids(
    metadata: Native2026Metadata,
    received_identifiers: tuple[bytes, ...],
    identifier_records: tuple[bytes, ...],
    general_parameters: Any,
    *,
    configuration: Any,
    shrink_flag: bool,
    received_hardware: bytes = b"",
) -> NativeCPUSelection2026:
    """Host composition of primitives with36800 shape gate, not CheckTarget success.

    This retains empty-pruning transform controls even when match.check_target is
    false. Native callers must use the split APIs and stop on that false result.
    """
    match = native2026_match_received_cids(
        metadata,
        received_identifiers,
        identifier_records,
        general_parameters,
        configuration=configuration,
        shrink_flag=shrink_flag,
        received_hardware=received_hardware,
    )
    if native2026_cid_rebuild_allowed(metadata):
        return native2026_rebuild_received_cids(metadata, match, general_parameters)
    return native2026_unrebuilt_selection(match)


def native2026_metadata_for_cpu(
    metadata: Native2026Metadata, global_cpu_index: int
) -> Native2026Metadata:
    """Reselect an actual exported CPU through its original authenticated producer."""
    native2026_validate_runtime_metadata(metadata)
    native2026_cpu_values(metadata, global_cpu_index)
    if metadata.runtime_projection is not None:
        _validate_projection(metadata)
        return _record_cid_match_view(
            _select_projection(metadata, global_cpu_index), metadata
        )
    if metadata.source_container is None:
        raise ValueError("Original native container required for CPU reselection")
    if (
        metadata.format_version < 101
        or type(metadata.source_container) is NativeRecoveryHeaderSource2026
    ):
        selected = native2026_metadata(
            metadata.source_container,
            cpu_index=global_cpu_index,
            region=metadata.region,
        )
    else:
        node_index = native2026_node_index(metadata, global_cpu_index)
        selected = native2026_metadata(
            metadata.source_container, node=node_index + 1, region=metadata.region
        )
        if selected.cpus:
            local_index = next(
                index
                for index, cpu in enumerate(selected.cpus)
                if cpu.index == global_cpu_index
            )
        else:
            local_index = next(
                index
                for index, block in enumerate(selected.logical_blocks)
                if block.cpu_index == global_cpu_index
            )
        if local_index:
            selected = native2026_metadata(
                metadata.source_container,
                node=node_index + 1,
                cpu_index=local_index,
                region=metadata.region,
            )
    for cpu_index, value in metadata.cpu_type_overrides.items():
        selected = native2026_with_cpu_type(selected, cpu_index, value)
    if metadata.parser_parameters_validated:
        selected = native2026_with_parser_parameters(
            selected, metadata.parser_general_parameters
        )
    for index, targets in metadata.cpu_target_overrides.items():
        selected = _with_cpu_targets(selected, index, targets)
    return _record_cid_match_view(selected, metadata)


def native2026_node_index(metadata: Native2026Metadata, cpu_index: int = 0) -> int:
    """GetNodeIdx is zero-based; historical CPU constructor initializes it to zero."""
    native2026_cpu_values(metadata, cpu_index)
    if metadata.runtime_projection is not None:
        _validate_projection(metadata)
        return metadata.cpu_node_indices[cpu_index]
    offset = 0
    for node_index in range(native2026_node_count(metadata)):
        count = native2026_node_cpu_count(metadata, node_index)
        if offset <= cpu_index < offset + count:
            return node_index
        offset += count
    return 0


def native2026_location_id(metadata: Native2026Metadata, cpu_index: int = 0) -> str:
    return native2026_cpu_values(metadata, cpu_index).get("locationid", "")


def native2026_new_calibration_id(
    metadata: Native2026Metadata, cpu_index: int = 0
) -> str:
    return native2026_cpu_values(metadata, cpu_index).get("newcid", "")


def native2026_cpu_type(metadata: Native2026Metadata, cpu_index: int = 0) -> str:
    return native2026_cpu_values(metadata, cpu_index).get("cputype", "")


def native2026_cpu_p4_server_max_time(
    metadata: Native2026Metadata, cpu_index: int = 0
) -> int:
    values = native2026_cpu_values(metadata, cpu_index)
    if metadata.format_version in (10, 12):
        return 0
    value = _number(
        values,
        "P4ServerMaxTime",
        base=16,
        default=3 if "p4servermaxtime" not in values else 0,
    )
    return (min(value, 0x7FFFFFFF) * 60) & 0xFFFFFFFF


def native2026_cpu_security_bytes(
    metadata: Native2026Metadata, name: str, cpu_index: int = 0
) -> bytes:
    """Fixed native CPU fields; require explicit input rather than inventing keys."""
    widths = {"seedkey": 16, "nonce": 16, "offsetaddress": 5}
    if not isinstance(name, str) or name.casefold() not in widths:
        raise ValueError("Known fixed native CPU field required")
    key = name.casefold()
    value = native2026_cpu_values(metadata, cpu_index).get(key, "")
    if key in ("nonce", "offsetaddress"):
        return _fixed_metadata_bytes(value, widths[key])
    return _hex(value, widths[key])


def native2026_cpu_cmac(
    metadata: Native2026Metadata, *, flash_code: bool = False, cpu_index: int = 0
) -> bytes:
    """a150/17490: version4 encoded CMAC strings, empty in other schemas."""
    if type(flash_code) is not bool:
        raise TypeError("Explicit native archive selection required")
    values = native2026_cpu_values(metadata, cpu_index)
    key = "cmacforflashcodedata" if flash_code else "cmacforcpuimagedata"
    return _hex(values.get(key, ""))


def native2026_new_password(
    metadata: Native2026Metadata, parameters: Mapping[str, str]
) -> int:
    """3290→33c0: explicit NewPassword wins; otherwise read bounded image DWORD."""
    values = metadata.cpu.values
    if values.get("newpassword", ""):
        return _number(values, "NewPassword", base=16)
    return native2026_archive_password(native2026_archive(metadata), parameters)


def native2026_archive_password(
    archive: NativeArchive2026, parameters: Mapping[str, str]
) -> int:
    """33c0 archive GetPassword; an explicit CPU NewPassword is irrelevant here."""
    if not isinstance(archive, NativeArchive2026) or archive.streamed:
        raise ValueError("Materialized native archive required for password extraction")
    if not isinstance(parameters, Mapping):
        raise TypeError("Native parameter mapping required")
    address_text = parameters.get("PasswordAddress", "")
    if not isinstance(address_text, str) or not re.fullmatch(
        r"[0-9a-fA-F]{1,8}", address_text
    ):
        raise ValueError("Explicit native PasswordAddress required")
    order_text = parameters.get("ByteOrder", "0")
    if not isinstance(order_text, str) or not re.fullmatch(
        r"-?[0-9]{1,10}", order_text
    ):
        raise ValueError("Native decimal ByteOrder required")
    order = int(order_text)
    if not -(2**31) <= order <= 2**31 - 1:
        raise ValueError("Native ByteOrder outside signed long bounds")
    address = int(address_text, 16)
    if archive.data is None or address + 4 > len(archive.data):
        raise ValueError("Native password address outside materialized image")
    return int.from_bytes(
        archive.data[address : address + 4], "little" if order & 0xFFFF == 0 else "big"
    )


def native2026_baud_rate(metadata: Native2026Metadata) -> int:
    """CF+48 native vehicle baud-rate DWORD, populated only in metadata10/12."""
    return (
        _number(metadata.vehicle, "BaudRate")
        if metadata.format_version in (10, 12)
        else 0
    )


def native2026_byte_number_of_transmitting(metadata: Native2026Metadata) -> int:
    """CF+98 is Vehicle.ByteNumberOfTransmitting HEX for metadata10 only."""
    if metadata.format_version != 10:
        return 0
    value = _number(metadata.vehicle, "ByteNumberOfTransmitting", base=16)
    if value < 3:
        raise ValueError("Native metadata10 ByteNumberOfTransmitting must be at least3")
    return value


def native2026_node_values(
    metadata: Native2026Metadata, node_index: int = 0
) -> Mapping[str, str]:
    """Zero-based native node getter index, distinct from the human node selector."""
    if type(node_index) is not int or not 0 <= node_index < native2026_node_count(
        metadata
    ):
        raise ValueError("Native node getter index absent")
    if metadata.runtime_projection is not None:
        _validate_projection(metadata)
        return metadata.runtime_projection.nodes[node_index]
    return (
        _decoded_fields(
            metadata.sections.get(f"node{node_index + 1:02}", _EMPTY),
            ("ecuauthkey", "serviceauthkey"),
        )
        if metadata.format_version >= 101
        else _EMPTY
    )
