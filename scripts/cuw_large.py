"""Authenticated CUW2026 large-file descriptors with bounded original backing reads."""

from __future__ import annotations

import hashlib
import os
import stat
import struct
import weakref
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from scripts.calibration import CalibrationRecord
from scripts.calibration_2026 import metadata_sections_2026

MIN_SIZE = 0x12C00000
MAX_SIZE = 0xFFFFFFFF
CHUNK_SIZE = 0x500000
_issued: weakref.WeakValueDictionary[int, NativeLargeContainer2026] = (
    weakref.WeakValueDictionary()
)


def _check(cancelled: Callable[[], bool] | None) -> None:
    if cancelled is not None and cancelled():
        raise InterruptedError("Large CUW operation cancelled")


class _Source:
    def __init__(self, path: str | Path):
        self.path = os.path.abspath(path)
        probe = os.open(path, os.O_PATH | os.O_CLOEXEC)
        try:
            info = os.fstat(probe)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("Large CUW requires a regular file")
            if not MIN_SIZE <= info.st_size <= MAX_SIZE:
                raise ValueError("Large CUW size must be 300 MiB through UINT32_MAX")
            self.fd = os.open(f"/proc/self/fd/{probe}", os.O_RDONLY | os.O_CLOEXEC)
            self.identity = self._identity(info)
            self.size = info.st_size
        finally:
            os.close(probe)

    @staticmethod
    def _identity(info):
        return (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    def verify(self):
        if self.fd < 0 or self._identity(os.fstat(self.fd)) != self.identity:
            raise ValueError("Large CUW backing source changed or closed")
        if self._identity(os.stat(self.path)) != self.identity:
            raise ValueError("Large CUW backing pathname changed")

    def read(self, offset: int, length: int) -> bytes:
        self.verify()
        if (
            type(offset) is not int
            or type(length) is not int
            or not 0 <= length <= CHUNK_SIZE
            or not 0 <= offset <= self.size - length
        ):
            raise ValueError("Large CUW read outside bounded source span")
        data = os.pread(self.fd, length, offset)
        if len(data) != length:
            raise ValueError("Truncated large CUW backing source")
        self.verify()
        return data

    def chunks(self, offset, length, cancelled=None):
        if (
            type(offset) is not int
            or type(length) is not int
            or not 0 <= offset <= self.size - length
            or length < 0
        ):
            raise ValueError("Large CUW span outside source")
        while length:
            _check(cancelled)
            size = min(length, CHUNK_SIZE)
            yield self.read(offset, size)
            offset += size
            length -= size
        self.verify()

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __del__(self):
        if hasattr(self, "fd"):
            self.close()


@dataclass(frozen=True)
class LargeRecord2026:
    offset: int
    header: bytes = field(repr=False)
    crc32: int
    source_offset: int
    length: int
    descriptor: bytes = field(repr=False)
    source_sha256: str
    _source: _Source = field(repr=False, compare=False)

    @property
    def span(self) -> tuple[int, int]:
        return self.source_offset, self.length

    def iter_chunks(
        self, *, cancelled: Callable[[], bool] | None = None
    ) -> Iterator[bytes]:
        return self._source.chunks(self.source_offset, self.length, cancelled)

    def read(self, offset: int = 0, length: int | None = None) -> bytes:
        size = min(CHUNK_SIZE, self.length - offset) if length is None else length
        if (
            type(offset) is not int
            or type(size) is not int
            or offset < 0
            or size < 0
            or offset + size > self.length
        ):
            raise ValueError("Read outside authenticated record span")
        return self._source.read(self.source_offset + offset, size)


@dataclass(frozen=True)
class NativeLargeContainer2026:
    version: int
    digest: str
    attached: CalibrationRecord = field(repr=False)
    records: tuple[LargeRecord2026, ...] = field(repr=False)
    declared_count: int
    count_width: int
    format_version: int
    _source: _Source = field(repr=False, compare=False)

    def close(self) -> None:
        self._source.close()

    def __enter__(self):
        validate_large_container_2026(self)
        return self

    def __exit__(self, *_):
        self.close()


def validate_large_container_2026(container: NativeLargeContainer2026) -> None:
    """Only the exact parser-issued object is accepted; replacement dataclasses fail."""
    if (
        type(container) is not NativeLargeContainer2026
        or _issued.get(id(container)) is not container
    ):
        raise ValueError("Authenticated large CUW producer identity required")
    container._source.verify()


def native_large_cuw_2026(
    path: str | Path, *, cancelled: Callable[[], bool] | None = None
) -> NativeLargeContainer2026:
    """29a70/29cc0/2aad0: validate original file, retain header plus 0x144 descriptor."""
    if Path(path).suffix.lower() != ".cuw":
        raise ValueError("Large CUW requires case-insensitive .cuw extension")
    _check(cancelled)
    source = _Source(path)
    try:
        prefix = source.read(0, 22)
        if (
            prefix[:14] != b"\0CALIBRATION\0\x0c"
            or int.from_bytes(prefix[18:22], "big") != source.size
        ):
            raise ValueError("Native large CUW signature/version/size differs")
        digest = hashlib.sha256()
        crc = 0
        for chunk in source.chunks(0, source.size, cancelled):
            digest.update(chunk)
        for chunk in source.chunks(18, source.size - 18, cancelled):
            crc = zlib.crc32(chunk, crc)
        if crc != int.from_bytes(prefix[14:18], "big"):
            raise ValueError("Native large CUW file CRC32 differs")
        sha = digest.hexdigest()

        def framing(offset):
            n = int.from_bytes(source.read(offset, 2), "big")
            raw = source.read(offset, n + 10)
            length, expected = struct.unpack_from(">II", raw, n + 2)
            start = offset + len(raw)
            if start + length > source.size:
                raise ValueError("Native large record exceeds source")
            actual = 0
            for chunk in source.chunks(start, length, cancelled):
                actual = zlib.crc32(chunk, actual)
            if actual != expected:
                raise ValueError("Native large record CRC32 differs")
            return raw, start, length, expected

        raw, start, length, expected = framing(22)
        if not 0 < length <= 1024 * 1024:
            raise ValueError("Bounded attached native metadata required")
        attached = CalibrationRecord(
            22, raw[2:-8], source.read(start, length), expected
        )
        _sections, version = metadata_sections_2026(attached.data)
        protocol_start = attached.data.find(b"Protocol=")
        protocol = (
            attached.data[protocol_start + 9 : protocol_start + 11]
            if protocol_start >= 0
            else b""
        )
        if version not in (107, 209) and not (version == 500 and protocol == b"02"):
            raise ValueError("Native large conversion supports107/209/500 CANFD only")
        cursor = start + length
        count = source.read(cursor, 1)[0]
        cursor += 1
        records = []
        filename = os.fsencode(source.path)
        if len(filename) >= 0x104 or b"\0" in filename:
            raise ValueError("Native descriptor filename exceeds MAX_PATH")
        for _ in range(count):
            _check(cancelled)
            offset = cursor
            raw, start, length, expected = framing(offset)
            descriptor = bytearray(0x144)
            descriptor[:3] = str(version).encode("ascii")
            descriptor[4 : 4 + len(filename)] = filename
            struct.pack_into("<II", descriptor, 0x108, start, start + length - 1)
            records.append(
                LargeRecord2026(
                    offset,
                    raw[2:-8],
                    expected,
                    start,
                    length,
                    bytes(descriptor),
                    sha,
                    source,
                )
            )
            cursor = start + length
        if cursor != source.size:
            raise ValueError("Native large record count/trailing source differs")
        source.verify()
        container = NativeLargeContainer2026(
            12, sha, attached, tuple(records), count, 1, version, source
        )
        _issued[id(container)] = container
        return container
    except BaseException:
        source.close()
        raise


def validate_large_record_2026(
    container: NativeLargeContainer2026, record: LargeRecord2026
) -> None:
    validate_large_container_2026(container)
    if not any(record is candidate for candidate in container.records):
        raise ValueError("Record is not owned by authenticated large CUW")


@dataclass(frozen=True)
class LargeMaterialization2026:
    descriptor: bytes = field(repr=False)
    record: LargeRecord2026 = field(repr=False)
    binary: bool
    # Native source offsets for main, second, third and fourth address thresholds.
    group_offsets: tuple[int, int, int, int]
    prefix_s1: tuple[bool, bool]

    def iter_payload(self, *, cancelled: Callable[[], bool] | None = None):
        """Binary chunks or S-record (address, data) rows without gap allocation."""
        if self.binary:
            yield from self.record.iter_chunks(cancelled=cancelled)
        else:
            for _, _, address, data in _srecords(self.record, cancelled):
                if data:
                    yield address, data


def _srecords(record, cancelled):
    cursor = 0
    count = 0
    window_start = 0
    window = b""

    def read(position, size):
        nonlocal window_start, window
        if position < window_start or position + size > window_start + len(window):
            window_start = position
            window = record.read(position, min(CHUNK_SIZE, record.length - position))
        if size < 0 or position + size > record.length:
            raise ValueError("Truncated native large S-record")
        return window[position - window_start : position - window_start + size]

    while cursor < record.length:
        _check(cancelled)
        head = read(cursor, min(4, record.length - cursor))
        if (
            len(head) != 4
            or head[:1] != b"S"
            or head[1:2] not in (b"0", b"1", b"2", b"3", b"5", b"7", b"8", b"9")
        ):
            raise ValueError("Invalid native large S-record header")
        kind = int(chr(head[1]))
        if any(value not in b"0123456789abcdefABCDEF" for value in head[2:]):
            raise ValueError("Native large S-record count must be hexadecimal")
        try:
            size = int(head[2:], 16)  # noqa: FURB166 -- SREC count is hexadecimal without a prefix
            n = size * 2 + 4
            raw = bytes.fromhex(read(cursor + 4, n - 4).decode("ascii"))
        except (ValueError, UnicodeError) as exc:
            raise ValueError("Invalid native large S-record hexadecimal data") from exc
        width = {0: 2, 1: 2, 2: 3, 3: 4, 5: 2, 7: 4, 8: 3, 9: 2}[kind]
        if kind == 5:
            if size not in (3, 4, 5):
                raise ValueError("Native large S5 count width differs")
            width = size - 1
        if size < width + 1 or len(raw) != size or (size + sum(raw)) & 255 != 255:
            raise ValueError("Native large S-record count/checksum differs")
        address = int.from_bytes(raw[:width], "big")
        if kind in (7, 8, 9) and size != width + 1:
            raise ValueError("Native large termination size differs")
        if kind in (1, 2, 3):
            count += 1
        if kind == 5 and address != count:
            raise ValueError("Native large S5 count differs")
        consumed = n
        for _ in range(2):
            if cursor + consumed < record.length and read(cursor + consumed, 1) in (
                b"\r",
                b"\n",
            ):
                consumed += 1
            else:
                break
        yield cursor, kind, address, raw[width:-1] if kind in (1, 2, 3) else b""
        cursor += consumed


def materialize_large_record_2026(
    container: NativeLargeContainer2026,
    record: LargeRecord2026,
    *,
    addresses: tuple[int | None, int | None, int | None, int | None] = (
        0,
        None,
        None,
        None,
    ),
    binary: bool = False,
    cancelled: Callable[[], bool] | None = None,
) -> LargeMaterialization2026:
    """2b460: verify CRC and bind actual source positions for up to four groups."""
    validate_large_record_2026(container, record)
    if (
        type(binary) is not bool
        or len(addresses) != 4
        or any(
            value is not None and (type(value) is not int or not 0 <= value <= MAX_SIZE)
            for value in addresses
        )
    ):
        raise ValueError("Four bounded native address thresholds required")
    offsets = [0, 0, 0, 0]
    flags = [False, False]
    seen_s1 = False
    if binary:
        offsets[0] = record.source_offset
    else:
        for cursor, kind, address, _ in _srecords(record, cancelled):
            for index, threshold in enumerate(addresses):
                if index >= 2 and container.format_version != 500:
                    continue
                if (
                    not offsets[index]
                    and threshold is not None
                    and threshold <= address
                ):
                    offsets[index] = record.source_offset + cursor
                    if index < 2:
                        flags[index] = seen_s1
            if kind == 1:
                seen_s1 = True
    crc = 0
    for chunk in record.iter_chunks(cancelled=cancelled):
        crc = zlib.crc32(chunk, crc)
    if crc != record.crc32:
        raise ValueError("Native large backing record CRC differs")
    descriptor = bytearray(record.descriptor)
    for index, position in enumerate((0x110, 0x11C, 0x128, 0x130)):
        struct.pack_into(
            "<II", descriptor, position, addresses[index] or 0, offsets[index]
        )
    struct.pack_into("<I", descriptor, 0x118, flags[0])
    struct.pack_into("<I", descriptor, 0x124, flags[1])
    struct.pack_into("<I", descriptor, 0x138, binary)
    materialized = LargeMaterialization2026(
        bytes(descriptor),
        record,
        binary,
        (offsets[0], offsets[1], offsets[2], offsets[3]),
        (flags[0], flags[1]),
    )

    _materialized[id(materialized)] = materialized
    return materialized


_materialized: weakref.WeakValueDictionary[int, LargeMaterialization2026] = (
    weakref.WeakValueDictionary()
)


def validate_large_materialization_2026(
    container: NativeLargeContainer2026, materialized: LargeMaterialization2026
) -> None:
    if (
        type(materialized) is not LargeMaterialization2026
        or _materialized.get(id(materialized)) is not materialized
    ):
        raise ValueError("Authenticated native large materializer identity required")
    validate_large_record_2026(container, materialized.record)


@dataclass(frozen=True)
class LargeSource2026:
    """Absolute original-file byte view for native streaming consumers."""

    container: NativeLargeContainer2026 = field(repr=False)

    def __len__(self):
        validate_large_container_2026(self.container)
        return self.container._source.size

    def __getitem__(self, key: slice) -> bytes:
        validate_large_container_2026(self.container)
        if not isinstance(key, slice) or key.step not in (None, 1):
            raise ValueError("Large source permits bounded contiguous slices only")
        start = 0 if key.start is None else key.start
        end = len(self) if key.stop is None else key.stop
        if (
            type(start) is not int
            or type(end) is not int
            or not 0 <= start <= end <= len(self)
        ):
            raise ValueError("Large source slice outside authenticated file")
        return self.container._source.read(start, end - start)
