"""Native RMViewer communication logs and the CSDF in-memory log lifecycle.

Recovered statically; never loads proprietary modules. Unknown tables remain bytes.
"""

from __future__ import annotations

import struct
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from scripts import local_files, snapshot

MAGIC = 0x80000003
MAX_BYTES = snapshot.MAX_BYTES
LogRecord = snapshot.Table
LogError = snapshot.SnapshotError


def _uint(value: int, bits: int) -> None:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise LogError(f"value must fit uint{bits}")


@dataclass(frozen=True)
class LogTime:
    """Raw Win32 tick and local calendar (year, month, day, h, m, s, ms)."""

    tick: int
    calendar: tuple[int, ...]

    def __post_init__(self) -> None:
        _uint(self.tick, 32)
        if not isinstance(self.calendar, tuple) or len(self.calendar) != 7:
            raise LogError("calendar must contain seven native words")
        for value in self.calendar:
            _uint(value, 16)

    def record(self, end: bool = False) -> LogRecord:
        return LogRecord(
            0x8003 if end else 0x8000, struct.pack("<I7H", self.tick, *self.calendar)
        )


def decode_time(record: LogRecord) -> LogTime:
    if record.id not in (0x8000, 0x8003) or len(record.payload) != 18:
        raise LogError("invalid native time record")
    values = struct.unpack("<I7H", record.payload)
    return LogTime(values[0], values[1:])


@dataclass(frozen=True)
class CommunicationLogFile:
    version: int
    revision: int
    records: tuple[LogRecord, ...]

    def __post_init__(self) -> None:
        _uint(self.version, 16)
        _uint(self.revision, 16)
        if self.version != 1:
            raise LogError("unsupported RMViewer log version")
        if (
            not isinstance(self.records, tuple)
            or len(self.records) > snapshot.MAX_TABLES
        ):
            raise LogError("invalid log record collection")
        size = 8
        for record in self.records:
            if not isinstance(record, LogRecord):
                raise LogError("expected native log record")
            size += 6 + len(record.payload)
            if size > MAX_BYTES:
                raise LogError("log exceeds byte budget")
            if record.id in (0x8000, 0x8003):
                decode_time(record)
            elif record.id in (0x1103, 0x1105, 0x8001, 0x8002):
                if len(record.payload) != 10:
                    raise LogError("invalid native status record")
            elif record.id in (0x103, 0x203):
                if len(record.payload) < 4:
                    raise LogError("truncated native packet record")
            elif record.id in (0x105, 0x205) and len(record.payload) < 11:
                raise LogError("truncated native CAN record")

    def to_dict(self) -> dict:
        return {
            "format": "native-communication-log",
            "version": self.version,
            "revision": self.revision,
            "records": [record.to_dict() for record in self.records],
            "provenance": "native-static-layout",
        }


def parse(data: bytes) -> CommunicationLogFile:
    cursor = snapshot.Cursor(data)
    magic, version, revision = cursor.unpack("<IHH")
    if magic != MAGIC:
        raise LogError("not an RMViewer communication log")
    return CommunicationLogFile(version, revision, snapshot.parse_tables(data[8:]))


def dumps(log: CommunicationLogFile) -> bytes:
    if not isinstance(log, CommunicationLogFile):
        raise LogError("expected communication log")
    return struct.pack(
        "<IHH", MAGIC, log.version, log.revision
    ) + snapshot.encode_tables(log.records)


def load(path: str | Path) -> CommunicationLogFile:
    return parse(local_files.read_regular(path, limit=MAX_BYTES))


def replay(log: CommunicationLogFile) -> Iterator[dict]:
    """Yield records verbatim, with modulo-u32 relative ticks when defined."""
    start = None
    for index, record in enumerate(log.records):
        tick = None
        if record.id in (0x8000, 0x8003):
            tick = decode_time(record).tick
            if record.id == 0x8000 and start is None:
                start = tick
        elif record.id in (0x8001, 0x8002) or (
            record.id >> 8 in (1, 2, 3, 0x11, 0x12, 0x21, 0x22)
            and record.id & 0xFF in (3, 5)
        ):
            if len(record.payload) < 4:
                raise LogError("truncated timestamped log record")
            tick = struct.unpack_from("<I", record.payload)[0]
        yield {
            "index": index,
            "type": record.id,
            "payload": record.payload,
            "tick": tick,
            "elapsed_ms": None
            if tick is None or start is None
            else (tick - start) & 0xFFFFFFFF,
        }


@dataclass(frozen=True)
class LogMessage:
    """Exact native value fields; padding and linked-list pointers are excluded."""

    kind: int
    protocol: int
    first: bytes = b""
    second: bytes = b""
    field28: int = 0
    field2c: int = 0
    field30: int = 0

    def __post_init__(self) -> None:
        _uint(self.kind, 32)
        _uint(self.protocol, 8)
        for value in (self.field28, self.field2c, self.field30):
            _uint(value, 32)
        if not isinstance(self.first, bytes) or not isinstance(self.second, bytes):
            raise LogError("message buffers must be bytes")
        if len(self.first) + len(self.second) > MAX_BYTES - 32:
            raise LogError("message exceeds byte budget")


def _calendar() -> tuple[int, ...]:
    now = time.time()
    value = time.localtime(now)
    return (
        value.tm_year,
        value.tm_mon,
        (value.tm_wday + 1) % 7,
        value.tm_mday,
        value.tm_hour,
        value.tm_min,
        value.tm_sec,
        int(now % 1 * 1000),
    )


class CommunicationLog:
    """Bounded injected-clock implementation of all CSDF queue operations."""

    def __init__(
        self,
        *,
        ticks: Callable[[], int] | None = None,
        local_time: Callable[[], tuple[int, ...]] = _calendar,
    ):
        self._ticks = ticks or (lambda: int(time.monotonic() * 1000) & 0xFFFFFFFF)
        self._local_time = local_time
        self._messages: list[LogMessage] = []
        self._size = 0
        self.start_tick = self.end_tick = 0
        self.start_calendar = self.end_calendar = (0,) * 8

    @staticmethod
    def _check_calendar(calendar: tuple[int, ...]) -> None:
        if not isinstance(calendar, tuple) or len(calendar) != 8:
            raise LogError("SYSTEMTIME must contain eight native words")
        for value in calendar:
            _uint(value, 16)

    @staticmethod
    def _file_calendar(calendar: tuple[int, ...]) -> tuple[int, ...]:
        return calendar[:2] + calendar[3:]

    def clear(self) -> None:
        # Native makes two separate tick and calendar calls, in this order.
        start_tick, end_tick = self._ticks(), self._ticks()
        end_calendar, start_calendar = self._local_time(), self._local_time()
        self._check_calendar(start_calendar)
        self._check_calendar(end_calendar)
        _uint(start_tick, 32)
        _uint(end_tick, 32)
        self._messages.clear()
        self._size = 0
        self.start_tick, self.end_tick = start_tick, end_tick
        self.start_calendar, self.end_calendar = start_calendar, end_calendar

    def set_end_log_time(self) -> None:
        tick, calendar = self._ticks(), self._local_time()
        _uint(tick, 32)
        self._check_calendar(calendar)
        self.end_tick, self.end_calendar = tick, calendar

    def get_log(self) -> tuple[LogMessage, ...]:
        return tuple(self._messages)

    def get_log_time(self) -> bytes:
        """Native 40-byte _tagLogTime, including both raw SYSTEMTIME blocks."""

        def system(calendar: tuple[int, ...]) -> bytes:
            return struct.pack("<8H", *calendar)

        return (
            struct.pack("<II", self.start_tick, self.end_tick)
            + system(self.end_calendar)
            + system(self.start_calendar)
        )

    def _replace(self, message: LogMessage, index: int | None) -> None:
        if not isinstance(message, LogMessage):
            raise LogError("expected native log message")
        size = 32 + len(message.first) + len(message.second)
        old_size = 0
        if index is not None:
            old = self._messages[index]
            old_size = 32 + len(old.first) + len(old.second)
        if self._size - old_size + size > MAX_BYTES or (
            index is None and len(self._messages) >= snapshot.MAX_TABLES
        ):
            raise LogError("log queue budget exceeded")
        if index is None:
            self._messages.append(message)
        else:
            self._messages[index] = message
        self._size += size - old_size

    def put_log(self, message: LogMessage) -> None:
        self._replace(message, None)

    def update_log(self, index: int, message: LogMessage) -> None:
        _uint(index, 32)
        if index < len(self._messages):
            self._replace(message, index)

    def export(self) -> CommunicationLogFile:
        # RMViewer writes these apparently reversed calendar/tick associations.
        records = [
            LogTime(self.start_tick, self._file_calendar(self.end_calendar)).record(),
            LogTime(self.end_tick, self._file_calendar(self.start_calendar)).record(
                True
            ),
        ]
        size = 56  # File header and the two native time records.
        if size > MAX_BYTES or len(records) > snapshot.MAX_TABLES:
            raise LogError("log export budget exceeded")
        for message in self._messages:
            encoded = encode_message(
                message,
                max_bytes=MAX_BYTES - size,
                max_records=snapshot.MAX_TABLES - len(records),
            )
            size += sum(6 + len(record.payload) for record in encoded)
            records.extend(encoded)
        return CommunicationLogFile(1, 0, tuple(records))


def encode_message(
    message: LogMessage,
    *,
    max_bytes: int | None = None,
    max_records: int | None = None,
) -> tuple[LogRecord, ...]:
    """RMViewer native message-to-record conversion (RVA 1bee6..1c38e)."""
    byte_limit = MAX_BYTES if max_bytes is None else min(MAX_BYTES, max_bytes)
    record_limit = (
        snapshot.MAX_TABLES
        if max_records is None
        else min(snapshot.MAX_TABLES, max_records)
    )
    if any(type(value) is not int or value < 0 for value in (byte_limit, record_limit)):
        raise LogError("invalid export budget")

    def check(size: int, count: int = 1) -> None:
        if size > byte_limit or count > record_limit:
            raise LogError("expanded log exceeds budget")

    if message.kind not in (1, 2, 3):
        raise LogError("message kind has no native persisted representation")
    record_type = {1: 0x100, 2: 0x200, 3: 0x1100}[message.kind]
    record_type += (
        5 if message.protocol in (6, 11) else 3 if message.protocol == 4 else 5
    )
    if message.kind == 3:
        if len(message.second) < 2:
            raise LogError("native event requires two status bytes")
        check(16)
        return (
            LogRecord(
                record_type,
                struct.pack("<II", message.field2c, message.field28)
                + message.second[:2],
            ),
        )
    if message.protocol == 4:
        check(10 + len(message.first) + len(message.second))
        return (
            LogRecord(
                record_type,
                struct.pack("<I", message.field2c) + message.first + message.second,
            ),
        )
    if message.protocol not in (6, 11):
        raise LogError("native packet export requires protocol 4, 6 or 11")
    # Native expands long CAN buffers into padded 7-byte transport chunks.
    first = message.first
    length = len(message.second)
    if length > 7 and len(first) != 5:
        raise LogError("native long CAN export requires five-byte header")
    # Count exact wire sizes before allocating any output, including u16 wrap.
    position = size = count = 0
    while True:
        first_frame = count & 0xFFFF == 0
        width = 6 if length - position > 7 and first_frame else 7
        header_size = (6 if first_frame else 5) if length > 7 else len(first)
        size += 10 + header_size + width
        count += 1
        check(size, count)
        position += width
        if position >= length:
            break
    records = []
    position = 0
    sequence = 0
    while True:
        output = first
        first_frame = sequence & 0xFFFF == 0
        if len(message.second) > 7:
            if len(first) != 5:
                raise LogError("native long CAN export requires five-byte header")
            if first_frame:
                if len(first) > 5:
                    output = first[:4] + bytes((0x10 + (first[4] & 15),)) + first[5:]
                else:
                    output = first[:4] + b"\x10" + first[4:]
            else:
                output = first[:4] + bytes((0x20 | (sequence & 15),)) + first[5:]
        width = 6 if length - position > 7 and first_frame else 7
        chunk = message.second[position : position + width]
        position += len(chunk)
        tick = message.field2c if sequence == 0 else 0
        records.append(
            LogRecord(
                record_type,
                struct.pack("<I", tick) + output + chunk.ljust(width, b"\0"),
            )
        )
        sequence += 1
        if position >= length:
            break
    return tuple(records)


def parse_dlog(data: bytes) -> snapshot.TableFile:
    """ReadDlogFile_DT uses CDmFileReader; DLOG is a DM container, not CSDF."""
    result = snapshot.parse(data)
    if not isinstance(result, snapshot.TableFile) or result.magic != snapshot.DM_MAGIC:
        raise LogError("DLOG reader requires native DM container")
    return result
