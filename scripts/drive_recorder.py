"""Native DRS records and injected VIM recorder execution; no device opens here."""

from __future__ import annotations

import configparser
import math
import struct
import sys
import time
from _thread import LockType
from collections import deque
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from threading import Lock
from typing import TYPE_CHECKING, Protocol

from scripts.data_monitor import MonitorSignalMetadata, SelectedP4Monitor
from scripts.frame_transport import (
    DriverProperties,
    FramePlan,
    FrameTransportError,
    get_comm_frame,
)
from scripts.frame_transport import NativeMessage as TransportMessage
from scripts.monitor_support import (
    MonitorSupportCache,
    SupportQuery,
    SupportReceive,
    SupportSend,
)
from scripts.profiles import (
    ProtocolProfile,
    SelectedFrame,
    VehicleContext,
    VehicleProfile,
    VinVehicleContext,
    vehicle_matches,
)
from scripts.recorder_buffer import NativeRecorderRing, RecorderBufferError
from scripts.signal_conversion import affine, i32
from scripts.toyota_session import NativeFrameSend, SessionError

if TYPE_CHECKING:
    from scripts.native_communication import NativeCommunication
from scripts.snapshot import (
    DM_MAGIC,
    MonitorBuffer,
    SignalItem,
    SnapshotError,
    decode_packet_stream,
    decode_ring_buffer,
    decode_system_information,
    encode_monitor_buffer,
    encode_signal_item,
    encode_system_information,
    monitor_packets,
    recorded_bits,
)
from scripts.snapshot import (
    Table as SnapshotTable,
)
from scripts.snapshot import (
    TableFile as SnapshotTableFile,
)
from scripts.snapshot import (
    dumps as dump_snapshot,
)
from scripts.support import correspondence_rows, word
from scripts.toyota import ToyotaCodecError

MAX_RECORDER_BYTES = 32 * 1024 * 1024
DRS_MAGIC = 0x80000001
TABLE_NAMES = {
    1: "vehicle_selection",
    0x8100: "system_information",
    3: "receive_frame_info",
    4: "monitor_signal_info",
    5: "trigger_info",
    6: "trigger_parameters",
    2: "monitor_buffer_info",
    0x11: "monitor_setting_info",
    0x12: "monitor_stop_info",
    0x21: "diag_comm_setting",
    0x22: "diag_comm_end",
    0x23: "change_check_mode",
    0x24: "confirm_check_mode",
    0x27: "check_car_info",
    0x28: "default_session",
    0x29: "extended_session",
    0x200: "connect",
    0x201: "disconnect",
    0x202: "read_messages",
    0x203: "write_messages",
    0x206: "start_message_filter",
    0x211: "set_config",
    0x213: "five_baud_init",
    0x214: "fast_init",
}
DMCI_SCHEMAS: dict[int, tuple[str, ...]] = {
    0x100: ("string", "pairs", "I", "I", "I", "I"),
    0x101: ("B", "B", "I", "I", "I", "I", "I", "I", "I"),
    0x102: ("string", "I", "I"),
    0x103: ("string", "buffer", "pairs", "I", "I"),
    0x104: (),
    0x105: ("B", "H"),
    0x106: (),
    0x107: ("I",),
    0x108: (),
    0x109: ("I", "I", "mode_a1", "I", "pairs", "H"),
    0x10A: ("I", "I", "I", "mode_pair", "I", "pairs", "I", "I"),
    0x10B: ("I", "I", "I", "buffer", "I", "pairs"),
    0x10D: ("dwords",),
    0x10C: (),
    0x10E: (),
    0x10F: ("I", "buffer", "H"),
    0x110: ("I", "I"),
    0x111: ("I", "I", "I", "I", "I"),
    0x112: ("I", "buffer"),
    0x113: ("I", "buffer"),
    0x114: ("I", "I", "I"),
    0x115: ("B", "B", "B", "B", "I", "I", "I", "I", "I"),
    0x116: ("I",),
    0x117: ("I", "buffer"),
    0x118: ("B", "B", "I", "I", "I", "I", "I", "I", "I"),
    0x119: ("I", "I", "data_ids", "I", "pairs", "I"),
    0x11A: ("I", "buffer"),
    0x11B: ("I", "buffer", "buffer", "H", "I"),
    0x11C: ("I", "I", "buffer", "H", "words", "words", "I", "pairs", "I", "words"),
    0x11E: ("I",),
}
DMCI_NAMES = {
    0x100: "create_iso_interface",
    0x101: "create_can_interface",
    0x102: "create_vpw_interface",
    0x103: "create_pwm_interface",
    0x104: "delete_diag_interface",
    0x105: "create_dlc12_interface",
    0x106: "delete_dlc12_interface",
    0x107: "create_dm_interface",
    0x108: "delete_dm_interface",
    0x109: "monitor_setup_pack",
    0x10A: "monitor_setup_pair",
    0x10B: "monitor_setup_dtc",
    0x10D: "get_monitor_data",
    0x10C: "monitor_start",
    0x10E: "monitor_stop",
    0x10F: "active_test_start",
    0x110: "active_test_stop",
    0x111: "id_map_append",
    0x112: "set_pickup_data",
    0x113: "monitor_system_send",
    0x114: "set_negative_count",
    0x115: "create_psa_interface",
    0x116: "set_interrupt_timing",
    0x117: "set_additional_frame",
    0x118: "create_phase5_interface",
    0x119: "data_id_setup",
    0x11A: "clear_dynamic_data_id",
    0x11B: "active_test_start_phase5",
    0x11C: "monitor_setup_rid",
    0x11E: "set_routine_info",
}
DMCI_WIRE_COMMANDS = {
    0x100: 0x107F,
    0x101: 0x117F,
    0x102: 0x227F,
    0x103: 0x237F,
    0x104: 0x127F,
    0x105: 0x207F,
    0x106: 0x217F,
    0x107: 0x137F,
    0x108: 0x147F,
    0x109: 0x157F,
    0x10A: 0x167F,
    0x10B: 0x177F,
    0x10D: 0x197F,
    0x10C: 0x187F,
    0x10E: 0x1A7F,
    0x10F: 0x1B7F,
    0x110: 0x1C7F,
    0x111: 0x1D7F,
    0x112: 0x1E7F,
    0x113: 0x1F7F,
    0x114: 0x247F,
    0x115: 0x257F,
    0x116: 0x267F,
    0x117: 0x277F,
    0x118: 0x287F,
    0x119: 0x297F,
    0x11A: 0x2A7F,
    0x11B: 0x2B7F,
    0x11C: 0x2C7F,
    0x11E: 0x2D7F,
}
TABLE_NAMES.update({key: "dmci_" + value for key, value in DMCI_NAMES.items()})
EMPTY_TABLES = frozenset((0x11, 0x12, 0x21, 0x22, 0x23, 0x24, 0x27, 0x201))
CONTAINER_TABLES = EMPTY_TABLES - {0x201}


class RecorderError(ValueError):
    """Invalid native data or invalid host lifecycle request."""


@dataclass
class _CleanupClockState:
    last: float | None = None
    real: float = 0.0
    fallback: bool = False


_cleanup_clocks: ContextVar[dict[int, _CleanupClockState] | None] = ContextVar(
    "recorder_cleanup_clocks", default=None
)


@contextmanager
def _cleanup_clock_scope(clock: Callable[[], float]) -> Iterator[None]:
    """Keep owned-resource cleanup bounded if an injected clock breaks."""
    clocks = dict(_cleanup_clocks.get() or {})
    clocks.setdefault(id(clock), _CleanupClockState())
    token = _cleanup_clocks.set(clocks)
    try:
        yield
    finally:
        _cleanup_clocks.reset(token)


def _clock_now(
    clock: Callable[[], float], *, cause: BaseException | None = None
) -> float:
    clocks = _cleanup_clocks.get()
    state = clocks.get(id(clock)) if clocks is not None else None
    real = time.monotonic() if state is not None else 0.0
    try:
        value = clock() if state is None or not state.fallback else float("nan")
        valid = not isinstance(value, bool) and math.isfinite(value)
    except (Exception, KeyboardInterrupt):
        if state is None:
            raise
        valid, value = False, 0.0
    if state is not None:
        # Translate real elapsed time into the last valid injected time domain;
        # existing finite cleanup deadlines remain meaningful after failure.
        if valid and value + 2.0 > value:
            state.last, state.real = value, real
            return value
        state.fallback = True
        if state.last is None:
            state.last, state.real = real, real
        return state.last + (real - state.real)
    if not valid:
        raise RecorderError("Recorder clock must be finite") from cause
    return value


def _recorder_deadline(clock: Callable[[], float], timeout: float) -> float:
    now = _clock_now(clock)
    deadline = now + timeout
    if not math.isfinite(deadline):
        raise RecorderError("Recorder deadline must be finite")
    if deadline <= now:
        raise TimeoutError("Recorder deadline cannot advance")
    return deadline


@contextmanager
def _exclusive(lock: LockType, label: str) -> Iterator[None]:
    if not lock.acquire(blocking=False):
        raise RecorderError(f"{label} is busy")
    try:
        yield
    finally:
        lock.release()


class UnsupportedRecorderOperation(RecorderError):
    """Required adapter capability or native semantics are unavailable."""


class RecorderCancelled(RecorderError):
    pass


def _uint(value: int, bits: int = 32) -> int:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise RecorderError(f"Expected unsigned {bits}-bit integer")
    return value


def _bounded_join(parts: Iterable[bytes], limit: int = MAX_RECORDER_BYTES) -> bytes:
    result = bytearray()
    for part in parts:
        if len(result) + len(part) > limit:
            raise RecorderError("Native encoded byte budget exceeded")
        result.extend(part)
    return bytes(result)


class _Reader:
    def __init__(self, data: bytes):
        if not isinstance(data, bytes):
            raise RecorderError("Native record input must be bytes")
        self.data = data
        self.offset = 0

    def take(self, size: int) -> bytes:
        if size < 0 or size > len(self.data) - self.offset:
            raise RecorderError(f"Truncated native record at {self.offset}")
        result = self.data[self.offset : self.offset + size]
        self.offset += size
        return result

    def unpack(self, fmt: str) -> tuple[int, ...]:
        return struct.unpack("<" + fmt, self.take(struct.calcsize("<" + fmt)))

    def end(self) -> None:
        if self.offset != len(self.data):
            raise RecorderError(f"Unexpected trailing bytes at {self.offset}")


@dataclass(frozen=True)
class DrsTable:
    table_id: int
    payload: bytes = b""

    def __post_init__(self) -> None:
        _uint(self.table_id, 16)
        if not isinstance(self.payload, bytes):
            raise RecorderError("Native table payload must be bytes")

    @property
    def name(self) -> str:
        return TABLE_NAMES.get(self.table_id, "unknown")

    def encode(self) -> bytes:
        return (
            struct.pack("<IH", _uint(len(self.payload) + 2), self.table_id)
            + self.payload
        )


@dataclass(frozen=True)
class DrsFile:
    header_word_1: int
    header_word_2: int
    tables: tuple[DrsTable, ...]

    def encode(self) -> bytes:
        return struct.pack(
            "<IHH",
            DRS_MAGIC,
            _uint(self.header_word_1, 16),
            _uint(self.header_word_2, 16),
        ) + b"".join(table.encode() for table in self.tables)

    @classmethod
    def parse(
        cls, data: bytes, *, max_size: int = 64 * 1024 * 1024, max_tables: int = 100_000
    ) -> DrsFile:
        if (
            type(max_size) is not int
            or max_size < 8
            or type(max_tables) is not int
            or max_tables < 0
        ):
            raise RecorderError("Invalid DRS parsing bounds")
        if len(data) > max_size:
            raise RecorderError("DRS exceeds configured size limit")
        reader = _Reader(data)
        magic, word1, word2 = reader.unpack("IHH")
        if magic != DRS_MAGIC:
            raise RecorderError("Not a native DRS settings file")
        tables: list[DrsTable] = []
        while reader.offset < len(data):
            if len(tables) >= max_tables:
                raise RecorderError("DRS exceeds configured table count")
            size, table_id = reader.unpack("IH")
            if size < 2:
                raise RecorderError("Native table size excludes its identifier")
            tables.append(DrsTable(table_id, reader.take(size - 2)))
        return cls(word1, word2, tuple(tables))

    def report(self) -> dict[str, object]:
        return {
            "format": "native-drs",
            "provenance": "FileManagerIT3 static serialization; physical unconfirmed",
            "header_words": [self.header_word_1, self.header_word_2],
            "tables": [
                {"id": t.table_id, "name": t.name, "size": len(t.payload)}
                for t in self.tables
            ],
        }


@dataclass(frozen=True)
class NativeMessage:
    protocol_id: int
    rx_status: int
    tx_flags: int
    timestamp: int
    extra_data_index: int
    data: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes) or len(self.data) > 4128:
            raise RecorderError(
                "Native PASSTHRU message data must be bytes of at most 4128 bytes"
            )
        for value in (
            self.protocol_id,
            self.rx_status,
            self.tx_flags,
            self.timestamp,
            self.extra_data_index,
        ):
            _uint(value)

    def encode(self) -> bytes:
        # Native DRS stores DataSize before ExtraDataIndex, with no struct padding.
        fields = (
            self.protocol_id,
            self.rx_status,
            self.tx_flags,
            self.timestamp,
            len(self.data),
            self.extra_data_index,
        )
        return struct.pack("<6I", *(_uint(v) for v in fields)) + self.data

    @classmethod
    def read(cls, reader: _Reader) -> NativeMessage:
        protocol, rx, tx, timestamp, size, extra = reader.unpack("6I")
        return cls(protocol, rx, tx, timestamp, extra, reader.take(size))

    @classmethod
    def parse(cls, data: bytes) -> NativeMessage:
        reader = _Reader(data)
        result = cls.read(reader)
        reader.end()
        return result


def encode_command(table_id: int, fields: Mapping[str, object]) -> DrsTable:
    """Encode recovered DRS low-level record fields; unknown layouts fail closed."""
    if table_id in DMCI_SCHEMAS:
        command = fields.get("dmci")
        if not isinstance(command, NativeDmciCommand) or command.command_id != table_id:
            raise RecorderError("Expected matching native DMCI command")
        return command.table()
    if table_id == 0x8100:
        record = fields.get("system")
        if not isinstance(record, dict):
            raise RecorderError("Expected native system information mapping")
        try:
            return DrsTable(table_id, encode_system_information(record))
        except SnapshotError as exc:
            raise RecorderError(str(exc)) from exc
    if table_id == 1:
        selection = fields.get("selection")
        if not isinstance(selection, NativeVehicleSelection):
            raise RecorderError("Expected NativeVehicleSelection")
        return DrsTable(1, selection.encode())
    if table_id == 2:
        monitor = fields.get("monitor")
        if not isinstance(monitor, NativeMonitorBuffer):
            raise RecorderError("Expected NativeMonitorBuffer")
        return DrsTable(2, monitor.encode())
    if table_id == 4:
        signals = fields.get("signals")
        if (
            not isinstance(signals, tuple)
            or len(signals) > 100_000
            or not all(isinstance(x, NativeMonitorSignal) for x in signals)
        ):
            raise RecorderError("Expected bounded native monitor signal tuple")
        return DrsTable(
            4, struct.pack("<I", len(signals)) + b"".join(x.encode() for x in signals)
        )
    if table_id in (5, 6):
        trigger = fields.get("trigger")
        expected = NativeTriggerInfo if table_id == 5 else NativeTriggerParameters
        if not isinstance(trigger, expected):
            raise RecorderError("Expected native trigger record")
        return DrsTable(table_id, trigger.encode())
    if table_id in EMPTY_TABLES:
        if fields and table_id in CONTAINER_TABLES and set(fields) == {"children"}:
            children = fields["children"]
            if (
                not isinstance(children, tuple)
                or len(children) > 100_000
                or not all(isinstance(x, DrsTable) for x in children)
            ):
                raise RecorderError("Expected bounded native child table tuple")
            return DrsTable(table_id, b"".join(x.encode() for x in children))
        if fields:
            raise RecorderError("Native empty record cannot have fields")
        return DrsTable(table_id)
    if table_id == 0x200:
        payload = struct.pack(
            "<II", _field(fields, "protocol_id"), _field(fields, "flags")
        )
    elif table_id in (0x203, 0x214):
        message = fields.get("message")
        if not isinstance(message, NativeMessage):
            raise RecorderError("Expected NativeMessage")
        prefix = (
            struct.pack("<I", _field(fields, "timeout")) if table_id == 0x203 else b""
        )
        payload = prefix + message.encode()
    elif table_id == 0x206:
        messages = fields.get("messages")
        if (
            not isinstance(messages, tuple)
            or len(messages) != 3
            or not all(isinstance(m, NativeMessage) for m in messages)
        ):
            raise RecorderError(
                "Filter requires mask, pattern and flow-control messages"
            )
        payload = struct.pack("<I", _field(fields, "filter_type")) + b"".join(
            m.encode() for m in messages
        )
    elif table_id in (0x28, 0x29):
        data = fields.get("data")
        core = fields.get("core_words")
        if not isinstance(data, bytes) or not isinstance(core, tuple) or len(core) != 2:
            raise RecorderError("Session requires native buffer and two core words")
        if not all(type(v) is int for v in core):
            raise RecorderError("Core words must be integers")
        payload = (
            struct.pack(
                "<IHHI",
                _field(fields, "value_before_buffer"),
                _uint(core[0], 16),
                _uint(core[1], 16),
                len(data),
            )
            + data
        )
    elif table_id == 0x202:
        words = fields.get("words")
        pattern = fields.get("mask_data")
        flow = fields.get("pattern_data")
        if (
            not isinstance(words, tuple)
            or len(words) != 7
            or not all(type(v) is int for v in words)
        ):
            raise RecorderError("Read-messages requires seven native words")
        if not isinstance(pattern, bytes) or not isinstance(flow, bytes):
            raise RecorderError("Read-messages buffers must be bytes")
        if len(pattern) > 4128 or len(flow) > 4128:
            raise RecorderError("Native read buffers exceed message capacity")
        payload = (
            struct.pack("<7I", *(_uint(v) for v in words))
            + struct.pack("<I", len(pattern))
            + pattern
            + struct.pack("<I", len(flow))
            + flow
        )
    elif table_id == 0x211:
        pairs = fields.get("parameters")
        payload = _encode_pairs(pairs, "I")
    elif table_id == 3:
        payload = _encode_pairs(fields.get("frames"), "H")
    elif table_id == 0x213:
        data = fields.get("data")
        if not isinstance(data, bytes):
            raise RecorderError("Five baud data must be bytes")
        payload = (
            struct.pack("<I", len(data))
            + data
            + struct.pack("<I", _field(fields, "value_after_data"))
        )
    else:
        raise UnsupportedRecorderOperation(
            f"Typed encoding unavailable for DRS table {table_id:#x}"
        )
    return DrsTable(table_id, payload)


def _field(fields: Mapping[str, object], key: str) -> int:
    value = fields.get(key)
    if not isinstance(value, int):
        raise RecorderError(f"Missing integer field {key}")
    return _uint(value)


def _encode_pairs(value: object, code: str) -> bytes:
    if not isinstance(value, (list, tuple)):
        raise RecorderError("Expected parameter pairs")
    pairs: list[bytes] = []
    for pair in value:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise RecorderError("Expected a pair")
        if not all(type(v) is int for v in pair):
            raise RecorderError("Expected integer pair")
        pairs.append(
            struct.pack(
                "<" + code * 2, *(_uint(v, 16 if code == "H" else 32) for v in pair)
            )
        )
    return struct.pack("<I", len(pairs)) + b"".join(pairs)


def decode_command(table: DrsTable) -> dict[str, object]:
    """Decode native command records without assigning meanings to unknown enums."""
    r = _Reader(table.payload)
    result: dict[str, object]
    if table.table_id in DMCI_SCHEMAS:
        return {"dmci": NativeDmciCommand.parse(table)}
    if table.table_id == 0x8100:
        try:
            return {"system": decode_system_information(table.payload)}
        except SnapshotError as exc:
            raise RecorderError(str(exc)) from exc
    if table.table_id == 1:
        return {"selection": NativeVehicleSelection.parse(table.payload)}
    if table.table_id == 2:
        return {"monitor": NativeMonitorBuffer.parse(table.payload)}
    if table.table_id == 4:
        count = r.unpack("I")[0]
        if count > 100_000 or count > (len(r.data) - r.offset) // 71:
            raise RecorderError("Native signal count exceeds record length")
        result = {"signals": tuple(NativeMonitorSignal.read(r) for _ in range(count))}
        r.end()
        return result
    if table.table_id in (5, 6):
        trigger_type = (
            NativeTriggerInfo if table.table_id == 5 else NativeTriggerParameters
        )
        return {"trigger": trigger_type.parse(table.payload)}
    if table.table_id in CONTAINER_TABLES and table.payload:
        # WriteStart writes an empty own record, then WriteEnd backpatches size
        # around the following child tables. It does not add a second header.
        nested = DrsFile.parse(struct.pack("<IHH", DRS_MAGIC, 0, 0) + table.payload)
        return {"children": nested.tables}
    if table.table_id in EMPTY_TABLES:
        result = {}
    elif table.table_id == 0x200:
        protocol, flags = r.unpack("II")
        result = {"protocol_id": protocol, "flags": flags}
    elif table.table_id in (0x203, 0x214):
        result = {"timeout": r.unpack("I")[0]} if table.table_id == 0x203 else {}
        result["message"] = NativeMessage.read(r)
    elif table.table_id == 0x206:
        result = {
            "filter_type": r.unpack("I")[0],
            "messages": tuple(NativeMessage.read(r) for _ in range(3)),
        }
    elif table.table_id in (3, 0x211):
        count = r.unpack("I")[0]
        fmt = "HH" if table.table_id == 3 else "II"
        width = struct.calcsize("<" + fmt)
        if count > (len(r.data) - r.offset) // width:
            raise RecorderError("Pair count exceeds record length")
        result = {
            "frames" if table.table_id == 3 else "parameters": tuple(
                r.unpack(fmt) for _ in range(count)
            )
        }
    elif table.table_id == 0x213:
        result = {
            "data": r.take(r.unpack("I")[0]),
            "value_after_data": r.unpack("I")[0],
        }
    elif table.table_id in (0x28, 0x29):
        value, core1, core2, size = r.unpack("IHHI")
        result = {
            "value_before_buffer": value,
            "core_words": (core1, core2),
            "data": r.take(size),
        }
    elif table.table_id == 0x202:
        # Native Read/Write alias intentionally serializes only these portions.
        words = r.unpack("7I")
        pattern = r.take(r.unpack("I")[0])
        flow = r.take(r.unpack("I")[0])
        if len(pattern) > 4128 or len(flow) > 4128:
            raise RecorderError("Native read buffers exceed message capacity")
        result = {"words": words, "mask_data": pattern, "pattern_data": flow}
    else:
        raise UnsupportedRecorderOperation(
            f"Typed decoding unavailable for DRS table {table.table_id:#x}"
        )
    r.end()
    return result


@dataclass(frozen=True)
class NativeCoreBuffer:
    core_words: tuple[int, int]
    data: bytes

    def encode(self) -> bytes:
        if not isinstance(self.data, bytes) or len(self.data) > MAX_RECORDER_BYTES - 8:
            raise RecorderError("Native core buffer exceeds byte budget")
        return (
            struct.pack(
                "<HHI", *(_uint(x, 16) for x in self.core_words), _uint(len(self.data))
            )
            + self.data
        )

    @classmethod
    def read(cls, reader: _Reader) -> NativeCoreBuffer:
        first, second, size = reader.unpack("HHI")
        if size > MAX_RECORDER_BYTES - 8:
            raise RecorderError("Native core buffer exceeds byte budget")
        return cls((first, second), reader.take(size))


@dataclass(frozen=True)
class NativeDmciList:
    core_words: tuple[int, int]
    items: tuple[tuple[object, ...], ...]


def _dmci_read_value(reader: _Reader, kind: str) -> object:
    if kind in ("I", "H", "B"):
        return reader.unpack(kind)[0]
    if kind == "string":
        return NativeCoreString.read(reader)
    if kind == "buffer":
        return NativeCoreBuffer.read(reader)
    first, second, count = reader.unpack("HHI")
    width = {
        "pairs": 8,
        "mode_pair": 2,
        "mode_a1": 9,
        "dwords": 4,
        "monitor_data": 12,
        "words": 2,
        "data_ids": 4,
    }[kind]
    if count > 100_000 or count > (len(reader.data) - reader.offset) // width:
        raise RecorderError("Native DMCI list exceeds record bounds")
    items = []
    for _ in range(count):
        if kind in ("dwords", "words"):
            items.append((reader.unpack("I" if kind == "dwords" else "H")[0],))
        elif kind == "data_ids":
            items.append(tuple(reader.unpack("HH")))
        elif kind == "monitor_data":
            items.append((reader.unpack("I")[0], NativeCoreBuffer.read(reader)))
        elif kind == "pairs":
            items.append(tuple(reader.unpack("II")))
        elif kind == "mode_pair":
            items.append(tuple(reader.unpack("BB")))
        else:
            items.append((reader.unpack("B")[0], NativeCoreBuffer.read(reader)))
    return NativeDmciList((first, second), tuple(items))


def _dmci_encode_value(value: object, kind: str) -> bytes:
    if kind in ("I", "H", "B"):
        if type(value) is not int:
            raise RecorderError("Native DMCI scalar must be integer")
        return struct.pack("<" + kind, _uint(value, {"I": 32, "H": 16, "B": 8}[kind]))
    if kind in ("string", "buffer"):
        expected = NativeCoreString if kind == "string" else NativeCoreBuffer
        if not isinstance(value, expected):
            raise RecorderError("Wrong native DMCI core object")
        return value.encode()
    if not isinstance(value, NativeDmciList) or len(value.items) > 100_000:
        raise RecorderError("Expected bounded native DMCI list")

    def parts() -> Iterator[bytes]:
        yield struct.pack(
            "<HHI", *(_uint(x, 16) for x in value.core_words), len(value.items)
        )
        for item in value.items:
            if len(item) != (1 if kind in ("dwords", "words") else 2):
                raise RecorderError("Native DMCI list item field count mismatch")
            if kind in ("dwords", "words"):
                yield _dmci_encode_value(item[0], "I" if kind == "dwords" else "H")
            elif kind == "monitor_data":
                yield _dmci_encode_value(item[0], "I")
                yield _dmci_encode_value(item[1], "buffer")
            elif kind in ("pairs", "mode_pair", "data_ids"):
                fmt = {"pairs": "I", "mode_pair": "B", "data_ids": "H"}[kind]
                for item_value in item:
                    yield _dmci_encode_value(item_value, fmt)
            else:
                yield _dmci_encode_value(item[0], "B")
                yield _dmci_encode_value(item[1], "buffer")

    return _bounded_join(parts(), MAX_RECORDER_BYTES)


@dataclass(frozen=True)
class NativeDmciCommand:
    """Native CommandDataLib DMCI request body; base command header is not repeated."""

    command_id: int
    values: tuple[object, ...]

    def encode(self) -> bytes:
        schema = DMCI_SCHEMAS.get(self.command_id)
        if schema is None or len(self.values) != len(schema):
            raise RecorderError("Unsupported native DMCI command or field count")
        return _bounded_join(
            (
                _dmci_encode_value(value, kind)
                for value, kind in zip(self.values, schema, strict=True)
            ),
            MAX_RECORDER_BYTES,
        )

    @classmethod
    def parse(cls, table: DrsTable) -> NativeDmciCommand:
        schema = DMCI_SCHEMAS.get(table.table_id)
        if schema is None:
            raise UnsupportedRecorderOperation("Native DMCI layout unavailable")
        if len(table.payload) > MAX_RECORDER_BYTES:
            raise RecorderError("Native DMCI record exceeds byte budget")
        reader = _Reader(table.payload)
        values = tuple(_dmci_read_value(reader, kind) for kind in schema)
        reader.end()
        return cls(table.table_id, values)

    @classmethod
    def from_neutral(
        cls, command_id: int, values: tuple[object, ...]
    ) -> NativeDmciCommand:
        """Bind a shared producer's core-free primitive values to native serializers."""
        schema = DMCI_SCHEMAS.get(command_id)
        if (
            schema is None
            or not isinstance(values, tuple)
            or len(values) != len(schema)
        ):
            raise RecorderError("Invalid neutral DMCI command fields")
        bound = []
        for value, kind in zip(values, schema, strict=True):
            if kind == "string" and isinstance(value, bytes):
                value = NativeCoreString((1, 0), value)
            elif kind == "buffer" and isinstance(value, bytes):
                value = NativeCoreBuffer((1, 0), value)
            elif kind not in ("I", "H", "B", "string", "buffer"):
                if not isinstance(value, tuple):
                    raise RecorderError("Neutral DMCI list must be a tuple")
                if kind in ("mode_a1", "monitor_data"):
                    items = []
                    for item in value:
                        if not isinstance(item, tuple) or len(item) != 2:
                            raise RecorderError(
                                "Malformed neutral DMCI buffer list item"
                            )
                        identifier, payload = item
                        if not isinstance(payload, bytes):
                            raise RecorderError("Neutral DMCI payload must be bytes")
                        items.append((identifier, NativeCoreBuffer((1, 0), payload)))
                    value = tuple(items)
                value = NativeDmciList((1, 0), value)
            bound.append(value)
        result = cls(command_id, tuple(bound))
        result.encode()
        return result

    def table(self) -> DrsTable:
        return DrsTable(self.command_id, self.encode())


@dataclass(frozen=True)
class NativeMonitorReply:
    """CDmciGetMonitorDataRcv complete body (CommandDataLib51ff0)."""

    status: int
    interfaces: NativeDmciList
    buffers: tuple[
        NativeCoreBuffer,
        NativeCoreBuffer,
        NativeCoreBuffer,
        NativeCoreBuffer,
        NativeCoreBuffer,
    ]
    trailing_value: int

    def encode(self) -> bytes:
        if len(self.buffers) != 5:
            raise RecorderError("Native monitor reply needs five buffers")

        def parts() -> Iterator[bytes]:
            yield struct.pack("<I", _uint(self.status))
            yield _dmci_encode_value(self.interfaces, "monitor_data")
            for buffer in self.buffers:
                yield buffer.encode()
            yield struct.pack("<I", _uint(self.trailing_value))

        return _bounded_join(parts(), MAX_RECORDER_BYTES)

    @classmethod
    def parse(cls, data: bytes) -> NativeMonitorReply:
        if len(data) > MAX_RECORDER_BYTES:
            raise RecorderError("Native monitor reply exceeds byte budget")
        reader = _Reader(data)
        status = reader.unpack("I")[0]
        interfaces = _dmci_read_value(reader, "monitor_data")
        assert isinstance(interfaces, NativeDmciList)
        buffers = tuple(NativeCoreBuffer.read(reader) for _ in range(5))
        trailing = reader.unpack("I")[0]
        reader.end()
        return cls(
            status,
            interfaces,
            (buffers[0], buffers[1], buffers[2], buffers[3], buffers[4]),
            trailing,
        )


@dataclass(frozen=True)
class NativeMonitorPacket:
    timestamp_ms: int
    payload: bytes

    def __post_init__(self) -> None:
        _uint(self.timestamp_ms)
        if (
            not isinstance(self.payload, bytes)
            or len(self.payload) > MAX_RECORDER_BYTES
        ):
            raise RecorderError("Invalid native monitor packet payload")


class NativeMonitorPacketReader:
    """DatMonCommon phase0 full-cycle / phase1 first-frame native ring packets."""

    def __init__(
        self,
        frames: tuple[tuple[int, int], ...],
        *,
        phase: int,
        max_packets: int = 100_000,
        max_bytes: int = MAX_RECORDER_BYTES,
    ):
        if (
            type(max_bytes) is not int
            or not 1 <= max_bytes <= MAX_RECORDER_BYTES
            or type(phase) is not int
            or phase not in (0, 1)
            or not frames
            or len(frames) > 256
            or type(max_packets) is not int
            or max_packets < 1
        ):
            raise RecorderError("Invalid native monitor packet configuration")
        if len({index for index, _ in frames}) != len(frames):
            raise RecorderError("Duplicate native monitor frame index")
        for frame_id, size in frames:
            if type(frame_id) is not int or not 0 <= frame_id < 256:
                raise RecorderError("Invalid native monitor frame index")
            if type(size) is not int or not 0 < size <= 65535:
                raise RecorderError("Invalid native monitor frame size")
        self.frames = frames
        self.phase = phase
        self.packet_size = 4 + (
            sum(size for _, size in frames) if phase == 0 else frames[0][1]
        )
        self.max_packets = max_packets
        self.max_bytes, self.bytes_read = max_bytes, 0
        self.pending = b""
        self.count = 0

    def feed(self, data: bytes) -> tuple[NativeMonitorPacket, ...]:
        if not isinstance(data, bytes):
            raise RecorderError("Invalid native monitor packet chunk")
        if self.bytes_read + len(data) > self.max_bytes:
            raise RecorderError("Native monitor aggregate byte budget exceeded")
        self.bytes_read += len(data)
        joined = self.pending + data
        count = len(joined) // self.packet_size
        if self.count + count > self.max_packets:
            raise RecorderError("Native monitor packet budget exceeded")
        layout = self.frames if self.phase == 0 else self.frames[:1]
        try:
            decoded = decode_packet_stream(joined[: count * self.packet_size], layout)
        except SnapshotError as exc:
            raise RecorderError(str(exc)) from exc
        packets = tuple(
            NativeMonitorPacket(
                item["timestamp_raw"],
                b"".join(bytes.fromhex(frame["data_hex"]) for frame in item["frames"]),
            )
            for item in decoded
        )
        self.pending = joined[count * self.packet_size :]
        self.count += count
        return packets

    def finish(self) -> None:
        if self.pending:
            raise RecorderError("Truncated native monitor packet stream")

    def raw_value(
        self, packet: NativeMonitorPacket, signal: NativeMonitorSignal
    ) -> int:
        _, frame_id, start, end = signal.identity_words
        offset = 0
        for candidate, size in self.frames[:1] if self.phase == 1 else self.frames:
            if candidate == frame_id:
                if not 0 <= start <= end < size * 8:
                    raise RecorderError("Native signal exceeds monitor frame")
                return recorded_bits(
                    packet.payload, offset * 8 + start, offset * 8 + end
                )
            offset += size
        raise RecorderError("Native signal frame not present in monitor packet")


class NativeTriggerWindow:
    """Native timestamp window arithmetic; source timestamps are millisecond u32."""

    def __init__(
        self,
        info: NativeTriggerInfo,
        *,
        max_packets: int = 100_000,
        max_bytes: int = MAX_RECORDER_BYTES,
    ):
        if (
            info.trigger_point > 100
            or type(max_packets) is not int
            or max_packets < 1
            or type(max_bytes) is not int
            or not 1 <= max_bytes <= MAX_RECORDER_BYTES
        ):
            raise RecorderError("Invalid native recorder trigger window")
        self.pre_ms = (info.duration * info.trigger_point // 100) * 1000
        self.post_ms = (
            info.duration - info.duration * info.trigger_point // 100
        ) * 1000
        self.max_packets = max_packets
        self.packets: deque[NativeMonitorPacket] = deque()
        self.max_bytes, self.retained_bytes = max_bytes, 0
        self.trigger_timestamp: int | None = None
        self.complete = False

    def trigger(self, timestamp_ms: int) -> None:
        if self.trigger_timestamp is None:
            self.trigger_timestamp = _uint(timestamp_ms)

    def feed(self, packet: NativeMonitorPacket) -> None:
        if self.complete:
            raise RecorderError("Native trigger window is already complete")
        _uint(packet.timestamp_ms)
        if (
            self.packets
            and ((packet.timestamp_ms - self.packets[-1].timestamp_ms) & 0xFFFFFFFF)
            >= 0x80000000
        ):
            raise RecorderError("Native packet timestamps moved backward")
        cutoff_reference = (
            packet.timestamp_ms
            if self.trigger_timestamp is None
            else self.trigger_timestamp
        )
        # Native112f88 mode1 chooses floor at the left boundary: retain the
        # last packet at or before trigger-pre, including one predecessor.
        while self.packets:
            successor = self.packets[1] if len(self.packets) > 1 else packet
            age = (cutoff_reference - successor.timestamp_ms) & 0xFFFFFFFF
            if age >= 0x80000000 or age < self.pre_ms:
                break
            dropped = self.packets.popleft()
            self.retained_bytes -= 4 + len(dropped.payload)
        if self.retained_bytes + 4 + len(packet.payload) > self.max_bytes:
            raise RecorderError("Native trigger window byte budget exceeded")
        if len(self.packets) >= self.max_packets:
            raise RecorderError("Native trigger capture packet budget exceeded")
        self.packets.append(packet)
        self.retained_bytes += 4 + len(packet.payload)
        if self.trigger_timestamp is not None:
            # Native112f88 mode0 chooses ceil at the right boundary.
            elapsed = (packet.timestamp_ms - self.trigger_timestamp) & 0xFFFFFFFF
            self.complete = elapsed < 0x80000000 and elapsed >= self.post_ms


@dataclass(frozen=True)
class NativeReadExpectation:
    """Native CDrsPtReadMsgs timeout/header plus byte mask and expected pattern."""

    timeout: int
    initial_header_words: tuple[int, int, int, int, int, int]
    mask_data: bytes
    pattern_data: bytes

    def encode(self) -> bytes:
        if len(self.mask_data) > 4128 or len(self.pattern_data) > 4128:
            raise RecorderError("Native read expectation exceeds message capacity")
        data = struct.pack(
            "<7I", _uint(self.timeout), *(_uint(x) for x in self.initial_header_words)
        )
        return (
            data
            + struct.pack("<I", len(self.mask_data))
            + self.mask_data
            + struct.pack("<I", len(self.pattern_data))
            + self.pattern_data
        )

    @classmethod
    def parse(cls, data: bytes) -> NativeReadExpectation:
        reader = _Reader(data)
        timeout, protocol, rx, tx, stamp, size, extra = reader.unpack("7I")
        mask = reader.take(reader.unpack("I")[0])
        pattern = reader.take(reader.unpack("I")[0])
        reader.end()
        result = cls(timeout, (protocol, rx, tx, stamp, size, extra), mask, pattern)
        result.encode()
        return result

    def matches(self, message: NativeMessage) -> bool:
        """Read loop ignores RxStatus&0x1f; native0x1036c0 compares mask bytes."""
        if (
            message.rx_status & 0x1F
            or not message.data
            or len(self.mask_data) > len(message.data)
            or len(self.mask_data) > len(self.pattern_data)
        ):
            return False
        return all(
            (actual & mask) == (expected & mask)
            for actual, mask, expected in zip(
                message.data, self.mask_data, self.pattern_data
            )
        )


@dataclass(frozen=True)
class NativeCoreString:
    """CCmdString core words and byte string; encoding is not guessed."""

    core_words: tuple[int, int]
    data: bytes

    def encode(self) -> bytes:
        return (
            struct.pack(
                "<HHH",
                *(_uint(x, 16) for x in self.core_words),
                _uint(len(self.data), 16),
            )
            + self.data
        )

    @classmethod
    def read(cls, reader: _Reader) -> NativeCoreString:
        first, second, size = reader.unpack("HHH")
        return cls((first, second), reader.take(size))


@dataclass(frozen=True)
class NativeVehicleEntry:
    core_words: tuple[int, int]
    values: tuple[int, ...]
    text: NativeCoreString


@dataclass(frozen=True)
class NativeVehicleSelection:
    """CCmdSelectCarTypeVin table1; enum/index meanings remain raw."""

    core_words: tuple[int, int]
    vin: NativeCoreString
    list_core_words: tuple[tuple[int, int], tuple[int, int], tuple[int, int]]
    select_names: tuple[NativeVehicleEntry, ...]
    car_info: tuple[NativeVehicleEntry, ...]
    options: tuple[NativeVehicleEntry, ...]
    trailing_words: tuple[int, int]

    def encode(self) -> bytes:
        data = (
            struct.pack("<HH", *(_uint(x, 16) for x in self.core_words))
            + self.vin.encode()
        )
        for index, entries in enumerate(
            (self.select_names, self.car_info, self.options)
        ):
            if len(entries) > 100_000:
                raise RecorderError("Too many native vehicle entries")
            data += struct.pack(
                "<HHI",
                *(_uint(x, 16) for x in self.list_core_words[index]),
                len(entries),
            )
            for entry in entries:
                expected = 2 if index == 0 else 1
                if len(entry.values) != expected:
                    raise RecorderError("Invalid native vehicle entry word count")
                data += struct.pack("<HH", *(_uint(x, 16) for x in entry.core_words))
                values = struct.pack(
                    "<" + "H" * expected, *(_uint(x, 16) for x in entry.values)
                )
                data += (
                    entry.text.encode() + values
                    if index == 2
                    else values + entry.text.encode()
                )
        return data + struct.pack("<HH", *(_uint(x, 16) for x in self.trailing_words))

    @classmethod
    def parse(cls, data: bytes) -> NativeVehicleSelection:
        reader = _Reader(data)
        core1, core2 = reader.unpack("HH")
        vin = NativeCoreString.read(reader)
        cores = []
        lists = []
        for index in range(3):
            list1, list2, count = reader.unpack("HHI")
            if count > 100_000 or count > (len(data) - reader.offset) // 12:
                raise RecorderError("Native vehicle entry count exceeds record")
            cores.append((list1, list2))
            entries = []
            for _ in range(count):
                first, second = reader.unpack("HH")
                if index == 2:
                    text = NativeCoreString.read(reader)
                    values = reader.unpack("H")
                else:
                    values = reader.unpack("HH" if index == 0 else "H")
                    text = NativeCoreString.read(reader)
                entries.append(NativeVehicleEntry((first, second), values, text))
            lists.append(tuple(entries))
        trail1, trail2 = reader.unpack("HH")
        reader.end()
        return cls(
            (core1, core2),
            vin,
            (cores[0], cores[1], cores[2]),
            lists[0],
            lists[1],
            lists[2],
            (trail1, trail2),
        )


@dataclass(frozen=True)
class NativeCategoryChoice:
    value: int
    label: str


@dataclass(frozen=True)
class NativeCategoryItem:
    level: int
    label: str
    choices: tuple[NativeCategoryChoice, ...]


@dataclass(frozen=True)
class NativeCategoryMenu:
    mode: int
    items: tuple[NativeCategoryItem, ...]


@dataclass(frozen=True)
class NativeMultiOptionGroup:
    category: int
    bus: int
    option_key: int
    raw_group: int
    raw_choice: int
    label_reference: int
    terminal_model: int
    next_group: int
    assigned_index: int
    assigned_select: int
    text: str


@dataclass
class _NativeMultiOptionGroup:
    category: int
    bus: int
    option_key: int
    raw_group: int
    raw_choice: int
    label_reference: int
    terminal_model: int
    next_group: int
    assigned_index: int = 0
    assigned_select: int = 0
    text: str = ""
    text_bytes: bytes = b""

    def snapshot(self) -> NativeMultiOptionGroup:
        return NativeMultiOptionGroup(
            self.category,
            self.bus,
            self.option_key,
            self.raw_group,
            self.raw_choice,
            self.label_reference,
            self.terminal_model,
            self.next_group,
            self.assigned_index,
            self.assigned_select,
            self.text,
        )


@dataclass(frozen=True)
class NativeDisplayItem:
    core_words: tuple[int, int]
    value: int
    label: NativeCoreString
    bounds: tuple[int, int]
    flags: int | None = None

    def encode(self) -> bytes:
        if self.core_words[0] not in (0, 1, 2):
            raise UnsupportedRecorderOperation(
                "Unsupported native display core version"
            )
        if (self.core_words[0] >= 2) != (self.flags is not None):
            raise RecorderError("Native display item flags must match core version")
        data = (
            struct.pack(
                "<HHI", *(_uint(x, 16) for x in self.core_words), _uint(self.value)
            )
            + self.label.encode()
        )
        data += struct.pack("<II", *(_uint(x) for x in self.bounds))
        if self.flags is not None:
            data += struct.pack("<B", _uint(self.flags, 8))
        return data

    @classmethod
    def read(cls, reader: _Reader) -> NativeDisplayItem:
        first, second, value = reader.unpack("HHI")
        if first not in (0, 1, 2):
            raise UnsupportedRecorderOperation(
                "Unsupported native display core version"
            )
        label = NativeCoreString.read(reader)
        low, high = reader.unpack("II")
        flags = reader.unpack("B")[0] if first >= 2 else None
        return cls((first, second), value, label, (low, high), flags)


@dataclass(frozen=True)
class NativeMonitorSignal:
    """CDrsMonSignalInfo direct layout; opaque integers retain native order."""

    identity_words: tuple[int, int, int, int]
    strings: tuple[NativeCoreString, NativeCoreString, NativeCoreString]
    selector_words: tuple[int, int]
    sign_mode: int
    scaling_words: tuple[int, int, int]
    precision: int
    raw_bounds: tuple[int, int]
    display_core_words: tuple[int, int]
    display_items: tuple[NativeDisplayItem, ...]
    trailing_words: tuple[int, int, int]

    def encode(self) -> bytes:
        chunks = [struct.pack("<4H", *(_uint(x, 16) for x in self.identity_words))]
        chunks.extend(value.encode() for value in self.strings)
        chunks.append(
            struct.pack(
                "<HHBIIIHII",
                *(_uint(x, 16) for x in self.selector_words),
                _uint(self.sign_mode, 8),
                *(_uint(x) for x in self.scaling_words),
                _uint(self.precision, 16),
                *(_uint(x) for x in self.raw_bounds),
            )
        )
        if len(self.display_items) > 100_000:
            raise RecorderError("Too many native display items")
        chunks.append(
            struct.pack(
                "<HHI",
                *(_uint(x, 16) for x in self.display_core_words),
                len(self.display_items),
            )
        )
        chunks.extend(value.encode() for value in self.display_items)
        chunks.append(struct.pack("<3I", *(_uint(x) for x in self.trailing_words)))
        return b"".join(chunks)

    @classmethod
    def read(cls, reader: _Reader) -> NativeMonitorSignal:
        id1, id2, id3, id4 = reader.unpack("4H")
        strings = tuple(NativeCoreString.read(reader) for _ in range(3))
        selector1, selector2, sign, mul, div, offset, precision, low, high = (
            reader.unpack("HHBIIIHII")
        )
        core1, core2, count = reader.unpack("HHI")
        if count > 100_000 or count > (len(reader.data) - reader.offset) // 22:
            raise RecorderError("Native display count exceeds record length")
        displays = tuple(NativeDisplayItem.read(reader) for _ in range(count))
        trail1, trail2, trail3 = reader.unpack("3I")
        return cls(
            (id1, id2, id3, id4),
            (strings[0], strings[1], strings[2]),
            (selector1, selector2),
            sign,
            (mul, div, offset),
            precision,
            (low, high),
            (core1, core2),
            displays,
            (trail1, trail2, trail3),
        )


@dataclass(frozen=True)
class NativeMonitorBuffer:
    """CDrsMonBuffInfo, including native nested frame and signal tables."""

    value_before_buffer: int
    buffer_size: int
    frame_count: int
    value_after_count: int
    allocation_size: int
    frame_table: DrsTable
    signal_table: DrsTable
    name: NativeCoreString
    selected_core_words: tuple[int, int]
    selected_ids: tuple[tuple[int, int, int], ...]

    @property
    def phase(self) -> int:
        """SetPhase input; buffer_size is retained as a legacy field alias."""
        return self.buffer_size

    @property
    def block_packets(self) -> int:
        """SetBlockPacket input; frame_count is retained as a legacy alias."""
        return self.frame_count

    @property
    def serial_mode(self) -> int:
        """SetSerialMode input; value_after_count is retained as a legacy alias."""
        return self.value_after_count

    def encode(self) -> bytes:
        if self.frame_table.table_id != 3 or self.signal_table.table_id != 4:
            raise RecorderError("Native monitor buffer needs nested frame3 and signal4")
        decode_command(self.frame_table)
        decode_command(self.signal_table)
        if len(self.selected_ids) > 100_000:
            raise RecorderError("Too many selected native IDs")
        data = struct.pack(
            "<IIHII",
            _uint(self.value_before_buffer),
            _uint(self.buffer_size),
            _uint(self.frame_count, 16),
            _uint(self.value_after_count),
            _uint(self.allocation_size),
        )
        data += (
            self.frame_table.encode() + self.signal_table.encode() + self.name.encode()
        )
        data += struct.pack(
            "<HHI",
            *(_uint(x, 16) for x in self.selected_core_words),
            len(self.selected_ids),
        )
        for first, second, _ in self.selected_ids:
            if (first, second) != (1, 0):
                raise RecorderError("CCmdWordId constructor core is not serialized")
        return data + b"".join(
            struct.pack("<H", _uint(item[2], 16)) for item in self.selected_ids
        )

    @classmethod
    def parse(cls, data: bytes) -> NativeMonitorBuffer:
        reader = _Reader(data)
        before, size, count, after, allocation = reader.unpack("IIHII")
        tables = []
        for expected_id in (3, 4):
            length, table_id = reader.unpack("IH")
            if length < 2 or table_id != expected_id:
                raise RecorderError("Invalid native monitor nested table")
            table = DrsTable(table_id, reader.take(length - 2))
            decode_command(table)
            tables.append(table)
        name = NativeCoreString.read(reader)
        core1, core2, selected_count = reader.unpack("HHI")
        if (
            selected_count > 100_000
            or selected_count > (len(data) - reader.offset) // 2
        ):
            raise RecorderError("Native selected ID count exceeds record")
        ids = []
        for _ in range(selected_count):
            value = reader.unpack("H")[0]
            ids.append((1, 0, value))
        reader.end()
        return cls(
            before,
            size,
            count,
            after,
            allocation,
            tables[0],
            tables[1],
            name,
            (core1, core2),
            tuple(ids),
        )


@dataclass(frozen=True)
class NativeTriggerInfo:
    """CCmdTriggerInfo serialization, including its opaque CCmdCore words."""

    core_words: tuple[int, int]
    trigger_type: int
    duration: int
    trigger_point: int

    def encode(self) -> bytes:
        values = (
            *self.core_words,
            self.trigger_type,
            self.duration,
            self.trigger_point,
        )
        if len(values) != 5:
            raise RecorderError("Trigger info requires two core words")
        return struct.pack("<5H", *(_uint(v, 16) for v in values))

    @classmethod
    def parse(cls, data: bytes) -> NativeTriggerInfo:
        r = _Reader(data)
        core1, core2, trigger_type, duration, point = r.unpack("5H")
        r.end()
        return cls((core1, core2), trigger_type, duration, point)


@dataclass(frozen=True)
class NativeTriggerCondition:
    """CCmdParamSignalInfo. Numeric condition types are deliberately uninterpreted."""

    core_words: tuple[int, int]
    pid_id: int
    condition_type: int
    parameter_value: int
    unit_multiplier: int
    unit_divisor: int

    def encode(self) -> bytes:
        words = (*self.core_words, self.pid_id, self.condition_type)
        if len(words) != 4:
            raise RecorderError("Trigger condition requires two core words")
        integers = (self.parameter_value, self.unit_multiplier, self.unit_divisor)
        return struct.pack(
            "<4H3I", *(_uint(v, 16) for v in words), *(_uint(v) for v in integers)
        )

    @classmethod
    def parse(cls, data: bytes) -> NativeTriggerCondition:
        r = _Reader(data)
        c1, c2, pid, condition, value, mul, div = r.unpack("4H3I")
        r.end()
        return cls((c1, c2), pid, condition, value, mul, div)


@dataclass(frozen=True)
class NativeTriggerParameters:
    """CCmdTriggerParam and its two native lists, without guessed enum meanings."""

    core_words: tuple[int, int]
    record_quantity: int
    parameter_condition: int
    condition_list_core: tuple[int, int]
    conditions: tuple[NativeTriggerCondition, ...]
    stealth_list_core: tuple[int, int]
    stealth_ids: tuple[tuple[int, int, int], ...]

    def encode(self) -> bytes:
        def core(words: tuple[int, int]) -> bytes:
            if len(words) != 2:
                raise RecorderError("Expected two native core words")
            return struct.pack("<HH", *(_uint(v, 16) for v in words))

        result = core(self.core_words) + struct.pack(
            "<HH", _uint(self.record_quantity, 16), _uint(self.parameter_condition, 16)
        )
        result += core(self.condition_list_core) + struct.pack(
            "<I", len(self.conditions)
        )
        result += b"".join(c.encode() for c in self.conditions)
        result += core(self.stealth_list_core) + struct.pack(
            "<I", len(self.stealth_ids)
        )
        for words in self.stealth_ids:
            if len(words) != 3:
                raise RecorderError("Stealth ID requires core words and u16 ID")
            if words[:2] != (1, 0):
                raise RecorderError("CCmdWordId constructor core is not serialized")
            result += struct.pack("<H", _uint(words[2], 16))
        return result

    @classmethod
    def parse(cls, data: bytes) -> NativeTriggerParameters:
        r = _Reader(data)
        core1, core2, quantity, condition = r.unpack("4H")
        list1, list2, count = r.unpack("HHI")
        if count > (len(data) - r.offset) // 20:
            raise RecorderError("Trigger condition count exceeds record")
        conditions = tuple(
            NativeTriggerCondition.parse(r.take(20)) for _ in range(count)
        )
        list3, list4, count = r.unpack("HHI")
        if count > (len(data) - r.offset) // 2:
            raise RecorderError("Stealth ID count exceeds record")
        ids: list[tuple[int, int, int]] = []
        for _ in range(count):
            value = r.unpack("H")[0]
            ids.append((1, 0, value))
        r.end()
        return cls(
            (core1, core2),
            quantity,
            condition,
            (list1, list2),
            conditions,
            (list3, list4),
            tuple(ids),
        )


def native_trigger_sign_value(raw: int, sign_mode: int, bit_width: int) -> int:
    """DriveRecord0x118f24 sign conversion before native 64-bit arithmetic."""
    _uint(raw)
    _uint(sign_mode, 8)
    if type(bit_width) is not int or not 1 <= bit_width <= 32:
        raise RecorderError("Native trigger signal width must be 1..32")
    sign_bit = 1 << (bit_width - 1)
    if sign_mode == 1 and raw & sign_bit:
        result = (raw | (0xFFFFFFFF << (bit_width - 1))) & 0xFFFFFFFF
        return result - (1 << 32) if result & (1 << 31) else result
    if sign_mode == 3 and raw & sign_bit:
        return -(raw & (sign_bit - 1))
    return raw


def convert_native_trigger_value(
    raw: int, signal: NativeMonitorSignal, condition: NativeTriggerCondition
) -> int:
    """Native recorder affine conversion, then trigger-unit multiplication/division.

    The SH3 body matches independently recovered DatMonCommon x86 affine worker.
    This accepts an already extracted raw signal, not a complete diagnostic frame.
    """
    divisor, multiplier, offset = signal.scaling_words
    if i32(divisor) <= 0 or i32(condition.unit_divisor) <= 0:
        raise RecorderError("Native trigger divisors must be signed-positive")
    bits = signal.identity_words[3] - signal.identity_words[2] + 1
    _uint(raw)
    value = affine(raw, multiplier, divisor, offset, bits, signal.sign_mode)
    return affine(
        value & 0xFFFFFFFF, condition.unit_multiplier, condition.unit_divisor, 0, 32, 1
    )


@dataclass
class NativeTriggerComparison:
    """DriveRecord 0x118d24 comparisons on already converted signed32 values."""

    condition_type: int
    reference: int
    sliding_reference: bool = False
    phase: int = 2

    def evaluate(self, value: int) -> bool:
        if any(
            type(x) is not int or not -(1 << 31) <= x < (1 << 31)
            for x in (value, self.reference)
        ):
            raise RecorderError("Native trigger comparison requires signed32 values")
        if self.phase not in (0, 1, 2) or type(self.sliding_reference) is not bool:
            raise RecorderError("Invalid native trigger comparison state")
        if self.phase == 0:
            self.reference = value
        if self.condition_type == 3:
            matched = value == self.reference
        elif self.condition_type == 5:
            matched = value < self.reference
        elif self.condition_type == 6:
            matched = value > self.reference
        else:
            matched = False
        self.phase = 1 if matched else 2
        if self.sliding_reference:
            self.reference = value
        return matched


def evaluate_native_comparisons(
    comparisons: tuple[NativeTriggerComparison, ...],
    values: tuple[int, ...],
    parameter_condition: int,
) -> bool:
    """Native 0x118c98 AND1/OR2; scaling/bit conversion is deliberately separate."""
    if len(comparisons) != len(values) or len(comparisons) > 65535:
        raise RecorderError("Native trigger comparison/value count mismatch")
    if not comparisons:
        return False
    mode = 2 if len(comparisons) == 1 else parameter_condition
    if mode not in (1, 2):
        return False
    # The original evaluates every condition, updating every sliding reference.
    results = [
        comparison.evaluate(value)
        for comparison, value in zip(comparisons, values, strict=True)
    ]
    return all(results) if mode == 1 else any(results)


@dataclass(frozen=True)
class RecorderPaths:
    setting_folder: str
    output_folder: str
    max_file: int

    @classmethod
    def parse(cls, data: bytes) -> RecorderPaths:
        try:
            text = (
                data.decode("utf-16")
                if data.startswith((b"\xff\xfe", b"\xfe\xff"))
                else data.decode("utf-8-sig")
            )
            parser = configparser.ConfigParser(interpolation=None)
            parser.read_string(text)
            section = parser["DriveRecord"]
            result = cls(
                section["SettingFolder"],
                section["OutputFolder"],
                int(section["MaxFile"]),
            )
        except (UnicodeError, configparser.Error, KeyError, ValueError) as exc:
            raise RecorderError("Malformed DriveRecord INI") from exc
        if not result.setting_folder or not result.output_folder or result.max_file < 1:
            raise RecorderError("Invalid recorder paths/file count")
        return result


class RecorderBackend(Protocol):
    """Injected adapter boundary. Must honor deadline and cancellation itself."""

    def invoke(
        self,
        operation: str,
        fields: Mapping[str, object],
        *,
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> object: ...


class RecorderController:
    """Host policy around native records, independent of VIM wire command IDs."""

    def __init__(
        self,
        backend: RecorderBackend,
        *,
        capabilities: frozenset[str],
        clock: Callable[[], float] = time.monotonic,
    ):
        self.backend = backend
        self.capabilities = capabilities
        self.clock = clock
        self.state = "idle"
        self.last_error: str | None = None

    def _invoke(
        self,
        operation: str,
        fields: Mapping[str, object],
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> object:
        if cancelled():
            raise RecorderCancelled("Recorder operation cancelled")
        if _clock_now(self.clock) >= deadline:
            raise TimeoutError("Recorder deadline exceeded")
        try:
            result = self.backend.invoke(
                operation, fields, deadline=deadline, cancelled=cancelled
            )
        except (Exception, KeyboardInterrupt) as exc:
            if cancelled():
                raise RecorderCancelled("Recorder operation cancelled") from exc
            if _clock_now(self.clock, cause=exc) >= deadline:
                raise TimeoutError("Recorder deadline exceeded") from exc
            raise
        if cancelled():
            raise RecorderCancelled("Recorder operation cancelled")
        if _clock_now(self.clock) >= deadline:
            raise TimeoutError("Recorder deadline exceeded")
        return result

    def execute(
        self,
        settings: DrsFile,
        *,
        timeout: float = 10.0,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> list[object]:
        """Execute a fully decoded DRS sequence using an explicitly injected backend."""
        if self.state != "idle":
            raise RecorderError(f"Cannot execute from {self.state}; recover first")
        if "native-drs-execution" not in self.capabilities:
            raise UnsupportedRecorderOperation(
                "Adapter did not explicitly declare native-drs-execution"
            )
        if not math.isfinite(timeout) or timeout <= 0:
            raise RecorderError("Timeout must be finite and positive")
        # Preflight every table before the first adapter action.
        commands = [(table.name, decode_command(table)) for table in settings.tables]
        pending = [(table, 0) for table in settings.tables]
        seen = 0
        while pending:
            table, depth = pending.pop()
            seen += 1
            if depth > 64 or seen > 100_000:
                raise RecorderError("Native DRS command tree exceeds configured bounds")
            fields = decode_command(table)
            children = fields.get("children")
            if isinstance(children, tuple):
                pending.extend(
                    (child, depth + 1)
                    for child in children
                    if isinstance(child, DrsTable)
                )
        deadline = _recorder_deadline(self.clock, timeout)
        results: list[object] = []
        self.state = "executing"
        self.last_error = None
        try:
            if cancelled():
                raise RecorderCancelled("Recorder operation cancelled")
            for operation, fields in commands:
                results.append(self._invoke(operation, fields, deadline, cancelled))
        except (Exception, KeyboardInterrupt) as exc:
            self.state = "cancelled" if isinstance(exc, RecorderCancelled) else "fault"
            self.last_error = str(exc)
            raise
        self.state = "idle"
        return results

    def recover(self) -> None:
        """Acknowledge host error; does not assert adapter or ECU recovery."""
        if self.state == "executing":
            raise RecorderError("Cannot clear state while execution is active")
        self.state = "idle"
        self.last_error = None

    def report(self) -> dict[str, object]:
        return {
            "state": self.state,
            "last_error": self.last_error,
            "capabilities": sorted(self.capabilities),
            "physical": "PHYSICAL_UNCONFIRMED",
            "native_control_wire": "unresolved",
        }


class NativeTransferError(RecorderError):
    def __init__(self, native_error: int, message: str):
        self.native_error = native_error
        super().__init__(message)


@dataclass(frozen=True)
class NativeTransferFrame:
    """ComTol32 transfer frame: STX, control, length16, bytes, sum8, ETX."""

    control: int
    payload: bytes

    def encode(self) -> bytes:
        if len(self.payload) > 511:
            raise RecorderError("Native transfer frame exceeds 511 bytes")
        body = (
            struct.pack("<BH", _uint(self.control, 8), len(self.payload)) + self.payload
        )
        return b"\x02" + body + bytes((sum(body) & 255, 3))

    @classmethod
    def parse(cls, data: bytes) -> NativeTransferFrame:
        if len(data) < 4:
            raise NativeTransferError(0x900D0009, "Native transfer frame is too short")
        control, size = struct.unpack_from("<BH", data, 1)
        if size > 511 or len(data) != size + 6:
            raise NativeTransferError(
                0x900D0003, "Invalid native transfer frame length"
            )
        if sum(data[1:-2]) & 255 != data[-2]:
            raise NativeTransferError(
                0x900D0004, "Invalid native transfer frame checksum"
            )
        if data[0] != 2 or data[-1] != 3:
            raise NativeTransferError(
                0x900D0006, "Invalid native transfer frame boundary"
            )
        return cls(control, data[4:-2])


@dataclass(frozen=True)
class NativeTransferAcknowledgement:
    """Recovered transfer control3 ACK(state8) / NAK(error32), separate from command replies."""

    state: int | None = None
    error: int | None = None

    def encode(self) -> bytes:
        if (self.state is None) == (self.error is None):
            raise RecorderError("Native transfer acknowledgement needs state or error")
        if self.state is not None:
            payload = bytes((6, _uint(self.state, 8)))
        else:
            assert self.error is not None
            payload = b"\x15" + struct.pack("<I", _uint(self.error))
        return NativeTransferFrame(3, payload).encode()

    @classmethod
    def parse(cls, data: bytes) -> NativeTransferAcknowledgement:
        frame = NativeTransferFrame.parse(data)
        if frame.control != 3:
            raise RecorderError("Expected native transfer control3 acknowledgement")
        if len(frame.payload) == 2 and frame.payload[0] == 6:
            return cls(state=frame.payload[1])
        if len(frame.payload) == 5 and frame.payload[0] == 0x15:
            return cls(error=struct.unpack_from("<I", frame.payload, 1)[0])
        raise NativeTransferError(
            0x900D0006, "Invalid native transfer acknowledgement body"
        )


def encode_vim_transfer(
    data: bytes, *, max_size: int = 64 * 1024 * 1024
) -> tuple[bytes, ...]:
    """Original 511-byte segmentation; ACK/retry timing belongs to the transport."""
    if type(max_size) is not int or max_size < 0 or len(data) > max_size:
        raise RecorderError("Native transfer exceeds configured size")
    chunks = [data[i : i + 511] for i in range(0, len(data), 511)] or [b""]
    frames = []
    for index, chunk in enumerate(chunks):
        if len(chunks) == 1:
            control = 0
        elif index == 0:
            control = 1
        elif index == len(chunks) - 1:
            control = 2
        else:
            control = 0x80 + ((index - 1) & 0x7F)
        frames.append(NativeTransferFrame(control, chunk).encode())
    return tuple(frames)


def decode_vim_transfer(
    frames: tuple[bytes, ...], *, max_size: int = 64 * 1024 * 1024
) -> bytes:
    if (
        type(max_size) is not int
        or max_size < 0
        or not frames
        or len(frames) > max_size // 511 + 2
    ):
        raise RecorderError("Invalid native transfer bounds")
    chunks = []
    size = 0
    for index, raw in enumerate(frames):
        frame = NativeTransferFrame.parse(raw)
        expected = (
            0
            if len(frames) == 1
            else (
                1
                if index == 0
                else (2 if index == len(frames) - 1 else 0x80 + ((index - 1) & 0x7F))
            )
        )
        if frame.control != expected or (
            index < len(frames) - 1 and len(frame.payload) != 511
        ):
            raise RecorderError("Native transfer sequence mismatch")
        if len(frames) > 1 and not frame.payload:
            raise RecorderError("Empty segmented native transfer frame")
        size += len(frame.payload)
        if size > max_size:
            raise RecorderError("Native transfer exceeds configured size")
        chunks.append(frame.payload)
    return b"".join(chunks)


class NativeTransferSession:
    """Recovered ComTol a190/a450 FSM, with bounded authored buffer ownership."""

    def __init__(
        self,
        *,
        max_size: int = 64 * 1024 * 1024,
        clock: Callable[[], float] = time.monotonic,
    ):
        if type(max_size) is not int or max_size < 0:
            raise RecorderError("Invalid native transfer size limit")
        self.max_size = max_size
        self.clock = clock
        self.state = 1
        self.last_activity = _clock_now(clock)
        self.last_error: str | None = None
        self._outgoing: tuple[bytes, ...] = ()
        self._sent = 0
        self._chunks: list[bytes] = []
        self._size = 0
        self.complete = False

    def start(self, data: bytes) -> bytes:
        if self.state not in (0, 1):
            raise RecorderError("Native transfer already active")
        now = _clock_now(self.clock)
        self._outgoing = encode_vim_transfer(data, max_size=self.max_size)
        self._sent = 1
        self._chunks.clear()
        self._size = 0
        self.complete = False
        self.last_error = None
        self.last_activity = now
        self.state = 2
        return self._outgoing[0]

    def _append(self, frame: NativeTransferFrame) -> bytes:
        if frame.control in (0, 1):
            self._chunks.clear()
            self._size = 0
        elif frame.control != 2 and frame.control != 0x80 + (
            (len(self._chunks) - 1) & 0x7F
        ):
            raise NativeTransferError(
                0x900D0005, "Native transfer continuation sequence mismatch"
            )
        if self._size + len(frame.payload) > self.max_size:
            raise RecorderError("Native receive buffer exceeds configured size")
        self._chunks.append(frame.payload)
        self._size += len(frame.payload)
        self.last_activity = _clock_now(self.clock)
        self.state = 3
        self.complete = frame.control in (0, 2)
        return NativeTransferAcknowledgement(state=3).encode()

    def receive(self, data: bytes) -> tuple[bytes, ...]:
        try:
            _clock_now(self.clock)
            frame = NativeTransferFrame.parse(data)
            if self.state in (1, 4, 5) and frame.control == 0x7F:
                if len(frame.payload) != 2 or frame.payload[0] != 6:
                    raise RecorderError("Invalid native keepalive acknowledgement")
                self.last_activity = (
                    _clock_now(self.clock)
                    if self.state != 5 or frame.payload[1] not in (0, 1)
                    else 0.0
                )
                return ()
            if self.state == 2:
                ack = NativeTransferAcknowledgement.parse(data)
                self.last_activity = _clock_now(self.clock)
                if ack.error is not None:
                    raise RecorderError(f"Native transfer NAK: {ack.error:#010x}")
                if self._sent < len(self._outgoing):
                    result = self._outgoing[self._sent]
                    self._sent += 1
                    return (result,)
                self.state = 5
                return ()
            if self.state == 5 and frame.control in (0, 1):
                return (self._append(frame),)
            if self.state == 3 and (frame.control in (0, 1, 2) or frame.control & 0x80):
                return (self._append(frame),)
            raise RecorderError(f"Unexpected native frame in state {self.state}")
        except NativeTransferError as exc:
            self.last_error = f"{exc} ({exc.native_error:#010x})"
            control = data[1] if len(data) >= 2 else -1
            recoverable = (self.state == 5 and control in (0, 1)) or (
                self.state == 3
                and control >= 0
                and (control in (0, 1, 2) or control & 0x80)
            )
            if recoverable:
                return (NativeTransferAcknowledgement(error=exc.native_error).encode(),)
            raise
        except (Exception, KeyboardInterrupt) as exc:
            self.last_error = str(exc)
            raise

    def poll(self) -> tuple[bytes, ...]:
        """Native ACK timeout2s, receive timeout10s, state5 keepalive request."""
        now = _clock_now(self.clock)
        limit = 2.0 if self.state == 2 else 10.0
        if self.state in (2, 3, 5) and now > self.last_activity + limit:
            self.last_error = (
                "Native transfer acknowledgement timeout"
                if self.state == 2
                else "Native transfer response timeout"
            )
            raise TimeoutError(self.last_error)
        if self.state == 5:
            return (NativeTransferFrame(0x7F, b"").encode(),)
        return ()

    def take_response(self) -> bytes:
        if self.state != 3 or not self.complete:
            raise RecorderError("Native transfer response is incomplete")
        self.state = 4
        result = b"".join(self._chunks)
        self._chunks.clear()
        self._size = 0
        self.complete = False
        self.state = 1
        return result

    def cancel(self) -> None:
        self.state = 0
        self._outgoing = ()
        self._chunks.clear()
        self._size = 0
        self.complete = False
        self.last_error = "Native transfer cancelled"


def encode_vim_command(command_id: int, payload: bytes = b"") -> bytes:
    """ComTol32 logical packet; USB transfer framing is a separate layer."""
    value = _uint(command_id)
    raw = struct.pack("<I", value)
    size = 1
    if raw[0] & 0x7F == 0x7F:
        size = 2
        if raw[1] == 0xFF:
            size = 3
            if raw[2] == 0xFF:
                size = 4
    if any(raw[size:]):
        raise RecorderError(
            "Command ID is not representable by native compact encoding"
        )
    if not isinstance(payload, bytes):
        raise RecorderError("VIM payload must be bytes")
    return raw[:size] + payload


def _read_vim_command_id(reader: _Reader) -> int:
    first = reader.take(1)[0]
    value = first
    if first & 0x7F == 0x7F:
        second = reader.take(1)[0]
        value |= second << 8
        if second == 0xFF:
            third = reader.take(1)[0]
            value |= third << 16
            if third == 0xFF:
                value |= reader.take(1)[0] << 24
    return value


def decode_vim_command(data: bytes) -> tuple[int, bytes]:
    reader = _Reader(data)
    command = _read_vim_command_id(reader)
    return command, reader.take(len(data) - reader.offset)


@dataclass(frozen=True)
class NativeVimReply:
    command_id: int
    control: int
    payload: bytes
    error: int = 0

    @classmethod
    def parse(cls, data: bytes) -> NativeVimReply:
        reader = _Reader(data)
        command = _read_vim_command_id(reader)
        control = reader.take(1)[0]
        if control == 6:
            return cls(command, control, reader.take(len(data) - reader.offset))
        error = reader.unpack("I")[0]
        reader.end()
        return cls(command, control, b"", error)

    def encode(self) -> bytes:
        _uint(self.control, 8)
        body = (
            self.payload if self.control == 6 else struct.pack("<I", _uint(self.error))
        )
        return encode_vim_command(self.command_id, bytes([self.control]) + body)


class NativeVimError(RecorderError):
    def __init__(self, reply: NativeVimReply):
        self.reply = reply
        super().__init__(
            f"VIM control {reply.control:#x}, native error {reply.error:#010x}"
        )


class NativeDmciError(RecorderError):
    def __init__(self, status: int):
        self.status = _uint(status)
        super().__init__(f"Native DMCI status: {self.status:#010x}")


class NativeVimExchange(Protocol):
    def __call__(
        self, request: bytes, *, deadline: float, cancelled: Callable[[], bool]
    ) -> bytes: ...


@dataclass(frozen=True)
class NativeSystemTime:
    year: int
    month: int
    day_of_week: int
    day: int
    hour: int
    minute: int
    second: int
    milliseconds: int

    def encode(self) -> bytes:
        return struct.pack(
            "<8H",
            *(
                _uint(value, 16)
                for value in (
                    self.year,
                    self.month,
                    self.day_of_week,
                    self.day,
                    self.hour,
                    self.minute,
                    self.second,
                    self.milliseconds,
                )
            ),
        )

    @classmethod
    def parse(cls, data: bytes) -> NativeSystemTime:
        reader = _Reader(data)
        year, month, weekday, day, hour, minute, second, millis = reader.unpack("8H")
        reader.end()
        return cls(year, month, weekday, day, hour, minute, second, millis)


class NativeVimClient:
    """Actual ComTol32 logical command bytes against an injected packet exchange."""

    def __init__(
        self,
        exchange: NativeVimExchange,
        *,
        capabilities: frozenset[str],
        clock: Callable[[], float] = time.monotonic,
    ):
        self.exchange = exchange
        self.capabilities = capabilities
        self.clock = clock
        self._capture_lock = Lock()

    def call(
        self,
        command_id: int,
        payload: bytes = b"",
        *,
        timeout: float = 10.0,
        cancelled: Callable[[], bool] = lambda: False,
        received: Callable[[NativeVimReply], None] | None = None,
    ) -> NativeVimReply:
        if "denso-vim-control" not in self.capabilities:
            raise UnsupportedRecorderOperation(
                "Adapter did not explicitly declare denso-vim-control"
            )
        if not math.isfinite(timeout) or timeout <= 0:
            raise RecorderError("Timeout must be finite and positive")
        if cancelled():
            raise RecorderCancelled("VIM command cancelled")
        deadline = _recorder_deadline(self.clock, timeout)
        request = encode_vim_command(command_id, payload)
        try:
            response = self.exchange(request, deadline=deadline, cancelled=cancelled)
            reply = NativeVimReply.parse(response)
            if reply.command_id != command_id | 0x80:
                raise RecorderError(
                    "Native VIM response command does not match request"
                )
            if reply.control != 6:
                raise NativeVimError(reply)
            if received is not None:
                received(reply)
        except (Exception, KeyboardInterrupt) as exc:
            if cancelled():
                raise RecorderCancelled("VIM command cancelled") from exc
            if _clock_now(self.clock, cause=exc) >= deadline:
                raise TimeoutError("VIM command deadline exceeded") from exc
            raise
        if cancelled():
            raise RecorderCancelled("VIM command cancelled")
        if _clock_now(self.clock) >= deadline:
            raise TimeoutError("VIM command deadline exceeded")
        return reply

    def dmci(
        self,
        command: NativeDmciCommand,
        *,
        timeout: float = 10.0,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> bytes:
        if "denso-vim-dmci" not in self.capabilities:
            raise UnsupportedRecorderOperation(
                "Adapter did not explicitly declare denso-vim-dmci"
            )
        payload = command.encode()
        reply = self.call(
            DMCI_WIRE_COMMANDS[command.command_id],
            payload,
            timeout=timeout,
            cancelled=cancelled,
        )
        reader = _Reader(reply.payload)
        status = reader.unpack("I")[0]
        if status:
            raise NativeDmciError(status)
        return reader.take(len(reader.data) - reader.offset)

    def get_monitor_data(
        self,
        interface_ids: tuple[int, ...],
        *,
        timeout: float = 10.0,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> NativeMonitorReply:
        command = NativeDmciCommand(
            0x10D,
            (
                NativeDmciList(
                    (1, 0), tuple((_uint(value),) for value in interface_ids)
                ),
            ),
        )
        tail = self.dmci(command, timeout=timeout, cancelled=cancelled)
        result = NativeMonitorReply.parse(bytes(4) + tail)
        return result

    def get_mode(
        self, *, timeout: float = 10.0, cancelled: Callable[[], bool] = lambda: False
    ) -> int:
        reply = self.call(1, timeout=timeout, cancelled=cancelled)
        reader = _Reader(reply.payload)
        mode = reader.unpack("I")[0]
        reader.end()
        return mode

    def change_mode(
        self,
        mode: int,
        *,
        timeout: float = 10.0,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> int:
        reply = self.call(
            2, struct.pack("<I", _uint(mode)), timeout=timeout, cancelled=cancelled
        )
        reader = _Reader(reply.payload)
        result = reader.unpack("I")[0]
        reader.end()
        return result

    def get_time(
        self,
        *,
        local: bool = False,
        timeout: float = 10.0,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> NativeSystemTime:
        if type(local) is not bool:
            raise RecorderError("Native time selector must be boolean")
        reader = _Reader(
            self.call(6 if local else 4, timeout=timeout, cancelled=cancelled).payload
        )
        status = reader.unpack("I")[0]
        result = NativeSystemTime.parse(reader.take(16))
        reader.end()
        if status:
            raise RecorderError(f"Native VIM time status: {status:#010x}")
        return result

    def set_time(
        self,
        value: NativeSystemTime,
        *,
        local: bool = False,
        timeout: float = 10.0,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> bool:
        if type(local) is not bool or not isinstance(value, NativeSystemTime):
            raise RecorderError("Invalid native time input")
        reader = _Reader(
            self.call(
                7 if local else 5, value.encode(), timeout=timeout, cancelled=cancelled
            ).payload
        )
        status, result = reader.unpack("II")
        reader.end()
        if status:
            raise RecorderError(f"Native VIM time status: {status:#010x}")
        return bool(result)

    def command_execute(
        self,
        native_payload: bytes,
        *,
        timeout: float = 10.0,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> bytes:
        return self.call(
            0x70, native_payload, timeout=timeout, cancelled=cancelled
        ).payload


def _vim_path(path: str) -> bytes:
    if not path or "\0" in path:
        raise RecorderError("VIM path must be nonempty without embedded NUL")
    data = (path + "\0").encode("utf-16le")
    _uint(len(data), 16)
    return struct.pack("<IHHH", len(data), 1, 0, len(data)) + data


class NativeVimFiles:
    """Original ComTol file packets over injected exchange; no host filesystem I/O."""

    def __init__(self, client: NativeVimClient):
        self.client = client

    def _call(
        self,
        command: int,
        payload: bytes,
        timeout: float,
        cancelled: Callable[[], bool],
        received: Callable[[NativeVimReply], None] | None = None,
    ) -> bytes:
        if "denso-vim-files" not in self.client.capabilities:
            raise UnsupportedRecorderOperation(
                "Adapter did not explicitly declare denso-vim-files"
            )
        return self.client.call(
            command, payload, timeout=timeout, cancelled=cancelled, received=received
        ).payload

    def open(
        self,
        path: str,
        *,
        access: int = 0x80000000,
        sharing: int = 0,
        creation: int = 3,
        flags: int = 0x80,
        template: int = 0,
        timeout: float = 10.0,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> int:
        body = _vim_path(path) + struct.pack(
            "<5I", *(_uint(v) for v in (access, sharing, creation, flags, template))
        )
        handle: int | None = None

        def acquired(reply: NativeVimReply) -> None:
            nonlocal handle
            if len(reply.payload) >= 4:
                value = struct.unpack_from("<I", reply.payload)[0]
                if value not in (0, 0xFFFFFFFF):
                    handle = value

        try:
            reader = _Reader(self._call(0x21, body, timeout, cancelled, acquired))
            value = reader.unpack("I")[0]
            reader.end()
            if handle is None:
                raise RecorderError("Native VIM CreateFile returned an invalid handle")
            return value
        except BaseException as exc:
            if handle is not None:
                self._finish(handle, exc)
            raise

    def close(
        self,
        handle: int,
        *,
        timeout: float = 10.0,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> None:
        reader = _Reader(
            self._call(0x22, struct.pack("<I", _uint(handle)), timeout, cancelled)
        )
        success = reader.take(1)[0]
        reader.end()
        if not success:
            raise RecorderError("Native VIM CloseHandle failed")

    def read(
        self,
        handle: int,
        size: int,
        *,
        timeout: float = 10.0,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> bytes:
        reader = _Reader(
            self._call(
                0x23, struct.pack("<II", _uint(handle), _uint(size)), timeout, cancelled
            )
        )
        success = reader.take(1)[0]
        count, core1, core2, length = reader.unpack("IHHI")
        data = reader.take(length)
        reader.end()
        if not success or count != length or count > size:
            raise RecorderError(
                "Native VIM ReadFile failed or returned inconsistent byte counts"
            )
        if core1 != 1 or core2 != 0:
            raise UnsupportedRecorderOperation(
                "Unsupported native VIM read buffer core version"
            )
        return data

    def write(
        self,
        handle: int,
        data: bytes,
        *,
        timeout: float = 10.0,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> int:
        if not isinstance(data, bytes):
            raise RecorderError("Native VIM write data must be bytes")
        size = _uint(len(data))
        body = struct.pack("<IIHHI", _uint(handle), size, 1, 0, size) + data
        reader = _Reader(self._call(0x24, body, timeout, cancelled))
        success = reader.take(1)[0]
        written = reader.unpack("I")[0]
        reader.end()
        if not success or written > size:
            raise RecorderError(
                "Native VIM WriteFile failed or returned invalid byte count"
            )
        return written

    def seek(
        self,
        handle: int,
        offset: int,
        origin: int = 0,
        *,
        timeout: float = 10.0,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> int:
        if (
            type(offset) is not int
            or not -(1 << 63) <= offset < 1 << 63
            or origin not in (0, 1, 2)
        ):
            raise RecorderError("Invalid native file seek")
        body = struct.pack(
            "<4I",
            _uint(handle),
            offset & 0xFFFFFFFF,
            (offset >> 32) & 0xFFFFFFFF,
            origin,
        )
        reader = _Reader(self._call(0x2E, body, timeout, cancelled))
        low, high = reader.unpack("II")
        reader.end()
        return low | (high << 32)

    def _find_result(
        self, data: bytes, *, first: bool
    ) -> tuple[int, dict[str, object] | None]:
        reader = _Reader(data)
        status = reader.unpack("I")[0] if first else reader.take(1)[0]
        metadata = reader.unpack("9I")
        declared, core1, core2, length = reader.unpack("4H")
        raw_name = reader.take(length)
        reader.end()
        if (first and status in (0, 0xFFFFFFFF)) or (not first and not status):
            return status, None
        if (
            declared != length
            or core1 != 1
            or core2 != 0
            or length < 2
            or raw_name[-2:] != b"\0\0"
        ):
            raise RecorderError("Malformed native VIM FindFile result")
        try:
            name = raw_name[:-2].decode("utf-16le")
        except UnicodeError as exc:
            raise RecorderError("Malformed native VIM filename") from exc
        if "\0" in name:
            raise RecorderError("Embedded NUL in native VIM filename")
        return status, {
            "name": name,
            "attributes": metadata[0],
            "creation_time_words": metadata[1:3],
            "access_time_words": metadata[3:5],
            "write_time_words": metadata[5:7],
            "size": (metadata[7] << 32) | metadata[8],
        }

    def list_files(
        self,
        pattern: str,
        *,
        max_entries: int = 10_000,
        timeout: float = 30.0,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> list[dict[str, object]]:
        if (
            type(max_entries) is not int
            or max_entries < 1
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise RecorderError("Invalid native file listing bounds")
        path = _vim_path(pattern)
        body = struct.pack("<H", struct.unpack_from("<I", path)[0]) + path[4:]
        deadline = _recorder_deadline(self.client.clock, timeout)
        handle: int | None = None
        primary: BaseException | None = None

        def acquired(reply: NativeVimReply) -> None:
            nonlocal handle
            if len(reply.payload) >= 4:
                value = struct.unpack_from("<I", reply.payload)[0]
                if value not in (0, 0xFFFFFFFF):
                    handle = value

        try:
            _, entry = self._find_result(
                self._call(0x26, body, timeout, cancelled, acquired), first=True
            )
            if entry is None:
                return []
            assert handle is not None
            result = [entry]
            while True:
                remaining = deadline - _clock_now(self.client.clock)
                if remaining <= 0:
                    raise TimeoutError("VIM file listing deadline exceeded")
                _, entry = self._find_result(
                    self._call(0x27, struct.pack("<I", handle), remaining, cancelled),
                    first=False,
                )
                if entry is None:
                    return result
                if len(result) >= max_entries:
                    raise RecorderError(
                        "Native VIM listing exceeds configured entry count"
                    )
                result.append(entry)
        except BaseException as exc:
            primary = exc
            raise
        finally:
            try:
                if handle is not None:
                    with _cleanup_clock_scope(self.client.clock):
                        reader = _Reader(
                            self._call(
                                0x28, struct.pack("<I", handle), 2.0, lambda: False
                            )
                        )
                        success = reader.take(1)[0]
                        reader.end()
                        if not success:
                            raise RecorderError("Native VIM FindClose failed")
            except (Exception, KeyboardInterrupt) as exc:
                if primary is None:
                    raise
                primary.add_note(f"Native VIM search cleanup also failed: {exc}")

    def _finish(self, handle: int, primary: BaseException | None) -> None:
        try:
            # Cleanup has a fresh bounded deadline even when transfer was cancelled.
            with _cleanup_clock_scope(self.client.clock):
                self.close(handle, timeout=2.0)
        except (Exception, KeyboardInterrupt) as exc:
            if primary is None:
                raise
            primary.add_note(f"Native VIM handle cleanup also failed: {exc}")

    def download(
        self,
        path: str,
        *,
        max_size: int = 64 * 1024 * 1024,
        chunk_size: int = 64 * 1024,
        timeout: float = 30.0,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> bytes:
        if (
            type(max_size) is not int
            or max_size < 0
            or type(chunk_size) is not int
            or chunk_size <= 0
        ):
            raise RecorderError("Invalid download size bounds")
        if not math.isfinite(timeout) or timeout <= 0:
            raise RecorderError("Timeout must be finite and positive")
        deadline = _recorder_deadline(self.client.clock, timeout)
        handle = self.open(path, timeout=timeout, cancelled=cancelled)
        output = bytearray()
        primary: BaseException | None = None
        try:
            while True:
                remaining = deadline - _clock_now(self.client.clock)
                if remaining <= 0:
                    raise TimeoutError("VIM download deadline exceeded")
                count = min(chunk_size, max_size - len(output) + 1)
                data = self.read(handle, count, timeout=remaining, cancelled=cancelled)
                if len(data) > max_size - len(output):
                    raise RecorderError(
                        "Native recording exceeds configured download size"
                    )
                output.extend(data)
                if not data:
                    return bytes(output)
        except BaseException as exc:
            primary = exc
            raise
        finally:
            self._finish(handle, primary)

    def upload_settings(
        self,
        path: str,
        settings: DrsFile,
        *,
        chunk_size: int = 64 * 1024,
        timeout: float = 30.0,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> int:
        """CREATE_ALWAYS replaces the named VIM file; caller explicitly opts in."""
        if (
            type(chunk_size) is not int
            or chunk_size <= 0
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise RecorderError("Invalid upload bounds")
        data = settings.encode()
        deadline = _recorder_deadline(self.client.clock, timeout)
        handle = self.open(
            path, access=0x40000000, creation=2, timeout=timeout, cancelled=cancelled
        )
        primary: BaseException | None = None
        sent = 0
        try:
            while sent < len(data):
                remaining = deadline - _clock_now(self.client.clock)
                if remaining <= 0:
                    raise TimeoutError("VIM upload deadline exceeded")
                written = self.write(
                    handle,
                    data[sent : sent + chunk_size],
                    timeout=remaining,
                    cancelled=cancelled,
                )
                if not written:
                    raise RecorderError("Native VIM WriteFile made no progress")
                sent += written
            return sent
        except BaseException as exc:
            primary = exc
            raise
        finally:
            self._finish(handle, primary)


class RecorderEntrypoints(Protocol):
    """Injected equivalents of original DriveRecord Check/Execute/Cancel exports."""

    def check(
        self, root_path: str, *, deadline: float, cancelled: Callable[[], bool]
    ) -> int: ...
    def execute(
        self,
        notification_handle: int,
        root_path: str,
        *,
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> int: ...
    def cancel(self, *, deadline: float, cancelled: Callable[[], bool]) -> int: ...


class OnboardRecorderService:
    """Recovered DiagTool USB/switch lifecycle, without inventing remote opcodes."""

    def __init__(
        self,
        backend: RecorderEntrypoints,
        root_path: str,
        *,
        notification_handle: int = 0,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not root_path or "\0" in root_path:
            raise RecorderError("Invalid VIM application root path")
        self.backend = backend
        self.root_path = root_path
        self.notification_handle = _uint(notification_handle)
        self.clock = clock
        self.usb_known = False
        self.usb_connected = False
        self.switch_enabled = False
        self.active = False
        self.closed = False
        self.last_native_result = 0
        self.fault: str | None = None

    def update(
        self,
        *,
        usb_connected: bool | None = None,
        switch_enabled: bool | None = None,
        timeout: float = 30.0,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> dict[str, object]:
        deadline = self._deadline(timeout)
        if self.closed:
            raise RecorderError("Onboard recorder service is closed")
        if usb_connected is not None:
            if type(usb_connected) is not bool:
                raise RecorderError("USB event must be boolean")
            self.usb_known = True
            self.usb_connected = usb_connected
        if switch_enabled is not None:
            if type(switch_enabled) is not bool:
                raise RecorderError("Switch event must be boolean")
            self.switch_enabled = switch_enabled
        permitted = self.switch_enabled and not (self.usb_known and self.usb_connected)
        try:
            if self.active and not permitted:
                self.last_native_result = self._call("cancel", (), deadline, cancelled)
                if self.last_native_result:
                    raise RecorderError(
                        f"Native recorder Cancel failed: {self.last_native_result:#x}"
                    )
                self.active = False
            elif not self.active and permitted:
                self.last_native_result = self._call(
                    "check", (self.root_path,), deadline, cancelled
                )
                if self.last_native_result == 0:
                    self.last_native_result = self._call(
                        "execute",
                        (self.notification_handle, self.root_path),
                        deadline,
                        cancelled,
                    )
                    if self.last_native_result:
                        raise RecorderError(
                            f"Native recorder Execute failed: {self.last_native_result:#x}"
                        )
                    self.active = True
        except (Exception, KeyboardInterrupt) as exc:
            self.fault = str(exc)
            raise
        self.fault = None
        return self.report()

    def _deadline(self, timeout: float) -> float:
        if not math.isfinite(timeout) or timeout <= 0:
            raise RecorderError("Timeout must be finite and positive")
        return _recorder_deadline(self.clock, timeout)

    def _call(
        self,
        operation: str,
        args: tuple[object, ...],
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> int:
        if cancelled():
            raise RecorderCancelled("Recorder service operation cancelled")
        if _clock_now(self.clock) >= deadline:
            raise TimeoutError("Recorder service deadline exceeded")
        try:
            result = _uint(
                getattr(self.backend, operation)(
                    *args, deadline=deadline, cancelled=cancelled
                )
            )
            if result == 0 and operation in {"execute", "cancel"}:
                self.active = operation == "execute"
        except (Exception, KeyboardInterrupt) as exc:
            if cancelled():
                raise RecorderCancelled("Recorder service operation cancelled") from exc
            if _clock_now(self.clock, cause=exc) >= deadline:
                raise TimeoutError("Recorder service deadline exceeded") from exc
            raise
        if cancelled():
            raise RecorderCancelled("Recorder service operation cancelled")
        if _clock_now(self.clock) >= deadline:
            raise TimeoutError("Recorder service deadline exceeded")
        return result

    def shutdown(
        self, *, timeout: float = 30.0, cancelled: Callable[[], bool] = lambda: False
    ) -> None:
        deadline = self._deadline(timeout)
        if self.closed:
            return
        try:
            if self.active:
                self.last_native_result = self._call("cancel", (), deadline, cancelled)
                if self.last_native_result:
                    raise RecorderError(
                        f"Native recorder Cancel failed: {self.last_native_result:#x}"
                    )
                self.active = False
        except (Exception, KeyboardInterrupt) as exc:
            self.fault = str(exc)
            raise
        self.closed = True

    def report(self) -> dict[str, object]:
        return {
            "active": self.active,
            "closed": self.closed,
            "usb_known": self.usb_known,
            "usb_connected": self.usb_connected,
            "switch_enabled": self.switch_enabled,
            "native_result": self.last_native_result,
            "fault": self.fault,
            "provenance": "DiagTool native_1146c/1153c/1158c; injected entrypoints",
            "physical": "PHYSICAL_UNCONFIRMED",
        }


@dataclass(frozen=True)
class NativeRecorderCapture:
    trigger_timestamp_ms: int
    packets: tuple[NativeMonitorPacket, ...]
    ring_images: tuple[bytes, bytes] | None = None

    def packet_bytes(self) -> bytes:
        """Native ring packet grammar; this is not a synthetic JSON record file."""
        if not isinstance(self.packets, tuple) or len(self.packets) > 100_000:
            raise RecorderError("Native capture packet budget exceeded")
        if sum(4 + len(packet.payload) for packet in self.packets) > MAX_RECORDER_BYTES:
            raise RecorderError("Native capture byte budget exceeded")
        return b"".join(
            struct.pack("<I", packet.timestamp_ms) + packet.payload
            for packet in self.packets
        )

    def monitor_buffer(
        self,
        settings: NativeMonitorBuffer,
        metadata: MonitorBuffer,
        *,
        phase: int,
        block_packets: int,
        standard_values: tuple[tuple[int, int], ...] = (),
    ) -> MonitorBuffer:
        """Build native DM subbuffers while retaining explicit caller metadata.

        DatMonCommon constructors establish frame3/rev0, signal-table1/rev0,
        signal-item4/rev0 and ring1/rev0. Metadata is supplied separately because
        DRS does not contain every CDmMonBuffInfo field. Ring image is normalized.
        """
        if phase != settings.phase or block_packets != settings.block_packets:
            raise RecorderError(
                "DM export phase/block packets must match native DRS settings"
            )
        frames = decode_command(settings.frame_table)["frames"]
        signals = decode_command(settings.signal_table)["signals"]
        assert isinstance(frames, tuple) and isinstance(signals, tuple)
        reader = NativeMonitorPacketReader(frames, phase=phase)
        image = self.packet_bytes()
        reader.feed(image)
        reader.finish()
        indexes, lengths = [0] * 256, [0] * 256
        for position, (index, length) in enumerate(frames):
            indexes[position], lengths[index] = index, length
        frame_data = struct.pack(
            "<HHI256H256HI", 3, 0, len(frames), *indexes, *lengths, len(standard_values)
        )
        frame_data += b"".join(
            struct.pack("<II", _uint(pid), _uint(value))
            for pid, value in standard_values
        )
        encoded = []
        for signal in signals:
            if not isinstance(signal, NativeMonitorSignal):
                raise RecorderError("Invalid native monitor signal")
            divisor, multiplier, offset = signal.scaling_words
            item = SignalItem(
                version=4,
                revision=0,
                pid=signal.identity_words[0],
                frame_index=signal.identity_words[1],
                start_bit=signal.identity_words[2],
                end_bit=signal.identity_words[3],
                name=signal.strings[0].data,
                short_name=signal.strings[1].data,
                unit=signal.strings[2].data,
                selector=signal.selector_words[0],
                unit_id=signal.selector_words[1],
                sign_mode=signal.sign_mode,
                multiplier=i32(multiplier),
                divisor=i32(divisor),
                offset=i32(offset),
                precision=signal.precision,
                minimum_raw=signal.raw_bounds[0],
                maximum_raw=signal.raw_bounds[1],
                patterns=tuple(
                    (pattern.value, pattern.label.data, *pattern.bounds)
                    for pattern in signal.display_items
                ),
                extended=signal.trailing_words,
            )
            body = encode_signal_item(item)
            encoded.append(struct.pack("<I", len(body)) + body)
        signal_data = struct.pack("<HHI", 1, 0, len(encoded)) + b"".join(encoded)
        if self.ring_images is not None:
            if (
                not isinstance(self.ring_images, tuple)
                or len(self.ring_images) != 2
                or any(
                    not isinstance(value, bytes) or len(value) > MAX_RECORDER_BYTES
                    for value in self.ring_images
                )
            ):
                raise RecorderError("Invalid bounded native ring images")
            if settings.serial_mode not in (0, 1):
                raise UnsupportedRecorderOperation(
                    "Unsupported native ring serial mode"
                )
            ring_data = self.ring_images[settings.serial_mode]
            try:
                ring = decode_ring_buffer(ring_data)
            except SnapshotError as exc:
                raise RecorderError(str(exc)) from exc
            if (ring["phase"], ring["block_packets"], ring["capacity"]) != (
                phase,
                block_packets,
                settings.allocation_size,
            ):
                raise RecorderError("Captured native ring settings do not match DRS")
        else:
            size = len(image)
            capacity = settings.allocation_size
            if not 0 < capacity <= MAX_RECORDER_BYTES - 38 or size > capacity:
                raise RecorderError("Native capture exceeds configured ring capacity")
            if settings.serial_mode not in (0, 1):
                raise UnsupportedRecorderOperation(
                    "Unsupported native ring serial mode"
                )
            # The selected window is normalized to offset zero. Unused allocation
            # bytes are authored zeroes, never uninitialized native memory.
            if settings.serial_mode == 0:
                image += bytes(capacity - size)
            ring_data = (
                struct.pack(
                    "<HHIH7I",
                    1,
                    0,
                    phase,
                    _uint(block_packets, 16),
                    capacity,
                    capacity - size,
                    0,
                    0,
                    size,
                    size,
                    len(image),
                )
                + image
            )
        result = replace(
            metadata,
            frame_table=frame_data,
            signal_table=signal_data,
            ring_buffer=ring_data,
            marker=_uint(self.trigger_timestamp_ms),
        )
        try:
            monitor_packets(result)
        except SnapshotError as exc:
            raise RecorderError(str(exc)) from exc
        return result

    def dm_bytes(
        self,
        settings: NativeMonitorBuffer,
        metadata: MonitorBuffer,
        system_information: dict,
        *,
        phase: int,
        block_packets: int,
        standard_values: tuple[tuple[int, int], ...] = (),
    ) -> bytes:
        """Native Save105e90: CDmFileWriter(version1,revision0), system then buffer."""
        buffer = self.monitor_buffer(
            settings,
            metadata,
            phase=phase,
            block_packets=block_packets,
            standard_values=standard_values,
        )
        try:
            return dump_snapshot(
                SnapshotTableFile(
                    DM_MAGIC,
                    1,
                    0,
                    (
                        SnapshotTable(
                            0x8100, encode_system_information(system_information)
                        ),
                        SnapshotTable(0x8101, encode_monitor_buffer(buffer)),
                    ),
                )
            )
        except SnapshotError as exc:
            raise RecorderError(str(exc)) from exc


def _recording_export_budget(
    monitor: NativeMonitorBuffer,
    metadata: MonitorBuffer,
    system_information: dict,
    *,
    phase: int,
    block_packets: int,
) -> int:
    # Both serial modes fit at most one allocation; normalize the empty probe to
    # serial1 so preflight never allocates a full spare native ring image.
    empty = NativeRecorderCapture(0, ()).dm_bytes(
        replace(monitor, value_after_count=1),
        metadata,
        system_information,
        phase=phase,
        block_packets=block_packets,
    )
    maximum = len(empty) + monitor.allocation_size
    if maximum > MAX_RECORDER_BYTES:
        raise RecorderError("Native recording exceeds bounded DM file byte budget")
    return maximum


class NativeMonitorRecorder:
    """Executable native DMCI acquisition with injected byte exchange and trigger input.

    phase and interface ID must come from the resolved protocol provider. This
    class neither guesses an interface from a generic adapter nor opens hardware.
    """

    def __init__(
        self,
        settings: DrsFile,
        client: NativeVimClient,
        *,
        interface_id: int,
        phase: int,
        protocol: NativeDrsExecutor | None = None,
        recorder_state: NativeRecorderState | None = None,
    ):
        self.protocol = protocol
        self._protocol_prepared = False
        self.recorder_state = (
            protocol.recorder_state
            if protocol is not None
            else recorder_state or NativeRecorderState()
        )
        self.recorder_state.encode()
        self.settings, self.client = settings, client
        self.interface_id = _uint(interface_id)
        decoded = {
            table.table_id: decode_command(table) for table in reversed(settings.tables)
        }
        monitor = decoded.get(2, {}).get("monitor")
        info = decoded.get(5, {}).get("trigger")
        parameters = decoded.get(6, {}).get("trigger")
        if (
            not isinstance(monitor, NativeMonitorBuffer)
            or not isinstance(info, NativeTriggerInfo)
            or not isinstance(parameters, NativeTriggerParameters)
        ):
            raise RecorderError(
                "Native recorder requires monitor2, trigger5 and parameter6 records"
            )
        self.monitor, self.info, self.parameters = monitor, info, parameters
        if phase != monitor.phase:
            raise RecorderError(
                "Monitor phase must match the native DRS SetPhase field"
            )
        if monitor.block_packets not in (1, 2):
            raise UnsupportedRecorderOperation("Native block packet count must be1/2")
        if monitor.serial_mode not in (0, 1):
            raise UnsupportedRecorderOperation("Unsupported native ring serial mode")
        if not 0 < monitor.allocation_size <= MAX_RECORDER_BYTES - 38:
            raise RecorderError(
                "Native DRS ring allocation exceeds supported byte budget"
            )
        frame_values = decode_command(monitor.frame_table)["frames"]
        assert isinstance(frame_values, tuple)
        self.reader = NativeMonitorPacketReader(frame_values, phase=phase)
        if self.reader.packet_size > monitor.allocation_size:
            raise RecorderError(
                "Native monitor packet exceeds its configured ring capacity"
            )
        signal_values = decode_command(monitor.signal_table)["signals"]
        assert isinstance(signal_values, tuple)
        self.signals = tuple(
            signal
            for signal in signal_values
            if isinstance(signal, NativeMonitorSignal)
        )
        if phase == 1 and monitor.block_packets == 2:
            if len(frame_values) < 2 or frame_values[0][1] != frame_values[1][1]:
                raise UnsupportedRecorderOperation(
                    "Native phase1/block2 requires two equal-width frames"
                )
            # DriveRecord05914 SetPacket(slot0) on every ReadPacket. Only the
            # first frame has a defined in-packet extent; other fields overread.
            for signal in self.signals:
                self.reader.raw_value(
                    NativeMonitorPacket(0, bytes(self.reader.packet_size - 4)), signal
                )
        self._condition_signals: list[NativeMonitorSignal] = []
        for condition in parameters.conditions:
            signal = next(
                (
                    signal
                    for signal in self.signals
                    if signal.identity_words[0] == condition.pid_id
                ),
                None,
            )
            if signal is None:
                raise RecorderError(
                    "Native trigger PID is missing from monitor signals"
                )
            # Reject unsupported extraction/conversion before start group11.
            self.reader.raw_value(
                NativeMonitorPacket(0, bytes(self.reader.packet_size - 4)), signal
            )
            convert_native_trigger_value(0, signal, condition)
            self._condition_signals.append(signal)
        # Reject allocations that cannot fit even the minimum complete DM
        # envelope with these actual frame/signal records. Real caller metadata
        # is reserved exactly by NativeRecorderSeries before acquisition.
        _recording_export_budget(
            monitor,
            MonitorBuffer(b"", bytes(16), b"", b"", b"", b"", 0, (), (), b"", ()),
            {
                "identifier": 0,
                "strings": [{"core": [1, 0], "data_hex": ""}] * 2,
                "value_raw": 0,
            },
            phase=phase,
            block_packets=monitor.block_packets,
        )
        self.state = "idle"
        self.last_error: str | None = None

    def _group(
        self,
        group_id: int,
        deadline: float,
        cancelled: Callable[[], bool],
        *,
        best_effort: bool = False,
    ) -> None:
        group = next(
            (table for table in self.settings.tables if table.table_id == group_id),
            None,
        )
        if group is None:
            raise RecorderError(
                f"Required native recorder group {group_id:#x} is absent"
            )
        children = decode_command(group).get("children", ())
        if not isinstance(children, tuple):
            raise RecorderError("Native monitor group has invalid child tables")
        commands = []
        for child in children:
            if not isinstance(child, DrsTable):
                raise RecorderError("Native monitor child must be a table")
            command = decode_command(child).get("dmci")
            if not isinstance(command, NativeDmciCommand):
                raise UnsupportedRecorderOperation(
                    "Native monitor group requires DMCI records"
                )
            commands.append(command)
        failure: BaseException | None = None
        for command in commands:
            try:
                remaining = deadline - _clock_now(self.client.clock)
                if remaining <= 0:
                    raise TimeoutError("Native recorder group deadline exceeded")
                self.client.dmci(command, timeout=remaining, cancelled=cancelled)
            except BaseException as exc:
                if not best_effort:
                    raise
                if failure is None:
                    failure = exc
                else:
                    failure.add_note(
                        f"Native cleanup command {command.command_id:#x} also failed: {exc}"
                    )
        if failure is not None:
            raise failure

    def capture(
        self,
        *,
        timeout: float = 30.0,
        max_polls: int = 100_000,
        cancelled: Callable[[], bool] = lambda: False,
        trigger_event: Callable[[], int | None] = lambda: None,
    ) -> NativeRecorderCapture:
        with _exclusive(self.client._capture_lock, "Native monitor client"):
            if self.protocol is not None:
                with _exclusive(self.protocol._execution_lock, "Native DRS executor"):
                    return self._capture(
                        timeout=timeout,
                        max_polls=max_polls,
                        cancelled=cancelled,
                        trigger_event=trigger_event,
                    )
            return self._capture(
                timeout=timeout,
                max_polls=max_polls,
                cancelled=cancelled,
                trigger_event=trigger_event,
            )

    def _capture(
        self,
        *,
        timeout: float = 30.0,
        max_polls: int = 100_000,
        cancelled: Callable[[], bool] = lambda: False,
        trigger_event: Callable[[], int | None] = lambda: None,
    ) -> NativeRecorderCapture:
        if self.state != "idle":
            raise RecorderError(
                "Native monitor recorder must be recreated after a capture"
            )
        if (
            not math.isfinite(timeout)
            or timeout <= 0
            or type(max_polls) is not int
            or max_polls < 1
        ):
            raise RecorderError("Invalid native recorder acquisition bounds")
        if self.info.trigger_type != 0 and not self.parameters.conditions:
            raise RecorderError("Native parameter trigger requires conditions")
        deadline = _recorder_deadline(self.client.clock, timeout)
        if self.protocol is not None:
            self.recorder_state = self.protocol.recorder_state
        comparisons = []
        for condition, signal in zip(
            self.parameters.conditions, self._condition_signals, strict=True
        ):
            sliding = self.info.trigger_type in (1, 7)
            fresh = sliding and self.recorder_state.reference_raw == 0xFFFFFFFF
            reference = (
                0
                if fresh
                else convert_native_trigger_value(
                    self.recorder_state.reference_raw
                    if sliding
                    else condition.parameter_value,
                    signal,
                    condition,
                )
            )
            comparisons.append(
                NativeTriggerComparison(
                    condition.condition_type, reference, sliding, 0 if fresh else 2
                )
            )
        window = NativeTriggerWindow(self.info)
        try:
            ring = NativeRecorderRing(
                self.monitor.allocation_size,
                self.reader.packet_size,
                self.monitor.block_packets,
                phase=self.reader.phase,
                max_packets=self.reader.max_packets,
                native_source="sh3",
            )
        except RecorderBufferError as exc:
            raise RecorderError(str(exc)) from exc
        trigger_reference_raw: int | None = None
        manual_tick: int | None = None
        manual_previous = 0
        primary: BaseException | None = None
        attempted = False
        self.state = "starting"
        try:
            # Fully validate both lifecycle groups before the first native action.
            for group_id in (0x11, 0x12):
                group = next(
                    (
                        table
                        for table in self.settings.tables
                        if table.table_id == group_id
                    ),
                    None,
                )
                if group is None:
                    raise RecorderError("Native monitor start/stop groups are required")
                children = decode_command(group).get("children", ())
                if not isinstance(children, tuple) or any(
                    not isinstance(child, DrsTable)
                    or not isinstance(
                        decode_command(child).get("dmci"), NativeDmciCommand
                    )
                    for child in children
                ):
                    raise RecorderError(
                        "Native monitor lifecycle group contains unsupported commands"
                    )
            protocol_groups = {table.table_id for table in self.settings.tables}
            if not self._protocol_prepared and (
                0x27 in protocol_groups
                or (self.info.trigger_type == 7 and 0x21 in protocol_groups)
            ):
                if self.protocol is None or self.protocol.settings != self.settings:
                    raise UnsupportedRecorderOperation(
                        "Native recorder protocol groups require the matching NativeDrsExecutor"
                    )
                for group_id in (0x27, 0x21, 0x22, 0x23, 0x24):
                    self.protocol.preflight(group_id)
                if 0x27 in protocol_groups:
                    self.protocol._execute_group(
                        0x27,
                        timeout=deadline - _clock_now(self.client.clock),
                        cancelled=cancelled,
                    )
                    self.protocol._close()
                if self.info.trigger_type == 7:
                    self.protocol._check_mode(
                        timeout=deadline - _clock_now(self.client.clock),
                        cancelled=cancelled,
                    )
                    self.recorder_state = self.protocol.recorder_state
                self._protocol_prepared = True
            attempted = True
            self._group(0x11, deadline, cancelled)
            self.state = "recording"
            for _ in range(max_polls):
                if cancelled():
                    raise RecorderCancelled("Native recorder acquisition cancelled")
                remaining = deadline - _clock_now(self.client.clock)
                if remaining <= 0:
                    raise TimeoutError("Native recorder acquisition deadline exceeded")
                if self.info.trigger_type == 0 and manual_tick is None:
                    event = trigger_event()
                    if event is not None:
                        manual_tick = _uint(event)
                reply = self.client.get_monitor_data(
                    (self.interface_id,), timeout=remaining, cancelled=cancelled
                )
                for interface, buffer in reply.interfaces.items:
                    if interface != self.interface_id:
                        raise RecorderError(
                            "Native monitor reply names an unrequested interface"
                        )
                    if not isinstance(buffer, NativeCoreBuffer):
                        raise RecorderError("Malformed native interface monitor buffer")
                    batch = self.reader.feed(buffer.data)
                    # The producer fills the available snapshot before the
                    # consumer drains it; native05c74 inspects its last packet.
                    for packet in batch:
                        ring.append(packet.timestamp_ms, packet.payload, consume=False)
                    for packet_index, packet in enumerate(batch):
                        ring.read(self.reader.packet_size)
                        already_triggered = window.trigger_timestamp is not None
                        if (
                            self.info.trigger_type == 0
                            and manual_tick is not None
                            and window.trigger_timestamp is None
                        ):
                            # Native05914 waits strictly past the button tick,
                            # then uses the preceding consumed packet if nonzero.
                            if manual_tick < packet.timestamp_ms:
                                window.trigger(manual_previous or packet.timestamp_ms)
                            else:
                                manual_previous = packet.timestamp_ms
                        if (
                            window.trigger_timestamp is None
                            and self.info.trigger_type != 0
                        ):
                            raw_values = tuple(
                                self.reader.raw_value(packet, signal)
                                for signal in self._condition_signals
                            )
                            values = tuple(
                                convert_native_trigger_value(raw, signal, condition)
                                for raw, condition, signal in zip(
                                    raw_values,
                                    self.parameters.conditions,
                                    self._condition_signals,
                                    strict=True,
                                )
                            )
                            if evaluate_native_comparisons(
                                tuple(comparisons),
                                values,
                                self.parameters.parameter_condition,
                            ):
                                window.trigger(packet.timestamp_ms)
                                if self.info.trigger_type in (1, 7):
                                    trigger_reference_raw = raw_values[-1]
                        if (
                            already_triggered
                            and window.trigger_timestamp is not None
                            and packet_index == len(batch) - 1
                        ):
                            right = (
                                window.trigger_timestamp + window.post_ms
                            ) & 0xFFFFFFFF
                            if right <= packet.timestamp_ms:
                                left = max(0, window.trigger_timestamp - window.pre_ms)
                                selected = ring.select(left, right)
                                reader = NativeMonitorPacketReader(
                                    self.reader.frames, phase=self.reader.phase
                                )
                                packets = reader.feed(selected)
                                reader.finish()
                                images = (ring.serialize(0), ring.serialize(1))
                                self.state = "complete"
                                return NativeRecorderCapture(
                                    window.trigger_timestamp, packets, images
                                )
                    if (
                        self.info.trigger_type == 0
                        and manual_tick is not None
                        and window.trigger_timestamp is None
                        and batch
                    ):
                        # Native05914 consumes one GetPacketCount snapshot. If
                        # none crosses the button tick it returns the last time.
                        window.trigger(batch[-1].timestamp_ms)
            raise RecorderError("Native recorder acquisition poll budget exceeded")
        except BaseException as exc:
            primary = (
                RecorderError(str(exc)) if isinstance(exc, RecorderBufferError) else exc
            )
            self.last_error = str(primary)
            self.state = (
                "cancelled" if isinstance(primary, RecorderCancelled) else "fault"
            )
            if primary is not exc:
                raise primary from exc
            raise
        finally:
            if attempted:
                try:
                    with _cleanup_clock_scope(self.client.clock):
                        self._group(
                            0x12,
                            _recorder_deadline(self.client.clock, 2.0),
                            lambda: False,
                            best_effort=True,
                        )
                except BaseException as exc:
                    self.state = "fault" if primary is None else self.state
                    if primary is None:
                        self.last_error = str(exc)
                        raise
                    primary.add_note(f"Native monitor stop also failed: {exc}")
                    for note in getattr(exc, "__notes__", ()):
                        primary.add_note(note)
                if primary is None and trigger_reference_raw is not None:
                    self.recorder_state = replace(
                        self.protocol.recorder_state
                        if self.protocol is not None
                        else self.recorder_state,
                        reference_raw=trigger_reference_raw,
                    )
                    if self.protocol is not None:
                        self.protocol.recorder_state = self.recorder_state


@dataclass(frozen=True)
class NativeRecorderState:
    """Native temp.dat: persisted raw trigger reference then Check Mode DWORD (DriveRecord1161e4)."""

    reference_raw: int = 0xFFFFFFFF
    check_mode: int = 0

    def encode(self) -> bytes:
        return struct.pack("<II", _uint(self.reference_raw), _uint(self.check_mode))

    @classmethod
    def parse(cls, data: bytes) -> NativeRecorderState:
        reader = _Reader(data)
        reference, mode = reader.unpack("II")
        reader.end()
        return cls(reference, mode)


class NativeDrsError(RecorderError):
    def __init__(self, code: int):
        self.code = code
        super().__init__(f"Native DRS error {code:#010x}")


class NativeDrsExecutor:
    """Execute native J2534 command groups against an injected primitive provider.

    The provider implements the named J2534 primitives, not DRS branching. Reads
    return one NativeMessage; connect returns the actual unsigned channel ID.
    Native DriveRecord 0x101628/0x1026cc owns this channel and skips RxStatus&31.
    """

    _COMMANDS = frozenset((0x200, 0x201, 0x202, 0x203, 0x206, 0x211, 0x213, 0x214))

    def __init__(
        self,
        settings: DrsFile,
        backend: RecorderBackend,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_reads: int = 100_000,
        recorder_state: NativeRecorderState | None = None,
    ):
        self.recorder_state = recorder_state or NativeRecorderState()
        self.recorder_state.encode()
        if (
            isinstance(max_reads, bool)
            or not isinstance(max_reads, int)
            or max_reads < 1
        ):
            raise RecorderError("Read budget must be a positive integer")
        self.settings, self.backend, self.clock = settings, backend, clock
        self.max_reads = max_reads
        self._execution_lock = Lock()
        self.channel: int | None = None
        self.state = "idle"

    def _check(self, deadline: float, cancelled: Callable[[], bool]) -> None:
        if cancelled():
            raise RecorderCancelled("Native DRS execution cancelled")
        if _clock_now(self.clock) >= deadline:
            raise TimeoutError("Native DRS execution deadline exceeded")

    def _call(
        self,
        operation: str,
        fields: Mapping[str, object],
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> object:
        self._check(deadline, cancelled)
        try:
            result = self.backend.invoke(
                operation, fields, deadline=deadline, cancelled=cancelled
            )
            # Own the resource before checking post-I/O cancellation/deadline.
            if operation == "connect":
                if isinstance(result, bool) or not isinstance(result, int):
                    raise RecorderError("Connect provider must return a channel ID")
                self.channel = _uint(result)
            elif operation == "disconnect":
                self.channel = None
        except (Exception, KeyboardInterrupt) as exc:
            try:
                self._check(deadline, cancelled)
            except (RecorderError, TimeoutError) as boundary:
                raise boundary from exc
            raise
        self._check(deadline, cancelled)
        return result

    def preflight(self, group_id: int) -> tuple[DrsTable, ...]:
        if group_id not in (0x21, 0x22, 0x23, 0x24, 0x27):
            raise UnsupportedRecorderOperation("Unsupported native J2534 group")
        groups = [t for t in self.settings.tables if t.table_id == group_id]
        if not groups:
            return ()  # Native 0x901f0105 optional-group result.
        children = decode_command(groups[0]).get("children", ())
        if not isinstance(children, tuple) or any(
            not isinstance(t, DrsTable) or t.table_id not in self._COMMANDS
            for t in children
        ):
            raise UnsupportedRecorderOperation("Unsupported native J2534 group command")
        for child in children:
            if group_id in (0x23, 0x24) and child.table_id not in (0x202, 0x203):
                raise UnsupportedRecorderOperation(
                    "Native change/confirm groups permit only read/write messages"
                )
            decode_command(child)
        return children

    def close(self) -> None:
        with _exclusive(self._execution_lock, "Native DRS executor"):
            self._close()

    def execute_group(
        self,
        group_id: int,
        *,
        timeout: float = 10.0,
        cancelled: Callable[[], bool] = lambda: False,
        mismatch_is_false: bool = False,
    ) -> tuple[object, ...]:
        with _exclusive(self._execution_lock, "Native DRS executor"):
            return self._execute_group(
                group_id,
                timeout=timeout,
                cancelled=cancelled,
                mismatch_is_false=mismatch_is_false,
            )

    def check_mode(
        self,
        *,
        timeout: float = 20.0,
        cancelled: Callable[[], bool] = lambda: False,
        wait: Callable[[float], None] = time.sleep,
    ) -> int:
        with _exclusive(self._execution_lock, "Native DRS executor"):
            return self._check_mode(timeout=timeout, cancelled=cancelled, wait=wait)

    def _close(self) -> None:
        if self.channel is not None:
            with _cleanup_clock_scope(self.clock):
                self._call(
                    "disconnect",
                    {"channel_id": self.channel},
                    _recorder_deadline(self.clock, 2.0),
                    lambda: False,
                )

    def _execute_group(
        self,
        group_id: int,
        *,
        timeout: float = 10.0,
        cancelled: Callable[[], bool] = lambda: False,
        mismatch_is_false: bool = False,
    ) -> tuple[object, ...]:
        if not math.isfinite(timeout) or timeout <= 0:
            raise RecorderError("Timeout must be finite and positive")
        commands = self.preflight(group_id)
        deadline = _recorder_deadline(self.clock, timeout)
        results: list[object] = []
        self.state = "executing"
        try:
            self._check(deadline, cancelled)
            for table in commands:
                fields = decode_command(table)
                if table.table_id == 0x200:
                    if self.channel is not None:
                        raise RecorderError("Native DRS channel already connected")
                else:
                    if self.channel is None:
                        raise RecorderError(
                            "Native DRS command requires a connected channel"
                        )
                    fields["channel_id"] = self.channel
                if table.table_id == 0x203:
                    message = fields["message"]
                    assert isinstance(message, NativeMessage)
                    if not message.data:
                        continue
                if table.table_id == 0x202:
                    expectation = NativeReadExpectation.parse(table.payload)
                    for _ in range(self.max_reads):
                        try:
                            result = self._call(table.name, fields, deadline, cancelled)
                        except NativeDrsError as exc:
                            if mismatch_is_false and exc.code == 9:
                                # Native confirm permits ERR_TIMEOUT and checks an empty read.
                                results.append(False)
                                break
                            raise
                        if not isinstance(result, NativeMessage):
                            raise RecorderError(
                                "Read provider must return NativeMessage"
                            )
                        if result.rx_status & 0x1F:
                            continue
                        matched = expectation.matches(result)
                        if not matched and not mismatch_is_false:
                            raise NativeDrsError(0xA11F0201)
                        results.append(matched if mismatch_is_false else result)
                        if mismatch_is_false and matched:
                            self.state = "idle"
                            return tuple(
                                results
                            )  # Native confirm exits on first matching read.
                        break
                    else:
                        raise RecorderError("Native DRS read budget exceeded")
                else:
                    results.append(self._call(table.name, fields, deadline, cancelled))
            self.state = "idle"
            return tuple(results)
        except BaseException as primary:
            self.state = (
                "cancelled" if isinstance(primary, RecorderCancelled) else "fault"
            )
            try:
                self._close()
            except BaseException as cleanup:  # noqa: BLE001 - preserve the primary failure
                primary.add_note(f"Native DRS disconnect also failed: {cleanup}")
            raise

    def _check_mode(
        self,
        *,
        timeout: float = 20.0,
        cancelled: Callable[[], bool] = lambda: False,
        wait: Callable[[float], None] = time.sleep,
    ) -> int:
        """Native 0x102408: confirm24; at most seven change23/wait/confirm cycles.

        Return0 when initially confirmed,1 when a change was required. A missing
        setup21 returns0. When confirm24 is absent, the original first check uses
        the persisted temp.dat Check Mode DWORD; subsequent checks require24.
        """
        if not math.isfinite(timeout) or timeout <= 0:
            raise RecorderError("Timeout must be finite and positive")
        groups = {t.table_id for t in self.settings.tables}
        for group_id in (0x21, 0x22, 0x23, 0x24):
            self.preflight(group_id)
        if 0x21 not in groups:
            self._check(_recorder_deadline(self.clock, timeout), cancelled)
            self.recorder_state = replace(self.recorder_state, check_mode=0)
            return 0
        deadline = _recorder_deadline(self.clock, timeout)

        def run(group: int, confirm: bool = False) -> tuple[object, ...]:
            self._check(deadline, cancelled)
            return self._execute_group(
                group,
                timeout=deadline - _clock_now(self.clock),
                cancelled=cancelled,
                mismatch_is_false=confirm,
            )

        primary: BaseException | None = None
        try:
            run(0x21)
            confirmed = (
                any(value is True for value in run(0x24, True))
                if 0x24 in groups
                else self.recorder_state.check_mode == 1
            )
            changed = not confirmed
            if not confirmed:
                if 0x23 not in groups:
                    raise NativeDrsError(0x901F0105)
                for _ in range(7):
                    try:
                        run(0x23)
                    except NativeDrsError as exc:
                        if exc.code == 0xA11F0201:
                            raise NativeDrsError(0xA11F0203) from exc
                        raise
                    self._check(deadline, cancelled)
                    try:
                        wait(
                            1.0
                        )  # Original 0x102408 waits1000ms between change/confirm.
                    except (Exception, KeyboardInterrupt) as exc:
                        try:
                            self._check(deadline, cancelled)
                        except (RecorderError, TimeoutError) as boundary:
                            raise boundary from exc
                        raise
                    self._check(deadline, cancelled)
                    if 0x24 not in groups:
                        raise NativeDrsError(0x901F0105)
                    if any(value is True for value in run(0x24, True)):
                        confirmed = True
                        break
            if not confirmed:
                raise NativeDrsError(0xA11F0203)
            run(0x22)
            self.recorder_state = replace(self.recorder_state, check_mode=int(changed))
            return int(changed)
        except BaseException as exc:
            primary = exc
            self.state = "cancelled" if isinstance(exc, RecorderCancelled) else "fault"
            raise
        finally:
            try:
                self._close()
            except BaseException as exc:
                if primary is None:
                    self.state = "fault"
                    raise
                primary.add_note(f"Native check-mode disconnect also failed: {exc}")


class NativeRecordingStorage(Protocol):
    """Injected local-onboard filesystem primitives; never opens a host path itself."""

    def exists(
        self, path: str, *, deadline: float, cancelled: Callable[[], bool]
    ) -> bool: ...
    def free_bytes(
        self, folder: str, *, deadline: float, cancelled: Callable[[], bool]
    ) -> int: ...
    def write(
        self, path: str, data: bytes, *, deadline: float, cancelled: Callable[[], bool]
    ) -> None: ...


class NativeRecorderSeries:
    """Native repeated capture/first-free filename policy with bounded host execution.

    DriveRecord102344 selects name-01.dm..MaxFile,10239c requires at least2MiB
    free. Type4 stops after record_quantity (at least one capture); other native
    types continue until cancellation/storage failure. max_records is an explicit
    host budget so offline callers can request a finite prefix.
    """

    def __init__(
        self,
        recorder: NativeMonitorRecorder,
        storage: NativeRecordingStorage,
        paths: RecorderPaths,
        base_name: str,
        metadata: MonitorBuffer,
        system_information: dict,
        *,
        block_packets: int,
    ):
        if (
            not isinstance(base_name, str)
            or not base_name
            or any(char in base_name for char in "\\/:\0")
            or type(paths.max_file) is not int
            or not 1 <= paths.max_file <= 100_000
        ):
            raise RecorderError("Invalid native recording filename or slot budget")
        _recording_export_budget(
            recorder.monitor,
            metadata,
            system_information,
            phase=recorder.reader.phase,
            block_packets=block_packets,
        )
        self.recorder, self.storage, self.paths = recorder, storage, paths
        self.base_name, self.metadata = base_name, metadata
        self.system_information, self.block_packets = system_information, block_packets
        self.state = "idle"
        self.written: list[str] = []

    def _io(
        self,
        operation: Callable[[], object],
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> object:
        def check() -> None:
            if cancelled():
                raise RecorderCancelled("Native recorder series cancelled")
            if _clock_now(self.recorder.client.clock) >= deadline:
                raise TimeoutError("Native recorder series deadline exceeded")

        check()
        try:
            result = operation()
        except (Exception, KeyboardInterrupt) as exc:
            try:
                check()
            except (RecorderError, TimeoutError) as boundary:
                raise boundary from exc
            raise
        check()
        return result

    def run(
        self,
        *,
        timeout: float = 60.0,
        max_records: int = 1,
        max_polls: int = 100_000,
        cancelled: Callable[[], bool] = lambda: False,
        trigger_event: Callable[[], int | None] = lambda: None,
    ) -> tuple[str, ...]:
        with _exclusive(self.recorder.client._capture_lock, "Native monitor client"):
            if self.recorder.protocol is not None:
                with _exclusive(
                    self.recorder.protocol._execution_lock, "Native DRS executor"
                ):
                    return self._run(
                        timeout=timeout,
                        max_records=max_records,
                        max_polls=max_polls,
                        cancelled=cancelled,
                        trigger_event=trigger_event,
                    )
            return self._run(
                timeout=timeout,
                max_records=max_records,
                max_polls=max_polls,
                cancelled=cancelled,
                trigger_event=trigger_event,
            )

    def _run(
        self,
        *,
        timeout: float = 60.0,
        max_records: int = 1,
        max_polls: int = 100_000,
        cancelled: Callable[[], bool] = lambda: False,
        trigger_event: Callable[[], int | None] = lambda: None,
    ) -> tuple[str, ...]:
        if self.state != "idle":
            raise RecorderError("Native recorder series is one-shot")
        if (
            not math.isfinite(timeout)
            or timeout <= 0
            or type(max_records) is not int
            or not 1 <= max_records <= 100_000
            or type(max_polls) is not int
            or max_polls < 1
        ):
            raise RecorderError("Invalid native recording series bounds")
        count = (
            max(1, self.recorder.parameters.record_quantity)
            if self.recorder.info.trigger_type == 4
            else max_records
        )
        if count > max_records:
            raise RecorderError("Native record quantity exceeds host recording budget")
        deadline = _recorder_deadline(self.recorder.client.clock, timeout)
        self.state = "recording"
        try:
            for index in range(count):
                if index:
                    previous = self.recorder
                    self.recorder = NativeMonitorRecorder(
                        previous.settings,
                        previous.client,
                        interface_id=previous.interface_id,
                        phase=previous.reader.phase,
                        protocol=previous.protocol,
                        recorder_state=previous.recorder_state,
                    )
                    self.recorder._protocol_prepared = previous._protocol_prepared
                path = ""
                for slot in range(1, self.paths.max_file + 1):
                    candidate = (
                        f"{self.paths.output_folder}\\{self.base_name}-{slot:02d}.dm"
                    )
                    exists = self._io(
                        lambda candidate=candidate: self.storage.exists(
                            candidate, deadline=deadline, cancelled=cancelled
                        ),
                        deadline,
                        cancelled,
                    )
                    if type(exists) is not bool:
                        raise RecorderError("Storage exists provider must return bool")
                    if not exists:
                        path = candidate
                        break
                if not path:
                    raise NativeDrsError(0x901F010A)
                free = self._io(
                    lambda: self.storage.free_bytes(
                        self.paths.output_folder, deadline=deadline, cancelled=cancelled
                    ),
                    deadline,
                    cancelled,
                )
                if type(free) is not int or free < 0:
                    raise RecorderError(
                        "Storage free-space provider must return unsigned bytes"
                    )
                if free < 0x200000:
                    raise NativeDrsError(0xA01F010B)
                previous_state = self.recorder.recorder_state
                capture = self.recorder._capture(
                    timeout=deadline - _clock_now(self.recorder.client.clock),
                    max_polls=max_polls,
                    cancelled=cancelled,
                    trigger_event=trigger_event,
                )
                try:
                    data = capture.dm_bytes(
                        self.recorder.monitor,
                        self.metadata,
                        self.system_information,
                        phase=self.recorder.reader.phase,
                        block_packets=self.block_packets,
                    )
                except BaseException:
                    self.recorder.recorder_state = replace(
                        self.recorder.recorder_state,
                        reference_raw=previous_state.reference_raw,
                    )
                    if self.recorder.protocol is not None:
                        self.recorder.protocol.recorder_state = (
                            self.recorder.recorder_state
                        )
                    raise
                saved = False

                def save(path: str = path, data: bytes = data) -> None:
                    nonlocal saved
                    self.storage.write(
                        path, data, deadline=deadline, cancelled=cancelled
                    )
                    # Retain the successful write even if post-I/O cancellation fires.
                    saved = True
                    self.written.append(path)
                    if self.recorder.info.trigger_type in (1, 7):
                        # Native Main persists temp.dat after successful Save.
                        self.storage.write(
                            f"{self.paths.setting_folder}\\temp.dat",
                            self.recorder.recorder_state.encode(),
                            deadline=_recorder_deadline(
                                self.recorder.client.clock, 2.0
                            ),
                            cancelled=lambda: False,
                        )

                try:
                    self._io(save, deadline, cancelled)
                except BaseException:
                    if not saved:
                        # Original persists the reference after successful Save105e90.
                        self.recorder.recorder_state = replace(
                            self.recorder.recorder_state,
                            reference_raw=previous_state.reference_raw,
                        )
                        if self.recorder.protocol is not None:
                            self.recorder.protocol.recorder_state = (
                                self.recorder.recorder_state
                            )
                    raise
            self.state = "complete"
            return tuple(self.written)
        except BaseException as exc:
            self.state = "cancelled" if isinstance(exc, RecorderCancelled) else "fault"
            raise


def build_native_drs(
    selection: NativeVehicleSelection,
    system_information: dict,
    monitor: NativeMonitorBuffer,
    trigger: NativeTriggerInfo,
    parameters: NativeTriggerParameters,
    *,
    setup: tuple[NativeDmciCommand, ...],
    stop: tuple[NativeDmciCommand, ...],
    check_car: tuple[DrsTable, ...] = (),
    diagnostic_setup: tuple[DrsTable, ...] = (),
    diagnostic_end: tuple[DrsTable, ...] = (),
    change_mode: tuple[DrsTable, ...] = (),
    confirm_mode: tuple[DrsTable, ...] = (),
    sessions: tuple[DrsTable, ...] = (),
) -> DrsFile:
    """Assemble selected native plan values in CreateDrsFile_DT writer2/0 order.

    Database/protocol selection is performed by the shared producer. This layer
    owns native metadata/command serializers and never substitutes opaque
    generate/start callbacks. Neutral commands bind through from_neutral().
    """
    if not setup or not stop:
        raise RecorderError("Native DRS plan requires monitor setup and stop commands")
    groups = (
        (0x21, diagnostic_setup),
        (0x22, diagnostic_end),
        (0x23, change_mode),
        (0x24, confirm_mode),
    )
    if trigger.trigger_type != 7 and (
        any(children for _, children in groups) or sessions
    ):
        raise RecorderError("Native Check Mode/session plan requires trigger type7")
    for group_id, children in (*groups, (0x27, check_car)):
        if not isinstance(children, tuple):
            raise RecorderError("Native protocol group must be a tuple")
        for child in children:
            if (
                not isinstance(child, DrsTable)
                or child.table_id not in NativeDrsExecutor._COMMANDS
            ):
                raise RecorderError("Unsupported native protocol plan command")
            if group_id in (0x23, 0x24) and child.table_id not in (0x202, 0x203):
                raise RecorderError(
                    "Native Check Mode plans require read/write commands"
                )
            decode_command(child)
    for session in sessions:
        if not isinstance(session, DrsTable) or session.table_id not in (0x28, 0x29):
            raise RecorderError("Invalid native session metadata table")
        decode_command(session)
    for command in (*setup, *stop):
        if not isinstance(command, NativeDmciCommand):
            raise RecorderError("Native monitor plan command must be typed")
        command.encode()
    NativeTriggerWindow(trigger)
    tables = [
        encode_command(1, {"selection": selection}),
        encode_command(0x8100, {"system": system_information}),
        encode_command(0x11, {"children": tuple(command.table() for command in setup)}),
        encode_command(0x12, {"children": tuple(command.table() for command in stop)}),
        encode_command(2, {"monitor": monitor}),
    ]
    if trigger.trigger_type == 7:
        tables.extend(
            encode_command(group_id, {"children": children})
            for group_id, children in groups
            if children
        )
        tables.extend(sessions)
    tables.extend(
        (
            encode_command(5, {"trigger": trigger}),
            encode_command(6, {"trigger": parameters}),
        )
    )
    if check_car:
        tables.append(encode_command(0x27, {"children": check_car}))
    result = DrsFile(2, 0, tuple(tables))
    DrsFile.parse(result.encode())
    return result


def native_monitor_buffer(
    ecu_id: int,
    signals: tuple[MonitorSignalMetadata, ...],
    frame_sizes: tuple[tuple[int, int], ...],
    selected_ids: tuple[int, ...],
    *,
    phase: int,
    allocation_size: int,
    name: bytes,
    text_encoding: str,
    default_signal_slots: tuple[int, ...] = (),
    unassigned_short_name_slots: tuple[int, ...] = (),
) -> NativeMonitorBuffer:
    """Bind selected native metadata without guessing ANSI encoding or allocation.

    P4 8b60 supplies caller phase and block1; CreateDrs17b0 forces serial1.
    FileManager34b0 writes the selected ECU/category at buffer+468 first.
    Native strings include their terminator. The caller specifies the encoding
    used for the OEM char* language strings; raw short names retain source bytes.
    """
    if (
        not isinstance(signals, tuple)
        or len(signals) > 100_000
        or any(not isinstance(item, MonitorSignalMetadata) for item in signals)
    ):
        raise RecorderError("Typed selected native signal metadata is required")
    if phase not in (0, 1) or type(phase) is not int:
        raise RecorderError("Native monitor phase must be0/1")
    if (
        type(allocation_size) is not int
        or not 0 < allocation_size <= MAX_RECORDER_BYTES
    ):
        raise RecorderError("Native monitor allocation exceeds byte budget")
    if not isinstance(name, bytes) or not isinstance(text_encoding, str):
        raise RecorderError("Native monitor name/encoding must be explicit")

    for slots in (default_signal_slots, unassigned_short_name_slots):
        if (
            not isinstance(slots, tuple)
            or len(slots) > len(signals)
            or any(
                type(index) is not int or not 0 <= index < len(signals)
                for index in slots
            )
            or len(set(slots)) != len(slots)
        ):
            raise RecorderError("Invalid constructor-default signal slots")
    if any(signals[index].short_name != b"" for index in unassigned_short_name_slots):
        raise RecorderError("Unassigned short-name slot has assigned bytes")
    short_slots = frozenset(unassigned_short_name_slots)
    default = MonitorSignalMetadata(
        0, 0, 0, 0, "", b"", "", 0, 0, 0, 1, 1, 0, 0, 1, 0, (), (0, 1, 0)
    )
    if any(signals[index] != default for index in default_signal_slots):
        raise RecorderError("Constructor-default signal slot has assigned metadata")
    default_slots = frozenset(default_signal_slots)

    def text(value: str) -> NativeCoreString:
        try:
            data = (value.split("\0", 1)[0] + "\0").encode(text_encoding)
        except (LookupError, UnicodeError) as exc:
            raise RecorderError("Native language string encoding failed") from exc
        return NativeCoreString((1, 0), data)

    native_signals = tuple(
        NativeMonitorSignal(
            (item.pid, item.frame_index, item.start_bit, item.end_bit),
            (NativeCoreString((1, 0), b""),) * 3
            if index in default_slots
            else (
                text(item.name),
                NativeCoreString(
                    (1, 0), b"" if index in short_slots else item.short_name + b"\0"
                ),
                text(item.unit),
            ),
            (item.selector, item.unit_id),
            item.sign_mode,
            (item.divisor, item.multiplier, item.offset),
            item.precision,
            (item.minimum_raw, item.maximum_raw),
            (1, 0),
            tuple(
                NativeDisplayItem((2, 0), identity, text(label), (match, high), 0)
                for identity, label, match, high in item.patterns
            ),
            item.extended,
        )
        for index, item in enumerate(signals)
    )
    monitor = NativeMonitorBuffer(
        _uint(ecu_id),
        phase,
        1,
        1,
        allocation_size,
        encode_command(3, {"frames": frame_sizes}),
        encode_command(4, {"signals": native_signals}),
        NativeCoreString((1, 0), name),
        (1, 0),
        tuple((1, 0, identity) for identity in selected_ids),
    )
    monitor.encode()
    return monitor


def native_p4_monitor_buffer(
    plan: SelectedP4Monitor,
    *,
    phase: int,
    allocation_size: int,
    name: bytes,
    text_encoding: str,
) -> NativeMonitorBuffer:
    """Compatibility wrapper for the concrete selected P4 plan."""
    if not isinstance(plan, SelectedP4Monitor) or not plan.commands.setup:
        raise RecorderError("Selected native P4 monitor plan is required")
    setup = next(
        (
            command
            for command in plan.commands.setup
            if command.command_id in (0x109, 0x10A, 0x10B, 0x119, 0x11C)
        ),
        None,
    )
    if setup is None or not setup.values or type(setup.values[0]) is not int:
        raise RecorderError("Selected monitor setup must retain its native ECU ID")
    return native_monitor_buffer(
        setup.values[0],
        plan.signals,
        plan.frame_sizes,
        plan.definitions.selected_ids,
        phase=phase,
        allocation_size=allocation_size,
        name=name,
        text_encoding=text_encoding,
    )


@dataclass(frozen=True)
class NativeSelectedModeFrame:
    """Selected GetFrm[Conf]CheckMode output before protocol header construction."""

    request: bytes
    receive_mask: bytes
    receive_check: bytes
    settings_words: tuple[int, int]
    source: SelectedFrame


@dataclass(frozen=True)
class NativeSelectedModeFrames:
    change: NativeSelectedModeFrame
    confirm: tuple[NativeSelectedModeFrame, ...]


def selected_check_mode_frames(
    profile: ProtocolProfile, *, level: int = 1
) -> NativeSelectedModeFrames:
    """Execute original selected function3/4 and5 frame-list producers.

    CreateDrs30f0 selects level1. This resolves actual management DB joins;
    protocol-specific GetCommFrame headers are a separate concrete producer.
    CommandCommon6a930 binds request/+30, mask/+44 and check/+6c. Settings
    DWORD0/4 become CCommFrameData+18/+1c through6ab90.
    """
    if type(level) is not int or level not in (0, 1):
        raise NativeDrsError(0xC0040C01)
    changes = profile.frame_records(3 if level else 4)
    if len(changes) != 1:
        raise NativeDrsError(0xC0040102)
    confirmations = profile.frame_records(5)

    def frame(
        selected: SelectedFrame, *, confirmation: bool
    ) -> NativeSelectedModeFrame:
        if len(selected.settings_record) < 8:
            raise RecorderError("Truncated selected native communication settings")
        first, second = struct.unpack_from("<II", selected.settings_record)
        return NativeSelectedModeFrame(
            selected.frame.request,
            selected.frame.receive_mask if confirmation else b"\xff",
            selected.frame.receive_mask
            if confirmation
            else selected.frame.receive_check,
            (first, second),
            selected,
        )

    return NativeSelectedModeFrames(
        frame(changes[0], confirmation=False),
        tuple(frame(selected, confirmation=True) for selected in confirmations),
    )


def native_mode_exchange_tables(
    frame: NativeSelectedModeFrame, send: NativeMessage
) -> tuple[DrsTable, DrsTable]:
    """CreateDrs1e30's concrete write/read pair after native GetCommFrame.

    The native producer derives header length as wire-size minus selected
    request-size and prefixes that many zero bytes to both receive arrays.
    Initial read state copies only send protocol/RxStatus/TxFlags; other header
    DWORDs are zero, rather than copied from the outgoing data size.
    """
    send.encode()
    header_length = len(send.data) - len(frame.request)
    if header_length < 0:
        raise RecorderError("Native protocol message is shorter than selected request")
    prefix = bytes(header_length)
    expectation = NativeReadExpectation(
        frame.settings_words[1],
        (send.protocol_id, send.rx_status, send.tx_flags, 0, 0, 0),
        prefix + frame.receive_mask,
        prefix + frame.receive_check,
    )
    return (
        encode_command(0x203, {"timeout": frame.settings_words[0], "message": send}),
        DrsTable(0x202, expectation.encode()),
    )


def selected_session_tables(
    profile: ProtocolProfile, *, diagnostic_mode: bytes, bus_id: int
) -> tuple[DrsTable, ...]:
    """CreateDrs4310/4710 selected P5 default/extended session records.

    This helper intentionally differs from GetCommFrame's address override:
    session4710 checks only DWORD+8, without requiring diagnostic mode WORD0=1.
    The ordinary fallback is selected ProtInfo WORD+8 for the resolved bus ID.
    """
    if len(profile.category_record) < 73:
        raise RecorderError("Truncated selected native ECU category")
    if profile.category_record[72] & 31 != 20:
        return ()
    if not isinstance(diagnostic_mode, bytes) or len(diagnostic_mode) != 16:
        raise RecorderError("Native diagnostic mode must retain its16-byte structure")
    _uint(bus_id, 16)
    leading = struct.unpack_from("<I", diagnostic_mode, 8)[0]
    if not leading:
        if not bus_id:
            raise NativeDrsError(0xC0040602)
        protocol = profile.protocol_info(bus_id)
        if protocol is None:
            raise NativeDrsError(0xC0050101)
        if len(protocol) < 10:
            raise RecorderError("Truncated selected native protocol metadata")
        leading = struct.unpack_from("<H", protocol, 8)[0]
    tables = []
    for table_id, function in ((0x28, 0xD1), (0x29, 0xD2)):
        frames = profile.frame_records(function)
        if not frames:
            raise NativeDrsError(0xC0040101)
        tables.append(
            encode_command(
                table_id,
                {
                    "value_before_buffer": leading,
                    "core_words": (1, 0),
                    "data": frames[0].frame.request,
                },
            )
        )
    return tuple(tables)


def encode_native_mode21(items: tuple[tuple[int, bytes], ...]) -> bytes:
    """CCmdList<CCmdMode21>: core/count, then byte PID and native buffer.

    Mode21 Read50cc0/Write50cf0 has the same body grammar as ModeA1. Its item
    has no serialized core; its contained CCmdBuffer retains core1/0.
    """
    if not isinstance(items, tuple) or len(items) > 100_000:
        raise RecorderError("Native Mode21 list exceeds item budget")
    if any(
        not isinstance(item, tuple)
        or len(item) != 2
        or type(item[0]) is not int
        or not isinstance(item[1], bytes)
        for item in items
    ):
        raise RecorderError("Native Mode21 item requires byte PID and option bytes")
    return _dmci_encode_value(
        NativeDmciList(
            (1, 0), tuple((pid, NativeCoreBuffer((1, 0), data)) for pid, data in items)
        ),
        "mode_a1",
    )


def _native_empty_read(value: NativeMessage, timeout: int) -> DrsTable:
    return DrsTable(
        0x202,
        NativeReadExpectation(
            timeout,
            (value.protocol_id, value.rx_status, value.tx_flags, 0, 0, 0),
            b"",
            b"",
        ).encode(),
    )


def _native_protocol_setup(
    shared: FramePlan, settings_words: tuple[int, int], bus_id: int
) -> tuple[DrsTable, ...]:
    """Shared original CreateDrs1e30/3180 connect/config/init branch."""
    setup = [
        encode_command(
            0x200,
            {"protocol_id": shared.connect.protocol_id, "flags": shared.connect.flags},
        ),
        encode_command(
            0x211,
            {
                "parameters": tuple(
                    (item.parameter, item.value) for item in shared.configs
                )
            },
        ),
    ]
    if bus_id & 15 in (1, 9, 12):
        setup.append(
            encode_command(
                0x214,
                {
                    "message": NativeMessage.parse(
                        shared.initialization_message.encode()
                    )
                },
            )
        )
    elif bus_id & 15 in (2, 7):
        for item in shared.filters:
            if item.filter_type:
                setup.append(
                    encode_command(
                        0x206,
                        {
                            "filter_type": item.filter_type,
                            "messages": tuple(
                                NativeMessage.parse(value.encode())
                                for value in (
                                    item.mask,
                                    item.pattern,
                                    item.flow_control,
                                )
                            ),
                        },
                    )
                )
        init = NativeMessage.parse(shared.initialization_message.encode())
        setup.extend(
            (
                encode_command(
                    0x203,
                    {"timeout": settings_words[0], "message": init},
                ),
                _native_empty_read(init, settings_words[1]),
            )
        )
    else:
        raise NativeDrsError(0xC0040D01)
    return tuple(setup)


@dataclass(frozen=True)
class NativeCheckModePlan:
    diagnostic_setup: tuple[DrsTable, ...]
    diagnostic_end: tuple[DrsTable, ...]
    change_mode: tuple[DrsTable, ...]
    confirm_mode: tuple[DrsTable, ...]
    sessions: tuple[DrsTable, ...]


def selected_check_mode_plan(
    profile: ProtocolProfile,
    *,
    bus_id: int,
    driver: DriverProperties,
    diagnostic_mode: bytes,
) -> NativeCheckModePlan:
    """Compile CreateDrs1e30 selected frames through actual GetCommFrame packets.

    Group21 owns connect/config/protocol initialization,22 optional function58
    then disconnect,23 change and24 confirmation. The final GetCommFrame call
    supplies shared connect/config/filter/initialization outputs as in native.
    """
    selected = selected_check_mode_frames(profile)

    def build(request: bytes) -> FramePlan:
        try:
            return get_comm_frame(
                profile,
                request,
                bus_id=bus_id,
                driver=driver,
                diagnostic_mode=diagnostic_mode,
            )
        except FrameTransportError as exc:
            raise NativeDrsError(exc.status) from exc

    def message(value: TransportMessage) -> NativeMessage:
        return NativeMessage.parse(value.encode())

    def empty_read(value: NativeMessage, timeout: int) -> DrsTable:
        return DrsTable(
            0x202,
            NativeReadExpectation(
                timeout,
                (value.protocol_id, value.rx_status, value.tx_flags, 0, 0, 0),
                b"",
                b"",
            ).encode(),
        )

    change = build(selected.change.request)
    confirmations = tuple(build(item.request) for item in selected.confirm)
    startup_rows: tuple[SelectedFrame, ...] = ()
    if any(
        word(row, 0) == profile.category and word(row, 2) == 0x58
        for row in correspondence_rows(
            profile.catalog.management, 18, profile.exception_ids
        )
    ):
        startup_rows = profile.frame_records(0x58)
    if len(startup_rows) > 1:
        raise NativeDrsError(0xC0040102)
    startup = build(startup_rows[0].frame.request) if startup_rows else None
    shared = startup or (confirmations[-1] if confirmations else change)
    setup = _native_protocol_setup(shared, selected.change.settings_words, bus_id)
    end = []
    if startup is not None:
        assert startup_rows
        first, second = struct.unpack_from("<II", startup_rows[0].settings_record)
        outgoing = message(startup.send)
        end.extend(
            (
                encode_command(0x203, {"timeout": first, "message": outgoing}),
                empty_read(outgoing, second),
            )
        )
    end.append(encode_command(0x201, {}))
    return NativeCheckModePlan(
        tuple(setup),
        tuple(end),
        native_mode_exchange_tables(selected.change, message(change.send)),
        tuple(
            table
            for frame, plan in zip(selected.confirm, confirmations, strict=True)
            for table in native_mode_exchange_tables(frame, message(plan.send))
        ),
        selected_session_tables(
            profile, diagnostic_mode=diagnostic_mode, bus_id=bus_id
        ),
    )


@dataclass(frozen=True)
class NativeVinCheck:
    request: bytes
    responses: tuple[tuple[bytes, bytes], ...]  # mask, observed pattern
    source: SelectedFrame


@dataclass(frozen=True)
class NativeVinFrames:
    """GetFrmCarInfoVin1400/1b00 observed checks, before protocol packing."""

    initial: tuple[NativeVinCheck, ...]
    checks: tuple[NativeVinCheck, ...]
    settings_words: tuple[int, int]
    ignored_initial_status: int = 0


def selected_car_info_frames(
    profile: ProtocolProfile,
    cache: MonitorSupportCache,
    *,
    bus_id: int,
    category_flags: int = 0,
) -> NativeVinFrames:
    """Selected VIN support/probes through the actual shared native cache seam.

    Native Execute ignores helper1400's status; host cancellation and budget
    exceptions still propagate. Helper1b00 keeps the first successful frame per
    selected function and merges masks when a request already has one response.
    """
    bus_id, category_flags = _uint(bus_id, 8), _uint(category_flags, 8)
    if len(profile.category_record) < 73:
        raise RecorderError("Truncated selected native ECU category")
    if cache.profile is not profile:
        raise RecorderError("VIN cache must belong to the selected profile")
    category_flags = category_flags or profile.category_record[72]
    if not profile.category or not bus_id or not category_flags:
        raise NativeDrsError(0xC0040D02)
    phase = category_flags & 31
    if phase in (3, 5, 7, 9):
        functions = tuple(range(27, 40))
    elif phase in (4, 6, 8, 10):
        functions = (*range(40, 53), 54, 55, 56, 53, 57)
    elif phase == 20:
        functions = ()
    else:
        raise NativeDrsError(0xC0040D01)
    cache.begin_operation()
    timeouts = [0, 0]

    def frames(function: int) -> tuple[SelectedFrame, ...]:
        # Native5e351 maps an absent selected function to C0040101. Other
        # malformed host metadata is not assigned an invented native status.
        try:
            rows = correspondence_rows(
                profile.catalog.management, 18, profile.exception_ids
            )
            if not any(
                word(row, 0) == profile.category and word(row, 2) == function
                for row in rows
            ):
                raise NativeDrsError(0xC0040101)
            return profile.frame_records(function)
        except NativeDrsError:
            raise
        except ToyotaCodecError as exc:
            raise NativeDrsError(exc.code) from exc
        except ValueError as exc:
            raise RecorderError("Malformed selected VIN frame metadata") from exc

    def update(selected: SelectedFrame) -> None:
        if len(selected.settings_record) < 8:
            raise RecorderError("Truncated VIN communication settings")
        first, second = struct.unpack_from("<II", selected.settings_record)
        timeouts[0], timeouts[1] = max(timeouts[0], first), max(timeouts[1], second)

    def bounded(value: bytes) -> bytes:
        if not isinstance(value, bytes) or len(value) > 255:
            raise RecorderError("VIN frame exceeds native255-byte producer area")
        return value

    initial: tuple[NativeVinCheck, ...] = ()
    ignored = 0
    try:
        support = frames(0x85)
        if len(support) != 1:
            raise NativeDrsError(0xC0040102)
        reply = cache.transaction(
            support[0], support[0].frame.request, native_parameter=bus_id
        )
        index = 2 if bus_id & 15 in (2, 8, 10) else 3
        if len(reply) <= index:
            raise NativeDrsError(0xA0040202)
        if reply[index] & 0x40:
            selected = frames(0x86)
            if len(selected) != 1:
                raise NativeDrsError(0xC0040102)
            observed = cache.multi_receive(selected[0], native_parameter=bus_id)
            if observed.status:
                raise NativeDrsError(observed.status)
            if not observed.replies:
                raise NativeDrsError(0xA0040202)
            if len(observed.replies) > 10:
                raise RecorderError("VIN response count exceeds native10-message area")
            responses = tuple(
                (bytes([255]) * len(bounded(value)), value)
                for value in observed.replies
            )
            initial = (
                NativeVinCheck(
                    bounded(selected[0].frame.request), responses, selected[0]
                ),
            )
            update(selected[0])
    except (NativeDrsError, ToyotaCodecError) as exc:
        ignored = exc.code
    checks: list[NativeVinCheck] = []
    for function in functions:
        for selected in frames(function):
            request = bounded(selected.frame.request)
            duplicate = next(
                (
                    i
                    for i, item in enumerate(checks)
                    if item.request == request and len(item.responses) == 1
                ),
                None,
            )
            if duplicate is not None:
                previous = checks[duplicate]
                mask, pattern = previous.responses[0]
                incoming = selected.frame.receive_mask
                size = min(len(mask), len(incoming), len(pattern))
                combined = (
                    bytes(mask[i] | incoming[i] for i in range(size)) + mask[size:]
                )
                checks[duplicate] = replace(previous, responses=((combined, pattern),))
                update(selected)
                break
            try:
                reply = cache.transaction(selected, request, native_parameter=bus_id)
            except ToyotaCodecError:
                continue  # Native1b00 advances to the next selected frame.
            reply = bounded(reply)
            mask = selected.frame.receive_mask
            if not mask:
                raise UnsupportedRecorderOperation(
                    "Native VIN empty-mask lookup dereferences an absent list node"
                )
            # CommandDataLib.GetAt1e610 returns the FIRST element on an
            # out-of-range index into a nonempty list; preserve this quirk.
            expanded = (mask + mask[:1] * max(0, len(reply) - len(mask)))[: len(reply)]
            checks.append(NativeVinCheck(request, ((expanded, reply),), selected))
            if len(checks) > 10:
                raise RecorderError("VIN request count exceeds native10-message area")
            update(selected)
            break
    return NativeVinFrames(initial, tuple(checks), (timeouts[0], timeouts[1]), ignored)


def selected_car_info_plan(
    profile: ProtocolProfile,
    cache: MonitorSupportCache,
    *,
    bus_id: int,
    driver: DriverProperties,
    diagnostic_mode: bytes,
    category_flags: int = 0,
) -> tuple[DrsTable, ...]:
    """CreateDrs3180's complete selected/observed group27 primitive records."""
    observed = selected_car_info_frames(
        profile, cache, bus_id=bus_id, category_flags=category_flags
    )

    def build(request: bytes) -> FramePlan:
        try:
            return get_comm_frame(
                profile,
                request,
                bus_id=bus_id,
                driver=driver,
                diagnostic_mode=diagnostic_mode,
            )
        except FrameTransportError as exc:
            raise NativeDrsError(exc.status) from exc

    startup_rows: tuple[SelectedFrame, ...] = ()
    if any(
        word(row, 0) == profile.category and word(row, 2) == 0x58
        for row in correspondence_rows(
            profile.catalog.management, 18, profile.exception_ids
        )
    ):
        startup_rows = profile.frame_records(0x58)
    if len(startup_rows) > 1:
        raise NativeDrsError(0xC0040102)
    # Native3180 constructs optional58 before all observed requests.
    startup = build(startup_rows[0].frame.request) if startup_rows else None
    checks = observed.initial + observed.checks
    if not checks:
        return ()
    plans = tuple(build(item.request) for item in checks)
    result = list(_native_protocol_setup(plans[-1], observed.settings_words, bus_id))
    for check, plan in zip(checks, plans, strict=True):
        send = NativeMessage.parse(plan.send.encode())
        for index, (mask, pattern) in enumerate(check.responses):
            outgoing, incoming = native_mode_exchange_tables(
                NativeSelectedModeFrame(
                    check.request, mask, pattern, observed.settings_words, check.source
                ),
                send,
            )
            if index == 0:
                result.append(outgoing)
            result.append(incoming)
    if startup is not None:
        assert startup_rows
        outgoing = NativeMessage.parse(startup.send.encode())
        first, second = struct.unpack_from("<II", startup_rows[0].settings_record)
        result.extend(
            (
                encode_command(0x203, {"timeout": first, "message": outgoing}),
                _native_empty_read(outgoing, second),
            )
        )
    result.append(encode_command(0x201, {}))
    return tuple(result)


def _selected_vehicle_vin103(
    profile: ProtocolProfile, cache: MonitorSupportCache, *, bus_id: int
) -> bytes:
    """Original18 74c0, also used by the protocol14 category1c8 fallback."""
    try:
        try:
            frames = profile.frame_records(0x103)
        except ValueError as error:
            if isinstance(error, ToyotaCodecError):
                raise
            if str(error) in (
                "No selected function communication frames",
                "No selected communication frame",
            ):
                raise NativeDrsError(0xC0040101) from error
            raise RecorderError(
                "Malformed selected VIN communication metadata"
            ) from error
        if len(frames) != 1:
            raise NativeDrsError(0xC0040102)
        request = frames[0]
        with cache.temporary_scope(no_init=True, no_session=True):
            reply = cache.transaction(
                request,
                request.frame.request,
                native_parameter=bus_id,
                extended=True,
                cached=False,
            )
        if len(reply) < 20:
            raise NativeDrsError(0xA0040202)
        if len(reply) > 258:
            raise UnsupportedRecorderOperation(
                "Native alternate VIN copy exceeds defined255-byte work area"
            )
        return reply[3:20]
    except ToyotaCodecError as error:
        raise NativeDrsError(error.code) from error


def selected_vehicle_vin(
    profile: ProtocolProfile, cache: MonitorSupportCache, *, bus_id: int
) -> bytes | None:
    """Native85/86 or original18 category18d/function103 VIN observation.

    None means the support bit is clear. Communication failures retain native
    status; a returned17-byte value still needs the caller's first-byte check.
    The injected shared cache owns transaction deadlines and cancellation.
    """
    bus_id = _uint(bus_id, 8)
    if not bus_id or cache.profile is not profile:
        raise RecorderError("VIN cache must belong to the selected protocol profile")
    cache.check_context()

    def frame(function: int) -> SelectedFrame:
        try:
            values = profile.frame_records(function)
        except ValueError as exc:
            if str(exc) in (
                "No selected function communication frames",
                "No selected communication frame",
            ):
                raise NativeDrsError(0xC0040101) from exc
            raise RecorderError(
                "Malformed selected VIN communication metadata"
            ) from exc
        if len(values) != 1:
            raise NativeDrsError(0xC0040102)
        return values[0]

    try:
        if cache.source_build == 18 and profile.category == 0x18D:
            return _selected_vehicle_vin103(profile, cache, bus_id=bus_id)
        support = frame(0x85)
        reply = cache.transaction(
            support, support.frame.request, native_parameter=bus_id
        )
        index = 2 if bus_id == 0x12 else 3
        if len(reply) <= index:
            raise NativeDrsError(0xA0040202)
        if not reply[index] & 0x40:
            return None
        request = frame(0x86)
        if bus_id == 0x12:
            reply = cache.transaction(
                request,
                request.frame.request,
                native_parameter=bus_id,
                cached=False,
            )
            if len(reply) < 20:
                raise NativeDrsError(0xA0040202)
            return reply[3:20]
        if cache.stream is None:
            raise NativeDrsError(0xC0040601)
        if not 1 <= len(request.frame.request) <= 255:
            raise RecorderError("VIN request exceeds native255-byte work area")
        if len(request.settings_record) != 16:
            raise RecorderError("Truncated VIN communication settings")
        query = SupportQuery(
            cache.ecu, request.frame.request, request, cache.identity, bus_id
        )
        send_timer = struct.unpack_from("<I", request.settings_record)[0]
        data = bytearray(255)
        length = 0
        status, accepted = 0, False
        for _ in range(request.settings_record[14] + 1):
            if not accepted:
                cache._primitive_budget()
                status = _uint(
                    cache.stream.send(SupportSend(query, send_timer, bus_id))
                )
                cache.check_context()
                if status:
                    continue
            receive = SupportReceive(query, 255, cache._receive_timer(request, bus_id))
            cursor, packets = 0, 0
            while True:
                cache._primitive_budget()
                status, reply = cache.stream.receive(receive)
                cache.check_context()
                status = _uint(status)
                if not isinstance(reply, bytes) or len(reply) > 255:
                    raise RecorderError("VIN receive exceeds native255-byte work area")
                if status == 0x90020323:
                    raise NativeDrsError(status)
                if status == 0x91010009 and packets:
                    status = 0
                    break
                if status:
                    break
                if not reply or reply[0] != (query.request[0] | 0x40):
                    # 6580 drains a mismatched service before its A0040201 return.
                    while True:
                        cache._primitive_budget()
                        drain_status, _ = cache.stream.receive(receive)
                        cache.check_context()
                        if _uint(drain_status):
                            break
                    status = 0xA0040201
                    break
                accepted = True
                if len(reply) < 7:
                    raise NativeDrsError(0xA0040201)
                if cursor + 4 > len(data):
                    raise RecorderError("VIN segments exceed native255-byte work area")
                data[cursor : cursor + 4] = reply[3:7]
                cursor += 4
                packets += 1
                length = (length + len(reply) - len(query.request) - 1) & 255
            if accepted and status == 0:
                break
        if length != 20:
            raise NativeDrsError(0xA0040202)
        if status:
            raise NativeDrsError(status)
        # Native scratch starts zeroed and copies from offset3 after reassembly.
        return bytes(data[3:20])
    except ToyotaCodecError as exc:
        raise NativeDrsError(exc.code) from exc


@dataclass(frozen=True)
class _NativeVehicleProtocolState:
    phase: int
    data: bytes

    def formatted(self) -> dict[int, bytes]:
        phase, state = self.phase, self.data
        if phase in (20, 21):
            return {1: b"", 2: b"", 3: b"1900", 16: b"", 17: b""}
        if phase == 3:
            return {
                1: bytes(state[0x19 : 0x19 + state[0x18]]),
                2: bytes([state[0x1D] | 0x30, state[0x1E], state[0x1F]]),
                3: str(1900 + state[0x25]).encode("ascii"),
                16: str(state[0x27] >> 4).encode("ascii") if state[0x26] else b"",
                17: str(state[0x21]).encode("ascii") if state[0x20] else b"",
            }
        return {
            1: bytes(state[0x51 : 0x51 + state[0x50]]),
            2: bytes(state[0x59 : 0x59 + state[0x58]]),
            3: str(1900 + state[0x64]).encode("ascii"),
            16: str(state[0x66]).encode("ascii") if state[0x65] else b"",
            17: str(state[0x60]).encode("ascii") if state[0x5F] else b"",
        }


def _selected_vehicle_protocol_setup(
    communication: NativeCommunication,
    phase: int,
) -> _NativeVehicleProtocolState:
    """Provider virtual+0: receive identification state without a SendInt probe."""
    profile, cache = communication.profile, communication.cache
    state = bytearray(0x6C)
    if phase in (20, 21):
        return _NativeVehicleProtocolState(phase, bytes(state))
    if phase not in (3, 4):
        raise NativeDrsError(0xA0040403)
    if phase == 3:
        assignments = (
            (27, 0x2C, 0x2D),
            (28, 0x24, 0x25),
            (29, 0x22, 0x23),
            (30, 0x20, 0x21),
            (31, 0x1C, 0x1F),
            (32, 0x1C, 0x1E),
            (33, 0x1C, 0x1D),
            (34, 0x2A, 0x2B),
            (35, 0x18, 0x1B),
            (36, 0x18, 0x1A),
            (37, 0x18, 0x19),
            (38, 0x26, 0x27),
            (39, 0x28, 0x29),
        )
        capacity = 8
    else:
        assignments = (
            *((function, 0x50, 0x51) for function in range(40, 47)),
            *((function, 0x58, 0x59) for function in range(47, 53)),
            (54, 0x5F, 0x60),
            (55, 0x61, 0x62),
            (56, 0x63, 0x64),
            (53, 0x65, 0x66),
            (57, 0x67, 0x68),
        )
        capacity = 64
    header = bytearray(capacity)
    for function, count_offset, value_offset in assignments:
        try:
            frames = profile.frame_records(function)
        except ValueError as exc:
            raise NativeDrsError(0xC0040101) from exc
        if not frames:
            raise NativeDrsError(0xC0040101)
        negative_empty = False
        for selected in frames:
            try:
                reply = cache.transaction(
                    selected,
                    selected.frame.request,
                    native_parameter=communication.bus_id,
                )
            except ToyotaCodecError as exc:
                negative_empty = exc.code in (
                    0x91010009,
                    0x90020323,
                ) and cache.response_cached(selected.frame.request)
                continue
            break
        else:
            if not negative_empty:
                raise UnsupportedRecorderOperation(
                    "Native context setup has no defined received bytes"
                )
            reply = b""
        if communication.source_build == 12 and len(reply) > capacity:
            raise UnsupportedRecorderOperation(
                "Native12 context receive exceeds defined stack work area"
            )
        copied = reply[:capacity]
        header[: len(copied)] = copied
        mask, check = selected.frame.receive_mask, selected.frame.receive_check
        if not mask or not check:
            raise NativeDrsError(0xC0040001)
        if len(mask) > capacity or len(check) > capacity:
            raise RecorderError("Native context mask exceeds protocol work area")
        if header[: len(check)] != check:
            continue
        value = next(
            (
                header[index] & byte
                for index, byte in enumerate(mask)
                if header[index] & byte
            ),
            0,
        )
        if phase == 4 and count_offset in (0x50, 0x58):
            limit = 7 if count_offset == 0x50 else 6
            if state[count_offset] >= limit:
                raise NativeDrsError(0xA0040201)
            value_offset += state[count_offset]
        state[value_offset] = value
        state[count_offset] += 1
    return _NativeVehicleProtocolState(phase, bytes(state))


def _selected_vehicle_diagnostics(
    communication: NativeCommunication,
    module: str,
) -> tuple[dict[int, bytes], int]:
    """15b0 probes once before the provider virtual setup and formatters."""
    profile = communication.profile
    phase = profile.category_record[72] & 31
    if phase not in (3, 4, 20, 21) or (
        phase == 21 and module == "SelectCarVn10Std_DT.dll"
    ):
        return dict.fromkeys((1, 2, 3, 16, 17), b""), 0
    status = communication.send_native(
        NativeFrameSend(
            "SendInt", profile.category, None, 1000, communication.bus_id, 1, 1
        )
    )
    state = (
        _NativeVehicleProtocolState(phase, bytes(0x6C))
        if status
        else _selected_vehicle_protocol_setup(communication, phase)
    )
    return state.formatted(), status


@dataclass(frozen=True)
class NativeVehicleVinEntry:
    category: int
    data: bytes

    def __post_init__(self) -> None:
        _uint(self.category)
        if not isinstance(self.data, bytes) or len(self.data) != 17:
            raise RecorderError("Native shared VIN entry requires seventeen bytes")


class NativeVehicleSession:
    """DiagCommCtrlMain's owned vehicle state, including embedded ShareData2A.

    Native CDataCtrl1720 constructs the lists before registering them. This
    object owns that lifecycle; siblings receive the same owner rather than a
    caller-supplied cache-presence flag or VIN observation.
    """

    def __init__(self, communication: NativeCommunication) -> None:
        from scripts.native_communication import NativeCommunication

        if type(communication) is not NativeCommunication:
            raise RecorderError(
                "Native vehicle session requires its actual communication owner"
            )
        communication._check()
        self.communication = communication
        self._vin_entries: list[NativeVehicleVinEntry] = []
        self._contexts: dict[tuple[int, int], NativeCommunication] = {}
        self.shared_bus = 0xFF
        self.shared_category = 0xFFFFFFFF
        self.shared_protocol = 0xFF
        self.shared_option = 0xFFFF
        self.category_mode = 0
        self.category_ids: list[tuple[int, int]] = []
        self.option_groups: list[_NativeMultiOptionGroup] = []
        self.option_group_bytes = 0
        self.current_model: int | None = None
        self.model_list: list[int] = []
        self.manual_identity: tuple[object, ...] | None = None
        self.multi_identity: tuple[object, ...] | None = None
        self.manual_parent_record: bytes | None = None
        self._closed = False

    def _check(self) -> None:
        if self._closed:
            raise SessionError("Native vehicle session is disposed")
        self.communication._check()

    @property
    def vin_entries(self) -> tuple[NativeVehicleVinEntry, ...]:
        self._check()
        return tuple(self._vin_entries)

    @property
    def multi_option_groups(self) -> tuple[NativeMultiOptionGroup, ...]:
        self._check()
        return tuple(entry.snapshot() for entry in self.option_groups)

    def dispose(self) -> None:
        """Release this CDataCtrl's embedded lists, independently of the adapter."""
        self._vin_entries.clear()
        self._contexts.clear()
        self.category_ids.clear()
        self.option_groups.clear()
        self.option_group_bytes = 0
        self.model_list.clear()
        self.shared_bus = 0xFF
        self.shared_category = 0xFFFFFFFF
        self.shared_protocol = 0xFF
        self.shared_option = 0xFFFF
        self.category_mode = 0
        self.current_model = None
        self.manual_identity = None
        self.multi_identity = None
        self.manual_parent_record = None
        self._closed = True


class _NativeVehicleContexts(Mapping[tuple[int, int], "NativeCommunication"]):
    def __init__(
        self, selector: NativeVehicleSelector, keys: tuple[tuple[int, int], ...]
    ) -> None:
        self.selector = selector
        self._keys = dict.fromkeys(keys)

    def __getitem__(self, key: tuple[int, int]) -> NativeCommunication:
        if key not in self._keys:
            raise KeyError(key)
        return self.selector._context(*key)

    def __iter__(self) -> Iterator[tuple[int, int]]:
        return iter(self._keys)

    def __len__(self) -> int:
        return len(self._keys)


class NativeVehicleSelector:
    """Selected regional7d automatic requests and subsequent option answers.

    Contexts share the concrete native controller and its connection observations.
    The returned value is the GUI copy consumed by CreateDrs, including its
    display-only CarInfo filter. Hidden VIN names remain available on this owner.
    """

    def __init__(
        self,
        communication: NativeCommunication | NativeVehicleSession,
        *,
        info_ids: tuple[int, ...],
        text_encoding: str,
        division: int = 0,
    ) -> None:
        from scripts.native_communication import NativeCommunication

        self.session = (
            communication if type(communication) is NativeVehicleSession else None
        )
        if self.session is not None:
            self.session._check()
            communication = self.session.communication
        if (
            type(communication) is not NativeCommunication
            or not isinstance(info_ids, tuple)
            or len(info_ids) > 100_000
            or any(type(item) is not int or not 0 <= item <= 65535 for item in info_ids)
            or type(division) is not int
            or not 0 <= division <= 65535
            or not isinstance(text_encoding, str)
        ):
            raise RecorderError("Invalid automatic vehicle selection inputs")
        self.owner = communication
        self.catalog = communication.profile.catalog
        self.info_ids = info_ids
        self.text_encoding = text_encoding
        self.division = division
        self._text("")
        self._contexts: dict[tuple[int, int], NativeCommunication] = (
            self.session._contexts if self.session is not None else {}
        )
        self.communication: NativeCommunication | None = None
        self.protocol = 0
        self.option_key = 0
        self.hidden_name = ""
        self._state: _NativeVehicleProtocolState | None = None
        self._current: NativeVehicleSelection | None = None
        self._byte_budget = 39
        self._name_count = 0

    def _check(self) -> None:
        if self.session is not None:
            self.session._check()
        self.owner._check()
        if self.catalog is not self.owner.profile.catalog:
            raise RecorderError("Native vehicle selection catalog changed")
        if self.communication is not None:
            self.communication._check()

    def _manual_admit(self, *, bind: bool = False) -> tuple[bytes, ...]:
        """Admit only the source-selected ordinary NA18 translation."""
        from scripts.native_communication import NativeFrameController

        self._check()
        if (
            self.owner.source_build != 18
            or not isinstance(self.owner.operations, NativeFrameController)
            or self.owner.operations.native_build != 18
        ):
            raise UnsupportedRecorderOperation(
                "Manual categories require the admitted native18 controller"
            )
        rows = self.owner.profile.dll_records(0x7D)
        if not rows or len(rows[0]) < 80:
            raise UnsupportedRecorderOperation(
                "Manual categories require the selected native18 provider row"
            )
        module = rows[0][:80].decode("utf-16le").split("\0", 1)[0]
        if module != "SelectCarTypVn10_DT.dll":
            raise UnsupportedRecorderOperation(
                "Manual categories are admitted only for the NA18 provider"
            )
        identity = (
            self.catalog,
            self.catalog.management.sha256,
            rows[0],
            self.owner.profile.exception_ids,
            self.owner.source_build,
            self.owner.operations.native_build,
        )
        if self.session is not None and self.session.manual_identity is not None:
            if self.session.manual_identity != identity:
                raise UnsupportedRecorderOperation(
                    "Manual category owner no longer matches its source catalog"
                )
        elif bind and self.session is not None:
            self.session.manual_identity = identity
        return rows

    def _multi_admit(self, *, bind: bool = False) -> tuple[bytes, ...]:
        from scripts.native_communication import NativeFrameController

        self._manual_admit(bind=bind)
        if not isinstance(self.owner.operations, NativeFrameController):
            raise UnsupportedRecorderOperation(
                "Multi categories require the native18 frame controller"
            )
        rows = self.owner.profile.dll_records(0x48)
        if not rows or len(rows[0]) < 80:
            raise UnsupportedRecorderOperation(
                "Multi categories require the selected native18 multi-command row"
            )
        module = rows[0][:80].decode("utf-16le").split("\0", 1)[0]
        if module != "SelectCarCtgrMltOpt.dll":
            raise UnsupportedRecorderOperation(
                "Multi categories require SelectCarCtgrMltOpt.dll"
            )
        identity = (
            self.catalog,
            self.catalog.management.sha256,
            rows[0],
            self.owner.profile.exception_ids,
            self.owner.source_build,
            self.owner.operations.native_build,
        )
        if self.session is not None and self.session.multi_identity is not None:
            if self.session.multi_identity != identity:
                raise UnsupportedRecorderOperation(
                    "Multi-option owner no longer matches its source catalog"
                )
        elif bind and self.session is not None:
            self.session.multi_identity = identity
        if (
            self.session is not None
            and self.session.option_groups
            and self.session.multi_identity != identity
        ):
            raise UnsupportedRecorderOperation(
                "Retained multi-option state has no matching source owner"
            )
        return rows

    def _manual_owner(self) -> NativeVehicleSession:
        if self.session is None:
            self.session = NativeVehicleSession(self.owner)
            self._contexts = self.session._contexts
        self.session._check()
        return self.session

    def _consumer_cache_init(self) -> None:
        if self.session is None:
            return
        self.session._check()
        if self.session.current_model is None:
            self.session.current_model = 0xFFFF
        if not self.session.model_list:
            self.session.model_list.append(0xFFFF)

    def _text(self, value: str) -> NativeCoreString:
        try:
            data = (value.split("\0", 1)[0] + "\0").encode(self.text_encoding)
        except (LookupError, UnicodeError) as error:
            raise RecorderError("Native context text encoding failed") from error
        if len(data) > 65535:
            raise RecorderError("Native context string exceeds ushort byte length")
        return NativeCoreString((1, 0), data)

    def _reset_budget(self, vin: bytes) -> None:
        self._byte_budget = 39 + len(vin)
        self._name_count = 0
        if self._byte_budget > MAX_RECORDER_BYTES:
            raise RecorderError("Native vehicle context exceeds byte budget")

    def _append(
        self, entries: list[NativeVehicleEntry], entry: NativeVehicleEntry
    ) -> None:
        self._check()
        if len(entries) >= 100_000:
            raise RecorderError("Too many native vehicle entries")
        self._byte_budget += 10 + 2 * len(entry.values) + len(entry.text.data)
        if self._byte_budget > MAX_RECORDER_BYTES:
            raise RecorderError("Native vehicle context exceeds byte budget")
        entries.append(entry)

    def _context(self, category: int, bus: int) -> NativeCommunication:
        key = category, bus
        if key not in self._contexts:
            profile = self.catalog.build_protocol_profile(
                category, exception_ids=self.owner.profile.exception_ids
            )
            self._contexts[key] = self.owner.protocol_context(profile, bus_id=bus)
        return self._contexts[key]

    def _module(self) -> str:
        assert self.communication is not None
        rows = self.communication.profile.dll_records(0x7D)
        if not rows:
            raise NativeDrsError(0xC0040101)
        module = rows[0][:80].decode("utf-16le").split("\0", 1)[0]
        if module not in (
            "SelectCarVn10Brd_DT.dll",
            "SelectCarVn10Std_DT.dll",
            "SelectCarTypVn10_DT.dll",
        ):
            raise UnsupportedRecorderOperation(
                "Unsupported selected vehicle context provider"
            )
        return module

    def _registered(self, vehicle: int) -> bool:
        try:
            rows = self.catalog.vehicle_set_records(vehicle)
        except ToyotaCodecError as error:
            if error.code != 0xA0030107:
                raise
            return True
        if not rows:
            return True
        name = rows[0][:18].decode("utf-16le").split("\0", 1)[0]
        return name in self.catalog.registered_sets

    def _manual_key(
        self,
        category: int,
        bus: int,
        values: tuple[int, int, int, int],
        *,
        selected_fields: int,
    ) -> VehicleContext:
        key = bytearray(40)
        struct.pack_into("<H", key, 2, category & 0xFFFF)
        key[27] = bus
        struct.pack_into("<H", key, 28, selected_fields)
        key[30] = 1
        struct.pack_into("<4H", key, 32, *values)
        return VehicleContext.from_native_key(bytes(key))

    def _manual_rows(self, context: VehicleContext) -> tuple[dict, ...]:
        self._check()
        section = self.catalog.management.sections.get(41)
        if section is None:
            raise NativeDrsError(0xA0030107)
        if section.count > 100_000:
            raise RecorderError("Native vehicle table exceeds entry budget")
        if len(section.payload) != section.count * 52:
            raise RecorderError("Malformed native DB129 vehicle table")
        rows = self.catalog.raw_matching_vehicles(context)
        if len(rows) > 100_000:
            raise RecorderError("Too many native vehicle entries")
        result = []
        for row in rows:
            self._check()
            model, option = row["vehicle_name_key"], row["option_key"]
            if model:
                valid = self._registered(model)
            else:
                valid = self._valid_options(option, 1)[0]
            if valid:
                result.append(row)
        if not result:
            raise NativeDrsError(0xC0040101)
        return tuple(result)

    @staticmethod
    def _manual_variant_sort(
        rows: tuple[dict, ...], *, check: Callable[[], None] | None = None
    ) -> list[dict]:
        """The recovered variant-only shortsort/qsort, including unstable ties."""
        values = list(rows)

        def key(index: int) -> int:
            return bytes.fromhex(values[index]["raw_hex"])[2]

        if len(values) <= 8:
            for high in range(len(values) - 1, 0, -1):
                if check is not None:
                    check()
                maximum = 0
                for index in range(1, high + 1):
                    if check is not None:
                        check()
                    if key(index) > key(maximum):
                        maximum = index
                values[maximum], values[high] = values[high], values[maximum]
            return values

        stack: list[tuple[int, int]] = [(0, len(values) - 1)]
        while stack:
            if check is not None:
                check()
            low, high = stack.pop()
            if high - low + 1 <= 8:
                for end in range(high, low, -1):
                    if check is not None:
                        check()
                    maximum = low
                    for index in range(low + 1, end + 1):
                        if check is not None:
                            check()
                        if key(index) > key(maximum):
                            maximum = index
                    values[maximum], values[end] = values[end], values[maximum]
                continue
            middle = low + (high - low + 1) // 2
            values[low], values[middle] = values[middle], values[low]
            pivot, i, j = key(low), low, high + 1
            while True:
                if check is not None:
                    check()
                i += 1
                while i <= high and key(i) <= pivot:
                    if check is not None:
                        check()
                    i += 1
                j -= 1
                while j > low and key(j) >= pivot:
                    if check is not None:
                        check()
                    j -= 1
                if i > j:
                    break
                values[i], values[j] = values[j], values[i]
            values[low], values[j] = values[j], values[low]
            left, right = (low, j - 1), (i, high)
            if 4 * (j - low) - 1 < 4 * (high - i):
                if right[0] < right[1]:
                    stack.append(right)
                if left[0] < left[1]:
                    stack.append(left)
            else:
                if left[0] < left[1]:
                    stack.append(left)
                if right[0] < right[1]:
                    stack.append(right)
        return values

    def _manual_null_send(self, communication: NativeCommunication) -> int:
        """Run the native NULL SendInt through the already-bound real adapter."""
        from scripts.native_communication import NativeFrameController

        communication._primitive()
        operations = communication.operations
        if not isinstance(operations, NativeFrameController):
            raise UnsupportedRecorderOperation(
                "Manual protocol probes require the native frame controller"
            )
        try:
            status = operations.send(
                None,
                timeout=1000,
                initialization_mode=0,
                clear_rx=1,
                no_session=False,
                deadline=communication.deadline,
                profile=communication.profile,
                bus_id=communication.bus_id,
                first_request=communication._context_first_request,
            )
        finally:
            communication._check(timeout_error=sys.exception())
        if type(status) is not int or not 0 <= status <= 0xFFFFFFFF:
            raise RecorderError("Native NULL SendInt returned malformed status")
        return status

    def _manual_protocol_context(self, category: int, bus: int) -> NativeCommunication:
        communication = self._context(category, bus)
        self._check()
        return communication

    def _except_hv(self) -> tuple[int, int, int, int]:
        section = self.catalog.management.sections.get(2)
        if section is None:
            raise NativeDrsError(0xA0030107)
        if section.count > 0x7FFF:
            raise NativeDrsError(0xA0030110)
        if len(section.payload) != section.count * 4:
            raise RecorderError("Malformed native DB102 candidate table")
        if section.count == 0:
            raise NativeDrsError(0xC0040101)
        for index in range(section.count):
            self._check()
            candidate = section.payload[index * 4 : index * 4 + 4]
            category, bus = struct.unpack_from("<HB", candidate)
            records = self.owner.profile.category_records(category)
            if len(records) != 1:
                raise NativeDrsError(0xC0040102)
            protocol = records[0][72]
            communication = self._manual_protocol_context(category, bus)
            status = self._manual_null_send(communication)
            if status == 0 and (category, bus) != (0x3C, 0x12):
                return category, bus, protocol, index
            if status != 0:
                self.owner.connect_set(category, 0, bus, protocol)
        return 0, 0, 0, 0

    def _manual_probe_pair(self, rows: tuple[dict, ...]) -> tuple[int, int]:
        ordered = self._manual_variant_sort(rows, check=self._check)
        selected = (0, 0)
        for row in ordered:
            self._check()
            category = word(bytes.fromhex(row["raw_hex"]), 0)
            bus = bytes.fromhex(row["raw_hex"])[2]
            records = self.owner.profile.category_records(category)
            if len(records) != 1:
                raise NativeDrsError(0xC0040102)
            communication = self._manual_protocol_context(category, bus)
            if self._manual_null_send(communication) == 0:
                return category, bus
            selected = category, bus
        return selected

    def _multi_initial_pair(self) -> tuple[int, int]:
        candidates = self.catalog.protocol_candidates(self.owner.profile.exception_ids)
        contexts = _NativeVehicleContexts(
            self,
            tuple((candidate.category, candidate.variant) for candidate in candidates),
        )
        selected = self.owner.check_protocol(candidates, contexts=contexts)
        self._check()
        if selected is None:
            return 0, 0
        return selected.category, selected.variant

    @staticmethod
    def _multi_bus_probe_case(rows: tuple[dict, ...]) -> bool:
        return bool(rows) and all(
            word(bytes.fromhex(row["raw_hex"]), 0) == 1
            and bytes.fromhex(row["raw_hex"])[2] in (0x17, 0x21)
            for row in rows
        )

    def _multi_fallback_pair(self, rows: tuple[dict, ...]) -> tuple[int, int]:
        ordered = self._manual_variant_sort(rows, check=self._check)
        if not ordered:
            return 0, 0
        raw = bytes.fromhex(ordered[-1]["raw_hex"])
        return word(raw, 0), raw[2]

    def _multi_append_option_group(
        self,
        *,
        category: int,
        bus: int,
        option_key: int,
        raw_group: int,
        raw_choice: int,
        label_reference: int,
        terminal_model: int,
        next_group: int,
        text: str,
    ) -> None:
        assert self.session is not None
        self._check()
        label_bytes = self._text(text).data
        size = 44 + len(label_bytes)
        if (
            len(self.session.option_groups) >= 100_000
            or self.session.option_group_bytes + size > MAX_RECORDER_BYTES
        ):
            raise RecorderError("Native multi-option state exceeds host budget")
        self.session.option_groups.append(
            _NativeMultiOptionGroup(
                category,
                bus,
                option_key,
                raw_group,
                raw_choice,
                label_reference,
                terminal_model,
                next_group,
                text=text,
                text_bytes=label_bytes,
            )
        )
        self.session.option_group_bytes += size

    def _multi_create_option_groups(self, rows: tuple[dict, ...]) -> None:
        assert self.session is not None
        for vehicle in rows:
            self._check()
            raw = bytes.fromhex(vehicle["raw_hex"])
            option_key = word(raw, 48)
            records = self.catalog.option_records(option_key)
            valid, invalid = self._valid_options(option_key, 1)
            if not valid:
                raise NativeDrsError(0xC0040101)
            records = tuple(
                record
                for record in records
                if (word(record, 6), word(record, 8)) not in invalid
            )
            if not records:
                raise NativeDrsError(0xC0040101)
            for record in records:
                self._check()
                label_reference = struct.unpack_from("<I", record)[0]
                text = self.catalog.language.resolve(label_reference)
                self._multi_append_option_group(
                    category=word(raw, 0),
                    bus=raw[2],
                    option_key=option_key,
                    raw_group=word(record, 6),
                    raw_choice=word(record, 8),
                    label_reference=label_reference,
                    terminal_model=word(record, 10),
                    next_group=word(record, 12),
                    text=text,
                )

    def _multi_search_index(
        self, raw_group: int
    ) -> tuple[_NativeMultiOptionGroup, ...]:
        assert self.session is not None
        if type(raw_group) is not int or not 0 <= raw_group <= 0xFFFF:
            raise RecorderError("Native multi-option group must be a ushort")
        output: list[_NativeMultiOptionGroup] = []
        seen: set[str] = set()
        for entry in self.session.option_groups:
            self._check()
            entry.assigned_index = 0
            entry.assigned_select = 0
        for entry in self.session.option_groups:
            self._check()
            if entry.raw_group != raw_group:
                continue
            entry.assigned_index = raw_group
            entry.assigned_select = 0
            if entry.text in seen:
                continue
            if len(output) >= 0xFFFF:
                raise RecorderError("Native multi-option select IDs exceed WORD range")
            if len(output) >= 100_000:
                raise RecorderError("Native multi-option output exceeds entry budget")
            seen.add(entry.text)
            entry.assigned_select = len(output) + 1
            output.append(replace(entry))
        return tuple(output)

    def _multi_option_group(
        self,
        output: list[_NativeMultiOptionGroup],
        option_key: int,
        raw_group: int,
        assigned_index: int,
    ) -> None:
        assert self.session is not None
        seen = {entry.text for entry in output}
        for entry in self.session.option_groups:
            self._check()
            if entry.option_key != option_key or entry.raw_group != raw_group:
                continue
            entry.assigned_index = assigned_index
            entry.assigned_select = 0
            if entry.text in seen:
                continue
            if len(output) >= 0xFFFF:
                raise RecorderError("Native multi-option select IDs exceed WORD range")
            if len(output) >= 100_000:
                raise RecorderError("Native multi-option output exceeds entry budget")
            seen.add(entry.text)
            entry.assigned_select = len(output) + 1
            output.append(replace(entry))

    def _multi_search_select(
        self, index: int, select_id: int
    ) -> tuple[_NativeMultiOptionGroup, ...]:
        assert self.session is not None
        matches = [
            (position, entry)
            for position, entry in enumerate(self.session.option_groups)
            if entry.assigned_index == index and entry.assigned_select == select_id
        ]
        if len(matches) != 1:
            raise NativeDrsError(0xC0040602)
        position, selected = matches[0]
        if selected.terminal_model:
            return (replace(selected),)
        output: list[_NativeMultiOptionGroup] = []
        self._multi_option_group(
            output, selected.option_key, selected.next_group, selected.next_group
        )
        sibling_position = position + 1
        while sibling_position < len(self.session.option_groups):
            self._check()
            sibling = self.session.option_groups[sibling_position]
            if sibling.assigned_index == index and sibling.text == selected.text:
                self._multi_option_group(
                    output,
                    sibling.option_key,
                    sibling.next_group,
                    selected.next_group,
                )
            sibling_position += 1
        return tuple(output)

    def _multi_check_protocol_cache(self) -> tuple[int, int, int, int, int]:
        assert self.session is not None
        _ = self.owner.connection_entries
        section = self.catalog.management.sections.get(2)
        if section is None:
            raise NativeDrsError(0xA0030107)
        if section.count > 0x7FFF:
            raise NativeDrsError(0xA0030110)
        if len(section.payload) != section.count * 4:
            raise RecorderError("Malformed native DB102 candidate table")
        if section.count == 0:
            raise NativeDrsError(0xC0040101)
        displayed = self._multi_search_index(1)
        if not displayed:
            raise NativeDrsError(0xC0040602)
        for index in range(section.count):
            self._check()
            category, bus = struct.unpack_from("<HB", section.payload, index * 4)
            if not any(
                entry.category == category and entry.bus == bus for entry in displayed
            ):
                continue
            category_rows = self.owner.profile.category_records(category)
            if len(category_rows) != 1:
                raise NativeDrsError(0xC0040102)
            protocol = category_rows[0][72]
            communication = self._manual_protocol_context(category, bus)
            supported, found = communication.check_connection_buffer()
            self._check()
            if found:
                if supported == 1:
                    return category, bus, protocol, index, 1
                continue
            status = self._manual_null_send(communication)
            if status == 0:
                return category, bus, protocol, index, 1
            self.owner.connect_set(category, 0, bus, protocol)
            self._check()
        return 0, 0, 0, 0, 0

    def _multi_selection_output(
        self,
        index: int,
        entries: tuple[_NativeMultiOptionGroup, ...],
        *,
        base: NativeVehicleSelection | None = None,
    ) -> NativeVehicleSelection:
        self._check()
        if not entries:
            raise NativeDrsError(0xC0040602)
        if len(entries) > 100_000:
            raise RecorderError("Native multi-option output exceeds entry budget")
        options = []
        for entry in entries:
            self._check()
            self._append(
                options,
                NativeVehicleEntry(
                    (1, 0), (entry.assigned_select,), self._text(entry.text)
                ),
            )
        result = NativeVehicleSelection(
            (1, 0),
            base.vin if base is not None else self._text(""),
            ((1, 0), (1, 0), (1, 0)),
            base.select_names if base is not None else (),
            base.car_info if base is not None else (),
            tuple(options),
            (index, 0),
        )
        if len(result.encode()) > MAX_RECORDER_BYTES:
            raise RecorderError("Native multi-option output exceeds byte budget")
        self._check()
        self._current = result
        return result

    def _multi_initial(
        self,
        param_index: int,
        *,
        base: NativeVehicleSelection | None = None,
        caller_values: tuple[int, int, int, int] | None = None,
    ) -> NativeVehicleSelection:
        assert self.session is not None
        raw_group = param_index or 1
        output = self._multi_search_index(raw_group)
        if not output:
            raise NativeDrsError(0xC0040602)
        if param_index == 0:
            if caller_values is None:
                self._manual_commit_globals()
            else:
                bus, category, protocol, option = caller_values
                self._manual_commit_globals(
                    option_value=option,
                    category_value=category,
                    bus_value=bus,
                    protocol_value=protocol,
                )
        return self._multi_selection_output(raw_group, output, base=base)

    def _multi_answer(self, index: int, select_id: int) -> NativeVehicleSelection:
        assert self.session is not None
        output = self._multi_search_select(index, select_id)
        if not output:
            raise NativeDrsError(0xC0040602)
        if len(output) != 1 or output[0].terminal_model == 0:
            return self._multi_selection_output(output[0].assigned_index, output)
        selected = output[0]
        model, category, bus = (
            selected.terminal_model,
            selected.category,
            selected.bus & 0xFF,
        )
        self._consumer_cache_init()
        self.option_key = 0
        provider_protocol = self._manual_setup_protocol(category=category)
        result = self._manual_finish(
            model,
            option_value=0,
            provider_protocol=provider_protocol,
            category_value=category,
            bus_value=bus,
        )
        return result

    def select_categories(
        self,
        selected_ids: tuple[tuple[int, int], ...],
        *,
        bus_judge: int,
    ) -> NativeCategoryMenu:
        try:
            return self._select_categories(selected_ids, bus_judge=bus_judge)
        except ToyotaCodecError as error:
            raise NativeDrsError(error.code) from error

    def select_multigroup_categories(
        self,
        selected_ids: tuple[tuple[int, int], ...],
        *,
        bus_judge: int,
    ) -> NativeCategoryMenu:
        try:
            return self._select_categories(
                selected_ids, bus_judge=bus_judge, multigroup=True
            )
        except ToyotaCodecError as error:
            raise NativeDrsError(error.code) from error

    def _select_categories(
        self,
        selected_ids: tuple[tuple[int, int], ...],
        *,
        bus_judge: int,
        multigroup: bool = False,
    ) -> NativeCategoryMenu:
        """Execute an admitted18 category producer on the shared owner."""
        if (
            not isinstance(selected_ids, tuple)
            or len(selected_ids) > 100_000
            or any(
                not isinstance(pair, tuple)
                or len(pair) != 2
                or type(pair[0]) is not int
                or not 0 <= pair[0] <= 0xFFFF
                or type(pair[1]) is not int
                or not 0 <= pair[1] <= 0xFFFF
                for pair in selected_ids
            )
            or type(bus_judge) is not int
            or not 0 <= bus_judge <= 0xFF
        ):
            raise RecorderError("Invalid native manual category request")
        if any(level not in (1, 2, 3, 4) for level, _ in selected_ids):
            raise NativeDrsError(0xC0040001)
        session = self._manual_owner()
        self._multi_admit(bind=True) if multigroup else self._manual_admit(bind=True)
        self._check()
        selected: list[int] = [0, 0, 0, 0]
        for level, value in selected_ids:
            self._check()
            selected[level - 1] = value
        current_bus, current_category = 0, 0
        current_valid = 1
        if bus_judge == 1:
            self._check()
            current_bus, current_category = session.shared_bus, session.shared_category
            if current_bus == 0xFF and current_category == 0xFFFFFFFF:
                current_valid = 0
                if multigroup:
                    category, bus = self._multi_initial_pair()
                else:
                    category, bus, _protocol, _index = self._except_hv()
                session.shared_category = category
                session.shared_bus = bus
                current_category, current_bus = category, bus
            else:
                current_valid = int(not (current_bus == 0 and current_category == 0))

        selected_fields = (1 if current_category != 0 else 0) | (
            2 if current_bus != 0 else 0
        )
        context = self._manual_key(
            current_category,
            current_bus,
            (selected[0], selected[1], selected[2], selected[3]),
            selected_fields=selected_fields,
        )
        surviving = self._manual_rows(context)

        # DB12F is an eager ALL query, even when no selected value is present.
        master_section = self.catalog.management.sections.get(47)
        if master_section is None:
            raise NativeDrsError(0xA0030107)
        if master_section.count > 0x7FFF:
            raise NativeDrsError(0xA0030110)
        masters = self.catalog.category_master_records()
        if not masters:
            raise NativeDrsError(0xC0040101)
        items: list[NativeCategoryItem] = []
        count, budget = 0, 0
        max_choices = 0
        for master in masters:
            self._check()
            level = word(master, 4)
            if not 1 <= level <= 4:
                raise NativeDrsError(0xC0040102)
            values: list[int] = []
            for vehicle in surviving:
                self._check()
                raw = bytes.fromhex(vehicle["raw_hex"])
                value = word(raw, 40 + (level - 1) * 2)
                if value and value not in values:
                    values.append(value)
            gathered: list[tuple[int, str, int, bytes]] = []
            gathered_bytes = gathered_max = 0
            for value in values:
                self._check()
                records = self.catalog.collect_item_records(level, value)
                if not records:
                    raise NativeDrsError(0xC0040101)
                label = self.catalog.language.resolve(
                    struct.unpack_from("<I", records[0])[0]
                )
                label_data = self._text(label).data
                entry_bytes = 12 + len(label_data)
                gathered_bytes += entry_bytes
                gathered_max = max(gathered_max, entry_bytes)
                projected = max(gathered_bytes, len(gathered) * gathered_max)
                if (
                    count + len(gathered) + 1 > 100_000
                    or budget + projected > MAX_RECORDER_BYTES
                ):
                    raise RecorderError("Native category menu exceeds host budget")
                gathered.append((value, label, word(records[0], 8), label_data))
            choices: list[NativeCategoryChoice] = []
            for _ in range(len(gathered)):
                self._check()
                candidates = [
                    i for i, entry in enumerate(gathered) if int(entry[2]) != 0
                ]
                if candidates:
                    selected_index = min(candidates, key=lambda i: int(gathered[i][2]))
                elif gathered:
                    selected_index = 0
                else:
                    break
                value, label, _sort, label_data = gathered[selected_index]
                choices.append(NativeCategoryChoice(int(value), str(label)))
                budget += 10 + 2 + len(label_data)
                count += 1
                value, label, _sort, label_data = gathered[selected_index]
                gathered[selected_index] = (value, label, 0, label_data)
                if count > 100_000 or budget > MAX_RECORDER_BYTES:
                    raise RecorderError("Native category menu exceeds host budget")
            master_label = self.catalog.language.resolve(
                struct.unpack_from("<I", master)[0]
            )
            master_data = self._text(master_label).data
            budget += 10 + 2 + len(master_data)
            count += 1
            if count > 100_000 or budget > MAX_RECORDER_BYTES:
                raise RecorderError("Native category menu exceeds host budget")
            max_choices = max(max_choices, len(choices))
            items.append(NativeCategoryItem(level, master_label, tuple(choices)))

        mode = 0
        category_fields: list[tuple[int, int, int, int]] = []
        for row in surviving:
            self._check()
            raw = bytes.fromhex(row["raw_hex"])
            category_fields.append(
                (
                    word(raw, 40),
                    word(raw, 42),
                    word(raw, 44),
                    word(raw, 46),
                )
            )
        if multigroup:
            # Multi1900 owns 1D and clears it after every menu has been built,
            # including mode0/2 and any later error in output selection.
            self._check()
            session.option_groups.clear()
            session.option_group_bytes = 0
        if current_valid == 0 and (
            (len(surviving) == 1 and bytes.fromhex(surviving[0]["raw_hex"])[2] != 0)
            or (len(surviving) > 1 and max_choices == 1)
        ):
            mode = 2
        elif len(surviving) == 1:
            mode = 1
            raw = bytes.fromhex(surviving[0]["raw_hex"])
            session.shared_category = word(raw, 0)
            session.shared_bus = raw[2]
        elif len(surviving) > 1:
            first_row = bytes.fromhex(surviving[0]["raw_hex"])
            if all(fields == category_fields[0] for fields in category_fields) and any(
                word(bytes.fromhex(row["raw_hex"]), 0) != word(first_row, 0)
                or bytes.fromhex(row["raw_hex"])[2] != first_row[2]
                for row in surviving[1:]
            ):
                if multigroup and self._multi_bus_probe_case(surviving):
                    session.shared_category, session.shared_bus = (
                        self._manual_probe_pair(surviving)
                    )
                elif multigroup:
                    self._multi_create_option_groups(surviving)
                    category, bus, _protocol, _index, supported = (
                        self._multi_check_protocol_cache()
                    )
                    if supported != 1:
                        category, bus = self._multi_fallback_pair(surviving)
                    session.shared_category, session.shared_bus = category, bus
                else:
                    session.shared_category, session.shared_bus = (
                        self._manual_probe_pair(surviving)
                    )
                mode = 1

        if mode:
            session.category_ids.clear()
            session.category_mode = mode
            for item in items:
                self._check()
                session.category_ids.append(
                    (item.level, item.choices[0].value if item.choices else 0)
                )
                if len(session.category_ids) > 100_000:
                    raise RecorderError("Native category state exceeds entry budget")
        self._check()
        return NativeCategoryMenu(mode, tuple(items))

    def _manual_local_values(self) -> tuple[int, int, int, int]:
        assert self.session is not None
        return (
            0 if self.session.shared_bus == 0xFF else self.session.shared_bus,
            0
            if self.session.shared_category == 0xFFFFFFFF
            else self.session.shared_category,
            0 if self.session.shared_protocol == 0xFF else self.session.shared_protocol,
            0 if self.session.shared_option == 0xFFFF else self.session.shared_option,
        )

    def _manual_commit_globals(
        self,
        *,
        option_value: int | None = None,
        category_value: int | None = None,
        bus_value: int | None = None,
        protocol_value: int | None = None,
    ) -> None:
        assert self.session is not None
        bus, category, protocol, option = self._manual_local_values()
        if option_value is not None:
            option = option_value
        if category_value is not None:
            category = category_value
        if bus_value is not None:
            bus = bus_value
        if protocol_value is not None:
            protocol = protocol_value
        self.session.shared_category = category
        self.session.shared_protocol = protocol
        self.session.shared_option = option
        self.session.shared_bus = bus

    def _manual_setup_protocol(self, *, category: int | None = None) -> int:
        assert self.session is not None
        category = self.session.shared_category if category is None else category
        if category in (0, 0xFFFFFFFF):
            return 0
        records = self.owner.profile.category_records(category)
        if len(records) != 1:
            raise NativeDrsError(0xC0040102)
        return records[0][72]

    def _manual_option_output(
        self,
        option_key: int,
        group: int,
        *,
        base: NativeVehicleSelection | None = None,
    ) -> NativeVehicleSelection:
        self._check()
        rows = self.catalog.option_records(option_key, group)
        valid, invalid = self._valid_options(option_key, group)
        if not valid:
            raise NativeDrsError(0xC0040101)
        rows = tuple(row for row in rows if (word(row, 6), word(row, 8)) not in invalid)
        if not rows:
            raise NativeDrsError(0xC0040101)
        options = []
        for row in rows:
            self._check()
            label = self.catalog.language.resolve(struct.unpack_from("<I", row)[0])
            self._append(
                options,
                NativeVehicleEntry((1, 0), (word(row, 8),), self._text(label)),
            )
        result = NativeVehicleSelection(
            (1, 0),
            self._text(""),
            ((1, 0), (1, 0), (1, 0)),
            () if base is None else base.select_names,
            () if base is None else base.car_info,
            tuple(options),
            (group, 0),
        )
        self._check()
        self._current = result
        return result

    def _manual_car_info(
        self,
        model: int,
        provider_protocol: int,
        *,
        category_value: int | None = None,
        bus_value: int | None = None,
    ) -> tuple[tuple[NativeVehicleEntry, ...], tuple[NativeVehicleEntry, ...]]:
        assert self.session is not None
        select_names: list[NativeVehicleEntry] = []
        car_info: list[NativeVehicleEntry] = []
        provider: _NativeVehicleProtocolState | None = None
        provider_created = False
        masters: tuple[bytes, ...] | None = None
        info_level = info_value = 0
        category = (
            self.session.shared_category if category_value is None else category_value
        )
        bus = self.session.shared_bus if bus_value is None else bus_value
        protocol = provider_protocol & 31
        communication: NativeCommunication | None = None
        phase_supported = protocol in (3, 4, 20, 21)
        for item in self.info_ids:
            self._check()
            if item in (1, 2, 3, 16, 17):
                value = b""
                if phase_supported:
                    if not provider_created:
                        provider_created = True
                        communication = self._manual_protocol_context(category, bus)
                        status = self._manual_null_send(communication)
                        if status == 0:
                            provider = _selected_vehicle_protocol_setup(
                                communication, protocol
                            )
                        else:
                            provider = _NativeVehicleProtocolState(
                                protocol, bytes(0x6C)
                            )
                            text = NativeCoreString((1, 0), b"\0")
                            self._append(
                                car_info,
                                NativeVehicleEntry((1, 0), (item,), text),
                            )
                            continue
                    if provider_created and provider is not None:
                        value = provider.formatted().get(item, b"")
                text = NativeCoreString((1, 0), value.split(b"\0", 1)[0] + b"\0")
                self._append(car_info, NativeVehicleEntry((1, 0), (item,), text))
                continue
            if item == 4:
                rows = self.catalog.vehicle_name_records(model)
                label = (
                    self.catalog.language.resolve(struct.unpack_from("<I", rows[0])[0])
                    if len(rows) == 1
                    else ""
                )
                self._append(
                    car_info, NativeVehicleEntry((1, 0), (item,), self._text(label))
                )
                continue

            if masters is None:
                masters = self.catalog.category_master_records()
            if not masters:
                raise NativeDrsError(0xC0040101)
            for master in masters:
                self._check()
                if word(master, 6) == item:
                    info_level = word(master, 4)
                    info_value = next(
                        (
                            value
                            for level, value in self.session.category_ids
                            if level == info_level
                        ),
                        0,
                    )
                    break
            if not info_level:
                raise NativeDrsError(0xC0040001)
            if not 1 <= info_level <= 4:
                raise NativeDrsError(0xC0040102)
            if not info_value:
                text = self._text("")
                output_id = info_level
            else:
                records = self.catalog.collect_item_records(info_level, info_value)
                if len(records) != 1:
                    raise NativeDrsError(0xC0040102)
                label = self.catalog.language.resolve(
                    struct.unpack_from("<I", records[0])[0]
                )
                text = self._text(label)
                output_id = item
            self._append(
                select_names,
                NativeVehicleEntry((1, 0), (output_id, info_value), text),
            )
        return tuple(select_names), tuple(car_info)

    def _manual_finish(
        self,
        model: int,
        *,
        option_value: int = 0,
        provider_protocol: int = 0,
        postlude: bool = True,
        category_value: int | None = None,
        bus_value: int | None = None,
    ) -> NativeVehicleSelection:
        assert self.session is not None
        self._reset_budget(b"")
        select_names, names = self._manual_car_info(
            model,
            provider_protocol,
            category_value=category_value,
            bus_value=bus_value,
        )
        # 5BF0 commits only after the provider has formatted all requested IDs.
        self._manual_commit_globals(
            option_value=option_value,
            category_value=category_value,
            bus_value=bus_value,
        )
        self.session.current_model = model
        if self.session.model_list:
            self.session.model_list[0] = model
        else:
            self.session.model_list.append(model)
        self._check()
        car = tuple(row for row in names if row.values[0] not in (16, 17, 18))
        result = NativeVehicleSelection(
            (1, 0),
            self._text(""),
            ((1, 0), (1, 0), (1, 0)),
            select_names,
            car,
            (),
            (0, model),
        )
        if len(result.encode()) > MAX_RECORDER_BYTES:
            raise RecorderError("Native vehicle context exceeds byte budget")
        self._check()
        self._current = result
        if postlude:
            self._manual_parent_postlude()
            self._check()
        return result

    def _manual_parent_postlude(self) -> None:
        assert self.session is not None
        category = self.session.shared_category
        if category == 0:
            self.session.manual_parent_record = None
            self._check()
            return
        if category == 0xFFFFFFFF:
            self.session.manual_parent_record = None
            self._check()
            return
        records = self.owner.profile.category_records(category)
        if len(records) != 1:
            raise NativeDrsError(0xC0040102)
        self.session.manual_parent_record = records[0]
        self._check()

    def _manual_resume_index(self, category: int, bus: int) -> int:
        section = self.catalog.management.sections.get(2)
        if section is None:
            raise NativeDrsError(0xA0030107)
        if section.count > 0x7FFF:
            raise NativeDrsError(0xA0030110)
        if len(section.payload) != section.count * 4:
            raise RecorderError("Malformed native DB102 candidate table")
        if section.count == 0:
            raise NativeDrsError(0xC0040101)
        return self.catalog.protocol_resume_index(category, bus)

    def _manual_select(self) -> NativeVehicleSelection:
        session = self._manual_owner()
        self._manual_admit()
        if not session.category_ids:
            raise RecorderError("No retained native manual category menu")
        mode = session.category_mode
        if mode == 0:
            raise NativeDrsError(0xA0040403)
        if mode == 2:
            session.current_model = 0xFFFF
            if session.model_list:
                session.model_list[0] = 0xFFFF
            else:
                session.model_list.append(0xFFFF)
            result = NativeVehicleSelection(
                (1, 0),
                self._text(""),
                ((1, 0), (1, 0), (1, 0)),
                (),
                (),
                (),
                (0, 0xFFFF),
            )
            self._current = result
            self._manual_parent_postlude()
            self._check()
            return result
        if (
            not isinstance(session.category_ids, list)
            or len(session.category_ids) > 100_000
            or any(
                not isinstance(pair, tuple)
                or len(pair) != 2
                or type(pair[0]) is not int
                or not 0 <= pair[0] <= 0xFFFF
                or type(pair[1]) is not int
                or not 0 <= pair[1] <= 0xFFFF
                for pair in session.category_ids
            )
        ):
            raise RecorderError("Invalid retained native category state")
        pairs = tuple(session.category_ids)
        values: list[int] = [0, 0, 0, 0]
        for level, value in pairs:
            if level not in (1, 2, 3, 4):
                raise NativeDrsError(0xA0040403)
            values[level - 1] = value
        local_bus, local_category, _local_protocol, _local_option = (
            self._manual_local_values()
        )
        provider_protocol = self._manual_setup_protocol()
        context = self._manual_key(
            local_category,
            local_bus,
            (values[0], values[1], values[2], values[3]),
            selected_fields=0,
        )
        rows = self._manual_rows(context)
        if len(rows) == 1:
            chosen = rows[0]
        else:
            chosen = next(
                (row for row in rows if bytes.fromhex(row["raw_hex"])[2] == local_bus),
                None,
            )
            if chosen is None:
                raise NativeDrsError(0xC0040102)
        model, option_key = chosen["vehicle_name_key"], chosen["option_key"]
        if option_key:
            base = self._manual_finish(
                model,
                option_value=option_key,
                provider_protocol=provider_protocol,
                postlude=False,
            )
            if session.option_groups:
                self._multi_admit()
                return self._multi_initial(0, base=base)
            self.option_key = option_key
            result = self._manual_option_output(option_key, 1, base=base)
            if result.trailing_words[1] != 0:
                self._manual_parent_postlude()
                self._check()
            return result
        if not model:
            raise NativeDrsError(0xC0040102)
        result = self._manual_finish(
            model,
            option_value=0,
            provider_protocol=provider_protocol,
        )
        return result

    def _manual_answer(self, group: int, choice: int) -> NativeVehicleSelection:
        assert self.session is not None
        self._manual_admit()
        option_key = self.session.shared_option
        if not option_key:
            raise RecorderError("No pending native manual option selection")
        self._reset_budget(b"")
        self.hidden_name = ""
        try:
            rows = self.catalog.option_records(option_key, group, choice)
            valid, invalid = self._valid_options(option_key, group)
            if not valid:
                raise NativeDrsError(0xC0040101)
            rows = tuple(
                row for row in rows if (word(row, 6), word(row, 8)) not in invalid
            )
            if len(rows) != 1:
                raise NativeDrsError(0xC0040102)
            model, next_group = struct.unpack_from("<HH", rows[0], 10)
            if model:
                self.option_key = 0
                # Terminal option answers re-enter 1E30, then 5BF0 and the
                # common parent postlude. The provider protocol remains local.
                provider_protocol = self._manual_setup_protocol()
                return self._manual_finish(
                    model, option_value=0, provider_protocol=provider_protocol
                )
            if next_group:
                self.session.shared_option = option_key
                self.option_key = option_key
                result = self._manual_option_output(option_key, next_group)
                if result.trailing_words[1] != 0:
                    self._manual_parent_postlude()
                    self._check()
                return result
            self.option_key = 0
            category = self.session.shared_category
            bus = self.session.shared_bus
            result = self._select(self._manual_resume_index(category, bus))
            if result.trailing_words[1] == 0xFFFF:
                self.session.current_model = 0xFFFF
                if self.session.model_list:
                    self.session.model_list[0] = 0xFFFF
                else:
                    self.session.model_list.append(0xFFFF)
            if result.trailing_words[1] != 0:
                self._manual_parent_postlude()
                self._check()
            return result
        except ToyotaCodecError as error:
            raise NativeDrsError(error.code) from error

    def _valid_options(
        self, key: int, group: int, visited: frozenset[int] = frozenset()
    ) -> tuple[bool, frozenset[tuple[int, int]]]:
        self._check()
        if not key:
            raise NativeDrsError(0xC0040001)
        if group in visited or len(visited) >= 256:
            raise RecorderError(
                "Native option tree exceeds defined acyclic host boundary"
            )
        rows = self.catalog.option_records(key, group)
        if not rows:
            raise NativeDrsError(0xC0040102)
        invalid: set[tuple[int, int]] = set()
        allowed = False
        for row in rows:
            self._check()
            model, next_group = struct.unpack_from("<HH", row, 10)
            if model:
                valid = self._registered(model)
            else:
                valid, nested = self._valid_options(key, next_group, visited | {group})
                invalid.update(nested)
            allowed |= valid
            if not valid:
                invalid.add((word(row, 6), word(row, 8)))
        return allowed, frozenset(invalid)

    def _hidden_vin_name(self, model: int, option: int) -> str:
        if not model:
            if not option:
                raise NativeDrsError(0xC0040102)
            rows = self.catalog.option_records(option)
            model = next((word(row, 10) for row in rows if word(row, 10)), 0)
            if not model:
                raise NativeDrsError(0xC0040101)
        try:
            sets = self.catalog.vehicle_set_records(model)
        except ToyotaCodecError as error:
            if error.code != 0xA0030107:
                raise
            return ""
        if not sets:
            return ""
        name = sets[0][:18].decode("utf-16le").split("\0", 1)[0]
        return "" if name in self.catalog.registered_sets else name

    def _preferred(self, rows: tuple[bytes, ...], offset: int) -> tuple[bytes, ...]:
        order = {
            5: (2, 3, 1),
            6: (3, 1, 2),
            7: (1, 3, 2),
            8: (3, 2, 1),
            9: (2, 1, 3),
        }.get(self.division, (1, 2, 3))
        for key in order:
            selected = tuple(
                row for row in rows if not self.division or word(row, offset) == key
            )
            if selected:
                return selected
        return ()

    def _names(
        self, rows: tuple[bytes, ...], offset: int
    ) -> tuple[NativeVehicleEntry, ...]:
        levels = {5: 1, 11: 1, 6: 2, 12: 2, 13: 3, 15: 3, 14: 4}
        result = []
        for row in rows:
            for item in self.info_ids:
                self._check()
                level = levels.get(item)
                if level is None:
                    continue
                if self._name_count >= 100_000:
                    raise RecorderError("Too many native vehicle entries")
                self._name_count += 1
                value = word(row, offset + (level - 1) * 2)
                text = ""
                if value:
                    records = self.catalog.collect_item_records(level, value)
                    if len(records) != 1:
                        raise NativeDrsError(0xC0040102)
                    text = self.catalog.language.resolve(
                        struct.unpack_from("<I", records[0])[0]
                    )
                self._append(
                    result, NativeVehicleEntry((1, 0), (item, value), self._text(text))
                )
        return tuple(result)

    def _car(self, model: int) -> tuple[NativeVehicleEntry, ...]:
        assert self._state is not None
        formatted, module = self._state.formatted(), self._module()
        result = []
        for item in self.info_ids:
            self._check()
            if item in formatted:
                value = NativeCoreString(
                    (1, 0), formatted[item].split(b"\0", 1)[0] + b"\0"
                )
            elif item == 4 or (item == 18 and module == "SelectCarVn10Brd_DT.dll"):
                records = (
                    self.catalog.vehicle_name_records(model)
                    if item == 4
                    else self.catalog.vehicle_brand_records(model)
                )
                if len(records) != 1:
                    continue
                value = self._text(
                    self.catalog.language.resolve(
                        struct.unpack_from("<I", records[0])[0]
                    )
                )
            else:
                continue
            self._append(result, NativeVehicleEntry((1, 0), (item,), value))
        return tuple(result)

    def _output(
        self,
        vin: bytes,
        names: tuple[NativeVehicleEntry, ...],
        model: int,
        group: int = 0,
        *,
        car: tuple[NativeVehicleEntry, ...] | None = None,
    ) -> NativeVehicleSelection:
        if car is None:
            car = (
                ()
                if self.session is not None
                and (self.session.category_ids or self.session.option_groups)
                and model == 0
                else self._car(model)
            )
        if (
            self.session is not None
            and (self.session.category_ids or self.session.option_groups)
            and model != 0
        ):
            if self.communication is None or not 0 <= self.protocol <= 0xFF:
                raise RecorderError("Manual resume lost its selected native context")
            selected_bus = self.communication.bus_id
            if not 0 <= selected_bus <= 0xFF or not 0 <= self.option_key <= 0xFFFF:
                raise RecorderError("Manual resume returned invalid shared fields")
            self._check()
            self.session.shared_category = self.communication.profile.category
            self.session.shared_protocol = self.protocol
            self.session.shared_option = self.option_key
            self.session.shared_bus = selected_bus
            self.session.current_model = model
            if self.session.model_list:
                self.session.model_list[0] = model
            else:
                self.session.model_list.append(model)
        if self.session is not None and self.session.option_groups and self.option_key:
            base = NativeVehicleSelection(
                (1, 0),
                NativeCoreString((1, 0), vin.split(b"\0", 1)[0] + b"\0"),
                ((1, 0), (1, 0), (1, 0)),
                names,
                tuple(row for row in car if row.values[0] not in (16, 17, 18)),
                (),
                (0, model),
            )
            self._multi_admit()
            assert self.communication is not None
            return self._multi_initial(
                0,
                base=base,
                caller_values=(
                    self.communication.bus_id,
                    self.communication.profile.category,
                    self.protocol,
                    self.option_key,
                ),
            )
        options = ()
        if self.option_key:
            group = group or 1
            rows = self.catalog.option_records(self.option_key, group)
            if not self.hidden_name:
                valid, invalid = self._valid_options(self.option_key, group)
                if not valid:
                    raise NativeDrsError(0xC0040101)
                rows = tuple(
                    row for row in rows if (word(row, 6), word(row, 8)) not in invalid
                )
            if not rows:
                raise NativeDrsError(0xC0040101)
            option_entries = []
            for row in rows:
                self._append(
                    option_entries,
                    NativeVehicleEntry(
                        (1, 0),
                        (word(row, 8),),
                        self._text(
                            self.catalog.language.resolve(
                                struct.unpack_from("<I", row)[0]
                            )
                        ),
                    ),
                )
            options = tuple(option_entries)
            model = 0
        result = NativeVehicleSelection(
            (1, 0),
            NativeCoreString((1, 0), vin.split(b"\0", 1)[0] + b"\0"),
            ((1, 0), (1, 0), (1, 0)),
            names,
            tuple(row for row in car if row.values[0] not in (16, 17, 18)),
            options,
            (group, model),
        )
        if len(result.encode()) > MAX_RECORDER_BYTES:
            raise RecorderError("Native vehicle context exceeds byte budget")
        self._check()
        self._current = result
        if (
            self.session is not None
            and self.session.option_groups
            and not self.session.category_ids
            and model != 0
        ):
            self._manual_parent_postlude()
            self._check()
        return result

    def select(self) -> NativeVehicleSelection:
        """Execute an automatic request (Index0), with actual native probes."""
        self._check()
        try:
            if self.session is not None and self.session.category_ids:
                self._manual_admit()
                self._consumer_cache_init()
                return self._manual_select()
            self._consumer_cache_init()
            return self._select(0)
        except ToyotaCodecError as error:
            raise NativeDrsError(error.code) from error

    def _select(self, start: int) -> NativeVehicleSelection:
        self._check()
        self._reset_budget(b"")
        candidates = self.catalog.protocol_candidates(self.owner.profile.exception_ids)
        contexts = _NativeVehicleContexts(
            self,
            tuple((candidate.category, candidate.variant) for candidate in candidates),
        )
        while True:
            selection = self.owner.check_protocol(
                candidates, contexts=contexts, start=start
            )
            if selection is None:
                self.option_key = 0
                self.hidden_name = ""
                self._current = NativeVehicleSelection(
                    (1, 0),
                    self._text(""),
                    ((1, 0), (1, 0), (1, 0)),
                    (),
                    (),
                    (),
                    (0, 65535),
                )
                self._check()
                return self._current
            self.communication = self._context(selection.category, selection.variant)
            self.protocol = selection.protocol
            phase = self.protocol & 31
            module = self._module()
            if phase not in (3, 4, 20, 21) or (
                phase == 21 and module == "SelectCarVn10Std_DT.dll"
            ):
                raise UnsupportedRecorderOperation(
                    "Native automatic provider allocation is not defined for this protocol"
                )
            self.option_key, self.hidden_name = 0, ""
            self._state = None
            cached = (
                next(
                    (
                        entry
                        for entry in self.session.vin_entries
                        if entry.category == selection.category
                    ),
                    None,
                )
                if self.session is not None
                else None
            )
            if cached is not None:
                vin = cached.data
            else:
                try:
                    vin = selected_vehicle_vin(
                        self.communication.profile,
                        self.communication.cache,
                        bus_id=selection.variant,
                    )
                except NativeDrsError:
                    vin = None
                if (
                    self.owner.source_build == 18
                    and selection.category != 0x18D
                    and self.protocol == 0x14
                    and not vin
                ):
                    alternate = self._context(0x1C8, 0x12)
                    try:
                        vin = _selected_vehicle_vin103(
                            alternate.profile, alternate.cache, bus_id=0x12
                        )
                    except NativeDrsError:
                        vin = None
                if self.session is not None:
                    self._check()
                    self.session._vin_entries.append(
                        NativeVehicleVinEntry(
                            selection.category, vin if vin is not None else bytes(17)
                        )
                    )
            if vin and vin[0] in (0, 255, 63):
                vin = None
            self._reset_budget(vin or b"")
            if vin:
                matches = self.catalog.raw_matching_vin_vehicles(
                    VinVehicleContext.from_vin(
                        selection.category & 65535, selection.variant, vin
                    )
                )
                rows = self._preferred(
                    tuple(bytes.fromhex(row["raw_hex"]) for row in matches), 4
                )
                if matches:
                    names: list[NativeVehicleEntry] = []
                    for row in rows:
                        if not word(row, 12) and not word(row, 14):
                            raise NativeDrsError(0xC0040102)
                        if self._state is None:
                            self._state = _selected_vehicle_protocol_setup(
                                self.communication, phase
                            )
                        names.extend(self._names((row,), 4))
                    model = 0
                    if len(rows) == 1:
                        model, self.option_key = word(rows[0], 14), word(rows[0], 12)
                        self.hidden_name = self._hidden_vin_name(model, self.option_key)
                    if self._state is None:
                        self._state = _NativeVehicleProtocolState(phase, bytes(0x6C))
                    return self._output(vin, tuple(names), model)
            self._state = _selected_vehicle_protocol_setup(self.communication, phase)
            if phase in (20, 21):
                start = selection.index + 1
                continue
            state = self._state.data
            context = VehicleContext.from_identification_fields(
                selection.category & 65535,
                selection.variant,
                state[0x18:0x2E] if phase == 3 else state[0x50:0x69],
                extended=phase == 4,
            )
            section = self.catalog.management.sections.get(41)
            if section is None:
                raise NativeDrsError(0xA0030107)
            matched, score, best = [], 0, 0
            for row in section.rows(52):
                self._check()
                valid, score = vehicle_matches(row, context, score)
                if not valid:
                    continue
                if score > best:
                    matched.clear()
                    best = score
                matched.append(row)
            allowed = []
            for row in matched:
                model, option = word(row, 50), word(row, 48)
                valid = (
                    self._registered(model)
                    if model
                    else self._valid_options(option, 1)[0]
                )
                if valid:
                    allowed.append(row)
            if not allowed:
                for function in (
                    range(27, 40)
                    if phase == 3
                    else (*range(40, 53), 54, 55, 56, 53, 57)
                ):
                    for frame in self.communication.profile.frame_records(function):
                        self.communication.cache.invalidate_response(
                            frame.frame.request
                        )
                start = selection.index + 1
                continue
            rows = self._preferred(tuple(allowed), 40)
            names = []
            for row in rows:
                if not word(row, 48) and not word(row, 50):
                    raise NativeDrsError(0xC0040102)
                names.extend(self._names((row,), 40))
            model = 0
            if len(rows) == 1:
                model, self.option_key = word(rows[0], 50), word(rows[0], 48)
            return self._output(vin or b"", tuple(names), model)

    def answer(self, group: int, choice: int) -> NativeVehicleSelection:
        """Execute a later7d request with its actual pending Index/SelectId."""
        if any(
            type(value) is not int or not 0 <= value <= 65535
            for value in (group, choice)
        ):
            raise RecorderError("Native option answer must contain ushort integers")
        if self.session is not None and self.session.option_groups:
            self._check()
            self._multi_admit()
            self._consumer_cache_init()
            if (
                group == 0
                or self.session.shared_bus == 0xFF
                or self.session.shared_category == 0xFFFFFFFF
                or self.session.shared_protocol == 0xFF
                or self.session.shared_option == 0xFFFF
            ):
                raise NativeDrsError(0xC0040001)
            try:
                return self._multi_answer(group, choice)
            except ToyotaCodecError as error:
                raise NativeDrsError(error.code) from error
        if self.session is not None and self.session.category_ids:
            self._check()
            self._manual_admit()
            self._consumer_cache_init()
            if (
                group == 0
                or self.session.shared_bus == 0xFF
                or self.session.shared_category == 0xFFFFFFFF
                or self.session.shared_protocol == 0xFF
                or self.session.shared_option == 0xFFFF
            ):
                raise NativeDrsError(0xC0040001)
            if not self.session.shared_option:
                raise NativeDrsError(0xC0040001)
            try:
                return self._manual_answer(group, choice)
            except ToyotaCodecError as error:
                raise NativeDrsError(error.code) from error
        self._consumer_cache_init()
        if (
            not group
            or not self.option_key
            or self.communication is None
            or self._current is None
        ):
            raise RecorderError("No pending native option selection")
        self._check()
        self._reset_budget(b"")
        self.hidden_name = ""
        try:
            rows = self.catalog.option_records(self.option_key, group, choice)
            valid, invalid = self._valid_options(self.option_key, group)
            if not valid:
                raise NativeDrsError(0xC0040101)
            rows = tuple(
                row for row in rows if (word(row, 6), word(row, 8)) not in invalid
            )
            if len(rows) != 1:
                raise NativeDrsError(0xC0040102)
            model, next_group = struct.unpack_from("<HH", rows[0], 10)
            if model:
                self.option_key = 0
                self._state = _selected_vehicle_protocol_setup(
                    self.communication, self.protocol & 31
                )
                return self._output(b"", (), model)
            if next_group:
                return self._output(b"", (), 0, next_group, car=())
            return self._select(
                self.catalog.protocol_resume_index(
                    self.communication.profile.category, self.communication.bus_id
                )
            )
        except ToyotaCodecError as error:
            raise NativeDrsError(error.code) from error


def selected_vehicle_context(
    profile: VehicleProfile,
    *,
    decision_row: int,
    info_ids: tuple[int, ...],
    vin: bytes,
    text_encoding: str,
    source_build: int,
    answers: tuple[int, ...] = (),
    communication: NativeCommunication | None = None,
) -> NativeVehicleSelection:
    """Selected terminal 7d metadata branch, then native GUI/CreateDrs table1 copy.

    Requested diagnostic fields1/2/3/16/17 use the concrete native communication
    channel when provided. This function does not run the
    interactive VIN/option/protocol selection state machine.
    """
    if (
        not isinstance(profile, VehicleProfile)
        or type(source_build) is not int
        or source_build not in (12, 18)
        or not isinstance(info_ids, tuple)
        or len(info_ids) > 100_000
        or any(type(value) is not int or not 0 <= value <= 65535 for value in info_ids)
        or not isinstance(answers, tuple)
        or len(answers) > 100_000
        or any(type(value) is not int or not 0 <= value <= 65535 for value in answers)
        or not isinstance(vin, bytes)
        or len(vin) > 65534
        or not isinstance(text_encoding, str)
    ):
        raise RecorderError("Invalid selected native vehicle context inputs")
    catalog = profile.catalog
    try:
        vehicle = profile.vehicle_name_key
        if (
            type(vehicle) is not int
            or not 1 <= vehicle <= 65535
            or not any(
                system["category"] == profile.category
                for system in catalog.vehicle_systems(vehicle, profile.exception_ids)
            )
            or profile.category_record not in profile.category_records(profile.category)
        ):
            raise RecorderError("Vehicle context does not match the selected profile")
        rows = profile.dll_records(0x7D)
        if not rows:
            raise NativeDrsError(0xC0040101)
        module = rows[0][:80].decode("utf-16le").split("\0", 1)[0]
        if module not in (
            "SelectCarVn10Brd_DT.dll",
            "SelectCarVn10Std_DT.dll",
            "SelectCarTypVn10_DT.dll",
        ):
            raise UnsupportedRecorderOperation(
                "Unsupported selected vehicle context provider"
            )
        category_section = catalog.management.sections.get(47)
        categories = tuple(category_section.rows(8)) if category_section else ()
        decision_section = catalog.management.sections.get(41)
        decisions = tuple(decision_section.rows(52)) if decision_section else ()
        if type(decision_row) is not int or not 0 <= decision_row < len(decisions):
            raise RecorderError("Selected VehicleDecision source row is absent")
        definition = decisions[decision_row]
        if (
            bytes.fromhex(catalog.vehicle_definitions[decision_row]["raw_hex"])
            != definition
        ):
            raise RecorderError(
                "Selected VehicleDecision metadata differs from its source"
            )
        option_key, raw_vehicle = struct.unpack_from("<HH", definition, 48)
        group = 1
        for answer in answers:
            choices = catalog.option_records(option_key, group, answer)
            if len(choices) != 1 or raw_vehicle:
                raise RecorderError(
                    "Selected option answer differs from its native source"
                )
            raw_vehicle, group = struct.unpack_from("<HH", choices[0], 10)
        if raw_vehicle != vehicle:
            raise RecorderError(
                "Selected terminal vehicle differs from its native option path"
            )

        def text(value: str) -> NativeCoreString:
            try:
                raw = (value.split("\0", 1)[0] + "\0").encode(text_encoding)
            except (LookupError, UnicodeError) as exc:
                raise RecorderError("Native context text encoding failed") from exc
            if len(raw) > 65535:
                raise RecorderError("Native context string exceeds ushort byte length")
            return NativeCoreString((1, 0), raw)

        budget = 38 + len(vin) + 1

        def add(entries: list[NativeVehicleEntry], entry: NativeVehicleEntry) -> None:
            nonlocal budget
            budget += 10 + 2 * len(entry.values) + len(entry.text.data)
            if budget > MAX_RECORDER_BYTES:
                raise RecorderError("Native vehicle context exceeds byte budget")
            entries.append(entry)

        names: list[NativeVehicleEntry] = []
        car: list[NativeVehicleEntry] = []
        level = 0
        diagnostics: dict[int, bytes] | None = None
        for info_id in info_ids:
            if info_id in (1, 2, 3, 16, 17):
                if communication is None:
                    raise UnsupportedRecorderOperation(
                        "Requested vehicle context field requires native protocol observations"
                    )
                if (
                    communication.profile is not profile
                    or communication.source_build != source_build
                ):
                    raise RecorderError(
                        "Native context communication source differs from selected profile"
                    )
                failed_probe = 0
                if diagnostics is None:
                    diagnostics, failed_probe = _selected_vehicle_diagnostics(
                        communication, module
                    )
                raw = b"" if failed_probe else diagnostics[info_id]
                add(
                    car,
                    NativeVehicleEntry(
                        (1, 0),
                        (info_id,),
                        NativeCoreString((1, 0), raw.split(b"\0", 1)[0] + b"\0"),
                    ),
                )
                continue
            if info_id == 4:
                records = catalog.vehicle_name_records(vehicle)
                value = text("")
                if len(records) == 1:
                    value = text(
                        catalog.language.resolve(
                            struct.unpack_from("<I", records[0])[0]
                        )
                    )
                add(car, NativeVehicleEntry((1, 0), (4,), value))
                continue
            if info_id == 18 and module == "SelectCarVn10Brd_DT.dll":
                brands = catalog.vehicle_brand_records(vehicle)
                value = text("")
                if len(brands) == 1:
                    value = text(
                        catalog.language.resolve(struct.unpack_from("<I", brands[0])[0])
                    )
                add(car, NativeVehicleEntry((1, 0), (18,), value))
                continue
            if category_section is None:
                raise NativeDrsError(0xA0030107)
            if not categories:
                raise NativeDrsError(0xC0040101)
            category = next(
                (
                    row
                    for row in categories
                    if struct.unpack_from("<H", row, 6)[0] == info_id
                ),
                None,
            )
            # All six native15b0 helpers retain the previous level on a scan miss.
            if category is not None:
                level = struct.unpack_from("<H", category, 4)[0]
            if level == 0:
                raise NativeDrsError(0xC0040001)
            if level > 4:
                raise NativeDrsError(0xC0040102)
            value = struct.unpack_from("<H", definition, 38 + 2 * level)[0]
            if value == 0:
                # Native zero-value path retains the level as ID; the API/GUI then assigns an empty char*.
                add(
                    names,
                    NativeVehicleEntry((1, 0), (level, 0), text("")),
                )
                continue
            items = catalog.collect_item_records(level, value)
            if len(items) != 1:
                raise NativeDrsError(0xC0040102)
            add(
                names,
                NativeVehicleEntry(
                    (1, 0),
                    (info_id, value),
                    text(
                        catalog.language.resolve(struct.unpack_from("<I", items[0])[0])
                    ),
                ),
            )
        result = NativeVehicleSelection(
            (1, 0),
            NativeCoreString((1, 0), vin.split(b"\0", 1)[0] + b"\0"),
            ((1, 0), (1, 0), (1, 0)),
            tuple(names),
            # GUI6b9bb0 exports CarInfo after dropping its display-only fields.
            tuple(entry for entry in car if entry.values[0] not in (16, 17, 18)),
            (),
            (0, vehicle),
        )
        result.encode()
        return result
    except ToyotaCodecError as exc:
        raise NativeDrsError(exc.code) from exc
    except RecorderError:
        raise
    except (ValueError, UnicodeError) as exc:
        raise RecorderError(
            "Malformed selected native vehicle context metadata"
        ) from exc
