"""Source-bound stored resources and native DDR acquisition primitives."""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace
from hashlib import sha256
from os import fstat
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from scripts import snapshot, tse_reports
from scripts.toyota import ToyotaCodecError

if TYPE_CHECKING:
    from scripts.frame_transport import NativeFrameOperations
    from scripts.monitor_support import MonitorSupportCache, TemporaryResponseCache
    from scripts.native_communication import NativeCommunication, NativeFrameController
    from scripts.profiles import SelectedFrame, VehicleProfile
    from scripts.toyota_session import Limits

FAMILIES = ("MILMessage", "MktMonRam", "MktMonRamSSR")


def _toyota_profile(profile: object) -> VehicleProfile:
    """DDR resources require the actual Toyota DDB model, not another protocol profile."""
    from scripts.profiles import VehicleProfile

    if not isinstance(profile, VehicleProfile):
        raise TypeError("DDR resources require a selected Toyota VehicleProfile")
    return profile


@dataclass(frozen=True)
class StoredResource:
    path: tuple[int, ...]
    strings: tuple[bytes, ...]
    identifier: int | None
    buffers: tuple[bytes, ...]


@dataclass(frozen=True)
class CaptureSection:
    family: str
    source: str
    source_sha256: str
    raw: bytes
    resources: tuple[StoredResource, ...]
    file_sha256: str | None = None
    offset: int | None = None

    def summary(self) -> dict:
        """Sizes and provenance only: raw payloads are not engineering values."""
        return {
            "family": self.family,
            "source": self.source,
            "source_sha256": self.source_sha256,
            "file_sha256": self.file_sha256,
            "offset": self.offset,
            "coverage": "stored-structure-and-opaque-payload-preservation",
            "payload_semantics": "unresolved",
            "native_semantics": "mil-message-information"
            if self.family == "MILMessage"
            else "market-monitor-ram",
            "resources": [
                {
                    "source_path": list(row.path),
                    "role": ("message_screen", "confirmation_screen")[row.path[0]]
                    if self.family == "MILMessage"
                    else "ram_block",
                    "string_bytes": [len(value) for value in row.strings],
                    "identifier_raw": row.identifier,
                    "buffers": [
                        {"size": len(value), "sha256": sha256(value).hexdigest()}
                        for value in row.buffers
                    ],
                }
                for row in self.resources
            ],
        }


def capture_section(
    family: str,
    raw: bytes,
    *,
    source: str,
    cancelled: Callable[[], bool] | None = None,
) -> CaptureSection:
    """Inspect an actual native section, retaining every source byte.

    `recorded_unverified` establishes provenance, not physical authenticity.
    MILMessage holds native MIL message/confirmation screens.
    No mapping to diagnostic DDR producer DLL outputs has been established.
    """
    if source not in ("authored_synthetic", "recorded_unverified"):
        raise ValueError("Capture source must be explicit")
    if family not in FAMILIES:
        raise ValueError("Unsupported stored capture family")

    def check_cancelled() -> None:
        if cancelled is not None and cancelled():
            raise InterruptedError("Stored capture inspection cancelled")

    check_cancelled()
    section = tse_reports.decode_section(family, raw)
    check_cancelled()
    resources = []
    if family == "MILMessage":
        for group, rows in enumerate(section.records):
            for index, row in enumerate(rows):
                check_cancelled()
                resources.append(StoredResource((group, index), row[:3], None, row[3:]))
    else:
        for group, (name, blocks) in enumerate(section.records):
            for index, block in enumerate(blocks):
                check_cancelled()
                resources.append(
                    StoredResource(
                        (group, index),
                        (name,),
                        block[0] if section.version > 0x1000 else None,
                        (block[-1],),
                    )
                )
            if not blocks:
                resources.append(StoredResource((group,), (name,), None, ()))
    check_cancelled()
    return CaptureSection(
        family, source, sha256(raw).hexdigest(), raw, tuple(resources)
    )


def capture_file(
    file: snapshot.TSEFile,
    family: str,
    *,
    source: str,
    cancelled: Callable[[], bool] | None = None,
) -> CaptureSection:
    """Bind the native global index selection to immutable full-file provenance."""
    if family not in FAMILIES:
        raise ValueError("Unsupported stored capture family")
    if cancelled is not None and cancelled():
        raise InterruptedError("Stored capture inspection cancelled")
    offset, _section = tse_reports.select_report_section(file, family)
    result = capture_section(
        family, snapshot.tse_section(file, offset), source=source, cancelled=cancelled
    )
    return replace(result, file_sha256=sha256(file.source).hexdigest(), offset=offset)


@dataclass(frozen=True)
class RamFrame:
    """Literal tagGET_RAM_FRAME_DATA: three selector bytes, padding, u32 address."""

    raw: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.raw, bytes) or len(self.raw) != 8:
            raise ValueError("Native RAM frame must contain exactly eight bytes")

    @property
    def address(self) -> int:
        return int.from_bytes(self.raw[4:], "little")

    def at(self, address: int) -> RamFrame:
        if type(address) is not int or not 0 <= address <= 0xFFFFFFFF:
            raise ValueError("Native RAM address must fit uint32")
        return RamFrame(self.raw[:4] + address.to_bytes(4, "little"))


def ram_request(template: bytes, frame: RamFrame, length: int) -> bytes:
    """GetRamDataByte 0x46440: selected A1, selector/size and big-endian address."""
    from scripts.toyota import INVALID_RECORD, ToyotaCodecError

    if not isinstance(template, bytes) or not 5 <= len(template) <= 0xFFFF:
        raise ToyotaCodecError(
            "Native RAM A1 template needs five bytes", INVALID_RECORD
        )
    if type(length) is not int or not 1 <= length <= 255:
        raise ValueError("Native RAM byte-read size must be 1..255")
    # Native x86 shifts mask CL to five bits, including unusually wide templates.
    address = bytes(
        (frame.address >> ((index * 8) & 31)) & 255
        for index in reversed(range(len(template) - 3))
    )
    return template[:1] + bytes((frame.raw[2], length)) + address


def ram_payload(request: bytes, reply: bytes) -> bytes:
    """GetRamDataByte validates service, selector, length and every address byte."""
    from scripts.toyota import INVALID_REPLY, ToyotaCodecError

    if not isinstance(request, bytes) or len(request) < 5:
        raise ValueError("Native RAM request is truncated")
    if (
        not isinstance(reply, bytes)
        or len(reply) != len(request) + request[2]
        or reply[:1] != bytes((request[0] | 0x40,))
        or reply[1 : len(request)] != request[1:]
    ):
        raise ToyotaCodecError(
            "Native RAM response does not echo request", INVALID_REPLY
        )
    return reply[len(request) :]


@dataclass(frozen=True)
class RamQuery:
    """One concrete selected native A1 exchange, including its native settings."""

    ecu: str
    frame: RamFrame
    request: bytes
    selected: SelectedFrame
    bus_id: int | None = None


@dataclass(frozen=True)
class RamTransaction:
    query: RamQuery
    reply: bytes
    status: int


class NativeRamReader:
    """CCmdGetRamDataBlock P4 cached and DdrReal reads over typed primitive I/O."""

    def __init__(
        self,
        profile: VehicleProfile,
        exchange: Callable[[RamQuery], bytes],
        *,
        ecu: str,
        frame: RamFrame,
        block_size: int,
        bus_id: int | None = None,
        limits: Limits | None = None,
        cancelled: Callable[[], bool] | None = None,
        clock: Callable[[], float] = time.monotonic,
        source_build: int = 18,
    ):
        from scripts.toyota import MISSING_RECORD, ToyotaCodecError
        from scripts.toyota_session import Limits

        if type(source_build) is not int or source_build not in (12, 18):
            raise ValueError("Native RAM source build must be12 or18")
        self.source_build = source_build
        if not isinstance(ecu, str) or not ecu or len(ecu) > 128:
            raise ValueError("Native RAM reader needs an explicit ECU label")
        if type(block_size) is not int or not 1 <= block_size <= 255:
            raise ValueError("Native RAM block size must be 1..255")
        if bus_id is not None and (type(bus_id) is not int or not 0 <= bus_id <= 65535):
            raise ValueError("Observed native RAM bus identity must fit ushort")
        frames = profile.frame_records(0xA1)
        if not frames:
            raise ToyotaCodecError("Selected native A1 frame is absent", MISSING_RECORD)
        self.selected = frames[0]
        # Validate the selected template before the first exchange.
        ram_request(self.selected.frame.request, frame, block_size)
        self.profile, self.exchange, self.ecu = profile, exchange, ecu
        self.vehicle_sha256 = profile.database.sha256
        self.management_sha256 = profile.catalog.management.sha256
        self.category, self.exception_ids = profile.category, profile.exception_ids
        self.frame, self.block_size = frame, block_size
        self.bus_id = bus_id
        self.limits, self.cancelled = limits or Limits(), cancelled
        self.clock = clock
        self._cache: dict[int, bytes] = {}
        self._transactions: list[RamTransaction] = []
        self._transaction_bytes = 0
        self._deadline, self._remaining = 0.0, 0
        self._operation_active = False
        self._pcs_failed = False

    @classmethod
    def from_communication(
        cls, communication: NativeCommunication, *, frame: RamFrame, block_size: int
    ) -> NativeRamReader:
        """Bind the real selected Common send/receive implementation to RAM reads."""
        from scripts.native_communication import CommunicationError
        from scripts.toyota_session import NativeStatus

        if communication.source_build not in (12, 18):
            raise ValueError("Native RAM producer source is proven for build12/18")

        def exchange(query: RamQuery) -> bytes:
            if query.ecu != communication.ecu or query.bus_id != communication.bus_id:
                raise ValueError(
                    "RAM query differs from retained communication context"
                )
            try:
                return communication.cache.transaction(
                    query.selected, query.request, cached=False
                )
            except CommunicationError as error:
                raise NativeStatus(error.code, error.response) from error

        return cls(
            _toyota_profile(communication.profile),
            exchange,
            ecu=communication.ecu,
            bus_id=communication.bus_id,
            frame=frame,
            block_size=block_size,
            limits=communication.limits,
            cancelled=communication.cancelled,
            clock=communication.clock,
            source_build=communication.source_build,
        )

    @property
    def transactions(self) -> tuple[RamTransaction, ...]:
        return tuple(self._transactions)

    @contextmanager
    def _operation(self) -> Iterator[None]:
        """Keep one deadline/exchange budget across a producer's multiple reads."""
        if self._operation_active:
            yield
            return
        self._deadline = self.clock() + self.limits.seconds
        self._remaining = self.limits.exchanges
        self._operation_active = True
        try:
            yield
        finally:
            self._operation_active = False

    def _check(self) -> None:
        from scripts.toyota_session import Cancelled, SessionError

        if self.cancelled is not None and self.cancelled():
            raise Cancelled("Native RAM read cancelled")
        now = self.clock()
        if not math.isfinite(now) or now >= self._deadline:
            raise SessionError("Native RAM read deadline exceeded")
        if (
            self.profile.database.sha256 != self.vehicle_sha256
            or self.profile.catalog.management.sha256 != self.management_sha256
            or self.profile.category != self.category
            or self.profile.exception_ids != self.exception_ids
        ):
            raise SessionError("Selected native RAM source changed during capture")

    def _record(self, query: RamQuery, reply: bytes, status: int) -> None:
        from scripts.toyota_session import SessionError

        size = len(query.request) + len(reply)
        if size > snapshot.MAX_BYTES - self._transaction_bytes:
            raise SessionError("Native RAM recording byte budget exhausted")
        self._transactions.append(RamTransaction(query, reply, status))
        self._transaction_bytes += size

    def _read(self, address: int, length: int) -> bytes:
        from scripts.toyota import ToyotaCodecError
        from scripts.toyota_session import NativeStatus, SessionError

        self._check()
        if self._remaining == 0 or len(self._transactions) >= 100_000:
            raise SessionError("Native RAM exchange budget exhausted")
        self._remaining -= 1
        frame = self.frame.at(address)
        query = RamQuery(
            self.ecu,
            frame,
            ram_request(self.selected.frame.request, frame, length),
            self.selected,
            self.bus_id,
        )
        if (
            2 * len(query.request) + length
            > snapshot.MAX_BYTES - self._transaction_bytes
        ):
            raise SessionError("Native RAM recording byte budget exhausted")
        try:
            reply = self.exchange(query)
        except NativeStatus as error:
            self._record(query, error.reply, error.code)
            raise
        if not isinstance(reply, bytes):
            raise TypeError("Native RAM exchange must return bytes")
        try:
            payload = ram_payload(query.request, reply)
        except ToyotaCodecError as error:
            self._record(query, reply, error.code)
            raise
        self._record(query, reply, 0)
        self._check()
        return payload

    def _read_block(self, address: int, length: int, *, pcs: bool) -> bytes:
        from scripts.toyota import ToyotaCodecError

        try:
            result = self._read(address, length)
        except ToyotaCodecError:
            self._check()
            if not pcs or self._pcs_failed:
                raise
            # PCSDdr 45f80/46b10: tolerate one failed I/O, retain it in recording.
            self._pcs_failed = True
            return b"\xff" * length
        if pcs:
            self._pcs_failed = False
        return result

    def read(
        self, address: int, length: int, *, real: bool = False, pcs: bool = False
    ) -> bytes:
        """P4/PCSDdr cached reads or their exact uncached Real variants."""
        from scripts.toyota import ToyotaCodecError

        if self.source_build != 18:
            raise NotImplementedError("Cached/Real RAM variants require native18 proof")
        self.frame.at(address)
        maximum = snapshot.MAX_BYTES if real else 0xFFFF
        if type(length) is not int or not 1 <= length <= maximum:
            raise ValueError("Native RAM read length exceeds its operation bound")
        if type(real) is not bool:
            raise ValueError("Native RAM real-read selector must be boolean")
        if type(pcs) is not bool:
            raise ValueError("Native RAM PCS selector must be boolean")
        if not self._operation_active:
            self._deadline = self.clock() + self.limits.seconds
            self._remaining = self.limits.exchanges
        self._check()
        if real and address + length >= 0xFFFFFFFF:
            raise ToyotaCodecError("Native RAM address range overflows", 0xA0041201)
        if real:
            return b"".join(
                self._read_block(
                    address + offset, min(self.block_size, length - offset), pcs=pcs
                )
                for offset in range(0, length, self.block_size)
            )
        bank, low = address & 0xFFFF0000, address & 0xFFFF
        start = bank | (low // self.block_size * self.block_size)
        last = bank | ((low + length - 1) // self.block_size * self.block_size)
        if last < start or (last - start) // self.block_size >= 100_000:
            raise ValueError("Native aligned RAM range exceeds bounded cache work")
        blocks = []
        for block in range(start, last + 1, self.block_size):
            self._check()
            if block not in self._cache:
                if (
                    self.block_size
                    > snapshot.MAX_BYTES - len(self._cache) * self.block_size
                ):
                    raise ValueError("Native RAM cache byte budget exceeded")
                self._cache[block] = self._read_block(block, self.block_size, pcs=pcs)
            blocks.append(self._cache[block])
        offset = (address - start) & 255
        return b"".join(blocks)[offset : offset + length]

    def read_end_trim(
        self, length: int, *, cancelled: Callable[[], bool] | None = None
    ) -> bytes:
        """Native12:31690/18:459D0 uncached P4EndTrim, with FF failed-I/O chunks.

        Start at the exact frame address; trim only the final request's length.
        Native GetRamDataByte sets its failure flag immediately before I/O and
        clears it only after complete reply validation. Those failures become
        FF bytes and acquisition continues; host cancellation/bounds stay visible.
        """
        from scripts.toyota import ToyotaCodecError
        from scripts.toyota_session import Cancelled

        if type(length) is not int or not 0 <= length <= snapshot.MAX_BYTES:
            raise ValueError("Native EndTrim length exceeds bounded DWORD storage")
        if cancelled is not None and not callable(cancelled):
            raise TypeError("Native EndTrim cancellation requires a callback")
        if not length:
            return b""
        result = bytearray()
        with self._operation():
            for offset in range(0, length, self.block_size):
                self._check()
                if cancelled is not None and cancelled():
                    raise Cancelled("Native EndTrim RAM read cancelled")
                size = min(self.block_size, length - offset)
                if self.frame.address >= 0xFFFFFFFF - offset - size:
                    raise ToyotaCodecError(
                        "Native RAM address range overflows", 0xA0041201
                    )
                try:
                    payload = self._read(self.frame.address + offset, size)
                except ToyotaCodecError:
                    self._check()
                    payload = b"\xff" * size
                result.extend(payload)
        return bytes(result)


# GetDDRInfo_DT 0x2dc0 chooses these exact table banks from an observed spec value.
_DDR_BANKS = {2: 50, 3: 50, 5: 82, 6: 92, 7: 96, 8: 100, 9: 104, 11: 119, 12: 123}


def ddr_bits(raw: bytes, start: int, end: int) -> int:
    """GetDDRInfo_DT 0x3ed0: inclusive MSB-first bit positions, at most four bytes."""
    if (
        not isinstance(raw, bytes)
        or not 1 <= len(raw) <= 4
        or type(start) is not int
        or type(end) is not int
        or not 0 <= start <= end < len(raw) * 8
    ):
        raise ValueError("DDR value needs 1..4 bytes and valid inclusive bit bounds")
    return (int.from_bytes(raw, "big") >> (len(raw) * 8 - end - 1)) & (
        (1 << (end - start + 1)) - 1
    )


def ddr_timeline_values(
    raw: bytes, count: int, monitor_record: bytes
) -> tuple[int, ...]:
    """Normal 0x3890: literal native byte windows and MSB-first extraction.

    Native window offsets wrap at a byte. Non-byte strides retain the native
    modulo/window behavior; this is not a guessed continuously packed series.
    """
    from scripts.support import word

    if (
        not isinstance(raw, bytes)
        or not isinstance(monitor_record, bytes)
        or len(monitor_record) != 48
        or type(count) is not int
        or not 0 <= count <= 65535
    ):
        raise ValueError(
            "DDR timeline requires exact selected monitor and ushort count"
        )
    read_start, read_end = word(monitor_record, 32), word(monitor_record, 34)
    stride = read_end - read_start + 1
    if not 1 <= stride <= 32:
        raise ValueError("DDR timeline stride exceeds native scalar window")
    size = max(1, (count * stride + 7) // 8)
    if len(raw) != size or size > 280:
        raise ValueError(
            "DDR timeline bytes exceed native fixed buffer or selected size"
        )
    window = (stride + 7) // 8
    per_window = window * 8 // stride
    start, end = word(monitor_record, 28), word(monitor_record, 30)
    result = []
    for index in range(count):
        offset = (index * stride >> 3) & 255
        shift = index % per_window * stride
        result.append(
            ddr_bits(
                raw[offset : offset + window],
                (start + shift) & 65535,
                (end + shift) & 65535,
            )
        )
    return tuple(result)


@dataclass(frozen=True)
class DdrSamplePlan:
    monitor_id: int
    address_record: bytes
    monitor_record: bytes
    source_sha256: str
    category: int
    exception_ids: tuple[int, ...]

    def __post_init__(self) -> None:
        if (
            type(self.monitor_id) is not int
            or not 0 <= self.monitor_id <= 0xFFFF
            or not isinstance(self.address_record, bytes)
            or len(self.address_record) != 16
            or not isinstance(self.monitor_record, bytes)
            or len(self.monitor_record) != 48
        ):
            raise ValueError("DDR sample needs exact selected address/monitor records")

    def address(
        self, reader: NativeRamReader, *, base_address: int, record_index: int
    ) -> int:
        """Resolve the native address only in this plan's selected context."""
        if (
            reader.profile.database.sha256 != self.source_sha256
            or reader.profile.category != self.category
            or reader.profile.exception_ids != self.exception_ids
            or reader.frame.raw[:3] != b"\x01\x00\x04"
        ):
            raise ValueError(
                "DDR sample must use its selected profile and native frame"
            )
        if type(base_address) is not int or not 0 <= base_address <= 0xFFFFFFFF:
            raise ValueError("Observed DDR base address must fit uint32")
        if type(record_index) is not int or not 0 <= record_index <= 255:
            raise ValueError("Observed DDR record index must fit byte")
        address = (
            (record_index << 16) | int.from_bytes(self.address_record[:4], "little")
        ) + base_address
        if address > 0xFFFFFFFF:
            raise ValueError("DDR sample address overflows native width")
        return address

    def capture(
        self, reader: NativeRamReader, *, base_address: int, record_index: int
    ) -> tuple[bytes, int]:
        """Native 0x3405..0x3507 selected scalar capture; no physical scaling guess."""
        from scripts.support import word

        address = self.address(
            reader, base_address=base_address, record_index=record_index
        )
        start, end = word(self.monitor_record, 28), word(self.monitor_record, 30)
        read_start, read_end = (
            word(self.monitor_record, 32),
            word(self.monitor_record, 34),
        )
        if read_end < read_start:
            raise ValueError("DDR monitor read bit range is reversed")
        size = (read_end - read_start) // 8 + 1
        if not 1 <= size <= 4 or not 0 <= start <= end < size * 8:
            raise ValueError("DDR monitor bit range exceeds native scalar reader")
        raw = reader.read(address, size)
        return raw, ddr_bits(raw, start, end)


@dataclass(frozen=True)
class DdrRecordPlan:
    spec_value: int
    table_slots: tuple[int, int, int, int]
    trigger_record: bytes
    prefix_address_records: tuple[bytes, ...]
    samples: tuple[DdrSamplePlan, ...]
    source_sha256: str
    category: int
    exception_ids: tuple[int, ...]
    monitor_order: tuple[int, ...]


@dataclass(frozen=True)
class DdrRecordSamples:
    """Captured header and unsigned monitor values before native transformations."""

    header: bytes
    plan: DdrRecordPlan
    values: tuple[tuple[int, bytes, int], ...]

    @property
    def marker_present(self) -> bool:
        """Native 0x3f80 branch flag: selected ID's first scalar byte is 0x55."""
        return any(
            (17 <= identifier <= 36 or 55 <= identifier <= 58 or 71 <= identifier <= 98)
            and value & 255 == 0x55
            for identifier, _, value in self.values
        )

    @property
    def ordered_values(self) -> tuple[tuple[int, bytes, int], ...]:
        """Native 0x4090: selected monitor order, first matching captured ID."""
        first = {
            index + 1: (index + 1, self.header[index : index + 1], value)
            for index, value in enumerate(self.header)
        }
        for value in self.values:
            first.setdefault(value[0], value)
        return tuple(first[key] for key in self.plan.monitor_order if key in first)


@dataclass(frozen=True)
class DdrTimelineSamples:
    plan: DdrSamplePlan
    raw: bytes
    values: tuple[int, ...]


def capture_ddr_timeline_samples(
    reader: NativeRamReader,
    record: DdrRecordSamples,
    *,
    base_address: int,
    record_index: int,
) -> tuple[DdrTimelineSamples, ...] | None:
    """Native 0x3890 selected address-kind2 timelines; failed RAM skips record."""
    from scripts.support import word
    from scripts.toyota import MISSING_RECORD, ToyotaCodecError

    plan = record.plan
    if (
        reader.block_size != 56
        or reader.frame.raw[:3] != b"\x01\x00\x04"
        or reader.profile.database.sha256 != plan.source_sha256
        or reader.profile.category != plan.category
        or reader.profile.exception_ids != plan.exception_ids
        or not isinstance(record.header, bytes)
        or len(record.header) != 2
    ):
        raise ValueError("DDR timeline differs from selected record capture context")
    rows = reader.profile.ddr_records(plan.table_slots[2], record.header[0], 2)
    if not rows:
        raise ToyotaCodecError(
            "Selected DDR timeline addresses are absent", MISSING_RECORD
        )
    if len(rows) > 100_000:
        raise ValueError("DDR timeline count exceeds node budget")
    count = sum(word(plan.trigger_record, offset) for offset in (16, 18, 20)) & 65535
    result = []
    with reader._operation():
        reader._cache.clear()
        reader._pcs_failed = False
        for row in rows:
            identifier = word(row, 4)
            monitors = reader.profile.ddr_records(plan.table_slots[0], identifier)
            if not monitors:
                raise ToyotaCodecError(
                    "Selected DDR timeline monitor is absent", MISSING_RECORD
                )
            sample = DdrSamplePlan(
                identifier,
                row,
                monitors[0],
                plan.source_sha256,
                plan.category,
                plan.exception_ids,
            )
            address = sample.address(
                reader, base_address=base_address, record_index=record_index
            )
            stride = word(monitors[0], 34) - word(monitors[0], 32) + 1
            size = max(1, (count * stride + 7) // 8)
            if not 1 <= stride <= 32 or size > 280:
                raise ValueError("Selected DDR timeline exceeds native fixed buffer")
            try:
                raw = reader.read(address, size)
            except ToyotaCodecError:
                return None
            result.append(
                DdrTimelineSamples(
                    sample, raw, ddr_timeline_values(raw, count, monitors[0])
                )
            )
    return tuple(result)


def capture_ddr_record_samples(
    reader: NativeRamReader, *, spec_value: int, base_address: int, record_index: int
) -> DdrRecordSamples | None:
    """Normal producer 0x3090 raw record acquisition, before timeline/filter steps.

    Unknown headers and failed RAM reads are skipped natively; original failed
    transactions remain recorded. No finished history record is
    claimed until the separate timeline, invalidation and conversion steps run.
    """
    from scripts.toyota import ToyotaCodecError

    if reader.block_size != 0x38 or reader.frame.raw[:3] != b"\x01\x00\x04":
        raise ValueError(
            "Normal DDR record capture needs native frame and 56-byte blocks"
        )
    if type(spec_value) is not int or spec_value not in _DDR_BANKS:
        raise ToyotaCodecError("Unsupported observed DDR specification", 0xA0041001)
    if type(base_address) is not int or not 0 <= base_address <= 0xFFFFFFFF:
        raise ValueError("Observed DDR base address must fit uint32")
    if type(record_index) is not int or not 0 <= record_index <= 255:
        raise ValueError("Observed DDR record index must fit byte")
    address = base_address + (record_index << 16)
    if address >= 0xFFFFFFFF:
        raise ValueError("DDR header address overflows native width")
    with reader._operation():
        # The native helper constructs its block cache anew for each record.
        reader._cache.clear()
        reader._pcs_failed = False
        try:
            header = reader.read(address, 1) + reader.read(address + 1, 1)
        except ToyotaCodecError:
            return None
        if not reader.profile.ddr_records(_DDR_BANKS[spec_value] + 1, *header):
            return None
        plan = selected_ddr_record_plan(reader.profile, spec_value, header)
        values = []
        for sample in plan.samples:
            try:
                captured = sample.capture(
                    reader, base_address=base_address, record_index=record_index
                )
            except ToyotaCodecError:
                return None
            values.append((sample.monitor_id, *captured))
        return DdrRecordSamples(header, plan, tuple(values))


@dataclass(frozen=True)
class DdrValueSeries:
    """Native DDR ID/kind and ordered (raw uint32 value, raw uint32 flag) pairs."""

    identifier: int
    kind: int
    samples: tuple[tuple[int, int], ...]

    def __post_init__(self) -> None:
        if (
            type(self.identifier) is not int
            or not 0 <= self.identifier <= 65535
            or self.kind not in (1, 2)
            or type(self.kind) is not int
            or not isinstance(self.samples, tuple)
            or len(self.samples) > 100_000
            or any(
                not isinstance(pair, tuple)
                or len(pair) != 2
                or any(
                    type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                    for value in pair
                )
                for pair in self.samples
            )
        ):
            raise ValueError(
                "DDR series must retain bounded native ID/kind/value/flag fields"
            )


def ordered_ddr_series(
    record: DdrRecordSamples, timelines: tuple[DdrTimelineSamples, ...]
) -> tuple[DdrValueSeries, ...]:
    """Native4090 joins scalar and timeline IDs before first-match ordering."""
    if len(record.values) + len(timelines) > 100_000:
        raise ValueError("DDR series count exceeds node allowance")
    first = {
        index + 1: DdrValueSeries(index + 1, 1, ((value, 0),))
        for index, value in enumerate(record.header)
    }
    for identifier, _, value in record.values:
        first.setdefault(identifier, DdrValueSeries(identifier, 1, ((value, 0),)))
    for timeline in timelines:
        if (
            timeline.plan.source_sha256 != record.plan.source_sha256
            or timeline.plan.category != record.plan.category
            or timeline.plan.exception_ids != record.plan.exception_ids
        ):
            raise ValueError("DDR timeline source differs from selected record")
        first.setdefault(
            timeline.plan.monitor_id,
            DdrValueSeries(
                timeline.plan.monitor_id,
                2,
                tuple((value, 0) for value in timeline.values),
            ),
        )
    return tuple(first[key] for key in record.plan.monitor_order if key in first)


def mark_ddr_unchecked(
    series: tuple[DdrValueSeries, ...],
) -> tuple[DdrValueSeries, ...]:
    """Native42d0 sets flag1 except IDs1/2, scalar sample0 only."""
    return tuple(
        replace(
            row,
            samples=tuple(
                (
                    value,
                    1
                    if row.identifier not in (1, 2) and (row.kind != 1 or index == 0)
                    else flag,
                )
                for index, (value, flag) in enumerate(row.samples)
            ),
        )
        for row in series
    )


def apply_ddr_marker_flags(
    profile: VehicleProfile,
    record: DdrRecordSamples,
    series: tuple[DdrValueSeries, ...],
) -> tuple[DdrValueSeries, ...]:
    """Native4390 marker stage:4430/4CF0 or B260; flags remain raw values."""
    from scripts.support import word
    from scripts.toyota import INVALID_RECORD, ToyotaCodecError

    plan = record.plan
    if (
        profile.database.sha256 != plan.source_sha256
        or profile.category != plan.category
        or profile.exception_ids != plan.exception_ids
        or len(series) + sum(len(row.samples) for row in series) > 100_000
    ):
        raise ValueError("DDR marker source differs or exceeds node allowance")
    values = [list(row.samples) for row in series]

    def flag_at(
        row_index: int, sample_index: int, flag: int, *, only_zero: bool = False
    ) -> None:
        if not 0 <= sample_index < len(values[row_index]):
            raise ToyotaCodecError(
                "DDR marker index exceeds captured series", INVALID_RECORD
            )
        value, previous = values[row_index][sample_index]
        if not only_zero or previous == 0:
            values[row_index][sample_index] = (value, flag)

    def scalar(identifier: int) -> int | None:
        for index, row in enumerate(series):
            if row.identifier == identifier:
                if not values[index]:
                    raise ToyotaCodecError(
                        "DDR marker scalar is absent", INVALID_RECORD
                    )
                return values[index][0][0]
        return None

    first_count, second_count, third_count = (
        word(plan.trigger_record, offset) for offset in (16, 18, 20)
    )
    if third_count >= 2:
        # Source4430 repeats ID19 ten times; preserving its native numbering is essential.
        marker_ids = (
            (18,)
            + (19,) * 10
            + tuple(range(20, 37))
            + tuple(range(55, 59))
            + tuple(range(95, 99))
        )
        present = []
        for identifier in marker_ids:
            found = None
            for row_index, row in enumerate(series):
                if row.kind == 1 and row.identifier == identifier:
                    if not values[row_index]:
                        raise ToyotaCodecError(
                            "DDR marker scalar is absent", INVALID_RECORD
                        )
                    found = values[row_index][0][0]
            if found is not None:
                present.append((identifier, found))
        for row_index, row in enumerate(series):
            if row.kind == 2:
                for sample_index, (_, marker) in enumerate(present):
                    if marker != 0x55:
                        flag_at(row_index, sample_index, 1)
        linked_markers = (
            tuple(range(31, 37)) + tuple(range(55, 59)) + tuple(range(95, 99))
        )
        linked_ids = (
            tuple(range(37, 55, 3)) + tuple(range(59, 71, 3)) + tuple(range(99, 111, 3))
        )
        for marker_id, linked_id in zip(linked_markers, linked_ids, strict=True):
            if any(
                identifier == marker_id and marker != 0x55
                for identifier, marker in present
            ):
                for row_index, row in enumerate(series):
                    if row.kind == 1 and linked_id <= row.identifier <= linked_id + 2:
                        flag_at(row_index, 0, 1)
        if third_count - 1 > 14:
            raise ToyotaCodecError(
                "DDR marker pairs exceed native14-row storage", INVALID_RECORD
            )
        for pair_index, identifier in enumerate(linked_ids[: third_count - 1]):
            left, right = scalar(identifier), scalar(identifier + 1)
            if profile.ddr_records(
                plan.table_slots[1], (left or 0) & 255, (right or 0) & 255
            ):
                continue
            sample_index = first_count + second_count + 1 + pair_index
            for row_index, row in enumerate(series):
                if row.kind == 1:
                    if row.identifier in (identifier, identifier + 1):
                        flag_at(row_index, 0, 2)
                else:
                    flag_at(row_index, sample_index, 2, only_zero=True)
    elif scalar(17) is None:

        def mark_range(start: int, count: int) -> None:
            if count == 0:
                raise ToyotaCodecError(
                    "DDR marker range has zero count", INVALID_RECORD
                )
            for row_index, row in enumerate(series):
                if row.kind == 2:
                    for sample_index in range(start, start + count):
                        flag_at(row_index, sample_index, 1)

        first = scalar(18)
        first_offset = int(first is not None)
        if first is not None and first != 0x55:
            mark_range(0, 1)
        second = scalar(19)
        middle_count = first_count if second is not None else 0
        if second is not None and second != 0x55:
            mark_range(first_offset, middle_count)
        tail_ids = tuple(range(20, 31)) + tuple(range(71, 95))
        if second_count > len(tail_ids):
            raise ToyotaCodecError(
                "DDR marker tail exceeds native35-row storage", INVALID_RECORD
            )
        for index, identifier in enumerate(tail_ids[:second_count]):
            value = scalar(identifier)
            if value is not None and value != 0x55:
                mark_range(index + first_offset + middle_count, 1)
    return tuple(
        replace(row, samples=tuple(samples))
        for row, samples in zip(series, values, strict=True)
    )


def apply_ddr_invalid_conditions(
    profile: VehicleProfile,
    plan: DdrRecordPlan,
    series: tuple[DdrValueSeries, ...],
    *,
    cancelled: Callable[[], bool] | None = None,
) -> tuple[DdrValueSeries, ...]:
    """Native5230 then BAE0: condition flags and raw ID13 upper bound."""
    from scripts.support import word
    from scripts.toyota import INVALID_RECORD, ToyotaCodecError
    from scripts.toyota_session import Cancelled

    if (
        profile.database.sha256 != plan.source_sha256
        or profile.category != plan.category
        or profile.exception_ids != plan.exception_ids
        or not isinstance(series, tuple)
        or len(series) + sum(len(row.samples) for row in series) > 100_000
    ):
        raise ValueError("DDR condition context differs or exceeds node allowance")
    first = {}
    for row in series:
        first.setdefault(row.identifier, row)
    output = []
    steps = 0
    for row in series:
        conditions = profile.ddr_records(plan.table_slots[3], row.identifier)
        if any(len(condition) != 16 for condition in conditions):
            raise ToyotaCodecError(
                "DDR invalid condition has wrong width", INVALID_RECORD
            )
        samples = []
        for index, (value, flag) in enumerate(row.samples):
            result = False
            if flag == 0:
                for condition_index, condition in enumerate(conditions):
                    steps += 1
                    if steps > 1_000_000:
                        raise ValueError(
                            "DDR condition evaluation exceeds host allowance"
                        )
                    if cancelled and cancelled():
                        raise Cancelled("DDR condition evaluation cancelled")
                    if (
                        condition_index
                        and not result
                        and conditions[condition_index - 1][12] != 2
                    ):
                        continue
                    result = False
                    reference = (
                        row
                        if word(condition, 4) == word(condition, 6)
                        else first.get(word(condition, 6))
                    )
                    if reference is None:
                        continue
                    if reference.kind != 1 and len(reference.samples) != len(
                        row.samples
                    ):
                        raise ToyotaCodecError(
                            "DDR reference timeline count differs", INVALID_RECORD
                        )
                    reference_index = (
                        index
                        if word(condition, 4) == word(condition, 6)
                        else 0
                        if reference.kind == 1
                        else index
                    )
                    if reference_index >= len(reference.samples):
                        raise ToyotaCodecError(
                            "DDR reference sample is absent", INVALID_RECORD
                        )
                    observed = reference.samples[reference_index][0]
                    expected = int.from_bytes(condition[:4], "little")
                    if condition[13] == 1:
                        result = observed == expected
                    elif condition[13] == 2:
                        result = observed != expected
                    else:
                        raise ToyotaCodecError(
                            "DDR comparison opcode is invalid", INVALID_RECORD
                        )
                    if condition[12] == 2 and result:
                        break
                if result:
                    flag = 2
            samples.append((value, flag))
        output.append(replace(row, samples=tuple(samples)))
    for index, row in enumerate(output):
        if row.identifier == 13:
            if not row.samples:
                raise ToyotaCodecError("DDR ID13 sample is absent", INVALID_RECORD)
            value, flag = row.samples[0]
            if flag == 0 and value > 999999:
                output[index] = replace(row, samples=((value, 2),) + row.samples[1:])
            break
    if cancelled and cancelled():
        raise Cancelled("DDR condition evaluation cancelled")
    return tuple(output)


def propagate_ddr_invalid_flags(
    profile: VehicleProfile,
    plan: DdrRecordPlan,
    series: tuple[DdrValueSeries, ...],
    *,
    cancelled: Callable[[], bool] | None = None,
) -> tuple[DdrValueSeries, ...]:
    """Native5580: ordered pending-reference queue, preserving raw flag2 propagation."""
    from collections import deque

    from scripts.support import word
    from scripts.toyota import INVALID_RECORD, MISSING_RECORD, ToyotaCodecError
    from scripts.toyota_session import Cancelled

    if (
        profile.database.sha256 != plan.source_sha256
        or profile.category != plan.category
        or profile.exception_ids != plan.exception_ids
        or len(series) + sum(len(row.samples) for row in series) > 100_000
    ):
        raise ValueError("DDR propagation source differs or exceeds node allowance")
    all_conditions = profile.records(plan.table_slots[3])
    if not all_conditions:
        raise ToyotaCodecError("DDR invalid-condition table is empty", MISSING_RECORD)
    if len(all_conditions) > 100_000 or any(len(row) != 16 for row in all_conditions):
        raise ToyotaCodecError(
            "DDR invalid-condition table is malformed", INVALID_RECORD
        )
    references = tuple(
        dict.fromkeys(
            word(row, 6) for row in all_conditions if word(row, 4) != word(row, 6)
        )
    )
    pending = deque()
    values = [list(row.samples) for row in series]
    for reference in references:
        for row in series:
            if row.identifier == reference:
                indices = tuple(
                    index for index, (_, flag) in enumerate(row.samples) if flag == 2
                )
                if indices:
                    pending.append((reference, indices))
    changed = False  # Native5580 keeps this flag for the entire queue lifetime.
    steps = 0
    while pending:
        reference, indices = pending.popleft()
        for row_index, row in enumerate(series):
            conditions = profile.ddr_records(plan.table_slots[3], row.identifier)
            if any(len(condition) != 16 for condition in conditions):
                raise ToyotaCodecError("DDR condition has wrong width", INVALID_RECORD)
            position = 0
            while position < len(conditions):
                steps += 1
                if steps > 1_000_000:
                    raise ValueError("DDR invalid propagation exceeds host allowance")
                if cancelled and cancelled():
                    raise Cancelled("DDR invalid propagation cancelled")
                if word(conditions[position], 6) != reference:
                    position += 1
                    continue
                start = position
                while start and conditions[start - 1][12] != 2:
                    start -= 1
                end, valid = start, True
                while end < len(conditions):
                    if valid and end != position:
                        valid = any(
                            identifier == word(conditions[end], 6)
                            for identifier, _ in pending
                        )
                    if conditions[end][12] != 1:
                        break
                    end += 1
                if valid:
                    if indices[0] >= len(values[row_index]):
                        raise ToyotaCodecError(
                            "DDR propagation index exceeds captured series",
                            INVALID_RECORD,
                        )
                    if values[row_index][indices[0]][1] == 0:
                        selected = (
                            range(len(values[row_index]))
                            if reference < 1001
                            else indices
                        )
                        for index in selected:
                            if index >= len(values[row_index]):
                                raise ToyotaCodecError(
                                    "DDR propagated index exceeds captured series",
                                    INVALID_RECORD,
                                )
                            value, flag = values[row_index][index]
                            if flag != 2:
                                values[row_index][index] = (value, 2)
                                changed = True
                        if changed:
                            pending.append((row.identifier, indices))
                position = end + 1
    if cancelled and cancelled():
        raise Cancelled("DDR invalid propagation cancelled")
    return tuple(
        replace(row, samples=tuple(samples))
        for row, samples in zip(series, values, strict=True)
    )


def transform_ddr_record(
    profile: VehicleProfile,
    record: DdrRecordSamples,
    timelines: tuple[DdrTimelineSamples, ...],
    *,
    cancelled: Callable[[], bool] | None = None,
) -> tuple[DdrValueSeries, ...]:
    """Native2FE0/9D90: combined4090 order and42D0 or complete4390 flags."""
    from scripts.toyota_session import Cancelled

    if (
        profile.database.sha256 != record.plan.source_sha256
        or profile.category != record.plan.category
        or profile.exception_ids != record.plan.exception_ids
    ):
        raise ValueError("DDR transformation source differs from selected record")
    if cancelled and cancelled():
        raise Cancelled("DDR transformation cancelled")
    rows = ordered_ddr_series(record, timelines)
    if not record.marker_present:
        return mark_ddr_unchecked(rows)
    rows = apply_ddr_marker_flags(profile, record, rows)
    rows = apply_ddr_invalid_conditions(profile, record.plan, rows, cancelled=cancelled)
    return propagate_ddr_invalid_flags(profile, record.plan, rows, cancelled=cancelled)


def apply_ddr_p5_time_values(
    series: tuple[DdrValueSeries, ...],
) -> tuple[DdrValueSeries, ...]:
    """Common43E60 converts first ID111..116 sample from BCD and checks native ranges."""
    from scripts.toyota import INVALID_RECORD, ToyotaCodecError
    from scripts.toyota_session import decode_bcd32

    if (
        not isinstance(series, tuple)
        or len(series) + sum(len(row.samples) for row in series) > 100_000
    ):
        raise ValueError("P5 DDR time values exceed decoded-node allowance")
    output = list(series)
    for identifier, minimum, maximum in (
        (111, 0, 38),
        (112, 1, 12),
        (113, 1, 31),
        (114, 0, 23),
        (115, 0, 59),
        (116, 0, 59),
    ):
        for index, row in enumerate(output):
            if row.identifier != identifier:
                continue
            if not row.samples:
                raise ToyotaCodecError("P5 DDR time sample is absent", INVALID_RECORD)
            value, flag = row.samples[0]
            try:
                decoded = decode_bcd32(value)
            except ToyotaCodecError:
                decoded = None
            if decoded is not None and minimum <= decoded <= maximum:
                value = decoded
            else:
                flag = 2
            output[index] = replace(row, samples=((value, flag),) + row.samples[1:])
            break
    return tuple(output)


def transform_ddr_p5_record(
    profile: VehicleProfile,
    record: DdrRecordSamples,
    timelines: tuple[DdrTimelineSamples, ...] = (),
    *,
    cancelled: Callable[[], bool] | None = None,
) -> tuple[DdrValueSeries, ...]:
    """Common42C30/3A310: selected order, marker/value/time/odometer/link transforms.

    WCF/trigger/value/link rules share normal semantics; P5 additionally converts
    six BCD time components before propagating invalid references. Original bytes
    remain in record/timelines, since successful BCD conversion changes values.
    """
    from scripts.toyota_session import Cancelled

    if (
        record.plan.spec_value not in _DDR_P5_BANKS
        or profile.database.version != 0x0100032F
        or profile.database.sha256 != record.plan.source_sha256
        or profile.category != record.plan.category
        or profile.exception_ids != record.plan.exception_ids
    ):
        raise ValueError("P5 DDR transformation differs from selected18 source")
    if cancelled and cancelled():
        raise Cancelled("P5 DDR transformation cancelled")
    rows = ordered_ddr_series(record, timelines)
    if not record.marker_present:
        return mark_ddr_unchecked(rows)
    rows = apply_ddr_marker_flags(profile, record, rows)
    rows = apply_ddr_invalid_conditions(profile, record.plan, rows, cancelled=cancelled)
    rows = apply_ddr_p5_time_values(rows)
    return propagate_ddr_invalid_flags(profile, record.plan, rows, cancelled=cancelled)


@dataclass(frozen=True)
class DdrBulkRecordSamples:
    """NativeA0b0's observed 24-byte header, selected scalars and record span."""

    address: int
    raw: bytes
    record: DdrRecordSamples
    record_length: int


def capture_ddr_bulk_record_samples(
    reader: NativeRamReader,
    *,
    spec_value: int,
    address: int,
) -> DdrBulkRecordSamples | None:
    """NativeA0b0: one exact DdrReal24 read, no individual-record bank cache."""
    from scripts.support import word
    from scripts.toyota import INVALID_RECORD, ToyotaCodecError

    if reader.block_size != 24 or reader.frame.raw[:3] != b"\x01\x00\x02":
        raise ValueError("DDR bulk record needs native010002 frame and24-byte blocks")
    if type(spec_value) is not int or spec_value not in _DDR_BANKS:
        raise ToyotaCodecError("Unsupported observed DDR specification", 0xA0041001)
    if type(address) is not int or not 0 <= address <= 0xFFFFFFFF - 23:
        raise ValueError("DDR bulk header address exceeds native width")
    with reader._operation():
        reader._cache.clear()
        reader._pcs_failed = False
        try:
            raw = reader.read(address, 24, real=True)
        except ToyotaCodecError:
            return None
        header = raw[:2]
        if not reader.profile.ddr_records(_DDR_BANKS[spec_value] + 1, *header):
            return None
        plan = selected_ddr_record_plan(reader.profile, spec_value, header, bulk=True)
        length = word(plan.trigger_record, 22)
        if not length:
            raise ToyotaCodecError(
                "DDR bulk trigger record length is zero", INVALID_RECORD
            )
        values = []
        for sample in plan.samples:
            offset = int.from_bytes(sample.address_record[:4], "little")
            if offset >= 24:
                continue
            first, last = (
                word(sample.monitor_record, 28),
                word(sample.monitor_record, 30),
            )
            size = (last >> 3) - (first >> 3) + 1
            if not 1 <= size <= 4 or offset + size > 24:
                raise ToyotaCodecError(
                    "DDR bulk scalar exceeds header storage", INVALID_RECORD
                )
            data = raw[offset : offset + size]
            values.append((sample.monitor_id, data, ddr_bits(data, first, last)))
        record = DdrRecordSamples(header, plan, tuple(values))
        return DdrBulkRecordSamples(address, raw, record, length)


@dataclass(frozen=True)
class DdrBulkPayloadSamples:
    header: DdrBulkRecordSamples
    raw: bytes
    record: DdrRecordSamples
    timelines: tuple[DdrTimelineSamples, ...]


def decode_ddr_bulk_payload(
    profile: VehicleProfile,
    header: DdrBulkRecordSamples,
    raw: bytes,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> DdrBulkPayloadSamples:
    """NativeA970/AD40: remaining scalar fields and packed/strided timelines."""
    from scripts.support import word
    from scripts.toyota import INVALID_RECORD, MISSING_RECORD, ToyotaCodecError

    plan = header.record.plan
    if (
        profile.database.sha256 != plan.source_sha256
        or profile.category != plan.category
        or profile.exception_ids != plan.exception_ids
        or not isinstance(raw, bytes)
        or not 24 < header.record_length <= 65535
        or len(raw) != header.record_length - 24
        or len(header.raw) != 24
        or header.raw[:2] != header.record.header
        or word(plan.trigger_record, 22) != header.record_length
    ):
        raise ValueError("DDR bulk payload differs from observed selected header")

    def check() -> None:
        if cancelled and cancelled():
            from scripts.toyota_session import Cancelled

            raise Cancelled("DDR bulk payload decoding cancelled")

    check()
    data = bytes(24) + raw  # NativeA740 zero-allocates the unused header prefix.
    scalar_rows = profile.ddr_records(plan.table_slots[2], header.record.header[0], 1)
    if not scalar_rows:
        raise ToyotaCodecError("DDR bulk scalar addresses are absent", MISSING_RECORD)
    if len(scalar_rows) > 100_000:
        raise ValueError("DDR bulk scalar count exceeds node allowance")
    values, samples = list(header.record.values), list(plan.samples)
    for row in scalar_rows[2:]:
        check()
        offset = int.from_bytes(row[:4], "little")
        if offset < 24:
            continue
        monitor_id = word(row, 4)
        monitors = profile.ddr_records(plan.table_slots[0], monitor_id)
        if not monitors:
            raise ToyotaCodecError("DDR bulk scalar monitor is absent", MISSING_RECORD)
        monitor = monitors[0]
        first, last = word(monitor, 28), word(monitor, 30)
        size = (last >> 3) - (first >> 3) + 1
        if not 1 <= size <= 4 or offset + size > len(data):
            raise ToyotaCodecError(
                "DDR bulk scalar exceeds record storage", INVALID_RECORD
            )
        source = data[offset : offset + size]
        values.append((monitor_id, source, ddr_bits(source, first, last)))
        samples.append(
            DdrSamplePlan(
                monitor_id,
                row,
                monitor,
                plan.source_sha256,
                plan.category,
                plan.exception_ids,
            )
        )
    rows = profile.ddr_records(plan.table_slots[2], header.record.header[0], 2)
    if not rows:
        raise ToyotaCodecError("DDR bulk timeline addresses are absent", MISSING_RECORD)
    count = sum(word(plan.trigger_record, offset) for offset in (16, 18, 20)) & 65535
    if len(rows) + count * len(rows) + len(scalar_rows) > 100_000:
        raise ValueError("DDR bulk decoded values exceed node allowance")
    timelines = []
    for row in rows:
        check()
        identifier, byte_stride = word(row, 4), word(row, 6)
        offset = int.from_bytes(row[:4], "little")
        monitors = profile.ddr_records(plan.table_slots[0], identifier)
        if not monitors:
            raise ToyotaCodecError(
                "DDR bulk timeline monitor is absent", MISSING_RECORD
            )
        monitor = monitors[0]
        sample = DdrSamplePlan(
            identifier,
            row,
            monitor,
            plan.source_sha256,
            plan.category,
            plan.exception_ids,
        )
        if not byte_stride:
            stride = word(monitor, 34) - word(monitor, 32) + 1
            if not 1 <= stride <= 32:
                raise ToyotaCodecError(
                    "DDR bulk packed stride is invalid", INVALID_RECORD
                )
            size = max(1, (count * stride + 7) // 8)
            if size > 280 or offset + size > len(data):
                raise ToyotaCodecError(
                    "DDR bulk packed timeline exceeds storage", INVALID_RECORD
                )
            source = data[offset : offset + size]
            decoded = ddr_timeline_values(source, count, monitor)
        else:
            first, last = word(monitor, 28), word(monitor, 30)
            size = (last >> 3) - (first >> 3) + 1
            span = (count - 1) * byte_stride + size if count else 0
            if not 1 <= size <= 4 or (count and offset + span > len(data)):
                raise ToyotaCodecError(
                    "DDR bulk strided timeline exceeds storage", INVALID_RECORD
                )
            source = data[offset : offset + span]
            decoded = tuple(
                ddr_bits(
                    source[index * byte_stride : index * byte_stride + size],
                    first,
                    last,
                )
                for index in range(count)
            )
        timelines.append(DdrTimelineSamples(sample, source, decoded))
    return DdrBulkPayloadSamples(
        header,
        raw,
        replace(
            header.record,
            plan=replace(plan, samples=tuple(samples)),
            values=tuple(values),
        ),
        tuple(timelines),
    )


def capture_ddr_bulk_payload(
    reader: NativeRamReader,
    header: DdrBulkRecordSamples,
) -> DdrBulkPayloadSamples | None:
    """NativeA740: exact Real chunks after the24-byte header; failed RAM skips."""
    from scripts.toyota import ToyotaCodecError

    plan = header.record.plan
    if (
        reader.block_size != 56
        or reader.frame.raw[:3] != b"\x01\x00\x02"
        or header.record_length <= 24
        or reader.profile.database.sha256 != plan.source_sha256
        or reader.profile.category != plan.category
        or reader.profile.exception_ids != plan.exception_ids
    ):
        raise ValueError("DDR bulk payload reader differs from selected header")
    with reader._operation():
        reader._cache.clear()
        reader._pcs_failed = False
        try:
            raw = reader.read(header.address + 24, header.record_length - 24, real=True)
        except ToyotaCodecError:
            return None
        result = decode_ddr_bulk_payload(
            reader.profile, header, raw, cancelled=reader.cancelled
        )
        reader._check()
        return result


def selected_ddr_record_plan(
    profile: VehicleProfile, spec_value: int, header: bytes, *, bulk: bool = False
) -> DdrRecordPlan:
    """Native 0x3369/0x33ce/0x3435 resource selection for one captured DDR header."""
    from scripts.toyota import ToyotaCodecError

    if type(bulk) is not bool:
        raise ValueError("DDR record selection requires an explicit bulk boolean")
    if type(spec_value) is not int or spec_value not in _DDR_BANKS:
        raise ToyotaCodecError("Unsupported observed DDR specification", 0xA0041001)
    if not isinstance(header, bytes) or len(header) != 2:
        raise ValueError(
            "DDR record header must contain its two observed selector bytes"
        )
    return _selected_ddr_plan(
        profile, spec_value, header, _DDR_BANKS[spec_value], 24 if bulk else None
    )


def _selected_ddr_plan(
    profile: VehicleProfile,
    spec_value: int,
    header: bytes,
    bank: int,
    header_limit: int | None,
) -> DdrRecordPlan:
    from scripts.support import word
    from scripts.toyota import INVALID_RECORD, MISSING_RECORD, ToyotaCodecError

    monitor, trigger, address, invalid = tuple(range(bank, bank + 4))
    triggers = profile.ddr_records(trigger, header[0], header[1])
    if not triggers:
        raise ToyotaCodecError(
            "Selected DDR trigger resource is absent", MISSING_RECORD
        )
    if header_limit is not None and not word(triggers[0], 22):
        raise ToyotaCodecError("DDR bulk trigger record length is zero", INVALID_RECORD)
    addresses = profile.ddr_records(address, header[0], 1)
    if not addresses:
        raise ToyotaCodecError(
            "Selected DDR trigger/address resource is absent", MISSING_RECORD
        )
    if len(addresses) > 100_000:
        raise ValueError("DDR selected sample count exceeds node budget")
    samples = []
    for row in addresses[2:]:
        if (
            header_limit is not None
            and int.from_bytes(row[:4], "little") >= header_limit
        ):
            continue
        identifier = word(row, 4)
        monitors = profile.ddr_records(monitor, identifier)
        if not monitors:
            raise ToyotaCodecError(
                "Selected DDR monitor resource is absent", MISSING_RECORD
            )
        samples.append(
            DdrSamplePlan(
                identifier,
                row,
                monitors[0],
                profile.database.sha256,
                profile.category,
                profile.exception_ids,
            )
        )
    return DdrRecordPlan(
        spec_value,
        (monitor, trigger, address, invalid),
        triggers[0],
        addresses[:2],
        tuple(samples),
        profile.database.sha256,
        profile.category,
        profile.exception_ids,
        tuple(word(row, 24) for row in profile.records(monitor)),
    )


def _ram_binding(reader: NativeRamReader) -> dict:
    return {
        "vehicle_ddb_sha256": reader.vehicle_sha256,
        "management_ddb_sha256": reader.management_sha256,
        "category": reader.category,
        "exception_ids": list(reader.exception_ids),
        "function_record": reader.selected.function_record.hex(),
        "communication_record": reader.selected.communication_record.hex(),
        "settings_record": reader.selected.settings_record.hex(),
        "frame": reader.frame.raw.hex(),
        "block_size": reader.block_size,
        "bus_id": reader.bus_id,
    }


def encode_ram_recording(reader: NativeRamReader, *, source: str) -> bytes:
    """Source-bound recording around the shared literal native-exchange codec."""
    import json

    from scripts.native_replay import MAX_FILE, SCHEMA, NativeReplay

    transactions = []
    for row in reader.transactions:
        item: dict = {"ecu": row.query.ecu, "request": row.query.request.hex()}
        if row.status:
            item.update(status=row.status, partial_response=row.reply.hex())
        else:
            item["response"] = row.reply.hex()
        transactions.append(item)
    exchange = {
        "schema": SCHEMA,
        "source": source,
        "ecus": [reader.ecu],
        "transactions": transactions,
        "support": {},
    }
    NativeReplay(exchange)
    raw = json.dumps(
        {
            "schema": "techstream-native-ram-v1",
            "binding": _ram_binding(reader),
            "exchange": exchange,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(raw) > MAX_FILE:
        raise ValueError("Native RAM recording exceeds file byte budget")
    return raw


class RamReplay:
    """Replays actual primitive exchanges only against the same selected sources."""

    def __init__(
        self,
        profile: VehicleProfile,
        raw: bytes,
        *,
        cancelled: Callable[[], bool] | None = None,
    ):
        import json

        from scripts.native_replay import MAX_FILE, NativeReplay

        if not isinstance(raw, bytes) or len(raw) > MAX_FILE:
            raise ValueError(
                "Native RAM recording exceeds file byte budget or is not bytes"
            )

        def unique(pairs: list[tuple[str, object]]) -> dict:
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate native RAM recording key")
                result[key] = value
            return result

        try:
            document = json.loads(raw, object_pairs_hook=unique)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise ValueError("Invalid native RAM recording JSON") from error
        if (
            not isinstance(document, dict)
            or set(document) != {"schema", "binding", "exchange"}
            or document["schema"] != "techstream-native-ram-v1"
        ):
            raise ValueError("Unsupported native RAM recording fields/schema")
        binding = document["binding"]
        if (
            not isinstance(binding, dict)
            or not isinstance(binding.get("frame"), str)
            or len(binding["frame"]) != 16
        ):
            raise ValueError("Invalid recorded native RAM frame binding")
        try:
            frame = RamFrame(bytes.fromhex(binding["frame"]))
        except ValueError as error:
            raise ValueError("Invalid recorded native RAM frame binding") from error
        self.replay = NativeReplay(document["exchange"], cancelled)
        if len(self.replay.ecus) != 1:
            raise ValueError("Native RAM recording must contain one selected ECU")
        block_size = binding.get("block_size")
        if type(block_size) is not int or not 1 <= block_size <= 255:
            raise ValueError("Invalid recorded native RAM block size")
        self.reader = NativeRamReader(
            profile,
            self.exchange,
            ecu=self.replay.ecus[0],
            frame=frame,
            block_size=block_size,
            bus_id=binding.get("bus_id"),
            cancelled=cancelled,
        )
        binding.setdefault("bus_id", None)
        if json.dumps(binding, sort_keys=True) != json.dumps(
            _ram_binding(self.reader), sort_keys=True
        ):
            raise ValueError(
                "Native RAM recording does not match selected DDB/frame sources"
            )
        self._binding = _ram_binding(self.reader)

    @classmethod
    def load(
        cls,
        profile: VehicleProfile,
        path: str | Path,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> RamReplay:
        from scripts.local_files import read_regular
        from scripts.native_replay import MAX_FILE

        return cls(profile, read_regular(path, limit=MAX_FILE), cancelled=cancelled)

    def exchange(self, query: RamQuery) -> bytes:
        if query.frame.raw[:4].hex() != self._binding["frame"][:8] or (
            query.selected.provenance != self.reader.selected.provenance
            or query.selected.function_record.hex() != self._binding["function_record"]
            or query.selected.communication_record.hex()
            != self._binding["communication_record"]
            or query.selected.settings_record.hex() != self._binding["settings_record"]
        ):
            raise ValueError(
                "Native RAM replay query uses different selected source fields"
            )
        return self.replay.exchange(query.ecu, query.request)

    def assert_complete(self) -> None:
        self.replay.assert_complete()


@dataclass(frozen=True)
class DdrLessA8Attribute:
    """Selected GetPidDataLessA8 primitive; support expansion is deliberately absent."""

    logical_id: int
    record: bytes
    selected: SelectedFrame

    def __post_init__(self) -> None:
        if not isinstance(self.record, bytes) or len(self.record) != 44:
            raise ValueError("LessA8 requires an exact selected CommPidData44 record")

    def read(self, cache: MonitorSupportCache) -> int:
        if cache.profile.frame_records(0x6B) != (
            self.selected,
        ) or self.record not in cache.profile.comm_pid_records(self.logical_id):
            raise ValueError(
                "LessA8 cache context differs from selected resource sources"
            )
        return self.decode(
            cache.transaction(
                self.selected,
                self.request,
                native_parameter=self.cache_parameter,
                cached=False,
                temporary=True,
            )
        )

    @property
    def cache_parameter(self) -> int:
        return self.record[38]

    @property
    def request(self) -> bytes:
        template = self.selected.frame.request
        return template[:1] + self.record[39:40] + template[2:]

    def decode(self, reply: bytes) -> int:
        from scripts.signal_conversion import extract_bits
        from scripts.support import word
        from scripts.toyota import SHORT_REPLY, CommandFrame, ToyotaCodecError

        request = self.request
        CommandFrame(request).check_reply(reply)
        count = (len(reply) - 2) & 255
        if not count or len(request) + count > len(reply):
            raise ToyotaCodecError(
                "LessA8 response lacks native payload bytes", SHORT_REPLY
            )
        start, end = word(self.record, 20), word(self.record, 22)
        if start > end or end >= count * 8 or end - start >= 32:
            raise ToyotaCodecError(
                "LessA8 response lacks selected bit range", SHORT_REPLY
            )
        return extract_bits(reply[len(request) : len(request) + count], start, end)


def selected_ddr_less_a8_attribute(
    profile: VehicleProfile, logical_id: int
) -> DdrLessA8Attribute | None:
    """Explicit lower LessA8 reader for a selected native B1/B2 PID group.

    Upper activation comes only from the observed spec2 legacy override.
    """
    from scripts.support import word
    from scripts.toyota import INVALID_RECORD, MISSING_RECORD, ToyotaCodecError

    if type(logical_id) is not int or logical_id not in _DDR_ATTRIBUTE_IDS:
        raise ValueError("Logical DDR attribute is not a native dispatcher entry")
    rows = profile.comm_pid_records(logical_id)
    if not rows:
        return None
    row = next((item for item in rows if word(item, 18) == profile.category), None)
    if row is None:
        raise ToyotaCodecError(
            "DDR attribute lacks selected ECU category", MISSING_RECORD
        )
    if row[39] not in (0xB1, 0xB2):
        raise ValueError("Native LessA8 override applies only to B1/B2 PID groups")
    try:
        selected = profile.frame_records(0x6B)
    except ValueError as error:
        raise ToyotaCodecError(
            "LessA8 lacks selected function6B frame", INVALID_RECORD
        ) from error
    if len(selected) != 1 or not 2 <= len(selected[0].frame.request) <= 255:
        raise ToyotaCodecError(
            "LessA8 requires exactly one native function6B frame", INVALID_RECORD
        )
    return DdrLessA8Attribute(logical_id, row, selected[0])


# Native18 Common440f0 switch: these logical IDs bypass support only for type20.
_DDR_ITEM_IDS = frozenset(
    (
        *range(101, 119),
        *range(138, 142),
        *range(155, 159),
        170,
        171,
        *range(177, 188),
        208,
        209,
        211,
        212,
        214,
        215,
    )
)
_DDR_ATTRIBUTE_IDS = (
    *range(101, 118),
    138,
    139,
    140,
    141,
    155,
    156,
    157,
    158,
    118,
    *range(159, 172),
    137,
    136,
)
_DDR_P5_ATTRIBUTE_IDS = (
    118,
    101,
    102,
    103,
    170,
    171,
    177,
    *range(104, 118),
    138,
    139,
    140,
    141,
    155,
    156,
    157,
    158,
    *range(178, 188),
    208,
    209,
    211,
    212,
    214,
    215,
)


@dataclass(frozen=True)
class DdrEcuContext:
    """Common6b6b0 compares native DWORD category and WORD observed bus."""

    category: int
    bus_id: int

    def __post_init__(self) -> None:
        if type(self.category) is not int or not 0 <= self.category <= 0xFFFFFFFF:
            raise ValueError("DDR context category must fit uint32")
        if type(self.bus_id) is not int or not 0 <= self.bus_id <= 65535:
            raise ValueError("DDR context bus must fit uint16")


@dataclass(frozen=True)
class DdrAttribute:
    """One native1c930 selected candidate, retained before native27a0 reading."""

    logical_id: int
    record: bytes
    category_record: bytes
    management_sha256: str
    exception_ids: tuple[int, ...]
    less_a8: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.logical_id) is not int
            or not 0 <= self.logical_id <= 65535
            or not isinstance(self.record, bytes)
            or len(self.record) != 44
            or not isinstance(self.category_record, bytes)
            or len(self.category_record) != 76
            or type(self.less_a8) is not bool
        ):
            raise ValueError(
                "CommPid target requires exact selected rows and decode policy"
            )

    def read(self, cache: MonitorSupportCache) -> int:
        from scripts.support import word
        from scripts.toyota import INVALID_RECORD, ToyotaCodecError
        from scripts.toyota_session import decode_comm_pid_reply

        profile = _toyota_profile(cache.profile)
        if (
            cache.source_build not in (12, 18)
            or _ddr_profile_build(profile) != cache.source_build
            or profile.catalog.management.sha256 != self.management_sha256
            or profile.exception_ids != self.exception_ids
            or self.record not in profile.comm_pid_records(self.logical_id)
            or profile.category_record != self.category_record
            or word(self.record, 18) != profile.category
        ):
            raise ValueError("DDR attribute cache differs from selected target sources")
        category_type = self.category_record[72]
        extended = (
            category_type in ((20, 21, 52) if cache.source_build == 18 else (20, 21))
            and not self.less_a8
        )
        function = 0xCA if extended else 0x6B
        try:
            frames = profile.frame_records(function)
        except ValueError as error:
            raise ToyotaCodecError(
                "DDR attribute frame is absent", INVALID_RECORD
            ) from error
        if len(frames) != 1:
            raise ToyotaCodecError(
                "DDR attribute requires one selected frame", INVALID_RECORD
            )
        selected = frames[0]
        request = selected.frame.request
        minimum = 3 if extended else 2
        if not minimum <= len(request) <= (65535 if extended else 255):
            raise ToyotaCodecError(
                "DDR attribute frame length is invalid", INVALID_RECORD
            )
        request = (
            request[:1] + word(self.record, 34).to_bytes(2, "big") + request[3:]
            if extended
            else request[:1] + self.record[39:40] + request[2:]
        )
        reply = cache.transaction(
            selected,
            request,
            native_parameter=self.record[38],
            cached=False,
            temporary=True,
        )
        if self.less_a8:
            # Native dispatcher calls LessA8 rather than GetPidDataCommon here.
            return DdrLessA8Attribute(self.logical_id, self.record, selected).decode(
                reply
            )
        positions = None if extended else cache.support_bits(1).get(self.record[39])
        return decode_comm_pid_reply(
            self.record,
            category_type,
            request,
            reply,
            positions=positions,
            bcd=False,
        )


def select_comm_pid_target(
    cache: MonitorSupportCache,
    logical_id: int,
    *,
    connections: Mapping[tuple[int, int], NativeCommunication] | None = None,
    ecu_specific: tuple[DdrEcuContext, ...] = (),
) -> DdrAttribute | None:
    """Native1c930 first-supported candidate, including exact ECU/bus filter.

    Support errors skip candidates; cancellation and host bounds still propagate.
    """
    from scripts.support import word
    from scripts.toyota import INVALID_RECORD, MISSING_RECORD, ToyotaCodecError

    if (
        cache.source_build not in (12, 18)
        or type(logical_id) is not int
        or not 0 <= logical_id <= 65535
    ):
        raise ValueError("Native CommPid logical ID must fit uint16")
    if (
        not isinstance(ecu_specific, tuple)
        or len(ecu_specific) > 100_000
        or any(not isinstance(item, DdrEcuContext) for item in ecu_specific)
    ):
        raise ValueError("DDR ECU-specific context list is invalid")
    targets = {(item.category, item.bus_id) for item in ecu_specific}
    cache.check_context()
    profile = _toyota_profile(cache.profile)
    if _ddr_profile_build(profile) != cache.source_build:
        raise ValueError("DDR profile schema differs from selected native source")
    rows = profile.comm_pid_records(logical_id)
    if not rows:
        raise ToyotaCodecError("DDR attribute candidates are absent", MISSING_RECORD)
    for row in rows:
        cache.check_context()
        if targets and (word(row, 18), row[38]) not in targets:
            continue
        categories = profile.category_records(word(row, 18))
        if not categories:
            raise ToyotaCodecError("DDR target category is absent", MISSING_RECORD)
        category = categories[0]
        kind = category[72]
        allowed_kinds = (
            (3, 4, 20, 21, 52) if cache.source_build == 18 else (3, 4, 20, 21)
        )
        if kind not in allowed_kinds:
            raise ToyotaCodecError(
                "DDR target category type is invalid", INVALID_RECORD
            )
        if cache.source_build == 18 and kind == 20 and logical_id in (3, 16):
            raise NotImplementedError(
                "Native type20 tire-ID support branch remains unresolved"
            )
        reference = word(row, 24)
        supported = reference == 0 or (
            cache.source_build == 18 and kind == 20 and logical_id in _DDR_ITEM_IDS
        )
        if not supported:
            try:
                supported = cache.get_comm_support_bit(
                    reference,
                    connections=connections,
                    temporary=False,
                    force=False,
                    with_value=False,
                ).supported
            except ToyotaCodecError:
                continue
        if supported:
            return DdrAttribute(
                logical_id,
                row,
                category,
                profile.catalog.management.sha256,
                profile.exception_ids,
            )
    return None


def select_ddr_attribute(
    cache: MonitorSupportCache,
    logical_id: int,
    *,
    connections: Mapping[tuple[int, int], NativeCommunication] | None = None,
    ecu_specific: tuple[DdrEcuContext, ...] = (),
) -> DdrAttribute | None:
    """Native DDR dispatcher uses ordinary decoding until explicit legacy override."""
    if type(logical_id) is not int or logical_id not in (
        *_DDR_ATTRIBUTE_IDS,
        *_DDR_P5_ATTRIBUTE_IDS,
    ):
        raise ValueError("Unsupported native DDR attribute dispatcher entry")
    selected = select_comm_pid_target(
        cache,
        logical_id,
        connections=connections,
        ecu_specific=ecu_specific,
    )
    return selected


@dataclass(frozen=True)
class DdrAttributeSlot:
    logical_id: int
    candidates: tuple[bytes, ...]
    initial_pid: int | None
    selected_index: int = 0
    supported: bool = False
    enabled: bool = True
    less_a8: bool = False


@dataclass(frozen=True)
class DdrAttributePlan:
    """Native13e0/2730 state, preserving unsupported index-zero fallback."""

    slots: tuple[DdrAttributeSlot, ...]
    management_sha256: str
    vehicle_sha256: str
    category: int
    exception_ids: tuple[int, ...]
    p5: bool = False
    source_build: int = 18

    def _check(self, cache: MonitorSupportCache) -> None:
        if (
            type(self.p5) is not bool
            or type(self.source_build) is not int
            or self.source_build not in (12, 18)
            or not isinstance(self.slots, tuple)
            or len(self.slots) > (45 if self.p5 else 41)
        ):
            raise ValueError("DDR attribute plan exceeds native family allowance")
        cache.check_context()
        profile = _toyota_profile(cache.profile)
        if (
            cache.source_build != self.source_build
            or profile.catalog.management.sha256 != self.management_sha256
            or profile.database.sha256 != self.vehicle_sha256
            or profile.category != self.category
            or profile.exception_ids != self.exception_ids
            or any(
                profile.comm_pid_records(slot.logical_id) != slot.candidates
                for slot in self.slots
            )
        ):
            raise ValueError("DDR attribute plan differs from selected sources")

    def check_support(
        self,
        cache: MonitorSupportCache,
        *,
        connections: Mapping[tuple[int, int], NativeCommunication] | None = None,
        ecu_specific: tuple[DdrEcuContext, ...] = (),
    ) -> DdrAttributePlan:
        self._check(cache)
        slots = []
        for slot in self.slots:
            if not slot.candidates or self.p5 and slot.logical_id == 118:
                slots.append(slot)
                continue
            selected = select_ddr_attribute(
                cache,
                slot.logical_id,
                connections=connections,
                ecu_specific=ecu_specific,
            )
            slots.append(
                replace(
                    slot,
                    selected_index=slot.candidates.index(selected.record)
                    if selected
                    else 0,
                    supported=selected is not None,
                )
            )
        return replace(self, slots=tuple(slots))

    def validate_required(self) -> None:
        from scripts.toyota import ToyotaCodecError

        if any(
            slot.candidates
            and slot.logical_id in (118, 137, 136)
            and not slot.supported
            for slot in self.slots
        ):
            raise ToyotaCodecError(
                "Native DDR required attribute is unsupported", 0xA0041001
            )

    def for_specification(self, spec_value: int) -> DdrAttributePlan:
        """Native2dc0 resource-bank selection also disables absent spec groups."""
        from scripts.toyota import ToyotaCodecError

        allowed = (
            (2, 3, 5, 6, 7, 8)
            if self.source_build == 12 and not self.p5
            else (_DDR_P5_BANKS if self.p5 else _DDR_BANKS)
        )
        if type(spec_value) is not int or spec_value not in allowed:
            raise ToyotaCodecError(
                "Native DDR specification is unsupported", 0xA0041001
            )
        disabled = set()
        if self.p5:
            if spec_value == 10:
                disabled.update((208, 209))
            if spec_value in (10, 13):
                disabled.update((211, 212))
            if spec_value in (10, 13, 14):
                disabled.update((214, 215))
            return replace(
                self,
                slots=tuple(
                    replace(slot, enabled=False)
                    if slot.logical_id in disabled
                    else slot
                    for slot in self.slots
                ),
            )
        if spec_value in (2, 3):
            disabled.update(range(138, 142))
        if spec_value in (2, 3, 5):
            disabled.update(range(155, 172))
        return replace(
            self,
            slots=tuple(
                replace(slot, enabled=False) if slot.logical_id in disabled else slot
                for slot in self.slots
            ),
        )

    def with_legacy_group_override(
        self,
        spec_value: int,
        variant: int | None = None,
    ) -> DdrAttributePlan:
        """Native1810→1d80: only spec2 and observed137 variant2/3 force B1/B2."""
        if type(spec_value) is not int or not 0 <= spec_value <= 0xFFFFFFFF:
            raise ValueError("Observed DDR specification must fit uint32")
        if spec_value != 2:
            return self
        if type(variant) is not int or not 0 <= variant <= 0xFFFFFFFF:
            raise ValueError("Spec2 requires observed logical137 variant")
        if variant not in (2, 3):
            return self
        return replace(
            self,
            slots=tuple(
                replace(slot, supported=True, less_a8=True)
                if slot.candidates and slot.initial_pid in (0xB1, 0xB2)
                else slot
                for slot in self.slots
            ),
        )

    def group_supported(self, pid: int) -> bool:
        """Native1db0: a group needs at least one present entry, all supported."""
        if type(pid) is not int or not 0 <= pid <= 255:
            raise ValueError("Native DDR PID group must fit uint8")
        matches = tuple(
            slot
            for slot in self.slots
            if slot.candidates and slot.enabled and slot.initial_pid == pid
        )
        return bool(matches) and all(slot.supported for slot in matches)

    def read_group(
        self,
        cache: MonitorSupportCache,
        pid: int,
        *,
        connections: Mapping[tuple[int, int], NativeCommunication] | None = None,
        temporary_instances: dict[int, TemporaryResponseCache] | None = None,
    ) -> tuple[DdrAttributePlan, tuple[tuple[int, int], ...]]:
        """Native27a0 fresh TEMP, or SaveLog caller-owned instance per target."""
        return self._read(cache, pid, False, connections, temporary_instances)

    def read_one(
        self,
        cache: MonitorSupportCache,
        logical_id: int,
        *,
        connections: Mapping[tuple[int, int], NativeCommunication] | None = None,
        temporary_instances: dict[int, TemporaryResponseCache] | None = None,
    ) -> int | None:
        """Native28d0 logical ID read, without group support suppression."""
        _, observations = self._read(
            cache, logical_id, True, connections, temporary_instances
        )
        return observations[0][1] if observations else None

    def _read(
        self,
        cache: MonitorSupportCache,
        identifier: int,
        one: bool,
        connections: Mapping[tuple[int, int], NativeCommunication] | None,
        temporary_instances: dict[int, TemporaryResponseCache] | None,
    ) -> tuple[DdrAttributePlan, tuple[tuple[int, int], ...]]:
        from contextlib import ExitStack

        from scripts.monitor_support import TemporaryResponseCache
        from scripts.support import word
        from scripts.toyota import MISSING_RECORD, ToyotaCodecError
        from scripts.toyota_session import SessionError

        self._check(cache)
        if type(identifier) is not int or not 0 <= identifier <= (
            65535 if self.p5 else 255
        ):
            raise ValueError("Native DDR attribute/group selector exceeds family width")
        slots, observations = list(self.slots), []
        with ExitStack() as scopes:
            scoped = set()
            for index, slot in enumerate(self.slots):
                matches = (
                    slot.logical_id == identifier
                    if one
                    else slot.enabled and slot.initial_pid == identifier
                )
                if not slot.candidates or not matches:
                    continue
                if not one and identifier == 0xB2 and not slot.supported:
                    slots[index] = replace(slot, enabled=False)
                    continue
                row = slot.candidates[slot.selected_index]
                category, bus = word(row, 18), row[38]
                local = category == cache.profile.category and (
                    cache.bus_id is None or bus in (0, cache.bus_id)
                )
                communication = (
                    None if local else (connections or {}).get((category, bus))
                )
                if not local and communication is None:
                    raise SessionError(
                        "DDR attribute target communication context absent"
                    )
                if local:
                    target = cache
                else:
                    assert communication is not None
                    target = communication.cache
                if id(target) not in scoped:
                    instance = None
                    if temporary_instances is not None:
                        instance = temporary_instances.setdefault(
                            id(target),
                            TemporaryResponseCache(
                                (*target.identity, target.source_build)
                            ),
                        )
                    scopes.enter_context(target.temporary_scope(instance))
                    scoped.add(id(target))
                categories = target.profile.category_records(category)
                if not categories:
                    raise ToyotaCodecError(
                        "DDR attribute target category is absent", MISSING_RECORD
                    )
                attribute = DdrAttribute(
                    slot.logical_id,
                    row,
                    categories[0],
                    self.management_sha256,
                    self.exception_ids,
                    less_a8=slot.less_a8,
                )
                with cache.target_operation(communication):
                    observations.append((slot.logical_id, attribute.read(target)))
                if one:
                    break
        return replace(self, slots=tuple(slots)), tuple(observations)


def initial_ddr_attribute_plan(profile: VehicleProfile) -> DdrAttributePlan:
    """Native13e0 preflight; no communication or support query occurs here."""
    return _initial_ddr_attribute_plan(profile, p5=False)


def _ddr_profile_build(profile: VehicleProfile) -> int:
    if profile.database.version == 0x0100030C:
        return 12
    if profile.database.version == 0x0100032F:
        return 18
    raise ValueError("DDR attributes require an authored supported Toyota DDB schema")


def initial_ddr_p5_attribute_plan(profile: VehicleProfile) -> DdrAttributePlan:
    """Common412C0: exact45 entries, native selected-category first candidate and DID."""
    if profile.database.version != 0x0100032F:
        raise ValueError("P5 DDR attributes require the recovered18 factory")
    return _initial_ddr_attribute_plan(profile, p5=True)


def _initial_ddr_attribute_plan(
    profile: VehicleProfile, *, p5: bool
) -> DdrAttributePlan:
    from scripts.support import word
    from scripts.toyota import MISSING_RECORD, ToyotaCodecError

    source_build = _ddr_profile_build(profile)
    if p5 and source_build != 18:
        raise ValueError("P5 DDR attributes require the recovered18 factory")
    slots = []
    for logical in _DDR_P5_ATTRIBUTE_IDS if p5 else _DDR_ATTRIBUTE_IDS:
        rows = profile.comm_pid_records(logical)
        initial = next((row for row in rows if word(row, 18) == profile.category), None)
        if rows and initial is None:
            raise ToyotaCodecError(
                "DDR attribute lacks initial selected category", MISSING_RECORD
            )
        slots.append(
            DdrAttributeSlot(
                logical,
                rows,
                (word(initial, 34) if p5 else initial[39]) if initial else None,
            )
        )
    return DdrAttributePlan(
        tuple(slots),
        profile.catalog.management.sha256,
        profile.database.sha256,
        profile.category,
        profile.exception_ids,
        p5,
        source_build,
    )


@dataclass(frozen=True)
class DdrAttributeCapture:
    """Native1810 attribute phase; values precede record and report conversion."""

    plan: DdrAttributePlan
    observations: tuple[tuple[int, int], ...]
    spec_value: int
    group_count: int


def capture_ddr_attributes(
    cache: MonitorSupportCache,
    *,
    connections: Mapping[tuple[int, int], NativeCommunication] | None = None,
    ecu_specific: tuple[DdrEcuContext, ...] = (),
    saved_log: bool = False,
    internal_image: bool = False,
) -> DdrAttributeCapture:
    """Source-bound normal1810 preparation, support and exact attribute order.

    One existing cache operation budget spans every exchange; callers start a
    fresh operation explicitly when appropriate. This does not format a report.
    """
    from scripts.toyota import INVALID_RECORD, ToyotaCodecError

    if (
        type(saved_log) is not bool
        or type(internal_image) is not bool
        or (internal_image and not saved_log)
    ):
        raise ValueError("DDR attribute phase requires an explicit source variant")
    temporary_instances: dict[int, TemporaryResponseCache] | None = (
        {} if saved_log else None
    )
    if cache.source_build not in (12, 18):
        raise ValueError("Normal DDR attribute producer requires native12 or18")
    if (
        not isinstance(ecu_specific, tuple)
        or len(ecu_specific) > 100_000
        or any(not isinstance(item, DdrEcuContext) for item in ecu_specific)
    ):
        raise ValueError("DDR ECU-specific context list is invalid")
    cache.check_context()
    plan = initial_ddr_attribute_plan(_toyota_profile(cache.profile))
    if plan.source_build != cache.source_build:
        raise ValueError("DDR profile schema differs from selected native source")
    if cache.source_build == 12 and not internal_image:
        raise NotImplementedError("Native12 external DDR capture is unsupported")
    prepare_ddr_session(cache)
    plan = plan.check_support(cache, connections=connections, ecu_specific=ecu_specific)
    plan.validate_required()
    plan, initial = plan.read_group(
        cache, 0x21, connections=connections, temporary_instances=temporary_instances
    )
    observations = list(initial)

    def observed(logical: int) -> int:
        for identifier, value in reversed(observations):
            if identifier == logical:
                return value
        raise ToyotaCodecError("DDR required observation is absent", INVALID_RECORD)

    if observed(136) != 0xA0:
        raise ToyotaCodecError("Native DDR signature is unsupported", 0xA0041001)
    spec = plan.read_one(
        cache, 118, connections=connections, temporary_instances=temporary_instances
    )
    if spec is None:
        raise ToyotaCodecError(
            "DDR specification observation is absent", INVALID_RECORD
        )
    observations.append((118, spec))
    plan = plan.for_specification(spec)
    variant = observed(137) if spec == 2 else None
    legacy = spec == 2 and variant in (2, 3)
    plan = plan.with_legacy_group_override(spec, variant)
    if not legacy and not plan.group_supported(0xB1):
        raise ToyotaCodecError("Native DDR B1 group is unsupported", 0xA0041001)
    for pid in (0xB2,) if internal_image else (0xB2, 0xB1):
        plan, values = plan.read_group(
            cache, pid, connections=connections, temporary_instances=temporary_instances
        )
        observations.extend(values)
    limit = 7 if spec in (2, 3) else 9 if spec == 5 else 11
    return DdrAttributeCapture(
        plan,
        tuple(observations),
        spec,
        0 if internal_image else min(observed(101), limit),
    )


def ddr_bulk_record_eligible(
    attributes: DdrAttributePlan,
    observations: Mapping[int, int],
    record: DdrRecordSamples,
) -> bool:
    """Native9b70/9bc0 raw cutoff comparison; no guessed time/odometer label."""
    if (
        attributes.vehicle_sha256 != record.plan.source_sha256
        or attributes.category != record.plan.category
        or attributes.exception_ids != record.plan.exception_ids
        or len(attributes.slots) > (45 if attributes.p5 else 41)
        or len(record.values) > 100_000
    ):
        raise ValueError("DDR bulk cutoff context differs from selected record")
    present = {
        slot.logical_id for slot in attributes.slots if slot.candidates and slot.enabled
    }
    if not {170, 171} <= present:
        return True

    def observed(identifier: int) -> int:
        value = observations.get(identifier)
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("DDR bulk cutoff lacks observed uint32 attribute")
        return value

    first = observed(170)
    if first == 0xFFFF:
        return True
    second = observed(171) & 0x1FFFFFFF
    values = {}
    for identifier, _, value in record.values:
        values.setdefault(identifier, value)
    if 7 not in values or 10 not in values:
        raise ValueError("DDR bulk cutoff lacks native record IDs7/10")
    if any(
        type(values[key]) is not int or not 0 <= values[key] <= 0xFFFFFFFF
        for key in (7, 10)
    ):
        raise ValueError("DDR bulk cutoff record values must fit uint32")
    difference = (
        second - values[10] if first == values[7] else first - values[7]
    ) & 0xFFFFFFFF
    return difference >= 0x80000000


@dataclass(frozen=True)
class DdrSignalDefinition:
    identifier: int
    name_id: int
    name: str
    unit: str
    unit_code: int
    selector: int
    exponent: int
    sign_mode: int
    coefficients: tuple[int, int, int]
    limits: tuple[int, int]
    conversion: tuple[int, int]
    bit_width: int
    patterns: tuple[tuple[int, str, int], ...]
    monitor_record: bytes
    physical_record: bytes
    unit_record: bytes
    pattern_records: tuple[bytes, ...]


def selected_ddr_signal_definition(
    profile: VehicleProfile, plan: DdrRecordPlan, identifier: int
) -> DdrSignalDefinition:
    """Native8AF0 CCmdFrzFrmDat metadata, retaining every selected backing row."""
    from scripts.toyota import MISSING_RECORD, ToyotaCodecError

    if (
        profile.database.sha256 != plan.source_sha256
        or profile.category != plan.category
        or profile.exception_ids != plan.exception_ids
        or type(identifier) is not int
        or not 0 <= identifier <= 65535
    ):
        raise ValueError("DDR signal definition differs from selected source")
    rows = profile.ddr_records(plan.table_slots[0], identifier)
    if not rows:
        raise ToyotaCodecError("DDR signal monitor is absent", MISSING_RECORD)
    monitor = rows[0]
    return _ddr_signal_metadata(profile, monitor, identifier)


def selected_ads_signal_definition(
    profile: VehicleProfile, identifier: int
) -> DdrSignalDefinition:
    """ADS7F80/8450 CCmdFrzFrmDat[Ex] metadata from selected DB28660-byte rows."""
    from scripts.support import word
    from scripts.toyota import MISSING_RECORD, ToyotaCodecError

    if (
        profile.database.version != 0x0100032F
        or type(identifier) is not int
        or not 0 <= identifier <= 65535
    ):
        raise ValueError("ADS signal requires selected18 and uint16 identifier")
    monitor = next(
        (row for row in profile.records(134) if word(row, 36) == identifier), None
    )
    if monitor is None:
        raise ToyotaCodecError("ADS signal definition is absent", MISSING_RECORD)
    return _ddr_signal_metadata(profile, monitor, identifier, ads=True)


def _ddr_signal_metadata(
    profile: VehicleProfile, monitor: bytes, identifier: int, *, ads: bool = False
) -> DdrSignalDefinition:
    from scripts.support import word
    from scripts.toyota import INVALID_RECORD, MISSING_RECORD, ToyotaCodecError

    physical = next(
        (
            row
            for row in profile.records(13)
            if word(row, 12) == word(monitor, 40 if ads else 26)
        ),
        None,
    )
    if physical is None:
        raise ToyotaCodecError(
            "DDR signal physical definition is absent", MISSING_RECORD
        )
    unit = next(
        (row for row in profile.records(15) if word(row, 4) == word(physical, 14)), None
    )
    if unit is None:
        raise ToyotaCodecError("DDR signal unit definition is absent", MISSING_RECORD)
    if len(monitor) != (60 if ads else 48) or len(physical) != 24 or len(unit) != 12:
        raise ToyotaCodecError("DDR signal metadata width is invalid", INVALID_RECORD)
    pattern_id = word(monitor, 48 if ads else 38)
    patterns = []
    for row in profile.records(14):
        if len(row) != 24:
            raise ToyotaCodecError(
                "DDR display pattern width is invalid", INVALID_RECORD
            )
        if word(row, 12) == pattern_id:
            patterns.append(row)
        elif patterns:
            break
    if pattern_id and not patterns:
        raise ToyotaCodecError("DDR signal display pattern is absent", MISSING_RECORD)
    width = (
        word(monitor, 44 if ads else 30) - word(monitor, 42 if ads else 28) + 1
    ) & 65535
    if not 1 <= width <= (64 if ads else 32) or len(patterns) > 100_000:
        raise ToyotaCodecError("DDR signal metadata exceeds bounds", INVALID_RECORD)
    language = profile.catalog.language

    def dword(row: bytes, offset: int) -> int:
        return int.from_bytes(row[offset : offset + 4], "little")

    labels = tuple(
        (pattern_id, language.resolve(dword(row, 0)), dword(row, 4)) for row in patterns
    )
    name_id = dword(monitor, 24 if ads else 20)
    return DdrSignalDefinition(
        identifier,
        name_id,
        language.resolve(name_id),
        language.resolve(dword(unit, 0)),
        word(unit, 6),
        monitor[54 if ads else 44],
        physical[21],
        physical[20],
        (dword(physical, 0), dword(physical, 4), dword(physical, 8)),
        (dword(monitor, 12), dword(monitor, 16)),
        (
            (dword(monitor, 4), dword(monitor, 8))
            if ads
            else (dword(monitor, 0), dword(monitor, 4))
        ),
        width,
        labels,
        monitor,
        physical,
        unit,
        tuple(patterns),
    )


@dataclass(frozen=True)
class DdrDataIdTransaction:
    did: int
    request: bytes
    reply: bytes
    payload: bytes
    cache_hit: bool
    status: int = 0


def selected_ads_security_key(common_module: bytes) -> bytes:
    """Recover native90C40 material from the exact supplied18 PE, never embed it.

    Offsets select verified instruction immediates, not an executable import.
    This function neither loads nor executes the vendor module.
    """
    import struct

    if (
        not isinstance(common_module, bytes)
        or sha256(common_module).hexdigest()
        != "07547a9e47378d37c3ef7d96c2f33f6c62c4151626d98d3f3ff03b7c74909de7"
    ):
        raise ValueError(
            "ADS security material requires the exact supplied18 CommandCommon PE"
        )
    pe = struct.unpack_from("<I", common_module, 60)[0]
    sections = pe + 24 + struct.unpack_from("<H", common_module, pe + 20)[0]

    def immediate(rva: int) -> int:
        for index in range(struct.unpack_from("<H", common_module, pe + 6)[0]):
            _, address, size, offset = struct.unpack_from(
                "<4I", common_module, sections + 40 * index + 8
            )
            if address <= rva < address + size:
                return common_module[offset + rva - address] ^ 255
        raise ValueError("ADS security immediate is outside the original PE")

    return bytes(
        immediate(rva)
        for rva in (
            0x90CC6,
            0x90C44,
            0x90CCD,
            0x90C44,
            0x90CAD,
            0x90C68,
            0x90CD2,
            0x90C6E,
            0x90C4F,
            0x90C68,
            0x90CD7,
            0x90C6E,
            0x90C4F,
            0x90C5A,
            0x90CAD,
            0x90C5A,
        )
    )


@dataclass(frozen=True)
class AdsSecurityExchange:
    seed_reply: bytes
    key_request: bytes | None
    key_reply: bytes | None


def cancel_ads_security(cache: MonitorSupportCache, key: bytes) -> AdsSecurityExchange:
    """Common90C40/90E30/91180: selected109 seed and appended AES128 key on10A.

    Key is explicit material; production callers obtain it from the exact source
    using selected_ads_security_key. No vendor module is executed.
    """
    from scripts.programming_2026_common import native_aes128_ecb_block
    from scripts.toyota import (
        INVALID_RECORD,
        MISSING_RECORD,
        SHORT_REPLY,
        ToyotaCodecError,
    )

    cache.check_context()
    if (
        cache.source_build != 18
        or not cache.profile.category
        or not isinstance(key, bytes)
        or len(key) != 16
    ):
        raise ValueError(
            "ADS AES security requires selected18 ECU and sixteen-byte material"
        )

    def selected(function: int) -> SelectedFrame:
        try:
            frames = cache.profile.frame_records(function)
        except ValueError as error:
            raise ToyotaCodecError(
                "ADS security frame is absent", MISSING_RECORD
            ) from error
        if not frames:
            raise ToyotaCodecError("ADS security frame is absent", MISSING_RECORD)
        return frames[0]

    frame = selected(0x109)
    reply = cache.transaction(frame, frame.frame.request, cached=False, extended=True)
    frame.frame.check_mask(reply)
    # Native rejects >18 yet dereferences all16 seed bytes on shorter replies.
    # Require all18 bytes before reproducing its copy from reply[2:18].
    if len(reply) != 18:
        raise ToyotaCodecError(
            "ADS seed reply must contain exactly sixteen bytes", SHORT_REPLY
        )
    seed = reply[2:18]
    if not any(seed):
        return AdsSecurityExchange(reply, None, None)
    frame = selected(0x10A)
    if len(frame.frame.request) < 2:
        raise ToyotaCodecError("ADS key template lacks native prefix", INVALID_RECORD)
    request = frame.frame.request + native_aes128_ecb_block(key, seed)
    key_reply = cache.transaction(frame, request, cached=False, extended=True)
    frame.frame.check_mask(key_reply)
    return AdsSecurityExchange(reply, request, key_reply)


@dataclass(frozen=True)
class AdsDataIdPayload:
    identifier: int
    raw: bytes


@dataclass(frozen=True)
class AdsPacketGroup:
    declared_count: int
    rows: tuple[AdsDataIdPayload, ...]


@dataclass(frozen=True)
class AdsPacket:
    raw: bytes
    groups: tuple[AdsPacketGroup, ...]
    consumed: int
    incomplete: bool


def parse_ads_record_packet(raw: bytes) -> AdsPacket:
    """ADS25F0/3DC0 grouped DID/byte-length payloads after the8-byte wire prefix.

    Native retains complete rows before truncation and ignores duplicate/zero DIDs
    or zero-length values. The original packet and incomplete suffix remain visible.
    """
    if not isinstance(raw, bytes) or len(raw) > 65535:
        raise ValueError("ADS record packet must fit native receive WORD")

    def fallback_count() -> int:
        position, count = 9, 0
        while position + 3 <= len(raw):
            following = position + 3 + raw[position + 2]
            if following > len(raw):
                break
            count += 1
            position = following
        return count

    groups, position, incomplete, nodes = [], min(8, len(raw)), len(raw) < 8, 0
    while position < len(raw):
        declared = raw[position]
        position += 1
        count = declared or fallback_count()
        rows, seen = [], set()
        for _ in range(count):
            nodes += 1
            if nodes > 100_000:
                raise ValueError("ADS packet exceeds decoded-node allowance")
            if position + 3 > len(raw):
                incomplete = True
                break
            identifier = int.from_bytes(raw[position : position + 2], "big")
            length = raw[position + 2]
            position += 3
            if position + length > len(raw):
                incomplete = True
                break
            value = raw[position : position + length]
            position += length
            if identifier and length and identifier not in seen:
                rows.append(AdsDataIdPayload(identifier, value))
                seen.add(identifier)
        groups.append(AdsPacketGroup(declared, tuple(rows)))
        if incomplete:
            break
    return AdsPacket(raw, tuple(groups), position, incomplete)


@dataclass(frozen=True)
class AdsFrameTransaction:
    function: int
    selected: SelectedFrame
    request: bytes
    reply: bytes
    status: int = 0


@dataclass(frozen=True)
class AdsRawRecord:
    behavior: int
    behavior_records: tuple[bytes, ...]
    primary: int
    identifiers: tuple[int, ...]
    packets: tuple[tuple[int, AdsPacket], ...]


@dataclass(frozen=True)
class AdsRawCapture:
    source_sha256: str
    management_sha256: str
    category: int
    exception_ids: tuple[int, ...]
    security: AdsSecurityExchange
    ready_transactions: tuple[DdrDataIdTransaction, ...]
    transactions: tuple[AdsFrameTransaction, ...]
    records: tuple[AdsRawRecord, ...]


_ADS_IGNORABLE_ERRORS = frozenset(
    (
        0x91010009,
        0x90020321,
        0x90020323,
        0xA0040201,
        0xA0040202,
        0x90020327,
        0x91020320,
        0x91020310,
        0x91020322,
    )
)


def capture_ads_ddr_raw(cache: MonitorSupportCache, key: bytes) -> AdsRawCapture:
    """ADS Execute1D80→1050 selected security/ready/index/record wire acquisition.

    This preserves grouped raw DID values before the distinct64-bit ADS resource
    decoder, merge rules and formatter. It does not claim a complete ADS report.
    """
    from scripts.toyota import (
        INVALID_RECORD,
        MISSING_RECORD,
        SHORT_REPLY,
        ToyotaCodecError,
    )
    from scripts.toyota_session import SessionError

    cache.check_context()
    profile = _toyota_profile(cache.profile)
    if cache.source_build != 18 or profile.database.version != 0x0100032F:
        raise ValueError("ADS DDR requires the recovered18 resource factory")
    security = cancel_ads_security(cache, key)
    reader = DdrP5DataIdReader(cache, enable_list=False)
    state, _ = reader.read_no_enable_list(0x1C08, 1)
    if state != 1:
        raise ToyotaCodecError("ADS DDR global readiness support is absent", 0x90040501)
    state, ready = reader.read_no_enable_list(0x1C08, 6)
    if state != 2 or not ready or ready[0] != 0:
        raise ToyotaCodecError("ADS DDR readiness status is invalid", 0x90040501)
    transactions, records = [], []
    retained = (
        len(security.seed_reply)
        + len(security.key_request or b"")
        + len(security.key_reply or b"")
        + sum(len(row.request) + len(row.reply) for row in reader.transactions)
    )

    def read(function: int, patch: bytes = b"") -> bytes:
        nonlocal retained
        cache.check_context()
        try:
            frames = profile.frame_records(function)
        except ValueError as error:
            raise ToyotaCodecError(
                "ADS selected function frame is absent", MISSING_RECORD
            ) from error
        if not frames:
            raise ToyotaCodecError(
                "ADS selected function frame is absent", MISSING_RECORD
            )
        frame = frames[0]
        request = frame.frame.request
        if len(request) < 2 + len(patch):
            raise ToyotaCodecError(
                "ADS selected request lacks selector fields", INVALID_RECORD
            )
        request = request[:2] + patch + request[2 + len(patch) :]
        status, reply = 0, b""
        try:
            reply = cache.transaction(
                frame, request, cached=False, extended=True, capacity=65535
            )
            return reply
        except ToyotaCodecError as error:
            status, reply = (
                error.code,
                getattr(error, "reply", getattr(error, "response", b"")),
            )
            raise
        finally:
            size = len(request) + len(reply)
            if size > snapshot.MAX_BYTES - retained:
                raise SessionError("ADS raw capture byte allowance exhausted")
            retained += size
            transactions.append(
                AdsFrameTransaction(function, frame, request, reply, status)
            )

    # Native initializes one empty list entry per selected behavior-data record.
    if not profile.records(134):
        raise ToyotaCodecError("ADS behavior-data resources are absent", MISSING_RECORD)
    reply = read(0x10B)
    if len(reply) < 2:
        raise ToyotaCodecError("ADS behavior index lacks wire prefix", SHORT_REPLY)
    for offset in range(2, len(reply) - 1, 2):
        behavior = int.from_bytes(reply[offset : offset + 2], "big")
        selected = []
        for row in profile.records(133):
            if int.from_bytes(row[32:34], "little") == behavior:
                selected.append(row)
            elif selected:
                break
        if not selected:
            continue
        try:
            reply = read(0x10C, behavior.to_bytes(2, "big"))
        except ToyotaCodecError as error:
            if error.code in _ADS_IGNORABLE_ERRORS:
                continue
            raise
        if len(reply) < 4:
            raise ToyotaCodecError("ADS record index lacks wire prefix", SHORT_REPLY)
        identifiers = tuple(
            sorted(
                {
                    int.from_bytes(reply[index : index + 4], "big")
                    for index in range(4, len(reply) - 3, 4)
                }
            )
        )
        for primary in (
            identifier for identifier in identifiers if identifier >> 16 == 0
        ):
            group = (primary,) + tuple(
                identifier
                for identifier in identifiers
                if identifier >> 16 == primary and identifier >> 16 != 0
            )
            packets = []
            for index, identifier in enumerate(group):
                try:
                    raw = read(
                        0x10D,
                        behavior.to_bytes(2, "big") + identifier.to_bytes(4, "big"),
                    )
                except ToyotaCodecError as error:
                    if error.code not in _ADS_IGNORABLE_ERRORS:
                        raise
                    if index == 0:
                        break
                    continue
                packet = parse_ads_record_packet(raw)
                if index == 0 and not any(group.rows for group in packet.groups):
                    break
                packets.append((identifier, packet))
            else:
                if len(records) >= 100_000:
                    raise SessionError("ADS raw record-node allowance exhausted")
                records.append(
                    AdsRawRecord(
                        behavior, tuple(selected), primary, group, tuple(packets)
                    )
                )
    return AdsRawCapture(
        profile.database.sha256,
        profile.catalog.management.sha256,
        profile.category,
        profile.exception_ids,
        security,
        tuple(reader.transactions),
        tuple(transactions),
        tuple(records),
    )


def ads_bits(raw: bytes, first: int, last: int) -> int:
    """ADS9350 inclusive MSB-first field, preserving the native low64-bit result."""
    if (
        not isinstance(raw, bytes)
        or not 1 <= len(raw) <= 255
        or type(first) is not int
        or type(last) is not int
        or not 0 <= first <= last < len(raw) * 8
    ):
        raise ValueError("ADS scalar requires captured bytes and inclusive bit bounds")
    return (int.from_bytes(raw, "big") >> (len(raw) * 8 - last - 1)) & (
        (1 << min(64, last - first + 1)) - 1
    )


@dataclass(frozen=True)
class AdsValueSeries:
    identifier: int
    kind: int
    samples: tuple[tuple[int, int], ...]
    definition: bytes

    def __post_init__(self) -> None:
        if (
            type(self.identifier) is not int
            or not 0 <= self.identifier <= 65535
            or type(self.kind) is not int
            or not 0 <= self.kind <= 255
            or not isinstance(self.definition, bytes)
            or len(self.definition) != 60
            or not isinstance(self.samples, tuple)
            or len(self.samples) > 100_000
            or any(
                not isinstance(sample, tuple)
                or len(sample) != 2
                or type(sample[0]) is not int
                or not 0 <= sample[0] <= 0xFFFFFFFFFFFFFFFF
                or type(sample[1]) is not int
                or not 0 <= sample[1] <= 0xFFFFFFFF
                for sample in self.samples
            )
        ):
            raise ValueError(
                "ADS series requires selected60-byte metadata and uint64 values/flags"
            )


@dataclass(frozen=True)
class AdsDecodedRecord:
    source_sha256: str
    category: int
    exception_ids: tuple[int, ...]
    raw: AdsRawRecord
    series: tuple[AdsValueSeries, ...]
    header: bytes = b""
    counts: tuple[int, int, int] = (0, 0, 0)


def _ads_behavior_records(
    profile: VehicleProfile, behavior: int, selectors: tuple[int, int] | None = None
) -> tuple[bytes, ...]:
    from scripts.support import word

    rows = profile.records(133)
    keys = ((32, behavior, False),) + (
        ()
        if selectors is None
        else ((40, selectors[0], True), (41, selectors[1], True))
    )
    for offset, key, byte_key in keys:
        selected = []
        for row in rows:
            value = row[offset] if byte_key else word(row, offset)
            if value == key:
                selected.append(row)
            elif selected:
                break
        rows = tuple(selected)
    return rows


def _ads_payload_valid(
    profile: VehicleProfile,
    row: bytes,
    raw: bytes,
    group: AdsPacketGroup,
    previous: bool,
) -> bool:
    """ADS3300/36C0: RoB end-bit marker and optional selected in-packet DID bit."""
    from scripts.support import word
    from scripts.toyota import INVALID_RECORD, ToyotaCodecError

    definitions = profile.rob_data_id_records(word(row, 52))
    # Native logs a missing RoB definition but returns0 without overwriting the
    # caller's current validity variable (initialized once per received DID).
    if not definitions:
        return previous
    last = word(row, 44)
    if len(raw) * 8 <= last:
        return False
    mode = definitions[0][6]
    if mode == 1:
        offset = (last >> 3) - 1
        if offset < 0:
            raise ToyotaCodecError(
                "ADS RoB marker precedes captured storage", INVALID_RECORD
            )
        marker = 0x80 >> (last & 7)
        valid = raw[offset] & marker == marker
    else:
        valid = mode in (0, 2)
    reference = word(row, 38)
    if not valid or not reference:
        return valid
    bits = profile._bit_records(89, reference)
    if not bits:
        return False
    bit = bits[0]
    variable = profile._bit_variable(89, bit)
    if len(variable) < 2:
        raise ToyotaCodecError("ADS RoB bit variable lacks its DID", INVALID_RECORD)
    did = int.from_bytes(variable[:2], "big")
    observed = next((item.raw for item in group.rows if item.identifier == did), None)
    if observed is None or bit[11] != 7:
        return False
    return ads_bits(observed, word(bit, 6), word(bit, 8)) != 0


def decode_ads_ddr_record(
    profile: VehicleProfile,
    captured: AdsRawRecord,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> AdsDecodedRecord | None:
    """ADS1AE0/3170/2CA0/3300/38C0: selected64-bit values and native missingflag3.

    Each accepted base/secondary packet appends one sample per selected record
    definition. Unknown selectors or sentinel headers skip a secondary packet and
    discard a base record. Native keeps first matching logical/DID observations.
    """
    from collections import deque

    from scripts.support import word
    from scripts.toyota import INVALID_RECORD, MISSING_RECORD, ToyotaCodecError
    from scripts.toyota_session import Cancelled

    if cancelled and cancelled():
        raise Cancelled("ADS decoding cancelled")
    if (
        profile.database.version != 0x0100032F
        or captured.behavior_records
        != _ads_behavior_records(profile, captured.behavior)
    ):
        raise ValueError("ADS record differs from selected18 behavior resources")
    definitions = profile.records(134)
    if not definitions:
        raise ToyotaCodecError("ADS behavior-data records are absent", MISSING_RECORD)
    if len(definitions) > 100_000:
        raise ValueError("ADS behavior-data count exceeds node allowance")
    output = [AdsValueSeries(word(row, 36), row[59], (), row) for row in definitions]
    by_did: dict[int, list[int]] = {}
    logical_groups: dict[int, list[bytes]] = {}
    previous = None
    for row in definitions:
        logical = word(row, 36)
        by_did.setdefault(word(row, 52), []).append(logical)
        if logical == previous or logical not in logical_groups:
            logical_groups.setdefault(logical, []).append(row)
        previous = logical
    steps = 0
    for identifier, packet in captured.packets:
        decoded = []
        for group in packet.groups:
            for payload in group.rows:
                valid = False
                for logical in dict.fromkeys(by_did.get(payload.identifier, ())):
                    steps += 1
                    if steps > 1_000_000:
                        raise ValueError("ADS decoding exceeds host work allowance")
                    if cancelled and cancelled():
                        raise Cancelled("ADS decoding cancelled")
                    matches = logical_groups[logical]
                    if len(matches) != 1:
                        raise ToyotaCodecError(
                            "ADS logical record resource is not unique", 0xC0040102
                        )
                    row = matches[0]
                    first, last = word(row, 42), word(row, 44)
                    needed = ((last >> 3) + 1) & 255
                    if needed == ((first >> 3) & 255):
                        raise ToyotaCodecError(
                            "ADS selected scalar bit interval is invalid",
                            INVALID_RECORD,
                        )
                    if len(payload.raw) < needed:
                        break
                    valid = _ads_payload_valid(profile, row, payload.raw, group, valid)
                    if valid:
                        decoded.append((logical, ads_bits(payload.raw, first, last)))
        if not decoded:
            if identifier >> 16 == 0:
                return None
            continue
        first = {}
        for logical, value in decoded:
            first.setdefault(logical, value)
        selectors = (first.get(17), first.get(18))
        usable = (
            selectors[0] is not None
            and selectors[1] is not None
            and bool(
                _ads_behavior_records(
                    profile, captured.behavior, (selectors[0] & 255, selectors[1] & 255)
                )
            )
        )
        mode, value = first.get(12), first.get(13)
        usable = (
            usable
            and mode is not None
            and value is not None
            and mode & 255 < 4
            and value & 0xFFFFFFFF != (0x1FFFFFFF if mode & 255 == 3 else 0xFFFFFFFF)
        )
        if not usable:
            if identifier >> 16 == 0:
                return None
            continue
        pending_values = {}
        for logical, value in decoded:
            pending_values.setdefault(logical, deque()).append(value)
        for index, row in enumerate(output):
            candidates = pending_values.get(row.identifier)
            sample = (candidates.popleft(), 0) if candidates else (0, 3)
            output[index] = replace(row, samples=row.samples + (sample,))
        if len(output) + sum(len(row.samples) for row in output) > 100_000:
            raise ValueError("ADS decoded samples exceed node allowance")
    return AdsDecodedRecord(
        profile.database.sha256,
        profile.category,
        profile.exception_ids,
        captured,
        tuple(output),
    )


def _ads_condition_records(
    profile: VehicleProfile, identifier: int
) -> tuple[bytes, ...]:
    from scripts.support import word

    selected = []
    for row in profile.records(135):
        if word(row, 8) == identifier:
            selected.append(row)
        elif selected:
            break
    return tuple(selected)


def transform_ads_ddr_record(
    profile: VehicleProfile,
    record: AdsDecodedRecord,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> AdsDecodedRecord | None:
    """ADS45D0..51C0: header counts, marker/64-bit invalid rules and propagation."""
    from collections import deque

    from scripts.support import word
    from scripts.toyota import INVALID_RECORD, ToyotaCodecError
    from scripts.toyota_session import Cancelled, decode_bcd32

    selected_definitions = profile.records(134)
    definitions = frozenset(selected_definitions)
    metadata_by_id = {}
    for definition in selected_definitions:
        metadata_by_id.setdefault(word(definition, 36), definition)
    if (
        profile.database.version != 0x0100032F
        or (record.source_sha256, record.category, record.exception_ids)
        != (profile.database.sha256, profile.category, profile.exception_ids)
        or len(record.series) + sum(len(row.samples) for row in record.series) > 100_000
        or any(
            row.definition not in definitions
            or word(row.definition, 36) != row.identifier
            or row.definition[59] != row.kind
            for row in record.series
        )
    ):
        raise ValueError("ADS transformation differs from selected18 source")
    steps = 0

    def check() -> None:
        nonlocal steps
        steps += 1
        if steps > 1_000_000:
            raise ValueError("ADS transformation exceeds host work allowance")
        if cancelled and cancelled():
            raise Cancelled("ADS transformation cancelled")

    check()
    series = tuple(
        row
        for row in record.series
        if row.kind != 1 or any(flag != 3 for _, flag in row.samples)
    )
    first = {}
    for index, row in enumerate(series):
        first.setdefault(row.identifier, index)
    if not {13, 17, 18} <= first.keys():
        return None
    selector_a, selector_b, times = (series[first[key]].samples for key in (17, 18, 13))
    count = len(selector_a)
    if not count or len(selector_b) < count or len(times) < count:
        raise ToyotaCodecError(
            "ADS header series lacks captured samples", INVALID_RECORD
        )
    pair = (selector_a[0][0] & 255, selector_b[0][0] & 255)
    different = sum(
        (selector_a[i][0] & 255, selector_b[i][0] & 255) != pair
        for i in range(1, count)
    )
    remaining = count - different
    before = 0
    for i in range(1, remaining):
        if times[0][0] & 0xFFFFFFFF <= times[i][0] & 0xFFFFFFFF:
            break
        before += 1
    counts = (before, remaining - before - 1, different + 1)
    values = [list(row.samples) for row in series]
    marker: tuple[tuple[int, int], ...] = (
        series[first[19]].samples if 19 in first else ()
    )
    if not any(value & 255 == 0x55 for value, _ in marker):
        for index, row in enumerate(series):
            for offset in range(
                1 if row.identifier in (17, 18) else 0, len(row.samples)
            ):
                value, flag = values[index][offset]
                if flag == 0:
                    values[index][offset] = (value, 1)
        return replace(
            record,
            series=tuple(
                replace(row, samples=tuple(value))
                for row, value in zip(series, values, strict=True)
            ),
            header=bytes(pair),
            counts=counts,
        )
    for offset, marker_sample in enumerate(marker):
        mark = marker_sample[0]
        check()
        if mark & 255 == 0x55:
            continue
        for index, row in enumerate(series):
            if row.kind == 1 or (offset and row.identifier in (17, 18)):
                if offset >= len(values[index]):
                    raise ToyotaCodecError(
                        "ADS marker exceeds captured timeline", INVALID_RECORD
                    )
                value, flag = values[index][offset]
                if flag == 0 or (offset and row.identifier in (17, 18)):
                    values[index][offset] = (value, 1)
    all_conditions = profile.records(135)
    if len(all_conditions) > 100_000 or any(len(row) != 24 for row in all_conditions):
        raise ToyotaCodecError(
            "ADS invalid-condition table exceeds width/count", INVALID_RECORD
        )
    conditions_by_id: dict[int, list[bytes]] = {}
    previous = None
    for condition in all_conditions:
        identifier = word(condition, 8)
        if identifier == previous or identifier not in conditions_by_id:
            conditions_by_id.setdefault(identifier, []).append(condition)
        previous = identifier
    for row_index, row in enumerate(series):
        conditions = conditions_by_id.get(row.identifier, [])
        for offset, (value, flag) in enumerate(values[row_index]):
            if flag != 0:
                continue
            invalid = False
            for position, condition in enumerate(conditions):
                check()
                if position and not invalid and conditions[position - 1][16] != 2:
                    continue
                invalid = False
                reference = word(condition, 10)
                if reference == row.identifier:
                    observed = value
                elif reference in first:
                    other = series[first[reference]]
                    selected = 0 if other.kind == 0 else offset
                    if other.kind != 0 and len(other.samples) != len(row.samples):
                        raise ToyotaCodecError(
                            "ADS condition timelines differ", 0xC0040102
                        )
                    if selected >= len(values[first[reference]]):
                        raise ToyotaCodecError(
                            "ADS condition reference is absent", INVALID_RECORD
                        )
                    observed = values[first[reference]][selected][0]
                else:
                    continue
                expected = int.from_bytes(condition[:8], "little")
                if condition[17] not in (1, 2):
                    raise ToyotaCodecError(
                        "ADS condition comparison is invalid", 0xC0040102
                    )
                invalid = (
                    (observed == expected)
                    if condition[17] == 1
                    else (observed != expected)
                )
                if invalid and condition[16] == 2:
                    break
            if invalid:
                values[row_index][offset] = (value, 2)
    for identifier, low, high in (
        (6, 0, 38),
        (7, 1, 12),
        (8, 1, 31),
        (9, 0, 23),
        (10, 0, 59),
        (11, 0, 59),
    ):
        if identifier not in first:
            continue
        index = first[identifier]
        if not values[index]:
            raise ToyotaCodecError("ADS time sample is absent", INVALID_RECORD)
        value, flag = values[index][0]
        if flag:
            continue
        try:
            decoded = decode_bcd32(value & 0xFFFFFFFF)
        except ToyotaCodecError:
            decoded = None
        values[index][0] = (
            (decoded, 0)
            if decoded is not None and low <= decoded <= high
            else (value, 2)
        )
    if 5 in first:
        index = first[5]
        if not values[index]:
            raise ToyotaCodecError("ADS ID5 sample is absent", INVALID_RECORD)
        value, flag = values[index][0]
        if flag == 0 and value & 0xFFFFFFFF > 999999:
            values[index][0] = (value, 2)
    references = tuple(
        dict.fromkeys(
            word(row, 10) for row in all_conditions if word(row, 8) != word(row, 10)
        )
    )
    pending = deque()
    for reference in references:
        for index, row in enumerate(series):
            if row.identifier == reference:
                indices = tuple(
                    i for i, (_, flag) in enumerate(values[index]) if flag == 2
                )
                if indices:
                    pending.append((reference, indices))
    changed = False  # Native51C0 retains local_94 throughout the pending queue.
    while pending:
        reference, indices = pending.popleft()
        for index, row in enumerate(series):
            conditions = conditions_by_id.get(row.identifier, [])
            position = 0
            while position < len(conditions):
                check()
                if word(conditions[position], 10) != reference:
                    position += 1
                    continue
                start = position
                while start and conditions[start - 1][16] != 2:
                    start -= 1
                end, valid = start, True
                while end < len(conditions):
                    if valid and end != position:
                        valid = any(
                            item == word(conditions[end], 10) for item, _ in pending
                        )
                    if conditions[end][16] != 1:
                        break
                    end += 1
                if valid:
                    if indices[0] >= len(values[index]):
                        raise ToyotaCodecError(
                            "ADS propagated index exceeds timeline", INVALID_RECORD
                        )
                    if values[index][indices[0]][1] == 0:
                        metadata = metadata_by_id.get(reference)
                        if metadata is not None:
                            selected = (
                                range(len(values[index]))
                                if metadata[59] == 0
                                else indices
                            )
                            for offset in selected:
                                if offset >= len(values[index]):
                                    raise ToyotaCodecError(
                                        "ADS propagated index exceeds timeline",
                                        INVALID_RECORD,
                                    )
                                value, flag = values[index][offset]
                                if flag != 2:
                                    values[index][offset] = (value, 2)
                                    changed = True
                            if changed:
                                pending.append((row.identifier, indices))
                position = end + 1
    check()
    return replace(
        record,
        series=tuple(
            replace(row, samples=tuple(value))
            for row, value in zip(series, values, strict=True)
        ),
        header=bytes(pair),
        counts=counts,
    )


def capture_ads_ddr_records(
    cache: MonitorSupportCache, key: bytes
) -> tuple[AdsRawCapture, tuple[AdsDecodedRecord, ...]]:
    """Actual ADS acquisition joined to selected64-bit decoding and native flags."""
    captured = capture_ads_ddr_raw(cache, key)
    records = []
    for raw in captured.records:
        decoded = decode_ads_ddr_record(
            _toyota_profile(cache.profile), raw, cancelled=cache.cancelled
        )
        if decoded is not None:
            transformed = transform_ads_ddr_record(
                _toyota_profile(cache.profile), decoded, cancelled=cache.cancelled
            )
            if transformed is not None:
                records.append(transformed)
    return captured, tuple(records)


@dataclass(frozen=True)
class AdsDdrInfo:
    source_sha256: str
    language_sha256: str
    header_a: tuple[tuple[int, int], ...]
    header_b: tuple[tuple[int, int], ...]
    triggers: tuple[DdrTriggerDescription, ...]
    conversion: tuple[int, int]
    counts: tuple[int, int, int]
    scalars: tuple[DdrFormattedSignal, ...]
    bytes: tuple[tuple[int, int, int], ...]
    mode: tuple[int, int] | None
    markers: tuple[tuple[tuple[int, int], ...], ...]
    main_signals: tuple[DdrFormattedSignal, ...]
    side_signals: tuple[DdrFormattedSignal, ...]


@dataclass(frozen=True)
class AdsDdrReport:
    capture: AdsRawCapture
    records: tuple[AdsDecodedRecord, ...]
    information: tuple[AdsDdrInfo, ...]
    monitor_catalog: tuple[DdrMonitorCatalogEntry, ...]


def format_ads_ddr_info(
    profile: VehicleProfile, record: AdsDecodedRecord
) -> AdsDdrInfo:
    """ADS5B90/5F30/7960 CCmdADSDdrInfo, retaining uint64 channels and selected rows."""
    from scripts.support import word
    from scripts.toyota import INVALID_RECORD, MISSING_RECORD, ToyotaCodecError

    if (record.source_sha256, record.category, record.exception_ids) != (
        profile.database.sha256,
        profile.category,
        profile.exception_ids,
    ) or profile.database.version != 0x0100032F:
        raise ValueError("ADS report differs from selected18 source")
    definitions = frozenset(profile.records(134))
    if len(record.series) + sum(
        len(row.samples) for row in record.series
    ) > 100_000 or any(
        row.definition not in definitions
        or word(row.definition, 36) != row.identifier
        or row.definition[59] != row.kind
        for row in record.series
    ):
        raise ValueError(
            "ADS report series differs from selected metadata or host allowance"
        )
    rows = tuple(row for row in record.series if row.definition[55] != 2)
    first = {}
    for row in rows:
        first.setdefault(row.identifier, row)
    before, after, main_count = record.counts
    if (
        len(record.header) != 2
        or any(type(n) is not int or n < 0 for n in record.counts)
        or main_count < 1
    ):
        raise ValueError("ADS report requires transformed header/counts")
    start = before + after + 1
    indices = (0,) + tuple(range(start, start + main_count - 1))
    side_indices = tuple(range(1, start))

    def samples(
        identifier: int, positions: tuple[int, ...]
    ) -> tuple[tuple[int, int], ...]:
        row = first.get(identifier)
        if row is None or any(i >= len(row.samples) for i in positions):
            raise ToyotaCodecError(
                "ADS formatter series/slice is absent", INVALID_RECORD
            )
        return tuple((row.samples[i][0], row.samples[i][1] & 255) for i in positions)

    header_a = tuple((value & 255, flag) for value, flag in samples(17, indices))
    header_b = tuple((value & 255, flag) for value, flag in samples(18, indices))
    descriptions = []
    language = profile.catalog.language
    for (a, flag), (b, _) in zip(header_a, header_b, strict=True):
        if flag:
            descriptions.append(DdrTriggerDescription(0, 0, "", "", flag, None))
            continue
        selected = _ads_behavior_records(profile, record.raw.behavior, (a, b))
        if not selected:
            raise ToyotaCodecError("ADS trigger resource is absent", MISSING_RECORD)
        resource = selected[0]
        name_id, memo_id = (
            int.from_bytes(resource[i : i + 4], "little") for i in (12, 16)
        )
        descriptions.append(
            DdrTriggerDescription(
                name_id,
                memo_id,
                language.resolve(name_id),
                language.resolve(int.from_bytes(resource[28:32], "little")),
                0,
                resource,
            )
        )
    selected = _ads_behavior_records(
        profile, record.raw.behavior, (header_a[0][0], header_b[0][0])
    )
    if not selected:
        raise ToyotaCodecError("ADS base trigger resource is absent", MISSING_RECORD)
    conversion = tuple(
        int.from_bytes(selected[0][i : i + 4], "little") for i in (20, 24)
    )
    scalars = []
    for identifier in (1, 5, 12, 13, 14, 15, 16):
        row = first.get(identifier)
        if row is None:
            continue
        if not row.samples:
            raise ToyotaCodecError("ADS scalar has no sample", INVALID_RECORD)
        values = row.samples if identifier == 13 else row.samples[:1]
        # Native1/5/12/13 scalar CCmdMultiData retains lowDWORD;14/15/16 Ex retains64.
        mask = 0xFFFFFFFFFFFFFFFF if identifier in (14, 15, 16) else 0xFFFFFFFF
        scalars.append(
            DdrFormattedSignal(
                selected_ads_signal_definition(profile, identifier),
                tuple((value & mask, flag & 255) for value, flag in values),
            )
        )
    bytes_out = tuple(
        (identifier, values[0][0] & 255, values[0][1])
        for identifier in (4, 6, 7, 8, 9, 10, 11)
        if identifier in first and (values := samples(identifier, (0,)))
    )
    mode = samples(12, (0,))[0] if 12 in first else None
    if mode is not None:
        mode = (mode[0] & 0xFFFFFFFF, mode[1])
    markers = (
        tuple(
            tuple((value & 255, flag) for value, flag in samples(19, positions))
            for positions in (
                tuple(range(1, before + 1)),
                tuple(range(before + 1, start)),
                indices,
            )
        )
        if 19 in first
        else ((), (), ())
    )
    main, side = [], []
    for row in rows:
        if row.kind != 1:
            continue
        definition = selected_ads_signal_definition(profile, row.identifier)
        # Preserve each native series, including repeated logical IDs.
        if any(i >= len(row.samples) for i in indices + side_indices):
            raise ToyotaCodecError(
                "ADS monitor timeline slice is absent", INVALID_RECORD
            )
        main.append(
            DdrFormattedSignal(
                definition,
                tuple((row.samples[i][0], row.samples[i][1] & 255) for i in indices),
            )
        )
        side.append(
            DdrFormattedSignal(
                definition,
                tuple(
                    (row.samples[i][0], row.samples[i][1] & 255) for i in side_indices
                ),
            )
        )
    return AdsDdrInfo(
        profile.database.sha256,
        language.sha256,
        header_a,
        header_b,
        tuple(descriptions),
        (conversion[0], conversion[1]),
        record.counts,
        tuple(scalars),
        bytes_out,
        mode,
        markers,
        tuple(main),
        tuple(side),
    )


def _ads_monitor_catalog(profile: VehicleProfile) -> tuple[DdrMonitorCatalogEntry, ...]:
    from scripts.support import word

    catalog = []
    definitions = profile.records(134)
    by_id, physical_by_id, units_by_id = {}, {}, {}
    for row in definitions:
        by_id.setdefault(word(row, 36), row)
    for row in profile.records(13):
        physical_by_id.setdefault(word(row, 12), row)
    for row in profile.records(15):
        units_by_id.setdefault(word(row, 4), row)
    for row in definitions:
        if row[59] != 1:
            continue
        identifier = word(row, 36)
        selected = by_id[identifier]
        if selected[55] == 2:
            continue
        physical = physical_by_id.get(word(selected, 40))
        unit = units_by_id.get(word(physical, 14)) if physical is not None else None
        if physical is None or unit is None:
            continue  # Native8C70 logs missing metadata and continues catalog construction.
        name_id = int.from_bytes(selected[24:28], "little")
        catalog.append(
            DdrMonitorCatalogEntry(
                identifier,
                profile.catalog.language.resolve(name_id),
                profile.catalog.language.resolve(int.from_bytes(unit[:4], "little")),
                word(unit, 6),
                selected,
                physical,
                unit,
            )
        )
    return tuple(catalog)


def format_ads_ddr_capture(
    profile: VehicleProfile,
    capture: AdsRawCapture,
    records: tuple[AdsDecodedRecord, ...],
) -> AdsDdrReport:
    if (
        capture.source_sha256,
        capture.management_sha256,
        capture.category,
        capture.exception_ids,
    ) != (
        profile.database.sha256,
        profile.catalog.management.sha256,
        profile.category,
        profile.exception_ids,
    ) or any(record.raw not in capture.records for record in records):
        raise ValueError("ADS capture/report sources differ")
    # NativeExecute calls5B90 only for a nonempty transformed list.
    return AdsDdrReport(
        capture,
        records,
        tuple(format_ads_ddr_info(profile, record) for record in records),
        _ads_monitor_catalog(profile) if records else (),
    )


def capture_ads_ddr_report(cache: MonitorSupportCache, key: bytes) -> AdsDdrReport:
    captured, records = capture_ads_ddr_records(cache, key)
    cache.check_context()
    return format_ads_ddr_capture(_toyota_profile(cache.profile), captured, records)


class DdrP5DataIdReader:
    """Native69B20/69E50 over concrete selected CA and actual support observations."""

    def __init__(
        self,
        cache: MonitorSupportCache,
        *,
        enable_list: bool = True,
        no_init: bool = False,
    ):
        from scripts.monitor_support import DataIdSupport, TemporaryResponseCache
        from scripts.toyota import INVALID_RECORD, MISSING_RECORD, ToyotaCodecError

        cache.check_context()
        if type(enable_list) is not bool or type(no_init) is not bool:
            raise ValueError("DDR DID enable-list/no-init policies must be Boolean")
        if cache.source_build != 18 or not cache.profile.category or not cache.bus_id:
            raise ValueError(
                "Native P5 DDR DID reader requires selected18 ECU and observed nonzero bus"
            )
        try:
            frames = cache.profile.frame_records(0xCA)
        except ValueError as error:
            raise ToyotaCodecError(
                "DDR selected CA frame is absent", MISSING_RECORD
            ) from error
        if not frames or len(frames[0].frame.request) < 3:
            raise ToyotaCodecError("DDR CA template lacks DID fields", INVALID_RECORD)
        self.cache = cache
        self.no_init = no_init
        assert cache.bus_id is not None
        self.bus_id = cache.bus_id
        self.identity = (*cache.identity, cache.source_build, cache.bus_id)
        self.selected = frames[0]
        self.support = cache.data_ids() if enable_list else DataIdSupport(())
        self.temporary = TemporaryResponseCache((*cache.identity, cache.source_build))
        self.transactions: list[DdrDataIdTransaction] = []
        self.retained_bytes = 0

    def check_ddr_support(self) -> None:
        from scripts.toyota import ToyotaCodecError

        self.cache.check_context()
        if not {0x1401, 0x1402} <= set(self.support.identifiers):
            raise ToyotaCodecError(
                "Native DDR required DIDs are unsupported", 0xA0041001
            )

    def read(self, did: int) -> bytes | None:
        return self._read(did, supported=True)

    def read_no_enable_list(self, did: int, control: int) -> tuple[int, bytes]:
        """Common69C70/6A0C0: literal global/group support stages and unchecked read.

        State1 means global support, state2 means selected group support. Native
        control1 performs only the first stage; control6 checks group then reads.
        """
        from scripts.toyota import ToyotaCodecError

        if (
            type(did) is not int
            or not 1 <= did <= 65535
            or type(control) is not int
            or not 0 <= control <= 255
            or not control & 7
        ):
            raise ValueError("Native DataRef no-enable selector/control is invalid")
        state, payload = 0, b""

        def supported(raw: bytes, position: int) -> bool:
            index, bit = divmod(position, 8)
            # Native6A0C0 has an inclusive length check before GetAt; the host
            # bounds its read instead of dereferencing a missing final byte.
            return index < len(raw) and bool(raw[index] & (0x80 >> bit))

        if control & 1:
            observed = self._read(0x0101, supported=False)
            assert observed is not None
            if not supported(observed, did >> 8):
                return state, payload
            state = 1
        if control & 2:
            if not did & 255:
                raise ToyotaCodecError(
                    "Native group DID support needs a nonzero low byte", 0xC0040001
                )
            observed = self._read(did & 0xFF00, supported=False)
            assert observed is not None
            if not supported(observed, (did & 255) - 1):
                return state, payload
            state = 2
        if control & 4:
            observed = self._read(did, supported=False)
            assert observed is not None
            payload = observed
        return state, payload

    def _read(self, did: int, *, supported: bool) -> bytes | None:
        from scripts.toyota import SHORT_REPLY, ToyotaCodecError
        from scripts.toyota_session import SessionError

        if type(did) is not int or not 1 <= did <= 65535:
            raise ValueError("Native DataRef DID must be a nonzero uint16")
        self.cache.check_context()
        if (
            *self.cache.identity,
            self.cache.source_build,
            self.cache.bus_id,
        ) != self.identity:
            raise ValueError("DDR DID selected context changed")
        if supported and did not in self.support.identifiers:
            return None
        if len(self.transactions) >= 100_000:
            raise SessionError("DDR DID transaction allowance exhausted")
        request = self.selected.frame.request
        request = request[:1] + did.to_bytes(2, "big") + request[3:]
        try:
            with self.cache.temporary_scope(self.temporary, no_init=self.no_init):
                reply = self.cache.transaction(
                    self.selected,
                    request,
                    native_parameter=self.bus_id,
                    cached=False,
                    temporary=True,
                )
        except ToyotaCodecError as error:
            reply = getattr(error, "reply", getattr(error, "response", b""))
            self._record(did, request, reply, error.code)
            raise
        status = SHORT_REPLY if len(reply) <= 3 else 0
        transaction = self._record(did, request, reply, status)
        if status:
            raise ToyotaCodecError("Native DDR DID reply has no payload", status)
        return transaction.payload

    def _record(
        self, did: int, request: bytes, reply: bytes, status: int
    ) -> DdrDataIdTransaction:
        from scripts.toyota_session import SessionError

        if not isinstance(reply, bytes):
            raise TypeError("DDR DID provider must preserve reply bytes")
        retained = len(request) + len(reply)
        if retained > snapshot.MAX_BYTES - self.retained_bytes:
            raise SessionError("DDR DID recording byte allowance exhausted")
        self.retained_bytes += retained
        transaction = DdrDataIdTransaction(
            did,
            request,
            reply,
            reply[3:] if status == 0 else b"",
            self.cache.cache_hit,
            status,
        )
        self.transactions.append(transaction)
        return transaction


def capture_ddr_p5_attributes(
    cache: MonitorSupportCache,
    *,
    connections: Mapping[tuple[int, int], NativeCommunication] | None = None,
    ecu_specific: tuple[DdrEcuContext, ...] = (),
) -> DdrAttributeCapture:
    """Common38660 attribute phase: C1/C2, requiredDIDs, spec118, support, DID1401.

    The command-owned TEMP is shared by the initial spec read and later attributes;
    header and case collection use their own separate native TEMP lifetimes.
    """
    from scripts.toyota import ToyotaCodecError

    plan = initial_ddr_p5_attribute_plan(_toyota_profile(cache.profile))
    plan._check(cache)
    _prepare_ddr_pairs(cache, ((0xC1, 0xC2),))
    DdrP5DataIdReader(cache).check_ddr_support()
    temporary: dict[int, TemporaryResponseCache] = {}
    spec = plan.read_one(
        cache, 118, connections=connections, temporary_instances=temporary
    )
    if spec is None:
        raise ToyotaCodecError("P5 DDR specification attribute is absent", 0xA0041001)
    plan = plan.for_specification(spec)
    plan = plan.check_support(cache, connections=connections, ecu_specific=ecu_specific)
    plan, observations = plan.read_group(
        cache, 0x1401, connections=connections, temporary_instances=temporary
    )
    return DdrAttributeCapture(plan, ((118, spec),) + observations, spec, 1)


_DDR_P5_BANKS = {
    10: (110, 108, 109),
    13: (129, 127, 128),
    14: (138, 136, 137),
    15: (147, 145, 146),
}


def decode_ddr_p5_header(
    profile: VehicleProfile, spec_value: int, raw: bytes
) -> DdrRecordSamples | None:
    """Common42370: one complete selected DID header block; unknown trigger skips."""
    from scripts.support import word
    from scripts.toyota import INVALID_RECORD, ToyotaCodecError

    if profile.database.version != 0x0100032F:
        raise ValueError("P5 DDR requires the recovered native18 database factory")
    if type(spec_value) is not int or spec_value not in _DDR_P5_BANKS:
        raise ToyotaCodecError("Unsupported P5 DDR specification", 0xA0041001)
    if not isinstance(raw, bytes) or not 2 <= len(raw) <= 512:
        raise ValueError("P5 DDR header exceeds native512-byte storage")
    bank = _DDR_P5_BANKS[spec_value][0]
    if not profile.ddr_records(bank + 1, *raw[:2]):
        return None
    plan = _selected_ddr_plan(profile, spec_value, raw[:2], bank, len(raw))
    values = []
    for sample in plan.samples:
        offset = int.from_bytes(sample.address_record[:4], "little")
        first, last = word(sample.monitor_record, 28), word(sample.monitor_record, 30)
        size = (last >> 3) - (first >> 3) + 1
        if not 1 <= size <= 4 or offset + size > len(raw):
            raise ToyotaCodecError(
                "P5 DDR scalar exceeds selected header", INVALID_RECORD
            )
        source = raw[offset : offset + size]
        values.append((sample.monitor_id, source, ddr_bits(source, first, last)))
    return DdrRecordSamples(raw[:2], plan, tuple(values))


def decode_ddr_p5_detail(
    profile: VehicleProfile,
    record: DdrRecordSamples,
    raw: bytes,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> tuple[DdrTimelineSamples, ...]:
    """Common436D0: case-buffer timelines, including native selector0x22 byte swap."""
    from scripts.support import word
    from scripts.toyota import INVALID_RECORD, MISSING_RECORD, ToyotaCodecError
    from scripts.toyota_session import Cancelled

    plan = record.plan
    if (
        plan.spec_value not in _DDR_P5_BANKS
        or plan.table_slots
        != tuple(
            range(
                _DDR_P5_BANKS[plan.spec_value][0], _DDR_P5_BANKS[plan.spec_value][0] + 4
            )
        )
        or profile.database.version != 0x0100032F
        or profile.database.sha256 != plan.source_sha256
        or profile.category != plan.category
        or profile.exception_ids != plan.exception_ids
        or not isinstance(raw, bytes)
        or not 2 <= len(raw) <= 4096
        or raw[:2] != record.header
    ):
        raise ValueError("P5 DDR detail differs from selected captured header")
    rows = profile.ddr_records(plan.table_slots[2], record.header[0], 2)
    if not rows:
        raise ToyotaCodecError("P5 DDR timeline addresses are absent", MISSING_RECORD)
    count = sum(word(plan.trigger_record, offset) for offset in (16, 18, 20)) & 65535
    if len(rows) * (count + 1) > 100_000:
        raise ValueError("P5 DDR timeline exceeds decoded-node allowance")
    timelines = []
    for row in rows:
        if cancelled and cancelled():
            raise Cancelled("P5 DDR detail decoding cancelled")
        identifier, byte_stride = word(row, 4), word(row, 6)
        offset = int.from_bytes(row[:4], "little")
        monitors = profile.ddr_records(plan.table_slots[0], identifier)
        if not monitors:
            raise ToyotaCodecError("P5 DDR timeline monitor is absent", MISSING_RECORD)
        monitor = monitors[0]
        sample = DdrSamplePlan(
            identifier,
            row,
            monitor,
            plan.source_sha256,
            plan.category,
            plan.exception_ids,
        )
        if not byte_stride:
            stride = word(monitor, 34) - word(monitor, 32) + 1
            if not 1 <= stride <= 32:
                raise ToyotaCodecError(
                    "P5 DDR packed stride is invalid", INVALID_RECORD
                )
            size = max(1, (count * stride + 7) // 8)
            if size > 280 or offset + size > len(raw):
                raise ToyotaCodecError(
                    "P5 DDR packed timeline exceeds storage", INVALID_RECORD
                )
            source = raw[offset : offset + size]
            decoded = ddr_timeline_values(source, count, monitor)
        else:
            first, last = word(monitor, 28), word(monitor, 30)
            size = (last >> 3) - (first >> 3) + 1
            span = (count - 1) * byte_stride + size if count else 0
            if not 1 <= size <= 4 or offset + span > len(raw):
                raise ToyotaCodecError(
                    "P5 DDR strided timeline exceeds storage", INVALID_RECORD
                )
            source = raw[offset : offset + span]
            values = []
            for index in range(count):
                value = source[index * byte_stride : index * byte_stride + size]
                if monitor[44] == 0x22:
                    # Native swaps bytes0/1 in a zero-initialized DWORD before GetMaskData.
                    value = value + bytes(4 - size)
                    value = (value[1:2] + value[:1] + value[2:])[:size]
                values.append(ddr_bits(value, first, last))
            decoded = tuple(values)
        timelines.append(DdrTimelineSamples(sample, source, decoded))
    return tuple(timelines)


def ddr_p5_case_identifiers(
    profile: VehicleProfile,
    spec_value: int,
    header_did: int,
    header_index: int,
    supported: tuple[int, ...],
) -> tuple[int, ...]:
    """Common431B0: first contiguous header-DID group and BYTE8+header-index mapping."""
    from scripts.support import word
    from scripts.toyota import MISSING_RECORD, ToyotaCodecError

    if (
        profile.database.version != 0x0100032F
        or type(spec_value) is not int
        or spec_value not in _DDR_P5_BANKS
        or type(header_did) is not int
        or not 1 <= header_did <= 65535
        or type(header_index) is not int
        or not 0 <= header_index <= 65535
        or not isinstance(supported, tuple)
        or any(type(did) is not int or not 1 <= did <= 65535 for did in supported)
    ):
        raise ValueError("P5 DDR case query requires selected18 uint16 identities")
    rows = []
    for row in profile.records(_DDR_P5_BANKS[spec_value][2]):
        if word(row, 0) == header_did:
            rows.append(row)
        elif rows:
            break
    if not rows:
        raise ToyotaCodecError("P5 DDR case DID resource is absent", MISSING_RECORD)
    identifiers = tuple(
        word(row, 2) for row in rows if row[8] == rows[0][8] + header_index
    )
    return identifiers if all(did in supported for did in identifiers) else ()


def trim_ddr_p5_case_payload(record: DdrRecordSamples, raw: bytes) -> bytes | None:
    """Common433B0: minimum triggerWORD22 and removal of inclusive WORD24..WORD26 gap.

    The returned buffer retains the original length with the removed tail zeroed,
    matching the native zero-initialized4096-byte case allocation's consumed prefix.
    """
    from scripts.support import word

    if (
        record.plan.spec_value not in _DDR_P5_BANKS
        or not isinstance(raw, bytes)
        or len(raw) > 4096
    ):
        raise ValueError("P5 DDR case payload exceeds native storage")
    minimum, start, end = (
        word(record.plan.trigger_record, offset) for offset in (22, 24, 26)
    )
    # The trigger structure adds4 bytes inside _DDR_P5_HEADER_DATA: offsets22/24/26
    # become native fields+0x22/+0x24/+0x26 after the trigger's16-byte list/header.
    if len(raw) < minimum:
        return None
    if start < end:
        if end >= len(raw):
            raise ValueError("P5 DDR removed range exceeds received case data")
        kept = raw[:start] + raw[end + 1 :]
        return kept + bytes(len(raw) - len(kept))
    return raw


@dataclass(frozen=True)
class DdrP5Header:
    did: int
    index: int
    stride: int
    raw: bytes
    record: DdrRecordSamples


@dataclass(frozen=True)
class DdrP5Case:
    header: DdrP5Header
    dids: tuple[int, ...]
    raw: bytes
    decoded_buffer: bytes
    record: DdrRecordSamples
    timelines: tuple[DdrTimelineSamples, ...]
    series: tuple[DdrValueSeries, ...] = ()


@dataclass(frozen=True)
class DdrP5RawCapture:
    """Common41580 acquisition stage before P5 flag transforms and report construction."""

    attributes: DdrAttributeCapture
    headers: tuple[DdrP5Header, ...]
    cases: tuple[DdrP5Case, ...]
    transactions: tuple[DdrDataIdTransaction, ...]


def capture_ddr_p5_raw_records(
    cache: MonitorSupportCache,
    *,
    connections: Mapping[tuple[int, int], NativeCommunication] | None = None,
    ecu_specific: tuple[DdrEcuContext, ...] = (),
) -> DdrP5RawCapture:
    """Actual selected CA transport through41580/417C0/41BA0/42C30/433B0.

    Native header read errors skip the DID, case read errors skip that case;
    cancellation and host storage/context violations remain visible failures.
    """
    from scripts.support import word
    from scripts.toyota import INVALID_RECORD, MISSING_RECORD, ToyotaCodecError
    from scripts.toyota_session import SessionError

    attributes = capture_ddr_p5_attributes(
        cache, connections=connections, ecu_specific=ecu_specific
    )
    observations = dict(attributes.observations)
    profile = _toyota_profile(cache.profile)
    spec = attributes.spec_value
    header_rows = profile.records(_DDR_P5_BANKS[spec][1])
    if not header_rows:
        raise ToyotaCodecError("P5 DDR header DID resources are absent", MISSING_RECORD)
    header_reader = DdrP5DataIdReader(cache)
    transactions, headers, cases, groups = [], [], [], []
    retained = 0

    def retain(size: int) -> None:
        nonlocal retained
        if size > snapshot.MAX_BYTES - retained:
            raise SessionError("P5 DDR acquisition byte allowance exhausted")
        retained += size

    def read(reader: DdrP5DataIdReader, did: int) -> bytes | None:
        before = len(reader.transactions)
        try:
            return reader.read(did)
        finally:
            for transaction in reader.transactions[before:]:
                retain(len(transaction.request) + len(transaction.reply))
                transactions.append(transaction)

    if len(header_rows) > 100_000:
        raise SessionError("P5 DDR header-resource allowance exhausted")
    for resource in header_rows:
        cache.check_context()
        did, stride = word(resource, 0), word(resource, 2)
        if not did or not 2 <= stride <= 512:
            raise ToyotaCodecError(
                "P5 DDR header DID/stride is invalid", INVALID_RECORD
            )
        try:
            payload = read(header_reader, did)
        except ToyotaCodecError:
            continue
        if payload is None or len(payload) < stride:
            continue
        if len(payload) > 512:
            raise ValueError("P5 DDR header response exceeds native512-byte allocation")
        group = []
        for offset in range(0, len(payload) - stride + 1, stride):
            cache.check_context()
            raw_header = payload[offset : offset + stride]
            record = decode_ddr_p5_header(profile, spec, raw_header)
            if record is None or not ddr_bulk_record_eligible(
                attributes.plan, observations, record
            ):
                continue
            retain(len(raw_header))
            header = DdrP5Header(did, offset // stride, stride, raw_header, record)
            headers.append(header)
            group.append(header)
        if group:
            groups.append((did, stride, group))
    for did, stride, group in groups:
        # Native42C30 creates one fresh TEMP per header-DID group, shared by all its cases.
        reader = DdrP5DataIdReader(cache)
        for header in group:
            cache.check_context()
            identifiers = ddr_p5_case_identifiers(
                profile, spec, did, header.index, reader.support.identifiers
            )
            if not identifiers:
                continue
            fragments = []
            size = 0
            for case_did in identifiers:
                try:
                    fragment = read(reader, case_did)
                except ToyotaCodecError:
                    break
                if not fragment:
                    break
                size += len(fragment)
                if size > 4096:
                    # Native's overflow branch subtracts from512 despite4096 allocation;
                    # reject before reproducing its unsigned underflow/out-of-bounds write.
                    raise ValueError(
                        "P5 DDR case response exceeds native4096-byte allocation"
                    )
                fragments.append(fragment)
            else:
                raw_case = b"".join(fragments)
                trimmed = trim_ddr_p5_case_payload(header.record, raw_case)
                if trimmed is None:
                    continue
                buffer = trimmed + bytes(4096 - len(trimmed))
                record = decode_ddr_p5_header(profile, spec, buffer[:stride])
                # Native42C30 breaks the current DID group for unknown/ineligible case headers.
                if record is None or not ddr_bulk_record_eligible(
                    attributes.plan, observations, record
                ):
                    break
                timelines = decode_ddr_p5_detail(
                    profile, record, buffer, cancelled=cache.cancelled
                )
                retain(
                    len(raw_case) + len(buffer) + sum(len(row.raw) for row in timelines)
                )
                if len(cases) >= 100_000:
                    raise SessionError("P5 DDR case-node allowance exhausted")
                cases.append(
                    DdrP5Case(header, identifiers, raw_case, buffer, record, timelines)
                )
    return DdrP5RawCapture(
        attributes, tuple(headers), tuple(cases), tuple(transactions)
    )


def capture_ddr_p5_records(
    cache: MonitorSupportCache,
    *,
    connections: Mapping[tuple[int, int], NativeCommunication] | None = None,
    ecu_specific: tuple[DdrEcuContext, ...] = (),
) -> DdrP5RawCapture:
    """Join source-bound P5 acquisition, native transforms and381D0 record sorting."""
    from scripts.toyota import INVALID_RECORD, ToyotaCodecError

    captured = capture_ddr_p5_raw_records(
        cache, connections=connections, ecu_specific=ecu_specific
    )
    cases = [
        replace(
            row,
            series=transform_ddr_p5_record(
                _toyota_profile(cache.profile),
                row.record,
                row.timelines,
                cancelled=cache.cancelled,
            ),
        )
        for row in captured.cases
    ]

    def compare(left: DdrP5Case, right: DdrP5Case) -> int:
        for identifier in (7, 10):
            values = []
            for row in (left, right):
                found = next(
                    (item for item in row.series if item.identifier == identifier), None
                )
                if found is None or not found.samples:
                    raise ToyotaCodecError(
                        "P5 DDR sort field is absent", INVALID_RECORD
                    )
                values.append(found.samples[0][0])
            difference = (values[0] - values[1]) & 0xFFFFFFFF
            if difference:
                return (
                    difference - 0x100000000 if difference >= 0x80000000 else difference
                )
        return 0

    for first in range(len(cases)):
        cache.check_context()
        for second in range(first + 1, len(cases)):
            if compare(cases[first], cases[second]) > 0:
                cases[first], cases[second] = cases[second], cases[first]
    return replace(captured, cases=tuple(cases))


@dataclass(frozen=True)
class DdrCapturedRecord:
    group_index: int
    record_index: int | None
    address: int
    record: DdrRecordSamples
    timelines: tuple[DdrTimelineSamples, ...]
    series: tuple[DdrValueSeries, ...]


@dataclass(frozen=True)
class DdrFormattedSignal:
    definition: DdrSignalDefinition
    samples: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class DdrTriggerDescription:
    name_id: int
    memo_id: int
    name: str
    memo: str
    flag: int
    resource_record: bytes | None


@dataclass(frozen=True)
class DdrInfo:
    """Native6410/8470 CCmdDdrInfo values; no inferred meaning for raw groups."""

    source_sha256: str
    language_sha256: str
    header_a: tuple[tuple[int, int], ...]
    header_b: tuple[tuple[int, int], ...]
    triggers: tuple[DdrTriggerDescription, ...]
    conversion: tuple[int, int]
    counts: tuple[int, int, int]
    dwords: tuple[tuple[int, int, int], ...]
    bytes: tuple[tuple[int, int, int], ...]
    scalar_signals: tuple[DdrFormattedSignal, ...]
    marker_groups: tuple[tuple[tuple[int, int], ...], ...]
    extra_signal: DdrFormattedSignal
    timeline_main: tuple[DdrFormattedSignal, ...]
    timeline_side: tuple[DdrFormattedSignal, ...]


def format_ddr_info(
    profile: VehicleProfile, captured: DdrCapturedRecord, *, saved_log: bool = False
) -> DdrInfo:
    """Native6030 removes hidden monitors, then6410/8470 construct one DDR info."""
    from scripts.toyota import INVALID_RECORD, MISSING_RECORD, ToyotaCodecError

    plan = captured.record.plan
    if type(saved_log) is not bool:
        raise ValueError("DDR formatter requires an explicit source variant")
    if (
        profile.database.sha256 != plan.source_sha256
        or profile.category != plan.category
        or profile.exception_ids != plan.exception_ids
        or len(captured.series) + sum(len(row.samples) for row in captured.series)
        > 100_000
    ):
        raise ValueError("DDR formatter differs from selected source or exceeds bounds")
    rows = []
    for row in captured.series:
        selected = profile.ddr_records(plan.table_slots[0], row.identifier)
        if not selected:
            raise ToyotaCodecError("DDR formatter monitor is absent", MISSING_RECORD)
        if saved_log or selected[0][43] != 2:
            rows.append(row)
    first = {}
    for row in rows:
        first.setdefault(row.identifier, row)

    def scalar(identifier: int, byte: bool = False) -> tuple[int, int] | None:
        row = first.get(identifier)
        if row is None:
            return None
        if not row.samples:
            raise ToyotaCodecError(
                "DDR formatted scalar sample is absent", INVALID_RECORD
            )
        value, flag = row.samples[0]
        return (value & 255 if byte else value, flag & 255)

    def byte_group(identifiers: tuple[int, ...]) -> tuple[tuple[int, int], ...]:
        return tuple(
            found
            for identifier in identifiers
            if (found := scalar(identifier, True)) is not None
        )

    groups_a = (1, 37, 40, 43, 46, 49, 52, 59, 62, 65, 68, 99, 102, 105, 108)
    groups_b = (2, 38, 41, 44, 47, 50, 53, 60, 63, 66, 69, 100, 103, 106, 109)
    header_a, header_b = byte_group(groups_a), byte_group(groups_b)
    if not header_a or not header_b or len(header_b) < len(header_a):
        raise ToyotaCodecError(
            "DDR formatter paired header lists are incomplete", INVALID_RECORD
        )
    language = profile.catalog.language
    descriptions = []
    for index, (left, flag) in enumerate(header_a):
        if flag:
            descriptions.append(DdrTriggerDescription(0, 0, "", "", flag, None))
            continue
        selected = profile.ddr_records(plan.table_slots[1], left, header_b[index][0])
        if not selected:
            raise ToyotaCodecError("DDR formatted trigger is absent", MISSING_RECORD)
        trigger = selected[0]
        name_id, memo_id = (
            int.from_bytes(trigger[offset : offset + 4], "little") for offset in (8, 12)
        )
        descriptions.append(
            DdrTriggerDescription(
                name_id,
                memo_id,
                language.resolve(name_id),
                language.resolve(memo_id),
                0,
                trigger,
            )
        )
    selected = profile.ddr_records(plan.table_slots[1], header_a[0][0], header_b[0][0])
    if not selected:
        raise ToyotaCodecError(
            "DDR formatter primary trigger is absent", MISSING_RECORD
        )
    trigger = selected[0]
    conversion = tuple(
        int.from_bytes(trigger[offset : offset + 4], "little") for offset in (0, 4)
    )
    before, after, main_count = trigger[16], trigger[18], len(header_a) & 255
    definitions = {}

    def definition(identifier: int) -> DdrSignalDefinition:
        if identifier not in definitions:
            definitions[identifier] = selected_ddr_signal_definition(
                profile, plan, identifier
            )
        return definitions[identifier]

    scalar_signals = tuple(
        DdrFormattedSignal(definition(identifier), (sample,))
        for identifier in (7, 10, 9, 13)
        if (sample := scalar(identifier)) is not None
    )
    extra_ids = (3, 39, 42, 45, 48, 51, 54, 61, 64, 67, 70, 101, 104, 107, 110)
    extra = DdrFormattedSignal(
        definition(3),
        tuple(
            sample
            for identifier in extra_ids
            if (sample := scalar(identifier)) is not None
        ),
    )
    main, side = [], []
    for row in rows:
        if row.kind != 2:
            continue
        start = (before + after + 1) & 255
        indices = (0,) + tuple(range(start, start + main_count - 1))
        side_indices = tuple(range(1, before + after + 1))
        if any(
            index >= len(row.samples) or index > 255 for index in indices + side_indices
        ):
            raise ToyotaCodecError(
                "DDR formatter timeline slice exceeds native sample storage",
                INVALID_RECORD,
            )
        metadata = definition(row.identifier)
        main.append(
            DdrFormattedSignal(
                metadata,
                tuple(
                    (row.samples[index][0], row.samples[index][1] & 255)
                    for index in indices
                ),
            )
        )
        side.append(
            DdrFormattedSignal(
                metadata,
                tuple(
                    (row.samples[index][0], row.samples[index][1] & 255)
                    for index in side_indices
                ),
            )
        )
    dwords = tuple(
        (identifier, sample[0], sample[1])
        for identifier in (4, 5, 6, 9)
        if (sample := scalar(identifier)) is not None
    )
    byte_values = tuple(
        (identifier, sample[0], sample[1])
        for identifier in (
            (14, 15, 16, 117, 111, 112, 113, 114, 115, 116)
            if plan.spec_value in _DDR_P5_BANKS
            else (14, 15, 16)
        )
        if (sample := scalar(identifier, True)) is not None
    )
    return DdrInfo(
        plan.source_sha256,
        language.sha256,
        header_a,
        header_b,
        tuple(descriptions),
        (conversion[0], conversion[1]),
        (before, after, main_count),
        dwords,
        byte_values,
        scalar_signals,
        (
            byte_group(
                (17, 18)
                + tuple(range(31, 37))
                + tuple(range(55, 59))
                + tuple(range(95, 99))
            ),
            byte_group((19,)),
            byte_group(tuple(range(20, 31)) + tuple(range(71, 95))),
        ),
        extra,
        tuple(main),
        tuple(side),
    )


@dataclass(frozen=True)
class DdrCapture:
    attributes: DdrAttributeCapture
    records: tuple[DdrCapturedRecord, ...]
    transactions: tuple[RamTransaction, ...]


@dataclass(frozen=True)
class DdrMonitorCatalogEntry:
    identifier: int
    name: str
    unit: str
    unit_code: int
    monitor_record: bytes
    physical_record: bytes
    unit_record: bytes


@dataclass(frozen=True)
class DdrReport:
    capture: DdrCapture
    information: tuple[DdrInfo, ...]
    logical103: int | None
    specification: int | None
    attributes: tuple[tuple[int, bool, int], ...]
    monitor_catalog: tuple[DdrMonitorCatalogEntry, ...]


@dataclass(frozen=True)
class DdrP5SupportValue:
    logical_id: int
    present: bool
    value: int


@dataclass(frozen=True)
class DdrP5Report:
    capture: DdrP5RawCapture
    information: tuple[DdrInfo, ...]
    logical103: int | None
    specification: int | None
    csv_110: DdrP5SupportValue
    csv_128: DdrP5SupportValue
    monitor_catalog: tuple[DdrMonitorCatalogEntry, ...]


class DdrPartialReportError(ToyotaCodecError):
    """Native final catalog failure after receiver information/support writes."""

    def __init__(self, failure: ToyotaCodecError, report: DdrReport | DdrP5Report):
        super().__init__(str(failure), failure.code)
        self.partial_report = report


def _complete_ddr_report_catalog(
    profile: VehicleProfile, report: DdrReport | DdrP5Report, table_slot: int
) -> DdrReport | DdrP5Report:
    # Native6030/61E0/3C7C0 populate support before the final catalog call.
    try:
        catalog = _ddr_monitor_catalog(profile, table_slot)
    except ToyotaCodecError as failure:
        raise DdrPartialReportError(failure, report) from failure
    return replace(report, monitor_catalog=catalog)


def ddr_report_support_values(
    report: DdrReport | DdrP5Report,
) -> tuple[DdrP5SupportValue, DdrP5SupportValue]:
    """Native receiver+170/+188: normal170/171 or P5 CSV110/128 support values.

    Empty successful reports retain constructor defaults. A final catalog
    failure exposes these same writes through DdrPartialReportError.
    """
    if isinstance(report, DdrP5Report):
        result = report.csv_110, report.csv_128
    elif isinstance(report, DdrReport):
        if report.attributes and (
            len(report.attributes) != 13
            or tuple(row[0] for row in report.attributes) != tuple(range(159, 172))
        ):
            raise ValueError("Normal DDR support slots differ from native receiver")
        values = {
            identifier: (present, value)
            for identifier, present, value in report.attributes
        }
        result = tuple(
            DdrP5SupportValue(identifier, *values.get(identifier, (False, 0)))
            for identifier in (170, 171)
        )
    else:
        raise TypeError("Native DDR support requires an acquired typed report")
    if any(
        type(item.present) is not bool
        or type(item.value) is not int
        or not 0 <= item.value <= 0xFFFFFFFF
        for item in result
    ):
        raise ValueError("Native DDR support presence/value is malformed")
    return result[0], result[1]


def format_ddr_p5_capture(
    profile: VehicleProfile, capture: DdrP5RawCapture
) -> DdrP5Report:
    """Common3C7C0/410E0: P5 command report and exact CSV support fallback/masks."""
    from scripts.toyota import INVALID_RECORD, ToyotaCodecError

    plan = capture.attributes.plan
    spec = capture.attributes.spec_value
    if (
        not plan.p5
        or spec not in _DDR_P5_BANKS
        or plan.vehicle_sha256 != profile.database.sha256
        or plan.management_sha256 != profile.catalog.management.sha256
        or plan.category != profile.category
        or plan.exception_ids != profile.exception_ids
    ):
        raise ValueError("P5 DDR report differs from selected18 attribute sources")
    values = dict(capture.attributes.observations)

    def observed(identifier: int) -> int:
        value = values.get(identifier)
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ToyotaCodecError("P5 DDR report attribute is absent", INVALID_RECORD)
        return value

    slots = {slot.logical_id: slot for slot in plan.slots}

    def support(identifier: int) -> DdrP5SupportValue:
        slot = slots.get(identifier)
        present = (
            slot is not None
            and bool(slot.candidates)
            and slot.enabled
            and slot.supported
        )
        value = observed(identifier) if present else 0
        if identifier in (171, 177):
            value &= 0x1FFFFFFF
        return DdrP5SupportValue(identifier, present, value)

    information = []
    for row in capture.cases:
        if row.record.plan.spec_value != spec:
            raise ValueError(
                "P5 DDR case specification differs from observed attributes"
            )
        captured = DdrCapturedRecord(
            0, row.header.index, 0, row.record, row.timelines, row.series
        )
        information.append(format_ddr_info(profile, captured))
    first, second = support(170), support(177)
    if not second.present:
        second = support(171)
    if observed(118) != spec:
        raise ValueError("P5 DDR report specification observation changed")
    report = DdrP5Report(
        capture,
        tuple(information),
        observed(103),
        spec,
        first,
        second,
        (),
    )
    completed = _complete_ddr_report_catalog(profile, report, _DDR_P5_BANKS[spec][0])
    assert isinstance(completed, DdrP5Report)
    return completed


def capture_ddr_p5_report(
    cache: MonitorSupportCache,
    *,
    connections: Mapping[tuple[int, int], NativeCommunication] | None = None,
    ecu_specific: tuple[DdrEcuContext, ...] = (),
) -> DdrP5Report:
    """P5 selected native18 preparation, acquisition, transforms and command report."""
    captured = capture_ddr_p5_records(
        cache, connections=connections, ecu_specific=ecu_specific
    )
    cache.check_context()
    if not captured.cases:
        return _empty_ddr_p5_report(captured)
    return format_ddr_p5_capture(_toyota_profile(cache.profile), captured)


def _empty_ddr_p5_report(captured: DdrP5RawCapture) -> DdrP5Report:
    # Native P5 Execute bypasses3C7C0 for an empty acquired case list.
    return DdrP5Report(
        captured,
        (),
        None,
        None,
        DdrP5SupportValue(170, False, 0),
        DdrP5SupportValue(171, False, 0),
        (),
    )


def format_ddr_capture(
    profile: VehicleProfile, capture: DdrCapture, *, saved_log: bool = False
) -> DdrReport:
    """Native normal6030/B680/9080 full selected capture-to-command report."""
    from scripts.toyota import INVALID_RECORD, ToyotaCodecError

    attributes = capture.attributes
    if type(saved_log) is not bool:
        raise ValueError("DDR report requires an explicit source variant")
    if (
        attributes.plan.vehicle_sha256 != profile.database.sha256
        or attributes.plan.management_sha256 != profile.catalog.management.sha256
        or attributes.plan.category != profile.category
        or attributes.plan.exception_ids != profile.exception_ids
    ):
        raise ValueError("DDR report capture differs from selected source")
    # Native Execute does not invoke6030 when acquisition returns an empty list.
    if not capture.records:
        return DdrReport(capture, (), None, None, (), ())
    information = tuple(
        format_ddr_info(profile, record, saved_log=saved_log)
        for record in capture.records
    )
    values = dict(attributes.observations)

    def observed(identifier: int) -> int:
        value = values.get(identifier)
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ToyotaCodecError(
                "DDR report attribute observation is absent", INVALID_RECORD
            )
        return value

    slots = {slot.logical_id: slot for slot in attributes.plan.slots}
    extra = []
    for identifier in range(159, 172):
        slot = slots.get(identifier)
        present = (
            slot is not None
            and bool(slot.candidates)
            and slot.enabled
            and slot.supported
        )
        value = observed(identifier) if present else 0
        if identifier in (163, 166, 169, 171):
            value &= 0x1FFFFFFF
        extra.append((identifier, present, value))
    report = DdrReport(
        capture,
        information,
        observed(103),
        observed(118),
        tuple(extra),
        (),
    )
    completed = _complete_ddr_report_catalog(
        profile, report, capture.records[0].record.plan.table_slots[0]
    )
    assert isinstance(completed, DdrReport)
    return completed


def _ddr_saved_signal(signal: DdrFormattedSignal | None, encoding: str) -> tuple:
    """CommandAPI06AD0→GUI40A2A0→GFC signal(flavor7,fullFalse)."""
    zero_descriptor = (0, 0, 0, 0, 0, 0, (), 0, 0, 0, 0)
    if signal is None:
        return (0, b"", b"", b"", 0, 0, zero_descriptor, ())
    definition = signal.definition
    descriptor = (
        *definition.coefficients,
        definition.unit_code,
        definition.sign_mode,
        definition.bit_width,
        tuple(
            (identifier, label.encode(encoding), value, 0, 0)
            for identifier, label, value in definition.patterns
        ),
        *definition.limits,
        *definition.conversion,
    )
    from scripts.signal_display import render_signal

    def stored_text(value: int) -> bytes:
        # ConvertData's %c branch writes a narrow byte, not a Unicode scalar.
        if definition.selector in (4, 32):
            return bytes((value & 255,)) if value & 255 else b""
        rendered = render_signal(
            value & 0xFFFFFFFF,
            selector=definition.selector,
            sign_mode=definition.sign_mode,
            bits=((definition.bit_width - 1) & 31) + 1,
            multiplier=definition.coefficients[0],
            divisor=definition.coefficients[1],
            offset=definition.coefficients[2],
            precision=definition.exponent,
            patterns=tuple((raw, label, 0, 0) for _, label, raw in definition.patterns),
            minimum_raw=definition.limits[0],
            maximum_raw=definition.limits[1],
            raw_words=(value & 0xFFFFFFFF, value >> 32),
        )
        display = rendered["display"]
        if not isinstance(display, str):
            raise TypeError("Native DDR sample display is unresolved")
        return display.encode(encoding)

    # CommandAPI06AD0/06D80 call05F70 before copying the stored CString.
    # Native sample type remains0; invalid flags occupy separate validity lists.
    return (
        definition.identifier,
        definition.name.encode(encoding),
        b"",
        definition.unit.encode(encoding),
        definition.selector,
        definition.exponent,
        descriptor,
        tuple((value, stored_text(value), 0) for value, _ in signal.samples),
    )


def ddr_saved_information(
    info: DdrInfo, *, version: int, encoding: str
) -> tuple[tuple, tuple]:
    """Exact normal/P5 command info→CommandAPI→GUI→b1340/b1760 native wire pair.

    Caller supplies the native text encoding. CommandAPI sample formatting and
    the separate validity arrays are retained.
    """
    from scripts.signal_conversion import affine

    if type(version) is not int or not 0x1000 <= version <= 0x1027:
        raise ValueError("DDR saved information version is unsupported")
    if not isinstance(encoding, str):
        raise TypeError("DDR saved text encoding must be explicit")
    "".encode(encoding)
    scalars = {row.definition.identifier: row for row in info.scalar_signals}
    dwords = {identifier: (value, flag) for identifier, value, flag in info.dwords}
    byte_values = {identifier: (value, flag) for identifier, value, flag in info.bytes}

    def signal(identifier: int) -> tuple:
        return _ddr_saved_signal(scalars.get(identifier), encoding)

    def flag(identifier: int) -> int:
        row = scalars.get(identifier)
        return row.samples[0][1] if row is not None and row.samples else 0

    def converted(identifier: int) -> int:
        row = scalars.get(identifier)
        if row is None or not row.samples:
            return 0
        definition = row.definition
        return (
            affine(
                row.samples[0][0],
                *definition.coefficients,
                definition.bit_width,
                definition.sign_mode,
            )
            & 0xFFFFFFFF
        )

    def unpack(values: tuple[tuple[int, int], ...]) -> tuple[int, ...]:
        return tuple(value for value, _ in values)

    def flags(values: tuple[tuple[int, int], ...]) -> tuple[int, ...]:
        return tuple(flag for _, flag in values)

    descriptor = (*info.conversion, 0, 0, 0, 0, (), 0, 0, 0, 0)
    # GUI50 stays at its constructor default: memo IDs/text live in344/358.
    main = (
        unpack(info.header_a),
        unpack(info.header_b),
        tuple(item.name_id for item in info.triggers),
        tuple(item.name.encode(encoding) for item in info.triggers),
        (),
        descriptor,
        info.counts[0],
        info.counts[1],
        *(dwords.get(identifier, (0, 0))[0] for identifier in (4, 5, 6)),
        converted(7),
        signal(7),
        converted(10),
        signal(10),
        signal(9),
        dwords.get(9, (0, 0))[0],
        signal(13),
        *(byte_values.get(identifier, (0, 0))[0] for identifier in (14, 15, 16)),
        *(unpack(group) for group in info.marker_groups),
        _ddr_saved_signal(info.extra_signal, encoding),
        tuple(_ddr_saved_signal(row, encoding) for row in info.timeline_side),
        tuple(_ddr_saved_signal(row, encoding) for row in info.timeline_main),
    )
    trigger_flags = tuple(item.flag for item in info.triggers)
    validity = (
        flags(info.header_a),
        flags(info.header_b),
        trigger_flags,
        trigger_flags,
        0,
        0,
        0,
        *(dwords.get(identifier, (0, 0))[1] for identifier in (4, 5, 6)),
        flag(7),
        flag(10),
        flag(9),
        dwords.get(9, (0, 0))[1],
        flag(13),
        *(byte_values.get(identifier, (0, 0))[1] for identifier in (14, 15, 16)),
        *(flags(group) for group in info.marker_groups),
        flags(info.extra_signal.samples),
        tuple(flags(row.samples) for row in info.timeline_side),
        tuple(flags(row.samples) for row in info.timeline_main),
    )
    if version > 0x1002:
        main += (
            tuple(item.memo_id for item in info.triggers),
            tuple(item.memo.encode(encoding) for item in info.triggers),
        )
        validity += (trigger_flags, trigger_flags)
    if version >= 0x1007:
        main += tuple(
            byte_values.get(identifier, (0, 0))[0]
            for identifier in (117, 111, 112, 113, 114, 115, 116)
        )
        validity += tuple(
            byte_values.get(identifier, (0, 0))[1]
            for identifier in (117, 111, 112, 113, 114, 115, 116)
        )
    # Native row2 width changes fromWORD toDWORD at1002; fail rather than truncate.
    codec = tse_reports._Codec()
    codec.node(tse_reports._layout("b1340", version), main)
    codec.node(tse_reports._layout("b1760", version), validity)
    return main, validity


def bind_ddr_report(
    section: tse_reports.ReportSection,
    report: DdrReport | DdrP5Report,
    *,
    encoding: str,
    record_index: int = 0,
) -> tse_reports.ReportSection:
    """Bind full normal acquired info/validity plus header in caller's DDRData context."""
    section = bind_ddr_report_header(section, report, record_index=record_index)
    acquired = (
        report.capture.records
        if isinstance(report, DdrReport)
        else report.capture.cases
    )
    if len(report.information) != len(acquired):
        raise ValueError("DDR saved information differs from acquired record count")
    index = 1 + 2 * (section.version > 0x1004) + 4 * (section.version >= 0x1009)
    row = list(section.records[record_index])
    row[index] = tuple(
        ddr_saved_information(info, version=section.version, encoding=encoding)
        for info in report.information
    )
    # Native9080→CommandAPI→GUI49F2D0 catalog: only ID/name/unit/unitcode
    # are populated; every other numeric and short-name field is ctor-default0.
    row[index + 1] = tuple(
        (
            item.identifier,
            item.name.encode(encoding),
            b"",
            item.unit.encode(encoding),
            0,
            0,
            0,
            0,
            0,
            0,
            item.unit_code,
            0,
            0,
            0,
            0,
        )
        for item in report.monitor_catalog
    )
    records = list(section.records)
    records[record_index] = tuple(row)
    result = replace(section, records=tuple(records))
    tse_reports.encode_section(result)
    return result


def ads_ddr_saved_information(
    info: AdsDdrInfo, *, version: int, encoding: str
) -> tuple[tuple, tuple]:
    """ADS CommandAPI1B1A0/1BFF0→GUI→GFC b2190/b2560, including85E10 uint64 samples."""
    from scripts.signal_conversion import affine

    if type(version) is not int or not 0x1009 <= version <= 0x1027:
        raise ValueError("ADS saved information requires native version1009..1027")
    if not isinstance(encoding, str):
        raise TypeError("ADS saved text encoding must be explicit")
    "".encode(encoding)
    scalars = {row.definition.identifier: row for row in info.scalars}
    byte_values = {identifier: (value, flag) for identifier, value, flag in info.bytes}

    def signal(identifier: int) -> tuple:
        return _ddr_saved_signal(scalars.get(identifier), encoding)

    def flags(identifier: int) -> tuple[int, ...]:
        row = scalars.get(identifier)
        return tuple(flag for _, flag in row.samples) if row is not None else ()

    def flag(identifier: int) -> int:
        observed = flags(identifier)
        return observed[0] if observed else 0

    def converted(identifier: int) -> int:
        row = scalars.get(identifier)
        if row is None or not row.samples:
            return 0
        definition = row.definition
        # A7D10 GetValue iterates all type0 values and retains the LAST result.
        # Its32-bit helper masks x86 shift counts even for an ADS64-bit field.
        bits = ((definition.bit_width - 1) & 31) + 1
        return (
            affine(
                row.samples[-1][0], *definition.coefficients, bits, definition.sign_mode
            )
            & 0xFFFFFFFF
        )

    def values(group: tuple[tuple[int, int], ...]) -> tuple[int, ...]:
        return tuple(value for value, _ in group)

    def validity(group: tuple[tuple[int, int], ...]) -> tuple[int, ...]:
        return tuple(flag for _, flag in group)

    before, after, main_count = info.counts
    if before < 0 or after < 0 or main_count < 1 or len(info.markers) != 3:
        raise ValueError("ADS saved information requires transformed counts/markers")
    marker_groups = (info.markers[2], info.markers[0], info.markers[1])
    main = (
        values(info.header_a),
        values(info.header_b),
        tuple(item.name_id for item in info.triggers),
        tuple(item.name.encode(encoding) for item in info.triggers),
        (),
        (*info.conversion, 0, 0, 0, 0, (), 0, 0, 0, 0),
        before,
        after,
        converted(1),
        signal(1),
        converted(13),
        signal(13),
        signal(12),
        info.mode[0] if info.mode is not None else 0,
        signal(5),
        byte_values.get(4, (0, 0))[0],
        *(values(group) for group in marker_groups),
    )
    trigger_flags = tuple(item.flag for item in info.triggers)
    checked = (
        validity(info.header_a),
        validity(info.header_b),
        trigger_flags,
        trigger_flags,
        0,
        0,
        0,
        flag(1),
    )
    if version < 0x100A:
        main += (_ddr_saved_signal(None, encoding),)
        checked += (
            0,
        )  # API common+57 remains default; newer format usesfull13flaglist.
    else:
        checked += (flags(13),)
    main += (
        tuple(_ddr_saved_signal(row, encoding) for row in info.side_signals),
        tuple(_ddr_saved_signal(row, encoding) for row in info.main_signals),
        tuple(item.memo_id for item in info.triggers),
        tuple(item.memo.encode(encoding) for item in info.triggers),
        *(byte_values.get(identifier, (0, 0))[0] for identifier in range(6, 12)),
        *(signal(identifier) for identifier in (14, 15, 16)),
    )
    checked += (
        flag(12),
        info.mode[1] if info.mode is not None else 0,
        flag(5),
        byte_values.get(4, (0, 0))[1],
        *(validity(group) for group in marker_groups),
    )
    if version < 0x100A:
        checked += (
            (),
        )  # unused normal extra-signal flags before the100A format change.
    checked += (
        tuple(validity(row.samples) for row in info.side_signals),
        tuple(validity(row.samples) for row in info.main_signals),
        trigger_flags,
        trigger_flags,
        *(byte_values.get(identifier, (0, 0))[1] for identifier in range(6, 12)),
        *(flag(identifier) for identifier in (14, 15, 16)),
    )
    codec = tse_reports._Codec()
    codec.node(tse_reports._layout("b2190", version), main)
    codec.node(tse_reports._layout("b2560", version), checked)
    return main, checked


def bind_ads_ddr_report(
    section: tse_reports.ReportSection,
    report: AdsDdrReport,
    *,
    encoding: str,
    record_index: int = 0,
) -> tse_reports.ReportSection:
    """Actual ADS info/flags/catalog→late native DDRData list, preserving caller context."""
    if (
        section.family != "DDRData"
        or not 0x1009 <= section.version <= 0x1027
        or type(record_index) is not int
        or not 0 <= record_index < len(section.records)
        or len(report.information) != len(report.records)
    ):
        raise ValueError(
            "ADS saved report requires an existing supported DDRData record"
        )
    tse_reports.encode_section(section)
    row = list(section.records[record_index])
    # GFCafae0 late-list group: b2190/b2560;DWORD280;catalog284.
    index = 7 + 2 * (section.version > 0x1004) + 4 * (section.version >= 0x1009) + 7
    row[index] = tuple(
        ads_ddr_saved_information(info, version=section.version, encoding=encoding)
        for info in report.information
    )
    row[index + 1] = 0  # ADS Execute1D80 passes0 to1050, copiedtoCmdRcv+3c on success.
    row[index + 2] = tuple(
        (
            item.identifier,
            item.name.encode(encoding),
            b"",
            item.unit.encode(encoding),
            0,
            0,
            0,
            0,
            0,
            0,
            item.unit_code,
            0,
            0,
            0,
            0,
        )
        for item in report.monitor_catalog
    )
    records = list(section.records)
    records[record_index] = tuple(row)
    result = replace(section, records=tuple(records))
    tse_reports.encode_section(result)
    return result


def bind_ddr_report_header(
    section: tse_reports.ReportSection,
    report: DdrReport | DdrP5Report,
    *,
    record_index: int = 0,
) -> tse_reports.ReportSection:
    """Normal nativeCmdRcv+60→API+34→GUI+bc→GFC+98 support/value header bridge.

    Fill the source-proven fields in an existing complete DDRData record. Other
    fields retain their original native values; this is not a whole-record factory.
    """
    if isinstance(report, DdrReport):
        attributes = report.attributes
    elif isinstance(report, DdrP5Report):
        # Common410E0 addresses are relative to the CSV subobject, not Rcv.
        # Its170 slot is+110 and final171 slot+128 receives177-fallback171.
        attributes = tuple(
            (
                identifier,
                report.csv_110.present
                if identifier == 170
                else report.csv_128.present
                if identifier == 171
                else False,
                report.csv_110.value
                if identifier == 170
                else report.csv_128.value
                if identifier == 171
                else 0,
            )
            for identifier in range(159, 172)
        )
    else:
        raise TypeError("DDR saved header requires a normal or P5 command report")
    if (
        section.family != "DDRData"
        or not 0x1003 < section.version <= 0x1027
        or type(record_index) is not int
        or not 0 <= record_index < len(section.records)
        or report.logical103 is None
        or report.specification is None
        or len(attributes) != 13
    ):
        raise ValueError(
            "DDR saved header requires an existing supported record and acquired normal report"
        )
    tse_reports.encode_section(section)
    values = []
    for index, (identifier, present, value) in enumerate(attributes):
        if (
            identifier != 159 + index
            or type(present) is not bool
            or type(value) is not int
            or not 0 <= value <= 0xFFFFFFFF
        ):
            raise ValueError(
                "DDR report header differs from native13 support/value slots"
            )
        values.extend((int(present), value))
    if any(
        type(value) is not int or not 0 <= value <= 0xFFFFFFFF
        for value in (report.logical103, report.specification)
    ):
        raise ValueError("DDR saved count/specification requires uint32 observations")
    index = 7 + 2 * (section.version > 0x1004) + 4 * (section.version >= 0x1009)
    row = list(section.records[record_index])
    row[index - 4], row[index - 1], row[index] = (
        report.logical103,
        report.specification,
        tuple(values),
    )
    records = list(section.records)
    records[record_index] = tuple(row)
    result = replace(section, records=tuple(records))
    tse_reports.encode_section(result)
    return result


def _ddr_monitor_catalog(
    profile: VehicleProfile, bank: int
) -> tuple[DdrMonitorCatalogEntry, ...]:
    from scripts.support import word

    excluded = {word(row, 4) for row in profile.records(bank + 2) if row[11] == 1}
    physical = {}
    for row in profile.records(13):
        physical.setdefault(word(row, 12), row)
    units = {}
    for row in profile.records(15):
        units.setdefault(word(row, 4), row)
    catalog = []
    for monitor in profile.records(bank):
        identifier = word(monitor, 24)
        if identifier in excluded:
            continue
        selected = profile.ddr_records(bank, identifier)
        if not selected or selected[0][43] == 2:
            continue
        monitor = selected[0]
        phy = physical.get(word(monitor, 26))
        if phy is None:
            continue
        unit = units.get(word(phy, 14))
        if unit is None:
            continue
        language = profile.catalog.language
        catalog.append(
            DdrMonitorCatalogEntry(
                identifier,
                language.resolve(int.from_bytes(monitor[20:24], "little")),
                language.resolve(int.from_bytes(unit[:4], "little")),
                word(unit, 6),
                monitor,
                phy,
                unit,
            )
        )
        if len(catalog) > 100_000:
            raise ValueError("DDR monitor catalog exceeds node allowance")
    return tuple(catalog)


def capture_ddr_report(
    communication: NativeCommunication,
    *,
    connections: Mapping[tuple[int, int], NativeCommunication] | None = None,
    ecu_specific: tuple[DdrEcuContext, ...] = (),
) -> DdrReport:
    """Native normal record acquisition followed by complete command report construction."""
    capture = capture_ddr_records(
        communication, connections=connections, ecu_specific=ecu_specific
    )
    communication.cache.check_context()
    return format_ddr_capture(_toyota_profile(communication.profile), capture)


def capture_ddr_records(
    communication: NativeCommunication,
    *,
    connections: Mapping[tuple[int, int], NativeCommunication] | None = None,
    ecu_specific: tuple[DdrEcuContext, ...] = (),
    saved_log: bool = False,
) -> DdrCapture:
    """Native1810/2FE0/9D90 acquisition and flags, before CCmdDdrInfo formatting."""
    from scripts.toyota import INVALID_RECORD, ToyotaCodecError
    from scripts.toyota_session import SessionError

    cache = communication.cache
    attributes = capture_ddr_attributes(
        cache, connections=connections, ecu_specific=ecu_specific, saved_log=saved_log
    )
    observations = dict(attributes.observations)
    base_ids = (104, 106, 108, 110, 112, 114, 116, 138, 140, 155, 157)
    count_ids = (105, 107, 109, 111, 113, 115, 117, 139, 141, 156, 158)

    def observed(identifier: int) -> int:
        value = observations.get(identifier)
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ToyotaCodecError(
                "DDR capture requires observed selected attribute", INVALID_RECORD
            )
        return value

    records = []
    chronology: list[RamTransaction] = []
    retained: dict[int, int] = {}
    retained_bytes = 0

    def retain(instance: NativeRamReader) -> None:
        nonlocal retained_bytes
        fresh = instance.transactions[retained.get(id(instance), 0) :]
        added = sum(len(item.query.request) + len(item.reply) for item in fresh)
        if added > snapshot.MAX_BYTES - retained_bytes:
            raise SessionError("DDR aggregate recording byte allowance exhausted")
        chronology.extend(fresh)
        retained_bytes += added
        retained[id(instance)] = len(instance.transactions)

    def reader(frame: bytes, size: int) -> NativeRamReader:
        instance = NativeRamReader.from_communication(
            communication, frame=RamFrame(frame), block_size=size
        )
        return instance

    def append(
        group: int,
        index: int | None,
        address: int,
        record: DdrRecordSamples,
        timelines: tuple[DdrTimelineSamples, ...],
    ) -> None:
        cache.check_context()
        if len(records) >= 100_000:
            raise SessionError("DDR captured record allowance exhausted")
        series = transform_ddr_record(
            _toyota_profile(communication.profile),
            record,
            timelines,
            cancelled=communication.cancelled,
        )
        records.append(
            DdrCapturedRecord(group, index, address, record, timelines, series)
        )

    if attributes.spec_value in (2, 3, 5):
        normal = reader(bytes.fromhex("0100040000000000"), 56)
        for group in range(attributes.group_count):
            base = observed(base_ids[group])
            count = observed(count_ids[group]) & 255
            for index in range(count):
                cache.check_context()
                record = capture_ddr_record_samples(
                    normal,
                    spec_value=attributes.spec_value,
                    base_address=base,
                    record_index=index,
                )
                retain(normal)
                if record is None:
                    continue
                timelines = capture_ddr_timeline_samples(
                    normal, record, base_address=base, record_index=index
                )
                retain(normal)
                if timelines is not None:
                    append(group, index, base + (index << 16), record, timelines)
    else:
        header_reader = reader(bytes.fromhex("0100020000000000"), 24)
        payload_reader = reader(bytes.fromhex("0100020000000000"), 56)
        starts = sorted(
            (observed(base_ids[group]), group)
            for group in range(attributes.group_count)
            if observed(base_ids[group]) < 0x1FFFF
        )
        for position, (base, group) in enumerate(starts):
            # Native last range includes address1FFFF; earlier ranges end before the next base.
            stop = (
                starts[position + 1][0] - 1 if position + 1 < len(starts) else 0x1FFFF
            )
            span = (stop - base + 1) & 0xFFFFFFFF
            blocks = (span >> 11) + int((span & 0x7FF) >= 24)
            if blocks > 64:
                raise SessionError("DDR bulk source range exceeds native128KiB storage")
            for block in range(blocks):
                address = base + block * 0x800
                boundary = base + (block + 1) * 0x800
                while True:
                    cache.check_context()
                    header = capture_ddr_bulk_record_samples(
                        header_reader, spec_value=attributes.spec_value, address=address
                    )
                    retain(header_reader)
                    if header is None:
                        break
                    following = address + header.record_length
                    if following > boundary:
                        break
                    if ddr_bulk_record_eligible(
                        attributes.plan, observations, header.record
                    ):
                        payload = capture_ddr_bulk_payload(payload_reader, header)
                        retain(payload_reader)
                        if payload is not None:
                            append(
                                group, None, address, payload.record, payload.timelines
                            )
                    address = following

    def compare(left: DdrCapturedRecord, right: DdrCapturedRecord) -> int:
        def value(record: DdrCapturedRecord, identifier: int) -> int:
            for row in record.series:
                if row.identifier == identifier and row.samples:
                    return row.samples[0][0]
            raise ToyotaCodecError(
                "DDR sort requires native scalar IDs7/10", INVALID_RECORD
            )

        first, second = value(left, 7), value(right, 7)
        difference = (
            value(left, 10) - value(right, 10) if first == second else first - second
        ) & 0xFFFFFFFF
        return difference if difference < 0x80000000 else difference - 0x100000000

    # NativeB930 comparator feeds the literal nested pair-swap loop. Python's
    # stable sort differs for equal keys moved across a smaller record and for
    # signed-subtraction wrap, where the comparison is not transitive.
    for first in range(len(records)):
        cache.check_context()
        for second in range(first + 1, len(records)):
            if compare(records[first], records[second]) > 0:
                records[first], records[second] = records[second], records[first]
    # Shared communication.cache retains the one aggregate budget across all readers.
    return DdrCapture(
        attributes,
        tuple(records),
        tuple(chronology),
    )


class DdrPacketLog:
    """KGP171b0/17220 kind2 file owner, bound to the concrete packet logger.

    The output root is explicit; native Windows common-documents lookup is not
    replaced by a guessed Linux directory. Constructing this class performs no I/O.
    """

    def __init__(
        self,
        common_documents: Path,
        operations: NativeFrameOperations | NativeFrameController,
        *,
        max_bytes: int = 32 * 1024 * 1024,
    ):
        if type(max_bytes) is not int or not 1 <= max_bytes <= 32 * 1024 * 1024:
            raise ValueError("DDR packet-log byte allowance is invalid")
        if operations.native_build not in (12, 18):
            raise ValueError(
                "DDR packet-file lifecycle requires recovered native build12/18"
            )
        self.source_build = operations.native_build
        self.max_bytes, self.written = max_bytes, 0
        self.directory = Path(common_documents) / "Techstream" / "EcuData"
        self.path = self.directory / "DDR.log"
        self.kind: int | None = None
        self.operations = operations
        self._file: BinaryIO | None = None
        self._failed = False
        self.active = False

    def _failure(self) -> None:
        self._failed = True

    def _write(self, data: bytes) -> int:
        if self._file is None:
            raise OSError("DDR packet log is closed")
        if len(data) > self.max_bytes - self.written:
            raise OSError("DDR packet-log host byte allowance exhausted")
        written = self._file.write(data)
        if written is None:
            raise OSError("DDR packet-log write made no progress")
        self.written += written
        return written

    def start(self, kind: int = 2) -> int:
        """Native171B0/17250/17930: exact mode filename and same-kind handle reuse."""
        if type(kind) is not int or not 0 <= kind <= 65535:
            raise ValueError("Native communication-log kind must fit uint16")
        if self._file is not None:
            if self.kind != kind:
                return 0x90020706
            self.active = True
            return 0
        names = (
            "OperationFFD",
            "ImageFFD",
            "DDR",
            "AbsoluteTimeStamp",
            "Airbag_Hinban",
            "Airbag_Software",
            "CSP_Hinban",
            "CSP_MakerId",
            "CSP_SerialNo",
            "PCS_Hinban",
            "PCS_MakerId",
            "PCS_SerialNo",
            "FCM_Hinban",
            "FCM_MakerId",
            "FCM_SerialNo",
            "TripCount",
            "OdoMeter",
            "OdoUnit",
            "MarkMonRam",
            "LCSOperationFFD",
            "MarkMonRam_SSR",
            "PVMImageFFD",
            "ADSOperationFFD",
            "ADSOperationFFD_Eng",
            "ADSImageFFD",
            "TSS3OperationFFD",
            "RCImageFFD",
        )
        if kind >= (20 if self.source_build == 12 else len(names)):
            return 0x90020701
        self.path = self.directory / (names[kind] + ".log")
        self._failed = False
        self.written = 0
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._file = self.path.open("w+b", buffering=0)
        except OSError:
            return 0x90020706
        self.operations.set_packet_log(self._write, self._failure)
        self.kind = kind
        self.active = True
        return 0

    def get_size(self) -> tuple[int, int | None]:
        """KGP12:13150/18:17B00 GetFileSize; preserve position and absent out-value."""
        if self._file is None:
            return 0x90020706, None
        try:
            size = fstat(self._file.fileno()).st_size
        except (OSError, ValueError):
            return 0x90020706, None
        if size > self.max_bytes or size & 0xFFFFFFFF == 0xFFFFFFFF:
            return 0x90020706, None
        return 0, size

    def set_pointer(self, position: int) -> int:
        """KGP12:131D0/18:17B80 FILE_BEGIN seek followed by SetEndOfFile."""
        if type(position) is not int or not 0 <= position <= 0xFFFFFFFF:
            raise ValueError("Native communication-log offset must fit DWORD")
        # No high-distance pointer is supplied: the native LONG is signed.
        if self._file is None or position >= 0x80000000 or position > self.max_bytes:
            return 0x90020706
        try:
            self._file.seek(position)
            self._file.truncate()
        except (OSError, ValueError):
            return 0x90020706
        self.written = position
        return 0

    def change(self, kind: int) -> int:
        """Native18 17610/native12 12CB0: validate, close/open only while saving.

        The save-enabled flag stays set after close/create failure, as native
        ChangeCommLogFile does; its caller chooses whether to stop logging.
        """
        if type(kind) is not int or not 0 <= kind <= 65535:
            raise ValueError("Native communication-log kind must fit uint16")
        if kind >= (20 if self.source_build == 12 else 27):
            return 0x90020701
        if not self.active:
            return 0
        status = self.stop()
        if not status:
            status = self.start(kind)
        self.active = True
        return status

    def stop(self) -> int:
        """Native Close17500 strips only the final literal backslash+n pair."""
        self.active = False
        status = 0
        if self._file is not None:
            handle = self._file
            try:
                handle.seek(-2, 2)
                if handle.read(2) == b"\\n":
                    handle.seek(-2, 2)
                    handle.truncate()
            except OSError:
                # Native seek/read/tail mismatch never prevents CloseHandle.
                pass
            try:
                handle.close()
            except OSError:
                status = 0x90020706
            else:
                self._file = None
                self.operations.set_packet_log(None, None)
        if not status and self._failed:
            status = 0x90020706
        self._failed = False
        return status

    start_comm_log = start
    stop_comm_log = stop
    change_comm_log_file = change
    get_comm_log_file_size = get_size
    set_comm_log_file_pointer = set_pointer


def capture_internal_ddr_report(
    communication: NativeCommunication,
    *,
    p5: bool,
    connections: Mapping[tuple[int, int], NativeCommunication] | None = None,
) -> DdrReport | DdrP5Report:
    """Internal image BC/1BC DDR business on the retained controller, bus0x12.

    The image caller owns its packet log and decides whether to ignore a native
    numeric failure. No DDR log is opened here. Canonical target metadata and
    actual retained contexts replace native DataCtrl/controller pointers.
    """
    from scripts.native_communication import NativeCommunication, NativeFrameController
    from scripts.profiles import VehicleProfile
    from scripts.toyota import MISSING_RECORD, ToyotaCodecError
    from scripts.toyota_session import NativeStatus, SessionError

    if type(p5) is not bool:
        raise TypeError("Internal DDR source variant must be boolean")
    if (
        not isinstance(communication, NativeCommunication)
        or communication.source_build not in (12, 18)
        or not isinstance(communication.operations, NativeFrameController)
        or not isinstance(communication.profile, VehicleProfile)
    ):
        raise ValueError(
            "Internal DDR requires a retained selected native Toyota controller"
        )
    if p5 and communication.source_build == 12:
        raise NotImplementedError("Native12 internal P5 DDR is unsupported")
    controller = communication.operations
    communication.cache.check_context()
    category, bus = (0x1BC if p5 else 0xBC), 0x12
    source = communication.profile
    if not source.category_records(category):
        raise ToyotaCodecError("Internal DDR target category is absent", MISSING_RECORD)
    canonical = source.catalog.build_profile(
        category,
        exception_ids=source.exception_ids,
        vehicle_name_key=source.vehicle_name_key,
    )
    target = (connections or {}).get((category, bus))
    if target is None:
        target = (
            communication
            if source.category == category and communication.bus_id == bus
            else communication.protocol_context(canonical, bus_id=bus)
        )
    if (
        not isinstance(target, NativeCommunication)
        or target.source_build != communication.source_build
        or target.operations is not communication.operations
        or target.bus_id != bus
        or not isinstance(target.profile, VehicleProfile)
        or target.profile.category_record != canonical.category_record
        or target.profile.database.sha256 != canonical.database.sha256
        or target.profile.catalog.management.sha256 != source.catalog.management.sha256
        or target.profile.exception_ids != source.exception_ids
        or target.profile.vehicle_name_key != source.vehicle_name_key
    ):
        raise ValueError(
            "Internal DDR retained target differs from canonical selected context"
        )
    contexts = (DdrEcuContext(category, bus),)
    with communication.cache.target_operation(target):
        if p5:
            try:
                initial_ddr_p5_attribute_plan(target.profile)
                connected = target.connection_no_buffer()
                if connected.status:
                    raise NativeStatus(connected.status, connected.response)
                result = capture_ddr_p5_report(
                    target.cache, connections=connections, ecu_specific=contexts
                )
            except BaseException as primary:
                try:
                    controller.disconnect(1)
                except (OSError, SessionError, ToyotaCodecError) as cleanup:
                    primary.add_note(
                        f"Internal DDR Disconnect also failed: {type(cleanup).__name__}"
                    )
                raise
            # Native closes the shared controller, not the parent host context.
            # Ignore only its numeric result, preserving later image acquisition.
            controller.disconnect(1)
            return result
        plan = initial_ddr_attribute_plan(target.profile)
        if plan.source_build != target.source_build:
            raise ValueError("Internal DDR profile schema differs from native source")
        target.cache.invalidate_a8(1)
        connected = target.connection_no_buffer()
        if connected.status:
            raise NativeStatus(connected.status, connected.response)
        attributes = capture_ddr_attributes(
            target.cache,
            connections=connections,
            ecu_specific=contexts,
            saved_log=True,
            internal_image=True,
        )
        # Inline Image1F70 writes spec/CSV only; its trigger list stays empty,
        # so19F0 never invokes the normal row/catalog formatter3500.
        observations = dict(attributes.observations)
        extra = []
        for slot in attributes.plan.slots:
            if not 159 <= slot.logical_id <= 171:
                continue
            present = bool(slot.candidates) and slot.enabled and slot.supported
            value = observations[slot.logical_id] if present else 0
            if slot.logical_id in (163, 166, 169, 171):
                value &= 0x1FFFFFFF
            extra.append((slot.logical_id, present, value))
        return DdrReport(
            DdrCapture(attributes, (), ()),
            (),
            None,
            attributes.spec_value,
            tuple(extra),
            (),
        )


def _capture_ddr_logged(
    communication: NativeCommunication,
    packet_log: DdrPacketLog,
    *,
    report: bool,
    connections: Mapping[tuple[int, int], NativeCommunication] | None = None,
) -> DdrCapture | DdrReport:
    """Native SaveLog13E0 file/cache/no-buffer/acquisition/stop chronology.

    This returns acquired records before the separate61E0 report formatter.
    Logging failure never substitutes a successful diagnostic status.
    """
    from scripts.toyota_session import NativeStatus

    if (
        communication.source_build != 18
        or packet_log.operations is not communication.operations
    ):
        raise ValueError(
            "DDR saved-log file must bind the retained native18 controller"
        )
    communication.cache.check_context()
    initial_ddr_attribute_plan(_toyota_profile(communication.profile))
    started = packet_log.start()
    try:
        communication.cache.invalidate_a8(1)
        connection = communication.connection_no_buffer()
        if connection.status:
            raise NativeStatus(connection.status, connection.response)
        capture = capture_ddr_records(
            communication,
            connections=connections,
            ecu_specific=(
                DdrEcuContext(communication.profile.category, communication.bus_id),
            ),
            saved_log=True,
        )
        result = (
            format_ddr_capture(
                _toyota_profile(communication.profile), capture, saved_log=True
            )
            if report
            else capture
        )
    except BaseException:
        if started == 0:
            packet_log.stop()
        raise
    status = packet_log.stop() if started == 0 else started
    if status:
        raise NativeStatus(status)
    return result


def capture_ddr_records_saved_log(
    communication: NativeCommunication,
    packet_log: DdrPacketLog,
    *,
    connections: Mapping[tuple[int, int], NativeCommunication] | None = None,
) -> DdrCapture:
    """Native saved-log acquisition phase, preserving error/stop chronology."""
    result = _capture_ddr_logged(
        communication, packet_log, report=False, connections=connections
    )
    assert isinstance(result, DdrCapture)
    return result


def capture_ddr_saved_log(
    communication: NativeCommunication,
    packet_log: DdrPacketLog,
    *,
    connections: Mapping[tuple[int, int], NativeCommunication] | None = None,
) -> DdrReport:
    """Native saved-log record acquisition plus61E0 command report before Stop."""
    result = _capture_ddr_logged(
        communication, packet_log, report=True, connections=connections
    )
    assert isinstance(result, DdrReport)
    return result


def capture_ddr_p5_saved_log(
    communication: NativeCommunication,
    packet_log: DdrPacketLog,
    *,
    connections: Mapping[tuple[int, int], NativeCommunication] | None = None,
) -> DdrP5Report:
    """P5SaveLog10B0: Start2, no-buffer capture/report, Disconnect1, conditionalStop.

    Native ignores the numeric Disconnect status. Acquisition errors retain
    precedence over Start/Stop errors; Stop runs only after successful Start.
    """
    from scripts.native_communication import NativeFrameController
    from scripts.toyota import ToyotaCodecError
    from scripts.toyota_session import NativeStatus, SessionError

    if (
        communication.source_build != 18
        or not isinstance(communication.operations, NativeFrameController)
        or packet_log.operations is not communication.operations
    ):
        raise ValueError(
            "P5 DDR saved log requires the retained native18 outer controller"
        )
    communication.cache.check_context()
    initial_ddr_p5_attribute_plan(_toyota_profile(communication.profile))
    started = packet_log.start(2)
    try:
        connection = communication.connection_no_buffer()
        if connection.status:
            raise NativeStatus(connection.status, connection.response)
        result = capture_ddr_p5_report(
            communication.cache,
            connections=connections,
            ecu_specific=(
                DdrEcuContext(communication.profile.category, communication.bus_id),
            ),
        )
    except BaseException as primary:
        try:
            communication.disconnect(1)
        except (OSError, SessionError, ToyotaCodecError) as cleanup:
            primary.add_note(
                f"P5 saved-log disconnect also failed: {type(cleanup).__name__}"
            )
        if started == 0:
            try:
                packet_log.stop()
            except (OSError, SessionError, ToyotaCodecError) as cleanup:
                primary.add_note(
                    f"P5 saved-log Stop also failed: {type(cleanup).__name__}"
                )
        raise
    try:
        communication.disconnect(1)
    finally:
        status = packet_log.stop() if started == 0 else started
    if status:
        raise NativeStatus(status)
    return result


def prepare_ddr_session(cache: MonitorSupportCache) -> None:
    """Normal DDR 0x1810: selected C3/C4 preparation, then selected C1/C2.

    Templates remain selected private DDB data. No OEM constants are embedded.
    This performs the preparation exchanges, not the complete DDR acquisition.
    """
    _prepare_ddr_pairs(cache, ((0xC3, 0xC4), (0xC1, 0xC2)))


def _prepare_ddr_pairs(
    cache: MonitorSupportCache, pairs: tuple[tuple[int, int], ...]
) -> None:
    from scripts.toyota import INVALID_RECORD, SHORT_REPLY, ToyotaCodecError

    def first_frame(function: int) -> SelectedFrame:
        try:
            selected = cache.profile.frame_records(function)
        except ValueError as error:
            raise ToyotaCodecError(
                "DDR preparation frame is absent", INVALID_RECORD
            ) from error
        if not selected or not 1 <= len(selected[0].frame.request) <= 255:
            raise ToyotaCodecError("DDR preparation frame is absent", INVALID_RECORD)
        return selected[0]

    for challenge_function, response_function in pairs:
        selected = first_frame(challenge_function)
        reply = cache.transaction(selected, selected.frame.request, cached=False)
        selected.frame.check_mask(reply)
        if len(reply) < 4:
            raise ToyotaCodecError("DDR preparation reply lacks word", SHORT_REPLY)
        challenge = int.from_bytes(reply[2:4], "big")
        if challenge == 0:
            continue
        selected = first_frame(response_function)
        request = selected.frame.request
        if len(request) < 4:
            raise ToyotaCodecError(
                "DDR preparation template lacks word", INVALID_RECORD
            )
        adjusted = (int.from_bytes(request[2:4], "big") - challenge - 1) & 0xFFFF
        request = request[:2] + adjusted.to_bytes(2, "big") + request[4:]
        reply = cache.transaction(selected, request, cached=False)
        selected.frame.check_mask(reply)


def create_ram_examples() -> dict[str, bytes]:
    """Build authored A1 resources and replay through production codecs only."""
    import json
    import struct
    from tempfile import TemporaryDirectory

    from scripts.demo import _ddb, _language
    from scripts.profiles import VehicleCatalog

    category = bytearray(76)
    category[:18] = "demo.ddb\0".encode("utf-16le")
    struct.pack_into("<H", category, 68, 42)
    category[72] = 3
    request = bytes.fromhex("91000000000000")
    files = {
        "Toyota.ddb": _ddb(
            1,
            {
                0: (1, struct.pack("<IH", 0, len(request)) + request),
                16: (1, bytes(category)),
                17: (1, struct.pack("<4H", 1, 1, 0, 0)),
                18: (1, struct.pack("<8H", 42, 0xA1, 1, 1, 0, 0, 0, 0)),
                29: (1, bytes.fromhex("44332211000000000000010000000000")),
            },
        ),
        "M_English.ddb": _language(["Authored raw RAM example"]),
        "demo.ddb": _ddb(2, {10: (0, b"")}),
    }

    def exchange(query: RamQuery) -> bytes:
        payload = bytes(
            (query.frame.address + index) & 255 for index in range(query.request[2])
        )
        return bytes((query.request[0] | 0x40,)) + query.request[1:] + payload

    with TemporaryDirectory(prefix="techstream-ram-example-") as directory:
        root = Path(directory)
        for name, raw in files.items():
            (root / name).write_bytes(raw)
        profile = VehicleCatalog(root).build_profile(42)
        reader = NativeRamReader(
            profile,
            exchange,
            ecu="authored-ecu",
            frame=RamFrame(bytes.fromhex("0100040000000000")),
            block_size=56,
        )
        assert reader.read(256, 8) == bytes(range(8))
        files["ram.json"] = encode_ram_recording(reader, source="authored_synthetic")
    files["ram-example.json"] = (
        json.dumps(
            {
                "source": "authored_synthetic",
                "category": 42,
                "actions": [
                    {
                        "address": 256,
                        "length": 8,
                        "real": False,
                        "expected_hex": "0001020304050607",
                    }
                ],
                "files": {name: sha256(raw).hexdigest() for name, raw in files.items()},
            },
            indent=2,
        )
        + "\n"
    ).encode()
    return files
