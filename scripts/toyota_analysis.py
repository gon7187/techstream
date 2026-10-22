"""Source-bound work-factor history decoding; imports never open a device.

DCM35 and RoB providers consume selected metadata and diagnostic primitives.
Unrecovered original branches fail closed; imports never open a transport.
"""

from __future__ import annotations

import codecs
import re
import struct
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from scripts.monitor_support import MonitorSupportCache, monitor_source_identity
from scripts.profiles import ProtocolProfile, VehicleProfile
from scripts.signal_conversion import extract_bits
from scripts.support import word
from scripts.toyota import ToyotaCodecError
from scripts.toyota_session import SessionError

if TYPE_CHECKING:
    from scripts.native_communication import NativeCommunication

COMMON12_SHA256 = "d2542b8bf82347080ed73f84285a8d14d0c592fb9713abfc50448725b414a126"
COMMON18_SHA256 = "07547a9e47378d37c3ef7d96c2f33f6c62c4151626d98d3f3ff03b7c74909de7"
DCM35_SHA256 = "f154e9b2fceede17af35cdb90148ccc9b33f030f7de8d66b00498873cc9eccf2"
ROB18_SHA256 = "3d6c8ad1d93d4690f88e8b0fc51a3ae3d7b9b4348e6077781b2a7b6988842c02"
_SKIPPABLE = frozenset(
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


@dataclass(frozen=True)
class WorkFactorRecordP5:
    """An actual CCmdWrkFctDataDcmP5 row, with raw history bytes retained."""

    index: int
    operation_code: int
    function_name: str
    content_name: str
    time_valid: bool
    time_values: tuple[int, ...]
    network_valid: bool
    network_status: tuple[str, ...]
    raw: bytes
    operation_definition: bytes


@dataclass(frozen=True)
class WorkFactorGroupP5:
    data_id: int
    display_id: int
    name: str
    records: tuple[WorkFactorRecordP5, ...]
    definition: bytes
    received_payload: bytes


@dataclass(frozen=True)
class AnalysisResult:
    """Typed business output; native status is separate from decoded records."""

    native_status: int
    source_sha256: str
    common_sha256: str
    selected_identity: tuple[object, ...]
    groups: tuple[WorkFactorGroupP5, ...]
    skipped: tuple[tuple[int, int], ...] = ()
    source_build: int = 18
    disconnect_status: int | None = None
    language_sha256: str = ""
    observed_bus: int | None = None


def marker_order_p5(payload: bytes) -> tuple[int, ...]:
    """Common18 2e850/2e8e0/2e45d: first FF12 marker, two reverse passes.

    Native FindMarker leaves index zero if no marker occurs. Preserve that
    behavior: without a marker, record zero is not returned by AnalyzeRcvData.
    Native ignores the incomplete final record; retain it in the outer payload.
    """
    if not isinstance(payload, bytes) or len(payload) > 4093:
        raise ToyotaCodecError(
            "Work-factor payload exceeds native receive storage", 0xA0040202
        )
    count = len(payload) // 12
    marker = next(
        (i for i in range(count) if payload[i * 12 : (i + 1) * 12] == b"\xff" * 12), 0
    )
    return (*range(marker - 1, -1, -1), *range(count - 1, marker, -1))


def dcm_marker(record: bytes) -> bool:
    """Common18 2c650: only WORK_FACTOR_DATA_DCM bytes +4..+7 are marker."""
    if not isinstance(record, bytes) or len(record) < 8:
        raise ToyotaCodecError("DCM record lacks its marker field", 0xC0040001)
    return record[4:8] == b"\xff" * 4


def rob_marker(data_ids: tuple[bytes, ...]) -> bool:
    """Common18 37ae0: empty DID list is not a marker; empty DID data is."""
    if not isinstance(data_ids, tuple) or any(
        not isinstance(value, bytes) for value in data_ids
    ):
        raise ToyotaCodecError("RoB marker requires DID byte observations", 0xC0040001)
    return bool(data_ids) and all(
        all(value == 255 for value in data) for data in data_ids
    )


def rob_marker_order(records: tuple[tuple[bytes, ...], ...]) -> tuple[int, ...]:
    """Common18 37bb0/37dc0: reverse both sides of the first marker.

    Additional markers are copied by SortMarkerDataForRob, unlike P5 decoding.
    No marker leaves the native default index zero.
    """
    if not isinstance(records, tuple) or len(records) > 32768:
        raise ToyotaCodecError(
            "RoB marker input exceeds host history bound", 0xC0040001
        )
    markers = tuple(rob_marker(record) for record in records)
    marker = next((index for index, value in enumerate(markers) if value), 0)
    return (*range(marker - 1, -1, -1), *range(len(records) - 1, marker, -1))


def rob_lsb(raw: int, physical: bytes, first: int, last: int) -> tuple[int, int]:
    """Common18 37960: low-DWORD multiply, signed divide and x86 shift modulus.

    The offset in PhyData is intentionally unused by this native helper.
    Both returned scalars retain native DWORD bits; units are not inferred.
    """
    if (
        type(raw) is not int
        or not 0 <= raw <= 0xFFFFFFFF
        or not isinstance(physical, bytes)
        or len(physical) != 24
        or any(
            type(value) is not int or not 0 <= value <= 65535 for value in (first, last)
        )
        or first > last
    ):
        raise ToyotaCodecError("Invalid RoB scalar/physical definition", 0xC0040001)
    multiplier, divisor = struct.unpack_from("<Ii", physical)
    divisor = divisor or 1

    def divide(value: int) -> int:
        magnitude = (value & 0xFFFFFFFF) // abs(divisor)
        return (-magnitude if divisor < 0 else magnitude) & 0xFFFFFFFF

    return (
        divide(multiplier * raw),
        divide((1 << ((last - first + 1) & 31)) * multiplier),
    )


@dataclass(frozen=True)
class RoBTiming:
    """Native scalar fields; no wall-clock units are inferred."""

    happened: tuple[int | None, ...]
    passed: tuple[int, ...]
    max_wraps: int
    current_after_reset: int


@dataclass(frozen=True)
class RoBValue:
    name: str = ""
    value: int = 0
    unit: str = ""
    format: int = 0x4000
    definition: bytes = b""
    physical: bytes = b""


@dataclass(frozen=True)
class RoBCurrent:
    values: tuple[RoBValue, ...]
    system_time: tuple[int, ...]
    modulus: int
    adjusted_ticks: int = 0


@dataclass(frozen=True)
class WorkFactorRecordRoB:
    operation_code: int
    operation_label: str
    help: str
    help_type: int
    values: tuple[RoBValue, ...]
    happened: int | None
    passed: int
    data_ids: tuple[tuple[int, bytes], ...]


@dataclass(frozen=True)
class WorkFactorGroupRoB:
    data_id: int
    display_id: int
    name: str
    records: tuple[WorkFactorRecordRoB, ...]
    definition: bytes


@dataclass(frozen=True)
class RoBAnalysisResult:
    native_status: int
    source_sha256: str
    common_sha256: str
    selected_identity: tuple[object, ...]
    groups: tuple[WorkFactorGroupRoB, ...]
    current: RoBCurrent | None
    skipped: tuple[tuple[int, int], ...] = ()
    source_build: int = 18
    language_sha256: str = ""
    ansi_encoding: str | None = None
    observed_bus: int | None = None


def _rob_bits(payload: bytes, first: int, last: int) -> int:
    """DT4090/Common9bf8a: byte shifts and DWORD shifts retain x86 truncation."""
    if first > last:
        raise ToyotaCodecError("Reversed RoB bit range", 0xC0000001)
    if last >= len(payload) * 8:
        raise ToyotaCodecError("RoB field exceeds observed bytes", 0xA0040202)
    start, end = first >> 3, last >> 3
    shift = (~last) & 7
    value = payload[end] >> shift
    for distance in range(1, end - start):
        value |= payload[end - distance] << ((8 * distance - shift) & 31)
    if start == end:
        value &= (1 << (last - first + 1)) - 1
    else:
        value |= ((payload[start] << (first & 7)) & 255) << ((last - first - 7) & 31)
    return value & 0xFFFFFFFF


def rob_timing(
    records: tuple[tuple[int, int], ...],
    *,
    current_ticks: int,
    modulus: int,
    current_generation: int,
    previous_max_wraps: int = 0,
) -> RoBTiming:
    """Common18 37fa0/380b0/381b0, including unsigned DWORD rollover.

    Each input row is (original field+0xac, field+0x13c). Outputs correspond
    to happened field+0xf4, rewritten passed field+0xac and current field+0xac.
    This scalar primitive does not read or synthesize RoB diagnostic records.
    """
    if not isinstance(records, tuple) or len(records) > 32768:
        raise ToyotaCodecError(
            "RoB timing input exceeds host history bound", 0xC0040001
        )
    values = [current_ticks, modulus, current_generation, previous_max_wraps]
    for row in records:
        if not isinstance(row, tuple) or len(row) != 2:
            raise ToyotaCodecError("RoB timing row needs two native DWORDs", 0xC0040001)
        values.extend(row)
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in values):
        raise ToyotaCodecError("RoB timing values must be native DWORDs", 0xC0040001)
    happened: list[int | None] = [None] * len(records)
    previous, accumulated, wraps, maximum = current_ticks, 0, 0, previous_max_wraps
    for index, (ticks, generation) in enumerate(records):
        if generation != current_generation:
            break
        delta = previous - ticks
        if previous < ticks:
            delta += modulus
            wraps = (wraps + 1) & 0xFFFFFFFF
        accumulated = (accumulated + delta) & 0xFFFFFFFF
        happened[index] = accumulated
        previous = ticks
        maximum = max(maximum, wraps)
    passed = [0] * len(records)
    previous, previous_generation, accumulated = 0, 0, 0
    for index in range(len(records) - 1, -1, -1):
        ticks, generation = records[index]
        if index == len(records) - 1 or generation != previous_generation:
            delta, accumulated = ticks, 0
        else:
            delta = ticks - previous
            if previous > ticks:
                delta += modulus
        accumulated = (accumulated + delta) & 0xFFFFFFFF
        passed[index] = accumulated
        previous, previous_generation = ticks, generation
    return RoBTiming(
        tuple(happened),
        tuple(passed),
        maximum,
        (current_ticks + maximum * modulus) & 0xFFFFFFFF,
    )


class DcmP5Analysis:
    """Actual DCM35 support/read/decode composition over selected cache primitives.

    Common18 2dd60,2e020,2e140,2e2e0; DT Execute1010. Metadata comes from
    the caller-selected DDB and language, never from a successful-analysis hook.
    """

    def __init__(self, profile: ProtocolProfile, cache: MonitorSupportCache):
        if not isinstance(profile, VehicleProfile):
            raise SessionError("Work-factor analysis requires selected Toyota metadata")
        if cache.profile is not profile or cache.identity != monitor_source_identity(
            profile, cache.ecu
        ):
            raise SessionError("Work-factor cache belongs to another selected context")
        if (
            cache.source_build != 18
            or profile.database.version != 0x0100032F
            or profile.catalog.management.version != 0x0100032F
        ):
            raise SessionError("DCM35 source is proven only for native build18")
        if type(cache.bus_id) is not int or not 0 <= cache.bus_id <= 65535:
            raise SessionError("Work-factor analysis requires an observed native bus")
        modules = profile.dll_records(0xD7)
        if not modules:
            raise ToyotaCodecError("Selected work-factor module is absent", 0xC0040101)
        names = tuple(row[:80].decode("utf-16le").split("\0", 1)[0] for row in modules)
        if names != ("GetAnlWkFctDcm35_DT.dll",):
            raise SessionError(
                "Selected work-factor module has no recovered DCM35 provider"
            )
        self.profile, self.cache = profile, cache
        self.identity = cache.identity
        self.observed_bus = cache.bus_id
        self.language_sha256 = profile.catalog.language.sha256
        self.communication: NativeCommunication | None = None
        self.cleanup_status: int | None = None

    def _check(self) -> None:
        self.cache.check_context()
        if (
            self.profile is not self.cache.profile
            or self.cache.identity != self.identity
            or self.cache.bus_id != self.observed_bus
        ):
            raise SessionError("Work-factor selected context changed")
        if self.profile.catalog.language.sha256 != self.language_sha256:
            raise SessionError("Work-factor language source changed")

    @classmethod
    def from_communication(cls, communication: NativeCommunication) -> DcmP5Analysis:
        """Bind the actual selected outer controller and native Disconnect(1)."""
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )

        if not isinstance(communication, NativeCommunication) or not isinstance(
            communication.operations, NativeFrameController
        ):
            raise TypeError(
                "Work-factor lifecycle requires the concrete native controller"
            )
        provider = cls(communication.profile, communication.cache)
        provider.communication = communication
        return provider

    def _rows(self, slot: int, width: int) -> tuple[bytes, ...]:
        if slot not in self.profile.database.sections:
            raise ToyotaCodecError("Selected work-factor table is absent", 0xA0030107)
        rows = self.profile.records(slot)
        if len(rows) > 32767 or any(len(row) != width for row in rows):
            raise ToyotaCodecError(
                "Invalid selected work-factor definition width", 0xC0040102
            )
        return rows

    @staticmethod
    def _one(rows: tuple[bytes, ...], *, optional: bool = False) -> bytes | None:
        if not rows and optional:
            return None
        if len(rows) != 1:
            raise ToyotaCodecError(
                "Expected one selected work-factor definition", 0xC0040102
            )
        return rows[0]

    def _text(self, row: bytes, offset: int) -> str:
        reference = struct.unpack_from("<I", row, offset)[0]
        if reference == 0:
            raise ToyotaCodecError(
                "Native work-factor name pointer is null", 0xC0040102
            )
        try:
            return self.profile.catalog.language.resolve(reference)
        except ValueError as error:
            raise ToyotaCodecError(
                "Invalid work-factor text reference", 0xC0040102
            ) from error

    def _network(self, status: int) -> tuple[str, ...]:
        names = []
        for selector in range(1, 5):
            row = self._one(self.profile.work_factor_records(117, selector))
            if row is None:
                raise ToyotaCodecError("Network status selector is absent", 0xC0040102)
            try:
                value = extract_bits(bytes((status,)), word(row, 4), word(row, 6)) & 255
            except ValueError as error:
                raise ToyotaCodecError(
                    "Invalid network status bit range", 0xC0040102
                ) from error
            pattern = self._one(
                self.profile.work_factor_records(37, word(row, 8), value)
            )
            if pattern is None:
                raise ToyotaCodecError("Network status pattern is absent", 0xC0040102)
            names.append(self._text(pattern, 0))
        return tuple(names)

    def decode(self, data_id: int, payload: bytes) -> WorkFactorGroupP5:
        """Decode already observed DID bytes with selected definitions and provenance."""
        self._check()
        definition = self._one(self.profile.work_factor_records(114, data_id))
        if definition is None:
            raise ToyotaCodecError(
                "Work-factor signal definition is absent", 0xC0040102
            )
        records = []
        for index in marker_order_p5(payload):
            self._check()
            raw = payload[index * 12 : (index + 1) * 12]
            if raw == b"\xff" * 12:
                continue
            operation_code = int.from_bytes(raw[:2], "big")
            operation = self._one(
                self.profile.work_factor_records(116, data_id, operation_code),
                optional=True,
            )
            if operation is None:
                continue
            time_values: tuple[int, ...] = ()
            time_valid = raw[2:4] == b"\x02\x06"
            if time_valid:
                values = []
                for value in raw[4:11]:
                    if value >> 4 >= 10 or value & 15 >= 10:
                        time_valid = False
                        break
                    values.append((value >> 4) * 10 + (value & 15))
                time_values = tuple(values)
            network_valid = raw[2] == 2 and raw[10] == 1
            records.append(
                WorkFactorRecordP5(
                    index,
                    operation_code,
                    self._text(operation, 0),
                    self._text(operation, 4),
                    time_valid,
                    time_values,
                    network_valid,
                    self._network(raw[11]) if network_valid else (),
                    raw,
                    operation,
                )
            )
        return WorkFactorGroupP5(
            data_id,
            word(definition, 18),
            self._text(definition, 12),
            tuple(records),
            definition,
            payload,
        )

    def run(self) -> AnalysisResult:
        self._check()
        if self.communication is None:
            return self._run()
        try:
            result = self._run()
        finally:
            # DT1010/121d ignores this status; retain it separately for host cleanup.
            self.cleanup_status = self.communication.disconnect(1)
        return replace(result, disconnect_status=self.cleanup_status)

    def _run(self) -> AnalysisResult:
        self._check()
        with self.cache.temporary_scope():
            signals = self._rows(114, 24)
            if not signals:
                raise ToyotaCodecError("Work-factor signal table is empty", 0xC0040102)
            supported, any_upper = [], False
            for row in signals:
                data_id = word(row, 16)
                status = self.cache.data_id_support_status(data_id)
                any_upper |= status != 0
                if status == 2:
                    supported.append(data_id)
            if not any_upper:
                raise ToyotaCodecError("Work-factor data is unsupported", 0x90040501)
            frames = self.profile.frame_records(0xCA)
            if not frames or len(frames[0].frame.request) < 3:
                raise ToyotaCodecError(
                    "Work-factor CA frame is absent or short", 0xC0040102
                )
            frame = frames[0]
            groups, skipped = [], []
            for data_id in supported:
                request = (
                    frame.frame.request[:1]
                    + data_id.to_bytes(2, "big")
                    + frame.frame.request[3:]
                )
                try:
                    reply = self.cache.transaction(
                        frame,
                        request,
                        native_parameter=self.cache.bus_id or 0,
                        cached=False,
                        temporary=True,
                        extended=True,
                    )
                    if len(reply) <= 3:
                        raise ToyotaCodecError(
                            "Work-factor DID payload is absent", 0xA0040202
                        )
                except ToyotaCodecError as error:
                    if error.code not in _SKIPPABLE:
                        raise
                    skipped.append((data_id, error.code))
                    continue
                groups.append(self.decode(data_id, reply[3:]))
            return AnalysisResult(
                0,
                DCM35_SHA256,
                COMMON18_SHA256,
                self.identity,
                tuple(groups),
                tuple(skipped),
                language_sha256=self.language_sha256,
                observed_bus=self.observed_bus,
            )


class RoBAnalysis:
    """Original18 D6 provider: selected F3/F4/F5 observations and native joins."""

    def __init__(
        self,
        profile: ProtocolProfile,
        cache: MonitorSupportCache,
        *,
        ansi_encoding: str | None = None,
    ):
        if not isinstance(profile, VehicleProfile):
            raise SessionError("RoB analysis requires selected Toyota metadata")
        if cache.profile is not profile or cache.identity != monitor_source_identity(
            profile, cache.ecu
        ):
            raise SessionError("RoB cache belongs to another selected context")
        if (
            cache.source_build != 18
            or profile.database.version != 0x0100032F
            or profile.catalog.management.version != 0x0100032F
        ):
            raise SessionError("RoB provider requires original build18")
        if type(cache.bus_id) is not int or not 0 <= cache.bus_id <= 65535:
            raise SessionError("RoB analysis requires an observed native bus")
        modules = profile.dll_records(0xD6)
        if not modules:
            raise ToyotaCodecError("Selected RoB module is absent", 0xC0040101)
        if tuple(row[:80].decode("utf-16le").split("\0", 1)[0] for row in modules) != (
            "GetRoBP5_AnlzWkFct_DT.dll",
        ):
            raise SessionError("Selected D6 module has no recovered RoB provider")
        self.ansi_encoding = (
            codecs.lookup(ansi_encoding).name if ansi_encoding is not None else None
        )
        self.profile, self.cache = profile, cache
        self.observed_bus = cache.bus_id
        self._selected_encoding = self.ansi_encoding
        self.identity, self.language_sha256 = (
            cache.identity,
            profile.catalog.language.sha256,
        )

    def _check(self):
        self.cache.check_context()
        if (
            self.profile is not self.cache.profile
            or self.cache.identity != self.identity
            or self.cache.bus_id != self.observed_bus
            or self.ansi_encoding != self._selected_encoding
        ):
            raise SessionError("RoB selected context changed")
        if self.language_sha256 != self.profile.catalog.language.sha256:
            raise SessionError("RoB language source changed")

    @staticmethod
    def _first(rows: tuple[bytes, ...], *, exact: bool = False) -> bytes:
        if not rows or (exact and len(rows) != 1):
            raise ToyotaCodecError(
                "Selected RoB definition count is invalid", 0xC0040102
            )
        return rows[0]

    def _format(self, text: str) -> str:
        # Narrow sprintf has no capacity argument; the caller's stack buffer is256.
        if self.ansi_encoding is None and not text.isascii():
            raise SessionError("RoB narrow formatting requires observed ANSI encoding")
        try:
            encoded = text.encode(self.ansi_encoding or "ascii")
        except UnicodeError as error:
            raise SessionError(
                "RoB text cannot round-trip through selected ANSI encoding"
            ) from error
        if b"\0" in encoded or len(encoded) >= 256:
            raise SessionError("RoB formatted text exceeds native256-byte buffer")
        return text

    def _text(self, row: bytes, offset: int = 0, *, null: str = "") -> str:
        reference = struct.unpack_from("<I", row, offset)[0]
        if not reference:
            return null
        try:
            return self.profile.catalog.language.resolve(reference)
        except ValueError as error:
            raise SessionError("RoB used an unresolved native text pointer") from error

    def _read(
        self, function: int, replacement: bytes = b"", *, current: bool = False
    ) -> bytes:
        self._check()
        frames = self.profile.frame_records(function)
        if not frames or ((function == 0xF3 or current) and len(frames) != 1):
            raise ToyotaCodecError("Selected RoB frame count is invalid", 0xC0040102)
        selected = frames[0]
        offset = 1 if current else 2
        request = selected.frame.request
        if replacement:
            if len(request) < offset + len(replacement):
                raise ToyotaCodecError("Selected RoB request is short", 0xC0040102)
            request = (
                request[:offset] + replacement + request[offset + len(replacement) :]
            )
        return self.cache.transaction(
            selected,
            request,
            native_parameter=0,
            cached=False,
            temporary=current,
            extended=True,
            capacity=65535 if not current and self.cache.bus_id == 0x14 else None,
        )

    def current_value(self, signal: int) -> tuple[RoBValue, int]:
        """Common37120/37420/37500/37960, including eager selected text faults."""
        self._check()
        groups = self.profile.signal_group_records(signal)
        if not groups:
            raise ToyotaCodecError("RoB current SignalGroup is absent", 0xC0040101)
        pids = self.profile.signal_pids(signal)
        logical = pids[0]
        definitions = self.profile.datamonitor_p5_records(logical)
        if not definitions:
            raise ToyotaCodecError("RoB current logical PID is absent", 0xC0040101)
        row = definitions[0]
        first, last, did = word(row, 44), word(row, 46), word(row, 54)
        reply = self._read(0xCA, did.to_bytes(2, "big"), current=True)
        if len(reply) < 4:
            raise ToyotaCodecError("RoB current payload is absent", 0xA0040202)
        raw = _rob_bits(reply[3:], first, last)
        # GetLsbInfo performs its own eager query before physical lookup.
        row = self.profile.datamonitor_p5_records(logical)[0]
        physicals = self.profile.physical_records(word(row, 42))
        if not physicals:
            raise ToyotaCodecError(
                "RoB current physical definition is absent", 0xC0040101
            )
        physical = physicals[0]
        value, modulus = rob_lsb(raw, physical, first, last)
        units = self.profile.unit_records(word(physical, 14))
        unit = self._text(units[0]) if units else ""
        return RoBValue(
            self._text(groups[0]),
            value,
            unit,
            4 if signal == 0x1A else 0,
            row,
            physical,
        ), modulus if signal == 0x1A else 0

    @staticmethod
    def _history(reply: bytes) -> tuple[tuple[int, bytes], ...] | None:
        """DT1a40/32b0: malformed trailing entries discard the whole read."""
        if len(reply) <= 6:
            return None
        result: list[tuple[int, bytes]] = []
        offset = 6
        while offset < len(reply):
            count = reply[offset]
            offset += 1
            if not count:
                # Native fallback scans from absolute offset7, not this block.
                cursor, count = 7, 0
                while cursor + 3 <= len(reply):
                    cursor += 3 + reply[cursor + 2]
                    if cursor > len(reply):
                        break
                    count += 1
            for _ in range(count):
                if offset + 3 > len(reply):
                    return None
                did, size = (
                    int.from_bytes(reply[offset : offset + 2], "big"),
                    reply[offset + 2],
                )
                offset += 3
                if size:
                    if offset + size > len(reply):
                        return None
                    result.append((did, reply[offset : offset + size]))
                    offset += size
        return tuple(result)

    def _decode(self, raw: tuple[tuple[int, bytes], ...]) -> WorkFactorRecordRoB | None:
        # DT30d0 keeps defined DIDs only; a duplicate clears the whole record.
        selected: list[tuple[int, bytes]] = []
        for did, data in raw:
            if not self.profile.work_factor_records(115, did):
                continue
            if any(previous == did for previous, _ in selected):
                return None
            selected.append((did, data))
        if len(selected) != 2:
            return None
        values = [RoBValue(), RoBValue(), RoBValue()]
        opcode, label, help_text, help_type = 0, "", "", 0
        for did, data in selected:
            items = self.profile.work_factor_records(115, did)
            for item_type in dict.fromkeys(row[18] for row in items):
                row = self._first(self.profile.work_factor_records(115, did, item_type))
                first, last = word(row, 6), word(row, 8)
                end_byte = ((last >> 3) + 1) & 255
                if end_byte == ((first >> 3) & 255):
                    raise ToyotaCodecError("Invalid RoB item byte boundary", 0xC0040102)
                if len(data) & 255 < end_byte:
                    return None
                raw_value = _rob_bits(data, first, last)
                physical = self._first(
                    self.profile.physical_records(word(row, 10)), exact=True
                )
                value, _ = rob_lsb(raw_value, physical, first, last)
                units = self.profile.unit_records(word(physical, 14))
                unit = self._text(self._first(units, exact=True))
                if item_type == 1:
                    patterns = self.profile.work_factor_records(
                        37, word(row, 12), value
                    )
                    opcode = value & 65535
                    label = f"0x{value:02X}"
                    if patterns:
                        label += ":" + self._text(patterns[0], null="(null)")
                        help_text, help_type = (
                            self._text(patterns[0], 4),
                            word(patterns[0], 12),
                        )
                    else:
                        help_text, help_type = "", 1
                    label = self._format(label)
                elif item_type in (2, 3, 4):
                    values[item_type - 2] = RoBValue(
                        self._text(row),
                        value,
                        unit,
                        4 if item_type == 3 else 0,
                        row,
                        physical,
                    )
                else:
                    raise ToyotaCodecError(
                        "Unknown RoB work-factor item type", 0xC0040102
                    )
        return WorkFactorRecordRoB(
            opcode,
            label,
            help_text,
            help_type,
            tuple(values),
            None,
            values[1].value,
            raw,
        )

    def run(self, *, mode: int = 1, current_flag: int = 1) -> RoBAnalysisResult:
        """Execute38b0: metadata mode2, history mode1; no invented Disconnect."""
        self._check()
        if (
            type(mode) is not int
            or mode not in (1, 2)
            or type(current_flag) is not int
            or not 0 <= current_flag <= 0xFFFFFFFF
        ):
            raise ToyotaCodecError("Invalid native RoB command inputs", 0xC0040001)
        current = None
        ticks = generation = modulus = max_wraps = 0
        if current_flag == 1:
            with self.cache.temporary_scope():
                first, _ = self.current_value(0x19)
                second, modulus = self.current_value(0x1A)
                now = datetime.now(tz=UTC).astimezone()
                system_time = (
                    now.year,
                    now.month,
                    (now.weekday() + 1) % 7,
                    now.day,
                    now.hour,
                    now.minute,
                    now.second,
                    now.microsecond // 1000,
                )
                third, _ = self.current_value(0x1B)
            ticks, generation = second.value, third.value
            current = RoBCurrent((first, second, third), system_time, modulus)
        time.sleep(0.1)  # Native Execute38b0 Sleep(100), before F3 enumeration.
        reply = self._read(0xF3)
        ids = tuple(
            int.from_bytes(reply[i : i + 2], "big") for i in range(2, len(reply) - 1, 2)
        )
        if not ids:
            raise ToyotaCodecError(
                "RoB supported work-factor list is empty", 0xA0040201
            )
        groups, skipped = [], []
        for signal in ids:
            self._check()
            rows = self.profile.work_factor_records(114, signal)
            if not rows:
                continue
            definition, records = rows[0], []
            if mode == 1:
                try:
                    did_reply = self._read(0xF4, signal.to_bytes(2, "big"))
                except ToyotaCodecError as error:
                    if error.code not in _SKIPPABLE:
                        raise
                    skipped.append((signal, error.code))
                    continue
                dids = dict.fromkeys(
                    int.from_bytes(did_reply[i : i + 2], "big")
                    for i in range(4, len(did_reply) - 1, 2)
                )
                raw_records, previous_marker = [], False
                for did in dids:
                    try:
                        observed = self._read(
                            0xF5, signal.to_bytes(2, "big") + did.to_bytes(2, "big")
                        )
                    except ToyotaCodecError as error:
                        if error.code not in _SKIPPABLE | {0xC0040001}:
                            raise
                        skipped.append((did, error.code))
                        previous_marker = False
                        continue
                    raw = self._history(observed)
                    if raw is None:
                        # Execute clears its out-marker before every F5 helper call.
                        previous_marker = False
                        continue
                    raw_records.append(raw)
                    marker = rob_marker(tuple(data for _, data in raw))
                    if marker and previous_marker:
                        break
                    previous_marker = marker
                for index in rob_marker_order(
                    tuple(tuple(data for _, data in raw) for raw in raw_records)
                ):
                    raw = raw_records[index]
                    if rob_marker(tuple(data for _, data in raw)):
                        continue
                    decoded = self._decode(raw)
                    if decoded is not None:
                        records.append(decoded)
                timing = rob_timing(
                    tuple(
                        (row.values[1].value, row.values[2].value) for row in records
                    ),
                    current_ticks=ticks,
                    modulus=modulus,
                    current_generation=generation,
                    previous_max_wraps=max_wraps,
                )
                max_wraps = timing.max_wraps
                records = [
                    replace(
                        row,
                        happened=timing.happened[index],
                        passed=timing.passed[index],
                    )
                    for index, row in enumerate(records)
                ]
            prefix = definition[:12].decode("utf-16le").split("\0", 1)[0]
            name = self._format(f"{prefix}:{self._text(definition, 12, null='(null)')}")
            groups.append(
                WorkFactorGroupRoB(
                    signal, word(definition, 18), name, tuple(records), definition
                )
            )
        if current is not None:
            current = replace(
                current, adjusted_ticks=(ticks + max_wraps * modulus) & 0xFFFFFFFF
            )
        self._check()
        return RoBAnalysisResult(
            0,
            ROB18_SHA256,
            COMMON18_SHA256,
            self.identity,
            tuple(groups),
            current,
            tuple(skipped),
            language_sha256=self.language_sha256,
            ansi_encoding=self.ansi_encoding,
            observed_bus=self.observed_bus,
        )


@dataclass(frozen=True)
class DcmRamCapture:
    native_status: int
    words: tuple[tuple[int, bytes], ...]
    failures: tuple[tuple[int, int], ...]
    frame: bytes
    source_build: int
    common_sha256: str
    selected_identity: tuple[object, ...]
    observed_bus: int | None


def read_dcm_ram(
    cache: MonitorSupportCache, raw_frame: bytes, *, record_length: int = 4
) -> DcmRamCapture:
    """DT18 P4 2fe0/TS34b0 + Common451c0: direct A1, any-success status."""
    from scripts.database_resources import RamFrame, ram_payload, ram_request

    cache.check_context()
    if not isinstance(cache.profile, VehicleProfile):
        raise SessionError("DCM RAM requires selected Toyota metadata")
    version = 0x0100030C if cache.source_build == 12 else 0x0100032F
    if (
        cache.profile.database.version != version
        or cache.profile.catalog.management.version != version
    ):
        raise SessionError("DCM RAM selected build/version differs")
    if not isinstance(raw_frame, bytes) or len(raw_frame) != 8:
        raise ToyotaCodecError("Invalid native DCM RAM frame", 0xC0040001)
    if type(record_length) is not int or not 1 <= record_length <= 255:
        raise ToyotaCodecError("Invalid native RAM record length", 0xC0040001)
    count = raw_frame[1]
    if count == 0:
        return DcmRamCapture(
            0,
            (),
            (),
            raw_frame,
            cache.source_build,
            COMMON12_SHA256 if cache.source_build == 12 else COMMON18_SHA256,
            cache.identity,
            cache.bus_id,
        )
    if raw_frame[0] not in (0, 1):
        raise ToyotaCodecError("Invalid native DCM RAM address mode", 0xC0040001)
    if count == 255:
        raise SessionError("Native DCM BYTE loop would not terminate for count255")
    frame = RamFrame(raw_frame)
    frames = cache.profile.frame_records(0xA1)
    if not frames:
        raise ToyotaCodecError("Selected DCM A1 frame is absent", 0xC0040101)
    selected = frames[0]
    divisor = 2 if raw_frame[0] == 0 else 1
    step = (record_length + divisor - 1) // divisor
    words, failures = [], []
    for index in range(count + 1):
        cache.check_context()
        address = (frame.address + index * step) & 0xFFFFFFFF
        request = ram_request(selected.frame.request, frame.at(address), record_length)
        try:
            reply = cache.transaction(
                selected, request, cached=False, extended=False, native_parameter=0
            )
            data = ram_payload(request, reply)
        except ToyotaCodecError as error:
            failures.append((address, error.code))
        else:
            words.append((address, data))
    return DcmRamCapture(
        0 if words else failures[-1][1],
        tuple(words),
        tuple(failures),
        raw_frame,
        cache.source_build,
        COMMON12_SHA256 if cache.source_build == 12 else COMMON18_SHA256,
        cache.identity,
        cache.bus_id,
    )


def read_plain_p3_ram(cache: MonitorSupportCache, raw_frame: bytes) -> DcmRamCapture:
    """PlainP3 DT1e80/Common44c40: two direct A1 halfwords per native record.

    Unlike DCM P4's BYTE counter, this wrapper's DWORD loop terminates for255.
    The wrapper zeroes an eight-byte field; GetRamDataP3 fills its first four.
    """
    cache.check_context()
    if not isinstance(cache.profile, VehicleProfile):
        raise SessionError("PlainP3 RAM requires selected Toyota metadata")
    version = {12: 0x0100030C, 18: 0x0100032F}.get(cache.source_build)
    if (
        version is None
        or cache.profile.database.version != version
        or cache.profile.catalog.management.version != version
    ):
        raise SessionError("PlainP3 RAM requires matching original12/18 sources")
    if not isinstance(raw_frame, bytes) or len(raw_frame) != 8:
        raise ToyotaCodecError("Invalid native PlainP3 RAM frame", 0xC0040001)
    source = COMMON12_SHA256 if cache.source_build == 12 else COMMON18_SHA256
    if raw_frame[1] == 0:
        return DcmRamCapture(
            0,
            (),
            (),
            raw_frame,
            cache.source_build,
            source,
            cache.identity,
            cache.bus_id,
        )
    if raw_frame[0] not in (0, 1):
        raise ToyotaCodecError("Invalid native PlainP3 address mode", 0xC0040001)
    frames = cache.profile.frame_records(0xA1)
    if not frames:
        raise ToyotaCodecError("Selected PlainP3 A1 frame absent", 0xC0040101)
    selected = frames[0]
    if len(selected.frame.request) < 4:
        raise ToyotaCodecError("Selected PlainP3 A1 address absent", 0xC0040102)
    first = int.from_bytes(raw_frame[4:], "little")
    half_step = 1 if raw_frame[0] == 0 else 2
    words, failures = [], []
    for index in range(raw_frame[1] + 1):
        start = (first + index * half_step * 2) & 0xFFFFFFFF
        data = bytearray()
        try:
            for half in range(2):
                cache.check_context()
                address = (start + half * half_step) & 0xFFFFFFFF
                request = (
                    selected.frame.request[:1]
                    + bytes((raw_frame[2],))
                    + bytes(
                        (address >> ((shift * 8) & 31)) & 255
                        for shift in reversed(range(len(selected.frame.request) - 2))
                    )
                )
                reply = cache.transaction(
                    selected, request, cached=False, native_parameter=0, extended=False
                )
                if (
                    len(reply) != len(request) + 2
                    or reply[:1] != bytes((request[0] | 0x40,))
                    or reply[1 : len(request)] != request[1:]
                ):
                    raise ToyotaCodecError(
                        "PlainP3 RAM reply does not echo request", 0xA0040201
                    )
                data.extend(reply[-2:])
        except ToyotaCodecError as error:
            failures.append((address, error.code))
        else:
            words.append((start, bytes(data) + bytes(4)))
    return DcmRamCapture(
        0 if words else failures[-1][1],
        tuple(words),
        tuple(failures),
        raw_frame,
        cache.source_build,
        source,
        cache.identity,
        cache.bus_id,
    )


def read_dcm_variable_ram(
    cache: MonitorSupportCache, raw_frame: bytes, record_length: int
) -> DcmRamCapture:
    """DT18 3240/Common46d10:56-byte chunks, word alignment and native caching."""
    cache.check_context()
    if not isinstance(cache.profile, VehicleProfile):
        raise SessionError("Variable DCM RAM requires selected Toyota metadata")
    version = 0x0100030C if cache.source_build == 12 else 0x0100032F
    if (
        cache.profile.database.version != version
        or cache.profile.catalog.management.version != version
    ):
        raise SessionError("Variable DCM RAM selected build/version differs")
    if (
        not isinstance(raw_frame, bytes)
        or len(raw_frame) != 8
        or type(record_length) is not int
        or not 1 <= record_length <= 255
    ):
        raise ToyotaCodecError("Invalid variable DCM RAM input", 0xC0040001)
    count = raw_frame[1]
    if count == 0:
        return DcmRamCapture(
            0,
            (),
            (),
            raw_frame,
            cache.source_build,
            COMMON12_SHA256 if cache.source_build == 12 else COMMON18_SHA256,
            cache.identity,
            cache.bus_id,
        )
    if raw_frame[0] not in (0, 1):
        raise ToyotaCodecError("Invalid variable DCM RAM address mode", 0xC0040001)
    if count == 255:
        raise SessionError("Native DCM BYTE loop would not terminate for count255")
    frames = cache.profile.frame_records(0xA1)
    if not frames:
        raise ToyotaCodecError("Selected variable DCM A1 frame is absent", 0xC0040101)
    selected = frames[0]
    if not selected.frame.request:
        raise ToyotaCodecError("Selected variable DCM A1 service is absent", 0xC0040102)
    divisor = 2 if raw_frame[0] == 0 else 1
    address = int.from_bytes(raw_frame[4:], "little")
    words, failures = [], []
    for index in range(count + 1):
        start = address
        skip = int(divisor == 2 and bool(record_length & 1) and bool(index & 1))
        remaining, failed, payload = record_length + skip, False, bytearray()
        while remaining:
            cache.check_context()
            size = min(56, remaining)
            if not failed:
                request = (
                    selected.frame.request[:1]
                    + bytes((raw_frame[2], size))
                    + bytes(
                        (address >> ((shift * 8) & 31)) & 255
                        for shift in reversed(range(raw_frame[3]))
                    )
                )
                try:
                    reply = cache.transaction(
                        selected,
                        request,
                        cached=False,
                        temporary=True,
                        extended=False,
                        native_parameter=0,
                    )
                    if (
                        len(reply) != len(request) + size
                        or reply[:1] != bytes((request[0] | 0x40,))
                        or reply[1 : len(request)] != request[1:]
                    ):
                        raise ToyotaCodecError(
                            "Variable DCM RAM response does not echo request",
                            0xA0040201,
                        )
                except ToyotaCodecError as error:
                    failures.append((address, error.code))
                    failed = True
                else:
                    payload.extend(reply[len(request) + skip :])
            address = (address + size // divisor) & 0xFFFFFFFF
            skip = 0
            remaining -= size
        if not failed:
            words.append((start, bytes(payload)))
    return DcmRamCapture(
        0 if words else failures[-1][1],
        tuple(words),
        tuple(failures),
        raw_frame,
        cache.source_build,
        COMMON12_SHA256 if cache.source_build == 12 else COMMON18_SHA256,
        cache.identity,
        cache.bus_id,
    )


@dataclass(frozen=True)
class DcmValue:
    name: str
    value: int
    content: str
    unit: str
    format: int
    definition: bytes


@dataclass(frozen=True)
class DcmRecord:
    address: int
    items: tuple[DcmValue, ...]
    raw: bytes


@dataclass(frozen=True)
class DcmGroup:
    pid: int
    name: str
    records: tuple[DcmRecord, ...]
    format: int
    definition: bytes
    capture: DcmRamCapture


@dataclass(frozen=True)
class DcmAnalysisResult:
    native_status: int
    source_sha256: str
    common_sha256: str
    selected_identity: tuple[object, ...]
    groups: tuple[DcmGroup, ...]
    current: tuple[RoBValue, ...]
    source_build: int
    language_sha256: str
    observed_bus: int
    mode: int
    journal_path: Path | None = None


def _dcm_bits(payload: bytes, first: int, last: int) -> int:
    """Common2d9f0 differs from the generic helper for narrow cross-byte fields."""
    if first > last:
        raise ToyotaCodecError("Reversed DCM bit range", 0xC0000001)
    if last >= len(payload) * 8:
        raise ToyotaCodecError("DCM field exceeds observed bytes", 0xA0040202)
    start, end = first >> 3, last >> 3
    shift = (~last) & 7
    value = payload[end] >> shift
    for distance in range(1, end - start):
        value |= payload[end - distance] << ((8 * distance - shift) & 31)
    width = last - first
    if start == end:
        value &= (1 << (width + 1)) - 1
    else:
        high = (payload[start] << (first & 7)) & 255
        value |= high << ((width - 7) & 31) if width > 6 else high >> (7 - width)
    return value & 0xFFFFFFFF


@dataclass(frozen=True)
class DcmLog:
    """Observed Linux mapping of native CSIDL2e/Techstream/DCM and shared9 WORD."""

    directory: Path
    car_id: int
    family: str = "DCM-02"

    def __post_init__(self) -> None:
        if not isinstance(self.directory, Path):
            raise TypeError("DCM journal directory must be an explicit Path")
        if type(self.car_id) is not int or not 0 <= self.car_id <= 65535:
            raise ValueError("Observed DCM shared9 car ID must fit WORD")
        if self.family not in ("DCM-02", "BT-03"):
            raise ValueError("Journal family requires a recovered native module")

    def write(
        self, category: int, bus: int, observations: tuple[tuple[bytes, bytes], ...]
    ) -> tuple[int, Path | None]:
        # DT3700: count eligible files, remove oldest while count>=10. A failed
        # deletion still advances the cutoff; files before it are not retried.
        cutoff = (0, 0)
        target: Path | None = None
        prefix = self.family + "_"
        offset = len(prefix)
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            while True:
                candidates = []
                for path in self.directory.iterdir():
                    name = path.name
                    if (
                        not path.is_dir()
                        and name.casefold().startswith(prefix.casefold())
                        and name.casefold().endswith(".log")
                        and (self.family != "BT-03" or name.endswith(".log"))
                        and len(name) == offset + 18
                        and name[offset : offset + 14].isascii()
                        and name[offset : offset + 14].isdigit()
                    ):
                        date, clock = (
                            int(name[offset : offset + 8]),
                            int(name[offset + 8 : offset + 14]),
                        )
                        stamp = (date // 10000 + (date % 10000) * 10000, clock)
                        if stamp > cutoff:
                            candidates.append((stamp, path))
                if len(candidates) < 10:
                    break
                cutoff, oldest = min(candidates, key=lambda row: row[0])
                try:
                    oldest.unlink()
                except OSError:
                    pass
            now = datetime.now(tz=UTC).astimezone()
            target = self.directory / (prefix + now.strftime("%m%d%Y%H%M%S") + ".log")
            # Native CREATE_ALWAYS and three separate header fields. The hex
            # formatter3ed0 emits at most63 bytes; its BYTE sum is unused.
            with target.open("wb") as stream:
                stream.write(
                    (
                        f"Car ID:{self.car_id}\r\nECU ID:{category}\r\n"
                        f"BUS ID:{bus}\r\n\r\n"
                    ).encode("ascii")
                )
                for request, reply in observations:
                    stream.write(
                        b"TST:"
                        + request[:63].hex(",").upper().encode("ascii")
                        + b"\r\n"
                    )
                    stream.write(
                        b"ECU:" + reply[:63].hex(",").upper().encode("ascii") + b"\r\n"
                    )
        except OSError:
            if target is not None:
                try:
                    target.unlink()
                except OSError:
                    pass
            return 0x90040F01, None
        return 0, target


def _dcm_sort(rows: tuple[bytes, ...], offset: int) -> tuple[bytes, ...]:
    """DT4d0e/4e62 qsort: preserve equal-key swaps and the eight-row cutoff."""
    values = list(rows)
    pending = [(0, len(values) - 1)]
    while pending:
        low, high = pending.pop()
        while low < high:
            if high - low + 1 <= 8:
                while low < high:
                    largest = low
                    for index in range(low + 1, high + 1):
                        if word(values[index], offset) > word(values[largest], offset):
                            largest = index
                    values[largest], values[high] = values[high], values[largest]
                    high -= 1
                break
            middle = low + ((high - low + 1) >> 1)
            values[middle], values[low] = values[low], values[middle]
            left, right = low, high + 1
            while True:
                left += 1
                while left <= high and word(values[left], offset) <= word(
                    values[low], offset
                ):
                    left += 1
                right -= 1
                while right > low and word(values[right], offset) >= word(
                    values[low], offset
                ):
                    right -= 1
                if left > right:
                    break
                values[left], values[right] = values[right], values[left]
            values[low], values[right] = values[right], values[low]
            if (right - low) * 8 - 1 < (high - left) * 8:
                if left < high:
                    pending.append((left, high))
                high = right - 1
            else:
                if low + 1 < right:
                    pending.append((low, right - 1))
                low = left
    return tuple(values)


class DcmAnalysis:
    """Selected original12/18 DCM P4 current/fixed PID and RAM business.

    Variable journals require observed file-output inputs. Other native module
    variants remain explicit source boundaries.
    """

    def __init__(
        self,
        profile: ProtocolProfile,
        cache: MonitorSupportCache,
        *,
        journal: DcmLog | None = None,
    ):
        if not isinstance(profile, VehicleProfile):
            raise SessionError("DCM analysis requires selected Toyota metadata")
        if cache.profile is not profile or cache.identity != monitor_source_identity(
            profile, cache.ecu
        ):
            raise SessionError("DCM cache belongs to another selected context")
        version = {12: 0x0100030C, 18: 0x0100032F}.get(cache.source_build)
        if (
            version is None
            or profile.database.version != version
            or profile.catalog.management.version != version
        ):
            raise SessionError(
                "DCM Execute requires matching original12/18 selected sources"
            )
        if type(cache.bus_id) is not int or not 0 <= cache.bus_id <= 65535:
            raise SessionError("DCM requires an observed native bus")
        modules = profile.dll_records(0x78)
        if not modules:
            raise ToyotaCodecError("Selected DCM module is absent", 0xC0040101)
        names = tuple(row[:80].decode("utf-16le").split("\0", 1)[0] for row in modules)
        if len(names) != 1 or names[0] not in (
            "GetAnlWkFctDcmP4_DT.dll",
            "GetAnlWkFctDcm24_DT.dll",
            "GetAnlWkFctBTP4_DT.dll",
        ):
            raise SessionError("Selected module has no recovered DCM Execute provider")
        self.is_dcm24 = names[0] == "GetAnlWkFctDcm24_DT.dll"
        self.is_battery = names[0] == "GetAnlWkFctBTP4_DT.dll"
        if self.is_dcm24 and cache.source_build != 18:
            raise SessionError("DCM24 requires its original18 source")
        if journal is not None and not isinstance(journal, DcmLog):
            raise TypeError("DCM journal requires concrete file output")
        self.journal = journal
        self._selected_journal = journal
        self.journal_path: Path | None = None
        self.profile, self.cache = profile, cache
        self.identity, self.observed_bus = cache.identity, cache.bus_id
        self.language_sha256 = profile.catalog.language.sha256
        self.source_sha256 = (
            "d697f922c182ec4274bed1fd6939440b8cacffc21e0450cd44a6576d179702ba"
            if cache.source_build == 12
            else "75eeffb791ee55c3a334288590e4e53a796a850111bc616ee192cd39d78e1db8"
        )
        if self.is_dcm24:
            self.source_sha256 = (
                "65dee471c46438f8b097833eb9a1df90b252a5b7162fc7de473ef99b4e638b68"
            )
        if self.is_battery:
            self.source_sha256 = (
                "96d54db1e4bc176ccc9e22820d2a5c9be00fd36e17ed6b16c971bbf9d279d880"
                if cache.source_build == 12
                else "4e748d7cf69550c06aea703d3d41e468773c492cf5ddf9472588df1f6a1e4def"
            )
        self._masks: dict[int, bytes] = {}
        self._enabled: dict[int, int] = {}

    def _check(self) -> None:
        self.cache.check_context()
        if (
            self.journal != self._selected_journal
            or self.cache.profile is not self.profile
            or self.cache.identity != self.identity
            or self.cache.bus_id != self.observed_bus
            or self.profile.catalog.language.sha256 != self.language_sha256
        ):
            raise SessionError("DCM selected context changed")

    @staticmethod
    def _first(rows: tuple[bytes, ...]) -> bytes:
        if not rows:
            raise ToyotaCodecError("Selected DCM definition is absent", 0xC0040101)
        return rows[0]

    def _text(self, row: bytes, offset: int) -> str:
        reference = struct.unpack_from("<I", row, offset)[0]
        if not reference:
            return ""
        try:
            return self.profile.catalog.language.resolve(reference)
        except ValueError as error:
            raise SessionError(
                "Used native DCM text pointer cannot be resolved"
            ) from error

    def _freeze(self, logical_pid: int) -> bytes:
        return self._first(self.profile.freeze_records(logical_pid=logical_pid))

    def _pid(self, logical_pid: int, *, phase: int = 4) -> tuple[bool, int]:
        """Common2c060/2c150/2c270/2c3a0; P3 raw and P4 expanded PID reads."""
        from scripts.toyota_session import expand_supported_pid

        self._check()
        freeze = self._freeze(logical_pid)
        pid, first, last = freeze[79], word(freeze, 62), word(freeze, 64)
        positions = self._masks.get(pid)
        if phase == 3:
            if not self.cache.check_freeze_pid(freeze, self._enabled, pid_lengths={}):
                return False, 0
        elif phase == 4:
            if pid not in self._enabled:
                return False, 0
            if positions is None:
                raise ToyotaCodecError(
                    "Selected DCM PID support mask absent", 0xC0040001
                )
            if last >= len(positions) * 8 or not _rob_bits(positions, first, last):
                return False, 0
        else:
            raise ToyotaCodecError("Unsupported DCM phase", 0xC0040001)
        freeze = self._freeze(logical_pid)
        frames = self.profile.frame_records(0x6B)
        if len(frames) != 1 or len(frames[0].frame.request) < 2:
            raise ToyotaCodecError("Selected DCM PID frame geometry", 0xC0040102)
        selected = frames[0]
        request = bytearray(selected.frame.request)
        request[1] = freeze[79]
        reply = self.cache.transaction(
            selected,
            bytes(request),
            cached=False,
            temporary=True,
            native_parameter=0,
            extended=False,
            capacity=255 if phase == 4 else None,
        )
        start = len(request)
        if phase == 3:
            if len(reply) <= start:
                raise ToyotaCodecError("DCM P3 PID reply empty", 0xA0040202)
            return True, _rob_bits(reply[start:], word(freeze, 62), word(freeze, 64))
        length = (len(reply) - 2) & 255
        if start + length > len(reply):
            raise ToyotaCodecError("DCM PID reply lacks native payload", 0xA0040202)
        assert positions is not None
        payload = expand_supported_pid(reply[start : start + length], positions)
        return True, _dcm_bits(payload, word(freeze, 62), word(freeze, 64))

    def _current(self) -> tuple[RoBValue, ...]:
        phase = self.profile.category_record[72] & 31
        if phase not in (3, 4):
            raise ToyotaCodecError("Unsupported DCM current phase", 0xC0040001)
        values = []
        for signal in range(0x1E, 0x23):
            group = self._first(self.profile.signal_group_records(signal))
            pids = self.profile.signal_pids(signal)
            if not pids:
                raise ToyotaCodecError("Selected DCM current signal empty", 0xC0040101)
            logical_pid = pids[0]
            try:
                supported, raw = self._pid(logical_pid, phase=phase)
            except ToyotaCodecError:
                supported, raw = False, 0
            value, unit, physical = raw, "", b""
            if supported:
                freeze = self._freeze(logical_pid)
                physical = self._first(self.profile.physical_records(word(freeze, 60)))
                units = self.profile.unit_records(word(physical, 14))
                unit = self._text(units[0], 0) if units else ""
                multiplier, divisor, offset = struct.unpack_from("<iiI", physical)
                if divisor:
                    product = multiplier * raw
                    quotient = abs(product) // abs(divisor)
                    if (product < 0) != (divisor < 0):
                        quotient = -quotient
                    value = (quotient + offset) & 0xFFFFFFFF
            values.append(
                RoBValue(
                    self._text(group, 0),
                    value,
                    unit,
                    4 if supported else 0x4004,
                    group,
                    physical,
                )
            )
        return tuple(values)

    def _decode(
        self,
        definition: bytes,
        capture: DcmRamCapture,
        *,
        variable: bool = False,
        pid: int = 0x61,
    ) -> DcmGroup:
        phase = self.profile.category_record[72] & 31
        if phase not in (3, 4):
            raise ToyotaCodecError("Unsupported DCM phase", 0xC0040001)
        observations = capture.words
        marker = next(
            (
                i
                for i, (_, data) in enumerate(observations)
                if data and all(value == 255 for value in data)
            ),
            0,
        )
        rows = []
        for index in (
            *range(marker - 1, -1, -1),
            *range(len(observations) - 1, marker, -1),
        ):
            address, payload = observations[index]
            if payload and (
                all(value == 0 for value in payload)
                or all(value == 255 for value in payload)
            ):
                continue
            definitions = self.profile.work_factor_item_records(word(definition, 4))
            if not definitions:
                raise ToyotaCodecError("Selected DCM items absent", 0xC0040101)
            items = []
            for item in definitions:
                if variable and word(item, 24) >= len(payload) * 8:
                    raise ToyotaCodecError("Variable DCM item exceeds data", 0xC0040001)
                raw = _dcm_bits(payload, word(item, 22), word(item, 24))
                multiplier, divisor, offset = struct.unpack_from("<III", item)
                value = (multiplier * raw) & 0xFFFFFFFF
                if divisor:
                    value //= divisor
                value = (value + offset) & 0xFFFFFFFF
                patterns = self.profile.work_factor_records(
                    37, word(item, 30), value & 65535
                )
                content = self._text(patterns[0], 0) if patterns else ""
                display = 0
                if variable:
                    display = word(definition, 22)
                    if not item[36] or (word(item, 30) and not patterns):
                        display |= 0x8000
                items.append(
                    DcmValue(
                        self._text(item, 12),
                        value,
                        content,
                        self._text(item, 16),
                        display,
                        item,
                    )
                )
            rows.append(DcmRecord(address, tuple(items), payload))
        return DcmGroup(
            pid,
            self._text(definition, 0),
            tuple(rows),
            word(definition, 22) if variable else 0,
            definition,
            capture,
        )

    def run(self, mode: int = 2) -> DcmAnalysisResult:
        """Native send DWORD mode (API input0/1/2 selects2/1/4 respectively)."""
        if type(mode) is not int or not 0 <= mode <= 0xFFFFFFFF:
            raise ToyotaCodecError("Invalid DCM native mode", 0xC0040001)
        self._check()
        variable = bool(mode & 4)
        if variable and self.journal is None:
            raise SessionError(
                "DCM variable-record Execute requires observed journal mapping"
            )
        if variable and self.journal is not None:
            expected_family = "BT-03" if self.is_battery else "DCM-02"
            if self.journal.family != expected_family:
                raise SessionError(
                    "Journal mapping differs from selected native module"
                )
        self.journal_path = None
        current: tuple[RoBValue, ...] = ()
        groups: list[DcmGroup] = []
        status = 0
        with self.cache.temporary_scope():
            self._masks = self.cache.support_bits(1)
            self._enabled = self.cache.enabled_pids(family="p4")
            if mode & 1 or variable:
                try:
                    current = self._current()
                except ToyotaCodecError as error:
                    if error.code != 0xC0050414:
                        raise
                    if not variable:
                        return self._result(mode, (), current, 0)
            if mode & 2 or variable:
                definitions = self.profile.work_factor_signal_records()
                if not definitions:
                    raise ToyotaCodecError("Selected DCM signals absent", 0xC0040101)
                captures = []
                pid_acquired, valid_count = False, False
                if variable:
                    definitions = _dcm_sort(definitions, 18)
                for definition in definitions:
                    freeze = self._freeze(word(definition, 14))
                    if not variable and freeze[79] != 0x61:
                        continue
                    raw_values = []
                    try:
                        for offset in (8, 10, 12, 14):
                            supported, value = self._pid(word(definition, offset))
                            if not supported:
                                break
                            raw_values.append(value)
                    except ToyotaCodecError as error:
                        status = error.code
                        continue
                    if len(raw_values) != 4:
                        continue
                    pid_acquired = True
                    valid_count |= definition[24] == 1 and bool(raw_values[1] & 255)
                    raw_frame = (
                        bytes(value & 255 for value in raw_values[:3])
                        + b"\0"
                        + struct.pack("<I", raw_values[3])
                    )
                    if variable:
                        width = word(freeze, 64) - word(freeze, 62) + 1
                        address_bytes = (abs(width) // 8) * (-1 if width < 0 else 1)
                        raw_frame = (
                            raw_frame[:3]
                            + bytes((address_bytes & 255,))
                            + raw_frame[4:]
                        )
                    try:
                        capture = (
                            read_dcm_variable_ram(self.cache, raw_frame, definition[25])
                            if variable
                            else read_dcm_ram(self.cache, raw_frame)
                        )
                    except ToyotaCodecError as error:
                        capture = DcmRamCapture(
                            error.code,
                            (),
                            (),
                            raw_frame,
                            self.cache.source_build,
                            COMMON12_SHA256
                            if self.cache.source_build == 12
                            else COMMON18_SHA256,
                            self.identity,
                            self.observed_bus,
                        )
                    captures.append((definition, capture))
                    if capture.native_status:
                        status = capture.native_status
                if variable and self.is_dcm24 and pid_acquired and not valid_count:
                    return self._result(mode, (), current, 0)
                if (variable and self.is_dcm24 and pid_acquired) or any(
                    capture.native_status == 0 for _, capture in captures
                ):
                    status = 0
                    if variable:
                        captures.sort(key=lambda row: word(row[0], 20))
                    groups = [
                        self._decode(
                            definition,
                            capture,
                            variable=variable,
                            pid=self._freeze(word(definition, 14))[79]
                            if variable
                            else 0x61,
                        )
                        for definition, capture in captures
                        if not variable or definition[24]
                    ]
                    if variable and groups:
                        self._check()
                        assert self.journal is not None
                        status, self.journal_path = self.journal.write(
                            self.profile.category,
                            self.observed_bus,
                            self.cache.temporary_observations(),
                        )
                        self._check()
        return self._result(mode, tuple(groups), current, status)

    def _result(
        self,
        mode: int,
        groups: tuple[DcmGroup, ...],
        current: tuple[RoBValue, ...],
        status: int,
    ) -> DcmAnalysisResult:
        self._check()
        return DcmAnalysisResult(
            status,
            self.source_sha256,
            COMMON12_SHA256 if self.cache.source_build == 12 else COMMON18_SHA256,
            self.identity,
            groups,
            current,
            self.cache.source_build,
            self.language_sha256,
            self.observed_bus,
            mode,
            self.journal_path,
        )


@dataclass(frozen=True)
class PlainWorkFactorItem:
    address: int
    opcode: int
    content: str
    name: str
    value: int
    unit: str
    format: int
    definition: bytes


@dataclass(frozen=True)
class PlainWorkFactorGroup:
    identifier: int
    display_type: int
    pid: int
    name: str
    items: tuple[PlainWorkFactorItem, ...]
    definition: bytes
    capture: DcmRamCapture


@dataclass(frozen=True)
class PlainFreezeData:
    """Owned CCmdFrzFrmDat fields; rendered values belong to CommandAPI."""

    pid: int = 0
    name: str = ""
    short_name: str = ""
    unit: str = ""
    selector: int = 0
    precision: int = 0
    multiplier: int = 0
    divisor: int = 0
    offset: int = 0
    unit_id: int = 0
    sign_mode: int = 0
    width: int = 0
    patterns: tuple[tuple[int, str, int, int, int], ...] = ()
    threshold: int = 0
    threshold_high: int = 0
    minimum_raw: int = 0
    maximum_raw: int = 0
    values: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True)
class PlainTimestamp:
    dword00: int = 0
    dword04: int = 0
    auxiliary: tuple[int, int] = (0, 0)
    dword148: int = 0
    freezes: tuple[PlainFreezeData, PlainFreezeData, PlainFreezeData] = (
        PlainFreezeData(),
        PlainFreezeData(),
        PlainFreezeData(),
    )


@dataclass(frozen=True)
class PlainTSItem:
    address: int
    opcode: int
    content: str
    name: str
    unit: str
    format: int
    timestamp: PlainTimestamp


@dataclass(frozen=True)
class PlainTSGroup:
    identifier: int
    display_type: int
    pid: int
    name: str
    items: tuple[PlainTSItem, ...]
    definition: bytes
    capture: DcmRamCapture


@dataclass(frozen=True)
class PlainAnalysisResult:
    native_status: int
    source_sha256: str
    common_sha256: str
    selected_identity: tuple[object, ...]
    groups: tuple[PlainWorkFactorGroup, ...]
    current: tuple[RoBValue, ...]
    calendar: tuple[int, ...]
    coefficient: int
    source_build: int
    language_sha256: str
    observed_bus: int
    ts_groups: tuple[PlainTSGroup, ...] = ()
    current_timestamp: PlainTimestamp = PlainTimestamp()


class PlainAnalysis:
    """Original normal6F P3/P4 Execute; TS/PSC remain guarded."""

    def __init__(
        self,
        profile: ProtocolProfile,
        cache: MonitorSupportCache,
        *,
        ansi_encoding: str | None = None,
    ):
        if not isinstance(profile, VehicleProfile):
            raise SessionError("Plain analysis requires selected Toyota metadata")
        if cache.profile is not profile or cache.identity != monitor_source_identity(
            profile, cache.ecu
        ):
            raise SessionError("Plain analysis cache belongs to another context")
        version = {12: 0x0100030C, 18: 0x0100032F}.get(cache.source_build)
        if (
            version is None
            or profile.database.version != version
            or profile.catalog.management.version != version
        ):
            raise SessionError("Plain analysis requires matching original12/18 sources")
        modules = profile.dll_records(0x6F)
        if not modules:
            raise ToyotaCodecError("Selected plain module absent", 0xC0040101)
        names = tuple(row[:80].decode("utf-16le").split("\0", 1)[0] for row in modules)
        if len(names) != 1 or names[0] not in (
            "GetAnlzWrkFctP3_DT.dll",
            "GetAnlzWrkFctP4_DT.dll",
            "GetAnlWkFctP4PSC_DT.dll",
        ):
            raise SessionError(
                "Selected plain module has no recovered Execute provider"
            )
        self.is_p4 = names[0] == "GetAnlzWrkFctP4_DT.dll"
        self.is_psc = names[0] == "GetAnlWkFctP4PSC_DT.dll"
        self.phase = profile.category_record[72] & 31
        if self.phase not in ((3, 4) if self.is_p4 or self.is_psc else (3,)):
            raise SessionError(
                "Plain provider requires matching selected phase metadata"
            )
        if ansi_encoding is not None:
            ansi_encoding = codecs.lookup(ansi_encoding).name
            if "0123456789".encode(ansi_encoding) != b"0123456789":
                raise SessionError(
                    "Observed native ANSI encoding must preserve ASCII digits"
                )
        self.ansi_encoding = ansi_encoding
        if type(cache.bus_id) is not int or not 0 <= cache.bus_id <= 65535:
            raise SessionError("Plain analysis requires observed bus")
        self.profile, self.cache = profile, cache
        self.identity, self.bus = cache.identity, cache.bus_id
        self.language_sha256 = profile.catalog.language.sha256
        self.source_sha256 = (
            "1e8424cef67f9566ce9128f6d2a571429b2394ac288fe8b168375253e4886e15"
            if cache.source_build == 12
            else "10dc84495bca356be967e7c055734bc9f5b31d5e3ea64ebea996d85d3f42473f"
        )
        self._enabled: dict[int, int] = {}
        self._masks: dict[int, bytes] = {}
        if self.is_p4:
            self.source_sha256 = (
                "6acb323475cf41520d4d05ff48484fccd6e4ebb4c95691927e583143fdea0f7f"
                if cache.source_build == 12
                else "2e6669768703dd2e3a1d29fb516f76db5324d3ac0c7ea6a292d610b9a672ad2e"
            )
        if self.is_psc:
            self.source_sha256 = (
                "8887ae4549e49df00a199162272c5a5036f58752af12470aa19a15212bcf2fec"
                if cache.source_build == 12
                else "053f22b16e5feb7d7dd3b55ad6fdd12e545a0562cc87bf6cb9b7694c5229fd06"
            )
        self._source_context = (
            self.is_p4,
            self.is_psc,
            self.phase,
            self.source_sha256,
            cache.source_build,
            ansi_encoding,
        )
        self._values: list[RoBValue] = []
        self._calendar: tuple[int, ...] = (0,) * 6
        self._coefficient = self._logical = self._modulus = self._wraps = 0
        self._conversion_valid = False

    def _check(self) -> None:
        self.cache.check_context()
        if (
            (
                self.is_p4,
                self.is_psc,
                self.phase,
                self.source_sha256,
                self.cache.source_build,
                self.ansi_encoding,
            )
            != self._source_context
            or self.cache.profile is not self.profile
            or self.cache.identity != self.identity
            or self.cache.bus_id != self.bus
            or self.profile.catalog.language.sha256 != self.language_sha256
        ):
            raise SessionError("Plain selected context changed")

    @staticmethod
    def _first(rows: tuple[bytes, ...]) -> bytes:
        if not rows:
            raise ToyotaCodecError("Selected plain definition absent", 0xC0040101)
        return rows[0]

    def _text(self, row: bytes, offset: int) -> str:
        reference = struct.unpack_from("<I", row, offset)[0]
        if not reference:
            return ""
        try:
            return self.profile.catalog.language.resolve(reference)
        except ValueError:
            # CCmdString::operator=(NULL) empties the string. Eager query status
            # validation still runs in the source-derived selected query.
            return ""

    def _freeze(self, logical: int) -> bytes:
        return self._first(self.profile.freeze_records(logical_pid=logical))

    def _pid(self, logical: int, *, phase: int | None = None) -> tuple[bool, int]:
        from scripts.toyota_session import expand_supported_pid

        self._check()
        phase = self.phase if phase is None else phase
        freeze = self._freeze(logical)
        positions = self._masks.get(freeze[79])
        if phase == 4:
            if freeze[79] not in self._enabled:
                return False, 0
            if positions is None:
                raise ToyotaCodecError("PlainP4 support mask absent", 0xC0040001)
            if word(freeze, 64) >= len(positions) * 8 or not _rob_bits(
                positions, word(freeze, 62), word(freeze, 64)
            ):
                return False, 0
        elif not self.cache.check_freeze_pid(freeze, self._enabled, pid_lengths={}):
            return False, 0
        freeze = self._freeze(logical)
        frames = self.profile.frame_records(0x6B)
        if len(frames) != 1 or len(frames[0].frame.request) < 2:
            raise ToyotaCodecError("Plain PID frame geometry", 0xC0040102)
        selected = frames[0]
        request = bytearray(selected.frame.request)
        request[1] = freeze[79]
        reply = self.cache.transaction(
            selected,
            bytes(request),
            cached=False,
            temporary=True,
            native_parameter=0,
            extended=False,
            capacity=255 if phase == 4 else None,
        )
        payload = reply[len(request) :]
        if phase == 4:
            length = (len(reply) - 2) & 255
            if len(payload) < length:
                raise ToyotaCodecError("PlainP4 PID lacks native payload", 0xA0040202)
            assert positions is not None
            payload = expand_supported_pid(payload[:length], positions)
        return True, _rob_bits(payload, word(freeze, 62), word(freeze, 64))

    @staticmethod
    def _scale(coefficient: int, raw: int, divisor: int) -> int:
        value = coefficient * raw & 0xFFFFFFFFFFFFFFFF
        if value & (1 << 63):
            value -= 1 << 64
        divisor = divisor or 1
        magnitude = abs(value) // abs(divisor)
        return (-magnitude if (value < 0) != (divisor < 0) else magnitude) & 0xFFFFFFFF

    def _current_value(self, signal: int) -> RoBValue:
        try:
            groups = self.profile.signal_group_records(signal)
        except ToyotaCodecError:
            if not self.is_p4:
                raise
            return RoBValue()
        if self.is_p4 and not groups:
            return RoBValue()
        group = self._first(groups)
        pids = self.profile.signal_pids(signal)
        if not pids:
            raise ToyotaCodecError("Plain signal PID absent", 0xC0040101)
        logical = pids[0]
        value, unit, fmt, physical = 0, "", 0x4000, b""
        try:
            supported, value = self._pid(logical)
        except ToyotaCodecError:
            supported = False
        if supported:
            physical = self._first(
                self.profile.physical_records(word(self._freeze(logical), 60))
            )
            units = self.profile.unit_records(word(physical, 14))
            unit = self._text(units[0], 0) if units else ""
            fmt = 0
        if signal == 0x1A:
            self._conversion_valid = False
            try:
                self._first(self.profile.signal_group_records(0x18))
                coefficients = self.profile.signal_pids(0x18)
                if not coefficients:
                    raise ToyotaCodecError("Plain coefficient absent", 0xC0040101)
                coefficient_logical = coefficients[0]
                enabled, coefficient = self._pid(coefficient_logical)
                if not enabled:
                    raise ToyotaCodecError("Plain coefficient unsupported", 0xC0050414)
                self._coefficient, self._logical = (
                    coefficient & 255,
                    coefficient_logical,
                )
                coefficient_physical = self._first(
                    self.profile.physical_records(
                        word(self._freeze(coefficient_logical), 60)
                    )
                )
                multiplier, divisor = struct.unpack_from("<Ii", coefficient_physical)
                converted = self._scale(
                    coefficient * multiplier & 0xFFFFFFFF, value, divisor
                )
            except ToyotaCodecError:
                fmt |= 0x4000
            else:
                self._conversion_valid = True
                freeze = self._freeze(logical)
                self._modulus = (
                    (1 << ((word(freeze, 64) - word(freeze, 62) + 1) & 31))
                    * self._coefficient
                ) & 0xFFFFFFFF
                value = converted
            fmt |= 4
        return RoBValue(self._text(group, 0), value, unit, fmt, group, physical)

    def _item(
        self, definition: bytes, address: int, payload: bytes, content: str
    ) -> PlainWorkFactorItem:
        value = _rob_bits(payload, word(definition, 22), word(definition, 24))
        fmt = 0
        if word(definition, 28):
            if not self._conversion_valid:
                fmt = 0x4000
            elif word(definition, 28) != self._logical:
                raise ToyotaCodecError(
                    "Plain history conversion logical differs", 0xC0050102
                )
            else:
                multiplier, divisor = struct.unpack_from("<Ii", definition)
                value = self._scale(
                    self._coefficient * multiplier & 0xFFFFFFFF, value, divisor
                )
        return PlainWorkFactorItem(
            address,
            payload[0],
            content,
            self._text(definition, 12),
            value,
            self._text(definition, 16),
            fmt,
            definition,
        )

    def _history(
        self, definition: bytes, capture: DcmRamCapture, *, adjust: bool = False
    ) -> tuple[PlainWorkFactorItem, ...]:
        marker = next(
            (
                i
                for i, (_, payload) in enumerate(capture.words)
                if payload[:4] == b"\xff" * 4
            ),
            0,
        )
        flat: list[PlainWorkFactorItem] = []
        for index in (*range(marker + 1, len(capture.words)), *range(marker)):
            self._check()
            address, payload = capture.words[index]
            if payload[:4] == b"\xff" * 4:
                continue
            if adjust and payload[4:8] == b"\x01\0\0\0":
                default = PlainWorkFactorItem(0, 0, "", "", 0, "", 0x2000, b"")
                flat.extend((default, default, default))
                continue
            items = self.profile.work_factor_item_records(word(definition, 4))
            self._first(items)
            content_definition = next((row for row in items if row[34] == 1), None)
            reset_definition = next((row for row in items if row[34] == 4), None)
            if content_definition is None or (
                reset_definition is None and not self.is_p4
            ):
                raise ToyotaCodecError(
                    "Plain content/reset definition absent", 0xC0040102
                )
            patterns = self.profile.work_factor_records(
                37, word(content_definition, 30), payload[0]
            )
            pattern = patterns[0] if patterns else None
            name = self._text(pattern, 0) if pattern else ""
            help_text = self._text(pattern, 4) if pattern else ""
            pattern_format = 0 if pattern else 0x8000
            display_type = word(pattern, 12) if pattern else 1
            selected: dict[int, PlainWorkFactorItem] = {}
            for item in items:
                if item[34] in (2, 3):
                    row = self._item(
                        item, address, payload, name if item[34] == 2 else help_text
                    )
                    row = replace(row, format=row.format | pattern_format)
                    if self.is_p4 and not adjust:
                        selected[item[34]] = row
                    else:
                        flat.append(row)
            if self.is_p4 and not adjust:
                for kind, content in ((2, name), (3, help_text)):
                    default = PlainWorkFactorItem(
                        address, payload[0], content, "", 0, "", 0x4000, b""
                    )
                    flat.append(selected.get(kind, default))
            row = (
                self._item(reset_definition, address, payload, str(display_type))
                if reset_definition is not None
                else PlainWorkFactorItem(
                    address, payload[0], str(display_type), "", 0, "", 0x4000, b""
                )
            )
            flat.append(replace(row, format=row.format | pattern_format))
        if len(flat) % 3:
            raise SessionError("Selected native plain rows do not form timing triples")
        triples = [tuple(flat[index : index + 3]) for index in range(0, len(flat), 3)]
        happened: list[tuple[PlainWorkFactorItem, ...]] = []
        passed: list[tuple[PlainWorkFactorItem, ...]] = []
        passed_count = len(triples)
        if self._values[2].format & 0x4000 == 0:
            passed_count = 0
            previous = elapsed = wraps = 0
            seen_valid = False
            for index in reversed(range(len(triples))):
                first, time_row, reset = triples[index]
                if adjust and first.format & 0x2000:
                    happened.append((first, time_row, reset))
                    continue
                if reset.value != self._values[2].value:
                    passed_count = index + 1
                    break
                if not time_row.format & 0x4000:
                    if index == len(triples) - 1 or (adjust and not seen_valid):
                        previous = self._values[1].value
                        elapsed = 0
                    if previous < time_row.value:
                        delta = self._modulus - time_row.value + previous
                        wraps += 1
                    else:
                        delta = previous - time_row.value
                    elapsed = (elapsed + delta) & 0xFFFFFFFF
                    previous = time_row.value
                    time_row = replace(time_row, value=elapsed)
                    self._wraps = max(self._wraps, wraps)
                    seen_valid = True
                happened.append(
                    (first, replace(time_row, format=time_row.format | 1), reset)
                )
        previous = generation = elapsed = 0
        for index in range(passed_count):
            first, time_row, reset = triples[index]
            if adjust and first.format & 0x2000:
                passed.append((first, time_row, reset))
                continue
            if not time_row.format & 0x4000:
                delta = time_row.value
                if index == 0 or generation != reset.value:
                    elapsed = 0
                else:
                    delta = (
                        time_row.value - previous
                        if time_row.value >= previous
                        else self._modulus - previous + time_row.value
                    )
                elapsed = (elapsed + delta) & 0xFFFFFFFF
                previous, generation = time_row.value, reset.value
                time_row = replace(time_row, value=elapsed)
            passed.append((first, replace(time_row, format=time_row.format | 2), reset))
        merged = tuple(
            row for triple in (*happened, *reversed(passed)) for row in triple
        )
        return self._adjust_items(merged) if adjust else merged

    def _adjust_items(
        self, items: tuple[PlainWorkFactorItem, ...]
    ) -> tuple[PlainWorkFactorItem, ...]:
        """Common32180: five-record blocks, native flags and narrow text edit."""
        output: list[PlainWorkFactorItem] = []
        for start in range(0, len(items) - 14, 15):
            block = [
                replace(row, format=row.format | 0x8000)
                for row in items[start + 9 : start + 12]
            ]
            block.extend(items[start + 12 : start + 15])
            block.extend(items[start : start + 9])
            if 0xDF < block[3].opcode < 0xF0:
                try:
                    raw = block[3].content.encode(self.ansi_encoding or "ascii")
                except UnicodeEncodeError as error:
                    raise SessionError(
                        "Plain Adjust requires observed native ANSI encoding"
                    ) from error
                if len(raw) > 255 or b"\0" in raw:
                    raise SessionError("Plain Adjust input exceeds native text buffer")
                changed = re.sub(
                    r"[0-9]+", str(block[0].opcode * 10), block[3].content
                ).encode(self.ansi_encoding or "ascii")[:254]
                try:
                    content = changed.decode(self.ansi_encoding or "ascii")
                except UnicodeDecodeError as error:
                    raise SessionError(
                        "Native Adjust truncation splits an ANSI character"
                    ) from error
                block[3] = replace(block[3], content=content)
            output.extend(block)
        return tuple(output)

    def _freeze_data(self, logical: int, raw: int) -> PlainFreezeData:
        from scripts.signal_lsb import SignalLSB

        lsb = SignalLSB(
            self.cache, source_build=12 if self.cache.source_build == 12 else 18
        )
        freeze = self._freeze(logical)
        physical = self._first(self.profile.physical_records(word(freeze, 60)))
        unit = self._first(self.profile.unit_records(word(physical, 14)))
        pattern_id = word(freeze, 70)
        patterns = self.profile.pattern_records(pattern_id)
        if pattern_id and not patterns:
            raise ToyotaCodecError("Plain timestamp pattern absent", 0xC0040101)
        width = (word(freeze, 64) - word(freeze, 62) + 1) & 65535
        multiplier, divisor, offset = struct.unpack_from("<III", physical)
        threshold, threshold_high = struct.unpack_from("<II", freeze, 32)
        multiplier, divisor, threshold = lsb.p4(
            logical,
            exponent=physical[21],
            width=width,
            multiplier=multiplier,
            divisor=divisor,
            threshold=threshold,
        ).values
        short_name = freeze[:24].split(b"\0", 1)[0]
        try:
            short_text = short_name.decode(self.ansi_encoding or "ascii")
        except UnicodeDecodeError as error:
            raise SessionError(
                "Timestamp short name requires observed ANSI encoding"
            ) from error
        return PlainFreezeData(
            logical,
            self._text(freeze, 48),
            short_text,
            self._text(unit, 0),
            freeze[76],
            physical[21],
            multiplier,
            divisor,
            offset,
            word(unit, 6),
            physical[20],
            width,
            tuple(
                (
                    pattern_id,
                    self._text(row, 0),
                    word(row, 10)
                    if self.cache.source_build == 12
                    else int.from_bytes(row[4:8], "little"),
                    0,
                    0,
                )
                for row in patterns
            ),
            threshold,
            threshold_high,
            int.from_bytes(freeze[24:28], "little"),
            int.from_bytes(freeze[28:32], "little"),
            ((raw, 0),),
        )

    def _current_timestamp(self) -> PlainTimestamp:
        acquired: list[PlainFreezeData] = []
        for signal in (0x1C, 0x1D):
            try:
                group = self._first(self.profile.signal_group_records(signal))
                check = self._first(self.profile.signal_check_records(word(group, 4)))
                logical = word(check, 2)
                supported, raw = self._pid(logical)
                if not supported:
                    return PlainTimestamp()
                freeze = self._freeze_data(logical, raw)
                if raw == 0xFFFFFFFF >> ((32 - freeze.width) & 31):
                    return PlainTimestamp()
                acquired.append(freeze)
            except ToyotaCodecError:
                return PlainTimestamp()
        return PlainTimestamp(
            1, 0, (1, 0), 0, (acquired[0], acquired[1], PlainFreezeData())
        )

    def _history_timestamp(
        self, definition: bytes, capture: DcmRamCapture
    ) -> tuple[PlainTSItem, ...]:
        marker = next(
            (
                index
                for index, (_, data) in enumerate(capture.words)
                if data and all(byte == 255 for byte in data)
            ),
            0,
        )
        result: list[PlainTSItem] = []
        for index in (*range(marker + 1, len(capture.words)), *range(marker)):
            self._check()
            address, payload = capture.words[index]
            if payload and all(byte == 255 for byte in payload):
                continue
            if not payload:
                raise SessionError("Native timestamp opcode is outside empty record")
            items = self.profile.work_factor_item_records(word(definition, 4))
            self._first(items)
            content = next((item for item in items if item[34] == 1), None)
            if content is None:
                raise ToyotaCodecError(
                    "Plain timestamp content definition absent", 0xC0040102
                )
            patterns = self.profile.work_factor_records(
                37, word(content, 30), payload[0]
            )
            pattern = patterns[0] if patterns else None
            flags = 8 | (0 if pattern else 0x8000)
            freezes: list[PlainFreezeData] = []
            for kind in (2, 0x18):
                item = next((item for item in items if item[34] == kind), None)
                if item is None:
                    flags |= 0x4000
                    freezes.append(PlainFreezeData())
                    continue
                try:
                    raw = _rob_bits(payload, word(item, 22), word(item, 24))
                except ToyotaCodecError:
                    flags |= 0x4000
                    freezes.append(PlainFreezeData())
                    continue
                multiplier, divisor = struct.unpack_from("<II", item)
                if kind == 2:
                    multiplier, divisor = 1, 1
                else:
                    divisor = divisor * 10 & 0xFFFFFFFF
                freezes.append(
                    PlainFreezeData(
                        unit=self._text(item, 16),
                        multiplier=multiplier,
                        divisor=divisor,
                        values=((raw, 0),),
                    )
                )
            first, second = freezes
            timestamp = PlainTimestamp(
                int(bool(first.values)),
                0,
                (int(bool(second.values)), 0),
                0,
                (first, second, PlainFreezeData()),
            )
            result.append(
                PlainTSItem(
                    address,
                    payload[0],
                    self._text(pattern, 0) if pattern else "",
                    self._text(pattern, 4) if pattern else "",
                    str(word(pattern, 12) if pattern else 1),
                    flags,
                    timestamp,
                )
            )
        return tuple(result)

    def run(self) -> PlainAnalysisResult:
        self._check()
        self._values, self._calendar = [], (0,) * 6
        self._coefficient = self._logical = self._modulus = self._wraps = 0
        self._conversion_valid = False
        groups: list[PlainWorkFactorGroup] = []
        self._ts_groups: list[PlainTSGroup] = []
        self._timestamp = PlainTimestamp()
        status = 0
        with self.cache.temporary_scope():
            try:
                definitions = None
                if self.is_p4 or self.is_psc:
                    self._masks = self.cache.support_bits(1)
                self._enabled = self.cache.enabled_pids(
                    family="p4" if self.is_p4 or self.is_psc else "normal",
                    kind=1,
                    control=0,
                )
                if self.is_p4:
                    definitions = self.profile.work_factor_signal_records()
                    self._first(definitions)
                if (
                    self.is_p4
                    and definitions
                    and any(word(row, 22) == 4 for row in definitions)
                ):
                    self._timestamp = self._current_timestamp()
                ordinary = not self.is_p4 or bool(
                    definitions
                    and any(word(row, 22) in (0, 3, 99) for row in definitions)
                )
                if ordinary:
                    for signal in (0x19, 0x1A, 0x1B):
                        try:
                            self._values.append(self._current_value(signal))
                        except ToyotaCodecError as error:
                            if error.code != 0xC0050414:
                                raise
                            return self._result(0, groups)
                        if signal == 0x1A:
                            now = datetime.now(tz=UTC).astimezone()
                            self._calendar = (
                                now.year,
                                now.month,
                                now.day,
                                now.hour,
                                now.minute,
                                now.second,
                            )
                definitions = (
                    self.profile.work_factor_signal_records()
                    if definitions is None
                    else definitions
                )
                self._first(definitions)
                captured: list[tuple[bytes, DcmRamCapture]] = []
                ts_captured: list[tuple[bytes, DcmRamCapture]] = []
                any_success = False
                for definition in definitions:
                    freeze = self._freeze(word(definition, 14))
                    adjust = (self.is_p4 and word(definition, 22) == 99) or (
                        self.is_psc and freeze[79] == 0x29
                    )
                    values = []
                    for offset in (8, 10, 12, 14):
                        try:
                            supported, value = self._pid(
                                word(definition, offset),
                                phase=4 if self.is_p4 or self.is_psc else 3,
                            )
                        except ToyotaCodecError as error:
                            status = error.code
                            break
                        if not supported:
                            break
                        values.append(value)
                    if len(values) != 4:
                        continue
                    raw = (
                        bytes(value & 255 for value in values[:3])
                        + b"\0"
                        + struct.pack("<I", values[3])
                    )
                    if self.is_p4 and (
                        word(definition, 22) not in (0, 3, 4, 99)
                        or (word(definition, 22) != 4 and definition[25] not in (0, 4))
                    ):
                        continue
                    timestamp_record = self.is_p4 and word(definition, 22) == 4
                    try:
                        capture = (
                            read_dcm_ram(
                                self.cache, raw, record_length=definition[25] or 4
                            )
                            if timestamp_record
                            else read_dcm_ram(self.cache, raw)
                            if self.is_p4 or self.is_psc
                            else read_plain_p3_ram(self.cache, raw)
                        )
                    except ToyotaCodecError as error:
                        capture = DcmRamCapture(
                            error.code,
                            (),
                            (),
                            raw,
                            self.cache.source_build,
                            COMMON12_SHA256
                            if self.cache.source_build == 12
                            else COMMON18_SHA256,
                            self.identity,
                            self.bus,
                        )
                    if (self.is_p4 or self.is_psc) and not timestamp_record:
                        if adjust and (capture.words or capture.failures):
                            successful = dict(capture.words)
                            stride = 2 if raw[0] == 0 else 4
                            first_address = int.from_bytes(raw[4:], "little")
                            addresses = tuple(
                                (first_address + index * stride) & 0xFFFFFFFF
                                for index in range(raw[1] + 1)
                            )
                            words = tuple(
                                (
                                    address,
                                    successful[address] + bytes(4)
                                    if address in successful
                                    else bytes(4) + b"\x01\0\0\0",
                                )
                                for address in addresses
                            )
                        else:
                            words = tuple(
                                (address, payload + bytes(4))
                                for address, payload in capture.words
                            )
                        capture = replace(capture, words=words)
                    if capture.native_status:
                        status = capture.native_status
                    else:
                        any_success = True
                    (ts_captured if timestamp_record else captured).append(
                        (definition, capture)
                    )
                if any_success:
                    if self.is_p4:
                        captured.sort(key=lambda entry: word(entry[0], 22) == 99)
                    for definition, capture in captured:
                        items = self._history(
                            definition,
                            capture,
                            adjust=(self.is_p4 and word(definition, 22) == 99)
                            or (
                                self.is_psc
                                and self._freeze(word(definition, 14))[79] == 0x29
                            ),
                        )
                        freeze = self._freeze(word(definition, 14))
                        groups.append(
                            PlainWorkFactorGroup(
                                word(definition, 6),
                                word(definition, 22) or 3,
                                freeze[79],
                                self._text(definition, 0),
                                items,
                                definition,
                                capture,
                            )
                        )
                    for definition, capture in ts_captured:
                        freeze = self._freeze(word(definition, 14))
                        self._ts_groups.append(
                            PlainTSGroup(
                                word(definition, 6),
                                word(definition, 22),
                                freeze[79],
                                self._text(definition, 0),
                                self._history_timestamp(definition, capture),
                                definition,
                                capture,
                            )
                        )
                    if len(self._values) >= 3:
                        self._values[1] = replace(
                            self._values[1],
                            value=(self._values[1].value + self._wraps * self._modulus)
                            & 0xFFFFFFFF,
                        )
                    status = 0
            except ToyotaCodecError as error:
                status = error.code
            self._check()
        return self._result(status, groups)

    def _result(
        self, status: int, groups: list[PlainWorkFactorGroup]
    ) -> PlainAnalysisResult:
        self._check()
        return PlainAnalysisResult(
            status,
            self.source_sha256,
            COMMON12_SHA256 if self.cache.source_build == 12 else COMMON18_SHA256,
            self.identity,
            tuple(groups),
            tuple(self._values),
            self._calendar,
            self._coefficient,
            self.cache.source_build,
            self.language_sha256,
            self.bus,
            tuple(self._ts_groups),
            self._timestamp,
        )
