"""Selected Common12/18 P5 freeze metadata and observable native state.

No transport or diagnostic outcome is synthesized here. Observations are actual
CCmdDataIdData payloads; the concrete support cache supplies only primitive I/O.
"""

from __future__ import annotations

from collections import deque
from copy import deepcopy
from dataclasses import dataclass, field, replace
from typing import Literal

from scripts.monitor_support import MonitorSupportCache, monitor_source_identity
from scripts.profiles import VehicleProfile
from scripts.signal_display import render_signal
from scripts.signal_lsb import SignalLSB
from scripts.support import word
from scripts.toyota import ToyotaCodecError
from scripts.toyota_session import (
    SessionError,
    _profile_frames,
    absolute_time_values,
    compare_timestamp,
    dtc_metadata_p5_profile,
    ffd_existence_flag,
    ffd_type,
)

SOURCE_SHA256 = {
    12: "d2542b8bf82347080ed73f84285a8d14d0c592fb9713abfc50448725b414a126",
    18: "07547a9e47378d37c3ef7d96c2f33f6c62c4151626d98d3f3ff03b7c74909de7",
}
FFD_GROUPS = ((1, 0x10, 0x30), (2, 0x50)) + tuple(
    (0x101 + index, 0x210 + index * 16) for index in range(14)
)
MAX_ITEMS = 65535
MAX_CAPTURE_BYTES = 16 * 1024 * 1024
SNAPSHOT_TOLERATED = frozenset(
    (
        0x91010009,
        0x90020321,
        0x90020323,
        0xA0040201,
        0xC0040001,
        0xA0040202,
        0x90020327,
        0x91020320,
        0x91020310,
        0x91020322,
    )
)


def _uint(value: int, maximum: int, label: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"Native {label} outside unsigned bounds")
    return value


def _dword(row: bytes, offset: int) -> int:
    return int.from_bytes(row[offset : offset + 4], "little")


def _extract_native(payload: bytes, start: int, end: int) -> int:
    """Common12 6d2da /18 9bf8a, including DWORD shift-count wrap."""
    if end < start:
        raise ToyotaCodecError("Native reversed FFD bit range", 0xC0000001)
    if start < 0 or end >= len(payload) * 8:
        raise SessionError("Native FFD bit address outside bounded observation")
    first, last = start >> 3, end >> 3
    right = (~end) & 7
    result = payload[last] >> right
    for distance in range(1, last - first):
        result |= payload[last - distance] << ((distance * 8 - right) & 31)
    if first == last:
        result &= (1 << (end - start + 1)) - 1
    else:
        result |= ((payload[first] << (start & 7)) & 255) << ((end - start - 7) & 31)
    return result & 0xFFFFFFFF


@dataclass(frozen=True)
class P5DataIdObservation:
    did: int
    data: bytes

    def __post_init__(self) -> None:
        _uint(self.did, 0xFFFF, "DID")
        if not self.did:
            raise ValueError("CCmdDataIdData.Set rejects DID zero")
        if not isinstance(self.data, bytes) or not 1 <= len(self.data) <= 255:
            raise ValueError("AnalyzeSingleDataId requires a nonempty BYTE payload")


@dataclass(frozen=True)
class P5Value:
    value: int
    index: int
    kind: int

    def __post_init__(self) -> None:
        _uint(self.value, 0xFFFFFFFF, "value")
        _uint(self.kind, 0xFFFFFFFF, "FFD type")
        if type(self.index) is not int or not -128 <= self.index <= 127:
            raise ValueError("Native time index must fit signed BYTE")


@dataclass(frozen=True)
class P5SignalMetadata:
    pid: int
    name_id: int
    name: str
    order: int
    selector: int
    start_bit: int
    end_bit: int
    unit_name_id: int
    unit: str
    unit_id: int
    sign_mode: int
    precision: int
    multiplier: int
    divisor: int
    offset: int
    minimum_raw: int
    maximum_raw: int
    threshold: int
    threshold_high: int
    # Native FFD display-info retains match LOW and HIGH, unlike monitor items.
    patterns: tuple[tuple[int, str, int, int], ...]

    @property
    def width(self) -> int:
        return (self.end_bit - self.start_bit + 1) & 0xFFFF

    def render(self, value: P5Value) -> dict[str, object]:
        return render_signal(
            value.value,
            selector=self.selector,
            sign_mode=self.sign_mode,
            bits=self.width,
            multiplier=self.multiplier,
            divisor=self.divisor,
            offset=self.offset,
            precision=self.precision,
            minimum_raw=self.minimum_raw,
            maximum_raw=self.maximum_raw,
            patterns=tuple(
                (low, label, low, high) for _, label, low, high in self.patterns
            ),
        )


@dataclass
class P5FreezeSignal:
    metadata: P5SignalMetadata
    values: list[P5Value] = field(default_factory=list)

    @property
    def pid(self) -> int:
        return self.metadata.pid


@dataclass
class P5Diagnostic:
    code: int
    metadata: dict[str, object]
    status: int = 0
    diag_type: int = 0
    existence_flags: int = 0
    normal_numbers: list[int] = field(default_factory=list)
    extended_numbers: list[int] = field(default_factory=list)
    signals: list[P5FreezeSignal] = field(default_factory=list)
    timestamps: list[P5FreezeSignal | None] = field(default_factory=lambda: [None] * 3)
    odometer: P5FreezeSignal | None = None
    absolute: dict[int, P5FreezeSignal] = field(default_factory=dict)
    timestamp_flags: int = 0
    odometer_flags: int = 0
    absolute_flags: int = 0
    stored_all: bool = False


@dataclass
class P5SnapshotRequest:
    code: int
    numbers: list[int]

    def __post_init__(self) -> None:
        _uint(self.code, 0xFFFFFF, "DTC")
        if not isinstance(self.numbers, list) or len(self.numbers) > 255:
            raise ValueError("Snapshot numbers must be a bounded native BYTE list")
        for number in self.numbers:
            _uint(number, 255, "snapshot number")
            if not number:
                raise ToyotaCodecError("Zero snapshot request number", 0xC0040001)


class P5FreezeState:
    """CGetFrzFrmDatP5Base association, support cache and partial mutations.

    source_build selects the original code, independently of the selected DDB.
    Native ignored errors are retained in diagnostics rather than promoted to
    successful observations. Fatal failures leave prior native mutations intact.
    """

    def __init__(
        self,
        profile: VehicleProfile,
        *,
        source_build: Literal[12, 18],
        cache: MonitorSupportCache,
        subaru: bool = False,
        native_cancel_value: int = 0,
    ) -> None:
        if type(source_build) is not int or source_build not in SOURCE_SHA256:
            raise ValueError("Explicit original Common build12 or18 required")
        if not isinstance(cache, MonitorSupportCache):
            raise TypeError("Concrete selected support cache required")
        if (
            source_build != cache.source_build
            or monitor_source_identity(profile, cache.ecu) != cache.identity
        ):
            raise SessionError("Freeze base and support cache source differ")
        if type(subaru) is not bool or subaru and source_build != 18:
            raise ValueError("Original12 has no Subaru snapshot base")
        self.profile, self.source_build, self.cache = profile, source_build, cache
        self.identity = cache.identity
        self.connection_bus_id = cache.bus_id
        if self.connection_bus_id is not None:
            _uint(self.connection_bus_id, 0xFFFF, "connection bus")
        self.subaru = subaru
        self.native_cancel_value = _uint(native_cancel_value, 0xFFFFFFFF, "cancel flag")
        self.diagnostics: list[P5Diagnostic] = []
        self.support: dict[int, bool] = {}
        self._ignored_errors: deque[tuple[int, int]] = deque(maxlen=MAX_ITEMS)
        self.signal_pids: dict[int, tuple[int, ...]] = {}
        self.cached_selector = P5Value(0, 0, 0)
        self.cached_selector_signal: P5FreezeSignal | None = None
        self.snapshot_frames: list[bytes] = []
        self.snapshot_success = False
        self._snapshot_partial: deque[tuple[int, int]] = deque(maxlen=MAX_ITEMS)
        self._snapshot_bytes = 0
        self.stored_numbers: list[int] = []

    @property
    def ignored_errors(self) -> list[tuple[int, int]]:
        return list(self._ignored_errors)

    @property
    def snapshot_partial(self) -> list[tuple[int, int]]:
        return list(self._snapshot_partial)

    @property
    def source_sha256(self) -> str:
        return SOURCE_SHA256[self.source_build]

    def _check(self) -> None:
        self.cache._check()
        if (
            self.cache.source_build != self.source_build
            or self.cache.bus_id != self.connection_bus_id
            or monitor_source_identity(self.profile, self.cache.ecu) != self.identity
        ):
            raise SessionError("Freeze base selected source changed")

    @property
    def diagnostic_limit(self) -> int:
        return (
            0x3FFF
            if self.source_build == 18 and self.connection_bus_id == 0x14
            else 0x3FF
        )

    def init_freeze_data(self) -> None:
        """InitFrzFrmDat rebind validation and collected-frame reset only."""
        self._check()
        self.snapshot_frames.clear()
        self._snapshot_bytes = 0

    def _rows(self, slot: int, width: int) -> tuple[bytes, ...]:
        if slot not in self.profile.database.sections:
            raise ToyotaCodecError("Selected FFD table absent", 0xA0030107)
        rows = self.profile.records(slot)
        if any(len(row) != width for row in rows):
            raise ToyotaCodecError("Invalid selected FFD record width", 0xC0040102)
        if len(rows) > 0x7FFF:
            raise ToyotaCodecError("FFD record count exceeds SHORT", 0xC0040102)
        return rows

    def diagnostic(self, code: int) -> P5Diagnostic | None:
        _uint(code, 0xFFFFFF, "DTC")
        return next((item for item in self.diagnostics if item.code == code), None)

    def add_diagnostic(
        self, code: int, *, status: int = 0, diag_type: int = 0
    ) -> P5Diagnostic | None:
        self._check()
        _uint(status, 255, "DTC status")
        _uint(diag_type, 0xFFFFFFFF, "diagnostic type")
        existing = self.diagnostic(code)
        if existing is not None:
            existing.status |= status
            existing.diag_type |= diag_type
            return existing
        metadata = dtc_metadata_p5_profile(self.profile, code)
        if metadata is None:
            return None
        if len(self.diagnostics) >= self.diagnostic_limit:
            raise SessionError("FFD diagnostic count exceeds native caller bound")
        item = P5Diagnostic(code, metadata, status, diag_type)
        self.diagnostics.append(item)
        return item

    @staticmethod
    def set_dtc(request: bytes, code: int, number: int | None = None) -> bytes:
        _uint(code, 0xFFFFFF, "DTC")
        if not isinstance(request, bytes) or len(request) < (
            6 if number is not None else 5
        ):
            raise ToyotaCodecError("DTC request template is too short", 0xC0040001)
        result = bytearray(request)
        result[2:5] = code.to_bytes(3, "big")
        if number is not None:
            _uint(number, 255, "record number")
            if not number:
                raise ToyotaCodecError("Zero FFD request number", 0xC0040001)
            result[5] = number
        return bytes(result)

    def get_ffd_type(self, number: int, *, extended: bool = False) -> int:
        return ffd_type(number, extended=extended, subaru=self.subaru)

    def set_ffd_exist_flag(
        self, code: int, number: int, *, extended: bool = False
    ) -> None:
        self._check()
        _uint(number, 255, "record number")
        if not number:
            raise ToyotaCodecError("Zero FFD record number", 0xC0040001)
        item = self.diagnostic(code)
        if item is None:
            return
        if self.subaru:
            accepted = (
                number < 255 if extended else number == 1 or 0x10 <= number <= 0x2F
            )
        else:
            accepted = (
                1 <= number <= 14
                if extended
                else number in (1, 2) or 0x10 <= number <= 0x6F
            )
        if not accepted:
            return
        numbers = item.extended_numbers if extended else item.normal_numbers
        if number not in numbers:
            numbers.append(number)
        kind = self.get_ffd_type(number, extended=extended)
        if self.subaru and extended:
            item.existence_flags |= 1
        elif kind:
            item.existence_flags = ffd_existence_flag(kind, item.existence_flags)

    def get_pid_ids(self, did: int) -> tuple[int, ...]:
        _uint(did, 65535, "DID")
        rows = self._rows(62, 64)
        if not rows:
            raise ToyotaCodecError("P5 FFD monitor table empty", 0xC0040101)
        return tuple(word(row, 36) for row in rows if word(row, 56) == did)

    @staticmethod
    def search_data_id(did: int, data_ids: tuple[P5DataIdObservation, ...]) -> int:
        _uint(did, 65535, "DID")
        if not did:
            return -1
        return next((i for i, item in enumerate(data_ids) if item.did == did), -1)

    @staticmethod
    def search_pid(pid: int, signals: list[P5FreezeSignal]) -> int:
        _uint(pid, 65535, "PID")
        if not pid:
            return -1
        return next((i for i, item in enumerate(signals) if item.pid == pid), -1)

    def check_support_bit(
        self, row: bytes, variable: bytes, data_ids: tuple[P5DataIdObservation, ...]
    ) -> bool:
        if len(variable) < 2 or len(row) != 12:
            raise ToyotaCodecError("FFD support variable too short", 0xC0040102)
        found = self.search_data_id(int.from_bytes(variable[:2], "big"), data_ids)
        if found < 0:
            return False
        if row[11] != 7:
            raise ToyotaCodecError("Unsupported FFD support-bit mode", 0xC0040102)
        return _extract_native(data_ids[found].data, word(row, 6), word(row, 8)) > 0

    def check_support_pid(
        self,
        row: bytes,
        data: bytes,
        data_ids: tuple[P5DataIdObservation, ...],
        previous: bool = False,
    ) -> bool:
        if row not in self._rows(62, 64):
            raise ValueError("FFD support row is outside selected source")
        pid, end = word(row, 36), word(row, 46)
        if not pid:
            raise ToyotaCodecError("Zero native support PID", 0xC0040001)
        result = previous
        try:
            did_rows = tuple(
                item for item in self._rows(61, 8) if word(item, 2) == word(row, 56)
            )
            if did_rows:
                mode = did_rows[0][6]
                if len(data) * 8 <= end:
                    result = False
                elif mode in (0, 2):
                    result = True
                elif mode == 1:
                    at = (end >> 3) - 1
                    if at < 0:
                        raise SessionError(
                            "Native support-byte address precedes bounded payload"
                        )
                    result = bool(data[at] & (0x80 >> (end & 7)))
                else:
                    self._ignored_errors.append((pid, 0xC0040102))
                if result and word(row, 40):
                    result = False
                    bits = self.profile.ffd_bit_records(word(row, 40))
                    if bits:
                        variable = self.profile.ffd_bit_variable(bits[0])
                        if variable:
                            result = self.check_support_bit(bits[0], variable, data_ids)
        except ToyotaCodecError as error:
            self._ignored_errors.append((pid, error.code))
        self.support[pid] = result
        return result

    def signal_metadata(self, row: bytes) -> P5SignalMetadata:
        self._check()
        if row not in self._rows(62, 64):
            raise ValueError("FFD metadata row is outside selected source")
        lsb = SignalLSB(self.cache, source_build=self.source_build)
        pid, start, end = word(row, 36), word(row, 44), word(row, 46)
        physical = next(
            (item for item in self._rows(13, 24) if word(item, 12) == word(row, 42)),
            None,
        )
        if physical is None:
            raise ToyotaCodecError("FFD physical definition absent", 0xC0040101)
        unit = next(
            (
                item
                for item in self._rows(15, 12)
                if word(item, 4) == word(physical, 14)
            ),
            None,
        )
        if unit is None:
            raise ToyotaCodecError("FFD unit definition absent", 0xC0040101)
        family = word(row, 50)
        pattern_rows = self._rows(14, 20 if self.source_build == 12 else 24)
        family_at = 4 if self.source_build == 12 else 12
        patterns = tuple(
            item for item in pattern_rows if word(item, family_at) == family
        )
        if family and not patterns:
            raise ToyotaCodecError("FFD display pattern absent", 0xC0040101)
        language = self.profile.catalog.language
        name = language.resolve(_dword(row, 24))
        unit_name = language.resolve(_dword(unit, 0))
        resolved_patterns = tuple(
            (
                family,
                language.resolve(_dword(item, 0)),
                word(item, 10) if self.source_build == 12 else _dword(item, 4),
                word(item, 12) if self.source_build == 12 else _dword(item, 8),
            )
            for item in patterns
        )
        observed = lsb.p5(
            pid,
            exponent=physical[21],
            width=(end - start + 1) & 0xFFFF,
            multiplier=_dword(physical, 0),
            divisor=_dword(physical, 4),
            threshold=_dword(row, 12),
        )
        return P5SignalMetadata(
            pid,
            _dword(row, 24),
            name,
            row[59],
            row[58],
            start,
            end,
            _dword(unit, 0),
            unit_name,
            word(unit, 6),
            physical[20],
            physical[21],
            observed.multiplier,
            observed.divisor,
            _dword(physical, 8),
            _dword(row, 4),
            _dword(row, 8),
            observed.threshold,
            _dword(row, 16),
            resolved_patterns,
        )

    def analyze_single_data_id(
        self,
        code: int,
        did: int,
        multi: P5Value,
        data: bytes,
        data_ids: tuple[P5DataIdObservation, ...],
    ) -> None:
        self._check()
        P5DataIdObservation(did, data)
        if (
            not isinstance(multi, P5Value)
            or not isinstance(data_ids, tuple)
            or len(data_ids) > MAX_ITEMS
            or any(not isinstance(item, P5DataIdObservation) for item in data_ids)
        ):
            raise TypeError("Typed native multi-data and DID observations required")
        diagnostic = self.diagnostic(code)
        if diagnostic is None:
            return
        previous = False
        rows = self._rows(62, 64)
        for pid in self.get_pid_ids(did):
            self._check()
            row = next(item for item in rows if word(item, 36) == pid)
            if not _dword(row, 32) & 2:
                continue
            start, end = word(row, 44), word(row, 46)
            if ((end >> 3) + 1) & 255 == (start >> 3) & 255:
                raise ToyotaCodecError("Native empty FFD range", 0xC0040102)
            if ((end >> 3) + 1) & 255 > len(data):
                continue
            previous = (
                self.support[pid]
                if pid in self.support
                else self.check_support_pid(row, data, data_ids, previous)
            )
            if previous:
                value = replace(multi, value=_extract_native(data, start, end))
                self.set_freeze_data(diagnostic, row, value)

    def set_freeze_data(
        self, diagnostic: P5Diagnostic, row: bytes, value: P5Value
    ) -> None:
        self._check()
        if row not in self._rows(62, 64):
            raise ValueError("FFD value row is outside selected source")
        pid = word(row, 36)
        # One native association can append main + two special values.
        if sum(len(values) for values in self._all_lists(diagnostic)) + 3 > MAX_ITEMS:
            raise SessionError("FFD retained sample budget exhausted")
        if (
            self.source_build == 18
            and pid == self._pid(0x4A)
            and self.cached_selector.value < 3
        ):
            value = replace(value, value=value.value & 0xFFFFFF)
        if row[59] in (0, 1):
            existing = next(
                (item for item in diagnostic.signals if item.pid == pid), None
            )
            if existing is None:
                existing = P5FreezeSignal(self.signal_metadata(row))
                diagnostic.signals.append(existing)
            existing.values.append(value)
        if not self.signal_pids:
            return
        if self.subaru and self.profile.category != 0x26B:
            for index, signal in enumerate((0x4D, 0x4E, 0x4F)):
                if pid == self._pid(signal):
                    sentinel = (0xFFFF, 0x1FFFFFFF, None)[index]
                    if value.value != sentinel:
                        self._timestamp(
                            diagnostic, index, row, value, require_pid=index != 0
                        )
                    return
            return
        for index, signal in enumerate((0x1C, 0x1D, 0x27)):
            if pid == self._pid(signal):
                sentinel = (0xFFFF, 0xFFFFFFFF, None)[index]
                if value.value != sentinel:
                    self._timestamp(
                        diagnostic, index, row, value, require_pid=index != 0
                    )
                return
        if self.source_build == 18 and pid == self._pid(0x49):
            self.cached_selector = value
            if diagnostic.timestamps[2] is None or diagnostic.timestamps[2].pid != pid:
                self.cached_selector_signal = P5FreezeSignal(
                    self.signal_metadata(row), [value]
                )
            return
        if self.source_build == 18 and pid == self._pid(0x4A):
            selector = self.cached_selector.value
            if selector > 3 or value.value == (
                0x1FFFFFFF if selector == 3 else 0xFFFFFFFF
            ):
                return
            self._timestamp(diagnostic, 1, row, value, replace_other=True)
            old = diagnostic.timestamps[2]
            if old is not None and old.pid == self._pid(0x49):
                old.values.append(self.cached_selector)
            elif self.cached_selector_signal is not None:
                diagnostic.timestamps[2] = P5FreezeSignal(
                    self.cached_selector_signal.metadata, [self.cached_selector]
                )
            return
        if pid in self.signal_pids.get(0x28, ())[:2]:
            if value.value:
                if diagnostic.odometer is None:
                    diagnostic.odometer = P5FreezeSignal(
                        self.signal_metadata(row), [value]
                    )
                elif diagnostic.odometer.pid == pid:
                    diagnostic.odometer.values.append(value)
            return
        if self.source_build == 18:
            selected = {signal: self._pid(signal) for signal in range(0x3C, 0x42)}
            for signal, converted in absolute_time_values(
                {pid: value.value}, selected
            ).items():
                if signal not in diagnostic.absolute:
                    diagnostic.absolute[signal] = P5FreezeSignal(
                        self.signal_metadata(row)
                    )
                diagnostic.absolute[signal].values.append(
                    replace(value, value=converted)
                )

    def _pid(self, signal: int) -> int:
        return next(iter(self.signal_pids.get(signal, ())), 0)

    def _timestamp(
        self,
        diagnostic: P5Diagnostic,
        index: int,
        row: bytes,
        value: P5Value,
        *,
        require_pid: bool = False,
        replace_other: bool = False,
    ) -> None:
        existing = diagnostic.timestamps[index]
        if replace_other and existing is not None and existing.pid == word(row, 36):
            existing.values.append(value)
            return
        if existing is not None and existing.values:
            if existing.pid == word(row, 36) or not require_pid and not replace_other:
                existing.values.append(value)
                return
            if not replace_other:
                return
        diagnostic.timestamps[index] = P5FreezeSignal(
            self.signal_metadata(row), [value]
        )

    def set_timestamp_odometer_pid_ids(self) -> None:
        self._check()
        signals = [0x1C, 0x1D, 0x27]
        if self.subaru and self.profile.category != 0x26B:
            signals = [0x4D, 0x4E, 0x4F]
        elif self.source_build == 18:
            if self.profile.category in (0x190, 0x191):
                signals.extend((0x49, 0x4A))
            signals.append(0x28)
            signals.extend(range(0x3C, 0x42))
        else:
            signals.append(0x28)
        # Native assigns each field immediately; later lookup failure retains it.
        for signal in signals:
            pids = self.profile.signal_pids(signal)
            if not pids:
                raise ToyotaCodecError("FFD signal PID group absent", 0xC0040101)
            self.signal_pids[signal] = pids

    def set_timestamp_odometer_flags(self, diagnostic: P5Diagnostic) -> None:
        self._check()
        for attribute, source in (
            ("timestamp_flags", diagnostic.timestamps[0]),
            ("odometer_flags", diagnostic.odometer),
            (
                "absolute_flags",
                diagnostic.absolute.get(0x3C) if self.source_build == 18 else None,
            ),
        ):
            if source is not None:
                flags = getattr(diagnostic, attribute)
                for value in source.values:
                    if value.kind in (1, 2) or 0x101 <= value.kind <= 0x10E:
                        flags = ffd_existence_flag(value.kind, flags)
                setattr(diagnostic, attribute, flags)

    def analyze_record(
        self,
        code: int,
        number: int,
        items: tuple[P5DataIdObservation, ...],
        *,
        extended: bool = False,
        set_existence: bool = True,
    ) -> None:
        self._check()
        if (
            not isinstance(items, tuple)
            or len(items) > MAX_ITEMS
            or any(not isinstance(item, P5DataIdObservation) for item in items)
        ):
            raise TypeError("Bounded typed DID observations required")
        kind = self.get_ffd_type(number, extended=extended)
        if not kind:
            return
        if set_existence:
            self.set_ffd_exist_flag(code, number, extended=extended)
        index = ((number - 0x7F + 128) & 255) - 128
        multi = P5Value(0, index, kind)
        seen: set[int] = set()
        for item in items:
            if item.did not in seen:
                seen.add(item.did)
                self.analyze_single_data_id(code, item.did, multi, item.data, items)

    def sort_display_order(self, diagnostic: P5Diagnostic) -> None:
        self._check()
        if len(diagnostic.signals) < 2:
            return
        old = diagnostic.signals[:]
        diagnostic.signals.clear()
        rows = self._rows(62, 64)
        if not rows:
            raise ToyotaCodecError("FFD display order table empty", 0xC0040101)
        for row in rows:
            match = next((item for item in old if item.pid == word(row, 36)), None)
            if match is not None:
                diagnostic.signals.append(
                    P5FreezeSignal(match.metadata, match.values[:])
                )

    @staticmethod
    def search_multi_data(values: list[P5Value], kind: int, index: int) -> int:
        _uint(kind, 0xFFFFFFFF, "FFD type")
        if not kind:
            return -1
        return next(
            (
                i
                for i, value in enumerate(values)
                if (value.kind, value.index) == (kind, index)
            ),
            -1,
        )

    @staticmethod
    def search_ffd_type(values: list[P5Value], kind: int) -> tuple[int, ...]:
        _uint(kind, 0xFFFFFFFF, "FFD type")
        return tuple(
            index for index, value in enumerate(values) if kind and value.kind == kind
        )

    @staticmethod
    def _values(signal: P5FreezeSignal | None) -> list[P5Value]:
        return [] if signal is None else signal.values

    def _search_timestamp(self, diagnostic: P5Diagnostic, value: P5Value) -> int:
        if not value.kind:
            return -1
        first, second = (self._values(item) for item in diagnostic.timestamps[:2])
        for index, current in enumerate(first):
            if (current.kind, current.index) == (value.kind, value.index):
                if index >= len(second):
                    raise ToyotaCodecError(
                        "Native paired timestamp list truncated", 0xC0040102
                    )
                if (second[index].kind, second[index].index) == (
                    value.kind,
                    value.index,
                ):
                    return index
        return -1

    def sort_multi_data_by_ffd_type(self, diagnostic: P5Diagnostic) -> tuple[int, ...]:
        self._check()
        original = deepcopy(diagnostic)
        old_timestamps = [self._values(item) for item in original.timestamps]
        timestamp_lists: list[list[P5Value]] = [[], [], []]
        counts: list[int] = []
        for group in FFD_GROUPS:
            count = 0
            stop = False
            for rank, kind in enumerate(group):
                candidates = [
                    value for value in old_timestamps[0] if value.kind == kind
                ]
                if not candidates and rank == 0:
                    break
                for value in candidates:
                    matches = [
                        self.search_multi_data(values, kind, value.index)
                        for values in old_timestamps[1:]
                    ]
                    if min(matches) < 0:
                        if rank == 0:
                            stop = True
                            break
                        continue
                    timestamp_lists[0].append(value)
                    for target, values, index in zip(
                        timestamp_lists[1:], old_timestamps[1:], matches, strict=True
                    ):
                        target.append(values[index])
                    count = (count + 1) & 255
                if stop:
                    break
            counts.append(count)
        for target, values in zip(diagnostic.timestamps, timestamp_lists, strict=True):
            if target is not None:
                target.values[:] = values
        for target, values in zip(original.timestamps, timestamp_lists, strict=True):
            if target is not None:
                target.values[:] = values

        def filtered(values: list[P5Value]) -> list[P5Value]:
            result: list[P5Value] = []
            for group in FFD_GROUPS:
                for rank, kind in enumerate(group):
                    candidates = [value for value in values if value.kind == kind]
                    if not candidates and rank == 0:
                        break
                    result.extend(
                        value
                        for value in candidates
                        if rank == 0 or self._search_timestamp(original, value) >= 0
                    )
            return result

        if diagnostic.odometer is not None:
            diagnostic.odometer.values[:] = filtered(diagnostic.odometer.values)
        if self.source_build == 18:
            absolute_lists = [
                self._values(diagnostic.absolute.get(signal))
                for signal in range(0x3C, 0x42)
            ]
            result_lists: list[list[P5Value]] = [[] for _ in range(6)]
            for group in FFD_GROUPS:
                stop = False
                for rank, kind in enumerate(group):
                    candidates = [
                        value for value in absolute_lists[0] if value.kind == kind
                    ]
                    if not candidates and rank == 0:
                        break
                    for value in candidates:
                        if rank and self._search_timestamp(original, value) < 0:
                            continue
                        matches = [
                            self.search_multi_data(values, kind, value.index)
                            for values in absolute_lists[1:]
                        ]
                        if min(matches) < 0:
                            if rank == 0:
                                stop = True
                                break
                            continue
                        result_lists[0].append(value)
                        for target, values, index in zip(
                            result_lists[1:], absolute_lists[1:], matches, strict=True
                        ):
                            target.append(values[index])
                    if stop:
                        break
            for signal, values in zip(range(0x3C, 0x42), result_lists, strict=True):
                if signal in diagnostic.absolute:
                    diagnostic.absolute[signal].values[:] = values
        diagnostic.signals[:] = [
            P5FreezeSignal(item.metadata, values)
            for item in diagnostic.signals
            if (values := filtered(item.values))
        ]
        return tuple(counts)

    def _all_lists(self, diagnostic: P5Diagnostic) -> list[list[P5Value]]:
        result = [self._values(item) for item in diagnostic.timestamps]
        result.append(self._values(diagnostic.odometer))
        if self.source_build == 18:
            result.extend(
                self._values(diagnostic.absolute.get(signal))
                for signal in range(0x3C, 0x42)
            )
        result.extend(item.values for item in diagnostic.signals)
        return result

    def _swap_multi_data(self, diagnostic: P5Diagnostic, index: int) -> None:
        first = self._values(diagnostic.timestamps[0])
        left, right = first[index - 1], first[index]
        for position, values in enumerate(self._all_lists(diagnostic)):
            if position < 4 and index >= len(values):
                continue
            a = self.search_multi_data(values, left.kind, left.index)
            b = self.search_multi_data(values, right.kind, right.index)
            if a >= 0 and b >= 0:
                values[a], values[b] = values[b], values[a]

    def _set_time_index(
        self,
        diagnostic: P5Diagnostic,
        original: P5Diagnostic,
        value: P5Value,
        index: int,
    ) -> None:
        index = (index + 128) % 256 - 128
        targets, sources = self._all_lists(diagnostic), self._all_lists(original)
        for position, (target, source) in enumerate(zip(targets, sources, strict=True)):
            searched = (
                target if self.source_build == 18 and 4 <= position < 10 else source
            )
            found = self.search_multi_data(searched, value.kind, value.index)
            if found >= 0:
                target[found] = replace(target[found], index=index)

    def sort_multi_data_by_timestamp(self, diagnostic: P5Diagnostic) -> None:
        counts = self.sort_multi_data_by_ffd_type(diagnostic)
        first = self._values(diagnostic.timestamps[0])
        second = self._values(diagnostic.timestamps[1])
        start = end = 0
        for count in counts:
            end += count
            if count > 1:
                if len(first) < end or len(second) < end:
                    break
                # Native singleton groups advance end but leave start in place.
                for _ in range(end - start - 1):
                    for position in range(start + 1, end):
                        self._check()
                        if (
                            compare_timestamp(
                                first[position - 1].value,
                                first[position].value,
                                second[position - 1].value,
                                second[position].value,
                            )
                            == 1
                        ):
                            self._swap_multi_data(diagnostic, position)
                start = end
        original = deepcopy(diagnostic)
        start = 0
        for group, count in zip(FFD_GROUPS, counts, strict=True):
            end = start + count
            if not count:
                lists = [item.values for item in diagnostic.signals]
                lists.append(self._values(diagnostic.odometer))
                if self.source_build == 18:
                    lists.extend(
                        self._values(diagnostic.absolute.get(signal))
                        for signal in range(0x3C, 0x42)
                    )
                for values in lists:
                    found = next(
                        (i for i, value in enumerate(values) if value.kind == group[0]),
                        -1,
                    )
                    if found >= 0:
                        values[found] = replace(values[found], index=0)
            else:
                if len(first) < end or len(second) < end:
                    break
                anchor = next(
                    (i for i in range(start, end) if first[i].kind == group[0]), -1
                )
                if anchor >= 0:
                    for position in range(anchor, end):
                        equal = (
                            position > anchor
                            and compare_timestamp(
                                first[position - 1].value,
                                first[position].value,
                                second[position - 1].value,
                                second[position].value,
                            )
                            == 3
                        )
                        new = (
                            0
                            if position == anchor
                            else first[position - 1].index + (not equal)
                        )
                        self._set_time_index(diagnostic, original, first[position], new)
                    for position in range(anchor - 1, start - 1, -1):
                        equal = (
                            compare_timestamp(
                                first[position + 1].value,
                                first[position].value,
                                second[position + 1].value,
                                second[position].value,
                            )
                            == 3
                        )
                        self._set_time_index(
                            diagnostic,
                            original,
                            first[position],
                            first[position + 1].index - (not equal),
                        )
            start = end

    def get_category_info(self) -> int:
        self._check()
        if not self.subaru:
            raise ValueError("GetCategoryInfoSUBARU requires original18 subclass")
        if len(self.profile.category_record) < 73:
            raise ToyotaCodecError("Selected category record absent", 0xC0040101)
        return self.profile.category_record[72]

    def comm_execute_snapshot(self, requests: tuple[P5SnapshotRequest, ...]) -> bool:
        self._check()
        if not self.subaru:
            raise ValueError("Snapshot communication requires original18 Subaru base")
        if (
            not isinstance(requests, tuple)
            or len(requests) > self.diagnostic_limit
            or any(not isinstance(item, P5SnapshotRequest) for item in requests)
        ):
            raise TypeError("Bounded typed snapshot requests required")
        for item in requests:
            item.__post_init__()
        frames = _profile_frames(self.profile, 0xCF)
        if not frames:
            raise ToyotaCodecError(
                "Subaru snapshot communication frame absent", 0xC0040101
            )
        frame = frames[0]
        for item in requests:
            at = 0
            while at < len(item.numbers):
                self._check()
                request = self.set_dtc(frame.frame.request, item.code, item.numbers[at])
                if _uint(self.native_cancel_value, 0xFFFFFFFF, "cancel flag") == 1:
                    raise ToyotaCodecError(
                        "Native snapshot command cancelled", 0xA0040003
                    )
                try:
                    response = self.cache.transaction(
                        frame, request, cached=False, temporary=False, extended=True
                    )
                except ToyotaCodecError as error:
                    if error.code not in SNAPSHOT_TOLERATED:
                        raise
                    self._ignored_errors.append((item.numbers[at], error.code))
                    del item.numbers[at]
                    continue
                self.snapshot_success = True
                if (
                    len(self.snapshot_frames) >= MAX_ITEMS
                    or self._snapshot_bytes + len(response) > MAX_CAPTURE_BYTES
                ):
                    raise SessionError("FFD captured response budget exhausted")
                self.snapshot_frames.append(response)
                self._snapshot_bytes += len(response)
                at += 1
        return self.snapshot_success

    def comm_execute_stored(self) -> bool:
        """Original18 88a00/88d80, function113 then numbered fallback1..254."""
        self._check()
        if not self.subaru:
            raise ValueError("Stored communication requires original18 Subaru base")
        frames = _profile_frames(self.profile, 0x113)
        if not frames:
            raise ToyotaCodecError("Subaru stored frame absent", 0xC0040101)
        frame = frames[0]
        template = frame.frame.request
        if len(template) < 3:
            raise ToyotaCodecError("Subaru stored request too short", 0xC0040001)
        for number in (None, *range(1, 255)):
            self._check()
            if self.native_cancel_value == 1:
                raise ToyotaCodecError("Native stored command cancelled", 0xA0040003)
            request = (
                template
                if number is None
                else template[:2] + bytes((number,)) + template[3:]
            )
            try:
                response = self.cache.transaction(
                    frame, request, cached=False, extended=True
                )
            except ToyotaCodecError as error:
                if error.code not in SNAPSHOT_TOLERATED:
                    raise
                self._ignored_errors.append((request[2], error.code))
                if number is None:
                    continue
                break
            self.snapshot_success = True
            if len(response) < 4:
                if number is None:
                    continue
                break
            if (
                len(self.snapshot_frames) >= MAX_ITEMS
                or self._snapshot_bytes + len(response) > MAX_CAPTURE_BYTES
            ):
                raise SessionError("FFD captured response budget exhausted")
            self.snapshot_frames.append(response)
            self._snapshot_bytes += len(response)
            if len(self.stored_numbers) >= MAX_ITEMS:
                raise SessionError("FFD stored request number budget exhausted")
            self.stored_numbers.append(request[2])
            if number is None:
                break
        return self.snapshot_success

    def set_stored_confirmed(self, diagnostic: P5Diagnostic) -> None:
        """Original18 8c800 chooses one stored index and marks first matches."""
        self._check()
        if not self.subaru:
            raise ValueError("Stored confirmation requires original18 Subaru base")
        pids = self.get_pid_ids(0x101F)
        selected = None
        if pids:
            signal = next(
                (item for item in diagnostic.signals if item.pid == pids[0]), None
            )
            if signal is not None:
                zero = next(
                    (value for value in signal.values if value.value == 0), None
                )
                if zero is not None and zero.index != -1:
                    selected = zero.index
        if selected is None:
            selected = (
                (max(diagnostic.extended_numbers, default=0) + 0x81 + 128) & 255
            ) - 128
        for values in [item.values for item in diagnostic.signals] + [
            self._values(item) for item in diagnostic.timestamps
        ]:
            found = next(
                (
                    index
                    for index, value in enumerate(values)
                    if value.index == selected
                ),
                -1,
            )
            if found >= 0:
                values[found] = replace(values[found], kind=1)

    def analyze_stored_received(self) -> None:
        """Original18 88fc0 parses a private diagnostic stage, then merges it."""
        self._check()
        if not self.subaru:
            raise ValueError("Stored analysis requires original18 Subaru base")
        if not self.snapshot_frames:
            return
        if len(self.stored_numbers) < len(self.snapshot_frames):
            raise SessionError("Stored capture lacks native request-number association")
        for signal in (0x4D, 0x4E, 0x4F):
            pids = self.profile.signal_pids(signal)
            if not pids:
                raise ToyotaCodecError("FFD signal PID group absent", 0xC0040101)
            self.signal_pids[signal] = pids
        existing = self.diagnostics
        self.diagnostics = []
        try:
            for frame_index, response in enumerate(self.snapshot_frames):
                self._check()
                at = 2
                while at < len(response):
                    if at + 6 > len(response):
                        self._snapshot_partial.append((frame_index, at))
                        break
                    number = response[at]
                    kind = self.get_ffd_type(number, extended=True)
                    if not kind:
                        self._snapshot_partial.append((frame_index, at))
                        break
                    code = int.from_bytes(response[at + 1 : at + 4], "big")
                    diagnostic = self.add_diagnostic(code)
                    if diagnostic is not None:
                        if number != 255:
                            self.set_ffd_exist_flag(code, number, extended=True)
                        diagnostic.stored_all = self.stored_numbers[frame_index] == 255
                    count = response[at + 5]
                    at += 6
                    if not count and self.stored_numbers[frame_index] == 255:
                        break
                    observations: list[P5DataIdObservation] = []
                    consumed = 0
                    while consumed < count or not count:
                        if at + 2 > len(response):
                            at = len(response)
                            break
                        did = int.from_bytes(response[at : at + 2], "big")
                        at += 2
                        rows = [row for row in self._rows(61, 8) if word(row, 2) == did]
                        length = next((row[4] for row in rows if row[4]), 0)
                        if not length or at + length > len(response):
                            self._snapshot_partial.append((frame_index, at - 2))
                            at = len(response)
                            break
                        payload = response[at : at + length]
                        at += length
                        if did and not any(item.did == did for item in observations):
                            observations.append(P5DataIdObservation(did, payload))
                        consumed += 1
                    self.analyze_record(
                        code,
                        number,
                        tuple(observations),
                        extended=True,
                        set_existence=False,
                    )
            staged = self.diagnostics
            for diagnostic in staged:
                self.set_stored_confirmed(diagnostic)
                self.sort_multi_data_by_timestamp(diagnostic)
        finally:
            self.diagnostics = existing
        for diagnostic in staged:
            self._merge_stored(diagnostic)

    def _merge_stored(self, incoming: P5Diagnostic) -> None:
        target = self.diagnostic(incoming.code)
        if target is None:
            if len(self.diagnostics) >= self.diagnostic_limit:
                raise SessionError("FFD diagnostic count exceeds native caller bound")
            self.diagnostics.append(incoming)
            return
        if (
            sum(map(len, self._all_lists(target)))
            + sum(map(len, self._all_lists(incoming)))
            > MAX_ITEMS
        ):
            raise SessionError("FFD retained sample budget exhausted")
        target.status |= incoming.status
        target.diag_type |= incoming.diag_type
        target.existence_flags |= incoming.existence_flags
        # Native copies the existing extended-number list into the local stage.
        incoming.extended_numbers[:] = target.extended_numbers
        target.stored_all = incoming.stored_all
        if not self._values(target.timestamps[0]):
            target.timestamps[:] = deepcopy(incoming.timestamps)
        else:
            for index in range(len(self._values(incoming.timestamps[0]))):
                for destination, source in zip(
                    target.timestamps, incoming.timestamps, strict=True
                ):
                    if source is not None and index < len(source.values):
                        if destination is None:
                            raise SessionError(
                                "Native stored timestamp append lacks metadata"
                            )
                        destination.values.append(source.values[index])
        if not self._values(target.odometer):
            target.odometer = deepcopy(incoming.odometer)
        elif incoming.odometer is not None:
            assert target.odometer is not None
            target.odometer.values.extend(incoming.odometer.values)
        for position, signal in enumerate(incoming.signals):
            found = self.search_pid(signal.pid, target.signals)
            if found < 0:
                target.signals.append(deepcopy(signal))
            else:
                # 88fc0 uses the destination PID index for the local loop bound.
                if found >= len(incoming.signals):
                    raise SessionError(
                        "Native stored merge indexes outside local signals"
                    )
                count = len(incoming.signals[found].values)
                if count > len(incoming.signals[position].values):
                    raise SessionError(
                        "Native stored merge indexes outside local values"
                    )
                target.signals[found].values.extend(signal.values[:count])

    def analyze_snapshot_received(
        self,
        requests: tuple[P5SnapshotRequest, ...],
        *,
        create_diagnostics: bool = True,
    ) -> None:
        self._check()
        if not self.subaru:
            raise ValueError("Snapshot analysis requires original18 Subaru base")
        if (
            not isinstance(requests, tuple)
            or len(requests) > self.diagnostic_limit
            or any(not isinstance(item, P5SnapshotRequest) for item in requests)
        ):
            raise TypeError("Bounded typed snapshot requests required")
        if not self.snapshot_frames:
            return
        if not requests:
            return
        self.set_timestamp_odometer_pid_ids()
        offset = 0
        for request in requests:
            end = offset + len(request.numbers)
            for frame_index, response in enumerate(
                self.snapshot_frames[offset:end], offset
            ):
                self._check()
                if len(response) <= 6:
                    continue
                code = int.from_bytes(response[2:5], "big")
                if self.diagnostic(code) is None and (
                    not create_diagnostics or self.add_diagnostic(code) is None
                ):
                    break
                at = 6
                while at < len(response):
                    if at + 2 > len(response):
                        self._snapshot_partial.append((frame_index, at))
                        break
                    number, count = response[at : at + 2]
                    kind = self.get_ffd_type(number)
                    if not kind:
                        self._snapshot_partial.append((frame_index, at))
                        break
                    if create_diagnostics:
                        self.set_ffd_exist_flag(code, number)
                    at += 2
                    if not count and request.numbers and request.numbers[0] == 255:
                        break
                    observations: list[P5DataIdObservation] = []
                    consumed = 0
                    while consumed < count or not count:
                        if at + 2 > len(response):
                            if at < len(response):
                                self._snapshot_partial.append((frame_index, at))
                            at = len(response)
                            break
                        did = int.from_bytes(response[at : at + 2], "big")
                        at += 2
                        rows = [row for row in self._rows(61, 8) if word(row, 2) == did]
                        length = next((row[4] for row in rows if row[4]), 0)
                        if not length or at + length > len(response):
                            self._snapshot_partial.append((frame_index, at - 2))
                            at = len(response)
                            break
                        data = response[at : at + length]
                        at += length
                        if did and not any(item.did == did for item in observations):
                            observations.append(P5DataIdObservation(did, data))
                        consumed += 1
                    # Native analyzes successfully parsed identifiers even when
                    # the current record ended in a malformed/unknown tail.
                    self.analyze_record(
                        code, number, tuple(observations), set_existence=False
                    )
            offset = end
        for diagnostic in self.diagnostics:
            self.sort_multi_data_by_timestamp(diagnostic)
