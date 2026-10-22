"""Source-bound support-query and packet caches; import performs no I/O."""

from __future__ import annotations

import math
import struct
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from scripts.profiles import ProtocolProfile, SelectedFrame, VehicleProfile
from scripts.signal_conversion import extract_bits
from scripts.support import correspondence_rows, word
from scripts.toyota import CommandFrame, ToyotaCodecError

if TYPE_CHECKING:
    from scripts.native_communication import NativeCommunication

from scripts.toyota_session import Cancelled, Limits, SessionError, expand_supported_pid


def _uint(value: int, maximum: int, label: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"Invalid native {label}")
    return value


def first_pid_lengths(entries: Sequence[tuple[int, int]]) -> dict[int, int]:
    """Host lookup projection of a native ordered PID list; first match wins."""
    result: dict[int, int] = {}
    for pid, length in entries:
        result.setdefault(pid, length)
    return result


def monitor_source_identity(profile: ProtocolProfile, ecu: str) -> tuple[object, ...]:
    """One public identity contract for cache creation and consumer binding."""
    return (
        ecu,
        profile.ecu_database_sha256,
        profile.catalog.management.sha256,
        profile.category,
        profile.category_record,
        tuple(profile.exception_ids),
        getattr(profile, "vehicle_name_key", None),
    )


@dataclass(frozen=True)
class Mode35FrameMap:
    """CPidMapMode35 produced widths/positions for ordered supported identifiers."""

    pid: int
    identifiers: bytes
    positions: tuple[int, ...]
    widths: tuple[int, ...]
    total_bits: int

    def position(self, freeze: bytes) -> tuple[int, int]:
        """CommandCommon8e3c0: use first matching identifier and native WORD wrap."""
        try:
            index = self.identifiers.index(freeze[83])
        except ValueError:
            raise ToyotaCodecError(
                "PSA dynamic identifier is absent", 0x90041103
            ) from None
        start, end = word(freeze, 62), word(freeze, 64)
        base = self.positions[index]
        if self.widths[index] == end - start + 1:
            first, last = base, base - start + end
        else:
            first = base - freeze[83] * 8 + start
            last = base - freeze[83] * 8 + end
        first, last = first & 65535, last & 65535
        if first >= self.total_bits or last >= self.total_bits:
            raise ToyotaCodecError(
                "PSA dynamic signal exceeds packed frame", 0x90041104
            )
        return first, last


def mode35_frame_map(
    pid: int, identifiers: bytes, freezes: Sequence[bytes]
) -> Mode35FrameMap:
    """CommandCommon8de70 SetFrameValueInfo, including native bit packing quirks."""
    _uint(pid, 255, "frame PID")
    if pid == 0 or not isinstance(identifiers, bytes) or len(identifiers) > 256:
        raise ToyotaCodecError("Invalid PSA Mode35 frame values", 0xC0050001)
    rows = tuple(row for row in freezes if len(row) == 84 and row[79] == pid)
    if not rows:
        raise ToyotaCodecError("Mode35 frame has no Freeze rows", 0xC0050101)
    positions, widths = [], []
    total = 0
    for identifier in identifiers:
        matches = [row for row in rows if row[83] == identifier]
        if not matches:
            raise ToyotaCodecError("Mode35 value lacks a Freeze definition", 0x90041103)
        base, different, width = 0xFFFF, False, 0
        for row in matches:
            candidate = (word(row, 62) - identifier * 8) & 65535
            width = (word(row, 64) - word(row, 62) + 1) & 65535
            if base == 0xFFFF:
                base = candidate
            else:
                # 8e0c4 sign-extends the incumbent, but zero-extends candidate.
                signed = base if base < 32768 else base - 65536
                if signed != candidate:
                    different = True
                    if signed >= candidate:
                        base = candidate
        if base == 0xFFFF:
            raise ToyotaCodecError(
                "Mode35 sentinel offset has no native map", 0x90041103
            )
        signed = base if base < 32768 else base - 65536
        if different and signed % 8:
            width = (abs(signed) // 8 * (-1 if signed < 0 else 1) * 8 + 8) & 65535
        widths.append(width)
        if width == 1:
            positions.append(((total >> 3) * 8 - (total % 8) + 7) & 65535)
            total = (total + 1) & 65535
        else:
            position = (total + 7) // 8 * 8
            positions.append(position & 65535)
            total = (position + width) & 65535
    total = ((total + 7) // 8 * 8) & 65535
    return Mode35FrameMap(pid, identifiers, tuple(positions), tuple(widths), total)


@dataclass(frozen=True)
class DataIdSupport:
    identifiers: tuple[int, ...]
    lengths: tuple[tuple[int, int], ...] = ()
    suppressed_errors: tuple[tuple[bytes, int], ...] = ()


@dataclass(frozen=True)
class TemporaryResponseCache:
    """One source-bound native CCommCachePlus instance's TEMP responses."""

    source_identity: tuple[object, ...]
    _responses: dict[tuple[object, ...], bytes] = field(
        default_factory=dict, repr=False
    )


@dataclass(frozen=True)
class CommSupportResult:
    supported: bool
    value: int | None = None


@dataclass(frozen=True)
class SendSupportObservation:
    status: int
    supported: bool
    ignored_failure: bool = False
    cache_hit: bool = True
    value: int | None = None


@dataclass(frozen=True)
class MultiReceiveResult:
    status: int
    replies: tuple[bytes, ...]


@dataclass(frozen=True)
class SupportQuery:
    """A selected payload transaction, with literal metadata and cache identity."""

    ecu: str
    request: bytes
    selected: SelectedFrame
    source_identity: tuple[object, ...]
    native_parameter: int = 0
    extended: bool = False
    capacity: int | None = None


class SupportTransaction(Protocol):
    def __call__(self, query: SupportQuery, /) -> bytes: ...


@dataclass(frozen=True)
class SupportSend:
    query: SupportQuery
    parameter4: int
    parameter5: int
    parameter6: int = 0
    parameter7: int = 1

    @property
    def request(self) -> bytes | None:
        return self.query.request or None


@dataclass(frozen=True)
class SupportReceive:
    query: SupportQuery
    capacity: int
    parameter4: int
    parameter5: int = 0
    wait_ms: int = 100


class SupportStream(Protocol):
    def send(self, send: SupportSend, /) -> int: ...
    def receive(self, receive: SupportReceive, /) -> tuple[int, bytes]: ...


class MonitorSupportCache:
    """Common native support producers over chronological payload transactions.

    Exchange receives a typed request and selected communication/timer records.
    A provider performs only the primitive transaction, never support decisions.
    """

    def __init__(
        self,
        profile: ProtocolProfile,
        exchange: SupportTransaction,
        ecu: str,
        *,
        limits: Limits | None = None,
        source_build: int = 18,
        stream: SupportStream | None = None,
        bus_id: int | None = None,
        cancelled: Callable[[], bool] = lambda: False,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not isinstance(ecu, str) or not ecu:
            raise ValueError("Support requires explicit ECU identity")
        if type(source_build) is not int or source_build not in (12, 18):
            raise ValueError("Native source build must be 12 or 18")
        self.source_build = self._selected_source_build = source_build
        self.profile, self.exchange, self.ecu = profile, exchange, ecu
        self.stream, self.bus_id = stream, bus_id
        self._support_bits: dict[
            tuple[object, ...], tuple[int, tuple[tuple[int, bytes], ...]]
        ] = {}
        self.limits, self.cancelled, self.clock = limits or Limits(), cancelled, clock
        self.identity = monitor_source_identity(profile, ecu)
        self._response_scope = self._discovery_scope = self.identity[1:]
        self._native_storage_namespace = False
        self.deadline = clock() + self.limits.seconds
        self.calls = 0
        self._responses: dict[tuple[object, ...], bytes] = {}
        self._temporary_responses: dict[tuple[object, ...], bytes] = {}
        self._temporary_identity = self.identity
        self._cache_hit = False
        self._mode35: dict[
            tuple[object, ...], tuple[int, tuple[tuple[int, bytes], ...]]
        ] = {}
        self._maps: dict[int, Mode35FrameMap] = {}
        self._data_ids: dict[int, DataIdSupport] = {}
        self._no_cache_data_ids: dict[int, DataIdSupport] = {}
        self._p5_support: dict[int, tuple[bool, bool]] = {}
        self._p5_active: set[int] = set()
        self._data_id_lengths: dict[int, dict[int, int]] = {}
        self._did_support_pages: set[int] = set()
        self._check()

    def begin_operation(self, *, limits: Limits | None = None) -> None:
        """Start a host operation budget while retaining native ECU cache state."""
        if self.cancelled():
            raise Cancelled("Support query cancelled")
        if monitor_source_identity(self.profile, self.ecu) != self.identity:
            raise SessionError("Selected source identity changed during support query")
        now = self.clock()
        if not math.isfinite(now):
            raise SessionError("Support operation clock is not finite")
        if limits is not None:
            self.limits = limits
        self.deadline = now + self.limits.seconds
        self.calls = 0
        self._temporary_responses.clear()
        self._check()

    def _check(self) -> None:
        if self.source_build != self._selected_source_build:
            raise SessionError("Selected native source build changed")
        if self.cancelled():
            raise Cancelled("Support query cancelled")
        now = self.clock()
        if (
            not math.isfinite(now)
            or not math.isfinite(self.deadline)
            or now >= self.deadline
        ):
            raise SessionError("Support query deadline exhausted")
        current = monitor_source_identity(self.profile, self.ecu)
        if current != self.identity:
            raise SessionError("Selected source identity changed during support query")

    def check_context(self) -> None:
        """Validate the selected source, host deadline and cancellation state."""
        self._check()

    @property
    def cache_hit(self) -> bool:
        """Whether the most recent response transaction read a native cache."""
        return self._cache_hit

    def response_cached(self, request: bytes, *, temporary: bool = False) -> bool:
        self._check()
        if not isinstance(request, bytes):
            raise TypeError("Native response-cache request must be immutable bytes")
        responses = self._temporary_responses if temporary else self._responses
        identity = self._temporary_identity if temporary else self._response_scope
        return (*identity, request) in responses

    def invalidate_response(self, request: bytes, *, temporary: bool = False) -> None:
        """Delete the first exact ECU/request entry; perform no transport I/O."""
        self._check()
        if not isinstance(request, bytes):
            raise TypeError("Native response-cache request must be immutable bytes")
        responses = self._temporary_responses if temporary else self._responses
        identity = self._temporary_identity if temporary else self._response_scope
        responses.pop((*identity, request), None)

    def _frames(self, function: int) -> tuple[SelectedFrame, ...]:
        try:
            frames = self.profile.frame_records(function)
        except ValueError as error:
            if str(error) in (
                "No selected function communication frames",
                "No selected communication frame",
            ):
                raise ToyotaCodecError(
                    "Selected support frame absent", 0xC0040101
                ) from error
            raise
        if not frames or len(frames) > 0x7FFF:
            raise ToyotaCodecError("Invalid selected support frames", 0xC0040102)
        return frames

    def _read(
        self,
        frame: SelectedFrame,
        request: bytes,
        *,
        cached=True,
        native_parameter: int = 0,
        extended: bool = False,
        temporary: bool = False,
        temporary_cache: dict[tuple[object, ...], bytes] | None = None,
        capacity: int | None = None,
    ) -> bytes:
        self._check()
        self.profile.validate_frame(frame)
        maximum = 0x1000 if extended else 255
        if capacity is not None:
            maximum = _uint(capacity, 65535 if extended else 255, "receive capacity")
            if maximum == 0:
                raise ToyotaCodecError("Zero native receive capacity", 0xC0040001)
        if not isinstance(request, bytes) or not 0 <= len(request) <= (
            65535 if extended else 255
        ):
            raise ToyotaCodecError(
                "Support request exceeds native byte length", 0xC0040102
            )
        _uint(native_parameter, 65535, "communication parameter")
        # CSndRcvBufferList::SearchBuffer matches ECU and literal send bytes;
        # different selected functions/timers do not create another cache entry.
        key = (
            *(self._temporary_identity if temporary else self._response_scope),
            request,
        )
        if temporary and cached:
            raise ValueError("Select either temporary or Ever cache")
        responses = (
            (self._temporary_responses if temporary_cache is None else temporary_cache)
            if temporary
            else self._responses
        )
        use_cache = cached or temporary
        self._cache_hit = use_cache and key in responses
        if self._cache_hit:
            reply = responses[key]
            if not reply:
                raise ToyotaCodecError("Cached native empty receive", 0x91010009)
            return reply
        if self.calls >= self.limits.exchanges:
            raise SessionError("Support query exchange budget exhausted")
        self.calls += 1
        try:
            reply = self.exchange(
                SupportQuery(
                    self.ecu,
                    request,
                    frame,
                    self.identity,
                    native_parameter,
                    extended,
                    capacity,
                )
            )
        except ToyotaCodecError as error:
            self._check()
            if use_cache and error.code in (0x91010009, 0x90020323):
                # SetSndRcvData60150 stores these failures as an empty receive;
                # CommCacheEverSndRcv5dcf1 returns timeout on subsequent hits.
                responses[key] = b""
            raise
        self._check()
        if not isinstance(reply, bytes):
            raise TypeError("Support transaction must return immutable bytes")
        if not request:
            if reply:
                raise SessionError("Send-only native transaction returned receive data")
        elif len(reply) > maximum:
            raise ToyotaCodecError("Receive exceeds native frame capacity", 0xA0040202)
        elif extended:
            if not reply:
                raise ToyotaCodecError(
                    "Extended receive exceeds native frame capacity", 0xA0040202
                )
            if reply[0] != (request[0] | 0x40):
                raise ToyotaCodecError("Extended receive service mismatch", 0xA0040201)
        else:
            CommandFrame(
                request, frame.frame.receive_mask, frame.frame.receive_check
            ).check_reply(reply)
        if use_cache:
            responses[key] = reply
        return reply

    def transaction(
        self,
        frame: SelectedFrame,
        request: bytes,
        *,
        native_parameter: int = 0,
        cached: bool = True,
        extended: bool = False,
        temporary: bool = False,
        capacity: int | None = None,
    ) -> bytes:
        """CommCacheSndRcv primitive with an explicit native ushort option."""
        if not isinstance(frame, SelectedFrame):
            raise TypeError("Communication cache requires selected frame metadata")
        return self._read(
            frame,
            request,
            cached=cached,
            native_parameter=native_parameter,
            extended=extended,
            temporary=temporary,
            capacity=capacity,
        )

    def _ecu_profile(self) -> VehicleProfile:
        self._check()
        if not isinstance(self.profile, VehicleProfile):
            raise SessionError("Selected context has no ECU database")
        return self.profile

    def _rows(self, slot: int, width: int, *, optional=False) -> tuple[bytes, ...]:
        if slot not in self._ecu_profile().database.sections:
            if optional:
                return ()
            raise ToyotaCodecError("Selected support table absent", 0xA0030107)
        rows = self._ecu_profile().records(slot)
        if len(rows) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        if any(len(row) != width for row in rows):
            raise ToyotaCodecError("Malformed selected support records", 0xC0040101)
        return rows

    def _options(self, pid: int) -> bytes:
        # 5b080: first DB237 PID row, then its DB111 variable send data.
        row = next(
            (row for row in self._rows(55, 8, optional=True) if row[4] == pid), None
        )
        if row is None:
            return b""
        section = self.profile.catalog.management.sections.get(17)
        if section is None:
            raise ToyotaCodecError("Additional support frame absent", 0xA0030107)
        comm = next(
            (item for item in section.rows(8) if word(item, 0) == word(row, 0)), None
        )
        if comm is None:
            raise ToyotaCodecError("Additional support frame missing", 0xC0040101)
        from scripts.toyota import VariableTable

        variables = self.profile.catalog.management.sections[0]
        return CommandFrame.from_record(
            comm, VariableTable(variables.payload, variables.count)
        ).request

    @staticmethod
    def _bitmap(base: int, data: bytes, candidates: list[int]) -> bool:
        # AnalyzeFrameData6c810 includes the queried base; continuation is OR
        # of every byte's bit0 (not only the final bitmap byte).
        candidates.append(base)
        continuation = False
        for index, byte in enumerate(data[:255]):
            for bit in range(8):
                pid = base + index * 8 + bit + 1
                if pid > 255:
                    break
                if byte & (0x80 >> bit):
                    candidates.append(pid)
            continuation |= bool(byte & 1)
        return continuation

    def _template(self, function: int) -> SelectedFrame:
        frames = self._frames(function)
        if len(frames) != 1:
            raise ToyotaCodecError("Support requires exactly one frame", 0xC0040102)
        return frames[0]

    def _init_ecu(self, frame: SelectedFrame) -> None:
        """InitEcu60250 NULL SendInt, flags1/1; native ignores send status."""
        if self.stream is None or self.bus_id is None:
            raise ToyotaCodecError(
                "InitEcu connection cache/bus identity absent", 0xC0040601
            )
        self._check()
        if self.calls >= self.limits.exchanges:
            raise SessionError("InitEcu primitive budget exhausted")
        if len(frame.settings_record) != 16:
            raise ToyotaCodecError("InitEcu timer record malformed", 0xC0040102)
        self.calls += 1
        query = SupportQuery(self.ecu, b"", frame, self.identity)
        self.stream.send(
            SupportSend(
                query,
                struct.unpack_from("<I", frame.settings_record)[0],
                self.bus_id,
                1,
                1,
            )
        )
        self._check()

    def valid_ids(
        self,
        *,
        function: int = 15,
        pid_offset: int = 1,
        receive_offset: int = 2,
        control: int = 0,
        value: int = 0,
    ) -> dict[int, int]:
        """First-match lookup projection; valid_id_entries retains native occurrences."""
        return first_pid_lengths(
            self.valid_id_entries(
                function=function,
                pid_offset=pid_offset,
                receive_offset=receive_offset,
                control=control,
                value=value,
            )
        )

    def valid_id_entries(
        self,
        *,
        function: int = 15,
        pid_offset: int = 1,
        receive_offset: int = 2,
        control: int = 0,
        value: int = 0,
    ) -> tuple[tuple[int, int], ...]:
        """CCmdValidIdListPidExt5ac30 DB203/206 and first DB237 extension."""
        self._ecu_profile()
        for number, limit, label in (
            (function, 65535, "function"),
            (pid_offset, 65535, "PID offset"),
            (receive_offset, 65535, "receive offset"),
            (control, 65535, "control offset"),
            (value, 255, "control value"),
        ):
            _uint(number, limit, label)
        frame = self._template(function)
        request = bytearray(frame.frame.request)
        if len(request) <= pid_offset or control and len(request) <= control:
            raise ToyotaCodecError("Support request offset outside frame", 0xC0040102)
        if control:
            request[control] = value
        support = tuple(row for row in self._rows(3, 8, optional=True) if row[5])
        candidates: list[int] = []
        if support:
            for row in support:
                base, mode = row[4:6]
                if mode == 2 and base not in candidates:
                    continue
                request[pid_offset] = base
                try:
                    reply = self._read(frame, bytes(request))
                except ToyotaCodecError as error:
                    if error.code in (0x91010009, 0x90020323):
                        if not self._cache_hit:
                            self._init_ecu(frame)
                        continue
                    raise
                if len(reply) <= receive_offset:
                    raise ToyotaCodecError(
                        "Support bitmap header truncated", 0xA0040202
                    )
                self._bitmap(base, reply[receive_offset:], candidates)
        definition_rows = self._rows(6, 8) if not support else ()
        if not support:
            candidates = [row[2] for row in definition_rows]
        result: list[tuple[int, int]] = []
        # The selected database is immutable; memoize only queries already reached.
        queried_rows: dict[int, tuple[bytes, ...]] = {}
        for index, pid in enumerate(candidates):
            self._check()
            if support:
                if pid not in queried_rows:
                    queried_rows[pid] = self._ecu_profile().pid_records(pid)
                rows = queried_rows[pid]
                if not rows:
                    continue
                length = rows[0][3]
            else:
                length = definition_rows[index][3]
            if not length:
                request[pid_offset] = pid
                try:
                    reply = self._read(
                        frame, bytes(request) + self._options(pid), cached=True
                    )
                except ToyotaCodecError as error:
                    ignored = (
                        (0x91010009, 0x90020323)
                        if support
                        else (0x91010009, 0x90020323, 0x90020321)
                    )
                    if error.code in ignored:
                        continue
                    raise
                if len(reply) <= receive_offset:
                    raise ToyotaCodecError(
                        "Support reply shorter than offset", 0xA0040202
                    )
                length = (len(reply) - receive_offset) & 255
            result.append((pid, length))
        self._check()
        return tuple(result)

    def enabled_pids(
        self,
        *,
        family: str = "valid_ext",
        kind: int = 1,
        control: int = 0,
        force: bool = False,
    ) -> dict[int, int]:
        """First-match host lookup projection of enabled_pid_entries."""
        return first_pid_lengths(
            self.enabled_pid_entries(
                family=family, kind=kind, control=control, force=force
            )
        )

    def enabled_pid_entries(
        self,
        *,
        family: str = "valid_ext",
        kind: int = 1,
        control: int = 0,
        force: bool = False,
    ) -> tuple[tuple[int, int], ...]:
        """CreateEnablePidList6bdc0 / Ext6ead0 selected native byte PID lists."""
        if family == "valid_ext":
            if kind != 1 or force:
                raise ValueError(
                    "ValidIdExt requires PID kind1 and no force invalidation"
                )
            return self.valid_id_entries(control=control)
        if family not in (
            "normal",
            "no_frame_number",
            "ext",
            "p4",
            "p4_ignore",
            "a8",
        ) or kind not in ((1, 2, 3, 4) if family in ("p4", "p4_ignore") else (1, 2, 3)):
            raise ValueError("Unsupported native enable-list family/kind")
        _uint(control, 255, "control")
        support = self._rows(
            4 if kind == 2 and family not in ("p4", "p4_ignore", "a8") else 3,
            8,
            optional=family == "ext",
        )
        definition_slot, width = (7, 8) if kind == 2 else (6, 8)
        definitions = {}
        definition_rows = (
            self._rows(definition_slot, width)
            if family != "normal" or kind == 2
            else ()
        )
        for row in definition_rows:
            definitions.setdefault(
                row[4] if kind == 2 else row[2], row[5] if kind == 2 else row[3]
            )
        if not support and family in (
            "normal",
            "no_frame_number",
            "p4",
            "p4_ignore",
            "a8",
        ):
            raise ToyotaCodecError("Native support definitions empty", 0xC0040101)
        function = {1: 15, 2: 14, 3: 0x63, 4: 0xE3}[kind]
        frame = self._template(function)
        request = bytearray(frame.frame.request)
        if (
            len(request) < 2
            and family != "a8"
            and not (family in ("p4", "p4_ignore") and kind == 2)
        ):
            raise ToyotaCodecError("Support request too short", 0xC0040102)
        if force and family != "normal":
            raise ValueError(
                "Native forced request invalidation belongs to normal PID helper"
            )
        candidates: list[int] = []
        observed_bits = (
            self.support_bits(2)
            if family in ("p4", "p4_ignore") and kind == 2
            else self.support_bits(1)
            if family == "a8"
            else None
        )
        if family in ("p4", "p4_ignore") and kind == 2:
            candidates.extend(pid for pid, _ in self.support_bit_entries(2))
        for row in support:
            if family in ("p4", "p4_ignore") and kind == 2:
                break
            if family == "a8":
                data = (observed_bits or {}).get(row[4])
                if data is not None:
                    self._bitmap(row[4], data, candidates)
                continue
            base, mode = row[4:6]
            if mode == 2 and family in ("p4", "p4_ignore") and base not in candidates:
                continue
            if kind in (3, 4):
                if len(request) not in (3, 4):
                    raise ToyotaCodecError(
                        "Freeze support request geometry", 0xC0040102
                    )
                request[2 if len(request) == 3 else 1] = control
            request[3 if kind in (3, 4) and len(request) == 4 else 1] = base
            if force:
                self.invalidate_response(bytes(request))
            try:
                reply = self._read(frame, bytes(request))
            except ToyotaCodecError as error:
                if error.code in (
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
                    if family == "p4_ignore"
                    else (0x91010009, 0x90020323, 0x90020321)
                    if family == "ext"
                    else (0x91010009, 0x90020323)
                ):
                    if not self._cache_hit:
                        self._init_ecu(frame)
                    continue
                raise
            offset = (
                3
                if kind in (3, 4) and len(request) == 3
                else 4
                if kind in (3, 4)
                else 2
            )
            data = (
                reply[offset - 2 : -2]
                if (kind in (3, 4) or family == "no_frame_number") and len(request) == 4
                else reply[offset:]
            )
            if family == "no_frame_number" and len(request) != 4:
                if kind != 3:
                    raise ToyotaCodecError(
                        "NoFrmNo requires a freeze reply", 0xC0040001
                    )
                # 12:4c2e3/18:705f3 derives the header from the base PID's length.
                length = definitions.get(base, 0)
                if base in definitions and not length:
                    length = (
                        len(self._read(frame, bytes(request))) - len(request)
                    ) & 255
                offset = (len(reply) - length) & 255
                if not length or offset not in (2, 3):
                    raise ToyotaCodecError("NoFrmNo reply geometry", 0xA0040202)
                data = reply[offset:]
            self._bitmap(base, data, candidates)
        if not support:
            candidates = [row[4] if kind == 2 else row[2] for row in definition_rows]
        result: list[tuple[int, int]] = []
        queried_rows: dict[int, tuple[bytes, ...]] = {}
        for index, pid in enumerate(candidates):
            self._check()
            if family == "normal" and kind != 2:
                if pid not in queried_rows:
                    queried_rows[pid] = self._ecu_profile().pid_records(pid)
                rows = queried_rows[pid]
                if not rows:
                    continue
                length = rows[0][3]
            else:
                if pid not in definitions:
                    continue
                length = (
                    definitions[pid]
                    if support
                    else definition_rows[index][5 if kind == 2 else 3]
                )
            if not length and family in ("p4", "p4_ignore") and observed_bits is None:
                observed_bits = self.support_bits(2 if kind == 2 else 1)
            if (
                not length
                and observed_bits is not None
                and family in ("p4", "p4_ignore")
            ):
                if pid not in observed_bits:
                    continue
                length = len(observed_bits[pid]) & 255
            elif not length and kind != 2:
                request[3 if len(request) == 4 else 1] = pid
                try:
                    reply = self._read(frame, bytes(request), cached=True)
                except ToyotaCodecError as error:
                    if error.code in (0x91010009, 0x90020323):
                        continue
                    raise
                # 18:6cbc1/6cbcb, 12:488b1/488bb subtract native request BYTE.
                length = (len(reply) - len(request)) & 255
            result.append((pid, length))
        self._check()
        return tuple(result)

    def pcs_operation_pids(
        self, *, kind: int = 1, control: int = 0, force: bool = False
    ) -> dict[int, int]:
        """First-match host lookup projection of pcs_operation_pid_entries."""
        return first_pid_lengths(
            self.pcs_operation_pid_entries(kind=kind, control=control, force=force)
        )

    def pcs_operation_pid_entries(
        self,
        *,
        kind: int = 1,
        control: int = 0,
        force: bool = False,
    ) -> tuple[tuple[int, int], ...]:
        """CreateEnablePCSOpeFfdPidListP4: bitmap candidates, DB256, raw PID lengths."""
        self._check()
        if type(kind) is not int or kind not in (1, 3):
            raise ToyotaCodecError("Invalid PCS operation PID kind", 0xC0040001)
        _uint(control, 255, "PCS control")
        if type(force) is not bool:
            raise ValueError("PCS forced invalidation must be boolean")
        support = self._rows(3, 8)
        if not support:
            raise ToyotaCodecError("Native support definitions empty", 0xC0040101)
        frame = self._template(0x0F if kind == 1 else 0x0E)
        request = bytearray(frame.frame.request)
        if len(request) < 2:
            raise ToyotaCodecError("PCS support request too short", 0xC0040102)
        candidates: list[int] = []
        for row in support:
            base, mode = row[4:6]
            if mode == 2 and base not in candidates:
                continue
            offset = 2
            if kind == 3:
                if len(request) not in (3, 4):
                    raise ToyotaCodecError("PCS support request geometry", 0xC0040102)
                request[2 if len(request) == 3 else 1] = control
                offset = len(request)
            request[3 if kind == 3 and len(request) == 4 else 1] = base
            if force:
                self.invalidate_response(bytes(request))
            try:
                reply = self._read(frame, bytes(request))
            except ToyotaCodecError as error:
                if error.code not in (0x91010009, 0x90020323):
                    raise
                if not self._cache_hit:
                    self._init_ecu(frame)
                continue
            data = reply[offset - 2 : -2] if len(request) == 4 else reply[offset:]
            self._bitmap(base, data, candidates)
        result: list[tuple[int, int]] = []
        for pid in candidates:
            self._check()
            if not self._ecu_profile().pcs_operation_pid_records():
                continue
            observed = self.support_bits(1)
            if pid in observed:
                result.append((pid, len(observed[pid]) & 255))
        self._check()
        return tuple(result)

    def mode35(self) -> dict[int, bytes]:
        """CreateLid26d60, native CB pages, FF LID escapes and Freeze truncation."""
        self._ecu_profile()
        self._check()
        key = self._discovery_scope
        if key in self._mode35:
            status, entries = self._mode35[key]
            if status:
                raise ToyotaCodecError("Cached Mode35 discovery failure", status)
            return dict(entries)
        values: dict[int, bytearray] = {}
        lid, pending = 0, False
        responses: dict[tuple[object, ...], bytes] = {}
        for frame in self._frames(0xCB):
            request = bytearray(frame.frame.request)
            if len(request) < 5:
                raise ToyotaCodecError("Mode35 request lacks page counter", 0xC0040102)
            while True:
                try:
                    reply = self._read(
                        frame,
                        bytes(request),
                        cached=False,
                        temporary=True,
                        temporary_cache=responses,
                    )
                except ToyotaCodecError:
                    # 270bf ignores the helper's status, then stores partial list.
                    break
                if len(reply) < 7 or len(reply) < 7 + reply[6]:
                    raise ToyotaCodecError("Mode35 page truncated", 0xA0040202)
                for index, value in enumerate(reply[7 : 7 + reply[6]]):
                    if (request[2:5] == b"\0\0\1" and index == 0) or pending:
                        lid, pending = value | request[1], False
                    elif value == 255:
                        pending = True
                    else:
                        values.setdefault(lid, bytearray()).append(value)
                if reply[2] == 255:
                    break
                page = (int.from_bytes(request[2:5], "big") + 1) & 0xFFFFFF
                request[2:5] = page.to_bytes(3, "big")
        try:
            rows = self._rows(10, 84)
        except ToyotaCodecError as error:
            # N_DelUnSupportedFrameValue stores its native failure in ECU info.
            self._mode35[key] = (error.code, ())
            raise
        result = {}
        for pid, identifiers in values.items():
            supported = bytearray()
            for value in identifiers:
                if not any(row[79] == pid and row[83] == value for row in rows):
                    break
                supported.append(value)
            result[pid] = bytes(supported)
        self._mode35[key] = (0, tuple(result.items()))
        return dict(result)

    def support_bits(
        self, kind: int = 1, *, no_retry: bool = False
    ) -> dict[int, bytes]:
        """First-match GetData lookup; support_bit_entries preserves native chunks."""
        result: dict[int, bytes] = {}
        for pid, payload in self.support_bit_entries(kind, no_retry=no_retry):
            result.setdefault(pid, payload)
        return result

    def support_bit_entries(
        self,
        kind: int = 1,
        *,
        no_retry: bool = False,
    ) -> tuple[tuple[int, bytes], ...]:
        """CCmdSupportBitList54740: raw13/14/82/A9 stream until timeout."""
        self._ecu_profile()
        if kind not in (1, 2, 3, 4):
            raise ValueError("Invalid native support-bit kind")
        self._check()
        key = (*self._discovery_scope, kind)
        if key in self._support_bits:
            status, data = self._support_bits[key]
            if status:
                raise ToyotaCodecError("Cached support-bit discovery failure", status)
            return data
        if self.stream is None or self.bus_id is None:
            raise ToyotaCodecError(
                "Support-bit primitive stream/bus identity absent", 0xC0040601
            )
        _uint(self.bus_id, 65535, "observed bus ID")
        if type(no_retry) is not bool or (no_retry and kind not in (1, 3)):
            raise ToyotaCodecError("Invalid native NoRetry support kind", 0xC0040102)
        # Native NoRetry names select DE/DF templates; retry count still comes
        # from selected settings (56060), rather than an invented zero limit.
        function = (
            {1: 0xDE, 3: 0xDF}[kind]
            if no_retry
            else {1: 0x13, 2: 0x14, 3: 0x82, 4: 0xA9}[kind]
        )
        frame = self._template(function)
        settings = frame.settings_record
        if len(settings) != 16 or not frame.frame.request:
            raise ToyotaCodecError(
                "Support-bit frame/timer geometry invalid", 0xC0040102
            )
        send_timer, receive_timer = struct.unpack_from("<II", settings)
        receive_timer = self._receive_timer(frame, self.bus_id)
        query = SupportQuery(self.ecu, frame.frame.request, frame, self.identity)
        received = 0
        sending = True
        result: list[tuple[int, bytes]] = []
        status = 0
        for _ in range(settings[14] + 1):
            if sending:
                self._check()
                if self.calls >= self.limits.exchanges:
                    raise SessionError("Support stream primitive budget exhausted")
                self.calls += 1
                status = self.stream.send(SupportSend(query, send_timer, self.bus_id))
                self._check()
                _uint(status, 0xFFFFFFFF, "support stream send status")
                if status:
                    continue
            while True:
                self._check()
                if self.calls >= self.limits.exchanges:
                    raise SessionError("Support stream primitive budget exhausted")
                self.calls += 1
                status, reply = self.stream.receive(
                    SupportReceive(query, 255, receive_timer)
                )
                self._check()
                _uint(status, 0xFFFFFFFF, "support stream receive status")
                if status == 0x91010009:
                    if received:
                        entries = tuple(result)
                        self._support_bits[key] = (0, entries)
                        return entries
                    break
                if status:
                    break
                if (
                    not isinstance(reply, bytes)
                    or not 0 < len(reply) <= 255
                    or reply[0] != (query.request[0] | 0x40)
                ):
                    status = 0xA0040201
                    break
                sending = False
                offset = 2
                # Native malformed tail stops this page's chunk scan, yet the
                # valid page still counts toward received; preserve that choice.
                while len(reply) > offset + 2:
                    length = reply[offset + 1]
                    end = offset + length + 2
                    if not length or end > len(reply):
                        break
                    result.append((reply[offset], reply[offset + 2 : end]))
                    offset = end
                received += 1
        self._support_bits[key] = (status, ())
        raise ToyotaCodecError("Support-bit discovery failed", status)

    def _receive_timer(self, frame: SelectedFrame, bus_id: int) -> int:
        receive_timer = struct.unpack_from("<I", frame.settings_record, 4)[0]
        # CConvertUtil6bbe0 replaces the timeout for selected CAN protocol rows.
        version = self.source_build
        # Version12 native35f72 passes the selected receive timer directly.
        if version == 18:
            try:
                protocol = self.profile.protocol_info(bus_id)
            except ToyotaCodecError:
                protocol = None
            if (
                protocol is not None
                and protocol[26] == 1
                and 1 <= frame.frame.request[0] <= 10
            ):
                try:
                    can_rows = self.profile.comm_info_can_records(word(protocol, 2))
                except ToyotaCodecError as error:
                    if error.code != 0xA0030107:
                        raise
                    can_rows = ()
                if can_rows:
                    receive_timer = word(can_rows[0], 14)
        return receive_timer

    def multi_receive(
        self, frame: SelectedFrame, *, native_parameter: int = 0, capacity: int = 255
    ) -> MultiReceiveResult:
        """CommFrameSendMultiReceive61720: send once after any accepted reply."""
        self._check()
        self.profile.validate_frame(frame)
        if self.stream is None:
            raise ToyotaCodecError("Multi-receive primitive stream absent", 0xC0040601)
        bus = _uint(native_parameter, 65535, "multi-receive bus ID")
        if bus == 0:
            if self.bus_id is None:
                raise ToyotaCodecError(
                    "Multi-receive connection cache absent", 0xC0040601
                )
            bus = _uint(self.bus_id, 65535, "connected bus ID")
        _uint(capacity, 255, "multi-receive capacity")
        if not isinstance(frame, SelectedFrame) or len(frame.settings_record) != 16:
            raise ToyotaCodecError("Invalid multi-receive metadata", 0xC0040102)
        request = frame.frame.request
        if not isinstance(request, bytes) or not 1 <= len(request) <= 255:
            raise ToyotaCodecError("Invalid multi-receive request", 0xC0040102)
        query = SupportQuery(self.ecu, request, frame, self.identity, bus)
        send_timer = struct.unpack_from("<I", frame.settings_record)[0]
        replies: list[bytes] = []
        status = 0
        for _ in range(frame.settings_record[14] + 1):
            if replies:
                break
            self._primitive_budget()
            status = self.stream.send(SupportSend(query, send_timer, bus))
            self._check()
            _uint(status, 0xFFFFFFFF, "multi-receive send status")
            if status:
                continue
            receive_timer = self._receive_timer(frame, bus)
            while True:
                self._primitive_budget()
                status, reply = self.stream.receive(
                    SupportReceive(query, capacity, receive_timer)
                )
                self._check()
                _uint(status, 0xFFFFFFFF, "multi-receive status")
                if not isinstance(reply, bytes) or len(reply) > capacity:
                    raise TypeError("Multi-receive must return bounded immutable bytes")
                if status == 0x90020323:
                    return MultiReceiveResult(status, tuple(replies))
                if status == 0x91010009 and replies:
                    return MultiReceiveResult(0, tuple(replies))
                if status:
                    break
                if not reply or reply[0] != (request[0] | 0x40):
                    status = 0xA0040201
                    break
                replies.append(reply)
        return MultiReceiveResult(status, tuple(replies))

    def _primitive_budget(self) -> None:
        self._check()
        if self.calls >= self.limits.exchanges:
            raise SessionError("Support primitive budget exhausted")
        self.calls += 1

    @staticmethod
    def _data_id_bitmap(
        base: int, data: bytes, shift: int, identifiers: list[int]
    ) -> None:
        """AnalyzeFrameData57950; group query skips the final continuation bit."""
        for index, byte in enumerate(data[:32]):
            for bit in range(8):
                if shift == 0 and index == 31 and bit == 7:
                    break
                if byte & (0x80 >> bit):
                    value = (
                        base + ((index * 8 + bit + (1 if shift == 0 else 0)) << shift)
                    ) & 65535
                    identifiers.append(value)

    def data_ids(
        self,
        *,
        family: str = "normal",
        designation: Sequence[int] = (),
        excluded: Sequence[int] = (),
        response_cache: TemporaryResponseCache | None = None,
    ) -> DataIdSupport:
        """CreateEnableDataIdList569d0: C8 upper/group pages and partial cache."""
        self._ecu_profile()
        self._check()
        if family not in (
            "normal",
            "designation",
            "with_bus_id",
            "mazda",
            "subaru",
            "no_cache",
        ):
            raise ValueError("Invalid native DataId producer family")
        if self.source_build == 12 and family in ("with_bus_id", "subaru", "no_cache"):
            raise SessionError("Selected DataId producer is absent from native build12")
        if response_cache is not None:
            if family != "no_cache":
                raise ValueError(
                    "Only native NoCache accepts a supplied response cache"
                )
            if type(
                response_cache
            ) is not TemporaryResponseCache or response_cache.source_identity != (
                *self.identity,
                self.source_build,
            ):
                raise SessionError(
                    "Native TEMP cache belongs to another selected context"
                )
        if len(designation) > 0xFFFFFFFF or len(excluded) > 0xFFFFFFFF:
            raise ValueError("DataId designation exceeds native DWORD count")
        for did in (*designation, *excluded):
            _uint(did, 65535, "designated DID")
        cache = self._no_cache_data_ids if family == "no_cache" else self._data_ids
        local_responses: dict[tuple[object, ...], bytes] = (
            {} if response_cache is None else response_cache._responses
        )
        if (
            family in ("normal", "with_bus_id", "no_cache")
            and self.profile.category in cache
        ):
            return cache[self.profile.category]
        if (
            family == "subaru"
            or family == "mazda"
            or (
                family in ("normal", "with_bus_id", "no_cache")
                and self.profile.category_record[72] & 31 == 21
            )
        ):
            if family in ("normal", "with_bus_id", "no_cache"):
                output: list[int] = []
                try:
                    result = self._enumerated_data_ids(family, output=output)
                except ToyotaCodecError:
                    # Native automatic Mazda callers pack partial output, ignoring status.
                    lengths = self._data_id_lengths.get(self.profile.category, {})
                    result = DataIdSupport(tuple(output), tuple(lengths.items()))
            else:
                result = self._enumerated_data_ids(family)
            if family in ("normal", "with_bus_id", "no_cache"):
                cache[self.profile.category] = result
            return result
        native_parameter = 0
        if family == "with_bus_id":
            if self.bus_id is None:
                raise ToyotaCodecError("Explicit DataId bus ID absent", 0xC0040601)
            native_parameter = _uint(self.bus_id, 65535, "DataId bus ID")
        identifiers: list[int] = list(designation) if family == "designation" else []
        errors: list[tuple[bytes, int]] = []
        try:
            frame = self._frames(0xC8)[0]
        except ToyotaCodecError as error:
            if family == "designation":
                raise
            result = DataIdSupport((), (), ((b"", error.code),))
            if family in ("normal", "with_bus_id", "no_cache"):
                cache[self.profile.category] = result
            return result
        request = bytearray(frame.frame.request)
        if len(request) < 3:
            raise ToyotaCodecError(
                "DataId C8 template lacks two identifier bytes", 0xC0040102
            )
        if family in ("normal", "with_bus_id", "no_cache"):
            try:
                reply = self._read(
                    frame,
                    bytes(request),
                    extended=True,
                    native_parameter=native_parameter,
                    cached=family in ("normal", "with_bus_id"),
                    temporary=family in ("no_cache", "designation"),
                    temporary_cache=local_responses
                    if family in ("designation", "no_cache")
                    else None,
                )
            except ToyotaCodecError as error:
                errors.append((bytes(request), error.code))
                reply = b""
            if len(reply) > 3:
                self._data_id_bitmap(0, reply[3:35], 8, identifiers)
            groups = tuple(identifiers)
        else:
            groups = tuple(designation)
        for group in groups:
            if group == 0xF300 and family in ("normal", "with_bus_id", "no_cache"):
                continue
            if family == "no_cache" and group in excluded:
                continue
            request[1:3] = group.to_bytes(2, "big")
            try:
                reply = self._read(
                    frame,
                    bytes(request),
                    extended=True,
                    native_parameter=native_parameter,
                    cached=family in ("normal", "with_bus_id"),
                    temporary=family in ("no_cache", "designation"),
                    temporary_cache=local_responses
                    if family in ("designation", "no_cache")
                    else None,
                )
            except ToyotaCodecError as error:
                errors.append((bytes(request), error.code))
                continue
            if len(reply) > 3:
                self._data_id_bitmap(group, reply[3:35], 0, identifiers)
        self._check()
        result = DataIdSupport(tuple(identifiers), (), tuple(errors))
        if family == "no_cache":
            self._no_cache_data_ids[self.profile.category] = result
        elif family in ("normal", "with_bus_id"):
            cache[self.profile.category] = result
        return result

    def subaru_did_support(self, identifiers: Sequence[int]) -> DataIdSupport:
        """SubaruCheckDIDSupport58bc0: native 32-bit pages and attempted-page cache."""
        self._ecu_profile()
        self._check()
        if self.source_build == 12:
            raise SessionError(
                "Subaru DID-support producer is absent from native build12"
            )
        if len(identifiers) > 0xFFFFFFFF:
            raise ValueError("Subaru support identifiers exceed native DWORD count")
        for did in identifiers:
            _uint(did, 65535, "Subaru support DID")
        frame = self._frames(0x10E)[0]
        request = bytearray(frame.frame.request)
        if len(request) < 3:
            raise ToyotaCodecError("Subaru support template is short", 0xC0040102)
        known = self._data_ids.get(self.profile.category, DataIdSupport(()))
        enabled = list(known.identifiers)
        errors = list(known.suppressed_errors)
        stopped = False
        # Native five consecutive ushort triplets at CommandCommon18:b19bc.
        ranges = (
            (0x200, 0x2E0, 32),
            (0x300, 0xFE0, 32),
            (0x1000, 0x1FE0, 32),
            (0x2000, 0x2FE0, 32),
            (0x3000, 0xEFE0, 32),
        )
        for did in identifiers:
            selected = next(
                (
                    (base, end, step)
                    for base, end, step in ranges
                    if base <= did < end + step
                ),
                None,
            )
            if selected is None:
                continue
            base, end, step = selected
            while base <= end:
                self._check()
                if base not in self._did_support_pages:
                    request[1:3] = base.to_bytes(2, "big")
                    try:
                        reply = self._read(frame, bytes(request), extended=True)
                    except ToyotaCodecError as error:
                        errors.append((bytes(request), error.code))
                        reply = b""
                        stopped = error.code == 0x91010009
                    self._did_support_pages.add(base)
                    if len(reply) > 3:
                        self._data_id_bitmap(base, reply[3:7], 0, enabled)
                    if stopped:
                        break
                base += step
                if did <= base or base not in enabled:
                    break
            if stopped:
                break
        self._check()
        result = DataIdSupport(tuple(enabled), known.lengths, tuple(errors))
        self._data_ids[self.profile.category] = result
        return result

    def _enumerated_data_ids(
        self, family: str, *, output: list[int] | None = None
    ) -> DataIdSupport:
        """Mazda57b00/Subaru59260: actual selected candidates, CA replies, lengths."""
        category = self.profile.category
        if family == "subaru" and category in self._data_id_lengths:
            lengths = self._data_id_lengths[category]
            return DataIdSupport(tuple(lengths), tuple(lengths.items()))
        frame = self._frames(0xCA)[0]
        request = bytearray(frame.frame.request)
        if len(request) < 3:
            raise ToyotaCodecError("DataId CA template is short", 0xC0040102)
        lengths = self._data_id_lengths.get(category, {})
        identifiers: list[int] = [] if output is None else output
        errors: list[tuple[bytes, int]] = []

        def probe(did: int) -> int | None:
            self._check()
            if did in lengths:
                return
            request[1:3] = did.to_bytes(2, "big")
            try:
                # CheckDataIdLength58160 calls the temporary cache, not Ever cache.
                reply = self._read(frame, bytes(request), cached=False, extended=True)
            except ToyotaCodecError as error:
                errors.append((bytes(request), error.code))
                return error.code
            if len(reply) > 3:
                lengths[did] = (len(reply) - 3) & 65535
                if did not in identifiers:
                    identifiers.append(did)
            return 0

        # Missing either DataId source is explicitly logged and skipped natively.
        for slot, width in ((61, 8), (67, 12)):
            for row in self._rows(slot, width, optional=True):
                probe(word(row, 2))
        management = self.profile.catalog.management
        if 20 not in management.sections:
            raise ToyotaCodecError("CustSignList table absent", 0xA0030107)
        status = 0
        for sign in correspondence_rows(management, 20, self.profile.exception_ids):
            items = self._ecu_profile().custom_item_records(word(sign, 4))
            status = 0
            for item in items:
                if word(item, 12) == category:
                    for offset in (38, 40, 42):
                        observed = probe(word(item, offset))
                        if observed is not None:
                            status = observed
        self._check()
        self._data_id_lengths[category] = lengths
        if family != "subaru" and status:
            raise ToyotaCodecError("Mazda final custom-item probe failed", status)
        return DataIdSupport(tuple(identifiers), tuple(lengths.items()), tuple(errors))

    def check_freeze_pid(
        self,
        freeze: bytes,
        freeze_pid_lengths: Mapping[int, int],
        *,
        pid_lengths: Mapping[int, int],
    ) -> bool:
        """Native18:5eed0/12:3e5d0 with distinct freeze and normal PID lists."""
        from scripts.toyota import pid_support_p3

        self._check()
        if not isinstance(freeze, bytes) or len(freeze) != 84:
            raise ToyotaCodecError("Malformed selected Freeze row", 0xC0040001)
        if freeze not in self._rows(10, 84):
            raise SessionError("Freeze row belongs to another selected source")
        available = _uint(
            freeze_pid_lengths.get(freeze[79], 0), 255, "freeze PID length"
        )
        early = pid_support_p3(freeze, available)
        if early is not None:
            return early
        rows = self._ecu_profile().pid_bit_records(word(freeze, 58))
        if not rows:
            return False
        row = rows[0]
        variable = self._ecu_profile().pid_bit_variable(row)
        if not variable:
            raise ToyotaCodecError("Empty native PidBit variable", 0xC0040102)
        return self._legacy_support_bit(row, variable, pid_lengths)

    def _legacy_support_bit(
        self,
        row: bytes,
        variable: bytes,
        pid_lengths: Mapping[int, int],
    ) -> bool:
        """CheckSupportBit18:5f100/12:3e800; Freeze passes NULL second list."""
        if len(row) != 12 or row[11] not in (2, 3, 4):
            raise ToyotaCodecError("Invalid native PidBit selector", 0xC0040102)
        selector = row[11]
        function = {2: 0x10, 3: 0x69, 4: 0x6A}[selector]
        management = self.profile.catalog.management
        if 18 not in management.sections:
            raise ToyotaCodecError("Selected function table absent", 0xA0030107)
        functions = tuple(
            record
            for record in correspondence_rows(
                management, 18, self.profile.exception_ids
            )
            if word(record, 0) == self.profile.category and word(record, 2) == function
        )
        if not functions:
            raise ToyotaCodecError("Support function records empty", 0xC0040102)
        frame = self._frames(function)[0]
        if len(variable) != (2 if selector == 4 else 1):
            raise ToyotaCodecError("Native PidBit identifier length", 0xC0040102)
        if selector == 3:
            raise SessionError(
                "Native Freeze PidBit selector3 dereferences a NULL DID list"
            )
        if selector == 2 and variable[0] not in pid_lengths:
            return False
        request = bytearray(frame.frame.request)
        if not request:
            raise ToyotaCodecError("Empty support frame", 0xC0040102)
        offset = 2 if selector == 4 else 1
        for index, value in enumerate(variable, offset):
            # CommandDataLib.GetAt uses the first node for an out-of-range index.
            request[index if index < len(request) else 0] = value
        try:
            reply = self._read(frame, bytes(request))
        except ToyotaCodecError as error:
            if error.code in (0x91010009, 0x90020323):
                return False
            raise
        header = 4 if selector == 4 else 2
        if len(reply) <= header:
            raise ToyotaCodecError("Native support payload absent", 0xA0040201)
        first, last = word(row, 6), word(row, 8)
        if first > last:
            raise ToyotaCodecError("Native support bit start exceeds end", 0xC0000001)
        if last >= (len(reply) - header) * 8:
            raise SessionError("Native support bit access exceeds recovered storage")
        return extract_bits(reply[header:], first, last) != 0

    def check_support_pid(
        self,
        signal_id: int,
        *,
        enabled_dids: Sequence[int] | None = None,
        raw_support: bool = True,
        source_build: int | None = None,
    ) -> bool:
        """P5 CheckSupportPid63070/12:42040, including dynamic cached conditions."""
        _uint(signal_id, 65535, "P5 signal ID")
        self._check()
        version = self.source_build if source_build is None else source_build
        if type(version) is not int or version not in (12, 18):
            raise ValueError("Native P5 support source build must be 12 or 18")
        if version != self.source_build:
            raise ValueError("P5 support source build differs from its cache context")
        row = next((r for r in self._rows(62, 64) if word(r, 36) == signal_id), None)
        if row is None:
            raise ToyotaCodecError("P5 monitor signal missing", 0xC0040101)
        if signal_id in self._p5_active:
            raise SessionError("P5 support dependency cycle")
        if enabled_dids is None:
            enabled_dids = self.data_ids().identifiers
        if len(enabled_dids) > 0xFFFFFFFF:
            raise ValueError("Enabled DataId list exceeds native DWORD count")
        for did in enabled_dids:
            _uint(did, 65535, "enabled DID")
        self._p5_active.add(signal_id)
        try:
            if signal_id in self._p5_support:
                supported, dynamic = self._p5_support[signal_id]
                if dynamic:
                    try:
                        supported = self._p5_condition(row, enabled_dids, version)
                    except ToyotaCodecError:
                        supported = False
            else:
                supported, dynamic = False, False
                did = word(row, 54)
                try:
                    if did in enabled_dids:
                        if self.profile.category_record[72] & 31 == 21:
                            length = self._data_id_lengths.get(
                                self.profile.category, {}
                            ).get(did)
                            supported = length is not None and length * 8 > word(
                                row, 46
                            )
                        else:
                            definitions = tuple(
                                r for r in self._rows(61, 8) if word(r, 2) == did
                            )
                            if definitions:
                                frame = self._frames(0xCA)[0]
                                request = frame.frame.request
                                if len(request) < 3:
                                    raise ToyotaCodecError(
                                        "P5 CA template is short", 0xC0040102
                                    )
                                reply = self._read(
                                    frame,
                                    request[:1] + did.to_bytes(2, "big") + request[3:],
                                    cached=False,
                                    temporary=True,
                                    extended=True,
                                )
                                if len(reply) > 3 and (
                                    (len(reply) - 3) & 65535
                                ) * 8 > word(row, 46):
                                    mode = definitions[0][6]
                                    if mode in (0, 2):
                                        supported = True
                                    elif mode == 1:
                                        end = word(row, 46)
                                        position = (end >> 3) + 2
                                        if position >= len(reply):
                                            raise ToyotaCodecError(
                                                "P5 support byte is absent", 0xA0040202
                                            )
                                        mask = 0x80 >> (end & 7)
                                        supported = reply[position] & mask == mask
                                    if supported and word(row, 38):
                                        supported = self._p5_condition(
                                            row, enabled_dids, version
                                        )
                                        dynamic = (
                                            version == 18
                                            and self._p5_condition_mode(row) in (1, 2)
                                        )
                except ToyotaCodecError:
                    supported = False
                self._p5_support[signal_id] = (supported, dynamic)
            self._check()
            if raw_support or row[59] == 0:
                return supported
            return row[59] == 1
        finally:
            self._p5_active.remove(signal_id)

    def _p5_condition_mode(self, monitor: bytes) -> int:
        rows = self._ecu_profile().data_id_bit_records(word(monitor, 38))
        return rows[0][14] if rows else 0

    def _p5_condition(
        self, monitor: bytes, enabled_dids: Sequence[int], version: int
    ) -> bool:
        rows = self._ecu_profile().data_id_bit_records(word(monitor, 38))
        if not rows:
            raise ToyotaCodecError("P5 support-bit definition absent", 0xC0040101)
        row = rows[0]
        identifier = self._ecu_profile().data_id_bit_variable(row)
        selector = row[13] if version == 18 else row[11]
        if not identifier or selector != 7:
            raise ToyotaCodecError(
                "Invalid P5 support-bit variable/selector", 0xC0040102
            )
        comparison = row[14] if version == 18 else 0
        if comparison:
            if len(identifier) < 2:
                raise SessionError(
                    "Native P5 value lookup reads outside variable storage"
                )
            did = int.from_bytes(identifier[:2], "big")
            target = next(
                (
                    r
                    for r in self._rows(62, 64)
                    if word(r, 54) == did
                    and word(r, 44) == word(row, 6)
                    and word(r, 46) == word(row, 8)
                    and not 7000 <= word(r, 36) <= 9999
                ),
                None,
            )
            if target is None or word(target, 36) == 0:
                raise ToyotaCodecError("P5 support-value signal absent", 0xC0050101)
            if not self.check_support_pid(
                word(target, 36), enabled_dids=enabled_dids, raw_support=True
            ):
                supported = False
            else:
                value = self._p5_condition_value(identifier, word(row, 6), word(row, 8))
                supported = value is not None and value == word(row, 10)
            return (
                supported
                if comparison == 1
                else (not supported if comparison == 2 else False)
            )
        value = self._p5_condition_value(identifier, word(row, 6), word(row, 8))
        return value is not None and value != 0

    def _p5_condition_value(
        self, identifier: bytes, first: int, last: int
    ) -> int | None:
        frame = self._frames(0xC9)[0]
        if len(identifier) != 2:
            raise ToyotaCodecError(
                "P5 support identifier must be two bytes", 0xC0040102
            )
        request = frame.frame.request
        if len(request) < 3:
            raise ToyotaCodecError("P5 C9 template is short", 0xC0040102)
        try:
            reply = self._read(
                frame,
                request[:1] + identifier[:2] + request[3:],
                cached=False,
                temporary=True,
                extended=True,
            )
        except ToyotaCodecError:
            return None
        if len(reply) <= 3:
            return None
        if first > last:
            raise ToyotaCodecError("P5 support bit start exceeds end", 0xC0000001)
        if last >= (len(reply) - 3) * 8:
            raise SessionError("Native P5 support bit access exceeds recovered storage")
        return extract_bits(reply[3:], first, last)

    def data_id_support_status(
        self, identifier: int, *, native_parameter: int | None = None
    ) -> int:
        """CCommDataIDData69c70 flags3: CA0101 upper, then CAxx00 lower bit."""
        self._ecu_profile()
        self._check()
        if self.source_build == 12:
            raise SessionError("CCommDataIDData69c70 is absent from native build12")
        _uint(identifier, 65535, "DataId support identifier")
        if identifier == 0:
            raise ToyotaCodecError("Zero DataId support identifier", 0xC0040001)
        bus = self.bus_id if native_parameter is None else native_parameter
        if bus is None or _uint(bus, 65535, "DataId support bus") == 0:
            raise ToyotaCodecError("DataId support bus is zero", 0xC0040001)
        frame = self._frames(0xCA)[0]
        template = frame.frame.request
        if len(template) < 3:
            raise ToyotaCodecError("DataId support CA template is short", 0xC0040102)

        def receive(did: int) -> bytes:
            request = template[:1] + did.to_bytes(2, "big") + template[3:]
            reply = self._read(
                frame,
                request,
                cached=False,
                temporary=True,
                extended=True,
                native_parameter=bus,
            )
            if len(reply) <= 3:
                raise ToyotaCodecError("DataId support payload absent", 0xA0040202)
            return reply[3:]

        def bit(data: bytes, index: int) -> bool:
            byte, offset = divmod(index, 8)
            if byte == len(data):
                raise SessionError(
                    "Native DataId support access exceeds receive storage"
                )
            return byte < len(data) and data[byte] & (0x80 >> offset) != 0

        if not bit(receive(0x101), identifier >> 8):
            return 0
        low = identifier & 255
        group = receive(identifier & 0xFF00)
        if low == 0:
            raise ToyotaCodecError("Zero lower DataId support selector", 0xC0040001)
        return 2 if bit(group, low - 1) else 1

    def send_support_comm(
        self,
        function: int,
        identifier: int,
        position: int,
        mask: int,
        expected: int,
        *,
        with_value: bool = False,
        force: bool = False,
        native_parameter: int = 0,
    ) -> SendSupportObservation:
        """CCmdCheckSupport13030 selected-context native predicate dispatcher."""
        self._check()
        _uint(function, 65535, "support function")
        _uint(native_parameter, 65535, "support bus")
        _uint(identifier, 65535, "support identifier")
        _uint(position, 65535, "support position")
        _uint(mask, 255, "support mask")
        _uint(expected, 255, "support expected byte")
        if self.source_build == 12 and function in (0x104, 0x10E):
            return SendSupportObservation(0xC0040102, False)
        kinds = {0x13: 1, 0x14: 2, 0x82: 3, 0xA9: 4, 0xDE: 1, 0xDF: 3}
        if function in kinds:
            try:
                pages = self.support_bits(
                    kinds[function], no_retry=function in (0xDE, 0xDF)
                )
            except ToyotaCodecError as error:
                return SendSupportObservation(error.code, False, True)
            data = pages.get(identifier & 255)
            index = position & 255
            supported = (
                data is not None
                and len(data) > index
                and data[index] & mask == expected
            )
            return SendSupportObservation(0, supported)
        if function in (0xC8, 0x10E):
            try:
                result = (
                    self.data_ids()
                    if function == 0xC8
                    else self.subaru_did_support((identifier,))
                )
            except ToyotaCodecError as error:
                return SendSupportObservation(error.code, False, True)
            return SendSupportObservation(0, identifier in result.identifiers)
        if function == 0x104:
            try:
                state = self.data_id_support_status(
                    identifier, native_parameter=native_parameter
                )
            except ToyotaCodecError as error:
                return SendSupportObservation(error.code, False, True)
            return SendSupportObservation(0, state == 2)
        if function not in (0x6B, 0x75, 0xCA, 0xE0):
            return SendSupportObservation(0xC0040102, False)
        positions: dict[int, bytes] | None = None
        if function in (0x6B, 0xE0):
            try:
                positions = self.support_bits(1, no_retry=function == 0xE0)
            except ToyotaCodecError as error:
                return SendSupportObservation(error.code, False, True)
        try:
            frame = self._template(function)
        except ToyotaCodecError as error:
            return SendSupportObservation(error.code, False)
        request = bytearray(frame.frame.request)
        minimum = 3 if function == 0xCA else 2
        if len(request) < minimum:
            return SendSupportObservation(0xC0040102, False)
        if function == 0xCA:
            request[1:3] = identifier.to_bytes(2, "big")
        else:
            request[1] = identifier & 255
        literal = bytes(request)
        if force and function == 0x6B:
            self.invalidate_response(literal)
        hit = self.response_cached(literal)
        try:
            reply = self._read(
                frame,
                literal,
                extended=function == 0xCA,
                native_parameter=native_parameter,
            )
        except ToyotaCodecError as error:
            return SendSupportObservation(error.code, False, True, hit)
        if function == 0xCA:
            if len(reply) <= 3:
                return SendSupportObservation(0, False, cache_hit=hit)
            data = reply[3:]
            index = position
        else:
            length = (len(reply) - 2) & 255
            if length > len(reply) - len(request):
                raise SessionError("Native support copy exceeds received storage")
            data = reply[len(request) : len(request) + length]
            index = position & 255
            if positions is not None:
                table = positions.get(identifier & 255)
                if table is None:
                    return SendSupportObservation(0xC0040001, False, cache_hit=hit)
                try:
                    data = expand_supported_pid(data, table)
                except ToyotaCodecError as error:
                    return SendSupportObservation(error.code, False, cache_hit=hit)
                if not data:
                    return SendSupportObservation(0xA0040202, False, cache_hit=hit)
        if len(data) <= index:
            return SendSupportObservation(0, False, cache_hit=hit)
        value = data[index] & mask
        # 75's source branch always compares; only 6B/CA/E0 write raw out-value.
        capture = with_value and function != 0x75
        return SendSupportObservation(
            0,
            True if capture else value == expected,
            cache_hit=hit,
            value=value if capture else None,
        )

    def new_temporary_cache(self) -> TemporaryResponseCache:
        """Construct a native cache instance without clearing shared support/Ever."""
        self._check()
        return TemporaryResponseCache((*self.identity, self.source_build))

    def share_ever_cache(self, owner: MonitorSupportCache) -> None:
        """Bind a fresh context to its native DataCtrl's shared Ever buffer."""
        self._check()
        owner._check()
        if (
            self.source_build != owner.source_build
            or self.profile.catalog.management.sha256
            != owner.profile.catalog.management.sha256
            or tuple(self.profile.exception_ids) != tuple(owner.profile.exception_ids)
            or getattr(self.profile, "vehicle_name_key", None)
            != getattr(owner.profile, "vehicle_name_key", None)
        ):
            raise SessionError("Native Ever cache belongs to another selected source")
        if self._responses is owner._responses:
            return
        if self._responses:
            raise SessionError("Cannot replace an already populated native Ever cache")
        scope = (
            self._canonical_category_scope()
            if owner._native_storage_namespace
            else None
        )
        self._responses = owner._responses
        if scope is not None:
            self._response_scope = scope
            self._native_storage_namespace = True

    def share_discovery_cache(self, owner: MonitorSupportCache) -> None:
        """Bind native ShareData support slots10/11/19/1a and Mode35 slot21."""
        self._check()
        owner._check()
        if (
            self.source_build != owner.source_build
            or self.profile.catalog.management.sha256
            != owner.profile.catalog.management.sha256
            or tuple(self.profile.exception_ids) != tuple(owner.profile.exception_ids)
            or getattr(self.profile, "vehicle_name_key", None)
            != getattr(owner.profile, "vehicle_name_key", None)
        ):
            raise SessionError(
                "Native discovery cache belongs to another selected source"
            )
        if self._support_bits is owner._support_bits and self._mode35 is owner._mode35:
            return
        if self._support_bits or self._mode35:
            raise SessionError(
                "Cannot replace an already populated native discovery cache"
            )
        scope = (
            self._canonical_category_scope()
            if owner._native_storage_namespace
            else None
        )
        self._support_bits = owner._support_bits
        self._mode35 = owner._mode35
        if scope is not None:
            self._discovery_scope = scope
            self._native_storage_namespace = True

    def _canonical_category_scope(self) -> tuple[object, ...]:
        profile = self.profile.catalog.build_protocol_profile(
            self.profile.category, exception_ids=tuple(self.profile.exception_ids)
        )
        return monitor_source_identity(profile, self.ecu)[1:]

    def _bind_selected_vehicle_storage(
        self,
        owner: MonitorSupportCache,
        *,
        protocol_profile: ProtocolProfile,
    ) -> None:
        """View this selected category's native DataCtrl ShareData slots."""
        self._check()
        if not isinstance(owner, MonitorSupportCache):
            raise SessionError("Native cache owner is invalid")
        owner._check()
        exceptions = tuple(self.profile.exception_ids)
        owner_exceptions = tuple(owner.profile.exception_ids)
        if (
            type(protocol_profile) is not ProtocolProfile
            or not isinstance(self.profile, VehicleProfile)
            or self.source_build != 18
            or self.source_build != owner.source_build
            or self.profile.catalog is not owner.profile.catalog
            or self.profile.catalog.management.sha256
            != owner.profile.catalog.management.sha256
            or exceptions != owner_exceptions
            or protocol_profile.catalog is not self.profile.catalog
            or protocol_profile.category != self.profile.category
            or tuple(protocol_profile.exception_ids) != exceptions
            or protocol_profile.category_record != self.profile.category_record
        ):
            raise SessionError(
                "Native selected-vehicle cache belongs to another source"
            )
        canonical = self.profile.catalog.build_protocol_profile(
            self.profile.category, exception_ids=exceptions
        )
        owner_canonical = owner.profile.catalog.build_protocol_profile(
            owner.profile.category, exception_ids=owner_exceptions
        )
        if (
            protocol_profile != canonical
            or owner_canonical.category_record != owner.profile.category_record
        ):
            raise SessionError(
                "Native selected-vehicle category resource is not canonical"
            )
        if (
            self._native_storage_namespace
            or self._responses
            or self._support_bits
            or self._mode35
        ):
            raise SessionError("Cannot bind populated native selected-vehicle storage")
        self._responses = owner._responses
        self._support_bits = owner._support_bits
        self._mode35 = owner._mode35
        scope = monitor_source_identity(protocol_profile, self.ecu)[1:]
        self._response_scope = scope
        self._discovery_scope = scope
        self._native_storage_namespace = True

    def temporary_observations(self) -> tuple[tuple[bytes, bytes], ...]:
        """Snapshot the active native TEMP buffer in insertion order, including empty replies."""
        self._check()
        observations = []
        for key, reply in self._temporary_responses.items():
            request = key[-1]
            if (
                key[:-1] != self._temporary_identity
                or not isinstance(request, bytes)
                or not isinstance(reply, bytes)
            ):
                raise SessionError(
                    "Native TEMP observation belongs to another selected context"
                )
            observations.append((request, reply))
        return tuple(observations)

    @contextmanager
    def temporary_scope(
        self,
        instance: TemporaryResponseCache | None = None,
        *,
        no_init: bool = False,
        no_session: bool = False,
    ) -> Iterator[None]:
        """Bind a native CCommCachePlus instance, restoring its caller on exit."""
        from scripts.native_communication import NativeCommunication

        self._check()
        if type(no_init) is not bool or type(no_session) is not bool:
            raise ValueError("Native cache flags must be booleans")
        if instance is not None and (
            type(instance) is not TemporaryResponseCache
            or instance.source_identity != (*self.identity, self.source_build)
        ):
            raise SessionError("Native TEMP cache belongs to another selected context")
        with ExitStack() as flags:
            providers = {id(self.exchange): self.exchange, id(self.stream): self.stream}
            for provider in providers.values():
                if isinstance(provider, NativeCommunication):
                    flags.enter_context(
                        provider.communication_flags(
                            no_init=no_init,
                            no_session=no_session,
                        )
                    )
            previous = self._temporary_responses
            previous_identity = self._temporary_identity
            self._temporary_responses = {} if instance is None else instance._responses
            self._temporary_identity = self.identity
            try:
                yield
            finally:
                self._temporary_responses = previous
                self._temporary_identity = previous_identity

    def get_comm_support_bit(
        self,
        reference: int,
        *,
        connections: Mapping[tuple[int, int], NativeCommunication] | None = None,
        temporary: bool = False,
        force: bool = False,
        with_value: bool = False,
    ) -> CommSupportResult:
        """CCmdCheckSupport12a70 (12:e8a0), one local TEMP cache per call."""
        from scripts.native_communication import NativeCommunication

        with ExitStack() as scopes:
            # Native12/18 construct one local CCommCachePlus for the whole call.
            # The flag selects connection Ever/TEMP; 104 always uses this TEMP.
            caches: dict[int, MonitorSupportCache] = {id(self): self}
            for connection in (connections or {}).values():
                if isinstance(connection, NativeCommunication):
                    caches[id(connection.cache)] = connection.cache
            responses: dict[tuple[object, ...], dict[tuple[object, ...], bytes]] = {}
            for cache in caches.values():
                scopes.enter_context(cache.temporary_scope())
                # One native local instance keys by category/request, independent of bus/name.
                cache._temporary_identity = cache.identity[1:]
                cache._temporary_responses = responses.setdefault(
                    cache._temporary_identity, {}
                )
            return self._get_comm_support_bit(
                reference,
                connections=connections,
                temporary=temporary,
                force=force,
                with_value=with_value,
            )

    @contextmanager
    def target_operation(
        self,
        communication: NativeCommunication | None,
    ) -> Iterator[None]:
        """Constrain a selected native target and charge actual nested primitive I/O."""
        self._check()
        if communication is None:
            yield
            return
        target = communication.cache
        if (
            target.source_build != self.source_build
            or target.profile.catalog.management.sha256
            != self.profile.catalog.management.sha256
            or tuple(target.profile.exception_ids) != tuple(self.profile.exception_ids)
            or getattr(target.profile, "vehicle_name_key", None)
            != getattr(self.profile, "vehicle_name_key", None)
        ):
            raise SessionError("Target operation selected source context differs")
        remaining = self.limits.exchanges - self.calls
        if remaining <= 0:
            raise SessionError("Communication support aggregate budget exhausted")
        initial = self.calls
        usage = None
        try:
            with communication.constrain_operation(
                deadline=self.deadline,
                exchanges=remaining,
                cancelled=self.cancelled,
            ) as usage:
                yield
        finally:
            if usage is not None:
                already_charged = self.calls - initial if target is self else 0
                self.calls += max(0, usage.used - already_charged)

    def _get_comm_support_bit(
        self,
        reference: int,
        *,
        connections: Mapping[tuple[int, int], NativeCommunication] | None = None,
        temporary: bool = False,
        force: bool = False,
        with_value: bool = False,
    ) -> CommSupportResult:
        """CCmdCheckSupport12a70 (12:e8a0): ordered native AND/OR predicates."""
        from scripts.native_communication import NativeCommunication

        self._check()
        _uint(reference, 65535, "communication support reference")
        rows = self.profile.communication_support_records(reference)
        if not rows:
            raise ToyotaCodecError("Communication support reference absent", 0xC0040101)
        if len(rows) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        if any(len(row) != 24 for row in rows):
            raise ToyotaCodecError("Malformed communication support rows", 0xC0040101)
        supported, value, skipped, conjunction = False, None, False, True
        for index, row in enumerate(rows):
            self._check()
            if index and rows[index - 1][21] == 2:
                conjunction = True
            elif index and skipped:
                continue
            skipped = False
            ecu, bus = word(row, 10), row[20]
            local = ecu == self.profile.category and bus in (0, self.bus_id)
            communication = (
                self.exchange
                if local and isinstance(self.exchange, NativeCommunication)
                else None
            )
            target = self if local else None
            if not local:
                communication = (
                    None if connections is None else connections.get((ecu, bus))
                )
                if not isinstance(communication, NativeCommunication):
                    raise SessionError(
                        "Selected support target communication context absent"
                    )
                target = communication.cache
                if target.profile.category != ecu or (
                    bus and communication.bus_id != bus
                ):
                    raise SessionError(
                        "Support target category/bus differs from binding"
                    )
                if (
                    target.source_build != self.source_build
                    or target.profile.catalog.management.sha256
                    != self.profile.catalog.management.sha256
                ):
                    raise SessionError("Support target source build/management differs")
            assert target is not None
            target.check_context()
            ignored, hit = False, True
            connect = word(row, 2)
            # The outer frame contains no request; only the send timer is set
            # in the no-connection branch before its conditional InitEcu call.
            settings = (
                bytes(16)
                if connect
                else target.profile.communication_settings(word(row, 4))
            )
            init_frame = SelectedFrame(
                CommandFrame(b""),
                b"",
                b"",
                settings,
                f"native-CommSupport:{reference}:row={index}",
            )
            with self.target_operation(communication):
                if not connect:
                    observed = target.send_support_comm(
                        word(row, 6),
                        word(row, 8),
                        word(row, 16),
                        row[18],
                        row[19],
                        with_value=with_value,
                        force=force,
                        native_parameter=bus,
                    )
                    status, supported = observed.status, observed.supported
                    ignored, hit = observed.ignored_failure, observed.cache_hit
                    if observed.value is not None:
                        value = observed.value
                else:
                    if (
                        not isinstance(communication, NativeCommunication)
                        or communication.cache is not target
                    ):
                        raise SessionError(
                            "Connection support needs concrete native communication"
                        )
                    hit = target.response_cached(b"")
                    if row[23] == 6:
                        observed_behavior = communication.is_behavior_code(
                            connect, word(row, 4)
                        )
                        status, supported, ignored = (
                            observed_behavior.status,
                            observed_behavior.supported,
                            observed_behavior.ignored_failure,
                        )
                    else:
                        observed_connection = communication.connection_no_buffer(
                            connect, word(row, 4), temporary=temporary, force=force
                        )
                        status, supported = (
                            observed_connection.status,
                            observed_connection.connected,
                        )
                        ignored = status != 0
                self._check()
                if status and not ignored:
                    raise ToyotaCodecError(
                        "Native communication support failed", status
                    )
                if status in (0x91010009, 0x90020323) and not hit:
                    target._init_ecu(init_frame)
                    status = 0
                if ignored:
                    status = 0
                predicate = row[23]
                if predicate in (2, 6):
                    supported = False if ignored else not supported
                elif predicate == 5:
                    supported = ignored
                elif predicate == 1:
                    supported = False if ignored else bool(supported)
                else:
                    raise ToyotaCodecError(
                        "Invalid communication support predicate", 0xC0040101
                    )
                if not supported:
                    conjunction = False
                    skipped = True
                if row[21] == 2 and conjunction:
                    break
        self._check()
        return CommSupportResult(supported, value)

    def invalidate_a8(self, kind: int) -> None:
        """DelA8CommFrameCache55c90 deletes this ECU's first kind entry only."""
        if kind not in (1, 2, 3, 4):
            raise ToyotaCodecError("Invalid A8 cache kind", 0xC0040001)
        self._check()
        self._support_bits.pop((*self._discovery_scope, kind), None)

    def frame_map(self, pid: int) -> Mode35FrameMap:
        _uint(pid, 255, "frame PID")
        self._check()
        if pid not in self._maps:
            values = self.mode35()
            if pid not in values:
                raise ToyotaCodecError("Mode35 PID data absent", 0x90041103)
            self._maps[pid] = mode35_frame_map(pid, values[pid], self._rows(10, 84))
        return self._maps[pid]


@dataclass(frozen=True)
class PacketReceive:
    """GetPacketFrame Receive ABI: capacity8, parameter4 timer, flags0, wait100."""

    ecu: int
    capacity: int
    parameter4: int
    parameter5: int = 0
    wait_ms: int = 100


class PacketPrimitives(Protocol):
    def send(
        self,
        ecu: int,
        request: bytes,
        parameter4: int,
        parameter5: int,
        parameter6: int,
        parameter7: int,
    ) -> int: ...
    def receive(self, receive: PacketReceive, /) -> tuple[int, bytes]: ...
    def interrupt(self, enabled: bool) -> None: ...


@dataclass(frozen=True)
class PacketFrame:
    sequence: int
    payload: bytes


class PacketFrameCache:
    """CCommCachePacketFrame5cb90, including A2 retries and A3 interrupt drain."""

    def __init__(
        self,
        primitive: PacketPrimitives,
        *,
        source_identity: tuple[object, ...],
        send_timer: int,
        receive_timer: int,
        retries: int,
        disable_packet_ecu: Callable[[int], None] | None = None,
        limits: Limits | None = None,
        cancelled: Callable[[], bool] = lambda: False,
        clock: Callable[[], float] = time.monotonic,
    ):
        for value, label in (
            (send_timer, "send timer"),
            (receive_timer, "receive timer"),
            (retries, "retry limit"),
        ):
            _uint(value, 0xFFFFFFFF, label)
        if not source_identity:
            raise ValueError("Packet cache needs explicit source/context identity")
        if disable_packet_ecu is not None and not callable(disable_packet_ecu):
            raise TypeError("Packet disable target must be callable")
        self.disable_packet_ecu = disable_packet_ecu
        self.primitive, self.identity = primitive, source_identity
        self.send_timer, self.receive_timer, self.retries = (
            send_timer,
            receive_timer,
            retries,
        )
        self.limits, self.cancelled, self.clock = limits or Limits(), cancelled, clock
        self.deadline = clock() + self.limits.seconds
        self.calls = 0
        self.entries: list[tuple[int, tuple[PacketFrame, ...]]] = []
        self.disabled: list[int] = []
        self._selected_context: tuple[ProtocolProfile, str] | None = None

    @classmethod
    def from_profile(
        cls,
        profile: ProtocolProfile,
        primitive: PacketPrimitives,
        ecu: str,
        *,
        disable_packet_ecu: Callable[[int], None] | None = None,
        limits: Limits | None = None,
        cancelled: Callable[[], bool] = lambda: False,
        clock: Callable[[], float] = time.monotonic,
    ) -> PacketFrameCache:
        """Native Init18:5caa0/12:3c2b0: FIRST ComSet1 or source defaults."""
        if profile is None or primitive is None:
            raise ToyotaCodecError("Packet initialization pointer absent", 0xC0050001)
        try:
            settings = profile.communication_settings_first(1)
        except ToyotaCodecError:
            send_timer, receive_timer, retries = 1000, 200, 2
        else:
            if not isinstance(settings, bytes) or len(settings) != 16:
                raise SessionError("Malformed selected packet settings")
            send_timer, receive_timer = struct.unpack_from("<II", settings)
            retries = settings[14]
        cache = cls(
            primitive,
            source_identity=monitor_source_identity(profile, ecu),
            send_timer=send_timer,
            receive_timer=receive_timer,
            retries=retries,
            disable_packet_ecu=disable_packet_ecu,
            limits=limits,
            cancelled=cancelled,
            clock=clock,
        )
        cache._selected_context = profile, ecu
        cache._check()
        return cache

    def _check(self, *, count=False) -> None:
        if self._selected_context is not None:
            profile, ecu = self._selected_context
            if monitor_source_identity(profile, ecu) != self.identity:
                raise SessionError("Packet cache selected source/context changed")
        if self.cancelled():
            raise Cancelled("Packet query cancelled")
        now = self.clock()
        if (
            not math.isfinite(now)
            or not math.isfinite(self.deadline)
            or now >= self.deadline
        ):
            raise SessionError("Packet query deadline exhausted")
        if count:
            if self.calls >= self.limits.exchanges:
                raise SessionError("Packet query primitive budget exhausted")
            self.calls += 1

    def _send(self, ecu: int, request: bytes, parameter5: int) -> int:
        self._check(count=True)
        status = self.primitive.send(ecu, request, self.send_timer, parameter5, 0, 0)
        self._check()
        return _uint(status, 0xFFFFFFFF, "packet send status")

    def _receive(self, ecu: int) -> tuple[int, bytes]:
        self._check(count=True)
        status, data = self.primitive.receive(PacketReceive(ecu, 8, self.receive_timer))
        self._check()
        _uint(status, 0xFFFFFFFF, "packet receive status")
        if not isinstance(data, bytes) or len(data) > 8:
            raise ToyotaCodecError(
                "Packet receive exceeds native eight bytes", 0xA0040202
            )
        return status, data

    def get_packet_frame(
        self, ecu: int, parameter5: int, *, source_identity: tuple[object, ...]
    ) -> tuple[PacketFrame, ...]:
        _uint(ecu, 0xFFFFFFFF, "packet ECU")
        _uint(parameter5, 65535, "packet parameter5")
        self._check()
        if source_identity != self.identity:
            raise SessionError("Packet cache source/context identity mismatch")
        # Native comparator5d060 keys only the ECU, first matching cache entry.
        for cached_ecu, frames in self.entries:
            if cached_ecu == ecu:
                return frames
        failures = 0
        result: list[PacketFrame] = []
        status = 0
        complete = False
        while failures <= self.retries and not complete:
            result = []
            expected = 0x11
            status = self._send(ecu, b"\xa2\x04", parameter5)
            if status:
                failures += 1
                continue
            while True:
                status, data = self._receive(ecu)
                if status:
                    status = 0xA1050307
                    failures += 1
                    break
                if not data or data[0] != 0xE2:
                    continue
                if len(data) < 2:
                    raise ToyotaCodecError(
                        "Packet sequence header truncated", 0xA0040202
                    )
                sequence = data[1]
                if expected == 0x11 and sequence != 0x11:
                    continue
                if expected != 0x11 and (sequence == 0x11 or sequence != expected):
                    complete = True
                    break
                result.append(PacketFrame(sequence, data[2:]))
                expected = (sequence + 1) & 255
        if status:
            raise ToyotaCodecError("Packet frame receive failed", status)
        # Native enables interrupt around A3 and drains until the timeout code.
        try:
            self.primitive.interrupt(True)
            if self._send(ecu, b"\xa3", parameter5):
                self.disabled.append(ecu)
                if self.disable_packet_ecu is not None:
                    self.disable_packet_ecu(ecu)
            while True:
                status, _ = self._receive(ecu)
                if status == 0x91010009:
                    break
        finally:
            self.primitive.interrupt(False)
        self._check()
        frames = tuple(result)
        self.entries.append((ecu, frames))
        return frames
