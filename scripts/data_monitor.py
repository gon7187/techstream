"""Native selected DataMonitor orchestration with injected exchanges.

No OEM binary is executed and no device is opened by this module.
"""

from __future__ import annotations

import math
import struct
import time
from bisect import bisect_right
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from itertools import pairwise
from threading import Lock
from typing import TYPE_CHECKING, Protocol

from scripts.profiles import ProtocolProfile, VehicleProfile
from scripts.support import word
from scripts.toyota import ToyotaCodecError
from scripts.toyota_session import Cancelled, Exchange, Limits, SessionError

if TYPE_CHECKING:
    from scripts.drive_recorder import (
        DrsFile,
        NativeMonitorBuffer,
        NativeTriggerInfo,
        NativeTriggerParameters,
        NativeVehicleSelection,
        NativeVimClient,
    )
    from scripts.frame_transport import NativeFrameOperations, NativeMultiMonOperations
    from scripts.monitor_dlc12 import DLC12VoltageObservation, DLC12VoltageState
    from scripts.monitor_dual import DualTarget
    from scripts.monitor_j2534 import (
        ActiveMonitorEvent,
        DirectJ2534Worker,
        MonitorSystemEvent,
    )
    from scripts.monitor_legacy import (
        LegacyCheckTarget,
        LegacyControlMessage,
        LegacyMonitorController,
        LegacyRunTarget,
    )
    from scripts.monitor_p5 import SelectedP5Monitor
    from scripts.monitor_packet_a8 import SelectedPacketA8Monitor
    from scripts.monitor_poll import (
        NormalOscilloscopeSelection,
        NormalPollingWorker,
        Phase5ActiveEvent,
        Phase5SystemEvent,
    )
    from scripts.monitor_support import (
        MonitorSupportCache,
        PacketFrameCache,
        SupportStream,
        SupportTransaction,
    )
    from scripts.monitor_variable import (
        SelectedVariableMonitor,
        VariableActiveOperation,
        VariableMonitorRuntime,
        VariableRuntimeTarget,
        VariableSystemOperation,
    )
    from scripts.native_communication import NativeCommunication
    from scripts.signal_lsb import SignalLSB

MAX_ITEMS = 100_000
MAX_BYTES = 32 * 1024 * 1024
MAX_DYNAMIC_COMPARISONS = 6_400_000


class MonitorError(ValueError):
    """Invalid selected monitor inputs or an unavailable native operation."""

    def __init__(self, message: str, code: int | None = None):
        super().__init__(message)
        self.code = code


class SelectedMonitorSession:
    """Selected application ShareData1b list shared by workers and CheckStart."""

    def __init__(
        self,
        profile: ProtocolProfile,
        *,
        source_build: int,
        shared_interface: int | None = None,
        disabled_packet_ecus: tuple[int, ...] = (),
    ):
        if (
            not isinstance(profile, ProtocolProfile)
            or type(source_build) is not int
            or source_build not in (12, 18)
        ):
            raise MonitorError("Monitor session requires selected profile/build12/18")
        if shared_interface is not None and (
            type(shared_interface) is not int or not 0 <= shared_interface <= 0xFFFFFFFF
        ):
            raise MonitorError("Native ShareData1e must fit DWORD")
        if (
            not isinstance(disabled_packet_ecus, tuple)
            or len(disabled_packet_ecus) > MAX_ITEMS
            or any(
                type(category) is not int or not 0 <= category <= 0xFFFFFFFF
                for category in disabled_packet_ecus
            )
        ):
            raise MonitorError("Native ShareData1b requires bounded DWORD entries")
        self._profile, self._source_build = profile, source_build
        self._identity = self._context(profile)
        self.shared_interface = shared_interface
        self._disabled_packet_ecus = list(disabled_packet_ecus)
        self._lock = Lock()

    @staticmethod
    def _context(profile: ProtocolProfile) -> tuple[object, ...]:
        management = profile.catalog.management
        return (
            management.sha256,
            management.version,
            profile.vehicle_name_key,
            tuple(profile.exception_ids),
        )

    @property
    def source_build(self) -> int:
        return self._source_build

    def check(self, profile: ProtocolProfile, *, source_build: int) -> None:
        if (
            not isinstance(profile, ProtocolProfile)
            or type(source_build) is not int
            or source_build != self._source_build
            or self._context(profile) != self._identity
            or self._context(self._profile) != self._identity
        ):
            raise MonitorError("Monitor session selected application/vehicle changed")

    @property
    def disabled_packet_ecus(self) -> tuple[int, ...]:
        self.check(self._profile, source_build=self._source_build)
        with self._lock:
            return tuple(self._disabled_packet_ecus)

    def disable_packet_ecu(self, category: int) -> None:
        self.check(self._profile, source_build=self._source_build)
        if type(category) is not int or not 0 <= category <= 0xFFFFFFFF:
            raise MonitorError("Native packet-disable category must fit DWORD")
        with self._lock:
            if category in self._disabled_packet_ecus:
                return
            if len(self._disabled_packet_ecus) >= MAX_ITEMS:
                raise MonitorError("Native ShareData1b exceeds host item budget")
            self._disabled_packet_ecus.append(category)


@dataclass(frozen=True)
class MonitorCapabilities:
    mask: int
    attribute_2_23: bool
    queried: tuple[int, ...]


@dataclass(frozen=True)
class DynamicSource:
    """A native DID's ordered byte runs: (one-based position, byte count)."""

    did: int
    runs: tuple[tuple[int, int], ...]

    def __post_init__(self) -> None:
        if type(self.did) is not int or not 0 <= self.did <= 65535:
            raise MonitorError("Native source DID must fit uint16")
        if (
            not isinstance(self.runs, tuple)
            or not self.runs
            or len(self.runs) > MAX_ITEMS
        ):
            raise MonitorError("Native dynamic source requires bounded byte runs")
        for run in self.runs:
            if (
                not isinstance(run, tuple)
                or len(run) != 2
                or any(type(value) is not int or not 1 <= value <= 255 for value in run)
            ):
                raise MonitorError(
                    "Native dynamic byte-run position/count must fit nonzero bytes"
                )

    @property
    def length(self) -> int:
        return sum(length for _, length in self.runs)


@dataclass(frozen=True)
class DynamicSlot:
    did: int
    run_capacity: int

    def __post_init__(self) -> None:
        if (
            type(self.did) is not int
            or not 0 <= self.did <= 65535
            or (
                type(self.run_capacity) is not int
                or not 0 <= self.run_capacity <= 65535
            )
        ):
            raise MonitorError("Native dynamic slot ID/capacity must fit uint16")


@dataclass(frozen=True)
class DynamicPlan:
    requests: tuple[bytes, ...]
    read_ids: tuple[int, ...]
    read_lengths: tuple[int, ...]
    sources: tuple[tuple[DynamicSource, ...], ...]
    remaining: tuple[DynamicSource, ...]


@dataclass(frozen=True)
class DynamicOutcome:
    """Native registration result; disable_packet_ecu is an explicit side effect."""

    status: int
    plan: DynamicPlan
    failed_clears: tuple[tuple[int, int], ...]
    failed_definitions: tuple[tuple[int, int], ...]
    failed_validation: tuple[int, int] | None
    disable_packet_ecu: bool
    clear_ids: tuple[int, ...] = ()


def _dynamic_order(
    sources: Sequence[DynamicSource],
) -> list[tuple[DynamicSource, int, int]]:
    """Native5f10/12:5630 nonadjacent interchange sort, including reordered ties."""
    measured = [(source, len(source.runs), source.length) for source in sources]
    keys = [(runs, -length) for _, runs, length in measured]
    if all(left <= right for left, right in pairwise(keys)):
        return measured  # An already ordered native list performs no swaps.
    if len(measured) * (len(measured) - 1) // 2 > MAX_DYNAMIC_COMPARISONS:
        raise MonitorError("Native dynamic interchange sort exceeds comparison budget")
    for index in range(len(measured)):
        for candidate in range(index + 1, len(measured)):
            if keys[index] > keys[candidate]:
                keys[index], keys[candidate] = keys[candidate], keys[index]
                measured[index], measured[candidate] = (
                    measured[candidate],
                    measured[index],
                )
    return measured


def pack_dynamic_dids(
    template: bytes,
    sources: Sequence[DynamicSource],
    slots: Sequence[DynamicSlot],
    *,
    max_request: int,
    max_reply: int,
) -> DynamicPlan:
    """Phase5 6220 packing after5f10 analysis and73b0 interchange sorting.

    The selected D3 template and observed dynamic slots are explicit inputs.
    Sources stay whole; a source that does not fit is retried in the next slot.
    Unassigned sources are returned, never silently reported as configured.
    """
    if not isinstance(template, bytes) or not 4 <= len(template) <= 65535:
        raise MonitorError(
            "Selected dynamic definition template needs at least four bytes"
        )
    if any(
        type(limit) is not int or not 0 <= limit <= 65535
        for limit in (max_request, max_reply)
    ):
        raise MonitorError("Native monitor request/reply limits must fit uint16")
    if (
        len(sources) > MAX_ITEMS
        or len(slots) > MAX_ITEMS
        or any(not isinstance(source, DynamicSource) for source in sources)
        or any(not isinstance(slot, DynamicSlot) for slot in slots)
    ):
        raise MonitorError(
            "Invalid or excessive native dynamic source/slot descriptors"
        )
    if sum(len(source.runs) for source in sources) > MAX_ITEMS:
        raise MonitorError("Native dynamic byte-run aggregate exceeds budget")
    measured = _dynamic_order(sources)
    ordered = tuple(item[0] for item in measured)
    requests = []
    read_ids = []
    lengths = []
    grouped = []
    index = 0
    output_size = 0
    for slot in slots:
        selected = []
        runs = 0
        size = 0
        while index < len(ordered):
            source, run_count, source_length = measured[index]
            next_runs = runs + run_count
            if (
                next_runs > slot.run_capacity
                or len(template) + next_runs * 4 > max_request
                or 3 + size + source_length > max_reply
            ):
                break
            selected.append(source)
            runs = next_runs
            size += source_length
            index += 1
        if selected:
            output_size += len(template) + runs * 4
            if output_size > MAX_BYTES:
                raise MonitorError(
                    "Native dynamic definition output exceeds byte budget"
                )
            request = template[:2] + slot.did.to_bytes(2, "big") + template[4:]
            request += b"".join(
                source.did.to_bytes(2, "big") + bytes(run)
                for source in selected
                for run in source.runs
            )
            requests.append(request)
            read_ids.append(slot.did)
            lengths.append(size)
            grouped.append(tuple(selected))
        if index == len(ordered):
            break
    return DynamicPlan(
        tuple(requests),
        tuple(read_ids),
        tuple(lengths),
        tuple(grouped),
        tuple(ordered[index:]),
    )


def monitor_capabilities(observed: Mapping[int, bool]) -> MonitorCapabilities:
    """Phase4 1f00 CheckEcuFunc(group2) decisions from explicit observations."""
    queried = []

    def check(key: int) -> bool:
        if key not in observed or type(observed[key]) is not bool:
            raise MonitorError(f"Missing boolean native function observation2/{key}")
        queried.append(key)
        return observed[key]

    mask = 0
    if check(0x16):
        mask |= 5
    else:
        for key, bit in ((10, 2), (8, 1), (9, 4)):
            if check(key):
                mask |= bit
    for key, bit in ((12, 0x20), (25, 0x100), (11, 0x10), (26, 0x200)):
        if check(key):
            mask |= bit
    if check(29):
        mask |= 0x2000
    else:
        if check(27):
            mask |= 0x800
        if check(28):
            mask |= 0x1000
    attribute = check(35)
    if not mask:
        raise MonitorError("Native monitor capability mask is empty", 0x90051007)
    return MonitorCapabilities(mask, attribute, tuple(queried))


def monitor_mode(command_id: int, current_mode: int, dual_observed: bool | None) -> int:
    """KgpDataMonitorCtrl aca0 mode transition; Dual predicate result is explicit."""
    if type(command_id) is not int or not 0 <= command_id <= 0xFFFFFFFF:
        raise MonitorError("Native monitor command must fit uint32")
    if type(current_mode) is not int or current_mode not in (0, 1, 2):
        raise MonitorError("Native monitor controller mode must be0,1or2")
    if dual_observed is not None and type(dual_observed) is not bool:
        raise MonitorError("Native Dual observation must be boolean")
    if command_id == 0x38:
        if dual_observed is None:
            raise MonitorError(
                "Native MultiMon requires observed Dual predicate result"
            )
        return 2 if dual_observed else 0
    if command_id in (9, 0x57):
        return 0
    if command_id == 0x89:
        return 1
    return current_mode


def dmci_id_map_fields(
    request_id: int, response_id: int, value3: int, value4: int, value5: int
) -> tuple[int, int, int, int, int]:
    """DataListIF2910/e910/25ce0 -> command111 five native DWORDs.

    DMCI wrappers substitute the third field when zero. The direct Dual J2534
    mapper17f50 stores the supplied fields unchanged and must not use this rule.
    Signed caller ints retain their raw DWORD bits; names await consumer proof.
    """
    if any(
        type(x) is not int or not 0 <= x <= 0xFFFFFFFF
        for x in (request_id, response_id)
    ):
        raise MonitorError("Native IDMap identifiers must fit uint32")
    if any(
        type(x) is not int or not -0x80000000 <= x <= 0x7FFFFFFF
        for x in (value3, value4, value5)
    ):
        raise MonitorError("Native IDMap fields must fit int32")
    resolved = value3 or (1000 if request_id & 0xC0000000 == 0x80000000 else 50)
    return (
        request_id,
        response_id,
        resolved & 0xFFFFFFFF,
        value4 & 0xFFFFFFFF,
        value5 & 0xFFFFFFFF,
    )


def _ids(values: Sequence[int], maximum: int) -> tuple[int, ...]:
    result = tuple(values)
    if (
        not result
        or len(result) > MAX_ITEMS
        or any(type(value) is not int or not 0 <= value <= maximum for value in result)
    ):
        raise MonitorError("Native monitor IDs are empty, excessive or out of range")
    return result


def p4_monitor_requests(data_type: int, ids: Sequence[int]) -> tuple[bytes, ...]:
    """DataListIF CCommEventDualP4DM::DataMonitorSetup14850, in native order."""
    if type(data_type) is not int or data_type not in (0, 1, 2, 3, 6):
        raise MonitorError("Native P4 monitor type must be0,1,2,3or6")
    selected = _ids(ids, 255)
    service = 1 if data_type in (0, 2) else 0x21
    suffix = b"\x01" if data_type in (2, 3) else b""
    return tuple(bytes((service, value)) + suffix for value in selected)


def p5_monitor_requests(data_ids: Sequence[int]) -> tuple[bytes, ...]:
    """DataListIF CCommEventDualP5DM::DataidSetup15150 emits22 + big-endian DID."""
    return tuple(b"\x22" + value.to_bytes(2, "big") for value in _ids(data_ids, 65535))


class MonitorEvent:
    pickup_spans: tuple[tuple[int, int], ...] = ()
    _pickup_previous: bytes = b""

    """Native P4/P5 monitor request cycle and retained packet storage.

    The caller supplies observed response lengths, not guessed PID sizes. Native
    CheckRcvFrame copies available bytes and retains the rest of a short frame;
    timestamps belong to the response completing a cycle. This event performs
    no exchange, clock conversion or interpolation.
    """

    def __init__(
        self,
        requests: tuple[bytes, ...],
        lengths: Sequence[int],
        *,
        p4_type: int | None,
    ):
        if (
            not isinstance(requests, tuple)
            or not requests
            or len(requests) > MAX_ITEMS
            or any(
                not isinstance(request, bytes) or len(request) < 2
                for request in requests
            )
        ):
            raise MonitorError("Native monitor event requires bounded requests")
        if p4_type is None:
            if any(len(request) != 3 or request[0] != 0x22 for request in requests):
                raise MonitorError(
                    "Native P5 data-ID event requires22 plus two ID bytes"
                )
        elif requests != p4_monitor_requests(
            p4_type, tuple(request[1] for request in requests)
        ):
            raise MonitorError("Native P4 request bytes do not match selected type")
        sizes = tuple(lengths)
        if len(requests) != len(sizes) or any(
            type(size) is not int or not 1 <= size <= 65535 for size in sizes
        ):
            raise MonitorError("Observed native response sizes must match requests")
        if sum(sizes) > 32 * 1024 * 1024:
            raise MonitorError("Native monitor cycle exceeds byte budget")
        self.requests, self.lengths, self.p4_type = requests, sizes, p4_type
        self.index = 0
        self._offset = 0
        self._data = bytearray(sum(sizes))

    @classmethod
    def p4(
        cls, data_type: int, ids: Sequence[int], lengths: Sequence[int]
    ) -> MonitorEvent:
        return cls(p4_monitor_requests(data_type, ids), lengths, p4_type=data_type)

    @classmethod
    def p5(cls, ids: Sequence[int], lengths: Sequence[int]) -> MonitorEvent:
        return cls(p5_monitor_requests(ids), lengths, p4_type=None)

    @property
    def request(self) -> bytes:
        return self.requests[self.index]

    def accept(self, reply: bytes, timestamp_raw: int) -> tuple[int, bytes] | None:
        """DataListIF14bd0/15ff0; bounded headers replace native unchecked reads."""
        if type(timestamp_raw) is not int or not 0 <= timestamp_raw <= 0xFFFFFFFF:
            raise MonitorError("Native monitor timestamp must fit uint32")
        if not isinstance(reply, bytes) or not reply or len(reply) > 65535:
            raise MonitorError("Native monitor reply lacks header")
        # Native P4 recognizes53 as a cycle item without a data copy.
        no_copy = self.p4_type is not None and reply[0] == 0x53
        if not no_copy:
            expected = self.request[0] | 0x40
            if reply[0] != expected:
                raise MonitorError("Native monitor reply service differs")
            header = (
                3
                if self.p4_type is None
                else (1 if self.p4_type == 6 and self.request[1] == 1 else 2)
            )
            if len(reply) < header:
                raise MonitorError("Native monitor reply lacks header")
            copied = min(len(reply) - header, self.lengths[self.index])
            self._data[self._offset : self._offset + copied] = reply[
                header : header + copied
            ]
            self._offset += self.lengths[self.index]
        self.index += 1
        if self.index == len(self.requests):
            self.index, self._offset = 0, 0
            packet = bytes(self._data)
            if self.p4_type is None:
                # Phase5 dc80 and Dual15ff0 zero storage after each packet.
                self._data[:] = bytes(len(self._data))
            if self.pickup_spans:
                packet = pickup_packet(
                    packet,
                    timestamp_raw,
                    self.pickup_spans,
                    p4=self.p4_type is not None,
                    previous=self._pickup_previous,
                )
                self._pickup_previous = packet[len(self._data) :]
            return timestamp_raw, packet
        return None


def exchange_cycle(
    event: MonitorEvent,
    exchange: Exchange,
    ecu: str,
    *,
    tick_ms: Callable[[], int],
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[int, bytes]:
    """Bound one native event cycle at the diagnostic payload exchange boundary.

    The selected transport lifecycle remains caller-owned. GetSndFrame's entire
    bytes reach SendIntExtMultiMon13e10/14400 unchanged. The caller supplies the
    native millisecond tick observation; no packet timestamp is synthesized from
    a recording or inferred from a vehicle profile.
    """
    if not isinstance(event, MonitorEvent) or not isinstance(ecu, str) or not ecu:
        raise MonitorError("Selected native monitor event and ECU identity required")
    budget = limits or Limits()
    started = clock()
    if not math.isfinite(started):
        raise SessionError("Native monitor clock must be finite")
    deadline = started + budget.seconds

    def check() -> None:
        if cancelled():
            raise Cancelled("Native monitor cancelled")
        now = clock()
        if not math.isfinite(now) or now >= deadline:
            raise SessionError("Native monitor deadline exceeded")

    for _ in range(min(budget.exchanges, MAX_ITEMS)):
        check()
        try:
            reply = exchange(ecu, event.request)
        finally:
            check()
        result = event.accept(reply, tick_ms())
        if result is not None:
            return result
    raise SessionError("Native monitor exchange budget exhausted")


@dataclass(frozen=True)
class MonitorRange:
    """Native eleven-byte range descriptor assembled by Phase4 d040."""

    start_bit: int
    end_bit: int
    signal_id: int
    frame_id: int
    byte_4d: int
    flags: int
    composite_flags: int
    runtime_flag: int = 0

    def __post_init__(self) -> None:
        values = (self.start_bit, self.end_bit, self.signal_id)
        if any(type(x) is not int or not 0 <= x <= 65535 for x in values):
            raise MonitorError("Native monitor range words must fit uint16")
        if self.end_bit < self.start_bit:
            raise MonitorError("Native monitor range ends before its start")
        if any(
            type(x) is not int or not 0 <= x <= 255
            for x in (
                self.frame_id,
                self.byte_4d,
                self.flags,
                self.composite_flags,
                self.runtime_flag,
            )
        ):
            raise MonitorError("Native monitor range flags must fit bytes")


@dataclass(frozen=True)
class MonitorGroup:
    """DB21a parent/ordinal/child links, retaining native request order."""

    signal_id: int
    links: tuple[tuple[int, int, int], ...]
    padding_ordinal: int | None


@dataclass(frozen=True)
class MonitorDefinitions:
    selected_ids: tuple[int, ...]
    ranges: tuple[MonitorRange, ...]
    groups: tuple[MonitorGroup, ...]
    source_sha256: str | None
    source_identity: tuple[object, ...] = ()


def _profile_identity(profile: ProtocolProfile) -> tuple[object, ...]:
    # Structural authored inputs remain usable by pure metadata/packing tests;
    # only an actual selected ProtocolProfile produces an I/O lifecycle identity.
    if not isinstance(profile, ProtocolProfile):
        return ()
    from scripts.monitor_support import monitor_source_identity

    return monitor_source_identity(profile, "")


def selected_definitions(
    profile: VehicleProfile, selected_ids: Sequence[int]
) -> MonitorDefinitions:
    """Phase4 d040 selected Freeze/MultiPID producer; no capability is inferred.

    Native first-match lookup and shared child ranges are preserved. This builds
    the pre-packing descriptors; observed enable/cache state is a later input.
    """
    keys = tuple(selected_ids)
    if (
        not keys
        or len(keys) > MAX_ITEMS
        or any(type(key) is not int or not 0 <= key <= 65535 for key in keys)
    ):
        raise MonitorError("Select bounded uint16 signal IDs")
    rows = profile.records(10)
    if len(rows) > MAX_ITEMS or any(len(row) != 84 for row in rows):
        raise MonitorError("Selected Freeze table must contain bounded84-byte rows")
    first: dict[int, bytes] = {}
    for row in rows:
        first.setdefault(word(row, 56), row)
    ranges: dict[int, MonitorRange] = {}
    groups = []
    multi_rows: tuple[bytes, ...] | None = None
    multi_index: dict[int, list[bytes]] = {}
    link_count = 0

    def append(key: int, composite_flags: int) -> MonitorRange:
        if key not in first:
            raise MonitorError(f"Selected Freeze signal {key} is absent")
        row = first[key]
        if row[78] & 16:
            raise MonitorError("Composite child cannot refer to another composite")
        if key not in ranges:
            ranges[key] = MonitorRange(
                word(row, 62),
                word(row, 64),
                key,
                row[79],
                row[77],
                row[78],
                composite_flags,
            )
        else:
            # Native range updater15e0 ORs child flags into existing node+0d.
            ranges[key] = replace(
                ranges[key],
                composite_flags=ranges[key].composite_flags | composite_flags,
            )
        if len(ranges) > MAX_ITEMS:
            raise MonitorError("Native monitor range budget exceeded")
        return ranges[key]

    for key in keys:
        if key in ranges:
            continue
        if key not in first:
            raise MonitorError(f"Selected Freeze signal {key} is absent")
        row = first[key]
        if not row[78] & 16:
            append(key, 0)
            continue
        if multi_rows is None:
            multi_rows = profile.records(26)
            if len(multi_rows) > MAX_ITEMS or any(
                len(item) != 12 for item in multi_rows
            ):
                raise MonitorError("Invalid selected MultiPID table")
            for item in multi_rows:
                multi_index.setdefault(word(item, 0), []).append(item)
        children = multi_index.get(key, ())
        if not children:
            raise MonitorError(f"Selected MultiPID signal {key} has no children")
        link_count += len(children)
        if link_count > MAX_ITEMS:
            raise MonitorError("Native monitor composite link budget exceeded")
        links = []
        total_bits = 0
        max_ordinal = 0
        for child in children:
            parent, ordinal, child_id = word(child, 0), word(child, 2), word(child, 4)
            item = append(child_id, child[9])
            links.append((parent, ordinal, child_id))
            max_ordinal = max(max_ordinal, ordinal)
            total_bits += item.end_bit - item.start_bit + 1
        groups.append(
            MonitorGroup(
                key, tuple(links), (max_ordinal + 1) & 65535 if total_bits & 7 else None
            )
        )
    return MonitorDefinitions(
        keys,
        tuple(ranges.values()),
        tuple(groups),
        profile.database.sha256,
        _profile_identity(profile),
    )


def select_provider(
    category_flags: int,
    communication_protocol: int,
    attribute_3_31: bool | None,
) -> str:
    """KgpDataMonitorCtrl b0a0: selected DB110 BYTE48 and observed protocol.

    Attribute(3,31) is consulted only for phase4. Its absence must not be
    interpreted as a negative observation.
    """
    if type(category_flags) is not int or not 0 <= category_flags <= 255:
        raise MonitorError("Selected category flags must fit a byte")
    if (
        type(communication_protocol) is not int
        or not 0 <= communication_protocol <= 65535
    ):
        raise MonitorError("Observed communication protocol must fit uint16")
    if attribute_3_31 is not None and type(attribute_3_31) is not bool:
        raise MonitorError("Attribute(3,31) observation must be boolean")
    phase = category_flags & 31
    if phase == 4:
        if attribute_3_31 is None:
            raise MonitorError("Phase4 requires observed Attribute(3,31)")
        return "DM_ActVariable_DT.dll" if attribute_3_31 else "DataMonitorPhase4.dll"
    if phase == 9:
        return (
            "DataMonitorPhase4.dll"
            if communication_protocol & 15 in (2, 8)
            else "DataMonitorPhase3.dll"
        )
    names = {
        1: "DataMonitorDLC12.dll",
        2: "DataMonitorDLC12.dll",
        3: "DataMonitorPhase3.dll",
        5: "DataMonitorPhase3.dll",
        6: "DataMonitorPhase4.dll",
        7: "DataMonitorDKIso9141.dll",
        8: "DataMonitorPhase4.dll",
        10: "DataMonitorPSA_DT.dll",
        18: "DataMonitorPhase3.dll",
        19: "DataMonitorPSA_DT.dll",
        20: "DataMonitorPhase5_DT.dll",
        21: "DataMonitorPhase5_DT.dll",
    }
    try:
        return names[phase]
    except KeyError as error:
        raise MonitorError(
            f"Native monitor provider unavailable for phase {phase}"
        ) from error


@dataclass(frozen=True)
class P4Frame:
    frame_id: int
    support: bytes
    selected_bytes: tuple[int, ...]
    mode: int
    full_length: int


@dataclass(frozen=True)
class P4Packing:
    """Original setup frames, response descriptors and signal range decisions."""

    mode_mask: int
    category_flags: int
    frames: tuple[P4Frame, ...]
    setup_requests: tuple[bytes, ...]
    response_frames: tuple[tuple[int, int], ...]
    ranges: tuple[MonitorRange, ...]


def pack_p4(
    definitions: MonitorDefinitions,
    support: Mapping[int, bytes],
    *,
    category_flags: int,
    capabilities: int,
    excluded: int,
    max_request: int,
    max_reply: int,
) -> P4Packing:
    """Phase4 4da0/5010/5120 with explicit CCmdSupportEcu observations.

    Missing and zero support are distinct. Native ANY supported bit selects the
    whole byte span, except byte_4d==1 which requires every covered byte nonzero.
    """
    if any(
        type(x) is not int or not 0 <= x <= 0xFFFFFFFF for x in (capabilities, excluded)
    ):
        raise MonitorError("Native capability masks must fit uint32")
    if any(type(x) is not int or not 4 <= x <= 255 for x in (max_request, max_reply)):
        raise MonitorError("Native P4 setup requires bounded byte request/reply limits")
    if not definitions.ranges or len(definitions.ranges) > MAX_ITEMS:
        raise MonitorError("Native P4 packing requires bounded ranges")
    if (
        type(category_flags) is not int
        or not 0 <= category_flags <= 255
        or category_flags & 31 not in (4, 6)
    ):
        raise MonitorError("Native P4 cache requires category phase4 or6")

    def full_length(bitmap: bytes) -> int:
        return (
            len(bitmap)
            if category_flags & 31 == 6
            else sum(value != 0 for value in bitmap)
        )

    selected: dict[int, set[int]] = {}
    observations: dict[int, bytes] = {}
    ranges = []
    work = 0
    for item in definitions.ranges:
        bitmap = support.get(item.frame_id)
        if bitmap is not None and (
            not isinstance(bitmap, bytes) or not 1 <= len(bitmap) <= 255
        ):
            raise MonitorError("Native support cache must contain bounded bytes")
        first, last = item.start_bit // 8, item.end_bit // 8
        work += item.end_bit - item.start_bit + 1
        if work > MAX_BYTES:
            raise MonitorError("Native support range aggregate exceeds work budget")
        if bitmap is not None:
            observations.setdefault(item.frame_id, bitmap)
            selected.setdefault(item.frame_id, set())
        enabled = bitmap is not None and last < len(bitmap)
        if enabled:
            assert bitmap is not None
            enabled = (
                all(bitmap[index] != 0 for index in range(first, last + 1))
                if item.byte_4d == 1
                else any(
                    bitmap[bit // 8] & (0x80 >> (bit & 7))
                    for bit in range(item.start_bit, item.end_bit + 1)
                )
            )
        if not enabled:
            if not item.composite_flags & 1:
                raise MonitorError(
                    "Selected signal is unavailable in observed support", 0xC005100C
                )
            ranges.append(replace(item, runtime_flag=1))
        else:
            selected[item.frame_id].update(range(first, last + 1))
            ranges.append(item)
    # 102f0(1) uses107e0: omitted bytes descending, full length descending,
    # then PID ascending. No observed frame is manufactured for missing cache.
    ids = sorted(
        observations,
        key=lambda key: (
            -(len(observations[key]) - len(selected[key])),
            -len(observations[key]),
            key,
        ),
    )
    modes = {key: 0 for key in ids}
    available = capabilities & ~excluded
    mask = 0
    failed = True
    if available & 4:
        used = 0
        failed = False
        for key in ids:
            count = len(selected[key])
            if max_request - 4 <= used:
                failed = True
                break
            if max_request - 2 < count + 2 + used:
                failed = True
            else:
                used += count + 2
                modes[key] = 6
        mask = 4
    if failed:
        if available & 1:
            request_count = response_length = 0
            failed = False
            for key in ids:
                if modes[key] != 6:
                    request_count += 1
                    response_length += full_length(observations[key])
                    if (
                        request_count > max_request - 2
                        or response_length > max_reply - 2
                    ):
                        failed = True
                        break
                    modes[key] = 1
            if not failed:
                mask |= 1
        if failed:
            mask = 0
    if not mask and available & 0x30:
        modes = {key: 0 for key in ids}
        mask = 0x20 if available & 0x20 else 0x10
    if not mask:
        raise MonitorError(
            "No native monitor packing mode fits selected limits", 0x90051001
        )
    frames = tuple(
        P4Frame(
            key,
            observations[key],
            tuple(sorted(selected[key])),
            modes[key],
            full_length(observations[key]),
        )
        for key in sorted(ids)
    )
    requests: list[bytes] = []
    response: list[tuple[int, int]] = []
    if mask in (1, 4, 5):
        for mode in (6, 1):
            group = [
                frame for frame in frames if frame.mode == mode and frame.selected_bytes
            ]
            if group:
                body = b"".join(
                    bytes(
                        (
                            frame.frame_id,
                            len(frame.selected_bytes),
                            *(index + 1 for index in frame.selected_bytes),
                        )
                    )
                    if mode == 6
                    else bytes((frame.frame_id,))
                    for frame in group
                )
                requests.append(bytes((0xA1, mode)) + body)
                response.append(
                    (
                        0x0606 if mode == 6 else 0x0101,
                        sum(
                            len(frame.selected_bytes)
                            if mode == 6
                            else frame.full_length
                            for frame in group
                        ),
                    )
                )
    else:
        active = [frame for frame in frames if frame.selected_bytes]
        if not active:
            raise MonitorError("Native polling setup has no selected bytes", 0x90051010)
        requests.append(
            bytes((1 if mask == 0x10 else 0x21, *(frame.frame_id for frame in active)))
        )
        requests.append(
            bytes(
                (
                    0x41 if mask == 0x10 else 0x61,
                    *(frame.full_length for frame in active),
                )
            )
        )
        response.extend(
            (index << 8, frame.full_length) for index, frame in enumerate(active)
        )
    if any(len(request) > max_request for request in requests):
        raise MonitorError("Native P4 setup exceeds supplied request bound")
    return P4Packing(
        mask, category_flags, frames, tuple(requests), tuple(response), tuple(ranges)
    )


def clear_dynamic_requests(
    profile: VehicleProfile, dids: Sequence[int]
) -> tuple[bytes, ...]:
    """Dual19cb0: selected D4 first frame, replacing only DID bytes2/3."""
    ids = tuple(dids)
    if len(ids) > 255 or any(
        type(did) is not int or not 0 <= did <= 65535 for did in ids
    ):
        raise MonitorError("Native clear dynamic IDs require at most255 uint16 IDs")
    frames = profile.command_frames(0xD4)
    if not frames or not 4 <= len(frames[0].request) <= 4096:
        raise MonitorError("Selected D4 first request requires4..4096 bytes")
    template = frames[0].request
    return tuple(template[:2] + did.to_bytes(2, "big") + template[4:] for did in ids)


@dataclass(frozen=True)
class MonitorCommand:
    """Core-free native DMCI fields; serializers supply their proven cores."""

    command_id: int
    values: tuple[object, ...]


@dataclass(frozen=True)
class MonitorSetup:
    setup: tuple[MonitorCommand, ...]
    start: tuple[MonitorCommand, ...]
    stop: tuple[MonitorCommand, ...]


def p4_setup_commands(
    packing: P4Packing,
    *,
    interface_id: int,
    buffer_468: int,
    total_length: int,
    standard_values: Sequence[tuple[int, int]],
    attribute_2_23: bool,
) -> MonitorSetup:
    """Phase4 dc50→DataListIF2d20/31f0, retaining native DMCI field order.

    Buffer+468 and standard values must come from the generated native monitor
    metadata. This function does not guess buffer ownership or capabilities.
    """
    for value in (interface_id, buffer_468, total_length):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise MonitorError("Native monitor setup DWORD field is invalid")
    if type(attribute_2_23) is not bool:
        raise MonitorError("Native Attribute2/35 must be an explicit boolean")
    standards = tuple(standard_values)
    if len(standards) > MAX_ITEMS or any(
        not isinstance(pair, tuple)
        or len(pair) != 2
        or any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in pair)
        for pair in standards
    ):
        raise MonitorError("Native standard values require bounded DWORD pairs")
    if packing.mode_mask in (1, 4, 5):
        modes = tuple((request[1], request[2:]) for request in packing.setup_requests)
        if not 1 <= len(modes) <= 2 or any(len(body) > 64 for _, body in modes):
            raise MonitorError(
                "Native ModeA1 setup requires1..2 messages of at most64 bytes"
            )
        setup = MonitorCommand(
            0x109, (buffer_468, interface_id, modes, total_length, standards, 3000)
        )
    elif packing.mode_mask in (0x10, 0x20):
        if len(packing.setup_requests) != 2:
            raise MonitorError(
                "Native pair setup requires request and size descriptors"
            )
        ids, lengths = packing.setup_requests
        if len(ids) != len(lengths) or len(ids) < 2:
            raise MonitorError("Native pair setup lengths differ")
        data_type = 0 if packing.mode_mask == 0x10 else (6 if attribute_2_23 else 1)
        setup = MonitorCommand(
            0x10A,
            (
                buffer_468,
                interface_id,
                data_type,
                tuple(zip(ids[1:], lengths[1:])),
                total_length,
                standards,
                3,
                0xFFFFFFFF,
            ),
        )
    else:
        raise MonitorError("Native P4 setup has unsupported mode mask")
    return MonitorSetup(
        (setup,), (MonitorCommand(0x10C, ()),), (MonitorCommand(0x10E, ()),)
    )


@dataclass(frozen=True)
class RoutineMonitor:
    """GetRidSetup's selected frame and three ordered WORD status lists."""

    request: bytes
    size: int
    normal: tuple[int, ...]
    abnormal: tuple[int, ...]
    stop: tuple[int, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.request, bytes) or not 4 <= len(self.request) <= 65535:
            raise MonitorError("Native routine monitor request needs4..65535 bytes")
        if type(self.size) is not int or not 1 <= self.size <= 65535:
            raise MonitorError("Native routine monitor size must fit nonzero uint16")
        for values in (self.normal, self.abnormal, self.stop):
            if (
                not isinstance(values, tuple)
                or len(values) > 65535
                or any(
                    type(value) is not int or not 0 <= value <= 65535
                    for value in values
                )
            ):
                raise MonitorError(
                    "Native routine status lists require bounded uint16 values"
                )

    @property
    def rid(self) -> int:
        return int.from_bytes(self.request[2:4], "big")

    def check_status(
        self, reply: bytes, *, routine_info: bool, abnormal: bool = False
    ) -> bool:
        """Phase5 da00/db40 and Dual15d70/15eb0, including low-byte comparison."""
        if type(routine_info) is not bool or type(abnormal) is not bool:
            raise MonitorError("Native routine-info/status selection must be boolean")
        values = self.abnormal if abnormal else self.normal
        if not values:
            return False
        offset = 5 if routine_info else 4
        if (
            not isinstance(reply, bytes)
            or len(reply) < offset + self.size
            or reply[0] != 0x71
        ):
            raise MonitorError("Native routine status reply is invalid", 0xE0000102)
        if self.size == 2:
            return int.from_bytes(reply[offset : offset + 2], "big") in values
        return any(reply[offset] == (value & 255) for value in values)


def p5_setup_commands(
    *,
    interface_id: int,
    buffer_468: int,
    total_length: int,
    standard_values: Sequence[tuple[int, int]],
    data_ids: Sequence[tuple[int, int]],
    dtc_requests: Sequence[bytes],
    routines: Sequence[RoutineMonitor],
    parameter_6: int,
    dtc_patterns: Sequence[int] | None = None,
    clear_ids: Sequence[int] = (),
) -> MonitorSetup:
    """DataListIF ee90/f340 plus DTC wrapper's native119/11c/10b fields.

    Inputs are already selected metadata and explicit observations. After the
    first buffer registration native wrappers pass total length zero. The final
    DWORD is retained as parameter_6 rather than guessed as a timeout or rate.
    """
    for value in (interface_id, buffer_468, total_length, parameter_6):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise MonitorError("Native P5 setup DWORD is invalid")
    if len(clear_ids) > 255 or any(
        type(did) is not int or not 0 <= did <= 65535 for did in clear_ids
    ):
        raise MonitorError("Native P5 clear list requires bounded WORD identifiers")
    standards = tuple(standard_values)
    ids = tuple(data_ids)
    dtc = tuple(dtc_requests)
    rid = tuple(routines)
    if dtc_patterns is not None and len(dtc_patterns) > MAX_ITEMS:
        raise MonitorError("Native DTC pattern count exceeds budget")
    patterns = (0,) * len(dtc) if dtc_patterns is None else tuple(dtc_patterns)
    if len(patterns) != len(dtc) or any(
        type(value) is not int or not 0 <= value <= 255 for value in patterns
    ):
        raise MonitorError("Native DTC patterns require matching byte values")
    if len(ids) + len(dtc) + len(rid) + len(standards) > MAX_ITEMS or not (
        ids or dtc or rid
    ):
        raise MonitorError("Native P5 setup requires bounded selected entries")
    for values, maximum, name in (
        (standards, 0xFFFFFFFF, "standard"),
        (ids, 65535, "DID"),
    ):
        if any(
            not isinstance(pair, tuple)
            or len(pair) != 2
            or any(
                type(value) is not int or not 0 <= value <= maximum for value in pair
            )
            for pair in values
        ):
            raise MonitorError(f"Native P5 {name} pairs are invalid")
    if any(
        not isinstance(request, bytes) or not 1 <= len(request) <= 65535
        for request in dtc
    ):
        raise MonitorError("Native P5 DTC setup needs bounded selected requests")
    if any(not isinstance(item, RoutineMonitor) for item in rid):
        raise MonitorError("Native P5 RID setup requires typed selected routines")
    if (
        sum(len(request) for request in dtc)
        + sum(
            len(item.request)
            + 2 * (len(item.normal) + len(item.abnormal) + len(item.stop))
            for item in rid
        )
        > MAX_BYTES
    ):
        raise MonitorError("Native P5 setup exceeds byte budget")
    result: list[MonitorCommand] = []
    if ids:
        result.append(
            MonitorCommand(
                0x119,
                (buffer_468, interface_id, ids, total_length, standards, parameter_6),
            )
        )
    for request, pattern in zip(dtc, patterns):
        result.append(
            MonitorCommand(
                0x10B,
                (
                    buffer_468,
                    interface_id,
                    pattern,
                    request,
                    0 if result else total_length,
                    () if result else standards,
                ),
            )
        )
    allocated = bool(result)
    if clear_ids:
        result.append(
            MonitorCommand(
                0x11A, (interface_id, struct.pack(f"<{len(clear_ids)}H", *clear_ids))
            )
        )
    for item in rid:
        result.append(
            MonitorCommand(
                0x11C,
                (
                    buffer_468,
                    interface_id,
                    item.request,
                    item.size,
                    tuple((value,) for value in item.normal),
                    tuple((value,) for value in item.abnormal),
                    0 if allocated else total_length,
                    () if allocated else standards,
                    parameter_6,
                    tuple((value,) for value in item.stop),
                ),
            )
        )
        allocated = True
    return MonitorSetup(
        tuple(result), (MonitorCommand(0x10C, ()),), (MonitorCommand(0x10E, ()),)
    )


class P5MonitorEvent(MonitorEvent):
    """Native Phase5/Dual mixed DID, DTC-count and routine-data cycle."""

    def __init__(
        self,
        data_ids: Sequence[tuple[int, int]],
        dtc_requests: Sequence[bytes],
        routines: Sequence[RoutineMonitor],
        *,
        routine_info: bool,
        dtc_patterns: Sequence[int] | None = None,
    ):
        if type(routine_info) is not bool:
            raise MonitorError("Native routine-info observation must be boolean")
        # The setup producer provides the common bounds before allocation.
        plan = p5_setup_commands(
            interface_id=0,
            buffer_468=0,
            total_length=0,
            standard_values=(),
            data_ids=data_ids,
            dtc_requests=dtc_requests,
            routines=routines,
            parameter_6=0,
            dtc_patterns=dtc_patterns,
        )
        del plan
        requests = []
        sizes = []
        kinds = []
        for did, size in data_ids:
            requests.append(b"\x22" + did.to_bytes(2, "big"))
            sizes.append(size)
            kinds.append(0x22)
        for request in dtc_requests:
            requests.append(request)
            sizes.append(2)
            kinds.append(0x19)
        for routine in routines:
            requests.append(routine.request)
            sizes.append(routine.size)
            kinds.append(0x31)
        size = sum(sizes)
        if size > MAX_BYTES:
            raise MonitorError("Native P5 monitor packet exceeds byte budget")
        self.requests = tuple(requests)
        self.lengths = tuple(sizes)
        self._kinds = tuple(kinds)
        self._dtc_patterns = (
            (0,) * len(data_ids)
            + (
                tuple(dtc_patterns)
                if dtc_patterns is not None
                else (0,) * len(dtc_requests)
            )
            + (0,) * len(routines)
        )
        self.p4_type = None
        self.routine_info = routine_info
        self.index = 0
        self._offset = 0
        self._data = bytearray(size)

    def accept(self, reply: bytes, timestamp_raw: int) -> tuple[int, bytes] | None:
        if type(timestamp_raw) is not int or not 0 <= timestamp_raw <= 0xFFFFFFFF:
            raise MonitorError("Native monitor timestamp must fit uint32")
        if not isinstance(reply, bytes) or not 1 <= len(reply) <= 65535:
            raise MonitorError("Native P5 monitor reply is invalid")
        kind = self._kinds[self.index]
        expected = self.lengths[self.index]
        if reply[0] != kind | 0x40:
            raise MonitorError("Native P5 monitor reply service differs", 0xE0000102)
        if kind == 0x19:
            if self._dtc_patterns[self.index] != 0:
                raise MonitorError("Native P5 DTC pattern is unsupported", 0xE0000102)
            count = max(0, len(reply) - 3) // 4
            payload = count.to_bytes(2, "big")
        else:
            offset = 3 if kind == 0x22 else (5 if self.routine_info else 4)
            if len(reply) < offset or (kind == 0x31 and len(reply) < offset + expected):
                raise MonitorError("Native P5 monitor reply is truncated", 0xE0000102)
            payload = reply[offset : offset + expected]
        self._data[self._offset : self._offset + len(payload)] = payload
        self._offset += expected
        self.index += 1
        if self.index != len(self.requests):
            return None
        packet = bytes(self._data)
        self.index = self._offset = 0
        self._data[:] = bytes(len(self._data))
        if self.pickup_spans:
            packet = pickup_packet(packet, timestamp_raw, self.pickup_spans, p4=False)
        return timestamp_raw, packet


@dataclass(frozen=True)
class MonitorReceive:
    """Literal ReceiveExt observation, including its native status and address."""

    data: bytes
    source_id: int
    code: int

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes) or len(self.data) > 4096:
            raise MonitorError("Native monitor receive exceeds4096 bytes")
        if any(
            type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (self.source_id, self.code)
        ):
            raise MonitorError("Native monitor receive fields must fit uint32")


class MonitorProvider(Protocol):
    """Low-level injected driver calls; None is the actual NULL data pointer."""

    def send(
        self,
        ecu: str,
        request: bytes | None,
        *,
        timeout: int,
        protocol: int,
        initialize: bool,
    ) -> int: ...

    def receive(
        self,
        ecu: str,
        *,
        buffer: bool,
        maximum: int,
        timeout: int,
        argument_5: int,
        flags: int,
    ) -> MonitorReceive: ...


def legacy_initialize(
    provider: MonitorProvider,
    ecu: str,
    *,
    send_timeout: int,
    receive_timeout: int,
    protocol: int,
) -> tuple[int, MonitorReceive]:
    """DkKwpThreadMain2bc70/FuelThreadMain2c530 AT stop GetInitFlag branch.

    Native invokes both calls even if send reports an error, then ignores their
    codes. Both observations are returned here so a caller can retain evidence.
    This is a NULL-pointer driver operation, not an empty diagnostic PDU.
    """
    if not isinstance(ecu, str) or not ecu:
        raise MonitorError("Native initialization requires selected ECU identity")
    if (
        any(
            type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (send_timeout, receive_timeout)
        )
        or type(protocol) is not int
        or not 0 <= protocol <= 65535
    ):
        raise MonitorError("Native initialization timing/protocol fields are invalid")
    sent = provider.send(
        ecu, None, timeout=send_timeout, protocol=protocol, initialize=True
    )
    if type(sent) is not int or not 0 <= sent <= 0xFFFFFFFF:
        raise MonitorError("Native send status must fit uint32")
    received = provider.receive(
        ecu, buffer=False, maximum=0, timeout=receive_timeout, argument_5=0, flags=100
    )
    if not isinstance(received, MonitorReceive) or received.data:
        raise MonitorError("NULL native receive cannot return payload bytes")
    return sent, received


@dataclass(frozen=True)
class MonitorSignalMetadata:
    """Named native SignalItem fields before string encoding/DRS serialization."""

    pid: int
    frame_index: int
    start_bit: int
    end_bit: int
    name: str
    short_name: bytes
    unit: str
    selector: int
    unit_id: int
    sign_mode: int
    multiplier: int
    divisor: int
    offset: int
    precision: int
    minimum_raw: int
    maximum_raw: int
    patterns: tuple[tuple[int, str, int, int], ...]
    extended: tuple[int, int, int]


def selected_signal_metadata(
    profile: VehicleProfile,
    layouts: Sequence[tuple[int, int, int, int]],
    *,
    voltage_state: DLC12VoltageState | None = None,
    voltage_observations: Mapping[int, DLC12VoltageObservation] | None = None,
    lsb_producer: SignalLSB | None = None,
    lsb_observations: Mapping[int, tuple[int, int, int]] | None = None,
) -> tuple[MonitorSignalMetadata, ...]:
    """P4 a3d0 selected Freeze/PhyData/Unit/PatDisp producer.

    Layouts are native packing outputs (PID, frame, first bit, last bit).
    For the exact raw category flag4 LSB branch, matching DB227 rows require
    observed resulting (multiplier,divisor,extended_low) until its wire producer
    is supplied. Absence of a DB227 row is the native identity branch.
    """
    return _selected_signal_metadata(
        profile,
        layouts,
        lsb_producer=lsb_producer,
        lsb_observations=lsb_observations,
        voltage_state=voltage_state,
        voltage_observations=voltage_observations,
    )


def selected_p5_signal_metadata(
    profile: VehicleProfile,
    layouts: Sequence[tuple[int, int, int, int]],
    *,
    source_build: int,
    active_alias_pid: int,
    voltage_state: DLC12VoltageState | None = None,
    voltage_observations: Mapping[int, DLC12VoltageObservation] | None = None,
    lsb_producer: SignalLSB | None = None,
    lsb_observations: Mapping[int, tuple[int, int, int]] | None = None,
) -> tuple[MonitorSignalMetadata, ...]:
    """P5 c8d0 DB23E metadata; alias PID is the observed module WORD1d4.

    P5 uses its64-byte monitor table, with no native short-name assignment.
    LSB exchange output remains explicit when a matching DB240 row exists.
    """
    if type(active_alias_pid) is not int or not 0 <= active_alias_pid <= 65535:
        raise MonitorError("Native P5 active alias PID must fit uint16")
    return _selected_signal_metadata(
        profile,
        layouts,
        lsb_producer=lsb_producer,
        lsb_observations=lsb_observations,
        p5=True,
        source_build=source_build,
        active_alias_pid=active_alias_pid,
        voltage_state=voltage_state,
        voltage_observations=voltage_observations,
    )


def _selected_signal_metadata(
    profile: VehicleProfile,
    layouts: Sequence[tuple[int, int, int, int]],
    *,
    voltage_state: DLC12VoltageState | None = None,
    voltage_observations: Mapping[int, DLC12VoltageObservation] | None = None,
    lsb_producer: SignalLSB | None = None,
    lsb_observations: Mapping[int, tuple[int, int, int]] | None,
    source_build: int | None = None,
    p5: bool = False,
    active_alias_pid: int | None = None,
) -> tuple[MonitorSignalMetadata, ...]:
    if len(layouts) > MAX_ITEMS:
        raise MonitorError("Native signal metadata exceeds item budget")
    if lsb_producer is not None:
        from scripts.monitor_support import monitor_source_identity
        from scripts.signal_lsb import SignalLSB

        if not isinstance(lsb_producer, SignalLSB) or lsb_observations is not None:
            raise MonitorError(
                "Select one concrete LSB producer or explicit observations"
            )
        if (
            monitor_source_identity(profile, lsb_producer.cache.ecu)
            != lsb_producer.identity
        ):
            raise MonitorError(
                "Native LSB producer belongs to another selected profile"
            )
        if p5 and lsb_producer.source_build != source_build:
            raise MonitorError("Native LSB and P5 monitor source builds differ")
    p5_lsb_flags = (0x14, 0x15)
    if p5:
        if type(source_build) is not int or source_build not in (12, 18):
            raise MonitorError("Native P5 metadata requires explicit source build12/18")
        if source_build == 18:
            p5_lsb_flags += (0x34,)
    first: dict[int, bytes] = {}
    # Offsets are producer-specific: P4 a3d0 Freeze84, P5 c8d0 Datamonitor64.
    width, slot, pid_at, phy_at = (64, 62, 36, 42) if p5 else (84, 10, 56, 60)
    low_at, high_at, identifier_at = (12, 16, 28) if p5 else (32, 36, 52)
    minimum_at, maximum_at = (4, 8) if p5 else (24, 28)
    name_at, selector_at, pattern_at = (24, 58, 50) if p5 else (48, 76, 70)
    for row in profile.records(slot):
        if len(row) != width:
            raise MonitorError(f"Native monitor metadata requires{width}-byte rows")
        first.setdefault(word(row, pid_at), row)
    physical: dict[int, bytes] = {}
    for row in profile.records(13):
        if len(row) != 24:
            raise MonitorError("Native PhyData metadata requires24-byte rows")
        physical.setdefault(word(row, 12), row)
    units: dict[int, bytes] = {}
    for row in profile.records(15):
        if len(row) != 12:
            raise MonitorError("Native unit metadata requires12-byte rows")
        units.setdefault(word(row, 4), row)
    patterns: dict[int, list[bytes]] = {}
    for row in profile.records(14):
        if len(row) not in (20, 24):
            raise MonitorError("Native pattern metadata requires20/24-byte rows")
        patterns.setdefault(word(row, 4 if len(row) == 20 else 12), []).append(row)
    result = []
    retained = 0
    language = profile.catalog.language

    def dword(row: bytes, position: int) -> int:
        return int.from_bytes(row[position : position + 4], "little")

    for layout in layouts:
        if (
            not isinstance(layout, tuple)
            or len(layout) != 4
            or any(
                type(value) is not int or not 0 <= value <= 65535 for value in layout
            )
        ):
            raise MonitorError("Native signal layout requires four uint16 fields")
        pid, frame, start, end = layout
        if end < start or pid not in first:
            raise MonitorError("Selected signal layout/Freeze definition is invalid")
        freeze = first[pid]
        phy = physical.get(word(freeze, phy_at))
        if phy is None:
            raise MonitorError("Selected native PhyData row is absent", 0xC0050101)
        multiplier, divisor = dword(phy, 0), dword(phy, 4)
        extended_low = dword(freeze, low_at)
        if (
            profile.category not in (0x68, 999)
            and (
                profile.category_record[72] in p5_lsb_flags
                if p5
                else profile.category_record[72] == 4
            )
            and (
                profile.signal_did_lsb_records(pid)
                if p5
                else profile.signal_lsb_records(pid)
            )
        ):
            if lsb_producer is not None:
                # a3d0/c8d0 construct and destroy a local LSB helper per row.
                # The shared ECU cache survives; helper-local discovery does not.
                row_lsb = SignalLSB(
                    lsb_producer.cache, source_build=lsb_producer.source_build
                )
                method = row_lsb.p5 if p5 else row_lsb.p4
                # DatMonCommon6b0f initializes SignalItem+64 to1. The normal
                # monitor producer unconditionally replaces this after LSB.
                observed = method(
                    pid,
                    exponent=phy[21],
                    width=end - start + 1,
                    multiplier=multiplier,
                    divisor=divisor,
                    threshold=1,
                ).values
            else:
                if lsb_observations is None or pid not in lsb_observations:
                    raise MonitorError(
                        "Selected signal requires native LSB communication observations"
                    )
                observed = lsb_observations[pid]
            if (
                not isinstance(observed, tuple)
                or len(observed) != 3
                or any(
                    type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                    for value in observed
                )
            ):
                raise MonitorError("Native LSB observations require three DWORD fields")
            multiplier, divisor, _ = observed
            # Native a3d0 later overwrites +64 from Freeze20 after LSB.
        offset = dword(phy, 8)
        if profile.category == 0x68:
            from scripts.monitor_dlc12 import DLC12VoltageState, dlc12_voltage_offset

            if not isinstance(voltage_state, DLC12VoltageState):
                raise MonitorError("Voltage metadata requires native calibration state")
            if type(voltage_state.mode) is not int or voltage_state.mode not in (
                0,
                1,
                2,
            ):
                raise MonitorError("Native voltage calibration mode must be0/1/2")
            if voltage_state.mode == 1:
                if voltage_observations is None or pid not in voltage_observations:
                    raise MonitorError(
                        "Voltage calibration requires observed driver results"
                    )
                offset, error = dlc12_voltage_offset(
                    offset, multiplier, divisor, voltage_observations[pid]
                )
                voltage_state.cached_offset = offset
                if error is not None:
                    if len(voltage_state.errors) >= MAX_ITEMS:
                        raise MonitorError("Native voltage diagnostics exceed budget")
                    voltage_state.errors += ((pid, error),)
            elif voltage_state.mode == 2 and voltage_state.cached_offset is not None:
                offset = voltage_state.cached_offset
                if type(offset) is not int or not 0 <= offset <= 0xFFFFFFFF:
                    raise MonitorError("Native voltage cached offset must fit DWORD")
        unit = units.get(word(phy, 14))
        unit_name = "" if unit is None else language.resolve(dword(unit, 0))
        unit_id = 0 if unit is None else word(unit, 6)
        name = language.resolve(dword(freeze, name_at))
        # Native GetDataMonitorShortName returns the row prefix as char*.
        # Keep original bytes; no guessed code page is applied.
        short_name = b"" if p5 else freeze[:24].split(b"\0", 1)[0]
        retained += 4 * (len(name) + len(unit_name)) + len(short_name)
        labels_list = []
        for row in patterns.get(word(freeze, pattern_at), ()):
            text = language.resolve(dword(row, 0))
            retained += 4 * len(text) + 32
            if retained > MAX_BYTES:
                raise MonitorError("Native signal metadata exceeds decoded byte budget")
            if len(row) == 20:
                labels_list.append((word(row, 4), text, word(row, 10), 0))
            else:
                labels_list.append((word(row, 12), text, dword(row, 4), 0))
        labels = tuple(labels_list)
        if retained > MAX_BYTES:
            raise MonitorError("Native signal metadata exceeds decoded byte budget")
        result.append(
            MonitorSignalMetadata(
                0x2134 if p5 and pid == active_alias_pid else pid,
                frame,
                start,
                end,
                name,
                short_name,
                unit_name,
                freeze[selector_at],
                unit_id,
                phy[20],
                multiplier,
                divisor,
                offset,
                phy[21],
                dword(freeze, minimum_at),
                dword(freeze, maximum_at),
                labels,
                (dword(freeze, identifier_at), extended_low, dword(freeze, high_at)),
            )
        )
    return tuple(result)


def p4_signal_layouts(packing: P4Packing) -> tuple[tuple[int, int, int, int], ...]:
    """Native5120→105d0/10aa0 and1aa0 remapping into generated frame fields."""
    frame_index: dict[int, tuple[int, int, P4Frame]] = {}
    offsets = {1: 0, 6: 0}
    for index, frame in enumerate(
        frame for frame in packing.frames if frame.selected_bytes
    ):
        if packing.mode_mask in (1, 4, 5):
            output = frame.mode
            offset = offsets[output]
            offsets[output] += (
                len(frame.selected_bytes) if output == 6 else frame.full_length
            )
        else:
            output, offset = index, 0
        frame_index[frame.frame_id] = (output, offset, frame)
    layouts = []
    for item in packing.ranges:
        if item.runtime_flag == 1:
            continue
        if item.frame_id not in frame_index:
            raise MonitorError("Native signal has no generated frame")
        output, offset, frame = frame_index[item.frame_id]
        first = item.start_bit // 8
        removed = 0
        if packing.category_flags & 31 == 4:
            if (
                first >= len(frame.support)
                or not frame.support[first]
                or first not in frame.selected_bytes
            ):
                raise MonitorError(
                    "Native signal first byte is unavailable", 0xC0050001
                )
            removed = (
                sum(value == 0 for value in frame.support[:first])
                if frame.mode in (0, 1)
                else first - sum(index < first for index in frame.selected_bytes)
            )
        start, end = (
            item.start_bit + (offset - removed) * 8,
            item.end_bit + (offset - removed) * 8,
        )
        if not 0 <= start <= end <= 65535:
            raise MonitorError("Native generated signal bit range exceeds uint16")
        layouts.append((item.signal_id, output, start, end))
    return tuple(layouts)


@dataclass(frozen=True)
class SelectedP4Monitor:
    definitions: MonitorDefinitions
    packing: P4Packing
    signals: tuple[MonitorSignalMetadata, ...]
    frame_sizes: tuple[tuple[int, int], ...]
    commands: MonitorSetup
    pickup_spans: tuple[tuple[int, int], ...]
    source_build: int | None = None


class P4MonitorPlan(Protocol):
    """Selected metadata consumed by the proven common P4 transport constructor."""

    @property
    def definitions(self) -> MonitorDefinitions: ...

    @property
    def packing(self) -> P4Packing: ...

    @property
    def commands(self) -> MonitorSetup: ...


def selected_p4_monitor(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    support: Mapping[int, bytes],
    observed_functions: Mapping[int, bool],
    *,
    interface_id: int,
    excluded: int,
    max_request: int,
    max_reply: int,
    standard_values: Sequence[tuple[int, int]],
    source_build: int | None = None,
    voltage_state: DLC12VoltageState | None = None,
    voltage_observations: Mapping[int, DLC12VoltageObservation] | None = None,
    lsb_producer: SignalLSB | None = None,
    lsb_observations: Mapping[int, tuple[int, int, int]] | None = None,
) -> SelectedP4Monitor:
    """Concrete selected DB→P4 packing→SignalItem fields→native setup producer."""
    if source_build is not None and (
        type(source_build) is not int or source_build not in (12, 18)
    ):
        raise MonitorError("Native P4 source build must be explicit12/18")
    if lsb_producer is not None:
        from scripts.signal_lsb import SignalLSB

        if not isinstance(lsb_producer, SignalLSB):
            raise MonitorError("Native P4 requires concrete selected LSB producer")
        if source_build is not None and source_build != lsb_producer.source_build:
            raise MonitorError("Native P4 LSB source build differs from selected plan")
        source_build = lsb_producer.source_build
    definitions = selected_definitions(profile, selected_ids)
    capabilities = monitor_capabilities(observed_functions)
    packing = pack_p4(
        definitions,
        support,
        category_flags=profile.category_record[72],
        capabilities=capabilities.mask,
        excluded=excluded,
        max_request=max_request,
        max_reply=max_reply,
    )
    layouts = p4_signal_layouts(packing)
    frame_sizes = tuple(
        (identity >> 8, size) for identity, size in packing.response_frames
    )
    layouts, frame_sizes, pickup = p4_composite_layouts(
        definitions, packing, layouts, frame_sizes
    )
    signals = selected_signal_metadata(
        profile,
        layouts,
        lsb_producer=lsb_producer,
        lsb_observations=lsb_observations,
        voltage_state=voltage_state,
        voltage_observations=voltage_observations,
    )
    commands = p4_setup_commands(
        packing,
        interface_id=interface_id,
        buffer_468=profile.category,
        total_length=sum(size for _, size in frame_sizes),
        standard_values=standard_values,
        attribute_2_23=capabilities.attribute_2_23,
    )
    if pickup:
        body = b"".join(
            struct.pack("<II", start & 0xFFFFFFFF, count) for start, count in pickup
        )
        commands = replace(
            commands,
            setup=commands.setup + (MonitorCommand(0x112, (interface_id, body)),),
        )
    return SelectedP4Monitor(
        definitions, packing, signals, frame_sizes, commands, pickup, source_build
    )


def p4_composite_layouts(
    definitions: MonitorDefinitions,
    packing: P4Packing,
    layouts: tuple[tuple[int, int, int, int], ...],
    frame_sizes: tuple[tuple[int, int], ...],
) -> tuple[
    tuple[tuple[int, int, int, int], ...],
    tuple[tuple[int, int], ...],
    tuple[tuple[int, int], ...],
]:
    """P4 2500/1d50/dc50: append each sorted parent's padded pickup frame."""
    return monitor_composite_layouts(definitions, packing.ranges, layouts, frame_sizes)


def monitor_composite_layouts(
    definitions: MonitorDefinitions | P5Definitions,
    source_ranges: Sequence[MonitorRange | P5Range],
    layouts: tuple[tuple[int, int, int, int], ...],
    frame_sizes: tuple[tuple[int, int], ...],
) -> tuple[
    tuple[tuple[int, int, int, int], ...],
    tuple[tuple[int, int], ...],
    tuple[tuple[int, int], ...],
]:
    """Shared native parent/ordinal pickup layout, before phase-specific copying."""
    if (
        any(
            len(items) > MAX_ITEMS
            for items in (definitions.groups, source_ranges, layouts, frame_sizes)
        )
        or sum(
            len(group.links) + int(group.padding_ordinal is not None)
            for group in definitions.groups
        )
        > MAX_ITEMS
    ):
        raise MonitorError("Native composite descriptor aggregate exceeds budget")
    by_pid = {layout[0]: layout for layout in layouts}
    ranges = {item.signal_id: item for item in source_ranges}
    bases = {}
    offset = 0
    for frame, size in frame_sizes:
        bases[frame] = offset * 8
        offset += size
    output_layouts = list(layouts)
    output_sizes = list(frame_sizes)
    pickup = []
    frame = max((frame for frame, _ in frame_sizes), default=0)
    bits = 0
    for group in sorted(definitions.groups, key=lambda item: item.signal_id):
        width = 0
        for _, _, child in sorted(group.links, key=lambda item: item[:2]):
            item = ranges[child]
            count = item.end_bit - item.start_bit + 1
            disabled = (
                item.runtime_flag == 1
                if isinstance(item, P5Range)
                else bool(item.runtime_flag & 1)
            )
            if disabled and item.composite_flags & 1:
                source = -1
            else:
                layout = by_pid[child]
                source = bases[layout[1]] + layout[2]
            pickup.append((source, count))
            width += count
        if group.padding_ordinal is not None:
            padding = 8 - width % 8
            pickup.append((-1, padding))
            width += padding
        frame += 1
        bits += width
        if (
            frame > 255
            or width > 65536
            or bits > MAX_BYTES * 8
            or len(pickup) > MAX_ITEMS
        ):
            raise MonitorError("Native composite pickup exceeds frame/bit/item bounds")
        output_sizes.append((frame, width // 8))
        output_layouts.append((group.signal_id, frame, 0, width - 1))
    return tuple(output_layouts), tuple(output_sizes), tuple(pickup)


def pickup_packet(
    payload: bytes,
    timestamp_raw: int,
    spans: Sequence[tuple[int, int]],
    *,
    p4: bool,
    previous: bytes = b"",
) -> bytes:
    """Literal P4 CheckRcv14d15 and P5 WritePickup163b0 bit copies.

    P4 adds32 before its -1 check and keeps the initial source byte on a byte
    crossing; those original quirks are preserved. P5 handles -1 as zero fill
    and reloads each source byte. Generated groups are padded to whole bytes.
    """
    if (
        not isinstance(payload, bytes)
        or len(payload) > MAX_BYTES
        or type(p4) is not bool
    ):
        raise MonitorError("Invalid native pickup payload/phase")
    if type(timestamp_raw) is not int or not 0 <= timestamp_raw <= 0xFFFFFFFF:
        raise MonitorError("Native pickup timestamp must fit uint32")
    if len(spans) > MAX_ITEMS:
        raise MonitorError("Native pickup exceeds item budget")
    total = 0
    for span in spans:
        if (
            not isinstance(span, tuple)
            or len(span) != 2
            or type(span[0]) is not int
            or not -33 <= span[0] <= 0xFFFFFFFF
            or type(span[1]) is not int
            or not 0 <= span[1] <= 0xFFFFFFFF
        ):
            raise MonitorError("Native pickup requires bounded start/count pairs")
        total += span[1]
        if total > MAX_BYTES * 8 or len(payload) + total // 8 > MAX_BYTES:
            raise MonitorError("Native pickup exceeds aggregate byte budget")
    if total % 8:
        raise MonitorError("Native producer pickup must be byte aligned")
    if not isinstance(previous, bytes) or len(previous) not in (0, total // 8):
        raise MonitorError("Native pickup retained storage has wrong length")
    output_size = total // 8
    retained = previous if p4 and previous else bytes(output_size)
    data = bytearray(timestamp_raw.to_bytes(4, "little") + payload + retained)
    destination = 0
    accumulated = 0
    for start, count in spans:
        original = start & 0xFFFFFFFF
        source = (original + 32) & 0xFFFFFFFF
        # Native P4's ffffffff comparison skips this span entirely14de5.
        if p4 and source == 0xFFFFFFFF:
            continue
        zero = not p4 and original == 0xFFFFFFFF
        if not zero and count:
            if source + count > len(data) * 8:
                raise MonitorError("Native pickup source is outside captured packet")
            initial = data[source // 8]
        else:
            initial = 0
        for bit in range(count):
            value = initial if p4 else (0 if zero else data[(source + bit) // 8])
            if not zero and value & (0x80 >> ((source + bit) & 7)):
                accumulated |= 0x80 >> (destination & 7)
            destination += 1
            if destination & 7 == 0:
                data[4 + len(payload) + destination // 8 - 1] = accumulated
                accumulated = 0
            if p4 and (source + bit + 1) & 7 == 0:
                initial = data[source // 8]
    return bytes(data[4:])


@dataclass(frozen=True)
class MonitorPacket:
    timestamp_raw: int
    payload: bytes


def run_monitor_commands(
    plan: MonitorSetup,
    client: NativeVimClient,
    *,
    interface_id: int,
    frame_sizes: tuple[tuple[int, int], ...],
    phase: int,
    packet_limit: int,
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[MonitorPacket, ...]:
    """Execute native DMCI setup/start/GetMonitorData/stop on an opened interface.

    The client exchanges actual ComTol command bytes; interface creation and its
    observed addressing remain the caller's responsibility. Raw packet ticks are
    preserved. Cleanup has a separate bounded deadline, including on cancellation.
    """
    from scripts.drive_recorder import (
        NativeCoreBuffer,
        NativeDmciCommand,
        NativeMonitorPacketReader,
    )

    if type(interface_id) is not int or not 0 <= interface_id <= 0xFFFFFFFF:
        raise MonitorError("Native monitor interface key must fit uint32")
    if type(packet_limit) is not int or not 1 <= packet_limit <= MAX_ITEMS:
        raise MonitorError("Native monitor packet limit exceeds budget")
    if not isinstance(plan, MonitorSetup):
        raise MonitorError("Native monitor setup is required")
    if sum(map(len, (plan.setup, plan.start, plan.stop))) > MAX_ITEMS:
        raise MonitorError("Native monitor command count exceeds budget")
    # Charge aliased neutral values on every occurrence before native wrappers
    # materialize. A small shared input must not expand commands × list items.
    nodes = retained = 0
    for group in (plan.setup, plan.start, plan.stop):
        if not isinstance(group, tuple):
            raise MonitorError("Native monitor commands require tuple groups")
        for command in group:
            if not isinstance(command, MonitorCommand):
                raise MonitorError("Native monitor command is malformed")
            pending: list[tuple[object, int]] = [(command.values, 0)]
            while pending:
                value, depth = pending.pop()
                nodes += 1
                if nodes > MAX_ITEMS or depth > 8:
                    raise MonitorError("Native monitor aggregate field budget exceeded")
                if isinstance(value, bytes):
                    retained += len(value)
                elif type(value) is int:
                    retained += 8
                elif isinstance(value, tuple):
                    if len(value) + nodes > MAX_ITEMS:
                        raise MonitorError(
                            "Native monitor aggregate field budget exceeded"
                        )
                    retained += 8 * len(value)
                    pending.extend((item, depth + 1) for item in value)
                else:
                    raise MonitorError(
                        "Native monitor requires core-free primitive fields"
                    )
                if retained > MAX_BYTES:
                    raise MonitorError("Native monitor aggregate field bytes exceeded")
    # Validate every command, including cleanup, before the first exchange.
    setup, start, stop = (
        tuple(NativeDmciCommand.from_neutral(c.command_id, c.values) for c in group)
        for group in (plan.setup, plan.start, plan.stop)
    )
    reader = NativeMonitorPacketReader(
        frame_sizes, phase=phase, max_packets=packet_limit, max_bytes=MAX_BYTES
    )
    budget = limits or Limits()
    deadline = clock() + budget.seconds
    if not math.isfinite(deadline):
        raise SessionError("Native monitor clock/deadline must be finite")
    calls = 0

    def remaining() -> float:
        nonlocal calls
        if cancelled():
            raise Cancelled("Native monitor cancelled")
        left = deadline - clock()
        if not math.isfinite(left):
            raise SessionError("Native monitor clock must be finite")
        if left <= 0:
            raise TimeoutError("Native monitor deadline exceeded")
        if calls >= budget.exchanges:
            raise MonitorError("Native monitor exchange budget exceeded")
        calls += 1
        return left

    packets: list[MonitorPacket] = []
    primary: BaseException | None = None
    attempted = False
    try:
        for command in setup + start:
            timeout = remaining()
            attempted = True
            response = client.dmci(command, timeout=timeout, cancelled=cancelled)
            # SetNegCountRcv adds a DWORD boolean after the checked status.
            if command.command_id == 0x114 and response != struct.pack("<I", 1):
                raise MonitorError("Native SetNegCount did not return true", 0xA0050425)
        while len(packets) < packet_limit:
            timeout = remaining()
            attempted = True
            reply = client.get_monitor_data(
                (interface_id,), timeout=timeout, cancelled=cancelled
            )
            seen = False
            for key, buffer in reply.interfaces.items:
                if (
                    key != interface_id
                    or seen
                    or not isinstance(buffer, NativeCoreBuffer)
                ):
                    raise MonitorError("Unexpected or duplicate monitor interface data")
                seen = True
                packets.extend(
                    MonitorPacket(item.timestamp_ms, item.payload)
                    for item in reader.feed(buffer.data)
                )
        reader.finish()
        if cancelled():
            raise Cancelled("Native monitor cancelled")
        finished = clock()
        if not math.isfinite(finished):
            raise SessionError("Native monitor clock must be finite")
        if finished >= deadline:
            raise TimeoutError("Native monitor deadline exceeded")
        return tuple(packets)
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if attempted:
            cleanup_errors: list[Exception] = []
            try:
                cleanup_deadline = clock() + budget.seconds
            except Exception as error:  # noqa: BLE001 - retain the primary failure
                cleanup_errors.append(error)
                cleanup_deadline = None
            for command in stop:
                if cleanup_deadline is None:
                    break
                try:
                    left = cleanup_deadline - clock()
                    if not math.isfinite(left):
                        raise SessionError("Native monitor stop clock must be finite")
                    if left <= 0:
                        raise TimeoutError("Native monitor stop deadline exceeded")
                    client.dmci(command, timeout=left, cancelled=lambda: False)
                except Exception as exc:  # noqa: BLE001 - preserve primary failure during cleanup
                    cleanup_errors.append(exc)
            if cleanup_errors:
                if primary is not None:
                    for error in cleanup_errors:
                        primary.add_note(f"Native monitor stop failed: {error}")
                else:
                    raise MonitorError(
                        f"Native monitor stop failed: {cleanup_errors[0]}"
                    ) from cleanup_errors[0]


@dataclass(frozen=True)
class P5Range:
    """Phase5 102b0 descriptor: word DID and DWORD flags, unlike P4."""

    start_bit: int
    end_bit: int
    signal_id: int
    frame_id: int
    byte_4d: int
    flags: int
    composite_flags: int
    runtime_flag: int = 0

    def __post_init__(self) -> None:
        if any(
            type(v) is not int or not 0 <= v <= 65535
            for v in (self.start_bit, self.end_bit, self.signal_id, self.frame_id)
        ):
            raise MonitorError("Native P5 range requires uint16 fields")
        if self.end_bit < self.start_bit:
            raise MonitorError("Native P5 range ends before its start")
        if type(self.flags) is not int or not 0 <= self.flags <= 0xFFFFFFFF:
            raise MonitorError("Native P5 range flags must fit uint32")
        if any(
            type(v) is not int or not 0 <= v <= 255
            for v in (self.byte_4d, self.composite_flags, self.runtime_flag)
        ):
            raise MonitorError("Native P5 range byte fields are invalid")


@dataclass(frozen=True)
class P5Definitions:
    selected_ids: tuple[int, ...]
    ranges: tuple[P5Range, ...]
    groups: tuple[MonitorGroup, ...]
    source_sha256: str
    source_identity: tuple[object, ...] = ()


def selected_p5_definitions(
    profile: VehicleProfile, selected_ids: Sequence[int]
) -> P5Definitions:
    """Native Phase5 102b0 DB23E/DB21A first-match range producer."""
    keys = tuple(selected_ids)
    if (
        not keys
        or len(keys) > MAX_ITEMS
        or any(type(key) is not int or not 0 <= key <= 65535 for key in keys)
    ):
        raise MonitorError("Select bounded uint16 P5 signal IDs")
    rows = profile.records(62)
    if len(rows) > MAX_ITEMS or any(len(row) != 64 for row in rows):
        raise MonitorError("Selected P5 monitor table requires bounded64-byte rows")
    first: dict[int, bytes] = {}
    for row in rows:
        first.setdefault(word(row, 36), row)
    ranges: dict[int, P5Range] = {}
    groups = []
    multi_index: dict[int, list[bytes]] | None = None
    links_used = 0

    def append(pid: int, flags: int) -> P5Range:
        if pid not in first:
            raise MonitorError(f"Selected P5 signal {pid} is absent")
        row = first[pid]
        native_flags = int.from_bytes(row[32:36], "little")
        if native_flags & 16:
            raise MonitorError("P5 composite child cannot be another composite")
        if pid not in ranges:
            ranges[pid] = P5Range(
                word(row, 44),
                word(row, 46),
                pid,
                word(row, 54),
                row[59],
                native_flags,
                flags,
            )
        else:
            ranges[pid] = replace(
                ranges[pid], composite_flags=ranges[pid].composite_flags | flags
            )
        if len(ranges) > MAX_ITEMS:
            raise MonitorError("Native P5 range budget exceeded")
        return ranges[pid]

    for pid in keys:
        if pid in ranges:
            continue
        if pid not in first:
            raise MonitorError(f"Selected P5 signal {pid} is absent")
        if not int.from_bytes(first[pid][32:36], "little") & 16:
            append(pid, 0)
            continue
        if multi_index is None:
            multi_index = {}
            multi_rows = profile.records(26)
            if len(multi_rows) > MAX_ITEMS or any(len(r) != 12 for r in multi_rows):
                raise MonitorError("Invalid selected P5 MultiPID table")
            for row in multi_rows:
                multi_index.setdefault(word(row, 0), []).append(row)
        children = multi_index.get(pid, ())
        if not children:
            raise MonitorError(f"Selected P5 MultiPID signal {pid} has no children")
        links_used += len(children)
        if links_used > MAX_ITEMS:
            raise MonitorError("Native P5 composite link budget exceeded")
        links = []
        bits = 0
        max_ordinal = 0
        for child in children:
            ordinal, child_id = word(child, 2), word(child, 4)
            item = append(child_id, child[9])
            links.append((pid, ordinal, child_id))
            max_ordinal = max(max_ordinal, ordinal)
            bits += item.end_bit - item.start_bit + 1
        groups.append(
            MonitorGroup(
                pid, tuple(links), (max_ordinal + 1) & 65535 if bits & 7 else None
            )
        )
    return P5Definitions(
        keys,
        tuple(ranges.values()),
        tuple(groups),
        profile.database.sha256,
        _profile_identity(profile),
    )


@dataclass(frozen=True)
class P5PollingPacking:
    data_ids: tuple[tuple[int, int], ...]
    frame_sizes: tuple[tuple[int, int], ...]
    ranges: tuple[P5Range, ...]
    layouts: tuple[tuple[int, int, int, int], ...]


def pack_p5_polling(
    definitions: P5Definitions,
    enabled_dids: Sequence[int],
    observed_functions: Mapping[int, bool],
    *,
    excluded: int,
) -> P5PollingPacking:
    """Native6d80 range selection and6960 direct DID registration.

    This is the explicit non-dynamic mode20 branch of4eb0. Enabled DID IDs are
    observed cache contents, not inferred from database definitions. DTC ranges
    use a separate native producer and are rejected here.
    """
    if type(excluded) is not int or not 0 <= excluded <= 0xFFFFFFFF:
        raise MonitorError("Native P5 excluded modes must fit uint32")
    for key in (0x1A, 0x49):
        if key not in observed_functions or type(observed_functions[key]) is not bool:
            raise MonitorError(f"P5 requires observed Attribute(2,{key})")
    mask = (4 if observed_functions[0x1A] else 0) | (
        0x20 if observed_functions[0x49] else 0
    )
    if not mask:
        raise MonitorError("Native P5 has no observed monitor mode", 0x90051007)
    if not mask & ~excluded & 0x20:
        raise MonitorError("Native P5 direct DID mode is unavailable", 0x90051001)
    lengths, ranges = _p5_range_selection(definitions, enabled_dids)
    if not lengths:
        raise MonitorError("Native P5 has no direct DID frames", 0x90051010)
    if len(lengths) > 256 or sum(lengths.values()) > MAX_BYTES:
        raise MonitorError("Native P5 direct DID output exceeds frame/byte budget")
    frame_index = {did: index for index, did in enumerate(lengths)}
    layouts = tuple(
        (item.signal_id, frame_index[item.frame_id], item.start_bit, item.end_bit)
        for item in ranges
        if item.runtime_flag != 1
    )
    return P5PollingPacking(
        tuple(lengths.items()),
        tuple((frame_index[did], length) for did, length in lengths.items()),
        tuple(ranges),
        layouts,
    )


@dataclass(frozen=True)
class SelectedP5PollingMonitor:
    definitions: P5Definitions
    packing: P5PollingPacking
    signals: tuple[MonitorSignalMetadata, ...]
    frame_sizes: tuple[tuple[int, int], ...]
    commands: MonitorSetup
    pickup_spans: tuple[tuple[int, int], ...]
    source_build: int | None = None


@dataclass(frozen=True)
class SelectedP5DynamicMonitor:
    definitions: P5Definitions
    selection: P5DynamicSelection
    outcome: DynamicOutcome
    signals: tuple[MonitorSignalMetadata, ...]
    frame_sizes: tuple[tuple[int, int], ...]
    commands: MonitorSetup
    pickup_spans: tuple[tuple[int, int], ...]
    source_build: int | None = None


class DynamicRegistrationError(MonitorError):
    """Registration needs native direct fallback; retain its observed side effects."""

    def __init__(self, outcome: DynamicOutcome):
        super().__init__(
            "Native dynamic registration requires direct-DID fallback", outcome.status
        )
        self.outcome = outcome


class P5MonitorPlan(Protocol):
    """Selected P5 metadata needed by the concrete CAN lifecycle."""

    @property
    def definitions(self) -> P5Definitions: ...

    @property
    def commands(self) -> MonitorSetup: ...

    @property
    def source_build(self) -> int | None: ...


def selected_p5_polling_monitor(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    enabled_dids: Sequence[int],
    observed_functions: Mapping[int, bool],
    *,
    interface_id: int,
    excluded: int,
    standard_values: Sequence[tuple[int, int]],
    parameter_6: int,
    source_build: int,
    active_alias_pid: int,
    voltage_state: DLC12VoltageState | None = None,
    voltage_observations: Mapping[int, DLC12VoltageObservation] | None = None,
    lsb_producer: SignalLSB | None = None,
    lsb_observations: Mapping[int, tuple[int, int, int]] | None = None,
) -> SelectedP5PollingMonitor:
    """Selected normal P5 direct-DID path, with explicit non-dynamic policy.

    The caller chooses this branch; dynamic discovery, DTC/RID selection and
    transport initialization belong to their separate native producer paths.
    """
    definitions = selected_p5_definitions(profile, selected_ids)
    packing = pack_p5_polling(
        definitions, enabled_dids, observed_functions, excluded=excluded
    )
    layouts, frames, pickup = monitor_composite_layouts(
        definitions, packing.ranges, packing.layouts, packing.frame_sizes
    )
    signals = selected_p5_signal_metadata(
        profile,
        layouts,
        source_build=source_build,
        active_alias_pid=active_alias_pid,
        lsb_producer=lsb_producer,
        lsb_observations=lsb_observations,
        voltage_state=voltage_state,
        voltage_observations=voltage_observations,
    )
    commands = p5_setup_commands(
        interface_id=interface_id,
        buffer_468=profile.category,
        total_length=sum(size for _, size in frames),
        standard_values=standard_values,
        data_ids=packing.data_ids,
        dtc_requests=(),
        routines=(),
        parameter_6=parameter_6,
    )
    if pickup:
        payload = b"".join(
            struct.pack("<II", start & 0xFFFFFFFF, count) for start, count in pickup
        )
        commands = replace(
            commands,
            setup=commands.setup + (MonitorCommand(0x112, (interface_id, payload)),),
        )
    return SelectedP5PollingMonitor(
        definitions, packing, signals, frames, commands, pickup, source_build
    )


@dataclass(frozen=True)
class MonitorAddress:
    request_id: int
    response_id: int
    functional_id: int


def p4_monitor_address(
    *,
    bus_id: int,
    category_flags: int,
    default_request: int,
    target: int,
    can_word: int,
) -> MonitorAddress:
    """Literal P4 b220 and10af0 address construction, with DWORD wrapping.

    bus_id is observed GetBusId; default_request/target are selected ProtInfo
    WORD6/WORD8 (target may be the observed diagnostic DWORD8 override).
    can_word is selected ProtInfo WORD10. This does not open an interface.
    """
    for value, maximum in (
        (bus_id, 65535),
        (category_flags, 255),
        (default_request, 65535),
        (target, 0xFFFFFFFF),
        (can_word, 65535),
    ):
        if type(value) is not int or not 0 <= value <= maximum:
            raise MonitorError("Native monitor address inputs exceed field bounds")
    low, high = bus_id & 15, bus_id & 0xF0
    if low == 2:
        source = 0
    elif low in (1, 6, 7, 8, 9):
        source = 0xF1 if category_flags & 0xE0 == 0x80 else 0xF0
    else:
        source = 0
    request = response = functional = 0xFFFFFFFF
    if low in (1, 9):
        if high in (0x10, 0x50):
            request = (target | 0x8000) << 8 | source
            if default_request:
                functional = (default_request | 0xC000) << 8 | source
        elif high == 0x20:
            request, response = source | 0x686A00, target | 0x486B00
        elif high == 0x30:
            request = (default_request | 0xC000) << 8 | source
            response = (source | 0x8000) << 8 | target
        else:
            raise MonitorError("Unsupported native monitor bus subtype", 0xC0050001)
    elif low == 2:
        if high == 0x10:
            request, response = target, target | 8
        elif high == 0x20:
            request = (target | 0xFF800000) << 8 | can_word
            response = (target | 0xFF800008) << 8 | can_word
        elif high == 0x30:
            request, response = default_request, target | 8
        else:
            raise MonitorError("Unsupported native monitor CAN subtype", 0xC0050001)
    elif low in (5, 12):
        request = target
    elif low == 6:
        request, response = source | 0x616A00, target | 0x416B00
    elif low == 7:
        request, response = source | 0x686A00, target | 0x486B00
    elif low == 8:
        if high == 0x10:
            request = (target | 0xFFD8DA00) << 8 | source
            response = (source | 0xFFD8DA00) << 8 | target
        elif high == 0x30:
            request = (default_request | 0xFFD8DB00) << 8 | source
            response = (source | 0xFFD8DA00) << 8 | target
        else:
            raise MonitorError(
                "Unsupported native monitor extended CAN subtype", 0xC0050001
            )
    else:
        raise MonitorError("Unsupported native monitor bus family", 0xC0050001)
    return MonitorAddress(
        request & 0xFFFFFFFF, response & 0xFFFFFFFF, functional & 0xFFFFFFFF
    )


@dataclass(frozen=True)
class SelectedMonitorConnection:
    ecu_id: int
    bus_id: int
    address: MonitorAddress
    maximum_request: int
    maximum_reply: int
    parameter_word: int
    can_word: int
    can_parameter: int
    can_byte_0: int
    can_byte_1: int
    protocol_record: bytes
    can_record: bytes | None
    source_identity: tuple[object, ...] = ()


@dataclass(frozen=True)
class SelectedP5CanConnection:
    connection: SelectedMonitorConnection
    additional_request_id: int
    additional_response_id: int
    entry_parameter: int
    source_build: int


def selected_p5_can_connection(
    profile: VehicleProfile,
    *,
    bus_id: int,
    diagnostic_mode: bytes,
    controller_category_flags: int,
    source_build: int,
) -> SelectedP5CanConnection:
    """Native12 a850/d630 and18 b780/e7b0 selected P5 CAN connection."""
    if type(source_build) is not int or source_build not in (12, 18):
        raise MonitorError("P5 CAN connection requires explicit source build12/18")
    if type(bus_id) is not int or not 0 <= bus_id <= 65535 or bus_id & 15 not in (2, 8):
        raise MonitorError("Native P5 CAN connection requires CAN bus family2/8")
    # P5 additionally accepts subtype60 with the subtype10 physical address rule.
    address_bus = (bus_id & ~0xF0) | 0x10 if bus_id & 0xFF == 0x62 else bus_id
    if not isinstance(diagnostic_mode, bytes) or len(diagnostic_mode) != 16:
        raise MonitorError("Native P5 requires observed16-byte diagnostic mode")
    if profile.category in (0x68, 999):
        raise MonitorError("Native P5 instrument category uses separate interface")
    protocol = profile.protocol_info(bus_id)
    if protocol is None or len(protocol) not in (24, 28):
        raise MonitorError("Selected native P5 ProtInfo row is absent", 0xC0050101)
    rows = profile.comm_info_can_records(word(protocol, 2))
    if not rows or len(rows[0]) != 28:
        raise MonitorError("Selected native P5 CommInfoCan row is absent", 0xC0050101)
    can = rows[0]
    target = int.from_bytes(diagnostic_mode[8:12], "little") or word(protocol, 8)
    address = p4_monitor_address(
        bus_id=address_bus,
        category_flags=controller_category_flags,
        default_request=word(protocol, 6),
        target=target,
        can_word=word(protocol, 10),
    )
    base = SelectedMonitorConnection(
        profile.category,
        bus_id,
        address,
        word(protocol, 14),
        word(protocol, 16),
        180000,
        word(protocol, 10),
        word(can, 12),
        can[0],
        can[1],
        protocol,
        can,
        _profile_identity(profile),
    )
    additional_request = additional_response = 0xFFFFFFFF
    if bus_id & 15 == 2 and bus_id & 0xF0 in (0x10, 0x60):
        additional_request = word(protocol, 6) or 0xFFFFFFFF
        additional_response = word(protocol, 20)
        additional_response = (
            additional_response | 8 if additional_response else 0xFFFFFFFF
        )
    entry = int.from_bytes(diagnostic_mode[8:12], "little") or word(protocol, 8)
    return SelectedP5CanConnection(
        base, additional_request, additional_response, entry, source_build
    )


def p5_can_lifecycle(
    plan: P5MonitorPlan,
    selected: SelectedP5CanConnection,
    *,
    connected_device: int,
    routine_info: int | None,
    recording: bool,
) -> MonitorSetup:
    """Native12 11380/10b00 and18 12860/11fe0 DMCI CAN lifecycle.

    routine_info is the observed shared-list enum1/2/3; None represents its
    native lookup error branch. recording reflects the actual writer presence.
    Direct J2534 and its security-release flag use their separate interface.
    """
    if (
        type(connected_device) is not int
        or not (connected_device == 4 or connected_device == 8 and recording is True)
        or selected.source_build not in (12, 18)
    ):
        raise MonitorError(
            "Native P5 CAN requires source12/18 device4 or device8 recording writer"
        )
    if (
        type(recording) is not bool
        or routine_info is not None
        and (type(routine_info) is not int or routine_info not in (1, 2, 3))
    ):
        raise MonitorError("Native P5 routine-info/writer observation is invalid")
    connection = selected.connection
    if plan.source_build != selected.source_build:
        raise MonitorError("P5 monitor and connection native source builds differ")
    if (
        not connection.source_identity
        or connection.source_identity != plan.definitions.source_identity
    ):
        raise MonitorError("P5 connection and monitor selected source identity differ")
    if (
        connection.can_record is None
        or len(connection.can_record) != 28
        or int.from_bytes(connection.can_record[4:8], "little") != 500000
    ):
        raise MonitorError(
            "Native P5 CAN producer only accepts selected500000 baud", 0xC0050101
        )
    if not plan.commands.setup or plan.commands.setup[0].values[:2] != (
        connection.ecu_id,
        connection.address.request_id,
    ):
        raise MonitorError("P5 setup differs from selected connection")
    filters = (
        (0xC6D78800, 0x392877FF)
        if connection.bus_id & 15 == 8
        else (0xE0000000, 0x1FFFFFFF)
    )
    setup = [
        MonitorCommand(0x118, (1, 0x36, *filters, 0xC6, 0x40030, 1, 2, 10)),
        MonitorCommand(0x107, (3,)),
        MonitorCommand(0x11E, (int(routine_info == 2),)),
    ]
    pairs = [(connection.address.request_id, connection.address.response_id)]
    if (
        not recording
        and selected.additional_request_id != 0xFFFFFFFF
        and selected.additional_response_id != 0xFFFFFFFF
    ):
        pairs.append((selected.additional_request_id, selected.additional_response_id))
    setup.extend(
        MonitorCommand(
            0x111,
            dmci_id_map_fields(
                request,
                response,
                connection.can_parameter,
                connection.can_byte_0,
                connection.can_byte_1,
            ),
        )
        for request, response in pairs
    )
    setup.extend(
        MonitorCommand(0x114, (request, response, 180000))
        for request, response in pairs
    )
    return MonitorSetup(
        tuple(setup) + plan.commands.setup,
        plan.commands.start,
        plan.commands.stop + (MonitorCommand(0x108, ()), MonitorCommand(0x104, ())),
    )


def selected_p4_connection(
    profile: ProtocolProfile,
    *,
    bus_id: int,
    diagnostic_mode: bytes,
    controller_category_flags: int,
) -> SelectedMonitorConnection:
    """P4 8fc0 selected ProtInfo/CommInfoCan and observed diagnostic override.

    Controller flags are explicit because a multi-ECU controller's flag byte
    need not equal an individual target's category flags. No device is opened.
    """
    if type(bus_id) is not int or not 1 <= bus_id <= 65535:
        raise MonitorError(
            "Native connection requires nonzero observed bus ID", 0xC0040602
        )
    if not isinstance(diagnostic_mode, bytes) or len(diagnostic_mode) != 16:
        raise MonitorError("Native connection requires observed16-byte diagnostic mode")
    if profile.category in (0x68, 999):
        raise MonitorError("Voltage/sentinel targets use their separate interface path")
    protocol = profile.protocol_info(bus_id)
    if protocol is None or len(protocol) not in (24, 28):
        raise MonitorError("Selected native ProtInfo row is absent", 0xC0050101)
    override = int.from_bytes(diagnostic_mode[8:12], "little")
    target = override or word(protocol, 8)
    can_word = can_parameter = can_byte_0 = can_byte_1 = 0
    can_record = None
    if bus_id & 15 in (2, 8):
        rows = profile.comm_info_can_records(word(protocol, 2))
        if not rows:
            raise MonitorError("Selected native CommInfoCan row is absent", 0xC0050101)
        can_record = rows[0]
        if len(can_record) != 28:
            raise MonitorError("Native CommInfoCan row must contain28 bytes")
        can_word, can_parameter = word(protocol, 10), word(can_record, 12)
        can_byte_0, can_byte_1 = can_record[0], can_record[1]
    address = p4_monitor_address(
        bus_id=bus_id,
        category_flags=controller_category_flags,
        default_request=word(protocol, 6),
        target=target,
        can_word=can_word,
    )
    return SelectedMonitorConnection(
        profile.category,
        bus_id,
        address,
        word(protocol, 14),
        word(protocol, 16),
        word(protocol, 18) or 100,
        can_word,
        can_parameter,
        can_byte_0,
        can_byte_1,
        protocol,
        can_record,
        _profile_identity(profile),
    )


def selected_dual_target(
    profile: VehicleProfile,
    plan: SelectedP4Monitor | P5MonitorPlan,
    *,
    ecu: str,
    bus_id: int,
    diagnostic_mode: bytes,
    controller_category_flags: int,
    source_build: int,
    retry_limit: int,
    send_timeout: int,
    receive_timeout: int,
    map_values: tuple[int, int, int],
) -> DualTarget:
    """Bind selected normal packing and actual connection fields to Dual entry.

    Both native controllers use the selected request address as interface key.
    Driver observations and application build remain explicit caller inputs.
    """
    from scripts.monitor_dual import DualTarget

    if type(source_build) is not int or source_build not in (12, 18):
        raise MonitorError("Native Dual requires explicit source build12/18")
    if type(plan.source_build) is not int or plan.source_build != source_build:
        raise MonitorError("Native Dual plan and controller source builds differ")
    identity = _profile_identity(profile)
    if not identity or plan.definitions.source_identity != identity:
        raise MonitorError(
            "Native Dual plan belongs to another selected source identity"
        )
    phase5 = isinstance(plan.definitions, P5Definitions)
    if phase5:
        if profile.category_record[72] & 31 != 20:
            raise MonitorError("Native Dual P5 target requires category phase20")
        selected = selected_p5_can_connection(
            profile,
            bus_id=bus_id,
            diagnostic_mode=diagnostic_mode,
            controller_category_flags=controller_category_flags,
            source_build=source_build,
        )
        connection, entry = selected.connection, selected.entry_parameter
    else:
        connection = selected_p4_connection(
            profile,
            bus_id=bus_id,
            diagnostic_mode=diagnostic_mode,
            controller_category_flags=controller_category_flags,
        )
        entry = int.from_bytes(diagnostic_mode[8:12], "little") or word(
            connection.protocol_record, 8
        )
    request_id = connection.address.request_id
    if not plan.commands.setup:
        raise MonitorError("Native Dual selected plan has no monitor setup")
    for command in plan.commands.setup:
        index = 0 if command.command_id in (0x112, 0x11A) else 1
        allowed = (0x119, 0x10B, 0x11C, 0x112, 0x11A) if phase5 else (0x10A, 0x112)
        if (
            command.command_id not in allowed
            or len(command.values) <= index
            or command.values[index] != request_id
        ):
            raise MonitorError(
                "Native Dual selected setup differs from target request address"
            )
    return DualTarget(
        ecu,
        request_id,
        connection.address.response_id,
        bus_id,
        profile.category_record[72],
        profile.category,
        retry_limit,
        send_timeout,
        receive_timeout,
        map_values,
        entry,
    )


def p4_can_lifecycle(
    plan: P4MonitorPlan,
    connection: SelectedMonitorConnection,
    *,
    connected_device: int,
    interrupt_send_timing: bool,
    recording: bool = False,
) -> MonitorSetup:
    """Single-ECU native P4 d7e0/eac0/a1e0 and DataListIF1d1d0 CAN path.

    Device4 and an explicit device8 recording writer use this DMCI route.
    Live device8 has its distinct J2534 interface.
    """
    if (
        type(connected_device) is not int
        or type(recording) is not bool
        or not (connected_device == 4 or connected_device == 8 and recording)
    ):
        raise MonitorError("P4 CAN DMCI requires device4 or device8 recording writer")
    if type(interrupt_send_timing) is not bool:
        raise MonitorError("P4 requires observed Attribute(2,60)")
    if (
        connection.bus_id & 15 not in (2, 8)
        or connection.can_record is None
        or len(connection.can_record) != 28
    ):
        raise MonitorError("P4 CAN lifecycle requires selected CAN connection")
    if int.from_bytes(connection.can_record[4:8], "little") != 500000:
        raise MonitorError("Native P4 CAN producer only accepts500000 baud", 0xC0050101)
    if not plan.commands.setup or plan.commands.setup[0].values[:2] != (
        connection.ecu_id,
        connection.address.request_id,
    ):
        raise MonitorError("P4 monitor setup does not match selected connection")
    filters = (
        (0xC6D78800, 0x392877FF)
        if connection.bus_id & 15 == 8
        else (0xE0000000, 0x1FFFFFFF)
    )
    return _p4_transport_lifecycle(
        plan,
        connection,
        MonitorCommand(0x101, (1, 0x36, *filters, 0xC6, 0x40030, 1, 2, 10)),
        interrupt_send_timing=interrupt_send_timing,
    )


def _p4_transport_lifecycle(
    plan: P4MonitorPlan,
    connection: SelectedMonitorConnection,
    create: MonitorCommand,
    *,
    interrupt_send_timing: bool,
) -> MonitorSetup:
    if type(interrupt_send_timing) is not bool:
        raise MonitorError("P4 requires observed Attribute(2,60)")
    if (
        not connection.source_identity
        or connection.source_identity != plan.definitions.source_identity
    ):
        raise MonitorError("P4 connection and monitor selected source identity differ")
    if not plan.commands.setup or plan.commands.setup[0].values[:2] != (
        connection.ecu_id,
        connection.address.request_id,
    ):
        raise MonitorError("P4 monitor setup does not match selected connection")
    setup = (
        create,
        MonitorCommand(0x107, (1,)),
        MonitorCommand(
            0x111,
            dmci_id_map_fields(
                connection.address.request_id,
                connection.address.response_id,
                connection.can_parameter,
                connection.can_byte_0,
                connection.can_byte_1,
            ),
        ),
        MonitorCommand(
            0x114,
            (
                connection.address.request_id,
                connection.address.response_id,
                connection.parameter_word,
            ),
        ),
    )
    if plan.packing.mode_mask in (1, 4, 5) and interrupt_send_timing:
        setup += (MonitorCommand(0x116, (3,)),)
    return MonitorSetup(
        setup + plan.commands.setup,
        plan.commands.start,
        plan.commands.stop + (MonitorCommand(0x108, ()), MonitorCommand(0x104, ())),
    )


def p4_iso_configs(row: bytes, *, bus_id: int) -> tuple[tuple[int, int], ...]:
    """P4 9ce0's23 native SCONFIG pairs in their original order."""
    if not isinstance(row, bytes) or len(row) != 56:
        raise MonitorError("Native CommInfoIso row must contain56 bytes")
    if type(bus_id) is not int or not 0 <= bus_id <= 65535:
        raise MonitorError("Native ISO configuration bus must fit uint16")
    fields = (
        (6, 30),
        (7, 28),
        (8, 34),
        (9, 32),
        (10, 38),
        (11, 36),
        (12, 42),
        (13, 40),
        (14, 10),
        (0x10005, 8),
        (15, 14),
        (0x10006, 12),
        (16, 18),
        (0x10007, 16),
        (17, 22),
        (0x10008, 20),
        (18, 26),
        (0x10009, 24),
        (19, 44),
        (20, 46),
        (21, 48),
    )
    return (
        ((1, int.from_bytes(row[:4], "little")),)
        + tuple((parameter, word(row, position)) for parameter, position in fields)
        + ((0x1000A, int(bool(bus_id & 8))),)
    )


def selected_p4_from_exchange(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    exchange: SupportTransaction,
    ecu: str,
    observed_functions: Mapping[int, bool],
    *,
    source_build: int,
    support_stream: SupportStream,
    bus_id: int,
    interface_id: int,
    excluded: int,
    max_request: int,
    max_reply: int,
    standard_values: Sequence[tuple[int, int]],
    lsb_producer: SignalLSB | None = None,
    lsb_observations: Mapping[int, tuple[int, int, int]] | None = None,
    voltage_state: DLC12VoltageState | None = None,
    voltage_observations: Mapping[int, DLC12VoltageObservation] | None = None,
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> SelectedP4Monitor:
    """Original streamed CreatePid support producer feeding concrete P4 packing."""
    from scripts.monitor_support import MonitorSupportCache

    selected_definitions(profile, selected_ids)
    monitor_capabilities(observed_functions)
    if profile.category_record[72] & 31 not in (4, 6):
        raise MonitorError("Native P4 cache requires category phase4 or6")
    if any(
        type(value) is not int or not 4 <= value <= 255
        for value in (max_request, max_reply)
    ):
        raise MonitorError("Native P4 setup requires bounded byte request/reply limits")
    if any(
        type(value) is not int or not 0 <= value <= 0xFFFFFFFF
        for value in (interface_id, excluded)
    ):
        raise MonitorError("Native P4 interface/mask must fit DWORD")
    if len(standard_values) > MAX_ITEMS or any(
        not isinstance(pair, tuple)
        or len(pair) != 2
        or any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in pair)
        for pair in standard_values
    ):
        raise MonitorError("Native standard values require bounded DWORD pairs")
    cache = MonitorSupportCache(
        profile,
        exchange,
        ecu,
        stream=support_stream,
        bus_id=bus_id,
        source_build=source_build,
        limits=limits,
        cancelled=cancelled,
        clock=clock,
    )
    support = cache.support_bits(1)
    if lsb_producer is None and lsb_observations is None:
        from scripts.signal_lsb import SignalLSB

        lsb_producer = SignalLSB(cache, source_build=12 if source_build == 12 else 18)
    return selected_p4_monitor(
        profile,
        selected_ids,
        support,
        observed_functions,
        interface_id=interface_id,
        excluded=excluded,
        max_request=max_request,
        max_reply=max_reply,
        standard_values=standard_values,
        source_build=source_build,
        lsb_producer=lsb_producer,
        lsb_observations=lsb_observations,
        voltage_state=voltage_state,
        voltage_observations=voltage_observations,
    )


def selected_p4_from_cache(
    cache: MonitorSupportCache,
    selected_ids: Sequence[int],
    observed_functions: Mapping[int, bool],
    *,
    interface_id: int,
    excluded: int,
    max_request: int,
    max_reply: int,
    standard_values: Sequence[tuple[int, int]],
) -> SelectedP4Monitor:
    """Normal P4 support/LSB pass bound to one concrete selected cache."""
    from scripts.monitor_support import MonitorSupportCache
    from scripts.signal_lsb import SignalLSB

    if not isinstance(cache, MonitorSupportCache):
        raise MonitorError("Native P4 requires concrete selected support cache")
    profile = cache.profile
    if not isinstance(profile, VehicleProfile):
        raise MonitorError("Native P4 requires a bound selected ECU database")
    selected_definitions(profile, selected_ids)
    monitor_capabilities(observed_functions)
    if profile.category_record[72] & 31 not in (4, 6):
        raise MonitorError("Normal P4 cache requires category phase4/6")
    if any(type(v) is not int or not 4 <= v <= 255 for v in (max_request, max_reply)):
        raise MonitorError("Native P4 setup requires bounded byte request/reply limits")
    if any(
        type(v) is not int or not 0 <= v <= 0xFFFFFFFF for v in (interface_id, excluded)
    ):
        raise MonitorError("Native P4 interface/mask must fit DWORD")
    if len(standard_values) > MAX_ITEMS or any(
        not isinstance(pair, tuple)
        or len(pair) != 2
        or any(type(v) is not int or not 0 <= v <= 0xFFFFFFFF for v in pair)
        for pair in standard_values
    ):
        raise MonitorError("Native standards require bounded DWORD pairs")
    cache.begin_operation()
    support = cache.support_bits(1)
    return selected_p4_monitor(
        profile,
        selected_ids,
        support,
        observed_functions,
        interface_id=interface_id,
        excluded=excluded,
        max_request=max_request,
        max_reply=max_reply,
        standard_values=standard_values,
        source_build=cache.source_build,
        lsb_producer=SignalLSB(
            cache, source_build=12 if cache.source_build == 12 else 18
        ),
    )


def selected_normal_monitor_worker(
    operations: NativeFrameOperations,
    plan: SelectedP4Monitor | SelectedP5Monitor | SelectedPacketA8Monitor,
    connection: SelectedMonitorConnection,
    *,
    routine_info: bool = False,
    oscilloscope: NormalOscilloscopeSelection | None = None,
    active: ActiveMonitorEvent | Phase5ActiveEvent | None = None,
    system: MonitorSystemEvent | Phase5SystemEvent | None = None,
    system_connection: SelectedP5CanConnection | None = None,
    security_release: bool = False,
    monitor_session: SelectedMonitorSession | None = None,
    limits: Limits | None = None,
    clock: Callable[[], float] = time.monotonic,
    ticks: Callable[[], int] | None = None,
    cancelled: Callable[[], bool] = lambda: False,
) -> DirectJ2534Worker | NormalPollingWorker:
    """Route selected normal plans to their exact packet/pair/P5 worker."""
    from scripts.monitor_p5 import SelectedP5Monitor
    from scripts.monitor_packet_a8 import (
        SelectedPacketA8Monitor,
        selected_packet_a8_worker,
    )
    from scripts.monitor_poll import selected_normal_poll_worker

    budget = limits or Limits()
    if not isinstance(operations.profile, VehicleProfile):
        raise MonitorError("Normal worker requires a bound selected ECU database")
    if monitor_session is not None:
        if not isinstance(monitor_session, SelectedMonitorSession):
            raise MonitorError("Normal worker requires typed selected monitor session")
        monitor_session.check(operations.profile, source_build=operations.native_build)
    if not isinstance(
        plan, (SelectedP4Monitor, SelectedP5Monitor, SelectedPacketA8Monitor)
    ):
        raise MonitorError("Normal worker requires its concrete selected provider")
    if isinstance(plan, SelectedPacketA8Monitor) and plan.packing.mode == 1:
        if (
            any(
                value is not None
                for value in (oscilloscope, active, system, system_connection)
            )
            or security_release
            or routine_info
        ):
            raise MonitorError(
                "Native A8 packet worker does not accept normal auxiliary slots"
            )
        worker = selected_packet_a8_worker(
            operations,
            plan,
            connection,
            limits=budget,
            clock=clock,
            cancelled=cancelled,
        )
    else:
        worker = selected_normal_poll_worker(
            operations,
            plan,
            connection,
            routine_info=routine_info,
            oscilloscope=oscilloscope,
            active=active,
            system=system,
            system_connection=system_connection,
            security_release=security_release,
            timeout=budget.seconds,
            max_steps=budget.exchanges,
            clock=clock,
            ticks=ticks,
            cancelled=cancelled,
        )
    if monitor_session is not None:
        from scripts.monitor_j2534 import DirectJ2534Worker

        if isinstance(worker, DirectJ2534Worker):
            worker.disable_packet_ecu = monitor_session.disable_packet_ecu
    return worker


def selected_monitor_buffer(
    plan: SelectedP4Monitor | SelectedP5Monitor | SelectedPacketA8Monitor,
    *,
    phase: int,
    allocation_size: int,
    name: bytes,
    text_encoding: str,
) -> NativeMonitorBuffer:
    """Export selected native metadata with its producer's constructor policy."""
    from scripts.drive_recorder import native_monitor_buffer
    from scripts.monitor_p5 import SelectedP5Monitor
    from scripts.monitor_packet_a8 import SelectedPacketA8Monitor

    if not isinstance(
        plan, (SelectedP4Monitor, SelectedP5Monitor, SelectedPacketA8Monitor)
    ):
        raise MonitorError("Selected normal monitor metadata plan is required")
    setup = next(
        (
            command
            for command in plan.commands.setup
            if command.command_id in (0x109, 0x10A, 0x10B, 0x119, 0x11C)
        ),
        None,
    )
    if setup is None or not setup.values or type(setup.values[0]) is not int:
        raise MonitorError("Selected monitor setup must retain its native ECU ID")
    p5 = isinstance(plan, SelectedP5Monitor)
    return native_monitor_buffer(
        setup.values[0],
        plan.signals,
        plan.frame_sizes,
        plan.definitions.selected_ids,
        phase=phase,
        allocation_size=allocation_size,
        name=name,
        text_encoding=text_encoding,
        default_signal_slots=plan.default_signal_slots if p5 else (),
        unassigned_short_name_slots=tuple(range(len(plan.signals))) if p5 else (),
    )


def selected_legacy_check_target(
    communication: NativeCommunication,
    selected_ids: Sequence[int],
    observed_functions: Mapping[int, bool],
    *,
    monitor_session: SelectedMonitorSession | None = None,
) -> LegacyCheckTarget:
    """Bind native legacy measurement to its retained communication and packet cache."""
    from scripts.monitor_j2534 import selected_packet_frame_cache
    from scripts.monitor_legacy import (
        LegacyCheckTarget,
    )
    from scripts.native_communication import NativeCommunication

    if not isinstance(communication, NativeCommunication):
        raise MonitorError("Legacy selected check requires concrete communication")
    if not isinstance(communication.profile, VehicleProfile):
        raise MonitorError("Legacy selected check requires a bound ECU database")
    keys = _ids(selected_ids, 65535)
    if not keys:
        raise MonitorError("Legacy selected check requires signal IDs")
    return LegacyCheckTarget(
        communication.profile,
        keys,
        communication.ecu,
        communication.bus_id,
        observed_functions,
        communication,
        source_build=communication.source_build,
        support_stream=communication,
        packet_cache=selected_packet_frame_cache(
            communication, monitor_session=monitor_session
        ),
        packet_ecu=communication.profile.category,
        packet_protocol=communication.bus_id,
    )


def selected_legacy_monitor_runtime(
    targets: tuple[LegacyRunTarget, ...],
    *,
    command_id: int,
    command_ecu: int,
    connected_device: int,
    primary: LegacyRunTarget | None = None,
    client: NativeVimClient | None = None,
    phase: int = 0,
    enable_mode: int = 65535,
    selection: NativeVehicleSelection | None = None,
    system_information: dict | None = None,
    trigger: NativeTriggerInfo | None = None,
    parameters: NativeTriggerParameters | None = None,
    init_mode: int | None = None,
    parameter_c0: int | None = None,
    monitor_session: SelectedMonitorSession | None = None,
    shared_interface: int | None = None,
    disabled_packet_ecus: tuple[int, ...] | None = None,
    limits: Limits | None = None,
    clock: Callable[[], float] = time.monotonic,
    cancelled: Callable[[], bool] = lambda: False,
) -> tuple[LegacyMonitorController, LegacyControlMessage]:
    """Prepare the source-selected P3/DK Run queue; construction performs no I/O.

    The actual command ECU owns the primary NULL slot. The controller registers
    selected targets in native order and retains empty/unsupported source paths.
    Choose its cooperative run_one/poll API or run(queue), never both at once.
    """
    from scripts.monitor_legacy import (
        LegacyCommandQueue,
        LegacyControlMessage,
        LegacyDrsWriter,
        LegacyMonitorController,
        LegacyRunTarget,
    )
    from scripts.native_communication import NativeFrameController

    _ids((command_ecu,), 65535)
    if (
        not isinstance(targets, tuple)
        or not 1 <= len(targets) <= 3
        or any(not isinstance(target, LegacyRunTarget) for target in targets)
        or type(command_id) is not int
        or command_id not in (9, 56, 87)
    ):
        raise MonitorError("Selected legacy Run command/targets are invalid")
    if primary is None:
        actual = next(
            (
                target
                for target in targets
                if target.communication.profile.category == command_ecu
            ),
            None,
        )
        if actual is None:
            raise MonitorError(
                "Legacy Run requires the actual command ECU communication"
            )
        primary = replace(actual, selected_ids=(), allocation_size=0)
    if (
        not isinstance(primary, LegacyRunTarget)
        or primary.selected_ids
        or primary.communication.profile.category != command_ecu
    ):
        raise MonitorError(
            "Legacy Run primary must be the selected command ECU NULL slot"
        )
    first = primary.communication
    for target in (primary, *targets):
        communication = target.communication
        if (
            not isinstance(communication.operations, NativeFrameController)
            or not isinstance(communication.profile, ProtocolProfile)
            or (
                target.selected_ids
                and not isinstance(communication.profile, VehicleProfile)
            )
            or communication.source_build != first.source_build
            or communication.profile.catalog.management.sha256
            != first.profile.catalog.management.sha256
            or communication.profile.catalog.management.version
            != first.profile.catalog.management.version
            or communication.profile.exception_ids != first.profile.exception_ids
            or communication.profile.vehicle_name_key != first.profile.vehicle_name_key
        ):
            raise MonitorError("Legacy Run selected primary/target contexts differ")
        if communication.closed:
            raise MonitorError(
                "Legacy Run requires live selected support communication"
            )
        if monitor_session is not None:
            monitor_session.check(
                communication.profile, source_build=communication.source_build
            )
    provider = select_provider(first.profile.category_record[72], first.bus_id, None)
    family = {"DataMonitorPhase3.dll": "P3", "DataMonitorDKIso9141.dll": "DK"}.get(
        provider
    )
    if family is None:
        raise MonitorError(f"Selected provider {provider} requires its own runtime")
    writer = None
    if command_id == 87:
        if (
            selection is None
            or system_information is None
            or trigger is None
            or parameters is None
        ):
            raise MonitorError("Run87 requires actual vehicle/system/trigger metadata")
        writer = LegacyDrsWriter(selection, system_information, trigger, parameters)
    elif any(
        value is not None
        for value in (selection, system_information, trigger, parameters)
    ):
        raise MonitorError("Recording metadata requires native Run87")
    controller = LegacyMonitorController(
        family=family,
        connected_device=connected_device,
        client=client,
        recording_writer=writer,
        init_mode=init_mode,
        parameter_c0=parameter_c0,
        monitor_session=monitor_session,
        shared_interface=shared_interface,
        disabled_packet_ecus=disabled_packet_ecus,
        limits=limits,
        clock=clock,
        cancelled=cancelled,
    )
    message = LegacyControlMessage(
        command_id, targets, primary=primary, phase=phase, enable_mode=enable_mode
    )
    controller.queue = LegacyCommandQueue()
    controller.queue.put(message)
    # Host ownership guard: the finisher may only consume this prepared pair.
    setattr(controller, "_selected_initial_command", message)  # noqa: B010 - adapter-owned provenance on the source controller
    return controller, message


def complete_selected_legacy_recording(
    controller: LegacyMonitorController,
    message: LegacyControlMessage,
) -> DrsFile:
    """Finish selected Run87, then outer VIN metadata, then release resources.

    Consumes an unstarted cooperative Run87 or an already-finished threaded
    Run87. Support communication remains live until recording_file completes.
    """
    from scripts.monitor_legacy import LegacyControlMessage, LegacyMonitorController

    if (
        not isinstance(controller, LegacyMonitorController)
        or not isinstance(message, LegacyControlMessage)
        or message.command_id != 87
        or controller.recording_writer is None
        or controller.queue is None
        or getattr(controller, "_selected_initial_command", None) is not message
    ):
        raise MonitorError("Selected recording requires its own prepared Run87 pair")
    if (
        message.result is None
        and message.exception is None
        and controller._thread is not None
    ):
        raise MonitorError("Await native Run87 finish before completing recording")
    communications = tuple(
        dict.fromkeys(
            target.communication
            for target in (
                *((message.primary,) if message.primary is not None else ()),
                *message.targets,
            )
        )
    )
    primary = None
    try:
        if message.result is None and message.exception is None:
            controller.run_one()
        if message.exception is not None:
            raise message.exception
        if not controller.queue.finish_event.is_set() or message.result is None:
            raise MonitorError("Native Run87 did not signal completion")
        if message.result.status:
            raise MonitorError("Native Run87 failed", message.result.status)
        return controller.recording_file()
    except BaseException as error:
        primary = error
        raise
    finally:
        failures = []
        try:
            controller.close()
        except BaseException as error:  # noqa: BLE001 - release support after controller failure
            failures.append(error)
        for communication in communications:
            try:
                status = communication.close()
                if status:
                    failures.append(
                        MonitorError("Recording support cleanup failed", status)
                    )
            except BaseException as error:  # noqa: BLE001 - release every selected communication
                failures.append(error)
        if failures:
            if primary is None:
                primary = failures.pop(0)
                for error in failures:
                    primary.add_note(f"Additional recording cleanup failure: {error}")
                raise primary
            for error in failures:
                primary.add_note(f"Recording cleanup also failed: {error}")


def _selected_variable_multi_lower(
    targets: tuple[VariableRuntimeTarget, ...],
    communications: tuple[NativeCommunication, ...],
    source_operations: NativeFrameOperations,
    *,
    controller_communication: NativeCommunication,
    controller_category_flags: int,
    cancelled: Callable[[], bool],
) -> NativeMultiMonOperations:
    """Build fresh MultiMon registrations from the final selected variable slots."""
    from scripts.frame_transport import NativeFrameOperations, NativeMultiMonOperations
    from scripts.monitor_dual import DualTarget
    from scripts.monitor_legacy import dk_monitor_timing
    from scripts.monitor_variable import (
        SelectedVariableMonitor,
        VariableMonitorSource,
        VariableRuntimeTarget,
    )
    from scripts.native_communication import NativeCommunication, NativeFrameController

    if (
        not isinstance(source_operations, NativeFrameOperations)
        or source_operations.device_kind != 8
        or source_operations.channel is not None
        or source_operations.owns_channel
        or not isinstance(controller_communication, NativeCommunication)
        or not isinstance(controller_communication.operations, NativeFrameController)
        or type(controller_category_flags) is not int
        or not isinstance(targets, tuple)
        or not 1 <= len(targets) <= 2
    ):
        raise MonitorError("Variable MultiMon requires fresh device8 source context")

    source_controller = controller_communication.operations.operations
    if (
        source_controller.backend is not source_operations.backend
        or source_controller.driver != source_operations.driver
        or source_controller.native_build != source_operations.native_build
        or source_controller.device_kind != source_operations.device_kind
        or source_controller.diagnostic_mode != source_operations.diagnostic_mode
        or controller_communication.profile.category_record[72]
        != controller_category_flags
    ):
        raise MonitorError("Variable MultiMon selected native contexts differ")

    profiles: dict[str, ProtocolProfile] = {}
    lower_targets = []
    for target in targets:
        if not isinstance(target, VariableRuntimeTarget):
            raise MonitorError("Variable MultiMon requires final selected targets")
        target.check()
        cache, connection, plan = target.cache, target.connection, target.plan
        communication = next(
            (item for item in communications if item.cache is cache), None
        )
        if (
            communication is None
            or not communication.closed
            or communication.profile is not cache.profile
            or communication.ecu != cache.ecu
            or communication.bus_id != cache.bus_id
            or communication.source_build != cache.source_build
            or not isinstance(communication.operations, NativeFrameController)
            or communication.operations.operations.backend
            is not source_operations.backend
            or communication.operations.operations.driver != source_operations.driver
            or communication.operations.operations.native_build
            != source_operations.native_build
            or communication.operations.operations.device_kind != 8
            or communication.operations.operations.diagnostic_mode
            != source_operations.diagnostic_mode
            or cache.source_build != source_operations.native_build
            or cache.profile.catalog.management.sha256
            != controller_communication.profile.catalog.management.sha256
            or cache.profile.catalog.management.version
            != controller_communication.profile.catalog.management.version
            or cache.profile.vehicle_name_key
            != controller_communication.profile.vehicle_name_key
            or cache.profile.exception_ids
            != controller_communication.profile.exception_ids
            or not isinstance(cache.profile, VehicleProfile)
            or connection is None
        ):
            raise MonitorError("Variable MultiMon target source/context changed")
        if not isinstance(plan, SelectedVariableMonitor):
            raise MonitorError("Variable MultiMon entry requires pair setup")
        expected_connection = selected_p4_connection(
            cache.profile,
            bus_id=communication.bus_id,
            diagnostic_mode=source_operations.diagnostic_mode,
            controller_category_flags=controller_category_flags,
        )
        if connection != expected_connection:
            raise MonitorError("Variable MultiMon target connection was changed")
        expected_entry = int.from_bytes(
            source_operations.diagnostic_mode[8:12], "little"
        ) or word(expected_connection.protocol_record, 8)
        if target.entry_parameter != expected_entry:
            raise MonitorError("Variable MultiMon target entry was changed")
        setup = next(
            (item for item in plan.commands.setup if item.command_id == 0x10A), None
        )
        if (
            setup is None
            or len(setup.values) != 8
            or setup.values[:2]
            != (cache.profile.category, expected_connection.address.request_id)
            or type(setup.values[6]) is not int
        ):
            raise MonitorError("Variable MultiMon selected pair command is absent")
        retry_limit = setup.values[6]
        ecu = cache.ecu
        if ecu in profiles or any(
            item.command_id == cache.profile.category for item in lower_targets
        ):
            raise MonitorError("Variable MultiMon ECU identity is ambiguous")
        profiles[ecu] = cache.profile
        lower_targets.append(
            DualTarget(
                ecu,
                expected_connection.address.request_id,
                expected_connection.address.response_id,
                expected_connection.bus_id,
                cache.profile.category_record[72],
                cache.profile.category,
                retry_limit,
                *dk_monitor_timing(cache.profile),
                (
                    expected_connection.can_parameter,
                    expected_connection.can_byte_0,
                    expected_connection.can_byte_1,
                ),
                expected_entry,
            )
        )

    lower = NativeMultiMonOperations(
        tuple(lower_targets),
        profiles,
        source_operations.backend,
        driver=source_operations.driver,
        native_build=source_operations.native_build,
        source_identity=VariableMonitorSource.for_build(
            source_operations.native_build
        ).sha256,
        device_kind=8,
        diagnostic_mode=source_operations.diagnostic_mode,
        clock=source_operations.clock,
        cancelled=cancelled,
        wait=source_operations.wait,
    )
    if lower.operations.channel is not None or lower.operations.owns_channel:
        raise MonitorError("Fresh variable MultiMon unexpectedly owns a channel")
    return lower


def selected_variable_monitor_runtime(
    targets: tuple[LegacyCheckTarget, ...],
    operations: NativeFrameOperations | NativeMultiMonOperations | NativeVimClient,
    *,
    connected_device: int = 8,
    controller_communication: NativeCommunication | None = None,
    init_mode: int | None = None,
    parameter_c0: int | None = None,
    command_kind: int,
    command_ecu: int,
    allocation: int,
    standard_values: tuple[Sequence[tuple[int, int]], ...],
    names: tuple[bytes, ...],
    text_encoding: str,
    phase: int,
    active: VariableActiveOperation | None = None,
    system: VariableSystemOperation | None = None,
    monitor_session: SelectedMonitorSession | None = None,
    voltage_state: DLC12VoltageState | None = None,
    voltage_observations: Mapping[int, DLC12VoltageObservation] | None = None,
    limits: Limits | None = None,
    clock: Callable[[], float] = time.monotonic,
    ticks: Callable[[], int] | None = None,
    cancelled: Callable[[], bool] = lambda: False,
) -> VariableMonitorRuntime:
    """Join selected variable CheckStart, real child plans and allocated runtime.

    Targets must come from selected_legacy_check_target. This factory owns the
    support channels and closes them before handing fresh lower operations to
    the runtime; it never opens a second channel for packet discovery.
    """
    from scripts.drive_recorder import NativeVimClient
    from scripts.frame_transport import NativeFrameOperations
    from scripts.monitor_legacy import (
        LegacyCheckTarget,
    )
    from scripts.monitor_variable import (
        VariableMonitorRuntime,
        VariableNullController,
        check_variable_monitor,
        selected_variable_monitor_from_cache,
        selected_variable_packet_monitor,
        selected_variable_runtime_target,
        selected_variable_voltage_monitor,
        variable_target_mask,
    )
    from scripts.native_communication import NativeCommunication, NativeFrameController

    _ids((command_ecu,), 65535)
    if (
        not isinstance(targets, tuple)
        or not 1 <= len(targets) <= 3
        or any(not isinstance(target, LegacyCheckTarget) for target in targets)
    ):
        raise MonitorError("Variable runtime requires1..3 concrete selected targets")
    if (
        not isinstance(standard_values, tuple)
        or len(standard_values) != len(targets)
        or not isinstance(names, tuple)
        or len(names) != len(targets)
        or any(not isinstance(name, bytes) for name in names)
        or not isinstance(text_encoding, str)
        or type(phase) is not int
        or phase not in (0, 1)
    ):
        raise MonitorError("Variable runtime display/standard selections differ")
    communications = []
    for target in targets:
        communication = target.transaction
        if (
            not isinstance(communication, NativeCommunication)
            or not isinstance(communication.operations, NativeFrameController)
            or target.support_stream is not communication
            or target.profile is not communication.profile
            or target.ecu != communication.ecu
            or target.bus_id != communication.bus_id
            or target.source_build != communication.source_build
            or target.packet_ecu != communication.profile.category
            or target.packet_protocol != communication.bus_id
        ):
            raise MonitorError(
                "Variable runtime target lacks retained selected communication"
            )
        communications.append(communication)
    if monitor_session is not None:
        if not isinstance(monitor_session, SelectedMonitorSession):
            raise MonitorError(
                "Variable runtime requires typed selected monitor session"
            )
        for target in targets:
            monitor_session.check(target.profile, source_build=target.source_build)
            if target.packet_cache is not None:
                target.packet_cache.disable_packet_ecu = (
                    monitor_session.disable_packet_ecu
                )
    actual_controller = next(
        (
            communication
            for communication in communications
            if communication.profile.category == command_ecu
        ),
        None,
    )
    if controller_communication is None:
        controller_communication = actual_controller
    if (
        not isinstance(controller_communication, NativeCommunication)
        or not isinstance(controller_communication.operations, NativeFrameController)
        or not isinstance(controller_communication.profile, ProtocolProfile)
        or controller_communication.profile.category != command_ecu
        or controller_communication.closed
    ):
        raise MonitorError("Variable Run requires actual command ECU communication")
    for communication in communications:
        if (
            communication.source_build != controller_communication.source_build
            or SelectedMonitorSession._context(communication.profile)
            != SelectedMonitorSession._context(controller_communication.profile)
        ):
            raise MonitorError("Variable controller/target selected contexts differ")
    if monitor_session is not None:
        monitor_session.check(
            controller_communication.profile,
            source_build=controller_communication.source_build,
        )
    if type(connected_device) is not int or connected_device not in (4, 8):
        raise MonitorError("Variable Run requires observed device4 or8")
    if isinstance(operations, NativeVimClient) != (connected_device == 4):
        raise MonitorError("Variable Run lower operations differ from observed device")
    flags = controller_communication.profile.category_record[72]
    if flags & 31 not in (4, 6, 9):
        raise MonitorError("Variable controller child provider is unavailable")
    controller_connection = selected_p4_connection(
        controller_communication.profile,
        bus_id=controller_communication.bus_id,
        diagnostic_mode=controller_communication.operations.operations.diagnostic_mode,
        controller_category_flags=flags,
    )
    iso_record = None
    if connected_device == 4 and controller_connection.bus_id & 15 == 1:
        rows = controller_communication.profile.comm_info_iso_records(
            word(controller_connection.protocol_record, 2)
        )
        if not rows:
            raise MonitorError(
                "Variable selected controller ISO row is absent", 0xC0050101
            )
        iso_record = rows[0]
        if (
            init_mode not in (1, 2)
            or type(init_mode) is not int
            or parameter_c0 is None
        ):
            raise MonitorError(
                "Variable ISO requires actual initialization/C0 observations"
            )
    null_controller = (
        VariableNullController(
            controller_communication.profile,
            controller_connection,
            controller_communication.source_build,
        )
        if actual_controller is None
        else None
    )
    registered_indices: dict[int, int | None] = {command_ecu: None}
    for index, target in enumerate(targets):
        registered_indices[target.profile.category] = index
    excluded = variable_target_mask(
        tuple(
            (
                category,
                controller_communication.bus_id
                if index is None
                else targets[index].bus_id,
            )
            for category, index in registered_indices.items()
        ),
        connected_device=connected_device,
    )
    if (
        any(target.profile.category == 0x68 for target in targets)
        and voltage_state is None
    ):
        raise MonitorError("Variable voltage target requires actual selected state")
    if controller_communication not in communications:
        communications.append(controller_communication)
    selected = []
    primary = None
    try:
        checked = check_variable_monitor(
            targets,
            command_kind=command_kind,
            allocation=allocation,
            connected_device=connected_device,
            command_ecu=command_ecu,
            limits=limits,
            clock=clock,
            cancelled=cancelled,
        )
        if not checked.available or len(checked.measurements) != len(targets):
            raise MonitorError("Variable selected check is unavailable")
        for index in registered_indices.values():
            if index is None:
                continue
            target = targets[index]
            communication = communications[index]
            measurement = checked.measurements[index]
            cache = communication.cache
            if target.profile.category == 0x68:
                assert voltage_state is not None
                plan = selected_variable_voltage_monitor(
                    cache,
                    target.selected_ids,
                    voltage_state=voltage_state,
                    voltage_observations=voltage_observations,
                )
                connection = None
                diagnostic_mode = None
            else:
                diagnostic_mode = communication.operations.operations.diagnostic_mode
                connection = selected_p4_connection(
                    target.profile,
                    bus_id=target.bus_id,
                    diagnostic_mode=diagnostic_mode,
                    controller_category_flags=flags,
                )
                if flags & 31 == 9:
                    plan = selected_variable_packet_monitor(
                        cache,
                        target.selected_ids,
                        target.observed_functions,
                        packet_cache=target.packet_cache,
                        communication_protocol=target.bus_id,
                        interface_id=connection.address.request_id,
                        excluded=excluded,
                        standard_values=standard_values[index],
                        max_request=connection.maximum_request,
                        max_reply=connection.maximum_reply,
                        controller_category_flags=flags,
                    )
                else:
                    plan = selected_variable_monitor_from_cache(
                        cache,
                        target.selected_ids,
                        target.observed_functions,
                        attribute_3_31=True,
                        communication_protocol=target.bus_id,
                        interface_id=connection.address.request_id,
                        excluded=excluded,
                        standard_values=standard_values[index],
                        max_request=connection.maximum_request,
                        max_reply=connection.maximum_reply,
                        controller_category_flags=flags,
                    )
            selected.append(
                selected_variable_runtime_target(
                    plan,
                    cache,
                    connection,
                    measurement=measurement,
                    diagnostic_mode=diagnostic_mode,
                    phase=phase,
                    name=names[index],
                    text_encoding=text_encoding,
                )
            )
    except BaseException as error:
        primary = error
        raise
    finally:
        failures = []
        for communication in communications:
            try:
                status = communication.close()
                if status:
                    failures.append(
                        MonitorError("Variable support cleanup failed", status)
                    )
            except BaseException as error:  # noqa: BLE001 - release every owned support channel
                failures.append(error)
        if failures:
            if primary is None:
                primary = failures.pop(0)
                for error in failures:
                    primary.add_note(f"Additional variable cleanup failure: {error}")
                raise primary
            for error in failures:
                primary.add_note(f"Variable support cleanup also failed: {error}")
    if (
        connected_device == 8
        and isinstance(operations, NativeFrameOperations)
        and len(registered_indices) >= 2
        and null_controller is None
        and 1 <= sum(target.cache.profile.category != 0x68 for target in selected) <= 2
    ):
        operations = _selected_variable_multi_lower(
            tuple(
                target for target in selected if target.cache.profile.category != 0x68
            ),
            tuple(communications),
            operations,
            controller_communication=controller_communication,
            controller_category_flags=flags,
            cancelled=cancelled,
        )
    # Registration order was fixed before child creation; Check allocations
    # remain attached to the final selected target in each overwritten slot.
    runtime = VariableMonitorRuntime(
        tuple(selected),
        operations,
        connected_device=connected_device,
        controller_connection=controller_connection,
        null_controller=null_controller,
        iso_record=iso_record,
        init_mode=init_mode,
        parameter_c0=parameter_c0,
        active=active,
        system=system,
        limits=limits,
        clock=clock,
        ticks=ticks,
        cancelled=cancelled,
    )
    if monitor_session is not None:
        from scripts.monitor_j2534 import DirectJ2534Worker

        if isinstance(runtime.worker, DirectJ2534Worker):
            runtime.worker.disable_packet_ecu = monitor_session.disable_packet_ecu
    return runtime


def selected_normal_monitor_from_cache(
    cache: MonitorSupportCache,
    selected_ids: Sequence[int],
    observed_functions: Mapping[int, bool],
    *,
    communication_protocol: int,
    attribute_3_31: bool | None,
    interface_id: int,
    excluded: int,
    standard_values: Sequence[tuple[int, int]],
    max_request: int,
    max_reply: int,
    parameter_6: int,
    active_alias_pid: int,
    dynamic_requested: bool,
    routine_ids: Sequence[int] = (),
    native_ecu: int | None = None,
    packet_cache: PacketFrameCache | None = None,
) -> (
    P5MonitorPlan
    | SelectedP4Monitor
    | SelectedPacketA8Monitor
    | SelectedVariableMonitor
):
    """Select the native normal P4/P5 producer using explicit observed dispatch.

    Legacy/instrument/Dual producers have their separate typed configuration
    contracts. This entry never coerces one of them into a normal monitor.
    """
    from scripts.monitor_support import MonitorSupportCache

    if not isinstance(cache, MonitorSupportCache):
        raise MonitorError("Native monitor router requires concrete selected cache")
    provider = select_provider(
        cache.profile.category_record[72], communication_protocol, attribute_3_31
    )
    if provider == "DataMonitorPhase4.dll":
        if routine_ids:
            raise MonitorError("Normal P4 producer does not consume P5 routine IDs")
        if cache.profile.category_record[72] & 31 == 9:
            from scripts.monitor_packet_a8 import selected_packet_a8_from_cache

            if native_ecu is None:
                raise MonitorError(
                    "Native A8 packet producer requires explicit ECU key"
                )
            return selected_packet_a8_from_cache(
                cache,
                selected_ids,
                observed_functions,
                communication_protocol=communication_protocol,
                interface_id=interface_id,
                excluded=excluded,
                max_request=max_request,
                max_reply=max_reply,
                standard_values=standard_values,
                packet_cache=packet_cache,
                native_ecu=native_ecu,
            )
        return selected_p4_from_cache(
            cache,
            selected_ids,
            observed_functions,
            interface_id=interface_id,
            excluded=excluded,
            max_request=max_request,
            max_reply=max_reply,
            standard_values=standard_values,
        )
    if provider == "DM_ActVariable_DT.dll":
        from scripts.monitor_variable import selected_variable_monitor_from_cache

        if routine_ids or attribute_3_31 is not True:
            raise MonitorError(
                "Variable monitor requires its actual dispatch observation"
            )
        return selected_variable_monitor_from_cache(
            cache,
            selected_ids,
            observed_functions,
            communication_protocol=communication_protocol,
            attribute_3_31=attribute_3_31,
            interface_id=interface_id,
            excluded=excluded,
            standard_values=standard_values,
            max_request=max_request,
            max_reply=max_reply,
        )
    if provider == "DataMonitorPhase5_DT.dll":
        from scripts.monitor_p5 import selected_p5_monitor_from_cache

        return selected_p5_monitor_from_cache(
            cache,
            selected_ids,
            observed_functions,
            interface_id=interface_id,
            excluded=excluded,
            standard_values=standard_values,
            parameter_6=parameter_6,
            active_alias_pid=active_alias_pid,
            dynamic_requested=dynamic_requested,
            max_request=max_request,
            max_reply=max_reply,
            routine_ids=routine_ids,
        )
    raise MonitorError(
        f"Native selected provider {provider} requires its typed producer"
    )


def p4_iso_lifecycle(
    plan: P4MonitorPlan,
    connection: SelectedMonitorConnection,
    iso_record: bytes,
    *,
    connected_device: int,
    init_mode: int,
    parameter_c0: int,
    interrupt_send_timing: bool,
    recording: bool = False,
) -> MonitorSetup:
    """P4 e960/9ce0 selected ISO constructor and common DMCI lifecycle.

    init_mode is the observed CInitModeList result1/2. parameter_c0 is the
    original Run command DWORDC0 copied to controller188; its value is explicit.
    """
    if (
        type(connected_device) is not int
        or type(recording) is not bool
        or not (connected_device == 4 or connected_device == 8 and recording)
    ):
        raise MonitorError("P4 ISO DMCI requires device4 or device8 recording writer")
    if connection.bus_id & 15 != 1:
        raise MonitorError("P4 ISO constructor requires observed bus family1")
    if type(init_mode) is not int or init_mode not in (1, 2):
        raise MonitorError(
            "Native ISO initialization mode must be observed1/2", 0x90050424
        )
    if type(parameter_c0) is not int or not 0 <= parameter_c0 <= 0xFFFFFFFF:
        raise MonitorError("Native ISO commandC0 parameter must fit DWORD")
    configs = p4_iso_configs(iso_record, bus_id=connection.bus_id)
    if len(connection.protocol_record) not in (24, 28) or word(iso_record, 4) != word(
        connection.protocol_record, 2
    ):
        raise MonitorError("Native ISO record does not match selected ProtInfo")
    create = MonitorCommand(
        0x100, (b"ComIso32.dll\0", configs, init_mode - 1, 0xC6, parameter_c0, 0)
    )
    return _p4_transport_lifecycle(
        plan, connection, create, interrupt_send_timing=interrupt_send_timing
    )


def selected_dynamic_slots(
    cache: MonitorSupportCache,
    *,
    source_build: int,
    enabled_dynamic_dids: Sequence[int] | None = None,
) -> tuple[DynamicSlot, ...]:
    """P5 5330 selected DB251 or actual114/115 slot discovery transactions."""
    profile = cache.profile
    if type(source_build) is not int or source_build not in (12, 18):
        raise MonitorError("Native dynamic slots require explicit source build12/18")
    if cache.source_build != source_build:
        raise MonitorError("Dynamic slot source build differs from its support cache")
    if source_build == 18 and profile.category_record[72] & 0xE0 == 0x20:
        replies = []
        for function in (0x114, 0x115):
            frames = profile.frame_records(function)
            if not frames:
                raise MonitorError(
                    "Native dynamic slot discovery frame is absent", 0xA0050422
                )
            frame = frames[0]
            reply = cache.transaction(frame, frame.frame.request)
            if len(reply) < 5:
                raise MonitorError(
                    "Native dynamic slot discovery reply is short", 0xA0050422
                )
            value = int.from_bytes(reply[3:5], "big")
            if function == 0x114 and not 1 <= value <= 255:
                raise MonitorError("Native dynamic slot count is invalid", 0xA0050422)
            replies.append(value)
        count, capacity = replies
        if not 1 <= count <= 255 or not 1 <= capacity < 0x3FF:
            raise MonitorError(
                "Native dynamic slot count/capacity is invalid", 0xA0050422
            )
        return tuple(
            DynamicSlot((index - 0xD00) & 65535, capacity) for index in range(count)
        )
    if not isinstance(profile, VehicleProfile):
        raise MonitorError("Native dynamic slots require a bound selected ECU database")
    try:
        rows = profile.records(81)
    except ToyotaCodecError as exc:
        if exc.code != 0xA0030107:
            raise
        raise MonitorError("Native dynamic slot table is absent", 0xA0050422) from exc
    if not rows or len(rows) > MAX_ITEMS or any(len(row) != 8 for row in rows):
        raise MonitorError("Native dynamic slot table geometry is invalid", 0xA0050422)
    if source_build == 12:
        # Version12 4e30 intersects the observed enabled-DID cache, in cache
        # order, with FIRST DB251 matches. It has no114/115 discovery branch.
        if (
            enabled_dynamic_dids is None
            or len(enabled_dynamic_dids) > MAX_ITEMS
            or any(
                type(did) is not int or not 0 <= did <= 65535
                for did in enabled_dynamic_dids
            )
        ):
            raise MonitorError("Version12 requires observed enabled dynamic DIDs")
        first: dict[int, bytes] = {}
        for row in rows:
            first.setdefault(word(row, 0), row)
        selected = tuple(first[did] for did in enabled_dynamic_dids if did in first)
    else:
        selected = rows
    if not selected or len(selected) > 255:
        raise MonitorError("Native dynamic slot selection exceeds capacity", 0xA0050422)
    return tuple(DynamicSlot(word(row, 0), word(row, 2)) for row in selected)


def _p5_range_selection(
    definitions: P5Definitions, enabled_dids: Sequence[int]
) -> tuple[dict[int, int], tuple[P5Range, ...]]:
    """Shared6d80 selection before native dynamic/direct branches."""
    if len(enabled_dids) > MAX_ITEMS or any(
        type(did) is not int or not 0 <= did <= 65535 for did in enabled_dids
    ):
        raise MonitorError("Native P5 enabled DID cache exceeds bounds")
    if len(definitions.ranges) > MAX_ITEMS:
        raise MonitorError("Native P5 selected ranges exceed budget")
    total = 0
    enabled = set(enabled_dids)
    lengths: dict[int, int] = {}
    ranges = []
    for item in definitions.ranges:
        if item.flags & 8:
            raise MonitorError("P5 DTC ranges require the separate DTC setup producer")
        if item.frame_id not in enabled:
            if item.byte_4d == 1:
                enabled.add(item.frame_id)
            elif item.composite_flags & 1:
                ranges.append(replace(item, runtime_flag=1))
                continue
            else:
                raise MonitorError("Native P5 DID is unavailable", 0xC0050414)
        length = item.end_bit // 8 + 1
        # Native descriptor uses fixed4096-byte selected bitmap storage.
        if length > 4096:
            raise MonitorError("Native P5 selected DID exceeds bitmap capacity")
        previous = lengths.get(item.frame_id, 0)
        if length > previous:
            total += length - previous
            if total > MAX_BYTES:
                raise MonitorError("Native P5 selected DID aggregate bytes exceeded")
            lengths[item.frame_id] = length
        ranges.append(item)
    return lengths, tuple(ranges)


@dataclass(frozen=True)
class P5DynamicSelection:
    sources: tuple[DynamicSource, ...]
    ineligible_dids: tuple[int, ...]
    full_lengths: tuple[tuple[int, int], ...]
    ranges: tuple[P5Range, ...]


def p5_dynamic_sources(
    definitions: P5Definitions, enabled_dids: Sequence[int]
) -> P5DynamicSelection:
    """Native6d80→5f10 selected byte spans and8-bit dynamic run eligibility."""
    lengths, ranges = _p5_range_selection(definitions, enabled_dids)
    spans: dict[int, list[tuple[int, int]]] = {}
    for item in ranges:
        if item.runtime_flag != 1:
            spans.setdefault(item.frame_id, []).append(
                (item.start_bit // 8, item.end_bit // 8 + 1)
            )
    sources = []
    ineligible = []
    total_runs = 0
    for did, length in lengths.items():
        selected = bytearray(length)
        for begin, end in spans[did]:
            selected[begin:end] = b"\1" * (end - begin)
        runs = []
        index = 0
        while index < length:
            if not selected[index]:
                index += 1
                continue
            end = index + 1
            while end < length and selected[end]:
                end += 1
            if index + 1 > 255 or end - index > 255:
                ineligible.append(did)
                break
            runs.append((index + 1, end - index))
            index = end
        else:
            total_runs += len(runs)
            if total_runs > MAX_ITEMS:
                raise MonitorError("Native dynamic source run budget exceeded")
            if runs:
                sources.append(DynamicSource(did, tuple(runs)))
    sources = [source for source, _, _ in _dynamic_order(sources)]
    return P5DynamicSelection(
        tuple(sources), tuple(ineligible), tuple(lengths.items()), ranges
    )


def selected_p4_iso_lifecycle(
    profile: VehicleProfile,
    plan: P4MonitorPlan,
    connection: SelectedMonitorConnection,
    *,
    connected_device: int,
    init_mode: int,
    parameter_c0: int,
    interrupt_send_timing: bool,
    recording: bool = False,
) -> MonitorSetup:
    """Select FIRST native DB10F row before the literal ISO constructor."""
    if profile.category != connection.ecu_id or len(connection.protocol_record) not in (
        24,
        28,
    ):
        raise MonitorError("Native ISO connection does not match selected profile")
    rows = profile.comm_info_iso_records(word(connection.protocol_record, 2))
    if not rows:
        raise MonitorError("Selected native CommInfoIso row is absent", 0xC0050101)
    return p4_iso_lifecycle(
        plan,
        connection,
        rows[0],
        connected_device=connected_device,
        init_mode=init_mode,
        parameter_c0=parameter_c0,
        interrupt_send_timing=interrupt_send_timing,
        recording=recording,
    )


def register_dynamic_dids(
    cache: MonitorSupportCache,
    sources: Sequence[DynamicSource],
    slots: Sequence[DynamicSlot],
    *,
    max_request: int,
    max_reply: int,
    source_rows_present: bool | None = None,
) -> DynamicOutcome:
    """Native12 5050/5940 and18 5900/6220 registration transactions.

    Only eligible5f10 sources are accepted. The caller must preserve/report
    ineligible sources from p5_dynamic_sources separately. This performs no
    signal remapping and no polling. Cancellation, deadlines and host I/O
    failures propagate; native communication status failures follow5900.
    """
    from scripts.monitor_support import MonitorSupportCache

    if not isinstance(cache, MonitorSupportCache) or cache.source_build not in (12, 18):
        raise MonitorError("Dynamic registration requires native12/18 support cache")
    if len(slots) > 255 or not slots:
        raise MonitorError("Native dynamic registration requires1..255 slots")
    if source_rows_present is None:
        source_rows_present = bool(sources)
    if type(source_rows_present) is not bool or (sources and not source_rows_present):
        raise MonitorError("Native dynamic source-list presence is inconsistent")
    frames = []
    for function, minimum in ((0xD4, 4), (0xD3, 4), (0xCA, 3)):
        selected = cache.profile.frame_records(function)
        if not selected or not minimum <= len(selected[0].frame.request) <= 4096:
            raise MonitorError("Selected dynamic registration template is absent/short")
        frames.append(selected[0])
    clear, define, validate = frames
    template = define.frame.request
    # Validate the complete source/slot geometry before the first exchange.
    pack_dynamic_dids(
        template, sources, slots, max_request=max_request, max_reply=max_reply
    )
    empty = DynamicPlan((), (), (), (), tuple(sources))
    failed_clears: list[tuple[int, int]] = []
    cleared = []
    for slot in slots:
        request = clear.frame.request
        request = request[:2] + slot.did.to_bytes(2, "big") + request[4:]
        try:
            cache.transaction(clear, request, cached=False, extended=True)
        except ToyotaCodecError as exc:
            failed_clears.append((slot.did, exc.code))
            if cache.source_build == 12:
                # 12 aborts at the first failed clear;18 retains successful slots.
                return DynamicOutcome(
                    0xA0050422, empty, tuple(failed_clears), (), None, True
                )
        else:
            cleared.append(slot)
    if not cleared:
        return DynamicOutcome(0xA0050422, empty, tuple(failed_clears), (), None, True)
    clear_ids = tuple(slot.did for slot in cleared)
    if not source_rows_present:
        # 5f10/12:5630 checks the original linked-list head/tail after D4.
        return DynamicOutcome(
            0x90051019, empty, tuple(failed_clears), (), None, False, clear_ids
        )
    remaining = tuple(sources)
    requests: list[bytes] = []
    read_ids: list[int] = []
    read_lengths: list[int] = []
    groups: list[tuple[DynamicSource, ...]] = []
    failed_definitions: list[tuple[int, int]] = []
    for slot in cleared:
        candidate = pack_dynamic_dids(
            template, remaining, (slot,), max_request=max_request, max_reply=max_reply
        )
        if not candidate.requests:
            continue
        try:
            cache.transaction(
                define, candidate.requests[0], cached=False, extended=True
            )
        except ToyotaCodecError as exc:
            # 6220 resets its source cursor to the last successful registration.
            failed_definitions.append((slot.did, exc.code))
            continue
        requests.extend(candidate.requests)
        read_ids.extend(candidate.read_ids)
        read_lengths.extend(candidate.read_lengths)
        groups.extend(candidate.sources)
        remaining = candidate.remaining
        if not remaining:
            break
    for did in read_ids:
        request = validate.frame.request
        request = request[:1] + did.to_bytes(2, "big") + request[3:]
        try:
            cache.transaction(validate, request, cached=False, extended=True)
        except ToyotaCodecError as exc:
            # 5900 discards the host registration cache; it sends no D4 rollback.
            return DynamicOutcome(
                0xA0050422,
                empty,
                tuple(failed_clears),
                tuple(failed_definitions),
                (did, exc.code),
                False,
                clear_ids,
            )
    if not read_ids:
        return DynamicOutcome(
            0xA0050422,
            empty,
            tuple(failed_clears),
            tuple(failed_definitions),
            None,
            False,
            clear_ids,
        )
    plan = DynamicPlan(
        tuple(requests), tuple(read_ids), tuple(read_lengths), tuple(groups), remaining
    )
    return DynamicOutcome(
        0x9005100A if remaining else 0,
        plan,
        tuple(failed_clears),
        tuple(failed_definitions),
        None,
        False,
        clear_ids,
    )


def selected_p5_polling_from_cache(
    cache: MonitorSupportCache,
    selected_ids: Sequence[int],
    observed_functions: Mapping[int, bool],
    *,
    interface_id: int,
    excluded: int,
    standard_values: Sequence[tuple[int, int]],
    parameter_6: int,
    active_alias_pid: int,
) -> SelectedP5PollingMonitor:
    """Native direct-DID branch using actual C8/CA discovery and LSB caches.

    One invocation is one logical support pass. begin_operation clears the
    temporary support cache while retaining native per-ECU Ever/LSB entries.
    Dynamic/DTC/RID policies are explicit separate producers.
    """
    from scripts.monitor_support import MonitorSupportCache
    from scripts.signal_lsb import SignalLSB

    if not isinstance(cache, MonitorSupportCache):
        raise MonitorError("Native P5 polling requires concrete support cache")
    if not isinstance(cache.profile, VehicleProfile):
        raise MonitorError("Native P5 polling requires a bound ECU database")
    selected_p5_definitions(cache.profile, selected_ids)
    cache.begin_operation()
    enabled = cache.data_ids().identifiers
    return selected_p5_polling_monitor(
        cache.profile,
        selected_ids,
        enabled,
        observed_functions,
        interface_id=interface_id,
        excluded=excluded,
        standard_values=standard_values,
        parameter_6=parameter_6,
        source_build=cache.source_build,
        active_alias_pid=active_alias_pid,
        lsb_producer=SignalLSB(
            cache, source_build=12 if cache.source_build == 12 else 18
        ),
    )


def p5_dynamic_layouts(
    selection: P5DynamicSelection,
    plan: DynamicPlan,
) -> tuple[tuple[tuple[int, int, int, int], ...], tuple[tuple[int, int], ...]]:
    """Native21a0/6220 packed-source offsets for a complete dynamic plan.

    Each source's selected bytes retain their order; unselected preceding bytes
    are subtracted before adding the source's offset in its dynamic response.
    The partial direct-DID fallback requires its separate combined producer.
    """
    if selection.ineligible_dids or plan.remaining:
        raise MonitorError("Partial dynamic plan requires direct-DID fallback")
    if (
        not 1 <= len(plan.read_ids) <= 256
        or len(plan.read_ids) != len(plan.read_lengths)
        or len(plan.read_ids) != len(plan.sources)
        or len(plan.read_ids) != len(plan.requests)
        or len(selection.ranges) > MAX_ITEMS
        or len(selection.sources) > MAX_ITEMS
        or sum(len(group) for group in plan.sources) > MAX_ITEMS
        or sum(len(source.runs) for source in selection.sources) > MAX_ITEMS
    ):
        raise MonitorError("Invalid dynamic mapping geometry")
    expected = {source.did: source for source in selection.sources}
    mapped: dict[
        int, tuple[int, int, DynamicSource, tuple[int, ...], tuple[int, ...]]
    ] = {}
    frames = []
    aggregate = 0
    for frame, (sources, length) in enumerate(zip(plan.sources, plan.read_lengths)):
        offset = 0
        for source in sources:
            if source.did in mapped or expected.get(source.did) != source:
                raise MonitorError("Dynamic mapping source differs from selected runs")
            starts, prefixes = [], []
            total = end = 0
            for position, count in source.runs:
                if position - 1 < end:
                    raise MonitorError("Dynamic selected runs overlap or are unordered")
                starts.append(position - 1)
                prefixes.append(total)
                total += count
                end = position - 1 + count
            mapped[source.did] = (frame, offset, source, tuple(starts), tuple(prefixes))
            offset += source.length
        if type(length) is not int or length != offset or not 0 < length <= 65535:
            raise MonitorError("Dynamic mapping response size differs from source runs")
        aggregate += length
        if aggregate > MAX_BYTES:
            raise MonitorError("Dynamic mapping response aggregate exceeds budget")
        frames.append((frame, length))
    if len(mapped) != len(expected):
        raise MonitorError("Dynamic mapping omits selected sources")
    layouts = []
    for item in selection.ranges:
        if item.runtime_flag == 1:
            continue
        if item.frame_id not in mapped:
            raise MonitorError("Dynamic mapping has no selected source DID")
        frame, offset, source, starts, prefixes = mapped[item.frame_id]
        start_byte = item.start_bit // 8
        index = bisect_right(starts, start_byte) - 1
        before = (
            prefixes[index] + min(start_byte - starts[index], source.runs[index][1])
            if index >= 0
            else 0
        )
        shift = (offset + before - start_byte) * 8
        start, end = item.start_bit + shift, item.end_bit + shift
        if not 0 <= start <= end < plan.read_lengths[frame] * 8 or end > 65535:
            raise MonitorError("Native dynamic signal position exceeds WORD/response")
        layouts.append((item.signal_id, frame, start, end))
    return tuple(layouts), tuple(frames)


def selected_p5_dynamic_from_cache(
    cache: MonitorSupportCache,
    selected_ids: Sequence[int],
    observed_functions: Mapping[int, bool],
    *,
    interface_id: int,
    excluded: int,
    standard_values: Sequence[tuple[int, int]],
    parameter_6: int,
    active_alias_pid: int,
    max_request: int,
    max_reply: int,
) -> SelectedP5DynamicMonitor:
    """Selected native18 complete dynamic DID path through actual support/exchanges.

    Failed/partial registration exposes DynamicRegistrationError.outcome with
    native status and disable-packet-ECU state. Its combined direct fallback,
    native12 loop and mixed DTC/RID path remain separate unfinished branches.
    """
    from scripts.monitor_support import MonitorSupportCache
    from scripts.signal_lsb import SignalLSB

    if not isinstance(cache, MonitorSupportCache) or cache.source_build != 18:
        raise MonitorError("Selected dynamic producer requires concrete native18 cache")
    if type(excluded) is not int or not 0 <= excluded <= 0xFFFFFFFF:
        raise MonitorError("Native P5 excluded modes must fit DWORD")
    if 26 not in observed_functions or type(observed_functions[26]) is not bool:
        raise MonitorError("Native P5 dynamic mode requires observed Attribute(2,26)")
    if not observed_functions[26] or excluded & 4:
        raise MonitorError("Native P5 dynamic mode is unavailable", 0x90051001)
    if not isinstance(cache.profile, VehicleProfile):
        raise MonitorError("Native P5 dynamic metadata requires a bound ECU database")
    definitions = selected_p5_definitions(cache.profile, selected_ids)
    cache.begin_operation()
    enabled = cache.data_ids().identifiers
    selection = p5_dynamic_sources(definitions, enabled)
    if selection.ineligible_dids:
        raise MonitorError(
            "Ineligible dynamic sources require native direct-DID fallback"
        )
    slots = selected_dynamic_slots(cache, source_build=18)
    outcome = register_dynamic_dids(
        cache, selection.sources, slots, max_request=max_request, max_reply=max_reply
    )
    if outcome.status:
        raise DynamicRegistrationError(outcome)
    layouts, frames = p5_dynamic_layouts(selection, outcome.plan)
    layouts, frames, pickup = monitor_composite_layouts(
        definitions, selection.ranges, layouts, frames
    )
    signals = selected_p5_signal_metadata(
        cache.profile,
        layouts,
        source_build=18,
        active_alias_pid=active_alias_pid,
        lsb_producer=SignalLSB(cache, source_build=18),
    )
    commands = p5_setup_commands(
        interface_id=interface_id,
        buffer_468=cache.profile.category,
        total_length=sum(length for _, length in frames),
        standard_values=standard_values,
        data_ids=tuple(zip(outcome.plan.read_ids, outcome.plan.read_lengths)),
        dtc_requests=(),
        routines=(),
        parameter_6=parameter_6,
        clear_ids=outcome.clear_ids,
    )
    if pickup:
        commands = replace(
            commands,
            setup=commands.setup
            + (
                MonitorCommand(
                    0x112,
                    (
                        interface_id,
                        b"".join(
                            struct.pack("<II", start & 0xFFFFFFFF, count)
                            for start, count in pickup
                        ),
                    ),
                ),
            ),
        )
    return SelectedP5DynamicMonitor(
        definitions,
        selection,
        outcome,
        signals,
        frames,
        commands,
        pickup,
        cache.source_build,
    )
