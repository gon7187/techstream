"""Selected PSA monitor packing and the native low-level polling machine.

Only explicit exchanges/providers are used; importing this module opens nothing.
"""

from __future__ import annotations

import math
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from threading import Event, Lock
from typing import Literal

from scripts import monitor_dlc12 as _voltage
from scripts.data_monitor import (
    MAX_BYTES,
    MAX_ITEMS,
    MonitorCommand,
    MonitorDefinitions,
    MonitorError,
    MonitorProvider,
    MonitorRange,
    MonitorReceive,
    MonitorSetup,
    MonitorSignalMetadata,
    selected_signal_metadata,
)
from scripts.drive_recorder import (
    NativeCoreBuffer,
    NativeDmciCommand,
    NativeMonitorBuffer,
    NativeMonitorPacket,
    NativeMonitorPacketReader,
    NativeMonitorReply,
    NativeVimClient,
    native_monitor_buffer,
)
from scripts.frame_transport import (
    DriverProperties,
    FramePlan,
    J2534Backend,
    J2534Result,
    NativeMessage,
)
from scripts.monitor_legacy import (
    LegacyMonitorEvent,
    LegacyPacking,
    legacy_pair_commands,
)
from scripts.monitor_support import (
    MonitorSupportCache,
    SupportQuery,
    SupportReceive,
    SupportSend,
    SupportStream,
    SupportTransaction,
    monitor_source_identity,
)
from scripts.monitor_support import mode35_frame_map as create_psa_frame_map
from scripts.profiles import VehicleProfile
from scripts.support import word
from scripts.toyota_session import Cancelled, LegacyActiveQueue, Limits

# PSA5e40/71d0/7240 reuse the exact nADMonitor stubs/calibration body recovered
# for DLC12. Keep one implementation of this common native behavior.
PSAVoltageObservation = _voltage.DLC12VoltageObservation
psa_voltage_controller = _voltage.dlc12_voltage_controller
psa_voltage_offset = _voltage.dlc12_voltage_offset


def _uint(value: int, maximum: int, label: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise MonitorError(f"Invalid native PSA {label}")
    return value


def _psa_profile(profile: VehicleProfile) -> None:
    if not isinstance(profile, VehicleProfile):
        raise MonitorError("Selected native PSA profile required")
    if profile.database.version not in (
        0x0100030C,
        0x0100032F,
    ) or profile.catalog.management.version not in (0x0100030C, 0x0100032F):
        raise MonitorError("PSA database layout is unproven for this version")
    if (
        not isinstance(profile.category_record, bytes)
        or len(profile.category_record) != 76
    ):
        raise MonitorError("Native PSA category requires76 bytes")


def psa_capabilities(observed: Mapping[int, bool]) -> tuple[int, tuple[int, ...]]:
    """PSA01890: the P4 extra29/27/28/35 queries are absent."""
    queried = []

    def check(key):
        if key not in observed or type(observed[key]) is not bool:
            raise MonitorError("Missing explicit PSA function observation")
        queried.append(key)
        return observed[key]

    mask = (
        5
        if check(22)
        else sum(bit for key, bit in ((10, 2), (8, 1), (9, 4)) if check(key))
    )
    for key, bit in ((12, 0x20), (25, 0x100), (11, 0x10), (26, 0x200)):
        if check(key):
            mask |= bit
    if not mask:
        raise MonitorError("Native PSA capabilities are empty", 0x90051007)
    return mask, tuple(queried)


def psa_definitions(
    profile: VehicleProfile, selected_ids: Sequence[int]
) -> MonitorDefinitions:
    """PSA08450/01450 append selected Freeze descriptors without P4 expansion."""
    _psa_profile(profile)
    if not selected_ids or len(selected_ids) > MAX_ITEMS:
        raise MonitorError("Select bounded PSA signal identifiers", 0xC0050001)
    if 10 not in profile.database.sections:
        raise MonitorError("Native PSA Freeze table absent", 0xA0030107)
    rows = profile.records(10)
    if len(rows) > MAX_ITEMS:
        raise MonitorError("Native PSA Freeze table exceeds item budget")
    first = {}
    for row in rows:
        if len(row) != 84:
            raise MonitorError("PSA Freeze rows require84 bytes", 0xC0050101)
        first.setdefault(word(row, 56), row)
    ranges = []
    for pid in selected_ids:
        _uint(pid, 65535, "signal identifier")
        if pid not in first:
            raise MonitorError("Selected PSA Freeze row is absent", 0xC0050101)
        row = first[pid]
        ranges.append(
            MonitorRange(word(row, 62), word(row, 64), pid, row[79], 0, row[78], 0)
        )
    return MonitorDefinitions(
        tuple(selected_ids), tuple(ranges), (), profile.database.sha256
    )


@dataclass(frozen=True)
class PSAPacking:
    mode: int
    setup_requests: tuple[bytes, ...]
    frame_sizes: tuple[tuple[int, int], ...]
    layouts: tuple[tuple[int, int, int, int], ...]
    enabled_pairs: tuple[tuple[int, int], ...]
    special_request: bytes | None = None


def pack_psa(
    definitions: MonitorDefinitions,
    enabled_lengths: Mapping[int, int],
    observed_functions: Mapping[int, bool],
    *,
    excluded: int,
    detail_mode35: int,
    mode35_data: Mapping[int, bytes] | None = None,
    freeze_rows: Sequence[bytes] = (),
    special_request: bytes | None = None,
) -> PSAPacking:
    """PSA22a0/26e0/30a0: native selection order, fallback lengths and Mode35."""
    if (
        not isinstance(definitions, MonitorDefinitions)
        or not 1 <= len(definitions.ranges) <= MAX_ITEMS
        or any(not isinstance(item, MonitorRange) for item in definitions.ranges)
    ):
        raise MonitorError("Bounded native PSA range definitions required")
    if len(freeze_rows) > MAX_ITEMS or any(
        not isinstance(row, bytes) or len(row) != 84 for row in freeze_rows
    ):
        raise MonitorError("Bounded84-byte PSA dynamic Freeze rows required")
    _uint(excluded, 0xFFFFFFFF, "excluded mode mask")
    _uint(detail_mode35, 0xFFFFFFFF, "detail function2/70")
    if len(enabled_lengths) > 256:
        raise MonitorError("PSA enabled PID table exceeds256 entries")
    for pid, length in enabled_lengths.items():
        _uint(pid, 255, "enabled PID")
        _uint(length, 255, "enabled length")
    special = next((row for row in reversed(definitions.ranges) if row.flags & 8), None)
    selected = []
    selected_seen = set()
    for item in definitions.ranges:
        if item.flags & 8:
            continue
        if item.frame_id not in enabled_lengths:
            raise MonitorError("Selected PSA PID is not enabled", 0xC0050414)
        if item.frame_id not in selected_seen:
            selected.append(item.frame_id)
            selected_seen.add(item.frame_id)
    capabilities, _ = psa_capabilities(observed_functions)
    available = capabilities & ~excluded
    if special is not None:
        available = capabilities & ~7
    # PSA mode1/mode2 builders are native C0050004 stubs; pair fallback follows.
    if not available & 0x30:
        code = 0xC0050004 if available & 3 else 0x90051001
        raise MonitorError("No reachable PSA monitor mode", code)
    mode = 0x10 if available & 0x10 else 0x100 if available & 0x100 else 0x20
    maps = {}
    if detail_mode35 == 1:
        if mode35_data is None:
            raise MonitorError("Native Mode35 cache was not supplied", 0x90051017)
        for item in definitions.ranges:
            if item.frame_id not in maps:
                if item.frame_id not in mode35_data:
                    raise MonitorError("Native Mode35 PID data absent", 0x90041103)
                maps[item.frame_id] = create_psa_frame_map(
                    item.frame_id, mode35_data[item.frame_id], freeze_rows
                )
    pairs = []
    frame_indexes = {}
    for pid in selected:
        length = enabled_lengths[pid]
        if not length:
            continue
        if detail_mode35 == 1 and not maps[pid].total_bits:
            continue
        frame_indexes[pid] = len(pairs)
        pairs.append((pid, length))
    if not pairs and special is None:
        raise MonitorError("Native PSA pair selection is empty", 0x90051010)
    if len(pairs) > 255:
        raise MonitorError("PSA pair descriptor count exceeds255")
    service = 1 if available & 0x10 else 0x21
    requests = (
        (
            bytes((service, *(pid for pid, _ in pairs))),
            bytes((service | 0x40, *(size for _, size in pairs))),
        )
        if pairs
        else ()
    )
    frames = [(index, size) for index, (_, size) in enumerate(pairs)]
    if special is not None:
        if (
            not isinstance(special_request, bytes)
            or not 1 <= len(special_request) <= 256
        ):
            raise MonitorError(
                "Native PSA trigger request was not selected", 0xC0050101
            )
        requests += (special_request,)
        frames.append((len(pairs), (special.end_bit - special.start_bit) // 8 + 1))
        # Native16e0 selects the first descriptor matching the source frame key.
        frame_indexes.setdefault(special.frame_id, len(pairs))
    layouts = []
    for item in definitions.ranges:
        if item.flags & 8:
            if item.frame_id not in frame_indexes:
                raise MonitorError(
                    "PSA signal has no matching special frame", 0x90051004
                )
            layouts.append(
                (
                    item.signal_id,
                    frame_indexes[item.frame_id],
                    item.start_bit,
                    item.end_bit,
                )
            )
            continue
        if item.frame_id not in frame_indexes:
            raise MonitorError("Selected PSA signal has no packed frame", 0x90051004)
        start, end = item.start_bit, item.end_bit
        if detail_mode35 == 1:
            freeze = next(
                (row for row in freeze_rows if word(row, 56) == item.signal_id), None
            )
            if freeze is None:
                raise MonitorError("PSA dynamic signal definition absent", 0xC0050101)
            if freeze[78] & 1:
                if freeze[77] > 2:
                    raise MonitorError("PSA dynamic metadata mode invalid", 0xA0040004)
                if freeze[77] < 2 and freeze[83] in maps[item.frame_id].identifiers:
                    from scripts.toyota import ToyotaCodecError

                    try:
                        mapped_start, mapped_end = maps[item.frame_id].position(freeze)
                    except ToyotaCodecError:
                        pass
                    else:
                        if mapped_end < enabled_lengths[item.frame_id] * 8:
                            start, end = mapped_start, mapped_end
        layouts.append((item.signal_id, frame_indexes[item.frame_id], start, end))
    return PSAPacking(
        mode,
        requests,
        tuple(frames),
        tuple(layouts),
        tuple(pairs),
        special_request,
    )


@dataclass(frozen=True)
class SelectedPSAMonitor:
    definitions: MonitorDefinitions
    packing: PSAPacking
    signals: tuple[MonitorSignalMetadata, ...]
    frame_sizes: tuple[tuple[int, int], ...]
    commands: MonitorSetup
    addition_frames: tuple[tuple[int, bytes], ...]
    source_identity: tuple[object, ...] = ()

    def measurement(self, bus_id: int) -> PSAMeasurement:
        return psa_measurement(self.packing, bus_id)

    def event(self) -> LegacyMonitorEvent:
        if self.packing.mode != 0x20:
            # Actual DataListIF1d30 admits DataMonType1 only.
            raise MonitorError(
                "PSA J2534 event requires native DataMonType1", 0xE0000102
            )
        pairs = _psa_pair_descriptors(self.packing.setup_requests)
        event = LegacyMonitorEvent.psa(
            tuple(pid for pid, _ in pairs),
            tuple(size for _, size in pairs),
            addition_frames=self.addition_frames,
        )
        total = sum(size for _, size in self.frame_sizes)
        if sum(event.lengths) > total:
            raise MonitorError(
                "Native PSA descriptors exceed selected packet", 0xE0000102
            )
        event._data = bytearray(total)
        return event


def _psa_pair_descriptors(requests: tuple[bytes, ...]) -> tuple[tuple[int, int], ...]:
    """PSA8b20 uses the last recognized request and response descriptor."""
    ids = lengths = b""
    for request in requests:
        if not request:
            raise MonitorError("Empty native PSA descriptor", 0xC005100E)
        if request[0] in (1, 0x21):
            ids = request[1:]
        elif request[0] in (0x41, 0x61):
            lengths = request[1:]
        else:
            raise MonitorError(
                "Native PSA setup descriptor service rejected", 0xC005100E
            )
    if not ids or len(ids) != len(lengths):
        raise MonitorError("Native PSA descriptor arrays differ", 0xC005100E)
    return tuple(zip(ids, lengths))


def _psa_function_request(profile: VehicleProfile, function: int) -> bytes:
    from scripts.support import correspondence_rows
    from scripts.toyota import CommandFrame, VariableTable

    management = profile.catalog.management
    for slot in (0, 17, 18):
        if slot not in management.sections:
            raise MonitorError("Native PSA trigger frame table absent", 0xA0030107)
    functions = correspondence_rows(management, 18, profile.exception_ids)
    if len(functions) > MAX_ITEMS:
        raise MonitorError("Native PSA function frame table exceeds budget")
    selected = next(
        (
            row
            for row in functions
            if word(row, 0) == profile.category and word(row, 2) == function
        ),
        None,
    )
    if selected is None:
        raise MonitorError("Native PSA trigger function row absent", 0xC0050101)
    if management.sections[17].count > MAX_ITEMS:
        raise MonitorError("Native PSA frame table exceeds budget")
    frames = tuple(management.sections[17].rows(8))
    if len(frames) > MAX_ITEMS:
        raise MonitorError("Native PSA frame table exceeds budget")
    frame = next((row for row in frames if word(row, 0) == word(selected, 6)), None)
    if frame is None:
        raise MonitorError("Native PSA trigger communication frame absent", 0xC0050101)
    variables = management.sections[0]
    return CommandFrame.from_record(
        frame, VariableTable(variables.payload, variables.count)
    ).request


def _psa_special_request(
    profile: VehicleProfile, definitions: MonitorDefinitions
) -> bytes | None:
    special_request = None
    special = next(
        (item for item in reversed(definitions.ranges) if item.flags & 8), None
    )
    if special is not None:
        if 19 not in profile.database.sections:
            raise MonitorError("Native PSA trigger table absent", 0xA0030107)
        triggers = profile.records(19)
        if len(triggers) > MAX_ITEMS or any(len(row) != 8 for row in triggers):
            raise MonitorError("Invalid PSA trigger table", 0xC0050101)
        trigger = next(
            (row for row in triggers if word(row, 0) == special.signal_id), None
        )
        if trigger is None:
            raise MonitorError("Native PSA trigger row absent", 0xC0050101)
        special_request = _psa_function_request(profile, word(trigger, 2))
    return special_request


def selected_psa_monitor(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    support: Mapping[int, int],
    observed_functions: Mapping[int, bool],
    *,
    detail_mode35: int,
    interface_id: int,
    excluded: int,
    standard_values: Sequence[tuple[int, int]],
    mode35_data: Mapping[int, bytes] | None = None,
) -> SelectedPSAMonitor:
    _psa_profile(profile)
    if len(selected_ids) == 0:
        # Native8450 returns80 before voltage/support/Freeze queries when the
        # selected list pointer is absent or its count is zero.
        _uint(interface_id, 0xFFFFFFFF, "active-only interface identity")
        return SelectedPSAMonitor(
            MonitorDefinitions((), (), (), profile.database.sha256),
            PSAPacking(0x80, (), (), (), ()),
            (),
            (),
            MonitorSetup((), (), ()),
            (),
            monitor_source_identity(profile, "")[1:],
        )
    if profile.category == 0x68:
        raise MonitorError(
            "Native PSA selected monitor rejects voltage category", 0xC0050004
        )
    if len(profile.category_record) < 73:
        raise MonitorError("Native PSA category row is truncated", 0xC0050101)
    if profile.category_record[72] & 31 not in (10, 19):
        raise MonitorError("Selected source is not a PSA category", 0xC0050001)
    definitions = psa_definitions(profile, selected_ids)
    rows = profile.records(10)
    special_request = _psa_special_request(profile, definitions)
    packing = pack_psa(
        definitions,
        support,
        observed_functions,
        excluded=excluded,
        detail_mode35=detail_mode35,
        mode35_data=mode35_data,
        freeze_rows=rows,
        special_request=special_request,
    )
    if packing.mode not in (0x10, 0x20):
        raise MonitorError("Native PSA setup rejects selected mode", 0xA0050422)
    signals = selected_signal_metadata(profile, packing.layouts)
    runtime_pairs = _psa_pair_descriptors(packing.setup_requests)
    service = 1 if packing.mode == 0x10 else 0x21
    runtime_requests = (
        bytes((service, *(pid for pid, _ in runtime_pairs))),
        bytes((service | 0x40, *(size for _, size in runtime_pairs))),
    )
    legacy = LegacyPacking(
        "PSA", packing.mode, runtime_requests, packing.frame_sizes, ()
    )
    commands = legacy_pair_commands(
        legacy,
        interface_id=interface_id,
        buffer_468=profile.category,
        standard_values=standard_values,
        parameter_8=0xFFFFFFFF,
    )
    additions = []
    if 55 in profile.database.sections:
        addition_rows = profile.records(55)
        if len(addition_rows) > MAX_ITEMS or any(
            len(row) != 8 for row in addition_rows
        ):
            raise MonitorError("Invalid native PSA additional frame table")
        from scripts.toyota import CommandFrame, VariableTable

        management = profile.catalog.management
        variables_section = management.sections.get(0)
        if variables_section is None:
            raise MonitorError("Selected native frame variables absent", 0xC0040101)
        variables = VariableTable(variables_section.payload, variables_section.count)
        frame_section = management.sections.get(17)
        if frame_section is not None and frame_section.count > MAX_ITEMS:
            raise MonitorError("Native PSA additional frame table exceeds budget")
        frame_rows = () if frame_section is None else tuple(frame_section.rows(8))
        for pid, _ in runtime_pairs:
            row = next((row for row in addition_rows if row[4] == pid), None)
            if row is None:
                continue
            frame = next(
                (frame for frame in frame_rows if word(frame, 0) == word(row, 0)), None
            )
            if frame is None:
                raise MonitorError(
                    "PSA additional communication frame absent", 0xC0040101
                )
            option = CommandFrame.from_record(frame, variables).request
            if not 1 <= len(option) <= 64:
                raise MonitorError(
                    "PSA DMCI additional option exceeds native64 bytes", 0xE0000102
                )
            additions.append((pid, option))
    if additions:
        from scripts.drive_recorder import encode_native_mode21

        commands = MonitorSetup(
            commands.setup
            + (
                MonitorCommand(
                    0x117, (interface_id, encode_native_mode21(tuple(additions)))
                ),
            ),
            commands.start,
            commands.stop,
        )
    return SelectedPSAMonitor(
        definitions,
        packing,
        signals,
        packing.frame_sizes,
        commands,
        tuple(additions),
        monitor_source_identity(profile, "")[1:],
    )


class PSAMonitorFault(MonitorError):
    """Native error callback code and byte2 detail, without exposing response data."""

    def __init__(self, code: int, detail: int = 0):
        super().__init__("Native PSA monitor communication failed", code)
        self.detail = detail


class PSAMonitorStopped(MonitorError):
    """Native stop notification at a request boundary, without a complete packet."""


def psa_monitor_cycle(
    event: LegacyMonitorEvent,
    provider: MonitorProvider,
    ecu: str,
    *,
    expected_source_id: int,
    protocol: int,
    send_timeout: int,
    receive_timeout: int,
    retry_limit: int,
    tick_ms: Callable[[], int],
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    stopped: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[int, bytes]:
    """DataListIF4f40 monitor slot1; foreign addresses remain in receive state."""
    if (
        not isinstance(event, LegacyMonitorEvent)
        or event.family != "PSA"
        or not isinstance(ecu, str)
        or not ecu
    ):
        raise MonitorError("Selected PSA event and ECU required")
    for value, maximum, label in (
        (expected_source_id, 0xFFFFFFFF, "response address"),
        (protocol, 65535, "protocol"),
        (send_timeout, 0xFFFFFFFF, "send timeout"),
        (receive_timeout, 0xFFFFFFFF, "receive timeout"),
        (retry_limit, MAX_ITEMS, "retry limit"),
    ):
        _uint(value, maximum, label)
    budget = limits or Limits()
    started = clock()
    if not math.isfinite(started):
        raise MonitorError("PSA monitor clock must be finite")
    deadline = started + budget.seconds
    calls = retries = 0
    receive_only = False
    request_ready = True

    def check(before=False):
        nonlocal calls
        if cancelled():
            raise Cancelled("PSA monitor cancelled")
        now = clock()
        if not math.isfinite(now) or now >= deadline:
            raise MonitorError("PSA monitor deadline exhausted")
        if before:
            calls += 1
            if calls > budget.exchanges:
                raise MonitorError("PSA monitor driver budget exhausted")

    while True:
        check()
        if not receive_only:
            if request_ready and stopped():
                raise PSAMonitorStopped("Native PSA monitor stopped")
            request_ready = False
            check(True)
            code = provider.send(
                ecu,
                event.request,
                timeout=send_timeout,
                protocol=protocol,
                initialize=True,
            )
            check()
            _uint(code, 0xFFFFFFFF, "send status")
            if code:
                retries += 1
                if retries >= retry_limit:
                    raise PSAMonitorFault(0xE0000108)
                continue
        check(True)
        observed = provider.receive(
            ecu,
            buffer=True,
            maximum=4096,
            timeout=receive_timeout,
            argument_5=0,
            flags=100,
        )
        check()
        if not isinstance(observed, MonitorReceive):
            raise MonitorError("PSA monitor receive requires typed observation")
        if observed.code:
            if observed.code in (0x90020321, 0x90020323):
                raise PSAMonitorFault(
                    0xE000010E, observed.data[2] if len(observed.data) > 2 else 0
                )
            retries += 1
            if retries >= retry_limit:
                raise PSAMonitorFault(0xE0000108)
            receive_only = False
            continue
        retries = 0
        timestamp = _uint(tick_ms(), 0xFFFFFFFF, "receive timestamp")
        if observed.source_id != expected_source_id:
            receive_only = True
            continue
        try:
            result = event.accept(observed.data, timestamp)
        except MonitorError as error:
            raise PSAMonitorFault(0xE0000108) from error
        check()
        receive_only = False
        request_ready = True
        if result is not None:
            return result


def selected_psa_from_transaction(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    transaction: SupportTransaction,
    ecu: str,
    observed_functions: Mapping[int, bool],
    *,
    detail_mode35: int,
    interface_id: int,
    excluded: int,
    standard_values: Sequence[tuple[int, int]],
    support_stream: SupportStream | None = None,
    bus_id: int | None = None,
    source_build: int = 18,
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> SelectedPSAMonitor:
    """Selected source→actual raw support requests→PSA metadata and DMCI setup."""
    if len(selected_ids) == 0:
        return selected_psa_monitor(
            profile,
            selected_ids,
            {},
            observed_functions,
            detail_mode35=detail_mode35,
            interface_id=interface_id,
            excluded=excluded,
            standard_values=standard_values,
        )
    cache = MonitorSupportCache(
        profile,
        transaction,
        ecu,
        source_build=source_build,
        stream=support_stream,
        bus_id=bus_id,
        limits=limits,
        cancelled=cancelled,
        clock=clock,
    )
    dynamic = cache.mode35() if detail_mode35 == 1 else None
    support = cache.valid_ids(
        function=15, pid_offset=1, receive_offset=2, control=0, value=0
    )
    result = selected_psa_monitor(
        profile,
        selected_ids,
        support,
        observed_functions,
        detail_mode35=detail_mode35,
        interface_id=interface_id,
        excluded=excluded,
        standard_values=standard_values,
        mode35_data=dynamic,
    )
    cache._check()
    return result


def selected_psa_from_exchange(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    exchange: Callable[[str, bytes], bytes],
    ecu: str,
    observed_functions: Mapping[int, bool],
    *,
    detail_mode35: int,
    interface_id: int,
    excluded: int,
    standard_values: Sequence[tuple[int, int]],
    support_stream: SupportStream | None = None,
    bus_id: int | None = None,
    source_build: int = 18,
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> SelectedPSAMonitor:
    """Compatibility adapter: caller binds the selected frame and transport settings."""
    return selected_psa_from_transaction(
        profile,
        selected_ids,
        lambda query: exchange(query.ecu, query.request),
        ecu,
        observed_functions,
        detail_mode35=detail_mode35,
        interface_id=interface_id,
        excluded=excluded,
        standard_values=standard_values,
        support_stream=support_stream,
        bus_id=bus_id,
        source_build=source_build,
        limits=limits,
        cancelled=cancelled,
        clock=clock,
    )


@dataclass(frozen=True)
class PSAMeasurement:
    """Native MultiMonMeasureInfo payload: cycle, packet size, allocation, mode."""

    cycle: int
    packet_size: int
    allocation: int
    mode: int


def psa_voltage_packing(
    profile: VehicleProfile, selected_ids: Sequence[int]
) -> PSAPacking:
    """PSA33a0 voltage geometry used by the CheckDataMonitor branch."""
    if profile.category != 0x68:
        raise MonitorError("Native PSA voltage category required", 0xC0050001)
    if len(selected_ids) != 1:
        raise MonitorError("Native PSA voltage requires one signal", 0x90051003)
    definitions = psa_definitions(profile, selected_ids)
    item = definitions.ranges[0]
    difference = item.end_bit - item.start_bit
    # Native signed division truncates toward zero, including reversed ranges.
    quotient = difference // 8 if difference >= 0 else -(-difference // 8)
    if quotient != 1:
        raise MonitorError("Native PSA voltage width rejected", 0xC0050102)
    return PSAPacking(
        0x40,
        (b"\x04\0\0\0\x01",),
        ((0, 2),),
        ((item.signal_id, 0, item.start_bit, item.end_bit),),
        (),
    )


def psa_measurement(packing: PSAPacking, bus_id: int) -> PSAMeasurement:
    """PSA3b20/9c30/9ee0: selected pair timing and packet accounting."""
    if not isinstance(packing, PSAPacking):
        raise MonitorError("Native PSA packing required", 0xC0050001)
    _uint(bus_id, 65535, "measurement bus")
    sizes = tuple(size for _, size in packing.frame_sizes)
    if not sizes:
        raise MonitorError("Native PSA measurement has no frames", 0xC005100F)
    if len(sizes) > MAX_ITEMS:
        raise MonitorError("Native PSA measurement exceeds frame budget")
    for size in sizes:
        _uint(size, 65535, "measurement frame length")
    if packing.mode == 0x40:
        if packing.setup_requests != (b"\x04\0\0\0\x01",) or sizes != (2,):
            raise MonitorError("Native PSA voltage descriptors rejected", 0xC005100F)
        return PSAMeasurement(4, 6, 0, 0x40)
    if packing.mode not in (0x10, 0x20):
        raise MonitorError("Native PSA measurement mode rejected", 0xC005100D)
    if bus_id & 15 == 10 or bus_id in (0x12, 0x22):
        # Native unsigned multiply-and-shift, including exact multiples of seven.
        cycle = sum(4 + ((size * 0x124924925 >> 33) & 0xFFFFFFFC) for size in sizes)
    elif bus_id in (0x11, 0x21, 0x51):
        cycle = len(sizes) * 160
    else:
        raise MonitorError("Native PSA measurement bus rejected", 0xC0040602)
    return PSAMeasurement(cycle, sum(sizes) + 4, 0, packing.mode)


def psa_allocate_measurements(
    total: int, measurements: tuple[PSAMeasurement, ...]
) -> tuple[PSAMeasurement, ...]:
    """PSA9a30 proportional allocation, with remainder on the last monitor."""
    _uint(total, 0x7FFFFFFF, "measurement allocation")
    if (
        not total
        or not isinstance(measurements, tuple)
        or not 1 <= len(measurements) <= 3
    ):
        raise MonitorError("Native PSA allocation arguments rejected", 0xC0050001)
    for item in measurements:
        if not isinstance(item, PSAMeasurement):
            raise MonitorError("Typed native PSA measurements required", 0xC0050001)
        _uint(item.cycle, 0xFFFFFFFF, "measurement cycle")
        _uint(item.packet_size, 0xFFFFFFFF, "measurement packet size")
        if not item.cycle:
            raise MonitorError("Native PSA measurement cycle is zero")
    if len(measurements) == 1:
        allocations = [total]
    else:
        weights = [
            (item.packet_size * 10000 & 0xFFFFFFFF) // item.cycle
            for item in measurements
        ]
        denominator = sum(weights) & 0xFFFFFFFF
        if not denominator:
            raise MonitorError("Native PSA proportional weight is zero")
        allocations = [weight * total // denominator for weight in weights]
        used = sum(allocations)
        allocations[-1] = (
            allocations[-1] - used - total
            if total < used
            else allocations[-1] - used + total
        )
        if any(value < 0 or value > 0xFFFFFFFF for value in allocations):
            raise MonitorError("Native PSA proportional allocation exceeds host bounds")
    return tuple(
        PSAMeasurement(item.cycle, item.packet_size, value, item.mode)
        for item, value in zip(measurements, allocations)
    )


def check_psa_measurement_transaction(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    transaction: SupportTransaction,
    ecu: str,
    observed_functions: Mapping[int, bool],
    *,
    bus_id: int,
    detail_mode35: int,
    excluded: int = 7,
    support_stream: SupportStream | None = None,
    source_build: int = 18,
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> PSAMeasurement:
    """Source-bound PSA3b20 CheckDataMonitor eligibility and measured geometry."""
    if not selected_ids:
        raise MonitorError("Native PSA check selection is empty", 0xC0050404)
    if profile.category == 0x68:
        if cancelled():
            raise Cancelled("PSA voltage check cancelled")
        return psa_measurement(psa_voltage_packing(profile, selected_ids), 0)
    protocol = profile.protocol_info(bus_id)
    if protocol is None:
        raise MonitorError("Native PSA check protocol row absent", 0xC0050101)
    if len(profile.category_record) < 73:
        raise MonitorError("Native PSA check category row is truncated", 0xC0050101)
    if profile.category_record[72] & 31 not in (10, 19):
        raise MonitorError("Selected source is not a PSA category", 0xC0050001)
    definitions = psa_definitions(profile, selected_ids)
    cache = MonitorSupportCache(
        profile,
        transaction,
        ecu,
        source_build=source_build,
        stream=support_stream,
        bus_id=bus_id,
        limits=limits,
        cancelled=cancelled,
        clock=clock,
    )
    dynamic = cache.mode35() if detail_mode35 == 1 else None
    support = cache.valid_ids(
        function=15, pid_offset=1, receive_offset=2, control=0, value=0
    )
    packing = pack_psa(
        definitions,
        support,
        observed_functions,
        excluded=excluded,
        detail_mode35=detail_mode35,
        mode35_data=dynamic,
        freeze_rows=profile.records(10),
        special_request=_psa_special_request(profile, definitions),
    )
    cache._check()
    return psa_measurement(packing, bus_id)


def check_psa_measurement(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    exchange: Callable[[str, bytes], bytes],
    ecu: str,
    observed_functions: Mapping[int, bool],
    *,
    bus_id: int,
    detail_mode35: int,
    excluded: int = 7,
    support_stream: SupportStream | None = None,
    source_build: int = 18,
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> PSAMeasurement:
    """Compatibility adapter for a caller-bound selected transport."""
    return check_psa_measurement_transaction(
        profile,
        selected_ids,
        lambda query: exchange(query.ecu, query.request),
        ecu,
        observed_functions,
        bus_id=bus_id,
        detail_mode35=detail_mode35,
        excluded=excluded,
        support_stream=support_stream,
        source_build=source_build,
        limits=limits,
        cancelled=cancelled,
        clock=clock,
    )


@dataclass(frozen=True)
class PSACheckTarget:
    profile: VehicleProfile
    selected_ids: tuple[int, ...]
    ecu: str
    bus_id: int
    observed_functions: Mapping[int, bool]
    detail_mode35: int
    support_stream: SupportStream | None = None
    transaction: SupportTransaction | None = None
    source_build: int = 18


def check_psa_multi(
    targets: tuple[PSACheckTarget, ...],
    allocation: int,
    exchange: Callable[[str, bytes], bytes],
    *,
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[PSAMeasurement, ...]:
    """PSA3730 function42: up to three targets, native excluded-mask choice."""
    if not isinstance(targets, tuple) or not 1 <= len(targets) <= 3:
        raise MonitorError("Native PSA multi-monitor target count rejected", 0xC0050404)
    if any(
        not isinstance(item, PSACheckTarget) or not item.selected_ids
        for item in targets
    ):
        raise MonitorError("Native PSA multi-monitor target rejected", 0xC0050404)
    budget = limits or Limits()
    started = clock()
    if not math.isfinite(started):
        raise MonitorError("PSA check clock must be finite")
    calls = 0

    def check():
        if cancelled():
            raise Cancelled("PSA multi-monitor check cancelled")
        now = clock()
        if not math.isfinite(now) or now >= started + budget.seconds:
            raise MonitorError("PSA multi-monitor check deadline exhausted")
        return now

    def bounded_exchange(ecu, request):
        nonlocal calls
        check()
        calls += 1
        if calls > budget.exchanges:
            raise MonitorError("PSA multi-monitor check exchange budget exhausted")
        reply = exchange(ecu, request)
        check()
        return reply

    class BoundedTransaction:
        def __init__(self, transaction: SupportTransaction | None):
            self.transaction = transaction

        def __call__(self, query: SupportQuery, /) -> bytes:
            nonlocal calls
            if self.transaction is None:
                return bounded_exchange(query.ecu, query.request)
            check()
            calls += 1
            if calls > budget.exchanges:
                raise MonitorError("PSA multi-monitor transaction budget exhausted")
            reply = self.transaction(query)
            check()
            return reply

    class BoundedStream:
        def __init__(self, stream: SupportStream):
            self.stream = stream

        def consume(self):
            nonlocal calls
            check()
            calls += 1
            if calls > budget.exchanges:
                raise MonitorError("PSA multi-monitor primitive budget exhausted")

        def send(self, send: SupportSend, /) -> int:
            self.consume()
            result = self.stream.send(send)
            check()
            return result

        def receive(self, receive: SupportReceive, /) -> tuple[int, bytes]:
            self.consume()
            result = self.stream.receive(receive)
            check()
            return result

    excluded = 5 if sum(item.profile.category != 0x68 for item in targets) > 1 else 0
    measurements = []
    for item in targets:
        now = check()
        measurements.append(
            check_psa_measurement_transaction(
                item.profile,
                item.selected_ids,
                BoundedTransaction(item.transaction),
                item.ecu,
                item.observed_functions,
                bus_id=item.bus_id,
                detail_mode35=item.detail_mode35,
                source_build=item.source_build,
                support_stream=(
                    BoundedStream(item.support_stream)
                    if item.support_stream is not None
                    else None
                ),
                excluded=excluded,
                limits=Limits(
                    seconds=started + budget.seconds - now,
                    exchanges=max(1, budget.exchanges - calls),
                ),
                cancelled=cancelled,
                clock=clock,
            )
        )
        check()
    return psa_allocate_measurements(allocation, tuple(measurements))


def psa_comtol_identity(
    profile: VehicleProfile, bus_id: int, *, phase: int | None = None
) -> tuple[int, int, int]:
    """PSA54b0/9990: selected request identity, mapped peer, IDMap timer."""
    _psa_profile(profile)
    _uint(bus_id, 65535, "observed bus")
    if not bus_id:
        raise MonitorError("Native PSA connection bus is empty", 0xC0040602)
    if len(profile.category_record) < 73:
        raise MonitorError("Native PSA interface category is truncated", 0xC0050101)
    protocol = profile.protocol_info(bus_id)
    if protocol is None or len(protocol) < 18:
        raise MonitorError("Native PSA interface protocol absent", 0xC0050101)
    identity = word(protocol, 8)
    if bus_id & 15 != 10:
        raise MonitorError("Native PSA interface bus rejected", 0xC0050001)
    peer = (
        (identity - 0x100) & 0xFFFFFFFF
        if bus_id == 0x4A
        else (identity - 0xC0) & 0xFFFFFFFF
        if bus_id == 0x5A
        else identity & 0xFFFFFFDF
    )
    timeout = 0
    selected_phase = (
        profile.category_record[72]
        if phase is None
        else _uint(phase, 255, "global phase")
    )
    if selected_phase & 31 != 10:
        rows = profile.comm_info_can_records(word(protocol, 2))
        if not rows:
            raise MonitorError("Native PSA interface CAN row absent", 0xC0050101)
        timeout = word(rows[0], 12)
    return identity, peer, timeout or 50


def psa_comtol_commands(
    profile: VehicleProfile,
    selected: SelectedPSAMonitor,
    bus_id: int,
    *,
    phase: int | None = None,
) -> MonitorSetup:
    """PSA9740/87f0 and DataListIF5890/46b0/2910 full native DMCI plan."""
    if not isinstance(selected, SelectedPSAMonitor):
        raise MonitorError("Selected PSA monitor required")
    if (
        selected.definitions.source_sha256 != profile.database.sha256
        or selected.source_identity != monitor_source_identity(profile, "")[1:]
    ):
        raise MonitorError("PSA monitor source identity changed")
    identity, peer, timeout = psa_comtol_identity(profile, bus_id, phase=phase)
    protocol = profile.protocol_info(bus_id)
    assert protocol is not None
    can_rows = profile.comm_info_can_records(word(protocol, 2))
    if not can_rows or len(can_rows[0]) != 28:
        raise MonitorError("Native PSA baudrate CAN row absent", 0xC0050101)
    if int.from_bytes(can_rows[0][4:8], "little") != 500000:
        raise MonitorError("Native PSA baudrate is unsupported", 0xC0050101)
    if selected.packing.mode == 0x80:
        return MonitorSetup(
            (
                MonitorCommand(0x115, (1, 0x36, 0xC0, 0x1F, 0xC6, 0x40030, 1, 2, 10)),
                MonitorCommand(0x107, (2,)),
                MonitorCommand(
                    0x111, (identity, peer, timeout, 0xFFFFFFFF, 0xFFFFFFFF)
                ),
            ),
            (),
            (MonitorCommand(0x108, ()), MonitorCommand(0x104, ())),
        )
    if not selected.commands.setup or selected.commands.setup[0].values[1] != identity:
        raise MonitorError("PSA setup request identity differs from selected protocol")
    return MonitorSetup(
        (
            MonitorCommand(0x115, (1, 0x36, 0xC0, 0x1F, 0xC6, 0x40030, 1, 2, 10)),
            MonitorCommand(0x107, (2,)),
            MonitorCommand(0x111, (identity, peer, timeout, 0xFFFFFFFF, 0xFFFFFFFF)),
        )
        + selected.commands.setup,
        selected.commands.start,
        selected.commands.stop + (MonitorCommand(0x108, ()), MonitorCommand(0x104, ())),
    )


def _psa_worker_timers(profile: VehicleProfile) -> tuple[int, int]:
    """DataListIF4f40 first FuncCommFrameA7→ComSet; native fallback1000/200."""
    from scripts.support import correspondence_rows

    management = profile.catalog.management
    if 18 not in management.sections or 29 not in management.sections:
        return 1000, 200
    functions = correspondence_rows(management, 18, profile.exception_ids)
    function = next(
        (
            row
            for row in functions
            if word(row, 0) == profile.category and word(row, 2) == 0xA7
        ),
        None,
    )
    if function is None:
        return 1000, 200
    settings = correspondence_rows(management, 29, profile.exception_ids)
    timer = next((row for row in settings if word(row, 10) == word(function, 4)), None)
    if timer is None:
        return 1000, 200
    return int.from_bytes(timer[:4], "little"), int.from_bytes(timer[4:8], "little")


class PSAJ2534Monitor:
    """DataListIF selected monitor worker lifecycle over explicit primitives.

    Local signal offsets retain native SetEvent/ResetEvent meaning. The caller
    schedules poll() on its worker; no Windows thread or adapter is opened here.
    """

    def __init__(
        self,
        profile: VehicleProfile,
        selected: SelectedPSAMonitor,
        bus_id: int,
        ecu: str,
        *,
        transport_profile: VehicleProfile | None = None,
        source_id: int | None = None,
    ):
        from threading import Lock

        if (
            not isinstance(selected, SelectedPSAMonitor)
            or not isinstance(ecu, str)
            or not ecu
        ):
            raise MonitorError("Selected PSA context and ECU required")
        if selected.source_identity != monitor_source_identity(profile, "")[1:]:
            raise MonitorError("PSA J2534 selected source identity changed")
        identity, peer, _timer = psa_comtol_identity(profile, bus_id)
        if (
            not selected.commands.setup
            or selected.commands.setup[0].values[1] != identity
        ):
            raise MonitorError(
                "PSA J2534 setup identity differs from selected protocol", 0xE0000102
            )
        transport_profile = profile if transport_profile is None else transport_profile
        if (
            transport_profile.catalog.management.sha256
            != profile.catalog.management.sha256
            or transport_profile.exception_ids != profile.exception_ids
            or transport_profile.vehicle_name_key != profile.vehicle_name_key
        ):
            raise MonitorError("PSA monitor transport and metadata catalogs differ")
        if source_id is not None:
            _uint(source_id, 0xFFFFFFFF, "PSA receive source")
        self._profile = profile
        self._transport_profile = transport_profile
        self._selected = selected
        self.event = selected.event()
        self.ecu, self.bus_id, self.source_id = (
            ecu,
            bus_id,
            peer if source_id is None else source_id,
        )
        self.source_identity = monitor_source_identity(transport_profile, ecu)
        self.send_timeout, self.receive_timeout = _psa_worker_timers(transport_profile)
        self.retry_limit = 3
        self._signals = {
            0x28: False,
            0x2C: False,
            0x30: True,
            0x34: False,
            0x38: True,
            0x50: True,
        }
        self.state = "ready"
        self._busy = False
        self._lock = Lock()

    def _check_source(self) -> None:
        if (
            monitor_source_identity(self._transport_profile, self.ecu)
            != self.source_identity
            or monitor_source_identity(self._profile, "")[1:]
            != self._selected.source_identity
        ):
            raise MonitorError("PSA J2534 source context changed during monitoring")

    @property
    def signals(self) -> tuple[tuple[int, bool], ...]:
        with self._lock:
            return tuple(sorted(self._signals.items()))

    def setup(self) -> None:
        """DataListIF4ac0 rebuilds the event and sets setup notification50."""
        self._check_source()
        with self._lock:
            if self._busy or self.state == "running":
                raise MonitorError("PSA J2534 monitor cannot configure while running")
            self.event = self._selected.event()
            self._signals[0x50] = True
            self.state = "ready"

    def start(self) -> None:
        """DataListIF1ee0/4c30 zero packet storage and signal worker start."""
        self._check_source()
        with self._lock:
            if self._busy or self.state != "ready":
                raise MonitorError(
                    "PSA J2534 monitor cannot start in its current state"
                )
            self.event._data[:] = bytes(len(self.event._data))
            self._signals.update({0x28: False, 0x30: False, 0x2C: True})
            self.state = "running"

    def stop(self) -> None:
        """DataListIF296d0 resets setup/quit/start and sets stop notification."""
        with self._lock:
            self._signals.update({0x50: False, 0x28: False, 0x2C: False, 0x30: True})
            self.state = "stopped"
            if not self._busy:
                self._signals.update({0x34: False, 0x38: True})

    def _stopped(self) -> bool:
        with self._lock:
            return self.state == "stopped"

    def poll(
        self,
        provider: MonitorProvider,
        *,
        tick_ms: Callable[[], int],
        limits: Limits | None = None,
        cancelled: Callable[[], bool] = lambda: False,
        clock: Callable[[], float] = time.monotonic,
    ) -> tuple[int, bytes]:
        if (
            isinstance(provider, PSAJ2534Provider)
            and provider.source_identity != self.source_identity
        ):
            raise MonitorError(
                "PSA monitor and primitive provider source contexts differ"
            )
        with self._lock:
            if self.state != "running" or self._busy:
                raise MonitorError("PSA J2534 monitor is not available for polling")
            self._busy = True
            self._signals.update({0x2C: False, 0x38: False, 0x34: True})

        def guarded(callback):
            def observe():
                self._check_source()
                value = callback()
                self._check_source()
                return value

            return observe

        try:
            return psa_monitor_cycle(
                self.event,
                provider,
                self.ecu,
                expected_source_id=self.source_id,
                protocol=self.bus_id,
                send_timeout=self.send_timeout,
                receive_timeout=self.receive_timeout,
                retry_limit=self.retry_limit,
                tick_ms=guarded(tick_ms),
                limits=limits,
                cancelled=guarded(cancelled),
                stopped=self._stopped,
                clock=guarded(clock),
            )
        except BaseException:
            with self._lock:
                if self.state != "stopped":
                    self.state = "failed"
            raise
        finally:
            with self._lock:
                self._busy = False
                if self.state == "stopped":
                    self._signals.update({0x34: False, 0x38: True})


@dataclass(frozen=True)
class PSAJ2534FramePlan:
    frame: FramePlan
    open_baud: int
    source_identity: tuple[object, ...]


def psa_j2534_frame_plan(
    profile: VehicleProfile,
    request: bytes,
    *,
    bus_id: int,
    driver: DriverProperties,
    diagnostic_mode: bytes = bytes(16),
) -> PSAJ2534FramePlan:
    """CommFrameCtrl14510 lowA CAN path; intentionally distinct from GetCommFrame."""
    from scripts.frame_transport import (
        MAX_DATA,
        NativeConnect,
        NativeFilter,
        translate_configs,
    )

    _psa_profile(profile)
    _uint(bus_id, 65535, "PSA native bus")
    if not bus_id or bus_id & 15 != 10 or not isinstance(driver, DriverProperties):
        raise MonitorError("Native PSA lowA bus and observed driver required")
    header_size = 5 if bus_id & 0xF0 == 0x20 else 4
    if (
        not isinstance(request, bytes)
        or not request
        or len(request) > MAX_DATA - header_size
    ):
        raise MonitorError("Bounded native PSA request bytes required")
    if not isinstance(diagnostic_mode, bytes) or len(diagnostic_mode) != 16:
        raise MonitorError("Native PSA diagnostic mode requires16 bytes")
    protocol = profile.protocol_info(bus_id)
    if protocol is None:
        raise MonitorError("Native PSA protocol row absent", 0x90020104)
    can_rows = profile.comm_info_can_records(word(protocol, 2))
    if not can_rows:
        raise MonitorError("Native PSA CAN row absent", 0x90020104)
    can = can_rows[0]
    startup, tester = (
        _psa_function_request(profile, 0x67),
        _psa_function_request(profile, 0x7F),
    )
    if not startup or not tester:
        raise MonitorError(
            "Native PSA startup/tester frame is empty",
            0x90020501 if not startup else 0x90020502,
        )
    configs = translate_configs(
        (
            (1, int.from_bytes(can[4:8], "little")),
            (0x10100, 8),
            (0x10102, 0xE0),
            (0x10101, 0x1F),
            (0x10103, int.from_bytes(can[:4], "little")),
            (
                0x10105,
                word(
                    can, 16 if profile.catalog.management.version == 0x0100030C else 18
                ),
            ),
            (0x10206, 0),
            (0x10106, word(can, 12)),
        ),
        driver,
    )
    physical, functional = word(protocol, 8), word(protocol, 6)
    target = functional if bus_id & 0xF0 == 0x30 else physical
    payload = b"\0\0" + target.to_bytes(2, "big")
    if bus_id & 0xF0 == 0x20:
        payload += bytes((word(protocol, 10) & 255,))
    payload += request

    def message(data):
        return NativeMessage(6, 0, 0, 0, len(data), data)

    def identifier(value):
        return message((value & 0xFFFFFFFF).to_bytes(4, "big"))

    empty = NativeMessage(0, 0, 0, 0, 0, b"")
    address = (
        int.from_bytes(diagnostic_mode[8:12], "little")
        if word(diagnostic_mode, 0)
        else physical
    )
    if bus_id in (0x1A, 0x4A, 0x5A):
        delta = {0x1A: 0x20, 0x4A: 0x100, 0x5A: 0xC0}[bus_id]
        filters = (
            NativeFilter(1, identifier(0x7FF), identifier(address - delta), empty),
            NativeFilter(
                3,
                identifier(0xFFFFFFFF),
                identifier(address - delta),
                identifier(address),
            ),
        )
    elif bus_id & 0xF0 in (0x10, 0x20):
        # Source9a10 sees driver kind8 here, so its kind4 extra filter is absent.
        filters = (
            NativeFilter(
                3, identifier(0xFFFFFFFF), identifier(address | 8), identifier(address)
            ),
        )
    else:
        filters = ()
    frame = FramePlan(
        NativeConnect(0x1000C, 0),
        configs,
        filters,
        message(payload),
        empty,
        b"",
        startup,
        tester,
        physical,
        f"PSA:{profile.database.sha256}:{profile.catalog.management.sha256}:bus={bus_id}",
        driver.source,
    )
    return PSAJ2534FramePlan(frame, 0, monitor_source_identity(profile, "")[1:])


def decode_psa_j2534_message(
    message: NativeMessage, *, bus_id: int, maximum: int = 4096
) -> MonitorReceive:
    """CAN95f0/ae40 strips the native header and retains its literal source ID."""
    if not isinstance(message, NativeMessage) or message.protocol_id != 6:
        raise MonitorError("Native PSA CAN message required")
    _uint(bus_id, 65535, "PSA receive bus")
    _uint(maximum, 4096, "PSA receive capacity")
    if bus_id & 15 != 10:
        raise MonitorError("Native PSA receive requires lowA bus")
    header = 5 if bus_id & 0xF0 == 0x20 else 4
    if len(message.data) < header or len(message.data) - header > maximum:
        raise MonitorError("Native PSA receive payload exceeds bounded storage")
    return MonitorReceive(
        message.data[header:], int.from_bytes(message.data[2:4], "big"), 0
    )


@dataclass(frozen=True)
class PSAActiveOperation:
    category: int
    bus_id: int
    signal_id: int
    request_identity: int
    request: bytes
    repeat: int
    source_identity: tuple[object, ...]
    profile: VehicleProfile = field(repr=False, compare=False)
    protocol_phase: int

    def __post_init__(self) -> None:
        for value, maximum, label in (
            (self.category, 65535, "active category"),
            (self.bus_id, 65535, "active bus"),
            (self.signal_id, 65535, "active signal"),
            (self.request_identity, 0xFFFFFFFF, "active request identity"),
            (self.repeat, 65535, "active repeat"),
            (self.protocol_phase, 255, "active phase"),
        ):
            _uint(value, maximum, label)
        if not isinstance(self.request, bytes) or not 3 <= len(self.request) <= 63:
            raise MonitorError("PSA active request must contain3..63 bytes")
        if (
            not isinstance(self.profile, VehicleProfile)
            or self.source_identity != monitor_source_identity(self.profile, "")[1:]
        ):
            raise MonitorError("PSA active operation source identity differs")

    @property
    def command(self) -> MonitorCommand:
        # DataListIF3d90 copies the entire request, including its service byte.
        return MonitorCommand(0x10F, (self.request_identity, self.request, self.repeat))


def selected_psa_active_operation(
    profile: VehicleProfile,
    signal_id: int,
    value: int,
    *,
    observed_bus_id: int | None,
    variable_drive: bool,
    auxiliary: int = 0,
    support: bytes | None = None,
    support_cache: MonitorSupportCache | None = None,
    phase: int | None = None,
) -> PSAActiveOperation:
    """7fd0 selects the actual6690/73c0 request producer from observed function31.

    Function availability is an explicit observation. Variable-drive opcode13
    discovers the native Mode35 cache through its typed primitive transaction.
    """
    from scripts.toyota_session import active_request_psa

    _psa_profile(profile)
    _uint(signal_id, 65535, "active signal")
    _uint(value, 0xFFFFFFFF, "active value")
    _uint(auxiliary, 255, "active auxiliary")
    selected_phase = (
        profile.category_record[72]
        if phase is None
        else _uint(phase, 255, "active global phase")
    )
    if type(variable_drive) is not bool:
        raise MonitorError("PSA function31 observation must be boolean")
    if observed_bus_id is None:
        raise MonitorError("PSA active ECU connection cache absent", 0xC0040601)
    _uint(observed_bus_id, 65535, "active bus")
    if not observed_bus_id:
        raise MonitorError("PSA active ECU bus unavailable", 0xC0040602)
    protocol = profile.protocol_info(observed_bus_id)
    if protocol is None:
        raise MonitorError("PSA active protocol row absent", 0xC0050101)
    slot, width = (41, 92) if variable_drive else (11, 92)
    rows = _psa_active_rows(profile, slot, width)
    record = next((row for row in rows if word(row, 56) == signal_id), None)
    if record is None:
        raise MonitorError("PSA active selected signal absent", 0xC0050101)
    patterns = _psa_active_rows(profile, 12, 24)
    pattern = next((row for row in patterns if word(row, 0) == word(record, 64)), None)
    if pattern is None:
        raise MonitorError("PSA active selected pattern absent", 0xC0050101)
    comm_modes = () if 60 not in profile.database.sections else profile.records(60)
    if len(comm_modes) > MAX_ITEMS or any(len(row) != 8 for row in comm_modes):
        raise MonitorError("PSA active communication mode table malformed")
    comm_mode = next((row for row in comm_modes if word(row, 0) == signal_id), None)
    if not variable_drive:
        request, repeat = active_request_psa(
            record,
            pattern,
            selected_phase,
            value,
            auxiliary=auxiliary,
            support=support,
            comm_mode=comm_mode,
        )
    else:
        from scripts.toyota import CommandFrame, VariableTable

        management = profile.catalog.management
        section = management.sections.get(17)
        variables = management.sections.get(0)
        if section is None or variables is None:
            raise MonitorError(
                "PSA variable-drive communication table absent", 0xA0030107
            )
        if section.count > MAX_ITEMS:
            raise MonitorError("PSA variable-drive frame table exceeds budget")
        frame = next(
            (row for row in section.rows(8) if word(row, 0) == word(record, 74)), None
        )
        if frame is None:
            raise MonitorError(
                "PSA variable-drive communication frame absent", 0xC0050101
            )
        instructions = CommandFrame.from_record(
            frame, VariableTable(variables.payload, variables.count)
        ).request
        if len(instructions) > 61:
            raise MonitorError("PSA variable-drive frame exceeds61 bytes", 0xC0050102)
        output = bytearray((0x30 if comm_mode is None else comm_mode[2], record[80]))
        mode35 = None
        for opcode in instructions:
            if not opcode:
                break
            if opcode in (11, 12, 13):
                raise MonitorError(
                    "PSA variable-drive support opcode invalid", 0xC0050102
                )
            if opcode == 19:
                if support_cache is None:
                    raise MonitorError(
                        "PSA variable-drive requires native Mode35 discovery"
                    )
                if (
                    support_cache.identity[1:]
                    != monitor_source_identity(profile, "")[1:]
                ):
                    raise MonitorError("PSA active support source identity changed")
                if mode35 is None:
                    mode35 = support_cache.mode35()
                identifiers = mode35.get(record[80])
                if identifiers is None or record[86] not in identifiers:
                    raise MonitorError(
                        "PSA variable-drive identifier unsupported", 0xC0050443
                    )
                byte = identifiers.index(record[86])
            else:
                length = word(pattern, 8)
                byte = {
                    2: value,
                    3: value << ((7 - (record[68] & 7)) & 31),
                    4: record[86],
                    5: record[86],
                    6: record[86] + value,
                    7: (length & 255) if length else 6,
                    8: auxiliary,
                    10: value >> 8,
                    16: record[88],
                    17: length & 255,
                    18: 0x12,
                    20: 1,
                    21: 0x10,
                }.get(opcode, 0)
            output.append(byte & 255)
        request = bytes(output)
        repeat = word(pattern, 2) if pattern[20] else 0
    if len(request) <= 1:
        raise MonitorError("PSA active request has no parameter", 0xA0050441)
    return PSAActiveOperation(
        profile.category,
        observed_bus_id,
        signal_id,
        word(protocol, 8),
        request,
        repeat,
        monitor_source_identity(profile, "")[1:],
        profile,
        selected_phase,
    )


def _psa_active_rows(
    profile: VehicleProfile, slot: int, width: int
) -> tuple[bytes, ...]:
    if slot not in profile.database.sections:
        raise MonitorError("PSA selected active table absent", 0xA0030107)
    if profile.database.sections[slot].count > MAX_ITEMS:
        raise MonitorError("PSA selected active table exceeds budget")
    rows = profile.records(slot)
    if any(len(row) != width for row in rows):
        raise MonitorError("PSA selected active table has invalid row width")
    return rows


@dataclass(frozen=True)
class PSARunTarget:
    """Selected input to7b90/7cb0, before support discovery or setup."""

    profile: VehicleProfile
    selected_ids: tuple[int, ...]
    transaction: SupportTransaction
    ecu: str
    bus_id: int
    observed_functions: Mapping[int, bool]
    detail_mode35: int
    standard_values: tuple[tuple[int, int], ...] = ()
    support_stream: SupportStream | None = None
    source_build: int = 18
    allocation_size: int = 65536
    name: bytes = b""
    text_encoding: str = "ascii"
    source_identity: tuple[object, ...] = field(init=False)

    def __post_init__(self) -> None:
        from types import MappingProxyType

        _psa_profile(self.profile)
        if (
            not isinstance(self.selected_ids, tuple)
            or not 0 <= len(self.selected_ids) <= MAX_ITEMS
        ):
            raise MonitorError("PSA Run requires bounded selected signal IDs")
        for signal in self.selected_ids:
            _uint(signal, 65535, "Run signal")
        _uint(self.bus_id, 65535, "Run bus")
        if type(self.source_build) is not int or self.source_build not in (12, 18):
            raise MonitorError("PSA source build must be12 or18")
        if (
            not isinstance(self.ecu, str)
            or not self.ecu
            or not callable(self.transaction)
        ):
            raise MonitorError("PSA Run requires typed transaction and ECU identity")
        if (
            type(self.allocation_size) is not int
            or not 1 <= self.allocation_size <= MAX_BYTES
        ):
            raise MonitorError("PSA Run allocation exceeds byte budget")
        if not isinstance(self.name, bytes) or len(self.name) > 256:
            raise MonitorError("PSA Run buffer name exceeds budget")
        object.__setattr__(
            self, "observed_functions", MappingProxyType(dict(self.observed_functions))
        )
        object.__setattr__(
            self, "source_identity", monitor_source_identity(self.profile, "")[1:]
        )


@dataclass(frozen=True)
class PSAControlResult:
    command_id: int
    status: int
    flags20: int = 0
    flags24: int = 0
    flags28: int = 0


@dataclass(frozen=True)
class PSANotification:
    message_id: int
    wparam: int
    lparam: int = 0


def psa_error_notification(
    native_error: int, status: int, *, signal_id: int = 0
) -> PSANotification | None:
    """Native44e0 callback→window-message table, without posting a message."""
    _uint(native_error, 0xFFFFFFFF, "callback error")
    _uint(status, 0xFFFFFFFF, "callback status")
    _uint(signal_id, 65535, "active callback signal")
    if status == 0xE0000100 or 0xE0000189 <= status <= 0xE000018E:
        return None
    if status == 0xE000FFFF:
        return PSANotification(0x608, native_error)
    if status == 0xE00001CC:
        return PSANotification(0x602, 0, signal_id)
    codes = {
        0xE0000103: 0xA1050301,
        0xE0000104: 0xA1050308,
        0xE0000105: 0xA1050303,
        0xE0000106: 0xA1050305,
        0xE0000107: 0xA1050304,
        0xE0000108: 0xA1050304,
        0xE0000109: 0xA1050301,
        0xE000010A: 0xA1050308,
        0xE000010B: 0xA1050303,
        0xE000010C: 0xA1050305,
        0xE000010D: 0xA1050304,
        0xE000010E: 0xA1050304,
        0xE0001000: 0xA1050311,
    }
    return PSANotification(0x603, codes.get(status, 0xA1050307))


def psa_notifications(
    reply: NativeMonitorReply, *, signal_id: int = 0
) -> tuple[PSANotification, ...]:
    """DiagInterface3fe0→PSA4430/44e0/4790, preserving native array order."""
    if not isinstance(reply, NativeMonitorReply):
        raise MonitorError("PSA notifications require native monitor reply")
    if len(reply.buffers) != 5 or any(
        not isinstance(buffer, NativeCoreBuffer) for buffer in reply.buffers
    ):
        raise MonitorError("PSA notification buffers malformed")
    result = []
    first, detailed, active = (reply.buffers[index].data for index in range(3))
    if (
        sum(len(buffer.data) for buffer in reply.buffers) > MAX_BYTES
        or len(first) // 4
        + len(detailed) // 13
        + len(active) // 75
        + reply.trailing_value
        > MAX_ITEMS
    ):
        raise MonitorError("PSA notification input exceeds aggregate budget")
    for index in range(0, len(first) - 3, 4):
        note = psa_error_notification(
            int.from_bytes(first[index : index + 4], "little"),
            0xE000FFFF,
            signal_id=signal_id,
        )
        assert note is not None
        result.append(note)
    for index in range(0, len(detailed) - 12, 13):
        note = psa_error_notification(
            int.from_bytes(detailed[index + 4 : index + 8], "little"),
            int.from_bytes(detailed[index + 8 : index + 12], "little"),
            signal_id=signal_id,
        )
        if note is not None:
            result.append(note)
    if reply.trailing_value > MAX_ITEMS:
        raise MonitorError("PSA stop notification count exceeds budget")
    result.extend(PSANotification(0x515, 0) for _ in range(reply.trailing_value))
    for index in range(0, len(active) - 74, 75):
        size = int.from_bytes(active[index + 8 : index + 12], "little")
        if size > 63:
            raise MonitorError("PSA active notification exceeds native63-byte payload")
        if size >= 3:
            result.append(PSANotification(0x60C, active[index + 14]))
    if len(result) > MAX_ITEMS:
        raise MonitorError("PSA notification count exceeds budget")
    return tuple(result)


@dataclass
class PSAControlMessage:
    command_id: int
    targets: tuple[PSARunTarget, ...] = ()
    active: PSAActiveOperation | None = None
    stop_active: bool = False
    phase: int = 0
    primary: PSARunTarget | None = None
    completed: Event = field(default_factory=Event, init=False, repr=False)
    result: PSAControlResult | None = field(default=None, init=False)
    exception: BaseException | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        _uint(self.command_id, 0xFFFFFFFF, "queue command")
        if (
            not isinstance(self.targets, tuple)
            or len(self.targets) > 3
            or any(not isinstance(target, PSARunTarget) for target in self.targets)
        ):
            raise MonitorError(
                "PSA Run target list exceeds native three slots", 0xC0050001
            )
        if type(self.stop_active) is not bool:
            raise MonitorError("PSA active stop flag must be boolean")
        if type(self.phase) is not int or self.phase not in (0, 1):
            raise MonitorError("PSA monitor phase must be0 or1")
        if self.primary is not None and not isinstance(self.primary, PSARunTarget):
            raise MonitorError("PSA primary requires selected Run target")


class PSAController:
    """PSA4b80/4d30 cooperative queue and ComTol three-slot lifecycle.

    Run executes each selected support producer through typed transactions.
    Windows wait outcomes are explicit; no worker thread or adapter is opened.
    """

    def __init__(
        self,
        client: NativeVimClient | None = None,
        *,
        backend: J2534Backend | None = None,
        driver: DriverProperties | None = None,
        native_build: Literal[12, 18] = 18,
        clock: Callable[[], float] = time.monotonic,
        wait: Callable[[float], None] = time.sleep,
        maximum_queued: int = MAX_ITEMS,
        maximum_primitives: int = MAX_ITEMS,
    ):
        if (client is None) == (backend is None):
            raise MonitorError("PSA controller requires exactly one concrete transport")
        if client is not None and not isinstance(client, NativeVimClient):
            raise MonitorError("PSA ComTol controller requires native VIM client")
        if backend is not None and (driver is None or native_build not in (12, 18)):
            raise MonitorError("PSA J2534 controller requires driver and source build")
        self.device_kind = 4 if client is not None else 8
        self._backend, self._driver = backend, driver
        self._native_build: Literal[12, 18] = native_build
        self._clock = client.clock if client is not None else clock
        self._wait = wait
        self._provider: PSAJ2534Provider | None = None
        self._monitor: PSAJ2534Monitor | None = None
        self._monitor_category = 0
        self._primary: PSARunTarget | None = None
        self._last_identity = self._last_peer = 0
        self._active_queue = LegacyActiveQueue("psa")
        if type(maximum_queued) is not int or not 1 <= maximum_queued <= MAX_ITEMS:
            raise MonitorError("PSA queue budget invalid")
        if (
            type(maximum_primitives) is not int
            or not 1 <= maximum_primitives <= MAX_ITEMS
        ):
            raise MonitorError("PSA primitive budget invalid")
        self._cleaning = False

        def guarded_exchange(request, *, deadline, cancelled):
            # NativeVimClient invokes user clock/cancel callbacks internally.
            # Guard the actual byte boundary after those callbacks as well.
            if not self._cleaning:
                self._check_sources()
            assert client is not None
            reply = client.exchange(request, deadline=deadline, cancelled=cancelled)
            if not self._cleaning:
                self._check_sources()
            return reply

        self.client = (
            None
            if client is None
            else NativeVimClient(
                guarded_exchange, capabilities=client.capabilities, clock=client.clock
            )
        )
        self.maximum_queued = maximum_queued
        self.maximum_primitives = maximum_primitives
        self._remaining = maximum_primitives
        self._execution_lock = Lock()
        self.queue: deque[PSAControlMessage] = deque()
        self.slots: list[
            tuple[PSARunTarget, SelectedPSAMonitor, NativeMonitorBuffer | None] | None
        ] = [None, None, None]
        self.errors = [0, 0, 0]
        self.readers: dict[int, NativeMonitorPacketReader] = {}
        self.active_mask = 0
        self.active_operation: PSAActiveOperation | None = None
        self.created = False
        self.closed = False
        self.received_bytes = 0
        self.notifications: deque[PSANotification] = deque(maxlen=MAX_ITEMS)
        self.trace: deque[tuple[str, int]] = deque(maxlen=MAX_ITEMS)

    def enqueue(self, message: PSAControlMessage) -> None:
        if self.closed or not isinstance(message, PSAControlMessage):
            raise MonitorError("PSA controller closed or queue message invalid")
        if message.completed.is_set() or any(old is message for old in self.queue):
            raise MonitorError("PSA message already queued or completed")
        if len(self.queue) >= self.maximum_queued:
            raise MonitorError("PSA queue budget exceeded")
        self.queue.append(message)

    def _check_sources(self) -> None:
        active = self.active_operation
        if (
            active is not None
            and active.source_identity
            != monitor_source_identity(active.profile, "")[1:]
        ):
            raise MonitorError("PSA active source context changed")
        for slot in self.slots:
            if slot is not None:
                target, selected, _buffer = slot
                if (
                    selected.source_identity
                    != monitor_source_identity(target.profile, "")[1:]
                ):
                    raise MonitorError("PSA Run selected source context changed")

    def _claim_primitive(self) -> None:
        if self._remaining <= 0:
            raise MonitorError("PSA aggregate primitive budget exhausted")
        self._remaining -= 1

    def _commands(
        self,
        commands: Sequence[MonitorCommand],
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> None:
        assert self.client is not None
        bound = tuple(
            NativeDmciCommand.from_neutral(command.command_id, command.values)
            for command in commands
        )
        for command in bound:
            self._check_sources()
            remaining = deadline - self._clock()
            if not math.isfinite(remaining) or remaining <= 0:
                raise TimeoutError("PSA controller deadline exceeded")
            if cancelled():
                raise Cancelled("PSA controller cancelled")
            self._check_sources()
            self._claim_primitive()
            if command.command_id == 0x115:
                self.created = True
            self.client.dmci(command, timeout=remaining, cancelled=cancelled)
            self._check_sources()

    def post_error(self, code: int) -> None:
        _uint(code, 0xFFFFFFFF, "posted error")
        if not code:
            raise MonitorError("PSA posted error must be nonzero")
        for index, slot in enumerate(self.slots):
            if slot is not None:
                self.errors[index] = code
        self.trace.append(("error", code))

    def buffer_error(self, index: int = 3) -> int:
        _uint(index, 0xFFFFFFFF, "buffer error slot")
        if index >= 3:
            return next(
                (
                    code
                    for slot, code in zip(self.slots, self.errors, strict=True)
                    if slot is not None and code
                ),
                0,
            )
        return self.errors[index] if self.slots[index] is not None else 0

    def _stop(self) -> None:
        primary: BaseException | None = None
        deadline = time.monotonic() + 2
        self._cleaning = True
        if self.device_kind == 8:
            saved_clock, saved_wait = self._clock, self._wait
            try:
                if self._monitor is not None:
                    self._monitor.stop()
                elif (
                    self._active_queue.items
                    and self._active_queue.items[-1].state != 2
                    and self._active_queue.items[-1].next_tick
                    and self._provider is not None
                    and not self._provider.operations.poisoned
                    and self._provider.operations.channel is not None
                ):
                    self._remaining = 64
                    self._provider.prepare_cleanup(seconds=2)
                    self._clock, self._wait = self._provider.clock, time.sleep
                    self._active_queue.stop()
                    # Native9880 waits for the pending ActiveTestStop before disposal.
                    # Host cleanup remains bounded even if a recorded peer never replies.
                    for _ in range(64):
                        if time.monotonic() >= deadline:
                            raise TimeoutError("PSA active cleanup deadline exceeded")
                        self._poll_active(
                            min(deadline - time.monotonic(), 2), lambda: False
                        )
                        if self._active_queue.items[-1].state == 2:
                            break
                    else:
                        raise MonitorError(
                            "PSA active cleanup observation budget exhausted"
                        )
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - complete local disposal before preserving failure
                primary = exc
            finally:
                if self._provider is not None:
                    try:
                        self._provider.close()
                    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - release the channel after active-stop failure
                        if primary is None:
                            primary = exc
                        else:
                            primary.add_note(f"PSA channel disposal also failed: {exc}")
                self._clock, self._wait = saved_clock, saved_wait
                self._provider = None
                self._monitor = None
                self._primary = None
                self._active_queue = LegacyActiveQueue("psa")
        elif self.created:
            assert self.client is not None
            stopping = []
            if self.active_mask == 0x80:
                if self.active_operation is not None:
                    stopping.append(
                        MonitorCommand(
                            0x110, (self.active_operation.request_identity, 0)
                        )
                    )
            else:
                stopping.append(MonitorCommand(0x10E, ()))
            stopping.extend((MonitorCommand(0x108, ()), MonitorCommand(0x104, ())))
            for command in stopping:
                try:
                    remaining = deadline - time.monotonic()
                    if not math.isfinite(remaining) or remaining <= 0:
                        raise TimeoutError("PSA cleanup deadline exceeded")
                    self.client.dmci(
                        NativeDmciCommand.from_neutral(
                            command.command_id, command.values
                        ),
                        timeout=remaining,
                    )
                except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - attempt all cleanup primitives
                    if primary is None:
                        primary = exc
                    else:
                        primary.add_note(f"PSA cleanup also failed: {exc}")
            try:
                remaining = deadline - time.monotonic()
                if not math.isfinite(remaining) or remaining <= 0:
                    raise TimeoutError("PSA disposal deadline exceeded")
                status = self.client.change_mode(0, timeout=remaining)
                if status:
                    raise MonitorError("PSA ChangeMode0 failed", status)
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - disposal follows earlier cleanup faults
                if primary is None:
                    primary = exc
                else:
                    primary.add_note(f"PSA disposal also failed: {exc}")
        self.created = False
        self._cleaning = False
        self.active_mask = 0
        self.active_operation = None
        self.slots = [None, None, None]
        self.readers = {}
        self.trace.append(("stop", 0))
        if primary is not None:
            raise primary

    def _run_one(
        self,
        *,
        wait_status: int = 0,
        timeout: float = 10,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> PSAControlResult | None:
        if self.closed:
            raise MonitorError("PSA worker closed")
        _uint(wait_status, 0xFFFFFFFF, "worker wait result")
        if (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise MonitorError("PSA worker timeout must be positive finite")
        if wait_status == 1:
            try:
                self._stop()
            finally:
                self.closed = True
                while self.queue:
                    message = self.queue.popleft()
                    message.result = PSAControlResult(message.command_id, 0xC0050503)
                    message.completed.set()
            return None
        if wait_status == 0x102:
            if self.buffer_error():
                self._stop()
            return None
        if wait_status:
            self.post_error(0xA0050511)
            self._stop()
            return None
        if not self.queue:
            raise MonitorError("PSA queue event has no command", 0xC0050001)
        message = self.queue.popleft()
        self.trace.append(("dispatch", message.command_id))
        try:
            if cancelled():
                raise Cancelled("PSA controller cancelled")
            message.__post_init__()
            result = self._dispatch(message, timeout, cancelled)
        except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - completion precedes error propagation
            message.exception = exc
            result = PSAControlResult(
                message.command_id,
                exc.code if isinstance(exc, MonitorError) and exc.code else 0xC0050001,
            )
        message.result = result
        message.completed.set()
        self.trace.append(("finish", message.command_id))
        if result.status:
            self.post_error(result.status)
        if result.status or self.buffer_error():
            try:
                self._stop()
            except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - preserve primary outcome
                if message.exception is None:
                    message.exception = cleanup
                else:
                    message.exception.add_note(
                        f"PSA worker cleanup also failed: {cleanup}"
                    )
        return result

    def _dispatch(
        self, message: PSAControlMessage, timeout: float, cancelled: Callable[[], bool]
    ) -> PSAControlResult:
        command = message.command_id
        if command == 0xA:
            self._stop()
            return PSAControlResult(command, 0)
        if command in (0xB, 0xC):
            if not self.active_mask:
                return PSAControlResult(command, 0x90050405)
            deadline = self._clock() + timeout
            if command == 0xC:
                if self.device_kind == 8:
                    if self._active_queue.items:
                        self._active_queue.stop(initialize=message.stop_active)
                    return PSAControlResult(command, 0)
                if self.active_operation is not None:
                    self._commands(
                        (
                            MonitorCommand(
                                0x110,
                                (
                                    self.active_operation.request_identity,
                                    int(message.stop_active),
                                ),
                            ),
                        ),
                        deadline,
                        cancelled,
                    )
                self.active_operation = None
            else:
                active = message.active
                if (
                    active is None
                    or not isinstance(active.profile, VehicleProfile)
                    or active.category != active.profile.category
                    or active.source_identity
                    != monitor_source_identity(active.profile, "")[1:]
                ):
                    return PSAControlResult(command, 0xC0050001)
                primary = next(
                    (slot[0] for slot in self.slots if slot is not None), None
                )
                if primary is None or (
                    active.profile.catalog.management.sha256
                    != primary.profile.catalog.management.sha256
                    or active.profile.exception_ids != primary.profile.exception_ids
                    or active.profile.vehicle_name_key
                    != primary.profile.vehicle_name_key
                    or active.protocol_phase != primary.profile.category_record[72]
                ):
                    return PSAControlResult(command, 0xC0050001)
                same_category = next(
                    (
                        slot
                        for slot in self.slots
                        if slot is not None
                        and slot[0].profile.category == active.category
                    ),
                    None,
                )
                if (
                    same_category is not None
                    and active.source_identity != same_category[1].source_identity
                ):
                    return PSAControlResult(command, 0xC0050001)
                if self.device_kind == 8:
                    if self._monitor is not None or (
                        self._last_identity != 0
                        and active.request_identity != self._last_identity
                    ):
                        return PSAControlResult(command, 0xA0050441)
                    running = bool(
                        self._active_queue.items
                        and self._active_queue.items[-1].state != 2
                    )
                    if active.request[2] == 0x11:
                        if running:
                            self._active_queue.stop()
                        else:
                            self.notifications.append(PSANotification(0x515, 0))
                    else:
                        if running:
                            return PSAControlResult(command, 0xA0050441)
                        try:
                            self._active_queue.enqueue(
                                active.request, repeat_ms=active.repeat
                            )
                        except ValueError as exc:
                            raise MonitorError(
                                "PSA active native enqueue failed", 0xA0050441
                            ) from exc
                    self.active_operation = active
                    self._prepare_provider(active.request, timeout, cancelled)
                else:
                    self.active_operation = active
                    self._commands((active.command,), deadline, cancelled)
            return PSAControlResult(command, 0)
        if command not in (9, 0x38) or self.active_mask:
            return PSAControlResult(command, 0x90050405)
        targets = message.targets
        system_count = sum(target.profile.category != 0x68 for target in targets)
        if command == 0x38 and message.primary is not None:
            if (
                message.primary.source_identity
                != monitor_source_identity(message.primary.profile, "")[1:]
            ):
                raise MonitorError("PSA primary input source identity changed")
            # 7cb0 registers the global category with no signal list first.
            targets = (replace(message.primary, selected_ids=()),) + targets
        if not targets or (command == 9 and len(targets) != 1):
            return PSAControlResult(command, 0xC0050001)
        if len({target.profile.category for target in targets}) > 3:
            return PSAControlResult(command, 0xC0050001)
        primary_profile = targets[0].profile
        if any(
            target.profile.catalog.management.sha256
            != primary_profile.catalog.management.sha256
            or target.profile.exception_ids != primary_profile.exception_ids
            or target.profile.vehicle_name_key != primary_profile.vehicle_name_key
            for target in targets
        ):
            return PSAControlResult(command, 0xC0050001)
        primary_bus = targets[0].bus_id
        if any(
            target.profile.category != 0x68
            and not (primary_bus & 15 == 2 and target.bus_id & 15 == 2)
            and target.bus_id != primary_bus
            for target in targets
        ):
            return PSAControlResult(command, 0xC0050001)
        # Native7cb0 registers all categories before8b20 visits the final slots.
        # Re-registering preserves the slot position and replaces its signal list.
        registered: dict[int, PSARunTarget] = {}
        for target in targets:
            previous = registered.get(target.profile.category)
            if previous is not None and (
                previous.source_identity != target.source_identity
                or previous.bus_id != target.bus_id
                or previous.ecu != target.ecu
            ):
                return PSAControlResult(command, 0xC0050001)
            registered[target.profile.category] = target
        targets = tuple(registered.values())
        if sum(t.allocation_size for t in targets if t.selected_ids) > MAX_BYTES:
            raise MonitorError("PSA Run aggregate allocation exceeds budget")
        if self.created:
            self._stop()
        self.slots = [None, None, None]
        self.errors = [0, 0, 0]
        self.readers = {}
        self.received_bytes = 0
        self._remaining = self.maximum_primitives
        deadline = self._clock() + timeout
        excluded = (
            7
            if command == 9
            else 5
            if self.device_kind == 8 or system_count >= 2
            else 0
        )
        self._primary = targets[0]
        for target in targets:
            if (
                target.source_identity
                != monitor_source_identity(target.profile, "")[1:]
            ):
                raise MonitorError("PSA Run input source identity changed")
            identity, _peer, _timer = psa_comtol_identity(target.profile, target.bus_id)
            remaining = deadline - self._clock()
            if not math.isfinite(remaining) or remaining <= 0:
                raise TimeoutError("PSA Run support deadline exceeded")

            def transaction(
                query: SupportQuery, target: PSARunTarget = target
            ) -> bytes:
                self._claim_primitive()
                return target.transaction(query)

            class BoundedStream:
                def __init__(self, stream: SupportStream, claim: Callable[[], None]):
                    self.stream, self.claim = stream, claim

                def send(self, request: SupportSend) -> int:
                    self.claim()
                    return self.stream.send(request)

                def receive(self, request: SupportReceive) -> tuple[int, bytes]:
                    self.claim()
                    return self.stream.receive(request)

            selected = selected_psa_from_transaction(
                target.profile,
                target.selected_ids,
                transaction,
                target.ecu,
                target.observed_functions,
                detail_mode35=target.detail_mode35,
                interface_id=identity,
                excluded=excluded,
                standard_values=target.standard_values,
                support_stream=None
                if target.support_stream is None
                else BoundedStream(target.support_stream, self._claim_primitive),
                bus_id=target.bus_id,
                source_build=target.source_build,
                limits=Limits(seconds=remaining),
                cancelled=cancelled,
                clock=self._clock,
            )
            buffer = (
                None
                if selected.packing.mode == 0x80
                else native_monitor_buffer(
                    target.profile.category,
                    selected.signals,
                    selected.frame_sizes,
                    selected.definitions.selected_ids,
                    phase=message.phase,
                    allocation_size=target.allocation_size,
                    name=target.name,
                    text_encoding=target.text_encoding,
                )
            )
            index = next(
                index
                for index, slot in enumerate(self.slots)
                if slot is None or slot[0].profile.category == target.profile.category
            )
            self.slots[index] = (target, selected, buffer)
        if self.device_kind == 8:
            self.created = True
            self.active_mask = 0
            last_monitor = None
            for slot in self.slots:
                if slot is None:
                    continue
                target, selected, _buffer = slot
                self.active_mask |= selected.packing.mode
                self._last_identity, self._last_peer, _ = psa_comtol_identity(
                    target.profile,
                    target.bus_id,
                    phase=primary_profile.category_record[72],
                )
                if selected.packing.mode != 0x80:
                    last_monitor = slot
            if last_monitor is not None:
                target, selected, _buffer = last_monitor
                try:
                    self._monitor = PSAJ2534Monitor(
                        target.profile,
                        selected,
                        primary_bus,
                        self._primary.ecu,
                        transport_profile=primary_profile,
                        source_id=self._last_peer,
                    )
                except MonitorError as exc:
                    raise MonitorError(
                        "PSA native event setup failed", 0xA0050422
                    ) from exc
                self._monitor_category = target.profile.category
                self._prepare_provider(
                    selected.packing.setup_requests[0], timeout, cancelled
                )
                self._monitor.start()
            return PSAControlResult(
                command,
                0,
                flags20=self.active_mask,
                flags28=int(command == 9),
                flags24=int(command == 0x38),
            )
        commands = []
        for slot in self.slots:
            if slot is None:
                continue
            target, selected, _buffer = slot
            plan = psa_comtol_commands(
                target.profile,
                selected,
                target.bus_id,
                phase=targets[0].profile.category_record[72],
            )
            if not commands:
                commands.extend(plan.setup[:2])
            commands.extend(plan.setup[2:])
            if selected.frame_sizes:
                self.readers[target.profile.category] = NativeMonitorPacketReader(
                    selected.frame_sizes, phase=message.phase
                )
        self._commands(commands, deadline, cancelled)
        self.active_mask = 0
        for slot in self.slots:
            if slot is not None:
                self.active_mask |= slot[1].packing.mode
        if self.active_mask & 0x337:
            self._commands((MonitorCommand(0x10C, ()),), deadline, cancelled)
        return PSAControlResult(
            command,
            0,
            flags20=self.active_mask,
            flags28=int(command == 9),
            flags24=int(command == 0x38),
        )

    def _tick(self) -> int:
        self._check_sources()
        value = self._clock()
        self._check_sources()
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise MonitorError("PSA worker clock must be finite nonnegative")
        return int(value * 1000) & 0xFFFFFFFF

    def _poll_active(
        self,
        timeout: float,
        cancelled: Callable[[], bool],
        *,
        deadline: float | None = None,
    ) -> tuple[tuple[int, NativeMonitorPacket], ...]:
        if not self._active_queue.items:
            return ()
        if (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise MonitorError("PSA active polling timeout must be positive finite")
        deadline = self._clock() + timeout if deadline is None else deadline

        def check_wait() -> None:
            self._check_sources()
            if cancelled():
                raise Cancelled("PSA active polling cancelled")
            self._check_sources()
            value = self._clock()
            self._check_sources()
            if (
                type(value) not in (int, float)
                or not math.isfinite(value)
                or value >= deadline
            ):
                raise TimeoutError("PSA active scheduler deadline exceeded")

        check_wait()
        item = self._active_queue.items[-1]
        now = self._tick()
        if item.state == 2:
            return ()
        if item.state == 1:
            if now < item.next_tick:
                self._check_sources()
                self._wait(min((item.next_tick - now) / 1000, timeout, 0.05))
                check_wait()
                now = self._tick()
                if now < item.next_tick:
                    return ()
            item.state = 0
            # Native4f40 schedules an expired repeated item on the next 1ms turn.
            self._wait(0.001)
            check_wait()
            return ()
        request = self._active_queue.send_frame(now)
        if request is None:
            self._wait(min(0.05, timeout))
            check_wait()
            return ()
        assert self._primary is not None
        provider = self._prepare_provider(
            request, timeout, cancelled, deadline=deadline
        )
        send_timeout, receive_timeout = _psa_worker_timers(self._primary.profile)
        code = provider.send(
            self._primary.ecu,
            request,
            timeout=send_timeout,
            protocol=self._primary.bus_id,
            initialize=True,
        )
        if code:
            raise PSAMonitorFault(0xE0000106)
        for _ in range(64 if self._cleaning else self.maximum_primitives):
            self._check_sources()
            if cancelled():
                raise Cancelled("PSA active polling cancelled")
            self._check_sources()
            if self._clock() >= deadline:
                raise TimeoutError("PSA active polling deadline exceeded")
            reply = provider.receive(
                self._primary.ecu,
                buffer=True,
                maximum=4096,
                timeout=receive_timeout,
                argument_5=0,
                flags=100,
            )
            tick = self._tick()
            if self._clock() >= deadline:
                raise TimeoutError("PSA active reply completed after deadline")
            self._check_sources()
            if reply.code:
                hard = reply.code in (0x90020321, 0x90020323)
                raise PSAMonitorFault(
                    0xE000010C if hard else 0xE0000106,
                    reply.data[2] if hard and len(reply.data) >= 3 else 0,
                )
            if reply.source_id != self._last_peer:
                continue
            try:
                self._active_queue.accept(reply.data, tick)
            except ValueError as exc:
                status = getattr(exc, "code", 0)
                raise PSAMonitorFault(
                    0xE00001CC if status == 0xE00001CC else 0xE0000106
                ) from exc
            self.received_bytes += len(reply.data)
            if self.received_bytes > MAX_BYTES:
                raise MonitorError("PSA active stream exceeds aggregate budget")
            if len(reply.data) >= 3:
                self.notifications.append(PSANotification(0x60C, reply.data[2]))
            if item.state == 2:
                self.notifications.append(PSANotification(0x515, 0))
            return ()
        raise MonitorError("PSA active receive observation budget exhausted")

    def _prepare_provider(
        self,
        request: bytes,
        timeout: float,
        cancelled: Callable[[], bool],
        *,
        deadline: float | None = None,
    ) -> PSAJ2534Provider:
        if self._provider is None:
            assert (
                self._primary is not None
                and self._backend is not None
                and self._driver is not None
            )
            controller = self

            class BoundedBackend:
                def invoke(self, operation, fields, *, deadline, cancelled):
                    if operation not in ("stop_message_filter", "disconnect"):
                        controller._check_sources()
                        controller._claim_primitive()
                    assert controller._backend is not None
                    result = controller._backend.invoke(
                        operation, fields, deadline=deadline, cancelled=cancelled
                    )
                    if operation not in ("stop_message_filter", "disconnect"):
                        controller._check_sources()
                    return result

            self._provider = PSAJ2534Provider(
                self._primary.profile,
                BoundedBackend(),
                self._primary.ecu,
                bus_id=self._primary.bus_id,
                request=request,
                native_build=self._native_build,
                driver=self._driver,
                limits=Limits(seconds=timeout, exchanges=self.maximum_primitives),
                cancelled=cancelled,
                clock=self._clock,
                wait=self._wait,
                defer_host_cleanup=True,
            )
            # DataListIF4960 allocates only; first SendIntExt opens the channel.
            self._provider.prepare()
        self._provider._remaining = min(self._provider._remaining, self._remaining)
        self._provider.cancelled = cancelled
        self._provider.parent_deadline = deadline
        self._provider.limits = Limits(
            seconds=timeout, exchanges=64 if self._cleaning else self.maximum_primitives
        )
        return self._provider

    def run_one(
        self,
        *,
        wait_status: int = 0,
        timeout: float = 10,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> PSAControlResult | None:
        if not self._execution_lock.acquire(blocking=False):
            raise MonitorError("PSA controller worker is busy")
        try:
            return self._run_one(
                wait_status=wait_status, timeout=timeout, cancelled=cancelled
            )
        finally:
            self._execution_lock.release()

    def poll_registered(
        self, *, timeout: float = 10, cancelled: Callable[[], bool] = lambda: False
    ) -> tuple[tuple[int, NativeMonitorPacket], ...]:
        """Shared DiagInterface28890 routes native10D chunks by category."""
        if not self._execution_lock.acquire(blocking=False):
            raise MonitorError("PSA controller worker is busy")
        try:
            if not self.active_mask or not self.created:
                raise MonitorError("PSA polling requires active acquisition")
            self._check_sources()
            start = self._clock()
            self._check_sources()
            if (
                type(start) not in (int, float)
                or not math.isfinite(start)
                or type(timeout) not in (int, float)
                or not math.isfinite(timeout)
                or timeout <= 0
            ):
                raise MonitorError(
                    "PSA polling requires finite clock and positive timeout"
                )
            deadline = start + timeout
            if self.device_kind == 8:
                if self._monitor is None:
                    return self._poll_active(timeout, cancelled, deadline=deadline)
                provider = self._prepare_provider(
                    self._monitor._selected.packing.setup_requests[0],
                    timeout,
                    cancelled,
                    deadline=deadline,
                )
                tick, payload = self._monitor.poll(
                    provider,
                    tick_ms=self._tick,
                    limits=Limits(seconds=timeout, exchanges=self.maximum_primitives),
                    cancelled=cancelled,
                    clock=self._clock,
                )
                if self._clock() >= deadline:
                    raise TimeoutError("PSA monitor packet completed after deadline")
                self._check_sources()
                self.received_bytes += len(payload)
                if self.received_bytes > MAX_BYTES:
                    raise MonitorError("PSA monitor stream exceeds aggregate budget")
                return ((self._monitor_category, NativeMonitorPacket(tick, payload)),)
            assert self.client is not None
            self._claim_primitive()
            reply = self.client.get_monitor_data(
                tuple(reversed(tuple(self.readers))),
                timeout=timeout,
                cancelled=cancelled,
            )
            self._check_sources()
            packets = []
            for category, chunk in reply.interfaces.items:
                if type(category) is not int or category not in self.readers:
                    continue
                if not isinstance(chunk, NativeCoreBuffer):
                    raise MonitorError("PSA native monitor chunk malformed")
                self.received_bytes += len(chunk.data)
                if self.received_bytes > MAX_BYTES:
                    raise MonitorError("PSA monitor stream exceeds aggregate budget")
                packets.extend(
                    (category, packet)
                    for packet in self.readers[category].feed(chunk.data)
                )
            notes = psa_notifications(
                reply,
                signal_id=0
                if self.active_operation is None
                else self.active_operation.signal_id,
            )
            self.notifications.extend(notes)
            errors = [
                note.wparam
                for note in notes
                if note.message_id in (0x603, 0x608) and note.wparam
            ]
            if errors:
                for code in errors:
                    self.post_error(code)
                raise MonitorError("PSA native monitor error notification", errors[0])
            if any(note.message_id == 0x515 for note in notes):
                for reader in self.readers.values():
                    reader.finish()
                self._stop()
            return tuple(packets)
        except (Exception, KeyboardInterrupt) as primary:
            if self.device_kind == 8 and isinstance(primary, PSAMonitorFault):
                note = psa_error_notification(
                    0,
                    primary.code or 0xE0000106,
                    signal_id=0
                    if self.active_operation is None
                    else self.active_operation.signal_id,
                )
                if note is not None:
                    self.notifications.append(note)
            if self.active_mask or self.created:
                self.post_error(
                    primary.code
                    if isinstance(primary, MonitorError) and primary.code
                    else 0xC0050001
                )
                try:
                    self._stop()
                except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - preserve packet failure
                    primary.add_note(f"PSA polling cleanup also failed: {cleanup}")
            raise
        finally:
            self._execution_lock.release()


class PSAJ2534Provider:
    """MonitorProvider joined to43's concrete J2534 primitives and lowA plan.

    Construction does not connect. open()/close() explicitly own the channel;
    no operation or successful driver result is supplied by default.
    """

    def __init__(
        self,
        profile: VehicleProfile,
        backend: J2534Backend,
        ecu: str,
        *,
        bus_id: int,
        request: bytes,
        native_build: Literal[12, 18],
        driver: DriverProperties,
        limits: Limits | None = None,
        cancelled: Callable[[], bool] = lambda: False,
        clock: Callable[[], float] = time.monotonic,
        wait: Callable[[float], None] = time.sleep,
        defer_host_cleanup: bool = False,
    ):
        from scripts.frame_transport import NativeFrameOperations
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )

        if not isinstance(ecu, str) or not ecu:
            raise MonitorError("PSA primitive provider requires ECU identity")
        self.profile, self.ecu, self.bus_id = profile, ecu, bus_id
        self.source_identity = monitor_source_identity(profile, ecu)
        self.limits = limits or Limits()
        self.cancelled, self.clock = cancelled, clock
        self._remaining = self.limits.exchanges
        self._closing = False
        if type(defer_host_cleanup) is not bool:
            raise MonitorError("PSA deferred host cleanup flag must be boolean")
        self.defer_host_cleanup = defer_host_cleanup
        self._lock = Lock()
        self.state = "new"
        self.parent_deadline: float | None = None
        self._host_clock_failure: BaseException | None = None
        self._cleanup_policy: tuple[Callable, ...] | None = None
        plan = psa_j2534_frame_plan(profile, request, bus_id=bus_id, driver=driver)
        provider = self

        class GuardedBackend:
            def invoke(self, operation, fields, *, deadline, cancelled):
                cleanup = provider._closing or operation in (
                    "stop_message_filter",
                    "disconnect",
                )
                if not cleanup:
                    try:
                        provider._check()
                    except Cancelled:
                        return J2534Result(host_boundary="cancelled_before")
                    except TimeoutError:
                        return J2534Result(host_boundary="deadline_before")
                    if provider._remaining <= 0:
                        return J2534Result(host_boundary="deadline_before")
                    provider._remaining -= 1
                until = (
                    deadline
                    if cleanup or provider.parent_deadline is None
                    else min(deadline, provider.parent_deadline)
                )
                result = backend.invoke(
                    operation, fields, deadline=until, cancelled=cancelled
                )
                if not cleanup:
                    try:
                        provider._check()
                    except Cancelled:
                        return replace(result, host_boundary="cancelled_after")
                    except TimeoutError:
                        return replace(result, host_boundary="deadline_after")
                return result

        self.operations = NativeFrameOperations(
            profile,
            plan.frame,
            GuardedBackend(),
            native_build=native_build,
            bus_id=bus_id,
            driver=driver,
            device_kind=8,
            open_baud=plan.open_baud,
            clock=clock,
            cancelled=lambda: False if self._closing else self.cancelled(),
            wait=wait,
        )
        self.operations.defer_cancel_cleanup = defer_host_cleanup
        self.controller = NativeFrameController(self.operations)
        self.communication = NativeCommunication(
            profile,
            self.controller,
            ecu,
            bus_id=bus_id,
            source_build=native_build,
            limits=self.limits,
            cancelled=lambda: False if self._closing else self.cancelled(),
            clock=clock,
        )

    def _check(self) -> None:
        if monitor_source_identity(self.profile, self.ecu) != self.source_identity:
            raise MonitorError("PSA primitive provider source identity changed")
        if self.cancelled():
            raise Cancelled("PSA primitive provider cancelled")
        if monitor_source_identity(self.profile, self.ecu) != self.source_identity:
            raise MonitorError(
                "PSA primitive provider source changed during cancellation callback"
            )

        if self.parent_deadline is not None and not self._closing:
            try:
                now = self.clock()
            except Exception as error:
                self._host_clock_failure = error
                raise TimeoutError("PSA host clock callback failed") from error
            if (
                type(now) not in (int, float)
                or not math.isfinite(now)
                or not math.isfinite(self.parent_deadline)
                or now >= self.parent_deadline
            ):
                raise TimeoutError("PSA primitive exceeded parent operation deadline")
            if monitor_source_identity(self.profile, self.ecu) != self.source_identity:
                raise MonitorError(
                    "PSA primitive source changed during deadline callback"
                )

    def _deadline(self) -> float:
        self._check()
        now = self.clock()
        self._check()
        if (
            isinstance(now, bool)
            or not isinstance(now, (int, float))
            or not math.isfinite(now)
        ):
            raise MonitorError("PSA primitive clock must be finite")
        until = now + self.limits.seconds
        return (
            until if self.parent_deadline is None else min(until, self.parent_deadline)
        )

    def prepare(self) -> None:
        """Native4960 local allocation; channel opening belongs to first send."""
        if not self._lock.acquire(blocking=False):
            raise MonitorError("PSA primitive provider busy")
        try:
            if self.state != "new":
                raise MonitorError("PSA primitive provider is not new")
            self._check()
            self.state = "ready"
        finally:
            self._lock.release()

    def open(self) -> None:
        if not self._lock.acquire(blocking=False):
            raise MonitorError("PSA primitive provider busy")
        try:
            if self.state != "new":
                raise MonitorError("PSA primitive provider is not new")
            code = self.operations.open(deadline=self._deadline())
            if code:
                raise MonitorError("PSA native channel initialization failed", code)
            self.state = "ready"
        except BaseException as error:
            self.state = (
                "ready"
                if self.defer_host_cleanup and not self.operations.poisoned
                else "failed"
            )
            failure, self._host_clock_failure = self._host_clock_failure, None
            if failure is not None and failure is not error:
                raise failure from error
            raise
        finally:
            self._lock.release()

    def send(
        self,
        ecu: str,
        request: bytes | None,
        *,
        timeout: int,
        protocol: int,
        initialize: bool,
    ) -> int:
        if not self._lock.acquire(blocking=False):
            raise MonitorError("PSA primitive provider busy")
        try:
            if (
                self.state != "ready"
                or ecu != self.ecu
                or protocol != self.bus_id
                or type(initialize) is not bool
            ):
                raise MonitorError(
                    "PSA primitive send context differs from selected monitor"
                )
            self._check()
            from scripts.toyota_session import NativeFrameSend

            self._deadline()
            self.communication.begin_operation(limits=self.limits)
            return self.communication.send_native(
                NativeFrameSend(
                    "SendIntExt" if initialize else "SendIntNoInitExt",
                    self.profile.category,
                    request,
                    timeout,
                    protocol,
                    0,
                    1,
                )
            )
        except BaseException as error:
            self.state = (
                "ready"
                if self.defer_host_cleanup and not self.operations.poisoned
                else "failed"
            )
            failure, self._host_clock_failure = self._host_clock_failure, None
            if failure is not None and failure is not error:
                raise failure from error
            raise
        finally:
            self._lock.release()

    def receive(
        self,
        ecu: str,
        *,
        buffer: bool,
        maximum: int,
        timeout: int,
        argument_5: int,
        flags: int,
    ) -> MonitorReceive:
        if not self._lock.acquire(blocking=False):
            raise MonitorError("PSA primitive provider busy")
        try:
            if self.state != "ready" or ecu != self.ecu:
                raise MonitorError(
                    "PSA primitive receive context differs from selected monitor"
                )
            self._check()
            if type(buffer) is not bool:
                raise MonitorError("PSA receive buffer presence must be boolean")
            if not buffer:
                return MonitorReceive(b"", 0, 0x90020701)
            self._deadline()
            value = self.communication.receive_native(
                maximum=maximum,
                timeout=timeout,
                argument_5=argument_5,
                flags=flags,
            )
            return MonitorReceive(value.data, value.source_id, value.code)
        except BaseException as error:
            self.state = (
                "ready"
                if self.defer_host_cleanup and not self.operations.poisoned
                else "failed"
            )
            failure, self._host_clock_failure = self._host_clock_failure, None
            if failure is not None and failure is not error:
                raise failure from error
            raise
        finally:
            self._lock.release()

    def prepare_cleanup(self, *, seconds: float = 2) -> None:
        """Fresh bounded host lease for the frozen native pending-stop request."""
        if not self._lock.acquire(blocking=False):
            raise MonitorError("PSA primitive provider busy")
        try:
            if self.operations.poisoned or self.operations.channel is None:
                raise MonitorError(
                    "PSA uncertain channel cannot issue protocol cleanup"
                )
            if monitor_source_identity(self.profile, self.ecu) != self.source_identity:
                raise MonitorError("PSA cleanup source context changed")
            confirmed = self.operations.last_confirmed_clock
            if confirmed is None:
                raise MonitorError("PSA cleanup lacks confirmed channel clock")
            if self._cleanup_policy is None:
                self._cleanup_policy = (
                    self.clock,
                    self.cancelled,
                    self.operations.clock,
                    self.operations.wait,
                    self.communication.clock,
                    self.communication.cache.clock,
                )
            started = time.monotonic()
            self.clock = lambda: confirmed + (time.monotonic() - started)
            self.cancelled = lambda: False
            self.operations.clock = self.clock
            self.operations.wait = time.sleep
            self.communication.clock = self.clock
            self.communication.cache.clock = self.clock
            self.limits = Limits(seconds=seconds, exchanges=64)
            self.parent_deadline = self.clock() + seconds
            self._remaining = 64
            self.state = "ready"
        finally:
            self._lock.release()

    def close(self) -> None:
        if not self._lock.acquire(blocking=False):
            raise MonitorError("PSA primitive provider busy")
        try:
            if self.state == "closed":
                return
            self._closing = True
            code = self.controller.close()
            if code:
                raise MonitorError("PSA native channel disposal failed", code)
        finally:
            self.state = "closed"
            self.operations.defer_cancel_cleanup = False
            if self._cleanup_policy is not None:
                (
                    self.clock,
                    self.cancelled,
                    self.operations.clock,
                    self.operations.wait,
                    self.communication.clock,
                    self.communication.cache.clock,
                ) = self._cleanup_policy
                self._cleanup_policy = None
            self.communication.closed = True
            self._closing = False
            self._lock.release()
