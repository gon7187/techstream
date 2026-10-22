"""Selected native12/18 mixed Phase5 monitor producer.

Support/discovery and registration execute through MonitorSupportCache. Generated
commands use the existing typed DMCI client and packet/recorder runtime.
"""

from __future__ import annotations

import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace

from scripts.active_replay import selected_routine_monitors
from scripts.data_monitor import (
    MAX_BYTES,
    MAX_DYNAMIC_COMPARISONS,
    MAX_ITEMS,
    DynamicOutcome,
    DynamicPlan,
    MonitorCommand,
    MonitorError,
    MonitorSetup,
    MonitorSignalMetadata,
    P5Definitions,
    P5DynamicSelection,
    P5Range,
    RoutineMonitor,
    monitor_composite_layouts,
    p5_dynamic_layouts,
    p5_dynamic_sources,
    p5_setup_commands,
    register_dynamic_dids,
    selected_dynamic_slots,
    selected_p5_definitions,
    selected_p5_signal_metadata,
)
from scripts.monitor_support import MonitorSupportCache
from scripts.profiles import VehicleProfile
from scripts.signal_lsb import SignalLSB
from scripts.support import word
from scripts.toyota import ToyotaCodecError, VariableTable


@dataclass(frozen=True)
class P5MixedPacking:
    data_ids: tuple[tuple[int, int], ...]
    layouts: tuple[tuple[int, int, int, int], ...]
    frame_sizes: tuple[tuple[int, int], ...]
    selection: P5DynamicSelection
    outcome: DynamicOutcome | None


class P5ControllerError(MonitorError):
    """A failed controller still retains actual registration side effects."""

    def __init__(self, message: str, outcome: DynamicOutcome):
        super().__init__(message, outcome.status)
        self.outcome = outcome


def mixed_p5_layouts(
    selection: P5DynamicSelection, outcome: DynamicOutcome | None
) -> P5MixedPacking:
    """21a0/6960: registered groups first, then unmapped DIDs in cache order.

    A failed CA validation discards every dynamic mapping. No D4 rollback is
    invented: registration's actual side effects remain in outcome.
    """
    if outcome is not None and (
        outcome.status not in (0, 0x9005100A, 0xA0050422)
        or outcome.status == 0xA0050422
        and outcome.plan.read_ids
    ):
        raise MonitorError("Native dynamic outcome cannot supply successful mappings")
    plan = outcome.plan if outcome else DynamicPlan((), (), (), (), ())
    used = {source.did for group in plan.sources for source in group}
    if len(used) != sum(map(len, plan.sources)):
        raise MonitorError("Duplicate native dynamic source mapping")
    dynamic = replace(
        selection,
        sources=tuple(source for source in selection.sources if source.did in used),
        ineligible_dids=(),
        ranges=tuple(
            item
            for item in selection.ranges
            if item.frame_id in used and item.runtime_flag != 1
        ),
    )
    layouts, frames = (), ()
    if used:
        layouts, frames = p5_dynamic_layouts(dynamic, replace(plan, remaining=()))
    ids = list(zip(plan.read_ids, plan.read_lengths))
    direct = {}
    for did, length in selection.full_lengths:
        if did not in used:
            direct[did] = len(ids)
            ids.append((did, length))
    frames += tuple((index, ids[index][1]) for index in direct.values())
    layouts += tuple(
        (item.signal_id, direct[item.frame_id], item.start_bit, item.end_bit)
        for item in selection.ranges
        if item.frame_id in direct and item.runtime_flag != 1
    )
    if len(ids) > 256:
        raise MonitorError("Native P5 mixed frame index exceeds byte")
    return P5MixedPacking(tuple(ids), layouts, frames, selection, outcome)


@dataclass(frozen=True)
class SelectedP5Monitor:
    definitions: P5Definitions
    packing: P5MixedPacking
    signals: tuple[MonitorSignalMetadata, ...]
    frame_sizes: tuple[tuple[int, int], ...]
    commands: MonitorSetup
    pickup_spans: tuple[tuple[int, int], ...]
    source_build: int
    mode: int
    dtc_requests: tuple[bytes, ...]
    dtc_patterns: tuple[int, ...]
    routines: tuple[RoutineMonitor, ...]
    default_signal_slots: tuple[int, ...]


def p5_signal_table(
    definitions: P5Definitions,
    ranges: Sequence[P5Range],
    metadata: Mapping[int, MonitorSignalMetadata],
    routine_signals: Sequence[MonitorSignalMetadata],
) -> tuple[tuple[MonitorSignalMetadata, ...], tuple[int, ...]]:
    """18 bb40 /12 ac10 native SetItem indices, including overwrite and holes."""
    count = len(definitions.ranges) + len(routine_signals) + len(definitions.groups)
    if not 0 < count <= MAX_ITEMS:
        raise MonitorError("Native P5 signal table allocation exceeds host bound")
    # DatMonCommon6ab0 constructor; Create7080 constructs every allocated slot.
    empty = MonitorSignalMetadata(
        0, 0, 0, 0, "", b"", "", 0, 0, 0, 1, 1, 0, 0, 1, 0, (), (0, 1, 0)
    )
    table, written = [empty] * count, [False] * count
    runtime = {item.signal_id: item.runtime_flag for item in ranges}
    for index, item in enumerate(definitions.ranges):
        if runtime.get(item.signal_id, item.runtime_flag) == 1:
            continue
        table[index], written[index] = metadata[item.signal_id], True
    for index, signal in enumerate(routine_signals, len(definitions.ranges)):
        table[index], written[index] = signal, True
    # Native resets the base to completed RID count, not ordinary+RID count.
    for index, group in enumerate(
        sorted(definitions.groups, key=lambda group: group.signal_id),
        len(routine_signals),
    ):
        table[index], written[index] = metadata[group.signal_id], True
    return tuple(table), tuple(
        index for index, value in enumerate(written) if not value
    )


def _dtc_request(profile: VehicleProfile, signal_id: int) -> tuple[bytes, int]:
    """27e0 DB213→DB112→DB111 FIRST rows; no CommSet lookup here."""
    rows = profile.records(19)
    if len(rows) > MAX_ITEMS or any(len(row) != 8 for row in rows):
        raise MonitorError("Native P5 DB213 requires bounded8-byte records")
    row = next((row for row in rows if word(row, 0) == signal_id), None)
    if row is None:
        raise MonitorError("Selected P5 DTC retrieval is absent", 0xC0050101)
    try:
        selected = profile.function_frame(word(row, 2))
    except ToyotaCodecError as exc:
        if exc.code not in (0x90020104, 0xC0040101):
            raise
        raise MonitorError(
            "Selected P5 DTC function/frame is absent", 0xC0050101
        ) from exc
    request = selected.frame.request
    if not 3 <= len(request) <= 4096:
        raise MonitorError("Selected P5 DTC request is short/excessive", 0xC0040102)
    return request[:2] + b"\x08" + request[3:], row[6]


def p5_routine_signal_metadata(
    profile: VehicleProfile, signal_id: int, frame: int, size: int, *, source_build: int
) -> MonitorSignalMetadata:
    """Native18 cf40 /12 c010 RID display, independently of DB23E c8d0."""
    if source_build not in (12, 18) or not 0 <= frame <= 255 or not 1 <= size <= 8192:
        raise MonitorError("Native P5 routine display geometry is invalid")
    rows = profile.records(71)
    if len(rows) > MAX_ITEMS or any(
        len(row) != (60 if source_build == 12 else 64) for row in rows
    ):
        raise MonitorError("Native P5 routine display table is invalid")
    routine = next((row for row in rows if word(row, 30) == signal_id), None)
    if routine is None:
        raise MonitorError("Selected routine display is absent", 0xC0050101)
    displays = profile.records(73)
    if len(displays) > MAX_ITEMS or any(len(row) != 20 for row in displays):
        raise MonitorError("Native P5 button display table is invalid")
    group = word(routine, 52 if source_build == 12 else 54)
    selected = tuple(row for row in displays if word(row, 4) == group)
    if not selected:
        raise MonitorError("Selected routine display group is empty", 0xC0050101)
    section = profile.catalog.management.sections[0]
    variables = VariableTable(section.payload, section.count)
    patterns = []
    retained = 0
    maximum, minimum = 0, 0xFFFFFFFF
    for row in selected:
        value = 0
        payload = variables.get(word(row, 10))
        label = profile.catalog.language.resolve(int.from_bytes(row[:4], "little"))
        retained += len(payload) + 4 * len(label) + 32
        if retained > MAX_BYTES:
            raise MonitorError("Native RID display aggregate exceeds byte budget")
        for index, byte in enumerate(payload):
            value |= byte << (((len(payload) - index - 1) * 8) & 31)
        patterns.append(
            (
                word(row, 4),
                label,
                value,
                0,
            )
        )
        maximum, minimum = max(maximum, value), min(minimum, value)
    return MonitorSignalMetadata(
        0x2134,
        frame,
        0,
        size * 8 - 1,
        profile.catalog.language.resolve(int.from_bytes(routine[8:12], "little")),
        b"",
        "",
        1,
        0,
        0,
        1,
        1,
        0,
        0,
        maximum,
        minimum,
        tuple(patterns),
        (int.from_bytes(routine[12:16], "little"), maximum, minimum),
    )


def _routine_status_width(profile: VehicleProfile, key: int, source_build: int) -> int:
    row = next((row for row in profile.records(71) if word(row, 30) == key), None)
    if row is None:
        raise MonitorError("Selected routine status width is absent", 0xC0050101)
    group = word(row, 52 if source_build == 12 else 54)
    display = next((row for row in profile.records(73) if word(row, 4) == group), None)
    if display is None:
        raise MonitorError("Selected routine status group is empty", 0xC0050101)
    section = profile.catalog.management.sections[0]
    return len(VariableTable(section.payload, section.count).get(word(display, 10)))


def selected_p5_monitor_from_cache(
    cache: MonitorSupportCache,
    selected_ids: Sequence[int],
    observed_functions: Mapping[int, bool],
    *,
    interface_id: int,
    excluded: int,
    standard_values: Sequence[tuple[int, int]],
    parameter_6: int,
    active_alias_pid: int,
    dynamic_requested: bool,
    max_request: int,
    max_reply: int,
    routine_ids: Sequence[int] = (),
) -> SelectedP5Monitor:
    """4eb0 mixed setup with native registration→direct fallback chronology.

    routine_ids are the explicit selected RID list (1c50), separate from the
    normal102b0 range list. Neither list implies observed vehicle support.
    """
    if not isinstance(cache, MonitorSupportCache) or cache.source_build not in (12, 18):
        raise MonitorError("Mixed P5 requires concrete source12/18 support cache")
    # Validate caller-owned command fields before support I/O or ECU definitions.
    p5_setup_commands(
        interface_id=interface_id,
        buffer_468=cache.profile.category,
        total_length=0,
        standard_values=standard_values,
        data_ids=((0, 0),),
        dtc_requests=(),
        routines=(),
        parameter_6=parameter_6,
    )
    if any(
        type(value) is not int or not 0 <= value <= 65535
        for value in (max_request, max_reply, active_alias_pid)
    ):
        raise MonitorError("Native P5 limits/alias require uint16 fields")
    if (
        type(dynamic_requested) is not bool
        or type(excluded) is not int
        or not 0 <= excluded <= 0xFFFFFFFF
    ):
        raise MonitorError("Invalid native P5 mode inputs")
    if len(routine_ids) > MAX_ITEMS or any(
        type(key) is not int or not 0 <= key <= 65535 for key in routine_ids
    ):
        raise MonitorError("Native P5 routine selection requires bounded uint16 IDs")
    if routine_ids:
        rows = sum(len(cache.profile.records(slot)) for slot in (71, 72, 73))
        if rows * len(routine_ids) > MAX_DYNAMIC_COMPARISONS:
            raise MonitorError("Native P5 RID selection exceeds host work budget")
        section = cache.profile.catalog.management.sections[0]
        variables = VariableTable(section.payload, section.count)
        payload_work = 0
        for slot, offset in ((72, 2), (73, 10)):
            for row in cache.profile.records(slot):
                payload_work += len(variables.get(word(row, offset)))
                if payload_work * len(routine_ids) > MAX_BYTES:
                    raise MonitorError(
                        "Native P5 RID pattern work exceeds host byte budget"
                    )
    mask = 0
    for function, flag in ((0x1A, 4), (0x49, 0x20)):
        if (
            function not in observed_functions
            or type(observed_functions[function]) is not bool
        ):
            raise MonitorError("Mixed P5 requires observed monitor attributes")
        if observed_functions[function]:
            mask |= flag
    definitions = selected_p5_definitions(cache.profile, selected_ids)
    ordinary = replace(
        definitions,
        ranges=tuple(item for item in definitions.ranges if not item.flags & 8),
        groups=(),
    )
    dtc_ranges = tuple(item for item in definitions.ranges if item.flags & 8)
    cache.begin_operation()
    enabled = cache.data_ids().identifiers
    selection = p5_dynamic_sources(ordinary, enabled)
    if not mask:
        raise MonitorError("Native P5 has no observed monitor mode", 0x90051007)
    mask &= ~excluded
    outcome = None
    mode = 0
    if dynamic_requested and mask & 4:
        try:
            slots = selected_dynamic_slots(
                cache, source_build=cache.source_build, enabled_dynamic_dids=enabled
            )
        except (MonitorError, ToyotaCodecError) as exc:
            if exc.code != 0xA0050422:
                raise
            outcome = DynamicOutcome(
                exc.code,
                DynamicPlan((), (), (), (), selection.sources),
                (),
                (),
                None,
                False,
            )
        else:
            outcome = register_dynamic_dids(
                cache,
                selection.sources,
                slots,
                max_request=max_request,
                max_reply=max_reply,
                source_rows_present=bool(selection.full_lengths),
            )
            if outcome.status == 0 and selection.ineligible_dids:
                outcome = replace(outcome, status=0x9005100A)
            if outcome.status not in (0, 0x9005100A, 0xA0050422):
                raise P5ControllerError(
                    "Native P5 dynamic registration failed", outcome
                )
            if outcome.status in (0, 0x9005100A):
                mode = 4
    used = (
        {source.did for group in outcome.plan.sources for source in group}
        if outcome
        else set()
    )
    fallback = any(did not in used for did, _ in selection.full_lengths)
    if fallback or not mode:
        if not mask & 0x20:
            if outcome is not None:
                raise P5ControllerError(
                    "Native P5 direct fallback unavailable", outcome
                )
            raise MonitorError(
                "Native P5 direct fallback unavailable",
                0x9005100A,
            )
        mode = 0x20
    packing = mixed_p5_layouts(selection, outcome)
    if not packing.data_ids:
        # 6960 returns before appending DTC/RID when neither direct nor dynamic
        # frame exists, even if auxiliary selections were supplied.
        raise MonitorError("Native P5 has no DID frames", 0x90051010)
    layouts, frames = packing.layouts, packing.frame_sizes
    dtc, patterns = (), ()
    if dtc_ranges:
        last = dtc_ranges[-1]
        request, pattern = _dtc_request(cache.profile, last.signal_id)
        dtc, patterns = (request,), (pattern,)
        frame = len(frames)
        length = (last.end_bit - last.start_bit) // 8 + 1
        if length != 2:
            # Host bound: dc80 always writes the two-byte DTC count.
            raise MonitorError("Unsafe native DTC count/frame geometry")
        frames += ((frame, length),)
        normal_dids = dict(selection.full_lengths)
        for item in dtc_ranges[:-1]:
            if item.frame_id not in normal_dids:
                code = 0x90051018 if item.frame_id == last.frame_id else 0x90051004
                raise MonitorError(
                    "Native P5 DTC source has no21a0 normal mapping", code
                )
        if dtc_ranges[:-1]:
            extra = mixed_p5_layouts(
                replace(selection, ranges=dtc_ranges[:-1]), outcome
            )
            layouts += extra.layouts
        # 21a0 uses FIRST source mapping; only the last DTC signal skips the
        # normal DID bitmap lookup/compression, including source-ID collisions.
        native_frame, native_offset = frame, 0
        if last.frame_id in normal_dids:
            if outcome and last.frame_id in used:
                for index, group in enumerate(outcome.plan.sources):
                    offset = 0
                    for source in group:
                        if source.did == last.frame_id:
                            native_frame, native_offset = index, offset
                        offset += source.length
            else:
                native_frame = next(
                    index
                    for index, (did, _) in enumerate(packing.data_ids)
                    if did == last.frame_id
                )
        layouts += (
            (
                last.signal_id,
                native_frame,
                last.start_bit + native_offset * 8,
                last.end_bit + native_offset * 8,
            ),
        )
    routines = []
    routine_signals = []
    retained = 0
    for key in routine_ids:
        group = selected_routine_monitors(cache.profile, key)
        routines.extend(group)
        # 2fb0 emits each special child's request, but ONE logical frame whose
        # length comes from the original parent descriptor, not either child.
        frame, size = (
            len(frames),
            _routine_status_width(cache.profile, key, cache.source_build),
        )
        if size != sum(item.size for item in group):
            # Host bound: native child appends must fit the parent allocation.
            raise MonitorError("Unsafe native RID parent/child packet geometry")
        frames += ((frame, size),)
        routine_signals.append(
            p5_routine_signal_metadata(
                cache.profile, key, frame, size, source_build=cache.source_build
            )
        )
        signal = routine_signals[-1]
        retained += (
            sum(
                len(item.request)
                + 2 * (len(item.normal) + len(item.abnormal) + len(item.stop))
                for item in group
            )
            + 4 * len(signal.name)
            + sum(32 + 4 * len(label) for _, label, _, _ in signal.patterns)
        )
        if retained > MAX_BYTES or len(routines) > MAX_ITEMS:
            raise MonitorError("Native P5 RID aggregate exceeds host byte/item budget")
    layouts, frames, pickup = monitor_composite_layouts(
        definitions, selection.ranges + dtc_ranges, layouts, frames
    )
    sizes = dict(frames)
    if any(
        frame not in sizes or end >= sizes[frame] * 8 for _, frame, _, end in layouts
    ):
        raise MonitorError("Unsafe native selected signal/frame geometry")
    signals = selected_p5_signal_metadata(
        cache.profile,
        layouts,
        source_build=cache.source_build,
        active_alias_pid=active_alias_pid,
        lsb_producer=SignalLSB(cache, source_build=cache.source_build),
    )
    signals, defaults = p5_signal_table(
        definitions,
        selection.ranges + dtc_ranges,
        {layout[0]: signal for layout, signal in zip(layouts, signals, strict=True)},
        routine_signals,
    )
    commands = p5_setup_commands(
        interface_id=interface_id,
        buffer_468=cache.profile.category,
        total_length=sum(size for _, size in frames),
        standard_values=standard_values,
        data_ids=packing.data_ids,
        dtc_requests=dtc,
        dtc_patterns=patterns,
        clear_ids=outcome.clear_ids if outcome else (),
        routines=tuple(routines),
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
    return SelectedP5Monitor(
        definitions,
        packing,
        signals,
        frames,
        commands,
        pickup,
        cache.source_build,
        mode,
        dtc,
        patterns,
        tuple(routines),
        defaults,
    )
