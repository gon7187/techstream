"""Distinct original12/18 flag9 CAN packet monitor; all I/O is injected."""

from __future__ import annotations

import struct
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace

from scripts.data_monitor import (
    MonitorCommand,
    MonitorDefinitions,
    MonitorError,
    MonitorSetup,
    MonitorSignalMetadata,
    SelectedMonitorConnection,
    dmci_id_map_fields,
    monitor_capabilities,
    monitor_composite_layouts,
    run_monitor_commands,
    selected_definitions,
    selected_signal_metadata,
)
from scripts.drive_recorder import NativeVimClient
from scripts.frame_transport import NativeFrameOperations, get_comm_frame
from scripts.frame_transport_variants import ExtendedCanOperations, lower_frame_plan
from scripts.monitor_j2534 import (
    INVALID,
    OK,
    CommItem,
    DirectJ2534Worker,
    PacketMonitorEvent,
)
from scripts.monitor_legacy import (
    LegacyPacking,
    phase3_auxiliary,
    select_phase3_packing,
)
from scripts.monitor_support import (
    MonitorSupportCache,
    PacketFrameCache,
    SupportStream,
    SupportTransaction,
    monitor_source_identity,
)
from scripts.profiles import VehicleProfile
from scripts.toyota import ToyotaCodecError
from scripts.toyota_session import Limits


def _uint(value: int, maximum: int, label: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise MonitorError(f"Invalid native A8 {label}")
    return value


def _guard(profile: VehicleProfile, protocol: int, source_build: int) -> None:
    _uint(protocol, 65535, "protocol")
    if type(source_build) is not int or source_build not in (12, 18):
        raise MonitorError("A8 requires explicit original source build12/18")
    if (
        len(profile.category_record) != 76
        or profile.category_record[72] & 31 != 9
        or protocol & 15 not in (2, 8)
    ):
        raise MonitorError("A8 requires selected flag9 and observed CAN protocol2/8")
    if profile.category in (0x68, 999):
        raise MonitorError("Instrument targets use their separate producer")


@dataclass(frozen=True)
class PacketA8Packing:
    mode: int
    setup_requests: tuple[bytes, ...]
    frame_sizes: tuple[tuple[int, int], ...]
    pid_layouts: tuple[tuple[int, int, int, int], ...]

    @property
    def family(self) -> str:
        return "A8"


def pack_packet_a8(
    selected_lengths: Sequence[tuple[int, int]],
    enabled_lengths: Mapping[int, int],
    pid_definitions: Mapping[int, tuple[bool, int]],
    cached_frames: Sequence[tuple[int, int]] | None,
    *,
    capabilities: int,
    excluded: int,
    maximum_request: int,
    maximum_reply: int,
    trigger: bool = False,
) -> tuple[PacketA8Packing, tuple[tuple[int, int], ...]]:
    """P4 34c0→3ee0/3990/41f0, independently audited against P3 algorithms."""
    result = select_phase3_packing(
        selected_lengths,
        enabled_lengths,
        pid_definitions,
        cached_frames,
        capabilities=capabilities,
        excluded=excluded,
        maximum_request=maximum_request,
        maximum_reply=maximum_reply,
        trigger=trigger,
    )
    p = result.packing
    return PacketA8Packing(
        p.mode, p.setup_requests, p.frame_sizes, p.pid_layouts
    ), result.attempts


def packet_a8_commands(
    packing: PacketA8Packing,
    *,
    interface_id: int,
    buffer_468: int,
    standard_values: Sequence[tuple[int, int]],
    attribute_2_23: bool,
) -> MonitorSetup:
    """P4dc50 literal wrapper, including its native rejection of mode2/100."""
    for value in (interface_id, buffer_468):
        _uint(value, 0xFFFFFFFF, "setup field")
    if type(attribute_2_23) is not bool:
        raise MonitorError("A8 requires observed Attribute(2,35)")
    standards = tuple(standard_values)
    if len(standards) > 100000 or any(
        not isinstance(pair, tuple)
        or len(pair) != 2
        or any(type(v) is not int or not 0 <= v <= 0xFFFFFFFF for v in pair)
        for pair in standards
    ):
        raise MonitorError("A8 standard values require bounded DWORD pairs")
    total = sum(size for _, size in packing.frame_sizes)
    if packing.mode == 1:
        if len(packing.setup_requests) != 1 or not packing.setup_requests[0].startswith(
            b"\xa1\x01"
        ):
            raise MonitorError("A8 ModeA1 descriptor is malformed", 0xC005100E)
        fields = (
            buffer_468,
            interface_id,
            ((1, packing.setup_requests[0][2:]),),
            total,
            standards,
            3000,
        )
        setup = MonitorCommand(0x109, fields)
    elif packing.mode in (0x10, 0x20):
        ids = sizes = b""
        for request in packing.setup_requests:
            if not request:
                raise MonitorError("A8 pair descriptor is empty", 0xC005100E)
            if request[0] in (1, 0x21):
                ids = request
            elif request[0] in (0x41, 0x61):
                sizes = request
            else:
                raise MonitorError("A8 pair descriptor service is invalid", 0xC005100E)
        if len(sizes) < 2 or len(ids) < len(sizes):
            raise MonitorError("A8 pair descriptors disagree", 0xC005100E)
        data_type = 0 if packing.mode == 0x10 else (6 if attribute_2_23 else 1)
        setup = MonitorCommand(
            0x10A,
            (
                buffer_468,
                interface_id,
                data_type,
                tuple(zip(ids[1 : len(sizes)], sizes[1:])),
                total,
                standards,
                3,
                0xFFFFFFFF,
            ),
        )
    else:
        raise MonitorError("Native P4 wrapper rejects this A8 mode", 0xC005100D)
    return MonitorSetup(
        (setup,), (MonitorCommand(0x10C, ()),), (MonitorCommand(0x10E, ()),)
    )


@dataclass(frozen=True)
class SelectedPacketA8Monitor:
    definitions: MonitorDefinitions
    packing: PacketA8Packing
    signals: tuple[MonitorSignalMetadata, ...]
    frame_sizes: tuple[tuple[int, int], ...]
    commands: MonitorSetup
    pickup_spans: tuple[tuple[int, int], ...]
    attempts: tuple[tuple[int, int], ...]
    source_identity: tuple[object, ...]
    source_build: int


def selected_packet_a8_monitor(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    enabled_lengths: Mapping[int, int],
    observed_functions: Mapping[int, bool],
    *,
    source_build: int,
    communication_protocol: int,
    interface_id: int,
    excluded: int,
    maximum_request: int,
    maximum_reply: int,
    cached_frames: Sequence[tuple[int, int]] | None,
    standard_values: Sequence[tuple[int, int]] = (),
) -> SelectedPacketA8Monitor:
    """Selected Freeze/DB206→distinct FUN3360 packing→actual native DMCI fields."""
    _guard(profile, communication_protocol, source_build)
    definitions = selected_definitions(profile, selected_ids)
    rows = profile.records(6)
    if len(rows) > 100000 or any(len(row) != 8 for row in rows):
        raise MonitorError("A8 DB206 requires bounded8-byte rows")
    pid_definitions, defaults = {}, {}
    for row in rows:
        pid_definitions.setdefault(row[2], (bool(row[4]), row[5]))
        defaults.setdefault(row[2], row[3])
    if len(enabled_lengths) > 256:
        raise MonitorError("A8 enabled PID table exceeds256 entries")
    enabled = dict(enabled_lengths)
    selected, ranges = {}, []
    trigger = None
    for item in definitions.ranges:
        if item.flags & 8:
            trigger = item
            ranges.append(item)
            continue
        if item.frame_id not in enabled:
            if item.byte_4d == 1:
                if item.frame_id not in defaults:
                    raise MonitorError("A8 fallback DB206 row absent", 0xC0050101)
                if not defaults[item.frame_id]:
                    raise MonitorError("A8 fallback DB206 length is zero", 0xC0050102)
                enabled[item.frame_id] = defaults[item.frame_id]
            elif item.composite_flags & 1:
                ranges.append(replace(item, runtime_flag=1))
                continue
            else:
                raise MonitorError("A8 selected PID is absent", 0xC0050414)
        selected.setdefault(item.frame_id, enabled[item.frame_id])
        ranges.append(item)
    capabilities = monitor_capabilities(observed_functions)
    packing, attempts = pack_packet_a8(
        tuple(selected.items()),
        enabled,
        pid_definitions,
        cached_frames,
        capabilities=capabilities.mask,
        excluded=excluded,
        maximum_request=maximum_request,
        maximum_reply=maximum_reply,
        trigger=trigger is not None,
    )
    if trigger is not None:
        auxiliary = phase3_auxiliary(
            profile,
            trigger,
            LegacyPacking(
                "P3",
                packing.mode,
                packing.setup_requests,
                packing.frame_sizes,
                packing.pid_layouts,
            ),
        )
        packing = replace(
            packing,
            setup_requests=packing.setup_requests + (auxiliary.request,),
            frame_sizes=packing.frame_sizes + ((auxiliary.frame_id, auxiliary.length),),
            pid_layouts=packing.pid_layouts
            + ((auxiliary.source_frame, auxiliary.frame_id, 0, auxiliary.length),),
        )
    definitions = replace(definitions, ranges=tuple(ranges))
    mapped = {
        pid: (frame, offset, length)
        for pid, frame, offset, length in packing.pid_layouts
    }
    layouts = []
    for item in ranges:
        if item.runtime_flag & 1:
            continue
        if item.frame_id not in mapped:
            raise MonitorError("A8 selected PID has no packed frame", 0x90051004)
        frame, offset, length = mapped[item.frame_id]
        if item.end_bit >= length * 8:
            raise MonitorError("A8 selected bit range exceeds packed PID")
        layouts.append(
            (
                item.signal_id,
                frame,
                item.start_bit + offset * 8,
                item.end_bit + offset * 8,
            )
        )
    full, frames, pickup = monitor_composite_layouts(
        definitions, tuple(ranges), tuple(layouts), packing.frame_sizes
    )
    signals = selected_signal_metadata(profile, full)
    packing = replace(packing, frame_sizes=frames)
    commands = packet_a8_commands(
        packing,
        interface_id=interface_id,
        buffer_468=profile.category,
        standard_values=standard_values,
        attribute_2_23=capabilities.attribute_2_23,
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
    return SelectedPacketA8Monitor(
        definitions,
        packing,
        signals,
        frames,
        commands,
        pickup,
        attempts,
        monitor_source_identity(profile, ""),
        source_build,
    )


def selected_packet_a8_from_exchange(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    exchange: SupportTransaction,
    ecu: str,
    observed_functions: Mapping[int, bool],
    *,
    source_build: int,
    communication_protocol: int,
    interface_id: int,
    excluded: int,
    maximum_request: int,
    maximum_reply: int,
    native_ecu: int,
    packet_cache: PacketFrameCache | None = None,
    standard_values: Sequence[tuple[int, int]] = (),
    support_stream: SupportStream | None = None,
    bus_id: int | None = None,
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> SelectedPacketA8Monitor:
    """Actual CreateEnablePidListExt then lazy A2/04 packet-cache fallback."""
    _guard(profile, communication_protocol, source_build)
    _uint(native_ecu, 0xFFFFFFFF, "ECU")
    cache = MonitorSupportCache(
        profile,
        exchange,
        ecu,
        source_build=source_build,
        stream=support_stream,
        bus_id=bus_id,
        limits=limits,
        cancelled=cancelled,
        clock=clock,
    )
    return selected_packet_a8_from_cache(
        cache,
        selected_ids,
        observed_functions,
        communication_protocol=communication_protocol,
        interface_id=interface_id,
        excluded=excluded,
        max_request=maximum_request,
        max_reply=maximum_reply,
        native_ecu=native_ecu,
        packet_cache=packet_cache,
        standard_values=standard_values,
    )


def selected_packet_a8_from_cache(
    cache: MonitorSupportCache,
    selected_ids: Sequence[int],
    observed_functions: Mapping[int, bool],
    *,
    communication_protocol: int,
    interface_id: int,
    excluded: int,
    max_request: int,
    max_reply: int,
    native_ecu: int,
    packet_cache: PacketFrameCache | None = None,
    standard_values: Sequence[tuple[int, int]] = (),
) -> SelectedPacketA8Monitor:
    """Consume the caller's live cache and existing operation budget unchanged."""
    if not isinstance(cache, MonitorSupportCache):
        raise MonitorError("A8 requires the concrete selected support cache")
    profile, source_build = cache.profile, cache.source_build
    _guard(profile, communication_protocol, source_build)
    _uint(native_ecu, 0xFFFFFFFF, "ECU")
    cache.check_context()
    if native_ecu != profile.category:
        raise MonitorError("A8 packet-cache ECU differs from selected category")
    maximum_request, maximum_reply = max_request, max_reply
    support = cache.enabled_pids(family="ext", kind=1)

    def build(
        frames: Sequence[tuple[int, int]] | None, mask: int = excluded
    ) -> SelectedPacketA8Monitor:
        return selected_packet_a8_monitor(
            profile,
            selected_ids,
            support,
            observed_functions,
            source_build=source_build,
            communication_protocol=communication_protocol,
            interface_id=interface_id,
            excluded=mask,
            maximum_request=maximum_request,
            maximum_reply=maximum_reply,
            cached_frames=frames,
            standard_values=standard_values,
        )

    try:
        result = build(None)
    except MonitorError as error:
        if error.code != 0x90051012 or packet_cache is None:
            raise
        result = None
    needs_cache = result is None or (2, 0x90051012) in result.attempts
    if needs_cache and packet_cache is not None:
        try:
            frames = packet_cache.get_packet_frame(
                native_ecu, communication_protocol, source_identity=cache.identity
            )
        except ToyotaCodecError as error:
            if result is None:
                raise MonitorError(
                    "A8 packet-cache query failed", error.code
                ) from error
            return replace(
                result,
                attempts=tuple(
                    (mode, error.code if mode == 2 else status)
                    for mode, status in result.attempts
                ),
            )
        return build(tuple((frame.sequence, len(frame.payload)) for frame in frames))
    assert result is not None
    return result


class PacketA8Event(PacketMonitorEvent):
    """Distinct PacketDMP4 single ModeA1, CheckModeA2 exact-length semantics."""

    def __init__(
        self,
        descriptor: bytes,
        frame_sizes: tuple[tuple[int, int], ...],
        *,
        pickup_spans: tuple[tuple[int, int], ...] = (),
    ):
        super().__init__(
            1, descriptor, frame_sizes, timeout=3000, pickup_spans=pickup_spans
        )
        self.items = [
            CommItem(b"\xa1\x01" + descriptor, status=7),
            CommItem(b"\xa2\x01", 3000, 9),
        ]

    def check_rcv_frame(self, reply: bytes, tick: int) -> int:
        if not isinstance(reply, bytes) or len(reply) > 4096:
            raise MonitorError("A8 received bytes exceed native storage", INVALID)
        _uint(tick, 0xFFFFFFFF, "tick")
        if not reply or reply[0] != 0xE2:
            return super().check_rcv_frame(reply, tick)
        if len(reply) < 3 or reply[1] not in (1, 6):
            return 0xE0000104
        if (reply[1] == 1 and len(reply) - 2 != self.raw_length) or (
            reply[1] == 6 and len(reply) - 2 < self.raw_length
        ):
            return 0xE0000104
        self.data[: self.raw_length] = reply[2 : 2 + self.raw_length]
        self._write_packet(tick)
        if self.item.status not in (13, 14):
            self.item.status = 12
        return OK

    def _write_packet(self, tick: int) -> None:
        from scripts.data_monitor import pickup_packet

        if self.pickup_spans:
            self.data[:] = pickup_packet(
                bytes(self.data[: self.raw_length]), 0, self.pickup_spans, p4=False
            )
        self._emit(tick)


def selected_packet_a8_worker(
    operations: NativeFrameOperations,
    plan: SelectedPacketA8Monitor,
    connection: SelectedMonitorConnection,
    *,
    clock: Callable[[], float] = time.monotonic,
    cancelled: Callable[[], bool] = lambda: False,
    limits: Limits | None = None,
) -> DirectJ2534Worker:
    """Bind the distinct PacketDMP4 event to actual selected J2534 primitives."""
    _guard(operations.profile, operations.bus_id, operations.native_build)
    if (
        plan.source_build != operations.native_build
        or plan.source_identity != monitor_source_identity(operations.profile, "")
        or connection.source_identity != plan.definitions.source_identity
    ):
        raise MonitorError("A8 runtime source/build identity differs")
    if (
        connection.bus_id != operations.bus_id
        or connection.protocol_record != operations.protocol_record
        or operations.native_variant != "normal"
        or operations.device_kind != 8
    ):
        raise MonitorError("A8 direct runtime requires selected device8 CAN transport")
    if plan.packing.mode != 1:
        raise MonitorError("A8 packet worker requires native ModeA1")
    request = plan.packing.setup_requests[0]
    if operations.bus_id & 15 == 8:
        if not isinstance(operations, ExtendedCanOperations):
            raise MonitorError("A8 low8 requires the native extended CAN lower class")
        expected = lower_frame_plan(
            operations.profile,
            request,
            native_build=12 if plan.source_build == 12 else 18,
            bus_id=operations.bus_id,
            driver=operations.driver,
            device_kind=operations.device_kind,
            interface_word=int(operations.plan.send.protocol_id != 5),
            diagnostic_mode=operations.diagnostic_mode,
        )
    else:
        expected = get_comm_frame(
            operations.profile,
            request,
            bus_id=operations.bus_id,
            driver=operations.driver,
            diagnostic_mode=operations.diagnostic_mode,
        )
    if operations.plan != expected or plan.commands.setup[0].values[:2] != (
        connection.ecu_id,
        connection.address.request_id,
    ):
        raise MonitorError("A8 transport differs from actual selected request")
    budget = limits or Limits()
    return DirectJ2534Worker(
        operations,
        PacketA8Event(
            request[2:],
            plan.frame_sizes,
            pickup_spans=tuple(
                (start & 0xFFFFFFFF, count) for start, count in plan.pickup_spans
            ),
        ),
        request_id=connection.address.request_id,
        response_id=connection.address.response_id,
        default_source=connection.address.response_id,
        full_source=True,
        timeout=budget.seconds,
        max_steps=budget.exchanges,
        clock=clock,
        cancelled=cancelled,
    )


def packet_a8_can_lifecycle(
    plan: SelectedPacketA8Monitor,
    connection: SelectedMonitorConnection,
    *,
    connected_device: int,
    interrupt_send_timing: bool,
    recording: bool = False,
) -> MonitorSetup:
    """P4 CAN101→phase1 DM107→IDMap111/114→selected setup→108/104 cleanup."""
    if (
        type(connected_device) is not int
        or type(recording) is not bool
        or not (connected_device == 4 or connected_device == 8 and recording)
        or type(interrupt_send_timing) is not bool
    ):
        raise MonitorError(
            "A8 DMCI requires device4 or observed device8 recording route"
        )
    if (
        not connection.source_identity
        or connection.source_identity != plan.definitions.source_identity
        or connection.bus_id & 15 not in (2, 8)
    ):
        raise MonitorError("A8 DMCI selected source identity differs")
    if len(connection.protocol_record) != (24 if plan.source_build == 12 else 28):
        raise MonitorError("A8 connection source-build record width differs")
    if (
        connection.can_record is None
        or len(connection.can_record) != 28
        or int.from_bytes(connection.can_record[4:8], "little") != 500000
    ):
        raise MonitorError("A8 native CAN requires selected500000 baud", 0xC0050101)
    if plan.commands.setup[0].values[:2] != (
        connection.ecu_id,
        connection.address.request_id,
    ):
        raise MonitorError("A8 setup target differs from selected connection")
    filters = (
        (0xC6D78800, 0x392877FF)
        if connection.bus_id & 15 == 8
        else (0xE0000000, 0x1FFFFFFF)
    )
    setup = (
        MonitorCommand(0x101, (1, 0x36, *filters, 0xC6, 0x40030, 1, 2, 10)),
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
    if plan.packing.mode == 1 and interrupt_send_timing:
        setup += (MonitorCommand(0x116, (3,)),)
    return MonitorSetup(
        setup + plan.commands.setup,
        plan.commands.start,
        plan.commands.stop + (MonitorCommand(0x108, ()), MonitorCommand(0x104, ())),
    )


def run_packet_a8_dmci(
    plan: SelectedPacketA8Monitor,
    connection: SelectedMonitorConnection,
    client: NativeVimClient,
    *,
    connected_device: int,
    interrupt_send_timing: bool,
    packet_limit: int,
    recording: bool = False,
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
):
    return run_monitor_commands(
        packet_a8_can_lifecycle(
            plan,
            connection,
            connected_device=connected_device,
            interrupt_send_timing=interrupt_send_timing,
            recording=recording,
        ),
        client,
        interface_id=connection.ecu_id,
        frame_sizes=plan.frame_sizes,
        phase=1,
        packet_limit=packet_limit,
        limits=limits,
        cancelled=cancelled,
        clock=clock,
    )
