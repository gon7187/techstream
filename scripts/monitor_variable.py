"""Source-bound original variable-drive monitor command reconstruction.

No OEM code is executed and no device is opened. The normal P4 monitor is not
an implementation of this provider's selected variable-drive command path.
"""

from __future__ import annotations

import hashlib
import math
import struct
import time
from collections.abc import Callable, Generator, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

from scripts.data_monitor import (
    MAX_ITEMS,
    MonitorCommand,
    MonitorDefinitions,
    MonitorError,
    MonitorPacket,
    MonitorSetup,
    MonitorSignalMetadata,
    P4Packing,
    SelectedMonitorConnection,
    dmci_id_map_fields,
    monitor_capabilities,
    monitor_composite_layouts,
    p4_composite_layouts,
    p4_iso_configs,
    p4_monitor_address,
    p4_setup_commands,
    p4_signal_layouts,
    pack_p4,
    run_monitor_commands,
    selected_definitions,
    selected_signal_metadata,
)
from scripts.drive_recorder import (
    DMCI_WIRE_COMMANDS,
    DrsFile,
    NativeCoreBuffer,
    NativeDmciCommand,
    NativeDmciError,
    NativeMonitorBuffer,
    NativeMonitorPacket,
    NativeMonitorPacketReader,
    NativeMonitorReply,
    NativeRecorderCapture,
    NativeTriggerInfo,
    NativeTriggerParameters,
    NativeVehicleSelection,
    NativeVimClient,
    NativeVimReply,
    build_native_drs,
    decode_vim_command,
    native_monitor_buffer,
)
from scripts.monitor_instruments import (
    SelectedInstrumentMonitor,
    VoltageMonitorInterface,
    selected_instrument_monitor,
)
from scripts.monitor_j2534 import ActiveMonitorEvent, MonitorSystemEvent
from scripts.monitor_legacy import LegacyCheckTarget, LegacyPacking, phase3_auxiliary
from scripts.monitor_packet_a8 import (
    PacketA8Packing,
    pack_packet_a8,
    packet_a8_commands,
)
from scripts.monitor_support import MonitorSupportCache, monitor_source_identity
from scripts.profiles import ProtocolProfile, VehicleProfile
from scripts.recorder_buffer import NativeRecorderRing
from scripts.support import word
from scripts.toyota import CommandFrame, ToyotaCodecError, VariableTable
from scripts.toyota_session import Cancelled, Limits

if TYPE_CHECKING:
    from scripts.frame_transport import NativeFrameOperations, NativeMultiMonOperations
    from scripts.monitor_dlc12 import DLC12VoltageObservation, DLC12VoltageState
    from scripts.monitor_support import PacketFrameCache
    from scripts.snapshot import MonitorBuffer


@dataclass(frozen=True)
class VariableMonitorSource:
    """An actual imported module, independently identified from database layout."""

    path: Path | None
    build: int
    sha256: str

    @classmethod
    def for_build(cls, build: int) -> VariableMonitorSource:
        """Explicit application algorithm selection; never inferred from DDB."""
        if type(build) is not int or build not in (12, 18):
            raise MonitorError("Variable monitor requires explicit source build12/18")
        return cls(
            None,
            build,
            {
                12: "340dd411bd94b409bb44b7cb318e83c80aa39ff94e4030c1f1a9a802774ad13b",
                18: "e6f6b82e41f8c2689835a25e13d35fed21b45ea44bfb2f9199edfd8192b759a6",
            }[build],
        )

    @classmethod
    def from_path(cls, path: Path) -> VariableMonitorSource:
        if path.stat().st_size not in (135168, 139264):
            raise MonitorError("Unproven variable monitor module size")
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        builds = {
            "340dd411bd94b409bb44b7cb318e83c80aa39ff94e4030c1f1a9a802774ad13b": 12,
            "e6f6b82e41f8c2689835a25e13d35fed21b45ea44bfb2f9199edfd8192b759a6": 18,
        }
        if digest not in builds:
            raise MonitorError("Unproven variable monitor module source")
        return cls(path.resolve(), builds[digest], digest)

    def check(self) -> None:
        expected = self.for_build(self.build)
        if self.sha256 != expected.sha256:
            raise MonitorError("Variable monitor source build/hash mismatch")
        if self.path is None:
            return
        current = self.from_path(self.path)
        if current != self:
            raise MonitorError("Selected variable monitor module changed")


def _uint(value: int, maximum: int, name: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise MonitorError(f"Invalid variable monitor {name}", 0xC0050001)
    return value


def variable_excluded_mask(
    connected_device: int, *, target_count: int = 1, voltage_targets: int = 0
) -> int:
    """6150/7260 device selection; multi-device4 counts only non-voltage ECUs."""
    _uint(connected_device, 0xFFFFFFFF, "connected device")
    _uint(target_count, 3, "target count")
    _uint(voltage_targets, 3, "voltage target count")
    if not target_count or voltage_targets > target_count:
        raise MonitorError("Variable monitor requires1..3 explicit targets", 0xC0050404)
    if connected_device in (1, 2):
        raise MonitorError("Variable monitor connected device unsupported", 0xC0051301)
    if connected_device == 8:
        return 5
    if connected_device != 4:
        raise MonitorError("Variable monitor connected device unknown", 0xC0051302)
    return 5 if target_count - voltage_targets >= 2 else 0


def variable_target_mask(
    targets: tuple[tuple[int, int], ...],
    *,
    connected_device: int,
    excluded: int = 0,
) -> int:
    """74B0/7631 target bus compatibility and the native low-WORD mask join.

    Each pair is the selected target category and observed bus identifier.
    Voltage category68 is exempt; two low-nibble2 buses may differ in subtype.
    """
    _uint(excluded, 0xFFFFFFFF, "excluded capability mask")
    if not isinstance(targets, tuple) or not 1 <= len(targets) <= 3:
        raise MonitorError("Variable monitor requires1..3 targets", 0xC0050001)
    for target in targets:
        if not isinstance(target, tuple) or len(target) != 2:
            raise MonitorError("Variable monitor target malformed", 0xC0050001)
        _uint(target[0], 65535, "target category")
        _uint(target[1], 65535, "target bus")
    mask = variable_excluded_mask(
        connected_device,
        target_count=len(targets),
        voltage_targets=sum(category == 0x68 for category, _ in targets),
    )
    buses = tuple(bus for category, bus in targets if category != 0x68)
    if buses and any(
        bus != buses[0] and not (bus & 15 == buses[0] & 15 == 2) for bus in buses
    ):
        raise MonitorError("Variable monitor target buses differ", 0xC0050001)
    return mask | (excluded & 65535)


def variable_definitions(
    profile: VehicleProfile, selected_ids: Sequence[int]
) -> MonitorDefinitions:
    """66E0 selected Freeze/MultiPID ranges with native direct-entry validity."""
    definitions = selected_definitions(profile, selected_ids)
    rows = profile.records(10)
    first: dict[int, bytes] = {}
    for row in rows:
        first.setdefault(word(row, 56), row)
    for signal in definitions.selected_ids:
        if not first[signal][78] & 1:
            raise MonitorError(
                "Variable monitor selected Freeze row invalid", 0xC0050102
            )
    return definitions


def pack_variable(
    definitions: MonitorDefinitions,
    support: Mapping[int, bytes],
    *,
    category_flags: int,
    capabilities: int,
    excluded: int,
    max_request: int,
    max_reply: int,
) -> P4Packing:
    """01440/01670/01780 use the common packing after ANY-bit range selection.

    Unlike normal P4,01440 always calls D7D0, even for BYTE77==1. Retain the
    authored descriptor fields while sharing the proven mode/request algorithm.
    """
    translated = replace(
        definitions,
        ranges=tuple(replace(item, byte_4d=0) for item in definitions.ranges),
    )

    packing = pack_p4(
        translated,
        support,
        category_flags=category_flags,
        capabilities=capabilities,
        excluded=excluded,
        max_request=max_request,
        max_reply=max_reply,
    )
    return replace(
        packing,
        ranges=tuple(
            replace(original, runtime_flag=item.runtime_flag)
            for original, item in zip(definitions.ranges, packing.ranges)
        ),
    )


@dataclass(frozen=True)
class SelectedVariableMonitor:
    definitions: MonitorDefinitions
    packing: P4Packing
    signals: tuple[MonitorSignalMetadata, ...]
    frame_sizes: tuple[tuple[int, int], ...]
    commands: MonitorSetup
    pickup_spans: tuple[tuple[int, int], ...]
    source_build: int
    source_identity: tuple[object, ...]


@dataclass(frozen=True)
class SelectedVariablePacketMonitor:
    """2510 flag9 child, independently dispatched from the basic1170 child."""

    definitions: MonitorDefinitions
    packing: PacketA8Packing
    signals: tuple[MonitorSignalMetadata, ...]
    frame_sizes: tuple[tuple[int, int], ...]
    commands: MonitorSetup
    pickup_spans: tuple[tuple[int, int], ...]
    attempts: tuple[tuple[int, int], ...]
    source_identity: tuple[object, ...]
    source_build: int


def selected_variable_packet_monitor(
    cache: MonitorSupportCache,
    selected_ids: Sequence[int],
    observed_functions: Mapping[int, bool],
    *,
    communication_protocol: int,
    interface_id: int,
    excluded: int,
    max_request: int,
    max_reply: int,
    packet_cache: PacketFrameCache | None = None,
    standard_values: Sequence[tuple[int, int]] = (),
    controller_category_flags: int | None = None,
) -> SelectedVariablePacketMonitor:
    """66E0→23B0/2510→CreateEnablePidListExt(kind1), then exact shared codecs.

    Native28D0/2E20/3130/35C0 match the A8 helpers after explicit diagnostic
    relocations (packet-helper-comparison.json). The provider stays distinct.
    """
    if not isinstance(cache, MonitorSupportCache):
        raise MonitorError("Variable packet requires concrete selected cache")
    VariableMonitorSource.for_build(cache.source_build).check()
    profile = cache.profile
    if not isinstance(profile, VehicleProfile):
        raise MonitorError("Variable producer requires selected ECU database")
    flags = (
        profile.category_record[72]
        if controller_category_flags is None
        else _uint(controller_category_flags, 255, "controller category flags")
    )
    if flags & 31 != 9 or profile.category == 0x68:
        raise MonitorError("Variable packet requires selected flag9 child")
    _uint(communication_protocol, 65535, "packet protocol")
    if not communication_protocol or cache.bus_id != communication_protocol:
        raise MonitorError("Variable packet selected bus differs", 0xC0040602)
    definitions = variable_definitions(profile, selected_ids)
    cache.begin_operation()
    definitions, packing, attempts = _variable_packet_packing(
        cache,
        definitions,
        observed_functions,
        excluded=excluded,
        maximum_request=max_request,
        maximum_reply=max_reply,
        cached_frames=None,
        packet_cache=packet_cache,
    )
    mapped = {
        pid: (frame, offset, length)
        for pid, frame, offset, length in packing.pid_layouts
    }
    layouts = []
    for item in definitions.ranges:
        if item.runtime_flag & 1:
            continue
        if item.frame_id not in mapped:
            raise MonitorError("Variable selected PID has no packed frame", 0x90051004)
        frame, offset, length = mapped[item.frame_id]
        if item.end_bit >= length * 8:
            raise MonitorError("Variable selected bit range exceeds packed PID")
        layouts.append(
            (
                item.signal_id,
                frame,
                item.start_bit + offset * 8,
                item.end_bit + offset * 8,
            )
        )
    layouts, frames, pickup = monitor_composite_layouts(
        definitions, definitions.ranges, tuple(layouts), packing.frame_sizes
    )
    signals = selected_signal_metadata(profile, layouts)
    packing = replace(packing, frame_sizes=frames)
    commands = packet_a8_commands(
        packing,
        interface_id=interface_id,
        buffer_468=profile.category,
        standard_values=standard_values,
        attribute_2_23=monitor_capabilities(observed_functions).attribute_2_23,
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
    cache.check_context()
    return SelectedVariablePacketMonitor(
        definitions,
        packing,
        signals,
        frames,
        commands,
        pickup,
        attempts,
        cache.identity,
        cache.source_build,
    )


@dataclass(frozen=True)
class SelectedVariableVoltageMonitor:
    instrument: SelectedInstrumentMonitor
    measurement: VariableMeasurement
    source_build: int
    source_identity: tuple[object, ...]


@dataclass(frozen=True)
class VariableRuntimeTarget:
    plan: (
        SelectedVariableMonitor
        | SelectedVariablePacketMonitor
        | SelectedVariableVoltageMonitor
    )
    cache: MonitorSupportCache
    connection: SelectedMonitorConnection | None
    entry_parameter: int
    buffer: NativeMonitorBuffer

    def check(self) -> None:
        VariableMonitorSource.for_build(self.plan.source_build).check()
        if (
            self.plan.source_identity != self.cache.identity
            or self.plan.source_build != self.cache.source_build
        ):
            raise MonitorError("Variable target selected source changed")
        self.cache.check_context()


def selected_variable_runtime_target(
    plan: SelectedVariableMonitor
    | SelectedVariablePacketMonitor
    | SelectedVariableVoltageMonitor,
    cache: MonitorSupportCache,
    connection: SelectedMonitorConnection | None,
    *,
    measurement: VariableTargetMeasurement,
    diagnostic_mode: bytes | None,
    phase: int,
    name: bytes,
    text_encoding: str,
) -> VariableRuntimeTarget:
    """A8A0/AC20: selected connection, check allocation and native signal buffer."""
    if not isinstance(
        plan,
        (
            SelectedVariableMonitor,
            SelectedVariablePacketMonitor,
            SelectedVariableVoltageMonitor,
        ),
    ) or not isinstance(cache, MonitorSupportCache):
        raise MonitorError("Variable target requires typed selected plan/cache")
    if (
        not isinstance(measurement, VariableTargetMeasurement)
        or measurement.category != cache.profile.category
    ):
        raise MonitorError("Variable target check measurement differs")
    if isinstance(plan, SelectedVariableVoltageMonitor):
        if connection is not None or measurement.mode != 64:
            raise MonitorError("Variable voltage target has communication connection")
        signals, frames, ids = (
            plan.instrument.signals,
            plan.instrument.frame_sizes,
            plan.instrument.selected_ids,
        )
        entry_parameter = 0
    else:
        if not isinstance(connection, SelectedMonitorConnection):
            raise MonitorError("Variable target selected connection absent")
        # Check66E0 uses per-target flags; Run7EC0 uses controller flags.
        # Native Run retains the allocated capacity and recomputes its own mode.
        if (
            connection.ecu_id != cache.profile.category
            or connection.bus_id != cache.bus_id
            or connection.source_identity != plan.definitions.source_identity
        ):
            raise MonitorError("Variable target selected connection source differs")
        if not isinstance(diagnostic_mode, bytes) or len(diagnostic_mode) != 16:
            raise MonitorError("Variable target requires actual diagnostic mode")
        entry_parameter = int.from_bytes(diagnostic_mode[8:12], "little") or word(
            connection.protocol_record, 8
        )
        signals, frames, ids = (
            plan.signals,
            plan.frame_sizes,
            plan.definitions.selected_ids,
        )
    buffer = native_monitor_buffer(
        cache.profile.category,
        signals,
        frames,
        ids,
        phase=phase,
        allocation_size=measurement.measurement.allocation,
        name=name,
        text_encoding=text_encoding,
    )
    target = VariableRuntimeTarget(plan, cache, connection, entry_parameter, buffer)
    target.check()
    return target


def selected_variable_voltage_monitor(
    cache: MonitorSupportCache,
    selected_ids: Sequence[int],
    *,
    voltage_state: DLC12VoltageState,
    voltage_observations: Mapping[int, DLC12VoltageObservation] | None = None,
) -> SelectedVariableVoltageMonitor:
    """66E0→5710/5760 category68, with its exact selected Freeze guard."""
    if not isinstance(cache, MonitorSupportCache) or cache.profile.category != 0x68:
        raise MonitorError("Variable voltage requires selected category68")
    cache.check_context()
    VariableMonitorSource.for_build(cache.source_build).check()
    if not isinstance(cache.profile, VehicleProfile):
        raise MonitorError("Variable voltage producer requires selected ECU database")
    definitions = variable_definitions(cache.profile, selected_ids)
    if len(definitions.ranges) != 1:
        raise MonitorError("Variable voltage requires one native range", 0x90051003)
    instrument = selected_instrument_monitor(
        cache.profile,
        selected_ids,
        voltage_state=voltage_state,
        voltage_observations=voltage_observations,
    )
    cache.check_context()
    return SelectedVariableVoltageMonitor(
        instrument,
        variable_measurement(64, 0, (2,), request_length=5),
        cache.source_build,
        cache.identity,
    )


def variable_voltage_interface(
    source: VariableMonitorSource,
    *,
    limits: Limits | None = None,
    clock: Callable[[], float] = time.monotonic,
    cancelled: Callable[[], bool] = lambda: False,
) -> VoltageMonitorInterface:
    """8610/8899 literal retry, bounded by host policy instead of hanging.

    The imported voltage implementation always reportsFFFFFFFF. That native
    observation is retained; exhaustion is a host budget failure with no invented
    native status or samples.
    """
    if not isinstance(source, VariableMonitorSource):
        raise MonitorError("Variable voltage requires explicit selected source")
    source.check()
    budget = limits or Limits()
    deadline = clock() + budget.seconds
    if not math.isfinite(deadline):
        raise MonitorError("Variable voltage clock must be finite")
    status = 0xFFFFFFFF
    for _ in range(budget.exchanges):
        if cancelled():
            raise Cancelled("Variable voltage allocation cancelled")
        now = clock()
        if not math.isfinite(now):
            raise MonitorError("Variable voltage clock must be finite")
        if now >= deadline:
            raise TimeoutError("Variable voltage allocation host deadline exceeded")
        source.check()
        interface = VoltageMonitorInterface()
        status = _uint(interface.get_error(), 0xFFFFFFFF, "voltage error")
        if status == 0:
            return interface
    raise MonitorError(
        f"Variable voltage allocation host retry budget exceeded; native GetError={status:#010x}"
    )


def selected_variable_monitor_from_cache(
    cache: MonitorSupportCache,
    selected_ids: Sequence[int],
    observed_functions: Mapping[int, bool],
    *,
    communication_protocol: int,
    attribute_3_31: bool,
    interface_id: int,
    excluded: int,
    standard_values: Sequence[tuple[int, int]],
    max_request: int,
    max_reply: int,
    controller_category_flags: int | None = None,
) -> SelectedVariableMonitor:
    """Selected basic variable monitor descriptor→support→packing→DMCI path.

    8A30 calls the shared DataListIF ModeA1/pair setup consumers.01440's support
    distinction is applied by pack_variable before using those common codecs.
    """
    from scripts.signal_lsb import SignalLSB

    if not isinstance(cache, MonitorSupportCache):
        raise MonitorError("Variable monitor requires concrete selected cache")
    profile = cache.profile
    if not isinstance(profile, VehicleProfile):
        raise MonitorError("Variable producer requires selected ECU database")
    flags = (
        profile.category_record[72]
        if controller_category_flags is None
        else _uint(controller_category_flags, 255, "controller category flags")
    )
    if attribute_3_31 is not True or flags & 31 not in (4, 6):
        raise MonitorError("Selected metadata does not route to variable monitor")
    if (
        not profile.category
        or type(communication_protocol) is not int
        or communication_protocol not in (0x12, 0x22, 0x11, 0x51, 0x32, 0x18, 0x38)
        or cache.bus_id != communication_protocol
    ):
        raise MonitorError("Variable1170 selected protocol rejected", 0xC0050001)
    source = VariableMonitorSource.for_build(cache.source_build)
    source.check()
    definitions = variable_definitions(profile, selected_ids)
    capabilities = monitor_capabilities(observed_functions)
    _uint(interface_id, 0xFFFFFFFF, "interface identifier")
    _uint(excluded, 0xFFFFFFFF, "excluded capability mask")
    if any(
        type(value) is not int or not 4 <= value <= 255
        for value in (max_request, max_reply)
    ):
        raise MonitorError(
            "Variable monitor requires bounded byte request/reply limits"
        )
    # Validate fields before support exchange, which is an observable primitive.
    if len(standard_values) > MAX_ITEMS or any(
        not isinstance(pair, tuple)
        or len(pair) != 2
        or any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in pair)
        for pair in standard_values
    ):
        raise MonitorError("Variable monitor standards require bounded DWORD pairs")
    cache.begin_operation()
    packing = pack_variable(
        definitions,
        cache.support_bits(1),
        category_flags=flags,
        capabilities=capabilities.mask,
        excluded=excluded,
        max_request=max_request,
        max_reply=max_reply,
    )
    layouts = p4_signal_layouts(packing)
    frames = tuple((identity >> 8, size) for identity, size in packing.response_frames)
    layouts, frames, pickup = p4_composite_layouts(
        definitions, packing, layouts, frames
    )
    signals = selected_signal_metadata(
        profile,
        layouts,
        lsb_producer=SignalLSB(cache, source_build=12 if source.build == 12 else 18),
    )
    commands = p4_setup_commands(
        packing,
        interface_id=interface_id,
        buffer_468=profile.category,
        total_length=sum(size for _, size in frames),
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
    cache.check_context()
    return SelectedVariableMonitor(
        definitions,
        packing,
        signals,
        frames,
        commands,
        pickup,
        source.build,
        cache.identity,
    )


def variable_dmci_lifecycle(
    plan: SelectedVariableMonitor | SelectedVariablePacketMonitor,
    connection: SelectedMonitorConnection,
    *,
    connected_device: int,
    iso_record: bytes | None = None,
    init_mode: int | None = None,
    parameter_c0: int | None = None,
    recording: bool = False,
) -> MonitorSetup:
    """8610/9390/94F0 constructors and8A30 setup, without P4-only virtuals."""
    if not isinstance(plan, (SelectedVariableMonitor, SelectedVariablePacketMonitor)):
        raise MonitorError("Variable lifecycle requires its selected child")
    if (
        type(connected_device) is not int
        or type(recording) is not bool
        or not (connected_device == 4 or connected_device == 8 and recording)
    ):
        raise MonitorError("Variable DMCI requires device4 or recording device8")
    target_setup = _variable_dmci_target_setup(plan, connection)
    constructor = _variable_dmci_constructor(
        connection,
        iso_record=iso_record,
        init_mode=init_mode,
        parameter_c0=parameter_c0,
    )
    return MonitorSetup(
        constructor + target_setup,
        plan.commands.start,
        plan.commands.stop + (MonitorCommand(0x108, ()), MonitorCommand(0x104, ())),
    )


def _variable_dmci_target_setup(
    plan: SelectedVariableMonitor | SelectedVariablePacketMonitor,
    connection: SelectedMonitorConnection,
) -> tuple[MonitorCommand, ...]:
    """8A30 target IDMap/Mode setup does not construct another interface."""
    mode = (
        plan.packing.mode_mask
        if isinstance(plan, SelectedVariableMonitor)
        else plan.packing.mode
    )
    if mode not in (1, 4, 5, 0x10, 0x20):
        raise MonitorError("Variable child runtime mode rejected", 0xC005100D)
    if (
        not isinstance(connection, SelectedMonitorConnection)
        or connection.source_identity != plan.definitions.source_identity
        or not plan.commands.setup
        or plan.commands.setup[0].values[:2]
        != (connection.ecu_id, connection.address.request_id)
    ):
        raise MonitorError("Variable lifecycle selected connection differs")
    return (_variable_id_map(connection),) + plan.commands.setup


def _variable_dmci_constructor(
    connection: SelectedMonitorConnection,
    *,
    iso_record: bytes | None,
    init_mode: int | None,
    parameter_c0: int | None,
) -> tuple[MonitorCommand, ...]:
    """8610 constructor uses controller management data, without a producer."""
    family = connection.bus_id & 15
    if family == 1:
        if type(init_mode) is not int or init_mode not in (1, 2):
            raise MonitorError(
                "Variable ISO initialization observation absent", 0x90050424
            )
        if iso_record is None or parameter_c0 is None:
            raise MonitorError("Variable ISO selected record/context absent")
        _uint(parameter_c0, 0xFFFFFFFF, "Run commandC0 parameter")
        configs = p4_iso_configs(iso_record, bus_id=connection.bus_id)
        if word(iso_record, 4) != word(connection.protocol_record, 2):
            raise MonitorError("Variable ISO record differs from selected protocol")
        create = MonitorCommand(
            0x100, (b"ComIso32.dll\0", configs, init_mode - 1, 0xC6, parameter_c0, 0)
        )
    elif family in (2, 8):
        if connection.can_record is None or len(connection.can_record) != 28:
            raise MonitorError("Variable CAN selected record absent")
        if int.from_bytes(connection.can_record[4:8], "little") != 500000:
            raise MonitorError("Variable CAN baud unsupported", 0xC0050101)
        filters = (0xC6D78800, 0x392877FF) if family == 8 else (0xE0000000, 0x1FFFFFFF)
        create = MonitorCommand(0x101, (1, 0x36, *filters, 0xC6, 0x40030, 1, 2, 10))
    else:
        raise MonitorError("Variable lifecycle bus unsupported", 0xC0040602)
    return (create, MonitorCommand(0x107, (1,)))


def _variable_id_map(connection: SelectedMonitorConnection) -> MonitorCommand:
    return MonitorCommand(
        0x111,
        dmci_id_map_fields(
            connection.address.request_id,
            connection.address.response_id,
            connection.can_parameter,
            connection.can_byte_0,
            connection.can_byte_1,
        ),
    )


@dataclass(frozen=True)
class VariableNullController:
    """74B0/A8A0 primary absent from selection: mode80, no producer or buffer."""

    profile: ProtocolProfile
    connection: SelectedMonitorConnection
    source_build: int

    @property
    def mode(self) -> int:
        return 0x80

    def check(self) -> None:
        VariableMonitorSource.for_build(self.source_build).check()
        if (
            not isinstance(self.profile, ProtocolProfile)
            or not isinstance(self.connection, SelectedMonitorConnection)
            or self.connection.ecu_id != self.profile.category
            or self.connection.source_identity
            != monitor_source_identity(self.profile, "")
        ):
            raise MonitorError("Variable NULL controller selected context differs")

    def check_targets(self, targets: tuple[VariableRuntimeTarget, ...]) -> None:
        self.check()
        if not targets or len(targets) > 2:
            raise MonitorError(
                "Variable NULL controller exceeds three native slots", 0xC0050001
            )
        for target in targets:
            profile = target.cache.profile
            if (
                profile.category == self.profile.category
                or target.cache.source_build != self.source_build
                or profile.catalog.management.sha256
                != self.profile.catalog.management.sha256
                or profile.vehicle_name_key != self.profile.vehicle_name_key
                or profile.exception_ids != self.profile.exception_ids
            ):
                raise MonitorError(
                    "Variable NULL controller differs from selected targets"
                )


def selected_variable_recording(
    target: VariableRuntimeTarget,
    selection: NativeVehicleSelection,
    system_information: dict,
    trigger: NativeTriggerInfo,
    parameters: NativeTriggerParameters,
    *,
    connected_device: int,
    enable_mode: int,
    iso_record: bytes | None = None,
    init_mode: int | None = None,
    parameter_c0: int | None = None,
) -> DrsFile:
    """87 selected writer path: actual11 setup/start and12 stop/dispose groups.

    The target must already be selected with the caller's complemented enable
    mask. Finalized group serialization equals native WriteStart/WriteEnd length
    patching; device8 recording deliberately uses CAN/ISO DMCI, not live BASE.
    """
    if (
        not isinstance(target, VariableRuntimeTarget)
        or not isinstance(
            target.plan, (SelectedVariableMonitor, SelectedVariablePacketMonitor)
        )
        or target.connection is None
    ):
        raise MonitorError("Variable recording requires selected communication target")
    target.check()
    _uint(enable_mode, 65535, "recording enable mode")
    mode = (
        target.plan.packing.mode_mask
        if isinstance(target.plan, SelectedVariableMonitor)
        else target.plan.packing.mode
    )
    if mode & ~enable_mode:
        raise MonitorError(
            "Variable recording selected child violates enable mask", 0xC005100D
        )
    lifecycle = variable_dmci_lifecycle(
        target.plan,
        target.connection,
        connected_device=connected_device,
        iso_record=iso_record,
        init_mode=init_mode,
        parameter_c0=parameter_c0,
        recording=True,
    )
    result = build_native_drs(
        selection,
        system_information,
        replace(target.buffer, value_after_count=1),
        trigger,
        parameters,
        setup=tuple(
            NativeDmciCommand.from_neutral(item.command_id, item.values)
            for item in lifecycle.setup + lifecycle.start
        ),
        stop=tuple(
            NativeDmciCommand.from_neutral(item.command_id, item.values)
            for item in lifecycle.stop
        ),
    )
    target.check()
    return result


def selected_variable_recording_setup(
    targets: tuple[VariableRuntimeTarget, ...],
    controller_connection: SelectedMonitorConnection,
    *,
    connected_device: int,
    null_controller: VariableNullController | None = None,
    iso_record: bytes | None = None,
    init_mode: int | None = None,
    parameter_c0: int | None = None,
    emit: Callable[[NativeDmciCommand], None] | None = None,
    on_construct: Callable[[], None] | None = None,
) -> tuple[tuple[NativeDmciCommand, ...], tuple[NativeDmciCommand, ...]]:
    """Build one native recording constructor around selected target setup."""
    if not isinstance(targets, tuple) or not 1 <= len(targets) <= 3:
        raise MonitorError("Variable recording requires1..3 selected slots")
    if type(connected_device) is not int or connected_device not in (4, 8):
        raise MonitorError("Variable recording requires observed device4 or8")
    commands: list[NativeDmciCommand] = []

    def append(command: MonitorCommand, *, constructor: bool = False) -> None:
        native = NativeDmciCommand.from_neutral(command.command_id, command.values)
        commands.append(native)
        if constructor and on_construct is not None:
            on_construct()
        if emit is not None:
            emit(native)

    for command in _variable_dmci_constructor(
        controller_connection,
        iso_record=iso_record,
        init_mode=init_mode,
        parameter_c0=parameter_c0,
    ):
        append(command, constructor=command.command_id in (0x100, 0x101))
    if null_controller is not None:
        null_controller.check_targets(targets)
        if null_controller.connection != controller_connection:
            raise MonitorError("Variable recording NULL slot connection differs")
        append(_variable_id_map(controller_connection))
    for target in targets:
        target.check()
        if (
            not isinstance(
                target.plan, (SelectedVariableMonitor, SelectedVariablePacketMonitor)
            )
            or target.connection is None
        ):
            raise MonitorError("Variable recording slot requires communication child")
        for command in _variable_dmci_target_setup(target.plan, target.connection):
            append(command)
    append(MonitorCommand(0x10C, ()))
    return tuple(commands), _variable_recording_stop()


def _variable_recording_stop() -> tuple[NativeDmciCommand, ...]:
    return tuple(
        NativeDmciCommand.from_neutral(command.command_id, command.values)
        for command in (
            MonitorCommand(0x10E, ()),
            MonitorCommand(0x108, ()),
            MonitorCommand(0x104, ()),
        )
    )


class _VariableVimClient(NativeVimClient):
    def dmci(
        self,
        command: NativeDmciCommand,
        *,
        timeout: float = 10,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> bytes:
        try:
            return super().dmci(command, timeout=timeout, cancelled=cancelled)
        except NativeDmciError as error:
            if command.command_id == 0x111:
                # 8A30 calls IDMap without checking its returned status.
                return b""
            status = {
                0x109: 0xA0050425,
                0x10A: 0xA0050425,
                0x112: 0xA0050425,
                0x10C: 0xA0050421,
                # DiagInterface poll thread maps nonzero reply.m_dwResult to
                # callback E0000102; variable5C90 maps that to A1050307.
                0x10D: 0xA1050307,
                0x10E: 0xA0050431,
            }.get(command.command_id)
            if status is None:
                raise
            raise MonitorError(
                "Variable native monitor operation failed", status
            ) from error


def run_variable_dmci(
    plan: SelectedVariableMonitor | SelectedVariablePacketMonitor,
    cache: MonitorSupportCache,
    connection: SelectedMonitorConnection,
    client: NativeVimClient,
    *,
    connected_device: int,
    interrupt_send_timing: bool,
    packet_limit: int,
    iso_record: bytes | None = None,
    init_mode: int | None = None,
    parameter_c0: int | None = None,
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
) -> tuple[MonitorPacket, ...]:
    """8610/8A30 normal ComTol route with exact shared DataListIF consumers.

    Source mutation blocks subsequent work while disposal retains its separate
    bounded budget; an already-created native interface is still cleaned up.
    """
    if (
        not isinstance(plan, (SelectedVariableMonitor, SelectedVariablePacketMonitor))
        or not isinstance(cache, MonitorSupportCache)
        or not isinstance(client, NativeVimClient)
    ):
        raise MonitorError("Variable DMCI run requires typed plan/cache/client")

    def check() -> None:
        if (
            plan.source_identity != cache.identity
            or plan.source_build != cache.source_build
        ):
            raise MonitorError("Variable DMCI plan and selected source differ")
        cache.check_context()

    cache.begin_operation(limits=limits)
    check()
    if type(interrupt_send_timing) is not bool:
        raise MonitorError("Variable interrupt timing observation must be boolean")
    commands = variable_dmci_lifecycle(
        plan,
        connection,
        connected_device=connected_device,
        iso_record=iso_record,
        init_mode=init_mode,
        parameter_c0=parameter_c0,
    )
    cleanup_ids = {DMCI_WIRE_COMMANDS[item.command_id] for item in commands.stop}

    def guarded_exchange(
        request: bytes, *, deadline: float, cancelled: Callable[[], bool]
    ) -> bytes:
        cleanup = decode_vim_command(request)[0] in cleanup_ids
        if not cleanup:
            check()
        response = client.exchange(request, deadline=deadline, cancelled=cancelled)
        if not cleanup:
            check()
            if decode_vim_command(request)[0] == DMCI_WIRE_COMMANDS[0x10D]:
                reply = NativeVimReply.parse(response)
                if (
                    reply.control == 6
                    and reply.command_id == DMCI_WIRE_COMMANDS[0x10D] | 0x80
                ):
                    native = NativeMonitorReply.parse(reply.payload)
                    if native.status == 0:
                        for notification in variable_reply_notifications(
                            native, signal_id=0
                        ):
                            if notification.message in (0x603, 0x608):
                                raise MonitorError(
                                    "Variable monitor native error notification",
                                    notification.wparam,
                                )
        return response

    guarded = _VariableVimClient(
        guarded_exchange, capabilities=client.capabilities, clock=client.clock
    )
    try:
        return run_monitor_commands(
            commands,
            guarded,
            # DiagInterface polling thread requests buffer DWORD+468 (ECU
            # category), independently from the IDMap request address.
            interface_id=cache.profile.category,
            frame_sizes=plan.frame_sizes,
            phase=0,
            packet_limit=packet_limit,
            limits=limits,
            cancelled=cancelled,
            clock=client.clock,
        )
    except MonitorError as error:
        if error.code is None and isinstance(error.__cause__, MonitorError):
            error.code = error.__cause__.code
        raise


def _variable_multi_dmci_steps(
    targets: tuple[VariableRuntimeTarget, ...],
    controller_connection: SelectedMonitorConnection,
    client: NativeVimClient,
    *,
    packet_limits: tuple[int, ...],
    null_controller: VariableNullController | None = None,
    limits: Limits | None = None,
    iso_record: bytes | None = None,
    init_mode: int | None = None,
    parameter_c0: int | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    packet_store: list[list[MonitorPacket]],
    notifications: list[VariableNotification],
    completion_counts: list[int],
) -> Generator[str, None, None]:
    """Device4 one-interface acquisition with category-keyed native buffers.

    The explicit controller connection supplies8610's CAN/ISO constructor;
    per-target IDMap/Mode commands retain their own selected addressing.
    """
    if (
        not isinstance(targets, tuple)
        or not 1 <= len(targets) <= 3
        or any(not isinstance(target, VariableRuntimeTarget) for target in targets)
        or not isinstance(controller_connection, SelectedMonitorConnection)
        or not isinstance(client, NativeVimClient)
    ):
        raise MonitorError(
            "Variable aggregate requires selected targets/controller/client"
        )
    if (
        not isinstance(packet_limits, tuple)
        or len(packet_limits) != len(targets)
        or any(
            type(count) is not int or not 0 < count <= 65535 for count in packet_limits
        )
    ):
        raise MonitorError(
            "Variable aggregate packet limits differ from selected slots"
        )
    budget = limits or Limits()
    if not isinstance(budget, Limits):
        raise MonitorError("Variable aggregate requires typed host limits")
    keys = tuple(target.cache.profile.category for target in targets)
    if len(set(keys)) != len(keys):
        raise MonitorError("Variable aggregate target categories repeat", 0xC0050001)
    if null_controller is not None:
        if not isinstance(null_controller, VariableNullController):
            raise MonitorError("Variable aggregate requires typed NULL controller")
        null_controller.check_targets(targets)
        if null_controller.connection != controller_connection:
            raise MonitorError("Variable NULL controller connection differs")
    elif targets[0].connection != controller_connection:
        raise MonitorError(
            "Variable aggregate requires its nonempty controller slot first"
        )
    excluded = variable_target_mask(
        (
            ((null_controller.profile.category, null_controller.connection.bus_id),)
            if null_controller
            else ()
        )
        + tuple((key, target.cache.bus_id or 0) for key, target in zip(keys, targets)),
        connected_device=4,
    )
    setups = []
    readers = []
    for target, count in zip(targets, packet_limits):
        target.cache.begin_operation(limits=budget)
        target.check()
        if (
            not isinstance(
                target.plan, (SelectedVariableMonitor, SelectedVariablePacketMonitor)
            )
            or target.connection is None
        ):
            raise MonitorError("Variable aggregate requires communication slots")
        mode = (
            target.plan.packing.mode_mask
            if isinstance(target.plan, SelectedVariableMonitor)
            else target.plan.packing.mode
        )
        if mode & excluded:
            raise MonitorError(
                "Variable aggregate child was not selected with native exclusions"
            )
        setups.append(_variable_dmci_target_setup(target.plan, target.connection))
        readers.append(
            NativeMonitorPacketReader(
                target.plan.frame_sizes, phase=target.buffer.phase, max_packets=count
            )
        )
    setup = (
        _variable_dmci_constructor(
            controller_connection,
            iso_record=iso_record,
            init_mode=init_mode,
            parameter_c0=parameter_c0,
        )
        + ((_variable_id_map(controller_connection),) if null_controller else ())
        + tuple(command for item in setups for command in item)
        + (MonitorCommand(0x10C, ()),)
    )
    stop = (
        MonitorCommand(0x10E, ()),
        MonitorCommand(0x108, ()),
        MonitorCommand(0x104, ()),
    )
    native_setup, native_stop = (
        tuple(
            NativeDmciCommand.from_neutral(command.command_id, command.values)
            for command in group
        )
        for group in (setup, stop)
    )
    cleanup_ids = {DMCI_WIRE_COMMANDS[command.command_id] for command in stop}

    def check() -> None:
        if null_controller is not None:
            null_controller.check_targets(targets)
        for target in targets:
            target.check()
        if any(
            target.cache.source_build != targets[0].cache.source_build
            or target.cache.profile.catalog.management.sha256
            != targets[0].cache.profile.catalog.management.sha256
            or target.cache.profile.vehicle_name_key
            != targets[0].cache.profile.vehicle_name_key
            or target.cache.profile.exception_ids
            != targets[0].cache.profile.exception_ids
            for target in targets
        ):
            raise MonitorError("Variable aggregate selected contexts differ")

    def exchange(
        request: bytes, *, deadline: float, cancelled: Callable[[], bool]
    ) -> bytes:
        cleanup = decode_vim_command(request)[0] in cleanup_ids
        if not cleanup:
            check()
        response = client.exchange(request, deadline=deadline, cancelled=cancelled)
        if not cleanup:
            check()
        return response

    check()
    guarded = _VariableVimClient(
        exchange, capabilities=client.capabilities, clock=client.clock
    )
    yield "configured"
    deadline = client.clock() + budget.seconds
    if not math.isfinite(deadline):
        raise MonitorError("Variable aggregate deadline must be finite")
    calls, attempted = 0, False
    packets = packet_store
    primary: BaseException | None = None

    def remaining() -> float:
        nonlocal calls
        if cancelled():
            raise Cancelled("Variable aggregate cancelled")
        left = deadline - client.clock()
        if not math.isfinite(left) or left <= 0:
            raise TimeoutError("Variable aggregate deadline exceeded")
        if calls >= budget.exchanges:
            raise MonitorError("Variable aggregate exchange budget exceeded")
        calls += 1
        check()
        return left

    try:
        for command in native_setup:
            timeout = remaining()
            attempted = True
            guarded.dmci(command, timeout=timeout, cancelled=cancelled)
            yield "setup"
        yield "select"
        while any(len(items) < count for items, count in zip(packets, packet_limits)):
            reply = guarded.get_monitor_data(
                keys, timeout=remaining(), cancelled=cancelled
            )
            seen = set()
            for key, buffer in reply.interfaces.items:
                if (
                    key not in keys
                    or key in seen
                    or not isinstance(buffer, NativeCoreBuffer)
                ):
                    raise MonitorError(
                        "Variable aggregate unexpected or repeated buffer key"
                    )
                seen.add(key)
                index = keys.index(key)
                packets[index].extend(
                    MonitorPacket(item.timestamp_ms, item.payload)
                    for item in readers[index].feed(buffer.data)
                )
            # Native thread copies all data before error callbacks and then
            # invokes NotifyEnd once for each trailing completion observation.
            notices = tuple(variable_reply_notifications(reply, signal_id=0))
            notifications.extend(notices)
            completion_counts[0] += reply.trailing_value
            fatal = next(
                (notice for notice in notices if notice.message in (0x603, 0x608)), None
            )
            if fatal is not None:
                raise MonitorError(
                    "Variable aggregate native error notification", fatal.wparam
                )
            yield "select"
        for reader in readers:
            reader.finish()
        check()
        if cancelled():
            raise Cancelled("Variable aggregate cancelled")
        return
    except GeneratorExit:
        raise
    except BaseException as error:
        primary = error
        raise
    finally:
        if attempted:
            cleanup_errors = []
            for command in native_stop:
                try:
                    guarded.dmci(
                        command, timeout=budget.seconds, cancelled=lambda: False
                    )
                except Exception as cleanup:  # noqa: BLE001 - complete every native disposal command
                    cleanup_errors.append(cleanup)
            if cleanup_errors:
                if primary is not None:
                    for error in cleanup_errors:
                        primary.add_note(
                            f"Variable aggregate cleanup also failed: {error}"
                        )
                else:
                    raise cleanup_errors[0]


class VariableDmciWorker:
    """Cooperative device4 worker; every acquisition step performs one10D."""

    def __init__(
        self,
        targets: tuple[VariableRuntimeTarget, ...],
        controller_connection: SelectedMonitorConnection,
        client: NativeVimClient,
        *,
        packet_limits: tuple[int, ...],
        null_controller: VariableNullController | None = None,
        limits: Limits | None = None,
        iso_record: bytes | None = None,
        init_mode: int | None = None,
        parameter_c0: int | None = None,
        cancelled: Callable[[], bool] = lambda: False,
    ):
        self.targets, self.client = targets, client
        self.limits, self.cancelled = limits or Limits(), cancelled
        self.packets: list[list[MonitorPacket]] = [[] for _ in targets]
        self.notifications: list[VariableNotification] = []
        self._completion_counts = [0]
        self.active: VariableActiveRuntime | None = None
        self.state = "configured"
        self._steps = _variable_multi_dmci_steps(
            targets,
            controller_connection,
            client,
            packet_limits=packet_limits,
            null_controller=null_controller,
            limits=self.limits,
            iso_record=iso_record,
            init_mode=init_mode,
            parameter_c0=parameter_c0,
            cancelled=cancelled,
            packet_store=self.packets,
            notifications=self.notifications,
            completion_counts=self._completion_counts,
        )
        assert next(self._steps) == "configured"

    @property
    def completion_count(self) -> int:
        """Observed60A0 NotifyEnd calls; no Windows handle success is invented."""
        return self._completion_counts[0]

    def start(self) -> int:
        if self.state != "configured":
            raise MonitorError("Variable DMCI worker already started", 0x90050405)
        for target in self.targets:
            target.cache.begin_operation(limits=self.limits)
        self.deadline = self.client.clock() + self.limits.seconds
        try:
            while next(self._steps) != "select":
                pass
            self.state = "select"
            return 0xE0000100
        except BaseException:
            self.state = "fault"
            raise

    def step(self) -> int:
        if self.state != "select":
            raise MonitorError("Variable DMCI worker is not running", 0x90050405)
        try:
            next(self._steps)
        except StopIteration:
            self.state = "stopped"
        except BaseException as error:
            self.state = "fault"
            if isinstance(error, MonitorError) and error.code is not None:
                notice = VariableNotification(0x603, error.code)
                if not any(
                    item.message in (0x603, 0x608) and item.wparam == error.code
                    for item in self.notifications
                ):
                    self.notifications.append(notice)
            raise
        return 0xE0000100

    def _submit(
        self,
        command: int,
        operation: VariableActiveOperation | VariableSystemOperation | None,
        *,
        initialize: bool = False,
    ) -> None:
        if self.state != "select":
            raise MonitorError(
                "Variable DMCI command requires running state", 0x90050405
            )
        for target in self.targets:
            target.check()
        timeout = self.deadline - self.client.clock()
        if not math.isfinite(timeout) or timeout <= 0:
            raise TimeoutError("Variable DMCI command deadline exceeded")
        if command == 12:
            if self.active is not None:
                self.active.stop(initialize=initialize, timeout=timeout)
        elif isinstance(operation, VariableActiveOperation) and command == 11:
            active = VariableActiveRuntime(operation, self.client)
            active.start(timeout=timeout, cancelled=self.cancelled)
            self.active = active
        elif isinstance(operation, VariableSystemOperation) and command == 96:
            operation.send(self.client, timeout=timeout, cancelled=self.cancelled)
        else:
            raise MonitorError("Variable DMCI selected command absent", 0xC0050001)

    def stop(self) -> int:
        try:
            self._steps.close()
        finally:
            self.state = "stopped"
        return 0xE0000100

    def close(self) -> int:
        self.stop()
        self.state = "closed"
        return 0

    def run(self) -> tuple[tuple[MonitorPacket, ...], ...]:
        primary: BaseException | None = None
        try:
            self.start()
            while self.state == "select":
                self.step()
            return tuple(tuple(items) for items in self.packets)
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                self.close()
            except BaseException as cleanup:
                if primary is None:
                    raise
                primary.add_note(f"Variable DMCI cleanup also failed: {cleanup}")


def run_variable_multi_dmci(
    targets: tuple[VariableRuntimeTarget, ...],
    controller_connection: SelectedMonitorConnection,
    client: NativeVimClient,
    *,
    packet_limits: tuple[int, ...],
    limits: Limits | None = None,
    iso_record: bytes | None = None,
    init_mode: int | None = None,
    parameter_c0: int | None = None,
    cancelled: Callable[[], bool] = lambda: False,
) -> tuple[tuple[MonitorPacket, ...], ...]:
    return VariableDmciWorker(
        targets,
        controller_connection,
        client,
        packet_limits=packet_limits,
        limits=limits,
        iso_record=iso_record,
        init_mode=init_mode,
        parameter_c0=parameter_c0,
        cancelled=cancelled,
    ).run()


@dataclass
class VariableCommandResult:
    """One cooperative host command, retaining its exact failure object."""

    command: int
    completed: bool = False
    status: int | None = None
    error: BaseException | None = None


class VariableMonitorRuntime:
    """Selected8610 device4/8 composition and native allocated buffer faults.

    Windows thread/event handles use explicit bounded cooperative scheduling.
    The concrete ComTol, BASE and MultiMon workers own their lower stop/disposal.
    """

    def __init__(
        self,
        targets: tuple[VariableRuntimeTarget, ...],
        operations: NativeFrameOperations | NativeMultiMonOperations | NativeVimClient,
        *,
        connected_device: int = 8,
        controller_connection: SelectedMonitorConnection | None = None,
        null_controller: VariableNullController | None = None,
        iso_record: bytes | None = None,
        init_mode: int | None = None,
        parameter_c0: int | None = None,
        active: VariableActiveOperation | None = None,
        system: VariableSystemOperation | None = None,
        limits: Limits | None = None,
        clock: Callable[[], float] = time.monotonic,
        ticks: Callable[[], int] | None = None,
        cancelled: Callable[[], bool] = lambda: False,
    ):
        from scripts.frame_transport import (
            NativeFrameOperations,
            NativeMultiMonOperations,
        )
        from scripts.monitor_poll import (
            MultiMonitorPollingWorker,
            selected_variable_single_worker,
        )

        if not isinstance(targets, tuple) or not 1 <= len(targets) <= 3:
            raise MonitorError(
                "Variable runtime requires1..3 selected slots", 0xC0050001
            )
        if any(not isinstance(target, VariableRuntimeTarget) for target in targets):
            raise MonitorError("Variable runtime requires typed selected slots")
        if null_controller is not None:
            if not isinstance(null_controller, VariableNullController):
                raise MonitorError("Variable runtime requires typed NULL controller")
            null_controller.check_targets(targets)
            if controller_connection != null_controller.connection:
                raise MonitorError(
                    "Variable runtime NULL controller connection differs"
                )
        self.null_controller = null_controller
        self.native_slot_categories = (
            (null_controller.profile.category,) if null_controller else ()
        ) + tuple(target.cache.profile.category for target in targets)
        self.targets = targets
        self.state = "new"
        self.faults = [0] * len(targets)
        self.notifications: list[VariableNotification] = []
        self.captures: tuple[NativeRecorderCapture, ...] = ()
        self.command_results: list[VariableCommandResult] = []
        self._pending: list[
            tuple[
                VariableCommandResult,
                VariableActiveOperation | VariableSystemOperation | None,
                bool,
            ]
        ] = []
        rings = []
        for target in targets:
            packet_size = NativeMonitorPacketReader(
                target.plan.instrument.frame_sizes
                if isinstance(target.plan, SelectedVariableVoltageMonitor)
                else target.plan.frame_sizes,
                phase=target.buffer.phase,
            ).packet_size
            if (
                target.buffer.allocation_size
                < packet_size * target.buffer.block_packets
            ):
                raise MonitorError(
                    "Variable native packet allocation failed", 0xA005060E
                )
            rings.append(
                NativeRecorderRing(
                    target.buffer.allocation_size,
                    packet_size,
                    target.buffer.block_packets,
                    phase=target.buffer.phase,
                )
            )
        self.rings = tuple(rings)
        self.worker = None
        self._check()
        variable_target_mask(
            (
                ((null_controller.profile.category, null_controller.connection.bus_id),)
                if null_controller
                else ()
            )
            + tuple(
                (target.cache.profile.category, target.cache.bus_id or 0)
                for target in targets
            ),
            connected_device=connected_device,
        )
        if len({target.cache.profile.category for target in targets}) != len(targets):
            raise MonitorError("Variable runtime target categories repeat", 0xC0050001)
        if any(
            target.cache.source_build != targets[0].cache.source_build
            or target.cache.profile.catalog.management.sha256
            != targets[0].cache.profile.catalog.management.sha256
            or target.cache.profile.vehicle_name_key
            != targets[0].cache.profile.vehicle_name_key
            or target.cache.profile.exception_ids
            != targets[0].cache.profile.exception_ids
            for target in targets
        ):
            raise MonitorError("Variable runtime selected contexts differ")
        if limits is None:
            limits = Limits()
        if not isinstance(limits, Limits):
            raise MonitorError("Variable runtime requires typed host limits")
        if active is not None:
            if not isinstance(active, VariableActiveOperation):
                raise MonitorError(
                    "Variable runtime requires its selected active operation"
                )
            if active.profile.category != targets[0].cache.profile.category:
                raise MonitorError("Variable runtime active target differs")
            event = active.event()
        else:
            event = None
        self.active = active
        if system is not None:
            if not isinstance(system, VariableSystemOperation):
                raise MonitorError(
                    "Variable runtime requires its selected system operation"
                )
            if system.profile.category != targets[0].cache.profile.category:
                raise MonitorError("Variable runtime system target differs")
            modes = tuple(
                target.plan.packing.mode_mask
                if isinstance(target.plan, SelectedVariableMonitor)
                else target.plan.packing.mode
                for target in targets
                if not isinstance(target.plan, SelectedVariableVoltageMonitor)
            )
            if any(mode & 7 for mode in modes):
                raise MonitorError(
                    "Variable system requires non-packet running mode", 0xC005100D
                )
            system_event = system.event()
        else:
            system_event = None
        self.system = system
        self.clock, self.cancelled, self.limits = clock, cancelled, limits
        non_voltage = tuple(
            target for target in targets if target.cache.profile.category != 0x68
        )
        if isinstance(operations, NativeVimClient):
            if connected_device != 4 or controller_connection is None:
                raise MonitorError(
                    "Variable DMCI runtime requires observed device4 and selected controller connection"
                )
            self.worker = VariableDmciWorker(
                non_voltage,
                controller_connection,
                operations,
                packet_limits=(65535,) * len(non_voltage),
                null_controller=null_controller,
                limits=limits,
                iso_record=iso_record,
                init_mode=init_mode,
                parameter_c0=parameter_c0,
                cancelled=cancelled,
            )
        elif connected_device != 8:
            raise MonitorError("Variable J2534 runtime requires observed device8")
        elif null_controller is not None:
            if len(non_voltage) >= 2:
                raise MonitorError(
                    "Native NULL controller exceeds MultiMon entry map", 0xA0050425
                )
            raise MonitorError(
                "Native NULL MultiMon controller has no entry event", 0xE0000102
            )
        elif len(non_voltage) == 1 and len(targets) == 1:
            if (
                not isinstance(operations, NativeFrameOperations)
                or operations.device_kind != 8
            ):
                raise MonitorError(
                    "Variable single target requires concrete frame operations"
                )
            self.worker = selected_variable_single_worker(
                operations,
                non_voltage[0],
                active=event,
                system=system_event,
                timeout=limits.seconds,
                max_steps=limits.exchanges,
                clock=clock,
                ticks=ticks,
                cancelled=cancelled,
            )
        elif 1 <= len(non_voltage) <= 2 and len(targets) >= 2:
            if not isinstance(operations, NativeMultiMonOperations):
                raise MonitorError(
                    "Variable multi target requires concrete MultiMon operations"
                )
            self.worker = MultiMonitorPollingWorker(
                operations,
                non_voltage,
                active=event,
                system=system_event,
                timeout=limits.seconds,
                max_steps=limits.exchanges,
                clock=clock,
                ticks=ticks,
                cancelled=cancelled,
            )
        elif non_voltage:
            raise MonitorError(
                "Native MultiMon accepts at most two communication slots", 0xC0050001
            )

    def _check(self) -> None:
        if self.null_controller is not None:
            self.null_controller.check_targets(self.targets)
        for target in self.targets:
            target.check()
        if getattr(self, "active", None) is not None:
            assert self.active is not None
            _ = self.active.command
        if getattr(self, "system", None) is not None:
            assert self.system is not None
            _ = self.system.command

    def mark_fault(self, status: int) -> None:
        """CAA0 marks every allocated slot; host exceptions never become DWORDs."""
        _uint(status, 0xFFFFFFFF, "buffer fault")
        if not status:
            raise MonitorError("Variable native buffer fault is zero", 0xC0050001)
        self.faults[:] = [status] * len(self.targets)

    def get_fault(self, index: int = 3) -> int:
        """CB00:0..2 selects a slot; larger indexes select the first marked slot."""
        _uint(index, 0xFFFFFFFF, "buffer index")
        if index < 3:
            if self.null_controller is not None:
                if index == 0:
                    return 0
                index -= 1
            return self.faults[index] if index < len(self.faults) else 0
        return next((status for status in self.faults if status), 0)

    def start(self) -> None:
        """9900 host adaptation: explicitly start the concrete selected worker."""
        if self.state != "new":
            raise MonitorError("Variable runtime already started", 0x90050405)
        for target in self.targets:
            target.cache.begin_operation(limits=self.limits)
        self._check()
        self.state = "running"
        try:
            self._start_voltage()
            if self.worker is None:
                raise MonitorError("Variable runtime has no communication worker")
            status = self.worker.start()
            if status != 0xE0000100:
                raise MonitorError("Variable runtime start failed", status)
            if isinstance(self.worker, VariableDmciWorker):
                if self.active is not None:
                    self._service_command(11, self.active, False)
                if self.system is not None:
                    self._service_command(96, self.system, False)
        except BaseException as primary:
            self.state = "fault"
            try:
                self.close()
            except BaseException as cleanup:  # noqa: BLE001 - retain the primary failure
                primary.add_note(f"Variable cleanup also failed: {cleanup}")
            self.state = "fault"
            raise

    def _start_voltage(self) -> None:
        for target in self.targets:
            if target.cache.profile.category != 0x68:
                continue
            interface = variable_voltage_interface(
                VariableMonitorSource.for_build(target.plan.source_build),
                limits=self.limits,
                clock=self.clock,
                cancelled=self.cancelled,
            )
            assert isinstance(target.plan, SelectedVariableVoltageMonitor)
            descriptor = target.plan.instrument.descriptors[0]
            if not interface.setup(
                int.from_bytes(descriptor[:4], "little"), descriptor[4], target.buffer
            ):
                raise MonitorError("Variable native voltage setup failed", 0x90051205)
            if not interface.start():
                raise MonitorError("Variable native voltage start failed", 0x90051201)
            raise MonitorError(
                "Imported voltage interface exposes no acquisition primitive"
            )

    def enqueue(
        self,
        command: int,
        operation: VariableActiveOperation | VariableSystemOperation | None = None,
        *,
        initialize: bool = False,
    ) -> VariableCommandResult:
        """9C70 commands11/12/96, serviced between concrete worker exchanges.

        This bounded cooperative policy replaces Windows event/thread scheduling;
        it does not claim concurrent native handle or thread equivalence.
        """
        if len(self.command_results) >= self.limits.exchanges:
            raise MonitorError("Variable host command result budget exceeded")
        result = VariableCommandResult(command)
        self.command_results.append(result)
        if self.state != "running" or command not in (11, 12, 96):
            result.error = MonitorError(
                "Variable command requires running state", 0x90050405
            )
            result.status, result.completed = 0x90050405, True
        elif len(self._pending) >= self.limits.exchanges:
            result.error = MonitorError("Variable host command queue exceeds budget")
            result.completed = True
        else:
            self._pending.append((result, operation, initialize))
        return result

    def _service_command(
        self,
        command: int,
        operation: VariableActiveOperation | VariableSystemOperation | None,
        initialize: bool,
    ) -> None:
        from scripts.monitor_poll import MultiMonitorPollingWorker

        assert self.worker is not None
        if command == 12:
            if operation is not None or type(initialize) is not bool:
                raise MonitorError(
                    "Variable active stop arguments malformed", 0xC0050001
                )
            if isinstance(self.worker, VariableDmciWorker):
                self.worker._submit(12, None, initialize=initialize)
            else:
                active = (
                    self.worker.active
                    if isinstance(self.worker, MultiMonitorPollingWorker)
                    else self.worker.events[0]
                )
                if active is not None:
                    assert isinstance(active, ActiveMonitorEvent)
                    active.stop(initialize=initialize)
            return
        expected = VariableActiveOperation if command == 11 else VariableSystemOperation
        if not isinstance(operation, expected):
            raise MonitorError("Variable command selected arguments absent", 0xC0050001)
        if operation.profile.category != self.targets[0].cache.profile.category:
            raise MonitorError("Variable command target differs", 0xC0050001)
        _ = operation.command
        if (
            operation.source.build != self.targets[0].cache.source_build
            or operation.source_identity
            != monitor_source_identity(self.targets[0].cache.profile, "")[1:]
        ):
            raise MonitorError("Variable command selected context differs")
        connection = self.targets[0].connection
        if (
            connection is None
            or operation.request_identity != connection.address.request_id
        ):
            raise MonitorError("Variable command requires its concrete lower target")
        if isinstance(operation, VariableSystemOperation):
            for target in self.targets:
                plan = target.plan
                if isinstance(plan, SelectedVariableVoltageMonitor):
                    continue
                mode = (
                    plan.packing.mode_mask
                    if isinstance(plan, SelectedVariableMonitor)
                    else plan.packing.mode
                )
                if mode & 7:
                    raise MonitorError(
                        "Variable system requires non-packet running mode", 0xC005100D
                    )
        if isinstance(self.worker, VariableDmciWorker):
            self.worker._submit(command, operation)
        elif isinstance(operation, VariableActiveOperation):
            active = (
                self.worker.active
                if isinstance(self.worker, MultiMonitorPollingWorker)
                else self.worker.events[0]
            )
            if active is None:
                event = operation.event()
                if isinstance(self.worker, MultiMonitorPollingWorker):
                    self.worker.active = event
                else:
                    self.worker.events = (
                        event,
                        self.worker.events[1],
                        self.worker.events[2],
                    )
            else:
                assert isinstance(active, ActiveMonitorEvent)
                active.append(operation.request[1:], operation.repeat)
        else:
            event = operation.event()
            if isinstance(self.worker, MultiMonitorPollingWorker):
                self.worker.system = event
            else:
                self.worker.events = (
                    self.worker.events[0],
                    event,
                    self.worker.events[2],
                )
        if isinstance(operation, VariableActiveOperation):
            self.active = operation
        else:
            self.system = operation

    def step(self) -> None:
        """Advance acquisition; command failures remain attached to their result."""
        if self.state != "running" or self.worker is None:
            raise MonitorError("Variable runtime is not running", 0x90050405)
        try:
            self._check()
            if self.worker.state == "select" and self._pending:
                result, operation, initialize = self._pending.pop(0)
                try:
                    self._service_command(result.command, operation, initialize)
                    result.status = 0
                except Exception as error:  # noqa: BLE001 - completion retains exact command failure
                    result.error = error
                    result.status = getattr(error, "code", None)
                result.completed = True
            status = self.worker.step()
            if status != 0xE0000100:
                raise MonitorError("Variable runtime acquisition failed", status)
        except BaseException as primary:
            self._record_faults()
            try:
                self.stop()
            except BaseException as cleanup:  # noqa: BLE001 - retain the primary failure
                primary.add_note(f"Variable stop also failed: {cleanup}")
            self.state = "fault"
            raise

    def stop(self) -> tuple[NativeRecorderCapture, ...]:
        """9A30: stop then dispose independently of cancellation/source mutation."""
        from scripts.monitor_poll import MultiMonitorPollingWorker

        if self.state != "running":
            return self.captures
        assert self.worker is not None
        primary: BaseException | None = None
        previous = (
            None
            if isinstance(self.worker, VariableDmciWorker)
            else self.worker.operations.cancelled
        )
        try:
            if not isinstance(self.worker, VariableDmciWorker):
                self.worker.operations.cancelled = lambda: False
            if not isinstance(
                self.worker, (MultiMonitorPollingWorker, VariableDmciWorker)
            ):
                self.worker.cleanup_mode, self.worker.cleanup_steps = True, 0
            status = self.worker.stop()
            if status != 0xE0000100:
                raise MonitorError("Variable runtime stop failed", status)
            packets = (
                self.worker.packets
                if isinstance(
                    self.worker, (MultiMonitorPollingWorker, VariableDmciWorker)
                )
                else [self.worker.packets]
            )
            self._retain(
                tuple(
                    NativeRecorderCapture(
                        0,
                        tuple(
                            NativeMonitorPacket(
                                item.timestamp_raw
                                if isinstance(item, MonitorPacket)
                                else item.timestamp_ms,
                                item.payload,
                            )
                            for item in items
                        ),
                    )
                    for items in packets
                )
            )
        except BaseException as error:
            primary = error
            raise
        finally:
            if not isinstance(
                self.worker, (MultiMonitorPollingWorker, VariableDmciWorker)
            ):
                self.worker.cleanup_mode = False
            if not isinstance(self.worker, VariableDmciWorker):
                assert previous is not None
                self.worker.operations.cancelled = previous
            self.state = "stopping"
            try:
                self.close()
            except BaseException as cleanup:  # noqa: BLE001 - complete cleanup and retain exact failure
                if primary is None:
                    primary = cleanup
                else:
                    primary.add_note(f"Variable close also failed: {cleanup}")
            self.state = "fault" if primary else "stopped"
            for result, _, _ in self._pending:
                result.error = MonitorError(
                    "Variable command stopped before service", 0x90050405
                )
                result.status, result.completed = 0x90050405, True
            self._pending.clear()
            if primary is not None:
                raise primary
        return self.captures

    def _retain(self, captures: tuple[NativeRecorderCapture, ...]) -> None:
        retained = []
        for capture, ring in zip(captures, self.rings):
            for packet in capture.packets:
                ring.append(packet.timestamp_ms, packet.payload)
            ring.set_record_area(ring.start, ring.active_size)
            retained.append(
                NativeRecorderCapture(
                    capture.trigger_timestamp_ms,
                    tuple(
                        NativeMonitorPacket(int.from_bytes(raw[:4], "little"), raw[4:])
                        for raw in ring.packets()
                    ),
                    (ring.serialize(0), ring.serialize(1)),
                )
            )
        self.captures = tuple(retained)

    def run(self, counts: tuple[int, ...]) -> tuple[NativeRecorderCapture, ...]:
        from scripts.monitor_poll import MultiMonitorPollingWorker

        if self.state != "new":
            raise MonitorError("Variable runtime already started", 0x90050405)
        if (
            not isinstance(counts, tuple)
            or len(counts) != len(self.targets)
            or any(type(count) is not int or not 0 < count <= 65535 for count in counts)
        ):
            raise MonitorError(
                "Variable runtime capture counts differ from selected slots"
            )
        if isinstance(self.worker, VariableDmciWorker):
            self.start()
            try:
                while any(
                    len(items) < count
                    for items, count in zip(self.worker.packets, counts)
                ):
                    self.step()
                return self.stop()
            except BaseException as primary:
                try:
                    self.stop()
                except BaseException as cleanup:  # noqa: BLE001 - preserve primary failure
                    primary.add_note(f"Variable DMCI stop also failed: {cleanup}")
                self.state = "fault"
                raise
        for target in self.targets:
            target.cache.begin_operation(limits=self.limits)
        self._check()
        self.state = "running"
        try:
            self._start_voltage()
            if self.worker is None:
                raise MonitorError("Variable runtime has no communication worker")
            if isinstance(self.worker, MultiMonitorPollingWorker):
                captures = self.worker.run(counts)
            else:
                captures = (self.worker.run(counts[0]),)
            self._check()
            self._retain(captures)
            self.state = "stopped"
            return self.captures
        except BaseException:
            self.state = "fault"
            self._record_faults()
            raise

    def _record_faults(self) -> None:
        if self.worker is None:
            return
        for notice in self.worker.notifications:
            mapped = (
                notice
                if isinstance(notice, VariableNotification)
                else variable_error_notification(
                    notice.request_id,
                    notice.code,
                    notice.parameter,
                    signal_id=self.active.signal_id if self.active else 0,
                )
            )
            if mapped is not None:
                self.notifications.append(mapped)
                if mapped.message in (0x603, 0x608):
                    self.mark_fault(mapped.wparam)

    def close(self) -> None:
        """9A30 disposal remains callable after source mutation or host failure."""
        if self.state == "running":
            self.stop()
            self.state = "closed"
            return
        if self.worker is not None:
            status = self.worker.close()
            if status:
                self.state = "fault"
                raise MonitorError("Variable runtime close failed", status)
        self.state = "closed"

    def dm_bytes(
        self, index: int, metadata: MonitorBuffer, system_information: dict
    ) -> bytes:
        """Export the actual selected slot's native capture and allocated buffer."""
        self._check()
        _uint(index, 2, "export slot")
        if index >= len(self.captures):
            raise MonitorError("Variable runtime slot has no acquired capture")
        target, capture = self.targets[index], self.captures[index]
        return capture.dm_bytes(
            target.buffer,
            metadata,
            system_information,
            phase=target.buffer.phase,
            block_packets=target.buffer.block_packets,
        )


@dataclass(frozen=True)
class VariableMeasurement:
    cycle: int
    packet_size: int
    allocation: int = 0


@dataclass(frozen=True)
class VariableTargetMeasurement:
    category: int
    mode: int
    measurement: VariableMeasurement


@dataclass(frozen=True)
class VariableCheckResult:
    available: bool
    measurements: tuple[VariableTargetMeasurement, ...]
    excluded: int


def check_variable_monitor(
    targets: tuple[LegacyCheckTarget, ...] | None,
    *,
    command_kind: int,
    allocation: int,
    connected_device: int,
    command_ecu: int,
    limits: Limits | None = None,
    clock: Callable[[], float] = time.monotonic,
    cancelled: Callable[[], bool] = lambda: False,
) -> VariableCheckResult:
    """Export CEE0→6150: actual selected single7/multi42 check and CF40 join.

    The shared target is supplied by selected_legacy_check_target's concrete
    NativeCommunication binder. Runtime74B0 bus compatibility is deliberately
    absent here: the native check measures each target independently.
    """
    if targets is None:
        raise MonitorError("Variable CheckStart request absent", 0xC0050401)
    if (
        not isinstance(targets, tuple)
        or not 1 <= len(targets) <= 3
        or type(command_kind) is not int
        or command_kind not in (7, 0x42)
        or command_kind == 7
        and len(targets) != 1
        or any(
            not isinstance(target, LegacyCheckTarget) or not target.selected_ids
            for target in targets
        )
    ):
        raise MonitorError("Variable CheckStart command/targets rejected", 0xC0050404)
    _uint(command_ecu, 0xFFFFFFFF, "check ECU")
    _uint(allocation, 0xFFFFFFFF, "check allocation")
    if not allocation:
        raise MonitorError("Variable check allocation zero", 0xC0050001)
    if command_kind == 7 and command_ecu != targets[0].profile.category:
        raise MonitorError("Variable single check ECU differs from selection")
    first = targets[0]
    for target in targets:
        VariableMonitorSource.for_build(target.source_build).check()
        if (
            target.source_build != first.source_build
            or target.profile.catalog.management.sha256
            != first.profile.catalog.management.sha256
            or target.profile.vehicle_name_key != first.profile.vehicle_name_key
            or target.profile.exception_ids != first.profile.exception_ids
        ):
            raise MonitorError(
                "Variable check targets differ in selected vehicle/source"
            )
    excluded = variable_excluded_mask(
        connected_device,
        target_count=len(targets),
        voltage_targets=sum(target.profile.category == 0x68 for target in targets),
    )
    budget = limits or Limits()
    started = clock()
    deadline = started + budget.seconds
    if not math.isfinite(started) or not math.isfinite(deadline):
        raise MonitorError("Variable check clock must be finite")
    last, calls = started, 0

    def guard() -> float:
        nonlocal last
        if cancelled():
            raise Cancelled("Variable check cancelled")
        now = clock()
        if not math.isfinite(now) or now < last:
            raise MonitorError("Variable check clock must be finite/monotonic")
        if now >= deadline:
            raise TimeoutError("Variable check host deadline exhausted")
        last = now
        return now

    def consume() -> None:
        nonlocal calls
        guard()
        if calls >= budget.exchanges:
            raise MonitorError("Variable check host primitive budget exhausted")
        calls += 1

    class BoundedStream:
        def __init__(self, stream):
            self.stream = stream

        def send(self, query):
            consume()
            result = self.stream.send(query)
            guard()
            return result

        def receive(self, query):
            consume()
            result = self.stream.receive(query)
            guard()
            return result

    measurements = []
    for target in targets:
        now = guard()

        def transaction(query, transaction=target.transaction):
            consume()
            result = transaction(query)
            guard()
            return result

        cache = MonitorSupportCache(
            target.profile,
            transaction,
            target.ecu,
            bus_id=target.bus_id,
            source_build=target.source_build,
            stream=BoundedStream(target.support_stream)
            if target.support_stream is not None
            else None,
            limits=Limits(
                seconds=deadline - now, exchanges=max(1, budget.exchanges - calls)
            ),
            cancelled=cancelled,
            clock=guard,
        )
        measurements.append(
            check_variable_target_from_cache(
                cache,
                target.selected_ids,
                target.observed_functions,
                excluded=excluded,
                packet_cache=target.packet_cache,
            )
        )
    allocated = allocate_variable_measurements(
        allocation, tuple(item.measurement for item in measurements)
    )
    guard()
    return VariableCheckResult(
        True,
        tuple(
            replace(item, measurement=value)
            for item, value in zip(measurements, allocated)
        ),
        excluded,
    )


def _variable_packet_packing(
    cache: MonitorSupportCache,
    definitions: MonitorDefinitions,
    observed_functions: Mapping[int, bool],
    *,
    excluded: int,
    maximum_request: int,
    maximum_reply: int,
    cached_frames: Sequence[tuple[int, int]] | None,
    packet_cache: PacketFrameCache | None,
) -> tuple[MonitorDefinitions, PacketA8Packing, tuple[tuple[int, int], ...]]:
    """Native2510 selected ranges and proven28D0/2E20/3130 pure codecs."""
    profile = cache.profile
    if not isinstance(profile, VehicleProfile):
        raise MonitorError("Variable producer requires selected ECU database")
    bus = cache.bus_id
    if bus is None or bus == 0:
        raise MonitorError("Variable packet selected bus unavailable", 0xC0040602)
    capabilities = monitor_capabilities(observed_functions)
    enabled = cache.enabled_pids(family="ext", kind=1)
    rows = profile.records(6)
    if len(rows) > MAX_ITEMS or any(len(row) != 8 for row in rows):
        raise MonitorError("Variable packet DB206 malformed", 0xC0050101)
    pid_definitions, defaults = {}, {}
    for row in rows:
        pid_definitions.setdefault(row[2], (bool(row[4]), row[5]))
        defaults.setdefault(row[2], row[3])
    selected_lengths, ranges = {}, []
    trigger = None
    for item in definitions.ranges:
        if item.flags & 8:
            trigger = item
            ranges.append(item)
            continue
        if item.frame_id not in enabled:
            if item.byte_4d == 1:
                if item.frame_id not in defaults:
                    raise MonitorError("Variable fallback PID absent", 0xC0050101)
                if not defaults[item.frame_id]:
                    raise MonitorError("Variable fallback length zero", 0xC0050102)
                enabled[item.frame_id] = defaults[item.frame_id]
            elif item.composite_flags & 1:
                ranges.append(replace(item, runtime_flag=1))
                continue
            else:
                raise MonitorError("Variable selected PID unsupported", 0xC0050414)
        selected_lengths.setdefault(item.frame_id, enabled[item.frame_id])
        ranges.append(item)

    def build_packet(frames):
        return pack_packet_a8(
            tuple(selected_lengths.items()),
            enabled,
            pid_definitions,
            frames,
            capabilities=capabilities.mask,
            excluded=excluded,
            maximum_request=maximum_request,
            maximum_reply=maximum_reply,
            trigger=trigger is not None,
        )

    packet = None
    failure = None
    attempts = ()
    try:
        packet, attempts = build_packet(cached_frames)
    except MonitorError as error:
        if error.code != 0x90051012 or packet_cache is None:
            raise
        failure = error
    if (
        cached_frames is None
        and packet_cache is not None
        and (packet is None or (2, 0x90051012) in attempts)
    ):
        try:
            frames = packet_cache.get_packet_frame(
                profile.category,
                bus,
                source_identity=cache.identity,
            )
        except ToyotaCodecError as error:
            if packet is None:
                raise MonitorError(
                    "Variable packet cache failed", error.code
                ) from error
            attempts = tuple(
                (mode, error.code if mode == 2 else status) for mode, status in attempts
            )
        else:
            packet, attempts = build_packet(
                tuple((frame.sequence, len(frame.payload)) for frame in frames)
            )
    if packet is None:
        assert failure is not None
        raise failure
    if trigger is not None:
        auxiliary = phase3_auxiliary(
            profile,
            trigger,
            LegacyPacking(
                "P3",
                packet.mode,
                packet.setup_requests,
                packet.frame_sizes,
                packet.pid_layouts,
            ),
        )
        packet = replace(
            packet,
            setup_requests=packet.setup_requests + (auxiliary.request,),
            frame_sizes=packet.frame_sizes + ((auxiliary.frame_id, auxiliary.length),),
            pid_layouts=packet.pid_layouts
            + ((auxiliary.source_frame, auxiliary.frame_id, 0, auxiliary.length),),
        )
    cache.check_context()
    return replace(definitions, ranges=tuple(ranges)), packet, attempts


def check_variable_target_from_cache(
    cache: MonitorSupportCache,
    selected_ids: Sequence[int],
    observed_functions: Mapping[int, bool],
    *,
    excluded: int,
    cached_frames: Sequence[tuple[int, int]] | None = None,
    packet_cache: PacketFrameCache | None = None,
) -> VariableTargetMeasurement:
    """66E0 selected packing/measurement, before signal/display construction."""
    if not isinstance(cache, MonitorSupportCache):
        raise MonitorError("Variable check requires concrete selected cache")
    source = VariableMonitorSource.for_build(cache.source_build)
    source.check()
    profile = cache.profile
    if not isinstance(profile, VehicleProfile):
        raise MonitorError("Variable producer requires selected ECU database")
    definitions = variable_definitions(profile, selected_ids)
    cache.check_context()
    if profile.category == 0x68:
        if len(definitions.ranges) != 1:
            raise MonitorError("Variable voltage requires one range", 0x90051003)
        selected = definitions.ranges[0]
        if (
            selected.end_bit < selected.start_bit
            or (selected.end_bit - selected.start_bit) // 8 != 1
        ):
            raise MonitorError("Variable voltage requires two-byte range", 0xC0050102)
        return VariableTargetMeasurement(
            0x68, 64, variable_measurement(64, 0, (2,), request_length=5)
        )
    bus = cache.bus_id
    if bus is None or bus == 0:
        raise MonitorError("Variable check selected bus unavailable", 0xC0040602)
    protocol = profile.protocol_info(bus)
    if protocol is None:
        raise MonitorError("Variable check protocol absent", 0xC0050101)
    maximum_request, maximum_reply = word(protocol, 14), word(protocol, 16)
    capabilities = monitor_capabilities(observed_functions)
    phase = profile.category_record[72] & 31
    if phase != 9:
        if bus not in (0x12, 0x22, 0x11, 0x51, 0x32, 0x18, 0x38):
            raise MonitorError("Variable1170 selected protocol rejected", 0xC0050001)
        packing = pack_variable(
            definitions,
            cache.support_bits(1),
            category_flags=profile.category_record[72],
            capabilities=capabilities.mask,
            excluded=excluded,
            max_request=maximum_request,
            max_reply=maximum_reply,
        )
        mode = packing.mode_mask
        sizes = tuple(size for _, size in packing.response_frames)
    else:
        _, packet, _ = _variable_packet_packing(
            cache,
            definitions,
            observed_functions,
            excluded=excluded,
            maximum_request=maximum_request,
            maximum_reply=maximum_reply,
            cached_frames=cached_frames,
            packet_cache=packet_cache,
        )
        sizes = tuple(size for _, size in packet.frame_sizes)
        mode = packet.mode
    cache.check_context()
    return VariableTargetMeasurement(
        profile.category, mode, variable_measurement(mode, bus, sizes)
    )


@dataclass(frozen=True)
class VariableNotification:
    message: int
    wparam: int
    lparam: int = 0


def variable_reply_notifications(
    reply: NativeMonitorReply, *, signal_id: int
) -> tuple[VariableNotification, ...]:
    """DataListIF error buffers feed the distinct variable Phase4 callback."""
    from scripts.monitor_dlc12 import dlc12_notifications

    if not isinstance(reply, NativeMonitorReply):
        raise MonitorError("Variable notifications require decoded native reply")
    _uint(signal_id, 65535, "callback signal")
    return tuple(
        notification
        for error, status, data in dlc12_notifications(reply).errors
        if (
            notification := variable_error_notification(
                error, status, data, signal_id=signal_id
            )
        )
        is not None
    )


def variable_error_notification(
    native_error: int, status: int, data: int, *, signal_id: int
) -> VariableNotification | None:
    """5C90 Phase4Interface error callback, without posting a window message."""
    _uint(native_error, 0xFFFFFFFF, "callback error")
    _uint(status, 0xFFFFFFFF, "callback status")
    _uint(data, 0xFFFFFFFF, "callback data")
    _uint(signal_id, 65535, "callback signal")
    if status == 0xE0000100 or 0xE0000189 <= status <= 0xE0000190:
        return None
    if status == 0xE000FFFF:
        return VariableNotification(0x608, native_error)
    if (
        status in (0xE00001CC, 0xE00001CD)
        or status == 0xE0000110
        and data & 255 == 0x22
    ):
        return VariableNotification(0x602, 0, signal_id)
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
        0xE000010F: 0xA1050309,
        0xE0000110: 0xA1050312,
        0xE0000111: 0xA1050309,
        0xE0000112: 0xA1050312,
    }
    return VariableNotification(0x603, codes.get(status, 0xA1050307))


def variable_measurement(
    mode: int, bus_id: int, frame_sizes: tuple[int, ...], *, request_length: int = 0
) -> VariableMeasurement:
    """66e0/D140..D4e0 timing and the four-byte common packet prefix."""
    _uint(mode, 65535, "mode")
    _uint(bus_id, 65535, "measurement bus")
    if not isinstance(frame_sizes, tuple) or not 1 <= len(frame_sizes) <= MAX_ITEMS:
        raise MonitorError("Variable monitor measurement has no frames", 0xC005100F)
    for size in frame_sizes:
        _uint(size, 65535, "measurement frame size")
    if mode == 64:
        _uint(request_length, 255, "voltage request length")
        return VariableMeasurement(request_length, frame_sizes[0] + 4)
    if mode not in (1, 4, 5, 16, 32):
        raise MonitorError("Variable monitor measurement mode rejected", 0xC005100D)
    family = bus_id & 15
    if family in (2, 8):
        cycle = sum((size // 7) * 4 + 4 for size in frame_sizes)
    elif family == 1:
        cycle = (
            sum(size * 7 + 51 for size in frame_sizes)
            if mode in (1, 4, 5)
            else len(frame_sizes) * 160
        )
    else:
        raise MonitorError("Variable monitor measurement bus rejected", 0xC0040602)
    return VariableMeasurement(cycle & 0xFFFFFFFF, (sum(frame_sizes) + 4) & 0xFFFFFFFF)


def allocate_variable_measurements(
    total: int, measurements: tuple[VariableMeasurement, ...]
) -> tuple[VariableMeasurement, ...]:
    """CF40 exact DWORD weighting and signed allocation remainder branch."""
    _uint(total, 0xFFFFFFFF, "measurement allocation")
    if (
        not total
        or not isinstance(measurements, tuple)
        or not 1 <= len(measurements) <= 3
    ):
        raise MonitorError("Variable monitor allocation arguments rejected", 0xC0050001)
    for item in measurements:
        if not isinstance(item, VariableMeasurement):
            raise MonitorError("Variable monitor requires typed measurements")
        _uint(item.cycle, 0xFFFFFFFF, "measurement cycle")
        _uint(item.packet_size, 0xFFFFFFFF, "measurement packet size")
        if not item.cycle:
            raise MonitorError("Variable monitor measurement cycle is zero")
    if len(measurements) == 1:
        allocations = [total]
    else:
        weights = [
            (item.packet_size * 10000 & 0xFFFFFFFF) // item.cycle
            for item in measurements
        ]
        denominator = sum(weights) & 0xFFFFFFFF
        if not denominator:
            raise MonitorError("Variable monitor proportional weight is zero")
        signed_total = total if total < 0x80000000 else total - 0x100000000
        # CF40 sign-extends total for __allmul/__alldiv; division truncates to zero.
        allocations = [
            (
                (weight * abs(signed_total) // denominator)
                * (-1 if signed_total < 0 else 1)
            )
            & 0xFFFFFFFF
            for weight in weights
        ]
        used = sum(allocations) & 0xFFFFFFFF
        # Preserve native signed comparison and its asymmetric over-allocation branch.
        signed_used = used if used < 0x80000000 else used - 0x100000000
        allocations[-1] = (
            allocations[-1] - used + (total if signed_total >= signed_used else -total)
        ) & 0xFFFFFFFF
    return tuple(
        VariableMeasurement(item.cycle, item.packet_size, allocation)
        for item, allocation in zip(measurements, allocations)
    )


def variable_active_request(
    record: bytes,
    pattern: bytes,
    instructions: bytes,
    phase: int,
    value: int,
    *,
    auxiliary: int = 0,
) -> tuple[bytes, int | None]:
    """Original18 C260: variable frame bytecode, full SID and native repeat.

    Opcodes11/12/13 fail;14/15 emit zero. This differs from the
    PSA producer and must not inherit its Mode35 extensions or service override.
    """
    if not isinstance(record, bytes) or len(record) != 92:
        raise MonitorError("Variable drive row requires92 bytes", 0xC0050101)
    if not isinstance(pattern, bytes) or len(pattern) != 24:
        raise MonitorError("Variable drive pattern requires24 bytes", 0xC0050101)
    if not isinstance(instructions, bytes) or len(instructions) > 61:
        raise MonitorError("Variable drive frame exceeds61 bytes", 0xC0050102)
    _uint(phase, 255, "phase")
    _uint(value, 0xFFFFFFFF, "value")
    _uint(auxiliary, 0xFFFFFFFF, "auxiliary")
    low = phase & 31
    output = bytearray(
        (0x6D if low in (1, 2) else 0x3D if low == 7 else 0x30, record[80])
    )
    if low == 7:
        # Native jumps over the output repeat assignment on this branch.
        return bytes(output), None
    length = word(pattern, 8)
    for opcode in instructions:
        if not opcode:
            break
        if opcode in (11, 12, 13):
            raise MonitorError("Variable drive frame opcode invalid", 0xC0050102)
        byte = {
            2: value,
            3: value << (7 - (record[68] & 7)),
            4: record[86],
            5: record[86],
            6: record[86] + value,
            7: length & 255 if length else 6,
            8: auxiliary,
            10: value >> 8,
            16: record[88],
            17: length & 255,
        }.get(opcode, 0)
        output.append(byte & 255)
    return bytes(output), word(pattern, 2) if pattern[20] else 0


@dataclass(frozen=True)
class VariableSystemOperation:
    """7AE0/C6D0 command96, a distinct08 monitor-system slot, not active30."""

    source: VariableMonitorSource
    profile: VehicleProfile
    source_identity: tuple[object, ...]
    signal_id: int
    request: bytes
    request_identity: int

    @property
    def command(self) -> MonitorCommand:
        self.source.check()
        if self.source_identity != monitor_source_identity(self.profile, "")[1:]:
            raise MonitorError("Variable system selected context changed")
        _uint(self.signal_id, 65535, "system signal")
        _uint(self.request_identity, 0xFFFFFFFF, "system identity")
        if (
            not isinstance(self.request, bytes)
            or len(self.request) not in (2, 7)
            or self.request[:2] != bytes((8, self.signal_id & 255))
            or any(self.request[2:])
        ):
            raise MonitorError("Variable system frame malformed", 0xC0050001)
        return MonitorCommand(0x113, (self.request_identity, self.request[1:]))

    def event(self) -> MonitorSystemEvent:
        _ = self.command
        return MonitorSystemEvent(self.request[1:])

    def send(
        self,
        client: NativeVimClient,
        *,
        timeout: float = 10,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> None:
        command = self.command
        if not isinstance(client, NativeVimClient):
            raise MonitorError("Variable system requires concrete native client")
        try:
            client.dmci(
                NativeDmciCommand.from_neutral(command.command_id, command.values),
                timeout=timeout,
                cancelled=cancelled,
            )
        except NativeDmciError as error:
            raise MonitorError(
                "Variable native system setup failed", 0xA0051401
            ) from error
        _ = self.command


def selected_variable_system_operation(
    profile: VehicleProfile,
    signal_id: int,
    *,
    source: VariableMonitorSource,
    observed_bus_id: int | None,
    controller_category_flags: int,
) -> VariableSystemOperation:
    """Selected7AE0 connection and C6D0 one-byte signal/five-zero padding."""
    source.check()
    _uint(signal_id, 65535, "system signal")
    if observed_bus_id is None:
        raise MonitorError("Variable system connection cache absent", 0xC0040601)
    _uint(observed_bus_id, 65535, "system bus")
    if not observed_bus_id:
        raise MonitorError("Variable system selected bus unavailable", 0xC0040602)
    family = observed_bus_id & 15
    if family not in (1, 2, 6, 7, 8, 9):
        raise MonitorError("Variable system bus rejected", 0xC0040602)
    protocol = profile.protocol_info(observed_bus_id)
    if protocol is None:
        raise MonitorError("Variable system protocol absent", 0xC0050101)
    address = p4_monitor_address(
        bus_id=observed_bus_id,
        category_flags=controller_category_flags,
        default_request=word(protocol, 6),
        target=word(protocol, 8),
        can_word=word(protocol, 10),
    )
    request = bytes((8, signal_id & 255)) + (
        bytes(5) if family in (1, 6, 7, 9) else b""
    )
    return VariableSystemOperation(
        source,
        profile,
        monitor_source_identity(profile, "")[1:],
        signal_id,
        request,
        address.request_id,
    )


@dataclass(frozen=True)
class VariableActiveOperation:
    source: VariableMonitorSource
    profile: VehicleProfile
    source_identity: tuple[object, ...]
    signal_id: int
    request: bytes
    repeat: int
    request_identity: int

    @property
    def command(self) -> MonitorCommand:
        self.source.check()
        if monitor_source_identity(self.profile, "")[1:] != self.source_identity:
            raise MonitorError("Selected variable monitor metadata changed")
        if not isinstance(self.request, bytes) or not 2 <= len(self.request) <= 63:
            raise MonitorError("Variable active request has no body", 0xA0050441)
        _uint(self.repeat, 65535, "active repeat")
        _uint(self.request_identity, 0xFFFFFFFF, "active request identity")
        # 7800 passes C260 output+1 and length-1 to active_test_start.
        return MonitorCommand(
            0x10F, (self.request_identity, self.request[1:], self.repeat)
        )

    def stop_command(self, *, initialize: bool) -> MonitorCommand:
        """DataListIF active_test_stop: selected identity and explicit init flag."""
        if type(initialize) is not bool:
            raise MonitorError("Variable active stop requires boolean init flag")
        _ = self.command
        return MonitorCommand(0x110, (self.request_identity, int(initialize)))

    def event(self) -> ActiveMonitorEvent:
        """Same selected body for the normal J2534 CCommEventAT consumer."""
        _ = self.command
        return ActiveMonitorEvent(self.request[1:], self.repeat)


class VariableActiveRuntime:
    """7800/7DB0 active slot on the actual DMCI10F/110 packet consumer.

    Keep the validated stop command independently from mutable selected sources:
    a context change or cancellation after native start must still release it.
    """

    def __init__(self, operation: VariableActiveOperation, client: NativeVimClient):
        if not isinstance(operation, VariableActiveOperation) or not isinstance(
            client, NativeVimClient
        ):
            raise MonitorError(
                "Variable active slot requires selected operation/client"
            )
        command = operation.command
        self.operation, self.client = operation, client
        self._start = NativeDmciCommand.from_neutral(command.command_id, command.values)
        self.state = "new"
        self.attempted = False

    def _execute(
        self, command: NativeDmciCommand, timeout: float, cancelled: Callable[[], bool]
    ) -> None:
        try:
            self.client.dmci(command, timeout=timeout, cancelled=cancelled)
        except NativeDmciError as error:
            raise MonitorError(
                "Variable active native primitive failed", 0xA0050441
            ) from error

    def start(
        self, *, timeout: float = 10, cancelled: Callable[[], bool] = lambda: False
    ) -> None:
        if self.state != "new":
            raise MonitorError("Variable active slot already started")
        _ = self.operation.command
        try:
            # Native start can succeed before a response/cancellation is observed.
            self.attempted = True
            self._execute(self._start, timeout, cancelled)
            _ = self.operation.command
            self.state = "running"
        except BaseException as primary:
            try:
                self.stop(timeout=2)
            except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - preserve the primary failure
                primary.add_note(f"Variable active cleanup also failed: {cleanup}")
            self.state = "fault"
            raise

    def stop(self, *, initialize: bool = False, timeout: float = 2) -> None:
        if type(initialize) is not bool:
            raise MonitorError("Variable active stop requires boolean init flag")
        if not self.attempted:
            return
        command = NativeDmciCommand.from_neutral(
            0x110, (self.operation.request_identity, int(initialize))
        )
        try:
            self._execute(command, timeout, lambda: False)
        except BaseException:
            self.state = "fault"
            raise
        self.attempted = False
        self.state = "stopped"


def selected_variable_active_operation(
    profile: VehicleProfile,
    signal_id: int,
    value: int,
    *,
    source: VariableMonitorSource,
    observed_bus_id: int | None,
    auxiliary: int = 0,
    initial_repeat: int | None = None,
    controller_category_flags: int | None = None,
) -> VariableActiveOperation:
    """C260 joins actual DB229 wildcard key, DB20C and management DB111."""
    if not isinstance(source, VariableMonitorSource) or not isinstance(
        profile, VehicleProfile
    ):
        raise MonitorError("Variable monitor requires typed source and profile")
    source.check()
    _uint(signal_id, 65535, "signal identifier")
    if observed_bus_id is None:
        raise MonitorError("Variable active ECU connection cache absent", 0xC0040601)
    _uint(observed_bus_id, 65535, "bus identifier")
    if observed_bus_id == 0:
        raise MonitorError("Variable active ECU bus unavailable", 0xC0040602)
    if profile.database.version not in (
        0x0100030C,
        0x0100032F,
    ) or profile.catalog.management.version not in (0x0100030C, 0x0100032F):
        raise MonitorError("Unproven variable monitor database layout")
    if len(profile.category_record) != 76:
        raise MonitorError("Variable monitor category requires76 bytes")

    def rows(slot: int, width: int) -> tuple[bytes, ...]:
        if slot not in profile.database.sections:
            raise MonitorError("Variable monitor table absent", 0xA0030107)
        result = profile.records(slot)
        if len(result) > MAX_ITEMS or any(len(row) != width for row in result):
            raise MonitorError("Variable monitor table malformed", 0xC0050101)
        return result

    record = next((row for row in rows(41, 92) if word(row, 56) == signal_id), None)
    if record is None:
        raise MonitorError("Variable monitor signal absent", 0xC0050101)
    pattern = next(
        (row for row in rows(12, 24) if word(row, 0) == word(record, 64)), None
    )
    if pattern is None:
        raise MonitorError("Variable monitor pattern absent", 0xC0050101)
    protocol = profile.protocol_info(observed_bus_id)
    if protocol is None:
        raise MonitorError("Variable monitor protocol absent", 0xC0050101)
    management = profile.catalog.management
    frame_section = management.sections.get(17)
    variables = management.sections.get(0)
    if frame_section is None or variables is None:
        raise MonitorError("Variable monitor communication table absent", 0xA0030107)
    if frame_section.count > MAX_ITEMS:
        raise MonitorError("Variable monitor communication table exceeds budget")
    frame = next(
        (row for row in frame_section.rows(8) if word(row, 0) == word(record, 74)), None
    )
    if frame is None:
        raise MonitorError("Variable monitor communication frame absent", 0xC0050101)
    instructions = CommandFrame.from_record(
        frame, VariableTable(variables.payload, variables.count)
    ).request
    request, repeat = variable_active_request(
        record,
        pattern,
        instructions,
        profile.category_record[72],
        value,
        auxiliary=auxiliary,
    )
    if repeat is None:
        if initial_repeat is None:
            raise MonitorError(
                "Variable monitor phase7 requires the retained repeat observation"
            )
        repeat = _uint(initial_repeat, 65535, "retained repeat")
    return VariableActiveOperation(
        source,
        profile,
        monitor_source_identity(profile, "")[1:],
        signal_id,
        request,
        repeat,
        p4_monitor_address(
            bus_id=observed_bus_id,
            category_flags=profile.category_record[72]
            if controller_category_flags is None
            else controller_category_flags,
            default_request=0,
            target=word(protocol, 8),
            can_word=word(protocol, 10),
        ).request_id,
    )
