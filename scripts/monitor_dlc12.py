"""Selected DLC12 monitor production and bounded native DMCI acquisition.

The selected database and observed driver/function state are mandatory inputs.
Only the injected NativeVimClient performs transport; no OEM code is executed.
"""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from threading import Event
from typing import cast

from scripts.data_monitor import (
    MAX_BYTES,
    MAX_ITEMS,
    MonitorCapabilities,
    MonitorCommand,
    MonitorError,
    MonitorSetup,
    MonitorSignalMetadata,
    monitor_capabilities,
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
    RecorderCancelled,
    RecorderError,
    decode_command,
    native_monitor_buffer,
)
from scripts.monitor_legacy import (
    LegacyPacking,
    dlc12_interface_commands,
    dlc12_setup_commands,
    pack_dlc12_ranges,
)
from scripts.monitor_support import monitor_source_identity
from scripts.profiles import VehicleProfile
from scripts.support import word
from scripts.toyota_session import active_request_dlc12


def dlc12_voltage_controller(
    action: str, *, mode_mask: int, interface_present: bool
) -> int:
    """51f0/6420 against the shipped nADMonitor false stubs, not a sampler."""
    if action not in ("start", "stop") or type(interface_present) is not bool:
        raise MonitorError("DLC12 voltage controller requires explicit action/presence")
    if type(mode_mask) is not int or not 0 <= mode_mask <= 0xFFFFFFFF:
        raise MonitorError("DLC12 voltage controller mask must fit DWORD")
    if action == "start" and not mode_mask & 0x40:
        return 0
    if not interface_present:
        return 0xC0050001
    # Original12/18 VoltageMonitorInterface start/stop both return false.
    return 0x90051201 if action == "start" else 0x90051202


@dataclass(frozen=True)
class DLC12VoltageObservation:
    """Actual DeviceIoControl setup/read results, in6490 native call order."""

    selector: int
    setup_success: bool
    reads: tuple[tuple[bool, bytes], ...]

    def __post_init__(self) -> None:
        if type(self.selector) is not int or not 0 <= self.selector <= 255:
            raise MonitorError("DLC12 voltage selector must fit BYTE")
        if type(self.setup_success) is not bool or not isinstance(self.reads, tuple):
            raise MonitorError(
                "DLC12 voltage observations require explicit native results"
            )
        expected = 4 if self.setup_success else 0
        if len(self.reads) > expected:
            raise MonitorError("DLC12 voltage observation exceeds native read count")
        failed = False
        for success, data in self.reads:
            if type(success) is not bool or not isinstance(data, bytes):
                raise MonitorError("DLC12 voltage read observation is malformed")
            if failed or (success and len(data) != 2) or len(data) > 2:
                raise MonitorError(
                    "DLC12 voltage read does not match native WORD output"
                )
            failed = not success
        if self.setup_success and not failed and len(self.reads) != 4:
            raise MonitorError(
                "DLC12 voltage calibration needs four successful WORD reads"
            )

    @property
    def setup_ioctl(self) -> int:
        return 0xFFFEFF90 if self.selector else 0xFFFEFF84


def dlc12_voltage_offset(
    offset: int, multiplier: int, divisor: int, observation: DLC12VoltageObservation
) -> tuple[int, int | None]:
    """6490 arithmetic and nonfatal logged driver failures; no hardware access."""
    for value in (offset, multiplier, divisor):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise MonitorError("DLC12 voltage scaling requires DWORD fields")
    if not observation.setup_success:
        return offset, 0x90051203
    if any(not success for success, _ in observation.reads):
        return offset, 0x90051204
    if not divisor:
        raise MonitorError("DLC12 voltage calibration divisor is zero")
    average = sum(int.from_bytes(data, "little") for _, data in observation.reads) >> 2
    adjustment = ((average * multiplier) & 0xFFFFFFFF) // divisor
    return (offset - adjustment) & 0xFFFFFFFF, None


@dataclass
class DLC12VoltageState:
    """Controller WORD+ d4 mode and shared-data16 cached offset."""

    mode: int
    cached_offset: int | None = None
    errors: tuple[tuple[int, int], ...] = field(default=(), init=False)

    def __post_init__(self) -> None:
        if type(self.mode) is not int or self.mode not in (0, 1, 2):
            raise MonitorError("DLC12 voltage calibration mode must be0/1/2")
        if self.cached_offset is not None and (
            type(self.cached_offset) is not int
            or not 0 <= self.cached_offset <= 0xFFFFFFFF
        ):
            raise MonitorError("DLC12 cached voltage offset must fit DWORD")


@dataclass(frozen=True)
class SelectedDLC12Monitor:
    packing: LegacyPacking
    commands: MonitorSetup
    metadata: tuple[MonitorSignalMetadata, ...]
    layouts: tuple[tuple[int, int, int, int], ...]
    capabilities: MonitorCapabilities
    interface_id: int
    buffer_468: int
    constructor_send: int
    constructor_mask: int
    database_sha256: str
    source_identity: tuple[object, ...]

    @property
    def signals(self) -> tuple[MonitorSignalMetadata, ...]:
        return self.metadata

    @property
    def frame_sizes(self) -> tuple[tuple[int, int], ...]:
        return self.packing.frame_sizes


def selected_dlc12_monitor(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    *,
    observed_functions: Mapping[int, bool],
    connected_device: int,
    interface_id: int,
    buffer_468: int,
    excluded: int = 0,
    lsb_observations: Mapping[int, tuple[int, int, int]] | None = None,
    voltage_state: DLC12VoltageState | None = None,
    voltage_observations: Mapping[int, DLC12VoltageObservation] | None = None,
) -> SelectedDLC12Monitor:
    """DLC12 6e20→26a0/2770/1ea0/29e0→4900→7130→74b0.

    Unlike P4 this producer directly selects Freeze rows and does not expand
    MultiPID flags. Native rolling end-bit truncation is kept by the packer.
    """
    if type(connected_device) is not int or connected_device != 4:
        raise MonitorError("DLC12 requires observed connected device4", 0xC0051302)
    if type(buffer_468) is not int or buffer_468 != profile.category:
        raise MonitorError("DLC12 buffer header identity must equal selected category")
    keys = tuple(selected_ids)
    if (
        not keys
        or len(keys) > MAX_ITEMS
        or any(type(key) is not int or not 0 <= key <= 65535 for key in keys)
    ):
        raise MonitorError(
            "DLC12 requires bounded selected WORD signal IDs", 0x90051010
        )
    first: dict[int, bytes] = {}
    rows = profile.records(10)
    if len(rows) > MAX_ITEMS or any(len(row) != 84 for row in rows):
        raise MonitorError("DLC12 Freeze table requires bounded84-byte rows")
    for row in rows:
        first.setdefault(word(row, 56), row)
    ranges = []
    layouts = []
    seen = set()
    for key in keys:
        if key not in first:
            raise MonitorError("DLC12 selected Freeze row is absent", 0xC0050101)
        if key in seen:
            continue
        seen.add(key)
        row = first[key]
        start, end, frame = word(row, 62), word(row, 64), row[79]
        ranges.append((key, start, end, frame))
        # 1aa0: generated source PID1 maps to frame0 with byte offset0.
        layouts.append((key, 0, start, end))
    capabilities = monitor_capabilities(observed_functions)
    packing = pack_dlc12_ranges(
        ranges, capabilities=capabilities.mask, excluded=excluded
    )
    if any(end >= packing.frame_sizes[0][1] * 8 for _, _, _, end in layouts):
        raise MonitorError("DLC12 selected range exceeds generated buffer")
    commands = dlc12_setup_commands(
        packing, interface_id=interface_id, buffer_468=buffer_468
    )
    metadata = selected_signal_metadata(
        profile,
        layouts,
        lsb_observations=lsb_observations,
        voltage_state=voltage_state,
        voltage_observations=voltage_observations,
    )
    interface = dlc12_interface_commands(profile, connected_device=connected_device)
    constructor_send, constructor_mask = interface.setup[0].values
    assert type(constructor_send) is int and type(constructor_mask) is int
    commands = replace(commands, setup=interface.setup + commands.setup)
    return SelectedDLC12Monitor(
        packing,
        commands,
        metadata,
        tuple(layouts),
        capabilities,
        interface_id,
        buffer_468,
        constructor_send,
        constructor_mask,
        profile.database.sha256,
        monitor_source_identity(profile, ""),
    )


@dataclass(frozen=True)
class DLC12Notifications:
    errors: tuple[tuple[int, int, int], ...]
    stop_count: int


def dlc12_notifications(reply: NativeMonitorReply) -> DLC12Notifications:
    """DataListIF28890: DWORD errors, packed13-byte errors and stop count.

    Partial notification tails are ignored by native integer division. The five
    core buffers are retained by the reply parser; only slots0 and1 are read by
    this consumer (native pointer fields Rcv+3c and+4c).
    """
    first = reply.buffers[0].data
    detailed = reply.buffers[1].data
    errors = [
        (int.from_bytes(first[i : i + 4], "little"), 0x13, 0)
        for i in range(0, len(first) - 3, 4)
    ]
    errors.extend(
        (
            int.from_bytes(detailed[i + 4 : i + 8], "little"),
            int.from_bytes(detailed[i + 8 : i + 12], "little"),
            detailed[i + 12],
        )
        for i in range(0, len(detailed) - 12, 13)
    )
    return DLC12Notifications(tuple(errors), reply.trailing_value)


class DLC12MonitorRuntime:
    """One native buffer registration; concrete shared DMCI start/poll/stop.

    Registering again with the same identity sends total_length0, as280e0 does.
    All commands are validated before the first exchange. Transport failure
    invalidates the interface; a new runtime is then required.
    """

    def __init__(self, selected: SelectedDLC12Monitor, client: NativeVimClient):
        self.selected, self.client = selected, client
        self.state = "new"
        self.registered = False
        self.created = False
        self.last_notifications = DLC12Notifications((), 0)
        self.reader = NativeMonitorPacketReader(selected.packing.frame_sizes, phase=0)

    def setup(
        self, *, timeout: float = 10, cancelled: Callable[[], bool] = lambda: False
    ) -> None:
        if self.state not in ("new", "ready", "stopped"):
            raise MonitorError("DLC12 setup is unavailable in current state")
        commands = self.selected.commands.setup
        if self.registered:
            commands = tuple(
                replace(command, values=command.values[:4] + (0,) + command.values[5:])
                if command.command_id == 0x10A
                else command
                for command in commands
                if command.command_id != 0x105
            )
        try:
            self._commands(commands, timeout, cancelled)
        except BaseException as primary:
            if self.created:
                try:
                    self.close(timeout=2)
                except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - preserve the primary failure
                    primary.add_note(f"DLC12 interface cleanup also failed: {cleanup}")
            self.state = "fault"
            raise
        self.registered = True
        self.state = "ready"

    def close(self, *, timeout: float = 10) -> None:
        """27f20 attempts DeleteDLC12Interface twice, then ChangeMode0."""
        if self.state == "closed":
            return
        if not self.created:
            self.state = "closed"
            return
        if (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise MonitorError("DLC12 disposal requires positive finite timeout")
        primary: BaseException | None = None
        for _ in range(2):
            try:
                self._commands((MonitorCommand(0x106, ()),), timeout / 3, lambda: False)
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - collect then re-raise cleanup failures
                if primary is None:
                    primary = exc
                else:
                    primary.add_note(f"DLC12 second interface deletion failed: {exc}")
        try:
            status = self.client.change_mode(0, timeout=timeout / 3)
            if status:
                raise MonitorError(
                    "DLC12 ChangeMode0 returned native failure status", status
                )
        except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - collect then re-raise cleanup failures
            if primary is None:
                primary = exc
            else:
                primary.add_note(f"DLC12 ChangeMode0 failed: {exc}")
        self.registered = self.created = False
        if primary is not None:
            self.state = "fault"
            raise primary
        self.state = "closed"

    def _commands(
        self,
        commands: Sequence[MonitorCommand],
        timeout: float,
        cancelled: Callable[[], bool],
    ) -> None:
        if (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise MonitorError("DLC12 command requires positive finite timeout")
        bound = tuple(
            NativeDmciCommand.from_neutral(command.command_id, command.values)
            for command in commands
        )
        deadline = self.client.clock() + timeout
        try:
            for command in bound:
                if cancelled():
                    raise RecorderCancelled("DLC12 monitor cancelled")
                remaining = deadline - self.client.clock()
                if remaining <= 0:
                    raise TimeoutError("DLC12 monitor command deadline exceeded")
                if command.command_id == 0x105:
                    self.created = True
                self.client.dmci(command, timeout=remaining, cancelled=cancelled)
        except BaseException:
            self.state = "fault"
            raise

    def start(
        self, *, timeout: float = 10, cancelled: Callable[[], bool] = lambda: False
    ) -> None:
        if self.state not in ("ready", "stopped"):
            raise MonitorError("DLC12 start requires registered setup")
        self.reader = NativeMonitorPacketReader(self.selected.frame_sizes, phase=0)
        self._commands(self.selected.commands.start, timeout, cancelled)
        self.state = "running"

    def poll(
        self, *, timeout: float = 10, cancelled: Callable[[], bool] = lambda: False
    ) -> tuple[NativeMonitorPacket, ...]:
        if self.state != "running":
            raise MonitorError("DLC12 poll requires running monitor")
        reply = self.client.get_monitor_data(
            (self.selected.buffer_468,), timeout=timeout, cancelled=cancelled
        )
        self.last_notifications = dlc12_notifications(reply)
        packets = []
        for identity, chunk in reply.interfaces.items:
            if identity == self.selected.buffer_468:
                if not isinstance(chunk, NativeCoreBuffer):
                    raise RecorderError("DLC12 monitor chunk is malformed")
                packets.extend(self.reader.feed(chunk.data))
        if self.last_notifications.errors:
            raise MonitorError(
                "DLC12 native error notification", self.last_notifications.errors[0][0]
            )
        return tuple(packets)

    def stop(self, *, timeout: float = 2) -> None:
        if not self.created:
            return
        self._commands(self.selected.commands.stop, timeout, lambda: False)
        self.state = "stopped"

    def capture(
        self,
        *,
        max_polls: int,
        max_packets: int,
        timeout: float,
        max_bytes: int = MAX_BYTES,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> tuple[NativeMonitorPacket, ...]:
        if self.state != "ready":
            raise MonitorError("DLC12 capture requires completed setup")
        if any(
            type(value) is not int or not 1 <= value <= MAX_ITEMS
            for value in (max_polls, max_packets)
        ):
            raise MonitorError("DLC12 capture requires bounded poll/packet budgets")
        if (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise MonitorError("DLC12 capture requires positive finite timeout")
        self.reader = NativeMonitorPacketReader(
            self.selected.packing.frame_sizes,
            phase=0,
            max_packets=max_packets,
            max_bytes=max_bytes,
        )
        deadline = self.client.clock() + timeout
        packets = []
        primary: BaseException | None = None
        attempted = False
        try:
            attempted = True
            self._commands(self.selected.commands.start, timeout, cancelled)
            self.state = "running"
            for _ in range(max_polls):
                if cancelled():
                    raise RecorderCancelled("DLC12 monitor cancelled")
                remaining = deadline - self.client.clock()
                if remaining <= 0:
                    raise TimeoutError("DLC12 acquisition deadline exceeded")
                reply = self.client.get_monitor_data(
                    (self.selected.buffer_468,), timeout=remaining, cancelled=cancelled
                )
                self.last_notifications = dlc12_notifications(reply)
                for identity, chunk in reply.interfaces.items:
                    # 28890 walks registrations and silently skips unmatched IDs.
                    if identity == self.selected.buffer_468:
                        if not isinstance(chunk, NativeCoreBuffer):
                            raise RecorderError("DLC12 monitor chunk is malformed")
                        packets.extend(self.reader.feed(chunk.data))
                if self.last_notifications.errors:
                    raise MonitorError(
                        "DLC12 native error notification",
                        self.last_notifications.errors[0][0],
                    )
                if self.last_notifications.stop_count or len(packets) >= max_packets:
                    self.reader.finish()
                    return tuple(packets)
            raise MonitorError("DLC12 monitor poll budget exceeded")
        except BaseException as exc:
            primary = exc
            self.state = "cancelled" if isinstance(exc, RecorderCancelled) else "fault"
            raise
        finally:
            if attempted:
                try:
                    self._commands(self.selected.commands.stop, 2, lambda: False)
                    if primary is None:
                        self.state = "stopped"
                except BaseException as exc:
                    if primary is None:
                        raise
                    primary.add_note(f"DLC12 stop also failed: {exc}")


def dlc12_protocol_headers(
    category_flags: int, bus_id: int, value10: int, value14: int, value1c: int = 0
) -> tuple[int, int, int]:
    """5fd0/7800 native header DWORDs from observed bus and selected ProtInfo."""
    if (
        any(
            type(x) is not int or not 0 <= x <= 65535
            for x in (bus_id, value10, value14, value1c)
        )
        or type(category_flags) is not int
        or not 0 <= category_flags <= 255
    ):
        raise MonitorError("DLC12 header inputs must fit their native fields")
    low, high = bus_id & 15, bus_id & 0xF0
    address = (
        (0xF1 if category_flags & 0xE0 == 0x80 else 0xF0)
        if low in (1, 6, 7, 8, 9)
        else 0
    )
    third = 0xFFFFFFFF
    if low in (1, 9):
        if high in (0x10, 0x50):
            request = ((value14 | 0x8000) << 8) | address
            response = 0xFFFFFFFF
            if value10:
                third = ((value10 | 0xC000) << 8) | address
        elif high == 0x20:
            request, response = address | 0x686A00, value14 | 0x486B00
        elif high == 0x30:
            request = ((value10 | 0xC000) << 8) | address
            response = ((address | 0x8000) << 8) | value14
        else:
            raise MonitorError(
                "DLC12 native bus addressing mode is unsupported", 0xC0050001
            )
    elif low == 2:
        if high == 0x10:
            request, response = value14, value14 | 8
        elif high == 0x20:
            request = ((value14 | 0xFF800000) << 8) | value1c
            response = ((value14 | 0xFF800008) << 8) | value14
        elif high == 0x30:
            request, response = value10, value14 | 8
        else:
            raise MonitorError(
                "DLC12 native bus addressing mode is unsupported", 0xC0050001
            )
    elif low in (5, 12):
        request, response = value14, 0xFFFFFFFF
    elif low in (6, 7):
        request = address | (0x616A00 if low == 6 else 0x686A00)
        response = value14 | (0x416B00 if low == 6 else 0x486B00)
    elif low == 8 and high in (0x10, 0x30):
        request = (
            ((value14 | 0xFFD8DA00) if high == 0x10 else (value10 | 0xFFD8DB00)) << 8
        ) | address
        response = ((address | 0xFFD8DA00) << 8) | value14
    else:
        raise MonitorError("DLC12 native bus identifier is unsupported", 0xC0050001)
    return request & 0xFFFFFFFF, response & 0xFFFFFFFF, third & 0xFFFFFFFF


@dataclass(frozen=True)
class DLC12ActiveOperation:
    category: int
    bus_id: int
    signal_id: int
    headers: tuple[int, int, int]
    command: MonitorCommand
    database_sha256: str
    source_identity: tuple[object, ...]


def selected_dlc12_active_operation(
    profile: VehicleProfile,
    signal_id: int,
    value: int,
    *,
    observed_bus_id: int | None,
    auxiliary: int = 0,
    support: bytes | None = None,
) -> DLC12ActiveOperation:
    """69e0→ProtInfo/5fd0→58d0→DLC12 active_test_start; no driver callback."""
    if observed_bus_id is None:
        raise MonitorError("DLC12 active ECU connection cache is absent", 0xC0040601)
    if type(observed_bus_id) is not int or not 0 <= observed_bus_id <= 65535:
        raise MonitorError("DLC12 observed active bus must fit WORD")
    if not observed_bus_id:
        raise MonitorError("DLC12 active ECU bus is unavailable", 0xC0040602)
    if type(signal_id) is not int or not 0 <= signal_id <= 65535:
        raise MonitorError("DLC12 active signal must fit WORD")
    protocol = profile.protocol_info(observed_bus_id)
    if protocol is None:
        raise MonitorError("DLC12 active selected ProtInfo row is absent", 0xC0050101)
    records = profile.records(11)
    patterns = profile.records(12)
    if (
        len(records) > MAX_ITEMS
        or len(patterns) > MAX_ITEMS
        or any(len(row) != 92 for row in records)
        or any(len(row) != 24 for row in patterns)
    ):
        raise MonitorError("DLC12 selected active tables are malformed or excessive")
    record = next((row for row in records if word(row, 56) == signal_id), None)
    if record is None:
        raise MonitorError("DLC12 selected ActTest row is absent", 0xC0050101)
    pattern = next((row for row in patterns if word(row, 0) == word(record, 64)), None)
    if pattern is None:
        raise MonitorError("DLC12 selected ActTestPattern row is absent", 0xC0050101)
    headers = dlc12_protocol_headers(
        profile.category_record[72],
        observed_bus_id,
        word(protocol, 6),
        word(protocol, 8),
    )
    request, repeat = active_request_dlc12(
        record,
        pattern,
        profile.category_record[72],
        value,
        auxiliary=auxiliary,
        support=support,
    )
    if len(request) < 2:
        raise MonitorError("DLC12 active request has no payload", 0xA0050441)
    return DLC12ActiveOperation(
        profile.category,
        observed_bus_id,
        signal_id,
        headers,
        MonitorCommand(0x10F, (headers[0], request[1:], repeat)),
        profile.database.sha256,
        monitor_source_identity(profile, ""),
    )


@dataclass(frozen=True)
class DLC12RecordingBufferSpec:
    selected: SelectedDLC12Monitor
    selected_ids: tuple[int, ...]
    phase: int
    allocation_size: int
    name: bytes
    text_encoding: str

    def native(self) -> NativeMonitorBuffer:
        return native_monitor_buffer(
            self.selected.buffer_468,
            self.selected.signals,
            self.selected.frame_sizes,
            self.selected_ids,
            phase=self.phase,
            allocation_size=self.allocation_size,
            name=self.name,
            text_encoding=self.text_encoding,
        )


@dataclass(frozen=True)
class DLC12RecordingSettings:
    """The concrete category/buffer and setup/start/stop maps captured by CMD57."""

    buffers: tuple[NativeMonitorBuffer, ...]
    commands: MonitorSetup


@dataclass(frozen=True)
class DLC12ControlResult:
    command_id: int
    status: int
    flags20: int = 0
    flags28: int = 0
    settings: DLC12RecordingSettings | None = None

    @property
    def failed(self) -> bool:
        return bool(self.status)


@dataclass
class DLC12ControlMessage:
    command_id: int
    selected: SelectedDLC12Monitor | None = None
    system_count: int = 1
    slot_index: int = 0
    recording: tuple[DLC12RecordingBufferSpec, ...] = ()
    active: DLC12ActiveOperation | None = None
    completed: Event = field(default_factory=Event, init=False, repr=False)
    result: DLC12ControlResult | None = field(default=None, init=False)
    exception: BaseException | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if type(self.command_id) is not int or not 0 <= self.command_id <= 0xFFFFFFFF:
            raise MonitorError("DLC12 command identity must fit DWORD")
        if (
            type(self.system_count) is not int
            or not 0 <= self.system_count <= 0xFFFFFFFF
        ):
            raise MonitorError("DLC12 command system count must fit DWORD")
        if type(self.slot_index) is not int or not 0 <= self.slot_index <= 0xFFFFFFFF:
            raise MonitorError("DLC12 command slot must fit DWORD")


class DLC12Controller:
    """Native3570 cooperative command queue and3720 dispatch, with three slots.

    Windows wait results remain explicit so shutdown, timeout, queue-fault and
    completion ordering can be exercised without running a vendor thread.
    """

    def __init__(self, client: NativeVimClient, *, maximum_queued: int = MAX_ITEMS):
        if type(maximum_queued) is not int or not 1 <= maximum_queued <= MAX_ITEMS:
            raise MonitorError("DLC12 controller queue budget is invalid")
        self.client = client
        self.maximum_queued = maximum_queued
        self.queue: deque[DLC12ControlMessage] = deque()
        self.runtime: DLC12MonitorRuntime | None = None
        self.active_mask = 0
        self.active_operation: DLC12ActiveOperation | None = None
        self.closed = False
        self.slots: list[NativeMonitorBuffer | None] = [None, None, None]
        self.slot_categories: list[int | None] = [None, None, None]
        self.errors = [0, 0, 0]
        self.readers: dict[int, NativeMonitorPacketReader] = {}
        self.received_bytes = 0
        self.trace: deque[tuple[str, int]] = deque(maxlen=MAX_ITEMS)

    def check_start(self, command_id: int) -> DLC12ControlResult:
        """Export2e40/2ce0: flags only; these are not3720 dispatch IDs."""
        if type(command_id) is not int:
            raise MonitorError("DLC12 CheckStart command must be DWORD")
        if command_id == 7:
            return DLC12ControlResult(command_id, 0, flags28=1)
        if command_id == 0x42:
            return DLC12ControlResult(command_id, 0, flags20=1)
        return DLC12ControlResult(command_id, 0xC0050404)

    def register_buffer(self, buffer: NativeMonitorBuffer) -> int:
        """4550: same category reuses slot; otherwise first empty of three."""
        if not isinstance(buffer, NativeMonitorBuffer):
            raise MonitorError("DLC12 slot requires concrete native monitor metadata")
        buffer.encode()
        for index, category in enumerate(self.slot_categories):
            if category is None or category == buffer.value_before_buffer:
                frames = cast(
                    tuple[tuple[int, int], ...],
                    decode_command(buffer.frame_table)["frames"],
                )
                reader = NativeMonitorPacketReader(frames, phase=buffer.phase)
                self.slots[index] = buffer
                self.slot_categories[index] = buffer.value_before_buffer
                self.errors[index] = 0
                self.readers[buffer.value_before_buffer] = reader
                return index
        raise MonitorError("DLC12 native three-slot table is full", 0xC0050001)

    def buffer_by_category(self, category: int) -> NativeMonitorBuffer | None:
        if type(category) is not int or not 0 <= category <= 0xFFFFFFFF:
            raise MonitorError("DLC12 buffer category must fit DWORD")
        return next(
            (
                buffer
                for buffer in self.slots
                if buffer is not None and buffer.value_before_buffer == category
            ),
            None,
        )

    def post_error(self, code: int) -> None:
        """62b0: set error in every allocated native buffer."""
        if type(code) is not int or not 1 <= code <= 0xFFFFFFFF:
            raise MonitorError("DLC12 posted error must be a nonzero DWORD")
        for index, category in enumerate(self.slot_categories):
            if category is not None:
                self.errors[index] = code
        self.trace.append(("error", code))

    def buffer_error(self, index: int = 3) -> int:
        """6310: index>=3 returns the first nonzero slot error."""
        if type(index) is not int or not 0 <= index <= 0xFFFFFFFF:
            raise MonitorError("DLC12 error slot index must fit DWORD")
        if index >= 3:
            return next(
                (
                    error
                    for category, error in zip(
                        self.slot_categories, self.errors, strict=True
                    )
                    if category is not None and error
                ),
                0,
            )
        return self.errors[index] if self.slot_categories[index] is not None else 0

    def enqueue(self, message: DLC12ControlMessage) -> None:
        if self.closed or not isinstance(message, DLC12ControlMessage):
            raise MonitorError("DLC12 controller is closed or message is invalid")
        if message.completed.is_set() or any(old is message for old in self.queue):
            raise MonitorError("DLC12 command message was already queued/completed")
        if len(self.queue) >= self.maximum_queued:
            raise MonitorError("DLC12 command queue budget exceeded")
        self.queue.append(message)

    def _stop(self) -> None:
        try:
            if self.runtime is not None and self.runtime.created:
                self.runtime.stop()
        finally:
            self.active_mask = 0
            self.active_operation = None
            self.trace.append(("stop", 0))

    def run_one(
        self,
        *,
        wait_status: int = 0,
        timeout: float = 10,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> DLC12ControlResult | None:
        if self.closed:
            raise MonitorError("DLC12 worker is closed")
        if type(wait_status) is not int or not 0 <= wait_status <= 0xFFFFFFFF:
            raise MonitorError("DLC12 worker wait status must fit DWORD")
        if wait_status == 1:
            failures: list[BaseException] = []
            try:
                try:
                    self._stop()
                except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - disposal must still be attempted
                    failures.append(exc)
                if self.runtime is not None:
                    try:
                        self.runtime.close()
                    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - preserve all shutdown failures
                        failures.append(exc)
            finally:
                self.closed = True
                while self.queue:
                    message = self.queue.popleft()
                    message.result = DLC12ControlResult(message.command_id, 0xC0050503)
                    message.completed.set()
            if failures:
                for failure in failures[1:]:
                    failures[0].add_note(
                        f"DLC12 shutdown cleanup also failed: {failure}"
                    )
                raise failures[0]
            return None
        if wait_status == 0x102:
            if self.buffer_error():
                self._stop()
            return None
        if wait_status != 0:
            self.post_error(0xA0050511)
            self._stop()
            return None
        if not self.queue:
            raise MonitorError("DLC12 queue event has no queued command", 0xC0050001)
        message = self.queue.popleft()
        self.trace.append(("dispatch", message.command_id))
        try:
            if cancelled():
                raise RecorderCancelled("DLC12 controller command cancelled")
            result = self._dispatch(message, timeout, cancelled)
        except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - delivered through the command completion
            message.exception = exc
            code = (
                exc.code
                if isinstance(exc, MonitorError) and exc.code is not None
                else 0xC0050001
            )
            result = DLC12ControlResult(message.command_id, code)
        message.result = result
        message.completed.set()
        self.trace.append(("finish", message.command_id))
        if result.status:
            self.post_error(result.status)
        if self.buffer_error() or result.status:
            try:
                self._stop()
            except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - preserve the command outcome
                if message.exception is not None:
                    message.exception.add_note(
                        f"DLC12 worker stop also failed: {cleanup}"
                    )
                else:
                    message.exception = cleanup
            if self.runtime is not None and self.runtime.created:
                try:
                    self.runtime.close()
                except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - preserve primary command failure
                    if message.exception is not None:
                        message.exception.add_note(
                            f"DLC12 worker disposal also failed: {cleanup}"
                        )
                    else:
                        message.exception = cleanup
        return result

    def poll_registered(
        self, *, timeout: float = 10, cancelled: Callable[[], bool] = lambda: False
    ) -> tuple[tuple[int, NativeMonitorPacket], ...]:
        """28890 routes actual native10D chunks by buffer+468 across all slots."""
        if not self.active_mask or self.runtime is None:
            raise MonitorError("DLC12 controller poll requires active acquisition")
        identities = tuple(reversed(tuple(self.readers)))
        if not 1 <= len(identities) <= 3:
            raise MonitorError(
                "DLC12 acquisition needs one to three registered buffers"
            )
        try:
            reply = self.client.get_monitor_data(
                identities, timeout=timeout, cancelled=cancelled
            )
            packets = []
            for identity, chunk in reply.interfaces.items:
                if type(identity) is not int or identity not in self.readers:
                    continue
                if not isinstance(chunk, NativeCoreBuffer):
                    raise MonitorError("DLC12 registered chunk is malformed")
                self.received_bytes += len(chunk.data)
                if self.received_bytes > MAX_BYTES:
                    raise MonitorError(
                        "DLC12 registered stream exceeds aggregate byte budget"
                    )
                packets.extend(
                    (identity, packet)
                    for packet in self.readers[identity].feed(chunk.data)
                )
            notifications = dlc12_notifications(reply)
            if notifications.errors:
                for code, _, _ in notifications.errors:
                    if code:
                        self.post_error(code)
                raise MonitorError(
                    "DLC12 registered stream has native error notifications",
                    notifications.errors[0][0],
                )
            if notifications.stop_count:
                for reader in self.readers.values():
                    reader.finish()
                self._stop()
            return tuple(packets)
        except (Exception, KeyboardInterrupt) as primary:
            code = (
                primary.code
                if isinstance(primary, MonitorError) and primary.code
                else 0xC0050001
            )
            self.post_error(code)
            try:
                self._stop()
            except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - preserve acquisition failure
                primary.add_note(f"DLC12 registered stream stop also failed: {cleanup}")
            raise

    def _dispatch(
        self,
        message: DLC12ControlMessage,
        timeout: float,
        cancelled: Callable[[], bool],
    ) -> DLC12ControlResult:
        command = message.command_id
        if command == 0xA:
            self._stop()
            return DLC12ControlResult(command, 0)
        if command == 0xB:
            if not self.active_mask:
                return DLC12ControlResult(command, 0x90050405)
            if self.active_mask & 0x3800 not in (0, 0x2000):
                return DLC12ControlResult(command, 0xC005100D)
            if self.runtime is None or message.active is None:
                return DLC12ControlResult(command, 0xC0050001)
            operation = message.active
            if (
                operation.category != self.runtime.selected.buffer_468
                or operation.database_sha256 != self.runtime.selected.database_sha256
                or operation.source_identity != self.runtime.selected.source_identity
            ):
                return DLC12ControlResult(command, 0xC0050001)
            self.runtime._commands((operation.command,), timeout, cancelled)
            self.active_operation = operation
            return DLC12ControlResult(command, 0)
        if command in (9, 0x60, 0x89):
            return DLC12ControlResult(command, 0x90050405)
        if command not in (0xC, 0x38, 0x57):
            return DLC12ControlResult(command, 0x90050405)
        if self.active_mask:
            return DLC12ControlResult(command, 0x90050405)
        if (
            message.system_count != 1
            or message.slot_index != 0
            or message.selected is None
        ):
            return DLC12ControlResult(command, 0xC0050001)
        selected = message.selected
        if (
            not isinstance(message.recording, tuple)
            or len(message.recording) > 3
            or any(
                not isinstance(spec, DLC12RecordingBufferSpec)
                for spec in message.recording
            )
        ):
            raise MonitorError("DLC12 recording buffer map exceeds native bounds")
        if (
            any(
                type(spec.allocation_size) is not int
                or not 0 < spec.allocation_size <= MAX_BYTES
                for spec in message.recording
            )
            or sum(spec.allocation_size for spec in message.recording) > MAX_BYTES
        ):
            raise MonitorError(
                "DLC12 recording allocation exceeds aggregate byte budget"
            )
        if (
            len(selected.source_identity) != 7
            or selected.database_sha256 != selected.source_identity[1]
            or any(
                spec.selected.database_sha256 != selected.database_sha256
                or spec.selected.source_identity != selected.source_identity
                for spec in message.recording
            )
        ):
            raise MonitorError(
                "DLC12 recording metadata belongs to a different selected source"
            )
        if any(spec.selected != selected for spec in message.recording):
            raise MonitorError(
                "DLC12 recording metadata differs from the selected acquisition plan"
            )
        buffers = tuple(spec.native() for spec in message.recording)
        if len({buffer.value_before_buffer for buffer in buffers}) > 1:
            # Derived6e20 rejects every secondary index before category dispatch.
            return DLC12ControlResult(command, 0xC0050001)
        if command == 0x57 and not buffers:
            raise MonitorError(
                "DLC12 recording settings require concrete selected buffer metadata"
            )
        if buffers and buffers[0].value_before_buffer != selected.buffer_468:
            raise MonitorError(
                "DLC12 recording first buffer is not the selected primary"
            )
        if self.runtime is not None and self.runtime.created:
            self.runtime.close()
        self.slots = [None, None, None]
        self.slot_categories = [selected.buffer_468, None, None]
        self.errors = [0, 0, 0]
        self.readers = {}
        self.received_bytes = 0
        for buffer in buffers:
            self.register_buffer(buffer)
        self.runtime = DLC12MonitorRuntime(selected, self.client)
        self.runtime.setup(timeout=timeout, cancelled=cancelled)
        self.runtime.start(timeout=timeout, cancelled=cancelled)
        self.active_mask = selected.packing.mode
        self.readers.setdefault(
            selected.buffer_468,
            NativeMonitorPacketReader(selected.frame_sizes, phase=0),
        )
        if command == 0x57:
            settings = DLC12RecordingSettings(
                tuple(buffer for buffer in self.slots if buffer is not None),
                selected.commands,
            )
            primary: BaseException | None = None
            try:
                self._stop()
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - disposal follows even after stop failure
                primary = exc
            try:
                self.runtime.close()
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - preserve initial settings cleanup failure
                if primary is None:
                    primary = exc
                else:
                    primary.add_note(f"DLC12 settings disposal also failed: {exc}")
            if primary is not None:
                raise primary
            return DLC12ControlResult(command, 0, flags20=1, settings=settings)
        return DLC12ControlResult(command, 0, flags20=1)
