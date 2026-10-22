"""Original12/18 normal data-slot polling over concrete J2534 primitives.

The caller selects and opens no devices implicitly. The selected factory binds
P4 pair/packet and P5 data, active and monitor-system slots.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, TypeAlias

from scripts.data_monitor import (
    MonitorError,
    P5MonitorEvent,
    SelectedMonitorConnection,
    SelectedP4Monitor,
    SelectedP5CanConnection,
    SelectedP5DynamicMonitor,
    SelectedP5PollingMonitor,
)
from scripts.drive_recorder import (
    MAX_RECORDER_BYTES,
    NativeMonitorPacket,
    NativeRecorderCapture,
    RecorderCancelled,
)
from scripts.frame_transport import NativeFrameOperations, get_comm_frame
from scripts.monitor_instruments import OscPrimitives
from scripts.monitor_j2534 import (
    ALLOCATION,
    INVALID,
    OK,
    ActiveMonitorEvent,
    CommItem,
    DataMonitorEvent,
    DirectJ2534Worker,
    MonitorSystemEvent,
    PacketMonitorEvent,
    WorkerNotification,
    selected_worker_oscilloscope,
)
from scripts.monitor_legacy import dk_monitor_timing
from scripts.monitor_p5 import SelectedP5Monitor
from scripts.monitor_packet_a8 import SelectedPacketA8Monitor
from scripts.monitor_support import monitor_source_identity
from scripts.monitor_variable import (
    SelectedVariableMonitor,
    SelectedVariablePacketMonitor,
    VariableRuntimeTarget,
)
from scripts.native_communication import (
    CommunicationResult,
    NativeCommunication,
    NativeFrameController,
)
from scripts.profiles import VehicleProfile
from scripts.support import word
from scripts.toyota import ToyotaCodecError
from scripts.toyota_session import Limits

if TYPE_CHECKING:
    from scripts.frame_transport import NativeFrameReceive, NativeMultiMonOperations


PollPlan: TypeAlias = (
    SelectedP4Monitor
    | SelectedVariableMonitor
    | SelectedVariablePacketMonitor
    | SelectedPacketA8Monitor
    | SelectedP5PollingMonitor
    | SelectedP5DynamicMonitor
    | SelectedP5Monitor
)


@dataclass(frozen=True)
class RoutineNotice:
    request_id: int
    reply: bytes
    kind: Literal["normal", "abnormal", "before_drive"]


@dataclass(frozen=True)
class NormalOscilloscopeSelection:
    """Normal P4 category999 selection that invokes native set_measure_mode."""

    profile: VehicleProfile
    selected_ids: tuple[int, ...]
    provider: OscPrimitives
    measure_time_range: int | None = None
    forward_time_range: int | None = None


class Phase4PacketEvent(PacketMonitorEvent):
    """Native PacketDMP4 255e0/25910, distinct from P3 and flag9 A8."""

    def __init__(
        self,
        modes: tuple[tuple[int, bytes], ...],
        frame_sizes: tuple[tuple[int, int], ...],
        *,
        timeout: int,
        pickup_spans: tuple[tuple[int, int], ...] = (),
    ):
        if (
            not isinstance(modes, tuple)
            or not 1 <= len(modes) <= 2
            or any(
                not isinstance(mode, tuple)
                or len(mode) != 2
                or type(mode[0]) is not int
                or mode[0] not in (1, 6)
                or not isinstance(mode[1], bytes)
                or not 1 <= len(mode[1]) <= 64
                for mode in modes
            )
        ):
            raise MonitorError(
                "P4 packet setup requires one or two bounded A1 modes", INVALID
            )
        if len(modes) == 2 and tuple(mode for mode, _ in modes) != (6, 1):
            raise MonitorError("P4 mixed packet order must be modes6,1", INVALID)
        super().__init__(
            modes[0][0],
            modes[0][1],
            frame_sizes,
            timeout=timeout,
            pickup_spans=pickup_spans,
        )
        self.modes = modes
        self.items = [
            CommItem(b"\xa1" + bytes((mode,)) + body, status=7) for mode, body in modes
        ]
        self.items.append(
            CommItem(b"\xa2" + bytes(mode for mode, _ in modes), timeout, 9)
        )
        self.first_length = self.raw_length
        if len(modes) == 2:
            body = modes[0][1]
            self.first_length = 0
            index = 0
            while index < len(body):
                if index + 2 > len(body) or index + 2 + body[index + 1] > len(body):
                    raise MonitorError(
                        "P4 mode6 selection descriptor is truncated", INVALID
                    )
                count = body[index + 1]
                self.first_length += count
                index += count + 2
            if not 0 < self.first_length < self.raw_length:
                raise MonitorError(
                    "P4 mixed packet partitions exceed selected storage", INVALID
                )
        self.received_modes: set[int] = set()

    def check_rcv_frame(self, reply: bytes, tick: int) -> int:
        if not isinstance(reply, bytes) or not reply or len(reply) > 4096:
            return INVALID
        if reply[0] != 0xE2:
            return super().check_rcv_frame(reply, tick)
        if type(tick) is not int or not 0 <= tick <= 0xFFFFFFFF or len(reply) < 3:
            return 0xE0000104
        mode = reply[1]
        if mode not in (1, 6):
            return 0xE0000104
        mixed = len(self.modes) == 2
        size = (
            self.first_length
            if mixed and mode == 6
            else self.raw_length - self.first_length
            if mixed
            else self.raw_length
        )
        offset = self.first_length if mixed and mode == 1 else 0
        if len(reply) - 2 < size or mode == 1 and len(reply) - 2 != size:
            return 0xE0000104
        self.data[offset : offset + size] = reply[2 : 2 + size]
        self.received_modes.add(mode)
        if not mixed or self.received_modes == {1, 6}:
            self._write_packet(tick)
            self.received_modes.clear()
        if self.item.status not in (13, 14):
            self.item.status = 12
        return OK


class Phase5ActiveEvent:
    """Actual Phase5AT a080/a430/a520 with its retained stop-command queue."""

    def __init__(self, start: bytes, stop: bytes, *, active_type: int, delay: int = 0):
        self.items: list[CommItem] = []
        self.end_items: list[CommItem] = []
        self.request = b""
        self.stopped = False
        self.retained_bytes = 0
        self.append(start, stop, active_type=active_type, delay=delay)

    @property
    def item(self) -> CommItem:
        return self.items[0]

    @property
    def info(self) -> int:
        if not self.request:
            return 0
        control = self.request[3] if self.request[0] == 0x2F else self.request[1]
        return (
            (2 if control == 3 else 3)
            if self.request[0] == 0x2F
            else (4 if control == 1 else 5)
        )

    def append(
        self, start: bytes, stop: bytes, *, active_type: int, delay: int = 0
    ) -> None:
        if (
            type(active_type) is not int
            or active_type not in (0, 1)
            or type(delay) is not int
            or not 0 <= delay <= 65535
            or any(
                not isinstance(body, bytes) or not 3 <= len(body) <= 4095
                for body in (start, stop)
            )
        ):
            raise MonitorError(
                "P5 active setup requires bounded bodies, type and delay", INVALID
            )
        if (
            self.stopped
            or len(self.items) + len(self.end_items) >= 65535
            or self.retained_bytes + len(start) + len(stop) + 2 > MAX_RECORDER_BYTES
        ):
            raise MonitorError(
                "P5 active queue exceeds lifecycle or allocation budget", ALLOCATION
            )
        service = 0x2F if active_type == 0 else 0x31
        self.items.append(CommItem(bytes((service,)) + start, delay))
        self.retained_bytes += len(start) + 1
        end = bytes((service,)) + stop
        for item in self.end_items:
            if service == 0x2F and item.request[0] == service:
                if item.request[1:3] == end[1:3]:
                    return
                if delay or any(command.delay for command in self.items):
                    raise MonitorError(
                        "Native P5 different IO controls cannot retain timers", INVALID
                    )
            if (
                service == 0x31
                and item.request[0] == service
                and item.request[2:4] == end[2:4]
            ):
                return
        self.end_items.append(CommItem(end))
        self.retained_bytes += len(end)

    def advance(self) -> None:
        if self.item.status not in (0, 1, 2) and len(self.items) > 1:
            self.retained_bytes -= len(self.items.pop(0).request)

    def get_snd_frame(self, tick: int) -> bytes:
        if type(tick) is not int or not 0 <= tick <= 0xFFFFFFFF:
            raise MonitorError("P5 active tick must fit uint32", INVALID)
        self.request = self.item.request
        self.item.status = 1
        return self.request

    def check_rcv_frame(self, reply: bytes, tick: int) -> int:
        if (
            not isinstance(reply, bytes)
            or not reply
            or len(reply) > 65535
            or type(tick) is not int
            or not 0 <= tick <= 0xFFFFFFFF
        ):
            return INVALID
        if self.request[0] == 0x2F:
            if reply[0] != 0x6F or len(reply) < 3:
                return INVALID
            control = self.request[3]
            if control not in (0, 3):
                return OK
            if control == 3:
                self.item.next_send = (
                    (tick + self.item.delay) & 0xFFFFFFFF if self.item.delay else 0
                )
                self.item.status = 3 if self.item.delay else 4
                return OK
        else:
            if reply[0] != 0x71:
                return INVALID
            control = self.request[1]
            if control not in (1, 2):
                return OK
            if control == 1:
                self.item.status, self.item.next_send = 4, 0
                return OK
        self.item.next_send = 0
        self.item.status = 5 if len(self.items) == 1 else 4
        return OK

    def stop(self) -> int:
        if self.end_items:
            self.items = self.end_items
            self.end_items = []
            self.retained_bytes = sum(len(item.request) for item in self.items)
        self.stopped = True
        return OK


class Phase5SystemEvent(MonitorSystemEvent):
    """P5 MS e470/e640 shares literal08/48 fields with the P4 event."""

    def append(self, body: bytes) -> None:
        if not isinstance(body, bytes) or len(body) > 4095:
            raise MonitorError("P5 monitor-system body exceeds storage", INVALID)
        # Native MonitorSystemSend makes the newly appended node current.
        self.items = [CommItem(b"\x08" + body)]
        self.index = 0


def selected_poll_event(
    operations: NativeFrameOperations,
    plan: PollPlan,
    *,
    routine_info: bool,
) -> DataMonitorEvent | P5MonitorEvent:
    """Bind actual producer metadata to the corresponding native event class."""
    if (
        not isinstance(operations, NativeFrameOperations)
        or operations.native_variant != "normal"
        and not (
            isinstance(
                plan,
                (SelectedP5PollingMonitor, SelectedP5DynamicMonitor, SelectedP5Monitor),
            )
            and operations.native_variant == "psa"
            and operations.bus_id & 15 == 2
            and operations.ecu_flags & 0x1F == 0x14
        )
    ):
        raise MonitorError(
            "Normal polling requires selected normal frame operations", INVALID
        )
    if not isinstance(
        plan,
        (
            SelectedP4Monitor,
            SelectedVariableMonitor,
            SelectedVariablePacketMonitor,
            SelectedPacketA8Monitor,
            SelectedP5PollingMonitor,
            SelectedP5DynamicMonitor,
            SelectedP5Monitor,
        ),
    ):
        raise MonitorError("Normal polling requires a concrete selected plan", INVALID)
    if plan.definitions.source_identity != monitor_source_identity(
        operations.profile, ""
    ):
        raise MonitorError(
            "Normal polling plan belongs to another selected source", INVALID
        )
    if plan.source_build != operations.native_build:
        raise MonitorError(
            "Normal polling source build differs from selected operations", INVALID
        )
    if type(routine_info) is not bool:
        raise MonitorError("Routine information observation must be boolean", INVALID)
    if isinstance(
        plan,
        (
            SelectedP4Monitor,
            SelectedVariableMonitor,
            SelectedVariablePacketMonitor,
            SelectedPacketA8Monitor,
        ),
    ):
        setup = next(
            (item for item in plan.commands.setup if item.command_id == 0x10A), None
        )
        mode = (
            plan.packing.mode_mask
            if isinstance(plan, (SelectedP4Monitor, SelectedVariableMonitor))
            else plan.packing.mode
        )
        if setup is None or mode not in (0x10, 0x20):
            raise MonitorError(
                "Normal pair polling requires P4 pair setup, not packet setup", INVALID
            )
        data_type, pairs = setup.values[2:4]
        if type(data_type) is not int or not isinstance(pairs, tuple):
            raise MonitorError("P4 pair setup is malformed", INVALID)
        if any(
            not isinstance(pair, tuple)
            or len(pair) != 2
            or any(type(v) is not int or not 0 <= v <= 255 for v in pair)
            for pair in pairs
        ):
            raise MonitorError("P4 pair entries must contain two bytes", INVALID)
        return DataMonitorEvent(
            data_type,
            bytes(pair[0] for pair in pairs),
            bytes(pair[1] for pair in pairs),
            sum(size for _, size in plan.frame_sizes),
            pickup_spans=plan.pickup_spans,
        )
    if isinstance(plan, SelectedP5DynamicMonitor):
        ids = tuple(
            zip(plan.outcome.plan.read_ids, plan.outcome.plan.read_lengths)
        ) + tuple(
            (item.did, dict(plan.selection.full_lengths)[item.did])
            for item in plan.outcome.plan.remaining
        )
    else:
        ids = plan.packing.data_ids
    event = P5MonitorEvent(
        ids,
        plan.dtc_requests if isinstance(plan, SelectedP5Monitor) else (),
        plan.routines if isinstance(plan, SelectedP5Monitor) else (),
        routine_info=routine_info,
        dtc_patterns=plan.dtc_patterns if isinstance(plan, SelectedP5Monitor) else (),
    )
    event.pickup_spans = plan.pickup_spans
    return event


def _validate_connection(
    operations: NativeFrameOperations,
    plan: PollPlan,
    connection: SelectedMonitorConnection,
) -> None:
    if (
        not isinstance(connection, SelectedMonitorConnection)
        or connection.source_identity != plan.definitions.source_identity
        or connection.bus_id != operations.bus_id
        or connection.protocol_record != operations.protocol_record
        or not plan.commands.setup
        or plan.commands.setup[0].values[:2]
        != (
            operations.profile.category,
            connection.address.request_id,
        )
    ):
        raise MonitorError(
            "Normal polling connection differs from selected transport", INVALID
        )
    header = (
        (5 if operations.bus_id & 0xF0 == 0x20 else 4)
        if operations.plan.send.protocol_id == 6
        else 3
    )
    expected = get_comm_frame(
        operations.profile,
        operations.plan.send.data[header:],
        bus_id=operations.bus_id,
        driver=operations.driver,
        diagnostic_mode=operations.diagnostic_mode,
    )
    if expected != operations.plan:
        raise MonitorError(
            "Normal polling lower plan differs from selected metadata", INVALID
        )


def _retained_normal_snapshot(operations: NativeFrameOperations) -> tuple[object, ...]:
    return (
        operations,
        operations.backend,
        operations.profile,
        operations.native_build,
        operations.driver,
        operations.device_kind,
        operations.bus_id,
        operations.diagnostic_mode,
        operations.channel,
        operations.owns_channel,
    )


def _validate_retained_normal_communication(
    operations: NativeFrameOperations,
    plan: PollPlan,
    connection: SelectedMonitorConnection,
    communication: NativeCommunication,
    *,
    snapshot: tuple[object, ...] | None = None,
) -> None:
    if (
        not isinstance(communication, NativeCommunication)
        or not isinstance(communication.operations, NativeFrameController)
        or communication.operations.operations is not operations
        or communication.profile is not operations.profile
        or communication.operations.profile is not communication.profile
        or communication.source_build != operations.native_build
        or communication.bus_id != operations.bus_id
        or communication.closed
        or not communication._shared_controller
        or not isinstance(communication._context_first_request, bytes)
        or len(communication._context_first_request) > 65535
        or communication.operations._context_failed
        or operations.poisoned
        or operations.device_kind != 8
        or not isinstance(plan, (SelectedP4Monitor, SelectedP5PollingMonitor))
        or plan.source_build != operations.native_build
        or plan.definitions.source_identity
        != monitor_source_identity(communication.profile, "")
    ):
        raise MonitorError(
            "Retained normal polling context differs from selected source", INVALID
        )
    current = _retained_normal_snapshot(operations)
    if snapshot is not None and (
        snapshot[0] is not current[0]
        or snapshot[1] is not current[1]
        or snapshot[2] is not current[2]
        or snapshot[3] != current[3]
        or snapshot[4] is not current[4]
        or snapshot[5:] != current[5:]
    ):
        raise MonitorError(
            "Retained normal polling lower or channel ownership changed", INVALID
        )
    if operations.channel is None:
        if operations.owns_channel:
            raise MonitorError(
                "Retained cold lower has inconsistent ownership", INVALID
            )
    elif not operations.owns_channel:
        raise MonitorError("Retained normal polling channel is borrowed", INVALID)
    communication._check()
    _validate_connection(operations, plan, connection)


class NormalPollingWorker:
    """Native normal P5 three-slot ThreadMain, one primitive per step.

    Native unbounded waits become explicit host deadline/call/storage budgets.
    A caller cannot inject a producer that claims a completed business stage.
    """

    def __init__(
        self,
        operations: NativeFrameOperations,
        plan: PollPlan,
        connection: SelectedMonitorConnection,
        *,
        routine_info: bool = False,
        active: Phase5ActiveEvent | None = None,
        system: Phase5SystemEvent | None = None,
        system_connection: SelectedP5CanConnection | None = None,
        security_release: bool = False,
        timeout: float = 30,
        max_steps: int = 65535,
        max_packets: int = 65535,
        max_bytes: int = MAX_RECORDER_BYTES,
        clock: Callable[[], float] = time.monotonic,
        ticks: Callable[[], int] | None = None,
        cancelled: Callable[[], bool] = lambda: False,
        packet_sink: Callable[[NativeMonitorPacket], None] | None = None,
        communication: NativeCommunication | None = None,
    ):
        if communication is not None:
            _validate_retained_normal_communication(
                operations, plan, connection, communication
            )
        self.event = selected_poll_event(operations, plan, routine_info=routine_info)
        if communication is None:
            _validate_connection(operations, plan, connection)
        if (
            operations.device_kind != 8
            or communication is None
            and operations.channel is not None
            or operations.poisoned
        ):
            raise MonitorError(
                "Normal direct worker requires an admitted retained or fresh non-DMCI transport",
                INVALID,
            )
        if (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise MonitorError(
                "Normal polling deadline must be finite and positive", INVALID
            )
        if (
            any(
                type(limit) is not int or not 0 < limit <= 65535
                for limit in (max_steps, max_packets)
            )
            or type(max_bytes) is not int
            or not 0 < max_bytes <= MAX_RECORDER_BYTES
        ):
            raise MonitorError("Normal polling budget is invalid", ALLOCATION)
        if (
            active is not None
            and not isinstance(active, Phase5ActiveEvent)
            or system is not None
            and not isinstance(system, Phase5SystemEvent)
        ):
            raise MonitorError(
                "Normal P5 slots require concrete native event types", INVALID
            )
        if (active is not None or system is not None) and not isinstance(
            self.event, P5MonitorEvent
        ):
            raise MonitorError(
                "P4 common slots use the selected P4 worker factory", INVALID
            )
        if system is not None and (
            system_connection is None
            or system_connection.connection != connection
            or system_connection.source_build != operations.native_build
        ):
            raise MonitorError(
                "P5 system slot requires selected additional ID mapping", INVALID
            )
        if type(security_release) is not bool:
            raise MonitorError("P5 security-release flag must be boolean", INVALID)
        self.security_release, self.stop_fault = security_release, False
        self.active, self.system = active, system
        self.system_connection = system_connection
        self.slot = 2
        self.active_rids: list[int] = []
        self.active_drive, self.before_drive = False, True
        self.end_results: list[tuple[int, int]] = []
        self.operations, self.plan, self.connection = operations, plan, connection
        self.communication = communication
        if communication is not None:
            assert isinstance(communication.operations, NativeFrameController)
            self.controller = communication.operations
        else:
            self.controller = NativeFrameController(operations)
        self.retained_snapshot = (
            _retained_normal_snapshot(operations) if communication is not None else None
        )
        self.clock, self.ticks, self.cancelled = clock, ticks, cancelled
        self.timeout, self.max_steps, self.max_packets, self.max_bytes = (
            timeout,
            max_steps,
            max_packets,
            max_bytes,
        )
        self.packet_sink = packet_sink
        self.packets: list[NativeMonitorPacket] = []
        self.notifications: list[WorkerNotification] = []
        self.routine_notices: list[RoutineNotice] = []
        self.receive_times: list[int] = []
        self.steps = self.packet_count = self.byte_count = self.failures = 0
        self.state = "configured"
        self.owned = False
        self.original_cancelled: Callable[[], bool] | None = None
        self.original_defer_cancel_cleanup = operations.defer_cancel_cleanup
        self.last_clock: float | None = None
        self.deadline = 0.0
        self.request = b""
        self.send_timeout, self.receive_timeout = dk_monitor_timing(operations.profile)
        command = next(
            (item for item in plan.commands.setup if item.command_id in (0x10A, 0x119)),
            None,
        )
        attempts = (
            command.values[6 if command.command_id == 0x10A else 5] if command else 0
        )
        if type(attempts) is not int or not 0 <= attempts <= 0xFFFFFFFF:
            raise MonitorError("Selected native retry count is invalid", INVALID)
        self.attempts = attempts
        self.cleanup_error: BaseException | None = None
        self.clear_results: list[CommunicationResult] = []
        clear = tuple(item for item in plan.commands.setup if item.command_id == 0x11A)
        if len(clear) > 1:
            raise MonitorError(
                "Normal polling has duplicate clear-list registration", INVALID
            )
        self.clear_ids: tuple[int, ...] = ()
        if clear:
            values = clear[0].values
            if (
                len(values) != 2
                or values[0] != connection.address.request_id
                or not isinstance(values[1], bytes)
                or not 2 <= len(values[1]) <= 510
                or len(values[1]) % 2
            ):
                raise MonitorError(
                    "Normal polling clear-list registration is malformed", INVALID
                )
            self.clear_ids = tuple(
                int.from_bytes(values[1][index : index + 2], "little")
                for index in range(0, len(values[1]), 2)
            )
        dynamic = (
            plan.outcome
            if isinstance(plan, SelectedP5DynamicMonitor)
            else plan.packing.outcome
            if isinstance(plan, SelectedP5Monitor)
            else None
        )
        if dynamic is not None and self.clear_ids != dynamic.clear_ids:
            raise MonitorError(
                "Normal polling requires the exact selected native stop-clear list",
                INVALID,
            )

    def _now(self) -> float:
        now = self.clock()
        if (
            type(now) not in (int, float)
            or not math.isfinite(now)
            or self.last_clock is not None
            and now < self.last_clock
        ):
            raise MonitorError(
                "Normal polling clock is invalid or moved backwards", INVALID
            )
        self.last_clock = float(now)
        return float(now)

    def _check(self) -> None:
        self._alive()
        if self.steps >= self.max_steps:
            raise MonitorError("Normal polling call budget exceeded", ALLOCATION)
        self.steps += 1

    def _alive(self) -> None:
        if self._now() >= self.deadline:
            raise MonitorError("Normal polling deadline exceeded", INVALID)
        if self.cancelled():
            raise RecorderCancelled("Normal polling cancelled")

    def _tick(self) -> int:
        tick = (
            self.ticks()
            if self.ticks is not None
            else int(self._now() * 1000) & 0xFFFFFFFF
        )
        if type(tick) is not int or not 0 <= tick <= 0xFFFFFFFF:
            raise MonitorError("Normal polling tick must fit uint32", INVALID)
        return tick

    def start(self) -> int:
        if self.state != "configured":
            raise MonitorError(
                "Normal polling start requires configured state", INVALID
            )
        if self.communication is None:
            if self.operations.channel is not None or self.operations.poisoned:
                raise MonitorError(
                    "Normal polling requires a fresh owned transport", INVALID
                )
        else:
            _validate_retained_normal_communication(
                self.operations,
                self.plan,
                self.connection,
                self.communication,
                snapshot=self.retained_snapshot,
            )
        self.deadline = self._now() + self.timeout
        self._check()
        self.state = "opening"
        self.owned = True
        self.original_cancelled = self.operations.cancelled
        self.original_defer_cancel_cleanup = self.operations.defer_cancel_cleanup
        original_cancelled = self.original_cancelled
        self.operations.cancelled = lambda: original_cancelled() or self.cancelled()
        self.operations.defer_cancel_cleanup = True
        status = (
            0
            if self.communication is not None
            else self.operations.open(deadline=self.deadline)
        )
        self._alive()
        if not status and self.communication is not None:
            self.operations.apply_temporary_config(deadline=self.deadline)
        self.state = "fault" if status else "select"
        if not status and isinstance(self.event, DataMonitorEvent):
            self.event.start()
        return status or OK

    def expected_source(self) -> int:
        response = self.connection.address.response_id
        if response in (0, 0xFFFFFFFF):
            return int.from_bytes(
                self.operations.diagnostic_mode[8:12], "little"
            ) or word(self.connection.protocol_record, 8)
        if self.operations.bus_id & 15 not in (2, 8):
            return response & 255
        mode = self.connection.address.request_id & 0xC0000000
        return (
            response >> 8 & 0xFFF
            if mode == 0x80000000
            else response & 255
            if mode == 0xC0000000
            else response
        )

    def _error(self, *, negative: bool = False, data: bytes = b"") -> int:
        if self.slot == 0:
            assert self.active is not None
            base = {2: 0xE0000201, 3: 0xE0000205, 4: 0xE0000501, 5: 0xE0000505}.get(
                self.active.info, INVALID
            )
            code = base + int(negative) if base != INVALID else INVALID
        elif self.slot == 1:
            code = 0xE0000602 if negative else 0xE0000601
        elif isinstance(self.event, P5MonitorEvent):
            base = {0x22: 0xE0000301, 0x19: 0xE0000801, 0x31: 0xE0000509}[
                self.request[0]
            ]
            code = base + int(negative)
        else:
            code = {1: (0xE0000107, 0xE000010D), 0x21: (0xE0000108, 0xE000010E)}.get(
                self.request[0], (INVALID, INVALID)
            )[int(negative)]
        self.notifications.append(
            WorkerNotification(
                self.system_connection.additional_request_id
                if self.slot == 1 and self.system_connection is not None
                else self.connection.address.request_id,
                code,
                data[2] if negative and len(data) > 2 else 0,
            )
        )
        if self.slot == 0 and self.active is not None and self.active.info in (3, 5):
            self.stop_fault = True
            self.active.item.status = 5
            self.state = "select"
            return OK
        self.state = "idle"
        return code

    def step(self) -> int:
        if self.state not in ("select", "send", "receive", "idle"):
            raise MonitorError("Normal polling step requires running state", INVALID)
        self._check()
        if self.state == "idle":
            return OK
        if self.state == "select":
            tick = self._tick()
            for slot, event in ((0, self.active), (1, self.system)):
                if event is None:
                    continue
                event.advance()
                if event.item.status in (4, 5):
                    continue
                if event.item.status == 3:
                    if event.item.next_send <= tick:
                        event.item.status = 0
                        return OK
                    continue
                self.slot = slot
                self.request = event.get_snd_frame(tick)
                self.state = "send"
                return OK
            self.slot = 2
            self.request = (
                self.event.get_snd_frame(tick)
                if isinstance(self.event, DataMonitorEvent)
                else self.event.request
            )
            self.state = "send"
            return OK
        if self.state == "send":
            code = self.controller.send(
                self.request,
                timeout=self.send_timeout,
                initialization_mode=1,
                clear_rx=1,
                deadline=self.deadline,
            )
            self._alive()
            if code:
                self.failures += 1
                if self.slot != 2 or self.failures >= self.attempts:
                    return self._error()
            else:
                auxiliary = (
                    self.active
                    if self.slot == 0
                    else self.system
                    if self.slot == 1
                    else None
                )
                if auxiliary is not None:
                    auxiliary.item.status = 2
                self.state = "receive"
            return OK
        maximum = (
            65535
            if isinstance(self.event, P5MonitorEvent)
            and self.operations.native_build == 18
            and self.operations.bus_id == 0x14
            else 4096
        )
        reply = self.controller.receive(
            maximum=maximum,
            timeout=self.receive_timeout,
            argument_5=0,
            flags=100,
            deadline=self.deadline,
        )
        self._alive()
        reply_data = reply.data
        synthetic = (
            self.operations.native_build == 18
            and self.operations.ecu_flags & 0xE0 == 0x20
            and isinstance(self.event, P5MonitorEvent)
            and self.slot == 2
            and self.request[0] == 0x31
            and reply.code == 0x90020321
            and len(reply_data) >= 3
            and reply_data[2] in (0x24, 0x33)
        )
        if synthetic:
            # Native18 1262e: this specific RID failure becomes a zero-filled71.
            reply_data = b"\x71" + self.request[1:4] + bytes(maximum - 4)
        elif reply.code:
            if reply.code in (0x90020321, 0x90020323):
                return self._error(negative=True, data=reply_data)
            self.failures += 1
            if self.slot != 2 or self.failures >= self.attempts:
                return self._error()
            self.state = "send"
            return OK
        tick = self._tick()
        # ThreadMain resets its retry counter before checking the source address.
        self.failures = 0
        if self.operations.native_build == 18 and tick >= 2_000_000_000:
            if len(self.receive_times) >= self.max_steps:
                raise MonitorError(
                    "Normal polling receive-time budget exceeded", ALLOCATION
                )
            self.receive_times.append(tick)
        source = (
            self.system_connection.additional_response_id
            if self.slot == 1 and self.system_connection is not None
            else self.expected_source()
        )
        if (
            self.slot == 1
            or self.operations.native_build == 12
            or self.operations.bus_id & 15 != 4
        ) and reply.source_id != source:
            return OK
        if self.slot != 2:
            auxiliary = self.active if self.slot == 0 else self.system
            assert auxiliary is not None
            result = auxiliary.check_rcv_frame(reply_data, tick)
            if result != OK:
                return self._error()
            if self.slot == 0:
                assert self.active is not None
                info, status = self.active.info, self.active.item.status
                if info == 4:
                    self.notifications.append(
                        WorkerNotification(self.connection.address.request_id, 4)
                    )
                if status in (3, 4):
                    self.active_drive, self.before_drive = True, False
                    if info == 4 and self.operations.native_build == 18:
                        rid = int.from_bytes(self.request[2:4], "big")
                        if rid not in self.active_rids:
                            if len(self.active_rids) > 1:
                                self.active_rids.clear()
                            self.active_rids.append(rid)
                elif status == 5:
                    self.active_drive, self.before_drive = False, True
                    self.active_rids.clear()
            elif self.system_connection is not None:
                self.notifications.append(
                    WorkerNotification(self.system_connection.additional_request_id, 7)
                )
            self.state = "select"
            return OK
        try:
            if isinstance(self.plan, SelectedP5Monitor) and self.request[0] == 0x31:
                assert isinstance(self.event, P5MonitorEvent)
                index = (
                    self.event.index
                    - len(self.plan.packing.data_ids)
                    - len(self.plan.dtc_requests)
                )
                routine = self.plan.routines[index]
                if self.active_drive and (
                    self.operations.native_build == 12
                    or routine.rid == 0
                    or routine.rid in self.active_rids
                ):
                    if routine.check_status(
                        reply_data, routine_info=self.event.routine_info
                    ):
                        self.routine_notices.append(
                            RoutineNotice(
                                self.connection.address.request_id, reply_data, "normal"
                            )
                        )
                        self.active_drive = False
                    if routine.check_status(
                        reply_data, routine_info=self.event.routine_info, abnormal=True
                    ):
                        self.routine_notices.append(
                            RoutineNotice(
                                self.connection.address.request_id,
                                reply_data,
                                "abnormal",
                            )
                        )
                        self.state = "idle"
                        return OK
                if self.before_drive:
                    # CheckAbnormalBeforeDrive compares the separate stop-status list.
                    from dataclasses import replace

                    if replace(routine, normal=routine.stop).check_status(
                        reply_data, routine_info=self.event.routine_info
                    ):
                        self.routine_notices.append(
                            RoutineNotice(
                                self.connection.address.request_id,
                                reply_data,
                                "before_drive",
                            )
                        )
                        self.state = "idle"
                        return OK
            if isinstance(self.event, DataMonitorEvent):
                result = self.event.check_rcv_frame(reply_data, tick)
                if result != OK:
                    return self._error()
                packets = tuple(self.event.packets)
                self.event.packets.clear()
                self.event.pending_packet_bytes = 0
            else:
                packet = self.event.accept(reply_data, tick)
                packets = () if packet is None else (NativeMonitorPacket(*packet),)
        except MonitorError:
            return self._error()
        for packet in packets:
            size = 4 + len(packet.payload)
            if (
                self.packet_count >= self.max_packets
                or self.byte_count + size > self.max_bytes
            ):
                raise MonitorError("Normal polling packet budget exceeded", ALLOCATION)
            self.packet_count += 1
            self.byte_count += size
            if self.packet_sink is None:
                self.packets.append(packet)
            else:
                self.packet_sink(packet)
        self.state = "select"
        return OK

    def stop(self) -> int:
        if self.state not in ("select", "send", "receive", "idle"):
            raise MonitorError("Normal polling stop requires running state", INVALID)
        original = self.operations.cancelled
        try:
            self.operations.cancelled = lambda: False
            self.active_rids.clear()
            if self.active is not None and self.operations.poisoned:
                self.active.stop()
            if self.active is not None and not self.operations.poisoned:
                self.active.stop()
                until, calls = self._now() + self.timeout, 0
                while self.active.item.status != 5:
                    if calls >= self.max_steps or self._now() >= until:
                        raise MonitorError(
                            "P5 active end sequence exceeds cleanup budget", ALLOCATION
                        )
                    calls += 1
                    request = self.active.get_snd_frame(self._tick())
                    sent = self.controller.send(
                        request,
                        timeout=self.send_timeout,
                        initialization_mode=1,
                        clear_rx=1,
                        deadline=until,
                    )
                    received = sent
                    if sent == 0:
                        if calls >= self.max_steps or self._now() >= until:
                            raise MonitorError(
                                "P5 active end receive exceeds cleanup budget",
                                ALLOCATION,
                            )
                        calls += 1
                        reply = self.controller.receive(
                            maximum=65535
                            if self.operations.native_build == 18
                            and self.operations.bus_id == 0x14
                            else 4096,
                            timeout=self.receive_timeout,
                            argument_5=0,
                            flags=100,
                            deadline=until,
                        )
                        received = reply.code
                        if received == 0:
                            received = self.active.check_rcv_frame(reply.data, 0)
                    self.end_results.append((sent, received))
                    self.active.item.status = 5
                    self.active.advance()
            if self.clear_ids and not self.operations.poisoned:
                try:
                    selected = self.operations.profile.frame_records(0xD4)[0]
                except (ToyotaCodecError, ValueError, IndexError) as error:
                    # Native GetCommFrmInfo failure skips the entire best-effort clear.
                    self.cleanup_error = error
                else:
                    if len(selected.frame.request) < 4:
                        raise MonitorError(
                            "Selected D4 clear request is truncated", INVALID
                        )
                    communication = NativeCommunication(
                        self.operations.profile,
                        self.controller,
                        f"category:{self.operations.profile.category}",
                        bus_id=self.operations.bus_id,
                        source_build=self.operations.native_build,
                        limits=Limits(seconds=self.timeout, exchanges=self.max_steps),
                        cancelled=lambda: False,
                        clock=self.clock,
                    )
                    for did in self.clear_ids:
                        request = (
                            selected.frame.request[:2]
                            + did.to_bytes(2, "big")
                            + selected.frame.request[4:]
                        )
                        self.clear_results.append(
                            communication.execute(selected, request, extended=True)
                        )
            if isinstance(self.event, DataMonitorEvent):
                self.event.stop()
        finally:
            self.operations.cancelled = original
            self.state = "stopped"
        return OK

    def close(self) -> int:
        if self.state == "closed" or not self.owned:
            return 0
        original = self.operations.cancelled
        failure: BaseException | None = None
        until: float | None = None
        try:
            self.operations.cancelled = lambda: False
            try:
                until = self._now() + self.timeout
            except BaseException as error:  # noqa: BLE001 - release after broken host clock
                failure = error
            if self.communication is not None and not self.operations.poisoned:
                try:
                    self.operations.restore_temporary_config(deadline=until)
                except BaseException as error:  # noqa: BLE001 - disconnect still releases the owner
                    failure = failure or error
            try:
                status = self.controller.disconnect(
                    int(self.security_release or self.stop_fault), deadline=until
                )
            except BaseException as error:  # noqa: BLE001 - retain the primary cleanup failure
                if failure is None:
                    failure = error
                else:
                    failure.add_note(f"Normal polling disconnect failed: {error}")
                status = INVALID
        finally:
            self.operations.cancelled = (
                self.original_cancelled
                if self.original_cancelled is not None
                else original
            )
            self.operations.defer_cancel_cleanup = self.original_defer_cancel_cleanup
            self.state = "closed" if self.operations.channel is None else "fault"
        if failure is not None:
            raise failure
        return status

    def run(self, packet_count: int) -> NativeRecorderCapture:
        if type(packet_count) is not int or not 0 < packet_count <= self.max_packets:
            raise MonitorError("Requested packet count exceeds budget", ALLOCATION)
        primary: BaseException | None = None
        try:
            code = self.start()
            if code != OK:
                raise MonitorError("Normal polling open failed", code)
            while self.packet_count < packet_count:
                code = self.step()
                if code != OK:
                    raise MonitorError("Normal polling acquisition failed", code)
            self.stop()
            return NativeRecorderCapture(0, tuple(self.packets))
        except BaseException as error:
            primary = error
            raise
        finally:
            if self.state in ("select", "send", "receive", "idle"):
                try:
                    self.stop()
                except BaseException as error:  # noqa: BLE001 - always release after stop failure
                    self.cleanup_error = error
                    if primary is not None:
                        primary.add_note(f"Normal polling stop failed: {error}")
                    else:
                        primary = error
            try:
                status = self.close()
                if status:
                    raise MonitorError("Normal polling close failed", status)
            except BaseException as error:
                self.cleanup_error = error
                if primary is None:
                    raise
                primary.add_note(f"Normal polling cleanup failed: {error}")


def selected_normal_poll_worker(
    operations: NativeFrameOperations,
    plan: PollPlan,
    connection: SelectedMonitorConnection,
    *,
    routine_info: bool = False,
    oscilloscope: NormalOscilloscopeSelection | None = None,
    active: ActiveMonitorEvent | Phase5ActiveEvent | None = None,
    system: MonitorSystemEvent | Phase5SystemEvent | None = None,
    system_connection: SelectedP5CanConnection | None = None,
    security_release: bool = False,
    timeout: float = 30,
    max_steps: int = 65535,
    max_packets: int = 65535,
    max_bytes: int = MAX_RECORDER_BYTES,
    clock: Callable[[], float] = time.monotonic,
    ticks: Callable[[], int] | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    packet_sink: Callable[[NativeMonitorPacket], None] | None = None,
    communication: NativeCommunication | None = None,
) -> DirectJ2534Worker | NormalPollingWorker:
    """Actual normal P4 packet/pair or P5 constructor; A8 remains distinct."""
    if communication is not None and (
        oscilloscope is not None
        or not isinstance(plan, (SelectedP4Monitor, SelectedP5PollingMonitor))
    ):
        raise MonitorError(
            "Retained normal polling supports only selected P4/P5 plans", INVALID
        )
    if oscilloscope is not None and (
        not isinstance(oscilloscope, NormalOscilloscopeSelection)
        or not isinstance(plan, SelectedP4Monitor)
    ):
        raise MonitorError(
            "Normal combined oscilloscope requires selected P4 data and category999",
            INVALID,
        )
    if isinstance(
        plan,
        (SelectedP4Monitor, SelectedVariableMonitor, SelectedVariablePacketMonitor),
    ):
        if (
            not isinstance(operations, NativeFrameOperations)
            or operations.native_variant != "normal"
            or operations.device_kind != 8
            or plan.definitions.source_identity
            != monitor_source_identity(operations.profile, "")
            or plan.source_build != operations.native_build
        ):
            raise MonitorError(
                "Normal P4 factory source identity/build differs", INVALID
            )
        _validate_connection(operations, plan, connection)
        if (
            active is not None
            and not isinstance(active, ActiveMonitorEvent)
            or system is not None
            and (
                not isinstance(system, MonitorSystemEvent)
                or isinstance(system, Phase5SystemEvent)
            )
        ):
            raise MonitorError(
                "Normal P4 slots require actual P4 active/system events", INVALID
            )
        mode_mask = (
            plan.packing.mode
            if isinstance(plan, SelectedVariablePacketMonitor)
            else plan.packing.mode_mask
        )
        if isinstance(
            plan, (SelectedVariableMonitor, SelectedVariablePacketMonitor)
        ) and mode_mask not in (1, 4, 5, 0x10, 0x20):
            raise MonitorError(
                "Native variable setup rejects this child mode", 0xC005100D
            )
        if mode_mask in (1, 4, 5):
            command = next(
                (item for item in plan.commands.setup if item.command_id == 0x109), None
            )
            if command is None or len(command.values) != 6:
                raise MonitorError("Normal P4 packet has no native109 setup", INVALID)
            raw_modes = command.values[2]
            timeout_value = command.values[5]
            if not isinstance(raw_modes, tuple) or type(timeout_value) is not int:
                raise MonitorError("Normal P4 A1 setup has invalid fields", INVALID)
            modes: list[tuple[int, bytes]] = []
            for mode in raw_modes:
                if (
                    not isinstance(mode, tuple)
                    or len(mode) != 2
                    or type(mode[0]) is not int
                    or not isinstance(mode[1], bytes)
                ):
                    raise MonitorError("Normal P4 A1 descriptor is invalid", INVALID)
                modes.append((mode[0], mode[1]))
            event = Phase4PacketEvent(
                tuple(modes),
                plan.frame_sizes,
                timeout=timeout_value,
                pickup_spans=plan.pickup_spans,
            )
            attempts = 0
        else:
            event = selected_poll_event(operations, plan, routine_info=routine_info)
            assert isinstance(event, DataMonitorEvent)
            attempts = 3
        send_timeout, receive_timeout = dk_monitor_timing(operations.profile)
        worker = DirectJ2534Worker(
            operations,
            event,
            request_id=connection.address.request_id,
            response_id=connection.address.response_id,
            default_source=int.from_bytes(operations.diagnostic_mode[8:12], "little")
            or word(connection.protocol_record, 8),
            full_source=True,
            native_worker_class="base"
            if isinstance(
                plan, (SelectedVariableMonitor, SelectedVariablePacketMonitor)
            )
            else None,
            attempts=attempts,
            send_timeout=send_timeout,
            receive_timeout=receive_timeout,
            active=active,
            system=system,
            timeout=timeout,
            max_steps=max_steps,
            max_packets=max_packets,
            max_bytes=max_bytes,
            clock=clock,
            ticks=ticks,
            cancelled=cancelled,
            packet_sink=packet_sink,
            communication=communication,
        )
        if oscilloscope is not None:
            selected_worker_oscilloscope(
                worker,
                oscilloscope.profile,
                oscilloscope.selected_ids,
                oscilloscope.provider,
                measure_time_range=oscilloscope.measure_time_range,
                forward_time_range=oscilloscope.forward_time_range,
            )
        return worker
    if (
        active is not None
        and not isinstance(active, Phase5ActiveEvent)
        or system is not None
        and not isinstance(system, Phase5SystemEvent)
    ):
        raise MonitorError(
            "Normal P5 slots require actual P5 active/system events", INVALID
        )
    return NormalPollingWorker(
        operations,
        plan,
        connection,
        routine_info=routine_info,
        active=active,
        system=system,
        system_connection=system_connection,
        security_release=security_release,
        timeout=timeout,
        max_steps=max_steps,
        max_packets=max_packets,
        max_bytes=max_bytes,
        clock=clock,
        ticks=ticks,
        cancelled=cancelled,
        packet_sink=packet_sink,
        communication=communication,
    )


class MultiMonitorPollingWorker:
    """DataListIF MultiMon worker, distinct from the seven-state Dual controller.

    Two native non-voltage entries share one concrete lower channel. The outer
    variable controller owns its optional third voltage slot and command queue.
    """

    def __init__(
        self,
        operations: NativeMultiMonOperations,
        targets: tuple[VariableRuntimeTarget, ...],
        *,
        active: ActiveMonitorEvent | None = None,
        system: MonitorSystemEvent | None = None,
        timeout: float = 30,
        max_steps: int = 65535,
        max_packets: int = 65535,
        max_bytes: int = MAX_RECORDER_BYTES,
        clock: Callable[[], float] = time.monotonic,
        ticks: Callable[[], int] | None = None,
        cancelled: Callable[[], bool] = lambda: False,
    ):
        from scripts.frame_transport import NativeMultiMonOperations

        if not isinstance(operations, NativeMultiMonOperations):
            raise MonitorError(
                "MultiMon requires concrete selected lower operations", INVALID
            )
        if operations.control.connected_device != 8:
            raise MonitorError("Direct MultiMon requires observed device8", INVALID)
        if (
            operations.control.channel is not None
            or operations.operations.poisoned
            or operations.control.poisoned
        ):
            raise MonitorError("MultiMon requires fresh owned lower transport", INVALID)
        if not isinstance(targets, tuple) or not 1 <= len(targets) <= 2:
            raise MonitorError(
                "MultiMon requires one or two non-voltage targets", INVALID
            )
        if any(not isinstance(target, VariableRuntimeTarget) for target in targets):
            raise MonitorError("MultiMon requires selected variable targets", INVALID)
        if (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or timeout <= 0
            or any(
                type(limit) is not int or not 0 < limit <= 65535
                for limit in (max_steps, max_packets)
            )
            or type(max_bytes) is not int
            or not 0 < max_bytes <= MAX_RECORDER_BYTES
        ):
            raise MonitorError("MultiMon host budget is invalid", ALLOCATION)
        if (
            active is not None
            and type(active) is not ActiveMonitorEvent
            or system is not None
            and type(system) is not MonitorSystemEvent
        ):
            raise MonitorError(
                "MultiMon common slots require native P4 events", INVALID
            )
        self.operations, self.targets = operations, targets
        self.original_cancelled: Callable[[], bool] | None = None
        self.original_defer_cancel_cleanup = operations.defer_cancel_cleanup
        self.connections: list[SelectedMonitorConnection] = []
        self.events: list[DataMonitorEvent] = []
        self.attempts: list[int] = []
        self.timings: list[tuple[int, int]] = []
        for target in targets:
            target.check()
            plan = target.plan
            mode = (
                plan.packing.mode
                if isinstance(plan, SelectedVariablePacketMonitor)
                else plan.packing.mode_mask
                if isinstance(plan, SelectedVariableMonitor)
                else None
            )
            if not isinstance(
                plan, (SelectedVariableMonitor, SelectedVariablePacketMonitor)
            ) or mode not in (0x10, 0x20):
                # MultiMon overrides pair setup only: inherited packet setup does
                # not populate the per-entry event pointer used by native start.
                raise MonitorError("Native MultiMon entry requires pair setup", INVALID)
            if (
                target.connection is None
                or plan.source_build != operations.native_build
            ):
                raise MonitorError(
                    "MultiMon selected connection/build differs", INVALID
                )
            self.connections.append(target.connection)
            command = next(
                (item for item in plan.commands.setup if item.command_id == 0x10A), None
            )
            if command is None or len(command.values) != 8:
                raise MonitorError("MultiMon selected pair command is absent", INVALID)
            if command.values[:2] != (
                target.cache.profile.category,
                target.connection.address.request_id,
            ):
                raise MonitorError(
                    "MultiMon setup differs from selected entry identity", INVALID
                )
            data_type, pairs, attempts = (
                command.values[2],
                command.values[3],
                command.values[6],
            )
            if (
                type(data_type) is not int
                or not isinstance(pairs, tuple)
                or type(attempts) is not int
                or not 0 <= attempts <= 0xFFFFFFFF
            ):
                raise MonitorError(
                    "MultiMon selected pair command is malformed", INVALID
                )
            if any(
                not isinstance(pair, tuple)
                or len(pair) != 2
                or any(
                    type(value) is not int or not 0 <= value <= 255 for value in pair
                )
                for pair in pairs
            ):
                raise MonitorError("MultiMon pair entries require two bytes", INVALID)
            self.events.append(
                DataMonitorEvent(
                    data_type,
                    bytes(pair[0] for pair in pairs),
                    bytes(pair[1] for pair in pairs),
                    sum(size for _, size in plan.frame_sizes),
                    pickup_spans=plan.pickup_spans,
                )
            )
            self.attempts.append(attempts)
            self.timings.append(dk_monitor_timing(target.cache.profile))
        registered = tuple(operations.targets)
        if len(registered) != len(targets):
            raise MonitorError("MultiMon lower entry count differs", INVALID)
        for actual, selected in zip(registered, targets):
            connection = selected.connection
            assert connection is not None
            if (
                actual.ecu,
                actual.command_id,
                actual.protocol,
                actual.entry_parameter,
                actual.request_id,
                actual.response_id,
                actual.map_values,
            ) != (
                selected.cache.ecu,
                selected.cache.profile.category,
                connection.bus_id,
                selected.entry_parameter,
                connection.address.request_id,
                connection.address.response_id,
                (
                    connection.can_parameter,
                    connection.can_byte_0,
                    connection.can_byte_1,
                ),
            ):
                raise MonitorError(
                    "MultiMon lower registration differs from selected IDMap", INVALID
                )
        self.active, self.system = active, system
        self.timeout, self.max_steps, self.max_packets, self.max_bytes = (
            timeout,
            max_steps,
            max_packets,
            max_bytes,
        )
        self.clock, self.ticks, self.cancelled = clock, ticks, cancelled
        self.last_clock: float | None = None
        self.deadline = 0.0
        self.steps = self.packet_count = self.byte_count = self.failures = 0
        self.cleanup_steps = 0
        self.index, self.restore_index, self.slot = 0, 0, 2
        self.request = b""
        self.packets: list[list[NativeMonitorPacket]] = [[] for _ in targets]
        self.notifications: list[WorkerNotification] = []
        self.state = "configured"
        self.owned = False
        self.cleanup_error: BaseException | None = None
        self.end_results: list[tuple[int, int]] = []
        self.setup_results: list[int] = []

    def _now(self) -> float:
        now = self.clock()
        if (
            type(now) not in (int, float)
            or not math.isfinite(now)
            or self.last_clock is not None
            and now < self.last_clock
        ):
            raise MonitorError("MultiMon clock is invalid or moved backwards", INVALID)
        self.last_clock = float(now)
        return float(now)

    def _check(self, *, cleanup: bool = False) -> None:
        if self._now() >= self.deadline:
            raise MonitorError("MultiMon deadline exceeded", INVALID)
        if not cleanup and self.cancelled():
            raise RecorderCancelled("MultiMon cancelled")
        used = self.cleanup_steps if cleanup else self.steps
        if used >= self.max_steps:
            raise MonitorError("MultiMon call budget exceeded", ALLOCATION)
        if cleanup:
            self.cleanup_steps += 1
        else:
            self.steps += 1
        for target in self.targets:
            if cleanup:
                if (
                    monitor_source_identity(target.cache.profile, target.cache.ecu)
                    != target.plan.source_identity
                ):
                    raise MonitorError(
                        "MultiMon selected source changed during cleanup", INVALID
                    )
            else:
                target.check()

    def _tick(self) -> int:
        value = (
            self.ticks()
            if self.ticks is not None
            else int(self._now() * 1000) & 0xFFFFFFFF
        )
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise MonitorError("MultiMon tick must fit DWORD", INVALID)
        return value

    def start(self) -> int:
        if self.state != "configured":
            raise MonitorError("MultiMon start requires configured state", INVALID)
        if (
            self.operations.control.channel is not None
            or self.operations.operations.poisoned
            or self.operations.control.poisoned
        ):
            raise MonitorError("MultiMon requires fresh owned lower transport", INVALID)
        self.deadline = self._now() + self.timeout
        self._check()
        self.original_cancelled = self.operations.cancelled
        self.original_defer_cancel_cleanup = self.operations.defer_cancel_cleanup
        original = self.original_cancelled
        self.operations.cancelled = lambda: self.cancelled() or original()
        self.operations.defer_cancel_cleanup = True
        self.state, self.owned = "opening", True
        status = self.operations.connect_multi_mon(deadline=self.deadline)
        self.setup_results.append(status)
        for target, event in zip(self.targets, self.events):
            self._check()
            status = self.operations.entry_comm_system_info(
                target.cache.profile.category,
                self.connections[self.targets.index(target)].bus_id,
                target.entry_parameter,
                deadline=self.deadline,
            )
            # Native2d340 ignores these scalar setup statuses; host I/O
            # uncertainty still raises before acquisition can continue.
            self.setup_results.append(status)
            event.start()
        self._check()
        self.state = "select"
        return OK

    def _event(self) -> DataMonitorEvent:
        event = (
            self.active
            if self.slot == 0
            else self.system
            if self.slot == 1
            else self.events[self.index]
        )
        assert event is not None
        return event

    def _send(self, *, cleanup: bool = False) -> int:
        self._check(cleanup=cleanup)
        target = self.targets[self.index]
        return self.operations.send_multi_mon(
            target.cache.profile.category,
            self.request,
            timeout=self.timings[self.index][0],
            bus=self.connections[self.index].bus_id,
            argument_6=0,
            clear_rx=1,
            deadline=self.deadline,
        )

    def _receive(self, *, cleanup: bool = False) -> NativeFrameReceive:
        self._check(cleanup=cleanup)
        return self.operations.receive(
            maximum=4096,
            timeout=self.timings[self.index][1],
            argument_5=0,
            flags=100,
            deadline=self.deadline,
        )

    def _error(
        self, *, negative: bool = False, data: bytes = b"", direct: int | None = None
    ) -> int:
        code = (
            direct
            if direct == 0xE00001CC and self.slot == 0
            else (0xE000010C if negative else 0xE0000106)
            if self.slot == 0
            else (0xE000010E if negative else 0xE0000108)
            if self.request[:1] == b"\x21"
            else 0xE0000102
        )
        self.notifications.append(
            WorkerNotification(
                self.connections[self.index].address.request_id,
                code,
                data[2] if negative and len(data) > 2 else 0,
            )
        )
        self.state = "idle"
        return code

    def step(self) -> int:
        if self.state not in ("select", "send", "receive", "idle"):
            raise MonitorError("MultiMon step requires running state", INVALID)
        self._check()
        if self.state == "idle":
            return OK
        if self.state == "select":
            tick = self._tick()
            for slot, event in ((0, self.active), (1, self.system)):
                if event is None:
                    continue
                if slot == 0:
                    event.advance()
                    if event.item.status in (4, 5):
                        continue
                    if event.item.status == 3:
                        if event.item.next_send <= tick:
                            event.item.status = 0
                            return OK
                        continue
                    if self.index:
                        self.restore_index, self.index = self.index, 0
                self.slot = slot
                self.request = event.get_snd_frame(tick)
                self.state = "send"
                return OK
            self.slot = 2
            self.request = self.events[self.index].get_snd_frame(tick)
            self.state = "send"
            return OK
        if self.state == "send":
            status = self._send()
            self._check()
            if status:
                self.failures += 1
                return (
                    self._error()
                    if self.slot != 2 or self.failures >= self.attempts[self.index]
                    else OK
                )
            self._event().set_status(2)
            self.state = "receive"
            return OK
        reply = self._receive()
        self._check()
        if reply.code:
            if reply.code in (0x90020321, 0x90020323):
                return self._error(negative=True, data=reply.data)
            self.failures += 1
            if self.slot == 2 and self.failures < self.attempts[self.index]:
                self.state = "send"
                return OK
            return self._error()
        self.failures = 0
        event = self._event()
        status = event.check_rcv_frame(reply.data, self._tick())
        if status != OK:
            return self._error(direct=status)
        # MultiMon intentionally has no ordinary source-ID filter.
        completed = bool(event.packets)
        for packet in event.packets:
            size = len(packet.payload) + 4
            if (
                self.packet_count >= self.max_packets
                or self.byte_count + size > self.max_bytes
            ):
                raise MonitorError("MultiMon packet storage exceeded", ALLOCATION)
            self.packet_count += 1
            self.byte_count += size
            self.packets[self.index].append(packet)
        event.packets.clear()
        event.pending_packet_bytes = 0
        if self.slot == 0 and self.restore_index:
            self.index, self.restore_index = self.restore_index, 0
        elif self.slot == 2 and completed:
            self.index = (self.index + 1) % len(self.targets)
        self.state = "select"
        return OK

    def stop(self) -> int:
        if self.state not in ("select", "send", "receive", "idle"):
            raise MonitorError("MultiMon stop requires running state", INVALID)
        self.deadline = self._now() + self.timeout
        previous = self.operations.cancelled
        self.cleanup_steps = 0
        try:
            self.operations.cancelled = lambda: False
            if self.active is not None and self.active.item.status != 5:
                self.active.stop()
                self.active.skip_end()
                self.index = 0
                self.request = self.active.get_snd_frame(self._tick())
                sent = self._send(cleanup=True)
                received = self._receive(cleanup=True).code if not sent else sent
                self.end_results.append((sent, received))
            for event in self.events:
                event.stop()
        finally:
            self.operations.cancelled = previous
            self.state = "stopped"
        return OK

    def close(self) -> int:
        if not self.owned or self.state == "closed":
            return 0
        failure: BaseException | None = None
        until: float | None = None
        previous_cancelled = self.operations.cancelled
        try:
            self.operations.cancelled = lambda: False
            try:
                until = self._now() + self.timeout
            except BaseException as error:  # noqa: BLE001 - resource release survives host clock failure
                failure = error
            status = self.operations.close(disconnect_flag=1, deadline=until)
        finally:
            self.operations.cancelled = (
                self.original_cancelled
                if self.original_cancelled is not None
                else previous_cancelled
            )
            self.operations.defer_cancel_cleanup = self.original_defer_cancel_cleanup
            self.state = (
                "closed" if self.operations.control.channel is None else "fault"
            )
        if failure is not None:
            raise failure
        return status

    def run(self, counts: tuple[int, ...]) -> tuple[NativeRecorderCapture, ...]:
        if (
            not isinstance(counts, tuple)
            or len(counts) != len(self.targets)
            or any(
                type(count) is not int or not 0 < count <= self.max_packets
                for count in counts
            )
            or sum(counts) > self.max_packets
        ):
            raise MonitorError(
                "MultiMon requested capture counts exceed budget", ALLOCATION
            )
        primary: BaseException | None = None
        try:
            status = self.start()
            if status != OK:
                raise MonitorError("MultiMon open failed", status)
            while any(
                len(packets) < count for packets, count in zip(self.packets, counts)
            ):
                status = self.step()
                if status != OK:
                    raise MonitorError("MultiMon acquisition failed", status)
            self.stop()
            return tuple(
                NativeRecorderCapture(0, tuple(packets)) for packets in self.packets
            )
        except BaseException as error:
            primary = error
            raise
        finally:
            if self.state in ("select", "send", "receive", "idle"):
                try:
                    self.stop()
                except BaseException as error:  # noqa: BLE001 - release after cleanup failure
                    self.cleanup_error = error
                    if primary is not None:
                        primary.add_note(f"MultiMon stop failed: {error}")
            try:
                status = self.close()
                if status:
                    raise MonitorError("MultiMon close failed", status)
            except BaseException as error:
                if primary is None:
                    raise
                primary.add_note(f"MultiMon close failed: {error}")


def selected_variable_single_worker(
    operations: NativeFrameOperations,
    target: VariableRuntimeTarget,
    *,
    active: ActiveMonitorEvent | None = None,
    system: MonitorSystemEvent | None = None,
    timeout: float = 30,
    max_steps: int = 65535,
    max_packets: int = 65535,
    max_bytes: int = MAX_RECORDER_BYTES,
    clock: Callable[[], float] = time.monotonic,
    ticks: Callable[[], int] | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    packet_sink: Callable[[NativeMonitorPacket], None] | None = None,
) -> DirectJ2534Worker:
    """8610/8A30 single variable child: base worker even with an A1 event.

    Shared event setup is native DataListIF code. No ordinary P4 DMCI lifecycle
    (114/116) is inserted into the variable controller's separate lifecycle.
    """
    if not isinstance(target, VariableRuntimeTarget):
        raise MonitorError("Variable worker requires selected runtime target", INVALID)
    target.check()
    if target.connection is None or not isinstance(
        target.plan, (SelectedVariableMonitor, SelectedVariablePacketMonitor)
    ):
        raise MonitorError(
            "Variable communication worker requires non-voltage target", INVALID
        )
    worker = selected_normal_poll_worker(
        operations,
        target.plan,
        target.connection,
        active=active,
        system=system,
        timeout=timeout,
        max_steps=max_steps,
        max_packets=max_packets,
        max_bytes=max_bytes,
        clock=clock,
        ticks=ticks,
        cancelled=cancelled,
        packet_sink=packet_sink,
    )
    assert isinstance(worker, DirectJ2534Worker)
    return worker
