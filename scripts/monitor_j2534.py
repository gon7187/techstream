"""Direct native P3 J2534 monitor event machines over injected observations.

Import does not load vendor code, open a driver, or touch a vehicle.
"""

from __future__ import annotations

import math
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from scripts.data_monitor import MonitorError, SelectedMonitorSession, pickup_packet
from scripts.drive_recorder import (
    MAX_RECORDER_BYTES,
    NativeMonitorPacket,
    NativeRecorderCapture,
    RecorderCancelled,
)
from scripts.frame_transport import (
    DriverProperties,
    FramePlan,
    FrameTransportError,
    NativeConnect,
    NativeFrameOperations,
    NativeMessage,
    _function_request,
    _simple_record,
    _source_address,
    translate_configs,
)
from scripts.monitor_instruments import (
    OscConfiguration,
    OscilloscopeRuntime,
    OscPrimitives,
    OscRead,
    SelectedInstrumentMonitor,
    selected_instrument_monitor,
)
from scripts.monitor_support import PacketFrameCache, PacketReceive
from scripts.native_communication import NativeCommunication, NativeFrameController
from scripts.support import word
from scripts.toyota_session import NativeFrameSend

if TYPE_CHECKING:
    from scripts.monitor_legacy import SelectedPhase3Monitor
    from scripts.profiles import ProtocolProfile, VehicleProfile

OK = 0xE0000100
INVALID = 0xE0000102
ALLOCATION = 0xE0000101


class NativeMonitorSourceFault(RuntimeError):
    """A proven native invalid-pointer branch, without an invented DLL status."""


class NativePacketPrimitives:
    """CommandCommon GetPacketFrame's SendInt/Receive/interrupt ABI join.

    The selected communication owns its channel, deadline and primitive budget.
    This adapter borrows them and never opens or closes an independent channel.
    """

    def __init__(self, communication: NativeCommunication):
        if not isinstance(communication, NativeCommunication) or not isinstance(
            communication.operations, NativeFrameController
        ):
            raise TypeError("Packet primitives require concrete selected communication")
        self.communication = communication

    def send(
        self,
        ecu: int,
        request: bytes,
        parameter4: int,
        parameter5: int,
        parameter6: int,
        parameter7: int,
    ) -> int:
        communication = self.communication
        with communication.constrain_operation(
            deadline=communication.deadline,
            exchanges=communication.limits.exchanges,
        ):
            return communication.send_native(
                NativeFrameSend(
                    "SendInt",
                    ecu,
                    request,
                    parameter4,
                    parameter5,
                    parameter6,
                    parameter7,
                )
            )

    def receive(self, receive: PacketReceive, /) -> tuple[int, bytes]:
        communication = self.communication
        if (
            not isinstance(receive, PacketReceive)
            or receive.ecu != communication.profile.category
        ):
            raise ValueError("Packet receive selected category differs from channel")
        for value in (
            receive.capacity,
            receive.parameter4,
            receive.parameter5,
            receive.wait_ms,
        ):
            _uint(value)
        if not 0 < receive.capacity <= 255:
            raise ValueError("Packet Receive capacity exceeds native BYTE ABI")
        if receive.parameter5 > 255:
            raise ValueError("Packet Receive argument5 exceeds native BYTE ABI")
        with communication.constrain_operation(
            deadline=communication.deadline,
            exchanges=communication.limits.exchanges,
        ):
            result = communication.receive_native(
                maximum=receive.capacity,
                timeout=receive.parameter4,
                argument_5=receive.parameter5,
                flags=receive.wait_ms,
            )
        return result.code, result.data

    def interrupt(self, enabled: bool) -> None:
        if type(enabled) is not bool:
            raise ValueError("Native packet interrupt requires bool")
        communication = self.communication
        controller = communication.operations
        assert isinstance(controller, NativeFrameController)
        with communication.constrain_operation(
            deadline=communication.deadline,
            exchanges=communication.limits.exchanges,
        ):
            communication._primitive()
            try:
                controller.operations.set_interrupt_mode(
                    int(enabled), deadline=communication.deadline
                )
            finally:
                communication._check(timeout_error=sys.exception())


def selected_packet_frame_cache(
    communication: NativeCommunication,
    *,
    monitor_session: SelectedMonitorSession | None = None,
) -> PacketFrameCache:
    """Bind native FIRST ComSet1/default timers to the retained concrete channel."""
    primitive = NativePacketPrimitives(communication)
    if monitor_session is not None:
        if not isinstance(monitor_session, SelectedMonitorSession):
            raise TypeError("Packet cache requires a typed selected monitor session")
        monitor_session.check(
            communication.profile, source_build=communication.source_build
        )
    cache = PacketFrameCache.from_profile(
        communication.profile,
        primitive,
        communication.ecu,
        limits=communication.limits,
        cancelled=communication.cancelled,
        clock=communication.clock,
        disable_packet_ecu=(
            monitor_session.disable_packet_ecu if monitor_session is not None else None
        ),
    )
    cache.deadline = min(cache.deadline, communication.deadline)
    return cache


def _uint(value: int, bits: int = 32) -> int:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise MonitorError(f"Native J2534 field must fit uint{bits}", INVALID)
    return value


def _bytes(value: bytes, maximum: int = 4096) -> bytes:
    if not isinstance(value, bytes) or len(value) > maximum:
        raise MonitorError("Native J2534 bytes exceed storage", INVALID)
    return value


def _pickup_bits(spans: tuple[tuple[int, int], ...]) -> int:
    if not isinstance(spans, tuple) or len(spans) > 65535:
        raise MonitorError("Native pickup count exceeds budget", ALLOCATION)
    total = 0
    for span in spans:
        if not isinstance(span, tuple) or len(span) != 2:
            raise MonitorError("Native pickup span requires offset and count", INVALID)
        start, count = span
        _uint(start)
        _uint(count)
        total += count
    if total % 8:
        raise MonitorError("Native selected pickup is not byte aligned", INVALID)
    return total


@dataclass
class CommItem:
    request: bytes
    delay: int = 0
    status: int = 0
    next_send: int = 0

    def __post_init__(self) -> None:
        _bytes(self.request)
        _uint(self.delay, 16)
        _uint(self.status)
        _uint(self.next_send)


class DataMonitorEvent:
    """CCommEventDM234b0..23df0: retained cycle bytes and literal service checks."""

    def __init__(
        self,
        data_type: int,
        ids: bytes,
        lengths: bytes,
        total_length: int,
        *,
        pickup_spans: tuple[tuple[int, int], ...] = (),
        dtc_request: bytes | None = None,
        dtc_pattern: int = 0,
    ):
        if data_type not in (0, 1, 2, 3, 6) or type(data_type) is not int:
            raise MonitorError("Unsupported native DataMonType", INVALID)
        _bytes(ids, 255)
        _bytes(lengths, 255)
        if len(ids) != len(lengths) or not ids and dtc_request is None:
            raise MonitorError("Native PID and length arrays disagree", INVALID)
        if type(total_length) is not int or not 0 < total_length <= 65535:
            raise MonitorError("Native event allocation exceeds budget", ALLOCATION)
        pickup_bits = _pickup_bits(pickup_spans)
        if sum(lengths) + (dtc_request is not None) + pickup_bits // 8 > total_length:
            raise MonitorError(
                "Native frame table is shorter than selected event data", INVALID
            )
        service = 1 if data_type in (0, 2) else 0x21
        suffix = b"\x01" if data_type in (2, 3) else b""
        self.items = [CommItem(bytes((service, pid)) + suffix) for pid in ids]
        if dtc_request is not None:
            _bytes(dtc_request, 4095)
            if dtc_pattern != 0:
                raise MonitorError("Native DTC pattern must be zero", INVALID)
            self.items.append(CommItem(b"\x13" + dtc_request))
        self.data_type, self.ids, self.lengths = data_type, ids, lengths
        self.pickup_spans, self.dtc_pattern = pickup_spans, dtc_pattern
        self.dtc_length = int(dtc_request is not None)
        self.data = bytearray(total_length)
        self.index = self.offset = 0
        self.packets: list[NativeMonitorPacket] = []
        self.pending_packet_bytes = 0
        self.receive_times: list[int] = []
        self.stopped = False

    @property
    def item(self) -> CommItem:
        if not 0 <= self.index < len(self.items):
            raise MonitorError(
                "Native event has no current communication item", INVALID
            )
        return self.items[self.index]

    def start(self) -> int:
        self.data[:] = bytes(len(self.data))
        return OK

    def _emit(self, tick: int) -> None:
        if (
            len(self.packets) >= 65535
            or self.pending_packet_bytes + 4 + len(self.data) > MAX_RECORDER_BYTES
        ):
            raise MonitorError("Native event output queue exceeds budget", ALLOCATION)
        self.packets.append(NativeMonitorPacket(tick, bytes(self.data)))
        self.pending_packet_bytes += 4 + len(self.data)

    def get_snd_frame(self, tick: int) -> bytes:
        _uint(tick)
        self.item.status = 1
        return self.item.request

    def set_status(self, value: int) -> None:
        self.item.status = _uint(value)

    def advance(self) -> None:
        # CCommEventBase::ProcNextCommItem is an actual no-op.
        return

    def check_rcv_frame(self, reply: bytes, tick: int) -> int:
        _bytes(reply)
        _uint(tick)
        if not reply:
            return INVALID
        dtc = reply[0] == 0x53
        if dtc:
            if (
                self.index != len(self.items) - 1
                or self.dtc_pattern != 0
                or len(reply) < 2
            ):
                return INVALID
            payload, size = reply[1:2], self.dtc_length
        else:
            expected = 0x41 if self.data_type in (0, 2) else 0x61
            if reply[0] != expected or self.index >= len(self.lengths):
                return INVALID
            header = 1 if self.data_type == 6 and self.item.request[1] == 1 else 2
            if len(reply) < header:
                return INVALID
            size = self.lengths[self.index]
            payload = reply[header : header + size]
        if self.offset + size > len(self.data):
            return INVALID
        self.data[self.offset : self.offset + len(payload)] = payload
        self.offset += size
        if self.index == len(self.items) - 1:
            if self.pickup_spans:
                prior = bytes(self.data[self.offset :])
                merged = pickup_packet(
                    bytes(self.data[: self.offset]),
                    0,
                    self.pickup_spans,
                    p4=True,
                    previous=prior,
                )
                if len(merged) != len(self.data):
                    return INVALID
                self.data[:] = merged
            self._emit(tick)
            self.index = self.offset = 0
        else:
            self.index += 1
        self.item.status = 0
        return OK

    def set_receive_time(self, tick: int) -> None:
        if len(self.receive_times) >= 65535:
            raise MonitorError("Native receive-time queue exceeds budget", ALLOCATION)
        self.receive_times.append(_uint(tick))

    def stop(self) -> int:
        self.stopped = True
        return OK


class CenturyMonitorEvent(DataMonitorEvent):
    """CCommEventDMCentury: unordered PID arrivals and per-cycle received flags."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.data_type != 0 or self.dtc_length or self.pickup_spans:
            raise MonitorError("Native Century event requires DataMonType0", INVALID)
        self.received = [False] * len(self.ids)
        self.receive_flag = 0

    def check_rcv_frame(self, reply: bytes, tick: int) -> int:
        _bytes(reply)
        _uint(tick)
        if len(reply) < 2 or reply[0] != 0x41:
            return INVALID
        if reply[1] in self.ids:
            index = self.ids.index(reply[1])
            self.received[index] = True
            offset = sum(self.lengths[:index])
            payload = reply[2 : 2 + self.lengths[index]]
            self.data[offset : offset + len(payload)] = payload
        if all(self.received):
            self._emit(tick)
            self.receive_flag = 1
            self.received[:] = [False] * len(self.ids)
            self.index = 0
            self.item.status = 0
        else:
            self.receive_flag = 0
        return OK

    def skip_selected_pid(self, pid: int) -> int:
        _uint(pid, 8)
        if pid not in self.ids:
            return INVALID
        self.index = self.ids.index(pid)
        self.item.status = 0
        return OK

    def skip_functional_items(self) -> int:
        for index in range(self.index, len(self.items)):
            if not self.received[index]:
                self.index = index
                self.item.status = 0
                return OK
        return INVALID

    def advance(self) -> None:
        self.index += 1
        if self.index >= len(self.items):
            raise MonitorError("Native Century communication list ended", INVALID)
        self.item.status = 0


class PacketMonitorEvent(DataMonitorEvent):
    """Native PacketDMBase and PacketDMP3 A1/A2/A3 state and retained buffers."""

    def __init__(
        self,
        dpid: int,
        descriptor: bytes,
        frame_sizes: tuple[tuple[int, int], ...],
        *,
        timeout: int,
        pickup_spans: tuple[tuple[int, int], ...] = (),
        dtc_request: bytes | None = None,
    ):
        _uint(dpid, 8)
        _uint(timeout, 16)
        _bytes(descriptor, 253)
        if not descriptor:
            raise MonitorError("Native packet descriptor is empty", INVALID)
        if not isinstance(frame_sizes, tuple) or len(frame_sizes) > 65535:
            raise MonitorError("Native frame count exceeds budget", ALLOCATION)
        total = 0
        for frame in frame_sizes:
            if not isinstance(frame, tuple) or len(frame) != 2:
                raise MonitorError("Native frame requires identity and size", INVALID)
            _uint(frame[0], 16)
            total += _uint(frame[1], 16)
        if not 0 < total <= 65535:
            raise MonitorError("Native packet allocation exceeds budget", ALLOCATION)
        # Common event allocation is reused; packet parsing owns its grammar.
        super().__init__(0, b"\0", b"\x01", total, pickup_spans=())
        self.pickup_spans = pickup_spans
        self.raw_length = total - _pickup_bits(pickup_spans) // 8
        if not 0 < self.raw_length <= total:
            raise MonitorError("Native packet pickup exceeds data storage", INVALID)
        self.dpid, self.descriptor, self.timeout = dpid, descriptor, timeout
        self.items = (
            []
            if dpid == 4
            else [CommItem(b"\xa1" + bytes((dpid,)) + descriptor, status=7)]
        )
        self.items.append(CommItem(bytes((0xA2, dpid)), timeout, 9))
        if dtc_request is not None:
            _bytes(dtc_request, 4095)
            self.items.append(CommItem(b"\x13" + dtc_request))
            self.dtc_length = 1
        self.sequence = 0

    def get_snd_frame(self, tick: int) -> bytes:
        _uint(tick)
        status = self.item.status
        if status == 7:
            self.item.status = 8
        elif status in (9, 10):
            self.item.next_send = (tick + self.item.delay) & 0xFFFFFFFF
            self.item.status = 11 if status == 9 else 12
        elif status == 13:
            self.item.status = 14
        return self.item.request

    def set_status(self, value: int) -> None:
        if value in (6, 7, 9, 10, 11, 12, 13, 14):
            self.item.status = value

    def check_rcv_frame(self, reply: bytes, tick: int) -> int:
        _bytes(reply)
        _uint(tick)
        if not reply:
            return INVALID
        code = reply[0]
        if code == 0xE1:
            request = self.item.request
            if len(reply) < len(request) or reply[1 : len(request)] != request[1:]:
                return 0xE0000103
            self.index += 1
            if self.index >= len(self.items):
                return INVALID
            return OK
        if code == 0xE3:
            self.item.status = 6
            return OK
        if code != 0xE2:
            return INVALID
        if len(reply) > 2:
            if self.dpid == 4:
                sequence = (reply[1] - 0x10) & 255
                index = (reply[1] - 0x11) & 255
                if sequence <= len(self.descriptor):
                    if not 0 <= index < len(self.descriptor):
                        return INVALID
                    if sequence <= self.sequence:
                        self._write_packet(tick)
                    self.sequence = sequence
                    offset = sum(self.descriptor[:index])
                    size = min(self.descriptor[index], len(reply) - 2)
                    if offset + size > self.raw_length:
                        return INVALID
                    self.data[offset : offset + size] = reply[2 : 2 + size]
            else:
                size = min(len(reply) - 2, self.raw_length)
                self.data[:size] = reply[2 : 2 + size]
                self._write_packet(tick)
        if self.item.status not in (13, 14):
            self.item.status = 12
        return OK

    def _write_packet(self, tick: int) -> None:
        if self.pickup_spans:
            self.data[:] = pickup_packet(
                bytes(self.data[: self.raw_length]), 0, self.pickup_spans, p4=False
            )
        self._emit(tick)

    def stop(self) -> int:
        if self.item.status in (6, 7, 8, 9, 14):
            self.item.status = 6
        else:
            self.items = [CommItem(b"\xa3", status=13)]
            self.index = 0
        self.stopped = True
        return OK


class ActiveMonitorEvent(DataMonitorEvent):
    """Concurrent CCommEventAT / DkKwp active queue, timers and stop marker."""

    def __init__(self, body: bytes, delay: int = 0, *, dk_kwp: bool = False):
        if type(dk_kwp) is not bool:
            raise MonitorError("Native active-test variant must be boolean", INVALID)
        super().__init__(0, b"\0", b"\x01", 1)
        self.items = []
        self.dk_kwp = dk_kwp
        self.initialize_after_stop = False
        self.append(body, delay)

    def append(self, body: bytes, delay: int = 0) -> None:
        _bytes(body, 4095)
        _uint(delay, 16)
        if len(self.items) >= 65535:
            raise MonitorError("Native active queue exceeds budget", ALLOCATION)
        self.items.append(CommItem(b"\x30" + body, delay))

    def advance(self) -> None:
        if self.item.status not in (0, 1, 2) and len(self.items) > 1:
            self.items.pop(0)

    def check_rcv_frame(self, reply: bytes, tick: int) -> int:
        _bytes(reply)
        _uint(tick)
        if not reply or reply[0] != 0x70:
            return INVALID
        if self.dk_kwp or len(reply) == 2:
            self.item.next_send = (
                ((tick + self.item.delay) & 0xFFFFFFFF) if self.item.delay else 0
            )
            self.item.status = 3 if self.item.delay else 4
        elif len(reply) == 1:
            self.item.next_send = 0
            self.item.status = 5
        elif len(reply) == 3:
            return 0xE00001CC
        return OK

    def stop(self, *, initialize: bool = False) -> int:
        if type(initialize) is not bool:
            raise MonitorError("Native active stop flag must be boolean", INVALID)
        if len(self.items) >= 65535:
            raise MonitorError("Native active stop exceeds queue budget", ALLOCATION)
        self.initialize_after_stop = initialize
        self.items.append(CommItem(b"\x30"))
        self.stopped = True
        return OK

    def skip_end(self) -> None:
        self.items = [self.items[-1]]


class MonitorSystemEvent(DataMonitorEvent):
    """CCommEventMS MonitorSystemSend248c0 / CheckRcvFrame24a40."""

    def __init__(self, body: bytes):
        super().__init__(0, b"\0", b"\x01", 1)
        _bytes(body, 4095)
        self.items = [CommItem(b"\x08" + body)]

    def check_rcv_frame(self, reply: bytes, tick: int) -> int:
        _bytes(reply)
        _uint(tick)
        if not reply or reply[0] != 0x48:
            return INVALID
        self.item.status = 4
        return OK


@dataclass(frozen=True)
class WorkerNotification:
    request_id: int
    code: int
    parameter: int = 0


def selected_phase3_event(
    profile: VehicleProfile,
    plan: SelectedPhase3Monitor,
    *,
    backend_family: str,
) -> DataMonitorEvent:
    """Selected native setup metadata to actual direct-worker event bytes."""
    from scripts.monitor_legacy import SelectedPhase3Monitor
    from scripts.monitor_support import monitor_source_identity

    if not isinstance(
        plan, SelectedPhase3Monitor
    ) or plan.source_identity != monitor_source_identity(profile, ""):
        raise MonitorError("Direct event belongs to another selected source", INVALID)
    if backend_family not in ("j2534", "j2534_century", "j2534_packet", "j2534_dk_kwp"):
        raise MonitorError("Selected constructor is not a direct P3 worker", INVALID)
    total = sum(size for _, size in plan.frame_sizes)
    if backend_family == "j2534_packet":
        command = next((c for c in plan.commands.setup if c.command_id == 0x109), None)
        if command is None:
            raise MonitorError(
                "Native packet setup requires one A1 descriptor", INVALID
            )
        pairs = command.values[2]
        if not isinstance(pairs, tuple) or len(pairs) != 1:
            raise MonitorError("Native packet worker requires one descriptor", INVALID)
        pair = pairs[0]
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise MonitorError("Native packet descriptor fields disagree", INVALID)
        dpid, descriptor = pair
        timeout = command.values[5]
        if (
            type(dpid) is not int
            or not isinstance(descriptor, bytes)
            or type(timeout) is not int
        ):
            raise MonitorError(
                "Native packet descriptor has invalid field types", INVALID
            )
        return PacketMonitorEvent(
            dpid,
            descriptor,
            plan.frame_sizes,
            timeout=timeout,
            pickup_spans=plan.pickup_spans,
            dtc_request=None if plan.auxiliary is None else plan.auxiliary.request[1:],
        )
    mode = plan.packing.mode
    if mode not in (0, 0x10, 0x20, 0x100) or len(plan.packing.setup_requests) not in (
        0,
        2,
    ):
        raise MonitorError("Native pair worker setup is unavailable", INVALID)
    ids, lengths = (
        (r[1:] for r in plan.packing.setup_requests)
        if plan.packing.setup_requests
        else (b"", b"")
    )
    event_type = (
        CenturyMonitorEvent if backend_family == "j2534_century" else DataMonitorEvent
    )
    return event_type(
        {0: 0, 0x10: 0, 0x20: 1, 0x100: 3}[mode],
        ids,
        lengths,
        total,
        pickup_spans=plan.pickup_spans,
        dtc_request=None if plan.auxiliary is None else plan.auxiliary.request[1:],
    )


class DirectJ2534Worker:
    """Bounded execution of the native P3 three-slot worker state machine.

    Each step performs at most one lower operation. Waiting native states yield
    to the caller; injected clocks and cancellation retain an absolute deadline.
    """

    _allow_century = False

    def __init__(
        self,
        operations: NativeFrameOperations,
        event: DataMonitorEvent | None,
        *,
        request_id: int,
        response_id: int,
        default_source: int,
        full_source: bool = False,
        attempts: int = 3,
        send_timeout: int = 1000,
        receive_timeout: int = 200,
        active: ActiveMonitorEvent | None = None,
        system: MonitorSystemEvent | None = None,
        oscilloscope: OscilloscopeRuntime | None = None,
        native_worker_class: Literal["base", "packet"] | None = None,
        timeout: float = 30,
        max_steps: int = 65535,
        max_packets: int = 65535,
        max_bytes: int = MAX_RECORDER_BYTES,
        clock: Callable[[], float] = time.monotonic,
        ticks: Callable[[], int] | None = None,
        cancelled: Callable[[], bool] | None = None,
        packet_sink: Callable[[NativeMonitorPacket], None] | None = None,
        disable_packet_ecu: Callable[[int], None] | None = None,
    ):
        if not isinstance(operations, NativeFrameOperations):
            raise MonitorError(
                "Concrete selected NativeFrameOperations required", INVALID
            )
        if operations.channel is not None or operations.poisoned:
            raise MonitorError(
                "Native worker requires a fresh owned transport", INVALID
            )
        if event is not None and not isinstance(event, DataMonitorEvent):
            raise MonitorError("Native data slot requires a typed event", INVALID)
        if active is not None and not isinstance(active, ActiveMonitorEvent):
            raise MonitorError("Native active slot requires a typed event", INVALID)
        if system is not None and not isinstance(system, MonitorSystemEvent):
            raise MonitorError("Native system slot requires a typed event", INVALID)
        if oscilloscope is not None and (
            not isinstance(oscilloscope, OscilloscopeRuntime)
            or oscilloscope.state != "configured"
            or self._allow_century
        ):
            raise MonitorError(
                "Combined oscillator requires a fresh base/Packet runtime", INVALID
            )
        for value in (
            request_id,
            response_id,
            default_source,
            send_timeout,
            receive_timeout,
        ):
            _uint(value)
        if (
            type(full_source) is not bool
            or type(attempts) is not int
            or not 0 <= attempts <= 65535
        ):
            raise MonitorError("Invalid native worker source mode or attempts", INVALID)
        if (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise MonitorError("Worker timeout must be finite and positive", INVALID)
        for limit in (max_steps, max_packets, max_bytes):
            if type(limit) is not int or not 0 < limit <= 64 * 1024 * 1024:
                raise MonitorError("Worker resource limit exceeds budget", ALLOCATION)
        if max_bytes > MAX_RECORDER_BYTES:
            raise MonitorError(
                "Native capture exceeds recorder byte budget", ALLOCATION
            )
        if isinstance(event, CenturyMonitorEvent) and not self._allow_century:
            raise MonitorError("Century requires its two-system worker", INVALID)
        if native_worker_class not in (None, "base", "packet"):
            raise MonitorError("Unknown native J2534 worker class", INVALID)
        if disable_packet_ecu is not None and not callable(disable_packet_ecu):
            raise MonitorError("Packet disable-list consumer must be callable", INVALID)
        if native_worker_class == "packet" and not isinstance(
            event, PacketMonitorEvent
        ):
            raise MonitorError(
                "Native Packet worker requires its packet event", INVALID
            )
        # D850 selects by event mode; variable8610 explicitly constructs BASE.
        self.native_worker_class = native_worker_class or (
            "packet" if isinstance(event, PacketMonitorEvent) else "base"
        )
        self.operations = operations
        self.controllers = {operations: NativeFrameController(operations)}
        self.controller = self.controllers[operations]
        self.oscilloscope = oscilloscope
        self._instrument_guard: (
            tuple[Callable[[], bool], Callable[[], float]] | None
        ) = None
        self.events = (active, system, event)
        self.request_id, self.response_id = request_id, response_id
        self.default_source, self.full_source = default_source, full_source
        self.attempts, self.send_timeout, self.receive_timeout = (
            attempts,
            send_timeout,
            receive_timeout,
        )
        self.timeout, self.clock = timeout, clock
        self.ticks = ticks or (lambda: int(self._now() * 1000) & 0xFFFFFFFF)
        self.cancelled = cancelled or (lambda: False)
        self.packet_sink = packet_sink
        self.disable_packet_ecu = disable_packet_ecu
        self.max_steps, self.max_packets, self.max_bytes = (
            max_steps,
            max_packets,
            max_bytes,
        )
        self.packets: list[NativeMonitorPacket] = []
        self.notifications: list[WorkerNotification] = []
        self.packet_count = self.byte_count = self.steps = 0
        self.state = "configured"
        self.slot = 2
        self.request = b""
        self.failures = 0
        self.deadline = 0.0
        self.last_receive_slot = 0xFFFFFFFF
        self.burst = self.interrupt = False
        self.packet_active = False
        self.last_clock: float | None = None
        self.owned = False
        self.cleanup_mode = False
        self.cleanup_steps = 0
        self.cleanup_error: BaseException | None = None
        self.dk_kwp = False
        self._operation_guards: dict[
            NativeFrameOperations, tuple[Callable[[], bool], bool]
        ] = {}

    def _activate_operations(self, operations: NativeFrameOperations) -> None:
        if operations not in self._operation_guards:
            previous = operations.cancelled
            self._operation_guards[operations] = (
                previous,
                operations.defer_cancel_cleanup,
            )
            operations.cancelled = lambda: self.cancelled() or previous()
            operations.defer_cancel_cleanup = True
        self.operations = operations
        if operations not in self.controllers:
            self.controllers[operations] = NativeFrameController(operations)
        self.controller = self.controllers[operations]

    def _restore_operation_guards(self) -> None:
        for operations, (previous, defer_cancel) in self._operation_guards.items():
            operations.cancelled, operations.defer_cancel_cleanup = (
                previous,
                defer_cancel,
            )
        self._operation_guards.clear()
        if self.oscilloscope is not None and self._instrument_guard is not None:
            self.oscilloscope.cancelled, self.oscilloscope.clock = (
                self._instrument_guard
            )
            self._instrument_guard = None

    def _instrument_error(self, status: int) -> int:
        instrument = self.oscilloscope
        assert instrument is not None
        code = {
            0x907F: 0xE2001000,
            0x917F: 0xE2001001,
            0x927F: 0xE2001002,
            0x937F: 0xE2001003,
        }.get(instrument.error_word)
        if code is not None:
            self.notifications.append(
                WorkerNotification(self.request_id, code, instrument.error_parameter)
            )
        return status

    def _stop_instrument(self) -> int:
        instrument = self.oscilloscope
        if instrument is None or instrument.state not in (
            "starting",
            "running",
            "fault",
        ):
            return 0
        previous = instrument.cancelled
        try:
            instrument.cancelled = lambda: False
            return self._instrument_error(instrument.stop())
        finally:
            instrument.cancelled = previous

    def _now(self) -> float:
        now = self.clock()
        if type(now) not in (int, float) or not math.isfinite(now):
            raise MonitorError("Worker clock must be finite", INVALID)
        if self.last_clock is not None and now < self.last_clock:
            raise MonitorError("Worker clock moved backwards", INVALID)
        self.last_clock = float(now)
        return float(now)

    def _check(self, *, cleanup: bool = False) -> None:
        cleanup = cleanup or self.cleanup_mode
        if not math.isfinite(self.deadline) or self._now() >= self.deadline:
            raise MonitorError("Native monitor deadline exceeded", INVALID)
        if not cleanup and self.cancelled():
            raise RecorderCancelled("Native monitor cancelled")
        if not cleanup and self.steps >= self.max_steps:
            raise MonitorError("Native monitor step budget exceeded", ALLOCATION)
        if not cleanup:
            self.steps += 1
        elif self.cleanup_mode:
            if self.cleanup_steps >= self.max_steps:
                raise MonitorError("Native monitor cleanup budget exceeded", ALLOCATION)
            self.cleanup_steps += 1

    def _tick(self) -> int:
        return _uint(self.ticks())

    def _mode(self, parameter: int, value: int) -> None:
        # The native setters intentionally discard the SetConfig return status.
        if self.operations.device_kind != 4:
            if (
                parameter in (0x10500, 0x10501)
                and self.operations.plan.send.protocol_id != 4
            ):
                return  # CAN/J1850 vtables retain the actual no-op interrupt slots.
            self.operations.configure(((parameter, value),), deadline=self.deadline)
            if parameter == 0x10400:
                self.operations.set_burst_mode_state(value)
            if parameter == 0x10500:
                self.operations.set_interrupt_mode_state(value)
                iso = _simple_record(
                    self.operations.profile,
                    15,
                    56,
                    4,
                    word(self.operations.protocol_record, 2),
                )
                self.operations.configure(
                    ((0x1000B, word(iso, 52)),), deadline=self.deadline
                )

    def expected_source(self) -> int:
        response = self.response_id
        if response in (0, 0xFFFFFFFF):
            return self.default_source
        if not self.full_source:
            return response & 255
        if self.operations.bus_id & 15 in (2, 8):
            mode = self.request_id & 0xC0000000
            if mode == 0x80000000:
                return response >> 8 & 0xFFF
            if mode == 0xC0000000:
                return response & 255
            return response
        return response & 255

    def start(self) -> int:
        if self.state != "configured":
            raise MonitorError("Native worker start requires configured state", INVALID)
        if self.operations.channel is not None or self.operations.poisoned:
            raise MonitorError(
                "Native worker requires a fresh owned transport", INVALID
            )
        self.deadline = self._now() + self.timeout
        self._check()
        self.owned = True
        self._activate_operations(self.operations)
        try:
            status = self.operations.open(deadline=self.deadline)
        except BaseException:
            self._restore_operation_guards()
            self.state = "fault"
            raise
        if status:
            self._restore_operation_guards()
            self.state = "fault"
            return status
        for event in self.events:
            if event is not None:
                event.start()
        self.state = "select"
        if self.oscilloscope is not None:
            instrument = self.oscilloscope
            previous = instrument.cancelled
            self._instrument_guard = previous, instrument.clock
            instrument.cancelled = lambda: self.cancelled() or previous()
            instrument.clock = self.clock
            original_timeout = instrument.timeout
            try:
                self._check()
                instrument.timeout = min(original_timeout, self.deadline - self._now())
                status = instrument.start()
                if status:
                    return self._instrument_error(status)
            finally:
                instrument.timeout = original_timeout
        return OK

    def _harvest(self, event: DataMonitorEvent) -> None:
        for packet in event.packets:
            if (
                self.packet_count >= self.max_packets
                or self.byte_count + 4 + len(packet.payload) > self.max_bytes
            ):
                raise MonitorError("Native monitor capture budget exceeded", ALLOCATION)
            self.packet_count += 1
            self.byte_count += 4 + len(packet.payload)
            if self.packet_sink is not None:
                self.packet_sink(packet)
            else:
                self.packets.append(packet)
        event.packets.clear()
        event.pending_packet_bytes = 0
        # Native18 writes receive-time observations to a bounded shared log.
        event.receive_times.clear()

    def _error(
        self,
        *,
        negative: bool = False,
        data: bytes = b"",
        direct: int = 0,
        error_slot: int | None = None,
    ) -> int:
        service = self.request[0] if self.request else 0
        slot = self.slot if error_slot is None else error_slot
        if slot == 0:
            code = (
                0xE00001CC
                if direct == 0xE00001CC
                else (0xE000010C if negative else 0xE0000106)
            )
        elif slot == 1:
            code = 0xE0000110 if negative else 0xE0000112
        elif self.native_worker_class == "packet":
            code = {
                0xA1: (0xE0000103, 0xE0000109),
                0xA3: (0xE0000105, 0xE000010B),
            }.get(service, (0xE0000104, 0xE000010A))[int(negative)]
        else:
            code = {
                1: (0xE0000107, 0xE000010D),
                0x13: (0xE0000111, 0xE000010F),
                0x21: (0xE0000108, 0xE000010E),
            }.get(service, (INVALID, INVALID))[int(negative)]
        if (
            self.native_worker_class == "packet"
            and code != 0xE00001CC
            and self.disable_packet_ecu is not None
        ):
            self.disable_packet_ecu(self.operations.profile.category)
        self.notifications.append(
            WorkerNotification(
                self.request_id, code, data[2] if negative and len(data) > 2 else 0
            )
        )
        self.state = "idle"
        return code

    def step(self) -> int:
        if self.state not in ("select", "send", "receive", "idle"):
            raise MonitorError("Native worker is not running", INVALID)
        self._check()
        tick = self._tick()
        if self.state == "idle":
            return OK
        packet = self.native_worker_class == "packet"
        if self.state == "select":
            for slot, event in enumerate(self.events):
                if event is None:
                    continue
                event.advance()
                status = event.item.status
                if slot != 2 and packet and status in (2, 3, 4, 5):
                    continue
                if not packet and status in (4, 5):
                    continue
                if not packet and slot == 0 and status == 3:
                    if tick >= event.item.next_send:
                        event.set_status(0)
                    continue
                if packet and slot == 2 and status == 6:
                    continue
                self.slot = slot
                if packet and slot == 2 and status in (8, 11, 14):
                    self.state = "receive"
                    return OK
                if packet and slot == 2 and status == 9:
                    self._mode(0x10400, 1)
                    self.burst = True
                self.request = event.get_snd_frame(tick)
                self.state = "send"
                return OK
            return OK
        event = self.events[self.slot]
        assert event is not None
        if self.state == "send":
            clear_rx = 1
            if (
                packet
                and self.events[2] is not None
                and self.events[2].item.status in (12, 14)
            ):
                clear_rx = 0
                if not self.interrupt:
                    self._mode(0x10500, 1)
                    self.interrupt = True
            status = self.controller.send(
                self.request,
                timeout=self.send_timeout,
                initialization_mode=1,
                clear_rx=clear_rx,
                deadline=self.deadline,
            )
            if status:
                self.failures += 1
                if self.slot != 2 or self.failures >= self.attempts:
                    return self._error()
            else:
                event.set_status(2)
                if packet and self.slot == 0:
                    self.packet_active = True
                self.state = "receive"
            return OK
        observed = self.controller.receive(
            maximum=0x1000,
            timeout=self.receive_timeout,
            argument_5=0,
            flags=100,
            deadline=self.deadline,
        )
        if observed.code:
            if observed.code in (0x90020321, 0x90020323):
                return self._error(
                    negative=True,
                    data=observed.data,
                    error_slot=(0 if observed.data[1:2] == b"\x30" else 2)
                    if packet
                    else None,
                )
            self.failures += 1
            if self.slot == 2 and self.failures < self.attempts:
                self.state = "send"
                return OK
            return self._error()
        instrument = self.oscilloscope
        osc_read = None
        if packet and instrument is not None:
            # KGP15520: timestamped receive succeeds before the single named
            # read with zero sentinel. Its status is independent of normal RX.
            self._check()
            if instrument.read_count >= instrument.max_reads:
                raise MonitorError("Oscilloscope read budget exceeded", ALLOCATION)
            instrument.read_count += 1
            osc_read = instrument.provider.read_buffer(0, deadline=self.deadline)
            self._check()
            if not isinstance(osc_read, OscRead):
                raise MonitorError(
                    "Combined oscillator requires typed read output", INVALID
                )
            if osc_read.status:
                instrument.error_word, instrument.error_parameter = 0x937F, 0
                return self._instrument_error(osc_read.status)
        tick = observed.timestamp if packet else self._tick()
        if (
            self.operations.native_build == 18
            and not self.dk_kwp
            and tick >= 0x77359400
        ):
            self.last_receive_slot = self.slot
            event.set_receive_time(tick)
        self.failures = 0
        if observed.source_id != self.expected_source():
            return OK
        reply_slot = None
        if packet:
            reply_slot = 2
            if observed.data[:1] == b"\x70":
                reply_slot = 0
                self.packet_active = False
                event = self.events[0]
                if event is None:
                    return self._error(direct=INVALID, error_slot=reply_slot)
                if self.events[2] is not None and self.full_source:
                    self.events[2].set_status(10)
            elif observed.data and 0xE1 <= observed.data[0] <= 0xE3:
                event = self.events[2]
                assert event is not None
            else:
                return self._error(direct=INVALID, error_slot=reply_slot)
        result = event.check_rcv_frame(observed.data, tick)
        if result != OK:
            return self._error(direct=result, error_slot=reply_slot)
        self._harvest(event)
        if instrument is not None:
            status = (
                instrument._samples(osc_read, self.deadline)
                if osc_read is not None
                else instrument.drain(deadline=self.deadline)
            )
            if status:
                return self._instrument_error(status)
        if (
            self.slot == 0
            and isinstance(event, ActiveMonitorEvent)
            and event.item.status == 5
        ):
            if event.initialize_after_stop:
                self.controller.send(
                    None,
                    timeout=self.send_timeout,
                    initialization_mode=0,
                    clear_rx=1,
                    deadline=self.deadline,
                )
                self.controller.receive(
                    maximum=0,
                    timeout=self.receive_timeout,
                    argument_5=0,
                    flags=100,
                    deadline=self.deadline,
                )
            if self.events[2] is None:
                self.state = "idle"
                return OK
        if packet:
            active, _, monitor = self.events
            if active is not None:
                active.advance()
                if active.item.status not in (2, 3, 4, 5):
                    self.state = "select"
                    return OK
                if active.item.status == 3 and tick >= active.item.next_send:
                    active.set_status(0)
                    self.state = "select"
                    return OK
            if monitor is not None and monitor.item.status == 12:
                if not self.packet_active and self._tick() >= monitor.item.next_send:
                    monitor.set_status(10)
                    self.state = "select"
                else:
                    self.state = "receive"
                return OK
        self.state = "select"
        return OK

    def close(self) -> int:
        """Release owned transport even after cancellation or acquisition failure."""
        if self.state == "closed" or not self.owned:
            return 0
        failure: BaseException | None = None
        status = 0
        until: float | None = None
        try:
            self.deadline = self._now() + self.timeout
            self._check(cleanup=True)
            until = self.deadline
            if self.interrupt:
                self._mode(0x10500, 0)
            if self.burst:
                self._mode(0x10400, 0)
        except BaseException as error:  # noqa: BLE001 - release despite mode failure
            failure = error
        finally:
            try:
                instrument_status = self._stop_instrument()
                if instrument_status:
                    failure = failure or MonitorError(
                        "Native oscillator stop failed", instrument_status
                    )
            except BaseException as error:  # noqa: BLE001 - transport still needs release
                failure = failure or error
            try:
                status = self.controller.disconnect(0, deadline=until)
            except BaseException as error:  # noqa: BLE001 - preserve earlier cleanup fault
                failure = failure or error
            self.state = "closed" if self.operations.channel is None else "fault"
            self._restore_operation_guards()
        if failure is not None:
            raise failure
        return status

    def stop(self) -> int:
        if self.state not in ("select", "send", "receive", "idle"):
            raise MonitorError("Native worker stop requires running state", INVALID)
        self.deadline = self._now() + self.timeout
        if self.dk_kwp:
            self._check()
            status = self.controller.disconnect(1, deadline=self.deadline)
            self.state = "stopped" if status == 0 else "fault"
            return OK if status == 0 else status
        packet = self.native_worker_class == "packet"
        self._check()
        if packet and self.interrupt:
            self._mode(0x10501, 0)
        for slot in (0, 2):
            event = self.events[slot]
            if event is None:
                continue
            if slot == 0:
                assert isinstance(event, ActiveMonitorEvent)
                if event.item.status == 5:
                    continue
                event.stop()
                event.skip_end()
            elif packet:
                event.stop()
                if event.item.status == 6:
                    continue
            else:
                event.stop()
                continue
            self._check()
            request = event.get_snd_frame(self._tick())
            if packet and not self.interrupt:
                self._mode(0x10500, 1)
                self.interrupt = True
            status = self.controller.send(
                request,
                timeout=self.send_timeout,
                initialization_mode=1,
                clear_rx=0 if packet else 1,
                deadline=self.deadline,
            )
            if status == 0:
                self._check()
                self.controller.receive(
                    maximum=0x1000,
                    timeout=self.receive_timeout,
                    argument_5=0,
                    flags=100,
                    deadline=self.deadline,
                )
        instrument_status = self._stop_instrument()
        if packet:
            while True:
                self._check()
                observed = self.controller.receive(
                    maximum=0x1000,
                    timeout=self.receive_timeout,
                    argument_5=0,
                    flags=100,
                    deadline=self.deadline,
                )
                if observed.code == 0x91010009:
                    break
            if self.interrupt:
                self._mode(0x10500, 0)
                self.interrupt = False
            if self.burst:
                self._mode(0x10400, 0)
                self.burst = False
        self.state = "stopped"
        return instrument_status or OK

    def run(self, packet_count: int) -> NativeRecorderCapture:
        if type(packet_count) is not int or not 0 < packet_count <= self.max_packets:
            raise MonitorError(
                "Requested native packet count exceeds budget", ALLOCATION
            )
        primary: BaseException | None = None
        try:
            status = self.start()
            if status != OK:
                raise MonitorError("Native monitor open failed", status)
            while self.packet_count < packet_count:
                status = self.step()
                if status != OK:
                    raise MonitorError("Native monitor acquisition failed", status)
            status = self.stop()
            if status != OK:
                raise MonitorError("Native monitor stop failed", status)
            return self.capture()
        except BaseException as error:
            primary = error
            raise
        finally:
            if (
                self.owned
                and self.operations.channel is not None
                and self.state in ("select", "send", "receive", "idle")
            ):
                previous_cancelled = self.operations.cancelled
                try:
                    self.operations.cancelled = lambda: False
                    self.cleanup_mode, self.cleanup_steps = True, 0
                    self.stop()
                except BaseException as error:  # noqa: BLE001 - preserve acquisition fault
                    self.cleanup_error = error
                finally:
                    self.cleanup_mode = False
                    self.operations.cancelled = previous_cancelled
            try:
                status = self.close()
                if status and primary is None:
                    raise MonitorError("Native monitor close failed", status)
            except BaseException:
                if primary is None:
                    raise
            if self.cleanup_error is not None and primary is None:
                raise self.cleanup_error

    def capture(self, trigger_timestamp_ms: int = 0) -> NativeRecorderCapture:
        return NativeRecorderCapture(_uint(trigger_timestamp_ms), tuple(self.packets))


class DkKwpJ2534Worker(DirectJ2534Worker):
    """Original2bc70 worker: no oscillator/log path; stop disconnects directly."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.oscilloscope is not None:
            raise MonitorError("DK KWP has no oscillator branch", INVALID)
        active = self.events[0]
        if active is not None and not active.dk_kwp:
            raise MonitorError("DK KWP requires its actual active-test event", INVALID)
        self.dk_kwp = True


def selected_worker_oscilloscope(
    worker: DirectJ2534Worker,
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    provider: OscPrimitives,
    *,
    measure_time_range: int | None = None,
    forward_time_range: int | None = None,
) -> SelectedInstrumentMonitor:
    """Bind native set_measure_mode/set_buffer to actual selected category999.

    This is the shared base worker registration seam. A caller must retain its
    native constructor routing; selecting P3 does not itself enable this flag.
    """
    if (
        type(worker) is not DirectJ2534Worker
        or worker.state != "configured"
        or worker.oscilloscope is not None
        or profile.catalog.management.sha256
        != worker.operations.profile.catalog.management.sha256
        or profile.catalog.management.version
        != worker.operations.profile.catalog.management.version
        or profile.vehicle_name_key != worker.operations.profile.vehicle_name_key
        or profile.exception_ids != worker.operations.profile.exception_ids
    ):
        raise MonitorError(
            "Oscilloscope registration requires the same selected source and fresh base worker",
            INVALID,
        )
    plan = selected_instrument_monitor(
        profile,
        selected_ids,
        measure_time_range=measure_time_range,
        forward_time_range=forward_time_range,
    )
    worker.oscilloscope = OscilloscopeRuntime(
        provider,
        OscConfiguration.selected(plan),
        timeout=worker.timeout,
        max_reads=min(worker.max_steps, 100_000),
        max_packets=min(worker.max_packets, 100_000),
        clock=worker.clock,
    )
    return plan


def century_frame_plan(
    profile: ProtocolProfile,
    *,
    bus_id: int,
    driver: DriverProperties,
    diagnostic_mode: bytes = bytes(16),
) -> FramePlan:
    """Actual ConnectCentury13c60→Entry10ed0→ISO11110 selected setup."""
    _uint(bus_id, 16)
    if not isinstance(diagnostic_mode, bytes) or len(diagnostic_mode) != 16:
        raise MonitorError("Century diagnostic mode requires sixteen bytes", INVALID)
    protocol = profile.protocol_info(bus_id)
    if protocol is None:
        raise FrameTransportError(0x90020104, "Century selected protocol is absent")
    iso = _simple_record(profile, 15, 56, 4, word(protocol, 2))
    startup = _function_request(profile, 0x68, 0x90020501)
    tester = _function_request(profile, 0x7F, 0x90020502)
    values = ((1, int.from_bytes(iso[:4], "little")),) + tuple(
        (parameter, word(iso, offset))
        for parameter, offset in (
            (6, 30),
            (7, 28),
            (8, 34),
            (9, 32),
            (10, 50),
            (11, 36),
            (12, 42),
            (13, 40),
            (19, 44),
            (20, 46),
            (21, 48),
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
        )
    )
    source = _source_address(bus_id, profile.category_record[72])
    target = word(protocol, 6) & 255

    def message(body: bytes) -> NativeMessage:
        if len(body) + 3 > 4128:
            raise FrameTransportError(
                0x91020310, "Century native message exceeds storage"
            )
        return NativeMessage(
            4, 0, 0, 0, 0, bytes((0xC0 | (len(body) & 255), target, source)) + body
        )

    address = (
        int.from_bytes(diagnostic_mode[8:12], "little")
        if word(diagnostic_mode, 0) == 1
        else word(protocol, 8)
    )
    return FramePlan(
        NativeConnect(4, 0),
        translate_configs(values, driver),
        (),
        message(b"\x01"),
        message(startup),
        bytes((word(protocol, 4) & 255,)) if word(iso, 6) & 2 else b"",
        startup,
        tester,
        address,
        f"DDB:{profile.catalog.management.sha256}:category={profile.category}:bus={bus_id}:Century11110",
        driver.source,
    )


class CenturyNativeFrameOperations(NativeFrameOperations):
    """Concrete Century24140 vtable11af0/11bb0 framing and registered sources."""

    def __init__(self, *args, registered_response_ids: tuple[int, int], **kwargs):
        if (
            not isinstance(registered_response_ids, tuple)
            or len(registered_response_ids) != 2
        ):
            raise MonitorError(
                "Native Century retains exactly two system registrations", INVALID
            )
        for source in registered_response_ids:
            _uint(source)
        kwargs["native_variant"] = "century"
        super().__init__(*args, **kwargs)
        if self.plan.connect != NativeConnect(4, 0) or self.plan.send.protocol_id != 4:
            raise MonitorError(
                "Century requires its actual fixed ISO connection", INVALID
            )
        self.registered_response_ids = registered_response_ids

    def _frame_message(self, request: bytes) -> NativeMessage:
        _bytes(request, 4125)
        target = word(self.protocol_record, 6) & 255
        source = _source_address(self.bus_id, self.ecu_flags)
        return NativeMessage(
            4,
            0,
            0,
            0,
            0,
            bytes((0xC0 | (len(request) & 255), target, source)) + request,
        )

    def _validate_message(self, message: NativeMessage) -> int:
        data = message.data
        if len(data) < 3:
            return 0x90020601
        if data[0] & 0x3F:
            header, expected = 3, (data[0] & 0x3F) + 3
        elif len(data) >= 4:
            header, expected = 4, data[3] + 4
        else:
            return 0x90020601
        status = (
            0 if (message.extra_data_index or len(data)) == expected else 0x91020324
        )
        if data[1] != 0xB5 or data[2] not in tuple(
            value & 255 for value in self.registered_response_ids
        ):
            status = 0x91020325
        if len(data) > header and data[header] == 0x7F:
            if len(data) < header + 3:
                return 0x90020601
            return {0x78: 0x90020323, 0x21: 0x90020326}.get(
                data[header + 2], 0x90020321
            )
        return status

    def _iso_fast_initialize(self, deadline: float) -> tuple[int, bytes]:
        """Century vtable148→11890 validates B5 and either registered source."""
        if not self.plan.address:
            return 0x90020701, b""
        if not self.plan.startup_request:
            return 0x90020501, b""
        message = self._frame_message(self.plan.startup_request)
        if len(message.data) > 64:
            raise MonitorError(
                "Century fast-init scratch exceeds native storage", INVALID
            )
        message = NativeMessage(4, 0, 0, 0, len(message.data), message.data)
        cleared = self._ioctl(8, None, deadline)
        if cleared.code:
            return self._status(cleared.code), b""
        result = self._ioctl(5, message, deadline, output_capacity=64)
        if result.code:
            return self._status(9 if result.code == 7 else result.code), b""
        if len(result.messages) != 1 or len(result.messages[0].data) < 6:
            return 0x91020301, b""
        data = result.messages[0].data
        valid = (
            data[1] == 0xB5
            and data[2] in tuple(value & 255 for value in self.registered_response_ids)
            and data[3] == 0xC1
        )
        return (0 if valid else 0x91020301), data[4:6]


@dataclass(frozen=True)
class CenturySystem:
    operations: NativeFrameOperations
    event: CenturyMonitorEvent | None
    request_id: int
    response_id: int
    parameter_8: int
    send_timeout: int
    receive_timeout: int
    default_source: int
    attempts: int = 3

    def __post_init__(self) -> None:
        if not isinstance(self.operations, NativeFrameOperations) or (
            self.event is not None and not isinstance(self.event, CenturyMonitorEvent)
        ):
            raise MonitorError("Century requires selected typed systems", INVALID)
        if self.operations.channel is not None or self.operations.poisoned:
            raise MonitorError(
                "Century physical system must own a fresh transport", INVALID
            )
        for value in (
            self.request_id,
            self.response_id,
            self.parameter_8,
            self.send_timeout,
            self.receive_timeout,
            self.attempts,
            self.default_source,
        ):
            _uint(value)

    @property
    def data_event(self) -> CenturyMonitorEvent:
        if self.event is None:
            raise NativeMonitorSourceFault(
                "Native Century start dereferences an absent registered DM event "
                f"(build {self.operations.native_build}, category {self.operations.profile.category})"
            )
        return self.event


class CenturyJ2534Worker(DirectJ2534Worker):
    """Native2b290/2b6a0 common-PID functional and physical two-system loop."""

    _allow_century = True

    def __init__(
        self,
        systems: tuple[CenturySystem, CenturySystem],
        functional: CenturyNativeFrameOperations,
        *,
        default_source: int,
        system_packet_sink: Callable[[int, NativeMonitorPacket], None] | None = None,
        **kwargs,
    ):
        if (
            not isinstance(systems, tuple)
            or len(systems) != 2
            or not all(isinstance(s, CenturySystem) for s in systems)
        ):
            raise MonitorError(
                "Native Century requires exactly two selected systems", INVALID
            )
        if not isinstance(functional, CenturyNativeFrameOperations):
            raise MonitorError(
                "Native Century requires concrete registered transport", INVALID
            )
        first, second = systems
        if kwargs.get("packet_sink") is not None:
            raise MonitorError(
                "Century packet sink requires the selected system index", INVALID
            )
        if default_source != first.default_source:
            raise MonitorError(
                "Century constructor source disagrees with its first system", INVALID
            )
        if functional.registered_response_ids != (
            first.default_source,
            second.default_source,
        ):
            raise MonitorError(
                "Century source registrations disagree with selected systems", INVALID
            )
        if any(
            s.operations.backend is not functional.backend
            or s.operations.native_build != functional.native_build
            for s in systems
        ):
            raise MonitorError(
                "Century systems must share one native driver source", INVALID
            )
        super().__init__(
            functional,
            first.event,
            request_id=first.request_id,
            response_id=first.response_id,
            default_source=default_source,
            attempts=first.attempts,
            send_timeout=first.send_timeout,
            receive_timeout=first.receive_timeout,
            **kwargs,
        )
        self.systems, self.functional = systems, functional
        self.system_packet_sink = system_packet_sink
        self.common_ids = b""
        self.century_mode = 0
        if first.event is not None and second.event is not None:
            self.common_ids = bytes(
                pid for pid in first.event.ids if pid in second.event.ids
            )
            self.century_mode = (
                1
                if len(self.common_ids) == len(first.event.ids) == len(second.event.ids)
                else 3
                if self.common_ids
                else 2
            )
        self.functional_mode = self.century_mode in (1, 3)
        self.common_index = self.physical_index = self.received_count = 0
        self.system_packets: list[tuple[int, NativeMonitorPacket]] = []
        self._physical_open = False

    def _set_system(self, index: int) -> None:
        selected = self.systems[index]
        self.physical_index = index
        self.request_id, self.response_id = selected.request_id, selected.response_id
        self.default_source = selected.default_source
        self.send_timeout, self.receive_timeout = (
            selected.send_timeout,
            selected.receive_timeout,
        )
        self.attempts = selected.attempts
        self.events = (*self.events[:2], selected.event)

    def _physical(self, index: int) -> int:
        selected = self.systems[index]
        previous = self.operations
        if previous is not selected.operations:
            if self.functional_mode or previous.channel is None:
                status = previous.close(deadline=self.deadline)
                if status:
                    return status
                self._activate_operations(selected.operations)
                status = self.operations.open(deadline=self.deadline)
            else:
                # SetCommSystemInfo changes the selected category on the existing
                # ISO channel; it does not connect a second hardware session.
                handle, owned = previous.channel, previous.owns_channel
                selected.operations.adopt_channel(handle, owned=owned)
                previous.channel, previous.owns_channel = None, False
                self._activate_operations(selected.operations)
                status = self.operations.setup(deadline=self.deadline)
            if status:
                return status
        self.functional_mode = False
        self._physical_open = True
        self._set_system(index)
        return 0

    def _functional(self) -> int:
        if self.operations is not self.functional:
            status = self.controller.disconnect(0, deadline=self.deadline)
            if status:
                return status
            self._activate_operations(self.functional)
        if self.operations.channel is None:
            status = self.operations.open(deadline=self.deadline)
            if status:
                return status
        self.functional_mode = True
        self._set_system(0)
        return 0

    def start(self) -> int:
        if self.state != "configured" or any(
            s.operations.channel is not None or s.operations.poisoned
            for s in self.systems
        ):
            raise MonitorError("Century start requires fresh selected systems", INVALID)
        events = tuple(system.data_event for system in self.systems)
        if self.functional.channel is not None or self.functional.poisoned:
            raise MonitorError("Century functional transport must be fresh", INVALID)
        self.deadline = self._now() + self.timeout
        self._check()
        self.owned = True
        for event in events:
            event.start()
        if self.century_mode == 2:
            self._activate_operations(self.systems[0].operations)
            self.functional_mode = False
            self._set_system(0)
        self._activate_operations(self.operations)
        try:
            status = self.operations.open(deadline=self.deadline)
        except BaseException:
            self._restore_operation_guards()
            self.state = "fault"
            raise
        if status:
            self._restore_operation_guards()
            self.state = "fault"
            return status
        self.state = "select"
        return OK

    def _error(
        self, *, negative: bool = False, data: bytes = b"", direct: int = 0
    ) -> int:
        previous = self.request_id
        if self.functional_mode:
            self.request_id = self.systems[0].parameter_8
        try:
            return super()._error(negative=negative, data=data, direct=direct)
        finally:
            self.request_id = previous

    def _century_harvest(self, index: int) -> None:
        event = self.systems[index].data_event
        packets = tuple(event.packets)
        self._harvest(event)
        self.system_packets.extend((index, packet) for packet in packets)
        if self.system_packet_sink is not None:
            for packet in packets:
                self.system_packet_sink(index, packet)

    def _next_physical(self) -> int:
        next_index = (self.physical_index + 1) % 2
        if self.century_mode == 3:
            if next_index == 1 and len(self.common_ids) == len(
                self.systems[1].data_event.ids
            ):
                next_index = 0
            if next_index == 0:
                self.common_index = self.received_count = 0
                return self._functional()
        return self._physical(next_index)

    def step(self) -> int:
        if self.state not in ("select", "send", "receive", "idle"):
            raise MonitorError("Native Century worker is not running", INVALID)
        self._check()
        if self.state == "idle":
            return OK
        event = self.systems[self.physical_index].data_event
        if self.state == "select":
            result = (
                event.skip_selected_pid(self.common_ids[self.common_index])
                if self.functional_mode
                else event.skip_functional_items()
            )
            if result != OK:
                return self._error(direct=result)
            self.slot = 2
            self.request = event.get_snd_frame(self._tick())
            self.state = "send"
            return OK
        if self.state == "send":
            self.received_count = 0
            status = self.controller.send(
                self.request,
                timeout=self.send_timeout,
                initialization_mode=1,
                clear_rx=1,
                deadline=self.deadline,
            )
            if status:
                self.failures += 1
                if self.failures >= self.attempts:
                    return self._error()
            else:
                event.set_status(2)
                self.state = "receive"
            return OK
        observed = self.controller.receive(
            maximum=0x1000,
            timeout=self.receive_timeout,
            argument_5=0,
            flags=100,
            deadline=self.deadline,
        )
        if observed.code:
            if observed.code in (0x90020321, 0x90020323):
                return self._error(negative=True, data=observed.data)
            self.failures += 1
            if self.failures < self.attempts:
                self.state = "send"
                return OK
            return self._error()
        tick = self._tick()
        if self.functional_mode:
            index = next(
                (
                    i
                    for i, system in enumerate(self.systems)
                    if system.default_source == observed.source_id
                ),
                -1,
            )
            if index < 0:
                return self._error(direct=INVALID)
            result = self.systems[index].data_event.check_rcv_frame(observed.data, tick)
            if result != OK:
                return self._error(direct=result)
            self._century_harvest(index)
            self.received_count = (self.received_count + 1) % 2
            if self.received_count:
                return OK
            self.common_index += 1
            if self.common_index == len(self.common_ids):
                self.common_index = 0
                if self.century_mode == 3:
                    for system in self.systems:
                        system.data_event.index = 0
                        system.data_event.item.status = 0
                    index = (
                        1
                        if len(self.common_ids) == len(self.systems[0].data_event.ids)
                        else 0
                    )
                    status = self._physical(index)
                    if status:
                        self.state = "fault"
                        return status
        else:
            result = event.check_rcv_frame(observed.data, tick)
            if result != OK:
                return self._error(direct=result)
            self._century_harvest(self.physical_index)
            if event.receive_flag != 1:
                event.advance()
            else:
                status = self._next_physical()
                if status:
                    self.state = "fault"
                    return status
        self.failures = 0
        self.state = "select"
        return OK

    def stop(self) -> int:
        if self.state not in ("select", "send", "receive", "idle"):
            raise MonitorError("Century stop requires running state", INVALID)
        self.deadline = self._now() + self.timeout
        self._check()
        self.state = "stopped"
        return OK

    def system_capture(self, index: int) -> NativeRecorderCapture:
        if type(index) is not int or index not in (0, 1):
            raise MonitorError("Century system index must be zero or one", INVALID)
        return NativeRecorderCapture(
            0,
            tuple(packet for source, packet in self.system_packets if source == index),
        )

    def run_systems(
        self, cycles: int
    ) -> tuple[NativeRecorderCapture, NativeRecorderCapture]:
        if type(cycles) is not int or not 0 < cycles <= self.max_packets // 2:
            raise MonitorError("Century cycle count exceeds packet budget", ALLOCATION)
        self.run(cycles * 2)
        captures = (self.system_capture(0), self.system_capture(1))
        if any(len(capture.packets) != cycles for capture in captures):
            raise MonitorError(
                "Century native cycles did not complete both systems", INVALID
            )
        return captures
