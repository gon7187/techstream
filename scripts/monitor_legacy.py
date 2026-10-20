"""Recovered normal legacy monitor producers and concrete low-level event machines.

All transport calls are injected; this module never executes an OEM binary.
Native function offsets and remaining family coverage are in docs/monitor-legacy.md.
"""

from __future__ import annotations

import math
import struct
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from io import BytesIO

    from scripts.data_monitor import (
        MonitorCommand,
        MonitorPacket,
        SelectedMonitorConnection,
        SelectedMonitorSession,
    )
    from scripts.drive_recorder import (
        DrsFile,
        DrsTable,
        NativeDmciCommand,
        NativeMonitorBuffer,
        NativeRecorderCapture,
        NativeTriggerInfo,
        NativeTriggerParameters,
        NativeVehicleSelection,
        NativeVimClient,
    )
    from scripts.frame_transport import (
        DriverProperties,
        FramePlan,
        NativeFrameOperations,
    )
    from scripts.monitor_dlc12 import (
        DLC12VoltageObservation,
        DLC12VoltageState,
        SelectedDLC12Monitor,
    )
    from scripts.monitor_instruments import SelectedInstrumentMonitor
    from scripts.monitor_j2534 import (
        CenturyJ2534Worker,
        CenturyNativeFrameOperations,
        DirectJ2534Worker,
    )
    from scripts.monitor_psa import SelectedPSAMonitor
    from scripts.monitor_support import (
        PacketFrameCache,
        SupportStream,
        SupportTransaction,
    )
    from scripts.native_communication import NativeCommunication

from scripts.data_monitor import (
    MAX_BYTES,
    MAX_ITEMS,
    MonitorDefinitions,
    MonitorError,
    MonitorProvider,
    MonitorRange,
    MonitorReceive,
    MonitorSetup,
    MonitorSignalMetadata,
)
from scripts.profiles import ProtocolProfile, VehicleProfile


def _selected_profile(profile: object) -> VehicleProfile:
    if not isinstance(profile, VehicleProfile):
        raise MonitorError("Legacy monitor requires a selected ECU database")
    return profile


from scripts.toyota_session import Cancelled, Limits


def _uint(value: int, maximum: int, name: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise MonitorError(f"{name} must fit uint{maximum.bit_length()}")
    return value


def _lengths(items: Sequence[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    result = tuple(items)
    if not result or len(result) > 255:
        raise MonitorError("Native legacy PID list requires1..255 entries")
    for item in result:
        if not isinstance(item, tuple) or len(item) != 2:
            raise MonitorError("Native PID descriptor requires ID and length")
        _uint(item[0], 255, "PID")
        _uint(item[1], 255, "PID length")
    return result


@dataclass(frozen=True)
class LegacyPacking:
    family: str
    mode: int
    setup_requests: tuple[bytes, ...]
    frame_sizes: tuple[tuple[int, int], ...]
    # PID, generated frame, byte offset, data length; no semantic value is inferred.
    pid_layouts: tuple[tuple[int, int, int, int], ...]


def pack_phase3_mode1(
    selected_lengths: Mapping[int, int], *, maximum_request: int
) -> LegacyPacking:
    """Phase3 39e0: ascending PID scan, A1/01 and FF byte placeholders."""
    _uint(maximum_request, 256, "Maximum native request")
    if maximum_request < 2 or len(selected_lengths) > 256:
        raise MonitorError("Native Phase3 request capacity is invalid")
    selected = _lengths(tuple(selected_lengths.items()))
    request = bytearray(b"\xa1\x01")
    layouts = []
    size = 0
    for pid, length in sorted(selected):
        if not length or length > maximum_request - 2:
            continue
        if size + length > maximum_request - 2:
            raise MonitorError("Native Phase3 mode1 capacity exceeded", 0x9005100A)
        layouts.append((pid, 1, size, length))
        size += length
        request.extend(bytes((pid,)) + b"\xff" * (length - 1))
    if not size:
        raise MonitorError("Native Phase3 mode1 has no data", 0xA0050422)
    return LegacyPacking("P3", 1, (bytes(request),), ((1, size),), tuple(layouts))


def pack_legacy_pairs(
    family: str,
    selected_lengths: Sequence[tuple[int, int]],
    enabled_lengths: Mapping[int, int],
    *,
    mode: int,
) -> LegacyPacking:
    """P3 3cf0/DK43d0: selected order, observed fallback lengths, paired descriptors.

    PSA26e0 also uses the same final ID/length form after Mode35 remapping;
    callers must pass that producer's resulting IDs, never guessed raw DIDs.
    """
    if (
        family not in ("P3", "DK", "PSA")
        or mode not in (0x10, 0x20, 0x100, 0x200)
        or (mode == 0x200 and family != "DK")
        or (family == "PSA" and mode == 0x100)
    ):
        raise MonitorError("Native legacy pair family/mode is invalid")
    selected = _lengths(selected_lengths)
    if len(enabled_lengths) > 256:
        raise MonitorError("Native enabled PID table exceeds256 entries")
    for pid, length in enabled_lengths.items():
        _uint(pid, 255, "Enabled PID")
        _uint(length, 255, "Enabled length")
    ids, sizes, frames, layouts = [], [], [], []
    for pid, selected_length in selected:
        if pid not in enabled_lengths:
            continue
        length = selected_length or enabled_lengths[pid]
        if not length:
            continue
        frame = len(frames)
        ids.append(pid)
        sizes.append(length)
        frames.append((frame, length))
        layouts.append((pid, frame, 0, length))
    if not frames:
        raise MonitorError("Native legacy pair selection has no data", 0x90051010)
    service = 0x2C if mode == 0x200 else (1 if mode == 0x10 else 0x21)
    return LegacyPacking(
        family,
        mode,
        (bytes((service, *ids)), bytes((service | 0x40, *sizes))),
        tuple(frames),
        tuple(layouts),
    )


class LegacyMonitorEvent:
    """DataListIF PSA1d30/2030 and DK6360/6810 retained cycle storage."""

    def __init__(
        self,
        family: str,
        ids: Sequence[int],
        lengths: Sequence[int],
        *,
        addition_frames: Sequence[tuple[int, bytes]] = (),
        dtc_request: bytes | None = None,
        packet_size: int | None = None,
    ):
        if family not in ("PSA", "DK") or len(ids) != len(lengths):
            raise MonitorError("Native legacy event family or lengths differ")
        pairs = _lengths(tuple(zip(ids, lengths))) if ids else ()
        if any(not length for _, length in pairs):
            raise MonitorError("Native legacy event lengths must be nonzero")
        if len(addition_frames) > 255:
            raise MonitorError("Native PSA additional frame count exceeds255")
        options: dict[int, bytes] = {}
        for pid, option in addition_frames:
            _uint(pid, 255, "Additional frame PID")
            if family != "PSA" or not isinstance(option, bytes) or len(option) > 4094:
                raise MonitorError("Native additional frame is invalid")
            # GetSndFrame chooses the first matching Mode21 descriptor.
            options.setdefault(pid, option)
        requests = [
            bytes((0x21 if family == "PSA" else 0x2C, pid)) + options.get(pid, b"")
            for pid, _ in pairs
        ]
        sizes = [length for _, length in pairs]
        if dtc_request is not None:
            if (
                family != "DK"
                or not isinstance(dtc_request, bytes)
                or len(dtc_request) > 4095
            ):
                raise MonitorError("Native DK DTC request is invalid")
            requests.append(b"\x13" + dtc_request)
            sizes.append(1)
        if not requests:
            raise MonitorError("Native legacy event requires selected data")
        self.family = family
        self.requests = tuple(requests)
        self.lengths = tuple(sizes)
        self.index = self._offset = 0
        total = sum(sizes)
        if packet_size is not None:
            _uint(packet_size, 65535, "Native packet size")
            if packet_size < total:
                raise MonitorError("Native packet buffer is shorter than event data")
            total = packet_size
        self._data = bytearray(total)

    @classmethod
    def psa(
        cls,
        ids: Sequence[int],
        lengths: Sequence[int],
        *,
        addition_frames: Sequence[tuple[int, bytes]] = (),
    ) -> LegacyMonitorEvent:
        return cls("PSA", ids, lengths, addition_frames=addition_frames)

    @classmethod
    def dk_iso9141(
        cls,
        ids: Sequence[int],
        lengths: Sequence[int],
        *,
        dtc_request: bytes | None = None,
        packet_size: int | None = None,
    ) -> LegacyMonitorEvent:
        return cls("DK", ids, lengths, dtc_request=dtc_request, packet_size=packet_size)

    @property
    def request(self) -> bytes:
        return self.requests[self.index]

    def accept(self, reply: bytes, timestamp_raw: int) -> tuple[int, bytes] | None:
        _uint(timestamp_raw, 0xFFFFFFFF, "Native timestamp")
        if not isinstance(reply, bytes) or len(reply) > 4096:
            raise MonitorError("Native legacy reply exceeds4096 bytes", 0xE0000102)
        size = self.lengths[self.index]
        if self.family == "DK" and self.request[0] == 0x13:
            count = next(
                (index for index, value in enumerate(reply) if value == 0), len(reply)
            )
            payload = bytes((count & 255,))
        else:
            header = 2 if self.family == "PSA" else 1
            if len(reply) < header or (self.family == "PSA" and reply[0] != 0x61):
                raise MonitorError(
                    "Native legacy reply lacks expected header", 0xE0000102
                )
            payload = reply[header : header + size]
        self._data[self._offset : self._offset + len(payload)] = payload
        self._offset += size
        self.index += 1
        if self.index != len(self.requests):
            return None
        packet = bytes(self._data)
        self.index = self._offset = 0
        self._data[:] = bytes(len(self._data))
        return timestamp_raw, packet


class Phase3Stream:
    """Low-level raw stream fragments only; ring packet assembly is caller-owned.

    Phase3 6570/6770/68d0/6950 A1→E2/A2→A3/E3 machine.

    ECU names bind the native send address at the injected provider; source_id
    remains a separate literal receive address, as in the original node.
    """

    def __init__(
        self,
        provider: MonitorProvider,
        ecu: str,
        *,
        source_id: int,
        protocol: int,
        request: bytes,
        retries: int,
        send_timeout: int,
        receive_timeout: int,
        interval: int,
    ):
        if (
            not isinstance(ecu, str)
            or not ecu
            or not isinstance(request, bytes)
            or not 2 <= len(request) <= 255
        ):
            raise MonitorError("Native Phase3 requires ECU and2..255-byte setup")
        if request[0] != 0xA1:
            raise MonitorError("Native Phase3 stream setup must use A1")
        self.source_id = _uint(source_id, 0xFFFFFFFF, "Receive source ID")
        self.protocol = _uint(protocol, 65535, "Protocol")
        self.retries = _uint(retries, MAX_ITEMS - 1, "Retry count")
        self.send_timeout = _uint(send_timeout, 0xFFFFFFFF, "Send timeout")
        self.receive_timeout = _uint(receive_timeout, 0xFFFFFFFF, "Receive timeout")
        self.interval = _uint(interval, 0xFFFFFFFF, "Interval")
        self.provider, self.ecu, self.request = provider, ecu, request
        self._call_guard: Callable[[], None] = lambda: None
        self.state = 1
        self.deadline = 0

    def _send(self, request: bytes, initialize: bool) -> int:
        self._call_guard()
        code = self.provider.send(
            self.ecu,
            request,
            timeout=self.send_timeout,
            protocol=self.protocol,
            initialize=initialize,
        )
        return _uint(code, 0xFFFFFFFF, "Native send code")

    def _receive(self, timeout: int) -> MonitorReceive:
        self._call_guard()
        result = self.provider.receive(
            self.ecu, buffer=True, maximum=8, timeout=timeout, argument_5=0, flags=100
        )
        if not isinstance(result, MonitorReceive) or len(result.data) > 8:
            raise MonitorError("Native Phase3 receive exceeds8-byte frame")
        return result

    def start(
        self,
        *,
        tick_ms: Callable[[], int],
        cancelled: Callable[[], bool] = lambda: False,
        maximum_receives: int = 1000,
    ) -> None:
        _uint(maximum_receives, MAX_ITEMS, "Receive budget")
        if maximum_receives == 0:
            raise MonitorError("Native receive budget must be nonzero")
        if cancelled():
            raise Cancelled("Native Phase3 monitor cancelled")
        if self.state != 1:
            raise MonitorError("Native Phase3 setup already consumed")
        if self.request[1] == 1:
            remaining = maximum_receives
            code = 0
            for _ in range(self.retries + 1):
                if cancelled():
                    raise Cancelled("Native Phase3 monitor cancelled")
                code = self._send(self.request, True)
                if not code:
                    started = _uint(tick_ms(), 0xFFFFFFFF, "Native tick")
                    while remaining:
                        if cancelled():
                            raise Cancelled("Native Phase3 monitor cancelled")
                        now = _uint(tick_ms(), 0xFFFFFFFF, "Native tick")
                        if now > ((started + self.receive_timeout) & 0xFFFFFFFF):
                            code = 0xA1050302
                            break
                        remaining -= 1
                        observed = self._receive(self.receive_timeout)
                        code = observed.code
                        if code:
                            break
                        if (
                            observed.source_id == self.source_id
                            and observed.data
                            == bytes((self.request[0] | 0x40,)) + self.request[1:]
                        ):
                            self.state, self.deadline = 2, 0
                            return
                    else:
                        raise MonitorError(
                            "Native Phase3 receive budget exhausted", 0xA1050302
                        )
            if code:
                raise MonitorError("Native Phase3 setup failed", code)
        self.state, self.deadline = 2, 0

    def poll(
        self,
        timestamp_raw: int,
        *,
        timeout: int = 0,
        tick_ms: Callable[[], int] | None = None,
    ) -> tuple[int, bytes] | None:
        _uint(timestamp_raw, 0xFFFFFFFF, "Native timestamp")
        _uint(timeout, 0xFFFFFFFF, "Native receive timeout")
        observed = self._receive(timeout)
        if tick_ms is not None:
            timestamp_raw = _uint(tick_ms(), 0xFFFFFFFF, "Native receive tick")
        if observed.code == 0x91010009:
            return None
        if observed.code:
            raise MonitorError("Native Phase3 receive failed", 0xA1050307)
        if observed.source_id != self.source_id or not observed.data:
            return None
        if observed.data[0] == 0xE3 and self.state == 6:
            self.state = 0
        elif (
            observed.data[0] == 0xE2
            and len(observed.data) >= 2
            and self.state in (2, 3, 4)
        ):
            self.state = 4
            return timestamp_raw, observed.data[1:]
        return None

    def resume(self, timestamp_raw: int) -> None:
        _uint(timestamp_raw, 0xFFFFFFFF, "Native timestamp")
        if self.state not in (2, 4):
            raise MonitorError(
                "Native Phase3 resume requires setup or completed receive"
            )
        code = self._send(b"\xa2" + self.request[1:2], False)
        if code:
            raise MonitorError("Native Phase3 A2 send failed", code)
        self.state = 3
        self.deadline = (timestamp_raw + self.interval) & 0xFFFFFFFF

    def advance(self, timestamp_raw: int) -> None:
        """Phase3 63a0 states2/3/4 scheduler decisions at an explicit tick."""
        _uint(timestamp_raw, 0xFFFFFFFF, "Native timestamp")
        if self.state == 2 or (self.state == 4 and self.deadline <= timestamp_raw):
            self.resume(timestamp_raw)
        elif self.state == 3 and self.deadline <= timestamp_raw:
            raise MonitorError("Native Phase3 receive interval expired", 0xA1050308)

    def stop(self) -> None:
        if self.state == 0:
            return
        code = self._send(b"\xa3", False)
        if code:
            raise MonitorError("Native Phase3 A3 send failed", code)
        self.state, self.deadline = 6, 0

    def shutdown(
        self,
        *,
        tick_ms: Callable[[], int],
        maximum_receives: int = 1000,
    ) -> None:
        """Native6220 A3/E3 cleanup with its literal2000ms drain window."""
        _uint(maximum_receives, MAX_ITEMS, "Receive budget")
        if not maximum_receives:
            raise MonitorError("Native receive budget must be nonzero")
        if self.state in (2, 3, 4):
            self.stop()
        if self.state != 6:
            return
        deadline = (_uint(tick_ms(), 0xFFFFFFFF, "Native tick") + 2000) & 0xFFFFFFFF
        for _ in range(maximum_receives):
            now = _uint(tick_ms(), 0xFFFFFFFF, "Native tick")
            if now > deadline:
                break
            self.poll(now, timeout=self.receive_timeout)
            if self.state == 0:
                return
        raise MonitorError("Native Phase3 E3 shutdown incomplete", 0xA1050303)


class LegacyNativeProvider:
    """Literal MonitorProvider binding to the recovered lower J2534 operations."""

    def __init__(
        self,
        operations: NativeFrameOperations,
        *,
        ecu: str,
        deadline: float | None = None,
    ):
        from scripts.frame_transport import NativeFrameOperations
        from scripts.monitor_support import monitor_source_identity

        if (
            not isinstance(operations, NativeFrameOperations)
            or not isinstance(ecu, str)
            or not ecu
        ):
            raise MonitorError(
                "Native monitor binding requires selected operations and ECU"
            )
        self.operations, self.ecu, self.deadline = operations, ecu, deadline
        self._call_guard: Callable[[], None] = lambda: None
        self.source_identity = monitor_source_identity(operations.profile, ecu)
        self.transport_identity = (
            operations.plan,
            operations.bus_id,
            operations.driver,
            operations.diagnostic_mode,
            operations.native_build,
            operations.native_variant,
        )

    def _check(self, ecu: str) -> None:
        self._call_guard()
        from scripts.monitor_support import monitor_source_identity

        if (
            ecu != self.ecu
            or monitor_source_identity(self.operations.profile, ecu)
            != self.source_identity
            or (
                self.operations.plan,
                self.operations.bus_id,
                self.operations.driver,
                self.operations.diagnostic_mode,
                self.operations.native_build,
                self.operations.native_variant,
            )
            != self.transport_identity
        ):
            raise MonitorError("Native monitor binding source changed")

    def send(
        self,
        ecu: str,
        request: bytes | None,
        *,
        timeout: int,
        protocol: int,
        initialize: bool,
    ) -> int:
        self._check(ecu)
        if protocol != self.operations.bus_id or type(initialize) is not bool:
            raise MonitorError("Native monitor protocol/initialization differs")
        return self.operations.send(
            request,
            timeout=timeout,
            initialization_mode=0 if request is None else (1 if initialize else 2),
            deadline=self.deadline,
        )

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
        self._check(ecu)
        result = self.operations.receive(
            maximum=maximum,
            timeout=timeout,
            argument_5=argument_5,
            flags=flags,
            buffer=buffer,
            deadline=self.deadline,
        )
        return MonitorReceive(result.data, result.source_id, result.code)


def run_dk_native(
    plan: SelectedDkMonitor,
    operations: NativeFrameOperations,
    *,
    ecu: str,
    retry_limit: int,
    packet_limit: int,
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[MonitorPacket, ...]:
    """Selected DK setup/start→native event cycles→stop/disconnect lifecycle."""
    from scripts.data_monitor import MonitorPacket
    from scripts.frame_transport import NativeFrameOperations
    from scripts.monitor_support import monitor_source_identity

    if not isinstance(plan, SelectedDkMonitor) or not isinstance(
        operations, NativeFrameOperations
    ):
        raise MonitorError(
            "Native DK lifecycle requires selected plan and lower operations"
        )
    if operations.channel is not None or operations.poisoned:
        raise MonitorError("Native DK lifecycle requires a fresh unopened transport")
    _uint(retry_limit, MAX_ITEMS, "Retry limit")
    bounds = limits or Limits()
    _uint(packet_limit, MAX_ITEMS, "Packet limit")
    if not packet_limit:
        raise MonitorError("Native DK packet limit must be positive")
    if packet_limit * (4 + sum(size for _, size in plan.frame_sizes)) > MAX_BYTES:
        raise MonitorError("Native DK capture exceeds timestamp/payload byte budget")
    profile = _selected_profile(operations.profile)
    if plan.source_identity != monitor_source_identity(profile, ""):
        raise MonitorError("Native DK lifecycle source differs")
    selected = selected_legacy_j2534_frames(
        profile,
        plan,
        ecu=ecu,
        bus_id=operations.bus_id,
        driver=operations.driver,
        diagnostic_mode=operations.diagnostic_mode,
        connected_device=operations.device_kind,
        source_build=operations.native_build,
    )
    if not selected.frames or operations.plan != selected.frames[0]:
        raise MonitorError("Native DK lower frame differs from selected constructor")

    last_clock: float | None = None

    def now() -> float:
        nonlocal last_clock
        value = clock()
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise MonitorError("Native DK lifecycle clock must be finite")
        value = float(value)
        if last_clock is not None and value < last_clock:
            raise MonitorError("Native DK lifecycle clock moved backwards")
        last_clock = value
        return value

    deadline = now() + bounds.seconds
    calls = 0

    def guard() -> None:
        nonlocal calls
        if cancelled():
            raise Cancelled("Native DK lifecycle cancelled")
        calls += 1
        if calls > bounds.exchanges or now() >= deadline:
            raise MonitorError("Native DK lifecycle budget exhausted")

    provider = LegacyNativeProvider(operations, ecu=ecu, deadline=deadline)
    provider._call_guard = guard
    send_timer, receive_timer = dk_monitor_timing(profile)
    data_ids = plan.packing.setup_requests[0][1:] if plan.packing.setup_requests else ()
    data_lengths = (
        plan.packing.setup_requests[1][1:] if plan.packing.setup_requests else ()
    )
    event = LegacyMonitorEvent.dk_iso9141(
        data_ids,
        data_lengths,
        dtc_request=None if plan.auxiliary is None else plan.auxiliary.request[1:],
        packet_size=sum(size for _, size in plan.frame_sizes),
    )
    packets = []
    packet_bytes = 0
    failure: BaseException | None = None
    original_cancelled = operations.cancelled
    operations.cancelled = lambda: cancelled() or original_cancelled()
    try:
        guard()
        code = operations.open(deadline=deadline)
        if code:
            raise MonitorError("Native DK interface open/setup failed", code)
        while len(packets) < packet_limit:
            timestamp, payload = dk_monitor_cycle(
                event,
                provider,
                ecu,
                protocol=operations.bus_id,
                send_timeout=send_timer,
                receive_timeout=receive_timer,
                retry_limit=retry_limit,
                tick_ms=lambda: int(now() * 1000) & 0xFFFFFFFF,
                cancelled=cancelled,
                maximum_calls=bounds.exchanges,
            )
            if now() >= deadline:
                raise MonitorError("Native DK lifecycle deadline exhausted")
            packet_bytes += 4 + len(payload)
            if packet_bytes > MAX_BYTES:
                raise MonitorError("Native DK capture byte budget exhausted")
            packets.append(MonitorPacket(timestamp, payload))
        return tuple(packets)
    except BaseException as error:
        if isinstance(error, InterruptedError) and cancelled():
            failure = Cancelled("Native DK lifecycle cancelled")
            raise failure from error
        failure = error
        raise
    finally:
        try:
            try:
                cleanup_deadline = now() + bounds.seconds
            except BaseException as clock_error:
                # The lower owner has a separate bounded fallback cleanup clock.
                code = operations.close()
                if code:
                    raise MonitorError(
                        "Native DK fallback disconnect failed", code
                    ) from clock_error
                raise
            code = operations.close(deadline=cleanup_deadline)
            if code or now() >= cleanup_deadline:
                raise MonitorError(
                    "Native DK disconnect failed or exceeded deadline",
                    code or 0xC0050503,
                )
        except BaseException as error:
            if failure is None:
                raise
            failure.add_note(f"Native DK cleanup failed: {error}")
        finally:
            operations.cancelled = original_cancelled


def dk_monitor_timing(profile: ProtocolProfile) -> tuple[int, int]:
    """DataListIF7a10: first selected functionA7 settings, native defaults."""
    from scripts.support import correspondence_rows, word

    management = profile.catalog.management
    functions = tuple(
        row
        for row in correspondence_rows(management, 18, profile.exception_ids)
        if word(row, 0) == profile.category and word(row, 2) == 0xA7
    )
    settings_id = word(functions[0], 4) if functions else 1
    settings = tuple(
        row
        for row in correspondence_rows(management, 29, profile.exception_ids)
        if word(row, 10) == settings_id
    )
    if not settings:
        return 1000, 200
    row = settings[0]
    return int.from_bytes(row[:4], "little"), int.from_bytes(row[4:8], "little")


def dk_monitor_cycle(
    event: LegacyMonitorEvent,
    provider: MonitorProvider,
    ecu: str,
    *,
    protocol: int,
    send_timeout: int,
    receive_timeout: int,
    retry_limit: int,
    tick_ms: Callable[[], int],
    cancelled: Callable[[], bool] = lambda: False,
    maximum_calls: int = 1000,
) -> tuple[int, bytes]:
    """DataListIF7650 synchronous states1/2, bounded at low-level driver calls.

    Every receive failure retransmits the same request, except13 DTC which
    immediately faults. Send and receive errors share the native retry counter;
    a successful response resets it before the next cycle item.
    """
    if not isinstance(event, LegacyMonitorEvent) or event.family != "DK":
        raise MonitorError("Native DK cycle requires its selected event")
    if not isinstance(ecu, str) or not ecu:
        raise MonitorError("Native DK cycle requires selected ECU")
    _uint(protocol, 65535, "Protocol")
    _uint(send_timeout, 0xFFFFFFFF, "Send timeout")
    _uint(receive_timeout, 0xFFFFFFFF, "Receive timeout")
    _uint(retry_limit, MAX_ITEMS, "Retry limit")
    _uint(maximum_calls, MAX_ITEMS, "Driver call budget")
    calls = 0
    retries = 0

    def check() -> None:
        nonlocal calls
        if cancelled():
            raise Cancelled("Native DK monitor cancelled")
        calls += 1
        if calls > maximum_calls:
            raise MonitorError("Native DK monitor driver budget exhausted")

    while True:
        check()
        code = provider.send(
            ecu, event.request, timeout=send_timeout, protocol=protocol, initialize=True
        )
        _uint(code, 0xFFFFFFFF, "Native send code")
        if cancelled():
            raise Cancelled("Native DK monitor cancelled")
        if not code:
            check()
            observed = provider.receive(
                ecu,
                buffer=True,
                maximum=4096,
                timeout=receive_timeout,
                argument_5=0,
                flags=100,
            )
            if cancelled():
                raise Cancelled("Native DK monitor cancelled")
            if not isinstance(observed, MonitorReceive):
                raise MonitorError("Native DK receive requires typed fields")
            code = observed.code
            if not code:
                result = event.accept(observed.data, tick_ms())
                retries = 0
                if result is not None:
                    return result
                continue
            if event.request[0] == 0x13:
                raise MonitorError("Native DK DTC receive failed", 0xE0040001)
        retries += 1
        if retries >= retry_limit:
            mapped = (
                0xE0001001
                if code == 0x90020328
                else (0xE0040001 if event.request[0] == 0x13 else 0xE0020001)
            )
            raise MonitorError("Native DK monitor exchange failed", mapped)


def legacy_pair_commands(
    packing: LegacyPacking,
    *,
    interface_id: int,
    buffer_468: int,
    standard_values: Sequence[tuple[int, int]],
    parameter_8: int,
) -> MonitorSetup:
    """P3 dea0 and PSA8b20→DataListIF31f0/280e0 SetupPair fields.

    P3 parameter8 is caller field piVar1[4] for interfacecount>=2 and FFFFFFFF
    otherwise; preserving it explicitly avoids assuming a timeout meaning.
    """
    from scripts.data_monitor import MonitorCommand, MonitorSetup

    if packing.family not in ("P3", "PSA") or packing.mode not in (0x10, 0x20, 0x100):
        raise MonitorError("Native DMCI pair wrapper requires P3/PSA pair packing")
    for value in (interface_id, buffer_468, parameter_8):
        _uint(value, 0xFFFFFFFF, "Native pair field")
    standards = tuple(standard_values)
    if len(standards) > MAX_ITEMS:
        raise MonitorError("Native standard table exceeds budget")
    for pair in standards:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise MonitorError("Native standard requires two DWORD fields")
        for value in pair:
            _uint(value, 0xFFFFFFFF, "Native standard field")
    if len(packing.setup_requests) != 2:
        raise MonitorError("Native pair setup requires two descriptors")
    ids, lengths = packing.setup_requests
    if len(ids) != len(lengths) or len(ids) < 2:
        raise MonitorError("Native pair descriptor lengths differ")
    data_type = {0x10: 0, 0x20: 1, 0x100: 3}[packing.mode]
    return MonitorSetup(
        (
            MonitorCommand(
                0x10A,
                (
                    buffer_468,
                    interface_id,
                    data_type,
                    tuple(zip(ids[1:], lengths[1:])),
                    sum(size for _, size in packing.frame_sizes),
                    standards,
                    3,
                    parameter_8,
                ),
            ),
        ),
        (MonitorCommand(0x10C, ()),),
        (MonitorCommand(0x10E, ()),),
    )


@dataclass(frozen=True)
class SelectedPhase3Pairs:
    packing: LegacyPacking
    signals: tuple[MonitorSignalMetadata, ...]
    commands: MonitorSetup


def selected_phase3_pairs(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    enabled_lengths: Mapping[int, int],
    observed_functions: Mapping[int, bool],
    *,
    mode: int,
    interface_id: int,
    parameter_8: int,
    standard_values: Sequence[tuple[int, int]],
) -> SelectedPhase3Pairs:
    """Selected Freeze→native P3 3cf0→1aa0/a9b0 metadata→dea0 setup.

    This is the explicit normal pair branch. The automatic mode fallback and
    trigger/composite branches require their own concrete producers.
    """
    from scripts.data_monitor import (
        monitor_capabilities,
        selected_definitions,
        selected_signal_metadata,
    )

    if profile.category_record[72] & 31 not in (3, 5, 9, 0x12):
        raise MonitorError("Selected category is not a native P3 normal profile")
    capabilities = monitor_capabilities(observed_functions)
    if mode not in (0x10, 0x20, 0x100) or not capabilities.mask & mode:
        raise MonitorError("Selected P3 pair mode is unavailable", 0x90051001)
    definitions = selected_definitions(profile, selected_ids)
    if definitions.groups or any(
        item.flags & 8 or not item.flags & 1 for item in definitions.ranges
    ):
        raise MonitorError("Selected P3 pair branch requires simple normal signals")
    selected: dict[int, int] = {}
    for item in definitions.ranges:
        if item.frame_id not in enabled_lengths:
            raise MonitorError(
                "Selected P3 PID is absent from enabled observations", 0xC0050414
            )
        selected.setdefault(item.frame_id, enabled_lengths[item.frame_id])
    packing = pack_legacy_pairs(
        "P3", tuple(selected.items()), enabled_lengths, mode=mode
    )
    mapped = {
        pid: (frame, offset, length)
        for pid, frame, offset, length in packing.pid_layouts
    }
    layouts = []
    for item in definitions.ranges:
        if item.frame_id not in mapped:
            raise MonitorError("Selected native signal has no generated frame")
        frame, offset, length = mapped[item.frame_id]
        if item.end_bit >= length * 8:
            raise MonitorError("Native signal bit range exceeds observed PID length")
        layouts.append(
            (
                item.signal_id,
                frame,
                item.start_bit + offset * 8,
                item.end_bit + offset * 8,
            )
        )
    signals = selected_signal_metadata(profile, layouts)
    commands = legacy_pair_commands(
        packing,
        interface_id=interface_id,
        buffer_468=profile.category,
        standard_values=standard_values,
        parameter_8=parameter_8,
    )
    return SelectedPhase3Pairs(packing, signals, commands)


def pack_phase3_mode2(
    selected_pids: Sequence[int],
    enabled_lengths: Mapping[int, int],
    pid_definitions: Mapping[int, tuple[bool, int]],
    cached_frames: Sequence[tuple[int, int]],
    *,
    maximum_reply: int,
) -> LegacyPacking:
    """Phase3 3490 scans enabled PID0..255 against selected DB206+cache frames.

    Each definition is the actual DB206 enabled-byte predicate and length-byte.
    The packet cache must be produced by the native cache operation; passing a
    frame-length guess here cannot establish native protocol support.
    """
    _uint(maximum_reply, 65535, "Maximum native reply")
    if (
        maximum_reply < 2
        or len(selected_pids) > 256
        or len(enabled_lengths) > 256
        or len(pid_definitions) > 256
    ):
        raise MonitorError("Native fixed-packet inputs exceed bounds")
    for pid in selected_pids:
        _uint(pid, 255, "Selected PID")
    for pid, length in enabled_lengths.items():
        _uint(pid, 255, "Enabled PID")
        _uint(length, 255, "Enabled length")
    for pid, definition in pid_definitions.items():
        _uint(pid, 255, "DB206 PID")
        if (
            not isinstance(definition, tuple)
            or len(definition) != 2
            or type(definition[0]) is not bool
        ):
            raise MonitorError(
                "Native DB206 definition requires enabled predicate and length"
            )
        _uint(definition[1], 255, "DB206 length")
    frames = _lengths(cached_frames)
    if any(not length for _, length in frames):
        raise MonitorError("Native packet cache cannot have zero-length frames")
    generated = []
    layouts = []
    frame_index = offset = 0
    selected_set = set(selected_pids)
    for pid in range(256):
        if pid not in enabled_lengths or pid not in pid_definitions:
            continue
        enabled, defined_length = pid_definitions[pid]
        if not enabled:
            if pid in selected_set:
                raise MonitorError(
                    "Selected PID is disabled in native fixed packets", 0x90051008
                )
            continue
        length = defined_length or enabled_lengths[pid]
        if not length or length > maximum_reply - 2:
            continue
        if frame_index >= len(frames):
            raise MonitorError("Native packet cache has no matching frame", 0x90051012)
        frame_id, frame_length = frames[frame_index]
        layouts.append((pid, frame_id, offset, length))
        offset += length
        if offset > frame_length:
            raise MonitorError("Native fixed packet exceeds cached frame", 0x90051013)
        if offset == frame_length:
            generated.append((frame_id, frame_length))
            if frame_id == 255:
                raise MonitorError(
                    "Native fixed packet frameFF is terminal error", 0x90051009
                )
            frame_index += 1
            offset = 0
    if offset:
        raise MonitorError(
            "Native enabled data does not complete cached frame", 0x90051014
        )
    return LegacyPacking("P3", 2, (b"\xa1\x04",), tuple(generated), tuple(layouts))


def pack_dlc12_ranges(
    ranges: Sequence[tuple[int, int, int, int]], *, capabilities: int, excluded: int = 0
) -> LegacyPacking:
    """DLC12 2770/29e0 (cached ASM): singlePID1, A1/E1 descriptors.

    Ranges contain selected(signal_id,start_bit,end_bit,source_frame). Native
    stores its rolling largest end in a BYTE; preserve that truncation here.
    """
    _uint(capabilities, 0xFFFFFFFF, "Native capability mask")
    _uint(excluded, 0xFFFFFFFF, "Native excluded modes")
    if not ranges or len(ranges) > MAX_ITEMS:
        raise MonitorError("Native DLC12 ranges are empty or excessive", 0x90051010)
    end_byte = 0
    for item in ranges:
        if not isinstance(item, tuple) or len(item) != 4:
            raise MonitorError("Native DLC12 range requires four WORD fields")
        signal, start, end, frame = item
        for value in (signal, start, end):
            _uint(value, 65535, "Native DLC12 range field")
        if frame != 1 or type(frame) is not int or start > end:
            raise MonitorError("Native DLC12 requires source frame1", 0xC0050001)
        if end_byte < end:
            end_byte = end & 255
    length = (end_byte >> 3) + 1
    mode = capabilities & ~excluded
    if not mode & 0x3800:
        raise MonitorError("Native DLC12 capability mask is empty", 0x90051007)
    return LegacyPacking(
        "DLC12",
        mode,
        (b"\xa1\x01", bytes((0xE1, length))),
        ((0, length),),
        ((1, 0, 0, length),),
    )


def dlc12_setup_commands(
    packing: LegacyPacking, *, interface_id: int, buffer_468: int
) -> MonitorSetup:
    """DLC1274a0 chooses datatype0/1/2 in800/1000/2000 priority."""
    from scripts.data_monitor import MonitorCommand

    _uint(interface_id, 0xFFFFFFFF, "Native DLC12 interface")
    _uint(buffer_468, 0xFFFFFFFF, "Native DLC12 buffer identity")
    if (
        packing.family != "DLC12"
        or not packing.mode & 0x3800
        or len(packing.setup_requests) != 2
    ):
        raise MonitorError("Native DLC12 setup requires its selected packing")
    request, sizes = packing.setup_requests
    if request != b"\xa1\x01" or len(sizes) != 2 or sizes[0] != 0xE1 or not sizes[1]:
        raise MonitorError("Native DLC12 pair descriptors are invalid", 0xC005100E)
    data_type = 0 if packing.mode & 0x800 else (1 if packing.mode & 0x1000 else 2)
    return MonitorSetup(
        (
            MonitorCommand(
                0x10A,
                (
                    buffer_468,
                    interface_id,
                    data_type,
                    ((1, sizes[1]),),
                    sizes[1],
                    (),
                    3,
                    0xFFFFFFFF,
                ),
            ),
        ),
        (MonitorCommand(0x10C, ()),),
        (MonitorCommand(0x10E, ()),),
    )


@dataclass(frozen=True)
class SelectedDlc12Monitor:
    packing: LegacyPacking
    signals: tuple[MonitorSignalMetadata, ...]
    commands: MonitorSetup


def selected_dlc12_monitor(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    observed_functions: Mapping[int, bool],
    *,
    interface_id: int,
    excluded: int = 0,
) -> SelectedDlc12Monitor:
    """DLC126e20→2770/29e0→4900 metadata→74a0 SetupPair producer."""
    from scripts.data_monitor import monitor_capabilities, selected_signal_metadata
    from scripts.support import word

    if not selected_ids or len(selected_ids) > MAX_ITEMS:
        raise MonitorError("Select bounded DLC12 normal signal IDs")
    for pid in selected_ids:
        _uint(pid, 65535, "Selected signal ID")
    rows = profile.records(10)
    if len(rows) > MAX_ITEMS or any(len(row) != 84 for row in rows):
        raise MonitorError("Selected DLC12 Freeze rows require84-byte records")
    first: dict[int, bytes] = {}
    for row in rows:
        first.setdefault(word(row, 56), row)
    ranges = []
    layouts = []
    for pid in selected_ids:
        if pid not in first:
            raise MonitorError("Selected DLC12 Freeze signal is absent", 0xC0050101)
        row = first[pid]
        start, end = word(row, 62), word(row, 64)
        ranges.append((pid, start, end, row[79]))
        layouts.append((pid, 0, start, end))
    capabilities = monitor_capabilities(observed_functions)
    packing = pack_dlc12_ranges(
        ranges, capabilities=capabilities.mask, excluded=excluded
    )
    # Native BYTE truncation can yield an out-of-buffer SignalItem. Preserve the
    # low-level packing result, but reject such malformed selected metadata.
    if any(end >= packing.frame_sizes[0][1] * 8 for _, _, _, end in layouts):
        raise MonitorError("Selected DLC12 bit range exceeds generated buffer")
    signals = selected_signal_metadata(profile, layouts)
    commands = dlc12_setup_commands(
        packing, interface_id=interface_id, buffer_468=profile.category
    )
    return SelectedDlc12Monitor(packing, signals, commands)


def dlc12_interface_commands(
    profile: VehicleProfile, *, connected_device: int
) -> MonitorSetup:
    """DLC127130→DataListIF27dc0: function6B send BYTE and mask WORDLE."""
    from scripts.data_monitor import MonitorCommand
    from scripts.support import correspondence_rows, word
    from scripts.toyota import VariableTable

    _uint(connected_device, 0xFFFFFFFF, "Native connected device")
    if connected_device != 4:
        raise MonitorError("Native DLC12 requires connected device4", 0xC0051302)
    management = profile.catalog.management
    functions = correspondence_rows(management, 18, profile.exception_ids)
    if len(functions) > MAX_ITEMS:
        raise MonitorError("Native DLC12 function table exceeds budget")
    function = next(
        (
            row
            for row in functions
            if word(row, 0) == profile.category and word(row, 2) == 0x6B
        ),
        None,
    )
    if function is None:
        raise MonitorError("Native DLC12 function6B is absent", 0xC0050101)
    section = management.sections.get(17)
    variable_section = management.sections.get(0)
    if section is None or variable_section is None:
        raise MonitorError("Native DLC12 communication table is absent", 0xC0050101)
    records = tuple(section.rows(8))
    if len(records) > MAX_ITEMS:
        raise MonitorError("Native DLC12 communication table exceeds budget")
    record = next((row for row in records if word(row, 0) == word(function, 6)), None)
    if record is None:
        raise MonitorError("Native DLC12 communication frame is absent", 0xC0050101)
    variables = VariableTable(variable_section.payload, variable_section.count)
    request = variables.get(word(record, 2))
    mask = variables.get(word(record, 4))
    if len(request) != 1 or len(mask) != 2:
        raise MonitorError("Native DLC12 constructor needs send1/mask2", 0xC0050102)
    return MonitorSetup(
        (MonitorCommand(0x105, (request[0], int.from_bytes(mask, "little"))),),
        (),
        (MonitorCommand(0x106, ()),),
    )


@dataclass(frozen=True)
class SelectedDkMonitor:
    packing: LegacyPacking
    signals: tuple[MonitorSignalMetadata, ...]
    event: LegacyMonitorEvent
    source_sha256: str
    source_identity: tuple[object, ...]
    selected_ids: tuple[int, ...]
    auxiliary: Phase3Auxiliary | None = None

    @property
    def frame_sizes(self) -> tuple[tuple[int, int], ...]:
        return self.packing.frame_sizes


def selected_dk_packing(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    enabled_lengths: Mapping[int, int],
    observed_functions: Mapping[int, bool],
    *,
    excluded: int = 0,
) -> tuple[
    LegacyPacking,
    tuple[tuple[int, int, int, int], ...],
    MonitorRange | None,
    Phase3Auxiliary | None,
]:
    """DK5f30/a650 selected Freeze→mode200 frames, before display metadata."""
    from scripts.data_monitor import monitor_capabilities
    from scripts.support import word

    if profile.category_record[72] & 31 != 7:
        raise MonitorError("Selected profile is not native DK ISO9141")
    _uint(excluded, 0xFFFFFFFF, "Excluded native modes")
    capabilities = monitor_capabilities(observed_functions)
    if not capabilities.mask & ~excluded & 0x200:
        raise MonitorError("Native DK mode200 is unavailable", 0x90051001)
    if not selected_ids or len(selected_ids) > MAX_ITEMS:
        raise MonitorError("Select bounded DK signal IDs")
    rows = profile.records(10)
    if len(rows) > MAX_ITEMS or any(len(row) != 84 for row in rows):
        raise MonitorError("Selected DK Freeze rows require84-byte records")
    first: dict[int, bytes] = {}
    for row in rows:
        first.setdefault(word(row, 56), row)
    selected: dict[int, int] = {}
    source_layouts = []
    trigger = None
    enabled = dict(enabled_lengths)
    for pid in selected_ids:
        _uint(pid, 65535, "Selected signal ID")
        if pid not in first:
            raise MonitorError("Selected DK Freeze signal is absent", 0xC0050101)
        row = first[pid]
        # DK a650 copies one descriptor directly, without P3 b620 DB21A expansion.
        if row[78] & 8:
            trigger = MonitorRange(
                signal_id=pid,
                frame_id=row[79],
                start_bit=word(row, 62),
                end_bit=word(row, 64),
                flags=row[78],
                byte_4d=row[77],
                composite_flags=0,
            )
            continue
        frame = row[79]
        if frame not in enabled:
            if row[77] != 1:
                raise MonitorError(
                    "Selected DK PID is absent from enabled observations", 0xC0050414
                )
            definitions = profile.records(6)
            if len(definitions) > MAX_ITEMS or any(
                len(item) != 8 for item in definitions
            ):
                raise MonitorError("Selected DK DB206 requires8-byte records")
            definition = next((item for item in definitions if item[2] == frame), None)
            if definition is None:
                raise MonitorError("Selected DK fallback PID is absent", 0xC0050101)
            if not definition[3]:
                raise MonitorError(
                    "Selected DK fallback PID length is zero", 0xC0050102
                )
            enabled[frame] = definition[3]
        selected.setdefault(frame, enabled[frame])
        source_layouts.append((pid, frame, word(row, 62), word(row, 64)))
    packing = (
        pack_legacy_pairs("DK", tuple(selected.items()), enabled, mode=0x200)
        if selected
        else LegacyPacking("DK", 0x200, (), (), ())
    )
    if not selected and trigger is None:
        raise MonitorError("Native DK selection has no data", 0x90051010)
    auxiliary = (
        phase3_auxiliary(profile, trigger, packing) if trigger is not None else None
    )
    if auxiliary is not None:
        if auxiliary.flag != 1:
            raise MonitorError("Native DK auxiliary DTC flag is not1", 0xC0050003)
        if auxiliary.request[0] != 0x13:
            raise MonitorError("Native DK auxiliary descriptor is not13", 0xC005100E)
        packing = replace(
            packing,
            frame_sizes=packing.frame_sizes + ((auxiliary.frame_id, auxiliary.length),),
        )
    return packing, tuple(source_layouts), trigger, auxiliary


def selected_dk_monitor(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    enabled_lengths: Mapping[int, int],
    observed_functions: Mapping[int, bool],
    *,
    excluded: int = 0,
) -> SelectedDkMonitor:
    """DK a650 selected packing→metadata→direct2C native event."""
    from scripts.data_monitor import selected_signal_metadata
    from scripts.monitor_support import monitor_source_identity

    packing, source_layouts, trigger, auxiliary = selected_dk_packing(
        profile, selected_ids, enabled_lengths, observed_functions, excluded=excluded
    )
    selected = bool(packing.setup_requests)
    mapped = {
        pid: (frame, offset, length)
        for pid, frame, offset, length in packing.pid_layouts
    }
    layouts = []
    for pid, source, start, end in source_layouts:
        frame, offset, length = mapped[source]
        if start > end or end >= length * 8:
            raise MonitorError("Native DK bit range exceeds observed PID length")
        layouts.append((pid, frame, start + offset * 8, end + offset * 8))
    if trigger is not None and auxiliary is not None:
        layouts.append(
            (
                trigger.signal_id,
                auxiliary.frame_id,
                trigger.start_bit,
                trigger.end_bit,
            )
        )
    signals = selected_signal_metadata(profile, layouts)
    event = LegacyMonitorEvent.dk_iso9141(
        tuple(packing.setup_requests[0][1:]) if selected else (),
        tuple(packing.setup_requests[1][1:]) if selected else (),
        dtc_request=auxiliary.request[1:] if auxiliary is not None else None,
        packet_size=sum(size for _, size in packing.frame_sizes),
    )
    return SelectedDkMonitor(
        packing,
        signals,
        event,
        profile.database.sha256,
        monitor_source_identity(profile, ""),
        tuple(selected_ids),
        auxiliary,
    )


class Phase3PacketGenerator:
    """DatMonCommon47c0/4890/4900/4aa0 native single-block packet assembly.

    Missing frames are copied from the previous completed packet. Before the
    first complete packet such cache bytes are not known; explicit initial
    cache is required rather than inventing initial native heap contents.
    """

    def __init__(
        self,
        frames: Sequence[tuple[int, int]],
        *,
        initial_cache: bytes | None = None,
        phase: int = 0,
    ):
        if type(phase) is not int or phase not in (0, 1):
            raise MonitorError("Native P3 packet phase must be0/1")
        self.phase = phase
        self.frames = _lengths(frames)
        if any(not size for _, size in self.frames) or len(
            {frame for frame, _ in self.frames}
        ) != len(self.frames):
            raise MonitorError("Native P3 packet frames must be unique and nonempty")
        self.size = sum(size for _, size in self.frames)
        if initial_cache is not None and (
            not isinstance(initial_cache, bytes) or len(initial_cache) != self.size
        ):
            raise MonitorError("Native initial packet cache length differs")
        self.cache = initial_cache
        self.timestamp = 0
        self.index = self.offset = 0
        self._data = bytearray(self.size)

    def _write(self, payload: bytes, timestamp_raw: int) -> tuple[int, bytes] | None:
        if not payload:
            return None
        available = self.size - self.offset
        copied = min(available, len(payload))
        self._data[self.offset : self.offset + copied] = payload[:copied]
        if len(payload) >= available:
            packet = bytes(self._data)
            self.cache = packet
            self.index = self.offset = 0
            return timestamp_raw, packet
        self.offset += copied
        self.index += 1
        return None

    def append(
        self, fragment: bytes, timestamp_raw: int
    ) -> tuple[tuple[int, bytes], ...]:
        _uint(timestamp_raw, 0xFFFFFFFF, "Native timestamp")
        if not isinstance(fragment, bytes) or not 1 <= len(fragment) <= 7:
            raise MonitorError("Native P3 E2 fragment requires1..7 bytes", 0xA0050613)
        incoming = fragment[0]
        if self.phase == 1:
            # Native7ec0 sets BlockPacket=1, so phase1 compares the first frame
            # ID for every fragment.4900 writes the incoming timestamp as data
            # before the previous packet payload and retains the latched tick.
            if incoming != self.frames[0][0]:
                if self.cache is None:
                    raise MonitorError("Native phase1 complement needs observed cache")
                packets = []
                completed = self._write(
                    timestamp_raw.to_bytes(4, "little"), self.timestamp
                )
                if completed is not None:
                    packets.append(completed)
                completed = self._write(self.cache, self.timestamp)
                if completed is not None:
                    packets.append(completed)
                return tuple(packets)
            self.timestamp = timestamp_raw
            completed = self._write(fragment[1:], timestamp_raw)
            return () if completed is None else (completed,)
        if self.index >= len(self.frames):
            raise MonitorError("Native P3 frame ordinal exceeds selected frame table")
        packets = []
        if self.frames[self.index][0] != incoming:
            for _ in self.frames:
                if self.cache is None:
                    raise MonitorError(
                        "Native P3 missing frame needs observed previous packet cache"
                    )
                position = self.offset
                size = self.frames[self.index][1]
                completed = self._write(
                    self.cache[position : position + size], timestamp_raw
                )
                if completed is not None:
                    packets.append(completed)
                if self.index >= len(self.frames):
                    raise MonitorError("Native P3 cached frame ordinal exceeds table")
                if self.frames[self.index][0] == incoming:
                    break
            else:
                return tuple(packets)
        completed = self._write(fragment[1:], timestamp_raw)
        if completed is not None:
            packets.append(completed)
        return tuple(packets)


@dataclass(frozen=True)
class Phase3ModeSelection:
    packing: LegacyPacking
    attempts: tuple[tuple[int, int], ...]


def select_phase3_packing(
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
) -> Phase3ModeSelection:
    """P3 2fc0 concrete mode1→mode2→pair fallbacks, preserving attempt codes."""
    _uint(capabilities, 0xFFFFFFFF, "Native capability mask")
    _uint(excluded, 0xFFFFFFFF, "Native excluded mask")
    if type(trigger) is not bool:
        raise MonitorError("Native trigger predicate must be boolean")
    selected = _lengths(selected_lengths) if selected_lengths else ()
    if not selected and not trigger:
        raise MonitorError("Native Phase3 requires selected normal data")
    available = capabilities & (0xFFFFFFF8 if trigger else (~excluded & 0xFFFFFFFF))
    attempts = []
    if available & 1:
        try:
            packing = pack_phase3_mode1(dict(selected), maximum_request=maximum_request)
        except MonitorError as error:
            attempts.append((1, error.code or 0xC0050001))
        else:
            return Phase3ModeSelection(packing, ((1, 0),))
    if available & 2:
        try:
            if cached_frames is None:
                raise MonitorError(
                    "Native packet cache observation is absent", 0x90051012
                )
            packing = pack_phase3_mode2(
                tuple(pid for pid, _ in selected),
                enabled_lengths,
                pid_definitions,
                cached_frames,
                maximum_reply=maximum_reply,
            )
        except MonitorError as error:
            attempts.append((2, error.code or 0xC0050001))
        else:
            return Phase3ModeSelection(packing, tuple(attempts) + ((2, 0),))
    if available & 0x30:
        mode = 0x10 if available & 0x10 else (0x100 if available & 0x100 else 0x20)
        if not selected and trigger:
            return Phase3ModeSelection(
                LegacyPacking("P3", mode, (), (), ()), ((mode, 0x90051010),)
            )
        try:
            packing = pack_legacy_pairs("P3", selected, enabled_lengths, mode=mode)
        except MonitorError as error:
            attempts.append((mode, error.code or 0xC0050001))
            raise MonitorError(
                "Native Phase3 selected mode failed", error.code
            ) from error
        return Phase3ModeSelection(packing, tuple(attempts) + ((mode, 0),))
    raise MonitorError(
        "Native Phase3 has no usable monitor mode",
        attempts[-1][1] if attempts else 0x90051001,
    )


def phase3_setup_commands(
    packing: LegacyPacking,
    *,
    interface_id: int,
    buffer_468: int,
    standard_values: Sequence[tuple[int, int]],
    parameter_8: int,
) -> MonitorSetup:
    """P3dea0 mode1 raw body versus mode2 cached lengths as ModeA1 data."""
    from scripts.data_monitor import MonitorCommand

    if packing.mode not in (1, 2):
        return legacy_pair_commands(
            packing,
            interface_id=interface_id,
            buffer_468=buffer_468,
            standard_values=standard_values,
            parameter_8=parameter_8,
        )
    if packing.family != "P3" or len(packing.setup_requests) != 1:
        raise MonitorError("Native P3 packet setup requires one descriptor")
    request = packing.setup_requests[0]
    if len(request) < 2 or request[0] != 0xA1:
        raise MonitorError("Native P3 packet setup requires A1 header", 0xC005100E)
    for value in (interface_id, buffer_468, parameter_8):
        _uint(value, 0xFFFFFFFF, "Native setup field")
    standards = tuple(standard_values)
    if len(standards) > MAX_ITEMS or any(
        not isinstance(pair, tuple)
        or len(pair) != 2
        or any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in pair)
        for pair in standards
    ):
        raise MonitorError("Native standard values require bounded DWORD pairs")
    data = (
        request[2:]
        if packing.mode == 1
        else bytes(size for _, size in packing.frame_sizes)
    )
    return MonitorSetup(
        (
            MonitorCommand(
                0x109,
                (
                    buffer_468,
                    interface_id,
                    ((request[1], data),),
                    sum(size for _, size in packing.frame_sizes),
                    standards,
                    3000,
                ),
            ),
        ),
        (MonitorCommand(0x10C, ()),),
        (MonitorCommand(0x10E, ()),),
    )


@dataclass(frozen=True)
class SelectedPhase3Monitor:
    definitions: MonitorDefinitions
    packing: LegacyPacking
    signals: tuple[MonitorSignalMetadata, ...]
    frame_sizes: tuple[tuple[int, int], ...]
    commands: MonitorSetup
    pickup_spans: tuple[tuple[int, int], ...]
    attempts: tuple[tuple[int, int], ...]
    source_identity: tuple[object, ...]
    native_packing: LegacyPacking
    auxiliary: Phase3Auxiliary | None = None


def selected_phase3_packing(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    enabled_lengths: Mapping[int, int],
    observed_functions: Mapping[int, bool],
    *,
    excluded: int,
    maximum_request: int,
    maximum_reply: int,
    cached_frames: Sequence[tuple[int, int]] | None,
) -> tuple[MonitorDefinitions, Phase3ModeSelection, MonitorRange | None]:
    """P350d0/acf0 shared Freeze/MultiPID→actual mode packing, before metadata."""
    from scripts.data_monitor import monitor_capabilities, selected_definitions
    from scripts.support import word

    if profile.category_record[72] & 31 not in (3, 5, 9, 0x12):
        raise MonitorError("Selected category is not native P3")
    definitions = selected_definitions(profile, selected_ids)
    rows = profile.records(10)
    first: dict[int, bytes] = {}
    for row in rows:
        first.setdefault(word(row, 56), row)
    if any(not first[pid][78] & 1 for pid in selected_ids):
        raise MonitorError(
            "Selected P3 Freeze is not a normal monitor signal", 0xC0050102
        )
    pid_rows = profile.records(6)
    if len(pid_rows) > MAX_ITEMS or any(len(row) != 8 for row in pid_rows):
        raise MonitorError("Selected P3 DB206 requires8-byte rows")
    pid_definitions: dict[int, tuple[bool, int]] = {}
    defaults = {}
    for row in pid_rows:
        pid_definitions.setdefault(row[2], (bool(row[4]), row[5]))
        defaults.setdefault(row[2], row[3])
    enabled = dict(enabled_lengths)
    selected: dict[int, int] = {}
    ranges = []
    trigger = None
    for item in definitions.ranges:
        if item.flags & 8:
            trigger = item
            ranges.append(item)
            continue
        if item.frame_id not in enabled:
            if item.byte_4d == 1:
                length = defaults.get(item.frame_id)
                if length is None:
                    raise MonitorError(
                        "Native P3 missing DB206 fallback row", 0xC0050101
                    )
                if not length:
                    raise MonitorError(
                        "Native P3 DB206 fallback length is zero", 0xC0050102
                    )
                enabled[item.frame_id] = length
            elif item.composite_flags & 1:
                ranges.append(replace(item, runtime_flag=1))
                continue
            else:
                raise MonitorError("Selected native P3 PID is absent", 0xC0050414)
        selected.setdefault(item.frame_id, enabled[item.frame_id])
        ranges.append(item)
    definitions = replace(definitions, ranges=tuple(ranges))
    capabilities = monitor_capabilities(observed_functions)
    selection = select_phase3_packing(
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
    return definitions, selection, trigger


def selected_phase3_monitor(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    enabled_lengths: Mapping[int, int],
    observed_functions: Mapping[int, bool],
    *,
    interface_id: int,
    excluded: int,
    maximum_request: int,
    maximum_reply: int,
    cached_frames: Sequence[tuple[int, int]] | None,
    parameter_8: int,
    standard_values: Sequence[tuple[int, int]],
) -> SelectedPhase3Monitor:
    """P3acf0 selected normal+MultiPID→native mode fallbacks→metadata+DMCI."""
    import struct
    from dataclasses import replace

    from scripts.data_monitor import (
        MonitorCommand,
        monitor_composite_layouts,
        selected_signal_metadata,
    )
    from scripts.monitor_support import monitor_source_identity

    definitions, selection, trigger = selected_phase3_packing(
        profile,
        selected_ids,
        enabled_lengths,
        observed_functions,
        excluded=excluded,
        maximum_request=maximum_request,
        maximum_reply=maximum_reply,
        cached_frames=cached_frames,
    )
    ranges = definitions.ranges
    packing = selection.packing
    auxiliary = (
        phase3_auxiliary(profile, trigger, packing) if trigger is not None else None
    )
    if auxiliary is not None:
        packing = replace(
            packing,
            frame_sizes=packing.frame_sizes + ((auxiliary.frame_id, auxiliary.length),),
            pid_layouts=packing.pid_layouts
            + ((auxiliary.source_frame, auxiliary.frame_id, 0, auxiliary.length),),
        )
    native_packing = packing
    mapped = {
        pid: (frame, offset, length)
        for pid, frame, offset, length in packing.pid_layouts
    }
    layouts = []
    for item in ranges:
        if item.runtime_flag & 1:
            continue
        if item.frame_id not in mapped:
            raise MonitorError("Selected P3 signal has no packed frame", 0x90051004)
        frame, offset, length = mapped[item.frame_id]
        if item.end_bit >= length * 8:
            raise MonitorError("Selected P3 signal exceeds packed data")
        layouts.append(
            (
                item.signal_id,
                frame,
                item.start_bit + offset * 8,
                item.end_bit + offset * 8,
            )
        )
    full_layouts, frame_sizes, pickup = monitor_composite_layouts(
        definitions, tuple(ranges), tuple(layouts), packing.frame_sizes
    )
    signals = selected_signal_metadata(profile, full_layouts)
    packing = replace(packing, frame_sizes=frame_sizes)
    if auxiliary is not None:
        commands = phase3_auxiliary_setup(
            packing,
            auxiliary,
            interface_id=interface_id,
            buffer_468=profile.category,
            standard_values=standard_values,
            parameter_8=parameter_8,
        )
    else:
        commands = phase3_setup_commands(
            packing,
            interface_id=interface_id,
            buffer_468=profile.category,
            standard_values=standard_values,
            parameter_8=parameter_8,
        )
    if pickup:
        body = b"".join(
            struct.pack("<II", start & 0xFFFFFFFF, count) for start, count in pickup
        )
        commands = replace(
            commands,
            setup=commands.setup + (MonitorCommand(0x112, (interface_id, body)),),
        )
    return SelectedPhase3Monitor(
        definitions,
        packing,
        signals,
        frame_sizes,
        commands,
        pickup,
        selection.attempts,
        monitor_source_identity(profile, ""),
        native_packing,
        auxiliary,
    )


@dataclass(frozen=True)
class Phase3Auxiliary:
    request: bytes
    flag: int
    source_frame: int
    frame_id: int
    length: int


def phase3_auxiliary(
    profile: VehicleProfile, signal: MonitorRange, packing: LegacyPacking
) -> Phase3Auxiliary:
    """P32160 selected DB213→firstDB112/DB111 raw auxiliary request."""
    from scripts.support import correspondence_rows, word
    from scripts.toyota import VariableTable

    if 19 not in profile.database.sections:
        raise MonitorError("Selected native DB213 table is absent", 0xA0030107)
    rows = profile.records(19)
    if len(rows) > MAX_ITEMS or any(len(row) != 8 for row in rows):
        raise MonitorError("Native DB213 requires bounded8-byte rows")
    row = next((row for row in rows if word(row, 0) == signal.signal_id), None)
    if row is None:
        raise MonitorError("Selected native DB213 signal is absent", 0xC0050101)
    management = profile.catalog.management
    functions = correspondence_rows(management, 18, profile.exception_ids)
    function = next(
        (
            item
            for item in functions
            if word(item, 0) == profile.category and word(item, 2) == word(row, 2)
        ),
        None,
    )
    if function is None:
        raise MonitorError("Selected auxiliary function frame is absent", 0xC0050101)
    comm_section = management.sections.get(17)
    variables_section = management.sections.get(0)
    if comm_section is None or variables_section is None:
        raise MonitorError(
            "Selected auxiliary communication table is absent", 0xC0050101
        )
    comm = next(
        (item for item in comm_section.rows(8) if word(item, 0) == word(function, 6)),
        None,
    )
    if comm is None:
        raise MonitorError(
            "Selected auxiliary communication frame is absent", 0xC0050101
        )
    variables = VariableTable(variables_section.payload, variables_section.count)
    request = variables.get(word(comm, 2))
    if not 1 <= len(request) <= 255:
        raise MonitorError("Native auxiliary request is empty or excessive", 0xC0050102)
    # P32910 computes max generated PID-map frame before appending this item.
    frame = max((frame for _, frame, _, _ in packing.pid_layouts), default=0) + 1
    if frame > 255:
        raise MonitorError("Native auxiliary frame ID exceeds byte")
    length = (signal.end_bit - signal.start_bit) // 8 + 1
    return Phase3Auxiliary(request, row[6], signal.frame_id, frame, length)


def phase3_auxiliary_setup(
    packing: LegacyPacking,
    auxiliary: Phase3Auxiliary,
    *,
    interface_id: int,
    buffer_468: int,
    standard_values: Sequence[tuple[int, int]],
    parameter_8: int,
) -> MonitorSetup:
    """P3dea0 raw13 descriptor→native DTC10B, sharedbuffer registration once."""
    from scripts.data_monitor import MonitorCommand

    if auxiliary.flag != 1:
        raise MonitorError("Native auxiliary DTC flag is not1", 0xC0050003)
    if auxiliary.request[0] != 0x13:
        raise MonitorError("Native auxiliary descriptor is not13", 0xC005100E)
    if packing.setup_requests:
        commands = phase3_setup_commands(
            packing,
            interface_id=interface_id,
            buffer_468=buffer_468,
            standard_values=standard_values,
            parameter_8=parameter_8,
        )
        extra = MonitorCommand(
            0x10B, (buffer_468, interface_id, 0, auxiliary.request[1:], 0, ())
        )
        return MonitorSetup(commands.setup + (extra,), commands.start, commands.stop)
    _uint(interface_id, 0xFFFFFFFF, "Native interface")
    _uint(buffer_468, 0xFFFFFFFF, "Native buffer")
    standards = tuple(standard_values)
    if len(standards) > MAX_ITEMS or any(
        not isinstance(pair, tuple)
        or len(pair) != 2
        or any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in pair)
        for pair in standards
    ):
        raise MonitorError("Native standards require bounded DWORD pairs")
    return MonitorSetup(
        (
            MonitorCommand(
                0x10B,
                (
                    buffer_468,
                    interface_id,
                    0,
                    auxiliary.request[1:],
                    sum(size for _, size in packing.frame_sizes),
                    standards,
                ),
            ),
        ),
        (MonitorCommand(0x10C, ()),),
        (MonitorCommand(0x10E, ()),),
    )


def selected_dk_from_exchange(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    exchange: SupportTransaction,
    ecu: str,
    observed_functions: Mapping[int, bool],
    *,
    excluded: int = 0,
    source_build: int = 18,
    support_stream: SupportStream | None = None,
    bus_id: int | None = None,
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> SelectedDkMonitor:
    """Actual DK2eb0 CreateEnablePidListExt transactions before selected packing."""
    from scripts.monitor_support import MonitorSupportCache

    cache = MonitorSupportCache(
        profile,
        exchange,
        ecu,
        limits=limits,
        stream=support_stream,
        bus_id=bus_id,
        source_build=source_build,
        cancelled=cancelled,
        clock=clock,
    )
    support = cache.enabled_pids(family="ext")
    return selected_dk_monitor(
        profile, selected_ids, support, observed_functions, excluded=excluded
    )


def selected_phase3_from_exchange(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    exchange: SupportTransaction,
    ecu: str,
    observed_functions: Mapping[int, bool],
    *,
    interface_id: int,
    excluded: int,
    maximum_request: int,
    maximum_reply: int,
    parameter_8: int,
    standard_values: Sequence[tuple[int, int]],
    packet_cache: PacketFrameCache | None = None,
    native_ecu: int,
    packet_protocol: int,
    source_build: int = 18,
    support_stream: SupportStream | None = None,
    bus_id: int | None = None,
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> SelectedPhase3Monitor:
    """Native P32fc0 support producer and lazy fixed-packet fallback query."""
    from scripts.monitor_support import MonitorSupportCache
    from scripts.toyota import ToyotaCodecError

    _uint(native_ecu, 0xFFFFFFFF, "Native ECU")
    _uint(packet_protocol, 65535, "Packet protocol")
    phase = profile.category_record[72] & 31
    if phase not in (3, 5, 9, 0x12):
        raise MonitorError("Selected profile is not native Phase3")
    cache = MonitorSupportCache(
        profile,
        exchange,
        ecu,
        limits=limits,
        stream=support_stream,
        bus_id=bus_id,
        source_build=source_build,
        cancelled=cancelled,
        clock=clock,
    )
    support = cache.enabled_pids(
        family="normal" if phase == 3 else ("valid_ext" if phase == 0x12 else "ext")
    )
    # The native packet cache is queried only if mode1 has not succeeded. First
    # build with no cache to retain the real fallback ordering without I/O.
    result = None
    try:
        result = selected_phase3_monitor(
            profile,
            selected_ids,
            support,
            observed_functions,
            interface_id=interface_id,
            excluded=excluded,
            maximum_request=maximum_request,
            maximum_reply=maximum_reply,
            cached_frames=None,
            parameter_8=parameter_8,
            standard_values=standard_values,
        )
    except MonitorError as error:
        if error.code != 0x90051012 or packet_cache is None:
            raise
    needs_cache = result is None or (2, 0x90051012) in result.attempts
    if needs_cache and packet_cache is not None:
        try:
            frames = packet_cache.get_packet_frame(
                native_ecu, packet_protocol, source_identity=cache.identity
            )
        except ToyotaCodecError as error:
            if result is None:
                raise MonitorError(
                    "Native fixed-packet query failed", error.code
                ) from error
            return replace(
                result,
                attempts=tuple(
                    (mode, error.code if mode == 2 else code)
                    for mode, code in result.attempts
                ),
            )
        return selected_phase3_monitor(
            profile,
            selected_ids,
            support,
            observed_functions,
            interface_id=interface_id,
            excluded=excluded,
            maximum_request=maximum_request,
            maximum_reply=maximum_reply,
            cached_frames=tuple(
                (frame.sequence, len(frame.payload)) for frame in frames
            ),
            parameter_8=parameter_8,
            standard_values=standard_values,
        )
    assert result is not None
    return result


def selected_legacy_monitor(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    *,
    observed_functions: Mapping[int, bool],
    communication_protocol: int,
    interface_id: int,
    enabled_lengths: Mapping[int, int] | None = None,
    excluded: int = 0,
    maximum_request: int | None = None,
    maximum_reply: int | None = None,
    cached_frames: Sequence[tuple[int, int]] | None = None,
    parameter_8: int | None = None,
    standard_values: Sequence[tuple[int, int]] = (),
    connected_device: int | None = None,
    detail_mode35: int | None = None,
    mode35_data: Mapping[int, bytes] | None = None,
    lsb_observations: Mapping[int, tuple[int, int, int]] | None = None,
    voltage_state: DLC12VoltageState | None = None,
    voltage_observations: Mapping[int, DLC12VoltageObservation] | None = None,
) -> (
    SelectedPhase3Monitor
    | SelectedDkMonitor
    | SelectedDLC12Monitor
    | SelectedPSAMonitor
    | SelectedInstrumentMonitor
):
    """Native provider selection followed by the concrete selected family producer.

    Support lengths and dynamic data are explicit observations. For actual
    support transactions use the family from_exchange entry point first.
    """
    from scripts.data_monitor import select_provider

    provider = select_provider(
        profile.category_record[72], communication_protocol, None
    )
    if profile.category == 0x68 and provider in (
        "DataMonitorPhase3.dll",
        "DataMonitorDKIso9141.dll",
    ):
        from scripts.monitor_instruments import selected_instrument_monitor

        return selected_instrument_monitor(
            profile,
            selected_ids,
            voltage_state=voltage_state,
            voltage_observations=voltage_observations,
        )
    if provider == "DataMonitorDLC12.dll":
        from scripts.monitor_dlc12 import selected_dlc12_monitor as selected_dlc12

        if connected_device is None:
            raise MonitorError("DLC12 requires the observed connected device")
        return selected_dlc12(
            profile,
            selected_ids,
            observed_functions=observed_functions,
            connected_device=connected_device,
            interface_id=interface_id,
            buffer_468=profile.category,
            excluded=excluded,
            lsb_observations=lsb_observations,
            voltage_state=voltage_state,
            voltage_observations=voltage_observations,
        )
    if provider not in (
        "DataMonitorPhase3.dll",
        "DataMonitorDKIso9141.dll",
        "DataMonitorPSA_DT.dll",
    ):
        raise MonitorError("Selected provider is outside the legacy monitor families")
    if enabled_lengths is None:
        raise MonitorError(
            "Selected legacy producer requires actual enabled PID lengths"
        )
    if provider == "DataMonitorDKIso9141.dll":
        return selected_dk_monitor(
            profile,
            selected_ids,
            enabled_lengths,
            observed_functions,
            excluded=excluded,
        )
    if provider == "DataMonitorPSA_DT.dll":
        from scripts.monitor_psa import selected_psa_monitor

        if detail_mode35 is None:
            raise MonitorError("PSA requires the selected detail Mode35 value")
        return selected_psa_monitor(
            profile,
            selected_ids,
            enabled_lengths,
            observed_functions,
            detail_mode35=detail_mode35,
            interface_id=interface_id,
            excluded=excluded,
            standard_values=standard_values,
            mode35_data=mode35_data,
        )
    if maximum_request is None or maximum_reply is None or parameter_8 is None:
        raise MonitorError("P3 requires selected request/reply limits and parameter8")
    return selected_phase3_monitor(
        profile,
        selected_ids,
        enabled_lengths,
        observed_functions,
        interface_id=interface_id,
        excluded=excluded,
        maximum_request=maximum_request,
        maximum_reply=maximum_reply,
        cached_frames=cached_frames,
        parameter_8=parameter_8,
        standard_values=standard_values,
    )


def run_phase3_stream(
    stream: Phase3Stream,
    generator: Phase3PacketGenerator,
    *,
    packet_limit: int,
    tick_ms: Callable[[], int],
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[tuple[int, bytes], ...]:
    """Native6220 start→63a0 scheduler→6570 fragments→A3/E3 cleanup.

    A separate bounded cleanup budget remains available after cancellation or
    the main capture deadline, so stop acknowledgements can still be drained.
    """
    _uint(packet_limit, MAX_ITEMS, "Native packet limit")
    if not packet_limit:
        raise MonitorError("Native packet limit must be nonzero")
    if packet_limit * (4 + generator.size) > MAX_BYTES:
        raise MonitorError("Native P3 capture exceeds timestamp/payload byte budget")
    bounds = limits or Limits()
    started = clock()
    if not math.isfinite(started):
        raise MonitorError("Native session clock must be finite")
    deadline = started + bounds.seconds
    calls = 0
    packets = []
    packet_bytes = 0

    def check() -> None:
        if cancelled():
            raise Cancelled("Native Phase3 monitor cancelled")
        now = clock()
        if not math.isfinite(now) or now >= deadline:
            raise MonitorError("Native Phase3 session deadline exhausted")

    def primitive_guard() -> None:
        nonlocal calls
        check()
        calls += 1
        if calls > bounds.exchanges:
            raise MonitorError("Native Phase3 session call budget exhausted")

    failure = None
    original_guard = stream._call_guard
    stream._call_guard = primitive_guard
    try:
        check()
        stream.start(
            tick_ms=tick_ms, cancelled=cancelled, maximum_receives=bounds.exchanges
        )
        while len(packets) < packet_limit:
            check()
            stream.advance(_uint(tick_ms(), 0xFFFFFFFF, "Native tick"))
            check()
            fragment = stream.poll(0, timeout=stream.receive_timeout, tick_ms=tick_ms)
            check()
            if fragment is not None:
                for packet in generator.append(fragment[1], fragment[0]):
                    if len(packets) >= packet_limit:
                        break
                    packet_bytes += 4 + len(packet[1])
                    if packet_bytes > MAX_BYTES:
                        raise MonitorError("Native P3 capture byte budget exhausted")
                    packets.append(packet)
        return tuple(packets[:packet_limit])
    except BaseException as error:
        failure = error
        raise
    finally:
        cleanup_calls = 0
        cleanup_deadline = math.inf

        def cleanup_check() -> None:
            now = clock()
            if not math.isfinite(now) or now >= cleanup_deadline:
                raise MonitorError("Native Phase3 shutdown deadline exhausted")

        def cleanup_guard() -> None:
            nonlocal cleanup_calls
            cleanup_check()
            cleanup_calls += 1
            if cleanup_calls > bounds.exchanges:
                raise MonitorError("Native Phase3 shutdown call budget exhausted")

        stream._call_guard = cleanup_guard
        try:
            cleanup_started = clock()
            if not math.isfinite(cleanup_started):
                raise MonitorError("Native Phase3 shutdown clock must be finite")
            cleanup_deadline = cleanup_started + bounds.seconds
            stream.shutdown(tick_ms=tick_ms, maximum_receives=bounds.exchanges)
            cleanup_check()
        except Exception as cleanup:
            if failure is None:
                raise
            failure.add_note(f"Native Phase3 shutdown also failed: {cleanup}")
        finally:
            stream._call_guard = original_guard


def phase3_interface_lifecycle(
    profile: ProtocolProfile,
    plan: SelectedPhase3Monitor | SelectedLegacyActiveMonitor,
    connection: SelectedMonitorConnection,
    *,
    connected_device: int,
    init_mode: int | None,
    parameter_c0: int,
    recording: bool = False,
) -> MonitorSetup:
    """P3da10/c600/c890/c9b0: selected ISO/VPW/PWM DMCI lifecycle.

    Direct device8 J2534 workers use their own primitive transport path. The
    selected connection carries literal request/response addresses and timers.
    """
    from scripts.data_monitor import MonitorCommand, p4_iso_configs
    from scripts.monitor_support import monitor_source_identity
    from scripts.support import word

    _uint(connected_device, 0xFFFFFFFF, "Connected device")
    if type(recording) is not bool:
        raise MonitorError("Native recording state requires bool")
    if connected_device != 4 and not (connected_device == 8 and recording):
        raise MonitorError(
            "P3 DMCI constructor requires device4 or recording device8", 0xC0051302
        )
    _uint(parameter_c0, 0xFFFFFFFF, "Native commandC0 field")
    if (
        connection.ecu_id != profile.category
        or plan.source_identity != monitor_source_identity(profile, "")
        or plan.definitions.source_sha256 != profile.ecu_database_sha256
        or (
            not plan.commands.setup
            and not isinstance(plan, SelectedLegacyActiveMonitor)
        )
    ):
        raise MonitorError("P3 lifecycle source does not match selected setup")
    if plan.commands.setup and plan.commands.setup[0].values[:2] != (
        profile.category,
        connection.address.request_id,
    ):
        raise MonitorError("P3 setup interface differs from selected request address")
    protocol = profile.protocol_info(connection.bus_id)
    if protocol is None or protocol != connection.protocol_record:
        raise MonitorError("P3 selected protocol identity differs", 0xC0050101)
    bus = connection.bus_id
    if bus in (0x11, 0x21, 0x51, 0x19, 0x31):
        if type(init_mode) is not int or init_mode not in (1, 2):
            raise MonitorError(
                "Native ISO initialization requires observed1/2", 0x90050424
            )
        records = profile.comm_info_iso_records(word(protocol, 2))
        if not records:
            raise MonitorError("P3 selected ISO settings are absent", 0xC0050101)
        configs = p4_iso_configs(records[0], bus_id=bus)
        phase = profile.category_record[72] & 31
        if phase not in (3, 5, 9, 18):
            raise MonitorError("Native P3 ISO category is invalid", 0xC0050003)
        create = MonitorCommand(
            0x100,
            (
                b"ComIso32.dll\0",
                configs,
                init_mode - 1,
                0xC6,
                parameter_c0,
                int(phase == 5),
            ),
        )
    elif bus == 0x17:
        create = MonitorCommand(0x102, (b"ComVpw32.dll\0", 0xC6, 100))
    elif bus == 0x16:
        section = profile.catalog.management.sections.get(51)
        if section is None:
            raise MonitorError("Native J1850 settings table is absent", 0xA0030107)
        row = next(
            (row for row in section.rows(16) if word(row, 0) == word(protocol, 2)), None
        )
        if row is None:
            raise MonitorError("Native J1850 settings row is absent", 0xC0050101)
        configs = (
            (4, 0xF1),
            (5, int.from_bytes(row[8:12], "little")),
            (0x10300, 0),
            (0x10301, 0),
        )
        create = MonitorCommand(0x103, (b"ComPwm32.dll\0", b"\x6b", configs, 0xC6, 100))
    else:
        raise MonitorError("Unsupported native P3 DMCI protocol", 0xC0040602)
    prefix = (create, MonitorCommand(0x107, (0,)))
    return MonitorSetup(
        prefix + _phase3_dmci_system_setup(plan, connection),
        plan.commands.start,
        plan.commands.stop + (MonitorCommand(0x108, ()), MonitorCommand(0x104, ())),
    )


def _phase3_dmci_system_setup(
    plan: SelectedPhase3Monitor | SelectedLegacyActiveMonitor,
    connection: SelectedMonitorConnection,
) -> tuple[MonitorCommand, ...]:
    """P3 per-slot setup; the outer primary owns the sole constructor."""
    from scripts.data_monitor import MonitorCommand, dmci_id_map_fields

    prefix: tuple[MonitorCommand, ...] = ()
    if connection.address.response_id != 0xFFFFFFFF:
        prefix += (
            MonitorCommand(
                0x111,
                dmci_id_map_fields(
                    connection.address.request_id,
                    connection.address.response_id,
                    0,
                    -1,
                    -1,
                ),
            ),
        )
    prefix += (
        MonitorCommand(
            0x114,
            (
                connection.address.request_id,
                connection.address.response_id,
                connection.parameter_word,
            ),
        ),
    )
    return prefix + plan.commands.setup


def phase3_constructor_route(
    *,
    connected_device: int,
    recording: bool,
    interface_count: int,
    mode_mask: int,
    category_flags: int,
    bus_id: int,
) -> str:
    """P3da10 native device, recorder, aggregate mode and protocol decisions."""
    _uint(connected_device, 0xFFFFFFFF, "Connected device")
    _uint(interface_count, MAX_ITEMS, "Native interface count")
    _uint(mode_mask, 0xFFFFFFFF, "Native aggregate mode mask")
    _uint(category_flags, 255, "Native category flags")
    _uint(bus_id, 65535, "Native bus ID")
    if type(recording) is not bool:
        raise MonitorError("Native recorder presence requires a boolean")
    if connected_device in (1, 2):
        raise MonitorError("Native legacy device is unsupported", 0xC0051301)
    if connected_device not in (4, 8):
        raise MonitorError("Native monitor device is unsupported", 0xC0051302)
    if connected_device == 8 and not recording:
        if interface_count >= 2:
            return "j2534_century"
        if mode_mask & 3:
            return "j2534_packet"
        return "j2534_dk_kwp" if category_flags & 31 == 5 else "j2534"
    if bus_id == 0x17:
        return "com_vpw"
    if bus_id == 0x16:
        return "com_pwm"
    if bus_id not in (0x11, 0x21, 0x51, 0x19, 0x31):
        raise MonitorError("Unsupported native ISO constructor protocol", 0xC0040602)
    return "com_iso"


@dataclass(frozen=True)
class LegacyJ2534Frames:
    family: str
    backend: str
    ecu: str
    bus_id: int
    source_build: int
    source_identity: tuple[object, ...]
    frames: tuple[FramePlan, ...]


def selected_legacy_j2534_frames(
    profile: ProtocolProfile,
    plan: SelectedPhase3Monitor | SelectedDkMonitor | SelectedLegacyActiveMonitor,
    *,
    ecu: str,
    bus_id: int,
    driver: DriverProperties,
    diagnostic_mode: bytes,
    connected_device: int,
    interface_count: int = 1,
    recording: bool = False,
    mode_mask: int | None = None,
    source_build: int = 18,
) -> LegacyJ2534Frames:
    """Native selected caller→GetCommFrame→actual headers/configs/filters.

    Driver execution and receive inversion are the primitive lower transport's
    responsibility; no business producer is hidden behind an injected callback.
    """
    from scripts.data_monitor import select_provider
    from scripts.frame_transport import get_comm_frame
    from scripts.monitor_support import monitor_source_identity

    mask = plan.packing.mode if mode_mask is None else mode_mask
    if type(source_build) is not int or source_build not in (12, 18):
        raise MonitorError("Native monitor source build must be12/18")
    _uint(connected_device, 0xFFFFFFFF, "Connected device")
    _uint(mask, 0xFFFFFFFF, "Native aggregate mode mask")
    source = (
        plan.source_sha256
        if isinstance(plan, (SelectedDkMonitor, SelectedLegacyActiveMonitor))
        else plan.definitions.source_sha256
    )
    if (
        source != profile.ecu_database_sha256
        or plan.source_identity != monitor_source_identity(profile, "")
    ):
        raise MonitorError("Native transport plan belongs to another selected source")
    if isinstance(plan, SelectedDkMonitor) or (
        isinstance(plan, SelectedLegacyActiveMonitor) and plan.family == "DK"
    ):
        if connected_device in (1, 2):
            raise MonitorError("Native DK legacy device is unsupported", 0xC0051301)
        if type(connected_device) is not int or connected_device != 8:
            raise MonitorError("Native DK requires observed device8", 0xC0051302)
        if mask & 5 or mask & 0x337 not in (0, 0x200):
            raise MonitorError("Native DK constructor mode is invalid", 0xC0040602)
        requests = plan.event.requests if isinstance(plan, SelectedDkMonitor) else ()
        family, backend = "DK", "j2534_dk_iso9141"
    else:
        backend = phase3_constructor_route(
            connected_device=connected_device,
            recording=recording,
            interface_count=interface_count,
            mode_mask=mask,
            category_flags=profile.category_record[72],
            bus_id=bus_id,
        )
        if not backend.startswith("j2534"):
            raise MonitorError("Selected constructor uses the separate DMCI path")
        if plan.packing.mode in (1, 2):
            requests = plan.packing.setup_requests
        else:
            requests = ()
            if plan.packing.setup_requests:
                ids = plan.packing.setup_requests[0]
                requests = tuple(bytes((ids[0], pid)) for pid in ids[1:])
            if plan.auxiliary is not None:
                requests += (plan.auxiliary.request,)
        family = "P3"
    expected_provider = (
        "DataMonitorDKIso9141.dll" if family == "DK" else "DataMonitorPhase3.dll"
    )
    if select_provider(profile.category_record[72], bus_id, None) != expected_provider:
        raise MonitorError("Native monitor plan belongs to another selected provider")
    identity = monitor_source_identity(profile, ecu)
    if isinstance(plan, SelectedLegacyActiveMonitor):
        from scripts.frame_transport import runtime_frame_plan

        return LegacyJ2534Frames(
            family,
            backend,
            ecu,
            bus_id,
            source_build,
            identity,
            (
                runtime_frame_plan(
                    profile,
                    b"",
                    native_build=source_build,
                    native_variant="normal",
                    bus_id=bus_id,
                    driver=driver,
                    diagnostic_mode=diagnostic_mode,
                ),
            ),
        )
    frames = tuple(
        get_comm_frame(
            profile,
            request,
            bus_id=bus_id,
            driver=driver,
            diagnostic_mode=diagnostic_mode,
        )
        for request in requests
    )
    return LegacyJ2534Frames(
        family, backend, ecu, bus_id, source_build, identity, frames
    )


@dataclass(frozen=True)
class Phase3Measurement:
    """Native MultiMonMeasureInfo DWORD cycle/packet/allocation and WORD mode."""

    cycle: int
    packet_size: int
    allocation: int
    mode: int


def phase3_measurement(
    plan: SelectedPhase3Monitor | LegacyPacking,
) -> Phase3Measurement:
    """P350d0/592c→eaf0/ebd0: native frames include DTC and precede pickup."""
    packing = plan.native_packing if isinstance(plan, SelectedPhase3Monitor) else plan
    if not isinstance(packing, LegacyPacking) or packing.family != "P3":
        raise MonitorError(
            "Native P3 measurement requires selected mode packing", 0xC0050001
        )
    if packing.mode not in (1, 2, 0x10, 0x20, 0x100):
        raise MonitorError("Native P3 measurement mode is invalid", 0xC005100D)
    if not packing.frame_sizes:
        raise MonitorError("Native P3 measurement has no response frames", 0xC005100F)
    sizes = tuple(size for _, size in packing.frame_sizes)
    for size in sizes:
        _uint(size, 65535, "Native response frame length")
    cycle = len(sizes) * (130 if packing.mode in (1, 2) else 160) & 0xFFFFFFFF
    packet_size = (sum(sizes) + 4) & 0xFFFFFFFF
    return Phase3Measurement(cycle, packet_size, 0, packing.mode)


def dk_measurement(packing: LegacyPacking) -> Phase3Measurement:
    """DK5f30→b480: each native response contributes160ms and its byte length."""
    if not isinstance(packing, LegacyPacking) or packing.family != "DK":
        raise MonitorError("Native DK measurement requires DK packing", 0xC0050001)
    if packing.mode != 0x200:
        raise MonitorError("Native DK measurement mode is invalid", 0xC005100D)
    if not packing.frame_sizes:
        raise MonitorError("Native DK measurement has no response frames", 0xC005100F)
    sizes = tuple(
        _uint(size, 65535, "Native frame length") for _, size in packing.frame_sizes
    )
    return Phase3Measurement(
        len(sizes) * 160 & 0xFFFFFFFF, (sum(sizes) + 4) & 0xFFFFFFFF, 0, packing.mode
    )


def legacy_allocate_measurements(
    total: int, measurements: tuple[Phase3Measurement, ...]
) -> tuple[Phase3Measurement, ...]:
    """P3e8f0/DKb280: DWORD weights, signed allocation, last-item remainder."""
    _uint(total, 0x7FFFFFFF, "Native allocation")
    if (
        not total
        or not isinstance(measurements, tuple)
        or not 1 <= len(measurements) <= 3
    ):
        raise MonitorError("Native allocation arguments rejected", 0xC0050001)
    for item in measurements:
        if not isinstance(item, Phase3Measurement):
            raise MonitorError("Typed native measurement required", 0xC0050001)
        _uint(item.cycle, 0xFFFFFFFF, "Native measurement cycle")
        _uint(item.packet_size, 0xFFFFFFFF, "Native measurement packet size")
        if not item.cycle:
            raise MonitorError("Native measurement cycle is zero")
    if len(measurements) == 1:
        return (replace(measurements[0], allocation=total),)
    weights = tuple(
        (item.packet_size * 10000 & 0xFFFFFFFF) // item.cycle for item in measurements
    )
    denominator = sum(weights) & 0xFFFFFFFF
    if not denominator:
        raise MonitorError("Native allocation has zero proportional weight")
    allocations = [weight * total // denominator for weight in weights]
    used = sum(allocations)
    allocations[-1] += -used - total if total < used else -used + total
    if any(not 0 <= value <= 0xFFFFFFFF for value in allocations):
        raise MonitorError("Native allocation exceeds bounded host output")
    return tuple(
        replace(item, allocation=value)
        for item, value in zip(measurements, allocations)
    )


def phase3_check_excluded(
    categories: tuple[int, ...],
    *,
    command_kind: int,
    connected_device: int,
    command_ecu: int,
    shared_interface: int | None = None,
    disabled_packet_ecus: tuple[int, ...] | None = None,
) -> int:
    """P34a50 literal single/multi device policy and ShareData1e/1b joins."""
    _uint(connected_device, 0xFFFFFFFF, "Native connected device")
    _uint(command_ecu, 0xFFFFFFFF, "Native command ECU")
    if not isinstance(categories, tuple) or not 1 <= len(categories) <= 3:
        raise MonitorError("Native check target count rejected", 0xC0050404)
    for category in categories:
        _uint(category, 0xFFFFFFFF, "Native category")
    if command_kind not in (7, 0x42) or (command_kind == 7 and len(categories) != 1):
        raise MonitorError("Native check command kind rejected", 0xC0050404)
    if connected_device in (1, 2):
        raise MonitorError("Native monitor device unsupported", 0xC0051301)
    if connected_device not in (4, 8):
        raise MonitorError("Native monitor device rejected", 0xC0051302)
    if command_kind == 7:
        return 0 if connected_device == 4 else 3
    if sum(category != 0x68 for category in categories) >= 2:
        return 3
    if connected_device == 4:
        return 0
    if shared_interface is None:
        raise MonitorError("Native ShareData1e pointer absent", 0xC0040601)
    _uint(shared_interface, 0xFFFFFFFF, "Native shared interface")
    if shared_interface == 3:
        return 0
    if disabled_packet_ecus is None:
        raise MonitorError("Native ShareData1b pointer absent", 0xC0040601)
    if len(disabled_packet_ecus) > MAX_ITEMS:
        raise MonitorError("Native packet-disable list exceeds budget")
    for ecu in disabled_packet_ecus:
        _uint(ecu, 0xFFFFFFFF, "Native disabled packet ECU")
    return 3 if command_ecu in disabled_packet_ecus else 0


def check_legacy_packing(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    enabled_lengths: Mapping[int, int],
    observed_functions: Mapping[int, bool],
    *,
    bus_id: int,
    family: str,
    excluded: int = 0,
    cached_frames: Sequence[tuple[int, int]] | None = None,
) -> Phase3Measurement | None:
    """Native P350d0/DK5f30 scalar producer, without display-table prerequisites.

    None is the native P3 available=false result for status90051008 only.
    Voltage mode40 is a measurable descriptor even though its sampler is stubbed.
    """
    from scripts.support import word

    if family not in ("P3", "DK"):
        raise MonitorError("Native measurement family rejected", 0xC0050001)
    _uint(bus_id, 65535, "Native selected bus")
    if not selected_ids or len(selected_ids) > MAX_ITEMS:
        raise MonitorError("Native check signal count rejected", 0xC0050404)
    if profile.category == 0x68:
        rows = profile.records(10)
        if any(len(row) != 84 for row in rows) or len(rows) > MAX_ITEMS:
            raise MonitorError("Native voltage Freeze table malformed", 0xC0050101)
        first = {}
        for row in rows:
            first.setdefault(word(row, 56), row)
        if family == "P3":
            from scripts.data_monitor import selected_definitions

            definitions = selected_definitions(profile, selected_ids)
            keys = tuple(item.signal_id for item in definitions.ranges)
            if any(not first[key][78] & 1 for key in selected_ids):
                raise MonitorError("Native P3 signal is not normal", 0xC0050102)
        else:
            keys = tuple(dict.fromkeys(selected_ids))
        if len(keys) != 1:
            raise MonitorError(
                "Native voltage requires one effective signal", 0x90051003
            )
        row = first.get(keys[0])
        if row is None:
            raise MonitorError("Native voltage Freeze absent", 0xC0050101)
        difference = word(row, 64) - word(row, 62)
        quotient = difference // 8 if difference >= 0 else -(-difference // 8)
        if quotient != 1:
            raise MonitorError("Native voltage range rejected", 0xC0050102)
        return Phase3Measurement(4, 6, 0, 0x40)
    protocol = profile.protocol_info(bus_id)
    if protocol is None or len(protocol) < 18:
        raise MonitorError("Native measurement protocol absent", 0xC0050101)
    if family == "DK":
        packing, _, _, _ = selected_dk_packing(
            profile,
            selected_ids,
            enabled_lengths,
            observed_functions,
            excluded=excluded,
        )
        return dk_measurement(packing)
    try:
        _, selection, trigger = selected_phase3_packing(
            profile,
            selected_ids,
            enabled_lengths,
            observed_functions,
            excluded=excluded,
            maximum_request=word(protocol, 14),
            maximum_reply=word(protocol, 16),
            cached_frames=cached_frames,
        )
    except MonitorError as error:
        if error.code == 0x90051008:
            return None
        raise
    packing = selection.packing
    if trigger is not None:
        auxiliary = phase3_auxiliary(profile, trigger, packing)
        if auxiliary is not None:
            packing = replace(
                packing,
                frame_sizes=packing.frame_sizes
                + ((auxiliary.frame_id, auxiliary.length),),
            )
    return phase3_measurement(packing)


@dataclass(frozen=True)
class LegacyCheckTarget:
    profile: VehicleProfile
    selected_ids: tuple[int, ...]
    ecu: str
    bus_id: int
    observed_functions: Mapping[int, bool]
    transaction: SupportTransaction
    source_build: int = 18
    support_stream: SupportStream | None = None
    packet_cache: PacketFrameCache | None = None
    packet_ecu: int = 0
    packet_protocol: int = 0


@dataclass(frozen=True)
class LegacyCheckResult:
    available: bool
    measurements: tuple[Phase3Measurement, ...]
    excluded: int


def check_legacy_monitor(
    targets: tuple[LegacyCheckTarget, ...],
    *,
    family: str,
    command_kind: int,
    allocation: int,
    connected_device: int = 4,
    command_ecu: int,
    shared_interface: int | None = None,
    disabled_packet_ecus: tuple[int, ...] | None = None,
    monitor_session: SelectedMonitorSession | None = None,
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> LegacyCheckResult:
    """P34a50/DK5b90 actual selected targets→support→measurement→allocation.

    An unavailable P3 target retains preceding measurements and stops the loop.
    PacketFrameCache retains its independently bounded native retry/drain budget.
    """
    from scripts.monitor_support import MonitorSupportCache
    from scripts.toyota import ToyotaCodecError

    if (
        family not in ("P3", "DK")
        or not isinstance(targets, tuple)
        or not 1 <= len(targets) <= 3
    ):
        raise MonitorError("Native check target/family rejected", 0xC0050404)
    if command_kind not in (7, 0x42) or (command_kind == 7 and len(targets) != 1):
        raise MonitorError("Native check command rejected", 0xC0050404)
    if any(
        not isinstance(target, LegacyCheckTarget) or not target.selected_ids
        for target in targets
    ):
        raise MonitorError("Native check target signals rejected", 0xC0050404)
    first_profile = targets[0].profile
    first_build = targets[0].source_build
    for target in targets:
        if (
            target.source_build not in (12, 18)
            or target.source_build != first_build
            or target.profile.catalog.management.sha256
            != first_profile.catalog.management.sha256
            or target.profile.catalog.management.version
            != first_profile.catalog.management.version
            or target.profile.vehicle_name_key != first_profile.vehicle_name_key
            or target.profile.exception_ids != first_profile.exception_ids
        ):
            raise MonitorError(
                "Native check targets must share one application and vehicle context"
            )
        _uint(target.packet_ecu, 0xFFFFFFFF, "Native packet ECU")
        _uint(target.packet_protocol, 65535, "Native packet protocol")
    if monitor_session is not None:
        from scripts.data_monitor import SelectedMonitorSession

        if not isinstance(monitor_session, SelectedMonitorSession):
            raise MonitorError("Native check session type rejected")
        for target in targets:
            monitor_session.check(target.profile, source_build=target.source_build)
            if target.packet_cache is not None:
                target.packet_cache.disable_packet_ecu = (
                    monitor_session.disable_packet_ecu
                )
        shared_interface = monitor_session.shared_interface
        disabled_packet_ecus = monitor_session.disabled_packet_ecus
    _uint(allocation, 0x7FFFFFFF, "Native requested allocation")
    if not allocation:
        raise MonitorError("Native requested allocation is zero", 0xC0050001)
    excluded = (
        phase3_check_excluded(
            tuple(target.profile.category for target in targets),
            command_kind=command_kind,
            connected_device=connected_device,
            command_ecu=command_ecu,
            shared_interface=shared_interface,
            disabled_packet_ecus=disabled_packet_ecus,
        )
        if family == "P3"
        else 0
    )
    bounds = limits or Limits()
    started = clock()
    if not math.isfinite(started):
        raise MonitorError("Native check clock must be finite")
    last = started
    calls = 0

    def guard():
        nonlocal last
        if cancelled():
            raise Cancelled("Native monitor check cancelled")
        now = clock()
        if not math.isfinite(now) or now < last or now >= started + bounds.seconds:
            raise MonitorError("Native monitor check deadline exhausted")
        last = now
        return now

    def consume():
        nonlocal calls
        guard()
        calls += 1
        if calls > bounds.exchanges:
            raise MonitorError("Native monitor check primitive budget exhausted")

    class BoundedStream:
        def __init__(self, stream):
            self.stream = stream

        def send(self, request):
            consume()
            result = self.stream.send(request)
            guard()
            return result

        def receive(self, request):
            consume()
            result = self.stream.receive(request)
            guard()
            return result

    results = []
    for target in targets:
        now = guard()
        if target.profile.category == 0x68:
            measured = check_legacy_packing(
                target.profile,
                target.selected_ids,
                {},
                target.observed_functions,
                bus_id=0,
                family=family,
                excluded=excluded,
            )
        else:

            def exchange(query, transaction=target.transaction):
                consume()
                result = transaction(query)
                guard()
                return result

            cache = MonitorSupportCache(
                target.profile,
                exchange,
                target.ecu,
                source_build=target.source_build,
                stream=BoundedStream(target.support_stream)
                if target.support_stream is not None
                else None,
                bus_id=target.bus_id,
                limits=Limits(
                    seconds=started + bounds.seconds - now,
                    exchanges=max(1, bounds.exchanges - calls),
                ),
                cancelled=cancelled,
                clock=clock,
            )
            phase = target.profile.category_record[72] & 31
            support = cache.enabled_pids(
                family="ext"
                if family == "DK" or phase not in (3, 0x12)
                else ("normal" if phase == 3 else "valid_ext")
            )
            measured = None
            failure = None
            try:
                measured = check_legacy_packing(
                    target.profile,
                    target.selected_ids,
                    support,
                    target.observed_functions,
                    bus_id=target.bus_id,
                    family=family,
                    excluded=excluded,
                )
            except MonitorError as error:
                if error.code != 0x90051012 or target.packet_cache is None:
                    raise
                failure = error
            if family == "P3" and target.packet_cache is not None:
                # Re-evaluate the pure producer to decide whether mode2 was tried;
                # a successful mode1 must never perform the A2/A3 cache exchange.
                from scripts.support import word

                protocol = target.profile.protocol_info(target.bus_id)
                assert protocol is not None
                needs_cache = failure is not None
                if failure is None and measured is not None:
                    _, selection, _ = selected_phase3_packing(
                        target.profile,
                        target.selected_ids,
                        support,
                        target.observed_functions,
                        excluded=excluded,
                        maximum_request=word(protocol, 14),
                        maximum_reply=word(protocol, 16),
                        cached_frames=None,
                    )
                    needs_cache = (2, 0x90051012) in selection.attempts
                if needs_cache:
                    guard()
                    try:
                        frames = target.packet_cache.get_packet_frame(
                            target.packet_ecu,
                            target.packet_protocol,
                            source_identity=cache.identity,
                        )
                    except ToyotaCodecError as error:
                        if failure is not None:
                            raise MonitorError(
                                "Native fixed-packet measurement query failed",
                                error.code,
                            ) from error
                    else:
                        measured = check_legacy_packing(
                            target.profile,
                            target.selected_ids,
                            support,
                            target.observed_functions,
                            bus_id=target.bus_id,
                            family=family,
                            excluded=excluded,
                            cached_frames=tuple(
                                (frame.sequence, len(frame.payload)) for frame in frames
                            ),
                        )
                    guard()
            cache._check()
        guard()
        if measured is None:
            return LegacyCheckResult(False, tuple(results), excluded)
        results.append(measured)
    if command_kind == 7:
        measurements = (replace(results[0], allocation=allocation),)
    else:
        measurements = legacy_allocate_measurements(allocation, tuple(results))
    return LegacyCheckResult(True, measurements, excluded)


@dataclass(frozen=True)
class SelectedMonitorCapture:
    """Capture bound to the exact selected metadata that produced its packets."""

    plan: SelectedPhase3Monitor | SelectedDkMonitor
    capture: NativeRecorderCapture

    def monitor_buffer(
        self,
        *,
        phase: int,
        allocation_size: int,
        name: bytes,
        text_encoding: str,
    ) -> NativeMonitorBuffer:
        from scripts.drive_recorder import native_monitor_buffer

        category = self.plan.source_identity[3]
        if type(category) is not int:
            raise MonitorError("Selected native capture category is invalid")
        selected_ids = (
            self.plan.definitions.selected_ids
            if isinstance(self.plan, SelectedPhase3Monitor)
            else self.plan.selected_ids
        )
        return native_monitor_buffer(
            category,
            self.plan.signals,
            self.plan.frame_sizes,
            selected_ids,
            phase=phase,
            allocation_size=allocation_size,
            name=name,
            text_encoding=text_encoding,
        )


def run_phase3_native(
    plan: SelectedPhase3Monitor,
    operations: NativeFrameOperations,
    *,
    ecu: str,
    packet_limit: int,
    interface_count: int = 1,
    recording: bool = False,
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> SelectedMonitorCapture:
    worker = selected_phase3_native_worker(
        plan,
        operations,
        ecu=ecu,
        interface_count=interface_count,
        recording=recording,
        limits=limits,
        cancelled=cancelled,
        clock=clock,
    )
    return SelectedMonitorCapture(plan, worker.run(packet_limit))


def run_dk_native_capture(
    plan: SelectedDkMonitor,
    operations: NativeFrameOperations,
    *,
    ecu: str,
    retry_limit: int,
    packet_limit: int,
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> SelectedMonitorCapture:
    from scripts.drive_recorder import NativeMonitorPacket, NativeRecorderCapture

    packets = run_dk_native(
        plan,
        operations,
        ecu=ecu,
        retry_limit=retry_limit,
        packet_limit=packet_limit,
        limits=limits,
        cancelled=cancelled,
        clock=clock,
    )
    capture = NativeRecorderCapture(
        0,
        tuple(
            NativeMonitorPacket(packet.timestamp_raw, packet.payload)
            for packet in packets
        ),
    )
    return SelectedMonitorCapture(plan, capture)


def selected_phase3_century_worker(
    targets: tuple[
        tuple[
            SelectedPhase3Monitor | SelectedLegacyActiveMonitor, NativeFrameOperations
        ],
        tuple[
            SelectedPhase3Monitor | SelectedLegacyActiveMonitor, NativeFrameOperations
        ],
    ],
    functional: CenturyNativeFrameOperations,
    *,
    ecus: tuple[str, str],
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> CenturyJ2534Worker:
    """P3da10 multi-system registration→actual Century functional/physical worker."""
    from scripts.data_monitor import selected_p4_connection
    from scripts.frame_transport import NativeFrameOperations
    from scripts.monitor_j2534 import (
        CenturyJ2534Worker,
        CenturyMonitorEvent,
        CenturyNativeFrameOperations,
        CenturySystem,
        century_frame_plan,
        selected_phase3_event,
    )
    from scripts.monitor_support import monitor_source_identity
    from scripts.support import word

    if (
        not isinstance(targets, tuple)
        or len(targets) != 2
        or not isinstance(ecus, tuple)
        or len(ecus) != 2
    ):
        raise MonitorError("Native Century requires exactly two selected targets")
    if (
        not isinstance(functional, CenturyNativeFrameOperations)
        or functional.channel is not None
        or functional.poisoned
    ):
        raise MonitorError("Native Century functional transport must be fresh")
    systems = []
    for target, ecu in zip(targets, ecus):
        if not isinstance(target, tuple) or len(target) != 2:
            raise MonitorError("Native Century target fields differ")
        plan, operations = target
        if not isinstance(
            plan, (SelectedPhase3Monitor, SelectedLegacyActiveMonitor)
        ) or not isinstance(operations, NativeFrameOperations):
            raise MonitorError("Native Century requires selected plans and operations")
        if operations.channel is not None or operations.poisoned:
            raise MonitorError("Native Century physical transport must be fresh")
        profile = operations.profile
        if systems:
            first_profile = systems[0].operations.profile
            if (
                profile.catalog.management.sha256
                != first_profile.catalog.management.sha256
                or profile.catalog.management.version
                != first_profile.catalog.management.version
                or profile.vehicle_name_key != first_profile.vehicle_name_key
                or profile.exception_ids != first_profile.exception_ids
            ):
                raise MonitorError(
                    "Native Century targets must share one selected vehicle context"
                )
        selected = selected_legacy_j2534_frames(
            profile,
            plan,
            ecu=ecu,
            bus_id=operations.bus_id,
            driver=operations.driver,
            diagnostic_mode=operations.diagnostic_mode,
            connected_device=operations.device_kind,
            interface_count=2,
            source_build=operations.native_build,
        )
        if (
            selected.backend != "j2534_century"
            or not selected.frames
            or operations.plan != selected.frames[0]
        ):
            raise MonitorError(
                "Native Century physical frame differs from selected constructor"
            )
        connection = selected_p4_connection(
            profile,
            bus_id=operations.bus_id,
            diagnostic_mode=operations.diagnostic_mode,
            controller_category_flags=profile.category_record[72],
        )
        if any(
            command.values[:2] != (profile.category, connection.address.request_id)
            for command in plan.commands.setup
            if command.command_id in (0x109, 0x10A, 0x10B)
        ):
            raise MonitorError("Native Century setup target differs")
        setup = next(
            (command for command in plan.commands.setup if command.command_id == 0x10A),
            None,
        )
        attempts, parameter_8 = (
            (0, connection.address.functional_id)
            if setup is None
            else (setup.values[6], setup.values[7])
        )
        if type(attempts) is not int or type(parameter_8) is not int:
            raise MonitorError("Native Century attempts/address fields differ")
        if setup is not None and parameter_8 != connection.address.functional_id:
            raise MonitorError(
                "Native Century parameter8 differs from selected functional address"
            )
        default_source = int.from_bytes(
            operations.diagnostic_mode[8:12], "little"
        ) or word(connection.protocol_record, 8)
        event = (
            None
            if isinstance(plan, SelectedLegacyActiveMonitor)
            else selected_phase3_event(
                _selected_profile(profile), plan, backend_family="j2534_century"
            )
        )
        if event is not None and not isinstance(event, CenturyMonitorEvent):
            raise MonitorError("Native Century event type differs")
        send_timer, receive_timer = dk_monitor_timing(profile)
        systems.append(
            CenturySystem(
                operations,
                event,
                connection.address.request_id,
                connection.address.response_id,
                parameter_8,
                send_timer,
                receive_timer,
                default_source,
                attempts,
            )
        )
    first = systems[0].operations
    if (
        monitor_source_identity(functional.profile, "")
        != monitor_source_identity(first.profile, "")
        or functional.bus_id != first.bus_id
        or functional.driver != first.driver
        or functional.plan
        != century_frame_plan(
            first.profile,
            bus_id=first.bus_id,
            driver=first.driver,
            diagnostic_mode=first.diagnostic_mode,
        )
    ):
        raise MonitorError(
            "Native Century functional frame differs from selected first target"
        )
    bounds = limits or Limits()
    return CenturyJ2534Worker(
        (systems[0], systems[1]),
        functional,
        default_source=systems[0].default_source,
        timeout=bounds.seconds,
        max_steps=bounds.exchanges,
        clock=clock,
        cancelled=cancelled,
    )


def run_phase3_century_capture(
    targets: tuple[
        tuple[SelectedPhase3Monitor, NativeFrameOperations],
        tuple[SelectedPhase3Monitor, NativeFrameOperations],
    ],
    functional: CenturyNativeFrameOperations,
    *,
    ecus: tuple[str, str],
    cycles: int,
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[SelectedMonitorCapture, SelectedMonitorCapture]:
    worker = selected_phase3_century_worker(
        targets,
        functional,
        ecus=ecus,
        limits=limits,
        cancelled=cancelled,
        clock=clock,
    )
    captures = worker.run_systems(cycles)
    return SelectedMonitorCapture(targets[0][0], captures[0]), SelectedMonitorCapture(
        targets[1][0], captures[1]
    )


def selected_phase3_native_worker(
    plan: SelectedPhase3Monitor | SelectedLegacyActiveMonitor,
    operations: NativeFrameOperations,
    *,
    ecu: str,
    interface_count: int = 1,
    recording: bool = False,
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> DirectJ2534Worker:
    """Native P3 caller selection and actual direct-worker constructor fields."""
    from scripts.data_monitor import selected_p4_connection
    from scripts.frame_transport import NativeFrameOperations
    from scripts.monitor_j2534 import (
        DirectJ2534Worker,
        DkKwpJ2534Worker,
        selected_phase3_event,
    )
    from scripts.support import word

    if not isinstance(
        plan, (SelectedPhase3Monitor, SelectedLegacyActiveMonitor)
    ) or not isinstance(operations, NativeFrameOperations):
        raise MonitorError(
            "Native P3 worker requires selected plan and lower operations"
        )
    if operations.channel is not None or operations.poisoned:
        raise MonitorError("Native P3 worker requires fresh unopened transport")
    profile = operations.profile
    selected = selected_legacy_j2534_frames(
        profile,
        plan,
        ecu=ecu,
        bus_id=operations.bus_id,
        driver=operations.driver,
        diagnostic_mode=operations.diagnostic_mode,
        connected_device=operations.device_kind,
        interface_count=interface_count,
        recording=recording,
        source_build=operations.native_build,
    )
    if not selected.frames or selected.frames[0] != operations.plan:
        raise MonitorError("Native P3 lower frame differs from selected constructor")
    connection = selected_p4_connection(
        profile,
        bus_id=operations.bus_id,
        diagnostic_mode=operations.diagnostic_mode,
        controller_category_flags=profile.category_record[72],
    )
    if any(
        command.values[:2] != (profile.category, connection.address.request_id)
        for command in plan.commands.setup
        if command.command_id in (0x109, 0x10A, 0x10B)
    ):
        raise MonitorError("Native P3 setup differs from selected constructor address")
    # P38340 selects record=this+10+index40;851c/8521 stores its +14.
    # da10 pushes outer+24 (first record+14), not CommInfoCan BYTE0.
    default_source = int.from_bytes(operations.diagnostic_mode[8:12], "little") or word(
        connection.protocol_record, 8
    )
    event = (
        None
        if isinstance(plan, SelectedLegacyActiveMonitor)
        else selected_phase3_event(
            _selected_profile(profile), plan, backend_family=selected.backend
        )
    )
    setup = next(
        (command for command in plan.commands.setup if command.command_id == 0x10A),
        None,
    )
    attempts = 0 if setup is None else setup.values[6]
    if type(attempts) is not int:
        raise MonitorError("Native P3 setup attempts must be an integer")
    send_timer, receive_timer = dk_monitor_timing(profile)
    bounds = limits or Limits()
    worker_type = (
        DkKwpJ2534Worker if selected.backend == "j2534_dk_kwp" else DirectJ2534Worker
    )
    return worker_type(
        operations,
        event,
        request_id=connection.address.request_id,
        response_id=connection.address.response_id,
        default_source=default_source,
        full_source=False,
        attempts=attempts,
        send_timeout=send_timer,
        receive_timeout=receive_timer,
        timeout=bounds.seconds,
        max_steps=bounds.exchanges,
        clock=clock,
        cancelled=cancelled,
    )


def run_phase3_dmci(
    profile: VehicleProfile,
    plan: SelectedPhase3Monitor,
    connection: SelectedMonitorConnection,
    client: NativeVimClient,
    *,
    connected_device: int,
    init_mode: int | None,
    parameter_c0: int,
    packet_limit: int,
    phase: int = 0,
    recording: bool = False,
    limits: Limits | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[MonitorPacket, ...]:
    """Selected native constructor→setup→poll packets→stop/delete interfaces."""
    from scripts.data_monitor import run_monitor_commands

    lifecycle = phase3_interface_lifecycle(
        profile,
        plan,
        connection,
        connected_device=connected_device,
        init_mode=init_mode,
        parameter_c0=parameter_c0,
        recording=recording,
    )
    return run_monitor_commands(
        lifecycle,
        client,
        interface_id=profile.category,
        frame_sizes=plan.frame_sizes,
        phase=phase,
        packet_limit=packet_limit,
        limits=limits,
        cancelled=cancelled,
        clock=clock,
    )


@dataclass(frozen=True)
class LegacyNotification:
    message: int
    wparam: int
    lparam: int = 0


def legacy_error_notification(
    native_error: int, status: int, *, family: str, signal_id: int = 0
) -> LegacyNotification | None:
    """P36bf0 versus DK6620: literal native callback ranges and DWORD mapping."""
    _uint(native_error, 0xFFFFFFFF, "Native callback error")
    _uint(status, 0xFFFFFFFF, "Native callback status")
    _uint(signal_id, 65535, "Native callback signal")
    if family not in ("P3", "DK"):
        raise MonitorError("Native callback family invalid")
    if status == 0xE0000100 or family == "P3" and 0xE0000189 <= status <= 0xE0000190:
        return None
    if status == 0xE000FFFF:
        return LegacyNotification(
            0x608, native_error & (255 if family == "DK" else 0xFFFFFFFF)
        )
    if family == "DK":
        return LegacyNotification(
            0x603,
            {
                0xE0020001: 0xA1050304,
                0xE0030001: 0xA1050305,
                0xE0040001: 0xA1050309,
            }.get(status, 0xA1050307),
        )
    if status in (0xE00001CC, 0xE00001CD):
        return LegacyNotification(0x602, 0, signal_id)
    codes = (
        0xA1050301,
        0xA1050308,
        0xA1050303,
        0xA1050305,
        0xA1050304,
        0xA1050304,
        0xA1050301,
        0xA1050308,
        0xA1050303,
        0xA1050305,
        0xA1050304,
        0xA1050304,
        0xA1050309,
        0xA1050312,
        0xA1050309,
        0xA1050312,
    )
    return LegacyNotification(
        0x603,
        codes[status - 0xE0000103]
        if 0xE0000103 <= status <= 0xE0000112
        else 0xA1050307,
    )


@dataclass(frozen=True)
class SelectedLegacyActiveMonitor:
    """Native absent/empty monitor buffer: P3b6b5 mode80, DKa6d2 mode400."""

    family: str
    packing: LegacyPacking
    source_sha256: str | None
    source_identity: tuple[object, ...]
    definitions: MonitorDefinitions
    signals: tuple[MonitorSignalMetadata, ...] = ()
    frame_sizes: tuple[tuple[int, int], ...] = ()
    commands: MonitorSetup = field(default_factory=lambda: MonitorSetup((), (), ()))
    auxiliary: Phase3Auxiliary | None = None


class LegacyDrsWriter:
    """Concrete FileManager groups11/12 writer over local BytesIO primitives."""

    def __init__(
        self,
        selection: NativeVehicleSelection,
        system_information: dict,
        trigger: NativeTriggerInfo,
        parameters: NativeTriggerParameters,
        *,
        stream: BytesIO | None = None,
    ):
        from copy import deepcopy
        from io import BytesIO

        from scripts.drive_recorder import (
            NativeTriggerInfo,
            NativeTriggerParameters,
            NativeVehicleSelection,
            encode_command,
        )

        if (
            not isinstance(selection, NativeVehicleSelection)
            or not isinstance(trigger, NativeTriggerInfo)
            or not isinstance(parameters, NativeTriggerParameters)
        ):
            raise MonitorError("Native DRS writer requires typed caller metadata")
        if stream is not None and not isinstance(stream, BytesIO):
            raise MonitorError("Native DRS writer requires concrete BytesIO primitives")
        selection.encode()
        trigger.encode()
        parameters.encode()
        encode_command(0x8100, {"system": system_information}).encode()
        self.selection, self.system_information = (
            selection,
            deepcopy(system_information),
        )
        self.trigger, self.parameters = trigger, parameters
        self.stream = stream if stream is not None else BytesIO()
        self.groups: dict[int, list[NativeDmciCommand]] = {}
        self.current: int | None = None
        self.position = 0
        self.result: DrsFile | None = None
        self.failure: BaseException | None = None

    def _write(self, data: bytes) -> None:
        if self.stream.tell() + len(data) > MAX_BYTES:
            raise MonitorError("Native DRS writer byte budget exhausted")
        if self.stream.write(data) != len(data):
            raise OSError("Native DRS writer short write")

    def begin(self, group: int) -> None:
        if (
            group not in (0x11, 0x12)
            or self.current is not None
            or group in self.groups
        ):
            raise MonitorError("Native DRS group start order rejected")
        self.position = self.stream.tell()
        self._write(bytes(4))
        self._write(struct.pack("<H", group))
        self.current = group
        self.groups[group] = []

    def command(self, command: NativeDmciCommand) -> None:
        if self.current is None:
            raise MonitorError("Native DRS command has no writer group")
        table = command.table()
        self._write(struct.pack("<I", len(table.payload) + 2))
        self._write(struct.pack("<H", table.table_id))
        self._write(table.payload)
        self.groups[self.current].append(command)

    def end(self) -> None:
        if self.current is None:
            raise MonitorError("Native DRS group end has no start")
        end = self.stream.tell()
        self.stream.seek(self.position)
        self._write(struct.pack("<I", end - self.position - 4))
        self.stream.seek(end)
        self.current = None

    def finalize(
        self,
        monitor: NativeMonitorBuffer,
        *,
        target: LegacyRunTarget,
        limits: Limits,
        clock: Callable[[], float],
        cancelled: Callable[[], bool],
    ) -> DrsFile:
        from scripts.drive_recorder import build_native_drs

        if (
            self.current is not None
            or set(self.groups) != {0x11, 0x12}
            or self.failure is not None
        ):
            raise MonitorError("Native DRS writer is incomplete")
        if self.result is not None:
            return self.result
        try:
            result = build_native_drs(
                self.selection,
                self.system_information,
                replace(monitor, value_after_count=1),
                self.trigger,
                self.parameters,
                setup=tuple(self.groups[0x11]),
                stop=tuple(self.groups[0x12]),
                **_selected_recording_protocol(
                    target,
                    self.trigger,
                    limits=limits,
                    clock=clock,
                    cancelled=cancelled,
                ),
            )
        except BaseException as error:
            self.failure = error
            raise
        groups = b"".join(
            table.encode() for table in result.tables if table.table_id in (0x11, 0x12)
        )
        if groups != self.stream.getvalue():
            raise MonitorError("Native DRS framing differs from emitted writer bytes")
        self.result = result
        return result


@dataclass(frozen=True)
class LegacyRunTarget:
    """Selected input to native P3ccc0/cf10 or DK9cd0/9ea0, before packing."""

    communication: NativeCommunication
    selected_ids: tuple[int, ...]
    observed_functions: Mapping[int, bool]
    allocation_size: int = 65536
    name: bytes = b""
    text_encoding: str = "ascii"
    standard_values: tuple[tuple[int, int], ...] = ()

    voltage_state: DLC12VoltageState | None = None
    voltage_observations: Mapping[int, DLC12VoltageObservation] | None = None

    def __post_init__(self) -> None:
        from types import MappingProxyType

        from scripts.native_communication import NativeCommunication

        if not isinstance(self.communication, NativeCommunication):
            raise MonitorError("Legacy Run requires retained native communication")
        if (
            not isinstance(self.selected_ids, tuple)
            or len(self.selected_ids) > MAX_ITEMS
        ):
            raise MonitorError("Legacy Run requires selected signal IDs", 0xC0050404)
        for signal in self.selected_ids:
            _uint(signal, 65535, "Selected signal")
        _uint(self.allocation_size, MAX_BYTES, "Native buffer allocation")
        if (
            (not self.allocation_size and bool(self.selected_ids))
            or not isinstance(self.name, bytes)
            or len(self.name) > 256
        ):
            raise MonitorError("Legacy native buffer fields invalid")
        object.__setattr__(
            self, "observed_functions", MappingProxyType(dict(self.observed_functions))
        )


@dataclass(frozen=True)
class LegacyControlResult:
    command_id: int
    status: int
    flags20: int = 0
    flags24: int = 0
    flags28: int = 0


@dataclass
class LegacyControlMessage:
    command_id: int
    targets: tuple[LegacyRunTarget, ...] = ()
    primary: LegacyRunTarget | None = field(default=None, kw_only=True)
    phase: int = 0
    signal_id: int = 0
    value: int = 0
    auxiliary: int = field(default=0, kw_only=True)
    initialize: bool = False
    enable_mode: int = 65535
    result: LegacyControlResult | None = None
    exception: BaseException | None = None
    _submitted: bool = field(default=False, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        _uint(self.command_id, 0xFFFFFFFF, "Native command")
        if (
            not isinstance(self.targets, tuple)
            or len(self.targets) > 3
            or any(not isinstance(t, LegacyRunTarget) for t in self.targets)
        ):
            raise MonitorError("Legacy command requires at most three selected targets")
        if self.primary is not None and (
            not isinstance(self.primary, LegacyRunTarget) or self.primary.selected_ids
        ):
            raise MonitorError(
                "Native command primary requires an empty selected target"
            )
        if type(self.phase) is not int or self.phase not in (0, 1):
            raise MonitorError("Native packet phase must be0/1")
        _uint(self.signal_id, 65535, "Active signal")
        _uint(self.value, 0xFFFFFFFF, "Active value")
        _uint(self.auxiliary, 255, "Active auxiliary value")
        _uint(self.enable_mode, 65535, "Native recording enable mode")
        if type(self.initialize) is not bool:
            raise MonitorError("Native active initialization must be boolean")


class LegacyCommandQueue:
    """Concrete external command queue plus manual-reset write/finish events."""

    def __init__(self, maximum: int = MAX_ITEMS):
        from collections import deque
        from threading import Event, Lock

        _uint(maximum, MAX_ITEMS, "Native queue capacity")
        if not maximum:
            raise MonitorError("Native queue capacity is zero")
        self.maximum = maximum
        self.write_event, self.finish_event = Event(), Event()
        self._lock = Lock()
        self._items: deque[LegacyControlMessage] = deque()

    def put(self, message: LegacyControlMessage) -> None:
        if not isinstance(message, LegacyControlMessage):
            raise MonitorError("Native queue requires typed command")
        with self._lock:
            if (
                message._submitted
                or message.result is not None
                or message.exception is not None
            ):
                raise MonitorError("Native queue command already submitted")
            if len(self._items) >= self.maximum:
                raise MonitorError("Native command queue budget exceeded")
            self._items.append(message)
            message._submitted = True
            self.finish_event.clear()
            self.write_event.set()

    def get(self) -> LegacyControlMessage:
        with self._lock:
            if not self._items:
                self.write_event.clear()
                raise MonitorError("Native GetCommand queue is empty", 0xC0050404)
            item = self._items.popleft()
            if not self._items:
                self.write_event.clear()
            return item


class LegacyMonitorController:
    """Source-owned Run queue and selected P3/DK monitor lifecycle.

    A cooperative run_one/poll seam and the actual host queue thread share the
    same dispatcher. No OEM code, user operation plan or whole-worker callback.
    """

    def __init__(
        self,
        *,
        family: str,
        connected_device: int,
        client: NativeVimClient | None = None,
        recording: bool = False,
        recording_writer: LegacyDrsWriter | None = None,
        init_mode: int | None = None,
        parameter_c0: int | None = None,
        shared_interface: int | None = None,
        disabled_packet_ecus: tuple[int, ...] | None = None,
        monitor_session: SelectedMonitorSession | None = None,
        limits: Limits | None = None,
        clock: Callable[[], float] = time.monotonic,
        cancelled: Callable[[], bool] = lambda: False,
    ):
        from collections import deque
        from threading import Event, RLock

        from scripts.drive_recorder import NativeVimClient

        if family not in ("P3", "DK") or type(recording) is not bool:
            raise MonitorError("Native Run family/recording rejected")
        _uint(connected_device, 0xFFFFFFFF, "Connected device")
        if client is not None and not isinstance(client, NativeVimClient):
            raise MonitorError("Native Run requires concrete VIM client")
        if recording_writer is not None and not isinstance(
            recording_writer, LegacyDrsWriter
        ):
            raise MonitorError("Native Run requires concrete DRS writer")
        self.recording_writer = recording_writer
        self.family, self.connected_device, self.recording = (
            family,
            connected_device,
            recording or recording_writer is not None,
        )
        from scripts.data_monitor import SelectedMonitorSession

        if monitor_session is not None and not isinstance(
            monitor_session, SelectedMonitorSession
        ):
            raise MonitorError("Native Run session type rejected")
        self.monitor_session = monitor_session
        self.client, self.init_mode, self.parameter_c0 = client, init_mode, parameter_c0
        self.shared_interface, self.disabled_packet_ecus = (
            shared_interface,
            disabled_packet_ecus,
        )
        self.limits, self.clock, self.cancelled = limits or Limits(), clock, cancelled
        self.queue: LegacyCommandQueue | None = None
        self.exit_event, self.worker_exit, self._data_exit = Event(), Event(), Event()
        self._lock = RLock()
        self._thread = None
        self._acquisition = None
        self._worker = None
        self._lower = None
        self._provider = None
        self._stop_commands: tuple = ()
        self._created = False
        self.targets: tuple[LegacyRunTarget, ...] = ()
        self._recording_slot = 0
        self._recording_original: LegacyRunTarget | None = None
        self.plans: tuple = ()
        self.buffers: tuple = ()
        self.readers: tuple = ()
        self.rings: tuple = ()
        self.packets: list[list] = []
        self.active_mask = 0
        self.errors = [0, 0, 0]
        self.trace: deque[tuple[str, int]] = deque(maxlen=MAX_ITEMS)
        self.notifications: deque[LegacyNotification] = deque(maxlen=MAX_ITEMS)
        self.failure: BaseException | None = None
        self.closed = False
        self._sources: tuple = ()
        self._active_queue = None
        self._active_identity = 0
        self._signal_id = 0
        self._system_request: bytes | None = None
        self._system_identity = 0
        self._pending_source_fault: BaseException | None = None
        self._dk_slot = 0
        self._dk_running = False
        self.dk_events = {
            name: Event() for name in ("stopped", "active", "data", "failed")
        }
        for event in self.dk_events.values():
            event.set()
        self._pending_command: LegacyControlMessage | None = None
        self._wait_key: str | None = None
        self._wait_deadline = 0.0
        self._calls = 0
        self._retained_bytes = 0
        self._deadline = math.inf
        self._last_clock: float | None = None

    def _check(self) -> None:
        from scripts.monitor_support import monitor_source_identity

        if self.cancelled():
            raise Cancelled("Native Run cancelled")
        now = self.clock()
        if (
            not math.isfinite(now)
            or now >= self._deadline
            or (self._last_clock is not None and now < self._last_clock)
        ):
            raise MonitorError("Native Run clock/deadline rejected")
        self._last_clock = now
        for target, identity in zip(self.targets, self._sources, strict=True):
            comm = target.communication
            if monitor_source_identity(comm.profile, comm.ecu) != identity:
                raise MonitorError("Native Run selected source changed")

    def _dmci(self, commands: tuple, *, cleanup: bool = False) -> None:
        from scripts.drive_recorder import NativeDmciCommand

        if self.client is None and self.recording_writer is None:
            raise MonitorError("Native Run DMCI client/writer absent")
        for command in commands:
            if not cleanup:
                self._check()
            if self.recording_writer is not None:
                self.recording_writer.command(
                    NativeDmciCommand.from_neutral(command.command_id, command.values)
                )
                continue
            assert self.client is not None
            response = self.client.dmci(
                NativeDmciCommand.from_neutral(command.command_id, command.values),
                timeout=2 if cleanup else max(0.001, self._deadline - self.clock()),
                cancelled=(lambda: False) if cleanup else self.cancelled,
            )
            if command.command_id == 0x114 and response != b"\x01\x00\x00\x00":
                raise MonitorError("Native SetNegCount did not return true", 0xA0050425)

    def post_error(self, status: int) -> None:
        _uint(status, 0xFFFFFFFF, "Native buffer error")
        if not status:
            raise MonitorError("Native buffer error is zero", 0xC0050001)
        for index, buffer in enumerate(self.buffers):
            if buffer is not None:
                self.errors[index] = status
        self.trace.append(("error", status))

    def buffer_error(self, index: int = 3) -> int:
        _uint(index, 0xFFFFFFFF, "Native buffer slot")
        return (
            self.errors[index]
            if index < len(self.buffers)
            else next((e for e in self.errors[: len(self.buffers)] if e), 0)
            if index >= 3
            else 0
        )

    def _start(self, message: LegacyControlMessage) -> int:
        from scripts.data_monitor import (
            selected_legacy_check_target,
            selected_p4_connection,
        )
        from scripts.drive_recorder import (
            NativeMonitorPacketReader,
            native_monitor_buffer,
        )
        from scripts.frame_transport import NativeFrameOperations
        from scripts.monitor_support import monitor_source_identity
        from scripts.native_communication import NativeFrameController
        from scripts.recorder_buffer import NativeRecorderRing
        from scripts.support import word

        targets = message.targets
        if not targets or (message.command_id == 9 and len(targets) != 1):
            raise MonitorError("Native Run selected target count invalid", 0xC0050404)
        inputs = ((message.primary,) if message.primary is not None else ()) + targets
        first = inputs[0].communication
        if any(
            t.communication.source_build != first.source_build
            or t.communication.profile.catalog.management.sha256
            != first.profile.catalog.management.sha256
            or t.communication.profile.vehicle_name_key
            != first.profile.vehicle_name_key
            or t.communication.profile.exception_ids != first.profile.exception_ids
            for t in inputs
        ):
            raise MonitorError(
                "Native Run selected application/vehicle contexts differ"
            )
        identities = {}
        for target in inputs:
            comm = target.communication
            category = comm.profile.category
            identity = monitor_source_identity(comm.profile, comm.ecu)
            if category in identities and identities[category] != identity:
                raise MonitorError("Native Run duplicate ECU selected sources differ")
            identities[category] = identity
        if message.command_id in (56, 87):
            # P3cfa8/DK9f28 first register command ECU with NULL buffer;8320
            # overwrites matching category slots instead of appending duplicates.
            primary = message.primary or replace(targets[0], selected_ids=())
            registered = {primary.communication.profile.category: primary}
            for target in targets:
                registered[target.communication.profile.category] = target
            if len(registered) > 3:
                raise MonitorError(
                    "Native registration exceeds three ECU slots", 0xC0050001
                )
            targets = tuple(registered.values())
        elif (
            message.primary is not None
            and message.primary.communication is not targets[0].communication
        ):
            raise MonitorError(
                "Native single command primary differs from selected target"
            )
        self._recording_original = (
            message.targets[0] if message.command_id == 87 else None
        )
        self._recording_slot = next(
            index
            for index, target in enumerate(targets)
            if target.communication.profile.category
            == message.targets[0].communication.profile.category
        )
        if (
            sum(target.allocation_size for target in targets if target.selected_ids)
            > MAX_BYTES
        ):
            raise MonitorError("Native Run aggregate allocation budget exceeded")
        first = targets[0].communication
        if self.monitor_session is not None:
            for target in inputs:
                self.monitor_session.check(
                    target.communication.profile,
                    source_build=target.communication.source_build,
                )
            self.shared_interface = self.monitor_session.shared_interface
            self.disabled_packet_ecus = self.monitor_session.disabled_packet_ecus
        self.targets = targets
        self._sources = tuple(
            monitor_source_identity(t.communication.profile, t.communication.ecu)
            for t in targets
        )
        excluded = (
            phase3_check_excluded(
                tuple(t.communication.profile.category for t in targets),
                command_kind=7 if message.command_id == 9 else 0x42,
                connected_device=self.connected_device,
                command_ecu=first.profile.category,
                shared_interface=self.shared_interface,
                disabled_packet_ecus=self.disabled_packet_ecus,
            )
            if self.family == "P3"
            else 0
        )
        if message.command_id == 87:
            excluded |= ~message.enable_mode & 65535
        plans, connections = [], []
        for target in targets:
            comm, profile = (
                target.communication,
                target.communication.profile,
            )
            self._check()
            if profile.category == 0x68:
                from scripts.monitor_instruments import selected_instrument_monitor

                plans.append(
                    selected_instrument_monitor(
                        _selected_profile(profile),
                        target.selected_ids,
                        voltage_state=target.voltage_state,
                        voltage_observations=target.voltage_observations,
                    )
                )
                connections.append(None)
                continue
            if not isinstance(comm.operations, NativeFrameController):
                raise MonitorError("Native Run selected controller absent", 0xC0040601)
            connection = selected_p4_connection(
                profile,
                bus_id=comm.bus_id,
                diagnostic_mode=comm.operations.operations.diagnostic_mode,
                controller_category_flags=profile.category_record[72],
            )
            connections.append(connection)
            if not target.selected_ids:
                identity = monitor_source_identity(profile, "")
                definitions = MonitorDefinitions(
                    (), (), (), profile.ecu_database_sha256, identity
                )
                plans.append(
                    SelectedLegacyActiveMonitor(
                        self.family,
                        LegacyPacking(
                            self.family,
                            0x80 if self.family == "P3" else 0x400,
                            (),
                            (),
                            (),
                        ),
                        profile.ecu_database_sha256,
                        identity,
                        definitions,
                    )
                )
                continue
            profile = _selected_profile(profile)
            if self.family == "P3":
                check_target = selected_legacy_check_target(
                    comm,
                    target.selected_ids,
                    target.observed_functions,
                    monitor_session=self.monitor_session,
                )
                protocol = profile.protocol_info(comm.bus_id)
                if protocol is None:
                    raise MonitorError("Native Run protocol absent", 0xC0050101)
                plan = selected_phase3_from_exchange(
                    profile,
                    target.selected_ids,
                    comm,
                    comm.ecu,
                    target.observed_functions,
                    interface_id=connection.address.request_id,
                    excluded=excluded,
                    maximum_request=word(protocol, 14),
                    maximum_reply=word(protocol, 16),
                    parameter_8=connection.address.functional_id
                    if len(targets) > 1
                    else 0xFFFFFFFF,
                    standard_values=target.standard_values,
                    native_ecu=profile.category,
                    packet_protocol=comm.bus_id,
                    packet_cache=check_target.packet_cache,
                    support_stream=comm,
                    bus_id=comm.bus_id,
                    source_build=comm.source_build,
                    limits=self.limits,
                    clock=self.clock,
                    cancelled=self.cancelled,
                )
            else:
                plan = selected_dk_from_exchange(
                    profile,
                    target.selected_ids,
                    comm,
                    comm.ecu,
                    target.observed_functions,
                    excluded=0,
                    support_stream=comm,
                    bus_id=comm.bus_id,
                    source_build=comm.source_build,
                    limits=self.limits,
                    clock=self.clock,
                    cancelled=self.cancelled,
                )
            plans.append(plan)
        if self.family == "P3" and len(targets) > 1:
            selected_connections = tuple(c for c in connections if c is not None)
            if selected_connections and any(
                connection.bus_id != selected_connections[0].bus_id
                or connection.address.response_id
                != selected_connections[0].address.response_id
                for connection in selected_connections[1:]
            ):
                raise MonitorError(
                    "Native P3 multi connection identity differs", 0xC0050001
                )
        self.plans = tuple(plans)
        self.buffers = tuple(
            native_monitor_buffer(
                t.communication.profile.category,
                p.signals,
                p.frame_sizes,
                t.selected_ids,
                phase=message.phase,
                allocation_size=t.allocation_size,
                name=t.name,
                text_encoding=t.text_encoding,
            )
            if not isinstance(p, SelectedLegacyActiveMonitor)
            else None
            for t, p in zip(targets, plans, strict=True)
        )
        self.readers = tuple(
            NativeMonitorPacketReader(p.frame_sizes, phase=message.phase)
            if p.frame_sizes
            else None
            for p in plans
        )
        self.rings = tuple(
            NativeRecorderRing(t.allocation_size, r.packet_size, 1, phase=message.phase)
            if r is not None
            else None
            for t, r in zip(targets, self.readers, strict=True)
        )
        self.packets = [[] for _ in targets]
        self._retained_bytes = 0
        self.errors[:] = [0, 0, 0]
        mode = 0
        from scripts.monitor_instruments import (
            SelectedInstrumentMonitor,
            VoltageMonitorInterface,
        )

        for plan in plans:
            mode |= (
                plan.mode
                if isinstance(plan, SelectedInstrumentMonitor)
                else plan.packing.mode
            )
        for index, plan in enumerate(plans):
            if isinstance(plan, SelectedInstrumentMonitor):
                descriptor = plan.descriptors[0]
                if not VoltageMonitorInterface.setup(
                    int.from_bytes(descriptor[:4], "little"),
                    descriptor[4],
                    self.buffers[index],
                ):
                    raise MonitorError("Native voltage setup failed", 0x90051205)
        if self.family == "P3" and (self.connected_device == 4 or self.recording):
            if self.client is None and self.recording_writer is None:
                raise MonitorError("Native Run DMCI client absent", 0xC0050001)
            if self.parameter_c0 is None:
                raise MonitorError("Native commandC0 observation absent", 0xC0050001)
            lifecycle = phase3_interface_lifecycle(
                first.profile,
                plans[0],
                connections[0],
                connected_device=self.connected_device,
                init_mode=self.init_mode,
                parameter_c0=self.parameter_c0,
                recording=self.recording,
            )
            self._stop_commands = lifecycle.stop
            self._created = True
            self._dmci(lifecycle.setup)
            for plan, connection in zip(plans[1:], connections[1:], strict=True):
                self._dmci(_phase3_dmci_system_setup(plan, connection))
            self._dmci(lifecycle.start)
        else:
            if self.connected_device != 8:
                raise MonitorError("Native Run device rejected", 0xC0051302)
            operations = []
            for target, plan in zip(targets, plans, strict=True):
                comm = target.communication
                controller = comm.operations
                if not isinstance(controller, NativeFrameController):
                    raise MonitorError("Native Run requires retained frame controller")
                lower = controller.operations
                selected = selected_legacy_j2534_frames(
                    comm.profile,
                    plan,
                    ecu=comm.ecu,
                    bus_id=comm.bus_id,
                    driver=lower.driver,
                    diagnostic_mode=lower.diagnostic_mode,
                    connected_device=8,
                    source_build=comm.source_build,
                    interface_count=len(targets),
                )
                operations.append(
                    NativeFrameOperations(
                        comm.profile,
                        selected.frames[0],
                        lower.backend,
                        native_build=comm.source_build,
                        bus_id=comm.bus_id,
                        driver=lower.driver,
                        device_kind=8,
                        diagnostic_mode=lower.diagnostic_mode,
                        clock=self.clock,
                        cancelled=self.cancelled,
                    )
                )
            self._lower = operations[0]
            if len(targets) > 1 and self.family == "DK":
                # DK7050 updates its single event only for allocated data slots;
                # an absent buffer returns400 before DataListIF setup.
                data_slots = tuple(i for i, p in enumerate(plans) if p.frame_sizes)
                if data_slots and any(
                    (connections[index].address.request_id & 255)
                    != (connections[data_slots[0]].address.request_id & 255)
                    for index in data_slots[1:]
                ):
                    raise MonitorError("Native DK setup source differs", 0xA0050425)
                self._dk_slot = data_slots[-1] if data_slots else 0
                self._lower = operations[self._dk_slot]
                if data_slots:
                    code = self._lower.open(deadline=self._deadline)
                    if code:
                        raise MonitorError("Native DK Run open failed", code)
                self._provider = LegacyNativeProvider(
                    self._lower,
                    ecu=targets[self._dk_slot].communication.ecu,
                    deadline=self._deadline,
                )
            elif len(targets) > 1:
                from scripts.monitor_j2534 import (
                    CenturyNativeFrameOperations,
                    century_frame_plan,
                )

                if self.family != "P3" or len(targets) != 2:
                    raise MonitorError(
                        "Native Century registration exceeds two systems", 0xA0050425
                    )
                lower = operations[0]
                sources = tuple(
                    int.from_bytes(op.diagnostic_mode[8:12], "little")
                    or word(connections[i].protocol_record, 8)
                    for i, op in enumerate(operations)
                )
                functional = CenturyNativeFrameOperations(
                    first.profile,
                    century_frame_plan(
                        first.profile,
                        bus_id=first.bus_id,
                        driver=lower.driver,
                        diagnostic_mode=lower.diagnostic_mode,
                    ),
                    lower.backend,
                    registered_response_ids=(sources[0], sources[1]),
                    native_build=first.source_build,
                    bus_id=first.bus_id,
                    driver=lower.driver,
                    device_kind=8,
                    diagnostic_mode=lower.diagnostic_mode,
                    clock=self.clock,
                    cancelled=self.cancelled,
                )
                self._worker = selected_phase3_century_worker(
                    ((plans[0], operations[0]), (plans[1], operations[1])),
                    functional,
                    ecus=(targets[0].communication.ecu, targets[1].communication.ecu),
                    limits=self.limits,
                    clock=self.clock,
                    cancelled=self.cancelled,
                )
                if mode & 0x337:
                    code = self._worker.start()
                    if code != 0xE0000100:
                        raise MonitorError("Native Century Run start failed", code)
            elif self.family == "P3":
                self._worker = selected_phase3_native_worker(
                    plans[0],
                    self._lower,
                    ecu=first.ecu,
                    limits=self.limits,
                    clock=self.clock,
                    cancelled=self.cancelled,
                )
                if self.monitor_session is not None:
                    self._worker.disable_packet_ecu = (
                        self.monitor_session.disable_packet_ecu
                    )
                if not isinstance(plans[0], SelectedLegacyActiveMonitor):
                    code = self._worker.start()
                    if code != 0xE0000100:
                        raise MonitorError("Native Run worker start failed", code)
            else:
                if not isinstance(plans[0], SelectedLegacyActiveMonitor):
                    code = self._lower.open(deadline=self._deadline)
                    if code:
                        raise MonitorError("Native DK Run open failed", code)
                self._provider = LegacyNativeProvider(
                    self._lower, ecu=first.ecu, deadline=self._deadline
                )
        self.active_mask = mode
        self._dk_running = self.family == "DK" and bool(
            plans[self._dk_slot].frame_sizes
        )
        if self._dk_running:
            for key in ("data", "stopped", "failed"):
                self.dk_events[key].clear()
        self.trace.append(("started", mode))
        return mode

    def _dk_wait(self, key: str, milliseconds: int, notification: int) -> bool:
        """DKa377/a4b8/a5a3 cooperative native event/deadline observation."""
        if self.dk_events[key].is_set():
            if self._wait_key == key:
                self._wait_key = None
            return True
        if self._wait_key != key:
            self._wait_key = key
            self._wait_deadline = self.clock() + milliseconds / 1000
            self.trace.append(("wait-" + key, milliseconds))
        if self.clock() < self._wait_deadline:
            return False
        self._wait_key = None
        self.notifications.append(LegacyNotification(0x603, notification))
        return True

    def _active(self, message: LegacyControlMessage) -> bool | None:
        from scripts.data_monitor import MonitorCommand, selected_p4_connection
        from scripts.monitor_j2534 import (
            ActiveMonitorEvent,
            CenturyJ2534Worker,
            MonitorSystemEvent,
            NativeMonitorSourceFault,
        )
        from scripts.support import word
        from scripts.toyota_session import LegacyActiveQueue, active_request_p3

        if not self.active_mask:
            raise MonitorError("Native control requires started interface", 0x90050405)
        if message.command_id == 12:
            if self._active_queue is None and not self._active_identity:
                return
            if self._worker is not None:
                active = self._worker.events[0]
                if active is not None:
                    active.stop(initialize=message.initialize)
            elif self._created:
                self._dmci(
                    (
                        MonitorCommand(
                            0x110, (self._active_identity, int(message.initialize))
                        ),
                    )
                )
            elif self.family == "DK":
                if not self._dk_wait("active", 10000, 0xC0050504):
                    return False
                if not self.dk_events["failed"].is_set():
                    assert self._lower is not None
                    status = self._lower.close()
                    if status:
                        raise MonitorError("Native DK active stop failed", 0xA0050432)
                    self.dk_events["stopped"].set()
                self._dk_running = False
            self._active_queue = None
            self._active_identity = 0
            return
        target = message.targets[0] if message.targets else self.targets[0]
        if not any(
            target.communication is retained.communication for retained in self.targets
        ):
            raise MonitorError("Native control target was not registered by this Run")
        comm, profile = (
            target.communication,
            target.communication.profile,
        )
        controller = comm.operations
        from scripts.native_communication import NativeFrameController

        if not isinstance(controller, NativeFrameController):
            raise MonitorError("Native control connection absent", 0xC0040601)
        connection = selected_p4_connection(
            profile,
            bus_id=comm.bus_id,
            diagnostic_mode=controller.operations.diagnostic_mode,
            controller_category_flags=profile.category_record[72],
        )
        if message.command_id == 96:
            if self.family == "DK":
                raise MonitorError(
                    "Native DK system operation is unavailable", 0x90050405
                )
            if self.active_mask & 7:
                raise MonitorError(
                    "Native monitor system rejects packet modes", 0xC005100D
                )
            family = comm.bus_id & 15
            if family not in (1, 2, 6, 7, 8, 9):
                raise MonitorError("Native monitor system bus rejected", 0xC0040602)
            request = bytes((8, message.signal_id & 255)) + (
                bytes(5) if family in (1, 6, 7, 9) else b""
            )
            if self._worker is not None:
                system = MonitorSystemEvent(request[1:])
                if isinstance(self._worker, CenturyJ2534Worker):
                    # BASE system registration retains its first request ID; the
                    # Century thread processes only the separate DM event.
                    if self._system_identity not in (0, connection.address.request_id):
                        raise MonitorError(
                            "Native Century system identity rejected", 0xA0051401
                        )
                    self._system_identity = connection.address.request_id
                    self._worker.events = (
                        self._worker.events[0],
                        system,
                        self._worker.events[2],
                    )
                else:
                    self._worker.events = (
                        self._worker.events[0],
                        system,
                        self._worker.events[2],
                    )
                if self._worker.state == "configured":
                    try:
                        code = self._worker.start()
                    except NativeMonitorSourceFault as error:
                        self._pending_source_fault = error
                    else:
                        if code != 0xE0000100:
                            raise MonitorError(
                                "Native system worker start failed", 0xA0051401
                            )
            elif self._created:
                self._dmci(
                    (
                        MonitorCommand(
                            0x113, (connection.address.request_id, request[1:])
                        ),
                    )
                )
            else:
                self._system_request = request
            return
        profile = _selected_profile(profile)
        records = profile.records(11)
        if any(len(row) != 92 for row in records):
            raise MonitorError("Native active records malformed", 0xC0050101)
        record = next(
            (row for row in records if word(row, 56) == message.signal_id), None
        )
        if record is None:
            raise MonitorError("Native active signal absent", 0xC0050101)
        patterns = profile.records(12)
        if any(len(row) != 24 for row in patterns):
            raise MonitorError("Native active pattern malformed", 0xC0050101)
        pattern = next(
            (row for row in patterns if word(row, 0) == word(record, 64)), None
        )
        if pattern is None:
            raise MonitorError("Native active pattern absent", 0xC0050101)
        from scripts.toyota import ToyotaCodecError

        category_flags = self.targets[0].communication.profile.category_record[72]
        try:
            support = None
            if category_flags & 31 == 4:
                comm.cache.begin_operation(limits=self.limits)
                support = comm.cache.support_bits(2).get(record[0x52])
                if support is None:
                    raise MonitorError("Native active DID service absent", 0xC005100C)
            request, repeat = active_request_p3(
                record,
                pattern,
                category_flags,
                message.value,
                auxiliary=message.auxiliary,
                support=support,
            )
        except ToyotaCodecError as error:
            raise MonitorError(
                "Native active selected request failed", error.code
            ) from error
        if not 1 < len(request) <= 63:
            raise MonitorError("Native active body is invalid", 0xA0050441)
        if self.family == "DK":
            if not self._dk_wait("stopped", 30000, 0xC0050503):
                return False
            for key in ("active", "stopped", "failed"):
                self.dk_events[key].clear()
        self._active_identity = connection.address.request_id
        if self.family == "P3":
            self._signal_id = message.signal_id
        if self._worker is not None:
            if (
                isinstance(self._worker, CenturyJ2534Worker)
                and self._active_identity != self._worker.systems[0].request_id
            ):
                raise MonitorError(
                    "Native Century active identity rejected", 0xA0050441
                )
            active = self._worker.events[0]
            if active is None or active.stopped:
                active = ActiveMonitorEvent(
                    request[1:], repeat, dk_kwp=self._worker.dk_kwp
                )
            else:
                active.append(request[1:], repeat)
            if isinstance(self._worker, CenturyJ2534Worker):
                self._worker.events = (
                    active,
                    self._worker.events[1],
                    self._worker.events[2],
                )
            else:
                self._worker.events = (
                    active,
                    self._worker.events[1],
                    self._worker.events[2],
                )
            if self._worker.state == "configured":
                try:
                    code = self._worker.start()
                except NativeMonitorSourceFault as error:
                    self._pending_source_fault = error
                else:
                    if code != 0xE0000100:
                        raise MonitorError(
                            "Native active worker start failed", 0xA0050441
                        )
        elif self._created:
            self._dmci(
                (MonitorCommand(0x10F, (self._active_identity, request[1:], repeat)),)
            )
        else:
            if self._active_queue is None:
                self._active_queue = LegacyActiveQueue(
                    "dk" if self.family == "DK" else "ordinary"
                )
            if self._lower is not None and self._lower.channel is None:
                code = self._lower.open(deadline=self._deadline)
                if code:
                    raise MonitorError("Native DK active open failed", 0xA0050441)
            self._active_queue.enqueue(request[1:], repeat_ms=repeat)
            self._dk_running = self.family == "DK"

    def poll(self) -> tuple:
        with self._lock:
            try:
                return self._poll()
            except MonitorError as error:
                if self.family == "DK" and error.code is not None:
                    # DK6620 signals these before mapping/posting the error.
                    for key in ("active", "data", "failed"):
                        self.dk_events[key].set()
                raise

    def _poll(self) -> tuple:
        from scripts.drive_recorder import NativeCoreBuffer, NativeMonitorPacket

        with self._lock:
            self._check()
            if not self.active_mask:
                raise MonitorError(
                    "Native Run polling requires active monitor", 0x90050405
                )
            if self._pending_source_fault is not None:
                error, self._pending_source_fault = self._pending_source_fault, None
                raise error
            if self.family == "DK" and not self._dk_running:
                return ()
            self._calls += 1
            if self._calls > self.limits.exchanges:
                raise MonitorError("Native Run primitive budget exhausted")
            emitted = []
            if self._worker is not None:
                from scripts.monitor_j2534 import CenturyJ2534Worker

                century = isinstance(self._worker, CenturyJ2534Worker)
                observed = (
                    self._worker.system_packets
                    if isinstance(self._worker, CenturyJ2534Worker)
                    else self._worker.packets
                )
                if self._worker.state == "configured":
                    return ()
                before = len(observed)
                code = self._worker.step()
                if code != 0xE0000100:
                    note = legacy_error_notification(
                        self._worker.request_id,
                        code,
                        family=self.family,
                        signal_id=self._signal_id,
                    )
                    if note is not None:
                        self.notifications.append(note)
                    raise MonitorError("Native Run worker failed", code)
                emitted.extend(
                    observed[before:]
                    if century
                    else ((0, packet) for packet in observed[before:])
                )
            elif self._provider is not None:
                comm, plan = (
                    self.targets[self._dk_slot].communication,
                    self.plans[self._dk_slot],
                )
                send, receive = dk_monitor_timing(comm.profile)
                request = self._system_request
                if (
                    request is None
                    and self._active_queue is not None
                    and self._active_queue.items[-1].state == 0
                ):
                    request = self._active_queue.send_frame(
                        int(self.clock() * 1000) & 0xFFFFFFFF
                    )
                if request is not None:
                    code = self._provider.send(
                        comm.ecu,
                        request,
                        timeout=send,
                        protocol=comm.bus_id,
                        initialize=False,
                    )
                    if code:
                        raise MonitorError("Native control send failed", code)
                    reply = self._provider.receive(
                        comm.ecu,
                        maximum=4096,
                        timeout=receive,
                        buffer=True,
                        argument_5=0,
                        flags=100,
                    )
                    if reply.code:
                        raise MonitorError("Native control receive failed", reply.code)
                    if self._system_request is not None:
                        if not reply.data or reply.data[0] != 0x48:
                            raise MonitorError(
                                "Native monitor system reply rejected", 0xA0051401
                            )
                        self._system_request = None
                    elif self._active_queue is not None:
                        self._active_queue.accept(
                            reply.data, int(self.clock() * 1000) & 0xFFFFFFFF
                        )
                        self.dk_events["active"].set()
                if isinstance(plan, SelectedLegacyActiveMonitor):
                    self._check()
                    return ()
                timestamp, payload = dk_monitor_cycle(
                    plan.event,
                    self._provider,
                    comm.ecu,
                    protocol=comm.bus_id,
                    send_timeout=send,
                    receive_timeout=receive,
                    retry_limit=0,
                    tick_ms=lambda: int(self.clock() * 1000) & 0xFFFFFFFF,
                    cancelled=self.cancelled,
                    maximum_calls=self.limits.exchanges,
                )
                self.dk_events["data"].set()
                emitted.append((self._dk_slot, NativeMonitorPacket(timestamp, payload)))
            else:
                assert self.client is not None
                slots = tuple(
                    (index, target.communication.profile.category)
                    for index, target in enumerate(self.targets)
                    if self.buffers[index] is not None
                )
                reply = self.client.get_monitor_data(
                    tuple(key for _, key in slots),
                    timeout=max(0.001, self._deadline - self.clock()),
                    cancelled=self.cancelled,
                )
                for interface, buffer in reply.interfaces.items:
                    if not isinstance(buffer, NativeCoreBuffer):
                        raise MonitorError("Native monitor reply buffer malformed")
                    for index, key in slots:
                        if key == interface:
                            reader = self.readers[index]
                            assert reader is not None
                            emitted.extend(
                                (index, packet) for packet in reader.feed(buffer.data)
                            )
                if (
                    sum(len(buffer.data) for buffer in reply.buffers) > MAX_BYTES
                    or reply.trailing_value > MAX_ITEMS
                ):
                    raise MonitorError("Native Run notification budget exceeded")
                first, detailed = (reply.buffers[i].data for i in (0, 1))
                notices = [
                    (int.from_bytes(first[i : i + 4], "little"), 0xE000FFFF)
                    for i in range(0, len(first) - 3, 4)
                ]
                notices.extend(
                    (
                        int.from_bytes(detailed[i + 4 : i + 8], "little"),
                        int.from_bytes(detailed[i + 8 : i + 12], "little"),
                    )
                    for i in range(0, len(detailed) - 12, 13)
                )
                for native, status in notices:
                    note = legacy_error_notification(
                        native, status, family=self.family, signal_id=self._signal_id
                    )
                    if note is not None:
                        self.notifications.append(note)
                        if note.message in (0x603, 0x608) and note.wparam:
                            self.post_error(note.wparam)
                self.notifications.extend(
                    LegacyNotification(0x515, 0) for _ in range(reply.trailing_value)
                )
                if reply.trailing_value:
                    self._stop()
            for index, packet in emitted:
                charge = 4 + len(packet.payload)
                if self._retained_bytes + charge > MAX_BYTES:
                    raise MonitorError("Native Run capture budget exhausted")
                ring = self.rings[index]
                if ring is None:
                    raise MonitorError("Native packet has no allocated monitor buffer")
                ring.append(packet.timestamp_ms, packet.payload)
                self.packets[index].append(packet)
                self._retained_bytes += charge
            self._check()
            return tuple(emitted)

    def _stop(self) -> None:
        failure: BaseException | None = None
        try:
            if self._worker is not None:
                try:
                    if self._worker.state in ("select", "send", "receive", "idle"):
                        previous = self._worker.operations.cancelled
                        self._worker.operations.cancelled = lambda: False
                        self._worker.cleanup_mode, self._worker.cleanup_steps = True, 0
                        try:
                            status = self._worker.stop()
                            if status != 0xE0000100:
                                raise MonitorError("Native Run stop failed", status)
                        finally:
                            self._worker.cleanup_mode = False
                            self._worker.operations.cancelled = previous
                except BaseException as error:  # noqa: BLE001 - close after protocol stop failure
                    failure = error
                try:
                    status = self._worker.close()
                    if status:
                        raise MonitorError("Native Run close failed", status)
                except BaseException as error:  # noqa: BLE001 - preserve the first cleanup fault
                    failure = failure or error
            elif self._lower is not None:
                status = self._lower.close()
                if status:
                    raise MonitorError("Native DK close failed", status)
            elif self._created:
                from scripts.data_monitor import MonitorCommand

                commands = self._stop_commands
                if self._active_identity:
                    commands = (
                        MonitorCommand(0x110, (self._active_identity, 0)),
                    ) + commands
                for command in commands:
                    try:
                        self._dmci((command,), cleanup=True)
                    except BaseException as error:  # noqa: BLE001 - dispose every native resource
                        failure = failure or error
        finally:
            self._worker = self._lower = self._provider = None
            self._created = False
            self._dk_running = False
            self.dk_events["stopped"].set()
            self._wait_key = None
            self._active_queue = None
            self._active_identity = 0
            self._signal_id = 0
            self._system_request = None
            self._system_identity = 0
            self._pending_source_fault = None
            self.active_mask = 0
            self.trace.append(("stopped", 0))
        if failure is not None:
            raise failure

    def _record87(self, message: LegacyControlMessage) -> int:
        writer = self.recording_writer
        assert writer is not None
        failure: BaseException | None = None
        mode = 0
        writer.begin(0x11)
        self.trace.append(("drs-start", 0x11))
        try:
            mode = self._start(message)
        except BaseException as error:  # noqa: BLE001 - retain first native/host failure through writer cleanup
            failure = error
        try:
            writer.end()
            self.trace.append(("drs-end", 0x11))
        except BaseException as error:  # noqa: BLE001 - stop/dispose is still required
            failure = failure or error
            writer.current = None
        try:
            writer.begin(0x12)
            self.trace.append(("drs-start", 0x12))
            self._stop()
        except BaseException as error:  # noqa: BLE001 - finish writer framing after cleanup failure
            failure = failure or error
        try:
            writer.end()
            self.trace.append(("drs-end", 0x12))
        except BaseException as error:  # noqa: BLE001 - preserve operation-local failure identity
            failure = failure or error
        if failure is not None:
            writer.failure = failure
            raise failure
        return mode

    def run_one(self, *, wait_status: int = 0) -> LegacyControlResult | None:
        with self._lock:
            if self.closed or self.queue is None:
                raise MonitorError("Native Run queue is not attached", 0xC0050001)
            if wait_status == 1:
                self.exit_event.set()
                self._stop()
                self.worker_exit.set()
                return None
            if wait_status == 0x102:
                if self.buffer_error():
                    self._stop()
                return None
            if wait_status:
                self.post_error(0xA0050511)
                self._stop()
                return None
            try:
                message = self._pending_command or self.queue.get()
            except MonitorError as error:
                self.queue.finish_event.set()
                self.trace.append(("finish", 0))
                self.post_error(error.code or 0xC0050404)
                if self.buffer_error():
                    self._stop()
                return LegacyControlResult(0, error.code or 0xC0050404)
            status, mode, started = 0, 0, 0
            try:
                if self._deadline == math.inf:
                    self._deadline = self.clock() + self.limits.seconds
                self._check()
                if message.command_id in (9, 56, 87):
                    if self.family == "DK" and message.command_id == 87:
                        raise MonitorError(
                            "Native DK recording operation is unavailable", 0x90050405
                        )
                    if self.active_mask:
                        raise MonitorError("Native Run already active", 0x90050405)
                    mode = (
                        self._record87(message)
                        if message.command_id == 87
                        and self.recording_writer is not None
                        else self._start(message)
                    )
                    started = 1
                elif message.command_id in (11, 12, 96):
                    if self._active(message) is False:
                        self._pending_command = message
                        return None
                elif message.command_id == 10:
                    if self.active_mask:
                        if self.family == "DK":
                            if self._active(LegacyControlMessage(12)) is False:
                                self._pending_command = message
                                return None
                            if self.active_mask & 0x337 in (
                                0,
                                0x200,
                            ) and not self._dk_wait("data", 10000, 0xC0050504):
                                self._pending_command = message
                                return None
                        self._stop()
                else:
                    raise MonitorError("Native Run command rejected", 0x90050405)
            except MonitorError as error:
                status = error.code or 0xC0050001
            except BaseException as error:
                message.exception = error
                self._pending_command = None
                self.queue.finish_event.set()
                self.trace.append(("finish", message.command_id))
                try:
                    self._stop()
                except BaseException as cleanup:  # noqa: BLE001 - preserve host failure identity
                    error.add_note(f"Native Run cleanup failed: {cleanup}")
                raise
            self._pending_command = None
            result = LegacyControlResult(
                message.command_id,
                status,
                mode,
                started if message.command_id in (56, 87) else 0,
                started if message.command_id == 9 else 0,
            )
            message.result = result
            self.queue.finish_event.set()
            self.trace.append(("finish", message.command_id))
            if status:
                self.post_error(status)
            if self.buffer_error():
                self._stop()
            return result

    def run(self, queue: LegacyCommandQueue) -> int:
        from threading import Thread

        if (
            not isinstance(queue, LegacyCommandQueue)
            or self._thread is not None
            or self.closed
        ):
            raise MonitorError("Native Run arguments/state rejected", 0xC0050001)
        self.queue = queue
        self._deadline = self.clock() + self.limits.seconds
        self.exit_event.clear()
        self.worker_exit.clear()

        def worker() -> None:
            try:
                while not self.exit_event.is_set():
                    if (
                        queue.write_event.wait(0.01)
                        or self._pending_command is not None
                    ):
                        self.run_one()
                    elif self.buffer_error():
                        with self._lock:
                            self._stop()
                    with self._lock:
                        self._check()
            except BaseException as error:  # noqa: BLE001 - retain exact worker exception for the caller
                self.failure = error
            finally:
                try:
                    with self._lock:
                        self._stop()
                except BaseException as error:  # noqa: BLE001 - signal exit even after cleanup fault
                    self.failure = self.failure or error
                with self._lock:
                    if self._pending_command is not None:
                        self._pending_command.exception = self.failure or MonitorError(
                            "Native Run exited during command wait", 0xA0050511
                        )
                        self.trace.append(("finish", self._pending_command.command_id))
                        self._pending_command = None
                        queue.finish_event.set()
                self.worker_exit.set()

        def acquisition() -> None:
            while not self._data_exit.wait(0.01):
                try:
                    if self.active_mask:
                        self.poll()
                except MonitorError as error:
                    if error.code is not None:
                        with self._lock:
                            if self.family == "DK":
                                for key in ("active", "data", "failed"):
                                    self.dk_events[key].set()
                                note = legacy_error_notification(
                                    0, error.code, family="DK"
                                )
                                if note is not None:
                                    self.notifications.append(note)
                            self.post_error(error.code)
                            try:
                                self._stop()
                            except BaseException as cleanup_error:  # noqa: BLE001 - signal failed resource release
                                self.failure = cleanup_error
                                self.exit_event.set()
                                return
                    else:
                        self.failure = error
                        self.exit_event.set()
                        return
                except BaseException as error:  # noqa: BLE001 - retain host cancellation/failure identity
                    self.failure = error
                    self.exit_event.set()
                    return

        self._acquisition = Thread(
            target=acquisition, name=f"native-{self.family}-acquisition", daemon=True
        )
        self._acquisition.start()
        self._thread = Thread(
            target=worker, name=f"native-{self.family}-monitor", daemon=True
        )
        self._thread.start()
        return 0

    def close(self) -> None:
        self.exit_event.set()
        self._data_exit.set()
        if self._acquisition is not None:
            self._acquisition.join(timeout=1)
            if self._acquisition.is_alive():
                raise MonitorError(
                    "Native acquisition worker did not exit within1000ms", 0xA0050511
                )
        if self._thread is not None:
            self._thread.join(timeout=1)
            if self._thread.is_alive():
                raise MonitorError(
                    "Native Run worker did not exit within1000ms", 0xA0050511
                )
        with self._lock:
            self._stop()
            if self._pending_command is not None:
                self._pending_command.exception = self.failure or MonitorError(
                    "Native Run exited during command wait", 0xA0050511
                )
                self.trace.append(("finish", self._pending_command.command_id))
                self._pending_command = None
                if self.queue is not None:
                    self.queue.finish_event.set()
            self.closed = True
            self.worker_exit.set()

    def recording_file(self) -> DrsFile:
        """Actual outer caller writes first-buffer metadata after Run87 finish."""
        from scripts.monitor_support import monitor_source_identity

        with self._lock:
            if (
                self.recording_writer is None
                or self.active_mask
                or not self.buffers
                or self.buffers[self._recording_slot] is None
            ):
                raise MonitorError(
                    "Native DRS caller has no completed first monitor buffer"
                )
            for target, identity in zip(self.targets, self._sources, strict=True):
                if (
                    monitor_source_identity(
                        target.communication.profile,
                        target.communication.ecu,
                    )
                    != identity
                ):
                    raise MonitorError("Native DRS caller selected source changed")
            if self.targets[self._recording_slot] is not self._recording_original:
                from scripts.drive_recorder import UnsupportedRecorderOperation

                error = UnsupportedRecorderOperation(
                    "Native first original DRS buffer was overwritten before packing; "
                    "unpacked buffer serialization is not recovered"
                )
                self.recording_writer.failure = error
                raise error
            return self.recording_writer.finalize(
                self.buffers[self._recording_slot],
                target=self.targets[self._recording_slot],
                limits=self.limits,
                clock=self.clock,
                cancelled=self.cancelled,
            )

    def capture(self, index: int = 0) -> SelectedMonitorCapture:
        from scripts.drive_recorder import NativeRecorderCapture

        _uint(index, 2, "Native buffer slot")
        if index >= len(self.plans):
            raise MonitorError("Native Run buffer slot is absent")
        ring = self.rings[index]
        if ring is None:
            raise MonitorError("Native active-only target has no monitor capture")
        ring.set_record_area(ring.start, ring.active_size)
        return SelectedMonitorCapture(
            self.plans[index],
            NativeRecorderCapture(
                0, tuple(self.packets[index]), (ring.serialize(0), ring.serialize(1))
            ),
        )

    def dm_bytes(self, index: int, metadata, system_information: dict) -> bytes:
        """Serialize the actual acquired ring and selected tables to native DM."""
        with self._lock:
            selected = self.capture(index)
            settings = self.buffers[index]
            if settings is None:
                raise MonitorError("Native active-only target has no monitor buffer")
            return selected.capture.dm_bytes(
                settings,
                metadata,
                system_information,
                phase=settings.phase,
                block_packets=settings.block_packets,
                standard_values=self.targets[index].standard_values,
            )


def _selected_recording_protocol(
    target: LegacyRunTarget,
    trigger: NativeTriggerInfo,
    *,
    limits: Limits,
    clock: Callable[[], float],
    cancelled: Callable[[], bool],
) -> dict[str, tuple[DrsTable, ...]]:
    """Outer CreateDrs1e30/3180 after Run87, from the retained selected channel."""
    from scripts.drive_recorder import selected_car_info_plan, selected_check_mode_plan
    from scripts.monitor_support import MonitorSupportCache, monitor_source_identity
    from scripts.native_communication import NativeFrameController

    comm = target.communication
    profile = _selected_profile(comm.profile)
    identity = monitor_source_identity(profile, comm.ecu)
    if not isinstance(comm.operations, NativeFrameController):
        raise MonitorError("Native DRS selected lower controller absent", 0xC0040601)
    operations = comm.operations.operations
    protocol: dict[str, tuple[DrsTable, ...]] = {}
    if trigger.trigger_type == 7:
        mode = selected_check_mode_plan(
            profile,
            bus_id=comm.bus_id,
            driver=operations.driver,
            diagnostic_mode=operations.diagnostic_mode,
        )
        protocol.update(
            diagnostic_setup=mode.diagnostic_setup,
            diagnostic_end=mode.diagnostic_end,
            change_mode=mode.change_mode,
            confirm_mode=mode.confirm_mode,
            sessions=mode.sessions,
        )
    cache = MonitorSupportCache(
        profile,
        comm,
        comm.ecu,
        stream=comm,
        bus_id=comm.bus_id,
        source_build=comm.source_build,
        limits=limits,
        clock=clock,
        cancelled=cancelled,
    )
    protocol["check_car"] = selected_car_info_plan(
        profile,
        cache,
        bus_id=comm.bus_id,
        driver=operations.driver,
        diagnostic_mode=operations.diagnostic_mode,
    )
    if cancelled():
        raise Cancelled("Native DRS outer caller cancelled")
    if monitor_source_identity(profile, comm.ecu) != identity:
        raise MonitorError("Native DRS outer selected source changed")
    return protocol


def selected_phase3_recording(
    target: LegacyRunTarget,
    selection: NativeVehicleSelection,
    system_information: dict,
    trigger: NativeTriggerInfo,
    parameters: NativeTriggerParameters,
    *,
    connected_device: int,
    enable_mode: int,
    init_mode: int | None,
    parameter_c0: int,
    shared_interface: int | None = None,
    disabled_packet_ecus: tuple[int, ...] | None = None,
    monitor_session: SelectedMonitorSession | None = None,
    phase: int = 0,
    limits: Limits | None = None,
    clock: Callable[[], float] = time.monotonic,
    cancelled: Callable[[], bool] = lambda: False,
) -> DrsFile:
    """Selected P3 87 writer groups11/12, without executing serialized DMCI.

    Support observations use the retained communication. Metadata and the native
    setup/start/stop/dispose commands are produced here, never supplied as an
    opaque plan. The outer Run87 writer fault/finish chronology remains separate.
    """
    from scripts.data_monitor import (
        SelectedMonitorSession,
        selected_legacy_check_target,
        selected_p4_connection,
    )
    from scripts.drive_recorder import (
        NativeDmciCommand,
        build_native_drs,
        native_monitor_buffer,
    )
    from scripts.monitor_support import monitor_source_identity
    from scripts.native_communication import NativeFrameController
    from scripts.support import word

    if not isinstance(target, LegacyRunTarget) or not target.selected_ids:
        raise MonitorError(
            "Native P3 DRS requires an allocated selected target", 0xC0050404
        )
    _uint(enable_mode, 65535, "Native recording enable mode")
    comm = target.communication
    profile = _selected_profile(comm.profile)
    identity = monitor_source_identity(profile, comm.ecu)
    if monitor_session is not None:
        if not isinstance(monitor_session, SelectedMonitorSession):
            raise MonitorError("Native P3 DRS session type rejected")
        monitor_session.check(profile, source_build=comm.source_build)
        shared_interface = monitor_session.shared_interface
        disabled_packet_ecus = monitor_session.disabled_packet_ecus
    if profile.category == 0x68:
        raise MonitorError("Native voltage setup failed", 0x90051205)
    if not isinstance(comm.operations, NativeFrameController):
        raise MonitorError("Native P3 DRS selected lower controller absent", 0xC0040601)
    connection = selected_p4_connection(
        profile,
        bus_id=comm.bus_id,
        diagnostic_mode=comm.operations.operations.diagnostic_mode,
        controller_category_flags=profile.category_record[72],
    )
    protocol = profile.protocol_info(comm.bus_id)
    if protocol is None:
        raise MonitorError("Native P3 DRS selected protocol absent", 0xC0050101)
    excluded = phase3_check_excluded(
        (profile.category,),
        command_kind=0x42,
        connected_device=connected_device,
        command_ecu=profile.category,
        shared_interface=shared_interface,
        disabled_packet_ecus=disabled_packet_ecus,
    ) | (~enable_mode & 65535)
    check = selected_legacy_check_target(
        comm,
        target.selected_ids,
        target.observed_functions,
        monitor_session=monitor_session,
    )
    plan = selected_phase3_from_exchange(
        profile,
        target.selected_ids,
        comm,
        comm.ecu,
        target.observed_functions,
        interface_id=connection.address.request_id,
        excluded=excluded,
        maximum_request=word(protocol, 14),
        maximum_reply=word(protocol, 16),
        parameter_8=0xFFFFFFFF,
        standard_values=target.standard_values,
        native_ecu=profile.category,
        packet_protocol=comm.bus_id,
        packet_cache=check.packet_cache,
        support_stream=comm,
        bus_id=comm.bus_id,
        source_build=comm.source_build,
        limits=limits or comm.limits,
        clock=clock,
        cancelled=cancelled,
    )
    lifecycle = phase3_interface_lifecycle(
        profile,
        plan,
        connection,
        connected_device=connected_device,
        init_mode=init_mode,
        parameter_c0=parameter_c0,
        recording=True,
    )
    monitor = native_monitor_buffer(
        profile.category,
        plan.signals,
        plan.frame_sizes,
        target.selected_ids,
        phase=phase,
        allocation_size=target.allocation_size,
        name=target.name,
        text_encoding=target.text_encoding,
    )
    result = build_native_drs(
        selection,
        system_information,
        replace(monitor, value_after_count=1),
        trigger,
        parameters,
        setup=tuple(
            NativeDmciCommand.from_neutral(command.command_id, command.values)
            for command in lifecycle.setup + lifecycle.start
        ),
        stop=tuple(
            NativeDmciCommand.from_neutral(command.command_id, command.values)
            for command in lifecycle.stop
        ),
        **_selected_recording_protocol(
            target,
            trigger,
            limits=limits or comm.limits,
            clock=clock,
            cancelled=cancelled,
        ),
    )
    if cancelled():
        raise Cancelled("Native P3 DRS cancelled")
    if monitor_source_identity(profile, comm.ecu) != identity:
        raise MonitorError("Native P3 DRS selected context changed")
    return result
