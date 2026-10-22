"""Native Dual monitor orchestration over primitive, injected driver operations.

The seven states follow the recovered 18dd0 switch, including the missing 1/2/3
entries. This module never opens a device or executes an OEM library.
"""

from __future__ import annotations

import math
import struct
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import IntEnum
from typing import Literal, Protocol, cast

from scripts.data_monitor import (
    MAX_BYTES,
    MAX_ITEMS,
    DynamicPlan,
    MonitorCommand,
    MonitorError,
    MonitorEvent,
    MonitorProvider,
    MonitorReceive,
    MonitorSetup,
    P5MonitorEvent,
    RoutineMonitor,
    clear_dynamic_requests,
    pickup_packet,
)
from scripts.drive_recorder import NativeDrsError, NativeMessage, RecorderBackend
from scripts.frame_transport import (
    DriverProperties,
    FramePlan,
    J2534Backend,
    J2534Result,
    NativeConfig,
    NativeFrameOperations,
    _HostClockError,
    translate_configs,
)
from scripts.frame_transport import (
    NativeMessage as J2534Message,
)
from scripts.monitor_support import monitor_source_identity
from scripts.profiles import ProtocolProfile, VehicleProfile
from scripts.support import word
from scripts.toyota_session import Cancelled, NativeFrameSend, NativeSend

SUCCESS = 0xE0000100
INVALID = 0xE0000102
CLEANUP_SECONDS = 2.0


def _uint(value: int, maximum: int = 0xFFFFFFFF) -> None:
    if type(value) is not int or not 0 <= value <= maximum:
        raise MonitorError("Native Dual integer is out of range", INVALID)


def _bytes(value: bytes, minimum: int = 1, maximum: int = 4096) -> None:
    if not isinstance(value, bytes) or not minimum <= len(value) <= maximum:
        raise MonitorError("Native Dual message length is invalid", INVALID)


def _number(value: object) -> int:
    if type(value) is not int:
        raise MonitorError("Native Dual setup integer is invalid")
    _uint(value)
    return value


def _message(value: object) -> bytes:
    if not isinstance(value, bytes):
        raise MonitorError("Native Dual setup request is invalid")
    _bytes(value)
    return value


def _pairs(value: object) -> tuple[tuple[int, int], ...]:
    if not isinstance(value, tuple) or len(value) > MAX_ITEMS:
        raise MonitorError("Native Dual setup pairs must be a bounded tuple")
    result = []
    for pair in value:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise MonitorError("Native Dual setup pair shape differs")
        result.append((_number(pair[0]), _number(pair[1])))
    return tuple(result)


def _words(value: object) -> tuple[int, ...]:
    if not isinstance(value, tuple) or len(value) > 65535:
        raise MonitorError("Native Dual setup status words must be bounded")
    result = []
    for row in value:
        if not isinstance(row, tuple) or len(row) != 1:
            raise MonitorError("Native Dual setup status word shape differs")
        number = _number(row[0])
        _uint(number, 65535)
        result.append(number)
    return tuple(result)


def _routine(values: tuple[object, ...]) -> RoutineMonitor:
    if len(values) != 10:
        raise MonitorError("Native Dual routine setup shape differs")
    return RoutineMonitor(
        _message(values[2]),
        _number(values[3]),
        _words(values[4]),
        _words(values[5]),
        _words(values[9]),
    )


def selected_dual_cache(
    profiles: Mapping[int, VehicleProfile], commands: Sequence[int] = (0xDD, 0xD1, 0xD2)
) -> dict[tuple[int, int], bytes]:
    """SendReceiveDualMon1a600 selects only the first cached native frame."""
    if not 1 <= len(profiles) <= 2 or len(commands) > MAX_ITEMS:
        raise MonitorError("Native Dual selected cache input exceeds budget")
    result = {}
    for request_id, profile in profiles.items():
        _uint(request_id)
        for command in commands:
            _uint(command, 65535)
            frames = profile.command_frames(command)
            if not frames:
                raise MonitorError("Selected native Dual command has no frame")
            request = frames[0].request
            _bytes(request)
            result[(request_id, command)] = request
    if sum(len(request) for request in result.values()) > MAX_BYTES:
        raise MonitorError("Native Dual selected cache exceeds byte budget")
    return result


class DualState(IntEnum):
    SELECT = 0
    SEND = 1
    RECEIVE = 2
    ERROR = 3
    STOPPED = 4
    START_OSC = 5
    OSC_ERROR = 6


@dataclass(frozen=True)
class DualTarget:
    """EntryCommSystemItem + literal IDMap fields; arg3 is never a period."""

    ecu: str
    request_id: int
    response_id: int
    protocol: int
    category_flags: int
    command_id: int
    retry_limit: int
    send_timeout: int = 1000
    receive_timeout: int = 200
    map_values: tuple[int, int, int] = (0, 0, 0)
    entry_parameter: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.ecu, str) or not self.ecu or len(self.ecu) > 4096:
            raise MonitorError("Native Dual target needs an ECU identity", INVALID)
        for value in (
            self.request_id,
            self.response_id,
            self.command_id,
            self.send_timeout,
            self.receive_timeout,
            self.retry_limit,
        ):
            _uint(value)
        _uint(self.protocol, 65535)
        _uint(self.category_flags, 255)
        if self.entry_parameter is not None:
            _uint(self.entry_parameter)
        if not isinstance(self.map_values, tuple) or len(self.map_values) != 3:
            raise MonitorError("Native Dual IDMap needs three raw fields", INVALID)
        for value in self.map_values:
            _uint(value)

    @property
    def phase5(self) -> bool:
        return self.category_flags & 31 == 20

    @property
    def receive_id(self) -> int:
        if self.protocol & 15 in (2, 8):
            kind = self.request_id & 0xC0000000
            if kind == 0x80000000:
                return self.response_id >> 8 & 0xFFF
            if kind != 0xC0000000:
                return self.response_id
        return self.response_id & 255


@dataclass(frozen=True)
class DualControl:
    operation: str
    arguments: tuple[int, ...]

    def __post_init__(self) -> None:
        sizes = {
            "ConnectDualMon": (0,),
            "ConnectMultiMon": (0,),
            "EntryCommSystemInfo": (3, 4),
            "Disconnect": (1,),
        }
        if (
            self.operation not in sizes
            or len(self.arguments) not in sizes[self.operation]
        ):
            raise MonitorError("Invalid native Dual driver control")
        for value in self.arguments:
            _uint(value)


DualControlProvider = Callable[[DualControl], int]


@dataclass(frozen=True)
class _DualPrimitiveOutcome:
    result: J2534Result


class NativeDualControl:
    """KGP Dual registration over an already initialized J2534 backend.

    The backend owns driver/module initialization. This object owns the actual
    channel, native per-target configuration and filters; no OEM code is loaded.
    Application build provenance is explicit and independent of DDB format.
    """

    def __init__(
        self,
        targets: Sequence[DualTarget],
        profiles: Mapping[str, ProtocolProfile],
        backend: RecorderBackend,
        *,
        driver: DriverProperties,
        source_build: int,
        source_identity: str,
        connected_device: int,
        diagnostic_mode: bytes,
        source_variant: Literal["dual", "multi"] = "dual",
        clock: Callable[[], float] = time.monotonic,
    ):
        if type(source_build) is not int or source_build not in (12, 18):
            raise MonitorError("Explicit native application source build required")
        if source_variant not in ("dual", "multi"):
            raise MonitorError("Explicit native monitor control variant required")
        self.source_variant = source_variant
        if (
            not isinstance(source_identity, str)
            or not 1 <= len(source_identity) <= 4096
        ):
            raise MonitorError("Native application source provenance required")
        _uint(connected_device)
        if not isinstance(driver, DriverProperties):
            raise MonitorError("Observed native driver properties required")
        if not isinstance(diagnostic_mode, bytes) or len(diagnostic_mode) != 16:
            raise MonitorError("Observed native16-byte diagnostic mode required")
        selected = tuple(targets)
        if not 1 <= len(selected) <= 2 or any(
            not isinstance(x, DualTarget) for x in selected
        ):
            raise MonitorError("Native Dual control requires typed targets")
        if len({x.command_id for x in selected}) != len(selected):
            raise MonitorError(
                "Native Dual control requires one or two distinct targets"
            )
        self.source_build, self.source_identity = source_build, source_identity
        self.driver, self.connected_device, self.diagnostic_mode = (
            driver,
            connected_device,
            diagnostic_mode,
        )
        self._source_policy = (
            source_build,
            source_identity,
            driver,
            connected_device,
            diagnostic_mode,
            source_variant,
        )
        self._sources = {}
        for target in selected:
            if target.ecu not in profiles or target.entry_parameter is None:
                raise MonitorError("Native Dual control lacks selected target metadata")
            profile = profiles[target.ecu]
            self._sources[target.command_id] = (
                profile,
                target.ecu,
                monitor_source_identity(profile, target.ecu),
            )
        self.selected = {}
        for target in selected:
            if target.ecu not in profiles or target.entry_parameter is None:
                raise MonitorError("Native Dual control lacks selected target metadata")
            profile = profiles[target.ecu]
            self._check_sources()
            if (
                profile.category != target.command_id
                or len(profile.category_record) != 76
                or profile.category_record[72] != target.category_flags
            ):
                raise MonitorError(
                    "Native Dual control target differs from selected ECU"
                )
            protocol = profile.protocol_info(target.protocol)
            self._check_sources()
            if protocol is None or len(protocol) not in (24, 28):
                raise MonitorError(
                    "Selected Dual protocol record is absent", 0x90020104
                )
            rows = profile.comm_info_can_records(word(protocol, 2))
            self._check_sources()
            if not rows or len(rows[0]) != 28:
                raise MonitorError("Selected Dual CAN record is absent", 0x90020104)
            can = rows[0]
            if not target.phase5 or source_variant == "multi":
                try:
                    tester = profile.command_frames(0x7F)
                except ValueError as exc:
                    raise MonitorError(
                        "Selected Dual tester frame is absent", 0x90020502
                    ) from exc
                self._check_sources()
                if not tester:
                    raise MonitorError(
                        "Selected Dual tester frame is absent", 0x90020502
                    )
            raw = (
                (1, int.from_bytes(can[4:8], "little")),
                (0x10100, 8),
                (0x10102, 0xE0),
                (0x10101, 0x1F),
                (0x10103, int.from_bytes(can[:4], "little")),
                (0x10105, word(can, 16 if source_build == 12 else 18)),
                (0x10206, 0),
                (0x10106, word(can, 12)),
                (0x2A, word(can, 20 if source_build == 12 else 22)),
            )
            configs = tuple(
                (item.parameter, item.value) for item in translate_configs(raw, driver)
            )
            self.selected[target.command_id] = (target, profile, protocol, can, configs)
        self.backend, self.driver, self.clock = backend, driver, clock
        self.source_build, self.source_identity = source_build, source_identity
        self.connected_device, self.diagnostic_mode = connected_device, diagnostic_mode
        self.channel: int | None = None
        self.filter_handles: list[int] = []
        self.poisoned = False
        self.current_service = 0
        self.previous_service = 0
        self.request_state = 0
        self.previous_request_state = 0
        self.preinit_d1_suppressed = 1
        self._lower: NativeFrameOperations | None = None
        self.channel_generation = 0
        self.registered: list[int] = []
        self.configs: dict[int, tuple[tuple[int, int], ...]] = {}
        self.last_target: int | None = None
        self.refresh_configs = False
        self.optional_config = True
        self.observations: deque[tuple[str, int]] = deque(maxlen=MAX_ITEMS)
        self._calls = 0

    def _check_sources(self) -> None:
        if self._source_policy != (
            self.source_build,
            self.source_identity,
            self.driver,
            self.connected_device,
            self.diagnostic_mode,
            self.source_variant,
        ):
            raise MonitorError("Native Dual source context changed")
        for profile, ecu, identity in self._sources.values():
            if monitor_source_identity(profile, ecu) != identity:
                raise MonitorError("Native Dual selected source identity changed")

    def _guard(
        self, deadline: float, cancelled: Callable[[], bool], *, release: bool = False
    ) -> None:
        if not release:
            self._check_sources()
        stopped = cancelled()
        if not release:
            self._check_sources()
        if stopped:
            if isinstance(self.backend, NativeDualPrimitives):
                NativeFrameOperations._raise_host_boundary("cancelled_before")
            raise Cancelled("Native Dual control cancelled")
        now = self.clock()
        if not release:
            self._check_sources()
        if not math.isfinite(now) or not math.isfinite(deadline):
            if isinstance(self.backend, NativeDualPrimitives):
                raise _HostClockError("Native Dual control clock is not finite")
            raise MonitorError("Native Dual control deadline exceeded")
        if now >= deadline:
            if isinstance(self.backend, NativeDualPrimitives):
                NativeFrameOperations._raise_host_boundary("deadline_before")
            raise MonitorError("Native Dual control deadline exceeded")

    def check_context(self, *, deadline: float, cancelled: Callable[[], bool]) -> None:
        self._guard(deadline, cancelled)

    def check_source_context(self) -> None:
        self._check_sources()

    def _call(
        self,
        operation: str,
        fields: Mapping[str, object],
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> object:
        release = operation == "disconnect"
        if self.poisoned and not release:
            raise MonitorError(
                "Native Dual uncertain I/O permits resource cleanup only"
            )
        self._guard(deadline, cancelled, release=release)
        if self._calls >= 256:
            raise MonitorError("Native Dual control operation budget exceeded")
        self._calls += 1
        try:
            result = self.backend.invoke(
                operation, fields, deadline=deadline, cancelled=cancelled
            )
        except NativeDrsError:
            raise
        except BaseException:
            self.poisoned = True
            raise
        if isinstance(result, _DualPrimitiveOutcome):
            outcome = result.result
            if outcome.host_boundary is not None and outcome.host_boundary.endswith(
                "_before"
            ):
                NativeFrameOperations._raise_host_boundary(outcome.host_boundary)
            # Driver ownership is already real even if the host stopped afterwards.
            if operation == "connect" and outcome.handle is not None:
                self.channel = outcome.handle
                self.channel_generation += 1
            elif operation == "disconnect" and not outcome.code:
                self.channel = None
                self.filter_handles.clear()
                self.registered.clear()
                self.last_target = None
            elif operation == "start_message_filter" and outcome.handle is not None:
                self.filter_handles.append(outcome.handle)
            if not outcome.code and (
                (
                    operation in ("connect", "start_message_filter")
                    and outcome.handle is None
                )
                or (operation == "write" and outcome.count != 1)
                or (
                    operation == "read"
                    and (outcome.count != 1 or len(outcome.messages) != 1)
                )
            ):
                self.poisoned = True
            if outcome.host_boundary is not None:
                NativeFrameOperations._raise_host_boundary(outcome.host_boundary)
            if outcome.code:
                raise NativeDrsError(outcome.code)
            if operation in ("connect", "start_message_filter"):
                if outcome.handle is None:
                    self.poisoned = True
                    raise MonitorError(
                        "Native Dual primitive omitted its actual handle"
                    )
                result = outcome.handle
            elif operation == "write":
                if outcome.count != 1:
                    self.poisoned = True
                    raise MonitorError("Native Dual write did not confirm one message")
                result = None
            elif operation == "read":
                if outcome.count != 1 or len(outcome.messages) != 1:
                    self.poisoned = True
                    raise MonitorError("Native Dual read did not return one message")
                result = NativeMessage.parse(outcome.messages[0].encode())
            else:
                result = None
            self._guard(deadline, cancelled, release=release)
            self.observations.append((operation, 0))
            return result
        if operation == "connect":
            if type(result) is not int:
                raise MonitorError("Native Dual connect requires actual channel ID")
            _uint(result)
            self.channel = result
            self.channel_generation += 1
        elif operation == "disconnect":
            self.channel = None
        elif operation == "read" and not isinstance(result, NativeMessage):
            raise MonitorError("Native Dual read requires an actual native message")
        self._guard(deadline, cancelled, release=release)
        self.observations.append((operation, 0))
        return result

    def _status(
        self,
        operation: str,
        fields: Mapping[str, object],
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> int:
        try:
            self._call(operation, fields, deadline, cancelled)
        except NativeDrsError as exc:
            self._guard(deadline, cancelled, release=operation == "disconnect")
            code = exc.code | 0x91010000
            self.observations.append((operation, code))
            return code
        return 0

    @staticmethod
    def _message(data: bytes, flags: int = 0) -> NativeMessage:
        return NativeMessage(6, 0, flags, 0, 0, data)

    def _filter(
        self,
        kind: int,
        mask: bytes,
        pattern: bytes,
        flow: bytes,
        deadline: float,
        cancelled: Callable[[], bool],
        flags: int = 0,
    ) -> int:
        return self._status(
            "start_message_filter",
            {
                "channel_id": self.channel,
                "filter_type": kind,
                "messages": tuple(
                    self._message(data, flags) for data in (mask, pattern, flow)
                ),
            },
            deadline,
            cancelled,
        )

    def __call__(self, call: DualControl) -> int:
        if call.operation != "Disconnect":
            self._check_sources()
        now = self.clock()
        if call.operation != "Disconnect":
            self._check_sources()
        return self.execute(
            call, deadline=now + CLEANUP_SECONDS, cancelled=lambda: False
        )

    def execute(
        self, call: DualControl, *, deadline: float, cancelled: Callable[[], bool]
    ) -> int:
        self._calls = 0
        if call.operation == "Disconnect":
            self._guard(deadline, cancelled, release=True)
            if call.arguments[0] not in (0, 1):
                raise MonitorError("Native Dual supports Disconnect(0/1)")
            status = self._disconnect(
                deadline, cancelled, disconnect_flag=call.arguments[0]
            )
            if status:
                raise MonitorError("Native Dual channel release failed", status)
            return 0
        self._guard(deadline, cancelled)
        if call.operation in ("ConnectDualMon", "ConnectMultiMon"):
            if call.operation != (
                "ConnectDualMon" if self.source_variant == "dual" else "ConnectMultiMon"
            ):
                raise MonitorError("Native monitor connect variant differs")
            self._disconnect(deadline, cancelled)
            if self.channel is not None:
                raise MonitorError("Native Dual previous channel release failed")
            self.registered.clear()
            self.configs.clear()
            self.last_target = None
            self.refresh_configs, self.optional_config = False, True
            self.poisoned = False
            self.current_service = self.previous_service = 0
            self.request_state = self.previous_request_state = 0
            self.preinit_d1_suppressed = 1
            return self._status(
                "connect", {"protocol_id": 6, "flags": 0}, deadline, cancelled
            )
        expected_size = 4 if self.source_variant == "dual" else 3
        if len(call.arguments) != expected_size:
            raise MonitorError("Native monitor registration ABI differs")
        key, protocol, parameter = call.arguments[:3]
        if key not in self.selected:
            raise MonitorError("Native Dual entry lacks selected metadata")
        target = self.selected[key][0]
        if (protocol, parameter) != (
            target.protocol,
            target.entry_parameter,
        ):
            raise MonitorError("Native Dual entry differs from selected target")
        if self.source_variant == "dual" and call.arguments[3] != target.category_flags:
            raise MonitorError("Native Dual entry phase differs from selected target")
        if self.channel is None:
            return 0x90020701
        if key in self.registered or len(self.registered) == 2:
            return 0x90020701
        index = len(self.registered)
        return self._configure_target(key, index, deadline, cancelled)

    def _configure_target(
        self, key: int, index: int, deadline: float, cancelled: Callable[[], bool]
    ) -> int:
        target, _, prot, can, configs = self.selected[key]
        protocol = target.protocol
        configs = configs if self.optional_config else configs[:-1]
        if not index:
            status = self._status(
                "set_config",
                {"channel_id": self.channel, "parameters": configs},
                deadline,
                cancelled,
            )
            if status:
                self.optional_config = False
                configs = configs[:-1]
                status = self._status(
                    "set_config",
                    {"channel_id": self.channel, "parameters": configs},
                    deadline,
                    cancelled,
                )
                if status:
                    self.close_resources(deadline=deadline, cancelled=cancelled)
                    return status
        else:
            first = self.configs[self.registered[0]]
            self.refresh_configs = any(
                value != dict(configs).get(parameter)
                for parameter, value in first
                if parameter < 0x10000 or parameter == 0x10103
            )
        self.configs[key] = configs
        if key not in self.registered:
            self.registered.append(key)
        if not index:
            offset = 18 if self.source_build == 12 else 20
            parameter = word(can, offset)
            enabled = can[24 if self.source_build == 12 else 26]
            if (
                protocol & 15 == 2
                and enabled
                and (parameter <= 255 or parameter == 65535)
            ):
                self._status(
                    "set_config",
                    {"channel_id": self.channel, "parameters": ((0x23, parameter),)},
                    deadline,
                    cancelled,
                )
        if (
            self.source_variant == "multi"
            and protocol & 0xF0 not in (0x10, 0x20, 0x30)
            and protocol not in (0x4A, 0x5A)
        ):
            return 0
        if self.source_variant == "multi" and (
            protocol in (0x1A, 0x4A, 0x5A) or protocol & 0xF0 == 0x30
        ):
            if self._lower is None:
                raise MonitorError(
                    "Native Multi filter setup requires its selected lower context"
                )
            status = 0
            for item in self._lower._can_filters(bus_id=protocol, protocol_record=prot):
                status = self._status(
                    "start_message_filter",
                    {
                        "channel_id": self.channel,
                        "filter_type": item.filter_type,
                        "messages": tuple(
                            NativeMessage.parse(message.encode())
                            for message in (item.mask, item.pattern, item.flow_control)
                        ),
                    },
                    deadline,
                    cancelled,
                )
                if status:
                    break
            # Native d9b0 ignores ordinary filter status, like b2f0.
            return 0
        address = word(prot, 8)
        if self.connected_device == 4:
            status = self._filter(
                1,
                (0x7FF).to_bytes(4, "big"),
                (address | 8).to_bytes(4, "big"),
                b"",
                deadline,
                cancelled,
            )
        else:
            status = 0
        if not status:
            status = (
                0x9101000A
                if protocol == 0x22 and not word(self.diagnostic_mode, 0)
                else self._filter(
                    3,
                    bytes.fromhex("ffffffff"),
                    (address | 8).to_bytes(4, "big"),
                    address.to_bytes(4, "big"),
                    deadline,
                    cancelled,
                )
            )
        if status and protocol == 0x22:
            address = address & 0xFFFF
            suffix = bytes((word(prot, 10) & 255,))
            status = self._filter(
                3,
                b"\xff" * 5,
                b"\0\0" + (address | 8).to_bytes(2, "big") + suffix,
                b"\0\0" + (address & ~8).to_bytes(2, "big") + suffix,
                deadline,
                cancelled,
                0xC0,
            )
        elif status:
            status = 0  # Native b2f0 ignores ordinary c7a0 filter failure.
        if status:
            self.close_resources(deadline=deadline, cancelled=cancelled)
        return status

    def before_send(
        self, target: DualTarget, *, deadline: float, cancelled: Callable[[], bool]
    ) -> int:
        self._calls = 0
        self._guard(deadline, cancelled)
        if self.channel is None or target.command_id not in self.registered:
            return 0x90020701
        self.last_target = target.command_id
        if self.refresh_configs:
            return self._status(
                "set_config",
                {
                    "channel_id": self.channel,
                    "parameters": self.configs[target.command_id],
                },
                deadline,
                cancelled,
            )
        return 0

    def _disconnect(
        self,
        deadline: float,
        cancelled: Callable[[], bool],
        *,
        disconnect_flag: int = 0,
    ) -> int:
        if self.channel is None:
            return 0
        primary: Exception | None = None
        try:
            self._check_sources()
            if self.last_target is not None and not self.poisoned:
                target, profile, prot, can, _ = self.selected[self.last_target]
                if target.category_flags & 31 in (20, 21):
                    if disconnect_flag != 1 and (
                        self.source_build == 12 or self.source_variant == "dual"
                    ):
                        self.preinit_d1_suppressed = 1
                        if self._lower is not None:
                            self._lower.set_preinit_d1_suppressed(1)
                    current = (
                        self.current_service
                        if self._lower is None
                        else self._lower.current_service
                    )
                    compatible = current >= 0x10 and not (
                        self.source_build == 18 and self.source_variant == "multi"
                    )
                    if not compatible:
                        self.previous_service, self.current_service = current, 0x10
                        if self._lower is not None:
                            self._lower.set_service_context(0x10)
                        if self.source_build == 18:
                            self.previous_request_state, self.request_state = (
                                self.request_state,
                                1,
                            )
                            if self._lower is not None:
                                (
                                    self._lower.previous_request_state,
                                    self._lower.request_state,
                                ) = self._lower.request_state, 1
                        key = self.last_target
                        status = self._configure_target(
                            key, self.registered.index(key), deadline, cancelled
                        )
                        if status:
                            primary = MonitorError(
                                "Native monitor close session setup failed", status
                            )
                if self._lower is not None and self.channel is not None:
                    self._lower.cancelled = cancelled
                    self._lower.pre_initialize(deadline=deadline)
                    self._check_sources()
                    self._lower.finish_bus_session(deadline=deadline)
                    self._check_sources()
                elif (
                    self.source_variant == "dual"
                    and not self.preinit_d1_suppressed
                    and self.channel is not None
                ):
                    try:
                        rows = profile.command_frames(0xD1)
                    except ValueError:
                        rows = ()  # Native c810 metadata error is ignored by01900.
                    self._check_sources()
                    if rows:
                        request = rows[0].request
                        _bytes(request, 1, 255)
                        high = target.protocol & 0xF0
                        address = word(prot, 6 if high == 0x30 else 8)
                        header = address.to_bytes(4, "big")
                        if high == 0x20:
                            header += bytes((word(prot, 10) & 255,))
                        message = self._message(
                            header + request, 0 if target.protocol & 15 == 10 else 0x40
                        )
                        self._status(
                            "write",
                            {
                                "channel_id": self.channel,
                                "timeout": min(
                                    1000, max(0, int((deadline - self.clock()) * 1000))
                                ),
                                "message": message,
                            },
                            deadline,
                            cancelled,
                        )
                        self._status(
                            "read",
                            {
                                "channel_id": self.channel,
                                "timeout": min(
                                    word(can, 12),
                                    max(0, int((deadline - self.clock()) * 1000)),
                                ),
                                "maximum": 0x78,
                            },
                            deadline,
                            cancelled,
                        )
                    else:
                        self.observations.append(
                            ("disconnect-default-session", 0x90020104)
                        )
        except Exception as exc:  # noqa: BLE001 - disconnect must retain primary failure
            if self._lower is not None:
                self.poisoned |= self._lower.poisoned
            primary = exc
        try:
            status = self.close_resources(deadline=deadline, cancelled=cancelled)
        except Exception as release:
            if primary is not None:
                primary.add_note(
                    f"Native Dual channel disconnect also failed: {release}"
                )
                raise primary from release
            raise
        if self.channel is None:
            self.registered.clear()
            self.last_target = None
        if primary is None:
            self._check_sources()
        if primary is not None:
            raise primary
        return status

    def close_resources(self, *, deadline: float, cancelled: Callable[[], bool]) -> int:
        """Release the actual channel without protocol traffic after uncertain I/O."""
        if self.channel is None:
            return 0
        self._calls = 0
        status = self._status(
            "disconnect", {"channel_id": self.channel}, deadline, cancelled
        )
        if self.channel is None:
            self.filter_handles.clear()
            self.registered.clear()
            self.last_target = None
        return status


class NativeDualPrimitives:
    """Expose Dual control over the same typed J2534 primitives as lower frames."""

    def __init__(self, backend: J2534Backend):
        self.backend = backend

    def invoke(
        self,
        operation: str,
        fields: Mapping[str, object],
        *,
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> object:
        native_operation: Literal[
            "connect",
            "disconnect",
            "ioctl",
            "start_message_filter",
            "write_messages",
            "read_messages",
        ]
        native_fields = dict(fields)
        if operation == "connect":
            native_operation = "connect"
            # Native Open(6,0,0): zero selects standard Connect, not a line baud.
            native_fields["baud_rate"] = 0
        elif operation == "set_config":
            native_operation = "ioctl"
            pairs = cast(tuple[tuple[int, int], ...], fields["parameters"])
            native_fields = {
                "channel_id": fields["channel_id"],
                "ioctl_id": 2,
                "input": tuple(NativeConfig(key, value) for key, value in pairs),
                "output_capacity": 0,
            }
        elif operation == "start_message_filter":
            native_operation = "start_message_filter"
            messages = cast(tuple[NativeMessage, ...], fields["messages"])
            if len(messages) != 3 or any(
                not isinstance(x, NativeMessage) for x in messages
            ):
                raise MonitorError("Native Dual filter requires three typed messages")
            native_fields = {
                "channel_id": fields["channel_id"],
                "filter_type": fields["filter_type"],
                "mask": J2534Message.decode(messages[0].encode()),
                "pattern": J2534Message.decode(messages[1].encode()),
                "flow_control": J2534Message.decode(messages[2].encode())
                if fields["filter_type"] == 3
                else None,
            }
        elif operation == "write":
            native_operation = "write_messages"
            native_fields = {
                "channel_id": fields["channel_id"],
                "timeout": fields["timeout"],
                "count": 1,
                "messages": (
                    J2534Message.decode(
                        cast(NativeMessage, fields["message"]).encode()
                    ),
                ),
            }
        elif operation == "read":
            native_operation = "read_messages"
            native_fields = {
                "channel_id": fields["channel_id"],
                "timeout": fields["timeout"],
                "count": 1,
            }
        elif operation == "disconnect":
            native_operation = "disconnect"
        else:
            raise MonitorError("Unsupported native Dual control primitive")
        result = self.backend.invoke(
            native_operation,
            native_fields,
            deadline=deadline,
            cancelled=cancelled,
        )
        if not isinstance(result, J2534Result):
            raise MonitorError("Native Dual primitive requires typed J2534 output")
        return _DualPrimitiveOutcome(result)


class NativeDualTransport:
    """Concrete seven-ABI/ReceiveExt join borrowing the Dual control channel."""

    def __init__(
        self,
        control: NativeDualControl,
        operations: NativeFrameOperations,
        plans: Mapping[str, FramePlan],
    ):
        if (
            not isinstance(control, NativeDualControl)
            or not isinstance(operations, NativeFrameOperations)
            or not isinstance(control.backend, NativeDualPrimitives)
            or operations.backend is not control.backend.backend
            or operations.native_variant != control.source_variant
            or operations.native_build != control.source_build
            or operations.driver != control.driver
            or operations.device_kind != control.connected_device
            or operations.diagnostic_mode != control.diagnostic_mode
            or operations.channel is not None
            or operations.owns_channel
            or control._lower is not None
        ):
            raise MonitorError("Native Dual lower transport/control contexts differ")
        self.control, self.operations = control, operations
        self.plans = dict(plans)
        if set(self.plans) != {row[0].ecu for row in control.selected.values()} or any(
            not isinstance(plan, FramePlan) for plan in self.plans.values()
        ):
            raise MonitorError(
                "Native Dual requires selected frame plans for every target"
            )
        self._policy = (
            operations.native_build,
            operations.native_variant,
            operations.driver,
            operations.device_kind,
            operations.diagnostic_mode,
            operations.backend,
        )
        self._plans = dict(self.plans)
        self._current_ecu: str | None = None
        self._channel: int | None = None
        self._generation: int | None = None
        control.check_source_context()
        control._lower = operations

    def _bind(
        self, target: DualTarget, deadline: float, cancelled: Callable[[], bool]
    ) -> None:
        control, operations = self.control, self.operations
        if control._lower is not operations:
            control.poisoned = True
            raise MonitorError("Native Dual lower owner changed")
        control.check_context(deadline=deadline, cancelled=cancelled)
        if (
            self._policy
            != (
                operations.native_build,
                operations.native_variant,
                operations.driver,
                operations.device_kind,
                operations.diagnostic_mode,
                operations.backend,
            )
            or self.plans != self._plans
        ):
            control.poisoned = True
            raise MonitorError("Native Dual lower transport policy changed")
        selected, profile, _, _, _ = control.selected[target.command_id]
        if selected != target or self.plans.get(target.ecu) is None:
            raise MonitorError(
                "Native Dual lower target differs from registered metadata"
            )
        if control.channel is None:
            raise MonitorError("Native Dual lower transport has no control channel")
        if self._generation != control.channel_generation:
            # ConnectDualMon released the previous channel, even if its ID is reused.
            operations.channel = None
            operations.filter_handles.clear()
            operations.reset_released_runtime()
            operations.adopt_channel(control.channel, owned=False, configured=True)
            self._channel = control.channel
            self._generation = control.channel_generation
            self._current_ecu = None
            operations.last_activity = 0
        if (
            self._channel != control.channel
            or operations.channel != control.channel
            or operations.owns_channel
        ):
            control.poisoned = True
            raise MonitorError("Native Dual borrowed channel lease changed")
        if self._current_ecu != target.ecu:
            operations.rebind(profile, self.plans[target.ecu], bus_id=target.protocol)
            self._current_ecu = target.ecu
        if monitor_source_identity(
            operations.profile, target.ecu
        ) != monitor_source_identity(profile, target.ecu):
            raise MonitorError("Native Dual lower selected source differs")
        control.check_context(deadline=deadline, cancelled=cancelled)
        self._check_bound(target)

    def _check_bound(self, target: DualTarget) -> None:
        operations, control = self.operations, self.control
        if control._lower is not operations:
            control.poisoned = True
            raise MonitorError("Native Dual lower owner changed during a callback")
        if (
            self._policy
            != (
                operations.native_build,
                operations.native_variant,
                operations.driver,
                operations.device_kind,
                operations.diagnostic_mode,
                operations.backend,
            )
            or self.plans != self._plans
            or self._generation != control.channel_generation
            or self._channel != control.channel
            or operations.channel != control.channel
            or operations.owns_channel
            or operations.plan != self.plans[target.ecu]
            or operations.bus_id != target.protocol
            or monitor_source_identity(operations.profile, target.ecu)
            != monitor_source_identity(
                control.selected[target.command_id][1], target.ecu
            )
        ):
            control.poisoned = True
            raise MonitorError("Native Dual lower binding changed during a callback")

    def released(self) -> None:
        """A completed control disconnect has already released channel filters."""
        if self.control.channel is None:
            self.operations.channel = None
            self.operations.filter_handles.clear()
            self._channel = self._current_ecu = self._generation = None

    def send_frame(
        self,
        target: DualTarget,
        call: NativeFrameSend,
        *,
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> int:
        if (call.command_id, call.parameter5) != (target.command_id, target.protocol):
            raise MonitorError("Native Dual seven-ABI target context differs")
        if call.operation not in ("SendIntExtDualMon", "SendIntNoInitNoSession"):
            raise MonitorError("Native Dual lower operation differs")
        if (
            self.control.source_build == 12
            and call.operation == "SendIntNoInitNoSession"
            and call.request is not None
            and len(call.request) > 255
        ):
            raise MonitorError("Native12 NoInitNoSession request exceeds BYTE length")
        self._bind(target, deadline, cancelled)
        operations = self.operations
        operations.cancelled = cancelled
        try:
            code = operations.send(
                call.request,
                timeout=call.parameter4,
                initialization_mode=2,
                clear_rx=call.parameter7,
                no_session=call.operation == "SendIntNoInitNoSession",
                deadline=deadline,
            )
        except BaseException:
            self.control.poisoned |= operations.poisoned
            raise
        self.control.check_context(deadline=deadline, cancelled=cancelled)
        self._check_bound(target)
        return code

    def receive_frame(
        self,
        target: DualTarget,
        *,
        deadline: float,
        cancelled: Callable[[], bool],
        buffer: bool,
        maximum: int,
        timeout: int,
        argument_5: int,
        flags: int,
    ) -> MonitorReceive:
        self._bind(target, deadline, cancelled)
        self.operations.cancelled = cancelled
        try:
            result = self.operations.receive(
                buffer=buffer,
                maximum=maximum,
                timeout=timeout,
                argument_5=argument_5,
                flags=flags,
                deadline=deadline,
            )
        except BaseException:
            self.control.poisoned |= self.operations.poisoned
            raise
        self.control.check_context(deadline=deadline, cancelled=cancelled)
        self._check_bound(target)
        return MonitorReceive(result.data, result.source_id, result.code)

    def send(self, ecu, request, *, timeout, protocol, initialize):
        raise MonitorError(
            "Native Dual lower transport requires seven-ABI runtime context"
        )

    def receive(self, ecu, *, buffer, maximum, timeout, argument_5, flags):
        raise MonitorError(
            "Native Dual lower transport requires runtime deadline context"
        )


@dataclass(frozen=True)
class DualPacket:
    target_id: int
    ecu: str
    timestamp_raw: int
    payload: bytes

    def __post_init__(self) -> None:
        _uint(self.target_id)
        _uint(self.timestamp_raw)
        if not isinstance(self.ecu, str) or not self.ecu:
            raise MonitorError("Native Dual packet needs an ECU identity")
        _bytes(self.payload, 0, MAX_BYTES)

    @property
    def native_bytes(self) -> bytes:
        """DatMonCommon ring element: little-endian DWORD followed by payload."""
        return self.timestamp_raw.to_bytes(4, "little") + self.payload


@dataclass(frozen=True)
class DualFault:
    target_id: int
    slot: int
    code: int
    detail: int
    provider_code: int


@dataclass(frozen=True)
class DualAuxExchange:
    target_id: int
    request: bytes
    received: MonitorReceive


@dataclass(frozen=True)
class DualNotice:
    target_id: int
    kind: str
    data: bytes


class DualRing:
    """Bounded per-target packet storage; overflow is a native buffer failure."""

    def __init__(self, maximum: int = MAX_BYTES):
        _uint(maximum, MAX_BYTES)
        if maximum < 4:
            raise MonitorError("Native Dual ring must hold a timestamp")
        self.maximum = maximum
        self.size = 0
        self._packets: deque[DualPacket] = deque()

    def append(self, packet: DualPacket) -> None:
        size = len(packet.payload) + 4
        if size > self.maximum - self.size or len(self._packets) >= MAX_ITEMS:
            raise MonitorError("Native Dual ring is full", 0xE0000101)
        self._packets.append(packet)
        self.size += size

    def drain(self) -> tuple[DualPacket, ...]:
        result = tuple(self._packets)
        self._packets.clear()
        self.size = 0
        return result


@dataclass(frozen=True)
class OscRead:
    data: bytes
    timestamp_raw: int
    remaining: int
    code: int = 0

    def __post_init__(self) -> None:
        _bytes(self.data, 0, 0x1068)
        if len(self.data) % 4:
            raise MonitorError("Native oscilloscope samples require four-byte words")
        for value in (self.timestamp_raw, self.remaining, self.code):
            _uint(value)


class OscProvider(Protocol):
    def command(self, command: int) -> int: ...

    def set_parameter(self, parameter: int, data: bytes) -> int: ...

    def read_buffer(self, maximum: int) -> OscRead: ...


def osc_sampling_increment(mode: int) -> int:
    """Literal1a980 SetSamplingRate switch; native units remain unnamed."""
    _uint(mode, 255)
    return {
        1: 62500000,
        2: 0x1DCD650,
        3: 0xEE6B28,
        4: 0x5F5E10,
        5: 0x2FAF08,
        6: 0x17D784,
        8: 0x4A817,
        9: 0x2540B,
        10: 0xEE6B,
        11: 0x7735,
        12: 0x3B9A,
        13: 0x17D7,
        14: 0xBEB,
        15: 0x5F5,
        16: 0x254,
        17: 0x12A,
        18: 0x95,
        19: 0x3B,
        20: 0x1D,
        21: 0xE,
    }.get(mode, 0x9502F)


@dataclass(frozen=True)
class OscSetup:
    parameter_9: bytes
    parameter_10_start: bytes
    parameter_6: bytes
    parameter_8: bytes
    parameter_10_stop: bytes

    def __post_init__(self) -> None:
        for data, size in (
            (self.parameter_9, 8),
            (self.parameter_10_start, 4),
            (self.parameter_6, 4),
            (self.parameter_8, 1),
            (self.parameter_10_stop, 4),
        ):
            _bytes(data, size, size)

    @property
    def sample_increment(self) -> int:
        return osc_sampling_increment(self.parameter_10_start[0])


@dataclass
class _Command:
    request: bytes
    delay: int
    state: int = 0
    due: int = 0


class DualActiveEvent:
    """Concrete P4/P5 active-test linked-item queue, not a producer callback."""

    def __init__(self, phase5: bool):
        if type(phase5) is not bool:
            raise MonitorError("Native Dual active-test phase must be explicit")
        self.phase5 = phase5
        self.items: deque[_Command] = deque()
        self.stop_items: list[_Command] = []
        self.last_time = 0
        self._item_bytes = self._stop_bytes = 0

    @property
    def current(self) -> _Command | None:
        return self.items[0] if self.items else None

    def p4_start(self, body: bytes, delay: int = 0) -> None:
        if self.phase5:
            raise MonitorError("P4 active-test cannot target a P5 event")
        _bytes(body, 0, 4095)
        _uint(delay, 65535)
        self._append(_Command(b"\x30" + body, delay))

    def p5_start(self, body: bytes, stop_body: bytes, *, delay: int, kind: int) -> None:
        if not self.phase5:
            raise MonitorError("P5 active-test cannot target a P4 event")
        _uint(kind, 1)
        minimum = 3
        _bytes(body, minimum, 4095)
        _bytes(stop_body, minimum, 4095)
        _uint(delay, 65535)
        service = b"\x2f" if kind == 0 else b"\x31"
        start = _Command(service + body, delay)
        request = service + stop_body
        identity = request[1:3] if kind == 0 else request[2:4]
        for item in self.stop_items:
            same_kind = item.request[0] == request[0]
            other = item.request[1:3] if kind == 0 else item.request[2:4]
            if same_kind and identity == other:
                self._append(start)
                return
            if kind == 0 and same_kind and (delay or any(x.delay for x in self.items)):
                raise MonitorError(
                    "Native P5 mixed timed IO control is invalid", INVALID
                )
        if (
            len(self.stop_items) >= MAX_ITEMS
            or self._item_bytes + self._stop_bytes + len(start.request) + len(request)
            > MAX_BYTES
        ):
            raise MonitorError("Native Dual active stop queue exceeds budget")
        self._append(start)
        self.stop_items.append(_Command(request, 0))
        self._stop_bytes += len(request)

    def _append(self, item: _Command) -> None:
        if (
            len(self.items) >= MAX_ITEMS
            or self._item_bytes + self._stop_bytes + len(item.request) > MAX_BYTES
        ):
            raise MonitorError("Native Dual active queue exceeds budget")
        self.items.append(item)
        self._item_bytes += len(item.request)

    def stop(self) -> None:
        if self.phase5:
            if self.stop_items:
                self.items.clear()
                self._item_bytes = 0
            stops = tuple(self.stop_items)
            self.stop_items.clear()
            self._stop_bytes = 0
            for item in stops:
                self._append(_Command(item.request, 0))
        elif self.items:
            self._append(_Command(b"\x30", 0))

    def advance(self) -> None:
        item = self.current
        if item is not None and item.state not in (0, 1, 2) and len(self.items) > 1:
            self._item_bytes -= len(self.items.popleft().request)

    @property
    def send_info(self) -> int:
        item = self.current
        if item is None:
            return 0
        request = item.request
        if not self.phase5:
            return 0
        if request[0] == 0x2F:
            return 2 if request[3] == 3 else 3
        return 4 if request[1] == 1 else 5

    def accept(self, reply: bytes, tick: int) -> None:
        _bytes(reply)
        item = self.current
        if item is None:
            raise MonitorError("Native active-test queue is empty", INVALID)
        if not self.phase5:
            if reply[0] != 0x70:
                raise MonitorError("Native P4 active-test reply differs", INVALID)
            if len(reply) == 1:
                item.state, item.due = 5, 0
            elif len(reply) == 2:
                item.state = 3 if item.delay else 4
                item.due = (tick + item.delay) & 0xFFFFFFFF if item.delay else 0
            elif len(reply) == 3:
                raise MonitorError("Native P4 active-test reports error", 0xE00001CC)
            return
        if item.request[0] == 0x2F:
            if reply[0] != 0x6F or len(reply) < 3:
                raise MonitorError("Native P5 IO reply differs", INVALID)
            parameter = item.request[3]
            if parameter == 0:
                item.state, item.due = (4 if len(self.items) > 1 else 5), 0
            elif parameter == 3:
                item.state = 3 if item.delay else 4
                item.due = (tick + item.delay) & 0xFFFFFFFF if item.delay else 0
        else:
            if reply[0] != 0x71:
                raise MonitorError("Native P5 routine reply differs", INVALID)
            parameter = item.request[1]
            if parameter == 1:
                item.state, item.due = 4, 0
            elif parameter == 2:
                item.state, item.due = (4 if len(self.items) > 1 else 5), 0
        self.last_time = tick


@dataclass
class _TargetRuntime:
    target: DualTarget
    event: MonitorEvent | None = None
    setup: MonitorSetup | None = None
    clear_ids: tuple[int, ...] | None = None
    clear_requests: tuple[bytes, ...] = ()
    define_requests: tuple[bytes, ...] = ()
    last_time: int = 0
    dynamic_enabled: bool = False


class DualMonitorRuntime:
    """Cooperative ThreadMain: SELECT→SEND→RECEIVE, faults→ERROR→STOPPED.

    Call step() on native wake/timer observations or run_packets() for bounded
    offline acquisition. Events preserve target-local storage and raw ticks.
    """

    def __init__(
        self,
        targets: Sequence[DualTarget],
        provider: MonitorProvider,
        *,
        tick_ms: Callable[[], int],
        native_send: NativeSend | None = None,
        version: int = 18,
        connected_device: int | None = None,
        driver_control: DualControlProvider | None = None,
        clock: Callable[[], float] = time.monotonic,
        cancelled: Callable[[], bool] = lambda: False,
        maximum_steps: int = 100_000,
        seconds: float = 30,
        ring_bytes: int = MAX_BYTES,
        command_cache: Mapping[tuple[int, int], bytes] | None = None,
        osc_provider: OscProvider | None = None,
        osc_setup: OscSetup | None = None,
    ):
        if type(version) is not int or version not in (12, 18):
            raise MonitorError("Native Dual source version must be12or18")
        if (
            isinstance(driver_control, NativeDualControl)
            and driver_control.source_build != version
        ):
            raise MonitorError(
                "Native Dual runtime differs from selected application source"
            )
        self.version = version
        selected = tuple(targets)
        if not 1 <= len(selected) <= 2 or any(
            not isinstance(x, DualTarget) for x in selected
        ):
            raise MonitorError("Native Dual requires one or two typed targets", INVALID)
        if len({x.request_id for x in selected}) != len(selected) or len(
            {x.ecu for x in selected}
        ) != len(selected):
            raise MonitorError("Native Dual target identity collision", INVALID)
        _uint(maximum_steps, MAX_ITEMS)
        if (
            not maximum_steps
            or isinstance(seconds, bool)
            or not isinstance(seconds, (float, int))
            or not math.isfinite(seconds)
            or seconds <= 0
        ):
            raise MonitorError("Native Dual execution budget is invalid")
        if (osc_provider is None) != (osc_setup is None):
            raise MonitorError(
                "Native Dual oscilloscope needs provider and selected parameters"
            )
        self.targets = tuple(_TargetRuntime(x) for x in selected)
        self.provider = provider
        if isinstance(provider, NativeDualTransport):
            if driver_control is not provider.control or native_send is not None:
                raise MonitorError(
                    "Concrete native Dual transport must own the send/control join"
                )
        elif native_send is None:
            raise MonitorError("Native Dual requires its seven-argument send primitive")
        self.native_send = native_send
        self.driver_control = driver_control
        self.control_observations: list[tuple[DualControl, int]] = []
        if connected_device is not None:
            _uint(connected_device)
        self.no_init_no_session = connected_device == 4 and any(
            x.protocol & 0xF0 == 0x20 for x in selected
        )
        self.tick_ms, self.clock, self.cancelled = tick_ms, clock, cancelled
        self.maximum_steps, self.seconds = maximum_steps, seconds
        self.cache = dict(command_cache or {})
        if (
            len(self.cache) > MAX_ITEMS
            or sum(len(x) for x in self.cache.values()) > MAX_BYTES
        ):
            raise MonitorError("Native Dual command cache exceeds budget")
        for key, value in self.cache.items():
            if not isinstance(key, tuple) or len(key) != 2:
                raise MonitorError("Native Dual command cache key is invalid")
            _uint(key[0])
            _uint(key[1], 65535)
            _bytes(value)
            if key[0] not in {x.request_id for x in selected}:
                raise MonitorError("Native Dual command cache has unknown target")
        self.rings = {x.request_id: DualRing(ring_bytes) for x in selected}
        self.active = DualActiveEvent(selected[0].phase5)
        self.osc_provider, self.osc_setup = osc_provider, osc_setup
        self.osc_ring = DualRing(ring_bytes)
        self._osc_increment = osc_setup.sample_increment if osc_setup is not None else 0
        self.state = DualState.STOPPED
        self.current_target = self.slot = self.failures = 0
        self.provider_code = self.error_code = self.error_detail = 0
        self.faults: list[DualFault] = []
        self.notices: list[DualNotice] = []
        self.auxiliary_exchanges: list[DualAuxExchange] = []
        self._auxiliary_bytes = 0
        self.cleanup_exchanges: deque[DualAuxExchange] = deque()
        self._cleanup_trace_bytes = 0
        self.cleanup_trace_dropped = 0
        self.transitions: list[DualState] = []
        self._request = b""
        self._received = b""
        self._stop_requested = False
        self._cleaning = False
        self._cleaned = True
        self._cleanup_started: float | None = None
        self._cleanup_operations = self._cleanup_bytes = 0
        self.cleanup_error: str | None = None
        self.cleanup_failures: list[DualAuxExchange] = []
        self._closed = False
        self._security_release = False
        self._default_session_on_close = False
        self._steps = self._operations = 0
        self._started: float | None = None
        self._restore_target = 0
        self._rid_list: list[int] = []
        self._check_normal, self._check_abnormal = False, True
        self._osc_error = (0, 0)
        self._osc_next = self._osc_last = self._osc_wrap = self._osc_wrap_fraction = (
            self._osc_fraction
        ) = 0

    def _target(self, request_id: int) -> _TargetRuntime:
        _uint(request_id)
        for target in self.targets:
            if target.target.request_id == request_id:
                return target
        raise MonitorError("Native Dual target was not registered", INVALID)

    def configure(self, request_id: int, setup: MonitorSetup) -> None:
        """Decode the actual selected DMCI setup into native P4/P5 requests."""
        if self.state != DualState.STOPPED:
            raise MonitorError("Native Dual setup requires a stopped runtime")
        target = self._target(request_id)
        if (
            not isinstance(setup, MonitorSetup)
            or not isinstance(setup.setup, tuple)
            or not 1 <= len(setup.setup) <= MAX_ITEMS
            or any(not isinstance(command, MonitorCommand) for command in setup.setup)
        ):
            raise MonitorError("Native Dual requires selected monitor setup")
        if setup.start != (MonitorCommand(0x10C, ()),) or setup.stop != (
            MonitorCommand(0x10E, ()),
        ):
            raise MonitorError("Native Dual setup start/stop commands differ")
        p4 = None
        ids: list[tuple[int, int]] = []
        dtc: list[bytes] = []
        routines: list[RoutineMonitor] = []
        pickup: tuple[tuple[int, int], ...] = ()
        pickup_seen = False
        clear_ids: tuple[int, ...] | None = None
        for command in setup.setup:
            values = command.values
            if not isinstance(values, tuple):
                raise MonitorError("Native Dual command values must be a tuple")
            if command.command_id == 0x112:
                if (
                    pickup_seen
                    or len(values) != 2
                    or values[0] != request_id
                    or not isinstance(values[1], bytes)
                ):
                    raise MonitorError("Native Dual pickup setup shape differs")
                payload = values[1]
                if not payload or len(payload) % 8 or len(payload) > MAX_ITEMS * 8:
                    raise MonitorError("Native Dual pickup setup length is invalid")
                pickup = tuple(struct.iter_unpack("<II", payload))
                pickup_seen = True
                continue
            if command.command_id == 0x11A:
                if (
                    not target.target.phase5
                    or clear_ids is not None
                    or len(values) != 2
                    or values[0] != request_id
                    or not isinstance(values[1], bytes)
                    or not 0 < len(values[1]) <= 510
                    or len(values[1]) % 2
                ):
                    raise MonitorError("Native Dual clear-ID setup shape differs")
                clear_ids = tuple(
                    value[0] for value in struct.iter_unpack("<H", values[1])
                )
                continue
            if len(values) < 2 or values[1] != request_id:
                raise MonitorError(
                    "Native Dual setup targets another registered interface"
                )
            try:
                if command.command_id == 0x10A and not target.target.phase5:
                    if p4 is not None or len(values) != 8:
                        raise MonitorError("Native Dual P4 setup shape differs")
                    pairs = _pairs(values[3])
                    if len(pairs) > 256:
                        raise MonitorError(
                            "Native Dual P4 BYTE ordinal supports at most256 pairs"
                        )
                    p4 = MonitorEvent.p4(
                        _number(values[2]),
                        tuple(x[0] for x in pairs),
                        tuple(x[1] for x in pairs),
                    )  # type: ignore[arg-type]
                elif command.command_id == 0x119 and target.target.phase5:
                    if len(values) != 6:
                        raise MonitorError("Native Dual DID setup shape differs")
                    ids.extend(_pairs(values[2]))
                elif command.command_id == 0x10B and target.target.phase5:
                    if self.version == 12:
                        raise MonitorError("Native12 Dual has no DTC monitor setup")
                    if len(values) != 6 or values[2] != 0:
                        raise MonitorError(
                            "Native Dual DTC setup pattern is unsupported"
                        )
                    dtc.append(_message(values[3]))
                elif command.command_id == 0x11C and target.target.phase5:
                    if len(values) != 10 or target is not self.targets[0]:
                        raise MonitorError(
                            "Native Dual RID setup belongs to first target"
                        )
                    routines.append(_routine(values))
                else:
                    raise MonitorError(
                        "Selected command is not a native Dual monitor setup"
                    )
            except (TypeError, IndexError, AttributeError) as exc:
                raise MonitorError("Malformed native Dual setup fields") from exc
        event = (
            p4
            if p4 is not None
            else P5MonitorEvent(ids, dtc, routines, routine_info=False)
        )
        if pickup_seen:
            pickup_packet(
                bytes(sum(event.lengths)), 0, pickup, p4=not target.target.phase5
            )
            event.pickup_spans = pickup
        if any(len(x) > 4096 for x in event.requests):
            raise MonitorError("Native Dual requests exceed its4096-byte stack buffer")
        target.event, target.setup = event, setup
        target.clear_ids = clear_ids
        target.clear_requests = target.define_requests = ()
        target.dynamic_enabled = clear_ids is not None

    def set_routine_info(self, exists: bool) -> None:
        if type(exists) is not bool:
            raise MonitorError("Native routine-info flag must be boolean")
        for target in self.targets:
            if isinstance(target.event, P5MonitorEvent):
                target.event.routine_info = exists

    def set_security_release(self, request_id: int, released: bool) -> None:
        """Native18 18d20: only the first target owns this exit-session flag."""
        if (
            self.version != 18
            or type(released) is not bool
            or request_id != self.targets[0].target.request_id
        ):
            raise MonitorError(
                "Native Dual security release requires18 first-target identity", INVALID
            )
        self._security_release = released

    def dynamic(
        self,
        request_id: int,
        plan: DynamicPlan,
        profile: VehicleProfile,
        *,
        clear_ids: Sequence[int] | None = None,
    ) -> None:
        target = self._target(request_id)
        if (
            self.state != DualState.STOPPED
            or not target.target.phase5
            or not isinstance(plan, DynamicPlan)
        ):
            raise MonitorError("Native dynamic-DID setup requires stopped P5 target")
        if plan.remaining:
            raise MonitorError("Native dynamic-DID setup has unpacked selected sources")
        for request in plan.requests:
            _bytes(request, 4)
        if not 1 <= len(plan.read_ids) <= 255 or not (
            len(plan.requests)
            == len(plan.read_ids)
            == len(plan.read_lengths)
            == len(plan.sources)
        ):
            raise MonitorError("Native dynamic-DID setup descriptor counts differ")
        if not isinstance(target.event, P5MonitorEvent):
            raise MonitorError("Native dynamic-DID setup requires configured monitor")
        selected = dict(zip(target.event.requests, target.event.lengths))
        for did, length, request in zip(
            plan.read_ids, plan.read_lengths, plan.requests
        ):
            _uint(did, 65535)
            _uint(length, 65535)
            if (
                request[2:4] != did.to_bytes(2, "big")
                or selected.get(b"\x22" + did.to_bytes(2, "big")) != length
            ):
                raise MonitorError(
                    "Native dynamic-DID plan differs from selected monitor"
                )
        for request in plan.requests:
            _bytes(request, 4)
        ids = tuple(clear_ids) if clear_ids is not None else target.clear_ids
        if ids is None:
            raise MonitorError(
                "Native Dual dynamic setup requires explicit cleared IDs"
            )
        if target.clear_ids is not None and ids != target.clear_ids:
            raise MonitorError("Native Dual dynamic cleared IDs differ from11A")
        requests = clear_dynamic_requests(profile, ids)
        target.clear_ids, target.clear_requests = ids, requests
        target.define_requests = plan.requests
        target.dynamic_enabled = True

    def start(self) -> None:
        self._check_source_context()
        for runtime in self.targets:
            if runtime.clear_ids is not None and not runtime.clear_requests:
                if isinstance(self.driver_control, NativeDualControl):
                    profile = self.driver_control.selected[runtime.target.command_id][1]
                    runtime.clear_requests = clear_dynamic_requests(
                        profile, runtime.clear_ids
                    )
                else:
                    template = self.cache.get((runtime.target.request_id, 0xD4))
                    if template is None or not 4 <= len(template) <= 4096:
                        raise MonitorError(
                            "Native Dual11A requires selected D4 metadata"
                        )
                    runtime.clear_requests = tuple(
                        template[:2] + did.to_bytes(2, "big") + template[4:]
                        for did in runtime.clear_ids
                    )
                self._check_source_context()
        if self.cleanup_error is not None:
            raise MonitorError(
                "Native Dual previous cleanup failed; stop before restarting"
            )
        if any(ring.size for ring in self.rings.values()):
            raise MonitorError("Drain native Dual packets before restarting")
        if self.state != DualState.STOPPED or any(
            x.event is None for x in self.targets
        ):
            raise MonitorError("Native Dual start requires all target setups")
        if (
            self.driver_control is not None
            and not self.no_init_no_session
            and any(x.target.entry_parameter is None for x in self.targets)
        ):
            raise MonitorError(
                "Native Dual registration lacks selected entry parameter"
            )
        for target in self.targets:
            event = target.event
            assert event is not None
            event.index = event._offset = 0
            event._data[:] = bytes(len(event._data))
            event._pickup_previous = b""
            target.last_time = 0
        self.current_target = self.failures = self._steps = self._operations = 0
        self._started = self.clock()
        self._check_source_context()
        if not math.isfinite(self._started):
            raise MonitorError("Native Dual clock must be finite")
        self._stop_requested = False
        self._cleaned = False
        self.cleanup_error = None
        self.cleanup_failures.clear()
        self._closed = False
        self._rid_list.clear()
        self._check_normal, self._check_abnormal = False, True
        self.faults.clear()
        self.notices.clear()
        self.auxiliary_exchanges.clear()
        self._auxiliary_bytes = 0
        self.cleanup_exchanges.clear()
        self._cleanup_trace_bytes = self.cleanup_trace_dropped = 0
        self.control_observations.clear()
        self.error_code = self.error_detail = self.provider_code = 0
        self.transitions.clear()
        if self.driver_control is not None:
            if not self.no_init_no_session:
                self._control("ConnectDualMon", ())
                for runtime in self.targets:
                    target = runtime.target
                    if target.entry_parameter is None:
                        raise MonitorError(
                            "Native Dual registration lacks selected entry parameter"
                        )
                    self._control(
                        "EntryCommSystemInfo",
                        (
                            target.command_id,
                            target.protocol,
                            target.entry_parameter,
                            target.category_flags,
                        ),
                    )
            self._select_target(0)
        self._set_state(
            DualState.START_OSC if self.osc_provider is not None else DualState.SELECT
        )

    def request_stop(self) -> None:
        self._stop_requested = True

    def _control(self, operation: str, arguments: tuple[int, ...]) -> None:
        if self.driver_control is None:
            return
        self._guard()
        call = DualControl(operation, arguments)
        self._operation(4 * len(arguments))
        if isinstance(self.driver_control, NativeDualControl):
            deadline, cancelled = self._control_context()
            if operation == "Disconnect" and not self._cleaning:
                self.driver_control.check_context(
                    deadline=deadline, cancelled=cancelled
                )
            code = self.driver_control.execute(
                call, deadline=deadline, cancelled=cancelled
            )
        else:
            code = self.driver_control(call)
        _uint(code)
        self.control_observations.append((call, code))
        self._guard()

    def _control_context(self) -> tuple[float, Callable[[], bool]]:
        if self._cleaning:
            assert self._cleanup_started is not None
            return self._cleanup_started + CLEANUP_SECONDS, lambda: False
        assert self._started is not None
        return self._started + self.seconds, self.cancelled

    def _select_target(self, index: int) -> None:
        self.current_target = index
        if self.no_init_no_session:
            self._control("Disconnect", (0,))

    def close(self) -> None:
        """Bounded native destruction disconnect, preserving any stop failure."""
        if self._started is None or self._closed:
            return
        try:
            self.stop()
        except Exception as primary:
            try:
                self._disconnect()
            except Exception as release:  # noqa: BLE001 - preserve stop failure
                primary.add_note(f"Native Dual disconnect also failed: {release}")
            raise
        self._disconnect()

    def _disconnect(self) -> None:
        self._cleanup_started = self.clock()
        self._cleanup_operations = self._cleanup_bytes = 0
        self._cleaning = True
        try:
            session_error: Exception | None = None
            try:
                if (
                    self._default_session_on_close
                    or self.version == 18
                    and self._security_release
                ):
                    self._select_target(0)
                    self._cached(self.targets[0].target, 0xD1)
            except Exception as exc:  # noqa: BLE001 - final disconnect still required
                session_error = exc
            try:
                self._control("Disconnect", (0,))
                self._closed = True
            except Exception as release:
                if session_error is not None:
                    session_error.add_note(
                        f"Native Dual disconnect also failed: {release}"
                    )
                    raise session_error from release
                raise
            if session_error is not None:
                raise session_error
        except Exception as exc:
            previous = self.cleanup_error
            self.cleanup_error = (
                f"{previous}; disconnect: {exc}" if previous else f"disconnect: {exc}"
            )
            raise
        finally:
            if isinstance(self.provider, NativeDualTransport):
                self.provider.released()
            self._cleaning = False

    def _set_state(self, state: DualState) -> None:
        self.state = state
        if len(self.transitions) >= self.maximum_steps + 2:
            raise MonitorError("Native Dual transition trace exceeds budget")
        self.transitions.append(state)

    def _tick(self) -> int:
        self._check_source_context()
        tick = self.tick_ms()
        self._check_source_context()
        _uint(tick)
        return tick

    def _check_source_context(self) -> None:
        if not self._cleaning and isinstance(self.driver_control, NativeDualControl):
            self.driver_control.check_source_context()

    def _guard(self) -> None:
        self._check_source_context()
        if not self._cleaning:
            stopped = self.cancelled()
            self._check_source_context()
            if stopped:
                self._stop_requested = True
                raise Cancelled("Native Dual monitor cancelled")
        now = self.clock()
        self._check_source_context()
        started = self._cleanup_started if self._cleaning else self._started
        seconds = CLEANUP_SECONDS if self._cleaning else self.seconds
        if (
            not math.isfinite(now)
            or started is None
            or now < started
            or now - started >= seconds
        ):
            raise MonitorError(
                "Native Dual cleanup deadline exceeded"
                if self._cleaning
                else "Native Dual monitor deadline exceeded"
            )
        if not self._cleaning:
            if self._operations >= self.maximum_steps:
                raise MonitorError("Native Dual primitive budget exhausted")
            if self._steps >= self.maximum_steps:
                raise MonitorError("Native Dual state budget exhausted")

    def _account_cleanup_bytes(self, size: int) -> None:
        if self._cleaning:
            if size > MAX_BYTES - self._cleanup_bytes:
                raise MonitorError("Native Dual cleanup byte budget exhausted")
            self._cleanup_bytes += size

    def _operation(self, size: int = 0) -> None:
        if self._cleaning:
            if self._cleanup_operations >= MAX_ITEMS:
                raise MonitorError("Native Dual cleanup primitive budget exhausted")
            self._account_cleanup_bytes(size)
            self._cleanup_operations += 1
        else:
            self._operations += 1

    def _timeout(self, selected: int) -> int:
        if self._cleaning:
            assert self._cleanup_started is not None
            remaining = self._cleanup_started + CLEANUP_SECONDS - self.clock()
            return min(selected, max(0, int(remaining * 1000)))
        return selected

    def _send(self, target: DualTarget, request: bytes) -> int:
        self._guard()
        if self.version == 12 and self.no_init_no_session and len(request) > 255:
            raise MonitorError("Native12 NoInitNoSession request exceeds BYTE length")
        if isinstance(self.driver_control, NativeDualControl):
            deadline, cancelled = self._control_context()
            if self.no_init_no_session:
                self.driver_control.check_context(
                    deadline=deadline, cancelled=cancelled
                )
            else:
                self.driver_control.before_send(
                    target, deadline=deadline, cancelled=cancelled
                )
        operation = (
            "SendIntNoInitNoSession" if self.no_init_no_session else "SendIntExtDualMon"
        )
        call = NativeFrameSend(
            operation,
            target.command_id,
            request,
            self._timeout(target.send_timeout),
            target.protocol,
            0,
            1,
        )
        self._operation(len(request))
        if isinstance(self.provider, NativeDualTransport):
            deadline, cancelled = self._control_context()
            code = self.provider.send_frame(
                target, call, deadline=deadline, cancelled=cancelled
            )
        else:
            assert self.native_send is not None
            code = self.native_send(target.ecu, call)
        _uint(code)
        self._guard()
        return code

    def _receive(self, target: DualTarget) -> MonitorReceive:
        self._guard()
        self._operation()
        if isinstance(self.provider, NativeDualTransport):
            deadline, cancelled = self._control_context()
            result = self.provider.receive_frame(
                target,
                deadline=deadline,
                cancelled=cancelled,
                buffer=True,
                maximum=4096,
                timeout=self._timeout(target.receive_timeout),
                argument_5=0,
                flags=100,
            )
        else:
            result = self.provider.receive(
                target.ecu,
                buffer=True,
                maximum=4096,
                timeout=self._timeout(target.receive_timeout),
                argument_5=0,
                flags=100,
            )
        self._guard()
        if not isinstance(result, MonitorReceive):
            raise MonitorError("Native Dual provider did not return typed receive")
        self._account_cleanup_bytes(len(result.data))
        return result

    def _exchange(self, target: DualTarget, request: bytes) -> MonitorReceive:
        code = self._send(target, request)
        result = MonitorReceive(b"", 0, code) if code else self._receive(target)
        if not result.code and (not result.data or result.data[0] != request[0] | 0x40):
            result = MonitorReceive(result.data, result.source_id, 0xA0040201)
        observation = DualAuxExchange(target.request_id, request, result)
        if self._cleaning:
            self._record_cleanup(observation)
        else:
            self._auxiliary_bytes += len(request) + len(result.data)
            if (
                self._auxiliary_bytes > MAX_BYTES
                or len(self.auxiliary_exchanges) >= MAX_ITEMS
            ):
                raise MonitorError("Native Dual auxiliary trace exceeds budget")
            self.auxiliary_exchanges.append(observation)
        return result

    def _record_cleanup(self, observation: DualAuxExchange) -> None:
        size = len(observation.request) + len(observation.received.data)
        removed = set()
        while self.cleanup_exchanges and (
            self._cleanup_trace_bytes + size > MAX_BYTES
            or len(self.cleanup_exchanges) >= MAX_ITEMS
        ):
            old = self.cleanup_exchanges.popleft()
            self._cleanup_trace_bytes -= len(old.request) + len(old.received.data)
            removed.add(id(old))
            self.cleanup_trace_dropped += 1
        if removed:
            self.cleanup_failures[:] = [
                item for item in self.cleanup_failures if id(item) not in removed
            ]
        if size > MAX_BYTES:
            self.cleanup_trace_dropped += 1
            return
        self.cleanup_exchanges.append(observation)
        self._cleanup_trace_bytes += size
        if observation.received.code:
            self.cleanup_failures.append(observation)

    def _cached(self, target: DualTarget, command: int) -> MonitorReceive:
        key = (target.request_id, command)
        if key not in self.cache:
            raise MonitorError(f"Selected native Dual cache lacks command{command:02X}")
        return self._exchange(target, self.cache[key])

    def _recover(self, runtime: _TargetRuntime) -> None:
        target = runtime.target
        if not target.phase5:
            return
        last = max(
            runtime.last_time,
            self.active.last_time if runtime is self.targets[0] else 0,
        )
        if last and self._tick() <= (last + 2000) & 0xFFFFFFFF:
            return
        reply = self._cached(target, 0xDD)
        byte_3_is_extended = len(reply.data) >= 4 and reply.data[3] == 3
        extended = (
            byte_3_is_extended
            if self.version == 12
            else not reply.code and (reply.data[:1] == b"\x50" or byte_3_is_extended)
        )
        if extended:
            return
        self._cached(target, 0xD1)
        self._cached(target, 0xD2)
        if runtime.dynamic_enabled:
            cleared = False
            for request in runtime.clear_requests:
                if self._exchange(target, request).code == 0:
                    cleared = True
            if self.version == 12 or cleared:
                for request in runtime.define_requests:
                    self._exchange(target, request)
        runtime.last_time = self._tick()

    def _select(self) -> None:
        self.active.advance()
        item = self.active.current
        if item is not None and item.state not in (4, 5):
            if item.state == 3:
                if item.due <= self._tick():
                    item.state = 0
                    return
            else:
                self._restore_target = self.current_target
                if self.current_target != 0:
                    self._select_target(0)
                self.slot, self._request = 0, item.request
                item.state = 1
                self._set_state(DualState.SEND)
                return
        runtime = self.targets[self.current_target]
        assert runtime.event is not None
        self.slot, self._request = 2, runtime.event.request
        self._set_state(DualState.SEND)

    def _fault(self, provider_code: int, *, negative: bool = False) -> None:
        self.provider_code = provider_code
        self.error_detail = (
            self._received[2] if negative and len(self._received) > 2 else 0
        )
        self._negative = negative
        self._set_state(DualState.ERROR)

    def _error(self) -> None:
        target = self.targets[self.current_target].target
        code = self.error_code
        if self.slot == 2:
            if target.phase5:
                kind = {0x22: 0, 0x19: 0x12}.get(self._request[0], 6)
                code = {0: 0xE0000301, 6: 0xE0000509, 0x12: 0xE0000801}[kind] + int(
                    self._negative
                )
            elif self._negative:
                code = 0xE000010E if self._request[0] == 0x21 else 0xE0000102
            else:
                code = 0xE0000108 if self._request[0] == 0x21 else 0xE0000102
        elif self.slot == 0:
            if target.phase5:
                if self.active.send_info in (3, 5):
                    self._default_session_on_close = True
                code = {2: 0xE0000201, 3: 0xE0000205, 4: 0xE0000501, 5: 0xE0000505}.get(
                    self.active.send_info, INVALID
                ) + int(self._negative)
            elif code != 0xE00001CC:
                code = 0xE000010C if self._negative else 0xE0000106
        self.error_code = code
        self.faults.append(
            DualFault(
                target.request_id,
                self.slot,
                code,
                self.error_detail,
                self.provider_code,
            )
        )
        if target.phase5 and code in (0xE0000205, 0xE0000505, 0xE0000206, 0xE0000506):
            item = self.active.current
            if item is not None:
                item.state = 5
            self._set_state(DualState.SELECT)
        else:
            self._set_state(DualState.STOPPED)

    def _normal_receive(self, runtime: _TargetRuntime, reply: bytes) -> None:
        tick = self._tick()
        if self.slot == 0:
            self.active.accept(reply, tick)
            if runtime.target.phase5:
                item = self.active.current
                assert item is not None
                if self.active.send_info == 4:
                    self.notices.append(
                        DualNotice(
                            runtime.target.request_id, "active-start-info", b"\x04"
                        )
                    )
                if item.state in (3, 4):
                    self._check_normal, self._check_abnormal = True, False
                    if self.active.send_info == 4:
                        rid = int.from_bytes(self._request[2:4], "big")
                        if rid not in self._rid_list:
                            if len(self._rid_list) > 1:
                                self._rid_list.clear()
                            self._rid_list.append(rid)
                elif item.state == 5:
                    self._check_normal, self._check_abnormal = False, True
                    self._rid_list.clear()
            if self._restore_target:
                self._select_target(self._restore_target)
        else:
            event = runtime.event
            assert event is not None
            if (
                isinstance(event, P5MonitorEvent)
                and runtime is self.targets[0]
                and self._request[0] == 0x31
            ):
                routine = next(
                    (x for x in self._routines(runtime) if x.request == self._request),
                    None,
                )
                if routine is not None:
                    if self._check_normal and (
                        self.version == 12
                        or routine.rid == 0
                        or routine.rid in self._rid_list
                    ):
                        if routine.check_status(reply, routine_info=event.routine_info):
                            self._check_normal = False
                            self.notices.append(
                                DualNotice(
                                    runtime.target.request_id, "routine-normal", reply
                                )
                            )
                        if routine.check_status(
                            reply, routine_info=event.routine_info, abnormal=True
                        ):
                            self._check_abnormal = True
                            self.notices.append(
                                DualNotice(
                                    runtime.target.request_id, "routine-abnormal", reply
                                )
                            )
                            self._set_state(DualState.STOPPED)
                            return
                    elif (
                        self._check_abnormal
                        and routine.stop
                        and self._stop_status(routine, reply, event.routine_info)
                    ):
                        self.notices.append(
                            DualNotice(
                                runtime.target.request_id, "routine-before-drive", reply
                            )
                        )
                        self._set_state(DualState.STOPPED)
                        return
            result = event.accept(reply, tick)
            runtime.last_time = tick
            if result is not None:
                stamp, payload = result
                self.rings[runtime.target.request_id].append(
                    DualPacket(
                        runtime.target.request_id, runtime.target.ecu, stamp, payload
                    )
                )
                self._select_target((self.current_target + 1) % len(self.targets))
        if self.osc_provider is not None and self._read_osc():
            self._set_state(DualState.OSC_ERROR)
        else:
            self._set_state(DualState.SELECT)

    @staticmethod
    def _stop_status(routine: RoutineMonitor, reply: bytes, info: bool) -> bool:
        selected = RoutineMonitor(routine.request, routine.size, routine.stop, (), ())
        return selected.check_status(reply, routine_info=info)

    @staticmethod
    def _routines(runtime: _TargetRuntime) -> tuple[RoutineMonitor, ...]:
        assert runtime.setup is not None
        result = []
        for command in runtime.setup.setup:
            if command.command_id == 0x11C:
                v = command.values
                result.append(_routine(v))
        return tuple(result)

    def step(self) -> DualState:
        if self.state == DualState.STOPPED:
            return self.state
        try:
            self._guard()
            self._steps += 1
            if self._stop_requested and self.state == DualState.SELECT:
                self.stop()
            elif self.state == DualState.SELECT:
                self._select()
            elif self.state == DualState.SEND:
                runtime = self.targets[self.current_target]
                self._recover(runtime)
                code = self._send(runtime.target, self._request)
                if not code:
                    if self.slot == 0 and self.active.current is not None:
                        self.active.current.state = 2
                        self.active.last_time = self._tick()
                    self._set_state(DualState.RECEIVE)
                elif self.slot == 2 and self.failures + 1 < runtime.target.retry_limit:
                    self.failures += 1
                else:
                    self._fault(code)
            elif self.state == DualState.RECEIVE:
                runtime = self.targets[self.current_target]
                received = self._receive(runtime.target)
                self._received = received.data
                if received.code:
                    if received.code in (0x90020321, 0x90020323):
                        if self._synthetic_routine(runtime, received):
                            self.failures = 0
                            if received.source_id == runtime.target.receive_id:
                                self._normal_receive(runtime, self._received)
                        else:
                            self._fault(received.code, negative=True)
                    elif (
                        self.slot == 2
                        and self.failures + 1 < runtime.target.retry_limit
                    ):
                        self.failures += 1
                        self._set_state(DualState.SEND)
                    else:
                        self._fault(received.code)
                else:
                    self.failures = 0
                    if received.source_id == runtime.target.receive_id:
                        try:
                            self._normal_receive(runtime, received.data)
                        except MonitorError as exc:
                            self.error_code = exc.code or INVALID
                            self._fault(0)
            elif self.state == DualState.ERROR:
                self._error()
            elif self.state == DualState.START_OSC:
                self._set_state(
                    DualState.OSC_ERROR if self._start_osc() else DualState.SELECT
                )
            elif self.state == DualState.OSC_ERROR:
                code, detail = self._osc_error
                target = self.targets[self.current_target].target
                self.faults.append(
                    DualFault(
                        target.request_id, self.slot, code, detail, self.provider_code
                    )
                )
                self._set_state(DualState.STOPPED)
        except Exception:
            self._set_state(DualState.STOPPED)
            raise
        return self.state

    def _synthetic_routine(
        self, runtime: _TargetRuntime, received: MonitorReceive
    ) -> bool:
        if not (
            self.version == 18
            and self.current_target == 0
            and self.targets[0].target.category_flags & 0xE0 == 0x20
            and received.code == 0x90020321
            and self.slot == 2
            and self._request[0] == 0x31
            and len(received.data) > 2
            and received.data[2] in (0x24, 0x33)
        ):
            return False
        self._received = (b"\x71" + self._request[1:4]).ljust(4096, b"\0")
        return True

    def drain(self, request_id: int) -> tuple[DualPacket, ...]:
        self._target(request_id)
        return self.rings[request_id].drain()

    def run_packets(self, packets_per_target: int = 1) -> tuple[DualPacket, ...]:
        _uint(packets_per_target, MAX_ITEMS)
        if not packets_per_target:
            raise MonitorError("Native Dual packet goal must be positive")
        self.start()
        result: list[DualPacket] = []
        result_bytes = 0
        counts = {x.target.request_id: 0 for x in self.targets}
        try:
            while self.state != DualState.STOPPED:
                self.step()
                for target_id in counts:
                    packets = self.drain(target_id)
                    result_bytes += sum(len(packet.payload) + 4 for packet in packets)
                    if (
                        result_bytes > MAX_BYTES
                        or len(result) + len(packets) > MAX_ITEMS
                    ):
                        raise MonitorError(
                            "Native Dual acquisition exceeds output budget"
                        )
                    result.extend(packets)
                    counts[target_id] += len(packets)
                if all(value >= packets_per_target for value in counts.values()):
                    self.request_stop()
        except Exception:
            try:
                self.stop()
            except Exception as cleanup:  # noqa: BLE001 - preserve original failure
                self.cleanup_error = str(cleanup)
            raise
        if self.faults:
            try:
                self.stop()
            except Exception as cleanup:  # noqa: BLE001 - retain native fault code
                self.cleanup_error = str(cleanup)
            raise MonitorError(
                "Native Dual monitor terminated with a native fault",
                self.faults[-1].code,
            )
        if not all(value >= packets_per_target for value in counts.values()):
            self.stop()
            raise MonitorError(
                "Native Dual monitor stopped before requested packet goal"
            )
        return tuple(result)

    def stop(self) -> None:
        """Run native stop items and clear selected dynamic definitions once."""
        if self._cleaned:
            return
        self._cleanup_started = self.clock()
        self._cleanup_operations = self._cleanup_bytes = 0
        self.cleanup_error = None
        self._cleaning = True
        try:
            self._cleanup()
            self._cleaned = True
        except Exception as exc:
            self.cleanup_error = str(exc)
            raise
        finally:
            self._cleaning = False
            if self.state != DualState.STOPPED:
                self._set_state(DualState.STOPPED)

    def _cleanup(self) -> None:
        failures: list[Exception] = []
        try:
            self._cleanup_active()
        except Exception as exc:  # noqa: BLE001 - finish independent cleanup stages
            failures.append(exc)
        if self.osc_provider is not None:
            try:
                self._stop_osc()
            except Exception as exc:  # noqa: BLE001 - finish independent cleanup stages
                failures.append(exc)
        for index, runtime in enumerate(self.targets):
            if runtime.dynamic_enabled:
                try:
                    self._select_target(index)
                    self._recover(runtime)
                except Exception as exc:  # noqa: BLE001 - finish independent cleanup stages
                    failures.append(exc)
                for request in runtime.clear_requests:
                    try:
                        self._exchange(runtime.target, request)
                    except Exception as exc:  # noqa: BLE001 - finish independent cleanup stages
                        failures.append(exc)
        if failures:
            primary, *secondary = failures
            for failure in secondary:
                primary.add_note(f"Native Dual cleanup also failed: {failure}")
            raise primary
        self.notices.append(
            DualNotice(self.targets[0].target.request_id, "stopped", b"")
        )

    def _cleanup_active(self) -> None:
        item = self.active.current
        if not self.active.phase5:
            # SkipEndCommItem21a40 discards pending starts before the final30.
            self.active.items = deque((item,)) if item is not None else deque()
            self.active._item_bytes = len(item.request) if item is not None else 0
            if item is not None and item.state != 5:
                self.active.items.clear()
                self.active._item_bytes = 0
                self.active.p4_start(b"")
        elif item is not None and (item.state != 5 or self.active.stop_items):
            self.active.stop()
        # Native shutdown sends only pending stop items, retaining literal replies.
        for _ in range(MAX_ITEMS + 1):
            self.active.advance()
            item = self.active.current
            if item is None or item.state == 5:
                break
            item.state = 0
            target = self.targets[0].target
            received = self._exchange(target, item.request)
            if not received.code:
                try:
                    self.active.accept(received.data, self._tick())
                except MonitorError:
                    if self.active.phase5:
                        self._default_session_on_close = True
                    item.state = 5
            else:
                if self.active.phase5:
                    self._default_session_on_close = True
                item.state = 5
            if len(self.active.items) == 1:
                item.state = 5
        else:
            raise MonitorError("Native Dual stop queue exceeds budget")

    def _osc_call(self, operation: int, data: bytes | None = None) -> int:
        provider = self.osc_provider
        assert provider is not None
        self._guard()
        self._operation(len(data) if data is not None else 0)
        code = (
            provider.command(operation)
            if data is None
            else provider.set_parameter(operation, data)
        )
        _uint(code)
        self._guard()
        if code:
            self.provider_code = code
            self._osc_error = (0xE2001000 if data is None else 0xE2001001, operation)
        return code

    def _start_osc(self) -> int:
        setup = self.osc_setup
        assert setup is not None
        for operation, data in (
            (0, None),
            (9, setup.parameter_9),
            (10, setup.parameter_10_start),
            (6, setup.parameter_6),
            (8, setup.parameter_8),
            (2, None),
        ):
            code = self._osc_call(operation, data)
            if code:
                return code
            if operation == 10 and data is not None:
                self._osc_increment = osc_sampling_increment(data[0])
        return 0

    def _read_osc(self) -> int:
        provider, setup = self.osc_provider, self.osc_setup
        assert provider is not None and setup is not None
        for _ in range(MAX_ITEMS):
            self._guard()
            self._operation()
            read = provider.read_buffer(0x1068)
            self._guard()
            if not isinstance(read, OscRead):
                raise MonitorError("Native Dual oscilloscope read must be typed")
            self._account_cleanup_bytes(len(read.data))
            if read.code:
                self.provider_code = read.code
                self._osc_error = (0xE2001003, 0)
                return read.code
            if not read.data:
                return 0
            tick = self._osc_next or read.timestamp_raw
            for offset in range(0, len(read.data), 4):
                if tick < self._osc_last:
                    fraction = self._osc_wrap_fraction + 0x128
                    self._osc_wrap = (
                        self._osc_wrap + fraction // 1000 + 0x418937
                    ) & 0xFFFFFFFF
                    self._osc_wrap_fraction = fraction % 1000
                self._osc_last = tick
                stamp = (
                    (tick % 1000 + self._osc_wrap_fraction) // 1000
                    + tick // 1000
                    + self._osc_wrap
                ) & 0xFFFFFFFF
                try:
                    self.osc_ring.append(
                        DualPacket(
                            self.targets[0].target.request_id,
                            self.targets[0].target.ecu,
                            stamp,
                            read.data[offset : offset + 4],
                        )
                    )
                except MonitorError:
                    self._osc_error = (0xE2001003, 0)
                    return 0xE0000101
                fraction = self._osc_increment % 1000 + self._osc_fraction
                tick = (
                    self._osc_increment // 1000 + tick + fraction // 1000
                ) & 0xFFFFFFFF
                self._osc_next, self._osc_fraction = tick, fraction % 1000
            if not read.remaining:
                return 0
        raise MonitorError("Native Dual oscilloscope read budget exhausted")

    def _stop_osc(self) -> None:
        setup = self.osc_setup
        assert setup is not None
        primary: Exception | None = None
        code = 0
        try:
            code = self._osc_call(3)
            if not code:
                code = self._osc_call(11)
                if not code:
                    code = self._osc_call(10, setup.parameter_10_stop)
                    if not code:
                        self._osc_increment = osc_sampling_increment(
                            setup.parameter_10_stop[0]
                        )
                        self.osc_ring.drain()
                        self._osc_next = self._osc_last = self._osc_wrap = (
                            self._osc_wrap_fraction
                        ) = self._osc_fraction = 0
                        code = self._read_osc()
        except Exception as exc:  # noqa: BLE001 - retain failure and attempt final stop
            primary = exc
        first_error, first_status = self._osc_error, self.provider_code
        final_code = 0
        try:
            final_code = self._osc_call(1)
        except Exception as exc:  # noqa: BLE001 - retain failure and attempt final stop
            if primary is None and code:
                primary = MonitorError(
                    "Native Dual OSC stop failed before final command",
                    first_error[0],
                )
                primary.add_note(f"Native Dual OSC final command also failed: {exc}")
            elif primary is None:
                primary = exc
            else:
                primary.add_note(f"Native Dual OSC final command also failed: {exc}")
        if code:
            self._osc_error, self.provider_code = first_error, first_status
        if code or final_code:
            native_code, detail = self._osc_error
            self.faults.append(
                DualFault(
                    self.targets[0].target.request_id,
                    self.slot,
                    native_code,
                    detail,
                    self.provider_code,
                )
            )
        if primary is not None:
            if code or final_code:
                primary.add_note(
                    f"Native Dual OSC cleanup status: {self.provider_code} "
                    f"at operation {self._osc_error[1]}"
                )
            raise primary
