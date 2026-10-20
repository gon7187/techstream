"""Source-derived ChangeCommIF lower classes; never execute the Windows driver."""

from __future__ import annotations

import math
import struct
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Literal, Protocol, runtime_checkable

from scripts.frame_transport import (
    MAX_DATA,
    DriverProperties,
    FramePlan,
    FrameTransportError,
    J2534Backend,
    J2534Result,
    NativeConfig,
    NativeConnect,
    NativeFilter,
    NativeFrameOperations,
    NativeFrameReceive,
    NativeMessage,
    NativeSharedState,
    _frame_inputs,
    _function_request,
    _message,
    _simple_record,
    _source_address,
    _uint,
    decode_frame_message,
    runtime_frame_plan,
    translate_configs,
)
from scripts.profiles import ProtocolProfile
from scripts.support import word
from scripts.toyota import ToyotaCodecError

Variant = Literal["normal", "psa", "psa_wwh", "dual", "century"]


EthernetPrimitiveName = Literal[
    "physical_connect",
    "physical_disconnect",
    "logical_connect",
    "logical_disconnect",
    "queue_messages",
    "read_bytes",
    "read_messages",
    "channel_ioctl",
    "device_ioctl",
]


@runtime_checkable
class EthernetBackend(Protocol):
    """Additional actual J2534-2 primitives; TCP counts are bytes, not messages."""

    def invoke_ethernet(
        self,
        operation: EthernetPrimitiveName,
        fields: Mapping[str, object],
        *,
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> J2534Result: ...


@dataclass(frozen=True)
class EthernetSettings:
    """Native EtherTimeParam.ini defaults or explicitly observed overrides."""

    connect_delay: int = 200
    connect_ip_timeout: int = 10000
    source_udp_port: int = 0xC000
    source_tcp_port: int = 0xC000
    read_voltage_wait: int = 0
    read_voltage_wait_pullup: int = 1
    mongoose_voltage_skip: bool = False
    disconnect_wait: int = 0

    def __post_init__(self) -> None:
        for value in (
            self.connect_delay,
            self.connect_ip_timeout,
            self.read_voltage_wait,
            self.read_voltage_wait_pullup,
            self.disconnect_wait,
        ):
            _uint(value)
        _uint(self.source_udp_port, 16)
        _uint(self.source_tcp_port, 16)
        if type(self.mongoose_voltage_skip) is not bool:
            raise ValueError("Observed Mongoose prefix override must be Boolean")


@dataclass(frozen=True)
class EthernetResources:
    connector: int
    pins: tuple[int, ...]

    def __post_init__(self) -> None:
        _uint(self.connector)
        if not isinstance(self.pins, tuple) or not 1 <= len(self.pins) <= 32:
            raise ValueError("Bounded native resource identifiers required")
        for pin in self.pins:
            _uint(pin)


def lower_frame_plan(
    profile: ProtocolProfile,
    request: bytes,
    *,
    native_build: Literal[12, 18],
    bus_id: int,
    driver: DriverProperties,
    device_kind: int,
    interface_word: int = 0,
    diagnostic_mode: bytes = bytes(16),
    native_variant: Variant = "normal",
) -> FramePlan:
    """Runtime constructor metadata, deliberately separate from GetCommFrame."""
    _uint(bus_id, 16)
    _uint(device_kind)
    _uint(interface_word, 16)
    if type(native_build) is not int or native_build not in (12, 18):
        raise ValueError("Recovered build 12 or 18 required")
    if not isinstance(profile, ProtocolProfile) or not isinstance(
        driver, DriverProperties
    ):
        raise TypeError("Selected profile and observed driver required")
    if not isinstance(request, bytes) or len(request) > 0xFFFF:
        raise FrameTransportError(
            0x90020701, "Bounded constructor request bytes required"
        )
    if not isinstance(diagnostic_mode, bytes) or len(diagnostic_mode) != 16:
        raise ValueError("DIAGNOSTIC_INFO must contain sixteen bytes")
    low = bus_id & 15
    if low not in (3, 4, 8, 12):
        return runtime_frame_plan(
            profile,
            request,
            native_build=native_build,
            native_variant=native_variant,
            bus_id=bus_id,
            driver=driver,
            diagnostic_mode=diagnostic_mode,
        )
    if native_variant != "normal":
        raise ValueError("These constructors have no PSA or Century variant")
    expected = 0x0100030C if native_build == 12 else 0x0100032F
    if profile.catalog.management.version != expected:
        raise ValueError("Profile database differs from selected source build")
    if len(profile.category_record) != 76 or not profile.category or not bus_id:
        raise FrameTransportError(0x90020701, "Selected category and bus required")
    if low == 4 and native_build == 12:
        raise FrameTransportError(0x90020201, "Original12 has no low4 constructor")
    prot = profile.protocol_info(bus_id)
    if prot is None:
        raise FrameTransportError(0x90020104, "Selected protocol record absent")
    address = (
        struct.unpack_from("<I", diagnostic_mode, 8)[0]
        if word(diagnostic_mode, 0) == 1
        else word(prot, 8)
    )
    flags = profile.category_record[72]
    empty = _message(0, b"")
    source = f"DDB:{profile.catalog.management.sha256}:category={profile.category}:bus={bus_id}"
    if low == 4:
        ethernet = _simple_record(profile, 85, 12, 0, word(prot, 2))
        software = _simple_record(profile, 86, 12, 0, word(ethernet, 2))
        startup = _function_request(profile, 0x106, 0x90020501)
        data = (
            b"\x02\xfd\x80\x01"
            + (len(request) + 4).to_bytes(4, "big")
            + word(software, 2).to_bytes(2, "big")
            + word(prot, 8).to_bytes(2, "big")
            + request
        )
        if len(data) > MAX_DATA:
            raise FrameTransportError(0x91020310, "Native Ethernet frame exceeds1020")
        return FramePlan(
            NativeConnect(0x800F, 0),
            (),
            (),
            _message(0x8208, data),
            empty,
            b"",
            startup,
            b"",
            address,
            source,
            driver.source,
        )
    if low == 12:
        info = _simple_record(profile, 15, 56, 4, word(prot, 2))
        _frame_inputs(address, flags, len(request) + 1)
        values = ((1, struct.unpack_from("<I", info)[0]),) + tuple(
            (parameter, word(info, offset))
            for parameter, offset in (
                (6, 30),
                (7, 28),
                (8, 34),
                (9, 32),
                (10, 38 if device_kind == 4 else 50),
                (11, 36),
                (12, 42),
                (13, 40),
                (25, 26),
                (14, 10),
                (0x10005, 8),
                (15, 14),
                (0x10006, 12),
                (16, 18),
                (0x10007, 16),
                (17, 22),
                (0x10008, 20),
                (19, 44),
                (20, 46),
                (21, 48),
            )
        )
        return FramePlan(
            NativeConnect(0x1000D, 0),
            translate_configs(values + ((0x1000A, 0),), driver),
            (),
            _message(3, bytes(((len(request) + 2) & 255,)) + request),
            empty,
            b"",
            b"",
            b"",
            address,
            source,
            driver.source,
        )
    if low == 3:
        header = word(prot, 6 if bus_id & 0xF0 == 0x30 else 8).to_bytes(4, "big")
        if bus_id & 0xF0 == 0x20:
            header += bytes((word(prot, 10) & 255,))
        _frame_inputs(address, flags, len(header) + len(request))
        return FramePlan(
            NativeConnect(5, 0),
            translate_configs(
                (
                    (1, 500000),
                    (0x10100, 8),
                    (0x10102, profile.category & 255),
                    (0x10101, bus_id & 255),
                    (0x10206, 0),
                ),
                driver,
            ),
            (),
            _message(5, header + request, 0x40),
            empty,
            b"",
            b"",
            b"",
            address,
            source,
            driver.source,
        )
    info = _simple_record(profile, 14, 28, 8, word(prot, 2))
    startup = _function_request(profile, 0x67, 0x90020501)
    tester = _function_request(profile, 0x7F, 0x90020502)
    raw = low == 3 or (device_kind in (2, 8) and interface_word == 0)
    protocol = 5 if raw else 6
    values = (
        (1, struct.unpack_from("<I", info, 4)[0]),
        (0x10100, 8),
        (0x10102, 0xE0),
        (0x10101, 0x1F),
    )
    if low != 8 or not raw:
        values += ((0x10103, struct.unpack_from("<I", info)[0]),)
    values += (
        (0x10105, word(info, 16 if native_build == 12 else 18)),
        (0x10206, 0),
        (0x10106, word(info, 12)),
    )
    target = word(prot, 6 if bus_id & 0xF0 == 0x30 else 8)
    if low == 8:
        tat = {0x18: 0xDA, 0x28: 0xCE, 0x38: 0xDB, 0x48: 0xCD}.get(bus_id, 0)
        source_address = _source_address(bus_id, flags)
        if not target or not tat or not source_address:
            raise FrameTransportError(
                0x90020701, "Native extended CAN header is undefined"
            )
        header = bytes((0x18, tat, target & 255, source_address))
        if raw:
            header += bytes((len(request) & 255,))
        elif bus_id & 0xF0 == 0x20:
            header += bytes((word(prot, 10) & 255,))
    else:
        header = target.to_bytes(4, "big")
        if bus_id & 0xF0 == 0x20:
            header += bytes((word(prot, 10) & 255,))
    _frame_inputs(
        address,
        flags,
        len(header)
        + len(request)
        + (1 if low == 8 and raw and bus_id & 0xF0 == 0x20 else 0),
    )
    return FramePlan(
        NativeConnect(protocol, 0x100 if low == 8 else 0),
        translate_configs(values, driver),
        (),
        _message(
            protocol,
            header
            + request
            + (b"\0" if low == 8 and raw and bus_id & 0xF0 == 0x20 else b""),
            0x100 if low == 8 and raw else 0x140 if low == 8 else 0x40,
        ),
        empty,
        b"",
        startup,
        tester,
        address,
        source,
        driver.source,
    )


class ExtendedCanOperations(NativeFrameOperations):
    """Native 4200/4710: four-byte extended address, optional length byte."""

    def _protocol_family(self) -> int:
        return 6

    def _can_filters(self) -> tuple[NativeFilter, ...]:
        source = _source_address(self.bus_id, self.ecu_flags)
        address = (
            struct.unpack_from("<I", self.diagnostic_mode, 8)[0]
            if word(self.diagnostic_mode, 0)
            else word(self.protocol_record, 8)
        )
        prefix = 0x18DA0000
        receive = prefix | source << 8
        transmit = prefix | address << 8 | source
        empty = _message(0, b"")

        def msg(value: int) -> NativeMessage:
            return _message(
                self.plan.send.protocol_id,
                (value & 0xFFFFFFFF).to_bytes(4, "big"),
            )

        def item(
            kind: int, mask: int, pattern: int, flow: int | None = None
        ) -> NativeFilter:
            return NativeFilter(
                kind, msg(mask), msg(pattern), empty if flow is None else msg(flow)
            )

        if self.bus_id & 0xF0 in (0x10, 0x20):
            return (
                item(1, 0x1FFFFF00, receive),
                item(3, 0xFFFFFF, receive | address, transmit),
            )
        if self.bus_id & 0xF0 == 0x30:
            if word(self.diagnostic_mode, 0) == 1:
                mask = 0x1FFFFFFF if self.device_kind == 4 else 0xFFFFFFFF
                return (
                    item(1, 0x1FFFFFFF, receive | address),
                    item(3, mask, receive | address, transmit),
                )
            mask = 0x1FFFFF00 if self.device_kind == 4 else 0xFFFFFF00
            result = (item(1, mask, receive),)
            if self.device_kind == 4:
                result += tuple(
                    item(3, 0x1FFFFFFF, receive | peer, prefix | peer << 8 | source)
                    for peer in range(0x10, 0x20)
                )
            return result
        return ()

    def _frame_message(self, request: bytes) -> NativeMessage:
        header = self.plan.send.data[:4]
        raw = self.plan.send.protocol_id == 5
        if raw:
            header += bytes((len(request) & 255,))
        elif self.bus_id & 0xF0 == 0x20:
            header += bytes((word(self.protocol_record, 10) & 255,))
        tail = b"\0" if raw and self.bus_id & 0xF0 == 0x20 else b""
        _frame_inputs(
            self.plan.address, self.ecu_flags, len(header) + len(request) + len(tail)
        )
        return _message(
            self.plan.send.protocol_id, header + request + tail, self.plan.send.tx_flags
        )

    def _decode_message(
        self, message: NativeMessage, *, maximum: int = MAX_DATA
    ) -> NativeFrameReceive:
        # 4330/4ff0: source is byte3, and raw4710 removes its extra length byte.
        raw = self.plan.send.protocol_id == 5
        header = 5 if raw or self.bus_id & 0xF0 == 0x20 else 4
        tail = 1 if raw and self.bus_id & 0xF0 == 0x20 else 0
        size = len(message.data) - header - tail
        if size < 0 or size > maximum:
            return NativeFrameReceive(code=0x90020601)
        return NativeFrameReceive(
            message.data[header : header + size],
            message.data[3],
            timestamp=message.timestamp,
        )

    def _drop_message(self, message: NativeMessage) -> bool:
        return bool(message.rx_status & ~0x100)

    def _validate_message(self, message: NativeMessage) -> int:
        header = (
            5 if self.plan.send.protocol_id == 5 or self.bus_id & 0xF0 == 0x20 else 4
        )
        if len(message.data) < header:
            return 0x90020601
        payload = message.data[header:]
        if payload[:1] == b"\x7f":
            if len(payload) < 3:
                return 0x90020601
            return {0x78: 0x90020323, 0x21: 0x90020326}.get(payload[2], 0x90020321)
        return 0

    def _runtime_configs(self):
        return (
            self.plan.configs
            if self.plan.send.protocol_id == 5
            else super()._runtime_configs()
        )

    def setup(self, *, deadline: float | None = None) -> int:
        if self.plan.send.protocol_id != 5:
            return super().setup(deadline=deadline)
        until = self._deadline(deadline)
        if self.channel in (None, 0) or self.poisoned:
            return 0x90020701
        if self._configured:
            return 0
        try:
            result = self._ioctl(2, self.plan.configs, until)
            if result.code:
                return self._status(result.code)
            for item in self._can_filters():
                result = self._invoke(
                    "start_message_filter",
                    {
                        "channel_id": self.channel,
                        "filter_type": item.filter_type,
                        "mask": item.mask,
                        "pattern": item.pattern,
                        "flow_control": item.flow_control,
                    },
                    until,
                )
                if result.code:
                    break
            self._configured = True
            return 0
        except BaseException:
            self._fault()
            raise

    def _preinit_function(self):
        return None


class RawCanOperations(NativeFrameOperations):
    """Native 50b0/53e0 reads one zero-status frame without response validation."""

    def _protocol_family(self) -> int:
        return 6

    def setup(self, *, deadline: float | None = None) -> int:
        until = self._deadline(deadline)
        if self.channel in (None, 0) or self.poisoned:
            return 0x90020701
        if self._configured:
            return 0
        try:
            self._ioctl(
                2, self.plan.configs, until
            )  # Native5110 ignores SET_CONFIG status.
            mask = ((~self.bus_id) & 255) << 3
            pattern = (self.profile.category & 255) << 3
            result = self._invoke(
                "start_message_filter",
                {
                    "channel_id": self.channel,
                    "filter_type": 1,
                    "mask": _message(5, mask.to_bytes(4, "big")),
                    "pattern": _message(5, pattern.to_bytes(4, "big")),
                    "flow_control": _message(0, b""),
                },
                until,
            )
            if not result.code:
                self._configured = True
            return self._status(result.code)
        except BaseException as error:
            self._fault_for(error)
            raise

    def _frame_message(self, request: bytes) -> NativeMessage:
        header = 5 if self.bus_id & 0xF0 == 0x20 else 4
        _frame_inputs(self.plan.address, self.ecu_flags, header + len(request))
        return _message(
            5, self.plan.send.data[:header] + request, self.plan.send.tx_flags
        )

    def _decode_message(
        self, message: NativeMessage, *, maximum: int = MAX_DATA
    ) -> NativeFrameReceive:
        return decode_frame_message(
            replace(message, protocol_id=6),
            bus_id=self.bus_id,
            protocol_id=6,
            maximum=maximum,
        )

    def _validate_message(self, message: NativeMessage) -> int:
        return 0

    def _preinit_function(self):
        return None

    def receive(
        self,
        *,
        maximum: int,
        timeout: int,
        argument_5: int = 0,
        flags: int = 100,
        buffer: bool = True,
        deadline: float | None = None,
    ) -> NativeFrameReceive:
        until = self._deadline(deadline)
        for value, bits in (
            (maximum, 16),
            (timeout, 32),
            (argument_5, 16),
            (flags, 32),
        ):
            _uint(value, bits)
        if type(buffer) is not bool:
            raise ValueError("Explicit buffer presence required")
        if self.channel in (None, 0) or self.poisoned or not maximum or not buffer:
            return NativeFrameReceive(code=0x90020701)
        try:
            while True:
                result = self._invoke(
                    "read_messages",
                    {"channel_id": self.channel, "count": 1, "timeout": timeout},
                    until,
                )
                if result.code:
                    return NativeFrameReceive(
                        code=self._status(9 if result.code == 0x10 else result.code)
                    )
                if result.count != 1 or len(result.messages) != 1:
                    raise OSError("Native raw read omitted one message")
                message = result.messages[0]
                if message.rx_status:
                    continue
                decoded = self._decode_message(message, maximum=maximum)
                if not decoded.code:
                    self.last_activity = self._tick()
                return decoded
        except BaseException:
            self._fault()
            raise


class Iso9141Operations(NativeFrameOperations):
    """Native 11c70 uses protocol3 and proprietary initialization IOCTLs."""

    def _frame_message(self, request: bytes) -> NativeMessage:
        _frame_inputs(self.plan.address, self.ecu_flags, len(request) + 1)
        return _message(3, bytes(((len(request) + 2) & 255,)) + request)

    def _decode_message(
        self, message: NativeMessage, *, maximum: int = MAX_DATA
    ) -> NativeFrameReceive:
        if not message.data or len(message.data) - 1 > maximum:
            return NativeFrameReceive(code=0x90020601)
        return NativeFrameReceive(message.data[1:], timestamp=message.timestamp)

    def _validate_message(self, message: NativeMessage) -> int:
        if not message.data:
            return 0x90020601
        return 0 if len(message.data) == (message.data[0] & 63) - 1 else 0x91020324

    def _preinit_function(self):
        return None

    def setup(self, *, deadline: float | None = None) -> int:
        until = self._deadline(deadline)
        if self.channel in (None, 0) or self.poisoned:
            return 0x90020701
        if self._configured:
            return 0
        try:
            result = self._ioctl(2, self.plan.configs, until)
            if not result.code:
                self._configured = True
            return self._status(result.code)
        except BaseException:
            self._fault()
            raise

    def prepare_bus_session(self, *, deadline: float | None = None) -> int:
        until = self._deadline(deadline)
        if self.channel in (None, 0) or self.poisoned:
            return 0x90020701
        info = _simple_record(self.profile, 15, 56, 4, word(self.protocol_record, 2))
        code = self.send(
            bytes((self.plan.address & 255,)),
            timeout=1000,
            initialization_mode=2,
            deadline=until,
        )
        if code:
            return code
        reply = self.receive(maximum=120, timeout=word(info, 32), deadline=until)
        if reply.code:
            return reply.code
        return 0 if reply.data[:1] == b"\x67" else 0x90020328

    def _initialize(self, deadline: float) -> int:
        if self.channel in (None, 0) or not self.plan.address:
            return 0x90020701
        info = _simple_record(self.profile, 15, 56, 4, word(self.protocol_record, 2))
        modes = word(info, 6)
        ioctl_id = 0x10005 if modes & 1 else 0x10004 if modes & 2 else 0
        if not ioctl_id:
            return 0x90020304
        result = self._ioctl(8, None, deadline)
        if result.code:
            return self._status(result.code)
        for _ in range(4):
            result = self._ioctl(
                ioctl_id, bytes((self.plan.address & 255,)), deadline, output_capacity=2
            )
            if not result.code:
                return 0
            if ioctl_id == 0x10005:
                self._wait_ms(300, deadline)
        return self._status(9 if result.code == 7 else result.code)


class EthernetOperations(NativeFrameOperations):
    """Original18 5530: physical Ethernet plus owned IP/UDP/TCP channels."""

    ethernet_backend: EthernetBackend
    ethernet_settings = EthernetSettings()

    def bind_ethernet(
        self, backend: EthernetBackend, settings: EthernetSettings
    ) -> None:
        self.ethernet_backend = backend
        self.ethernet_settings = settings
        self.logical_channels: list[int] = []
        self.ip_channel = self.udp_channel = self.tcp_channel = 0
        self.peer_ip = bytes(4)
        self.peer_port = 0
        self.previous_payload = b""
        self.last_ethernet_frame: NativeMessage | None = None
        self.pending_by_time = True
        self._load_ethernet_records()

    def _load_ethernet_records(self) -> None:
        self.ethernet_record = _simple_record(
            self.profile, 85, 12, 0, word(self.protocol_record, 2)
        )
        self.software_record = _simple_record(
            self.profile, 86, 12, 0, word(self.ethernet_record, 2)
        )
        self.source_address = word(self.software_record, 2)

    def rebind(
        self,
        profile: ProtocolProfile,
        plan: FramePlan,
        *,
        bus_id: int,
        diagnostic_mode: bytes | None = None,
    ) -> None:
        super().rebind(profile, plan, bus_id=bus_id, diagnostic_mode=diagnostic_mode)
        self._load_ethernet_records()

    def _ethernet_call(
        self,
        operation: EthernetPrimitiveName,
        fields: Mapping[str, object],
        deadline: float,
    ) -> J2534Result:
        self._check(deadline)
        self._primitive_uncertain = True
        result = self.ethernet_backend.invoke_ethernet(
            operation,
            MappingProxyType(dict(fields)),
            deadline=deadline,
            cancelled=self.cancelled,
        )
        if not isinstance(result, J2534Result):
            raise TypeError("Ethernet primitive must return J2534Result")
        if len(self.observations) == 256:
            del self.observations[0]
        self.observations.append((operation, result))
        if result.host_boundary and result.host_boundary.endswith("_before"):
            self._primitive_uncertain = False
            self._raise_host_boundary(result.host_boundary)
        if operation == "physical_connect" and result.handle is not None:
            if not result.handle:
                raise OSError("Native physical connect returned a zero handle")
            self.channel, self.owns_channel = result.handle, True
            self._native_close_started = False
            self._configured = False
            self.last_activity = 0
        if (
            not result.code
            and operation == "physical_connect"
            and result.handle is None
        ):
            raise OSError("Native physical connect omitted its owned handle")
        if operation == "logical_connect" and result.handle is not None:
            if not result.handle or result.handle in self.logical_channels:
                raise OSError(
                    "Native logical connect returned invalid/duplicate handle"
                )
            self.logical_channels.append(result.handle)
        if not result.code and operation == "logical_connect" and result.handle is None:
            raise OSError("Native logical connect omitted its owned handle")
        if not result.code and operation == "queue_messages" and result.count != 1:
            raise OSError("Native queue did not confirm one message")
        if (
            not result.code
            and operation == "read_messages"
            and (result.count != 1 or len(result.messages) != 1)
        ):
            raise OSError("Native v0500 read did not confirm one actual message")
        if not result.code and operation == "read_bytes":
            count = fields["count"]
            if (
                not isinstance(count, int)
                or result.count > count
                or result.count != len(result.data)
            ):
                raise OSError("Native byte read did not report actual byte count")
        self._primitive_uncertain = False
        if result.host_boundary:
            self._raise_host_boundary(result.host_boundary)
        self._check(deadline)
        return result

    def _device_ioctl(
        self,
        number: int,
        data: bytes | EthernetResources,
        until: float,
        capacity: int = 0,
    ) -> J2534Result:
        return self._ethernet_call(
            "device_ioctl",
            {
                "ioctl_id": number,
                "input": data,
                "output_capacity": capacity,
            },
            until,
        )

    def _channel_ioctl(
        self,
        channel: int,
        number: int,
        value: object,
        until: float,
        *,
        output_capacity: int = 0,
    ) -> J2534Result:
        return self._ethernet_call(
            "channel_ioctl",
            {
                "channel_id": channel,
                "ioctl_id": number,
                "input": value,
                "output_capacity": output_capacity,
            },
            until,
        )

    def _voltage(self, pin: int, until: float) -> tuple[int, int]:
        # 7d10 uses READ_VBATT with a native RESOURCE_STRUCT containing one pin.
        result = self._device_ioctl(3, EthernetResources(1, (pin,)), until, 4)
        if result.code:
            return self._status(result.code), 0
        if len(result.data) != 4:
            raise OSError("Native voltage primitive omitted its DWORD")
        return 0, int.from_bytes(result.data, "little")

    def _check_voltage(self, until: float) -> int:
        settings = self.ethernet_settings
        self._device_ioctl(
            0x8022, (0xFFFFFFFF).to_bytes(4, "little"), until
        )  # Native ignores first status.
        self._wait_ms(settings.read_voltage_wait, until)
        code, first = self._voltage(8, until)
        if code:
            return code
        if first >= 2000:
            return 0x81020000
        result = self._device_ioctl(0x8022, (0x125C).to_bytes(4, "little"), until)
        if result.code and not settings.mongoose_voltage_skip:
            return self._status(result.code)
        if not result.code:
            self._wait_ms(settings.read_voltage_wait_pullup, until)
            code, pulled = self._voltage(8, until)
            if code:
                return code
            code, reference = self._voltage(16, until)
            if code:
                return code
            if reference >= 16000:
                return 0x81020000
            if not settings.mongoose_voltage_skip:
                ratio = pulled / reference if reference else float("inf")
                if not 0.53 < ratio <= 0.83:
                    return 0x81020000
        for value in (0xFFFFFFFF, 0x1FE):
            result = self._device_ioctl(0x8022, value.to_bytes(4, "little"), until)
            if result.code:
                return self._status(result.code)
        return 0

    def _logical_connect(
        self, parent: int, protocol: int, data: bytes, until: float
    ) -> tuple[int, int]:
        result = self._ethernet_call(
            "logical_connect",
            {
                "channel_id": parent,
                "protocol_id": protocol,
                "flags": 0,
                "input": data,
            },
            until,
        )
        return self._status(result.code), result.handle or 0

    def _read_message(self, channel: int, timeout: int, until: float) -> J2534Result:
        return self._ethernet_call(
            "read_messages",
            {"channel_id": channel, "count": 1, "timeout": timeout},
            until,
        )

    def _read_bytes(self, count: int, timeout: int, until: float) -> J2534Result:
        return self._ethernet_call(
            "read_bytes",
            {
                "channel_id": self.tcp_channel,
                "protocol_id": 0x8208,
                "count": count,
                "timeout": timeout,
            },
            until,
        )

    def _queue(self, channel: int, protocol: int, data: bytes, until: float) -> int:
        message = _message(protocol, data)
        result = self._ethernet_call(
            "queue_messages",
            {
                "channel_id": channel,
                "messages": (message,),
                "count": 1,
            },
            until,
        )
        return self._status(result.code)

    def _packet_log(self, message: NativeMessage) -> None:
        return  # Ethernet logs diagnostic payloads, not link/discovery messages.

    def _log_payload(self, payload: bytes) -> None:
        if self._log_writer is None or not payload:
            return
        record = payload.hex().upper().encode("ascii") + b"\\n"
        try:
            if self._log_writer(record) != len(record):
                raise OSError("Incomplete native Ethernet packet log write")
        except Exception:  # noqa: BLE001 - native disables failed logging, not transport
            self.log_error, self._log_writer = True, None
            if self._log_failure is not None:
                self._log_failure()

    def open(self, *, deadline: float | None = None, setup: bool = True) -> int:
        until = self._deadline(deadline)
        if self.poisoned:
            return 0x90020701
        try:
            if self.channel is not None or self.logical_channels:
                code = self.close(deadline=until)
                if code:
                    return 0x91020306
            code = self._check_voltage(until)
            if not code:
                self._wait_ms(self.ethernet_settings.connect_delay, until)
                result = self._ethernet_call(
                    "physical_connect",
                    {
                        "protocol_id": 0x800F,
                        "flags": 0,
                        "baud_rate": 100000000,
                        "resources": EthernetResources(1, (3, 11, 12, 13)),
                    },
                    until,
                )
                code = self._status(result.code)
            if not code:
                code = self.setup(deadline=until) if setup else 0
            if code:
                return 0x91020306  # 56d0 maps every native preparation failure.
            return 0
        except BaseException as error:
            self._fault_for(error)
            raise

    def setup(self, *, deadline: float | None = None) -> int:
        until = self._deadline(deadline)
        if self.channel in (None, 0) or self.poisoned:
            return 0x90020701
        if self._configured:
            return 0
        try:
            result = self._channel_ioctl(
                self.channel, 2, (NativeConfig(0x805F, 1),), until
            )
            if result.code:
                return self._status(result.code)
            result = self._read_message(
                self.channel, word(self.software_record, 4), until
            )
            if result.code:
                return self._status(result.code)
            if not result.messages[0].rx_status & 0x10000:
                return 0x81020000
            code, self.ip_channel = self._logical_connect(
                self.channel,
                0x8203,
                b"\x01"
                + struct.pack("<I", self.ethernet_settings.connect_ip_timeout)
                + bytes(16),
                until,
            )
            if code:
                return code
            code, self.udp_channel = self._logical_connect(
                self.ip_channel,
                0x8205,
                struct.pack("<H", self.ethernet_settings.source_udp_port),
                until,
            )
            if code:
                return code
            result = self._channel_ioctl(self.udp_channel, 8, None, until)
            if result.code:
                return self._status(result.code)
            code = self._queue(
                self.udp_channel,
                0x8205,
                bytes.fromhex("ffffffff3458ff00000100000000"),
                until,
            )
            if code:
                return code
            result = self._read_message(
                self.udp_channel, word(self.software_record, 6), until
            )
            if result.code:
                return self._status(result.code)
            data = result.messages[0].data
            if len(data) < 46:
                return 0x91020324
            if int.from_bytes(data[8:10], "big") != 4:
                return 0x81020000
            self.peer_ip, self.peer_port = data[:4], int.from_bytes(data[4:6], "big")
            code, self.tcp_channel = self._logical_connect(
                self.ip_channel,
                0x8206,
                struct.pack(
                    "<HH", self.ethernet_settings.source_tcp_port, self.peer_port
                )
                + self.peer_ip,
                until,
            )
            if code:
                return code
            result = self._channel_ioctl(self.tcp_channel, 8, None, until)
            if result.code:
                return self._status(result.code)
            routing = (
                b"\x02\xfd\x00\x05\x00\x00\x00\x07"
                + self.source_address.to_bytes(2, "big")
                + bytes(5)
            )
            code = self._queue(self.tcp_channel, 0x8208, routing, until)
            if code:
                return code
            result = self._read_bytes(17, word(self.software_record, 8), until)
            if result.code:
                return self._status(result.code)
            if len(result.data) < 13:
                return 0x91020324
            if int.from_bytes(result.data[2:4], "big") != 6:
                return 0x81020000
            self._configured = True
            self.current_category = self.profile.category
            return 0
        except BaseException as error:
            self._fault_for(error)
            raise

    def _frame_message(self, request: bytes) -> NativeMessage:
        if len(request) + 12 > MAX_DATA:
            raise FrameTransportError(
                0x91020310, "Native Ethernet send buffer exceeded"
            )
        address = word(
            self.protocol_record, 6 if 1 <= self.current_service <= 15 else 8
        )
        data = (
            b"\x02\xfd\x80\x01"
            + (len(request) + 4).to_bytes(4, "big")
            + self.source_address.to_bytes(2, "big")
            + address.to_bytes(2, "big")
            + request
        )
        return _message(0x8208, data)

    def _response_address(self) -> int:
        if word(self.diagnostic_mode, 0) == 1:
            return struct.unpack_from("<I", self.diagnostic_mode, 8)[0]
        return word(self.protocol_record, 20 if 1 <= self.current_service <= 15 else 8)

    def _decode_message(
        self, message: NativeMessage, *, maximum: int = MAX_DATA
    ) -> NativeFrameReceive:
        if len(message.data) < 4 or len(message.data) - 4 > maximum:
            return NativeFrameReceive(code=0x90020601)
        return NativeFrameReceive(
            message.data[4:],
            int.from_bytes(message.data[:2], "big"),
            timestamp=message.timestamp,
        )

    def _validate_message(self, message: NativeMessage) -> int:
        data = message.data
        if len(data) >= 7 and data[4] == 0x7F:
            return {0x78: 0x90020323, 0x21: 0x90020326}.get(data[6], 0x90020321)
        return 0

    def send(
        self,
        request: bytes | None,
        *,
        timeout: int,
        initialization_mode: int = 1,
        clear_rx: int = 1,
        no_session: bool = False,
        deadline: float | None = None,
    ) -> int:
        until = self._deadline(deadline)
        _uint(timeout)
        _uint(initialization_mode, 8)
        if type(clear_rx) is not int or not -(1 << 31) <= clear_rx < 1 << 32:
            raise ValueError("Native clear-RX argument must fit a word")
        if type(no_session) is not bool:
            raise ValueError("Explicit NoSession flag required")
        if request is not None and (
            not isinstance(request, bytes) or len(request) > 65535
        ):
            raise ValueError("Bounded native request bytes required")
        if (
            not self.tcp_channel
            or self.poisoned
            or not self.plan.address
            or (request is None and initialization_mode != 0)
        ):
            return 0x90020701
        try:
            if initialization_mode == 0:
                self.force_initialization = True
            if initialization_mode != 2 and self._needs_initialize(
                (self._tick() - self.last_activity) & 0xFFFFFFFF
            ):
                code = self._initialize(until)
                if code and initialization_mode != 0x11:
                    return code
                if not code:
                    self.last_activity = self._tick()
                    self.force_initialization = False
            if request is None:
                return 0
            if len(request) + 12 > MAX_DATA:
                return 0x91020310
            message = self._frame_message(request)
            if clear_rx == 1:
                self._channel_ioctl(self.tcp_channel, 8, None, until)
            self.last_ethernet_frame = message
            code = self._queue(self.tcp_channel, 0x8208, message.data, until)
            if not code:
                self.previous_payload = request
                self.last_send_tick = self._tick()
                self._log_payload(request)
            return code
        except BaseException as error:
            self._fault_for(error)
            raise

    def _initialize(self, deadline: float) -> int:
        code = self.send(
            self.plan.startup_request[: len(self.plan.startup_request) & 255],
            timeout=1000,
            initialization_mode=2,
            deadline=deadline,
        )
        if code:
            return code
        reply = self.receive(maximum=65535, timeout=1000, deadline=deadline)
        if reply.code:
            return reply.code
        return (
            0
            if reply.data[:1] == bytes(((self.plan.startup_request[0] + 0x40) & 255,))
            else 0x91020306
        )

    def _needs_initialize(self, elapsed: int) -> bool:
        return not 1 <= self.current_service <= 15 and (
            self.force_initialization or elapsed >= self.communication_interval
        )

    def receive(
        self,
        *,
        maximum: int,
        timeout: int,
        argument_5: int = 0,
        flags: int = 100,
        buffer: bool = True,
        deadline: float | None = None,
    ) -> NativeFrameReceive:
        until = self._deadline(deadline)
        for value, bits in (
            (maximum, 16),
            (timeout, 32),
            (argument_5, 16),
            (flags, 32),
        ):
            _uint(value, bits)
        if type(buffer) is not bool:
            raise ValueError("Explicit buffer presence required")
        if not self.tcp_channel or self.poisoned or not maximum or not buffer:
            return NativeFrameReceive(code=0x90020701)
        self.pending_count = 0
        ack = True
        retry = 0
        first_source: int | None = None
        state = self.current_service
        normal_timeout = word(self.ethernet_record, 6 if 1 <= state <= 15 else 4)
        pending_timeout = word(self.ethernet_record, 10 if 1 <= state <= 15 else 8)
        current_timeout = normal_timeout
        try:
            while True:
                if ack:
                    result = self._read_bytes(13, word(self.software_record, 10), until)
                    if result.code:
                        return NativeFrameReceive(
                            code=self._status(9 if result.code == 16 else result.code)
                        )
                    if len(result.data) < 13:
                        return NativeFrameReceive(code=0x91020324)
                    if int.from_bytes(result.data[2:4], "big") != 0x8002:
                        return NativeFrameReceive(code=0x81020000)
                    if (
                        int.from_bytes(result.data[8:10], "big")
                        != self._response_address()
                    ):
                        return NativeFrameReceive(code=0x91020325)
                result = self._read_bytes(8, current_timeout, until)
                if result.code:
                    return NativeFrameReceive(
                        code=self._status(9 if result.code == 16 else result.code)
                    )
                if len(result.data) < 8:
                    return NativeFrameReceive(code=0x91020324)
                if int.from_bytes(result.data[2:4], "big") != 0x8001:
                    return NativeFrameReceive(code=0x81020000)
                size = int.from_bytes(result.data[4:8], "big")
                if size <= 4 or size - 4 > maximum:
                    return NativeFrameReceive(code=0x91020324)
                expected = min(MAX_DATA, size)
                result = self._read_bytes(expected, current_timeout, until)
                if result.code:
                    return NativeFrameReceive(
                        code=self._status(9 if result.code == 16 else result.code)
                    )
                if result.count != expected:
                    return NativeFrameReceive(code=0x91020324)
                received = bytearray(result.data)
                message = _message(0x8208, bytes(received[:MAX_DATA]))
                source = int.from_bytes(received[:2], "big")
                payload = bytes(received[4:])
                code = self._validate_message(message)
                if code:
                    self._log_payload(payload)
                if code == 0x90020323:
                    self.last_activity = self._tick()
                    if first_source is None:
                        first_source, self.pending_count = source, 1
                    elif source == first_source:
                        self.pending_count += 1
                    if ((self.last_send_tick + 180000) & 0xFFFFFFFF) <= self._tick():
                        return NativeFrameReceive(code=0x90020323)
                    ack = False
                    current_timeout = pending_timeout
                    continue
                if code == 0x90020326:
                    self.last_activity = self._tick()
                    retry += 1
                    self.pending_count, first_source = 0, None
                    if retry >= 256:
                        return NativeFrameReceive(code=0x90020323)
                    if self.last_ethernet_frame is None:
                        return NativeFrameReceive(code=0x91020310)
                    code = self._queue(
                        self.tcp_channel, 0x8208, self.last_ethernet_frame.data, until
                    )
                    if code:
                        return NativeFrameReceive(code=0x91020310)
                    self.last_send_tick = self._tick()
                    self._log_payload(self.previous_payload)
                    ack = True
                    current_timeout = normal_timeout
                    continue
                if code:
                    self.last_activity = self._tick()
                    return NativeFrameReceive(payload, source, code=code)
                if source != self._response_address():
                    return NativeFrameReceive(code=0x91020325)
                while len(received) < size:
                    expected = min(MAX_DATA, size - len(received))
                    result = self._read_bytes(expected, current_timeout, until)
                    if result.code:
                        return NativeFrameReceive(
                            code=self._status(9 if result.code == 16 else result.code)
                        )
                    if result.count != expected:
                        return NativeFrameReceive(code=0x91020324)
                    received += result.data
                payload = bytes(received[4:])
                self._log_payload(payload)
                self.last_activity = self._tick()
                return NativeFrameReceive(payload, source)
        except BaseException as error:
            self._fault_for(error)
            raise

    def session_state(self, *, deadline: float | None = None) -> tuple[int, int]:
        """Native virtual14c/8970: status8023, retaining its zero-initialized DWORD."""
        until = self._deadline(deadline)
        if not self.tcp_channel:
            return 0, 0
        try:
            result = self._channel_ioctl(
                self.tcp_channel, 0x8023, None, until, output_capacity=4
            )
            if not result.code and len(result.data) != 4:
                raise OSError("Native Ethernet session status omitted its DWORD")
            if result.data and len(result.data) != 4:
                raise OSError("Native Ethernet session status returned a partial DWORD")
            return self._status(result.code), int.from_bytes(
                result.data, "little"
            ) if result.data else 0
        except BaseException as error:
            self._fault_for(error)
            raise

    def release_channels(self, *, deadline: float | None = None) -> int:
        """Native virtual158/8800 used before ChangeCommIF reload/reopen; no D1."""
        return self.close(deadline=deadline, native_session=False)

    def close(
        self, *, deadline: float | None = None, native_session: bool = True
    ) -> int:
        # Host cleanup preserves failed ownership; native clears it unconditionally.
        if type(native_session) is not bool:
            raise ValueError("Explicit native session cleanup selection required")
        if deadline is not None and (
            isinstance(deadline, bool)
            or not isinstance(deadline, (int, float))
            or not math.isfinite(deadline)
        ):
            raise ValueError("Finite cleanup deadline required")
        cleanup_clock = self._now
        clock_failed = False
        try:
            now = cleanup_clock()
        except Exception as error:
            if deadline is not None:
                raise
            self.cleanup_error = error
            cleanup_clock, clock_failed = time.monotonic, True
            now = cleanup_clock()
        until = now + 5 if deadline is None else deadline
        if (
            self.tcp_channel
            and self.current_category
            and not self.poisoned
            and not self._native_close_started
            and not clock_failed
            and native_session
        ):
            self._native_close_started = True
            original_cancelled = self.cancelled
            self.cancelled = lambda: False
            try:
                self.pre_initialize(deadline=until)
            finally:
                self.cancelled = original_cancelled
        first = 0
        for handle in tuple(reversed(self.logical_channels)):
            if cleanup_clock() >= until:
                raise TimeoutError("Ethernet logical cleanup deadline expired")
            result = self.ethernet_backend.invoke_ethernet(
                "logical_disconnect",
                {"channel_id": handle},
                deadline=until,
                cancelled=lambda: False,
            )
            if not isinstance(result, J2534Result):
                raise TypeError("Ethernet cleanup must return J2534Result")
            if result.host_boundary and result.host_boundary.endswith("_before"):
                self._raise_host_boundary(result.host_boundary)
            if result.code:
                first = first or self._status(result.code)
            else:
                self.logical_channels.remove(handle)
                if handle == self.ip_channel:
                    self.ip_channel = 0
                if handle == self.udp_channel:
                    self.udp_channel = 0
                if handle == self.tcp_channel:
                    self.tcp_channel = 0
            if result.host_boundary:
                self._raise_host_boundary(result.host_boundary)
            if result.code:
                break  # Retain parents while a child's ownership is unresolved.
            self.wait(self.ethernet_settings.disconnect_wait / 1000)
        if self.logical_channels:
            return first
        if self.channel is not None and self.owns_channel:
            if cleanup_clock() >= until:
                raise TimeoutError("Ethernet physical cleanup deadline expired")
            result = self.ethernet_backend.invoke_ethernet(
                "physical_disconnect",
                {"channel_id": self.channel},
                deadline=until,
                cancelled=lambda: False,
            )
            if not isinstance(result, J2534Result):
                raise TypeError("Ethernet physical cleanup must return J2534Result")
            if result.host_boundary and result.host_boundary.endswith("_before"):
                self._raise_host_boundary(result.host_boundary)
            if not result.code:
                self.channel, self.owns_channel = None, False
                self.current_category = 0
                self._configured = False
            if result.host_boundary:
                self._raise_host_boundary(result.host_boundary)
            self.wait(self.ethernet_settings.disconnect_wait / 1000)
            if cleanup_clock() >= until:
                raise TimeoutError("Ethernet physical cleanup deadline expired")
            return self._status(result.code)
        self.channel = None
        return first

    def _preinit_function(self):
        return (0xD1, 65535, 0) if self.preinit_d1_suppressed == 0 else None

    def pre_initialize(self, *, deadline: float | None = None) -> int:
        code = super().pre_initialize(deadline=deadline)
        self.last_activity = 0
        return code

    def send_function(
        self,
        function: int,
        *,
        initialization_mode: int = 1,
        no_session: bool = False,
        deadline: float | None = None,
    ) -> int:
        """76c0 ignores transport statuses and enables the subsequent D1 helper."""
        until = self._deadline(deadline)
        _uint(function, 16)
        _uint(initialization_mode, 8)
        if type(no_session) is not bool:
            raise ValueError("Explicit NoSession flag required")
        try:
            request = _function_request(self.profile, function, 0x90020104)
        except (FrameTransportError, ToyotaCodecError) as error:
            return (
                error.status if isinstance(error, FrameTransportError) else error.code
            )
        self.send(
            request[: len(request) & 255],
            timeout=1000,
            initialization_mode=initialization_mode,
            no_session=no_session,
            deadline=until,
        )
        self.receive(maximum=65535, timeout=0, deadline=until)
        self.preinit_d1_suppressed = 0
        return 0

    def drain(self, *, deadline: float | None = None) -> int:
        self._deadline(deadline)
        return 0  # Low4 virtual44 is native constant2570, not CAN drain2e00.


def create_lower_transport(
    profile: ProtocolProfile,
    request: bytes,
    backend: J2534Backend,
    *,
    native_build: Literal[12, 18],
    bus_id: int,
    driver: DriverProperties,
    device_kind: int,
    interface_word: int = 0,
    diagnostic_mode: bytes = bytes(16),
    native_variant: Variant = "normal",
    open_baud: int = 0,
    communication_interval: int = 4500,
    clock: Callable[[], float] = time.monotonic,
    cancelled: Callable[[], bool] | None = None,
    wait: Callable[[float], None] = time.sleep,
    shared_state: NativeSharedState | None = None,
    ethernet_settings: EthernetSettings | None = None,
) -> NativeFrameOperations:
    if (
        bus_id & 15 == 4
        and native_build == 18
        and not isinstance(backend, EthernetBackend)
    ):
        raise TypeError(
            "Low4 requires actual EthernetBackend.invoke_ethernet primitives"
        )
    if ethernet_settings is not None and not isinstance(
        ethernet_settings, EthernetSettings
    ):
        raise TypeError("Explicit native Ethernet settings required")
    plan = lower_frame_plan(
        profile,
        request,
        native_build=native_build,
        bus_id=bus_id,
        driver=driver,
        device_kind=device_kind,
        interface_word=interface_word,
        diagnostic_mode=diagnostic_mode,
        native_variant=native_variant,
    )
    cls = {
        3: RawCanOperations,
        4: EthernetOperations,
        8: ExtendedCanOperations,
        12: Iso9141Operations,
    }.get(bus_id & 15, NativeFrameOperations)
    instance = cls(
        profile,
        plan,
        backend,
        native_build=native_build,
        bus_id=bus_id,
        driver=driver,
        device_kind=device_kind,
        diagnostic_mode=diagnostic_mode,
        native_variant=native_variant,
        open_baud=open_baud,
        communication_interval=communication_interval,
        clock=clock,
        cancelled=cancelled,
        wait=wait,
        shared_state=shared_state,
    )
    if isinstance(instance, EthernetOperations):
        if not isinstance(backend, EthernetBackend):
            raise TypeError("Low4 requires actual Ethernet primitives")
        instance.bind_ethernet(backend, ethernet_settings or EthernetSettings())
    return instance
