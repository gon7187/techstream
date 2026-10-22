"""Selected native communication metadata and injected J2534 primitives.

Importing or constructing these objects performs no device, file or network I/O.
"""

from __future__ import annotations

import math
import re
import struct
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal, Protocol

from scripts.profiles import ProtocolProfile
from scripts.support import correspondence_rows, word
from scripts.toyota import ToyotaCodecError, VariableTable

if TYPE_CHECKING:
    from scripts.monitor_dual import DualTarget

MAX_DATA = 0x1020

J2534Operation = Literal[
    "connect",
    "disconnect",
    "ioctl",
    "start_message_filter",
    "stop_message_filter",
    "write_messages",
    "read_messages",
    "start_periodic_message",
    "stop_periodic_message",
]


class _HostCancellation(InterruptedError):
    """Cancellation observed by the host at a confirmed primitive boundary."""


class _HostDeadline(TimeoutError):
    """Deadline observed by the host at a confirmed primitive boundary."""


class _HostClockError(ValueError):
    """A host clock failed without creating a driver primitive outcome."""


class FrameTransportError(ValueError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _uint(value: int, bits: int = 32) -> int:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f"Expected uint{bits}")
    return value


@dataclass(frozen=True)
class NativeMessage:
    protocol_id: int
    rx_status: int
    tx_flags: int
    timestamp: int
    extra_data_index: int
    data: bytes

    def __post_init__(self) -> None:
        for value in (
            self.protocol_id,
            self.rx_status,
            self.tx_flags,
            self.timestamp,
            self.extra_data_index,
        ):
            _uint(value)
        if not isinstance(self.data, bytes) or len(self.data) > MAX_DATA:
            raise ValueError("PASSTHRU_MSG data exceeds 4128-byte native storage")

    @property
    def header_words(self) -> tuple[int, int, int, int, int, int]:
        return (
            self.protocol_id,
            self.rx_status,
            self.tx_flags,
            self.timestamp,
            len(self.data),
            self.extra_data_index,
        )

    def encode(self) -> bytes:
        return struct.pack("<6I", *self.header_words) + self.data

    @classmethod
    def decode(cls, data: bytes) -> NativeMessage:
        if not isinstance(data, bytes) or not 24 <= len(data) <= 24 + MAX_DATA:
            raise ValueError("Truncated or oversized PASSTHRU_MSG")
        protocol, rx, tx, timestamp, size, extra = struct.unpack_from("<6I", data)
        if size != len(data) - 24:
            raise ValueError("PASSTHRU_MSG DataSize disagrees with supplied bytes")
        return cls(protocol, rx, tx, timestamp, extra, data[24:])


@dataclass(frozen=True)
class NativeConnect:
    """Native CONECT/DRS200 carries two DWORDs; baud is not a third field."""

    protocol_id: int
    flags: int

    def __post_init__(self) -> None:
        _uint(self.protocol_id)
        _uint(self.flags)

    def encode(self) -> bytes:
        return struct.pack("<II", self.protocol_id, self.flags)


@dataclass(frozen=True)
class NativeConfig:
    parameter: int
    value: int

    def __post_init__(self) -> None:
        _uint(self.parameter)
        _uint(self.value)

    def encode(self) -> bytes:
        return struct.pack("<II", self.parameter, self.value)


@dataclass(frozen=True)
class NativeFilter:
    filter_type: int
    mask: NativeMessage
    pattern: NativeMessage
    flow_control: NativeMessage

    def __post_init__(self) -> None:
        _uint(self.filter_type)
        if not all(
            isinstance(message, NativeMessage)
            for message in (self.mask, self.pattern, self.flow_control)
        ):
            raise TypeError("Filter requires three explicit native messages")


@dataclass(frozen=True)
class DriverProperties:
    """Explicit observed PassThruReadVersion result, never a queried device."""

    version_status: int
    api_version: bytes
    source: str

    def __post_init__(self) -> None:
        _uint(self.version_status)
        if not isinstance(self.api_version, bytes) or len(self.api_version) > 80:
            raise ValueError("Observed API version exceeds its native output buffer")
        if not isinstance(self.source, str) or not 1 <= len(self.source) <= 4096:
            raise ValueError("Explicit bounded driver-property source required")
        if (
            not self.version_status
            and re.fullmatch(rb"[0-9]{2}\.[0-9]{2}(?:\.[0-9]+)?\x00?", self.api_version)
            is None
        ):
            # Native atoi reads fixed positions in its output buffer. Reject an
            # incomplete/malformed observation rather than invent unwritten bytes.
            raise ValueError("Observed API version lacks the native NN.NN format")

    @property
    def api_word(self) -> int:
        if self.version_status:
            return 0
        return (int(self.api_version[:2]) << 8) + int(self.api_version[3:5])


@dataclass(frozen=True)
class FramePlan:
    connect: NativeConnect
    configs: tuple[NativeConfig, ...]
    filters: tuple[NativeFilter, ...]
    send: NativeMessage
    initialization_message: NativeMessage
    init_bytes: bytes
    startup_request: bytes
    tester_request: bytes
    address: int
    source: str
    driver_source: str


def _translated_configs(
    values: tuple[tuple[int, int], ...], driver: DriverProperties
) -> tuple[NativeConfig, ...]:
    """Native 182c0/183d0: omit unsupported IDs, preserve order/duplicates."""
    result = []
    remap = {0x10005: 14, 0x10006: 15, 0x10007: 16, 0x10008: 17}
    omitted = {
        14,
        15,
        16,
        17,
        0x10009,
        0x10100,
        0x10101,
        0x10102,
        0x10105,
        0x10206,
        0x10300,
        0x10301,
    }
    for parameter, value in values:
        _uint(parameter)
        _uint(value)
        if driver.api_word >= 0x305 and 6 <= parameter <= 13:
            value = value * 2 & 0xFFFFFFFF
        if len(result) == 32:
            raise FrameTransportError(0xC0020203, "Native configuration list is full")
        if parameter in omitted:
            continue
        result.append(NativeConfig(remap.get(parameter, parameter), value))
    return tuple(result)


translate_configs = _translated_configs


def _simple_record(
    profile: ProtocolProfile, slot: int, width: int, key_offset: int, key: int
) -> bytes:
    section = profile.catalog.management.sections.get(slot)
    if section is None:
        raise FrameTransportError(0xA0030107, "Selected transport table is absent")
    for row in section.rows(width):
        if word(row, key_offset) == key:
            return row
    raise FrameTransportError(0x90020104, "Selected transport record is absent")


def _function_request(
    profile: ProtocolProfile, function: int, empty_status: int
) -> bytes:
    database = profile.catalog.management
    if 18 not in database.sections:
        raise FrameTransportError(0xA0030107, "Native function table is absent")
    functions = correspondence_rows(database, 18, profile.exception_ids)
    row = next(
        (
            row
            for row in functions
            if word(row, 0) == profile.category and word(row, 2) == function
        ),
        None,
    )
    if row is None:
        raise FrameTransportError(
            0x90020104, "Required native initialization function is absent"
        )
    frame = _simple_record(profile, 17, 8, 0, word(row, 6))
    section = database.sections.get(0)
    if section is None:
        raise FrameTransportError(0xA0030107, "Native variable table is absent")
    request = VariableTable(section.payload, section.count).get(word(frame, 2))
    if not request:
        raise FrameTransportError(
            empty_status, "Required native initialization request is empty"
        )
    return request


def _message(protocol: int, data: bytes, flags: int = 0) -> NativeMessage:
    return NativeMessage(protocol, 0, flags, 0, len(data), data)


def _source_address(bus: int, ecu_flags: int) -> int:
    if bus & 15 in (1, 6, 7, 8, 9):
        return 0xF1 if ecu_flags & 0xE0 == 0x80 else 0xF0
    return 0


def _frame_inputs(address: int, flags: int, size: int) -> None:
    if not address or not flags:
        raise FrameTransportError(
            0x90020701, "Native frame address and category flags must be nonzero"
        )
    if size > MAX_DATA:
        raise FrameTransportError(
            0x90020702, "Native protocol header exceeds message storage"
        )


def get_comm_frame(
    profile: ProtocolProfile,
    request: bytes,
    *,
    bus_id: int,
    driver: DriverProperties,
    diagnostic_mode: bytes = bytes(16),
) -> FramePlan:
    """Pure native GetCommFrame export semantics, without runtime class selection."""
    return _selected_frame_plan(
        profile, request, bus_id=bus_id, driver=driver, diagnostic_mode=diagnostic_mode
    )


def runtime_frame_plan(
    profile: ProtocolProfile,
    request: bytes,
    *,
    native_build: Literal[12, 18],
    native_variant: Literal["normal", "psa", "psa_wwh", "dual", "multi", "century"],
    bus_id: int,
    driver: DriverProperties,
    diagnostic_mode: bytes = bytes(16),
) -> FramePlan:
    """Selected lower-class metadata; PSA setup never requires the unused 7f frame."""
    if type(native_build) is not int or native_build not in (12, 18):
        raise ValueError("Explicit recovered native source build required")
    if native_variant not in ("normal", "psa", "psa_wwh", "dual", "multi", "century"):
        raise ValueError("Unsupported recovered native class variant")
    if native_variant == "psa_wwh" and native_build != 18:
        raise ValueError("WWH subclass is absent from native build12")
    if native_variant not in ("dual", "multi") and bus_id & 15 not in (1, 2, 6, 7, 9):
        raise FrameTransportError(
            0x90020101,
            "This actual native runtime subclass still requires reconstruction",
        )
    return _selected_frame_plan(
        profile,
        request,
        bus_id=bus_id,
        driver=driver,
        diagnostic_mode=diagnostic_mode,
        runtime_psa=native_variant in ("psa", "psa_wwh", "dual"),
        runtime_multi=native_variant == "multi",
        runtime_seed=True,
        runtime_protocol=(
            6
            if native_variant in ("dual", "multi")
            else (2 if bus_id & 15 == 6 else None)
        ),
    )


def _selected_frame_plan(
    profile: ProtocolProfile,
    request: bytes,
    *,
    bus_id: int,
    driver: DriverProperties,
    diagnostic_mode: bytes = bytes(16),
    runtime_psa: bool = False,
    runtime_multi: bool = False,
    runtime_seed: bool = False,
    runtime_protocol: int | None = None,
) -> FramePlan:
    """Native selected DB joins and packet generation, with no implicit I/O."""
    if not isinstance(profile, ProtocolProfile) or not isinstance(
        driver, DriverProperties
    ):
        raise TypeError("Selected profile and observed driver properties required")
    _uint(bus_id, 16)
    if (
        not isinstance(request, bytes)
        or (not request and not runtime_seed)
        or len(request) > 0xFFFF
    ):
        raise FrameTransportError(
            0x90020701, "Nonempty bounded native request required"
        )
    if not isinstance(diagnostic_mode, bytes) or len(diagnostic_mode) != 16:
        raise ValueError("DIAGNOSTIC_INFO must contain exactly sixteen bytes")
    if profile.catalog.management.version not in (0x0100030C, 0x0100032F):
        raise ValueError("Only recovered version12/18 transport databases are accepted")
    if (
        not isinstance(profile.category_record, bytes)
        or len(profile.category_record) != 76
    ):
        raise ValueError("Selected ECU category record must contain 76 bytes")
    if not profile.category or not bus_id:
        raise FrameTransportError(0x90020701, "Native category and bus must be nonzero")
    low, high = bus_id & 15, bus_id & 0xF0
    if (
        runtime_protocol != 6
        and low not in (1, 2, 7, 9, 12)
        and not (low == 6 and runtime_protocol == 2)
    ):
        raise FrameTransportError(
            0x90020101, "Native GetCommFrame protocol is unsupported"
        )
    try:
        prot = profile.protocol_info(bus_id)
        if prot is None:
            raise FrameTransportError(
                0x90020104, "Selected protocol information is absent"
            )
        flags = profile.category_record[72]
        physical, functional, slow_address = word(prot, 8), word(prot, 6), word(prot, 4)
        address = (
            struct.unpack_from("<I", diagnostic_mode, 8)[0]
            if word(diagnostic_mode, 0) == 1
            else physical
        )
        source = _source_address(bus_id, flags)
        empty = NativeMessage(0, 0, 0, 0, 0, b"")
        initialization, init_bytes, filters = empty, b"", ()
        if low == 2 or runtime_protocol == 6:
            info = _simple_record(profile, 14, 28, 8, word(prot, 2))
            startup = (
                b"" if runtime_multi else _function_request(profile, 0x67, 0x90020501)
            )
            psa = flags & 0x1F == 0x14
            tester = (
                b""
                if (psa or runtime_psa) and not runtime_multi
                else _function_request(profile, 0x7F, 0x90020502)
            )
            _frame_inputs(address, flags, len(request) + (5 if high == 0x20 else 4))
            values = (
                (1, struct.unpack_from("<I", info, 4)[0]),
                (0x10100, 8),
                (0x10102, 0xE0),
                (0x10101, 0x1F),
                (0x10103, struct.unpack_from("<I", info)[0]),
                (
                    0x10105,
                    word(
                        info,
                        16 if profile.catalog.management.version == 0x0100030C else 18,
                    ),
                ),
                (0x10206, 0),
                (0x10106, word(info, 12)),
            )
            connect = NativeConnect(6, 0x80 if bus_id == 0x22 else 0)
            target = functional if high == 0x30 else physical
            payload = b"\x00\x00" + target.to_bytes(2, "big")
            if high == 0x20:
                payload += bytes((word(prot, 10) & 255,))
            payload += request
            send = _message(6, payload, 0x40)
            if high in (0x10, 0x20):
                filter_address = (
                    struct.unpack_from("<I", diagnostic_mode, 8)[0]
                    if word(diagnostic_mode, 0)
                    else physical
                )

                def identifier(value: int) -> NativeMessage:
                    return _message(6, value.to_bytes(4, "big"))

                filters = (
                    NativeFilter(
                        1, identifier(0x7FF), identifier(filter_address | 8), empty
                    ),
                    NativeFilter(
                        3,
                        identifier(0xFFFFFFFF if psa else 0x7FF),
                        identifier(physical | 8),
                        identifier(physical),
                    ),
                )
        elif low == 7 or runtime_protocol == 2:
            info = _simple_record(profile, 51, 16, 0, word(prot, 2))
            startup = _function_request(profile, 0x98, 0x90020501)
            try:
                tester = _function_request(profile, 0x7F, 0x90020502)
            except (FrameTransportError, ToyotaCodecError) as error:
                # J1850 ignores the tester-helper status, then checks the fresh
                # object's empty tester pointer/length (13040). CAN propagates it.
                raise FrameTransportError(
                    0x90020502, "Required J1850 tester request is unavailable"
                ) from error
            _frame_inputs(address, flags, len(request) + 3)
            values = ((1, struct.unpack_from("<I", info, 4)[0]),)
            protocol = 2 if runtime_protocol == 2 else 1
            connect = NativeConnect(protocol, 0)
            target = functional if high == 0x10 else physical
            send = _message(
                protocol,
                bytes((0x61 if protocol == 2 else 0x68, target & 255, source))
                + request,
            )
        else:
            info = _simple_record(profile, 15, 56, 4, word(prot, 2))
            startup = _function_request(profile, 0x68, 0x90020501)
            tester = _function_request(profile, 0x7F, 0x90020502)
            _frame_inputs(address, flags, len(request) + 3)
            values = ((1, struct.unpack_from("<I", info)[0]),) + tuple(
                (parameter, word(info, offset))
                for parameter, offset in (
                    (6, 30),
                    (7, 28),
                    (8, 34),
                    (9, 32),
                    (10, 38),
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
            connect = NativeConnect(4, 0)
            control, target = {
                0x10: (0x80, physical),
                0x50: (0x80, physical),
                0x20: (0x68, 0x6A),
                0x30: (0xC0, functional),
            }.get(high, (0, 0))

            def iso_header(body: bytes) -> bytes:
                return (
                    bytes(
                        (
                            control if high == 0x20 else control | (len(body) & 255),
                            target & 255,
                            source,
                        )
                    )
                    + body
                )

            send = _message(4, iso_header(request))
            init_flags = word(info, 6)
            if init_flags & 1:
                if len(startup) + 3 > 64:
                    raise ValueError(
                        "Native fast-init scratch storage is only 64 bytes"
                    )
                initialization = _message(4, iso_header(startup))
            if init_flags & 2:
                if not slow_address:
                    raise FrameTransportError(
                        0x90020701, "Native slow-init address is missing"
                    )
                init_bytes = bytes((slow_address & 255,))
        return FramePlan(
            connect,
            _translated_configs(values, driver),
            filters,
            send,
            initialization,
            init_bytes,
            startup,
            tester,
            address,
            f"DDB:{profile.catalog.management.sha256}:category={profile.category}:bus={bus_id}",
            driver.source,
        )
    except ToyotaCodecError as error:
        raise FrameTransportError(
            error.code, "Native selected metadata lookup failed"
        ) from error


@dataclass(frozen=True)
class NativeFrameReceive:
    data: bytes = b""
    source_id: int = 0
    code: int = 0
    timestamp: int = 0

    def __post_init__(self) -> None:
        for value in (self.source_id, self.code, self.timestamp):
            _uint(value)
        if not isinstance(self.data, bytes) or len(self.data) > 0xFFFF:
            raise ValueError("Native assembled receive exceeds WORD capacity")


def frame_message(plan: FramePlan, request: bytes, *, bus_id: int) -> NativeMessage:
    """The retained native header context, without repeated database initialization."""
    if not isinstance(plan, FramePlan) or not isinstance(request, bytes):
        raise TypeError("FramePlan and explicit request bytes required")
    _uint(bus_id, 16)
    protocol = plan.send.protocol_id
    high = bus_id & 0xF0
    size = (5 if high == 0x20 else 4) if protocol == 6 else 3
    if len(plan.send.data) < size or len(request) + size > MAX_DATA:
        raise FrameTransportError(0x91020310, "Native request header exceeds storage")
    header = plan.send.data[:size]
    if protocol == 4:
        control = {0x10: 0x80, 0x50: 0x80, 0x20: 0x68, 0x30: 0xC0}.get(high, 0)
        header = (
            bytes((control if high == 0x20 else control | (len(request) & 255),))
            + header[1:]
        )
    elif protocol not in (1, 2, 6):
        raise ValueError("No recovered message header for this protocol")
    return _message(protocol, header + request, plan.send.tx_flags)


def decode_frame_message(
    message: NativeMessage, *, bus_id: int, protocol_id: int, maximum: int = MAX_DATA
) -> NativeFrameReceive:
    """Native f900/95f0 copying; checksum removal is not part of these methods."""
    if not isinstance(message, NativeMessage):
        raise TypeError("Explicit native message required")
    _uint(bus_id, 16)
    _uint(maximum, 16)
    _uint(protocol_id)
    header = (5 if bus_id & 0xF0 == 0x20 else 4) if protocol_id == 6 else 3
    if len(message.data) < header or len(message.data) - header > maximum:
        return NativeFrameReceive(code=0x90020601)
    source = (
        int.from_bytes(message.data[2:4], "big")
        if protocol_id == 6
        else message.data[2]
    )
    return NativeFrameReceive(message.data[header:], source, 0, message.timestamp)


@dataclass(frozen=True)
class J2534Result:
    """Result of one actual driver primitive, with explicit status and output counts."""

    code: int = 0
    handle: int | None = None
    count: int = 0
    messages: tuple[NativeMessage, ...] = ()
    data: bytes = b""
    configs: tuple[NativeConfig, ...] = ()
    host_boundary: (
        Literal[
            "cancelled_before", "deadline_before", "cancelled_after", "deadline_after"
        ]
        | None
    ) = None

    def __post_init__(self) -> None:
        if self.host_boundary not in (
            None,
            "cancelled_before",
            "deadline_before",
            "cancelled_after",
            "deadline_after",
        ):
            raise ValueError("Invalid primitive host-boundary observation")
        if (
            self.host_boundary is not None
            and self.host_boundary.endswith("_before")
            and (
                self.code
                or self.handle is not None
                or self.count
                or self.messages
                or self.data
                or self.configs
            )
        ):
            raise ValueError("Before-I/O boundary cannot contain a primitive outcome")
        _uint(self.code)
        _uint(self.count)
        if self.handle is not None:
            _uint(self.handle)
        if (
            not isinstance(self.messages, tuple)
            or len(self.messages) > 1
            or not all(isinstance(m, NativeMessage) for m in self.messages)
        ):
            raise ValueError("Native primitive returns at most one explicit message")
        if not isinstance(self.data, bytes) or len(self.data) > MAX_DATA:
            raise ValueError("Invalid primitive output bytes")
        if (
            not isinstance(self.configs, tuple)
            or len(self.configs) > 32
            or not all(isinstance(c, NativeConfig) for c in self.configs)
        ):
            raise ValueError("Invalid primitive configuration output")


class J2534Backend(Protocol):
    def invoke(
        self,
        operation: J2534Operation,
        fields: Mapping[str, object],
        *,
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> J2534Result: ...


def validate_frame_message(
    plan: FramePlan,
    message: NativeMessage,
    *,
    bus_id: int,
    ecu_flags: int,
    response_mode: int = 0,
) -> int:
    """Native protocol validator result, separate from bounded byte extraction."""
    _uint(bus_id, 16)
    _uint(ecu_flags, 8)
    _uint(response_mode)
    data = message.data
    protocol = plan.send.protocol_id
    high = bus_id & 0xF0
    header = (5 if high == 0x20 else 4) if protocol == 6 else 3
    if len(data) < header:
        return 0x90020601
    status = 0
    if protocol == 6:
        pass  # Native CAN ae60 validates negative responses; driver filters IDs.
    elif protocol in (1, 2):
        if plan.send.data[0] & 0x80:
            header = 1
        else:
            expected = 0x41 if protocol == 2 else 0x48
            if data[0] != expected or data[1] != 0x6B:
                return 0x91020325
            if (high != 0x10 or response_mode == 0) and data[2] != plan.address & 255:
                return 0x91020325
    elif protocol == 4:
        if high in (0x10, 0x30, 0x50):
            if high == 0x30 and response_mode != 1 and data[2] != plan.address & 255:
                if len(data) > 5 and data[3] == 0x7F and data[5] == 0x78:
                    return 0x90020323
                return 0x91020325
            if data[0] & 0x3F:
                size = (data[0] & 0x3F) + 3
            else:
                if len(data) < 4:
                    return 0x90020601
                size, header = data[3] + 4, 4
            if (message.extra_data_index or len(data)) != size:
                status = 0x91020324
            source = _source_address(bus_id, ecu_flags)
            if high == 0x30:
                if data[1] != source:
                    return 0x91020320
            elif data[1] != source or data[2] != plan.address & 255:
                status = 0x91020325
        elif high == 0x20:
            if data[0] != 0x48 or data[1] != 0x6B:
                return 0x91020320
            if response_mode == 0 and data[2] != plan.address & 255:
                status = 0x91020325
    else:
        raise ValueError("No recovered validator for this protocol")
    if len(data) > header and data[header] == 0x7F:
        if len(data) < header + 3:
            return 0x90020601
        if data[header + 2] == 0x78:
            return 0x90020323
        if data[header + 2] == 0x21:
            return 0x90020326
        return 0x90020321
    return status


def packet_log_record(payload: bytes) -> bytes:
    """Native 4000: uppercase application bytes and literal backslash+n."""
    if not isinstance(payload, bytes) or len(payload) > MAX_DATA:
        raise ValueError("Invalid bounded packet-log payload")
    return payload.hex().upper().encode("ascii") + b"\\n" if payload else b""


@dataclass
class NativeSharedState:
    mask_result: int | None = None
    connection_blocked: int | None = None
    source: str = "explicit-unavailable-share-data"

    def __post_init__(self) -> None:
        for value in (self.mask_result, self.connection_blocked):
            if value is not None:
                _uint(value, 8)
        if not isinstance(self.source, str) or not 1 <= len(self.source) <= 4096:
            raise ValueError("Explicit bounded shared-state source required")


class NativeFrameOperations:
    """Owned lower native operations over injected, concrete J2534 primitives."""

    def __init__(
        self,
        profile: ProtocolProfile,
        plan: FramePlan,
        backend: J2534Backend,
        *,
        native_build: Literal[12, 18],
        bus_id: int,
        driver: DriverProperties,
        device_kind: int,
        open_baud: int = 0,
        diagnostic_mode: bytes = bytes(16),
        communication_interval: int = 4500,
        clock: Callable[[], float] = time.monotonic,
        cancelled: Callable[[], bool] | None = None,
        wait: Callable[[float], None] = time.sleep,
        shared_state: NativeSharedState | None = None,
        native_variant: Literal["normal", "psa", "psa_wwh", "dual", "multi", "century"]
        | None = None,
    ):
        if native_build not in (12, 18) or type(native_build) is not int:
            raise ValueError("Explicit recovered native build 12 or 18 required")
        if (
            not isinstance(profile, ProtocolProfile)
            or not isinstance(plan, FramePlan)
            or not isinstance(driver, DriverProperties)
        ):
            raise TypeError(
                "Selected profile, plan and observed driver properties required"
            )
        for value in (device_kind, open_baud, communication_interval):
            _uint(value)
        _uint(bus_id, 16)
        if not isinstance(diagnostic_mode, bytes) or len(diagnostic_mode) != 16:
            raise ValueError("DIAGNOSTIC_INFO must contain sixteen bytes")
        self.profile, self.plan, self.backend = profile, plan, backend
        self.native_build, self.bus_id, self.driver = native_build, bus_id, driver
        self.device_kind, self.open_baud = device_kind, open_baud
        self.diagnostic_mode = diagnostic_mode
        self.communication_interval = communication_interval
        self.clock, self.cancelled = clock, cancelled or (lambda: False)
        self.wait, self.shared_state = wait, shared_state
        if shared_state is not None and not isinstance(shared_state, NativeSharedState):
            raise TypeError("Explicit native shared-state observation required")
        self.burst_mode = 0
        self.interrupt_mode = 0
        self._recovering_pending = False
        self.current_category = profile.category
        self.write_without_wait = False
        self.timestamp_unwrap = False
        self.pending_by_time = False
        self.previous_request_state = 0
        self.request_state = 0
        self.previous_service = 0
        self.current_service = 0
        self._timestamp_previous = 0
        self._timestamp_accumulator = 0
        self._timestamp_remainder = 0
        self.channel: int | None = None
        self.owns_channel = False
        self.filter_handles: list[int] = []
        self.observations: list[tuple[str, J2534Result]] = []
        self.last_message: NativeMessage | None = None
        self.last_write_timeout = 0
        self.last_activity = 0
        self.last_send_tick = 0
        self.force_initialization = False
        self.initialization_mode = 0
        self.pending_count = 0
        self.active_test = False
        self.active_test_tick = 0
        self.poisoned = False
        self.defer_cancel_cleanup = False
        self._primitive_uncertain = False
        self.cleanup_error: BaseException | int | None = None
        self._log_bound_writer: Callable[[bytes], int] | None = None
        self._log_writer: Callable[[bytes], int] | None = None
        self._log_failure: Callable[[], None] | None = None
        self.log_error = False
        self._last_clock: float | None = None
        self._steps = 0
        self._configured = False
        self.idle = False
        self._native_close_started = False
        self.preinit_d1_suppressed = 1
        self.last_no_session = False
        self._temporary_config: int | None = None
        prot = profile.protocol_info(bus_id)
        if prot is None:
            raise FrameTransportError(
                0x90020104, "Selected protocol information is absent"
            )
        self.protocol_record = prot
        self.ecu_flags = profile.category_record[72]
        inferred: Literal["psa", "normal"] = (
            "psa"
            if bus_id & 15 == 2 and self.ecu_flags & 0x1F in (0x14, 0x15)
            else "normal"
        )
        self.native_variant: Literal[
            "normal", "psa", "psa_wwh", "dual", "multi", "century"
        ] = native_variant or inferred
        if self.native_variant not in (
            "normal",
            "psa",
            "psa_wwh",
            "dual",
            "multi",
            "century",
        ):
            raise ValueError("Unsupported recovered native class variant")
        if self.native_variant == "psa_wwh" and native_build != 18:
            raise ValueError(
                "WWH subclass requires its recovered native build18 source"
            )
        if self.native_variant in ("psa", "psa_wwh", "dual"):
            self.pending_by_time = True  # bd10 constructor sets native2128 to one.
        self.pending_limit = word(prot, 18) or 100
        self.response_mode = 0

    @property
    def last_confirmed_clock(self) -> float | None:
        return self._last_clock

    def _now(self) -> float:
        try:
            value = self.clock()
        except Exception as error:
            raise _HostClockError("Native host clock callback failed") from error
        if (
            isinstance(value, bool)
            or not isinstance(value, (float, int))
            or not math.isfinite(value)
        ):
            raise _HostClockError("Primitive clock must return a finite number")
        value = float(value)
        if self._last_clock is not None and value < self._last_clock:
            raise _HostClockError("Primitive clock moved backwards")
        self._last_clock = value
        return value

    def _tick(self) -> int:
        return int(self._now() * 1000) & 0xFFFFFFFF

    def _deadline(self, deadline: float | None) -> float:
        now = self._now()
        if deadline is None:
            deadline = now + 30.0
        if (
            isinstance(deadline, bool)
            or not isinstance(deadline, (float, int))
            or not math.isfinite(deadline)
        ):
            raise ValueError("Finite seconds deadline required")
        if self.cancelled():
            raise _HostCancellation("Native frame operation cancelled")
        if now >= deadline:
            raise _HostDeadline("Native frame operation deadline expired")
        self._steps = 0
        return float(deadline)

    def _check(self, deadline: float) -> None:
        if self.cancelled():
            raise _HostCancellation("Native frame operation cancelled")
        if self._now() >= deadline:
            raise _HostDeadline("Native frame operation deadline expired")
        self._steps += 1
        if self._steps > 4096:
            raise FrameTransportError(
                0x90020323, "Bounded native primitive budget exhausted"
            )

    def _invoke(
        self,
        operation: J2534Operation,
        fields: Mapping[str, object],
        deadline: float,
    ) -> J2534Result:
        self._check(deadline)
        self._primitive_uncertain = True
        result = self.backend.invoke(
            operation,
            MappingProxyType(dict(fields)),
            deadline=deadline,
            cancelled=self.cancelled,
        )
        if not isinstance(result, J2534Result):
            raise TypeError("Primitive backend must return J2534Result")
        if len(self.observations) == 256:
            del self.observations[0]
        self.observations.append((operation, result))
        if result.host_boundary is not None and result.host_boundary.endswith(
            "_before"
        ):
            self._primitive_uncertain = False
            self._raise_host_boundary(result.host_boundary)
        # Ownership must be recorded before checking cancellation after connect.
        if operation == "connect" and result.handle is not None:
            self.channel, self.owns_channel = result.handle, True
            self._native_close_started = False
            self._configured = False
            self.last_activity = 0
        if operation == "connect" and result.code == 0 and result.handle is None:
            raise ValueError("Successful connect primitive omitted its channel")
        if (
            not result.code
            and fields.get("count") == 1
            and (
                (operation == "write_messages" and result.count != 1)
                or (
                    operation == "read_messages"
                    and (result.count != 1 or len(result.messages) != 1)
                )
            )
        ):
            self.poisoned = True
            raise OSError(
                "Native message primitive did not confirm its requested count"
            )
        if operation == "start_message_filter" and result.code == 0:
            if result.handle is None:
                raise ValueError("Successful filter primitive omitted its handle")
            self.filter_handles.append(result.handle)
            if len(self.filter_handles) > 32:
                raise ValueError("Native filter ownership exceeds bounded storage")
        if operation == "disconnect" and not result.code:
            self.channel, self.owns_channel = None, False
            self.filter_handles.clear()
            self.current_category = 0
        if operation == "ioctl" and fields.get("ioctl_id") == 10 and not result.code:
            self.filter_handles.clear()  # Driver already released every channel filter.
        self._primitive_uncertain = False
        if not result.code and operation == "read_messages" and result.messages:
            self._packet_log(result.messages[0])
        elif not result.code and operation == "write_messages":
            messages = fields.get("messages")
            if (
                isinstance(messages, tuple)
                and len(messages) == 1
                and isinstance(messages[0], NativeMessage)
            ):
                self._packet_log(messages[0])
        if result.host_boundary is not None:
            self._raise_host_boundary(result.host_boundary)
        self._check(deadline)
        return result

    @staticmethod
    def _raise_host_boundary(boundary: str) -> None:
        if boundary.startswith("cancelled_"):
            raise _HostCancellation(
                "Owning host observed cancellation at primitive boundary"
            )
        raise _HostDeadline("Owning host observed deadline at primitive boundary")

    @staticmethod
    def _status(code: int) -> int:
        return code | 0x91010000 if code else 0

    def adopt_channel(
        self, channel: int, *, owned: bool = False, configured: bool = False
    ) -> None:
        _uint(channel)
        if type(owned) is not bool or type(configured) is not bool:
            raise ValueError("Explicit channel ownership/configuration state required")
        if self.channel is not None or self.poisoned:
            raise RuntimeError("Native channel is already bound or faulted")
        self.channel, self.owns_channel = channel, owned
        self._configured = configured

    def reset_released_runtime(self) -> None:
        """A confirmed new native object generation, before adopting its channel."""
        if type(self) is not NativeFrameOperations:
            raise TypeError("Subclass runtime reset requires its concrete constructor")
        if self.channel is not None or self.owns_channel or self.filter_handles:
            raise RuntimeError("Release old native channel resources before resetting")
        log_state = (
            self._log_bound_writer,
            self._log_writer,
            self._log_failure,
            self.log_error,
        )
        deferred, last_clock = self.defer_cancel_cleanup, self._last_clock
        NativeFrameOperations.__init__(
            self,
            self.profile,
            self.plan,
            self.backend,
            native_build=self.native_build,
            bus_id=self.bus_id,
            driver=self.driver,
            device_kind=self.device_kind,
            open_baud=self.open_baud,
            diagnostic_mode=self.diagnostic_mode,
            communication_interval=self.communication_interval,
            clock=self.clock,
            cancelled=self.cancelled,
            wait=self.wait,
            shared_state=self.shared_state,
            native_variant=self.native_variant,
        )
        (
            self._log_bound_writer,
            self._log_writer,
            self._log_failure,
            self.log_error,
        ) = log_state
        self.defer_cancel_cleanup, self._last_clock = deferred, last_clock

    def rebind(
        self,
        profile: ProtocolProfile,
        plan: FramePlan,
        *,
        bus_id: int,
        diagnostic_mode: bytes | None = None,
    ) -> None:
        """Retain the channel while the native outer selector retargets this same class."""
        if self.poisoned:
            raise RuntimeError("Cannot rebind a faulted native transport")
        if not isinstance(profile, ProtocolProfile) or not isinstance(plan, FramePlan):
            raise TypeError("Actual selected profile and frame plan required")
        _uint(bus_id, 16)
        if (
            plan.send.protocol_id != self.plan.send.protocol_id
            or plan.connect.protocol_id != self.plan.connect.protocol_id
        ):
            raise ValueError(
                "A different native channel protocol requires reconnecting"
            )
        prot = profile.protocol_info(bus_id)
        if prot is None:
            raise FrameTransportError(
                0x90020104, "Selected protocol information is absent"
            )
        if diagnostic_mode is not None and (
            not isinstance(diagnostic_mode, bytes) or len(diagnostic_mode) != 16
        ):
            raise ValueError("DIAGNOSTIC_INFO must contain sixteen bytes")
        category = profile.category_record
        if not isinstance(category, bytes) or len(category) != 76:
            raise ValueError("Selected category record must contain76 bytes")
        changed = (
            profile.category != self.profile.category
            or bus_id != self.bus_id
            or prot != self.protocol_record
            or plan.configs != self.plan.configs
            or (diagnostic_mode is not None and diagnostic_mode != self.diagnostic_mode)
        )
        if profile.category != self.profile.category:
            self.last_activity = 0
        self.profile, self.plan, self.bus_id = profile, plan, bus_id
        self.current_category = profile.category
        self.protocol_record, self.ecu_flags = prot, category[72]
        self.pending_limit = word(prot, 18) or 100
        if diagnostic_mode is not None:
            self.diagnostic_mode = diagnostic_mode
        self._configured = self._configured and not changed

    def set_packet_log(
        self,
        writer: Callable[[bytes], int] | None,
        failure: Callable[[], None] | None = None,
    ) -> None:
        self._log_bound_writer = writer
        self._log_writer, self._log_failure, self.log_error = writer, failure, False

    @property
    def packet_log_hooks(
        self,
    ) -> tuple[Callable[[bytes], int] | None, Callable[[], None] | None]:
        """Outer-owned file hooks survive reconstruction of the native lower class."""
        return self._log_bound_writer, self._log_failure

    def _packet_log(self, message: NativeMessage) -> None:
        if self._log_writer is None:
            return
        result = self._decode_message(message)
        try:
            if result.code:
                raise ValueError("Native packet-log decode failed")
            data = packet_log_record(result.data)
            if data and self._log_writer(data) != len(data):
                raise OSError("Incomplete native packet-log write")
        except Exception:  # noqa: BLE001 - native log failure disables logging, not transport
            self.log_error, self._log_writer = True, None
            if self._log_failure is not None:
                self._log_failure()

    def configure(
        self, values: tuple[tuple[int, int], ...], *, deadline: float | None = None
    ) -> int:
        until = self._deadline(deadline)
        if self.channel is None or self.poisoned:
            return 0x90020701
        configs = translate_configs(values, self.driver)
        try:
            result = self._ioctl(2, configs, until)
            return self._status(result.code)
        except BaseException as error:
            self._fault_for(error)
            raise

    def _fault_for(self, error: BaseException) -> None:
        if (
            isinstance(error, (_HostCancellation, _HostDeadline, _HostClockError))
            and self.defer_cancel_cleanup is True
            and not self.poisoned
            and not self._primitive_uncertain
        ):
            return  # The owning worker performs its concrete bounded protocol stop.
        self._fault()

    def _fault(self) -> None:
        self.poisoned = True
        try:
            self.close()
        except BaseException as error:  # noqa: BLE001 - preserve the original transport fault
            self.cleanup_error = error

    def close(self, *, deadline: float | None = None) -> int:
        if deadline is not None and (
            isinstance(deadline, bool)
            or not isinstance(deadline, (float, int))
            or not math.isfinite(deadline)
        ):
            raise ValueError("Finite cleanup seconds deadline required")
        if self.channel is None:
            return 0
        cleanup_clock = self._now
        try:
            now = cleanup_clock()
        except Exception as error:
            if deadline is not None:
                raise
            self.cleanup_error = error
            cleanup_clock = time.monotonic
            now = cleanup_clock()
        until = float(deadline) if deadline is not None else now + 5.0

        def check(result: J2534Result | None = None) -> None:
            if result is not None and result.host_boundary is not None:
                self._raise_host_boundary(result.host_boundary)
            if cleanup_clock() >= until:
                raise TimeoutError("Native channel cleanup deadline expired")

        def invoke(
            operation: Literal[
                "stop_message_filter",
                "disconnect",
                "ioctl",
                "write_messages",
                "read_messages",
            ],
            fields: Mapping[str, object],
        ) -> J2534Result:
            check()
            result = self.backend.invoke(
                operation, fields, deadline=until, cancelled=lambda: False
            )
            if not isinstance(result, J2534Result):
                raise TypeError("Primitive backend must return J2534Result")
            if result.host_boundary is not None and result.host_boundary.endswith(
                "_before"
            ):
                self._raise_host_boundary(result.host_boundary)
            return result

        channel = self.channel
        first = 0
        if (
            self.owns_channel
            and self.current_category
            and not self.poisoned
            and not self._native_close_started
        ):
            self._native_close_started = True  # Never repeat an uncertain close write.
            selected = self._preinit_function()
            closing = [selected] if selected is not None else []
            if self.bus_id == 0x1C:
                info = _simple_record(
                    self.profile, 15, 56, 4, word(self.protocol_record, 2)
                )
                closing.append((0x81, 120, word(info, 32)))
            for function, _maximum, timeout in closing:
                try:
                    request = _function_request(self.profile, function, 0x90020104)
                except (FrameTransportError, ToyotaCodecError):
                    continue  # NativeClose ignores helper metadata/status failures.
                message = self._frame_message(request[: len(request) & 255])
                cleared = invoke(
                    "ioctl",
                    {
                        "channel_id": channel,
                        "ioctl_id": 8,
                        "input": None,
                        "output_capacity": 0,
                    },
                )
                check(cleared)
                if self.current_category == 0x1C7:
                    self.wait(0.015)
                    check()
                written = invoke(
                    "write_messages",
                    {
                        "channel_id": channel,
                        "messages": (message,),
                        "count": 1,
                        "timeout": 0 if self.write_without_wait else 1000,
                    },
                )
                if not written.code and written.count != 1:
                    self.poisoned = True
                    raise OSError("Native close write omitted its confirmed count")
                if not written.code:
                    self._packet_log(message)
                check(written)
                result = invoke(
                    "read_messages",
                    {"channel_id": channel, "count": 1, "timeout": timeout},
                )
                if not result.code and (result.count != 1 or len(result.messages) != 1):
                    self.poisoned = True
                    raise OSError("Native close read omitted its reported message")
                if not result.code:
                    self._packet_log(result.messages[0])
                check(result)
        for handle in tuple(reversed(self.filter_handles)):
            result = invoke(
                "stop_message_filter", {"channel_id": channel, "filter_id": handle}
            )
            if result.code:
                first = first or self._status(result.code)
            else:
                self.filter_handles.remove(handle)
            check(result)
        if self.owns_channel:
            result = invoke("disconnect", {"channel_id": channel})
            if not result.code:
                self.channel, self.owns_channel = None, False
                self.current_category = 0
                self.filter_handles.clear()
            check(result)
            return first or self._status(result.code)
        if not first:
            self.channel, self.owns_channel = None, False
        return first

    def _ioctl(
        self, number: int, value: object, deadline: float, *, output_capacity: int = 0
    ) -> J2534Result:
        return self._invoke(
            "ioctl",
            {
                "channel_id": self.channel,
                "ioctl_id": number,
                "input": value,
                "output_capacity": output_capacity,
            },
            deadline,
        )

    def _can_record(self) -> bytes:
        return _simple_record(self.profile, 14, 28, 8, word(self.protocol_record, 2))

    def apply_temporary_config(self, *, deadline: float | None = None) -> None:
        """Native CAN virtual b0: retain parameter23 before its temporary override."""
        until = self._deadline(deadline)
        if (
            self._protocol_family() != 6
            or self.device_kind == 4
            or self._temporary_config is not None
            or self.bus_id & 15 != 2
        ):
            return
        info = self._can_record()
        enabled = info[24 if self.native_build == 12 else 26]
        value = word(info, 18 if self.native_build == 12 else 20)
        if not enabled or not (value <= 255 or value == 65535):
            return
        try:
            result = self._ioctl(1, (NativeConfig(0x23, 0),), until)
            if result.code:
                return
            if len(result.configs) != 1 or result.configs[0].parameter != 0x23:
                raise OSError("Native GET_CONFIG omitted requested parameter23")
            saved = result.configs[0].value & 65535
            self.configure(((0x23, value),), deadline=until)
            self._temporary_config = saved  # Native ignores SET_CONFIG status.
        except BaseException as error:
            self._fault_for(error)
            raise

    def restore_temporary_config(self, *, deadline: float | None = None) -> None:
        """Native CAN virtual b4; restore only after a successful GET_CONFIG."""
        until = self._deadline(deadline)
        if self._temporary_config is not None:
            self.configure(((0x23, self._temporary_config),), deadline=until)
            self._temporary_config = None

    def _runtime_configs(self) -> tuple[NativeConfig, ...]:
        configs = self.plan.configs
        if self.native_variant in ("psa", "psa_wwh") and self.bus_id == 0x62:
            configs = (NativeConfig(0x8001, 0x30B),) + configs
        if self._protocol_family() == 6 and self.device_kind == 8:
            info = self._can_record()
            offset = 20 if self.native_build == 12 else 22
            configs += (NativeConfig(0x2A, word(info, offset)),)
        elif self._protocol_family() == 2:
            info = _simple_record(
                self.profile, 51, 16, 0, word(self.protocol_record, 2)
            )
            configs += translate_configs(
                (
                    (4, _source_address(self.bus_id, self.ecu_flags)),
                    (5, struct.unpack_from("<I", info, 8)[0]),
                    (0x10300, 0),
                    (0x10301, 0),
                ),
                self.driver,
            )
        elif self._protocol_family() == 4 and self.device_kind != 4:
            info = _simple_record(
                self.profile, 15, 56, 4, word(self.protocol_record, 2)
            )
            replacement = translate_configs(((10, word(info, 50)),), self.driver)[0]
            configs = tuple(replacement if c.parameter == 10 else c for c in configs)
        return configs

    def _can_filters(
        self, *, bus_id: int | None = None, protocol_record: bytes | None = None
    ) -> tuple[NativeFilter, ...]:
        bus_id = self.bus_id if bus_id is None else bus_id
        protocol_record = (
            self.protocol_record if protocol_record is None else protocol_record
        )
        _uint(bus_id, 16)
        if not isinstance(protocol_record, bytes) or len(protocol_record) not in (
            24,
            28,
        ):
            raise ValueError("Explicit native selected protocol record required")
        address = (
            struct.unpack_from("<I", self.diagnostic_mode, 8)[0]
            if word(self.diagnostic_mode, 0)
            else word(protocol_record, 8)
        )
        high = bus_id & 0xF0
        if (
            self.native_variant in ("psa", "psa_wwh")
            and not word(self.diagnostic_mode, 0)
            and (
                (self.native_variant == "psa" and 1 <= self.current_service <= 15)
                or (self.native_variant == "psa_wwh" and self.request_state in (3, 4))
            )
        ):
            address = word(protocol_record, 20)
        empty = NativeMessage(0, 0, 0, 0, 0, b"")

        def msg(value: int) -> NativeMessage:
            return _message(
                self.plan.send.protocol_id, (value & 0xFFFFFFFF).to_bytes(4, "big")
            )

        def filt(
            kind: int, mask: int, pattern: int, flow: int | None = None
        ) -> NativeFilter:
            return NativeFilter(
                kind, msg(mask), msg(pattern), empty if flow is None else msg(flow)
            )

        if bus_id in (0x1A, 0x4A, 0x5A):
            delta = {0x1A: 0x20, 0x4A: 0x100, 0x5A: 0xC0}[bus_id]
            peer = address - delta & 0xFFFFFFFF
            return (filt(1, 0x7FF, peer), filt(3, 0xFFFFFFFF, peer, address))
        psa = self.native_variant in ("psa", "psa_wwh", "dual")
        if high in (0x10, 0x20) or psa:
            result = (filt(1, 0x7FF, address | 8),) if self.device_kind == 4 else ()
            if bus_id == 0x22 and word(self.diagnostic_mode, 0) == 0:
                # Native 9a10 reports9101000a; setup8bc0 builds this fallback.
                extension = word(protocol_record, 10) & 255

                def extended(data: bytes) -> NativeMessage:
                    return NativeMessage(6, 0, 0xC0, 0, 0, data)

                return result + (
                    NativeFilter(
                        3,
                        extended(bytes([255]) * 5),
                        extended(
                            (address | 8).to_bytes(4, "big") + bytes((extension,))
                        ),
                        extended(
                            (address & ~8).to_bytes(4, "big") + bytes((extension,))
                        ),
                    ),
                )
            return result + (filt(3, 0xFFFFFFFF, address | 8, address),)
        if high == 0x30:
            if word(self.diagnostic_mode, 0) == 1:
                return (
                    filt(1, 0x7FF, address),
                    filt(
                        3,
                        0xFFFFFFFF if self.device_kind == 8 else 0x7FF,
                        address,
                        address & ~8,
                    ),
                )
            return (filt(1, 0x7F8, 0x7E8),) + tuple(
                filt(3, 0x7FF, 0x7E8 + i, 0x7E0 + i) for i in range(8)
            )
        return ()

    def setup(self, *, deadline: float | None = None) -> int:
        until = self._deadline(deadline)
        if self.channel is None or self.poisoned:
            return 0x90020701
        if self._configured:
            return 0
        if not self.plan.startup_request:
            return 0x90020501
        if (
            self.native_variant not in ("psa", "psa_wwh", "dual")
            and not self.plan.tester_request
        ):
            return 0x90020502
        try:
            configs = self._runtime_configs()
            if self._protocol_family() == 2:
                self._ioctl(12, b"\x6b", until)  # Native ignores this ioctl status.
            result = self._ioctl(2, configs, until)
            if result.code and self._protocol_family() == 6 and self.device_kind == 8:
                result = self._ioctl(2, configs[:-1], until)
            if result.code and self._protocol_family() not in (1, 2):
                return self._status(result.code)
            if self._protocol_family() == 6:
                if self.device_kind == 8 and (
                    self.bus_id in (0x12, 0x22)
                    or (
                        self.native_variant in ("psa", "psa_wwh")
                        and self.bus_id == 0x62
                    )
                    or self.bus_id & 15 == 10
                ):
                    self._ioctl(
                        10, None, until
                    )  # Native ignores CLEAR_MSG_FILTERS status.
                filters = self._can_filters()
                for index, item in enumerate(filters):
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
                        if self.bus_id == 0x22 and word(self.diagnostic_mode, 0) == 0:
                            if index + 1 < len(filters):
                                continue
                            return self._status(result.code)
                        break  # Other normal setup branches ignore installer failure.
            self._configured = True
            self.current_category = self.profile.category
            return 0
        except BaseException as error:
            self._fault_for(error)
            raise

    def open(self, *, deadline: float | None = None, setup: bool = True) -> int:
        until = self._deadline(deadline)
        if self.channel is not None or self.poisoned:
            return 0x90020701
        try:
            if (
                self.shared_state is not None
                and self.shared_state.connection_blocked == 1
                and self.plan.connect.protocol_id in (5, 6, 0x1000C, 0x8005)
            ):
                return 0x91010009
            result = self._invoke(
                "connect",
                {
                    "protocol_id": self.plan.connect.protocol_id,
                    "flags": self.plan.connect.flags,
                    "baud_rate": self.open_baud,
                },
                until,
            )
            if result.code:
                if self.channel is not None:
                    self.close()
                return self._status(result.code)
            if self.channel is None:
                raise ValueError("Successful connect primitive omitted its channel")
            if setup:
                code = self.setup(deadline=until)
                if code:
                    self.close()
                    return code
            return 0
        except BaseException as error:
            self._fault_for(error)
            raise

    def _write(
        self,
        message: NativeMessage,
        timeout: int,
        deadline: float,
        *,
        resend: bool = False,
    ) -> int:
        if self.current_category == 0x1C7:
            self._wait_ms(15, deadline)
        result = self._invoke(
            "write_messages",
            {
                "channel_id": self.channel,
                "messages": (message,),
                "count": 1,
                "timeout": 0 if self.write_without_wait else timeout,
            },
            deadline,
        )
        if result.code:
            return 0x91020310 if resend else self._status(result.code)
        if result.count != 1:
            self.poisoned = True
            raise OSError("Successful native write did not confirm one message")
        self.last_send_tick = self._tick()
        payload = self._decode_message(message).data
        if self.burst_mode and len(payload) > 1 and payload[0] == 0x30:
            self.active_test = True
        if self.active_test:
            self.active_test_tick = self._tick()
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
        if type(clear_rx) is not int or not -(1 << 31) <= clear_rx < 1 << 32:
            raise ValueError("Native clear-RX argument must fit a 32-bit word")
        _uint(initialization_mode, 8)
        if type(no_session) is not bool:
            raise ValueError("Explicit NoSession flag required")
        if request is not None and (
            not isinstance(request, bytes) or len(request) > 0xFFFF
        ):
            raise ValueError("Native request must be bytes or explicit NULL")
        if (
            self.channel is None
            or self.poisoned
            or not self.plan.address
            or (request is None and initialization_mode != 0)
        ):
            return 0x90020701
        self.last_no_session = no_session
        try:
            if initialization_mode == 0:
                self.force_initialization = True
            if initialization_mode != 2:
                elapsed = self._tick() - self.last_activity & 0xFFFFFFFF
                if self._needs_initialize(elapsed):
                    code = self._initialize(until)
                    self._record_mask_judgment(code)
                    if code:
                        if initialization_mode != 0x11:
                            return code
                    else:
                        self.force_initialization = False
                        self.last_activity = self._tick()
                else:
                    self.force_initialization = False
            if request is None:
                return 0
            message = self._message_for_request(request)
            self.last_message, self.last_write_timeout = message, timeout
            if clear_rx == 1:
                self._ioctl(8, None, until)  # Native intentionally ignores this status.
            return self._write(message, timeout, until)
        except BaseException as error:
            self._fault_for(error)
            raise

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
        _uint(maximum, 16)
        _uint(timeout)
        _uint(argument_5, 16)
        _uint(flags)
        if type(buffer) is not bool:
            raise ValueError("Explicit native output-buffer presence required")
        if (
            self.channel in (None, 0)
            or self.poisoned
            or not self.plan.address
            or not maximum
            or not buffer
        ):
            return NativeFrameReceive(code=0x90020701)
        if self.active_test and self.active_test_tick + 200 + timeout < self._tick():
            self.active_test, self.active_test_tick = False, 0
            return NativeFrameReceive(code=0x90020329)
        self.pending_count = 0
        first_source: int | None = None
        busy_count = 0
        read_timeout = timeout
        try:
            while True:
                result = self._invoke(
                    "read_messages",
                    {"channel_id": self.channel, "count": 1, "timeout": read_timeout},
                    until,
                )
                if result.code:
                    return NativeFrameReceive(
                        code=self._status(9 if result.code == 0x10 else result.code)
                    )
                if result.count != 1 or len(result.messages) != 1:
                    raise OSError("Native read did not supply its one reported message")
                message = result.messages[0]
                if self._drop_message(message):
                    continue
                code = self._validate_message(message)
                if code == 0x91020325:
                    self.pending_count, first_source = 0, None
                    continue
                if code == 0x90020323:
                    self.last_activity = self._tick()
                    decoded = self._decode_message(message)
                    if first_source is None:
                        first_source = decoded.source_id
                        self.pending_count = 1
                    elif decoded.source_id == first_source:
                        self.pending_count += 1
                    if self.pending_by_time:
                        if (
                            (self.last_send_tick + 180000) & 0xFFFFFFFF
                        ) <= self._tick():
                            return NativeFrameReceive(code=code)
                    elif self.pending_count >= self.pending_limit:
                        if not self._recovering_pending:
                            self.recover_pending(timeout=timeout, deadline=until)
                        return NativeFrameReceive(code=code)
                    if self._protocol_family() == 6:
                        read_timeout = word(self._can_record(), 12) or timeout
                    continue
                if code == 0x90020326:
                    if self._protocol_family() == 6 and self.bus_id & 0xF0 == 0x30:
                        self.drain(
                            deadline=until
                        )  # ae60 intentionally ignores drain status.
                    self.last_activity = self._tick()
                    self.pending_count, first_source = 0, None
                    busy_count += 1
                    if busy_count > 255:
                        return NativeFrameReceive(code=0x90020323)
                    if self.last_message is None or not message.data:
                        return NativeFrameReceive(code=0x90020327)
                    if self._protocol_family() == 6:
                        offset = 22 if self.native_build == 12 else 24
                        delay = word(self._can_record(), offset)
                        if delay:
                            self._wait_ms(delay, until)
                    resend_code = self._write(
                        self.last_message, self.last_write_timeout, until, resend=True
                    )
                    if resend_code:
                        return NativeFrameReceive(code=resend_code)
                    continue
                if code not in (0, 0x90020321):
                    return NativeFrameReceive(code=code)
                decoded = self._decode_message(message, maximum=maximum)
                if decoded.code:
                    return decoded if code == 0 else NativeFrameReceive(code=0x90020321)
                self.last_activity = self._tick()
                if self.active_test and decoded.data[:1] == b"\x70":
                    self.active_test, self.active_test_tick = False, 0
                if code == 0x90020321 and self._protocol_family() == 6:
                    delay = word(
                        self._can_record(), 22 if self.native_build == 12 else 24
                    )
                    if delay:
                        self._wait_ms(delay, until)
                stamp = (
                    self._unwrap_timestamp(decoded.timestamp)
                    if self.timestamp_unwrap and code == 0
                    else decoded.timestamp
                )
                return NativeFrameReceive(decoded.data, decoded.source_id, code, stamp)
        except BaseException as error:
            self._fault_for(error)
            raise

    def _wait_ms(self, milliseconds: int, deadline: float) -> None:
        end = self._now() + milliseconds / 1000
        while self._now() < end:
            self._check(deadline)
            self.wait(min(0.05, max(0.0, min(end, deadline) - self._now())))
        self._check(deadline)

    def _startup_expectation(self) -> tuple[bytes, bytes]:
        database = self.profile.catalog.management
        row = next(
            (
                r
                for r in correspondence_rows(database, 18, self.profile.exception_ids)
                if word(r, 0) == self.profile.category and word(r, 2) == 0x67
            ),
            None,
        )
        if row is None:
            raise FrameTransportError(0x90020104, "Startup function is absent")
        frame = _simple_record(self.profile, 17, 8, 0, word(row, 6))
        variables = database.sections.get(0)
        if variables is None:
            raise FrameTransportError(0xA0030107, "Startup variables are absent")
        table = VariableTable(variables.payload, variables.count)
        return table.get(word(frame, 4)), table.get(word(frame, 6))

    def drain(self, *, deadline: float | None = None) -> int:
        """Native virtual44: discard/log raw messages until the driver reports empty."""
        until = self._deadline(deadline)
        if self.channel in (None, 0) or self.poisoned:
            return 0x90020701
        if self._protocol_family() == 6:
            timeout = word(self._can_record(), 12)
        elif self._protocol_family() == 4:
            timeout = word(
                _simple_record(self.profile, 15, 56, 4, word(self.protocol_record, 2)),
                32,
            )
        else:
            timeout = word(
                _simple_record(self.profile, 51, 16, 0, word(self.protocol_record, 2)),
                12,
            )
        try:
            while True:
                result = self._invoke(
                    "read_messages",
                    {"channel_id": self.channel, "count": 1, "timeout": timeout},
                    until,
                )
                if result.code:
                    return self._status(9 if result.code == 0x10 else result.code)
                if result.count != 1 or len(result.messages) != 1:
                    raise OSError(
                        "Native drain did not supply its one reported message"
                    )
        except BaseException as error:
            self._fault_for(error)
            raise

    def _keyword_check(self, keywords: bytes) -> bool:
        if len(keywords) != 2:
            return False
        value = int.from_bytes(keywords, "big")
        if self.ecu_flags & 0x1F == 9:
            if self.bus_id == 0x21:
                return value in (0x0808, 0x9494)
            if self.bus_id == 0x31:
                return value in (0xE98F, 0x6B8F, 0x6D8F, 0xEF8F)
        return True

    def _iso_fast_initialize(self, deadline: float) -> tuple[int, bytes]:
        if not self.plan.startup_request:
            return 0x90020501, b""
        message = self._frame_message(self.plan.startup_request)
        if len(message.data) > 64:
            raise ValueError("Native fast initialization has 64-byte scratch storage")
        cleared = self._ioctl(8, None, deadline)
        if cleared.code:
            return self._status(cleared.code), b""
        result = self._ioctl(5, message, deadline, output_capacity=64)
        if result.code:
            return self._status(9 if result.code == 7 else result.code), b""
        if len(result.messages) != 1 or len(result.messages[0].data) < 6:
            return 0x91020301, b""
        data = result.messages[0].data
        high = self.bus_id & 0xF0
        valid = data[3] == 0xC1
        if high in (0x10, 0x50):
            valid = (
                valid
                and data[1] == _source_address(self.bus_id, self.ecu_flags)
                and data[2] == word(self.protocol_record, 8) & 255
            )
        elif high == 0x30:
            valid = valid and data[1] == _source_address(self.bus_id, self.ecu_flags)
        return (0 if valid else 0x91020301), data[4:6]

    def _iso_slow_initialize(self, deadline: float) -> tuple[int, bytes]:
        address = word(self.protocol_record, 4)
        if not address:
            return 0x90020701, b""
        for attempt in range(2):
            cleared = self._ioctl(8, None, deadline)
            if cleared.code:
                return self._status(cleared.code), b""
            result = self._ioctl(
                4, bytes((address & 255,)), deadline, output_capacity=2
            )
            if not result.code:
                if len(result.data) != 2:
                    return 0x91020302, b""
                expected = {3: b"\x08\x08", 4: b"\xe9\x8f"}.get(self.ecu_flags & 0x1F)
                if expected is not None and result.data != expected:
                    return 0x91020302, b""
                return 0, result.data
            if attempt == 0:
                self._wait_ms(5000, deadline)
        return self._status(9 if result.code == 7 else result.code), b""

    def set_preinit_d1_suppressed(self, value: int) -> None:
        """Native PSA virtual54/bd00 DWORD state (zero enables the D1 helper)."""
        self.preinit_d1_suppressed = _uint(value)

    def _preinit_function(self) -> tuple[int, int, int] | None:
        protocol = self._protocol_family()
        if protocol == 6:
            if self.native_variant in ("psa", "psa_wwh", "dual"):
                function = 0xD1 if self.preinit_d1_suppressed == 0 else None
            else:
                function = 0x58 if self.bus_id & 15 == 10 else None
            return (
                None
                if function is None
                else (function, 120, word(self._can_record(), 12))
            )
        if self.ecu_flags & 0x1F in (5, 9):
            info = _simple_record(
                self.profile, 15, 56, 4, word(self.protocol_record, 2)
            )
            return 0x58, MAX_DATA, word(info, 32)
        return None

    def pre_initialize(self, *, deadline: float | None = None) -> int:
        """Native virtual3c/114 selected pre-initialization exchange."""
        until = self._deadline(deadline)
        if not self.current_category:
            return 0
        selected = self._preinit_function()
        if selected is None:
            if self.native_variant in ("psa", "psa_wwh", "dual"):
                self.last_activity = 0
            return 0
        function, maximum, timeout = selected
        try:
            request = _function_request(self.profile, function, 0x90020104)
        except (FrameTransportError, ToyotaCodecError) as error:
            return (
                error.status if isinstance(error, FrameTransportError) else error.code
            )
        # Native helpers ignore both primitive status values, but still perform the read.
        self.send(
            request[: len(request) & 255],
            timeout=1000,
            initialization_mode=2,
            deadline=until,
        )
        self.receive(maximum=maximum, timeout=timeout, deadline=until)
        self.last_activity = 0
        return 0

    def finish_bus_session(self, *, deadline: float | None = None) -> int:
        """Native virtual64/3250: selected81 exchange on bus1c, retaining the channel."""
        until = self._deadline(deadline)
        if not self.current_category or self.bus_id != 0x1C:
            return 0
        info = _simple_record(self.profile, 15, 56, 4, word(self.protocol_record, 2))
        try:
            request = _function_request(self.profile, 0x81, 0x90020104)
        except (FrameTransportError, ToyotaCodecError) as error:
            return (
                error.status if isinstance(error, FrameTransportError) else error.code
            )
        self.send(
            request[: len(request) & 255],
            timeout=1000,
            initialization_mode=2,
            deadline=until,
        )
        self.receive(maximum=120, timeout=word(info, 32), deadline=until)
        self.last_activity = 0
        return 0

    def _initialize(self, deadline: float) -> int:
        protocol = self._protocol_family()
        if self.last_activity and (
            protocol == 4
            or (protocol == 6 and self.native_variant in ("normal", "multi"))
        ):
            code = self.pre_initialize(deadline=deadline)
            if code:
                return code
        if protocol == 4:
            info = _simple_record(
                self.profile, 15, 56, 4, word(self.protocol_record, 2)
            )
            modes = word(info, 6)
            code = 0x90020304
            if modes & 1:
                code, keywords = self._iso_fast_initialize(deadline)
                if not code:
                    self.drain(deadline=deadline)
                    if not self._keyword_check(keywords):
                        return 0x91020301
                    self.initialization_mode = 1
                    return 0
            if modes & 2:
                code, keywords = self._iso_slow_initialize(deadline)
                if not code:
                    if not self._keyword_check(keywords):
                        return 0x91020302
                    self.initialization_mode = 2
                    return 0
            return code
        startup = self.plan.startup_request
        if not startup and self.native_variant == "multi":
            try:
                startup = _function_request(self.profile, 0x67, 0x90020501)
            except (FrameTransportError, ToyotaCodecError) as error:
                return (
                    error.status
                    if isinstance(error, FrameTransportError)
                    else error.code
                )
        if not startup:
            return 0x90020501
        message = self._message_for_request(
            startup[: len(startup) & 255] if protocol == 6 else startup
        )
        self.last_message, self.last_write_timeout = message, 1000
        self._ioctl(8, None, deadline)
        code = self._write(message, 1000, deadline)
        if code:
            return code
        old_mode = self.response_mode
        if protocol == 6 and self.bus_id == 0x32:
            self.response_mode = 1
        elif protocol in (1, 2) and self.bus_id & 0xF0 == 0x10:
            self.response_mode = 0 if word(self.diagnostic_mode, 0) else 1
        try:
            result = self.receive(maximum=MAX_DATA, timeout=1000, deadline=deadline)
        finally:
            self.response_mode = old_mode
        code = result.code
        if not code:
            if (
                protocol == 6
                and self.bus_id & 15 == 10
                and self.native_variant in ("normal", "multi")
            ):
                try:
                    mask, pattern = self._startup_expectation()
                except (FrameTransportError, ToyotaCodecError) as error:
                    code = (
                        error.status
                        if isinstance(error, FrameTransportError)
                        else error.code
                    )
                else:
                    if not mask:
                        self.idle = True
                    elif not pattern or len(pattern) < len(mask):
                        code = 0x90020501
                    elif len(result.data) < len(mask):
                        code = 0x91020303
                    else:
                        self.idle = True
                        if any(
                            (data & bits) != (expected & bits)
                            for data, bits, expected in zip(
                                result.data, mask, pattern, strict=False
                            )
                        ):
                            code = 0x91020303
            elif not result.data or result.data[0] != (startup[0] + 0x40) & 255:
                code = 0x91020303 if protocol == 6 else 0x91020305
        if not code and self.native_variant in ("normal", "multi"):
            self.initialization_mode = 0 if protocol == 6 else 4
        if (
            protocol == 6
            and self.bus_id & 0xF0 == 0x30
            and (self.native_variant in ("normal", "multi") or not result.code)
        ) or (protocol in (1, 2) and self.bus_id & 0xF0 == 0x10 and not result.code):
            self.drain(deadline=deadline)  # Native ignores this final drain status.
        return code

    def recover_pending(self, *, timeout: int, deadline: float | None = None) -> int:
        """Native virtual120/25b0 tester exchange after the pending-count limit."""
        _uint(timeout)
        until = self._deadline(deadline)
        if not self.plan.tester_request:
            return 0x90020502
        if self._recovering_pending:
            return 0x90020323  # Host bounds native recursive recovery to one level.
        message = self._frame_message(self.plan.tester_request)
        changed = False
        self._recovering_pending = True
        try:
            cleared = self._ioctl(8, None, until)
            if cleared.code:
                return self._status(cleared.code)
            if self.interrupt_mode == 0:
                self.set_interrupt_mode(1, deadline=until)
                changed = self.interrupt_mode == 1
            restore_allowed = True
            try:
                result = self._invoke(
                    "write_messages",
                    {
                        "channel_id": self.channel,
                        "messages": (message,),
                        "count": 1,
                        "timeout": 0 if self.interrupt_mode != 0 else timeout,
                    },
                    until,
                )
                if result.code:
                    return self._status(result.code)
                while True:
                    if self.plan.send.protocol_id in (3, 4):
                        self._wait_ms(1000, until)
                    result = self._invoke(
                        "read_messages",
                        {"channel_id": self.channel, "count": 1, "timeout": timeout},
                        until,
                    )
                    if result.code:
                        return self._status(9 if result.code == 0x10 else result.code)
                    received = result.messages[0]
                    if not self._drop_message(received):
                        break
            except BaseException:
                restore_allowed = (
                    False  # Uncertain/interrupted I/O gets no new configuration I/O.
                )
                raise
            finally:
                if changed and restore_allowed:
                    self.set_interrupt_mode(0, deadline=until)
            code = self._validate_message(received)
            if code:
                self._ioctl(8, None, until)
                self._initialize(until)  # Native ignores recovery initializer status.
            return code
        except BaseException as error:
            self._fault_for(error)
            raise
        finally:
            self._recovering_pending = False

    def clear_runtime_context(self) -> None:
        """Native virtual18/2410 clears current category, retaining selected metadata."""
        self.current_category = 0
        self._configured = False

    def set_burst_mode_state(self, value: int) -> None:
        """Native3bc0 state after its explicit driver configuration operation."""
        self.burst_mode = _uint(value)
        self.timestamp_unwrap = value == 1
        self.active_test, self.active_test_tick = False, 0

    def set_interrupt_mode_state(self, value: int) -> None:
        self.interrupt_mode = _uint(value)
        self.write_without_wait = value == 1

    def set_interrupt_mode(self, value: int, *, deadline: float | None = None) -> None:
        """Native10e00: ISO interrupt configuration, with ignored driver status."""
        _uint(value)
        until = self._deadline(deadline)
        if self._protocol_family() != 4 or self.device_kind == 4:
            return
        info = _simple_record(self.profile, 15, 56, 4, word(self.protocol_record, 2))
        self.configure(((0x10500, value),), deadline=until)
        self.set_interrupt_mode_state(value)
        self.configure(((0x1000B, word(info, 52)),), deadline=until)

    def set_runtime_flags(
        self,
        *,
        write_without_wait: bool = False,
        timestamp_unwrap: bool = False,
        pending_by_time: bool = False,
    ) -> None:
        if any(
            type(value) is not bool
            for value in (write_without_wait, timestamp_unwrap, pending_by_time)
        ):
            raise ValueError("Explicit native boolean state required")
        self.interrupt_mode = int(write_without_wait)
        self.burst_mode = int(timestamp_unwrap)
        self.write_without_wait, self.timestamp_unwrap, self.pending_by_time = (
            write_without_wait,
            timestamp_unwrap,
            pending_by_time,
        )

    def _unwrap_timestamp(self, value: int) -> int:
        if value < self._timestamp_previous:
            self._timestamp_accumulator += (
                self._timestamp_remainder + 296
            ) // 1000 + 4294967
            self._timestamp_remainder = (self._timestamp_remainder + 296) % 1000
        self._timestamp_previous = value
        return (
            (self._timestamp_remainder + value % 1000) // 1000
            + self._timestamp_accumulator
            + value // 1000
        ) & 0xFFFFFFFF

    def _record_mask_judgment(self, code: int) -> None:
        state = self.shared_state
        if (
            self.device_kind not in (2, 8)
            or state is None
            or state.mask_result != 255
            or state.connection_blocked is None
        ):
            return
        table = self.profile.catalog.management.sections.get(70)
        if table is not None and any(
            word(row, 0) == self.current_category and row[2] == self.bus_id & 255
            for row in table.rows(4)
        ):
            state.mask_result = state.connection_blocked = int(code == 0)

    def set_service_context(self, service: int, *, previous: int | None = None) -> None:
        _uint(service, 8)
        if previous is not None:
            _uint(previous, 8)
        old = self.current_service if previous is None else previous
        self.previous_service, self.current_service = old, service
        if self.native_variant == "psa":
            unchanged_family = (1 <= old <= 15 and 1 <= service <= 15) or (
                old > 15 and service > 15
            )
            if not unchanged_family:
                self._configured = False

    def set_request_state(self, state: int) -> None:
        """Retain the actual WWH virtual160 classifier output supplied by the caller."""
        _uint(state)
        if state > 4:
            raise ValueError("Recovered WWH request state must be 0..4")
        self.previous_request_state, self.request_state = self.request_state, state
        if self.previous_request_state != state:
            self._configured = False

    def _needs_initialize(self, elapsed: int) -> bool:
        if self.native_variant == "psa_wwh":
            return self.request_state in (1, 2) and (
                self.force_initialization or elapsed >= self.communication_interval
            )
        if (
            self.native_variant in ("psa", "psa_wwh", "dual")
            and 1 <= self.current_service <= 15
        ):
            return (
                False  # Exact C650 GetInit: service1..15 suppresses even forced init.
            )
        return self.force_initialization or elapsed >= self.communication_interval

    def _protocol_family(self) -> int:
        """Retained native class family, distinct from a subclass's driver ProtocolID."""
        return self.plan.send.protocol_id

    def prepare_bus_session(self, *, deadline: float | None = None) -> int:
        """Native base virtual60/2510 is constant zero; subclasses override actual work."""
        self._deadline(deadline)
        return 0

    def _drop_message(self, message: NativeMessage) -> bool:
        """Native virtual140; base3240 drops every nonzero RxStatus."""
        return bool(message.rx_status)

    def _decode_message(
        self, message: NativeMessage, *, maximum: int = MAX_DATA
    ) -> NativeFrameReceive:
        """Native virtual110 inverse framing; retained class controls the format."""
        return decode_frame_message(
            message,
            bus_id=self.bus_id,
            protocol_id=self.plan.send.protocol_id,
            maximum=maximum,
        )

    def _validate_message(self, message: NativeMessage) -> int:
        """Native virtual validator; subclasses implement their concrete wire format."""
        return validate_frame_message(
            self.plan,
            message,
            bus_id=self.bus_id,
            ecu_flags=self.ecu_flags,
            response_mode=self.response_mode,
        )

    def _message_for_request(self, request: bytes) -> NativeMessage:
        return self._frame_message(request)

    def _frame_message(self, request: bytes) -> NativeMessage:
        """Native virtual send-header producer, also used for initialization."""
        message = frame_message(self.plan, request, bus_id=self.bus_id)
        if self.native_variant in ("psa", "psa_wwh") and message.protocol_id == 6:
            offset = 6 if 1 <= self.current_service <= 15 else 8
            if self.native_variant == "psa_wwh":
                offset = {4: 6, 3: 20}.get(self.request_state, 8)
            target = word(self.protocol_record, offset)
            data = b"\x00\x00" + target.to_bytes(2, "big")
            if self.bus_id & 0xF0 == 0x20:
                data += bytes((word(self.protocol_record, 10) & 255,))
            return _message(6, data + request, message.tx_flags)
        return message


class NativeMultiMonOperations:
    """Actual shared Dual/MultiMon native lower, with two registered ECU entries."""

    def __init__(
        self,
        targets: Sequence[DualTarget],
        profiles: Mapping[str, ProtocolProfile],
        backend: J2534Backend,
        *,
        driver: DriverProperties,
        native_build: Literal[12, 18],
        source_identity: str,
        device_kind: int,
        diagnostic_mode: bytes = bytes(16),
        clock: Callable[[], float] = time.monotonic,
        cancelled: Callable[[], bool] | None = None,
        wait: Callable[[float], None] = time.sleep,
    ):
        # Shared send bodies use distinct source-selected controls; avoid a reverse import.
        from scripts.monitor_dual import (
            NativeDualControl,
            NativeDualPrimitives,
            NativeDualTransport,
        )

        self.targets = tuple(targets)
        self.profiles = MappingProxyType(dict(profiles))
        self.native_build = native_build
        self._cancelled = cancelled or (lambda: False)
        # Validate native target count/identity before constructing any channel.
        control = NativeDualControl(
            self.targets,
            self.profiles,
            NativeDualPrimitives(backend),
            driver=driver,
            source_build=native_build,
            source_identity=source_identity,
            connected_device=device_kind,
            diagnostic_mode=diagnostic_mode,
            clock=clock,
            source_variant="multi",
        )
        plans = {
            target.ecu: runtime_frame_plan(
                self.profiles[target.ecu],
                _function_request(self.profiles[target.ecu], 0x7F, 0x90020502),
                native_build=native_build,
                native_variant="multi",
                bus_id=target.protocol,
                driver=driver,
                diagnostic_mode=diagnostic_mode,
            )
            for target in self.targets
        }
        first = self.targets[0]
        self.operations = NativeFrameOperations(
            self.profiles[first.ecu],
            plans[first.ecu],
            backend,
            native_build=native_build,
            bus_id=first.protocol,
            driver=driver,
            device_kind=device_kind,
            diagnostic_mode=diagnostic_mode,
            clock=clock,
            cancelled=self.cancelled,
            wait=wait,
            native_variant="multi",
        )
        self.control = control
        self.transport = NativeDualTransport(control, self.operations, plans)
        self._defer_cancel_cleanup = False
        self.cleanup_error: BaseException | None = None
        self._current: DualTarget | None = None

    @property
    def cancelled(self) -> Callable[[], bool]:
        return self._cancelled

    @cancelled.setter
    def cancelled(self, callback: Callable[[], bool]) -> None:
        if not callable(callback):
            raise TypeError("Explicit MultiMon cancellation predicate required")
        self._cancelled = self.operations.cancelled = callback

    @property
    def defer_cancel_cleanup(self) -> bool:
        return self._defer_cancel_cleanup

    @defer_cancel_cleanup.setter
    def defer_cancel_cleanup(self, enabled: bool) -> None:
        if type(enabled) is not bool:
            raise TypeError("Explicit MultiMon cleanup lease flag required")
        self._defer_cancel_cleanup = self.operations.defer_cancel_cleanup = enabled

    def _failed(self, error: BaseException) -> None:
        if (
            isinstance(error, (_HostCancellation, _HostDeadline, _HostClockError))
            and self.defer_cancel_cleanup
            and not self.operations.poisoned
            and not self.control.poisoned
        ):
            return
        self.control.poisoned = True
        self.operations.poisoned = True
        try:
            self.control.close_resources(
                deadline=self.operations._now() + 5.0, cancelled=lambda: False
            )
        except BaseException as cleanup:  # noqa: BLE001 - retain the original I/O fault
            self.cleanup_error = cleanup
        if self.control.channel is None:
            self.transport.released()
        self._current = None

    def connect_multi_mon(self, *, deadline: float) -> int:
        from scripts.monitor_dual import DualControl

        if self.operations.poisoned:
            return 0x90020701
        try:
            code = self.control.execute(
                DualControl("ConnectMultiMon", ()),
                deadline=deadline,
                cancelled=self.cancelled,
            )
            self._current = None
            return code
        except BaseException as error:
            self._failed(error)
            raise

    def entry_comm_system_info(
        self, category: int, bus: int, entry: int, *, deadline: float
    ) -> int:
        from scripts.monitor_dual import DualControl

        _uint(category)
        _uint(bus, 16)
        _uint(entry)
        target = next((t for t in self.targets if t.command_id == category), None)
        if target is None or (bus, entry) != (target.protocol, target.entry_parameter):
            raise ValueError("MultiMon entry differs from its selected native target")
        try:
            return self.control.execute(
                DualControl("EntryCommSystemInfo", (category, bus, entry)),
                deadline=deadline,
                cancelled=self.cancelled,
            )
        except BaseException as error:
            self._failed(error)
            raise

    def send_multi_mon(
        self,
        category: int,
        request: bytes,
        *,
        timeout: int,
        bus: int,
        argument_6: int = 0,
        clear_rx: int = 1,
        deadline: float,
    ) -> int:
        _uint(category)
        _uint(bus, 16)
        _uint(timeout)
        if type(clear_rx) is not int or not -(1 << 31) <= clear_rx < 1 << 32:
            raise ValueError("Native clear-RX argument must fit a 32-bit word")
        if type(argument_6) is not int or not -(1 << 31) <= argument_6 < 1 << 31:
            raise ValueError("Native ignored argument must fit signed int32")
        if not isinstance(request, bytes) or len(request) > 0xFFFF:
            raise ValueError("MultiMon request must fit native WORD length")
        target = next((t for t in self.targets if t.command_id == category), None)
        if target is None or target.protocol != bus:
            raise ValueError("MultiMon send differs from its registered target")
        if category not in self.control.registered or self.operations.poisoned:
            return 0x90020701
        # Reject unsafe native storage before target activation can change the driver.
        frame_message(self.transport.plans[target.ecu], request, bus_id=bus)
        try:
            from scripts.toyota_session import NativeFrameSend

            self.operations.defer_cancel_cleanup = self.defer_cancel_cleanup
            self._current = target
            self.transport._bind(target, deadline, self.cancelled)
            # Native14400 ignores refresh status; uncertain primitive I/O still raises.
            self.control.before_send(
                target, deadline=deadline, cancelled=self.cancelled
            )
            return self.transport.send_frame(
                target,
                NativeFrameSend(
                    "SendIntExtDualMon",
                    category,
                    request,
                    timeout,
                    bus,
                    argument_6,
                    clear_rx,
                ),
                deadline=deadline,
                cancelled=self.cancelled,
            )
        except BaseException as error:
            self._failed(error)
            raise

    def receive(
        self,
        *,
        maximum: int,
        timeout: int,
        argument_5: int = 0,
        flags: int = 100,
        buffer: bool = True,
        deadline: float,
    ) -> NativeFrameReceive:
        if self._current is None:
            return NativeFrameReceive(code=0x90020701)
        try:
            self.operations.cancelled = self.cancelled
            return self.operations.receive(
                maximum=maximum,
                timeout=timeout,
                argument_5=argument_5,
                flags=flags,
                buffer=buffer,
                deadline=deadline,
            )
        except BaseException as error:
            self._failed(error)
            raise

    def close(self, *, disconnect_flag: int = 1, deadline: float | None = None) -> int:
        from scripts.monitor_dual import DualControl

        if type(disconnect_flag) is not int or disconnect_flag not in (0, 1):
            raise ValueError("Native MultiMon disconnect flag must be zero or one")
        if deadline is not None and (
            isinstance(deadline, bool)
            or not isinstance(deadline, (int, float))
            or not math.isfinite(deadline)
        ):
            raise ValueError("Finite cleanup seconds deadline required")
        if self.control.channel is None:
            self.transport.released()
            self._current = None
            return 0
        try:
            until = (
                float(deadline)
                if deadline is not None
                else self.operations._now() + 5.0
            )
            if self.control.poisoned:
                code = self.control.close_resources(
                    deadline=until, cancelled=lambda: False
                )
            else:
                code = self.control.execute(
                    DualControl("Disconnect", (disconnect_flag,)),
                    deadline=until,
                    cancelled=lambda: False,
                )
            self.transport.released()
            self._current = None
            return code
        except _HostClockError as error:
            if deadline is not None:
                raise
            self.cleanup_error = error
            self.control.poisoned = self.operations.poisoned = True
            previous = self.control.clock
            try:
                # A failed host clock permits only resource release on a fresh finite clock.
                self.control.clock = time.monotonic
                code = self.control.close_resources(
                    deadline=time.monotonic() + 5.0,
                    cancelled=lambda: False,
                )
                self.transport.released()
                self._current = None
                return code
            finally:
                self.control.clock = previous
        except BaseException as error:
            self._failed(error)
            raise
