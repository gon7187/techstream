"""Recovered UtilityEx UDS transaction/session algorithms, without implicit I/O.

The native lower connection, filter and worker lifecycle is deliberately not
substituted with Common or CUW2026. Unported manager initialization fails closed.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from dataclasses import field as dataclass_field
from typing import TYPE_CHECKING, Protocol, TypeVar, cast

from scripts.j2534_2026 import (
    J2534Device2026,
    NativeJ2534Error2026,
    NativeMessage,
    PrimitiveResult,
)

if TYPE_CHECKING:
    from scripts.utility_ex_lifecycle import (
        UtilityExClassicCANLower,
        UtilityExFixedLifecycle,
        UtilityExSISFields,
        UtilityExSISLifecycle,
        UtilityExSISLower,
    )


class UtilityExSourceError(ValueError):
    """The exact source operation has not been recovered."""


@dataclass(frozen=True)
class DriverReceive:
    """One native lower receive result; status is not a business result."""

    status: int
    data: bytes = b""
    native_error: int = 0

    def __post_init__(self):
        for value in (self.status, self.native_error):
            if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
                raise ValueError("Native receive status must be uint32")
        if not isinstance(self.data, bytes) or len(self.data) > 0x101F:
            raise ValueError("Bounded immutable native response required")


def pack_uds_request(address: int, request: bytes, protocol: int = 6) -> NativeMessage:
    """18 NK24a90: four big-endian address bytes precede the service bytes."""
    if type(address) is not int or not 0 <= address <= 0xFFFFFFFF:
        raise ValueError("Native address must be uint32")
    if not isinstance(request, bytes) or len(request) > 0x101C:
        raise ValueError("Bounded immutable request required")
    return NativeMessage(protocol, address.to_bytes(4, "big") + request)


def pack_p6_request(address: int, request: bytes, protocol: int = 6) -> NativeMessage:
    """Plus P625cc0/47870: CAN29 header and literal CANFD flags."""
    if type(protocol) is not int or protocol not in (6, 0x8012):
        raise ValueError("P6 physical protocol must be6 or8012")
    return replace(
        pack_uds_request(address, request, protocol),
        tx_flags=0x180140 if protocol == 0x8012 else 0x140,
    )


def p6_configuration(
    protocol: int,
    *,
    override: bool,
    flags: int,
    timing: int,
    broker_parameters: tuple[tuple[int, int], ...] = (),
) -> tuple[tuple[int, int], ...]:
    """Plus25340/46ef0: rebuild literal five/nine-entry SET_CONFIG lists."""
    if type(protocol) is not int or protocol not in (6, 0x8012):
        raise ValueError("P6 physical protocol must be6 or8012")
    if type(override) is not bool:
        raise TypeError("Explicit P6 configuration branch required")
    if any(
        type(value) is not int or not 0 <= value <= 0xFFFFFFFF
        for value in (flags, timing)
    ):
        raise ValueError("Native live configuration fields must be uint32")
    if not isinstance(broker_parameters, tuple) or len(broker_parameters) > 65536:
        raise ValueError("Bounded immutable native SCONFIG_LIST required")
    values = {0x805C: 0, 0x8001: 0, 0x805D: 0, 0x8060: 0, 0x23: 0xFFFF, 0x2A: 0xFFFF}
    for pair in broker_parameters:
        if (
            not isinstance(pair, tuple)
            or len(pair) != 2
            or any(
                type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in pair
            )
        ):
            raise ValueError("Native SCONFIG entries must be uint32 pairs")
        if pair[0] in values:
            values[pair[0]] = pair[1]
    standard = (
        (0x10103, 0x300000 if override else flags),
        (1, 500000),
        (0x10106, 50 if override else timing),
        (0x23, 0 if override else values[0x23]),
        (0x2A, 3 if override else values[0x2A]),
    )
    if protocol == 6:
        return standard
    return (
        (0x805C, 2000000 if override else values[0x805C]),
        (0x8001, 0x60E if override else values[0x8001]),
        *standard,
        (0x805D, 0x20 if override else values[0x805D]),
        (0x8060, 0xCC if override else values[0x8060]),
    )


def pack_p3_request(address: int, request: bytes, protocol: int = 0) -> NativeMessage:
    """NK18 16870/16b00:80+length,target,f0,payload,additive checksum.

    The caller zeroes the backing;21960 later writes the channel protocol.
    """
    if type(address) is not int or not 0 <= address <= 0xFFFFFFFF:
        raise ValueError("Native P3 target must be uint32")
    if not isinstance(request, bytes) or len(request) > 0x101C:
        raise ValueError("Bounded immutable P3 request required")
    data = bytes(((len(request) + 0x80) & 255, address & 255, 0xF0)) + request
    return NativeMessage(protocol, data + bytes((sum(data) & 255,)))


def unpack_p3_response(message: NativeMessage, address: int) -> DriverReceive:
    """NK18 168d0: validate destination/source/checksum, map only78 and21."""
    if type(address) is not int or not 0 <= address <= 0xFFFFFFFF:
        raise ValueError("Native P3 target must be uint32")
    data = message.data
    # Native's unchecked length subtraction can overrun its output on malformed
    # frames; the host boundary rejects that invalid memory operation.
    if len(data) < 4 or data[1] != 0xF0 or data[2] != address:
        return DriverReceive(3)
    if data[-1] != sum(data[:-1]) & 255:
        return DriverReceive(3)
    payload = data[3:-1]
    padded = payload.ljust(3, b"\0")
    status = {0x78: 5, 0x21: 27}.get(padded[2], 0) if padded[0] == 0x7F else 0
    return DriverReceive(status, payload)


NATIVE_NRC: dict[int, int] = dict(
    zip(
        (
            0x10,
            0x12,
            0x13,
            0x14,
            0x21,
            0x22,
            0x24,
            0x31,
            0x33,
            0x35,
            0x36,
            0x37,
            0x70,
            0x71,
            0x72,
            0x73,
            0x78,
            0x7E,
            0x92,
            0x93,
        ),
        range(100, 120),
    )
)


def unpack_uds_response(
    message: NativeMessage, address: int, response_delta: int = 8
) -> DriverReceive:
    """18 NK24af0: exact address and negative-response length/status mapping.

    The native lower applies its configured sleep after NRC12/21/other negatives;
    this pure codec leaves that sleep to its caller, never sleeps on NRC78.
    """
    if type(address) is not int or not 0 <= address <= 0xFFFFFFFF:
        raise ValueError("Native response address must be uint32")
    if type(response_delta) is not int or response_delta not in (8, 16):
        raise ValueError("Reviewed native response address delta required")
    response_address = (address + response_delta) & 0xFFFFFFFF
    if len(message.data) < 4 or message.data[:4] != response_address.to_bytes(4, "big"):
        return DriverReceive(3)
    return _native_uds_payload(message.data[4:])


def _native_uds_payload(response: bytes) -> DriverReceive:
    status, error = 0, 0
    if response[:1] == b"\x7f":
        if len(response) != 3:
            status = 3
        else:
            status = {0x12: 0x16, 0x21: 0x1B, 0x78: 5}.get(response[2], 7)
            error = NATIVE_NRC.get(response[2], 999)
    return DriverReceive(status, response, error)


def unpack_p6_response(message: NativeMessage, address: int) -> DriverReceive:
    """Plus25930/474e0:18DA followed by target bytes in the opposite order."""
    if type(address) is not int or not 0 <= address <= 0xFFFFFFFF:
        raise ValueError("Native P6 address must be uint32")
    header = bytes((0x18, 0xDA, address & 255, (address >> 8) & 255))
    if len(message.data) < 4 or message.data[:4] != header:
        return DriverReceive(3)
    return _native_uds_payload(message.data[4:])


class DriverOperations(Protocol):
    """Individual native lower operations; no exchange/init/business callback."""

    def send(self, request: bytes) -> int: ...
    def receive(self) -> DriverReceive: ...
    def interrupt(self, timeout_ms: int) -> int | None: ...


class CommContext(Protocol):
    module_sha256: str
    module_bytes: bytes
    state: dict[str, object]

    def broker(self, key: int) -> int: ...
    def broker_data(self, key: int) -> bytes: ...
    def native_parameter(self, key: int) -> int: ...
    def driver_binding(
        self, protocol: int, *, constructor_parameter: int = 0
    ) -> object: ...
    def is_cancelled(self) -> bool: ...
    def ticks(self) -> int: ...
    def sleep(self, milliseconds: int) -> None: ...
    def native_sleep(self, milliseconds: int) -> None: ...


_T = TypeVar("_T")
# One published owner per context key. The lock covers creation and publication,
# not native I/O, so a slow constructor cannot be raced into a second owner.
_PUBLICATION_LOCK = threading.RLock()


def _published_state(
    context: CommContext,
    key: str,
    expected: type[_T] | tuple[type, ...],
    factory: Callable[[], _T],
    error: str,
    error_type: type[Exception] = TypeError,
    *,
    contextual: bool = True,
) -> _T:
    """Return the single same-context owner published under one state key."""

    def checked(value: object) -> _T:
        if not isinstance(value, expected) or (
            contextual and getattr(value, "context", None) is not context
        ):
            raise error_type(error)
        return cast(_T, value)

    value = context.state.get(key)
    if value is not None:
        return checked(value)
    with _PUBLICATION_LOCK:
        value = context.state.get(key)
        if value is None:
            created = factory()
            context.state[key] = created
            value = created
        return checked(value)


SHA_18_TY = "79fc495c68eb099a7ebc0d1eefe0eafd80101ac0bc09a58d3f603ed556c84762"
SHA_18_NK = "8d9623f028f23876f69cb02baa10e1881c01fa01a4f906013bd36266f7e0fb33"

SHA_12_NK = "980435d6bb2d9c57aab29e8f281d2641e3822b3172728f223c975ec6493d3c1e"
SHA_12_TY = "e85b2456b26d3966ca243c03fa775cf81ad58bf05689bdb87b616eda4c8b6f5f"
SHA_DS4_NK = "797833dc0c798984fcb739c21ac6fbd5230871fb67495d3339698df2ee53753f"
SHA_DS4_TY = "87bc49ada3f9dc8db442e74ebaf62ce868679b37d58fe3fdc4d3f24e31c4ce57"
SHA_PLUS_NK = "36dcdad2e72e29aae813db5576daf0168dd032b08a9cdda3841078dfb0b7b9fd"
SHA_PLUS_TY = "821bbfd9957679ceef4ac32c239b8840c984e98ac61050ce7348ac2bc88b04ce"

# Each exact source selector, normalized by branch rather than data layout.
_MANAGER_OBJECTS = {
    SHA_18_TY: (
        0x10118E00,
        0x1011A108,
        0x1011E5E0,
        0x10119FC0,
        0x1011A1E8,
        0x10118E40,
        0x10118DB0,
        0x10118E90,
        0x10118D70,
        0x10118CA0,
        0x1011A078,
        0x1011A198,
    ),
    SHA_18_NK: (
        0x1014AEF0,
        0x1014C1F8,
        0x101506D0,
        0x1014C0B0,
        0x1014C2D8,
        0x1014AF30,
        0x1014AEA0,
        0x1014AF80,
        0x1014AE60,
        0x1014AD90,
        0x1014C168,
        0x1014C288,
    ),
    SHA_12_NK: (
        0x100E6240,
        0x100E6488,
        0x100EA940,
        0x100E6368,
        0x100E6550,
        0x100E6278,
        0x100E61F8,
        0x100E62C0,
        0x100E61C0,
        0x100E6108,
        0x100E6408,
        0x100E6508,
    ),
    SHA_12_TY: (
        0x100AB740,
        0x100AB988,
        0x100AFE40,
        0x100AB868,
        0x100ABA50,
        0x100AB778,
        0x100AB6F8,
        0x100AB7C0,
        0x100AB6C0,
        0x100AB608,
        0x100AB908,
        0x100ABA08,
    ),
    SHA_DS4_NK: (
        0x101B4208,
        0x101B549C,
        0x101B66A4,
        0x101B554C,
        0x101B8938,
        0x101B8A10,
        0x101B6658,
        0x101B5408,
        0x101B66D8,
        0x101B53B8,
        0x101B54D0,
        0x101B1FA0,
    ),
    SHA_DS4_TY: (
        0x1006AA38,
        0x1006BCCC,
        0x1006CED4,
        0x1006BD7C,
        0x1006F168,
        0x1006F240,
        0x1006CE88,
        0x1006BC38,
        0x1006CF08,
        0x1006BBE8,
        0x1006BD00,
        0x100687D0,
    ),
    SHA_PLUS_NK: (
        0x101BF318,
        0x101C05B8,
        0x101C17E0,
        0x101C0674,
        0x101C6D68,
        0x101C7F38,
        0x101C1790,
        0x101C0520,
        0x101C1818,
        0x101C04D0,
        0x101C05F0,
        0x101BD0A0,
    ),
    SHA_PLUS_TY: (
        0x10136D48,
        0x10137FE8,
        0x10139210,
        0x101380A4,
        0x1013E798,
        0x1013F968,
        0x101391C0,
        0x10137F50,
        0x10139248,
        0x10137F00,
        0x10138020,
        0x10134AD0,
    ),
}


_FIXED_OBJECTS = {
    SHA_12_NK: 0x100E9850,
    SHA_18_NK: 0x1014F5E0,
    SHA_DS4_NK: 0x101B6758,
    SHA_PLUS_NK: 0x101C18A0,
    SHA_12_TY: 0x100AED50,
    SHA_18_TY: 0x1011D4F0,
    SHA_DS4_TY: 0x1006CF88,
    SHA_PLUS_TY: 0x101392D0,
}
# PlusTY CRT100011d0/11f0 invoke the same1d360 constructor for these
# distinct objects. Their mutable manager fields must never be shared.
_ADDITIONAL_FIXED_OBJECTS = {
    SHA_18_TY: (0x1011C400, 0x1011A220, 0x1011B310),
    SHA_PLUS_TY: (0x10135C58, 0x1013D6A8, 0x10136E10),
}
_P6_OBJECTS = {SHA_PLUS_NK: (0x101C6DA0,), SHA_PLUS_TY: (0x1013E7D0,)}
_SIS_OBJECTS = {SHA_18_TY: (0x1011E618,), SHA_PLUS_TY: (0x10134B78,)}
_CAN_LOWER_SOURCES = (
    SHA_12_NK,
    SHA_12_TY,
    SHA_18_NK,
    SHA_18_TY,
    SHA_DS4_NK,
    SHA_DS4_TY,
    SHA_PLUS_NK,
    SHA_PLUS_TY,
)
_SELECTED_LOWER_OBJECTS = _MANAGER_OBJECTS
_SELECTED_GLOBALS = {
    SHA_12_NK: (0x100EA9A4, 0x100EA9A8, 0x100EA9D0),
    SHA_12_TY: (0x100AFEA0, 0x100AFEA4, 0x100AFECC),
    SHA_18_NK: (0x10151854, 0x10151858, 0x10151880),
    SHA_18_TY: (0x1011F760, 0x1011F764, 0x1011F78C),
    SHA_DS4_NK: (0x101B8B44, 0x101B8B4C, 0x101B8B50),
    SHA_DS4_TY: (0x1006F378, 0x1006F380, 0x1006F384),
    SHA_PLUS_NK: (0x101C8074, 0x101C807C, 0x101C8080),
    SHA_PLUS_TY: (0x1013FAA8, 0x1013FAB0, 0x1013FAB4),
}
# Current object, abort, pending count, worker handoff, worker owner.
_SELECTED_PENDING_GLOBALS = {
    SHA_12_NK: (0x100EA9A4, 0x100EA9AC, 0x100EA9C0, 0x100EA9E0, 0x100EBA08),
    SHA_12_TY: (0x100AFEA0, 0x100AFEA8, 0x100AFEBC, 0x100AFEE4, 0x100B0F0C),
    SHA_18_NK: (0x10151854, 0x1015185C, 0x10151870, 0x10151890, 0x101528B8),
    SHA_18_TY: (0x1011F760, 0x1011F768, 0x1011F77C, 0x1011F7A4, 0x101207CC),
    SHA_DS4_NK: (0x101B8B44, 0x101B8B48, 0x101B8B64, 0x101B8B70, 0x101B8B74),
    SHA_DS4_TY: (0x1006F378, 0x1006F37C, 0x1006F398, 0x1006F3A8, 0x1006F3AC),
    SHA_PLUS_NK: (0x101C8074, 0x101C8078, 0x101C8094, 0x101C80A0, 0x101C80A4),
    SHA_PLUS_TY: (0x1013FAA8, 0x1013FAAC, 0x1013FAC8, 0x1013FAD8, 0x1013FADC),
}

_TARGET_GLOBAL_BASES = {
    SHA_12_NK: 0x100EA978,
    SHA_18_NK: 0x101517F0,
    SHA_DS4_NK: 0x101B8AD8,
    SHA_PLUS_NK: 0x101C8008,
    SHA_12_TY: 0x100AFE78,
    SHA_18_TY: 0x1011F700,
    SHA_DS4_TY: 0x1006F308,
    SHA_PLUS_TY: 0x1013FA38,
}
_FIXED_SETTERS = {
    SHA_12_NK: (0x110E0, 0x11100, 0x11160),
    SHA_18_NK: (0x18970, 0x18990, 0x189C0),
    SHA_DS4_NK: (0x33620, 0x33640, 0x33660),
    SHA_PLUS_NK: (0x34630, 0x34650, 0x34670),
    SHA_12_TY: (0x12960, 0x12980, 0x129D0),
    SHA_18_TY: (0x1A860, 0x1A880, 0x1A8C0),
    SHA_DS4_TY: (0x11700, 0x11720, 0x11740),
    SHA_PLUS_TY: (0x1E290, 0x1E2B0, 0x1E2D0),
}
_NATIVE_COUNTER_GETTERS = {
    SHA_12_NK: (0xFAB0, 0xFAC0, 0xFAD0, 0xFAE0, 0xFAF0),
    SHA_18_NK: (0x17340, 0x17350, 0x17360, 0x17370, 0x17380),
    SHA_DS4_NK: (0x321B0, 0x321A0, 0x321C0, 0x321E0, 0x321F0),
    SHA_PLUS_NK: (0x330C0, 0x330B0, 0x330D0, 0x330F0, 0x33100),
}
_SHORT_RECEIVE_SETTERS = {
    SHA_12_NK: 0x10FB0,
    SHA_18_NK: 0x18840,
    SHA_DS4_NK: 0x32B90,
    SHA_PLUS_NK: 0x33AA0,
    SHA_18_TY: 0x1A730,
}
_GLOBAL_PENDING_SETTERS = {
    SHA_12_NK: 0xFA60,
    SHA_18_NK: 0x172D0,
    SHA_DS4_NK: 0x32410,
    SHA_PLUS_NK: 0x33320,
    SHA_12_TY: 0xB940,
    SHA_18_TY: 0x12180,
    SHA_DS4_TY: 0x7930,
    SHA_PLUS_TY: 0x142F0,
}


# Independently recovered direct setters. Modern NK swaps the order of the
# busy time budget and the inter-request delay; RVA adjacency is not a schema.
_GLOBAL_COUNTER_SETTERS = {
    SHA_12_NK: {
        0xFA70: "pending_ms",
        0xFA80: "no_response_limit",
        0xFA90: "busy_limit",
        0xFAA0: "busy_ms",
        0xFB00: "busy_interval_ms",
    },
    SHA_18_NK: {
        0x172E0: "pending_ms",
        0x172F0: "no_response_limit",
        0x17320: "busy_limit",
        0x17330: "busy_ms",
        0x17390: "busy_interval_ms",
    },
    SHA_DS4_NK: {
        0x32420: "pending_ms",
        0x32430: "continue_pending",
        0x32440: "busy_ms",
        0x32450: "busy_limit",
        0x32460: "busy_interval_ms",
        0x32480: "no_response_limit",
    },
    SHA_PLUS_NK: {
        0x33330: "pending_ms",
        0x33340: "continue_pending",
        0x33350: "busy_ms",
        0x33360: "busy_limit",
        0x33370: "busy_interval_ms",
        0x33390: "no_response_limit",
    },
    SHA_12_TY: {
        0xB950: "pending_ms",
        0xB960: "busy_limit",
        0xB970: "busy_ms",
        0xB990: "busy_interval_ms",
    },
    SHA_18_TY: {
        0x12170: "pending_count",
        0x12190: "pending_ms",
        0x121A0: "no_response_limit",
        0x121D0: "busy_limit",
        0x121E0: "busy_ms",
        0x12200: "busy_interval_ms",
    },
    SHA_DS4_TY: {
        0x7940: "pending_ms",
        0x7950: "busy_ms",
        0x7960: "busy_limit",
        0x7970: "no_response_limit",
    },
    SHA_PLUS_TY: {
        0x14300: "pending_ms",
        0x14310: "busy_ms",
        0x14320: "busy_limit",
        0x14330: "no_response_limit",
    },
}


def select_native_manager(source_sha256: str, mode: int, protocol: int) -> int | None:
    """Native branch order matters: protocol21 ignores the mode entirely."""
    if source_sha256 not in _MANAGER_OBJECTS:
        raise UtilityExSourceError("UtilityEx selector source is not reviewed")
    for value in (mode, protocol):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("Native selector inputs must be uint32")
    objects = _MANAGER_OBJECTS[source_sha256]
    if protocol == 0x11:
        index = {3: 0, 0x12: 1, 4: 2}.get(mode)
    elif protocol == 0x21:
        index = 3
    elif protocol == 0x51:
        index = {3: 4, 4: 2}.get(mode)
    elif mode == 0x13:
        index = {0x1A: 5, 0x4A: 6, 0x5A: 7}.get(protocol)
    elif mode in (4, 0x14, 0x15) or (
        mode == 0x34 and source_sha256 not in (SHA_12_NK, SHA_12_TY)
    ):
        index = ({0x12: 8, 0x22: 10} if mode == 4 else {0x12: 9, 0x22: 11}).get(
            protocol
        )
    else:
        index = None
    return None if index is None else objects[index]


def native_manager_protocol(source_sha256: str, manager: int) -> int:
    """All8 exact global object vslot1c getters, individually source-checked."""
    if source_sha256 not in _MANAGER_OBJECTS:
        raise UtilityExSourceError("Native manager protocol source is not reviewed")
    if type(manager) is not int:
        raise ValueError("Native global manager identity must be uint32")
    try:
        index = _MANAGER_OBJECTS[source_sha256].index(manager)
    except ValueError as error:
        raise UtilityExSourceError("Unknown native selected global manager") from error
    return (1, 15, 6, 4, 3, 13, 13, 13, 5, 16, 8, 17)[index]


@dataclass
class UDSFields:
    """Constructor offsets, TY19b70/NK17bc0, with native mutable state."""

    pending_count: int = 0  # 10ac
    busy_interval_ms: int = 0  # 10a8
    suppress_positive: int = 0  # 1068
    receive_cancelled: int = 0  # 1088
    no_response_seen: int = 0  # 1094
    busy_seen: int = 0  # 109c
    retry_count: int = 3  # 1064
    receive_count: int = 150  # 1080
    receive_ms: int = 180000  # 1084
    response_pending_count: int = 3  # 1098
    busy_count: int = 0xFF  # 10a0
    busy_ms: int = 0  # 10a4
    suppress_error: int = 0  # 106c
    continue_pending: int = 0  # 1090
    current_session: int = 0  # 105c
    diagnostic_enabled: int = 1  # 1060
    response_pending_seen: int = 0  # 108c
    native_error: int = 0  # 10b0
    primary_address: int = 0  # 10d4
    alternate_address: int = 0  # 10d8
    alternate_extension: int = 0  # 10dc
    extension: int = 0  # 10e0
    oem_parameter: int = 0  # 10ec
    target_configured: bool = False  # 10d0 starts1 until19d40/17e10
    lower_kind: int = 0  # 107c, explicit selected lower class
    parameters: tuple[tuple[int, int], ...] = ()  # 10e4/10e8


@dataclass
class UtilityExP6Fields(UDSFields):
    """Plus1e5f0/3ee30 semantic state; native offsets are explicitly separate."""

    native_109c: int = 1000
    no_response_seen: int = 0
    busy_seen: int = 0
    pending_count: int = 0
    suppress_positive: int = 0
    receive_cancelled: int = 0


P6_FIELD_OFFSETS = {
    0x105C: "current_session",  # Byte, unlike the ordinary DWORD member.
    0x1060: "diagnostic_enabled",
    0x1064: "retry_count",
    0x1068: "suppress_positive",
    0x106C: "suppress_error",
    0x107C: "lower_kind",
    0x1080: "receive_count",
    0x1084: "receive_ms",
    0x1088: "receive_cancelled",
    0x108C: "response_pending_seen",
    0x1090: "continue_pending",
    0x1094: "no_response_seen",
    0x1098: "response_pending_count",
    0x109C: "native_109c",
    0x10A0: "busy_seen",
    0x10A4: "busy_count",
    0x10A8: "busy_ms",
    0x10AC: "busy_interval_ms",
    0x10B0: "pending_count",
    0x10B4: "native_error",
    0x10D8: "target_configured",  # Native DWORD is inverted:1 means defaults pending.
    0x10DC: "primary_address",
    0x10E0: "alternate_address",
    0x10E4: "alternate_extension",
    0x10E8: "extension",
    0x10F4: "oem_parameter",
}


def elapsed(now: int, start: int) -> int:
    """GetTickCount subtraction uses uint32 wrap, not signed host time."""
    return (now - start) & 0xFFFFFFFF


def _uds_fields(context: CommContext, manager: int) -> UDSFields:
    key = f"utility_ex:uds_fields:{context.module_sha256}:{manager:x}"
    return _published_state(
        context,
        key,
        UDSFields,
        UDSFields,
        "Concrete native UDS manager fields required",
        contextual=False,
    )


class UtilityExUDSScheduler:
    """18 TY128d0/NK22a80 over individual lower send/receive primitives.

    This class does not connect a manager. Its caller must hold an established
    native lower and serialize it with the native keepalive worker.
    """

    def __init__(
        self,
        context: CommContext,
        driver: DriverOperations,
        *,
        fields: UDSFields | None = None,
    ):
        if fields is not None and not isinstance(fields, UDSFields):
            raise TypeError("Concrete native UDS manager fields required")
        self.context, self.driver = context, driver
        self.fields = UDSFields() if fields is None else fields
        self.cancel_receive = False
        self._suppress_positive = False
        self._calls = 0

    @property
    def last_native_error(self) -> int:
        return self.fields.native_error

    @last_native_error.setter
    def last_native_error(self, value: int) -> None:
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("Native error field must be uint32")
        self.fields.native_error = value

    def _check(self) -> None:
        self._calls += 1
        if self._calls > 65536:
            raise TimeoutError("UtilityEx host primitive call budget exceeded")

    def _receive(self) -> DriverReceive:
        # TY1a2b0/NK183c0: 5 is NRC78; 1b is NRC21, not the reverse.
        start, count = self.context.ticks(), 0
        while True:
            self._check()
            reply = self.driver.receive()
            if not isinstance(reply, DriverReceive):
                raise TypeError("Typed native lower receive required")
            if len(reply.data) == 3 and reply.data[0] == 0x7F:
                self.last_native_error = NATIVE_NRC.get(reply.data[2], 999)
            if reply.status != 5:
                if (
                    reply.status == 7
                    and self.last_native_error == 100
                    and self.fields.suppress_error == 1
                ):
                    self.last_native_error = 0x3E6
                    return DriverReceive(7, reply.data, 0x3E6)
                return reply
            self.fields.suppress_error = 1
            self._suppress_positive = False
            count += 1
            limit = (
                elapsed(self.context.ticks(), start) >= self.fields.receive_ms
                if self.fields.receive_ms
                else count >= self.fields.receive_count
            )
            if self.cancel_receive or (limit and not self.fields.continue_pending):
                self.driver.interrupt(100)
                return DriverReceive(
                    20 if self.cancel_receive else 5, reply.data, reply.native_error
                )

    def exchange(self, request: bytes) -> tuple[int, bytes]:
        if not isinstance(request, bytes) or not 1 <= len(request) <= 0x101F:
            raise ValueError("Bounded nonempty native request required")
        self._calls = 0
        self._check()
        f = self.fields
        start, retry, no_response, busy = self.context.ticks(), 0, 0, 0
        self._suppress_positive = (
            len(request) >= 2
            and request[0] in (0x10, 0x11, 0x19, 0x27, 0x2C, 0x31, 0x3E, 0x85)
            and bool(request[1] & 0x80)
        )
        f.suppress_error = 0
        self.cancel_receive = False
        try:
            while True:
                self._check()
                self.last_native_error = 0
                status = self.driver.send(request)
                if type(status) is not int or not 0 <= status <= 0xFFFFFFFF:
                    raise ValueError("Native send status must be uint32")
                if status:
                    return status, b""
                reply = self._receive()
                status = reply.status
                if self.context.is_cancelled():
                    return status, reply.data
                if status == 0x1B:
                    busy += 1
                    no_response = 0
                    exhausted = (
                        elapsed(self.context.ticks(), start) >= f.busy_ms
                        if f.busy_ms
                        else busy >= f.busy_count
                    )
                    if exhausted:
                        return 0x1C, reply.data
                    continue
                if status == 2:
                    if self._suppress_positive:
                        return 0, reply.data
                    no_response += 1
                    if no_response < f.response_pending_count:
                        continue
                    return status, reply.data
                if status == 5:
                    return status, reply.data
                if (
                    status == 7
                    and reply.native_error == 0x3E6
                    and f.suppress_error == 1
                ):
                    return 5, reply.data
                if status == 0:
                    # ASM12a3c: compare request SID + 0x40 against response SID.
                    return (
                        0 if reply.data and reply.data[0] == request[0] + 0x40 else 3
                    ), reply.data
                retry += 1
                if retry >= f.retry_count:
                    return status, reply.data
        finally:
            f.suppress_error = 0

    def session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int:
        # Session helpers require worker lifecycle, which remains unported.
        if keepalive:
            raise UtilityExSourceError("Native UtilityEx keepalive worker is unported")
        if type(mode) is not int or not 0 <= mode <= 255:
            raise ValueError("Session mode must be uint8")
        if normal_first:
            if mode != 3:
                raise ValueError("Native extended helper selects session3")
            status, response = self.exchange(b"\x10\x01")
            if status:
                return status
            if len(response) < 2:
                return 3
            if response[1] != 1:
                return 7
        selected = mode & 0x7F
        if not normal_first and self.fields.diagnostic_enabled != 1 and selected != 1:
            return 0x16
        status, response = self.exchange(bytes((0x10, mode)))
        if status == 0 and not mode & 0x80:
            if len(response) < 2:
                status = 3
            elif response[1] != selected:
                status = 7
        if status == 0:
            self.fields.current_session = selected
        return status


class UtilityExP6UDSScheduler(UtilityExUDSScheduler):
    """Plus25fd0/47f40 and1f150: primary P6 exchange with retained counters."""

    def __init__(
        self,
        context: CommContext,
        driver: DriverOperations,
        *,
        fields: UtilityExP6Fields,
    ):
        if not isinstance(fields, UtilityExP6Fields):
            raise TypeError("Concrete P6 native fields required")
        super().__init__(context, driver, fields=fields)

    def _receive(self) -> DriverReceive:
        f = self.fields
        start, count = self.context.ticks(), 0
        while True:
            self._check()
            reply = self.driver.receive()
            if not isinstance(reply, DriverReceive):
                raise TypeError("Typed native lower receive required")
            if len(reply.data) == 3 and reply.data[0] == 0x7F:
                self.last_native_error = NATIVE_NRC.get(reply.data[2], 999)
            if reply.status == 7:
                if self.last_native_error == 100 and f.suppress_error == 1:
                    self.last_native_error = 0x3E6
                return DriverReceive(7, reply.data, self.last_native_error)
            if reply.status != 5:
                if reply.status == 27:
                    f.pending_count = 0
                return reply
            f.suppress_error = 1
            f.suppress_positive = 0
            if f.receive_ms:
                exhausted = elapsed(self.context.ticks(), start) >= f.receive_ms
            else:
                count += 1
                f.pending_count = count
                exhausted = count >= f.receive_count
            if f.receive_cancelled or (exhausted and not f.continue_pending):
                # Native1df50 first tests108c, then clears1088 on every branch.
                cancelled = f.receive_cancelled
                f.receive_cancelled = 0
                if f.response_pending_seen:
                    return DriverReceive(0, reply.data, self.last_native_error)
                self.driver.interrupt(100)
                return DriverReceive(
                    20 if cancelled else 5, reply.data, self.last_native_error
                )

    def exchange(self, request: bytes) -> tuple[int, bytes]:
        if not isinstance(request, bytes) or not 1 <= len(request) <= 0x101F:
            raise ValueError("Bounded nonempty native request required")
        self._calls = 0
        f = self.fields
        start, retry = self.context.ticks(), 0
        f.busy_seen = f.no_response_seen = f.receive_cancelled = 0
        f.suppress_positive = int(
            len(request) >= 2
            and request[0] in (0x10, 0x11, 0x19, 0x27, 0x2C, 0x31, 0x3E, 0x85)
            and bool(request[1] & 0x80)
        )
        try:
            while True:
                self._check()
                self.last_native_error = 0
                f.pending_count = 0
                status = self.driver.send(request)
                if type(status) is not int or not 0 <= status <= 0xFFFFFFFF:
                    raise ValueError("Native send status must be uint32")
                if status:
                    return status, b""
                reply = self._receive()
                status = reply.status
                if self.context.is_cancelled():
                    return status, reply.data
                if status == 27:
                    if f.busy_ms:
                        exhausted = elapsed(self.context.ticks(), start) >= f.busy_ms
                    else:
                        f.busy_seen += 1
                        f.no_response_seen = 0
                        exhausted = f.busy_seen >= f.busy_count
                    if exhausted:
                        return 28, reply.data
                    continue
                if status == 2:
                    if f.suppress_positive == 1:
                        return 0, reply.data
                    f.no_response_seen += 1
                    if f.no_response_seen < f.response_pending_count:
                        continue
                    return status, reply.data
                if status == 5:
                    return status, reply.data
                if (
                    status == 7
                    and self.last_native_error == 0x3E6
                    and f.suppress_error == 1
                ):
                    return 5, reply.data
                if status == 0:
                    return (
                        0 if reply.data and reply.data[0] == request[0] + 0x40 else 3
                    ), reply.data
                retry += 1
                if retry >= f.retry_count:
                    return status, reply.data
        finally:
            f.suppress_error = 0


@dataclass
class ClassicFields:
    """NK18 module globals, shared by selected manager instances and getters."""

    no_response_limit: int = 3  # PE101490d8
    busy_limit: int = 100  # PE101490dc
    busy_ms: int = 0  # 1015186c
    busy_interval_ms: int = 0  # 10151878
    busy_count: int = 0  # 10151868
    no_response_count: int = 0  # 10151864
    pending_limit: int = 100  # NK18 101490e0
    pending_ms: int = 0  # NK18 10151874
    pending_count: int = 0  # NK18 10151870
    continue_pending: int = 0  # NK18 10151860
    short_circuit: int = 0  # NK18 1015187c, derived interrupt16e90

    def counters(self, source_sha256: str = SHA_18_NK) -> dict[str, int]:
        if source_sha256 not in _NATIVE_COUNTER_GETTERS:
            raise UtilityExSourceError(
                "Native cancellation getter source is not reviewed"
            )
        values = (
            self.busy_ms,
            self.busy_count,
            self.busy_limit,
            self.no_response_count,
            self.no_response_limit,
        )
        return {
            f"native_rva:{rva:x}": value
            for rva, value in zip(_NATIVE_COUNTER_GETTERS[source_sha256], values)
        }


def _classic_fields(context: CommContext) -> ClassicFields:
    key = f"utility_ex:classic_globals:{context.module_sha256}"
    return _published_state(
        context,
        key,
        ClassicFields,
        ClassicFields,
        "Concrete native classic counter state required",
        contextual=False,
    )


class UtilityExSelectedPending:
    """NK18 selected17110/17160/173b0 over individual lower primitives.

    Native abort173a0 is a different flag from the outer wrapper cancellation.
    This component retains the pending getter state and worker handoff globals;
    it neither constructs nor initializes a lower manager.
    """

    def __init__(
        self, context: CommContext, driver: DriverOperations, *, derived: bool = False
    ):
        if context.module_sha256 not in _SELECTED_PENDING_GLOBALS:
            raise UtilityExSourceError("Native selected pending source is not reviewed")
        if type(derived) is not bool:
            raise TypeError("Native selected stack class must be explicit")
        self.context, self.driver, self.derived = context, driver, derived
        self.fields = _classic_fields(context)

    def _global_key(self, address: int) -> str:
        index = (0x10151854, 0x1015185C, 0x10151870, 0x10151890, 0x101528B8).index(
            address
        )
        address = _SELECTED_PENDING_GLOBALS[self.context.module_sha256][index]
        return f"native_global:{address:x}"

    def _global(self, address: int) -> int:
        value = self.context.state.get(self._global_key(address), 0)
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("Native selected global must be uint32")
        return value

    def _count(self, count: int) -> None:
        self.fields.pending_count = count
        self.context.state[self._global_key(0x10151870)] = count

    def send(self, request: bytes) -> int:
        if not isinstance(request, bytes) or not 1 <= len(request) <= 0x101F:
            raise ValueError("Bounded nonempty native request required")
        self._count(0)
        # 17110 preserves the worker's state1 handoff, clears only a zero owner.
        worker = self._global(0x101528B8)
        if not (self._global(0x10151890) == 1 and worker == 1) and worker == 0:
            self.context.state[self._global_key(0x10151890)] = 0
        result = self.driver.send(request)
        if type(result) is not int or not 0 <= result <= 0xFFFFFFFF:
            raise ValueError("Native send status must be uint32")
        return result

    def interrupt(self, timeout_ms: int) -> int:
        if timeout_ms != 100 or type(timeout_ms) is not int:
            raise ValueError("Native selected interrupt uses100ms")
        if self.derived and self.fields.short_circuit:
            self.context.state[self._global_key(0x1015185C)] = 0
            return 0
        status = self.driver.interrupt(100)
        if status is None:
            status = 0
        if type(status) is not int or not 0 <= status <= 0xFFFFFFFF:
            raise ValueError("Native interrupt status must be uint32")
        result = (
            (20 if self._global(0x1015185C) else 5)
            if self.derived
            else (status or (20 if self._global(0x1015185C) else 5))
        )
        self.context.state[self._global_key(0x1015185C)] = 0
        return result

    def receive(self) -> DriverReceive:
        start, count, exhausted = self.context.ticks(), 0, False
        try:
            for _ in range(65536):
                reply = self.driver.receive()
                if not isinstance(reply, DriverReceive):
                    raise TypeError("Typed native lower receive required")
                if reply.status != 5:
                    if reply.status == 27:
                        self._count(0)
                    return reply
                if self.fields.pending_ms:
                    if elapsed(self.context.ticks(), start) >= self.fields.pending_ms:
                        exhausted = True
                else:
                    count = (count + 1) & 0xFFFFFFFF
                    self._count(count)
                    if count >= self.fields.pending_limit:
                        exhausted = True
                if self._global(0x1015185C) or (
                    exhausted and not self.fields.continue_pending
                ):
                    return DriverReceive(
                        self.interrupt(100), reply.data, reply.native_error
                    )
            raise TimeoutError("UtilityEx host primitive call budget exceeded")
        finally:
            self.context.state[self._global_key(0x10151890)] = 1


class UtilityExClassicScheduler:
    """18 NK18ef0 selected-manager outer algorithm and actual counter getters.

    Different from fixed UDS22a80: native cancellation returns the last lower
    status and retains the exact counters used by NK14aa0 normalization.
    """

    def __init__(self, context: CommContext, driver: DriverOperations):
        self.context, self.driver = context, driver
        self.fields = _classic_fields(context)

    def counters(self) -> dict[str, int]:
        return self.fields.counters()

    def _wait_busy(self, received: int) -> None:
        # NK18 14b60 / TY18 ff40: unelapsed delay in100ms slices.
        deadline = (received + self.fields.busy_interval_ms) & 0xFFFFFFFF
        while not self.context.is_cancelled():
            now = self.context.ticks()
            if (now + 100) & 0xFFFFFFFF < deadline:
                self.context.native_sleep(100)
                continue
            remaining = (deadline - self.context.ticks()) & 0xFFFFFFFF
            if remaining <= 100:
                self.context.native_sleep(remaining)
            break

    def exchange(self, request: bytes) -> tuple[int, bytes]:
        if not isinstance(request, bytes) or not 1 <= len(request) <= 0x101F:
            raise ValueError("Bounded nonempty native request required")
        self.fields.busy_count = self.fields.no_response_count = 0
        start = self.context.ticks()
        for _ in range(65536):
            status = self.driver.send(request)
            if type(status) is not int or not 0 <= status <= 0xFFFFFFFF:
                raise ValueError("Native send status must be uint32")
            if status:
                return status, b""
            reply = self.driver.receive()
            if not isinstance(reply, DriverReceive):
                raise TypeError("Typed native lower receive required")
            received = self.context.ticks()
            if self.context.is_cancelled():
                return reply.status, reply.data
            if reply.status == 0x1B:
                if self.fields.busy_ms == 0:
                    self.fields.busy_count += 1
                    self.fields.no_response_count = 0
                    if self.fields.busy_count >= self.fields.busy_limit:
                        return 0x1C, reply.data
                elif elapsed(self.context.ticks(), start) >= self.fields.busy_ms:
                    return 0x1C, reply.data
                self._wait_busy(received)
                continue
            if reply.status == 2:
                self.fields.no_response_count += 1
                if self.fields.no_response_count < self.fields.no_response_limit:
                    continue
                return 2, reply.data
            if reply.status:
                return reply.status, reply.data
            return (
                0 if reply.data and reply.data[0] == request[0] + 0x40 else 3
            ), reply.data
        raise TimeoutError("UtilityEx host primitive call budget exceeded")

    def support_snapshot(self, kind: int) -> tuple[int, bytes, tuple[int, ...]]:
        """TY18 11ac0/NK18 19650: collect A8 records until native receive stops.

        Only failures before the first accepted frame are resent. Offset zero
        suppresses the final receive error exactly as the native return branch.
        """
        if type(kind) is not int or not 0 <= kind <= 0xFF:
            raise ValueError("Native support kind must be byte")
        request = bytes((0xA8, kind))
        output, offsets = bytearray(0x1020), [0x1020] * 256
        used, first = 0, True
        self.fields.busy_count = self.fields.no_response_count = 0
        start = self.context.ticks()
        status = self.driver.send(request)
        for _ in range(65536):
            if type(status) is not int or not 0 <= status <= 0xFFFFFFFF:
                raise ValueError("Native send status must be uint32")
            if status:
                break
            reply = self.driver.receive()
            if not isinstance(reply, DriverReceive):
                raise TypeError("Typed native lower receive required")
            received, status = self.context.ticks(), reply.status
            if first:
                if self.context.is_cancelled():
                    break
                if status == 0x1B:
                    if self.fields.busy_ms == 0:
                        self.fields.busy_count += 1
                        self.fields.no_response_count = 0
                        if self.fields.busy_count >= self.fields.busy_limit:
                            status = 0x1C
                            break
                    elif elapsed(self.context.ticks(), start) >= self.fields.busy_ms:
                        status = 0x1C
                        break
                    self._wait_busy(received)
                    status = self.driver.send(request)
                    continue
                if status == 2:
                    self.fields.no_response_count += 1
                    if self.fields.no_response_count >= self.fields.no_response_limit:
                        break
                    status = self.driver.send(request)
                    continue
            if status:
                break
            # Native checks the zero-filled backing, without a minimum length.
            frame = reply.data.ljust(0x1020, b"\0")
            if frame[:2] != bytes((0xE8, kind)):
                status = 3
                break
            # A short declared record consumes its zero-filled tail.
            position = 2
            while position < len(reply.data):
                end = position + 2 + frame[position + 1]
                if end + used > 0x1020:
                    status = 99
                    break
                offsets[frame[position]] = used + position - 2
                position = end
            segment = frame[2:position]
            output[used : used + len(segment)] = segment
            used += len(segment)
            first = False
        else:
            raise TimeoutError("UtilityEx host primitive call budget exceeded")
        return (status if offsets[output[0]] != 0 else 0), bytes(output), tuple(offsets)

    def read_dtcs(self, mode: int = 0x80, capacity: int = 0x1000) -> tuple[int, bytes]:
        """TY18 11870:13[mode],53/count and two-byte records across frames.

        The returned prefix is the first53/count header. Later frame headers
        are discarded. A receive error after the first frame is never resent.
        """
        if self.context.module_sha256 != SHA_18_TY:
            raise UtilityExSourceError("Native selected DTC source is not reviewed")
        if type(mode) is not int or not 0 <= mode <= 255:
            raise ValueError("Native DTC mode must be byte")
        if type(capacity) is not int or not 2 <= capacity <= 0x1020:
            raise ValueError("Native DTC receive capacity must be2..1020")
        request = b"\x13" + (bytes((mode,)) if mode else b"")
        output, expected, count = bytearray(), 0, 0
        first = True
        self.fields.busy_count = self.fields.no_response_count = 0
        start = self.context.ticks()
        status = self.driver.send(request)
        for _ in range(65536):
            if type(status) is not int or not 0 <= status <= 0xFFFFFFFF:
                raise ValueError("Native send status must be uint32")
            if status:
                return status, bytes(output)
            reply = self.driver.receive()
            if not isinstance(reply, DriverReceive):
                raise TypeError("Typed native lower receive required")
            received, status = self.context.ticks(), reply.status
            if first:
                if self.context.is_cancelled():
                    return status, bytes(output)
                if status == 27:
                    if self.fields.busy_ms == 0:
                        self.fields.busy_count += 1
                        self.fields.no_response_count = 0
                        if self.fields.busy_count >= self.fields.busy_limit:
                            return 28, bytes(output)
                    elif elapsed(self.context.ticks(), start) >= self.fields.busy_ms:
                        return 28, bytes(output)
                    self._wait_busy(received)
                    status = self.driver.send(request)
                    continue
                if status == 2:
                    self.fields.no_response_count += 1
                    if self.fields.no_response_count >= self.fields.no_response_limit:
                        return status, bytes(output)
                    status = self.driver.send(request)
                    continue
            if status:
                return status, bytes(output)
            data = reply.data
            if not 2 <= len(data) <= capacity or data[0] != 0x53 or len(data) & 1:
                return 3, bytes(output)
            if first:
                expected = data[1]
                output.extend(data[:2])
                first = False
            # A malformed native aggregate would overrun the fixed local buffer.
            if len(output) + len(data) - 2 > 0x1020:
                return 99, bytes(output)
            output.extend(data[2:])
            count += (len(data) - 2) // 2
            if count >= expected:
                return 0, bytes(output)
        raise TimeoutError("UtilityEx host primitive call budget exceeded")


def _validate_support_key(target: tuple[int, int], protocol: int, kind: int) -> None:
    if (
        not isinstance(target, tuple)
        or len(target) != 2
        or any(
            type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (*target, protocol)
        )
        or type(kind) is not int
        or not 0 <= kind <= 255
    ):
        raise ValueError("Native support profile target/protocol/kind required")


@dataclass(frozen=True)
class UtilityExSupportProfile:
    target: tuple[int, int]
    protocol: int
    kind: int
    data: bytes
    offsets: tuple[int, ...]

    def __post_init__(self):
        _validate_support_key(self.target, self.protocol, self.kind)
        if (
            not isinstance(self.data, bytes)
            or len(self.data) != 0x1020
            or not isinstance(self.offsets, tuple)
            or len(self.offsets) != 256
            or any(
                type(value) is not int or not 0 <= value <= 0x1020
                for value in self.offsets
            )
        ):
            raise ValueError(
                "Native support profile requires bounded data and256 offsets"
            )


class UtilityExSupportCache:
    """NK12/18/DS4/Plus profile cache shared by all selected consumers.

    Native refresh helpers16af0/20100/3db70/3eb80 independently preserve the
    same142c record,16-profile limit, and source-local selected protocol key.
    """

    def __init__(self, context: CommContext):
        if context.module_sha256 not in (SHA_12_NK, SHA_18_NK, SHA_DS4_NK, SHA_PLUS_NK):
            raise UtilityExSourceError(
                "Native support profile cache source is not reviewed"
            )
        self.context = context
        self.profiles: list[UtilityExSupportProfile] = []
        self._lock = threading.RLock()

    def _index(self, kind: int, target: tuple[int, int], protocol: int) -> int | None:
        return next(
            (
                index
                for index, profile in enumerate(self.profiles)
                if (profile.kind, profile.target, profile.protocol)
                == (kind, target, protocol)
            ),
            None,
        )

    def refresh(
        self,
        scheduler: UtilityExClassicScheduler,
        kind: int,
        target: tuple[int, int],
        protocol: int,
    ) -> int:
        if (
            not isinstance(scheduler, UtilityExClassicScheduler)
            or scheduler.context is not self.context
        ):
            raise TypeError("Concrete same-context A8 scheduler required")
        # Validate metadata before attempting a native send or capacity decision.
        _validate_support_key(target, protocol, kind)
        with self._lock:
            index = self._index(kind, target, protocol)
            if index is None and len(self.profiles) >= 16:
                return 80
            status, data, offsets = scheduler.support_snapshot(kind)
            if status:
                return status
            try:
                profile = UtilityExSupportProfile(target, protocol, kind, data, offsets)
                if index is None:
                    self.profiles.append(profile)
                else:
                    self.profiles[index] = profile
            except MemoryError:
                return 81
            return 0

    def append(
        self, raw: bytes, kind: int, target: tuple[int, int], protocol: int
    ) -> int:
        """NK12 17580/18 20b90/DS4 3d4c0/Plus 3e4d0 append profiles.

        This source primitive deliberately has no16-profile admission limit;
        refresh20100 still enforces its own limit for a new key.
        """
        _validate_support_key(target, protocol, kind)
        if not isinstance(raw, bytes) or len(raw) > 0x1020:
            raise ValueError("Bounded immutable native support input required")
        try:
            offsets = [0x1020] * 256
            backing = raw.ljust(0x1021, b"\0")
            position = 0
            while position < len(raw):
                offsets[backing[position]] = position
                position += 2 + backing[position + 1]
            profile = UtilityExSupportProfile(
                target, protocol, kind, raw.ljust(0x1020, b"\0"), tuple(offsets)
            )
            with self._lock:
                self.profiles.append(profile)
        except MemoryError:
            return 81
        return 99

    def snapshot(
        self, kind: int, target: tuple[int, int], protocol: int
    ) -> tuple[bytes, tuple[int, ...]] | None:
        _validate_support_key(target, protocol, kind)
        with self._lock:
            index = self._index(kind, target, protocol)
            if index is None:
                return None
            profile = self.profiles[index]
            return profile.data, profile.offsets


class UtilityExDriverArbitration:
    """NK18 21fc0/22090/22100/22190 four-thread, protocol-aware lock queue."""

    def __init__(self, context: CommContext):
        self.context = context
        self.waiters: list[tuple[int, int]] = []
        self._lock = threading.Lock()

    def enroll(self, thread: int, protocol: int) -> int:
        for value in (thread, protocol):
            if type(value) is not int or value <= 0:
                raise ValueError("Positive native thread/protocol identity required")
        with self._lock:
            if any(owner == thread for owner, _ in self.waiters):
                return 0
            if len(self.waiters) == 4:
                return 99
            self.waiters.append((thread, protocol))
            return 0

    def ready(self, thread: int, protocol: int) -> bool:
        with self._lock:
            if not self.waiters:
                return False
            if self.waiters[0][0] == thread:
                return True
            if self.waiters[0][1] == protocol:
                return False
            return next(
                (
                    owner == thread
                    for owner, kind in self.waiters[1:]
                    if kind == protocol
                ),
                True,
            )

    def release(self, thread: int) -> int:
        with self._lock:
            before = len(self.waiters)
            self.waiters = [
                (owner, kind) for owner, kind in self.waiters if owner != thread
            ]
            return int(len(self.waiters) != before)

    def acquire(
        self,
        thread: int,
        protocol: int,
        timeout_ms: int,
        queued: Callable[[], bool] | None = None,
    ) -> int:
        if type(timeout_ms) is not int or not 0 <= timeout_ms <= 0xFFFFFFFF:
            raise ValueError("Native lock timeout must be uint32")
        if self.enroll(thread, protocol):
            return 3
        try:
            while timeout_ms:
                if self.ready(thread, protocol):
                    return 0
                delay = min(100, timeout_ms)
                self.context.native_sleep(delay)
                timeout_ms -= delay
                if queued is not None:
                    if queued():
                        self.release(thread)
                        return 1
                    return 3
        except BaseException:
            self.release(thread)
            raise
        self.release(thread)
        return 2


@dataclass
class LogicalChannel:
    protocol: int
    address: int
    extra: int
    physical: int
    mask: bytes = b""
    pattern: bytes = b""
    config_owner: bool = True
    delay_ms: int = 0


class UtilityExDriverPrimitives:
    """Exact18 DRIVER function table, with native positional typed outputs.

    This executes supplied individual export primitives, never the original DLL.
    Out handles are four little-endian bytes; message buffers contain typed
    NativeMessage records. PrimitiveResult carries the raw SDK status only.
    """

    def __init__(self, context: CommContext, binding: object):
        from scripts.utility_ex import UtilityDriverBinding, UtilityP6DriverBinding

        if not isinstance(binding, (UtilityDriverBinding, UtilityP6DriverBinding)):
            raise TypeError("Concrete UtilityEx DRIVER binding required")
        if binding.module_sha256 != context.module_sha256:
            raise UtilityExSourceError("DRIVER binding source mismatch")
        if not binding.ready:
            raise UtilityExSourceError("Native DRIVER required symbols are unavailable")
        self.context, self.binding = context, binding

    @staticmethod
    def _word(output: bytearray) -> int:
        if len(output) != 4:
            raise ValueError("Native DWORD output must retain four bytes")
        return int.from_bytes(output, "little")

    def __call__(self, operation: dict, remaining: float) -> PrimitiveResult:
        name = operation["operation"]
        if name == "P6CtrlInitialize":
            from scripts.utility_ex import UtilityP6DriverBinding

            if not isinstance(self.binding, UtilityP6DriverBinding):
                raise UtilityExSourceError("Separate P6 controller schema required")
            output = bytearray(4)
            status = self.binding.invoke_raw(
                "J2534CtrlInitialize", 1, output, operation["label"]
            )
            return PrimitiveResult(status, self._word(output))
        slots = {
            "PassThruConnect": 0x20,
            "PassThruOemConnect": 0x24,
            "PassThruDisconnect": 0x28,
            "PassThruIoctl": 0x2C,
            "PassThruWriteMsgs": 0x34,
            "PassThruReadMsgs": 0x38,
            "PassThruStartPeriodicMsg": 0x3C,
            "PassThruStopPeriodicMsg": 0x40,
            "PassThruStartMsgFilter": 0x44,
            "PassThruStopMsgFilter": 0x48,
        }
        if name not in slots:
            raise UtilityExSourceError("Unreviewed native DRIVER primitive")
        function = self.binding.resolve(self.binding.slot_offset(name))
        if function is None:
            raise UtilityExSourceError("Native DRIVER primitive is unavailable")
        output = bytearray(4)
        messages: list[NativeMessage] = []
        if name == "PassThruConnect":
            arguments = (operation["protocol_id"], operation["flags"], output)
        elif name == "PassThruOemConnect":
            arguments = (
                operation["protocol_id"],
                operation["flags"],
                operation["oem_parameter"],
                output,
            )
        elif name == "PassThruDisconnect":
            arguments = (operation["channel_id"],)
        elif name == "PassThruIoctl":
            arguments = (
                operation["channel_id"],
                operation["ioctl_id"],
                operation.get("input"),
                operation.get("output"),
            )
        elif name in ("PassThruReadMsgs", "PassThruWriteMsgs"):
            output[:] = int(operation["count"]).to_bytes(4, "little")
            messages = (
                list(operation["messages"])
                if name == "PassThruWriteMsgs"
                else [NativeMessage(0, b"")]
            )
            arguments = (
                operation["channel_id"],
                messages,
                output,
                operation["timeout_ms"],
            )
        elif name == "PassThruStartMsgFilter":
            arguments = (
                operation["channel_id"],
                operation["filter_type"],
                operation["mask"],
                operation["pattern"],
                operation["flow_control"],
                output,
            )
        elif name == "PassThruStartPeriodicMsg":
            arguments = (
                operation["channel_id"],
                operation["message"],
                output,
                operation["interval_ms"],
            )
        else:
            arguments = (
                operation["channel_id"],
                operation[
                    "filter_id" if name == "PassThruStopMsgFilter" else "periodic_id"
                ],
            )
        result = function(*arguments)
        if not isinstance(result, PrimitiveResult) or result.value is not None:
            raise TypeError(
                "Raw typed DRIVER SDK status with positional outputs required"
            )
        if result.status:
            return result
        if name in (
            "PassThruConnect",
            "PassThruOemConnect",
            "PassThruStartMsgFilter",
            "PassThruStartPeriodicMsg",
        ):
            return PrimitiveResult(0, self._word(output))
        if name in ("PassThruReadMsgs", "PassThruWriteMsgs"):
            count = self._word(output)
            if (
                len(messages) != 1
                or count > 1
                or not isinstance(messages[0], NativeMessage)
            ):
                raise ValueError("One bounded typed native message backing required")
            return PrimitiveResult(
                0, tuple(messages) if name == "PassThruReadMsgs" else count
            )
        return result


class UtilityExDirectDriver:
    """NK18 singleton21370/21660/21840/21960/21ac0, distinct from slot pool.

    P3 uses protocol4 here. It must not inherit213f0's logical sharing,
    receive queue or arbitration. The source has one retained physical handle.
    """

    def __init__(
        self, context: CommContext, adapter: UtilityExDriverPrimitives, protocol: int
    ):
        if context.module_sha256 not in _CAN_LOWER_SOURCES:
            raise UtilityExSourceError("Native direct DRIVER source is not reviewed")
        if (
            not isinstance(adapter, UtilityExDriverPrimitives)
            or adapter.context is not context
        ):
            raise TypeError("Concrete same-context raw DRIVER adapter required")
        if type(protocol) is not int or protocol not in (1, 4, 6):
            raise ValueError("Native211b0 singleton protocol must be1/4/6")
        self.context, self.adapter, self.protocol = context, adapter, protocol
        self.device = J2534Device2026(
            adapter, cancelled=context.is_cancelled, background_workers=False
        )
        self.handle: int | None = None
        self.address = 0

    def _call(
        self, operation: str, *, cleanup: bool = False, acquired=None, **values
    ) -> PrimitiveResult:
        observed: list[PrimitiveResult] = []
        self.device._call(
            operation,
            cleanup=cleanup,
            ignore_status=acquired is None,
            acquired=acquired,
            observed=observed.append,
            **values,
        )
        return observed[0]

    def connect(self, address: int, flags: int = 0x200) -> int:
        from scripts.utility_ex import UtilityDriverBinding

        if not isinstance(self.adapter.binding, UtilityDriverBinding):
            raise UtilityExSourceError(
                "Direct classic DRIVER requires its standard schema"
            )
        for value in (address, flags):
            if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
                raise ValueError("Native direct connection fields must be uint32")
        if self.handle is not None:
            return 13 if address == self.address else 14

        def retain(handle: int) -> None:
            self.handle = handle
            self.address = address

        try:
            result = self._call(
                "PassThruConnect",
                acquired=retain,
                protocol_id=self.protocol
                if self.adapter.binding.constructor_parameter == 0
                else 0x1000C,
                native_protocol=self.protocol,
                flags=flags,
                abi="legacy-wrapper3",
            )
        except NativeJ2534Error2026:
            return 99
        return 0 if result.status == 0 else 99

    def finalize(self) -> int:
        if self.handle is None:
            return 0
        result = self._call("PassThruDisconnect", channel_id=self.handle, cleanup=True)
        if result.status:
            return 99
        self.handle = None
        return 0

    def ioctl(
        self, ioctl_id: int, payload: object = None, output: object = None
    ) -> int:
        if self.handle is None:
            return 99
        if type(ioctl_id) is not int or not 0 <= ioctl_id <= 0xFFFFFFFF:
            raise ValueError("Native IOCTL identifier must be uint32")
        result = self._call(
            "PassThruIoctl",
            channel_id=self.handle,
            ioctl_id=ioctl_id,
            input=payload,
            output=output,
        )
        return 0 if result.status == 0 else 2 if result.status == 9 else 99

    def write(self, message: NativeMessage, timeout_ms: int) -> int:
        if self.handle is None:
            return 3
        if not isinstance(message, NativeMessage):
            raise TypeError("Typed native message required")
        if type(timeout_ms) is not int or not 0 <= timeout_ms <= 0xFFFFFFFF:
            raise ValueError("Native write timeout must be uint32")
        result = self._call(
            "PassThruWriteMsgs",
            channel_id=self.handle,
            messages=(replace(message, protocol_id=self.protocol),),
            count=1,
            timeout_ms=timeout_ms,
        )
        return 0 if result.status == 0 else 3

    def read(self, timeout_ms: int) -> tuple[int, NativeMessage | None]:
        if self.handle is None:
            return 3, None
        if type(timeout_ms) is not int or not 0 <= timeout_ms <= 0xFFFFFFFF:
            raise ValueError("Native read timeout must be uint32")
        result = self._call(
            "PassThruReadMsgs", channel_id=self.handle, count=1, timeout_ms=timeout_ms
        )
        if result.status in (9, 0x10):
            return 2, None
        if result.status:
            return 3, None
        if (
            not isinstance(result.value, tuple)
            or len(result.value) != 1
            or not isinstance(result.value[0], NativeMessage)
        ):
            raise TypeError("One typed native read output required")
        return 0, result.value[0]


class UtilityExPassThruPool:
    """18 NK213f0/216b0/219c0/21b30 and queue22230/22310.

    Only the bounded raw primitive guard is shared with48. Operation arguments
    retain the legacy wrapper ABI; none of48's connect/config/business runs.
    The pool must belong to one original DRIVER instance (protocol family).
    """

    def __init__(self, context: CommContext, device: J2534Device2026):
        if not isinstance(device, J2534Device2026):
            raise TypeError("Concrete bounded typed primitive guard required")
        self.context, self.device = context, device
        self.channels: list[LogicalChannel | None] = [None] * 4
        self.queue: list[tuple[int, NativeMessage]] = []
        self.owned: set[int] = set()
        self.filters: dict[tuple[int, int], int] = {}
        self.last_cleanup_error: BaseException | None = None
        self._pool_lock = threading.RLock()
        self._driver_lock = threading.RLock()
        self._queue_lock = threading.RLock()
        self._owned_protocols: dict[int, int] = {}
        key = f"utility_ex:driver_arbitration:{context.module_sha256}"
        self.arbitration = _published_state(
            context,
            key,
            UtilityExDriverArbitration,
            lambda: UtilityExDriverArbitration(context),
            "Concrete native driver arbitration required",
        )

    def _call(
        self,
        operation: str,
        *,
        cleanup: bool = False,
        acquired=None,
        lock_timeout_ms: int = 1000,
        lock_attempts: int = 3,
        wait_for_slot: int | None = None,
        allow_unlocked: bool = False,
        ignore_native_status: bool = False,
        **values,
    ) -> PrimitiveResult:
        result: list[PrimitiveResult] = []
        protocol = (
            values["native_protocol"]
            if "native_protocol" in values
            else self._owned_protocols[values["channel_id"]]
        )
        thread = threading.get_ident()

        def queued() -> bool:
            with self._queue_lock:
                return any(owner == wait_for_slot for owner, _ in self.queue)

        for _ in range(lock_attempts):
            locked = (
                self.arbitration.acquire(
                    thread,
                    protocol,
                    lock_timeout_ms,
                    queued if wait_for_slot is not None else None,
                )
                == 0
            )
            if locked:
                break
        else:
            if not allow_unlocked:
                return PrimitiveResult(9 if wait_for_slot is not None else 99)
        try:
            with self._driver_lock:
                self.device._call(
                    operation,
                    cleanup=cleanup,
                    ignore_status=acquired is None,
                    acquired=acquired,
                    observed=result.append,
                    **values,
                )
        finally:
            if locked:
                self.arbitration.release(thread)
        return (
            PrimitiveResult(0, result[0].value) if ignore_native_status else result[0]
        )

    def _disconnect(self, handle: int) -> int:
        result = self._call(
            "PassThruDisconnect",
            channel_id=handle,
            cleanup=True,
            allow_unlocked=True,
        )
        if result.status == 0:
            self.owned.discard(handle)
            self._owned_protocols.pop(handle, None)
            self.filters = {
                key: slot for key, slot in self.filters.items() if key[0] != handle
            }
            return 0
        return 99

    def connect(
        self,
        protocol: int,
        address: int,
        *,
        flags: int = 0,
        extra: int = 0,
        native_mode: int = 0,
        oem_parameter: int = 0,
    ) -> tuple[int, int]:
        with self._pool_lock:
            for value in (protocol, address, flags, extra, native_mode, oem_parameter):
                if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
                    raise ValueError("Legacy connect fields must be uint32")
            # Native table rejects duplicate address+extension even across protocols.
            if any(
                c is not None
                and c.address == address
                and (
                    self.context.module_sha256 in (SHA_12_NK, SHA_12_TY)
                    or c.extra == extra
                )
                for c in self.channels
            ):
                return 13, 4
            free = next((i for i, c in enumerate(self.channels) if c is None), None)
            if free is None:
                return 14, 4
            shared = next(
                (c for c in self.channels if c is not None and c.protocol == protocol),
                None,
            )
            if shared is not None:
                handle = shared.physical
            else:
                acquired: list[int] = []

                def retain(handle: int) -> None:
                    acquired.append(handle)
                    self.owned.add(handle)
                    self._owned_protocols[handle] = protocol

                try:
                    # 213f0 uses OEM only for mode15; other wrapper modes use1000c.
                    oem = native_mode == 0x15
                    arguments = {
                        "protocol_id": protocol
                        if native_mode in (0, 0x15)
                        else 0x1000C,
                        "native_protocol": protocol,
                        "flags": flags,
                        "abi": "legacy-oem-wrapper4" if oem else "legacy-wrapper3",
                    }
                    if oem:
                        arguments["oem_parameter"] = oem_parameter
                    response = self._call(
                        "PassThruOemConnect" if oem else "PassThruConnect",
                        acquired=retain,
                        **arguments,
                    )
                    if response.status:
                        return 99, 4
                    handle = response.value
                except NativeJ2534Error2026:
                    return 99, 4
                except (Exception, KeyboardInterrupt) as error:
                    for handle in acquired:
                        try:
                            if self._disconnect(handle):
                                raise OSError("Legacy PassThruDisconnect failed")
                        except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - retain failed resource
                            self.last_cleanup_error = cleanup_error
                            error.add_note(
                                "UtilityEx fresh-channel cleanup failed: "
                                + type(cleanup_error).__name__
                            )
                    raise
                if type(handle) is not int or not 0 <= handle <= 0xFFFFFFFF:
                    raise ValueError("Legacy channel handle must be uint32")
            self.channels[free] = LogicalChannel(
                protocol, address, extra, handle, config_owner=shared is None
            )
            return 0, free

    def close(self, slot: int) -> int:
        with self._pool_lock:
            channel = self._channel(slot)
            with self._queue_lock:
                self.queue = [(i, m) for i, m in self.queue if i != slot]
            # A shared physical connection survives until its final logical owner.
            if any(
                i != slot and c is not None and c.physical == channel.physical
                for i, c in enumerate(self.channels)
            ):
                self.channels[slot] = None
                return 0
            status = self._disconnect(channel.physical)
            if status == 0:
                self.channels[slot] = None
            return status

    def finalize(self) -> int:
        """Retry every owned physical release, including failed-acquire rollback."""
        status = 0
        first_error: BaseException | None = None
        with self._pool_lock:
            for handle in tuple(self.owned):
                try:
                    result = self._disconnect(handle)
                except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - release all owners
                    self.last_cleanup_error = error
                    if first_error is None:
                        first_error = error
                    else:
                        first_error.add_note(
                            "Additional UtilityEx release failed: "
                            + type(error).__name__
                        )
                else:
                    if result:
                        status = result
                    else:
                        self.channels = [
                            None if c is not None and c.physical == handle else c
                            for c in self.channels
                        ]
            with self._queue_lock:
                self.queue = [
                    (i, m) for i, m in self.queue if self.channels[i] is not None
                ]
        if first_error is not None:
            raise first_error
        return status

    def _channel(self, slot: int) -> LogicalChannel:
        if type(slot) is not int or not 0 <= slot < 4:
            raise ValueError("Native logical slot must be 0..3")
        channel = self.channels[slot]
        if channel is None:
            raise ValueError("Native logical slot is not connected")
        return channel

    def start_filter(
        self,
        slot: int,
        filter_type: int,
        mask: NativeMessage,
        pattern: NativeMessage,
        flow: NativeMessage | None,
    ) -> tuple[int, int]:
        """NK21cd0 ignores SDK status; keep ownership of successful out handles."""
        channel = self._channel(slot)
        acquired: list[int] = []

        def retain(handle: int) -> None:
            acquired.append(handle)
            self.filters[(channel.physical, handle)] = slot

        try:
            result = self._call(
                "PassThruStartMsgFilter",
                channel_id=channel.physical,
                filter_type=filter_type,
                mask=mask,
                pattern=pattern,
                flow_control=flow,
                acquired=retain,
            )
            if result.status:
                return 99, 0xFFFFFFFF
        except NativeJ2534Error2026:
            return 0, 0xFFFFFFFF
        except (Exception, KeyboardInterrupt) as error:
            for handle in acquired:
                try:
                    self.stop_filter(slot, handle)
                except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - retain ownership
                    self.last_cleanup_error = cleanup_error
                    error.add_note(
                        "UtilityEx filter rollback failed: "
                        + type(cleanup_error).__name__
                    )
            raise
        return 0, acquired[0]

    def stop_filter(self, slot: int, handle: int) -> int:
        channel = self._channel(slot)
        result = self._call(
            "PassThruStopMsgFilter",
            cleanup=True,
            ignore_native_status=True,
            channel_id=channel.physical,
            filter_id=handle,
        )
        if result.status == 0:
            self.filters.pop((channel.physical, handle), None)
            return 0
        return 99

    def route_filter(self, slot: int, mask: bytes, pattern: bytes) -> None:
        with self._pool_lock:
            channel = self._channel(slot)
            if (
                not isinstance(mask, bytes)
                or not isinstance(pattern, bytes)
                or not 0 <= len(mask) <= 5
                or len(mask) != len(pattern)
            ):
                raise ValueError(
                    "Native routing mask/pattern must have equal bounded length"
                )
            channel.mask, channel.pattern = mask, pattern

    def _take(self, slot: int) -> NativeMessage | None:
        with self._queue_lock:
            for i, (owner, message) in enumerate(self.queue):
                if owner == slot:
                    del self.queue[i]
                    return message
            return None

    def ioctl(self, slot: int, ioctl_id: int, payload: object = None) -> int:
        channel = self._channel(slot)
        if type(ioctl_id) is not int or not 0 <= ioctl_id <= 0xFFFFFFFF:
            raise ValueError("Native IOCTL identifier must be uint32")
        # 21890: shared logical owners skip SET_CONFIG on an existing channel.
        if ioctl_id == 2 and not channel.config_owner:
            return 0
        result = self._call(
            "PassThruIoctl",
            channel_id=channel.physical,
            ioctl_id=ioctl_id,
            input=payload,
        )
        return 0 if result.status == 0 else 2 if result.status == 9 else 99

    def configure_can(
        self,
        slot: int,
        *,
        override: bool,
        supplied: tuple[tuple[int, int], ...] | None = None,
        native_delay_ms: int = 0,
        oem_configuration: bool = False,
    ) -> int:
        """18 NK24630/241f0 configuration, including parameter2a fallback.

        `supplied` is explicit native SCONFIG_LIST content, not a callback. In
        the non-override branch it is the caller's decoded broker-data500.
        """
        channel = self._channel(slot)
        if type(override) is not bool or type(oem_configuration) is not bool:
            raise TypeError("Explicit native configuration branch required")
        if type(native_delay_ms) is not int or not 0 <= native_delay_ms <= 0xFFFFFFFF:
            raise ValueError("Native configured delay must be uint32")
        if supplied is not None:
            if not isinstance(supplied, tuple) or len(supplied) > 65536:
                raise ValueError("Bounded immutable native SCONFIG_LIST required")
            for pair in supplied:
                if (
                    not isinstance(pair, tuple)
                    or len(pair) != 2
                    or any(type(v) is not int or not 0 <= v <= 0xFFFFFFFF for v in pair)
                ):
                    raise ValueError("Native SCONFIG entries must be uint32 pairs")
        if not override:
            if supplied is None:
                raise UtilityExSourceError("Native broker-data500 was not supplied")
            channel.delay_ms = native_delay_ms
        if supplied is not None and (not override or supplied):
            status = self.ioctl(slot, 2, supplied)
            if status and any(pair[0] == 0x2A for pair in supplied):
                status = self.ioctl(
                    slot, 2, tuple(pair for pair in supplied if pair[0] != 0x2A)
                )
            return status
        channel.delay_ms = 0
        parameters = (
            ((0x8001, 0x30B), (1, 125000)) if oem_configuration else ((1, 500000),)
        )
        status = self.ioctl(slot, 2, parameters)
        if status:
            return status
        value = self.context.native_parameter(0xD3)
        if value not in (0xFFFFFFFF, 0xFFFF):
            status = self.ioctl(slot, 2, ((0x23, value),))
            if status:
                return status
        value = self.context.native_parameter(0xDD)
        if value != 0xFFFFFFFF:
            # 24630/241f0 intentionally return the preceding status, not this one.
            self.ioctl(slot, 2, ((0x2A, value),))
        return status

    def write(self, slot: int, message: NativeMessage, timeout_ms: int) -> int:
        channel = self._channel(slot)
        if type(timeout_ms) is not int or not 0 <= timeout_ms <= 0xFFFFFFFF:
            raise ValueError("Native write timeout must be uint32")
        if not isinstance(message, NativeMessage):
            raise TypeError("Typed native message required")
        message = replace(message, protocol_id=channel.protocol)
        # Native219c0 drains at most eight cached messages for this logical slot.
        for _ in range(8):
            if self._take(slot) is None:
                break
        result = self._call(
            "PassThruWriteMsgs",
            channel_id=channel.physical,
            messages=(message,),
            count=1,
            timeout_ms=timeout_ms,
        )
        return 0 if result.status == 0 else 3

    def read(self, slot: int, timeout_ms: int) -> tuple[int, NativeMessage | None]:
        try:
            return self._read(slot, timeout_ms)
        finally:
            # Host exceptions/deadlines must not strand native queued ownership.
            self.arbitration.release(threading.get_ident())

    def _read(self, slot: int, timeout_ms: int) -> tuple[int, NativeMessage | None]:
        channel = self._channel(slot)
        if type(timeout_ms) is not int or not 0 <= timeout_ms <= 0xFFFFFFFF:
            raise ValueError("Native read timeout must be uint32")
        deadline = (self.context.ticks() + timeout_ms) & 0xFFFFFFFF
        while True:
            cached = self._take(slot)
            if cached is not None:
                return 0, cached
            # Preserve original21b30's unsigned absolute-deadline comparison.
            if deadline < self.context.ticks():
                return 2, None
            result = self._call(
                "PassThruReadMsgs",
                channel_id=channel.physical,
                count=1,
                timeout_ms=100,
                lock_timeout_ms=min(
                    1000, (deadline - self.context.ticks()) & 0xFFFFFFFF
                ),
                lock_attempts=1,
                wait_for_slot=slot,
            )
            if result.status in (9, 0x10):
                continue
            if result.status:
                return 3, self._take(slot)
            if (
                not isinstance(result.value, tuple)
                or len(result.value) != 1
                or not isinstance(result.value[0], NativeMessage)
            ):
                raise ValueError("One typed native message required")
            message = result.value[0]
            owner = next(
                (
                    i
                    for i, candidate in enumerate(self.channels)
                    if candidate is not None
                    and candidate.protocol == channel.protocol
                    and candidate.mask
                    and len(message.data) >= len(candidate.mask)
                    and all(
                        (value & mask) == pattern
                        for value, mask, pattern in zip(
                            message.data, candidate.mask, candidate.pattern
                        )
                    )
                ),
                4,
            )
            if owner == slot:
                return 0, message
            with self._queue_lock:
                if owner >= 4 or len(self.queue) >= 8:
                    return 3, self._take(slot)
                self.queue.append((owner, message))


def p3_default_parameters(profile: int) -> tuple[tuple[int, int], ...]:
    """NK18 16460;EAX returns4 or15 entries despite the recovered C void type."""
    if type(profile) is not int or not 0 <= profile <= 0xFFFFFFFF:
        raise ValueError("Native P3 configuration profile must be uint32")
    if profile not in (1, 0x12):
        return ((1, 9600), (20, 35), (9, 100), (10, 100))
    return (
        (1, 9600),
        (20, 35),
        (14, 105 if profile == 1 else 110),
        (15, 20),
        (16, 20),
        (17, 50),
        (18, 330),
        (6, 0),
        (7, 40),
        (8, 50 if profile == 1 else 40),
        (9, 200 if profile == 1 else 500),
        (10, 110),
        (11, 10000),
        (12, 10 if profile == 1 else 8),
        (13, 40),
    )


class UtilityExP3Lower:
    """NK18 163d0/16710/16850/16870/168d0/16960 complete P3 lower.

    Uses the direct protocol4 singleton, independently from the CAN slot pool.
    Broker500 configuration is supplied as decoded native pairs by its caller.
    """

    def __init__(self, context: CommContext, driver: UtilityExDirectDriver):
        if (
            not isinstance(driver, UtilityExDirectDriver)
            or driver.context is not context
            or driver.protocol != 4
        ):
            raise TypeError("Concrete same-context protocol4 direct driver required")
        self.context, self.driver = context, driver
        self.attached = False
        self.timeout_ms, self.default_timeout_ms = 1000, 0x3FC
        self.native_timeout_10 = 1000
        self.last_receive_tick, self.profile = 0, 0

    def fast_init(self) -> int:
        if not self.attached:
            return 0
        for _ in range(3):
            request = pack_p3_request(self.driver.address, b"\x81", 4)
            output = [NativeMessage(4, bytes(7))]
            status = self.driver.ioctl(5, request, output)
            if status == 2:
                continue
            if status:
                return 4
            if len(output) != 1 or not isinstance(output[0], NativeMessage):
                raise ValueError("One bounded native FAST_INIT output required")
            # Native validates these source/destination/checksum bytes only;
            # it does not validate the returned service or a minimum length.
            data = output[0].data
            backing = data.ljust(4, b"\0")
            if backing[1] != 0xF0 or backing[2] != self.driver.address:
                return 3
            if not data or data[-1] != sum(data[:-1]) & 255:
                return 3
            return 0
        return 4

    def initialize(
        self,
        address: int,
        *,
        override: bool = False,
        supplied: tuple[tuple[int, int], ...] | None = None,
        reuse: bool = False,
    ) -> int:
        if type(override) is not bool or type(reuse) is not bool:
            raise TypeError("Native initialization flags must be bool")
        if supplied is not None and (
            not isinstance(supplied, tuple)
            or len(supplied) > 65536
            or any(
                not isinstance(pair, tuple)
                or len(pair) != 2
                or any(
                    type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                    for value in pair
                )
                for pair in supplied
            )
        ):
            raise ValueError("Bounded immutable native SCONFIG pairs required")
        self.attached = True
        try:
            status = self.driver.connect(address)
            if status == 0 or (reuse and status == 13):
                if not override and supplied is None:
                    blob = self.context.broker_data(500)
                    if type(blob) is not bytes or len(blob) > 65536 * 8:
                        raise ValueError("Bounded immutable native broker500 required")
                    supplied = tuple(
                        (
                            int.from_bytes(blob[index : index + 4], "little"),
                            int.from_bytes(blob[index + 4 : index + 8], "little"),
                        )
                        for index in range(0, len(blob) & ~7, 8)
                    )
                parameters = (
                    p3_default_parameters(self.profile) if override else supplied
                )
                status = self.driver.ioctl(2, parameters)
                if status == 0:
                    status = self.fast_init()
            if status and status != 13:
                self.finalize()
            return status
        except BaseException as error:
            try:
                self.finalize()
            except BaseException as cleanup_error:  # noqa: BLE001 - preserve first error
                error.add_note(
                    "Native P3 cleanup failed: " + type(cleanup_error).__name__
                )
            raise

    def finalize(self) -> int:
        if not self.attached:
            return 0
        status = self.driver.finalize()
        if status == 0:
            self.attached = False
        return status

    def send(self, request: bytes) -> int:
        if not self.attached:
            return 99
        return self.driver.write(
            pack_p3_request(self.driver.address, request), self.timeout_ms
        )

    def receive(self) -> DriverReceive:
        if not self.attached:
            return DriverReceive(99)
        status, message = self.driver.read(self.timeout_ms)
        self.last_receive_tick = self.context.ticks()
        if status:
            return DriverReceive(status)
        assert message is not None
        return unpack_p3_response(message, self.driver.address)

    def interrupt(self, timeout_ms: int) -> int:
        # 16960's DWORD is a pending receive count, not a millisecond timeout.
        if type(timeout_ms) is not int or not 0 <= timeout_ms <= 65536:
            raise ValueError("Native P3 interrupt count exceeds host primitive budget")
        if not self.attached:
            return 99
        temporary = self.context.native_parameter(0xC9)
        if type(temporary) is not int or not 0 <= temporary <= 0xFFFFFFFF:
            raise ValueError("Native broker parameterC9 must be uint32")
        if temporary == 0xFFFFFFFF:
            if self.send(b"\x82"):
                return 99
        else:
            previous = [(10, 0)]
            if self.driver.ioctl(1, previous):
                return 99
            if (
                len(previous) != 1
                or not isinstance(previous[0], tuple)
                or len(previous[0]) != 2
                or previous[0][0] != 10
                or type(previous[0][1]) is not int
                or not 0 <= previous[0][1] <= 0xFFFFFFFF
            ):
                raise ValueError("Native GET_CONFIG10 output required")
            if self.driver.ioctl(2, ((10, temporary),)):
                return 99
            try:
                status = self.send(b"\x82")
            except BaseException:
                self.driver.ioctl(2, tuple(previous))
                raise
            restored = self.driver.ioctl(2, tuple(previous))
            if status or restored:
                return 99
        status = 0
        for _ in range(timeout_ms):
            status = self.receive().status
            if status != 5:
                status = 99 if status else 0
                break
        self.context.native_sleep(300)
        self.fast_init()  # Native deliberately ignores this final handshake status.
        return status


class UtilityExManagerMutex:
    """NK18 24e30/24e80 bounded owner CAS, without recursive depth counting."""

    def __init__(self, context: CommContext):
        self.context, self.owner = context, 0
        self._lock = threading.Lock()

    def acquire(self) -> int:
        thread = threading.get_ident()
        for _ in range(30):
            with self._lock:
                if self.owner in (0, thread):
                    self.owner = thread
                    return 0
            self.context.native_sleep(100)
        return 99

    def release(self) -> int:
        with self._lock:
            if self.owner != threading.get_ident():
                return 99
            self.owner = 0
            return 0


@dataclass
class UtilityExP6DataList:
    """24970 output descriptor: one mutable12-byte record headed by ID77."""

    count: int = 1
    records: bytearray = dataclass_field(
        default_factory=lambda: bytearray(b"\x4d\0\0\0" + bytes(8))
    )


class UtilityExP6Pool(UtilityExPassThruPool):
    """Separate Plus24970/464f0 pool and25340 configuration; no standard binding."""

    def __init__(self, context: CommContext, device: J2534Device2026):
        from scripts.utility_ex import UtilityP6DriverBinding

        if context.module_sha256 not in (SHA_PLUS_NK, SHA_PLUS_TY):
            raise UtilityExSourceError("P6 pool source is not reviewed")
        if not isinstance(device.provider, UtilityExDriverPrimitives) or not isinstance(
            device.provider.binding, UtilityP6DriverBinding
        ):
            raise TypeError("Separate concrete P6 raw DRIVER required")
        super().__init__(context, device)
        self.controller_handle = 0
        self.protocol = device.provider.binding.protocol
        self._adapters = {self.protocol: device.provider}
        self.device.provider = self._invoke

    def register_binding(self, binding: object) -> None:
        from scripts.utility_ex import UtilityP6DriverBinding

        if not isinstance(binding, UtilityP6DriverBinding):
            raise TypeError("Separate concrete P6 DRIVER binding required")
        adapter = UtilityExDriverPrimitives(self.context, binding)
        if (
            binding.protocol in self._adapters
            and self._adapters[binding.protocol].binding is not binding
        ):
            raise ValueError("P6 factory protocol already has a distinct binding")
        self._adapters[binding.protocol] = adapter

    def _invoke(self, operation: dict, remaining: float) -> PrimitiveResult:
        protocol = operation.get("native_protocol")
        if type(protocol) is not int or protocol not in self._adapters:
            raise UtilityExSourceError("Registered P6 native factory protocol required")
        return self._adapters[protocol](operation, remaining)

    def _call(self, operation: str, **values) -> PrimitiveResult:
        if "native_protocol" not in values:
            values["native_protocol"] = self._owned_protocols[values["channel_id"]]
        return super()._call(operation, **values)

    def initialize_controller(self) -> int:
        """240d0 keeps the positional output even when SDK status is nonzero."""
        if 0x8012 not in self._adapters:
            raise UtilityExSourceError(
                "Native P6 controller initializer selects8012 factory"
            )
        base = _TARGET_GLOBAL_BASES[self.context.module_sha256]
        protocol = self.context.state.get(
            f"native_global:{base + 12:x}", self.context.broker(0x70)
        )
        result = self._call(
            "P6CtrlInitialize",
            native_protocol=0x8012,
            label="J2534-2:" if protocol == 0x78 else None,
        )
        if type(result.value) is not int or not 0 <= result.value <= 0xFFFFFFFF:
            raise ValueError("Native P6 controller DWORD required")
        self.controller_handle = result.value
        return result.status

    def connect(
        self,
        protocol: int,
        address: int,
        *,
        flags: int = 0x800,
        extra: int = 0,
        native_mode: int = 0,
        oem_parameter: int = 0,
    ) -> tuple[int, int]:
        if type(protocol) is not int or protocol not in self._adapters:
            raise ValueError("P6 pool protocol requires its independent DRIVER")
        if flags != 0x800 or extra != 0 or native_mode != 0:
            raise ValueError("P6 connect requires literal800 flags and no extension")
        for value in (address, oem_parameter):
            if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
                raise ValueError("Native P6 connection fields must be uint32")
        with self._pool_lock:
            if any(
                c is not None and c.address == address and c.extra == 0
                for c in self.channels
            ):
                return 13, 4
            if all(c is not None for c in self.channels):
                return 14, 4
            # Query only the first physical CANFD owner, before its rawConnect.
            if protocol == 0x8012 and not any(
                c is not None and c.protocol == protocol for c in self.channels
            ):
                output = UtilityExP6DataList()
                result = self._call(
                    "PassThruIoctl",
                    channel_id=self.controller_handle,
                    native_protocol=protocol,
                    ioctl_id=0x800C,
                    input=0,
                    output=output,
                )
                if result.status:
                    return (2 if result.status == 9 else 99), 4
            return super().connect(
                protocol, address, flags=flags, extra=0, oem_parameter=oem_parameter
            )

    def ioctl(self, slot: int, ioctl_id: int, payload: object = None) -> int:
        self._channel(slot)
        if type(ioctl_id) is not int or not 0 <= ioctl_id <= 0xFFFFFFFF:
            raise ValueError("Native IOCTL identifier must be uint32")
        base = _TARGET_GLOBAL_BASES[self.context.module_sha256]
        protocol = self.context.state.get(
            f"native_global:{base + 12:x}", self.context.broker(0x70)
        )
        if protocol == 0x78 and ioctl_id != 2:
            return 0
        return super().ioctl(slot, ioctl_id, payload)

    def configure_can(
        self,
        slot: int,
        *,
        override: bool,
        supplied: tuple[tuple[int, int], ...] | None = None,
        native_delay_ms: int = 0,
        oem_configuration: bool = False,
    ) -> int:
        channel = self._channel(slot)
        if type(native_delay_ms) is not int or not 0 <= native_delay_ms <= 0xFFFFFFFF:
            raise ValueError("Native P6 configured delay must be uint32")
        if type(oem_configuration) is not bool or oem_configuration:
            raise ValueError("P6 does not use ordinary OEM configuration")
        flags, timing = (
            self.context.native_parameter(0xA1),
            self.context.native_parameter(0x97),
        )
        values = p6_configuration(
            channel.protocol,
            override=override,
            flags=flags,
            timing=timing,
            broker_parameters=() if supplied is None else supplied,
        )
        channel.delay_ms = 0 if override else native_delay_ms
        status = self.ioctl(slot, 2, values)
        if status or not override:
            return status
        gate = self.context.native_parameter(0xD3)
        if gate not in (0xFFFFFFFF, 0xFFFF):
            status = self.ioctl(slot, 2, ((0x23, 0xFFFF),))
            if status:
                return status
        value = self.context.native_parameter(0xDD)
        if value != 0xFFFFFFFF:
            self.ioctl(slot, 2, ((0x2A, value),))
        return status


class UtilityExCANLower:
    """NK18 24140/24590/24eb0 CAN lower over concrete raw driver primitives.

    This lower implements its connection/configuration/routing/filter/packet
    lifecycle. The enclosing fixed manager and native worker are separate.
    """

    filter_count = 2

    def __init__(self, context: CommContext, pool: UtilityExPassThruPool, kind: int):
        if context.module_sha256 not in _CAN_LOWER_SOURCES:
            raise UtilityExSourceError("CAN lower source is not reviewed")
        if not isinstance(pool, UtilityExPassThruPool) or pool.context is not context:
            raise TypeError("Concrete same-context native driver pool required")
        if type(kind) is not int or kind not in (0x10, 0x11, 0x13, 0x14, 0x15):
            raise ValueError("Native CAN lower type required")
        self.context, self.pool, self.kind = context, pool, kind
        self.slot: int | None = None
        self.address, self.extra, self.alternate_extra = 0, 0, 0
        self.timeout_ms, self.default_timeout_ms = 1000, 0x3FC
        self.last_receive_tick = 0
        self.filter_ids = [0xFFFFFFFF] * self.filter_count
        key = f"utility_ex:can_manager_mutex:{context.module_sha256}"
        self.mutex = _published_state(
            context,
            key,
            UtilityExManagerMutex,
            lambda: UtilityExManagerMutex(context),
            "Concrete native CAN manager mutex required",
        )

    @property
    def connection_protocol(self) -> int:
        return 0x8005 if self.kind == 0x15 else 6

    @property
    def connection_flags(self) -> int:
        return 0x80 if self.extended else 0

    @property
    def connection_native_mode(self) -> int:
        return 0x15 if self.kind == 0x15 else 0

    @property
    def extended(self) -> bool:
        return self.kind in (0x11, 0x14)

    def _filter_message(self, address: int, extra: int) -> NativeMessage:
        data = address.to_bytes(4, "big")
        if extra:
            data += bytes((extra & 255,))
        return NativeMessage(0x8005 if self.kind == 0x15 else 6, data)

    def _response_delta(self) -> int:
        # Plus NK423c0/42650/42260/41c70 and TY21b10/23620/21a10/21420.
        if self.context.module_sha256 in (SHA_PLUS_NK, SHA_PLUS_TY):
            base = _TARGET_GLOBAL_BASES[self.context.module_sha256]
            mode = self.context.state.get(f"native_global:{base + 8:x}")
            if mode is None:
                mode = self.context.broker(0x6F)
            if type(mode) is not int or not 0 <= mode <= 0xFFFFFFFF:
                raise ValueError("Native CAN mode must be uint32")
            if mode == 0x74:
                return 16
        return 8

    def _routing(self, slot: int) -> None:
        mask = self._filter_message(0xFFFFFFFF, 255 if self.extra else 0)
        pattern = self._filter_message(
            (self.address + self._response_delta()) & 0x7FF, self.extra
        )
        self.pool.route_filter(slot, mask.data, pattern.data)

    def _filters(self, slot: int) -> int:
        broad = self._filter_message(0x700, 0)
        status, handle = self.pool.start_filter(slot, 1, broad, broad, broad)
        self.filter_ids[0] = handle
        if status:
            return status
        mask = self._filter_message(0xFFFFFFFF, 255 if self.extra else 0)
        pattern = self._filter_message(
            (self.address + self._response_delta()) & 0x7FF, self.extra
        )
        flow = self._filter_message(self.address & 0x7FF, self.extra)
        status, handle = self.pool.start_filter(slot, 3, mask, pattern, flow)
        self.filter_ids[1] = handle
        return status

    def initialize(
        self,
        address: int,
        *,
        extra: int = 0,
        alternate_extra: int = 0,
        override: bool = False,
        supplied: tuple[tuple[int, int], ...] | None = None,
        native_delay_ms: int | None = None,
        oem_parameter: int = 0,
    ) -> int:
        if type(address) is not int or not 0 <= address <= 0xFFFFFFFF:
            raise ValueError("Native CAN address must be uint32")
        for extension in (extra, alternate_extra):
            if type(extension) is not int or not 0 <= extension <= 0xFFFFFFFF:
                raise ValueError("Native extension must be uint32")
        status = self.mutex.acquire()
        if status:
            return status
        try:
            try:
                if self.slot is None:
                    status, slot = self.pool.connect(
                        self.connection_protocol,
                        address,
                        flags=self.connection_flags,
                        extra=extra if self.extended else 0,
                        native_mode=self.connection_native_mode,
                        oem_parameter=oem_parameter,
                    )
                    if status:
                        return 99
                    self.slot, self.address, self.extra = slot, address, extra & 255
                    self.alternate_extra = alternate_extra
                slot = self.slot
                if not override and supplied is None:
                    blob = self.context.broker_data(500)
                    if type(blob) is not bytes or len(blob) > 65536 * 8:
                        raise ValueError("Bounded immutable native broker500 required")
                    supplied = tuple(
                        (
                            int.from_bytes(blob[index : index + 4], "little"),
                            int.from_bytes(blob[index + 4 : index + 8], "little"),
                        )
                        for index in range(0, len(blob) & ~7, 8)
                    )
                delay = (
                    self.context.broker(0x14B)
                    if native_delay_ms is None
                    else native_delay_ms
                )
                status = self.pool.configure_can(
                    slot,
                    override=override,
                    supplied=supplied,
                    native_delay_ms=delay,
                    oem_configuration=self.kind == 0x15,
                )
                if not status:
                    self._routing(slot)
                    status = self._filters(slot)
            finally:
                self.mutex.release()
        except BaseException as error:
            try:
                self.finalize()
            except BaseException as cleanup_error:  # noqa: BLE001 - preserve primary fault
                error.add_note(
                    "UtilityEx CAN cleanup failed: " + type(cleanup_error).__name__
                )
            raise
        if status:
            self.finalize()
        return status

    def finalize(self) -> int:
        if self.slot is None:
            return 0
        status = self.mutex.acquire()
        if status:
            return status
        error: BaseException | None = None
        try:
            for index, handle in enumerate(self.filter_ids):
                try:
                    result = self.pool.stop_filter(self.slot, handle)
                    if result == 0:
                        self.filter_ids[index] = 0xFFFFFFFF
                except BaseException as failure:  # noqa: BLE001 - attempt every release
                    if error is None:
                        error = failure
                    else:
                        error.add_note("Additional native filter release failed")
            try:
                status = self.pool.close(self.slot)
                if status == 0:
                    self.slot = None
                    self.filter_ids[:] = [0xFFFFFFFF] * self.filter_count
            except BaseException as failure:  # noqa: BLE001 - preserve earlier release fault
                if error is None:
                    error = failure
                else:
                    error.add_note(
                        "Native physical disconnect failed: " + type(failure).__name__
                    )
            if error is not None:
                raise error
            return status
        finally:
            self.mutex.release()

    def send(self, request: bytes) -> int:
        if self.slot is None:
            return 99
        message = pack_uds_request(
            self.address, request, 0x8005 if self.kind == 0x15 else 6
        )
        if self.extended:
            message = replace(
                message, data=message.data[:4] + bytes((self.extra,)) + request
            )
        self.timeout_ms = self.default_timeout_ms
        return self.pool.write(self.slot, message, self.timeout_ms)

    def receive(self) -> DriverReceive:
        if self.slot is None:
            return DriverReceive(99)
        status, message = self.pool.read(self.slot, self.timeout_ms)
        self.last_receive_tick = self.context.ticks()
        if status:
            return DriverReceive(status)
        assert message is not None
        if self.extended:
            if len(message.data) < 5 or message.data[4] != self.extra:
                return DriverReceive(3)
            message = NativeMessage(
                message.protocol_id, message.data[:4] + message.data[5:]
            )
        reply = unpack_uds_response(message, self.address, self._response_delta())
        if reply.status == 5:
            self.timeout_ms = 5000 if self.extended else 5530
        elif reply.status in (7, 0x16, 0x1B):
            self.context.native_sleep(self.pool._channel(self.slot).delay_ms)
        return reply

    def interrupt(self, timeout_ms: int) -> None:
        # Exact lower vslot0c is NK1f0b0: returns0 and consumes its DWORD only.
        if type(timeout_ms) is not int or not 0 <= timeout_ms <= 0xFFFFFFFF:
            raise ValueError("Native interrupt argument must be uint32")


class UtilityExP6Lower(UtilityExCANLower):
    """Plus25240/46dc0 CAN29/CANFD lower, separate from ordinary fixed CAN."""

    filter_count = 1

    def __init__(self, context: CommContext, pool: UtilityExP6Pool, kind: int):
        if context.module_sha256 not in (SHA_PLUS_NK, SHA_PLUS_TY):
            raise UtilityExSourceError("P6 lower source is not reviewed")
        if (
            not isinstance(pool, UtilityExP6Pool)
            or type(kind) is not int
            or kind not in (0x17, 0x18)
        ):
            raise TypeError("Concrete P6 pool and nativekind17/18 required")
        super().__init__(context, pool, 0x10)
        self.kind = kind
        self._physical_protocol: int | None = None

    def _module_protocol(self) -> int:
        base = _TARGET_GLOBAL_BASES[self.context.module_sha256]
        value = self.context.state.get(
            f"native_global:{base + 12:x}", self.context.broker(0x70)
        )
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("Native P6 module protocol must be uint32")
        return value

    @property
    def connection_protocol(self) -> int:
        if self._physical_protocol is not None:
            return self._physical_protocol
        return 0x8012 if self._module_protocol() == 0x78 else 6

    def initialize(
        self,
        address: int,
        *,
        extra: int = 0,
        alternate_extra: int = 0,
        override: bool = False,
        supplied: tuple[tuple[int, int], ...] | None = None,
        native_delay_ms: int | None = None,
        oem_parameter: int = 0,
    ) -> int:
        if self.slot is None:
            self._physical_protocol = 0x8012 if self._module_protocol() == 0x78 else 6
        if native_delay_ms is None:
            base = _TARGET_GLOBAL_BASES[self.context.module_sha256]
            delay = self.context.state.get(
                f"native_global:{base + 28:x}", self.context.broker(0x14B)
            )
            if type(delay) is not int or not 0 <= delay <= 0xFFFFFFFF:
                raise ValueError("Native P6 module delay must be uint32")
            native_delay_ms = delay
        return super().initialize(
            address,
            extra=extra,
            alternate_extra=alternate_extra,
            override=override,
            supplied=supplied,
            native_delay_ms=native_delay_ms,
            oem_parameter=oem_parameter,
        )

    def finalize(self) -> int:
        status = super().finalize()
        if self.slot is None:
            self._physical_protocol = None
        return status

    def _request_message(self, address: int, request: bytes) -> NativeMessage:
        message = pack_p6_request(address, request, self.connection_protocol)
        # 25cc0 reads module70 for flags even when a prior physical driver remains.
        return replace(
            message, tx_flags=0x180140 if self._module_protocol() == 0x78 else 0x140
        )

    @property
    def connection_flags(self) -> int:
        return 0x800

    def _filter_message(self, address: int, extra: int) -> NativeMessage:
        data = address.to_bytes(4, "big") + (bytes((extra & 255,)) if extra else b"")
        return NativeMessage(self.connection_protocol, data, tx_flags=0x140)

    def _response_address(self) -> int:
        return ((self.address & 255 | 0x18DA00) << 8) | ((self.address >> 8) & 255)

    def _routing(self, slot: int) -> None:
        mask = self._filter_message(0xFFFFFFFF, 255 if self.extra else 0)
        pattern = self._filter_message(self._response_address(), self.extra)
        self.pool.route_filter(slot, mask.data, pattern.data)

    def _filters(self, slot: int) -> int:
        mask = self._filter_message(0xFFFFFFFF, 255 if self.extra else 0)
        pattern = self._filter_message(self._response_address(), self.extra)
        flow = self._filter_message(self.address, self.extra)
        status, handle = self.pool.start_filter(slot, 3, mask, pattern, flow)
        self.filter_ids[0] = handle
        return status

    def send(self, request: bytes) -> int:
        if self.slot is None:
            return 99
        self.timeout_ms = self.default_timeout_ms
        return self.pool.write(
            self.slot,
            self._request_message(self.address, request),
            self.timeout_ms,
        )

    def receive(self) -> DriverReceive:
        if self.slot is None:
            return DriverReceive(99)
        status, message = self.pool.read(self.slot, self.timeout_ms)
        self.last_receive_tick = self.context.ticks()
        if status:
            return DriverReceive(status)
        assert message is not None
        reply = unpack_p6_response(message, self.address)
        if reply.status == 5:
            self.timeout_ms = 5530
        elif reply.status in (7, 22, 27):
            self.context.native_sleep(self.pool._channel(self.slot).delay_ms)
        return reply


class UtilityExP6BroadcastLower(UtilityExP6Lower):
    """Plus25e70/47a40 selected P6 broadcast: physical RX, functional TX/flow."""

    def _filters(self, slot: int) -> int:
        mask = self._filter_message(0xFFFFFFFF, 0)
        pattern = self._filter_message(self._response_address(), 0)
        flow = self._filter_message(self.alternate_extra, 0)
        status, handle = self.pool.start_filter(slot, 3, mask, pattern, flow)
        self.filter_ids[0] = handle
        return status

    def send(self, request: bytes) -> int:
        if self.slot is None:
            return 99
        self.timeout_ms = self.default_timeout_ms
        return self.pool.write(
            self.slot,
            self._request_message(self.alternate_extra, request),
            self.timeout_ms,
        )


class UtilityExBroadcastCANLower(UtilityExCANLower):
    """NK18 cc14/cc68 and TY18 daa44/daa98 functional broadcast subclasses.

    The pool is keyed by physical ECU address; only the outgoing address comes
    from lower+24. Reply decoding/routing remains the physical address plus8.
    """

    def __init__(self, context: CommContext, pool: UtilityExPassThruPool, kind: int):
        if context.module_sha256 not in _CAN_LOWER_SOURCES:
            raise UtilityExSourceError("Broadcast CAN source is not reviewed")
        if kind not in (0x10, 0x13, 0x15):
            raise ValueError("Native broadcast CAN kind required")
        super().__init__(context, pool, kind)

    def _filters(self, slot: int) -> int:
        # Native27560: first pass filter has a NULL flow-control pointer.
        mask = self._filter_message(self.address | 0xFF, 0)
        # Plus MS broadcast filters keep literal+8 even under mode74;
        # HS filters and the inherited decoder/routing use the mode-specific delta.
        delta = 8 if self.kind == 0x15 else self._response_delta()
        response = (self.address + delta) & 0xFFFFFFFF
        pattern = self._filter_message(response, 0)
        status, handle = self.pool.start_filter(slot, 1, mask, pattern, None)
        self.filter_ids[0] = handle
        if status:
            return status
        mask = self._filter_message(0xFFFFFFFF, 0)
        pattern = self._filter_message(response & 0x7FF, 0)
        flow = self._filter_message(self.address & 0x7FF, 0)
        status, handle = self.pool.start_filter(slot, 3, mask, pattern, flow)
        self.filter_ids[1] = handle
        return status

    def send(self, request: bytes) -> int:
        if self.slot is None:
            return 99
        message = pack_uds_request(
            self.alternate_extra, request, 0x8005 if self.kind == 0x15 else 6
        )
        self.timeout_ms = (
            0x3FC
            if self.context.module_sha256 in (SHA_12_NK, SHA_12_TY)
            else self.default_timeout_ms
        )
        return self.pool.write(self.slot, message, self.timeout_ms)


class UtilityExComm:
    """Exact-source facade. Unported connection paths remain unavailable."""

    def __init__(self, context: CommContext, selector: str = "selected"):
        if context.module_sha256 not in _FIXED_OBJECTS:
            raise UtilityExSourceError("UtilityEx communication source is not reviewed")
        if hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256:
            raise UtilityExSourceError("UtilityEx module identity mismatch")
        managers = (
            _FIXED_OBJECTS[context.module_sha256],
            *_ADDITIONAL_FIXED_OBJECTS.get(context.module_sha256, ()),
            *_SIS_OBJECTS.get(context.module_sha256, ()),
            *_P6_OBJECTS.get(context.module_sha256, ()),
        )
        if selector != "selected" and selector not in {
            f"native:{address:x}" for address in managers
        }:
            raise UtilityExSourceError("Unknown native UtilityEx manager")
        self.context, self.selector = context, selector
        self.manager_address = (
            select_native_manager(
                context.module_sha256, context.broker(0x6F), context.broker(0x70)
            )
            if selector == "selected"
            else int(selector.split(":")[1], 16)
        )
        self._lower: (
            UtilityExCANLower
            | UtilityExP3Lower
            | UtilityExClassicCANLower
            | UtilityExSISLower
            | None
        ) = None
        self._classic_scheduler: UtilityExClassicScheduler | None = None
        self._sis_fields: UtilityExSISFields | None = None
        if self.manager_address in _SIS_OBJECTS.get(context.module_sha256, ()):
            from scripts.utility_ex_lifecycle import UtilityExSISFields

            key = f"utility_ex:sis_fields:{context.module_sha256}:{self.manager_address:x}"
            self._sis_fields = _published_state(
                context,
                key,
                UtilityExSISFields,
                UtilityExSISFields,
                "Concrete independent SIS manager fields required",
                contextual=False,
            )
        self._p6_fields: UtilityExP6Fields | None = None
        if self.manager_address in _P6_OBJECTS.get(context.module_sha256, ()):
            key = (
                f"utility_ex:p6_fields:{context.module_sha256}:{self.manager_address:x}"
            )
            self._p6_fields = _published_state(
                context,
                key,
                UtilityExP6Fields,
                UtilityExP6Fields,
                "Separate concrete P6 manager fields required",
                contextual=False,
            )
        self._fields = (
            self._p6_fields
            if self._p6_fields is not None
            else _uds_fields(context, self.manager_address)
            if selector != "selected"
            and self.manager_address is not None
            and self._sis_fields is None
            else None
        )

    def _scope_entry(self) -> None:
        if self.selector == "selected":
            # Every native stack-manager constructor resets this flag anew.
            abort = _SELECTED_PENDING_GLOBALS[self.context.module_sha256][1]
            self.context.state[f"native_global:{abort:x}"] = 0

    def cancellation_counters(self) -> dict[str, int]:
        """Direct source getters never construct/reset a selected stack scope."""
        return _classic_fields(self.context).counters(self.context.module_sha256)

    def _support_cache(self) -> UtilityExSupportCache:
        key = f"utility_ex:support_profiles:{self.context.module_sha256}"
        return _published_state(
            self.context,
            key,
            UtilityExSupportCache,
            lambda: UtilityExSupportCache(self.context),
            "Concrete same-context native support cache required",
        )

    def refresh_support_cache(self, kind: int) -> int:
        if self.manager_address is None:
            return 83
        if self._classic_scheduler is None:
            raise UtilityExSourceError(
                "Native selected communication scheduler is not initialized"
            )
        return self._support_cache().refresh(
            self._classic_scheduler, kind, self.read_target(), self.selected_protocol()
        )

    def append_support_profile(self, raw: bytes, kind: int) -> int:
        self._selected_scheduler()  # Native20b90 requires a current selected object.
        return self._support_cache().append(
            raw, kind, self.read_target(), self.selected_protocol()
        )

    def support_length(self, kind: int, selector: int) -> int:
        """NK16eb0/204c0/3d910/3e920: current-object metadata length/count."""
        for value in (kind, selector):
            if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
                raise ValueError("Native support selector must be uint32")
        pointer_address = {
            SHA_12_NK: 0x100EA9A4,
            SHA_18_NK: 0x10151854,
            SHA_DS4_NK: 0x101B8B44,
            SHA_PLUS_NK: 0x101C8074,
        }.get(self.context.module_sha256)
        if self.selector != "selected" or pointer_address is None:
            raise UtilityExSourceError("Native selected support length source required")
        pointer = self.context.state.get(f"native_global:{pointer_address:x}", 0)
        if pointer == 0:
            return 0
        if type(pointer) is not int:
            raise ValueError("Native selected pointer must be uint32")
        protocol = native_manager_protocol(self.context.module_sha256, pointer)
        cache = self.context.state.get(
            f"utility_ex:support_profiles:{self.context.module_sha256}"
        )
        if cache is None:
            return 0
        if (
            not isinstance(cache, UtilityExSupportCache)
            or cache.context is not self.context
        ):
            raise TypeError("Concrete same-context native support cache required")
        profile = cache.snapshot(kind & 255, self.read_target(), protocol)
        if profile is None:
            return 0
        raw, offsets = profile
        offset = offsets[selector & 255]
        if offset == 0x1020 or offset + 1 >= len(raw):
            return 0
        size = raw[offset + 1]
        if kind & 255 == 3:
            return size
        if kind & 255 == 2:
            end = offset + 2 + size
            if end > len(raw):
                raise ValueError("Native support record exceeds its backing")
            return sum(value != 0 for value in raw[offset + 2 : end])
        return 0

    def cached_support(self, kind: int) -> tuple[bytes, tuple[int, ...]] | None:
        return self._support_cache().snapshot(
            kind, self.read_target(), self.selected_protocol()
        )

    def selected_protocol(self) -> int:
        if self.selector != "selected" or self.manager_address is None:
            raise UtilityExSourceError("Concrete native selected manager required")
        return native_manager_protocol(self.context.module_sha256, self.manager_address)

    def _target_globals(self) -> tuple[str, str]:
        base = _TARGET_GLOBAL_BASES[self.context.module_sha256]
        return f"native_global:{base:x}", f"native_global:{base + 4:x}"

    def read_target(self) -> tuple[int, int]:
        result: list[int] = []
        for field, broker in zip(self._target_globals(), (0x74, 0xAB)):
            value = self.context.state.get(field)
            if value is None:
                value = self.context.broker(broker)
            if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
                raise ValueError("Native module target global must be uint32")
            result.append(value)
        return result[0], result[1]

    def configure_target(
        self,
        first: int,
        second: int = 0,
        third: int = 0,
        fourth: int = 0,
        fifth: int = 0,
    ) -> None:
        """TY18 19d40/NK18 17e10/PlusTY1d6e0, preserving zero fallbacks."""
        if self._fields is None:
            raise UtilityExSourceError(
                "Native fixed manager target configuration required"
            )
        for value in (first, second, third, fourth, fifth):
            if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
                raise ValueError("Native target fields must be uint32")
        primary, extension = self.read_target()
        self._fields.primary_address = first or primary
        self._fields.extension = second or extension
        self._fields.alternate_extension = third or self.context.broker(0x15F)
        self._fields.oem_parameter = fourth or self.context.native_parameter(0x71)
        self._fields.alternate_address = fifth or self.context.broker(0x155)
        self._fields.target_configured = True

    def configure_parameters(self, parameters: tuple[tuple[int, int], ...]) -> None:
        """NK18 17ea0, immutable native SCONFIG pairs and count."""
        if self._fields is None or self.context.module_sha256 not in (
            SHA_12_NK,
            SHA_18_NK,
            SHA_DS4_NK,
            SHA_PLUS_NK,
        ):
            raise UtilityExSourceError(
                "Native fixed manager parameter configuration required"
            )
        if not isinstance(parameters, tuple) or len(parameters) > 65536:
            raise ValueError("Bounded immutable native SCONFIG_LIST required")
        for pair in parameters:
            if (
                not isinstance(pair, tuple)
                or len(pair) != 2
                or any(
                    type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                    for value in pair
                )
            ):
                raise ValueError("Native SCONFIG entries must be uint32 pairs")
        self._fields.parameters = parameters

    def select_protocol(self, kind: int) -> int:
        """TY18 19dd0/NK18 17ec0/PlusTY1d570 select lower class before connect."""
        if self._p6_fields is not None:
            raise UtilityExSourceError(
                "Native P6 class selection uses its own source primitive"
            )
        if self._fields is None:
            raise UtilityExSourceError(
                "Native fixed manager protocol selection required"
            )
        if type(kind) is not int or not 0 <= kind <= 0xFFFFFFFF:
            raise ValueError("Native lower class selector must be uint32")
        if isinstance(self._lower, UtilityExCANLower) and self._lower.slot is not None:
            return 13
        if kind not in (0, 0x10, 0x11, 0x13, 0x14, 0x15):
            return 22
        self._fields.lower_kind = kind
        return 0

    def select_diagnostic_mode(self, mode: int) -> int:
        """Fixed23460 source class selection; unported broadcasts fail closed."""
        lifecycle = self._fixed_lifecycle(create=True)
        if self._sis_fields is not None:
            raise UtilityExSourceError("SIS diagnostic class differs from ordinary CAN")
        return cast("UtilityExFixedLifecycle", lifecycle).select_diagnostic_mode(mode)

    def select_target(self, identifier: int, second: int = 0) -> None:
        """TY18 11db0/NK18 16f00: direct module-global target DWORDs."""
        for value in (identifier, second):
            if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
                raise ValueError("Native target fields must be uint32")
        fields = self._target_globals()
        for field, value in zip(fields, (identifier, second)):
            self.context.state[field] = value

    def read_field(self, field: str) -> int:
        if self._p6_fields is not None:
            if (
                field == "native_rva:1eb90"
                and self.context.module_sha256 == SHA_PLUS_TY
            ):
                return self._p6_fields.busy_count
            if field.startswith("native_"):
                try:
                    offset = int(field[7:], 16)
                except ValueError:
                    offset = -1
                name = P6_FIELD_OFFSETS.get(offset)
                if name is not None:
                    value = getattr(self._p6_fields, name)
                    return int(not value) if offset == 0x10D8 else int(value)
            raise UtilityExSourceError("Native P6 field getter is not reviewed")
        if self._sis_fields is not None:
            from scripts.utility_ex_lifecycle import SIS_FIELD_OFFSETS

            getter = (
                "native_rva:1eb90"
                if self.context.module_sha256 == SHA_PLUS_TY
                else "native_rva:1ba20"
            )
            if field == getter:
                return self._sis_fields.native_error
            if field.startswith("native_"):
                try:
                    offset = int(field[7:], 16)
                except ValueError:
                    offset = -1
                name = SIS_FIELD_OFFSETS.get(offset)
                if name is not None:
                    return getattr(self._sis_fields, name)
            raise UtilityExSourceError("Native SIS field getter is not reviewed")
        getter = {
            SHA_12_TY: "native_rva:b980",
            SHA_18_TY: "native_rva:121f0",
            SHA_PLUS_TY: "native_rva:140c0",
        }.get(self.context.module_sha256)
        if getter is not None and field == getter:
            return _classic_fields(self.context).busy_limit
        if self.context.module_sha256 in _NATIVE_COUNTER_GETTERS:
            counters = self.cancellation_counters()
            if field in counters:
                return counters[field]
        if self._fields is None or field != "native_10b0":
            raise UtilityExSourceError("Native UtilityEx field getter is not reviewed")
        return self._fields.native_error

    def _sis_lifecycle(self, *, create: bool = False) -> UtilityExSISLifecycle:
        from scripts.utility_ex import UtilityExContext
        from scripts.utility_ex_lifecycle import (
            SISContext,
            UtilityExSISDriver,
            UtilityExSISLifecycle,
        )

        if self._sis_fields is None or self.manager_address is None:
            raise UtilityExSourceError("Concrete SIS manager required")
        sis_fields = self._sis_fields
        manager_address = self.manager_address
        key = f"utility_ex:fixed_lifecycle:{self.context.module_sha256}:{manager_address:x}"
        if not create:
            lifecycle = self.context.state.get(key)
            if lifecycle is None:
                raise UtilityExSourceError("Native SIS manager is not initialized")
            if (
                not isinstance(lifecycle, UtilityExSISLifecycle)
                or lifecycle.context is not self.context
            ):
                raise UtilityExSourceError("Native SIS manager is not initialized")
            return lifecycle

        def publish_lifecycle() -> UtilityExSISLifecycle:
            driver_key = f"utility_ex:sis_driver:{self.context.module_sha256}"
            driver = _published_state(
                self.context,
                driver_key,
                UtilityExSISDriver,
                lambda: UtilityExSISDriver(
                    self.context,
                    cast(UtilityExContext, self.context).sis_driver_binding(),
                ),
                "Concrete same-context SIS DRIVER required",
            )
            return UtilityExSISLifecycle(
                cast(SISContext, self.context),
                driver,
                sis_fields,
                manager_address,
            )

        return _published_state(
            self.context,
            key,
            UtilityExSISLifecycle,
            publish_lifecycle,
            "Native SIS manager is not initialized",
            UtilityExSourceError,
        )

    def _fixed_lifecycle(
        self, *, create: bool = False
    ) -> UtilityExFixedLifecycle | UtilityExSISLifecycle:
        from scripts.utility_ex_lifecycle import (
            UtilityExFixedLifecycle,
            UtilityExP6Lifecycle,
        )

        if self._sis_fields is not None:
            return self._sis_lifecycle(create=create)

        if (
            self.selector == "selected"
            or self._fields is None
            or self.manager_address is None
        ):
            raise UtilityExSourceError("Concrete fixed manager required")
        if self.context.module_sha256 not in _CAN_LOWER_SOURCES:
            raise UtilityExSourceError("Native fixed lower lifecycle is unported")
        key = f"utility_ex:fixed_lifecycle:{self.context.module_sha256}:{self.manager_address:x}"
        fields = self._fields
        manager = self.manager_address
        p6_fields = self._p6_fields
        if not create:
            lifecycle = self.context.state.get(key)
            if (
                not isinstance(lifecycle, UtilityExFixedLifecycle)
                or lifecycle.context is not self.context
            ):
                raise UtilityExSourceError("Native fixed manager is not initialized")
            return lifecycle

        def publish_lifecycle() -> UtilityExFixedLifecycle:
            if p6_fields is not None:
                from scripts.utility_ex import UtilityExContext

                pool_key = f"utility_ex:p6_pool:{self.context.module_sha256}"

                def publish_p6_pool() -> UtilityExP6Pool:
                    actual = cast(UtilityExContext, self.context)
                    adapter = UtilityExDriverPrimitives(
                        self.context, actual.p6_driver_binding(6)
                    )
                    pool = UtilityExP6Pool(
                        self.context,
                        J2534Device2026(
                            adapter,
                            cancelled=self.context.is_cancelled,
                            background_workers=False,
                        ),
                    )
                    pool.register_binding(actual.p6_driver_binding(0x8012))
                    return pool

                pool = _published_state(
                    self.context,
                    pool_key,
                    UtilityExP6Pool,
                    publish_p6_pool,
                    "Separate same-context P6 pool required",
                )
                return UtilityExP6Lifecycle(self.context, pool, p6_fields, manager)

            pool_key = f"utility_ex:can_pool:{self.context.module_sha256}"

            def publish_pool() -> UtilityExPassThruPool:
                adapter = UtilityExDriverPrimitives(
                    self.context, self.context.driver_binding(6)
                )
                return UtilityExPassThruPool(
                    self.context,
                    J2534Device2026(
                        adapter,
                        cancelled=self.context.is_cancelled,
                        background_workers=False,
                    ),
                )

            pool = _published_state(
                self.context,
                pool_key,
                UtilityExPassThruPool,
                publish_pool,
                "Concrete same-context native pool required",
            )
            return UtilityExFixedLifecycle(
                self.context, pool, cast(UDSFields, fields), manager
            )

        return _published_state(
            self.context,
            key,
            UtilityExFixedLifecycle,
            publish_lifecycle,
            "Native fixed manager is not initialized",
            UtilityExSourceError,
        )

    def _selected_lower(self) -> UtilityExP3Lower | UtilityExClassicCANLower:
        from scripts.utility_ex_lifecycle import UtilityExClassicCANLower

        if (
            self.context.module_sha256 not in _SELECTED_LOWER_OBJECTS
            or self.selector != "selected"
        ):
            raise UtilityExSourceError("Native selected lower lifecycle is unported")
        selected = _SELECTED_GLOBALS[self.context.module_sha256][0]
        pointer = self.context.state.get(f"native_global:{selected:x}", 0)
        key = (
            f"utility_ex:selected_lower:{self.context.module_sha256}:{pointer:x}"
            if type(pointer) is int
            else ""
        )
        lower = self.context.state.get(key)
        if pointer not in _SELECTED_LOWER_OBJECTS[
            self.context.module_sha256
        ] or not isinstance(lower, (UtilityExP3Lower, UtilityExClassicCANLower)):
            raise UtilityExSourceError("Native selected lower is not initialized")
        return lower

    def _selected_scheduler(self) -> UtilityExClassicScheduler:
        lower = self._selected_lower()
        return UtilityExClassicScheduler(
            self.context, UtilityExSelectedPending(self.context, lower, derived=True)
        )

    def initialize(self, mode: int = 0) -> int:
        return self._initialize(mode, None)

    def initialize_at(self, address: int, mode: int = 1) -> int:
        """Selected16f20 explicit address; preserve the module target globals."""
        if self.selector != "selected":
            raise UtilityExSourceError(
                "Explicit initialization address requires selected manager"
            )
        if type(address) is not int or not 0 <= address <= 0xFFFFFFFF:
            raise ValueError("Native initialization address must be uint32")
        return self._initialize(mode, address)

    def _initialize(self, mode: int, address: int | None) -> int:
        from scripts.utility_ex_lifecycle import (
            UtilityExClassicCANLower,
            UtilityExLegacyP4Lower,
            UtilityExP3F1Lower,
            UtilityExP3SlowLower,
            UtilityExP3StrictLower,
        )

        self._scope_entry()
        if type(mode) is not int or not 0 <= mode <= 0xFFFFFFFF:
            raise ValueError("Native initialization mode must be uint32")
        if self.selector != "selected":
            lifecycle = self._fixed_lifecycle(create=True)
            status = lifecycle.initialize(mode)
            self._lower = lifecycle.lower
            return status
        if self.context.module_sha256 not in _SELECTED_LOWER_OBJECTS:
            raise UtilityExSourceError(
                "Native UtilityEx lower initialization is unported"
            )
        selected_global, override_global, profile_global = _SELECTED_GLOBALS[
            self.context.module_sha256
        ]
        override = self.context.state.get(f"native_global:{override_global:x}", 0)
        if type(override) is not int or not 0 <= override <= 0xFFFFFFFF:
            raise ValueError("Native selected override must be uint32")
        manager = override or select_native_manager(
            self.context.module_sha256,
            self.context.broker(0x6F),
            self.context.broker(0x70),
        )
        if (
            manager is None
            or manager not in _SELECTED_LOWER_OBJECTS[self.context.module_sha256]
        ):
            raise UtilityExSourceError(
                "Native selected lower initialization is unported"
            )
        objects = _MANAGER_OBJECTS[self.context.module_sha256]
        index = objects.index(manager)
        protocol = 4 if index < 5 else 6
        constructor = 0xD if manager in objects[5:8] else 0
        key = f"utility_ex:direct_driver:{self.context.module_sha256}:{protocol}:{constructor}"

        def publish_driver() -> UtilityExDirectDriver:
            adapter = UtilityExDriverPrimitives(
                self.context,
                self.context.driver_binding(
                    protocol, constructor_parameter=constructor
                ),
            )
            return UtilityExDirectDriver(self.context, adapter, protocol)

        driver = _published_state(
            self.context,
            key,
            UtilityExDirectDriver,
            publish_driver,
            "Concrete same-context direct singleton required",
        )
        key = f"utility_ex:selected_lower:{self.context.module_sha256}:{manager:x}"

        def publish_lower() -> UtilityExP3Lower | UtilityExClassicCANLower:
            p3_types = (
                UtilityExP3Lower,
                UtilityExP3F1Lower,
                UtilityExP3StrictLower,
                UtilityExLegacyP4Lower,
                UtilityExP3SlowLower,
            )
            return (
                p3_types[index](self.context, driver)
                if index < len(p3_types)
                else UtilityExClassicCANLower(self.context, driver, manager)
            )

        lower = _published_state(
            self.context,
            key,
            (UtilityExP3Lower, UtilityExClassicCANLower),
            publish_lower,
            "Concrete same-context selected P3 lower required",
        )
        profile = self.context.state.get(f"native_global:{profile_global:x}", 0)
        if type(profile) is not int or not 0 <= profile <= 0xFFFFFFFF:
            raise ValueError("Native selected profile must be uint32")
        lower.profile = profile
        self.manager_address = manager
        self.context.state[f"native_global:{selected_global:x}"] = manager
        self._lower = lower
        status = lower.initialize(
            self.read_target()[0] if address is None else address,
            override=bool(mode),
            reuse=bool(override),
        )
        self._classic_scheduler = self._selected_scheduler()
        return status

    def finalize(self) -> None:
        self._scope_entry()
        if (
            self.context.module_sha256 in _SELECTED_LOWER_OBJECTS
            and self.selector == "selected"
        ):
            selected = _SELECTED_GLOBALS[self.context.module_sha256][0]
            pointer = self.context.state.get(f"native_global:{selected:x}", 0)
            if pointer:
                self._selected_lower().finalize()
            for address in _SELECTED_GLOBALS[self.context.module_sha256]:
                self.context.state[f"native_global:{address:x}"] = 0
            self._classic_scheduler = None
            self._lower = None
        elif (
            self.selector != "selected"
            and self.context.module_sha256 in _CAN_LOWER_SOURCES
        ):
            key = f"utility_ex:fixed_lifecycle:{self.context.module_sha256}:{self.manager_address:x}"
            if key in self.context.state:
                lifecycle = self._fixed_lifecycle()
                lifecycle.finalize()
                self._lower = lifecycle.lower
        # Other source paths cannot acquire resources until their initialize port.

    def exchange(self, request: bytes) -> tuple[int, bytes]:
        self._scope_entry()
        if self.selector != "selected":
            return self._fixed_lifecycle().exchange(request)
        return self._selected_scheduler().exchange(request)

    def exchange_plain(self, request: bytes) -> tuple[int, bytes]:
        """Base CComTestMode11740/12660 retains lower interrupt errors."""
        self._scope_entry()
        if self.selector != "selected":
            raise UtilityExSourceError("Plain selected stack manager required")
        return UtilityExClassicScheduler(
            self.context,
            UtilityExSelectedPending(
                self.context, self._selected_lower(), derived=False
            ),
        ).exchange(request)

    def cleanup_exchange(self, request: bytes) -> tuple[int, bytes]:
        """Bounded explicit release under the owned lower cleanup scope."""
        from scripts.utility_ex_lifecycle import utility_ex_cleanup_scope

        if self.selector != "selected":
            return self._fixed_lifecycle().cleanup_exchange(request)
        lower = self._selected_lower()
        with utility_ex_cleanup_scope(lower):
            return self._selected_scheduler().exchange(request)

    def support_snapshot(self, kind: int) -> tuple[int, bytes, tuple[int, ...]]:
        self._scope_entry()
        return self._selected_scheduler().support_snapshot(kind)

    def read_dtcs(self, mode: int = 0x80, capacity: int = 0x1000) -> tuple[int, bytes]:
        self._scope_entry()
        return self._selected_scheduler().read_dtcs(mode, capacity)

    def configure(self, field: str, value: int) -> None:
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("Native setter value must be uint32")
        source = self.context.module_sha256
        selected_setters = {
            SHA_12_NK: ((0xF830, 0x100EA9A8), (0xF840, 0x100EA9D0)),
            SHA_12_TY: ((0xB720, 0x100AFEA4),),
            SHA_18_NK: ((0x170A0, 0x10151858), (0x170B0, 0x10151880)),
            SHA_18_TY: ((0x11F50, 0x1011F764), (0x11F60, 0x1011F78C)),
            SHA_DS4_NK: ((0x323D0, 0x101B8B4C), (0x323E0, 0x101B8B50)),
            SHA_DS4_TY: ((0x78F0, 0x1006F380), (0x7900, 0x1006F384)),
            SHA_PLUS_NK: ((0x332E0, 0x101C807C), (0x332F0, 0x101C8080)),
            SHA_PLUS_TY: ((0x142B0, 0x1013FAB0), (0x142C0, 0x1013FAB4)),
        }.get(source, ())
        for rva, address in selected_setters:
            if field == f"native_rva:{rva:x}":
                self.context.state[f"native_global:{address:x}"] = value
                return
        if source == SHA_18_TY and field == "native_rva:121b0":
            self._selected_lower().native_timeout_10 = value
            return
        short_rva = {
            SHA_12_NK: 0x10310,
            SHA_18_NK: 0x17BA0,
            SHA_DS4_NK: 0x32470,
            SHA_PLUS_NK: 0x33380,
        }.get(source)
        if short_rva is not None and field == f"native_rva:{short_rva:x}":
            _classic_fields(self.context).short_circuit = value
            return
        # Global functions are direct calls and do not construct stack managers.
        pending = f"native_rva:{_GLOBAL_PENDING_SETTERS[source]:x}"
        if field == pending or (
            source == SHA_18_TY and field == "native_global:100f8194"
        ):
            _classic_fields(self.context).pending_limit = value
            return
        counter = {
            f"native_rva:{rva:x}": name
            for rva, name in _GLOBAL_COUNTER_SETTERS[source].items()
        }.get(field)
        if counter is not None:
            setattr(_classic_fields(self.context), counter, value)
            return
        self._scope_entry()
        if self._sis_fields is not None:
            setters = {
                SHA_18_TY: (0x1B730, 0x1B750, 0x1B7A0, 0x1B7B0),
                SHA_PLUS_TY: (0x1FBB0, 0x1FBC0, 0x1FBD0, 0x1E330),
            }[source]
            names = ("receive_count", "receive_ms", "retry_count", "busy_ms")
            aliases = dict(
                zip((f"native_rva:{rva:x}" for rva in setters), names, strict=True)
            )
            name = {
                "native_1074": "receive_count",
                "native_1078": "receive_ms",
                "native_1060": "retry_count",
                "native_1098": "busy_ms",
                **aliases,
            }.get(field)
            if name is not None:
                setattr(self._sis_fields, name, value)
                return
            lower_setters = (
                ("native_lower_3c", "native_rva:1fbf0")
                if source == SHA_PLUS_TY
                else ("native_lower_38", "native_rva:1ba60")
            )
            if field in lower_setters:
                lower = self._sis_lifecycle().lower
                if lower is None:
                    raise UtilityExSourceError("Native SIS lower child required")
                lower.address = value
                return
            raise UtilityExSourceError("Native SIS setter is not reviewed")
        if self._p6_fields is not None:
            aliases = {
                SHA_PLUS_TY: {
                    0x1E290: "receive_count",
                    0x1E2B0: "receive_ms",
                    0x1E2D0: "retry_count",
                    0x1E2E0: "busy_count",
                },
                SHA_PLUS_NK: {},
            }[source]
            name = {f"native_rva:{rva:x}": name for rva, name in aliases.items()}.get(
                field
            )
            if name is None and field.startswith("native_"):
                try:
                    offset = int(field[7:], 16)
                except ValueError:
                    offset = -1
                name = P6_FIELD_OFFSETS.get(offset)
                if name == "target_configured":
                    self._p6_fields.target_configured = value == 0
                    return
            if name is not None:
                setattr(self._p6_fields, name, value)
                return
            raise UtilityExSourceError("Native P6 setter is not reviewed")
        if self._fields is not None:
            lower_timeout_setter = {
                SHA_18_TY: "native_rva:1a890",
                SHA_PLUS_TY: "native_rva:1e280",
            }.get(source)
            if lower_timeout_setter is not None and field == lower_timeout_setter:
                lower = self._fixed_lifecycle().lower
                if not isinstance(lower, UtilityExCANLower):
                    raise UtilityExSourceError("Concrete native lower child required")
                lower.default_timeout_ms = value
                return
            if source in _SHORT_RECEIVE_SETTERS and field == (
                f"native_rva:{_SHORT_RECEIVE_SETTERS[source]:x}"
            ):
                short = value != 0
                self._fields.receive_count = 1 if short else 150
                self._fields.receive_ms = 0 if short else 180000
                self._fields.busy_count = 1 if short else 255
                self._fields.busy_ms = 0
                self._fields.response_pending_count = 1 if short else 3
                self._fields.retry_count = 1 if short else 3
                self._fields.response_pending_seen = int(short)
                return
            offsets = ("native_1080", "native_1084", "native_1064")
            setters = {
                f"native_rva:{rva:x}": offset
                for rva, offset in zip(_FIXED_SETTERS[source], offsets)
            }
            name = {
                "native_1080": "receive_count",
                "native_1084": "receive_ms",
                "native_1064": "retry_count",
                "native_1098": "response_pending_count",
            }.get(setters.get(field, field))
            if name is not None:
                setattr(self._fields, name, value)
                return
        raise UtilityExSourceError("Native UtilityEx setter is not connected")

    def configure_keepalive(
        self, interval_ms: int, request: bytes, response_size: int, flags: int
    ) -> None:
        self._fixed_lifecycle().configure_keepalive(
            interval_ms, request, response_size, flags
        )

    def keepalive(self, enabled: bool, wait: bool = False) -> int:
        # Native26380 argument1 closes the lower after stopping the worker.
        self._scope_entry()
        return self._fixed_lifecycle().keepalive(enabled, wait)

    def session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int:
        self._scope_entry()
        return self._fixed_lifecycle().session(
            mode, keepalive, normal_first=normal_first, stop_on_error=stop_on_error
        )

    def cleanup_session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int:
        """Explicit bounded release retaining native session and worker state."""
        return self._fixed_lifecycle().cleanup_session(
            mode, keepalive, normal_first=normal_first, stop_on_error=stop_on_error
        )
