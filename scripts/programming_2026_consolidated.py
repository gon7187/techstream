"""Source-bound CUW2026 consolidated legacy controller and CAN ID operations.

The consolidated binary contains independent SIL and old CAN engines. Its source
identity never selects a same-named CUW12/18 plugin. Workers and the persistent
Execute controller use primitive transport operations and actual imported metadata.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from scripts.native_modules import NativeModuleIdentity, identify_native_module
from scripts.programming_2026_common import (
    CanDiag2026,
    NativeException2026,
    NativeRuntime2026,
)
from scripts.programming_2026_legacy import (
    _NATIVE_BASE_ERRORS,
    _NATIVE_DRIVER_ERRORS,
    _driver_code,
    _is_driver_error,
    _native_enum,
)

MODULE = "TCUWLegacyCIDGettersAndFlashWriters.dll"
SOURCE_SHA256 = "84ea16929e342ae73170187efce957e1d7903b34b1c3fcdd440c69105590dd22"

# Execute13170, controller vtable2caa4; worker addresses are passive PE/source reads.
WORKERS = MappingProxyType(
    {
        "sil_cid": (0xEF60, 0xF050),
        "can_electric_id": (0x17BC0, 0x17C80),
        "can_emps_id": (0x19BA0, 0x19C60),
        "can_software_info_id": (0x1F270, 0x1F550),
        "sil_emps_id": (0x21770, 0x21870),
        "sil_occupant_id": (0x23150, 0x231D0),
        "sil_vpns_id": (0x25EE0, 0x25F30),
        "can_ecb_rom_id": (0x15110, 0x151D0),
        "sil_write": (0x10870, 0x10EB0),
        "can_chassis_write": (0x135D0, 0x14100),
        "can_electric_write": (0x15940, 0x16300),
        "can_emps_write": (0x18210, 0x18950),
        "can_epb_write": (0x1A3C0, 0x1AE80),
        "can_fc_write": (0x1C380, 0x1CA40),
        "can_old_ecb_write": (0x1D560, 0x1DF10),
        "sil_emps_write": (0x20780, 0x20950),
        "sil_m16c_write": (0x21D60, 0x22040),
        "sil_occupant_write": (0x23580, 0x247E0),
    }
)


class ConsolidatedError(ValueError):
    def __init__(self, code: int, operation: str):
        self.code, self.operation = code, operation
        self.transport_code: int | None = None
        super().__init__(f"CUW2026 consolidated {operation} error {code}")


def _native_driver_slot(error, previous: int) -> int:
    """Native CJ catches copy +2c; CPass and ALL retain the current driver slot."""
    if _is_driver_error(error):
        return _driver_code(error)
    if isinstance(error, ConsolidatedError) and error.transport_code is not None:
        return error.transport_code
    return previous


@contextmanager
def _getter_connection(
    runtime: NativeRuntime2026,
    protocol: int,
    partial=None,
    error_snapshot=None,
    completion_state=None,
    request_records=None,
):
    """Native getter worker catch scope ends before final Disconnect/callbacks."""
    if error_snapshot is not None and not callable(error_snapshot):
        raise TypeError("Native getter error-slot observer must be callable")
    if completion_state is not None:
        if not isinstance(completion_state, ConsolidatedControllerState):
            raise TypeError("Native consolidated getter state required")
        completion_state.__post_init__()
    runtime.check()
    runtime.own("disconnect")
    caught = None
    completed = False
    cancelled = False
    try:
        try:
            _void(runtime, "connect", protocol=protocol)
            yield
            cancelled = _native_cancel_requested(runtime)
            completed = True
        except (ConsolidatedError, *_NATIVE_BASE_ERRORS, NativeException2026) as exc:
            runtime.check()
            code = (
                exc.code
                if isinstance(exc, ConsolidatedError)
                else _native_enum(exc)
                if isinstance(exc, _NATIVE_BASE_ERRORS)
                else 0
            )
            caught = (code, _native_driver_slot(exc, 0))
            exc.__dict__["_consolidated_getter_error"] = caught
            if partial is not None:
                exc.__dict__["partial_identifiers"] = tuple(partial())
            if request_records is not None:
                exc.__dict__["request_id_records"] = tuple(request_records())
            raise
    finally:
        # All eight worker FuncInfo scopes switch to state-1 before Disconnect.
        runtime.release("disconnect")
        for handle in runtime.owned_identifiers("stop_filter"):
            if runtime.owns_resource("stop_filter", identifier=handle):
                runtime.forget_invalidated_resource("stop_filter", identifier=handle)
        if error_snapshot is not None and (caught is not None or completed):
            error_snapshot(*(caught or (0, 0)))
        if completion_state is not None and (caught is not None or completed):
            completion_state.getter_completion_callback = (
                "error" if caught is not None else "cancel" if cancelled else "normal"
            )
            if request_records is not None:
                completion_state.request_id_records = tuple(request_records())


# Exact initialized CPU data: CRT38d0/3b60/4690, independently decoded in review55.
# The packed firmware word is expected low byte plus native shrink byte<<8.
_FIRMWARE_CPU_WORDS = (
    (
        ("0", 1),
        ("1", 1),
        ("2", 1),
        ("3", 1),
        ("4", 5),
        ("5", 5),
        ("6", 5),
        ("7", 6),
        ("8", 7),
        ("9", 3),
        ("10", 3),
        ("11", 259),
        ("12", 258),
        ("13", 257),
        ("14", 260),
        ("15", 261),
        ("16", 262),
        ("21", 262),
        ("22", 382),
        ("28", 273),
        ("29", 276),
        ("20", 321),
        ("26", 322),
        ("40", 257),
        ("19", 265),
        ("70", 281),
        ("71", 282),
        ("73", 277),
        ("66", 287),
        ("85", 323),
        ("86", 279),
        ("87", 285),
        ("88", 284),
        ("89", 286),
        ("98", 291),
        ("92", 290),
        ("107", 257),
        ("124", 324),
        ("127", 293),
        ("136", 292),
        ("216", 297),
    ),
    (
        ("24", 257),
        ("27", 0),
        ("25", 257),
        ("30", 258),
        ("38", 259),
        ("39", 260),
        ("35", 262),
        ("36", 263),
        ("37", 265),
        ("42", 266),
        ("43", 267),
        ("23", 257),
        ("52", 269),
        ("53", 268),
        ("51", 272),
        ("55", 270),
        ("67", 273),
        ("68", 271),
        ("69", 264),
        ("83", 275),
        ("101", 281),
        ("102", 274),
        ("116", 278),
        ("118", 284),
        ("119", 280),
        ("120", 285),
        ("121", 276),
        ("122", 277),
        ("125", 286),
        ("131", 290),
        ("125", 286),
        ("137", 291),
        ("132", 288),
    ),
)
_BLOCK_CPU_RANGES = {
    "66": ((17, 22), (23, 96)),
    "19": ((1, 8), (9, 16), (17, 24), (25, 28), (29, 30)),
    "73": ((1, 8), (9, 16), (17, 24), (25, 28), (29, 30)),
    "85": ((1, 64), (129, 2560)),
    "98": ((1, 20), (25, 31)),
    "92": ((1, 8), (9, 61)),
    "107": ((1, 4), (7, 12)),
    "124": ((1, 64), (129, 2048), (9217, 10240)),
    "": ((1, 1), (2, 0)),
}

_OLD_ECB_BLOCK_CPU_RANGES = {
    "67": ((1, 16), (17, 120)),
    "68": ((8, 15), (16, 32)),
    "69": ((179, 194), (195, 242)),
    "83": ((29, 74), (75, 120)),
    "52": ((211, 226), (227, 242)),
    "102": ((1, 16), (17, 128)),
    "118": ((1, 2), (3, 12)),
    "121": ((1, 12), (13, 96)),
    "122": ((1, 12), (13, 128)),
    "125": ((1, 16), (17, 64)),
    "131": ((1, 8), (9, 16)),
    "137": ((1, 1), (2, 112)),
    "": ((1, 10), (11, 0)),
}


def consolidated_firmware_matches(
    cpu_type: str, firmware: int, shrink: bool, *, wide: bool = False
) -> bool:
    """bee0 compares exact CPU text and shrink byte before firmware bits."""
    if (
        type(cpu_type) is not str
        or not 0 < len(cpu_type) <= 64
        or "\0" in cpu_type
        or type(firmware) is not int
        or not 0 <= firmware <= 255
        or type(shrink) is not bool
        or type(wide) is not bool
    ):
        raise ValueError("Literal native CPU, firmware byte and shrink flags required")
    for cpu, packed in _FIRMWARE_CPU_WORDS[wide]:
        if cpu == cpu_type:
            actual = firmware & 0x7F if shrink else (firmware >> 4) & 7
            return packed >> 8 == shrink and packed & 255 == actual
    return False


def consolidated_block_ranges(
    cpu_type: str, block_count: int, *, old_spec_ecb: bool = False
) -> tuple[tuple[int, int], ...]:
    """c150 selects exact initialized ranges, replacing only final zero end."""
    if (
        type(cpu_type) is not str
        or not 0 < len(cpu_type) <= 64
        or "\0" in cpu_type
        or type(block_count) is not int
        or not 0 <= block_count <= 0xFFFFFFFF
        or type(old_spec_ecb) is not bool
    ):
        raise ValueError("Literal native CPU and bounded block count required")
    table = _OLD_ECB_BLOCK_CPU_RANGES if old_spec_ecb else _BLOCK_CPU_RANGES
    ranges = table.get(cpu_type, table[""])
    return ranges[:-1] + ((ranges[-1][0], ranges[-1][1] or block_count),)


def consolidated_archive_password(
    image: bytes, parameters, kind_of_ecu: str, cpu_type: str, contact_type: str
) -> int:
    """05150 reads image DWORD at actual global Parameter.ini PasswordAddress."""
    from scripts.programming_2026_common import (
        NativeBytes2026,
        NativeGeneralParameters2026,
    )

    if (
        type(image) is not bytes
        or not 0 < len(image) <= 64 * 1024 * 1024
        or not isinstance(parameters, NativeGeneralParameters2026)
    ):
        raise TypeError(
            "Actual materialized archive and global Parameter.ini binding required"
        )
    address_text = parameters.string_with_keys(
        kind_of_ecu, cpu_type, contact_type, "PasswordAddress"
    )
    byte_order = parameters.long_with_keys(
        kind_of_ecu, cpu_type, contact_type, "ByteOrder"
    )
    if len(address_text) >= 260:
        raise ValueError("Native PasswordAddress output buffer exceeded")
    address = NativeBytes2026.from_hex(address_text).unsigned()
    if address + 4 > len(image):
        raise ValueError("Native password DWORD lies outside imported image")
    # 0522c tests the full signed long, unlike CUW33c0's unsigned-short flag.
    return int.from_bytes(
        image[address : address + 4], "little" if byte_order == 0 else "big"
    )


def consolidated_progress_percent(count: int, flash_size: int) -> int:
    """9370/26c30 lowDWORD of native double→int64, including zero FlashSize."""
    if (
        type(count) is not int
        or not 0 <= count <= 0xFFFFFFFF
        or type(flash_size) is not int
        or not 0 <= flash_size <= 64 * 1024 * 1024
    ):
        raise ValueError("Unsigned native count and bounded actual flash size required")
    # Masked native DIVSD yields infinity/NaN for zero;26c30 returns INT64_MIN,
    # whose lowDWORD stored into the progress array is zero on both CRT paths.
    return int(count / (flash_size * 2) * 100) & 0xFFFFFFFF if flash_size else 0


def consolidated_location_addresses(location_id: bytes) -> tuple[bytes, bytes, bytes]:
    """9530 and5000: LocationID encodes response/request and final request IDs."""
    if type(location_id) is not bytes or len(location_id) != 8:
        raise ValueError("Native eight-byte LocationID required")
    return (
        b"\0\0" + location_id[2:4],
        b"\0\0" + location_id[:2],
        b"\0\0" + location_id[6:8],
    )


def consolidated_block_sizes(cpu_type: str, memory) -> tuple[int, ...]:
    """bbb0 legacy size-vector rules, independently of newer FlashUtils defaults.

    CPU7 deliberately ignores reported size; CPU19/73 drop partial4KiB tails.
    The source's zero tail on the special64KiB split is retained. Host policy
    bounds the memory span and rejects a negative special-case remainder.
    """
    from scripts.programming_2026_common import NativeMemoryInfo

    if (
        type(cpu_type) is not str
        or not 0 < len(cpu_type) <= 64
        or "\0" in cpu_type
        or not isinstance(memory, NativeMemoryInfo)
        or any(
            type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (memory.start_address, memory.end_address)
        )
        or type(memory.block_size_kib) is not int
        or not 0 <= memory.block_size_kib <= 255
    ):
        raise ValueError("Literal CPU and native memory-info fields required")
    capacity = memory.end_address - memory.start_address + 1
    if not 0 < capacity <= 64 * 1024 * 1024:
        raise ValueError("Bounded positive native memory span required")
    if cpu_type in ("4", "5", "6"):
        if capacity < 0x10000:
            raise ValueError(
                "Native special CPU range is smaller than its64KiB first block"
            )
        remainder = capacity - 0x10000
        return (
            (0x10000, remainder)
            if remainder <= 0x70000
            else (0x10000, 0x70000, capacity - 0x80000)
        )
    if cpu_type == "7":
        return (0x4000, 0x58000)
    if cpu_type in ("19", "73"):
        return (0x1000,) * (capacity // 0x1000)
    size = 0x40000 if cpu_type == "216" else memory.block_size_kib << 10
    if not size:
        raise ValueError("Native general CPU block size cannot be zero")
    count, remainder = divmod(capacity, size)
    return (size,) * count + ((remainder,) if remainder else ())


def consolidated_electric_block_sizes(cpu_type: str) -> tuple[int, ...]:
    """16300/47e0 exact initialized four-block CPU117 geometry, not reported sizes."""
    if type(cpu_type) is not str or not 0 < len(cpu_type) <= 64 or "\0" in cpu_type:
        raise ValueError("Literal bounded native CPU text required")
    if cpu_type != "117":
        raise ConsolidatedError(9999, "electric_block_sizes")
    return (8192, 122880, 122880, 8192)


def consolidated_sil_cpu_mode(cpu_type: str) -> tuple[bool, bool, str | None]:
    """ed70/eec0/ed10 and CRT3820: literal probe set, preferred format and CPU pair."""
    if type(cpu_type) is not str or not 0 < len(cpu_type) <= 64 or "\0" in cpu_type:
        raise ValueError("Literal bounded native CPU text required")
    preferred = next(
        (bool(word >> 8) for cpu, word in _FIRMWARE_CPU_WORDS[0] if cpu == cpu_type),
        False,
    )
    alternate = {
        "4": "12",
        "5": "13",
        "6": "14",
        "12": "4",
        "13": "5",
        "14": "6",
        "15": "16",
        "16": "15",
        "87": "88",
    }.get(cpu_type)
    return cpu_type in ("4", "5", "6", "12", "13", "14"), preferred, alternate


def _identity(identity: NativeModuleIdentity) -> None:
    if (
        not isinstance(identity, NativeModuleIdentity)
        or identity != identify_native_module(SOURCE_SHA256, MODULE)
        or identity.cuw_build != "2026"
    ):
        raise ValueError("Exact consolidated CUW2026 source identity required")


@dataclass(frozen=True)
class Branch:
    family: str
    writing: bool
    requires_ecb_fallback: bool = False

    @property
    def constructor_rva(self) -> int:
        return WORKERS[self.family][0]

    @property
    def worker_rva(self) -> int:
        return WORKERS[self.family][1]


def select_branch(
    identity: NativeModuleIdentity,
    contact_type: str,
    kind_of_ecu: str,
    cpu_types: tuple[str, ...],
    *,
    writing: bool = False,
    cpu_index: int = 0,
    old_spec_ecb: bool = False,
) -> Branch:
    """dcf0/c670 exact comparison order, without implicit fallback families.

    writing is context+978. old_spec_ecb is controller+64, set by the ECB ROM
    getter callback; it must come from that observed controller state. The first
    CPU selects EMPS; selected CPU chooses the SIL M16C writer before EMPS.
    """
    _identity(identity)
    if (
        any(
            type(value) is not str or not 0 < len(value) <= 64 or "\0" in value
            for value in (contact_type, kind_of_ecu)
        )
        or type(cpu_types) is not tuple
        or not 1 <= len(cpu_types) <= 256
        or any(
            type(value) is not str or len(value) > 64 or "\0" in value
            for value in cpu_types
        )
        or type(cpu_index) is not int
        or not 0 <= cpu_index < len(cpu_types)
        or type(writing) is not bool
        or type(old_spec_ecb) is not bool
    ):
        raise ValueError("Bounded literal native controller metadata required")
    kind, first = kind_of_ecu, cpu_types[0]
    emps = first in ("57", "58", "59", "60")
    family = None
    ecb_fallback = False
    if writing:
        if contact_type == "SIL":
            if kind not in ("8", "11"):
                if cpu_types[cpu_index] == "17":
                    family = "sil_m16c_write"
                elif emps:
                    family = "sil_emps_write"
                elif kind in ("37", "63"):
                    family = "sil_occupant_write"
                else:
                    family = "sil_write"
        elif contact_type == "CAN":
            if kind == "13" and first == "56":
                family = "can_emps_write"
            elif kind in ("5", "6"):
                family = "can_fc_write"
            elif kind == "4":
                family = "can_old_ecb_write" if old_spec_ecb else "can_chassis_write"
            elif kind == "7" and first == "27":
                family = "can_epb_write"
            elif kind == "45":
                family = "can_electric_write"
    elif contact_type == "SIL":
        if kind != "11":
            if emps:
                family = "sil_emps_id"
            elif kind == "37":
                family = "sil_occupant_id"
            elif kind not in ("30", "8"):
                family = "sil_vpns_id" if kind == "63" else "sil_cid"
    elif kind != "8" and contact_type == "CAN":
        if kind == "13" and first == "56":
            family = "can_emps_id"
        elif kind in ("4", "5", "13", "7", "51", "6"):
            family = "can_software_info_id"
            ecb_fallback = kind == "4"
        elif kind == "45":
            family = "can_electric_id"
    if family is None:
        raise ConsolidatedError(9999, "select_writer" if writing else "select_getter")
    return Branch(family, writing, ecb_fallback)


@dataclass(frozen=True)
class CANIdentifierContext:
    """Source-table targets for the audited CAN getters, without target overrides."""

    identity: NativeModuleIdentity
    branch: Branch
    request: bytes
    response: bytes

    def __post_init__(self):
        _identity(self.identity)
        if (
            not isinstance(self.branch, Branch)
            or self.branch.family not in ("can_emps_id", "can_electric_id")
            or self.branch.writing
            or self.branch.requires_ecb_fallback
            or any(
                type(value) is not bytes or len(value) != 2
                for value in (self.request, self.response)
            )
            or (self.request, self.response)
            != {
                "can_emps_id": (b"\x07\xa1", b"\x07\xa9"),
                "can_electric_id": (b"\x07\xc1", b"\x07\xc9"),
            }.get(self.branch.family)
        ):
            raise ValueError(
                "Audited CAN getter and exact two-byte native targets required"
            )


def bind_native_context(
    container, identity: NativeModuleIdentity, *, node: int = 1
) -> CANIdentifierContext | SILIdentifierContext | SoftwareIdentifierContext:
    """Bind actual2026 imported metadata to source-table09ff0 CAN getter targets.

    There is no catalog-supplied DLL or transport-address substitution in this
    consolidated source. Each audited getter uses its first fixed native node.
    """
    from scripts.calibration_2026 import (
        native2026_cpu_type,
        native2026_metadata,
        native2026_selection_metadata,
    )

    _identity(identity)
    metadata = native2026_metadata(container, node=node, cpu_index=0)
    selected = native2026_selection_metadata(container, node=node, cpu_index=0)
    cpus = (native2026_cpu_type(metadata, 0),)
    branch = select_branch(
        identity, selected["contact_type"], selected["kind_of_ecu"], cpus
    )
    if branch.family == "can_software_info_id":
        return SoftwareIdentifierContext(identity, selected["kind_of_ecu"], cpus[0])
    if branch.family in ("sil_emps_id", "sil_occupant_id", "sil_vpns_id", "sil_cid"):
        return SILIdentifierContext(identity, branch, selected["kind_of_ecu"])
    if branch.family == "can_emps_id":
        request, response = b"\x07\xa1", b"\x07\xa9"
    elif branch.family == "can_electric_id":
        request, response = b"\x07\xc1", b"\x07\xc9"
    else:
        raise ValueError(
            "Selected consolidated worker has no audited operation adapter"
        )
    return CANIdentifierContext(identity, branch, request, response)


def _void(runtime: NativeRuntime2026, operation: str, **values) -> None:
    if runtime.call(operation, **values) is not None:
        raise ValueError("Native void primitive must return None")


def _native_cancel_requested(runtime: NativeRuntime2026) -> bool:
    """Optional injected UI observation; host interruption stays a separate fault."""
    runtime.check()
    if runtime.native_cancelled is None:
        return False
    value = runtime.native_cancelled()
    runtime.check()
    if type(value) is not bool:
        raise ValueError("Native cancellation observation must be Boolean")
    return value


class ConsolidatedCanDiag2026(CanDiag2026):
    """9680 nullable bool functor returns retained output and skips restoration.

    Host faults and exceptions restore timeout via native9988; a true native
    cancellation return follows the separate native early-return continuation.
    """

    def call(
        self,
        request_address,
        response_address,
        payload,
        expected,
        *,
        minimum=0,
        error_code=3,
        delay_ms=0,
        check_native_cancel=False,
    ):
        self._addresses(request_address, response_address)
        if (
            type(payload) is not bytes
            or not 0 < len(payload) <= 4128 - len(request_address)
            or type(expected) is not bytes
            or len(expected) > 4128 - len(response_address)
            or any(
                type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                for value in (minimum, error_code, delay_ms)
            )
            or minimum > 4128 - len(response_address)
            or type(check_native_cancel) is not bool
        ):
            raise ValueError("Bounded native consolidated CAN exchange required")
        rt = self.runtime
        prior = rt.call("get_timeout")
        if type(prior) is not int or not 0 <= prior <= 0xFFFFFFFF:
            raise ValueError("Native unsigned receive timeout required")
        busy, retained = 0, b""
        native_return = False
        flags = 0x80 if len(request_address) == 5 else 0
        try:
            while True:
                self.write(request_address + payload, flags)
                _void(rt, "wait", milliseconds=delay_ms)
                pending = 0
                while True:
                    if check_native_cancel and _native_cancel_requested(rt):
                        native_return = True
                        return retained
                    reply = rt.call(
                        "read_specified_can_message",
                        address=response_address,
                        count=1,
                        frame=2,
                    )
                    if (
                        type(reply) is not bytes
                        or not len(response_address) <= len(reply) <= 4128
                        or not reply.startswith(response_address)
                    ):
                        raise ValueError("Bounded matching native CAN Data required")
                    retained = reply[len(response_address) :]
                    negative = len(retained) >= 3 and retained[:2] == bytes(
                        (0x7F, payload[0])
                    )
                    if negative and retained[2] == 0x78:
                        pending += 1
                        busy = 0
                        if pending > 149:
                            self.write(request_address + b"\x3e", flags)
                            raise ConsolidatedError(error_code, "can_pending")
                        if prior < 5000:
                            _void(rt, "set_timeout", milliseconds=5000)
                        continue
                    break
                if negative and retained[2] == 0x21:
                    busy += 1
                    if busy > 255:
                        raise ConsolidatedError(error_code, "can_busy")
                else:
                    busy = 0
                _void(rt, "set_timeout", milliseconds=prior)
                if not busy:
                    break
            if len(retained) < minimum or not retained.startswith(expected):
                raise ConsolidatedError(error_code, "can_response")
            return retained
        finally:
            if not native_return:
                _void(rt, "set_timeout", cleanup=True, milliseconds=prior)


def get_can_identifier(
    context: CANIdentifierContext,
    runtime: NativeRuntime2026,
    *,
    state: ConsolidatedControllerState | None = None,
    error_snapshot=None,
) -> str | None:
    """Native17c80/19c60 and17f40/19f30 over actual CAN primitives.

    These getters use ISO15765 protocol6, two leading zero bytes+address, source-specific
    request/response validation and real filter ownership. They never execute a
    whole-business-operation callback or load an OEM binary.
    """
    if not isinstance(context, CANIdentifierContext) or not isinstance(
        runtime, NativeRuntime2026
    ):
        raise TypeError("Audited context and bounded primitive runtime required")
    context.__post_init__()
    rt = runtime
    request, response = b"\0\0" + context.request, b"\0\0" + context.response
    diag = ConsolidatedCanDiag2026(rt)
    if context.branch.family == "can_emps_id":
        _void(rt, "wait", milliseconds=2000)
    observed, request_records = [], []
    with _getter_connection(
        rt,
        6,
        partial=lambda: observed,
        request_records=lambda: request_records,
        error_snapshot=error_snapshot,
        completion_state=state,
    ):
        _void(rt, "set_timeout", milliseconds=1000)
        handle = diag.start_filter(request, response)
        try:
            if context.branch.family == "can_electric_id":
                reply = diag.call(
                    request,
                    response,
                    b"\x1a\x81",
                    b"\x5a",
                    minimum=6,
                    error_code=3,
                    check_native_cancel=True,
                )
                if _native_cancel_requested(rt):
                    return None
                raw = reply[1:6]
            else:
                if _native_cancel_requested(rt):
                    return None
                diag.write(request + b"\xaa\x1e")
                if _native_cancel_requested(rt):
                    return None
                pending = 0
                reply = b""
                while True:
                    if _native_cancel_requested(rt):
                        break
                    reply = rt.call(
                        "read_specified_can_message",
                        address=response,
                        count=1,
                        frame=2,
                    )
                    if (
                        type(reply) is not bytes
                        or not 4 <= len(reply) <= 4128
                        or not reply.startswith(response)
                    ):
                        raise ValueError("Malformed native CAN response bytes")
                    reply = reply[4:]
                    if len(reply) > 2 and reply[:3] == b"\x7f\xaa\x78":
                        # Native19f30 checks the pre-increment count: 150th pending aborts.
                        pending += 1
                        if pending > 149:
                            diag.write(request + b"\x3e\x02")
                            raise ConsolidatedError(3, "emps_pending")
                        _void(rt, "set_timeout", milliseconds=5000)
                        continue
                    break
                _void(rt, "set_timeout", milliseconds=1000)
                if len(reply) != 10 or reply[:2] != b"\xea\x1e" or reply[2] == 0:
                    raise ConsolidatedError(3, "emps_identifier")
                raw = reply[2:10]
            # Native strncpy/c-string storage terminates at the first NUL.
            observed.append(raw.split(b"\0", 1)[0].decode("latin-1"))
        finally:
            rt.release("stop_filter", identifier=handle)
        request_records.append(context.request.hex().upper())
        return observed[-1]


def get_ecb_rom_identifiers(
    identity: NativeModuleIdentity,
    runtime: NativeRuntime2026,
    state: ConsolidatedControllerState | None = None,
    *,
    error_snapshot=None,
) -> tuple[str, ...]:
    """c570 fallback151d0/154a0: two A4 ROM reads, without guessing CID fallback.

    Controller+64 may be set only after this worker's actual success callback.
    Its returned ROMs are observations for that controller, never image metadata.
    """
    _identity(identity)
    if not isinstance(runtime, NativeRuntime2026):
        raise TypeError("Bounded native primitive runtime required")
    rt = runtime
    if state is not None:
        if not isinstance(state, ConsolidatedControllerState):
            raise TypeError("Native consolidated controller state required")
        state.__post_init__()
    diag = ConsolidatedCanDiag2026(rt)
    request, response = b"\0\0\x07\xb0", b"\0\0\x07\xb8"
    identifiers, request_records = [], []
    with _getter_connection(
        rt,
        6,
        partial=lambda: identifiers,
        error_snapshot=error_snapshot,
        completion_state=state,
        request_records=lambda: request_records,
    ):
        _void(rt, "set_timeout", milliseconds=1000)
        _void(rt, "wait", milliseconds=2000)
        handle = diag.start_filter(request, response)
        try:
            selectors = () if _native_cancel_requested(rt) else (0, 2)
            for selector in selectors:
                prefix = bytes((0xE4, selector))
                reply = diag.call(
                    request,
                    response,
                    bytes((0xA4, selector)) + b"\x08\0\0\x48\x3c",
                    prefix,
                    minimum=15,
                    error_code=3,
                    check_native_cancel=True,
                )
                raw = reply[7:15]
                if not raw or raw[0] == 0:
                    raise ConsolidatedError(3, "ecb_rom_identifier")
                identifiers.append(raw.split(b"\0", 1)[0].decode("latin-1"))
        finally:
            rt.release("stop_filter", identifier=handle)
        request_records.extend(["07B0"] * len(identifiers))
    if state is not None and state.getter_completion_callback == "normal":
        state.old_spec_ecb = True
        state.native_context_9e8 = True
    return tuple(identifiers)


def _consolidated_indication(runtime: NativeRuntime2026, rx_status: int) -> int:
    """CJ indication depends on retained device padding only for lowstatus16."""
    from scripts.j2534_2026 import j2534_indication

    padding = False
    if rx_status & 31 == 16:
        padding = runtime.call("get_can_frame_padding")
        if type(padding) is not bool:
            raise ValueError("Actual native device CAN padding observation required")
    return j2534_indication(rx_status, padding)


class SilDiag2026:
    """Consolidated10410/10070 SIL exchange using full native message bytes."""

    def __init__(self, runtime: NativeRuntime2026):
        if not isinstance(runtime, NativeRuntime2026):
            raise TypeError("Bounded primitive runtime required")
        self.runtime = runtime

    @staticmethod
    def packet(data: bytes) -> bytes:
        if type(data) is not bytes or not 4 <= len(data) <= 4127:
            raise ValueError("Bounded full SIL header and payload required")
        return data + bytes((sum(data) & 255,))

    def write(self, data: bytes) -> None:
        if type(data) is not bytes or not 4 <= len(data) <= 4128:
            raise ValueError("Bounded native SIL message required")
        count = self.runtime.call(
            "write_messages", protocol=3, data=data, tx_flags=0, count=1
        )
        if type(count) is not int or count != 1:
            raise ValueError("Native SIL primitive must write exactly one message")

    def read(self, *, wrap: bool = False) -> bytes:
        value = self.runtime.call(
            "read_messages" if wrap else "read_after_indication", count=1
        )
        if type(value) is not bytes or not 0 <= len(value) <= 4128:
            raise ValueError("Bounded full native SIL message required")
        return value

    def fast_init(
        self,
        target: int,
        *,
        mobd: bool = True,
        emps: bool = False,
        check_native_cancel: bool = False,
    ) -> None:
        from scripts.j2534_2026 import NativeMessage

        if (
            type(target) is not int
            or not 0 <= target <= 255
            or type(mobd) is not bool
            or type(emps) is not bool
            or type(check_native_cancel) is not bool
        ):
            raise ValueError("Native SIL target byte and communication mode required")
        rt = self.runtime
        for parameters in (
            ((1, 9600 if mobd or emps else 10400),),
            ((0x14, 35 if mobd or emps else 25),),
            ((0x15, 50),),
        ):
            _void(rt, "control_io", ioctl=2, parameters=parameters)
            if check_native_cancel and _native_cancel_requested(rt):
                return
        result = rt.call(
            "fast_init", data=self.packet(bytes((0x81, target, 0xF1, 0x81))), tx_flags=0
        )
        if not isinstance(result, NativeMessage) or result.protocol_id != 3:
            raise ValueError("FAST_INIT primitive must return raw native SIL message")
        indication = _consolidated_indication(rt, result.rx_status)
        if check_native_cancel and _native_cancel_requested(rt):
            return
        if not emps:
            _void(rt, "wait", milliseconds=100)
            if check_native_cancel and _native_cancel_requested(rt):
                return
        if indication != 3:
            self.read(wrap=True)

    def exchange(
        self,
        request: bytes,
        *,
        minimum: int = 0,
        header: bytes = b"",
        payload: bytes = b"",
        delay_ms: int = 100,
        send: bool = True,
        error_code: int = 3,
        check_native_cancel: bool = False,
    ) -> bytes:
        if (
            type(request) is not bytes
            or not 4 <= len(request) <= 4128
            or any(
                type(value) is not bytes or len(value) > 4128
                for value in (header, payload)
            )
            or type(minimum) is not int
            or not 0 <= minimum <= 4128
            or type(delay_ms) is not int
            or not 0 <= delay_ms <= 0xFFFFFFFF
            or type(send) is not bool
            or type(error_code) is not int
            or not 0 <= error_code <= 0xFFFFFFFF
            or type(check_native_cancel) is not bool
        ):
            raise ValueError("Bounded literal SIL exchange contract required")
        rt = self.runtime
        prior = rt.call("get_timeout")
        if type(prior) is not int or not 0 <= prior <= 0xFFFFFFFF:
            raise ValueError("Unsigned native receive timeout required")
        busy = 0
        native_return, retained = False, b""
        try:
            while True:
                if send:
                    self.write(request)
                    _void(rt, "wait", milliseconds=delay_ms)
                pending = 0
                while True:
                    if check_native_cancel and _native_cancel_requested(rt):
                        native_return = True
                        return retained
                    reply = self.read()
                    retained = reply
                    negative = len(reply) >= 6 and reply[3:5] == bytes(
                        (0x7F, request[3])
                    )
                    if negative and reply[5] == 0x78:
                        pending += 1
                        busy = 0
                        if pending > 149:
                            self.write(
                                self.packet(bytes((0x81, request[1], request[2], 0x82)))
                            )
                            raise ConsolidatedError(error_code, "sil_pending")
                        if prior < 5000:
                            _void(rt, "set_timeout", milliseconds=5000)
                        continue
                    break
                if send and negative and reply[5] == 0x21:
                    busy += 1
                    if busy > 255:
                        raise ConsolidatedError(error_code, "sil_busy")
                    _void(rt, "set_timeout", milliseconds=prior)
                    continue
                if (
                    len(reply) < minimum
                    or not reply.startswith(header)
                    or not reply[3:].startswith(payload)
                ):
                    raise ConsolidatedError(error_code, "sil_response")
                return reply
        finally:
            if not native_return:
                _void(rt, "set_timeout", cleanup=True, milliseconds=prior)


class ConsolidatedCAN2026:
    """Consolidated legacy base6970/65e0/7490/7e80/76c0/7850.

    These operations have fixed wide ranges and10ms polling. Standalone2026
    CommonFlash supplies only source-equivalent ACK/status primitives; its
    parameter-selected waits and operation exception mappings are not substituted.
    """

    def __init__(self, runtime: NativeRuntime2026):
        from scripts.programming_2026_legacy import CommonFlash2026

        if not isinstance(runtime, NativeRuntime2026):
            raise TypeError("Native consolidated primitive runtime required")
        self.runtime, self.diag = runtime, CanDiag2026(runtime)
        self.common = CommonFlash2026(runtime)
        # bae0 initializes this byte;7950 sets it after the first successful ACK.
        self.native_context_6c = False

    @staticmethod
    def _addresses(request: bytes, response: bytes):
        if any(
            type(value) is not bytes or len(value) != 4 for value in (request, response)
        ):
            raise ValueError(
                "Consolidated common operation requires native four-byte CAN addresses"
            )

    def _ack(self, response: bytes, code: int):
        if not self.common.receive_ack(response):
            raise ConsolidatedError(code, "common_ack")

    def epb_security_access(
        self, request: bytes, response: bytes, materials: tuple[bytes, ...]
    ) -> None:
        """1a8d0 uses extended5-byte address,270100 and source minimumDataSize10."""
        from scripts.programming_2026_common import seed_key_four_round

        if (
            any(
                type(value) is not bytes or len(value) != 5
                for value in (request, response)
            )
            or type(materials) is not tuple
            or len(materials) != 4
            or any(type(value) is not bytes or len(value) != 2 for value in materials)
        ):
            raise ValueError(
                "Native extended EPB addresses and four conversion materials required"
            )
        diag = ConsolidatedCanDiag2026(self.runtime)
        reply = diag.call(
            request,
            response,
            bytes.fromhex("270100"),
            bytes.fromhex("6701"),
            minimum=5,
            error_code=16,
        )
        # Local PASSTHRU_MSG is zeroed; min10 permits onlythree seed bytes after5+2.
        seed = reply[2:6].ljust(4, b"\0")
        key = seed_key_four_round(seed, materials)
        _void(self.runtime, "wait", milliseconds=100)
        diag.call(
            request,
            response,
            bytes.fromhex("2702") + key,
            bytes.fromhex("6702"),
            minimum=2,
            error_code=17,
        )

    def electric_security_access(self, request: bytes, response: bytes) -> None:
        """15ed0 uses the one-byte seed minusone modulo256; no seed-key table."""
        self._addresses(request, response)
        diag = ConsolidatedCanDiag2026(self.runtime)
        reply = diag.call(
            request, response, b"\x27\x01", b"\x67\x01", minimum=3, error_code=16
        )
        _void(self.runtime, "wait", milliseconds=100)
        diag.call(
            request,
            response,
            b"\x27\x02" + bytes(((reply[2] - 1) & 255,)),
            b"\x67\x02",
            minimum=2,
            error_code=17,
        )

    def old_ecb_security_access(
        self,
        request: bytes,
        response: bytes,
        selector: int,
        materials: tuple[bytes, ...],
        *,
        key_delay_ms: int = 0,
    ):
        """1db40 requests2701/selector, exact four-round key and no100ms key delay."""
        from scripts.programming_2026_common import seed_key_four_round

        self._addresses(request, response)
        if (
            type(selector) is not int
            or selector not in (0, 2)
            or type(materials) is not tuple
            or len(materials) != 4
            or any(type(value) is not bytes or len(value) != 2 for value in materials)
            or type(key_delay_ms) is not int
            or not 0 <= key_delay_ms <= 0xFFFFFFFF
        ):
            raise ValueError(
                "Native old ECB selector0/2 and authorized conversion material required"
            )
        diag = ConsolidatedCanDiag2026(self.runtime)
        reply = diag.call(
            request,
            response,
            bytes((0x27, 1, selector)),
            b"\x67\x01",
            minimum=6,
            error_code=16,
        )
        key = seed_key_four_round(reply[2:6], materials)
        if key_delay_ms:
            # 13c20 chassis adds100ms before key;1db40 old ECB has no key delay.
            _void(self.runtime, "wait", milliseconds=key_delay_ms)
        diag.call(
            request, response, b"\x27\x02" + key, b"\x67\x02", minimum=2, error_code=17
        )

    def old_ecb_dispose_error(self, request: bytes, response: bytes):
        """1ea00 sends05/ACK then65/ACK, errors native20; not generic reset."""
        from scripts.programming_2026_legacy import _mapped_transport

        self._addresses(request, response)
        try:
            self.diag.write(request + b"\x05")
            self._ack(response, 20)
            self.diag.write(request + b"\x65")
            self._ack(response, 20)
        except _NATIVE_DRIVER_ERRORS as exc:
            if not _is_driver_error(exc):
                raise
            raise _mapped_transport(exc, 20) from exc

    def fc_security_access(
        self, request: bytes, response: bytes, materials: tuple[bytes, ...]
    ) -> None:
        """1c7c0→62f0/6230: seed request, four exact rounds,100ms,key request."""
        from scripts.programming_2026_common import seed_key_four_round

        self._addresses(request, response)
        if (
            type(materials) is not tuple
            or len(materials) != 4
            or any(type(value) is not bytes or len(value) != 2 for value in materials)
        ):
            raise ValueError(
                "Four explicit authorized two-byte conversion materials required"
            )
        diag = ConsolidatedCanDiag2026(self.runtime)
        seed_reply = diag.call(
            request, response, b"\x27\x01", b"\x67\x01", minimum=6, error_code=16
        )
        key = seed_key_four_round(seed_reply[2:6], materials)
        _void(self.runtime, "wait", milliseconds=100)
        diag.call(
            request, response, b"\x27\x02" + key, b"\x67\x02", minimum=2, error_code=17
        )

    def check_id(
        self,
        request: bytes,
        response: bytes,
        location_id: bytes,
        password: int,
        *,
        initial_timeout: int = 0,
        swap_endian: bool = False,
        inter_message_wait_ms: int | None = None,
    ) -> None:
        from scripts.programming_2026_legacy import (
            _NATIVE_DRIVER_ERRORS,
            _is_driver_error,
            _mapped_transport,
        )
        from scripts.programming_vendor import common_check_id_frames

        self._addresses(request, response)
        if type(initial_timeout) is not int or not 0 <= initial_timeout <= 0xFFFFFFFF:
            raise ValueError("Unsigned native initial timeout required")
        if inter_message_wait_ms is not None and (
            type(inter_message_wait_ms) is not int
            or not 0 <= inter_message_wait_ms <= 0xFFFFFFFF
        ):
            raise ValueError("Explicit native separate-write delay required")
        # 6970 uses one WriteMsgs(count5), unlike standalone1510's separate writes.
        parts = common_check_id_frames(location_id, password, swap_endian=swap_endian)
        try:
            if inter_message_wait_ms is None:
                result = self.runtime.call(
                    "write_messages",
                    protocol=6,
                    messages=tuple(request + part for part in parts),
                    tx_flags=0,
                    count=5,
                )
                if type(result) is not int or result != 5:
                    raise ValueError(
                        "Native common CheckID requires five accepted messages"
                    )
            else:
                # 6e70 shares6970's bytes, but writes separately and waits four times.
                for index, part in enumerate(parts):
                    self.diag.write(request + part)
                    if index != 4:
                        _void(self.runtime, "wait", milliseconds=inter_message_wait_ms)
            self._ack(response, 7)
            if initial_timeout:
                _void(self.runtime, "set_timeout", milliseconds=initial_timeout)
            reply = self.runtime.call(
                "read_specified_can_message", address=response, count=1, frame=1
            )
            if type(reply) is not bytes or not 4 <= len(reply) <= 4128:
                raise ValueError("Native common CheckID requires bounded full CAN Data")
            self.diag.write(request + b"\x3c")
        except _NATIVE_DRIVER_ERRORS as exc:
            if not _is_driver_error(exc):
                raise
            raise _mapped_transport(exc, 7) from exc

    def block(
        self, operation: str, request: bytes, response: bytes, first: int, last: int
    ) -> bool:
        from scripts.programming_2026_legacy import (
            _NATIVE_DRIVER_ERRORS,
            _is_driver_error,
            _mapped_transport,
        )

        self._addresses(request, response)
        if (
            operation not in ("blank", "erase", "inverify")
            or type(first) is not int
            or type(last) is not int
            or not 1 <= first <= last <= 65536
        ):
            raise ValueError("Native consolidated wide block operation/range required")
        opcode, code = {
            "blank": (0x36, 11),
            "erase": (0x26, 12),
            "inverify": (0x48, 14),
        }[operation]
        try:
            self.diag.write(
                request
                + bytes((opcode,))
                + (first - 1).to_bytes(2, "big")
                + (last - 1).to_bytes(2, "big")
            )
            self._ack(response, code)
            for _ in range(4096):
                _void(self.runtime, "wait", milliseconds=10)
                status = self.common.get_status(request, response)
                pending = (
                    status == 0x10
                    if operation == "blank"
                    else status == 0x40
                    if operation == "inverify"
                    else status != 0 and status & 15 == 0
                )
                if pending:
                    continue
                if operation == "blank":
                    return status == 0
                if status:
                    raise ConsolidatedError(code, operation)
                return True
        except _NATIVE_DRIVER_ERRORS as exc:
            if not _is_driver_error(exc):
                raise
            raise _mapped_transport(exc, code) from exc
        raise TimeoutError("Host consolidated common block poll bound exceeded")

    def write_epb_block(
        self,
        request,
        response,
        block_number,
        sizes,
        memory,
        image,
        counts,
        percentages,
        notify,
        *,
        cpu_index=0,
        total_size=None,
        initial_wait_ms=0,
    ) -> None:
        """1bcc0 singleblock41/address/1024 then45, only40 is busy."""
        from scripts.programming_2026_common import NativeMemoryInfo
        from scripts.programming_2026_legacy import _mapped_transport

        self._addresses(request, response)
        self.common._progress(cpu_index, counts, percentages, notify)
        if (
            type(block_number) is not int
            or not 1 <= block_number <= 256
            or not isinstance(memory, NativeMemoryInfo)
            or type(initial_wait_ms) is not int
            or not 0 <= initial_wait_ms <= 0xFFFFFFFF
        ):
            raise ValueError("Native EPB block and memory descriptor required")
        offset, extent = self.common._geometry(
            block_number, block_number, sizes, image, 1024
        )
        total_size = len(image) if total_size is None else total_size
        consolidated_progress_percent(counts[cpu_index], total_size)
        address = memory.start_address + offset
        if not 0 <= address <= 0xFFFFFF or counts[cpu_index] + extent > 0xFFFFFFFF:
            raise ValueError("Native EPB address/count exceeds representation")
        try:
            self.diag.write(request + b"\x41")
            self._ack(response, 13)
            self.diag.write(request + address.to_bytes(3, "big") + b"\xff")
            if initial_wait_ms:
                # Electric17580 adds its3ms wait here; EPB1bcc0 has no wait.
                _void(self.runtime, "wait", milliseconds=initial_wait_ms)
            cursor = [0]
            while cursor[0] < extent:
                if cursor[0]:
                    self.diag.write(request + b"\x45")
                    self._ack(response, 13)
                self._write_progress(
                    request,
                    cpu_index,
                    1024,
                    cursor,
                    offset,
                    image,
                    total_size,
                    counts,
                    percentages,
                    notify,
                )
                self._ack(response, 13)
                for _ in range(4096):
                    _void(self.runtime, "wait", milliseconds=5)
                    status = self.common.get_status(request, response, True)
                    if status == 0x40:
                        continue
                    if status:
                        raise ConsolidatedError(13, "epb_write_status")
                    break
                else:
                    raise TimeoutError("Host EPB write status bound exceeded")
        except _NATIVE_BASE_ERRORS as exc:
            if _is_driver_error(exc):
                raise _mapped_transport(exc, 13) from exc
            raise ConsolidatedError(13, "epb_write") from exc

    def verify_epb_block(
        self,
        request,
        response,
        block_number,
        sizes,
        image,
        counts,
        percentages,
        notify,
        *,
        cpu_index=0,
        total_size=None,
    ) -> None:
        """1b6e0/1bbdd singleblock15,256byte packets, only20 is busy."""
        from scripts.programming_2026_legacy import _mapped_transport

        self._addresses(request, response)
        self.common._progress(cpu_index, counts, percentages, notify)
        if type(block_number) is not int or not 1 <= block_number <= 256:
            raise ValueError("Representable native EPB block required")
        offset, extent = self.common._geometry(
            block_number, block_number, sizes, image, 256
        )
        total_size = len(image) if total_size is None else total_size
        consolidated_progress_percent(counts[cpu_index], total_size)
        if counts[cpu_index] + extent > 0xFFFFFFFF:
            raise ValueError("Native EPB count exceeds representation")
        try:
            self.diag.write(request + bytes((0x15, block_number - 1)))
            self._ack(response, 15)
            cursor = [0]
            while cursor[0] < extent:
                self._write_progress(
                    request,
                    cpu_index,
                    256,
                    cursor,
                    offset,
                    image,
                    total_size,
                    counts,
                    percentages,
                    notify,
                )
                self._ack(response, 15)
                final, prior_status = cursor[0] == extent, 0
                for _ in range(4096):
                    _void(self.runtime, "wait", milliseconds=5)
                    try:
                        status = self.common.get_status(request, response, final)
                    except _NATIVE_BASE_ERRORS:
                        if final:
                            raise
                        if prior_status:
                            raise ConsolidatedError(
                                15, "epb_verify_retained_status"
                            ) from None
                        break
                    prior_status = status
                    if status == 0x20:
                        continue
                    if status:
                        raise ConsolidatedError(15, "epb_verify_status")
                    break
                else:
                    raise TimeoutError("Host EPB verify status bound exceeded")
        except _NATIVE_BASE_ERRORS as exc:
            if _is_driver_error(exc):
                raise _mapped_transport(exc, 15) from exc
            raise ConsolidatedError(15, "epb_verify") from exc

    def get_epb_memory_info(self, request: bytes, response: bytes):
        """1b3f0 sends75, exact12-byte Data and8-byte descriptor; no6c mutation."""
        from scripts.programming_2026_common import extract_memory_info
        from scripts.programming_2026_legacy import _mapped_transport

        self._addresses(request, response)
        try:
            self.diag.write(request + b"\x75")
            self._ack(response, 10)
            reply = self.runtime.call(
                "read_specified_can_message", address=response, count=1, frame=1
            )
            if type(reply) is not bytes:
                raise ValueError("Native EPB memory response must be immutable Data")
            if len(reply) != 12:
                raise ConsolidatedError(10, "epb_memory_size")
            memory = extract_memory_info(reply[4:])
            self._ack(response, 10)
            return memory
        except _NATIVE_DRIVER_ERRORS as exc:
            if not _is_driver_error(exc):
                raise
            raise _mapped_transport(exc, 10) from exc

    def erase_epb_block(
        self, request: bytes, response: bytes, block_number: int
    ) -> None:
        """1ac80 sends25/singleblock-1,10ms polls only status80 untilzero."""
        from scripts.programming_2026_legacy import _mapped_transport

        self._addresses(request, response)
        if type(block_number) is not int or not 1 <= block_number <= 256:
            raise ValueError("Representable native one-byte EPB block number required")
        try:
            self.diag.write(request + bytes((0x25, block_number - 1)))
            self._ack(response, 12)
            for _ in range(4096):
                _void(self.runtime, "wait", milliseconds=10)
                status = self.common.get_status(request, response, True)
                if status == 0x80:
                    continue
                if status:
                    raise ConsolidatedError(12, "epb_erase_status")
                return
            raise TimeoutError("Host EPB erase status bound exceeded")
        except _NATIVE_DRIVER_ERRORS as exc:
            if not _is_driver_error(exc):
                raise
            raise _mapped_transport(exc, 12) from exc

    def electric_inverify_block(
        self, request: bytes, response: bytes, block_number: int
    ):
        """16de0→16fb0 opcode47/singleblock,10ms polls only40 as busy."""
        from scripts.programming_2026_legacy import _mapped_transport

        self._addresses(request, response)
        if type(block_number) is not int or not 1 <= block_number <= 256:
            raise ValueError("Representable native electric block required")
        try:
            self.diag.write(request + bytes((0x47, block_number - 1)))
            self._ack(response, 14)
            for _ in range(4096):
                _void(self.runtime, "wait", milliseconds=10)
                status = self.common.get_status(request, response, True)
                if status == 0x40:
                    continue
                if status:
                    raise ConsolidatedError(14, "electric_inverify_status")
                return
            raise TimeoutError("Host electric inverify status bound exceeded")
        except _NATIVE_DRIVER_ERRORS as exc:
            if not _is_driver_error(exc):
                raise
            raise _mapped_transport(exc, 14) from exc

    def get_memory_info(self, request: bytes, response: bytes, *, wide: bool = False):
        """7950 is76-only; standalone's75 fallback is a different operation."""
        from scripts.programming_2026_common import extract_memory_info
        from scripts.programming_2026_legacy import (
            _NATIVE_DRIVER_ERRORS,
            _is_driver_error,
            _mapped_transport,
        )

        self._addresses(request, response)
        if type(wide) is not bool:
            raise ValueError("Native memory-information width flag required")
        try:
            self.diag.write(request + b"\x76")
            self._ack(response, 10)
            self.native_context_6c = True
            reply = self.runtime.call(
                "read_specified_can_message", address=response, count=1, frame=1
            )
            if type(reply) is not bytes:
                raise ValueError("Native memory response must be immutable Data")
            expected = 15 if wide else 13
            if len(reply) != expected:
                raise ConsolidatedError(10, "common_memory_size")
            # bf70 agrees exactly with FlashWriterUtils1d10 BE3/BE4+two bytes.
            memory = extract_memory_info(reply[4:-1])
            self._ack(response, 10)
            return memory
        except _NATIVE_DRIVER_ERRORS as exc:
            if not _is_driver_error(exc):
                raise
            raise _mapped_transport(exc, 10) from exc

    def _write_progress(
        self,
        request,
        cpu_index,
        size,
        cursor,
        offset,
        image,
        total_size,
        counts,
        percentages,
        notify,
    ):
        """9370 exact write/count callback/percentage/percentage callback order."""
        self.diag.write(request + image[offset + cursor[0] : offset + cursor[0] + size])
        cursor[0] += size
        counts[cpu_index] += size
        self.common._observe(notify, "count")
        percentages[cpu_index] = consolidated_progress_percent(
            counts[cpu_index], total_size
        )
        self.common._observe(notify, "percent")

    def dispose_write_error(
        self, request: bytes, response: bytes, error_code: int
    ) -> None:
        """80a0:05 ACK probe;13/15 zero padding until3c/ff, then3000ms retry."""
        self._addresses(request, response)
        if type(error_code) is not int or not 0 <= error_code <= 0xFFFFFFFF:
            raise ValueError("Native error enum required")
        for _ in range(4096):
            self.diag.write(request + b"\x05")
            if self.common.receive_ack(response):
                return
            if error_code not in (13, 15):
                raise ConsolidatedError(20, "common_dispose_error")
            self.diag.write(request + bytes(1024 if error_code == 13 else 256))
            for _ in range(4096):
                try:
                    reply = self.runtime.call(
                        "read_specified_can_message", address=response, count=1, frame=0
                    )
                except _NATIVE_DRIVER_ERRORS as exc:
                    # FuncInfo32d0c scope0 catches any CJ at8326, not base CPass.
                    if _is_driver_error(exc):
                        continue
                    raise
                if type(reply) is not bytes or len(reply) > 4128:
                    raise ValueError("Bounded raw native disposal response required")
                if len(reply) == 5 and reply[4] in (0x3C, 0xFF):
                    break
            else:
                raise TimeoutError("Host disposal reply bound exceeded")
            _void(self.runtime, "wait", milliseconds=3000)
        raise TimeoutError("Host disposal attempt bound exceeded")

    def write_block(
        self,
        request: bytes,
        response: bytes,
        first: int,
        last: int,
        sizes: tuple[int, ...],
        memory,
        image: bytes,
        counts: list[int],
        percentages: list[int],
        notify,
        *,
        cpu_index: int = 0,
        total_size: int | None = None,
        wait_ms: int = 0,
        wide: bool = False,
    ) -> None:
        """8c10:41/address/1024-byte first packet, then45 packets,5ms status."""
        from scripts.programming_2026_common import NativeMemoryInfo
        from scripts.programming_2026_legacy import _mapped_transport

        self._addresses(request, response)
        if total_size is None:
            total_size = len(image)
        if type(total_size) is not int or not 0 <= total_size <= 64 * 1024 * 1024:
            raise ValueError("Bounded actual native archive flash size required")
        self.common._progress(cpu_index, counts, percentages, notify)
        offset, extent = self.common._geometry(first, last, sizes, image, 1024)
        if (
            not isinstance(memory, NativeMemoryInfo)
            or type(wide) is not bool
            or type(wait_ms) is not int
            or not 0 <= wait_ms <= 0xFFFFFFFF
            or counts[cpu_index] + extent > 0xFFFFFFFF
        ):
            raise ValueError("Bound native memory, flags, wait and progress required")
        address, width = memory.start_address + offset, 4 if wide else 3
        if not 0 <= address < 1 << (8 * width):
            raise ValueError("Native start address exceeds selected width")
        try:
            self.diag.write(request + b"\x41")
            self._ack(response, 13)
            self.diag.write(request + address.to_bytes(width, "big") + b"\xff")
            if wait_ms:
                _void(self.runtime, "wait", milliseconds=wait_ms)
            cursor = [0]
            while cursor[0] < extent:
                if cursor[0]:
                    self.diag.write(request + b"\x45")
                    self._ack(response, 13)
                self._write_progress(
                    request,
                    cpu_index,
                    1024,
                    cursor,
                    offset,
                    image,
                    total_size,
                    counts,
                    percentages,
                    notify,
                )
                self._ack(response, 13)
                for _ in range(4096):
                    _void(self.runtime, "wait", milliseconds=5)
                    status = self.common.get_status(request, response, True)
                    if status == 0:
                        break
                    if status & 15:
                        raise ConsolidatedError(13, "common_write_status")
                else:
                    raise TimeoutError("Host consolidated write status bound exceeded")
        except _NATIVE_BASE_ERRORS as exc:
            if _is_driver_error(exc):
                raise _mapped_transport(exc, 13) from exc
            raise ConsolidatedError(13, "common_write") from exc

    def verify_block(
        self,
        request: bytes,
        response: bytes,
        first: int,
        last: int,
        sizes: tuple[int, ...],
        image: bytes,
        counts: list[int],
        percentages: list[int],
        notify,
        *,
        cpu_index: int = 0,
        total_size: int | None = None,
    ) -> None:
        """85e0: fixed256-byte packets,5ms status, exact retained-status EH."""
        from scripts.programming_2026_legacy import _mapped_transport

        self._addresses(request, response)
        if total_size is None:
            total_size = len(image)
        if type(total_size) is not int or not 0 <= total_size <= 64 * 1024 * 1024:
            raise ValueError("Bounded actual native archive flash size required")
        self.common._progress(cpu_index, counts, percentages, notify)
        offset, extent = self.common._geometry(first, last, sizes, image, 256)
        if last > 65536 or counts[cpu_index] + extent > 0xFFFFFFFF:
            raise ValueError("Native wide range and progress counter must fit")
        try:
            self.diag.write(
                request
                + b"\x16"
                + (first - 1).to_bytes(2, "big")
                + (last - 1).to_bytes(2, "big")
            )
            self._ack(response, 15)
            cursor = [0]
            while cursor[0] < extent:
                self._write_progress(
                    request,
                    cpu_index,
                    256,
                    cursor,
                    offset,
                    image,
                    total_size,
                    counts,
                    percentages,
                    notify,
                )
                self._ack(response, 15)
                final, prior_status = cursor[0] == extent, 0
                for _ in range(4096):
                    _void(self.runtime, "wait", milliseconds=5)
                    try:
                        status = self.common.get_status(request, response, final)
                    except _NATIVE_BASE_ERRORS:
                        # EH8ad5 only tests final;8ae8 retains last successful status.
                        if final:
                            raise
                        if prior_status:
                            raise ConsolidatedError(
                                15, "common_verify_retained_status"
                            ) from None
                        break
                    prior_status = status
                    if status == 0:
                        break
                    if status & 15:
                        raise ConsolidatedError(15, "common_verify_status")
                else:
                    raise TimeoutError("Host consolidated verify status bound exceeded")
        except _NATIVE_BASE_ERRORS as exc:
            if _is_driver_error(exc):
                raise _mapped_transport(exc, 15) from exc
            raise ConsolidatedError(15, "common_verify") from exc

    def finish(
        self, request: bytes, response: bytes, *, acknowledge: bool = False
    ) -> None:
        from scripts.programming_2026_legacy import (
            _NATIVE_DRIVER_ERRORS,
            _is_driver_error,
            _mapped_transport,
        )

        if any(
            type(value) is not bytes or len(value) not in (4, 5)
            for value in (request, response)
        ) or len(request) != len(response):
            raise ValueError("Matching four/five-byte native CAN addresses required")
        if type(acknowledge) is not bool:
            raise ValueError("Explicit native finish acknowledgment branch required")
        try:
            self.diag.write(
                request + b"\x80", tx_flags=0x80 if len(request) == 5 else 0
            )
            if acknowledge:
                self._ack(response, 35)
        except _NATIVE_DRIVER_ERRORS as exc:
            if not acknowledge or not _is_driver_error(exc):
                raise
            raise _mapped_transport(exc, 35) from exc


@dataclass(frozen=True)
class SILIdentifierContext:
    identity: NativeModuleIdentity
    branch: Branch
    kind_of_ecu: str

    def __post_init__(self):
        _identity(self.identity)
        if (
            not isinstance(self.branch, Branch)
            or self.branch.family
            not in ("sil_emps_id", "sil_occupant_id", "sil_vpns_id", "sil_cid")
            or self.branch.writing
            or self.branch.requires_ecb_fallback
            or type(self.kind_of_ecu) is not str
            or not 0 < len(self.kind_of_ecu) <= 64
            or "\0" in self.kind_of_ecu
            or (self.branch.family == "sil_occupant_id" and self.kind_of_ecu != "37")
            or (self.branch.family == "sil_vpns_id" and self.kind_of_ecu != "63")
        ):
            raise ValueError("Audited literal SIL getter context required")


def get_sil_identifier(
    context: SILIdentifierContext,
    runtime: NativeRuntime2026,
    *,
    state: ConsolidatedControllerState | None = None,
    error_snapshot=None,
) -> str | None:
    """21870/21990 EMPS and231d0/232f0 occupant getters, with real FAST_INIT."""
    if not isinstance(context, SILIdentifierContext) or not isinstance(
        runtime, NativeRuntime2026
    ):
        raise TypeError("Audited SIL context and bounded runtime required")
    context.__post_init__()
    if context.branch.family not in ("sil_emps_id", "sil_occupant_id"):
        raise ValueError("Selected SIL getter returns multiple identifiers")
    rt, diag = runtime, SilDiag2026(runtime)
    emps = context.branch.family == "sil_emps_id"
    if emps:
        _void(rt, "wait", milliseconds=2000)
    observed = []
    with _getter_connection(
        rt,
        3,
        partial=lambda: observed,
        error_snapshot=error_snapshot,
        completion_state=state,
    ):
        _void(rt, "set_timeout", milliseconds=1000)
        if not emps:
            _void(rt, "wait", milliseconds=1000)
        # Native216e0 maps kind13→32, kind14→34, and preserves zero otherwise.
        target = (
            (
                0x32
                if context.kind_of_ecu == "13"
                else 0x34
                if context.kind_of_ecu == "14"
                else 0
            )
            if emps
            else 0x5B
        )
        diag.fast_init(target, emps=emps, check_native_cancel=True)
        if not emps and _native_cancel_requested(rt):
            return None
        _void(rt, "wait", milliseconds=100)
        if _native_cancel_requested(rt):
            return None
        if emps:
            reply = diag.exchange(
                diag.packet(bytes((0x82, target, 0xF1, 0x9C, 0x0C))),
                minimum=14,
                payload=b"\xdc\x0c",
                check_native_cancel=True,
            )
            raw = reply[5:13]
        else:
            reply = diag.exchange(
                diag.packet(b"\x82\x5b\xf1\x21\xdf"),
                minimum=12,
                header=b"\x88\xf1\x5b",
                payload=b"\x61\xdf",
                check_native_cancel=True,
            )
            raw = reply[5:10]
        observed.append(raw.split(b"\0", 1)[0].decode("latin-1"))
        return observed[-1]


def get_sil_vpns_identifiers(
    identity: NativeModuleIdentity,
    runtime: NativeRuntime2026,
    *,
    state: ConsolidatedControllerState | None = None,
    error_snapshot=None,
) -> tuple[str, ...]:
    """25f30/26400/26100: source VPNS discovery and selected sixteen-byte IDs."""
    from scripts.programming_vendor import software_info_identifier

    _identity(identity)
    if not isinstance(runtime, NativeRuntime2026):
        raise TypeError("Bounded native primitive runtime required")
    rt, diag = runtime, SilDiag2026(runtime)
    identifiers = []
    with _getter_connection(
        rt,
        3,
        partial=lambda: identifiers,
        error_snapshot=error_snapshot,
        completion_state=state,
    ):
        _void(rt, "set_timeout", milliseconds=1000)
        _void(rt, "wait", milliseconds=3000)
        diag.fast_init(0xD3, mobd=False, check_native_cancel=True)
        if _native_cancel_requested(rt):
            return ()
        _void(rt, "wait", milliseconds=100)
        if _native_cancel_requested(rt):
            return ()
        reply = diag.exchange(
            diag.packet(b"\x83\xd3\xf1\x1a\x88\0"),
            minimum=8,
            payload=b"\x5a\x88\0",
            check_native_cancel=True,
        )
        selectors = reply[6:-1]
        if not selectors or 0 in selectors:
            if _native_cancel_requested(rt):
                return ()
            raise ConsolidatedError(3, "vpns_selectors")
        if _native_cancel_requested(rt):
            return ()
        for selector in selectors:
            reply = diag.exchange(
                diag.packet(b"\x83\xd3\xf1\x1a\x88" + bytes((selector,))),
                minimum=23,
                header=b"\x93\xf1\xd3",
                payload=b"\x5a\x88" + bytes((selector,)),
                check_native_cancel=True,
            )
            # Source26100 has the same16-byte strncpy/NUL/trailing-space parser.
            try:
                raw = software_info_identifier(reply[3:], selector)
            except ValueError as exc:
                raise ConsolidatedError(3, "vpns_identifier") from exc
            identifiers.append(raw.decode("latin-1"))
        return tuple(identifiers)


def get_identifiers(
    context: CANIdentifierContext | SILIdentifierContext | SoftwareIdentifierContext,
    runtime: NativeRuntime2026,
    state: ConsolidatedControllerState | None = None,
    *,
    error_snapshot=None,
) -> tuple[str, ...]:
    """Run only an implemented source-bound getter; each result is native text."""
    if isinstance(context, SoftwareIdentifierContext):
        return get_can_software_info_identifiers(
            context, runtime, state, error_snapshot=error_snapshot
        )
    if state is not None:
        if not isinstance(state, ConsolidatedControllerState):
            raise TypeError("Native consolidated controller state required")
        state.__post_init__()
    if isinstance(context, CANIdentifierContext):
        identifier = get_can_identifier(
            context, runtime, state=state, error_snapshot=error_snapshot
        )
        result = () if identifier is None else (identifier,)
        if state is not None:
            state.request_id_records = (context.request.hex().upper(),) * len(result)
        return result
    if not isinstance(context, SILIdentifierContext):
        raise TypeError("Source-bound consolidated getter context required")
    context.__post_init__()
    if context.branch.family == "sil_vpns_id":
        return get_sil_vpns_identifiers(
            context.identity, runtime, state=state, error_snapshot=error_snapshot
        )
    if context.branch.family == "sil_cid":
        return get_sil_cids(
            context.identity,
            context.kind_of_ecu,
            runtime,
            state=state,
            error_snapshot=error_snapshot,
        )
    identifier = get_sil_identifier(
        context, runtime, state=state, error_snapshot=error_snapshot
    )
    return () if identifier is None else (identifier,)


class ConsolidatedReadError(ConsolidatedError):
    def __init__(self, code: int, partial_identifiers: tuple[str, ...]):
        self.partial_identifiers = partial_identifiers
        super().__init__(code, "sil_cid")


def get_sil_cids(
    identity: NativeModuleIdentity,
    kind_of_ecu: str,
    runtime: NativeRuntime2026,
    *,
    state: ConsolidatedControllerState | None = None,
    error_snapshot=None,
) -> tuple[str, ...]:
    """f050/f290/f6f0: OBD2→MOBD→Phase4OBD2→Phase4 literal source attempts.

    ASM f0ba/f1c8/f1db proves the four-element retry loop missing from Ghidra C.
    Completed native IDs survive later failed attempts, matching the shared
    original CID vector. Cancellation and host-contract failures never retry.
    """

    _identity(identity)
    if (
        type(kind_of_ecu) is not str
        or not 0 < len(kind_of_ecu) <= 64
        or "\0" in kind_of_ecu
    ):
        raise ValueError("Literal native ECU kind required")
    if not isinstance(runtime, NativeRuntime2026):
        raise TypeError("Bounded native primitive runtime required")
    rt, diag = runtime, SilDiag2026(runtime)
    observed: list[str] = []

    def target(mode: int, ecu: int) -> int:
        if ecu == 0:
            return 0x10 if mode in (0, 2) else 0x13
        if ecu == 2:
            return 0x16
        if ecu == 1 and mode in (2, 3):
            return 0x19
        raise ConsolidatedError(3, "sil_cid_target")

    def read_one_mode(mode: int, ecu: int) -> None:
        _void(rt, "control_io", ioctl=8, parameters=())
        address = target(mode, ecu)
        if mode == 0:
            _void(rt, "control_io", ioctl=2, parameters=((1, 10400),))
            if _native_cancel_requested(rt):
                return
            initialized = rt.call("five_baud_init", data=b"\x33")
            if type(initialized) is not bytes or len(initialized) > 256:
                raise ValueError("Bounded native FIVE_BAUD_INIT result required")
            if _native_cancel_requested(rt):
                return
            _void(rt, "wait", milliseconds=100)
            if _native_cancel_requested(rt):
                return
            count_request = diag.packet(b"\x68\x6a\xf1\x09\x03")
            diag.write(count_request)
            if _native_cancel_requested(rt):
                return
            _void(rt, "wait", milliseconds=100)
            if _native_cancel_requested(rt):
                return
            count = 0
            while not _native_cancel_requested(rt):
                reply = diag.read()
                if len(reply) < 6 or reply[5] == 0 or reply[5] & 3:
                    raise ConsolidatedError(3, "sil_cid_count")
                if reply[2] == address:
                    count = reply[5]
                    break
            if _native_cancel_requested(rt):
                return
            _void(rt, "wait", milliseconds=100)
            if _native_cancel_requested(rt):
                return
            data_request = diag.packet(b"\x68\x6a\xf1\x09\x04")
            diag.write(data_request)
            if _native_cancel_requested(rt):
                return
            _void(rt, "wait", milliseconds=100)
            if _native_cancel_requested(rt):
                return
            reply = b""
        else:
            diag.fast_init(address, mobd=mode == 1, check_native_cancel=True)
            _void(rt, "wait", milliseconds=100)
            if _native_cancel_requested(rt):
                return
            count_request = diag.packet(bytes((0x82, address, 0xF1, 0x09, 0x03)))
            reply = diag.exchange(count_request, check_native_cancel=True)
            count = 0
            while not _native_cancel_requested(rt):
                if len(reply) < 6 or reply[5] == 0 or reply[5] & 3:
                    raise ConsolidatedError(3, "sil_cid_count")
                if reply[2] == address:
                    count = reply[5]
                    break
                reply = diag.exchange(count_request, send=False)
            # f290 still writes0904 after cancellation in the count loop.
            _void(rt, "wait", milliseconds=100)
            data_request = diag.packet(bytes((0x82, address, 0xF1, 0x09, 0x04)))
            reply = diag.exchange(data_request, check_native_cancel=True)
        chunks = bytearray()
        received = 0
        while mode != 0 or received < count:
            if _native_cancel_requested(rt):
                if mode == 0:
                    return
                break
            if mode == 0:
                reply = diag.read()
            if len(reply) > 9 and reply[4] == 4 and reply[2] == address:
                chunks.extend(reply[6:10].split(b"\0", 1)[0].ljust(4, b"\0"))
                received += 1
                if received % 4 == 0:
                    observed.append(bytes(chunks).split(b"\0", 1)[0].decode("latin-1"))
                    chunks.clear()
                if mode == 0 and _native_cancel_requested(rt):
                    return
                if received >= count:
                    break
            if mode != 0:
                if _native_cancel_requested(rt):
                    return
                reply = diag.exchange(data_request, send=False)
        _void(rt, "control_io", ioctl=8, parameters=())

    with _getter_connection(
        rt,
        3,
        partial=lambda: observed,
        error_snapshot=error_snapshot,
        completion_state=state,
    ):
        _void(rt, "set_timeout", milliseconds=1000)
        _void(rt, "wait", milliseconds=1000)
        ecu = 0 if kind_of_ecu == "0" else 2 if kind_of_ecu == "1" else 3
        for mode in (0, 1, 2, 3):
            try:
                read_one_mode(mode, ecu)
                if kind_of_ecu == "0" and mode in (2, 3):
                    try:
                        read_one_mode(mode, 1)
                    except (ConsolidatedError, *_NATIVE_BASE_ERRORS):
                        # FuncInfo334c8 state3/f193 swallows only native ECT faults.
                        rt.check()
                return tuple(observed)
            except (ConsolidatedError, *_NATIVE_BASE_ERRORS) as exc:
                rt.check()
                if mode == 3:
                    error = ConsolidatedReadError(
                        exc.code
                        if isinstance(exc, ConsolidatedError)
                        else _native_enum(exc),
                        tuple(observed),
                    )
                    # f279 rethrows the original subtype to the outer CJ catch.
                    # The authored partial-ID exception must retain that driver slot.
                    if _is_driver_error(exc):
                        error.transport_code = _driver_code(exc)
                    elif isinstance(exc, ConsolidatedError):
                        error.transport_code = exc.transport_code
                    raise error from exc
        raise AssertionError("Exhaustive native SIL mode loop")


@dataclass
class ConsolidatedControllerState:
    old_spec_ecb: bool = False
    native_context_9e8: bool = False
    # b760 copies the native 12-byte records (zero DWORD, CAN request hex text).
    request_id_records: tuple[str, ...] = ()
    # b2c0 copies the distinct 32-byte software-ID records into DAT1003a624.
    software_id_records: tuple[SoftwareIDRecord, ...] = ()
    getter_completion_callback: str = "normal"

    def __post_init__(self):
        if (
            type(self.old_spec_ecb) is not bool
            or type(self.native_context_9e8) is not bool
            or type(self.request_id_records) is not tuple
            or any(
                type(value) is not str
                or len(value) not in (4, 6)
                or any(char not in "0123456789ABCDEF" for char in value)
                for value in self.request_id_records
            )
            or self.getter_completion_callback not in ("normal", "cancel", "error")
            or type(self.software_id_records) is not tuple
            or any(
                not isinstance(value, SoftwareIDRecord)
                for value in self.software_id_records
            )
        ):
            raise ValueError("Native consolidated controller result state required")


@dataclass(frozen=True)
class SoftwareIDRecord:
    identifier: str
    request: bytes
    response: bytes
    extended: bool

    def __post_init__(self):
        if (
            type(self.identifier) is not str
            or not 1 <= len(self.identifier) <= 16
            or "\0" in self.identifier
            or any(ord(char) > 255 for char in self.identifier)
            or type(self.request) is not bytes
            or type(self.response) is not bytes
            or len(self.request) not in (2, 3)
            or len(self.response) != len(self.request)
            or type(self.extended) is not bool
            or self.extended != (len(self.request) == 3)
        ):
            raise ValueError("Native software-ID string and raw CAN route required")


@dataclass(frozen=True)
class SoftwareIdentifierContext:
    identity: NativeModuleIdentity
    kind_of_ecu: str
    first_cpu_type: str

    def __post_init__(self):
        branch = select_branch(
            self.identity, "CAN", self.kind_of_ecu, (self.first_cpu_type,)
        )
        if branch.family != "can_software_info_id":
            raise ValueError("Source-selected consolidated software ID getter required")

    @property
    def branch(self) -> Branch:
        return select_branch(
            self.identity, "CAN", self.kind_of_ecu, (self.first_cpu_type,)
        )


def get_can_software_info_identifiers(
    context: SoftwareIdentifierContext,
    runtime: NativeRuntime2026,
    state: ConsolidatedControllerState | None = None,
    *,
    error_snapshot=None,
) -> tuple[str, ...]:
    """1f550/20340/1fda0 with actual c570→151d0 ECB fallback and c640 state.

    Source9ff0 reverses its selected node list when producing the address vector;
    kind6 therefore queries8,5,7. It is not catalog order or numeric CAN order.
    """
    from scripts.programming_vendor import (
        software_info_identifier,
        software_info_selectors,
    )

    if not isinstance(context, SoftwareIdentifierContext) or not isinstance(
        runtime, NativeRuntime2026
    ):
        raise TypeError("Source-bound software getter and native runtime required")
    context.__post_init__()
    if state is not None:
        if not isinstance(state, ConsolidatedControllerState):
            raise TypeError("Native consolidated controller state required")
        state.__post_init__()
    nodes = {
        "4": ((b"\x07\xb0", b"\x07\xb8"),),
        "5": ((b"\x07\xd1", b"\x07\xd9"),),
        "6": (
            (b"\x07\xd3", b"\x07\xdb"),
            (b"\x07\x24", b"\x07\x2c"),
            (b"\x07\xd2", b"\x07\xda"),
        ),
        "7": ((b"\x07\x50\x2c", b"\x07\x58\x2c"),),
        "13": ((b"\x07\xa1", b"\x07\xa9"),),
        "51": ((b"\x07\x42", b"\x07\x4a"),),
    }[context.kind_of_ecu]
    rt, diag = runtime, ConsolidatedCanDiag2026(runtime)
    observed = []
    routes = []
    request_records = []

    def normal() -> tuple[str, ...]:
        with _getter_connection(
            rt,
            6,
            partial=lambda: observed,
            error_snapshot=error_snapshot,
            completion_state=state,
        ):
            _void(rt, "set_timeout", milliseconds=1000)
            for raw_request, raw_response in nodes:
                request, response = b"\0\0" + raw_request, b"\0\0" + raw_response
                extended = len(raw_request) == 3
                if extended:
                    diag.set_block_size(1)
                try:
                    handle = diag.start_filter(request, response)
                    try:
                        selectors = None
                        if not _native_cancel_requested(rt):
                            reply = diag.call(
                                request,
                                response,
                                b"\x1a\x88\0",
                                b"\x5a\x88\0",
                                minimum=4,
                                error_code=3,
                                check_native_cancel=True,
                            )
                            try:
                                selectors = software_info_selectors(reply)
                            except ValueError:
                                pass  # 20340 returns false;1f550 decides error versus cancellation.
                    finally:
                        rt.release("stop_filter", identifier=handle)
                    if selectors is None:
                        if _native_cancel_requested(rt):
                            continue
                        raise ConsolidatedError(3, "software_id_selectors")
                    before = len(observed)
                    handle = diag.start_filter(request, response)
                    try:
                        selected = () if _native_cancel_requested(rt) else selectors
                        for selector in selected:
                            reply = diag.call(
                                request,
                                response,
                                bytes((0x1A, 0x88, selector)),
                                bytes((0x5A, 0x88, selector)),
                                minimum=19,
                                error_code=3,
                                check_native_cancel=True,
                            )
                            try:
                                identifier = software_info_identifier(reply, selector)
                            except ValueError as exc:
                                raise ConsolidatedError(
                                    3, "software_identifier"
                                ) from exc
                            observed.append(identifier.decode("latin-1"))
                            routes.append(
                                SoftwareIDRecord(
                                    observed[-1], raw_request, raw_response, extended
                                )
                            )
                    finally:
                        rt.release("stop_filter", identifier=handle)
                    request_records.extend(
                        [raw_request.hex().upper()] * (len(observed) - before)
                    )
                finally:
                    if extended:
                        # Host cleanup policy also restores source block size after failure.
                        rt.call(
                            "control_io", cleanup=True, ioctl=2, parameters=((0x1E, 0),)
                        )
            return tuple(observed)

    try:
        result = normal()
        if state is not None:
            state.request_id_records = tuple(request_records)
            state.software_id_records = tuple(routes)
        return result
    except (ConsolidatedError, *_NATIVE_BASE_ERRORS, NativeException2026) as exc:
        rt.check()
        if "_consolidated_getter_error" not in exc.__dict__:
            raise
        if state is not None:
            state.request_id_records = tuple(request_records)
            state.software_id_records = tuple(routes)
        if context.kind_of_ecu != "4":
            raise
        # The native error callback runs after the failed worker disconnects.
        return get_ecb_rom_identifiers(
            context.identity, rt, state, error_snapshot=error_snapshot
        )


@dataclass(frozen=True)
class CANEMPSWriteContext:
    identity: NativeModuleIdentity
    loader: bytes = field(repr=False)
    image: bytes = field(repr=False)
    authorized_key: bytes = field(repr=False)
    retry_after_failure: bool = False
    retry_decisions: tuple[bool, ...] = ()

    def __post_init__(self):
        _identity(self.identity)
        if (
            type(self.loader) is not bytes
            or len(self.loader) > 64 * 1024 * 1024
            or type(self.image) is not bytes
            or len(self.image) > 64 * 1024 * 1024
            or type(self.authorized_key) is not bytes
            or len(self.authorized_key) != 4
            or type(self.retry_decisions) is not tuple
            or len(self.retry_decisions) > 256
            or any(type(v) is not bool for v in self.retry_decisions)
            or type(self.retry_after_failure) is not bool
        ):
            raise ValueError(
                "Bounded native EMPS extents and explicit authorized key required"
            )


def bind_can_emps_writer(
    container,
    identity: NativeModuleIdentity,
    attachments,
    *,
    retry_after_failure: bool = False,
    retry_decisions: tuple[bool, ...] = (),
) -> CANEMPSWriteContext:
    """Bind first native CPU loader/image; source18e90 fixes both download ranges.

    The source's authorization material is never redistributed. An authorized
    four-byte attachment supplies the actual key bytes; geometry is not an input.
    """
    from collections.abc import Mapping

    from scripts.calibration_2026 import (
        native2026_archive,
        native2026_cpu_type,
        native2026_metadata,
        native2026_metadata_for_cpu,
    )

    _identity(identity)
    metadata = native2026_metadata(container, node=1, cpu_index=0)
    branch = select_branch(
        identity,
        metadata.vehicle.get("contacttype", ""),
        metadata.vehicle.get("kindofecu", ""),
        (native2026_cpu_type(metadata, 0),),
        writing=True,
    )
    if (
        branch.family != "can_emps_write"
        or not isinstance(attachments, Mapping)
        or set(attachments) != {"authorized_key"}
    ):
        raise ValueError("Exact native EMPS writer and authorized attachment required")
    first_cpu = native2026_metadata_for_cpu(metadata, 0)
    loader = native2026_archive(first_cpu, flash_code=True)
    image = native2026_archive(first_cpu)
    loader_size, image_size = loader.length, image.flash_size
    for name, data, extent in (
        ("loader", loader.data, loader_size),
        ("image", image.data, image_size),
    ):
        if (
            type(extent) is not int
            or not 0 <= extent <= 64 * 1024 * 1024
            or (data is None and extent != 0)
            or (data is not None and (type(data) is not bytes or extent > len(data)))
        ):
            raise ValueError(f"Native EMPS {name} extent exceeds safe archive backing")
    loader_prefix = b"" if loader.data is None else loader.data[:loader_size]
    image_prefix = b"" if image.data is None else image.data[:image_size]
    return CANEMPSWriteContext(
        identity,
        loader_prefix,
        image_prefix,
        attachments["authorized_key"],
        retry_after_failure,
        retry_decisions,
    )


def write_can_emps(
    context: CANEMPSWriteContext,
    runtime: NativeRuntime2026,
    *,
    progress=None,
    error_snapshot=None,
) -> dict:
    """18950 connected-session EMPS PS2 writer with native disposal/retry preparation.

    No connection is opened on the success path. Source ControlCommPhase owns
    that session. Explicit retry_after_failure requests only the original
    disconnect/reconnect preparation; image bytes are never automatically replayed.
    """
    driver_error = 0
    if error_snapshot is not None and not callable(error_snapshot):
        raise TypeError("Native error-slot observer must be callable")

    def observe_error():
        if error_snapshot is not None:
            error_snapshot(0 if failure is None else failure, driver_error)

    if (
        not isinstance(context, CANEMPSWriteContext)
        or not isinstance(runtime, NativeRuntime2026)
        or (progress is not None and not callable(progress))
    ):
        raise TypeError(
            "Source-bound EMPS context, connected runtime and optional observer required"
        )
    context.__post_init__()
    rt, diag = runtime, CanDiag2026(runtime)
    if rt.call("get_protocol_id") != 6:
        raise ValueError("Native EMPS writer requires upstream connected protocol6")
    prior = rt.call("get_timeout")
    if type(prior) is not int or not 0 <= prior <= 0xFFFFFFFF:
        raise ValueError("Unsigned original receive timeout required")
    handles, cleanup_errors = [], []
    count = percent = 0
    failure = None
    completed = False
    retry_prepared = False
    decisions = 0
    initial_failure = None
    targets = ((b"\0\0\0\x08", b"\0\0\0\x09"), (b"\0\0\x07\xa0", b"\0\0\x07\xa8"))

    def response(request: bytes, address: bytes, service: int, error: int) -> bytes:
        pending = 0
        while True:
            data = rt.call(
                "read_specified_can_message", address=address, count=1, frame=2
            )
            if (
                type(data) is not bytes
                or not 4 <= len(data) <= 4128
                or not data.startswith(address)
            ):
                raise ValueError("Bounded native EMPS response required")
            data = data[4:]
            if len(data) > 2 and data[:3] == bytes((0x7F, service, 0x78)):
                pending += 1
                if pending > 149:
                    diag.write(request + b"\x3e\x02")
                    raise ConsolidatedError(error, "emps_write_pending")
                _void(rt, "set_timeout", milliseconds=5000)
                continue
            _void(rt, "set_timeout", milliseconds=1000)
            return data

    def exchange(request, address, payload, expected, minimum, error):
        try:
            diag.write(request + payload)
            reply = response(request, address, payload[0], error)
        except _NATIVE_DRIVER_ERRORS as exc:
            if not _is_driver_error(exc):
                raise
            mapped = ConsolidatedError(error, "emps_write_transport")
            mapped.transport_code = _driver_code(exc)
            raise mapped from exc
        if len(reply) < minimum or not reply.startswith(expected):
            raise ConsolidatedError(error, "emps_write_response")
        return reply

    def transfer(request: bytes, address: bytes, data: bytes, main: bool) -> None:
        nonlocal count, percent
        routine = 2 if main else 1
        exchange(
            request,
            address,
            bytes((0x31, routine)),
            bytes((0x71, routine)),
            2,
            38 if main else 37,
        )
        geometry = (
            b"\x00\x39\x00\0\x03\x87\x00" if main else b"\xff\x80\x00\0\x00\x0b\x8c"
        )
        exchange(request, address, b"\x34" + geometry, b"\x74\0\xf1", 3, 26)
        for offset in range(0, len(data), 240):
            chunk = data[offset : offset + 240]
            exchange(request, address, b"\x36" + chunk, b"\x76", 1, 34)
            if main:
                written = offset + len(chunk)
                count = written * 2
                if progress is not None:
                    progress("count", count)
                percent = int(written / len(data) * 100)
                if progress is not None:
                    progress("percent", percent)
        exchange(request, address, b"\x37", b"\x77", 1, 36)
        exchange(
            request,
            address,
            b"\x31\x03" + bytes((sum(data) & 255,)),
            b"\x71\x03",
            2,
            39,
        )

    # 18950 ControlIO precedes native state2 and has no worker catch/cleanup.
    _void(rt, "control_io", ioctl=2, parameters=((0x23, 2),))
    try:
        for request, address in targets:
            handles.append(diag.start_filter(request, address))
        for _ in range(3):
            diag.write(b"\0\0\x07\x20\xa0\x27")
            _void(rt, "wait", milliseconds=100)
        selected = None
        for request, address in targets:
            try:
                diag.write(request + b"\x10\x92\x02")
            except _NATIVE_DRIVER_ERRORS as exc:
                if not _is_driver_error(exc):
                    raise
                mapped = ConsolidatedError(18, "emps_boot_write")
                mapped.transport_code = _driver_code(exc)
                raise mapped from exc
            try:
                reply = response(request, address, 0x10, 18)
            except _NATIVE_DRIVER_ERRORS as exc:
                rt.check()
                if not _is_driver_error(exc):
                    raise
                if _driver_code(exc) not in (9, 16):
                    mapped = ConsolidatedError(18, "emps_boot_read")
                    mapped.transport_code = _driver_code(exc)
                    raise mapped from exc
                continue
            if reply.startswith(b"\x50\x92"):
                selected = request, address
                break
        if selected is None:
            raise ConsolidatedError(18, "emps_boot_target")
        request, address = selected
        _void(rt, "wait", milliseconds=20)
        exchange(request, address, b"\x27\x01", b"\x67\x01", 4, 16)
        exchange(
            request, address, b"\x27\x02" + context.authorized_key, b"\x67\x02", 2, 17
        )
        transfer(request, address, context.loader, False)
        transfer(request, address, context.image, True)
        exchange(request, address, b"\x11\x01", b"\x51", 1, 24)
        _void(rt, "wait", milliseconds=3000)
        completed = True
    except (ConsolidatedError, *_NATIVE_BASE_ERRORS) as exc:
        driver_error = _native_driver_slot(exc, driver_error)
        rt.check()
        failure = exc.code if isinstance(exc, ConsolidatedError) else _native_enum(exc)
    finally:
        initial_failure = failure
        cleanup_fault = None
        for handle in handles:
            try:
                rt.release("stop_filter", identifier=handle)
            except (
                ConsolidatedError,
                *_NATIVE_BASE_ERRORS,
                NativeException2026,
            ) as exc:
                rt.check()
                cleanup_errors.append(type(exc).__name__)
                # One native ALL scope covers the entire two-filter loop.
                break
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - release other owned filters before propagating host fault
                cleanup_fault = cleanup_fault or exc
        unhandled_native_retry = False
        try:
            answers = context.retry_decisions or (
                (True,) if context.retry_after_failure else ()
            )
            if initial_failure is not None and cleanup_fault is None:
                observe_error()
                for accepted in answers:
                    decisions += 1
                    if not accepted:
                        break
                    failure = driver_error = 0
                    try:
                        _void(rt, "disconnect")
                    except (
                        ConsolidatedError,
                        *_NATIVE_BASE_ERRORS,
                        NativeException2026,
                    ):
                        rt.check()
                    try:
                        _void(rt, "connect", protocol=6)
                    except _NATIVE_DRIVER_ERRORS as exc:
                        if not _is_driver_error(exc):
                            unhandled_native_retry = True
                            raise
                        rt.check()
                        failure = _native_enum(exc)
                        driver_error = _driver_code(exc)
                        observe_error()
                        continue
                    except (ConsolidatedError, *_NATIVE_BASE_ERRORS):
                        rt.check()
                        unhandled_native_retry = True
                        raise
                    retry_prepared = True
                    break
        finally:
            if not unhandled_native_retry:
                _void(rt, "set_timeout", cleanup=True, milliseconds=prior)
        if cleanup_fault is not None:
            raise cleanup_fault
    observe_error()
    return {
        "writer_completed": completed,
        "programming_completed": False,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "error_code": failure,
        "driver_error": driver_error,
        "native_error_code": 0 if failure is None else failure,
        "initial_error_code": initial_failure,
        "native_error_after_disposal": failure,
        "retry_decisions_consumed": decisions,
        "retry_prepared": retry_prepared,
        "count": count,
        "percent": percent,
        "cleanup_errors": tuple(cleanup_errors),
    }


@dataclass(frozen=True)
class SILEMPSWriteContext:
    identity: NativeModuleIdentity
    kind_of_ecu: str
    first_cpu_type: str
    image: bytes = field(repr=False)
    flash_size: int
    retry_decisions: tuple[bool, ...] = ()

    def __post_init__(self):
        branch = select_branch(
            self.identity, "SIL", self.kind_of_ecu, (self.first_cpu_type,), writing=True
        )
        if (
            branch.family != "sil_emps_write"
            or type(self.image) is not bytes
            or len(self.image) < self.page_count * 1024
            or type(self.flash_size) is not int
            or not 0 < self.flash_size <= 64 * 1024 * 1024
            or type(self.retry_decisions) is not tuple
            or len(self.retry_decisions) > 256
            or any(type(value) is not bool for value in self.retry_decisions)
        ):
            raise ValueError(
                "Safe native SIL EMPS backing, positive FlashSize and bounded retry observations required"
            )

    @property
    def page_count(self) -> int:
        return {"57": 256, "58": 240, "59": 128, "60": 192}.get(self.first_cpu_type, 0)


def bind_sil_emps_writer(
    container, identity: NativeModuleIdentity, *, retry_decisions: tuple[bool, ...] = ()
) -> SILEMPSWriteContext:
    """Bind actual native single-CPU archive; no supplied geometry or image alias."""
    from scripts.calibration_2026 import (
        native2026_archive,
        native2026_cpu_type,
        native2026_metadata,
        native2026_metadata_for_cpu,
    )

    _identity(identity)
    metadata = native2026_metadata(container, node=1, cpu_index=0)
    if metadata.vehicle.get("contacttype", "") != "SIL":
        raise ValueError("Native SIL contact required")
    archive = native2026_archive(native2026_metadata_for_cpu(metadata, 0))
    if (
        archive.data is None
        or type(archive.flash_size) is not int
        or not 0 < archive.flash_size <= 64 * 1024 * 1024
        or len(archive.data)
        < {"57": 256, "58": 240, "59": 128, "60": 192}.get(
            native2026_cpu_type(metadata, 0), 0
        )
        * 1024
    ):
        raise ValueError("Safe native SIL EMPS page backing and FlashSize required")
    return SILEMPSWriteContext(
        identity,
        metadata.vehicle.get("kindofecu", ""),
        native2026_cpu_type(metadata, 0),
        archive.data,
        archive.flash_size,
        retry_decisions,
    )


def write_sil_emps(
    context: SILEMPSWriteContext,
    runtime: NativeRuntime2026,
    *,
    progress=None,
    error_snapshot=None,
) -> dict:
    """20950/20d00/20f40/211d0 connected-session erase and raw page programming.

    Retry decisions are explicit observations of native UI answers. Only raw
    J2534 errors9/16 reconnect and resume the current page. Rejected replies and
    exhausted NAK retries never silently restart or erase the image again.
    """
    driver_error = 0
    if error_snapshot is not None and not callable(error_snapshot):
        raise TypeError("Native error-slot observer must be callable")

    def observe_error():
        if error_snapshot is not None:
            error_snapshot(0 if failure is None else failure, driver_error)

    if (
        not isinstance(context, SILEMPSWriteContext)
        or not isinstance(runtime, NativeRuntime2026)
        or (progress is not None and not callable(progress))
    ):
        raise TypeError(
            "Source-bound SIL EMPS context, native runtime and observer required"
        )
    context.__post_init__()
    rt, diag = runtime, SilDiag2026(runtime)
    if rt.call("get_protocol_id") != 3:
        raise ValueError("Native SIL EMPS writer requires upstream connected protocol3")
    prior, prior_send = rt.call("get_timeout"), rt.call("get_send_timeout")
    if any(
        type(value) is not int or not 0 <= value <= 0xFFFFFFFF
        for value in (prior, prior_send)
    ):
        raise ValueError("Unsigned original receive/send timeouts required")
    target = {"13": 0x32, "14": 0x34}.get(context.kind_of_ecu, 0)
    page = attempted = percent = decisions = reconnects = 0
    failure = 0
    completed = False
    cleanup_errors = []
    initializing = True
    restore_timeouts = True

    def boundary(operation, **values):
        nonlocal restore_timeouts
        try:
            _void(rt, operation, **values)
        except (ConsolidatedError, *_NATIVE_BASE_ERRORS, NativeException2026):
            rt.check()
            # 20950 timeout60000/20b59 sendtimeout20000 and208de connect are
            # outside the worker's native EH scopes; no native timeout restoration.
            restore_timeouts = False
            raise

    def retry(recoverable: bool) -> bool:
        nonlocal decisions, reconnects, failure, driver_error, restore_timeouts
        observe_error()
        while decisions < len(context.retry_decisions):
            accepted = context.retry_decisions[decisions]
            decisions += 1
            if not accepted:
                return False
            if recoverable:
                failure = driver_error = 0
                try:
                    _void(rt, "disconnect")
                except (ConsolidatedError, *_NATIVE_BASE_ERRORS, NativeException2026):
                    rt.check()
                try:
                    boundary("connect", protocol=3)
                except _NATIVE_DRIVER_ERRORS as exc:
                    if not _is_driver_error(exc):
                        raise
                    rt.check()
                    # 20820 state2 catches CJ only, sets disposal context and reasks.
                    restore_timeouts = True
                    failure = _native_enum(exc)
                    driver_error = _driver_code(exc)
                    observe_error()
                    continue
                reconnects += 1
                failure = 0
                return True
            # 20b80/20c58: an accepted nonrecoverable error waits and asks again.
            _void(rt, "wait", milliseconds=3000)
            observe_error()
        return False

    try:
        try:
            diag.fast_init(target, emps=True)
            initializing = False
            boundary("set_timeout", milliseconds=60000)
            erase = diag.packet(
                bytes((0x87, target, 0xF1, 0x9C, 0x0D, 1, 7, 255))
                + context.page_count.to_bytes(2, "big")
            )
            reply = diag.exchange(erase, delay_ms=0, error_code=12)
            if (reply[0] if reply else 0) != 0:
                raise ConsolidatedError(12, "sil_emps_erase")
        except (ConsolidatedError, *_NATIVE_BASE_ERRORS, NativeException2026) as exc:
            rt.check()
            if not restore_timeouts:
                raise
            driver_error = _native_driver_slot(exc, driver_error)
            if (
                _is_driver_error(exc)
                or not initializing
                and isinstance(exc, (ConsolidatedError, *_NATIVE_BASE_ERRORS))
            ):
                failure = (
                    exc.code
                    if isinstance(exc, ConsolidatedError)
                    else _native_enum(exc)
                )
            if initializing:
                # Native state0 catch20c5d→20c7b calls20820(true), then returns.
                retry(True)
            else:
                boundary("set_send_timeout", milliseconds=20000)
                retry(False)
        else:
            boundary("set_send_timeout", milliseconds=20000)
            while page < context.page_count:
                try:
                    # 211d0 resets timeout on every call, including resumed calls.
                    _void(rt, "set_timeout", milliseconds=1000)
                    while page < context.page_count:
                        if page == context.page_count - 1:
                            _void(rt, "set_timeout", milliseconds=10000)
                        resends = 0
                        while True:
                            raw = (
                                bytes((page & 255, 4, 0))
                                + context.image[page * 1024 : (page + 1) * 1024]
                            )
                            diag.write(raw + bytes(((~sum(raw)) & 255,)))
                            reply = diag.read().ljust(2, b"\0")
                            attempted += 1024
                            percent = int(attempted / context.flash_size * 100)
                            if progress is not None:
                                progress("count", attempted * 2)
                                progress("percent", percent)
                            discarded = 0
                            while (
                                reply[0] == 0x82
                                and len(reply) >= 2
                                and reply[1] == page - 1
                                and discarded < 3
                            ):
                                discarded += 1
                                reply = diag.read().ljust(2, b"\0")
                            if reply[0] == 0x82:
                                resends += 1
                                if len(reply) < 2 or reply[1] != page or resends > 3:
                                    raise ConsolidatedError(13, "sil_emps_nak")
                                continue
                            if reply[0] != (2 if page == context.page_count - 1 else 1):
                                raise ConsolidatedError(13, "sil_emps_ack")
                            page += 1
                            break
                except (
                    ConsolidatedError,
                    *_NATIVE_BASE_ERRORS,
                    NativeException2026,
                ) as exc:
                    driver_error = _native_driver_slot(exc, driver_error)
                    rt.check()
                    driver = _is_driver_error(exc)
                    failure = (
                        13
                        if driver
                        else exc.code
                        if isinstance(exc, ConsolidatedError)
                        else _native_enum(exc)
                        if isinstance(exc, _NATIVE_BASE_ERRORS)
                        else failure
                    )
                    if retry(driver and _driver_code(exc) in (9, 16)):
                        continue
                    break
            if page == context.page_count:
                _void(rt, "wait", milliseconds=2500)
                completed, failure = True, None
    finally:
        cleanup_fault = None
        for operation, value in (
            (("set_timeout", prior), ("set_send_timeout", prior_send))
            if restore_timeouts
            else ()
        ):
            try:
                _void(rt, operation, cleanup=True, milliseconds=value)
            except (ConsolidatedError, *_NATIVE_BASE_ERRORS, NativeException2026):
                rt.check()
                raise
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - restore both timeouts before propagating host fault
                cleanup_fault = cleanup_fault or exc
        if cleanup_fault is not None:
            raise cleanup_fault
    observe_error()
    return {
        "writer_completed": completed,
        "programming_completed": False,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "error_code": failure,
        "driver_error": driver_error,
        "native_error_code": 0 if failure is None else failure,
        "pages_written": page,
        "count": attempted * 2,
        "percent": percent,
        "reconnects": reconnects,
        "retry_decisions_consumed": decisions,
        "cleanup_errors": tuple(cleanup_errors),
    }


@dataclass(frozen=True)
class CANFCWriteContext:
    identity: NativeModuleIdentity
    kind_of_ecu: str
    cpu_type: str
    location_id: bytes = field(repr=False)
    prepare_route: SoftwareIDRecord
    password: int = field(repr=False)
    image: bytes = field(repr=False)
    flash_size: int
    security_materials: tuple[bytes, ...] = field(repr=False)
    retry_decisions: tuple[bool, ...] = ()
    cpu_index: int = 0
    cpu_count: int = 1

    def __post_init__(self):
        _identity(self.identity)
        if (
            select_branch(
                self.identity, "CAN", self.kind_of_ecu, (self.cpu_type,), writing=True
            ).family
            != "can_fc_write"
            or type(self.location_id) is not bytes
            or len(self.location_id) != 8
            or not isinstance(self.prepare_route, SoftwareIDRecord)
            or self.prepare_route.extended
            or type(self.password) is not int
            or not 0 <= self.password <= 0xFFFFFFFF
            or type(self.image) is not bytes
            or not 0 < len(self.image) <= 64 * 1024 * 1024
            or type(self.flash_size) is not int
            or not 0 <= self.flash_size <= 64 * 1024 * 1024
            or type(self.security_materials) is not tuple
            or len(self.security_materials) != 4
            or any(
                type(value) is not bytes or len(value) != 2
                for value in self.security_materials
            )
            or type(self.retry_decisions) is not tuple
            or len(self.retry_decisions) > 256
            or any(type(value) is not bool for value in self.retry_decisions)
            or type(self.cpu_index) is not int
            or type(self.cpu_count) is not int
            or not 0 <= self.cpu_index < self.cpu_count <= 256
        ):
            raise ValueError(
                "Source-bound FC CPU, route, archive and explicit native observations required"
            )


def bind_can_fc_writer(
    container,
    identity: NativeModuleIdentity,
    state: ConsolidatedControllerState,
    attachments,
    *,
    cpu_index: int = 0,
    target_index: int = 0,
    retry_decisions: tuple[bool, ...] = (),
) -> CANFCWriteContext:
    """Bind actual global CPU/TargetData/LocationID/archive plus prior software route.

    Source1c380 passes a null password-state pointer;1ca40 CheckID always reads
    TargetData.password directly, independently of the controller password byte.
    """
    from collections.abc import Mapping

    from scripts.calibration_2026 import (
        native2026_archive,
        native2026_cpu_count,
        native2026_cpu_targets,
        native2026_cpu_type,
        native2026_location_id,
        native2026_metadata,
        native2026_metadata_for_cpu,
    )

    _identity(identity)
    if (
        not isinstance(state, ConsolidatedControllerState)
        or not isinstance(attachments, Mapping)
        or set(attachments) != {"fc_security_materials"}
    ):
        raise ValueError(
            "Native prior software routes and explicit FC security materials required"
        )
    state.__post_init__()
    metadata = native2026_metadata(container)
    count = native2026_cpu_count(metadata)
    if (
        type(cpu_index) is not int
        or not 0 <= cpu_index < count <= 256
        or type(target_index) is not int
        or target_index < 0
    ):
        raise ValueError("Actual selected native CPU and target indices required")
    cpu_types = tuple(native2026_cpu_type(metadata, index) for index in range(count))
    branch = select_branch(
        identity,
        metadata.vehicle.get("contacttype", ""),
        metadata.vehicle.get("kindofecu", ""),
        cpu_types,
        cpu_index=cpu_index,
        writing=True,
    )
    if branch.family != "can_fc_write":
        raise ValueError("Imported metadata does not select native FC writer")
    targets = native2026_cpu_targets(metadata, cpu_index)
    if target_index >= len(targets):
        raise ValueError("Selected native TargetData row absent")
    target = targets[target_index]
    route = next(
        (
            row
            for row in state.software_id_records
            if row.identifier == target.calibration
        ),
        None,
    )
    if route is None:
        raise ValueError(
            "Native TargetCalibration has no prior matching software route"
        )
    location_text = native2026_location_id(metadata, cpu_index)
    if len(location_text) != 16 or any(
        char not in "0123456789abcdefABCDEF" for char in location_text
    ):
        raise ValueError(
            "Actual native LocationID must contain sixteen hexadecimal digits"
        )
    selected = native2026_metadata_for_cpu(metadata, cpu_index)
    archive = native2026_archive(selected)
    if archive.streamed or type(archive.data) is not bytes:
        raise ValueError(
            "Native FC selected archive requires its actual materialized byte producer"
        )
    password = target.password
    return CANFCWriteContext(
        identity,
        metadata.vehicle.get("kindofecu", ""),
        cpu_types[cpu_index],
        bytes.fromhex(location_text),
        route,
        password,
        archive.data,
        archive.flash_size,
        attachments["fc_security_materials"],
        retry_decisions,
        cpu_index,
        count,
    )


def write_can_fc(
    context: CANFCWriteContext,
    runtime: NativeRuntime2026,
    *,
    progress=None,
    error_snapshot=None,
    progress_snapshot=None,
    counts=None,
    percentages=None,
) -> dict:
    """1ca40/c3f0 normal FC worker plus source block-disposal/retry continuations.

    The context carries the actual selected TargetData password value. Retry observations never replace a business operation.
    """
    driver_error = 0
    if error_snapshot is not None and not callable(error_snapshot):
        raise TypeError("Native error-slot observer must be callable")

    def observe_error():
        if error_snapshot is not None:
            error_snapshot(0 if failure is None else failure, driver_error)

    if (
        not isinstance(context, CANFCWriteContext)
        or not isinstance(runtime, NativeRuntime2026)
        or progress is not None
        and not callable(progress)
    ):
        raise TypeError("Native FC context, runtime and progress observer required")
    context.__post_init__()
    if progress_snapshot is not None and not callable(progress_snapshot):
        raise TypeError("Native progress vector observer must be callable")
    rt = runtime
    if rt.call("get_protocol_id") != 6:
        raise ValueError("Native FC writer requires upstream connected protocol6")
    native_counts = (
        [0] * context.cpu_count
        if counts is None
        else counts
        if type(counts) is list
        else list(counts)
    )
    native_percentages = (
        [0] * context.cpu_count
        if percentages is None
        else percentages
        if type(percentages) is list
        else list(percentages)
    )
    channel = ConsolidatedCAN2026(rt)
    request, response, finish_request = consolidated_location_addresses(
        context.location_id
    )
    prepare_request, prepare_response = (
        b"\0\0" + context.prepare_route.request,
        b"\0\0" + context.prepare_route.response,
    )
    diag = ConsolidatedCanDiag2026(rt)
    decisions = restarts = 0
    failure = None
    completed = retry_prepared = False
    cleanup_errors = []
    swallowed_native_faults = []

    def notify(field):
        if progress_snapshot is not None:
            progress_snapshot(
                field,
                tuple(native_counts if field == "count" else native_percentages),
                context.cpu_index,
            )
        if progress is not None:
            progress(
                field,
                (native_counts if field == "count" else native_percentages)[
                    context.cpu_index
                ],
            )

    channel.common._progress(
        context.cpu_index, native_counts, native_percentages, notify
    )
    if len(native_counts) != context.cpu_count:
        raise ValueError("Native global CPU progress vector size differs")
    # 6020 preserves prior CPU entries and zeros selected/later entries.
    native_counts[context.cpu_index :] = [0] * (context.cpu_count - context.cpu_index)
    native_percentages[context.cpu_index :] = [0] * (
        context.cpu_count - context.cpu_index
    )

    def release_native_filter(handle, phase="stop_filter"):
        try:
            rt.release("stop_filter", identifier=handle)
        except (ConsolidatedError, *_NATIVE_BASE_ERRORS, NativeException2026) as exc:
            # 35300 states12/21 CatchAll continue normally after native cleanup faults.
            rt.check()
            cleanup_errors.append(type(exc).__name__)
            swallowed_native_faults.append(phase)

    def disconnect_reconnect():
        try:
            _void(rt, "disconnect")
        except (*_NATIVE_BASE_ERRORS, NativeException2026):
            # d1a1/d3e9 are explicit native CatchAll disconnect continuations.
            rt.check()
        _void(rt, "connect", protocol=6)

    def accepted():
        nonlocal decisions, driver_error
        observe_error()
        if decisions >= len(context.retry_decisions):
            return False
        value = context.retry_decisions[decisions]
        decisions += 1
        if value:
            driver_error = 0
        return value

    while True:
        in_block = in_prepare = False
        try:
            if not restarts:
                _void(rt, "wait", milliseconds=1000)
                in_prepare = True
                handle = diag.start_filter(prepare_request, prepare_response)
                try:
                    channel.fc_security_access(
                        prepare_request, prepare_response, context.security_materials
                    )
                    _void(rt, "wait", milliseconds=100)
                    for _ in range(3):
                        diag.write(finish_request + b"\xa0\x27")
                        _void(rt, "wait", milliseconds=100)
                    diag.call(
                        prepare_request,
                        prepare_response,
                        b"\x10\x02",
                        b"\x50",
                        minimum=1,
                        error_code=18,
                    )
                    if prepare_request[2:] in (b"\x07\x24", b"\x07\xd3"):
                        _void(rt, "wait", milliseconds=110)
                        diag.call(
                            prepare_request,
                            prepare_response,
                            b"\x10\x02",
                            b"\x50",
                            minimum=1,
                            error_code=18,
                        )
                finally:
                    release_native_filter(handle, "prepare_stop_filter")
                in_prepare = False
            handle = diag.start_filter(request, response)
            try:
                if not restarts:
                    _void(rt, "wait", milliseconds=500)
                    channel.check_id(
                        request, response, context.location_id, context.password
                    )
                memory = channel.get_memory_info(request, response)
                if not consolidated_firmware_matches(
                    context.cpu_type, memory.firmware_version, channel.native_context_6c
                ):
                    raise ConsolidatedError(10, "fc_firmware")
                sizes = consolidated_block_sizes(context.cpu_type, memory)
                for first, last in consolidated_block_ranges(
                    context.cpu_type, len(sizes)
                ):
                    in_block = True
                    if not channel.block("blank", request, response, first, last):
                        channel.block("erase", request, response, first, last)
                    channel.write_block(
                        request,
                        response,
                        first,
                        last,
                        sizes,
                        memory,
                        context.image,
                        native_counts,
                        native_percentages,
                        notify,
                        cpu_index=context.cpu_index,
                        total_size=context.flash_size,
                    )
                    channel.block("inverify", request, response, first, last)
                    channel.verify_block(
                        request,
                        response,
                        first,
                        last,
                        sizes,
                        context.image,
                        native_counts,
                        native_percentages,
                        notify,
                        cpu_index=context.cpu_index,
                        total_size=context.flash_size,
                    )
                    in_block = False
                try:
                    channel.finish(finish_request, response)
                except (ConsolidatedError, *_NATIVE_BASE_ERRORS, NativeException2026):
                    # State10 ALLce94 still selects the normal completion callback.
                    rt.check()
                    swallowed_native_faults.append("finish")
                completed = True
            finally:
                release_native_filter(handle)
            break
        except (ConsolidatedError, *_NATIVE_BASE_ERRORS, NativeException2026) as exc:
            driver_error = _native_driver_slot(exc, driver_error)
            rt.check()
            if isinstance(exc, NativeException2026) and not isinstance(
                exc, _NATIVE_BASE_ERRORS
            ):
                if not in_prepare:
                    raise
                # State0 CatchAll retains the worker's initialized native error0.
                failure = 0
                driver_error = 0
            else:
                failure = (
                    exc.code
                    if isinstance(exc, ConsolidatedError)
                    else _native_enum(exc)
                )
            if not in_block:
                while accepted():
                    try:
                        disconnect_reconnect()
                        retry_prepared, failure = True, None
                    except _NATIVE_BASE_ERRORS as retry_error:
                        driver_error = _native_driver_slot(retry_error, driver_error)
                        rt.check()
                        failure = _native_enum(retry_error)
                        continue
                    break
                break
            # d138..d166 resets count/callback then percent/callback before retry UI.
            while True:
                native_counts[context.cpu_index] = 0
                channel.common._observe(notify, "count")
                native_percentages[context.cpu_index] = 0
                channel.common._observe(notify, "percent")
                if not accepted():
                    break
                try:
                    disconnect_reconnect()
                    handle = diag.start_filter(request, response)
                    try:
                        channel.dispose_write_error(request, response, failure)
                    finally:
                        release_native_filter(handle)
                except (ConsolidatedError, *_NATIVE_BASE_ERRORS) as dispose_error:
                    driver_error = _native_driver_slot(dispose_error, driver_error)
                    rt.check()
                    failure = (
                        dispose_error.code
                        if isinstance(dispose_error, ConsolidatedError)
                        else _native_enum(dispose_error)
                    )
                    continue
                failure = None
                restarts += 1
                break
            if failure is not None:
                break
    observe_error()
    return {
        "writer_completed": completed,
        "completion_callback": "normal" if completed else "error",
        "swallowed_native_faults": tuple(swallowed_native_faults),
        "programming_completed": False,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "error_code": failure,
        "driver_error": driver_error,
        "native_error_code": 0 if failure is None else failure,
        "retry_prepared": retry_prepared,
        "restarts": restarts,
        "retry_decisions_consumed": decisions,
        "counts": tuple(native_counts),
        "percentages": tuple(native_percentages),
        "count": native_counts[context.cpu_index],
        "percent": native_percentages[context.cpu_index],
        "cleanup_errors": tuple(cleanup_errors),
    }


@dataclass(frozen=True)
class CANEPBWriteContext:
    identity: NativeModuleIdentity
    location_id: bytes = field(repr=False)
    password: int = field(repr=False)
    image: bytes = field(repr=False)
    flash_size: int
    security_materials: tuple[bytes, ...] = field(repr=False)
    cpu_type: str = "27"
    recovery_timeout: bool = False
    retry_decisions: tuple[bool, ...] = ()
    cpu_index: int = 0
    cpu_count: int = 1

    def __post_init__(self):
        _identity(self.identity)
        if (
            type(self.location_id) is not bytes
            or len(self.location_id) != 8
            or type(self.password) is not int
            or not 0 <= self.password <= 0xFFFFFFFF
            or type(self.image) is not bytes
            or not 0 < len(self.image) <= 64 * 1024 * 1024
            or type(self.flash_size) is not int
            or not 0 <= self.flash_size <= 64 * 1024 * 1024
            or type(self.security_materials) is not tuple
            or len(self.security_materials) != 4
            or any(
                type(value) is not bytes or len(value) != 2
                for value in self.security_materials
            )
            or type(self.cpu_type) is not str
            or self.cpu_type not in {cpu for cpu, _ in _FIRMWARE_CPU_WORDS[1]}
            or type(self.recovery_timeout) is not bool
            or type(self.retry_decisions) is not tuple
            or len(self.retry_decisions) > 256
            or any(type(value) is not bool for value in self.retry_decisions)
            or type(self.cpu_index) is not int
            or type(self.cpu_count) is not int
            or not 0 <= self.cpu_index < self.cpu_count <= 256
        ):
            raise ValueError(
                "Native EPB location, archive, security and retry observations required"
            )


def bind_can_epb_writer(
    container,
    identity: NativeModuleIdentity,
    attachments,
    *,
    cpu_index: int = 0,
    target_index: int = 0,
    recovery_timeout: bool = False,
    retry_decisions: tuple[bool, ...] = (),
) -> CANEPBWriteContext:
    """1ae80 consumes selected global CPU/TargetData/archive, not getter route overrides."""
    from collections.abc import Mapping

    from scripts.calibration_2026 import (
        native2026_archive,
        native2026_cpu_count,
        native2026_cpu_targets,
        native2026_cpu_type,
        native2026_location_id,
        native2026_metadata,
        native2026_metadata_for_cpu,
    )

    _identity(identity)
    if not isinstance(attachments, Mapping) or set(attachments) != {
        "epb_security_materials"
    }:
        raise ValueError(
            "Only explicit authorized EPB conversion materials are accepted"
        )
    metadata = native2026_metadata(container)
    count = native2026_cpu_count(metadata)
    if (
        type(cpu_index) is not int
        or not 0 <= cpu_index < count <= 256
        or type(target_index) is not int
        or target_index < 0
    ):
        raise ValueError("Actual selected global CPU and TargetData indices required")
    cpu_types = tuple(native2026_cpu_type(metadata, index) for index in range(count))
    if (
        select_branch(
            identity,
            metadata.vehicle.get("contacttype", ""),
            metadata.vehicle.get("kindofecu", ""),
            cpu_types,
            writing=True,
            cpu_index=cpu_index,
        ).family
        != "can_epb_write"
    ):
        raise ValueError("Imported metadata does not select native EPB writer")
    # The worker indexes the selected CPU table after first-CPU dispatch.
    if cpu_types[cpu_index] not in {cpu for cpu, _ in _FIRMWARE_CPU_WORDS[1]}:
        raise ValueError("Selected native EPB CPU is absent from its firmware table")
    targets = native2026_cpu_targets(metadata, cpu_index)
    if target_index >= len(targets):
        raise ValueError("Selected native TargetData row absent")
    location = native2026_location_id(metadata, cpu_index)
    if len(location) != 16 or any(
        char not in "0123456789abcdefABCDEF" for char in location
    ):
        raise ValueError("Actual native LocationID requires sixteen hexadecimal digits")
    archive = native2026_archive(native2026_metadata_for_cpu(metadata, cpu_index))
    if archive.streamed or type(archive.data) is not bytes:
        raise ValueError("EPB requires the actual materialized selected archive")
    return CANEPBWriteContext(
        identity,
        bytes.fromhex(location),
        targets[target_index].password,
        archive.data,
        archive.flash_size,
        attachments["epb_security_materials"],
        cpu_types[cpu_index],
        recovery_timeout,
        retry_decisions,
        cpu_index,
        count,
    )


def write_can_epb(
    context: CANEPBWriteContext,
    runtime: NativeRuntime2026,
    *,
    progress=None,
    error_snapshot=None,
    progress_snapshot=None,
    counts=None,
    percentages=None,
) -> dict:
    """1a4a0/1ae80 EPB preparation and per-block worker, plus1ab50 reconnect UI."""
    driver_error = 0
    if error_snapshot is not None and not callable(error_snapshot):
        raise TypeError("Native error-slot observer must be callable")

    def observe_error():
        if error_snapshot is not None:
            error_snapshot(0 if failure is None else failure, driver_error)

    if (
        not isinstance(context, CANEPBWriteContext)
        or not isinstance(runtime, NativeRuntime2026)
        or progress is not None
        and not callable(progress)
    ):
        raise TypeError("Native EPB context, runtime and progress observer required")
    context.__post_init__()
    if progress_snapshot is not None and not callable(progress_snapshot):
        raise TypeError("Native progress vector observer must be callable")
    rt = runtime
    if rt.call("get_protocol_id") != 6:
        raise ValueError("EPB requires upstream connected protocol6")
    prior = rt.call("get_timeout")
    if type(prior) is not int or not 0 <= prior <= 0xFFFFFFFF:
        raise ValueError("Native unsigned receive timeout required")
    channel, diag = ConsolidatedCAN2026(rt), ConsolidatedCanDiag2026(rt)
    request, response, finish_request = consolidated_location_addresses(
        context.location_id
    )
    prepare_request, prepare_response = (
        bytes.fromhex("000007502c"),
        bytes.fromhex("000007582c"),
    )
    native_counts = (
        [0] * context.cpu_count
        if counts is None
        else counts
        if type(counts) is list
        else list(counts)
    )
    native_percentages = (
        [0] * context.cpu_count
        if percentages is None
        else percentages
        if type(percentages) is list
        else list(percentages)
    )

    def notify(field):
        if progress_snapshot is not None:
            progress_snapshot(
                field,
                tuple(native_counts if field == "count" else native_percentages),
                context.cpu_index,
            )
        if progress is not None:
            progress(
                field,
                (native_counts if field == "count" else native_percentages)[
                    context.cpu_index
                ],
            )

    channel.common._progress(
        context.cpu_index, native_counts, native_percentages, notify
    )
    if len(native_counts) != context.cpu_count:
        raise ValueError("Native global CPU progress vector size differs")
    native_counts[context.cpu_index :] = [0] * (context.cpu_count - context.cpu_index)
    native_percentages[context.cpu_index :] = [0] * (
        context.cpu_count - context.cpu_index
    )
    completed = retry_prepared = False
    failure = None
    decisions = 0
    swallowed = []

    def release(handle, phase):
        try:
            rt.release("stop_filter", identifier=handle)
        except (ConsolidatedError, *_NATIVE_BASE_ERRORS, NativeException2026):
            rt.check()
            # Explicit ALL scopes1a727/1b320 preserve existing worker BOOL/error.
            swallowed.append(phase)

    def native_code(exc):
        return exc.code if isinstance(exc, ConsolidatedError) else _native_enum(exc)

    def retry():
        nonlocal decisions, retry_prepared, failure, driver_error
        observe_error()
        while decisions < len(context.retry_decisions):
            accepted = context.retry_decisions[decisions]
            decisions += 1
            if not accepted:
                break
            failure = 0
            driver_error = 0
            try:
                _void(rt, "disconnect")
            except (*_NATIVE_BASE_ERRORS, NativeException2026):
                rt.check()
                swallowed.append("disconnect")
            try:
                _void(rt, "connect", protocol=6)
            except _NATIVE_DRIVER_ERRORS as exc:
                driver_error = _native_driver_slot(exc, driver_error)
                if not _is_driver_error(exc):
                    raise
                rt.check()
                failure = _native_enum(exc)
                observe_error()
                continue
            retry_prepared = True
            break

    try:
        prepare_failed = False
        handle = None
        try:
            handle = diag.start_filter(prepare_request, prepare_response)
            channel.epb_security_access(
                prepare_request, prepare_response, context.security_materials
            )
            _void(rt, "wait", milliseconds=100)
            for _ in range(3):
                diag.write(finish_request + b"\xa0\x27")
                _void(rt, "wait", milliseconds=100)
            diag.call(
                prepare_request,
                prepare_response,
                b"\x10\x02",
                b"\x50",
                minimum=1,
                error_code=18,
            )
        except (ConsolidatedError, *_NATIVE_BASE_ERRORS) as exc:
            driver_error = _native_driver_slot(exc, driver_error)
            rt.check()
            failure, prepare_failed = native_code(exc), True
        finally:
            if handle is not None:
                release(handle, "prepare_stop_filter")
        if prepare_failed:
            retry()
        else:
            prior = rt.call("get_timeout")
            if type(prior) is not int or not 0 <= prior <= 0xFFFFFFFF:
                raise ValueError("Native unsigned receive timeout required")
            _void(
                rt,
                "set_timeout",
                milliseconds=10000 if context.recovery_timeout else 120000,
            )
            handle = None
            try:
                handle = diag.start_filter(request, response)
                _void(rt, "wait", milliseconds=500)
                channel.check_id(
                    request, response, context.location_id, context.password
                )
                memory = channel.get_epb_memory_info(request, response)
                if not consolidated_firmware_matches(
                    context.cpu_type, memory.firmware_version, False, wide=True
                ):
                    raise ConsolidatedError(10, "epb_firmware")
                sizes = consolidated_block_sizes(context.cpu_type, memory)
                for block in range(1, len(sizes) + 1):
                    channel.erase_epb_block(request, response, block)
                    channel.write_epb_block(
                        request,
                        response,
                        block,
                        sizes,
                        memory,
                        context.image,
                        native_counts,
                        native_percentages,
                        notify,
                        cpu_index=context.cpu_index,
                        total_size=context.flash_size,
                    )
                    channel.verify_epb_block(
                        request,
                        response,
                        block,
                        sizes,
                        context.image,
                        native_counts,
                        native_percentages,
                        notify,
                        cpu_index=context.cpu_index,
                        total_size=context.flash_size,
                    )
                try:
                    channel.finish(finish_request, response)
                except (ConsolidatedError, *_NATIVE_BASE_ERRORS, NativeException2026):
                    rt.check()
                    swallowed.append("finish")
                completed = True
            except (ConsolidatedError, *_NATIVE_BASE_ERRORS) as exc:
                driver_error = _native_driver_slot(exc, driver_error)
                rt.check()
                failure = native_code(exc)
                # 1b254/1b2d8 reset selected counters before error UI, no progress callbacks.
                native_counts[context.cpu_index] = native_percentages[
                    context.cpu_index
                ] = 0
            finally:
                if handle is not None:
                    release(handle, "stop_filter")
            if failure is not None:
                retry()
    finally:
        _void(rt, "set_timeout", cleanup=True, milliseconds=prior)
    observe_error()
    return {
        "writer_completed": completed,
        "completion_callback": "normal" if completed else "error",
        "programming_completed": False,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "error_code": failure,
        "driver_error": driver_error,
        "native_error_code": 0 if failure is None else failure,
        "retry_prepared": retry_prepared,
        "retry_decisions_consumed": decisions,
        "swallowed_native_faults": tuple(swallowed),
        "counts": tuple(native_counts),
        "percentages": tuple(native_percentages),
    }


class ConsolidatedSILBootError(NativeException2026):
    """0ef30 native CException subtype with reason DWORD+18, not a CPass enum."""

    def __init__(self, reason: int):
        if type(reason) is not int or reason not in (1, 2):
            raise ValueError("Native SIL boot error reason1/2 required")
        self.reason = reason
        super().__init__("")


class ConsolidatedSILFlash2026:
    """Shared consolidated raw SIL programming, without diagnostic packet framing."""

    def __init__(self, runtime: NativeRuntime2026):
        if not isinstance(runtime, NativeRuntime2026):
            raise TypeError("Native consolidated primitive runtime required")
        self.runtime = runtime
        self.count = self.percent = 0
        self.memory_shrink: bool | None = None

    def _write(self, *messages: bytes):
        if not messages or any(
            type(data) is not bytes or not 0 < len(data) <= 4128 for data in messages
        ):
            raise ValueError("Bounded immutable raw SIL messages required")
        if len(messages) == 1:
            result = self.runtime.call(
                "write_messages", protocol=3, tx_flags=0, count=1, data=messages[0]
            )
        else:
            result = self.runtime.call(
                "write_messages",
                protocol=3,
                tx_flags=0,
                count=len(messages),
                messages=messages,
            )
        if type(result) is not int or result != len(messages):
            raise ValueError("Raw SIL primitive must accept every native message")

    def read_exact(self, count: int) -> bytes:
        """11da0 truncates each message to remaining count and discards its excess."""
        if type(count) is not int or not 0 <= count <= 4128:
            raise ValueError("Bounded native raw read size required")
        result = bytearray()
        for _ in range(4096):
            if len(result) == count:
                return bytes(result)
            value = self.runtime.call("read_after_indication", count=1)
            if type(value) is not bytes or len(value) > 4128:
                raise ValueError("Bounded immutable raw SIL Data required")
            result.extend(value[: count - len(result)])
        raise TimeoutError("Host raw SIL read bound exceeded")

    def enter_programming(self, location_id: bytes, password: int, *, p2_max: int = 80):
        """10ad0 timing70/80, exact10-byte FAST_INIT, optional raw drain and3c."""
        from scripts.j2534_2026 import NativeMessage

        if (
            type(location_id) is not bytes
            or len(location_id) != 8
            or type(password) is not int
            or not 0 <= password <= 0xFFFFFFFF
            or type(p2_max) is not int
            or p2_max not in (80, 170)
        ):
            raise ValueError("Actual native LocationID and password DWORD required")
        for key, value in ((0x14, 70), (0x15, p2_max)):
            _void(self.runtime, "control_io", ioctl=2, parameters=((key, value),))
        data = b"\0\0" + location_id[:4][::-1] + password.to_bytes(4, "little")
        response = self.runtime.call("fast_init", data=data, tx_flags=0)
        if not isinstance(response, NativeMessage) or response.protocol_id != 3:
            raise ValueError("Programming FAST_INIT must return raw native SIL message")
        if _consolidated_indication(self.runtime, response.rx_status) != 3:
            value = self.runtime.call("read_messages", count=1)
            if type(value) is not bytes or len(value) > 4128:
                raise ValueError("Bounded immutable native FAST_INIT drain required")
        self._write(b"\x3c")

    def _receive_ack(self) -> bool:
        """11ca0 scans raw first byte;9/16 driver read fault returnsfalse."""
        for _ in range(4096):
            try:
                value = self.runtime.call("read_after_indication", count=1)
            except _NATIVE_DRIVER_ERRORS as exc:
                if _is_driver_error(exc) and _driver_code(exc) in (9, 16):
                    return False
                raise
            if type(value) is not bytes or len(value) > 4128:
                raise ValueError("Bounded immutable native raw ACK required")
            if value and value[0] == 0x3C:
                return True
        raise TimeoutError("Host raw SIL acknowledgment read bound exceeded")

    def select_programming_mode(self, mode: int):
        """11e70 raw60/response/mode/ACK/100ms/05/ACK;ff andother boot reasons."""
        if type(mode) is not int or not 0 <= mode <= 0xFFFFFFFF:
            raise ValueError("Native unsigned programming-mode selector required")
        self._write(b"\x60")
        response = self.read_exact(1)[0]
        if response != 0x3C:
            raise ConsolidatedSILBootError(1 if response == 255 else 2)
        self._write(bytes(((0, 1, 2, 3, 4, 6)[mode] if mode < 6 else 0,)))
        if not self._receive_ack():
            raise ConsolidatedError(5, "sil_programming_mode")
        _void(self.runtime, "wait", milliseconds=100)
        self._write(b"\x05")
        if not self._receive_ack():
            raise ConsolidatedError(5, "sil_programming_mode")

    def get_status(self, retry: bool = True) -> int:
        """119c0: one or three50/read3 attempts; only readCPass faults are retried."""
        if type(retry) is not bool:
            raise ValueError("Literal native status retry byte required")
        attempts = 3 if retry else 1
        for index in range(attempts):
            if index:
                _void(self.runtime, "wait", milliseconds=10)
            self._write(b"\x50")
            try:
                value = self.read_exact(3)
            except (ConsolidatedError, *_NATIVE_BASE_ERRORS):
                if index + 1 == attempts:
                    raise
                continue
            if value[0] == value[2] == 0x3C:
                return value[1]
            if index + 1 == attempts:
                raise ConsolidatedError(4, "sil_status_frame")
        raise AssertionError("Native status attempt loop must return or throw")

    def memory_info(self):
        """11700/11865 discover75→76 or retain the actual native format byte."""
        from scripts.programming_2026_common import extract_memory_info

        selected = self.memory_shrink
        self._write(b"\x76" if selected else b"\x75")
        if selected is None:
            try:
                value = self.read_exact(10)
            except (ConsolidatedError, *_NATIVE_BASE_ERRORS, NativeException2026):
                self.runtime.check()
                value = bytes(10)
            if value[0] == value[9] == 0x3C:
                selected = False
            else:
                self._write(b"\x76")
                value = self.read_exact(11)
                selected = True
        else:
            value = self.read_exact(11 if selected else 10)
        if value[0] != 0x3C or value[10 if selected else 9] != 0x3C:
            raise ConsolidatedError(10, "sil_memory_frame")
        self.memory_shrink = selected
        # Native bf70 receives an eight-byte CBytes even from the76 eleven-byte reply.
        return extract_memory_info(value[1:9])

    def block(
        self, operation: str, block_number: int, *, last_block: int | None = None
    ) -> bool:
        """109b0/10d70/11b60 raw35/25/47 and exact10ms busy bytes."""
        from scripts.programming_2026_legacy import _mapped_transport

        if (
            operation not in ("blank", "erase", "inverify")
            or type(block_number) is not int
            or not 1 <= block_number <= (256 if last_block is None else 65536)
            or last_block is not None
            and (type(last_block) is not int or not block_number <= last_block <= 65536)
        ):
            raise ValueError(
                "Native raw SIL block operation and one-byte block required"
            )
        opcode, pending, error = {
            "blank": (0x35, 0x10, 11),
            "erase": (0x25, 0x80, 12),
            "inverify": (0x47, 0x40, 14),
        }[operation]
        try:
            if last_block is None:
                self._write(bytes((opcode, block_number - 1)))
            else:
                opcode = {"blank": 0x36, "erase": 0x26, "inverify": 0x48}[operation]
                self._write(
                    bytes((opcode,))
                    + (block_number - 1).to_bytes(2, "big")
                    + (last_block - 1).to_bytes(2, "big")
                )
            if not self._receive_ack():
                raise ConsolidatedError(error, "sil_block_ack")
            for _ in range(4096):
                _void(self.runtime, "wait", milliseconds=10)
                status = self.get_status()
                if status == pending:
                    continue
                if operation == "blank":
                    return status == 0
                if status:
                    raise ConsolidatedError(error, "sil_block_status")
                return True
            raise TimeoutError("Host raw SIL block poll bound exceeded")
        except _NATIVE_DRIVER_ERRORS as exc:
            if not _is_driver_error(exc):
                raise
            raise _mapped_transport(exc, error) from exc

    def _progress(self, size: int, total_size: int, observer):
        self.count += size
        if observer is not None:
            self.runtime.check()
            observer("count", self.count)
            self.runtime.check()
        self.percent = consolidated_progress_percent(self.count, total_size)
        if observer is not None:
            self.runtime.check()
            observer("percent", self.percent)
            self.runtime.check()

    def write_block(
        self,
        block_number: int,
        sizes: tuple[int, ...],
        memory,
        image: bytes,
        total_size: int,
        *,
        progress=None,
        last_block: int | None = None,
    ):
        """12a20/12ef0 four256-byte messages per write group; first carriesaddress."""
        from scripts.programming_2026_common import NativeMemoryInfo
        from scripts.programming_2026_legacy import CommonFlash2026, _mapped_transport

        if (
            not isinstance(memory, NativeMemoryInfo)
            or progress is not None
            and not callable(progress)
        ):
            raise ValueError("Native SIL memory and progress observer required")
        if last_block is None and (
            type(block_number) is not int or not 1 <= block_number <= 255
        ):
            raise ValueError(
                "Native classic SIL transfer requires nonzero one-byte block index"
            )
        offset, extent = CommonFlash2026._geometry(
            block_number,
            block_number if last_block is None else last_block,
            sizes,
            image,
            1024,
        )
        consolidated_progress_percent(self.count, total_size)
        address = memory.start_address + offset
        if not 0 <= address <= 0xFFFFFF or self.count + extent > 0xFFFFFFFF:
            raise ValueError("Native SIL write address/count exceeds representation")
        try:
            self._write(b"\x41")
            if not self._receive_ack():
                raise ConsolidatedError(13, "sil_write_ack")
            for group in range(0, extent, 1024):
                if group:
                    self._write(b"\x45")
                    if not self._receive_ack():
                        raise ConsolidatedError(13, "sil_write_ack")
                for packet in range(0, 1024, 256):
                    prefix = (
                        address.to_bytes(3, "big") + b"\xff"
                        if not group and not packet
                        else b""
                    )
                    data = (
                        prefix
                        + image[offset + group + packet : offset + group + packet + 256]
                    )
                    _void(self.runtime, "set_send_timeout", milliseconds=10000)
                    try:
                        self._write(data)
                    except (
                        ConsolidatedError,
                        *_NATIVE_BASE_ERRORS,
                        NativeException2026,
                    ):
                        raise
                    except (Exception, KeyboardInterrupt):
                        # Host abort restores transient setting; native12ef0 has no such EH.
                        _void(
                            self.runtime,
                            "set_send_timeout",
                            cleanup=True,
                            milliseconds=1000,
                        )
                        raise
                    _void(self.runtime, "set_send_timeout", milliseconds=1000)
                    self._progress(256, total_size, progress)
                _void(self.runtime, "set_timeout", milliseconds=2000)
                self._receive_ack()  # Native explicitly ignores this BOOL.
                _void(self.runtime, "set_timeout", milliseconds=1000)
                for _ in range(4096):
                    _void(self.runtime, "wait", milliseconds=5)
                    status = self.get_status()
                    if status == 0x40:
                        continue
                    if status:
                        raise ConsolidatedError(13, "sil_write_status")
                    break
                else:
                    raise TimeoutError("Host raw SIL write status bound exceeded")
        except _NATIVE_DRIVER_ERRORS as exc:
            if not _is_driver_error(exc):
                raise
            raise _mapped_transport(exc, 13) from exc

    def verify_block(
        self,
        block_number: int,
        sizes: tuple[int, ...],
        image: bytes,
        total_size: int,
        *,
        progress=None,
        last_block: int | None = None,
    ):
        """12600 raw15/block then256-byte packets; nonfinal CPass status fault skipsahead."""
        from scripts.programming_2026_legacy import CommonFlash2026, _mapped_transport

        if progress is not None and not callable(progress):
            raise ValueError("Native progress observer required")
        if last_block is None and (
            type(block_number) is not int or not 1 <= block_number <= 255
        ):
            raise ValueError(
                "Native classic SIL transfer requires nonzero one-byte block index"
            )
        offset, extent = CommonFlash2026._geometry(
            block_number,
            block_number if last_block is None else last_block,
            sizes,
            image,
            256,
        )
        consolidated_progress_percent(self.count, total_size)
        if self.count + extent > 0xFFFFFFFF:
            raise ValueError("Native SIL verify count exceeds representation")
        try:
            if last_block is None:
                self._write(bytes((0x15, block_number - 1)))
            else:
                self._write(
                    b"\x16"
                    + (block_number - 1).to_bytes(2, "big")
                    + (last_block - 1).to_bytes(2, "big")
                )
            if not self._receive_ack():
                raise ConsolidatedError(15, "sil_verify_ack")
            for packet in range(0, extent, 256):
                self._write(image[offset + packet : offset + packet + 256])
                self._progress(256, total_size, progress)
                self._receive_ack()  # Native explicitly ignores this BOOL.
                final = packet + 256 == extent
                for _ in range(4096):
                    _void(self.runtime, "wait", milliseconds=5)
                    try:
                        status = self.get_status(final)
                    except (ConsolidatedError, *_NATIVE_BASE_ERRORS):
                        if final:
                            raise
                        # 12963 jumps directly to the next packet, unlike CAN'sretainedstatus.
                        break
                    if status == 0x20:
                        continue
                    if status:
                        raise ConsolidatedError(15, "sil_verify_status")
                    break
                else:
                    raise TimeoutError("Host raw SIL verify status bound exceeded")
        except _NATIVE_DRIVER_ERRORS as exc:
            if not _is_driver_error(exc):
                raise
            raise _mapped_transport(exc, 15) from exc

    def discover_baud(self, cpu_type: str) -> int:
        """121f0 literal9600/9800/10000 and100 mode/memory/blank probes per candidate."""
        probe, preferred, _ = consolidated_sil_cpu_mode(cpu_type)
        self.memory_shrink = None if probe else preferred
        previous_baud_failure = False
        rates = (9600, 9800, 10000)
        for candidate, baud in enumerate(rates):
            try:
                _void(self.runtime, "control_io", ioctl=2, parameters=((1, baud),))
                iteration = first_attempts = 0
                while iteration < 100:
                    if iteration == 0:
                        first_attempts += 1
                    try:
                        self.select_programming_mode(0)
                    except ConsolidatedSILBootError as exc:
                        if (
                            exc.reason == 1
                            and iteration == 0
                            and candidate > 0
                            and first_attempts < 2
                            and previous_baud_failure
                        ):
                            continue
                        previous_baud_failure = True
                        raise ConsolidatedError(5, "sil_baud_mode") from exc
                    previous_baud_failure = False
                    iteration += 1
                memory = self.memory_info()
                for _ in range(99):
                    self.memory_info()
                try:
                    for _ in range(100):
                        if self.memory_shrink:
                            sizes = consolidated_block_sizes(cpu_type, memory)
                            first, last = consolidated_block_ranges(
                                cpu_type, len(sizes)
                            )[0]
                            self.block("blank", first, last_block=last)
                        else:
                            self.block("blank", 1)
                except (ConsolidatedError, *_NATIVE_BASE_ERRORS):
                    # FuncInfo33abc scopes3..5 CPass12568:05/readone, then rethrow.
                    self._write(b"\x05")
                    self.read_exact(1)
                    raise
                return baud
            except (ConsolidatedError, *_NATIVE_BASE_ERRORS) as exc:
                self.runtime.check()
                if candidate + 1 == len(rates):
                    raise ConsolidatedError(21, "sil_baud_exhausted") from exc
        raise AssertionError("Native baud candidate loop must return or throw")


class ConsolidatedSILM16C2026(ConsolidatedSILFlash2026):
    """22d40/22700/228b0/22b20 source-specific M16C programming primitives."""

    def _status(self, *, verify=False) -> bytes | None:
        self._write(b"\xa8" if verify else b"\xa4")
        try:
            return self.read_exact(1 if verify else 2)
        except _NATIVE_DRIVER_ERRORS as exc:
            if _is_driver_error(exc) and _driver_code(exc) in (9, 16):
                return None
            raise

    def check_id(self, password: int) -> None:
        if type(password) is not int or not 0 <= password <= 0xFFFFFFFF:
            raise ValueError("Native unsigned password DWORD required")
        self._write(bytes.fromhex("a0dfff0f07"), password.to_bytes(4, "big") + bytes(3))
        value = self._status()
        if value is None or value[1] & 12 != 12:
            raise ConsolidatedError(7, "sil_m16c_check_id")

    def erase(self, end_address: int) -> None:
        if type(end_address) is not int or not 0 <= end_address <= 0xFFFFFF:
            raise ValueError("Native three-byte M16C erase end address required")
        self._write(b"\xa6")
        address = end_address.to_bytes(4, "big")
        self._write(bytes((0xA1, address[2], address[1], 0xD0)))
        self._poll(12)

    def _poll(self, code: int):
        for _ in range(4096):
            _void(self.runtime, "wait", milliseconds=5)
            value = self._status(verify=code == 15)
            if value is None:
                raise ConsolidatedError(code, "sil_m16c_status")
            if code == 15:
                if value[0] == 255:
                    continue
                valid = value[0] == 0
            else:
                if not value[0] & 128:
                    continue
                valid = not value[0] & 48 and (code == 12 or not value[1] & 2)
            if not valid:
                raise ConsolidatedError(code, "sil_m16c_status")
            return
        raise TimeoutError("Host SIL M16C status poll bound exceeded")

    def page(self, address: int, data: bytes, *, verify: bool = False, progress=None):
        """228b0/22b20 count uses fixed256-byte call argument as percent denominator."""
        if (
            type(address) is not int
            or not 0 <= address <= 0xFFFFFF
            or type(data) is not bytes
            or len(data) != 256
            or type(verify) is not bool
            or progress is not None
            and not callable(progress)
            or self.count + 256 > 0xFFFFFFFF
        ):
            raise ValueError("Exact native M16C page/address/progress required")
        if not verify:
            self._write(b"\xa6")
        raw_address = address.to_bytes(4, "big")
        self._write(
            bytes((0xA3 if verify else 0xA2, raw_address[2], raw_address[1])), data
        )
        self.count += 256
        if progress is not None:
            self.runtime.check()
            progress("count", self.count)
            self.runtime.check()
        self.percent = consolidated_progress_percent(self.count, 256)
        if progress is not None:
            self.runtime.check()
            progress("percent", self.percent)
            self.runtime.check()
        self._poll(15 if verify else 13)


@dataclass(frozen=True)
class SILM16CWriteContext:
    identity: NativeModuleIdentity
    kind_of_ecu: str
    cpu_types: tuple[str, ...]
    locations: tuple[bytes, ...] = field(repr=False)
    passwords: tuple[int, ...] = field(repr=False)
    image: bytes = field(repr=False)
    cpu_index: int = 0
    retry_decisions: tuple[bool, ...] = ()

    def __post_init__(self):
        if (
            select_branch(
                self.identity,
                "SIL",
                self.kind_of_ecu,
                self.cpu_types,
                writing=True,
                cpu_index=self.cpu_index,
            ).family
            != "sil_m16c_write"
        ):
            raise ValueError("Native selected SIL M16C writer required")
        if (
            type(self.locations) is not tuple
            or len(self.locations) != len(self.cpu_types)
            or any(
                type(value) is not bytes or len(value) != 8 for value in self.locations
            )
            or type(self.passwords) is not tuple
            or len(self.passwords) != len(self.cpu_types)
            or any(
                type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                for value in self.passwords
            )
            or type(self.image) is not bytes
            or not 24576 <= len(self.image) <= 64 * 1024 * 1024
            or type(self.retry_decisions) is not tuple
            or len(self.retry_decisions) > 256
            or any(type(value) is not bool for value in self.retry_decisions)
        ):
            raise ValueError(
                "Actual native CPU locations/passwords/M16C image/retry observations required"
            )


def bind_sil_m16c_writer(
    container,
    identity: NativeModuleIdentity,
    *,
    target_indices: tuple[int, ...],
    cpu_index: int = 0,
    retry_decisions: tuple[bool, ...] = (),
) -> SILM16CWriteContext:
    """22040 consumes the global CPU table, selected per-CPU targets and selected image."""
    from scripts.calibration_2026 import (
        native2026_archive,
        native2026_cpu_count,
        native2026_cpu_targets,
        native2026_cpu_type,
        native2026_location_id,
        native2026_metadata,
        native2026_metadata_for_cpu,
    )

    _identity(identity)
    metadata = native2026_metadata(container)
    count = native2026_cpu_count(metadata)
    if (
        type(cpu_index) is not int
        or not 0 <= cpu_index < count <= 256
        or type(target_indices) is not tuple
        or len(target_indices) != count
        or any(type(value) is not int or value < 0 for value in target_indices)
    ):
        raise ValueError("Actual global selected CPU/target-index vector required")
    cpus, locations, passwords = [], [], []
    for index, selected_target in enumerate(target_indices):
        cpus.append(native2026_cpu_type(metadata, index))
        location = native2026_location_id(metadata, index)
        if len(location) != 16 or any(
            char not in "0123456789abcdefABCDEF" for char in location
        ):
            raise ValueError(
                "Actual native LocationID requires sixteen hexadecimal digits"
            )
        locations.append(bytes.fromhex(location))
        targets = native2026_cpu_targets(metadata, index)
        if selected_target >= len(targets):
            raise ValueError("Selected native TargetData row absent")
        passwords.append(targets[selected_target].password)
    if metadata.vehicle.get("contacttype", "") != "SIL":
        raise ValueError("Imported M16C programming requires literal SIL contact")
    archive = native2026_archive(native2026_metadata_for_cpu(metadata, cpu_index))
    if archive.streamed or type(archive.data) is not bytes:
        raise ValueError("M16C requires the actual materialized selected archive")
    return SILM16CWriteContext(
        identity,
        metadata.vehicle.get("kindofecu", ""),
        tuple(cpus),
        tuple(locations),
        tuple(passwords),
        archive.data,
        cpu_index,
        retry_decisions,
    )


def write_sil_m16c(
    context: SILM16CWriteContext,
    runtime: NativeRuntime2026,
    *,
    progress=None,
    error_snapshot=None,
    progress_snapshot=None,
) -> dict:
    """22040 exact other-CPU preparation, three fixed areas, native error/retry scopes."""
    if progress_snapshot is not None and not callable(progress_snapshot):
        raise TypeError("Native scalar progress observer must be callable")
    driver_error = 0
    if error_snapshot is not None and not callable(error_snapshot):
        raise TypeError("Native error-slot observer must be callable")

    def observe_error():
        if error_snapshot is not None:
            error_snapshot(0 if failure is None else failure, driver_error)

    if (
        not isinstance(context, SILM16CWriteContext)
        or not isinstance(runtime, NativeRuntime2026)
        or progress is not None
        and not callable(progress)
    ):
        raise TypeError("Native SIL M16C context/runtime/progress required")
    context.__post_init__()
    rt, channel = runtime, ConsolidatedSILM16C2026(runtime)
    if rt.call("get_protocol_id") != 3:
        raise ValueError("SIL M16C requires upstream connected protocol3")
    failure = 0
    driver_error = 0
    phase, completed, retry_prepared = "prepare", False, False
    decisions = 0
    boot_cpu = next(
        (
            index
            for index, cpu in enumerate(context.cpu_types)
            if index != context.cpu_index and cpu in ("17", "18")
        ),
        None,
    )
    try:
        _void(rt, "control_io", ioctl=2, parameters=((1, 9600),))
        _void(rt, "control_io", ioctl=2, parameters=((0x0C, 0),))
        if boot_cpu is not None:
            channel.enter_programming(
                context.locations[boot_cpu], context.passwords[boot_cpu]
            )
            try:
                channel.select_programming_mode(0)
            except ConsolidatedSILBootError as exc:
                # FuncInfo35f3c state1 catches CSetBaudRateException, then CPass5.
                raise ConsolidatedError(5, "sil_m16c_programming_mode") from exc
            phase = "write"
            _void(rt, "set_timeout", milliseconds=2000)
            try:
                channel.check_id(context.passwords[context.cpu_index])
                offset = 0
                for address in (0xFA000, 0xFC000, 0xFE000):
                    channel.erase(address + 8191)
                    for within in range(0, 8192, 256):
                        page = context.image[offset + within : offset + within + 256]
                        channel.page(address + within, page, progress=progress)
                        channel.page(
                            address + within, page, verify=True, progress=progress
                        )
                    offset += 8192
            finally:
                # Source226d1 resets1000 even on native rethrow; host abort also cleans up.
                _void(rt, "set_timeout", cleanup=True, milliseconds=1000)
            completed, failure = True, None
    except (ConsolidatedError, *_NATIVE_BASE_ERRORS, NativeException2026) as exc:
        driver_error = _native_driver_slot(exc, driver_error)
        rt.check()
        if isinstance(exc, ConsolidatedError):
            failure = exc.code
        elif isinstance(exc, _NATIVE_BASE_ERRORS):
            failure = _native_enum(exc)
        # Native ALL22627/2269c preserve the worker's initialized error slot.
        if phase == "write":
            channel.count = channel.percent = 0
            if progress_snapshot is not None:
                progress_snapshot(0, 0)
    if not completed:
        observe_error()
        while decisions < len(context.retry_decisions):
            accepted = context.retry_decisions[decisions]
            decisions += 1
            if not accepted:
                break
            failure = 0
            driver_error = 0
            try:
                _void(rt, "disconnect")
            except (*_NATIVE_BASE_ERRORS, NativeException2026):
                rt.check()
            try:
                _void(rt, "connect", protocol=3)
            except _NATIVE_DRIVER_ERRORS as exc:
                driver_error = _native_driver_slot(exc, driver_error)
                if not _is_driver_error(exc):
                    raise
                rt.check()
                failure = _native_enum(exc)
                observe_error()
                continue
            retry_prepared = True
            break
    observe_error()
    return {
        "writer_completed": completed,
        "completion_callback": "normal" if completed else "error",
        "programming_completed": False,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "error_code": failure,
        "driver_error": driver_error,
        "native_error_code": 0 if failure is None else failure,
        "error_phase": None if completed else phase,
        "retry_prepared": retry_prepared,
        "retry_decisions_consumed": decisions,
        "boot_cpu_index": boot_cpu,
        "count": channel.count,
        "percent": channel.percent,
    }


@dataclass
class CANElectricWriteState:
    password_changed: bool = False
    last_block: bool = False
    block_started: bool = False

    def __post_init__(self):
        if any(
            type(value) is not bool
            for value in (self.password_changed, self.last_block, self.block_started)
        ):
            raise ValueError(
                "Literal native electric password/a8/ac state bytes required"
            )


@dataclass(frozen=True)
class CANElectricWriteContext:
    identity: NativeModuleIdentity
    cpu_type: str
    location_id: bytes = field(repr=False)
    initial_finish_request: bytes
    password: int = field(repr=False)
    image: bytes = field(repr=False)
    flash_size: int
    state: CANElectricWriteState
    cpu_index: int = 0
    cpu_count: int = 1
    retry_decisions: tuple[bool, ...] = ()

    def __post_init__(self):
        _identity(self.identity)
        if (
            type(self.cpu_type) is not str
            or not 0 < len(self.cpu_type) <= 64
            or "\0" in self.cpu_type
            or type(self.location_id) is not bytes
            or len(self.location_id) != 8
            or type(self.initial_finish_request) is not bytes
            or len(self.initial_finish_request) != 4
            or type(self.password) is not int
            or not 0 <= self.password <= 0xFFFFFFFF
            or type(self.image) is not bytes
            or not 262144 <= len(self.image) <= 64 * 1024 * 1024
            or type(self.flash_size) is not int
            or not 0 <= self.flash_size <= 64 * 1024 * 1024
            or not isinstance(self.state, CANElectricWriteState)
            or type(self.cpu_index) is not int
            or type(self.cpu_count) is not int
            or not 0 <= self.cpu_index < self.cpu_count <= 256
            or type(self.retry_decisions) is not tuple
            or len(self.retry_decisions) > 256
            or any(type(value) is not bool for value in self.retry_decisions)
        ):
            raise ValueError(
                "Native electric CPU/archive/borrowed state/progress context required"
            )
        self.state.__post_init__()


def bind_can_electric_writer(
    container,
    identity: NativeModuleIdentity,
    state: CANElectricWriteState,
    *,
    cpu_index: int = 0,
    target_index: int = 0,
    retry_decisions: tuple[bool, ...] = (),
    general_parameters=None,
) -> CANElectricWriteContext:
    """16300 binds selected global CPU/TargetData/archive and CPU0 preparation finish ID."""
    from scripts.calibration_2026 import (
        native2026_archive,
        native2026_cpu_count,
        native2026_cpu_targets,
        native2026_cpu_type,
        native2026_location_id,
        native2026_metadata,
        native2026_metadata_for_cpu,
    )

    _identity(identity)
    if not isinstance(state, CANElectricWriteState):
        raise TypeError("Actual native electric persistent state required")
    state.__post_init__()
    metadata = native2026_metadata(container)
    count = native2026_cpu_count(metadata)
    if (
        type(cpu_index) is not int
        or not 0 <= cpu_index < count <= 256
        or type(target_index) is not int
        or target_index < 0
    ):
        raise ValueError("Actual selected global CPU and TargetData indices required")
    cpus = tuple(native2026_cpu_type(metadata, index) for index in range(count))
    if (
        select_branch(
            identity,
            metadata.vehicle.get("contacttype", ""),
            metadata.vehicle.get("kindofecu", ""),
            cpus,
            writing=True,
            cpu_index=cpu_index,
        ).family
        != "can_electric_write"
    ):
        raise ValueError("Imported metadata does not select native electric writer")
    locations = tuple(
        native2026_location_id(metadata, index) for index in (0, cpu_index)
    )
    if any(
        len(text) != 16 or any(char not in "0123456789abcdefABCDEF" for char in text)
        for text in locations
    ):
        raise ValueError("Actual native LocationIDs require sixteen hexadecimal digits")
    targets = native2026_cpu_targets(metadata, cpu_index)
    if target_index >= len(targets):
        raise ValueError("Selected native TargetData row absent")
    archive = native2026_archive(native2026_metadata_for_cpu(metadata, cpu_index))
    if archive.streamed or type(archive.data) is not bytes:
        raise ValueError(
            "Electric worker requires actual materialized selected archive"
        )
    password = (
        consolidated_archive_password(
            archive.data,
            general_parameters,
            metadata.vehicle.get("kindofecu", ""),
            cpus[cpu_index],
            metadata.vehicle.get("contacttype", ""),
        )
        if state.password_changed
        else targets[target_index].password
    )
    return CANElectricWriteContext(
        identity,
        cpus[cpu_index],
        bytes.fromhex(locations[1]),
        consolidated_location_addresses(bytes.fromhex(locations[0]))[2],
        password,
        archive.data,
        archive.flash_size,
        state,
        cpu_index,
        count,
        retry_decisions,
    )


def write_can_electric(
    context: CANElectricWriteContext,
    runtime: NativeRuntime2026,
    *,
    progress=None,
    error_snapshot=None,
    progress_snapshot=None,
    counts=None,
    percentages=None,
) -> dict:
    """15ac0/16300 complete electric preparation, fixed single blocks and borrowed state."""
    driver_error = 0
    if error_snapshot is not None and not callable(error_snapshot):
        raise TypeError("Native error-slot observer must be callable")

    def observe_error():
        if error_snapshot is not None:
            error_snapshot(0 if failure is None else failure, driver_error)

    if (
        not isinstance(context, CANElectricWriteContext)
        or not isinstance(runtime, NativeRuntime2026)
        or progress is not None
        and not callable(progress)
    ):
        raise TypeError("Native electric context/runtime/progress required")
    context.__post_init__()
    if progress_snapshot is not None and not callable(progress_snapshot):
        raise TypeError("Native progress vector observer must be callable")
    rt, state = runtime, context.state
    if rt.call("get_protocol_id") != 6:
        raise ValueError("Electric writer requires upstream connected protocol6")
    prior = rt.call("get_timeout")
    if type(prior) is not int or not 0 <= prior <= 0xFFFFFFFF:
        raise ValueError("Native unsigned receive timeout required")
    channel, diag = ConsolidatedCAN2026(rt), ConsolidatedCanDiag2026(rt)
    native_counts = (
        [0] * context.cpu_count
        if counts is None
        else counts
        if type(counts) is list
        else list(counts)
    )
    native_percentages = (
        [0] * context.cpu_count
        if percentages is None
        else percentages
        if type(percentages) is list
        else list(percentages)
    )

    def notify(field):
        if progress_snapshot is not None:
            progress_snapshot(
                field,
                tuple(native_counts if field == "count" else native_percentages),
                context.cpu_index,
            )
        if progress is not None:
            progress(
                field,
                (native_counts if field == "count" else native_percentages)[
                    context.cpu_index
                ],
            )

    channel.common._progress(
        context.cpu_index, native_counts, native_percentages, notify
    )
    if len(native_counts) != context.cpu_count:
        raise ValueError("Native global CPU progress vector size differs")
    native_counts[context.cpu_index :] = [0] * (context.cpu_count - context.cpu_index)
    native_percentages[context.cpu_index :] = [0] * (
        context.cpu_count - context.cpu_index
    )
    request, response, finish_request = consolidated_location_addresses(
        context.location_id
    )
    prepare_request, prepare_response = (
        bytes.fromhex("000007c1"),
        bytes.fromhex("000007c9"),
    )
    completed = retry_prepared = False
    failure = None
    decisions = 0
    swallowed = []

    def release(handle, phase):
        try:
            rt.release("stop_filter", identifier=handle)
        except (ConsolidatedError, *_NATIVE_BASE_ERRORS, NativeException2026):
            rt.check()
            swallowed.append(phase)

    def code(exc):
        nonlocal driver_error
        driver_error = _native_driver_slot(exc, driver_error)
        return exc.code if isinstance(exc, ConsolidatedError) else _native_enum(exc)

    try:
        handle = None
        try:
            handle = diag.start_filter(prepare_request, prepare_response)
            channel.electric_security_access(prepare_request, prepare_response)
            _void(rt, "wait", milliseconds=100)
            for _ in range(3):
                diag.write(context.initial_finish_request + b"\xa0\x27")
                _void(rt, "wait", milliseconds=100)
            diag.call(
                prepare_request,
                prepare_response,
                b"\x10\x02",
                b"\x50",
                minimum=1,
                error_code=18,
            )
            _void(rt, "wait", milliseconds=300)
        except (ConsolidatedError, *_NATIVE_BASE_ERRORS) as exc:
            driver_error = _native_driver_slot(exc, driver_error)
            rt.check()
            failure = code(exc)
        finally:
            if handle is not None:
                release(handle, "prepare_stop_filter")
        if failure is None or state.block_started:
            failure = None
            handle = None
            try:
                _void(rt, "set_timeout", milliseconds=5000)
                sizes = consolidated_electric_block_sizes(context.cpu_type)
                handle = diag.start_filter(request, response)
                channel.check_id(
                    request,
                    response,
                    context.location_id,
                    context.password,
                    inter_message_wait_ms=3,
                )
                _void(rt, "wait", milliseconds=3)
                memory = channel.get_epb_memory_info(request, response)
                if (memory.firmware_version >> 4) & 7 != 7:
                    raise ConsolidatedError(10, "electric_firmware")
                for block in range(1, len(sizes) + 1):
                    if block == len(sizes):
                        state.last_block = True
                    state.block_started = True
                    channel.erase_epb_block(request, response, block)
                    channel.write_epb_block(
                        request,
                        response,
                        block,
                        sizes,
                        memory,
                        context.image,
                        native_counts,
                        native_percentages,
                        notify,
                        cpu_index=context.cpu_index,
                        total_size=context.flash_size,
                        initial_wait_ms=3,
                    )
                    channel.electric_inverify_block(request, response, block)
                    channel.verify_epb_block(
                        request,
                        response,
                        block,
                        sizes,
                        context.image,
                        native_counts,
                        native_percentages,
                        notify,
                        cpu_index=context.cpu_index,
                        total_size=context.flash_size,
                    )
                channel.finish(finish_request, response, acknowledge=True)
                _void(rt, "wait", milliseconds=1000)
                state.block_started = state.last_block = False
                completed = True
            except (ConsolidatedError, *_NATIVE_BASE_ERRORS) as exc:
                driver_error = _native_driver_slot(exc, driver_error)
                rt.check()
                failure = code(exc)
                native_counts[context.cpu_index] = 0
                channel.common._observe(notify, "count")
                native_percentages[context.cpu_index] = 0
                channel.common._observe(notify, "percent")
            finally:
                if handle is not None:
                    release(handle, "stop_filter")
        if failure is not None:
            # 16acf loads DL from borrowed+a8 before c2e0; +ac only picks error category.
            state.password_changed = (
                True
                if state.last_block
                else not state.password_changed
                if failure == 7
                else False
            )
            observe_error()
            while decisions < len(context.retry_decisions):
                accepted = context.retry_decisions[decisions]
                decisions += 1
                if not accepted:
                    break
                failure = 0
                driver_error = 0
                try:
                    _void(rt, "disconnect")
                except (*_NATIVE_BASE_ERRORS, NativeException2026):
                    rt.check()
                    swallowed.append("disconnect")
                try:
                    _void(rt, "connect", protocol=6)
                except _NATIVE_DRIVER_ERRORS as exc:
                    driver_error = _native_driver_slot(exc, driver_error)
                    if not _is_driver_error(exc):
                        raise
                    rt.check()
                    failure = _native_enum(exc)
                    observe_error()
                    continue
                retry_prepared = True
                break
    finally:
        _void(rt, "set_timeout", cleanup=True, milliseconds=prior)
    observe_error()
    return {
        "writer_completed": completed,
        "completion_callback": "normal" if completed else "error",
        "programming_completed": False,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "error_code": failure,
        "driver_error": driver_error,
        "native_error_code": 0 if failure is None else failure,
        "retry_prepared": retry_prepared,
        "retry_decisions_consumed": decisions,
        "counts": tuple(native_counts),
        "percentages": tuple(native_percentages),
        "swallowed_native_faults": tuple(swallowed),
        "password_changed": state.password_changed,
        "last_block": state.last_block,
        "block_started": state.block_started,
    }


@dataclass
class CANOldECBWriteState:
    password_changed: bool = False

    def __post_init__(self):
        if type(self.password_changed) is not bool:
            raise ValueError("Actual native old ECB password-state byte required")


@dataclass(frozen=True)
class CANOldECBWriteContext:
    identity: NativeModuleIdentity
    cpu_types: tuple[str, ...]
    locations: tuple[bytes, ...] = field(repr=False)
    passwords: tuple[int, ...] = field(repr=False)
    images: tuple[bytes, ...] = field(repr=False)
    flash_sizes: tuple[int, ...]
    security_materials: tuple[bytes, ...] = field(repr=False)
    prepare_count: int
    state: CANOldECBWriteState
    cpu_index: int = 0
    retry_decisions: tuple[bool, ...] = ()
    general_parameters: object = field(default=None, repr=False)

    def __post_init__(self):
        if (
            select_branch(
                self.identity,
                "CAN",
                "4",
                self.cpu_types,
                writing=True,
                cpu_index=self.cpu_index,
                old_spec_ecb=True,
            ).family
            != "can_old_ecb_write"
        ):
            raise ValueError("Native old ECB writer required")
        count = len(self.cpu_types)
        if (
            any(
                type(vector) is not tuple or len(vector) != count
                for vector in (
                    self.locations,
                    self.passwords,
                    self.images,
                    self.flash_sizes,
                )
            )
            or any(
                type(value) is not bytes or len(value) != 8 for value in self.locations
            )
            or any(
                type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                for value in self.passwords
            )
            or any(
                type(value) is not bytes or not 0 < len(value) <= 64 * 1024 * 1024
                for value in self.images
            )
            or any(
                type(value) is not int or not 0 <= value <= 64 * 1024 * 1024
                for value in self.flash_sizes
            )
            or type(self.security_materials) is not tuple
            or len(self.security_materials) != 4
            or any(
                type(value) is not bytes or len(value) != 2
                for value in self.security_materials
            )
            or type(self.prepare_count) is not int
            or not 1 <= self.prepare_count <= 2
            or not isinstance(self.state, CANOldECBWriteState)
            or type(self.retry_decisions) is not tuple
            or len(self.retry_decisions) > 256
            or any(type(value) is not bool for value in self.retry_decisions)
        ):
            raise ValueError(
                "Actual old ECB CPU/archive/state/preparation/retry context required"
            )
        self.state.__post_init__()


def bind_can_old_ecb_writer(
    container,
    identity: NativeModuleIdentity,
    controller_state: ConsolidatedControllerState,
    state: CANOldECBWriteState,
    attachments,
    *,
    target_indices: tuple[int, ...],
    cpu_index: int = 0,
    retry_decisions: tuple[bool, ...] = (),
    general_parameters=None,
) -> CANOldECBWriteContext:
    """1d6e0/1df10 global CPU archives plus actual old-ROM callback/address-vector count."""
    from collections.abc import Mapping

    from scripts.calibration_2026 import (
        native2026_archive,
        native2026_cpu_count,
        native2026_cpu_targets,
        native2026_cpu_type,
        native2026_location_id,
        native2026_metadata,
        native2026_metadata_for_cpu,
    )

    _identity(identity)
    if not isinstance(controller_state, ConsolidatedControllerState) or not isinstance(
        state, CANOldECBWriteState
    ):
        raise TypeError("Actual native old ECB controller/password state required")
    controller_state.__post_init__()
    state.__post_init__()
    if not controller_state.old_spec_ecb or not controller_state.native_context_9e8:
        raise ValueError(
            "Old ECB binding requires actual successful native ROM fallback state"
        )
    if not isinstance(attachments, Mapping) or set(attachments) != {
        "old_ecb_security_materials"
    }:
        raise ValueError(
            "Only explicit authorized old ECB conversion material is accepted"
        )
    metadata = native2026_metadata(container)
    count = native2026_cpu_count(metadata)
    if (
        type(cpu_index) is not int
        or not 0 <= cpu_index < count <= 256
        or type(target_indices) is not tuple
        or len(target_indices) != count
        or any(type(value) is not int or value < 0 for value in target_indices)
    ):
        raise ValueError("Actual global selected CPU/target-index vector required")
    cpus, locations, passwords, images, flash_sizes = [], [], [], [], []
    for index, selected_target in enumerate(target_indices):
        cpus.append(native2026_cpu_type(metadata, index))
        location = native2026_location_id(metadata, index)
        if len(location) != 16 or any(
            char not in "0123456789abcdefABCDEF" for char in location
        ):
            raise ValueError(
                "Actual native LocationIDs require sixteen hexadecimal digits"
            )
        locations.append(bytes.fromhex(location))
        targets = native2026_cpu_targets(metadata, index)
        if selected_target >= len(targets):
            raise ValueError("Selected native TargetData row absent")
        passwords.append(targets[selected_target].password)
        archive = native2026_archive(native2026_metadata_for_cpu(metadata, index))
        if archive.streamed or type(archive.data) is not bytes:
            raise ValueError("Old ECB requires actual materialized per-CPU archives")
        images.append(archive.data)
        flash_sizes.append(archive.flash_size)
    if (
        select_branch(
            identity,
            metadata.vehicle.get("contacttype", ""),
            metadata.vehicle.get("kindofecu", ""),
            tuple(cpus),
            writing=True,
            cpu_index=cpu_index,
            old_spec_ecb=controller_state.old_spec_ecb,
        ).family
        != "can_old_ecb_write"
    ):
        raise ValueError("Imported metadata does not select old ECB writer")
    # 9ff0 kind4 repeats fixed node9 once per observed request-record, defaulting one.
    prepare_count = max(1, len(controller_state.request_id_records))
    return CANOldECBWriteContext(
        identity,
        tuple(cpus),
        tuple(locations),
        tuple(passwords),
        tuple(images),
        tuple(flash_sizes),
        attachments["old_ecb_security_materials"],
        prepare_count,
        state,
        cpu_index,
        retry_decisions,
        general_parameters,
    )


def write_can_old_ecb(
    context: CANOldECBWriteContext,
    runtime: NativeRuntime2026,
    *,
    progress=None,
    error_snapshot=None,
    progress_snapshot=None,
    counts=None,
    percentages=None,
) -> dict:
    """1df10/1e6da old ECB multiple-CPU loop and native same-range retry continuation."""
    driver_error = 0
    if error_snapshot is not None and not callable(error_snapshot):
        raise TypeError("Native error-slot observer must be callable")

    def observe_error():
        if error_snapshot is not None:
            error_snapshot(0 if failure is None else failure, driver_error)

    if (
        not isinstance(context, CANOldECBWriteContext)
        or not isinstance(runtime, NativeRuntime2026)
        or progress is not None
        and not callable(progress)
    ):
        raise TypeError("Native old ECB context/runtime/progress required")
    context.__post_init__()
    if progress_snapshot is not None and not callable(progress_snapshot):
        raise TypeError("Native progress vector observer must be callable")
    rt, state = runtime, context.state
    if rt.call("get_protocol_id") != 6:
        raise ValueError("Old ECB requires upstream connected protocol6")
    prior = rt.call("get_timeout")
    if type(prior) is not int or not 0 <= prior <= 0xFFFFFFFF:
        raise ValueError("Native unsigned receive timeout required")
    channel, diag = ConsolidatedCAN2026(rt), ConsolidatedCanDiag2026(rt)
    native_counts = (
        [0] * len(context.cpu_types)
        if counts is None
        else counts
        if type(counts) is list
        else list(counts)
    )
    native_percentages = (
        [0] * len(context.cpu_types)
        if percentages is None
        else percentages
        if type(percentages) is list
        else list(percentages)
    )
    current = context.cpu_index

    def notify(field):
        if progress_snapshot is not None:
            progress_snapshot(
                field,
                tuple(native_counts if field == "count" else native_percentages),
                current,
            )
        if progress is not None:
            progress(
                field,
                (native_counts if field == "count" else native_percentages)[current],
            )

    channel.common._progress(current, native_counts, native_percentages, notify)
    if not len(context.cpu_types) <= len(native_counts) <= 256:
        raise ValueError(
            "Native global CPU progress capacity must cover actual CPU vector"
        )
    native_counts[current:] = [0] * (len(native_counts) - current)
    native_percentages[current:] = [0] * (len(native_percentages) - current)
    completed = retry_prepared = False
    failure = None
    decisions = restarts = 0
    swallowed = []
    prepare_request, prepare_response = (
        bytes.fromhex("000007b0"),
        bytes.fromhex("000007b8"),
    )

    def release(handle, phase):
        try:
            rt.release("stop_filter", identifier=handle)
        except (ConsolidatedError, *_NATIVE_BASE_ERRORS, NativeException2026):
            rt.check()
            swallowed.append(phase)
            return False
        return True

    def code(exc):
        nonlocal driver_error
        driver_error = _native_driver_slot(exc, driver_error)
        return exc.code if isinstance(exc, ConsolidatedError) else _native_enum(exc)

    def reconnect():
        nonlocal decisions, failure, retry_prepared, driver_error
        observe_error()
        while decisions < len(context.retry_decisions):
            accepted = context.retry_decisions[decisions]
            decisions += 1
            if not accepted:
                return False
            failure = 0
            driver_error = 0
            try:
                _void(rt, "disconnect")
            except (*_NATIVE_BASE_ERRORS, NativeException2026):
                rt.check()
                swallowed.append("disconnect")
            try:
                _void(rt, "connect", protocol=6)
            except _NATIVE_DRIVER_ERRORS as exc:
                driver_error = _native_driver_slot(exc, driver_error)
                if not _is_driver_error(exc):
                    raise
                rt.check()
                failure = _native_enum(exc)
                observe_error()
                continue
            retry_prepared = True
            return True
        return False

    try:
        _void(rt, "wait", milliseconds=2000)
        handle = None
        try:
            handle = diag.start_filter(prepare_request, prepare_response)
            for index, selector in enumerate((0, 2)[: context.prepare_count]):
                channel.old_ecb_security_access(
                    prepare_request,
                    prepare_response,
                    selector,
                    context.security_materials,
                )
                if index == 0:
                    initial_finish = consolidated_location_addresses(
                        context.locations[0]
                    )[2]
                    for _ in range(3):
                        diag.write(initial_finish + b"\xa0\x27")
                        _void(rt, "wait", milliseconds=100)
                diag.call(
                    prepare_request,
                    prepare_response,
                    b"\x10\x02",
                    b"\x50",
                    minimum=1,
                    error_code=18,
                )
        except (ConsolidatedError, *_NATIVE_BASE_ERRORS) as exc:
            driver_error = _native_driver_slot(exc, driver_error)
            rt.check()
            failure = code(exc)
        finally:
            if handle is not None:
                release(handle, "prepare_stop_filter")
        if failure is not None:
            reconnect()
        else:
            prior = rt.call("get_timeout")
            if type(prior) is not int or not 0 <= prior <= 0xFFFFFFFF:
                raise ValueError("Native unsigned receive timeout required")
            resume_range = 0
            last_range = False
            sizes: tuple[int, ...] = ()
            ranges: tuple[tuple[int, int], ...] = ()
            while current < len(context.cpu_types):
                request, response, finish_request = consolidated_location_addresses(
                    context.locations[current]
                )
                _void(rt, "set_timeout", milliseconds=120000)
                handle = None
                range_index = resume_range
                try:
                    handle = diag.start_filter(request, response)
                    password = (
                        consolidated_archive_password(
                            context.images[current],
                            context.general_parameters,
                            "4",
                            context.cpu_types[current],
                            "CAN",
                        )
                        if state.password_changed
                        else context.passwords[current]
                    )
                    _void(rt, "wait", milliseconds=500)
                    channel.check_id(
                        request, response, context.locations[current], password
                    )
                    memory = channel.get_memory_info(request, response)
                    if not consolidated_firmware_matches(
                        context.cpu_types[current],
                        memory.firmware_version,
                        True,
                        wide=True,
                    ):
                        raise ConsolidatedError(10, "old_ecb_firmware")
                    sizes = consolidated_block_sizes(context.cpu_types[current], memory)
                    ranges = consolidated_block_ranges(
                        context.cpu_types[current], len(sizes), old_spec_ecb=True
                    )
                    for range_index in range(resume_range, len(ranges)):
                        first, last = ranges[range_index]
                        last_range = range_index + 1 == len(ranges)
                        channel.block("erase", request, response, first, last)
                        channel.write_block(
                            request,
                            response,
                            first,
                            last,
                            sizes,
                            memory,
                            context.images[current],
                            native_counts,
                            native_percentages,
                            notify,
                            cpu_index=current,
                            total_size=context.flash_sizes[current],
                        )
                        channel.block("inverify", request, response, first, last)
                        channel.verify_block(
                            request,
                            response,
                            first,
                            last,
                            sizes,
                            context.images[current],
                            native_counts,
                            native_percentages,
                            notify,
                            cpu_index=current,
                            total_size=context.flash_sizes[current],
                        )
                    state.password_changed = False
                    if current + 1 == len(context.cpu_types):
                        try:
                            channel.finish(finish_request, response)
                        except (
                            ConsolidatedError,
                            *_NATIVE_BASE_ERRORS,
                            NativeException2026,
                        ):
                            rt.check()
                            swallowed.append("finish")
                        completed = True
                    else:
                        # 6450 is65/ACK;1ea00's05/ACK65/ACK is a separate error path.
                        diag.write(request + b"\x65")
                        channel._ack(response, 19)
                    failure = None
                except (ConsolidatedError, *_NATIVE_BASE_ERRORS) as exc:
                    driver_error = _native_driver_slot(exc, driver_error)
                    rt.check()
                    failure = code(exc)
                    # 1ec50 keeps only the immediately previous range length, not a sum.
                    retained = (
                        0
                        if not range_index or not ranges or not sizes
                        else (
                            ranges[range_index - 1][1] - ranges[range_index - 1][0] + 1
                        )
                        * sizes[0]
                        * 2
                    )
                    native_counts[current] = retained & 0xFFFFFFFF
                    channel.common._observe(notify, "count")
                    native_percentages[current] = consolidated_progress_percent(
                        native_counts[current], context.flash_sizes[current]
                    )
                    channel.common._observe(notify, "percent")
                finally:
                    if handle is not None:
                        release(handle, "stop_filter")
                if failure is None:
                    current += 1
                    resume_range = 0
                    continue
                while True:
                    state.password_changed = (
                        True
                        if last_range
                        else not state.password_changed
                        if failure == 7
                        else False
                    )
                    if not reconnect():
                        break
                    handle = None
                    disposed = False
                    try:
                        _void(rt, "set_timeout", milliseconds=120000)
                        handle = diag.start_filter(request, response)
                        channel.old_ecb_dispose_error(request, response)
                        disposed = True
                    except (
                        ConsolidatedError,
                        *_NATIVE_BASE_ERRORS,
                        NativeException2026,
                    ):
                        rt.check()
                        continue
                    finally:
                        if handle is not None:
                            disposed = (
                                release(handle, "dispose_stop_filter") and disposed
                            )
                    if not disposed:
                        continue
                    failure = None
                    resume_range = range_index
                    restarts += 1
                    break
                if failure is not None:
                    break
    finally:
        _void(rt, "set_timeout", cleanup=True, milliseconds=prior)
    observe_error()
    return {
        "writer_completed": completed,
        "completion_callback": "normal" if completed else "error",
        "programming_completed": False,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "error_code": failure,
        "driver_error": driver_error,
        "native_error_code": 0 if failure is None else failure,
        "retry_prepared": retry_prepared,
        "retry_decisions_consumed": decisions,
        "counts": tuple(native_counts),
        "percentages": tuple(native_percentages),
        "restarts": restarts,
        "password_changed": state.password_changed,
        "swallowed_native_faults": tuple(swallowed),
    }


@dataclass
class SILWriteState:
    password_changed: bool = False
    effective_cpu_type: str | None = None

    def __post_init__(self):
        if (
            type(self.password_changed) is not bool
            or self.effective_cpu_type is not None
            and (
                type(self.effective_cpu_type) is not str
                or not 0 < len(self.effective_cpu_type) <= 64
                or "\0" in self.effective_cpu_type
            )
        ):
            raise ValueError(
                "Native SIL password byte and literal runtime CPU type required"
            )


@dataclass(frozen=True)
class SILWriteContext:
    writer_family = "sil_write"

    identity: NativeModuleIdentity
    kind_of_ecu: str
    cpu_type: str
    location_id: bytes = field(repr=False)
    password: int = field(repr=False)
    image: bytes = field(repr=False)
    flash_size: int
    state: SILWriteState
    cpu_index: int = 0
    retry_decisions: tuple[bool, ...] = ()
    general_parameters: object = field(default=None, repr=False)

    def __post_init__(self):
        _identity(self.identity)
        if (
            type(self.kind_of_ecu) is not str
            or not 0 < len(self.kind_of_ecu) <= 64
            or "\0" in self.kind_of_ecu
            or type(self.cpu_type) is not str
            or not 0 < len(self.cpu_type) <= 64
            or "\0" in self.cpu_type
            or type(self.location_id) is not bytes
            or len(self.location_id) != 8
            or type(self.password) is not int
            or not 0 <= self.password <= 0xFFFFFFFF
            or type(self.image) is not bytes
            or not 0 < len(self.image) <= 64 * 1024 * 1024
            or type(self.flash_size) is not int
            or not 0 <= self.flash_size <= 64 * 1024 * 1024
            or not isinstance(self.state, SILWriteState)
            or type(self.cpu_index) is not int
            or not 0 <= self.cpu_index < 256
            or type(self.retry_decisions) is not tuple
            or len(self.retry_decisions) > 256
            or any(type(value) is not bool for value in self.retry_decisions)
        ):
            raise ValueError(
                "Native selected SIL CPU/TargetData/archive/state context required"
            )
        self.state.__post_init__()
        if (
            select_branch(
                self.identity, "SIL", self.kind_of_ecu, (self.cpu_type,), writing=True
            ).family
            != self.writer_family
        ):
            raise ValueError("Source-selected SIL writer context required")
        _, _, alternate = consolidated_sil_cpu_mode(self.cpu_type)
        if self.state.effective_cpu_type not in (None, self.cpu_type, alternate):
            raise ValueError(
                "Runtime CPU state differs from literal source CPU alternate pair"
            )


def bind_sil_writer(
    container,
    identity: NativeModuleIdentity,
    state: SILWriteState,
    *,
    cpu_index: int = 0,
    target_index: int = 0,
    retry_decisions: tuple[bool, ...] = (),
    general_parameters=None,
) -> SILWriteContext:
    """10eb0 selected global CPU/TargetData/image binding; family dispatch uses allCPUs."""
    from scripts.calibration_2026 import (
        native2026_archive,
        native2026_cpu_count,
        native2026_cpu_targets,
        native2026_cpu_type,
        native2026_location_id,
        native2026_metadata,
        native2026_metadata_for_cpu,
    )

    _identity(identity)
    metadata = native2026_metadata(container)
    count = native2026_cpu_count(metadata)
    if (
        type(cpu_index) is not int
        or not 0 <= cpu_index < count <= 256
        or type(target_index) is not int
        or target_index < 0
    ):
        raise ValueError("Actual selected global CPU and TargetData indices required")
    cpus = tuple(native2026_cpu_type(metadata, index) for index in range(count))
    if (
        select_branch(
            identity,
            metadata.vehicle.get("contacttype", ""),
            metadata.vehicle.get("kindofecu", ""),
            cpus,
            writing=True,
            cpu_index=cpu_index,
        ).family
        != "sil_write"
    ):
        raise ValueError("Imported metadata does not select native base SIL writer")
    targets = native2026_cpu_targets(metadata, cpu_index)
    if target_index >= len(targets):
        raise ValueError("Selected native TargetData row absent")
    location = native2026_location_id(metadata, cpu_index)
    if len(location) != 16 or any(
        char not in "0123456789abcdefABCDEF" for char in location
    ):
        raise ValueError("Actual native LocationID requires sixteen hexadecimal digits")
    archive = native2026_archive(native2026_metadata_for_cpu(metadata, cpu_index))
    if archive.streamed or type(archive.data) is not bytes:
        raise ValueError("Base SIL requires actual materialized selected archive")
    return SILWriteContext(
        identity,
        metadata.vehicle.get("kindofecu", ""),
        cpus[cpu_index],
        bytes.fromhex(location),
        targets[target_index].password,
        archive.data,
        archive.flash_size,
        state,
        cpu_index,
        retry_decisions,
        general_parameters,
    )


def write_sil(
    context: SILWriteContext,
    runtime: NativeRuntime2026,
    *,
    progress=None,
    error_snapshot=None,
) -> dict:
    """10eb0 full classic/shrink SIL worker and phase-specific native error UI/reconnect."""
    driver_error = 0
    if error_snapshot is not None and not callable(error_snapshot):
        raise TypeError("Native error-slot observer must be callable")

    def observe_error():
        if error_snapshot is not None:
            error_snapshot(0 if failure is None else failure, driver_error)

    if (
        not isinstance(context, SILWriteContext)
        or not isinstance(runtime, NativeRuntime2026)
        or progress is not None
        and not callable(progress)
    ):
        raise TypeError("Native base SIL context/runtime/progress required")
    context.__post_init__()
    rt, state, channel = runtime, context.state, ConsolidatedSILFlash2026(runtime)
    if rt.call("get_protocol_id") != 3:
        raise ValueError("Base SIL writer requires upstream connected protocol3")
    cpu = state.effective_cpu_type or context.cpu_type
    failure, phase, category, callback = 0, "prepare", "prepare", "error"
    completed = retry_prepared = last = False
    decisions = 0
    baud = None
    swallowed = []
    try:
        _void(rt, "control_io", ioctl=2, parameters=((1, 9600),))
        _void(rt, "control_io", ioctl=2, parameters=((0x0C, 0),))
        password = (
            consolidated_archive_password(
                context.image,
                context.general_parameters,
                context.kind_of_ecu,
                cpu,
                "SIL",
            )
            if state.password_changed
            else context.password
        )
        channel.enter_programming(context.location_id, password)
        probe, preferred, alternate = consolidated_sil_cpu_mode(cpu)
        baud = channel.discover_baud(cpu)
        try:
            channel.select_programming_mode(0)
        except ConsolidatedSILBootError as exc:
            raise ConsolidatedError(5, "sil_programming_mode") from exc
        memory = channel.memory_info()
        if probe and channel.memory_shrink != preferred:
            if alternate is None:
                raise ValueError("Source alternate CPU mapping absent")
            cpu = alternate
            state.effective_cpu_type = cpu
        if not consolidated_firmware_matches(
            cpu, memory.firmware_version, bool(channel.memory_shrink)
        ):
            raise ConsolidatedError(10, "sil_firmware")
        # Native11202 selects normalcallback BEFORE flash, retained even on writeerror.
        phase = category = "write"
        callback = "normal"
        sizes = consolidated_block_sizes(cpu, memory)
        if channel.memory_shrink:
            ranges = consolidated_block_ranges(cpu, len(sizes))
            for index, (first, final) in enumerate(ranges):
                blank = (
                    False
                    if context.kind_of_ecu == "30"
                    else channel.block("blank", first, last_block=final)
                )
                last = index + 1 == len(ranges)
                if not blank:
                    channel.block("erase", first, last_block=final)
                channel.write_block(
                    first,
                    sizes,
                    memory,
                    context.image,
                    context.flash_size,
                    progress=progress,
                    last_block=final,
                )
                channel.block("inverify", first, last_block=final)
                channel.verify_block(
                    first,
                    sizes,
                    context.image,
                    context.flash_size,
                    progress=progress,
                    last_block=final,
                )
            state.password_changed = False
        else:
            for block in range(1, len(sizes) + 1):
                blank = channel.block("blank", block)
                last = block == len(sizes)
                if not blank:
                    channel.block("erase", block)
                channel.write_block(
                    block,
                    sizes,
                    memory,
                    context.image,
                    context.flash_size,
                    progress=progress,
                )
                channel.block("inverify", block)
                channel.verify_block(
                    block, sizes, context.image, context.flash_size, progress=progress
                )
                if last:
                    state.password_changed = False
        completed, failure = True, None
    except (ConsolidatedError, *_NATIVE_BASE_ERRORS, NativeException2026) as exc:
        driver_error = _native_driver_slot(exc, driver_error)
        rt.check()
        if isinstance(exc, ConsolidatedError):
            failure = exc.code
        elif isinstance(exc, _NATIVE_BASE_ERRORS):
            failure = _native_enum(exc)
        state.password_changed = (
            True
            if phase == "write" and last
            else not state.password_changed
            if failure == 7
            else False
        )
    if not completed:
        while True:
            observe_error()
            accepted = False
            if decisions < len(context.retry_decisions):
                accepted = context.retry_decisions[decisions]
                decisions += 1
            if phase == "write":
                channel.count = 0
                if progress is not None:
                    rt.check()
                    progress("count", 0)
                    rt.check()
                channel.percent = 0
                if progress is not None:
                    rt.check()
                    progress("percent", 0)
                    rt.check()
            if not accepted:
                break
            if phase == "prepare":
                failure = 0
                driver_error = 0
            try:
                _void(rt, "disconnect")
            except (*_NATIVE_BASE_ERRORS, NativeException2026):
                rt.check()
                swallowed.append("disconnect")
            try:
                _void(rt, "connect", protocol=3)
            except _NATIVE_BASE_ERRORS as exc:
                driver_error = _native_driver_slot(exc, driver_error)
                rt.check()
                failure = _native_enum(exc)
                category = "disposal"
                continue
            retry_prepared = True
            break
    observe_error()
    return {
        "writer_completed": completed,
        "completion_callback": callback,
        "programming_completed": False,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "error_code": failure,
        "driver_error": driver_error,
        "native_error_code": 0 if failure is None else failure,
        "error_phase": None if completed else phase,
        "error_category": None if completed else category,
        "retry_prepared": retry_prepared,
        "retry_decisions_consumed": decisions,
        "count": channel.count,
        "percent": channel.percent,
        "baud_rate": baud,
        "effective_cpu_type": cpu,
        "password_changed": state.password_changed,
        "swallowed_native_faults": tuple(swallowed),
    }


@dataclass(frozen=True)
class CANChassisWriteContext(CANOldECBWriteContext):
    """Same consolidated CAN4 CPU/archive data contract; separate14100 orchestration."""

    recovery_timeout: bool = False

    def __post_init__(self):
        super().__post_init__()
        if type(self.recovery_timeout) is not bool:
            raise ValueError(
                "Literal native context+980 recovery-timeout byte required"
            )


def bind_can_chassis_writer(
    container,
    identity: NativeModuleIdentity,
    controller_state: ConsolidatedControllerState,
    state: CANOldECBWriteState,
    attachments,
    *,
    target_indices: tuple[int, ...],
    cpu_index: int = 0,
    retry_decisions: tuple[bool, ...] = (),
    recovery_timeout: bool = False,
    general_parameters=None,
) -> CANChassisWriteContext:
    """14100 binds selected global CPU vector and normal kind4 callback state."""
    from collections.abc import Mapping

    from scripts.calibration_2026 import (
        native2026_archive,
        native2026_cpu_count,
        native2026_cpu_targets,
        native2026_cpu_type,
        native2026_location_id,
        native2026_metadata,
        native2026_metadata_for_cpu,
    )

    _identity(identity)
    if not isinstance(controller_state, ConsolidatedControllerState) or not isinstance(
        state, CANOldECBWriteState
    ):
        raise TypeError("Actual native chassis controller/password state required")
    controller_state.__post_init__()
    state.__post_init__()
    if controller_state.old_spec_ecb:
        raise ValueError("Chassis binding requires native old-specification flag false")
    metadata = native2026_metadata(container)
    count = native2026_cpu_count(metadata)
    if (
        type(cpu_index) is not int
        or not 0 <= cpu_index < count <= 256
        or type(target_indices) is not tuple
        or len(target_indices) != count
        or any(type(value) is not int or value < 0 for value in target_indices)
    ):
        raise ValueError("Actual global selected CPU/target-index vector required")
    cpus, locations, passwords, images, flash_sizes = [], [], [], [], []
    for index, selected_target in enumerate(target_indices):
        cpus.append(native2026_cpu_type(metadata, index))
        location = native2026_location_id(metadata, index)
        if len(location) != 16 or any(
            char not in "0123456789abcdefABCDEF" for char in location
        ):
            raise ValueError(
                "Actual native LocationIDs require sixteen hexadecimal digits"
            )
        locations.append(bytes.fromhex(location))
        targets = native2026_cpu_targets(metadata, index)
        if selected_target >= len(targets):
            raise ValueError("Selected native TargetData row absent")
        passwords.append(targets[selected_target].password)
        archive = native2026_archive(native2026_metadata_for_cpu(metadata, index))
        if archive.streamed or type(archive.data) is not bytes:
            raise ValueError("Chassis requires actual materialized per-CPU archives")
        images.append(archive.data)
        flash_sizes.append(archive.flash_size)
    if (
        select_branch(
            identity,
            metadata.vehicle.get("contacttype", ""),
            metadata.vehicle.get("kindofecu", ""),
            tuple(cpus),
            writing=True,
            cpu_index=cpu_index,
        ).family
        != "can_chassis_write"
    ):
        raise ValueError("Imported metadata does not select chassis writer")
    # 13c20 selects the second source table using CPU0, not the selected CPU.
    key = (
        "chassis_secondary_security_materials"
        if cpus[0] in ("30", "38", "42")
        else "chassis_primary_security_materials"
    )
    if not isinstance(attachments, Mapping) or set(attachments) != {key}:
        raise ValueError(
            "Actual CPU0-selected authorized chassis conversion material required"
        )
    return CANChassisWriteContext(
        identity,
        tuple(cpus),
        tuple(locations),
        tuple(passwords),
        tuple(images),
        tuple(flash_sizes),
        attachments[key],
        max(1, len(controller_state.request_id_records)),
        state,
        cpu_index,
        retry_decisions,
        general_parameters,
        recovery_timeout,
    )


def write_can_chassis(
    context: CANChassisWriteContext,
    runtime: NativeRuntime2026,
    *,
    progress=None,
    error_snapshot=None,
    progress_snapshot=None,
    counts=None,
    percentages=None,
) -> dict:
    """13760/14100 full chassis multiple-CPU worker; failed worker retries only reconnect."""
    driver_error = 0
    if error_snapshot is not None and not callable(error_snapshot):
        raise TypeError("Native error-slot observer must be callable")

    def observe_error():
        if error_snapshot is not None:
            error_snapshot(0 if failure is None else failure, driver_error)

    if (
        not isinstance(context, CANChassisWriteContext)
        or not isinstance(runtime, NativeRuntime2026)
        or progress is not None
        and not callable(progress)
    ):
        raise TypeError("Native chassis context/runtime/progress required")
    context.__post_init__()
    if progress_snapshot is not None and not callable(progress_snapshot):
        raise TypeError("Native progress vector observer must be callable")
    rt, state = runtime, context.state
    if rt.call("get_protocol_id") != 6:
        raise ValueError("Chassis requires upstream connected protocol6")
    prior = rt.call("get_timeout")
    if type(prior) is not int or not 0 <= prior <= 0xFFFFFFFF:
        raise ValueError("Native unsigned receive timeout required")
    channel, diag = ConsolidatedCAN2026(rt), ConsolidatedCanDiag2026(rt)
    native_counts = (
        [0] * len(context.cpu_types)
        if counts is None
        else counts
        if type(counts) is list
        else list(counts)
    )
    native_percentages = (
        [0] * len(context.cpu_types)
        if percentages is None
        else percentages
        if type(percentages) is list
        else list(percentages)
    )
    current = context.cpu_index

    def notify(field):
        if progress_snapshot is not None:
            progress_snapshot(
                field,
                tuple(native_counts if field == "count" else native_percentages),
                current,
            )
        if progress is not None:
            progress(
                field,
                (native_counts if field == "count" else native_percentages)[current],
            )

    channel.common._progress(current, native_counts, native_percentages, notify)
    if not len(context.cpu_types) <= len(native_counts) <= 256:
        raise ValueError(
            "Native global CPU progress capacity must cover actual CPU vector"
        )
    native_counts[current:] = [0] * (len(native_counts) - current)
    native_percentages[current:] = [0] * (len(native_percentages) - current)
    completed = retry_prepared = last_range = False
    failure = None
    decisions = 0
    swallowed = []
    prepare_request, prepare_response = (
        bytes.fromhex("000007b0"),
        bytes.fromhex("000007b8"),
    )

    def release(handle, phase):
        try:
            rt.release("stop_filter", identifier=handle)
        except (ConsolidatedError, *_NATIVE_BASE_ERRORS, NativeException2026):
            rt.check()
            swallowed.append(phase)

    def code(exc):
        nonlocal driver_error
        driver_error = _native_driver_slot(exc, driver_error)
        return exc.code if isinstance(exc, ConsolidatedError) else _native_enum(exc)

    try:
        handle = None
        try:
            handle = diag.start_filter(prepare_request, prepare_response)
            for selector in (0, 2)[: context.prepare_count]:
                channel.old_ecb_security_access(
                    prepare_request,
                    prepare_response,
                    selector,
                    context.security_materials,
                    key_delay_ms=100,
                )
                _void(rt, "wait", milliseconds=100)
                initial_finish = consolidated_location_addresses(context.locations[0])[
                    2
                ]
                for _ in range(3):
                    diag.write(initial_finish + b"\xa0\x27")
                    _void(rt, "wait", milliseconds=100)
                diag.call(
                    prepare_request,
                    prepare_response,
                    b"\x10\x02",
                    b"\x50",
                    minimum=1,
                    error_code=18,
                )
        except (ConsolidatedError, *_NATIVE_BASE_ERRORS) as exc:
            driver_error = _native_driver_slot(exc, driver_error)
            rt.check()
            failure = code(exc)
        finally:
            if handle is not None:
                release(handle, "prepare_stop_filter")
        if failure is None:
            prior = rt.call("get_timeout")
            if type(prior) is not int or not 0 <= prior <= 0xFFFFFFFF:
                raise ValueError("Native unsigned receive timeout required")
            while current < len(context.cpu_types):
                _void(rt, "set_timeout", milliseconds=3000)
                request, response, finish_request = consolidated_location_addresses(
                    context.locations[current]
                )
                handle = None
                try:
                    handle = diag.start_filter(request, response)
                    password = (
                        consolidated_archive_password(
                            context.images[current],
                            context.general_parameters,
                            "4",
                            context.cpu_types[current],
                            "CAN",
                        )
                        if state.password_changed
                        else context.passwords[current]
                    )
                    _void(rt, "wait", milliseconds=500)
                    timeout = 10000 if context.recovery_timeout else 80000
                    separate = (
                        None
                        if context.cpu_types[current]
                        in ("23", "24", "25", "30", "35", "36", "37", "38", "42", "43")
                        else 3
                    )
                    channel.check_id(
                        request,
                        response,
                        context.locations[current],
                        password,
                        initial_timeout=timeout,
                        inter_message_wait_ms=separate,
                    )
                    _void(rt, "wait", milliseconds=3)
                    memory = channel.get_memory_info(request, response)
                    if not consolidated_firmware_matches(
                        context.cpu_types[current],
                        memory.firmware_version,
                        True,
                        wide=True,
                    ):
                        raise ConsolidatedError(10, "chassis_firmware")
                    sizes = consolidated_block_sizes(context.cpu_types[current], memory)
                    ranges = consolidated_block_ranges(
                        context.cpu_types[current], len(sizes), old_spec_ecb=True
                    )
                    if ranges[0][0] != 1:
                        sizes = (0,) * (ranges[0][0] - 1) + sizes
                    for index, (first, final) in enumerate(ranges):
                        last_range = index + 1 == len(ranges)
                        channel.block("erase", request, response, first, final)
                        channel.write_block(
                            request,
                            response,
                            first,
                            final,
                            sizes,
                            memory,
                            context.images[current],
                            native_counts,
                            native_percentages,
                            notify,
                            cpu_index=current,
                            total_size=context.flash_sizes[current],
                            wait_ms=3,
                        )
                        channel.block("inverify", request, response, first, final)
                        channel.verify_block(
                            request,
                            response,
                            first,
                            final,
                            sizes,
                            context.images[current],
                            native_counts,
                            native_percentages,
                            notify,
                            cpu_index=current,
                            total_size=context.flash_sizes[current],
                        )
                    state.password_changed = False
                    if current + 1 == len(context.cpu_types):
                        try:
                            channel.finish(finish_request, response)
                        except (
                            ConsolidatedError,
                            *_NATIVE_BASE_ERRORS,
                            NativeException2026,
                        ):
                            rt.check()
                            swallowed.append("finish")
                        completed = True
                    else:
                        diag.write(request + b"\x65")
                        channel._ack(response, 19)
                except (ConsolidatedError, *_NATIVE_BASE_ERRORS) as exc:
                    driver_error = _native_driver_slot(exc, driver_error)
                    rt.check()
                    failure = code(exc)
                    # 14e30 resets borrowed external vectors only, with no observers.
                    native_counts[current] = native_percentages[current] = 0
                finally:
                    if handle is not None:
                        release(handle, "stop_filter")
                if failure is not None:
                    break
                current += 1
        if failure is not None:
            state.password_changed = (
                True
                if last_range
                else not state.password_changed
                if failure == 7
                else False
            )
            observe_error()
            while decisions < len(context.retry_decisions):
                accepted = context.retry_decisions[decisions]
                decisions += 1
                if not accepted:
                    break
                failure = 0
                driver_error = 0
                try:
                    _void(rt, "disconnect")
                except (*_NATIVE_BASE_ERRORS, NativeException2026):
                    rt.check()
                    swallowed.append("disconnect")
                try:
                    _void(rt, "connect", protocol=6)
                except _NATIVE_DRIVER_ERRORS as exc:
                    driver_error = _native_driver_slot(exc, driver_error)
                    if not _is_driver_error(exc):
                        raise
                    rt.check()
                    failure = _native_enum(exc)
                    observe_error()
                    continue
                retry_prepared = True
                break
    finally:
        _void(rt, "set_timeout", cleanup=True, milliseconds=prior)
    observe_error()
    return {
        "writer_completed": completed,
        "completion_callback": "normal" if completed else "error",
        "programming_completed": False,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "error_code": failure,
        "driver_error": driver_error,
        "native_error_code": 0 if failure is None else failure,
        "retry_prepared": retry_prepared,
        "retry_decisions_consumed": decisions,
        "counts": tuple(native_counts),
        "percentages": tuple(native_percentages),
        "password_changed": state.password_changed,
        "swallowed_native_faults": tuple(swallowed),
    }


# CRT3d00's27 CPU/firmware words, passively authenticated in vpns-table-proof.json.
_VPNS_FIRMWARE = (
    ("72", 356),
    ("75", 365),
    ("76", 364),
    ("77", 358),
    ("80", 372),
    ("81", 371),
    ("82", 360),
    ("91", 342),
    ("96", 353),
    ("97", 344),
    ("95", 346),
    ("110", 333),
    ("114", 369),
    ("115", 345),
    ("111", 341),
    ("112", 332),
    ("113", 331),
    ("128", 339),
    ("129", 356),
    ("133", 354),
    ("134", 312),
    ("135", 311),
    ("138", 320),
    ("139", 319),
    ("140", 325),
    ("141", 314),
    ("163", 383),
)


def consolidated_vpns_key(seed: bytes) -> bytes:
    """13360 six-byte sequential in-place rotate/add; source indices use original seed."""
    if type(seed) is not bytes or len(seed) != 6:
        raise ValueError("Exactly six native VPNS seed bytes required")
    key = bytearray(seed)
    for index, shift in enumerate((1, 2, 3, 3, 2, 1)):
        rotation = ((seed[index] >> shift) & 3) + 1
        value = seed[index]
        reference = (value & 7) % 6
        key[index] = (
            key[reference] + ((value << rotation) | (value >> (8 - rotation)))
        ) & 255
    return bytes(key)


def prepare_sil_occupant(runtime: NativeRuntime2026, *, vpns: bool = False):
    """23620 primitive diagnostic FAST_INIT/security/session before raw programming."""
    if type(vpns) is not bool:
        raise ValueError("Literal native occupant/VPNS branch required")
    diag = SilDiag2026(runtime)
    target = 0xD3 if vpns else 0x5B
    diag.fast_init(target, mobd=not vpns)
    _void(runtime, "wait", milliseconds=100)
    if vpns:
        seed = diag.exchange(
            diag.packet(bytes((0x82, target, 0xF1, 0x27, 0x61))),
            header=bytes((0x88, 0xF1, target)),
            payload=b"\x67\x61",
            minimum=12,
            error_code=16,
        )[5:11]
        key = consolidated_vpns_key(seed)
        diag.exchange(
            diag.packet(b"\x88\xd3\xf1\x27\x62" + key),
            header=bytes((0x83, 0xF1, target)),
            payload=b"\x67\x62\x34",
            minimum=6,
            error_code=17,
        )
    else:
        seed = diag.exchange(
            diag.packet(bytes((0x84, target, 0xF1, 0x27, 1, 0x5D, 0xC2))),
            header=bytes((0x84, 0xF1, target)),
            payload=b"\x67\x01",
            minimum=7,
            error_code=16,
        )[5:7]
        key = ((0x61A4 + ~int.from_bytes(seed, "big")) & 65535).to_bytes(2, "big")
        diag.exchange(
            diag.packet(bytes((0x84, target, 0xF1, 0x27, 2)) + key),
            header=bytes((0x83, 0xF1, target)),
            payload=b"\x67\x02\xaa",
            minimum=6,
            error_code=17,
        )
    diag.exchange(
        diag.packet(bytes((0x82, target, 0xF1, 0x10, 2))),
        header=bytes((0x81, 0xF1, target)),
        payload=b"\x50",
        minimum=4,
        delay_ms=0,
        error_code=18,
    )
    _void(runtime, "wait", milliseconds=1500 if vpns else 500)


@dataclass
class SILOccupantWriteState(SILWriteState):
    last_range: bool = False
    block_started: bool = False

    def __post_init__(self):
        super().__post_init__()
        if type(self.last_range) is not bool or type(self.block_started) is not bool:
            raise ValueError("Actual borrowed native range/started bytes required")


@dataclass(frozen=True)
class SILOccupantWriteContext(SILWriteContext):
    state: SILOccupantWriteState
    writer_family = "sil_occupant_write"

    def __post_init__(self):
        super().__post_init__()
        if not isinstance(self.state, SILOccupantWriteState):
            raise TypeError("Native occupant/VPNS borrowed state required")


def bind_sil_occupant_writer(
    container,
    identity: NativeModuleIdentity,
    state: SILOccupantWriteState,
    *,
    cpu_index: int = 0,
    target_index: int = 0,
    retry_decisions: tuple[bool, ...] = (),
    general_parameters=None,
) -> SILOccupantWriteContext:
    """23580 actual selected global CPU/TargetData and materialized image binding."""
    from scripts.calibration_2026 import (
        native2026_archive,
        native2026_cpu_count,
        native2026_cpu_targets,
        native2026_cpu_type,
        native2026_location_id,
        native2026_metadata,
        native2026_metadata_for_cpu,
    )

    _identity(identity)
    metadata = native2026_metadata(container)
    count = native2026_cpu_count(metadata)
    if (
        type(cpu_index) is not int
        or not 0 <= cpu_index < count <= 256
        or type(target_index) is not int
        or target_index < 0
    ):
        raise ValueError("Actual selected CPU/TargetData indices required")
    cpus = tuple(native2026_cpu_type(metadata, index) for index in range(count))
    if (
        select_branch(
            identity,
            metadata.vehicle.get("contacttype", ""),
            metadata.vehicle.get("kindofecu", ""),
            cpus,
            writing=True,
            cpu_index=cpu_index,
        ).family
        != "sil_occupant_write"
    ):
        raise ValueError("Imported metadata does not select occupant/VPNS writer")
    targets = native2026_cpu_targets(metadata, cpu_index)
    if target_index >= len(targets):
        raise ValueError("Selected native TargetData absent")
    location = native2026_location_id(metadata, cpu_index)
    if len(location) != 16 or any(c not in "0123456789abcdefABCDEF" for c in location):
        raise ValueError("Actual native LocationID requires sixteen hex digits")
    archive = native2026_archive(native2026_metadata_for_cpu(metadata, cpu_index))
    if archive.streamed or type(archive.data) is not bytes:
        raise ValueError("Actual materialized selected archive required")
    return SILOccupantWriteContext(
        identity,
        metadata.vehicle.get("kindofecu", ""),
        cpus[cpu_index],
        bytes.fromhex(location),
        targets[target_index].password,
        archive.data,
        archive.flash_size,
        state,
        cpu_index,
        retry_decisions,
        general_parameters,
    )


def write_sil_occupant(
    context: SILOccupantWriteContext,
    runtime: NativeRuntime2026,
    *,
    progress=None,
    error_snapshot=None,
) -> dict:
    """247e0 complete kind37 occupant/kind63 VPNS worker; prelude outside native catch."""
    driver_error = 0
    if error_snapshot is not None and not callable(error_snapshot):
        raise TypeError("Native error-slot observer must be callable")

    def observe_error():
        if error_snapshot is not None:
            error_snapshot(0 if failure is None else failure, driver_error)

    if (
        not isinstance(context, SILOccupantWriteContext)
        or not isinstance(runtime, NativeRuntime2026)
        or progress is not None
        and not callable(progress)
    ):
        raise TypeError("Actual native occupant/VPNS context/runtime/progress required")
    context.__post_init__()
    if runtime.call("get_protocol_id") != 3:
        raise ValueError("Occupant/VPNS requires upstream connected protocol3")
    rt, state, channel = runtime, context.state, ConsolidatedSILFlash2026(runtime)
    vpns = context.kind_of_ecu != "37"
    prior = rt.call("get_timeout") if vpns else None
    prepare_sil_occupant(rt, vpns=vpns)
    completed = retry_prepared = False
    failure, phase, decisions = 0, "prepare", 0
    swallowed = []
    try:
        try:
            if vpns:
                _void(rt, "set_timeout", milliseconds=5000)
            _void(rt, "control_io", ioctl=2, parameters=((1, 10400 if vpns else 9600),))
            _void(rt, "control_io", ioctl=2, parameters=((0x0C, 0),))
            password = (
                consolidated_archive_password(
                    context.image,
                    context.general_parameters,
                    context.kind_of_ecu,
                    context.cpu_type,
                    "SIL",
                )
                if state.password_changed
                else context.password
            )
            if vpns:
                channel.enter_programming(context.location_id, password, p2_max=170)
                word = next(
                    (word for cpu, word in _VPNS_FIRMWARE if cpu == context.cpu_type),
                    None,
                )
                if word is None:
                    raise ConsolidatedError(9999, "vpns_cpu")
                channel.memory_shrink = bool(word >> 8)
            else:
                for index, data in enumerate(
                    (
                        b"\0",
                        b"\0",
                        context.location_id[:2][::-1],
                        context.location_id[2:4][::-1],
                        password.to_bytes(4, "little"),
                    )
                ):
                    channel._write(data)
                    if index != 4:
                        _void(rt, "wait", milliseconds=0)
                if channel.read_exact(17)[0] != 0x3C:
                    raise ConsolidatedError(7, "occupant_programming_password")
                channel._write(b"\x3c")
                channel.memory_shrink = consolidated_sil_cpu_mode(context.cpu_type)[1]
                channel.discover_baud(context.cpu_type)
                try:
                    channel.select_programming_mode(0)
                except ConsolidatedSILBootError as exc:
                    raise ConsolidatedError(5, "occupant_mode") from exc
            memory = channel.memory_info()
            if vpns:
                actual = (
                    memory.firmware_version & 127
                    if channel.memory_shrink
                    else (memory.firmware_version >> 4) & 7
                )
                matches = (bool(word >> 8), word & 255) == (
                    channel.memory_shrink,
                    actual,
                )
            else:
                matches = consolidated_firmware_matches(
                    context.cpu_type,
                    memory.firmware_version,
                    bool(channel.memory_shrink),
                )
            if not matches:
                raise ConsolidatedError(10, "occupant_firmware")
            try:
                sizes = consolidated_block_sizes(context.cpu_type, memory)
                ranges = consolidated_block_ranges(context.cpu_type, len(sizes))
                for index, (first, last) in enumerate(ranges):
                    blank = (
                        False
                        if context.kind_of_ecu == "30"
                        else channel.block("blank", first, last_block=last)
                    )
                    state.last_range = index + 1 == len(ranges)
                    if not blank:
                        channel.block("erase", first, last_block=last)
                    channel.write_block(
                        first,
                        sizes,
                        memory,
                        context.image,
                        context.flash_size,
                        progress=progress,
                        last_block=last,
                    )
                    channel.block("inverify", first, last_block=last)
                    channel.verify_block(
                        first,
                        sizes,
                        context.image,
                        context.flash_size,
                        progress=progress,
                        last_block=last,
                    )
                if vpns:
                    channel._write(b"\x80")
                    if not channel._receive_ack():
                        raise ConsolidatedError(35, "vpns_finish")
            except (ConsolidatedError, *_NATIVE_BASE_ERRORS, NativeException2026):
                rt.check()
                state.block_started = True
                phase = "write"
                raise
            completed, failure = True, None
            state.password_changed = state.last_range = state.block_started = False
        except (ConsolidatedError, *_NATIVE_BASE_ERRORS, NativeException2026) as exc:
            driver_error = _native_driver_slot(exc, driver_error)
            rt.check()
            if isinstance(exc, ConsolidatedError):
                failure = exc.code
            elif isinstance(exc, _NATIVE_BASE_ERRORS):
                failure = _native_enum(exc)
            # 24ef0 called by CJ/CPass catches only; unknown ALL retains progress.
            if isinstance(exc, (ConsolidatedError, *_NATIVE_BASE_ERRORS)):
                channel.count = 0
                if progress is not None:
                    progress("count", 0)
                    rt.check()
                channel.percent = 0
                if progress is not None:
                    progress("percent", 0)
                    rt.check()
            state.password_changed = (
                True
                if state.last_range
                else not state.password_changed
                if failure == 7
                else False
            )
            observe_error()
            while decisions < len(context.retry_decisions):
                accepted = context.retry_decisions[decisions]
                decisions += 1
                if not accepted:
                    break
                failure = 0
                driver_error = 0
                try:
                    _void(rt, "disconnect")
                except (*_NATIVE_BASE_ERRORS, NativeException2026):
                    rt.check()
                    swallowed.append("disconnect")
                try:
                    _void(rt, "connect", protocol=3)
                except _NATIVE_DRIVER_ERRORS as exc:
                    driver_error = _native_driver_slot(exc, driver_error)
                    if not _is_driver_error(exc):
                        raise
                    rt.check()
                    failure = _native_enum(exc)
                    observe_error()
                    continue
                retry_prepared = True
                break
    finally:
        if vpns:
            _void(rt, "set_timeout", cleanup=True, milliseconds=prior)
    observe_error()
    return {
        "writer_completed": completed,
        "completion_callback": "normal" if completed else "error",
        "programming_completed": False,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "error_code": failure,
        "driver_error": driver_error,
        "native_error_code": 0 if failure is None else failure,
        "error_phase": None if completed else phase,
        "retry_prepared": retry_prepared,
        "retry_decisions_consumed": decisions,
        "count": channel.count,
        "percent": channel.percent,
        "password_changed": state.password_changed,
        "last_range": state.last_range,
        "block_started": state.block_started,
        "swallowed_native_faults": tuple(swallowed),
    }


@dataclass(frozen=True)
class ConsolidatedExecuteContext:
    """Literal caller context bytes978/980/9c4 and global CPU/TargetData vector738/73c."""

    writing: bool = False
    cpu_index: int = 0
    target_indices: tuple[int, ...] = ()
    recovery_timeout: bool = False
    getter_option_9c4: int = 0
    retry_decisions: tuple[bool, ...] = ()

    def __post_init__(self):
        if (
            any(
                type(value) is not bool
                for value in (self.writing, self.recovery_timeout)
            )
            or type(self.cpu_index) is not int
            or not 0 <= self.cpu_index < 256
            or type(self.getter_option_9c4) is not int
            or not 0 <= self.getter_option_9c4 <= 255
            or type(self.target_indices) is not tuple
            or len(self.target_indices) > 256
            or any(
                type(v) is not int or not 0 <= v < 65536 for v in self.target_indices
            )
            or type(self.retry_decisions) is not tuple
            or len(self.retry_decisions) > 256
            or any(type(v) is not bool for v in self.retry_decisions)
        ):
            raise ValueError("Bounded literal native Execute caller context required")


class ConsolidatedExecute2026:
    """13170 persistent controller, actual metadata dispatch and synchronous worker bridge.

    Native05e80/05d70 thread rendezvous is represented synchronously. Every worker
    still performs real primitive operations; completion comes from that worker's
    native callback result. One instance represents the DLL's retained controller.
    """

    def __init__(
        self, identity: NativeModuleIdentity, general_parameters, *, common_definitions
    ):
        from scripts.programming_2026_common import (
            CommonDefinitions2026,
            NativeGeneralParameters2026,
        )

        _identity(identity)
        if not isinstance(general_parameters, NativeGeneralParameters2026):
            raise TypeError("Actual global Parameter.ini source required")
        if not isinstance(common_definitions, CommonDefinitions2026):
            raise TypeError("Actual shared native CommonDefinitions2026 required")
        self.common_definitions = common_definitions
        self.identity, self.general_parameters = identity, general_parameters
        self.state = ConsolidatedControllerState()
        self.created = self.active = False
        self.parameter_keys = None
        self.getter_option_9c4 = 0
        self.target_indices: tuple[int, ...] = ()
        self.password_changed = False
        self.last_range = False
        self.driver_error = self.error_code = 0
        self.occupant_state = SILOccupantWriteState()
        self.electric_state = CANElectricWriteState()
        self.sil_state = SILWriteState()
        self.counts: list[int] = []
        self.percentages: list[int] = []

    def _initialize(self, metadata):
        if self.created:
            return
        # Native controller pointer exists before parameter initialization; failed
        # initialization does not cause a second constructor/LoadParameter next call.
        self.created = True
        parameter = self.general_parameters._parameter()
        names = (
            "EngineTypeFlag",
            "PasswordAddress",
            "ByteOrder",
            "CalibrationType",
            "FlagToUseGetFlashSizeFunc",
            "WriteDataSize",
            "FlagToClearDTCOfENGECTWithMode04",
            "FlagToOutputAllAttachedInformation",
            "M16CTypeFlag",
            "FORESTTypeFlag",
            "FlagToChangeProtocolAtSuccessGetCID",
            "FlagToChangeWFSE",
            "CPUTypeWithModeChangeAtCPUTypeChangeFlag",
            "FlagToDoIGOFFONAtCPUTypeChange",
            "WaitTimeForIGOFFON",
            "KindOfECUNames",
            "FlagToWriteCIDAfterRepro",
            "FlagToUseCIDGetterAndFlashWriterDLL",
            "WaitTimeAfterIGOn",
            "FlagToChangeToReprogGWModeForCentralGW",
            "FlagToHoldSFormatRecords",
            "ClassNameForOEMVINReader",
            "FlagToNonVerifyProcess",
            "FlagToDisableSelectNewCalButton",
            "FlagToDisplayPSACableAttachOrRemoveScreen",
            "FlagToCancelAutomaticIGOFF",
            "FlagToReceiveRespForFinish",
            "WaitTimeAfterBatteryDisconnected",
            "WaitTimeAfterBatteryConnected",
            "BatteryVoltageUpperThreshold",
            "AlternateWaitTimeForIGOFFON",
        )
        if any(
            parameter.string_with_keys(name, "", "", "P5-Unified") is None
            for name in names
        ):
            raise ConsolidatedError(9999, "execute_load_parameters")
        from scripts.calibration_2026 import native2026_cpu_type

        keys = (
            metadata.vehicle.get("kindofecu", ""),
            native2026_cpu_type(metadata, 0),
            metadata.vehicle.get("contacttype", ""),
        )
        if not parameter.set_keys(*keys):
            raise ConsolidatedError(9999, "execute_set_keys")
        self.parameter_keys = keys

    def execute(
        self,
        container,
        runtime: NativeRuntime2026,
        context: ConsolidatedExecuteContext | None = None,
        *,
        attachments=None,
        progress=None,
    ) -> dict:
        from collections.abc import Mapping

        from scripts.calibration_2026 import (
            native2026_cpu_count,
            native2026_cpu_type,
            native2026_metadata,
        )

        if context is None:
            context = ConsolidatedExecuteContext()
        if (
            not isinstance(runtime, NativeRuntime2026)
            or not isinstance(context, ConsolidatedExecuteContext)
            or attachments is not None
            and not isinstance(attachments, Mapping)
            or progress is not None
            and not callable(progress)
        ):
            raise TypeError(
                "Actual consolidated Execute runtime/context/attachments/progress required"
            )
        context.__post_init__()
        if self.active:
            raise RuntimeError(
                "Native consolidated DLL globals do not support reentrant Execute"
            )
        metadata = native2026_metadata(container)
        count = native2026_cpu_count(metadata)
        if not 0 <= context.cpu_index < count <= 256:
            raise ValueError("Selected actual global CPU absent")
        if context.writing and len(context.target_indices) < count:
            raise ValueError(
                "Actual caller TargetData index vector must cover every native CPU"
            )
        if not self.created:
            capacity = self.common_definitions.num_cpu_maxnum
            if not count <= capacity <= 256:
                raise ValueError(
                    "Actual shared CPU capacity must cover imported CPUs within host bounds"
                )
            self.counts, self.percentages = [0] * capacity, [0] * capacity
        elif count > len(self.counts):
            raise ValueError(
                "Imported CPU count exceeds retained native controller capacity"
            )
        if context.writing and len(context.target_indices) > len(self.counts):
            raise ValueError(
                "Caller TargetData vector exceeds actual retained native capacity"
            )
        self.active = True
        family = None
        try:
            try:
                self._initialize(metadata)
                cpus = tuple(
                    native2026_cpu_type(metadata, index) for index in range(count)
                )
                branch = select_branch(
                    self.identity,
                    metadata.vehicle.get("contacttype", ""),
                    metadata.vehicle.get("kindofecu", ""),
                    cpus,
                    writing=context.writing,
                    cpu_index=context.cpu_index,
                    old_spec_ecb=self.state.old_spec_ecb,
                )
                family = branch.family
                if not context.writing:
                    self.getter_option_9c4 = context.getter_option_9c4

                    def getter_error_snapshot(code, driver):
                        self.error_code, self.driver_error = code, driver

                    getter_context = bind_native_context(container, self.identity)
                    getter_failed = False
                    self.state.getter_completion_callback = "normal"
                    try:
                        identifiers = get_identifiers(
                            getter_context,
                            runtime,
                            self.state,
                            error_snapshot=getter_error_snapshot,
                        )
                    except (
                        ConsolidatedError,
                        *_NATIVE_BASE_ERRORS,
                        NativeException2026,
                    ) as exc:
                        runtime.check()
                        if "_consolidated_getter_error" not in exc.__dict__:
                            raise
                        getter_failed = True
                        self.state.getter_completion_callback = "error"
                        identifiers = tuple(getattr(exc, "partial_identifiers", ()))
                        if isinstance(getter_context, CANIdentifierContext):
                            self.state.request_id_records = ()
                        elif (
                            isinstance(getter_context, SoftwareIdentifierContext)
                            and getter_context.kind_of_ecu == "4"
                        ):
                            # A failed ROM worker has no completed request rows.
                            self.state.request_id_records = ()
                    return {
                        "execute_return": self.state.getter_completion_callback
                        == "normal",
                        "completion_callback": self.state.getter_completion_callback,
                        "execute_return_origin": "host_projection_of_completion_byte",
                        "native_callback_completed": self.state.getter_completion_callback
                        == "normal",
                        "caller_old_spec_ecb_9e8": self.state.native_context_9e8,
                        "family": family,
                        "identifiers": identifiers,
                        "caller_error_code_754": self.error_code,
                        "caller_driver_error_758": self.driver_error,
                        "error_code": self.error_code if getter_failed else None,
                        "driver_error": self.driver_error,
                        "native_error_code": self.error_code,
                        "caller_failed_974": False,
                        "caller_abort_744": False,
                        "programming_completed": False,
                        "physical_status": "PHYSICAL_UNCONFIRMED",
                    }
                self.target_indices = context.target_indices
                common: dict[str, Any] = {
                    "cpu_index": context.cpu_index,
                    "retry_decisions": context.retry_decisions,
                }
                selected = dict(
                    common, target_index=context.target_indices[context.cpu_index]
                )
                bound: Any = None
                worker: Callable[..., dict]
                if family == "can_emps_write":
                    bound = bind_can_emps_writer(
                        container,
                        self.identity,
                        attachments or {},
                        retry_decisions=context.retry_decisions,
                    )
                    worker = write_can_emps
                elif family == "sil_emps_write":
                    bound = bind_sil_emps_writer(
                        container,
                        self.identity,
                        retry_decisions=context.retry_decisions,
                    )
                    worker = write_sil_emps
                elif family == "sil_m16c_write":
                    bound = bind_sil_m16c_writer(
                        container,
                        self.identity,
                        target_indices=context.target_indices[:count],
                        **common,
                    )
                    worker = write_sil_m16c
                elif family == "can_fc_write":
                    bound = bind_can_fc_writer(
                        container,
                        self.identity,
                        self.state,
                        attachments or {},
                        **selected,
                    )
                    worker = write_can_fc
                elif family == "can_epb_write":
                    bound = bind_can_epb_writer(
                        container,
                        self.identity,
                        attachments or {},
                        recovery_timeout=context.recovery_timeout,
                        **selected,
                    )
                    worker = write_can_epb
                elif family == "can_electric_write":
                    self.electric_state.password_changed = self.password_changed
                    self.electric_state.last_block = self.last_range
                    bound = bind_can_electric_writer(
                        container,
                        self.identity,
                        self.electric_state,
                        general_parameters=self.general_parameters,
                        **selected,
                    )
                    worker = write_can_electric
                elif family in ("can_chassis_write", "can_old_ecb_write"):
                    password = CANOldECBWriteState(self.password_changed)
                    args: dict[str, Any] = dict(
                        target_indices=context.target_indices[:count],
                        general_parameters=self.general_parameters,
                        **common,
                    )
                    if family == "can_chassis_write":
                        bound = bind_can_chassis_writer(
                            container,
                            self.identity,
                            self.state,
                            password,
                            attachments or {},
                            recovery_timeout=context.recovery_timeout,
                            **args,
                        )
                        worker = write_can_chassis
                    else:
                        bound = bind_can_old_ecb_writer(
                            container,
                            self.identity,
                            self.state,
                            password,
                            attachments or {},
                            **args,
                        )
                        worker = write_can_old_ecb
                elif family == "sil_write":
                    self.sil_state.password_changed = self.password_changed
                    bound = bind_sil_writer(
                        container,
                        self.identity,
                        self.sil_state,
                        general_parameters=self.general_parameters,
                        **selected,
                    )
                    worker = write_sil
                elif family == "sil_occupant_write":
                    self.occupant_state.password_changed = self.password_changed
                    self.occupant_state.last_range = self.last_range
                    bound = bind_sil_occupant_writer(
                        container,
                        self.identity,
                        self.occupant_state,
                        general_parameters=self.general_parameters,
                        **selected,
                    )
                    worker = write_sil_occupant
                else:
                    raise ConsolidatedError(9999, "execute_writer")

                def notify(*values):
                    if len(values) == 2:
                        key, value = values
                        index = context.cpu_index
                    else:
                        key, index, value = values
                    if key == "count":
                        self.counts[index] = value
                    elif key == "percent":
                        self.percentages[index] = value
                    if progress is not None:
                        progress(*values)

                def error_snapshot(code, driver):
                    # c340 publishes caller754/758 before the native retry UI.
                    self.error_code, self.driver_error = code, driver

                def snapshot(field, values, cpu_index):
                    target = self.counts if field == "count" else self.percentages
                    target[:] = values
                    if progress is not None:
                        progress(field, values[cpu_index])

                try:
                    if family in (
                        "can_fc_write",
                        "can_epb_write",
                        "can_electric_write",
                        "can_chassis_write",
                        "can_old_ecb_write",
                    ):
                        if family in (
                            "can_fc_write",
                            "can_epb_write",
                            "can_electric_write",
                        ):
                            from dataclasses import replace

                            bound = replace(bound, cpu_count=len(self.counts))
                        report = worker(
                            bound,
                            runtime,
                            error_snapshot=error_snapshot,
                            progress_snapshot=snapshot,
                            counts=self.counts,
                            percentages=self.percentages,
                        )
                    elif family == "sil_m16c_write":

                        def scalar_snapshot(count, percent):
                            self.counts[context.cpu_index] = count
                            self.percentages[context.cpu_index] = percent

                        report = worker(
                            bound,
                            runtime,
                            progress=notify,
                            progress_snapshot=scalar_snapshot,
                            error_snapshot=error_snapshot,
                        )
                    else:
                        report = worker(
                            bound,
                            runtime,
                            progress=notify,
                            error_snapshot=error_snapshot,
                        )
                finally:
                    if family in (
                        "can_electric_write",
                        "sil_occupant_write",
                        "sil_write",
                        "can_chassis_write",
                        "can_old_ecb_write",
                    ):
                        self.password_changed = bound.state.password_changed
                    if family == "can_electric_write":
                        self.last_range = self.electric_state.last_block
                    elif family == "sil_occupant_write":
                        self.last_range = self.occupant_state.last_range
                if "password_changed" in report:
                    self.password_changed = report["password_changed"]
                if "counts" in report:
                    self.counts[:] = report["counts"]
                    self.percentages[:] = report["percentages"]
                else:
                    self.counts[context.cpu_index] = report["count"]
                    self.percentages[context.cpu_index] = report["percent"]
                return {
                    **report,
                    "caller_error_code_754": self.error_code,
                    "caller_driver_error_758": self.driver_error,
                    "family": family,
                    "execute_return_origin": "host_projection_of_completion_byte",
                    "native_callback_completed": report.get(
                        "completion_callback",
                        "normal" if report["writer_completed"] else "error",
                    )
                    == "normal",
                    "caller_old_spec_ecb_9e8": self.state.native_context_9e8,
                    "execute_return": report.get(
                        "completion_callback",
                        "normal" if report["writer_completed"] else "error",
                    )
                    == "normal",
                    "counts": tuple(self.counts),
                    "percentages": tuple(self.percentages),
                    "caller_failed_974": False,
                    "caller_abort_744": not report["writer_completed"]
                    and not report.get("retry_prepared", False),
                }
            except (ConsolidatedError, *_NATIVE_BASE_ERRORS) as exc:
                runtime.check()
                self.error_code = (
                    exc.code
                    if isinstance(exc, ConsolidatedError)
                    else _native_enum(exc)
                )
                return {
                    "caller_error_code_754": self.error_code,
                    "caller_driver_error_758": self.driver_error,
                    "execute_return": False,
                    "execute_return_origin": "host_projection_of_completion_byte",
                    "native_callback_completed": False,
                    "caller_old_spec_ecb_9e8": self.state.native_context_9e8,
                    "family": family,
                    "error_code": exc.code
                    if isinstance(exc, ConsolidatedError)
                    else _native_enum(exc),
                    "driver_error": self.driver_error,
                    "native_error_code": exc.code
                    if isinstance(exc, ConsolidatedError)
                    else _native_enum(exc),
                    "caller_failed_974": True,
                    "caller_abort_744": True,
                    "programming_completed": False,
                    "physical_status": "PHYSICAL_UNCONFIRMED",
                }
        finally:
            self.active = False
