"""Static, source-admitted original CUW executable address factories.

Address bytes remain in the caller's private executable. Importing this module
never loads or executes a PE and never opens communication.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING

from scripts.cuw_legacy_engine import ExecutableContext, ExecutableImage, ExecutableIO

if TYPE_CHECKING:
    from scripts.cuw_legacy_can import CommonCAN


class NativeAddressFault(ValueError):
    """A native address producer requires an unavailable/invalid memory source."""


@dataclass(frozen=True)
class AddressConfig:
    """Snapshot of the optional native object's +14 count and +c string getter."""

    values: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.values) is not tuple
            or len(self.values) > 4096
            or any(
                type(value) is not str or len(value) > 128 or "\0" in value
                for value in self.values
            )
        ):
            raise ValueError("Bounded immutable native configuration strings required")


@dataclass(frozen=True)
class CAddress:
    """The exact native eight-byte record, including uninterpreted bytes."""

    raw: bytes

    def __post_init__(self) -> None:
        if type(self.raw) is not bytes or len(self.raw) != 8:
            raise ValueError("Native CAddress must contain exactly eight bytes")

    @property
    def identifier(self) -> int:
        return self.raw[0]

    @property
    def request_header(self) -> bytes:
        return b"\0\0" + self.raw[1:3]

    @property
    def response_header(self) -> bytes:
        return b"\0\0" + self.raw[4:6]

    @property
    def diagnostic_request_header(self) -> bytes:
        return self.request_header + (self.raw[3:4] if self.extended else b"")

    @property
    def diagnostic_response_header(self) -> bytes:
        return self.response_header + (self.raw[6:7] if self.extended else b"")

    @property
    def extended(self) -> bool:
        return self.raw[7] != 0


@dataclass(frozen=True)
class AddressFactoryState:
    """Native process-global vectors, copied from their actual metadata producers.

    Empty defaults and FC rows are the native post-constructor state. They are
    never manufactured from a DLL address catalog or from selected LocationID.
    """

    default_selectors: bytes = b""
    fuel_cell_rows: tuple[tuple[str, bytes], ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.default_selectors) is not bytes
            or len(self.default_selectors) > 4096
            or type(self.fuel_cell_rows) is not tuple
            or len(self.fuel_cell_rows) > 4096
            or any(
                type(row) is not tuple
                or len(row) != 2
                or type(row[0]) is not str
                or len(row[0]) > 128
                or "\0" in row[0]
                or type(row[1]) is not bytes
                or len(row[1]) != 7
                for row in self.fuel_cell_rows
            )
        ):
            raise ValueError(
                "Bounded original address-factory vector snapshots required"
            )


_INITIAL_FACTORY_STATE = AddressFactoryState()


def _string(image: ExecutableImage, pointer: int) -> str:
    address = int.from_bytes(image.read(pointer, 4), "little")
    value = bytearray()
    for offset in range(129):
        char = image.read(address + offset, 1)
        if char == b"\0":
            return value.decode("ascii")
        value.extend(char)
    raise NativeAddressFault("Native factory string exceeds host bound")


# These are native selector IDs, never OEM frame bytes. Original18 41ac7c.
_SINGLE = {
    "3": 5,
    "5": 6,
    "7": 31,
    "8": 47,
    "11": 47,
    "12": 11,
    "14": 16,
    "15": 17,
    "19": 27,
    "20": 32,
    "21": 33,
    "23": 36,
    "24": 28,
    "27": 29,
    "28": 30,
    "29": 38,
    "30": 42,
    "33": 41,
    "34": 43,
    "35": 44,
    "38": 54,
    "39": 48,
    "40": 49,
    "41": 50,
    "42": 51,
    "43": 52,
    "44": 53,
    "45": 55,
    "46": 56,
    "47": 57,
    "48": 58,
    "49": 59,
    "50": 63,
    "51": 61,
    "52": 62,
    "53": 64,
    "61": 60,
}


def _selectors(
    image: ExecutableImage,
    kind: str,
    config: AddressConfig | None,
    reprog_mode: bool,
    factory_state: AddressFactoryState,
    build: int,
) -> tuple[int, ...]:
    count = 0 if config is None else len(config.values)
    if kind in _SINGLE:
        return (_SINGLE[kind],)
    if kind == "0":
        if config is None:
            return (0, 1)
        special_base = 0x586190 if build == 12 else 0x5D620C
        special = tuple(_string(image, special_base + offset) for offset in (0, 4, 8))
        return (
            (0, 2, 1)
            if sum(value.startswith(special) for value in config.values) > 1
            else (0,)
        )
    if kind == "2":
        return (3, 0)
    if kind in ("1", "10", "16"):
        if config is not None:
            # Native 41b7d7/41ca3a/41dc7f pass this DWORD as a byte source.
            if not factory_state.default_selectors:
                raise NativeAddressFault("Native configuration selector source is NULL")
            first = factory_state.default_selectors[0]
            if kind == "1":
                extra = (
                    (4,)
                    if any(
                        value.startswith(
                            _string(image, 0x58619C if build == 12 else 0x5D6218)
                        )
                        for value in config.values
                    )
                    else ()
                )
                return (first,) + extra
            return (first,)
        return {"1": (18, 3), "10": (19, 10), "16": (21, 20)}[kind]
    if kind == "6":
        return (7, 5, 8)
    if kind == "4":
        return (9,) * max(1, count)
    if kind == "9":
        return (12, 13, 14) if count > 1 else (12,)
    if kind == "13":
        return (15,) * max(1, count)
    if kind == "17":
        return (26,) if reprog_mode else ((22,) if config is None else (23,))
    if kind == "18":
        return (24,) if config is None else (25,)
    if kind == "22":
        return (34,) if config is None else (35,)
    if kind == "25":
        return (37,) if config is None else (0, 2, 1, 37)
    if kind == "31":
        return (39,) if config is None else (40, 39)
    if kind == "32":
        return (40,) if config is None else (40, 39)
    if kind == "36":
        return (45,) if config is None else (46,)
    return ()


def select_legacy_addresses(
    context: ExecutableContext,
    kind_of_ecu: str,
    config: AddressConfig | None = None,
    *,
    reprog_mode: bool = False,
    factory_state: AddressFactoryState = _INITIAL_FACTORY_STATE,
) -> tuple[CAddress, ...]:
    """41ac7c: reverse selected IDs, then copy first matching private table row.

    Unknown kinds yield an empty vector, as native. Configuration absence and an
    empty configuration are different native states. No LocationID/catalog fallback.
    """
    if (
        not isinstance(context, ExecutableContext)
        or type(kind_of_ecu) is not str
        or len(kind_of_ecu) > 128
        or "\0" in kind_of_ecu
        or (config is not None and not isinstance(config, AddressConfig))
        or type(reprog_mode) is not bool
        or not isinstance(factory_state, AddressFactoryState)
    ):
        raise ValueError("Native context, literal KindOfECU and typed state required")
    image = ExecutableImage(context)
    identifiers = _selectors(
        image, kind_of_ecu, config, reprog_mode, factory_state, context.build
    )
    table = image.read(0x5861A0 if context.build == 12 else 0x5D621C, 65 * 8)
    if len(table) != 65 * 8:
        raise NativeAddressFault("Truncated private native address table")
    rows = tuple(
        CAddress(table[offset : offset + 8]) for offset in range(0, len(table), 8)
    )
    result = []
    for identifier in reversed(identifiers):
        for row in rows:
            if row.identifier == identifier:
                result.append(row)
                break
    return tuple(result)


def legacy_kind_override(context: ExecutableContext) -> str:
    """Body/DSS secondary preparation uses this actual native string pointer."""
    image = ExecutableImage(context)
    return _string(image, 0x5854C8 if context.build == 12 else 0x5D51E4)


def select_fuel_cell_address(
    context: ExecutableContext,
    key: str,
    factory_state: AddressFactoryState,
    previous: CAddress,
) -> CAddress:
    """424d1c: first exact key wins; absent key preserves the caller's record."""
    if (
        not isinstance(context, ExecutableContext)
        or type(key) is not str
        or len(key) > 128
        or "\0" in key
        or not isinstance(factory_state, AddressFactoryState)
        or not isinstance(previous, CAddress)
    ):
        raise ValueError(
            "Source context, native FC key/vector and prior record required"
        )
    ExecutableImage(context)
    for candidate, row in factory_state.fuel_cell_rows:
        if candidate == key:
            return CAddress(b"\x41" + row)
    return previous


@dataclass(frozen=True)
class AddressDiscovery:
    """Source-bound output of native CID discovery and its published vectors."""

    build: int
    container_sha256: str
    cids: tuple[str, ...]
    addresses: tuple[CAddress | P5Address, ...]
    reprog_mode: bool
    queried_addresses: tuple[CAddress | P5Address, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.build) is not int
            or self.build not in (12, 18)
            or type(self.container_sha256) is not str
            or len(self.container_sha256) != 64
            or any(char not in "0123456789abcdef" for char in self.container_sha256)
            or type(self.cids) is not tuple
            or not 0 <= len(self.cids) <= 4096
            or any(
                type(cid) is not str or not 0 < len(cid) <= 128 or "\0" in cid
                for cid in self.cids
            )
            or type(self.addresses) is not tuple
            or len(self.addresses) != len(self.cids)
            or any(
                not isinstance(address, (CAddress, P5Address))
                for address in self.addresses
            )
            or type(self.reprog_mode) is not bool
            or type(self.queried_addresses) is not tuple
            or len(self.queried_addresses) > 4096
            or any(
                not isinstance(address, (CAddress, P5Address))
                for address in self.queried_addresses
            )
        ):
            raise ValueError(
                "Source-bound native CID/address discovery output required"
            )


def _recovery_vector(fields, count_key: str, prefix: str, *, numeric: bool):
    if not isinstance(fields, Mapping):
        raise NativeAddressFault("Typed native saved recovery fields required")
    count = fields.get(count_key, 0)
    if type(count) is not int or not 0 <= count <= 4096:
        raise NativeAddressFault("Native saved CID vector count missing or invalid")
    result = []
    for index in range(1, count + 1):
        value = fields.get(f"{prefix}{index}")
        if numeric:
            if type(value) is not int or not 0 <= value <= 255:
                raise NativeAddressFault(
                    "Native saved CID address selector missing or invalid"
                )
        elif type(value) is not str or not 0 < len(value) <= 128 or "\0" in value:
            raise NativeAddressFault("Native saved CID identity missing or invalid")
        result.append(value)
    return tuple(result)


def legacy_address_inputs(
    context: ExecutableContext,
) -> tuple[str, AddressConfig, bool, AddressFactoryState]:
    """Bind manager CID strings and published vectors, never CPU type guesses.

    478aea passes manager+4 to CCan+108. 47ac00 constructs that TStringList;
    4731ac/42e180 restore it from RecoveryInfo's CID vector. 42e738 restores
    the default byte vector from RecoveryInfo's CIDNode vector. Normal flow
    publishes actual discovered CAddress IDs through 4597ec/424dfc, while FC
    586788..586888/587694 publishes CID-keyed header rows.
    """
    if not isinstance(context, ExecutableContext):
        raise TypeError("Source-selected executable context required")
    image = ExecutableImage(context)
    if not isinstance(context.native.base_metadata, Mapping):
        raise NativeAddressFault("Imported native base metadata required")
    kind = context.native.base_metadata.get("kind_of_ecu")
    if type(kind) is not str or len(kind) > 128 or "\0" in kind:
        raise NativeAddressFault("Imported native KindOfECU metadata required")
    observed = context.observations.get("observed_cids")
    if type(observed) is not tuple:
        raise NativeAddressFault("Actual ordered observed CID tuple required")
    config = AddressConfig(observed)
    discovery = context.observations.get("legacy_address_discovery")
    if discovery is not None:
        if (
            not isinstance(discovery, AddressDiscovery)
            or discovery.build != context.build
            or discovery.container_sha256 != context.container_sha256
            or discovery.cids != config.values
        ):
            raise NativeAddressFault(
                "CID address discovery belongs to another source/selection"
            )
        # Static admission of ordinary candidates prevents DLL/address-ID substitution.
        p5 = context.controller == "CP5CanFlashWriter"
        width = 7 if p5 else 8
        table_address = (
            (0x58B088 if context.build == 12 else 0x5DC97C)
            if p5
            else (0x5861A0 if context.build == 12 else 0x5D621C)
        )
        table = image.read(table_address, 21 if p5 else 520)
        candidates = {
            table[offset : offset + width] for offset in range(0, len(table), width)
        }
        if context.controller != "CCanFCFlashWriter" and any(
            address.raw not in candidates
            for address in (*discovery.addresses, *discovery.queried_addresses)
        ):
            raise NativeAddressFault(
                "Discovered candidate is absent from original executable table"
            )
    mode = context.observations.get("legacy_reprog_mode", False)
    if type(mode) is not bool:
        raise NativeAddressFault("Native reprog-mode latch must be BOOL")
    if discovery is not None:
        if (
            "legacy_reprog_mode" in context.observations
            and mode != discovery.reprog_mode
        ):
            raise NativeAddressFault(
                "Conflicting process-global reprog latch snapshots"
            )
        mode = discovery.reprog_mode
    fc_rows = ()
    if context.controller == "CCanFCFlashWriter":
        if discovery is None:
            raise NativeAddressFault("Actual FC CID/header discovery rows required")
        if any(address.identifier != 65 for address in discovery.addresses):
            raise NativeAddressFault("Native FC discovery records require identifier65")
        fc_rows = tuple(
            (cid, address.raw[1:])
            for cid, address in zip(discovery.cids, discovery.addresses, strict=True)
        )
    if context.recovery is not None:
        saved_cids = _recovery_vector(
            context.recovery.fields, "cidnum", "cid", numeric=False
        )
        if saved_cids != config.values:
            raise NativeAddressFault(
                "Saved manager CID list differs from current observed selection"
            )
        defaults = bytes(
            _recovery_vector(
                context.recovery.fields, "cidnodenum", "cidnode", numeric=True
            )
        )
    elif discovery is not None:
        if (
            context.controller != "CCanFCFlashWriter"
            and discovery.cids
            and not discovery.queried_addresses
        ):
            raise NativeAddressFault(
                "Actual completed native CID query sequence required"
            )
        defaults = bytes(address.identifier for address in discovery.queried_addresses)
    elif config.values:
        raise NativeAddressFault(
            "Actual normal-flow CID/address discovery vector required"
        )
    else:
        # 41abb4: freshly constructed process vectors are empty before discovery.
        defaults = b""
    return kind, config, mode, AddressFactoryState(defaults, fc_rows)


@dataclass(frozen=True)
class P5Address:
    """Native CP5CanIDTable seven-byte row; it has no CAddress flag byte."""

    raw: bytes

    def __post_init__(self) -> None:
        if type(self.raw) is not bytes or len(self.raw) != 7:
            raise ValueError("Native P5 address must contain exactly seven bytes")

    @property
    def identifier(self) -> int:
        return self.raw[0]

    @property
    def request_header(self) -> bytes:
        return b"\0\0" + self.raw[1:3]

    @property
    def response_header(self) -> bytes:
        return b"\0\0" + self.raw[4:6]


def select_p5_addresses(
    context: ExecutableContext,
    kind_of_ecu: str,
    config: AddressConfig | None = None,
) -> tuple[P5Address, ...]:
    """Original12 41da48 /18 43876c; independent CP5 table and CID prefixes."""
    if (
        not isinstance(context, ExecutableContext)
        or type(kind_of_ecu) is not str
        or len(kind_of_ecu) > 128
        or "\0" in kind_of_ecu
        or (config is not None and not isinstance(config, AddressConfig))
    ):
        raise ValueError(
            "Native P5 context, KindOfECU and optional CID configuration required"
        )
    image = ExecutableImage(context)
    if kind_of_ecu == "0":
        identifiers = (0, 1)
        if config is not None:
            base = 0x58B080 if context.build == 12 else 0x5DC974
            prefixes = (_string(image, base), _string(image, base + 4))
            if sum(cid.startswith(prefixes) for cid in config.values) < 2:
                identifiers = (0,)
    elif kind_of_ecu == "1":
        identifiers = (2,)
    else:
        identifiers = ()
    table = image.read(0x58B088 if context.build == 12 else 0x5DC97C, 21)
    if len(table) != 21:
        raise NativeAddressFault("Truncated private native P5 address table")
    rows = tuple(P5Address(table[offset : offset + 7]) for offset in range(0, 21, 7))
    result = []
    for identifier in reversed(identifiers):
        for row in rows:
            if row.identifier == identifier:
                result.append(row)
                break
    return tuple(result)


def parse_can_cids(payload: bytes) -> tuple[str, ...]:
    """459464: payload after the four-byte CAN header; ANSI strings are opaque."""
    from scripts.cuw_legacy_can import ExecutableCANError

    if type(payload) is not bytes:
        raise TypeError("Native CID payload must be bytes")
    if len(payload) < 19 or len(payload) != payload[2] * 16 + 3:
        raise ExecutableCANError(1)
    return tuple(
        item.split(b"\0", 1)[0].decode("latin1")
        for offset in range(3, len(payload), 16)
        if (item := payload[offset : offset + 16])[0]
    )


def parse_can_identifier(payload: bytes, previous: bytes) -> bytes:
    """45e084: update a thirteen-byte output buffer, preserving its unused tail."""
    if type(payload) is not bytes or type(previous) is not bytes or len(previous) != 13:
        raise ValueError("Native response and thirteen-byte previous buffer required")
    value = payload[1:13]
    if not value or any(byte and not 0x20 <= byte <= 0x7E for byte in value):
        return previous
    leading = len(value) - len(value.lstrip(b"\0"))
    if leading == len(value):
        return previous
    updated = b"I" * leading + value[leading:] + b"\0"
    return updated + previous[len(updated) :]


def query_can_cids(
    channel: CommonCAN,
    *,
    read_identifier: bool,
    previous_identifier: bytes,
    native_cancel: Callable[[], bool],
    terminated: bool,
) -> tuple[tuple[str, ...], bytes, bool]:
    """459188/45e084 over an already connected source-bound CommonCAN channel.

    The thread termination flag and its diagnostic cancellation callback are
    separate native inputs. Filter cleanup on every exit is host safety policy.
    """
    from scripts.cuw_legacy_body import diagnostic

    if (
        type(read_identifier) is not bool
        or type(terminated) is not bool
        or not callable(native_cancel)
        or type(previous_identifier) is not bytes
        or len(previous_identifier) != 13
    ):
        raise ValueError(
            "Actual getter flags, cancellation and identifier buffer required"
        )
    with _cid_filter(channel):
        if terminated:
            return (), previous_identifier, False
        payload = diagnostic(
            channel,
            b"\x09\x04",
            b"",
            0,
            3,
            padding=channel.padding,
            native_cancel=native_cancel,
        )
        cids = parse_can_cids(payload)
        identifier = previous_identifier
        if read_identifier:
            cancelled = native_cancel()
            if type(cancelled) is not bool:
                raise TypeError("Native cancellation predicate must return BOOL")
            if not cancelled:
                payload = diagnostic(
                    channel,
                    b"\x1a\x89",
                    b"\x5a",
                    1,
                    92,
                    padding=channel.padding,
                    native_cancel=native_cancel,
                )
                identifier = parse_can_identifier(payload, previous_identifier)
        return cids, identifier, read_identifier


def probe_can_cids(channel: CommonCAN) -> bool:
    """459584: unsupported PID or native driver statuses 9/16 mean no CID support."""
    from scripts.cuw_legacy_body import diagnostic
    from scripts.cuw_legacy_engine import ExecutableJ2534Error

    with _cid_filter(channel):
        try:
            payload = diagnostic(
                channel, b"\x09\x00", b"", 0, 3, padding=channel.padding
            )
        except ExecutableJ2534Error as error:
            if error.driver_status not in (9, 16):
                raise
            return False
        return len(payload) == 6 and bool(payload[2] & 0x30)


@contextmanager
def _cid_filter(channel: CommonCAN) -> Iterator[None]:
    from scripts.cuw_legacy_engine import (
        executable_start_filter,
        executable_stop_filter,
    )

    handle = executable_start_filter(
        channel.io, channel.request, channel.response, padding=channel.padding
    )
    try:
        yield
    except BaseException as error:
        try:
            executable_stop_filter(channel.io, handle)
        except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - preserve original fault
            error.add_note(
                "CID filter rollback failure: " + type(cleanup_error).__name__
            )
        raise
    else:
        executable_stop_filter(channel.io, handle)


def discover_legacy_can_addresses(
    context: ExecutableContext,
    io: ExecutableIO,
    *,
    read_identifier: bool,
    reprog_mode: bool,
    terminated: Callable[[], bool],
) -> tuple[AddressDiscovery, tuple[tuple[bytes, bool], ...]]:
    """Original12 436a4c /18 457e98 CAN getter over neutral primitives.

    Optional identifier and native cancellation flag must come from the
    caller's actual constructor/thread state. Returned identifier buffers are
    query ordered; each includes the original +90 publication flag.
    """
    from scripts.cuw_legacy_can import CommonCAN, ExecutableCANError
    from scripts.cuw_legacy_channel import channel_state, disconnect
    from scripts.cuw_legacy_engine import executable_reconnect

    if (
        not isinstance(context, ExecutableContext)
        or not isinstance(io, ExecutableIO)
        or type(read_identifier) is not bool
        or (context.build == 12 and read_identifier)
        or type(reprog_mode) is not bool
        or not callable(terminated)
    ):
        raise ValueError(
            "Native CAN getter, version-specific flags and actual getter state required"
        )
    kind = context.native.base_metadata.get("kind_of_ecu")
    if type(kind) is not str:
        raise NativeAddressFault("Actual native KindOfECU required")
    candidates = select_legacy_addresses(context, "1" if kind == "3" else kind)
    cids: list[str] = []
    addresses: list[CAddress] = []
    queried: list[CAddress] = []
    identifiers: list[tuple[bytes, bool]] = []
    executable_reconnect(context, io, 6)
    try:
        state = channel_state(context)
        state.read_timeout = 1000
        if io.call("set_timeout", milliseconds=1000, cleanup=False) is not None:
            raise ValueError("Native timeout field setter must return None")
        for address in candidates:
            channel = CommonCAN(
                io,
                address.request_header,
                address.response_header,
                padding=state.padding,
                read_timeout_ms=1000,
                send_timeout_ms=state.send_timeout,
            )
            if not probe_can_cids(channel):
                if address.identifier in (1, 3, 10, 20):
                    continue
                raise ExecutableCANError(1)
            stop = terminated()
            if type(stop) is not bool:
                raise TypeError("Native thread termination must return BOOL")
            found, identifier, flag = query_can_cids(
                channel,
                read_identifier=read_identifier,
                previous_identifier=b"\0" * 13,
                native_cancel=terminated,
                terminated=stop,
            )
            cids.extend(found)
            addresses.extend(address for _ in found)
            queried.append(address)
            if context.build == 18:
                identifiers.append((identifier, flag))
            if address.identifier in (3, 10, 20):
                break
        discovery = AddressDiscovery(
            context.build,
            context.container_sha256,
            tuple(cids),
            tuple(addresses),
            reprog_mode,
            tuple(queried),
        )
    except BaseException as error:
        try:
            disconnect(context, io)
        except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - preserve original fault
            error.add_note(
                "CID disconnect rollback failure: " + type(cleanup_error).__name__
            )
        raise
    else:
        disconnect(context, io)
        return discovery, tuple(identifiers)
