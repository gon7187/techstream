"""Source-bound original executable driver lifecycle over neutral host primitives.

The original executable is read as data only. A provider never supplies a
reconnect decision; it supplies individual library and J2534 operations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from scripts.cuw_legacy_engine import (
    ExecutableImage,
    ExecutableJ2534Error,
    ExecutableNativeError,
    executable_j2534_call,
)
from scripts.j2534_2026 import NativeMessage
from scripts.programming import NativeTransportError
from scripts.programming_vendor import NativeTransportError as VendorTransportError

if TYPE_CHECKING:
    from scripts.cuw_legacy_engine import ExecutableContext, ExecutableIO


@dataclass(frozen=True)
class SelectedLibraryBase:
    """Copied CJ2534Device ABI: four native strings and the distinct +10 enum."""

    build: int
    native_strings: tuple[str, str, str, str]
    native_kind: int


@dataclass
class ChannelState:
    """Native channel fields, with host-owned resource handles kept explicitly."""

    api_version: int = 0
    driver_kind: int = 0
    selected_library: SelectedLibraryBase | None = None
    library: int | None = None
    driver_loaded: bool = False
    device: int | None = None
    channel: int | None = None
    protocol: int = 0
    read_timeout: int = 0
    send_timeout: int = 1000
    padding: bool = True
    flag_66: bool = False
    filters: list[int] = field(default_factory=list)
    native_symbols: tuple[int, ...] = ()
    filter_count: int = 2
    retired: list[tuple[str, str, int]] = field(default_factory=list)

    def validate(self, build: int) -> None:
        if type(self.api_version) is not int or self.api_version not in (0, 1):
            raise ValueError("Native API selector must be zero or one")
        if type(self.driver_kind) is not int or self.driver_kind not in (0, 1, 2):
            raise ValueError("Source-derived driver kind must be zero, one or two")
        if self.selected_library is not None:
            selected = self.selected_library
            if (
                not isinstance(selected, SelectedLibraryBase)
                or type(selected.build) is not int
                or selected.build != build
                or type(selected.native_kind) is not int
                or selected.native_kind not in (0, 1, 2)
                or not isinstance(selected.native_strings, tuple)
                or len(selected.native_strings) != 4
            ):
                raise ValueError("Source-selected library ABI record required")
            for value in selected.native_strings:
                _text(value)
        if build == 12 and self.api_version:
            raise ValueError("Original12 has no alternate API branch")
        for value in (self.library, self.device, self.channel, *self.filters):
            if value is not None:
                _uint(value)
        for value in (
            self.protocol,
            self.read_timeout,
            self.send_timeout,
            *self.native_symbols,
        ):
            _uint(value)
        if any(
            type(v) is not bool
            for v in (self.driver_loaded, self.padding, self.flag_66)
        ):
            raise ValueError("Native channel flags must be BOOL")
        if type(self.filter_count) is not int or not 0 <= self.filter_count <= 2:
            raise ValueError("Native SIL filter count exceeds fixed array")
        if not isinstance(self.filters, list) or not isinstance(self.retired, list):
            raise TypeError("Owned native resources must be explicit lists")
        if len(self.retired) > 128:
            raise ValueError("Retired native resource budget exceeded")
        allowed = {
            "free_library": "library",
            "passthru_close": "device",
            "passthru_disconnect": "channel",
            "stop_filter": "filter_id",
            "passthru_unload_library": "version",
        }
        for item in self.retired:
            if not isinstance(item, tuple) or len(item) != 3:
                raise ValueError("Typed retired native resource required")
            operation, key, handle = item
            if operation not in allowed or allowed[operation] != key:
                raise ValueError("Retired native resource operation is not admitted")
            _uint(handle)
        if len(self.filters) > 2 or len(set(self.filters)) != len(self.filters):
            raise ValueError("Native SIL channel owns at most two unique filters")
        if self.channel is not None and self.device is None:
            raise ValueError("Channel requires an actual device")
        if self.device is not None and not self.driver_loaded:
            raise ValueError("Device requires an admitted selected driver")
        if self.driver_loaded and self.library is None:
            raise ValueError("Driver requires a shim library")
        if self.filters and (self.channel is None or self.protocol != 3):
            raise ValueError("SIL filters require an owned SIL channel")


def _uint(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("Native primitive requires a DWORD")
    return value


def _text(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 4096 or "\x00" in value:
        raise ValueError("Bounded native string required")
    return value


def _cstring(image: ExecutableImage, address: int) -> str:
    data = bytearray()
    for index in range(4096):
        value = image.read(address + index, 1)
        if value == b"\0":
            return data.decode("latin1")
        data.extend(value)
    raise ValueError("Unterminated native image string")


def _selected_kind(image: ExecutableImage, build: int, name: str) -> int:
    # Native substring order is significant when a name contains both markers.
    base = 0x59AA70 if build == 12 else 0x5F1CC8
    for kind in (0, 1):
        address = int.from_bytes(image.read(base + kind * 4, 4), "little")
        if _cstring(image, address) in name:
            return kind
    return 2


def select_library(
    context: ExecutableContext, native_strings: tuple[str, str, str, str]
) -> SelectedLibraryBase:
    """Run native name classification and copy the actual selected ABI record.

    The input is the selected record's strings in native order, never a Boolean
    adapter capability. Original18 name setter472d40 /12 setter44a6bc computes +10.
    """
    image = ExecutableImage(context)
    state = channel_state(context)
    if not isinstance(native_strings, tuple) or len(native_strings) != 4:
        raise ValueError("Four actual selected library ABI strings required")
    for value in native_strings:
        _text(value)
    if not native_strings[2]:
        raise ValueError("Actual selected driver library path required")
    selected = SelectedLibraryBase(
        context.build,
        native_strings,
        _selected_kind(image, context.build, native_strings[0]),
    )
    state.selected_library = selected
    return selected


def selected_driver_delay(context: ExecutableContext) -> bool:
    """Read selected driver+10==1, independently of marker/version classification."""
    image = ExecutableImage(context)
    selected = channel_state(context).selected_library
    if selected is None:
        raise ValueError("Actual source-selected library ABI record is not bound")
    if selected.native_kind != _selected_kind(
        image, context.build, selected.native_strings[0]
    ):
        raise ValueError("Selected native driver kind differs from source producer")
    return selected.native_kind == 1


def _selected_path(context: ExecutableContext) -> str:
    selected = channel_state(context).selected_library
    if selected is not None:
        return selected.native_strings[2]
    return _text(context.observations.get("legacy_selected_driver"))


def _call(io: ExecutableIO, operation: str, **values: Any) -> Any:
    try:
        return io.call(operation, **values)
    except ExecutableJ2534Error:
        raise
    except (NativeTransportError, VendorTransportError) as error:
        raise ExecutableJ2534Error(1, error.code) from error


def _acquire(
    io: ExecutableIO, operation: str, release: str, key: str, **values: Any
) -> int:
    try:
        return io.acquire(operation, release, release_key=key, **values)
    except ExecutableJ2534Error:
        raise
    except (NativeTransportError, VendorTransportError) as error:
        raise ExecutableJ2534Error(1, error.code) from error


def _library(io: ExecutableIO, path: str) -> int:
    # NativeRuntime.acquire admits DWORD zero; only LoadLibrary uses NULL instead.
    # Read-only capacity coupling preserves the shared runtime's preflight contract.
    remaining = io.check()
    if io.calls >= io.max_calls or len(io._resources) >= 256:
        raise ValueError("Host resource/call budget exceeded")
    io.calls += 1
    handle = _uint(io.action({"operation": "load_library", "path": path}, remaining))
    if handle:
        io.own("free_library", library=handle)
    try:
        io.check()
    except (InterruptedError, TimeoutError) as error:
        if handle:
            try:
                io.release("free_library", library=handle)
            except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - preserve original fault
                error.add_note(
                    "Library rollback failure: " + type(cleanup_error).__name__
                )
        raise
    return handle


def _void(result: Any) -> None:
    if result is not None:
        raise ValueError("Void native primitive must return None")


def channel_state(context: ExecutableContext) -> ChannelState:
    value = context.observations.get("legacy_channel_state")
    if not isinstance(value, ChannelState):
        raise TypeError("Explicit mutable legacy_channel_state required")
    value.validate(context.build)
    return value


def _owned(state: ChannelState, io: ExecutableIO) -> None:
    for operation, key, handle in (
        ("free_library", "library", state.library),
        ("passthru_close", "device", state.device),
        ("passthru_disconnect", "channel", state.channel),
        *(("stop_filter", "filter_id", value) for value in state.filters),
    ):
        if handle is not None and not io.owns_resource(operation, **{key: handle}):
            raise ValueError("Recorded handles must belong to this host runtime")
    for operation, key, handle in state.retired:
        if not io.owns_resource(operation, **{key: handle}):
            raise ValueError("Retired native handles must remain host-owned")
    if state.driver_loaded and not io.owns_resource(
        "passthru_unload_library", version=state.api_version
    ):
        raise ValueError("Selected driver must belong to this host runtime")


def _release_ignored(
    state: ChannelState, io: ExecutableIO, operation: str, key: str, handle: int
) -> None:
    # Native Disconnect/Close ignore driver status; host ownership survives failure.
    try:
        io.release(operation, **{key: handle})
    except ExecutableJ2534Error:
        raise
    except (NativeTransportError, VendorTransportError):
        state.retired.append((operation, key, handle))


def disconnect(context: ExecutableContext, io: ExecutableIO) -> None:
    """18 RVA6e870 /12 RVA46b74: filters, channel, device, selected driver."""
    state = channel_state(context)
    _owned(state, io)
    for identifier in tuple(state.filters):
        try:
            io.release("stop_filter", filter_id=identifier)
        except ExecutableJ2534Error:
            raise
        except (NativeTransportError, VendorTransportError) as error:
            raise ExecutableJ2534Error(1, error.code) from error
        state.filters.remove(identifier)
    if state.channel is not None:
        _release_ignored(state, io, "passthru_disconnect", "channel", state.channel)
        state.channel = None
        state.protocol = 0
        state.flag_66 = False
    if state.device is not None:
        _release_ignored(state, io, "passthru_close", "device", state.device)
        state.device = None
    if state.driver_loaded:
        io.release("passthru_unload_library", version=state.api_version)
        state.driver_loaded = False


def close(context: ExecutableContext, io: ExecutableIO) -> None:
    """Release only this channel's resources, preserving other runtime owners."""
    disconnect(context, io)
    state = channel_state(context)
    for operation, key, handle in reversed(tuple(state.retired)):
        io.release(operation, **{key: handle})
        state.retired.remove((operation, key, handle))
    if state.library is not None:
        io.release("free_library", library=state.library)
        state.library = None


_COMMON = (
    "PassThruOpen",
    "PassThruClose",
    "PassThruConnect",
    "PassThruDisconnect",
    "PassThruReadMsgs",
    "PassThruWriteMsgs",
    "PassThruStartMsgFilter",
    "PassThruStopMsgFilter",
    "PassThruSetProgrammingVoltage",
    "PassThruIoctl",
    "PassThruReadVersion",
    "PassThruStartPeriodicMsg",
    "PassThruStopPeriodicMsg",
    "PassThruLoadLibrary",
    "PassThruUnloadLibrary",
    "PassThruSaveLog",
)
_ALTERNATE = (
    "PassThruGetNextDevice",
    "PassThruScanForDevices",
    "PassThruOpen",
    "PassThruClose",
    "PassThruConnect",
    "PassThruDisconnect",
    "PassThruLogicalConnect",
    "PassThruLogicalDisconnect",
    "PassThruReadMsgs",
    "PassThruQueueMsgs",
    "PassThruIoctl",
    "PassThruReadVersion",
    "PassThruLoadLibrary",
    "PassThruUnloadLibrary",
    "PassThruSaveLog",
)


def _open(state: ChannelState, io: ExecutableIO, image: ExecutableImage) -> None:
    name = None
    if state.api_version:
        count = _uint(_call(io, "passthru_scan_for_devices"))
        if count == 0:
            raise ExecutableJ2534Error(1, 0)
        name = _cstring(image, 0x5F2DD9) + _text(_call(io, "passthru_get_next_device"))
    device = _acquire(
        io,
        "passthru_open",
        "passthru_close",
        "device",
        name=name,
        version=state.api_version,
    )
    if state.device is not None:
        state.retired.append(("passthru_close", "device", state.device))
    state.device = device


def _marker(
    context: ExecutableContext,
    io: ExecutableIO,
    image: ExecutableImage,
    state: ChannelState,
    path: str,
    *,
    mode: int | None = None,
) -> bool:
    library = _library(io, path)
    if library == 0:
        return False
    try:
        symbol = _uint(
            _call(
                io,
                "get_symbol",
                library=library,
                symbol=_cstring(image, 0x59BAF0 if context.build == 12 else 0x5F3184),
            )
        )
        if symbol and mode is not None:
            _uint(_call(io, "call_symbol", symbol=symbol, args=(0, 0)))
            _uint(_call(io, "call_symbol", symbol=symbol, args=(mode, 0)))
        return symbol != 0
    finally:
        io.release("free_library", library=library)


def _kind(
    context: ExecutableContext,
    io: ExecutableIO,
    image: ExecutableImage,
    state: ChannelState,
    path: str,
) -> int:
    if _marker(context, io, image, state, path):
        state.driver_kind = 1
        return 1
    temporary = state.device is None
    if temporary:
        _open(state, io, image)
    try:
        versions = _call(io, "passthru_read_version", device=state.device)
        if not isinstance(versions, tuple) or len(versions) != 3:
            raise ValueError("ReadVersion must return firmware, DLL, API strings")
        firmware, dll, api = (_text(value) for value in versions)
        del firmware, api
        needle = _cstring(image, 0x59BAC5 if context.build == 12 else 0x5F311B)
        state.driver_kind = 2 if needle in dll else 0
        return state.driver_kind
    finally:
        if temporary and state.device is not None:
            _release_ignored(state, io, "passthru_close", "device", state.device)
            state.device = None


def _mode_two(state: ChannelState, io: ExecutableIO, image: ExecutableImage) -> bool:
    temporary = state.device is None
    if temporary:
        _open(state, io, image)
    try:
        config = executable_j2534_call(
            io,
            "ioctl",
            identifier=state.device,
            ioctl_id=0x800C,
            input=None,
            output=(0x100, 0, 0, 0, 0, 0),
        )
        if not isinstance(config, tuple) or len(config) != 6:
            raise ValueError("Native mode query must return six DWORDs")
        words = tuple(_uint(value) for value in config)
        return words[1] == 3 and words[2] != 0
    finally:
        if temporary and state.device is not None:
            _release_ignored(state, io, "passthru_close", "device", state.device)
            state.device = None


def set_mode(context: ExecutableContext, io: ExecutableIO, mode: int) -> bool:
    """18 RVA713c8 /12 RVA48738: two calls to the resolved marker interface."""
    if type(mode) is not int or not -128 <= mode <= 127:
        raise ValueError("Native marker mode must be a signed byte")
    image = ExecutableImage(context)
    state = channel_state(context)
    _owned(state, io)
    return _marker(
        context,
        io,
        image,
        state,
        _selected_path(context),
        mode=mode,
    )


def get_mode(context: ExecutableContext, io: ExecutableIO) -> bool:
    """18 RVA715f8 /12 RVA48944: exact kind-specific native mode query."""
    image = ExecutableImage(context)
    state = channel_state(context)
    _owned(state, io)
    if not state.driver_loaded:
        raise ValueError("Native mode query requires the admitted selected driver")
    path = _selected_path(context)
    kind = _kind(context, io, image, state, path)
    if kind == 2:
        return _mode_two(state, io, image)
    if kind == 0:
        return False
    library = _library(io, path)
    if not library:
        return False
    try:
        symbol = _uint(
            _call(
                io,
                "get_symbol",
                library=library,
                symbol=_cstring(image, 0x59BAF0 if context.build == 12 else 0x5F3184),
            )
        )
        if not symbol:
            return False
        if state.device is not None:
            _release_ignored(state, io, "passthru_close", "device", state.device)
            state.device = None
        _uint(_call(io, "call_symbol", symbol=symbol, args=(0, 0)))
        _uint(_call(io, "call_symbol", symbol=symbol, args=(4, 0)))
        opened = False
        try:
            _open(state, io, image)
            opened = True
        except ExecutableJ2534Error:
            pass  # Original typed driver exception leaves the query result false.
        if state.device is not None:
            _release_ignored(state, io, "passthru_close", "device", state.device)
            state.device = None
        # The source explicitly sets open=true with DeviceID reset to zero here.
        # Register its corresponding Close before the interface can change state.
        result = io.call_owned(
            "call_symbol",
            "passthru_close",
            release_values={"device": 0},
            symbol=symbol,
            args=(0, 0),
        )
        state.device = 0
        _uint(result)
        return opened
    finally:
        io.release("free_library", library=library)


def connect(context: ExecutableContext, io: ExecutableIO, protocol_id: int) -> None:
    """Run the original selected-driver reconnect; all decisions remain native."""
    protocol_id = _uint(protocol_id)
    image = ExecutableImage(context)  # SHA admission precedes any side effect.
    state = channel_state(context)
    path = _selected_path(context)
    if not path:
        raise ValueError("Actual selected driver path required")
    _owned(state, io)
    try:
        if state.library is None:
            address = (
                0x59AE75
                if context.build == 12
                else 0x5F2387
                if state.api_version
                else 0x5F20EF
            )
            library = _library(io, _cstring(image, address))
            if not library:
                raise OSError("Native shim library could not be loaded")
            state.library = library
        for name in _ALTERNATE if state.api_version else _COMMON:
            if not _uint(_call(io, "get_symbol", library=state.library, symbol=name)):
                raise OSError("Required J2534 shim export is absent")
        try:
            result = io.call_owned(
                "passthru_load_library",
                "passthru_unload_library",
                release_values={"version": state.api_version},
                path=path,
                version=state.api_version,
            )
        except ExecutableJ2534Error:
            raise
        except (NativeTransportError, VendorTransportError) as error:
            raise ExecutableJ2534Error(1, error.code) from error
        if state.driver_loaded:
            state.retired.append(
                ("passthru_unload_library", "version", state.api_version)
            )
        state.driver_loaded = True
        _void(result)
        kind = _kind(context, io, image, state, path)
        if kind == 1:
            _marker(context, io, image, state, path, mode=1)
        _open(state, io, image)
        if kind == 2 and _mode_two(state, io, image):
            raise ExecutableJ2534Error(1, 0)
        baud_address = 0x59BAE8 if context.build == 12 else 0x5F3178
        baud = (
            int.from_bytes(image.read(baud_address, 4), "little")
            if protocol_id == 3
            else int.from_bytes(image.read(baud_address + 4, 4), "little")
            if protocol_id in (5, 6)
            else 0
        )
        values: dict[str, Any] = {
            "device": state.device,
            "protocol": protocol_id,
            "flags": 0x1200 if protocol_id == 3 else 0,
            "baud": baud,
            "version": state.api_version,
        }
        if state.api_version:
            _void(
                executable_j2534_call(
                    io,
                    "ioctl",
                    identifier=state.device,
                    ioctl_id=3,
                    input=(1, 1, (8,)),
                    output=(0,),
                )
            )
            _void(
                executable_j2534_call(
                    io,
                    "ioctl",
                    identifier=state.device,
                    ioctl_id=0x8022,
                    input=(0x1FE,),
                    output=None,
                )
            )
            values["baud"] = int.from_bytes(image.read(0x5F3180, 4), "little")
            values["flags"] = 0
            values["physical_channel_count"] = 1
            values["logical_channels"] = tuple(
                int.from_bytes(image.read(0x5F20AC + offset, 4), "little")
                for offset in range(0, 16, 4)
            )
        channel = _acquire(
            io,
            "passthru_connect",
            "passthru_disconnect",
            "channel",
            **values,
        )
        if state.channel is not None:
            state.retired.append(("passthru_disconnect", "channel", state.channel))
        state.retired.extend(
            ("stop_filter", "filter_id", value) for value in state.filters
        )
        state.filters.clear()
        state.channel = channel
        state.protocol = protocol_id
        if protocol_id == 3 and not state.api_version:
            for pattern in (0, 0x80)[: state.filter_count]:
                identifier = _acquire(
                    io,
                    "start_filter",
                    "stop_filter",
                    "filter_id",
                    channel=state.channel,
                    filter_type=1,
                    mask=NativeMessage(3, b"\x80"),
                    pattern=NativeMessage(3, bytes((pattern,))),
                    flow_control=None,
                )
                if identifier in state.filters:
                    io.release("stop_filter", filter_id=identifier)
                    raise ValueError("Driver reused a live filter handle")
                state.filters.append(identifier)
    except (Exception, KeyboardInterrupt) as error:
        try:
            close(context, io)
        except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - preserve original fault
            error.add_note("Channel rollback failure: " + type(cleanup_error).__name__)
        raise


def reconnect(context: ExecutableContext, io: ExecutableIO, protocol_id: int) -> None:
    _uint(protocol_id)
    ExecutableImage(context)
    if not _selected_path(context):
        raise ValueError("Actual selected driver path required")
    try:
        disconnect(context, io)
    except ExecutableNativeError:
        pass  # Native catch-all covers Disconnect only; host faults escape.
    connect(context, io, protocol_id)


executable_reconnect = reconnect


def restore_state(
    build: int, saved: bytes, io: ExecutableIO, *, driver_loaded: bool
) -> ChannelState:
    """18 RVA717c4 /12 RVA48b10: decode copied native state, without adopting handles.

    The provider must already own every live native handle in this runtime. Native
    function pointers are retained as source data and never used as host callables.
    """
    if type(build) is not int or build not in (12, 18):
        raise ValueError("Original executable build required")
    size = 0xAC if build == 18 else 0x78
    if (
        not isinstance(saved, bytes)
        or len(saved) != size
        or type(driver_loaded) is not bool
    ):
        raise ValueError("Exact native saved channel record and loaded BOOL required")

    def word(offset: int) -> int:
        return int.from_bytes(saved[offset : offset + 4], "little")

    def flag(offset: int) -> bool:
        if saved[offset] not in (0, 1):
            raise ValueError("Saved native BOOL must be zero or one")
        return bool(saved[offset])

    alternate = build == 18
    count_at = 0x3C if alternate else 0x28
    filters_at = count_at + 4
    flags_at = 0x48 if alternate else 0x34
    count = word(count_at)
    if count > 2:
        raise ValueError("Saved native SIL filter count exceeds static array")
    opened = flag(4)
    connected = flag(0x18 if alternate else 0x14)
    state = ChannelState(
        api_version=saved[0x10] if alternate else 0,
        library=word(0x14 if alternate else 0x10) or None,
        driver_loaded=driver_loaded,
        device=word(0) if opened else None,
        channel=word(0x0C) if connected else None,
        protocol=word(8),
        read_timeout=word(0x1C if alternate else 0x18),
        send_timeout=word(0x20 if alternate else 0x1C),
        padding=flag(flags_at + 3),
        flag_66=flag(flags_at + 2),
        filters=[
            word(filters_at + index * 4)
            for index in range(count)
            if flag(flags_at + index)
        ],
        filter_count=count,
        native_symbols=tuple(word(offset) for offset in range(flags_at + 4, size, 4)),
    )
    state.validate(build)
    _owned(state, io)
    return state
