"""Source-bound recovered2026 Suzuki/FHI software primitives.

No transport is opened here. Only inspected paths are callable; unresolved native
entry points fail explicitly instead of dispatching to an older CUW family.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import IntEnum
from types import MappingProxyType

from scripts.native_modules import NativeModuleIdentity, identify_native_module
from scripts.programming import NativeNegativeResponse, NativeProgrammingChannel

# Inspection image identities, authenticated against protected original+companion.
_INSPECTION_IDENTITIES = {
    "TCUWCanFHIFlashWriter.dll": "e4fcf4a111e60bce6a807fbdde5296d6b180ed29a6196631dcdfbdfd8f48d576",
    "TCUWCanFHIPrepareWriter.dll": "a7160955022d5090f6274957892c4aae079ab66da74c0d3d391e104008f188b0",
    "TCUWCanSuzukiUDSFlashWriter.dll": "39e1fb5f196cdc3081742880cff66bdbaec149d176e8d00fd76ce397608c8a81",
    "TCUWCanSuzukiUDSPrepareWriter.dll": "bb34e610990a7b9b2fa4957feb9e9c8eadb79fda221cfbf833bf664eeda80c39",
    "TCUWCanSuzukiUDSSoftwareIDGetter.dll": "b63abaebe764c6067ec5013c44c16f3c47cc6ebe6abfd84b0e93d3681c0b6315",
    "TCUWCanSuzukiUDSUtils.dll": "58db5e0494645ee4f665c714a0a59afa5e2765ce2f55c8505d31e5db76159283",
    "TCUWCanSuzukiUSBReproUDSFlashWriter.dll": "d48d438117ae5fa043811028636d1ddd3c0368f7e6d09f66ee7b341b073e251e",
    "TCUWFHIUtils.dll": "59737f83a1c9177313b8e4108c64b653000ba397d9c272ed2f4231424edc11ce",
}

SUZUKI_MAX_RESPONSE_PENDING = 255
FHI_CAN_ID_LENGTH = 4
FHI_RESPONSE_PENDING_TIMEOUT_MS = 5000


def _validate_key_observations(observations, seed_length, key_length):
    if observations is None:
        return
    if (
        not isinstance(observations, dict)
        or not 1 <= len(observations) <= 4096
        or any(
            not isinstance(seed, bytes)
            or len(seed) != seed_length
            or not isinstance(key, bytes)
            or len(key) != key_length
            for seed, key in observations.items()
        )
    ):
        raise ValueError("Bounded explicit seed/key observations required")


def _authorization_key(runtime, observations, seed, key_length, family, stage):
    if observations is None:
        key = runtime.call(
            "observe_authorization_key",
            family=family,
            stage=stage,
            seed=seed,
            key_length=key_length,
        )
    else:
        if seed not in observations:
            raise PermissionError(
                "No explicit authorization observation matches native seed"
            )
        key = observations[seed]
    if not isinstance(key, bytes) or len(key) != key_length:
        raise PermissionError(
            "Explicit authorization observation must return exact key bytes"
        )
    return key


def _driver_status(error):
    """Raw transport code is a driver status; native CPass primary enums are not."""
    return getattr(error, "passthru_status", getattr(error, "code", None))


def require_identity(identity: NativeModuleIdentity) -> NativeModuleIdentity:
    """Re-resolve the supplied digest; a hand-constructed dataclass is no authority."""
    if not isinstance(identity, NativeModuleIdentity):
        raise TypeError("Exact native module identity required")
    actual = identify_native_module(identity.sha256, identity.module_name)
    expected = _INSPECTION_IDENTITIES.get(actual.module_name)
    if (
        actual != identity
        or actual.cuw_build != "2026"
        or actual.engine_sha256 != expected
    ):
        raise ValueError("Exact recovered2026 Suzuki/FHI source identity required")
    return actual


class SuzukiRoutine(IntEnum):
    """Native RoutineControl enum,2026 utility RVA0x2130."""

    KIND_0 = 0
    KIND_1 = 1
    KIND_2 = 2


class SuzukiIdentification:
    """Utility getters at2026 RVAs1b00,1d00,1ef0 over injected PDU exchange.

    Native fixed field copies preserve embedded-NUL termination and byte strings.
    The shared channel supplies explicitly bounded host pending/deadline policy.
    """

    def __init__(
        self, identity: NativeModuleIdentity, channel: NativeProgrammingChannel
    ):
        require_identity(identity)
        if identity.module_name != "TCUWCanSuzukiUDSUtils.dll":
            raise ValueError("Suzuki utility source identity required")
        if not isinstance(channel, NativeProgrammingChannel):
            raise TypeError("Explicit native programming channel required")
        self.channel = channel

    def _read(self, did: int, width: int) -> bytes:
        from scripts.programming_2026_common import CommonResponseError

        suffix = did.to_bytes(2, "big")
        response = self.channel.call(b"\x22" + suffix, b"\x62" + suffix)
        if len(response) < 3 + width:
            raise CommonResponseError(3)
        return response[3 : 3 + width]

    def _identifier(self, did: int, width: int) -> bytes:
        from scripts.programming_2026_common import CommonResponseError

        value = self._read(did, width).split(b"\0", 1)[0]
        if not value:
            raise CommonResponseError(3)
        return value

    def hardware_id(self) -> bytes:
        return self._identifier(0xF191, 11)

    def software_id(self) -> bytes:
        return self._identifier(0xF188, 16)

    def software_version(self) -> str:
        return self._read(0xF189, 2).hex().upper()

    def routine_control(self, routine: SuzukiRoutine) -> None:
        """RVA0x2130:31/01, native two-byte routine ID, trailing00."""
        if not isinstance(routine, SuzukiRoutine):
            raise TypeError("Explicit native Suzuki routine enum required")
        identifier = (b"\xc0\x01", b"\xff\x00", b"\xff\x01")[routine]
        self.channel.call(b"\x31\x01" + identifier + b"\x00", b"\x71\x01" + identifier)


def fhi_can_ids(
    identity: NativeModuleIdentity, kind_of_ecu: str, addresses: tuple[bytes, ...]
) -> tuple[bytes, bytes]:
    """FHIUtils RVA1490 selects one native seven-byte address record.

    Kind31 is the2026 CalibrationFile ENG_FHI constant. Other native kinds use
    the second row. SetNum(4) in2026 Bytes RVA1a60 pads on the left.
    """
    require_identity(identity)
    if identity.module_name != "TCUWFHIUtils.dll":
        raise ValueError("FHI utility source identity required")
    if (
        not isinstance(kind_of_ecu, str)
        or len(kind_of_ecu) > 128
        or "\0" in kind_of_ecu
        or not isinstance(addresses, tuple)
        or not 2 <= len(addresses) <= 4096
        or any(not isinstance(row, bytes) or len(row) != 7 for row in addresses)
    ):
        raise ValueError(
            "Bounded native FHI kind and seven-byte address records required"
        )
    row = addresses[0 if kind_of_ecu == "31" else 1]
    return row[:2].rjust(4, b"\0"), row[3:5].rjust(4, b"\0")


def set_suzuki_baud_rate(
    identity: NativeModuleIdentity, runtime, baudrate: int
) -> None:
    """SuzukiUtils RVA2940: SET_CONFIG ioctl2 with DATA_RATE parameter1."""
    from scripts.programming_2026_common import NativeRuntime2026

    require_identity(identity)
    if identity.module_name != "TCUWCanSuzukiUDSUtils.dll":
        raise ValueError("Suzuki utility source identity required")
    if (
        not isinstance(runtime, NativeRuntime2026)
        or type(baudrate) is not int
        or not 0 <= baudrate <= 0xFFFFFFFF
    ):
        raise ValueError(
            "Explicit primitive runtime and unsigned native baudrate required"
        )
    if runtime.call("control_io", ioctl=2, parameters=((1, baudrate),)) is not None:
        raise TypeError("Native SET_CONFIG primitive must return None")


def fhi_response_status(
    identity: NativeModuleIdentity,
    service: int,
    received: tuple[bytes, ...],
    outstanding: tuple[bytes, ...],
) -> tuple[tuple[bytes, ...], tuple[bytes, ...], int]:
    """FHIUtils RVA1600: collect finals and remove completed response CAN IDs.

    Matching uses the final two CAN-ID bytes, as in the native helper. Pending
    7f/SID/78 retains its address. Other matched negatives count without copying.
    Tuple/count/message limits here are explicit host resource policy.
    """
    require_identity(identity)
    if identity.module_name != "TCUWFHIUtils.dll":
        raise ValueError("FHI utility source identity required")
    if (
        type(service) is not int
        or not 0 <= service <= 255
        or not isinstance(received, tuple)
        or not isinstance(outstanding, tuple)
        or len(received) > 256
        or len(outstanding) > 256
        or any(
            not isinstance(frame, bytes) or not 4 <= len(frame) <= 4128
            for frame in received
        )
        or any(
            not isinstance(address, bytes) or len(address) != 4
            for address in outstanding
        )
    ):
        raise ValueError(
            "Bounded FHI CAN frames, response addresses and service required"
        )
    pending = list(outstanding)
    final = []
    negatives = 0
    for frame in received:
        if len(frame) >= 7 and frame[4:6] == bytes((0x7F, service)):
            if frame[6] == 0x78:
                continue
            negatives += 1
        else:
            final.append(frame)
        for index, address in enumerate(pending):
            if address[2:4] == frame[2:4]:
                del pending[index]
                break
    return tuple(final), tuple(pending), negatives


def suzuki_download(
    identity: NativeModuleIdentity,
    channel: NativeProgrammingChannel,
    runtime,
    address: bytes,
    data: bytes,
    max_block_data: int,
    download_length: int = 0,
) -> int:
    """SuzukiFlash RVAs17f0/15a0/1a70/1720, one native data area.

    This is a transfer primitive, not the exported writer or a CUW adapter.
    Source metadata supplies address, data, maximum block size and download length.
    """
    from scripts.programming_2026_common import NativeRuntime2026

    require_identity(identity)
    if identity.module_name != "TCUWCanSuzukiUDSFlashWriter.dll":
        raise ValueError("Suzuki writer source identity required")
    if (
        not isinstance(channel, NativeProgrammingChannel)
        or not isinstance(runtime, NativeRuntime2026)
        or not isinstance(address, bytes)
        or not 1 <= len(address) <= 512
        or not isinstance(data, bytes)
        or not 1 <= len(data) <= 64 * 1024 * 1024
        or type(max_block_data) is not int
        or not 1 <= max_block_data <= 0xFFFFFFFF
        or type(download_length) is not int
        or not 0 <= download_length <= 0xFFFFFFFF
    ):
        raise ValueError("Bounded native Suzuki download fields required")
    size = min(max_block_data, 4095)
    if (len(data) + size - 1) // size + 2 + channel.attempt_count > 65536:
        raise ValueError("Suzuki transfer exceeds host request-count budget")
    runtime.check()
    if min(size, len(data)) + 2 > channel.message_limit:
        raise ValueError("Selected channel cannot carry native Suzuki transfer block")
    response = channel.call(
        b"\x34\x0f\x45" + address + (download_length or len(data)).to_bytes(4, "big"),
        b"\x74",
    )
    if len(response) < 3:
        raise ValueError("Native Suzuki download response requires three PDU bytes")
    previous = runtime.call("get_send_timeout")
    if type(previous) is not int or not 0 <= previous <= 0xFFFFFFFF:
        raise TypeError("Native send timeout primitive must return uint32")
    runtime.own("set_send_timeout", milliseconds=previous)
    try:
        if (
            runtime.call("set_send_timeout", milliseconds=(size // 7) * 127 + 1127)
            is not None
        ):
            raise TypeError("Native send timeout setter must return None")
        for block, start in enumerate(range(0, len(data), size), 1):
            runtime.check()
            counter = block & 255
            channel.call(
                b"\x36" + bytes((counter,)) + data[start : start + size],
                b"\x76" + bytes((counter,)),
            )
            transferred = min(start + size, len(data))
            runtime.call("notify_done_size", value=transferred)
            runtime.call(
                "notify_progress", value=int(float(transferred) / len(data) * 100.0)
            )
    finally:
        runtime.release("set_send_timeout", milliseconds=previous)
    channel.call(b"\x37", b"\x77")
    return len(data)


class SuzukiUSBCommands:
    """Source USB writer helpers RVA1040/19c0; outer status machine remains open."""

    def __init__(
        self, identity: NativeModuleIdentity, channel: NativeProgrammingChannel
    ):
        require_identity(identity)
        if identity.module_name != "TCUWCanSuzukiUSBReproUDSFlashWriter.dll":
            raise ValueError("Suzuki USB writer source identity required")
        if not isinstance(channel, NativeProgrammingChannel):
            raise TypeError("Explicit native programming channel required")
        self.channel = channel

    def enable_usb_repro(self) -> None:
        self.channel.call(b"\x2e\xcf\x80\x01", b"\x6e\xcf\x80")

    def routine(self, kind: int) -> int:
        if type(kind) is not int or not 0 <= kind <= 2:
            raise ValueError("Native USB routine kind0/1/2 required")
        identifier = (b"\xda\x00", b"\xd9\x15", b"\xda\x01")[kind]
        response = self.channel.call(b"\x31\x01" + identifier, b"\x71\x01" + identifier)
        if kind == 0:
            return 0
        if len(response) < 5:
            raise ValueError("Native USB routine status byte is missing")
        return response[4]

    def status(self, kind: int = 0) -> int:
        """USB writer RVA1b10:31/03, native result byte at payload offset4."""
        if type(kind) is not int or not 0 <= kind <= 2:
            raise ValueError("Native USB status routine kind0/1/2 required")
        identifier = b"\xda\x00" if kind == 0 else b"\x00\x00"
        response = self.channel.call(b"\x31\x03" + identifier, b"\x71\x03" + identifier)
        if len(response) < 5:
            raise ValueError("Native USB routine result byte is missing")
        return response[4] if kind == 0 else 0


class FHICommands:
    """FHI writer's concrete PDU helpers, without its outer state machine."""

    def __init__(
        self, identity: NativeModuleIdentity, channel: NativeProgrammingChannel
    ):
        require_identity(identity)
        if identity.module_name != "TCUWCanFHIFlashWriter.dll":
            raise ValueError("FHI writer source identity required")
        if not isinstance(channel, NativeProgrammingChannel):
            raise TypeError("Explicit native programming channel required")
        self.channel = channel

    def request_area(self, address: bytes, length: int, *, upload: bool = False) -> int:
        if (
            not isinstance(address, bytes)
            or not 1 <= len(address) <= 15
            or type(length) is not int
            or not 0 <= length <= 0xFFFFFFFF
            or type(upload) is not bool
        ):
            raise ValueError(
                "Bounded native FHI address, length and direction required"
            )
        width = len(address)
        encoded_length = length.to_bytes(4, "big")[-width:].rjust(width, b"\0")
        sid = 0x35 if upload else 0x34
        response = self.channel.call(
            bytes((sid, 4, (width * 17) & 255)) + address + encoded_length,
            bytes((sid + 0x40, 0x20)),
        )
        if len(response) < 4:
            raise ValueError("FHI block-size response lacks two-byte limit")
        maximum = int.from_bytes(response[2:4], "big") - 1 - (0 if upload else width)
        if maximum <= 0 or maximum > self.channel.message_limit - 1 - width:
            raise ValueError("FHI negotiated block payload exceeds channel bounds")
        return maximum

    def routine(self, identifier: int) -> None:
        if type(identifier) is not int or identifier not in (0x201, 0x202):
            raise ValueError("Native FHI routine0201/0202 required")
        routine = identifier.to_bytes(2, "big")
        option = b"\xff" * 4 if identifier == 0x201 else b"\x01"
        self.channel.call(b"\x31\x01" + routine + option, b"\x71\x01" + routine)

    def verify_chunk(self, address: bytes, expected: bytes) -> None:
        self._chunk(address, expected)
        self.channel.call(b"\xb7" + address, b"\xf7" + expected)

    def write_chunk(self, address: bytes, data: bytes) -> None:
        self._chunk(address, data)
        self.channel.call(b"\xb6" + address + data, b"\xf6")

    def _chunk(self, address: bytes, data: bytes) -> None:
        if (
            not isinstance(address, bytes)
            or not 1 <= len(address) <= 15
            or not isinstance(data, bytes)
            or not 1 <= len(data) <= self.channel.message_limit - len(address) - 1
        ):
            raise ValueError("Bounded native FHI chunk address and bytes required")

    def exit_area(self) -> None:
        self.channel.call(b"\x37", b"\x77")


@dataclass(frozen=True)
class FHIProgram2026:
    module: NativeModuleIdentity
    container_sha256: str
    archive_sha256: str
    request_address: bytes
    response_address: bytes
    start_address: bytes
    area_length: int
    data: bytes = field(repr=False)


def native_fhi_program(
    identity,
    utility_identity,
    container,
    parameters,
    *,
    cpu_index=0,
    current_cids=(),
    address_context=None,
) -> FHIProgram2026:
    """FHI1fe0 input: actual archive GetData/GetLength/GetFlashSize, selected CSV."""
    import hashlib

    from scripts.calibration_2026 import native2026_archive
    from scripts.j2534_2026 import communication_addresses_from_calibration
    from scripts.programming_2026_common import NativeParameter2026

    require_identity(identity)
    require_identity(utility_identity)
    if (
        identity.module_name != "TCUWCanFHIFlashWriter.dll"
        or utility_identity.module_name != "TCUWFHIUtils.dll"
        or not isinstance(parameters, NativeParameter2026)
    ):
        raise ValueError("Exact FHI writer/utility and native parameter table required")
    metadata = _current_metadata(container, address_context, cpu_index=cpu_index)
    keys = _parameter_keys(metadata)
    fields = {}
    for name in parameters.headers:
        value = parameters.values_with_keys(name, *keys)
        if value is not None:
            fields[name] = value
    functions = fields.get("GetCANIDFunctionNameForFlashWrite", ())[:1]
    if not functions:
        raise ValueError("Native FHI catalog address strategy missing")
    if address_context is not None:
        rows = _context_address_rows(address_context, identity, container, "FlashWrite")
        success = True
    else:
        success, rows = communication_addresses_from_calibration(
            container, fields
        ).resolve(
            functions,
            cids=current_cids,
            location_id=metadata.cpu.values.get("locationid", ""),
        )
    if not success or len(rows) < 2:
        raise ValueError("Native FHI utility requires at least two address rows")
    selected = rows[0 if metadata.vehicle.get("kindofecu", "") == "31" else 1]
    start = fields.get("StartAddress", ())
    if (
        not start
        or not 2 <= len(start[0]) <= 30
        or len(start[0]) % 2
        or any(value not in "0123456789abcdefABCDEF" for value in start[0])
    ):
        raise ValueError("Bounded native FHI StartAddress parameter required")
    address = bytes.fromhex(start[0])
    archive = native2026_archive(metadata)
    if (
        archive.data is None
        or not 1 <= archive.flash_size <= len(archive.data) <= 64 * 1024 * 1024
        or archive.length > 0xFFFFFFFF
    ):
        raise ValueError("Materialized bounded native FHI archive required")
    return FHIProgram2026(
        identity,
        metadata.source_sha256,
        hashlib.sha256(archive.raw).hexdigest(),
        selected.request[:2].rjust(4, b"\0"),
        selected.response[:2].rjust(4, b"\0"),
        address,
        archive.length,
        archive.data[: archive.flash_size],
    )


def suzuki_elapsed_seconds(
    identity: NativeModuleIdentity,
    runtime,
    start: tuple[int, ...],
    end: tuple[int, ...],
) -> int:
    """Utility RVA13b0/142a over explicit SystemTimeToFileTime primitives."""
    from scripts.programming_2026_common import NativeRuntime2026

    require_identity(identity)
    if identity.module_name != "TCUWCanSuzukiUDSUtils.dll":
        raise ValueError("Suzuki utility source identity required")
    if not isinstance(runtime, NativeRuntime2026) or any(
        not isinstance(value, tuple)
        or len(value) != 8
        or any(type(field) is not int or not 0 <= field <= 65535 for field in value)
        for value in (start, end)
    ):
        raise ValueError(
            "Explicit primitive runtime and native SYSTEMTIME words required"
        )
    ticks = []
    for value in (start, end):
        result = runtime.call("system_time_to_file_time", system_time=value)
        if type(result) is not int or not 0 <= result <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("SystemTimeToFileTime primitive must return uint64 ticks")
        ticks.append(result)
    return (max(0, ticks[1] - ticks[0]) // 10000000) & 0xFFFFFFFF


SUZUKI_GATEWAY_REQUEST = bytes.fromhex("00000751")
SUZUKI_GATEWAY_RESPONSE = bytes.fromhex("00000761")


def native_suzuki_addresses(
    identity: NativeModuleIdentity,
    container,
    *,
    parameters=None,
    phase: str = "FlashWrite",
    current_cids: tuple[str, ...] = (),
    address_context=None,
) -> tuple[bytes, bytes]:
    """Bind actual2026 physical CAN fields through CommunicationAddress RVA2180."""
    if address_context is not None:
        rows = _context_address_rows(address_context, identity, container, phase)
        return rows[0].request[:2].rjust(4, b"\0"), rows[0].response[:2].rjust(4, b"\0")
    from scripts.calibration_2026 import native2026_metadata
    from scripts.j2534_2026 import communication_addresses_from_calibration

    require_identity(identity)
    if "Suzuki" not in identity.module_name:
        raise ValueError("Suzuki source identity required")
    if native2026_metadata(container).format_version not in (10, 12):
        raise ValueError("Native Suzuki calibration format10/12 required")
    functions = ("GetCanIDsFromCalibrationFileForSUZUKI",)
    fields = {}
    if parameters is not None:
        from scripts.programming_2026_common import NativeParameter2026

        if not isinstance(parameters, NativeParameter2026) or phase not in (
            "GetCID",
            "PrepareWrite",
            "FlashWrite",
        ):
            raise ValueError(
                "Native selected parameter table and programming phase required"
            )
        metadata = native2026_metadata(container)
        keys = (
            metadata.vehicle.get("kindofecu", ""),
            metadata.cpu.values.get("cputype", ""),
            metadata.vehicle.get("contacttype", ""),
        )
        for name in parameters.headers:
            values = parameters.values_with_keys(name, *keys)
            if values is not None:
                fields[name] = values
        functions = fields.get("GetCANIDFunctionNameFor" + phase, ())
        if phase != "PrepareWrite" or metadata.vehicle.get("contacttype", "") in (
            "P5-Unified",
            "Phase6",
            "Ethernet",
        ):
            functions = functions[:1]
        elif len(functions) > 4:
            raise ValueError("Native classic prepare selector exceeds four slots")
        if not functions:
            raise ValueError("Native catalog address strategy missing")
    addresses = communication_addresses_from_calibration(container, fields)
    success, rows = addresses.resolve(functions, cids=current_cids)
    if not success or not rows:
        raise ValueError("Native Suzuki communication address selection failed")
    # Both inspected native Suzuki exports consume the first address record.
    return rows[0].request[:2].rjust(4, b"\0"), rows[0].response[:2].rjust(4, b"\0")


def suzuki_wait_time_for_igoffon(
    identity: NativeModuleIdentity,
    parameters,
    container=None,
    *,
    kind: int = 0,
    address_context=None,
) -> int:
    """Utility RVA20a0: source-bound keyed DWORD parameter, missing defaults0."""
    from scripts.programming_2026_common import NativeParameter2026

    require_identity(identity)
    if identity.module_name != "TCUWCanSuzukiUDSUtils.dll":
        raise ValueError("Suzuki utility source identity required")
    if (
        not isinstance(parameters, NativeParameter2026)
        or type(kind) is not int
        or not 0 <= kind <= 0xFFFFFFFF
    ):
        raise ValueError("Native parameter table and uint32 enum required")
    if container is None:
        return 0
    metadata = _current_metadata(container, address_context)
    name = (
        ("WaitTimeForIGOFFON", "AlternateWaitTimeForIGOFFON")[kind] if kind < 2 else ""
    )
    value = parameters.long_with_keys(
        name,
        *_parameter_keys(metadata),
    )
    return 0 if value is None else value & 0xFFFFFFFF


class SuzukiPrepareCommands:
    """Prepare RVAs31e0/30c0/2fa0/4890/4960/2770/2a40, raw utility I/O."""

    def __init__(
        self,
        identity,
        utility_identity,
        runtime,
        container,
        *,
        parameters=None,
        phase="PrepareWrite",
        address_context=None,
    ):
        from scripts.programming_2026_common import NativeRuntime2026

        require_identity(identity)
        require_identity(utility_identity)
        if (
            identity.module_name != "TCUWCanSuzukiUDSPrepareWriter.dll"
            or utility_identity.module_name != "TCUWCanSuzukiUDSUtils.dll"
        ):
            raise ValueError("Exact Suzuki prepare and utility identities required")
        if not isinstance(runtime, NativeRuntime2026):
            raise TypeError("Primitive native runtime required")
        self.request, self.response = native_suzuki_addresses(
            identity,
            container,
            parameters=parameters,
            phase=phase,
            address_context=address_context,
        )
        program_fields = _suzuki_functional_address(container)
        self.functional = program_fields
        self.identity, self.runtime = utility_identity, runtime

    def _call(self, request, expected, *, functional=False, minimum=2, error_code=9999):
        return suzuki_exchange(
            self.identity,
            self.runtime,
            self.functional if functional else self.request,
            self.response,
            request,
            expected,
            minimum=minimum,
            error_code=error_code,
            native_flag_10=functional,
        )

    def extended_session(self):
        return self._call(b"\x10\x83", b"\x50\x83", functional=True, error_code=0x58)

    def disable_dtc(self):
        return self._call(
            b"\x85\x82\x00", b"\xc5\x02", functional=True, error_code=0x2A
        )

    def communication_control(self):
        return self._call(
            b"\x28\x83\x01", b"\x68\x03", functional=True, error_code=0x2B
        )

    def programming_session(self, *, usb=False):
        if type(usb) is not bool:
            raise TypeError("Explicit native USB branch required")
        suffix = b"\x44" if usb else b"\x02"
        return self._call(
            b"\x10" + suffix, b"\x50" + suffix, minimum=6, error_code=0x29
        )

    def authorize(self, observations: dict[bytes, bytes] | None, *, usb=False):
        if type(usb) is not bool:
            raise TypeError("Explicit native USB branch required")
        _validate_key_observations(observations, 16, 16)
        if usb:
            self._call(b"\x22\x10\x18", b"\x62\x10\x18", minimum=12, error_code=0x405)
        subfunction = 0x29 if usb else 1
        response = self._call(
            bytes((0x27, subfunction)),
            bytes((0x67, subfunction)),
            minimum=18,
            error_code=0x10,
        )
        seed = response[2:18]
        key = _authorization_key(
            self.runtime,
            observations,
            seed,
            16,
            "suzuki_usb_uds" if usb else "suzuki_uds",
            "ecu",
        )
        self._call(
            bytes((0x27, subfunction + 1)) + key,
            bytes((0x67, subfunction + 1)),
            error_code=0x11,
        )


def _suzuki_functional_address(container) -> bytes:
    from scripts.calibration_2026 import native2026_metadata

    metadata = native2026_metadata(container)
    text = metadata.vehicle.get("canidtx_func_usdt", "")
    if (
        not text
        or len(text) % 2
        or len(text) > 1024
        or any(character not in "0123456789abcdefABCDEF" for character in text)
    ):
        raise ValueError("Native Suzuki functional CAN hexadecimal field required")
    return bytes.fromhex(text)[-4:].rjust(4, b"\0")


def suzuki_recheck_prepare_cid(
    identity,
    utility_identity,
    runtime,
    container,
    parameters,
    controller_state,
    current_cid: bytes,
    *,
    address_context=None,
    result: SuzukiUSBResult | None = None,
) -> bytes | None:
    """Prepare32f0/3eb9 readback and real persistent+a5c mutation."""
    from scripts.calibration_2026 import native2026_baud_rate
    from scripts.cuw_2026 import SuzukiControllerState2026
    from scripts.programming import NativeTransportError
    from scripts.programming_2026_common import (
        CommonResponseError,
        NativeParameter2026,
        NativePassThruException2026,
    )

    commands = SuzukiPrepareCommands(
        identity,
        utility_identity,
        runtime,
        container,
        parameters=parameters,
        phase="GetCID",
        address_context=address_context,
    )
    metadata = _current_metadata(container, address_context)
    if (
        not isinstance(parameters, NativeParameter2026)
        or not isinstance(controller_state, SuzukiControllerState2026)
        or controller_state.source_sha256 != metadata.source_sha256
        or controller_state.node != metadata.node
        or controller_state.cpu_index != metadata.cpu_index
        or runtime.native_cancelled is None
        or not isinstance(current_cid, bytes)
        or len(current_cid) > 4096
        or b"\0" in current_cid
        or (result is not None and not isinstance(result, SuzukiUSBResult))
    ):
        raise ValueError(
            "Bound native Suzuki controller, parameter table and current CID required"
        )
    timeout = parameters.long_with_keys(
        "ReceiveTimeoutBeforeGetCID",
        *_parameter_keys(metadata),
    )
    handle = None
    readback = None
    try:
        runtime.call("set_timeout", milliseconds=(timeout or 0) & 0xFFFFFFFF)
        set_suzuki_baud_rate(
            utility_identity,
            runtime,
            (native2026_baud_rate(metadata) * 1000) & 0xFFFFFFFF,
        )
        handle = runtime.acquire(
            "start_flow_control_filter",
            "stop_filter",
            request_address=commands.request,
            response_address=commands.response,
        )

        def exchange(_, payload):
            widths = {0x88: 16, 0x89: 2, 0x91: 11}
            if (
                len(payload) != 3
                or payload[:2] != b"\x22\xf1"
                or payload[2] not in widths
            ):
                raise ValueError("Unexpected native Suzuki CID request")
            return suzuki_exchange(
                utility_identity,
                runtime,
                commands.request,
                commands.response,
                payload,
                b"\x62" + payload[1:],
                minimum=3 + widths[payload[2]],
                error_code=3,
                native_flag_9=True,
            )

        utility = SuzukiIdentification(
            utility_identity,
            NativeProgrammingChannel(
                exchange,
                commands.request.hex(),
                timeout=runtime.check(),
                clock=runtime.clock,
                cancelled=runtime.cancelled,
            ),
        )
        version = utility.software_version()
        software = utility.software_id()
        hardware = utility.hardware_id()
        readback = hardware + b"_" + software + b"_" + version.encode("ascii")
        controller_state.compare_prepare_cid(current_cid, readback)
    except (Exception, KeyboardInterrupt) as exc:
        controller_state.clear_after_prepare_fault()
        if not isinstance(
            exc,
            (CommonResponseError, NativeTransportError, NativePassThruException2026),
        ):
            raise
        fields = _native_error_fields(exc)
        controller_state.record_native_error(
            1, fields["native_primary_error"], fields.get("native_passthru_error")
        )
        if result is not None:
            result.error_status = 1
            result.native_error = {
                "native_error_kind": controller_state.error_kind,
                "native_primary_error": controller_state.primary_error,
                "native_passthru_error": controller_state.passthru_error,
            }
    finally:
        if handle is not None:
            try:
                runtime.release("stop_filter", identifier=handle)
            except (InterruptedError, TimeoutError):
                raise
            except Exception as exc:  # noqa: BLE001 - native recheck catch-all suppresses filter cleanup
                if result is not None:
                    result.suppressed_cleanup_errors.append(type(exc).__name__)
    return readback


def suzuki_gateway_authorize(
    identity: NativeModuleIdentity,
    channel: NativeProgrammingChannel,
    runtime,
    observations: dict[bytes, bytes] | None,
    *,
    with_filter: bool = False,
) -> None:
    """Utility RVA1750:2713/2714 with explicit observed seed/key pairs.

    Keys are never derived, fetched or included in a result. Native NRC37 retries
    the whole seed/key exchange once after10100ms; other failures propagate.
    """
    from scripts.programming_2026_common import CommonResponseError, NativeRuntime2026

    require_identity(identity)
    if identity.module_name != "TCUWCanSuzukiUDSUtils.dll":
        raise ValueError("Suzuki utility source identity required")
    if (
        not isinstance(channel, NativeProgrammingChannel)
        or channel.ecu.lower() != SUZUKI_GATEWAY_REQUEST.hex()
        or not isinstance(runtime, NativeRuntime2026)
        or type(with_filter) is not bool
    ):
        raise ValueError(
            "Explicit gateway channel, runtime and observed sixteen/256-byte authorization pairs required"
        )
    _validate_key_observations(observations, 16, 256)
    handle = None
    if with_filter:
        handle = runtime.acquire(
            "start_flow_control_filter",
            "stop_filter",
            request_address=SUZUKI_GATEWAY_REQUEST,
            response_address=SUZUKI_GATEWAY_RESPONSE,
        )
    try:
        for attempt in range(2):
            runtime.check()
            try:
                response = channel.call(b"\x27\x13", b"\x67\x13")
                if len(response) < 18:
                    raise ValueError(
                        "Native gateway seed response requires sixteen bytes"
                    )
                seed = response[2:18]
                key = _authorization_key(
                    runtime, observations, seed, 256, "suzuki_uds", "gateway"
                )
                channel.call(b"\x27\x14" + key, b"\x67\x14")
                return
            except (NativeNegativeResponse, CommonResponseError) as exc:
                if attempt or exc.response != b"\x7f\x27\x37":
                    raise
                if runtime.call("wait", milliseconds=10100) is not None:
                    raise TypeError("Native wait primitive must return None")
    finally:
        if handle is not None:
            runtime.release("stop_filter", identifier=handle)


def suzuki_supports_wired_repro(
    identity: NativeModuleIdentity,
    channel: NativeProgrammingChannel,
    runtime,
    *,
    with_filter: bool = False,
) -> bool:
    """Utility RVA1510:221004 reply byte04; only J2534 errors9/16 mean false."""
    from scripts.programming import NativeTransportError
    from scripts.programming_2026_common import (
        NativeJ2534Exception2026,
        NativeRuntime2026,
    )

    require_identity(identity)
    if identity.module_name != "TCUWCanSuzukiUDSUtils.dll":
        raise ValueError("Suzuki utility source identity required")
    if (
        not isinstance(channel, NativeProgrammingChannel)
        or channel.ecu.lower() != SUZUKI_GATEWAY_REQUEST.hex()
        or not isinstance(runtime, NativeRuntime2026)
        or type(with_filter) is not bool
    ):
        raise ValueError("Explicit bounded Suzuki central gateway context required")
    handle = None
    if with_filter:
        handle = runtime.acquire(
            "start_flow_control_filter",
            "stop_filter",
            request_address=SUZUKI_GATEWAY_REQUEST,
            response_address=SUZUKI_GATEWAY_RESPONSE,
        )
    try:
        try:
            response = channel.call(b"\x22\x10\x04", b"\x62\x10\x04")
        except (NativeTransportError, NativeJ2534Exception2026) as exc:
            if _driver_status(exc) in (9, 16):
                return False
            raise
        if len(response) < 4:
            raise ValueError("Native wired repro capability byte is missing")
        return response[3] == 4
    finally:
        if handle is not None:
            runtime.release("stop_filter", identifier=handle)


def fhi_exchange(
    identity: NativeModuleIdentity,
    runtime,
    requests: tuple[bytes, ...],
    response_addresses: tuple[bytes, ...],
    expected: bytes,
    *,
    minimum: int = 0,
    error_code: int = 9999,
    negative_retries: int = 3,
    retry_delay_ms: int = 0,
    write_delay_ms: int = 0,
    pending_limit: int = 0x95,
    native_flag_8: bool = False,
) -> tuple[bytes, ...]:
    """FHIUtils RVA18d0 multi-message send/read/retry over J2534 primitives."""
    from scripts.programming_2026_common import CommonResponseError, NativeRuntime2026

    require_identity(identity)
    if identity.module_name != "TCUWFHIUtils.dll":
        raise ValueError("FHI utility source identity required")
    if (
        not isinstance(runtime, NativeRuntime2026)
        or not isinstance(requests, tuple)
        or not 1 <= len(requests) <= 256
        or any(
            not isinstance(frame, bytes) or not 5 <= len(frame) <= 4128
            for frame in requests
        )
        or not isinstance(response_addresses, tuple)
        or not 1 <= len(response_addresses) <= 256
        or any(
            not isinstance(address, bytes) or len(address) != 4
            for address in response_addresses
        )
        or not isinstance(expected, bytes)
        or type(native_flag_8) is not bool
        or not 1 <= len(expected) <= 4124
        or any(
            type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (
                minimum,
                error_code,
                negative_retries,
                retry_delay_ms,
                write_delay_ms,
                pending_limit,
            )
        )
        or minimum > 4124
    ):
        raise ValueError(
            "Bounded native FHI message, response and retry fields required"
        )
    if native_flag_8 and runtime.native_cancelled is None:
        raise ValueError("Native FHI cancellation callback is not bound")
    previous = runtime.call("get_timeout")
    if type(previous) is not int or not 0 <= previous <= 0xFFFFFFFF:
        raise TypeError("Native timeout getter must return uint32")
    runtime.own("set_timeout", milliseconds=previous)

    def write(messages):
        result = runtime.call("write_messages", messages=messages, count=len(messages))
        if type(result) is not int or result != len(messages):
            raise ValueError("J2534 batch primitive must report all messages written")

    retries = 0
    try:
        while True:
            write(requests)
            runtime.call("wait", milliseconds=write_delay_ms)
            remaining = response_addresses
            finals = []
            negatives = 0
            pending = 0
            while remaining:
                if native_flag_8:
                    runtime.check_native_cancelled()
                received = runtime.call(
                    "read_specified_can_messages",
                    addresses=remaining,
                    count=len(remaining),
                )
                if not isinstance(received, tuple) or len(received) > len(remaining):
                    raise TypeError("J2534 batch read must return bounded frame tuple")
                positive, remaining, negative = fhi_response_status(
                    identity, requests[0][4], received, remaining
                )
                finals.extend(positive)
                negatives += negative
                if len(finals) + negatives > len(response_addresses):
                    raise ValueError("FHI batch contains surplus final responses")
                if remaining:
                    pending += 1
                    if pending > pending_limit:
                        write(tuple(frame[:4] + b"\x3e" for frame in requests))
                        raise CommonResponseError(error_code)
                    if previous < 5000:
                        runtime.call("set_timeout", milliseconds=5000)
            if not negatives:
                break
            retries += 1
            if retries > negative_retries:
                raise CommonResponseError(error_code)
            runtime.call("wait", milliseconds=retry_delay_ms)
            runtime.call("set_timeout", milliseconds=previous)
        if len(finals) != len(response_addresses):
            raise ValueError("FHI batch lacks final responses")
        for frame in finals:
            if len(frame) < 4 + minimum or not frame[4:].startswith(expected):
                raise CommonResponseError(error_code, frame[4:])
        return tuple(frame[4:] for frame in finals)
    finally:
        runtime.release("set_timeout", milliseconds=previous)


def suzuki_exchange(
    identity: NativeModuleIdentity,
    runtime,
    request_address: bytes,
    response_address: bytes,
    payload: bytes,
    expected: bytes | None,
    *,
    minimum: int = 0,
    error_code: int = 9999,
    pending_limit: int = SUZUKI_MAX_RESPONSE_PENDING,
    native_flag_9: bool = False,
    native_flag_10: bool = False,
) -> bytes:
    """SuzukiUtils RVA2370, including native pending-count and silent branch.

    Flag10 permits an initial J2534 timeout9/16 but rejects an immediate positive
    response. This preserves the native branch without guessing its domain name.
    Extra native Unlock calls are retained; the native mutex wrapper ignores a
    failed ReleaseMutex. Providers must implement that void primitive contract.
    """
    from scripts.programming import NativeTransportError
    from scripts.programming_2026_common import (
        CommonResponseError,
        NativeJ2534Exception2026,
        NativeRuntime2026,
    )

    require_identity(identity)
    if identity.module_name != "TCUWCanSuzukiUDSUtils.dll":
        raise ValueError("Suzuki utility source identity required")
    if (
        not isinstance(runtime, NativeRuntime2026)
        or any(
            not isinstance(address, bytes) or len(address) != 4
            for address in (request_address, response_address)
        )
        or not isinstance(payload, bytes)
        or not 1 <= len(payload) <= 4124
        or (
            expected is not None
            and (not isinstance(expected, bytes) or not 1 <= len(expected) <= 4124)
        )
        or any(
            type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (minimum, error_code, pending_limit)
        )
        or minimum > 4124
        or type(native_flag_10) is not bool
        or type(native_flag_9) is not bool
    ):
        raise ValueError("Bounded native Suzuki communication fields required")
    if native_flag_9 and runtime.native_cancelled is None:
        raise ValueError("Native Suzuki cancellation callback is not bound")
    previous = runtime.call("get_timeout")
    if type(previous) is not int or not 0 <= previous <= 0xFFFFFFFF:
        raise TypeError("Native timeout primitive must return uint32")
    timeout_maximum = max(previous, 5000)
    runtime.own("set_timeout", milliseconds=previous)

    def lock():
        runtime.call_owned("lock", "unlock")

    def unlock():
        if runtime.owns_resource("unlock"):
            runtime.release("unlock")
        else:
            runtime.call("unlock", cleanup=True)

    pending = 0
    timeout_count = 0
    silent = False
    data = b""
    try:
        lock()
        count = runtime.call(
            "write_messages",
            protocol=6,
            tx_flags=0,
            data=request_address + payload,
            count=1,
        )
        if type(count) is not int or count != 1:
            raise ValueError("J2534 primitive must report one written message")
        while True:
            if native_flag_9:
                runtime.check_native_cancelled()
            if pending:
                lock()
            try:
                frame = runtime.call(
                    "read_specified_can_message",
                    address=response_address,
                    count=1,
                    frame=2,
                )
            except (NativeTransportError, NativeJ2534Exception2026) as exc:
                if _driver_status(exc) not in (9, 16):
                    raise
                if not pending:
                    if native_flag_10:
                        silent = True
                        break
                    raise
                timeout_count += 1
                if timeout_count >= timeout_maximum // 1000:
                    raise
                if timeout_count == timeout_maximum // 1000 - 1:
                    runtime.call(
                        "set_timeout", milliseconds=timeout_maximum % 1000 + 1000
                    )
                unlock()
                continue
            if pending:
                unlock()
            if (
                not isinstance(frame, bytes)
                or not 4 <= len(frame) <= 4128
                or not frame.startswith(response_address)
            ):
                raise ValueError("Malformed native Suzuki CAN response")
            data = frame[4:]
            if len(data) < 3 or data[:3] != bytes((0x7F, payload[0], 0x78)):
                break
            if not pending:
                unlock()
            pending += 1
            if pending > pending_limit:
                raise CommonResponseError(error_code)
            runtime.call("set_timeout", milliseconds=1000)
            timeout_count = 0
        unlock()
        runtime.call("set_timeout", milliseconds=previous)
        if silent:
            return b""
        if native_flag_10 and not pending:
            raise CommonResponseError(error_code, data)
        if len(data) < minimum or (
            expected is not None and not data.startswith(expected)
        ):
            raise CommonResponseError(error_code, data)
        return data
    finally:
        try:
            unlock()
        finally:
            runtime.release("set_timeout", milliseconds=previous)


class FHIPrepareCommands:
    """Source FHI prepare helpers19b0/1d00/1f30 with observed authorization."""

    def __init__(
        self,
        identity: NativeModuleIdentity,
        utility_identity: NativeModuleIdentity,
        runtime,
    ):
        from scripts.programming_2026_common import NativeRuntime2026

        require_identity(identity)
        require_identity(utility_identity)
        if (
            identity.module_name != "TCUWCanFHIPrepareWriter.dll"
            or utility_identity.module_name != "TCUWFHIUtils.dll"
            or not isinstance(runtime, NativeRuntime2026)
        ):
            raise ValueError(
                "Exact FHI preparation/utility identities and runtime required"
            )
        self.utility_identity, self.runtime = utility_identity, runtime

    @staticmethod
    def _addresses(values: tuple[bytes, ...]) -> None:
        if (
            not isinstance(values, tuple)
            or not 1 <= len(values) <= 256
            or any(
                not isinstance(address, bytes) or len(address) != 4
                for address in values
            )
        ):
            raise ValueError("Bounded four-byte native FHI addresses required")

    def disable_dtc(
        self,
        request_addresses: tuple[bytes, ...],
        response_addresses: tuple[bytes, ...],
    ) -> None:
        self._addresses(request_addresses)
        self._addresses(response_addresses)
        fhi_exchange(
            self.utility_identity,
            self.runtime,
            tuple(address + b"\x85\x02" for address in request_addresses),
            response_addresses,
            b"\xc5\x02",
            minimum=2,
            error_code=0x2A,
            retry_delay_ms=200,
        )

    def communication_control(
        self, functional_address: bytes, response_addresses: tuple[bytes, ...]
    ) -> None:
        self._addresses((functional_address,))
        self._addresses(response_addresses)
        fhi_exchange(
            self.utility_identity,
            self.runtime,
            (functional_address + b"\x28\x03\x01",),
            response_addresses,
            b"\x68\x03",
            minimum=2,
            error_code=0x2B,
            retry_delay_ms=20,
        )

    def session(
        self, request_address: bytes, response_address: bytes, subfunction: int
    ) -> None:
        """Prepare2170: exact selected session byte and native error29."""
        self._addresses((request_address, response_address))
        if type(subfunction) is not int or not 0 <= subfunction <= 255:
            raise ValueError("Native FHI session byte required")
        fhi_exchange(
            self.utility_identity,
            self.runtime,
            (request_address + bytes((0x10, subfunction)),),
            (response_address,),
            bytes((0x50, subfunction)),
            minimum=2,
            error_code=0x29,
        )

    def probe(self, request_address: bytes, response_address: bytes) -> bytes:
        """Prepare2f60 delegates09/00 to actual2026 CanDiag utility."""
        from scripts.programming_2026_common import CanDiag2026

        self._addresses((request_address, response_address))
        return CanDiag2026(self.runtime).call(
            request_address,
            response_address,
            b"\x09\x00",
            None,
            error_code=3,
            pending_limit=149,
            busy_limit=255,
            send_tester_present=True,
            pending_timeout_ms=5000,
        )

    def authorize(
        self,
        request_address: bytes,
        response_address: bytes,
        observations: dict[bytes, bytes] | None,
    ) -> None:
        self._addresses((request_address,))
        self._addresses((response_address,))
        _validate_key_observations(observations, 4, 4)
        seed_response = fhi_exchange(
            self.utility_identity,
            self.runtime,
            (request_address + b"\x27\x61",),
            (response_address,),
            b"\x67\x61",
            minimum=6,
            error_code=0x10,
        )[0]
        seed = seed_response[2:6]
        key = _authorization_key(self.runtime, observations, seed, 4, "fhi", "ecu")
        fhi_exchange(
            self.utility_identity,
            self.runtime,
            (request_address + b"\x27\x62" + key,),
            (response_address,),
            b"\x67\x62",
            minimum=2,
            error_code=0x11,
        )


def suzuki_get_identification(
    identity: NativeModuleIdentity,
    utility_identity: NativeModuleIdentity,
    runtime,
    channel: NativeProgrammingChannel,
    request_address: bytes,
    response_address: bytes,
    *,
    baudrate_kbps: int,
    receive_timeout_ms: int,
    result: SuzukiUSBResult | None = None,
) -> bytes:
    """Getter RVA14e0: connect/configure/filter/version/software/hardware/CID.

    Addresses and numeric fields are native producer inputs. CUW metadata
    selection is separate and must establish their source before calling this.
    """
    from scripts.programming_2026_common import NativeRuntime2026

    require_identity(identity)
    require_identity(utility_identity)
    if (
        identity.module_name != "TCUWCanSuzukiUDSSoftwareIDGetter.dll"
        or utility_identity.module_name != "TCUWCanSuzukiUDSUtils.dll"
    ):
        raise ValueError("Exact Suzuki getter and utility identities required")
    if (
        not isinstance(runtime, NativeRuntime2026)
        or (result is not None and not isinstance(result, SuzukiUSBResult))
        or not isinstance(channel, NativeProgrammingChannel)
        or any(
            not isinstance(address, bytes) or len(address) != 4
            for address in (request_address, response_address)
        )
        or channel.ecu.lower() != request_address.hex()
        or any(
            type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (baudrate_kbps, receive_timeout_ms)
        )
    ):
        raise ValueError("Bounded native Suzuki getter producer inputs required")
    connected = False
    handle = None
    if result is not None:
        result.success = False
        result.progress = result.error_status = 0
        result.recovery_needed = False
        result.cleanup_errors.clear()
        result.suppressed_cleanup_errors.clear()
        result.native_error.clear()
    try:
        runtime.call_owned("connect", "disconnect", protocol=6)
        connected = True
        runtime.call("set_timeout", milliseconds=receive_timeout_ms)
        set_suzuki_baud_rate(
            utility_identity, runtime, (baudrate_kbps * 1000) & 0xFFFFFFFF
        )
        handle = runtime.acquire(
            "start_flow_control_filter",
            "stop_filter",
            request_address=request_address,
            response_address=response_address,
        )
        utility = SuzukiIdentification(utility_identity, channel)
        version = utility.software_version()
        software = utility.software_id()
        hardware = utility.hardware_id()
        if result is not None:
            result.success = True
        return hardware + b"_" + software + b"_" + version.encode("ascii")
    finally:
        try:
            if handle is not None:
                try:
                    runtime.release("stop_filter", identifier=handle)
                except (InterruptedError, TimeoutError):
                    raise
                except Exception as exc:  # noqa: BLE001 - native state11 catch-all1e9b
                    if result is not None:
                        result.suppressed_cleanup_errors.append(type(exc).__name__)
        finally:
            if connected:
                runtime.release("disconnect")
                if handle is not None and runtime.owns_resource(
                    "stop_filter", identifier=handle
                ):
                    runtime.forget_invalidated_resource(
                        "stop_filter", identifier=handle
                    )


def get_suzuki_cid(
    identity,
    utility_identity,
    runtime,
    container,
    parameters,
    *,
    address_context=None,
    result: SuzukiUSBResult | None = None,
) -> bytes:
    """StartGetCID1f60/14e0 with actual CUW and selected native CSV producers."""
    from scripts.calibration_2026 import native2026_baud_rate
    from scripts.programming_2026_common import NativeParameter2026, NativeRuntime2026

    require_identity(identity)
    require_identity(utility_identity)
    if (
        identity.module_name != "TCUWCanSuzukiUDSSoftwareIDGetter.dll"
        or utility_identity.module_name != "TCUWCanSuzukiUDSUtils.dll"
        or not isinstance(parameters, NativeParameter2026)
        or not isinstance(runtime, NativeRuntime2026)
    ):
        raise ValueError(
            "Exact native Suzuki getter, utility, runtime and parameter table required"
        )
    if runtime.native_cancelled is None:
        raise ValueError("Native Suzuki getter cancellation callback is not bound")
    metadata = _current_metadata(container, address_context)
    request, response = native_suzuki_addresses(
        identity,
        container,
        parameters=parameters,
        phase="GetCID",
        address_context=address_context,
    )
    timeout = parameters.long_with_keys(
        "ReceiveTimeoutBeforeGetCID",
        *_parameter_keys(metadata),
    )

    def exchange(_, payload):
        widths = {0x88: 16, 0x89: 2, 0x91: 11}
        if len(payload) != 3 or payload[:2] != b"\x22\xf1" or payload[2] not in widths:
            raise ValueError("Unexpected native Suzuki CID request")
        return suzuki_exchange(
            utility_identity,
            runtime,
            request,
            response,
            payload,
            b"\x62" + payload[1:],
            minimum=3 + widths[payload[2]],
            error_code=3,
            native_flag_9=True,
        )

    channel = NativeProgrammingChannel(
        exchange,
        request.hex(),
        timeout=runtime.check(),
        clock=runtime.clock,
        cancelled=runtime.cancelled,
    )
    return suzuki_get_identification(
        identity,
        utility_identity,
        runtime,
        channel,
        request,
        response,
        baudrate_kbps=native2026_baud_rate(metadata),
        receive_timeout_ms=(timeout or 0) & 0xFFFFFFFF,
        result=result,
    )


def suzuki_tester_information(
    identity: NativeModuleIdentity,
    channel: NativeProgrammingChannel,
    tester_info: str,
    system_time: tuple[int, ...],
) -> None:
    """SuzukiFlash RVA1ba0: tester hex suffix and UTC month/day ASCII fields."""
    require_identity(identity)
    if identity.module_name != "TCUWCanSuzukiUDSFlashWriter.dll":
        raise ValueError("Suzuki writer source identity required")
    if (
        not isinstance(channel, NativeProgrammingChannel)
        or not isinstance(tester_info, str)
        or len(tester_info) != 34
        or any(char not in "0123456789abcdefABCDEF" for char in tester_info)
        or not isinstance(system_time, tuple)
        or len(system_time) != 8
        or any(
            type(value) is not int or not 0 <= value <= 65535 for value in system_time
        )
        or not 1 <= system_time[1] <= 12
        or not 1 <= system_time[3] <= 31
    ):
        raise ValueError(
            "Native tester34hex and observed SYSTEMTIME month/day required"
        )
    channel.call(b"\x2e\xf1\x98" + bytes.fromhex(tester_info[14:]), b"\x6e\xf1\x98")
    date = f"{system_time[1]:02d}{system_time[3]:02d}".encode("ascii")
    channel.call(b"\x2e\xf1\x99" + date, b"\x6e\xf1\x99")


@dataclass(frozen=True)
class SuzukiProgram2026:
    module: NativeModuleIdentity
    container_sha256: str
    archive_sha256: str
    start_address: bytes
    data: bytes = field(repr=False)
    download_length: int
    max_block_data: int
    post_request_address: bytes

    def report(self) -> dict:
        return {
            "module": self.module.module_name,
            "module_sha256": self.module.sha256,
            "engine_sha256": self.module.engine_sha256,
            "native_build": "2026",
            "container_sha256": self.container_sha256,
            "archive_sha256": self.archive_sha256,
            "start_address_hex": self.start_address.hex(),
            "download_length": self.download_length,
            "transfer_length": len(self.data),
            "max_block_data": self.max_block_data,
            "post_request_address_hex": self.post_request_address.hex(),
            "provenance": "CUW2026 Format10/12 native producer fields",
        }


def native_suzuki_program(
    identity: NativeModuleIdentity, container
) -> SuzukiProgram2026:
    """Bind exact2026 Format10/12 producer fields and original archive bytes."""
    import hashlib

    from scripts.calibration_2026 import (
        native2026_archive,
        native2026_download_geometry,
        native2026_metadata,
    )

    require_identity(identity)
    if identity.module_name != "TCUWCanSuzukiUDSFlashWriter.dll":
        raise ValueError("Suzuki writer source identity required")
    metadata = native2026_metadata(container)
    geometry = native2026_download_geometry(metadata)
    archive = native2026_archive(metadata)
    data = archive.data
    if data is None:
        raise ValueError("Native Suzuki archive has no materialized image bytes")
    maximum = metadata.vehicle.get("bytenumberoftransmitting", "")
    functional = metadata.vehicle.get("canidtx_func_usdt", "")
    if (
        not 1 <= len(maximum) <= 8
        or any(char not in "0123456789abcdefABCDEF" for char in maximum)
        or not 2 <= len(functional) <= 1024
        or len(functional) % 2
        or any(char not in "0123456789abcdefABCDEF" for char in functional)
        or int(maximum, 16) == 0
        or len(data) < geometry.download_size
    ):
        raise ValueError(
            "Native Suzuki block, functional address or archive size differs"
        )
    return SuzukiProgram2026(
        identity,
        container.digest,
        hashlib.sha256(archive.raw).hexdigest(),
        geometry.start_address,
        data[: geometry.download_size],
        geometry.uncompressed_size or geometry.download_size,
        int(maximum, 16),
        bytes.fromhex(functional)[-4:].rjust(4, b"\0"),
    )


def suzuki_poll_usb(
    identity: NativeModuleIdentity,
    utility_identity: NativeModuleIdentity,
    channel: NativeProgrammingChannel,
    runtime,
) -> dict:
    """USB writer11f0/1493 polling stages, before finalD915/DA01 routines."""
    from scripts.programming_2026_common import CommonResponseError, NativeRuntime2026

    require_identity(utility_identity)
    if utility_identity.module_name != "TCUWCanSuzukiUDSUtils.dll" or not isinstance(
        runtime, NativeRuntime2026
    ):
        raise ValueError("Native Suzuki utility identity and runtime required")
    commands = SuzukiUSBCommands(identity, channel)
    previous = 255
    started = None
    limit = 0
    progress = []
    retry_errors = 0
    while True:
        runtime.check()
        try:
            status = commands.status()
            if status <= 5:
                group = 0 if status == 0 else 5
                if group == previous:
                    now = runtime.call("get_system_time")
                    if not isinstance(now, tuple):
                        raise ValueError(
                            "Native GetSystemTime primitive must return WORD tuple"
                        )
                    if (
                        not isinstance(started, tuple)
                        or suzuki_elapsed_seconds(
                            utility_identity, runtime, started, now
                        )
                        >= limit
                    ):
                        raise CommonResponseError(0x406)
                elif group > previous or previous == 255:
                    started = runtime.call("get_system_time")
                    if (
                        not isinstance(started, tuple)
                        or len(started) != 8
                        or any(
                            type(value) is not int or not 0 <= value <= 65535
                            for value in started
                        )
                    ):
                        raise ValueError(
                            "Native GetSystemTime primitive must return eight WORDs"
                        )
                    limit = 300 if group == 0 else 10800
                    value = 20 if group == 0 else 30
                    runtime.call("notify_progress", value=value)
                    progress.append(value)
                else:
                    raise CommonResponseError(0x407)
                previous = group
                runtime.call("wait", milliseconds=2000)
                continue
            if status == 6:
                runtime.call("notify_progress", value=80)
                progress.append(80)
                return {"native_status": 6, "progress": progress, "completed": False}
            if 7 <= status <= 12:
                raise CommonResponseError(0x408)
            raise CommonResponseError(9999)
        except (InterruptedError, TimeoutError):
            raise
        except Exception as exc:
            if isinstance(exc, CommonResponseError) and exc.code in (
                0x406,
                0x407,
                0x408,
            ):
                raise
            retry_errors += 1
            if retry_errors >= 4:
                raise


@dataclass
class SuzukiUSBResult:
    success: bool = False
    progress: int = 0
    error_status: int = 0
    recovery_needed: bool = False
    cleanup_errors: list[str] = field(default_factory=list)
    suppressed_cleanup_errors: list[str] = field(default_factory=list)
    native_error: dict[str, int] = field(default_factory=dict)
    native_return_reached: bool | None = None

    def report(self) -> dict:
        return self.native_error | {
            "success": self.success,
            "progress": self.progress,
            "error_status": self.error_status,
            "recovery_needed": self.recovery_needed,
            "cleanup_errors": list(self.cleanup_errors),
            "suppressed_cleanup_errors": list(self.suppressed_cleanup_errors),
            "physical_status": "PHYSICAL_UNCONFIRMED",
        }


def write_suzuki_uds(
    identity: NativeModuleIdentity,
    utility_identity: NativeModuleIdentity,
    runtime,
    container,
    notification,
    *,
    parameters,
    tester_info: str = "",
    result: SuzukiUSBResult | None = None,
    address_context=None,
) -> SuzukiUSBResult:
    """SuzukiFlash1e10/11f0 concrete single-CPU flow, actual CUW producer fields.

    The injected runtime carries raw messages and notifications only. No external
    callback can claim programming completion or choose download geometry.
    """
    from scripts.programming_2026_common import (
        CommonResponseError,
        NativeParameter2026,
        NativeRuntime2026,
        NotificationBool,
    )

    program = native_suzuki_program(identity, container)
    require_identity(utility_identity)
    if (
        utility_identity.module_name != "TCUWCanSuzukiUDSUtils.dll"
        or not isinstance(runtime, NativeRuntime2026)
        or not isinstance(notification, NotificationBool)
        or not isinstance(parameters, NativeParameter2026)
        or not isinstance(tester_info, str)
        or len(tester_info) > 4096
        or (result is not None and not isinstance(result, SuzukiUSBResult))
    ):
        raise ValueError("Native Suzuki writer producer state required")
    request, response = native_suzuki_addresses(
        identity, container, parameters=parameters, address_context=address_context
    )
    state = result if result is not None else SuzukiUSBResult()
    state.success, state.progress, state.error_status, state.recovery_needed = (
        False,
        0,
        0,
        False,
    )
    state.cleanup_errors.clear()
    state.suppressed_cleanup_errors.clear()
    state.native_error.clear()

    def exchange(_, payload):
        sid = payload[0]
        if sid == 0x2E:
            expected, minimum, code = (
                b"\x6e" + payload[1:3],
                3,
                0x54 if payload[2] == 0x98 else 0x55,
            )
        elif sid == 0x31:
            expected, minimum, code = b"\x71" + payload[1:4], 4, 0x19
        elif sid == 0x34:
            expected, minimum, code = b"\x74", 3, 0x1A
        elif sid == 0x36:
            expected, minimum, code = b"\x76" + payload[1:2], 2, 0x22
        elif sid == 0x37:
            expected, minimum, code = b"\x77", 1, 0x1C
        else:
            raise ValueError("Unexpected Suzuki writer request")
        return suzuki_exchange(
            utility_identity,
            runtime,
            request,
            response,
            payload,
            expected,
            minimum=minimum,
            error_code=code,
        )

    blocks = (len(program.data) + min(program.max_block_data, 4095) - 1) // min(
        program.max_block_data, 4095
    )
    channel = NativeProgrammingChannel(
        exchange,
        request.hex(),
        timeout=runtime.check(),
        clock=runtime.clock,
        cancelled=runtime.cancelled,
        message_limit=4116,
        response_budget=max(4096, (blocks + 6) * 32),
        retain_payload_history=False,
    )
    handle = None
    try:
        handle = runtime.acquire(
            "start_flow_control_filter",
            "stop_filter",
            request_address=request,
            response_address=response,
        )
        if len(tester_info) != 34:
            raise CommonResponseError(0x54)
        if any(character not in "0123456789abcdefABCDEF" for character in tester_info):
            raise ValueError("Native tester information must encode seventeen bytes")
        channel.call(b"\x2e\xf1\x98" + bytes.fromhex(tester_info[14:]), b"\x6e\xf1\x98")
        observed_time = runtime.call("get_system_time")
        if (
            not isinstance(observed_time, tuple)
            or len(observed_time) != 8
            or any(
                type(value) is not int or not 0 <= value <= 65535
                for value in observed_time
            )
            or not 1 <= observed_time[1] <= 12
            or not 1 <= observed_time[3] <= 31
        ):
            raise ValueError(
                "Native GetSystemTime must return eight WORDs with valid month/day"
            )
        date = f"{observed_time[1]:02d}{observed_time[3]:02d}".encode("ascii")
        channel.call(b"\x2e\xf1\x99" + date, b"\x6e\xf1\x99")
        notification.assign(True)
        utility = SuzukiIdentification(utility_identity, channel)
        utility.routine_control(SuzukiRoutine.KIND_1)
        suzuki_download(
            identity,
            channel,
            runtime,
            program.start_address,
            program.data,
            program.max_block_data,
            program.download_length,
        )
        state.progress = 100
        utility.routine_control(SuzukiRoutine.KIND_2)
        suzuki_exchange(
            utility_identity,
            runtime,
            request,
            response,
            b"\x11\x01",
            b"\x51\x01",
            minimum=2,
            error_code=0x18,
        )
        suzuki_exchange(
            utility_identity,
            runtime,
            program.post_request_address,
            response,
            b"\x10\x81",
            b"\x50\x81",
            minimum=2,
            error_code=0x3F9,
            native_flag_10=True,
        )
        runtime.call("wait", milliseconds=1000)
        notification.assign(False)
        state.success = True
    except (Exception, KeyboardInterrupt):
        state.progress = 0
        state.error_status = 2 if bool(notification) else 1
        state.recovery_needed = not bool(notification)
        for operation in ("notify_done_size", "notify_progress"):
            try:
                runtime.call(operation, cleanup=True, value=0)
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - preserve original fault
                state.cleanup_errors.append(type(exc).__name__)
        raise
    finally:
        if handle is not None:
            try:
                runtime.release("stop_filter", identifier=handle)
            except (InterruptedError, TimeoutError):
                raise
            except Exception as exc:  # noqa: BLE001 - native state4 catch-all1413
                state.suppressed_cleanup_errors.append(type(exc).__name__)
        try:
            if runtime.owns_resource("stop_sync_periodic_message"):
                runtime.release("stop_sync_periodic_message")
            else:
                runtime.call("stop_sync_periodic_message", cleanup=True)
        except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - attempt every cleanup
            state.cleanup_errors.append(type(exc).__name__)
        if state.cleanup_errors:
            state.success = False
    if state.success and request in (
        bytes.fromhex("00000790"),
        bytes.fromhex("00000791"),
        bytes.fromhex("00000792"),
    ):
        runtime.call(
            "wait",
            milliseconds=480000 if request == bytes.fromhex("00000791") else 10000,
        )
    return state


def write_fhi(
    identity,
    utility_identity,
    runtime,
    container,
    parameters,
    notification,
    *,
    cpu_index=0,
    current_cids=(),
    result: SuzukiUSBResult | None = None,
    address_context=None,
) -> SuzukiUSBResult:
    """FHI1070 concrete selected-CPU verify/write phases and native fault state."""
    from scripts.programming_2026_common import NativeRuntime2026, NotificationBool
    from scripts.programming_2026_legacy import writing_error_dispose

    program = native_fhi_program(
        identity,
        utility_identity,
        container,
        parameters,
        cpu_index=cpu_index,
        current_cids=current_cids,
        address_context=address_context,
    )
    if (
        not isinstance(runtime, NativeRuntime2026)
        or not isinstance(notification, NotificationBool)
        or (result is not None and not isinstance(result, SuzukiUSBResult))
    ):
        raise ValueError("Primitive native FHI runtime and notification required")
    state = result if result is not None else SuzukiUSBResult()
    state.success, state.progress, state.error_status, state.recovery_needed = (
        False,
        0,
        0,
        False,
    )
    state.cleanup_errors.clear()
    state.suppressed_cleanup_errors.clear()
    state.native_error.clear()
    state.native_return_reached = False
    verify_expected = b""

    def exchange(_, payload):
        sid = payload[0]
        if sid in (0x34, 0x35):
            expected, minimum, code = (
                bytes((sid + 0x40, 0x20)),
                4,
                0x1A if sid == 0x34 else 0x2C,
            )
        elif sid == 0x31:
            expected, minimum, code = b"\x71" + payload[1:4], 4, 0x19
        elif sid == 0xB7:
            expected, minimum, code = (
                b"\xf7" + verify_expected,
                len(verify_expected) + 1,
                0x2D,
            )
        elif sid == 0xB6:
            expected, minimum, code = b"\xf6", 1, 0x22
        elif sid == 0x37:
            expected, minimum, code = b"\x77", 1, 0x1C
        else:
            raise ValueError("Unexpected native FHI writer request")
        return fhi_exchange(
            utility_identity,
            runtime,
            (program.request_address + payload,),
            (program.response_address,),
            expected,
            minimum=minimum,
            error_code=code,
        )[0]

    channel = NativeProgrammingChannel(
        exchange,
        program.request_address.hex(),
        timeout=runtime.check(),
        clock=runtime.clock,
        cancelled=runtime.cancelled,
        message_limit=4116,
        response_budget=len(program.data) * 2 + 65536,
        retain_payload_history=False,
    )
    commands = FHICommands(identity, channel)
    handle = None
    writing = False
    done = 0

    def chunks(maximum, upload):
        nonlocal verify_expected, done
        count = (len(program.data) + maximum - 1) // maximum
        if count + channel.attempt_count + 1 > 65536:
            raise ValueError(
                "Native FHI transfer exceeds remaining channel request budget"
            )
        base = int.from_bytes(program.start_address[-4:], "big")
        width = len(program.start_address)
        for offset in range(0, len(program.data), maximum):
            runtime.check()
            chunk = program.data[offset : offset + maximum]
            address = (
                ((base + offset) & 0xFFFFFFFF)
                .to_bytes(4, "big")[-width:]
                .rjust(width, b"\0")
            )
            if upload:
                commands.write_chunk(address, chunk)
            else:
                verify_expected = chunk
                commands.verify_chunk(address, chunk)
            done += len(chunk)
            runtime.call("notify_done_size", value=done)
            state.progress = (
                int(float(offset + len(chunk)) / len(program.data) * 100.0) >> 1
            ) + (50 if upload else 0)
            runtime.call("notify_progress", value=state.progress)

    try:
        runtime.call("set_timeout", milliseconds=2000)
        handle = runtime.acquire(
            "start_flow_control_filter",
            "stop_filter",
            request_address=program.request_address,
            response_address=program.response_address,
        )
        maximum = commands.request_area(program.start_address, program.area_length)
        runtime.call("wait", milliseconds=100)
        writing = True
        notification.assign(True)
        runtime.call("set_timeout", milliseconds=5000)
        commands.routine(0x201)
        runtime.call("set_timeout", milliseconds=2000)
        chunks(maximum, False)
        commands.exit_area()
        commands.routine(0x202)
        maximum = commands.request_area(
            program.start_address, program.area_length, upload=True
        )
        runtime.call("set_timeout", milliseconds=10000)
        chunks(maximum, True)
        runtime.call("set_timeout", milliseconds=2000)
        commands.exit_area()
        notification.assign(False)
        state.success = True
    except (Exception, KeyboardInterrupt) as exc:
        state.error_status = 2 if writing else 1
        fields = _native_error_fields(exc)
        if fields:
            state.native_error = {"native_error_kind": state.error_status} | fields
            if address_context is not None:
                controller = address_context.controller_state
                controller.record_native_error(
                    state.error_status,
                    fields["native_primary_error"],
                    fields.get("native_passthru_error"),
                )
                state.native_error["native_passthru_error"] = controller.passthru_error
        raise
    finally:
        if handle is not None:
            try:
                runtime.release("stop_filter", identifier=handle)
            except (InterruptedError, TimeoutError):
                raise
            except Exception as exc:  # noqa: BLE001 - native state6 catch-all141c
                state.suppressed_cleanup_errors.append(type(exc).__name__)
        if not state.success and state.error_status == 2:

            def dispose_notify(kind):
                if kind == "percent":
                    state.progress = 0
                runtime.call(
                    "notify_done_size" if kind == "count" else "notify_progress",
                    cleanup=True,
                    value=0,
                )

            writing_error_dispose(0, [done], [state.progress], dispose_notify)
        runtime.call("set_timeout", cleanup=True, milliseconds=2000)
        state.native_return_reached = True
    return state


def prepare_suzuki_uds(
    identity,
    utility_identity,
    runtime,
    container,
    parameters,
    controller_state,
    current_cid: bytes,
    gateway_observations,
    ecu_observations,
    *,
    result: SuzukiUSBResult | None = None,
    address_context=None,
) -> SuzukiUSBResult:
    """SuzukiPrepare4ea0/40a0 with real controller state and observed keys."""
    from scripts.calibration_2026 import native2026_baud_rate
    from scripts.cuw_2026 import SuzukiControllerState2026
    from scripts.programming_2026_common import NativeParameter2026

    commands = SuzukiPrepareCommands(
        identity,
        utility_identity,
        runtime,
        container,
        parameters=parameters,
        address_context=address_context,
    )
    metadata = _current_metadata(container, address_context)
    if (
        not isinstance(parameters, NativeParameter2026)
        or not isinstance(controller_state, SuzukiControllerState2026)
        or controller_state.source_sha256 != metadata.source_sha256
        or controller_state.node != metadata.node
        or controller_state.cpu_index != metadata.cpu_index
        or type(controller_state.native_context_964) is not bool
        or not isinstance(current_cid, bytes)
        or b"\0" in current_cid
        or len(current_cid) > 4096
        or (result is not None and not isinstance(result, SuzukiUSBResult))
    ):
        raise ValueError(
            "Bound native Suzuki prepare controller and current CID required"
        )
    state = result if result is not None else SuzukiUSBResult()
    state.success, state.progress, state.error_status, state.recovery_needed = (
        False,
        0,
        0,
        False,
    )
    state.cleanup_errors.clear()
    state.suppressed_cleanup_errors.clear()
    state.native_error.clear()
    usb = commands.request == bytes.fromhex("00000795")
    if usb and controller_state.value == 2:
        runtime.call(
            "notify_igoffon_wait",
            value=suzuki_wait_time_for_igoffon(
                utility_identity, parameters, container, address_context=address_context
            ),
        )
        readback = suzuki_recheck_prepare_cid(
            identity,
            utility_identity,
            runtime,
            container,
            parameters,
            controller_state,
            current_cid,
            address_context=address_context,
            result=state,
        )
        if readback is None:
            return state
        if controller_state.value == 1:
            state.success = True
            return state
    handles = []
    periodic_started = False
    try:
        runtime.call("set_local_time_to_previous_send_time")
        timeout = parameters.long_with_keys(
            "ReceiveTimeoutBeforeFlashWrite",
            *_parameter_keys(metadata),
        )
        runtime.call("set_timeout", milliseconds=(timeout or 0) & 0xFFFFFFFF)
        set_suzuki_baud_rate(
            utility_identity,
            runtime,
            (native2026_baud_rate(metadata) * 1000) & 0xFFFFFFFF,
        )
        handles.append(
            runtime.acquire(
                "start_flow_control_filter",
                "stop_filter",
                request_address=commands.request,
                response_address=commands.response,
            )
        )
        if commands.request != SUZUKI_GATEWAY_REQUEST:
            handles.append(
                runtime.acquire(
                    "start_flow_control_filter",
                    "stop_filter",
                    request_address=SUZUKI_GATEWAY_REQUEST,
                    response_address=SUZUKI_GATEWAY_RESPONSE,
                )
            )
        if not usb and (
            commands.request
            in (
                bytes.fromhex("00000790"),
                bytes.fromhex("00000791"),
                bytes.fromhex("00000792"),
            )
            or (
                commands.request == SUZUKI_GATEWAY_REQUEST
                and controller_state.native_context_964
            )
        ):
            count = runtime.call(
                "write_messages",
                protocol=6,
                tx_flags=0,
                data=commands.functional + b"\x3e\x80",
                count=1,
            )
            if type(count) is not int or count != 1:
                raise ValueError("Native Suzuki tester-present write count mismatch")
            runtime.call("wait", milliseconds=1100)
        commands.extended_session()
        runtime.call("wait", milliseconds=1000)
        runtime.call_owned(
            "start_sync_periodic",
            "stop_sync_periodic_message",
            frames=((commands.functional + b"\x3e\x80", 0),),
            count=1,
            interval_ms=2000,
            retry_ms=100,
            delay_ms=0,
        )
        periodic_started = True

        def exchange(_, payload):
            if payload[:2] == b"\x27\x13":
                expected, minimum, code = b"\x67\x13", 18, 0x10
            elif payload[:2] == b"\x27\x14":
                expected, minimum, code = b"\x67\x14", 2, 0x11
            elif payload == b"\x31\x01\xc0\x01\x00":
                expected, minimum, code = b"\x71\x01\xc0\x01", 4, 0x19
            else:
                raise ValueError("Unexpected native Suzuki gateway prepare request")
            return suzuki_exchange(
                utility_identity,
                runtime,
                SUZUKI_GATEWAY_REQUEST,
                SUZUKI_GATEWAY_RESPONSE,
                payload,
                expected,
                minimum=minimum,
                error_code=code,
            )

        gateway = NativeProgrammingChannel(
            exchange,
            SUZUKI_GATEWAY_REQUEST.hex(),
            timeout=runtime.check(),
            clock=runtime.clock,
            cancelled=runtime.cancelled,
        )
        suzuki_gateway_authorize(
            utility_identity, gateway, runtime, gateway_observations
        )
        SuzukiIdentification(utility_identity, gateway).routine_control(
            SuzukiRoutine.KIND_0
        )
        runtime.call("wait", milliseconds=20)
        commands.disable_dtc()
        runtime.call("wait", milliseconds=1000)
        commands.communication_control()
        runtime.call("wait", milliseconds=1000)
        commands.programming_session(usb=usb)
        commands.authorize(ecu_observations, usb=usb)
        state.success = True
    except (Exception, KeyboardInterrupt):
        state.error_status = 1
        raise
    finally:
        for handle in handles:
            try:
                runtime.release("stop_filter", identifier=handle)
            except (InterruptedError, TimeoutError):
                raise
            except Exception as exc:  # noqa: BLE001 - native state23 catch-all47db
                state.suppressed_cleanup_errors.append(type(exc).__name__)
        if periodic_started and (not state.success or state.cleanup_errors):
            try:
                runtime.release("stop_sync_periodic_message")
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - attempt every cleanup
                state.cleanup_errors.append(type(exc).__name__)
        if state.cleanup_errors:
            state.success = False
    return state


@dataclass
class FHIPrepareResult(SuzukiUSBResult):
    skipped_after_probe_timeout: bool = False
    ect_present: bool = True

    def report(self) -> dict:
        return super().report() | {
            "skipped_after_probe_timeout": self.skipped_after_probe_timeout,
            "ect_present": self.ect_present,
        }


def prepare_fhi(
    identity,
    utility_identity,
    runtime,
    container,
    parameters,
    observations,
    *,
    cpu_index=0,
    current_cids=(),
    result: FHIPrepareResult | None = None,
    address_context=None,
) -> FHIPrepareResult:
    """FHIPrepare31e0/2250: real selected addresses and observed4-byte keys.

    The native successful return after a non-ECT probe timeout is retained as
    an explicit skipped flag. It never denotes completed programming.
    """
    from scripts.j2534_2026 import communication_addresses_from_calibration
    from scripts.programming import NativeTransportError
    from scripts.programming_2026_common import (
        NativeJ2534Exception2026,
        NativeParameter2026,
    )

    commands = FHIPrepareCommands(identity, utility_identity, runtime)
    if not isinstance(parameters, NativeParameter2026) or (
        result is not None and not isinstance(result, FHIPrepareResult)
    ):
        raise ValueError("Native FHI parameter table and preparation result required")
    metadata = _current_metadata(container, address_context, cpu_index=cpu_index)
    fields = {}
    keys = _parameter_keys(metadata)
    for name in parameters.headers:
        value = parameters.values_with_keys(name, *keys)
        if value is not None:
            fields[name] = value
    functions = fields.get("GetCANIDFunctionNameForPrepareWrite", ())
    if metadata.vehicle.get("contacttype", "") in ("P5-Unified", "Phase6", "Ethernet"):
        functions = functions[:1]
    elif len(functions) > 4:
        raise ValueError("Native classic prepare selector exceeds four slots")
    if not functions:
        raise ValueError("Native FHI preparation address strategy missing")
    if address_context is not None:
        selected = _context_address_rows(
            address_context, identity, container, "PrepareWrite"
        )
        success = True
    else:
        success, selected = communication_addresses_from_calibration(
            container, fields
        ).resolve(functions, cids=current_cids)
    if not success or len(selected) != 2:
        raise ValueError(
            "Native FHI preparation requires two address records within its three-filter storage"
        )
    rows = tuple(
        (item.request[:2].rjust(4, b"\0"), item.response[:2].rjust(4, b"\0"))
        for item in selected
    )
    engine_kind = metadata.vehicle.get("kindofecu", "") == "31"
    state = result if result is not None else FHIPrepareResult()
    state.success, state.progress, state.error_status, state.recovery_needed = (
        False,
        0,
        0,
        False,
    )
    state.skipped_after_probe_timeout, state.ect_present = False, True
    state.cleanup_errors.clear()
    state.suppressed_cleanup_errors.clear()
    state.native_error.clear()
    handles = []
    try:
        runtime.call("set_timeout", milliseconds=2000)
        for request, response in rows + (
            (bytes.fromhex("000007b0"), bytes.fromhex("000007b8")),
        ):
            handles.append(
                runtime.acquire(
                    "start_flow_control_filter",
                    "stop_filter",
                    request_address=request,
                    response_address=response,
                )
            )
        active = []
        for request, response in rows:
            try:
                commands.probe(request, response)
                active.append((request, response))
            except (NativeTransportError, NativeJ2534Exception2026) as exc:
                if _driver_status(exc) not in (9, 16):
                    raise
                if request == rows[1][0] and engine_kind:
                    state.ect_present = False
                else:
                    state.skipped_after_probe_timeout = True
                    active.append((request, response))
        if not state.skipped_after_probe_timeout:
            for request, response in active:
                runtime.call(
                    "set_timeout", milliseconds=500 if request == rows[1][0] else 2000
                )
                commands.session(request, response, 0x63)
            runtime.call("set_timeout", milliseconds=180)
            responses = (bytes.fromhex("000007b8"), rows[0][1]) + (
                (rows[1][1],) if state.ect_present else ()
            )
            commands.disable_dtc(
                (bytes.fromhex("000007b0"), bytes.fromhex("000007df")), responses
            )
            runtime.call("wait", milliseconds=120)
            runtime.call("set_timeout", milliseconds=500)
            commands.communication_control(bytes.fromhex("000007df"), responses[1:])
            runtime.call("wait", milliseconds=100)
            runtime.call("set_timeout", milliseconds=2000)
            request, response = rows[0 if engine_kind else 1]
            commands.authorize(request, response, observations)
            commands.session(request, response, 0x62)
        state.success = True
    except (Exception, KeyboardInterrupt):
        state.error_status = 1
        raise
    finally:
        for handle in handles:
            try:
                runtime.release("stop_filter", identifier=handle)
            except (InterruptedError, TimeoutError):
                raise
            except Exception as exc:  # noqa: BLE001 - native state32 catch-all2ee0
                state.suppressed_cleanup_errors.append(type(exc).__name__)
        try:
            runtime.call("set_timeout", cleanup=True, milliseconds=2000)
        except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - attempt every cleanup
            state.cleanup_errors.append(type(exc).__name__)
        if state.cleanup_errors:
            state.success = False
    return state


def first_suzuki_usb_write(
    identity: NativeModuleIdentity,
    utility_identity: NativeModuleIdentity,
    channel: NativeProgrammingChannel,
    runtime,
    request_address: bytes,
    response_address: bytes,
    notification,
    *,
    wait_for_igoffon_value: int,
    result: SuzukiUSBResult | None = None,
    controller_state=None,
) -> SuzukiUSBResult:
    """USB export's fresh-context path, concrete PDU polling and cleanup.

    A nonzero persisted engine+a5c branch is intentionally not accepted as a
    caller-provided success. Its authoritative producer belongs to the engine.
    Wait value is the native AlternateWaitTimeForIGOFFON parameter observation.
    """
    from scripts.cuw_2026 import SuzukiControllerState2026
    from scripts.programming_2026_common import (
        CommonResponseError,
        NativeRuntime2026,
        NotificationBool,
    )

    require_identity(utility_identity)
    commands = SuzukiUSBCommands(identity, channel)
    if (
        utility_identity.module_name != "TCUWCanSuzukiUDSUtils.dll"
        or not isinstance(runtime, NativeRuntime2026)
        or not isinstance(notification, NotificationBool)
        or any(
            not isinstance(address, bytes) or len(address) != 4
            for address in (request_address, response_address)
        )
        or channel.ecu.lower() != request_address.hex()
        or type(wait_for_igoffon_value) is not int
        or not 0 <= wait_for_igoffon_value <= 0xFFFFFFFF
        or (result is not None and not isinstance(result, SuzukiUSBResult))
        or (
            controller_state is not None
            and not isinstance(controller_state, SuzukiControllerState2026)
        )
    ):
        raise ValueError("Explicit native Suzuki USB producer state required")
    state = result if result is not None else SuzukiUSBResult()
    state.success, state.progress, state.error_status, state.recovery_needed = (
        False,
        0,
        0,
        False,
    )
    state.cleanup_errors.clear()
    state.suppressed_cleanup_errors.clear()
    state.native_error.clear()
    handle = None
    notification.disable_event_handler()

    def progress(value):
        state.progress = value
        runtime.call("notify_progress", value=value)

    def retry(operation):
        for attempt in range(4):
            runtime.check()
            try:
                return operation()
            except (InterruptedError, TimeoutError):
                raise
            except Exception:
                if attempt == 3:
                    raise

    def checked_routine(kind):
        if commands.routine(kind) != 1:
            raise CommonResponseError(0x19)

    try:
        progress(0)
        handle = runtime.acquire(
            "start_flow_control_filter",
            "stop_filter",
            request_address=request_address,
            response_address=response_address,
        )
        retry(commands.enable_usb_repro)
        notification.assign(True)
        progress(5)
        retry(lambda: commands.routine(0))
        progress(10)
        try:
            suzuki_poll_usb(identity, utility_identity, channel, runtime)
        except CommonResponseError as exc:
            if exc.code == 0x408:
                notification.assign(False)
            raise
        state.progress = 80
        retry(lambda: checked_routine(1))
        progress(90)
        for attempt in range(4):
            runtime.check()
            returned_bad_status = False
            try:
                if commands.routine(2) != 1:
                    returned_bad_status = True
                    raise CommonResponseError(0x19)
                break
            except (InterruptedError, TimeoutError):
                raise
            except Exception as exc:
                if attempt < 3:
                    continue
                if returned_bad_status:
                    raise
                if controller_state is not None:
                    controller_state.mark_usb_retry_fault()
                runtime.call("notify_igoffon_wait", value=wait_for_igoffon_value)
                raise CommonResponseError(0x409) from exc
        progress(100)
        runtime.call("notify_igoffon_wait", value=wait_for_igoffon_value)
        notification.assign(False)
        state.success = True
        return state
    except (Exception, KeyboardInterrupt):
        state.progress = 0
        state.error_status = 2 if bool(notification) else 1
        state.recovery_needed = not bool(notification)
        try:
            runtime.call("notify_progress", cleanup=True, value=0)
        except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - attempt every cleanup
            state.cleanup_errors.append(type(exc).__name__)
        raise
    finally:
        if handle is not None:
            try:
                runtime.release("stop_filter", identifier=handle)
            except (InterruptedError, TimeoutError):
                raise
            except Exception as exc:  # noqa: BLE001 - native state14 catch-all1716
                state.suppressed_cleanup_errors.append(type(exc).__name__)
        try:
            if runtime.owns_resource("stop_sync_periodic_message"):
                runtime.release("stop_sync_periodic_message")
            else:
                runtime.call("stop_sync_periodic_message", cleanup=True)
        except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - attempt every cleanup
            state.cleanup_errors.append(type(exc).__name__)
        notification.enable_event_handler()
        if state.cleanup_errors:
            state.success = False


@dataclass
class SuzukiUSBWriteResult(SuzukiUSBResult):
    skipped_for_persistent_state: bool = False
    persistent_native_state: int = 0

    def report(self) -> dict:
        return super().report() | {
            "skipped_for_persistent_state": self.skipped_for_persistent_state,
            "persistent_native_state": self.persistent_native_state,
        }


def write_suzuki_usb(
    identity,
    utility_identity,
    runtime,
    container,
    parameters,
    controller_state,
    notification,
    *,
    result: SuzukiUSBWriteResult | None = None,
    address_context=None,
) -> SuzukiUSBWriteResult:
    """USB1c20/1120 using exact CUW/catalog and engine-owned persistent state."""
    from scripts.cuw_2026 import SuzukiControllerState2026
    from scripts.programming_2026_common import (
        NativeParameter2026,
        NativeRuntime2026,
        NotificationBool,
    )

    require_identity(identity)
    require_identity(utility_identity)
    metadata = _current_metadata(container, address_context)
    if (
        identity.module_name != "TCUWCanSuzukiUSBReproUDSFlashWriter.dll"
        or utility_identity.module_name != "TCUWCanSuzukiUDSUtils.dll"
        or not isinstance(runtime, NativeRuntime2026)
        or not isinstance(parameters, NativeParameter2026)
        or not isinstance(notification, NotificationBool)
        or not isinstance(controller_state, SuzukiControllerState2026)
        or controller_state.source_sha256 != metadata.source_sha256
        or controller_state.node != metadata.node
        or controller_state.cpu_index != metadata.cpu_index
        or (result is not None and not isinstance(result, SuzukiUSBWriteResult))
    ):
        raise ValueError(
            "Bound native Suzuki USB controller, catalog and runtime required"
        )
    state = result if result is not None else SuzukiUSBWriteResult()
    state.success, state.progress, state.error_status, state.recovery_needed = (
        False,
        0,
        0,
        False,
    )
    state.cleanup_errors.clear()
    state.suppressed_cleanup_errors.clear()
    state.native_error.clear()
    state.persistent_native_state = controller_state.value
    state.skipped_for_persistent_state = controller_state.value != 0
    if state.skipped_for_persistent_state:
        runtime.call("notify_progress", value=100)
        state.progress, state.success = 100, True
        return state
    request, response = native_suzuki_addresses(
        identity, container, parameters=parameters, address_context=address_context
    )

    def exchange(_, payload):
        if payload == b"\x2e\xcf\x80\x01":
            expected, minimum, code = b"\x6e\xcf\x80", 3, 0x403
        elif payload == b"\x31\x03\xda\x00":
            expected, minimum, code = b"\x71\x03\xda\x00", 5, 0x404
        elif payload in (b"\x31\x01\xda\x00", b"\x31\x01\xd9\x15", b"\x31\x01\xda\x01"):
            expected, minimum, code = (
                b"\x71" + payload[1:4],
                4 if payload[2:] == b"\xda\x00" else 5,
                0x19,
            )
        else:
            raise ValueError("Unexpected native Suzuki USB request")
        return suzuki_exchange(
            utility_identity,
            runtime,
            request,
            response,
            payload,
            expected,
            minimum=minimum,
            error_code=code,
        )

    channel = NativeProgrammingChannel(
        exchange,
        request.hex(),
        timeout=runtime.check(),
        clock=runtime.clock,
        cancelled=runtime.cancelled,
        retain_payload_history=False,
    )
    try:
        first_suzuki_usb_write(
            identity,
            utility_identity,
            channel,
            runtime,
            request,
            response,
            notification,
            wait_for_igoffon_value=suzuki_wait_time_for_igoffon(
                utility_identity,
                parameters,
                container,
                kind=1,
                address_context=address_context,
            ),
            result=state,
            controller_state=controller_state,
        )
        return state
    finally:
        state.persistent_native_state = controller_state.value


class SuzukiUtils2026:
    """1170/1190 constructors and1340/1360 shallow assignment semantics.

    Callback/J2534 pointers are one explicit primitive runtime. Copy and move
    share it and the immutable calibration/table; neither consumes the source.
    """

    def __init__(self, identity, runtime, *, container=None, parameters=None):
        from scripts.calibration_2026 import native2026_metadata
        from scripts.programming_2026_common import (
            NativeParameter2026,
            NativeRuntime2026,
        )

        require_identity(identity)
        if (
            identity.module_name != "TCUWCanSuzukiUDSUtils.dll"
            or not isinstance(runtime, NativeRuntime2026)
            or (
                parameters is not None
                and not isinstance(parameters, NativeParameter2026)
            )
        ):
            raise ValueError(
                "Exact Suzuki utility identity and primitive runtime required"
            )
        if container is not None:
            native2026_metadata(container)
        self.identity, self.runtime = identity, runtime
        self.container, self.parameters = container, parameters

    def __copy__(self):
        return type(self)(
            self.identity,
            self.runtime,
            container=self.container,
            parameters=self.parameters,
        )

    def move(self):
        return self.__copy__()

    def assign(self, other):
        if not isinstance(other, SuzukiUtils2026):
            raise TypeError("Native Suzuki utility object required")
        checked = other.__copy__()
        self.runtime, self.container, self.parameters = (
            checked.runtime,
            checked.container,
            checked.parameters,
        )
        return self

    move_assign = assign

    def send(self, request_address, response_address, payload, expected, **options):
        return suzuki_exchange(
            self.identity,
            self.runtime,
            request_address,
            response_address,
            payload,
            expected,
            **options,
        )

    def _read(self, request_address, response_address, did, width):
        suffix = did.to_bytes(2, "big")
        return self.send(
            request_address,
            response_address,
            b"\x22" + suffix,
            b"\x62" + suffix,
            minimum=3 + width,
            error_code=3,
            native_flag_9=True,
        )[3 : 3 + width]

    def hardware_id(self, request_address, response_address):
        from scripts.programming_2026_common import CommonResponseError

        value = self._read(request_address, response_address, 0xF191, 11).split(
            b"\0", 1
        )[0]
        if not value:
            raise CommonResponseError(3)
        return value

    def software_id(self, request_address, response_address):
        from scripts.programming_2026_common import CommonResponseError

        value = self._read(request_address, response_address, 0xF188, 16).split(
            b"\0", 1
        )[0]
        if not value:
            raise CommonResponseError(3)
        return value

    def software_version(self, request_address, response_address):
        return self._read(request_address, response_address, 0xF189, 2).hex().upper()

    def routine_control(self, routine, request_address, response_address):
        if not isinstance(routine, SuzukiRoutine):
            raise TypeError("Native Suzuki routine enum required")
        identifier = (b"\xc0\x01", b"\xff\x00", b"\xff\x01")[routine]
        self.send(
            request_address,
            response_address,
            b"\x31\x01" + identifier + b"\0",
            b"\x71\x01" + identifier,
            minimum=4,
            error_code=0x19,
        )

    def _gateway_channel(self):
        def exchange(_, payload):
            if payload == b"\x22\x10\x04":
                expected, minimum, code = b"\x62\x10\x04", 4, 9999
            elif payload == b"\x27\x13":
                expected, minimum, code = b"\x67\x13", 18, 0x10
            elif payload[:2] == b"\x27\x14" and len(payload) == 258:
                expected, minimum, code = b"\x67\x14", 2, 0x11
            else:
                raise ValueError("Unexpected native Suzuki gateway request")
            return self.send(
                SUZUKI_GATEWAY_REQUEST,
                SUZUKI_GATEWAY_RESPONSE,
                payload,
                expected,
                minimum=minimum,
                error_code=code,
            )

        return NativeProgrammingChannel(
            exchange,
            SUZUKI_GATEWAY_REQUEST.hex(),
            timeout=self.runtime.check(),
            clock=self.runtime.clock,
            cancelled=self.runtime.cancelled,
            retain_payload_history=False,
        )

    def supports_wired_repro(self, *, with_filter=False):
        return suzuki_supports_wired_repro(
            self.identity,
            self._gateway_channel(),
            self.runtime,
            with_filter=with_filter,
        )

    def gateway_authorize(self, observations, *, with_filter=False):
        return suzuki_gateway_authorize(
            self.identity,
            self._gateway_channel(),
            self.runtime,
            observations,
            with_filter=with_filter,
        )

    def wait_time_for_igoffon(self, kind=0):
        if self.container is None:
            if type(kind) is not int or not 0 <= kind <= 0xFFFFFFFF:
                raise ValueError("Native uint32 wait-time enum required")
            return 0
        return suzuki_wait_time_for_igoffon(
            self.identity, self.parameters, self.container, kind=kind
        )

    def elapsed_seconds(self, start, end):
        return suzuki_elapsed_seconds(self.identity, self.runtime, start, end)

    def set_baud_rate(self, baudrate):
        return set_suzuki_baud_rate(self.identity, self.runtime, baudrate)


class FHIUtils2026:
    """FHI constructors12f0/1310 and assignments1430 share primitive pointers."""

    def __init__(self, identity, runtime):
        from scripts.programming_2026_common import NativeRuntime2026

        require_identity(identity)
        if identity.module_name != "TCUWFHIUtils.dll" or not isinstance(
            runtime, NativeRuntime2026
        ):
            raise ValueError(
                "Exact FHI utility identity and primitive runtime required"
            )
        self.identity, self.runtime = identity, runtime

    def __copy__(self):
        return type(self)(self.identity, self.runtime)

    def move(self):
        return self.__copy__()

    def assign(self, other):
        if not isinstance(other, FHIUtils2026):
            raise TypeError("Native FHI utility object required")
        self.runtime = other.__copy__().runtime
        return self

    move_assign = assign

    @property
    def virtual_methods(self):
        """Native vtable4194 order18d0/1700/1490, without native pointers."""
        return self.send_many, self.send, self.can_ids

    def can_ids(self, kind_of_ecu, addresses):
        return fhi_can_ids(self.identity, kind_of_ecu, addresses)

    def response_status(self, service, received, outstanding):
        return fhi_response_status(self.identity, service, received, outstanding)

    def send(self, request_address, response_address, payload, expected, **options):
        FHIPrepareCommands._addresses((request_address, response_address))
        if not isinstance(payload, bytes):
            raise TypeError("Native FHI payload bytes required")
        return self.send_many(
            (request_address + payload,), (response_address,), expected, **options
        )[0]

    def send_many(self, requests, response_addresses, expected, **options):
        return fhi_exchange(
            self.identity,
            self.runtime,
            requests,
            response_addresses,
            expected,
            **options,
        )


_CONTEXT_TOKEN = object()
_MAIN_MODULES = {
    "TCUWCanSuzukiUDSSoftwareIDGetter.dll": ("get_cid", "suzuki"),
    "TCUWCanSuzukiUDSPrepareWriter.dll": ("prepare", "suzuki"),
    "TCUWCanSuzukiUDSFlashWriter.dll": ("write", "suzuki"),
    "TCUWCanSuzukiUSBReproUDSFlashWriter.dll": ("write", "suzuki_usb"),
    "TCUWCanFHIPrepareWriter.dll": ("prepare", "fhi"),
    "TCUWCanFHIFlashWriter.dll": ("write", "fhi"),
}


@dataclass(frozen=True)
class NativeFamilyContext2026:
    identity: NativeModuleIdentity
    utility_identity: NativeModuleIdentity
    container: object = field(repr=False)
    selection: object = field(repr=False)
    observed_cids: tuple[str, ...] = field(repr=False)
    controller_state: object = field(repr=False)
    notification: object = field(repr=False)
    attachments: Mapping = field(repr=False)
    observations: Mapping = field(repr=False)
    addresses: tuple = field(repr=False)
    recheck_addresses: tuple = field(repr=False)
    source_sha256: str
    node: int
    cpu_index: int
    operation: str
    family: str
    _proof: object = field(default=None, repr=False)

    def __post_init__(self):
        if self._proof is not _CONTEXT_TOKEN:
            raise ValueError(
                "Native family context must originate from actual CUW/catalog binding"
            )


def _context_address_rows(context, identity, container, phase):
    if (
        not isinstance(context, NativeFamilyContext2026)
        or context._proof is not _CONTEXT_TOKEN
        or context.identity != identity
        or context.source_sha256 != container.digest
    ):
        raise ValueError("Actual bound native family address context required")
    expected_phase = {
        "get_cid": "GetCID",
        "prepare": "PrepareWrite",
        "write": "FlashWrite",
    }[context.operation]
    if phase == "GetCID" and context.operation == "prepare":
        rows = context.recheck_addresses
    elif phase == expected_phase:
        rows = context.addresses
    else:
        raise ValueError("Native address context belongs to a different phase")
    if not rows:
        raise ValueError("Native source address branch was not bound")
    return rows


def _current_metadata(container, context=None, *, cpu_index=0):
    """Retain actual current CalibrationFile mutations from canonical selection."""
    from scripts.calibration_2026 import native2026_metadata
    from scripts.programming_2026_common import NativeParameterBinding2026

    if context is None:
        return native2026_metadata(container, cpu_index=cpu_index)
    if (
        not isinstance(context, NativeFamilyContext2026)
        or context._proof is not _CONTEXT_TOKEN
        or context.source_sha256 != container.digest
        or not isinstance(context.selection, NativeParameterBinding2026)
    ):
        raise ValueError("Actual current native metadata context required")
    return context.selection.metadata


def _parameter_keys(metadata):
    from scripts.calibration_2026 import native2026_cpu_type

    return (
        metadata.vehicle.get("kindofecu", ""),
        native2026_cpu_type(metadata),
        metadata.vehicle.get("contacttype", ""),
    )


def bind_native_context(
    container, node, observed_cids, selection, identity, attachments, observations
) -> NativeFamilyContext2026:
    """Canonical31 selection + exact module bytes +47 CUW +48 addresses, no I/O."""
    import hashlib

    from scripts.cuw_2026 import SuzukiControllerState2026
    from scripts.j2534_2026 import communication_addresses_from_calibration
    from scripts.programming_2026_common import (
        NativeParameterBinding2026,
        NotificationBool,
    )

    if (
        not isinstance(selection, NativeParameterBinding2026)
        or not isinstance(attachments, Mapping)
        or not isinstance(observations, Mapping)
        or set(attachments) - {"selected_module", "utils_module", "cuw_module"}
        or set(observations)
        - {
            "cpu_index",
            "stage",
            "suzuki_state",
            "notification",
            "tester_info",
            "previous_addresses",
            "response_canids",
        }
    ):
        raise ValueError(
            "Actual native parameter binding and declared primitive observations required"
        )
    require_identity(identity)
    if identity.module_name not in _MAIN_MODULES:
        raise ValueError("Selected module is outside owned Suzuki/FHI exports")
    operation, family = _MAIN_MODULES[identity.module_name]
    cpu_index = observations.get("cpu_index", 0)
    if observations.get("stage", operation) != operation:
        raise ValueError("Selected native stage differs from module export")
    selection = selection.validate_against(
        container, operation=operation, node=node, cpu_index=cpu_index
    )
    if selection.module_name != identity.module_name:
        raise ValueError("Selected CSV module differs from exact native module")
    if (
        not {"selected_module", "utils_module"} <= set(attachments)
        or any(
            not isinstance(value, bytes) or not 0 < len(value) <= 64 * 1024 * 1024
            for value in attachments.values()
        )
        or sum(map(len, attachments.values())) > 128 * 1024 * 1024
    ):
        raise ValueError("Exact immutable selected module and utility bytes required")
    selected_identity = identify_native_module(
        hashlib.sha256(attachments["selected_module"]).hexdigest(), identity.module_name
    )
    if selected_identity != identity:
        raise ValueError("Selected module bytes differ from declared source identity")
    utility_name = (
        "TCUWFHIUtils.dll" if family == "fhi" else "TCUWCanSuzukiUDSUtils.dll"
    )
    utility_identity = identify_native_module(
        hashlib.sha256(attachments["utils_module"]).hexdigest(), utility_name
    )
    require_identity(utility_identity)
    metadata = selection.metadata
    state = observations.get("suzuki_state")
    if (
        not isinstance(state, SuzukiControllerState2026)
        or state.source_sha256 != metadata.source_sha256
        or state.node != node
        or replace(metadata, cpu_index=state.metadata.cpu_index) != state.metadata
    ):
        raise ValueError("Native state must originate from this loaded CUW engine")
    if (
        "cuw_module" in attachments
        and hashlib.sha256(attachments["cuw_module"]).hexdigest() != state.engine_sha256
    ):
        raise ValueError("Attached CUW engine differs from loaded controller")
    if (
        not isinstance(observed_cids, tuple)
        or len(observed_cids) > 256
        or any(
            not isinstance(value, str) or len(value) > 4096 or "\0" in value
            for value in observed_cids
        )
    ):
        raise ValueError("Bounded actual native CID tuple required")
    for value in observed_cids:
        value.encode("latin1")
    history = observations.get("previous_addresses", ())
    if not isinstance(history, tuple):
        raise TypeError("Immutable typed native address history required")
    persistent_usb_skip = family == "suzuki_usb" and state.value != 0
    rows: tuple = ()
    success = True
    if not persistent_usb_skip:
        resolver = communication_addresses_from_calibration(
            container,
            selection.values,
            response_canids=observations.get("response_canids"),
            history=list(history),
        )
        success, rows = resolver.resolve(
            selection.selector_functions,
            cids=observed_cids,
            location_id=metadata.cpu.values.get("locationid", ""),
        )
    if not persistent_usb_skip and (not success or not rows):
        raise ValueError("Actual native selected address strategy did not resolve")
    if family == "fhi" and (len(rows) < 2 if operation == "write" else len(rows) != 2):
        raise ValueError("Native FHI source requires two bounded address rows")
    recheck = ()
    if family == "suzuki" and operation == "prepare":
        _suzuki_functional_address(container)
        first = rows[0].request[:2].rjust(4, b"\0")
        if first == bytes.fromhex("00000795") and state.value == 2:
            check_functions = selection.lines("GetCANIDFunctionNameForGetCID")[:1]
            ok, recheck = communication_addresses_from_calibration(
                container,
                selection.values,
                response_canids=observations.get("response_canids"),
                history=list(history),
            ).resolve(check_functions, cids=observed_cids)
            if not ok or not recheck:
                raise ValueError(
                    "Native USB retry CID readback address strategy missing"
                )
    notification = (
        getattr(state, "notification", observations.get("notification"))
        if operation == "write"
        else None
    )
    if (
        "notification" in observations
        and notification is not observations["notification"]
    ):
        raise ValueError("Notification must share the actual engine-owned object")
    if operation == "write" and not isinstance(notification, NotificationBool):
        raise ValueError("Actual engine-owned native notification object required")
    if family == "suzuki" and operation == "write":
        native_suzuki_program(identity, container)
        tester = observations.get("tester_info")
        if (
            not isinstance(tester, str)
            or len(tester) != 34
            or any(value not in "0123456789abcdefABCDEF" for value in tester)
        ):
            raise ValueError(
                "Actual native tester information observation must contain34 hexadecimal characters"
            )
    bound = NativeFamilyContext2026(
        identity,
        utility_identity,
        container,
        selection,
        observed_cids,
        state,
        notification,
        MappingProxyType(dict(attachments)),
        MappingProxyType(dict(observations)),
        tuple(rows),
        tuple(recheck),
        metadata.source_sha256,
        node,
        cpu_index,
        operation,
        family,
        _CONTEXT_TOKEN,
    )

    if family == "fhi" and operation == "write":
        native_fhi_program(
            identity,
            utility_identity,
            container,
            selection.parameter,
            cpu_index=cpu_index,
            current_cids=observed_cids,
            address_context=bound,
        )
    return bound


def _native_error_fields(error: BaseException) -> dict:
    """Keep the native primary enum separate from the optional J2534 status."""
    from scripts.programming import NativeTransportError
    from scripts.programming_2026_common import (
        CommonResponseError,
        NativeException2026,
        NativePassThruException2026,
    )

    if isinstance(error, CommonResponseError):
        return {"native_primary_error": error.code}
    if isinstance(error, (NativeTransportError, NativePassThruException2026)):
        primary = getattr(error, "native_error_code", 1)
        secondary = getattr(error, "passthru_status", getattr(error, "code", None))
        result = {"native_primary_error": primary & 0xFFFFFFFF}
        if secondary is not None:
            result["native_passthru_error"] = secondary & 0xFFFFFFFF
        return result
    if isinstance(error, NativeException2026):
        return {"native_primary_error": 9999}
    return {}


def execute_context(context: NativeFamilyContext2026, runtime) -> dict:
    """Execute a canonical source-bound export; byte observations never mean success."""
    from scripts.cuw_2026 import SuzukiControllerState2026
    from scripts.programming_2026_common import (
        NativeException2026,
        NativeParameterBinding2026,
        NativeRuntime2026,
    )

    if (
        not isinstance(context, NativeFamilyContext2026)
        or context._proof is not _CONTEXT_TOKEN
        or not isinstance(runtime, NativeRuntime2026)
    ):
        raise TypeError(
            "Bound native Suzuki/FHI execution context and runtime required"
        )
    checked = bind_native_context(
        context.container,
        context.node,
        context.observed_cids,
        context.selection,
        context.identity,
        context.attachments,
        context.observations,
    )
    if checked != context:
        raise ValueError("Native family context changed after binding")
    selection = context.selection
    assert isinstance(selection, NativeParameterBinding2026)
    parameters = selection.parameter
    assert isinstance(context.controller_state, SuzukiControllerState2026)
    report = {
        "state": "failed",
        "module": context.identity.module_name,
        "module_sha256": context.identity.sha256,
        "source_sha256": context.source_sha256,
        "node": context.node,
        "cpu_index": context.cpu_index,
        "native_return": None,
        "programming_completed": False,
        "physical_status": "PHYSICAL_UNCONFIRMED",
    }
    result = (
        SuzukiUSBWriteResult()
        if context.family == "suzuki_usb"
        else FHIPrepareResult()
        if context.family == "fhi" and context.operation == "prepare"
        else SuzukiUSBResult()
    )
    try:
        if context.operation == "get_cid":
            cid = get_suzuki_cid(
                context.identity,
                context.utility_identity,
                runtime,
                context.container,
                parameters,
                address_context=context,
                result=result,
            )
            return (
                report
                | result.report()
                | {
                    "state": "read_completed",
                    "native_success": True,
                    "identifiers": [cid.decode("latin1")],
                }
            )
        if context.family == "suzuki_usb":
            assert isinstance(result, SuzukiUSBWriteResult)
            write_suzuki_usb(
                context.identity,
                context.utility_identity,
                runtime,
                context.container,
                parameters,
                context.controller_state,
                context.notification,
                result=result,
                address_context=context,
            )
        elif context.family == "suzuki" and context.operation == "prepare":
            current = (
                context.observed_cids[0].encode("latin1")
                if context.observed_cids
                else b""
            )
            prepare_suzuki_uds(
                context.identity,
                context.utility_identity,
                runtime,
                context.container,
                parameters,
                context.controller_state,
                current,
                None,
                None,
                result=result,
                address_context=context,
            )
        elif context.family == "suzuki":
            write_suzuki_uds(
                context.identity,
                context.utility_identity,
                runtime,
                context.container,
                context.notification,
                parameters=parameters,
                tester_info=context.observations["tester_info"],
                result=result,
                address_context=context,
            )
        elif context.operation == "prepare":
            assert isinstance(result, FHIPrepareResult)
            prepare_fhi(
                context.identity,
                context.utility_identity,
                runtime,
                context.container,
                parameters,
                None,
                cpu_index=context.cpu_index,
                current_cids=context.observed_cids,
                result=result,
                address_context=context,
            )
        else:
            write_fhi(
                context.identity,
                context.utility_identity,
                runtime,
                context.container,
                parameters,
                context.notification,
                cpu_index=context.cpu_index,
                current_cids=context.observed_cids,
                result=result,
                address_context=context,
            )
        state = (
            "prepare_completed"
            if context.operation == "prepare"
            else "writer_completed"
        )
        return (
            report
            | result.report()
            | {
                "state": state if result.success else "failed",
                "native_success": result.success,
                "native_return": (
                    result.success if not result.cleanup_errors else None
                ),
            }
        )
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - native result retains bounded failure state
        native_error = (
            {} if result.native_return_reached is False else _native_error_fields(exc)
        )
        if native_error:
            context.controller_state.record_native_error(
                None
                if context.operation == "get_cid" or result.error_status == 0
                else result.error_status,
                native_error["native_primary_error"],
                native_error.get("native_passthru_error"),
            )
            native_error = {
                "native_error_kind": context.controller_state.error_kind,
                "native_primary_error": context.controller_state.primary_error,
                "native_passthru_error": context.controller_state.passthru_error,
            }
        cancelled = (
            isinstance(exc, (InterruptedError, KeyboardInterrupt))
            or isinstance(exc, NativeException2026)
            and exc.messages() == ("",)
        )
        return (
            report
            | result.report()
            | native_error
            | {
                "state": "cancelled" if cancelled else "failed",
                "native_success": False,
                "native_return": (
                    False
                    if native_error
                    and context.operation != "get_cid"
                    and result.error_status in (1, 2)
                    else None
                ),
                "error": type(exc).__name__,
            }
        )
